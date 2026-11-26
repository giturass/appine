//! flock(2) locks and fcntl(2) record locks (the kernel/locks map).
//!
//! Each lock has one owner: a POSIX lock belongs to an fd table
//! (shared by all threads of one process), and closing any non-O_PATH fd in that table referring to the
//! file releases all of the table's locks on the file. OFD and flock locks belong to an open
//! file and lapse when its last reference is closed. Record locks of one owner never overlap,
//! and adjacent ranges of the same type are merged.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cell::RefCell;
use crate::fd::{FdTable, FileKind, FileRef, OpenFile};
use crate::kernel::{Kernel, Tid, request_wake_locks};
use crate::pidns::PidNs;
use crate::pseudo::{self, PseudoNode};
use crate::vfs::store::Ino;
use crate::vfs::{Node, Vfs};

/// Monotonic sequence number for lock acquisition order (`/proc/locks` lists newest first).
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_seq() -> u64 {
    NEXT_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// Filesystem, pipefs, sockfs and devpts inodes have independent number spaces.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum LockKey {
    Node(Ino),
    Pipe(Ino),
    Socket(Ino),
    Devpts(u64, Ino),
}

impl LockKey {
    pub fn of(file: &OpenFile) -> Option<Self> {
        // Linux skips POSIX lock removal on close of an O_PATH descriptor.
        if file.flags & crate::fd::oflags::O_PATH != 0 {
            return None;
        }
        if let Some(ino) = file.lock_ino() {
            return Some(Self::Node(ino));
        }
        match &file.kind {
            FileKind::Pipe(end) => Some(Self::Pipe(end.pipe.borrow().ino)),
            FileKind::Socket(s) => Some(Self::Socket(pseudo::socket_ino(s))),
            FileKind::Pty(end) => {
                if let Some(ino) = end.lock_ino {
                    return Some(Self::Node(ino));
                }
                let tty = end.tty.borrow();
                let node = if end.master {
                    PseudoNode::PtsPtmx(tty.fs)
                } else {
                    PseudoNode::Pts(tty.fs, tty.index)
                };
                Some(Self::Devpts(tty.fs, pseudo::ino_of(&node)))
            }
            _ => None,
        }
    }
}

struct FlockHolder {
    file: Weak<RefCell<OpenFile>>,
    exclusive: bool,
    /// The process that took the lock, as reported in /proc/locks.
    pid: Tid,
    /// Acquisition order for `/proc/locks` (newest first).
    seq: u64,
}

/// A thread waiting for a whole-file lock in flock(2).
pub(crate) struct FlockWaiter {
    pub tid: Tid,
    pub key: LockKey,
    pub file: Weak<RefCell<OpenFile>>,
    pub exclusive: bool,
    pub pid: Tid,
}

#[derive(Default)]
pub(crate) struct Flocks {
    by_key: BTreeMap<LockKey, Vec<FlockHolder>>,
    waiters: Vec<FlockWaiter>,
    sweep_at: usize,
}

/// Last close can drop a weak owner without revisiting its key. Sweep as the table grows.
fn sweep_dead<T>(
    by_key: &mut BTreeMap<LockKey, Vec<T>>,
    sweep_at: &mut usize,
    alive: impl Fn(&T) -> bool,
) {
    if by_key.len() >= (*sweep_at).max(256) {
        by_key.retain(|_, locks| {
            locks.retain(&alive);
            !locks.is_empty()
        });
        *sweep_at = 2 * by_key.len();
    }
}

impl Flocks {
    pub fn set_waiting(&mut self, tid: Tid, wait: Option<FlockWaiter>) {
        self.waiters
            .retain(|w| w.tid != tid && w.file.strong_count() > 0);
        if let Some(w) = wait {
            self.waiters.push(w);
        }
    }

    /// Returns false if another open file holds a conflicting lock.
    pub fn try_lock(&mut self, key: LockKey, file: &FileRef, exclusive: bool, pid: Tid) -> bool {
        sweep_dead(&mut self.by_key, &mut self.sweep_at, |holder| {
            holder.file.strong_count() > 0
        });
        let holders = self.by_key.entry(key).or_default();
        holders.retain(|holder| holder.file.strong_count() > 0);
        let owner = Rc::downgrade(file);
        if let Some(i) = holders.iter().position(|holder| holder.file.ptr_eq(&owner)) {
            if holders[i].exclusive == exclusive {
                return true;
            }
            // A conversion releases the old lock even when the new request would block.
            holders.remove(i);
            request_wake_locks();
        }
        if holders.iter().any(|holder| exclusive || holder.exclusive) {
            return false;
        }
        holders.push(FlockHolder {
            file: owner,
            exclusive,
            pid,
            seq: next_seq(),
        });
        file.borrow_mut().holds_locks = true;
        true
    }

    pub fn unlock(&mut self, key: LockKey, file: &FileRef) {
        let Some(holders) = self.by_key.get_mut(&key) else {
            return;
        };
        let owner = Rc::downgrade(file);
        if let Some(i) = holders.iter().position(|holder| holder.file.ptr_eq(&owner)) {
            holders.remove(i);
            request_wake_locks();
        }
        if holders.is_empty() {
            self.by_key.remove(&key);
        }
    }
}

/// The owner of a lock.
#[derive(Clone)]
pub(crate) enum Owner {
    /// Traditional POSIX lock: belongs to an fd table.
    Posix(Weak<RefCell<FdTable>>),
    /// OFD lock: belongs to an open file.
    Ofd(Weak<RefCell<OpenFile>>),
}

impl Owner {
    fn same(&self, other: &Owner) -> bool {
        match (self, other) {
            (Owner::Posix(a), Owner::Posix(b)) => a.ptr_eq(b),
            (Owner::Ofd(a), Owner::Ofd(b)) => a.ptr_eq(b),
            _ => false,
        }
    }

    fn alive(&self) -> bool {
        match self {
            Owner::Posix(w) => w.strong_count() > 0,
            Owner::Ofd(w) => w.strong_count() > 0,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Owner::Posix(_) => "POSIX  ADVISORY  ",
            Owner::Ofd(_) => "OFDLCK ADVISORY  ",
        }
    }
}

/// A lock covering `[start, end)`; an `end` of `u64::MAX` means to the end of the file and beyond.
#[derive(Clone)]
pub(crate) struct Lock {
    pub owner: Owner,
    /// The open file through which the lock was taken (Linux's `fl_file`).
    pub file: Weak<RefCell<OpenFile>>,
    /// The process that took the lock (the `l_pid` F_GETLK reports); -1 for OFD locks.
    pub pid: Tid,
    pub start: u64,
    pub end: u64,
    /// Write lock (exclusive); otherwise a read lock (shared).
    pub write: bool,
    /// Acquisition order for `/proc/locks` (newest first).
    pub seq: u64,
}

impl Lock {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }

    /// Conflicts with a request from a different owner with an incompatible type.
    fn conflicts(&self, req: &Lock) -> bool {
        !self.owner.same(&req.owner)
            && (self.write || req.write)
            && self.overlaps(req.start, req.end)
    }

    /// The open file shown for this lock or waiter, falling back to `owner.file` only when no
    /// taking open file was recorded.
    fn shown_file(&self, key: LockKey) -> Option<FileRef> {
        self.file.upgrade().or_else(|| {
            self.file
                .ptr_eq(&Weak::new())
                .then(|| self.owner.file(key))
                .flatten()
        })
    }
}

/// What a lock request is waiting for (for deadlock detection and `/proc/locks` `->` lines).
pub(crate) struct Waiter {
    /// The thread waiting in `F_SETLKW` / `F_OFD_SETLKW`.
    pub tid: Tid,
    pub key: LockKey,
    pub req: Lock,
}

/// Record locks on all inodes.
#[derive(Default)]
pub(crate) struct Locks {
    by_key: BTreeMap<LockKey, Vec<Lock>>,
    sweep_at: usize,
    /// Record-lock requests waiting in `F_SETLKW` / `F_OFD_SETLKW`.
    waiters: Vec<Waiter>,
}

impl Locks {
    /// The first lock (in order of start) that conflicts with the request.
    pub fn conflict(&mut self, key: LockKey, req: &Lock) -> Option<Lock> {
        let locks = self.by_key.get_mut(&key)?;
        locks.retain(|l| l.owner.alive());
        locks.iter().find(|l| l.conflicts(req)).cloned()
    }

    fn conflict_ref(&self, key: LockKey, req: &Lock) -> Option<&Lock> {
        self.by_key
            .get(&key)?
            .iter()
            .find(|l| l.owner.alive() && l.conflicts(req))
    }

    /// Sets (or, with `unlock`, removes) the locks in `req`'s range. The caller has already made
    /// sure there is no conflict.
    pub fn set(&mut self, key: LockKey, req: Lock, unlock: bool) {
        sweep_dead(&mut self.by_key, &mut self.sweep_at, |lock| {
            lock.owner.alive()
        });
        let locks = self.by_key.entry(key).or_default();
        let (mut start, mut end) = (req.start, req.end);
        let mut merged: Option<(Weak<RefCell<OpenFile>>, u64)> = None;
        let mut kept = Vec::with_capacity(locks.len() + 2);
        for l in locks.drain(..).filter(|l| l.owner.alive()) {
            if !l.owner.same(&req.owner) {
                kept.push(l);
                continue;
            }
            // Locks of the same type that overlap or are adjacent merge into the new lock
            if !unlock && l.write == req.write && l.start <= end && start <= l.end {
                start = start.min(l.start);
                end = end.max(l.end);
                merged.get_or_insert((l.file, l.seq));
                continue;
            }
            if !l.overlaps(req.start, req.end) {
                kept.push(l);
                continue;
            }
            // Different type, or unlocking: keep only the parts outside the requested range
            if l.start < req.start {
                kept.push(Lock {
                    end: req.start,
                    ..l.clone()
                });
            }
            if l.end > req.end {
                kept.push(Lock {
                    start: req.end,
                    ..l
                });
            }
        }
        if !unlock {
            let (file, seq) = merged
                .unwrap_or_else(|| (req.file, if req.seq != 0 { req.seq } else { next_seq() }));
            kept.push(Lock {
                start,
                end,
                file,
                seq,
                ..req
            });
        }
        kept.sort_by_key(|l| l.start);
        if kept.is_empty() {
            self.by_key.remove(&key);
        } else {
            *locks = kept;
        }
        request_wake_locks();
    }

    /// Whether waiting for `req` would deadlock: follow "whose lock blocks the waiting request"
    /// along the chain; coming back to ourselves is a deadlock (`posix_locks_deadlock`). Checks
    /// POSIX locks only.
    pub fn deadlock(&self, key: LockKey, req: &Lock) -> bool {
        let Owner::Posix(_) = req.owner else {
            return false;
        };
        let mut stack = Vec::new();
        let mut visited: Vec<Owner> = Vec::new();
        if let Some(l) = self.conflict_ref(key, req) {
            stack.push(l.owner.clone());
        }
        while let Some(blocker) = stack.pop() {
            if blocker.same(&req.owner) {
                return true;
            }
            if visited.iter().any(|v| v.same(&blocker)) {
                continue;
            }
            for w in self
                .waiters
                .iter()
                .filter(|w| w.req.owner.same(&blocker) && w.req.owner.alive())
            {
                if let Some(l) = self.conflict_ref(w.key, &w.req) {
                    stack.push(l.owner.clone());
                }
            }
            visited.push(blocker);
        }
        false
    }

    /// Records (`Some`) or clears thread `tid`'s wait in `F_SETLKW` / `F_OFD_SETLKW`.
    pub fn set_waiting(&mut self, tid: Tid, wait: Option<Waiter>) {
        self.waiters.retain(|w| w.tid != tid && w.req.owner.alive());
        if let Some(w) = wait {
            self.waiters.push(w);
        }
    }

    /// These files in fd table `fds` were closed: release this fd table's POSIX locks on them.
    pub fn closed(&mut self, fds: &Rc<RefCell<FdTable>>, files: &[FileRef]) {
        let owner = Owner::Posix(Rc::downgrade(fds));
        for file in files {
            let Some(key) = LockKey::of(&file.borrow()) else {
                continue;
            };
            if let Some(locks) = self.by_key.get_mut(&key) {
                let before = locks.len();
                locks.retain(|l| !l.owner.same(&owner) && l.owner.alive());
                if locks.len() != before {
                    request_wake_locks();
                }
                if locks.is_empty() {
                    self.by_key.remove(&key);
                }
            }
        }
    }
}

/// Called after fds are closed: releases the current process's POSIX locks on these files.
pub(crate) fn closed(k: &mut Kernel, fds: &Rc<RefCell<FdTable>>, files: &[FileRef]) {
    if !files.is_empty() {
        k.locks.closed(fds, files);
    }
}

// ---- /proc/locks ----

/// `/proc/locks` lists flocks, POSIX and OFD locks, and leases newest first by acquisition
/// sequence (Linux 6.1's `locks_show` and `lock_get_status`). Blocked `flock`, `F_SETLKW` and
/// `F_OFD_SETLKW` requests appear on `->` lines with their first conflicting holder's number.
/// Each line shows the pid in the reader's namespace `ns` (-1 for OFD locks), the device and
/// inode from stat, and the lock range. Invisible holders consume a number and hide their
/// waiters. Entries without a shown device/inode identity are omitted without consuming a number.
pub(crate) fn proc_locks(k: &Kernel, vfs: &Vfs, ns: &PidNs) -> String {
    let mut out = String::new();
    let mut pos = 0;
    let mut entries = shown(k, None);
    entries.sort_by(|a, b| b.seq.cmp(&a.seq));
    let translate = |pid: Tid| match pid {
        -1 => Some(-1),
        // As Linux's locks_translate_pid: the initial namespace shows the number as recorded
        p if ns.level == 0 => Some(p),
        p => ns.vnr(p).filter(|&p| p != 0),
    };
    for s in entries {
        let Some(id) = shown_id(vfs, &s.line.file.borrow()) else {
            continue;
        };
        pos += 1;
        if let Some(pid) = translate(s.line.pid) {
            writeln!(out, "{pos}: {}", s.line.status(id, pid)).unwrap();
            for w in &s.waiters {
                if let Some(wpid) = translate(w.pid) {
                    let wid = shown_id(vfs, &w.file.borrow()).unwrap_or(id);
                    writeln!(out, "{pos}: -> {}", w.status(wid, wpid)).unwrap();
                }
            }
        }
    }
    out
}

/// The `lock:` lines of `/proc/<pid>/fdinfo/<n>` (Linux's `show_fd_locks`), which lslocks reads to
/// tell who holds an OFD lock: the flock lock, OFD locks and lease held through open file `file`
/// and the POSIX locks of fd table `fds` taken through `file`, numbered from 1, with the pid as
/// `ns` sees it (0 when it cannot).
pub(crate) fn fd_locks(
    k: &Kernel,
    vfs: &Vfs,
    ns: &PidNs,
    fds: &Rc<RefCell<FdTable>>,
    file: &FileRef,
) -> String {
    let Some(key) = LockKey::of(&file.borrow()) else {
        return String::new();
    };
    let mut out = String::new();
    let mut n = 0;
    for s in shown(k, Some(key)).iter().filter(|s| {
        Rc::ptr_eq(&s.line.file, file)
            && s.table
                .as_ref()
                .is_none_or(|t| std::ptr::eq(t.as_ptr(), Rc::as_ptr(fds)))
    }) {
        let Some(id) = shown_id(vfs, &s.line.file.borrow()) else {
            continue;
        };
        let pid = match s.line.pid {
            -1 => -1,
            p if ns.level == 0 => p,
            p => ns.vnr(p).unwrap_or(0),
        };
        n += 1;
        writeln!(out, "lock:\t{n}: {}", s.line.status(id, pid)).unwrap();
    }
    out
}

/// One lock, lease, or blocked waiter line as `/proc/locks` and fdinfo format it.
struct ShownLine {
    /// The kind and mode columns, padded as `lock_get_status` pads them.
    kind: &'static str,
    /// A write lock or lease, a read one, or None for `F_UNLCK` (a lease being broken to none).
    write: Option<bool>,
    /// The process that took it (-1 for OFD locks).
    pid: Tid,
    /// The open file it is held through (Linux's `fl_file`).
    file: FileRef,
    /// The last column: the byte range of a record lock, `0 EOF` otherwise.
    range: String,
}

impl ShownLine {
    fn flock(file: FileRef, exclusive: bool, pid: Tid) -> Self {
        Self {
            kind: "FLOCK  ADVISORY  ",
            write: Some(exclusive),
            pid,
            file,
            range: "0 EOF".into(),
        }
    }

    /// The line after the number, for device/inode `(dev, ino)` and `pid` as the reader sees it.
    fn status(&self, (dev, ino): (u64, u64), pid: Tid) -> String {
        let ty = match self.write {
            Some(true) => "WRITE",
            Some(false) => "READ",
            None => "UNLCK",
        };
        // glibc's major() and minor() of the dev_t stat reports
        let major = (dev >> 8 & 0xfff) | (dev >> 32 & !0xfff);
        let minor = (dev & 0xff) | (dev >> 12 & !0xff);
        format!(
            "{}{ty} {pid} {major:02x}:{minor:02x}:{ino} {}",
            self.kind, self.range
        )
    }
}

/// One lock or lease as `/proc/locks` and fdinfo show it.
struct Shown {
    line: ShownLine,
    /// A POSIX lock's owner (`fl_owner`); the others are owned by `line.file`.
    table: Option<Weak<RefCell<FdTable>>>,
    /// Acquisition order for `/proc/locks` (newest first).
    seq: u64,
    /// Waiters blocked by this lock (populated only for `/proc/locks`).
    waiters: Vec<ShownLine>,
}

fn format_range(start: u64, end: u64) -> String {
    // Linux's inclusive end, OFFSET_MAX meaning to the end
    let last = end.wrapping_sub(1);
    if last >= i64::MAX as u64 {
        format!("{start} EOF")
    } else {
        format!("{start} {last}")
    }
}

/// Every lock and lease (only those on `only` when given), in the order Linux keeps an inode's:
/// flock locks, then POSIX and OFD locks, then leases. The global listing uses each entry's
/// acquisition sequence and attaches blocked flock and record-lock waiters to their holders.
fn shown(k: &Kernel, only: Option<LockKey>) -> Vec<Shown> {
    let wanted = |ino: &Ino| only.is_none_or(|o| o == LockKey::Node(*ino));
    let mut out = Vec::new();
    for (key, holders) in &k.flocks.by_key {
        if only.is_some_and(|o| o != *key) {
            continue;
        }
        let base = out.len();
        for holder in holders {
            if let Some(file) = holder.file.upgrade() {
                out.push(Shown {
                    line: ShownLine::flock(file, holder.exclusive, holder.pid),
                    table: None,
                    seq: holder.seq,
                    waiters: Vec::new(),
                });
            }
        }
        let live = &mut out[base..];
        if only.is_some() || live.is_empty() {
            continue;
        }
        for w in k.flocks.waiters.iter().filter(|w| w.key == *key) {
            let Some(file) = w.file.upgrade() else {
                continue;
            };
            if let Some(holder) = live.iter_mut().find(|h| {
                !Rc::ptr_eq(&h.line.file, &file) && (w.exclusive || h.line.write == Some(true))
            }) {
                holder
                    .waiters
                    .push(ShownLine::flock(file, w.exclusive, w.pid));
            }
        }
    }
    for (&key, locks) in &k.locks.by_key {
        if only.is_some_and(|o| o != key) {
            continue;
        }
        let base = out.len();
        let mut live: Vec<&Lock> = Vec::new();
        for l in locks.iter().filter(|l| l.owner.alive()) {
            let Some(file) = l.shown_file(key) else {
                continue;
            };
            let table = match &l.owner {
                Owner::Posix(t) => Some(t.clone()),
                Owner::Ofd(_) => None,
            };
            out.push(Shown {
                line: ShownLine {
                    kind: l.owner.kind(),
                    write: Some(l.write),
                    pid: l.pid,
                    file,
                    range: format_range(l.start, l.end),
                },
                table,
                seq: l.seq,
                waiters: Vec::new(),
            });
            live.push(l);
        }
        if only.is_none() && !live.is_empty() {
            for w in k
                .locks
                .waiters
                .iter()
                .filter(|w| w.key == key && w.req.owner.alive())
            {
                let Some(idx) = live.iter().position(|l| l.conflicts(&w.req)) else {
                    continue;
                };
                let Some(file) = w.req.shown_file(key) else {
                    continue;
                };
                out[base + idx].waiters.push(ShownLine {
                    kind: w.req.owner.kind(),
                    write: Some(w.req.write),
                    pid: w.req.pid,
                    file,
                    range: format_range(w.req.start, w.req.end),
                });
            }
        }
    }
    // Leases are keyed by the store inode, or by an overlay node's key (same as lock_ino)
    for (_, leases) in k.leases.iter().filter(|(i, _)| wanted(i)) {
        for lease in leases {
            let Some((file, write, breaking, pid, seq)) = lease.shown() else {
                continue;
            };
            out.push(Shown {
                line: ShownLine {
                    kind: if breaking {
                        "LEASE  BREAKING  "
                    } else {
                        "LEASE  ACTIVE    "
                    },
                    write,
                    pid,
                    file,
                    range: "0 EOF".into(),
                },
                table: None,
                seq,
                waiters: Vec::new(),
            });
        }
    }
    out
}

impl Owner {
    /// An open file the lock on `key` is held through: an OFD lock's own, or for a POSIX lock one
    /// in its fd table that refers to the file (any close of which would release the lock).
    fn file(&self, key: LockKey) -> Option<FileRef> {
        match self {
            Owner::Ofd(f) => f.upgrade(),
            Owner::Posix(t) => {
                let t = t.upgrade()?;
                let t = t.borrow();
                t.open_fds()
                    .into_iter()
                    .filter_map(|fd| t.get(fd).ok())
                    .find(|f| LockKey::of(&f.borrow()) == Some(key))
            }
        }
    }
}

/// The device and inode numbers stat shows for `file` (`/proc/locks` prints the inode's): those of
/// its node, with an overlay node's shown inode number or a FUSE node's cached inode number.
fn shown_id(vfs: &Vfs, file: &OpenFile) -> Option<(u64, u64)> {
    let Some(node) = file.node() else {
        return matches!(
            file.kind,
            FileKind::Pipe(_) | FileKind::Socket(_) | FileKind::Pty(_)
        )
        .then(|| crate::syscall::dev_ino(file));
    };
    let ino = match &node {
        Node::Overlay(_, o) => vfs.overlay().shown_ino(*o),
        Node::Fuse(_, f) => vfs.fuse().get(*f)?.attr.ino,
        n => n.ino()?,
    };
    Some((vfs.dev_of(&node), ino))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd::{FileKind, OpenFile};

    fn owner(t: &Rc<RefCell<FdTable>>) -> Owner {
        Owner::Posix(Rc::downgrade(t))
    }

    fn lock(o: &Owner, start: u64, end: u64, write: bool) -> Lock {
        Lock {
            owner: o.clone(),
            file: Weak::new(),
            pid: 1,
            start,
            end,
            write,
            seq: 0,
        }
    }

    fn ranges(l: &Locks, ino: Ino) -> Vec<(u64, u64, bool)> {
        l.by_key.get(&LockKey::Node(ino)).map_or(Vec::new(), |v| {
            v.iter().map(|l| (l.start, l.end, l.write)).collect()
        })
    }

    #[test]
    fn locks_split_merge_and_conflict() {
        let (a, b) = (
            Rc::new(RefCell::new(FdTable::new())),
            Rc::new(RefCell::new(FdTable::new())),
        );
        let (oa, ob) = (owner(&a), owner(&b));
        let mut l = Locks::default();
        let key = LockKey::Node(1);
        l.set(key, lock(&oa, 0, 100, true), false);
        // Turn the middle into a read lock: split into three pieces
        l.set(key, lock(&oa, 40, 60, false), false);
        assert_eq!(
            ranges(&l, 1),
            vec![(0, 40, true), (40, 60, false), (60, 100, true)]
        );
        // Another owner: a read lock does not conflict with read locks but does with write locks
        assert!(l.conflict(key, &lock(&ob, 45, 50, false)).is_none());
        assert_eq!(l.conflict(key, &lock(&ob, 30, 50, false)).unwrap().start, 0);
        // Adjacent locks of the same type merge
        l.set(key, lock(&oa, 40, 60, true), false);
        assert_eq!(ranges(&l, 1), vec![(0, 100, true)]);
        // Unlock a piece in the middle
        l.set(key, lock(&oa, 10, 20, false), true);
        assert_eq!(ranges(&l, 1), vec![(0, 10, true), (20, 100, true)]);
        // The owner goes away, and its locks lapse with it
        drop(a);
        assert!(l.conflict(key, &lock(&ob, 0, u64::MAX, true)).is_none());
    }

    #[test]
    fn closing_any_fd_releases_the_posix_locks() {
        let a = Rc::new(RefCell::new(FdTable::new()));
        let mut l = Locks::default();
        let file = OpenFile::new(
            FileKind::Path(crate::vfs::Node::Store(crate::vfs::ROOT_MOUNT, 7)),
            0,
        );
        l.set(LockKey::Node(7), lock(&owner(&a), 0, 10, true), false);
        l.closed(&a, &[file]);
        assert!(ranges(&l, 7).is_empty());
    }

    #[test]
    fn waiting_in_a_cycle_is_a_deadlock() {
        let (a, b) = (
            Rc::new(RefCell::new(FdTable::new())),
            Rc::new(RefCell::new(FdTable::new())),
        );
        let (oa, ob) = (owner(&a), owner(&b));
        let mut l = Locks::default();
        let key = LockKey::Node(1);
        l.set(key, lock(&oa, 0, 10, true), false);
        l.set(key, lock(&ob, 10, 20, true), false);
        // a is waiting for b's lock; b then waiting for a's lock is a deadlock
        let wait = lock(&oa, 10, 20, true);
        assert!(!l.deadlock(key, &wait));
        l.set_waiting(
            1,
            Some(Waiter {
                tid: 1,
                key,
                req: wait,
            }),
        );
        assert!(l.deadlock(key, &lock(&ob, 0, 10, true)));
    }

    fn temp_vfs(tag: &str) -> (std::path::PathBuf, Vfs) {
        let dir = std::env::temp_dir().join(format!(
            "appine-locks-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        drop(crate::vfs::store::Store::create(&dir).unwrap());
        let vfs = Vfs::open(&dir).unwrap();
        (dir, vfs)
    }

    fn null_file(ino: Ino) -> FileRef {
        OpenFile::new(
            FileKind::Device {
                ino,
                dev: crate::vfs::dev::Device::Null,
                kmsg: None,
                block: None,
            },
            0,
        )
    }

    fn block_flock(k: &mut Kernel, file: &FileRef, exclusive: bool, tid: Tid, pid: Tid) {
        let key = LockKey::of(&file.borrow()).unwrap();
        assert!(!k.flocks.try_lock(key, file, exclusive, pid));
        k.flocks.set_waiting(
            tid,
            Some(FlockWaiter {
                tid,
                key,
                file: Rc::downgrade(file),
                exclusive,
                pid,
            }),
        );
    }

    #[test]
    fn flock_waiter_is_shown_under_its_first_shared_blocker() {
        let (dir, vfs) = temp_vfs("shared-flocks");
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let ns = PidNs::init();
        let (first, second, waiter) = (null_file(42), null_file(42), null_file(42));
        let key = LockKey::of(&first.borrow()).unwrap();
        assert!(k.flocks.try_lock(key, &first, false, 100));
        assert!(k.flocks.try_lock(key, &second, false, 200));
        block_flock(&mut k, &waiter, true, 301, 300);

        assert_eq!(
            proc_locks(&k, &vfs, &ns),
            "1: FLOCK  ADVISORY  READ 200 08:01:42 0 EOF\n\
             2: FLOCK  ADVISORY  READ 100 08:01:42 0 EOF\n\
             2: -> FLOCK  ADVISORY  WRITE 300 08:01:42 0 EOF\n"
        );
        let fds = Rc::new(RefCell::new(FdTable::new()));
        assert!(fd_locks(&k, &vfs, &ns, &fds, &waiter).is_empty());
        assert_eq!(
            fd_locks(&k, &vfs, &ns, &fds, &first),
            "lock:\t1: FLOCK  ADVISORY  READ 100 08:01:42 0 EOF\n"
        );

        let child = PidNs::child(&ns, crate::cred::Cred::root().user_ns.clone());
        PidNs::register(&child, 200, &[]).unwrap();
        PidNs::register(&child, 300, &[]).unwrap();
        // A visible waiter stays hidden while its first blocker is invisible.
        assert_eq!(
            proc_locks(&k, &vfs, &child),
            "1: FLOCK  ADVISORY  READ 1 08:01:42 0 EOF\n"
        );
        k.flocks.unlock(key, &first);
        assert_eq!(
            proc_locks(&k, &vfs, &child),
            "1: FLOCK  ADVISORY  READ 1 08:01:42 0 EOF\n\
             1: -> FLOCK  ADVISORY  WRITE 2 08:01:42 0 EOF\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exclusive_flock_lists_live_waiters_until_cleared() {
        let (dir, vfs) = temp_vfs("exclusive-flock");
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let ns = PidNs::init();
        let (holder, reader, writer) = (null_file(42), null_file(42), null_file(42));
        let key = LockKey::of(&holder.borrow()).unwrap();
        assert!(k.flocks.try_lock(key, &holder, true, 100));
        block_flock(&mut k, &reader, false, 201, 200);
        block_flock(&mut k, &writer, true, 202, 200);
        assert_eq!(
            proc_locks(&k, &vfs, &ns),
            "1: FLOCK  ADVISORY  WRITE 100 08:01:42 0 EOF\n\
             1: -> FLOCK  ADVISORY  READ 200 08:01:42 0 EOF\n\
             1: -> FLOCK  ADVISORY  WRITE 200 08:01:42 0 EOF\n"
        );
        let child = PidNs::child(&ns, crate::cred::Cred::root().user_ns.clone());
        PidNs::register(&child, 100, &[]).unwrap();
        assert_eq!(
            proc_locks(&k, &vfs, &child),
            "1: FLOCK  ADVISORY  WRITE 1 08:01:42 0 EOF\n"
        );
        k.flocks.set_waiting(201, None);
        assert_eq!(
            proc_locks(&k, &vfs, &ns),
            "1: FLOCK  ADVISORY  WRITE 100 08:01:42 0 EOF\n\
             1: -> FLOCK  ADVISORY  WRITE 200 08:01:42 0 EOF\n"
        );
        drop(writer);
        assert_eq!(
            proc_locks(&k, &vfs, &ns),
            "1: FLOCK  ADVISORY  WRITE 100 08:01:42 0 EOF\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lease_uses_acquisition_order_in_proc_locks_and_inode_order_in_fdinfo() {
        let (dir, vfs) = temp_vfs("lease-order");
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let ns = PidNs::init();
        let fds = Rc::new(RefCell::new(FdTable::new()));
        let ino = 42;
        let file = OpenFile::new(
            FileKind::Regular {
                ino,
                file: std::fs::File::create(dir.join("file")).unwrap(),
                cow: false,
            },
            0,
        );
        let key = LockKey::of(&file.borrow()).unwrap();
        assert!(k.flocks.try_lock(key, &file, false, 100));
        let lease = crate::syscall::Lease::new(&file, 3, libc::F_RDLCK as i16, 100);
        k.leases.entry(ino).or_default().push(lease);
        k.locks.set(
            key,
            Lock {
                file: Rc::downgrade(&file),
                pid: 100,
                ..lock(&owner(&fds), 10, 20, false)
            },
            false,
        );

        assert_eq!(
            proc_locks(&k, &vfs, &ns),
            "1: POSIX  ADVISORY  READ 100 08:01:42 10 19\n\
             2: LEASE  ACTIVE    READ 100 08:01:42 0 EOF\n\
             3: FLOCK  ADVISORY  READ 100 08:01:42 0 EOF\n"
        );
        assert_eq!(
            fd_locks(&k, &vfs, &ns, &fds, &file),
            "lock:\t1: FLOCK  ADVISORY  READ 100 08:01:42 0 EOF\n\
             lock:\t2: POSIX  ADVISORY  READ 100 08:01:42 10 19\n\
             lock:\t3: LEASE  ACTIVE    READ 100 08:01:42 0 EOF\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proc_locks_and_fd_locks_handle_fuse_and_omitted_entries() {
        use crate::cred::Cred;
        use crate::vfs::fuse;
        use crate::vfs::store::mode;

        let (dir, vfs) = temp_vfs("test");
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let init_ns = PidNs::init();
        let root_cred = Cred::root();

        fuse::new_syscall();
        let (fuse_mnt, conn) = vfs.new_fuse((Node::ROOT, None), 0, b"testfuse".to_vec(), |dev| {
            fuse::Conn::new(dev, fuse::Options::default(), &root_cred, init_ns.clone())
        });
        let fuse_dev = conn.borrow().dev;
        let fuse_root = vfs.fuse().root_of(fuse_dev).unwrap();
        let fuse_id = vfs
            .fuse_mut()
            .enter(
                fuse_root,
                b"locked",
                &fuse::Entry {
                    nodeid: 2,
                    attr: fuse::Attr {
                        ino: 4242,
                        mode: mode::S_IFREG | 0o644,
                        nlink: 1,
                        ..fuse::Attr::default()
                    },
                    entry_until: None,
                    attr_until: None,
                },
            )
            .unwrap();

        let store_a = null_file(10);
        let store_b = null_file(20);
        let fuse_file = OpenFile::new(
            FileKind::Fuse(Box::new(fuse::Handle {
                conn: conn.clone(),
                id: fuse_id,
                nodeid: 2,
                fh: 1,
                open_flags: 0,
                flags: 0,
                dir: false,
                no_release: true,
            })),
            0,
        );
        fuse_file.borrow_mut().mnt = fuse_mnt;

        let fds = Rc::new(RefCell::new(FdTable::new()));
        fds.borrow_mut()
            .install(fuse_file.clone(), false, 0..16)
            .unwrap();

        let key_a = LockKey::of(&store_a.borrow()).unwrap();
        let key_b = LockKey::of(&store_b.borrow()).unwrap();
        let key_fuse = LockKey::of(&fuse_file.borrow()).unwrap();

        assert!(k.flocks.try_lock(key_a, &store_a, true, 100));
        assert!(k.flocks.try_lock(key_fuse, &fuse_file, true, 100));
        assert!(k.flocks.try_lock(key_b, &store_b, false, 200));
        k.locks.set(
            key_fuse,
            Lock {
                owner: Owner::Ofd(Rc::downgrade(&fuse_file)),
                file: Rc::downgrade(&fuse_file),
                pid: -1,
                start: 10,
                end: 20,
                write: true,
                seq: 0,
            },
            false,
        );
        k.locks.set(
            key_fuse,
            Lock {
                owner: Owner::Posix(Rc::downgrade(&fds)),
                file: Rc::downgrade(&fuse_file),
                pid: 100,
                start: 30,
                end: u64::MAX,
                write: false,
                seq: 0,
            },
            false,
        );

        let major = (fuse_dev >> 8 & 0xfff) | (fuse_dev >> 32 & !0xfff);
        let minor = (fuse_dev & 0xff) | (fuse_dev >> 12 & !0xff);
        let fuse_dev_ino = format!("{major:02x}:{minor:02x}:4242");

        // Live FUSE locks show in /proc/locks newest first with consecutive numbering, and in
        // fdinfo in per-inode order (flock, OFD, POSIX).
        let listing = proc_locks(&k, &vfs, &init_ns);
        let lines: Vec<&str> = listing.lines().collect();
        assert_eq!(lines.len(), 5, "{listing}");
        assert_eq!(
            lines[0],
            format!("1: POSIX  ADVISORY  READ 100 {fuse_dev_ino} 30 EOF")
        );
        assert_eq!(
            lines[1],
            format!("2: OFDLCK ADVISORY  WRITE -1 {fuse_dev_ino} 10 19")
        );
        assert!(lines[2].starts_with("3: FLOCK  ADVISORY  READ 200 08:01:20 0 EOF"));
        assert_eq!(
            lines[3],
            format!("4: FLOCK  ADVISORY  WRITE 100 {fuse_dev_ino} 0 EOF")
        );
        assert!(lines[4].starts_with("5: FLOCK  ADVISORY  WRITE 100 08:01:10 0 EOF"));

        let fdinfo = fd_locks(&k, &vfs, &init_ns, &fds, &fuse_file);
        let fd_lines: Vec<&str> = fdinfo.lines().collect();
        assert_eq!(fd_lines.len(), 3, "{fdinfo}");
        assert_eq!(
            fd_lines[0],
            format!("lock:\t1: FLOCK  ADVISORY  WRITE 100 {fuse_dev_ino} 0 EOF")
        );
        assert_eq!(
            fd_lines[1],
            format!("lock:\t2: OFDLCK ADVISORY  WRITE -1 {fuse_dev_ino} 10 19")
        );
        assert_eq!(
            fd_lines[2],
            format!("lock:\t3: POSIX  ADVISORY  READ 100 {fuse_dev_ino} 30 EOF")
        );

        // Once the FUSE instance is gone, its locks are omitted without consuming line numbers
        vfs.fuse_mut().remove(fuse_dev);
        // Add a store record lock (newest) to verify no numbering gap after omitted FUSE entries
        k.locks.set(
            key_a,
            Lock {
                owner: Owner::Ofd(Rc::downgrade(&store_a)),
                file: Rc::downgrade(&store_a),
                pid: -1,
                start: 0,
                end: 10,
                write: true,
                seq: 0,
            },
            false,
        );
        let after_remove = proc_locks(&k, &vfs, &init_ns);
        let after_lines: Vec<&str> = after_remove.lines().collect();
        assert_eq!(after_lines.len(), 3, "{after_remove}");
        assert!(after_lines[0].starts_with("1: OFDLCK ADVISORY  WRITE -1 08:01:10 0 9"));
        assert!(after_lines[1].starts_with("2: FLOCK  ADVISORY  READ 200 08:01:20 0 EOF"));
        assert!(after_lines[2].starts_with("3: FLOCK  ADVISORY  WRITE 100 08:01:10 0 EOF"));
        assert!(fd_locks(&k, &vfs, &init_ns, &fds, &fuse_file).is_empty());

        // Pid-namespace filtering still skips line numbers for invisible PIDs on shown locks
        let child_ns = PidNs::child(&init_ns, root_cred.user_ns.clone());
        PidNs::register(&child_ns, 100, &[]).unwrap();
        let child_listing = proc_locks(&k, &vfs, &child_ns);
        let child_lines: Vec<&str> = child_listing.lines().collect();
        assert_eq!(child_lines.len(), 2, "{child_listing}");
        assert!(child_lines[0].starts_with("1: OFDLCK ADVISORY  WRITE -1 08:01:10 0 9"));
        assert!(child_lines[1].starts_with("3: FLOCK  ADVISORY  WRITE 1 08:01:10 0 EOF"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn posix_fdinfo_shows_taking_file_and_proc_locks_lists_waiters() {
        use crate::cred::Cred;

        let (dir, vfs) = temp_vfs("waiters");
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let init_ns = PidNs::init();

        // Two distinct open files on the same inode in one fd table: taking a POSIX lock on the
        // second (higher fd) must appear only in the second file's fdinfo, not the first's.
        let (file1, file2) = (null_file(42), null_file(42));
        let fds_holder = Rc::new(RefCell::new(FdTable::new()));
        fds_holder
            .borrow_mut()
            .install(file1.clone(), false, 0..16)
            .unwrap();
        fds_holder
            .borrow_mut()
            .install(file2.clone(), false, 0..16)
            .unwrap();
        let key = LockKey::of(&file2.borrow()).unwrap();
        k.locks.set(
            key,
            Lock {
                owner: Owner::Posix(Rc::downgrade(&fds_holder)),
                file: Rc::downgrade(&file2),
                pid: 100,
                start: 10,
                end: 30,
                write: true,
                seq: 0,
            },
            false,
        );

        assert!(fd_locks(&k, &vfs, &init_ns, &fds_holder, &file1).is_empty());
        assert_eq!(
            fd_locks(&k, &vfs, &init_ns, &fds_holder, &file2),
            "lock:\t1: POSIX  ADVISORY  WRITE 100 08:01:42 10 29\n"
        );

        // Two blocked waiters (one POSIX, one OFD) appear as `->` lines under the blocking lock.
        let fds_waiter = Rc::new(RefCell::new(FdTable::new()));
        let (waiter_file, ofd_waiter_file) = (null_file(42), null_file(42));
        k.locks.set_waiting(
            200,
            Some(Waiter {
                tid: 200,
                key,
                req: Lock {
                    owner: Owner::Posix(Rc::downgrade(&fds_waiter)),
                    file: Rc::downgrade(&waiter_file),
                    pid: 200,
                    start: 15,
                    end: 45,
                    write: true,
                    seq: 0,
                },
            }),
        );
        k.locks.set_waiting(
            201,
            Some(Waiter {
                tid: 201,
                key,
                req: Lock {
                    owner: Owner::Ofd(Rc::downgrade(&ofd_waiter_file)),
                    file: Rc::downgrade(&ofd_waiter_file),
                    pid: -1,
                    start: 0,
                    end: u64::MAX,
                    write: false,
                    seq: 0,
                },
            }),
        );
        let listing = proc_locks(&k, &vfs, &init_ns);
        let lines: Vec<&str> = listing.lines().collect();
        assert_eq!(
            lines,
            vec![
                "1: POSIX  ADVISORY  WRITE 100 08:01:42 10 29",
                "1: -> POSIX  ADVISORY  WRITE 200 08:01:42 15 44",
                "1: -> OFDLCK ADVISORY  READ -1 08:01:42 0 EOF",
            ]
        );
        // fdinfo never lists blocked waiters.
        assert_eq!(
            fd_locks(&k, &vfs, &init_ns, &fds_holder, &file2),
            "lock:\t1: POSIX  ADVISORY  WRITE 100 08:01:42 10 29\n"
        );

        // Pid-namespace filtering omits invisible waiters while preserving visible ones.
        let child_ns = PidNs::child(&init_ns, Cred::root().user_ns.clone());
        PidNs::register(&child_ns, 100, &[]).unwrap();
        let child_listing = proc_locks(&k, &vfs, &child_ns);
        let child_lines: Vec<&str> = child_listing.lines().collect();
        assert_eq!(
            child_lines,
            vec![
                "1: POSIX  ADVISORY  WRITE 1 08:01:42 10 29",
                "1: -> OFDLCK ADVISORY  READ -1 08:01:42 0 EOF",
            ]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
