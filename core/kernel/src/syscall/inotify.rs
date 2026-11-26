//! inotify (the kernel/inotify map): inotify_init1, inotify_add_watch, inotify_rm_watch, and reads
//! from it.
//!
//! Every filesystem change goes through the kernel layer, and each syscall reports its events
//! after changing the store, at the same places and in the same order as Linux's fsnotify hooks.
//! Watches are registered in [`Registry`] by store inode; with no watches at all, each event costs
//! only one emptiness check.
//!
//! - Events on a file are also reported to the watches of its directory (with the name). For
//!   path-based operations, the path is resolved a second time to find the directory only when
//!   there are watches ([`watched_at`]). For fd-based operations (reads, writes, truncation,
//!   close) the directory and name the open went through are used: every open store file carries
//!   an [`Opened`] recording them, the equivalent of the dentry a Linux open file references. They
//!   are updated when rename moves the dentry ([`renamed`]); after deletion they stay unchanged
//!   and, as on Linux, events still go to the original directory.
//! - `IN_CLOSE_*` is reported when the last reference to the open file is released ([`Opened`]
//!   dropped), the same as Linux's fput.
//! - `IN_DELETE_SELF` is reported when the last link is removed; while files opened through the
//!   removed name are still open, it is reported after they have all closed ([`deleted`]), the
//!   same as Linux reporting it when the last reference to the dentry is released.
//! - Events on directories carry `IN_ISDIR`; `IN_DELETE_SELF` and `IN_MOVE_SELF` do not, as
//!   inotify always has (Linux leaves it out deliberately for compatibility with old programs).
//! - In an overlay, watches and events are on the overlay's nodes (Linux's overlay inodes and
//!   dentries), registered under their [`crate::vfs::overlay::key`]: what is done through the
//!   overlay is reported to the node and its overlay directory, not to the layers' inodes behind
//!   it, which copying up changes. Linux's overlay also changes the upper layer through the VFS,
//!   which reports there too; here only creations are also reported to the upper directory.
//! - Watches can be added on synthetic filesystems, but only cgroup2 files and directories get
//!   events ([`kernfs_modified`]).
//! - As on Linux: an event identical to the unread event at the tail of the queue is merged; once
//!   `max_queued_events` events are queued, new ones are dropped and one `IN_Q_OVERFLOW` is
//!   queued. Each user's (effective uid's) instances and watches are limited by
//!   `max_user_instances` and `max_user_watches`; going over is EMFILE and ENOSPC respectively.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::rc::{Rc, Weak};

use super::{SysResult, read_path};
use crate::cell::RefCell;
use crate::cred::MAY_READ;
use crate::errno::Errno;
use crate::fd::{FileKind, OpenFile, oflags};
use crate::kernel::{Cx, Kernel, request_wake_object, wake};
use crate::vfs::browse::Change;
use crate::vfs::store::Ino;
use crate::vfs::{Node, overlay};

pub(crate) const IN_ACCESS: u32 = 0x1;
pub(crate) const IN_MODIFY: u32 = 0x2;
pub(crate) const IN_ATTRIB: u32 = 0x4;
pub(crate) const IN_CLOSE_WRITE: u32 = 0x8;
pub(crate) const IN_CLOSE_NOWRITE: u32 = 0x10;
pub(crate) const IN_OPEN: u32 = 0x20;
pub(crate) const IN_MOVED_FROM: u32 = 0x40;
pub(crate) const IN_MOVED_TO: u32 = 0x80;
pub(crate) const IN_CREATE: u32 = 0x100;
pub(crate) const IN_DELETE: u32 = 0x200;
pub(crate) const IN_DELETE_SELF: u32 = 0x400;
pub(crate) const IN_MOVE_SELF: u32 = 0x800;
const IN_ALL_EVENTS: u32 = 0xfff;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
pub(crate) const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;
/// Events reported only to the object itself, not to its directory.
const SELF_EVENTS: u32 = IN_DELETE_SELF | IN_MOVE_SELF;

/// The most events queued in one instance (the default of `max_queued_events`).
const MAX_QUEUED: usize = 16384;
/// The most instances per user (the default of `max_user_instances`).
const MAX_INSTANCES: usize = 128;
/// The most watches per user (the default of `max_user_watches`).
const MAX_WATCHES: usize = 1 << 20;

// ---- Instances and watches ----

struct Watch {
    node: Node,
    mask: u32,
    /// The inode number shown in fdinfo.
    ino: Ino,
    /// The filesystem device in the kernel's internal encoding.
    sdev: u64,
}

impl Watch {
    /// Bind mounts share a watch. Store, overlay and FUSE node IDs are unique across
    /// instances, while the same synthetic node can occur on separate superblocks.
    fn same_inode(&self, other: &Watch) -> bool {
        match (&self.node, &other.node) {
            (Node::Store(_, a), Node::Store(_, b))
            | (Node::Overlay(_, a), Node::Overlay(_, b))
            | (Node::Fuse(_, a), Node::Fuse(_, b)) => a == b,
            (Node::Pseudo(_, a), Node::Pseudo(_, b)) => a == b && self.sdev == other.sdev,
            _ => false,
        }
    }
}

#[derive(PartialEq)]
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Vec<u8>,
}

impl Event {
    /// The length read gives: a 16-byte `struct inotify_event`, with the name padded with NULs
    /// to a multiple of 16 bytes.
    fn len(&self) -> usize {
        16 + if self.name.is_empty() {
            0
        } else {
            (self.name.len() + 1).next_multiple_of(16)
        }
    }
}

/// An inotify instance.
pub struct Inotify {
    watches: BTreeMap<i32, Watch>,
    last_wd: i32,
    queue: VecDeque<Event>,
    /// Total length of the queued events (FIONREAD).
    bytes: usize,
    /// The queue holds an `IN_Q_OVERFLOW`.
    overflowed: bool,
    /// Number of events queued (`EPOLLET` fires for each one queued).
    queued: u64,
    /// The most events to queue: as on Linux, `max_queued_events` at creation time.
    max_queued: usize,
    /// The creator's effective uid: instances and watches are charged to this user.
    uid: u32,
    /// The [`Registry`] the watches are registered in: when the instance is closed it removes its
    /// watches from it.
    registry: Weak<RefCell<Registry>>,
}

impl Default for Inotify {
    fn default() -> Inotify {
        Inotify {
            watches: BTreeMap::new(),
            last_wd: 0,
            queue: VecDeque::new(),
            bytes: 0,
            overflowed: false,
            queued: 0,
            max_queued: MAX_QUEUED,
            uid: 0,
            registry: Weak::new(),
        }
    }
}

impl Inotify {
    fn push(&mut self, wd: i32, mask: u32, cookie: u32, name: &[u8]) {
        // Check queue overflow before tail merging, as Linux's fsnotify_add_event does: when the
        // queue is already full, even an event identical to the last one queues IN_Q_OVERFLOW.
        let event = if self.queue.len() >= self.max_queued {
            if self.overflowed {
                return;
            }
            self.overflowed = true;
            Event {
                wd: -1,
                mask: IN_Q_OVERFLOW,
                cookie: 0,
                name: Vec::new(),
            }
        } else {
            let event = Event {
                wd,
                mask,
                cookie,
                name: name.to_vec(),
            };
            if self.queue.back() == Some(&event) {
                return;
            }
            event
        };
        self.bytes += event.len();
        self.queue.push_back(event);
        self.queued += 1;
        request_wake_object(wake::of_value(self));
    }

    /// Whether there are events to read.
    pub fn ready(&self) -> bool {
        !self.queue.is_empty()
    }

    /// How many events have been queued in total.
    pub fn queued(&self) -> u64 {
        self.queued
    }

    /// The number of readable bytes.
    pub fn pending(&self) -> usize {
        self.bytes
    }

    /// One line per watch in `/proc/<pid>/fdinfo/<fd>`, in the same format as Linux. Files in the
    /// store carry the handle name_to_handle_at gives.
    pub fn fdinfo(&self) -> String {
        let mut out = String::new();
        for (wd, w) in &self.watches {
            out += &format!(
                "inotify wd:{wd:x} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:0",
                w.ino, w.sdev, w.mask
            );
            if let Node::Store(_, ino) = w.node {
                let handle: String = ino
                    .to_le_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                out += &format!(" fhandle-bytes:8 fhandle-type:1 f_handle:{handle}");
            }
            out.push('\n');
        }
        out
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let Ok(mut r) = registry.try_borrow_mut() else {
            return;
        };
        let user = r.users.entry(self.uid).or_default();
        user.0 = user.0.saturating_sub(1);
        user.1 = user.1.saturating_sub(self.watches.len());
        for w in self.watches.values() {
            if let Some(ino) = key_of(&w.node)
                && let Some(list) = r.by_ino.get_mut(&ino)
            {
                // An instance being dropped has no strong references left, so all weak
                // references to it are dead
                list.retain(|(weak, _)| weak.strong_count() > 0);
                if list.is_empty() {
                    r.by_ino.remove(&ino);
                    r.doomed.remove(&ino);
                }
            }
        }
    }
}

pub(super) fn inotify_init1(cx: &mut Cx<'_>, flags: u32) -> SysResult {
    if flags & !(oflags::O_CLOEXEC | oflags::O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let uid = cx.cred().euid;
    let registry = cx.kr().inotify.clone();
    let mut r = registry.borrow_mut();
    if r.users.get(&uid).map_or(0, |u| u.0) >= r.max_instances {
        return Err(Errno::EMFILE);
    }
    r.users.entry(uid).or_default().0 += 1;
    let mut inotify = Inotify::default();
    inotify.max_queued = r.max_queued;
    inotify.uid = uid;
    inotify.registry = Rc::downgrade(&registry);
    drop(r);
    // If it does not fit in the fd table the instance is dropped here, and the counts are
    // returned with it
    let file = OpenFile::new(
        FileKind::Inotify(Rc::new(RefCell::new(inotify))),
        oflags::O_RDONLY | (flags & oflags::O_NONBLOCK),
    );
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

pub(super) fn inotify_add_watch(cx: &mut Cx<'_>, fd: i32, path: u64, mask: u32) -> SysResult {
    let inotify = inotify_of(cx, fd)?;
    let path = read_path(cx, path)?;
    if mask & IN_ALL_EVENTS == 0 || mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
        return Err(Errno::EINVAL);
    }
    let node = super::fs::lookup_at(cx, super::fs::AT_FDCWD, &path, mask & IN_DONT_FOLLOW == 0)?;
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    // Magic links to unlinked regular files, memfds, or deleted executables resolve to the
    // underlying inode so watches on `/proc/<pid>/fd/<n>` or `/proc/<pid>/exe` receive events.
    let node = match &node {
        Node::Pseudo(_, crate::pseudo::PseudoNode::OpenFd(proc, tid, fd)) => {
            let source = view.open_file(*proc, *tid, *fd).ok_or(Errno::ENOENT)?;
            let source = source.borrow();
            if let Some(o) = source.ovl {
                Node::Overlay(source.mnt, o)
            } else if let Some((ino, ..)) = source.regular_backing() {
                Node::Store(source.mnt, ino)
            } else {
                source.node().unwrap_or(node)
            }
        }
        Node::Pseudo(_, crate::pseudo::PseudoNode::OpenExe(proc)) => {
            super::fs::exe_file(cx, *proc)?.backing(&vfs)?.0
        }
        _ => node,
    };
    if mask & IN_ONLYDIR != 0 && !vfs.is_dir(&view, &node)? {
        return Err(Errno::ENOTDIR);
    }
    // fdinfo encodes the filesystem device as (major << 20) | minor.
    let internal = |dev: u64| {
        let major = (dev >> 8) & 0xfff | (dev >> 32) & !0xfff;
        let minor = dev & 0xff | (dev >> 12) & !0xff;
        major << 20 | minor
    };
    let (ino, sdev) = match &node {
        Node::Store(_, ino) => {
            // Use the database row (`attrs`): unlinked files and memfds have no host path left.
            cx.cred().permission(&vfs.store().attrs(*ino)?, MAY_READ)?;
            (*ino, internal(vfs.dev_of(&node)))
        }
        Node::Overlay(_, o) => {
            let st = vfs.overlay_stat(*o)?;
            cx.cred().permission(&st, MAY_READ)?;
            (st.ino, internal(vfs.dev_of(&node)))
        }
        Node::Pseudo(_, p) => {
            // A namespace file belongs to nsfs even when reached through procfs.
            let dev = if matches!(p, crate::pseudo::PseudoNode::NsFile(..)) {
                crate::vfs::Fs::Nsfs.dev()
            } else {
                vfs.dev_of(&node)
            };
            (crate::pseudo::node_ino(p), internal(dev))
        }
        Node::Fuse(_, f) => {
            vfs.fuse_permission(&cx.cred(), *f, MAY_READ)?;
            let ino = crate::vfs::fuse::cached_attr(&vfs, *f)?.ino;
            (ino, internal(vfs.dev_of(&node)))
        }
    };
    // A cgroup2 file, or a cgroup's directory, starts being looked at for changes
    match &node {
        Node::Pseudo(_, crate::pseudo::PseudoNode::Cgroup(id, b"", 0)) => {
            crate::cgroup::observe_all(cx.k(), *id);
        }
        Node::Pseudo(_, crate::pseudo::PseudoNode::Cgroup(id, name, _)) => {
            crate::cgroup::observe(cx.k(), *id, name);
        }
        _ => {}
    }
    let watch = Watch {
        node,
        mask: mask & (IN_ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT),
        ino,
        sdev,
    };
    let mut i = inotify.borrow_mut();
    // The same object already has a watch: change its mask (merged with IN_MASK_ADD)
    if let Some((&wd, w)) = i.watches.iter_mut().find(|(_, w)| w.same_inode(&watch)) {
        if mask & IN_MASK_CREATE != 0 {
            return Err(Errno::EEXIST);
        }
        w.mask = if mask & IN_MASK_ADD != 0 {
            w.mask | watch.mask
        } else {
            watch.mask
        };
        return Ok(wd as u64);
    }
    let registry = cx.kr().inotify.clone();
    let mut r = registry.borrow_mut();
    let user = r.users.get(&i.uid).map_or(0, |u| u.1);
    if user >= r.max_watches {
        return Err(Errno::ENOSPC);
    }
    i.last_wd = i.last_wd.checked_add(1).ok_or(Errno::ENOSPC)?;
    r.users.entry(i.uid).or_default().1 += 1;
    let wd = i.last_wd;
    if let Some(ino) = key_of(&watch.node) {
        r.by_ino
            .entry(ino)
            .or_default()
            .push((Rc::downgrade(&inotify), wd));
    }
    i.watches.insert(wd, watch);
    Ok(wd as u64)
}

pub(super) fn inotify_rm_watch(cx: &mut Cx<'_>, fd: i32, wd: i32) -> SysResult {
    let inotify = inotify_of(cx, fd)?;
    let mut i = inotify.borrow_mut();
    let w = i.watches.remove(&wd).ok_or(Errno::EINVAL)?;
    i.push(wd, IN_IGNORED, 0, b"");
    let mut r = cx.kr().inotify.borrow_mut();
    r.uncharge(i.uid);
    if let Some(ino) = key_of(&w.node)
        && let Some(list) = r.by_ino.get_mut(&ino)
    {
        list.retain(|(weak, w)| !(*w == wd && weak.ptr_eq(&Rc::downgrade(&inotify))));
        if list.is_empty() {
            r.by_ino.remove(&ino);
            r.doomed.remove(&ino);
        }
    }
    Ok(0)
}

fn inotify_of(cx: &Cx<'_>, fd: i32) -> Result<Rc<RefCell<Inotify>>, Errno> {
    match &cx.fds().get(fd)?.borrow().kind {
        FileKind::Inotify(i) => Ok(i.clone()),
        _ => Err(Errno::EINVAL),
    }
}

/// Reads the queued events: as many as fit, EINVAL if not even the first fits; blocks when there
/// are none.
pub(super) fn read(
    cx: &mut Cx<'_>,
    inotify: &Rc<RefCell<Inotify>>,
    nonblock: bool,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    loop {
        {
            let mut i = inotify.borrow_mut();
            if let Some(first) = i.queue.front() {
                if first.len() > buf.len() {
                    return Err(Errno::EINVAL);
                }
                let mut n = 0;
                while let Some(e) = i.queue.front() {
                    let len = e.len();
                    if n + len > buf.len() {
                        break;
                    }
                    let out = &mut buf[n..n + len];
                    out.fill(0);
                    out[0..4].copy_from_slice(&e.wd.to_le_bytes());
                    out[4..8].copy_from_slice(&e.mask.to_le_bytes());
                    out[8..12].copy_from_slice(&e.cookie.to_le_bytes());
                    out[12..16].copy_from_slice(&((len - 16) as u32).to_le_bytes());
                    out[16..16 + e.name.len()].copy_from_slice(&e.name);
                    if e.mask == IN_Q_OVERFLOW {
                        i.overflowed = false;
                    }
                    i.bytes -= len;
                    i.queue.pop_front();
                    n += len;
                }
                return Ok(n);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_objects(None, &mut [], wake::FILE, &[wake::of(inotify)])?;
    }
}

// ---- Reporting ----

/// An instance and wd watching some inode.
type Watcher = (Weak<RefCell<Inotify>>, i32);

/// All watches, by watched inode.
pub struct Registry {
    /// The (instance, wd) pairs on each inode: a store inode number, or an overlay, FUSE or
    /// cgroup2 node key. The weak references die once the instance is closed and are cleared the
    /// next time they are come across.
    by_ino: HashMap<Ino, Vec<Watcher>>,
    last_cookie: u32,
    /// Instance and watch counts per user (effective uid).
    users: HashMap<u32, (usize, usize)>,
    /// The three limits under `/proc/sys/fs/inotify/`.
    pub max_queued: usize,
    pub max_instances: usize,
    pub max_watches: usize,
    /// Inodes whose last link has been removed but that still have files open through that name:
    /// `IN_DELETE_SELF` is reported once those files have all closed.
    doomed: HashMap<Ino, Vec<Weak<OpenRecord>>>,
    /// Live file descriptions, including files held by exec rather than in an fd table.
    opened: BTreeMap<(Ino, usize), Weak<OpenRecord>>,
}

impl Default for Registry {
    fn default() -> Registry {
        Registry {
            by_ino: HashMap::new(),
            last_cookie: 0,
            users: HashMap::new(),
            max_queued: MAX_QUEUED,
            max_instances: MAX_INSTANCES,
            max_watches: MAX_WATCHES,
            doomed: HashMap::new(),
            opened: BTreeMap::new(),
        }
    }
}

impl Registry {
    fn opens_of(&self, ino: Ino) -> impl Iterator<Item = Rc<OpenRecord>> + '_ {
        self.opened
            .range((ino, 0)..=(ino, usize::MAX))
            .filter_map(|(_, f)| f.upgrade())
    }

    pub(crate) fn has_open(&self, ino: Ino) -> bool {
        self.opened
            .range((ino, 0)..=(ino, usize::MAX))
            .any(|(_, f)| f.strong_count() > 0)
    }

    pub(crate) fn watches(&self, ino: Ino) -> bool {
        self.by_ino.contains_key(&ino)
    }

    /// The inodes (and node keys) with watches on them.
    pub(crate) fn watched(&self) -> impl Iterator<Item = Ino> + '_ {
        self.by_ino.keys().copied()
    }

    /// An event of `ino` itself: reported first to the watches of its directory `parent` (with
    /// the name), then to its own. When `unlinked` is true, watches with `IN_EXCL_UNLINK` skip
    /// the event. Each instance that got an event requests a wakeup (`Inotify::push`).
    fn notify(&mut self, ino: Ino, parent: Option<(Ino, &[u8])>, mask: u32, unlinked: bool) {
        if let Some((dir, name)) = parent
            && mask & SELF_EVENTS == 0
        {
            self.deliver(dir, mask, 0, name, unlinked);
        }
        self.deliver(ino, mask, 0, b"", unlinked);
    }

    /// Hands an event to the watches on `ino` that want it; returns whether any event was queued
    /// (instances that queue an event request a wakeup, see `Inotify::push`). When `unlinked` is
    /// true, watches with `IN_EXCL_UNLINK` ignore the event (Linux's `d_unlinked` check on
    /// path-based open/access/modify/close events).
    fn deliver(&mut self, ino: Ino, mask: u32, cookie: u32, name: &[u8], unlinked: bool) -> bool {
        let Some(list) = self.by_ino.get_mut(&ino) else {
            return false;
        };
        let mut queued = false;
        let mut gone = Vec::new();
        list.retain(|(weak, wd)| {
            let Some(inotify) = weak.upgrade() else {
                return false;
            };
            let Ok(mut inotify) = inotify.try_borrow_mut() else {
                return true;
            };
            let Some(wmask) = inotify.watches.get(wd).map(|w| w.mask) else {
                return false;
            };
            let excluded = wmask & IN_EXCL_UNLINK != 0 && unlinked && !crate::cgroup::is_key(ino);
            let wanted = mask & wmask & IN_ALL_EVENTS != 0 && !excluded;
            if wanted {
                inotify.push(*wd, mask, cookie, name);
                queued = true;
            }
            // The object is gone, or a one-shot watch has already reported: remove the watch and
            // report IN_IGNORED
            if mask & IN_DELETE_SELF != 0 || wanted && wmask & IN_ONESHOT != 0 {
                inotify.watches.remove(wd);
                inotify.push(*wd, IN_IGNORED, 0, b"");
                gone.push(inotify.uid);
                queued = true;
                return false;
            }
            true
        });
        if list.is_empty() {
            self.by_ino.remove(&ino);
            self.doomed.remove(&ino);
        }
        for uid in gone {
            self.uncharge(uid);
        }
        queued
    }

    /// User `uid` has one watch fewer.
    fn uncharge(&mut self, uid: u32) {
        let user = self.users.entry(uid).or_default();
        user.1 = user.1.saturating_sub(1);
    }

    /// An open file was closed: if it was the last file opened through a deleted name, report
    /// `IN_DELETE_SELF`.
    fn closed(&mut self, ino: Ino) {
        let Some(list) = self.doomed.get_mut(&ino) else {
            return;
        };
        // An open file being dropped has no strong references left
        list.retain(|f| f.strong_count() > 0);
        if list.is_empty() {
            self.doomed.remove(&ino);
            self.notify(ino, None, IN_DELETE_SELF, false);
        }
    }
}

/// Carried by an open store, overlay or FUSE file: fd-based events are reported to its directory
/// through it, `unlinked` tracks whether its dentry was unlinked (`IN_EXCL_UNLINK`), and
/// `IN_CLOSE_WRITE` or `IN_CLOSE_NOWRITE` is reported when the last reference is released.
#[derive(Clone)]
pub struct Opened(Rc<OpenRecord>);

struct OpenRecord {
    registry: Weak<RefCell<Registry>>,
    ino: Ino,
    parent: RefCell<Option<(Ino, Vec<u8>)>>,
    close: u32,
    unlinked: std::cell::Cell<bool>,
}

impl Opened {
    fn new(
        registry: &Rc<RefCell<Registry>>,
        ino: Ino,
        parent: Option<(Ino, Vec<u8>)>,
        close: u32,
        unlinked: bool,
    ) -> Self {
        let record = Rc::new(OpenRecord {
            registry: Rc::downgrade(registry),
            ino,
            parent: RefCell::new(parent),
            close,
            unlinked: unlinked.into(),
        });
        let weak = Rc::downgrade(&record);
        let mut r = registry.borrow_mut();
        if let Some(doomed) = r.doomed.get_mut(&ino) {
            doomed.push(weak.clone());
        }
        r.opened.insert((ino, Rc::as_ptr(&record).addr()), weak);
        Self(record)
    }

    pub(crate) fn is_unlinked(&self) -> bool {
        self.0.unlinked.get()
    }

    /// The current parent and name in the mount through which this file was opened.
    pub(crate) fn dentry(&self, original: &Node) -> Option<crate::vfs::Dentry> {
        let parent = self.0.parent.borrow();
        let (key, name) = parent.as_ref()?;
        let mnt = original.mnt();
        let dir = match original {
            Node::Store(..) => Node::Store(mnt, *key),
            Node::Fuse(..) => Node::Fuse(mnt, crate::vfs::fuse::id_of(*key)?),
            Node::Overlay(..) => Node::Overlay(mnt, overlay::of_key(*key)?),
            Node::Pseudo(..) => return None,
        };
        Some((dir, name.clone()))
    }

    /// A magic-link reopen has its own last close at the original dentry, even after unlink.
    pub(super) fn reopen(&self, k: &Kernel, writable: bool) -> Self {
        let (ino, parent, unlinked) = self.location();
        Self::open(k, ino, parent, close_mask(writable), unlinked)
    }

    fn open(
        k: &Kernel,
        ino: Ino,
        parent: Option<(Ino, Vec<u8>)>,
        close: u32,
        unlinked: bool,
    ) -> Self {
        let open = Self::new(&k.inotify, ino, parent, close, unlinked);
        if active(k) {
            open.0
                .notify(&mut k.inotify.borrow_mut(), IN_OPEN, unlinked);
        }
        open
    }

    fn location(&self) -> (Ino, Option<(Ino, Vec<u8>)>, bool) {
        (
            self.0.ino,
            self.0.parent.borrow().clone(),
            self.is_unlinked(),
        )
    }
}

impl OpenRecord {
    fn at(&self, dir: Ino, name: &[u8]) -> bool {
        self.parent
            .borrow()
            .as_ref()
            .is_some_and(|(d, n)| *d == dir && n == name)
    }

    fn notify(&self, r: &mut Registry, mask: u32, unlinked: bool) {
        let parent = self.parent.borrow();
        r.notify(
            self.ino,
            parent.as_ref().map(|(d, n)| (*d, n.as_slice())),
            mask,
            unlinked,
        );
    }
}

impl Drop for OpenRecord {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade()
            && let Ok(mut r) = registry.try_borrow_mut()
        {
            r.opened
                .remove(&(self.ino, std::ptr::from_ref(self).addr()));
            if self.close != 0 && !r.by_ino.is_empty() {
                self.notify(&mut r, self.close, self.unlinked.get());
            }
            if !r.doomed.is_empty() {
                r.closed(self.ino);
            }
        }
    }
}

/// There are watches: callers use this to decide whether to query the store once more to report
/// an event.
pub(crate) fn active(k: &Kernel) -> bool {
    !idle(k)
}

/// What events of node `node` are keyed by: a store inode's number, an overlay node's
/// [`overlay::key`]; None for synthetic nodes, which never report.
pub(crate) fn key_of(node: &Node) -> Option<Ino> {
    match node {
        Node::Store(_, ino) => Some(*ino),
        Node::Overlay(_, o) => Some(overlay::key(*o)),
        Node::Fuse(_, f) => Some(crate::vfs::fuse::key(*f)),
        // cgroup2 files report the changes Linux notifies (crate::cgroup::notify_changes)
        Node::Pseudo(_, crate::pseudo::PseudoNode::Cgroup(id, name, _)) => {
            Some(crate::cgroup::key(*id, name))
        }
        Node::Pseudo(..) => None,
    }
}

/// A notifying cgroup2 file (inotify key `key`, and optionally its directory's `(dir, name)` when
/// the child file's dentry has been instantiated) changed: `IN_MODIFY` to the watches on the file
/// and, when instantiated, on its directory, matching Linux's `kernfs_notify`.
pub(crate) fn kernfs_modified(k: &Kernel, key: Ino, dir: Option<(Ino, &[u8])>) {
    if let Ok(mut r) = k.inotify.try_borrow_mut() {
        r.notify(key, dir, IN_MODIFY, false);
    }
}

/// What events of a path-based operation go to: `ino`, the store inode it changed, or the
/// overlay/FUSE node the path names, and the directory and name (for the directory's watches).
/// The path is resolved again only when there are watches.
pub(crate) fn watched_at(
    cx: &Cx<'_>,
    ino: Ino,
    (dirfd, path): (i32, &[u8]),
    follow: bool,
) -> (Ino, Option<(Ino, Vec<u8>)>) {
    if idle(cx.kr()) || path.is_empty() {
        return (ino, None);
    }
    let found = (|| {
        let vfs = cx.vfs().ok()?;
        let start = super::fs::start_dir(cx, dirfd, path).ok()?;
        vfs.walk(&cx.view(&vfs), &cx.cred(), &cx.root(), &start, path, follow)
            .ok()
    })();
    let Some((node, dentry)) = found else {
        // After a FUSE change that staled cached attributes, fall back to the node's recorded
        // parent and name so the directory watch still receives the event.
        if let Some(f) = crate::vfs::fuse::id_of(ino)
            && let Ok(vfs) = cx.vfs()
            && let Some(n) = vfs.fuse().get(f)
            && n.parent != f
            && !n.name.is_empty()
        {
            return (ino, Some((crate::vfs::fuse::key(n.parent), n.name.clone())));
        }
        return (ino, None);
    };
    let target = match node {
        Node::Overlay(_, o) => overlay::key(o),
        Node::Fuse(_, f) => crate::vfs::fuse::key(f),
        _ => ino,
    };
    let parent = dentry.and_then(|(dir, name)| Some((key_of(&dir)?, name)));
    (target, parent)
}

/// An event of the object `ino` itself in a path-based operation; `parent` is its directory and
/// name.
pub(crate) fn path_event(k: &Kernel, ino: Ino, parent: Option<(Ino, &[u8])>, mask: u32) {
    path_event_unlinked(k, ino, parent, mask, false);
}

/// Like [`path_event`], but honours `IN_EXCL_UNLINK` when `unlinked` is true (e.g. `IN_OPEN` of
/// an unlinked file reopened through `/proc/<pid>/fd/N`).
pub(crate) fn path_event_unlinked(
    k: &Kernel,
    ino: Ino,
    parent: Option<(Ino, &[u8])>,
    mask: u32,
    unlinked: bool,
) {
    if !idle(k) {
        k.inotify.borrow_mut().notify(ino, parent, mask, unlinked);
    }
}

/// A metadata or truncation event on an open file (`fchmod`, `fchown`, `futimens`, `ftruncate`,
/// `fsetxattr`, `fremovexattr`): Linux's `fsnotify_change`/`fsnotify_xattr` pass the inode rather
/// than the path, so `IN_EXCL_UNLINK` does not filter them.
pub(crate) fn file_event(k: &Kernel, f: &OpenFile, mask: u32) {
    file_event_inner(k, f, mask, false);
}

/// A file-I/O event on an open file (`read`, `write`, `getdents64`, `fallocate`, copies): Linux's
/// `fsnotify_access`/`fsnotify_modify` pass the open file's dentry, so watches with
/// `IN_EXCL_UNLINK` (both directory and file watches) skip events on an unlinked name.
pub(crate) fn file_io_event(k: &Kernel, f: &OpenFile, mask: u32) {
    let unlinked = f.dentry_unlinked();
    file_event_inner(k, f, mask, unlinked);
}

fn file_event_inner(k: &Kernel, f: &OpenFile, mask: u32, unlinked: bool) {
    if idle(k) {
        return;
    }
    let Some((ino, dir)) = file_key(f) else {
        return;
    };
    let mask = mask | dir;
    let mut registry = k.inotify.borrow_mut();
    if let Some(open) = &f.watch {
        open.0.notify(&mut registry, mask, unlinked);
    } else {
        registry.notify(ino, None, mask, unlinked);
    }
}

/// A child named `name` in directory `dir` was created, deleted, moved in or moved out.
pub(crate) fn dir_event(k: &Kernel, dir: Ino, name: &[u8], mask: u32, cookie: u32) {
    if !idle(k) {
        k.inotify
            .borrow_mut()
            .deliver(dir, mask, cookie, name, false);
    }
}

/// The cookie shared by the two events of a rename.
pub(crate) fn cookie(k: &Kernel) -> u32 {
    let mut r = k.inotify.borrow_mut();
    r.last_cookie = r.last_cookie.wrapping_add(1);
    r.last_cookie
}

/// What events of open file `f` are keyed by, and `IN_ISDIR` for a directory: its store inode,
/// or the overlay node it was opened through (whose store inode copying up changes). None for
/// other kinds of files.
fn file_key(f: &OpenFile) -> Option<(Ino, u32)> {
    match &f.kind {
        FileKind::Regular { ino, .. } | FileKind::Device { ino, .. } => {
            Some((f.ovl.map_or(*ino, overlay::key), 0))
        }
        FileKind::Pipe(_) | FileKind::Pty(_) => Some((key_of(&f.node()?)?, 0)),
        FileKind::Directory { node, .. } => Some((key_of(node)?, IN_ISDIR)),
        FileKind::Fuse(h) => Some((crate::vfs::fuse::key(h.id), 0)),
        FileKind::Proc {
            node: crate::pseudo::PseudoNode::Cgroup(id, name, _),
            ..
        } if !name.is_empty() => Some((crate::cgroup::key(*id, name), 0)),
        _ => None,
    }
}

fn close_mask(writable: bool) -> u32 {
    if writable {
        IN_CLOSE_WRITE
    } else {
        IN_CLOSE_NOWRITE
    }
}

/// The [`Opened`] a newly opened store, overlay or FUSE file carries. `parent` is the directory
/// and name the open went through; `unlinked` is true when reopened from an already-unlinked file.
pub(crate) fn opened(
    k: &Kernel,
    f: &OpenFile,
    parent: Option<(Ino, Vec<u8>)>,
    unlinked: bool,
) -> Option<Opened> {
    if let FileKind::Path(node) = &f.kind {
        return Some(Opened::new(&k.inotify, key_of(node)?, parent, 0, unlinked));
    }
    let (ino, dir) = file_key(f)?;
    let parent = parent.or_else(|| match &f.kind {
        FileKind::Proc {
            node: crate::pseudo::PseudoNode::Cgroup(id, name, _),
            ..
        } if !name.is_empty() => Some((crate::cgroup::key(*id, b""), name.to_vec())),
        _ => None,
    });
    let close = close_mask(f.writable());
    Some(Opened::new(&k.inotify, ino, parent, dir | close, unlinked))
}

/// One exec's logical opens. A FUSE retry walks the same prefix again, sometimes
/// after another task renamed or replaced a file. Reuse only the matching opens.
#[derive(Default)]
pub(super) struct ExecOpens {
    files: Vec<(Opened, usize)>,
    next: usize,
    pending_fuse: Option<(Ino, Option<crate::vfs::Dentry>)>,
}

impl ExecOpens {
    pub(super) fn retry(&mut self) {
        self.next = 0;
        self.pending_fuse = None;
    }

    pub(super) fn expect_fuse(&mut self, ino: Ino, dentry: Option<crate::vfs::Dentry>) {
        self.pending_fuse = Some((ino, dentry));
    }

    pub(super) fn fuse_opened(&mut self, k: &Kernel, ino: Ino) {
        if let Some((key, dentry)) = self.pending_fuse.take() {
            debug_assert_eq!(key, ino);
            self.push(k, ino, dentry, false, None);
        }
    }

    pub(super) fn push(
        &mut self,
        k: &Kernel,
        ino: Ino,
        dentry: Option<crate::vfs::Dentry>,
        unlinked: bool,
        source: Option<&Opened>,
    ) {
        let (ino, parent, unlinked) = source.map(Opened::location).unwrap_or_else(|| {
            (
                ino,
                dentry.and_then(|(dir, name)| Some((key_of(&dir)?, name))),
                unlinked,
            )
        });
        let same = self.files.get(self.next).is_some_and(|(f, _)| {
            f.0.ino == ino && f.is_unlinked() == unlinked && *f.0.parent.borrow() == parent
        });
        if !same {
            self.close_after(self.next);
            let file = Opened::open(k, ino, parent, IN_CLOSE_NOWRITE, unlinked);
            self.files.push((file, 0));
        }
        self.next += 1;
    }

    /// Report positive reads on the current open up to `count`, skipping those reported on a retry.
    pub(super) fn accessed(&mut self, k: &Kernel, count: usize) {
        let (file, seen) = &mut self.files[self.next - 1];
        if count > *seen {
            if active(k) {
                let mut r = k.inotify.borrow_mut();
                for _ in *seen..count {
                    file.0.notify(&mut r, IN_ACCESS, file.is_unlinked());
                }
            }
            *seen = count;
        }
    }

    fn close_after(&mut self, index: usize) {
        while self.files.len() > index {
            self.files.pop();
        }
    }

    pub(super) fn take_last(&mut self) -> Opened {
        self.close_after(self.next);
        self.next -= 1;
        self.files.pop().unwrap().0
    }

    pub(super) fn close(&mut self) {
        self.close_after(0);
        self.next = 0;
    }
}

/// The name `(dir, name)` of `ino` was unlinked, rmdir'd or replaced by a rename: mark every open
/// file opened through that name as unlinked (`d_unlinked`) so `IN_EXCL_UNLINK` filters its
/// open/access/modify/close events even when another hard link remains or watches are added later.
pub(crate) fn unlinked(k: &Kernel, ino: Ino, dir: Ino, name: &[u8]) {
    for file in k.inotify.borrow().opens_of(ino).filter(|f| f.at(dir, name)) {
        file.unlinked.set(true);
    }
}

/// rename moved dentry `from` to `to`: files opened through it report later fd-based events to
/// the new directory and name (Linux's d_move). `moved` finds the object that was moved: deleted
/// files with the same name are not updated.
pub(crate) fn renamed(
    k: &Kernel,
    from: (Ino, &[u8]),
    to: (Ino, &[u8]),
    moved: impl FnOnce() -> Option<Ino>,
) {
    if k.inotify.borrow().opened.is_empty() {
        return;
    }
    if let Some(ino) = moved() {
        for file in k.inotify.borrow().opens_of(ino) {
            if !file.unlinked.get() && file.at(from.0, from.1) {
                *file.parent.borrow_mut() = Some((to.0, to.1.to_vec()));
            }
        }
    }
}

/// The last link `name` of `ino` in directory `dir` was removed: report `IN_DELETE_SELF`. While
/// files opened through this name are still open, it is reported after they have all closed.
pub(crate) fn deleted(k: &Kernel, ino: Ino, dir: Ino, name: &[u8]) {
    if !k.inotify.borrow().by_ino.contains_key(&ino) {
        return;
    }
    let mut registry = k.inotify.borrow_mut();
    let open: Vec<_> = registry
        .opens_of(ino)
        .filter(|f| f.at(dir, name))
        .map(|f| Rc::downgrade(&f))
        .collect();
    if open.is_empty() {
        registry.notify(ino, None, IN_DELETE_SELF, false);
    } else {
        registry.doomed.entry(ino).or_default().extend(open);
    }
}

/// Changes the host made through its own connection to the store (the Files app,
/// [`crate::browse_changing`]): events are reported as the corresponding syscalls report them —
/// creation as mkdirat or openat's `O_CREAT`, removal as unlinkat, moves as renameat2's
/// `RENAME_NOREPLACE`, opening for write as openat (`IN_MODIFY` first when truncating), and on
/// close the other side's writes (`IN_MODIFY`) and `IN_CLOSE_WRITE` are added. Called with the BKL
/// held.
pub(crate) fn host_change(k: &Kernel, c: &Change) {
    let isdir = |d: bool| if d { IN_ISDIR } else { 0 };
    // Files open through the moved name follow the rename, even with no watches (later watches
    // need it); removed names are marked unlinked for IN_EXCL_UNLINK
    match c {
        Change::Moved { from, to, ino, .. } => {
            renamed(k, (from.0, &from.1), (to.0, &to.1), || Some(*ino));
        }
        Change::Removed { dir, name, ino, .. } => {
            unlinked(k, *ino, *dir, name);
        }
        _ => {}
    }
    // A held file the host made private as it opened it for writing: its open descriptions
    // move to the current object, even with no watches
    if let Change::Opened {
        ino,
        unshared: true,
        ..
    }
    | Change::Unshared(ino) = c
    {
        super::fs::host_unshared(k, *ino);
    }
    if idle(k) {
        return;
    }
    match c {
        Change::Created { dir, name, is_dir } => {
            dir_event(k, *dir, name, IN_CREATE | isdir(*is_dir), 0);
        }
        Change::Removed {
            dir,
            name,
            ino,
            is_dir: true,
        } => {
            deleted(k, *ino, *dir, name);
            dir_event(k, *dir, name, IN_DELETE | IN_ISDIR, 0);
        }
        Change::Removed { dir, name, ino, .. } => {
            path_event(k, *ino, None, IN_ATTRIB);
            let nlink = k
                .vfs
                .as_ref()
                .and_then(|v| v.store().stat(*ino).ok())
                .map_or(0, |st| st.nlink);
            if nlink == 0 {
                deleted(k, *ino, *dir, name);
            }
            dir_event(k, *dir, name, IN_DELETE, 0);
        }
        Change::Moved {
            from,
            to,
            ino,
            is_dir,
        } => {
            let cookie = cookie(k);
            dir_event(k, from.0, &from.1, IN_MOVED_FROM | isdir(*is_dir), cookie);
            dir_event(k, to.0, &to.1, IN_MOVED_TO | isdir(*is_dir), cookie);
            path_event(k, *ino, None, IN_MOVE_SELF);
        }
        Change::Opened {
            ino,
            parent,
            truncated,
            ..
        } => {
            let parent = Some((parent.0, parent.1.as_slice()));
            if *truncated {
                path_event(k, *ino, parent, IN_MODIFY);
            }
            path_event(k, *ino, parent, IN_OPEN);
        }
        Change::Unshared(_) => {}
        Change::Written { ino, parent } => {
            let parent = Some((parent.0, parent.1.as_slice()));
            path_event(k, *ino, parent, IN_MODIFY);
            path_event(k, *ino, parent, IN_CLOSE_WRITE);
        }
    }
}

/// Whether there are any watches (with none, nothing needs doing for events).
fn idle(k: &Kernel) -> bool {
    k.inotify.borrow().by_ino.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(r: &mut Registry, i: &Rc<RefCell<Inotify>>, ino: Ino, mask: u32) -> i32 {
        let mut inotify = i.borrow_mut();
        inotify.last_wd += 1;
        let wd = inotify.last_wd;
        inotify.watches.insert(
            wd,
            Watch {
                node: Node::Store(crate::vfs::ROOT_MOUNT, ino),
                mask,
                ino,
                sdev: 0x80_0001,
            },
        );
        r.by_ino
            .entry(ino)
            .or_default()
            .push((Rc::downgrade(i), wd));
        wd
    }

    fn events(i: &Rc<RefCell<Inotify>>) -> Vec<(i32, u32, Vec<u8>)> {
        let mut i = i.borrow_mut();
        i.bytes = 0;
        i.queue.drain(..).map(|e| (e.wd, e.mask, e.name)).collect()
    }

    #[test]
    fn reports_to_the_file_and_its_directory() {
        let mut r = Registry::default();
        let i = Rc::new(RefCell::new(Inotify::default()));
        let dir = watch(&mut r, &i, 1, IN_MODIFY | IN_CREATE);
        let file = watch(&mut r, &i, 2, IN_MODIFY | IN_DELETE_SELF);
        r.notify(2, Some((1, b"f")), IN_MODIFY, false);
        // Compared only with the event at the tail: only identical ones merge
        r.notify(2, None, IN_MODIFY, false);
        r.notify(2, Some((1, b"f")), IN_ATTRIB, false);
        r.notify(2, Some((1, b"f")), IN_DELETE_SELF, false);
        assert_eq!(
            events(&i),
            vec![
                (dir, IN_MODIFY, b"f".to_vec()),
                (file, IN_MODIFY, vec![]),
                (file, IN_DELETE_SELF, vec![]),
                (file, IN_IGNORED, vec![]),
            ]
        );
        // The file's watch goes away with IN_DELETE_SELF; the directory's stays
        assert!(!r.by_ino.contains_key(&2));
        assert!(r.deliver(1, IN_CREATE | IN_ISDIR, 0, b"d", false));
        assert_eq!(events(&i), vec![(dir, IN_CREATE | IN_ISDIR, b"d".to_vec())]);
    }

    #[test]
    fn oneshot_watches_and_closed_instances_go_away() {
        let mut r = Registry::default();
        let i = Rc::new(RefCell::new(Inotify::default()));
        let wd = watch(&mut r, &i, 5, IN_OPEN | IN_ONESHOT);
        r.notify(5, None, IN_OPEN, false);
        r.notify(5, None, IN_OPEN | IN_ISDIR, false);
        assert_eq!(
            events(&i),
            vec![(wd, IN_OPEN, vec![]), (wd, IN_IGNORED, vec![])]
        );
        assert!(r.by_ino.is_empty());
        watch(&mut r, &i, 6, IN_OPEN);
        drop(i);
        assert!(!r.deliver(6, IN_OPEN, 0, b"", false));
        assert!(r.by_ino.is_empty());
    }

    #[test]
    fn delete_self_waits_for_the_last_close() {
        let registry = Rc::new(RefCell::new(Registry::default()));
        let i = Rc::new(RefCell::new(Inotify::default()));
        let wd = watch(&mut registry.borrow_mut(), &i, 7, IN_ALL_EVENTS);
        let open = || {
            Opened::new(
                &registry,
                7,
                Some((1, b"f".to_vec())),
                IN_CLOSE_NOWRITE,
                false,
            )
        };
        let (a, b) = (open(), open());
        registry
            .borrow_mut()
            .doomed
            .insert(7, vec![Rc::downgrade(&a.0), Rc::downgrade(&b.0)]);
        // An exec through a still-open fd gets a new open after unlink.
        let exe = open();
        drop(a);
        assert_eq!(events(&i), vec![(wd, IN_CLOSE_NOWRITE, vec![])]);
        drop(b);
        assert_eq!(events(&i), vec![(wd, IN_CLOSE_NOWRITE, vec![])]);
        drop(exe);
        assert_eq!(
            events(&i),
            vec![
                (wd, IN_CLOSE_NOWRITE, vec![]),
                (wd, IN_DELETE_SELF, vec![]),
                (wd, IN_IGNORED, vec![]),
            ]
        );
        assert!(registry.borrow().doomed.is_empty());
    }

    #[test]
    fn interpreter_closes_after_inherited_and_remapped_segments() {
        use crate::mm::{Mm, flags};
        use appine_engine::{PAGE_SIZE, prot};
        use std::os::fd::AsRawFd;

        let registry = Rc::new(RefCell::new(Registry::default()));
        let i = Rc::new(RefCell::new(Inotify::default()));
        let wd = watch(&mut registry.borrow_mut(), &i, 7, IN_CLOSE_NOWRITE);
        let file = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let src = Some((file.as_raw_fd(), 0, false));
        let parent = Mm::new().into_shared();
        let addr = parent
            .borrow_mut()
            .mmap(0, PAGE_SIZE, prot::READ, flags::MAP_PRIVATE, src)
            .unwrap();
        let open = Opened::new(&registry, 7, None, IN_CLOSE_NOWRITE, false);
        parent
            .borrow_mut()
            .keep_interp_open(addr, addr + PAGE_SIZE, &open);
        drop(open);
        let child = parent.borrow_mut().fork().unwrap();
        drop(parent);
        assert!(events(&i).is_empty());

        let mut mm = child.borrow_mut();
        let (dst, refill) = mm.mremap_dontunmap(addr, PAGE_SIZE, None).unwrap();
        assert_eq!(refill.len(), 1);
        mm.mmap(
            addr,
            PAGE_SIZE,
            prot::READ,
            flags::MAP_PRIVATE | flags::MAP_FIXED,
            src,
        )
        .unwrap();
        mm.apply_refill_flags(&refill[0]);
        drop(refill);
        mm.munmap(dst, PAGE_SIZE).unwrap();
        assert!(events(&i).is_empty());
        mm.munmap(addr, PAGE_SIZE).unwrap();
        assert_eq!(events(&i), vec![(wd, IN_CLOSE_NOWRITE, vec![])]);
    }

    #[test]
    fn delete_self_entry_clears_when_watches_disappear_before_close() {
        let registry = Rc::new(RefCell::new(Registry::default()));
        let i = Rc::new(RefCell::new(Inotify::default()));
        i.borrow_mut().registry = Rc::downgrade(&registry);
        watch(&mut registry.borrow_mut(), &i, 9, IN_ALL_EVENTS);
        let file = Opened::new(
            &registry,
            9,
            Some((1, b"g".to_vec())),
            IN_CLOSE_NOWRITE,
            true,
        );
        registry
            .borrow_mut()
            .doomed
            .insert(9, vec![Rc::downgrade(&file.0)]);
        // Dropping the inotify instance removes the last watch on inode 9 and cleans doomed
        drop(i);
        assert!(registry.borrow().by_ino.is_empty());
        assert!(registry.borrow().doomed.is_empty());
        // Even if a doomed entry remained with no watches left, dropping the last open file clears it
        registry
            .borrow_mut()
            .doomed
            .insert(9, vec![Rc::downgrade(&file.0)]);
        drop(file);
        assert!(registry.borrow().doomed.is_empty());
    }

    #[test]
    fn queue_overflows_once() {
        let mut i = Inotify::default();
        for n in 0..MAX_QUEUED + 10 {
            i.push(1, IN_MODIFY, n as u32, b"");
        }
        assert_eq!(i.queue.len(), MAX_QUEUED + 1);
        assert_eq!(i.queue.back().unwrap().mask, IN_Q_OVERFLOW);
        assert_eq!(i.pending(), (MAX_QUEUED + 1) * 16);
        // When full, an event identical to the tail must still queue IN_Q_OVERFLOW instead of merging
        let mut small = Inotify::default();
        small.max_queued = 2;
        small.push(1, IN_OPEN, 0, b"");
        small.push(1, IN_MODIFY, 0, b"");
        small.push(1, IN_MODIFY, 0, b"");
        assert_eq!(small.queue.len(), 3);
        assert_eq!(small.queue.back().unwrap().mask, IN_Q_OVERFLOW);
        assert_eq!(
            Event {
                wd: 1,
                mask: 0,
                cookie: 0,
                name: b"0123456789abcde".to_vec()
            }
            .len(),
            32
        );
    }

    #[test]
    fn excl_unlink_filters_unlinked_events_on_both_dir_and_file_watches() {
        let mut r = Registry::default();
        let i = Rc::new(RefCell::new(Inotify::default()));
        let fuse_dir = crate::vfs::fuse::key(10);
        let fuse_file = crate::vfs::fuse::key(11);
        let d_wd = watch(
            &mut r,
            &i,
            fuse_dir,
            IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_EXCL_UNLINK,
        );
        let f_wd = watch(
            &mut r,
            &i,
            fuse_file,
            IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_EXCL_UNLINK,
        );
        // Linked FUSE child: events are delivered to both directory and file watches
        r.notify(fuse_file, Some((fuse_dir, b"f")), IN_MODIFY, false);
        assert_eq!(
            events(&i),
            vec![(d_wd, IN_MODIFY, b"f".to_vec()), (f_wd, IN_MODIFY, vec![]),]
        );
        // Unlinked name: I/O and close are excluded on both watches, while metadata (unlinked=false) is kept
        r.notify(fuse_file, Some((fuse_dir, b"f")), IN_MODIFY, true);
        r.notify(fuse_file, Some((fuse_dir, b"f")), IN_CLOSE_WRITE, true);
        assert!(events(&i).is_empty());
        r.notify(fuse_file, Some((fuse_dir, b"f")), IN_ATTRIB, false);
        assert_eq!(
            events(&i),
            vec![(d_wd, IN_ATTRIB, b"f".to_vec()), (f_wd, IN_ATTRIB, vec![]),]
        );
    }

    #[test]
    fn cgroup_dir_watch_skips_uninstantiated_child_events_on_inherited_freeze() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let cred = crate::cred::Cred::root();
        let pid_ns = crate::pidns::PidNs::init();
        let writer = crate::cgroup::Writer {
            tid: 0,
            pid_ns: &pid_ns,
            ns_root: crate::cgroup::ROOT,
            opener: &cred,
            cred: &cred,
        };
        let parent = k
            .cgroups
            .mkdir(crate::cgroup::ROOT, b"p", &cred, 0o755)
            .unwrap();
        let child = k.cgroups.mkdir(parent, b"c", &cred, 0o755).unwrap();

        // Watch child directory without ever looking up child/cgroup.events.
        let i = Rc::new(RefCell::new(Inotify::default()));
        let wd = watch(
            &mut k.inotify.borrow_mut(),
            &i,
            crate::cgroup::key(child, b""),
            IN_MODIFY,
        );
        crate::cgroup::observe_all(&mut k, child);

        // Inherited freeze from parent must NOT deliver IN_MODIFY for un-looked-up child/cgroup.events.
        crate::cgroup::write(&mut k, &writer, (parent, b"cgroup.freeze"), b"1\n").unwrap();
        crate::cgroup::notify_changes(&mut k);
        assert!(
            events(&i).is_empty(),
            "directory watch must not receive inherited freeze event before child file is looked up"
        );

        // Once child/cgroup.events is looked up (dentry instantiated), subsequent inherited thaw
        // delivers IN_MODIFY to the directory watch.
        k.cgroups.file_looked_up(child, b"cgroup.events");
        crate::cgroup::write(&mut k, &writer, (parent, b"cgroup.freeze"), b"0\n").unwrap();
        crate::cgroup::notify_changes(&mut k);
        assert_eq!(events(&i), vec![(wd, IN_MODIFY, b"cgroup.events".to_vec())]);
    }
}
