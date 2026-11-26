//! I/O multiplexing (the kernel/poll map): ppoll, pselect6 and epoll, plus eventfd.
//!
//! ppoll and pselect6 scan files with [`wait_ready`], batching host fds in a zero-timeout poll.
//! epoll_pwait checks tracked epolls via [`Epoll::ready`] using [`EpollWatches`] and
//! [`appine_hal::HostEpoll`] (with a dynamic fallback list for special kinds), and batches
//! level-triggered host fds when scanning dynamic/untracked interests. In-process objects (pipes,
//! PTYs, eventfds...) supply their readiness directly. When nothing is ready, [`Waits`] waits on
//! the host fds together with the thread's own wake event (kernel/process).
//!
//! `EPOLLET`: every time Linux wakes a file's wait queue (data arrives, a new connection, an
//! eventfd is written, a timerfd expires...), edge-triggered interests report once more, even
//! when the file was already ready; mio's (tokio's) waker relies on this, and it never reads the
//! eventfd's count away. Here this is decided by "data generations" ([`arrivals`]): in-process
//! objects count every event; data on host sockets does not pass through the kernel layer and is
//! recorded by an edge-triggered host epoll that watches only that socket ([`HostEdges`], set up
//! only when there are edge-triggered interests). An interest fires when a bit goes from not
//! ready to ready, or when another event arrives in that direction, and when it fires it reports
//! all bits currently ready, as on Linux. After the program uses up the data in one direction (a
//! read or write gets EAGAIN, or reads or writes less than the requested length, see
//! [`drained`]), all bits last reported in that direction are forgotten as well: where no
//! [`HostEdges`] can be set up (regular files on the host) this is the only thing to rely on, and
//! it also loses no events when epoll_wait is not called between reading EAGAIN and new data
//! arriving (as Go's netpoller does).
//!
//! While waiting, edge-triggered interests do not wait for bits that were reported and are still
//! ready: the host poll would return at once, and epoll_wait would become a busy loop that
//! releases and takes the BKL over and over, starving other threads. So they wait for new events
//! on the host fds instead (the [`HostEdges`] fd), and these epoll_waits are woken to recompute
//! when data arrives at an in-process object (for a non-empty pipe only these waiters are woken,
//! see [`arrived`]) or the program uses up the data
//! ([`Kernel::edge_waiters`](crate::kernel::Kernel)).
//!
//! `EPOLLEXCLUSIVE`: Linux wakes only one exclusive waiter per wakeup. Here one edge (data
//! generation) is reported to only one epoll ([`OpenFile::exclusive_claim`]): for a
//! level-triggered interest, the epoll that reported the edge keeps reporting it, and other epolls
//! wait for the next edge, so when several processes each wait on the same listening socket with
//! their own epoll, a new connection makes only one process return from epoll_wait. Waiting
//! threads do not wait on the file themselves but queue on its exclusive gate ([`ExGate`]), and a
//! new edge wakes only the first one in the queue.
//!
//! While waiting, the in-process objects of interest are registered ([`wake_objects`]): changes
//! that affect only other objects (reads and writes of another pipe, another eventfd, another
//! AF_UNIX connection...) do not wake the waiter (the kernel/process map).

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::{SysResult, get, read_timespec, tty};
use crate::cell::RefCell;
use crate::errno::Errno;
use crate::fd::{EventFd, FileKind, FileRef, HostEdges, OpenFile, oflags};
use crate::kernel::{Cx, request_wake_object, wake};
use crate::process::RLIMIT_NOFILE;
use crate::signal;
use crate::uaccess::UserSlice;
use crate::vfs::dev::Device;
use crate::vfs::{Fs, MQUEUE_DEV, Node, ROOT_DEV, Vfs};

const POLLIN: i16 = 0x001;
const POLLPRI: i16 = 0x002;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLHUP: i16 = 0x010;
const POLLNVAL: i16 = 0x020;
const POLLRDNORM: i16 = 0x040;
const POLLWRNORM: i16 = 0x100;

/// Events a poll reports regardless of the requested mask.
const ALWAYS_REPORTED: i16 = POLLERR | POLLHUP | POLLNVAL;

/// Readiness bits of the write direction; all others count as the read direction.
const WRITE_BITS: u32 = (POLLOUT | POLLWRNORM) as u32 | 0x200; // POLLWRBAND

/// Maximum depth of nested epolls, the same as Linux's `EP_MAX_NESTS`.
const MAX_NESTS: u32 = 4;

// ---- ppoll and pselect6 ----

pub(super) fn ppoll(
    cx: &mut Cx<'_>,
    fds: u64,
    nfds: usize,
    timeout: u64,
    sigmask: u64,
    sigsetsize: usize,
) -> SysResult {
    if nfds as u64 > cx.t.group.borrow().rlimits[RLIMIT_NOFILE as usize].0 {
        return Err(Errno::EINVAL);
    }
    let (deadline, zero) = match timeout {
        0 => (None, false),
        addr => {
            let t = read_timespec(cx, addr)?;
            (Some(Instant::now() + t), t.is_zero())
        }
    };
    let mut raw = vec![0u8; nfds * 8];
    cx.mm().read(UserSlice::new(fds, raw.len()), &mut raw)?;
    // struct pollfd: fd, events, revents; negative fds are ignored
    let items: Vec<(Option<FileRef>, i16, bool)> = raw
        .chunks_exact(8)
        .map(|e| {
            let fd = i32::from_le_bytes(e[..4].try_into().unwrap());
            let events = i16::from_le_bytes([e[4], e[5]]);
            (cx.fds().get(fd).ok(), events, fd < 0)
        })
        .collect();
    let wanted: Vec<(Option<FileRef>, i16)> = items
        .iter()
        .filter(|(_, _, skip)| !skip)
        .map(|(f, e, _)| (f.clone(), *e))
        .collect();
    set_temp_mask(cx, sigmask, sigsetsize)?;
    let r = wait_ready(cx, &wanted, deadline, false);
    restore_mask(cx, &r);
    let r = write_back_timeout(cx, timeout, deadline.filter(|_| !zero), r);
    // As Linux's do_sys_poll, revents are written back whatever the outcome: zeros when the wait
    // was interrupted
    let mut ready = match &r {
        Ok(ready) => ready.clone(),
        Err(_) => vec![0; wanted.len()],
    }
    .into_iter();
    let mut n = 0;
    for ((_, _, skip), out) in items.iter().zip(raw.chunks_exact_mut(8)) {
        let ev = if *skip { 0 } else { ready.next().unwrap() };
        n += (ev != 0) as u64;
        out[6..8].copy_from_slice(&ev.to_le_bytes());
    }
    cx.mm().write(UserSlice::new(fds, raw.len()), &raw)?;
    r.map(|_| n)
}

pub(super) fn pselect6(
    cx: &mut Cx<'_>,
    nfds: i32,
    sets: [u64; 3],
    timeout: u64,
    sigdata: u64,
) -> SysResult {
    if nfds < 0 {
        return Err(Errno::EINVAL);
    }
    // core_sys_select clamps nfds to the size of the fd table (`select(FD_SETSIZE, ...)` works
    // whatever the fd limit): bits above it are neither read nor written back
    let nfds = (nfds as usize).min(cx.fds().capacity());
    let words = nfds.div_ceil(64);
    // The three fd_sets: read, write and except
    let mut bits = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    for (set, &addr) in bits.iter_mut().zip(&sets) {
        if addr == 0 {
            continue;
        }
        let mut b = vec![0u8; words * 8];
        cx.mm().read(UserSlice::new(addr, b.len()), &mut b)?;
        for (w, c) in set.iter_mut().zip(b.chunks_exact(8)) {
            *w = u64::from_le_bytes(c.try_into().unwrap());
        }
    }
    let is_set = |set: &[u64], fd: usize| set[fd / 64] >> (fd % 64) & 1 != 0;
    // The events that make an fd ready in the read, write and except sets (Linux's POLLIN_SET,
    // POLLOUT_SET and POLLEX_SET). POLLNVAL, an fd select cannot poll (O_PATH), is in all three, so
    // select does not sleep on it forever
    let masks = [
        POLLIN | POLLRDNORM | POLLHUP | POLLERR | POLLNVAL,
        POLLOUT | POLLWRNORM | POLLERR | POLLNVAL,
        POLLPRI | POLLNVAL,
    ];
    let mut items = Vec::new();
    let mut fds = Vec::new();
    for fd in 0..nfds {
        let ev = (0..3)
            .filter(|&i| is_set(&bits[i], fd))
            .fold(0, |ev, i| ev | masks[i]);
        if ev != 0 {
            items.push((Some(cx.fds().get(fd as i32)?), ev));
            fds.push(fd);
        }
    }
    let (deadline, zero) = match timeout {
        0 => (None, false),
        addr => {
            let t = read_timespec(cx, addr)?;
            (Some(Instant::now() + t), t.is_zero())
        }
    };
    // The sixth argument points to { const sigset_t *ss; size_t ss_len; }
    if sigdata != 0 {
        let d: [u8; 16] = get(cx, sigdata)?;
        let ss = u64::from_le_bytes(d[..8].try_into().unwrap());
        let len = u64::from_le_bytes(d[8..].try_into().unwrap()) as usize;
        set_temp_mask(cx, ss, len)?;
    }
    let r = wait_ready(cx, &items, deadline, true);
    restore_mask(cx, &r);
    let ready = write_back_timeout(cx, timeout, deadline.filter(|_| !zero), r)?;
    let mut out = [vec![0u64; words], vec![0u64; words], vec![0u64; words]];
    let mut n = 0;
    for (&fd, &ev) in fds.iter().zip(&ready) {
        for (i, mask) in masks.into_iter().enumerate() {
            if is_set(&bits[i], fd) && ev & mask != 0 {
                out[i][fd / 64] |= 1 << (fd % 64);
                n += 1;
            }
        }
    }
    for (set, &addr) in out.iter().zip(&sets) {
        if addr != 0 {
            let b: Vec<u8> = set.iter().flat_map(|w| w.to_le_bytes()).collect();
            cx.mm().write(UserSlice::new(addr, b.len()), &b)?;
        }
    }
    Ok(n)
}

/// Installs the temporary signal mask given by the guest; when interrupted by a signal, signal
/// delivery restores it, otherwise [`restore_mask`] does.
pub(super) fn set_temp_mask(cx: &mut Cx<'_>, sigmask: u64, size: usize) -> Result<(), Errno> {
    if sigmask == 0 {
        return Ok(());
    }
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let mask = u64::from_le_bytes(get(cx, sigmask)?);
    cx.task.saved_sigmask.set(Some(cx.task.sigmask.get()));
    cx.task.sigmask.set(mask & !signal::UNBLOCKABLE);
    Ok(())
}

/// Polls a batch of host fds with zero timeout, falling back to per-fd polls if the batch call
/// fails (e.g. exceeding the host's `RLIMIT_NOFILE` or interrupted by a host signal).
fn poll_host_batch(fds: &mut [(i32, i16, i16)]) {
    if fds.is_empty() {
        return;
    }
    if appine_hal::poll(fds, Some(Duration::ZERO)).is_err() {
        for fd in fds {
            let _ = appine_hal::poll(std::slice::from_mut(fd), Some(Duration::ZERO));
        }
    }
}

/// Waits until at least one file in `items` is ready, a timeout, or an interruption by a signal,
/// and returns the ready events of each item. `None` means an invalid fd, reported as POLLNVAL.
/// With `only_wanted` (select) only events in an item's mask count: POLLHUP and POLLERR outside
/// it are returned but do not end the wait, as in Linux's `do_select`, which counts only what
/// matches the sets.
fn wait_ready(
    cx: &mut Cx<'_>,
    items: &[(Option<FileRef>, i16)],
    deadline: Option<Instant>,
    only_wanted: bool,
) -> Result<Vec<i16>, Errno> {
    let mut hosts = vec![None; items.len()];
    let mut host_fds = Vec::new();
    let mut host_slots = Vec::new();
    loop {
        let mut ready = vec![0i16; items.len()];
        host_fds.clear();
        host_slots.clear();
        for (i, (f, wanted)) in items.iter().enumerate() {
            match f {
                Some(f) => {
                    let (known, host) = readiness(&f.borrow(), 0);
                    hosts[i] = host;
                    if let Some(fd) = host {
                        host_fds.push((fd, *wanted, 0));
                        host_slots.push((i, known, *wanted));
                    } else {
                        ready[i] = known & (*wanted | ALWAYS_REPORTED);
                    }
                }
                None => {
                    hosts[i] = None;
                    ready[i] = POLLNVAL;
                }
            }
        }
        if !host_fds.is_empty() {
            poll_host_batch(&mut host_fds);
            for (&(i, known, wanted), &(_, _, revents)) in host_slots.iter().zip(&host_fds) {
                ready[i] = (known | revents) & (wanted | ALWAYS_REPORTED);
            }
        }
        let counts = |(&e, (_, wanted)): (&i16, &(Option<FileRef>, i16))| {
            if only_wanted { e & wanted != 0 } else { e != 0 }
        };
        if ready.iter().zip(items).any(counts) || deadline.is_some_and(|d| Instant::now() >= d) {
            for ((f, _), &e) in items.iter().zip(&ready) {
                if let Some(f) = f {
                    took_change(&f.borrow(), e);
                }
            }
            return Ok(ready);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTNOHAND);
        }
        let mut waits = Waits::default();
        for (((f, wanted), &e), &host) in items.iter().zip(&ready).zip(&hosts) {
            let Some(f) = f else { continue };
            let f = f.borrow();
            if e & (POLLHUP | POLLERR) != 0 {
                // A hangup or error that does not count (select's write or except set): the host
                // poll always reports these bits and would end every wait at once, so wait only
                // on the file's in-process objects, as epoll does after reporting a hangup
                waits.files = true;
                wake_objects(&f, &mut waits.objects);
            } else {
                waits.add_with_host(&f, *wanted, host, 0);
            }
        }
        waits.wait(cx, deadline)?;
    }
}

pub(super) fn restore_mask<T>(cx: &mut Cx<'_>, r: &Result<T, Errno>) {
    // An interrupted epoll_pwait returns EINTR (Linux's
    // restore_saved_sigmask_unless(error == -EINTR))
    let interrupted = matches!(r, Err(e) if *e == Errno::ERESTARTNOHAND || *e == Errno::EINTR);
    if !interrupted && let Some(saved) = cx.task.saved_sigmask.take() {
        cx.task.sigmask.set(saved);
    }
}

/// As Linux's `poll_select_finish` does, writes the remaining time back to the guest's `timeout`
/// (when given and not 0; `deadline` is when it expires), also when interrupted by a signal: a
/// restart then waits only for the remaining time, and after a stop and continue or a cgroup
/// freeze and thaw it does not wait from the beginning again. When it cannot be written, an
/// interruption becomes EINTR (no restart), and a completed call returns as usual.
fn write_back_timeout<T>(
    cx: &mut Cx<'_>,
    timeout: u64,
    deadline: Option<Instant>,
    r: Result<T, Errno>,
) -> Result<T, Errno> {
    let Some(d) = deadline.filter(|_| timeout != 0) else {
        return r;
    };
    let left = d.saturating_duration_since(Instant::now());
    let written = super::write_pair(
        cx,
        timeout,
        left.as_secs() as i64,
        left.subsec_nanos() as i64,
    );
    match r {
        Err(e) if e == Errno::ERESTARTNOHAND && written.is_err() => Err(Errno::EINTR),
        r => r,
    }
}

// ---- epoll ----

const EPOLL_CTL_ADD: u32 = 1;
const EPOLL_CTL_DEL: u32 = 2;
const EPOLL_CTL_MOD: u32 = 3;
const EPOLLONESHOT: u32 = 1 << 30;
const EPOLLET: u32 = 1 << 31;
/// Wakes only one of several epolls waiting on the same fd (see the module docs).
const EPOLLEXCLUSIVE: u32 = 1 << 28;
const EPOLLWAKEUP: u32 = 1 << 29;
/// Bits usable together with `EPOLLEXCLUSIVE` (Linux's `EPOLLEXCLUSIVE_OK_BITS`).
const EXCLUSIVE_OK: u32 =
    (POLLIN | POLLOUT | POLLERR | POLLHUP) as u32 | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// Monotonic registration order for `EPOLLEXCLUSIVE` interests, preserving Linux's stable
/// wait-queue order across wakeups instead of rotating woken waiters to the back.
static NEXT_EXCLUSIVE_ORDER: AtomicU64 = AtomicU64::new(1);

/// Encodes a `st_dev` value as Linux's internal `dev_t` (`(major << 20) | minor`), matching
/// `inode->i_sb->s_dev` in `/proc/<pid>/fdinfo`.
fn kernel_dev(dev: u64) -> u64 {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major << 20) | minor
}

/// Computes `(sdev, ino)` for `/proc/<pid>/fdinfo` of an epoll interest, matching `stat`/`fstat`
/// for tmpfs, overlay, FUSE, synthetic mounts, message queues, host fds, and anonymous files.
fn file_fdinfo_dev_ino(vfs: Option<&Vfs>, f: &OpenFile) -> (u64, u64) {
    let (dev, ino) = match &f.kind {
        FileKind::Host(fd) => match appine_hal::fstat(*fd) {
            #[allow(clippy::unnecessary_cast)]
            Ok(st) => (st.st_dev as u64, st.st_ino as u64),
            Err(_) => super::fs::dev_ino(f),
        },
        FileKind::MessageQueue(q) => {
            let q = q.borrow();
            (vfs.map_or(MQUEUE_DEV, |v| v.mq_dev(q.ns)), q.stat().ino)
        }
        _ => match f.node() {
            Some(node @ Node::Store(_, ino)) => (vfs.map_or(ROOT_DEV, |v| v.dev_of(&node)), ino),
            Some(node @ Node::Overlay(_, o)) => (
                vfs.map_or(0, |v| v.dev_of(&node)),
                vfs.map_or(o, |v| v.overlay().shown_ino(o)),
            ),
            Some(node @ Node::Fuse(_, id)) => (
                vfs.map_or(0, |v| v.dev_of(&node)),
                vfs.and_then(|v| v.fuse().get(id).map(|n| n.attr.ino))
                    .unwrap_or(id),
            ),
            Some(ref node @ Node::Pseudo(_, ref p)) => {
                let dev = if matches!(p, crate::pseudo::PseudoNode::NsFile(..)) {
                    Fs::Nsfs.dev()
                } else {
                    vfs.map_or_else(|| crate::pseudo::fs_of(p).dev(), |v| v.dev_of(node))
                };
                (dev, crate::pseudo::ino_of(p))
            }
            None => super::fs::dev_ino(f),
        },
    };
    (kernel_dev(dev), ino)
}

/// One subscription in [`EpollWatches`], identifying an interest slot inside a tracked epoll.
#[derive(Clone)]
struct EpollSub {
    ep: Weak<RefCell<Epoll>>,
    slot: usize,
    epoch: u32,
}

impl EpollSub {
    fn keep(&self, ep_ptr: usize, slot: usize) -> bool {
        self.ep.strong_count() > 0 && !(self.ep.as_ptr() as usize == ep_ptr && self.slot == slot)
    }
}

/// Per-kernel wake-object subscriptions for tracked epolls ([`crate::kernel::Kernel::epoll_watches`]).
///
/// When an in-process object calls `request_wake_object(obj)` (or `poll::drained` / `poll::arrived`),
/// matching epoll slots are marked dirty in O(subscribers) and their sleeping waiters are signalled
/// directly, avoiding O(n) scans of idle interests under the BKL.
#[derive(Default)]
pub(crate) struct EpollWatches {
    by_object: HashMap<wake::Object, Vec<EpollSub>>,
    by_file: HashMap<usize, Vec<EpollSub>>,
    et_pipes: Vec<EpollSub>,
}

impl EpollWatches {
    fn register(
        &mut self,
        ep: &Weak<RefCell<Epoll>>,
        slot: usize,
        epoch: u32,
        objs: &[wake::Object],
        file_ptr: usize,
        et_pipe: bool,
    ) {
        self.register_objects(ep, slot, epoch, objs);
        let sub = EpollSub {
            ep: ep.clone(),
            slot,
            epoch,
        };
        self.by_file.entry(file_ptr).or_default().push(sub.clone());
        if et_pipe {
            self.et_pipes.push(sub);
        }
    }

    fn register_objects(
        &mut self,
        ep: &Weak<RefCell<Epoll>>,
        slot: usize,
        epoch: u32,
        objs: &[wake::Object],
    ) {
        let sub = EpollSub {
            ep: ep.clone(),
            slot,
            epoch,
        };
        for &obj in objs {
            self.by_object.entry(obj).or_default().push(sub.clone());
        }
    }

    fn unregister_objects(&mut self, ep_ptr: usize, slot: usize, objs: &[wake::Object]) {
        for &obj in objs {
            remove_sub_entry(&mut self.by_object, &obj, ep_ptr, slot);
        }
    }

    fn register_et_pipe(&mut self, ep: &Weak<RefCell<Epoll>>, slot: usize, epoch: u32) {
        self.et_pipes.push(EpollSub {
            ep: ep.clone(),
            slot,
            epoch,
        });
    }

    fn unregister(
        &mut self,
        ep_ptr: usize,
        slot: usize,
        objs: &[wake::Object],
        file_ptr: usize,
        et_pipe: bool,
    ) {
        self.unregister_objects(ep_ptr, slot, objs);
        remove_sub_entry(&mut self.by_file, &file_ptr, ep_ptr, slot);
        if et_pipe {
            self.et_pipes.retain(|s| s.keep(ep_ptr, slot));
        }
    }

    /// Marks every tracked epoll interest watching any object in `objects` dirty and wakes its
    /// waiters (and ancestor epolls).
    pub(crate) fn notify_objects(&mut self, objects: &[wake::Object]) {
        for &obj in objects {
            let Some(subs) = self.by_object.get_mut(&obj) else {
                continue;
            };
            notify_subs(subs, 0);
            if subs.is_empty() {
                self.by_object.remove(&obj);
            }
        }
    }

    /// Marks every tracked epoll interest watching `file_ptr` dirty (used by `drained` and when
    /// one epoll consumes a shared `HostEdges` event so other epolls watching the same open file
    /// still see the incremented edge counter).
    fn notify_file(&mut self, file_ptr: usize, skip_ep: usize) {
        let Some(subs) = self.by_file.get_mut(&file_ptr) else {
            return;
        };
        notify_subs(subs, skip_ep);
        if subs.is_empty() {
            self.by_file.remove(&file_ptr);
        }
    }

    fn notify_files(&mut self, files: &[usize], skip_ep: usize) {
        for &fp in files {
            self.notify_file(fp, skip_ep);
        }
    }

    /// Marks every tracked edge-triggered pipe interest dirty (`poll::arrived`).
    fn notify_et_pipes(&mut self) {
        notify_subs(&mut self.et_pipes, 0);
    }
}

fn remove_sub_entry<K: Eq + std::hash::Hash>(
    map: &mut HashMap<K, Vec<EpollSub>>,
    key: &K,
    ep_ptr: usize,
    slot: usize,
) {
    if let Some(list) = map.get_mut(key) {
        list.retain(|s| s.keep(ep_ptr, slot));
        if list.is_empty() {
            map.remove(key);
        }
    }
}

fn notify_watched_files(watches: &RefCell<EpollWatches>, files: &[usize], skip_ep: usize) {
    if !files.is_empty()
        && let Ok(mut w) = watches.try_borrow_mut()
    {
        w.notify_files(files, skip_ep);
    }
}

fn notify_subs(subs: &mut Vec<EpollSub>, skip_ep: usize) {
    subs.retain(|sub| {
        let Some(ep_rc) = sub.ep.upgrade() else {
            return false;
        };
        if Rc::as_ptr(&ep_rc) as usize == skip_ep {
            return true;
        }
        match ep_rc.try_borrow_mut() {
            Ok(mut ep) => {
                if !ep.slot_matches(sub.slot, sub.epoch) {
                    return false;
                }
                ep.mark_dirty(sub.slot);
                ep.wake_waiters();
                let parents = ep.live_parents();
                drop(ep);
                notify_parents(parents, 0);
                true
            }
            Err(_) => true,
        }
    });
}

fn notify_parents(parents: Vec<Rc<RefCell<Epoll>>>, depth: u32) {
    if depth >= MAX_NESTS {
        return;
    }
    for parent_rc in parents {
        if let Ok(mut parent) = parent_rc.try_borrow_mut() {
            parent.wake_waiters();
            let next = parent.live_parents();
            drop(parent);
            notify_parents(next, depth + 1);
        }
    }
}

/// How a tracked interest is monitored for readiness changes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WatchMode {
    /// Watched via [`EpollWatches::by_object`] (pipes, eventfds, connected AF_UNIX, PTYs, etc.).
    WakeObjects,
    /// Watched via [`Epoll::host_epoll`] (host TCP/UDP sockets, GpuFence), plus wake objects for
    /// guest-side socket events (close, DNS stub answers, pending error).
    HostEpoll {
        armed_fd: Option<i32>,
        armed_events: u32,
        armed_edges_fd: Option<i32>,
    },
    /// Always checked on scan: TimerFd, SignalFd, Pidfd, nested Epoll, EPOLLEXCLUSIVE, host stdio,
    /// udp_tap sockets, duplicate/non-epollable host fds, or unconnected AF_UNIX sockets.
    Dynamic,
}

/// Encodes `(slot, epoch, edges)` into a `HostEpoll` event token: bit 63 flags a `HostEdges` fd,
/// bits 62..32 carry the ABA-safe slot epoch, and bits 31..0 carry the slot index.
fn host_token(slot: usize, epoch: u32, edges: bool) -> u64 {
    ((edges as u64) << 63) | ((epoch as u64) << 32) | (slot as u64)
}

fn decode_host_token(data: u64) -> (usize, u32, bool) {
    let slot = (data & 0xffff_ffff) as usize;
    let epoch = ((data >> 32) & 0x7fff_ffff) as u32;
    let edges = (data >> 63) != 0;
    (slot, epoch, edges)
}

/// Whether `f` is a host-fd kind eligible for `Epoll::host_epoll` (owns its host fd, so closing
/// `OpenFile` closes the host fd and auto-removes it from `host_epoll`, and has no `readiness`
/// side effects like `udp_tap`).
fn is_host_epoll_kind(f: &OpenFile) -> bool {
    match &f.kind {
        FileKind::GpuFence(_) => true,
        FileKind::Socket(s) => matches!(
            &*s.borrow(),
            crate::net::Socket::Inet(i) if i.icmp.is_none() && i.udp_tap.is_none()
        ),
        _ => false,
    }
}

/// Host fd that can currently be armed in `Epoll::host_epoll` (None while an inet socket is
/// deferred or has queued DNS stub answers).
fn armable_host_fd(f: &OpenFile) -> Option<i32> {
    match &f.kind {
        FileKind::GpuFence(fd) => Some(std::os::fd::AsRawFd::as_raw_fd(fd)),
        FileKind::Socket(s) => match &*s.borrow() {
            crate::net::Socket::Inet(i)
                if i.icmp.is_none()
                    && i.udp_tap.is_none()
                    && i.deferred.is_none()
                    && i.answers.is_empty() =>
            {
                Some(i.fd)
            }
            _ => None,
        },
        _ => None,
    }
}

/// Whether an interest must stay in [`WatchMode::Dynamic`] (always checked during scans).
fn is_dynamic_interest(f: &OpenFile, events: u32) -> bool {
    if events & EPOLLEXCLUSIVE != 0 {
        return true;
    }
    match &f.kind {
        FileKind::Host(_)
        | FileKind::TimerFd(_)
        | FileKind::SignalFd(_)
        | FileKind::Pidfd(_)
        | FileKind::Epoll(_) => true,
        FileKind::Socket(s) => match &*s.borrow() {
            crate::net::Socket::Inet(i) if i.udp_tap.is_some() => true,
            crate::net::Socket::Unix(u)
                if matches!(
                    u.link,
                    crate::unix::Link::None | crate::unix::Link::Dgram { .. }
                ) =>
            {
                true
            }
            _ => false,
        },
        _ => false,
    }
}

/// A file watched by an epoll.
struct Interest {
    fd: i32,
    /// After the open file is closed, the interest becomes void automatically (as on Linux, it
    /// does not keep the file from closing).
    file: Weak<RefCell<OpenFile>>,
    /// Address of the `RefCell<OpenFile>`, kept for cleanup in [`EpollWatches::by_file`] after
    /// the open file drops.
    file_ptr: usize,
    events: u32,
    data: u64,
    /// `EPOLLONESHOT`: disarmed after one report, until `EPOLL_CTL_MOD`.
    armed: bool,
    /// `EPOLLET`: the bits ready at the last report that are still ready now. Fires only when a
    /// ready bit not among them appears.
    seen: Cell<u32>,
    /// `EPOLLET`: the open file's [`OpenFile::drained`] and [`arrivals`] at the last check.
    drained: Cell<[u64; 2]>,
    arrivals: Cell<[u64; 2]>,
    /// The number of events the file had seen in the watched directions when added, and the
    /// number seen since (this epoll's data generation when nested, [`epoll_arrivals`]).
    origin: u64,
    share: Cell<u64>,
    /// `(sdev, ino)` captured via `Vfs` for `/proc/<pid>/fdinfo`.
    fdinfo_id: (u64, u64),
    /// Monotonic registration order for `EPOLLEXCLUSIVE` (0 for non-exclusive interests).
    exclusive_order: u64,
    /// Non-zero generation of this slot (for ABA-safe subscriptions and host-epoll tokens).
    epoch: u32,
    /// Whether this slot is currently queued in [`Epoll::ready_queue`].
    in_ready: bool,
    /// Wake objects currently subscribed in [`EpollWatches::by_object`].
    wake_objs: Vec<wake::Object>,
    /// Whether currently subscribed in [`EpollWatches::et_pipes`].
    in_et_pipes: bool,
    /// How this interest is monitored on tracked epolls.
    mode: WatchMode,
    /// Cached host fd from the last empty scan so building `Waits` avoids recomputing `readiness`.
    cached_host: Cell<Option<Option<i32>>>,
}

impl Interest {
    fn new(
        fd: i32,
        file: &FileRef,
        events: u32,
        data: u64,
        fdinfo_id: (u64, u64),
        epoch: u32,
    ) -> Interest {
        let f = file.borrow();
        let came = arrivals(&f);
        let exclusive_order = if events & EPOLLEXCLUSIVE != 0 {
            NEXT_EXCLUSIVE_ORDER.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        Interest {
            fd,
            file: Rc::downgrade(file),
            file_ptr: Rc::as_ptr(file) as usize,
            events,
            data,
            armed: true,
            seen: Cell::new(0),
            drained: Cell::new(f.drained),
            arrivals: Cell::new(came),
            origin: directional(events, came),
            share: Cell::new(0),
            fdinfo_id,
            exclusive_order,
            epoch,
            in_ready: false,
            wake_objs: Vec::new(),
            in_et_pipes: false,
            mode: WatchMode::Dynamic,
            cached_host: Cell::new(None),
        }
    }
}

/// An epoll instance.
#[derive(Default)]
pub(crate) struct Epoll {
    /// Slab of watched interests; vacant slots are `None` and tracked in `free`.
    interests: Vec<Option<Interest>>,
    free: Vec<usize>,
    /// `(fd, file_ptr) -> slot` for O(1) `epoll_ctl` lookup.
    index: HashMap<(i32, usize), usize>,
    /// Occupied slot count.
    live_count: usize,
    /// Occupied `WatchMode::WakeObjects` count (used to distinguish gated-only epolls).
    wake_tracked_count: usize,
    /// Monotonic slot generation (1..=0x7fff_ffff, never 0).
    next_epoch: u32,
    /// Outer epolls that currently watch this epoll (one entry per `EPOLL_CTL_ADD` interest),
    /// used to enforce `MAX_NESTS` when extending a leaf top-down.
    parents: Vec<Weak<RefCell<Epoll>>>,
    /// Round-robin cursor (used for dynamic/untracked scans).
    cursor: usize,
    /// Former shares of removed interests, plus the number of times an interest was already
    /// ready when added or modified ([`epoll_arrivals`]).
    base: Cell<u64>,
    /// Another epoll watches this epoll edge-triggered: the host fds it watches must record newly
    /// arrived data too ([`mark_edge_watched`]).
    edge_watched: Cell<bool>,
    /// Threads waiting in epoll_wait (or ppoll/pselect6 on this epoll): woken directly by
    /// `epoll_ctl` and [`EpollWatches`] when watched objects change.
    waiters: Vec<Arc<appine_hal::Event>>,
    /// Per-kernel wake-object registry (`Some` for epolls created by `epoll_create1`; `None` for
    /// standalone `Epoll::default()` in unit tests, which fall back to full scans).
    watches: Option<Weak<RefCell<EpollWatches>>>,
    /// Weak self-reference used when registering subscriptions in `watches`.
    self_weak: Weak<RefCell<Epoll>>,
    /// Ready/dirty queue of slot indices for tracked epolls.
    ready_queue: VecDeque<usize>,
    /// Slots in [`WatchMode::Dynamic`] (always checked during scans).
    dynamic: Vec<usize>,
    /// Host epoll monitoring [`WatchMode::HostEpoll`] interests (lazily created on first host fd).
    host_epoll: Option<appine_hal::HostEpoll>,
    /// Number of host fds + `HostEdges` fds currently armed in `host_epoll`.
    host_epoll_count: usize,
    /// Host fd -> slot currently armed in `host_epoll` (prevents `EEXIST` on duplicate host fds).
    host_epoll_fds: HashMap<i32, usize>,
}

/// Level-triggered host fds in scan order and the events already known inside the guest kernel.
#[derive(Default)]
struct HostPollBatch {
    fds: Vec<(i32, i16, i16)>,
    interests: Vec<(usize, i16)>,
}

impl HostPollBatch {
    fn push(&mut self, index: usize, fd: i32, wanted: i16, known: i16) {
        self.fds.push((fd, wanted, 0));
        self.interests.push((index, known));
    }

    fn report(&mut self, out: &mut Vec<(usize, u32)>) {
        if self.fds.is_empty() {
            return;
        }
        poll_host_batch(&mut self.fds);
        for ((index, known), (_, wanted, revents)) in
            self.interests.drain(..).zip(self.fds.drain(..))
        {
            let ev = (known | revents) & (wanted | ALWAYS_REPORTED);
            if ev != 0 {
                out.push((index, ev as u16 as u32));
            }
        }
    }
}

impl Drop for Epoll {
    fn drop(&mut self) {
        self.with_watches(|w, ep_ptr| {
            for (slot, entry) in self.interests.iter().enumerate() {
                if let Some(int) = entry {
                    w.unregister(ep_ptr, slot, &int.wake_objs, int.file_ptr, int.in_et_pipes);
                }
            }
        });
    }
}

impl Epoll {
    fn with_watches(&self, f: impl FnOnce(&mut EpollWatches, usize)) {
        if let Some(watches) = self.watches.as_ref().and_then(Weak::upgrade)
            && let Ok(mut w) = watches.try_borrow_mut()
        {
            f(&mut w, self.self_weak.as_ptr() as usize);
        }
    }

    fn alloc_epoch(&mut self) -> u32 {
        self.next_epoch = (self.next_epoch.wrapping_add(1)) & 0x7fff_ffff;
        if self.next_epoch == 0 {
            self.next_epoch = 1;
        }
        self.next_epoch
    }

    fn slot_matches(&self, slot: usize, epoch: u32) -> bool {
        self.interests
            .get(slot)
            .and_then(Option::as_ref)
            .is_some_and(|int| int.epoch == epoch)
    }

    fn mark_dirty(&mut self, slot: usize) {
        if let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut)
            && int.armed
            && !matches!(int.mode, WatchMode::Dynamic)
            && !int.in_ready
        {
            int.in_ready = true;
            self.ready_queue.push_back(slot);
        }
    }

    fn unmark_dirty(&mut self, slot: usize) {
        if let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut)
            && int.in_ready
        {
            if let Some(pos) = self.ready_queue.iter().rposition(|&s| s == slot) {
                self.ready_queue.remove(pos);
            }
            int.in_ready = false;
        }
    }

    fn wake_waiters(&self) {
        for w in &self.waiters {
            crate::kernel::signal_later(w);
        }
    }

    fn live_parents(&mut self) -> Vec<Rc<RefCell<Epoll>>> {
        self.parents.retain(|w| w.strong_count() > 0);
        self.parents.iter().filter_map(Weak::upgrade).collect()
    }

    /// Removes interests whose file has been closed.
    fn prune(&mut self) {
        for slot in 0..self.interests.len() {
            if self.interests[slot]
                .as_ref()
                .is_some_and(|int| int.file.strong_count() == 0)
            {
                self.remove_slot(slot, false);
            }
        }
    }

    /// Inserts `int` into a free slab slot, returning the slot index.
    fn alloc_slot(&mut self, int: Interest) -> usize {
        let key = (int.fd, int.file_ptr);
        let slot = if let Some(slot) = self.free.pop() {
            self.interests[slot] = Some(int);
            slot
        } else {
            let slot = self.interests.len();
            self.interests.push(Some(int));
            slot
        };
        self.index.insert(key, slot);
        self.live_count += 1;
        slot
    }

    /// Unregisters tracking state for `slot` (subscriptions, host_epoll, dynamic list, ready_queue).
    /// `file_alive` must be false when the `OpenFile` has already been dropped so we never `DEL`
    /// a reused host fd number belonging to another file.
    fn untrack_slot(&mut self, slot: usize, file_alive: bool) {
        self.unmark_dirty(slot);
        let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        let mode = int.mode;
        int.mode = WatchMode::Dynamic;
        match mode {
            WatchMode::WakeObjects => {
                self.wake_tracked_count = self.wake_tracked_count.saturating_sub(1);
            }
            WatchMode::HostEpoll {
                armed_fd,
                armed_edges_fd,
                ..
            } => {
                if let Some(fd) = armed_fd {
                    if self.host_epoll_fds.get(&fd) == Some(&slot) {
                        self.host_epoll_fds.remove(&fd);
                    }
                    self.host_epoll_count = self.host_epoll_count.saturating_sub(1);
                    if file_alive && let Some(he) = &self.host_epoll {
                        let _ = he.remove(fd);
                    }
                }
                if let Some(efd) = armed_edges_fd {
                    self.host_epoll_count = self.host_epoll_count.saturating_sub(1);
                    if file_alive && let Some(he) = &self.host_epoll {
                        let _ = he.remove(efd);
                    }
                }
            }
            WatchMode::Dynamic => {
                if let Some(pos) = self.dynamic.iter().position(|&s| s == slot) {
                    self.dynamic.swap_remove(pos);
                }
            }
        }
        let wake_objs = std::mem::take(&mut int.wake_objs);
        let file_ptr = int.file_ptr;
        let in_et_pipes = std::mem::replace(&mut int.in_et_pipes, false);
        self.with_watches(|w, ep_ptr| {
            w.unregister(ep_ptr, slot, &wake_objs, file_ptr, in_et_pipes);
        });
    }

    /// Removes interest at `slot`, adding its share to `base` so the nested data generation never
    /// decreases.
    fn remove_slot(&mut self, slot: usize, file_alive: bool) -> Option<Interest> {
        self.untrack_slot(slot, file_alive);
        let int = self.interests.get_mut(slot)?.take()?;
        self.index.remove(&(int.fd, int.file_ptr));
        self.free.push(slot);
        self.live_count = self.live_count.saturating_sub(1);
        self.base.set(self.base.get() + int.share.get());
        Some(int)
    }

    /// Registers a newly added or modified slot on a tracked epoll.
    fn track_slot(&mut self, slot: usize) {
        if self.watches.is_none() {
            return;
        }
        let Some(int) = self.interests.get(slot).and_then(Option::as_ref) else {
            return;
        };
        let Some(file) = int.file.upgrade() else {
            return;
        };
        let f = file.borrow();
        let events = int.events;
        let epoch = int.epoch;
        let file_ptr = int.file_ptr;
        let dynamic = is_dynamic_interest(&f, events);
        let host_kind = !dynamic && is_host_epoll_kind(&f);
        let mut wake_objs = Vec::new();
        let mut et_pipe = false;
        if !dynamic {
            wake_objects(&f, &mut wake_objs);
            et_pipe = matches!(f.kind, FileKind::Pipe(_))
                && (events & EPOLLET != 0 || self.edge_watched.get());
        }
        drop(f);

        if dynamic {
            let int = self.interests[slot].as_mut().unwrap();
            int.mode = WatchMode::Dynamic;
            self.dynamic.push(slot);
            return;
        }

        self.with_watches(|w, _| {
            w.register(&self.self_weak, slot, epoch, &wake_objs, file_ptr, et_pipe);
        });
        let int = self.interests[slot].as_mut().unwrap();
        int.wake_objs = wake_objs;
        int.in_et_pipes = et_pipe;
        if host_kind {
            int.mode = WatchMode::HostEpoll {
                armed_fd: None,
                armed_events: 0,
                armed_edges_fd: None,
            };
            self.sync_host_epoll_slot(slot);
        } else {
            int.mode = WatchMode::WakeObjects;
            self.wake_tracked_count += 1;
        }
        // Check initial readiness on the next scan (Linux checks readiness at ADD/MOD).
        self.mark_dirty(slot);
    }

    /// Reconciles `slot`'s `HostEpoll` registrations with its current `armed`/`seen`/socket state.
    /// Demotes `slot` to `WatchMode::Dynamic` if the host fd cannot be added (`EPERM`/`EEXIST`).
    fn sync_host_epoll_slot(&mut self, slot: usize) {
        let Some(int) = self.interests.get(slot).and_then(Option::as_ref) else {
            return;
        };
        let WatchMode::HostEpoll {
            mut armed_fd,
            mut armed_events,
            mut armed_edges_fd,
        } = int.mode
        else {
            return;
        };
        let Some(file) = int.file.upgrade() else {
            self.remove_slot(slot, false);
            return;
        };
        let f = file.borrow();
        if !is_host_epoll_kind(&f) {
            drop(f);
            self.demote_to_dynamic(slot);
            return;
        }
        let (want_fd, want_edges_fd) = if !int.armed {
            (None, None)
        } else {
            let wanted = int.events as i16;
            let want_fd = armable_host_fd(&f).and_then(|fd| {
                if int.events & EPOLLET != 0 {
                    let seen = int.seen.get() as i16;
                    if seen & (POLLHUP | POLLERR) != 0 {
                        None
                    } else {
                        Some((fd, (wanted & !seen) as u16 as u32))
                    }
                } else {
                    Some((fd, wanted as u16 as u32))
                }
            });
            let want_edges_fd = if int.events & EPOLLET != 0 || self.edge_watched.get() {
                f.host_edges.as_ref().map(HostEdges::fd)
            } else {
                None
            };
            (want_fd, want_edges_fd)
        };
        let epoch = int.epoch;
        drop(f);

        if (want_fd.is_some() || want_edges_fd.is_some()) && self.host_epoll.is_none() {
            match appine_hal::HostEpoll::new() {
                Ok(he) => self.host_epoll = Some(he),
                Err(_) => {
                    self.demote_to_dynamic(slot);
                    return;
                }
            }
        }
        let Some(he) = self.host_epoll.as_ref() else {
            return;
        };

        let mut ok = true;
        // Reconcile the primary host fd.
        if let Some(old) = armed_fd
            && want_fd.map(|(fd, _)| fd) != Some(old)
        {
            let _ = he.remove(old);
            if self.host_epoll_fds.get(&old) == Some(&slot) {
                self.host_epoll_fds.remove(&old);
            }
            self.host_epoll_count = self.host_epoll_count.saturating_sub(1);
            armed_fd = None;
            armed_events = 0;
        }
        if let Some((fd, ev)) = want_fd {
            let token = host_token(slot, epoch, false);
            if armed_fd == Some(fd) {
                if armed_events != ev {
                    if he.modify(fd, ev, token).is_ok() {
                        armed_events = ev;
                    } else {
                        ok = false;
                    }
                }
            } else if !self.host_epoll_fds.contains_key(&fd) && he.add(fd, ev, token).is_ok() {
                self.host_epoll_fds.insert(fd, slot);
                self.host_epoll_count += 1;
                armed_fd = Some(fd);
                armed_events = ev;
            } else {
                // Duplicate host fd in the same epoll or non-epollable host fd: use Dynamic path.
                ok = false;
            }
        }

        // Reconcile the HostEdges fd (for EPOLLET / edge_watched).
        if ok {
            if let Some(old) = armed_edges_fd
                && want_edges_fd != Some(old)
            {
                let _ = he.remove(old);
                self.host_epoll_count = self.host_epoll_count.saturating_sub(1);
                armed_edges_fd = None;
            }
            if let Some(efd) = want_edges_fd
                && armed_edges_fd != Some(efd)
            {
                let etoken = host_token(slot, epoch, true);
                if he.add(efd, POLLIN as u32, etoken).is_ok() {
                    self.host_epoll_count += 1;
                    armed_edges_fd = Some(efd);
                } else {
                    ok = false;
                }
            }
        }

        if let Some(int) = self.interests[slot].as_mut() {
            int.mode = WatchMode::HostEpoll {
                armed_fd,
                armed_events,
                armed_edges_fd,
            };
        }
        if !ok {
            self.demote_to_dynamic(slot);
        }
    }

    fn demote_to_dynamic(&mut self, slot: usize) {
        self.untrack_slot(slot, true);
        if let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut) {
            int.mode = WatchMode::Dynamic;
            self.dynamic.push(slot);
        }
    }

    /// Refreshes a `WatchMode::WakeObjects` interest's wake-object subscriptions when an AF_UNIX
    /// socket changes link (e.g. `SOCK_DGRAM` reconnect).
    fn refresh_wake_objects(&mut self, slot: usize, f: &OpenFile) {
        let mut current = Vec::new();
        wake_objects(f, &mut current);
        let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        if int.wake_objs == current {
            return;
        }
        let old = std::mem::replace(&mut int.wake_objs, current.clone());
        let epoch = int.epoch;
        self.with_watches(|w, ep_ptr| {
            w.unregister_objects(ep_ptr, slot, &old);
            w.register_objects(&self.self_weak, slot, epoch, &current);
        });
    }

    /// Checks immediately which interests are ready, at most `max`: `(slot, events)`. Only checks,
    /// without consuming edge-triggered events (they are recorded by [`Epoll::reported`] after
    /// being reported).
    fn ready(&mut self, depth: u32, max: usize) -> Vec<(usize, u32)> {
        if self.watches.is_some() {
            self.ready_tracked(depth, max)
        } else {
            self.ready_untracked(depth, max)
        }
    }

    /// Pulls ready host-backed interests from `host_epoll` in a single O(ready) call, marking them
    /// dirty and pruning dead slots. Returns `(host_hits, truncated)`.
    fn poll_host_epoll(&mut self, max: usize) -> (Vec<(usize, i16)>, bool) {
        let mut host_hits = Vec::new();
        let mut truncated = false;
        let mut dead_slots = Vec::new();
        if self.host_epoll_count > 0
            && let Some(he) = &self.host_epoll
        {
            let want = max.clamp(16, 256).min(self.host_epoll_count);
            let mut stack_buf = [(0u64, 0u32); 64];
            let mut heap_buf;
            let buf: &mut [(u64, u32)] = if want <= stack_buf.len() {
                &mut stack_buf[..want]
            } else {
                heap_buf = vec![(0u64, 0u32); want];
                &mut heap_buf
            };
            if let Ok(count) = he.wait_now(buf) {
                truncated = count == buf.len();
                for &(data, revents) in &buf[..count] {
                    let (slot, epoch, is_edges) = decode_host_token(data);
                    if !self.slot_matches(slot, epoch) {
                        continue;
                    }
                    let Some(file) = self.interests[slot]
                        .as_ref()
                        .and_then(|int| int.file.upgrade())
                    else {
                        dead_slots.push(slot);
                        continue;
                    };
                    if is_edges {
                        if let Some(e) = &file.borrow().host_edges {
                            e.polled(POLLIN);
                        }
                    } else {
                        host_hits.push((slot, revents as i16));
                    }
                    self.mark_dirty(slot);
                }
            } else {
                truncated = true;
            }
        }
        for slot in dead_slots {
            self.remove_slot(slot, false);
        }
        (host_hits, truncated)
    }

    fn flush_tracked_batch(&mut self, batch: &mut HostPollBatch, out: &mut Vec<(usize, u32)>) {
        let before = out.len();
        batch.report(out);
        for &(s, _) in &out[before..] {
            self.mark_dirty(s);
        }
    }

    /// Event-driven ready scan for tracked epolls: polls `host_epoll` in O(ready), drains only
    /// queued entries from `ready_queue`, and checks the `dynamic` list.
    fn ready_tracked(&mut self, depth: u32, max: usize) -> Vec<(usize, u32)> {
        // 1. Pull ready host-backed interests from host_epoll in a single O(ready) call.
        let (mut host_hits, host_truncated) = self.poll_host_epoll(max);
        let sorted_hits = host_hits.len() > 16;
        if sorted_hits {
            host_hits.sort_unstable_by_key(|&(s, _)| s);
        }
        let lookup_hit = |slot: usize| -> Option<i16> {
            if sorted_hits {
                host_hits
                    .binary_search_by_key(&slot, |&(s, _)| s)
                    .ok()
                    .map(|idx| host_hits[idx].1)
            } else {
                host_hits.iter().find(|&&(s, _)| s == slot).map(|&(_, r)| r)
            }
        };

        let mut out = Vec::new();
        let mut batch = HostPollBatch::default();
        let mut to_sync: Vec<usize> = Vec::new();
        let mut notify_files: Vec<usize> = Vec::new();

        // 2. Process queued dirty/ready entries (at most the initial queue length so newly
        //    re-queued entries wait for the next call, preserving Linux's round-robin order).
        let to_check = self.ready_queue.len();
        for _ in 0..to_check {
            if out.len() == max {
                break;
            }
            let Some(slot) = self.ready_queue.pop_front() else {
                break;
            };
            let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut) else {
                continue;
            };
            int.in_ready = false;
            if !int.armed {
                continue;
            }
            let Some(file) = int.file.upgrade() else {
                self.remove_slot(slot, false);
                continue;
            };
            let mode = int.mode;
            let events = int.events;
            let wanted = events as i16;
            let file_ptr = int.file_ptr;
            let f = file.borrow();
            let ev = match mode {
                WatchMode::HostEpoll { armed_fd, .. } => {
                    let host_ok = is_host_epoll_kind(&f);
                    if host_ok && events & EPOLLET == 0 && f.host_edges.is_none() {
                        let (known, host) = readiness(&f, depth);
                        if let Some(fd) = host {
                            if let Some(revents) = lookup_hit(slot) {
                                ((known | revents) & (wanted | ALWAYS_REPORTED)) as u16 as u32
                            } else if !host_truncated && armed_fd == Some(fd) {
                                (known & (wanted | ALWAYS_REPORTED)) as u16 as u32
                            } else if max > 1 {
                                drop(f);
                                batch.push(slot, fd, wanted, known);
                                if armed_fd != Some(fd) {
                                    to_sync.push(slot);
                                }
                                if batch.fds.len() == max - out.len() {
                                    self.flush_tracked_batch(&mut batch, &mut out);
                                }
                                continue;
                            } else {
                                if armed_fd != Some(fd) {
                                    to_sync.push(slot);
                                }
                                poll_now(&f, wanted, depth) as u16 as u32
                            }
                        } else {
                            if armed_fd.is_some() {
                                to_sync.push(slot);
                            }
                            (known & (wanted | ALWAYS_REPORTED)) as u16 as u32
                        }
                    } else {
                        // Also handles a UDP socket that gained `udp_tap` (e.g. IP_RECVERR) after
                        // EPOLL_CTL_ADD: dispatch via poll_now_full and demote via `to_sync`.
                        let (raw, _, edge_seen) = poll_now_full(&f, wanted, depth);
                        let raw = raw as u16 as u32;
                        let ev = if events & EPOLLET != 0 {
                            et_filter(self.interests[slot].as_ref().unwrap(), &f, raw)
                        } else {
                            raw
                        };
                        if edge_seen {
                            notify_files.push(file_ptr);
                        }
                        if !host_ok || ev == 0 {
                            to_sync.push(slot);
                        }
                        ev
                    }
                }
                WatchMode::WakeObjects => {
                    let (known, _) = readiness(&f, depth);
                    let raw = (known & (wanted | ALWAYS_REPORTED)) as u16 as u32;
                    let ev = if events & EPOLLET != 0 {
                        et_filter(self.interests[slot].as_ref().unwrap(), &f, raw)
                    } else {
                        raw
                    };
                    if matches!(f.kind, FileKind::Socket(_)) {
                        self.refresh_wake_objects(slot, &f);
                    }
                    ev
                }
                WatchMode::Dynamic => continue,
            };
            drop(f);
            if ev != 0 {
                self.flush_tracked_batch(&mut batch, &mut out);
                // Keep queued until `reported` confirms copy-out (preserves EFAULT safety and
                // level-triggered round-robin).
                self.mark_dirty(slot);
                if out.len() < max {
                    out.push((slot, ev));
                } else {
                    break;
                }
            }
        }
        self.flush_tracked_batch(&mut batch, &mut out);
        for slot in to_sync {
            self.sync_host_epoll_slot(slot);
        }

        // 3. Check dynamic/fallback interests (timers, signalfds, pidfds, nested epolls,
        //    EPOLLEXCLUSIVE, host stdio, udp_tap, duplicate host fds).
        if out.len() < max && !self.dynamic.is_empty() {
            let dlen = self.dynamic.len();
            let start = self.cursor % dlen;
            let slots: Vec<usize> = (start..dlen)
                .chain(0..start)
                .map(|i| self.dynamic[i])
                .collect();
            let mut dead_slots = Vec::new();
            self.scan_slots(
                &slots,
                depth,
                max,
                &mut out,
                &mut dead_slots,
                &mut notify_files,
            );
            for slot in dead_slots {
                self.remove_slot(slot, false);
            }
        }
        if !notify_files.is_empty() {
            self.with_watches(|w, ep_ptr| w.notify_files(&notify_files, ep_ptr));
        }

        out
    }

    /// Full scan for untracked (`Epoll::default()`) standalone instances used in unit tests.
    fn ready_untracked(&mut self, depth: u32, max: usize) -> Vec<(usize, u32)> {
        let mut out = Vec::new();
        let n = self.interests.len();
        if n == 0 {
            return out;
        }
        let start = self.cursor % n;
        let slots: Vec<usize> = (start..n).chain(0..start).collect();
        let mut dead = Vec::new();
        let mut notify_files = Vec::new();
        self.scan_slots(&slots, depth, max, &mut out, &mut dead, &mut notify_files);
        out
    }

    /// Scans `slots` in order, batching eligible level-triggered host fds and caching each
    /// scanned interest's `host` fd so `Waits` avoids recomputing `readiness`.
    fn scan_slots(
        &self,
        slots: &[usize],
        depth: u32,
        max: usize,
        out: &mut Vec<(usize, u32)>,
        dead: &mut Vec<usize>,
        notify_files: &mut Vec<usize>,
    ) {
        let owner = self as *const Epoll as usize;
        let mut batch = HostPollBatch::default();
        for &slot in slots {
            if out.len() == max {
                break;
            }
            let Some(int) = self.interests.get(slot).and_then(Option::as_ref) else {
                continue;
            };
            if !int.armed {
                continue;
            }
            let Some(file) = int.file.upgrade() else {
                dead.push(slot);
                continue;
            };
            let f = file.borrow();
            // Exclusive interest: this edge has gone to another epoll, so treat it as not ready.
            let (is_claimed, edge_consumed) = check_claimed(int, &f, owner);
            if edge_consumed {
                notify_files.push(int.file_ptr);
            }
            if is_claimed {
                continue;
            }
            let wanted = int.events as i16;
            let ev = if max > 1
                && int.events & (EPOLLET | EPOLLEXCLUSIVE) == 0
                && f.host_edges.is_none()
            {
                let (known, host) = readiness(&f, depth);
                int.cached_host.set(Some(host));
                if let Some(fd) = host {
                    batch.push(slot, fd, wanted, known);
                    // Even if every fd is ready, keep this scan within the caller's output limit.
                    if batch.fds.len() == max - out.len() {
                        batch.report(out);
                    }
                    continue;
                }
                known & (wanted | ALWAYS_REPORTED)
            } else {
                let (ev, host, edge_seen) = poll_now_full(&f, wanted, depth);
                int.cached_host.set(Some(host));
                if edge_seen {
                    notify_files.push(int.file_ptr);
                }
                ev
            } as u16 as u32;
            let ev = if int.events & EPOLLET != 0 {
                et_filter(int, &f, ev)
            } else {
                ev
            };
            if ev != 0 {
                // Report preceding host fds first. Idle guest objects leave the batch open.
                batch.report(out);
                if out.len() == max {
                    break;
                }
                out.push((slot, ev));
            }
        }
        batch.report(out);
    }

    /// Events `ev` of interest at `slot` have been reported to the guest.
    fn reported(&mut self, slot: usize, ev: u32) {
        let owner = self as *const Epoll as usize;
        let Some(int) = self.interests.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        int.seen.set(ev);
        let events = int.events;
        if events & EPOLLONESHOT != 0 {
            int.armed = false;
        }
        if let Some(file) = int.file.upgrade() {
            let f = file.borrow();
            took_change(&f, ev as i16);
            // Exclusive interest: this edge belongs to this epoll; other epolls wait for the next
            // edge
            if events & EPOLLEXCLUSIVE != 0 {
                f.exclusive_claim.set(Some((edge(&f), owner)));
            }
        }
        let tracked = self.watches.is_some();
        let is_host_epoll = matches!(int.mode, WatchMode::HostEpoll { .. });
        if tracked && events & (EPOLLET | EPOLLONESHOT) != 0 {
            self.unmark_dirty(slot);
            if is_host_epoll {
                self.sync_host_epoll_slot(slot);
            }
        }
        self.cursor = slot + 1;
    }

    /// The open file of the `nth` interest (counting from 0) with fd `fd` (kcmp's
    /// `KCMP_EPOLL_TFD`).
    pub(crate) fn target(&self, fd: i32, nth: usize) -> Option<FileRef> {
        self.interests
            .iter()
            .flatten()
            .filter(|i| i.fd == fd)
            .filter_map(|i| i.file.upgrade())
            .nth(nth)
    }

    /// One line per interest in `/proc/<pid>/fdinfo`. As on Linux, the watched events always
    /// include EPOLLERR and EPOLLHUP.
    pub(crate) fn fdinfo(&self) -> String {
        let mut s = String::new();
        for int in self.interests.iter().flatten() {
            let Some(file) = int.file.upgrade() else {
                continue;
            };
            let f = file.borrow();
            let (dev, ino) = int.fdinfo_id;
            let events = int.events | (POLLERR | POLLHUP) as u32;
            s += &format!(
                "tfd: {:8} events: {events:8x} data: {:16x}  pos:{} ino:{ino:x} sdev:{dev:x}\n",
                int.fd, int.data, f.pos
            );
        }
        s
    }
}

/// Applies `EPOLLET` filtering to raw ready bits `ev` of `int`: forgets reported bits in any
/// direction that was drained or received a new arrival, drops bits no longer ready, and returns
/// `ev` if any un-seen bit is ready (otherwise 0).
fn et_filter(int: &Interest, f: &OpenFile, ev: u32) -> u32 {
    let drained = f.drained;
    let last = int.drained.replace(drained);
    let came = arrivals_polled(f);
    let before = int.arrivals.replace(came);
    let mut seen = int.seen.get();
    if drained[0] != last[0] || came[0] != before[0] {
        seen &= WRITE_BITS;
    }
    if drained[1] != last[1] || came[1] != before[1] {
        seen &= !WRITE_BITS;
    }
    // Forget bits no longer ready, so they can fire again the next time they become ready
    seen &= ev;
    int.seen.set(seen);
    if ev & !seen == 0 { 0 } else { ev }
}

pub(super) fn epoll_create1(cx: &mut Cx<'_>, flags: u32) -> SysResult {
    if flags & !oflags::O_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let watches = Rc::downgrade(&cx.kr().epoll_watches);
    let mut ep = Epoll::default();
    ep.watches = Some(watches);
    let ep = Rc::new(RefCell::new(ep));
    ep.borrow_mut().self_weak = Rc::downgrade(&ep);
    let file = OpenFile::new(FileKind::Epoll(ep), oflags::O_RDWR);
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

pub(super) fn epoll_ctl(cx: &mut Cx<'_>, epfd: i32, op: u32, fd: i32, event: u64) -> SysResult {
    // Linux 6.1's order: the event is copied first (every operation but DEL), then both fds are
    // looked up (EBADF), the target must support poll (EPERM), and only then is epfd checked to
    // be another file and an epoll (EINVAL)
    let (events, data) = if op == EPOLL_CTL_DEL {
        (0, 0)
    } else {
        let b: [u8; 16] = get(cx, event)?;
        (
            u32::from_le_bytes(b[..4].try_into().unwrap()),
            u64::from_le_bytes(b[8..].try_into().unwrap()),
        )
    };
    let epf = cx.fds().get(epfd)?;
    let file = cx.fds().get(fd)?;
    if file.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    // Regular files, directories, devices like /dev/null and the synthetic files without a poll
    // operation (per-process procfs files, nsfs) do not support poll, and Linux does not allow
    // adding them to an epoll
    if matches!(
        &file.borrow().kind,
        FileKind::Proc { klog: None, node, .. } if !crate::pseudo::pollable(node)
    ) || matches!(
        file.borrow().kind,
        FileKind::Regular { .. }
            | FileKind::Directory { .. }
            | FileKind::Device {
                dev: Device::Null
                    | Device::Zero
                    | Device::Full
                    | Device::Loop
                    | Device::LoopControl,
                ..
            }
    ) {
        return Err(Errno::EPERM);
    }
    let FileKind::Epoll(ep) = &epf.borrow().kind else {
        return Err(Errno::EINVAL);
    };
    let ep = ep.clone();
    let key = wake::of(&ep);
    if Rc::ptr_eq(&epf, &file) {
        return Err(Errno::EINVAL);
    }
    // As on Linux: EPOLLEXCLUSIVE can be used only when adding, not on epolls, and not with other
    // flags
    if events & EPOLLEXCLUSIVE != 0
        && (op == EPOLL_CTL_MOD
            || op == EPOLL_CTL_ADD
                && (matches!(file.borrow().kind, FileKind::Epoll(_))
                    || events & !EXCLUSIVE_OK != 0))
    {
        return Err(Errno::EINVAL);
    }
    // Adding another epoll: no loops, and total nesting depth (ancestors of `ep` plus the
    // target's subtree) no deeper than EP_MAX_NESTS levels
    if op == EPOLL_CTL_ADD && matches!(file.borrow().kind, FileKind::Epoll(_)) {
        let ancestors = ancestor_depth(&ep, 0);
        if nesting(&file, &ep, 0).is_none_or(|d| ancestors.saturating_add(d) > MAX_NESTS) {
            return Err(Errno::ELOOP);
        }
    }
    let had_host_edges = op != EPOLL_CTL_DEL && file.borrow().host_edges.is_some();
    if op != EPOLL_CTL_DEL {
        if events & (EPOLLET | EPOLLEXCLUSIVE) != 0 || ep.borrow().edge_watched.get() {
            watch_host_edges(&file);
        }
        // Watching another epoll edge-triggered, or adding an epoll to an epoll watched that
        // way: the host fds inside must record newly arrived data too
        if let FileKind::Epoll(inner) = &file.borrow().kind
            && (events & EPOLLET != 0 || ep.borrow().edge_watched.get())
        {
            mark_edge_watched(inner, 0);
        }
    }
    // Already ready when added or modified: as on Linux, wake the outer epolls waiting on it (the
    // data generation when nested goes up by one). This matters only when an outer epoll waits
    // on it edge-triggered, so the host need not be asked every time
    let ready_now = op != EPOLL_CTL_DEL
        && ep.borrow().edge_watched.get()
        && poll_now(&file.borrow(), events as i16, 0) != 0;
    let fdinfo_id = if op != EPOLL_CTL_DEL {
        let vfs = cx.vfs().ok();
        file_fdinfo_dev_ino(vfs.as_deref(), &file.borrow())
    } else {
        (0, 0)
    };
    let ep_rc = ep.clone();
    let mut ep = ep.borrow_mut();
    let file_ptr = Rc::as_ptr(&file) as usize;
    // Check only the matching `(fd, file_ptr)` entry in O(1); prune if its file already died.
    let pos = match ep.index.get(&(fd, file_ptr)).copied() {
        Some(slot)
            if ep.interests[slot]
                .as_ref()
                .is_some_and(|i| i.file.strong_count() == 0) =>
        {
            ep.remove_slot(slot, false);
            None
        }
        other => other,
    };
    // Other threads may be in epoll_wait: wake them to wait again with the new interests. Epolls
    // and polls wrapping this one wait on its wake object (request_wake_object below)
    ep.wake_waiters();
    match (op, pos) {
        (EPOLL_CTL_ADD, Some(_)) => Err(Errno::EEXIST),
        (EPOLL_CTL_ADD, None) => {
            // Amortized pruning when the slab is about to grow and has no free slots.
            if ep.free.is_empty()
                && ep.interests.len() >= 64
                && ep.interests.len().is_power_of_two()
            {
                ep.prune();
            }
            let epoch = ep.alloc_epoch();
            let int = Interest::new(fd, &file, events, data, fdinfo_id, epoch);
            let slot = ep.alloc_slot(int);
            ep.base.set(ep.base.get() + ready_now as u64);
            ep.track_slot(slot);
            drop(ep);
            if had_host_edges {
                // `Interest::new` called `arrivals(&f)` -> `HostEdges::counts()`, which may have
                // drained a pending host edge shared with other tracked epolls on this open file.
                cx.kr()
                    .epoll_watches
                    .borrow_mut()
                    .notify_file(file_ptr, Rc::as_ptr(&ep_rc) as usize);
            }
            if let FileKind::Epoll(inner) = &file.borrow().kind {
                inner.borrow_mut().parents.push(Rc::downgrade(&ep_rc));
            }
            request_wake_object(key);
            Ok(0)
        }
        // An interest added with EPOLLEXCLUSIVE cannot be modified
        (EPOLL_CTL_MOD, Some(slot))
            if ep.interests[slot]
                .as_ref()
                .is_some_and(|i| i.events & EPOLLEXCLUSIVE != 0) =>
        {
            Err(Errno::EINVAL)
        }
        // As on Linux, readiness is judged again after a modification: if already ready, it is
        // reported once more
        (EPOLL_CTL_MOD, Some(slot)) => {
            ep.untrack_slot(slot, true);
            let epoch = ep.alloc_epoch();
            let new_int = Interest::new(fd, &file, events, data, fdinfo_id, epoch);
            let old = ep.interests[slot].replace(new_int).unwrap();
            ep.base
                .set(ep.base.get() + old.share.get() + ready_now as u64);
            ep.track_slot(slot);
            drop(ep);
            if had_host_edges {
                cx.kr()
                    .epoll_watches
                    .borrow_mut()
                    .notify_file(file_ptr, Rc::as_ptr(&ep_rc) as usize);
            }
            request_wake_object(key);
            Ok(0)
        }
        (EPOLL_CTL_DEL, Some(slot)) => {
            ep.remove_slot(slot, true);
            drop(ep);
            if let FileKind::Epoll(inner) = &file.borrow().kind {
                let mut inner = inner.borrow_mut();
                if let Some(p) = inner
                    .parents
                    .iter()
                    .position(|w| w.as_ptr() == Rc::as_ptr(&ep_rc))
                {
                    inner.parents.swap_remove(p);
                }
            }
            Ok(0)
        }
        (EPOLL_CTL_MOD | EPOLL_CTL_DEL, None) => Err(Errno::ENOENT),
        _ => Err(Errno::EINVAL),
    }
}

/// How many levels of outer epolls currently watch `ep` (0 when none do).
fn ancestor_depth(ep: &Rc<RefCell<Epoll>>, level: u32) -> u32 {
    if level > MAX_NESTS {
        return level;
    }
    let parents = ep.borrow_mut().live_parents();
    let mut depth = 0;
    for parent in parents {
        depth = depth.max(1 + ancestor_depth(&parent, level + 1));
    }
    depth
}

/// How many levels of epoll are nested in `file` (0 when it is not an epoll, 1 for an epoll that
/// watches only ordinary objects); None when `target` can be reached from it (which would make a
/// loop) or the nesting is too deep.
fn nesting(file: &FileRef, target: &Rc<RefCell<Epoll>>, level: u32) -> Option<u32> {
    let FileKind::Epoll(ep) = &file.borrow().kind else {
        return Some(0);
    };
    if Rc::ptr_eq(ep, target) || level > MAX_NESTS {
        return None;
    }
    let children: Vec<FileRef> = ep
        .borrow()
        .interests
        .iter()
        .flatten()
        .filter_map(|i| i.file.upgrade())
        .collect();
    let mut depth = 0;
    for child in children {
        depth = depth.max(nesting(&child, target, level + 1)?);
    }
    Some(depth + 1)
}

/// An epoll watches `ep` edge-triggered (`depth` is the nesting level going inward): sets up
/// [`HostEdges`] for the host fds watched by it and by the epolls nested inside it, and for those
/// added later too ([`Epoll::edge_watched`]). The data generations of existing interests take a
/// new starting point, so the newly set-up records do not count as new events.
fn mark_edge_watched(ep: &Rc<RefCell<Epoll>>, depth: u32) {
    if depth >= MAX_NESTS {
        return;
    }
    let mut inner_epolls = Vec::new();
    let mut host_slots = Vec::new();
    {
        let mut ep_mut = ep.borrow_mut();
        ep_mut.edge_watched.set(true);
        let watches = ep_mut.watches.as_ref().and_then(Weak::upgrade);
        let self_weak = ep_mut.self_weak.clone();
        for (slot, entry) in ep_mut.interests.iter_mut().enumerate() {
            let Some(int) = entry else {
                continue;
            };
            let Some(file) = int.file.upgrade() else {
                continue;
            };
            if file.borrow().host_edges.is_none() {
                watch_host_edges(&file);
                int.arrivals.set(arrivals(&file.borrow()));
            }
            if matches!(int.mode, WatchMode::HostEpoll { .. }) {
                host_slots.push(slot);
            }
            if matches!(file.borrow().kind, FileKind::Pipe(_))
                && !int.in_et_pipes
                && !matches!(int.mode, WatchMode::Dynamic)
                && let Some(ref w) = watches
                && let Ok(mut w) = w.try_borrow_mut()
            {
                w.register_et_pipe(&self_weak, slot, int.epoch);
                int.in_et_pipes = true;
            }
            if let FileKind::Epoll(inner) = &file.borrow().kind {
                inner_epolls.push(inner.clone());
            }
        }
        for slot in host_slots {
            ep_mut.sync_host_epoll_slot(slot);
        }
    }
    for inner in inner_epolls {
        mark_edge_watched(&inner, depth + 1);
    }
}

/// Edge-triggered and exclusive interests need to know about newly arrived data on host fds:
/// sets up [`HostEdges`] the first time. It cannot be set up for fds the host does not allow in
/// an epoll (regular files on the host), which still depend only on whether the program has used
/// up the data.
fn watch_host_edges(file: &FileRef) {
    let mut f = file.borrow_mut();
    if f.host_edges.is_some() {
        return;
    }
    let Some(fd) = host_fd(&f) else {
        return;
    };
    match HostEdges::new(fd) {
        Ok(e) => f.host_edges = Some(e),
        Err(e) => crate::debug::log(format_args!("epoll: host fd {fd}: edges: errno {e}")),
    }
}

/// epoll_pwait's timeout: milliseconds; negative means wait forever.
pub(super) fn deadline_ms(timeout: i32) -> Option<Instant> {
    (timeout >= 0).then(|| Instant::now() + Duration::from_millis(timeout as u64))
}

/// epoll_pwait2's timeout: a `struct timespec`; NULL means wait forever.
pub(super) fn deadline_ts(cx: &Cx<'_>, timeout: u64) -> Result<Option<Instant>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    Ok(Some(Instant::now() + read_timespec(cx, timeout)?))
}

pub(super) fn epoll_pwait(
    cx: &mut Cx<'_>,
    epfd: i32,
    events: u64,
    maxevents: i32,
    deadline: Option<Instant>,
    sigmask: u64,
    sigsetsize: usize,
) -> SysResult {
    if maxevents <= 0 || maxevents > i32::MAX / 16 {
        return Err(Errno::EINVAL);
    }
    // access_ok: the events buffer must lie below arm64's TASK_SIZE_MAX (48-bit addresses),
    // mapped or not; before the epoll is looked at
    const TASK_SIZE_MAX: u64 = 1 << 48;
    if events
        .checked_add(maxevents as u64 * 16)
        .is_none_or(|end| end > TASK_SIZE_MAX)
    {
        return Err(Errno::EFAULT);
    }
    // Borrow the open file for this statement only: when `let … else` binds a reference
    // borrowed from it, the borrow lives until the end of the function, and another thread
    // changing this open file while we wait (fcntl, FIONBIO) would panic. epf itself is kept
    // until the end, so it stays alive if the fd is closed while waiting
    let epf = cx.fds().get(epfd)?;
    let ep = match &epf.borrow().kind {
        FileKind::Epoll(ep) => ep.clone(),
        _ => return Err(Errno::EINVAL),
    };
    set_temp_mask(cx, sigmask, sigsetsize)?;
    let r = (|| loop {
        let ready = ep.borrow_mut().ready(0, maxevents as usize);
        if !ready.is_empty() || deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(ready);
        }
        // EINTR as in Linux's ep_poll, never restarted: a signal with no handler (stopped and
        // then continued) and thawing after a cgroup freeze are EINTR too (signal(7))
        if cx.interrupted() {
            return Err(Errno::EINTR);
        }
        let mut waits = Waits::default();
        waits.add_epoll_rc(&ep, 0);
        waits.wait(cx, deadline)?;
    })();
    restore_mask(cx, &r);
    let ready = r?;
    // Copy each event to userspace before marking it reported (ONESHOT disarmed, edge seen,
    // exclusive claim taken), so a faulting buffer leaves unreported events available to a later
    // wait and returns the partial count already copied (Linux's ep_try_send_events)
    let entries: Vec<(usize, u32, u64)> = {
        let ep = ep.borrow();
        ready
            .iter()
            .filter_map(|&(slot, ev)| {
                ep.interests
                    .get(slot)
                    .and_then(Option::as_ref)
                    .map(|int| (slot, ev, int.data))
            })
            .collect()
    };
    let mut written = 0u64;
    for (slot, ev, data) in entries {
        let mut entry = [0u8; 16];
        entry[..4].copy_from_slice(&ev.to_le_bytes());
        entry[8..].copy_from_slice(&data.to_le_bytes());
        let addr = events + written * 16;
        if let Err(e) = cx.mm().write(UserSlice::new(addr, 16), &entry) {
            return if written > 0 { Ok(written) } else { Err(e) };
        }
        ep.borrow_mut().reported(slot, ev);
        written += 1;
    }
    Ok(written)
}

// ---- Waiting ----

/// An `EPOLLEXCLUSIVE` file to register on its [`ExGate`], paired with the caller's requested
/// events, already-seen `EPOLLET` bits, and stable registration order.
struct GatedFile {
    file: FileRef,
    wanted: i16,
    seen: i16,
    order: u64,
}

/// What to wait for together: host fds, and the earliest timerfd expiration (including those in
/// nested epolls).
#[derive(Default)]
struct Waits {
    host: Vec<(i32, i16, i16)>,
    /// Wake objects of in-process objects ([`wake_objects`]).
    objects: Vec<wake::Object>,
    /// Epolls whose `waiters` list this thread joins while sleeping (direct wakes from
    /// `epoll_ctl` and [`EpollWatches`]).
    epolls: Vec<Rc<RefCell<Epoll>>>,
    /// There is a pidfd: changes in child state ([`wake::CHILD`]) must wake it too. No other file
    /// cares about this channel; before, every process exit woke all poll and epoll waiters.
    pidfd: bool,
    /// There is a signalfd: a blocked signal becoming pending ([`wake::SIGNAL`]) must wake it too.
    signalfd: bool,
    timer: Option<Instant>,
    /// Some edge-triggered interest left out bits it has reported from the wait.
    edge: bool,
    /// There are in-process objects that rely on the kernel to wake them (pipes, eventfds,
    /// AF_UNIX...): register on the FILE wake channel.
    files: bool,
    /// Files of `EPOLLEXCLUSIVE` interests: not waited on directly, but registered on their
    /// exclusive gates ([`ExGate`]).
    gated: Vec<GatedFile>,
}

impl Waits {
    fn push_epoll(&mut self, ep: &Rc<RefCell<Epoll>>) {
        if !self.epolls.iter().any(|e| Rc::ptr_eq(e, ep)) {
            self.epolls.push(ep.clone());
        }
    }

    fn add(&mut self, f: &OpenFile, wanted: i16, depth: u32) {
        let (_, host) = readiness(f, depth);
        self.add_with_host(f, wanted, host, depth);
    }

    /// Adds `f` using an already-computed `host` fd so building a blocking wait after an empty
    /// scan does not recompute `readiness(f, depth)`.
    fn add_with_host(&mut self, f: &OpenFile, wanted: i16, host: Option<i32>, depth: u32) {
        self.files |= host.is_none();
        self.pidfd |= matches!(f.kind, FileKind::Pidfd(_));
        self.signalfd |= matches!(f.kind, FileKind::SignalFd(_));
        wake_objects(f, &mut self.objects);
        match (&f.kind, host) {
            (_, Some(fd)) => self.host.push((fd, wanted, 0)),
            (FileKind::TimerFd(t), None) => {
                if let Some(d) = t.borrow().deadline.map(crate::itimer::Expiry::instant) {
                    self.timer = Some(self.timer.map_or(d, |e| e.min(d)));
                }
            }
            // Wait only for new events (an outer edge-triggered interest has reported it
            // readable): wait for newly arrived data on the host sockets inside it and for
            // timers; when events arrive at in-process objects the kernel wakes edge-triggered
            // waiters
            (FileKind::Epoll(ep), None) if depth < MAX_NESTS && wanted & POLLIN == 0 => {
                self.edge = true;
                self.push_epoll(ep);
                self.add_epoll_edges(&ep.borrow(), depth + 1);
            }
            (FileKind::Epoll(ep), None) if depth < MAX_NESTS => {
                self.add_epoll_rc(ep, depth + 1);
            }
            _ => {}
        }
    }

    /// In a nested epoll, waits only for new events: newly arrived data on each interest's host fd
    /// ([`HostEdges`], set up when an outer epoll watches it edge-triggered,
    /// [`mark_edge_watched`]), timerfd expirations, and the same for epolls nested further in.
    fn add_epoll_edges(&mut self, ep: &Epoll, depth: u32) {
        self.files = true;
        for int in ep.interests.iter().flatten().filter(|i| i.armed) {
            let Some(file) = int.file.upgrade() else {
                continue;
            };
            let f = file.borrow();
            if let Some(e) = &f.host_edges {
                self.host.push((e.fd(), POLLIN, 0));
            }
            wake_objects(&f, &mut self.objects);
            self.pidfd |= matches!(f.kind, FileKind::Pidfd(_));
            self.signalfd |= matches!(f.kind, FileKind::SignalFd(_));
            match &f.kind {
                FileKind::TimerFd(t) => {
                    if let Some(d) = t.borrow().deadline.map(crate::itimer::Expiry::instant) {
                        self.timer = Some(self.timer.map_or(d, |e| e.min(d)));
                    }
                }
                FileKind::Epoll(inner) if depth < MAX_NESTS => {
                    self.push_epoll(inner);
                    self.add_epoll_edges(&inner.borrow(), depth + 1);
                }
                _ => {}
            }
        }
    }

    /// Adds a tracked or untracked epoll `Rc`: tracked epolls wait in O(1 + #dynamic) via
    /// `ep.waiters` (woken by [`EpollWatches`]) and `ep.host_epoll` (one host fd for all tracked
    /// host sockets), without copying or sorting all idle interests' wake objects.
    fn add_epoll_rc(&mut self, ep_rc: &Rc<RefCell<Epoll>>, depth: u32) {
        self.push_epoll(ep_rc);
        let ep = ep_rc.borrow();
        if ep.watches.is_some() {
            if let Some(he) = &ep.host_epoll
                && ep.host_epoll_count > 0
            {
                self.host.push((he.fd(), POLLIN, 0));
            }
            if ep.wake_tracked_count > 0 {
                self.files = true;
            }
            for &slot in &ep.dynamic {
                let Some(int) = ep.interests.get(slot).and_then(Option::as_ref) else {
                    continue;
                };
                if !int.armed {
                    continue;
                }
                let Some(file) = int.file.upgrade() else {
                    continue;
                };
                self.add_epoll_interest(&ep, int, file, depth);
            }
        } else {
            self.add_epoll(&ep, depth);
        }
    }

    /// The live, armed interests of an epoll (used for untracked standalone epolls in unit tests).
    fn add_epoll(&mut self, ep: &Epoll, depth: u32) {
        for int in ep.interests.iter().flatten().filter(|i| i.armed) {
            let Some(file) = int.file.upgrade() else {
                continue;
            };
            self.add_epoll_interest(ep, int, file, depth);
        }
    }

    fn add_epoll_interest(&mut self, ep: &Epoll, int: &Interest, file: FileRef, depth: u32) {
        // Exclusive interests: not waited on directly (the host poll would wake every thread
        // waiting on it); the exclusive gate wakes only one waiter on a new edge. Newly
        // arrived data on a host fd must be seen through HostEdges; where that cannot be set
        // up, the thread still waits on the file itself
        let gate = {
            let f = file.borrow();
            int.events & EPOLLEXCLUSIVE != 0 && (host_fd(&f).is_none() || f.host_edges.is_some())
        };
        if gate {
            let wanted = int.events as i16;
            let seen = if int.events & EPOLLET != 0 {
                int.seen.get() as i16
            } else {
                0
            };
            let order = int.exclusive_order;
            if let Some(g) = self.gated.iter_mut().find(|g| Rc::ptr_eq(&g.file, &file)) {
                g.wanted |= wanted;
                g.seen &= seen;
                g.order = g.order.min(order);
            } else {
                self.gated.push(GatedFile {
                    file,
                    wanted,
                    seen,
                    order,
                });
            }
            return;
        }
        let mut wanted = int.events as i16;
        let seen = int.seen.get() as i16;
        let f = file.borrow();
        // Newly arrived data on a host fd can be seen only through HostEdges' host epoll:
        // wait on it
        let mut edges = false;
        let mut hung_up = false;
        if int.events & EPOLLET != 0 && seen != 0 {
            self.edge = true;
            edges = true;
            hung_up = seen & (POLLHUP | POLLERR) != 0;
            wanted &= !seen;
        }
        // An exclusive interest waited on directly (see above): when the current edge went to
        // another epoll, do not wait for the bits ready now
        if check_claimed(int, &f, ep as *const Epoll as usize).0 {
            self.edge = true;
            wanted &= !poll_now(&f, wanted, depth);
        }
        if edges && let Some(e) = &f.host_edges {
            self.host.push((e.fd(), POLLIN, 0));
        }
        if !hung_up {
            match int.cached_host.take() {
                Some(host) => self.add_with_host(&f, wanted, host, depth),
                None => self.add(&f, wanted, depth),
            }
        } else {
            // Not waiting on the host fd itself, but in-process objects may still get events
            // later (a PTY whose slave is reopened)
            self.files = true;
            wake_objects(&f, &mut self.objects);
        }
    }

    /// Waits until `deadline`, until some host fd is ready or a timerfd expires, or until woken.
    fn wait(mut self, cx: &mut Cx<'_>, deadline: Option<Instant>) -> Result<(), Errno> {
        let until = match (deadline, self.timer) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let event = cx.task.event.clone();
        for ep in &self.epolls {
            ep.borrow_mut().waiters.push(event.clone());
        }
        if self.edge {
            cx.k().edge_waiters.push(event.clone());
        }
        if !self.gated.is_empty() {
            gate_enter(cx, &self.gated, &event);
        }
        // When waiting only for exclusive interests, do not register on the FILE channel: the
        // exclusive gates, signals and epoll_ctl all wake the thread directly, and changes to
        // other files need not wake it
        let only_gated = !self.files && self.host.is_empty() && !self.gated.is_empty();
        let interest = if only_gated {
            0
        } else {
            wake::FILE
                | if self.pidfd { wake::CHILD } else { 0 }
                | if self.signalfd { wake::SIGNAL } else { 0 }
        };
        let r = cx.wait_objects(until, &mut self.host, interest, &self.objects);
        for ep in &self.epolls {
            ep.borrow_mut().waiters.retain(|e| !Arc::ptr_eq(e, &event));
        }
        if self.edge {
            cx.k().edge_waiters.retain(|e| !Arc::ptr_eq(e, &event));
        }
        if !self.gated.is_empty() {
            gate_leave(cx, &self.gated, &event);
        }
        r
    }
}

/// AIO's io_getevents: waits as ppoll would on `polls` (the files of the context's pending
/// `IOCB_CMD_POLL`s, each with the events it waits for), so that host sockets and timerfds are
/// watched too, and on `context`, which is woken when an event is queued or the context is
/// destroyed; until then, `deadline` or a signal.
pub(super) fn wait_aio_polls(
    cx: &mut Cx<'_>,
    polls: &[(FileRef, i16)],
    context: wake::Object,
    deadline: Option<Instant>,
) -> Result<(), Errno> {
    let mut waits = Waits::default();
    for (file, events) in polls {
        waits.add(&file.borrow(), *events, 0);
    }
    waits.objects.push(context);
    waits.wait(cx, deadline)
}

/// The timer thread watching a pending AIO poll for its eventfd: adds the host fds of `f` to
/// poll for `events` and its timerfd expiration. Changes to in-process objects need nothing more:
/// the timer thread listens on every channel while such polls exist.
pub(super) fn watch_aio_poll(
    f: &OpenFile,
    events: i16,
    host: &mut Vec<(i32, i16, i16)>,
    timer: &mut Option<Instant>,
) {
    let mut waits = Waits::default();
    waits.add(f, events, 0);
    host.append(&mut waits.host);
    if let Some(t) = waits.timer {
        *timer = Some(timer.map_or(t, |e| e.min(t)));
    }
}

/// Returns `(claimed, host_edge_consumed)` for an `EPOLLEXCLUSIVE` interest `int` of the epoll
/// at address `owner`. Linux wakes only one exclusive waiter per wakeup, and those whose turn it
/// is not do not report; an edge-triggered interest also does not report again what it reported
/// itself. Calling `edge(f)` may consume a shared `HostEdges` event, signalled via the second flag.
fn check_claimed(int: &Interest, f: &OpenFile, owner: usize) -> (bool, bool) {
    if int.events & EPOLLEXCLUSIVE == 0 {
        return (false, false);
    }
    let Some((edge_then, by)) = f.exclusive_claim.get() else {
        return (false, false);
    };
    let now = edge(f);
    let edge_consumed = f.host_edges.is_some() && now[2..] != edge_then[2..];
    let is_claimed = edge_then == now && (by != owner || int.events & EPOLLET != 0);
    (is_claimed, edge_consumed)
}

/// One sleeping waiter on an exclusive gate ([`ExGate`]): its wake event, requested mask,
/// `EPOLLET` bits already seen before sleeping (0 for level-triggered interests), and stable
/// registration order (`EPOLL_CTL_ADD` order, matching Linux's wait queue).
struct GateWaiter {
    event: Arc<appine_hal::Event>,
    wanted: i16,
    seen: i16,
    order: u64,
}

/// Threads waiting on a file of `EPOLLEXCLUSIVE` interests (the exclusive entries in a Linux wait
/// queue). Waiters do not wait on the file themselves (the host poll and FILE-channel broadcasts
/// would wake every thread waiting on it); they register here in stable registration order, and
/// the timer thread watches the file for them ([`check_exclusive`]): when the data generation has
/// changed, the file is ready and this edge has not been reported by any epoll, only the first
/// matching waiter in the queue is woken, as Linux wakes only one exclusive waiter per wakeup.
pub(crate) struct ExGate {
    file: Weak<RefCell<OpenFile>>,
    /// Waiting threads, ordered by registration (`GateWaiter::order`).
    sleepers: Vec<GateWaiter>,
    /// The file's data generation at the last check ([`edge`]).
    last: [u64; 4],
}

impl ExGate {
    /// Inserts `waiter` keeping ascending `GateWaiter::order` (Linux's stable wait-queue order).
    fn insert_waiter(&mut self, waiter: GateWaiter) {
        let pos = self.sleepers.partition_point(|w| w.order <= waiter.order);
        self.sleepers.insert(pos, waiter);
    }

    /// Looks at file `f`: when the data generation has changed, the file is ready and this edge
    /// has not been reported by any epoll, takes out the first waiter whose interest mask and
    /// edge state match the ready events.
    fn next_waiter(&mut self, f: &OpenFile) -> Option<Arc<appine_hal::Event>> {
        let now = edge(f);
        if now == self.last || self.sleepers.is_empty() {
            return None;
        }
        let read_changed = now[0] != self.last[0] || now[2] != self.last[2];
        let write_changed = now[1] != self.last[1] || now[3] != self.last[3];
        self.last = now;
        if f.exclusive_claim.get().is_some_and(|(e, _)| e == now) {
            return None;
        }
        let all = self.sleepers.iter().fold(0i16, |m, w| m | w.wanted);
        let ready = poll_now(f, all, 0);
        if ready == 0 {
            return None;
        }
        let i = self.sleepers.iter().position(|w| {
            let mut seen = w.seen;
            if read_changed {
                seen &= WRITE_BITS as i16;
            }
            if write_changed {
                seen &= !(WRITE_BITS as i16);
            }
            let ev = ready & (w.wanted | ALWAYS_REPORTED);
            ev & !seen != 0
        })?;
        Some(self.sleepers.remove(i).event)
    }

    /// Wakes all waiting threads (when a check fails, better to wake too many).
    pub(crate) fn wake_all(&self) {
        for w in &self.sleepers {
            crate::kernel::signal_later(&w.event);
        }
    }
}

/// Before waiting: registers `event` on the exclusive gate of each of `files`, preserving Linux's
/// stable registration order rather than rotating woken waiters to the back. When a gate is new,
/// wakes the timer thread so that it starts watching that file.
fn gate_enter(cx: &mut Cx<'_>, files: &[GatedFile], event: &Arc<appine_hal::Event>) {
    let mut created = false;
    for gf in files {
        let waiter = GateWaiter {
            event: event.clone(),
            wanted: gf.wanted,
            seen: gf.seen,
            order: gf.order,
        };
        let k = cx.k();
        match k
            .ex_gates
            .iter_mut()
            .find(|g| g.file.as_ptr() == Rc::as_ptr(&gf.file))
        {
            Some(g) => g.insert_waiter(waiter),
            None => {
                k.ex_gates.push(ExGate {
                    file: Rc::downgrade(&gf.file),
                    sleepers: vec![waiter],
                    last: edge(&gf.file.borrow()),
                });
                created = true;
            }
        }
    }
    if created {
        crate::kernel::signal_later(&cx.shared.timers);
    }
}

/// The timer thread watches files for `EPOLLEXCLUSIVE` waiters ([`ExGate`]): every change wakes
/// the timer thread (it registers on all channels while there are exclusive gates), newly arrived
/// data on host sockets is seen through their [`HostEdges`], and a timerfd expires at its
/// deadline; these host fds and the earliest such deadline are returned for the timer thread to
/// wait on as well. Gates with no waiters or whose file is closed are removed.
pub(crate) fn check_exclusive(
    k: &mut crate::kernel::Kernel,
) -> (Vec<(i32, i16, i16)>, Option<Instant>) {
    let mut host = Vec::new();
    let mut due: Option<Instant> = None;
    let mut notify_files = Vec::new();
    k.ex_gates.retain_mut(|g| {
        let Some(file) = g.file.upgrade().filter(|_| !g.sleepers.is_empty()) else {
            return false;
        };
        let f = file.borrow();
        let prev = g.last;
        if let Some(first) = g.next_waiter(&f) {
            crate::kernel::signal_later(&first);
        }
        if f.host_edges.is_some() && g.last[2..] != prev[2..] {
            notify_files.push(Rc::as_ptr(&file) as usize);
        }
        if let Some(e) = &f.host_edges {
            host.push((e.fd(), POLLIN, 0));
        }
        // Brought up to date by the edge check: the next expiry, if armed
        if let FileKind::TimerFd(t) = &f.kind
            && let Some(d) = t.borrow().deadline.map(crate::itimer::Expiry::instant)
        {
            due = Some(due.map_or(d, |e| e.min(d)));
        }
        true
    });
    notify_watched_files(&k.epoll_watches, &notify_files, 0);
    (host, due)
}

/// After waiting: removes `event` from the exclusive gates of `files` (a woken one has already
/// been removed).
fn gate_leave(cx: &mut Cx<'_>, files: &[GatedFile], event: &Arc<appine_hal::Event>) {
    for g in cx.k().ex_gates.iter_mut() {
        if files
            .iter()
            .any(|gf| g.file.as_ptr() == Rc::as_ptr(&gf.file))
        {
            g.sleepers.retain(|w| !Arc::ptr_eq(&w.event, event));
        }
    }
}

// ---- Signal-driven I/O ----

/// An open file with `O_ASYNC` set (Linux's fasync).
pub(crate) struct Fasync {
    file: Weak<RefCell<OpenFile>>,
    /// The fd used when setting `O_ASYNC`: an `F_SETSIG` signal puts it in si_fd.
    fd: i32,
    /// Events ready at the last check.
    last: i16,
    /// The open file's [`OpenFile::drained`], [`OpenFile::reads`] and [`arrivals`] at the last
    /// check.
    drained: [u64; 2],
    reads: u64,
    arrivals: [u64; 2],
}

/// An open file has just had `O_ASYNC` set: registers it. Events already ready are not
/// signalled, as on Linux. Wakes the timer thread: while there was no file with `O_ASYNC` it
/// listened only on the "other" channel, and would start checking this file only after waking
/// up for something else.
pub(super) fn register_fasync(cx: &mut Cx<'_>, file: &FileRef, fd: i32) {
    // Only files whose Linux file operations have fasync ever raise SIGIO (pipes and FIFOs,
    // sockets, terminals, inotify); the others keep the flag and stay silent (setfl): regular
    // files, eventfds, timerfds, signalfds, epoll and message queues among them
    if !matches!(
        file.borrow().kind,
        FileKind::Pipe(_)
            | FileKind::Socket(_)
            | FileKind::Pty(_)
            | FileKind::Inotify(_)
            | FileKind::Host(_)
    ) {
        return;
    }
    let k = cx.k();
    k.fasync.retain(|e| e.file.strong_count() > 0);
    if k.fasync.iter().any(|e| e.file.as_ptr() == Rc::as_ptr(file)) {
        return;
    }
    let f = file.borrow();
    let had_edges = f.host_edges.is_some();
    k.fasync.push(Fasync {
        file: Rc::downgrade(file),
        fd,
        last: poll_now(&f, POLLIN | POLLOUT, 0),
        drained: f.drained,
        reads: f.reads,
        arrivals: arrivals(&f),
    });
    drop(f);
    if had_edges {
        notify_watched_files(&k.epoll_watches, &[Rc::as_ptr(file) as usize], 0);
    }
    crate::kernel::signal_later(&cx.shared.timers);
}

/// Checks the files with `O_ASYNC` set and signals the owner about newly ready events. Returns
/// the host fds and events to poll while waiting: data on host sockets does not pass through the
/// kernel, so nobody would request a wakeup. Called every time the timer thread wakes; every
/// change that might make a file ready wakes it.
pub(crate) fn check_fasync(k: &mut crate::kernel::Kernel) -> Vec<(i32, i16, i16)> {
    const POLL_IN: i32 = 1;
    const POLL_OUT: i32 = 2;
    const POLL_ERR: i32 = 4;
    const POLL_HUP: i32 = 6;
    if k.fasync.is_empty() {
        return Vec::new();
    }
    let mut host = Vec::new();
    let mut signals = Vec::new();
    let mut notify_files = Vec::new();
    k.fasync.retain_mut(|e| {
        let Some(file) = e.file.upgrade() else {
            return false;
        };
        let f = file.borrow();
        if f.flags & oflags::O_ASYNC == 0 {
            return false;
        }
        // The program used up the data in one direction, or another event arrived in that
        // direction: the direction counts as not ready again and is notified again if still
        // ready, since Linux notifies on every arrival of data. Still being readable after data
        // was read is notified once more too: newly arrived data on host sockets cannot be seen
        // (without HostEdges), and between two checks the data may have been read empty and new
        // data arrived
        let came = arrivals(&f);
        if f.host_edges.is_some() && came != e.arrivals {
            notify_files.push(Rc::as_ptr(&file) as usize);
        }
        if f.drained[0] != e.drained[0] || f.reads != e.reads || came[0] != e.arrivals[0] {
            e.last &= !(POLLIN | POLLRDNORM);
        }
        if f.drained[1] != e.drained[1] || came[1] != e.arrivals[1] {
            e.last &= !(POLLOUT | POLLWRNORM);
        }
        e.drained = f.drained;
        e.reads = f.reads;
        e.arrivals = came;
        let (_, host_fd) = readiness(&f, 0);
        let ev = poll_now(&f, POLLIN | POLLOUT, 0);
        let new = ev & !e.last;
        e.last = ev;
        if let Some(fd) = host_fd {
            let wanted = (POLLIN | POLLOUT) & !ev;
            if wanted != 0 {
                host.push((fd, wanted, 0));
            }
        }
        for (bit, code, band) in [
            // Linux's band_table
            (POLLIN, POLL_IN, POLLIN | POLLRDNORM),
            (POLLOUT, POLL_OUT, POLLOUT | POLLWRNORM | 0x200),
            (POLLERR, POLL_ERR, POLLERR),
            (POLLHUP, POLL_HUP, POLLHUP | POLLERR),
        ] {
            if new & bit != 0 {
                signals.push((f.owner, f.owner_ids, f.sig, code, band, e.fd));
            }
        }
        true
    });
    notify_watched_files(&k.epoll_watches, &notify_files, 0);
    for (owner, ids, sig, code, band, fd) in signals {
        let Some(signo) = crate::process::Signal::new(if sig == 0 { 29 } else { sig }) else {
            continue;
        };
        // When F_SETSIG has set a signal, include the events and the fd; the default SIGIO does
        // not
        let info = if sig == 0 {
            signal::SigInfo::kernel()
        } else {
            signal::SigInfo {
                code,
                fields: signal::InfoFields::Poll {
                    band: band as i64,
                    fd,
                },
                ..signal::SigInfo::default()
            }
        };
        send_to_owner(k, owner, ids, signo, info);
    }
    host
}

/// Sends a signal to the owner recorded by `F_SETOWN_EX`; none when there is no owner (pid 0).
/// `ids` are the real and effective user IDs of whoever set the owner ([`OpenFile::owner_ids`]):
/// a thread or process (by its main thread) gets the signal only when the effective one is root or
/// either one is its real or saved user ID (Linux's `sigio_perm`, checked for each process of a
/// group), so no one can point a file at another user's process and signal it.
pub(crate) fn send_to_owner(
    k: &crate::kernel::Kernel,
    (ty, pid): (i32, i32),
    (uid, euid): (u32, u32),
    sig: crate::process::Signal,
    info: signal::SigInfo,
) {
    const F_OWNER_TID: i32 = 0;
    const F_OWNER_PGRP: i32 = 2;
    if pid <= 0 {
        return;
    }
    let allowed = |tid: crate::kernel::Tid| {
        k.cred_of(tid).is_some_and(|c| {
            euid == 0 || [uid, euid].iter().any(|&id| id == c.ruid || id == c.suid)
        })
    };
    // Linux 6.1's send_sigio_to_task falls back to SIGIO/SI_KERNEL on RT RLIMIT_SIGPENDING overflow.
    let sigio = crate::process::Signal::new(29).unwrap();
    let send_group = |tgid| {
        if !signal::try_send_to_group(k, tgid, sig, info) && sig != sigio {
            signal::send_to_group(k, tgid, sigio, signal::SigInfo::kernel());
        }
    };
    match ty {
        F_OWNER_TID => {
            if let Some(t) = k.tasks.get(&pid).filter(|_| allowed(pid))
                && !signal::try_send_to_task(k, t, sig, info)
                && sig != sigio
            {
                signal::send_to_task(k, t, sigio, signal::SigInfo::kernel());
            }
        }
        F_OWNER_PGRP => {
            let members: Vec<crate::kernel::Tid> = k
                .groups
                .values()
                .filter(|g| g.borrow().pgid == pid)
                .map(|g| g.borrow().tgid)
                .collect();
            for tgid in members.into_iter().filter(|&g| allowed(g)) {
                send_group(tgid);
            }
        }
        _ if allowed(pid) => send_group(pid),
        _ => {}
    }
}

// ---- Readiness and data generations ----

/// AIO's `IOCB_CMD_POLL`: the events of interest that are ready now (plus POLLERR and POLLHUP,
/// which are always reported). With `all`, when any event of interest is ready, all ready bits
/// are reported: that is how Linux completes a request that was queued and then woken.
pub(super) fn poll_once(f: &OpenFile, events: i16, all: bool) -> i16 {
    let wanted = poll_now(f, events, 0);
    if all && wanted != 0 {
        poll_now(f, !0, 0)
    } else {
        wanted
    }
}

/// Checks a file's ready events immediately (one non-waiting poll for a host fd), keeping only
/// `wanted` and POLLERR, POLLHUP and POLLNVAL, which are always reported.
fn poll_now(f: &OpenFile, wanted: i16, depth: u32) -> i16 {
    poll_now_full(f, wanted, depth).0
}

/// Like [`poll_now`], also returning the discovered host fd and whether `HostEdges`' host epoll
/// fd was readable (so the caller knows `arrivals_polled` consumed a host edge and notifies
/// sibling epolls on the same open file).
fn poll_now_full(f: &OpenFile, wanted: i16, depth: u32) -> (i16, Option<i32>, bool) {
    let (mut ev, host) = readiness(f, depth);
    let mut edge_seen = false;
    if let Some(fd) = host {
        // Ask the host epoll that records new events at the same time: when it is not readable,
        // arrivals_polled need not ask again
        let edges = f.host_edges.as_ref();
        let mut p = [
            (fd, wanted, 0),
            (edges.map_or(-1, HostEdges::fd), POLLIN, 0),
        ];
        let n = if edges.is_some() { 2 } else { 1 };
        if appine_hal::poll(&mut p[..n], Some(Duration::ZERO)).is_ok() {
            ev |= p[0].2;
            if let Some(e) = edges {
                edge_seen = p[1].2 != 0;
                e.polled(p[1].2);
            }
        }
    }
    (ev & (wanted | ALWAYS_REPORTED), host, edge_seen)
}

/// The current readiness of an open file: (events already known, host fd to ask).
fn readiness(f: &OpenFile, depth: u32) -> (i16, Option<i32>) {
    match &f.kind {
        FileKind::GpuFence(fd) => (0, Some(std::os::fd::AsRawFd::as_raw_fd(fd))),
        FileKind::Host(fd) => (0, Some(*fd)),
        FileKind::Socket(s) => super::net::readiness(&s.borrow()),
        FileKind::Pipe(end) => {
            let p = end.pipe.borrow();
            let mut ev = 0;
            // pipe_poll: writable while not full, also with no readers left (when writing
            // raises EPIPE), which adds POLLERR
            if end.write {
                if p.writable() {
                    ev |= POLLOUT | POLLWRNORM;
                }
                if p.readers == 0 {
                    ev |= POLLERR;
                }
            }
            if end.read {
                if !p.bytes().is_empty() {
                    ev |= POLLIN | POLLRDNORM;
                }
                if p.writers == 0 && end.hup_after != Some(p.writer_opens) {
                    ev |= POLLHUP;
                }
            }
            (ev, None)
        }
        FileKind::Pty(end) => (
            tty::readiness(&end.tty.borrow(), end.master, end.born),
            None,
        ),
        // eventfd_poll reports POLLIN and POLLOUT without the RDNORM/WRNORM bits
        FileKind::EventFd(e) => {
            let e = e.borrow();
            let mut ev = 0;
            if e.count > 0 {
                ev |= POLLIN;
            }
            if e.count < u64::MAX - 1 {
                ev |= POLLOUT;
            }
            (ev, None)
        }
        FileKind::TimerFd(t) => {
            let mut t = t.borrow_mut();
            t.update();
            (
                // timerfd_poll reports POLLIN alone
                if t.expirations > 0 { POLLIN } else { 0 },
                None,
            )
        }
        FileKind::Inotify(i) => (
            if i.borrow().ready() {
                POLLIN | POLLRDNORM
            } else {
                0
            },
            None,
        ),
        // signalfd_poll reports POLLIN alone
        FileKind::SignalFd(s) => (if s.borrow().ready() { POLLIN } else { 0 }, None),
        // ep_eventpoll_poll: POLLIN and POLLRDNORM while an interest is ready
        FileKind::Epoll(ep) if depth < MAX_NESTS => {
            let ready = ep.borrow_mut().ready(depth + 1, 1);
            let ev = if ready.is_empty() {
                0
            } else {
                POLLIN | POLLRDNORM
            };
            (ev, None)
        }
        FileKind::Epoll(_) => (0, None),
        // Since 6.9 there is also POLLHUP after the process is reaped; here it is the same as 6.1
        FileKind::Pidfd(p) => (if p.exited() { POLLIN | POLLRDNORM } else { 0 }, None),
        FileKind::MessageQueue(q) => (q.borrow().readiness(), None),
        FileKind::SeccompNotify(l) => (l.readiness(), None),
        FileKind::Path(_) => (POLLNVAL, None),
        FileKind::FuseDev(d) => (d.readiness(), None),
        // /dev/kmsg (`devkmsg_poll`): readable while there are unread records, with POLLERR and
        // POLLPRI as well when the record to be read has been pushed out; never reports writable
        FileKind::Device {
            kmsg: Some(user), ..
        } => {
            let log = user.log.borrow();
            let ev = if !log.readable(user.seq) {
                0
            } else if user.seq < log.first_seq() {
                POLLIN | POLLRDNORM | POLLERR | POLLPRI
            } else {
                POLLIN | POLLRDNORM
            };
            (ev, None)
        }
        // /proc/kmsg (`kmsg_poll`): readable while syslog has unread records
        FileKind::Proc {
            klog: Some(log), ..
        } => (
            if log.borrow_mut().size_unread(true) > 0 {
                POLLIN | POLLRDNORM
            } else {
                0
            },
            None,
        ),
        // sysfs and cgroup2 files (`kernfs_generic_poll`), mounts and mountinfo (`mounts_poll`):
        // POLLERR and POLLPRI while changed since last read from the start
        FileKind::Proc { event: Some(e), .. } => {
            let base = if e.mounts {
                POLLIN | POLLRDNORM
            } else {
                POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM
            };
            (
                if e.changed() {
                    base | POLLERR | POLLPRI
                } else {
                    base
                },
                None,
            )
        }
        _ => (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM, None),
    }
}

/// Events `ev` of open file `f` were reported to the guest: a change of the mount table reported
/// by mounts or mountinfo is taken in (`mounts_poll` records the namespace's event as it reports
/// it), so it is not reported again until the next change.
fn took_change(f: &OpenFile, ev: i16) {
    if ev & (POLLPRI | POLLERR) != 0
        && let FileKind::Proc { event: Some(e), .. } = &f.kind
        && e.mounts
    {
        e.seen.set(e.counter.get());
    }
}

/// The host fd behind an open file (host stdio, TCP/UDP sockets).
fn host_fd(f: &OpenFile) -> Option<i32> {
    match &f.kind {
        FileKind::GpuFence(fd) => Some(std::os::fd::AsRawFd::as_raw_fd(fd)),
        FileKind::Host(fd) => Some(*fd),
        FileKind::Socket(s) => match &*s.borrow() {
            // Messages received by a raw ICMP socket are in the tap's queue (crate::rawicmp);
            // the host fd is not looked at
            crate::net::Socket::Inet(i) if i.icmp.is_none() => Some(i.fd),
            _ => None,
        },
        _ => None,
    }
}

/// The wake objects to register when waiting for the readiness of open file `f` to change
/// ([`wake::of`]). A change to the readiness of an in-process object either requests a wakeup of
/// one of the objects listed here, or requests a channel (a pending signal requests
/// [`wake::SIGNAL`], a pidfd's child requests [`wake::CHILD`]; only waiters interested in them
/// listen); data on host fds is waited for by the host poll, and a host socket lists itself
/// (closing, answers of the DNS stub). A signalfd lists only itself (mask changes), and an epoll
/// lists only itself (epoll_ctl); the interests inside it are added one by one by [`Waits`].
fn wake_objects(f: &OpenFile, out: &mut Vec<wake::Object>) {
    match &f.kind {
        FileKind::Pipe(end) => out.push(crate::pipe::object(&end.pipe)),
        FileKind::Pty(end) => out.push(wake::of(&end.tty)),
        FileKind::EventFd(e) => out.push(wake::of(e)),
        FileKind::TimerFd(t) => out.push(wake::of(t)),
        FileKind::Inotify(i) => out.push(wake::of(i)),
        FileKind::SignalFd(s) => out.push(wake::of(s)),
        FileKind::Epoll(ep) => out.push(wake::of(ep)),
        FileKind::Socket(s) => super::net::wake_objects(s, out),
        FileKind::MessageQueue(q) => out.push(wake::of(q)),
        FileKind::SeccompNotify(l) => out.push(l.object()),
        FileKind::FuseDev(d) => out.extend(d.object()),
        FileKind::Device {
            kmsg: Some(user), ..
        } => out.push(wake::of(&*user.log)),
        FileKind::Proc {
            klog: Some(log), ..
        } => out.push(wake::of(&**log)),
        FileKind::Proc { event: Some(e), .. } => out.push(wake::of_value(&*e.counter)),
        _ => {}
    }
}

/// The current "data generation" of an open file: how many times the data was used up and how
/// many events have arrived, in the read and write directions. While the generation is
/// unchanged it is still the same edge (`EPOLLEXCLUSIVE`).
fn edge(f: &OpenFile) -> [u64; 4] {
    let a = arrivals(f);
    [f.drained[0], f.drained[1], a[0], a[1]]
}

/// How many events have arrived on an open file in each of the read and write directions:
/// in-process objects count every arrival of data (writes to pipes and sockets, eventfd writes,
/// timerfd expirations, new connections...), matching each time Linux wakes the wait queue;
/// those on host fds are recorded by [`HostEdges`], and are 0 when it is not set up. `EPOLLET`
/// uses this to fire once more when data arrives while the file is already ready.
fn arrivals(f: &OpenFile) -> [u64; 2] {
    arrivals_with(f, HostEdges::counts, 0)
}

/// The same as [`arrivals`], but the host fd has just been through [`poll_now`]: if the host epoll
/// was not readable then, the host need not be asked again.
fn arrivals_polled(f: &OpenFile) -> [u64; 2] {
    arrivals_with(f, HostEdges::counts_polled, 0)
}

/// `depth` is the number of levels of nested epolls ([`epoll_arrivals`]).
fn arrivals_with(f: &OpenFile, host: fn(&HostEdges) -> [u64; 2], depth: u32) -> [u64; 2] {
    let local = match &f.kind {
        FileKind::Epoll(ep) => [epoll_arrivals(&ep.borrow(), depth), 0],
        FileKind::Pipe(end) => {
            let p = end.pipe.borrow();
            [
                if end.read { p.writes } else { 0 },
                if end.write { p.room } else { 0 },
            ]
        }
        FileKind::Pty(end) => [end.tty.borrow().arrivals[end.master as usize], 0],
        FileKind::Socket(s) => super::net::arrivals(&s.borrow()),
        FileKind::EventFd(e) => {
            let e = e.borrow();
            [e.writes, e.reads]
        }
        FileKind::TimerFd(t) => {
            let mut t = t.borrow_mut();
            t.update();
            [t.fired, 0]
        }
        FileKind::Inotify(i) => [i.borrow().queued(), 0],
        FileKind::SignalFd(s) => [s.borrow().arrivals(), 0],
        FileKind::MessageQueue(q) => q.borrow().arrivals(),
        FileKind::SeccompNotify(l) => l.arrivals(),
        FileKind::Device {
            kmsg: Some(user), ..
        } => [user.log.borrow().next_seq(), 0],
        FileKind::Proc {
            klog: Some(log), ..
        } => [log.borrow().next_seq(), 0],
        FileKind::Proc { event: Some(e), .. } => [e.counter.get(), 0],
        _ => [0, 0],
    };
    let host = f.host_edges.as_ref().map_or([0, 0], host);
    [local[0] + host[0], local[1] + host[1]]
}

/// Events that have arrived in an epoll instance: every time Linux's `ep_poll_callback` is woken
/// (a watched file gets an event in a watched direction) it wakes the `poll_wait` waiting on this
/// epoll, so an edge-triggered interest of an epoll containing it fires once more. Here it is the
/// sum of the events each interest has seen in its watched directions since it was added, plus
/// the former shares of removed interests and the number of times interests were already ready
/// when added or modified ([`Epoll::base`]); it only grows.
fn epoll_arrivals(ep: &Epoll, depth: u32) -> u64 {
    let mut total = ep.base.get();
    for int in ep.interests.iter().flatten() {
        // Disarmed interests (reported with EPOLLONESHOT) do not wake; their share stays at its
        // old value
        if int.armed
            && depth < MAX_NESTS
            && let Some(file) = int.file.upgrade()
        {
            let now = interest_arrivals(int.events, &file.borrow(), depth + 1);
            int.share.set(now.saturating_sub(int.origin));
        }
        total += int.share.get();
    }
    total
}

/// How many events have arrived on file `f` in the directions of `events` (the read and write
/// directions counted separately, as Linux filters by the woken events).
fn interest_arrivals(events: u32, f: &OpenFile, depth: u32) -> u64 {
    directional(events, arrivals_with(f, HostEdges::counts, depth))
}

/// Of the event counts of the two directions, those in the directions `events` watches.
fn directional(events: u32, a: [u64; 2]) -> u64 {
    let read = events & !WRITE_BITS & 0xffff != 0;
    let write = events & WRITE_BITS != 0;
    (if read { a[0] } else { 0 }) + (if write { a[1] } else { 0 })
}

/// The program used up the data in one direction of `file` (0 read, 1 write): a read or write
/// returned EAGAIN, or read or wrote less than the requested length (runtimes like tokio take
/// that to mean the data is all read and stop reading until EAGAIN). Edge-triggered interests
/// then report events in this direction again, and epoll_waits that left these events out while
/// waiting are woken to recompute.
pub(super) fn drained(cx: &mut Cx<'_>, file: &FileRef, dir: usize) {
    file.borrow_mut().drained[dir] += 1;
    for event in &cx.k().edge_waiters {
        crate::kernel::signal_later(event);
    }
    cx.k()
        .epoll_watches
        .borrow_mut()
        .notify_file(Rc::as_ptr(file) as usize, 0);
    // Signal-driven I/O also starts over when data is used up, see check_fasync: only wake the
    // timer thread
    if file.borrow().flags & oflags::O_ASYNC != 0 {
        crate::kernel::signal_later(&cx.shared.timers);
    }
}

/// An in-process object that was already ready got more data, and the writer did not request a
/// wakeup (a non-empty pipe): wakes the edge-triggered epoll_waits that left these events out, to
/// recompute.
pub(super) fn arrived(cx: &mut Cx<'_>) {
    for event in &cx.k().edge_waiters {
        crate::kernel::signal_later(event);
    }
    cx.k().epoll_watches.borrow_mut().notify_et_pipes();
}

// ---- eventfd ----

const EFD_SEMAPHORE: u32 = 1;

pub(super) fn eventfd2(cx: &mut Cx<'_>, initval: u32, flags: u32) -> SysResult {
    if flags & !(EFD_SEMAPHORE | oflags::O_CLOEXEC | oflags::O_NONBLOCK) != 0 {
        return Err(Errno::EINVAL);
    }
    let efd = EventFd {
        count: initval as u64,
        semaphore: flags & EFD_SEMAPHORE != 0,
        writes: 0,
        reads: 0,
    };
    let file = OpenFile::new(
        FileKind::EventFd(Rc::new(RefCell::new(efd))),
        oflags::O_RDWR | (flags & oflags::O_NONBLOCK),
    );
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

/// eventfd read: takes the count (1 in semaphore mode), blocking while the count is 0.
pub(super) fn eventfd_read(
    cx: &mut Cx<'_>,
    efd: &Rc<RefCell<EventFd>>,
    nonblock: bool,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    if buf.len() < 8 {
        return Err(Errno::EINVAL);
    }
    loop {
        {
            let mut e = efd.borrow_mut();
            if e.count > 0 {
                let v = if e.semaphore { 1 } else { e.count };
                e.count -= v;
                e.reads += 1;
                buf[..8].copy_from_slice(&v.to_le_bytes());
                request_wake_object(wake::of(efd));
                return Ok(8);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_objects(None, &mut [], wake::FILE, &[wake::of(efd)])?;
    }
}

/// eventfd write: adds to the count, blocking when it would overflow.
pub(super) fn eventfd_write(
    cx: &mut Cx<'_>,
    efd: &Rc<RefCell<EventFd>>,
    nonblock: bool,
    data: &[u8],
) -> Result<usize, Errno> {
    if data.len() < 8 {
        return Err(Errno::EINVAL);
    }
    let v = u64::from_le_bytes(data[..8].try_into().unwrap());
    if v == u64::MAX {
        return Err(Errno::EINVAL);
    }
    loop {
        {
            let mut e = efd.borrow_mut();
            if e.count.checked_add(v).is_some_and(|c| c < u64::MAX) {
                e.count += v;
                e.writes += 1;
                request_wake_object(wake::of(efd));
                return Ok(8);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_objects(None, &mut [], wake::FILE, &[wake::of(efd)])?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_test_interest(
        ep: &mut Epoll,
        fd: i32,
        file: &FileRef,
        events: u32,
        data: u64,
    ) -> usize {
        let id = file_fdinfo_dev_ino(None, &file.borrow());
        let epoch = ep.alloc_epoch();
        ep.alloc_slot(Interest::new(fd, file, events, data, id, epoch))
    }

    #[test]
    fn level_triggered_host_fds_share_the_cursor_with_guest_interests() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (socket, peer) = UnixStream::pair().unwrap();
        let host = OpenFile::new(FileKind::Host(socket.as_raw_fd()), oflags::O_RDWR);
        let event = OpenFile::new(
            FileKind::EventFd(Rc::new(RefCell::new(EventFd {
                count: 1,
                semaphore: false,
                writes: 1,
                reads: 0,
            }))),
            oflags::O_RDWR,
        );
        let mut ep = Epoll::default();
        let read = POLLIN as u32;
        let write = POLLOUT as u32;
        // Duplicated guest descriptors can watch the same host socket with different masks.
        for (file, events) in [
            (&host, read),
            (&host, write | EPOLLONESHOT),
            (&event, read | EPOLLET),
            (&host, write),
            (&host, write),
        ] {
            let fd = ep.live_count as i32 + 3;
            push_test_interest(&mut ep, fd, file, events, 0);
        }
        for expected in [[(1, write), (2, read)], [(3, write), (4, write)]] {
            let ready = ep.ready(0, 2);
            assert_eq!(ready, expected);
            for (i, ev) in ready {
                ep.reported(i, ev);
            }
        }
        assert_eq!(ep.ready(0, 4), [(3, write), (4, write)]);
        drop(peer);
        let hup = POLLHUP as u32;
        assert_eq!(
            ep.ready(0, 4),
            [(0, read | hup), (3, write | hup), (4, write | hup)]
        );
    }

    #[test]
    fn edge_triggered_interests_fire_on_new_readiness() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let both = (POLLIN | POLLOUT) as u32;
        let mut ep = Epoll::default();
        push_test_interest(&mut ep, 3, &file, both | EPOLLET, 0);
        // Writable from the start: after one report, no more reports without a change
        assert_eq!(ep.ready(0, 8), vec![(0, POLLOUT as u32)]);
        ep.reported(0, POLLOUT as u32);
        assert!(ep.ready(0, 8).is_empty());
        // Becoming readable: report all bits currently ready
        efd.borrow_mut().count = 1;
        assert_eq!(ep.ready(0, 8), vec![(0, both)]);
        // Only checking (nested epoll) does not consume the events
        assert_eq!(ep.ready(0, 8), vec![(0, both)]);
        ep.reported(0, both);
        assert!(ep.ready(0, 8).is_empty());
        // Written again after being read empty: fires again
        efd.borrow_mut().count = 0;
        assert!(ep.ready(0, 8).is_empty());
        efd.borrow_mut().count = 5;
        assert_eq!(ep.ready(0, 8), vec![(0, both)]);
        ep.reported(0, both);
        // Read empty, got EAGAIN and more data arrived, with no epoll_wait in between: must fire
        // again too
        efd.borrow_mut().count = 0;
        file.borrow_mut().drained[0] += 1;
        efd.borrow_mut().count = 2;
        assert_eq!(ep.ready(0, 8), vec![(0, both)]);
        ep.reported(0, both);
        assert!(ep.ready(0, 8).is_empty());
        // Using up the write direction re-reports only the write direction's bits; while
        // waiting, bits that were reported and are still ready are not waited for
        file.borrow_mut().drained[1] += 1;
        assert_eq!(ep.ready(0, 8), vec![(0, both)]);
        ep.reported(0, both);
        assert!(ep.ready(0, 8).is_empty());
        let mut waits = Waits::default();
        waits.add_epoll(&ep, 0);
        assert!(waits.edge);
    }

    #[test]
    fn edge_triggered_interests_fire_on_every_arrival() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let mut ep = Epoll::default();
        push_test_interest(&mut ep, 3, &file, POLLIN as u32 | EPOLLET, 0);
        let write = |n| {
            let mut e = efd.borrow_mut();
            e.count += n;
            e.writes += 1;
        };
        write(1);
        assert_eq!(ep.ready(0, 8), vec![(0, POLLIN as u32)]);
        ep.reported(0, POLLIN as u32);
        assert!(ep.ready(0, 8).is_empty());
        // The count was not read away and another write came (mio's waker): report once more
        write(1);
        assert_eq!(ep.ready(0, 8), vec![(0, POLLIN as u32)]);
        ep.reported(0, POLLIN as u32);
        assert!(ep.ready(0, 8).is_empty());
        // While waiting, still-ready bits are not waited for, but the waiter must be woken (an
        // edge-triggered waiter)
        let mut waits = Waits::default();
        waits.add_epoll(&ep, 0);
        assert!(waits.edge);
        // Writing zero counts too (Linux wakes as usual)
        write(0);
        assert_eq!(ep.ready(0, 8), vec![(0, POLLIN as u32)]);
    }

    #[test]
    fn waits_register_the_objects_of_watched_files() {
        let eventfd = || {
            let e = Rc::new(RefCell::new(EventFd {
                count: 0,
                semaphore: false,
                writes: 0,
                reads: 0,
            }));
            (
                OpenFile::new(FileKind::EventFd(e.clone()), oflags::O_RDWR),
                e,
            )
        };
        let (f1, e1) = eventfd();
        let (f2, e2) = eventfd();
        let mut inner = Epoll::default();
        push_test_interest(&mut inner, 3, &f1, POLLIN as u32, 0);
        let inner = Rc::new(RefCell::new(inner));
        let inner_file = OpenFile::new(FileKind::Epoll(inner.clone()), oflags::O_RDWR);
        let cred = crate::unix::Ucred::of(1, 0, 0);
        let (a, _b) = crate::unix::UnixSocket::pair(crate::net::SOCK_STREAM, cred);
        let mut unix_objects = Vec::new();
        a.wake_objects(&mut unix_objects);
        let sock = Rc::new(RefCell::new(crate::net::Socket::Unix(a)));
        let sock_file = OpenFile::new(FileKind::Socket(sock), oflags::O_RDWR);
        let mut outer = Epoll::default();
        for (fd, f) in [(4, &inner_file), (5, &f2), (6, &sock_file)] {
            push_test_interest(&mut outer, fd, f, POLLIN as u32, 0);
        }
        let mut waits = Waits::default();
        waits.add_epoll(&outer, 0);
        // The nested epoll itself (epoll_ctl) and the files it watches, the AF_UNIX socket's
        // receive queue and both directions of the connection
        let mut want = vec![wake::of(&inner), wake::of(&e1), wake::of(&e2)];
        want.extend(&unix_objects);
        assert_eq!(unix_objects.len(), 3);
        for o in want {
            assert!(waits.objects.contains(&o));
        }
        assert!(!waits.pidfd);
    }

    #[test]
    fn nested_epolls_fire_on_every_inner_event() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        // The inner epoll watches an eventfd level-triggered, the outer one watches the inner
        // edge-triggered
        let mut inner = Epoll::default();
        push_test_interest(&mut inner, 3, &file, POLLIN as u32, 0);
        let inner = OpenFile::new(
            FileKind::Epoll(Rc::new(RefCell::new(inner))),
            oflags::O_RDWR,
        );
        let mut outer = Epoll::default();
        push_test_interest(&mut outer, 4, &inner, POLLIN as u32 | EPOLLET, 0);
        let write = || {
            let mut e = efd.borrow_mut();
            e.count += 1;
            e.writes += 1;
        };
        assert!(outer.ready(0, 8).is_empty());
        write();
        assert_eq!(outer.ready(0, 8), vec![(0, POLLIN as u32)]);
        outer.reported(0, POLLIN as u32);
        assert!(outer.ready(0, 8).is_empty());
        // The inner one is still ready and another event came: the outer one reports again
        write();
        assert_eq!(outer.ready(0, 8), vec![(0, POLLIN as u32)]);
        outer.reported(0, POLLIN as u32);
        // Removing an interest from the inner one does not count as a new event
        if let FileKind::Epoll(ep) = &inner.borrow().kind {
            ep.borrow_mut().remove_slot(0, true);
        }
        assert!(outer.ready(0, 8).is_empty());
    }

    #[test]
    fn exclusive_interests_report_each_edge_to_one_epoll() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let new = || {
            let mut ep = Epoll::default();
            push_test_interest(&mut ep, 3, &file, POLLIN as u32 | EPOLLEXCLUSIVE, 0);
            ep
        };
        let (mut a, mut b) = (new(), new());
        let write = || {
            let mut e = efd.borrow_mut();
            e.count += 1;
            e.writes += 1;
        };
        write();
        assert_eq!(a.ready(0, 8), vec![(0, POLLIN as u32)]);
        a.reported(0, POLLIN as u32);
        // Level-triggered: the epoll that reported keeps reporting while it is still ready, and
        // other epolls wait for the next edge
        assert!(b.ready(0, 8).is_empty());
        assert_eq!(a.ready(0, 8), vec![(0, POLLIN as u32)]);
        // While waiting, the file of an exclusive interest is not waited on directly but
        // registered on its exclusive gate (the timer thread wakes only one)
        let mut waits = Waits::default();
        waits.add_epoll(&b, 0);
        assert_eq!(waits.gated.len(), 1);
        assert!(waits.host.is_empty() && !waits.files);
        // More data arrived: it goes to the one that checks first
        write();
        assert_eq!(b.ready(0, 8), vec![(0, POLLIN as u32)]);
        b.reported(0, POLLIN as u32);
        assert!(a.ready(0, 8).is_empty());
        // More arrives after being read empty: still reported to only one
        efd.borrow_mut().count = 0;
        file.borrow_mut().drained[0] += 1;
        assert!(a.ready(0, 8).is_empty() && b.ready(0, 8).is_empty());
        write();
        assert_eq!(a.ready(0, 8), vec![(0, POLLIN as u32)]);
        a.reported(0, POLLIN as u32);
        assert!(b.ready(0, 8).is_empty());
    }

    #[test]
    fn exclusive_gates_pick_one_waiter_per_edge() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let sleepers: Vec<_> = (0..3)
            .map(|_| Arc::new(appine_hal::Event::new().unwrap()))
            .collect();
        let mut gate = ExGate {
            file: Rc::downgrade(&file),
            sleepers: sleepers
                .iter()
                .enumerate()
                .map(|(idx, e)| GateWaiter {
                    event: e.clone(),
                    wanted: POLLIN,
                    seen: 0,
                    order: idx as u64 + 1,
                })
                .collect(),
            last: edge(&file.borrow()),
        };
        let write = || {
            let mut e = efd.borrow_mut();
            e.count += 1;
            e.writes += 1;
        };
        // No new edge: nobody is woken
        assert!(gate.next_waiter(&file.borrow()).is_none());
        // A new edge wakes only the first in the queue, and the same edge wakes no other
        write();
        let w = gate.next_waiter(&file.borrow()).unwrap();
        assert!(Arc::ptr_eq(&w, &sleepers[0]));
        assert!(gate.next_waiter(&file.borrow()).is_none());
        // An edge already reported by some epoll wakes nobody
        write();
        let now = edge(&file.borrow());
        file.borrow().exclusive_claim.set(Some((now, 1)));
        assert!(gate.next_waiter(&file.borrow()).is_none());
        // The next edge goes to the second
        write();
        let w = gate.next_waiter(&file.borrow()).unwrap();
        assert!(Arc::ptr_eq(&w, &sleepers[1]));
        assert_eq!(gate.sleepers.len(), 1);
    }

    #[test]
    fn exclusive_gates_match_direction_and_wanted_mask() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let out_waiter = Arc::new(appine_hal::Event::new().unwrap());
        let in_waiter = Arc::new(appine_hal::Event::new().unwrap());
        let mut gate = ExGate {
            file: Rc::downgrade(&file),
            sleepers: vec![
                GateWaiter {
                    event: out_waiter.clone(),
                    wanted: POLLOUT,
                    seen: POLLOUT,
                    order: 1,
                },
                GateWaiter {
                    event: in_waiter.clone(),
                    wanted: POLLIN,
                    seen: 0,
                    order: 2,
                },
            ],
            last: edge(&file.borrow()),
        };
        // A read-side arrival must skip the EPOLLET POLLOUT waiter and wake the POLLIN waiter
        {
            let mut e = efd.borrow_mut();
            e.count = 1;
            e.writes += 1;
        }
        let w = gate.next_waiter(&file.borrow()).unwrap();
        assert!(Arc::ptr_eq(&w, &in_waiter));
        assert_eq!(gate.sleepers.len(), 1);
        assert!(Arc::ptr_eq(&gate.sleepers[0].event, &out_waiter));
        // A write-side edge (draining count) wakes the waiting POLLOUT sleeper
        {
            let mut e = efd.borrow_mut();
            e.count = 0;
            e.reads += 1;
        }
        let w = gate.next_waiter(&file.borrow()).unwrap();
        assert!(Arc::ptr_eq(&w, &out_waiter));
        assert!(gate.sleepers.is_empty());
    }

    #[test]
    fn exclusive_gates_preserve_stable_waiter_order() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        let w0 = Arc::new(appine_hal::Event::new().unwrap());
        let w1 = Arc::new(appine_hal::Event::new().unwrap());
        let mut gate = ExGate {
            file: Rc::downgrade(&file),
            sleepers: vec![
                GateWaiter {
                    event: w0.clone(),
                    wanted: POLLIN,
                    seen: 0,
                    order: 10,
                },
                GateWaiter {
                    event: w1.clone(),
                    wanted: POLLIN,
                    seen: 0,
                    order: 20,
                },
            ],
            last: edge(&file.borrow()),
        };
        let write = || {
            let mut e = efd.borrow_mut();
            e.count += 1;
            e.writes += 1;
        };
        // First edge wakes w0
        write();
        assert!(Arc::ptr_eq(&gate.next_waiter(&file.borrow()).unwrap(), &w0));
        // w0 handles the event and re-enters the gate with its original registration order (10):
        // it must stay ahead of w1 (20) rather than rotating to the back
        gate.insert_waiter(GateWaiter {
            event: w0.clone(),
            wanted: POLLIN,
            seen: 0,
            order: 10,
        });
        // Second edge must wake w0 again, leaving w1 untouched
        write();
        assert!(Arc::ptr_eq(&gate.next_waiter(&file.borrow()).unwrap(), &w0));
        assert_eq!(gate.sleepers.len(), 1);
        assert!(Arc::ptr_eq(&gate.sleepers[0].event, &w1));
    }

    #[test]
    fn tracked_epoll_uses_ready_list_without_scanning_idle_entries() {
        let watches = Rc::new(RefCell::new(EpollWatches::default()));
        let mut ep = Epoll::default();
        ep.watches = Some(Rc::downgrade(&watches));
        let ep = Rc::new(RefCell::new(ep));
        ep.borrow_mut().self_weak = Rc::downgrade(&ep);

        let mut files = Vec::new();
        let mut efds = Vec::new();
        for i in 0..64 {
            let e = Rc::new(RefCell::new(EventFd {
                count: 0,
                semaphore: false,
                writes: 0,
                reads: 0,
            }));
            let f = OpenFile::new(FileKind::EventFd(e.clone()), oflags::O_RDWR);
            let mut ep_mut = ep.borrow_mut();
            let slot =
                push_test_interest(&mut ep_mut, i + 3, &f, POLLIN as u32 | EPOLLET, i as u64);
            ep_mut.track_slot(slot);
            files.push(f);
            efds.push(e);
        }

        // Initial scan drains the initial ready_queue; afterwards ready_queue is empty
        assert!(ep.borrow_mut().ready(0, 8).is_empty());
        assert!(ep.borrow().ready_queue.is_empty());

        // Wake only slot 37 via EpollWatches: only slot 37 enters ready_queue
        {
            let mut e = efds[37].borrow_mut();
            e.count = 1;
            e.writes += 1;
        }
        watches.borrow_mut().notify_objects(&[wake::of(&efds[37])]);
        assert_eq!(ep.borrow().ready_queue.len(), 1);
        let got = ep.borrow_mut().ready(0, 8);
        assert_eq!(got, vec![(37, POLLIN as u32)]);
        // Still queued before reported() so EFAULT preserves the event
        assert_eq!(ep.borrow().ready_queue.len(), 1);
        ep.borrow_mut().reported(37, POLLIN as u32);
        // After reporting EPOLLET, ready_queue is empty again
        assert!(ep.borrow().ready_queue.is_empty());
        assert!(ep.borrow_mut().ready(0, 8).is_empty());

        // Building Waits on a tracked epoll does not copy all 64 idle wake objects
        let mut waits = Waits::default();
        waits.add_epoll_rc(&ep, 0);
        assert!(waits.objects.is_empty());
        assert_eq!(waits.epolls.len(), 1);
    }

    #[test]
    fn epoll_fdinfo_reports_tmpfs_and_overlay_devices() {
        use crate::vfs::{Fs, Node, ROOT_MOUNT, store::ROOT};

        let dir = std::env::temp_dir().join(format!(
            "appine-epoll-fdinfo-{}-{}",
            std::process::id(),
            crate::vfs::new_ns_id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        drop(crate::vfs::store::Store::create(&dir).unwrap());
        let vfs = Vfs::open(&dir).unwrap();

        // Create a tmpfs mount and a FIFO on it
        let mnt_dir = vfs.store().mkdir(ROOT, b"t", 0o755, 0, 0).unwrap();
        let tmp_root = vfs.store().create_detached_dir(0o1777, 0, 0).unwrap();
        let tmp_mnt = vfs.add_mount(
            Fs::Tmpfs,
            Node::Store(0, tmp_root),
            (
                Node::Store(ROOT_MOUNT, mnt_dir),
                Some((Node::ROOT, b"t".to_vec())),
            ),
            0,
            b"tmpfs".to_vec(),
            None,
        );
        let fifo_ino = vfs
            .store()
            .mknod(tmp_root, b"f", 0o010600, 0, 0, 0)
            .unwrap();
        let tmp_dev = vfs.dev_of(&Node::Store(tmp_mnt, fifo_ino));
        assert_ne!(tmp_dev, ROOT_DEV);

        let pipe = crate::pipe::Pipe::fifo(fifo_ino, crate::pipe::PIPE_CAPACITY);
        pipe.borrow_mut().readers = 1;
        pipe.borrow_mut().writers = 1;
        let fifo_file = OpenFile::new(
            FileKind::Pipe(crate::pipe::PipeEnd {
                pipe,
                read: true,
                write: true,
                hup_after: None,
            }),
            oflags::O_RDWR,
        );
        fifo_file.borrow_mut().mnt = tmp_mnt;

        let (sdev, ino) = file_fdinfo_dev_ino(Some(&vfs), &fifo_file.borrow());
        assert_eq!(sdev, kernel_dev(tmp_dev));
        assert_eq!(ino, fifo_ino);

        // Rootfs store FIFO reports (8 << 20) | 1
        let root_fifo_ino = vfs.store().mknod(ROOT, b"rf", 0o010600, 0, 0, 0).unwrap();
        let root_pipe = crate::pipe::Pipe::fifo(root_fifo_ino, crate::pipe::PIPE_CAPACITY);
        root_pipe.borrow_mut().readers = 1;
        root_pipe.borrow_mut().writers = 1;
        let root_file = OpenFile::new(
            FileKind::Pipe(crate::pipe::PipeEnd {
                pipe: root_pipe,
                read: true,
                write: true,
                hup_after: None,
            }),
            oflags::O_RDWR,
        );
        let (rsdev, rino) = file_fdinfo_dev_ino(Some(&vfs), &root_file.borrow());
        assert_eq!(rsdev, (8 << 20) | 1);
        assert_eq!(rino, root_fifo_ino);

        // FUSE file reports its FUSE mount device and cached inode number
        let init_ns = crate::pidns::PidNs::init();
        let root_cred = crate::cred::Cred::root();
        crate::vfs::fuse::new_syscall();
        let (fuse_mnt, conn) = vfs.new_fuse((Node::ROOT, None), 0, b"testfuse".to_vec(), |dev| {
            crate::vfs::fuse::Conn::new(
                dev,
                crate::vfs::fuse::Options::default(),
                &root_cred,
                init_ns.clone(),
            )
        });
        let fuse_dev = conn.borrow().dev;
        let fuse_root = vfs.fuse().root_of(fuse_dev).unwrap();
        let fuse_id = vfs
            .fuse_mut()
            .enter(
                fuse_root,
                b"f",
                &crate::vfs::fuse::Entry {
                    nodeid: 2,
                    attr: crate::vfs::fuse::Attr {
                        ino: 4242,
                        mode: crate::vfs::store::mode::S_IFREG | 0o644,
                        nlink: 1,
                        ..crate::vfs::fuse::Attr::default()
                    },
                    entry_until: None,
                    attr_until: None,
                },
            )
            .unwrap();
        let fuse_file = OpenFile::new(
            FileKind::Fuse(Box::new(crate::vfs::fuse::Handle {
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
        let (fsdev, fino) = file_fdinfo_dev_ino(Some(&vfs), &fuse_file.borrow());
        assert_eq!(fsdev, kernel_dev(fuse_dev));
        assert_eq!(fino, 4242);

        drop(vfs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ancestor_depth_tracks_top_down_nesting() {
        let n = MAX_NESTS as usize;
        let epolls: Vec<Rc<RefCell<Epoll>>> = (0..=n + 1)
            .map(|_| Rc::new(RefCell::new(Epoll::default())))
            .collect();
        // Build top-down chain e0 -> e1 -> e2 -> e3 -> e4 (depth 4 at e4)
        for i in 0..n {
            epolls[i + 1]
                .borrow_mut()
                .parents
                .push(Rc::downgrade(&epolls[i]));
        }
        assert_eq!(ancestor_depth(&epolls[0], 0), 0);
        assert_eq!(ancestor_depth(&epolls[n], 0), MAX_NESTS);
        // Adding one more nested epoll (subtree depth 1) under e4 exceeds MAX_NESTS
        assert!(ancestor_depth(&epolls[n], 0).saturating_add(1) > MAX_NESTS);
        // Removing the top link lowers the ancestor depth by one
        epolls[1].borrow_mut().parents.clear();
        assert_eq!(ancestor_depth(&epolls[n], 0), MAX_NESTS - 1);
    }

    #[test]
    fn eventfd_readiness_and_epoll_oneshot() {
        let efd = Rc::new(RefCell::new(EventFd {
            count: 0,
            semaphore: false,
            writes: 0,
            reads: 0,
        }));
        let file = OpenFile::new(FileKind::EventFd(efd.clone()), oflags::O_RDWR);
        assert_eq!(poll_now(&file.borrow(), POLLIN | POLLOUT, 0), POLLOUT);
        let mut ep = Epoll::default();
        push_test_interest(&mut ep, 3, &file, (POLLIN as u32) | EPOLLONESHOT, 7);
        assert!(ep.ready(0, 8).is_empty());
        efd.borrow_mut().count = 2;
        assert_eq!(ep.ready(0, 8), vec![(0, POLLIN as u32)]);
        ep.reported(0, POLLIN as u32);
        assert!(ep.ready(0, 8).is_empty());
        // After the file is closed, the interest becomes void automatically
        ep.interests[0].as_mut().unwrap().armed = true;
        drop(file);
        assert!(
            ep.ready(0, 8).is_empty() && ep.interests[0].as_ref().unwrap().file.upgrade().is_none()
        );
    }
}
