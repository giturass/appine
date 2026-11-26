//! Open files and fd tables (the kernel/files map).
//!
//! An open file (Linux's `struct file`) records the file position and status flags and can be
//! shared by several fds (dup, fork); the close-on-exec flag belongs to the fd itself. Open files
//! and fd tables are accessed only while holding the BKL ([`crate::kernel`]).

use std::fs::File;
use std::ops::Range;
use std::rc::Rc;
use std::time::Duration;

use crate::cell::RefCell;
use crate::errno::Errno;
use crate::pipe::PipeEnd;
use crate::pseudo::PseudoNode;
use crate::tty::PtyEnd;
use crate::vfs::Node;
use crate::vfs::dev::Device;
use crate::vfs::store::{DirEntry, Ino};

/// The most fds a process can open (`/proc/sys/fs/nr_open`, the upper bound of `RLIMIT_NOFILE`),
/// the same as Linux's default.
pub const MAX_FDS: usize = 1 << 20;

/// `RLIMIT_NOFILE` of a new process: soft limit 1024, hard limit 4096, the same as the Linux
/// kernel's defaults. Go raises the soft limit to the hard limit at startup.
pub const DEFAULT_NOFILE: (usize, usize) = (1024, 4096);

/// open(2) flag bits (arm64 values).
pub mod oflags {
    /// Access mode mask.
    pub const O_ACCMODE: u32 = 0o3;
    /// Read-only.
    pub const O_RDONLY: u32 = 0o0;
    /// Write-only.
    pub const O_WRONLY: u32 = 0o1;
    /// Read-write.
    pub const O_RDWR: u32 = 0o2;
    /// Create if missing.
    pub const O_CREAT: u32 = 0o100;
    /// With `O_CREAT`: fail if it exists.
    pub const O_EXCL: u32 = 0o200;
    /// Do not make a terminal the controlling terminal.
    pub const O_NOCTTY: u32 = 0o400;
    /// Truncate.
    pub const O_TRUNC: u32 = 0o1000;
    /// Append.
    pub const O_APPEND: u32 = 0o2000;
    /// Nonblocking.
    pub const O_NONBLOCK: u32 = 0o4000;
    /// Signal-driven I/O: signal the owner on readiness (`syscall::poll`'s fasync).
    pub const O_ASYNC: u32 = 0o20000;
    /// Direct I/O (only recorded).
    pub const O_DIRECT: u32 = 0o200000;
    /// Must be a directory.
    pub const O_DIRECTORY: u32 = 0o40000;
    /// Do not follow a symlink in the last component.
    pub const O_NOFOLLOW: u32 = 0o100000;
    /// Large file (always true on 64-bit).
    pub const O_LARGEFILE: u32 = 0o400000;
    /// Writes to a regular file wait for the data to reach disk (fdatasync after each write).
    pub const O_DSYNC: u32 = 0o10000;
    /// `__O_SYNC`: with [`O_DSYNC`] it is `O_SYNC`, waiting as fsync does.
    pub const O_SYNC_BIT: u32 = 0o4000000;
    /// Do not update the access time (only for the owner or a process with `CAP_FOWNER`).
    pub const O_NOATIME: u32 = 0o1000000;
    /// Close on exec.
    pub const O_CLOEXEC: u32 = 0o2000000;
    /// Path only.
    pub const O_PATH: u32 = 0o10000000;
    /// `__O_TMPFILE`: unnamed temporary file bit (must be combined with [`O_DIRECTORY`]).
    pub const O_TMPFILE_BIT: u32 = 0o20000000;
    /// Create an unnamed temporary file in the named directory.
    pub const O_TMPFILE: u32 = O_TMPFILE_BIT | O_DIRECTORY;
    /// The flags fcntl(F_SETFL) can change.
    pub const SETFL_MASK: u32 = O_APPEND | O_NONBLOCK | O_ASYNC | O_DIRECT | O_NOATIME;
}

/// The kind of an open file.
pub enum FileKind {
    /// A host fd: `appine-run` hands the host's stdin/stdout/stderr to the guest as they are.
    Host(i32),
    /// A regular file in the inode store.
    Regular {
        /// The inode.
        ino: Ino,
        /// The host object file.
        file: File,
        /// Opened for writing while the file was held (it shares its object with other files,
        /// `Store::share`): `file` is then only open for reading, and the first change through
        /// this description gives the file an object of its own (`syscall::fs::prepare_write`).
        cow: bool,
    },
    /// A directory. Its entries are snapshotted on the first getdents and dropped on an lseek to
    /// 0.
    Directory {
        /// The directory node (in the store or in a synthetic filesystem).
        node: Node,
        /// Snapshot of the entries (including `.` and `..`).
        entries: Option<Vec<DirEntry>>,
        /// `/proc/<pid>`: the process at open time (used as a pidfd).
        process: Option<std::rc::Weak<RefCell<crate::process::ThreadGroup>>>,
        /// A FUSE directory: the daemon's handle from `FUSE_OPENDIR`, listed with
        /// `FUSE_READDIR`.
        fuse: Option<Box<crate::vfs::fuse::Handle>>,
    },
    /// A file opened with `O_PATH`: usable only as the starting point of `*at` calls or as the
    /// object of fstat.
    Path(Node),
    /// One end of a pipe.
    Pipe(PipeEnd),
    /// A device (`/dev/null`, a loop device and so on); `ino` is the device node in the store.
    Device {
        /// The inode.
        ino: Ino,
        /// The device.
        dev: Device,
        /// The read position and write rate limit of `/dev/kmsg` (only for [`Device::Kmsg`]).
        kmsg: Option<Box<crate::klog::KmsgFile>>,
        /// The loop device and this open of it (only for [`Device::Loop`]).
        block: Option<crate::syscall::LoopOpen>,
    },
    /// A virtio-gpu render node. Duplicated descriptors share this context and handle table.
    Render {
        ino: Ino,
        file: Rc<crate::syscall::RenderFile>,
    },
    /// A pollable, read-only GPU completion notification.
    GpuFence(std::os::fd::OwnedFd),
    /// The master or slave side of a PTY.
    Pty(PtyEnd),
    /// A socket.
    Socket(crate::syscall::SocketRef),
    /// An epoll instance.
    Epoll(Rc<RefCell<crate::syscall::Epoll>>),
    /// eventfd: a 64-bit counter.
    EventFd(Rc<RefCell<EventFd>>),
    /// timerfd: a timer whose expiration count read takes.
    TimerFd(Rc<RefCell<TimerFd>>),
    /// signalfd: read takes the caller's pending signals that are in the mask.
    SignalFd(Rc<RefCell<SignalFd>>),
    /// An inotify instance: read takes the queued filesystem events.
    Inotify(Rc<RefCell<crate::syscall::Inotify>>),
    /// pidfd: refers to a process and becomes readable when the process ends.
    Pidfd(Pidfd),
    /// A POSIX message queue.
    MessageQueue(Rc<RefCell<crate::syscall::MessageQueue>>),
    /// A seccomp notification fd (`SECCOMP_FILTER_FLAG_NEW_LISTENER`).
    SeccompNotify(crate::seccomp::Listener),
    /// An eBPF program ([`crate::bpf`]).
    Bpf(std::rc::Rc<crate::bpf::Prog>),
    /// A file in a FUSE filesystem other than a directory, read and written through its daemon
    /// (in mount [`OpenFile::mnt`]).
    Fuse(Box<crate::vfs::fuse::Handle>),
    /// `/dev/fuse`: a FUSE daemon reads requests from it and writes replies.
    FuseDev(crate::vfs::fuse::DevFile),
    /// A procfs, sysfs or cgroup2 file: content generated at open, regenerated when read again
    /// from offset 0.
    Proc {
        /// The mount it was reached through.
        mnt: crate::vfs::MountId,
        /// The node.
        node: PseudoNode,
        /// The content.
        data: Vec<u8>,
        /// `data` was just generated at open and has not been read or written yet: the first
        /// read from 0 need not regenerate it.
        fresh: bool,
        /// `/proc/<pid>/mem` and `/proc/<pid>/pagemap`: the address space of that process at open
        /// time. As on Linux, after the process execs or exits (even if its pid is reused), reads
        /// and writes still go to this address space (EOF once it has been freed), not to the new
        /// program's.
        mm: Option<std::rc::Weak<RefCell<crate::mm::Mm>>>,
        /// A namespace file (nsfs): keeps that namespace alive while open; used by setns and
        /// `NS_GET_*`.
        ns: Option<crate::nsproxy::NsRef>,
        /// `/proc/kmsg`: the kernel log (poll needs to look at it).
        klog: Option<Rc<RefCell<crate::klog::Klog>>>,
        /// The opener's credentials (Linux's `f_cred`): regeneration translates IDs through them
        /// and the id maps, `setgroups` and `timens_offsets` check writes with them, so a
        /// descriptor handed to another process keeps its opener's view and rights.
        opener: Rc<crate::cred::Cred>,
        /// Change notifications of a file Linux polls for them: sysfs and cgroup2 files, mounts
        /// and mountinfo.
        event: Option<ProcEvent>,
    },
}

/// Change notifications of an open synthetic file: kernfs's `kernfs_generic_poll` for sysfs and
/// cgroup2 files, procfs's `mounts_poll` for mounts and mountinfo. Poll reports `POLLERR` and
/// `POLLPRI` while the file has changed since a kernfs file was last read from the start, or since
/// mounts or mountinfo last had a change reported (`syscall::poll`'s `took_change`).
pub struct ProcEvent {
    /// Bumped at each change of what the file shows (cgroup2's notifying files,
    /// [`crate::cgroup::notify_changes`]; the mount table, [`crate::vfs::Vfs::mount_events`]);
    /// constant for the other kernfs files.
    pub counter: Rc<std::cell::Cell<u64>>,
    /// The counter when a kernfs file was last read from the start (0 before its first read, so
    /// it is reported as changed until then, as kernfs's are), or when mounts or mountinfo last
    /// had a change reported.
    pub seen: std::cell::Cell<u64>,
    /// The counter when the contents were generated.
    pub generated: std::cell::Cell<u64>,
    /// mounts and mountinfo: readable only (`EPOLLIN|EPOLLRDNORM`), where kernfs files are also
    /// writable (`DEFAULT_POLLMASK`).
    pub mounts: bool,
}

impl ProcEvent {
    /// A kernfs file following `counter` (Linux's open node starts its event at 1, the open file
    /// at 0).
    pub fn kernfs(counter: Rc<std::cell::Cell<u64>>) -> ProcEvent {
        let now = counter.get();
        ProcEvent {
            counter,
            seen: std::cell::Cell::new(0),
            generated: std::cell::Cell::new(now),
            mounts: false,
        }
    }

    /// mounts or mountinfo following the mount table's `counter`, seen as of the open
    /// (`mounts_open_common` records the namespace's event).
    pub fn mounts(counter: Rc<std::cell::Cell<u64>>) -> ProcEvent {
        let now = counter.get();
        ProcEvent {
            counter,
            seen: std::cell::Cell::new(now),
            generated: std::cell::Cell::new(now),
            mounts: true,
        }
    }

    /// Whether the file has changed since it was last read from the start (`POLLPRI`).
    pub fn changed(&self) -> bool {
        self.seen.get() != self.counter.get()
    }
}

/// An open file.
pub struct OpenFile {
    /// Store inode, pinned object and host write access for an O_PATH reopen through procfs.
    /// An overlay path keeps its overlay node separately from this backing inode.
    pub(crate) path_object: Option<(Ino, File, bool)>,
    /// A queue inode pinned by an O_PATH description, even after mq_unlink.
    pub(crate) mq_path: Option<Rc<RefCell<crate::syscall::MessageQueue>>>,
    /// Keeps an O_PATH node in the FUSE cache for the lifetime of the description.
    fuse_path: Option<Rc<()>>,
    /// The kind.
    pub kind: FileKind,
    /// Access mode and status flags (without `O_CLOEXEC`).
    pub flags: u32,
    /// File position; for a directory, the index of the next entry.
    pub pos: u64,
    /// Display name at open time, also used for files without a tracked dentry.
    pub path: Option<Rc<[u8]>>,
    /// The last directory and name passed through when opened by path: when it is used as a
    /// mount point through `/proc/<pid>/fd/<n>` (bubblewrap mounts this way), the mount records
    /// it ([`crate::vfs::Mount::at`]).
    pub dentry: Option<crate::vfs::Dentry>,
    /// The mount through which a store regular file, device node or FIFO was opened
    /// ([`OpenFile::node`]): flags such as read-only and noexec are taken from it. Directory and
    /// `O_PATH` nodes carry their mount already.
    pub mnt: crate::vfs::MountId,
    /// The overlay node in mount [`OpenFile::mnt`] for a regular file, device, FIFO or an
    /// `O_PATH` descriptor with a pinned backing file. Reads and writes use the backing inode.
    /// Metadata changes go through the overlay node ([`OpenFile::node`]).
    pub ovl: Option<crate::vfs::overlay::OvlId>,
    /// The overlay nodes it names (its directory or `O_PATH` node, [`OpenFile::ovl`], the
    /// directory of [`OpenFile::dentry`]), kept from being forgotten while it is open
    /// ([`OpenFile::hold`]).
    ovl_holds: Vec<crate::vfs::overlay::Hold>,
    /// The lower inode's object such a file was opened with, once its reads have moved to the
    /// copied-up one (`syscall::fs::follow_copy_up`): kept until the file is closed, since a read
    /// without the BKL may still be using it.
    pub ovl_lower: Option<std::fs::File>,
    /// The objects a regular file was opened with before its data moved to another object
    /// (`syscall::fs::rehome`): kept until the file is closed, as for
    /// [`OpenFile::ovl_lower`].
    pub retired: Vec<std::fs::File>,
    /// `F_SETOWN_EX`'s (type, pid) and `F_SETSIG`'s signal: with `O_ASYNC`, whom to signal on
    /// readiness and with which signal (0 is SIGIO); they are also signalled when a file lease is
    /// broken.
    pub owner: (i32, i32),
    /// The real and effective user IDs (kernel IDs) of whoever set `owner` (Linux's
    /// `f_owner.uid`/`euid`): they decide which processes the signals may reach
    /// (`syscall::poll::send_to_owner`).
    pub owner_ids: (u32, u32),
    pub sig: i32,
    /// How many times the program has used up the data in each direction, read and write, on this
    /// open file: from this, epoll's `EPOLLET` knows the program has used up the last reported
    /// event (`syscall::poll::drained`).
    pub drained: [u64; 2],
    /// Number of reads that got data: with `O_ASYNC` set, if it is still readable after a read,
    /// new data may have arrived, so notify once more (`syscall::poll`'s fasync).
    pub reads: u64,
    /// The edge an `EPOLLEXCLUSIVE` interest reported (`syscall::poll`'s data generation) and the
    /// epoll that reported it: other epolls do not report the same edge again (Linux wakes only one
    /// waiter).
    pub exclusive_claim: std::cell::Cell<Option<([u64; 4], usize)>>,
    /// Newly arrived events on a host fd: set up only when there is an edge-triggered or
    /// `EPOLLEXCLUSIVE` interest (`syscall::poll`).
    pub host_edges: Option<HostEdges>,
    /// An open store file: inotify reports fd-based events to the directory the open went
    /// through, and reports `IN_CLOSE_*` when the last reference is released.
    pub watch: Option<crate::syscall::Opened>,
    /// A read or write using the file position is in progress without the BKL (the equivalent
    /// of Linux's f_pos_lock; see `unlocked_io` in `syscall::fs`): 0 none, 1 one, 2 one and other
    /// threads are waiting for it.
    pub pos_busy: u8,
    /// Has taken a flock, OFD lock or lease: those have the open file as owner and are released
    /// with it on close, so threads waiting for locks must check again.
    pub holds_locks: bool,
    /// The anonymous mount namespace holding a tree copied by open_tree(`OPEN_TREE_CLONE`): held
    /// by this open file until attached; once it is closed the tree is torn down (Linux's
    /// `FMODE_NEED_UNMOUNT`).
    pub tree: Option<Rc<crate::vfs::MntNs>>,
    /// Not created through open (memfd_create, Linux's `alloc_file_pseudo`): not counted as a
    /// writer of the file, so executing it is not ETXTBSY; a reopen through
    /// `/proc/<pid>/fd/<n>` counts as usual. It also goes through no mount, so noexec and nosuid
    /// do not apply.
    pub pseudo: bool,
}

impl OpenFile {
    /// Creates an open file.
    pub fn new(kind: FileKind, flags: u32) -> FileRef {
        Self::with_path(kind, flags, None)
    }

    /// Creates an open file and records the absolute path at open time.
    pub fn with_path(kind: FileKind, flags: u32, path: Option<Rc<[u8]>>) -> FileRef {
        let ovl_holds = match &kind {
            FileKind::Directory {
                node: Node::Overlay(_, o),
                ..
            }
            | FileKind::Path(Node::Overlay(_, o)) => vec![crate::vfs::overlay::Hold::new(*o)],
            _ => Vec::new(),
        };
        Rc::new(RefCell::new(OpenFile {
            path_object: None,
            mq_path: None,
            fuse_path: None,
            kind,
            flags: flags & !oflags::O_CLOEXEC,
            pos: 0,
            path,
            dentry: None,
            mnt: crate::vfs::ROOT_MOUNT,
            ovl: None,
            ovl_holds,
            ovl_lower: None,
            retired: Vec::new(),
            owner: (0, 0),
            owner_ids: (0, 0),
            sig: 0,
            drained: [0; 2],
            reads: 0,
            exclusive_claim: std::cell::Cell::new(None),
            host_edges: None,
            pos_busy: 0,
            holds_locks: false,
            watch: None,
            pseudo: false,
            tree: None,
        }))
    }

    pub(crate) fn pin_fuse_path(&mut self, vfs: &crate::vfs::Vfs) -> Result<(), Errno> {
        if let FileKind::Path(Node::Fuse(_, id)) = self.kind {
            let mut fuse = vfs.fuse_mut();
            let node = fuse.get_mut(id).ok_or(Errno::ENOTCONN)?;
            self.fuse_path = Some(node.pin_path());
        }
        Ok(())
    }

    /// Whether it is readable.
    pub fn readable(&self) -> bool {
        self.flags & oflags::O_PATH == 0
            && matches!(
                self.flags & oflags::O_ACCMODE,
                oflags::O_RDONLY | oflags::O_RDWR
            )
    }

    /// Whether it is writable. Access mode 3 (`O_WRONLY|O_RDWR`) is neither readable nor
    /// writable: it only allows ioctls (Linux's `OPEN_FMODE`), though opening it needs read and
    /// write permission.
    pub fn writable(&self) -> bool {
        self.flags & oflags::O_PATH == 0
            && matches!(
                self.flags & oflags::O_ACCMODE,
                oflags::O_WRONLY | oflags::O_RDWR
            )
    }

    /// Keeps `node`, when it is an overlay node, from being forgotten while the file is open:
    /// for the overlay node set as [`OpenFile::ovl`] and the directory of [`OpenFile::dentry`]
    /// (the kind's node is held when the file is created).
    pub fn hold(&mut self, node: &Node) {
        if let Node::Overlay(_, o) = node {
            self.ovl_holds.push(crate::vfs::overlay::Hold::new(*o));
        }
    }

    /// Store inode, backing file and host write access for metadata or a magic-link reopen.
    pub(crate) fn regular_backing(&self) -> Option<(Ino, &File, bool)> {
        match &self.kind {
            FileKind::Regular { ino, file, cow } => Some((*ino, file, self.writable() && !cow)),
            FileKind::Path(_) => {
                let (ino, file, writable) = self.path_object.as_ref()?;
                Some((*ino, file, *writable))
            }
            _ => None,
        }
    }

    /// Queue behind a normal descriptor or an O_PATH reference to the same queue.
    pub(crate) fn message_queue(&self) -> Option<&Rc<RefCell<crate::syscall::MessageQueue>>> {
        match &self.kind {
            FileKind::MessageQueue(q) => Some(q),
            _ => self.mq_path.as_ref(),
        }
    }

    pub(crate) fn dentry_unlinked(&self) -> bool {
        self.watch
            .as_ref()
            .is_some_and(crate::syscall::Opened::is_unlinked)
    }

    /// The corresponding filesystem node (host fds, anonymous pipes and devpts/master PTYs have
    /// none; `/dev/tty` and `/dev/console` keep their device node).
    pub fn node(&self) -> Option<Node> {
        if let Some(o) = self.ovl {
            return Some(Node::Overlay(self.mnt, o));
        }
        match &self.kind {
            FileKind::Pipe(end) => end.pipe.borrow().fifo.map(|ino| Node::Store(self.mnt, ino)),
            FileKind::Pty(end) => end.dev_ino.map(|ino| Node::Store(self.mnt, ino)),
            FileKind::Host(_)
            | FileKind::Socket(_)
            | FileKind::Epoll(_)
            | FileKind::EventFd(_)
            | FileKind::TimerFd(_)
            | FileKind::SignalFd(_)
            | FileKind::Inotify(_)
            | FileKind::Pidfd(_)
            | FileKind::SeccompNotify(_)
            | FileKind::Bpf(_)
            | FileKind::MessageQueue(_) => None,
            FileKind::Render { ino, .. } => Some(Node::Store(self.mnt, *ino)),
            FileKind::GpuFence(_) => None,
            FileKind::FuseDev(d) => d.ino.map(|ino| Node::Store(self.mnt, ino)),
            FileKind::Fuse(h) => Some(Node::Fuse(self.mnt, h.id)),
            FileKind::Regular { ino, .. } | FileKind::Device { ino, .. } => {
                Some(Node::Store(self.mnt, *ino))
            }
            FileKind::Directory { node, .. } | FileKind::Path(node) => Some(node.clone()),
            FileKind::Proc { mnt, node, .. } => Some(Node::Pseudo(*mnt, node.clone())),
        }
    }

    /// Mount ID reported by statx and procfs fdinfo, including for node-less descriptors.
    pub(crate) fn mnt_id(&self) -> crate::vfs::MountId {
        self.node().map_or(crate::vfs::ANON_MOUNT, |n| n.mnt())
    }

    /// The inode in the store (chmod, chown and the like only make sense for these).
    pub fn ino(&self) -> Option<Ino> {
        self.node()?.ino()
    }

    /// The opened name follows renames independently of other hard links to the same inode.
    pub(crate) fn current_dentry(&self) -> Option<crate::vfs::Dentry> {
        let entry = self.dentry.as_ref()?;
        self.watch
            .as_ref()
            .and_then(|w| w.dentry(&entry.0))
            .or_else(|| Some(entry.clone()))
    }

    /// The store inode whose data a regular file reads and writes: for a file opened through an
    /// overlay, the one behind its overlay node.
    pub fn data_ino(&self) -> Option<Ino> {
        match &self.kind {
            FileKind::Regular { ino, .. } => Some(*ino),
            _ => self.ino(),
        }
    }

    /// What locks are keyed by ([`crate::locks`]): the store inode, or for a file opened through
    /// an overlay its overlay node's key (Linux locks the overlay's inode, which copying up does
    /// not change; [`crate::vfs::overlay::key`]), or a FUSE node's key (the daemon is not asked:
    /// `FUSE_POSIX_LOCKS` is not offered, so Linux keeps them in the kernel too).
    pub fn lock_ino(&self) -> Option<Ino> {
        match (self.ovl, self.node()) {
            (Some(o), _) => Some(crate::vfs::overlay::key(o)),
            (None, Some(Node::Fuse(_, f))) => Some(crate::vfs::fuse::key(f)),
            (None, _) => self.ino(),
        }
    }

    /// Whether it was opened nonblocking.
    pub fn nonblocking(&self) -> bool {
        self.flags & oflags::O_NONBLOCK != 0
    }
}

impl Drop for OpenFile {
    /// The last reference goes away: the flocks, OFD locks and leases it holds are released with
    /// it, so threads waiting for locks must check again
    /// ([`wake::LOCK`](crate::kernel::wake::LOCK)); a host socket's fd is about to be closed, and
    /// the host polls of threads waiting for it in poll, epoll or blocking sends and receives
    /// still hold it (the host socket is really closed only once they let go), so only the waiters
    /// registered for this socket are woken. Closing
    /// other files need not wake anyone: the other side of a pipe, PTY or AF_UNIX socket is woken
    /// by `PipeEnd`, `PtyEnd` or `UnixSocket` (only those waiting for that pipe, PTY or
    /// connection), and no thread waits for objects such as epoll, eventfd, inotify and message
    /// queues when they are closed (blocked sends and receives on them hold the open file and, as
    /// on Linux, do not wake because someone else closed the fd). A shell closes several files on
    /// every exec and exit, and each close used to wake the processes reading pipes. The mount it
    /// was in may have been detached and now be unused ([`crate::vfs::released`]).
    fn drop(&mut self) {
        crate::vfs::released(self.mnt);
        if let Some(node) = self.node() {
            let mnt = node.mnt();
            if mnt != self.mnt {
                crate::vfs::released(mnt);
            }
        }
        if let FileKind::Pty(end) = &self.kind
            && end.pin
        {
            crate::vfs::released(end.mnt);
        }
        if self.tree.is_some() {
            crate::vfs::released(crate::vfs::ANY_MOUNT);
        }
        match &self.kind {
            FileKind::Socket(s)
                if !s
                    .try_borrow()
                    .is_ok_and(|s| matches!(*s, crate::net::Socket::Unix(_))) =>
            {
                crate::kernel::request_wake_object(crate::kernel::wake::of(s));
            }
            _ => {}
        }
        if self.holds_locks {
            crate::kernel::request_wake_locks();
        }
    }
}

/// signalfd state. As on Linux it belongs to no thread: poll, epoll and read all look at the
/// signals pending for the calling thread and its thread group ([`crate::task::current`]), and a
/// forked process sees its own.
pub struct SignalFd {
    /// The signals of interest (excluding SIGKILL and SIGSTOP).
    pub mask: u64,
    /// The thread group that created it: when it is checked off a guest thread (the timer thread
    /// on behalf of signal-driven I/O and exclusive gates), only this thread group's pending
    /// signals are looked at.
    pub group: std::rc::Weak<RefCell<crate::process::ThreadGroup>>,
}

impl SignalFd {
    /// How many signals have become pending in total for the calling thread and its thread group
    /// (`syscall::poll`'s data generation).
    pub fn arrivals(&self) -> u64 {
        let (task, group) = self.pending();
        let group = group.map_or(0, |g| g.borrow().pending.arrivals());
        group + task.map_or(0, |t| t.pending.borrow().arrivals())
    }

    /// Whether there is a signal the calling thread can read (poll).
    pub fn ready(&self) -> bool {
        let (task, group) = self.pending();
        let group = group.map_or(0, |g| g.borrow().pending.set());
        let task = task.map_or(0, |t| t.pending.borrow().set());
        (group | task) & self.mask != 0
    }

    /// The calling thread and its thread group; off a guest thread, the thread group that created
    /// it.
    fn pending(
        &self,
    ) -> (
        Option<Rc<crate::task::Task>>,
        Option<Rc<RefCell<crate::process::ThreadGroup>>>,
    ) {
        match crate::task::current() {
            Some((task, group)) => (Some(task), Some(group)),
            None => (None, self.group.upgrade()),
        }
    }
}

/// The process a pidfd refers to. It holds a weak reference: after the pid is given to another
/// process, it still refers to the original one.
pub struct Pidfd {
    pub tgid: crate::kernel::Tid,
    pub group: std::rc::Weak<RefCell<crate::process::ThreadGroup>>,
}

impl Pidfd {
    /// Returns the process's thread group if it has not been reaped yet (it may be a zombie).
    pub fn group(
        &self,
        k: &crate::kernel::Kernel,
    ) -> Option<Rc<RefCell<crate::process::ThreadGroup>>> {
        let g = self.group.upgrade()?;
        k.groups
            .get(&self.tgid)
            .is_some_and(|o| Rc::ptr_eq(o, &g))
            .then_some(g)
    }

    /// All threads have exited (poll readable).
    pub fn exited(&self) -> bool {
        self.group
            .upgrade()
            .is_none_or(|g| g.borrow().threads.is_empty())
    }
}

/// timerfd state.
pub struct TimerFd {
    /// The clock (`CLOCK_REALTIME` and so on).
    pub clock: i32,
    /// The next expiration, on the clock's base; None means not armed.
    pub deadline: Option<crate::itimer::Expiry>,
    /// `TFD_TIMER_CANCEL_ON_SET` on an absolute realtime timer (Linux's `might_cancel`): the
    /// wall-clock jump count when set ([`crate::itimer::clock_epoch`]), and whether a jump since
    /// has been counted as an expiration and not yet read (`moffs == KTIME_MAX`): the next read is
    /// then `ECANCELED`.
    pub cancel: Option<(u64, bool)>,
    /// The interval to rearm with after expiring; 0 means firing only once.
    pub interval: Duration,
    /// Expirations that have happened and not been read yet.
    pub expirations: u64,
    /// Total expirations (not reduced by reads): epoll's `EPOLLET` fires on every expiration.
    pub fired: u64,
    /// The flags of the last timerfd_settime (`/proc/<pid>/fdinfo`).
    pub settime_flags: u32,
}

impl TimerFd {
    /// How long until the next expiration, 0 when not armed (timerfd_gettime's `it_value`).
    pub fn remaining(&mut self) -> Duration {
        self.update();
        self.deadline
            .map_or(Duration::ZERO, crate::itimer::Expiry::remaining)
    }

    /// The timerfd-specific lines in `/proc/<pid>/fdinfo`.
    pub fn fdinfo(&mut self) -> String {
        let left = self.remaining();
        format!(
            "clockid: {}\nticks: {}\nsettime flags: 0{:o}\nit_value: ({}, {})\nit_interval: ({}, {})\n",
            self.clock,
            self.expirations,
            self.settime_flags,
            left.as_secs(),
            left.subsec_nanos(),
            self.interval.as_secs(),
            self.interval.subsec_nanos()
        )
    }

    /// Adds the expirations that have passed to `expirations`, and a wall-clock jump of a
    /// `TFD_TIMER_CANCEL_ON_SET` timer as one more (`timerfd_clock_was_set`).
    pub fn update(&mut self) {
        if let Some((epoch, pending)) = &mut self.cancel {
            let now = crate::itimer::clock_epoch();
            if !*pending && *epoch != now {
                *epoch = now;
                *pending = true;
                self.expirations += 1;
                self.fired += 1;
            }
        }
        let Some((d, late)) = self.deadline.and_then(|d| Some((d, d.late()?))) else {
            return;
        };
        self.fired += 1;
        if self.interval.is_zero() {
            self.expirations += 1;
            self.deadline = None;
        } else {
            let n = (late.as_nanos() / self.interval.as_nanos()) as u64 + 1;
            self.expirations += n;
            let step = Duration::from_nanos((self.interval.as_nanos() * u128::from(n)) as u64);
            self.deadline = Some(d.add(step));
        }
    }

    /// Takes a pending cancellation (`timerfd_canceled`): true once after a wall-clock jump.
    pub fn take_cancel(&mut self) -> bool {
        match &mut self.cancel {
            Some((_, pending)) if *pending => {
                *pending = false;
                true
            }
            _ => false,
        }
    }
}

/// eventfd state.
pub struct EventFd {
    /// The counter.
    pub count: u64,
    /// `EFD_SEMAPHORE`: each read only subtracts 1.
    pub semaphore: bool,
    /// Number of writes and reads: as on Linux, every write makes the reading side's `EPOLLET`
    /// fire again (mio's waker relies on this and never reads the count away), and every read
    /// makes the writing side's fire again.
    pub writes: u64,
    pub reads: u64,
}

/// Accumulated counts of newly arrived events on a host fd ([`appine_hal::Edges`]).
pub struct HostEdges {
    edges: appine_hal::Edges,
    counts: std::cell::Cell<[u64; 2]>,
    /// The host epoll may have events not yet taken: it was readable the last time it was polled
    /// together with the host fd ([`HostEdges::polled`]).
    unread: std::cell::Cell<bool>,
}

impl HostEdges {
    /// Starts recording newly arrived events on host fd `fd`.
    pub fn new(fd: i32) -> Result<HostEdges, i32> {
        Ok(HostEdges {
            edges: appine_hal::Edges::new(fd)?,
            counts: std::cell::Cell::new([0; 2]),
            unread: std::cell::Cell::new(true),
        })
    }

    /// How many events have arrived so far in each direction, read and write.
    pub fn counts(&self) -> [u64; 2] {
        self.unread.set(false);
        let (r, w) = self.edges.take();
        let [a, b] = self.counts.get();
        let now = [a + r as u64, b + w as u64];
        self.counts.set(now);
        now
    }

    /// The same as [`HostEdges::counts`], but just after polling together with the host fd
    /// ([`HostEdges::polled`]): if the host epoll was not readable then, there is no need to ask
    /// the host again, saving one system call per check.
    pub fn counts_polled(&self) -> [u64; 2] {
        if self.unread.get() {
            self.counts()
        } else {
            self.counts.get()
        }
    }

    /// The host epoll's fd was polled together with the host fd, giving `revents`.
    pub fn polled(&self, revents: i16) {
        self.unread.set(self.unread.get() || revents != 0);
    }

    /// The host fd that is readable when there are new events, put into the host poll while
    /// waiting.
    pub fn fd(&self) -> i32 {
        self.edges.fd()
    }
}

/// A shared reference to an open file.
pub type FileRef = Rc<RefCell<OpenFile>>;

#[derive(Clone)]
struct Slot {
    file: FileRef,
    cloexec: bool,
}

/// Initial logical descriptor-table capacity (Linux's `NR_OPEN_DEFAULT = BITS_PER_LONG`).
const MIN_CAPACITY: usize = 64;

/// A process's fd table.
pub struct FdTable {
    slots: Vec<Option<Slot>>,
    /// Logical table capacity (`fdt->max_fds`): starts at 64 and grows in powers of two, capped
    /// at the kernel's `nr_open` rounded up to 64 when expanding. Closing a file clears its slot
    /// without shrinking the table.
    capacity: usize,
    /// fds taken by [`reserve`](Self::reserve) for a file not made yet (Linux's
    /// `get_unused_fd_flags`: an open_fds bit with no file): new fds skip them, dup2 onto one is
    /// EBUSY, and every other call sees them closed.
    reserved: Vec<usize>,
    /// Has taken POSIX record locks (the locks belong to the fd table, see `crate::locks`).
    pub holds_locks: bool,
}

impl Default for FdTable {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            capacity: MIN_CAPACITY,
            reserved: Vec::new(),
            holds_locks: false,
        }
    }
}

/// Logical capacity for `need` slots: at least 64, power-of-two growth, capped at `nr_open`
/// rounded up to 64 (never below the 64-aligned slot count required for `need`).
fn capacity_for(need: usize, nr_open: usize) -> usize {
    let min_cap = need.next_multiple_of(MIN_CAPACITY).max(MIN_CAPACITY);
    let pow2 = need.max(MIN_CAPACITY).next_power_of_two();
    let cap = nr_open.next_multiple_of(MIN_CAPACITY).max(min_cap);
    pow2.min(cap)
}

impl FdTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Logical capacity of the descriptor table (`fdt->max_fds`).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Expands the table's logical capacity to hold descriptor `fd` (Linux's `expand_files` and
    /// `alloc_fdtable`): when `fd` already fits, no expansion occurs; otherwise refuses `fd >=
    /// nr_open` with `EMFILE` and grows by powers of two capped at `nr_open` rounded up to 64.
    fn grow_for(&mut self, fd: usize, nr_open: usize) -> Result<(), Errno> {
        if fd < self.capacity {
            return Ok(());
        }
        if fd >= nr_open {
            return Err(Errno::EMFILE);
        }
        self.capacity = capacity_for(fd + 1, nr_open).max(self.capacity);
        Ok(())
    }

    /// 0/1/2 are the host's stdin/stdout/stderr respectively.
    pub fn with_host_stdio() -> Self {
        let mut t = Self::new();
        // With O_LARGEFILE as the originals have it: on the host side these are most likely
        // terminals or files opened with open
        for (fd, flags) in [
            (0, oflags::O_RDONLY | oflags::O_LARGEFILE),
            (1, oflags::O_WRONLY | oflags::O_LARGEFILE),
            (2, oflags::O_WRONLY | oflags::O_LARGEFILE),
        ] {
            t.install(
                OpenFile::new(FileKind::Host(fd), flags),
                false,
                0..DEFAULT_NOFILE.0,
            )
            .unwrap();
        }
        t
    }

    /// Installs at the lowest free fd in the allocating process's range.
    pub fn install(
        &mut self,
        file: FileRef,
        cloexec: bool,
        range: Range<usize>,
    ) -> Result<i32, Errno> {
        self.install_capped(file, cloexec, range, MAX_FDS)
    }

    /// Installs at the lowest free fd in `range`, respecting `nr_open` when expanding the table.
    pub fn install_capped(
        &mut self,
        file: FileRef,
        cloexec: bool,
        range: Range<usize>,
        nr_open: usize,
    ) -> Result<i32, Errno> {
        let fd = self.free_slot(range)?;
        self.grow_for(fd as usize, nr_open)?;
        self.replace_slot(fd as usize, Slot { file, cloexec });
        Ok(fd)
    }

    /// The lowest free fd in the requested range.
    pub fn free_slot(&self, mut range: Range<usize>) -> Result<i32, Errno> {
        range
            .find(|&i| self.slots.get(i).is_none_or(Option::is_none) && !self.reserved.contains(&i))
            .map(|i| i as i32)
            .ok_or(Errno::EMFILE)
    }

    /// Takes the lowest free fd in `range` for a file to be made later (accept4 before it waits,
    /// or AF_UNIX `SCM_RIGHTS` delivery), respecting `nr_open` when expanding the table, until
    /// [`fill`](Self::fill) or [`unreserve`](Self::unreserve).
    pub fn reserve(&mut self, range: Range<usize>, nr_open: usize) -> Result<i32, Errno> {
        let fd = self.free_slot(range)?;
        self.grow_for(fd as usize, nr_open)?;
        if self.slots.len() <= fd as usize {
            self.slots.resize(fd as usize + 1, None);
        }
        self.reserved.push(fd as usize);
        Ok(fd)
    }

    /// Installs `file` at fd `fd`, which [`reserve`](Self::reserve) took (the limit is not checked
    /// again, as Linux's `fd_install`).
    pub fn fill(&mut self, fd: i32, file: FileRef, cloexec: bool) {
        let i = fd as usize;
        self.reserved.retain(|&r| r != i);
        self.slots[i] = Some(Slot { file, cloexec });
    }

    /// Gives back fd `fd`, which [`reserve`](Self::reserve) took (Linux's `put_unused_fd`).
    pub fn unreserve(&mut self, fd: i32) {
        self.reserved.retain(|&r| r != fd as usize);
    }

    /// Installs at the given fd, returning the file it replaced (dup2/dup3).
    pub fn install_at(
        &mut self,
        fd: i32,
        file: FileRef,
        cloexec: bool,
        limit: usize,
    ) -> Result<Option<FileRef>, Errno> {
        self.install_at_capped(fd, file, cloexec, limit, MAX_FDS)
    }

    /// Installs at `fd`, respecting `nr_open` when expanding (returning `EBADF`, as Linux's
    /// `do_dup2` / `replace_fd` maps `expand_files`'s `EMFILE` to `EBADF`).
    pub fn install_at_capped(
        &mut self,
        fd: i32,
        file: FileRef,
        cloexec: bool,
        limit: usize,
        nr_open: usize,
    ) -> Result<Option<FileRef>, Errno> {
        let i = usize::try_from(fd)
            .ok()
            .filter(|&i| i < limit)
            .ok_or(Errno::EBADF)?;
        // An fd reserved for a file still being made (do_dup2)
        if self.reserved.contains(&i) {
            return Err(Errno::EBUSY);
        }
        self.grow_for(i, nr_open).map_err(|_| Errno::EBADF)?;
        Ok(self.replace_slot(i, Slot { file, cloexec }))
    }

    /// Both allocation and dup3 have already checked the slot against the caller's limit and reservations.
    fn replace_slot(&mut self, i: usize, slot: Slot) -> Option<FileRef> {
        if self.slots.len() <= i {
            self.slots.resize(i + 1, None);
        }
        self.slots[i].replace(slot).map(|old| old.file)
    }

    /// Gets the open file for an fd.
    pub fn get(&self, fd: i32) -> Result<FileRef, Errno> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get(i))
            .and_then(Option::as_ref)
            .map(|s| s.file.clone())
            .ok_or(Errno::EBADF)
    }

    /// Reads the close-on-exec flag.
    pub fn cloexec(&self, fd: i32) -> Result<bool, Errno> {
        self.slot(fd).map(|s| s.cloexec)
    }

    fn slot(&self, fd: i32) -> Result<&Slot, Errno> {
        usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get(i))
            .and_then(Option::as_ref)
            .ok_or(Errno::EBADF)
    }

    /// Sets the close-on-exec flag.
    pub fn set_cloexec(&mut self, fd: i32, cloexec: bool) -> Result<(), Errno> {
        let i = usize::try_from(fd).map_err(|_| Errno::EBADF)?;
        let slot = self
            .slots
            .get_mut(i)
            .and_then(Option::as_mut)
            .ok_or(Errno::EBADF)?;
        slot.cloexec = cloexec;
        Ok(())
    }

    /// Closes an fd, returning the closed file.
    pub fn close(&mut self, fd: i32) -> Result<FileRef, Errno> {
        let slot = usize::try_from(fd)
            .ok()
            .and_then(|i| self.slots.get_mut(i))
            .ok_or(Errno::EBADF)?;
        slot.take().map(|s| s.file).ok_or(Errno::EBADF)
    }

    /// execve: closes every fd with the close-on-exec flag, returning the closed files.
    pub fn close_on_exec(&mut self) -> Vec<FileRef> {
        let mut closed = Vec::new();
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|s| s.cloexec) {
                closed.extend(slot.take().map(|s| s.file));
            }
        }
        closed
    }

    /// close_range(2): closes (or only marks close-on-exec) the fds in `[first, last]`, returning
    /// the closed files.
    pub fn close_range(&mut self, first: usize, last: usize, cloexec_only: bool) -> Vec<FileRef> {
        let mut closed = Vec::new();
        let end = last.saturating_add(1).min(self.slots.len());
        for slot in self.slots.iter_mut().take(end).skip(first) {
            match slot {
                Some(s) if cloexec_only => s.cloexec = true,
                _ => closed.extend(slot.take().map(|s| s.file)),
            }
        }
        closed
    }

    /// Linux's dup_fd sizes the copy from the highest open bitmap bit. Reservations count
    /// towards the size but have no file to copy. close_range may exclude a range of fds.
    pub fn copy_len(&self, keep: impl Fn(usize) -> bool) -> usize {
        let file = self
            .slots
            .iter()
            .enumerate()
            .rfind(|(i, slot)| slot.is_some() && keep(*i));
        let reserved = self.reserved.iter().copied().filter(|&i| keep(i)).max();
        file.map(|(i, _)| i).max(reserved).map_or(0, |i| i + 1)
    }

    fn copy_slots(&self, len: usize, nr_open: usize) -> Self {
        Self {
            slots: self.slots[..len].to_vec(),
            capacity: capacity_for(len, nr_open),
            reserved: Vec::new(),
            holds_locks: false,
        }
    }

    /// Clones the table, sizing its logical capacity for the surviving descriptors capped by
    /// `nr_open` rounded up to 64 (Linux's `dup_fd`).
    pub fn clone_capped(&self, nr_open: usize) -> Self {
        self.copy_slots(self.copy_len(|_| true), nr_open)
    }

    /// Applies close_range while unsharing. Size the new table for the surviving bitmap
    /// and return every closed file for lock, notification and FUSE cleanup.
    pub fn unshare_close_range(
        &self,
        first: usize,
        last: usize,
        cloexec: bool,
        nr_open: usize,
    ) -> Result<(Self, Vec<FileRef>), Errno> {
        let len = self.copy_len(|fd| cloexec || fd < first || fd > last);
        if len.next_multiple_of(MIN_CAPACITY) > nr_open {
            return Err(Errno::EMFILE);
        }
        let mut copy = self.copy_slots(len, nr_open);
        let mut closed = copy.close_range(first, last, cloexec);
        closed.extend(self.slots[len..].iter().flatten().map(|s| s.file.clone()));
        Ok((copy, closed))
    }

    /// Open file descriptions in descriptor order, including duplicate references.
    pub(crate) fn files(&self) -> impl Iterator<Item = &FileRef> {
        self.slots.iter().flatten().map(|slot| &slot.file)
    }

    /// All open fds, in increasing order.
    pub fn open_fds(&self) -> Vec<i32> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i as i32)
            .collect()
    }
}

impl Clone for FdTable {
    /// fork, clone without `CLONE_FILES`, unshare: POSIX locks belong to the original fd table
    /// and are not copied with it, nor are reserved fds (dup_fd clears their bits).
    fn clone(&self) -> Self {
        self.clone_capped(MAX_FDS)
    }
}

impl Drop for FdTable {
    /// The fd table goes away (process exit): the record locks it holds lapse with it, so threads
    /// waiting for locks must check again. Not needed if it never took a lock: every process exit
    /// used to wake all threads reading pipes or waiting in poll.
    fn drop(&mut self) {
        if self.holds_locks {
            crate::kernel::request_wake_locks();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_lowest_free_fd() {
        let mut t = FdTable::with_host_stdio();
        let f = OpenFile::new(FileKind::Host(1), oflags::O_WRONLY);
        assert_eq!(t.install(f.clone(), false, 0..DEFAULT_NOFILE.0), Ok(3));
        t.close(1).unwrap();
        assert_eq!(t.install(f.clone(), true, 0..DEFAULT_NOFILE.0), Ok(1));
        assert_eq!(t.cloexec(1), Ok(true));
        assert_eq!(t.install(f.clone(), false, 10..DEFAULT_NOFILE.0), Ok(10));
        assert_eq!(t.close(7).err(), Some(Errno::EBADF));
        assert_eq!(t.get(-1).err(), Some(Errno::EBADF));
        // New fds cannot exceed RLIMIT_NOFILE
        let limit = 11;
        for fd in [4, 5, 6, 7, 8, 9] {
            assert_eq!(t.install(f.clone(), false, 0..limit), Ok(fd));
        }
        assert_eq!(t.install(f.clone(), false, 0..limit), Err(Errno::EMFILE));
        // A starting point beyond the limit also means no free slot (the caller checks F_DUPFD's
        // EINVAL)
        assert_eq!(t.install(f.clone(), false, 11..limit), Err(Errno::EMFILE));
        // fds created by dup share one open file
        f.borrow_mut().pos = 5;
        assert_eq!(t.get(10).unwrap().borrow().pos, 5);
    }

    #[test]
    fn table_capacity_after_copy() {
        let mut parent = FdTable::with_host_stdio();
        let file = parent.get(1).unwrap();
        parent
            .install_at(100, file.clone(), false, DEFAULT_NOFILE.0)
            .unwrap();
        parent.reserve(200..DEFAULT_NOFILE.0, MAX_FDS).unwrap();
        let child = parent.clone();
        assert_eq!(child.capacity(), 256);
        assert_eq!(child.free_slot(200..DEFAULT_NOFILE.0), Ok(200));
        parent.unreserve(200);
        assert_eq!(parent.capacity(), 256);
        assert_eq!(parent.clone().capacity(), 128);

        let (private, closed) = parent.unshare_close_range(100, 200, false, 64).unwrap();
        assert_eq!(private.capacity(), 64);
        assert_eq!(closed.len(), 1);
        assert!(Rc::ptr_eq(&closed[0], &file));
        assert!(parent.get(100).is_ok());
        let (marked, closed) = parent.unshare_close_range(100, 200, true, 128).unwrap();
        assert_eq!(marked.capacity(), 128);
        assert_eq!(marked.cloexec(100), Ok(true));
        assert!(closed.is_empty());
    }

    /// A reserved fd is skipped by new fds, closed to everything else, EBUSY to dup2, not copied
    /// by fork, and filled or given back later.
    #[test]
    fn reserved_fds() {
        let mut t = FdTable::with_host_stdio();
        let f = OpenFile::new(FileKind::Host(1), oflags::O_WRONLY);
        assert_eq!(t.reserve(0..DEFAULT_NOFILE.0, MAX_FDS), Ok(3));
        assert_eq!(t.install(f.clone(), false, 0..DEFAULT_NOFILE.0), Ok(4));
        assert_eq!(t.get(3).err(), Some(Errno::EBADF));
        assert_eq!(t.close(3).err(), Some(Errno::EBADF));
        assert_eq!(
            t.install_at(3, f.clone(), false, DEFAULT_NOFILE.0).err(),
            Some(Errno::EBUSY)
        );
        assert_eq!(t.open_fds(), [0, 1, 2, 4]);
        let mut child = t.clone();
        assert_eq!(child.install(f.clone(), false, 0..DEFAULT_NOFILE.0), Ok(3));
        t.fill(3, f.clone(), true);
        assert_eq!(t.cloexec(3), Ok(true));
        assert_eq!(t.reserve(0..DEFAULT_NOFILE.0, MAX_FDS), Ok(5));
        t.unreserve(5);
        assert_eq!(t.install(f.clone(), false, 0..DEFAULT_NOFILE.0), Ok(5));
    }

    #[test]
    fn table_growth_respects_nr_open_cap() {
        let mut t = FdTable::with_host_stdio();
        let f = t.get(1).unwrap();
        assert_eq!(t.capacity(), 64);

        // Lowered nr_open (192) caps expansion instead of rounding up to 256.
        assert!(
            t.install_at_capped(150, f.clone(), false, 4096, 192)
                .unwrap()
                .is_none()
        );
        assert_eq!(t.capacity(), 192);
        // Expanding past nr_open fails with EBADF for dup3/install_at and EMFILE for alloc/reserve.
        assert_eq!(
            t.install_at_capped(192, f.clone(), false, 4096, 192).err(),
            Some(Errno::EBADF)
        );
        assert_eq!(
            t.install_capped(f.clone(), false, 192..4096, 192),
            Err(Errno::EMFILE)
        );
        assert_eq!(t.reserve(192..4096, 192), Err(Errno::EMFILE));
        // Reserve itself also caps expansion at nr_open and leaves no reservation on EMFILE.
        let mut r = FdTable::with_host_stdio();
        assert_eq!(r.reserve(150..4096, 192), Ok(150));
        assert_eq!(r.capacity(), 192);
        assert_eq!(r.reserve(192..4096, 192), Err(Errno::EMFILE));
        assert_eq!(r.capacity(), 192);
        assert_eq!(r.free_slot(192..4096), Ok(192));
        // Slot 191 still fits within the already-expanded capacity (192).
        assert_eq!(t.install_capped(f.clone(), false, 191..4096, 192), Ok(191));
        assert_eq!(t.capacity(), 192);

        // Lowering nr_open further does not shrink existing capacity; fds within existing capacity
        // still succeed, while fds requiring expansion past nr_open fail.
        assert!(
            t.install_at_capped(180, f.clone(), false, 4096, 128)
                .unwrap()
                .is_none()
        );
        assert_eq!(t.capacity(), 192);
        assert_eq!(
            t.install_capped(f.clone(), false, 192..4096, 128),
            Err(Errno::EMFILE)
        );

        // Cloning with nr_open=192 also keeps capacity capped at 192.
        let copy = t.clone_capped(192);
        assert_eq!(copy.capacity(), 192);

        // Unsharing with close_range caps the new table at nr_open as well.
        let (unshared, closed) = t.unshare_close_range(180, 191, false, 192).unwrap();
        assert_eq!(unshared.capacity(), 192);
        assert_eq!(closed.len(), 2);
    }
}
