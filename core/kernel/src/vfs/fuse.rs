//! FUSE (Linux 6.1's `fs/fuse`, the kernel/fuse map): filesystems whose content a guest process
//! (the daemon: sshfs, rclone mount, any libfuse program) serves through `/dev/fuse`.
//!
//! Opening `/dev/fuse` gives a device file with no connection ([`DevFile`]); mount(2) of type
//! `fuse` or `fuse.<subtype>` names it with `fd=` and creates the connection ([`Conn`]) and its
//! instance, then queues `FUSE_INIT` without waiting for it, as Linux does: the daemon reads it
//! once it starts serving, and every other request waits until it has been answered. Requests are
//! messages in Linux's format (`fuse_in_header` and the operation's arguments); the daemon reads
//! one per read(2) and writes its reply, matched by `unique`, with write(2). A thread making a
//! request releases the BKL until the reply comes ([`call`]), following Linux's
//! `request_wait_answer`: a signal while the daemon holds the request sends it `FUSE_INTERRUPT`
//! and goes on waiting, and only a fatal signal before the daemon has read it gives up. Unmounting
//! the last mount of an instance, or closing the last device file attached to the connection,
//! aborts it: requests in flight end with `ECONNABORTED`, later ones with `ENOTCONN`, and the
//! daemon's reads with `ENODEV`.
//!
//! Path resolution runs under the BKL inside the store's read snapshot and cannot wait, so lookups
//! go through a cache ([`Fuses`]): each directory keeps what `FUSE_LOOKUP` said about its names
//! (Linux's dentries, for the `entry_valid` time the reply gave) and each node its attributes (for
//! `attr_valid`) and, within a syscall, its symlink target. A walk that needs something the cache
//! does not hold records the request ([`need`]) and fails with the internal [`Errno::FUSE_RETRY`];
//! the syscall dispatcher then makes that request with the BKL released ([`serve`]) and runs the
//! syscall again from the start, as Linux's RCU walk falls back to a walk that may sleep. What a
//! request brought back counts as fresh for the rest of that syscall ([`token`]), however short
//! its validity, so every retry makes progress. Only queries that change nothing (lookups,
//! attributes, links) go this way; operations that change something are made directly by the
//! syscall that has `&mut Cx`, after which it must not need a retry.
//!
//! Nodes are cached by node id per instance. Descriptor I/O goes through the daemon and
//! live mappings share demand-filled file pages. Inode notifications revoke affected
//! translations before the pages can be filled from a new daemon reply.

use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::store::{Ino, Stat, mode};
use crate::cell::RefCell;
use crate::cred::{Cred, UserNs};
use crate::errno::Errno;
use crate::kernel::{Cx, Tid, request_wake_object, wake};
use crate::mm::FillPages;

mod host;

/// A FUSE node's number (in [`super::Node::Fuse`]), unique across all instances and never reused.
pub(crate) type FuseId = u64;

/// The number that stands for node `id` in tables keyed by store inode number (locks, inotify
/// watches): its id with the top two bits set; store inode numbers have neither, and overlay keys
/// only the top one ([`super::overlay::key`]).
pub(crate) const fn key(id: FuseId) -> Ino {
    3 << 62 | id
}

/// The node a [`key`] stands for.
pub(crate) const fn id_of(key: Ino) -> Option<FuseId> {
    if key >> 62 == 3 {
        Some(key & !(3 << 62))
    } else {
        None
    }
}

/// `FUSE_SUPER_MAGIC` (statfs's `f_type`).
pub(crate) const SUPER_MAGIC: u64 = 0x6573_5546;

/// `/dev/fuse`'s device number (misc 10:229).
pub(crate) const DEV_RDEV: u64 = crate::vfs::dev::rdev(10, 229);

/// The protocol version Linux 6.1 speaks (`FUSE_KERNEL_VERSION`, `FUSE_KERNEL_MINOR_VERSION`).
const KERNEL_MAJOR: u32 = 7;
const KERNEL_MINOR: u32 = 37;
/// The node id of an instance's root directory (`FUSE_ROOT_ID`).
const ROOT_ID: u64 = 1;
/// A read of the device must offer at least this much room (`FUSE_MIN_READ_BUFFER`).
const MIN_READ_BUFFER: usize = 8192;
/// `struct fuse_in_header` and `struct fuse_out_header`.
const IN_HEADER: usize = 40;
const OUT_HEADER: usize = 16;
/// The bit of `unique` that marks an interrupt request (`FUSE_INT_REQ_BIT`).
const INT_REQ_BIT: u64 = 1;
/// Pages per request without `FUSE_MAX_PAGES`, and the most with it.
const DEFAULT_MAX_PAGES: u32 = 32;
const MAX_MAX_PAGES: u32 = 256;
const PAGE: u32 = 4096;
/// The largest name FUSE passes (`FUSE_NAME_MAX`).
pub(crate) const NAME_MAX: usize = 1024;

/// Operation codes (`enum fuse_opcode`).
pub(crate) mod op {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const READLINK: u32 = 5;
    pub const SYMLINK: u32 = 6;
    pub const MKNOD: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RMDIR: u32 = 11;
    pub const RENAME: u32 = 12;
    pub const LINK: u32 = 13;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const SETXATTR: u32 = 21;
    pub const GETXATTR: u32 = 22;
    pub const LISTXATTR: u32 = 23;
    pub const REMOVEXATTR: u32 = 24;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const FSYNCDIR: u32 = 30;
    pub const ACCESS: u32 = 34;
    pub const CREATE: u32 = 35;
    pub const INTERRUPT: u32 = 36;
    pub const BATCH_FORGET: u32 = 42;
    pub const FALLOCATE: u32 = 43;
    pub const RENAME2: u32 = 45;
    pub const LSEEK: u32 = 46;
}

/// `FUSE_INIT` flags.
mod init {
    pub const ATOMIC_O_TRUNC: u32 = 1 << 3;
    pub const EXPORT_SUPPORT: u32 = 1 << 4;
    pub const BIG_WRITES: u32 = 1 << 5;
    pub const DONT_MASK: u32 = 1 << 6;
    pub const AUTO_INVAL_DATA: u32 = 1 << 12;
    pub const NO_OPEN_SUPPORT: u32 = 1 << 17;
    pub const PARALLEL_DIROPS: u32 = 1 << 18;
    pub const HANDLE_KILLPRIV: u32 = 1 << 19;
    pub const MAX_PAGES: u32 = 1 << 22;
    pub const NO_OPENDIR_SUPPORT: u32 = 1 << 24;
    /// Descriptor writes go to the daemon, so no writeback cache is negotiated. No splice, readdirplus or
    /// cache invalidation flags, and no `ASYNC_READ` (the kernel reads ahead in parallel with it,
    /// which this one does not: sshfs leaves reading ahead to a kernel that offers it, and does it
    /// itself otherwise); locks are kept in the kernel (no `POSIX_LOCKS`, `FLOCK_LOCKS`).
    /// libfuse 3.17 ends the session when a filesystem wants a flag not offered, and some want
    /// `DONT_MASK` whatever is offered (fuse-overlayfs); `EXPORT_SUPPORT` only allows lookups of
    /// `.` and `..`, which are never sent.
    pub const OFFERED: u32 = ATOMIC_O_TRUNC
        | EXPORT_SUPPORT
        | BIG_WRITES
        | DONT_MASK
        | AUTO_INVAL_DATA
        | NO_OPEN_SUPPORT
        | PARALLEL_DIROPS
        | HANDLE_KILLPRIV
        | MAX_PAGES
        | NO_OPENDIR_SUPPORT;
}

/// `FOPEN_*` flags of an open reply.
pub(crate) mod fopen {
    pub const DIRECT_IO: u32 = 1 << 0;
    pub const KEEP_CACHE: u32 = 1 << 1;
    pub const NONSEEKABLE: u32 = 1 << 2;
    pub const STREAM: u32 = 1 << 4;
    pub const NOFLUSH: u32 = 1 << 5;
}

/// `FATTR_*`: which fields a `FUSE_SETATTR` sets.
pub(crate) mod fattr {
    pub const MODE: u32 = 1 << 0;
    pub const UID: u32 = 1 << 1;
    pub const GID: u32 = 1 << 2;
    pub const SIZE: u32 = 1 << 3;
    pub const ATIME: u32 = 1 << 4;
    pub const MTIME: u32 = 1 << 5;
    pub const FH: u32 = 1 << 6;
    pub const ATIME_NOW: u32 = 1 << 7;
    pub const MTIME_NOW: u32 = 1 << 8;
}

/// Notification codes (`enum fuse_notify_code`), in the `error` field of a message with
/// `unique` 0.
mod notify {
    pub const POLL: i32 = 1;
    pub const INVAL_INODE: i32 = 2;
    pub const INVAL_ENTRY: i32 = 3;
    pub const STORE: i32 = 4;
    pub const RETRIEVE: i32 = 5;
    pub const DELETE: i32 = 6;
}

// ---- Wire format ----

/// The arguments of a request, built field by field in the protocol's little-endian layout.
#[derive(Default)]
pub(crate) struct Args(pub Vec<u8>);

impl Args {
    pub fn u32(mut self, v: u32) -> Args {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(mut self, v: u64) -> Args {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(mut self, b: &[u8]) -> Args {
        self.0.extend_from_slice(b);
        self
    }

    /// A name, NUL-terminated.
    pub fn name(mut self, b: &[u8]) -> Args {
        self.0.extend_from_slice(b);
        self.0.push(0);
        self
    }
}

/// Reads a reply's fields in order; a reply too short for them is EIO.
pub(crate) struct Fields<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    pub fn new(b: &'a [u8]) -> Fields<'a> {
        Fields { b, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Errno> {
        let s = self.b.get(self.at..self.at + n).ok_or(Errno::EIO)?;
        self.at += n;
        Ok(s)
    }

    pub fn u16(&mut self) -> Result<u16, Errno> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, Errno> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, Errno> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    /// What is left unread.
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.at.min(self.b.len())..]
    }
}

/// A node's attributes (`struct fuse_attr`), with owners as kernel IDs.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Attr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u64,
    pub blksize: u32,
}

impl Attr {
    /// Parses a `struct fuse_attr` (88 bytes), mapping its owners from the connection's user
    /// namespace (unmapped ones become the overflow IDs, as `make_kuid` gives an invalid ID that
    /// shows as them). A type Linux does not know is EIO (`fuse_invalid_attr`).
    fn parse(f: &mut Fields<'_>, ns: &UserNs) -> Result<Attr, Errno> {
        let (ino, size, blocks) = (f.u64()?, f.u64()?, f.u64()?);
        let (atime, mtime, ctime) = (f.u64()?, f.u64()?, f.u64()?);
        let (an, mn, cn) = (f.u32()?, f.u32()?, f.u32()?);
        let (mode, nlink, uid, gid, rdev, blksize) =
            (f.u32()?, f.u32()?, f.u32()?, f.u32()?, f.u32()?, f.u32()?);
        let _flags = f.u32()?;
        if !valid_type(mode) || an >= 1_000_000_000 || mn >= 1_000_000_000 {
            return Err(Errno::EIO);
        }
        let ns_time = |s: u64, n: u32| (s as i64).saturating_mul(1_000_000_000) + i64::from(n);
        Ok(Attr {
            ino,
            size,
            blocks,
            atime_ns: ns_time(atime, an),
            mtime_ns: ns_time(mtime, mn),
            ctime_ns: ns_time(ctime, cn),
            mode,
            nlink,
            uid: ns
                .uid_map
                .borrow()
                .down(uid)
                .unwrap_or(crate::cred::OVERFLOW_ID),
            gid: ns
                .gid_map
                .borrow()
                .down(gid)
                .unwrap_or(crate::cred::OVERFLOW_ID),
            rdev: u64::from(rdev),
            blksize,
        })
    }

    /// As the store's [`Stat`] (for stat and permission checks).
    pub fn stat(&self) -> Stat {
        Stat {
            ino: self.ino,
            mode: self.mode,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            size: self.size,
            atime_ns: self.atime_ns,
            mtime_ns: self.mtime_ns,
            ctime_ns: self.ctime_ns,
            blocks: Some(self.blocks),
            ..Stat::default()
        }
    }
}

/// Whether `mode` has a file type Linux accepts (`fuse_valid_type`).
fn valid_type(mode: u32) -> bool {
    matches!(
        mode & mode::S_IFMT,
        mode::S_IFREG
            | mode::S_IFDIR
            | mode::S_IFLNK
            | mode::S_IFCHR
            | mode::S_IFBLK
            | mode::S_IFIFO
            | mode::S_IFSOCK
    )
}

/// How long a validity the daemon gave (seconds and nanoseconds) lasts from now; None when it has
/// already run out. Huge values are clipped so the deadline can be represented.
fn deadline(secs: u64, nsecs: u32) -> Option<Instant> {
    let d = Duration::new(secs.min(1 << 32), nsecs.min(999_999_999));
    if d.is_zero() {
        return None;
    }
    Instant::now().checked_add(d)
}

// ---- Mount options ----

/// The options of a FUSE mount (6.1's `fuse_parse_param`).
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    pub fd: Option<i32>,
    pub rootmode: Option<u32>,
    /// The mounter's and its group, as kernel IDs (only they may use the mount without
    /// `allow_other`).
    pub user_id: Option<u32>,
    pub group_id: Option<u32>,
    pub default_permissions: bool,
    pub allow_other: bool,
    /// `max_read`; u32::MAX when not given.
    pub max_read: u32,
    pub subtype: Option<Vec<u8>>,
}

impl Options {
    /// Parses mount(2)'s data with the mounter's credentials (user and group IDs are in its user
    /// namespace): an unknown option, a bad number, an invalid `rootmode`, an unmapped ID, two
    /// subtypes or `blksize` (fuseblk only) is EINVAL. The superblock flags the VFS takes from the
    /// data (`ro`, `rw`, `sync`, `dirsync`, `mand`, `lazytime`) are skipped.
    pub fn parse(data: &[u8], cred: &Cred) -> Result<Options, Errno> {
        let mut o = Options {
            max_read: u32::MAX,
            ..Options::default()
        };
        for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
            let (key, value) = match opt.iter().position(|&b| b == b'=') {
                Some(i) => (&opt[..i], Some(&opt[i + 1..])),
                None => (opt, None),
            };
            let num = |radix: u32| -> Result<u32, Errno> {
                let v = value.ok_or(Errno::EINVAL)?;
                let s = std::str::from_utf8(v).map_err(|_| Errno::EINVAL)?;
                u32::from_str_radix(s, radix).map_err(|_| Errno::EINVAL)
            };
            match key {
                b"ro" | b"rw" | b"sync" | b"async" | b"dirsync" | b"mand" | b"nomand"
                | b"lazytime" | b"nolazytime"
                    if value.is_none() => {}
                b"source" => {
                    value.ok_or(Errno::EINVAL)?;
                }
                b"subtype" => {
                    if o.subtype.is_some() {
                        return Err(Errno::EINVAL);
                    }
                    o.subtype = Some(value.ok_or(Errno::EINVAL)?.to_vec());
                }
                b"fd" => o.fd = Some(num(10)? as i32),
                b"rootmode" => {
                    let m = num(8)?;
                    if !valid_type(m) {
                        return Err(Errno::EINVAL);
                    }
                    o.rootmode = Some(m);
                }
                b"user_id" => o.user_id = Some(cred.uid_in(num(10)?).ok_or(Errno::EINVAL)?),
                b"group_id" => o.group_id = Some(cred.gid_in(num(10)?).ok_or(Errno::EINVAL)?),
                b"default_permissions" if value.is_none() => o.default_permissions = true,
                b"allow_other" if value.is_none() => o.allow_other = true,
                b"max_read" => o.max_read = num(10)?,
                _ => return Err(Errno::EINVAL),
            }
        }
        Ok(o)
    }

    /// The superblock options mountinfo shows (6.1's `fuse_show_options`), IDs translated through
    /// the connection's user namespace.
    pub fn show(&self, ns: &UserNs) -> String {
        let id = |m: &crate::cred::IdMap, k: Option<u32>| {
            m.up(k.unwrap_or(0)).unwrap_or(crate::cred::OVERFLOW_ID)
        };
        let mut s = format!(
            ",user_id={},group_id={}",
            id(&ns.uid_map.borrow(), self.user_id),
            id(&ns.gid_map.borrow(), self.group_id)
        );
        if self.default_permissions {
            s.push_str(",default_permissions");
        }
        if self.allow_other {
            s.push_str(",allow_other");
        }
        if self.max_read != u32::MAX {
            s.push_str(&format!(",max_read={}", self.max_read.max(PAGE)));
        }
        s
    }
}

// ---- Connections ----

/// One FUSE connection (Linux's `struct fuse_conn` with its input queue): the instance's options,
/// what INIT negotiated, and the requests between the kernel and the daemon.
pub(crate) struct Conn {
    /// The instance's device number.
    pub dev: u64,
    pub opts: Options,
    /// The mounter's user and pid namespaces (`fc->user_ns`, `fc->pid_ns`): IDs and pids in
    /// requests and replies are in them.
    user_ns: Rc<UserNs>,
    pid_ns: Rc<crate::pidns::PidNs>,
    /// INIT: not answered yet, answered and accepted, or refused (`conn_error`: every request is
    /// then ECONNREFUSED).
    state: InitState,
    /// Aborted (`!fc->connected`): unmounted, or no device file is left.
    pub aborted: bool,
    /// What INIT negotiated: the daemon's minor version and the flags it accepted.
    pub minor: u32,
    pub flags: u32,
    /// The most data one write and one read request carry.
    pub max_write: u32,
    pub max_read: u32,
    /// Operations the daemon answered ENOSYS (Linux's `no_*` flags), not asked again.
    pub no: u64,
    /// Device files attached to the connection: the last one closing aborts it.
    devs: usize,
    next_unique: u64,
    /// Requests not yet read by the daemon, in order.
    pending: VecDeque<u64>,
    /// Interrupts to send, before any other request (the unique of the request each interrupts).
    interrupts: VecDeque<u64>,
    requests: HashMap<u64, Req>,
    /// Lookups to return (`FUSE_FORGET`): node id and count ([`Fuses::evict`]).
    forgets: VecDeque<(u64, u64)>,
    /// How many forgets may still go before a pending request (6.1's `forget_batch`).
    forget_batch: i32,
    /// Open handles of each node id ([`Handle`]): such nodes are never forgotten.
    opens: HashMap<u64, u32>,
    /// Node ids marked for prompt forgetting: either kept at `drop_caches` only for a release in
    /// flight, or whose last link was removed through the mount (`unlink`, `rmdir`, overwriting
    /// `rename`). Each is forgotten in the first sweep once nothing keeps it ([`Fuses::evict`]),
    /// without waiting for [`NODES_MAX`].
    doomed: HashSet<u64>,
    /// Serializes cross-directory directory renames on this instance (Linux's
    /// `s_vfs_rename_mutex`), preventing concurrent moves from forming a directory cycle.
    pub rename_busy: bool,
    /// The in-process shared-storage server, when no guest daemon serves this connection.
    host: Option<Arc<host::Host>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitState {
    Waiting,
    Ready,
    Refused,
}

/// Bits of [`Conn::no`]: operations the daemon does not implement.
pub(crate) mod no {
    pub const OPEN: u64 = 1 << 0;
    pub const OPENDIR: u64 = 1 << 1;
    pub const FLUSH: u64 = 1 << 2;
    pub const ACCESS: u64 = 1 << 3;
    pub const CREATE: u64 = 1 << 4;
    pub const FSYNC: u64 = 1 << 5;
    pub const FSYNCDIR: u64 = 1 << 6;
    pub const GETXATTR: u64 = 1 << 7;
    pub const SETXATTR: u64 = 1 << 8;
    pub const LISTXATTR: u64 = 1 << 9;
    pub const REMOVEXATTR: u64 = 1 << 10;
    pub const INTERRUPT: u64 = 1 << 11;
    pub const LSEEK: u64 = 1 << 12;
    pub const FALLOCATE: u64 = 1 << 13;
    pub const RENAME2: u64 = 1 << 14;
}

/// In-flight periodic background writeback state: clears `FillPages::bg_busy` and wakes
/// foreground I/O waiters on completion, error, oversized-request drop, or connection abort.
struct BgWriteback {
    id: FuseId,
    pages: Rc<FillPages>,
    offset: u64,
    data: Vec<u8>,
}

impl Drop for BgWriteback {
    fn drop(&mut self) {
        self.pages.bg_busy.set(false);
        crate::kernel::request_wake_locks();
    }
}

/// One request (Linux's `struct fuse_req`).
struct Req {
    /// The whole message, header included.
    message: Vec<u8>,
    state: ReqState,
    /// Nobody waits for the reply (RELEASE, INIT, periodic writeback): it is dropped, or handled
    /// in `dev_write` when the reply arrives.
    background: bool,
    /// Waited for even by a killed caller (6.1's `FR_FORCE`: FLUSH).
    force: bool,
    /// An interrupt was queued for it.
    interrupted: bool,
    /// Present for periodic background `FUSE_WRITE` requests.
    writeback: Option<BgWriteback>,
}

enum ReqState {
    /// Waiting to be read by the daemon (`FR_PENDING`).
    Pending,
    /// Read by the daemon, waiting for its reply (`FR_SENT`).
    Sent,
    /// Answered: the reply's arguments, or the error.
    Done(Result<Vec<u8>, Errno>),
}

/// The wake object of a connection's readers (daemon threads reading the device, poll on it).
fn readers(conn: &RefCell<Conn>) -> wake::Object {
    wake::of(conn)
}

const ANSWER_OFFSET: usize = 1;

/// The wake object of the threads waiting for answers (and for INIT): an address inside the
/// connection, different from [`readers`].
fn answers(conn: &RefCell<Conn>) -> wake::Object {
    readers(conn) + ANSWER_OFFSET
}

fn wake_connection(readers: wake::Object) {
    request_wake_object(readers);
    request_wake_object(readers + ANSWER_OFFSET);
}

impl Conn {
    /// A connection for a new instance with device number `dev`, mounted by a process with
    /// credentials `cred` in pid namespace `pid_ns`.
    pub fn new(dev: u64, opts: Options, cred: &Cred, pid_ns: Rc<crate::pidns::PidNs>) -> Conn {
        let max_read = opts.max_read;
        Conn {
            dev,
            opts,
            user_ns: cred.user_ns.clone(),
            pid_ns,
            state: InitState::Waiting,
            aborted: false,
            minor: 0,
            flags: 0,
            max_write: PAGE,
            max_read: max_read.clamp(PAGE, DEFAULT_MAX_PAGES * PAGE),
            no: 0,
            devs: 0,
            next_unique: 2,
            pending: VecDeque::new(),
            interrupts: VecDeque::new(),
            requests: HashMap::new(),
            forgets: VecDeque::new(),
            forget_batch: 16,
            opens: HashMap::new(),
            doomed: HashSet::new(),
            rename_busy: false,
            host: None,
        }
    }

    /// An already initialized connection to host shared storage; opening its root is lazy.
    pub fn shared_storage(
        dev: u64,
        path: &std::path::Path,
        cred: &Cred,
        pid_ns: Rc<crate::pidns::PidNs>,
    ) -> Result<Conn, Errno> {
        let host = Arc::new(host::Host::new(path)?);
        let opts = Options {
            rootmode: Some(mode::S_IFDIR | 0o777),
            user_id: Some(0),
            group_id: Some(0),
            allow_other: true,
            max_read: DEFAULT_MAX_PAGES * PAGE,
            subtype: Some(b"shared_storage".to_vec()),
            ..Options::default()
        };
        let mut c = Conn::new(dev, opts, cred, pid_ns);
        c.state = InitState::Ready;
        c.minor = KERNEL_MINOR;
        c.flags = init::ATOMIC_O_TRUNC | init::BIG_WRITES;
        c.max_write = DEFAULT_MAX_PAGES * PAGE;
        c.host = Some(host);
        Ok(c)
    }

    /// The user namespace IDs in requests and replies are in.
    pub fn user_ns(&self) -> &Rc<UserNs> {
        &self.user_ns
    }

    /// Whether a process with credentials `cred` may use the mount (6.1's
    /// `fuse_allow_current_process`): with `allow_other` anyone in the mounter's user namespace
    /// or one below it; otherwise only a process whose real, effective and saved user and group
    /// IDs are all the mounter's (root included).
    pub fn allows(&self, cred: &Cred) -> bool {
        if self.opts.allow_other {
            let mut ns = Some(cred.user_ns.clone());
            while let Some(n) = ns {
                if n.id == self.user_ns.id {
                    return true;
                }
                ns = n.parent.clone();
            }
            return false;
        }
        let (u, g) = (self.opts.user_id, self.opts.group_id);
        [cred.euid, cred.suid, cred.ruid]
            .iter()
            .all(|&i| Some(i) == u)
            && [cred.egid, cred.sgid, cred.rgid]
                .iter()
                .all(|&i| Some(i) == g)
    }

    /// Queues a request: `opcode` on `nodeid` by `caller` (or with zero IDs) with arguments
    /// `args`; returns its unique.
    fn queue(
        &mut self,
        opcode: u32,
        nodeid: u64,
        caller: Option<(u32, u32, Tid)>,
        args: &[u8],
        (background, force): (bool, bool),
    ) -> u64 {
        let unique = self.next_unique;
        self.next_unique += 2;
        let (uid, gid, pid) = match caller {
            Some((uid, gid, tid)) => (
                self.user_ns
                    .uid_map
                    .borrow()
                    .up(uid)
                    .unwrap_or(crate::cred::OVERFLOW_ID),
                self.user_ns
                    .gid_map
                    .borrow()
                    .up(gid)
                    .unwrap_or(crate::cred::OVERFLOW_ID),
                self.pid_ns.vnr(tid).unwrap_or(0) as u32,
            ),
            None => (0, 0, 0),
        };
        let len = (IN_HEADER + args.len()) as u32;
        let mut message = Args::default()
            .u32(len)
            .u32(opcode)
            .u64(unique)
            .u64(nodeid)
            .u32(uid)
            .u32(gid)
            .u32(pid)
            .u32(0)
            .0;
        message.extend_from_slice(args);
        self.requests.insert(
            unique,
            Req {
                message,
                state: ReqState::Pending,
                background,
                force,
                interrupted: false,
                writeback: None,
            },
        );
        self.pending.push_back(unique);
        unique
    }

    /// Queues a periodic background `FUSE_WRITE` with `FUSE_WRITE_CACHE` for a dirty mapped range.
    fn queue_writeback(&mut self, nodeid: u64, fh: u64, flags: u32, wb: BgWriteback) -> u64 {
        let args = Args::default()
            .u64(fh)
            .u64(wb.offset)
            .u32(wb.data.len() as u32)
            .u32(1) // FUSE_WRITE_CACHE
            .u64(0)
            .u32(flags)
            .u32(0)
            .bytes(&wb.data);
        let unique = self.queue(op::WRITE, nodeid, None, &args.0, (true, false));
        if let Some(r) = self.requests.get_mut(&unique) {
            r.writeback = Some(wb);
        }
        unique
    }

    /// Aborts the connection (6.1's `fuse_abort_conn`): every request still unanswered ends
    /// with ECONNABORTED, and every waiter, reader and poller is woken.
    pub fn abort(&mut self) {
        if self.aborted {
            return;
        }
        self.aborted = true;
        self.pending.clear();
        self.interrupts.clear();
        self.forgets.clear();
        self.requests.retain(|_, r| {
            if r.background {
                return false;
            }
            if !matches!(r.state, ReqState::Done(_)) {
                r.state = ReqState::Done(Err(Errno::ECONNABORTED));
            }
            true
        });
        wake_connection(wake::of_value(self));
        crate::kernel::request_wake_locks();
    }

    /// The next forget message for a read of `len` bytes (6.1's `fuse_read_forget`): one
    /// `FUSE_FORGET`, or a `FUSE_BATCH_FORGET` of as many as fit when several are queued and the
    /// daemon speaks 7.16 or later. Neither is answered.
    fn read_forget(&mut self, len: usize) -> Vec<u8> {
        let unique = self.next_unique;
        self.next_unique += 2;
        if self.minor < 16 || self.forgets.len() == 1 {
            let (nodeid, nlookup) = self.forgets.pop_front().unwrap();
            return Args::default()
                .u32((IN_HEADER + 8) as u32)
                .u32(op::FORGET)
                .u64(unique)
                .u64(nodeid)
                .u64(0)
                .u64(0)
                .u64(nlookup)
                .0;
        }
        let n = self.forgets.len().min((len - IN_HEADER - 8) / 16);
        let mut message = Args::default()
            .u32((IN_HEADER + 8 + n * 16) as u32)
            .u32(op::BATCH_FORGET)
            .u64(unique)
            .u64(0)
            .u64(0)
            .u64(0)
            .u32(n as u32)
            .u32(0);
        for (nodeid, nlookup) in self.forgets.drain(..n) {
            message = message.u64(nodeid).u64(nlookup);
        }
        message.0
    }

    /// The node ids requests still unanswered are about: the node of each, and the other
    /// directory of a rename or the file of a link (their callers hold those nodes until the
    /// reply comes).
    fn busy_nodeids(&self) -> HashSet<u64> {
        let mut ids = HashSet::new();
        for r in self.requests.values() {
            let (nodeid, other) = req_nodeids(&r.message);
            ids.insert(nodeid);
            ids.extend(other);
        }
        ids
    }

    /// Schedules a sweep when a finished request referenced a doomed node that has no open
    /// handles left, so an unlinked or `drop_caches`-doomed node kept only by that request is
    /// forgotten promptly without triggering sweeps on I/O of an open unlinked file.
    fn note_request_done(&self, message: &[u8]) {
        if self.doomed.is_empty() {
            return;
        }
        let (nodeid, other) = req_nodeids(message);
        if [Some(nodeid), other]
            .into_iter()
            .flatten()
            .any(|id| self.doomed.contains(&id) && !self.opens.contains_key(&id))
        {
            SWEEP.store(true, Ordering::Relaxed);
        }
    }

    /// The node ids of the releases still unanswered that no other request is about.
    fn releasing_only(&self) -> HashSet<u64> {
        let mut releasing = HashSet::new();
        let mut others = HashSet::new();
        for r in self.requests.values() {
            let opcode = u32::from_le_bytes(r.message[4..8].try_into().unwrap());
            let (nodeid, other) = req_nodeids(&r.message);
            if matches!(opcode, op::RELEASE | op::RELEASEDIR) {
                releasing.insert(nodeid);
            } else {
                others.insert(nodeid);
                others.extend(other);
            }
        }
        &releasing - &others
    }

    /// The error a new request gets before it is queued: ENOTCONN once aborted, ECONNREFUSED
    /// when INIT was refused.
    fn refusal(&self) -> Option<Errno> {
        if self.aborted {
            Some(Errno::ENOTCONN)
        } else if self.state == InitState::Refused {
            Some(Errno::ECONNREFUSED)
        } else {
            None
        }
    }

    /// Completes a sent request; an abort that won the race keeps its error. Returns whether
    /// callers waiting for answers need waking, and the periodic writeback the reply ends, for
    /// [`finish_bg_writeback`] once the connection is no longer borrowed.
    fn answer(
        &mut self,
        unique: u64,
        reply: Result<Vec<u8>, Errno>,
    ) -> (bool, Option<(BgWriteback, Result<Vec<u8>, Errno>)>) {
        let (opcode, background) = match self.requests.get(&unique) {
            Some(r) if matches!(r.state, ReqState::Sent) => (
                u32::from_le_bytes(r.message[4..8].try_into().unwrap()),
                r.background,
            ),
            _ => return (false, None),
        };
        if reply == Err(Errno::ENOSYS) {
            self.no |= match opcode {
                op::OPEN => no::OPEN,
                op::OPENDIR => no::OPENDIR,
                op::FLUSH => no::FLUSH,
                op::ACCESS => no::ACCESS,
                op::CREATE => no::CREATE,
                op::FSYNC => no::FSYNC,
                op::FSYNCDIR => no::FSYNCDIR,
                op::GETXATTR => no::GETXATTR,
                op::SETXATTR => no::SETXATTR,
                op::LISTXATTR => no::LISTXATTR,
                op::REMOVEXATTR => no::REMOVEXATTR,
                op::LSEEK => no::LSEEK,
                op::FALLOCATE => no::FALLOCATE,
                op::RENAME2 => no::RENAME2,
                _ => 0,
            };
        }
        if background {
            // A release for a doomed node (from drop_caches or unlink): once no open handle remains,
            // forget it at the end of this syscall.
            let removed = self.requests.remove(&unique);
            if let Some(r) = &removed
                && matches!(opcode, op::RELEASE | op::RELEASEDIR)
            {
                self.note_request_done(&r.message);
            }
            if opcode == op::INIT {
                init_reply(self, reply);
                return (true, None);
            }
            let writeback = removed.and_then(|r| r.writeback).map(|wb| (wb, reply));
            return (false, writeback);
        }
        self.requests.get_mut(&unique).unwrap().state = ReqState::Done(reply);
        (true, None)
    }
}

/// Decodes the primary node id from a FUSE request header and, for `RENAME`/`RENAME2`/`LINK`,
/// the secondary node id from the start of the request body.
fn req_nodeids(message: &[u8]) -> (u64, Option<u64>) {
    let opcode = u32::from_le_bytes(message[4..8].try_into().unwrap());
    let nodeid = u64::from_le_bytes(message[16..24].try_into().unwrap());
    let other = (matches!(opcode, op::RENAME | op::RENAME2 | op::LINK)
        && message.len() >= IN_HEADER + 8)
        .then(|| u64::from_le_bytes(message[IN_HEADER..IN_HEADER + 8].try_into().unwrap()));
    (nodeid, other)
}

/// Queues `FUSE_INIT` on a new connection (6.1's `fuse_send_init`); nobody waits for it, and its
/// reply is taken by [`init_reply`].
pub(crate) fn send_init(conn: &Rc<RefCell<Conn>>) {
    let args = Args::default()
        .u32(KERNEL_MAJOR)
        .u32(KERNEL_MINOR)
        .u32(DEFAULT_MAX_PAGES * PAGE)
        .u32(init::OFFERED)
        .u32(0)
        .bytes(&[0; 44]);
    conn.borrow_mut()
        .queue(op::INIT, 0, None, &args.0, (true, false));
    request_wake_object(readers(conn));
}

/// The INIT reply arrived (6.1's `process_init_reply`): an error or another major version
/// refuses the connection; otherwise the accepted flags, the write size and the pages per request
/// are taken. Requests waiting for INIT go on.
fn init_reply(c: &mut Conn, reply: Result<Vec<u8>, Errno>) {
    let parsed = reply.and_then(|r| {
        let mut f = Fields::new(&r);
        let (major, minor) = (f.u32()?, f.u32()?);
        if major != KERNEL_MAJOR {
            return Err(Errno::EPROTO);
        }
        // Old daemons send a shorter reply; what is missing counts as 0
        let mut tail = r.get(8..).unwrap_or_default().to_vec();
        tail.resize(56, 0);
        let mut f = Fields::new(&tail);
        let (_readahead, flags) = (f.u32()?, f.u32()?);
        let (_max_background, _congestion) = (f.u16()?, f.u16()?);
        let (max_write, _time_gran, max_pages) = (f.u32()?, f.u32()?, f.u16()?);
        Ok((minor, flags, max_write, max_pages))
    });
    match parsed {
        Ok((minor, flags, max_write, max_pages)) => {
            let flags = flags & init::OFFERED;
            let pages = if flags & init::MAX_PAGES != 0 {
                u32::from(max_pages).clamp(1, MAX_MAX_PAGES)
            } else {
                DEFAULT_MAX_PAGES
            };
            c.minor = minor;
            c.flags = flags;
            c.max_write = max_write.max(PAGE).min(pages * PAGE);
            c.max_read = c.opts.max_read.min(pages * PAGE).max(PAGE);
            c.state = InitState::Ready;
        }
        Err(_) => c.state = InitState::Refused,
    }
}

/// Whether INIT accepted `O_TRUNC` in open requests (`FUSE_ATOMIC_O_TRUNC`).
pub(crate) fn atomic_o_trunc(c: &Conn) -> bool {
    c.flags & init::ATOMIC_O_TRUNC != 0
}

/// Whether the daemon applies the umask itself (`FUSE_DONT_MASK`): creations then send the mode
/// unmasked, with the umask beside it.
pub(crate) fn dont_mask(c: &Conn) -> bool {
    c.flags & init::DONT_MASK != 0
}

// ---- Making requests ----

/// Makes request `opcode` on node id `nodeid` with arguments `args` and waits for its reply,
/// with the BKL released: the reply's arguments, or the daemon's error (6.1's
/// `fuse_simple_request`). The caller holds no borrow.
pub(crate) fn call(
    cx: &mut Cx<'_>,
    conn: &Rc<RefCell<Conn>>,
    opcode: u32,
    nodeid: u64,
    args: &[u8],
) -> Result<Vec<u8>, Errno> {
    let cred = cx.cred();
    call_as(cx, &cred, conn, (opcode, nodeid), args)
}

/// [`call`] on behalf of credentials `cred` (the header's uid and gid are their filesystem IDs):
/// access(2) asks with the real IDs, as Linux overrides the credentials for it.
pub(crate) fn call_as(
    cx: &mut Cx<'_>,
    cred: &Cred,
    conn: &Rc<RefCell<Conn>>,
    (opcode, nodeid): (u32, u64),
    args: &[u8],
) -> Result<Vec<u8>, Errno> {
    request(cx, cred, conn, (opcode, nodeid), args, false)
}

/// [`call`] for a request a killed caller still waits for (6.1's `FR_FORCE`: FLUSH, which a process
/// killed while closing or exiting still sends and waits for, unless the system is stopping).
pub(crate) fn call_forced(
    cx: &mut Cx<'_>,
    conn: &Rc<RefCell<Conn>>,
    opcode: u32,
    nodeid: u64,
    args: &[u8],
) -> Result<Vec<u8>, Errno> {
    let cred = cx.cred();
    request(cx, &cred, conn, (opcode, nodeid), args, true)
}

fn request(
    cx: &mut Cx<'_>,
    cred: &Cred,
    conn: &Rc<RefCell<Conn>>,
    (opcode, nodeid): (u32, u64),
    args: &[u8],
    force: bool,
) -> Result<Vec<u8>, Errno> {
    wait_init(cx, conn, force)?;
    let caller = (cred.fsuid, cred.fsgid, cx.tid());
    let unique = conn
        .borrow_mut()
        .queue(opcode, nodeid, Some(caller), args, (false, force));
    let host = conn.borrow().host.clone();
    if let Some(host) = host {
        let (messages, forgets) = {
            let mut c = conn.borrow_mut();
            let pending: Vec<_> = c.pending.drain(..).collect();
            let messages = pending
                .into_iter()
                .filter_map(|u| {
                    let r = c.requests.get_mut(&u)?;
                    r.state = ReqState::Sent;
                    Some((u, r.message.clone()))
                })
                .collect();
            (messages, c.forgets.drain(..).collect())
        };
        // Sent requests remain in Conn: cache eviction must keep their nodes while unlocked.
        let replies = cx.unlocked(move || host.dispatch(messages, forgets));
        let mut wake = false;
        let mut writebacks = Vec::new();
        {
            let mut c = conn.borrow_mut();
            for (u, reply) in replies {
                let (w, writeback) = c.answer(u, reply);
                wake |= w;
                writebacks.extend(writeback);
            }
        }
        if wake {
            request_wake_object(answers(conn));
        }
        if !writebacks.is_empty()
            && let Ok(vfs) = cx.vfs()
        {
            for (wb, reply) in writebacks {
                finish_bg_writeback(&vfs, wb, reply);
            }
        }
    } else {
        request_wake_object(readers(conn));
    }
    wait_answer(cx, conn, unique)
}

/// Queues request `opcode` with nobody waiting for the reply (RELEASE, RELEASEDIR): for when the
/// last reference to an open file goes, which cannot wait. Nothing is sent on an aborted
/// connection.
pub(crate) fn background(conn: &Rc<RefCell<Conn>>, opcode: u32, nodeid: u64, args: &[u8]) {
    let Ok(mut c) = conn.try_borrow_mut() else {
        return;
    };
    if c.refusal().is_some() {
        return;
    }
    c.queue(opcode, nodeid, None, args, (true, false));
    drop(c);
    request_wake_object(readers(conn));
}

/// Waits until INIT has been answered (6.1's `fuse_wait_initialized`; only a fatal signal stops
/// it, and for a forced request only the system stopping).
fn wait_init(cx: &mut Cx<'_>, conn: &Rc<RefCell<Conn>>, force: bool) -> Result<(), Errno> {
    loop {
        {
            let c = conn.borrow();
            if let Some(e) = c.refusal() {
                return Err(e);
            }
            if c.state == InitState::Ready {
                return Ok(());
            }
        }
        if cx.task.killed.get() && (!force || cx.kr().stopping) {
            return Err(Errno::EINTR);
        }
        cx.wait_object(answers(conn))?;
    }
}

/// Waits for the reply to request `unique` (6.1's `request_wait_answer`): the first signal while
/// the daemon holds the request queues `FUSE_INTERRUPT` for it, and the wait goes on; a fatal
/// signal before the daemon has read it takes it back (EINTR), unless it is forced. Once read, or
/// when forced, it is waited for until answered or the connection is aborted, unless the whole
/// system is stopping.
fn wait_answer(cx: &mut Cx<'_>, conn: &Rc<RefCell<Conn>>, unique: u64) -> Result<Vec<u8>, Errno> {
    loop {
        {
            let killed = cx.task.killed.get();
            let mut guard = conn.borrow_mut();
            let c = &mut *guard;
            let Some(r) = c.requests.get_mut(&unique) else {
                return Err(Errno::ECONNABORTED);
            };
            // The exit path sets killed before issuing forced I/O and still needs its reply.
            let interruptible = !(r.interrupted || killed && r.force);
            match r.state {
                ReqState::Done(_) => {
                    let Some(Req {
                        message,
                        state: ReqState::Done(reply),
                        ..
                    }) = c.requests.remove(&unique)
                    else {
                        unreachable!()
                    };
                    c.note_request_done(&message);
                    return reply;
                }
                ReqState::Pending if killed && !r.force => {
                    if let Some(r) = c.requests.remove(&unique) {
                        c.note_request_done(&r.message);
                    }
                    c.pending.retain(|&u| u != unique);
                    return Err(Errno::EINTR);
                }
                ReqState::Pending | ReqState::Sent if killed && cx.kr().stopping => {
                    r.background = true;
                    return Err(Errno::EINTR);
                }
                ReqState::Sent
                    if interruptible && c.no & no::INTERRUPT == 0 && cx.interrupted() =>
                {
                    r.interrupted = true;
                    c.interrupts.push_back(unique);
                    drop(guard);
                    request_wake_object(readers(conn));
                }
                // Not read yet: the interrupt is sent when it is (FR_INTERRUPTED)
                ReqState::Pending if interruptible && cx.interrupted() => r.interrupted = true,
                _ => {}
            }
        }
        cx.wait_object(answers(conn))?;
    }
}

// ---- The device ----

/// An open file of `/dev/fuse` (Linux's `struct fuse_dev`): attached to a connection by the mount
/// that names it (or by `FUSE_DEV_IOC_CLONE`); until then reads and writes are EPERM. The last
/// one of a connection to go aborts it.
pub(crate) struct DevFile {
    pub conn: Option<Rc<RefCell<Conn>>>,
    /// The device node it was opened through (fstat, `/proc/<pid>/fd`).
    pub ino: Option<Ino>,
    /// The opener's user namespace: a mount must be made in the same one (6.1's `fuse_fill_super`
    /// compares `f_cred->user_ns`).
    pub opener_ns: Rc<UserNs>,
}

impl DevFile {
    pub fn new(cred: &Cred, ino: Ino) -> DevFile {
        DevFile {
            conn: None,
            ino: Some(ino),
            opener_ns: cred.user_ns.clone(),
        }
    }

    /// Attaches the connection (mount, or cloning another device file's).
    pub fn attach(&mut self, conn: &Rc<RefCell<Conn>>) {
        conn.borrow_mut().devs += 1;
        self.conn = Some(conn.clone());
    }

    /// poll on the device (6.1's `fuse_dev_poll`): always writable, readable while a request
    /// waits, and an error once aborted or before a connection is attached.
    pub fn readiness(&self) -> i16 {
        const POLLIN: i16 = 1;
        const POLLOUT: i16 = 4;
        const POLLERR: i16 = 8;
        const POLLRDNORM: i16 = 0x40;
        const POLLWRNORM: i16 = 0x100;
        let Some(conn) = &self.conn else {
            return POLLERR;
        };
        let Ok(c) = conn.try_borrow() else {
            return POLLOUT | POLLWRNORM;
        };
        if c.aborted {
            return POLLERR;
        }
        let mut ev = POLLOUT | POLLWRNORM;
        let interrupt = c
            .interrupts
            .iter()
            .any(|u| matches!(c.requests.get(u).map(|r| &r.state), Some(ReqState::Sent)));
        if !c.pending.is_empty() || !c.forgets.is_empty() || interrupt {
            ev |= POLLIN | POLLRDNORM;
        }
        ev
    }

    /// The object poll and epoll wait on.
    pub fn object(&self) -> Option<wake::Object> {
        self.conn.as_deref().map(readers)
    }
}

impl Drop for DevFile {
    /// The last device file of a connection goes (6.1's `fuse_dev_release`): the connection is
    /// aborted, so the mount answers ENOTCONN from now on.
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else {
            return;
        };
        let Ok(mut c) = conn.try_borrow_mut() else {
            return;
        };
        c.devs = c.devs.saturating_sub(1);
        if c.devs == 0 {
            c.abort();
        }
    }
}

/// The connection a device file is attached to; EPERM before a mount attached one (6.1's
/// `fuse_get_dev`).
fn dev_conn(file: &crate::fd::FileRef) -> Result<Rc<RefCell<Conn>>, Errno> {
    match &file.borrow().kind {
        crate::fd::FileKind::FuseDev(d) => d.conn.clone().ok_or(Errno::EPERM),
        _ => Err(Errno::EINVAL),
    }
}

/// read(2) on the device (6.1's `fuse_dev_do_read`): takes the next interrupt or request, waiting
/// for one unless nonblocking. The buffer must hold at least 8 KiB and a whole write request
/// (EINVAL); a request that does not fit ends with EIO (E2BIG for SETXATTR) and the next one is
/// taken. A request whose caller was interrupted before it was read is followed by its
/// interrupt. An aborted connection is ENODEV.
pub(crate) fn dev_read(
    cx: &mut Cx<'_>,
    file: &crate::fd::FileRef,
    len: usize,
    nonblock: bool,
) -> Result<Vec<u8>, Errno> {
    let conn = dev_conn(file)?;
    {
        let c = conn.borrow();
        let min = MIN_READ_BUFFER.max(IN_HEADER + 40 + c.max_write as usize);
        if len < min {
            return Err(Errno::EINVAL);
        }
    }
    loop {
        {
            let mut guard = conn.borrow_mut();
            let c = &mut *guard;
            if c.aborted {
                return Err(Errno::ENODEV);
            }
            while let Some(unique) = c.interrupts.pop_front() {
                // Only for a request still held by the daemon
                if matches!(
                    c.requests.get(&unique).map(|r| &r.state),
                    Some(ReqState::Sent)
                ) {
                    let message = Args::default()
                        .u32((IN_HEADER + 8) as u32)
                        .u32(op::INTERRUPT)
                        .u64(unique | INT_REQ_BIT)
                        .u64(0)
                        .u64(0)
                        .u64(0)
                        .u64(unique)
                        .0;
                    return Ok(message);
                }
            }
            // Forgets go first while nothing is pending, else up to 16 between requests and then
            // 8 requests in a row (6.1's fuse_dev_do_read)
            if !c.forgets.is_empty() {
                if c.pending.is_empty() || {
                    c.forget_batch -= 1;
                    c.forget_batch >= 0
                } {
                    return Ok(c.read_forget(len));
                }
                if c.forget_batch <= -8 {
                    c.forget_batch = 16;
                }
            }
            let mut ended = false;
            while let Some(unique) = c.pending.pop_front() {
                let r = c.requests.get_mut(&unique).expect("pending request");
                // A request the buffer cannot hold ends with EIO (E2BIG for a SETXATTR, whose
                // value may be too large), and the read goes on with the next one
                if r.message.len() > len {
                    if r.background {
                        if let Some(r) = c.requests.remove(&unique) {
                            c.note_request_done(&r.message);
                        }
                        continue;
                    }
                    let opcode = u32::from_le_bytes(r.message[4..8].try_into().unwrap());
                    let e = if opcode == op::SETXATTR {
                        Errno::E2BIG
                    } else {
                        Errno::EIO
                    };
                    r.state = ReqState::Done(Err(e));
                    ended = true;
                    continue;
                }
                r.state = ReqState::Sent;
                let message = r.message.clone();
                // Its caller was interrupted while it waited to be read: the interrupt follows it
                if r.interrupted && c.no & no::INTERRUPT == 0 {
                    c.interrupts.push_back(unique);
                }
                if ended {
                    drop(guard);
                    request_wake_object(answers(&conn));
                }
                return Ok(message);
            }
            if ended {
                drop(guard);
                request_wake_object(answers(&conn));
                continue;
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(readers(&conn))?;
    }
}

/// write(2) on the device (6.1's `fuse_dev_do_write`): a reply or a notification. The header's
/// length must be the write's, an error must come alone and be a negative errno below 512
/// (EINVAL); a reply to no request the daemon holds is ENOENT. ENOSYS replies mark the operation
/// as not implemented ([`no`]); an interrupt answered with EAGAIN is queued again.
pub(crate) fn dev_write(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    file: &crate::fd::FileRef,
    data: &[u8],
) -> Result<usize, Errno> {
    let conn = dev_conn(file)?;
    if data.len() < OUT_HEADER {
        return Err(Errno::EINVAL);
    }
    let mut f = Fields::new(data);
    let (len, error, unique) = (f.u32()? as usize, f.u32()? as i32, f.u64()?);
    if len != data.len() {
        return Err(Errno::EINVAL);
    }
    let body = &data[OUT_HEADER..];
    if conn.borrow().aborted {
        return Err(Errno::ENOENT);
    }
    if unique == 0 {
        notification(cx, vfs, &conn, error, body)?;
        return Ok(len);
    }
    if error > 0 || error <= -512 || (error != 0 && !body.is_empty()) {
        return Err(Errno::EINVAL);
    }
    let mut c = conn.borrow_mut();
    // An interrupt's reply: only a header, for a request the daemon holds
    if unique & INT_REQ_BIT != 0 {
        let orig = unique & !INT_REQ_BIT;
        if !matches!(
            c.requests.get(&orig).map(|r| &r.state),
            Some(ReqState::Sent)
        ) {
            return Err(Errno::ENOENT);
        }
        if !body.is_empty() {
            return Err(Errno::EINVAL);
        }
        if error == -Errno::ENOSYS.0 {
            c.no |= no::INTERRUPT;
        } else if error == -Errno::EAGAIN.0 {
            c.interrupts.push_back(orig);
            drop(c);
            request_wake_object(readers(&conn));
        }
        return Ok(len);
    }
    if !matches!(
        c.requests.get(&unique).map(|r| &r.state),
        Some(ReqState::Sent)
    ) {
        return Err(Errno::ENOENT);
    }
    let reply = if error == 0 {
        Ok(body.to_vec())
    } else {
        Err(Errno(-error))
    };
    let (wake, writeback) = c.answer(unique, reply);
    drop(c);
    if wake {
        request_wake_object(answers(&conn));
    }
    if let Some((wb, reply)) = writeback {
        finish_bg_writeback(vfs, wb, reply);
    }
    Ok(len)
}

/// Ordinary FUSE mmap labels share their path allocation with the pinned open file. ELF
/// snapshots have separately allocated labels. This distinguishes a daemon's full-width inode
/// from an internal program key even when both numbers occur in the same address space.
pub(crate) fn mapped_paths(mm: &crate::mm::Mm) -> HashSet<*const u8> {
    let mut paths = HashSet::new();
    if mm.has_fills() {
        let mut files = Vec::new();
        mm.mapped_file_inos(&mut Vec::new(), &mut files);
        for file in files {
            if let Some(path) = &file.borrow().path {
                paths.insert(path.as_ptr());
            }
        }
    }
    paths
}

pub(crate) fn mapped_pages(vfs: &super::Vfs, id: FuseId) -> Option<Rc<FillPages>> {
    vfs.fuse().get(id)?.pages.upgrade()
}

fn for_each_mm(cx: &Cx<'_>, mut f: impl FnMut(&mut crate::mm::Mm) -> bool) {
    let mut seen = HashSet::new();
    for task in cx.kr().tasks.values() {
        let mm = task.res.borrow().mm.clone();
        if seen.insert(Rc::as_ptr(&mm)) {
            let mut mm = mm.borrow_mut();
            if f(&mut mm) {
                mm.sync(&cx.task.sync);
            }
        }
    }
}

/// Revoke all translations before marking the file pages stale. The daemon may still owe a
/// READ reply, so this runs under the BKL without acquiring the inode I/O lock.
fn invalidate_pages(cx: &Cx<'_>, pages: &Rc<FillPages>, lo: u64, hi: u64) {
    for_each_mm(cx, |mm| mm.invalidate_fill(pages, lo, hi));
    pages.invalidate(lo, hi);
}

/// Queue Tier 1 code-cache invalidation for executable mappings of `pages` overlapping `[lo, hi)`.
fn invalidate_code_pages(cx: &Cx<'_>, pages: &Rc<FillPages>, lo: u64, hi: u64) {
    for_each_mm(cx, |mm| mm.invalidate_fill_code(pages, lo, hi));
}

/// Processes the daemon's reply to a periodic background `FUSE_WRITE`, advancing the clean
/// baseline for acknowledged bytes and chaining the next dirty chunk if the node is still idle.
fn finish_bg_writeback(vfs: &super::Vfs, wb: BgWriteback, reply: Result<Vec<u8>, Errno>) {
    let id = wb.id;
    let acked = match reply {
        Ok(r) => Fields::new(&r)
            .u32()
            .ok()
            .map(|n| n as usize)
            .filter(|&n| n <= wb.data.len()),
        Err(_) => None,
    };
    let mut chain = false;
    if let Some(n) = acked {
        wb.pages.acknowledge(wb.offset, &wb.data[..n]);
        if let Ok(mut f) = vfs.fuse.try_borrow_mut() {
            f.stale(id);
        }
        chain = n == wb.data.len();
    }
    // Drops `wb`, clearing `FillPages::bg_busy` and waking any foreground `with_io` waiter.
    drop(wb);
    if chain {
        let _ = queue_next_bg_writeback(vfs, id);
    }
}

/// Queues the next dirty byte run for node `id` as a background `FUSE_WRITE` when no foreground
/// I/O or background writeback is in progress. Returns whether a request was queued.
fn queue_next_bg_writeback(vfs: &super::Vfs, id: FuseId) -> bool {
    let (conn, nodeid, pages, fh, flags) = {
        let Ok(mut f) = vfs.fuse.try_borrow_mut() else {
            return false;
        };
        let Some(n) = f.nodes.get_mut(&id) else {
            return false;
        };
        if n.io_busy {
            return false;
        }
        let Some(pages) = n.pages.upgrade() else {
            n.retry_writeback = None;
            return false;
        };
        if pages.bg_busy.get() || pages.size_stale.get() || !pages.has_tracked() {
            return false;
        }
        let Some(writer) = pages.writer() else {
            return false;
        };
        let (conn, nodeid, fh, flags) = {
            let Ok(file) = writer.source.try_borrow() else {
                return false;
            };
            match &file.kind {
                crate::fd::FileKind::Fuse(h) => (h.conn.clone(), h.nodeid, h.fh, h.flags),
                _ => return false,
            }
        };
        (conn, nodeid, pages, fh, flags)
    };
    let max_write = {
        let Ok(c) = conn.try_borrow() else {
            return false;
        };
        if c.aborted || c.state != InitState::Ready {
            return false;
        }
        c.max_write as usize
    };
    let mut next_run = None;
    for page in pages.tracked(0, u64::MAX) {
        let Ok(runs) = pages.dirty_runs(page) else {
            return false;
        };
        if let Some((at, mut data)) = runs.into_iter().next() {
            let len = (data.len() as u64)
                .min(pages.size().saturating_sub(at))
                .min(max_write as u64) as usize;
            if len != 0 {
                data.truncate(len);
                next_run = Some((at, data));
                break;
            }
        }
    }
    let Some((offset, data)) = next_run else {
        if let Ok(mut f) = vfs.fuse.try_borrow_mut()
            && let Some(n) = f.nodes.get_mut(&id)
        {
            n.retry_writeback = None;
        }
        return false;
    };
    let Ok(mut c) = conn.try_borrow_mut() else {
        return false;
    };
    if c.aborted || c.state != InitState::Ready {
        return false;
    }
    pages.bg_busy.set(true);
    let wb = BgWriteback {
        id,
        pages,
        offset,
        data,
    };
    c.queue_writeback(nodeid, fh, flags, wb);
    drop(c);
    request_wake_object(readers(&conn));
    true
}

/// Periodic dirty-page writeback for shared writable FUSE mappings (called from the timer thread
/// under the BKL; never blocks). Honours `/proc/sys/vm/dirty_writeback_centisecs` (default 500 =
/// 5 s; `<= 0` disables periodic writeback) and returns `None` when no writable shared FUSE
/// mapping exists so the timer thread stays idle.
pub(crate) fn flush_dirty(k: &crate::kernel::Kernel) -> Option<Instant> {
    let vfs = k.vfs.as_ref()?;
    let centisecs = k
        .sysctls
        .get(b"sys/vm/dirty_writeback_centisecs".as_slice())
        .copied()
        .unwrap_or(500);
    if centisecs <= 0 {
        if let Ok(mut f) = vfs.fuse.try_borrow_mut() {
            f.next_writeback = None;
        }
        return None;
    }
    let interval = Duration::from_millis((centisecs as u64).saturating_mul(10).max(10));
    let now = Instant::now();
    let (ids, due) = {
        let Ok(mut f) = vfs.fuse.try_borrow_mut() else {
            return Some(now + interval);
        };
        let Fuses {
            mapped,
            nodes,
            next_writeback,
            ..
        } = &mut *f;
        let mut active = Vec::new();
        mapped.retain(|&id| {
            let Some(n) = nodes.get(&id) else {
                return false;
            };
            let Some(p) = n.pages.upgrade() else {
                return false;
            };
            if n.retry_writeback.is_some() || (p.writer().is_some() && p.has_tracked()) {
                active.push(id);
            }
            true
        });
        if active.is_empty() {
            *next_writeback = None;
            return None;
        }
        let Some(target) = next_writeback.map(|due| due.min(now + interval)) else {
            let first = now + interval;
            *next_writeback = Some(first);
            return Some(first);
        };
        if now < target {
            *next_writeback = Some(target);
            return Some(target);
        }
        let next = now + interval;
        *next_writeback = Some(next);
        (active, next)
    };
    for id in ids {
        let _ = queue_next_bg_writeback(vfs, id);
    }
    Some(due)
}

/// Daemon notifications for cached attributes, directory entries and mapped file ranges.
fn notification(
    cx: &Cx<'_>,
    vfs: &super::Vfs,
    conn: &Rc<RefCell<Conn>>,
    code: i32,
    body: &[u8],
) -> Result<(), Errno> {
    let dev = conn.borrow().dev;
    let mut f = Fields::new(body);
    match code {
        notify::INVAL_INODE => {
            let nodeid = f.u64()?;
            let offset = f.u64()? as i64;
            let len = f.u64()? as i64;
            if !f.rest().is_empty() {
                return Err(Errno::EINVAL);
            }
            let pages = {
                let mut nodes = vfs.fuse_mut();
                let id = *nodes.by_nodeid.get(&(dev, nodeid)).ok_or(Errno::ENOENT)?;
                nodes.stale(id);
                nodes.node(id).pages.upgrade()
            };
            if let Some(pages) = pages
                && offset >= 0
            {
                use appine_engine::PAGE_SIZE;
                let lo = offset as u64 / PAGE_SIZE;
                let hi = if len <= 0 {
                    u64::MAX
                } else {
                    (offset as u64 + len as u64).div_ceil(PAGE_SIZE)
                };
                invalidate_pages(cx, &pages, lo, hi);
            }
            Ok(())
        }
        notify::INVAL_ENTRY | notify::DELETE => {
            let parent = f.u64()?;
            if code == notify::DELETE {
                f.u64()?;
            }
            let namelen = f.u32()? as usize;
            f.u32()?;
            let name = f.rest().get(..namelen).ok_or(Errno::EINVAL)?;
            if namelen > NAME_MAX || f.rest().get(namelen) != Some(&0) {
                return Err(Errno::EINVAL);
            }
            vfs.fuse_mut().invalidate_entry(dev, parent, name);
            Ok(())
        }
        notify::STORE => {
            let nodeid = f.u64()?;
            let offset = f.u64()?;
            let size = f.u32()?;
            let _padding = f.u32()?;
            let data = f.rest();
            if data.len() != size as usize {
                return Err(Errno::EINVAL);
            }
            let end = offset.checked_add(u64::from(size)).ok_or(Errno::EINVAL)?;
            let pages = {
                let mut nodes = vfs.fuse_mut();
                let id = *nodes.by_nodeid.get(&(dev, nodeid)).ok_or(Errno::ENOENT)?;
                let n = nodes.nodes.get_mut(&id).ok_or(Errno::ENOENT)?;
                if end > n.attr.size {
                    n.attr.size = end;
                }
                n.pages.upgrade()
            };
            if let Some(pages) = pages
                && size > 0
                && pages.notify_store(offset, data)?
            {
                use appine_engine::PAGE_SIZE;
                let lo = offset / PAGE_SIZE;
                let hi = end.div_ceil(PAGE_SIZE);
                invalidate_code_pages(cx, &pages, lo, hi);
            }
            Ok(())
        }
        notify::POLL => Ok(()),
        notify::RETRIEVE => Err(Errno::ENOSYS),
        _ => Err(Errno::EINVAL),
    }
}

// ---- Nodes and their caches ----

/// Every FUSE connection and the nodes looked up in its instance.
pub(crate) struct Fuses {
    /// Connections by their instance's device number (bind mounts share their source's).
    conns: HashMap<u64, Rc<RefCell<Conn>>>,
    nodes: HashMap<FuseId, Node>,
    /// The node of each (device number, node id).
    by_nodeid: HashMap<(u64, u64), FuseId>,
    next: FuseId,
    /// Counts entries made ([`Node::seen`]).
    clock: u64,
    /// Node count above which [`Fuses::enter`] asks for a sweep. Starts at [`NODES_MAX`],
    /// backs off above remaining live nodes after a sweep so working sets above [`NODES_MAX`] do
    /// not scan on every entry, and resets as nodes drop or `drop_caches` runs.
    sweep_at: usize,
    /// Nodes that currently have a live [`FillPages`] (tracked for periodic writeback).
    mapped: HashSet<FuseId>,
    /// Next periodic dirty-page writeback tick, or `None` when idle.
    next_writeback: Option<Instant>,
}

impl Default for Fuses {
    fn default() -> Fuses {
        Fuses {
            conns: HashMap::new(),
            nodes: HashMap::new(),
            by_nodeid: HashMap::new(),
            next: 0,
            clock: 0,
            sweep_at: NODES_MAX,
            mapped: HashSet::new(),
            next_writeback: None,
        }
    }
}

/// Nodes the cache keeps before it forgets the ones least recently looked up ([`Fuses::evict`]).
const NODES_MAX: usize = 1 << 14;
/// Target node count after a normal size-triggered eviction (3/4 of [`NODES_MAX`]).
const NODES_TARGET: usize = NODES_MAX / 4 * 3;
/// Minimum headroom above live pinned nodes before triggering another sweep (1/4 of [`NODES_MAX`]).
const NODES_HEADROOM: usize = NODES_MAX / 4;

/// The cache should be swept at the end of the syscall ([`Fuses::evict`]): it outgrew
/// [`Fuses::sweep_at`], an unlinked/doomed node may be ready to forget, or `drop_caches` asked
/// ([`DROP`]).
pub(crate) static SWEEP: AtomicBool = AtomicBool::new(false);

/// `drop_caches` asked to drop dentries and inodes: every node nothing uses goes.
pub(crate) static DROP: AtomicBool = AtomicBool::new(false);

/// A write of `value` to `/proc/sys/vm/drop_caches`: 2 and 3 drop dentries and inodes, which
/// for FUSE means forgetting the nodes nothing uses.
pub(crate) fn drop_caches(value: i64) {
    if value & 2 != 0 {
        DROP.store(true, Ordering::Relaxed);
        SWEEP.store(true, Ordering::Relaxed);
    }
}

/// One FUSE node (Linux's fuse inode, with the dentries naming it under its directory).
pub(crate) struct Node {
    pub dev: u64,
    pub nodeid: u64,
    /// The directory it was last found in and its name there (a directory's `..`, getcwd); the
    /// root's is itself and empty.
    pub parent: FuseId,
    pub name: Vec<u8>,
    /// The last attributes known; the type never changes.
    pub attr: Attr,
    /// Until when they are valid (None: no longer), or the syscall that fetched them ([`token`]).
    attr_until: Option<Instant>,
    attr_token: u64,
    /// Whether `attr` has been populated by a daemon reply (`LOOKUP`, `GETATTR`, `SETATTR`).
    attr_seen: bool,
    /// What lookups said about names in this directory: the node (None: no such name), until
    /// when, and the syscall that asked.
    children: HashMap<Vec<u8>, (Option<FuseId>, Option<Instant>, u64)>,
    /// A symlink's target and the syscall that read it (Linux caches it only with
    /// `FUSE_CACHE_SYMLINKS`, which is not offered).
    link: Option<(Vec<u8>, u64)>,
    /// Serializes page fills, writeback and mutations, including append offset selection.
    pub io_busy: bool,
    /// Serializes directory-modifying operations (Linux's directory `i_rwsem`).
    pub dir_busy: bool,
    /// Threads waiting to acquire [`Node::dir_busy`]; keeps the node alive in [`Fuses::evict`].
    pub dir_waiters: u32,
    pub pages: Weak<FillPages>,
    /// A last unmap or exit could not write back. Keep dirty data for a later sync on
    /// this inode, or until the connection is torn down.
    pub retry_writeback: Option<Rc<crate::mm::Fill>>,
    /// Entries the daemon returned for it, given back with `FUSE_FORGET` when it is forgotten
    /// (Linux's `nlookup`).
    nlookup: u64,
    /// Shared by O_PATH descriptions, which have no daemon file handle.
    path_pin: Weak<()>,
    /// Live AF_UNIX socket bound to this node, pinning it against cache eviction while bound.
    sock_pin: Weak<RefCell<crate::net::Socket>>,
    /// True once `unlink`, `rmdir`, or an overwriting `rename` removed the node's last link.
    pub unlinked: bool,
    /// When it was last entered ([`Fuses::clock`]): the oldest go first.
    seen: u64,
}

impl Node {
    pub(crate) fn pin_path(&mut self) -> Rc<()> {
        if let Some(pin) = self.path_pin.upgrade() {
            return pin;
        }
        let pin = Rc::new(());
        self.path_pin = Rc::downgrade(&pin);
        pin
    }

    /// The file type bits.
    pub fn kind(&self) -> u32 {
        self.attr.mode & mode::S_IFMT
    }

    /// The attributes when still valid, or fetched by this syscall.
    pub fn fresh_attr(&self) -> Option<&Attr> {
        fresh(self.attr_until, self.attr_token).then_some(&self.attr)
    }

    /// Whether any I/O or directory lock (or waiter) pins this node.
    fn is_locked(&self) -> bool {
        self.io_busy || self.dir_busy || self.dir_waiters != 0
    }
}

/// Whether something valid `until`, or fetched since this syscall started, can be used now.
/// A later syscall's query also counts: concurrent zero-validity walks must not erase each
/// other's retry progress.
fn fresh(until: Option<Instant>, t: u64) -> bool {
    let current = token();
    (current != 0 && t >= current) || until.is_some_and(|u| Instant::now() < u)
}

impl Fuses {
    /// Adds the connection of a new instance and its root directory (mode `rootmode`, attributes
    /// not yet fetched, as 6.1's `fuse_get_root_inode` makes it); returns the root's node.
    pub fn add(&mut self, conn: Rc<RefCell<Conn>>) -> FuseId {
        let (dev, rootmode) = {
            let c = conn.borrow();
            (c.dev, c.opts.rootmode.unwrap_or(mode::S_IFDIR | 0o755))
        };
        self.conns.insert(dev, conn);
        let id = self.next;
        self.next += 1;
        self.nodes.insert(
            id,
            Node {
                dev,
                nodeid: ROOT_ID,
                parent: id,
                name: Vec::new(),
                attr: Attr {
                    ino: ROOT_ID,
                    mode: rootmode,
                    nlink: 1,
                    ..Attr::default()
                },
                attr_until: None,
                attr_token: 0,
                attr_seen: false,
                children: HashMap::new(),
                link: None,
                io_busy: false,
                dir_busy: false,
                dir_waiters: 0,
                pages: Weak::new(),
                retry_writeback: None,
                nlookup: 0,
                path_pin: Weak::new(),
                sock_pin: Weak::new(),
                unlinked: false,
                seen: 0,
            },
        );
        self.by_nodeid.insert((dev, ROOT_ID), id);
        id
    }

    /// Next node count at which [`Fuses::enter`] should trigger a sweep, given `live` nodes
    /// remaining in the cache: at least [`NODES_MAX`], and at least 25% (or [`NODES_HEADROOM`])
    /// above `live` so working sets larger than [`NODES_MAX`] do not rescan on every new entry.
    fn next_sweep_at(live: usize) -> usize {
        let headroom = (live / 4).max(NODES_HEADROOM);
        NODES_MAX.max(live.saturating_add(headroom))
    }

    /// Forgets instance `dev`: its connection is aborted and its nodes go (the instance's last
    /// mount was collected, 6.1's `fuse_sb_destroy`).
    pub fn remove(&mut self, dev: u64) {
        if let Some(conn) = self.conns.remove(&dev) {
            if let Ok(mut c) = conn.try_borrow_mut() {
                c.abort();
            } else {
                wake_connection(readers(&conn));
            }
        }
        let wake_locks = self.nodes.values().any(|n| n.dev == dev && n.is_locked());
        self.nodes.retain(|_, n| n.dev != dev);
        self.by_nodeid.retain(|&(d, _), _| d != dev);
        self.mapped.retain(|id| self.nodes.contains_key(id));
        self.sweep_at = self.sweep_at.min(Self::next_sweep_at(self.nodes.len()));
        if wake_locks {
            crate::kernel::request_wake_locks();
        }
    }

    /// Pins node `id` against cache eviction while AF_UNIX socket `sock` stays bound to it.
    pub fn pin_socket(&mut self, id: FuseId, sock: &Rc<RefCell<crate::net::Socket>>) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.sock_pin = Rc::downgrade(sock);
        }
    }

    /// Records node `id` as having a live [`FillPages`] so periodic writeback can find it.
    pub fn track_mapped(&mut self, id: FuseId) {
        self.mapped.insert(id);
    }

    /// The device numbers of every instance.
    pub fn devs(&self) -> Vec<u64> {
        self.conns.keys().copied().collect()
    }

    /// The root directory of instance `dev`.
    pub fn root_of(&self, dev: u64) -> Option<FuseId> {
        self.by_nodeid.get(&(dev, ROOT_ID)).copied()
    }

    /// The connection of instance `dev`.
    pub fn conn(&self, dev: u64) -> Option<Rc<RefCell<Conn>>> {
        self.conns.get(&dev).cloned()
    }

    /// Node `id`.
    pub fn node(&self, id: FuseId) -> &Node {
        &self.nodes[&id]
    }

    /// Node `id`, when it still exists (its instance may have gone).
    pub fn get(&self, id: FuseId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    pub fn get_mut(&mut self, id: FuseId) -> Option<&mut Node> {
        self.nodes.get_mut(&id)
    }

    /// The connection node `id` belongs to.
    pub fn conn_of(&self, id: FuseId) -> Result<Rc<RefCell<Conn>>, Errno> {
        let n = self.nodes.get(&id).ok_or(Errno::ENOTCONN)?;
        self.conn(n.dev).ok_or(Errno::ENOTCONN)
    }

    /// What the cache knows of `name` in directory `dir`: `Some(Ok(node))`, `Some(Err(ENOENT))`
    /// for a cached negative entry, `Some(Err(e))` for a non-`ENOENT` lookup error recorded for
    /// this syscall, or `None` when it must be looked up.
    pub fn cached_child(&self, dir: FuseId, name: &[u8]) -> Option<Result<FuseId, Errno>> {
        if let Some((node, until, t)) = self.nodes.get(&dir)?.children.get(name)
            && fresh(*until, *t)
        {
            return Some(node.ok_or(Errno::ENOENT));
        }
        lookup_error(dir, name).map(Err)
    }

    /// The node of an entry the daemon returned for `name` in directory `dir` (a lookup, or a
    /// creation): a known node id keeps its node, which a directory then moves under `dir`; the
    /// attributes and the entry are cached for their validity and this syscall. A known node id
    /// of another type gets a new node (6.1's `fuse_iget` gives up a stale inode of another type),
    /// and a directory that would move into itself or below itself is ELOOP (`d_splice_alias`),
    /// so following parents always ends at a root. The root's node id is EIO; ENOTCONN when `dir`
    /// is gone (its instance went while the request was answered).
    pub fn enter(&mut self, dir: FuseId, name: &[u8], e: &Entry) -> Result<FuseId, Errno> {
        let dev = self.nodes.get(&dir).ok_or(Errno::ENOTCONN)?.dev;
        // The root's node id names no entry (6.1's invalid_nodeid)
        if e.nodeid == ROOT_ID {
            return Err(Errno::EIO);
        }
        let t = token();
        let known = self
            .by_nodeid
            .get(&(dev, e.nodeid))
            .copied()
            .filter(|id| (self.nodes[id].attr.mode ^ e.attr.mode) & mode::S_IFMT == 0);
        self.clock += 1;
        let id = match known {
            Some(id) => {
                // The lookup counts even when the entry is refused (the inode stays cached on
                // Linux, to be forgotten later), and a new name saves a doomed node
                self.nodes.get_mut(&id).unwrap().nlookup += 1;
                if let Some(c) = self.conns.get(&dev)
                    && let Ok(mut c) = c.try_borrow_mut()
                {
                    c.doomed.remove(&e.nodeid);
                }
                if self.nodes[&id].kind() == mode::S_IFDIR && self.is_within(dir, id) {
                    return Err(Errno::ELOOP);
                }
                id
            }
            None => {
                let id = self.next;
                self.next += 1;
                self.by_nodeid.insert((dev, e.nodeid), id);
                self.nodes.insert(
                    id,
                    Node {
                        dev,
                        nodeid: e.nodeid,
                        parent: dir,
                        name: name.to_vec(),
                        attr: e.attr,
                        attr_until: None,
                        attr_token: 0,
                        attr_seen: false,
                        children: HashMap::new(),
                        link: None,
                        io_busy: false,
                        dir_busy: false,
                        dir_waiters: 0,
                        pages: Weak::new(),
                        retry_writeback: None,
                        nlookup: 1,
                        path_pin: Weak::new(),
                        sock_pin: Weak::new(),
                        unlinked: false,
                        seen: 0,
                    },
                );
                // A daemon reusing a doomed node id for a different type must not inherit doom
                if let Some(c) = self.conns.get(&dev)
                    && let Ok(mut c) = c.try_borrow_mut()
                {
                    c.doomed.remove(&e.nodeid);
                }
                if self.nodes.len() > self.sweep_at {
                    SWEEP.store(true, Ordering::Relaxed);
                }
                id
            }
        };
        let n = self.nodes.get_mut(&id).unwrap();
        n.seen = self.clock;
        n.unlinked = false;
        // The root keeps itself as its parent
        if n.nodeid != ROOT_ID {
            n.parent = dir;
            n.name = name.to_vec();
        }
        n.attr = e.attr;
        n.attr_until = e.attr_until;
        n.attr_token = t;
        n.attr_seen = true;
        n.link = None;
        clear_lookup_error(dir, name);
        self.nodes
            .get_mut(&dir)
            .unwrap()
            .children
            .insert(name.to_vec(), (Some(id), e.entry_until, t));
        Ok(id)
    }

    /// Forgets the nodes nothing uses (Linux evicting unused inodes), giving their lookups back to
    /// their daemons (`FUSE_FORGET`, [`Conn::read_forget`]); returns how many went. Kept are
    /// those in `keep` (what processes' roots, cwds and open files, mounts, inotify watches and
    /// running programs are), roots, nodes with an O_PATH pin, an open handle or a request in
    /// flight, and the directories any of these or any remaining node lies in. Doomed nodes
    /// ([`Conn::doomed`]: unlinked/rmdir'd/overwritten nodes or nodes `drop_caches` kept only for
    /// a release in flight) go in the first sweep once nothing keeps them, without waiting for
    /// [`NODES_MAX`]. With `all` (`drop_caches`) every other unused node goes; otherwise bulk
    /// eviction runs only when the cache holds more than [`NODES_MAX`], the least recently entered
    /// first, down to [`NODES_TARGET`], raising [`Fuses::sweep_at`] above remaining live nodes so
    /// working sets above [`NODES_MAX`] do not rescan on every new entry. Entries naming forgotten
    /// nodes go too, and so do negative entries no longer valid.
    pub fn evict(&mut self, keep: &HashSet<FuseId>, all: bool) -> usize {
        let target = if all { 0 } else { NODES_TARGET };
        let mut doomed = HashSet::new();
        for c in self.conns.values() {
            let Ok(mut c) = c.try_borrow_mut() else {
                return 0;
            };
            let dev = c.dev;
            // A doomed node forgotten some other way leaves the set
            c.doomed.retain(|nodeid| {
                let id = self.by_nodeid.get(&(dev, *nodeid)).copied();
                if let Some(id) = id {
                    doomed.insert(id);
                }
                id.is_some()
            });
        }
        if !all && self.nodes.len() <= NODES_MAX && doomed.is_empty() {
            self.sweep_at = self.sweep_at.min(Self::next_sweep_at(self.nodes.len()));
            return 0;
        }
        let mut kept = keep.clone();
        // What only a release in flight keeps: the file was closed and the daemon has yet to
        // answer its release
        let mut releasing = HashSet::new();
        for c in self.conns.values() {
            let c = c.borrow();
            let busy = c.busy_nodeids();
            let only = if all {
                c.releasing_only()
            } else {
                HashSet::new()
            };
            for (&id, n) in &self.nodes {
                if n.dev != c.dev {
                    continue;
                }
                let open = n.path_pin.strong_count() != 0
                    || n.sock_pin.strong_count() != 0
                    || c.opens.contains_key(&n.nodeid);
                let locked = n.is_locked();
                if n.nodeid == ROOT_ID || open || locked || busy.contains(&n.nodeid) {
                    kept.insert(id);
                    if all
                        && n.nodeid != ROOT_ID
                        && !open
                        && !locked
                        && only.contains(&n.nodeid)
                        && !keep.contains(&id)
                    {
                        releasing.insert(id);
                    }
                }
            }
        }
        // The directories they are in
        for id in kept.clone() {
            let mut x = id;
            while let Some(n) = self.nodes.get(&x) {
                if n.parent == x || !kept.insert(n.parent) {
                    break;
                }
                x = n.parent;
            }
        }
        let mut gone: HashSet<FuseId> = HashSet::new();
        // Doomed nodes nothing keeps any more go now, along with any unused cached descendants
        // under a doomed directory (e.g. a directory rmdir'd after the daemon removed its entries).
        let mut doomed_unused: HashSet<FuseId> =
            doomed.into_iter().filter(|id| !kept.contains(id)).collect();
        if !doomed_unused.is_empty() {
            let mut parents = self.parents();
            if doomed_unused.iter().any(|id| parents.contains(id)) {
                let extra: Vec<FuseId> = self
                    .nodes
                    .keys()
                    .copied()
                    .filter(|id| !kept.contains(id) && !doomed_unused.contains(id))
                    .filter(|&id| {
                        let mut x = id;
                        while let Some(n) = self.nodes.get(&x) {
                            if n.parent == x {
                                return false;
                            }
                            x = n.parent;
                            if doomed_unused.contains(&x) {
                                return true;
                            }
                        }
                        false
                    })
                    .collect();
                doomed_unused.extend(extra);
            }
            loop {
                let leaves: Vec<FuseId> = doomed_unused
                    .iter()
                    .copied()
                    .filter(|id| !parents.contains(id))
                    .collect();
                if leaves.is_empty() {
                    break;
                }
                for id in leaves {
                    doomed_unused.remove(&id);
                    self.forget_node(id);
                    gone.insert(id);
                }
                if doomed_unused.is_empty() {
                    break;
                }
                parents = self.parents();
            }
        }
        // Bulk LRU trim runs only on drop_caches or when the cache is above NODES_MAX.
        let trim = all || self.nodes.len() > NODES_MAX;
        if trim {
            // Leaves first, oldest first; a directory whose last node went is a leaf the next round
            while self.nodes.len() > target {
                let parents = self.parents();
                let mut leaves: Vec<(u64, FuseId)> = self
                    .nodes
                    .iter()
                    .filter(|(id, _)| !kept.contains(id) && !parents.contains(id))
                    .map(|(&id, n)| (n.seen, id))
                    .collect();
                if leaves.is_empty() {
                    break;
                }
                leaves.sort_unstable();
                leaves.truncate(self.nodes.len() - target);
                for (_, id) in leaves {
                    self.forget_node(id);
                    gone.insert(id);
                }
            }
            // Raise the next sweep trigger above remaining live nodes (with headroom), or reset
            // to NODES_MAX once nodes dropped back down.
            self.sweep_at = Self::next_sweep_at(self.nodes.len());
        } else {
            self.sweep_at = self.sweep_at.min(Self::next_sweep_at(self.nodes.len()));
        }
        // Linux has dropped the dentries of what only a release keeps, and evicts the inode when
        // the release ends (FUSE keeps no unused inode, generic_delete_inode): such a node loses
        // its names, so a walk looks it up again (which saves it), and is doomed
        if all {
            for id in releasing {
                let Some(n) = self.nodes.get(&id) else {
                    continue;
                };
                let (dev, nodeid, parent) = (n.dev, n.nodeid, n.parent);
                if let Some(p) = self.nodes.get_mut(&parent) {
                    p.children.retain(|_, (child, _, _)| *child != Some(id));
                }
                if let Some(c) = self.conns.get(&dev) {
                    c.borrow_mut().doomed.insert(nodeid);
                }
            }
        }
        if !gone.is_empty() || trim {
            for n in self.nodes.values_mut() {
                n.children.retain(|_, (child, until, t)| match child {
                    Some(c) => !gone.contains(c),
                    None => fresh(*until, *t),
                });
            }
        }
        for c in self.conns.values() {
            if !c.borrow().forgets.is_empty() {
                request_wake_object(readers(c));
            }
        }
        gone.len()
    }

    /// Updates the cache after `FUSE_UNLINK`, `FUSE_RMDIR`, or an overwriting `FUSE_RENAME`
    /// removed a link to node `id`: decrements its cached link count, returns whether this was its
    /// last link (always true for a directory or a vanished cache entry), and when it was, dooms
    /// the node and schedules a sweep so it is forgotten once nothing keeps it.
    pub fn unlinked(&mut self, id: FuseId, rmdir: bool) -> bool {
        let Some(n) = self.nodes.get_mut(&id) else {
            return true;
        };
        let last = rmdir || n.attr.nlink <= 1;
        n.attr.nlink = if rmdir {
            0
        } else {
            n.attr.nlink.saturating_sub(1)
        };
        if last && n.nodeid != ROOT_ID {
            n.unlinked = true;
            let (dev, nodeid) = (n.dev, n.nodeid);
            if let Some(c) = self.conns.get(&dev)
                && let Ok(mut c) = c.try_borrow_mut()
            {
                c.doomed.insert(nodeid);
                SWEEP.store(true, Ordering::Relaxed);
            }
        }
        last
    }

    /// The nodes other nodes lie in.
    fn parents(&self) -> HashSet<FuseId> {
        self.nodes
            .iter()
            .filter(|(id, n)| n.parent != **id)
            .map(|(_, n)| n.parent)
            .collect()
    }

    /// Forgets node `id` ([`Fuses::evict`]): it leaves the table, the node-id index and the doomed,
    /// and its lookups are queued as a forget.
    fn forget_node(&mut self, id: FuseId) {
        let n = self.nodes.remove(&id).unwrap();
        self.mapped.remove(&id);
        if self.by_nodeid.get(&(n.dev, n.nodeid)) == Some(&id) {
            self.by_nodeid.remove(&(n.dev, n.nodeid));
        }
        if let Some(c) = self.conns.get(&n.dev) {
            let mut c = c.borrow_mut();
            c.doomed.remove(&n.nodeid);
            if n.nlookup > 0 && !c.aborted {
                c.forgets.push_back((n.nodeid, n.nlookup));
            }
        }
    }

    /// Whether node `id` is `top` or below it, by following parents up to a root (whose parent
    /// is itself; [`Fuses::enter`] keeps parents free of loops).
    pub fn is_within(&self, mut id: FuseId, top: FuseId) -> bool {
        loop {
            if id == top {
                return true;
            }
            match self.nodes.get(&id) {
                Some(n) if n.parent != id => id = n.parent,
                _ => return false,
            }
        }
    }

    /// Records that directory `dir` has no `name`, for `until` and this syscall.
    pub fn enter_negative(&mut self, dir: FuseId, name: &[u8], until: Option<Instant>) {
        clear_lookup_error(dir, name);
        if let Some(n) = self.nodes.get_mut(&dir) {
            n.children.insert(name.to_vec(), (None, until, token()));
        }
    }

    /// Drops what the cache knows of `name` in directory `dir` (removed or renamed through the
    /// mount, or invalidated by the daemon).
    pub fn forget_child(&mut self, dir: FuseId, name: &[u8]) {
        clear_lookup_error(dir, name);
        if let Some(n) = self.nodes.get_mut(&dir) {
            n.children.remove(name);
        }
    }

    /// Directory `id` was renamed to `name` in `dir` through the mount: `..` and getcwd follow
    /// it at once.
    pub fn moved(&mut self, id: FuseId, dir: FuseId, name: &[u8]) {
        if self.is_within(dir, id) {
            return;
        }
        if let Some(n) = self.nodes.get_mut(&id)
            && n.nodeid != ROOT_ID
        {
            n.parent = dir;
            n.name = name.to_vec();
        }
    }

    /// Node `id`'s attributes as the daemon just reported them, valid until `until`.
    pub fn set_attr(&mut self, id: FuseId, attr: Attr, until: Option<Instant>) {
        if let Some(n) = self.nodes.get_mut(&id) {
            // The type is the node's for good (a reply giving another one is ignored there)
            let kind = n.attr.mode & mode::S_IFMT;
            n.attr = Attr {
                mode: kind | (attr.mode & !mode::S_IFMT),
                ..attr
            };
            n.attr_until = until;
            n.attr_token = token();
            n.attr_seen = true;
        }
    }

    /// Node `id`'s attributes are no longer known (it was written, its attributes changed).
    pub fn stale(&mut self, id: FuseId) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.attr_until = None;
            n.attr_token = 0;
        }
    }

    /// Symlink `id`'s target, when this syscall has read it.
    pub fn link(&self, id: FuseId) -> Option<&[u8]> {
        match &self.nodes.get(&id)?.link {
            Some((target, t)) if fresh(None, *t) => Some(target),
            _ => None,
        }
    }

    pub fn set_link(&mut self, id: FuseId, target: Vec<u8>) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.link = Some((target, token()));
        }
    }

    /// The daemon invalidated `name` in directory node id `parent` (`FUSE_NOTIFY_INVAL_ENTRY`,
    /// `FUSE_NOTIFY_DELETE`).
    fn invalidate_entry(&mut self, dev: u64, parent: u64, name: &[u8]) {
        if let Some(&id) = self.by_nodeid.get(&(dev, parent)) {
            self.forget_child(id, name);
            self.stale(id);
        }
    }
}

/// An entry a lookup or creation returned (`struct fuse_entry_out`).
pub(crate) struct Entry {
    pub nodeid: u64,
    pub attr: Attr,
    pub entry_until: Option<Instant>,
    pub attr_until: Option<Instant>,
}

impl Entry {
    /// Parses a `struct fuse_entry_out`; a node id of 0 is a negative entry (None, with its
    /// validity).
    pub fn parse(reply: &[u8], ns: &UserNs) -> Result<Result<Entry, Option<Instant>>, Errno> {
        let mut f = Fields::new(reply);
        let (nodeid, _generation) = (f.u64()?, f.u64()?);
        let (entry_valid, attr_valid) = (f.u64()?, f.u64()?);
        let (entry_nsec, attr_nsec) = (f.u32()?, f.u32()?);
        let entry_until = deadline(entry_valid, entry_nsec);
        if nodeid == 0 {
            return Ok(Err(entry_until));
        }
        let attr = Attr::parse(&mut f, ns)?;
        Ok(Ok(Entry {
            nodeid,
            attr,
            entry_until,
            attr_until: deadline(attr_valid, attr_nsec),
        }))
    }
}

/// Parses a `struct fuse_attr_out`: the attributes and until when they are valid.
pub(crate) fn attr_out(reply: &[u8], ns: &UserNs) -> Result<(Attr, Option<Instant>), Errno> {
    let mut f = Fields::new(reply);
    let (valid, nsec, _dummy) = (f.u64()?, f.u32()?, f.u32()?);
    Ok((Attr::parse(&mut f, ns)?, deadline(valid, nsec)))
}

// ---- Retrying a syscall for what the cache lacks ----

/// A query a walk could not answer from the cache.
#[derive(Debug, Clone)]
pub(crate) enum Query {
    Lookup(FuseId, Vec<u8>),
    /// A batch of consecutive plain components from a path walk inside mount `mnt`, resolved in
    /// one retry while checking directory type, mount crossings, and search permission at each
    /// step.
    LookupWalk {
        mnt: super::MountId,
        dir: FuseId,
        names: Vec<Vec<u8>>,
    },
    Getattr(FuseId, Option<u64>),
    Readlink(FuseId),
    /// A program to execute, read whole ([`program`]).
    Program(FuseId),
}

thread_local! {
    /// The syscall this thread is in ([`token`]).
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static TOKEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// The query the last [`Errno::FUSE_RETRY`] stands for.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static QUERY: std::cell::RefCell<Option<Query>> = const { std::cell::RefCell::new(None) };
    /// Non-`ENOENT` lookup errors seen in this syscall, keyed by `(dir, name)`, so walks and
    /// syscall handlers receive the error directly on retry (and can tolerate it when appropriate)
    /// instead of `serve()` aborting the syscall prematurely.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static LOOKUP_ERRORS: std::cell::RefCell<Vec<(FuseId, Vec<u8>, Errno)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    /// The programs execve read from FUSE nodes in this syscall (the program, its interpreters):
    /// dropped when the next syscall starts.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static PROGRAMS: std::cell::RefCell<Vec<(FuseId, std::fs::File)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn lookup_error(dir: FuseId, name: &[u8]) -> Option<Errno> {
    LOOKUP_ERRORS.with_borrow(|errs| {
        errs.iter()
            .find(|(d, n, _)| *d == dir && n.as_slice() == name)
            .map(|(_, _, e)| *e)
    })
}

fn record_lookup_error(dir: FuseId, name: Vec<u8>, err: Errno) {
    LOOKUP_ERRORS.with_borrow_mut(|errs| {
        if let Some(slot) = errs.iter_mut().find(|(d, n, _)| *d == dir && *n == name) {
            slot.2 = err;
        } else {
            errs.push((dir, name, err));
        }
    });
}

fn clear_lookup_error(dir: FuseId, name: &[u8]) {
    LOOKUP_ERRORS.with_borrow_mut(|errs| {
        if !errs.is_empty() {
            errs.retain(|(d, n, _)| !(*d == dir && n.as_slice() == name));
        }
    });
}

/// A copy of FUSE node `id`'s data for execve, when this syscall has read it ([`Query::Program`]):
/// the loader needs a fully populated host file.
pub(crate) fn program(id: FuseId) -> Option<std::fs::File> {
    PROGRAMS.with_borrow(|p| {
        p.iter()
            .find(|(i, _)| *i == id)
            .and_then(|(_, file)| file.try_clone().ok())
    })
}

/// The number of the syscall this thread is handling: what a request brings back during it is
/// usable until it ends, whatever its validity.
pub(crate) fn token() -> u64 {
    TOKEN.get()
}

/// A new syscall starts on this thread: what the last one read stops counting as fresh, and
/// the program copies it kept go.
pub(crate) fn new_syscall() {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    TOKEN.set(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    if LOOKUP_ERRORS.with_borrow(|e| !e.is_empty()) {
        LOOKUP_ERRORS.with_borrow_mut(Vec::clear);
    }
    if PROGRAMS.with_borrow(|p| !p.is_empty()) {
        PROGRAMS.with_borrow_mut(Vec::clear);
    }
}

/// Records that `q` must be asked before the syscall can go on, and returns the error that takes
/// the syscall back to the dispatcher ([`serve`]).
pub(crate) fn need(q: Query) -> Errno {
    QUERY.with_borrow_mut(|s| *s = Some(q));
    Errno::FUSE_RETRY
}

/// Checks whether the caller may search directory `dir` before continuing a batched
/// [`Query::LookupWalk`], matching [`super::Vfs::fuse_permission`] without issuing a nested retry.
fn may_search_in_walk(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    cred: &Cred,
    dir: FuseId,
) -> Result<bool, Errno> {
    let (allowed, default_permissions, cached) = {
        let f = vfs.fuse();
        let Some(n) = f.get(dir) else {
            return Ok(false);
        };
        if n.kind() != mode::S_IFDIR {
            return Ok(false);
        }
        let Ok(conn) = f.conn_of(dir) else {
            return Ok(false);
        };
        let c = conn.borrow();
        (
            c.allows(cred),
            c.opts.default_permissions,
            n.fresh_attr().copied(),
        )
    };
    if !allowed {
        return Ok(false);
    }
    if !default_permissions || cred.searches_all() {
        return Ok(true);
    }
    let attr = match cached {
        Some(a) => a,
        None => match getattr(cx, vfs, dir, None, false) {
            Ok(a) => a,
            Err(Errno::EINTR) => return Err(Errno::EINTR),
            Err(_) => return Ok(false),
        },
    };
    Ok(cred.permission(&attr.stat(), crate::cred::MAY_EXEC).is_ok())
}

/// Asks the daemon what the last [`need`] recorded and caches the answer for this syscall, with
/// the BKL released; the dispatcher then runs the syscall again. Lookup errors (other than
/// `EINTR`) are cached for this syscall so walks and handlers receive them directly and can
/// tolerate them when Linux VFS rules allow.
pub(crate) fn serve(
    cx: &mut Cx<'_>,
    program_opened: impl FnOnce(&crate::kernel::Kernel, FuseId),
) -> Result<(), Errno> {
    let Some(q) = QUERY.with_borrow_mut(Option::take) else {
        return Err(Errno::EIO);
    };
    let vfs = cx.vfs()?;
    match q {
        Query::Lookup(dir, name) => match lookup(cx, &vfs, dir, &name) {
            Ok(_) | Err(Errno::ENOENT) => Ok(()),
            Err(Errno::EINTR) => Err(Errno::EINTR),
            Err(e) => {
                record_lookup_error(dir, name, e);
                Ok(())
            }
        },
        Query::LookupWalk { mnt, dir, names } => {
            let cred = cx.cred();
            let mut cur = dir;
            for (i, name) in names.into_iter().enumerate() {
                if i > 0 {
                    if cx.task.killed.get() {
                        return Err(Errno::EINTR);
                    }
                    // Never cross a mount point inside the batched FUSE walk.
                    let node = super::Node::Fuse(mnt, cur);
                    if vfs.mounted(node.clone()) != node {
                        break;
                    }
                    if !may_search_in_walk(cx, &vfs, &cred, cur)? {
                        break;
                    }
                }
                let cached = vfs.fuse().cached_child(cur, &name);
                match cached {
                    Some(Ok(next)) => cur = next,
                    Some(Err(_)) => break,
                    None => match lookup(cx, &vfs, cur, &name) {
                        Ok(next) => cur = next,
                        Err(Errno::ENOENT) => break,
                        Err(Errno::EINTR) => return Err(Errno::EINTR),
                        Err(e) => {
                            record_lookup_error(cur, name, e);
                            break;
                        }
                    },
                }
            }
            Ok(())
        }
        Query::Getattr(id, fh) => getattr(cx, &vfs, id, fh, false).map(|_| ()),
        Query::Program(id) => {
            use crate::fd::oflags;
            let h = open(cx, &vfs, id, oflags::O_RDONLY | oflags::O_LARGEFILE, false)?;
            program_opened(cx.kr(), id);
            let size = getattr(cx, &vfs, id, h.fh(), false)?.size;
            let copy = snapshot(cx, (&h.conn, h.nodeid, h.fh, h.flags), 0, size)?;
            drop(h);
            PROGRAMS.with_borrow_mut(|p| p.push((id, copy)));
            Ok(())
        }
        Query::Readlink(id) => {
            let (conn, nodeid) = target(&vfs, id)?;
            let target = call(cx, &conn, op::READLINK, nodeid, &[])?;
            if target.is_empty() || target.contains(&0) {
                return Err(Errno::EIO);
            }
            vfs.fuse_mut().set_link(id, target);
            Ok(())
        }
    }
}

/// The connection and node id of node `id`.
pub(crate) fn target(vfs: &super::Vfs, id: FuseId) -> Result<(Rc<RefCell<Conn>>, u64), Errno> {
    let f = vfs.fuse();
    let conn = f.conn_of(id)?;
    Ok((conn, f.node(id).nodeid))
}

/// `FUSE_LOOKUP` of `name` in directory `dir` (6.1's `fuse_lookup_name`), cached: the node, or
/// ENOENT (a negative entry, cached for its validity; an ENOENT error only for this syscall).
pub(crate) fn lookup(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    dir: FuseId,
    name: &[u8],
) -> Result<FuseId, Errno> {
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    let (conn, nodeid) = target(vfs, dir)?;
    let reply = match call(cx, &conn, op::LOOKUP, nodeid, &Args::default().name(name).0) {
        Err(Errno::ENOENT) => {
            vfs.fuse_mut().enter_negative(dir, name, None);
            return Err(Errno::ENOENT);
        }
        r => r?,
    };
    let (ns, dev, auto_inval) = {
        let c = conn.borrow();
        (
            c.user_ns.clone(),
            c.dev,
            c.flags & init::AUTO_INVAL_DATA != 0,
        )
    };
    match Entry::parse(&reply, &ns)? {
        Ok(e) => {
            let inval = auto_inval
                .then(|| {
                    let f = vfs.fuse();
                    let id = *f.by_nodeid.get(&(dev, e.nodeid))?;
                    let n = f.get(id)?;
                    ((n.attr.mode ^ e.attr.mode) & mode::S_IFMT == 0
                        && n.attr_seen
                        && (e.attr.size != n.attr.size || e.attr.mtime_ns != n.attr.mtime_ns))
                        .then(|| n.pages.upgrade())
                        .flatten()
                })
                .flatten();
            let id = vfs.fuse_mut().enter(dir, name, &e)?;
            if let Some(pages) = inval {
                invalidate_pages(cx, &pages, 0, u64::MAX);
            }
            Ok(id)
        }
        Err(until) => {
            vfs.fuse_mut().enter_negative(dir, name, until);
            Err(Errno::ENOENT)
        }
    }
}

/// `FUSE_GETATTR` of node `id` (through open file handle `fh` when given, `FUSE_GETATTR_FH`),
/// cached. Under `FUSE_AUTO_INVAL_DATA`, invalidates resident mapped pages if size or mtime
/// changed on the daemon.
pub(crate) fn getattr(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    id: FuseId,
    fh: Option<u64>,
    forced: bool,
) -> Result<Attr, Errno> {
    getattr_inner(cx, vfs, id, fh, forced, true)
}

/// [`getattr`] without `FUSE_AUTO_INVAL_DATA` page invalidation (used by `refresh_mapping_size`
/// while servicing an invalidation so it cannot trigger a second invalidation loop).
pub(crate) fn getattr_no_inval(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    id: FuseId,
    fh: Option<u64>,
    forced: bool,
) -> Result<Attr, Errno> {
    getattr_inner(cx, vfs, id, fh, forced, false)
}

fn getattr_inner(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    id: FuseId,
    fh: Option<u64>,
    forced: bool,
    auto_inval_check: bool,
) -> Result<Attr, Errno> {
    const GETATTR_FH: u32 = 1;
    let (conn, nodeid) = target(vfs, id)?;
    let args = Args::default()
        .u32(if fh.is_some() { GETATTR_FH } else { 0 })
        .u32(0)
        .u64(fh.unwrap_or(0));
    let reply = request(
        cx,
        &cx.cred(),
        &conn,
        (op::GETATTR, nodeid),
        &args.0,
        forced,
    )?;
    let (ns, auto_inval) = {
        let c = conn.borrow();
        (c.user_ns.clone(), c.flags & init::AUTO_INVAL_DATA != 0)
    };
    let (attr, until) = attr_out(&reply, &ns)?;
    let (res, inval_pages) = {
        let mut f = vfs.fuse_mut();
        let n = f.get(id).ok_or(Errno::ENOTCONN)?;
        if (attr.mode ^ n.attr.mode) & mode::S_IFMT != 0 {
            return Err(Errno::EIO);
        }
        let inval = (auto_inval_check
            && auto_inval
            && n.attr_seen
            && (attr.size != n.attr.size || attr.mtime_ns != n.attr.mtime_ns))
            .then(|| n.pages.upgrade())
            .flatten();
        f.set_attr(id, attr, until);
        (f.node(id).attr, inval)
    };
    if let Some(pages) = inval_pages {
        invalidate_pages(cx, &pages, 0, u64::MAX);
    }
    Ok(res)
}

/// Node `id`'s attributes from the cache, or a retry to fetch them ([`need`]).
pub(crate) fn cached_attr(vfs: &super::Vfs, id: FuseId) -> Result<Attr, Errno> {
    cached_attr_fh(vfs, id, None)
}

/// [`cached_attr`], passing open file handle `fh` (`FUSE_GETATTR_FH`) if a retry fetches them.
pub(crate) fn cached_attr_fh(vfs: &super::Vfs, id: FuseId, fh: Option<u64>) -> Result<Attr, Errno> {
    let f = vfs.fuse();
    let n = f.get(id).ok_or(Errno::ENOTCONN)?;
    match n.fresh_attr() {
        Some(a) => Ok(*a),
        None => Err(need(Query::Getattr(id, fh))),
    }
}

// ---- Open files ----

/// What an open FUSE file holds (Linux's `struct fuse_file`): its node, the daemon's file handle
/// and open flags. When the last reference goes, `FUSE_RELEASE` (`FUSE_RELEASEDIR` for a
/// directory) is sent without waiting.
pub(crate) struct Handle {
    pub conn: Rc<RefCell<Conn>>,
    pub id: FuseId,
    pub nodeid: u64,
    pub fh: u64,
    /// `FOPEN_*` from the open reply.
    pub open_flags: u32,
    /// The flags the file was opened with (passed back in reads, writes and the release).
    pub flags: u32,
    pub dir: bool,
    /// No open was made (`FUSE_NO_OPEN_SUPPORT`): there is nothing to release.
    pub no_release: bool,
}

impl Handle {
    /// The daemon file handle when an open request actually succeeded (`!no_release`).
    pub(crate) fn fh(&self) -> Option<u64> {
        (!self.no_release).then_some(self.fh)
    }

    /// OPEN and CREATE use the same cache policy. An atomic truncate resizes the backing
    /// in the caller, even for a handle that otherwise keeps the cache.
    pub(crate) fn finish_open(self, cx: &Cx<'_>, vfs: &super::Vfs) -> Self {
        if !self.dir
            && self.flags & crate::fd::oflags::O_TRUNC == 0
            && self.open_flags & fopen::KEEP_CACHE == 0
            && let Some(pages) = mapped_pages(vfs, self.id)
        {
            invalidate_pages(cx, &pages, 0, u64::MAX);
        }
        self.counted()
    }

    /// Counts it among the node's open handles ([`Conn::opens`]), which keep the node from being
    /// forgotten until it goes.
    fn counted(self) -> Handle {
        *self.conn.borrow_mut().opens.entry(self.nodeid).or_insert(0) += 1;
        self
    }
}

impl Drop for Handle {
    /// Uncounts the handle and queues its release; when the connection is borrowed at that
    /// moment, both wait until the syscall ends ([`flush_released`]).
    fn drop(&mut self) {
        let release = (!self.no_release).then(|| {
            let opcode = if self.dir {
                op::RELEASEDIR
            } else {
                op::RELEASE
            };
            let args = Args::default().u64(self.fh).u32(self.flags).u32(0).u64(0);
            (opcode, args.0)
        });
        let r = Released {
            conn: self.conn.clone(),
            nodeid: self.nodeid,
            release,
        };
        if !r.send() {
            RELEASED.with(|q| q.borrow_mut().0.push(r));
        }
    }
}

/// An open file's last reference went ([`Handle`]): its node's open count goes down and the
/// daemon gets `FUSE_RELEASE`/`FUSE_RELEASEDIR` (`release`, None without an open).
struct Released {
    conn: Rc<RefCell<Conn>>,
    nodeid: u64,
    release: Option<(u32, Vec<u8>)>,
}

impl Released {
    /// Done now, or false when the connection is borrowed (nothing done then).
    fn send(&self) -> bool {
        let Ok(mut c) = self.conn.try_borrow_mut() else {
            return false;
        };
        if let Some(k) = c.opens.get_mut(&self.nodeid) {
            *k -= 1;
            if *k == 0 {
                c.opens.remove(&self.nodeid);
                if (self.release.is_none() || c.refusal().is_some())
                    && c.doomed.contains(&self.nodeid)
                {
                    SWEEP.store(true, Ordering::Relaxed);
                }
            }
        }
        drop(c);
        if let Some((opcode, args)) = &self.release {
            background(&self.conn, *opcode, self.nodeid, args);
        }
        true
    }
}

/// Releases waiting for their connection ([`Handle`]'s drop). Emptied under the BKL before the
/// thread's syscall ends or the thread exits; one left at thread exit is leaked rather than
/// dropped without the BKL (Rc counts are not atomic).
struct ReleasedQueue(Vec<Released>);

impl Drop for ReleasedQueue {
    fn drop(&mut self) {
        std::mem::forget(std::mem::take(&mut self.0));
    }
}

thread_local! {
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static RELEASED: std::cell::RefCell<ReleasedQueue> =
        const { std::cell::RefCell::new(ReleasedQueue(Vec::new())) };
}

/// Sends the releases that found their connection borrowed: at the end of every syscall and at
/// thread exit, with the BKL held and no connection borrowed.
pub(crate) fn flush_released() {
    let queued = RELEASED.with(|q| std::mem::take(&mut q.borrow_mut().0));
    for r in queued {
        if !r.send() {
            RELEASED.with(|q| q.borrow_mut().0.push(r));
        }
    }
}

/// File status flags kept on a FUSE handle and sent in a standalone OPEN request.
pub(crate) fn handle_flags(conn: &Conn, flags: u32) -> u32 {
    use crate::fd::oflags;
    let mut kept = flags & !(oflags::O_CREAT | oflags::O_EXCL | oflags::O_NOCTTY);
    if !atomic_o_trunc(conn) {
        kept &= !oflags::O_TRUNC;
    }
    kept
}

/// Opens node `id` (6.1's `fuse_do_open`): `FUSE_OPEN` or `FUSE_OPENDIR` with the open flags
/// less `O_CREAT`, `O_EXCL` and `O_NOCTTY` (and `O_TRUNC` unless the daemon takes it). A daemon
/// answering ENOSYS needs no open: no handle, no release, and none is asked again.
pub(crate) fn open(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    id: FuseId,
    flags: u32,
    dir: bool,
) -> Result<Handle, Errno> {
    let (conn, nodeid) = target(vfs, id)?;
    let sent = handle_flags(&conn.borrow(), flags);
    let (opcode, unsupported) = if dir {
        (op::OPENDIR, no::OPENDIR)
    } else {
        (op::OPEN, no::OPEN)
    };
    let (fh, open_flags, no_release) = if conn.borrow().no & unsupported != 0 {
        (0, fopen::KEEP_CACHE, true)
    } else {
        let args = Args::default().u32(sent).u32(0);
        match call(cx, &conn, opcode, nodeid, &args.0) {
            Ok(reply) => {
                let mut f = Fields::new(&reply);
                (f.u64()?, f.u32()?, false)
            }
            Err(Errno::ENOSYS) => (0, fopen::KEEP_CACHE, true),
            Err(e) => return Err(e),
        }
    };
    Ok(Handle {
        conn,
        id,
        nodeid,
        fh,
        flags: sent,
        open_flags,
        dir,
        no_release,
    }
    .finish_open(cx, vfs))
}

/// Reads up to `len` bytes at `offset` through open handle `h` (`FUSE_READ`), in requests of at
/// most the negotiated size; stops at the first short reply (the end of the file).
pub(crate) fn read(
    cx: &mut Cx<'_>,
    h: (&Rc<RefCell<Conn>>, u64, u64, u32),
    offset: u64,
    len: usize,
    forced: bool,
) -> Result<Vec<u8>, Errno> {
    let (conn, nodeid, fh, flags) = h;
    let chunk = conn.borrow().max_read as usize;
    let mut out = Vec::new();
    while out.len() < len {
        let want = (len - out.len()).min(chunk);
        let args = Args::default()
            .u64(fh)
            .u64(offset + out.len() as u64)
            .u32(want as u32)
            .u32(0)
            .u64(0)
            .u32(flags)
            .u32(0);
        let data = match request(cx, &cx.cred(), conn, (op::READ, nodeid), &args.0, forced) {
            Ok(d) => d,
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        };
        let short = data.len() < want;
        out.extend_from_slice(&data[..data.len().min(want)]);
        if short {
            break;
        }
    }
    Ok(out)
}

/// Writes `data` at `offset` through open handle `h` (`FUSE_WRITE`), in requests of at most the
/// negotiated size; returns how much the daemon took, stopping at a short write. A reply claiming
/// more than was sent is EIO.
pub(crate) fn write(
    cx: &mut Cx<'_>,
    h: (&Rc<RefCell<Conn>>, u64, u64, u32),
    offset: u64,
    data: &[u8],
    cached: bool,
) -> Result<usize, Errno> {
    let (conn, nodeid, fh, flags) = h;
    let chunk = conn.borrow().max_write as usize;
    let mut done = 0;
    while done < data.len() {
        let piece = &data[done..(done + chunk).min(data.len())];
        let args = Args::default()
            .u64(fh)
            .u64(offset + done as u64)
            .u32(piece.len() as u32)
            .u32(u32::from(cached)) // FUSE_WRITE_CACHE
            .u64(0)
            .u32(flags)
            .u32(0)
            .bytes(piece);
        let reply = if cached {
            call_forced(cx, conn, op::WRITE, nodeid, &args.0)
        } else {
            call(cx, conn, op::WRITE, nodeid, &args.0)
        };
        let n = match reply {
            Ok(r) => Fields::new(&r).u32()? as usize,
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        };
        if n > piece.len() {
            return Err(Errno::EIO);
        }
        done += n;
        if n < piece.len() {
            break;
        }
    }
    Ok(done)
}

/// The entries of directory handle `h` from the daemon (`FUSE_READDIR`, a page at a time from the
/// offset the last entry gave until an empty reply): name, inode number and type bits, as the
/// daemon lists them (its `.` and `..` included).
pub(crate) fn readdir(
    cx: &mut Cx<'_>,
    h: (&Rc<RefCell<Conn>>, u64, u64, u32),
) -> Result<Vec<super::store::DirEntry>, Errno> {
    let (conn, nodeid, fh, flags) = h;
    let mut out = Vec::new();
    let mut offset = 0u64;
    loop {
        let args = Args::default()
            .u64(fh)
            .u64(offset)
            .u32(PAGE)
            .u32(0)
            .u64(0)
            .u32(flags)
            .u32(0);
        let reply = call(cx, conn, op::READDIR, nodeid, &args.0)?;
        if reply.is_empty() {
            return Ok(out);
        }
        let mut at = 0;
        // struct fuse_dirent: ino, off, namelen, type, name padded to 8 bytes
        while reply.len() - at >= 24 {
            let mut f = Fields::new(&reply[at..]);
            let (ino, off, namelen, ty) = (f.u64()?, f.u64()?, f.u32()? as usize, f.u32()?);
            if namelen == 0 || namelen > NAME_MAX {
                return Err(Errno::EIO);
            }
            let name = f.rest().get(..namelen).ok_or(Errno::EIO)?;
            if name.contains(&b'/') {
                return Err(Errno::EIO);
            }
            out.push(super::store::DirEntry {
                name: name.to_vec(),
                ino,
                mode: (ty & 0xf) << 12,
            });
            offset = off;
            at += (24 + namelen).next_multiple_of(8);
        }
    }
}

/// What `FUSE_STATFS` reports (`struct fuse_kstatfs`).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Kstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u64,
    pub namelen: u64,
    pub frsize: u64,
}

/// statfs of the instance node `id` is in (`FUSE_STATFS`).
pub(crate) fn statfs(cx: &mut Cx<'_>, vfs: &super::Vfs, id: FuseId) -> Result<Kstatfs, Errno> {
    let (conn, nodeid) = target(vfs, id)?;
    let reply = call(cx, &conn, op::STATFS, nodeid, &[])?;
    let mut f = Fields::new(&reply);
    let (blocks, bfree, bavail, files, ffree) = (f.u64()?, f.u64()?, f.u64()?, f.u64()?, f.u64()?);
    let (bsize, namelen, frsize) = (f.u32()?, f.u32()?, f.u32()?);
    Ok(Kstatfs {
        blocks,
        bfree,
        bavail,
        files,
        ffree,
        bsize: u64::from(bsize),
        namelen: u64::from(namelen),
        frsize: u64::from(frsize),
    })
}

/// Asks whether the caller may access node `id` with mask `mask` (`FUSE_ACCESS`, 6.1's
/// `fuse_access`): a daemon without it (ENOSYS) allows everything.
pub(crate) fn access(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    cred: &Cred,
    id: FuseId,
    mask: u32,
) -> Result<(), Errno> {
    let (conn, nodeid) = target(vfs, id)?;
    if conn.borrow().no & no::ACCESS != 0 {
        return Ok(());
    }
    let args = Args::default().u32(mask).u32(0);
    match call_as(cx, cred, &conn, (op::ACCESS, nodeid), &args.0) {
        Err(Errno::ENOSYS) => Ok(()),
        r => r.map(|_| ()),
    }
}

/// `FUSE_GETXATTR` (`size` 0 asks only for the length) or `FUSE_LISTXATTR` (`name` None) on node
/// `id`: the value or the length. A daemon without them is EOPNOTSUPP.
pub(crate) fn getxattr(
    cx: &mut Cx<'_>,
    vfs: &super::Vfs,
    id: FuseId,
    name: Option<&[u8]>,
    size: usize,
) -> Result<Result<Vec<u8>, usize>, Errno> {
    let (conn, nodeid) = target(vfs, id)?;
    let (opcode, bit) = match name {
        Some(_) => (op::GETXATTR, no::GETXATTR),
        None => (op::LISTXATTR, no::LISTXATTR),
    };
    if conn.borrow().no & bit != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut args = Args::default().u32(size as u32).u32(0);
    if let Some(n) = name {
        args = args.name(n);
    }
    let reply = match call(cx, &conn, opcode, nodeid, &args.0) {
        Err(Errno::ENOSYS) => return Err(Errno::EOPNOTSUPP),
        r => r?,
    };
    if size == 0 {
        return Ok(Err(Fields::new(&reply).u32()? as usize));
    }
    if reply.len() > size {
        return Err(Errno::ERANGE);
    }
    Ok(Ok(reply))
}

/// The owner a lock or flush names: the fd table's address, mixed as 6.1's
/// `fuse_lock_owner_id` mixes `current->files`.
pub(crate) fn lock_owner(table: usize) -> u64 {
    let v = table as u64;
    (v ^ (v >> 29)).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// A FUSE file's data copied into a new host file, for a mapping of it (there being no page
/// cache to map): `len` bytes from `offset`, read through open handle `h`. The host file is as
/// long as the FUSE file reached, so a mapping past its end faults as on Linux.
pub(crate) fn snapshot(
    cx: &mut Cx<'_>,
    h: (&Rc<RefCell<Conn>>, u64, u64, u32),
    offset: u64,
    len: u64,
) -> Result<std::fs::File, Errno> {
    use std::os::unix::fs::FileExt;
    let data = read(cx, h, offset, len as usize, false)?;
    let file = appine_hal::memfd(c"appine-fuse").map_err(Errno)?;
    file.set_len(offset + data.len() as u64)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
    file.write_all_at(&data, offset)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
    Ok(file)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn concurrent_tokens_preserve_zero_validity_walk_progress() {
        new_syscall();
        let older = token();
        let mut f = Fuses::default();
        let root = f.add(Rc::new(RefCell::new(conn(Options::default()))));
        new_syscall();
        let newer = token();
        let e = Entry {
            nodeid: 2,
            attr: Attr {
                ino: 2,
                mode: mode::S_IFLNK | 0o777,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };
        let child = f.enter(root, b"link", &e).unwrap();
        f.set_link(child, b"target".to_vec());
        f.enter_negative(root, b"absent", None);
        // The newer lookup happened after the older syscall started: both may use it.
        TOKEN.set(older);
        assert_eq!(f.cached_child(root, b"link"), Some(Ok(child)));
        assert!(f.node(child).fresh_attr().is_some());
        assert_eq!(f.link(child), Some(b"target".as_slice()));
        assert_eq!(f.cached_child(root, b"absent"), Some(Err(Errno::ENOENT)));
        TOKEN.set(0);
        assert_eq!(f.cached_child(root, b"link"), None);
        assert!(f.node(child).fresh_attr().is_none());
        assert_eq!(f.link(child), None);
        TOKEN.set(older);
        // Explicit invalidation still forces a fresh request, even within the older syscall.
        f.stale(child);
        f.forget_child(root, b"absent");
        assert!(f.node(child).fresh_attr().is_none());
        assert_eq!(f.cached_child(root, b"absent"), None);
        TOKEN.set(newer);
        new_syscall();
        assert_eq!(f.cached_child(root, b"link"), None);
        assert_eq!(f.link(child), None);
    }

    #[test]
    fn shared_storage_allows_copies_of_the_same_user_namespace() {
        let cred = Cred::root();
        let c = Conn::shared_storage(
            77,
            std::path::Path::new("/shared-storage"),
            &cred,
            crate::pidns::PidNs::init(),
        )
        .unwrap();
        assert!(c.allows(&Cred::root()));
        let mut child = Cred::root();
        child.user_ns = UserNs::child(&child.user_ns, 0, true);
        assert!(c.allows(&child));
        let c = Conn::shared_storage(
            78,
            std::path::Path::new("/shared-storage"),
            &child,
            crate::pidns::PidNs::init(),
        )
        .unwrap();
        assert!(c.allows(&child));
        assert!(!c.allows(&Cred::root()));
    }

    fn conn(opts: Options) -> Conn {
        Conn::new(0x30, opts, &Cred::root(), crate::pidns::PidNs::init())
    }

    /// A `struct fuse_attr` with mode `mode` and owner `uid`.
    fn attr_bytes(mode: u32, uid: u32, nsec: u32) -> Vec<u8> {
        Args::default()
            .u64(7)
            .u64(5)
            .u64(8)
            .u64(1)
            .u64(2)
            .u64(3)
            .u32(nsec)
            .u32(0)
            .u32(0)
            .u32(mode)
            .u32(1)
            .u32(uid)
            .u32(uid)
            .u32(0)
            .u32(4096)
            .u32(0)
            .0
    }

    #[test]
    fn a_release_waits_while_its_connection_is_borrowed() {
        let c = Rc::new(RefCell::new(conn(Options::default())));
        let handle = Handle {
            conn: c.clone(),
            id: 1,
            nodeid: 5,
            fh: 9,
            open_flags: 0,
            flags: 0,
            dir: false,
            no_release: false,
        }
        .counted();
        let releases = |c: &Rc<RefCell<Conn>>| {
            let c = c.borrow();
            c.pending
                .iter()
                .filter(|u| c.requests[u].message[4..8] == op::RELEASE.to_le_bytes())
                .count()
        };
        // The last reference goes while the connection is borrowed: nothing is lost, only delayed
        let borrowed = c.borrow();
        drop(handle);
        drop(borrowed);
        assert_eq!(
            (c.borrow().opens.get(&5).copied(), releases(&c)),
            (Some(1), 0)
        );
        flush_released();
        assert_eq!((c.borrow().opens.get(&5).copied(), releases(&c)), (None, 1));
    }

    #[test]
    fn mount_options_follow_fuse_parse_param() {
        let cred = Cred::root();
        let o = Options::parse(
            b"ro,fd=3,rootmode=40000,user_id=1000,group_id=100,allow_other,max_read=65536",
            &cred,
        )
        .unwrap();
        assert_eq!(o.fd, Some(3));
        assert_eq!(o.rootmode, Some(mode::S_IFDIR));
        assert_eq!((o.user_id, o.group_id), (Some(1000), Some(100)));
        assert!(o.allow_other && !o.default_permissions);
        assert_eq!(
            o.show(&cred.user_ns),
            ",user_id=1000,group_id=100,allow_other,max_read=65536"
        );
        for bad in [
            &b"fd"[..],
            b"fd=x",
            b"bogus",
            b"rootmode=170000",
            b"subtype=a,subtype=b",
            b"blksize=4096",
            b"allow_other=1",
        ] {
            assert_eq!(
                Options::parse(bad, &cred).err(),
                Some(Errno::EINVAL),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn attributes_are_checked_and_mapped() {
        let ns = UserNs::init();
        let a = Attr::parse(
            &mut Fields::new(&attr_bytes(mode::S_IFREG | 0o644, 1000, 9)),
            &ns,
        )
        .unwrap();
        assert_eq!((a.ino, a.size, a.blocks, a.uid), (7, 5, 8, 1000));
        assert_eq!(a.atime_ns, 1_000_000_009);
        // No file type, or nanoseconds of a whole second or more, is EIO
        for (mode, nsec) in [(0o644, 0), (mode::S_IFREG, 1_000_000_000)] {
            let bytes = attr_bytes(mode, 0, nsec);
            assert_eq!(
                Attr::parse(&mut Fields::new(&bytes), &ns).err(),
                Some(Errno::EIO)
            );
        }
        assert_eq!(
            Attr::parse(&mut Fields::new(&[0; 40]), &ns).err(),
            Some(Errno::EIO)
        );
    }

    #[test]
    fn init_replies_set_what_was_negotiated() {
        // A reply of protocol 7.31 taking max_pages and a large max_write, and flags beyond the
        // offered ones ignored
        let mut c = conn(Options {
            max_read: u32::MAX,
            ..Options::default()
        });
        let reply = Args::default()
            .u32(7)
            .u32(31)
            .u32(0)
            .u32(init::MAX_PAGES | init::ATOMIC_O_TRUNC | 1 << 9 | 1)
            .u32(0)
            .u32(1 << 20)
            .u32(1)
            .u32(64)
            .0;
        init_reply(&mut c, Ok(reply));
        assert_eq!(c.state, InitState::Ready);
        assert_eq!(
            (c.minor, c.max_write, c.max_read),
            (31, 64 * 4096, 64 * 4096)
        );
        // FUSE_ASYNC_READ (bit 0) is not offered, so not taken either
        assert!(atomic_o_trunc(&c) && c.flags & (1 << 9 | 1) == 0);
        // An old daemon's eight-byte reply: 32 pages, writes of one page
        let mut c = conn(Options::default());
        init_reply(&mut c, Ok(Args::default().u32(7).u32(12).0));
        assert_eq!((c.state, c.max_write), (InitState::Ready, PAGE));
        // Another major version, or an error, refuses the connection
        let mut c = conn(Options::default());
        init_reply(&mut c, Ok(Args::default().u32(8).u32(0).0));
        assert_eq!(c.refusal(), Some(Errno::ECONNREFUSED));
        let mut c = conn(Options::default());
        init_reply(&mut c, Err(Errno::EIO));
        assert_eq!(c.refusal(), Some(Errno::ECONNREFUSED));
    }

    #[test]
    fn the_cache_keeps_entries_for_their_validity_and_the_syscall() {
        new_syscall();
        let mut f = Fuses::default();
        let root = f.add(Rc::new(RefCell::new(conn(Options {
            rootmode: Some(mode::S_IFDIR | 0o755),
            ..Options::default()
        }))));
        assert_eq!(f.cached_child(root, b"a"), None);
        let attr = |m| Attr {
            ino: 9,
            mode: m,
            nlink: 1,
            ..Attr::default()
        };
        // Fetched by this syscall: usable until it ends, though valid for no time at all
        let e = Entry {
            nodeid: 9,
            attr: attr(mode::S_IFDIR | 0o700),
            entry_until: None,
            attr_until: None,
        };
        let a = f.enter(root, b"a", &e).unwrap();
        assert_eq!(f.cached_child(root, b"a"), Some(Ok(a)));
        assert!(f.node(a).fresh_attr().is_some());
        f.enter_negative(root, b"gone", None);
        assert_eq!(f.cached_child(root, b"gone"), Some(Err(Errno::ENOENT)));
        // The same node id gives the same node, which a directory takes to its new place
        // A directory moving below itself is a loop
        assert_eq!(f.enter(a, b"b", &e), Err(Errno::ELOOP));
        assert_eq!(f.enter(root, b"b", &e), Ok(a));
        assert_eq!((f.node(a).parent, &f.node(a).name[..]), (root, &b"b"[..]));
        f.moved(a, a, b"self");
        assert_eq!(&f.node(a).name[..], b"b");
        f.moved(a, root, b"c");
        assert_eq!((f.node(a).parent, &f.node(a).name[..]), (root, &b"c"[..]));
        // The next syscall needs everything again, except what is still valid
        new_syscall();
        assert_eq!(f.cached_child(root, b"a"), None);
        assert!(f.node(a).fresh_attr().is_none());
        let long = Instant::now().checked_add(Duration::from_secs(60));
        f.set_attr(a, attr(mode::S_IFREG | 0o600), long);
        new_syscall();
        // Valid for a minute; the type stays the node's
        assert_eq!(
            f.node(a).fresh_attr().map(|a| a.mode),
            Some(mode::S_IFDIR | 0o600)
        );
        f.stale(a);
        assert!(f.node(a).fresh_attr().is_none());
        f.remove(0x30);
        assert!(f.get(a).is_none() && f.root_of(0x30).is_none());
    }

    #[test]
    fn nodes_nothing_uses_are_forgotten_with_their_lookups() {
        new_syscall();
        let mut f = Fuses::default();
        let c = Rc::new(RefCell::new(conn(Options::default())));
        c.borrow_mut().minor = 37;
        let root = f.add(c.clone());
        let entry = |nodeid, m| Entry {
            nodeid,
            attr: Attr {
                ino: nodeid,
                mode: m,
                nlink: 1,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };
        let d = f.enter(root, b"d", &entry(2, mode::S_IFDIR)).unwrap();
        let x = f.enter(d, b"x", &entry(3, mode::S_IFREG)).unwrap();
        // Looked up twice, under two names (a hard link)
        assert_eq!(f.enter(root, b"y", &entry(3, mode::S_IFREG)), Ok(x));
        let o = f.enter(root, b"o", &entry(4, mode::S_IFREG)).unwrap();
        let p = f.enter(d, b"p", &entry(5, mode::S_IFREG)).unwrap();
        // Below the limit nothing goes, unless dropping caches
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        // An open handle and a request in flight keep their nodes, a kept node its directory
        let h = Handle {
            conn: c.clone(),
            id: o,
            nodeid: 4,
            fh: 1,
            open_flags: 0,
            flags: 0,
            dir: false,
            no_release: true,
        }
        .counted();
        c.borrow_mut()
            .queue(op::GETATTR, 5, None, &[], (false, false));
        assert_eq!(f.evict(&HashSet::from([x]), true), 0);
        assert!([d, x, o, p].iter().all(|&id| f.get(id).is_some()));
        // Leaves first, then the directory left empty
        c.borrow_mut().requests.clear();
        drop(h);
        assert_eq!(f.evict(&HashSet::new(), true), 4);
        assert!(f.get(root).is_some() && f.nodes.len() == 1);
        assert_eq!(f.cached_child(root, b"y"), None);
        let mut forgets: Vec<_> = c.borrow().forgets.iter().copied().collect();
        forgets.sort_unstable();
        assert_eq!(forgets, [(2, 1), (3, 2), (4, 1), (5, 1)]);
        // Several go in one FUSE_BATCH_FORGET, one alone in a FUSE_FORGET
        let m = c.borrow_mut().read_forget(8192);
        assert_eq!(
            &m[..8],
            &[48 + 64, 0, 0, 0, op::BATCH_FORGET as u8, 0, 0, 0]
        );
        assert_eq!(u32::from_le_bytes(m[40..44].try_into().unwrap()), 4);
        // The node id is a new node once looked up again
        let x2 = f.enter(root, b"y", &entry(3, mode::S_IFREG)).unwrap();
        assert_ne!(x2, x);
        f.evict(&HashSet::new(), true);
        let m = c.borrow_mut().read_forget(8192);
        assert_eq!(&m[..8], &[48, 0, 0, 0, op::FORGET as u8, 0, 0, 0]);
        assert_eq!(&m[16..24], &3u64.to_le_bytes());
        assert_eq!(&m[40..48], &1u64.to_le_bytes());
    }

    #[test]
    fn a_node_dropping_caches_kept_for_its_release_goes_when_the_release_ends() {
        new_syscall();
        let mut f = Fuses::default();
        let c = Rc::new(RefCell::new(conn(Options::default())));
        c.borrow_mut().minor = 37;
        let root = f.add(c.clone());
        let entry = |nodeid| Entry {
            nodeid,
            attr: Attr {
                ino: nodeid,
                mode: mode::S_IFREG,
                nlink: 1,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };
        let a = f.enter(root, b"a", &entry(3)).unwrap();
        let b = f.enter(root, b"b", &entry(4)).unwrap();
        // Both closed, their releases not yet answered: dropping caches keeps them but drops
        // their names
        let release = |c: &Rc<RefCell<Conn>>, nodeid| {
            c.borrow_mut()
                .queue(op::RELEASE, nodeid, None, &[0; 24], (true, false))
        };
        let ra = release(&c, 3);
        release(&c, 4);
        assert_eq!(f.evict(&HashSet::new(), true), 0);
        assert!(f.get(a).is_some() && f.get(b).is_some());
        assert_eq!(f.cached_child(root, b"a"), None);
        assert_eq!(c.borrow().doomed, HashSet::from([3, 4]));
        // Looked up again before its release ends, b is saved
        assert_eq!(f.enter(root, b"b", &entry(4)), Ok(b));
        assert_eq!(c.borrow().doomed, HashSet::from([3]));
        // a goes at the first sweep after its release is answered, without dropping caches
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        c.borrow_mut().requests.remove(&ra);
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(a).is_none() && f.get(b).is_some());
        assert!(c.borrow().doomed.is_empty());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(3, 1)]
        );
        c.borrow_mut().requests.clear();
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        assert!(f.get(b).is_some());
    }

    pub(crate) static SWEEP_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn live_working_set_above_nodes_max_backs_off_and_recovers() {
        let _guard = SWEEP_TEST.lock().unwrap_or_else(|e| e.into_inner());
        SWEEP.store(false, Ordering::Relaxed);
        DROP.store(false, Ordering::Relaxed);
        new_syscall();
        let mut f = Fuses::default();
        let c = Rc::new(RefCell::new(conn(Options::default())));
        c.borrow_mut().minor = 37;
        let root = f.add(c.clone());
        let entry = |nodeid| Entry {
            nodeid,
            attr: Attr {
                ino: nodeid,
                mode: mode::S_IFREG | 0o644,
                nlink: 1,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };
        let mut keep = HashSet::new();
        // Enter NODES_MAX - 1 children (total NODES_MAX with root): no sweep yet.
        let mut next_nodeid = 2u64;
        for _ in 0..NODES_MAX - 1 {
            let name = next_nodeid.to_le_bytes();
            let id = f.enter(root, &name, &entry(next_nodeid)).unwrap();
            keep.insert(id);
            next_nodeid += 1;
        }
        assert_eq!(f.nodes.len(), NODES_MAX);
        assert!(!SWEEP.load(Ordering::Relaxed));

        // Crossing NODES_MAX requests a sweep once.
        let id = f
            .enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
            .unwrap();
        keep.insert(id);
        next_nodeid += 1;
        assert_eq!(f.nodes.len(), NODES_MAX + 1);
        assert!(SWEEP.swap(false, Ordering::Relaxed));

        // Nothing can be evicted because all nodes are live: sweep_at backs off with headroom.
        assert_eq!(f.evict(&keep, false), 0);
        let first_backoff = f.sweep_at;
        assert_eq!(first_backoff, Fuses::next_sweep_at(NODES_MAX + 1));
        assert!(first_backoff >= NODES_MAX + 1 + NODES_HEADROOM);

        // Entering additional live nodes up to sweep_at must NOT trigger redundant sweeps.
        while f.nodes.len() < first_backoff {
            let id = f
                .enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
                .unwrap();
            keep.insert(id);
            next_nodeid += 1;
            assert!(!SWEEP.load(Ordering::Relaxed));
        }

        // Crossing the backed-off threshold requests a sweep once, then backs off again.
        let id = f
            .enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
            .unwrap();
        keep.insert(id);
        next_nodeid += 1;
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&keep, false), 0);
        let second_backoff = f.sweep_at;
        assert!(second_backoff > first_backoff);

        // Once live nodes become unused, entering past the backed-off threshold triggers eviction
        // down to NODES_TARGET and resets sweep_at back to NODES_MAX.
        keep.clear();
        while f.nodes.len() < second_backoff {
            f.enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
                .unwrap();
            next_nodeid += 1;
            assert!(!SWEEP.load(Ordering::Relaxed));
        }
        f.enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
            .unwrap();
        next_nodeid += 1;
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        let before = f.nodes.len();
        let evicted = f.evict(&keep, false);
        assert_eq!(evicted, before - NODES_TARGET);
        assert_eq!(f.nodes.len(), NODES_TARGET);
        assert_eq!(f.sweep_at, NODES_MAX);
        assert_eq!(c.borrow().forgets.len(), evicted);
        c.borrow_mut().forgets.clear();

        // drop_caches also resets a backed-off threshold when pinned nodes are released.
        for _ in 0..NODES_MAX {
            let id = f
                .enter(root, &next_nodeid.to_le_bytes(), &entry(next_nodeid))
                .unwrap();
            keep.insert(id);
            next_nodeid += 1;
        }
        SWEEP.store(false, Ordering::Relaxed);
        f.evict(&keep, false);
        assert!(f.sweep_at > NODES_MAX);
        drop_caches(2);
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert!(DROP.swap(false, Ordering::Relaxed));
        let dropped = f.evict(&HashSet::new(), true);
        assert_eq!(dropped, NODES_MAX);
        assert_eq!(f.nodes.len(), 1);
        assert_eq!(f.sweep_at, NODES_MAX);
    }

    #[test]
    fn unlinked_unused_nodes_are_forgotten_promptly() {
        let _guard = SWEEP_TEST.lock().unwrap_or_else(|e| e.into_inner());
        SWEEP.store(false, Ordering::Relaxed);
        new_syscall();
        let mut f = Fuses::default();
        let c = Rc::new(RefCell::new(conn(Options::default())));
        c.borrow_mut().minor = 37;
        let root = f.add(c.clone());
        let mut dev = DevFile::new(&Cred::root(), 1);
        dev.attach(&c);
        let entry = |nodeid, m, nlink| Entry {
            nodeid,
            attr: Attr {
                ino: nodeid,
                mode: m,
                nlink,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };

        // Regular file with nlink == 1: unlinking forgets it at the next sweep well below NODES_MAX.
        let a = f
            .enter(root, b"a", &entry(2, mode::S_IFREG | 0o644, 1))
            .unwrap();
        f.forget_child(root, b"a");
        f.stale(a);
        assert!(f.unlinked(a, false));
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(a).is_none());
        assert!(c.borrow().doomed.is_empty());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(2, 1)]
        );
        // Queued forgets make /dev/fuse readable for poll/epoll-based daemons.
        assert_ne!(dev.readiness() & 1, 0);
        let _ = c.borrow_mut().read_forget(8192);
        assert_eq!(dev.readiness() & 1, 0);

        // Hard-linked file (nlink == 2): unlinking the first link decrements nlink and keeps it,
        // and unlinking the second link dooms and forgets it with both lookups returned.
        let b = f
            .enter(root, b"b1", &entry(3, mode::S_IFREG | 0o644, 2))
            .unwrap();
        assert_eq!(
            f.enter(root, b"b2", &entry(3, mode::S_IFREG | 0o644, 2)),
            Ok(b)
        );
        f.forget_child(root, b"b1");
        f.stale(b);
        assert!(!f.unlinked(b, false));
        assert!(!SWEEP.load(Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        assert!(f.get(b).is_some());

        f.forget_child(root, b"b2");
        f.stale(b);
        assert!(f.unlinked(b, false));
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(b).is_none());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(3, 2)]
        );
        c.borrow_mut().forgets.clear();

        // rmdir forgets the directory even when nlink >= 2, along with any stale unused child.
        let d = f
            .enter(root, b"d", &entry(4, mode::S_IFDIR | 0o755, 2))
            .unwrap();
        let stale_child = f
            .enter(d, b"ghost", &entry(5, mode::S_IFREG | 0o644, 1))
            .unwrap();
        f.forget_child(root, b"d");
        f.stale(d);
        assert!(f.unlinked(d, true));
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 2);
        assert!(f.get(d).is_none() && f.get(stale_child).is_none());
        let mut forgets: Vec<_> = c.borrow().forgets.iter().copied().collect();
        forgets.sort_unstable();
        assert_eq!(forgets, [(4, 1), (5, 1)]);
    }

    #[test]
    fn unlinked_open_and_pinned_nodes_stay_alive_until_released() {
        let _guard = SWEEP_TEST.lock().unwrap_or_else(|e| e.into_inner());
        SWEEP.store(false, Ordering::Relaxed);
        new_syscall();
        let mut f = Fuses::default();
        let c = Rc::new(RefCell::new(conn(Options::default())));
        c.borrow_mut().minor = 37;
        let root = f.add(c.clone());
        let entry = |nodeid, m| Entry {
            nodeid,
            attr: Attr {
                ino: nodeid,
                mode: m,
                nlink: 1,
                ..Attr::default()
            },
            entry_until: None,
            attr_until: None,
        };

        // Open file (normal FUSE_RELEASE): stays alive while open and while RELEASE is in flight,
        // does not trigger sweeps on I/O while open, and is forgotten once RELEASE is answered.
        let f1 = f.enter(root, b"f1", &entry(10, mode::S_IFREG)).unwrap();
        let h1 = Handle {
            conn: c.clone(),
            id: f1,
            nodeid: 10,
            fh: 1,
            open_flags: 0,
            flags: 0,
            dir: false,
            no_release: false,
        }
        .counted();
        f.forget_child(root, b"f1");
        assert!(f.unlinked(f1, false));
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::from([f1]), false), 0);
        assert!(f.get(f1).is_some() && c.borrow().forgets.is_empty());
        assert!(c.borrow().doomed.contains(&10));

        // Finishing an I/O request while still open does not trigger a redundant sweep.
        let read_u = c
            .borrow_mut()
            .queue(op::READ, 10, None, &[], (false, false));
        {
            let mut c = c.borrow_mut();
            let req = c.requests.remove(&read_u).unwrap();
            c.note_request_done(&req.message);
            c.pending.retain(|&u| u != read_u);
        }
        assert!(!SWEEP.load(Ordering::Relaxed));

        // Closing queues FUSE_RELEASE; node stays alive until the daemon answers RELEASE.
        drop(h1);
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        assert!(f.get(f1).is_some() && c.borrow().forgets.is_empty());
        {
            let mut c = c.borrow_mut();
            let rel_u = c.pending.pop_front().unwrap();
            let req = c.requests.remove(&rel_u).unwrap();
            assert_eq!(req.message[4..8], op::RELEASE.to_le_bytes());
            c.note_request_done(&req.message);
        }
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(f1).is_none());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(10, 1)]
        );
        c.borrow_mut().forgets.clear();

        // Open file with no_release (FUSE_NO_OPEN_SUPPORT): closing schedules a sweep immediately.
        let f2 = f.enter(root, b"f2", &entry(11, mode::S_IFREG)).unwrap();
        let h2 = Handle {
            conn: c.clone(),
            id: f2,
            nodeid: 11,
            fh: 0,
            open_flags: fopen::KEEP_CACHE,
            flags: 0,
            dir: false,
            no_release: true,
        }
        .counted();
        f.forget_child(root, b"f2");
        assert!(f.unlinked(f2, false));
        SWEEP.store(false, Ordering::Relaxed);
        assert_eq!(f.evict(&HashSet::from([f2]), false), 0);
        assert!(f.get(f2).is_some());
        drop(h2);
        assert!(SWEEP.swap(false, Ordering::Relaxed));
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(f2).is_none());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(11, 1)]
        );
        c.borrow_mut().forgets.clear();

        // O_PATH pin keeps an unlinked node alive until dropped.
        let f3 = f.enter(root, b"f3", &entry(12, mode::S_IFREG)).unwrap();
        let pin = f.get_mut(f3).unwrap().pin_path();
        f.forget_child(root, b"f3");
        assert!(f.unlinked(f3, false));
        SWEEP.store(false, Ordering::Relaxed);
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        assert!(f.get(f3).is_some());
        drop(pin);
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(f3).is_none());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(12, 1)]
        );
        c.borrow_mut().forgets.clear();

        // cwd / mount / watch in `keep` keeps an unlinked node alive until released.
        let f4 = f.enter(root, b"f4", &entry(13, mode::S_IFDIR)).unwrap();
        f.forget_child(root, b"f4");
        assert!(f.unlinked(f4, true));
        SWEEP.store(false, Ordering::Relaxed);
        assert_eq!(f.evict(&HashSet::from([f4]), false), 0);
        assert!(f.get(f4).is_some());
        assert_eq!(f.evict(&HashSet::new(), false), 1);
        assert!(f.get(f4).is_none());
        assert_eq!(
            c.borrow().forgets.iter().copied().collect::<Vec<_>>(),
            [(13, 1)]
        );
        c.borrow_mut().forgets.clear();

        // Daemon reusing a doomed node id for a different file type does not doom the new node.
        let f5 = f.enter(root, b"f5", &entry(14, mode::S_IFREG)).unwrap();
        let _h5 = Handle {
            conn: c.clone(),
            id: f5,
            nodeid: 14,
            fh: 2,
            open_flags: 0,
            flags: 0,
            dir: false,
            no_release: true,
        }
        .counted();
        assert!(f.unlinked(f5, false));
        assert!(c.borrow().doomed.contains(&14));
        let f6 = f.enter(root, b"f6", &entry(14, mode::S_IFDIR)).unwrap();
        assert_ne!(f6, f5);
        assert!(!c.borrow().doomed.contains(&14));
        assert_eq!(f.evict(&HashSet::new(), false), 0);
        assert!(f.get(f6).is_some());
    }
}
