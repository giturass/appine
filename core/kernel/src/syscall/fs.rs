//! File and directory syscalls (the kernel/vfs map; fd tables, opening and control: the
//! kernel/files map; data I/O, clones, truncation and syncing: the kernel/fileio map; overlay
//! paths: the kernel/overlay map; flock and fcntl locks: the kernel/locks map; pipes, FIFOs and
//! splice: the kernel/pipe map).
//!
//! Reads and writes have two layers: `read_bytes`/`write_bytes` do one operation on an open file
//! with a host buffer, and `read_file`/`write_file` copy to and from guest memory. Host fds and
//! pipes may block; while blocked they release the BKL and hold no borrow of any open file (other
//! threads may be using the same open file).

use std::io::Write;
use std::os::unix::fs::FileExt;
use std::rc::{Rc, Weak};
use std::time::Duration;

use super::SocketRef;
use super::{FUSE_CHUNK, IO_CHUNK, MAX_COPY, SysResult, get, inotify, put, read_path, tty};
use crate::cell::RefCell;
use crate::cred::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE, cap};
use crate::errno::Errno;
use crate::fd::{EventFd, FileKind, FileRef, OpenFile, TimerFd, oflags};
use crate::kernel::{Cx, Kernel, Tid, request_wake_locks, request_wake_object, wake};
use crate::locks::{self, Lock, LockKey, Owner, Waiter};
use crate::pipe::{PIPE_BUF, PIPE_CAPACITY, PIPE_DEV, Pipe, PipeEnd};
use crate::process::{RLIMIT_FSIZE, Signal};
use crate::pseudo::{self, PseudoNode};
use crate::signal::{self, SigInfo};
use crate::tty::{PTS_MAJOR, Tty};
use crate::uaccess::UserSlice;
use crate::vfs::dev::{self, Device, rdev};
use crate::vfs::overlay::{self, CopyUp, OvlId};
use crate::vfs::store::{DirEntry, FileTime, Ino, Stat, Store, inode_flags, mode};
use crate::vfs::{AnonTarget, Dentry, Fs, MountId, Node, Pseudo, TMPFS_PAGE, Vfs, ms, normalize};

pub(super) const AT_FDCWD: i32 = -100;
pub(super) const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_REMOVEDIR: u32 = 0x200;
const AT_EACCESS: u32 = 0x200;
const AT_SYMLINK_FOLLOW: u32 = 0x400;
const AT_NO_AUTOMOUNT: u32 = 0x800;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_STATX_SYNC_TYPE: u32 = 0x6000;

const F_DUPFD: u32 = 0;
const F_GETFD: u32 = 1;
const F_SETFD: u32 = 2;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;
const F_GETLK: u32 = 5;
const F_SETLK: u32 = 6;
const F_SETLKW: u32 = 7;
const F_OFD_GETLK: u32 = 36;
const F_OFD_SETLK: u32 = 37;
const F_OFD_SETLKW: u32 = 38;
const F_SETOWN: u32 = 8;
const F_GETOWN: u32 = 9;
const F_SETSIG: u32 = 10;
const F_GETSIG: u32 = 11;
const F_SETOWN_EX: u32 = 15;
const F_GETOWN_EX: u32 = 16;
const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;
const F_SETLEASE: u32 = 1024;
const F_GETLEASE: u32 = 1025;
const F_DUPFD_CLOEXEC: u32 = 1030;
const F_SETPIPE_SZ: u32 = 1031;
const F_GETPIPE_SZ: u32 = 1032;
const F_ADD_SEALS: u32 = 1033;
const F_GET_SEALS: u32 = 1034;
const FD_CLOEXEC: u64 = 1;

/// memfd seals.
const F_SEAL_SEAL: u32 = 0x1;
const F_SEAL_SHRINK: u32 = 0x2;
const F_SEAL_GROW: u32 = 0x4;
const F_SEAL_WRITE: u32 = 0x8;
const F_SEAL_FUTURE_WRITE: u32 = 0x10;
const F_SEAL_EXEC: u32 = 0x20;
const F_SEAL_ALL: u32 = 0x3f;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

const SEEK_SET: u32 = 0;
const SEEK_CUR: u32 = 1;
const SEEK_END: u32 = 2;
const SEEK_DATA: u32 = 3;
const SEEK_HOLE: u32 = 4;

const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

const UTIME_NOW: i64 = (1 << 30) - 1;
const UTIME_OMIT: i64 = (1 << 30) - 2;

const CLOSE_RANGE_UNSHARE: u32 = 2;
const CLOSE_RANGE_CLOEXEC: u32 = 4;

/// The most iovecs readv/writev accept (`UIO_MAXIOV`).
const UIO_MAXIOV: usize = 1024;

pub(super) use crate::vfs::ROOT_DEV;
/// Device number sockets and anon_inodes (epoll, eventfd) report.
const SOCK_DEV: u64 = 0x8;
const ANON_DEV: u64 = 0xe;
/// Filesystem types statfs reports.
const EXT4_SUPER_MAGIC: u64 = 0xef53;
const MQUEUE_MAGIC: u64 = 0x1980_0202;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const NSFS_MAGIC: u64 = 0x6e73_6673;
const PIPEFS_MAGIC: u64 = 0x5049_5045;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;
const DEVPTS_SUPER_MAGIC: u64 = 0x1cd1;
const SYSFS_MAGIC: u64 = 0x6265_6572;
const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c_7630;
/// Device number of the PTY master device (`/dev/ptmx`).
const PTMX_RDEV: u64 = rdev(5, 2);

/// ioctls that can be passed through to a host fd (the terminal, or the pipe or file `appine-run`
/// was given): number, argument size, whether the argument is an output.
const HOST_IOCTLS: [(u32, usize, bool); 15] = [
    (0x5401, 36, true),       // TCGETS
    (0x5402, 36, false),      // TCSETS
    (0x5403, 36, false),      // TCSETSW
    (0x5404, 36, false),      // TCSETSF
    (0x5405, 18, true),       // TCGETA
    (0x5406, 18, false),      // TCSETA
    (0x5407, 18, false),      // TCSETAW
    (0x5408, 18, false),      // TCSETAF
    (0x5413, 8, true),        // TIOCGWINSZ
    (0x5414, 8, false),       // TIOCSWINSZ
    (0x802c_542a, 44, true),  // TCGETS2
    (0x402c_542b, 44, false), // TCSETS2
    (0x402c_542c, 44, false), // TCSETSW2
    (0x402c_542d, 44, false), // TCSETSF2
    (FIONREAD, 4, true),
];
const FIONREAD: u32 = 0x541b;
const RNDGETENTCNT: u32 = 0x8004_5200;
const RNDADDTOENTCNT: u32 = 0x4004_5201;
const RNDADDENTROPY: u32 = 0x4008_5203;
const RNDZAPENTCNT: u32 = 0x5204;
const RNDCLEARPOOL: u32 = 0x5206;
const RNDRESEEDCRNG: u32 = 0x5207;
/// Number of bits in the entropy pool (`/proc/sys/kernel/random/entropy_avail`).
pub(crate) const ENTROPY: i32 = 256;

/// ioctls of `/dev/random` and `/dev/urandom` (Linux 6.1's `random_ioctl`). Random numbers come
/// from the host, and as on Linux since 5.18 the entropy pool is always full: added data and
/// entropy only have their arguments checked and are read once, with no effect (seedrng adds the
/// seed saved last time back with `RNDADDENTROPY` at boot). Changing the entropy pool needs
/// `CAP_SYS_ADMIN` in the initial namespace; unknown requests are EINVAL (tty requests too, not
/// ENOTTY, as on Linux).
fn random_ioctl(cx: &mut Cx<'_>, request: u32, arg: u64) -> SysResult {
    let admin = || {
        if cx.cred().capable(cap::SYS_ADMIN) {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    };
    match request {
        RNDGETENTCNT => put(cx, arg, ENTROPY.to_le_bytes()).map(|()| 0),
        RNDADDTOENTCNT => {
            admin()?;
            if i32::from_le_bytes(get(cx, arg)?) < 0 {
                return Err(Errno::EINVAL);
            }
            Ok(0)
        }
        // struct rand_pool_info: entropy bit count, data byte count, then the data; all of the
        // data must be readable
        RNDADDENTROPY => {
            admin()?;
            if i32::from_le_bytes(get(cx, arg)?) < 0 {
                return Err(Errno::EINVAL);
            }
            let len = i32::from_le_bytes(get(cx, arg + 4)?);
            let len = usize::try_from(len).map_err(|_| Errno::EFAULT)?;
            let mut buf = [0u8; 4096];
            let mut done = 0;
            while done < len {
                let n = (len - done).min(buf.len());
                cx.mm()
                    .read(UserSlice::new(arg + 8 + done as u64, n), &mut buf[..n])?;
                done += n;
            }
            Ok(0)
        }
        RNDZAPENTCNT | RNDCLEARPOOL | RNDRESEEDCRNG => admin().map(|()| 0),
        _ => Err(Errno::EINVAL),
    }
}
const FIONBIO: u32 = 0x5421;
const FIOASYNC: u32 = 0x5452;
const FIOSETOWN: u32 = 0x8901;
const SIOCSPGRP: u32 = 0x8902;
const FIOGETOWN: u32 = 0x8903;
const SIOCGPGRP: u32 = 0x8904;
const FIONCLEX: u32 = 0x5450;
const FIOCLEX: u32 = 0x5451;
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FICLONE: u32 = 0x4004_9409;
const FICLONERANGE: u32 = 0x4020_940d;
const FIDEDUPERANGE: u32 = 0xc018_9436;

const POLLIN: i16 = 0x001;
const POLLOUT: i16 = 0x004;

// ---- Opening, closing, duplicating ----

/// The status flags an open file keeps from open, as Linux keeps them in `f_flags`: F_GETFL
/// shows them, and `O_DSYNC`/`O_SYNC` make every write wait for the disk ([`write_sync`]).
const KEPT_AT_OPEN: u32 = oflags::O_ACCMODE
    | oflags::O_APPEND
    | oflags::O_NONBLOCK
    | oflags::O_PATH
    | oflags::O_DSYNC
    | oflags::O_SYNC_BIT
    | oflags::O_ASYNC
    | oflags::O_DIRECT
    | oflags::O_NOATIME
    | oflags::O_DIRECTORY
    | oflags::O_NOFOLLOW
    | oflags::O_TMPFILE_BIT;

/// The status flags an open file keeps from `flags`: with `O_PATH` only `O_PATH`, `O_DIRECTORY`
/// and `O_NOFOLLOW` (Linux's `build_open_flags` drops the access mode and every other flag but
/// `O_CLOEXEC`), otherwise [`KEPT_AT_OPEN`].
fn kept(flags: u32) -> u32 {
    if flags & oflags::O_PATH != 0 {
        oflags::O_PATH | oflags::O_DIRECTORY | oflags::O_NOFOLLOW
    } else {
        KEPT_AT_OPEN
    }
}

/// Type and length in a file handle (`struct file_handle`): the handle is the store inode
/// number.
const FILE_HANDLE_TYPE: i32 = 1;
const FILE_HANDLE_BYTES: u32 = 8;
/// Type written back when the handle does not fit (Linux's `FILEID_INVALID`).
const FILEID_INVALID: i32 = 255;
const MAX_HANDLE_SZ: u32 = 128;
const AT_HANDLE_FID: u32 = 0x200;

pub(super) fn openat(cx: &mut Cx<'_>, dirfd: i32, path: u64, flags: u32, perm: u32) -> SysResult {
    // Legacy open ignores the tmpfile bit when O_PATH is set.
    if flags & oflags::O_PATH == 0 {
        validate_tmpfile_flags(flags)?;
    }
    let path = read_path(cx, path)?;
    let file = open_path(cx, dirfd, path, flags, perm)?;
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

fn validate_tmpfile_flags(flags: u32) -> Result<(), Errno> {
    if flags & oflags::O_TMPFILE_BIT != 0
        && (flags & (oflags::O_TMPFILE | oflags::O_CREAT) != oflags::O_TMPFILE
            || flags & oflags::O_ACCMODE == oflags::O_RDONLY)
    {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// openat2 (Linux 6.1's `fs/open.c`): the flags, mode and resolve of `struct open_how`. Unlike
/// openat, unknown flags and a mode that should not be there are EINVAL, and path resolution
/// carries the `resolve` restrictions ([`crate::vfs::resolve`]).
pub(super) fn openat2(cx: &mut Cx<'_>, dirfd: i32, path: u64, how: u64, size: usize) -> SysResult {
    use crate::vfs::resolve;
    const OPEN_HOW_SIZE_VER0: usize = 24;
    /// `FMODE_NONOTIFY`: user space should not pass it; it is removed along with `O_CLOEXEC`
    /// and is not an error.
    const FMODE_NONOTIFY: u64 = 0x400_0000;
    const O_SYNC_BIT: u64 = oflags::O_SYNC_BIT as u64;
    const O_DSYNC: u64 = oflags::O_DSYNC as u64;
    const O_NOATIME: u64 = oflags::O_NOATIME as u64;
    const O_TMPFILE_BIT: u64 = oflags::O_TMPFILE_BIT as u64;
    const VALID_OPEN_FLAGS: u64 = (oflags::O_ACCMODE
        | oflags::O_CREAT
        | oflags::O_EXCL
        | oflags::O_NOCTTY
        | oflags::O_TRUNC
        | oflags::O_APPEND
        | oflags::O_NONBLOCK
        | oflags::O_ASYNC
        | oflags::O_DIRECT
        | oflags::O_LARGEFILE
        | oflags::O_DIRECTORY
        | oflags::O_NOFOLLOW
        | oflags::O_CLOEXEC
        | oflags::O_PATH) as u64
        | O_SYNC_BIT
        | O_DSYNC
        | O_NOATIME
        | O_TMPFILE_BIT;
    const O_PATH_FLAGS: u64 =
        (oflags::O_DIRECTORY | oflags::O_NOFOLLOW | oflags::O_PATH | oflags::O_CLOEXEC) as u64;
    if size < OPEN_HOW_SIZE_VER0 {
        return Err(Errno::EINVAL);
    }
    if size > 4096 {
        return Err(Errno::E2BIG);
    }
    // copy_struct_from_user: anything past 24 bytes must be all zero (fields added by later
    // versions)
    let mut raw = vec![0u8; size];
    cx.mm().read(UserSlice::new(how, size), &mut raw)?;
    if raw[OPEN_HOW_SIZE_VER0..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let field = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (mut flags, mode, res) = (field(0), field(1), field(2));
    // O_LARGEFILE is added only without O_PATH
    if flags & oflags::O_PATH as u64 == 0 {
        flags |= oflags::O_LARGEFILE as u64;
    }
    // The checks of build_open_flags, in its order
    let f = flags & !(oflags::O_CLOEXEC as u64 | FMODE_NONOTIFY);
    if f & !VALID_OPEN_FLAGS != 0 || res & !resolve::ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if res & resolve::SCOPED == resolve::SCOPED {
        return Err(Errno::EINVAL);
    }
    let will_create = f & (oflags::O_CREAT as u64 | O_TMPFILE_BIT) != 0;
    if (will_create && mode & !0o7777 != 0) || (!will_create && mode != 0) {
        return Err(Errno::EINVAL);
    }
    validate_tmpfile_flags(f as u32)?;
    if f & oflags::O_PATH as u64 != 0 && f & !O_PATH_FLAGS != 0 {
        return Err(Errno::EINVAL);
    }
    // RESOLVE_CACHED: creation, truncation and O_TMPFILE (which includes O_DIRECTORY, so
    // O_DIRECTORY counts too) are not tried; everything else resolves as usual, since Appine's
    // resolution waits for nothing but host I/O
    let busy = (oflags::O_TRUNC | oflags::O_CREAT | oflags::O_DIRECTORY) as u64 | O_TMPFILE_BIT;
    if res & resolve::CACHED != 0 && f & busy != 0 {
        return Err(Errno::EAGAIN);
    }
    let path = read_path(cx, path)?;
    let flags = flags as u32;
    let file = open_path_with(cx, dirfd, path, flags, mode as u32, res)?;
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

/// The kernel creates a file itself (core dump): relative to the current directory, EEXIST when
/// it already exists, symlinks not followed, opened write-only.
pub(crate) fn create_exclusive(cx: &mut Cx<'_>, path: &[u8], perm: u32) -> Result<FileRef, Errno> {
    let flags = oflags::O_CREAT | oflags::O_EXCL | oflags::O_NOFOLLOW | oflags::O_WRONLY;
    open_path(cx, AT_FDCWD, path.to_vec(), flags, perm)
}

/// The kernel deletes a file itself (the old file of the same name before a core dump), relative
/// to the current directory.
pub(crate) fn unlink_path(cx: &mut Cx<'_>, path: &[u8]) -> Result<(), Errno> {
    unlink(cx, AT_FDCWD, path.to_vec(), 0)
}

/// The kernel writes an open file itself at `offset` (core dump), as pwrite does.
pub(crate) fn write_at(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    offset: u64,
) -> Result<usize, Errno> {
    write_bytes(cx, file, data, Some(offset))
}

/// Opens (or creates) `path` for openat, not yet put in the fd table.
fn open_path(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: Vec<u8>,
    flags: u32,
    perm: u32,
) -> Result<FileRef, Errno> {
    open_path_with(cx, dirfd, path, flags, perm, 0)
}

/// [`open_path`], with path resolution carrying openat2's restrictions ([`crate::vfs::resolve`]).
fn open_path_with(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: Vec<u8>,
    flags: u32,
    perm: u32,
    res: u64,
) -> Result<FileRef, Errno> {
    use crate::vfs::resolve;
    let vfs = cx.vfs()?;
    let (start, root) = if res == 0 {
        (start_dir(cx, dirfd, &path)?, cx.root())
    } else {
        openat2_start(cx, dirfd, &path, res)?
    };
    let path_only = flags & oflags::O_PATH != 0;
    let create = !path_only && flags & oflags::O_CREAT != 0;
    let excl = create && flags & oflags::O_EXCL != 0;
    let follow = flags & oflags::O_NOFOLLOW == 0 && !excl;
    let cred = cx.cred();

    let view = pseudo::View {
        opening: true,
        ..cx.view(&vfs)
    };
    let resolved = vfs.walk_resolve(&view, &cred, &root, &start, &path, follow, res);
    if !path_only && flags & oflags::O_TMPFILE_BIT != 0 {
        let (dir, _) = resolved?;
        return open_tmpfile(cx, &vfs, &cred, &dir, (&start, &path), flags, perm);
    }
    // A queue was created in the mqueue filesystem (open permission is not checked again, as for
    // files just created in the store)
    let mut mq_created = false;
    // A file was created and opened in a FUSE filesystem
    let mut fuse_created = None;
    // parent is the last directory and name passed through, for reporting inotify events
    let mut unlinked_name = false;
    let (mut node, created, parent) = match resolved {
        Ok(_) if excl => return Err(Errno::EEXIST),
        Ok((node, found)) => {
            if create {
                may_create_in_sticky(cx, &vfs, &cred, &node, found.as_ref().map(|d| &d.entry.0))?;
            }
            unlinked_name = found.as_ref().is_some_and(|d| d.unlinked);
            (node, None, found.map(|d| d.entry))
        }
        Err(e) if e == Errno::ENOENT && create => {
            // When the last component is a dangling symlink, follow it and create the target
            // file, as on Linux
            let mut root_set = path.first() == Some(&b'/')
                || res & resolve::SCOPED != 0
                || path.split(|&b| b == b'/').any(|c| c == b"..");
            let (mut start, mut path) = (start.clone(), path.clone());
            let mut links = 0;
            loop {
                let (dir, name) =
                    vfs.resolve_parent_with(&cx.view(&vfs), &cred, &root, &start, &path, res)?;
                if path.ends_with(b"/") || name == b"." || name == b".." {
                    return Err(Errno::EISDIR);
                }
                // In the mqueue filesystem a message queue is created (Linux's mqueue_create),
                // with default attributes
                if let Node::Pseudo(mnt, PseudoNode::MqRoot(ns)) = dir {
                    if vfs.readonly(&dir) {
                        return Err(Errno::EROFS);
                    }
                    if flags & oflags::O_DIRECTORY != 0 {
                        return Err(Errno::ENOTDIR);
                    }
                    cx.fds().free_slot(0..cx.nofile())?;
                    let ipc = cx.kr().ipc(ns);
                    let dir_st = ipc.mq_dir.borrow().stat(ipc.mqueues.len());
                    cred.permission(&dir_st, MAY_WRITE | MAY_EXEC)?;
                    let perm = perm & !cx.umask();
                    let q = super::mqueue::new_queue(cx, ns, &cred, perm, None)?;
                    let ino = q.borrow().ino;
                    super::mqueue::insert_queue(cx.k().ipc_mut(ns), name.to_vec(), q);
                    mq_created = true;
                    break (
                        Node::Pseudo(mnt, PseudoNode::Mq(ns, ino)),
                        None,
                        Some((dir.clone(), name.to_vec())),
                    );
                }
                // Files cannot be created in cgroup directories (they have no create; Linux's
                // vfs_create is EACCES)
                if let Node::Pseudo(_, PseudoNode::Cgroup(..)) = dir
                    && !vfs.readonly(&dir)
                {
                    return Err(Errno::EACCES);
                }
                // A dangling symlink under the name (in an overlay, as the overlay shows it)
                let link = match &dir {
                    Node::Overlay(mnt, o) => vfs.overlay_child((*mnt, *o), name).ok(),
                    Node::Fuse(mnt, d) => match vfs.fuse_child(*d, name) {
                        Ok(c) => Some(Node::Fuse(*mnt, c)),
                        Err(e) if e == Errno::ENOENT => None,
                        Err(e) => return Err(e),
                    },
                    _ => {
                        let (mnt, d) = store_dir(&vfs, &dir)?;
                        vfs.store().lookup(d, name)?.map(|i| Node::Store(mnt, i))
                    }
                };
                if let Some(link) = link
                    && follow
                    && vfs.kind(&cx.view(&vfs), &link)? == mode::S_IFLNK
                {
                    links += 1;
                    if links > crate::vfs::MAX_SYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    // As in walk (pick_link, nd_jump_root): RESOLVE_NO_SYMLINKS and nosymfollow
                    // mounts do not follow; under NO_XDEV an absolute target must be in the same
                    // mount as the root
                    if res & resolve::NO_SYMLINKS != 0
                        || vfs
                            .mount_flags(&link)
                            .is_some_and(|f| f & ms::NOSYMFOLLOW != 0)
                    {
                        return Err(Errno::ELOOP);
                    }
                    path = vfs.readlink(&cx.view(&vfs), &link)?;
                    // Whether resolution has taken the root: approximated from the original path
                    // (absolute, scoped, containing `..`, or a jump already made here); those in
                    // earlier symlinks do not count
                    if path.first() == Some(&b'/')
                        && res & resolve::NO_XDEV != 0
                        && (!root_set || dir.mnt() != root.mnt())
                    {
                        return Err(Errno::EXDEV);
                    }
                    root_set |= path.first() == Some(&b'/');
                    start = dir;
                    continue;
                }
                // In a FUSE filesystem the daemon creates and opens it
                if let Node::Fuse(mnt, d) = dir {
                    let (id, kind) =
                        super::fuse::create(cx, &cred, &vfs, (mnt, d), name, perm, flags)?;
                    fuse_created = Some(kind);
                    break (
                        Node::Fuse(mnt, id),
                        None,
                        Some((dir.clone(), name.to_vec())),
                    );
                }
                // Check permissions and tmpfs room before copying up an overlay parent directory
                let (mnt, d, dir_st, _) =
                    prepare_create_dir(&vfs, &cred, &cx.view(&vfs), &dir, name, None, 0)?;
                let (uid, gid, perm) = cred.new_owner(&dir_st, perm, cx.umask(), false);
                let tmpfs = tmpfs_reserve_name(&vfs, (mnt, d), name, 0)?;
                let (ino, file) = create_in(
                    &vfs,
                    (mnt, d),
                    name,
                    dir_st.default_acl.as_deref(),
                    || vfs.store().create_file(d, name, perm, uid, gid),
                    |(ino, _)| *ino,
                )?;
                tmpfs_created_name(&vfs, tmpfs, 0);
                // In an overlay the new file is the overlay's node of that name
                if let Node::Overlay(mnt, o) = dir {
                    break (
                        vfs.overlay_child((mnt, o), name)?,
                        Some(file),
                        Some((dir.clone(), name.to_vec())),
                    );
                }
                break (
                    Node::Store(mnt, ino),
                    Some(file),
                    Some((Node::Store(mnt, d), name.to_vec())),
                );
            }
        }
        Err(e) => return Err(e),
    };

    let mut display = display_path(cx, &vfs, &start, &path, &node, parent.as_ref());
    // A namespace shows as `mnt:[number]` and the like in `/proc/<pid>/fd/<n>`; a namespace file
    // bind-mounted elsewhere opens as the mount point's path (Linux's d_path)
    if let Node::Pseudo(mnt, p @ PseudoNode::NsFile(..)) = &node
        && vfs.mount(*mnt).is_none_or(|m| m.fs != Fs::Nsfs)
    {
        display = Some(Rc::from(cx.view(&vfs).name(*mnt, p)));
    }
    let was_created = created.is_some() || fuse_created.is_some();
    let via_devpts = matches!(node, Node::Pseudo(_, PseudoNode::Pts(..)));
    let mut opened_ino = inotify::key_of(&node);
    let mut opened_mnt = match &node {
        Node::Store(mnt, _) | Node::Fuse(mnt, _) | Node::Pseudo(mnt, PseudoNode::Mq(..)) => {
            Some(*mnt)
        }
        _ => None,
    };
    let mut overlay = match &node {
        Node::Overlay(mnt, o) => Some((*mnt, *o)),
        _ => None,
    };
    let mut fifo_open = None;
    let mut path_object = None;
    let mut mq_path = None;
    // A magic-link reopen uses the source mount, dentry and object.
    match &node {
        Node::Pseudo(_, PseudoNode::OpenFd(proc, tid, fd)) => {
            let source = cx
                .view(&vfs)
                .open_file(*proc, *tid, *fd)
                .ok_or(Errno::ENOENT)?;
            let source = source.borrow();
            let backing = source.regular_backing();
            if !path_only || backing.is_some() {
                opened_mnt = Some(source.mnt);
                display = source.path.clone();
                overlay = source.ovl.map(|o| (source.mnt, o));
                opened_ino = source
                    .ovl
                    .map(overlay::key)
                    .or_else(|| backing.map(|(ino, ..)| ino));
                unlinked_name |= path_only
                    || source.ovl.is_some()
                    || source.dentry_unlinked()
                    || (!source.pseudo
                        && backing.is_some_and(|(ino, ..)| {
                            vfs.store().attrs(ino).is_ok_and(|st| st.nlink == 0)
                        }));
            }
            if path_only {
                if let Some((ino, host, writable)) = backing {
                    // Pin the object before the source fd number can be reused.
                    path_object = Some((ino, host.try_clone().map_err(host_errno)?, writable));
                    node = source.node().ok_or(Errno::ENOENT)?;
                } else {
                    mq_path = source.message_queue().cloned();
                }
            } else if matches!(source.kind, FileKind::Pipe(_)) {
                fifo_open = source.watch.clone();
            }
        }
        Node::Pseudo(_, PseudoNode::OpenExe(proc)) => {
            let exe = exe_file(cx, *proc)?;
            let (target, ino, host) = exe.backing(&vfs)?;
            overlay = exe.ovl.as_ref().map(|(mnt, o, _)| (*mnt, *o));
            opened_mnt = Some(target.mnt());
            opened_ino = inotify::key_of(&target);
            display = Some(exe.path.clone());
            unlinked_name = true;
            if path_only {
                path_object = Some((ino, host.try_clone().map_err(host_errno)?, false));
                node = target;
            }
        }
        _ => {}
    }
    unlinked_name |= matches!(node, Node::Overlay(_, o) if !vfs.overlay().linked(o));
    let kind = if path_only {
        if flags & oflags::O_DIRECTORY != 0 && !vfs.is_dir(&cx.view(&vfs), &node)? {
            return Err(Errno::ENOTDIR);
        }
        if let Node::Pseudo(_, PseudoNode::Mq(ns, ino)) = &node {
            mq_path = Some(mq_queue(cx, *ns, *ino)?);
        }
        FileKind::Path(node)
    } else {
        match node {
            Node::Store(mnt, ino) => {
                // A just-created file is already empty, so it is not truncated: ext4 treats a
                // file written after truncation to 0 as a whole replacement and starts writeback
                // right at close, which is slower than the write itself
                let flags = if was_created {
                    flags & !oflags::O_TRUNC
                } else {
                    flags
                };
                let beside = parent.as_ref().map(|(dir, _)| dir);
                let how = StoreOpen::by_path(created, beside);
                open_store(cx, &cred, &vfs, (mnt, ino), flags, how)?
            }
            Node::Pseudo(_, PseudoNode::Mq(ns, ino)) => {
                open_mq(cx, &cred, (ns, ino), flags, mq_created)?
            }
            Node::Pseudo(mnt, p) => open_pseudo(cx, &cred, &vfs, mnt, p, flags)?,
            Node::Overlay(mnt, o) => {
                let flags = if was_created {
                    flags & !oflags::O_TRUNC
                } else {
                    flags
                };
                let beside = parent.as_ref().map(|(dir, _)| dir);
                open_overlay(cx, &cred, &vfs, (mnt, o), flags, (created, beside))?
            }
            Node::Fuse(..) if fuse_created.is_some() => fuse_created.take().unwrap(),
            Node::Fuse(mnt, f) => super::fuse::open(cx, &cred, &vfs, (mnt, f), flags)?,
        }
    };
    // A 136:N device node outside devpts opens a specific slave: its path is the one in devpts
    // (fd links are computed by the mount reached through); /dev/tty and /dev/console (5:0 and
    // 5:1), the master, and slaves opened through devpts keep the opened path as usual
    if let FileKind::Pty(end) = &kind
        && !end.master
        && end.dev_ino.is_none()
        && !via_devpts
    {
        display = None;
    }
    let overlay = overlay.filter(|_| {
        path_object.is_some()
            || matches!(
                kind,
                FileKind::Regular { .. } | FileKind::Device { .. } | FileKind::Pipe(_)
            )
            || matches!(&kind, FileKind::Pty(end) if end.dev_ino.is_some())
    });
    let file = OpenFile::with_path(kind, flags & kept(flags) | largefile(flags), display);
    {
        let mut f = file.borrow_mut();
        f.path_object = path_object;
        f.mq_path = mq_path;
        f.pin_fuse_path(&vfs)?;
        if let Some(mnt) = opened_mnt {
            f.mnt = mnt;
        }
        if let Some((mnt, o)) = overlay {
            f.mnt = mnt;
            f.ovl = Some(o);
            f.hold(&Node::Overlay(mnt, o));
        }
        if let Some((dir, _)) = &parent {
            f.hold(dir);
        }
        f.dentry = parent.clone();
    }
    if let Some(ino) = opened_ino {
        open_events(cx, &file, ino, parent, was_created, flags, unlinked_name);
    } else if let Some(source) = fifo_open {
        let watch = source.reopen(cx.kr(), file.borrow().writable());
        file.borrow_mut().watch = Some(watch);
    }
    Ok(file)
}

/// Opens an unnamed temporary file (`O_TMPFILE`, Linux 6.1's `do_tmpfile`/`vfs_tmpfile`) in the
/// directory named by `path`. Supported on store and tmpfs directories; other filesystems check
/// read-only mount and directory write/search permission and return `EOPNOTSUPP`.
fn open_tmpfile(
    cx: &Cx<'_>,
    vfs: &Vfs,
    cred: &Cred,
    dir: &Node,
    (start, path): (&Node, &[u8]),
    flags: u32,
    perm: u32,
) -> Result<FileRef, Errno> {
    let view = cx.view(vfs);
    if !vfs.is_dir(&view, dir)? {
        return Err(Errno::ENOTDIR);
    }
    if vfs.readonly(dir) {
        return Err(Errno::EROFS);
    }
    let (mnt, d) = match dir {
        Node::Store(mnt, d) => (*mnt, *d),
        Node::Overlay(_, o) => {
            let real = vfs.overlay().node(*o).real();
            let st = vfs.store().attrs(real)?;
            may_add_name(cred, &st)?;
            return Err(Errno::EOPNOTSUPP);
        }
        Node::Fuse(_, d) => {
            vfs.fuse_permission(cred, *d, MAY_WRITE | MAY_EXEC)?;
            return Err(Errno::EOPNOTSUPP);
        }
        Node::Pseudo(_, p) => {
            cred.permission(&pseudo::stat(&view, p)?, MAY_WRITE | MAY_EXEC)?;
            return Err(Errno::EOPNOTSUPP);
        }
    };
    let dir_st = vfs.store().stat(d)?;
    may_add_name(cred, &dir_st)?;
    // tmpfs does not support O_DIRECT (do_dentry_open's direct_IO check).
    if flags & oflags::O_DIRECT != 0 && vfs.fs_of(dir) == Fs::Tmpfs {
        return Err(Errno::EINVAL);
    }
    let (uid, gid, mode) = cred.new_owner(&dir_st, perm, cx.umask(), false);
    let tmpfs = tmpfs_reserve(vfs, (mnt, d), 0)?;
    let linkable = flags & oflags::O_EXCL == 0;
    let (ino, host, tracked) = vfs.store().transaction(|store| {
        let (ino, host) =
            store.create_tmpfile(mode, uid, gid, linkable, dir_st.default_acl.as_deref())?;
        let inherited = dir_st.flags & inode_flags::INHERITED;
        if inherited != 0 {
            store.set_flags(ino, inherited)?;
        }
        let tracked = tmpfs
            .map(|dev| host.try_clone().map(|file| (dev, file)))
            .transpose()
            .map_err(host_errno)?;
        Ok((ino, host, tracked))
    })?;
    if let Some((dev, tracked)) = tracked {
        vfs.tmpfs_charge(dev, 0, 1);
        vfs.tmpfs_unlinked(dev, ino, 0, tracked);
    }
    // The unnamed dentry is displayed as <dir>/#<ino>, including at the root.
    let base = display_path(cx, vfs, start, path, dir, None);
    let mut name = base.as_deref().unwrap_or_default().to_vec();
    if !name.ends_with(b"/") {
        name.push(b'/');
    }
    write!(name, "#{ino}").unwrap();
    let file = OpenFile::with_path(
        FileKind::Regular {
            ino,
            file: host,
            cow: false,
        },
        flags & kept(flags) | largefile(flags),
        Some(Rc::from(name)),
    );
    file.borrow_mut().mnt = mnt;
    open_events(cx, &file, ino, None, true, flags, true);
    Ok(file)
}

fn sticky_protection_allows(
    mode: u32,
    uid: u32,
    fsuid: u32,
    dir_mode: u32,
    dir_uid: u32,
    level: i64,
) -> bool {
    if !matches!(mode & mode::S_IFMT, mode::S_IFREG | mode::S_IFIFO) {
        return true;
    }
    if level <= 0 || fsuid == uid || dir_mode & mode::S_ISVTX == 0 || uid == dir_uid {
        return true;
    }
    !(dir_mode & 0o002 != 0 || (level >= 2 && dir_mode & 0o020 != 0))
}

/// Linux 6.1's `may_create_in_sticky` (`fs.protected_regular` and `fs.protected_fifos`):
/// opening an existing regular file or FIFO with `O_CREAT` in a sticky directory (world-writable
/// at level 1, or also group-writable at level 2) is `EACCES` unless the caller owns the file or
/// the directory owner owns the file (even for root).
fn may_create_in_sticky(
    cx: &Cx<'_>,
    vfs: &Vfs,
    cred: &Cred,
    node: &Node,
    dir: Option<&Node>,
) -> Result<(), Errno> {
    let Some(dir) = dir else {
        return Ok(());
    };
    let node_attrs = |n: &Node| -> Result<Option<(u32, u32)>, Errno> {
        Ok(match n {
            Node::Store(_, ino) => {
                let st = vfs.store().attrs(*ino)?;
                Some((st.mode, st.uid))
            }
            Node::Overlay(_, o) => {
                let st = vfs.overlay_stat(*o)?;
                Some((st.mode, st.uid))
            }
            Node::Fuse(_, f) => {
                let st = crate::vfs::fuse::cached_attr(vfs, *f)?;
                Some((st.mode, st.uid))
            }
            Node::Pseudo(..) => None,
        })
    };
    let Some((mode, uid)) = node_attrs(node)? else {
        return Ok(());
    };
    let key = match mode & mode::S_IFMT {
        mode::S_IFREG => pseudo::PROTECTED_REGULAR,
        mode::S_IFIFO => pseudo::PROTECTED_FIFOS,
        _ => return Ok(()),
    };
    let level = pseudo::recorded_value(cx.kr(), key);
    if level <= 0 || cred.fsuid == uid {
        return Ok(());
    }
    let Some((dir_mode, dir_uid)) = node_attrs(dir)? else {
        return Ok(());
    };
    if !sticky_protection_allows(mode, uid, cred.fsuid, dir_mode, dir_uid, level) {
        return Err(Errno::EACCES);
    }
    Ok(())
}

/// Start and root directory of openat2 (path_init). With a scope (`BENEATH`, `IN_ROOT`) the root
/// is the start; absolute `IN_ROOT` paths also start at dirfd; other absolute paths ignore dirfd
/// (resolution reports EXDEV for `BENEATH` ones).
fn openat2_start(cx: &Cx<'_>, dirfd: i32, path: &[u8], flags: u64) -> Result<(Node, Node), Errno> {
    use crate::vfs::resolve;
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path[0] == b'/' && flags & resolve::IN_ROOT == 0 {
        let root = cx.root();
        return Ok((root.clone(), root));
    }
    let start = if dirfd == AT_FDCWD {
        cx.cwd()
    } else {
        let file = cx.fds().get(dirfd)?;
        let node = file.borrow().node().ok_or(Errno::ENOTDIR)?;
        let vfs = cx.vfs()?;
        if !vfs.is_dir(&cx.view(&vfs), &node)? {
            return Err(Errno::ENOTDIR);
        }
        node
    };
    let root = if flags & resolve::SCOPED != 0 {
        start.clone()
    } else {
        cx.root()
    };
    Ok((start, root))
}

/// Opens a queue in the mqueue filesystem: the resulting fd is the same as mq_open's (on Linux it
/// is the same kind of file), and mq_timedsend and the like work on it. A just-created one is not
/// checked for permission again.
fn open_mq(
    cx: &Cx<'_>,
    cred: &Cred,
    (ns, ino): (u64, u64),
    flags: u32,
    created: bool,
) -> Result<FileKind, Errno> {
    if flags & oflags::O_DIRECTORY != 0 {
        return Err(Errno::ENOTDIR);
    }
    let q = mq_queue(cx, ns, ino)?;
    if !created {
        cred.permission(&q.borrow().stat(), open_mask(flags))?;
    }
    Ok(FileKind::MessageQueue(q))
}

/// Opens a node in a synthetic filesystem.
fn open_pseudo(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    mnt: crate::vfs::MountId,
    node: PseudoNode,
    flags: u32,
) -> Result<FileKind, Errno> {
    let accmode = flags & oflags::O_ACCMODE;
    // O_TRUNC asks for write permission too (Linux's build_open_flags), although nothing here can
    // be truncated
    let mask = open_mask(flags)
        | if flags & oflags::O_TRUNC != 0 {
            MAY_WRITE
        } else {
            0
        };
    // /proc/sys/user/max_*: anyone may read the limits of their user namespace, and holders of
    // CAP_SYS_RESOURCE in it may write them, whoever owns the files (Linux's set_permissions for
    // the per-user-namespace sysctl tables)
    let user_limit = matches!(&node, PseudoNode::Static(p) if p.starts_with(b"sys/user/max_"));
    // Namespace files are immutable (nsfs): asking to write is EPERM before any permission check
    if matches!(node, PseudoNode::NsFile(..)) && mask & MAY_WRITE != 0 {
        return Err(Errno::EPERM);
    }
    if user_limit {
        if mask & MAY_WRITE != 0 && !cred.capable_here(cap::SYS_RESOURCE) {
            return Err(Errno::EACCES);
        }
    } else if let Some(net) = pseudo::sysctl_kind(&node) {
        // The rest of /proc/sys (proc_sys_permission, sysctl_perm, test_perm): the mode's owner
        // bits for euid 0, its group bits for a member of group 0, the others' otherwise, whatever
        // the capabilities; a net.* sysctl gives its owner bits to anyone with CAP_NET_ADMIN over
        // the network namespace's owner (net_ctl_permissions), so root of a container's user
        // namespace may write its own namespace's
        let st = pseudo::stat(&cx.view(vfs), &node)?;
        let mut m = st.mode & 0o777;
        if net {
            let owner = cx.task.ns.borrow().net.owner.clone();
            if cred.ns_capable(&owner, cap::NET_ADMIN) {
                let o = m >> 6;
                m = o << 6 | o << 3 | o;
            }
        }
        let bits = if cred.euid == 0 {
            m >> 6
        } else if cred.egid == 0 || cred.groups.binary_search(&0).is_ok() {
            m >> 3
        } else {
            m
        } & 7;
        if mask & 7 & !bits != 0 {
            return Err(Errno::EACCES);
        }
    } else if !matches!(node, PseudoNode::OpenFd(..) | PseudoNode::OpenExe(_)) {
        cred.permission(&pseudo::stat(&cx.view(vfs), &node)?, mask)?;
    }
    // /proc/<pid>/mem requires being able to trace that process, as ptrace does
    // (PTRACE_MODE_ATTACH); auxv, environ, maps, smaps and pagemap require being able to trace it
    // read-only (PTRACE_MODE_READ, same rules): even for a process of the same user they cannot
    // be opened when it is not dumpable. Both use the filesystem credentials (proc_mem_open adds
    // PTRACE_MODE_FSCREDS)
    let mut mm = None;
    if let PseudoNode::Entry(
        proc,
        tid,
        e @ (pseudo::Entry::Mem
        | pseudo::Entry::Auxv
        | pseudo::Entry::Environ
        | pseudo::Entry::Maps
        | pseudo::Entry::Smaps
        | pseudo::Entry::SmapsRollup
        | pseudo::Entry::Pagemap),
    ) = node
    {
        // proc.pid may name any thread (/proc/<tid>, pseudo::group_of_id): the check is on that
        // thread
        pseudo::group_of_id(cx.kr(), proc).ok_or(Errno::ESRCH)?;
        let thread = tid.unwrap_or(proc.pid);
        if !super::proc::may_ptrace_fs(cx, thread) {
            return Err(Errno::EACCES);
        }
        // mem and pagemap pin the named thread's address space at open (Linux's proc_mem_open /
        // pagemap_open): one that has exited (a zombie, a main thread whose process lives on) has
        // none, ESRCH at open as on Linux. environ also pins the address space at open
        // (proc_environ_operations / __mem_open), staying None (EOF on read) for a zombie so an
        // open fd cannot later read a new address space after execve.
        if matches!(
            e,
            pseudo::Entry::Mem | pseudo::Entry::Pagemap | pseudo::Entry::Environ
        ) {
            mm = cx
                .kr()
                .tasks
                .get(&thread)
                .map(|t| Rc::downgrade(&t.res.borrow().mm));
            if mm.is_none() && e != pseudo::Entry::Environ {
                return Err(Errno::ESRCH);
            }
        }
    }
    // Writing setgroups needs CAP_SYS_ADMIN in the process's user namespace, checked at open
    // (proc_setgroups_open)
    if let PseudoNode::Entry(proc, _, pseudo::Entry::Setgroups) = node
        && mask & MAY_WRITE != 0
    {
        let group = pseudo::group_of_id(cx.kr(), proc).ok_or(Errno::ESRCH)?;
        if !cred.ns_capable(&group.borrow().cred.user_ns, cap::SYS_ADMIN) {
            return Err(Errno::EACCES);
        }
    }
    // Device nodes cannot be opened in a nodev mount (Linux's may_open)
    if matches!(node, PseudoNode::Pts(..) | PseudoNode::PtsPtmx(_))
        && vfs.mount(mnt).is_some_and(|m| m.flags & ms::NODEV != 0)
    {
        return Err(Errno::EACCES);
    }
    // devpts terminals also go through the cgroup device filter
    let rdev = match node {
        PseudoNode::Pts(_, n) => Some(rdev(PTS_MAJOR, n)),
        PseudoNode::PtsPtmx(_) => Some(PTMX_RDEV),
        _ => None,
    };
    if let Some(r) = rdev {
        super::bpf::check_device(cx, mode::S_IFCHR, r, device_access(mask))?;
    }
    // No synthetic file supports direct I/O (do_dentry_open: EINVAL), terminals included; a
    // directory opened for writing is EISDIR first. Files reopened through /proc/<pid>/fd are
    // their own kind
    if flags & oflags::O_DIRECT != 0
        && !matches!(node, PseudoNode::OpenFd(..) | PseudoNode::OpenExe(_))
        && (accmode == oflags::O_RDONLY || Pseudo::kind(&cx.view(vfs), &node)? != mode::S_IFDIR)
    {
        return Err(Errno::EINVAL);
    }
    match node {
        PseudoNode::Pts(fs, n) => return tty::open_slave(cx, (fs, n, mnt, true), flags),
        PseudoNode::PtsPtmx(fs) => {
            return tty::open_ptmx(cx.k(), (fs, mnt, true), (cred.fsuid, cred.fsgid));
        }
        PseudoNode::OpenFd(proc, tid, fd) => return reopen(cx, cred, vfs, (proc, tid), fd, flags),
        PseudoNode::OpenExe(proc) => return reopen_exe(cx, cred, vfs, proc, flags),
        _ => {}
    }
    let view = cx.view(vfs);
    // With O_NOFOLLOW it stopped at a symlink (such as /proc/self/fd/<n>)
    if Pseudo::kind(&view, &node)? == mode::S_IFLNK {
        return Err(Errno::ELOOP);
    }
    let full = Node::Pseudo(mnt, node.clone());
    if vfs.is_dir(&view, &full)? {
        if accmode != oflags::O_RDONLY {
            return Err(Errno::EISDIR);
        }
        // /proc/<pid> remembers which process it is: Linux's open file references a struct pid,
        // so after the process is reaped, using it as a pidfd is ESRCH even if the pid has been
        // given to a new process
        let process = match node {
            PseudoNode::Pid(proc, None) => pseudo::group_of_id(cx.kr(), proc).map(Rc::downgrade),
            _ => None,
        };
        return Ok(FileKind::Directory {
            node: full,
            entries: None,
            process,
            fuse: None,
        });
    }
    if flags & oflags::O_DIRECTORY != 0 {
        return Err(Errno::ENOTDIR);
    }
    if mask & MAY_WRITE != 0 && vfs.readonly(&full) {
        return Err(Errno::EROFS);
    }
    // cgroup files are checked only by permission bits (root can open read-only ones; writing is
    // what gets EINVAL), the others by pseudo::open_unwritable
    if mask & MAY_WRITE != 0 && !pseudo::writable(&node) && !matches!(node, PseudoNode::Cgroup(..))
    {
        pseudo::open_unwritable(&node, accmode != oflags::O_RDONLY)?;
    }
    // Network sysctls fail only when read (an unset stable_secret is EIO, Linux's
    // proc_sys_call_handler): open starts with empty contents and the first read regenerates them.
    // So does /proc/<pid>/syscall, which shows the thread as it is when read (/proc/self/syscall
    // shows the read) and checks ptrace access then
    let mut fresh = true;
    let data = if pseudo::unreadable(&node) {
        Vec::new()
    } else if matches!(node, PseudoNode::Entry(_, _, pseudo::Entry::Syscall)) {
        fresh = false;
        Vec::new()
    } else if matches!(node, PseudoNode::Entry(_, _, pseudo::Entry::Environ)) {
        pseudo::read_environ(mm.as_ref().and_then(Weak::upgrade).as_ref())
    } else {
        match pseudo::content(&view, mnt, &node) {
            Err(_) if matches!(node, PseudoNode::NetConf(..)) => {
                fresh = false;
                Vec::new()
            }
            r => r?,
        }
    };
    // /proc/kmsg (`kmsg_open`): open checks permission as syslog's open does, and later reads do
    // not check again
    let klog = match node {
        PseudoNode::Global(pseudo::Global::Kmsg) => {
            super::misc::do_syslog(cx, super::misc::syslog_action::OPEN, 0, 0, true)?;
            Some(cx.kr().klog.clone())
        }
        _ => None,
    };
    // A namespace file holds that namespace
    let ns = match node {
        PseudoNode::NsFile(kind, id) => {
            Some(super::ns::find(cx.kr(), Some(vfs), kind, id).ok_or(Errno::ENOENT)?)
        }
        _ => None,
    };
    // Change notifications: per-namespace mount events for mounts/mountinfo, per-name UTS events
    // for hostname/domainname, cgroup2 observers, and kernfs first-read counters for sysfs.
    let event = pseudo::poll_event(cx.k(), vfs, &node);
    Ok(FileKind::Proc {
        mnt,
        node,
        data,
        fresh,
        mm,
        ns,
        klog,
        event,
        opener: Rc::new(cred.clone()),
    })
}

/// Reopens a file without a path through `/proc/<pid>/fd/<n>`: a pipe gives an end of the same
/// pipe, a host fd the same host fd, and a deleted regular file (memfd, or one still open after
/// deletion) opens the same host file through the host's `/proc/self/fd` (the object in the
/// store is already deleted), with the checks of an open on the mount it was opened through
/// ([`StoreOpen::Reopened`]).
fn reopen(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (proc, tid): (pseudo::ProcId, Option<Tid>),
    fd: i32,
    flags: u32,
) -> Result<FileKind, Errno> {
    let accmode = flags & oflags::O_ACCMODE;
    let file = cx.view(vfs).open_file(proc, tid, fd).ok_or(Errno::ENOENT)?;
    let f = file.borrow();
    if let Some(q) = f.message_queue() {
        if flags & oflags::O_DIRECTORY != 0 {
            return Err(Errno::ENOTDIR);
        }
        cred.permission(&q.borrow().stat(), open_mask(flags))?;
        return Ok(FileKind::MessageQueue(q.clone()));
    }

    if let Some((ino, host, writable)) = f.regular_backing() {
        if flags & oflags::O_TRUNC != 0 && accmode != oflags::O_RDONLY {
            seals_permit(cx, ino, host, false, |_| 0)?;
        }
        if let Some(o) = f.ovl
            && writes_on_open(flags)
        {
            check_overlay_write(cx, cred, vfs, (f.mnt, o), &vfs.store().attrs(ino)?, flags)?;
        }
        // A held object needs a writable host handle only after copy-on-write.
        let need_write = accmode != oflags::O_RDONLY && !writable && !vfs.store().held(ino)?;
        let new = clone_or_reopen(host, need_write)?;
        let (mnt, memfd) = (f.mnt, f.pseudo);
        let key = f.ovl.map_or(ino, overlay::key);
        drop(f);
        let how = StoreOpen::Reopened(new, memfd);
        return open_store_with(cx, cred, vfs, (mnt, ino), flags, how, key);
    }
    if let Some(Attrs::Anon(target)) = Attrs::anonymous(&f) {
        cred.permission(&target.stat(Some(vfs), cred), open_mask(flags))?;
    }
    match &f.kind {
        FileKind::Pipe(end) => Ok(FileKind::Pipe(PipeEnd::open(
            &end.pipe,
            accmode != oflags::O_WRONLY,
            accmode != oflags::O_RDONLY,
        ))),
        FileKind::Host(fd) => Ok(FileKind::Host(*fd)),
        _ => Err(Errno::ENXIO),
    }
}

/// Opens a deleted program file through `/proc/<pid>/exe` ([`PseudoNode::OpenExe`]): duplicates
/// the recorded host file, as [`reopen`] does for deleted regular files, with the same checks (a
/// program still being executed cannot be opened for write: ETXTBSY).
fn reopen_exe(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    proc: pseudo::ProcId,
    flags: u32,
) -> Result<FileKind, Errno> {
    let exe = exe_file(cx, proc)?;
    let (node, ino, host) = exe.backing(vfs)?;
    let accmode = flags & oflags::O_ACCMODE;
    if let Node::Overlay(mnt, o) = node
        && writes_on_open(flags)
    {
        check_overlay_write(cx, cred, vfs, (mnt, o), &vfs.store().attrs(ino)?, flags)?;
    }
    let new = clone_or_reopen(host, accmode != oflags::O_RDONLY)?;
    open_store_with(
        cx,
        cred,
        vfs,
        (node.mnt(), ino),
        flags,
        StoreOpen::Reopened(new, false),
        inotify::key_of(&node).unwrap_or(ino),
    )
}

/// Positional I/O lets guest descriptions share a host handle. Reopen through procfs only
/// to gain write access, since some host filesystems cannot reopen an unlinked file by fd.
fn clone_or_reopen(host: &std::fs::File, need_write: bool) -> Result<std::fs::File, Errno> {
    use std::os::fd::AsRawFd;
    if need_write {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{}", host.as_raw_fd()))
    } else {
        host.try_clone()
    }
    .map_err(host_errno)
}

/// inotify events of open, in the same order as Linux: create (reported to the directory),
/// truncation by `O_TRUNC`, open. `ino` is the file's key ([`inotify::key_of`]). Attaches an
/// [`inotify::Opened`] to the open file.
fn open_events(
    cx: &Cx<'_>,
    file: &FileRef,
    ino: Ino,
    parent: Option<(Node, Vec<u8>)>,
    created: bool,
    flags: u32,
    unlinked: bool,
) {
    let k = cx.kr();
    // A file created through an overlay was created in its upper directory first, which reports it
    // too (Linux's overlay creates it there through the VFS)
    let upper = match &parent {
        Some((Node::Overlay(_, d), _)) if created => {
            cx.vfs().ok().and_then(|v| v.overlay().node(*d).upper)
        }
        _ => None,
    };
    let parent = parent.and_then(|(dir, name)| Some((inotify::key_of(&dir)?, name)));
    if flags & oflags::O_PATH == 0 && inotify::active(k) {
        if let (Some(up), Some((_, name))) = (upper, &parent) {
            inotify::dir_event(k, up, name, inotify::IN_CREATE, 0);
        }
        open_notify(k, file, ino, parent.as_ref(), created, flags, unlinked);
    }
    let watch = inotify::opened(k, &file.borrow(), parent, unlinked);
    file.borrow_mut().watch = watch;
}

fn open_notify(
    k: &Kernel,
    file: &FileRef,
    ino: Ino,
    parent: Option<&(Ino, Vec<u8>)>,
    created: bool,
    flags: u32,
    unlinked: bool,
) {
    let parent = parent.map(|(d, n)| (*d, n.as_slice()));
    let (dir, truncated) = {
        let f = file.borrow();
        let regular = matches!(f.kind, FileKind::Regular { .. } | FileKind::Fuse(_));
        let dir = matches!(f.kind, FileKind::Directory { .. });
        // O_TRUNC truncates regular files even with O_RDONLY (open_store / fuse::open), emitting
        // IN_MODIFY unless the file was just created
        let truncated = regular && !created && flags & oflags::O_TRUNC != 0;
        (if dir { inotify::IN_ISDIR } else { 0 }, truncated)
    };
    match parent {
        Some((d, name)) if created => inotify::dir_event(k, d, name, inotify::IN_CREATE, 0),
        _ if truncated => inotify::path_event(k, ino, parent, inotify::IN_MODIFY),
        _ => {}
    }
    inotify::path_event_unlinked(k, ino, parent, inotify::IN_OPEN | dir, unlinked);
}

/// name_to_handle_at: the handle of a file in the store is its inode number; synthetic
/// filesystems do not support handles.
pub(super) fn name_to_handle_at(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    handle: u64,
    mount_id: u64,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH | AT_HANDLE_FID) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, path)?;
    let node = lookup_at_or_fd(
        cx,
        &cx.cred(),
        dirfd,
        &path,
        flags,
        flags & AT_SYMLINK_FOLLOW != 0,
    )?;
    let Node::Store(mnt, ino) = node else {
        return Err(Errno::EOPNOTSUPP);
    };
    let header: [u8; 8] = get(cx, handle)?;
    let room = u32::from_le_bytes(header[..4].try_into().unwrap());
    if room > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    // When it does not fit, only the handle header (the needed length, FILEID_INVALID) is
    // written back and the result is EOVERFLOW. Both cases write mount_id, and failing to write
    // it or the handle is EFAULT (Linux's do_sys_name_to_handle)
    let mut b = FILE_HANDLE_BYTES.to_le_bytes().to_vec();
    let ret = if room < FILE_HANDLE_BYTES {
        b.extend_from_slice(&FILEID_INVALID.to_le_bytes());
        Err(Errno::EOVERFLOW)
    } else {
        b.extend_from_slice(&FILE_HANDLE_TYPE.to_le_bytes());
        b.extend_from_slice(&ino.to_le_bytes());
        Ok(0)
    };
    put(cx, mount_id, (mnt as i32).to_le_bytes())?;
    cx.mm().write(UserSlice::new(handle, b.len()), &b)?;
    ret
}

/// open_by_handle_at: opens by inode number; requires `CAP_DAC_READ_SEARCH`.
pub(super) fn open_by_handle_at(
    cx: &mut Cx<'_>,
    mount_fd: i32,
    handle: u64,
    flags: u32,
) -> SysResult {
    if !cx.cred().capable(cap::DAC_READ_SEARCH) {
        return Err(Errno::EPERM);
    }
    // As in Linux's handle_to_path, read the handle header and check its length first, then the
    // whole handle, and look at mount_fd only last
    let header: [u8; 8] = get(cx, handle)?;
    let bytes = u32::from_le_bytes(header[..4].try_into().unwrap());
    if bytes == 0 || bytes > MAX_HANDLE_SZ {
        return Err(Errno::EINVAL);
    }
    let ty = i32::from_le_bytes(header[4..].try_into().unwrap());
    let mut f_handle = vec![0u8; bytes as usize];
    cx.mm()
        .read(UserSlice::new(handle + 8, f_handle.len()), &mut f_handle)?;
    // The file is opened through the mount mount_fd is in. Handles decode only in the store: when
    // mount_fd is on a pipe, a socket or a synthetic filesystem it is ESTALE, as on Linux where
    // these filesystems have no export_operations
    let node = if mount_fd == AT_FDCWD {
        Some(cx.cwd())
    } else {
        cx.fds().get(mount_fd)?.borrow().node()
    };
    let Some(node @ Node::Store(..)) = node else {
        return Err(Errno::ESTALE);
    };
    let mnt = node.mnt();
    let ino = match f_handle.first_chunk::<8>() {
        Some(b) if bytes == FILE_HANDLE_BYTES && ty == FILE_HANDLE_TYPE => u64::from_le_bytes(*b),
        _ => return Err(Errno::ESTALE),
    };
    let vfs = cx.vfs()?;
    let sb_root = vfs.store_sb_root(&node).ok_or(Errno::ESTALE)?;
    // Deleted or in another store/tmpfs superblock: ESTALE (exportfs_decode_fh).
    let st = vfs.store().stat(ino).map_err(|_| Errno::ESTALE)?;
    if st.nlink == 0 || vfs.store().tree_root(ino).ok().flatten() != Some(sb_root) {
        return Err(Errno::ESTALE);
    }
    let kind = if flags & oflags::O_PATH != 0 {
        if flags & oflags::O_DIRECTORY != 0 && !st.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        FileKind::Path(Node::Store(mnt, ino))
    } else {
        open_store(
            cx,
            &cx.cred(),
            &vfs,
            (mnt, ino),
            flags,
            StoreOpen::Found(None),
        )?
    };
    let file = OpenFile::new(kind, flags & kept(flags) | largefile(flags));
    file.borrow_mut().mnt = mnt;
    open_events(cx, &file, ino, None, false, flags, false);
    cx.install_fd(file, flags & oflags::O_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

/// A directory opened for writing, creating or truncating is EISDIR before O_DIRECT is looked at.
fn direct_open_is_eisdir(st: &Stat, flags: u32) -> bool {
    st.kind() == mode::S_IFDIR
        && (flags & oflags::O_ACCMODE != oflags::O_RDONLY
            || flags & (oflags::O_CREAT | oflags::O_TRUNC) != 0)
}

/// How [`open_store`] came to the inode it opens.
enum StoreOpen<'a> {
    /// Found by path, beside directory node `beside` when known (a ptmx node opens the devpts
    /// there): every check is made.
    Found(Option<&'a Node>),
    /// Created by this open, through the given host handle: no checks.
    Created(std::fs::File, Option<&'a Node>),
    /// A file without a name reopened through `/proc/<pid>/fd` or `exe`, through the given host
    /// handle (the store's own may be gone with its last name); a memfd (the bool) is on no mount
    /// of the store and never read-only. Every check is made, as Linux reopens the file's dentry.
    Reopened(std::fs::File, bool),
}

impl<'a> StoreOpen<'a> {
    fn by_path(created: Option<std::fs::File>, beside: Option<&'a Node>) -> Self {
        match created {
            Some(f) => StoreOpen::Created(f, beside),
            None => StoreOpen::Found(beside),
        }
    }
}

/// Opens a store inode reached through mount `mnt`.
fn open_store(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, ino): (MountId, Ino),
    flags: u32,
    how: StoreOpen<'_>,
) -> Result<FileKind, Errno> {
    open_store_with(cx, cred, vfs, (mnt, ino), flags, how, ino)
}

/// An overlay open supplies its own inode key for leases and PTY device-node locks.
fn open_store_with(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, ino): (MountId, Ino),
    flags: u32,
    how: StoreOpen<'_>,
    lock_ino: Ino,
) -> Result<FileKind, Errno> {
    let (created, beside, check, memfd) = match how {
        StoreOpen::Found(beside) => (None, beside, true, false),
        StoreOpen::Created(f, beside) => (Some(f), beside, false, false),
        StoreOpen::Reopened(f, memfd) => (Some(f), None, true, memfd),
    };
    let store = vfs.store();
    let accmode = flags & oflags::O_ACCMODE;
    // Only the type, permissions, owner and device number are used; no need to stat the object on
    // the host
    let st = store.attrs(ino)?;
    if check {
        let node = Node::Store(mnt, ino);
        let mnt_flags = vfs.mount_flags(&node).unwrap_or(0);
        // Read-only means the mount's flag or its instance's (mnt_want_write checks both), so a
        // bind keeping rw flags over an instance remounted read-only cannot write either. A
        // read-only filesystem instance (sb_rdonly) returns EROFS before DAC permission
        // (Linux 6.1's sb_permission in inode_permission), while a read-only bind over a writable
        // instance checks DAC permission first except for O_TRUNC.
        let readonly = !memfd && vfs.readonly(&node);
        let sb_readonly = !memfd && vfs.sb_readonly_node(&node);
        let mut mask = open_mask(flags);
        match st.kind() {
            mode::S_IFLNK => return Err(Errno::ELOOP),
            // O_TRUNC asks for write access even with O_RDONLY (Linux's build_open_flags)
            mode::S_IFDIR
                if accmode != oflags::O_RDONLY
                    || flags & (oflags::O_CREAT | oflags::O_TRUNC) != 0 =>
            {
                return Err(Errno::EISDIR);
            }
            // Truncation: EROFS comes first in a read-only mount (Linux's do_open, before
            // may_open)
            mode::S_IFREG if flags & oflags::O_TRUNC != 0 => {
                if readonly {
                    return Err(Errno::EROFS);
                }
                mask |= MAY_WRITE;
            }
            mode::S_IFREG if accmode != oflags::O_RDONLY && sb_readonly => {
                return Err(Errno::EROFS);
            }
            // Device nodes in a nodev mount cannot be opened (may_open_dev)
            mode::S_IFCHR | mode::S_IFBLK if mnt_flags & ms::NODEV != 0 => {
                return Err(Errno::EACCES);
            }
            _ => {}
        }
        open_permission(cred, &st, mask, flags)?;
        // Device nodes then go through the cgroup device filter (Linux's
        // devcgroup_inode_permission)
        if matches!(st.kind(), mode::S_IFCHR | mode::S_IFBLK) && st.rdev != 0 {
            super::bpf::check_device(cx, st.kind(), st.rdev, device_access(mask))?;
        }
        if flags & oflags::O_NOATIME != 0 && !cred.owns(&st) {
            return Err(Errno::EPERM);
        }
        // Opening a regular file for write in a read-only mount is EROFS; devices and FIFOs as
        // usual (do_dentry_open leaves special_file alone)
        if readonly && st.kind() == mode::S_IFREG && accmode != oflags::O_RDONLY {
            return Err(Errno::EROFS);
        }
    }
    // O_DIRECT needs a file whose pages support direct I/O (do_dentry_open's direct_IO check):
    // regular files of the store (ext4's) and loop devices; directories, tmpfs files (shmem has
    // none in 6.1), character devices and FIFOs are EINVAL. Linux checks after the file's own open
    // (a FIFO waits for its peer first); here before it
    let direct_io = || match st.kind() {
        mode::S_IFREG => vfs.mount(mnt).is_none_or(|m| m.fs != Fs::Tmpfs),
        mode::S_IFBLK | mode::S_IFSOCK => true,
        _ => false,
    };
    if flags & oflags::O_DIRECT != 0 && !direct_io() && !direct_open_is_eisdir(&st, flags) {
        return Err(Errno::EINVAL);
    }
    let mut kind = match st.kind() {
        mode::S_IFLNK => return Err(Errno::ELOOP),
        mode::S_IFDIR => {
            if accmode != oflags::O_RDONLY || flags & (oflags::O_CREAT | oflags::O_TRUNC) != 0 {
                return Err(Errno::EISDIR);
            }
            FileKind::Directory {
                node: Node::Store(mnt, ino),
                entries: None,
                process: None,
                fuse: None,
            }
        }
        _ if flags & oflags::O_DIRECTORY != 0 => return Err(Errno::ENOTDIR),
        mode::S_IFREG => {
            let write = writes_on_open(flags);
            if write && check && executing(cx, ino) {
                return Err(Errno::ETXTBSY);
            }
            // Leases of others: opening for write conflicts with every lease, opening for read
            // only with write leases
            if check {
                let nonblock = flags & oflags::O_NONBLOCK != 0;
                super::lease::break_leases(cx, lock_ino, write, nonblock, None)?;
            }
            // A held file shares its object: truncating it first gives it an empty one of its
            // own; otherwise a description opened for writing gets a read-only handle on the
            // shared object, and its first change gives the file its own copy (prepare_write)
            let mut created = created;
            if flags & oflags::O_TRUNC != 0 && store.held(ino)? {
                make_private(cx, ino, Some(0))?;
                if created.is_some() {
                    created = Some(store.open_object(ino, accmode != oflags::O_RDONLY)?);
                }
            }
            let cow = accmode != oflags::O_RDONLY && store.held(ino)?;
            let file = match created {
                Some(f) => f,
                None => store.open_object(ino, accmode != oflags::O_RDONLY && !cow)?,
            };
            // Even with O_RDONLY, as on Linux (do_open truncates whatever the access mode),
            // through a writable handle of its own then
            if flags & oflags::O_TRUNC != 0 {
                remove_privs(cx, ino)?;
                let writable = match accmode {
                    oflags::O_RDONLY => Some(store.open_object(ino, true)?),
                    _ => None,
                };
                let target = writable.as_ref().unwrap_or(&file);
                let tmpfs = tmpfs_size(vfs, &Node::Store(mnt, ino), ino, target)?;
                truncate_regular(cx, vfs, ino, target, 0, tmpfs)?;
            }
            FileKind::Regular { ino, file, cow }
        }
        mode::S_IFCHR => match st.rdev {
            // /dev/tty, /dev/console: the caller's controlling terminal
            r if r == rdev(5, 0) || r == rdev(5, 1) => tty::open_ctty(cx, ino)?,
            PTMX_RDEV => {
                let (fs, m) = devpts_beside(vfs, beside)?;
                tty::open_ptmx(cx.k(), (fs, m, false), (cred.fsuid, cred.fsgid))?
            }
            r if r == rdev(226, 128) => FileKind::Render {
                ino,
                file: super::gpu::open(cx)?,
            },
            crate::vfs::fuse::DEV_RDEV => {
                FileKind::FuseDev(crate::vfs::fuse::DevFile::new(cred, ino))
            }
            // Terminal device nodes outside devpts: those in the boot instance
            r => match pts_index(r) {
                Some(index) => {
                    let at = (crate::tty::BOOT_PTS, index, crate::vfs::PTS_MOUNT, false);
                    tty::open_slave(cx, at, flags)?
                }
                None => {
                    // A character device without a driver (Linux's `chrdev_open`)
                    let dev = dev::open(store, ino).inspect_err(|&e| {
                        if e == Errno::ENXIO {
                            let (major, minor) = dev::split_rdev(r);
                            crate::stub::hit(cx, crate::stub::Stub::Device(false, major, minor));
                        }
                    })?;
                    let kmsg = match dev {
                        Device::Kmsg => Some(open_kmsg(cx, accmode)?),
                        _ => None,
                    };
                    FileKind::Device {
                        ino,
                        dev,
                        kmsg,
                        block: None,
                    }
                }
            },
        },
        mode::S_IFBLK => super::loopdev::open(cx, ino, st.rdev, flags)?,
        mode::S_IFIFO => open_fifo(cx, ino, flags)?,
        // Socket files cannot be opened (they use connect)
        _ => return Err(Errno::ENXIO),
    };
    if let FileKind::Pty(end) = &mut kind {
        end.lock_ino = Some(lock_ino);
        if end.master {
            end.dev_ino = Some(ino);
        }
    }
    Ok(kind)
}

/// Opens overlay node `o` reached through mount `mnt` (Linux's `ovl_open`): the store inode
/// behind it is opened as a store file would be, and a directory is listed through the overlay.
/// A regular file opened for writing is copied up first (without its data for `O_TRUNC`), after
/// the checks open makes on the overlay's file: a read-only filesystem (EROFS, before permission
/// as 6.1's `sb_permission`), permission, and a program being executed (ETXTBSY). A file this
/// open just created (`created`) is already in the upper layer.
fn open_overlay(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, o): (MountId, crate::vfs::overlay::OvlId),
    flags: u32,
    (created, beside): (Option<std::fs::File>, Option<&Node>),
) -> Result<FileKind, Errno> {
    // Hold the overlay node across any BKL release in break_leases or open_fifo.
    let _hold = overlay::Hold::new(o);
    // A rename during the wait can separate the open dentry from its original parent.
    let _parent_hold = match beside {
        Some(Node::Overlay(_, dir)) => Some(overlay::Hold::new(*dir)),
        _ => None,
    };
    let mut real = vfs.overlay().node(o).real();
    let st = vfs.store().attrs(real)?;
    let lease_ino = overlay::key(o);
    if writes_on_open(flags) && created.is_none() && st.kind() == mode::S_IFREG {
        check_overlay_write(cx, cred, vfs, (mnt, o), &st, flags)?;
        let truncate = flags & oflags::O_TRUNC != 0;
        // Break leases on the overlay node identity before copying up so a nonblocking open
        // failing with EAGAIN does not copy up, and holders on the lower inode are notified
        let nonblock = flags & oflags::O_NONBLOCK != 0;
        super::lease::break_leases(cx, lease_ino, true, nonblock, None)?;
        let what = if truncate {
            CopyUp::NoData
        } else {
            CopyUp::All
        };
        real = copy_up(cx, vfs, o, what)?;
    }
    Ok(
        match open_store_with(
            cx,
            cred,
            vfs,
            (mnt, real),
            flags,
            StoreOpen::by_path(created, beside),
            lease_ino,
        )? {
            FileKind::Directory { process, .. } => FileKind::Directory {
                node: Node::Overlay(mnt, o),
                entries: None,
                process,
                fuse: None,
            },
            kind => kind,
        },
    )
}

/// O_TRUNC requires write access even when combined with O_RDONLY.
fn writes_on_open(flags: u32) -> bool {
    flags & oflags::O_ACCMODE != oflags::O_RDONLY || flags & oflags::O_TRUNC != 0
}

fn check_overlay_write(
    cx: &Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, o): (MountId, OvlId),
    st: &Stat,
    flags: u32,
) -> Result<(), Errno> {
    if vfs.readonly(&Node::Overlay(mnt, o)) {
        return Err(Errno::EROFS);
    }
    let truncate = flags & oflags::O_TRUNC != 0;
    let mask = open_mask(flags) | if truncate { MAY_WRITE } else { 0 };
    open_permission(cred, st, mask, flags)?;
    if flags & oflags::O_NOATIME != 0 && !cred.owns(st) {
        return Err(Errno::EPERM);
    }
    if flags & oflags::O_DIRECTORY != 0 {
        return Err(Errno::ENOTDIR);
    }
    if executing_overlay(cx, o, st.ino) {
        return Err(Errno::ETXTBSY);
    }
    Ok(())
}

fn open_permission(cred: &Cred, st: &Stat, mask: u32, flags: u32) -> Result<(), Errno> {
    if mask & MAY_WRITE != 0 {
        reject_flags(st.flags, inode_flags::IMMUTABLE)?;
    }
    cred.permission(st, mask)?;
    if flags & oflags::O_TRUNC != 0
        || (flags & oflags::O_ACCMODE != oflags::O_RDONLY && flags & oflags::O_APPEND == 0)
    {
        reject_flags(st.flags, inode_flags::APPEND)?;
    }
    Ok(())
}

/// The access permissions open requires (`MAY_*`).
pub(super) fn open_mask(flags: u32) -> u32 {
    match flags & oflags::O_ACCMODE {
        oflags::O_RDONLY => MAY_READ,
        oflags::O_WRONLY => MAY_WRITE,
        _ => MAY_READ | MAY_WRITE,
    }
}

/// Turns access permissions (`MAY_*`) into device-filter access (`BPF_DEVCG_ACC_*`).
fn device_access(mask: u32) -> u32 {
    let mut access = 0;
    if mask & MAY_WRITE != 0 {
        access |= crate::bpf::ACC_WRITE;
    }
    if mask & MAY_READ != 0 {
        access |= crate::bpf::ACC_READ;
    }
    access
}

/// Which devpts instance a ptmx device node outside devpts opens (Linux's `devpts_acquire`): the
/// one mounted on `pts` in the node's directory `dir` (its mount and device number). No `pts` is
/// ENOENT, and a `pts` that is not a devpts root is ENODEV; when the node's directory is unknown
/// (opened by handle) it is the boot one.
fn devpts_beside(vfs: &Vfs, dir: Option<&Node>) -> Result<(u64, MountId), Errno> {
    let Some(dir) = dir else {
        return Ok((crate::tty::BOOT_PTS, crate::vfs::PTS_MOUNT));
    };
    let sibling = match dir {
        Node::Store(mnt, ino) => {
            let pts = vfs.store().lookup(*ino, b"pts")?.ok_or(Errno::ENOENT)?;
            Node::Store(*mnt, pts)
        }
        Node::Overlay(mnt, o) => vfs.overlay_child((*mnt, *o), b"pts")?,
        _ => return Err(Errno::ENODEV),
    };
    match vfs.mounted(sibling) {
        Node::Pseudo(m, PseudoNode::PtsRoot(fs)) => Ok((fs, m)),
        _ => Err(Errno::ENODEV),
    }
}

/// The PTY slave index of a device number: major 136, and the minor is the index (Linux's pts
/// driver registers all 2^20 minors of 136).
fn pts_index(r: u64) -> Option<u32> {
    let major = ((r >> 8) & 0xfff) as u32;
    let minor = ((r & 0xff) | ((r >> 12) & !0xff)) as u32;
    (major == PTS_MAJOR).then_some(minor)
}

/// Opens `/dev/kmsg` (`devkmsg_open`): when `printk_devkmsg` is `off` nobody can open it; a read
/// open checks permission as syslog's read-all does (`dmesg_restrict`), and a write-only open is
/// not checked. Reading starts at the oldest record.
fn open_kmsg(cx: &mut Cx<'_>, accmode: u32) -> Result<Box<crate::klog::KmsgFile>, Errno> {
    let log = cx.kr().klog.clone();
    if log.borrow().devkmsg == crate::klog::Devkmsg::Off {
        return Err(Errno::EPERM);
    }
    if accmode != oflags::O_WRONLY {
        super::misc::check_syslog_permissions(cx, super::misc::syslog_action::READ_ALL, false)?;
    }
    Ok(Box::new(crate::klog::KmsgFile::new(log)))
}

/// Opens a named pipe (FIFO): all opens of one inode share one pipe. As on Linux, a read-only
/// open waits until there is a writer, a write-only open waits until there is a reader (with
/// `O_NONBLOCK` it returns ENXIO when there is no reader), and a read-write open does not wait.
fn open_fifo(cx: &mut Cx<'_>, ino: Ino, flags: u32) -> Result<FileKind, Errno> {
    let accmode = flags & oflags::O_ACCMODE;
    let nonblock = flags & oflags::O_NONBLOCK != 0;
    let (read, write) = match accmode {
        oflags::O_RDONLY => (true, false),
        oflags::O_WRONLY => (false, true),
        oflags::O_RDWR => (true, true),
        // Access mode 3 opens neither end (Linux's fifo_open)
        _ => return Err(Errno::EINVAL),
    };
    let capacity = pipe_capacity(cx);
    let pipe = {
        let k = cx.k();
        k.fifos.retain(|_, w| w.strong_count() > 0);
        match k.fifos.get(&ino).and_then(Weak::upgrade) {
            Some(p) => p,
            None => {
                let p = Pipe::fifo(ino, capacity);
                k.fifos.insert(ino, Rc::downgrade(&p));
                p
            }
        }
    };
    if write && !read && nonblock && pipe.borrow().readers == 0 {
        return Err(Errno::ENXIO);
    }
    let peer_opens = |p: &Pipe| if read { p.writer_opens } else { p.reader_opens };
    let before = peer_opens(&pipe.borrow());
    let mut end = PipeEnd::open(&pipe, read, write);
    if read && !write && nonblock && pipe.borrow().writers == 0 {
        end.hup_after = Some(before);
    }
    if read != write && !nonblock {
        // Wait for the other end to open: it is enough that it came, even if it has closed
        // already
        loop {
            {
                let p = pipe.borrow();
                let peers = if read { p.writers } else { p.readers };
                if peers > 0 || peer_opens(&p) != before {
                    break;
                }
            }
            if cx.interrupted() {
                return Err(Errno::ERESTARTSYS);
            }
            cx.wait_object(crate::pipe::object(&pipe))?;
        }
    }
    Ok(FileKind::Pipe(end))
}

/// Files opened by open, openat2 and open_by_handle_at carry `O_LARGEFILE` (on 64-bit Linux
/// always adds it, and drops it with `O_PATH`), visible in F_GETFL and fdinfo; files created by
/// other syscalls, such as pipes and sockets, do not have it.
fn largefile(flags: u32) -> u32 {
    if flags & oflags::O_PATH != 0 {
        0
    } else {
        oflags::O_LARGEFILE
    }
}

pub(super) fn close(cx: &mut Cx<'_>, fd: i32) -> SysResult {
    // Take it out of the table first, then release it: closing the last end of a pipe wakes the
    // other end
    let r = cx.fds_mut().close(fd);
    let file = r?;
    let fds = cx.t.fds.clone();
    locks::closed(cx.k(), &fds, std::slice::from_ref(&file));
    super::mqueue_closed(&cx.t.group, std::slice::from_ref(&file));
    // A FUSE file is flushed, and the error is close's (6.1's filp_close)
    let flushed = super::fuse::flush(cx, &file);
    crate::unix::released(cx.k(), vec![file]);
    flushed.map(|()| 0)
}

pub(super) fn close_range(cx: &mut Cx<'_>, first: u32, last: u32, flags: u32) -> SysResult {
    if flags & !(CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC) != 0 || first > last {
        return Err(Errno::EINVAL);
    }
    // Only when the table is shared with another thread or process (each thread holds two
    // references): copying an unshared one would make a new lock owner and drop the POSIX record
    // locks held through it. Enforce nr_open just as unshare(CLONE_FILES) / dup_fd does: when
    // closing through the end of the table without CLOEXEC, fds from `first` onward are not copied.
    let (first, last) = (first as usize, last as usize);
    let cloexec = flags & CLOSE_RANGE_CLOEXEC != 0;
    let closed = if flags & CLOSE_RANGE_UNSHARE != 0 && Rc::strong_count(&cx.t.fds) > 2 {
        let (copy, closed) = cx
            .fds()
            .unshare_close_range(first, last, cloexec, cx.kr().nr_open)?;
        cx.set_fds(Rc::new(RefCell::new(copy)));
        closed
    } else {
        cx.fds_mut().close_range(first, last, cloexec)
    };
    let fds = cx.t.fds.clone();
    locks::closed(cx.k(), &fds, &closed);
    super::mqueue_closed(&cx.t.group, &closed);
    super::fuse::flush_all(cx, &closed);
    crate::unix::released(cx.k(), closed);
    Ok(0)
}

pub(super) fn dup(cx: &mut Cx<'_>, fd: i32) -> SysResult {
    let file = cx.fds().get(fd)?;
    cx.install_fd(file, false).map(|fd| fd as u64)
}

pub(super) fn dup3(cx: &mut Cx<'_>, old: i32, new: i32, flags: u32) -> SysResult {
    if flags & !oflags::O_CLOEXEC != 0 || old == new {
        return Err(Errno::EINVAL);
    }
    let file = cx.fds().get(old)?;
    let replaced =
        cx.fds_mut()
            .install_at_capped(new, file, flags != 0, cx.nofile(), cx.kr().nr_open);
    let fds = cx.t.fds.clone();
    let replaced: Vec<_> = replaced?.into_iter().collect();
    locks::closed(cx.k(), &fds, &replaced);
    super::mqueue_closed(&cx.t.group, &replaced);
    super::fuse::flush_all(cx, &replaced);
    crate::unix::released(cx.k(), replaced);
    Ok(new as u64)
}

/// Files `replaced` in fd table `fds` of thread group `tgid`, another process's (seccomp's
/// `SECCOMP_ADDFD_FLAG_SETFD`), are closed as dup3 closes the file it replaces: locks, message
/// queue notifications and FUSE flushes are that process's.
pub(crate) fn close_replaced(
    cx: &mut Cx<'_>,
    fds: &Rc<RefCell<crate::fd::FdTable>>,
    tgid: Tid,
    replaced: Vec<FileRef>,
) {
    locks::closed(cx.k(), fds, &replaced);
    if let Some(group) = cx.kr().groups.get(&tgid).cloned() {
        super::mqueue_closed(&group, &replaced);
    }
    for f in &replaced {
        let _ = super::fuse::flush_as(cx, f, Rc::as_ptr(fds) as usize);
    }
    crate::unix::released(cx.k(), replaced);
}

pub(super) fn pipe2(cx: &mut Cx<'_>, fds: u64, flags: u32) -> SysResult {
    const O_DIRECT: u32 = 0o200000;
    if flags & !(oflags::O_CLOEXEC | oflags::O_NONBLOCK | O_DIRECT) != 0 {
        return Err(Errno::EINVAL);
    }
    let cloexec = flags & oflags::O_CLOEXEC != 0;
    let status = flags & oflags::O_NONBLOCK;
    let (r, w) = PipeEnd::pair(pipe_capacity(cx));
    if let Some(vfs) = &cx.kr().vfs {
        vfs.anon_attrs(&AnonTarget::Pipe(r.pipe.clone()), &cx.cred(), |_| ());
    }
    let r = OpenFile::new(FileKind::Pipe(r), oflags::O_RDONLY | status);
    let w = OpenFile::new(FileKind::Pipe(w), oflags::O_WRONLY | status);
    let rfd = cx.install_fd(r, cloexec)?;
    // End the borrow of the fd table first: on failure it must be borrowed again to close the
    // read end
    let installed = cx.install_fd(w, cloexec);
    let wfd = match installed {
        Ok(fd) => fd,
        Err(e) => {
            let _ = cx.fds_mut().close(rfd);
            return Err(e);
        }
    };
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&rfd.to_le_bytes());
    out[4..].copy_from_slice(&wfd.to_le_bytes());
    if let Err(e) = put(cx, fds, out) {
        let _ = cx.fds_mut().close(rfd);
        let _ = cx.fds_mut().close(wfd);
        return Err(e);
    }
    Ok(0)
}

/// Capacity of a new pipe: as on Linux, at most pipe-max-size, except with `CAP_SYS_RESOURCE`.
fn pipe_capacity(cx: &Cx<'_>) -> usize {
    if cx.cred().capable(cap::SYS_RESOURCE) {
        PIPE_CAPACITY
    } else {
        PIPE_CAPACITY.min(cx.kr().pipe_max_size)
    }
}

pub(super) fn memfd_create(cx: &mut Cx<'_>, name: u64, flags: u32) -> SysResult {
    const MFD_CLOEXEC: u32 = 0x1;
    const MFD_ALLOW_SEALING: u32 = 0x2;
    const MFD_NOEXEC_SEAL: u32 = 0x8;
    const MFD_EXEC: u32 = 0x10;
    // MFD_HUGETLB is not supported
    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL | MFD_EXEC) != 0
        || flags & (MFD_NOEXEC_SEAL | MFD_EXEC) == MFD_NOEXEC_SEAL | MFD_EXEC
    {
        return Err(Errno::EINVAL);
    }
    let name = cx.mm().read_cstr(name, 249).map_err(|e| {
        if e == Errno::ENAMETOOLONG {
            Errno::EINVAL
        } else {
            e
        }
    })?;
    let noexec = flags & MFD_NOEXEC_SEAL != 0;
    // As shmem_get_inode with no directory: owned by the creator's filesystem ids
    let cred = cx.cred();
    let (ino, file) = cx.vfs()?.store().create_anonymous(
        if noexec { 0o666 } else { 0o777 },
        cred.fsuid,
        cred.fsgid,
    )?;
    let seals = match (flags & MFD_ALLOW_SEALING != 0, noexec) {
        (_, true) => F_SEAL_EXEC,
        (true, false) => 0,
        (false, false) => F_SEAL_SEAL,
    };
    cx.k().seals.insert(ino, seals);
    let mut path = b"/memfd:".to_vec();
    path.extend_from_slice(&name);
    path.extend_from_slice(b" (deleted)");
    let file = OpenFile::with_path(
        FileKind::Regular {
            ino,
            file,
            cow: false,
        },
        oflags::O_RDWR | oflags::O_LARGEFILE,
        Some(Rc::from(path)),
    );
    file.borrow_mut().pseudo = true;
    open_events(cx, &file, ino, None, false, oflags::O_RDWR, false);
    cx.install_fd(file, flags & MFD_CLOEXEC != 0)
        .map(|fd| fd as u64)
}

pub(super) fn fcntl(cx: &mut Cx<'_>, fd: i32, cmd: u32, arg: u64) -> SysResult {
    let file = cx.fds().get(fd)?;
    // An O_PATH descriptor allows only dup, the descriptor flags and F_GETFL (check_fcntl_cmd)
    if file.borrow().flags & oflags::O_PATH != 0
        && !matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC | F_GETFD | F_SETFD | F_GETFL)
    {
        return Err(Errno::EBADF);
    }
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            // A start not below RLIMIT_NOFILE is EINVAL; only having no free slot is EMFILE
            let limit = cx.nofile();
            let min = usize::try_from(arg as i32)
                .ok()
                .filter(|&m| m < limit)
                .ok_or(Errno::EINVAL)?;
            cx.fds_mut()
                .install_capped(file, cmd == F_DUPFD_CLOEXEC, min..limit, cx.kr().nr_open)
                .map(|fd| fd as u64)
        }
        F_GETFD => Ok(cx.fds().cloexec(fd)? as u64),
        F_SETFD => cx
            .fds_mut()
            .set_cloexec(fd, arg & FD_CLOEXEC != 0)
            .map(|()| 0),
        F_GETFL => Ok(file.borrow().flags as u64),
        F_SETFL => {
            let async_on = {
                let mut f = file.borrow_mut();
                if (arg as u32 ^ f.flags) & oflags::O_APPEND != 0 {
                    reject_flags(file_inode_flags(cx, &f)?, inode_flags::APPEND)?;
                }
                if arg as u32 & oflags::O_NOATIME != 0 && f.flags & oflags::O_NOATIME == 0 {
                    let owner = match f.node() {
                        Some(Node::Store(_, ino)) => Some(cx.vfs()?.store().attrs(ino)?),
                        Some(Node::Overlay(_, o)) => Some(cx.vfs()?.overlay_stat(o)?),
                        _ => None,
                    };
                    if owner.is_some_and(|st| !cx.cred().owns(&st)) {
                        return Err(Errno::EPERM);
                    }
                }
                f.flags = (f.flags & !oflags::SETFL_MASK) | (arg as u32 & oflags::SETFL_MASK);
                f.flags & oflags::O_ASYNC != 0
            };
            if async_on {
                super::poll::register_fasync(cx, &file, fd);
            }
            Ok(0)
        }
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            record_lock(cx, &file, cmd, arg)
        }
        // The dispatcher translates F_SETOWN's argument and F_GETOWN's result (pid_args)
        F_SETOWN => set_owner(cx, &file, arg as i32).map(|()| 0),
        F_GETOWN => Ok(get_owner(&file) as i64 as u64),
        F_SETOWN_EX => {
            let b: [u8; 8] = get(cx, arg)?;
            let ty = i32::from_le_bytes(b[..4].try_into().unwrap());
            let pid = i32::from_le_bytes(b[4..].try_into().unwrap());
            if !matches!(ty, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
                return Err(Errno::EINVAL);
            }
            record_owner(cx, &file, (ty, cx.pid_in(pid))).map(|()| 0)
        }
        F_GETOWN_EX => {
            let (ty, pid) = file.borrow().owner;
            let pid = cx.pid_out(pid);
            let mut b = [0u8; 8];
            b[..4].copy_from_slice(&ty.to_le_bytes());
            b[4..].copy_from_slice(&pid.to_le_bytes());
            put(cx, arg, b).map(|()| 0)
        }
        F_SETSIG => {
            if arg != 0 && Signal::new(arg as i32).is_none() {
                return Err(Errno::EINVAL);
            }
            file.borrow_mut().sig = arg as i32;
            Ok(0)
        }
        F_GETSIG => Ok(file.borrow().sig as u64),
        F_SETLEASE => super::lease::set(cx, &file, fd, arg as i16).map(|()| 0),
        F_GETLEASE => Ok(super::lease::get(cx, &file) as u64),
        F_GETPIPE_SZ | F_SETPIPE_SZ => {
            let f = file.borrow();
            let FileKind::Pipe(end) = &f.kind else {
                return Err(Errno::EBADF);
            };
            let mut p = end.pipe.borrow_mut();
            if cmd == F_GETPIPE_SZ {
                return Ok(p.capacity as u64);
            }
            // Round up by pages to a power of two; growing past pipe-max-size requires
            // CAP_SYS_RESOURCE (shrinking or keeping the current size is allowed even when above
            // pipe-max-size). Shrinking must leave room for all occupied and reserved slots.
            let size = (arg as u32 as usize)
                .max(PIPE_BUF)
                .checked_next_power_of_two()
                .filter(|&n| n <= 1 << 31)
                .ok_or(Errno::EINVAL)?;
            if size > cx.kr().pipe_max_size
                && size > p.capacity
                && !cx.cred().capable(cap::SYS_RESOURCE)
            {
                return Err(Errno::EPERM);
            }
            if size / PIPE_BUF < p.used_slots() {
                return Err(Errno::EBUSY);
            }
            p.capacity = size;
            p.room += 1;
            request_wake_object(crate::pipe::object(&end.pipe));
            Ok(size as u64)
        }
        // Only memfds can have seals added
        F_ADD_SEALS | F_GET_SEALS => {
            let f = file.borrow();
            let FileKind::Regular { ino, .. } = f.kind else {
                return Err(Errno::EINVAL);
            };
            let seals = match cx.kr().seals.get(&ino) {
                Some(&seals) => seals,
                None if cx.vfs()?.fs_of(&Node::Store(f.mnt, ino)) == Fs::Tmpfs => F_SEAL_SEAL,
                None => return Err(Errno::EINVAL),
            };
            if cmd == F_GET_SEALS {
                return Ok(seals as u64);
            }
            let mut add = arg as u32;
            if add & !F_SEAL_ALL != 0 {
                return Err(Errno::EINVAL);
            }
            if !f.writable() || seals & F_SEAL_SEAL != 0 {
                return Err(Errno::EPERM);
            }
            // Sealing an executable memfd's execute bits also seals its contents, W^X from then
            // on (6.3's memfd_add_seals)
            if add & F_SEAL_EXEC != 0 && cx.vfs()?.store().attrs(ino)?.mode & 0o111 != 0 {
                add |= F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;
            }
            // Writes cannot be sealed while writable shared mappings exist
            if add & F_SEAL_WRITE != 0 && writably_mapped(cx, &f) {
                return Err(Errno::EBUSY);
            }
            *cx.k().seals.get_mut(&ino).unwrap() |= add;
            Ok(0)
        }
        _ => {
            crate::stub::hit(cx, crate::stub::Stub::Fcntl(cmd));
            Err(Errno::EINVAL)
        }
    }
}

/// `F_SETOWN` and the socket ioctls `FIOSETOWN`/`SIOCSPGRP` (Linux's `f_setown`): `pid` is
/// already a global number, a negative one a process group; `INT_MIN`, which has no negation, is
/// `EINVAL`.
fn set_owner(cx: &Cx<'_>, file: &FileRef, pid: i32) -> Result<(), Errno> {
    let owner = match pid.checked_neg() {
        None => return Err(Errno::EINVAL),
        Some(g) if pid < 0 => (F_OWNER_PGRP, g),
        Some(_) => (F_OWNER_PID, pid),
    };
    record_owner(cx, file, owner)
}

/// Records a file's owner (type, global number) for `F_SETOWN*` (Linux's `__f_setown` with
/// force): a number no pid has is `ESRCH` (`find_vpid`; numbers the caller cannot see arrive as
/// [`super::NO_PID`]), 0 removes the owner, and the caller's real and effective user IDs are kept
/// with it for the permission check at delivery ([`super::poll::send_to_owner`]).
fn record_owner(cx: &Cx<'_>, file: &FileRef, (ty, pid): (i32, i32)) -> Result<(), Errno> {
    if pid != 0 {
        let k = cx.kr();
        let named = k.tasks.contains_key(&pid)
            || k.groups.contains_key(&pid)
            || k.groups.values().any(|g| {
                let g = g.borrow();
                g.pgid == pid || g.sid == pid
            });
        if !named {
            return Err(Errno::ESRCH);
        }
    }
    let cred = cx.cred();
    let mut f = file.borrow_mut();
    f.owner = (ty, pid);
    if pid != 0 {
        f.owner_ids = (cred.ruid, cred.euid);
    }
    Ok(())
}

/// `F_GETOWN`, `FIOGETOWN`, `SIOCGPGRP`: the owner as a global number, a process group negated.
fn get_owner(file: &FileRef) -> Tid {
    let (ty, pid) = file.borrow().owner;
    if ty == F_OWNER_PGRP { -pid } else { pid }
}

/// fcntl's record-lock commands ([`crate::locks`]): `arg` points at a `struct flock`.
fn record_lock(cx: &mut Cx<'_>, file: &FileRef, cmd: u32, arg: u64) -> SysResult {
    let mut b: [u8; 32] = get(cx, arg)?;
    let half = |off: usize| i16::from_le_bytes(b[off..off + 2].try_into().unwrap());
    let long = |off: usize| i64::from_le_bytes(b[off..off + 8].try_into().unwrap());
    let (l_type, whence, l_start, l_len) = (half(0), half(2), long(8), long(16));
    let l_pid = i32::from_le_bytes(b[24..28].try_into().unwrap());
    let ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    let getlk = matches!(cmd, F_GETLK | F_OFD_GETLK);
    if ofd && l_pid != 0 {
        return Err(Errno::EINVAL);
    }
    let write = match l_type {
        F_RDLCK => false,
        F_WRLCK => true,
        F_UNLCK if !getlk => false,
        _ => return Err(Errno::EINVAL),
    };
    let unlock = l_type == F_UNLCK;
    if !matches!(whence as u32, SEEK_SET | SEEK_CUR | SEEK_END) {
        return Err(Errno::EINVAL);
    }
    let (key, start, end) = {
        let f = file.borrow();
        if !getlk && !unlock && !(if write { f.writable() } else { f.readable() }) {
            return Err(Errno::EBADF);
        }
        let Some(key) = LockKey::of(&f) else {
            // This file kind has no lock identity.
            if getlk {
                b[..2].copy_from_slice(&F_UNLCK.to_le_bytes());
                put(cx, arg, b)?;
            }
            return Ok(0);
        };
        let base = match whence as u32 {
            SEEK_SET => 0,
            SEEK_CUR => f.pos,
            SEEK_END => match &f.kind {
                FileKind::Regular { ino, file, .. } => regular_size(&*cx.vfs()?, *ino, file)?,
                _ => 0,
            },
            _ => return Err(Errno::EINVAL),
        };
        // Linux's flock64_to_posix_lock, in its order: the start may not pass OFFSET_MAX
        // (EOVERFLOW) or be negative (EINVAL); an l_len of 0 means to the end of the file and
        // beyond, a positive one may end at OFFSET_MAX at most (EOVERFLOW), a negative one is
        // [start + l_len, start) and may not begin below 0 (EINVAL)
        let base = i64::try_from(base).map_err(|_| Errno::EOVERFLOW)?;
        if l_start > i64::MAX - base {
            return Err(Errno::EOVERFLOW);
        }
        let start = base + l_start;
        if start < 0 {
            return Err(Errno::EINVAL);
        }
        // The last byte, inclusive
        let (start, last) = match l_len {
            0 => (start, i64::MAX),
            n if n > 0 => {
                if n - 1 > i64::MAX - start {
                    return Err(Errno::EOVERFLOW);
                }
                (start, start + (n - 1))
            }
            n => {
                if start + n < 0 {
                    return Err(Errno::EINVAL);
                }
                (start + n, start - 1)
            }
        };
        let end = if last == i64::MAX {
            u64::MAX
        } else {
            last as u64 + 1
        };
        (key, start as u64, end)
    };
    let owner = if ofd {
        file.borrow_mut().holds_locks = true;
        Owner::Ofd(Rc::downgrade(file))
    } else {
        cx.fds_mut().holds_locks = true;
        Owner::Posix(Rc::downgrade(&cx.t.fds))
    };
    let req = Lock {
        owner,
        file: Rc::downgrade(file),
        pid: if ofd { -1 } else { cx.tgid() },
        start,
        end,
        write,
        seq: 0,
    };
    if getlk {
        // With no conflict only l_type is changed to F_UNLCK; the other fields stay
        match cx.k().locks.conflict(key, &req) {
            None => b[..2].copy_from_slice(&F_UNLCK.to_le_bytes()),
            Some(l) => {
                let ty = if l.write { F_WRLCK } else { F_RDLCK };
                let len = if l.end == u64::MAX {
                    0
                } else {
                    l.end - l.start
                };
                b[..2].copy_from_slice(&ty.to_le_bytes());
                b[2..4].copy_from_slice(&(SEEK_SET as i16).to_le_bytes());
                b[8..16].copy_from_slice(&l.start.to_le_bytes());
                b[16..24].copy_from_slice(&len.to_le_bytes());
                // -1 for OFD locks, otherwise the number the caller sees (Linux's
                // locks_translate_pid)
                let pid = if l.pid > 0 { cx.pid_out(l.pid) } else { l.pid };
                b[24..28].copy_from_slice(&pid.to_le_bytes());
            }
        }
        return put(cx, arg, b).map(|()| 0);
    }
    let tid = cx.tid();
    loop {
        let locks = &mut cx.k().locks;
        if unlock || locks.conflict(key, &req).is_none() {
            locks.set_waiting(tid, None);
            locks.set(key, req, unlock);
            return Ok(0);
        }
        if matches!(cmd, F_SETLK | F_OFD_SETLK) {
            return Err(Errno::EAGAIN);
        }
        if locks.deadlock(key, &req) {
            locks.set_waiting(tid, None);
            return Err(Errno::EDEADLK);
        }
        locks.set_waiting(
            tid,
            Some(Waiter {
                tid,
                key,
                req: req.clone(),
            }),
        );
        if cx.interrupted() {
            cx.k().locks.set_waiting(tid, None);
            return Err(Errno::ERESTARTSYS);
        }
        // The holder requests a wakeup when it unlocks, closes the file or exits
        if let Err(e) = cx.wait_on(None, &mut [], crate::kernel::wake::LOCK) {
            cx.k().locks.set_waiting(tid, None);
            return Err(e);
        }
    }
}

/// Whether some address space maps this open file with a writable shared mapping.
fn writably_mapped(cx: &Cx<'_>, f: &OpenFile) -> bool {
    use std::os::unix::fs::MetadataExt;
    let FileKind::Regular { file, .. } = &f.kind else {
        return false;
    };
    let Ok(meta) = file.metadata() else {
        return false;
    };
    cx.kr().tasks.values().any(|t| {
        t.res
            .borrow()
            .mm
            .borrow()
            .writably_maps(meta.dev(), meta.ino())
    })
}

pub(super) fn flock(cx: &mut Cx<'_>, fd: i32, op: u32) -> SysResult {
    const LOCK_SH: u32 = 1;
    const LOCK_EX: u32 = 2;
    const LOCK_NB: u32 = 4;
    const LOCK_UN: u32 = 8;
    let file = cx.fds().get(fd)?;
    // O_PATH descriptors are not found (fdget)
    if file.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    let Some(key) = LockKey::of(&file.borrow()) else {
        return Ok(0);
    };
    let exclusive = match op & !LOCK_NB {
        LOCK_SH => false,
        LOCK_EX => true,
        LOCK_UN => {
            cx.k().flocks.unlock(key, &file);
            return Ok(0);
        }
        _ => return Err(Errno::EINVAL),
    };
    let tgid = cx.tgid();
    let tid = cx.tid();
    let result = loop {
        if cx.k().flocks.try_lock(key, &file, exclusive, tgid) {
            break Ok(0);
        }
        if op & LOCK_NB != 0 {
            return Err(Errno::EAGAIN);
        }
        cx.k().flocks.set_waiting(
            tid,
            Some(crate::locks::FlockWaiter {
                tid,
                key,
                file: Rc::downgrade(&file),
                exclusive,
                pid: tgid,
            }),
        );
        if cx.interrupted() {
            break Err(Errno::ERESTARTSYS);
        }
        // The file holding the lock requests a wakeup when it unlocks, converts or closes
        // (OpenFile's destructor)
        if let Err(e) = cx.wait_on(None, &mut [], crate::kernel::wake::LOCK) {
            break Err(e);
        }
    };
    cx.k().flocks.set_waiting(tid, None);
    result
}

fn real_inode(vfs: &Vfs, node: &Node) -> Option<Ino> {
    match node {
        Node::Store(_, ino) => Some(*ino),
        Node::Overlay(_, o) => Some(vfs.overlay().node(*o).real()),
        _ => None,
    }
}

pub(super) fn file_inode_flags(cx: &Cx<'_>, f: &OpenFile) -> Result<u32, Errno> {
    if matches!(
        f.kind,
        FileKind::Regular { .. } | FileKind::Directory { .. }
    ) {
        let vfs = cx.vfs()?;
        if let Some(ino) = f.node().and_then(|n| real_inode(&vfs, &n)) {
            return vfs.store().flags(ino);
        }
    }
    Ok(0)
}

fn reject_flags(flags: u32, forbidden: u32) -> Result<(), Errno> {
    if flags & forbidden != 0 {
        Err(Errno::EPERM)
    } else {
        Ok(())
    }
}

fn fileattr_ioctl(cx: &Cx<'_>, file: &FileRef, request: u32, arg: u64) -> SysResult {
    let (node, memfd) = {
        let f = file.borrow();
        if !matches!(
            f.kind,
            FileKind::Regular { .. } | FileKind::Directory { .. }
        ) {
            return Err(Errno::ENOTTY);
        }
        (f.node().ok_or(Errno::ENOTTY)?, f.pseudo)
    };
    let vfs = cx.vfs()?;
    let ino = real_inode(&vfs, &node).ok_or(Errno::ENOTTY)?;
    if request == FS_IOC_GETFLAGS {
        let flags = vfs.store().flags(ino)? & inode_flags::SUPPORTED;
        return put(cx, arg, flags.to_le_bytes()).map(|()| 0);
    }
    // The request encodes sizeof(long), but Linux reads and writes an int.
    let flags = u32::from_le_bytes(get(cx, arg)?);
    if !memfd && vfs.readonly(&node) {
        return Err(Errno::EROFS);
    }
    let cred = cx.cred();
    let st = vfs.store().attrs(ino)?;
    if !cred.owns(&st)
        || ((flags ^ st.flags) & inode_flags::PROTECTED != 0 && !cred.capable(cap::LINUX_IMMUTABLE))
    {
        return Err(Errno::EPERM);
    }
    if flags & !inode_flags::SUPPORTED != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let upper = match node {
        Node::Overlay(_, o) => copy_up(cx, &vfs, o, CopyUp::All)?,
        _ => ino,
    };
    let f = file.borrow();
    let unlinked = f
        .regular_backing()
        .filter(|(ino, _, _)| *ino == upper && st.nlink == 0);
    let host = if unlinked.is_some() && !vfs.store().held(upper)? {
        unlinked.map(|(_, host, _)| host)
    } else {
        None
    };
    vfs.store().set_flags_open(upper, flags, host)?;
    Ok(0)
}

pub(super) fn ioctl(cx: &mut Cx<'_>, fd: i32, request: u32, arg: u64) -> SysResult {
    let file = io_file(cx, fd)?;
    if request >> 8 & 0xff == b'd' as u32 {
        let render = match &file.borrow().kind {
            FileKind::Render { file, .. } => Some(file.clone()),
            _ => None,
        };
        if let Some(render) = render {
            return super::gpu::ioctl(cx, &render, request, arg);
        }
    }
    match request {
        FS_IOC_GETFLAGS | FS_IOC_SETFLAGS => return fileattr_ioctl(cx, &file, request, arg),
        FIOCLEX | FIONCLEX => {
            return cx.fds_mut().set_cloexec(fd, request == FIOCLEX).map(|()| 0);
        }
        FIONBIO => {
            let on = u32::from_le_bytes(get(cx, arg)?) != 0;
            let mut f = file.borrow_mut();
            f.flags = (f.flags & !oflags::O_NONBLOCK) | if on { oflags::O_NONBLOCK } else { 0 };
            return Ok(0);
        }
        FIOASYNC => {
            let on = u32::from_le_bytes(get(cx, arg)?) != 0;
            let was = {
                let mut f = file.borrow_mut();
                let was = f.flags & oflags::O_ASYNC != 0;
                f.flags = (f.flags & !oflags::O_ASYNC) | if on { oflags::O_ASYNC } else { 0 };
                was
            };
            if on && !was {
                super::poll::register_fasync(cx, &file, fd);
            }
            return Ok(0);
        }
        // Handled before the file type is looked at, as on Linux (do_vfs_ioctl)
        FICLONE | FICLONERANGE => {
            let (src, range) = if request == FICLONE {
                (arg as i32, (0, 0, 0))
            } else {
                // struct file_clone_range: the source fd (s64), then the source offset, the
                // length (0 is to the source's end) and the destination offset
                let b: [u8; 32] = get(cx, arg)?;
                let word = |i: usize| u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
                (word(0) as i64 as i32, (word(1), word(2), word(3)))
            };
            let src = io_file(cx, src)?;
            return clone_range(cx, &src, &file, range);
        }
        FIDEDUPERANGE => {
            // Header of struct file_dedupe_range: two u64s, dest_count (u16) and two reserved
            // fields
            let b: [u8; 24] = get(cx, arg)?;
            if b[18..24].iter().any(|&x| x != 0) {
                return Err(Errno::EINVAL);
            }
            return match file.borrow().kind {
                FileKind::Regular { .. } => Err(Errno::EOPNOTSUPP),
                FileKind::Directory { .. } => Err(Errno::EISDIR),
                _ => Err(Errno::EINVAL),
            };
        }
        // Socket owner (as with F_SETOWN and F_GETOWN; negative is a process group)
        FIOSETOWN | SIOCSPGRP | FIOGETOWN | SIOCGPGRP
            if matches!(file.borrow().kind, FileKind::Socket(_)) =>
        {
            // The number is in memory, so translated here, as the dispatcher does for F_SETOWN
            if matches!(request, FIOSETOWN | SIOCSPGRP) {
                let pid = match i32::from_le_bytes(get(cx, arg)?) {
                    p if p > 0 => cx.pid_in(p),
                    p if p < 0 && p != i32::MIN => -cx.pid_in(-p),
                    p => p,
                };
                return set_owner(cx, &file, pid).map(|()| 0);
            }
            let pid = get_owner(&file);
            let local = cx.pid_out(pid.abs());
            let pid = if pid < 0 { -local } else { local };
            return put(cx, arg, pid.to_le_bytes()).map(|()| 0);
        }
        // Before the file's own ioctls, as in Linux's do_vfs_ioctl: every regular inode answers,
        // in the store and tmpfs, procfs, sysfs and nsfs, FUSE files, and message queues
        FIONREAD
            if matches!(
                file.borrow().kind,
                FileKind::Regular { .. }
                    | FileKind::Proc { .. }
                    | FileKind::MessageQueue(_)
                    | FileKind::Fuse(_)
            ) =>
        {
            if let Some(n) = unread(cx, &file)? {
                return put(cx, arg, n.to_le_bytes()).map(|()| 0);
            }
        }
        _ => {}
    }
    let ns = match &file.borrow().kind {
        FileKind::Proc {
            mnt,
            node: PseudoNode::NsFile(kind, _),
            ns: Some(r),
            ..
        } => Some((*mnt, *kind, r.clone())),
        _ => None,
    };
    if let Some((mnt, kind, r)) = ns {
        return super::ns::ioctl(cx, mnt, kind, &r, request, arg);
    }
    if matches!(file.borrow().kind, FileKind::FuseDev(_)) {
        return super::fuse::dev_ioctl(cx, &file, request, arg);
    }
    // Take out the object needed, then release the borrow of the open file: NOTIF_RECV waits,
    // and while it waits other threads may want to change this open file (fcntl, FIONBIO)
    let notify = match &file.borrow().kind {
        FileKind::SeccompNotify(l) => Some(l.filter()),
        _ => None,
    };
    if let Some(f) = notify {
        return crate::seccomp::ioctl(cx, &f, request, arg);
    }
    let pty = match &file.borrow().kind {
        FileKind::Pty(end) => Some((end.tty.clone(), (end.master, end.born), end.mnt)),
        _ => None,
    };
    if let Some((t, side, mnt)) = pty {
        if request == tty::TIOCGPTPEER {
            return tty::open_peer(cx, &t, side, mnt, arg as u32);
        }
        let readable = file.borrow().readable();
        return tty::ioctl(cx, &t, side, readable, request, arg);
    }
    let sock = match &file.borrow().kind {
        FileKind::Socket(s) => Some(s.clone()),
        _ => None,
    };
    if let Some(s) = sock {
        return super::net::ioctl(cx, &s, request, arg);
    }
    let device = match &file.borrow().kind {
        FileKind::Device { dev, .. } => Some(*dev),
        _ => None,
    };
    match device {
        Some(Device::Loop) => return super::loopdev::ioctl(cx, &file, request, arg),
        Some(Device::LoopControl) => return super::loopdev::control_ioctl(cx, request, arg),
        _ => {}
    }
    let host_fd = match &file.borrow().kind {
        FileKind::Host(fd) => *fd,
        FileKind::Pipe(end) if request == FIONREAD => {
            let n = end.pipe.borrow().bytes().len() as i32;
            return put(cx, arg, n.to_le_bytes()).map(|()| 0);
        }
        FileKind::Inotify(i) if request == FIONREAD => {
            let n = i.borrow().pending() as i32;
            return put(cx, arg, n.to_le_bytes()).map(|()| 0);
        }
        FileKind::Device {
            dev: Device::Random,
            ..
        } => return random_ioctl(cx, request, arg),
        kind => {
            crate::stub::ioctl(cx, request, crate::stub::file_kind(kind));
            return Err(Errno::ENOTTY);
        }
    };
    let Some(&(_, size, out)) = HOST_IOCTLS.iter().find(|(r, ..)| *r == request) else {
        crate::stub::ioctl(cx, request, "host file");
        return Err(Errno::ENOTTY);
    };
    let mut buf = vec![0u8; size];
    if !out {
        cx.mm().read(UserSlice::new(arg, size), &mut buf)?;
    }
    let rc = appine_hal::ioctl(host_fd, request as u64, &mut buf).map_err(Errno)?;
    if out {
        cx.mm().write(UserSlice::new(arg, size), &buf)?;
    }
    Ok(rc as u64)
}

/// FIONREAD on a regular file (Linux's `do_vfs_ioctl`): the size as stat reports it less the file
/// position, as an int (negative past the end, cut to 32 bits as Linux's `put_user` into an int
/// cuts it); None when the file is not regular.
fn unread(cx: &Cx<'_>, file: &FileRef) -> Result<Option<i32>, Errno> {
    // asm-generic's struct stat: st_mode at 16, st_size at 48 (encode_stat)
    let st = file_stat(cx, file)?;
    let mode = u32::from_le_bytes(st[16..20].try_into().unwrap());
    if mode & mode::S_IFMT != mode::S_IFREG {
        return Ok(None);
    }
    let size = i64::from_le_bytes(st[48..56].try_into().unwrap());
    Ok(Some(size.wrapping_sub(file.borrow().pos as i64) as i32))
}

/// The open file of an ioctl fd or FICLONE's source fd: as with Linux's `fdget`, files opened
/// with `O_PATH` are not accepted (EBADF).
fn io_file(cx: &Cx<'_>, fd: i32) -> Result<FileRef, Errno> {
    let file = cx.fds().get(fd)?;
    if file.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    Ok(file)
}

/// FICLONE, FICLONERANGE: checked in Linux 6.1's order (`ioctl_file_clone`,
/// `do_clone_file_range`, `generic_remap_file_range_prep`, `generic_remap_checks`), with the
/// store's regular files cloning as those of btrfs and XFS do: `len` 0 is to the source's end,
/// offsets must be block-aligned, and so must the length unless it reaches the source's end. A
/// clone of a whole file into the start of one no longer than it shares the object
/// ([`try_share`]); any other range, or a file that cannot share now, is copied, which leaves the
/// same contents. tmpfs, overlay files and memfds have no reflink (EOPNOTSUPP), as in Linux
/// (shmem has none, and an overlay on ext4 has none either); files not on the same mount are
/// EXDEV.
fn clone_range(
    cx: &mut Cx<'_>,
    input: &FileRef,
    output: &FileRef,
    (pos_in, len, pos_out): (u64, u64, u64),
) -> SysResult {
    const BLOCK: u64 = 4096;
    let vfs = cx.vfs()?;
    {
        let (i, o) = (input.borrow(), output.borrow());
        // A memfd is on the internal shm mount
        let mount = |f: &OpenFile| match f.pseudo {
            true => None,
            false => f.node().map(|n| n.mnt()),
        };
        if i.pseudo != o.pseudo || mount(&i) != mount(&o) {
            return Err(Errno::EXDEV);
        }
        // generic_file_rw_checks
        if [&i, &o]
            .iter()
            .any(|f| matches!(f.kind, FileKind::Directory { .. }))
        {
            return Err(Errno::EISDIR);
        }
        if [&i, &o]
            .iter()
            .any(|f| !matches!(f.kind, FileKind::Regular { .. }))
        {
            return Err(Errno::EINVAL);
        }
        if !i.readable() || !o.writable() || o.flags & oflags::O_APPEND != 0 {
            return Err(Errno::EBADF);
        }
        reject_flags(file_inode_flags(cx, &o)?, inode_flags::PROTECTED)?;
        let tmpfs = |f: &OpenFile| {
            f.data_ino()
                .is_some_and(|ino| vfs.tmpfs_dev(&Node::Store(f.mnt, ino)).is_some())
        };
        if i.pseudo || i.ovl.is_some() || o.ovl.is_some() || tmpfs(&i) {
            return Err(Errno::EOPNOTSUPP);
        }
    }
    // remap_verify_area
    let fits = |pos: u64| {
        pos as i64 >= 0 && len as i64 >= 0 && pos.checked_add(len).is_some_and(|e| e as i64 >= 0)
    };
    if !fits(pos_in) || !fits(pos_out) {
        return Err(Errno::EINVAL);
    }
    let size = |f: &FileRef| -> Result<u64, Errno> {
        match &f.borrow().kind {
            FileKind::Regular { ino, file, .. } => Ok(vfs.store().stat_open(*ino, file)?.size),
            _ => Err(Errno::EINVAL),
        }
    };
    let (size_in, size_out) = (size(input)?, size(output)?);
    let mut len = len;
    if len == 0 {
        if pos_in == size_in {
            return Ok(0);
        }
        if pos_in > size_in {
            return Err(Errno::EINVAL);
        }
        len = size_in - pos_in;
    }
    if pos_in % BLOCK != 0 || pos_out % BLOCK != 0 || pos_in >= size_in {
        return Err(Errno::EINVAL);
    }
    let mut count = len.min(size_in - pos_in);
    // generic_write_check_limits
    let limit = cx.t.group.borrow().rlimits[RLIMIT_FSIZE as usize].0;
    if limit != u64::MAX {
        if pos_out >= limit {
            return Err(file_too_big(cx));
        }
        count = count.min(limit - pos_out);
    }
    count = count.min(i64::MAX as u64 - pos_out);
    let bcount = if pos_in + count == size_in {
        size_in.next_multiple_of(BLOCK) - pos_in
    } else if count % BLOCK != 0 {
        return Err(Errno::EINVAL);
    } else {
        count
    };
    let same = input.borrow().data_ino() == output.borrow().data_ino();
    if same && pos_out + bcount > pos_in && pos_out < pos_in + bcount {
        return Err(Errno::EINVAL);
    }
    // A request cut short is bounced back (no REMAP_FILE_CAN_SHORTEN)
    if count != len {
        return Err(Errno::EINVAL);
    }
    let whole = pos_in == 0 && pos_out == 0 && count == size_in && size_out <= size_in;
    if whole && try_share(cx, input, output)? {
        inotify::file_io_event(cx.kr(), &input.borrow(), inotify::IN_ACCESS);
        inotify::file_io_event(cx.kr(), &output.borrow(), inotify::IN_MODIFY);
        return Ok(0);
    }
    let mut done = 0;
    while done < count {
        let n = (count - done).min(MAX_COPY as u64) as usize;
        let at = (Some(pos_in + done), Some(pos_out + done));
        match copy_data(cx, input, at.0, output, at.1, n)? {
            0 => return Err(Errno::EIO),
            k => done += k as u64,
        }
    }
    Ok(0)
}

// ---- Reading and writing ----

/// The route one read or write takes, carried out without holding a borrow of the open file.
enum IoPath {
    Host(i32),
    Pipe(Rc<RefCell<Pipe>>),
    /// A terminal, whether the open file is the master, and how many hangups it had seen when
    /// opened ([`crate::tty::PtyEnd::born`]).
    Pty(Rc<RefCell<Tty>>, (bool, u32)),
    Socket(SocketRef),
    EventFd(Rc<RefCell<EventFd>>),
    TimerFd(Rc<RefCell<TimerFd>>),
    SignalFd(Rc<RefCell<crate::fd::SignalFd>>),
    Inotify(Rc<RefCell<super::Inotify>>),
    /// `/proc/<pid>/pagemap`: computed on the fly from the read position, from the address space
    /// pinned at open (None once it has been released).
    Pagemap(Option<Rc<RefCell<crate::mm::Mm>>>),
    /// `/proc/<pid>/mem`: the position is the address.
    /// The address space of `/proc/<pid>/mem` at open, None when it has been released.
    Mem(Option<Rc<RefCell<crate::mm::Mm>>>),
    /// `/dev/kmsg`: read and written by record, with the read position in the open file
    /// ([`crate::klog::KmsgFile`]).
    Kmsg,
    /// `/proc/kmsg`: syslog's read.
    ProcKmsg(Rc<RefCell<crate::klog::Klog>>),
    /// A loop device: read and written through its backing file (`syscall::loopdev`).
    Loop(crate::syscall::loopdev::LoopRef),
    /// A file in a FUSE filesystem: read and written through its daemon (`syscall::fuse`).
    Fuse(super::fuse::Io),
    /// `/dev/fuse`: a daemon reading requests and writing replies.
    FuseDev,
    /// Everything else (files in the store, devices, other synthetic files, and files with no
    /// read or write operation): never waits for data. Regular files are read and written with
    /// the BKL released ([`unlocked_io`]), except `O_APPEND` writes; the rest is done directly
    /// while holding the borrow.
    Local,
}

const SPLICE_F_NONBLOCK: u32 = 2;
const RWF_NOAPPEND: u32 = 0x20;

pub(super) fn read(cx: &mut Cx<'_>, fd: i32, buf: u64, len: usize) -> SysResult {
    let file = cx.fds().get(fd)?;
    read_file(cx, &file, buf, len, None)
}

pub(super) fn write(cx: &mut Cx<'_>, fd: i32, buf: u64, len: usize) -> SysResult {
    let file = cx.fds().get(fd)?;
    write_file(cx, &file, buf, len, None)
}

pub(super) fn pread(cx: &mut Cx<'_>, fd: i32, buf: u64, len: usize, offset: i64) -> SysResult {
    let offset = checked_offset(offset)?;
    let file = cx.fds().get(fd)?;
    read_file(cx, &file, buf, len, offset)
}

/// Per-request I/O flags (`RWF_NOWAIT`, `RWF_APPEND`) that override `OpenFile::flags` for a
/// single transfer without mutating the shared open file description.
#[derive(Clone, Copy, Default)]
pub(super) struct IoFlags {
    pub nowait: bool,
    pub append: bool,
}

pub(super) fn pwrite(cx: &mut Cx<'_>, fd: i32, buf: u64, len: usize, offset: i64) -> SysResult {
    let offset = checked_offset(offset)?;
    let file = cx.fds().get(fd)?;
    let offset = append_offset(&file, offset, false)?;
    write_file(cx, &file, buf, len, offset)
}

pub(super) fn readv(cx: &mut Cx<'_>, fd: i32, iov: u64, count: usize) -> SysResult {
    vectored(cx, fd, iov, count, None, false)
}

pub(super) fn writev(cx: &mut Cx<'_>, fd: i32, iov: u64, count: usize) -> SysResult {
    vectored(cx, fd, iov, count, None, true)
}

/// preadv, pwritev; with `flags` not None, preadv2 and pwritev2, where an offset of -1 means the
/// file position.
pub(super) fn pvectored(
    cx: &mut Cx<'_>,
    fd: i32,
    iov: u64,
    count: usize,
    offset: i64,
    flags: Option<u32>,
    write: bool,
) -> SysResult {
    // RWF_HIPRI does not affect the result; RWF_DSYNC and RWF_SYNC wait for the write to reach
    // disk ([`write_sync`]); RWF_NOWAIT makes blocking files return EAGAIN without mutating
    // O_NONBLOCK; RWF_APPEND appends per request without mutating O_APPEND; RWF_NOAPPEND (since
    // Linux 6.9, used by musl's pwrite) writes at the given offset on an O_APPEND file. Unknown
    // flags are EOPNOTSUPP.
    const RWF_NOWAIT: u32 = 0x8;
    const RWF_APPEND: u32 = 0x10;
    const RWF_SUPPORTED: u32 = 0x7 | RWF_NOWAIT | RWF_APPEND | RWF_NOAPPEND;
    let mut offset = match flags {
        Some(f) if f & !RWF_SUPPORTED != 0 => return Err(Errno::EOPNOTSUPP),
        Some(_) if offset == -1 => None,
        _ => checked_offset(offset)?,
    };
    let rwf = flags.unwrap_or(0);
    let append = write && rwf & RWF_APPEND != 0;
    let noappend = rwf & RWF_NOAPPEND != 0;
    if write && (append || !noappend) {
        offset = append_offset(&cx.fds().get(fd)?, offset, append)?;
    }
    let io = IoFlags {
        nowait: rwf & RWF_NOWAIT != 0,
        append,
    };
    vectored_inner(cx, fd, iov, count, offset, write, io, rwf)
}

fn checked_offset(offset: i64) -> Result<Option<u64>, Errno> {
    u64::try_from(offset).map(Some).map_err(|_| Errno::EINVAL)
}

/// Positioned appends to host stdio use its host length. Store objects select their
/// logical EOF inside the shared scalar and vectored write paths.
pub(super) fn append_offset(
    file: &FileRef,
    offset: Option<u64>,
    append: bool,
) -> Result<Option<u64>, Errno> {
    let f = file.borrow();
    match &f.kind {
        FileKind::Host(fd)
            if offset.is_some()
                && host_regular(*fd)
                && (append || f.flags & oflags::O_APPEND != 0) =>
        {
            Ok(Some(appine_hal::fstat(*fd).map_err(Errno)?.st_size as u64))
        }
        _ => Ok(offset),
    }
}

fn regular_append_offset(
    cx: &Cx<'_>,
    file: &OpenFile,
    offset: Option<u64>,
    append: bool,
) -> Result<Option<u64>, Errno> {
    if offset.is_some()
        && (append || file.flags & oflags::O_APPEND != 0)
        && let FileKind::Regular { ino, file, .. } = &file.kind
    {
        return Ok(Some(regular_size(&*cx.vfs()?, *ino, file)?));
    }
    Ok(offset)
}

/// splice: moves data between a pipe and another file (or two pipes). Copies through a host
/// buffer, not zero-copy. When to wait follows Linux 6.1's `do_splice`: between two pipes, for data
/// and then for room unless `SPLICE_F_NONBLOCK` or either end's `O_NONBLOCK`; from a pipe, for
/// data unless `SPLICE_F_NONBLOCK` or the input pipe's `O_NONBLOCK`, writing the output as its own
/// `O_NONBLOCK` says (data leaves the pipe only after the write succeeds, so a failed write loses
/// none); into a pipe, for room unless `SPLICE_F_NONBLOCK` or the output pipe's `O_NONBLOCK`,
/// reading the input as its own `O_NONBLOCK` says ([`splice_read`]).
pub(super) fn splice(
    cx: &mut Cx<'_>,
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    len: usize,
    flags: u32,
) -> SysResult {
    if len == 0 {
        return Ok(0);
    }
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let input = cx.fds().get(fd_in)?;
    let output = cx.fds().get(fd_out)?;
    if input.borrow().flags & oflags::O_PATH != 0 || output.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    let (in_pipe, out_pipe) = (pipe_of(&input), pipe_of(&output));
    // Linux 6.1 __do_splice rejects offsets on pipe ends (ESPIPE) and copies user offsets
    // (EFAULT) before do_splice checks access modes (EBADF), spliceability, and seekability.
    if in_pipe.is_some() && off_in != 0 || out_pipe.is_some() && off_out != 0 {
        return Err(Errno::ESPIPE);
    }
    let read_off = |cx: &Cx<'_>, addr: u64| -> Result<Option<i64>, Errno> {
        match addr {
            0 => Ok(None),
            a => Ok(Some(i64::from_le_bytes(get(cx, a)?))),
        }
    };
    let (raw_src, raw_dst) = (read_off(cx, off_in)?, read_off(cx, off_out)?);
    if !input.borrow().readable() || !output.borrow().writable() {
        return Err(Errno::EBADF);
    }
    if in_pipe.is_none() && out_pipe.is_none()
        || output.borrow().flags & oflags::O_APPEND != 0
        || !splice_reads(&input.borrow())
        || !splice_writes(&output.borrow())
    {
        return Err(Errno::EINVAL);
    }
    let check_off = |file: &FileRef, raw: Option<i64>| -> Result<Option<u64>, Errno> {
        let Some(off) = raw else {
            return Ok(None);
        };
        if !seekable(&file.borrow()) {
            return Err(Errno::EINVAL);
        }
        u64::try_from(off).map(Some).map_err(|_| Errno::EINVAL)
    };
    let (src, dst) = (check_off(&input, raw_src)?, check_off(&output, raw_dst)?);
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    let wrote = match (in_pipe, out_pipe) {
        (Some((from, _)), Some((to, _))) => {
            if Rc::ptr_eq(&from, &to) {
                return Err(Errno::EINVAL);
            }
            let nonblock =
                nonblock || input.borrow().nonblocking() || output.borrow().nonblocking();
            pipe_to_pipe(cx, &from, &to, len, nonblock, true)?
        }
        (Some((pipe, _)), None) => {
            let nonblock = nonblock || input.borrow().nonblocking();
            loop {
                if !pipe_wait_data(cx, &pipe, nonblock)? {
                    return Ok(0);
                }
                if !wait_splice_done(cx, &pipe)? {
                    break;
                }
            }
            // The data stays in the pipe until written; other consumers wait meanwhile, since
            // writing can release the BKL or wait
            let _splicing = Splicing::start(&pipe);
            // Snapshot live vmsplice pages here, including headers the daemon filled in later.
            let data = pipe.borrow().snapshot(len);
            let file_out = needs_pos_lock(&output.borrow());
            let _out_pos = PosGuard::lock_if(cx, &output, dst.is_none() && file_out)?;
            let pos_held = _out_pos.is_some();
            // For regular and FUSE files, loop while bytes remain in `data` as Linux's
            // iter_file_splice_write does: a short write at RLIMIT_FSIZE then attempts the next
            // slice at the limit, raising SIGXFSZ while still returning the bytes already written.
            let mut n = 0;
            loop {
                let at = dst.map(|d| d + n as u64);
                match write_bytes_inner(cx, &output, &data[n..], at, IoFlags::default(), pos_held) {
                    Ok(0) => break,
                    Ok(k) => {
                        n += k;
                        if n >= data.len() || !file_out {
                            break;
                        }
                    }
                    Err(_) if n > 0 => break,
                    Err(e) => return Err(e),
                }
            }
            {
                let mut p = pipe.borrow_mut();
                debug_assert!(
                    n <= p.bytes().len(),
                    "spliced data left the pipe while being written"
                );
                n = n.min(p.bytes().len());
                p.consume(n, false);
            }
            drop(_out_pos);
            if n > 0 {
                write_sync(cx, &output, 0)?;
            }
            n
        }
        // A FUSE daemon takes one whole request into the pipe (6.1's fuse_dev_splice_read): the
        // device's own O_NONBLOCK decides whether to wait, and a request the pipe has no room
        // for is EIO
        (None, Some((pipe, _))) if matches!(input.borrow().kind, FileKind::FuseDev(_)) => {
            let nonblock = input.borrow().nonblocking();
            let message = crate::vfs::fuse::dev_read(cx, &input, len, nonblock)?;
            let mut p = pipe.borrow_mut();
            if message.len().div_ceil(PIPE_BUF) > p.free_slots() {
                return Err(Errno::EIO);
            }
            p.push_pages(&message, 0, false);
            pipe_arrival(cx, &mut p, message.len());
            message.len()
        }
        (None, Some((pipe, _))) => {
            let nonblock = nonblock || output.borrow().nonblocking();
            splice_into_pipe(cx, &input, src, &pipe, len, nonblock)?
        }
        (None, None) => unreachable!("refused above"),
    };
    if let Some(s) = src {
        put(cx, off_in, (s + wrote as u64).to_le_bytes())?;
    }
    if let Some(d) = dst {
        put(cx, off_out, (d + wrote as u64).to_le_bytes())?;
    }
    Ok(wrote as u64)
}

/// The flags splice, tee and vmsplice know (`SPLICE_F_ALL`): `MOVE`, `NONBLOCK`, `MORE`, `GIFT`.
const SPLICE_F_ALL: u32 = 0xf;

/// Whether data can be spliced out of `f` (Linux's `splice_read`), which splice and sendfile from
/// it need (EINVAL otherwise): see [`splice_kind`]; of the devices, not `/dev/null`, `/dev/kmsg`
/// or `/dev/loop-control`; of procfs/sysfs, not per-process entries (other than `mounts`/
/// `mountinfo`), `fdinfo`, `ns/*` or `/proc/kmsg`.
fn splice_reads(f: &OpenFile) -> bool {
    match &f.kind {
        FileKind::Device { dev, .. } => {
            !matches!(dev, Device::Null | Device::Kmsg | Device::LoopControl)
        }
        FileKind::Proc { node, .. } => proc_splice_reads(node),
        kind => splice_kind(kind),
    }
}

/// Whether data can be spliced into `f` (Linux's `splice_write`), which splice and sendfile into
/// it need (EINVAL otherwise): see [`splice_kind`]; of the devices, not `/dev/full` (6.1's
/// `full_fops` has none, so it never gets to ENOSPC), `/dev/kmsg` or `/dev/loop-control`; of
/// synthetic files, only kernfs (sysfs, cgroup2) and `/proc/sys` sysctls (`pseudo::has_iter`).
fn splice_writes(f: &OpenFile) -> bool {
    match &f.kind {
        FileKind::Device { dev, .. } => {
            !matches!(dev, Device::Full | Device::Kmsg | Device::LoopControl)
        }
        FileKind::Proc { node, .. } => pseudo::has_iter(node, true),
        kind => splice_kind(kind),
    }
}

fn proc_splice_reads(node: &PseudoNode) -> bool {
    match node {
        PseudoNode::Entry(_, _, pseudo::Entry::Mounts | pseudo::Entry::MountInfo) => true,
        PseudoNode::Entry(..)
        | PseudoNode::FdInfo(..)
        | PseudoNode::NsFile(..)
        | PseudoNode::Global(pseudo::Global::Kmsg) => false,
        _ => true,
    }
}

/// The kinds of files that splice both ways (Linux's pipes, regular files, sockets, terminals,
/// FUSE files and `/dev/fuse`). Directories, eventfd, epoll and the other anonymous files do not.
fn splice_kind(kind: &FileKind) -> bool {
    matches!(
        kind,
        FileKind::Regular { .. }
            | FileKind::Pipe(_)
            | FileKind::Socket(_)
            | FileKind::Pty(_)
            | FileKind::Host(_)
            | FileKind::Fuse(_)
            | FileKind::FuseDev(_)
    )
}

/// Reserve page slots before reading the input: socket and file I/O can release the BKL,
/// and an intervening writer or resize must not consume the same slots.
struct PipeSlots<'a> {
    pipe: &'a Rc<RefCell<Pipe>>,
    slots: usize,
}

impl Drop for PipeSlots<'_> {
    fn drop(&mut self) {
        if self.slots != 0 {
            self.pipe.borrow_mut().reserved -= self.slots;
            request_wake_object(crate::pipe::object(self.pipe));
        }
    }
}

fn splice_into_pipe(
    cx: &mut Cx<'_>,
    input: &FileRef,
    src: Option<u64>,
    pipe: &Rc<RefCell<Pipe>>,
    len: usize,
    nonblock: bool,
) -> Result<usize, Errno> {
    // A splice in the opposite direction may need this same file position to drain the pipe.
    // Wait for a slot before taking the position, then recheck if acquiring it slept.
    let (pos, free) = loop {
        wait_room(cx, pipe, nonblock)?;
        let pos = PosGuard::lock_positioned(cx, input, src.is_none(), false)?;
        let p = pipe.borrow();
        if p.readers != 0 && p.free_slots() != 0 {
            break (pos, p.free_slots());
        }
    };
    let offset = {
        let f = input.borrow();
        if matches!(f.kind, FileKind::Regular { .. }) {
            src.unwrap_or(f.pos) as usize % PIPE_BUF
        } else {
            0
        }
    };
    let n = len.min(free * PIPE_BUF - offset);
    let slots = (offset + n).div_ceil(PIPE_BUF);
    pipe.borrow_mut().reserved += slots;
    let mut claim = PipeSlots { pipe, slots };
    let mut buf = vec![0; n];
    let got = match splice_read(cx, input, &mut buf, src, nonblock, pos.is_some()) {
        Err(e) if e == Errno::ENOTCONN => return Err(Errno::EINVAL),
        r => r?,
    };
    if got != 0 {
        let mut p = pipe.borrow_mut();
        let used = (offset + got).div_ceil(PIPE_BUF);
        p.reserved -= used;
        claim.slots -= used;
        p.push_pages(&buf[..got], offset, false);
        pipe_arrival(cx, &mut p, got);
    }
    Ok(got)
}

/// Reads splice's input into a buffer bound for a pipe: as the file's own `O_NONBLOCK` says (TCP's
/// `tcp_splice_read`, and `read_iter` for the rest), except that an AF_UNIX stream socket also
/// stops waiting with `nonblock` (`SPLICE_F_NONBLOCK` or the output pipe's `O_NONBLOCK`), as
/// `unix_stream_splice_read` does.
fn splice_read(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: &mut [u8],
    offset: Option<u64>,
    nonblock: bool,
    pos_held: bool,
) -> Result<usize, Errno> {
    let sock = match &file.borrow().kind {
        FileKind::Socket(s) => Some(s.clone()),
        _ => None,
    };
    let unix_stream = sock.filter(
        |s| matches!(&*s.borrow(), crate::net::Socket::Unix(u) if u.ty == crate::net::SOCK_STREAM),
    );
    let Some(sock) = unix_stream else {
        return read_bytes_inner(cx, file, buf, offset, IoFlags::default(), pos_held, true);
    };
    let nonblock = nonblock || file.borrow().nonblocking();
    let m = super::net::recv(cx, &sock, nonblock, buf.len(), 0, 0)?;
    buf[..m.data.len()].copy_from_slice(&m.data);
    Ok(m.data.len())
}

/// tee: copies the data in one pipe to another without taking it from the source pipe (Linux
/// 6.1's `do_tee`): it waits for data (0 once the source has no writers), then for room in the
/// destination (`EPIPE` without readers), unless `SPLICE_F_NONBLOCK` or either end's `O_NONBLOCK`,
/// and copies what is there and fits at that moment.
pub(super) fn tee(cx: &mut Cx<'_>, fd_in: i32, fd_out: i32, len: usize, flags: u32) -> SysResult {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    let input = cx.fds().get(fd_in)?;
    let output = cx.fds().get(fd_out)?;
    if !input.borrow().readable() || !output.borrow().writable() {
        return Err(Errno::EBADF);
    }
    let (Some((src, _)), Some((dst, _))) = (pipe_of(&input), pipe_of(&output)) else {
        return Err(Errno::EINVAL);
    };
    if Rc::ptr_eq(&src, &dst) {
        return Err(Errno::EINVAL);
    }
    let nonblock = flags & SPLICE_F_NONBLOCK != 0
        || input.borrow().nonblocking()
        || output.borrow().nonblocking();
    pipe_to_pipe(cx, &src, &dst, len, nonblock, false).map(|n| n as u64)
}

/// splice between two pipes (`take`) and tee: Linux's `ipipe_prep` (wait for data in `src`, going
/// on at end of file), `opipe_prep` (wait for room in `dst`), then `splice_pipe_to_pipe` or
/// `link_pipe`, which move or copy what is there and fits. When another reader or writer took the
/// data or the room during the waits, splice waits again (`EAGAIN` when nonblocking) and tee
/// returns 0; a source at end of file gives 0 once the destination has room.
fn pipe_to_pipe(
    cx: &mut Cx<'_>,
    src: &Rc<RefCell<Pipe>>,
    dst: &Rc<RefCell<Pipe>>,
    len: usize,
    nonblock: bool,
    take: bool,
) -> Result<usize, Errno> {
    loop {
        pipe_wait_data(cx, src, nonblock)?;
        wait_room(cx, dst, nonblock)?;
        if take && wait_splice_done(cx, src)? {
            continue;
        }
        let (mut s, mut d) = (src.borrow_mut(), dst.borrow_mut());
        if d.readers == 0 {
            drop((s, d));
            return Err(broken_pipe(cx));
        }
        if s.bytes().is_empty() && s.writers == 0 {
            return Ok(0);
        }
        if s.bytes().is_empty() || d.free_slots() == 0 {
            if !take {
                return Ok(0);
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            continue;
        }

        let n = s.transfer(&mut d, len, take);
        pipe_arrival(cx, &mut d, n);
        if take {
            s.consume(n, true);
        }
        return Ok(n);
    }
}

/// Waits for room in a pipe that splice, tee or vmsplice writes into (Linux's `wait_for_space`
/// and `opipe_prep`): no readers is `EPIPE` with `SIGPIPE`, a full pipe `EAGAIN` when nonblocking.
fn wait_room(cx: &mut Cx<'_>, pipe: &Rc<RefCell<Pipe>>, nonblock: bool) -> Result<(), Errno> {
    loop {
        {
            let p = pipe.borrow();
            if p.readers == 0 {
                drop(p);
                return Err(broken_pipe(cx));
            }
            if p.free_slots() > 0 {
                return Ok(());
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
}

/// Wake readers for a new arrival. An edge-triggered reader also observes writes to a
/// nonempty pipe through the write counter.
fn pipe_arrival(cx: &mut Cx<'_>, pipe: &mut Pipe, written: usize) {
    if written == 0 {
        return;
    }
    if pipe.bytes().len() == written {
        request_wake_object(wake::of_value(pipe));
    } else {
        super::poll::arrived(cx);
    }
    if let Some(vfs) = &cx.kr().vfs {
        vfs.pipe_io_time(pipe, true);
    }
    pipe.writes += 1;
}

/// vmsplice (Linux 6.1): an fd open for writing (checked first, so a FIFO opened read-write is
/// written) puts the iovecs into its pipe up to the room there is, and one open only for reading
/// takes data from its pipe like readv; nothing is done for an empty request, and either way the
/// wait (for room, or for data) is skipped only with `SPLICE_F_NONBLOCK`, whatever the pipe's own
/// `O_NONBLOCK` (`wait_for_space`, `splice_from_pipe_next`).
pub(super) fn vmsplice(cx: &mut Cx<'_>, fd: i32, iov: u64, count: usize, flags: u32) -> SysResult {
    if flags & !SPLICE_F_ALL != 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.fds().get(fd)?;
    let write = file.borrow().writable();
    if !write && !file.borrow().readable() {
        return Err(Errno::EBADF);
    }
    let iovecs = iovecs(cx, iov, count)?;
    let total: usize = iovecs.iter().map(|v| v.1).sum();
    if total == 0 {
        return Ok(0);
    }
    let Some((pipe, _)) = pipe_of(&file) else {
        return Err(Errno::EBADF);
    };
    let nonblock = flags & SPLICE_F_NONBLOCK != 0;
    if !write {
        return pipe_read_user(cx, &file, &pipe, nonblock, &iovecs);
    }
    wait_room(cx, &pipe, nonblock)?;
    let mut p = pipe.borrow_mut();
    let mut done = 0;
    let mut page = [0; PIPE_BUF];
    'iov: for (mut base, mut len) in iovecs {
        while len != 0 && p.free_slots() != 0 {
            let offset = base as usize % PIPE_BUF;
            let n = len.min(PIPE_BUF - offset);
            if let Err(e) = cx.mm().read(UserSlice::new(base, n), &mut page[..n]) {
                if done == 0 {
                    return Err(e);
                }
                break 'iov;
            }
            p.push_vmsplice(&page[..n], offset, &cx.t.mm, base);
            done += n;
            base = base.wrapping_add(n as u64);
            len -= n;
        }
    }
    pipe_arrival(cx, &mut p, done);
    Ok(done as u64)
}

/// When the open file is a pipe, returns the pipe and whether it is the read end.
fn pipe_of(file: &FileRef) -> Option<(Rc<RefCell<Pipe>>, bool)> {
    match &file.borrow().kind {
        FileKind::Pipe(end) => Some((end.pipe.clone(), end.read)),
        _ => None,
    }
}

/// Waits for data in the pipe: returns false when all write ends are closed (EOF).
fn pipe_wait_data(
    cx: &mut Cx<'_>,
    pipe: &Rc<RefCell<Pipe>>,
    nonblock: bool,
) -> Result<bool, Errno> {
    loop {
        {
            let p = pipe.borrow();
            if !p.bytes().is_empty() {
                return Ok(true);
            }
            if p.writers == 0 {
                return Ok(false);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
}

/// Waits while another task splices data out of the pipe ([`Pipe::splicing`]), whatever
/// `O_NONBLOCK` says, as Linux's consumers wait for the pipe's lock. Returns whether it waited, so
/// that the caller looks at the pipe again.
fn wait_splice_done(cx: &mut Cx<'_>, pipe: &Rc<RefCell<Pipe>>) -> Result<bool, Errno> {
    let mut waited = false;
    while pipe.borrow().splicing {
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(crate::pipe::object(pipe))?;
        waited = true;
    }
    Ok(waited)
}

/// A splice writing data out of a pipe ([`Pipe::splicing`]) until dropped, which wakes the
/// consumers that waited for it.
struct Splicing(Rc<RefCell<Pipe>>);

impl Splicing {
    fn start(pipe: &Rc<RefCell<Pipe>>) -> Splicing {
        pipe.borrow_mut().splicing = true;
        Splicing(pipe.clone())
    }
}

impl Drop for Splicing {
    fn drop(&mut self) {
        self.0.borrow_mut().splicing = false;
        request_wake_object(crate::pipe::object(&self.0));
    }
}

/// readv, writev and their positional variants. Pipes, terminals and sockets (and eventfd reads,
/// and host stdio that is not a regular file on the host) do one read or write over all the
/// iovecs, as Linux's `read_iter` and `write_iter` see them
/// ([`stream_vectored`]); everything else handles each iovec in order and stops at an incomplete
/// one, which is also what Linux does for files with only `read` or `write` (eventfd writes,
/// timerfd, signalfd, inotify, `/dev/kmsg` reads). With `offset` None the file position is used
/// and advanced.
pub(super) fn vectored(
    cx: &mut Cx<'_>,
    fd: i32,
    iov: u64,
    count: usize,
    offset: Option<u64>,
    write: bool,
) -> SysResult {
    vectored_with(cx, fd, iov, count, offset, write, IoFlags::default())
}

pub(super) fn vectored_with(
    cx: &mut Cx<'_>,
    fd: i32,
    iov: u64,
    count: usize,
    offset: Option<u64>,
    write: bool,
    io: IoFlags,
) -> SysResult {
    vectored_inner(cx, fd, iov, count, offset, write, io, 0)
}

#[allow(clippy::too_many_arguments)]
fn vectored_inner(
    cx: &mut Cx<'_>,
    fd: i32,
    iov: u64,
    count: usize,
    offset: Option<u64>,
    write: bool,
    io: IoFlags,
    rwf: u32,
) -> SysResult {
    let file = cx.fds().get(fd)?;
    let offset = if write && (io.append || rwf & RWF_NOAPPEND == 0) {
        regular_append_offset(cx, &file.borrow(), offset, io.append)?
    } else {
        offset
    };
    // /dev/kmsg's write_iter: the whole writev is one record (systemd logs this way)
    if write && matches!(file.borrow().kind, FileKind::Device { kmsg: Some(_), .. }) {
        let vecs = iovecs(cx, iov, count)?;
        let total: usize = vecs.iter().map(|&(_, len)| len).sum();
        if !file.borrow().writable() {
            return Err(Errno::EBADF);
        }
        // A writev with total length 0 does not call the file's write (do_iter_write)
        if total == 0 {
            return Ok(0);
        }
        if total > crate::klog::LOG_LINE_MAX {
            return Err(Errno::EINVAL);
        }
        let mut data = Vec::new();
        for (base, len) in vecs {
            let start = data.len();
            data.resize(start + len, 0);
            cx.mm()
                .read(UserSlice::new(base, len), &mut data[start..])?;
        }
        return kmsg_write(cx, &file, &data).map(|n| n as u64);
    }
    let vecs = iovecs(cx, iov, count)?;
    // Nothing to transfer returns 0 after the offset and mode checks without reaching the file
    // (Linux's do_iter_read and do_iter_write; a plain write of 0 bytes does reach it, so it sends
    // an empty datagram where this does not)
    if vecs.iter().all(|v| v.1 == 0) {
        let f = file.borrow();
        positional(&f, offset)?;
        if !(if write { f.writable() } else { f.readable() }) {
            return Err(Errno::EBADF);
        }
        return Ok(0);
    }
    if write && sysctl_write(&file.borrow()) {
        return write_sysctl_iov(cx, &file, &vecs, offset);
    }
    if let Some(r) = stream_vectored(cx, &file, &vecs, offset, write, io) {
        return r;
    }
    // Hold f_pos_lock across all iovecs (and the final sync on synchronous writev) so another
    // thread's I/O or lseek cannot interleave between iovecs
    let _pos = PosGuard::lock_positioned(cx, &file, offset.is_none(), io.nowait)?;
    let pos_held = _pos.is_some();
    if !write {
        verify_read_range(&file.borrow(), offset, vecs.iter().map(|v| v.1).sum())?;
    }
    // A writev checks RLIMIT_FSIZE once for all its iovecs (generic_write_checks), so one that
    // ends at the limit only shortens it
    let room = match write {
        true => fsize_allowed(
            cx,
            &file.borrow(),
            offset,
            vecs.iter().map(|v| v.1).sum(),
            io.append,
        )?,
        false => usize::MAX,
    };
    let mut total = 0;
    let mut touch_atime = !write;
    for (index, (base, len)) in vecs.into_iter().enumerate() {
        if index != 0 && len == 0 {
            continue;
        }
        if total as usize >= room {
            break;
        }
        let len = len.min(room - total as usize);
        let at = offset.map(|o| o + total);
        let r = if write {
            write_file_inner(cx, &file, base, len, at, io, pos_held, true)
        } else {
            let touch = touch_atime && len > 0;
            let res = read_file_inner(cx, &file, base, len, at, io, pos_held, touch);
            if res.is_ok() && touch {
                touch_atime = false;
            }
            res
        };
        match r {
            Ok(n) => {
                total += n;
                if (n as usize) < len {
                    break;
                }
            }
            Err(_) if total > 0 => break,
            Err(e) => return Err(e),
        }
    }
    if write && total > 0 {
        write_sync(cx, &file, rwf)?;
    }
    Ok(total)
}

/// readv and writev on files whose Linux operations are `read_iter`/`write_iter` and that have no
/// positions: one read or write over all the iovecs, so a datagram is one message, a pipe or
/// terminal read returns what was ready instead of waiting again once an iovec is full, a pipe
/// write up to `PIPE_BUF` stays atomic, and an eventfd value read may span iovecs. Host stdio that
/// is a pipe, terminal or socket on the host goes the same way (musl's stdio reads with a readv
/// into the caller's buffer and its own, and waiting for the second once the first was filled
/// blocks a program whose peer waits for its answer). None for the other files, which go iovec by
/// iovec: a host regular file is read whole, as Linux reads regular files.
fn stream_vectored(
    cx: &mut Cx<'_>,
    file: &FileRef,
    vecs: &[(u64, usize)],
    offset: Option<u64>,
    write: bool,
    io: IoFlags,
) -> Option<SysResult> {
    let path = match positional(&file.borrow(), offset) {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    Some(match path {
        IoPath::Socket(s) => {
            let nonblock = file.borrow().nonblocking() || io.nowait;
            super::net::rw(cx, &s, nonblock, vecs, write)
        }
        IoPath::Pipe(pipe) if write => {
            let f = file.borrow();
            if !f.writable() {
                return Some(Err(Errno::EBADF));
            }
            let nonblock = f.nonblocking() || io.nowait;
            drop(f);
            pipe_write_user(cx, &pipe, nonblock, vecs)
        }
        IoPath::Pty(..) if write => write_gathered(cx, file, vecs, IO_CHUNK, io),
        IoPath::Pipe(_) | IoPath::Pty(..) | IoPath::EventFd(_) if !write => {
            read_scattered(cx, file, vecs, IO_CHUNK, io)
        }
        // A FUSE message is read and written whole (fuse_dev_read and fuse_dev_write take an
        // iov_iter): libfuse writes a reply's header and data as separate iovecs
        IoPath::FuseDev if write => write_gathered(cx, file, vecs, FUSE_CHUNK, io),
        IoPath::FuseDev => read_scattered(cx, file, vecs, FUSE_CHUNK, io),
        IoPath::Host(fd) if !host_regular(fd) => {
            if write {
                write_gathered(cx, file, vecs, IO_CHUNK, io)
            } else {
                read_scattered(cx, file, vecs, IO_CHUNK, io)
            }
        }
        _ => return None,
    })
}

fn sysctl_write(f: &OpenFile) -> bool {
    matches!(&f.kind, FileKind::Proc { node, .. } if pseudo::is_sysctl_write(node))
}

/// proc_sys_write sees one buffer. Validate the full transfer before changing the value;
/// the sysctl handlers parse at most the first page minus its terminating NUL.
fn write_sysctl_iov(
    cx: &mut Cx<'_>,
    file: &FileRef,
    vecs: &[(u64, usize)],
    offset: Option<u64>,
) -> SysResult {
    positional(&file.borrow(), offset)?;
    if !file.borrow().writable() {
        return Err(Errno::EBADF);
    }
    const PREFIX: usize = appine_engine::PAGE_SIZE as usize - 1;
    let count = vecs
        .iter()
        .map(|&(_, len)| len)
        .sum::<usize>()
        .min(MAX_COPY);
    let mut data = vec![0; count.min(PREFIX)];
    let mut scratch = [0; 4096];
    let mut copied = 0;
    for &(mut base, len) in vecs {
        let mut left = len.min(count - copied);
        while left > 0 {
            let dst = if copied < data.len() {
                &mut data[copied..]
            } else {
                &mut scratch[..]
            };
            let n = dst.len().min(left);
            cx.read_user(UserSlice::new(base, n), &mut dst[..n])?;
            copied += n;
            base = base.wrapping_add(n as u64);
            left -= n;
        }
    }
    write_proc(cx, file, &data, count, offset).map(|n| n as u64)
}

/// Whether host fd `fd` (host stdio) is a regular file on the host.
fn host_regular(fd: i32) -> bool {
    appine_hal::fstat(fd).is_ok_and(|st| st.st_mode & mode::S_IFMT == mode::S_IFREG)
}

/// readv on a pipe, terminal, eventfd or `/dev/fuse`: one read of up to `step` bytes, scattered
/// over the iovecs in order. As on Linux, when copying out faults after data was taken, the part
/// copied is returned (the rest is lost).
fn read_scattered(
    cx: &mut Cx<'_>,
    file: &FileRef,
    vecs: &[(u64, usize)],
    step: usize,
    io: IoFlags,
) -> SysResult {
    if !file.borrow().readable() {
        return Err(Errno::EBADF);
    }
    let total: usize = vecs.iter().map(|v| v.1).sum();
    if total == 0 {
        return Ok(0);
    }
    if let Some((pipe, _)) = pipe_of(file) {
        let nonblock = file.borrow().nonblocking() || io.nowait;
        return pipe_read_user(cx, file, &pipe, nonblock, vecs);
    }
    let mut buf = vec![0u8; total.min(step)];
    let k = read_bytes_with(cx, file, &mut buf, None, io)?;
    note_read(cx, file, k);
    let mut done = 0;
    for &(base, len) in vecs {
        if done == k {
            break;
        }
        if len == 0 {
            continue;
        }
        let n = len.min(k - done);
        let copied = cx.write_user_partial(base, &buf[done..done + n]);
        done += copied;
        if copied < n {
            break;
        }
    }
    if done == 0 && k > 0 {
        return Err(Errno::EFAULT);
    }
    Ok(done as u64)
}

/// writev on a terminal, non-regular host stdio or `/dev/fuse`: the iovecs written as one stream,
/// in pieces of up to `step` bytes that cross iovec boundaries, stopping at a short write; a fault
/// ends the data there, and what came before it is still written.
fn write_gathered(
    cx: &mut Cx<'_>,
    file: &FileRef,
    vecs: &[(u64, usize)],
    step: usize,
    io: IoFlags,
) -> SysResult {
    if !file.borrow().writable() {
        return Err(Errno::EBADF);
    }
    let mut rest = vecs.iter().copied();
    let mut cur = None;
    let mut done = 0;
    let total = vecs.iter().map(|v| v.1).sum();
    let mut chunk = Vec::with_capacity(step.min(total));
    loop {
        chunk.clear();
        let mut fault = None;
        while chunk.len() < step {
            let Some((base, len)) = cur.take().or_else(|| rest.next()) else {
                break;
            };
            let n = len.min(step - chunk.len());
            let start = chunk.len();
            chunk.resize(start + n, 0);
            if let Err(e) = cx.read_user(UserSlice::new(base, n), &mut chunk[start..]) {
                chunk.truncate(start);
                fault = Some(e);
                break;
            }
            if n < len {
                cur = Some((base.wrapping_add(n as u64), len - n));
            }
        }
        if chunk.is_empty() {
            return match fault {
                Some(e) if done == 0 => Err(e),
                _ => Ok(done as u64),
            };
        }
        match write_bytes_with(cx, file, &chunk, None, io) {
            Ok(k) => {
                done += k;
                if k < chunk.len() || fault.is_some() {
                    return Ok(done as u64);
                }
            }
            Err(_) if done > 0 => return Ok(done as u64),
            Err(e) => return Err(e),
        }
    }
}

/// Reads an iovec array, rejecting counts over `UIO_MAXIOV` or totals over `isize::MAX` with
/// `EINVAL`, and capping the total length at `MAX_RW_COUNT` (`MAX_COPY`) as Linux's
/// `import_iovec` does so trailing iovecs beyond `MAX_RW_COUNT` are never touched.
fn iovecs(cx: &Cx<'_>, iov: u64, count: usize) -> Result<Vec<(u64, usize)>, Errno> {
    if count > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let mut out = Vec::with_capacity(count);
    let mut total: usize = 0;
    for i in 0..count as u64 {
        let raw: [u8; 16] = get(cx, iov.wrapping_add(i * 16))?;
        let base = u64::from_le_bytes(raw[..8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[8..].try_into().unwrap()) as usize;
        total = total
            .checked_add(len)
            .filter(|&t| t <= isize::MAX as usize)
            .ok_or(Errno::EINVAL)?;
        out.push((base, len));
    }
    cap_iovecs(&mut out);
    Ok(out)
}

fn cap_iovecs(vecs: &mut Vec<(u64, usize)>) {
    let mut left = MAX_COPY;
    let mut keep = 0;
    for (_, len) in vecs.iter_mut() {
        if left == 0 {
            break;
        }
        if *len > left {
            *len = left;
        }
        left -= *len;
        keep += 1;
    }
    vecs.truncate(keep);
}

pub(super) fn sendfile(
    cx: &mut Cx<'_>,
    out_fd: i32,
    in_fd: i32,
    offset: u64,
    count: usize,
) -> SysResult {
    let input = cx.fds().get(in_fd)?;
    let output = cx.fds().get(out_fd)?;
    if !input.borrow().readable() || !output.borrow().writable() {
        return Err(Errno::EBADF);
    }
    // The input is a seekable file that splices (splice_direct_to_actor's FMODE_LSEEK, then
    // splice_read): a regular or FUSE file or a device, not /dev/null
    {
        let f = input.borrow();
        let seekable = match &f.kind {
            FileKind::Regular { .. } | FileKind::Device { .. } => true,
            FileKind::Fuse(h) => super::fuse::seekable(h),
            _ => false,
        };
        if !seekable || !splice_reads(&f) {
            return Err(Errno::EINVAL);
        }
    }
    // Into anything but a pipe Linux goes through do_splice_direct, which refuses O_APPEND and an
    // output without splice_write (such as /dev/full or an eventfd)
    {
        let out = output.borrow();
        if !matches!(out.kind, FileKind::Pipe(_))
            && (out.flags & oflags::O_APPEND != 0 || !splice_writes(&out))
        {
            return Err(Errno::EINVAL);
        }
    }
    reject_flags(
        file_inode_flags(cx, &output.borrow())?,
        inode_flags::PROTECTED,
    )?;
    let mut off = match offset {
        0 => None,
        addr => Some(u64::try_from(i64::from_le_bytes(get(cx, addr)?)).map_err(|_| Errno::EINVAL)?),
    };
    verify_read_range(&input.borrow(), off, count)?;
    let count = count.min(MAX_COPY);
    if let Some((pipe, _)) = pipe_of(&output) {
        if count == 0 {
            return Ok(0);
        }
        let nonblock = output.borrow().nonblocking();
        let n = splice_into_pipe(cx, &input, off, &pipe, count, nonblock)?;
        if let Some(o) = off {
            put(cx, offset, (o + n as u64).to_le_bytes())?;
        }
        return Ok(n as u64);
    }
    if let Some(r) = copy_regular(cx, &input, off, &output, None, count) {
        let n = r?;
        if count > 0 {
            file_accessed(cx, &input.borrow());
        }
        if n > 0 {
            write_sync(cx, &output, 0)?;
        }
        if let Some(o) = off {
            put(cx, offset, (o + n as u64).to_le_bytes())?;
        }
        return Ok(n as u64);
    }
    let lock_in = off.is_none() && needs_pos_lock(&input.borrow());
    let lock_out = needs_pos_lock(&output.borrow());
    let _pos = TwoPosGuard::lock(cx, (&input, lock_in), (&output, lock_out))?;
    let mut chunk = vec![0u8; count.min(IO_CHUNK)];
    let mut done = 0;
    let mut touch_atime = true;
    while done < count {
        let n = (count - done).min(IO_CHUNK);
        let before = input.borrow().pos;
        let got = match read_bytes_inner(
            cx,
            &input,
            &mut chunk[..n],
            off,
            IoFlags::default(),
            lock_in,
            touch_atime,
        ) {
            Ok(0) => break,
            Ok(k) => {
                touch_atime = false;
                k
            }
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        let wrote = match write_bytes_inner(
            cx,
            &output,
            &chunk[..got],
            None,
            IoFlags::default(),
            lock_out,
        ) {
            Ok(k) => k,
            Err(_) if done > 0 => 0,
            Err(e) => {
                if off.is_none() {
                    give_back(&input, before, got);
                }
                return Err(e);
            }
        };
        // The part not written out goes back to the input
        match &mut off {
            Some(o) => *o += wrote as u64,
            None => give_back(&input, before, got - wrote),
        }
        done += wrote;
        if wrote < got || got < n {
            break;
        }
    }
    drop(_pos);
    if done > 0 {
        write_sync(cx, &output, 0)?;
    }
    if let Some(o) = off {
        put(cx, offset, o.to_le_bytes())?;
    }
    Ok(done as u64)
}

/// copy_file_range: copies between two regular files without passing through guest memory. A
/// null offset pointer uses and advances the file position; otherwise the offset it points at
/// is used and updated.
pub(super) fn copy_file_range(
    cx: &mut Cx<'_>,
    fd_in: i32,
    off_in: u64,
    fd_out: i32,
    off_out: u64,
    len: usize,
    flags: u32,
) -> SysResult {
    // O_PATH descriptors are not found (fdget)
    let open = |fd: i32| {
        cx.fds()
            .get(fd)
            .and_then(|f| match f.borrow().flags & oflags::O_PATH {
                0 => Ok(f.clone()),
                _ => Err(Errno::EBADF),
            })
    };
    let input = open(fd_in)?;
    let output = open(fd_out)?;
    let read_off = |addr: u64| -> Result<Option<i64>, Errno> {
        match addr {
            0 => Ok(None),
            a => Ok(Some(i64::from_le_bytes(get(cx, a)?))),
        }
    };
    let (src, dst) = (read_off(off_in)?, read_off(off_out)?);
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let len = copy_range_checks(cx, (&input, src), (&output, dst), len)?.min(MAX_COPY);
    let (src, dst) = (src.map(|s| s as u64), dst.map(|d| d as u64));
    if len == 0 {
        return Ok(0);
    }
    // A copy of the whole input (up to MAX_RW_COUNT, matching Linux's vfs_copy_file_range) into
    // an output no longer than it shares the input's object, as Linux tries remap_file_range first
    // on filesystems with reflinks.
    let shared = {
        let lock_in = src.is_none() && needs_pos_lock(&input.borrow());
        let lock_out = dst.is_none() && needs_pos_lock(&output.borrow());
        let _pos = TwoPosGuard::lock(cx, (&input, lock_in), (&output, lock_out))?;
        let pos_in = src.unwrap_or_else(|| input.borrow().pos);
        let pos_out = dst.unwrap_or_else(|| output.borrow().pos);
        if whole_copy(cx, &input, pos_in, &output, pos_out, len as u64)?
            && try_share(cx, &input, &output)?
        {
            for (f, given) in [(&input, src), (&output, dst)] {
                if given.is_none() {
                    f.borrow_mut().pos += len as u64;
                }
            }
            inotify::file_io_event(cx.kr(), &input.borrow(), inotify::IN_ACCESS);
            inotify::file_io_event(cx.kr(), &output.borrow(), inotify::IN_MODIFY);
            true
        } else {
            false
        }
    };
    let n = if shared {
        len
    } else {
        copy_data(cx, &input, src, &output, dst, len)?
    };
    file_accessed(cx, &input.borrow());
    if n > 0 {
        write_sync(cx, &output, 0)?;
    }
    if let Some(s) = src {
        put(cx, off_in, (s + n as u64).to_le_bytes())?;
    }
    if let Some(d) = dst {
        put(cx, off_out, (d + n as u64).to_le_bytes())?;
    }
    Ok(n as u64)
}

/// Copies up to `len` bytes from `input` to `output` (at `src`/`dst`, or the file positions,
/// which advance), returning how many were copied: between two regular files through the host
/// ([`copy_regular`]), otherwise block by block.
fn copy_data(
    cx: &mut Cx<'_>,
    input: &FileRef,
    mut src: Option<u64>,
    output: &FileRef,
    mut dst: Option<u64>,
    len: usize,
) -> Result<usize, Errno> {
    let len = len.min(MAX_COPY);
    if let Some(r) = copy_regular(cx, input, src, output, dst, len) {
        return r;
    }
    let lock_in = src.is_none() && needs_pos_lock(&input.borrow());
    let lock_out = dst.is_none() && needs_pos_lock(&output.borrow());
    let _pos = TwoPosGuard::lock(cx, (input, lock_in), (output, lock_out))?;
    // As with sendfile, an error after some bytes were copied returns those bytes
    let mut chunk = vec![0u8; len.min(IO_CHUNK)];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(IO_CHUNK);
        let before = input.borrow().pos;
        let got = match read_bytes_inner(
            cx,
            input,
            &mut chunk[..n],
            src,
            IoFlags::default(),
            lock_in,
            false,
        ) {
            Ok(0) => break,
            Ok(k) => k,
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        let wrote =
            match write_bytes_inner(cx, output, &chunk[..got], dst, IoFlags::default(), lock_out) {
                Ok(k) => k,
                Err(e) => {
                    if src.is_none() {
                        give_back(input, before, got);
                    }
                    if done > 0 {
                        break;
                    }
                    return Err(e);
                }
            };
        if let Some(s) = &mut src {
            *s += wrote as u64;
        } else {
            give_back(input, before, got - wrote);
        }
        if let Some(d) = &mut dst {
            *d += wrote as u64;
        }
        done += wrote;
        if wrote < got {
            break;
        }
    }
    Ok(done)
}

/// Moves `file`'s position back over `n` bytes that a read from position `before` took but that
/// went nowhere (not written on, not copied out), never further than that read moved it: devices
/// and FUSE stream files keep their positions when read.
fn give_back(file: &FileRef, before: u64, n: usize) {
    let mut f = file.borrow_mut();
    let moved = f.pos.saturating_sub(before);
    f.pos -= moved.min(n as u64);
}

/// Whether copying `len` bytes of `input` at `pos_in` to `output` at `pos_out` leaves the output
/// a copy of the whole input: both from the start, all of a non-empty input, and an output no
/// longer than it.
fn whole_copy(
    cx: &Cx<'_>,
    input: &FileRef,
    pos_in: u64,
    output: &FileRef,
    pos_out: u64,
    len: u64,
) -> Result<bool, Errno> {
    if pos_in != 0 || pos_out != 0 {
        return Ok(false);
    }
    let vfs = cx.vfs()?;
    let size = |f: &FileRef| -> Result<Option<u64>, Errno> {
        match &f.borrow().kind {
            FileKind::Regular { ino, file, .. } => Ok(Some(regular_size(&vfs, *ino, file)?)),
            _ => Ok(None),
        }
    };
    let (Some(size_in), Some(size_out)) = (size(input)?, size(output)?) else {
        return Ok(false);
    };
    Ok(size_in > 0 && len == size_in && size_out <= size_in)
}

/// FICLONE, FICLONERANGE and a whole-file copy_file_range: when `output` is to end up a copy of
/// all of `input`, makes it share `input`'s object instead ([`Store::share`]), as btrfs and XFS
/// share extents; returns whether it did. Not done when the two are not regular files of one
/// store outside tmpfs (Linux's shmem has no reflink), when one was opened through an overlay or
/// is a memfd, when something could still change the input's object in place (a description
/// open for writing it that is not marked `cow`, a shared mapping that can be made writable) or
/// the output is mapped, sealed or being copied: a mapping does not follow a file to another
/// object.
fn try_share(cx: &mut Cx<'_>, input: &FileRef, output: &FileRef) -> Result<bool, Errno> {
    use std::os::unix::fs::MetadataExt;
    let vfs = cx.vfs()?;
    let (src, dst, src_host, dst_host) = {
        let (i, o) = (input.borrow(), output.borrow());
        let (
            FileKind::Regular {
                ino: src, file: si, ..
            },
            FileKind::Regular {
                ino: dst, file: so, ..
            },
        ) = (&i.kind, &o.kind)
        else {
            return Ok(false);
        };
        let tmpfs = |f: &OpenFile, ino: Ino| vfs.tmpfs_dev(&Node::Store(f.mnt, ino)).is_some();
        if i.pseudo || o.pseudo || i.ovl.is_some() || o.ovl.is_some() || src == dst {
            return Ok(false);
        }
        if tmpfs(&i, *src) || tmpfs(&o, *dst) {
            return Ok(false);
        }
        let host = |f: &std::fs::File| f.metadata().map(|m| (m.dev(), m.ino()));
        (
            *src,
            *dst,
            host(si).map_err(host_errno)?,
            host(so).map_err(host_errno)?,
        )
    };
    // A deleted source's object may already be on its way to the reaper; an object the Files app
    // is writing would carry its writes into both files
    let k = cx.kr();
    if k.unsharing.contains(&dst)
        || k.seals.contains_key(&dst)
        || vfs.store().attrs(src)?.nlink == 0
        || vfs.store().host_writing(src)?
        || vfs.store().host_writing(dst)?
    {
        return Ok(false);
    }
    let writer = |f: &FileRef| {
        f.try_borrow()
            .is_ok_and(|f| f.writable() && matches!(f.kind, FileKind::Regular { cow: false, .. }))
    };
    if opens_of(k, src).iter().any(writer) {
        return Ok(false);
    }
    let mapped = k.tasks.values().any(|t| {
        let res = t.res.borrow();
        let mm = res.mm.borrow();
        mm.writably_maps(src_host.0, src_host.1) || mm.maps_file(dst_host.0, dst_host.1)
    });
    if mapped {
        return Ok(false);
    }
    remove_privs(cx, dst)?;
    if !vfs.store().try_share(src, dst)? {
        return Ok(false);
    }
    rehome(cx.kr(), &vfs, dst);
    Ok(true)
}

/// copy_file_range's checks, in 6.1's `generic_copy_file_checks` and `rw_verify_area` order:
/// directories `EISDIR`, other files that are not regular `EINVAL`; an input not open for reading
/// or an output not open for writing or appending `EBADF`; files on different filesystems
/// `EXDEV`; ranges whose end wraps around `EOVERFLOW`; then the length is cut to the input's end,
/// and to `RLIMIT_FSIZE` (at or past it, `SIGXFSZ` and `EFBIG`) and the largest file size
/// (`EFBIG`); overlapping ranges in one file `EINVAL`; negative positions `EINVAL`. Returns the
/// length to copy. `src`/`dst` are the offsets given, None for the file positions.
fn copy_range_checks(
    cx: &Cx<'_>,
    (input, src): (&FileRef, Option<i64>),
    (output, dst): (&FileRef, Option<i64>),
    len: usize,
) -> Result<usize, Errno> {
    let (i, o) = (input.borrow(), output.borrow());
    for f in [&i, &o] {
        match f.kind {
            // A FUSE file copies through reads and writes (6.1's fuse_copy_file_range falls back
            // to generic_copy_file_range when the daemon has no FUSE_COPY_FILE_RANGE)
            FileKind::Regular { .. } | FileKind::Fuse(_) => {}
            FileKind::Directory { .. } => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
    }
    if !i.readable() || !o.writable() || o.flags & oflags::O_APPEND != 0 {
        return Err(Errno::EBADF);
    }
    let vfs = cx.vfs()?;
    let dev = |f: &OpenFile| vfs.mount(f.mnt).map(|m| m.dev);
    if dev(&i) != dev(&o) {
        return Err(Errno::EXDEV);
    }
    reject_flags(file_inode_flags(cx, &o)?, inode_flags::PROTECTED)?;
    let pos_in = src.unwrap_or(i.pos as i64);
    let pos_out = dst.unwrap_or(o.pos as i64);
    let mut count = len as u64;
    let wraps = |pos: i64| (pos as u64).wrapping_add(count) < pos as u64;
    if wraps(pos_in) || wraps(pos_out) {
        return Err(Errno::EOVERFLOW);
    }
    let size_in = match &i.kind {
        FileKind::Regular { ino, file, .. } => regular_size(&vfs, *ino, file)? as i64,
        FileKind::Fuse(h) => crate::vfs::fuse::cached_attr_fh(&vfs, h.id, h.fh())?.size as i64,
        _ => return Err(Errno::EINVAL),
    };
    count = if pos_in >= size_in {
        0
    } else {
        count.min(size_in.saturating_sub(pos_in) as u64)
    };
    // generic_write_check_limits
    let limit = cx.t.group.borrow().rlimits[RLIMIT_FSIZE as usize].0;
    if limit != u64::MAX {
        if pos_out as u64 >= limit {
            return Err(file_too_big(cx));
        }
        count = count.min(limit - pos_out as u64);
    }
    // The largest file size (MAX_LFS_FILESIZE)
    if pos_out == i64::MAX {
        return Err(Errno::EFBIG);
    }
    count = count.min(i64::MAX.wrapping_sub(pos_out) as u64);
    let end = |pos: i64| pos.wrapping_add(count as i64);
    let same = match (i.data_ino(), o.data_ino()) {
        (Some(a), Some(b)) => a == b,
        _ => i.node() == o.node(),
    };
    if same && end(pos_out) > pos_in && pos_out < end(pos_in) {
        return Err(Errno::EINVAL);
    }
    // rw_verify_area
    if pos_in < 0 || pos_out < 0 || end(pos_in) < 0 || end(pos_out) < 0 {
        return Err(Errno::EINVAL);
    }
    Ok(count as usize)
}

/// When sendfile and copy_file_range copy between two regular files, the copy is left to the
/// host kernel ([`appine_hal::copy_file`]): the data does not pass through the kernel layer, and
/// it takes only one host call, without the BKL. With `src`/`dst` None the file positions are
/// used and advanced; the output fd's host position is also used, so the output's position is
/// always taken as [`unlocked_io`] does, and while waiting neither is taken, so copies in the
/// two directions do not wait for each other. When it does not apply (not two different regular
/// files, appending writes, seals, unsupported by the host) returns None, and the caller reads
/// and writes block by block.
fn copy_regular(
    cx: &mut Cx<'_>,
    input: &FileRef,
    src: Option<u64>,
    output: &FileRef,
    dst: Option<u64>,
    len: usize,
) -> Option<Result<usize, Errno>> {
    if let Err(e) = follow_copy_up(cx, input) {
        return Some(Err(e));
    }
    if len > 0
        && let Err(e) = prepare_write(cx, output, None)
    {
        return Some(Err(e));
    }
    let (fd_in, fd_out, ino) = {
        let (i, o) = (input.borrow(), output.borrow());
        if o.flags & oflags::O_APPEND != 0 || i.data_ino() == o.data_ino() {
            return None;
        }
        (regular_fd(&i)?, regular_fd(&o)?, o.ino()?)
    };
    // Seals must be checked block by block; tmpfs must be accounted block by block and stop when
    // full (write_bytes)
    let in_tmpfs = cx
        .vfs()
        .is_ok_and(|v| backing_tmpfs_dev(&v, &Node::Store(output.borrow().mnt, ino)).is_some());
    if cx.kr().seals.contains_key(&ino) || in_tmpfs {
        return None;
    }
    let len = match fsize_allowed(cx, &output.borrow(), dst, len.min(MAX_COPY), false) {
        Ok(n) => n,
        Err(e) => return Some(Err(e)),
    };
    if len > 0
        && let Err(e) = remove_privs(cx, ino)
    {
        return Some(Err(e));
    }
    let busy = |f: &FileRef, used: bool| used && f.borrow().pos_busy != 0;
    while busy(input, src.is_none()) || busy(output, true) {
        if cx.task.killed.get() {
            return Some(Err(Errno::EINTR));
        }
        for (f, used) in [(input, src.is_none()), (output, true)] {
            if busy(f, used) {
                f.borrow_mut().pos_busy = 2;
            }
        }
        if let Err(e) = cx.wait_on(None, &mut [], crate::kernel::wake::LOCK) {
            return Some(Err(e));
        }
    }
    if let Some(ino) = input.borrow().data_ino()
        && cx
            .t
            .vfs
            .as_ref()
            .and_then(|vfs| vfs.memfd_size(ino))
            .is_some()
    {
        return None;
    }
    let from = src.unwrap_or_else(|| input.borrow().pos);
    let to = dst.unwrap_or_else(|| output.borrow().pos);
    if src.is_none() {
        input.borrow_mut().pos_busy = 1;
    }
    output.borrow_mut().pos_busy = 1;
    let r = cx.unlocked(|| appine_hal::copy_file(fd_in, from, fd_out, to, len));
    let mut wake = false;
    for (f, used, dst, at) in [(input, src.is_none(), src, from), (output, true, dst, to)] {
        if used {
            let mut f = f.borrow_mut();
            if let (Ok(n), None) = (r, dst) {
                f.pos = at + n as u64;
            }
            wake |= std::mem::take(&mut f.pos_busy) == 2;
        }
    }
    if wake {
        request_wake_locks();
    }
    match r.map_err(Errno) {
        // The host does not support this pair of files: the caller reads and writes block by
        // block
        Err(Errno::EINVAL | Errno::ENOSYS | Errno::EOPNOTSUPP | Errno::EXDEV) => None,
        Err(e) => Some(Err(e)),
        Ok(n) => {
            if n > 0 {
                if let Ok(vfs) = cx.vfs() {
                    vfs.store().object_modified(ino);
                }
                inotify::file_io_event(cx.kr(), &input.borrow(), inotify::IN_ACCESS);
                inotify::file_io_event(cx.kr(), &output.borrow(), inotify::IN_MODIFY);
            }
            Some(Ok(n))
        }
    }
}

// Linux rw_verify_area checks the whole read before clipping to MAX_RW_COUNT or EOF.
fn verify_read_range(file: &OpenFile, offset: Option<u64>, count: usize) -> Result<(), Errno> {
    if matches!(file.kind, FileKind::Regular { .. }) {
        if !file.readable() {
            return Err(Errno::EBADF);
        }
        if offset.unwrap_or(file.pos).saturating_add(count as u64) > i64::MAX as u64 {
            return Err(Errno::EINVAL);
        }
    }
    Ok(())
}

/// Reads from an open file into a guest buffer (read, pread, readv).
pub(super) fn read_file(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
) -> SysResult {
    read_file_with(cx, file, buf, len, offset, IoFlags::default())
}

pub(super) fn read_file_with(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
    io: IoFlags,
) -> SysResult {
    read_file_inner(cx, file, buf, len, offset, io, false, true)
}

#[allow(clippy::too_many_arguments)]
fn read_file_inner(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
    io: IoFlags,
    pos_held: bool,
    mut touch_atime: bool,
) -> SysResult {
    let requested = len;
    let len = len.min(MAX_COPY);
    // A socket receives one message of up to the whole length (super::net::rw). The borrow must
    // end before: receiving may wait with the BKL released
    let sock = socket(&file.borrow());
    if let Some(s) = sock {
        positional(&file.borrow(), offset)?;
        let nonblock = file.borrow().nonblocking() || io.nowait;
        return super::net::rw(cx, &s, nonblock, &[(buf, len)], false);
    }
    if len == 0 {
        return read_bytes_inner(cx, file, &mut [], offset, io, pos_held, false).map(|n| n as u64);
    }
    // Pipe reads peek and copy into user memory before draining so an EFAULT never consumes bytes
    if let Some((pipe, _)) = pipe_of(file) {
        let nonblock = {
            let f = file.borrow();
            positional(&f, offset)?;
            if !f.readable() {
                return Err(Errno::EBADF);
            }
            f.nonblocking() || io.nowait
        };
        return pipe_read_user(cx, file, &pipe, nonblock, &[(buf, len)]);
    }
    let _pos = PosGuard::lock_positioned(cx, file, !pos_held && offset.is_none(), io.nowait)?;
    let held = pos_held || _pos.is_some();
    verify_read_range(&file.borrow(), offset, requested)?;
    // Each read of a terminal or pipe returns only data already ready and must not block again
    // to fill the buffer; /dev/zero and /dev/urandom fill it in one read as on Linux
    // (`dd bs=256M` reads whole blocks)
    let fill = matches!(
        file.borrow().kind,
        FileKind::Regular { .. }
            | FileKind::Proc { klog: None, .. }
            | FileKind::Device {
                dev: Device::Zero | Device::Full | Device::Random | Device::Loop,
                ..
            }
    ) || matches!(file.borrow().kind, FileKind::Host(fd) if host_regular(fd));
    let step = io_chunk(&file.borrow());
    let mut chunk = vec![0u8; len.min(step)];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(step);
        let before = file.borrow().pos;
        let k = match read_bytes_inner(
            cx,
            file,
            &mut chunk[..n],
            offset.map(|o| o + done as u64),
            io,
            held,
            touch_atime,
        ) {
            Ok(k) => {
                touch_atime = false;
                k
            }
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        };
        note_read(cx, file, k);
        // As on Linux, a fault partway returns the bytes copied before it (and EFAULT when there
        // are none); a regular file is read up to there. Data from other files has already been
        // consumed
        let copied = cx.write_user_partial(buf.wrapping_add(done as u64), &chunk[..k]);
        done += copied;
        if copied < k {
            let positioned = matches!(
                file.borrow().kind,
                FileKind::Regular { .. } | FileKind::Fuse(_)
            );
            if offset.is_none() && positioned {
                give_back(file, before, k - copied);
            }
            if done == 0 {
                return Err(Errno::EFAULT);
            }
            break;
        }
        if k < n || !fill {
            break;
        }
    }
    Ok(done as u64)
}

/// How much one read or write of open file `f` moves at once: [`FUSE_CHUNK`] for `/dev/fuse` and
/// FUSE files, [`IO_CHUNK`] for the rest.
fn io_chunk(f: &OpenFile) -> usize {
    match f.kind {
        FileKind::FuseDev(_) | FileKind::Fuse(_) => FUSE_CHUNK,
        _ => IO_CHUNK,
    }
}

/// Bookkeeping after a read that took `k` bytes: counted for signal-driven I/O, which the timer
/// thread checks (`check_fasync`), so it is only woken.
fn note_read(cx: &Cx<'_>, file: &FileRef, k: usize) {
    if k > 0 {
        if let FileKind::Pipe(end) = &file.borrow().kind
            && let Some(vfs) = &cx.kr().vfs
        {
            vfs.pipe_io_time(&end.pipe.borrow(), false);
        }
        file.borrow_mut().reads += 1;
        if file.borrow().flags & oflags::O_ASYNC != 0 {
            crate::kernel::signal_later(&cx.shared.timers);
        }
    }
}

/// The socket of an open file.
fn socket(f: &OpenFile) -> Option<SocketRef> {
    match &f.kind {
        FileKind::Socket(s) => Some(s.clone()),
        _ => None,
    }
}

/// Writes a guest buffer into an open file (write, pwrite, writev).
pub(super) fn write_file(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
) -> SysResult {
    write_file_with(cx, file, buf, len, offset, IoFlags::default())
}

pub(super) fn write_file_with(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
    io: IoFlags,
) -> SysResult {
    let offset = regular_append_offset(cx, &file.borrow(), offset, io.append)?;
    write_file_inner(cx, file, buf, len, offset, io, false, false)
}

#[allow(clippy::too_many_arguments)]
fn write_file_inner(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: u64,
    len: usize,
    offset: Option<u64>,
    io: IoFlags,
    pos_held: bool,
    defer_sync: bool,
) -> SysResult {
    let len = len.min(MAX_COPY);
    if sysctl_write(&file.borrow()) {
        return write_sysctl_iov(cx, file, &[(buf, len)], offset);
    }
    // ESPIPE and EBADF are reported before an unreadable buffer
    positional(&file.borrow(), offset)?;
    if !file.borrow().writable() {
        return Err(Errno::EBADF);
    }
    // write(2) does not skip zero-length writes: /dev/kmsg therefore logs an empty record
    if len == 0 && matches!(file.borrow().kind, FileKind::Device { kmsg: Some(_), .. }) {
        return kmsg_write(cx, file, &[]).map(|n| n as u64);
    }
    // A socket sends the whole buffer as one message, or a stream until it has all gone
    // (super::net::rw)
    let sock = socket(&file.borrow());
    if let Some(s) = sock {
        let nonblock = file.borrow().nonblocking() || io.nowait;
        return super::net::rw(cx, &s, nonblock, &[(buf, len)], true);
    }
    if let Some((pipe, _)) = pipe_of(file) {
        let nonblock = file.borrow().nonblocking() || io.nowait;
        return pipe_write_user(cx, &pipe, nonblock, &[(buf, len)]);
    }
    let _pos = PosGuard::lock_positioned(cx, file, !pos_held && offset.is_none(), io.nowait)?;
    let held = pos_held || _pos.is_some();
    // RLIMIT_FSIZE is checked once for the whole write, as generic_write_checks does: a piece
    // that ends at the limit only shortens it, without SIGXFSZ for the next
    let len = fsize_allowed(cx, &file.borrow(), offset, len, io.append)?;
    let step = io_chunk(&file.borrow());
    let mut chunk = vec![0u8; len.min(step)];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(step);
        let copied = cx.read_user(
            UserSlice::new(buf.wrapping_add(done as u64), n),
            &mut chunk[..n],
        );
        let step = copied.and_then(|()| {
            write_bytes_inner(
                cx,
                file,
                &chunk[..n],
                offset.map(|o| o + done as u64),
                io,
                held,
            )
        });
        match step {
            Ok(k) => {
                done += k;
                if k < n {
                    break;
                }
            }
            // When part was already written, return the bytes written, as Linux does
            Err(_) if done > 0 => break,
            Err(e) => return Err(e),
        }
    }
    if done > 0 && !defer_sync {
        write_sync(cx, file, 0)?;
    }
    Ok(done as u64)
}

/// Regular and FUSE files opened with `O_DSYNC` or `O_SYNC`, or pwritev2/AIO with `RWF_DSYNC` or
/// `RWF_SYNC` (`rwf`): after the write, wait for it to reach disk as fdatasync and fsync do
/// (Linux's generic_write_sync). Data, length and times are all in the host object, so the host
/// flushes them, waited for with the BKL released; FUSE files send `FUSE_FSYNC` (a daemon without
/// it succeeds silently).
pub(super) fn write_sync(cx: &mut Cx<'_>, file: &FileRef, rwf: u32) -> Result<(), Errno> {
    use oflags::{O_DSYNC, O_SYNC_BIT};
    const RWF_DSYNC: u32 = 2;
    const RWF_SYNC: u32 = 4;
    enum SyncTarget {
        Regular(i32),
        Fuse(super::fuse::Io),
    }
    let (target, data_only) = {
        let f = file.borrow();
        if f.flags & O_DSYNC == 0 && rwf & (RWF_DSYNC | RWF_SYNC) == 0 {
            return Ok(());
        }
        let target = match &f.kind {
            FileKind::Regular { file: host, .. } => {
                SyncTarget::Regular(std::os::fd::AsRawFd::as_raw_fd(host))
            }
            FileKind::Fuse(h) => SyncTarget::Fuse(super::fuse::Io::of(h)),
            _ => return Ok(()),
        };
        let full = f.flags & O_SYNC_BIT != 0 || rwf & RWF_SYNC != 0;
        (target, !full)
    };
    match target {
        // The open file is kept alive by file and not touched while the BKL is released
        SyncTarget::Regular(fd) => cx
            .unlocked(|| appine_hal::fsync(fd, data_only))
            .map_err(Errno),
        SyncTarget::Fuse(io) => super::fuse::fsync(cx, &io, false, data_only),
    }
}

/// Does one read from an open file into a host buffer. With `offset` None the file position is
/// used and advanced.
pub(super) fn read_bytes(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: &mut [u8],
    offset: Option<u64>,
) -> Result<usize, Errno> {
    read_bytes_with(cx, file, buf, offset, IoFlags::default())
}

fn read_bytes_with(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: &mut [u8],
    offset: Option<u64>,
    io: IoFlags,
) -> Result<usize, Errno> {
    read_bytes_inner(cx, file, buf, offset, io, false, true)
}

fn read_bytes_inner(
    cx: &mut Cx<'_>,
    file: &FileRef,
    buf: &mut [u8],
    offset: Option<u64>,
    io: IoFlags,
    pos_held: bool,
    touch_atime: bool,
) -> Result<usize, Errno> {
    let (path, nonblock) = {
        let f = file.borrow();
        let path = positional(&f, offset)?;
        if !f.readable() {
            return Err(Errno::EBADF);
        }
        (path, f.nonblocking() || io.nowait)
    };
    // Stream and regular-file reads can finish an empty transfer without waiting for
    // readiness or contacting a FUSE daemon. Record-oriented devices check their own sizes.
    if buf.is_empty()
        && (matches!(
            path,
            IoPath::Host(_) | IoPath::Pty(..) | IoPath::Fuse(_) | IoPath::Loop(_) | IoPath::Pipe(_)
        ) || matches!(file.borrow().kind, FileKind::Regular { .. }))
    {
        return Ok(0);
    }
    match path {
        IoPath::Host(fd) => match offset {
            Some(off) => cx
                .unlocked(|| appine_hal::pread(fd, buf, off))
                .map_err(Errno),
            None => {
                if !host_regular(fd) {
                    wait_host(cx, fd, POLLIN, nonblock)?;
                }
                cx.unlocked(|| appine_hal::read(fd, buf)).map_err(Errno)
            }
        },
        IoPath::Pipe(pipe) => {
            let n = pipe_read(cx, &pipe, nonblock, buf)?;
            if n != 0
                && let Some(vfs) = &cx.kr().vfs
            {
                vfs.pipe_io_time(&pipe.borrow(), false);
            }
            Ok(n)
        }
        IoPath::Pty(t, side) => tty::read(cx, &t, side, nonblock, buf),
        IoPath::Socket(s) => {
            let m = super::net::recv(cx, &s, nonblock, buf.len(), 0, 0)?;
            buf[..m.data.len()].copy_from_slice(&m.data);
            Ok(m.data.len())
        }
        IoPath::EventFd(e) => super::poll::eventfd_read(cx, &e, nonblock, buf),
        IoPath::TimerFd(t) => super::timerfd::read(cx, &t, nonblock, buf),
        IoPath::SignalFd(s) => super::sig::signalfd_read(cx, &s, nonblock, buf),
        IoPath::Inotify(i) => super::inotify::read(cx, &i, nonblock, buf),
        IoPath::Pagemap(mm) => {
            let pos = offset.unwrap_or(file.borrow().pos);
            let n = pseudo::read_pagemap(mm, buf, pos)?;
            if offset.is_none() {
                file.borrow_mut().pos = pos + n as u64;
            }
            Ok(n)
        }
        IoPath::Kmsg => kmsg_read(cx, file, nonblock, buf),
        IoPath::ProcKmsg(log) => proc_kmsg_read(cx, &log, nonblock, buf),
        IoPath::Loop(dev) => super::loopdev::read(cx, file, &dev, buf, offset),
        IoPath::Fuse(fio) => {
            let n = super::fuse::read(cx, file, &fio, buf, offset, pos_held)?;
            if n > 0 {
                inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_ACCESS);
            }
            Ok(n)
        }
        IoPath::FuseDev => {
            let message = crate::vfs::fuse::dev_read(cx, file, buf.len(), nonblock)?;
            buf[..message.len()].copy_from_slice(&message);
            Ok(message.len())
        }
        IoPath::Mem(mm) => {
            let _pos = PosGuard::lock_if(cx, file, !pos_held && offset.is_none())?;
            let pos = offset.unwrap_or(file.borrow().pos);
            let n = pseudo::access_mem(cx, mm, pos, buf.len(), |mm, addr, range| {
                mm.read_force(addr, &mut buf[range])
            })?;
            if offset.is_none() {
                file.borrow_mut().pos = pos.wrapping_add(n as u64);
            }
            Ok(n)
        }
        IoPath::Local => {
            follow_copy_up(cx, file)?;
            let regular = regular_fd(&file.borrow());
            let n = match regular {
                Some(fd) => {
                    let logical = file
                        .borrow()
                        .data_ino()
                        .and_then(|ino| cx.t.vfs.as_ref()?.memfd_size(ino));
                    let n =
                        unlocked_io(cx, file, fd, (offset, pos_held), |fd, pos| match logical {
                            Some(len) => read_sparse_memfd(fd, buf, pos, len),
                            None => appine_hal::pread(fd, buf, pos),
                        })?;
                    if touch_atime {
                        file_accessed(cx, &file.borrow());
                    }
                    n
                }
                None => {
                    if !buf.is_empty() {
                        refresh_pseudo(cx, file, offset)?;
                    }
                    local_read(&mut file.borrow_mut(), buf, offset)?
                }
            };
            if n > 0 {
                inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_ACCESS);
            }
            Ok(n)
        }
    }
}

/// Apply the access policy of the open description and its current mount.
pub(super) fn file_accessed(cx: &Cx<'_>, f: &OpenFile) {
    if f.flags & oflags::O_NOATIME != 0 {
        return;
    }
    if let FileKind::Regular { ino, file, .. } = &f.kind
        && let Some(vfs) = cx.kr().vfs.as_deref()
    {
        vfs.accessed(f.mnt, *ino, Some(file));
    }
}

/// Waits until a host fd (the host stdio `appine-run` gives the guest) is readable or writable;
/// does not wait when nonblocking. Waits only on the host fd itself and registers no object:
/// nothing in the process can make it ready, and previously every pipe or PTY read or write in
/// the system woke the threads blocked on host stdin once.
fn wait_host(cx: &mut Cx<'_>, fd: i32, events: i16, nonblock: bool) -> Result<(), Errno> {
    let mut pfd = [(fd, events, 0)];
    loop {
        appine_hal::poll(&mut pfd, Some(Duration::ZERO)).map_err(Errno)?;
        if pfd[0].2 != 0 {
            return Ok(());
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_objects(None, &mut pfd, crate::kernel::wake::FILE, &[])?;
        if pfd[0].2 != 0 {
            return Ok(());
        }
    }
}

/// Reads from a pipe directly into guest buffers `vecs` (read, readv, read-side vmsplice): peeks
/// the pipe buffer and copies into user memory before draining, so a fault (EFAULT) leaves
/// uncopied bytes in the pipe and wakes no writers when nothing was copied.
fn pipe_read_user(
    cx: &mut Cx<'_>,
    file: &FileRef,
    pipe: &Rc<RefCell<Pipe>>,
    nonblock: bool,
    vecs: &[(u64, usize)],
) -> SysResult {
    let total: usize = vecs.iter().map(|v| v.1).sum::<usize>().min(IO_CHUNK);
    if total == 0 {
        return Ok(0);
    }
    loop {
        if wait_splice_done(cx, pipe)? {
            continue;
        }
        {
            let p = pipe.borrow();
            if !p.bytes().is_empty() {
                break;
            }
            if p.writers == 0 {
                return Ok(0);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
    let data = pipe.borrow().snapshot(total);
    let mut done = 0;
    for &(base, len) in vecs {
        let n = len.min(data.len() - done);
        if n == 0 {
            continue;
        }
        let copied = cx.write_user_partial(base, &data[done..done + n]);
        done += copied;
        if copied < n {
            break;
        }
    }
    if done == 0 {
        return Err(Errno::EFAULT);
    }
    pipe.borrow_mut().consume(done, false);
    note_read(cx, file, done);
    Ok(done as u64)
}

fn pipe_read(
    cx: &mut Cx<'_>,
    pipe: &Rc<RefCell<Pipe>>,
    nonblock: bool,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    loop {
        if !buf.is_empty() && wait_splice_done(cx, pipe)? {
            continue;
        }
        {
            let mut p = pipe.borrow_mut();
            if !p.bytes().is_empty() || buf.is_empty() {
                let n = p.copy_out(buf);
                p.consume(n, false);
                return Ok(n);
            }
            if p.writers == 0 {
                return Ok(0);
            }
        }
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
}

/// Read of `/dev/kmsg` (`devkmsg_read`): reads one record at a time
/// ([`crate::klog::Klog::ext_text`]), waiting when there is no new record (EAGAIN when
/// nonblocking). When the record to read has been pushed out it is EPIPE and the position jumps
/// to the oldest record; a buffer too small for the record is EINVAL and the record counts as
/// read, as on Linux.
fn kmsg_read(
    cx: &mut Cx<'_>,
    file: &FileRef,
    nonblock: bool,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    loop {
        let object = {
            let mut f = file.borrow_mut();
            let FileKind::Device {
                kmsg: Some(user), ..
            } = &mut f.kind
            else {
                return Err(Errno::EBADF);
            };
            let log = user.log.clone();
            let l = log.borrow();
            if let Some(r) = l.ext_text(user.seq) {
                if r.seq != user.seq {
                    user.seq = r.seq;
                    return Err(Errno::EPIPE);
                }
                user.seq = r.seq + 1;
                if r.text.len() > buf.len() {
                    return Err(Errno::EINVAL);
                }
                buf[..r.text.len()].copy_from_slice(&r.text);
                return Ok(r.text.len());
            }
            wake::of(&*log)
        };
        if nonblock {
            return Err(Errno::EAGAIN);
        }
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(object)?;
    }
}

/// Read of `/proc/kmsg` (`kmsg_read`): syslog's read, sharing the read position with syslog(2);
/// what is read is gone. Nonblocking with no unread record is EAGAIN.
fn proc_kmsg_read(
    cx: &mut Cx<'_>,
    log: &Rc<RefCell<crate::klog::Klog>>,
    nonblock: bool,
    buf: &mut [u8],
) -> Result<usize, Errno> {
    if nonblock && log.borrow_mut().size_unread(true) == 0 {
        return Err(Errno::EAGAIN);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    while !log.borrow().syslog_readable() {
        if cx.interrupted() {
            return Err(Errno::ERESTARTSYS);
        }
        cx.wait_object(wake::of(&**log))?;
    }
    let text = log.borrow_mut().syslog_read(buf.len());
    buf[..text.len()].copy_from_slice(&text);
    Ok(text.len())
}

/// As with Linux's seq_file (`seq_read_iter` starts over at offset 0), reading a procfs, sysfs or
/// cgroup2 file from offset 0 regenerates the content: programs that keep it open and seek back
/// to 0 to read again (procps; runc writes `cgroup.freeze` and reads it back to confirm) read the
/// current content. Content just generated at open and not yet read or written is not
/// regenerated.
fn refresh_pseudo(cx: &mut Cx<'_>, file: &FileRef, offset: Option<u64>) -> Result<(), Errno> {
    let (mnt, node, opener) = {
        let mut f = file.borrow_mut();
        let pos = offset.unwrap_or(f.pos);
        match &mut f.kind {
            // environ pins the old mm. Its cached bytes expire at every offset when the mm dies.
            FileKind::Proc {
                node: PseudoNode::Entry(_, _, pseudo::Entry::Environ),
                data,
                fresh,
                mm,
                ..
            } => {
                let pinned = mm.as_ref().and_then(Weak::upgrade);
                if pinned.is_none() {
                    data.clear();
                } else if pos == 0 && !std::mem::take(fresh) {
                    *data = pseudo::read_environ(pinned.as_ref());
                }
                return Ok(());
            }
            FileKind::Proc {
                mnt,
                node,
                fresh,
                ns: None,
                klog: None,
                opener,
                event,
                ..
            } if pos == 0 && !pseudo::unreadable(node) => {
                // Reading a kernfs file from the start takes in its changes so far
                // (kernfs_seq_show; mounts and mountinfo take them in as poll reports them);
                // contents generated before a change are made again
                let current = event.as_ref().is_none_or(|e| {
                    let now = e.counter.get();
                    if !e.mounts {
                        e.seen.set(now);
                    }
                    e.generated.replace(now) == now
                });
                if std::mem::take(fresh) && current && !pseudo::gone(cx.kr(), node) {
                    return Ok(());
                }
                (*mnt, node.clone(), opener.clone())
            }
            _ => return Ok(()),
        }
    };
    let vfs = cx.vfs()?;
    // With the opener's credentials, as Linux's seq_file handlers use the file's f_cred: a
    // descriptor passed to another process shows the same IDs
    let view = pseudo::View {
        cred: Some(opener),
        ..cx.view(&vfs)
    };
    let content = pseudo::content(&view, mnt, &node)?;
    if let FileKind::Proc { data, .. } = &mut file.borrow_mut().kind {
        *data = content;
    }
    Ok(())
}

fn local_read(f: &mut OpenFile, buf: &mut [u8], offset: Option<u64>) -> Result<usize, Errno> {
    let pos = offset.unwrap_or(f.pos);
    let n = match &f.kind {
        FileKind::Regular { file, .. } => file.read_at(buf, pos).map_err(host_errno)?,
        FileKind::Device { dev, .. } => match dev {
            Device::Null => 0,
            Device::Zero | Device::Full => {
                buf.fill(0);
                buf.len()
            }
            Device::Random => {
                appine_hal::fill_random(buf).map_err(Errno)?;
                buf.len()
            }
            Device::Kmsg => return Err(Errno::EBADF),
            // No read operation (loop devices are read through IoPath::Loop)
            Device::LoopControl | Device::Loop => return Err(Errno::EINVAL),
        },
        // Namespaces (nsfs) cannot be read
        FileKind::Proc {
            node: PseudoNode::NsFile(..),
            ..
        } => return Err(Errno::EINVAL),
        FileKind::Proc { node, .. } if pseudo::unreadable(node) => return Err(Errno::EINVAL),
        FileKind::Proc { data, .. } => {
            let start = (pos as usize).min(data.len());
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            n
        }
        // A message queue reads as its status line
        FileKind::MessageQueue(q) => {
            let data = q.borrow().status();
            let start = (pos as usize).min(data.len());
            let n = buf.len().min(data.len() - start);
            buf[..n].copy_from_slice(&data[start..start + n]);
            n
        }
        FileKind::Directory { .. } => return Err(Errno::EISDIR),
        FileKind::Epoll(_) | FileKind::Pidfd(_) | FileKind::SeccompNotify(_) | FileKind::Bpf(_) => {
            return Err(Errno::EINVAL);
        }
        _ => return Err(Errno::EBADF),
    };
    let positioned = matches!(
        f.kind,
        FileKind::Regular { .. } | FileKind::Proc { .. } | FileKind::MessageQueue(_)
    );
    if offset.is_none() && positioned {
        f.pos = pos + n as u64;
    }
    Ok(n)
}

/// Does one write to an open file. With `offset` None the file position is used and advanced,
/// and with `O_APPEND` it first moves to the end of the file.
pub(super) fn write_bytes(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    offset: Option<u64>,
) -> Result<usize, Errno> {
    write_bytes_with(cx, file, data, offset, IoFlags::default())
}

fn write_bytes_with(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    offset: Option<u64>,
    io: IoFlags,
) -> Result<usize, Errno> {
    write_bytes_inner(cx, file, data, offset, io, false)
}

fn write_bytes_inner(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    offset: Option<u64>,
    io: IoFlags,
    pos_held: bool,
) -> Result<usize, Errno> {
    let (path, nonblock) = {
        let f = file.borrow();
        let path = positional(&f, offset)?;
        if !f.writable() {
            return Err(Errno::EBADF);
        }
        (path, f.nonblocking() || io.nowait)
    };
    match path {
        IoPath::Host(fd) => write_host(cx, fd, data, offset, nonblock),
        IoPath::Pipe(pipe) => pipe_write(cx, &pipe, nonblock, data, true),
        IoPath::Pty(t, side) => tty::write(cx, &t, side, nonblock, data),
        IoPath::Socket(s) => super::net::send(cx, &s, nonblock, data, &[], &[], 0),
        IoPath::EventFd(e) => super::poll::eventfd_write(cx, &e, nonblock, data),
        IoPath::TimerFd(_) | IoPath::SignalFd(_) | IoPath::Inotify(_) | IoPath::Pagemap(_) => {
            Err(Errno::EINVAL)
        }
        IoPath::Kmsg => kmsg_write(cx, file, data),
        // Opened for writing by root: proc_reg_write without a proc_write
        IoPath::ProcKmsg(_) => Err(Errno::EIO),
        IoPath::Loop(dev) => super::loopdev::write(cx, file, &dev, data, offset),
        IoPath::Fuse(fio) => {
            let n = super::fuse::write(cx, file, &fio, data, offset, io.append, pos_held)?;
            if n > 0 {
                inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_MODIFY);
            }
            Ok(n)
        }
        IoPath::FuseDev => {
            let vfs = cx.vfs()?;
            crate::vfs::fuse::dev_write(cx, &vfs, file, data)
        }
        IoPath::Mem(mm) => {
            let _pos = PosGuard::lock_if(cx, file, !pos_held && offset.is_none())?;
            let pos = offset.unwrap_or(file.borrow().pos);
            let sync = cx.task.sync.clone();
            let n = pseudo::access_mem(cx, mm, pos, data.len(), |mm, addr, range| {
                mm.write_force(addr, &data[range], &sync)
            })?;
            if offset.is_none() {
                file.borrow_mut().pos = pos.wrapping_add(n as u64);
            }
            Ok(n)
        }
        IoPath::Local => {
            // A write at the position of a regular file (including O_APPEND/RWF_APPEND) holds the
            // position from its checks to its end, so concurrent unlocked reads or seeks cannot
            // overwrite or interleave with it (Linux takes f_pos_lock before generic_write_checks).
            let append = io.append || file.borrow().flags & oflags::O_APPEND != 0;
            let need = !pos_held && offset.is_none() && regular_fd(&file.borrow()).is_some();
            let _pos = PosGuard::lock_if_with(cx, file, need, io.nowait)?;
            let held = pos_held || _pos.is_some();
            write_local(cx, file, data, (offset, held, append))
        }
    }
}

/// [`write_bytes_with`] to the files written here (`IoPath::Local`): regular and synthetic files.
/// `held`: the caller holds the position ([`take_pos`]). `append`: `O_APPEND` or `RWF_APPEND`.
fn write_local(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    (offset, held, append): (Option<u64>, bool, bool),
) -> Result<usize, Errno> {
    let flags = file_inode_flags(cx, &file.borrow())?;
    reject_flags(flags, inode_flags::IMMUTABLE)?;
    let append = append || flags & inode_flags::APPEND != 0;
    let offset = if offset.is_some() && flags & inode_flags::APPEND != 0 {
        let f = file.borrow();
        let (ino, host, _) = f.regular_backing().ok_or(Errno::EBADF)?;
        Some(regular_size(&*cx.vfs()?, ino, host)?)
    } else {
        offset
    };
    let data = &data[..fsize_allowed(cx, &file.borrow(), offset, data.len(), append)?];
    let (n, mut tmpfs) = tmpfs_write_room(cx, &file.borrow(), offset, data.len(), append)?;
    let data = &data[..n];
    check_seals(cx, &file.borrow(), true, |size| {
        let f = file.borrow();
        let pos = match offset {
            Some(off) => off,
            None if append => size,
            None => f.pos,
        };
        size.max(pos + data.len() as u64)
    })?;
    if matches!(file.borrow().kind, FileKind::Proc { .. }) {
        return write_proc(cx, file, data, data.len(), offset);
    }
    let (ino, cow) = match file.borrow().kind {
        FileKind::Regular { ino, cow, .. } => (Some(ino), cow),
        _ => (None, false),
    };
    if let Some(ino) = ino.filter(|_| !data.is_empty()) {
        prepare_write(cx, file, None)?;
        remove_privs(cx, ino)?;
    }
    // Copy-up may have released the BKL. Hold it from the final tmpfs room check through
    // the write and charge, so mapped faults and descriptor writes cannot claim the same page.
    let data = if cow && tmpfs.is_some() {
        let (allowed, before) = tmpfs_write_room(cx, &file.borrow(), offset, data.len(), append)?;
        tmpfs = before;
        &data[..allowed]
    } else {
        data
    };
    // Ordinary file writes can release the BKL. Appends keep it across offset selection
    // and the write, and tmpfs keeps it across the quota check, write and charge.
    let regular = regular_fd(&file.borrow()).filter(|_| !append && tmpfs.is_none());
    let n = match regular {
        Some(fd) => unlocked_io(cx, file, fd, (offset, held), |fd, pos| {
            appine_hal::pwrite(fd, data, pos)
        })?,
        None => local_write(cx, &mut file.borrow_mut(), data, offset, append)?,
    };
    if let (Some(t), FileKind::Regular { file: host, .. }) = (tmpfs, &file.borrow().kind) {
        tmpfs_resized(&*cx.vfs()?, Some(t), host);
    }
    if n > 0 {
        if let FileKind::Regular { ino, .. } = &file.borrow().kind
            && let Ok(vfs) = cx.vfs()
        {
            vfs.store().object_modified(*ino);
        }
        inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_MODIFY);
    }
    Ok(n)
}

fn write_proc(
    cx: &mut Cx<'_>,
    file: &FileRef,
    data: &[u8],
    count: usize,
    offset: Option<u64>,
) -> Result<usize, Errno> {
    let (node, opener, pos) = {
        let f = file.borrow();
        let FileKind::Proc { node, opener, .. } = &f.kind else {
            return Err(Errno::EBADF);
        };
        (node.clone(), opener.clone(), offset.unwrap_or(f.pos))
    };
    let (tid, cred, ns, pid_ns) = (cx.tid(), cx.cred(), cx.ns(), cx.pid_ns());
    let (written, next) = pseudo::write(
        cx.k(),
        (tid, &cred, &opener),
        (&ns, &pid_ns),
        &node,
        data,
        (pos, count),
    )?;
    {
        let mut f = file.borrow_mut();
        if offset.is_none() {
            f.pos = next;
        }
        if let FileKind::Proc { fresh, .. } = &mut f.kind {
            *fresh = false;
        }
    }
    // The cgroup memory limit changed: wake the timer thread to measure once right away
    if let PseudoNode::Cgroup(_, b"memory.max", _) = node {
        cx.k().oom.recheck();
        crate::kernel::signal_later(&cx.shared.timers);
    }
    // A write is IN_MODIFY (fsnotify_modify); of the synthetic files only cgroup2's are tracked
    // by `inotify::file_io_event`, which notifies both the parent directory and the file watch.
    if written > 0 {
        inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_MODIFY);
    }
    Ok(written)
}

/// Writes to a host stdio fd: positional writes use host `pwrite`; regular host files write
/// directly without polling; pipes/terminals/sockets poll `POLLOUT` via [`wait_host`] in
/// `PIPE_BUF`-sized pieces so blocked writes are interruptible by guest signals and honour
/// `O_NONBLOCK` without blocking inside the host kernel.
fn write_host(
    cx: &mut Cx<'_>,
    fd: i32,
    data: &[u8],
    offset: Option<u64>,
    nonblock: bool,
) -> Result<usize, Errno> {
    let map_err = |cx: &mut Cx<'_>, e: i32| {
        if e == Errno::EPIPE.0 {
            broken_pipe(cx)
        } else {
            Errno(e)
        }
    };
    if let Some(off) = offset {
        return cx
            .unlocked(|| appine_hal::pwrite(fd, data, off))
            .map_err(|e| map_err(cx, e));
    }
    if data.is_empty() || host_regular(fd) {
        return cx
            .unlocked(|| appine_hal::write(fd, data))
            .map_err(|e| map_err(cx, e));
    }
    let mut done = 0;
    while done < data.len() {
        if let Err(e) = wait_host(cx, fd, POLLOUT, nonblock) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        let chunk = &data[done..(done + PIPE_BUF).min(data.len())];
        match cx.unlocked(|| appine_hal::write(fd, chunk)) {
            Ok(0) => break,
            Ok(n) => {
                done += n;
                if n < chunk.len() {
                    break;
                }
            }
            Err(e) => {
                let e = map_err(cx, e);
                return if done > 0 { Ok(done) } else { Err(e) };
            }
        }
    }
    Ok(done)
}

struct IovCursor<'a> {
    vecs: &'a [(u64, usize)],
    idx: usize,
    off: usize,
    left: usize,
}

impl<'a> IovCursor<'a> {
    fn new(vecs: &'a [(u64, usize)]) -> Self {
        let left = vecs.iter().map(|v| v.1).sum();
        Self {
            vecs,
            idx: 0,
            off: 0,
            left,
        }
    }

    fn copy_exact(&mut self, cx: &mut Cx<'_>, dst: &mut [u8]) -> Result<(), Errno> {
        let mut pos = 0;
        while pos < dst.len() {
            let &(base, len) = &self.vecs[self.idx];
            if self.off == len {
                self.idx += 1;
                self.off = 0;
                continue;
            }
            let n = (len - self.off).min(dst.len() - pos);
            let addr = base.wrapping_add(self.off as u64);
            cx.read_user(UserSlice::new(addr, n), &mut dst[pos..pos + n])?;
            self.off += n;
            self.left -= n;
            pos += n;
        }
        Ok(())
    }
}

/// Writes guest buffers `vecs` into a pipe matching Linux 6.1's `pipe_write`: an initial partial
/// page (`total % PIPE_BUF`) may merge into the last mergeable slot if it copies completely, then
/// each remaining pipe page (up to `PIPE_BUF`) is copied and committed whole; a fault while
/// filling a page discards that incomplete page and returns the bytes committed so far (`EFAULT`
/// if none).
fn pipe_write_user(
    cx: &mut Cx<'_>,
    pipe: &Rc<RefCell<Pipe>>,
    nonblock: bool,
    vecs: &[(u64, usize)],
) -> SysResult {
    let mut iter = IovCursor::new(vecs);
    let total = iter.left;
    if total == 0 {
        return Ok(0);
    }
    let mut done = 0;
    let mut page = [0u8; PIPE_BUF];

    let tail = {
        let p = pipe.borrow();
        if p.readers == 0 {
            drop(p);
            return Err(broken_pipe(cx));
        }
        p.merge_len(total)
    };
    if tail != 0 {
        iter.copy_exact(cx, &mut page[..tail])?;
        let mut p = pipe.borrow_mut();
        if p.readers == 0 {
            drop(p);
            return Err(broken_pipe(cx));
        }
        p.write(&page[..tail], true);
        pipe_arrival(cx, &mut p, tail);
        done += tail;
        if iter.left == 0 {
            return Ok(done as u64);
        }
    }

    loop {
        let can_write = {
            let p = pipe.borrow();
            if p.readers == 0 {
                drop(p);
                let e = broken_pipe(cx);
                return if done > 0 { Ok(done as u64) } else { Err(e) };
            }
            p.free_slots() > 0
        };
        if can_write {
            let want = iter.left.min(PIPE_BUF);
            if let Err(e) = iter.copy_exact(cx, &mut page[..want]) {
                return if done > 0 { Ok(done as u64) } else { Err(e) };
            }
            let mut p = pipe.borrow_mut();
            p.write(&page[..want], false);
            pipe_arrival(cx, &mut p, want);
            done += want;
            if iter.left == 0 {
                return Ok(done as u64);
            }
            continue;
        }
        if nonblock || cx.interrupted() {
            let e = if nonblock {
                Errno::EAGAIN
            } else {
                Errno::ERESTARTSYS
            };
            return if done > 0 { Ok(done as u64) } else { Err(e) };
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
}

fn pipe_write(
    cx: &mut Cx<'_>,
    pipe: &Rc<RefCell<Pipe>>,
    nonblock: bool,
    data: &[u8],
    mut first: bool,
) -> Result<usize, Errno> {
    let mut done = 0;
    loop {
        let progress = {
            let mut p = pipe.borrow_mut();
            if p.readers == 0 {
                drop(p);
                let e = broken_pipe(cx);
                return if done > 0 { Ok(done) } else { Err(e) };
            }
            let n = p.write(&data[done..], first);
            first = false;
            done += n;
            pipe_arrival(cx, &mut p, n);
            n != 0
        };
        if done == data.len() {
            return Ok(done);
        }
        if progress {
            continue;
        }
        if nonblock || cx.interrupted() {
            let e = if nonblock {
                Errno::EAGAIN
            } else {
                Errno::ERESTARTSYS
            };
            return if done > 0 { Ok(done) } else { Err(e) };
        }
        cx.wait_object(crate::pipe::object(pipe))?;
    }
}

/// The write end has no readers left: EPIPE, and SIGPIPE to the current thread.
fn broken_pipe(cx: &mut Cx<'_>) -> Errno {
    let task = cx.task.clone();
    signal::send_to_task(cx.kr(), &task, Signal::PIPE, SigInfo::kernel());
    Errno::EPIPE
}

/// Write of `/dev/kmsg` (`devkmsg_write`): one write is one record
/// ([`crate::klog::KmsgFile::write`]), and more than `LOG_LINE_MAX` is EINVAL; without a prefix
/// the level is the default message level of `/proc/sys/kernel/printk`.
fn kmsg_write(cx: &mut Cx<'_>, file: &FileRef, data: &[u8]) -> Result<usize, Errno> {
    if data.len() > crate::klog::LOG_LINE_MAX {
        return Err(Errno::EINVAL);
    }
    let level = cx.kr().printk[1];
    if let FileKind::Device {
        kmsg: Some(user), ..
    } = &mut file.borrow_mut().kind
    {
        user.write(data, level);
    }
    Ok(data.len())
}

/// `RLIMIT_FSIZE`: a write to a regular file past the limit writes only up to the limit; when
/// not a single byte can be written, sends SIGXFSZ to the current thread and returns EFBIG.
/// Returns the number of bytes allowed.
fn fsize_allowed(
    cx: &Cx<'_>,
    f: &OpenFile,
    offset: Option<u64>,
    len: usize,
    append: bool,
) -> Result<usize, Errno> {
    let FileKind::Regular { file, ino, .. } = &f.kind else {
        return Ok(len);
    };
    let flags = file_inode_flags(cx, f)?;
    reject_flags(flags, inode_flags::IMMUTABLE)?;
    let limit = cx.t.group.borrow().rlimits[RLIMIT_FSIZE as usize].0;
    if limit == u64::MAX || len == 0 {
        return Ok(len);
    }
    let pos = match offset {
        _ if flags & inode_flags::APPEND != 0 => regular_size(&*cx.vfs()?, *ino, file)?,
        Some(off) => off,
        None if append || f.flags & oflags::O_APPEND != 0 => regular_size(&*cx.vfs()?, *ino, file)?,
        None => f.pos,
    };
    if pos >= limit {
        return Err(file_too_big(cx));
    }
    Ok(len.min((limit - pos) as usize))
}

fn local_write(
    cx: &Cx<'_>,
    f: &mut OpenFile,
    data: &[u8],
    offset: Option<u64>,
    append: bool,
) -> Result<usize, Errno> {
    match &f.kind {
        FileKind::Regular { file, ino, .. } => {
            let pos = match offset {
                Some(off) => off,
                None if append || f.flags & oflags::O_APPEND != 0 => {
                    regular_size(&*cx.vfs()?, *ino, file)?
                }
                None => f.pos,
            };
            let n = file.write_at(data, pos).map_err(host_errno)?;
            if offset.is_none() {
                f.pos = pos + n as u64;
            }
            Ok(n)
        }
        FileKind::Device { dev, .. } => match dev {
            Device::Full => Err(Errno::ENOSPC),
            // No write operation (loop devices are written through IoPath::Loop)
            Device::LoopControl | Device::Loop => Err(Errno::EINVAL),
            _ => Ok(data.len()),
        },
        // Anonymous inodes without a write operation
        FileKind::Epoll(_)
        | FileKind::Pidfd(_)
        | FileKind::MessageQueue(_)
        | FileKind::SeccompNotify(_)
        | FileKind::Bpf(_) => Err(Errno::EINVAL),
        _ => Err(Errno::EBADF),
    }
}

/// Which route a read or write takes. Reads and writes with an offset (pread, pwritev) on a file
/// that cannot seek are ESPIPE: as on Linux this comes before the open-mode check (pwrite on a
/// pipe opened read-only is also ESPIPE), except for `O_PATH`.
fn positional(f: &OpenFile, offset: Option<u64>) -> Result<IoPath, Errno> {
    let path = io_path(f);
    // pread and pwrite of /dev/kmsg and /proc/kmsg ignore the offset, like read and write
    let seekable = matches!(
        path,
        IoPath::Local
            | IoPath::Pagemap(_)
            | IoPath::Mem(_)
            | IoPath::Kmsg
            | IoPath::ProcKmsg(_)
            | IoPath::Loop(_)
    ) || matches!(&f.kind, FileKind::Fuse(h) if super::fuse::seekable(h))
        || matches!(path, IoPath::Host(fd) if host_regular(fd));
    if offset.is_some() && !seekable && f.flags & oflags::O_PATH == 0 {
        return Err(Errno::ESPIPE);
    }
    Ok(path)
}

/// Whether the file can be read and written by position (AIO ignores the offset for files that
/// cannot seek).
pub(super) fn seekable(f: &OpenFile) -> bool {
    matches!(
        io_path(f),
        IoPath::Local | IoPath::Pagemap(_) | IoPath::Mem(_) | IoPath::Loop(_)
    ) || matches!(&f.kind, FileKind::Fuse(h) if super::fuse::seekable(h))
        || matches!(&f.kind, FileKind::Host(fd) if host_regular(*fd))
}

fn io_path(f: &OpenFile) -> IoPath {
    match &f.kind {
        FileKind::Host(fd) => IoPath::Host(*fd),
        FileKind::Pipe(end) => IoPath::Pipe(end.pipe.clone()),
        FileKind::Pty(end) => IoPath::Pty(end.tty.clone(), (end.master, end.born)),
        FileKind::Socket(s) => IoPath::Socket(s.clone()),
        FileKind::EventFd(e) => IoPath::EventFd(e.clone()),
        FileKind::TimerFd(t) => IoPath::TimerFd(t.clone()),
        FileKind::SignalFd(s) => IoPath::SignalFd(s.clone()),
        FileKind::Inotify(i) => IoPath::Inotify(i.clone()),
        FileKind::Proc {
            node: PseudoNode::Entry(_, _, pseudo::Entry::Pagemap),
            mm,
            ..
        } => IoPath::Pagemap(mm.as_ref().and_then(std::rc::Weak::upgrade)),
        FileKind::Proc {
            node: PseudoNode::Entry(_, _, pseudo::Entry::Mem),
            mm,
            ..
        } => IoPath::Mem(mm.as_ref().and_then(std::rc::Weak::upgrade)),
        FileKind::Device { kmsg: Some(_), .. } => IoPath::Kmsg,
        FileKind::Device {
            block: Some(open), ..
        } => IoPath::Loop(open.dev.clone()),
        FileKind::Proc {
            klog: Some(log), ..
        } => IoPath::ProcKmsg(log.clone()),
        FileKind::Fuse(h) => IoPath::Fuse(super::fuse::Io::of(h)),
        FileKind::FuseDev(_) => IoPath::FuseDev,
        _ => IoPath::Local,
    }
}

/// The host fd of a regular file: the BKL can be released while reading or writing it
/// ([`unlocked_io`]).
/// A regular file opened through an overlay before it was copied up still holds the lower
/// inode's object: reads, fstat, seeks, copies out of it and new memory mappings then switch to
/// the upper one, as 6.1's `ovl_real_fdget` and `ovl_mmap` do, so they see what was changed
/// through the overlay since (a mapping created before copy-up keeps the lower object). The lower
/// object stays open with the file ([`OpenFile::ovl_lower`]): a read without the BKL may still be
/// using it.
pub(super) fn follow_copy_up(cx: &Cx<'_>, file: &FileRef) -> Result<(), Errno> {
    let (o, ino) = match &*file.borrow() {
        OpenFile {
            ovl: Some(o),
            kind: FileKind::Regular { ino, .. },
            ..
        } => (*o, *ino),
        _ => return Ok(()),
    };
    let vfs = cx.vfs()?;
    let real = vfs.overlay().node(o).real();
    if real == ino {
        return Ok(());
    }
    let writable = file.borrow().writable();
    // The copied-up file shares the lower one's object until written (open_store)
    let held = vfs.store().held(real)?;
    let object = vfs.store().open_object(real, writable && !held)?;
    let mut f = file.borrow_mut();
    if let FileKind::Regular { ino, file, cow } = &mut f.kind {
        *ino = real;
        *cow = writable && held;
        let lower = std::mem::replace(file, object);
        f.ovl_lower = Some(lower);
    }
    Ok(())
}

/// Uncopied overlay nodes along the ancestor chain of `nodes` in top-down order (parents before
/// children), so upper-layer inotify watches can be notified after copy-up succeeds.
fn overlay_uncopied_chain(vfs: &Vfs, nodes: &[OvlId]) -> Vec<OvlId> {
    let ovl = vfs.overlay();
    let mut out = Vec::new();
    for &start in nodes {
        let mut chain = Vec::new();
        let mut cur = start;
        loop {
            let n = ovl.node(cur);
            if n.upper.is_some() {
                break;
            }
            chain.push(cur);
            if n.parent == cur {
                break;
            }
            cur = n.parent;
        }
        for id in chain.into_iter().rev() {
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

fn store_dir_flag(vfs: &Vfs, ino: Ino) -> u32 {
    if vfs.store().kind(ino).is_ok_and(|k| k == mode::S_IFDIR) {
        inotify::IN_ISDIR
    } else {
        0
    }
}

/// Reports upper-layer `IN_CREATE` events for overlay nodes that were just copied up.
fn overlay_copy_up_events(k: &Kernel, vfs: &Vfs, copied: &[OvlId]) {
    if copied.is_empty() || !inotify::active(k) {
        return;
    }
    let ovl = vfs.overlay();
    for &id in copied {
        let n = ovl.node(id);
        let Some(up) = n.upper else {
            continue;
        };
        if n.parent == id {
            continue;
        }
        let Some(parent_up) = ovl.node(n.parent).upper else {
            continue;
        };
        inotify::dir_event(
            k,
            parent_up,
            &n.name,
            inotify::IN_CREATE | store_dir_flag(vfs, up),
            0,
        );
    }
}

/// Copies overlay node `o` up ([`Vfs::overlay_upper`]) and returns its upper inode, charging the
/// upper layer's tmpfs instance when it is on tmpfs. A regular file's copy shares the lower file's
/// object until either is written, so nothing may still write that object in place, as for
/// [`try_share`]: when something could (a writable shared mapping of the lower file, the Files app
/// writing it) the data is copied instead, and descriptions of the lower file open for writing
/// move to the shared object read-only, marked `cow` ([`rehome`]).
pub(super) fn copy_up(cx: &Cx<'_>, vfs: &Vfs, o: OvlId, what: CopyUp) -> Result<Ino, Errno> {
    use std::os::unix::fs::MetadataExt;
    let (upper, lower) = {
        let ovl = vfs.overlay();
        let n = ovl.node(o);
        (n.upper, n.real())
    };
    if let Some(up) = upper {
        return Ok(up);
    }
    let k = cx.kr();
    let copied = if inotify::active(k) {
        overlay_uncopied_chain(vfs, &[o])
    } else {
        Vec::new()
    };
    let mut share = what == CopyUp::All && vfs.store().attrs(lower)?.kind() == mode::S_IFREG;
    let actual = if share {
        let host = vfs.store().open_object(lower, false)?;
        let host = host.metadata().map_err(host_errno)?;
        let mapped = k.tasks.values().any(|t| {
            t.res
                .borrow()
                .mm
                .borrow()
                .writably_maps(host.dev(), host.ino())
        });
        if mapped || vfs.store().host_writing(lower)? {
            share = false;
            CopyUp::Copied
        } else {
            CopyUp::All
        }
    } else {
        what
    };
    let up = overlay_upper_charged(vfs, o, actual)?;
    overlay_copy_up_events(k, vfs, &copied);
    if share {
        let writer = |f: &FileRef| {
            f.try_borrow().is_ok_and(|f| {
                f.writable() && matches!(f.kind, FileKind::Regular { cow: false, .. })
            })
        };
        if opens_of(k, lower).iter().any(writer) {
            rehome(k, vfs, lower);
        }
    }
    Ok(up)
}

/// Before regular file `file` is changed (written, truncated to `keep` bytes, given space, mapped
/// shared): a description opened for writing while its file was held gives the file an object of
/// its own first ([`make_private`]). The caller holds no borrow of `file`.
pub(super) fn prepare_write(
    cx: &mut Cx<'_>,
    file: &FileRef,
    keep: Option<u64>,
) -> Result<(), Errno> {
    let ino = match &file.borrow().kind {
        FileKind::Regular { ino, cow: true, .. } => *ino,
        _ => return Ok(()),
    };
    make_private(cx, ino, keep)
}

/// Gives held file `ino` an object of its own ([`Store::unshare`]), copying the data (up to
/// `keep` bytes) with the BKL released, as copy_file_range does: copying a large file would
/// otherwise stop every process for seconds. Meanwhile others wanting to change the file wait
/// for it ([`Kernel::unsharing`](crate::kernel::Kernel::unsharing)). Then every description of
/// the file moves to its object ([`rehome`]).
pub(super) fn make_private(cx: &mut Cx<'_>, ino: Ino, keep: Option<u64>) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    release_deleted_shared(cx.kr(), &vfs);
    let was_held = vfs.store().held(ino).unwrap_or(true);
    loop {
        if cx.kr().unsharing.contains(&ino) {
            cx.wait_on(None, &mut [], crate::kernel::wake::LOCK)?;
            continue;
        }
        let Some(job) = vfs.store().unshare(ino, keep)? else {
            break;
        };
        cx.k().unsharing.insert(ino);
        let copied = cx.unlocked(|| crate::vfs::store::copy_object(&job.from, &job.to, job.len));
        cx.k().unsharing.remove(&ino);
        request_wake_locks();
        if let Err(e) = copied {
            vfs.store().abandon_unshare(job);
            return Err(e);
        }
        // No descriptor acquisition may fail after the store publishes the new identity.
        // Include descriptions opened while the copy ran without the BKL.
        let handles = opens_of(cx.kr(), ino)
            .into_iter()
            .map(|file| {
                let write = file.try_borrow_mut().map_err(|_| Errno::EBUSY)?.writable();
                let object = vfs.store().open_unshare(&job, write)?;
                Ok((file, object))
            })
            .collect::<Result<Vec<_>, Errno>>();
        let handles = match handles {
            Ok(handles) => handles,
            Err(e) => {
                vfs.store().abandon_unshare(job);
                return Err(e);
            }
        };
        match vfs.store().finish_unshare(job) {
            Err(Errno::EAGAIN) => continue,
            r => r?,
        }
        for (handle, object) in handles {
            replace_object(&mut handle.borrow_mut(), object, false);
        }
        vfs.forget_executable(ino);
        return Ok(());
    }
    // Descriptions need new handles only when the file was sharing its object, or when some still
    // hold a read-only one from then: rehoming always would keep every replaced handle open until
    // close, a host fd per description each time a file kept open (a log) is truncated
    let cow = |f: &FileRef| {
        f.try_borrow()
            .is_ok_and(|f| matches!(f.kind, FileKind::Regular { cow: true, .. }))
    };
    if was_held || opens_of(cx.kr(), ino).iter().any(cow) {
        rehome(cx.kr(), &vfs, ino);
    }
    Ok(())
}

/// Store regular file `ino` changed objects, or stopped being held: every description of it
/// takes a handle on its object as it is now, only for reading (and marked `cow`) while the file
/// is held, and the recorded program file of it goes. The old handles stay with the descriptions
/// until they are closed, since a read or write without the BKL may still be using them. A
/// description borrowed at this moment keeps its handle; one opened for writing then fails to
/// write (EBADF, its handle being read-only) rather than writing the shared object, or comes back
/// here before writing when still marked.
fn rehome(k: &crate::kernel::Kernel, vfs: &Vfs, ino: Ino) {
    let store = vfs.store();
    let held = store.held(ino).unwrap_or(true);
    for file in opens_of(k, ino) {
        let Ok(mut f) = file.try_borrow_mut() else {
            crate::debug::log(format_args!("rehome: an open file of inode {ino} is busy"));
            continue;
        };
        let write = f.writable() && !held;
        let Ok(object) = store.open_object(ino, write) else {
            continue;
        };
        replace_object(&mut f, object, held);
    }
    vfs.forget_executable(ino);
}

fn replace_object(f: &mut OpenFile, object: std::fs::File, held: bool) {
    let cow_now = f.writable() && held;
    if let FileKind::Regular { file, cow, .. } = &mut f.kind {
        f.retired.push(std::mem::replace(file, object));
        *cow = cow_now;
    } else if let Some((_, file, writable)) = &mut f.path_object {
        *file = object;
        *writable = false;
    }
}

/// A provider can commit its object switch before its notification reaches this kernel.
/// Check open descriptions against the pinned object before exposing a new store mapping.
pub(super) fn reconcile_mapping(k: &Kernel, ino: Ino, object: &std::fs::File) -> Result<(), Errno> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let current = object.metadata().map_err(host_errno)?;
    for handle in opens_of(k, ino) {
        let mut f = handle.try_borrow_mut().map_err(|_| Errno::EBUSY)?;
        if let Some((_, file, _)) = f.regular_backing() {
            let old = file.metadata().map_err(host_errno)?;
            if matches!(f.kind, FileKind::Regular { cow: true, .. })
                || (old.dev(), old.ino()) != (current.dev(), current.ino())
            {
                let fresh = std::fs::OpenOptions::new()
                    .read(true)
                    .write(f.writable())
                    .open(format!("/proc/self/fd/{}", object.as_raw_fd()))
                    .map_err(host_errno)?;
                replace_object(&mut f, fresh, false);
            }
        }
    }
    Ok(())
}

/// The host (the Files app) gave held regular file `ino` an object of its own as it opened it for
/// writing ([`crate::vfs::browse::open_write`]). Move this kernel's open descriptions to the
/// current object under the BKL.
pub(crate) fn host_unshared(k: &Kernel, ino: Ino) {
    if let Some(vfs) = &k.vfs {
        rehome(k, vfs, ino);
    }
}

/// Every description of store regular file `ino` in this kernel: in fd tables, in AF_UNIX
/// messages in flight and behind loop devices, each once. Those borrowed at this moment (by the
/// caller) are left out.
fn opens_of(k: &crate::kernel::Kernel, ino: Ino) -> Vec<FileRef> {
    let mut all = k.open_files();
    all.extend(crate::unix::inflight_files(k));
    all.extend(k.loops.backing_files());
    let mut out: Vec<FileRef> = Vec::new();
    for f in all {
        let ours = f
            .try_borrow()
            .is_ok_and(|f| f.regular_backing().is_some_and(|(i, ..)| i == ino));
        if ours && !out.iter().any(|o| Rc::ptr_eq(o, &f)) {
            out.push(f);
        }
    }
    out
}

/// The host stores the prefix. Bytes between host EOF and logical EOF are holes.
fn read_sparse_memfd(fd: i32, buf: &mut [u8], pos: u64, logical: u64) -> Result<usize, i32> {
    let physical = appine_hal::fstat(fd)?.st_size as u64;
    let want = buf
        .len()
        .min(physical.max(logical).saturating_sub(pos) as usize);
    let prefix = want.min(physical.saturating_sub(pos) as usize);
    if prefix != 0 {
        let n = appine_hal::pread(fd, &mut buf[..prefix], pos)?;
        if n < prefix {
            return Ok(n);
        }
    }
    buf[prefix..want].fill(0);
    Ok(want)
}

fn regular_size(vfs: &Vfs, ino: Ino, host: &std::fs::File) -> Result<u64, Errno> {
    let host_size = host.metadata().map_err(host_errno)?.len();
    Ok(logical_size(vfs, ino, host_size))
}

fn logical_size(vfs: &Vfs, ino: Ino, host_size: u64) -> u64 {
    host_size.max(vfs.memfd_size(ino).unwrap_or(0))
}

fn regular_fd(f: &OpenFile) -> Option<i32> {
    match &f.kind {
        FileKind::Regular { file, .. } => Some(std::os::fd::AsRawFd::as_raw_fd(file)),
        _ => None,
    }
}

/// Reads or writes a regular file without the BKL: a host pread/pwrite of cold data waits on
/// flash (hundreds of microseconds to milliseconds), and while the lock is held every process's
/// syscalls would have to wait too. With `offset` None the file position is used, and an open
/// file has only one such read or write at a time (Linux's f_pos_lock); others wait for it to
/// finish. `io` is called with the host fd and position while the BKL is released, and must not
/// touch any kernel object; the open file is kept alive by the caller's `file`, whose reference
/// count and borrows are not touched while the BKL is released. `held`: the caller already took
/// the position ([`take_pos`]) and gives it back itself.
fn unlocked_io(
    cx: &mut Cx<'_>,
    file: &FileRef,
    fd: i32,
    (offset, held): (Option<u64>, bool),
    io: impl FnOnce(i32, u64) -> Result<usize, i32> + Send,
) -> Result<usize, Errno> {
    let pos = match offset {
        Some(off) => off,
        None => {
            if !held {
                take_pos(cx, file)?;
            }
            file.borrow().pos
        }
    };
    let r = cx.unlocked(|| io(fd, pos));
    if offset.is_none() {
        if let Ok(n) = r {
            file.borrow_mut().pos = pos + n as u64;
        }
        if !held {
            release_pos(file);
        }
    }
    r.map_err(Errno)
}

/// Whether `f` performs unlocked I/O on its position and must serialize position readers/writers
/// with `pos_busy` (regular files and FUSE files).
fn needs_pos_lock(f: &OpenFile) -> bool {
    matches!(
        f.kind,
        FileKind::Regular { .. }
            | FileKind::Fuse(_)
            | FileKind::Proc {
                node: PseudoNode::Entry(_, _, pseudo::Entry::Mem),
                ..
            }
    )
}

/// RAII guard holding `OpenFile::pos_busy` (Linux's `f_pos_lock`).
pub(super) struct PosGuard(FileRef);

impl PosGuard {
    pub(super) fn lock(cx: &mut Cx<'_>, file: &FileRef) -> Result<PosGuard, Errno> {
        Self::lock_with(cx, file, false)
    }

    pub(super) fn lock_if(
        cx: &mut Cx<'_>,
        file: &FileRef,
        need: bool,
    ) -> Result<Option<PosGuard>, Errno> {
        Self::lock_if_with(cx, file, need, false)
    }

    fn lock_if_with(
        cx: &mut Cx<'_>,
        file: &FileRef,
        need: bool,
        nowait: bool,
    ) -> Result<Option<PosGuard>, Errno> {
        need.then(|| Self::lock_with(cx, file, nowait)).transpose()
    }

    fn lock_positioned(
        cx: &mut Cx<'_>,
        file: &FileRef,
        cond: bool,
        nowait: bool,
    ) -> Result<Option<PosGuard>, Errno> {
        let need = cond && needs_pos_lock(&file.borrow());
        Self::lock_if_with(cx, file, need, nowait)
    }

    fn lock_with(cx: &mut Cx<'_>, file: &FileRef, nowait: bool) -> Result<PosGuard, Errno> {
        take_pos_with(cx, file, nowait)?;
        Ok(PosGuard(file.clone()))
    }
}

impl Drop for PosGuard {
    fn drop(&mut self) {
        release_pos(&self.0);
    }
}

/// RAII guard holding `pos_busy` on up to two files simultaneously without deadlock (waits until
/// neither needed file is busy, then claims both atomically under the BKL).
struct TwoPosGuard {
    first: Option<FileRef>,
    second: Option<FileRef>,
}

impl TwoPosGuard {
    fn lock(
        cx: &mut Cx<'_>,
        (a, need_a): (&FileRef, bool),
        (b, need_b): (&FileRef, bool),
    ) -> Result<TwoPosGuard, Errno> {
        let same = Rc::ptr_eq(a, b);
        let need_b = need_b && !(same && need_a);
        let busy = |f: &FileRef, need: bool| need && f.borrow().pos_busy != 0;
        while busy(a, need_a) || busy(b, need_b) {
            if cx.task.killed.get() {
                return Err(Errno::EINTR);
            }
            if busy(a, need_a) {
                a.borrow_mut().pos_busy = 2;
            }
            if busy(b, need_b) {
                b.borrow_mut().pos_busy = 2;
            }
            cx.wait_on(None, &mut [], crate::kernel::wake::LOCK)?;
        }
        if need_a {
            a.borrow_mut().pos_busy = 1;
        }
        if need_b {
            b.borrow_mut().pos_busy = 1;
        }
        Ok(TwoPosGuard {
            first: need_a.then(|| a.clone()),
            second: need_b.then(|| b.clone()),
        })
    }
}

impl Drop for TwoPosGuard {
    fn drop(&mut self) {
        if let Some(f) = self.first.take() {
            release_pos(&f);
        }
        if let Some(f) = self.second.take() {
            release_pos(&f);
        }
    }
}

/// Takes `file`'s position for one read, write or seek by position (Linux's `f_pos_lock`), waiting
/// while another has it; [`release_pos`] gives it back.
fn take_pos(cx: &mut Cx<'_>, file: &FileRef) -> Result<(), Errno> {
    take_pos_with(cx, file, false)
}

fn take_pos_with(cx: &mut Cx<'_>, file: &FileRef, nowait: bool) -> Result<(), Errno> {
    while file.borrow().pos_busy != 0 {
        if nowait {
            return Err(Errno::EAGAIN);
        }
        if cx.task.killed.get() {
            return Err(Errno::EINTR);
        }
        file.borrow_mut().pos_busy = 2;
        cx.wait_on(None, &mut [], crate::kernel::wake::LOCK)?;
    }
    file.borrow_mut().pos_busy = 1;
    Ok(())
}

fn release_pos(file: &FileRef) {
    if std::mem::take(&mut file.borrow_mut().pos_busy) == 2 {
        request_wake_locks();
    }
}

// ---- Directories ----

/// getdents64 (Linux's `iterate_dir` and `filldir64`): `O_PATH` descriptors are not found
/// (`EBADF`); a removed directory is `ENOENT`; the count is an int, so one above `INT_MAX` fits no
/// entry (`EINVAL`); entries are copied one by one, so a buffer running into memory that cannot be
/// written returns the whole entries before it (`EFAULT` when there are none).
pub(super) fn getdents64(cx: &mut Cx<'_>, fd: i32, buf: u64, count: usize) -> SysResult {
    let file = cx.fds().get(fd)?;
    if file.borrow().flags & oflags::O_PATH == 0 {
        super::fuse::fill_dir(cx, &file)?;
    }
    let mut f = file.borrow_mut();
    if f.flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    let OpenFile {
        kind, pos, flags, ..
    } = &mut *f;
    let FileKind::Directory { node, entries, .. } = kind else {
        return Err(Errno::ENOTDIR);
    };
    if let Node::Store(mnt, ino) = node {
        let vfs = cx.vfs()?;
        if vfs.store().attrs(*ino)?.nlink == 0 {
            return Err(Errno::ENOENT);
        }
        if *flags & oflags::O_NOATIME == 0 {
            vfs.accessed(*mnt, *ino, None);
        }
    }
    let count = count as u32 as usize;
    if entries.is_none() {
        let vfs = cx.vfs()?;
        let view = cx.view(&vfs);
        let ino_of = |n: &Node| match n {
            Node::Store(_, i) => Ok(*i),
            Node::Pseudo(_, p) => Ok(pseudo::node_ino(p)),
            Node::Overlay(_, o) => vfs.overlay_stat(*o).map(|st| st.ino),
            Node::Fuse(_, f) => Ok(vfs.fuse().get(*f).map_or(0, |n| n.attr.ino)),
        };
        let parent = vfs.parent(&view, node)?;
        let mut list = vec![
            DirEntry {
                name: b".".to_vec(),
                ino: ino_of(node)?,
                mode: mode::S_IFDIR,
            },
            DirEntry {
                name: b"..".to_vec(),
                ino: ino_of(&parent)?,
                mode: mode::S_IFDIR,
            },
        ];
        match node {
            Node::Store(_, ino) => list.extend(vfs.store().readdir(*ino)?),
            Node::Pseudo(id, p) => list.extend(pseudo::readdir(&view, *id, p)?),
            Node::Overlay(_, o) => list.extend(vfs.overlay_readdir(*o)?),
            // Listed by fill_dir, unless the daemon's directory went away
            Node::Fuse(..) => return Err(Errno::ENOTCONN),
        }
        *entries = Some(list);
    }
    let list = entries.as_ref().unwrap();
    let mut out = Vec::new();
    let mut next = *pos as usize;
    if next < list.len() && count > i32::MAX as usize {
        return Err(Errno::EINVAL);
    }
    // Where each entry ends in `out`
    let mut ends = Vec::new();
    while let Some(e) = list.get(next) {
        // struct linux_dirent64: d_ino, d_off, d_reclen, d_type, d_name, aligned to 8 bytes
        let reclen = (19 + e.name.len() + 1).next_multiple_of(8);
        if out.len() + reclen > count {
            break;
        }
        let start = out.len();
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&(next as u64 + 1).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push((e.mode >> 12) as u8 & 0xf); // DT_* is just S_IFMT >> 12
        out.extend_from_slice(&e.name);
        out.resize(start + reclen, 0);
        ends.push(out.len());
        next += 1;
    }
    if out.is_empty() && next < list.len() {
        return Err(Errno::EINVAL);
    }
    let written = cx.write_user_partial(buf, &out);
    if written < out.len() {
        let whole = ends.iter().take_while(|&&end| end <= written).count();
        if whole == 0 {
            return Err(Errno::EFAULT);
        }
        next -= ends.len() - whole;
        out.truncate(ends[whole - 1]);
    }
    *pos = next as u64;
    inotify::file_io_event(cx.kr(), &f, inotify::IN_ACCESS);
    Ok(out.len() as u64)
}

pub(super) fn lseek(cx: &mut Cx<'_>, fd: i32, offset: i64, whence: u32) -> SysResult {
    let file = cx.fds().get(fd)?;
    if matches!(
        file.borrow().kind,
        FileKind::Fuse(_) | FileKind::Directory { fuse: Some(_), .. }
    ) {
        return super::fuse::lseek(cx, &file, offset, whence);
    }
    follow_copy_up(cx, &file)?;
    // Serialize regular-file seeks against unlocked I/O using pos_busy (Linux's f_pos_lock)
    let positioned = needs_pos_lock(&file.borrow());
    let _pos = PosGuard::lock_if(cx, &file, positioned)?;
    let mut f = file.borrow_mut();
    let OpenFile { kind, pos, .. } = &mut *f;
    let base = match kind {
        FileKind::Host(fd) => return appine_hal::lseek(*fd, offset, whence as i32).map_err(Errno),
        FileKind::Path(_) => return Err(Errno::EBADF),
        FileKind::Pipe(_)
        | FileKind::Pty(_)
        | FileKind::Socket(_)
        | FileKind::Epoll(_)
        | FileKind::EventFd(_)
        | FileKind::TimerFd(_)
        | FileKind::SignalFd(_)
        | FileKind::Inotify(_)
        | FileKind::Pidfd(_)
        | FileKind::SeccompNotify(_)
        | FileKind::FuseDev(_)
        | FileKind::Bpf(_) => return Err(Errno::ESPIPE),
        FileKind::Fuse(_) => return Err(Errno::EBADF),
        FileKind::Proc { data, .. } => match whence {
            SEEK_SET => 0,
            SEEK_CUR => *pos as i64,
            SEEK_END => data.len() as i64,
            _ => return Err(Errno::EINVAL),
        },
        FileKind::MessageQueue(q) => match whence {
            SEEK_SET => 0,
            SEEK_CUR => *pos as i64,
            SEEK_END => q.borrow().status().len() as i64,
            _ => return Err(Errno::EINVAL),
        },
        // /dev/kmsg seeks by record (`devkmsg_llseek`): the offset can only be 0; SEEK_SET goes
        // to the oldest record, SEEK_DATA to the first one after syslog last cleared (after
        // `dmesg -c`), SEEK_END to the next one; the file position is unchanged and 0 is returned
        FileKind::Device {
            kmsg: Some(user), ..
        } => {
            if offset != 0 {
                return Err(Errno::ESPIPE);
            }
            let log = user.log.borrow();
            user.seq = match whence {
                SEEK_SET => log.first_seq(),
                SEEK_DATA => log.clear_seq(),
                SEEK_END => log.next_seq(),
                _ => return Err(Errno::EINVAL),
            };
            return Ok(0);
        }
        FileKind::Device {
            block: Some(open), ..
        } => return super::loopdev::seek(&open.dev, pos, offset, whence),
        // As with Linux's /dev/null and the like, seek always succeeds and stays at 0
        FileKind::Render { .. } | FileKind::GpuFence(_) => return Err(Errno::ESPIPE),
        FileKind::Device { .. } => return Ok(0),
        FileKind::Directory { entries, node, .. } => {
            // Where SEEK_END and SEEK_DATA/SEEK_HOLE count from: store directories stand in for
            // ext4's, whose hashed directories end at the largest position (ext4_dir_llseek);
            // procfs, sysfs and cgroup2 ones are of size 0 (generic_file_llseek); tmpfs, devpts
            // and mqueue directories take only SEEK_SET and SEEK_CUR (dcache_dir_lseek)
            let eof = match cx.vfs()?.fs_of(node) {
                Fs::Store => Some(i64::MAX),
                Fs::Proc | Fs::Sys | Fs::Cgroup => Some(0),
                _ => None,
            };
            let new = match (whence, eof) {
                (SEEK_SET, _) => offset,
                (SEEK_CUR, _) => (*pos as i64).checked_add(offset).ok_or(Errno::EINVAL)?,
                (SEEK_END, Some(eof)) => eof.checked_add(offset).ok_or(Errno::EINVAL)?,
                (SEEK_DATA | SEEK_HOLE, Some(eof)) if offset as u64 >= eof as u64 => {
                    return Err(Errno::ENXIO);
                }
                (SEEK_DATA, Some(_)) => offset,
                (SEEK_HOLE, Some(eof)) => eof,
                _ => return Err(Errno::EINVAL),
            };
            if new < 0 {
                return Err(Errno::EINVAL);
            }
            if new == 0 {
                *entries = None;
            }
            *pos = new as u64;
            return Ok(new as u64);
        }
        FileKind::Regular { ino, file, .. } => {
            let host_size = file.metadata().map_err(host_errno)?.len();
            let vfs = cx.vfs()?;
            let size = logical_size(&vfs, *ino, host_size) as i64;
            match whence {
                SEEK_SET => 0,
                SEEK_CUR => *pos as i64,
                SEEK_END => size,
                SEEK_DATA | SEEK_HOLE if offset < 0 || offset >= size => {
                    return Err(Errno::ENXIO);
                }
                SEEK_DATA if offset as u64 >= host_size => return Err(Errno::ENXIO),
                SEEK_HOLE if offset as u64 >= host_size => {
                    *pos = offset as u64;
                    return Ok(*pos);
                }
                SEEK_DATA | SEEK_HOLE => {
                    let fd = std::os::fd::AsRawFd::as_raw_fd(file);
                    *pos =
                        vfs.seek_data_or_hole(*ino, fd, offset as u64, host_size, whence as i32)?;
                    return Ok(*pos);
                }
                _ => return Err(Errno::EINVAL),
            }
        }
    };
    let new = base
        .checked_add(offset)
        .filter(|&v| v >= 0)
        .ok_or(Errno::EINVAL)?;
    *pos = new as u64;
    Ok(new as u64)
}

// ---- Cache hints and syncing ----

/// posix_fadvise: affects only performance; ignored after the arguments are checked.
/// Matches Linux's `ksys_fadvise64_64` (`fdget`): `O_PATH` descriptors fail with EBADF before
/// pipe/socket or argument checks.
pub(super) fn fadvise64(cx: &mut Cx<'_>, fd: i32, len: i64, advice: i32) -> SysResult {
    let file = io_file(cx, fd)?;
    if matches!(file.borrow().kind, FileKind::Pipe(_) | FileKind::Socket(_)) {
        return Err(Errno::ESPIPE);
    }
    if len < 0 || !(0..=5).contains(&advice) {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}

/// sync_file_range, readahead, syncfs: mostly argument checks (data is written straight into the
/// host file, and reads are cached by the host too). sync_file_range with flags on a regular file
/// is passed to the host object with the BKL released; syncfs's flush is [`sync`], called after
/// this. `kind` tells the three apart: 0 is sync_file_range, 1 readahead, 2 syncfs.
pub(super) fn cache_hint(
    cx: &mut Cx<'_>,
    fd: i32,
    offset: i64,
    len: i64,
    flags: u32,
    kind: u32,
) -> SysResult {
    let file = cx.fds().get(fd)?;
    let f = file.borrow();
    match kind {
        0 => {
            if matches!(f.kind, FileKind::Path(_)) {
                return Err(Errno::EBADF);
            }
            if flags & !7 != 0 || offset < 0 || len < 0 || offset.checked_add(len).is_none() {
                return Err(Errno::EINVAL);
            }
            match &f.kind {
                // Handed to the host object: tools like dpkg first start writeback for a batch of
                // files and then fsync them one by one, merged into one journal commit. The open
                // file is kept alive by file and not touched while the BKL is released
                FileKind::Regular { file: host, .. } if flags != 0 => {
                    let fd = std::os::fd::AsRawFd::as_raw_fd(host);
                    drop(f);
                    cx.unlocked(|| appine_hal::sync_file_range(fd, offset, len, flags))
                        .map(|()| 0)
                        .map_err(Errno)
                }
                FileKind::Device {
                    block: Some(open), ..
                } if flags != 0 => {
                    let target = super::loopdev::sync_range(&open.dev, offset, len);
                    drop(f);
                    match target {
                        Some((_keep, fd, off, n)) => cx
                            .unlocked(|| appine_hal::sync_file_range(fd, off, n, flags))
                            .map(|()| 0)
                            .map_err(Errno),
                        None => Ok(0),
                    }
                }
                FileKind::Regular { .. }
                | FileKind::Directory { .. }
                | FileKind::Device { block: Some(_), .. } => Ok(0),
                _ => Err(Errno::ESPIPE),
            }
        }
        1 => match &f.kind {
            _ if !f.readable() => Err(Errno::EBADF),
            FileKind::Regular { .. } if offset >= 0 => Ok(0),
            _ => Err(Errno::EINVAL),
        },
        _ => Ok(0),
    }
}

/// cachestat (Linux 6.5): the state of a file in the page cache. Files in the store look at the
/// host file's page cache ([`appine_hal::cachestat`], only the number of pages in the cache);
/// other files have no page cache and get all 0s.
pub(super) fn cachestat(cx: &mut Cx<'_>, fd: i32, range: u64, out: u64, flags: u32) -> SysResult {
    let file = cx.fds().get(fd)?;
    if matches!(file.borrow().kind, FileKind::Path(_)) {
        return Err(Errno::EBADF);
    }
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let r: [u8; 16] = get(cx, range)?;
    let off = u64::from_le_bytes(r[..8].try_into().unwrap());
    let len = u64::from_le_bytes(r[8..].try_into().unwrap());
    let stats = match &file.borrow().kind {
        FileKind::Regular { file, .. } => {
            appine_hal::cachestat(std::os::fd::AsRawFd::as_raw_fd(file), off, len).map_err(Errno)?
        }
        _ => [0; 5],
    };
    let mut b = [0u8; 40];
    for (i, n) in stats.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&n.to_le_bytes());
    }
    put(cx, out, b).map(|()| 0)
}

/// fsync(2), fdatasync(2) (`data_only`): a regular file's data is in its host object, so the host
/// is asked to flush it to disk; metadata (names, permissions...) is in the store's database, so
/// the deferred write transaction is committed and then the WAL is awaited on disk
/// ([`durable`]). The BKL is released while flushing.
pub(super) fn fsync(cx: &mut Cx<'_>, fd: i32, data_only: bool) -> SysResult {
    let mut file = cx.fds().get(fd)?;
    if file.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    if !has_fsync(&file.borrow()) {
        return Err(Errno::EINVAL);
    }
    if let Some((io, dir)) = super::fuse::io_of(&file) {
        return super::fuse::fsync(cx, &io, dir, data_only).map(|()| 0);
    }
    // A loop device flushes by syncing its backing file, which may be another loop device
    loop {
        let next = match &file.borrow().kind {
            FileKind::Device {
                block: Some(open), ..
            } => match super::loopdev::flush_target(&open.dev) {
                Some(backing) => backing,
                None => return Ok(0),
            },
            _ => break,
        };
        file = next;
    }
    let host = {
        let f = file.borrow();
        match &f.kind {
            // A regular file syncs its host object; a directory has only the store's metadata
            // (host fds are left to the host)
            FileKind::Regular { file, .. } => Some(std::os::fd::AsRawFd::as_raw_fd(file)),
            FileKind::Host(_) => return Ok(0),
            _ => None,
        }
    };
    // The open file is kept alive by file and not touched while the BKL is released
    if let Some(fd) = host {
        cx.unlocked(|| appine_hal::fsync(fd, data_only))
            .map_err(Errno)?;
    }
    durable(cx, false)
}

/// Whether a file can be synced, which on Linux is having an fsync operation: regular files,
/// directories, loop devices and host fds (left to the host). For anything else fsync is EINVAL
/// (vfs_fsync_range), and so is submitting an AIO fsync of it (aio_fsync).
pub(super) fn has_fsync(f: &OpenFile) -> bool {
    matches!(
        f.kind,
        FileKind::Regular { .. }
            | FileKind::Directory { .. }
            | FileKind::Host(_)
            | FileKind::Fuse(_)
            | FileKind::Device { block: Some(_), .. }
    )
}

/// sync(2): commits the deferred write transaction and writes the whole host filesystem holding
/// the store to disk.
pub(super) fn sync(cx: &mut Cx<'_>) -> SysResult {
    durable(cx, true)
}

/// Commits the store's deferred write transaction and waits for it to reach disk
/// ([`Store::commit`] only writes into the WAL): with `all`, syncfs the whole host filesystem
/// together with the data of all objects, otherwise wait only for the WAL. Waits with the BKL
/// released.
fn durable(cx: &mut Cx<'_>, all: bool) -> SysResult {
    let Ok(vfs) = cx.vfs() else {
        return Ok(0);
    };
    let store = vfs.store();
    store.commit()?;
    let meta = store.meta().clone();
    drop(vfs);
    cx.unlocked(move || {
        if all {
            meta.sync_all()
        } else {
            meta.sync_metadata()
        }
    })?;
    Ok(0)
}

// ---- Metadata ----

pub(super) fn faccessat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    amode: u32,
    flags: u32,
) -> SysResult {
    if amode & !7 != 0 || flags & !(AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, path)?;
    // By default checks use the real user ID (including search permission along the path), and
    // with AT_EACCESS the effective user ID
    let cred = if flags & AT_EACCESS != 0 {
        cx.cred()
    } else {
        cx.cred().for_access()
    };
    let node = lookup_at_or_fd(
        cx,
        &cred,
        dirfd,
        &path,
        flags,
        flags & AT_SYMLINK_NOFOLLOW == 0,
    )?;
    if let Node::Fuse(_, f) = node {
        let vfs = cx.vfs()?;
        let kind = vfs.kind(&cx.view(&vfs), &node)?;
        if access_noexec(&vfs, &node, amode, kind) {
            return Err(Errno::EACCES);
        }
        super::fuse::access(cx, &vfs, &cred, f, amode)?;
        if amode & MAY_WRITE != 0
            && matches!(kind, mode::S_IFREG | mode::S_IFDIR | mode::S_IFLNK)
            && vfs.readonly(&node)
        {
            return Err(Errno::EROFS);
        }
        return Ok(0);
    }
    if amode == 0 {
        return Ok(0);
    }
    let mut flags = None;
    let (b, _) = node_stat(cx, &node, &mut flags)?;
    let word = |off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
    let st = Stat {
        mode: word(16),
        uid: word(24),
        gid: word(28),
        ..Stat::default()
    };
    // Asking whether a regular file on a noexec mount can be executed is EACCES (Linux's
    // do_faccessat path_noexec check; memfds live on an internal tmpfs and ignore noexec)
    let is_memfd = matches!(node, Node::Store(_, ino) if cx.kr().seals.contains_key(&ino));
    if !is_memfd && access_noexec(&*cx.vfs()?, &node, amode, st.mode & mode::S_IFMT) {
        return Err(Errno::EACCES);
    }
    if amode & MAY_WRITE != 0 {
        reject_flags(flags.unwrap_or(0), inode_flags::IMMUTABLE)?;
    }
    // R_OK, W_OK, X_OK have the same values as MAY_READ, MAY_WRITE, MAY_EXEC
    cred.permission(&st, amode)?;
    // Asking whether a regular file, directory or symlink in a read-only mount can be written is
    // EROFS (after the permission check)
    let special = !matches!(
        st.mode & mode::S_IFMT,
        mode::S_IFREG | mode::S_IFDIR | mode::S_IFLNK
    );
    if amode & MAY_WRITE != 0 && !special && cx.vfs()?.readonly(&node) {
        return Err(Errno::EROFS);
    }
    Ok(0)
}

pub(super) fn chdir(cx: &mut Cx<'_>, path: u64) -> SysResult {
    let path = read_path(cx, path)?;
    let node = lookup_at(cx, AT_FDCWD, &path, true)?;
    set_cwd(cx, node)
}

pub(super) fn fchdir(cx: &mut Cx<'_>, fd: i32) -> SysResult {
    let node = cx.fds().get(fd)?.borrow().node().ok_or(Errno::ENOTDIR)?;
    set_cwd(cx, node)
}

/// chdir, fchdir: the target must be a searchable directory.
fn set_cwd(cx: &mut Cx<'_>, node: Node) -> SysResult {
    let vfs = cx.vfs()?;
    if !vfs.is_dir(&cx.view(&vfs), &node)? {
        return Err(Errno::ENOTDIR);
    }
    if let Some(st) = searched_attrs(&vfs, &cx.view(&vfs), &node)? {
        cx.cred().permission(&st, MAY_EXEC)?;
    }
    if let Node::Fuse(_, f) = node {
        let cred = cx.cred();
        super::fuse::may_chdir(cx, &vfs, &cred, f)?;
    }
    cx.t.fs.borrow_mut().set_cwd(node);
    if vfs.has_removed_dirs() {
        vfs.prune_removed_dirs(&used_store_dirs(cx));
    }
    cx.shared.fast_changed();
    Ok(0)
}

/// The attributes chdir and chroot check search permission on: a store directory's, or those of
/// the store directory behind an overlay one; for synthetic directories what their view says
/// ([`Pseudo::searched`]: cgroup directories; the others are always searchable).
fn searched_attrs(vfs: &Vfs, view: &dyn Pseudo, node: &Node) -> Result<Option<Stat>, Errno> {
    Ok(match node {
        Node::Store(_, ino) => Some(vfs.store().attrs(*ino)?),
        Node::Overlay(_, o) => Some(vfs.store().attrs(vfs.overlay().node(*o).real())?),
        Node::Pseudo(_, p) => view.searched(p),
        // Checked by the daemon or on its attributes ([`super::fuse::may_chdir`])
        Node::Fuse(..) => None,
    })
}

/// chroot: the target must be a searchable directory; requires `CAP_SYS_CHROOT`. The current
/// directory is unchanged (it may be outside the new root, as on Linux).
pub(super) fn chroot(cx: &mut Cx<'_>, path: u64) -> SysResult {
    let path = read_path(cx, path)?;
    let node = lookup_at(cx, AT_FDCWD, &path, true)?;
    let vfs = cx.vfs()?;
    if !vfs.is_dir(&cx.view(&vfs), &node)? {
        return Err(Errno::ENOTDIR);
    }
    let cred = cx.cred();
    if let Some(st) = searched_attrs(&vfs, &cx.view(&vfs), &node)? {
        cred.permission(&st, MAY_EXEC)?;
    }
    if let Node::Fuse(_, f) = node {
        super::fuse::may_chdir(cx, &vfs, &cred, f)?;
    }
    if !cred.capable_here(cap::SYS_CHROOT) {
        return Err(Errno::EPERM);
    }
    cx.t.fs.borrow_mut().set_root(node);
    if vfs.has_removed_dirs() {
        vfs.prune_removed_dirs(&used_store_dirs(cx));
    }
    cx.shared.fast_changed();
    Ok(0)
}

pub(super) fn getcwd(cx: &mut Cx<'_>, buf: u64, size: u64) -> SysResult {
    let vfs = cx.vfs()?;
    let (path, reached) = vfs.reach(&cx.view(&vfs), &cx.root(), &cx.cwd())?;
    // As on Linux, when the current directory is not under the root the path starts with
    // (unreachable) (musl and glibc treat it as ENOENT)
    let mut path = if reached {
        path
    } else {
        [&b"(unreachable)"[..], &path].concat()
    };
    path.push(0);
    if (size as usize) < path.len() {
        return Err(Errno::ERANGE);
    }
    cx.mm().write(UserSlice::new(buf, path.len()), &path)?;
    Ok(path.len() as u64)
}

pub(super) fn readlinkat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    buf: u64,
    size: usize,
) -> SysResult {
    if size as isize <= 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, path)?;
    // An empty path reads dirfd itself (a symlink opened with O_PATH | O_NOFOLLOW), and
    // `AT_FDCWD` is the current directory; when it is not a symlink it is ENOENT (Linux's
    // do_readlinkat: `empty ? -ENOENT : -EINVAL`)
    let empty = path.is_empty();
    let node = if !empty {
        lookup_at(cx, dirfd, &path, false)?
    } else if dirfd == AT_FDCWD {
        cx.cwd()
    } else {
        cx.fds().get(dirfd)?.borrow().node().ok_or(Errno::ENOENT)?
    };
    let vfs = cx.vfs()?;
    let target = match vfs.readlink(&cx.view(&vfs), &node) {
        Err(e) if empty && e == Errno::EINVAL => return Err(Errno::ENOENT),
        r => r?,
    };
    let n = target.len().min(size);
    cx.mm().write(UserSlice::new(buf, n), &target[..n])?;
    Ok(n as u64)
}

pub(super) fn newfstatat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    buf: u64,
    flags: u32,
) -> SysResult {
    newfstatat_flags(flags)?;
    let path = read_path(cx, path)?;
    let (st, _) = stat_at(cx, dirfd, &path, flags, &mut None)?;
    put(cx, buf, st).map(|()| 0)
}

/// Linux 6.1's vfs_fstatat accepts all sync bits through vfs_statx. Only the statx syscall
/// rejects the combination of AT_STATX_FORCE_SYNC and AT_STATX_DONT_SYNC.
pub(super) fn newfstatat_flags(flags: u32) -> Result<(), Errno> {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE) != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

pub(super) fn statx(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    flags: u32,
    mask: u32,
    buf: u64,
) -> SysResult {
    let flags = statx_flags(flags, mask)?;
    let path = read_path(cx, path)?;
    let mut attrs = None;
    let (st, mnt_id) = stat_at(cx, dirfd, &path, flags, &mut attrs)?;
    put(cx, buf, encode_statx_attrs(&st, mnt_id, attrs)).map(|()| 0)
}

/// The `flags` and `mask` checks of statx; returns the flags for [`stat_at`].
pub(super) fn statx_flags(flags: u32, mask: u32) -> Result<u32, Errno> {
    const STATX_RESERVED: u32 = 0x8000_0000;
    newfstatat_flags(flags)?;
    if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE || mask & STATX_RESERVED != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(flags & (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
}

/// Builds a `struct statx` from a `struct stat`: always gives all the basic fields
/// (`STATX_BASIC_STATS`) and `STATX_MNT_ID` and `stx_mnt_id`
/// (Linux 6.1's `vfs_statx`), with no creation time.
pub(super) fn encode_statx(st: &[u8; 128], mnt_id: MountId) -> [u8; 256] {
    // The cached walker only resolves store nodes and falls back for visible inode flags.
    encode_statx_attrs(st, mnt_id, Some(0))
}

fn encode_statx_attrs(st: &[u8; 128], mnt_id: MountId, attrs: Option<u32>) -> [u8; 256] {
    const STATX_BASIC_STATS: u32 = 0x7ff;
    const STATX_MNT_ID: u32 = 0x1000;
    let u32_at = |o: usize| u32::from_le_bytes(st[o..o + 4].try_into().unwrap());
    let u64_at = |o: usize| u64::from_le_bytes(st[o..o + 8].try_into().unwrap());
    // glibc's and musl's major()/minor()
    let major = |d: u64| (((d >> 8) & 0xfff) | ((d >> 32) & !0xfff)) as u32;
    let minor = |d: u64| ((d & 0xff) | ((d >> 12) & !0xff)) as u32;
    let mut b = [0u8; 256];
    let mut put = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
    let mask = STATX_BASIC_STATS | STATX_MNT_ID;
    put(0, &mask.to_le_bytes());
    if let Some(flags) = attrs {
        put(8, &u64::from(flags & inode_flags::STATX).to_le_bytes());
        put(56, &u64::from(inode_flags::STATX).to_le_bytes());
    }
    put(4, &u32_at(56).to_le_bytes()); // blksize
    put(16, &u32_at(20).to_le_bytes()); // nlink
    put(20, &u32_at(24).to_le_bytes()); // uid
    put(24, &u32_at(28).to_le_bytes()); // gid
    put(28, &(u32_at(16) as u16).to_le_bytes()); // mode
    put(32, &u64_at(8).to_le_bytes()); // ino
    put(40, &u64_at(48).to_le_bytes()); // size
    put(48, &u64_at(64).to_le_bytes()); // blocks
    // atime, ctime, mtime: seconds and nanoseconds (statx_timestamp is i64 + u32 + reserved)
    for (dst, src) in [(64, 72), (96, 104), (112, 88)] {
        put(dst, &u64_at(src).to_le_bytes());
        put(dst + 8, &(u64_at(src + 8) as u32).to_le_bytes());
    }
    let (rdev, dev) = (u64_at(32), u64_at(0));
    put(128, &major(rdev).to_le_bytes());
    put(132, &minor(rdev).to_le_bytes());
    put(136, &major(dev).to_le_bytes());
    put(140, &minor(dev).to_le_bytes());
    put(144, &u64::from(mnt_id).to_le_bytes());
    b
}

/// Resolves the stat and mount together in one snapshot. Magic links take both from their target.
fn stat_at(
    cx: &Cx<'_>,
    dirfd: i32,
    path: &[u8],
    flags: u32,
    inode_flags: &mut Option<u32>,
) -> Result<([u8; 128], MountId), Errno> {
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 && dirfd != AT_FDCWD {
        let file = cx.fds().get(dirfd)?;
        let st = file_stat_attrs(cx, &file, inode_flags)?;
        Ok((owner_out(cx, st), file.borrow().mnt_id()))
    } else {
        // Resolution and fetching the attributes share one read transaction (which really starts
        // only on a cache miss)
        let vfs = cx.vfs()?;
        vfs.store().snapshot(|_| {
            let cred = cx.cred();
            let node = lookup_at_or_fd(
                cx,
                &cred,
                dirfd,
                path,
                flags,
                flags & AT_SYMLINK_NOFOLLOW == 0,
            )?;
            let (st, mnt) = node_stat(cx, &node, inode_flags)?;
            Ok((owner_out(cx, st), mnt))
        })
    }
}

pub(super) fn fstat(cx: &mut Cx<'_>, fd: i32, buf: u64) -> SysResult {
    let st = owner_out(cx, file_stat(cx, &cx.fds().get(fd)?)?);
    put(cx, buf, st).map(|()| 0)
}

/// Turns the owner and group in a stat result into those in the caller's user namespace (65534
/// when they do not map).
fn owner_out(cx: &Cx<'_>, mut st: [u8; 128]) -> [u8; 128] {
    let cred = cx.cred();
    if cred.user_ns.level > 0 {
        let word =
            |b: &[u8; 128], off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        let (uid, gid) = (cred.uid_out(word(&st, 24)), cred.gid_out(word(&st, 28)));
        st[24..28].copy_from_slice(&uid.to_le_bytes());
        st[28..32].copy_from_slice(&gid.to_le_bytes());
    }
    st
}

pub(super) fn statfs(cx: &mut Cx<'_>, path: u64, buf: u64) -> SysResult {
    let path = read_path(cx, path)?;
    let node = lookup_at(cx, AT_FDCWD, &path, true)?;
    let b = statfs_of(cx, &node)?;
    put(cx, buf, b).map(|()| 0)
}

pub(super) fn fstatfs(cx: &mut Cx<'_>, fd: i32, buf: u64) -> SysResult {
    let file = cx.fds().get(fd)?;
    let (pipe, node) = {
        let f = file.borrow();
        (matches!(f.kind, FileKind::Pipe(_)), f.node())
    };
    // Message queue fds are in the mqueue filesystem
    if matches!(file.borrow().kind, FileKind::MessageQueue(_)) {
        let empty = appine_hal::FsStats {
            block_size: 4096,
            ..Default::default()
        };
        return put(cx, buf, encode_statfs(MQUEUE_MAGIC, &empty, 0)).map(|()| 0);
    }
    let b = match (pipe, node) {
        // Named FIFOs belong to the filesystem that holds their inode; only anonymous pipes live
        // in pipefs.
        (_, Some(node)) => statfs_of(cx, &node)?,
        (true, None) => encode_statfs(
            PIPEFS_MAGIC,
            &appine_hal::FsStats {
                block_size: 4096,
                ..Default::default()
            },
            0,
        ),
        (false, None) => statfs_of(cx, &Node::ROOT)?,
    };
    put(cx, buf, b).map(|()| 0)
}

/// statfs of the filesystem a node is in.
fn statfs_of(cx: &mut Cx<'_>, node: &Node) -> Result<[u8; 120], Errno> {
    let empty = appine_hal::FsStats {
        block_size: 4096,
        ..Default::default()
    };
    let vfs = cx.vfs()?;
    // The mount's flags plus the filesystem's read-only, sync and mand ones (Linux's flags_by_mnt
    // and flags_by_sb)
    let sb = vfs.mount(node.mnt()).map_or(0, |m| vfs.sb_flags(&m));
    let flags = vfs.mount_flags(node).unwrap_or(0)
        | if vfs.readonly(node) { ms::RDONLY } else { 0 }
        | sb & (ms::SYNCHRONOUS | ms::MANDLOCK);
    // tmpfs reports by pages and inodes (Linux's shmem_statfs): an unlimited item is all 0s;
    // usage is counted afresh
    if let Some(dev) = vfs.tmpfs_dev(node) {
        evict_unlinked_tmpfs(cx.kr(), &vfs);
        let (p, pages, inodes) = vfs.tmpfs_usage(dev, true)?;
        let free = p.blocks.saturating_sub(pages);
        let s = appine_hal::FsStats {
            block_size: TMPFS_PAGE,
            blocks: p.blocks,
            free,
            available: free,
            files: p.inodes,
            files_free: p.inodes.saturating_sub(inodes),
        };
        return Ok(encode_statfs(TMPFS_MAGIC, &s, flags));
    }
    if let Node::Fuse(_, f) = node {
        let words = super::fuse::statfs(cx, &vfs, *f, statfs_flags(flags))?;
        let mut b = [0u8; 120];
        for (i, w) in words.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        return Ok(b);
    }
    Ok(match node {
        Node::Store(..) => encode_statfs(EXT4_SUPER_MAGIC, &vfs.store().fs_stats()?, flags),
        // The capacity of the filesystem the layers are in (Linux's ovl_statfs asks the upper
        // layer's, or the topmost lower one's)
        Node::Overlay(..) => encode_statfs(OVERLAYFS_SUPER_MAGIC, &vfs.store().fs_stats()?, flags),
        Node::Pseudo(_, PseudoNode::NsFile(..)) => encode_statfs(NSFS_MAGIC, &empty, 0),
        Node::Pseudo(_, p) => {
            let magic = match pseudo::fs_of(p) {
                Fs::Store => EXT4_SUPER_MAGIC,
                Fs::Tmpfs => TMPFS_MAGIC,
                Fs::Proc => PROC_SUPER_MAGIC,
                Fs::Pts => DEVPTS_SUPER_MAGIC,
                Fs::Sys => SYSFS_MAGIC,
                Fs::Cgroup => CGROUP2_SUPER_MAGIC,
                Fs::Nsfs => NSFS_MAGIC,
                Fs::Mqueue => MQUEUE_MAGIC,
                Fs::Overlay => OVERLAYFS_SUPER_MAGIC,
                Fs::Fuse => crate::vfs::fuse::SUPER_MAGIC,
            };
            encode_statfs(magic, &empty, flags)
        }
        Node::Fuse(..) => unreachable!("handled above"),
    })
}

fn encode_statfs(magic: u64, s: &appine_hal::FsStats, flags: u64) -> [u8; 120] {
    // asm-generic's struct statfs (64-bit)
    let mut b = [0u8; 120];
    let words = [
        magic,
        s.block_size,
        s.blocks,
        s.free,
        s.available,
        s.files,
        s.files_free,
        0, // f_fsid
        255,
        s.block_size,
        statfs_flags(flags),
    ];
    for (i, w) in words.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    b
}

/// statfs's `f_flags` (Linux's `calculate_f_flags`): the mount's flags plus `ST_VALID`.
fn statfs_flags(flags: u64) -> u64 {
    const ST_VALID: u64 = 0x20;
    const ST_RELATIME: u64 = 0x1000;
    const ST_NOSYMFOLLOW: u64 = 0x2000;
    // RDONLY, NOSUID, NODEV, NOEXEC, SYNCHRONOUS, MANDLOCK, NOATIME, NODIRATIME have the same
    // values as MS_*
    let same = ms::RDONLY
        | ms::NOSUID
        | ms::NODEV
        | ms::NOEXEC
        | ms::SYNCHRONOUS
        | ms::MANDLOCK
        | ms::NOATIME
        | ms::NODIRATIME;
    let mut f = ST_VALID | (flags & same);
    if flags & ms::RELATIME != 0 {
        f |= ST_RELATIME;
    }
    if flags & ms::NOSYMFOLLOW != 0 {
        f |= ST_NOSYMFOLLOW;
    }
    f
}

// ---- stat ----

/// Metadata of a filesystem node.
fn node_stat(
    cx: &Cx<'_>,
    node: &Node,
    inode_flags: &mut Option<u32>,
) -> Result<([u8; 128], MountId), Errno> {
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    let stat = match node {
        Node::Store(_, ino) => {
            let mut st = vfs.store().stat(*ino)?;
            st.size = logical_size(&vfs, *ino, st.size);
            vfs.tmpfs_stat_blocks(*ino, None, &mut st)?;
            *inode_flags = Some(st.flags);
            encode_stat(&st, vfs.dev_of(node))
        }
        Node::Overlay(_, o) => {
            let mut st = vfs.overlay_stat(*o)?;
            vfs.tmpfs_stat_blocks(vfs.overlay().node(*o).real(), None, &mut st)?;
            *inode_flags = Some(st.flags);
            encode_stat(&st, vfs.dev_of(node))
        }
        Node::Fuse(..) => super::fuse::stat(&vfs, &cx.cred(), node)?,
        // Namespaces are in nsfs
        Node::Pseudo(_, p @ PseudoNode::NsFile(..)) => {
            encode_stat(&pseudo::stat(&view, p)?, Fs::Nsfs.dev())
        }
        // The open file a magic link points at: report that file itself
        Node::Pseudo(_, PseudoNode::OpenFd(proc, tid, fd)) => {
            let file = view.open_file(*proc, *tid, *fd).ok_or(Errno::ENOENT)?;
            return Ok((
                file_stat_attrs(cx, &file, inode_flags)?,
                file.borrow().mnt_id(),
            ));
        }
        // A deleted program file
        Node::Pseudo(_, PseudoNode::OpenExe(proc)) => {
            let exe = exe_file(cx, *proc)?;
            let (node, ino, host) = exe.backing(&vfs)?;
            let mut st = vfs.store().stat_open(ino, host)?;
            st.size = logical_size(&vfs, ino, st.size);
            vfs.tmpfs_stat_blocks(ino, Some(host), &mut st)?;
            if let Node::Overlay(_, o) = node {
                st.ino = vfs.overlay().shown_ino(o);
            }
            *inode_flags = Some(st.flags);
            return Ok((encode_stat(&st, vfs.dev_of(&node)), node.mnt()));
        }
        Node::Pseudo(_, p) => {
            let b = encode_stat(&pseudo::stat(&view, p)?, vfs.dev_of(node));
            // procfs and devpts have 1024-byte blocks (proc_fill_super, devpts_fill_super)
            if matches!(vfs.fs_of(node), Fs::Proc | Fs::Pts) {
                with_blksize(b, 1024)
            } else {
                b
            }
        }
    };
    Ok((stat, node.mnt()))
}

pub(super) fn file_stat(cx: &Cx<'_>, file: &FileRef) -> Result<[u8; 128], Errno> {
    file_stat_attrs(cx, file, &mut None)
}

fn file_stat_attrs(
    cx: &Cx<'_>,
    file: &FileRef,
    inode_flags: &mut Option<u32>,
) -> Result<[u8; 128], Errno> {
    follow_copy_up(cx, file)?;
    let f = file.borrow();
    if let Some(q) = &f.mq_path {
        let q = q.borrow();
        return Ok(encode_stat(&q.stat(), cx.vfs()?.mq_dev(q.ns)));
    }
    if let Some((ino, file, _)) = f.regular_backing() {
        let vfs = cx.vfs()?;
        let dev = vfs.dev_of(&Node::Store(f.mnt, ino));
        let mut st = vfs.store().stat_open(ino, file)?;
        st.size = logical_size(&vfs, ino, st.size);
        vfs.tmpfs_stat_blocks(ino, Some(file), &mut st)?;
        // Through an overlay: the inode number stat shows for its node
        if let Some(o) = f.ovl {
            st.ino = vfs.overlay().shown_ino(o);
        }
        *inode_flags = Some(st.flags);
        return Ok(encode_stat(&st, dev));
    }
    let anon = |ino: u64, mode: u32, rdev: u64, dev: u64| {
        let st = Stat {
            ino,
            mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev,
            size: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            blocks: None,
            ..Stat::default()
        };
        encode_stat(&st, dev)
    };
    match &f.kind {
        FileKind::Host(fd) => host_stat(*fd),
        FileKind::Pipe(end) => match end.pipe.borrow().fifo {
            Some(_) => {
                let node = f.node().ok_or(Errno::EBADF)?;
                node_stat(cx, &node, inode_flags).map(|(st, _)| st)
            }
            None if cx.kr().vfs.is_none() => Ok(anon(
                end.pipe.borrow().ino,
                mode::S_IFIFO | 0o600,
                0,
                PIPE_DEV,
            )),
            None => Ok(encode_stat(
                &AnonTarget::Pipe(end.pipe.clone()).stat(cx.kr().vfs.as_deref(), &cx.cred()),
                PIPE_DEV,
            )),
        },
        FileKind::Pty(end) if end.master => {
            if end.pin {
                let vfs = cx.vfs()?;
                let fs = end.tty.borrow().fs;
                let st = pseudo::stat(&cx.view(&vfs), &PseudoNode::PtsPtmx(fs))?;
                Ok(with_blksize(encode_stat(&st, fs), 1024))
            } else if let Some(node) = f.node() {
                drop(f);
                node_stat(cx, &node, inode_flags).map(|(st, _)| st)
            } else {
                Ok(with_blksize(
                    anon(2, mode::S_IFCHR | 0o666, PTMX_RDEV, ROOT_DEV),
                    1024,
                ))
            }
        }
        FileKind::Socket(s) => Ok(encode_stat(
            &AnonTarget::Socket(s.clone()).stat(cx.kr().vfs.as_deref(), &cx.cred()),
            SOCK_DEV,
        )),
        // anon_inode: no file type bits
        FileKind::Epoll(_)
        | FileKind::EventFd(_)
        | FileKind::TimerFd(_)
        | FileKind::SignalFd(_)
        | FileKind::Inotify(_)
        | FileKind::Pidfd(_)
        | FileKind::SeccompNotify(_)
        | FileKind::Bpf(_) => Ok(anon(1, 0o600, 0, ANON_DEV)),
        // The device number is that of the mqueue filesystem of the queue's IPC namespace
        FileKind::MessageQueue(q) => {
            let q = q.borrow();
            Ok(encode_stat(&q.stat(), cx.vfs()?.mq_dev(q.ns)))
        }
        FileKind::Pty(end) if end.dev_ino.is_none() => {
            let t = end.tty.borrow();
            let st = Stat {
                ino: pseudo::ino_of(&PseudoNode::Pts(t.fs, t.index)),
                mode: mode::S_IFCHR | t.mode,
                nlink: 1,
                uid: t.owner.0,
                gid: t.owner.1,
                rdev: rdev(PTS_MAJOR, t.index),
                atime_ns: t.atime_ns,
                mtime_ns: t.mtime_ns,
                ctime_ns: t.ctime_ns,
                ..Stat::default()
            };
            // The device number is that of the devpts instance the terminal is in (ttyname
            // compares it with that of /dev/pts/<n>); devpts has 1024-byte blocks
            // (devpts_fill_super), matching stat by path.
            Ok(with_blksize(encode_stat(&st, t.fs), 1024))
        }
        FileKind::Path(node) => {
            let vfs = cx.vfs()?;
            if let Some(ino) = tmpfs_open_inode(&vfs, &f)
                && let Some(st) = vfs.unlinked_tmpfs_stat(ino)
            {
                let mut st = st?;
                if let Node::Overlay(_, o) = node {
                    st.ino = vfs.overlay().shown_ino(*o);
                }
                *inode_flags = Some(st.flags);
                Ok(encode_stat(&st, vfs.dev_of(node)))
            } else {
                let node = node.clone();
                drop(f);
                node_stat(cx, &node, inode_flags).map(|(st, _)| st)
            }
        }
        FileKind::Fuse(h) => {
            let node = Node::Fuse(f.mnt, h.id);
            let fh = h.fh();
            drop(f);
            super::fuse::stat_fh(&*cx.vfs()?, &cx.cred(), &node, fh)
        }
        _ => {
            let node = f.node().ok_or(Errno::EBADF)?;
            drop(f);
            node_stat(cx, &node, inode_flags).map(|(st, _)| st)
        }
    }
}

/// Metadata of a host fd.
// The st_* fields have different widths on different hosts
#[allow(clippy::unnecessary_cast)]
fn host_stat(fd: i32) -> Result<[u8; 128], Errno> {
    let s = appine_hal::fstat(fd).map_err(Errno)?;
    let st = Stat {
        ino: s.st_ino as u64,
        mode: s.st_mode as u32,
        nlink: s.st_nlink as u32,
        uid: s.st_uid,
        gid: s.st_gid,
        rdev: s.st_rdev as u64,
        size: s.st_size as u64,
        atime_ns: s.st_atime as i64 * 1_000_000_000 + s.st_atime_nsec as i64,
        mtime_ns: s.st_mtime as i64 * 1_000_000_000 + s.st_mtime_nsec as i64,
        ctime_ns: s.st_ctime as i64 * 1_000_000_000 + s.st_ctime_nsec as i64,
        blocks: Some(s.st_blocks as u64),
        ..Stat::default()
    };
    Ok(encode_stat(&st, s.st_dev as u64))
}

/// Encodes as asm-generic's `struct stat` (128 bytes).
pub(super) fn encode_stat(st: &Stat, dev: u64) -> [u8; 128] {
    let mut b = [0u8; 128];
    let mut put = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
    let (asec, ansec) = split_ns(st.atime_ns);
    let (msec, mnsec) = split_ns(st.mtime_ns);
    let (csec, cnsec) = split_ns(st.ctime_ns);
    put(0, &dev.to_le_bytes());
    put(8, &st.ino.to_le_bytes());
    put(16, &st.mode.to_le_bytes());
    put(20, &st.nlink.to_le_bytes());
    put(24, &st.uid.to_le_bytes());
    put(28, &st.gid.to_le_bytes());
    put(32, &st.rdev.to_le_bytes());
    // Directories in the store have no data; report one block, following ext4's habit
    let size = if st.is_dir() && dev == ROOT_DEV {
        4096
    } else {
        st.size
    };
    put(48, &size.to_le_bytes());
    put(56, &4096u32.to_le_bytes());
    // Short symlinks live in the inode and take no blocks: on ext4 targets shorter than 60 bytes
    // (`ext4_symlink`; with the trailing NUL they fit in `i_data`), on others such as tmpfs within
    // 128 bytes (`shmem_symlink`'s `SHORT_SYMLINK_LEN`)
    let inline = if dev == ROOT_DEV { 60 } else { 128 };
    let blocks = if let Some(blocks) = st.blocks {
        blocks
    } else if st.is_symlink() && size < inline {
        0
    } else {
        size.div_ceil(4096) * 8
    };
    put(64, &blocks.to_le_bytes());
    put(72, &asec.to_le_bytes());
    put(80, &ansec.to_le_bytes());
    put(88, &msec.to_le_bytes());
    put(96, &mnsec.to_le_bytes());
    put(104, &csec.to_le_bytes());
    put(112, &cnsec.to_le_bytes());
    b
}

/// Overrides `st_blksize` in an encoded `struct stat`.
fn with_blksize(mut b: [u8; 128], blksize: u32) -> [u8; 128] {
    b[56..60].copy_from_slice(&blksize.to_le_bytes());
    b
}

fn split_ns(ns: i64) -> (u64, u64) {
    (
        ns.div_euclid(1_000_000_000) as u64,
        ns.rem_euclid(1_000_000_000) as u64,
    )
}

/// The (st_dev, st_ino) fstat would report, the part known without querying the store (epoll's
/// fdinfo). Device numbers of synthetic nodes are those of the boot instances (procfs and devpts
/// instances mounted later have their own device numbers, [`Vfs::dev_of`]).
pub(crate) fn dev_ino(f: &OpenFile) -> (u64, u64) {
    match (&f.kind, f.node()) {
        (_, Some(Node::Store(_, ino))) => (ROOT_DEV, ino),
        (FileKind::Pipe(end), None) => (PIPE_DEV, end.pipe.borrow().ino),
        (FileKind::Socket(s), _) => (SOCK_DEV, pseudo::socket_ino(s)),
        (FileKind::Pty(end), None) if end.master && end.pin => (end.tty.borrow().fs, 2),
        (FileKind::Pty(end), None) if end.master => (ROOT_DEV, 2),
        (FileKind::Pty(end), None) => {
            let t = end.tty.borrow();
            (t.fs, pseudo::ino_of(&PseudoNode::Pts(t.fs, t.index)))
        }
        (_, Some(Node::Pseudo(_, p))) => (pseudo::fs_of(&p).dev(), pseudo::ino_of(&p)),
        _ => (ANON_DEV, 1),
    }
}

// ---- Changing the namespace ----

pub(super) fn mkdirat(cx: &mut Cx<'_>, dirfd: i32, path: u64, perm: u32) -> SysResult {
    let path = read_path(cx, path)?;
    if let Some(r) = cgroup_mkdir(cx, dirfd, &path, perm) {
        return r.map(|()| 0);
    }
    if let Some((mnt, dir, name)) = super::fuse::parent(cx, dirfd, &path)? {
        return super::fuse::mkdir(cx, (mnt, dir), name, perm).map(|()| 0);
    }
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    let view = cx.view(&vfs);
    let (parent, name) = resolve_create_parent(cx, &vfs, &cred, &view, dirfd, &path)?;
    let (mnt, dir, dir_st, ovl) = prepare_create_dir(&vfs, &cred, &view, &parent, name, None, 0)?;
    let (uid, gid, perm) = cred.new_owner(&dir_st, perm, cx.umask(), true);
    let tmpfs = tmpfs_reserve_name(&vfs, (mnt, dir), name, 0)?;
    create_in(
        &vfs,
        (mnt, dir),
        name,
        dir_st.default_acl.as_deref(),
        || vfs.store().mkdir(dir, name, perm, uid, gid),
        |&ino| ino,
    )?;
    tmpfs_created_name(&vfs, tmpfs, 0);
    created_events(cx.kr(), (dir, ovl), name, inotify::IN_ISDIR);
    Ok(0)
}

/// mkdir in a cgroup directory: creates a child cgroup ([`crate::cgroup::Cgroups::mkdir`]) with
/// the permission bits `perm` gives after the umask (vfs_mkdir's `S_IRWXUGO|S_ISVTX`, which kernfs
/// keeps). The order follows Linux: search permission on the parent (`EACCES`), `.`, `..` and
/// existing names (`EEXIST`), read-only mount (`EROFS`), then write permission on the parent
/// (`EACCES`).
fn cgroup_mkdir(cx: &mut Cx<'_>, dirfd: i32, path: &[u8], perm: u32) -> Option<Result<(), Errno>> {
    let (dir, id, st, name) = cgroup_parent(cx, dirfd, path)?;
    Some((|| {
        let cred = cx.cred();
        cred.permission(&st, MAY_EXEC)?;
        let cgroups = &cx.kr().cgroups;
        let exists = cgroups
            .get(id)
            .is_some_and(|g| g.children.contains_key(name))
            || cgroups.has_file(id, name);
        if name == b"." || name == b".." || exists {
            return Err(Errno::EEXIST);
        }
        let vfs = cx.vfs()?;
        if vfs.readonly(&dir) {
            return Err(Errno::EROFS);
        }
        cred.permission(&st, MAY_WRITE | MAY_EXEC)?;
        let mode = perm & 0o1777 & !cx.umask();
        cx.k().cgroups.mkdir(id, name, &cred, mode).map(|_| ())
    })())
}

pub(super) fn mknodat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    mode_arg: u32,
    dev: u64,
) -> SysResult {
    let path = read_path(cx, path)?;
    let kind = mode_arg & mode::S_IFMT;
    if let Some((mnt, dir, name)) = super::fuse::parent(cx, dirfd, &path)? {
        match kind {
            0 | mode::S_IFREG | mode::S_IFCHR | mode::S_IFBLK | mode::S_IFIFO | mode::S_IFSOCK => {}
            mode::S_IFDIR => return Err(Errno::EPERM),
            _ => return Err(Errno::EINVAL),
        }
        return super::fuse::mknod(cx, (mnt, dir), name, mode_arg, dev).map(|()| 0);
    }
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    let view = cx.view(&vfs);
    let (parent, name) = resolve_create_parent(cx, &vfs, &cred, &view, dirfd, &path)?;
    match kind {
        0 | mode::S_IFREG | mode::S_IFCHR | mode::S_IFBLK | mode::S_IFIFO | mode::S_IFSOCK => {}
        mode::S_IFDIR => return Err(Errno::EPERM),
        _ => return Err(Errno::EINVAL),
    }
    let dir_st = match &parent {
        Node::Overlay(mnt, o) => {
            reject_overlay_trailing_slash(&vfs, &view, &parent, name, &path)?;
            may_create_overlay(&vfs, &cred, &view, (*mnt, *o), name)?
        }
        _ => {
            let (mnt, dir) = store_dir(&vfs, &parent)?;
            reject_trailing_slash(&vfs, (mnt, dir), name, &path)?;
            may_create(&vfs, &cred, (mnt, dir), name)?
        }
    };
    // A whiteout (character device 0:0) needs no CAP_MKNOD and does not go through the device
    // filter (Linux's vfs_mknod)
    let whiteout = kind == mode::S_IFCHR && dev & 0xffff_ffff == 0;
    if matches!(kind, mode::S_IFCHR | mode::S_IFBLK) && !whiteout {
        if !cred.capable(cap::MKNOD) {
            return Err(Errno::EPERM);
        }
        super::bpf::check_device(cx, kind, dev & 0xffff_ffff, crate::bpf::ACC_MKNOD)?;
    }
    // An overlay does not make whiteouts for others (6.1's ovl_mknod)
    if whiteout && vfs.overlay_prefix(parent.mnt()).is_some() {
        return Err(Errno::EPERM);
    }
    let (mnt, dir, ovl) = match &parent {
        Node::Overlay(mnt, o) => {
            check_overlay_create_tmpfs(&vfs, *mnt, *o, name, 0)?;
            let (mnt, dir) = create_dir(&vfs, &parent)?;
            (mnt, dir, Some(*o))
        }
        _ => {
            let (mnt, dir) = store_dir(&vfs, &parent)?;
            (mnt, dir, None)
        }
    };
    let (uid, gid, perm) = cred.new_owner(&dir_st, mode_arg, cx.umask(), false);
    let tmpfs = tmpfs_reserve_name(&vfs, (mnt, dir), name, 0)?;
    let made = || {
        if kind == 0 || kind == mode::S_IFREG {
            vfs.store()
                .create_file(dir, name, perm, uid, gid)
                .map(|(ino, _)| ino)
        } else {
            vfs.store()
                .mknod(dir, name, kind | perm, dev & 0xffff_ffff, uid, gid)
        }
    };
    create_in(
        &vfs,
        (mnt, dir),
        name,
        dir_st.default_acl.as_deref(),
        made,
        |&ino| ino,
    )?;
    tmpfs_created_name(&vfs, tmpfs, 0);
    created_events(cx.kr(), (dir, ovl), name, 0);
    Ok(0)
}

pub(super) fn unlinkat(cx: &mut Cx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, path)?;
    unlink(cx, dirfd, path, flags).map(|()| 0)
}

fn unlink(cx: &mut Cx<'_>, dirfd: i32, path: Vec<u8>, flags: u32) -> Result<(), Errno> {
    if let Some(r) = unlink_mq(cx, dirfd, &path, flags) {
        return r;
    }
    if let Some(r) = cgroup_unlink(cx, dirfd, &path, flags) {
        return r;
    }
    if let Some(r) = unlink_overlay(cx, dirfd, &path, flags) {
        return r;
    }
    if let Some((mnt, dir, name)) = super::fuse::parent(cx, dirfd, &path)? {
        let rmdir = flags & AT_REMOVEDIR != 0;
        let slash = path.ends_with(b"/");
        return super::fuse::unlink(cx, (mnt, dir), name, rmdir, slash);
    }
    let (mnt, dir, name) = parent_at(cx, dirfd, &path)?;
    let store_vfs = cx.vfs()?;
    let store = store_vfs.store();
    let cred = cx.cred();
    // With inotify watches, note the inode to delete first
    let victim = match name {
        b"." | b".." => None,
        _ if inotify::active(cx.kr()) => store.lookup(dir, name)?,
        _ => None,
    };
    if flags & AT_REMOVEDIR != 0 {
        match name {
            b"." => return Err(Errno::EINVAL),
            b".." => return Err(Errno::ENOTEMPTY),
            _ => {
                writable_dir(&store_vfs, (mnt, dir))?;
                may_delete(store, &cred, dir, name)?;
                let gone = not_mount_point(cx, &store_vfs, dir, name)?;
                let tmpfs = tmpfs_victim(&store_vfs, (mnt, dir), name)?;
                store.rmdir(dir, name)?;
                tmpfs_removed(cx, &store_vfs, tmpfs);
                detach_points(cx, &store_vfs, gone, (dir, name));
                if let Some(ino) = gone {
                    inotify::unlinked(cx.kr(), ino, dir, name);
                }
            }
        }
        if let Some(ino) = victim {
            let k = cx.kr();
            inotify::deleted(k, ino, dir, name);
            inotify::dir_event(k, dir, name, inotify::IN_DELETE | inotify::IN_ISDIR, 0);
        }
    } else {
        if name == b"." || name == b".." {
            return Err(Errno::EISDIR);
        }
        writable_dir(&store_vfs, (mnt, dir))?;
        // A name ending in / can only be a directory: EISDIR when it is a directory, otherwise
        // ENOTDIR
        if path.ends_with(b"/") {
            let ino = store.lookup(dir, name)?.ok_or(Errno::ENOENT)?;
            return Err(if store.stat(ino)?.is_dir() {
                Errno::EISDIR
            } else {
                Errno::ENOTDIR
            });
        }
        may_delete(store, &cred, dir, name)?;
        let gone = not_mount_point(cx, &store_vfs, dir, name)?;
        let tmpfs = tmpfs_victim(&store_vfs, (mnt, dir), name)?;
        let held = gone.filter(|&ino| store.held(ino).unwrap_or(false));
        store.unlink(dir, name)?;
        tmpfs_removed(cx, &store_vfs, tmpfs);
        release_if_closed(cx, &store_vfs, held);
        detach_points(cx, &store_vfs, gone, (dir, name));
        if let Some(ino) = gone {
            inotify::unlinked(cx.kr(), ino, dir, name);
        }
        if let Some(ino) = victim {
            unlinked_events(cx, store, ino, (dir, name));
            inotify::dir_event(cx.kr(), dir, name, inotify::IN_DELETE, 0);
        }
    }
    Ok(())
}

/// unlink and rmdir in an overlay directory: returns Some when the parent is an overlay
/// directory. Linux's do_unlinkat and do_rmdir order: `.` and `..`, the read-only filesystem,
/// not found, a name ending in `/` on something that is not a directory, then `may_delete` on
/// what the overlay shows (search, then write permission and the sticky bit, then the type),
/// a mount point (EBUSY), a directory that the overlay does not show empty (ENOTEMPTY); then the
/// overlay's own removal ([`crate::vfs::overlay::Overlays::remove`]).
fn unlink_overlay(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: &[u8],
    flags: u32,
) -> Option<Result<(), Errno>> {
    let start = start_dir(cx, dirfd, path).ok()?;
    let vfs = cx.vfs().ok()?;
    let cred = cx.cred();
    let (dir, name) = vfs
        .resolve_parent(&cx.view(&vfs), &cred, &cx.root(), &start, path)
        .ok()?;
    let Node::Overlay(mnt, d) = dir else {
        return None;
    };
    let rmdir = flags & AT_REMOVEDIR != 0;
    Some((|| {
        match name {
            b"." if rmdir => return Err(Errno::EINVAL),
            b".." if rmdir => return Err(Errno::ENOTEMPTY),
            b"." | b".." => return Err(Errno::EISDIR),
            _ => {}
        }
        if vfs.readonly(&dir) {
            return Err(Errno::EROFS);
        }
        let child = vfs.overlay_child((mnt, d), name)?;
        let Node::Overlay(_, c) = child else {
            return Err(Errno::EIO);
        };
        let st = vfs.overlay_stat(c)?;
        if !rmdir && path.ends_with(b"/") {
            return Err(if st.is_dir() {
                Errno::EISDIR
            } else {
                Errno::ENOTDIR
            });
        }
        let dir_st = vfs.store().attrs(vfs.overlay().node(d).real())?;
        cred.permission(&dir_st, MAY_EXEC)?;
        may_delete_attrs(&cred, &dir_st, &st)?;
        match (rmdir, st.is_dir()) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        if vfs.is_point_in(&child, cx.mnt_ns()) {
            return Err(Errno::EBUSY);
        }
        if rmdir && !vfs.overlay_readdir(c)?.is_empty() {
            return Err(Errno::ENOTEMPTY);
        }
        // Account upper-layer tmpfs changes: parent dir copy-up, removed upper entry (and
        // whiteouts inside a removed upper dir), plus a new whiteout when a lower layer has it.
        let tmpfs = if let Some(dev) = overlay_upper_tmpfs_dev(&vfs, vfs.dev_of(&dir)) {
            let dir_inodes = overlay_uncopied_dirs(&vfs, &[d]);
            let lower = vfs.overlay().lower_has(vfs.store(), d, name)?;
            let child_upper = vfs.overlay().node(c).upper;
            let mut inodes = dir_inodes as i64 + i64::from(lower);
            let mut victim = None;
            if let Some(u) = child_upper {
                if rmdir {
                    inodes -= 1 + vfs.store().readdir(u)?.len() as i64;
                } else {
                    victim = tmpfs_victim_ino(&vfs, dev, u)?;
                }
            }
            let keeps_upper = child_upper.is_none()
                || victim
                    .as_ref()
                    .is_some_and(|v| v.object.is_some() && file_in_use(cx.kr(), &vfs, v.ino));
            let need_inodes = dir_inodes + u64::from(lower && keeps_upper);
            vfs.tmpfs_check(dev, 0, need_inodes)?;
            Some(OverlayTmpfsOp {
                dev,
                inodes,
                victim,
            })
        } else {
            None
        };
        let child_upper = vfs.overlay().node(c).upper;
        let lower_has = vfs.overlay().lower_has(vfs.store(), d, name)?;
        let copied_dirs = if inotify::active(cx.kr()) {
            overlay_uncopied_chain(&vfs, &[d])
        } else {
            Vec::new()
        };
        vfs.overlay_remove(d, name, rmdir)?;
        if let Some(op) = tmpfs {
            op.apply(cx, &vfs);
        }
        let k = cx.kr();
        // Report upper-layer changes first (parent dir copy-up, removed upper entry, and any
        // whiteout created in the upper directory), then the overlay node's events.
        overlay_copy_up_events(k, &vfs, &copied_dirs);
        let upper_gone = child_upper.map(|u| vfs.store().attrs(u).map_or(0, |s| s.nlink) == 0);
        let notify_removed = |target: Ino, dir: Ino, gone: bool| {
            inotify::unlinked(k, target, dir, name);
            if rmdir {
                inotify::deleted(k, target, dir, name);
                inotify::dir_event(k, dir, name, inotify::IN_DELETE | inotify::IN_ISDIR, 0);
            } else {
                inotify::path_event(k, target, None, inotify::IN_ATTRIB);
                if gone {
                    inotify::deleted(k, target, dir, name);
                }
                inotify::dir_event(k, dir, name, inotify::IN_DELETE, 0);
            }
        };
        if let Some(up) = vfs.overlay().node(d).upper {
            if let Some(u) = child_upper {
                notify_removed(u, up, upper_gone == Some(true));
            }
            if lower_has {
                inotify::dir_event(k, up, name, inotify::IN_CREATE, 0);
            }
        }
        notify_removed(
            overlay::key(c),
            overlay::key(d),
            upper_gone.unwrap_or(st.nlink <= 1),
        );
        Ok(())
    })())
}

/// Deletes a queue in the mqueue filesystem (as mq_unlink does): returns Some when the parent
/// directory is the mqueue root directory. The order follows Linux's do_unlinkat and do_rmdir:
/// `.` and `..`, the read-only mount, not found, unlink of a name ending in `/`, write permission
/// on the directory, the sticky bit (EPERM), rmdir's ENOTDIR.
fn unlink_mq(cx: &mut Cx<'_>, dirfd: i32, path: &[u8], flags: u32) -> Option<Result<(), Errno>> {
    let start = start_dir(cx, dirfd, path).ok()?;
    let vfs = cx.vfs().ok()?;
    let cred = cx.cred();
    let (dir, name) = vfs
        .resolve_parent(&cx.view(&vfs), &cred, &cx.root(), &start, path)
        .ok()?;
    let Node::Pseudo(_, PseudoNode::MqRoot(ns)) = dir else {
        return None;
    };
    let rmdir = flags & AT_REMOVEDIR != 0;
    Some((|| {
        match name {
            b"." if rmdir => return Err(Errno::EINVAL),
            b".." if rmdir => return Err(Errno::ENOTEMPTY),
            b"." | b".." => return Err(Errno::EISDIR),
            _ => {}
        }
        if vfs.readonly(&dir) {
            return Err(Errno::EROFS);
        }
        let ipc = cx.kr().ipc(ns);
        if !ipc.mqueues.contains_key(name) {
            return Err(Errno::ENOENT);
        }
        // unlink of a name ending in / is ENOTDIR before may_delete
        if !rmdir && path.ends_with(b"/") {
            return Err(Errno::ENOTDIR);
        }
        let dir_st = ipc.mq_dir.borrow().stat(ipc.mqueues.len());
        cred.permission(&dir_st, MAY_WRITE | MAY_EXEC)?;
        if rmdir {
            // rmdir checks the sticky bit first (may_delete); a queue is not a directory
            let q = ipc.mqueues[name].borrow().stat();
            if dir_st.mode & mode::S_ISVTX != 0
                && cred.fsuid != q.uid
                && cred.fsuid != dir_st.uid
                && !cred.capable_wrt(&q, cap::FOWNER)
            {
                return Err(Errno::EPERM);
            }
            return Err(Errno::ENOTDIR);
        }
        super::mqueue::remove_queue(cx.k().ipc_mut(ns), &cred, name)
    })())
}

/// unlink and rmdir in a cgroup directory: rmdir removes a child cgroup
/// ([`crate::cgroup::rmdir`]); files cannot be deleted (EPERM, cgroup directories have no
/// unlink).
fn cgroup_unlink(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: &[u8],
    flags: u32,
) -> Option<Result<(), Errno>> {
    let (dir, id, st, name) = cgroup_parent(cx, dirfd, path)?;
    let rmdir = flags & AT_REMOVEDIR != 0;
    Some((|| {
        match name {
            b"." if rmdir => return Err(Errno::EINVAL),
            b".." if rmdir => return Err(Errno::ENOTEMPTY),
            b"." | b".." => return Err(Errno::EISDIR),
            _ => {}
        }
        let vfs = cx.vfs()?;
        if vfs.readonly(&dir) {
            return Err(Errno::EROFS);
        }
        let cgroups = &cx.kr().cgroups;
        let child = cgroups.get(id).and_then(|g| g.children.get(name).copied());
        let file = cgroups.has_file(id, name);
        if child.is_none() && !file {
            return Err(Errno::ENOENT);
        }
        cx.cred().permission(&st, MAY_WRITE | MAY_EXEC)?;
        match (rmdir, child) {
            (true, Some(c)) => crate::cgroup::rmdir(cx.k(), c),
            (true, None) => Err(Errno::ENOTDIR),
            (false, Some(_)) => Err(Errno::EISDIR),
            (false, None) => Err(Errno::EPERM),
        }
    })())
}

/// When the parent directory is a cgroup directory: `name` is that cgroup's id, its metadata
/// and the last component.
fn cgroup_parent<'p>(
    cx: &Cx<'_>,
    dirfd: i32,
    path: &'p [u8],
) -> Option<(Node, u64, Stat, &'p [u8])> {
    let start = start_dir(cx, dirfd, path).ok()?;
    let vfs = cx.vfs().ok()?;
    let (dir, name) = vfs
        .resolve_parent(&cx.view(&vfs), &cx.cred(), &cx.root(), &start, path)
        .ok()?;
    let Node::Pseudo(_, PseudoNode::Cgroup(id, b"", 0)) = dir else {
        return None;
    };
    let st = pseudo::stat(&cx.view(&vfs), &PseudoNode::Cgroup(id, b"", 0)).ok()?;
    Some((dir, id, st, name))
}

pub(super) fn symlinkat(cx: &mut Cx<'_>, target: u64, dirfd: i32, path: u64) -> SysResult {
    let target = read_path(cx, target)?;
    if target.is_empty() {
        return Err(Errno::ENOENT);
    }
    let path = read_path(cx, path)?;
    if let Some((mnt, dir, name)) = super::fuse::parent(cx, dirfd, &path)? {
        return super::fuse::symlink(cx, (mnt, dir), name, &target).map(|()| 0);
    }
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    let view = cx.view(&vfs);
    let (parent, name) = resolve_create_parent(cx, &vfs, &cred, &view, dirfd, &path)?;
    // A long symlink takes an extra page in tmpfs (Linux's SHORT_SYMLINK_LEN)
    let pages = u64::from(target.len() >= 128);
    let (mnt, dir, dir_st, ovl) =
        prepare_create_dir(&vfs, &cred, &view, &parent, name, Some(&path), pages)?;
    let (uid, gid, _) = cred.new_owner(&dir_st, 0o777, 0, false);
    let tmpfs = tmpfs_reserve_name(&vfs, (mnt, dir), name, pages)?;
    create_in(
        &vfs,
        (mnt, dir),
        name,
        None,
        || vfs.store().symlink(dir, name, &target, uid, gid),
        |&ino| ino,
    )?;
    tmpfs_created_name(&vfs, tmpfs, pages);
    created_events(cx.kr(), (dir, ovl), name, 0);
    Ok(0)
}

pub(super) fn linkat(
    cx: &mut Cx<'_>,
    olddirfd: i32,
    oldpath: u64,
    newdirfd: i32,
    newpath: u64,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux 6.1's do_linkat: linking an fd by AT_EMPTY_PATH needs CAP_DAC_READ_SEARCH, or anyone
    // could give a name to a file passed to it
    let cred = cx.cred();
    if flags & AT_EMPTY_PATH != 0 && !cred.capable(cap::DAC_READ_SEARCH) {
        return Err(Errno::ENOENT);
    }
    let oldpath = read_path(cx, oldpath)?;
    let src = lookup_at_or_fd(
        cx,
        &cred,
        olddirfd,
        &oldpath,
        flags,
        flags & AT_SYMLINK_FOLLOW != 0,
    )?;
    let newpath = read_path(cx, newpath)?;
    let start = start_dir(cx, newdirfd, &newpath)?;
    let vfs = cx.vfs()?;
    // A deleted regular file reached through /proc/<pid>/fd/N is the open file itself
    // (follow_fd); Linux finds its dentry on the mount it was opened through, so the link is EXDEV
    // into another mount and refused as unlinked (ENOENT, below) in the same one
    let src = match src {
        Node::Pseudo(_, PseudoNode::OpenFd(proc, tid, fd)) => {
            let file = cx
                .view(&vfs)
                .open_file(proc, tid, fd)
                .ok_or(Errno::ENOENT)?;
            let f = file.borrow();
            // A memfd is on no mount of the caller's (Linux's internal shm mount): EXDEV
            if let Some((ino, ..)) = f.regular_backing()
                && !f.pseudo
                && f.ovl.is_none()
            {
                Node::Store(f.mnt, ino)
            } else {
                Node::Pseudo(f.mnt, PseudoNode::OpenFd(proc, tid, fd))
            }
        }
        src => src,
    };
    let (dir, name) = vfs.resolve_parent(&cx.view(&vfs), &cred, &cx.root(), &start, &newpath)?;
    if matches!(dir, Node::Pseudo(..)) && vfs.has_child(&cx.view(&vfs), &dir, name) {
        return Err(Errno::EEXIST);
    }
    if let (Node::Overlay(..), Node::Overlay(..)) = (&src, &dir) {
        return link_overlay(cx, &vfs, (&src, &dir), name, &newpath);
    }
    if let Node::Fuse(mnt, d) = dir {
        return super::fuse::link(cx, &src, (mnt, d), name).map(|()| 0);
    }
    // A synthetic filesystem is another "device": hard links cannot cross devices
    let (Node::Store(src_mnt, src), Node::Store(mnt, dir)) = (src, dir) else {
        return Err(Errno::EXDEV);
    };
    if name == b"." || name == b".." {
        return Err(Errno::EEXIST);
    }
    reject_trailing_slash(&vfs, (mnt, dir), name, &newpath)?;
    // Two sides reached through different mounts (even one filesystem bound in two places) are
    // EXDEV, after the existing name and the read-only mount and before the directory being
    // writable (Linux's do_linkat)
    let dir_st = may_create_name(&vfs, &cred, (mnt, dir), name)?;
    if src_mnt != mnt {
        return Err(Errno::EXDEV);
    }
    // A deleted source can still have a row after its host object has gone.
    let st = vfs.store().attrs(src)?;
    may_link(&cred, &dir_st, &st, cx.kr().protected_hardlinks)?;
    // The first link of a tmpfile moves its existing charge from the unlinked table.
    // Store::link checks whether a nameless inode can be linked before we change any charge.
    let tmpfs = backing_tmpfs_dev(&vfs, &Node::Store(mnt, dir));
    if let Some(dev) = tmpfs
        && st.nlink != 0
    {
        vfs.tmpfs_check(dev, 0, 1)?;
    }
    vfs.store().link(dir, name, src)?;
    if let Some(dev) = tmpfs {
        if st.nlink == 0 {
            vfs.tmpfs_take_unlinked(dev, src);
        } else {
            vfs.tmpfs_charge(dev, 0, 1);
        }
    }
    inotify::path_event(cx.kr(), src, None, inotify::IN_ATTRIB);
    inotify::dir_event(cx.kr(), dir, name, inotify::IN_CREATE, 0);
    Ok(0)
}

fn may_link(cred: &Cred, dir: &Stat, src: &Stat, protected_hardlinks: bool) -> Result<(), Errno> {
    // Linux checks protected_hardlinks after EXDEV and before directory write permission.
    if protected_hardlinks {
        let setgid_exec = mode::S_ISGID | 0o010;
        let safe = src.kind() == mode::S_IFREG
            && src.mode & mode::S_ISUID == 0
            && src.mode & setgid_exec != setgid_exec
            && cred.permission(src, MAY_READ | MAY_WRITE).is_ok();
        if !safe && !cred.owns(src) {
            return Err(Errno::EPERM);
        }
    }
    may_add_name(cred, dir)?;
    reject_flags(src.flags, inode_flags::PROTECTED)
}

/// linkat within an overlay (6.1's `ovl_link`, after `do_linkat`'s checks in the same order as
/// for the store, made on what the overlay shows): the file is copied up and linked in the upper
/// directory, replacing a whiteout of the name.
fn link_overlay(
    cx: &Cx<'_>,
    vfs: &Vfs,
    (src, dir): (&Node, &Node),
    name: &[u8],
    newpath: &[u8],
) -> SysResult {
    let (&Node::Overlay(src_mnt, so), &Node::Overlay(mnt, d)) = (src, dir) else {
        return Err(Errno::EXDEV);
    };
    if name == b"." || name == b".." || vfs.has_child(&cx.view(vfs), dir, name) {
        return Err(Errno::EEXIST);
    }
    if newpath.ends_with(b"/") {
        return Err(Errno::ENOENT);
    }
    let cred = cx.cred();
    let dir_st = vfs.store().attrs(vfs.overlay().node(d).real())?;
    cred.permission(&dir_st, MAY_EXEC)?;
    if vfs.readonly(dir) {
        return Err(Errno::EROFS);
    }
    if src_mnt != mnt {
        return Err(Errno::EXDEV);
    }
    let st = vfs.store().attrs(vfs.overlay().node(so).real())?;
    may_link(&cred, &dir_st, &st, cx.kr().protected_hardlinks)?;
    if st.is_dir() {
        return Err(Errno::EPERM);
    }
    check_overlay_create_tmpfs(vfs, mnt, d, name, 0)?;
    let file = copy_up(cx, vfs, so, CopyUp::All)?;
    let (mnt, up) = create_dir(vfs, dir)?;
    let tmpfs = tmpfs_reserve_name(vfs, (mnt, up), name, 0)?;
    create_in(
        vfs,
        (mnt, up),
        name,
        None,
        || {
            vfs.store().link(up, name, file)?;
            vfs.overlay().mark_origin_parent(vfs.store(), so, up)?;
            Ok(file)
        },
        |&ino| ino,
    )?;
    tmpfs_created_name(vfs, tmpfs, 0);
    // The upper inode's link count and upper directory entry first, then as 6.1's `fsnotify_link`
    // reports the link through the overlay: the file's link count changed, then the name
    let k = cx.kr();
    inotify::path_event(k, file, None, inotify::IN_ATTRIB);
    inotify::dir_event(k, up, name, inotify::IN_CREATE, 0);
    inotify::path_event(k, overlay::key(so), None, inotify::IN_ATTRIB);
    inotify::dir_event(k, overlay::key(d), name, inotify::IN_CREATE, 0);
    Ok(0)
}

pub(super) fn renameat2(
    cx: &mut Cx<'_>,
    olddirfd: i32,
    oldpath: u64,
    newdirfd: i32,
    newpath: u64,
    flags: u32,
) -> SysResult {
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE) != 0
        || flags == RENAME_NOREPLACE | RENAME_EXCHANGE
    {
        return Err(Errno::EINVAL);
    }
    let oldpath = read_path(cx, oldpath)?;
    let newpath = read_path(cx, newpath)?;
    let parent = |dirfd, path| -> Result<(Node, &[u8]), Errno> {
        let start = start_dir(cx, dirfd, path)?;
        let vfs = cx.vfs()?;
        let view = cx.view(&vfs);
        let cred = cx.cred();
        let (dir, name) = vfs.resolve_parent(&view, &cred, &cx.root(), &start, path)?;
        if let Node::Store(_, ino) = dir {
            cred.permission(&vfs.store().attrs(ino)?, MAY_EXEC)?;
        }
        Ok((dir, name))
    };
    let (old_parent, old_name) = parent(olddirfd, &oldpath)?;
    let (new_parent, new_name) = parent(newdirfd, &newpath)?;
    // Two sides reached through different mounts are EXDEV, and only then come `.` and `..` (a
    // destination one is EEXIST with RENAME_NOREPLACE), the read-only mount (Linux's
    // do_renameat2)
    if old_parent.mnt() != new_parent.mnt() {
        return Err(Errno::EXDEV);
    }
    let dots = |n: &[u8]| n == b"." || n == b"..";
    if dots(old_name) {
        return Err(Errno::EBUSY);
    }
    if dots(new_name) {
        return Err(if flags & RENAME_NOREPLACE != 0 {
            Errno::EEXIST
        } else {
            Errno::EBUSY
        });
    }
    if let (Node::Pseudo(..), _) | (_, Node::Pseudo(..)) = (&old_parent, &new_parent) {
        return rename_synthetic(
            cx,
            (olddirfd, &oldpath),
            (newdirfd, &newpath),
            flags,
            &old_parent,
        );
    }
    if let (Node::Overlay(mnt, od), Node::Overlay(_, nd)) = (&old_parent, &new_parent) {
        let slashes = oldpath.ends_with(b"/") || newpath.ends_with(b"/");
        return rename_overlay(cx, *mnt, (*od, old_name), (*nd, new_name), (flags, slashes));
    }
    if let (Node::Fuse(om, od), Node::Fuse(nm, nd)) = (&old_parent, &new_parent) {
        let (from, to) = ((*om, *od, old_name), (*nm, *nd, new_name));
        return super::fuse::rename_at(cx, from, to, flags).map(|()| 0);
    }
    let vfs = cx.vfs()?;
    let (old_mnt, old_dir) = store_dir(&vfs, &old_parent)?;
    let (new_mnt, new_dir) = store_dir(&vfs, &new_parent)?;
    writable_dir(&vfs, (old_mnt, old_dir))?;
    let exchange = flags & RENAME_EXCHANGE != 0;
    let noreplace = flags & RENAME_NOREPLACE != 0;
    let change = vfs.store().transaction(|store| {
        let src = store.attrs(store.lookup(old_dir, old_name)?.ok_or(Errno::ENOENT)?)?;
        let dst = store
            .lookup(new_dir, new_name)?
            .map(|ino| store.attrs(ino))
            .transpose()?;
        if noreplace && dst.is_some() {
            return Err(Errno::EEXIST);
        }
        if exchange && dst.is_none() {
            return Err(Errno::ENOENT);
        }
        let new_slash_ok = if exchange {
            dst.as_ref().is_some_and(Stat::is_dir)
        } else {
            src.is_dir()
        };
        if (oldpath.ends_with(b"/") && !src.is_dir()) || (newpath.ends_with(b"/") && !new_slash_ok)
        {
            return Err(Errno::ENOTDIR);
        }
        if old_dir != new_dir {
            if src.is_dir() && store.is_ancestor(src.ino, new_dir)? {
                return Err(Errno::EINVAL);
            }
            if let Some(d) = dst.as_ref().filter(|d| d.is_dir())
                && store.is_ancestor(d.ino, old_dir)?
            {
                return Err(if exchange {
                    Errno::EINVAL
                } else {
                    Errno::ENOTEMPTY
                });
            }
        }
        if dst.as_ref().is_some_and(|d| d.ino == src.ino) {
            return Ok(None);
        }
        may_rename(
            store,
            &cx.cred(),
            (old_dir, &src),
            (new_dir, dst.as_ref()),
            exchange,
        )?;
        not_mount_point(cx, &vfs, old_dir, old_name)?;
        let overwritten = not_mount_point(cx, &vfs, new_dir, new_name)?;
        let held = overwritten.filter(|&ino| store.held(ino).unwrap_or(false));
        let replaced = if !exchange && overwritten.is_some() {
            tmpfs_victim(&vfs, (new_mnt, new_dir), new_name)?
        } else {
            None
        };
        store.rename(old_dir, old_name, new_dir, new_name, noreplace, exchange)?;
        let entry = |st: &Stat| (st.ino, if st.is_dir() { inotify::IN_ISDIR } else { 0 });
        Ok(Some((entry(&src), dst.as_ref().map(entry), held, replaced)))
    })?;
    let Some((src, dst, held, replaced)) = change else {
        return Ok(0);
    };
    let overwritten = dst.map(|d| d.0);
    tmpfs_removed(cx, &vfs, replaced);
    // Detach the mounts of other namespaces on the overwritten target
    let k = cx.kr();
    if !exchange {
        release_if_closed(cx, &vfs, held);
        detach_points(cx, &vfs, overwritten, (new_dir, new_name));
        if let Some(ino) = overwritten {
            inotify::unlinked(k, ino, new_dir, new_name);
        }
    }
    // Files open through the moved name follow the rename
    let store = vfs.store();
    let lookup = |dir, name| move || store.lookup(dir, name).ok().flatten();
    inotify::renamed(
        k,
        (old_dir, old_name),
        (new_dir, new_name),
        lookup(new_dir, new_name),
    );
    if exchange {
        inotify::renamed(
            k,
            (new_dir, new_name),
            (old_dir, old_name),
            lookup(old_dir, old_name),
        );
    }
    // Order as in Linux's fsnotify_move; for an exchange the other side moves once more
    let moved = |isdir: u32, from: (Ino, &[u8]), to: (Ino, &[u8])| {
        let cookie = inotify::cookie(k);
        inotify::dir_event(k, from.0, from.1, inotify::IN_MOVED_FROM | isdir, cookie);
        inotify::dir_event(k, to.0, to.1, inotify::IN_MOVED_TO | isdir, cookie);
    };
    if inotify::active(k) {
        moved(src.1, (old_dir, old_name), (new_dir, new_name));
        match dst {
            Some(dst) if exchange => {
                inotify::path_event(k, src.0, None, inotify::IN_MOVE_SELF);
                moved(dst.1, (new_dir, new_name), (old_dir, old_name));
                inotify::path_event(k, dst.0, None, inotify::IN_MOVE_SELF);
            }
            // fsnotify_move: the replaced object's link count changed, then the moved one moved
            // itself; the replaced one is deleted with its last link
            Some((replaced, isdir)) => {
                inotify::path_event(k, replaced, None, inotify::IN_ATTRIB | isdir);
                inotify::path_event(k, src.0, None, inotify::IN_MOVE_SELF);
                if isdir != 0 || vfs.store().stat(replaced).map_or(0, |st| st.nlink) == 0 {
                    inotify::deleted(k, replaced, new_dir, new_name);
                }
            }
            None => inotify::path_event(k, src.0, None, inotify::IN_MOVE_SELF),
        }
    }
    Ok(0)
}

/// renameat2 within an overlay mount (after the mount and `.`/`..` checks): the read-only
/// filesystem, a trailing `/` on something that is not a directory, then [`may_rename`]'s checks
/// and mount points (EBUSY) on what the overlay shows, then the overlay's own rename
/// ([`crate::vfs::overlay::Overlays::rename`]).
fn rename_overlay(
    cx: &Cx<'_>,
    mnt: MountId,
    (od, old_name): (crate::vfs::overlay::OvlId, &[u8]),
    (nd, new_name): (crate::vfs::overlay::OvlId, &[u8]),
    (flags, slashes): (u32, bool),
) -> SysResult {
    let vfs = cx.vfs()?;
    let attrs = |o| vfs.store().attrs(vfs.overlay().node(o).real());
    let old_parent = Node::Overlay(mnt, od);
    if vfs.readonly(&old_parent) {
        return Err(Errno::EROFS);
    }
    let cred = cx.cred();
    let od_st = attrs(od)?;
    cred.permission(&od_st, MAY_EXEC)?;
    let Node::Overlay(m, src) = vfs.overlay_child((mnt, od), old_name)? else {
        return Err(Errno::EIO);
    };
    let src_st = attrs(src)?;
    if slashes && !src_st.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    may_delete_attrs(&cred, &od_st, &src_st)?;
    let nd_st = attrs(nd)?;
    let dst = match vfs.overlay_child((m, nd), new_name) {
        Ok(Node::Overlay(_, d)) => {
            let st = attrs(d)?;
            cred.permission(&nd_st, MAY_EXEC)?;
            may_delete_attrs(&cred, &nd_st, &st)?;
            Some((d, st))
        }
        _ => {
            may_add_name(&cred, &nd_st)?;
            None
        }
    };
    let exchange = flags & RENAME_EXCHANGE != 0;
    if od != nd {
        let moved = [
            Some(&src_st),
            dst.as_ref().map(|d| &d.1).filter(|_| exchange),
        ];
        for st in moved.iter().flatten().filter(|st| st.is_dir()) {
            cred.permission(st, MAY_WRITE)?;
        }
    }
    let ns = cx.mnt_ns();
    let busy = |o| vfs.is_point_in(&Node::Overlay(m, o), ns);
    if busy(src) || dst.as_ref().is_some_and(|d| busy(d.0)) {
        return Err(Errno::EBUSY);
    }
    // Renaming a name to itself or another hard link of the same file changes nothing
    if dst.as_ref().is_some_and(|d| {
        d.0 == src
            || (!exchange && vfs.overlay().node(d.0).real() == vfs.overlay().node(src).real())
    }) {
        return Ok(0);
    }
    // Files that move are copied up here, as copy_up copies them, before the rename finds them up
    let moved = [
        Some((src, &src_st)),
        dst.as_ref().map(|(d, st)| (*d, st)).filter(|_| exchange),
    ];
    for (o, st) in moved.into_iter().flatten() {
        if !st.is_dir() {
            copy_up(cx, &vfs, o, CopyUp::All)?;
        }
    }
    let tmpfs = if let Some(dev) = overlay_upper_tmpfs_dev(&vfs, vfs.dev_of(&old_parent)) {
        let dir_inodes = overlay_uncopied_dirs(&vfs, &[od, nd]);
        let dst_whiteout =
            dst.is_none()
                && vfs.overlay().node(nd).upper.is_some_and(|u| {
                    overlay::whiteout_at(vfs.store(), u, new_name).unwrap_or(false)
                });
        let old_lower = !exchange && vfs.overlay().lower_has(vfs.store(), od, old_name)?;
        let mut inodes = dir_inodes as i64 - i64::from(dst_whiteout) + i64::from(old_lower);
        let mut victim = None;
        if !exchange
            && let Some((d, d_st)) = &dst
            && let Some(du) = vfs.overlay().node(*d).upper
        {
            if d_st.is_dir() {
                inodes -= 1 + vfs.store().readdir(du)?.len() as i64;
            } else {
                victim = tmpfs_victim_ino(&vfs, dev, du)?;
            }
        }
        let need_inodes = dir_inodes + u64::from(old_lower && !dst_whiteout);
        vfs.tmpfs_check(dev, 0, need_inodes)?;
        Some(OverlayTmpfsOp {
            dev,
            inodes,
            victim,
        })
    } else {
        None
    };
    let copied_dirs = if inotify::active(cx.kr()) {
        overlay_uncopied_chain(&vfs, &[od, nd])
    } else {
        Vec::new()
    };
    let src_upper = vfs.overlay().node(src).upper;
    let dst_upper = dst.as_ref().and_then(|(d, _)| vfs.overlay().node(*d).upper);
    let old_lower = !exchange && vfs.overlay().lower_has(vfs.store(), od, old_name)?;
    vfs.overlay_rename(
        (od, old_name),
        (nd, new_name),
        (flags & RENAME_NOREPLACE != 0, exchange),
    )?;
    if let Some(op) = tmpfs {
        op.apply(cx, &vfs);
    }
    let k = cx.kr();
    let isdir = |st: &Stat| {
        if st.is_dir() { inotify::IN_ISDIR } else { 0 }
    };
    let moved = |isdir: u32, from: (Ino, &[u8]), to: (Ino, &[u8])| {
        let cookie = inotify::cookie(k);
        inotify::dir_event(k, from.0, from.1, inotify::IN_MOVED_FROM | isdir, cookie);
        inotify::dir_event(k, to.0, to.1, inotify::IN_MOVED_TO | isdir, cookie);
    };
    // Report upper-layer copy-up and rename changes first so watches on the upper layer see them,
    // then the overlay's own nodes in Linux's fsnotify_move order.
    overlay_copy_up_events(k, &vfs, &copied_dirs);
    let dst_upper_gone = dst_upper.map(|du| vfs.store().attrs(du).map_or(0, |s| s.nlink) == 0);
    let notify_rename = |old: (Ino, &[u8]),
                         new: (Ino, &[u8]),
                         src_ino: Option<Ino>,
                         dst_info: Option<(Ino, &Stat, bool)>| {
        if !exchange && let Some((d, _, _)) = dst_info {
            inotify::unlinked(k, d, new.0, new.1);
        }
        if let Some(s) = src_ino {
            inotify::renamed(k, old, new, || Some(s));
        }
        if exchange && let Some((d, _, _)) = dst_info {
            inotify::renamed(k, new, old, || Some(d));
        }
        if inotify::active(k)
            && let Some(s) = src_ino
        {
            moved(isdir(&src_st), old, new);
            match dst_info {
                Some((d, st, _)) if exchange => {
                    inotify::path_event(k, s, None, inotify::IN_MOVE_SELF);
                    moved(isdir(st), new, old);
                    inotify::path_event(k, d, None, inotify::IN_MOVE_SELF);
                }
                Some((d, st, gone)) => {
                    inotify::path_event(k, d, None, inotify::IN_ATTRIB | isdir(st));
                    inotify::path_event(k, s, None, inotify::IN_MOVE_SELF);
                    if st.is_dir() || gone {
                        inotify::deleted(k, d, new.0, new.1);
                    }
                }
                None => inotify::path_event(k, s, None, inotify::IN_MOVE_SELF),
            }
        }
    };
    if let (Some(old_up), Some(new_up)) =
        (vfs.overlay().node(od).upper, vfs.overlay().node(nd).upper)
    {
        let upper_dst = dst
            .as_ref()
            .zip(dst_upper)
            .map(|((_, st), du)| (du, st, dst_upper_gone == Some(true)));
        notify_rename((old_up, old_name), (new_up, new_name), src_upper, upper_dst);
        if old_lower && src_upper.is_some() {
            inotify::dir_event(k, old_up, old_name, inotify::IN_CREATE, 0);
        }
    }
    let ovl_dst = dst.as_ref().map(|(d, st)| {
        (
            overlay::key(*d),
            st,
            dst_upper_gone.unwrap_or(st.nlink <= 1),
        )
    });
    notify_rename(
        (overlay::key(od), old_name),
        (overlay::key(nd), new_name),
        Some(overlay::key(src)),
        ovl_dst,
    );
    Ok(0)
}

/// Checks before rename: both directories must be writable and obey the sticky bit; when a
/// directory changes parent, it must itself be writable too (its `..` is modified).
fn may_rename(
    store: &Store,
    cred: &Cred,
    (old_dir, src): (Ino, &Stat),
    (new_dir, dst): (Ino, Option<&Stat>),
    exchange: bool,
) -> Result<(), Errno> {
    may_delete_attrs(cred, &store.attrs(old_dir)?, src)?;
    let parent = store.attrs(new_dir)?;
    if let Some(d) = dst {
        may_delete_attrs(cred, &parent, d)?;
        if !exchange && src.is_dir() != d.is_dir() {
            return Err(if src.is_dir() {
                Errno::ENOTDIR
            } else {
                Errno::EISDIR
            });
        }
    } else {
        may_add_name(cred, &parent)?;
    }
    if old_dir != new_dir {
        for st in [Some(src), dst.filter(|_| exchange)]
            .into_iter()
            .flatten()
            .filter(|st| st.is_dir())
        {
            cred.permission(st, MAY_WRITE)?;
        }
    }
    Ok(())
}

/// Before deleting or renaming: EBUSY when a mount of the caller's namespace is on `name` in
/// directory `dir` (Linux's `is_local_mountpoint`). Returns its inode, used after the deletion
/// to detach the mounts on it in other namespaces ([`detach_points`]).
fn not_mount_point(cx: &Cx<'_>, vfs: &Vfs, dir: Ino, name: &[u8]) -> Result<Option<Ino>, Errno> {
    match vfs.store().lookup(dir, name)? {
        Some(ino) if vfs.is_store_point((ino, dir, name), cx.mnt_ns()) => Err(Errno::EBUSY),
        found => Ok(found),
    }
}

/// A held file (`ino`, looked at before the unlink, while its row was still cached) that has just
/// lost its last link stops sharing its object at once when nothing in this kernel has it open or
/// mapped ([`Store::release`]), rather than at the next boot: its object can go, and another file
/// still sharing it need not copy it before a write.
fn release_if_closed(cx: &Cx<'_>, vfs: &Vfs, ino: Option<Ino>) {
    let Some(ino) = ino else {
        return;
    };
    let store = vfs.store();
    if !store.attrs(ino).is_ok_and(|st| st.nlink == 0) {
        return;
    }
    let k = cx.kr();
    if !file_in_use(k, vfs, ino) && !k.unsharing.contains(&ino) && !k.inotify.borrow().has_open(ino)
    {
        let _ = store.release(ino);
    }
}

/// `name` in directory `dir` (formerly `ino`) has been deleted: the mounts on it in other
/// namespaces are detached (`detach_mounts` in Linux's vfs_rmdir, vfs_unlink and vfs_rename),
/// and mounts of it show it as deleted. Removed store directories still referenced by any task's
/// cwd, root or open directory/path descriptor keep their former name for `/proc/<pid>/cwd`.
fn detach_points(cx: &Cx<'_>, vfs: &Vfs, ino: Option<Ino>, (dir, name): (Ino, &[u8])) {
    if let Some(ino) = ino {
        if vfs
            .store()
            .attrs(ino)
            .is_ok_and(|st| st.is_dir() && st.nlink == 0)
        {
            record_removed_dir(cx, vfs, ino, name);
        }
        vfs.detach_store_point((ino, dir, name));
        vfs.roots_removed((ino, dir, name));
        cx.shared.fast_changed();
    }
}

/// Records the former name of removed store directory `ino` if any task's cwd, root or open
/// directory/path descriptor (or an already-tracked removed child) references it, pruning stale
/// entries first.
fn record_removed_dir(cx: &Cx<'_>, vfs: &Vfs, ino: Ino, name: &[u8]) {
    let used = used_store_dirs(cx);
    if vfs.has_removed_dirs() {
        vfs.prune_removed_dirs(&used);
    }
    if used.contains(&ino) || vfs.is_removed_dir_parent(ino) {
        vfs.record_removed_dir(ino, name);
    }
}

/// Store directory inodes referenced by any task's cwd, root or open directory/path descriptor.
fn used_store_dirs(cx: &Cx<'_>) -> std::collections::HashSet<Ino> {
    let mut used = std::collections::HashSet::new();
    let mut add = |node: &Node| {
        if let Node::Store(_, ino) = node {
            used.insert(*ino);
        }
    };
    for task in cx.kr().tasks.values() {
        let Ok(res) = task.res.try_borrow() else {
            continue;
        };
        if let Ok(fs) = res.fs.try_borrow() {
            add(&fs.cwd);
            add(&fs.root);
        }
        if let Ok(fds) = res.fds.try_borrow() {
            for file in fds.files() {
                if let Ok(f) = file.try_borrow()
                    && let FileKind::Directory { node, .. } | FileKind::Path(node) = &f.kind
                {
                    add(node);
                }
            }
        }
    }
    used
}

/// Link `name` of file `ino` was unlinked: the link count changed (IN_ATTRIB), and
/// IN_DELETE_SELF when the last link is gone too. Both events are reported only to the file
/// itself.
fn unlinked_events(cx: &Cx<'_>, store: &Store, ino: Ino, (dir, name): (Ino, &[u8])) {
    let k = cx.kr();
    inotify::path_event(k, ino, None, inotify::IN_ATTRIB);
    if store.stat(ino).map_or(0, |st| st.nlink) == 0 {
        inotify::deleted(k, ino, dir, name);
    }
}

// ---- chmod, chown and utimensat ----

/// What chmod, chown and utimensat act on: a store inode, or `/dev/pts/<n>` (owner, permissions
/// and times are kept on the terminal, as with Linux's devpts). Other nodes in synthetic
/// filesystems route through their own attribute storage when supported.
enum Attrs {
    Store(Ino),
    /// A node in an overlay: checked as what the overlay shows, changed in the upper layer
    /// after a copy-up (6.1's `ovl_setattr`).
    Overlay(crate::vfs::overlay::OvlId),
    Pts(Rc<RefCell<Tty>>),
    Anon(AnonTarget),
    /// A POSIX message queue: a file in the mqueue filesystem, or an fd from mq_open.
    Mq(Rc<RefCell<super::MessageQueue>>),
    /// The root directory of the mqueue filesystem of an IPC namespace (its id).
    MqDir(u64),
    Cgroup(u64, &'static [u8]),
    /// A node in a FUSE filesystem, changed by its daemon (`FUSE_SETATTR`, through the handle of
    /// the open file it was reached by, if any).
    Fuse(crate::vfs::fuse::FuseId, Option<u64>),
}

impl Attrs {
    fn anonymous(file: &OpenFile) -> Option<Attrs> {
        match &file.kind {
            FileKind::Socket(s) => Some(Self::Anon(AnonTarget::Socket(s.clone()))),
            FileKind::Pipe(end) if end.pipe.borrow().fifo.is_none() => {
                Some(Self::Anon(AnonTarget::Pipe(end.pipe.clone())))
            }
            _ => None,
        }
    }

    fn at(cx: &Cx<'_>, dirfd: i32, path: &[u8], flags: u32, follow: bool) -> Result<Self, Errno> {
        if path.is_empty()
            && flags & AT_EMPTY_PATH != 0
            && dirfd != AT_FDCWD
            && let Some(a) = Self::anonymous(&cx.fds().get(dirfd)?.borrow())
        {
            return Ok(a);
        }
        Self::of(
            cx,
            &lookup_at_or_fd(cx, &cx.cred(), dirfd, path, flags, follow)?,
        )
    }

    fn of(cx: &Cx<'_>, node: &Node) -> Result<Attrs, Errno> {
        match node {
            Node::Pseudo(_, PseudoNode::OpenFd(proc, tid, fd)) => {
                let vfs = cx.vfs()?;
                let file = cx
                    .view(&vfs)
                    .open_file(*proc, *tid, *fd)
                    .ok_or(Errno::ENOENT)?;
                if let Some(target) = Self::anonymous(&file.borrow()) {
                    return Ok(target);
                }
                store_ino(cx, node).map(Self::Store)
            }
            Node::Pseudo(_, PseudoNode::Pts(..)) if cx.vfs()?.readonly(node) => Err(Errno::EROFS),
            Node::Pseudo(_, PseudoNode::Pts(fs, n)) => pseudo::pty(cx.kr(), *fs, *n)
                .map(Attrs::Pts)
                .ok_or(Errno::ENOENT),
            Node::Pseudo(
                _,
                PseudoNode::MqRoot(_) | PseudoNode::Mq(..) | PseudoNode::Cgroup(..),
            ) if cx.vfs()?.readonly(node) => Err(Errno::EROFS),
            Node::Pseudo(_, PseudoNode::MqRoot(ns)) => Ok(Attrs::MqDir(*ns)),
            Node::Pseudo(_, PseudoNode::Mq(ns, ino)) => mq_queue(cx, *ns, *ino).map(Attrs::Mq),
            Node::Pseudo(_, n @ PseudoNode::Cgroup(id, name, _)) => {
                if pseudo::gone(cx.kr(), n) {
                    return Err(Errno::ENODEV);
                }
                Ok(Attrs::Cgroup(*id, name))
            }
            Node::Overlay(..) if cx.vfs()?.readonly(node) => Err(Errno::EROFS),
            Node::Overlay(_, o) => Ok(Attrs::Overlay(*o)),
            Node::Fuse(..) if cx.vfs()?.readonly(node) => Err(Errno::EROFS),
            Node::Fuse(_, f) => Ok(Attrs::Fuse(*f, None)),
            _ => store_ino(cx, node).map(Attrs::Store),
        }
    }

    /// Resolve fd-specific objects first. A FUSE open handle is passed through to SETATTR.
    fn of_fd(cx: &Cx<'_>, fd: i32) -> Result<Attrs, Errno> {
        let file = cx.fds().get(fd)?;
        let f = file.borrow();
        if let Some(target) = Self::anonymous(&f) {
            return Ok(target);
        }
        match &f.kind {
            FileKind::Pty(end)
                if !end.master && end.dev_ino.is_none() && f.flags & oflags::O_PATH == 0 =>
            {
                return Ok(Attrs::Pts(end.tty.clone()));
            }

            FileKind::MessageQueue(q) => return Ok(Attrs::Mq(q.clone())),
            _ => {}
        }
        if f.flags & oflags::O_PATH != 0 {
            return Err(Errno::EBADF);
        }
        let node = f.node().ok_or(Errno::EBADF)?;
        match node {
            Node::Fuse(_, id) => {
                if cx.vfs()?.readonly(&node) {
                    return Err(Errno::EROFS);
                }
                let fh = match &f.kind {
                    FileKind::Fuse(h) => h.fh(),
                    _ => None,
                };
                Ok(Attrs::Fuse(id, fh))
            }
            Node::Store(..) | Node::Overlay(..) | Node::Pseudo(_, PseudoNode::Cgroup(..)) => {
                Self::of(cx, &node)
            }
            Node::Pseudo(..) => Err(Errno::EBADF),
        }
    }

    /// The inotify key a change by path went to ([`attrib_at`], which finds an overlay or FUSE
    /// node again by its path): a store inode, an overlay node's topmost inode, or a FUSE key.
    fn ino(&self, cx: &Cx<'_>) -> Option<Ino> {
        match self {
            Attrs::Store(ino) => Some(*ino),
            Attrs::Cgroup(id, name) => Some(crate::cgroup::key(*id, name)),
            Attrs::Overlay(o) => Some(cx.vfs().ok()?.overlay().node(*o).real()),
            Attrs::Fuse(id, _) => Some(crate::vfs::fuse::key(*id)),
            _ => None,
        }
    }

    fn stat(&self, cx: &Cx<'_>) -> Result<Stat, Errno> {
        match self {
            Attrs::Store(ino) => cx.vfs()?.store().attrs(*ino),
            Attrs::Overlay(o) => {
                let vfs = cx.vfs()?;
                vfs.store().attrs(vfs.overlay().node(*o).real())
            }
            Attrs::Pts(t) => {
                let t = t.borrow();
                Ok(Stat {
                    mode: mode::S_IFCHR | t.mode,
                    uid: t.owner.0,
                    gid: t.owner.1,
                    ..Stat::default()
                })
            }
            Attrs::Anon(target) => Ok(target.stat(cx.kr().vfs.as_deref(), &cx.cred())),
            Attrs::Cgroup(id, name) => cx.kr().cgroups.get(*id).ok_or(Errno::ENOENT)?.attrs(name),
            Attrs::Mq(q) => Ok(q.borrow().stat()),
            Attrs::MqDir(ns) => {
                let ipc = cx.kr().ipc(*ns);
                Ok(ipc.mq_dir.borrow().stat(ipc.mqueues.len()))
            }
            Attrs::Fuse(id, fh) => {
                Ok(crate::vfs::fuse::cached_attr_fh(&*cx.vfs()?, *id, *fh)?.stat())
            }
        }
    }

    /// For a FUSE node: whether the kernel checks the change itself (`default_permissions`);
    /// a process the mount does not allow is EACCES (6.1's `fuse_setattr`). True for the rest.
    fn checked(&self, cx: &Cx<'_>) -> Result<bool, Errno> {
        let Attrs::Fuse(id, _) = self else {
            return Ok(true);
        };
        let vfs = cx.vfs()?;
        if !vfs.fuse().conn_of(*id)?.borrow().allows(&cx.cred()) {
            return Err(Errno::EACCES);
        }
        super::fuse::checks_permissions(&vfs, *id)
    }
}

pub(super) fn fchmodat(cx: &mut Cx<'_>, dirfd: i32, path: u64, perm: u32) -> SysResult {
    let path = read_path(cx, path)?;
    let target = Attrs::of(cx, &lookup_at(cx, dirfd, &path, true)?)?;
    chmod(cx, &target, perm)?;
    if let Some(ino) = target.ino(cx) {
        attrib_at(cx, ino, dirfd, &path, true);
    }
    Ok(0)
}

pub(super) fn fchmod(cx: &mut Cx<'_>, fd: i32, perm: u32) -> SysResult {
    let target = Attrs::of_fd(cx, fd)?;
    chmod(cx, &target, perm)?;
    attrib_fd(cx, fd);
    Ok(0)
}

/// Only the owner (or a holder of `CAP_FOWNER`) can change permission bits; a caller not in the
/// file's group cannot set the setgid bit (silently dropped without `CAP_FSETID`).
fn chmod(cx: &mut Cx<'_>, target: &Attrs, perm: u32) -> SysResult {
    let mut perm = perm & 0o7777;
    if target.checked(cx)? {
        let st = target.stat(cx)?;
        let cred = cx.cred();
        reject_flags(st.flags, inode_flags::PROTECTED)?;
        if !cred.owns(&st) {
            return Err(Errno::EPERM);
        }
        if !cred.in_group(st.gid) && !cred.capable_wrt(&st, cap::FSETID) {
            perm &= !mode::S_ISGID;
        }
    }
    match target {
        Attrs::Store(ino) => {
            // A memfd sealed with F_SEAL_EXEC keeps its execute bits (6.3's shmem_setattr)
            let sealed = cx.kr().seals.get(ino).is_some_and(|s| s & F_SEAL_EXEC != 0);
            if sealed && (target.stat(cx)?.mode ^ perm) & 0o111 != 0 {
                return Err(Errno::EPERM);
            }
            cx.vfs()?.store().set_mode(*ino, perm)?
        }
        Attrs::Overlay(o) => {
            let vfs = cx.vfs()?;
            let ino = copy_up(cx, &vfs, *o, CopyUp::All)?;
            vfs.store().set_mode(ino, perm)?;
        }
        Attrs::Pts(t) => {
            let mut t = t.borrow_mut();
            t.mode = perm;
            t.changed();
        }
        Attrs::Anon(target) => {
            if let Some(vfs) = &cx.kr().vfs {
                vfs.anon_attrs(target, &cx.cred(), |a| {
                    a.mode = (a.mode & mode::S_IFMT) | perm;
                    a.ctime_ns = crate::tty::wall_ns();
                });
            }
        }
        Attrs::Cgroup(id, name) => {
            let st = cx.k().cgroups.attrs_mut(*id, name)?;
            st.mode = st.kind() | perm;
            st.ctime_ns = crate::tty::wall_ns();
        }
        Attrs::Mq(q) => q.borrow_mut().set_mode(perm),
        Attrs::MqDir(ns) => {
            let ipc = cx.kr().ipc(*ns);
            let mut d = ipc.mq_dir.borrow_mut();
            d.mode = perm;
            d.ctime_ns = crate::tty::wall_ns();
        }
        Attrs::Fuse(id, fh) => {
            let set = super::fuse::SetAttr {
                mode: Some(perm),
                ..Default::default()
            };
            super::fuse::setattr(cx, &*cx.vfs()?, *id, &set, *fh)?;
        }
    }
    Ok(0)
}

pub(super) fn fchownat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    uid: u32,
    gid: u32,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, path)?;
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let target = Attrs::at(cx, dirfd, &path, flags, follow)?;
    if chown(cx, &target, uid, gid)? {
        if path.is_empty() {
            attrib_fd(cx, dirfd);
        } else if let Some(ino) = target.ino(cx) {
            attrib_at(cx, ino, dirfd, &path, follow);
        }
    }
    Ok(0)
}

pub(super) fn fchown(cx: &mut Cx<'_>, fd: i32, uid: u32, gid: u32) -> SysResult {
    let target = Attrs::of_fd(cx, fd)?;
    if chown(cx, &target, uid, gid)? {
        attrib_fd(cx, fd);
    }
    Ok(0)
}

/// Without `CAP_CHOWN`, the owner can only change the group to one it is in, and cannot change
/// the owner. IDs are in the caller's user namespace, and unmapped ones are EINVAL; `CAP_CHOWN`
/// requires the file's current owner and group to be mapped there. Returns whether any attribute
/// changed (so a no-op `chown(-1, -1)` that clears nothing does not emit `IN_ATTRIB`).
fn chown(cx: &mut Cx<'_>, target: &Attrs, uid: u32, gid: u32) -> Result<bool, Errno> {
    let cred = cx.cred();
    let uid = owner_arg(uid)
        .map(|u| cred.uid_in(u).ok_or(Errno::EINVAL))
        .transpose()?;
    let gid = owner_arg(gid)
        .map(|g| cred.gid_in(g).ok_or(Errno::EINVAL))
        .transpose()?;
    if let Attrs::Fuse(id, fh) = target {
        let checked = target.checked(cx)?;
        if checked {
            let st = target.stat(cx)?;
            let owner = cred.fsuid == st.uid;
            let uid_ok = uid.is_none_or(|u| owner && u == st.uid);
            let gid_ok = gid.is_none_or(|g| owner && (g == st.gid || cred.in_group(g)));
            if !(cred.capable_wrt(&st, cap::CHOWN) || uid_ok && gid_ok) {
                return Err(Errno::EPERM);
            }
        }
        if uid.is_none() && gid.is_none() {
            return Ok(false);
        }
        let set = super::fuse::SetAttr {
            uid,
            gid,
            ..Default::default()
        };
        super::fuse::setattr(cx, &*cx.vfs()?, *id, &set, *fh)?;
        return Ok(true);
    }
    let st = target.stat(cx)?;
    reject_flags(st.flags, inode_flags::PROTECTED)?;
    let owner = cred.fsuid == st.uid;
    let uid_ok = uid.is_none_or(|u| owner && u == st.uid);
    let gid_ok = gid.is_none_or(|g| owner && (g == st.gid || cred.in_group(g)));
    if !(cred.capable_wrt(&st, cap::CHOWN) || uid_ok && gid_ok) {
        return Err(Errno::EPERM);
    }
    // Changing a non-directory's owner, even chown(-1, -1), clears its setuid bit, and its setgid
    // bit when group-executable or when the caller is neither in its group nor has CAP_FSETID
    // (Linux's setattr_should_drop_sgid, since 6.2): a mode change, which only the owner or
    // CAP_FOWNER may make (notify_change adds ATTR_MODE, checked by inode_owner_or_capable).
    // Otherwise anyone could disable root's set-id programs (su, doas)
    let keep_sgid = cred.in_group(st.gid) || cred.capable_wrt(&st, cap::FSETID);
    let clears_setid = !st.is_dir()
        && (st.mode & mode::S_ISUID != 0
            || st.mode & mode::S_ISGID != 0 && (st.mode & 0o010 != 0 || !keep_sgid));
    if matches!(
        target,
        Attrs::Store(_) | Attrs::Overlay(_) | Attrs::Cgroup(..) | Attrs::Anon(_)
    ) && clears_setid
        && !cred.owns(&st)
    {
        return Err(Errno::EPERM);
    }
    if uid.is_none() && gid.is_none() && !clears_setid {
        let clears_caps = match target {
            Attrs::Store(ino) if !st.is_dir() => cx.vfs()?.store().has_file_caps(*ino)?,
            Attrs::Overlay(o) if !st.is_dir() => {
                let vfs = cx.vfs()?;
                let real = vfs.overlay().node(*o).real();
                vfs.store().has_file_caps(real)?
            }
            _ => false,
        };
        if !clears_caps {
            return Ok(false);
        }
    }
    match target {
        Attrs::Store(ino) => cx.vfs()?.store().set_owner(*ino, uid, gid, keep_sgid)?,
        Attrs::Overlay(o) => {
            let vfs = cx.vfs()?;
            let ino = copy_up(cx, &vfs, *o, CopyUp::All)?;
            vfs.store().set_owner(ino, uid, gid, keep_sgid)?;
        }
        Attrs::Pts(t) => {
            let mut t = t.borrow_mut();
            t.owner = (uid.unwrap_or(t.owner.0), gid.unwrap_or(t.owner.1));
            t.changed();
        }
        Attrs::Anon(target) => {
            if let Some(vfs) = &cx.kr().vfs {
                vfs.anon_attrs(target, &cred, |a| {
                    a.uid = uid.unwrap_or(a.uid);
                    a.gid = gid.unwrap_or(a.gid);
                    a.mode &= !mode::S_ISUID;
                    if a.mode & 0o010 != 0 || !keep_sgid {
                        a.mode &= !mode::S_ISGID;
                    }
                    a.ctime_ns = crate::tty::wall_ns();
                });
            }
            if let AnonTarget::Socket(s) = target
                && (uid.is_some() || gid.is_some())
            {
                s.borrow_mut()
                    .set_owner(uid.unwrap_or(st.uid), gid.unwrap_or(st.gid));
            }
        }
        Attrs::Cgroup(id, name) => {
            let st = cx.k().cgroups.attrs_mut(*id, name)?;
            st.uid = uid.unwrap_or(st.uid);
            st.gid = gid.unwrap_or(st.gid);
            if clears_setid {
                st.mode &= !mode::S_ISUID;
                if !keep_sgid || st.mode & 0o010 != 0 {
                    st.mode &= !mode::S_ISGID;
                }
            }
            st.ctime_ns = crate::tty::wall_ns();
        }
        Attrs::Mq(q) => q.borrow_mut().set_owner(uid, gid),
        Attrs::MqDir(ns) => {
            let ipc = cx.kr().ipc(*ns);
            let mut d = ipc.mq_dir.borrow_mut();
            (d.uid, d.gid) = (uid.unwrap_or(d.uid), gid.unwrap_or(d.gid));
            d.ctime_ns = crate::tty::wall_ns();
        }
        Attrs::Fuse(..) => unreachable!("handled above"),
    }
    Ok(true)
}

fn owner_arg(id: u32) -> Option<u32> {
    (id != u32::MAX).then_some(id)
}

pub(super) fn utimensat(
    cx: &mut Cx<'_>,
    dirfd: i32,
    path: u64,
    times: u64,
    flags: u32,
) -> SysResult {
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(Errno::EINVAL);
    }
    // A NULL path acts on dirfd itself (futimens)
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (target, path) = if path == 0 {
        if dirfd == AT_FDCWD {
            return Err(Errno::EFAULT);
        }
        if flags != 0 {
            return Err(Errno::EINVAL);
        }
        (Attrs::of_fd(cx, dirfd)?, Vec::new())
    } else {
        let path = read_path(cx, path)?;
        (Attrs::at(cx, dirfd, &path, flags, follow)?, path)
    };
    // times[0] is atime and times[1] is mtime. The current time is taken by the store (for
    // regular files it is left to the host)
    let (atime, mtime, needs_owner) = if times == 0 {
        (Some(FileTime::Now), Some(FileTime::Now), false)
    } else {
        let b: [u8; 32] = get(cx, times)?;
        let word = |i: usize| i64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        for nsec in [word(1), word(3)] {
            if nsec != UTIME_NOW && nsec != UTIME_OMIT && !(0..1_000_000_000).contains(&nsec) {
                return Err(Errno::EINVAL);
            }
        }
        if word(1) == UTIME_OMIT && word(3) == UTIME_OMIT {
            return Ok(0);
        }
        let needs_owner = word(1) != UTIME_NOW || word(3) != UTIME_NOW;
        let time = |sec: i64, nsec: i64| match nsec {
            UTIME_OMIT => None,
            UTIME_NOW => Some(FileTime::Now),
            nsec => {
                let ns = i128::from(sec) * 1_000_000_000 + i128::from(nsec);
                Some(FileTime::At(
                    ns.clamp(i64::MIN.into(), i64::MAX.into()) as i64
                ))
            }
        };
        (time(word(0), word(1)), time(word(2), word(3)), needs_owner)
    };
    // Write permission suffices only when both timestamps are set to now.
    if target.checked(cx)? {
        let st = target.stat(cx)?;
        let cred = cx.cred();
        reject_flags(
            st.flags,
            if needs_owner {
                inode_flags::PROTECTED
            } else {
                inode_flags::IMMUTABLE
            },
        )?;
        if !cred.owns(&st) {
            if needs_owner {
                return Err(Errno::EPERM);
            }
            if let Attrs::Fuse(id, _) = target {
                cx.vfs()?.fuse_permission(&cred, id, MAY_WRITE)?;
            } else {
                cred.permission(&st, MAY_WRITE)?;
            }
        }
    }
    let local_times = || {
        let now = crate::tty::wall_ns();
        let resolve = |time| match time {
            FileTime::Now => now,
            FileTime::At(ns) => ns,
        };
        (atime.map(resolve), mtime.map(resolve), now)
    };
    let ino = match target {
        Attrs::Store(ino) => ino,
        Attrs::Overlay(o) => {
            let vfs = cx.vfs()?;
            copy_up(cx, &vfs, o, CopyUp::All)?
        }
        // A terminal's times are kept on the terminal (changeable, as with Linux's devpts)
        Attrs::Pts(t) => {
            let mut t = t.borrow_mut();
            let (atime_ns, mtime_ns, _) = local_times();
            t.atime_ns = atime_ns.unwrap_or(t.atime_ns);
            t.mtime_ns = mtime_ns.unwrap_or(t.mtime_ns);
            t.changed();
            return Ok(0);
        }
        Attrs::Cgroup(id, name) => {
            let st = cx.k().cgroups.attrs_mut(id, name)?;
            let (atime_ns, mtime_ns, now) = local_times();
            st.atime_ns = atime_ns.unwrap_or(st.atime_ns);
            st.mtime_ns = mtime_ns.unwrap_or(st.mtime_ns);
            st.ctime_ns = now;
            notify_utimens(
                cx,
                crate::cgroup::key(id, name),
                dirfd,
                &path,
                follow,
                atime,
                mtime,
            );
            return Ok(0);
        }
        Attrs::Anon(target) => {
            let (at, mt, now) = local_times();
            if let Some(vfs) = &cx.kr().vfs {
                vfs.anon_attrs(&target, &cx.cred(), |a| {
                    a.atime_ns = at.unwrap_or(a.atime_ns);
                    a.mtime_ns = mt.unwrap_or(a.mtime_ns);
                    a.ctime_ns = now;
                });
            }
            return Ok(0);
        }
        // Times of message queues and the mqueue root directory are kept in the kernel layer
        Attrs::Mq(q) => {
            let (atime_ns, mtime_ns, _) = local_times();
            q.borrow_mut().set_times(atime_ns, mtime_ns);
            return Ok(0);
        }
        Attrs::MqDir(id) => {
            let (atime_ns, mtime_ns, now) = local_times();
            let ipc = cx.kr().ipc(id);
            let mut d = ipc.mq_dir.borrow_mut();
            d.atime_ns = atime_ns.unwrap_or(d.atime_ns);
            d.mtime_ns = mtime_ns.unwrap_or(d.mtime_ns);
            d.ctime_ns = now;
            return Ok(0);
        }
        Attrs::Fuse(id, fh) => {
            let time = |t: FileTime| match t {
                FileTime::Now => None,
                FileTime::At(ns) => Some(ns),
            };
            let set = super::fuse::SetAttr {
                atime: atime.map(time),
                mtime: mtime.map(time),
                ..Default::default()
            };
            super::fuse::setattr(cx, &*cx.vfs()?, id, &set, fh)?;
            notify_utimens(
                cx,
                crate::vfs::fuse::key(id),
                dirfd,
                &path,
                follow,
                atime,
                mtime,
            );
            return Ok(0);
        }
    };
    // Regular files set by fd are set through the open object, which also works for files still
    // open after deletion
    let open = match (path.is_empty(), dirfd) {
        (true, fd) if fd != AT_FDCWD => Some(cx.fds().get(fd)?),
        _ => None,
    };
    let vfs = cx.vfs()?;
    // (not one opened through an overlay, whose open object may be the lower inode's)
    if let Some(f) = open.as_ref().map(|f| f.borrow())
        && let FileKind::Regular { file, .. } = &f.kind
        && f.ovl.is_none()
    {
        vfs.store().set_times_open(ino, file, atime, mtime)?;
    } else {
        vfs.store().set_times(ino, atime, mtime)?;
    }
    notify_utimens(cx, ino, dirfd, &path, follow, atime, mtime);
    Ok(0)
}

/// Reports the inotify event for `utimensat` (`fsnotify_change`: both times are `IN_ATTRIB`,
/// access time alone is `IN_ACCESS`, modification time alone is `IN_MODIFY`).
fn notify_utimens(
    cx: &Cx<'_>,
    ino: Ino,
    dirfd: i32,
    path: &[u8],
    follow: bool,
    atime: Option<FileTime>,
    mtime: Option<FileTime>,
) {
    let event = match (atime, mtime) {
        (Some(_), None) => inotify::IN_ACCESS,
        (None, Some(_)) => inotify::IN_MODIFY,
        _ => inotify::IN_ATTRIB,
    };
    if path.is_empty() {
        event_fd(cx, dirfd, event);
    } else {
        event_at(cx, ino, dirfd, path, follow, event);
    }
}

/// Metadata changed by path: report IN_ATTRIB (also to the containing directory).
pub(super) fn attrib_at(cx: &Cx<'_>, ino: Ino, dirfd: i32, path: &[u8], follow: bool) {
    event_at(cx, ino, dirfd, path, follow, inotify::IN_ATTRIB);
}

/// Reports `event` for a change made by path to store inode or FUSE key `ino` (also to the
/// containing directory); through an overlay, to the overlay's node the path names.
fn event_at(cx: &Cx<'_>, ino: Ino, dirfd: i32, path: &[u8], follow: bool, event: u32) {
    if inotify::active(cx.kr()) {
        let (target, parent) = inotify::watched_at(cx, ino, (dirfd, path), follow);
        let parent = parent.as_ref().map(|(d, n)| (*d, n.as_slice()));
        let dir = if let Some(f) = crate::vfs::fuse::id_of(ino) {
            match cx.vfs().and_then(|v| crate::vfs::fuse::cached_attr(&v, f)) {
                Ok(a) if a.mode & mode::S_IFMT == mode::S_IFDIR => inotify::IN_ISDIR,
                _ => 0,
            }
        } else if crate::cgroup::is_key(ino) {
            if ino & 0xff == 0 {
                inotify::IN_ISDIR
            } else {
                0
            }
        } else {
            cx.vfs().map_or(0, |v| store_dir_flag(&v, ino))
        };
        // For overlay attribute changes, notify the upper inode first (as Linux's overlay calls
        // notify_change on the upper dentry), then the overlay node itself.
        if target != ino && overlay::of_key(target).is_some() {
            let upper_parent = parent.and_then(|(d, name)| {
                let po = overlay::of_key(d)?;
                let up = cx.vfs().ok()?.overlay().node(po).upper?;
                Some((up, name))
            });
            inotify::path_event(cx.kr(), ino, upper_parent, event | dir);
        }
        inotify::path_event(cx.kr(), target, parent, event | dir);
    }
}

/// Metadata changed by fd: report IN_ATTRIB.
pub(super) fn attrib_fd(cx: &Cx<'_>, fd: i32) {
    event_fd(cx, fd, inotify::IN_ATTRIB);
}

/// Reports `event` for a change made through fd `fd`.
fn event_fd(cx: &Cx<'_>, fd: i32, event: u32) {
    if !inotify::active(cx.kr()) {
        return;
    }
    if let Ok(file) = cx.fds().get(fd) {
        let file = file.borrow();
        if let Some(Node::Pseudo(_, PseudoNode::Cgroup(id, name, _))) = file.node()
            && !name.is_empty()
        {
            let parent = Some((crate::cgroup::key(id, b""), name));
            inotify::path_event(cx.kr(), crate::cgroup::key(id, name), parent, event);
        } else {
            if let Some(o) = file.ovl
                && let Ok(vfs) = cx.vfs()
                && let Some(up) = vfs.overlay().node(o).upper
            {
                let ovl = vfs.overlay();
                let n = ovl.node(o);
                let upper_parent = (n.parent != o)
                    .then(|| ovl.node(n.parent).upper.map(|pu| (pu, n.name.as_slice())))
                    .flatten();
                inotify::path_event(cx.kr(), up, upper_parent, event | store_dir_flag(&vfs, up));
            }
            inotify::file_event(cx.kr(), &file, event);
        }
    }
}

// ---- truncate and fallocate ----

pub(super) fn truncate(cx: &mut Cx<'_>, path: u64, len: i64) -> SysResult {
    let len = u64::try_from(len).map_err(|_| Errno::EINVAL)?;
    let path = read_path(cx, path)?;
    let vfs = cx.vfs()?;
    let node = lookup_at(cx, AT_FDCWD, &path, true)?;
    if let Node::Fuse(_, id) = node {
        super::fuse::truncate(cx, &node, len)?;
        event_at(
            cx,
            crate::vfs::fuse::key(id),
            AT_FDCWD,
            &path,
            true,
            inotify::IN_MODIFY,
        );
        return Ok(0);
    }
    // A regular file without a name reached through /proc/<pid>/fd/N (deleted, or a memfd) is
    // truncated itself, as Linux follows the magic link to its dentry on the mount it was opened
    // through. A memfd's internal mount is never read-only, and its object is only its open
    // files' (Store::create_anonymous), so their handle is used
    let (node, memfd, nameless) = match node {
        Node::Pseudo(proc_mnt, PseudoNode::OpenFd(proc, tid, fd)) => {
            let file = cx
                .view(&vfs)
                .open_file(proc, tid, fd)
                .ok_or(Errno::ENOENT)?;
            let f = file.borrow();
            if let Some((ino, host, _)) = f.regular_backing()
                && f.ovl.is_none()
            {
                let host = host.try_clone().map_err(host_errno)?;
                (Node::Store(f.mnt, ino), f.pseudo, Some(host))
            } else {
                (
                    Node::Pseudo(proc_mnt, PseudoNode::OpenFd(proc, tid, fd)),
                    false,
                    None,
                )
            }
        }
        node => (node, false, None),
    };
    let object = |ino| match (vfs.store().open_object(ino, true), &nameless) {
        (Err(Errno::ENOENT), Some(h)) => h.try_clone().map_err(host_errno),
        (r, _) => r,
    };
    // vfs_truncate: the type first (directories EISDIR, other non-regular files EINVAL), then a
    // read-only mount, then write permission
    if let Node::Pseudo(_, p) = &node {
        let st = pseudo::stat(&cx.view(&vfs), p)?;
        match st.kind() {
            mode::S_IFDIR => return Err(Errno::EISDIR),
            mode::S_IFREG => {}
            _ => return Err(Errno::EINVAL),
        }
        if vfs.readonly(&node) {
            return Err(Errno::EROFS);
        }
        cx.cred().permission(&st, MAY_WRITE)?;
        // Synthetic files have no size of their own to change (proc_setattr and kernfs accept
        // it and do nothing)
        return Ok(0);
    }
    // In an overlay the checks are made on what the overlay shows, leases on the overlay node are
    // broken before copy-up, and then the file is copied up (without its data when truncated to 0)
    // and truncated there
    let node = match node {
        Node::Overlay(mnt, o) => {
            let real = vfs.overlay().node(o).real();
            let st = vfs.store().attrs(real)?;
            match st.kind() {
                mode::S_IFDIR => return Err(Errno::EISDIR),
                mode::S_IFREG => {}
                _ => return Err(Errno::EINVAL),
            }
            if vfs.readonly(&Node::Overlay(mnt, o)) {
                return Err(Errno::EROFS);
            }
            reject_flags(st.flags, inode_flags::IMMUTABLE)?;
            cx.cred().permission(&st, MAY_WRITE)?;
            reject_flags(st.flags, inode_flags::APPEND)?;
            if executing_overlay(cx, o, real) {
                return Err(Errno::ETXTBSY);
            }
            check_fsize(cx, len)?;
            let _hold = overlay::Hold::new(o);
            super::lease::break_leases(cx, overlay::key(o), true, false, None)?;
            let what = if len == 0 {
                CopyUp::NoData
            } else {
                CopyUp::All
            };
            Node::Store(mnt, copy_up(cx, &vfs, o, what)?)
        }
        node => node,
    };
    let ino = node.ino().ok_or(Errno::EACCES)?;
    let st = vfs.store().attrs(ino)?;
    match st.kind() {
        mode::S_IFDIR => Err(Errno::EISDIR),
        mode::S_IFREG => {
            if !memfd && vfs.readonly(&node) {
                return Err(Errno::EROFS);
            }
            reject_flags(st.flags, inode_flags::IMMUTABLE)?;
            cx.cred().permission(&st, MAY_WRITE)?;
            reject_flags(st.flags, inode_flags::APPEND)?;
            if executing(cx, ino) {
                return Err(Errno::ETXTBSY);
            }
            check_fsize(cx, len)?;
            super::lease::break_leases(cx, ino, true, false, None)?;
            // A memfd's seals hold for truncation by path too (shmem_setattr)
            if cx.kr().seals.contains_key(&ino) {
                seals_permit(cx, ino, &object(ino)?, false, |_| len)?;
            }
            make_private(cx, ino, Some(len))?;
            remove_privs(cx, ino)?;
            let host = object(ino)?;
            let tmpfs = tmpfs_size(&vfs, &node, ino, &host)?;
            truncate_regular(cx, &vfs, ino, &host, len, tmpfs)?;
            if inotify::active(cx.kr()) {
                let (target, parent) = inotify::watched_at(cx, ino, (AT_FDCWD, &path), true);
                let parent = parent.as_ref().map(|(d, n)| (*d, n.as_slice()));
                inotify::path_event(cx.kr(), target, parent, inotify::IN_MODIFY);
            }
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub(super) fn ftruncate(cx: &mut Cx<'_>, fd: i32, len: i64) -> SysResult {
    let len = u64::try_from(len).map_err(|_| Errno::EINVAL)?;
    let file = cx.fds().get(fd)?;
    if let Some(io) = super::fuse::file_io(&file) {
        if !file.borrow().writable() {
            return Err(Errno::EINVAL);
        }
        check_fsize(cx, len)?;
        super::fuse::ftruncate(cx, &io, len)?;
        inotify::file_event(cx.kr(), &file.borrow(), inotify::IN_MODIFY);
        return Ok(0);
    }
    // The borrow ends before the lease break, which can wait with the BKL released
    let leased = {
        let f = file.borrow();
        if f.writable() {
            reject_flags(file_inode_flags(cx, &f)?, inode_flags::PROTECTED)?;
            super::lease::key_of(&f)
        } else {
            None
        }
    };
    if let Some(key) = leased {
        super::lease::break_leases(cx, key, true, false, Some(&file))?;
    }
    prepare_write(cx, &file, Some(len))?;
    let f = file.borrow();
    match &f.kind {
        FileKind::Regular { ino, file, .. } if f.writable() => {
            reject_flags(file_inode_flags(cx, &f)?, inode_flags::PROTECTED)?;
            check_fsize(cx, len)?;
            check_seals(cx, &f, false, |_| len)?;
            remove_privs(cx, *ino)?;
            let vfs = cx.vfs()?;
            let tmpfs = open_tmpfs_size(&vfs, &f, *ino, file)?;
            truncate_regular(cx, &vfs, *ino, file, len, tmpfs)?;
            inotify::file_event(cx.kr(), &f, inotify::IN_MODIFY);
            Ok(0)
        }
        FileKind::Path(_) => Err(Errno::EBADF),
        _ => Err(Errno::EINVAL),
    }
}

fn truncate_regular(
    cx: &Cx<'_>,
    vfs: &Vfs,
    ino: Ino,
    host: &std::fs::File,
    len: u64,
    tmpfs: Option<TmpfsFile>,
) -> Result<(), Errno> {
    truncating(cx, host, len);
    match host.set_len(len).map_err(host_errno) {
        Ok(()) => vfs.clear_memfd_size(ino),
        Err(Errno::EFBIG) if len <= i64::MAX as u64 && cx.kr().seals.contains_key(&ino) => {
            vfs.set_memfd_size(ino, len);
            let _ = appine_hal::set_times_fd(
                std::os::fd::AsRawFd::as_raw_fd(host),
                None,
                Some(appine_hal::TIME_NOW),
            );
        }
        Err(e) => return Err(e),
    }
    vfs.store().object_modified(ino);
    if let Some(t) = tmpfs
        && len <= t.size
    {
        vfs.tmpfs_forget_pages(t.ino, len, u64::MAX);
    }
    tmpfs_resized(vfs, tmpfs, host);
    Ok(())
}

pub(super) fn fallocate(cx: &mut Cx<'_>, fd: i32, mode: u32, offset: i64, len: i64) -> SysResult {
    const FALLOC_FL_KEEP_SIZE: u32 = 0x1;
    const FALLOC_FL_PUNCH_HOLE: u32 = 0x2;
    const FALLOC_FL_COLLAPSE_RANGE: u32 = 0x8;
    const FALLOC_FL_ZERO_RANGE: u32 = 0x10;
    const FALLOC_FL_INSERT_RANGE: u32 = 0x20;
    const FALLOC_FL_UNSHARE_RANGE: u32 = 0x40;
    // Linux 6.1 ksys_fallocate calls fdget(fd) first (rejecting closed and O_PATH fds with EBADF).
    let file = cx.fds().get(fd)?;
    if file.borrow().flags & oflags::O_PATH != 0 {
        return Err(Errno::EBADF);
    }
    // vfs_fallocate checks offset/len (EINVAL), then generic mode validity (EOPNOTSUPP), then
    // FMODE_WRITE (EBADF), then inode type (FIFO ESPIPE, dir EISDIR, other non-reg ENODEV), then
    // offset + len overflow / s_maxbytes (EFBIG).
    let (Ok(offset), Ok(len)) = (u64::try_from(offset), u64::try_from(len)) else {
        return Err(Errno::EINVAL);
    };
    if len == 0 {
        return Err(Errno::EINVAL);
    }
    let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
    let valid_mode = match mode & !FALLOC_FL_KEEP_SIZE {
        0 | FALLOC_FL_ZERO_RANGE | FALLOC_FL_UNSHARE_RANGE => true,
        FALLOC_FL_PUNCH_HOLE => keep,
        FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE => !keep,
        _ => false,
    };
    if !valid_mode {
        return Err(Errno::EOPNOTSUPP);
    }
    if !file.borrow().writable() {
        return Err(Errno::EBADF);
    }
    let forbidden = if mode & !FALLOC_FL_KEEP_SIZE == 0 {
        inode_flags::IMMUTABLE
    } else {
        inode_flags::PROTECTED
    };
    reject_flags(file_inode_flags(cx, &file.borrow())?, forbidden)?;
    // Beyond the largest file length (i64::MAX)
    let end_of = || {
        offset
            .checked_add(len)
            .filter(|&e| e <= i64::MAX as u64)
            .ok_or(Errno::EFBIG)
    };
    if let Some(io) = super::fuse::file_io(&file) {
        end_of()?;
        super::fuse::fallocate(cx, &io, mode, offset, len)?;
        inotify::file_io_event(cx.kr(), &file.borrow(), inotify::IN_MODIFY);
        return Ok(0);
    }
    match &file.borrow().kind {
        FileKind::Regular { .. } => {}
        FileKind::Pipe(_) => return Err(Errno::ESPIPE),
        FileKind::Directory { .. } => return Err(Errno::EISDIR),
        _ => return Err(Errno::ENODEV),
    }
    let end = end_of()?;
    prepare_write(cx, &file, None)?;
    let f = file.borrow();
    let FileKind::Regular {
        ino, file: host, ..
    } = &f.kind
    else {
        unreachable!("checked Regular above");
    };
    let ino = *ino;
    let host_size = host.metadata().map_err(host_errno)?.len();
    let vfs = cx.vfs()?;
    let logical = vfs.memfd_size(ino);
    let size = host_size.max(logical.unwrap_or(0));
    let tmpfs = open_tmpfs_size(&vfs, &f, ino, host)?;
    // Store files stand in for ext4's, which can also zero a range; tmpfs only reserves and
    // punches (shmem_fallocate)
    let zero = match mode & !FALLOC_FL_KEEP_SIZE {
        0 => false,
        FALLOC_FL_PUNCH_HOLE if keep => true,
        FALLOC_FL_ZERO_RANGE if tmpfs.is_none() => true,
        _ => return Err(Errno::EOPNOTSUPP),
    };
    if !keep {
        check_fsize(cx, end)?;
    }
    check_seals(cx, &f, zero, |size| if keep { size } else { size.max(end) })?;
    // In tmpfs the pages of the range that have none must all fit (Linux's shmem_fallocate gets
    // them one by one and undoes them on ENOSPC); punching needs none
    if let Some(t) = tmpfs
        && mode & FALLOC_FL_PUNCH_HOLE == 0
    {
        let fits = || -> Result<bool, Errno> {
            let Some(room) = vfs.tmpfs_room(t.dev, t.pages)? else {
                return Ok(true);
            };
            Ok(vfs
                .tmpfs_missing(ino, host, size, offset, end, room.saturating_sub(t.pages))
                .is_ok())
        };
        // A recorded usage that may have drifted is counted again before refusing
        let room = fits()? || vfs.tmpfs_recount(t.dev)? && fits()?;
        if !room {
            return Err(Errno::ENOSPC);
        }
    }
    remove_privs(cx, ino)?;
    if tmpfs.is_some() && mode & FALLOC_FL_PUNCH_HOLE != 0 {
        punch_tmpfs_maps(cx, ino, offset, end);
    }
    let fd = std::os::fd::AsRawFd::as_raw_fd(host);
    // Only the part of a punched range before host EOF can contain backing pages.
    let len = if mode & FALLOC_FL_PUNCH_HOLE != 0 && logical.is_some() {
        len.min(host_size.saturating_sub(offset))
    } else {
        len
    };
    let result = if len == 0 {
        appine_hal::set_times_fd(fd, None, Some(appine_hal::TIME_NOW))
    } else if tmpfs.is_some() && !zero {
        // Reserve guest quota while leaving host holes sparse. On ext4, readahead into an
        // unwritten extent can make SEEK_DATA and overlay copy-up see an untouched page.
        if !keep && end > size {
            host.set_len(end).map_err(host_errno)?;
        }
        appine_hal::set_times_fd(fd, None, Some(appine_hal::TIME_NOW))
    } else {
        appine_hal::fallocate(fd, mode as i32, offset, len)
    };
    match result {
        Ok(()) => {}
        Err(e) if e == Errno::EOPNOTSUPP.0 => {
            if zero {
                let zeros = vec![0u8; IO_CHUNK];
                let mut pos = offset;
                while pos < end.min(host_size) {
                    let n = (end.min(host_size) - pos).min(IO_CHUNK as u64) as usize;
                    host.write_all_at(&zeros[..n], pos).map_err(host_errno)?;
                    pos += n as u64;
                }
            }
            if !keep && end > size {
                host.set_len(end).map_err(host_errno)?;
            }
        }
        Err(e) => return Err(Errno(e)),
    }
    if let Some(t) = tmpfs {
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            vfs.tmpfs_forget_pages(ino, offset, end);
        } else {
            vfs.tmpfs_record_pages(t.dev, ino, offset, end, false);
        }
    }
    vfs.store().object_modified(ino);
    tmpfs_resized(&vfs, tmpfs, host);
    inotify::file_io_event(cx.kr(), &f, inotify::IN_MODIFY);
    Ok(0)
}

/// The length after truncation or reserving space must not exceed `RLIMIT_FSIZE`.
pub(super) fn check_fsize(cx: &Cx<'_>, len: u64) -> Result<(), Errno> {
    if len > cx.t.group.borrow().rlimits[RLIMIT_FSIZE as usize].0 {
        return Err(file_too_big(cx));
    }
    Ok(())
}

/// Over `RLIMIT_FSIZE`: sends SIGXFSZ and returns EFBIG.
/// `RLIMIT_FSIZE` for a write of `len` bytes at `pos` to a file other than a store one (a FUSE
/// file): how many may be written, or `SIGXFSZ` and EFBIG when none (generic_write_checks).
pub(super) fn fsize_room(cx: &Cx<'_>, pos: u64, len: usize) -> Result<usize, Errno> {
    let limit = cx.t.group.borrow().rlimits[RLIMIT_FSIZE as usize].0;
    if limit == u64::MAX || len == 0 {
        return Ok(len);
    }
    if pos >= limit {
        return Err(file_too_big(cx));
    }
    Ok(len.min((limit - pos) as usize))
}

fn file_too_big(cx: &Cx<'_>) -> Errno {
    signal::send_to_task(cx.kr(), cx.task, Signal::XFSZ, SigInfo::kernel());
    Errno::EFBIG
}

// ---- Paths ----

/// Resolves the path argument of the `*at` family.
pub(super) fn lookup_at(cx: &Cx<'_>, dirfd: i32, path: &[u8], follow: bool) -> Result<Node, Errno> {
    resolve_at(cx, &cx.cred(), dirfd, path, follow)
}

/// The common part of "an empty path acts on dirfd itself" (`AT_EMPTY_PATH`) in the `*at`
/// family.
fn lookup_at_or_fd(
    cx: &Cx<'_>,
    cred: &Cred,
    dirfd: i32,
    path: &[u8],
    flags: u32,
    follow: bool,
) -> Result<Node, Errno> {
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
        if dirfd == AT_FDCWD {
            return Ok(cx.cwd());
        }
        return cx.fds().get(dirfd)?.borrow().node().ok_or(Errno::EBADF);
    }
    resolve_at(cx, cred, dirfd, path, follow)
}

/// Resolves the path argument of the `*at` family with credentials `cred`.
fn resolve_at(
    cx: &Cx<'_>,
    cred: &Cred,
    dirfd: i32,
    path: &[u8],
    follow: bool,
) -> Result<Node, Errno> {
    let start = start_dir(cx, dirfd, path)?;
    let vfs = cx.vfs()?;
    vfs.resolve(&cx.view(&vfs), cred, &cx.root(), &start, path, follow)
}

/// Resolves a path to create or delete: returns the mount the parent directory was reached
/// through, the parent directory and the last component. Only directories in the store can be
/// modified; whether the mount is read-only is checked by the caller in Linux's order.
pub(super) fn parent_at<'p>(
    cx: &Cx<'_>,
    dirfd: i32,
    path: &'p [u8],
) -> Result<(MountId, Ino, &'p [u8]), Errno> {
    let start = start_dir(cx, dirfd, path)?;
    let vfs = cx.vfs()?;
    let (dir, name) = vfs.resolve_parent(&cx.view(&vfs), &cx.cred(), &cx.root(), &start, path)?;
    let (mnt, dir) = store_dir(&vfs, &dir)?;
    Ok((mnt, dir, name))
}

/// renameat2 in a synthetic filesystem (Linux's `do_renameat2` and `vfs_rename`, after the mount
/// and `.`/`..` checks): a read-only mount is EROFS, a missing source ENOENT (and in procfs a
/// missing destination too: its lookups fail rather than give a negative dentry), an existing
/// destination with `RENAME_NOREPLACE` EEXIST, a name renamed to itself succeeds without change;
/// anything else is refused as by [`store_dir`] (no synthetic directory renames), except that in
/// procfs, sysfs and devpts a caller who could delete there is told EPERM (no rename operation)
/// and others EACCES (`may_delete`).
fn rename_synthetic(
    cx: &Cx<'_>,
    (olddirfd, oldpath): (i32, &[u8]),
    (newdirfd, newpath): (i32, &[u8]),
    flags: u32,
    old_parent: &Node,
) -> SysResult {
    let vfs = cx.vfs()?;
    if vfs.readonly(old_parent) {
        return Err(Errno::EROFS);
    }
    let src = lookup_at(cx, olddirfd, oldpath, false)?;
    let dst = lookup_at(cx, newdirfd, newpath, false);
    if let Err(e) = &dst
        && vfs.fs_of(old_parent) == Fs::Proc
    {
        return Err(*e);
    }
    if flags & RENAME_NOREPLACE != 0 && dst.is_ok() {
        return Err(Errno::EEXIST);
    }
    if dst.is_ok_and(|d| d == src) {
        return Ok(0);
    }
    let Node::Pseudo(_, p) = old_parent else {
        return store_dir(&vfs, old_parent).map(|_| 0);
    };
    if matches!(p, PseudoNode::MqRoot(_) | PseudoNode::Cgroup(..)) {
        return Err(Errno::EPERM);
    }
    let st = pseudo::stat(&cx.view(&vfs), p)?;
    cx.cred().permission(&st, MAY_WRITE | MAY_EXEC)?;
    Err(Errno::EPERM)
}

/// Where a name is created ([`create_parent_at`]): the mount, the store directory, the name, and
/// the overlay directory it was reached as, if any.
pub(super) type CreateParent<'p> = (MountId, Ino, &'p [u8], Option<OvlId>);

/// Resolves the parent directory and basename of a creation path, rejecting `.`, `..`, and
/// existing names in synthetic directories with `EEXIST` (Linux's `filename_create`).
fn resolve_create_parent<'p>(
    cx: &Cx<'_>,
    vfs: &Vfs,
    cred: &Cred,
    view: &crate::pseudo::View<'_>,
    dirfd: i32,
    path: &'p [u8],
) -> Result<(Node, &'p [u8]), Errno> {
    let start = start_dir(cx, dirfd, path)?;
    let (parent, name) = vfs.resolve_parent(view, cred, &cx.root(), &start, path)?;
    if name == b"."
        || name == b".."
        || matches!(parent, Node::Pseudo(..)) && vfs.has_child(view, &parent, name)
    {
        return Err(Errno::EEXIST);
    }
    Ok((parent, name))
}

/// Overlay counterpart to [`reject_trailing_slash`]: rejects a non-directory creation whose path
/// ends in `/` before copying up the parent directory.
fn reject_overlay_trailing_slash(
    vfs: &Vfs,
    view: &crate::pseudo::View<'_>,
    dir: &Node,
    name: &[u8],
    path: &[u8],
) -> Result<(), Errno> {
    if !path.ends_with(b"/") {
        return Ok(());
    }
    Err(if vfs.has_child(view, dir, name) {
        Errno::EEXIST
    } else {
        Errno::ENOENT
    })
}

/// Validates permissions, trailing-slash rules and overlay upper tmpfs room before copying up an
/// overlay parent directory, returning the target store directory and its metadata.
fn prepare_create_dir(
    vfs: &Vfs,
    cred: &Cred,
    view: &crate::pseudo::View<'_>,
    parent: &Node,
    name: &[u8],
    trailing_slash_path: Option<&[u8]>,
    pages: u64,
) -> Result<(MountId, Ino, Stat, Option<OvlId>), Errno> {
    match parent {
        Node::Overlay(mnt, o) => {
            if let Some(path) = trailing_slash_path {
                reject_overlay_trailing_slash(vfs, view, parent, name, path)?;
            }
            let dir_st = may_create_overlay(vfs, cred, view, (*mnt, *o), name)?;
            check_overlay_create_tmpfs(vfs, *mnt, *o, name, pages)?;
            let (mnt, dir) = create_dir(vfs, parent)?;
            Ok((mnt, dir, dir_st, Some(*o)))
        }
        _ => {
            let (mnt, dir) = store_dir(vfs, parent)?;
            if let Some(path) = trailing_slash_path {
                reject_trailing_slash(vfs, (mnt, dir), name, path)?;
            }
            let dir_st = may_create(vfs, cred, (mnt, dir), name)?;
            Ok((mnt, dir, dir_st, None))
        }
    }
}

/// The parent directory of a non-directory name to create ([`parent_at`], used by `unix::bind`):
/// in a directory of a synthetic filesystem an existing name is EEXIST, ahead of the error that
/// the directory cannot be modified. In an overlay, permissions, trailing slash and tmpfs room are
/// checked before copying up parent directories.
pub(super) fn create_parent_at<'p>(
    cx: &Cx<'_>,
    dirfd: i32,
    path: &'p [u8],
) -> Result<CreateParent<'p>, Errno> {
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    let view = cx.view(&vfs);
    let (dir, name) = resolve_create_parent(cx, &vfs, &cred, &view, dirfd, path)?;
    if let Node::Overlay(mnt, o) = dir {
        reject_overlay_trailing_slash(&vfs, &view, &dir, name, path)?;
        may_create_overlay(&vfs, &cred, &view, (mnt, o), name)?;
        check_overlay_create_tmpfs(&vfs, mnt, o, name, 0)?;
    }
    let ovl = match dir {
        Node::Overlay(_, o) => Some(o),
        _ => None,
    };
    let (mnt, dir) = create_dir(&vfs, &dir)?;
    Ok((mnt, dir, name, ovl))
}

/// `name` was created in store directory `dir`: `IN_CREATE` (with `isdir`) to it, then to the
/// overlay directory `ovl` it was created through, if any (Linux's overlay creates the name in its
/// upper directory through the VFS, inside the creation through the overlay).
pub(super) fn created_events(
    k: &Kernel,
    (dir, ovl): (Ino, Option<OvlId>),
    name: &[u8],
    isdir: u32,
) {
    inotify::dir_event(k, dir, name, inotify::IN_CREATE | isdir, 0);
    if let Some(o) = ovl {
        inotify::dir_event(k, overlay::key(o), name, inotify::IN_CREATE | isdir, 0);
    }
}

/// Start directory of the `*at` family. An empty path is ENOENT at once (dirfd is not looked
/// at), as on Linux.
pub(super) fn start_dir(cx: &Cx<'_>, dirfd: i32, path: &[u8]) -> Result<Node, Errno> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.first() == Some(&b'/') {
        return Ok(cx.root());
    }
    if dirfd == AT_FDCWD {
        return Ok(cx.cwd());
    }
    let file = cx.fds().get(dirfd)?;
    let node = file.borrow().node().ok_or(Errno::ENOTDIR)?;
    let vfs = cx.vfs()?;
    if !vfs.is_dir(&cx.view(&vfs), &node)? {
        return Err(Errno::ENOTDIR);
    }
    Ok(node)
}

/// The directory to create or delete in: one in the store. Those in synthetic filesystems cannot
/// be modified, and are EROFS in a read-only mount. In the root directory of the mqueue filesystem
/// only queues can be created and deleted (openat and unlinkat handle them separately); everything
/// else (mkdir, mknod, symlink, link, rename) is EPERM as on Linux: its directory has no such
/// operations. cgroup2 directories are EPERM too (mkdirat and unlinkat handle child cgroups
/// before this).
fn store_dir(vfs: &Vfs, dir: &Node) -> Result<(MountId, Ino), Errno> {
    match dir {
        Node::Store(mnt, ino) => Ok((*mnt, *ino)),
        // Changing an overlay directory goes through its upper one ([`create_dir`]) or the
        // overlay's own removal and rename; never straight to a store inode
        // FUSE directories change through their daemon (`syscall::fuse`)
        Node::Overlay(..) | Node::Fuse(..) => Err(Errno::EXDEV),
        Node::Pseudo(..) if vfs.readonly(dir) => Err(Errno::EROFS),
        Node::Pseudo(_, PseudoNode::MqRoot(_) | PseudoNode::Cgroup(..)) => Err(Errno::EPERM),
        Node::Pseudo(..) => Err(Errno::EACCES),
    }
}

/// The store directory something is created in: a store directory as [`store_dir`] gives it,
/// or the upper directory of an overlay one, copied up first and charged to tmpfs when the upper
/// layer is on tmpfs (EROFS in a read-only overlay).
fn create_dir(vfs: &Vfs, dir: &Node) -> Result<(MountId, Ino), Errno> {
    match dir {
        Node::Overlay(mnt, o) => {
            if vfs.readonly(dir) {
                return Err(Errno::EROFS);
            }
            Ok((*mnt, overlay_upper_charged(vfs, *o, CopyUp::All)?))
        }
        _ => store_dir(vfs, dir),
    }
}

fn may_add_name(cred: &Cred, dir: &Stat) -> Result<(), Errno> {
    reject_flags(dir.flags, inode_flags::IMMUTABLE)?;
    cred.permission(dir, MAY_WRITE | MAY_EXEC)
}

/// Checks before creating `name` in overlay directory `(mnt, o)`, before copying up any parent
/// directories: directory search permission, `EEXIST` on the merged view, read-only mount
/// (`EROFS`), and write permission (`EACCES`). Returns the directory's metadata.
fn may_create_overlay(
    vfs: &Vfs,
    cred: &Cred,
    view: &crate::pseudo::View<'_>,
    (mnt, o): (MountId, OvlId),
    name: &[u8],
) -> Result<Stat, Errno> {
    let dir = Node::Overlay(mnt, o);
    let real = vfs.overlay().node(o).real();
    let st = vfs.store().stat(real)?;
    cred.permission(&st, MAY_EXEC)?;
    if vfs.has_child(view, &dir, name) {
        return Err(Errno::EEXIST);
    }
    if vfs.readonly(&dir) {
        return Err(Errno::EROFS);
    }
    may_add_name(cred, &st)?;
    Ok(st)
}

/// The queue with inode number `ino` in the mqueue filesystem of IPC namespace `ns`; a deleted
/// one is ENOENT.
fn mq_queue(cx: &Cx<'_>, ns: u64, ino: u64) -> Result<Rc<RefCell<super::MessageQueue>>, Errno> {
    super::mqueue::find(cx.kr().ipc(ns), ino)
        .map(|(_, q)| q.clone())
        .ok_or(Errno::ENOENT)
}

/// Checks before creating `name` in directory `dir` (`may_create`): [`may_create_name`], then the
/// directory must be writable. Returns the directory's metadata.
pub(super) fn may_create(
    vfs: &Vfs,
    cred: &Cred,
    dir: (MountId, Ino),
    name: &[u8],
) -> Result<Stat, Errno> {
    let st = may_create_name(vfs, cred, dir, name)?;
    may_add_name(cred, &st)?;
    Ok(st)
}

/// Checks on the name and the mount before creating `name` in directory `dir` (Linux's
/// `filename_create`): the directory must be searchable and the name must not exist, and only
/// then comes the read-only mount (EROFS). Returns the directory's metadata.
fn may_create_name(
    vfs: &Vfs,
    cred: &Cred,
    (mnt, dir): (MountId, Ino),
    name: &[u8],
) -> Result<Stat, Errno> {
    let store = vfs.store();
    let st = store.stat(dir)?;
    cred.permission(&st, MAY_EXEC)?;
    if exists_in(vfs, (mnt, dir), name)? {
        return Err(Errno::EEXIST);
    }
    if vfs.readonly(&Node::Store(mnt, dir)) {
        return Err(Errno::EROFS);
    }
    Ok(st)
}

/// Before deleting or renaming: EROFS in a read-only mount (Linux's `mnt_want_write`, before the
/// name is looked up).
fn writable_dir(vfs: &Vfs, (mnt, dir): (MountId, Ino)) -> Result<(), Errno> {
    if vfs.readonly(&Node::Store(mnt, dir)) {
        return Err(Errno::EROFS);
    }
    Ok(())
}

/// What is being created is not a directory but its name ends in `/`: EEXIST when it exists,
/// otherwise ENOENT (as in Linux's `filename_create`).
pub(super) fn reject_trailing_slash(
    vfs: &Vfs,
    dir: (MountId, Ino),
    name: &[u8],
    path: &[u8],
) -> Result<(), Errno> {
    if !path.ends_with(b"/") {
        return Ok(());
    }
    Err(if exists_in(vfs, dir, name)? {
        Errno::EEXIST
    } else {
        Errno::ENOENT
    })
}

/// Whether `name` exists in store directory `dir` of mount `mnt`; in an overlay's upper
/// directory a whiteout does not count (it hides a name, [`create_in`] replaces it).
fn exists_in(vfs: &Vfs, (mnt, dir): (MountId, Ino), name: &[u8]) -> Result<bool, Errno> {
    let store = vfs.store();
    match store.lookup(dir, name)? {
        Some(_) if vfs.fs_of(&Node::Store(mnt, dir)) == Fs::Overlay => {
            Ok(!crate::vfs::overlay::whiteout_at(store, dir, name)?)
        }
        found => Ok(found.is_some()),
    }
}

/// Creates `name` in store directory `dir` of mount `mnt` with `make`, which returns what `made`
/// takes the new inode from. In an overlay's upper directory a whiteout of the name is replaced
/// in the same transaction, and a directory made there is opaque, so what the lower layers have
/// under the name stays hidden (6.1's `ovl_create_over_whiteout`).
pub(super) fn create_in<T>(
    vfs: &Vfs,
    (mnt, dir): (MountId, Ino),
    name: &[u8],
    default_acl: Option<&[crate::vfs::acl::AclEntry]>,
    make: impl FnOnce() -> Result<T, Errno>,
    made: impl Fn(&T) -> Ino,
) -> Result<T, Errno> {
    let prefix = vfs.overlay_prefix(mnt);
    if prefix.is_none() && default_acl.is_none() {
        return make();
    }
    vfs.store().transaction(|s| {
        let whiteout = prefix.is_some() && crate::vfs::overlay::whiteout_at(s, dir, name)?;
        if whiteout {
            s.unlink(dir, name)?;
        }
        let new = make()?;
        let ino = made(&new);
        if let Some(acl) = default_acl {
            crate::vfs::acl::inherit(s, ino, acl)?;
        }
        if let Some(prefix) = prefix
            && whiteout
            && s.kind(ino)? == mode::S_IFDIR
        {
            s.set_xattr(ino, &[prefix, b"opaque"].concat(), b"y", false, false)?;
        }
        Ok(new)
    })
}

fn may_delete_attrs(cred: &Cred, dir: &Stat, victim: &Stat) -> Result<(), Errno> {
    reject_flags(dir.flags, inode_flags::IMMUTABLE)?;
    cred.may_delete(dir, victim)?;
    reject_flags(dir.flags | victim.flags, inode_flags::PROTECTED)
}

/// Checks before deleting `name` in directory `dir` or moving it away (`may_delete`); returns its
/// metadata.
fn may_delete(store: &Store, cred: &Cred, dir: Ino, name: &[u8]) -> Result<Stat, Errno> {
    let dir_st = store.stat(dir)?;
    cred.permission(&dir_st, MAY_EXEC)?;
    let victim = store.stat(store.lookup(dir, name)?.ok_or(Errno::ENOENT)?)?;
    may_delete_attrs(cred, &dir_st, &victim)?;
    Ok(victim)
}

/// The store inode to modify: EROFS in a read-only mount; nodes in synthetic filesystems cannot
/// be modified (EACCES).
fn store_ino(cx: &Cx<'_>, node: &Node) -> Result<Ino, Errno> {
    if cx.vfs()?.readonly(node) {
        return Err(Errno::EROFS);
    }
    node.ino().ok_or(Errno::EACCES)
}

/// The absolute path recorded at open (`/proc/<pid>/fd/<n>`, maps): as with Linux's `d_path`,
/// symlinks are fully resolved, and it is computed from the directory and name `found` where the
/// file was last found. valgrind reopens Debian's `/lib/ld-linux-aarch64.so.1` (whose last
/// component is a link) by its name in `/proc/self/fd`, with `O_NOFOLLOW`. A file reached through
/// a link like `/proc/<pid>/fd/<n>`, whose name is unknown, gets the lexically normalized path.
fn display_path(
    cx: &Cx<'_>,
    vfs: &Vfs,
    start: &Node,
    path: &[u8],
    node: &Node,
    found: Option<&Dentry>,
) -> Option<Rc<[u8]>> {
    if let Ok(p) = vfs.found_path(&cx.view(vfs), &cx.root(), node, found) {
        return Some(Rc::from(p));
    }
    let full = if path.first() == Some(&b'/') {
        path.to_vec()
    } else {
        let mut p = vfs.reach(&cx.view(vfs), &cx.root(), start).ok()?.0;
        p.push(b'/');
        p.extend_from_slice(path);
        p
    };
    Some(Rc::from(normalize(&full)))
}

// ---- tmpfs accounting ----

/// When overlay instance `ovl_dev`'s upper layer is on tmpfs, returns that tmpfs instance's device
/// number (`overlay_layers` pins the upper layer's tmpfs first in `Instance::pins`).
fn overlay_upper_tmpfs_dev(vfs: &Vfs, ovl_dev: u64) -> Option<u64> {
    let (upper, first_pin) = {
        let ovl = vfs.overlay();
        let inst = ovl.instance(ovl_dev)?;
        (inst.upper?, *inst.pins.first()?)
    };
    let store = vfs.store();
    let mut cur = upper;
    while let Ok(p) = store.parent(cur) {
        if p == cur {
            break;
        }
        cur = p;
    }
    // Detached store roots belong exclusively to tmpfs instances
    (cur != crate::vfs::store::ROOT).then_some(first_pin)
}

/// When changes to `node` land on a tmpfs instance — either directly or through an overlay whose
/// upper layer is on tmpfs — returns that tmpfs instance's device number.
fn backing_tmpfs_dev(vfs: &Vfs, node: &Node) -> Option<u64> {
    match vfs.fs_of(node) {
        Fs::Tmpfs => Some(vfs.dev_of(node)),
        Fs::Overlay => overlay_upper_tmpfs_dev(vfs, vfs.dev_of(node)),
        _ => None,
    }
}

/// Counts distinct uncopied overlay nodes along the ancestor chains of `nodes`.
fn overlay_uncopied_dirs(vfs: &Vfs, nodes: &[OvlId]) -> u64 {
    overlay_uncopied_chain(vfs, nodes).len() as u64
}

/// Copies an overlay node and its missing parent directories to the upper layer. A tmpfs upper
/// charges copied data, including zero pages instantiated by mappings of the lower inode.
fn overlay_upper_charged(vfs: &Vfs, o: OvlId, mut what: CopyUp) -> Result<Ino, Errno> {
    let (dev, lower) = {
        let ovl = vfs.overlay();
        let n = ovl.node(o);
        if let Some(upper) = n.upper {
            return Ok(upper);
        }
        (n.dev, n.real())
    };
    let Some(dev) = overlay_upper_tmpfs_dev(vfs, dev) else {
        return vfs.overlay_upper(o, what);
    };
    let inodes = overlay_uncopied_dirs(vfs, &[o]);
    let st = vfs.store().stat(lower)?;
    let pages = if st.kind() == mode::S_IFREG && what == CopyUp::NoData {
        0
    } else if let Some(pages) = vfs.tmpfs_copy_pages(&st)? {
        // Sharing the whole host object could import the lower file's unwritten reservations.
        what = CopyUp::Copied;
        pages
    } else {
        vfs.tmpfs_pages(&st)
    };
    vfs.tmpfs_check(dev, pages, inodes)?;
    let upper = vfs.overlay_upper(o, what)?;
    if what != CopyUp::NoData {
        vfs.tmpfs_copy_mapped_data(dev, lower, upper);
    }
    vfs.tmpfs_charge(dev, pages as i64, inodes as i64);
    Ok(upper)
}

/// Before copying up overlay directory `o` to create `name` (taking `pages` pages): verifies that
/// the upper layer's tmpfs instance has room for both the uncopied parent directories and the new
/// entry (replacing an existing upper whiteout takes no additional inode).
fn check_overlay_create_tmpfs(
    vfs: &Vfs,
    mnt: MountId,
    o: OvlId,
    name: &[u8],
    pages: u64,
) -> Result<(), Errno> {
    let Some(dev) = overlay_upper_tmpfs_dev(vfs, vfs.dev_of(&Node::Overlay(mnt, o))) else {
        return Ok(());
    };
    let dir_inodes = overlay_uncopied_dirs(vfs, &[o]);
    let replaces_whiteout = vfs
        .overlay()
        .node(o)
        .upper
        .is_some_and(|u| overlay::whiteout_at(vfs.store(), u, name).unwrap_or(false));
    let new_inodes = u64::from(!replaces_whiteout);
    vfs.tmpfs_check(dev, pages, dir_inodes + new_inodes)
}

/// Before creating a name (a new inode, or a hard link) in directory `dir` (the mount reached
/// through and the inode): in tmpfs (or an overlay whose upper layer is on tmpfs), checks whether
/// it fits, ENOSPC when it does not (Linux's `shmem_reserve_inode`; `pages` is the page a long
/// symlink needs). Returns the instance's device number, handed to [`tmpfs_created`] once created.
pub(super) fn tmpfs_reserve(
    vfs: &Vfs,
    (mnt, dir): (MountId, Ino),
    pages: u64,
) -> Result<Option<u64>, Errno> {
    let Some(dev) = backing_tmpfs_dev(vfs, &Node::Store(mnt, dir)) else {
        return Ok(None);
    };
    vfs.tmpfs_check(dev, pages, 1)?;
    Ok(Some(dev))
}

/// A name [`tmpfs_reserve`] found room for has been created: accounts it.
pub(super) fn tmpfs_created(vfs: &Vfs, dev: Option<u64>, pages: u64) {
    if let Some(dev) = dev {
        vfs.tmpfs_charge(dev, pages as i64, 1);
    }
}

/// Like [`tmpfs_reserve`], accounting for an overlay upper whiteout replaced by `name` (net 0
/// inodes).
fn tmpfs_reserve_name(
    vfs: &Vfs,
    (mnt, dir): (MountId, Ino),
    name: &[u8],
    pages: u64,
) -> Result<Option<(u64, i64)>, Errno> {
    let node = Node::Store(mnt, dir);
    let Some(dev) = backing_tmpfs_dev(vfs, &node) else {
        return Ok(None);
    };
    let replaces_whiteout =
        vfs.overlay_prefix(mnt).is_some() && overlay::whiteout_at(vfs.store(), dir, name)?;
    let inodes = u64::from(!replaces_whiteout);
    vfs.tmpfs_check(dev, pages, inodes)?;
    Ok(Some((dev, inodes as i64)))
}

/// A name [`tmpfs_reserve_name`] found room for has been created: accounts it.
fn tmpfs_created_name(vfs: &Vfs, reserved: Option<(u64, i64)>, pages: u64) {
    if let Some((dev, inodes)) = reserved {
        vfs.tmpfs_charge(dev, pages as i64, inodes);
    }
}

/// Whether `faccessat` is asking for `X_OK` on a regular file in a `noexec` mount.
fn access_noexec(vfs: &Vfs, node: &Node, amode: u32, kind: u32) -> bool {
    amode & MAY_EXEC != 0
        && kind == mode::S_IFREG
        && vfs.mount_flags(node).is_some_and(|m| m & ms::NOEXEC != 0)
}

/// Snapshot of a tmpfs regular file before a size change, passed to [`tmpfs_resized`].
#[derive(Clone, Copy)]
struct TmpfsFile {
    dev: u64,
    ino: Ino,
    pages: u64,
    size: u64,
}

/// Snapshot of a tmpfs entry about to be removed, passed to [`tmpfs_removed`].
struct TmpfsVictim {
    dev: u64,
    ino: Ino,
    pages: u64,
    object: Option<std::fs::File>,
}

/// Writing a regular file in tmpfs: writes until the instance is full (Linux's
/// `shmem_write_begin` asks page by page and returns what was already written when it cannot get
/// one), ENOSPC when not even a page can be written; pages that already hold data need nothing.
/// Returns the number of bytes allowed, plus the file snapshot that the accounting needs
/// afterwards ([`tmpfs_resized`]).
fn tmpfs_write_room(
    cx: &Cx<'_>,
    f: &OpenFile,
    offset: Option<u64>,
    len: usize,
    append: bool,
) -> Result<(usize, Option<TmpfsFile>), Errno> {
    let FileKind::Regular { ino, file, .. } = &f.kind else {
        return Ok((len, None));
    };
    let vfs = cx.vfs()?;
    let Some(t) = open_tmpfs_size(&vfs, f, *ino, file)? else {
        return Ok((len, None));
    };
    let (dev, own) = (t.dev, t.pages);
    if len == 0 || vfs.tmpfs_room(dev, own)?.is_none() {
        return Ok((len, Some(t)));
    }
    let pos = match offset {
        Some(off) => off,
        None if append || f.flags & oflags::O_APPEND != 0 => t.size,
        None => f.pos,
    };
    let end = pos.saturating_add(len as u64);
    loop {
        let room = vfs.tmpfs_room(dev, own)?.unwrap_or(u64::MAX);
        // Looking for holes only when the pages the write spans might not all fit
        let free = room.saturating_sub(own);
        if end.div_ceil(TMPFS_PAGE) - pos / TMPFS_PAGE <= free {
            return Ok((len, Some(t)));
        }
        return match vfs.tmpfs_missing(*ino, file, t.size, pos, end, free) {
            Ok(_) => Ok((len, Some(t))),
            // Short of room: the recorded usage may have drifted, so count it again first
            Err(_) if vfs.tmpfs_recount(dev)? => continue,
            Err(stop) if stop <= pos => Err(Errno::ENOSPC),
            Err(stop) => Ok(((stop - pos) as usize, Some(t))),
        };
    }
}

/// Upper-layer tmpfs accounting delta computed before an overlay removal or rename and applied
/// once the store transaction succeeds.
struct OverlayTmpfsOp {
    dev: u64,
    inodes: i64,
    victim: Option<TmpfsVictim>,
}

impl OverlayTmpfsOp {
    fn apply(self, cx: &Cx<'_>, vfs: &Vfs) {
        if self.inodes != 0 {
            vfs.tmpfs_charge(self.dev, 0, self.inodes);
        }
        tmpfs_removed(cx, vfs, self.victim);
    }
}

/// [`tmpfs_size`] for an open regular file, preserving its overlay node identity when present.
fn open_tmpfs_size(
    vfs: &Vfs,
    f: &OpenFile,
    ino: Ino,
    host: &std::fs::File,
) -> Result<Option<TmpfsFile>, Errno> {
    let node = f
        .ovl
        .map_or(Node::Store(f.mnt, ino), |o| Node::Overlay(f.mnt, o));
    tmpfs_size(vfs, &node, ino, host)
}

/// When `node` (a regular file with backing store inode `ino` and host object `host`) is in tmpfs
/// or on an overlay whose upper layer is on tmpfs, records its instance device, inode and host
/// page count: after it changes, they go to [`tmpfs_resized`] for accounting.
fn tmpfs_size(
    vfs: &Vfs,
    node: &Node,
    ino: Ino,
    host: &std::fs::File,
) -> Result<Option<TmpfsFile>, Errno> {
    let Some(dev) = backing_tmpfs_dev(vfs, node) else {
        return Ok(None);
    };
    Ok(Some(TmpfsFile {
        dev,
        ino,
        pages: vfs.tmpfs_file_pages(ino, host)?,
        size: host.metadata().map_err(host_errno)?.len(),
    }))
}

/// A regular file in tmpfs was written, truncated, reserved or punched: accounts the difference
/// in pages ([`tmpfs_size`] recorded the old count) and keeps any unlinked-open record in sync.
fn tmpfs_resized(vfs: &Vfs, tmpfs: Option<TmpfsFile>, host: &std::fs::File) {
    if let Some(t) = tmpfs
        && let Ok(pages) = vfs.tmpfs_file_pages(t.ino, host)
    {
        vfs.tmpfs_charge(t.dev, pages as i64 - t.pages as i64, 0);
        vfs.tmpfs_update_unlinked(t.dev, t.ino, pages);
    }
}

/// Before deleting `name` in directory `dir` (unlink, rmdir, overwritten by rename): in tmpfs,
/// records the instance device, inode, pages and whether this removes the last link of a regular
/// file (which stays charged until its last open descriptor or mapping closes). Handed to
/// [`tmpfs_removed`] after the deletion.
fn tmpfs_victim(
    vfs: &Vfs,
    (mnt, dir): (MountId, Ino),
    name: &[u8],
) -> Result<Option<TmpfsVictim>, Errno> {
    let Some(dev) = backing_tmpfs_dev(vfs, &Node::Store(mnt, dir)) else {
        return Ok(None);
    };
    let Some(ino) = vfs.store().lookup(dir, name)? else {
        return Ok(None);
    };
    tmpfs_victim_ino(vfs, dev, ino)
}

fn tmpfs_victim_ino(vfs: &Vfs, dev: u64, ino: Ino) -> Result<Option<TmpfsVictim>, Errno> {
    let st = vfs.store().stat(ino)?;
    let last_reg = st.kind() == mode::S_IFREG && st.nlink <= 1;
    let object = last_reg
        .then(|| vfs.store().open_object(ino, false))
        .transpose()?;
    let pages = if let Some(f) = &object {
        vfs.tmpfs_file_pages(ino, f)?
    } else if st.is_dir() || st.nlink <= 1 {
        vfs.tmpfs_pages(&st)
    } else {
        0
    };
    Ok(Some(TmpfsVictim {
        dev,
        ino,
        pages,
        object,
    }))
}

/// The name [`tmpfs_victim`] recorded has been deleted: accounts it, keeping an unlinked regular
/// file's pages and one inode charged while open or mapped (Linux's `shmem_evict_inode`).
fn tmpfs_removed(cx: &Cx<'_>, vfs: &Vfs, victim: Option<TmpfsVictim>) {
    if let Some(v) = victim {
        if let Some(object) = v.object {
            if file_in_use(cx.kr(), vfs, v.ino) {
                vfs.tmpfs_unlinked(v.dev, v.ino, v.pages, object);
                return;
            }
            vfs.tmpfs_forget_pages(v.ino, 0, u64::MAX);
        }
        vfs.tmpfs_charge(v.dev, -(v.pages as i64), -1);
    }
}

fn tmpfs_open_inode(vfs: &Vfs, file: &OpenFile) -> Option<Ino> {
    if let Some((ino, ..)) = file.path_object {
        return Some(ino);
    }
    match &file.kind {
        FileKind::Regular { ino, .. } | FileKind::Path(Node::Store(_, ino)) => Some(*ino),
        FileKind::Path(Node::Overlay(_, o)) => Some(vfs.overlay().node(*o).real()),
        _ => None,
    }
}

/// Collects all store regular-file inodes currently held open (fd tables, AF_UNIX inflight, loop
/// backing), mapped, or running as an executable. Returns `None` if a task resource is borrowed.
fn live_store_inodes(
    k: &crate::kernel::Kernel,
    vfs: &Vfs,
) -> Option<std::collections::HashSet<Ino>> {
    let mut live = std::collections::HashSet::new();
    let record = |live: &mut std::collections::HashSet<Ino>, file: &FileRef| -> Option<()> {
        let f = file.try_borrow().ok()?;
        if let Some(ino) = tmpfs_open_inode(vfs, &f) {
            live.insert(ino);
        }
        Some(())
    };
    let mut seen_mm = std::collections::HashSet::new();
    for task in k.tasks.values() {
        let res = task.res.try_borrow().ok()?;
        if seen_mm.insert(Rc::as_ptr(&res.mm) as usize) {
            let mm = res.mm.try_borrow().ok()?;
            mm.mapped_inos(&mut live);
        }
        let fds = res.fds.try_borrow().ok()?;
        for fd in fds.open_fds() {
            if let Ok(file) = fds.get(fd) {
                record(&mut live, &file)?;
            }
        }
    }
    for file in crate::unix::try_inflight_files(k)?
        .into_iter()
        .chain(k.loops.try_backing_files()?)
    {
        record(&mut live, &file)?;
    }
    for group in k.groups.values() {
        let g = group.try_borrow().ok()?;
        if !g.threads.is_empty()
            && let Some(exe) = &g.exe
            && let Some((_, ino)) = exe.node
        {
            live.insert(ino);
        }
    }
    Some(live)
}

/// Releases candidates with no remaining file, mapping, executable, unshare or inotify reference.
fn release_unused_inodes(
    k: &Kernel,
    live: &std::collections::HashSet<Ino>,
    candidates: Vec<Ino>,
    release: impl Fn(Ino) -> Result<(), Errno>,
) {
    let Ok(inotify) = k.inotify.try_borrow() else {
        return;
    };
    for ino in candidates {
        if !live.contains(&ino) && !k.unsharing.contains(&ino) && !inotify.has_open(ino) {
            let _ = release(ino);
        }
    }
}

/// Sweeps deleted held files awaiting release when any exist.
fn release_deleted_shared(k: &crate::kernel::Kernel, vfs: &Vfs) {
    let store = vfs.store();
    if !store.has_pending_release() {
        return;
    }
    if let Some(live) = live_store_inodes(k, vfs) {
        release_unused_inodes(k, &live, store.pending_releases(), |ino| store.release(ino));
    }
}

/// Whether regular store inode `ino` is still held open (fd table, AF_UNIX inflight, loop
/// backing), mapped, or running as an executable.
fn file_in_use(k: &crate::kernel::Kernel, vfs: &Vfs, ino: Ino) -> bool {
    if k.open_files()
        .into_iter()
        .chain(crate::unix::inflight_files(k))
        .chain(k.loops.backing_files())
        .any(|f| {
            f.try_borrow()
                .is_ok_and(|f| tmpfs_open_inode(vfs, &f) == Some(ino))
        })
    {
        return true;
    }
    if k.tasks
        .values()
        .any(|t| t.res.borrow().mm.borrow().maps_ino(ino))
    {
        return true;
    }
    k.groups.values().any(|g| {
        let g = g.borrow();
        !g.threads.is_empty()
            && g.exe
                .as_ref()
                .is_some_and(|e| e.node.is_some_and(|(_, i)| i == ino))
    })
}

/// Releases tmpfs page and inode charges for unlinked regular files, shared-object holds for
/// deleted held files, and unlinked linkable `O_TMPFILE` objects whose last descriptor, mapping
/// or executable reference has gone away.
pub(crate) fn evict_unlinked_tmpfs(k: &crate::kernel::Kernel, vfs: &Vfs) {
    let has_tmpfs = vfs.has_unlinked_tmpfs();
    let store = vfs.store();
    let has_shared = store.has_pending_release();
    let has_tmpfiles = store.has_linkable_tmpfiles();
    // An open record also pins descriptions held by a syscall after a concurrent close.
    // Scan mappings and executables only after the last such description is gone.
    let closed_memfds = vfs.closed_memfd_sizes(|ino| {
        k.inotify
            .try_borrow()
            .is_ok_and(|registry| !registry.has_open(*ino))
    });
    if !has_tmpfs && !has_shared && !has_tmpfiles && closed_memfds.is_empty() {
        return;
    }
    let Some(live) = live_store_inodes(k, vfs) else {
        return;
    };
    for ino in closed_memfds {
        if !live.contains(&ino) {
            vfs.clear_memfd_size(ino);
        }
    }
    if has_tmpfs {
        vfs.evict_tmpfs(&live);
    }
    if has_shared {
        release_unused_inodes(k, &live, store.pending_releases(), |ino| store.release(ino));
    }
    if has_tmpfiles {
        release_unused_inodes(k, &live, store.linkable_tmpfiles(), |ino| {
            store.release_tmpfile(ino)
        });
    }
}

// ---- Shared helpers ----

/// The program file process `proc` is executing (`/proc/<pid>/exe`).
pub(super) fn exe_file(
    cx: &Cx<'_>,
    proc: pseudo::ProcId,
) -> Result<Rc<crate::process::ExeFile>, Errno> {
    let group = pseudo::group_of_id(cx.kr(), proc)
        .cloned()
        .ok_or(Errno::ENOENT)?;
    group.borrow().exe.clone().ok_or(Errno::ENOENT)
}

/// Whether some process is executing the program `ino` in the store (opening it for write is
/// ETXTBSY).
pub(super) fn executing(cx: &Cx<'_>, ino: Ino) -> bool {
    cx.kr()
        .tasks
        .values()
        .any(|t| t.res.borrow().mm.borrow().exe == Some(ino))
}

/// A metadata copy-up changes the real inode while the running program keeps its overlay node.
fn executing_overlay(cx: &Cx<'_>, o: OvlId, real: Ino) -> bool {
    executing(cx, real)
        || cx.kr().groups.values().any(|g| {
            let g = g.borrow();
            !g.threads.is_empty()
                && g.exe
                    .as_ref()
                    .and_then(|exe| exe.ovl.as_ref())
                    .is_some_and(|(_, id, _)| *id == o)
        })
}

/// Whether `ino` is open for write (executing it is ETXTBSY).
/// fds from memfd_create do not count ([`OpenFile::pseudo`]).
pub(super) fn open_for_write(cx: &Cx<'_>, ino: Ino) -> bool {
    if let Some(id) = crate::vfs::fuse::id_of(ino)
        && let Ok(vfs) = cx.vfs()
        && vfs
            .fuse()
            .get(id)
            .and_then(|n| n.pages.upgrade())
            .is_some_and(|p| p.has_writable_open())
    {
        return true;
    }
    cx.kr().open_files().iter().any(|f| {
        let f = f.borrow();
        f.writable()
            && !f.pseudo
            && match &f.kind {
                FileKind::Regular { ino: i, .. } => *i == ino,
                // A FUSE program carries its node's key ([`crate::process`]'s open_fuse)
                FileKind::Fuse(h) => crate::vfs::fuse::key(h.id) == ino,
                _ => false,
            }
    })
}

/// Writes (write, pwrite) and length changes (ftruncate) forbidden by seals return EPERM.
/// `grow_to` is the length after the write or truncation.
fn check_seals(
    cx: &Cx<'_>,
    f: &OpenFile,
    write: bool,
    grow_to: impl FnOnce(u64) -> u64,
) -> Result<(), Errno> {
    let FileKind::Regular { ino, file, .. } = &f.kind else {
        return Ok(());
    };
    seals_permit(cx, *ino, file, write, grow_to)
}

/// [`check_seals`] for regular file `ino`, whose host object `host` gives its size.
fn seals_permit(
    cx: &Cx<'_>,
    ino: Ino,
    host: &std::fs::File,
    write: bool,
    grow_to: impl FnOnce(u64) -> u64,
) -> Result<(), Errno> {
    let Some(&seals) = cx.kr().seals.get(&ino) else {
        return Ok(());
    };
    if write && seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
        return Err(Errno::EPERM);
    }
    let size = regular_size(&*cx.vfs()?, ino, host)?;
    let new = grow_to(size);
    if (new > size && seals & F_SEAL_GROW != 0) || (new < size && seals & F_SEAL_SHRINK != 0) {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Removes the privileges of regular file `ino` before writing or truncating it
/// ([`Store::remove_privs`]): without `CAP_FSETID`, removes the setuid bit, and removes the setgid
/// bit when group-executable or when the caller is not in the file's group (Linux 6.2+
/// `setattr_should_drop_sgid`, aligned with `chown`); file capabilities are always removed.
fn remove_privs(cx: &Cx<'_>, ino: Ino) -> Result<(), Errno> {
    let cred = cx.cred();
    let vfs = cx.vfs()?;
    let st = vfs.store().attrs(ino)?;
    let keep_setid = cred.capable_wrt(&st, cap::FSETID);
    let keep_sgid = keep_setid || cred.in_group(st.gid);
    vfs.store().remove_privs(ino, keep_setid, keep_sgid)
}

/// Called before a file is cut to `len` bytes: in every address space, pages mapping it beyond
/// the new end are removed from the page tables ([`crate::mm::Mm::file_truncated`]) and every
/// address space that had some syncs at once, the current one too, so no thread can still reach
/// that tail through a stale translation when the host file shrinks (the host would raise SIGBUS
/// in the engine, ending the process as a kernel bug). Afterwards an access there faults into the
/// kernel, waits for the BKL and gets the guest's SIGBUS. Nothing happens when `len` is not
/// shorter.
pub(super) fn truncating(cx: &Cx<'_>, host: &std::fs::File, len: u64) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = host.metadata() else {
        return;
    };
    if len >= meta.len() {
        return;
    }
    change_file_maps(cx, |m| m.file_truncated(meta.dev(), meta.ino(), len));
}

pub(super) fn punch_tmpfs_maps(cx: &Cx<'_>, ino: Ino, offset: u64, end: u64) {
    change_file_maps(cx, |m| m.punch_tmpfs(ino, offset, end));
}

fn change_file_maps(cx: &Cx<'_>, mut change: impl FnMut(&mut crate::mm::Mm) -> bool) {
    let sync = cx.task.sync.clone();
    let mut seen = Vec::new();
    for t in cx.kr().tasks.values() {
        let mm = t.res.borrow().mm.clone();
        if seen.contains(&Rc::as_ptr(&mm)) {
            continue;
        }
        seen.push(Rc::as_ptr(&mm));
        let Ok(mut m) = mm.try_borrow_mut() else {
            crate::debug::log(format_args!(
                "file mapping invalidation: an address space is busy"
            ));
            continue;
        };
        if change(&mut m) {
            m.sync(&sync);
        }
    }
}

fn host_errno(e: std::io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(Errno::EIO.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combined_sync_flags_are_valid_only_for_newfstatat() {
        assert_eq!(newfstatat_flags(AT_STATX_SYNC_TYPE), Ok(()));
        assert_eq!(statx_flags(AT_STATX_SYNC_TYPE, 0), Err(Errno::EINVAL));
    }

    #[test]
    fn cap_iovecs_caps_at_max_rw_count_and_drops_trailing_vecs() {
        let mut vecs = vec![(0x1000, 0x5000_0000), (0x2000, 0x5000_0000), (0xdead, 4096)];
        cap_iovecs(&mut vecs);
        assert_eq!(vecs, vec![(0x1000, 0x5000_0000), (0x2000, 0x2fff_f000)]);

        let mut exact = vec![(0x1000, MAX_COPY), (0xdead, 1)];
        cap_iovecs(&mut exact);
        assert_eq!(exact, vec![(0x1000, MAX_COPY)]);

        let mut zeros = vec![(0x1000, 0), (0x2000, 0)];
        cap_iovecs(&mut zeros);
        assert_eq!(zeros, vec![(0x1000, 0), (0x2000, 0)]);
    }

    #[test]
    fn proc_splice_predicates_reject_unsupported_procfs_nodes() {
        let proc = pseudo::ProcId { pid: 1, serial: 0 };
        assert!(!proc_splice_reads(&PseudoNode::Entry(
            proc,
            None,
            pseudo::Entry::Status
        )));
        assert!(!proc_splice_reads(&PseudoNode::FdInfo(proc, None, 0)));
        assert!(!proc_splice_reads(&PseudoNode::NsFile(
            pseudo::NsKind::Mnt,
            1
        )));
        assert!(!proc_splice_reads(&PseudoNode::Global(
            pseudo::Global::Kmsg
        )));
        assert!(proc_splice_reads(&PseudoNode::Entry(
            proc,
            None,
            pseudo::Entry::Mounts
        )));
        assert!(proc_splice_reads(&PseudoNode::Entry(
            proc,
            None,
            pseudo::Entry::MountInfo
        )));
        assert!(proc_splice_reads(&PseudoNode::Global(
            pseudo::Global::Version
        )));
        assert!(proc_splice_reads(&PseudoNode::Sys(
            b"devices/system/cpu/online"
        )));
        assert!(proc_splice_reads(&PseudoNode::Cgroup(
            1,
            b"cgroup.procs",
            0
        )));
        assert!(!pseudo::has_iter(
            &PseudoNode::Entry(proc, None, pseudo::Entry::Comm),
            true
        ));
        assert!(pseudo::has_iter(
            &PseudoNode::Cgroup(1, b"cgroup.procs", 0),
            true
        ));
        assert!(pseudo::has_iter(
            &PseudoNode::Static(pseudo::PROTECTED_REGULAR),
            true
        ));
    }

    #[test]
    fn sticky_protection_levels_match_linux_6_1() {
        let sticky_world = mode::S_IFDIR | mode::S_ISVTX | 0o777;
        let sticky_group = mode::S_IFDIR | mode::S_ISVTX | 0o775;
        let non_sticky = mode::S_IFDIR | 0o777;
        for kind in [mode::S_IFREG | 0o666, mode::S_IFIFO | 0o666] {
            // Level 0 allows everything.
            assert!(sticky_protection_allows(kind, 1000, 0, sticky_world, 0, 0));
            // Level 1 denies in sticky world-writable dir (even for root), allows in sticky group-writable.
            assert!(!sticky_protection_allows(kind, 1000, 0, sticky_world, 0, 1));
            assert!(sticky_protection_allows(kind, 1000, 0, sticky_group, 0, 1));
            // Level 2 denies in both sticky world-writable and sticky group-writable dirs.
            assert!(!sticky_protection_allows(kind, 1000, 0, sticky_world, 0, 2));
            assert!(!sticky_protection_allows(kind, 1000, 0, sticky_group, 0, 2));
            // Owner of file, file owned by dir owner, and non-sticky dir are always allowed.
            assert!(sticky_protection_allows(
                kind,
                1000,
                1000,
                sticky_world,
                0,
                2
            ));
            assert!(sticky_protection_allows(kind, 0, 1000, sticky_world, 0, 2));
            assert!(sticky_protection_allows(kind, 1000, 0, non_sticky, 0, 2));
        }
    }

    #[test]
    fn encode_statx_populates_stx_mnt_id_and_mask() {
        let st = encode_stat(&Stat::default(), ROOT_DEV);
        for id in [0, 42] {
            let raw = encode_statx(&st, id);
            assert_eq!(u32::from_le_bytes(raw[..4].try_into().unwrap()), 0x17ff);
            assert_eq!(
                u64::from_le_bytes(raw[144..152].try_into().unwrap()),
                u64::from(id)
            );
        }
    }

    fn with_guest(uid: u32, run: impl FnOnce(&mut Cx<'_>, u64, &mut appine_engine::Cpu)) {
        use crate::kernel::Shared;
        let dir = std::env::temp_dir().join(format!(
            "appine-fs-{}-{}-{}",
            std::process::id(),
            crate::tty::wall_ns(),
            crate::vfs::new_ns_id()
        ));
        {
            let store = Store::create(&dir).unwrap();
            dev::ensure_dev_nodes(&store).unwrap();
            store
                .mkdir(crate::vfs::store::ROOT, b"tmp", 0o1777, 0, 0)
                .unwrap();
        }
        let mut kernel = Kernel::new(crate::process::Tier::Interpreter);
        kernel.vfs = Some(Rc::new(Vfs::open(&dir).unwrap()));
        let (proc, buf, mut cpu) =
            pseudo::tests::add_task(&mut kernel, 20, uid, true, b"USER_KEY=hello\0");
        let shared = std::sync::Arc::new(Shared::new(kernel));
        {
            let k = shared.lock();
            let task = k.tasks[&proc.pid].clone();
            let mut state = task.state.borrow_mut();
            run(&mut Cx::new(&shared, k, &task, &mut state), buf, &mut cpu);
        }
        drop(cpu);
        drop(shared);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memfd_max_length_reads_seeks_and_shrinks() {
        with_guest(0, |cx, addr, _| {
            write_cstr(cx, addr, b"sparse");
            let fd = memfd_create(cx, addr, 2).unwrap() as i32;
            assert_eq!(write(cx, fd, addr, 6), Ok(6));
            let file = cx.fds().get(fd).unwrap();
            {
                let f = file.borrow();
                let (ino, host, _) = f.regular_backing().unwrap();
                cx.vfs()
                    .unwrap()
                    .store()
                    .set_times_open(ino, host, None, Some(FileTime::At(0)))
                    .unwrap();
            }
            let max = i64::MAX;
            assert_eq!(ftruncate(cx, fd, max), Ok(0));
            fstat(cx, fd, addr + 128).unwrap();
            assert_eq!(i64::from_le_bytes(get(cx, addr + 128 + 48).unwrap()), max);
            assert!(i64::from_le_bytes(get(cx, addr + 128 + 88).unwrap()) > 0);
            let ino = file.borrow().data_ino().unwrap();
            assert_eq!(pread(cx, fd, addr, 16, max - 8), Err(Errno::EINVAL));
            assert_eq!(pread(cx, fd, addr, 10, max), Err(Errno::EINVAL));
            assert_eq!(pread(cx, fd, addr, 1, max), Err(Errno::EINVAL));
            assert_eq!(pread(cx, fd, addr, 1, -1), Err(Errno::EINVAL));
            assert_eq!(pread(cx, fd, addr, 4, max - 4), Ok(4));
            assert_eq!(get::<4>(cx, addr).unwrap(), [0; 4]);
            assert_eq!(pread(cx, fd, addr, 8, 2), Ok(8));
            assert_eq!(&get::<8>(cx, addr).unwrap(), b"arse\0\0\0\0");
            assert_eq!(lseek(cx, fd, 0, SEEK_END), Ok(max as u64));
            assert_eq!(lseek(cx, fd, max, SEEK_HOLE), Err(Errno::ENXIO));
            assert_eq!(lseek(cx, fd, max - 1, SEEK_DATA), Err(Errno::ENXIO));
            assert_eq!(lseek(cx, fd, max - 1, SEEK_HOLE), Ok(max as u64 - 1));
            assert_eq!(read(cx, fd, addr, 1), Ok(1));
            assert_eq!(file.borrow().pos, max as u64);
            let link = format!("/proc/self/fd/{fd}");
            write_cstr(cx, addr, link.as_bytes());
            newfstatat(cx, AT_FDCWD, addr, addr + 128, 0).unwrap();
            assert_eq!(i64::from_le_bytes(get(cx, addr + 128 + 48).unwrap()), max);
            assert_eq!(truncate(cx, addr, max - 4096), Ok(0));
            assert_eq!(lseek(cx, fd, 0, SEEK_END), Ok(max as u64 - 4096));
            assert_eq!(read(cx, fd, addr, 1), Ok(0));
            assert_eq!(ftruncate(cx, fd, 4096), Ok(0));
            assert_eq!(lseek(cx, fd, 0, SEEK_END), Ok(4096));
            assert_eq!(cx.vfs().unwrap().memfd_size(ino), None);
            assert_eq!(ftruncate(cx, fd, max), Ok(0));
            assert_eq!(fcntl(cx, fd, F_ADD_SEALS, F_SEAL_SHRINK.into()), Ok(0));
            assert_eq!(ftruncate(cx, fd, 4096), Err(Errno::EPERM));
        });
    }

    #[test]
    fn sparse_memfd_vectored_io_copies_and_seals() {
        with_guest(0, |cx, addr, _| {
            let dst = open(
                cx,
                addr,
                b"/tmp/copy",
                oflags::O_CREAT | oflags::O_RDWR,
                0o600,
            )
            .unwrap();
            write_cstr(cx, addr, b"data");
            let fd = memfd_create(cx, addr, 2).unwrap() as i32;
            assert_eq!(write(cx, fd, addr, 4), Ok(4));
            let end = i64::MAX - 4096;
            assert_eq!(ftruncate(cx, fd, end), Ok(0));
            assert_eq!(fcntl(cx, fd, F_ADD_SEALS, F_SEAL_GROW.into()), Ok(0));
            assert_eq!(ftruncate(cx, fd, end + 1), Err(Errno::EPERM));
            assert_eq!(pwrite(cx, fd, addr, 4, 4), Ok(4));
            assert_eq!(fallocate(cx, fd, 3, end - 4096, 4096), Ok(0));
            assert_eq!(fallocate(cx, fd, 3, i64::MAX - 1, 2), Err(Errno::EFBIG));

            let offset = addr + 128;
            let buf = addr + 256;
            put(cx, offset, 4_i64.to_le_bytes()).unwrap();
            assert_eq!(sendfile(cx, dst, fd, offset, 8), Ok(8));
            assert_eq!(i64::from_le_bytes(get(cx, offset).unwrap()), 12);
            put(cx, offset, (end - 3).to_le_bytes()).unwrap();
            assert_eq!(copy_file_range(cx, fd, offset, dst, 0, 8, 0), Ok(3));
            assert_eq!(pread(cx, dst, buf, 11, 0), Ok(11));
            assert_eq!(&get::<11>(cx, buf).unwrap(), b"data\0\0\0\0\0\0\0");

            // Check the complete iovec length before returning any of the first iovec.
            put(cx, offset, buf.to_le_bytes()).unwrap();
            put(cx, offset + 8, 2_u64.to_le_bytes()).unwrap();
            put(cx, offset + 16, (buf + 4).to_le_bytes()).unwrap();
            put(cx, offset + 24, 2_u64.to_le_bytes()).unwrap();
            assert_eq!(
                pvectored(cx, fd, offset, 2, i64::MAX - 2, Some(0), false),
                Err(Errno::EINVAL)
            );
            put(cx, buf, [0xff; 8]).unwrap();
            assert_eq!(lseek(cx, fd, end - 3, SEEK_SET), Ok((end - 3) as u64));
            assert_eq!(ioctl(cx, fd, FIONREAD, addr), Ok(0));
            assert_eq!(i32::from_le_bytes(get(cx, addr).unwrap()), 3);
            assert_eq!(readv(cx, fd, offset, 2), Ok(3));
            assert_eq!(
                get::<8>(cx, buf).unwrap(),
                [0, 0, 255, 255, 0, 255, 255, 255]
            );
            assert_eq!(fcntl(cx, fd, F_SETFL, oflags::O_APPEND.into()), Ok(0));
            assert_eq!(write(cx, fd, buf, 1), Err(Errno::EPERM));
            assert_eq!(pwrite(cx, fd, buf, 1, 0), Err(Errno::EPERM));
            assert_eq!(
                pvectored(cx, fd, offset, 2, 0, Some(RWF_NOAPPEND), true),
                Ok(4)
            );
        });
    }

    #[test]
    fn large_file_fallback_is_scoped_to_live_memfds() {
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let fd = open(
                cx,
                addr,
                b"/tmp/ordinary",
                oflags::O_CREAT | oflags::O_RDWR,
                0o600,
            )
            .unwrap();
            let file = cx.fds().get(fd).unwrap();
            let ino = file.borrow().data_ino().unwrap();
            let expected = vfs
                .store()
                .open_object(ino, true)
                .unwrap()
                .set_len(i64::MAX as u64)
                .map_err(host_errno);
            assert_eq!(ftruncate(cx, fd, i64::MAX), expected.map(|()| 0));
            assert_eq!(vfs.memfd_size(ino), None);
            write_cstr(cx, addr, b"anonymous");
            let mem = memfd_create(cx, addr, 0).unwrap() as i32;
            let held = cx.fds().get(mem).unwrap();
            let ino = held.borrow().data_ino().unwrap();
            assert_eq!(ftruncate(cx, mem, i64::MAX), Ok(0));
            let before = vfs.memfd_size(ino);
            let physical = held
                .borrow()
                .regular_backing()
                .unwrap()
                .1
                .metadata()
                .unwrap()
                .len();
            assert_eq!(
                before,
                (physical < i64::MAX as u64).then_some(i64::MAX as u64)
            );
            close(cx, mem).unwrap();
            evict_unlinked_tmpfs(cx.kr(), &vfs);
            assert_eq!(vfs.memfd_size(ino), before);
            drop(held);
            evict_unlinked_tmpfs(cx.kr(), &vfs);
            assert_eq!(vfs.memfd_size(ino), None);
        });
    }

    fn mountpoint(vfs: &Vfs, name: &[u8]) -> (Node, Option<Dentry>) {
        let ino = vfs
            .store()
            .mkdir(crate::vfs::store::ROOT, name, 0o755, 0, 0)
            .unwrap();
        (
            Node::Store(crate::vfs::ROOT_MOUNT, ino),
            Some((Node::ROOT, name.to_vec())),
        )
    }

    fn mount_tmpfs(vfs: &Vfs, inodes: u64) -> MountId {
        vfs.new_tmpfs(
            mountpoint(vfs, b"mnt"),
            0,
            b"tmpfs".to_vec(),
            crate::vfs::TmpfsParams {
                blocks: 16,
                inodes,
                perm: 0o1777,
                uid: 0,
                gid: 0,
                inode64: true,
            },
        )
        .unwrap()
    }

    fn bind_tmp(vfs: &Vfs, name: &[u8], flags: u64) -> MountId {
        let tmp = vfs
            .store()
            .lookup(crate::vfs::store::ROOT, b"tmp")
            .unwrap()
            .unwrap();
        vfs.add_mount(
            Fs::Store,
            Node::Store(crate::vfs::ROOT_MOUNT, tmp),
            mountpoint(vfs, name),
            flags,
            b"rootfs".to_vec(),
            Some(ROOT_DEV),
        )
    }

    fn write_cstr(cx: &Cx<'_>, addr: u64, path: &[u8]) {
        let mut bytes = path.to_vec();
        bytes.push(0);
        cx.mm()
            .write(UserSlice::new(addr, bytes.len()), &bytes)
            .unwrap();
    }

    fn open(cx: &mut Cx<'_>, addr: u64, path: &[u8], flags: u32, mode: u32) -> Result<i32, Errno> {
        write_cstr(cx, addr, path);
        openat(cx, AT_FDCWD, addr, flags, mode).map(|fd| fd as i32)
    }

    fn link_fd(cx: &mut Cx<'_>, addr: u64, fd: i32, dst: &[u8], flags: u32) -> SysResult {
        let (src, dirfd) = if flags == AT_EMPTY_PATH {
            (String::new(), fd)
        } else {
            (format!("/proc/self/fd/{fd}"), AT_FDCWD)
        };
        write_cstr(cx, addr, src.as_bytes());
        write_cstr(cx, addr + 256, dst);
        linkat(cx, dirfd, addr, AT_FDCWD, addr + 256, flags)
    }

    fn check_statx_mount(
        cx: &mut Cx<'_>,
        addr: u64,
        dirfd: i32,
        path: &[u8],
        flags: u32,
        expected: MountId,
    ) {
        write_cstr(cx, addr, path);
        let buf = addr + 512;
        assert_eq!(statx(cx, dirfd, addr, flags, 0x17ff, buf), Ok(0));
        let raw = get::<256>(cx, buf).unwrap();
        assert_ne!(
            u32::from_le_bytes(raw[..4].try_into().unwrap()) & 0x1000,
            0,
            "{path:?}"
        );
        assert_eq!(
            u64::from_le_bytes(raw[144..152].try_into().unwrap()),
            u64::from(expected),
            "{path:?}"
        );
    }

    #[test]
    fn anonymous_inode_metadata_is_shared_and_uses_the_creator() {
        with_guest(1000, |cx, addr, _| {
            let mut creator = cx.cred();
            creator.fsgid = 2000;
            cx.set_cred(creator.clone());
            pipe2(cx, addr, 0).unwrap();
            let (r, w) = (
                i32::from_le_bytes(get(cx, addr).unwrap()),
                i32::from_le_bytes(get(cx, addr + 4).unwrap()),
            );
            let sock = super::super::net::socket(cx, crate::net::AF_UNIX, 1, 0).unwrap() as i32;
            let read_stat = |cx: &Cx<'_>, fd| file_stat(cx, &cx.fds().get(fd).unwrap()).unwrap();
            let word = |s: &[u8; 128], i| u32::from_le_bytes(s[i..i + 4].try_into().unwrap());
            let seconds = |s: &[u8; 128], i| i64::from_le_bytes(s[i..i + 8].try_into().unwrap());
            for (fd, other, kind, initial) in [
                (r, w, mode::S_IFIFO, 0o600),
                (sock, sock, mode::S_IFSOCK, 0o777),
            ] {
                let st = read_stat(cx, fd);
                assert_eq!(
                    (word(&st, 16), word(&st, 24), word(&st, 28)),
                    (kind | initial, 1000, 2000)
                );
                assert_eq!(st, read_stat(cx, other));
                for off in [72, 88, 104] {
                    assert_eq!(seconds(&st, off) > 0, fd == r);
                }
                write_cstr(cx, addr, format!("/proc/self/fd/{fd}").as_bytes());
                assert_eq!(fchmodat(cx, AT_FDCWD, addr, 0o6750), Ok(0));
                assert_eq!(word(&read_stat(cx, other), 16), kind | 0o6750);
                put(cx, addr, [0; 32]).unwrap();
                put(cx, addr, 42i64.to_le_bytes()).unwrap();
                put(cx, addr + 16, 43i64.to_le_bytes()).unwrap();
                write_cstr(cx, addr + 64, b"");
                utimensat(cx, fd, addr + 64, addr, AT_EMPTY_PATH).unwrap();
                assert_eq!(seconds(&read_stat(cx, other), 72), 42);
                assert_eq!(seconds(&read_stat(cx, other), 88), 43);
                cx.set_cred(Cred::root());
                fchownat(cx, fd, addr + 64, 3000, 4000, AT_EMPTY_PATH).unwrap();
                let st = read_stat(cx, other);
                assert_eq!(
                    (word(&st, 16), word(&st, 24), word(&st, 28)),
                    (kind | 0o750, 3000, 4000)
                );
                if let FileKind::Socket(s) = &cx.fds().get(fd).unwrap().borrow().kind {
                    assert_eq!(s.borrow().uid(), 3000);
                }
                cx.set_cred(creator.clone());
                assert_eq!(fchmod(cx, fd, 0o777), Err(Errno::EPERM));
                assert_eq!(fchown(cx, fd, 1000, 2000), Err(Errno::EPERM));
                assert_eq!(utimensat(cx, fd, 0, addr, 0), Err(Errno::EPERM));
                assert_eq!(utimensat(cx, fd, 0, 0, 0), Err(Errno::EACCES));
            }
            assert_eq!(write(cx, w, addr, 1), Ok(1));
            assert!(seconds(&read_stat(cx, r), 88) > 43);
            assert_eq!(read(cx, r, addr, 1), Ok(1));
            assert!(seconds(&read_stat(cx, w), 72) > 42);
        });
    }

    #[test]
    fn socket_owner_survives_credential_changes_before_first_stat() {
        use super::super::net;
        use crate::net::{AF_INET, AF_NETLINK, AF_UNIX, SOCK_DGRAM, SOCK_STREAM};
        for (uid, gid) in [(1000, 3000), (4000, 5000)] {
            with_guest(1000, |cx, addr, _| {
                // Queue both connections under the listener's credentials before accepting.
                let mut listeners = Vec::new();
                for family in [AF_UNIX, AF_INET] {
                    let listener = net::socket(cx, family, SOCK_STREAM as u32, 0).unwrap() as i32;
                    let client = net::socket(cx, family, SOCK_STREAM as u32, 0).unwrap() as i32;
                    let len = if family == AF_UNIX {
                        put(cx, addr, [1, 0, 0, b's']).unwrap();
                        4
                    } else {
                        put(cx, addr, [2, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
                        16
                    };
                    net::bind(cx, listener, addr, len).unwrap();
                    net::listen(cx, listener, 1).unwrap();
                    put(cx, addr + 32, len.to_le_bytes()).unwrap();
                    net::getsockname(cx, listener, addr, addr + 32).unwrap();
                    net::connect(cx, client, addr, len).unwrap();
                    listeners.push(listener);
                }
                let mut cred = cx.cred();
                cred.fsgid = 2000;
                cx.set_cred(cred.clone());
                let mut sockets = Vec::new();
                for listener in listeners {
                    sockets.push(net::accept4(cx, listener, 0, 0, 0).unwrap() as i32);
                }
                for family in [AF_UNIX, AF_INET, AF_NETLINK] {
                    sockets.push(net::socket(cx, family, SOCK_DGRAM as u32, 0).unwrap() as i32);
                }
                net::socketpair(cx, AF_UNIX, SOCK_STREAM as u32, 0, addr).unwrap();
                for off in [0, 4] {
                    sockets.push(i32::from_le_bytes(get(cx, addr + off).unwrap()));
                }

                cred.fsuid = uid;
                cred.fsgid = gid;
                cx.set_cred(cred);
                let stat_owner = |cx: &mut Cx<'_>, fd| {
                    fstat(cx, fd, addr).unwrap();
                    (
                        u32::from_le_bytes(get(cx, addr + 24).unwrap()),
                        u32::from_le_bytes(get(cx, addr + 28).unwrap()),
                    )
                };
                for &fd in &sockets {
                    assert_eq!(stat_owner(cx, fd), (1000, 2000));
                }
                cx.set_cred(Cred::root());
                for &fd in &sockets {
                    fchown(cx, fd, u32::MAX, 6000).unwrap();
                    assert_eq!(stat_owner(cx, fd), (1000, 6000));
                }

                // Standalone guests read and change ownership directly on the socket.
                cx.k().vfs = None;
                cx.t.vfs = None;
                for fd in sockets {
                    fchown(cx, fd, 7000, u32::MAX).unwrap();
                    assert_eq!(stat_owner(cx, fd), (7000, 6000));
                }
            });
        }
    }

    #[test]
    fn ptmx_master_reports_the_opened_device() {
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let store = vfs.store();
            let lower = store
                .mkdir(crate::vfs::store::ROOT, b"lower", 0o755, 0, 0)
                .unwrap();
            store.mkdir(lower, b"pts", 0o755, 0, 0).unwrap();
            store
                .mknod(lower, b"ptmx", mode::S_IFCHR | 0o620, PTMX_RDEV, 123, 456)
                .unwrap();
            let upper = store
                .mkdir(crate::vfs::store::ROOT, b"upper", 0o755, 0, 0)
                .unwrap();
            vfs.new_overlay(
                mountpoint(&vfs, b"merged"),
                0,
                b"overlay".to_vec(),
                ((Some(upper), vec![lower]), (0, 0), Vec::new()),
                overlay::Options::default(),
            );
            let pts = lookup_at(cx, AT_FDCWD, b"/merged/pts", true).unwrap();
            vfs.add_mount(
                Fs::Pts,
                Fs::Pts.root(),
                (pts, None),
                0,
                b"devpts".to_vec(),
                Some(crate::tty::BOOT_PTS),
            );
            for path in [b"/dev/ptmx".as_slice(), b"/dev/pts/ptmx", b"/merged/ptmx"] {
                let fd = open(cx, addr, path, oflags::O_RDWR, 0).unwrap();
                newfstatat(cx, AT_FDCWD, addr, addr + 256, 0).unwrap();
                fstat(cx, fd, addr + 512).unwrap();
                let path_stat = get::<128>(cx, addr + 256).unwrap();
                let fd_stat = get::<128>(cx, addr + 512).unwrap();
                // devpts synthesizes its ptmx timestamps at each stat.
                if path == b"/dev/pts/ptmx" {
                    assert_eq!(path_stat[..72], fd_stat[..72]);
                } else {
                    assert_eq!(path_stat, fd_stat);
                }
            }
        });
    }

    fn set_inode_flags(cx: &mut Cx<'_>, fd: i32, addr: u64, flags: u32) -> SysResult {
        put(cx, addr, flags.to_le_bytes())?;
        ioctl(cx, fd, FS_IOC_SETFLAGS, addr)
    }

    #[test]
    fn inode_flags_control_open_fds_and_namespace_changes() {
        use inode_flags::*;
        use oflags::*;
        with_guest(0, |cx, addr, _| {
            let arg = addr + 512;
            mount_tmpfs(&cx.vfs().unwrap(), 32);
            for dir in [b"/tmp".as_slice(), b"/mnt"] {
                let dirfd = open(cx, addr, dir, O_DIRECTORY, 0).unwrap();
                write_cstr(cx, addr, b"src");
                let src = openat(cx, dirfd, addr, O_CREAT | O_RDWR, 0o666).unwrap() as i32;
                write_cstr(cx, addr, b"dst");
                let dst = openat(cx, dirfd, addr, O_CREAT | O_RDWR, 0o666).unwrap() as i32;
                write(cx, src, addr, 3).unwrap();
                put(cx, arg, [0xac; 8]).unwrap();
                set_inode_flags(cx, dst, arg, IMMUTABLE | NODUMP | NOATIME).unwrap();
                ioctl(cx, dst, FS_IOC_GETFLAGS, arg).unwrap();
                assert_eq!(
                    get::<8>(cx, arg).unwrap(),
                    [0xd0, 0, 0, 0, 0xac, 0xac, 0xac, 0xac]
                );
                statx(cx, dirfd, addr, 0, 0, arg).unwrap();
                assert_eq!(
                    u64::from_le_bytes(get(cx, arg + 8).unwrap()),
                    u64::from(IMMUTABLE | NODUMP)
                );
                assert_eq!(
                    u64::from_le_bytes(get(cx, arg + 56).unwrap()),
                    u64::from(STATX)
                );
                let denied = Err(Errno::EPERM);
                write_cstr(cx, addr + 64, b"other");
                assert_eq!(openat(cx, dirfd, addr, O_WRONLY, 0), denied);
                assert_eq!(faccessat(cx, dirfd, addr, MAY_WRITE, 0), denied);
                assert_eq!(unlinkat(cx, dirfd, addr, 0), denied);
                assert_eq!(renameat2(cx, dirfd, addr, dirfd, addr + 64, 0), denied);
                assert_eq!(linkat(cx, dirfd, addr, dirfd, addr + 64, 0), denied);
                assert_eq!(fchmod(cx, dst, 0o600), denied);
                assert_eq!(fchown(cx, dst, 0, 0), denied);
                assert_eq!(utimensat(cx, dst, 0, 0, 0), denied);
                assert_eq!(ftruncate(cx, dst, 12), denied);
                write_cstr(cx, addr + 128, &[dir, b"/dst"].concat());
                assert_eq!(truncate(cx, addr + 128, 12), denied);
                assert_eq!(fallocate(cx, dst, 0, 0, 32), denied);
                assert_eq!(write(cx, dst, addr, 1), denied);
                assert_eq!(copy_file_range(cx, src, 0, dst, 0, 1, 0), denied);
                assert_eq!(sendfile(cx, dst, src, 0, 1), denied);
                assert_eq!(ioctl(cx, dst, FICLONE, src as u64), denied);
                set_inode_flags(cx, dst, arg, APPEND).unwrap();
                assert_eq!(openat(cx, dirfd, addr, O_WRONLY, 0), denied);
                assert_eq!(openat(cx, dirfd, addr, O_RDONLY | O_TRUNC, 0), denied);
                let append = openat(cx, dirfd, addr, O_RDWR | O_APPEND, 0).unwrap() as i32;
                assert_eq!(fcntl(cx, append, F_SETFL, 0), denied);
                assert_eq!(
                    copy_file_range(cx, src, 0, append, 0, 1, 0),
                    Err(Errno::EBADF)
                );
                assert_eq!(copy_file_range(cx, src, 0, dst, 0, 1, 0), denied);
                assert_eq!(fallocate(cx, dst, 3, 0, 32), denied);
                assert_eq!(utimensat(cx, dst, 0, 0, 0), Ok(0));
                assert_eq!(pwrite(cx, dst, addr, 1, 0), Ok(1));
                assert_eq!(pwrite(cx, dst, addr + 1, 1, 0), Ok(1));
                assert_eq!(pread(cx, dst, arg, 2, 0), Ok(2));
                assert_eq!(&get::<2>(cx, arg).unwrap(), b"ds");
                assert_eq!(cx.fds().get(dst).unwrap().borrow().pos, 0);
                set_inode_flags(cx, dst, arg, 0).unwrap();
                set_inode_flags(cx, dirfd, arg, APPEND).unwrap();
                write_cstr(cx, addr, b"sub");
                mkdirat(cx, dirfd, addr, 0o755).unwrap();
                assert_eq!(unlinkat(cx, dirfd, addr, AT_REMOVEDIR), denied);
                set_inode_flags(cx, dirfd, arg, IMMUTABLE).unwrap();
                assert_eq!(mkdirat(cx, dirfd, addr + 64, 0o777), denied);
                assert_eq!(
                    openat(cx, dirfd, addr + 64, O_CREAT | O_RDWR, 0o600),
                    denied
                );
                set_inode_flags(cx, dirfd, arg, 0).unwrap();
                let sub = openat(cx, dirfd, addr, O_DIRECTORY, 0).unwrap() as i32;
                set_inode_flags(cx, sub, arg, IMMUTABLE).unwrap();
                assert_eq!(unlinkat(cx, dirfd, addr, AT_REMOVEDIR), denied);
            }
        });
    }

    fn set_test_xattr(cx: &mut Cx<'_>, addr: u64, fd: i32, name: &[u8], value: &[u8]) -> SysResult {
        use super::super::xattr::{Target, setxattr};
        write_cstr(cx, addr, name);
        cx.mm()
            .write(UserSlice::new(addr + 128, value.len()), value)?;
        setxattr(cx, Target::Fd(fd), addr, addr + 128, value.len(), 0)
    }

    fn test_access_acl(named: bool) -> Vec<u8> {
        use crate::vfs::acl::{ACL_USER, acl_encode};
        let id = u32::MAX;
        let mut entries = vec![(0x01, 7, id), (0x04, 4, id), (0x20, 0, id)];
        if named {
            entries.insert(1, (ACL_USER, 5, 1234));
            entries.insert(3, (0x10, 5, id));
        }
        acl_encode(&entries)
    }

    #[test]
    fn protected_inode_xattrs_preserve_values_and_mode() {
        use super::super::xattr::{Target, getxattr, listxattr, removexattr};
        use crate::vfs::acl::{ACL_ACCESS, ACL_DEFAULT};
        with_guest(0, |cx, addr, _| {
            mount_tmpfs(&cx.vfs().unwrap(), 32);
            bind_tmp(&cx.vfs().unwrap(), b"ro", ms::RDONLY);
            let acl = test_access_acl(true);
            let mode_acl = test_access_acl(false);
            let extra: [(&[u8], &[u8]); 4] = [
                (ACL_ACCESS, &mode_acl),
                (ACL_ACCESS, &[0]),
                (ACL_DEFAULT, &acl),
                (b"system.unknown", &[]),
            ];
            let mut caps = [0u8; 20];
            caps[3] = 2; // VFS_CAP_REVISION_2
            for dir in ["/tmp", "/mnt"] {
                let file = open(
                    cx,
                    addr,
                    format!("{dir}/file").as_bytes(),
                    oflags::O_RDWR | oflags::O_CREAT,
                    0o644,
                )
                .unwrap();
                let directory = open(cx, addr, dir.as_bytes(), oflags::O_DIRECTORY, 0).unwrap();
                for fd in [file, directory] {
                    let target = Target::Fd(fd);
                    let mut attrs = vec![
                        (b"user.test".as_slice(), b"original".as_slice()),
                        (b"trusted.test", b"trusted"),
                        (b"security.test", b"security"),
                        (ACL_ACCESS, acl.as_slice()),
                    ];
                    if fd == file {
                        attrs.push((crate::cred::XATTR_NAME_CAPS, &caps));
                    } else {
                        attrs.push((ACL_DEFAULT, &acl));
                    }
                    for &(name, value) in &attrs {
                        set_test_xattr(cx, addr, fd, name, value).unwrap();
                    }
                    fstat(cx, fd, addr).unwrap();
                    let mode = get::<4>(cx, addr + 16).unwrap();
                    for flag in [inode_flags::IMMUTABLE, inode_flags::APPEND] {
                        set_inode_flags(cx, fd, addr, flag).unwrap();
                        for &(name, value) in attrs.iter().chain(&extra) {
                            assert_eq!(
                                set_test_xattr(cx, addr, fd, name, value),
                                Err(Errno::EPERM)
                            );
                            assert_eq!(removexattr(cx, target, addr), Err(Errno::EPERM));
                        }
                        let len = listxattr(cx, target, addr, 512).unwrap() as usize;
                        let mut names = vec![0; len];
                        cx.mm().read(UserSlice::new(addr, len), &mut names).unwrap();
                        for &(name, value) in &attrs {
                            assert!(names.split(|b| *b == 0).any(|n| n == name));
                            write_cstr(cx, addr, name);
                            assert_eq!(
                                getxattr(cx, target, addr, addr + 128, 128),
                                Ok(value.len() as u64)
                            );
                            let mut read = vec![0; value.len()];
                            cx.mm()
                                .read(UserSlice::new(addr + 128, read.len()), &mut read)
                                .unwrap();
                            assert_eq!(read, value);
                        }
                        fstat(cx, fd, addr).unwrap();
                        assert_eq!(get::<4>(cx, addr + 16).unwrap(), mode);
                        if dir == "/tmp" && fd == file {
                            let ro = open(cx, addr, b"/ro/file", oflags::O_RDONLY, 0).unwrap();
                            assert_eq!(
                                set_test_xattr(cx, addr, ro, ACL_ACCESS, &[0]),
                                Err(Errno::EROFS)
                            );
                        }
                    }
                    set_inode_flags(cx, fd, addr, 0).unwrap();
                }
            }
        });
    }

    fn mount_test_overlay(vfs: &Vfs) -> (Ino, Ino) {
        let root = crate::vfs::store::ROOT;
        let lower = vfs.store().mkdir(root, b"lower", 0o755, 0, 0).unwrap();
        let upper = vfs.store().mkdir(root, b"upper", 0o755, 0, 0).unwrap();
        vfs.new_overlay(
            mountpoint(vfs, b"merged"),
            0,
            b"overlay".to_vec(),
            ((Some(upper), vec![lower]), (0, 0), Vec::new()),
            overlay::Options::default(),
        );
        (lower, upper)
    }

    #[test]
    fn protected_overlay_xattrs_check_the_lower_before_copy_up() {
        use super::super::xattr::{Target, removexattr};
        use crate::vfs::acl::{ACL_ACCESS, ACL_DEFAULT};
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let (lower, upper) = mount_test_overlay(&vfs);
            let store = vfs.store();
            let (ino, _) = store.create_file(lower, b"file", 0o750, 0, 0).unwrap();
            let acl = test_access_acl(true);
            store
                .set_xattr(ino, b"user.lower", b"value", false, false)
                .unwrap();
            store
                .set_xattr(ino, ACL_ACCESS, &acl, false, false)
                .unwrap();
            let fd = open(cx, addr, b"/merged/file", oflags::O_RDONLY, 0).unwrap();
            for flag in [inode_flags::IMMUTABLE, inode_flags::APPEND] {
                store.set_flags(ino, flag).unwrap();
                for name in [b"user.lower".as_slice(), ACL_ACCESS, ACL_DEFAULT] {
                    assert_eq!(set_test_xattr(cx, addr, fd, name, &acl), Err(Errno::EPERM));
                    assert_eq!(removexattr(cx, Target::Fd(fd), addr), Err(Errno::EPERM));
                }
                assert_eq!(store.lookup(upper, b"file").unwrap(), None);
            }
            store.set_flags(ino, 0).unwrap();
            set_test_xattr(cx, addr, fd, b"user.upper", b"new").unwrap();
            let copied = store.lookup(upper, b"file").unwrap().unwrap();
            assert_eq!(store.get_xattr(copied, b"user.lower").unwrap(), b"value");
            assert_eq!(store.get_xattr(copied, ACL_ACCESS).unwrap(), acl);
        });
    }

    fn check_protected_mappings(
        cx: &mut Cx<'_>,
        fd: i32,
        shared_error: Option<Errno>,
        write_error: Errno,
    ) {
        use super::super::mem::{mmap, mprotect, munmap};
        use crate::mm::flags::{MAP_PRIVATE, MAP_SHARED};
        use appine_engine::{PAGE_SIZE, prot};
        let rw = prot::READ | prot::WRITE;
        for shared in [MAP_SHARED, 3 /* MAP_SHARED_VALIDATE */] {
            assert_eq!(mmap(cx, 0, PAGE_SIZE, rw, shared, fd, 0), Err(write_error));
            let read = mmap(cx, 0, PAGE_SIZE, prot::READ, shared, fd, 0);
            if let Some(error) = shared_error {
                assert_eq!(read, Err(error));
            } else {
                let va = read.unwrap();
                assert_eq!(mprotect(cx, va, PAGE_SIZE, rw), Err(Errno::EACCES));
                munmap(cx, va, PAGE_SIZE).unwrap();
            }
        }
        let va = mmap(cx, 0, PAGE_SIZE, rw, MAP_PRIVATE, fd, 0).unwrap();
        munmap(cx, va, PAGE_SIZE).unwrap();
    }

    #[test]
    fn protected_inode_flags_control_shared_mappings() {
        use oflags::*;
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            mount_tmpfs(&vfs, 32);
            let (lower, upper) = mount_test_overlay(&vfs);
            let (ino, _) = vfs
                .store()
                .create_file(lower, b"file", 0o644, 0, 0)
                .unwrap();
            let lower_fd = open(cx, addr, b"/merged/file", O_RDONLY, 0).unwrap();
            for flag in [inode_flags::IMMUTABLE, inode_flags::APPEND] {
                vfs.store().set_flags(ino, flag).unwrap();
                check_protected_mappings(cx, lower_fd, None, Errno::EACCES);
                assert_eq!(vfs.store().lookup(upper, b"file").unwrap(), None);
            }
            vfs.store().set_flags(ino, 0).unwrap();
            write_cstr(cx, addr, b"mapped");
            let memfd = memfd_create(cx, addr, 0).unwrap() as i32;
            let mem_path = format!("/proc/self/fd/{memfd}");
            for path in ["/tmp/file", "/mnt/file", "/merged/file", &mem_path] {
                let fd = if path == mem_path {
                    memfd
                } else {
                    open(cx, addr, path.as_bytes(), O_CREAT | O_RDWR, 0o644).unwrap()
                };
                ftruncate(cx, fd, appine_engine::PAGE_SIZE as i64).unwrap();
                set_inode_flags(cx, fd, addr, inode_flags::IMMUTABLE).unwrap();
                check_protected_mappings(cx, fd, None, Errno::EPERM);
                set_inode_flags(cx, fd, addr, inode_flags::APPEND).unwrap();
                let append = open(cx, addr, path.as_bytes(), O_RDWR | O_APPEND, 0).unwrap();
                for writable in [fd, append] {
                    check_protected_mappings(cx, writable, Some(Errno::EACCES), Errno::EACCES);
                }
                let ro = open(cx, addr, path.as_bytes(), O_RDONLY, 0).unwrap();
                check_protected_mappings(cx, ro, None, Errno::EACCES);
            }
        });
    }

    #[test]
    fn overlay_flag_ioctl_reads_the_lower_and_changes_only_the_upper() {
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let store = vfs.store();
            let root = crate::vfs::store::ROOT;
            let lower = store.mkdir(root, b"lower", 0o755, 0, 0).unwrap();
            let upper = store.mkdir(root, b"upper", 0o755, 0, 0).unwrap();
            let (ino, _) = store.create_file(lower, b"file", 0o644, 0, 0).unwrap();
            store.set_flags(ino, inode_flags::NODUMP).unwrap();
            let point = mountpoint(&vfs, b"merged");
            vfs.new_overlay(
                point,
                0,
                b"overlay".to_vec(),
                ((Some(upper), vec![lower]), (0, 0), Vec::new()),
                overlay::Options::default(),
            );
            let fd = open(cx, addr, b"/merged/file", oflags::O_RDONLY, 0).unwrap();
            ioctl(cx, fd, FS_IOC_GETFLAGS, addr).unwrap();
            assert_eq!(
                u32::from_le_bytes(get(cx, addr).unwrap()),
                inode_flags::NODUMP
            );
            assert_eq!(store.lookup(upper, b"file").unwrap(), None);
            set_inode_flags(cx, fd, addr, inode_flags::IMMUTABLE).unwrap();
            assert_eq!(store.attrs(ino).unwrap().flags, inode_flags::NODUMP);
            let up = store.lookup(upper, b"file").unwrap().unwrap();
            assert_eq!(store.attrs(up).unwrap().flags, inode_flags::IMMUTABLE);
            assert_eq!(
                open(cx, addr, b"/merged/file", oflags::O_RDWR, 0),
                Err(Errno::EPERM)
            );
            write_cstr(cx, addr, b"");
            statx(cx, fd, addr, AT_EMPTY_PATH, 0, addr + 256).unwrap();
            assert_eq!(
                u64::from_le_bytes(get(cx, addr + 264).unwrap()),
                u64::from(inode_flags::IMMUTABLE)
            );
        });
    }

    #[test]
    fn inode_flag_ioctl_checks_owner_capability_mount_and_file_type() {
        use inode_flags::*;
        with_guest(0, |cx, addr, _| {
            let fd = open(
                cx,
                addr,
                b"/tmp/file",
                oflags::O_CREAT | oflags::O_RDWR,
                0o666,
            )
            .unwrap();
            let root = cx.cred();
            let mut cred = root.clone();
            cred.cap_effective &= !(1 << cap::LINUX_IMMUTABLE);
            cx.set_cred(cred.clone());
            assert_eq!(set_inode_flags(cx, fd, addr, IMMUTABLE), Err(Errno::EPERM));
            set_inode_flags(cx, fd, addr, NODUMP).unwrap();
            cred.fsuid = 123;
            cred.cap_effective = 0;
            cx.set_cred(cred.clone());
            assert_eq!(set_inode_flags(cx, fd, addr, NOATIME), Err(Errno::EPERM));
            cred.cap_effective = 1 << cap::FOWNER;
            cx.set_cred(cred);
            set_inode_flags(cx, fd, addr, NOATIME).unwrap();
            cx.set_cred(root);
            assert_eq!(
                set_inode_flags(cx, fd, addr, 0x1000),
                Err(Errno::EOPNOTSUPP)
            );
            bind_tmp(&cx.vfs().unwrap(), b"ro", ms::RDONLY);
            let ro = open(cx, addr, b"/ro/file", oflags::O_RDONLY, 0).unwrap();
            assert_eq!(set_inode_flags(cx, ro, addr, 0), Err(Errno::EROFS));
            pipe2(cx, addr, 0).unwrap();
            let pipe = i32::from_le_bytes(get(cx, addr).unwrap());
            assert_eq!(ioctl(cx, pipe, FS_IOC_GETFLAGS, addr), Err(Errno::ENOTTY));
            write_cstr(cx, addr, b"mem");
            let mem = memfd_create(cx, addr, 0).unwrap() as i32;
            set_inode_flags(cx, mem, addr, IMMUTABLE).unwrap();
            assert_eq!(write(cx, mem, addr, 1), Err(Errno::EPERM));
        });
    }

    #[test]
    fn store_rename_preflight_precedes_write_permission() {
        with_guest(1000, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let store = vfs.store();
            let root = crate::vfs::store::ROOT;
            let dir = store.mkdir(root, b"locked", 0o555, 0, 0).unwrap();
            let child = store.mkdir(dir, b"sub", 0o555, 0, 0).unwrap();
            let (file, _) = store.create_file(dir, b"file", 0o644, 0, 0).unwrap();
            store.link(dir, b"alias", file).unwrap();
            store.create_file(child, b"file", 0o644, 0, 0).unwrap();
            let mut rename = |old: &[u8], new: &[u8], flags| {
                write_cstr(cx, addr, old);
                write_cstr(cx, addr + 128, new);
                renameat2(cx, AT_FDCWD, addr, AT_FDCWD, addr + 128, flags)
            };
            assert_eq!(
                rename(b"/locked/missing", b"/locked/file", RENAME_NOREPLACE),
                Err(Errno::ENOENT)
            );
            assert_eq!(
                rename(b"/locked/file/", b"/locked/sub", RENAME_NOREPLACE),
                Err(Errno::EEXIST)
            );
            assert_eq!(
                rename(b"/locked/file", b"/locked/miss", RENAME_EXCHANGE),
                Err(Errno::ENOENT)
            );
            assert_eq!(
                rename(b"/locked/sub", b"/locked/sub/new", 0),
                Err(Errno::EINVAL)
            );
            assert_eq!(
                rename(b"/locked/sub/file", b"/locked/sub", 0),
                Err(Errno::ENOTEMPTY)
            );
            assert_eq!(
                rename(b"/locked/sub/file", b"/locked/sub", RENAME_EXCHANGE),
                Err(Errno::EINVAL)
            );
            assert_eq!(rename(b"/locked/file", b"/locked/alias", 0), Ok(0));
            assert_eq!(
                rename(b"/locked/file", b"/locked/alias", RENAME_EXCHANGE),
                Ok(0)
            );
            assert_eq!(
                rename(b"/locked/file", b"/locked/alias/", 0),
                Err(Errno::ENOTDIR)
            );
            assert_eq!(
                rename(b"/locked/file", b"/locked/miss", 0),
                Err(Errno::EACCES)
            );
            bind_tmp(&vfs, b"ro", ms::RDONLY);
            let tmp = store.lookup(root, b"tmp").unwrap().unwrap();
            store.create_file(tmp, b"x", 0o644, 0, 0).unwrap();
            assert_eq!(rename(b"/ro/x", b"/ro/x", 0), Err(Errno::EROFS));
        });
    }

    #[test]
    fn cached_statx_agrees_with_the_slow_path() {
        with_guest(0, |cx, addr, cpu| {
            let buf = addr + 512;
            check_statx_mount(cx, addr, AT_FDCWD, b"/tmp", 0, crate::vfs::ROOT_MOUNT);
            let slow = get::<256>(cx, buf).unwrap();
            put(cx, buf, [0; 256]).unwrap();
            let fast = super::super::fast::Fast::new(cx.shared, cx.task, cx.t);
            let regs = &mut cpu.state_mut().x;
            regs[..5].copy_from_slice(&[AT_FDCWD as u64, addr, 0, 0x17ff, buf]);
            regs[8] = 291; // arm64 statx
            assert!(fast.syscall(cx.shared, cx.task, cpu));
            assert_eq!(cpu.state().x[0], 0);
            assert_eq!(get::<256>(cx, buf).unwrap(), slow);
            let tmp = lookup_at(cx, AT_FDCWD, b"/tmp", true)
                .unwrap()
                .ino()
                .unwrap();
            cx.vfs()
                .unwrap()
                .store()
                .set_flags(tmp, inode_flags::NODUMP)
                .unwrap();
            cpu.state_mut().x[0] = AT_FDCWD as u64;
            assert!(!fast.syscall(cx.shared, cx.task, cpu));
            statx(cx, AT_FDCWD, addr, 0, 0x17ff, buf).unwrap();
            assert_eq!(
                u64::from_le_bytes(get(cx, buf + 8).unwrap()),
                u64::from(inode_flags::NODUMP)
            );
        });
    }

    #[test]
    fn statx_reports_path_fd_and_magic_link_mounts() {
        use crate::vfs::{ANON_MOUNT, DEV_MOUNT, PROC_MOUNT, ROOT_MOUNT};
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            let tmpfs = mount_tmpfs(&vfs, 16);
            let bind = bind_tmp(&vfs, b"bind", 0);
            assert_ne!(bind, ROOT_MOUNT);
            for (path, mnt) in [
                (b"/".as_slice(), ROOT_MOUNT),
                (b"/proc", PROC_MOUNT),
                (b"/dev", DEV_MOUNT),
                (b"/mnt", tmpfs),
                (b"/bind", bind),
            ] {
                check_statx_mount(cx, addr, AT_FDCWD, path, 0, mnt);
            }
            let dirfd = open(cx, addr, b"/mnt", oflags::O_DIRECTORY, 0).unwrap();
            check_statx_mount(cx, addr, dirfd, b"", AT_EMPTY_PATH, tmpfs);
            close(cx, dirfd).unwrap();

            let fd = open(cx, addr, b"/mnt", oflags::O_TMPFILE | oflags::O_RDWR, 0o600).unwrap();
            let path = format!("/proc/self/fd/{fd}");
            check_statx_mount(cx, addr, AT_FDCWD, path.as_bytes(), 0, tmpfs);
            check_statx_mount(
                cx,
                addr,
                AT_FDCWD,
                path.as_bytes(),
                AT_SYMLINK_NOFOLLOW,
                PROC_MOUNT,
            );
            close(cx, fd).unwrap();
            let (ino, host) = vfs
                .store()
                .create_file(crate::vfs::store::ROOT, b"exe", 0o755, 0, 0)
                .unwrap();
            vfs.store().unlink(crate::vfs::store::ROOT, b"exe").unwrap();
            cx.t.group.borrow_mut().exe = Some(Rc::new(crate::process::ExeFile {
                path: Rc::from(b"/exe".as_slice()),
                node: Some((ROOT_MOUNT, ino)),
                dentry: None,
                host: Some(std::sync::Arc::new(host)),
                ovl: None,
            }));
            check_statx_mount(cx, addr, AT_FDCWD, b"/proc/self/exe", 0, ROOT_MOUNT);

            let fd = cx
                .install_fd(OpenFile::new(FileKind::Host(1), oflags::O_WRONLY), false)
                .unwrap();
            check_statx_mount(cx, addr, fd, b"", AT_EMPTY_PATH, ANON_MOUNT);
            check_statx_mount(
                cx,
                addr,
                AT_FDCWD,
                format!("/proc/self/fd/{fd}").as_bytes(),
                0,
                ANON_MOUNT,
            );
            close(cx, fd).unwrap();
        });
    }

    #[test]
    fn environ_checks_access_and_reads_eof_after_exec() {
        with_guest(1000, |cx, addr, cpu| {
            let (_, _, _root_cpu) =
                pseudo::tests::add_task(cx.k(), 10, 0, true, b"ROOT_KEY=secret\0");
            assert_eq!(
                open(cx, addr, b"/proc/10/environ", oflags::O_RDONLY, 0),
                Err(Errno::EACCES)
            );
            let fd = open(cx, addr, b"/proc/self/environ", oflags::O_RDONLY, 0).unwrap();
            let file = cx.fds().get(fd).unwrap();
            let mut out = [0; 64];
            let n = read_bytes(cx, &file, &mut out, Some(0)).unwrap();
            assert_eq!(&out[..n], b"USER_KEY=hello\0");

            let (mm, _) = pseudo::tests::mm_with_env(b"SETUID_SECRET=1\0");
            let mm = mm.into_shared();
            unsafe { cpu.reset(mm.borrow().mmu()) };
            cx.task.res.borrow_mut().mm = mm.clone();
            cx.t.mm = mm;
            assert_eq!(read_bytes(cx, &file, &mut out, Some(1)), Ok(0));
            assert_eq!(read_bytes(cx, &file, &mut out, Some(0)), Ok(0));
            close(cx, fd).unwrap();
        });
    }

    #[test]
    fn zombie_environ_opens_at_eof() {
        with_guest(0, |cx, addr, _| {
            let (_, _, cpu) = pseudo::tests::add_task(cx.k(), 10, 1000, true, b"OLD=1\0");
            cx.k().groups[&10].borrow_mut().threads.clear();
            drop(cpu);
            cx.k().tasks.remove(&10).unwrap();
            let fd = open(cx, addr, b"/proc/10/environ", oflags::O_RDONLY, 0).unwrap();
            let file = cx.fds().get(fd).unwrap();
            assert_eq!(read_bytes(cx, &file, &mut [0; 8], None), Ok(0));
            close(cx, fd).unwrap();
        });
    }

    #[test]
    fn tmpfile_checks_flags_and_directory() {
        use oflags::*;
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            bind_tmp(&vfs, b"ro", ms::RDONLY);
            mount_tmpfs(&vfs, 16);
            vfs.store()
                .create_file(crate::vfs::store::ROOT, b"regfile", 0o644, 0, 0)
                .unwrap();
            vfs.store()
                .symlink(crate::vfs::store::ROOT, b"sym", b"/tmp", 0, 0)
                .unwrap();
            for (path, flags, error) in [
                (b"/tmp".as_slice(), O_TMPFILE | O_RDONLY, Errno::EINVAL),
                (b"/tmp", O_TMPFILE_BIT | O_RDWR, Errno::EINVAL),
                (b"/tmp", O_TMPFILE | O_CREAT | O_RDWR, Errno::EINVAL),
                (b"/regfile", O_TMPFILE | O_RDWR, Errno::ENOTDIR),
                (b"/ro", O_TMPFILE | O_RDWR, Errno::EROFS),
                (b"/proc", O_TMPFILE | O_RDWR, Errno::EOPNOTSUPP),
                (b"/mnt", O_TMPFILE | O_RDWR | O_DIRECT, Errno::EINVAL),
                (b"/sym", O_TMPFILE | O_RDWR | O_NOFOLLOW, Errno::ENOTDIR),
            ] {
                assert_eq!(
                    open(cx, addr, path, flags, 0o600),
                    Err(error),
                    "{path:?} {flags:#x}"
                );
            }
            // openat2 rejects O_PATH combined with extra flags and validates tmpfiles before lookup.
            write_cstr(cx, addr, b"/tmp");
            for flags in [
                O_PATH | O_TMPFILE | O_RDWR,
                O_TMPFILE_BIT | O_RDWR,
                O_TMPFILE | O_RDONLY,
                O_TMPFILE | O_CREAT | O_RDWR,
            ] {
                let mut how = [0; 24];
                how[..8].copy_from_slice(&u64::from(flags).to_le_bytes());
                put(cx, addr + 256, how).unwrap();
                assert_eq!(
                    openat2(cx, AT_FDCWD, addr, addr + 256, 24),
                    Err(Errno::EINVAL)
                );
            }
            let fd = open(cx, addr, b"/tmp", O_PATH | O_TMPFILE, 0).unwrap();
            assert_eq!(
                fcntl(cx, fd, F_GETFL, 0),
                Ok(u64::from(O_PATH | O_DIRECTORY))
            );
            close(cx, fd).unwrap();
        });
    }

    #[test]
    fn tmpfile_link_and_exclusive_open() {
        with_guest(0, |cx, p1, _| {
            let vfs = cx.vfs().unwrap();
            bind_tmp(&vfs, b"bind", 0);
            let fd = open(cx, p1, b"/tmp", oflags::O_TMPFILE | oflags::O_RDWR, 0o666).unwrap();
            let fl = fcntl(cx, fd, F_GETFL, 0).unwrap() as u32;
            assert_eq!(fl & oflags::O_TMPFILE, oflags::O_TMPFILE);
            let f = cx.fds().get(fd).unwrap();
            let ino = f.borrow().ino().unwrap();
            let st = vfs.store().stat(ino).unwrap();
            assert_eq!(st.nlink, 0);
            assert_eq!(st.mode, mode::S_IFREG | 0o644); // 0o666 & !umask(0o022)
            assert_eq!(write_bytes(cx, &f, b"hello tmpfile", Some(0)).unwrap(), 13);

            // Cross-mount linkat fails with EXDEV.
            assert_eq!(
                link_fd(cx, p1, fd, b"/bind/xdev", AT_EMPTY_PATH),
                Err(Errno::EXDEV)
            );

            // Link via AT_EMPTY_PATH (root has CAP_DAC_READ_SEARCH).
            assert_eq!(
                link_fd(cx, p1, fd, b"/tmp/linked_store", AT_EMPTY_PATH),
                Ok(0)
            );
            assert_eq!(vfs.store().stat(ino).unwrap().nlink, 1);
            let proc_fd = format!("/proc/self/fd/{fd}");
            let node = lookup_at(cx, AT_FDCWD, proc_fd.as_bytes(), false).unwrap();
            assert_eq!(
                vfs.readlink(&cx.view(&vfs), &node).unwrap(),
                format!("/tmp/#{ino} (deleted)").as_bytes()
            );
            let mut back = [0u8; 32];
            let linked_fd = open(cx, p1, b"/tmp/linked_store", oflags::O_RDONLY, 0).unwrap();
            let linked_f = cx.fds().get(linked_fd).unwrap();
            let n = read_bytes(cx, &linked_f, &mut back, Some(0)).unwrap();
            assert_eq!(&back[..n], b"hello tmpfile");
            drop(linked_f);
            close(cx, linked_fd).unwrap();
            close(cx, fd).unwrap();

            // O_TMPFILE | O_EXCL refuses linkat with ENOENT.
            let efd = open(
                cx,
                p1,
                b"/tmp",
                oflags::O_TMPFILE | oflags::O_EXCL | oflags::O_RDWR,
                0o600,
            )
            .unwrap();
            let ef = cx.fds().get(efd).unwrap();
            assert_eq!(write_bytes(cx, &ef, b"secret", Some(0)).unwrap(), 6);
            assert_eq!(
                link_fd(cx, p1, efd, b"/tmp/should_fail", AT_EMPTY_PATH),
                Err(Errno::ENOENT)
            );
            assert_eq!(
                link_fd(cx, p1, efd, b"/tmp/should_fail", AT_SYMLINK_FOLLOW),
                Err(Errno::ENOENT)
            );
            close(cx, efd).unwrap();
        });
    }

    #[test]
    fn tmpfile_tmpfs_charges_follow_link_and_close() {
        with_guest(0, |cx, p1, _| {
            let vfs = cx.vfs().unwrap();
            let mnt = mount_tmpfs(&vfs, 16);
            let tmpfs_dev = vfs.mount(mnt).unwrap().dev;
            let check_usage = |pages, inodes| {
                for fresh in [false, true] {
                    let (_, p, i) = vfs.tmpfs_usage(tmpfs_dev, fresh).unwrap();
                    assert_eq!((p, i), (pages, inodes));
                }
            };
            check_usage(0, 1);
            let tfd = open(cx, p1, b"/mnt", oflags::O_TMPFILE | oflags::O_RDWR, 0o600).unwrap();
            let tf = cx.fds().get(tfd).unwrap();
            let tino = tf.borrow().ino().unwrap();
            check_usage(0, 2);
            assert_eq!(write_bytes(cx, &tf, &[0xab; 4096], Some(0)).unwrap(), 4096);
            check_usage(1, 2);

            assert_eq!(
                link_fd(cx, p1, tfd, b"/tmp/cross-mount", AT_EMPTY_PATH),
                Err(Errno::EXDEV)
            );
            check_usage(1, 2);
            // Link into tmpfs via /proc/self/fd/N: must NOT double-charge inode or pages.
            assert_eq!(
                link_fd(cx, p1, tfd, b"/mnt/materialized", AT_SYMLINK_FOLLOW),
                Ok(0)
            );
            assert_eq!(vfs.store().stat(tino).unwrap().nlink, 1);
            check_usage(1, 2);
            close(cx, tfd).unwrap();

            // Unlinked tmpfs O_TMPFILE closed without linking releases both quota and host object.
            let tfd2 = open(cx, p1, b"/mnt", oflags::O_TMPFILE | oflags::O_RDWR, 0o600).unwrap();
            let tf2 = cx.fds().get(tfd2).unwrap();
            let tino2 = tf2.borrow().ino().unwrap();
            assert_eq!(write_bytes(cx, &tf2, &[0xcd; 4096], Some(0)).unwrap(), 4096);
            drop(tf2);
            check_usage(2, 3);
            close(cx, tfd2).unwrap();
            evict_unlinked_tmpfs(cx.kr(), &vfs);
            assert!(!vfs.store().is_linkable_tmpfile(tino2));
            check_usage(1, 2);
        });
    }

    #[test]
    fn tmpfile_link_on_full_tmpfs() {
        use oflags::*;
        with_guest(0, |cx, addr, _| {
            let vfs = cx.vfs().unwrap();
            mount_tmpfs(&vfs, 2); // The root and one unnamed inode.
            for (extra, expected) in [(O_EXCL, Err(Errno::ENOENT)), (0, Ok(0))] {
                let fd = open(cx, addr, b"/mnt", O_TMPFILE | O_RDWR | extra, 0o600).unwrap();
                assert_eq!(
                    open(cx, addr, b"/mnt", O_TMPFILE | O_RDWR, 0o600),
                    Err(Errno::ENOSPC)
                );
                assert_eq!(link_fd(cx, addr, fd, b"/mnt/file", AT_EMPTY_PATH), expected);
                close(cx, fd).unwrap();
                evict_unlinked_tmpfs(cx.kr(), &vfs);
            }
        });
    }

    #[test]
    fn tmpfile_unprivileged_link_requires_proc_fd() {
        with_guest(1000, |cx, p1, _| {
            cx.vfs()
                .unwrap()
                .store()
                .mkdir(crate::vfs::store::ROOT, b"locked", 0o755, 0, 0)
                .unwrap();
            assert_eq!(
                open(
                    cx,
                    p1,
                    b"/locked",
                    oflags::O_TMPFILE | oflags::O_RDWR,
                    0o600
                ),
                Err(Errno::EACCES)
            );

            let fd = open(cx, p1, b"/tmp", oflags::O_TMPFILE | oflags::O_RDWR, 0o600).unwrap();
            let f = cx.fds().get(fd).unwrap();
            assert_eq!(write_bytes(cx, &f, b"from user", Some(0)).unwrap(), 9);
            // Without CAP_DAC_READ_SEARCH, AT_EMPTY_PATH is ENOENT (Linux 6.1).
            assert_eq!(
                link_fd(cx, p1, fd, b"/tmp/user_empty_path", AT_EMPTY_PATH),
                Err(Errno::ENOENT)
            );
            // Via /proc/self/fd/N with AT_SYMLINK_FOLLOW succeeds for unprivileged user.
            assert_eq!(
                link_fd(cx, p1, fd, b"/tmp/user_linked", AT_SYMLINK_FOLLOW),
                Ok(0)
            );
            close(cx, fd).unwrap();
        });
    }
}
