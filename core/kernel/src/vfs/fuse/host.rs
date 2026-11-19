//! An in-process FUSE server for a host shared-storage directory (the kernel/fuse map).
//!
//! Only the trusted mount root is opened by path. Descendants are pinned with O_PATH and
//! O_NOFOLLOW, one name at a time; symlinks are returned to the guest walker. All host work,
//! including this server's mutex, runs with the BKL released.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::Mutex;

use super::{Args, Fields, ROOT_ID, fattr, fopen, op};
use crate::errno::Errno;
use crate::fd::oflags;
use crate::vfs::store::mode;

pub(super) struct Host {
    state: Mutex<State>,
}

struct State {
    root: CString,
    nodes: HashMap<u64, Node>,
    by_inode: HashMap<(u64, u64), u64>,
    handles: HashMap<u64, Handle>,
    next_node: u64,
    next_handle: u64,
}

struct Node {
    anchor: File,
    inode: (u64, u64),
    nlookup: u64,
}

struct Handle {
    file: File,
    nodeid: u64,
    dir: bool,
}

impl Host {
    pub fn new(path: &Path) -> Result<Host, Errno> {
        if !path.is_absolute() {
            return Err(Errno::EINVAL);
        }
        let root = CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::EINVAL)?;
        Ok(Host {
            state: Mutex::new(State {
                root,
                nodes: HashMap::new(),
                by_inode: HashMap::new(),
                handles: HashMap::new(),
                next_node: ROOT_ID + 1,
                next_handle: 1,
            }),
        })
    }

    /// Dispatches a batch in queue order, then returns lookup references. Connection requests
    /// stay pinned while this runs, including releases whose node an eviction still needs.
    pub fn dispatch(
        &self,
        messages: Vec<(u64, Vec<u8>)>,
        forgets: Vec<(u64, u64)>,
    ) -> Vec<(u64, Result<Vec<u8>, Errno>)> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let replies = messages
            .into_iter()
            .map(|(unique, message)| (unique, state.request(&message)))
            .collect();
        for (nodeid, count) in forgets {
            state.forget(nodeid, count);
        }
        replies
    }
}

impl State {
    fn fd(&mut self, nodeid: u64) -> Result<RawFd, Errno> {
        // Permission can be granted after startup: a failed open leaves the root unopened.
        if nodeid == ROOT_ID && !self.nodes.contains_key(&ROOT_ID) {
            let file = openat(
                libc::AT_FDCWD,
                &self.root,
                libc::O_PATH | libc::O_DIRECTORY,
                0,
            )?;
            let st = file.metadata().map_err(host_error)?;
            self.by_inode.insert((st.dev(), st.ino()), ROOT_ID);
            self.nodes.insert(
                ROOT_ID,
                Node {
                    anchor: file,
                    inode: (st.dev(), st.ino()),
                    nlookup: 0,
                },
            );
        }
        self.nodes
            .get(&nodeid)
            .map(|n| n.anchor.as_raw_fd())
            .ok_or(Errno::ESTALE)
    }

    fn dir(&mut self, nodeid: u64) -> Result<RawFd, Errno> {
        let fd = self.fd(nodeid)?;
        let st = self.nodes[&nodeid].anchor.metadata().map_err(host_error)?;
        if st.mode() & mode::S_IFMT != mode::S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        Ok(fd)
    }

    fn lookup(&mut self, parent: u64, name: &CStr) -> Result<Vec<u8>, Errno> {
        let fd = self.dir(parent)?;
        self.enter(openat(fd, name, libc::O_PATH | libc::O_NOFOLLOW, 0)?)
    }

    fn enter(&mut self, anchor: File) -> Result<Vec<u8>, Errno> {
        let st = anchor.metadata().map_err(host_error)?;
        let key = (st.dev(), st.ino());
        let nodeid = if let Some(&id) = self.by_inode.get(&key) {
            self.nodes.get_mut(&id).unwrap().nlookup += 1;
            id
        } else {
            let id = self.next_node;
            self.next_node += 1;
            self.by_inode.insert(key, id);
            self.nodes.insert(
                id,
                Node {
                    anchor,
                    inode: key,
                    nlookup: 1,
                },
            );
            id
        };
        // Zero validity keeps changes from other Android apps visible on the next syscall.
        Ok(attr(
            Args::default()
                .u64(nodeid)
                .u64(0)
                .u64(0)
                .u64(0)
                .u32(0)
                .u32(0),
            &st,
        )
        .0)
    }

    fn forget(&mut self, nodeid: u64, count: u64) {
        if nodeid == ROOT_ID {
            return;
        }
        if let Some(n) = self.nodes.get_mut(&nodeid) {
            n.nlookup = n.nlookup.saturating_sub(count);
            if n.nlookup != 0 || self.handles.values().any(|h| h.nodeid == nodeid) {
                return;
            }
            self.by_inode.remove(&n.inode);
            self.nodes.remove(&nodeid);
        }
    }

    fn handle(&self, fh: u64, nodeid: u64) -> Result<&Handle, Errno> {
        self.handles
            .get(&fh)
            .filter(|h| h.nodeid == nodeid)
            .ok_or(Errno::EBADF)
    }

    fn opened(&mut self, file: File, nodeid: u64, dir: bool) -> Vec<u8> {
        let fh = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(fh, Handle { file, nodeid, dir });
        Args::default().u64(fh).u32(fopen::DIRECT_IO).u32(0).0
    }

    fn open(&mut self, nodeid: u64, flags: u32, dir: bool) -> Result<Vec<u8>, Errno> {
        let fd = self.fd(nodeid)?;
        let st = self.nodes[&nodeid].anchor.metadata().map_err(host_error)?;
        match st.mode() & mode::S_IFMT {
            mode::S_IFDIR if dir => {}
            mode::S_IFREG if !dir => {}
            mode::S_IFLNK => return Err(Errno::ELOOP),
            mode::S_IFDIR => return Err(Errno::EISDIR),
            mode::S_IFREG => return Err(Errno::ENOTDIR),
            _ => return Err(Errno::ENXIO),
        }
        let flags = if dir {
            libc::O_RDONLY | libc::O_DIRECTORY
        } else {
            open_flags(flags)?
        };
        let file = reopen(fd, flags)?;
        Ok(self.opened(file, nodeid, dir))
    }

    fn getattr(&mut self, nodeid: u64, fh: Option<u64>) -> Result<Vec<u8>, Errno> {
        let st = if let Some(fh) = fh {
            self.handle(fh, nodeid)?.file.metadata()
        } else {
            self.fd(nodeid)?;
            self.nodes[&nodeid].anchor.metadata()
        }
        .map_err(host_error)?;
        Ok(attr(Args::default().u64(0).u32(0).u32(0), &st).0)
    }

    fn setattr(&mut self, nodeid: u64, f: &mut Fields<'_>) -> Result<Vec<u8>, Errno> {
        let (valid, _) = (f.u32()?, f.u32()?);
        let (fh, size, _) = (f.u64()?, f.u64()?, f.u64()?);
        let (atime, mtime, _) = (f.u64()?, f.u64()?, f.u64()?);
        let (ansec, mnsec, _) = (f.u32()?, f.u32()?, f.u32()?);
        let (perm, _, uid, gid) = (f.u32()?, f.u32()?, f.u32()?, f.u32()?);
        let fd = self.fd(nodeid)?;
        let st = self.nodes[&nodeid].anchor.metadata().map_err(host_error)?;
        // Shared-storage ownership and permissions belong to Android, not guest credentials.
        if (valid & fattr::UID != 0 && uid != 0)
            || (valid & fattr::GID != 0 && gid != 0)
            || (valid & fattr::MODE != 0 && perm & 0o7777 != st.mode() & 0o777)
        {
            return Err(Errno::EPERM);
        }
        let kind = st.mode() & mode::S_IFMT;
        if kind != mode::S_IFREG && kind != mode::S_IFDIR {
            return Err(Errno::EOPNOTSUPP);
        }
        if valid & fattr::SIZE != 0 && kind != mode::S_IFREG {
            return Err(Errno::EISDIR);
        }
        let owned;
        let file = if valid & fattr::FH != 0 {
            &self.handle(fh, nodeid)?.file
        } else {
            owned = reopen(
                fd,
                if valid & fattr::SIZE != 0 {
                    libc::O_WRONLY
                } else {
                    libc::O_RDONLY
                },
            )?;
            &owned
        };
        if valid & fattr::SIZE != 0 {
            if size > i64::MAX as u64 {
                return Err(Errno::EFBIG);
            }
            file.set_len(size).map_err(host_error)?;
        }
        if valid & (fattr::ATIME | fattr::MTIME | fattr::ATIME_NOW | fattr::MTIME_NOW) != 0 {
            let time = |secs, nsec, bit, now| -> Result<libc::timespec, Errno> {
                let ns = if valid & now != 0 {
                    libc::UTIME_NOW
                } else if valid & bit == 0 {
                    libc::UTIME_OMIT
                } else if nsec < 1_000_000_000 {
                    nsec as _
                } else {
                    return Err(Errno::EINVAL);
                };
                Ok(libc::timespec {
                    tv_sec: secs as _,
                    tv_nsec: ns,
                })
            };
            let times = [
                time(atime, ansec, fattr::ATIME, fattr::ATIME_NOW)?,
                time(mtime, mnsec, fattr::MTIME, fattr::MTIME_NOW)?,
            ];
            result(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })?;
        }
        let st = file.metadata().map_err(host_error)?;
        Ok(attr(Args::default().u64(0).u32(0).u32(0), &st).0)
    }

    fn request(&mut self, message: &[u8]) -> Result<Vec<u8>, Errno> {
        let mut f = Fields::new(message);
        let (_len, opcode, _unique, nodeid) = (f.u32()?, f.u32()?, f.u64()?, f.u64()?);
        f.take(16)?;
        match opcode {
            op::LOOKUP => self.lookup(nodeid, &name(&mut f)?),
            op::GETATTR => {
                let (flags, _, fh) = (f.u32()?, f.u32()?, f.u64()?);
                self.getattr(nodeid, (flags & 1 != 0).then_some(fh))
            }
            op::SETATTR => self.setattr(nodeid, &mut f),
            op::READLINK => {
                let fd = self.fd(nodeid)?;
                let mut buf = vec![0; 4096];
                let n = unsafe {
                    libc::readlinkat(fd, c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 {
                    return Err(last_error());
                }
                if n as usize == buf.len() {
                    return Err(Errno::ENAMETOOLONG);
                }
                buf.truncate(n as usize);
                Ok(buf)
            }
            op::OPEN | op::OPENDIR => self.open(nodeid, f.u32()?, opcode == op::OPENDIR),
            op::CREATE => {
                let (flags, perm, umask, _) = (f.u32()?, f.u32()?, f.u32()?, f.u32()?);
                let name = name(&mut f)?;
                let fd = self.dir(nodeid)?;
                let file = openat(
                    fd,
                    &name,
                    open_flags(flags)? | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    (perm & !umask & 0o666) as _,
                )?;
                // Pin the just-created file itself; another app may replace its directory entry.
                let anchor = reopen(file.as_raw_fd(), libc::O_PATH)?;
                let mut entry = self.enter(anchor)?;
                let id = u64::from_le_bytes(entry[..8].try_into().unwrap());
                entry.extend_from_slice(&self.opened(file, id, false));
                Ok(entry)
            }
            op::MKDIR => {
                let (perm, umask) = (f.u32()?, f.u32()?);
                let name = name(&mut f)?;
                let fd = self.dir(nodeid)?;
                result(unsafe { libc::mkdirat(fd, name.as_ptr(), (perm & !umask & 0o777) as _) })?;
                self.lookup(nodeid, &name)
            }
            op::MKNOD => {
                let (perm, rdev, umask, _) = (f.u32()?, f.u32()?, f.u32()?, f.u32()?);
                if perm & mode::S_IFMT != mode::S_IFREG || rdev != 0 {
                    return Err(Errno::EPERM);
                }
                let name = name(&mut f)?;
                let fd = self.dir(nodeid)?;
                let file = openat(
                    fd,
                    &name,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    (perm & !umask & 0o666) as _,
                )?;
                self.enter(reopen(file.as_raw_fd(), libc::O_PATH)?)
            }
            op::SYMLINK => {
                let name = name(&mut f)?;
                let target = string(&mut f)?;
                let fd = self.dir(nodeid)?;
                result(unsafe { libc::symlinkat(target.as_ptr(), fd, name.as_ptr()) })?;
                self.lookup(nodeid, &name)
            }
            op::UNLINK | op::RMDIR => {
                let name = name(&mut f)?;
                let fd = self.dir(nodeid)?;
                result(unsafe {
                    libc::unlinkat(
                        fd,
                        name.as_ptr(),
                        if opcode == op::RMDIR {
                            libc::AT_REMOVEDIR
                        } else {
                            0
                        },
                    )
                })?;
                Ok(Vec::new())
            }
            op::RENAME | op::RENAME2 => {
                let to = f.u64()?;
                let flags = if opcode == op::RENAME2 {
                    let v = f.u32()?;
                    f.u32()?;
                    v
                } else {
                    0
                };
                let (old, new) = (name(&mut f)?, name(&mut f)?);
                let (from, to) = (self.dir(nodeid)?, self.dir(to)?);
                let r = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        from,
                        old.as_ptr(),
                        to,
                        new.as_ptr(),
                        flags,
                    )
                };
                if r < 0 {
                    return Err(last_error());
                }
                Ok(Vec::new())
            }
            op::READ | op::WRITE | op::READDIR => {
                let (fh, offset, size, _) = (f.u64()?, f.u64()?, f.u32()? as usize, f.u32()?);
                let (_, flags, _) = (f.u64()?, f.u32()?, f.u32()?);
                if size > 1024 * 1024 || offset > i64::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                let h = self.handle(fh, nodeid)?;
                if opcode == op::READDIR {
                    if !h.dir {
                        return Err(Errno::ENOTDIR);
                    }
                    return readdir(&h.file, offset, size);
                }
                if h.dir {
                    return Err(Errno::EISDIR);
                }
                if opcode == op::READ {
                    let mut buf = vec![0; size];
                    let n = h.file.read_at(&mut buf, offset).map_err(host_error)?;
                    buf.truncate(n);
                    Ok(buf)
                } else {
                    let data = f.take(size)?;
                    let fd = h.file.as_raw_fd();
                    let current = result(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
                    let append = flags & oflags::O_APPEND != 0;
                    result(unsafe {
                        libc::fcntl(
                            fd,
                            libc::F_SETFL,
                            (current & !libc::O_APPEND) | if append { libc::O_APPEND } else { 0 },
                        )
                    })?;
                    let n = if append {
                        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
                        if n < 0 {
                            return Err(last_error());
                        }
                        n as usize
                    } else {
                        h.file.write_at(data, offset).map_err(host_error)?
                    };
                    Ok(Args::default().u32(n as u32).u32(0).0)
                }
            }
            op::FLUSH => {
                self.handle(f.u64()?, nodeid)?;
                Ok(Vec::new())
            }
            op::RELEASE | op::RELEASEDIR => {
                let fh = f.u64()?;
                self.handle(fh, nodeid)?;
                self.handles.remove(&fh);
                self.forget(nodeid, 0);
                Ok(Vec::new())
            }
            op::FSYNC | op::FSYNCDIR => {
                let (fh, flags) = (f.u64()?, f.u32()?);
                let h = self.handle(fh, nodeid)?;
                if flags & 1 != 0 {
                    h.file.sync_data()
                } else {
                    h.file.sync_all()
                }
                .map_err(host_error)?;
                Ok(Vec::new())
            }
            op::STATFS => {
                let fd = self.fd(nodeid)?;
                let mut st = std::mem::MaybeUninit::<libc::statfs>::uninit();
                result(unsafe { libc::fstatfs(fd, st.as_mut_ptr()) })?;
                let st = unsafe { st.assume_init() };
                Ok(Args::default()
                    .u64(st.f_blocks as _)
                    .u64(st.f_bfree as _)
                    .u64(st.f_bavail as _)
                    .u64(st.f_files as _)
                    .u64(st.f_ffree as _)
                    .u32(st.f_bsize as _)
                    .u32(st.f_namelen as _)
                    .u32(st.f_frsize as _)
                    .u32(0)
                    .bytes(&[0; 24])
                    .0)
            }
            op::ACCESS => {
                let mask = f.u32()? as i32;
                let fd = self.fd(nodeid)?;
                let st = self.nodes[&nodeid].anchor.metadata().map_err(host_error)?;
                if !matches!(st.mode() & mode::S_IFMT, mode::S_IFREG | mode::S_IFDIR) {
                    return Err(Errno::EACCES);
                }
                result(unsafe {
                    libc::faccessat(
                        libc::AT_FDCWD,
                        fd_path(fd).as_ptr(),
                        mask,
                        // Bionic accepts flags 0; guest IDs never change the app's host IDs.
                        0,
                    )
                })?;
                Ok(Vec::new())
            }
            op::LSEEK => {
                let (fh, offset, whence) = (f.u64()?, f.u64()? as i64, f.u32()? as i32);
                let h = self.handle(fh, nodeid)?;
                let at = unsafe { libc::lseek(h.file.as_raw_fd(), offset, whence) };
                if at < 0 {
                    return Err(last_error());
                }
                Ok(Args::default().u64(at as u64).0)
            }
            op::FALLOCATE => {
                let (fh, offset, len, mode) = (f.u64()?, f.u64()?, f.u64()?, f.u32()?);
                if offset > i64::MAX as u64 || len > i64::MAX as u64 {
                    return Err(Errno::EINVAL);
                }
                let h = self.handle(fh, nodeid)?;
                result(unsafe {
                    libc::fallocate(h.file.as_raw_fd(), mode as _, offset as _, len as _)
                })?;
                Ok(Vec::new())
            }
            // Host xattrs (especially capabilities and SELinux labels) are not guest metadata.
            op::SETXATTR | op::REMOVEXATTR | op::LINK => Err(Errno::EOPNOTSUPP),
            op::GETXATTR => Err(Errno::ENODATA),
            op::LISTXATTR => {
                let size = f.u32()?;
                Ok(if size == 0 {
                    Args::default().u32(0).u32(0).0
                } else {
                    Vec::new()
                })
            }
            _ => Err(Errno::ENOSYS),
        }
    }
}

fn attr(a: Args, st: &Metadata) -> Args {
    a.u64(st.ino())
        .u64(st.size())
        .u64(st.blocks())
        .u64(st.atime() as u64)
        .u64(st.mtime() as u64)
        .u64(st.ctime() as u64)
        .u32(st.atime_nsec() as u32)
        .u32(st.mtime_nsec() as u32)
        .u32(st.ctime_nsec() as u32)
        .u32(st.mode() & (mode::S_IFMT | 0o777))
        .u32(st.nlink().min(u32::MAX as u64) as u32)
        .u32(0)
        .u32(0)
        .u32(0)
        .u32(st.blksize().min(u32::MAX as u64) as u32)
        .u32(0)
}

fn string(f: &mut Fields<'_>) -> Result<CString, Errno> {
    let len = f.rest().iter().position(|&b| b == 0).ok_or(Errno::EINVAL)?;
    if len > 4096 {
        return Err(Errno::ENAMETOOLONG);
    }
    let s = CString::new(f.take(len)?).map_err(|_| Errno::EINVAL)?;
    f.take(1)?;
    Ok(s)
}

fn name(f: &mut Fields<'_>) -> Result<CString, Errno> {
    let s = string(f)?;
    let b = s.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(Errno::EINVAL);
    }
    if b.len() > 255 {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(s)
}

fn open_flags(flags: u32) -> Result<i32, Errno> {
    if flags & oflags::O_ACCMODE == oflags::O_ACCMODE {
        return Err(Errno::EINVAL);
    }
    Ok((flags
        & (oflags::O_ACCMODE
            | oflags::O_TRUNC
            | oflags::O_SYNC_BIT
            | oflags::O_DSYNC
            | oflags::O_NONBLOCK)) as i32)
}

fn fd_path(fd: RawFd) -> CString {
    CString::new(format!("/proc/self/fd/{fd}")).unwrap()
}

fn reopen(fd: RawFd, flags: i32) -> Result<File, Errno> {
    openat(libc::AT_FDCWD, &fd_path(fd), flags, 0)
}

fn openat(dir: RawFd, name: &CStr, flags: i32, perm: libc::mode_t) -> Result<File, Errno> {
    let fd = result(unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC, perm) })?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn readdir(file: &File, offset: u64, size: usize) -> Result<Vec<u8>, Errno> {
    struct Dir(*mut libc::DIR);
    impl Drop for Dir {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let file = reopen(file.as_raw_fd(), libc::O_RDONLY | libc::O_DIRECTORY)?;
    let fd = file.into_raw_fd();
    let ptr = unsafe { libc::fdopendir(fd) };
    if ptr.is_null() {
        let error = last_error();
        drop(unsafe { File::from_raw_fd(fd) });
        return Err(error);
    }
    let dir = Dir(ptr);
    unsafe { libc::seekdir(dir.0, offset as _) };
    let mut out = Vec::new();
    loop {
        // readdir returns null both at EOF and on error; distinguish them through errno.
        unsafe {
            *errno_ptr() = 0;
        }
        let entry = unsafe { libc::readdir(dir.0) };
        if entry.is_null() {
            if unsafe { *errno_ptr() } != 0 {
                return Err(last_error());
            }
            return Ok(out);
        }
        let entry = unsafe { &*entry };
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
        let len = (24 + name.len()).next_multiple_of(8);
        if out.len() + len > size {
            return Ok(out);
        }
        let mut b = Args::default()
            .u64(entry.d_ino as _)
            .u64(entry.d_off as _)
            .u32(name.len() as u32)
            .u32(u32::from(entry.d_type))
            .bytes(name)
            .0;
        b.resize(len, 0);
        out.extend_from_slice(&b);
    }
}

fn result(r: i32) -> Result<i32, Errno> {
    if r < 0 { Err(last_error()) } else { Ok(r) }
}

fn host_error(e: io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(Errno::EIO.0))
}
fn last_error() -> Errno {
    host_error(io::Error::last_os_error())
}

#[cfg(target_os = "android")]
unsafe fn errno_ptr() -> *mut i32 {
    unsafe { libc::__errno() }
}
#[cfg(not(target_os = "android"))]
unsafe fn errno_ptr() -> *mut i32 {
    unsafe { libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Root(PathBuf);
    impl Root {
        fn new() -> Root {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "appine-fuse-host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Root(path)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn request(host: &Host, opcode: u32, nodeid: u64, args: Args) -> Result<Vec<u8>, Errno> {
        let message = Args::default()
            .u32((40 + args.0.len()) as u32)
            .u32(opcode)
            .u64(2)
            .u64(nodeid)
            .u64(0)
            .u64(0)
            .bytes(&args.0)
            .0;
        host.dispatch(vec![(2, message)], Vec::new())
            .pop()
            .unwrap()
            .1
    }

    fn number(reply: &[u8]) -> u64 {
        u64::from_le_bytes(reply[..8].try_into().unwrap())
    }
    fn lookup(host: &Host, name: &[u8]) -> u64 {
        number(&request(host, op::LOOKUP, ROOT_ID, Args::default().name(name)).unwrap())
    }
    fn io(fh: u64, at: u64, len: u32, flags: u32) -> Args {
        Args::default()
            .u64(fh)
            .u64(at)
            .u32(len)
            .u32(0)
            .u64(0)
            .u32(flags)
            .u32(0)
    }
    fn set(valid: u32, size: u64, perm: u32, uid: u32) -> Args {
        Args::default()
            .u32(valid)
            .u32(0)
            .u64(0)
            .u64(size)
            .u64(0)
            .u64(0)
            .u64(0)
            .u64(0)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(perm)
            .u32(0)
            .u32(uid)
            .u32(0)
            .u32(0)
    }

    #[test]
    fn host_symlinks_and_invalid_names_cannot_escape_the_mount() {
        let root = Root::new();
        let shared = root.0.join("shared");
        fs::create_dir(&shared).unwrap();
        fs::write(root.0.join("secret"), b"outside").unwrap();
        symlink("../secret", shared.join("escape")).unwrap();
        symlink(&root.0, shared.join("dir escape")).unwrap();
        let host = Host::new(&shared).unwrap();
        for bad in [
            b"".as_slice(),
            b".",
            b"..",
            b"../secret",
            b"/etc/passwd",
            b"a/b",
        ] {
            assert_eq!(
                request(&host, op::LOOKUP, ROOT_ID, Args::default().name(bad)),
                Err(Errno::EINVAL)
            );
            assert_eq!(
                request(&host, op::UNLINK, ROOT_ID, Args::default().name(bad)),
                Err(Errno::EINVAL)
            );
        }
        assert_eq!(
            request(
                &host,
                op::LOOKUP,
                ROOT_ID,
                Args::default().name(&[b'a'; 256])
            ),
            Err(Errno::ENAMETOOLONG)
        );
        let node = lookup(&host, b"escape");
        assert_eq!(
            request(&host, op::READLINK, node, Args::default()).unwrap(),
            b"../secret"
        );
        assert_eq!(
            request(&host, op::OPEN, node, Args::default().u32(0).u32(0)),
            Err(Errno::ELOOP)
        );
        let dir = lookup(&host, b"dir escape");
        assert_eq!(
            request(&host, op::LOOKUP, dir, Args::default().name(b"secret")),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(fs::read(root.0.join("secret")).unwrap(), b"outside");
    }

    #[test]
    fn host_root_errors_are_lazy_and_a_later_root_can_be_used() {
        let root = Root::new();
        let shared = root.0.join("later");
        let host = Host::new(&shared).unwrap();
        assert_eq!(
            request(&host, op::LOOKUP, ROOT_ID, Args::default().name(b"file")),
            Err(Errno::ENOENT)
        );
        fs::write(&shared, b"not a directory").unwrap();
        assert_eq!(
            request(&host, op::LOOKUP, ROOT_ID, Args::default().name(b"file")),
            Err(Errno::ENOTDIR)
        );
        fs::remove_file(&shared).unwrap();
        fs::create_dir(&shared).unwrap();
        fs::write(shared.join("file"), b"ready").unwrap();
        request(&host, op::ACCESS, ROOT_ID, Args::default().u32(5)).unwrap();
        let node = lookup(&host, b"file");
        let fh = number(&request(&host, op::OPEN, node, Args::default().u32(0).u32(0)).unwrap());
        assert_eq!(
            request(&host, op::READ, node, io(fh, 0, 64, 0)).unwrap(),
            b"ready"
        );
        assert_eq!(Host::new(Path::new("relative")).err(), Some(Errno::EINVAL));
        if unsafe { libc::geteuid() } != 0 {
            fs::set_permissions(shared.join("file"), fs::Permissions::from_mode(0o000)).unwrap();
            assert_eq!(
                request(&host, op::OPEN, node, Args::default().u32(0).u32(0)),
                Err(Errno::EACCES)
            );
        }
    }

    #[test]
    fn opened_host_inodes_survive_replacement_unlink_and_forget() {
        let root = Root::new();
        fs::write(root.0.join("file"), b"old").unwrap();
        let host = Host::new(&root.0).unwrap();
        let node = lookup(&host, b"file");
        let fh = number(
            &request(
                &host,
                op::OPEN,
                node,
                Args::default().u32(oflags::O_RDWR).u32(0),
            )
            .unwrap(),
        );
        fs::rename(root.0.join("file"), root.0.join("old")).unwrap();
        fs::write(root.0.join("file"), b"replacement").unwrap();
        assert_ne!(lookup(&host, b"file"), node);
        fs::remove_file(root.0.join("old")).unwrap();
        host.dispatch(Vec::new(), vec![(node, 1)]);
        assert_eq!(
            request(&host, op::READ, node, io(fh, 0, 64, 0)).unwrap(),
            b"old"
        );
        request(&host, op::WRITE, node, io(fh, 0, 3, 0).bytes(b"new")).unwrap();
        assert_eq!(
            request(&host, op::READ, node, io(fh, 0, 64, 0)).unwrap(),
            b"new"
        );
        assert_eq!(fs::read(root.0.join("file")).unwrap(), b"replacement");
        request(&host, op::RELEASE, node, Args::default().u64(fh)).unwrap();
        assert_eq!(
            request(&host, op::OPEN, node, Args::default().u32(0).u32(0)),
            Err(Errno::ESTALE)
        );
    }

    #[test]
    fn writes_apply_current_append_flags_and_metadata_stays_host_owned() {
        let root = Root::new();
        fs::write(root.0.join("file"), b"first").unwrap();
        fs::set_permissions(root.0.join("file"), fs::Permissions::from_mode(0o640)).unwrap();
        let host = Host::new(&root.0).unwrap();
        let node = lookup(&host, b"file");
        let fh = number(
            &request(
                &host,
                op::OPEN,
                node,
                Args::default().u32(oflags::O_RDWR).u32(0),
            )
            .unwrap(),
        );
        let mut external = fs::OpenOptions::new()
            .append(true)
            .open(root.0.join("file"))
            .unwrap();
        use std::io::Write;
        external.write_all(b" outside").unwrap();
        request(
            &host,
            op::WRITE,
            node,
            io(fh, 0, 6, oflags::O_APPEND).bytes(b" guest"),
        )
        .unwrap();
        assert_eq!(
            fs::read(root.0.join("file")).unwrap(),
            b"first outside guest"
        );
        request(&host, op::WRITE, node, io(fh, 0, 5, 0).bytes(b"FIRST")).unwrap();
        assert_eq!(
            fs::read(root.0.join("file")).unwrap(),
            b"FIRST outside guest"
        );
        assert_eq!(
            request(&host, op::SETATTR, node, set(fattr::MODE, 0, 0o7777, 0)),
            Err(Errno::EPERM)
        );
        assert_eq!(
            request(&host, op::SETATTR, node, set(fattr::UID, 0, 0, 1234)),
            Err(Errno::EPERM)
        );
        assert_eq!(
            fs::metadata(root.0.join("file")).unwrap().mode() & 0o7777,
            0o640
        );
        request(&host, op::SETATTR, node, set(fattr::SIZE, 0, 0, 0)).unwrap();
        assert!(fs::read(root.0.join("file")).unwrap().is_empty());
        request(&host, op::FSYNC, node, Args::default().u64(fh).u32(0)).unwrap();
    }

    #[test]
    fn directory_cookies_list_every_entry_across_small_replies() {
        let root = Root::new();
        for i in 0..100 {
            fs::write(root.0.join(format!("file {i:03}")), b"").unwrap();
        }
        let host = Host::new(&root.0).unwrap();
        let fh =
            number(&request(&host, op::OPENDIR, ROOT_ID, Args::default().u32(0).u32(0)).unwrap());
        let mut offset = 0;
        let mut names = Vec::new();
        for _ in 0..102 {
            let reply = request(&host, op::READDIR, ROOT_ID, io(fh, offset, 64, 0)).unwrap();
            if reply.is_empty() {
                break;
            }
            let mut f = Fields::new(&reply);
            while !f.rest().is_empty() {
                f.u64().unwrap();
                offset = f.u64().unwrap();
                let (len, _) = (f.u32().unwrap() as usize, f.u32().unwrap());
                names.push(f.take(len).unwrap().to_vec());
                f.take((24 + len).next_multiple_of(8) - 24 - len).unwrap();
            }
        }
        names.sort();
        let mut expected = vec![b".".to_vec(), b"..".to_vec()];
        expected.extend((0..100).map(|i| format!("file {i:03}").into_bytes()));
        expected.sort();
        assert_eq!(names, expected);
    }
}
