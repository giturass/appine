//! File syscalls on FUSE nodes and open files (the kernel/fuse map): what 6.1's `fs/fuse/dir.c`
//! and `file.c` do for them, through requests to the daemon ([`crate::vfs::fuse`]). Each request
//! here changes something or needs the open file, so it is made directly with the BKL released;
//! what only a walk needs (lookups, attributes, links) comes from the cache or a retry.
//!
//! Permission follows `fuse_permission`: nobody but the processes the mount allows gets in
//! (`allow_other`), and only with `default_permissions` does the kernel check modes; otherwise the
//! daemon decides, and the kernel asks it only for access(2) and chdir (`FUSE_ACCESS`).

use std::collections::HashSet;
use std::rc::Rc;

use super::fs::encode_stat;
use super::inotify;
use crate::cell::RefCell;
use crate::cred::{Cred, MAY_EXEC, MAY_READ, MAY_WRITE};
use crate::errno::Errno;
use crate::fd::{FileKind, FileRef, oflags};
use crate::kernel::Cx;
use crate::mm::{Fill, FillPages};
use crate::vfs::fuse::{self, Args, Conn, Entry, FuseId, Handle, mapped_pages, op};
use crate::vfs::store::{DirEntry, mode};
use crate::vfs::{MountId, Node, Vfs, ms};
use appine_engine::PAGE_SIZE;

/// What a read or write of an open FUSE file needs, taken out of it so no borrow is held while
/// waiting: the connection, node, node id, file handle, open flags, and whether the file has a
/// position (not `FOPEN_STREAM`).
pub(super) struct Io {
    conn: Rc<RefCell<Conn>>,
    id: FuseId,
    nodeid: u64,
    fh: u64,
    flags: u32,
    stream: bool,
    no_release: bool,
}

impl Io {
    /// The I/O route of an open FUSE file.
    pub fn of(h: &Handle) -> Io {
        Io {
            conn: h.conn.clone(),
            id: h.id,
            nodeid: h.nodeid,
            fh: h.fh,
            flags: h.flags,
            stream: h.open_flags & fuse::fopen::STREAM != 0,
            no_release: h.no_release,
        }
    }

    fn handle(&self) -> (&Rc<RefCell<Conn>>, u64, u64, u32) {
        (&self.conn, self.nodeid, self.fh, self.flags)
    }

    /// The daemon file handle when an open request actually succeeded (`!no_release`).
    fn fh(&self) -> Option<u64> {
        (!self.no_release).then_some(self.fh)
    }
}

/// Whether an open FUSE file can seek (not `FOPEN_NONSEEKABLE` or `FOPEN_STREAM`).
pub(super) fn seekable(h: &Handle) -> bool {
    h.open_flags & (fuse::fopen::NONSEEKABLE | fuse::fopen::STREAM) == 0
}

// ---- Opening and creating ----

/// Opens existing FUSE node `id` reached through mount `mnt` (6.1's `may_open` and
/// `fuse_open_common`): the checks open makes on a store file, with permission as
/// [`Vfs::fuse_permission`] decides, then `FUSE_OPEN` or `FUSE_OPENDIR`. Without
/// `FUSE_ATOMIC_O_TRUNC`, `O_TRUNC` is a `FUSE_SETATTR` after the open. Device nodes, FIFOs and
/// sockets in a FUSE filesystem cannot be opened (ENXIO).
pub(super) fn open(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, id): (MountId, FuseId),
    flags: u32,
) -> Result<FileKind, Errno> {
    let node = Node::Fuse(mnt, id);
    let accmode = flags & oflags::O_ACCMODE;
    let kind = vfs.fuse().get(id).ok_or(Errno::ENOTCONN)?.kind();
    let mnt_flags = vfs.mount_flags(&node).unwrap_or(0);
    let readonly = vfs.readonly(&node);
    let mut mask = super::fs::open_mask(flags);
    match kind {
        mode::S_IFLNK => return Err(Errno::ELOOP),
        mode::S_IFDIR
            if accmode != oflags::O_RDONLY || flags & (oflags::O_CREAT | oflags::O_TRUNC) != 0 =>
        {
            return Err(Errno::EISDIR);
        }
        mode::S_IFREG if flags & oflags::O_TRUNC != 0 => {
            if readonly {
                return Err(Errno::EROFS);
            }
            mask |= MAY_WRITE;
        }
        mode::S_IFCHR | mode::S_IFBLK if mnt_flags & ms::NODEV != 0 => {
            return Err(Errno::EACCES);
        }
        _ => {}
    }
    vfs.fuse_permission(cred, id, mask)?;
    if flags & oflags::O_NOATIME != 0 && !cred.owns(&fuse::cached_attr(vfs, id)?.stat()) {
        return Err(Errno::EPERM);
    }
    if readonly && kind == mode::S_IFREG && accmode != oflags::O_RDONLY {
        return Err(Errno::EROFS);
    }
    // A program being run cannot be opened for writing (deny_write_access)
    if kind == mode::S_IFREG
        && accmode != oflags::O_RDONLY
        && super::fs::executing(cx, fuse::key(id))
    {
        return Err(Errno::ETXTBSY);
    }
    if kind != mode::S_IFDIR && flags & oflags::O_DIRECTORY != 0 {
        return Err(Errno::ENOTDIR);
    }
    match kind {
        mode::S_IFDIR => Ok(FileKind::Directory {
            node,
            entries: None,
            process: None,
            fuse: Some(Box::new(fuse::open(cx, vfs, id, flags, true)?)),
        }),
        mode::S_IFREG => {
            let truncate = flags & oflags::O_TRUNC != 0;
            let atomic = truncate && fuse::atomic_o_trunc(&vfs.fuse().conn_of(id)?.borrow());
            let h = if atomic {
                with_io(cx, vfs, id, false, |cx| {
                    let h = fuse::open(cx, vfs, id, flags, false)?;
                    resize_mapping(cx, vfs, id, 0)?;
                    Ok(h)
                })?
            } else {
                let h = fuse::open(cx, vfs, id, flags, false)?;
                if truncate {
                    let set = SetAttr {
                        size: Some(0),
                        ..SetAttr::default()
                    };
                    setattr(cx, vfs, id, &set, h.fh())?;
                }
                h
            };
            if truncate {
                vfs.fuse_mut().stale(id);
            }
            Ok(FileKind::Fuse(Box::new(h)))
        }
        _ => Err(Errno::ENXIO),
    }
}

/// Creates and opens regular file `name` in FUSE directory `dir` (6.1's `fuse_create_open`):
/// `FUSE_CREATE` with the open flags, the mode less the umask and the umask, or, from a daemon
/// without it, `FUSE_MKNOD` and then an open. The directory must be on a writable mount (EROFS)
/// and, with `default_permissions`, writable and searchable. A name another process created since
/// the walk (EEXIST without `O_EXCL`) is looked up again and the syscall runs again, opening it.
/// Returns the new node and the open file.
pub(super) fn create(
    cx: &mut Cx<'_>,
    cred: &Cred,
    vfs: &Vfs,
    (mnt, dir): (MountId, FuseId),
    name: &[u8],
    perm: u32,
    flags: u32,
) -> Result<(FuseId, FileKind), Errno> {
    if vfs.readonly(&Node::Fuse(mnt, dir)) {
        return Err(Errno::EROFS);
    }
    vfs.fuse_permission(cred, dir, MAY_WRITE | MAY_EXEC)?;
    let umask = cx.umask();
    let created = with_dir_lock(cx, vfs, dir, |cx| {
        let (conn, nodeid) = fuse::target(vfs, dir)?;
        let mode = mode::S_IFREG | masked(&conn, perm & 0o7777, umask);
        if conn.borrow().no & fuse::no::CREATE == 0 {
            let args = Args::default()
                .u32(flags & !oflags::O_NOCTTY)
                .u32(mode)
                .u32(umask)
                .u32(0)
                .name(name);
            match fuse::call(cx, &conn, op::CREATE, nodeid, &args.0) {
                Ok(reply) => {
                    let ns = conn.borrow().user_ns().clone();
                    let e = match Entry::parse(&reply, &ns)? {
                        Ok(e) if e.attr.mode & mode::S_IFMT == mode::S_IFREG => e,
                        _ => return Err(Errno::EIO),
                    };
                    let mut f = fuse::Fields::new(reply.get(128..).ok_or(Errno::EIO)?);
                    let (fh, open_flags) = (f.u64()?, f.u32()?);
                    let id = {
                        let mut fuse = vfs.fuse_mut();
                        fuse.stale(dir);
                        fuse.enter(dir, name, &e)?
                    };
                    let kept = fuse::handle_flags(&conn.borrow(), flags);
                    let h = Handle {
                        conn: conn.clone(),
                        id,
                        nodeid: e.nodeid,
                        fh,
                        open_flags,
                        flags: kept,
                        dir: false,
                        no_release: false,
                    }
                    .finish_open(cx, vfs);
                    return Ok((id, Some((h, kept))));
                }
                Err(Errno::ENOSYS) => {}
                // Created meanwhile by another process (Linux holds the directory's lock from the
                // lookup to the create, so it opens what is there): look it up again and open it
                Err(Errno::EEXIST) if flags & oflags::O_EXCL == 0 => {
                    vfs.fuse_mut().forget_child(dir, name);
                    return Err(fuse::need(fuse::Query::Lookup(dir, name.to_vec())));
                }
                Err(e) => return Err(e),
            }
        }
        // open_path_with emits IN_CREATE + IN_OPEN for newly created files, so the MKNOD fallback
        // uses make_node_locked to avoid emitting IN_CREATE twice.
        let id = match make_node_locked(cx, vfs, dir, name, Make::Node(mode, 0)) {
            Err(Errno::EEXIST) if flags & oflags::O_EXCL == 0 => {
                vfs.fuse_mut().forget_child(dir, name);
                return Err(fuse::need(fuse::Query::Lookup(dir, name.to_vec())));
            }
            r => r?,
        };
        Ok((id, None))
    })?;
    match created {
        (id, Some((h, kept))) => {
            if kept & oflags::O_TRUNC != 0 && mapped_pages(vfs, id).is_some() {
                // CREATE can return an inode already mapped through another name.
                with_io(cx, vfs, id, false, |cx| resize_mapping(cx, vfs, id, 0))?;
            }
            Ok((id, FileKind::Fuse(Box::new(h))))
        }
        (id, None) => {
            let h = fuse::open(cx, vfs, id, flags & !oflags::O_TRUNC, false)?;
            Ok((id, FileKind::Fuse(Box::new(h))))
        }
    }
}

/// Permission bits `perm` of something created by a process with umask `umask`: masked here,
/// unless the daemon applies the umask itself (`FUSE_DONT_MASK`, 6.1's `fc->dont_mask`).
pub(super) fn masked(conn: &Rc<RefCell<Conn>>, perm: u32, umask: u32) -> u32 {
    if fuse::dont_mask(&conn.borrow()) {
        perm
    } else {
        perm & !umask
    }
}

/// What [`make`] creates.
pub(super) enum Make<'a> {
    /// `FUSE_MKNOD`: type and permission bits (umask already applied), device number.
    Node(u32, u64),
    /// `FUSE_MKDIR`: permission bits (umask already applied).
    Dir(u32),
    /// `FUSE_SYMLINK`: the target.
    Symlink(&'a [u8]),
    /// `FUSE_LINK`: the node id of the file to link.
    Link(u64),
}

/// Creates `name` in FUSE directory `dir` (6.1's `create_new_entry`) and emits the directory
/// `IN_CREATE` (and `IN_ATTRIB` on link) inotify events.
pub(super) fn make(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    dir: FuseId,
    name: &[u8],
    what: Make<'_>,
) -> Result<FuseId, Errno> {
    let is_link = matches!(what, Make::Link(_));
    let isdir = if matches!(what, Make::Dir(_)) {
        inotify::IN_ISDIR
    } else {
        0
    };
    let id = make_node(cx, vfs, dir, name, what)?;
    // As the VFS reports creations on any filesystem: a link first changes the file's link count
    if is_link {
        inotify::path_event(cx.kr(), fuse::key(id), None, inotify::IN_ATTRIB);
    }
    inotify::dir_event(cx.kr(), fuse::key(dir), name, inotify::IN_CREATE | isdir, 0);
    Ok(id)
}

/// Creates `name` in FUSE directory `dir` (6.1's `create_new_entry`) without emitting inotify
/// events: serializes under `dir`'s lock, checks the reply type (EIO), caches the new entry, and
/// marks `dir`'s attributes stale.
fn make_node(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    dir: FuseId,
    name: &[u8],
    what: Make<'_>,
) -> Result<FuseId, Errno> {
    with_dir_lock(cx, vfs, dir, |cx| {
        make_node_locked(cx, vfs, dir, name, what)
    })
}

/// [`make_node`], with `dir`'s directory lock already held.
fn make_node_locked(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    dir: FuseId,
    name: &[u8],
    what: Make<'_>,
) -> Result<FuseId, Errno> {
    let (conn, nodeid) = fuse::target(vfs, dir)?;
    let umask = cx.umask();
    let (opcode, args, kind) = match what {
        Make::Node(mode, rdev) => (
            op::MKNOD,
            Args::default()
                .u32(mode)
                .u32(rdev as u32)
                .u32(umask)
                .u32(0)
                .name(name),
            mode & mode::S_IFMT,
        ),
        Make::Dir(perm) => (
            op::MKDIR,
            Args::default().u32(perm).u32(umask).name(name),
            mode::S_IFDIR,
        ),
        Make::Symlink(target) => (
            op::SYMLINK,
            Args::default().name(name).name(target),
            mode::S_IFLNK,
        ),
        Make::Link(old) => (op::LINK, Args::default().u64(old).name(name), 0),
    };
    let reply = fuse::call(cx, &conn, opcode, nodeid, &args.0)?;
    let ns = conn.borrow().user_ns().clone();
    let e = match Entry::parse(&reply, &ns)? {
        Ok(e) if kind == 0 || e.attr.mode & mode::S_IFMT == kind => e,
        _ => return Err(Errno::EIO),
    };
    let mut f = vfs.fuse_mut();
    f.stale(dir);
    f.enter(dir, name, &e)
}

/// Removes `name` from FUSE directory `dir` (`FUSE_UNLINK`, or `FUSE_RMDIR` for a directory):
/// serialized under `dir`'s lock; the name leaves the cache, and the directory's and the removed
/// node's attributes go stale.
pub(super) fn remove(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    dir: FuseId,
    name: &[u8],
    child: FuseId,
    rmdir: bool,
) -> Result<(), Errno> {
    let last = with_dir_lock(cx, vfs, dir, |cx| {
        let (conn, nodeid) = fuse::target(vfs, dir)?;
        let opcode = if rmdir { op::RMDIR } else { op::UNLINK };
        fuse::call(cx, &conn, opcode, nodeid, &Args::default().name(name).0)?;
        let mut f = vfs.fuse_mut();
        f.forget_child(dir, name);
        f.stale(dir);
        f.stale(child);
        Ok(f.unlinked(child, rmdir))
    })?;
    // As the store's removals report: mark open descriptions unlinked, then report the file's
    // link count, its deletion with its last link, and the directory's entry
    let k = cx.kr();
    let (key, dkey) = (fuse::key(child), fuse::key(dir));
    inotify::unlinked(k, key, dkey, name);
    if rmdir {
        inotify::deleted(k, key, dkey, name);
        inotify::dir_event(k, dkey, name, inotify::IN_DELETE | inotify::IN_ISDIR, 0);
    } else {
        inotify::path_event(k, key, None, inotify::IN_ATTRIB);
        if last {
            inotify::deleted(k, key, dkey, name);
        }
        inotify::dir_event(k, dkey, name, inotify::IN_DELETE, 0);
    }
    Ok(())
}

/// Renames `old` in FUSE directory `from` to `new` in `to` (`FUSE_RENAME`, or `FUSE_RENAME2`
/// with flags; a daemon without it makes flags EINVAL, as 6.1's `fuse_rename2`), with both
/// directories' locks already held: both names leave the cache, both directories' attributes go
/// stale, and a directory moved keeps its new place for `..` and getcwd.
fn rename_locked(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    (from, old): (FuseId, &[u8]),
    (to, new): (FuseId, &[u8]),
    moved: Option<FuseId>,
    flags: u32,
) -> Result<(), Errno> {
    let (conn, nodeid) = fuse::target(vfs, from)?;
    let to_nodeid = vfs.fuse().get(to).ok_or(Errno::ENOTCONN)?.nodeid;
    if flags != 0 {
        if conn.borrow().no & fuse::no::RENAME2 != 0 {
            return Err(Errno::EINVAL);
        }
        let args = Args::default()
            .u64(to_nodeid)
            .u32(flags)
            .u32(0)
            .name(old)
            .name(new);
        match fuse::call(cx, &conn, op::RENAME2, nodeid, &args.0) {
            Err(Errno::ENOSYS) => return Err(Errno::EINVAL),
            r => r?,
        };
    } else {
        let args = Args::default().u64(to_nodeid).name(old).name(new);
        fuse::call(cx, &conn, op::RENAME, nodeid, &args.0)?;
    }
    let mut f = vfs.fuse_mut();
    f.forget_child(from, old);
    f.forget_child(to, new);
    f.stale(from);
    f.stale(to);
    if let Some(m) = moved {
        f.stale(m);
        f.moved(m, to, new);
    }
    Ok(())
}

/// The fields a `FUSE_SETATTR` sets (`struct fuse_setattr_in`); owners as kernel IDs.
#[derive(Default)]
pub(super) struct SetAttr {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    /// Access and modification times: None to leave, Some(None) for now, Some(Some(ns)).
    pub atime: Option<Option<i64>>,
    pub mtime: Option<Option<i64>>,
}

/// `FUSE_SETATTR` on node `id` (through open handle `fh` when given): the attributes it reports
/// back are cached.
pub(super) fn setattr(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    id: FuseId,
    set: &SetAttr,
    fh: Option<u64>,
) -> Result<(), Errno> {
    use fuse::fattr;
    let (conn, nodeid) = fuse::target(vfs, id)?;
    let ns = conn.borrow().user_ns().clone();
    let mut valid = 0;
    let mut bit = |on: bool, b: u32| {
        if on {
            valid |= b;
        }
    };
    bit(set.mode.is_some(), fattr::MODE);
    bit(set.uid.is_some(), fattr::UID);
    bit(set.gid.is_some(), fattr::GID);
    bit(set.size.is_some(), fattr::SIZE);
    bit(fh.is_some(), fattr::FH);
    bit(set.atime.is_some(), fattr::ATIME);
    bit(set.mtime.is_some(), fattr::MTIME);
    bit(set.atime == Some(None), fattr::ATIME_NOW);
    bit(set.mtime == Some(None), fattr::MTIME_NOW);
    let split = |t: Option<Option<i64>>| {
        let ns = t.flatten().unwrap_or(0);
        (
            ns.div_euclid(1_000_000_000) as u64,
            ns.rem_euclid(1_000_000_000) as u32,
        )
    };
    let (asec, ansec) = split(set.atime);
    let (msec, mnsec) = split(set.mtime);
    let (csec, cnsec) = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (now.as_secs(), now.subsec_nanos())
    };
    let up = |m: &crate::cred::IdMap, k: Option<u32>| {
        k.map_or(0, |k| m.up(k).unwrap_or(crate::cred::OVERFLOW_ID))
    };
    let args = Args::default()
        .u32(valid)
        .u32(0)
        .u64(fh.unwrap_or(0))
        .u64(set.size.unwrap_or(0))
        .u64(0)
        .u64(asec)
        .u64(msec)
        .u64(csec)
        .u32(ansec)
        .u32(mnsec)
        .u32(cnsec)
        .u32(set.mode.unwrap_or(0))
        .u32(0)
        .u32(up(&ns.uid_map.borrow(), set.uid))
        .u32(up(&ns.gid_map.borrow(), set.gid))
        .u32(0);
    with_io(cx, vfs, id, false, |cx| {
        let reply = fuse::call(cx, &conn, op::SETATTR, nodeid, &args.0)?;
        let (attr, until) = fuse::attr_out(&reply, &ns)?;
        let mut f = vfs.fuse_mut();
        let old = f.get(id).ok_or(Errno::ENOTCONN)?.attr.mode;
        if (attr.mode ^ old) & mode::S_IFMT != 0 {
            f.stale(id);
            return Err(Errno::EIO);
        }
        let size = attr.size;
        f.set_attr(id, attr, until);
        drop(f);
        if set.size.is_some() {
            resize_mapping(cx, vfs, id, size)?;
        }
        Ok(())
    })
}

// ---- Reading and writing ----

/// read(2) and its relatives on an open FUSE file: `FUSE_READ` from the position (0 for a
/// stream). `pos_held` is true when the caller already holds `file`'s `pos_busy`.
pub(super) fn read(
    cx: &mut Cx<'_>,
    file: &FileRef,
    io: &Io,
    buf: &mut [u8],
    offset: Option<u64>,
    pos_held: bool,
) -> Result<usize, Errno> {
    let offset = if io.stream { Some(0) } else { offset };
    let _pos = super::fs::PosGuard::lock_if(cx, file, offset.is_none() && !pos_held)?;
    let start = offset.unwrap_or_else(|| file.borrow().pos);
    let vfs = cx.vfs()?;
    let mut read = |cx: &mut Cx<'_>| {
        let data = fuse::read(cx, io.handle(), start, buf.len(), false)?;
        buf[..data.len()].copy_from_slice(&data);
        if let Some(pages) = mapped_pages(&vfs, io.id) {
            pages.overlay(start, &mut buf[..data.len()])?;
        }
        Ok(data.len())
    };
    let n = if mapped_pages(&vfs, io.id).is_some() {
        with_io(cx, &vfs, io.id, false, read)?
    } else {
        read(cx)?
    };
    if offset.is_none() {
        file.borrow_mut().pos = start + n as u64;
    }
    Ok(n)
}

/// write(2) and its relatives on an open FUSE file: `FUSE_WRITE` at the position, or with
/// `O_APPEND` at the size the daemon reports first (6.1's `fuse_cache_write_iter` refreshes it
/// the same way). The node's attributes go stale. `pos_held` is true when the caller already
/// holds `file`'s `pos_busy`.
pub(super) fn write(
    cx: &mut Cx<'_>,
    file: &FileRef,
    io: &Io,
    data: &[u8],
    offset: Option<u64>,
    append: bool,
    pos_held: bool,
) -> Result<usize, Errno> {
    // As fcntl may have changed it since the open, or a per-request flag (RWF_APPEND) asked for it
    let flags = file.borrow().flags;
    let append = append || flags & oflags::O_APPEND != 0;
    let offset = if io.stream { Some(0) } else { offset };
    let _pos = super::fs::PosGuard::lock_if(cx, file, offset.is_none() && !pos_held)?;
    let start = offset.unwrap_or_else(|| file.borrow().pos);
    let vfs = cx.vfs()?;
    // Appends to one node go one at a time from asking for the size to writing there
    let (n, at) = with_io(cx, &vfs, io.id, false, |cx| {
        let at = if append {
            fuse::getattr(cx, &vfs, io.id, io.fh(), false)?.size
        } else {
            start
        };
        // RLIMIT_FSIZE, as generic_write_checks applies it
        let data = &data[..super::fs::fsize_room(cx, at, data.len())?];
        let n = fuse::write(cx, (&io.conn, io.nodeid, io.fh, flags), at, data, false)?;
        if n != 0
            && let Some(pages) = mapped_pages(&vfs, io.id)
        {
            let end = at + n as u64;
            if end > pages.size() {
                pages.resize(end)?;
            }
            pages.written(at, &data[..n])?;
        }
        vfs.fuse_mut().stale(io.id);
        Ok((n, at))
    })?;
    if offset.is_none() {
        file.borrow_mut().pos = at + n as u64;
    }
    Ok(n)
}

/// Waits on `wake::LOCK` until `try_lock` succeeds, returning `EINTR` when stopping or killed
/// (unless `forced`). `try_lock` must drop any `RefCell` borrows before returning.
fn wait_lock(
    cx: &mut Cx<'_>,
    forced: bool,
    mut try_lock: impl FnMut() -> Result<bool, Errno>,
) -> Result<(), Errno> {
    while !try_lock()? {
        if cx.kr().stopping || !forced && cx.task.killed.get() {
            return Err(Errno::EINTR);
        }
        cx.wait_on(None, &mut [], crate::kernel::wake::LOCK)?;
    }
    Ok(())
}

/// Serializes daemon operations that change the page cache. A fill cannot publish an old
/// reply after a descriptor write or truncate, and overlapping writebacks complete in order.
fn with_io<T>(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    id: FuseId,
    forced: bool,
    run: impl FnOnce(&mut Cx<'_>) -> Result<T, Errno>,
) -> Result<T, Errno> {
    wait_lock(cx, forced, || {
        let mut f = vfs.fuse_mut();
        let n = f.get_mut(id).ok_or(Errno::ENOTCONN)?;
        if n.pages.upgrade().is_some_and(|p| p.bg_busy.get()) {
            return Ok(false);
        }
        Ok(!std::mem::replace(&mut n.io_busy, true))
    })?;
    struct Unlock<'a>(&'a Vfs, FuseId);
    impl Drop for Unlock<'_> {
        fn drop(&mut self) {
            if let Some(node) = self.0.fuse_mut().get_mut(self.1) {
                node.io_busy = false;
            }
            crate::kernel::request_wake_locks();
        }
    }
    let _unlock = Unlock(vfs, id);
    run(cx)
}

/// Pins a FUSE directory against `Fuses::evict` via `Node::dir_waiters` while a thread waits
/// to acquire its `dir_busy` lock (or `Conn::rename_busy` ahead of it).
struct DirWaiter<'a>(&'a Vfs, FuseId);

impl<'a> DirWaiter<'a> {
    fn enter(vfs: &'a Vfs, id: FuseId) -> Result<Self, Errno> {
        vfs.fuse_mut()
            .get_mut(id)
            .ok_or(Errno::ENOTCONN)?
            .dir_waiters += 1;
        Ok(Self(vfs, id))
    }
}

impl Drop for DirWaiter<'_> {
    fn drop(&mut self) {
        if let Some(node) = self.0.fuse_mut().get_mut(self.1) {
            node.dir_waiters = node.dir_waiters.saturating_sub(1);
        }
    }
}

/// RAII guard holding `Node::dir_busy` on one FUSE directory (Linux's directory `i_rwsem`).
/// Lock order: `RenameGuard` -> `DirGuard(lo)` -> `DirGuard(hi)`, never held with `io_busy` or
/// `pos_busy`.
struct DirGuard<'a>(&'a Vfs, FuseId);

impl<'a> DirGuard<'a> {
    fn lock(cx: &mut Cx<'_>, vfs: &'a Vfs, id: FuseId) -> Result<Self, Errno> {
        Self::lock_pinned(cx, DirWaiter::enter(vfs, id)?)
    }

    /// Acquires `Node::dir_busy` while `waiter` pins the directory, releasing the waiter pin once
    /// `dir_busy` is held (or on error).
    fn lock_pinned(cx: &mut Cx<'_>, waiter: DirWaiter<'a>) -> Result<Self, Errno> {
        let (vfs, id) = (waiter.0, waiter.1);
        wait_lock(cx, false, || {
            let mut fuse = vfs.fuse_mut();
            if fuse.conn_of(id)?.borrow().aborted {
                return Err(Errno::ENOTCONN);
            }
            let node = fuse.get_mut(id).ok_or(Errno::ENOTCONN)?;
            Ok(!std::mem::replace(&mut node.dir_busy, true))
        })?;
        Ok(Self(vfs, id))
    }
}

impl Drop for DirGuard<'_> {
    fn drop(&mut self) {
        if let Some(node) = self.0.fuse_mut().get_mut(self.1) {
            node.dir_busy = false;
        }
        crate::kernel::request_wake_locks();
    }
}

/// RAII guard holding `Conn::rename_busy` for cross-directory directory moves (Linux's
/// `s_vfs_rename_mutex`), always acquired before any [`DirGuard`].
struct RenameGuard(Rc<RefCell<Conn>>);

impl RenameGuard {
    fn lock(cx: &mut Cx<'_>, conn: Rc<RefCell<Conn>>) -> Result<Self, Errno> {
        wait_lock(cx, false, || {
            let mut c = conn.borrow_mut();
            if c.aborted {
                return Err(Errno::ENOTCONN);
            }
            Ok(!std::mem::replace(&mut c.rename_busy, true))
        })?;
        Ok(Self(conn))
    }
}

impl Drop for RenameGuard {
    fn drop(&mut self) {
        if let Ok(mut c) = self.0.try_borrow_mut() {
            c.rename_busy = false;
        }
        crate::kernel::request_wake_locks();
    }
}

/// Serializes directory-modifying operations in one FUSE directory under its `dir_busy` lock.
fn with_dir_lock<T>(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    dir: FuseId,
    run: impl FnOnce(&mut Cx<'_>) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let _dir = DirGuard::lock(cx, vfs, dir)?;
    run(cx)
}

/// Serializes a FUSE rename across `from` and `to`: locks one directory when `from == to`,
/// otherwise pins both, takes `Conn::rename_busy` first for cross-directory directory moves, and
/// locks `(lo, hi)` in canonical `FuseId` order.
fn with_dir_locks<T>(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    from: FuseId,
    to: FuseId,
    dir_move: bool,
    run: impl FnOnce(&mut Cx<'_>) -> Result<T, Errno>,
) -> Result<T, Errno> {
    if from == to {
        return with_dir_lock(cx, vfs, from, run);
    }
    let (lo, hi) = if from < to { (from, to) } else { (to, from) };
    // Pin both directories (and their ancestors for `is_within`) before any wait so `Fuses::evict`
    // cannot evict either while parked on `rename_busy` or `lo`.
    let wait_lo = DirWaiter::enter(vfs, lo)?;
    let wait_hi = DirWaiter::enter(vfs, hi)?;
    let _rename = if dir_move {
        let conn = vfs.fuse().conn_of(from)?;
        Some(RenameGuard::lock(cx, conn)?)
    } else {
        None
    };
    let _lo = DirGuard::lock_pinned(cx, wait_lo)?;
    let _hi = DirGuard::lock_pinned(cx, wait_hi)?;
    run(cx)
}

fn resize_mapping(cx: &Cx<'_>, vfs: &Vfs, id: FuseId, size: u64) -> Result<(), Errno> {
    if let Some(pages) = mapped_pages(vfs, id) {
        if size < pages.size() {
            super::fs::truncating(cx, &pages.host, size);
        }
        pages.resize(size)?;
    }
    Ok(())
}

/// lseek on an open FUSE file or directory: regular files follow 6.1's `fuse_file_llseek`
/// (`SEEK_END` from the daemon's size, `SEEK_DATA`/`SEEK_HOLE` via `FUSE_LSEEK` with a size-based
/// fallback); directories follow `generic_file_llseek` (inode size via cache or `FUSE_GETATTR`
/// without `FUSE_GETATTR_FH`, clearing cached entries on seek to 0). `FOPEN_NONSEEKABLE` and
/// `FOPEN_STREAM` return `ESPIPE`. Holds `pos_busy` against concurrent FUSE I/O.
pub(super) fn lseek(
    cx: &mut Cx<'_>,
    file: &FileRef,
    offset: i64,
    whence: u32,
) -> Result<u64, Errno> {
    const SEEK_SET: u32 = 0;
    const SEEK_CUR: u32 = 1;
    const SEEK_END: u32 = 2;
    const SEEK_DATA: u32 = 3;
    const SEEK_HOLE: u32 = 4;
    let (io, dir, seekable) = {
        let f = file.borrow();
        match &f.kind {
            FileKind::Fuse(h) => (Io::of(h), false, seekable(h)),
            FileKind::Directory { fuse: Some(h), .. } => (Io::of(h), true, seekable(h)),
            _ => return Err(Errno::EBADF),
        }
    };
    if !seekable {
        return Err(Errno::ESPIPE);
    }
    let _pos = super::fs::PosGuard::lock(cx, file)?;
    let pos = file.borrow().pos;
    let vfs = cx.vfs()?;
    let size = |cx: &mut Cx<'_>| -> Result<i64, Errno> {
        let sz = if dir {
            let cached = vfs
                .fuse()
                .get(io.id)
                .ok_or(Errno::ENOTCONN)?
                .fresh_attr()
                .map(|a| a.size);
            match cached {
                Some(s) => s,
                None => fuse::getattr(cx, &vfs, io.id, None, false)?.size,
            }
        } else {
            fuse::getattr(cx, &vfs, io.id, io.fh(), false)?.size
        };
        i64::try_from(sz).map_err(|_| Errno::EINVAL)
    };
    let new = match whence {
        SEEK_SET => offset,
        SEEK_CUR => (pos as i64).checked_add(offset).ok_or(Errno::EINVAL)?,
        SEEK_END => size(cx)?.checked_add(offset).ok_or(Errno::EINVAL)?,
        SEEK_DATA | SEEK_HOLE => {
            let found = if !dir && io.conn.borrow().no & fuse::no::LSEEK == 0 {
                let args = Args::default()
                    .u64(io.fh)
                    .u64(offset as u64)
                    .u32(whence)
                    .u32(0);
                match fuse::call(cx, &io.conn, fuse::op::LSEEK, io.nodeid, &args.0) {
                    Ok(r) => Some(fuse::Fields::new(&r).u64()? as i64),
                    Err(Errno::ENOSYS) => None,
                    Err(e) => return Err(e),
                }
            } else {
                None
            };
            match found {
                Some(at) => at,
                None => {
                    let eof = size(cx)?;
                    if offset < 0 || offset >= eof {
                        return Err(Errno::ENXIO);
                    }
                    if whence == SEEK_DATA { offset } else { eof }
                }
            }
        }
        _ => return Err(Errno::EINVAL),
    };
    if new < 0 {
        return Err(Errno::EINVAL);
    }
    let mut f = file.borrow_mut();
    if dir
        && new == 0
        && let FileKind::Directory { entries, .. } = &mut f.kind
    {
        *entries = None;
    }
    f.pos = new as u64;
    Ok(new as u64)
}

/// Lists an open FUSE directory for getdents64 the first time (and after a seek to 0): the
/// daemon's entries, `.` and `..` included as it gives them.
pub(super) fn fill_dir(cx: &mut Cx<'_>, file: &FileRef) -> Result<(), Errno> {
    let io = {
        let f = file.borrow();
        match &f.kind {
            FileKind::Directory {
                fuse: Some(h),
                entries: None,
                ..
            } => Io::of(h),
            _ => return Ok(()),
        }
    };
    let list: Vec<DirEntry> = fuse::readdir(cx, io.handle())?;
    if let FileKind::Directory { entries, .. } = &mut file.borrow_mut().kind {
        *entries = Some(list);
    }
    Ok(())
}

/// fsync and fdatasync of an open FUSE file or directory (`FUSE_FSYNC`, `FUSE_FSYNCDIR`): a
/// daemon without them has nothing to sync.
pub(super) fn fsync(cx: &mut Cx<'_>, io: &Io, dir: bool, data_only: bool) -> Result<(), Errno> {
    if !dir {
        writeback(cx, io.id, 0, u64::MAX)?;
    }
    sync_handle(cx, io, dir, data_only)
}

fn sync_handle(cx: &mut Cx<'_>, io: &Io, dir: bool, data_only: bool) -> Result<(), Errno> {
    let (conn, nodeid, fh) = (&io.conn, io.nodeid, io.fh);
    let (opcode, bit) = if dir {
        (op::FSYNCDIR, fuse::no::FSYNCDIR)
    } else {
        (op::FSYNC, fuse::no::FSYNC)
    };
    if conn.borrow().no & bit != 0 {
        return Ok(());
    }
    let args = Args::default().u64(fh).u32(u32::from(data_only)).u32(0);
    match fuse::call(cx, conn, opcode, nodeid, &args.0) {
        Err(Errno::ENOSYS) => Ok(()),
        r => r.map(|_| ()),
    }
}

const KEEP_SIZE: u32 = 1;
const PUNCH_HOLE: u32 = 2;

pub(super) fn remove_mapped(
    cx: &mut Cx<'_>,
    fill: &Fill,
    start: u64,
    end: u64,
) -> Result<(), Errno> {
    let io = file_io(&fill.source).ok_or(Errno::EIO)?;
    fallocate(cx, &io, KEEP_SIZE | PUNCH_HOLE, start, end - start)
}

/// fallocate of an open FUSE file (`FUSE_FALLOCATE`; a daemon without it is EOPNOTSUPP).
pub(super) fn fallocate(
    cx: &mut Cx<'_>,
    io: &Io,
    mode: u32,
    offset: u64,
    len: u64,
) -> Result<(), Errno> {
    // Only these two (6.1's fuse_file_fallocate), and a hole keeps the size (vfs_fallocate)
    if mode & !(KEEP_SIZE | PUNCH_HOLE) != 0 || mode == PUNCH_HOLE {
        return Err(Errno::EOPNOTSUPP);
    }
    if mode & KEEP_SIZE == 0 {
        super::fs::check_fsize(cx, offset.saturating_add(len))?;
    }
    if io.conn.borrow().no & fuse::no::FALLOCATE != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let args = Args::default()
        .u64(io.fh)
        .u64(offset)
        .u64(len)
        .u32(mode)
        .u32(0);
    let vfs = cx.vfs()?;
    with_io(cx, &vfs, io.id, false, |cx| {
        match fuse::call(cx, &io.conn, op::FALLOCATE, io.nodeid, &args.0) {
            Err(Errno::ENOSYS) => return Err(Errno::EOPNOTSUPP),
            r => r?,
        };
        vfs.fuse_mut().stale(io.id);
        if let Some(pages) = mapped_pages(&vfs, io.id) {
            let end = offset.saturating_add(len);
            if mode & PUNCH_HOLE != 0 {
                pages.punch(offset, end)?;
            } else if mode & KEEP_SIZE == 0 && end > pages.size() {
                pages.resize(end)?;
            }
        }
        Ok(())
    })
}

/// The I/O route of an open FUSE file (regular file or directory), for fsync and fallocate.
pub(super) fn io_of(file: &FileRef) -> Option<(Io, bool)> {
    match &file.borrow().kind {
        FileKind::Fuse(h) => Some((Io::of(h), false)),
        FileKind::Directory { fuse: Some(h), .. } => Some((Io::of(h), true)),
        _ => None,
    }
}

/// close(2) of a FUSE file: `FUSE_FLUSH`, whose error close returns (the descriptor is gone
/// anyway), as 6.1's `filp_close` does.
pub(super) fn flush(cx: &mut Cx<'_>, file: &FileRef) -> Result<(), Errno> {
    let table = Rc::as_ptr(&cx.t.fds) as usize;
    flush_as(cx, file, table)
}

/// [`flush`] for a file closed in the fd table at address `table`, whose lock owner the daemon
/// is told (seccomp's `SECCOMP_ADDFD_FLAG_SETFD` replaces an fd in another process's table).
pub(super) fn flush_as(cx: &mut Cx<'_>, file: &FileRef, table: usize) -> Result<(), Errno> {
    let h = match &file.borrow().kind {
        FileKind::Fuse(h) => Io::of(h),
        _ => return Ok(()),
    };
    let skip = {
        let f = file.borrow();
        let FileKind::Fuse(handle) = &f.kind else {
            return Ok(());
        };
        handle.no_release || handle.open_flags & fuse::fopen::NOFLUSH != 0
    };
    writeback(cx, h.id, 0, u64::MAX)?;
    if skip || h.conn.borrow().no & fuse::no::FLUSH != 0 {
        return Ok(());
    }
    let owner = fuse::lock_owner(table);
    let args = Args::default().u64(h.fh).u32(0).u32(0).u64(owner);
    match fuse::call_forced(cx, &h.conn, op::FLUSH, h.nodeid, &args.0) {
        Err(Errno::ENOSYS) => Ok(()),
        r => r.map(|_| ()),
    }
}

// ---- Metadata ----

/// stat of FUSE node `id` (6.1's `fuse_getattr`): EACCES for a process the mount does not allow,
/// otherwise the cached attributes (fetched again when out of date), with the instance's device
/// number and the block size the daemon gave.
pub(super) fn stat(vfs: &Vfs, cred: &Cred, node: &Node) -> Result<[u8; 128], Errno> {
    stat_fh(vfs, cred, node, None)
}

/// [`stat`], passing open file handle `fh` (`FUSE_GETATTR_FH`) when fetching stale attributes on
/// an open FUSE regular file (`fstat`, `fstatat`/`statx` with `AT_EMPTY_PATH`, `/proc/pid/fd`).
pub(super) fn stat_fh(
    vfs: &Vfs,
    cred: &Cred,
    node: &Node,
    fh: Option<u64>,
) -> Result<[u8; 128], Errno> {
    let Node::Fuse(_, id) = node else {
        return Err(Errno::EINVAL);
    };
    if !vfs.fuse().conn_of(*id)?.borrow().allows(cred) {
        return Err(Errno::EACCES);
    }
    let attr = fuse::cached_attr_fh(vfs, *id, fh)?;
    let mut b = encode_stat(&attr.stat(), vfs.dev_of(node));
    if attr.blksize != 0 {
        b[56..60].copy_from_slice(&attr.blksize.to_le_bytes());
    }
    Ok(b)
}

/// statfs of the FUSE filesystem node `id` is in (6.1's `fuse_statfs`): only `FUSE_SUPER_MAGIC`
/// for a process the mount does not allow.
pub(super) fn statfs(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    id: FuseId,
    flags: u64,
) -> Result<[u64; 11], Errno> {
    let cred = cx.cred();
    if !vfs.fuse().conn_of(id)?.borrow().allows(&cred) {
        let mut w = [0; 11];
        w[0] = fuse::SUPER_MAGIC;
        return Ok(w);
    }
    let s = fuse::statfs(cx, vfs, id)?;
    Ok([
        fuse::SUPER_MAGIC,
        s.bsize,
        s.blocks,
        s.bfree,
        s.bavail,
        s.files,
        s.ffree,
        0,
        s.namelen,
        s.frsize,
        flags,
    ])
}

/// access(2) on FUSE node `id` (6.1's `fuse_permission` with `MAY_ACCESS`): the mount's own
/// checks, then without `default_permissions` the daemon's answer to `FUSE_ACCESS`.
pub(super) fn access(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    cred: &Cred,
    id: FuseId,
    amode: u32,
) -> Result<(), Errno> {
    let conn = vfs.fuse().conn_of(id)?;
    if !conn.borrow().allows(cred) {
        return Err(Errno::EACCES);
    }
    if conn.borrow().opts.default_permissions {
        return cred.permission(&fuse::cached_attr(vfs, id)?.stat(), amode);
    }
    fuse::access(cx, vfs, cred, id, amode)
}

/// The checks chdir, fchdir and chroot make on FUSE directory `id`: search permission, asked of
/// the daemon without `default_permissions` (6.1's `MAY_CHDIR`).
pub(super) fn may_chdir(cx: &mut Cx<'_>, vfs: &Vfs, cred: &Cred, id: FuseId) -> Result<(), Errno> {
    access(cx, vfs, cred, id, MAY_EXEC)
}

// ---- Extended attributes ----

/// The xattr permission rules of [`super::xattr`] on FUSE node `id`: `trusted.*` needs
/// `CAP_SYS_ADMIN` (hidden otherwise), `user.*` only on regular files and directories and with
/// read or write permission, which for FUSE is [`Vfs::fuse_permission`].
pub(super) fn xattr_permission(
    vfs: &Vfs,
    cred: &Cred,
    id: FuseId,
    name: &[u8],
    write: bool,
) -> Result<(), Errno> {
    use crate::cred::cap;
    let hidden = if write { Errno::EPERM } else { Errno::ENODATA };
    if name.starts_with(b"trusted.") {
        return if cred.capable(cap::SYS_ADMIN) {
            Ok(())
        } else {
            Err(hidden)
        };
    }
    if name.starts_with(b"user.") {
        let kind = vfs.fuse().get(id).ok_or(Errno::ENOTCONN)?.kind();
        if kind != mode::S_IFREG && kind != mode::S_IFDIR {
            return Err(hidden);
        }
        // In a sticky directory only its owner may change them (xattr_permission)
        if write && kind == mode::S_IFDIR {
            let st = fuse::cached_attr(vfs, id)?.stat();
            if st.mode & mode::S_ISVTX != 0 && !cred.owns(&st) {
                return Err(Errno::EPERM);
            }
        }
        return vfs.fuse_permission(cred, id, if write { MAY_WRITE } else { MAY_READ });
    }
    // Program file capabilities need CAP_SETFCAP over the file (cap_convert_nscap); other
    // security attributes CAP_SYS_ADMIN (cap_inode_setxattr)
    if write && name == crate::cred::XATTR_NAME_CAPS {
        let st = fuse::cached_attr(vfs, id)?.stat();
        if !cred.capable_wrt(&st, cap::SETFCAP) {
            return Err(Errno::EPERM);
        }
    } else if write && name.starts_with(b"security.") && !cred.capable(cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    vfs.fuse_permission(cred, id, 0)
}

/// setxattr (`value` Some, with flags) or removexattr on FUSE node `id`: `FUSE_SETXATTR` or
/// `FUSE_REMOVEXATTR`, EOPNOTSUPP from a daemon without them.
pub(super) fn set_xattr(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    id: FuseId,
    name: &[u8],
    value: Option<(&[u8], u32)>,
) -> Result<(), Errno> {
    let (conn, nodeid) = fuse::target(vfs, id)?;
    let (opcode, bit, args) = match value {
        Some((v, flags)) => (
            op::SETXATTR,
            fuse::no::SETXATTR,
            Args::default()
                .u32(v.len() as u32)
                .u32(flags)
                .name(name)
                .bytes(v),
        ),
        None => (
            op::REMOVEXATTR,
            fuse::no::REMOVEXATTR,
            Args::default().name(name),
        ),
    };
    if conn.borrow().no & bit != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    match fuse::call(cx, &conn, opcode, nodeid, &args.0) {
        Err(Errno::ENOSYS) => Err(Errno::EOPNOTSUPP),
        r => {
            r?;
            vfs.fuse_mut().stale(id);
            Ok(())
        }
    }
}

// ---- The device ----

/// `FUSE_DEV_IOC_CLONE` (`_IOR(229, 0, uint32_t)`): attaches device file `file`, which has no
/// connection yet, to the connection of the device file whose fd the argument holds, so a daemon
/// can read requests on several descriptors (6.1's `fuse_dev_ioctl`). Anything but an attached
/// device file opened in the same user namespace, a bad fd included, is EINVAL.
pub(super) const DEV_IOC_CLONE: u32 = 0x8004_e500;

pub(super) fn dev_ioctl(
    cx: &mut Cx<'_>,
    file: &FileRef,
    request: u32,
    arg: u64,
) -> Result<u64, Errno> {
    if request != DEV_IOC_CLONE {
        return Err(Errno::ENOTTY);
    }
    let mut b = [0u8; 4];
    cx.read_user(crate::uaccess::UserSlice::new(arg, 4), &mut b)?;
    let old = cx
        .fds()
        .get(i32::from_le_bytes(b))
        .map_err(|_| Errno::EINVAL)?;
    let (conn, ns) = match &old.borrow().kind {
        FileKind::FuseDev(d) => (d.conn.clone().ok_or(Errno::EINVAL)?, d.opener_ns.clone()),
        _ => return Err(Errno::EINVAL),
    };
    match &mut file.borrow_mut().kind {
        FileKind::FuseDev(d) if d.conn.is_none() && Rc::ptr_eq(&d.opener_ns, &ns) => {
            d.attach(&conn)
        }
        _ => return Err(Errno::EINVAL),
    }
    Ok(0)
}

// ---- Changing the namespace ----

/// A FUSE directory (through its mount) and a name in it.
pub(super) type FuseParent<'p> = (MountId, FuseId, &'p [u8]);

/// The FUSE directory the last name of `path` is in, and the name, when it is one (the parent's
/// resolution errors are returned as they are).
pub(super) fn parent<'p>(
    cx: &Cx<'_>,
    dirfd: i32,
    path: &'p [u8],
) -> Result<Option<FuseParent<'p>>, Errno> {
    let start = super::fs::start_dir(cx, dirfd, path)?;
    let vfs = cx.vfs()?;
    let (dir, name) = vfs.resolve_parent(&cx.view(&vfs), &cx.cred(), &cx.root(), &start, path)?;
    Ok(match dir {
        Node::Fuse(mnt, d) => Some((mnt, d, name)),
        _ => None,
    })
}

/// The checks before creating `name` in FUSE directory `dir` (6.1's `filename_create` and
/// `may_create`): `.`, `..` and an existing name are EEXIST, then a read-only mount EROFS, then
/// the directory must be writable and searchable as [`Vfs::fuse_permission`] decides.
fn may_create(
    vfs: &Vfs,
    cred: &Cred,
    (mnt, dir): (MountId, FuseId),
    name: &[u8],
) -> Result<(), Errno> {
    if name == b"." || name == b".." {
        return Err(Errno::EEXIST);
    }
    vfs.fuse_permission(cred, dir, MAY_EXEC)?;
    match vfs.fuse_child(dir, name) {
        Ok(_) => return Err(Errno::EEXIST),
        Err(e) if e == Errno::ENOENT => {}
        Err(e) => return Err(e),
    }
    if vfs.readonly(&Node::Fuse(mnt, dir)) {
        return Err(Errno::EROFS);
    }
    vfs.fuse_permission(cred, dir, MAY_WRITE | MAY_EXEC)
}

/// Creates a Unix-domain socket node for `bind(2)` in a FUSE directory (`FUSE_MKNOD` with
/// `S_IFSOCK`), pinning the node against cache eviction while `sock` stays bound. Returns
/// `Ok(None)` when `path`'s parent directory is not on a FUSE mount.
pub(super) fn bind_socket(
    cx: &mut Cx<'_>,
    path: &[u8],
    sock: &super::SocketRef,
) -> Result<Option<crate::vfs::store::Ino>, Errno> {
    let Some((mnt, dir, name)) = parent(cx, super::fs::AT_FDCWD, path)? else {
        return Ok(None);
    };
    let in_use = |e: Errno| {
        if e == Errno::EEXIST {
            Errno::EADDRINUSE
        } else {
            e
        }
    };
    if name == b"." || name == b".." {
        return Err(Errno::EADDRINUSE);
    }
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    if path.ends_with(b"/") {
        vfs.fuse_permission(&cred, dir, MAY_EXEC)?;
        return Err(match vfs.fuse_child(dir, name) {
            Ok(_) => Errno::EADDRINUSE,
            Err(e) => e,
        });
    }
    may_create(&vfs, &cred, (mnt, dir), name).map_err(in_use)?;
    let (conn, _) = fuse::target(&vfs, dir)?;
    let perm = masked(&conn, 0o777, cx.umask());
    let id = make(cx, &vfs, dir, name, Make::Node(mode::S_IFSOCK | perm, 0)).map_err(in_use)?;
    vfs.fuse_mut().pin_socket(id, sock);
    Ok(Some(fuse::key(id)))
}

/// mkdir in FUSE directory `dir` (`FUSE_MKDIR`).
pub(super) fn mkdir(
    cx: &mut Cx<'_>,
    at: (MountId, FuseId),
    name: &[u8],
    perm: u32,
) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    may_create(&vfs, &cx.cred(), at, name)?;
    let (conn, _) = fuse::target(&vfs, at.1)?;
    // vfs_mkdir keeps only the permission and sticky bits
    let perm = masked(&conn, perm & 0o1777, cx.umask());
    make(cx, &vfs, at.1, name, Make::Dir(perm)).map(|_| ())
}

/// mknod in FUSE directory `dir` (`FUSE_MKNOD`): devices need `CAP_MKNOD`, as `vfs_mknod`
/// checks.
pub(super) fn mknod(
    cx: &mut Cx<'_>,
    at: (MountId, FuseId),
    name: &[u8],
    mode_arg: u32,
    dev: u64,
) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    may_create(&vfs, &cred, at, name)?;
    let kind = match mode_arg & mode::S_IFMT {
        0 => mode::S_IFREG,
        k => k,
    };
    // A whiteout (character device 0:0) needs no CAP_MKNOD and does not go through the device
    // filter (Linux's vfs_mknod); block device 0:0 is not a whiteout and is still checked
    let whiteout = kind == mode::S_IFCHR && dev & 0xffff_ffff == 0;
    if matches!(kind, mode::S_IFCHR | mode::S_IFBLK) && !whiteout {
        if !cred.capable(crate::cred::cap::MKNOD) {
            return Err(Errno::EPERM);
        }
        super::bpf::check_device(cx, kind, dev & 0xffff_ffff, crate::bpf::ACC_MKNOD)?;
    }
    let (conn, _) = fuse::target(&vfs, at.1)?;
    let perm = masked(&conn, mode_arg & 0o7777, cx.umask());
    make(
        cx,
        &vfs,
        at.1,
        name,
        Make::Node(kind | perm, dev & 0xffff_ffff),
    )
    .map(|_| ())
}

/// symlink in FUSE directory `dir` (`FUSE_SYMLINK`).
pub(super) fn symlink(
    cx: &mut Cx<'_>,
    at: (MountId, FuseId),
    name: &[u8],
    target: &[u8],
) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    may_create(&vfs, &cx.cred(), at, name)?;
    make(cx, &vfs, at.1, name, Make::Symlink(target)).map(|_| ())
}

/// link of FUSE node `src` as `name` in FUSE directory `dir` (`FUSE_LINK`): both must be on one
/// mount (EXDEV), and a directory cannot be linked (EPERM).
pub(super) fn link(
    cx: &mut Cx<'_>,
    src: &Node,
    at: (MountId, FuseId),
    name: &[u8],
) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    let cred = cx.cred();
    let (mnt, dir) = at;
    // 6.1's do_linkat: the new name (EEXIST, then EROFS), the mounts (EXDEV), may_linkat, then
    // vfs_link (the directory's permission, EPERM for a directory)
    if name == b"." || name == b".." {
        return Err(Errno::EEXIST);
    }
    match vfs.fuse_child(dir, name) {
        Ok(_) => return Err(Errno::EEXIST),
        Err(e) if e == Errno::ENOENT => {}
        Err(e) => return Err(e),
    }
    if vfs.readonly(&Node::Fuse(mnt, dir)) {
        return Err(Errno::EROFS);
    }
    let Node::Fuse(src_mnt, id) = *src else {
        return Err(Errno::EXDEV);
    };
    if src_mnt != mnt {
        return Err(Errno::EXDEV);
    }
    // fs.protected_hardlinks, with the file's permission as the mount decides it
    if cx.kr().protected_hardlinks {
        let st = fuse::cached_attr(&vfs, id)?.stat();
        let setgid_exec = mode::S_ISGID | 0o010;
        let rw = match vfs.fuse_permission(&cred, id, MAY_READ | MAY_WRITE) {
            Ok(()) => true,
            Err(e) if e == Errno::FUSE_RETRY => return Err(e),
            Err(_) => false,
        };
        let safe = st.kind() == mode::S_IFREG
            && st.mode & mode::S_ISUID == 0
            && st.mode & setgid_exec != setgid_exec
            && rw;
        if !safe && !cred.owns(&st) {
            return Err(Errno::EPERM);
        }
    }
    vfs.fuse_permission(&cred, dir, MAY_WRITE | MAY_EXEC)?;
    let (kind, nodeid) = {
        let f = vfs.fuse();
        let n = f.get(id).ok_or(Errno::ENOTCONN)?;
        (n.kind(), n.nodeid)
    };
    if kind == mode::S_IFDIR {
        return Err(Errno::EPERM);
    }
    make(cx, &vfs, dir, name, Make::Link(nodeid))?;
    vfs.fuse_mut().stale(id);
    Ok(())
}

/// unlink and rmdir of `name` in FUSE directory `dir` (6.1's `do_unlinkat` and `do_rmdir`):
/// `.` and `..`, a read-only mount, the name's lookup, a trailing slash on a non-directory, the
/// directory's permission, the type, a mount point (EBUSY), then `FUSE_UNLINK` or `FUSE_RMDIR`
/// (the daemon answers ENOTEMPTY).
pub(super) fn unlink(
    cx: &mut Cx<'_>,
    (mnt, dir): (MountId, FuseId),
    name: &[u8],
    rmdir: bool,
    trailing_slash: bool,
) -> Result<(), Errno> {
    match name {
        b"." if rmdir => return Err(Errno::EINVAL),
        b".." if rmdir => return Err(Errno::ENOTEMPTY),
        b"." | b".." => return Err(Errno::EISDIR),
        _ => {}
    }
    let vfs = cx.vfs()?;
    let dnode = Node::Fuse(mnt, dir);
    if vfs.readonly(&dnode) {
        return Err(Errno::EROFS);
    }
    let child = vfs.fuse_child(dir, name)?;
    let kind = vfs.fuse().node(child).kind();
    let is_dir = kind == mode::S_IFDIR;
    if !rmdir && trailing_slash {
        return Err(if is_dir {
            Errno::EISDIR
        } else {
            Errno::ENOTDIR
        });
    }
    let cred = cx.cred();
    vfs.fuse_permission(&cred, dir, MAY_WRITE | MAY_EXEC)?;
    sticky(&vfs, &cred, dir, child)?;
    match (rmdir, is_dir) {
        (true, false) => return Err(Errno::ENOTDIR),
        (false, true) => return Err(Errno::EISDIR),
        _ => {}
    }
    if vfs.is_point_in(&Node::Fuse(mnt, child), cx.mnt_ns()) {
        return Err(Errno::EBUSY);
    }
    remove(cx, &vfs, dir, name, child, rmdir)
}

/// The sticky-directory rule of `may_delete` with `default_permissions`: in a sticky directory
/// only the owner of the file or of the directory (or `CAP_FOWNER`) may remove or rename it.
fn sticky(vfs: &Vfs, cred: &Cred, dir: FuseId, child: FuseId) -> Result<(), Errno> {
    let default_permissions = vfs.fuse().conn_of(dir)?.borrow().opts.default_permissions;
    if !default_permissions {
        return Ok(());
    }
    let d = fuse::cached_attr(vfs, dir)?.stat();
    let c = fuse::cached_attr(vfs, child)?.stat();
    cred.may_delete(&d, &c)
}

/// renameat2 between FUSE directories (6.1's `do_renameat2` and `vfs_rename` on a FUSE
/// filesystem): both on one mount (EXDEV), the names' checks in Linux's order, then the request.
pub(super) fn rename_at(
    cx: &mut Cx<'_>,
    (mnt, from, old): (MountId, FuseId, &[u8]),
    (to_mnt, to, new): (MountId, FuseId, &[u8]),
    flags: u32,
) -> Result<(), Errno> {
    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;
    if mnt != to_mnt {
        return Err(Errno::EXDEV);
    }
    for (name, src) in [(old, true), (new, false)] {
        if name == b"." || name == b".." {
            return Err(if !src && flags & RENAME_NOREPLACE != 0 {
                Errno::EEXIST
            } else {
                Errno::EBUSY
            });
        }
    }
    let vfs = cx.vfs()?;
    if vfs.readonly(&Node::Fuse(mnt, from)) {
        return Err(Errno::EROFS);
    }
    let src = vfs.fuse_child(from, old)?;
    let dst = match vfs.fuse_child(to, new) {
        Ok(d) => Some(d),
        Err(e) if e == Errno::ENOENT => None,
        Err(e) => return Err(e),
    };
    if flags & RENAME_EXCHANGE != 0 && dst.is_none() {
        return Err(Errno::ENOENT);
    }
    if flags & RENAME_NOREPLACE != 0 && dst.is_some() {
        return Err(Errno::EEXIST);
    }
    let cred = cx.cred();
    vfs.fuse_permission(&cred, from, MAY_WRITE | MAY_EXEC)?;
    vfs.fuse_permission(&cred, to, MAY_WRITE | MAY_EXEC)?;
    sticky(&vfs, &cred, from, src)?;
    let src_dir = vfs.fuse().node(src).kind() == mode::S_IFDIR;
    if let Some(d) = dst {
        if d == src {
            return Ok(());
        }
        sticky(&vfs, &cred, to, d)?;
        let dst_dir = vfs.fuse().node(d).kind() == mode::S_IFDIR;
        if flags & RENAME_EXCHANGE == 0 {
            match (src_dir, dst_dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                _ => {}
            }
        }
        if vfs.is_point_in(&Node::Fuse(mnt, d), cx.mnt_ns()) {
            return Err(Errno::EBUSY);
        }
    }
    if vfs.is_point_in(&Node::Fuse(mnt, src), cx.mnt_ns()) {
        return Err(Errno::EBUSY);
    }
    // What the replaced name was: a directory, or a file whose last link may be gone
    let dst_seen = dst.and_then(|d| {
        let f = vfs.fuse();
        Some((d, f.get(d)?.kind() == mode::S_IFDIR))
    });
    let exchange = flags & RENAME_EXCHANGE != 0;
    // A directory cannot move under itself (checked now and re-checked under the directory locks)
    let check_loop = || {
        let f = vfs.fuse();
        if src_dir && f.is_within(to, src)
            || exchange && matches!(dst_seen, Some((d, true)) if f.is_within(from, d))
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    };
    check_loop()?;
    let dir_move = src_dir || (exchange && dst_seen.is_some_and(|(_, d)| d));
    let dst_seen = with_dir_locks(cx, &vfs, from, to, dir_move, |cx| {
        check_loop()?;
        rename_locked(
            cx,
            &vfs,
            (from, old),
            (to, new),
            src_dir.then_some(src),
            flags,
        )?;
        Ok(dst_seen.map(|(d, dir)| {
            let mut f = vfs.fuse_mut();
            f.stale(d);
            let last = if exchange {
                if dir {
                    f.moved(d, from, old);
                }
                false
            } else {
                f.unlinked(d, dir)
            };
            (d, dir, last)
        }))
    })?;
    // fsnotify_move: mark any replaced target unlinked, move open files to their new names, then
    // emit the pair of moves with one cookie, the replaced file's events and the moved file's own
    // event
    let k = cx.kr();
    let isdir = |dir: bool| if dir { inotify::IN_ISDIR } else { 0 };
    let (fk, tk) = (fuse::key(from), fuse::key(to));
    if flags & RENAME_EXCHANGE == 0
        && let Some((d, _, _)) = dst_seen
    {
        inotify::unlinked(k, fuse::key(d), tk, new);
    }
    inotify::renamed(k, (fk, old), (tk, new), || Some(fuse::key(src)));
    if flags & RENAME_EXCHANGE != 0
        && let Some((d, _, _)) = dst_seen
    {
        inotify::renamed(k, (tk, new), (fk, old), || Some(fuse::key(d)));
    }
    let cookie = inotify::cookie(k);
    inotify::dir_event(k, fk, old, inotify::IN_MOVED_FROM | isdir(src_dir), cookie);
    inotify::dir_event(k, tk, new, inotify::IN_MOVED_TO | isdir(src_dir), cookie);
    match dst_seen {
        Some((d, dir, _)) if flags & RENAME_EXCHANGE != 0 => {
            let cookie = inotify::cookie(k);
            inotify::dir_event(k, tk, new, inotify::IN_MOVED_FROM | isdir(dir), cookie);
            inotify::dir_event(k, fk, old, inotify::IN_MOVED_TO | isdir(dir), cookie);
            inotify::path_event(k, fuse::key(d), None, inotify::IN_MOVE_SELF);
        }
        Some((d, dir, last)) => {
            inotify::path_event(k, fuse::key(d), None, inotify::IN_ATTRIB);
            if dir || last {
                inotify::deleted(k, fuse::key(d), tk, new);
            }
        }
        None => {}
    }
    inotify::path_event(k, fuse::key(src), None, inotify::IN_MOVE_SELF);
    Ok(())
}

// ---- Attributes ----

/// Whether the mount node `id` is in checks permissions itself (`default_permissions`); without
/// it, attribute changes are the daemon's to refuse (6.1's `fuse_setattr` sets `ATTR_FORCE`).
pub(super) fn checks_permissions(vfs: &Vfs, id: FuseId) -> Result<bool, Errno> {
    Ok(vfs.fuse().conn_of(id)?.borrow().opts.default_permissions)
}

/// truncate(2) of FUSE node `id` (6.1's `vfs_truncate`): the type, a read-only mount, write
/// permission, then `FUSE_SETATTR` with the size.
pub(super) fn truncate(cx: &mut Cx<'_>, node: &Node, len: u64) -> Result<(), Errno> {
    let Node::Fuse(_, id) = *node else {
        return Err(Errno::EINVAL);
    };
    let vfs = cx.vfs()?;
    match vfs.fuse().get(id).ok_or(Errno::ENOTCONN)?.kind() {
        mode::S_IFDIR => return Err(Errno::EISDIR),
        mode::S_IFREG => {}
        _ => return Err(Errno::EINVAL),
    }
    if vfs.readonly(node) {
        return Err(Errno::EROFS);
    }
    vfs.fuse_permission(&cx.cred(), id, MAY_WRITE)?;
    super::fs::check_fsize(cx, len)?;
    let set = SetAttr {
        size: Some(len),
        ..SetAttr::default()
    };
    setattr(cx, &vfs, id, &set, None)
}

/// ftruncate of an open FUSE file: `FUSE_SETATTR` with the size through its handle.
pub(super) fn ftruncate(cx: &mut Cx<'_>, io: &Io, len: u64) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    let set = SetAttr {
        size: Some(len),
        ..SetAttr::default()
    };
    setattr(cx, &vfs, io.id, &set, io.fh())
}

/// The open FUSE regular file of descriptor `file`.
pub(super) fn file_io(file: &FileRef) -> Option<Io> {
    match &file.borrow().kind {
        FileKind::Fuse(h) => Some(Io::of(h)),
        _ => None,
    }
}

// ---- Mappings ----

/// Independent opens of the same inode map one sparse memfd. Each mapping pins its own
/// handle for demand reads and a shared writable mapping also supplies the writeback handle.
pub(super) fn map_fill(
    cx: &mut Cx<'_>,
    file: &FileRef,
    shared: bool,
    refused: bool,
) -> Result<Option<Rc<Fill>>, Errno> {
    let (id, fh, direct) = {
        let f = file.borrow();
        match &f.kind {
            FileKind::Fuse(h) if f.readable() && !refused => {
                (h.id, h.fh(), h.open_flags & fuse::fopen::DIRECT_IO != 0)
            }
            _ => return Ok(None),
        }
    };
    if direct && shared {
        return Err(Errno::ENODEV);
    }
    let vfs = cx.vfs()?;
    let pages = if let Some(pages) = mapped_pages(&vfs, id) {
        pages
    } else {
        let size = fuse::cached_attr_fh(&vfs, id, fh)?.size;
        let host = appine_hal::memfd(c"appine-fuse").map_err(Errno)?;
        host.set_len(size)
            .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
        let pages = FillPages::new(host, size);
        {
            let mut f = vfs.fuse_mut();
            f.get_mut(id).ok_or(Errno::ENOTCONN)?.pages = Rc::downgrade(&pages);
            f.track_mapped(id);
        }
        pages
    };
    let fill = Rc::new(Fill {
        shared,
        source: file.clone(),
        pages,
    });
    if file.borrow().writable() {
        fill.add_writer(&fill);
    }
    Ok(Some(fill))
}

/// Refresh the mapped EOF after a data invalidation. A daemon can notify while replying
/// to GETATTR, so only a reply for the current generation may resize the backing.
fn refresh_mapping_size(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    io: &Io,
    pages: &FillPages,
    forced: bool,
) -> Result<(), Errno> {
    while pages.size_stale.get() {
        let generation = pages.generation.get();
        let reply = fuse::getattr_no_inval(cx, vfs, io.id, io.fh(), forced);
        if generation == pages.generation.get() {
            resize_mapping(cx, vfs, io.id, reply?.size)?;
            pages.size_stale.set(false);
        }
    }
    Ok(())
}

/// Reads into an on-demand mapping of a FUSE file ([`Fill`]) the pages missing around file page
/// `page` (Linux's `filemap_fault` read-around), the BKL released while the daemon answers.
pub(crate) fn fill(cx: &mut Cx<'_>, wanted: (Rc<Fill>, u64)) -> Result<(), Errno> {
    fill_page(cx, wanted, false)
}

/// The core writer runs after group_exit marked the dumping thread killed. Wait for its
/// daemon replies as for exit writeback, including a size refresh before reading the page.
pub(crate) fn fill_for_dump(cx: &mut Cx<'_>, addr: u64) -> Result<(), Errno> {
    for _ in 0..=super::FUSE_RETRIES {
        let Some(wanted) = cx.mm().first_unread(addr, 1, 0) else {
            return Ok(());
        };
        fill_page(cx, wanted, true)?;
    }
    Err(Errno::EIO)
}

/// After the other threads have exited, a device held only by the dumping process
/// cannot answer its own page fault. An inherited fd is fine if another task can serve it.
fn dump_owns_last_device(cx: &Cx<'_>, conn: &Rc<RefCell<Conn>>) -> bool {
    let serves = |fds: &crate::fd::FdTable| {
        fds.files().any(|file| {
            matches!(&file.borrow().kind, FileKind::FuseDev(dev)
                if dev.conn.as_ref().is_some_and(|c| Rc::ptr_eq(c, conn)))
        })
    };
    serves(&cx.fds())
        && !cx
            .kr()
            .tasks
            .values()
            .any(|task| !task.killed.get() && serves(&task.res.borrow().fds.borrow()))
}

fn fill_page(cx: &mut Cx<'_>, (fill, page): (Rc<Fill>, u64), forced: bool) -> Result<(), Errno> {
    let io = file_io(&fill.source).ok_or(Errno::EIO)?;
    if forced && dump_owns_last_device(cx, &io.conn) {
        return Err(Errno::ENOTCONN);
    }
    let vfs = cx.vfs()?;
    with_io(cx, &vfs, io.id, forced, |cx| {
        refresh_mapping_size(cx, &vfs, &io, &fill, forced)?;
        let Some(mut window) = fill.window(page) else {
            return Ok(());
        };
        let generation = fill.generation.get();
        loop {
            let around = window.0 < page * PAGE_SIZE;
            let read = read_fill_window(cx, &io, &fill, window, around, generation, forced);
            if generation != fill.generation.get() {
                // The page fault or kernel access retries using a fresh window.
                return Ok(());
            }
            let (data, eof) = read?;
            fill.store(window, &data, eof)?;
            if !around || fill.has(page) {
                break;
            }
            let Some(next) = fill.window_from(page) else {
                break;
            };
            window = next;
        }
        Ok(())
    })
}

/// For a forward read, collect at least one complete page unless the daemon confirms EOF.
fn read_fill_window(
    cx: &mut Cx<'_>,
    io: &Io,
    fill: &FillPages,
    (offset, len): (u64, u64),
    around: bool,
    generation: u64,
    forced: bool,
) -> Result<(Vec<u8>, bool), Errno> {
    let mut data = fuse::read(cx, io.handle(), offset, len as usize, forced)?;
    if around {
        return Ok((data, false));
    }
    let mut eof = data.is_empty();
    while !eof
        && data.len() < PAGE_SIZE as usize
        && offset + (data.len() as u64) < fill.size()
        && generation == fill.generation.get()
    {
        let want = PAGE_SIZE as usize - data.len();
        let more = fuse::read(cx, io.handle(), offset + data.len() as u64, want, forced)?;
        eof = more.is_empty();
        data.extend_from_slice(&more);
    }
    Ok((data, eof))
}

/// Write changed pages in the file range through a retained writable open. The baseline
/// advances only for bytes actually accepted by the daemon, so fsync can retry a failed write.
fn writeback(cx: &mut Cx<'_>, id: FuseId, start: u64, end: u64) -> Result<(), Errno> {
    let vfs = cx.vfs()?;
    let Some(pages) = mapped_pages(&vfs, id) else {
        return Ok(());
    };
    let Some(writer) = pages.writer() else {
        return Ok(());
    };
    let io = file_io(&writer.source).ok_or(Errno::EIO)?;
    with_io(cx, &vfs, id, true, |cx| {
        for page in pages.tracked(start, end) {
            refresh_mapping_size(cx, &vfs, &io, &pages, true)?;
            for (at, data) in pages.dirty_runs(page)? {
                // Another invalidation may have arrived during the preceding write.
                refresh_mapping_size(cx, &vfs, &io, &pages, true)?;
                let len = (data.len() as u64).min(pages.size().saturating_sub(at)) as usize;
                let n = fuse::write(cx, io.handle(), at, &data[..len], true)?;
                pages.acknowledge(at, &data[..n]);
                if n != len {
                    return Err(Errno::EIO);
                }
            }
        }
        if start == 0
            && end == u64::MAX
            && let Some(node) = vfs.fuse_mut().get_mut(id)
        {
            node.retry_writeback = None;
        }
        Ok(())
    })
}

pub(super) fn sync_mapping(
    cx: &mut Cx<'_>,
    fill: &Fill,
    start: u64,
    end: u64,
) -> Result<(), Errno> {
    let io = file_io(&fill.source).ok_or(Errno::EIO)?;
    writeback(cx, io.id, start, end)?;
    sync_handle(cx, &io, false, true)
}

pub(crate) fn flush_mappings(cx: &mut Cx<'_>) {
    let ranges = cx.mm().fuse_ranges(0, u64::MAX);
    flush_ranges(cx, ranges);
}

fn flush_ranges(cx: &mut Cx<'_>, ranges: Vec<(Rc<Fill>, u64, u64)>) {
    for (fill, start, end) in ranges {
        if let Some(io) = file_io(&fill.source)
            && writeback(cx, io.id, start, end).is_err()
            && let Ok(vfs) = cx.vfs()
            && let Some(node) = vfs.fuse_mut().get_mut(io.id)
        {
            node.retry_writeback = fill.writer();
        }
    }
}

/// Prefaults any cold FUSE `Fill` pages overlapping `[addr, addr + len)` that permit `need`.
/// Errors are swallowed so the syscall itself surfaces them with Linux's error order.
pub(super) fn prefault_range(cx: &mut Cx<'_>, addr: u64, len: u64, need: u32) {
    if len == 0 || addr == 0 || !cx.mm().has_fills() {
        return;
    }
    let mut retries = 0;
    let mut last: Option<(usize, u64)> = None;
    loop {
        let Some(w) = cx.mm().first_unread(addr, len, need) else {
            return;
        };
        let key = (Rc::as_ptr(&w.0.pages) as usize, w.1);
        if last == Some(key) {
            retries += 1;
            if retries > super::FUSE_RETRIES {
                return;
            }
        } else {
            last = Some(key);
            retries = 0;
        }
        if fill(cx, w).is_err() {
            return;
        }
    }
}

/// Prefaults an `iovec[count]` array (for reading) and each pointed-to buffer (for `need`).
pub(super) fn prefault_iov(cx: &mut Cx<'_>, iov: u64, count: usize, need: u32) {
    use appine_engine::prot;
    if count == 0 || iov == 0 || !cx.mm().has_fills() {
        return;
    }
    let n = count.min(1024);
    let bytes = n * 16;
    prefault_range(cx, iov, bytes as u64, prot::READ);
    let mut raw = vec![0u8; bytes];
    if cx
        .read_user(crate::uaccess::UserSlice::new(iov, bytes), &mut raw)
        .is_err()
    {
        return;
    }
    for c in raw.chunks_exact(16) {
        let base = u64::from_le_bytes(c[..8].try_into().unwrap());
        let len = u64::from_le_bytes(c[8..].try_into().unwrap());
        prefault_range(cx, base, len, need);
    }
}

/// Prefaults a `struct msghdr` (for reading) and its `msg_iov` buffers (for `need`).
fn prefault_msghdr(cx: &mut Cx<'_>, msg: u64, need: u32) {
    use appine_engine::prot;
    if msg == 0 || !cx.mm().has_fills() {
        return;
    }
    prefault_range(cx, msg, 56, prot::READ);
    let mut hdr = [0u8; 56];
    if cx
        .read_user(crate::uaccess::UserSlice::new(msg, 56), &mut hdr)
        .is_err()
    {
        return;
    }
    let iov = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
    let iovlen = u64::from_le_bytes(hdr[24..32].try_into().unwrap()) as usize;
    prefault_iov(cx, iov, iovlen, need);
}

/// Before a syscall (`nr`, arguments `a`): prefaults user buffers in on-demand FUSE mappings
/// ([`Fill`]) for syscalls that consume input or mutate state before copying results/buffers, as
/// Linux's `fault_in_iov_iter_readable`/`writeable` does, so a whole-syscall `FUSE_RETRY` cannot
/// repeat side effects or return unexpected short counts. Errors are left for the syscall to meet.
pub(super) fn prefault(cx: &mut Cx<'_>, nr: u64, a: &[u64; 6]) {
    use appine_engine::prot;
    if !cx.mm().has_fills() {
        return;
    }
    match nr {
        // epoll_pwait / epoll_pwait2: events array written after consuming EPOLLONESHOT/EPOLLET
        22 | 441 => {
            let max = (a[2] as i32).clamp(0, 65536) as u64;
            prefault_range(cx, a[1], max * 16, prot::WRITE);
        }
        // pipe2: pipefd[2]
        59 => prefault_range(cx, a[0], 8, prot::WRITE),
        // getdents64: advances directory pos before write_user_partial
        61 => prefault_range(cx, a[1], a[2].min(super::FUSE_CHUNK as u64), prot::WRITE),
        // read / pread64
        63 | 67 => prefault_range(cx, a[1], a[2], prot::WRITE),
        // write / pwrite64
        64 | 68 => prefault_range(cx, a[1], a[2], prot::READ),
        // readv / preadv / preadv2
        65 | 69 | 286 => prefault_iov(cx, a[1], a[2] as usize, prot::WRITE),
        // writev / pwritev / pwritev2
        66 | 70 | 287 => prefault_iov(cx, a[1], a[2] as usize, prot::READ),
        // sendfile: writes updated *offset after transferring data
        71 => prefault_range(cx, a[2], 8, prot::WRITE),
        // pselect6: writes fd_sets and remaining timeout after waiting
        72 => {
            let nfds = (a[0] as i32).clamp(0, 1024 * 1024) as u64;
            let bytes = nfds.div_ceil(8);
            for idx in [1, 2, 3] {
                prefault_range(cx, a[idx], bytes, prot::WRITE);
            }
            prefault_range(cx, a[4], 16, prot::WRITE);
        }
        // ppoll: writes pollfd revents and remaining timeout after waiting
        73 => {
            let nfds = (a[1] as usize).min(65536) as u64;
            prefault_range(cx, a[0], nfds * 8, prot::WRITE);
            prefault_range(cx, a[2], 16, prot::WRITE);
        }
        // vmsplice: transfers between pipe and iovec buffers
        75 => {
            let need = cx
                .fds()
                .get(a[0] as i32)
                .ok()
                .is_some_and(|f| f.borrow().writable());
            prefault_iov(
                cx,
                a[1],
                a[2] as usize,
                if need { prot::READ } else { prot::WRITE },
            );
        }
        // splice / copy_file_range: writes updated *off_in and *off_out after moving bytes
        76 | 285 => {
            prefault_range(cx, a[1], 8, prot::WRITE);
            prefault_range(cx, a[3], 8, prot::WRITE);
        }
        // socketpair: sv[2]
        199 => prefault_range(cx, a[3], 8, prot::WRITE),
        // sendto: payload buffer
        206 => prefault_range(cx, a[1], a[2], prot::READ),
        // getsockopt: SO_ERROR clears pending error before writing optval/optlen
        209 => {
            prefault_range(cx, a[4], 4, prot::WRITE);
            let mut b = [0u8; 4];
            if a[4] != 0
                && cx
                    .read_user(crate::uaccess::UserSlice::new(a[4], 4), &mut b)
                    .is_ok()
            {
                let len = u32::from_le_bytes(b).min(65536) as u64;
                prefault_range(cx, a[3], len, prot::WRITE);
            }
        }
        // sendmsg: msghdr and iovecs
        211 => prefault_msghdr(cx, a[1], prot::READ),
        // sendmmsg: writes msg_len after each message sent
        269 => {
            let vlen = (a[2] as usize).min(1024);
            prefault_range(cx, a[1], (vlen * 64) as u64, prot::WRITE);
            for i in 0..vlen {
                prefault_msghdr(cx, a[1].wrapping_add((i * 64) as u64), prot::READ);
            }
        }
        _ => {}
    }
}

// ---- Forgetting nodes ----

/// Forgets the FUSE nodes nothing uses when the cache asked for it ([`fuse::SWEEP`]: it grew too
/// large, or `drop_caches`), at the end of a syscall, when no syscall of this thread holds a node.
/// Other threads hold nodes through what [`in_use`] finds, O_PATH pins, open handles and
/// requests in flight ([`fuse::Fuses::evict`]).
pub(super) fn sweep(cx: &mut Cx<'_>) {
    if !cx.mm().unmapped_fills.is_empty() {
        let ranges = std::mem::take(&mut cx.mm_mut().unmapped_fills);
        let current = cx.task.sync.clone();
        cx.mm_mut().sync(&current);
        flush_ranges(cx, ranges);
    }
    use std::sync::atomic::Ordering::Relaxed;
    if !fuse::SWEEP.load(Relaxed) || !fuse::SWEEP.swap(false, Relaxed) {
        return;
    }
    let Ok(vfs) = cx.vfs() else {
        return;
    };
    let all = fuse::DROP.swap(false, Relaxed);
    match in_use(cx.kr(), &vfs) {
        Some(keep) => {
            vfs.fuse_mut().evict(&keep, all);
        }
        // Something is borrowed: another time
        None => {
            fuse::SWEEP.store(true, Relaxed);
            if all {
                fuse::DROP.store(true, Relaxed);
            }
        }
    }
}

/// FUSE nodes pinned by process roots, cwds, open files (including O_PATH), running programs,
/// mapped ELF interpreters, mount roots and points, or inotify watches. A busy borrow defers
/// the sweep.
fn in_use(k: &crate::kernel::Kernel, vfs: &Vfs) -> Option<HashSet<FuseId>> {
    let mut used = HashSet::new();
    let mut inodes = HashSet::new();
    let mut seen_mm = HashSet::new();
    let mut add = |n: Node| {
        if let Node::Fuse(_, id) = n {
            used.insert(id);
        }
    };
    for task in k.tasks.values() {
        let res = task.res.try_borrow().ok()?;
        {
            let fs = res.fs.try_borrow().ok()?;
            add(fs.root.clone());
            add(fs.cwd.clone());
        }
        if seen_mm.insert(Rc::as_ptr(&res.mm)) {
            let mm = res.mm.try_borrow().ok()?;
            inodes.extend(mm.exe);
            // ELF snapshots carry keys. Ordinary FUSE mmap inodes belong to the daemon
            // and are excluded by mapped_inos.
            mm.mapped_inos(&mut inodes);
        }
        let fds = res.fds.try_borrow().ok()?;
        for file in fds.files() {
            if let Some(n) = file.try_borrow().ok()?.node() {
                add(n);
            }
        }
    }
    for n in vfs.mount_nodes() {
        add(n);
    }
    used.extend(inodes.into_iter().filter_map(fuse::id_of));
    let inotify = k.inotify.try_borrow().ok()?;
    used.extend(inotify.watched().filter_map(fuse::id_of));
    Some(used)
}

/// Descriptors closed other than by close(2) (replaced by dup2, close_range, close-on-exec):
/// each FUSE file among `files` is flushed, its errors ignored, as `filp_close` does for them.
pub(super) fn flush_all(cx: &mut Cx<'_>, files: &[FileRef]) {
    for f in files {
        let _ = flush(cx, f);
    }
}

/// The thread is leaving the kernel for good: when it is the last user of its fd table, the FUSE
/// files in it are flushed before the table goes (6.1's `exit_files` closes each with
/// `filp_close`), so what a process wrote reaches the daemon's flush before its parent goes on.
/// A thread killed with requests not yet read gives them up at once ([`fuse::call`]).
pub(crate) fn flush_at_exit(cx: &mut Cx<'_>) {
    if Rc::strong_count(&cx.t.fds) > 2 {
        return;
    }
    let files: Vec<FileRef> = {
        let t = cx.fds();
        t.files()
            .filter(|f| matches!(f.borrow().kind, FileKind::Fuse(_)))
            .cloned()
            .collect()
    };
    flush_all(cx, &files);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::fd::{FdTable, OpenFile};
    use crate::kernel::{Kernel, Shared, Tid};
    use crate::mm::Mm;
    use crate::process::{ThreadGroup, Tier};
    use crate::signal::SigHandlers;
    use crate::task::{FsContext, Task, TaskState};
    use crate::vfs::fuse::{Attr, DevFile, Fuses, Options};
    use crate::vfs::store::{ROOT, Store};
    use crate::vfs::{INIT_MNT_NS, MntNs};

    /// Thread-safe handle shared across scoped worker and daemon threads.
    struct Harness {
        shared: Arc<Shared>,
        mnt: MountId,
        root: FuseId,
        dev_fd: i32,
        daemon_tid: Tid,
    }

    struct TestRig {
        h: Harness,
        dir: PathBuf,
        _cpus: Vec<appine_engine::Cpu>,
    }

    impl Drop for TestRig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn attr_bytes(ino: u64, mode: u32, size: u64, nlink: u32) -> Vec<u8> {
        attr_bytes_mtime(ino, mode, size, nlink, 0)
    }

    fn attr_bytes_mtime(ino: u64, mode: u32, size: u64, nlink: u32, mtime: u64) -> Vec<u8> {
        let mut a = Args::default()
            .u64(ino)
            .u64(size)
            .u64(0)
            .u64(0)
            .u64(mtime)
            .u64(mtime);
        for _ in 0..3 {
            a = a.u32(0);
        }
        a.u32(mode)
            .u32(nlink)
            .u32(0)
            .u32(0)
            .u32(0)
            .u32(4096)
            .u32(0)
            .0
    }

    fn entry_out(nodeid: u64, mode: u32, size: u64, nlink: u32, valid_secs: u64) -> Vec<u8> {
        Args::default()
            .u64(nodeid)
            .u64(0)
            .u64(valid_secs)
            .u64(valid_secs)
            .u32(0)
            .u32(0)
            .bytes(&attr_bytes(nodeid, mode, size, nlink))
            .0
    }

    fn attr_out_bytes(ino: u64, mode: u32, size: u64, nlink: u32, valid_secs: u64) -> Vec<u8> {
        attr_out_mtime(ino, mode, size, nlink, 0, valid_secs)
    }

    fn attr_out_mtime(
        ino: u64,
        mode: u32,
        size: u64,
        nlink: u32,
        mtime: u64,
        valid_secs: u64,
    ) -> Vec<u8> {
        Args::default()
            .u64(valid_secs)
            .u32(0)
            .u32(0)
            .bytes(&attr_bytes_mtime(ino, mode, size, nlink, mtime))
            .0
    }

    fn fuse_reply(unique: u64, error: i32, body: &[u8]) -> Vec<u8> {
        Args::default()
            .u32((16 + body.len()) as u32)
            .u32((-error) as u32)
            .u64(unique)
            .bytes(body)
            .0
    }

    fn parse_header(msg: &[u8]) -> (u32, u64, u64) {
        (
            u32::from_le_bytes(msg[4..8].try_into().unwrap()),
            u64::from_le_bytes(msg[8..16].try_into().unwrap()),
            u64::from_le_bytes(msg[16..24].try_into().unwrap()),
        )
    }

    fn task_state(
        mm: Rc<RefCell<Mm>>,
        fds: Rc<RefCell<FdTable>>,
        fs: Rc<RefCell<FsContext>>,
        group: Rc<RefCell<ThreadGroup>>,
        vfs: Option<Rc<Vfs>>,
    ) -> TaskState {
        TaskState {
            mm,
            fds,
            fs,
            group,
            vfs,
            altstack: Default::default(),
            clear_child_tid: 0,
            vfork_done: None,
            restart: None,
            fast_sleep: None,
            sem_undo: Rc::new(crate::ipc::SemUndo::new()),
        }
    }

    fn add_task(k: &mut Kernel, tid: Tid, user_ns: &Rc<crate::cred::UserNs>) -> appine_engine::Cpu {
        let group = Rc::new(RefCell::new(ThreadGroup::new(
            tid,
            1,
            Rc::new(RefCell::new(SigHandlers::default())),
        )));
        let mm = Mm::new().into_shared();
        let fds = Rc::new(RefCell::new(FdTable::new()));
        let fs = Rc::new(RefCell::new(FsContext {
            root: Node::ROOT,
            cwd: Node::ROOT,
            umask: 0o022,
            mnt_ns: Rc::new(MntNs {
                id: INIT_MNT_NS,
                owner: user_ns.clone(),
                anon: false,
            }),
        }));
        let cpu = unsafe { appine_engine::Cpu::new(mm.borrow().mmu()) };
        let state = task_state(mm, fds, fs, group.clone(), k.vfs.clone());
        let task = Task::new(tid, tid, &cpu, state, k.init_ns.clone(), 0, [0; 16]).unwrap();
        task.cred.borrow_mut().user_ns = user_ns.clone();
        group.borrow_mut().threads.push(tid);
        k.groups.insert(tid, group);
        k.tasks.insert(tid, task);
        cpu
    }

    impl Harness {
        fn cx<R>(&self, tid: Tid, f: impl FnOnce(&mut Cx<'_>) -> R) -> R {
            let mut held: Option<(Rc<Task>, TaskState)> = None;
            let out = {
                let k = self.shared.lock();
                let task = k.tasks[&tid].clone();
                let r = task.res.borrow();
                let t = task_state(
                    r.mm.clone(),
                    r.fds.clone(),
                    r.fs.clone(),
                    k.groups[&tid].clone(),
                    k.vfs.clone(),
                );
                drop(r);
                let (task, t) = held.insert((task, t));
                f(&mut Cx::new(&self.shared, k, task, t))
            };
            let _k = self.shared.lock();
            drop(held);
            out
        }

        /// Reads the next daemon request, silently skipping forgets and acking releases.
        fn read_req(&self, nonblock: bool) -> Result<(u32, u64, u64, Vec<u8>), Errno> {
            loop {
                let msg = self.cx(self.daemon_tid, |cx| {
                    let file = cx.fds().get(self.dev_fd).unwrap();
                    fuse::dev_read(cx, &file, 131072, nonblock)
                })?;
                let (opcode, unique, nodeid) = parse_header(&msg);
                if matches!(opcode, op::FORGET | op::BATCH_FORGET) {
                    continue;
                }
                if matches!(opcode, op::RELEASE | op::RELEASEDIR) {
                    self.reply_ok(unique, &[]);
                    continue;
                }
                return Ok((opcode, unique, nodeid, msg));
            }
        }

        fn reply(&self, unique: u64, error: i32, body: &[u8]) {
            let raw = fuse_reply(unique, error, body);
            self.cx(self.daemon_tid, |cx| {
                let file = cx.fds().get(self.dev_fd).unwrap();
                let vfs = cx.vfs().unwrap();
                fuse::dev_write(cx, &vfs, &file, &raw).unwrap();
            });
        }

        fn reply_ok(&self, unique: u64, body: &[u8]) {
            self.reply(unique, 0, body);
        }

        fn seed_dir(
            &self,
            parent: FuseId,
            name: &[u8],
            nodeid: u64,
            size: u64,
            valid: u64,
        ) -> FuseId {
            self.seed(parent, name, nodeid, mode::S_IFDIR | 0o755, size, 2, valid)
        }

        fn seed_file(
            &self,
            parent: FuseId,
            name: &[u8],
            nodeid: u64,
            size: u64,
            valid: u64,
        ) -> FuseId {
            self.seed(parent, name, nodeid, mode::S_IFREG | 0o644, size, 1, valid)
        }

        #[allow(clippy::too_many_arguments)]
        fn seed(
            &self,
            parent: FuseId,
            name: &[u8],
            nodeid: u64,
            mode: u32,
            size: u64,
            nlink: u32,
            valid_secs: u64,
        ) -> FuseId {
            let k = self.shared.lock();
            let vfs = k.vfs.as_ref().unwrap();
            let until = (valid_secs > 0).then(|| Instant::now() + Duration::from_secs(valid_secs));
            let e = Entry {
                nodeid,
                attr: Attr {
                    ino: nodeid,
                    size,
                    mode,
                    nlink,
                    blksize: 4096,
                    ..Attr::default()
                },
                entry_until: until,
                attr_until: until,
            };
            vfs.fuse_mut().enter(parent, name, &e).unwrap()
        }

        fn seed_negatives(&self, dir: FuseId, names: &[&[u8]]) {
            let k = self.shared.lock();
            let until = Some(Instant::now() + Duration::from_secs(3600));
            let mut f = k.vfs.as_ref().unwrap().fuse_mut();
            for name in names {
                f.enter_negative(dir, name, until);
            }
        }

        fn wait_until(&self, msg: &str, mut cond: impl FnMut(&Fuses) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if cond(&self.shared.lock().vfs.as_ref().unwrap().fuse()) {
                    return;
                }
                assert!(Instant::now() < deadline, "{msg}");
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn evict_all(&self) -> usize {
            self.shared
                .lock()
                .vfs
                .as_ref()
                .unwrap()
                .fuse_mut()
                .evict(&HashSet::new(), true)
        }

        fn assert_unlocked(&self, dirs: &[FuseId]) {
            let k = self.shared.lock();
            let f = k.vfs.as_ref().unwrap().fuse();
            for &d in dirs {
                assert!(!f.node(d).dir_busy && f.node(d).dir_waiters == 0);
            }
        }

        fn make_handle(
            &self,
            id: FuseId,
            nodeid: u64,
            fh: u64,
            dir: bool,
            no_release: bool,
            open_flags: u32,
        ) -> Handle {
            let conn = self
                .shared
                .lock()
                .vfs
                .as_ref()
                .unwrap()
                .fuse()
                .conn_of(id)
                .unwrap();
            Handle {
                conn,
                id,
                nodeid,
                fh,
                open_flags,
                flags: oflags::O_RDONLY,
                dir,
                no_release,
            }
        }

        fn install_fd(&self, tid: Tid, file: FileRef) -> i32 {
            self.shared.lock().tasks[&tid]
                .res
                .borrow()
                .fds
                .borrow_mut()
                .install(file, false, 0..64)
                .unwrap()
        }
    }

    fn new_rig(name: &str, worker_tids: &[Tid]) -> TestRig {
        new_rig_with_init_flags(name, worker_tids, 0)
    }

    fn new_rig_with_init_flags(name: &str, worker_tids: &[Tid], init_flags: u32) -> TestRig {
        let dir = std::env::temp_dir().join(format!(
            "appine-fuse-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Store::create(&dir)
            .unwrap()
            .mkdir(ROOT, b"mnt", 0o755, 0, 0)
            .unwrap();
        let shared = Arc::new(Shared::new(Kernel::new(Tier::Interpreter)));
        let daemon_tid = 100;
        let (mnt, root, dev_fd, cpus) = {
            let mut k = shared.lock();
            let vfs = Rc::new(Vfs::open(&dir).unwrap());
            k.vfs = Some(vfs.clone());
            let user_ns = crate::cred::UserNs::init();
            let mut cpus = vec![add_task(&mut k, daemon_tid, &user_ns)];
            cpus.extend(worker_tids.iter().map(|&t| add_task(&mut k, t, &user_ns)));
            let dev = 0x99u64;
            let opts = Options {
                rootmode: Some(mode::S_IFDIR | 0o755),
                user_id: Some(0),
                group_id: Some(0),
                allow_other: true,
                max_read: u32::MAX,
                ..Options::default()
            };
            let cred = k.tasks[&daemon_tid].cred.borrow().clone();
            let conn = Rc::new(RefCell::new(Conn::new(
                dev,
                opts,
                &cred,
                crate::pidns::PidNs::init(),
            )));
            let root = vfs.fuse_mut().add(conn.clone());
            let mut devfile = DevFile::new(&cred, 1);
            devfile.attach(&conn);
            fuse::send_init(&conn);
            let mnt_ino = vfs.store().lookup(ROOT, b"mnt").unwrap().unwrap();
            let mnt = vfs
                .add_fuse_mount(
                    (Node::Store(crate::vfs::ROOT_MOUNT, mnt_ino), None),
                    0,
                    b"testfuse".to_vec(),
                    dev,
                )
                .unwrap();
            let dev_fd = k.tasks[&daemon_tid]
                .res
                .borrow()
                .fds
                .borrow_mut()
                .install(
                    OpenFile::new(FileKind::FuseDev(devfile), oflags::O_RDWR),
                    false,
                    0..64,
                )
                .unwrap();
            (mnt, root, dev_fd, cpus)
        };
        let h = Harness {
            shared,
            mnt,
            root,
            dev_fd,
            daemon_tid,
        };
        // Complete FUSE_INIT handshake.
        let (opcode, unique, _, _) = h.read_req(true).unwrap();
        assert_eq!(opcode, op::INIT);
        let init_body = Args::default()
            .u32(7)
            .u32(37)
            .u32(0)
            .u32(init_flags)
            .u32(0)
            .u32(65536)
            .u32(1)
            .u32(0)
            .0;
        h.reply_ok(unique, &init_body);
        TestRig {
            h,
            dir,
            _cpus: cpus,
        }
    }

    fn run_with_retries<R>(
        cx: &mut Cx<'_>,
        mut f: impl FnMut(&mut Cx<'_>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        fuse::new_syscall();
        for _ in 0..32 {
            match f(cx) {
                Err(Errno::FUSE_RETRY) => fuse::serve(cx, |_, _| {})?,
                r => return r,
            }
        }
        Err(Errno::EIO)
    }

    #[test]
    fn maps_and_smaps_show_fuse_image_inodes_and_keep_the_internal_keys() {
        use crate::loader::Image;
        use crate::mm::flags::MAP_PRIVATE;
        use crate::pseudo::{self, ProcId, PseudoNode};
        use std::os::fd::AsRawFd;

        let rig = new_rig("image-maps", &[10]);
        let h = &rig.h;
        let (ino, host) = h.cx(10, |cx| {
            let vfs = cx.vfs().unwrap();
            let store = vfs.store();
            let pair = store.create_file(ROOT, b"unlinked", 0o700, 0, 0).unwrap();
            store.unlink(ROOT, b"unlinked").unwrap();
            assert_eq!(store.attrs(pair.0).unwrap().nlink, 0);
            pair
        });
        host.set_len(PAGE_SIZE).unwrap();
        let prog = h.seed_file(h.root, b"prog", ino, PAGE_SIZE, 3600);
        let interp = h.seed_file(h.root, b"ld", ino + 1, PAGE_SIZE, 3600);
        // A daemon can also choose an ordinary mmap inode numerically equal to the program key.
        let raw_ino = fuse::key(prog);
        let regular = h.seed_file(h.root, b"mapped", raw_ino, PAGE_SIZE, 3600);
        let handle = h.make_handle(regular, raw_ino, 0, false, true, 0);
        h.cx(10, |cx| {
            let vfs = cx.vfs().unwrap();
            let cred = cx.cred();
            let map_segment = || {
                cx.mm_mut()
                    .mmap(
                        0,
                        PAGE_SIZE,
                        5,
                        MAP_PRIVATE,
                        Some((host.as_raw_fd(), 0, false)),
                    )
                    .unwrap()
            };
            let main = map_segment();
            let ld = map_segment();
            let image = Image {
                main: (main, main + PAGE_SIZE),
                interp: Some((b"/mnt/ld".to_vec(), ld, ld + PAGE_SIZE)),
                entry: main,
                sp: 0,
                doomed: false,
            };
            let label = super::super::proc::interp_label(
                Some(&vfs),
                &cx.view(&vfs),
                &cred,
                &Node::ROOT,
                &Node::ROOT,
                &image,
            );
            let path = Rc::from(b"/mnt/prog".as_slice());
            super::super::proc::label_image(
                &mut cx.mm_mut(),
                &image,
                (&path, fuse::key(prog), Some(h.mnt)),
                label,
            );
            cx.mm_mut().exe = Some(fuse::key(prog));

            let mapped_path: Rc<[u8]> = Rc::from(b"/mnt/mapped".as_slice());
            let file = OpenFile::with_path(
                FileKind::Fuse(Box::new(handle)),
                oflags::O_RDONLY,
                Some(mapped_path.clone()),
            );
            let fill = map_fill(cx, &file, false, false).unwrap().unwrap();
            let addr = cx
                .mm_mut()
                .mmap_fill(0, PAGE_SIZE, 1, MAP_PRIVATE, (fill, 0))
                .unwrap();
            cx.mm_mut()
                .label(addr, PAGE_SIZE, Some(mapped_path), raw_ino);

            let pid = ProcId {
                pid: 10,
                serial: cx.t.group.borrow().serial,
            };
            for entry in [pseudo::Entry::Maps, pseudo::Entry::Smaps] {
                let content = pseudo::content(
                    &cx.view(&vfs),
                    crate::vfs::ROOT_MOUNT,
                    &PseudoNode::Entry(pid, None, entry),
                )
                .unwrap();
                let text = String::from_utf8(content).unwrap();
                for (addr, name, expected) in [
                    (main, "/mnt/prog", ino),
                    (ld, "/mnt/ld", ino + 1),
                    (addr, "/mnt/mapped", raw_ino),
                ] {
                    let prefix = format!("{addr:08x}-");
                    let fields: Vec<_> = text
                        .lines()
                        .find(|l| l.starts_with(&prefix))
                        .unwrap()
                        .split_whitespace()
                        .skip(3)
                        .collect();
                    assert_eq!(fields, ["08:01", &expected.to_string(), name]);
                }
            }
            assert!(cx.mm().maps_ino(fuse::key(prog)));
            assert!(cx.mm().maps_ino(fuse::key(interp)));
            assert!(!cx.mm().maps_ino(ino));
            assert!(super::super::fs::executing(cx, fuse::key(prog)));
            assert!(matches!(
                open(cx, &cred, &vfs, (h.mnt, prog), oflags::O_WRONLY),
                Err(Errno::ETXTBSY)
            ));
            let used = in_use(cx.kr(), &vfs).unwrap();
            assert!(used.contains(&prog) && used.contains(&interp));
            cx.mm_mut().munmap(ld, PAGE_SIZE).unwrap();
            cx.mm_mut().munmap(main, PAGE_SIZE).unwrap();
            let used = in_use(cx.kr(), &vfs).unwrap();
            vfs.fuse_mut().evict(&used, true);
            assert!(vfs.fuse().get(prog).is_some());
            assert!(vfs.fuse().get(interp).is_none());
        });
    }

    fn test_pipe(cx: &mut Cx<'_>, addr: u64) -> (i32, i32) {
        super::super::fs::pipe2(cx, addr, oflags::O_NONBLOCK).unwrap();
        let mut fds = [0; 8];
        cx.read_user(crate::uaccess::UserSlice::new(addr, 8), &mut fds)
            .unwrap();
        (
            i32::from_le_bytes(fds[..4].try_into().unwrap()),
            i32::from_le_bytes(fds[4..].try_into().unwrap()),
        )
    }

    fn vmsplice_bytes(cx: &mut Cx<'_>, fd: i32, iov: u64, addr: u64, data: &[u8]) {
        use crate::uaccess::UserSlice;
        cx.write_user(UserSlice::new(addr, data.len()), data)
            .unwrap();
        let vec = Args::default().u64(addr).u64(data.len() as u64).0;
        cx.write_user(UserSlice::new(iov, vec.len()), &vec).unwrap();
        assert_eq!(
            super::super::fs::vmsplice(cx, fd, iov, 1, 0),
            Ok(data.len() as u64)
        );
    }

    #[test]
    fn vmsplice_reads_follow_partial_transfers_and_fall_back_after_unmap() {
        use super::super::fs;
        use crate::uaccess::UserSlice;

        let rig = new_rig("vmsplice-transfer", &[]);
        rig.h.cx(rig.h.daemon_tid, |cx| {
            let base = 0x10000;
            cx.mm_mut().map_anonymous(base, 3 * PAGE_SIZE, 3).unwrap();
            let (src, write) = test_pipe(cx, base);
            let (copy, copy_write) = test_pipe(cx, base);
            let (moved, move_write) = test_pipe(cx, base);
            let addr = base + 2 * PAGE_SIZE - 2;
            vmsplice_bytes(cx, write, base, addr, b"abcdef");
            cx.write_user(UserSlice::new(addr, 6), b"ABCDEF").unwrap();
            assert_eq!(fs::read(cx, src, base, 1), Ok(1));
            let mut byte = [0];
            cx.read_user(UserSlice::new(base, 1), &mut byte).unwrap();
            assert_eq!(&byte, b"A");
            assert_eq!(fs::tee(cx, src, copy_write, 4, 0), Ok(4));
            assert_eq!(fs::splice(cx, src, 0, move_write, 0, 3, 0), Ok(3));
            cx.write_user(UserSlice::new(addr + 1, 5), b"12345")
                .unwrap();
            let read = |cx: &mut Cx<'_>, fd, expected: &[u8]| {
                let mut buf = vec![0; expected.len()];
                let file = cx.fds().get(fd).unwrap();
                assert_eq!(
                    fs::read_bytes(cx, &file, &mut buf, None),
                    Ok(expected.len())
                );
                assert_eq!(buf, expected);
            };
            read(cx, copy, b"1");
            read(cx, moved, b"1");
            read(cx, src, b"4");
            cx.mm_mut().munmap(base + 2 * PAGE_SIZE, PAGE_SIZE).unwrap();
            read(cx, copy, b"CDE");
            cx.mm_mut()
                .map_anonymous(base + 2 * PAGE_SIZE, PAGE_SIZE, 3)
                .unwrap();
            cx.write_user(UserSlice::new(addr + 2, 4), b"WXYZ").unwrap();
            read(cx, moved, b"CD");
            read(cx, src, b"f");
        });
    }

    #[test]
    fn spliced_fuse_reply_uses_live_header_and_rejects_wrong_lengths() {
        use super::super::fs;
        use crate::uaccess::UserSlice;

        let rig = new_rig("splice-reply", &[10]);
        let h = &rig.h;
        let base = 0x10000;
        let (read, write) = h.cx(h.daemon_tid, |cx| {
            cx.mm_mut().map_anonymous(base, PAGE_SIZE, 3).unwrap();
            test_pipe(cx, base)
        });
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                h.cx(10, |cx| {
                    let conn = cx.vfs()?.fuse().conn_of(h.root)?;
                    fuse::call(cx, &conn, op::READ, 1, &[])
                })
            });
            let (_, unique, _, _) = h.read_req(false).unwrap();
            let payload = b"spliced data";
            let len = 16 + payload.len();
            let result = h.cx(h.daemon_tid, |cx| {
                let header = base + 32;
                let mut bytes = fuse_reply(unique, 0, &[]);
                bytes[..4].fill(0);
                vmsplice_bytes(cx, write, base, header, &bytes);
                let body = base + 64;
                cx.write_user(UserSlice::new(body, payload.len()), payload)
                    .unwrap();
                assert_eq!(
                    fs::write(cx, write, body, payload.len()),
                    Ok(payload.len() as u64)
                );
                cx.write_user(UserSlice::new(header, 4), &(len as u32).to_le_bytes())
                    .unwrap();
                fs::splice(cx, read, 0, h.dev_fd, 0, len + 1, 0)
            });
            if result.is_err() {
                h.reply(unique, Errno::EIO.0, &[]);
            }
            assert_eq!(result, Ok(len as u64));
            assert_eq!(worker.join().unwrap().unwrap(), payload);
        });
        h.cx(h.daemon_tid, |cx| {
            let conn = cx.vfs().unwrap().fuse().conn_of(h.root).unwrap();
            fuse::background(&conn, op::READ, 1, &[]);
        });
        let (_, unique, _, _) = h.read_req(true).unwrap();
        h.cx(h.daemon_tid, |cx| {
            let reply = fuse_reply(unique, 0, b"12345678");
            cx.write_user(UserSlice::new(base, reply.len()), &reply)
                .unwrap();
            fs::write(cx, write, base, reply.len()).unwrap();
            assert_eq!(
                fs::splice(cx, read, 0, h.dev_fd, 0, 16, 0),
                Err(Errno::EINVAL)
            );
            let mut remaining = [0; 24];
            let file = cx.fds().get(read).unwrap();
            assert_eq!(fs::read_bytes(cx, &file, &mut remaining, None), Ok(24));
            assert_eq!(remaining.as_slice(), reply);
            let dev = cx.fds().get(h.dev_fd).unwrap();
            let vfs = cx.vfs().unwrap();
            assert_eq!(fuse::dev_write(cx, &vfs, &dev, &remaining), Ok(24));
        });
    }

    #[test]
    fn same_directory_mutations_are_serialized_and_other_dirs_stay_parallel() {
        let _sweep_guard = fuse::tests::SWEEP_TEST
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rig = new_rig("dir-serial", &[10, 11, 12, 13, 14, 15, 16, 17, 18]);
        let h = &rig.h;
        let dir1 = h.seed_dir(h.root, b"d1", 2, 4096, 3600);
        let dir2 = h.seed_dir(h.root, b"d2", 3, 4096, 3600);
        h.seed_file(dir1, b"c", 4, 0, 3600);
        h.seed_file(dir1, b"d", 5, 0, 3600);
        h.seed_dir(dir1, b"rmsub", 6, 4096, 3600);
        let link_src = h.seed_file(dir2, b"lsrc", 7, 0, 3600);
        h.seed_negatives(dir1, &[b"a", b"b", b"e", b"mk", b"sl", b"hl"]);
        h.seed_negatives(dir2, &[b"p"]);

        let observed_parallel = AtomicBool::new(false);
        std::thread::scope(|s| {
            // 8 concurrent mutations in dir1 + 1 in dir2 to prove per-directory serialization.
            let mnt = h.mnt;
            let threads = [
                s.spawn(move || h.cx(10, |cx| mkdir(cx, (mnt, dir1), b"a", 0o755))),
                s.spawn(move || {
                    h.cx(11, |cx| {
                        let (vfs, cred) = (cx.vfs()?, cx.cred());
                        let fl = oflags::O_CREAT | oflags::O_RDWR;
                        create(cx, &cred, &vfs, (mnt, dir1), b"b", 0o644, fl).map(|_| ())
                    })
                }),
                s.spawn(move || h.cx(12, |cx| unlink(cx, (mnt, dir1), b"c", false, false))),
                s.spawn(move || {
                    h.cx(13, |cx| {
                        rename_at(cx, (mnt, dir1, b"d"), (mnt, dir1, b"e"), 0)
                    })
                }),
                s.spawn(move || {
                    h.cx(15, |cx| {
                        mknod(cx, (mnt, dir1), b"mk", mode::S_IFREG | 0o644, 0)
                    })
                }),
                s.spawn(move || h.cx(16, |cx| symlink(cx, (mnt, dir1), b"sl", b"target"))),
                s.spawn(move || {
                    h.cx(17, |cx| {
                        link(cx, &Node::Fuse(mnt, link_src), (mnt, dir1), b"hl")
                    })
                }),
                s.spawn(move || h.cx(18, |cx| unlink(cx, (mnt, dir1), b"rmsub", true, false))),
                s.spawn(move || h.cx(14, |cx| mkdir(cx, (mnt, dir2), b"p", 0o755))),
            ];

            let (mut next_node, mut done_dir1, mut done_dir2) = (100u64, 0usize, 0usize);
            let mut pending1: Option<(u32, u64)> = None;
            let mut pending2: Option<(u32, u64)> = None;
            let mut reply_op = |opcode: u32, unique: u64| {
                let nid = next_node;
                let body = match opcode {
                    op::MKDIR => {
                        next_node += 1;
                        entry_out(nid, mode::S_IFDIR | 0o755, 4096, 2, 60)
                    }
                    op::CREATE => {
                        next_node += 1;
                        let mut b = entry_out(nid, mode::S_IFREG | 0o644, 0, 1, 60);
                        b.extend_from_slice(&Args::default().u64(77).u32(0).u32(0).0);
                        b
                    }
                    op::MKNOD => {
                        next_node += 1;
                        entry_out(nid, mode::S_IFREG | 0o644, 0, 1, 60)
                    }
                    op::SYMLINK => {
                        next_node += 1;
                        entry_out(nid, mode::S_IFLNK | 0o777, 6, 1, 60)
                    }
                    op::LINK => entry_out(7, mode::S_IFREG | 0o644, 0, 2, 60),
                    op::UNLINK | op::RMDIR | op::RENAME => Vec::new(),
                    other => panic!("unexpected opcode {other}"),
                };
                h.reply_ok(unique, &body);
            };
            let record =
                |opcode, unique, nodeid, p1: &mut Option<_>, p2: &mut Option<_>| match nodeid {
                    2 => {
                        assert!(
                            p1.is_none(),
                            "concurrent mutations reached daemon for dir1! op={opcode}"
                        );
                        *p1 = Some((opcode, unique));
                    }
                    3 => {
                        assert!(p2.is_none());
                        if p1.is_some() {
                            observed_parallel.store(true, Ordering::Relaxed);
                        }
                        *p2 = Some((opcode, unique));
                    }
                    _ => panic!("unexpected nodeid {nodeid} for op {opcode}"),
                };

            while done_dir1 < 8 || done_dir2 < 1 {
                if pending1.is_none() && pending2.is_none() {
                    let (op, u, nid, _) = h.read_req(false).unwrap();
                    record(op, u, nid, &mut pending1, &mut pending2);
                    continue;
                }
                let deadline = Instant::now() + Duration::from_millis(15);
                while Instant::now() < deadline {
                    match h.read_req(true) {
                        Ok((op, u, nid, _)) => record(op, u, nid, &mut pending1, &mut pending2),
                        Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(2)),
                        Err(e) => panic!("dev_read failed: {e:?}"),
                    }
                }
                if let Some((op, u)) = pending1.take() {
                    reply_op(op, u);
                    done_dir1 += 1;
                }
                if let Some((op, u)) = pending2.take() {
                    reply_op(op, u);
                    done_dir2 += 1;
                }
            }
            for t in threads {
                t.join().unwrap().unwrap();
            }
        });

        assert!(
            observed_parallel.load(Ordering::Relaxed),
            "mutation on dir2 should proceed in parallel with dir1"
        );
        h.assert_unlocked(&[dir1, dir2]);
    }

    #[test]
    fn cross_directory_renames_serialize_without_deadlock_and_prevent_cycles() {
        let rig = new_rig("cross-rename", &[20, 21, 22, 23]);
        let h = &rig.h;
        let dir_a = h.seed_dir(h.root, b"da", 2, 4096, 3600);
        let dir_b = h.seed_dir(h.root, b"db", 3, 4096, 3600);
        assert!(dir_a < dir_b);
        h.seed_file(dir_a, b"fa", 4, 0, 3600);
        h.seed_file(dir_b, b"fb", 5, 0, 3600);
        h.seed_negatives(dir_b, &[b"fa_dst"]);
        h.seed_negatives(dir_a, &[b"fb_dst"]);

        let mnt = h.mnt;

        // 1. Opposing cross-directory renames serialize without deadlock and survive eviction.
        std::thread::scope(|s| {
            let t1 = s.spawn(move || {
                h.cx(20, |cx| {
                    rename_at(cx, (mnt, dir_a, b"fa"), (mnt, dir_b, b"fa_dst"), 0)
                })
            });
            let t2 = s.spawn(move || {
                h.cx(21, |cx| {
                    rename_at(cx, (mnt, dir_b, b"fb"), (mnt, dir_a, b"fb_dst"), 0)
                })
            });
            for round in 0..2 {
                let (opcode, unique, _, _) = h.read_req(false).unwrap();
                assert_eq!(opcode, op::RENAME);
                if round == 0 {
                    h.wait_until("opposing rename did not park", |f| {
                        f.node(dir_a).dir_waiters == 1 && f.node(dir_b).dir_waiters == 1
                    });
                    h.evict_all();
                    let k = h.shared.lock();
                    let f = k.vfs.as_ref().unwrap().fuse();
                    assert!(f.get(dir_a).is_some() && f.get(dir_b).is_some());
                } else {
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert_eq!(
                    h.read_req(true).err(),
                    Some(Errno::EAGAIN),
                    "opposing cross-dir renames must not overlap at daemon"
                );
                h.reply_ok(unique, &[]);
            }
            t1.join().unwrap().unwrap();
            t2.join().unwrap().unwrap();
        });

        // 2. Concurrent opposing directory moves: one succeeds, the other sees EINVAL under
        //    rename_busy without sending a second FUSE_RENAME, and parked waiters pin all dirs.
        let sub_a = h.seed_dir(dir_a, b"sub_a", 6, 4096, 3600);
        let sub_b = h.seed_dir(dir_b, b"sub_b", 7, 4096, 3600);
        h.seed_negatives(sub_b, &[b"sub_a"]);
        h.seed_negatives(sub_a, &[b"sub_b"]);

        let renames_seen = AtomicUsize::new(0);
        let (r1, r2) = std::thread::scope(|s| {
            let t1 = s.spawn(move || {
                h.cx(22, |cx| {
                    rename_at(cx, (mnt, dir_a, b"sub_a"), (mnt, sub_b, b"sub_a"), 0)
                })
            });
            let t2 = s.spawn(move || {
                h.cx(23, |cx| {
                    rename_at(cx, (mnt, dir_b, b"sub_b"), (mnt, sub_a, b"sub_b"), 0)
                })
            });
            let (opcode, unique, _, _) = h.read_req(false).unwrap();
            assert_eq!(opcode, op::RENAME);
            renames_seen.fetch_add(1, Ordering::Relaxed);
            h.wait_until(
                "opposing dir-move rename did not park on rename_busy",
                |f| {
                    (f.node(dir_a).dir_waiters == 1 && f.node(sub_b).dir_waiters == 1)
                        || (f.node(dir_b).dir_waiters == 1 && f.node(sub_a).dir_waiters == 1)
                },
            );
            h.evict_all();
            {
                let k = h.shared.lock();
                let f = k.vfs.as_ref().unwrap().fuse();
                for d in [dir_a, dir_b, sub_a, sub_b] {
                    assert!(
                        f.get(d).is_some(),
                        "directory {d} evicted while rename waiter parked"
                    );
                }
            }
            assert_eq!(h.read_req(true).err(), Some(Errno::EAGAIN));
            h.reply_ok(unique, &[]);
            (t1.join().unwrap(), t2.join().unwrap())
        });

        assert_eq!(renames_seen.load(Ordering::Relaxed), 1);
        assert!(
            matches!(
                (r1, r2),
                (Ok(()), Err(Errno::EINVAL)) | (Err(Errno::EINVAL), Ok(()))
            ),
            "expected one success and one EINVAL, got ({r1:?}, {r2:?})"
        );
        assert!(
            !h.shared
                .lock()
                .vfs
                .as_ref()
                .unwrap()
                .fuse()
                .conn_of(dir_a)
                .unwrap()
                .borrow()
                .rename_busy
        );
        h.assert_unlocked(&[dir_a, dir_b, sub_a, sub_b]);
    }

    #[test]
    fn directory_lock_releases_on_error_kill_abort_and_prevents_eviction() {
        let rig = new_rig("dir-cleanup", &[30, 31, 32]);
        let h = &rig.h;
        let dir = h.seed_dir(h.root, b"d", 2, 4096, 3600);
        h.seed_negatives(dir, &[b"err", b"ok", b"killed", b"ab1", b"ab2"]);
        let mnt = h.mnt;

        // 1. Daemon error releases the lock, killed waiter returns EINTR, eviction pins dir.
        std::thread::scope(|s| {
            let t1 = s.spawn(move || h.cx(30, |cx| mkdir(cx, (mnt, dir), b"err", 0o755)));
            let (op1, u1, _, _) = h.read_req(false).unwrap();
            assert_eq!(op1, op::MKDIR);

            let t2 = s.spawn(move || h.cx(31, |cx| mkdir(cx, (mnt, dir), b"ok", 0o755)));
            let t3 = s.spawn(move || h.cx(32, |cx| mkdir(cx, (mnt, dir), b"killed", 0o755)));
            h.wait_until("waiters did not park on dir", |f| {
                f.node(dir).dir_waiters == 2
            });

            assert_eq!(h.evict_all(), 0);
            assert!(
                h.shared
                    .lock()
                    .vfs
                    .as_ref()
                    .unwrap()
                    .fuse()
                    .get(dir)
                    .is_some()
            );

            {
                let k = h.shared.lock();
                let task3 = &k.tasks[&32];
                task3.killed.set(true);
                task3.event.signal();
            }
            assert_eq!(t3.join().unwrap(), Err(Errno::EINTR));
            assert_eq!(
                h.shared
                    .lock()
                    .vfs
                    .as_ref()
                    .unwrap()
                    .fuse()
                    .node(dir)
                    .dir_waiters,
                1
            );

            h.reply(u1, Errno::EACCES.0, &[]);
            assert_eq!(t1.join().unwrap(), Err(Errno::EACCES));

            let (op2, u2, _, _) = h.read_req(false).unwrap();
            assert_eq!(op2, op::MKDIR);
            h.reply_ok(u2, &entry_out(10, mode::S_IFDIR | 0o755, 4096, 2, 60));
            t2.join().unwrap().unwrap();
        });

        // 2. Connection abort wakes holder (ECONNABORTED) and waiter (ENOTCONN).
        std::thread::scope(|s| {
            let t1 = s.spawn(move || h.cx(30, |cx| mkdir(cx, (mnt, dir), b"ab1", 0o755)));
            assert_eq!(h.read_req(false).unwrap().0, op::MKDIR);

            let t2 = s.spawn(move || h.cx(31, |cx| mkdir(cx, (mnt, dir), b"ab2", 0o755)));
            h.wait_until("waiter did not park on dir", |f| {
                f.node(dir).dir_waiters == 1
            });

            {
                let k = h.shared.lock();
                let conn = k.vfs.as_ref().unwrap().fuse().conn_of(dir).unwrap();
                conn.borrow_mut().abort();
            }
            assert_eq!(t1.join().unwrap(), Err(Errno::ECONNABORTED));
            assert_eq!(t2.join().unwrap(), Err(Errno::ENOTCONN));
        });

        h.assert_unlocked(&[dir]);
    }

    #[test]
    fn fstat_and_at_empty_path_send_getattr_fh() {
        let rig = new_rig("fstat-fh", &[40]);
        let h = &rig.h;
        let file_id = h.seed_file(h.root, b"unlinked", 20, 10, 0);
        let noopen_id = h.seed_file(h.root, b"noopen", 21, 10, 0);
        let dir_id = h.seed_dir(h.root, b"sub", 22, 4096, 0);

        let expected_fh = 0x1234_5678_9abc_def0u64;
        let install_reg = |id, nid, fh, no_release| {
            let f = OpenFile::new(
                FileKind::Fuse(Box::new(h.make_handle(id, nid, fh, false, no_release, 0))),
                oflags::O_RDONLY,
            );
            f.borrow_mut().mnt = h.mnt;
            h.install_fd(40, f)
        };
        let fd_open = install_reg(file_id, 20, expected_fh, false);
        let fd_noopen = install_reg(noopen_id, 21, 0, true);
        let f_opath = OpenFile::new(FileKind::Path(Node::Fuse(h.mnt, file_id)), oflags::O_PATH);
        f_opath.borrow_mut().mnt = h.mnt;
        let fd_opath = h.install_fd(40, f_opath);
        let fd_dir = h.install_fd(
            40,
            OpenFile::new(
                FileKind::Directory {
                    node: Node::Fuse(h.mnt, dir_id),
                    entries: None,
                    process: None,
                    fuse: Some(Box::new(h.make_handle(dir_id, 22, 0xdead, true, false, 0))),
                },
                oflags::O_RDONLY,
            ),
        );

        let (empty_path_addr, buf_addr) = {
            let k = h.shared.lock();
            let res = k.tasks[&40].res.borrow();
            let mut mm = res.mm.borrow_mut();
            let page = mm
                .mmap(
                    0,
                    PAGE_SIZE,
                    appine_engine::prot::READ | appine_engine::prot::WRITE,
                    0x22,
                    None,
                )
                .unwrap();
            mm.write(crate::uaccess::UserSlice::new(page, 1), &[0u8])
                .unwrap();
            (page, page + 64)
        };

        let seen = std::sync::Mutex::new(Vec::<(u64, u32, u64)>::new());
        std::thread::scope(|s| {
            let seen_ref = &seen;
            let daemon = s.spawn(move || {
                for _ in 0..6 {
                    let (opcode, unique, nodeid, msg) = h.read_req(false).unwrap();
                    assert_eq!(opcode, op::GETATTR);
                    let flags = u32::from_le_bytes(msg[40..44].try_into().unwrap());
                    let fh = u64::from_le_bytes(msg[48..56].try_into().unwrap());
                    seen_ref.lock().unwrap().push((nodeid, flags, fh));
                    let (m, sz) = if nodeid == 22 {
                        (mode::S_IFDIR | 0o755, 4096)
                    } else {
                        (mode::S_IFREG | 0o644, 12345)
                    };
                    // attr_valid = 0 so every syscall exercises FUSE_GETATTR afresh.
                    h.reply_ok(unique, &attr_out_bytes(nodeid, m, sz, 0, 0));
                }
            });

            {
                let k = h.shared.lock();
                let mut f = k.vfs.as_ref().unwrap().fuse_mut();
                for id in [file_id, noopen_id, dir_id] {
                    f.stale(id);
                }
            }

            const AT_EMPTY_PATH: u32 = 0x1000;
            const STATX_BASIC_STATS: u32 = 0x7ff;

            h.cx(40, |cx| {
                // 1. fstat(fd_open) -> FUSE_GETATTR_FH + expected_fh
                run_with_retries(cx, |cx| super::super::fs::fstat(cx, fd_open, buf_addr)).unwrap();
                let mut st = [0u8; 128];
                cx.mm()
                    .read(crate::uaccess::UserSlice::new(buf_addr, 128), &mut st)
                    .unwrap();
                assert_eq!(u64::from_le_bytes(st[48..56].try_into().unwrap()), 12345);

                // 2. newfstatat(fd_open, "", AT_EMPTY_PATH) -> FUSE_GETATTR_FH + expected_fh
                run_with_retries(cx, |cx| {
                    super::super::fs::newfstatat(
                        cx,
                        fd_open,
                        empty_path_addr,
                        buf_addr,
                        AT_EMPTY_PATH,
                    )
                })
                .unwrap();

                // 3. statx(fd_open, "", AT_EMPTY_PATH) -> FUSE_GETATTR_FH + expected_fh
                run_with_retries(cx, |cx| {
                    super::super::fs::statx(
                        cx,
                        fd_open,
                        empty_path_addr,
                        AT_EMPTY_PATH,
                        STATX_BASIC_STATS,
                        buf_addr,
                    )
                })
                .unwrap();
                let mut stx = [0u8; 256];
                cx.mm()
                    .read(crate::uaccess::UserSlice::new(buf_addr, 256), &mut stx)
                    .unwrap();
                assert_eq!(u64::from_le_bytes(stx[40..48].try_into().unwrap()), 12345);

                // 4-6. no_release, O_PATH, and OPENDIR handles must never send FUSE_GETATTR_FH
                for fd in [fd_noopen, fd_opath, fd_dir] {
                    run_with_retries(cx, |cx| super::super::fs::fstat(cx, fd, buf_addr)).unwrap();
                }
            });
            daemon.join().unwrap();
        });

        assert_eq!(
            seen.into_inner().unwrap(),
            vec![
                (20, 1, expected_fh),
                (20, 1, expected_fh),
                (20, 1, expected_fh),
                (21, 0, 0),
                (20, 0, 0),
                (22, 0, 0),
            ]
        );
    }

    #[test]
    fn directory_lseek_matches_linux_61() {
        const SEEK_SET: u32 = 0;
        const SEEK_CUR: u32 = 1;
        const SEEK_END: u32 = 2;
        const SEEK_DATA: u32 = 3;
        const SEEK_HOLE: u32 = 4;

        let rig = new_rig("dir-lseek", &[50]);
        let h = &rig.h;
        let dir_sized = h.seed_dir(h.root, b"sized", 30, 4096, 0);
        let dir_zero = h.seed_dir(h.root, b"zero", 31, 0, 3600);

        let open_dir = |id, nodeid, open_flags, with_entries: bool| {
            let entries = with_entries.then(|| {
                vec![DirEntry {
                    name: b".".to_vec(),
                    ino: nodeid,
                    mode: mode::S_IFDIR,
                }]
            });
            h.install_fd(
                50,
                OpenFile::new(
                    FileKind::Directory {
                        node: Node::Fuse(h.mnt, id),
                        entries,
                        process: None,
                        fuse: Some(Box::new(
                            h.make_handle(id, nodeid, 9, true, false, open_flags),
                        )),
                    },
                    oflags::O_RDONLY,
                ),
            )
        };
        let fd_sized = open_dir(dir_sized, 30, 0, true);
        let fd_zero = open_dir(dir_zero, 31, 0, true);
        let fd_nonseek = open_dir(dir_sized, 30, fuse::fopen::NONSEEKABLE, false);
        let fd_stream = open_dir(dir_sized, 30, fuse::fopen::STREAM, false);

        let getattrs = AtomicUsize::new(0);
        std::thread::scope(|s| {
            // Daemon answers one FUSE_GETATTR for dir_sized and verifies no FUSE_GETATTR_FH / LSEEK.
            let daemon = s.spawn(|| {
                let (opcode, unique, nodeid, msg) = h.read_req(false).unwrap();
                assert_eq!(opcode, op::GETATTR);
                assert_eq!(nodeid, 30);
                let flags = u32::from_le_bytes(msg[40..44].try_into().unwrap());
                assert_eq!(flags, 0, "dir GETATTR must not set FUSE_GETATTR_FH");
                getattrs.fetch_add(1, Ordering::Relaxed);
                h.reply_ok(
                    unique,
                    &attr_out_bytes(30, mode::S_IFDIR | 0o755, 4096, 2, 60),
                );
            });

            fuse::new_syscall();
            h.cx(50, |cx| {
                let seek = |cx: &mut Cx<'_>, fd, off, w| super::super::fs::lseek(cx, fd, off, w);
                let has_entries = |cx: &Cx<'_>, fd| {
                    matches!(
                        cx.fds().get(fd).unwrap().borrow().kind,
                        FileKind::Directory {
                            entries: Some(_),
                            ..
                        }
                    )
                };

                // SEEK_SET and SEEK_CUR skip GETATTR and preserve entries when != 0.
                assert_eq!(seek(cx, fd_sized, 5, SEEK_SET), Ok(5));
                assert_eq!(seek(cx, fd_sized, 3, SEEK_CUR), Ok(8));
                assert_eq!(seek(cx, fd_sized, -2, SEEK_CUR), Ok(6));
                assert_eq!(seek(cx, fd_sized, -10, SEEK_CUR), Err(Errno::EINVAL));
                assert_eq!(cx.fds().get(fd_sized).unwrap().borrow().pos, 6);
                assert!(has_entries(cx, fd_sized));

                // SEEK_END fetches stale dir_sized size (4096) via FUSE_GETATTR.
                assert_eq!(seek(cx, fd_sized, 0, SEEK_END), Ok(4096));
                assert_eq!(seek(cx, fd_sized, -100, SEEK_END), Ok(3996));
                assert_eq!(seek(cx, fd_sized, 10, SEEK_END), Ok(4106));
                assert_eq!(seek(cx, fd_sized, -5000, SEEK_END), Err(Errno::EINVAL));

                // SEEK_DATA and SEEK_HOLE use generic_file_llseek against dir size (never FUSE_LSEEK).
                assert_eq!(seek(cx, fd_sized, 100, SEEK_DATA), Ok(100));
                assert_eq!(seek(cx, fd_sized, 100, SEEK_HOLE), Ok(4096));
                assert_eq!(seek(cx, fd_sized, 4096, SEEK_DATA), Err(Errno::ENXIO));
                assert_eq!(seek(cx, fd_sized, -1, SEEK_DATA), Err(Errno::ENXIO));
                assert_eq!(seek(cx, fd_sized, 4096, SEEK_HOLE), Err(Errno::ENXIO));

                // Seeking to 0 clears cached entries; negative offset or unknown whence is EINVAL.
                assert_eq!(seek(cx, fd_sized, 0, SEEK_SET), Ok(0));
                assert!(!has_entries(cx, fd_sized));
                assert_eq!(seek(cx, fd_sized, -1, SEEK_SET), Err(Errno::EINVAL));
                assert_eq!(seek(cx, fd_sized, 0, 99), Err(Errno::EINVAL));

                // Zero-sized directory: cached size (0) without RPC, SEEK_END(0) resets entries.
                assert_eq!(seek(cx, fd_zero, 2, SEEK_SET), Ok(2));
                assert_eq!(seek(cx, fd_zero, 0, SEEK_END), Ok(0));
                assert!(!has_entries(cx, fd_zero));
                assert_eq!(seek(cx, fd_zero, -1, SEEK_END), Err(Errno::EINVAL));
                assert_eq!(seek(cx, fd_zero, 0, SEEK_DATA), Err(Errno::ENXIO));
                assert_eq!(seek(cx, fd_zero, 0, SEEK_HOLE), Err(Errno::ENXIO));

                // FOPEN_NONSEEKABLE and FOPEN_STREAM directories return ESPIPE.
                for fd in [fd_nonseek, fd_stream] {
                    assert_eq!(seek(cx, fd, 0, SEEK_SET), Err(Errno::ESPIPE));
                    assert_eq!(seek(cx, fd, 0, SEEK_END), Err(Errno::ESPIPE));
                }
            });
            daemon.join().unwrap();
        });

        assert_eq!(getattrs.load(Ordering::Relaxed), 1);
    }

    fn unix_sockaddr(path: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + path.len() + 1);
        out.extend_from_slice(&1u16.to_le_bytes()); // AF_UNIX
        out.extend_from_slice(path);
        out.push(0);
        out
    }

    struct StopOnDrop<'a>(&'a AtomicBool);
    impl Drop for StopOnDrop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    #[test]
    fn unix_bind_in_fuse_mknod_connect_and_eviction_pinning() {
        let _sweep_guard = fuse::tests::SWEEP_TEST
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let rig = new_rig("unix-bind", &[60, 61]);
        let h = &rig.h;

        let mknod_modes = std::sync::Mutex::new(Vec::<u32>::new());
        let sock_exists = AtomicBool::new(false);
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let daemon = s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let (opcode, unique, nodeid, msg) = match h.read_req(true) {
                        Ok(r) => r,
                        Err(Errno::EAGAIN) => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => panic!("dev_read failed: {e:?}"),
                    };
                    match opcode {
                        op::LOOKUP => {
                            assert_eq!(nodeid, 1);
                            let name = msg[40..].split(|&b| b == 0).next().unwrap();
                            if name == b"s.sock" && sock_exists.load(Ordering::Relaxed) {
                                h.reply_ok(
                                    unique,
                                    &entry_out(42, mode::S_IFSOCK | 0o755, 0, 1, 60),
                                );
                            } else {
                                h.reply(unique, Errno::ENOENT.0, &[]);
                            }
                        }
                        op::MKNOD => {
                            assert_eq!(nodeid, 1);
                            let m = u32::from_le_bytes(msg[40..44].try_into().unwrap());
                            let name = msg[56..].split(|&b| b == 0).next().unwrap();
                            assert_eq!(name, b"s.sock");
                            mknod_modes.lock().unwrap().push(m);
                            sock_exists.store(true, Ordering::Relaxed);
                            h.reply_ok(
                                unique,
                                &entry_out(42, mode::S_IFSOCK | (m & 0o777), 0, 1, 60),
                            );
                        }
                        other => panic!("unexpected opcode {other}"),
                    }
                }
            });
            let _stop_guard = StopOnDrop(&stop);

            let addr = unix_sockaddr(b"/mnt/s.sock");
            let server_sock = Rc::new(RefCell::new(
                super::super::unix::socket(1 /* SOCK_STREAM */, 0).unwrap(),
            ));
            let dup_sock = Rc::new(RefCell::new(
                super::super::unix::socket(1 /* SOCK_STREAM */, 0).unwrap(),
            ));
            let client_sock = Rc::new(RefCell::new(
                super::super::unix::socket(1 /* SOCK_STREAM */, 0).unwrap(),
            ));

            h.cx(60, |cx| {
                run_with_retries(cx, |cx| super::super::unix::bind(cx, &server_sock, &addr))
                    .unwrap();
                if let crate::net::Socket::Unix(u) = &mut *server_sock.borrow_mut() {
                    let ucred = crate::unix::Ucred {
                        pid: 60,
                        uid: 0,
                        gid: 0,
                    };
                    super::super::unix::listen(u, 4, ucred).unwrap();
                }
                // Second bind on the same FUSE socket returns EADDRINUSE.
                assert_eq!(
                    run_with_retries(cx, |cx| super::super::unix::bind(cx, &dup_sock, &addr)),
                    Err(Errno::EADDRINUSE)
                );
                // Trailing slash also returns EADDRINUSE.
                let slash = unix_sockaddr(b"/mnt/s.sock/");
                assert_eq!(
                    run_with_retries(cx, |cx| super::super::unix::bind(cx, &dup_sock, &slash)),
                    Err(Errno::EADDRINUSE)
                );
            });

            // Drop caches while bound: socket node stays pinned so connect still finds the server.
            assert_eq!(h.evict_all(), 0);

            h.cx(61, |cx| {
                run_with_retries(cx, |cx| {
                    super::super::unix::connect(cx, &client_sock, true, &addr)
                })
                .unwrap();
            });

            // Closing the bound socket unpins the FUSE node so eviction can reclaim it.
            drop(client_sock);
            drop(server_sock);
            assert!(h.evict_all() >= 1);

            stop.store(true, Ordering::Relaxed);
            daemon.join().unwrap();
        });

        // Default umask is 0o022 -> S_IFSOCK | 0o755.
        assert_eq!(*mknod_modes.lock().unwrap(), vec![mode::S_IFSOCK | 0o755]);
    }

    #[test]
    fn uncached_lookup_walk_batches_and_caches_errors() {
        let rig = new_rig("lookup-walk", &[70]);
        let h = &rig.h;

        let lookups = std::sync::Mutex::new(Vec::<(u64, Vec<u8>)>::new());
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let daemon = s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let (opcode, unique, nodeid, msg) = match h.read_req(true) {
                        Ok(r) => r,
                        Err(Errno::EAGAIN) => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => panic!("dev_read failed: {e:?}"),
                    };
                    assert_eq!(opcode, op::LOOKUP);
                    let name = msg[40..].split(|&b| b == 0).next().unwrap().to_vec();
                    lookups.lock().unwrap().push((nodeid, name.clone()));
                    match (nodeid, name.as_slice()) {
                        (1, b"a") => {
                            h.reply_ok(unique, &entry_out(10, mode::S_IFDIR | 0o755, 4096, 2, 60))
                        }
                        (10, b"b") => {
                            h.reply_ok(unique, &entry_out(11, mode::S_IFDIR | 0o755, 4096, 2, 60))
                        }
                        (11, b"c") => {
                            h.reply_ok(unique, &entry_out(12, mode::S_IFDIR | 0o755, 4096, 2, 60))
                        }
                        (12, b"d") => {
                            h.reply_ok(unique, &entry_out(13, mode::S_IFDIR | 0o755, 4096, 2, 60))
                        }
                        (13, b"e") => {
                            h.reply_ok(unique, &entry_out(14, mode::S_IFREG | 0o644, 7, 1, 60))
                        }
                        (1, b"bad") => h.reply(unique, Errno::EIO.0, &[]),
                        _ => h.reply(unique, Errno::ENOENT.0, &[]),
                    }
                }
            });
            let _stop_guard = StopOnDrop(&stop);

            // 5-component cold FUSE path resolves in ONE retry cycle (batched LookupWalk).
            h.cx(70, |cx| {
                let vfs = cx.vfs().unwrap();
                let cred = cx.cred();
                let root = cx.root();
                fuse::new_syscall();
                let mut retries = 0usize;
                let node = loop {
                    match vfs.resolve(&cx.view(&vfs), &cred, &root, &root, b"/mnt/a/b/c/d/e", true)
                    {
                        Err(Errno::FUSE_RETRY) => {
                            retries += 1;
                            fuse::serve(cx, |_, _| {}).unwrap();
                        }
                        Ok(n) => break n,
                        Err(e) => panic!("unexpected resolve error: {e:?}"),
                    }
                };
                assert_eq!(retries, 1, "expected 1 batched retry, got {retries}");
                assert!(matches!(node, Node::Fuse(_, _)));

                // Non-ENOENT lookup error (EIO) does NOT abort serve(); it is cached for the
                // syscall and returned directly by vfs.resolve on retry.
                fuse::new_syscall();
                let mut err_retries = 0usize;
                let res = loop {
                    match vfs.resolve(&cx.view(&vfs), &cred, &root, &root, b"/mnt/bad", true) {
                        Err(Errno::FUSE_RETRY) => {
                            err_retries += 1;
                            fuse::serve(cx, |_, _| {}).unwrap();
                        }
                        r => break r,
                    }
                };
                assert_eq!(err_retries, 1);
                assert_eq!(res, Err(Errno::EIO));

                // Same syscall still sees cached EIO without another daemon LOOKUP.
                assert_eq!(
                    vfs.resolve(&cx.view(&vfs), &cred, &root, &root, b"/mnt/bad", true),
                    Err(Errno::EIO)
                );
                // Next syscall clears per-syscall LOOKUP_ERRORS and asks the daemon again.
                fuse::new_syscall();
                assert_eq!(
                    vfs.resolve(&cx.view(&vfs), &cred, &root, &root, b"/mnt/bad", true),
                    Err(Errno::FUSE_RETRY)
                );
                fuse::serve(cx, |_, _| {}).unwrap();
                assert_eq!(
                    vfs.resolve(&cx.view(&vfs), &cred, &root, &root, b"/mnt/bad", true),
                    Err(Errno::EIO)
                );
            });

            stop.store(true, Ordering::Relaxed);
            daemon.join().unwrap();
        });

        let seen = lookups.into_inner().unwrap();
        assert_eq!(
            seen,
            vec![
                (1, b"a".to_vec()),
                (10, b"b".to_vec()),
                (11, b"c".to_vec()),
                (12, b"d".to_vec()),
                (13, b"e".to_vec()),
                (1, b"bad".to_vec()),
                (1, b"bad".to_vec()),
            ]
        );
    }

    #[test]
    fn periodic_writeback_notify_store_auto_inval_and_mlock_willneed() {
        const PAGE: u64 = appine_engine::PAGE_SIZE;
        const FUSE_AUTO_INVAL_DATA: u32 = 1 << 12;
        const FILE_LEN: u64 = 64 * PAGE;
        let rig = new_rig_with_init_flags("mm-wb-store", &[80], FUSE_AUTO_INVAL_DATA);
        let h = &rig.h;
        let file_id = h.seed_file(h.root, b"f", 20, FILE_LEN, 0);
        let fd = h.install_fd(
            80,
            OpenFile::new(
                FileKind::Fuse(Box::new(h.make_handle(file_id, 20, 77, false, false, 0))),
                oflags::O_RDWR,
            ),
        );
        // Set dirty_writeback_centisecs to 1 (10ms) for fast periodic writeback.
        h.shared
            .lock()
            .sysctls
            .insert(b"sys/vm/dirty_writeback_centisecs", 1);

        let reads = AtomicUsize::new(0);
        let bg_writes = std::sync::Mutex::new(Vec::<(u64, u32, Vec<u8>)>::new());
        let file_ver = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let daemon = s.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let (opcode, unique, nodeid, msg) = match h.read_req(true) {
                        Ok(r) => r,
                        Err(Errno::EAGAIN) => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => panic!("dev_read failed: {e:?}"),
                    };
                    assert_eq!(nodeid, 20);
                    match opcode {
                        op::READ => {
                            let off = u64::from_le_bytes(msg[48..56].try_into().unwrap());
                            let sz = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
                            reads.fetch_add(1, Ordering::Relaxed);
                            let mut buf = vec![0u8; sz];
                            for (i, b) in buf.iter_mut().enumerate() {
                                let page = (off + i as u64) / PAGE;
                                *b = if file_ver.load(Ordering::Relaxed) == 0 {
                                    if page == 0 { b'A' } else { b'B' }
                                } else {
                                    b'Z'
                                };
                            }
                            h.reply_ok(unique, &buf);
                        }
                        op::WRITE => {
                            let off = u64::from_le_bytes(msg[48..56].try_into().unwrap());
                            let sz = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
                            let wflags = u32::from_le_bytes(msg[60..64].try_into().unwrap());
                            let payload = msg[80..80 + sz].to_vec();
                            bg_writes.lock().unwrap().push((off, wflags, payload));
                            h.reply_ok(unique, &Args::default().u32(sz as u32).u32(0).0);
                        }
                        op::GETATTR => {
                            let ver = file_ver.load(Ordering::Relaxed) as u64;
                            h.reply_ok(
                                unique,
                                &attr_out_mtime(
                                    20,
                                    mode::S_IFREG | 0o644,
                                    FILE_LEN,
                                    1,
                                    100 + ver,
                                    0,
                                ),
                            );
                        }
                        other => panic!("unexpected opcode {other}"),
                    }
                }
            });
            let _stop_guard = StopOnDrop(&stop);

            // 1. Map the 64-page file shared RW (cold), then fetch page 0 via MADV_WILLNEED.
            let addr = h.cx(80, |cx| {
                run_with_retries(cx, |cx| {
                    super::super::mem::mmap(
                        cx,
                        0,
                        FILE_LEN,
                        appine_engine::prot::READ | appine_engine::prot::WRITE,
                        0x01, /* MAP_SHARED */
                        fd,
                        0,
                    )
                })
                .unwrap() as u64
            });
            assert_eq!(reads.load(Ordering::Relaxed), 0);

            h.cx(80, |cx| {
                super::super::mem::madvise(cx, addr, PAGE, 3 /* MADV_WILLNEED */).unwrap();
            });
            let reads_after_willneed = reads.load(Ordering::Relaxed);
            assert!(reads_after_willneed >= 1);

            // 2. mlock on far-away cold page 63 fetches it via FUSE_READ.
            h.cx(80, |cx| {
                super::super::mem::mlock(cx, addr + 63 * PAGE, PAGE, 0, true).unwrap();
            });
            assert!(reads.load(Ordering::Relaxed) > reads_after_willneed);
            h.cx(80, |cx| {
                let mut b = [0u8; 2];
                cx.read_user(crate::uaccess::UserSlice::new(addr, 1), &mut b[0..1])
                    .unwrap();
                cx.read_user(
                    crate::uaccess::UserSlice::new(addr + 63 * PAGE, 1),
                    &mut b[1..2],
                )
                .unwrap();
                assert_eq!(&b, b"AB");
            });

            // 3. FUSE_NOTIFY_STORE updates resident page 0 directly without a FUSE_READ.
            let store_payload = b"STORED!";
            let store_body = Args::default()
                .u64(20)
                .u64(0)
                .u32(store_payload.len() as u32)
                .u32(0)
                .bytes(store_payload)
                .0;
            // Notification uses unique=0 and positive code=4 (fuse_reply negates error).
            h.reply(0, -4, &store_body);
            h.cx(80, |cx| {
                let mut b = [0u8; 7];
                cx.read_user(crate::uaccess::UserSlice::new(addr, 7), &mut b)
                    .unwrap();
                assert_eq!(&b, b"STORED!");
            });

            // 4. Dirty page 0 and let flush_dirty queue periodic background FUSE_WRITE.
            h.cx(80, |cx| {
                cx.write_user(crate::uaccess::UserSlice::new(addr + 16, 5), b"DIRTY")
                    .unwrap();
            });
            // First tick schedules the deadline; wait 15ms and tick again to flush.
            let due = {
                let k = h.shared.lock();
                fuse::flush_dirty(&k)
            };
            assert!(due.is_some());
            std::thread::sleep(Duration::from_millis(20));
            {
                let k = h.shared.lock();
                let _ = fuse::flush_dirty(&k);
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while bg_writes.lock().unwrap().is_empty() {
                assert!(
                    Instant::now() < deadline,
                    "periodic writeback never arrived"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            let writes = bg_writes.lock().unwrap().clone();
            assert_eq!(writes.len(), 1);
            assert_eq!(writes[0].0, 16);
            assert_ne!(writes[0].1 & 1, 0, "expected FUSE_WRITE_CACHE flag");
            assert_eq!(writes[0].2, b"DIRTY");

            // 5. FUSE_AUTO_INVAL_DATA: changing mtime on GETATTR invalidates resident clean pages
            // so the next read re-fetches 'Z' from the daemon.
            file_ver.store(1, Ordering::Relaxed);
            h.cx(80, |cx| {
                let vfs = cx.vfs().unwrap();
                let _ = fuse::getattr(cx, &vfs, file_id, None, true).unwrap();
            });
            let reads_before = reads.load(Ordering::Relaxed);
            h.cx(80, |cx| {
                let mut b = [0u8; 1];
                super::super::retry_user_pages(cx, Errno::EINTR, |cx| {
                    cx.read_user(crate::uaccess::UserSlice::new(addr, 1), &mut b)
                })
                .unwrap();
                assert_eq!(&b, b"Z");
            });
            assert!(reads.load(Ordering::Relaxed) > reads_before);

            stop.store(true, Ordering::Relaxed);
            daemon.join().unwrap();
        });
    }
}
