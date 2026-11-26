//! mount(2), umount2(2), pivot_root(2) (the kernel/mount map; tmpfs options: the kernel/vfs map;
//! overlay options and the overlay node sweep: the kernel/overlay map).
//!
//! Synthetic filesystems (procfs, sysfs, devpts, cgroup2) can be mounted on any directory;
//! directories and files both in the store and in synthetic filesystems can be bind-mounted
//! (`MS_REC` brings the mounts inside along), and so can namespace files (nsfs; the mount keeps
//! that namespace alive). Mount flags, remounting, `MS_MOVE`, unmounting (`MNT_DETACH`,
//! `MNT_EXPIRE`), pivot_root and the various errors follow Linux 6.1's `path_mount`,
//! `path_umount` and `pivot_root`. Propagation follows `fs/pnode.c`: shared mounts have peer
//! groups and slaves, and mounts and unmounts under them propagate ([`propagate`],
//! [`crate::vfs::Vfs::umount_tree`]). Mounts must be in the caller's mount
//! namespace (Linux's `check_mnt`); those in other namespaces (seen through `/proc/<pid>/root`)
//! are EINVAL. A tmpfs is a tree in the store that does not hang under the root directory
//! (`Vfs::new_tmpfs`). mqueue lists the POSIX message queues in the IPC namespace of the process
//! that mounted it (`syscall::mqueue`).
//! Other filesystems are ENODEV, the same as ones not built into the kernel.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use super::fs::{AT_FDCWD, lookup_at, start_dir};
use super::{SysResult, get, read_path};
use crate::cred::{UserNs, cap};
use crate::errno::Errno;
use crate::fd::FileKind;
use crate::kernel::Cx;
use crate::nsproxy::{Counted, NsRef};
use crate::pseudo::NsKind;
use crate::vfs::store::{Ino, mode};
use crate::vfs::{
    Dentry, Fs, MntNs, Mount, MountId, Node, PropagationType, Pseudo, PseudoNode, Target,
    TmpfsParams, Vfs, fuse, lock, ms, overlay,
};

const MS_REMOUNT: u64 = 0x20;
const MS_BIND: u64 = 0x1000;
const MS_MOVE: u64 = 0x2000;
const MS_REC: u64 = 0x4000;
const MS_SILENT: u64 = 0x8000;
const MS_UNBINDABLE: u64 = 1 << 17;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_SHARED: u64 = 1 << 20;
const MS_STRICTATIME: u64 = 1 << 24;
const MS_NOUSER: u64 = 1 << 31;
const MS_MGC_MSK: u64 = 0xffff_0000;
const MS_MGC_VAL: u64 = 0xc0ed_0000;
const MS_PROPAGATION: u64 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;
/// The access-time flags: when a remount gives none of them, the old ones are kept.
const ATIME: u64 = ms::NOATIME | ms::NODIRATIME | ms::RELATIME;

const MNT_FORCE: u32 = 1;
const MNT_DETACH: u32 = 2;
const MNT_EXPIRE: u32 = 4;
const UMOUNT_NOFOLLOW: u32 = 8;

// ---- mount(2) ----

pub(super) fn mount(
    cx: &mut Cx<'_>,
    source: u64,
    target: u64,
    fstype: u64,
    flags: u64,
    data: u64,
) -> SysResult {
    // As in Linux's ksys_mount: copy the arguments and resolve the mount point first, then look
    // at the flags and permissions
    let fstype = optional_str(cx, fstype)?;
    let source = optional_str(cx, source)?;
    // Only tmpfs and devpts look at the options in data (proc's hidepid and the like are ignored);
    // Linux copies at most one page, and EFAULT if the first byte cannot be read
    let data = if data != 0 {
        get::<1>(cx, data)?;
        cx.mm().read_cstr(data, 4096).unwrap_or_default()
    } else {
        Vec::new()
    };
    let target = read_path(cx, target)?;
    let (node, at, resolved) = {
        let vfs = cx.vfs()?;
        let (node, at) = vfs.walk(
            &cx.view(&vfs),
            &cx.cred(),
            &cx.root(),
            &cx.cwd(),
            &target,
            true,
        )?;
        // When something is already mounted on the mount point, mount on the topmost one (Linux's
        // lock_mount): the same for paths that involve no lookup, such as `.` and the cwd
        let top = vfs.mounted(node.clone());
        let at = at.filter(|_| top == node);
        (top, at, node)
    };
    let mut flags = flags;
    if flags & MS_MGC_MSK == MS_MGC_VAL {
        flags &= !MS_MGC_MSK;
    }
    if flags & MS_NOUSER != 0 {
        return Err(Errno::EINVAL);
    }
    if !may_mount(cx) {
        return Err(Errno::EPERM);
    }
    // Mount flags, relatime by default
    let mut mnt = flags & ms::PER_MOUNT & !ms::RELATIME;
    if flags & ms::NOATIME == 0 {
        mnt |= ms::RELATIME;
    }
    if flags & MS_STRICTATIME != 0 {
        mnt &= !(ms::RELATIME | ms::NOATIME);
    }
    // remount does not climb up: a covered node reached through a magic link is not a mount root
    // (EINVAL)
    // Superblock flags: a new instance's, or a remount's without MS_BIND
    let sb = flags & ms::PER_SB;
    if flags & MS_REMOUNT != 0 {
        let keep_atime = flags & (ATIME | MS_STRICTATIME) == 0;
        let data = (flags & MS_BIND == 0).then_some((&data[..], sb));
        return remount(cx, &resolved, mnt, keep_atime, data);
    }
    if flags & MS_BIND != 0 {
        return bind(cx, source.as_deref(), (node, at), flags & MS_REC != 0);
    }
    if flags & MS_PROPAGATION != 0 {
        return change_type(cx, &node, flags);
    }
    if flags & MS_MOVE != 0 {
        return move_mount(cx, source.as_deref(), (node, at));
    }
    new_mount(cx, fstype, source, (node, at), (mnt, sb), &data)
}

/// The superblock flags `sb` of the instance mount `id` created (Linux's `fc->sb_flags`), and
/// the user namespace `owner` owning it (`fc->user_ns`, [`Mount::owner`]).
fn new_superblock(vfs: &Vfs, id: MountId, sb: u64, owner: &Rc<UserNs>) {
    if let Some(m) = vfs.mount(id) {
        vfs.set_sb_flags(m.dev, sb);
    }
    set_owner(vfs, id, owner);
}

/// Records `owner` as the user namespace owning mount `id`'s instance ([`Mount::owner`]; None
/// for the initial one).
fn set_owner(vfs: &Vfs, id: MountId, owner: &Rc<UserNs>) {
    let owner = (owner.level > 0).then(|| owner.clone());
    vfs.update_mount(id, |m| m.owner = owner);
}

/// A string argument of mount(2); None for a null pointer.
fn optional_str(cx: &Cx<'_>, addr: u64) -> Result<Option<Vec<u8>>, Errno> {
    if addr == 0 {
        return Ok(None);
    }
    read_path(cx, addr).map(Some)
}

/// Mounts a new filesystem (Linux's `do_new_mount`) with mount flags `flags`; a new instance
/// gets superblock flags `sb` ([`ms::PER_SB`]).
fn new_mount(
    cx: &mut Cx<'_>,
    fstype: Option<Vec<u8>>,
    source: Option<Vec<u8>>,
    (target, at): (Node, Option<Dentry>),
    (flags, sb): (u64, u64),
    data: &[u8],
) -> SysResult {
    let fstype = fstype.ok_or(Errno::EINVAL)?;
    let Some(fs) = Fs::from_type(&fstype) else {
        let name = String::from_utf8_lossy(&fstype);
        crate::debug::log(format_args!("mount: no filesystem type {name}"));
        return Err(Errno::ENODEV);
    };
    // mqueue mounts the instance of the caller's IPC namespace, which needs CAP_SYS_ADMIN in the
    // namespace's owner (Linux's mqueue_init_fs_context replaces fc->user_ns with that owner, then
    // calls mount_capable)
    let ipc = cx.ns().ipc;
    if fs == Fs::Mqueue && !cx.cred().ns_capable(&ipc.owner, cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    // proc needs CAP_SYS_ADMIN over the owner of the caller's pid namespace, sysfs over the owner
    // of its network namespace and cgroup2 over the owner of its cgroup namespace (the
    // fc->user_ns of Linux's proc_init_fs_context, sysfs_init_fs_context and
    // cgroup_init_fs_context, checked by mount_capable); then, outside the initial user
    // namespace, a proc or sysfs instance must already be fully visible (mount_too_revealing)
    let owner = match fs {
        Fs::Proc => Some(cx.pid_ns().owner.clone()),
        Fs::Sys => Some(cx.ns().net.owner.clone()),
        Fs::Cgroup => Some(cx.ns().cgroup.owner.clone()),
        _ => None,
    };
    if owner.is_some_and(|o| !cx.cred().ns_capable(&o, cap::SYS_ADMIN)) {
        return Err(Errno::EPERM);
    }
    // The user namespace owning the instance (sget_fc's s_user_ns): procfs's pid namespace's
    // owner and mqueue's IPC namespace's; sysfs and cgroup2 superblocks are global (fc->global),
    // so the initial one owns them whatever namespace they show; otherwise the mounter's
    let sb_owner = match fs {
        Fs::Proc => cx.pid_ns().owner.clone(),
        Fs::Mqueue => ipc.owner.clone(),
        Fs::Sys | Fs::Cgroup => UserNs::init(),
        _ => cx.cred().user_ns.clone(),
    };
    let inherited = if matches!(fs, Fs::Proc | Fs::Sys) {
        visible_locks(cx, fs, flags)?
    } else {
        0
    };
    // cgroup2 can be mounted without read-only (crun does so when mounting /sys/fs/cgroup for a
    // container), and is then writable like the boot mount
    let vfs = cx.vfs()?;
    may_mount_on(&target)?;
    check_mnt(cx, &vfs, target.mnt())?;
    // A filesystem with a single instance cannot be mounted again on the root of its own mount
    // (Linux's do_add_mount); mqueue has one instance per IPC namespace and sysfs one per network
    // namespace
    let net = cx.ns().net;
    let same_instance = |m: &Mount| {
        m.fs == fs
            && (fs != Fs::Mqueue
                || matches!(&m.root, Node::Pseudo(_, PseudoNode::MqRoot(n)) if *n == ipc.id))
            && (fs != Fs::Sys
                || vfs
                    .sys_net_ns(m.id)
                    .map_or(crate::nsproxy::INIT_NET_NS, |n| n.id)
                    == net.id)
    };
    if !fs.new_instance()
        && let Some(id) = vfs.mount_root(&target)
        && vfs.mount(id).is_some_and(|m| same_instance(&m))
    {
        return Err(Errno::EBUSY);
    }
    if !vfs.is_dir(&cx.view(&vfs), &target)? {
        return Err(Errno::ENOTDIR);
    }
    // devpts options (owner and permissions of the new instance's terminals, ptmx permissions,
    // the maximum)
    let devpts = if fs == Fs::Pts {
        let cred = cx.cred();
        Some(crate::tty::PtsOptions::parse(
            data,
            |u| cred.uid_in(u),
            |g| cred.gid_in(g),
        )?)
    } else {
        None
    };
    if fs == Fs::Overlay {
        let ((layers, pins), options) = overlay_layers(cx, &vfs, data)?;
        let targets = plan_attach(cx, &vfs, (&target, at.as_ref()), 1, 1)?;
        let cred = cx.cred();
        let id = vfs.new_overlay(
            (target, at),
            flags,
            source.unwrap_or_default(),
            (layers, (cred.fsuid, cred.fsgid), pins),
            options,
        );
        new_superblock(&vfs, id, sb, &sb_owner);
        propagate(cx, &vfs, id, &targets);
        return Ok(0);
    }
    if fs == Fs::Fuse {
        return fuse_mount(cx, &vfs, &fstype, source, (target, at), (flags, sb), data);
    }
    if fs == Fs::Tmpfs {
        let params = tmpfs_options(data, &cx.cred())?;
        let source = source.unwrap_or_default();
        let targets = plan_attach(cx, &vfs, (&target, at.as_ref()), 1, 1)?;
        let id = vfs.new_tmpfs((target, at), flags, source, params)?;
        new_superblock(&vfs, id, sb, &sb_owner);
        propagate(cx, &vfs, id, &targets);
        return Ok(0);
    }
    let targets = plan_attach(cx, &vfs, (&target, at.as_ref()), 1, 1)?;
    let (root, dev) = match fs {
        Fs::Mqueue => (
            Node::Pseudo(0, PseudoNode::MqRoot(ipc.id)),
            Some(vfs.mq_dev(ipc.id)),
        ),
        Fs::Sys => (fs.root(), Some(vfs.sys_dev(&net))),
        // The root of cgroup2 is the root of the caller's cgroup namespace (Linux's
        // cgroup_get_tree)
        Fs::Cgroup => (
            Node::Pseudo(0, PseudoNode::Cgroup(cx.ns().cgroup.root, b"", 0)),
            Some(fs.dev()),
        ),
        _ => (fs.root(), (!fs.own_dev()).then(|| fs.dev())),
    };
    let id = vfs.add_mount(
        fs,
        root,
        (target, at),
        flags,
        source.unwrap_or_default(),
        dev,
    );
    if inherited != 0 {
        vfs.update_mount(id, |m| m.locks = inherited);
    }
    if fs.new_instance() {
        new_superblock(&vfs, id, sb, &sb_owner);
    } else {
        set_owner(&vfs, id, &sb_owner);
    }
    // Every devpts mount is a new instance (since 4.7) with its own set of terminals, numbered by
    // the newly allocated device number
    if let Some(opts) = devpts {
        let dev = vfs.mount(id).map_or(0, |m| m.dev);
        vfs.set_devpts_options(dev, opts);
        vfs.update_mount(id, |m| {
            m.root = Node::Pseudo(id, PseudoNode::PtsRoot(dev));
        });
    }
    // An mqueue mount keeps that IPC namespace (and its queues) alive, just as Linux's superblock
    // references it
    if fs == Fs::Mqueue {
        vfs.update_mount(id, |m| m.pin = Some(crate::nsproxy::NsRef::Ipc(ipc)));
    }
    // Pids in procfs are counted in the pid namespace of the process that mounted it
    let pid_ns = cx.pid_ns();
    if fs == Fs::Proc && pid_ns.level > 0 {
        vfs.set_proc_pid_ns(id, pid_ns);
    }
    propagate(cx, &vfs, id, &targets);
    Ok(0)
}

/// Mounts a new FUSE instance (6.1's `fuse_get_tree` and `fuse_fill_super`): type `fuse` or
/// `fuse.<subtype>` (an empty subtype is EINVAL), the options of [`fuse::Options::parse`], of
/// which `fd`, `rootmode`, `user_id` and `group_id` must all be given, and `fd` must be open on
/// `/dev/fuse` by a process in the mounter's user namespace (EINVAL). The device file is attached
/// to the new connection and `FUSE_INIT` queued; the mount does not wait for the daemon to answer
/// it. A device file already attached mounts its instance again.
fn fuse_mount(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    fstype: &[u8],
    source: Option<Vec<u8>>,
    (target, at): (Node, Option<Dentry>),
    (flags, sb): (u64, u64),
    data: &[u8],
) -> SysResult {
    let cred = cx.cred();
    let mut opts = fuse::Options::parse(data, &cred)?;
    // The type's subtype is given before the options, so one there too is EINVAL (6.1's
    // do_new_mount, then "Multiple subtypes specified")
    if let Some(sub) = fstype.strip_prefix(b"fuse.") {
        if sub.is_empty() || opts.subtype.is_some() {
            return Err(Errno::EINVAL);
        }
        opts.subtype = Some(sub.to_vec());
    }
    // A descriptor that is not open is EINVAL (6.1's fuse_get_tree finds no file)
    let file = opts
        .fd
        .and_then(|fd| cx.fds().get(fd).ok())
        .ok_or(Errno::EINVAL)?;
    // One already attached to a connection mounts that connection's instance again, while it
    // still exists (ENOTCONN once it is gone), whatever the other options say (sget_fc keyed by
    // the connection)
    let attached = match &file.borrow().kind {
        FileKind::FuseDev(d) => d.conn.clone(),
        _ => None,
    };
    if let Some(conn) = attached {
        let dev = conn.borrow().dev;
        if vfs.fuse().conn(dev).is_none() {
            return Err(Errno::ENOTCONN);
        }
        let targets = plan_attach(cx, vfs, (&target, at.as_ref()), 1, 1)?;
        let id = vfs.add_fuse_mount((target, at), flags, source.unwrap_or_default(), dev)?;
        let owner = conn.borrow().user_ns().clone();
        set_owner(vfs, id, &owner);
        propagate(cx, vfs, id, &targets);
        return Ok(0);
    }
    let (Some(_), Some(_), Some(_)) = (opts.rootmode, opts.user_id, opts.group_id) else {
        return Err(Errno::EINVAL);
    };
    match &file.borrow().kind {
        FileKind::FuseDev(d) if Rc::ptr_eq(&d.opener_ns, &cred.user_ns) => {}
        _ => return Err(Errno::EINVAL),
    }
    let targets = plan_attach(cx, vfs, (&target, at.as_ref()), 1, 1)?;
    let pid_ns = cx.pid_ns();
    let (id, conn) = vfs.new_fuse((target, at), flags, source.unwrap_or_default(), |dev| {
        fuse::Conn::new(dev, opts, &cred, pid_ns)
    });
    new_superblock(vfs, id, sb, &cred.user_ns);
    propagate(cx, vfs, id, &targets);
    if let FileKind::FuseDev(d) = &mut file.borrow_mut().kind {
        d.attach(&conn);
    }
    fuse::send_init(&conn);
    cx.shared.fast_changed();
    Ok(0)
}

/// The layers of a new overlay as 6.1's `ovl_fill_super` finds them, each resolved from the
/// caller's root and current directory: the options (EINVAL as [`overlay::Options::parse`]); the
/// upper layer and the work directory, which must both be given, be on one mount that is not
/// read-only and be outside each other (EINVAL); the lower layers, topmost first (at least two
/// without an upper layer, EINVAL), none of which may be inside the upper layer or the work
/// directory (ELOOP). Every layer must be a directory in the store (EINVAL); resolution errors are
/// their own. The work directory then gets an empty `work` directory (mode 0, the mounter's), as
/// Linux's `ovl_make_workdir` leaves.
fn overlay_layers(
    cx: &Cx<'_>,
    vfs: &Vfs,
    data: &[u8],
) -> Result<((overlay::Layers, Vec<u64>), overlay::Options), Errno> {
    let options = overlay::Options::parse(data)?;
    // The tmpfs instances the layers are in
    let mut pins = Vec::new();
    let mut pin = |(mnt, ino): (MountId, Ino)| {
        if let Some(dev) = vfs.tmpfs_dev(&Node::Store(mnt, ino)) {
            pins.push(dev);
        }
        (mnt, ino)
    };
    let paths = options.lower_paths()?;
    let store = vfs.store();
    let upper = match (options.upper_path(), options.work_path()) {
        (None, _) => None,
        (Some(_), None) => return Err(Errno::EINVAL),
        (Some(upper), Some(work)) => {
            if upper.is_empty() || work.is_empty() {
                return Err(Errno::EINVAL);
            }
            let (mnt, upper) = pin(overlay_dir(cx, vfs, &upper)?);
            if vfs.readonly(&Node::Store(mnt, upper)) {
                return Err(Errno::EINVAL);
            }
            let (work_mnt, work) = pin(overlay_dir(cx, vfs, &work)?);
            if work_mnt != mnt || under(store, upper, work)? || under(store, work, upper)? {
                return Err(Errno::EINVAL);
            }
            Some((upper, work))
        }
    };
    if upper.is_none() && paths.len() < 2 {
        return Err(Errno::EINVAL);
    }
    let mut lower = Vec::new();
    for p in &paths {
        lower.push(pin(overlay_dir(cx, vfs, p)?).1);
    }
    if let Some((up, work)) = upper {
        for &l in &lower {
            if under(store, l, up)? || under(store, l, work)? {
                return Err(Errno::ELOOP);
            }
        }
        let cred = cx.cred();
        store.transaction(|s| {
            if s.lookup(work, b"work")?.is_some() {
                remove_tree(s, work, b"work")?;
            }
            s.mkdir(work, b"work", 0, cred.fsuid, cred.fsgid)
                .map(|_| ())
        })?;
    }
    Ok((((upper.map(|(up, _)| up), lower), pins), options))
}

/// The mount and store directory an overlay layer's path names (Linux's `ovl_mount_dir_noesc`,
/// then `clone_private_mount`): EINVAL when it is not a directory, for a directory in a synthetic
/// filesystem or in another overlay (Linux accepts an overlay as a lower layer; Appine does not),
/// on a mount of another mount namespace, and with a mount locked in place under it (the overlay
/// would uncover what that mount hides).
fn overlay_dir(cx: &Cx<'_>, vfs: &Vfs, path: &[u8]) -> Result<(MountId, Ino), Errno> {
    let view = cx.view(vfs);
    match vfs.resolve(&view, &cx.cred(), &cx.root(), &cx.cwd(), path, true)? {
        node @ Node::Store(mnt, ino) if vfs.store().kind(ino)? == mode::S_IFDIR => {
            check_mnt(cx, vfs, mnt)?;
            if has_locked_children(vfs, &view, &node) {
                return Err(Errno::EINVAL);
            }
            Ok((mnt, ino))
        }
        Node::Overlay(..) => {
            crate::debug::log(format_args!(
                "mount: overlay layers in an overlay are not supported"
            ));
            Err(Errno::EINVAL)
        }
        _ => Err(Errno::EINVAL),
    }
}

/// Store directory `ino` is `top` or inside it.
fn under(store: &crate::vfs::store::Store, ino: Ino, top: Ino) -> Result<bool, Errno> {
    let mut cur = ino;
    loop {
        if cur == top {
            return Ok(true);
        }
        let up = store.parent(cur)?;
        if up == cur {
            return Ok(false);
        }
        cur = up;
    }
}

/// Removes `name` from store directory `dir` with everything in it.
fn remove_tree(s: &crate::vfs::store::Store, dir: Ino, name: &[u8]) -> Result<(), Errno> {
    let ino = s.lookup(dir, name)?.ok_or(Errno::ENOENT)?;
    if s.kind(ino)? != mode::S_IFDIR {
        return s.unlink(dir, name);
    }
    for e in s.readdir(ino)? {
        remove_tree(s, ino, &e.name)?;
    }
    s.rmdir(dir, name)
}

/// Linux's `mount_too_revealing` for a new proc or sysfs mount with flags `flags`: in a mount
/// namespace owned by a user namespace other than the initial one, the caller must already see the
/// whole filesystem, through a mount of its root in its namespace whose locked read-only and
/// access-time flags the new mount keeps and with no locked mount over anything but an empty
/// mount-point directory (`mnt_already_visible`); otherwise a sandbox that hides or protects parts
/// of `/proc` or `/sys` could be undone with a new instance. EPERM when there is none; else the
/// locks the new mount takes over from it.
fn visible_locks(cx: &Cx<'_>, fs: Fs, flags: u64) -> Result<u64, Errno> {
    let ns = cx.t.fs.borrow().mnt_ns.clone();
    if ns.owner.id == crate::cred::INIT_USER_NS {
        return Ok(0);
    }
    let vfs = cx.vfs()?;
    let mounts: Vec<Mount> = vfs.mounts().into_iter().filter(|m| m.ns == ns.id).collect();
    let blocked: HashSet<MountId> = mounts
        .iter()
        .filter(|c| c.locks & lock::MOUNT != 0 && !c.point.as_ref().is_some_and(empty_mount_point))
        .filter_map(Mount::parent)
        .collect();
    let visible = mounts.iter().find(|m| {
        m.fs == fs
            && m.root == fs.root().in_mount(m.id)
            && (m.locks & lock::READONLY == 0 || flags & ms::RDONLY != 0)
            && (m.locks & lock::ATIME == 0 || m.flags & ATIME == flags & ATIME)
            && !blocked.contains(&m.id)
    });
    match visible {
        Some(m) => Ok(m.locks & (lock::READONLY | lock::ATIME)),
        None => Err(Errno::EPERM),
    }
}

/// A directory of proc or sysfs that is always empty, made only to have something mounted on it
/// (Linux's `is_empty_dir_inode`, from `sysfs_create_mount_point`): `/sys/fs/cgroup`.
fn empty_mount_point(point: &Node) -> bool {
    matches!(point, Node::Pseudo(_, p) if *p == crate::pseudo::CGROUP_POINT)
}

/// The parameters of a newly mounted tmpfs: defaults for what is not given (permissions 1777,
/// owner and group the mounting process's fsuid and fsgid, size and inode count half of physical
/// memory, inode64).
fn tmpfs_options(data: &[u8], cred: &crate::cred::Cred) -> Result<TmpfsParams, Errno> {
    let o = parse_tmpfs(data)?;
    // uid= and gid= are IDs in the mounter's user namespace (shmem_parse_one's make_kuid), EINVAL
    // when unmapped there
    let uid = o
        .uid
        .map(|u| cred.uid_in(u).ok_or(Errno::EINVAL))
        .transpose()?;
    let gid = o
        .gid
        .map(|g| cred.gid_in(g).ok_or(Errno::EINVAL))
        .transpose()?;
    let default = TmpfsParams::default_limit();
    Ok(TmpfsParams {
        perm: o.perm.unwrap_or(0o1777),
        uid: uid.unwrap_or(cred.fsuid),
        gid: gid.unwrap_or(cred.fsgid),
        blocks: o.blocks.unwrap_or(default),
        inodes: o.inodes.unwrap_or(default),
        inode64: o.inode64.unwrap_or(true),
    })
}

/// Bind mount (Linux's `do_loopback`): the new mount sees the source directory or file, with the
/// flags and device number of the mount the source is in.
fn bind(
    cx: &mut Cx<'_>,
    source: Option<&[u8]>,
    (target, at): (Node, Option<Dentry>),
    recursive: bool,
) -> SysResult {
    let source = source.filter(|s| !s.is_empty()).ok_or(Errno::EINVAL)?;
    let start = start_dir(cx, AT_FDCWD, source)?;
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    let (src, found) = vfs.walk(&view, &cx.cred(), &cx.root(), &start, source, true)?;
    if let Node::Pseudo(_, PseudoNode::NsFile(kind, ns)) = src {
        return bind_ns(cx, &vfs, kind, ns, src, (target, at));
    }
    may_mount_on(&target)?;
    let dir = vfs.is_dir(&view, &src)?;
    if dir != vfs.is_dir(&view, &target)? {
        return Err(Errno::ENOTDIR);
    }
    // An unbindable mount, unmounted mounts and mounts in other namespaces cannot be bound
    // (Linux's __do_loopback, check_mnt)
    if vfs.propagation(src.mnt()).unbindable {
        return Err(Errno::EINVAL);
    }
    check_mnt(cx, &vfs, src.mnt())?;
    check_mnt(cx, &vfs, target.mnt())?;
    if !recursive && has_locked_children(&vfs, &view, &src) {
        return Err(Errno::EINVAL);
    }
    let m = vfs.mount(src.mnt()).ok_or(Errno::EINVAL)?;
    // Plan the copies of the mounts inside the source before mounting: if the target is inside the
    // source, the new mount is not copied into itself
    let inside = if recursive { vfs.mounts() } else { Vec::new() };
    let plan = plan_copies(&vfs, &view, &inside, &src)?;
    let size = 1 + plan.len();
    let targets = plan_attach(cx, &vfs, (&target, at.as_ref()), size, size)?;
    let id = vfs.add_mount_unattached(
        m.fs,
        src.clone(),
        (target, at),
        m.flags,
        m.source,
        Some(m.dev),
    );
    if !dir {
        vfs.set_root_at(id, found);
    }
    // As in __do_loopback, the new mount keeps the source's locked flags but is not locked itself;
    // the mounts copied below it keep their locks. A bind of a shared mount is its peer, of a
    // slave a slave of the same master (clone_mnt), and then the parent's type applies
    vfs.update_mount(id, |n| {
        n.locks = m.locks & !lock::MOUNT;
        n.prop = m.prop.of_bind();
    });
    vfs.add_copies(id, &plan);
    vfs.attached(id);
    propagate(cx, &vfs, id, &targets);
    Ok(0)
}

/// Whether a mount locked in place ([`lock::MOUNT`]) is mounted on or under `src` in its mount
/// (Linux's `has_locked_children`): binding `src` without the mounts inside would uncover what
/// such a mount hides.
fn has_locked_children(vfs: &Vfs, ps: &dyn Pseudo, src: &Node) -> bool {
    vfs.children(src.mnt()).iter().any(|c| {
        c.locks & lock::MOUNT != 0
            && c.point.as_ref().is_some_and(|point| {
                let from = c.at.as_ref().map_or(point, |(dir, _)| dir);
                point == src || vfs.is_under(ps, from, src)
            })
    })
}

/// Bind-mounts a namespace file (how `ip netns add` keeps a namespace alive): the mount holds
/// that namespace ([`Mount::pin`]), lives in nsfs, and has only the rw flag. As in Linux's
/// do_loopback, a file found through a path in another mount namespace also works; a mount
/// namespace's file can only be mounted into a namespace older than it (`mnt_ns_loop`: otherwise
/// a namespace could keep itself alive through a mount).
fn bind_ns(
    cx: &mut Cx<'_>,
    vfs: &Vfs,
    kind: NsKind,
    id: u64,
    src: Node,
    (target, at): (Node, Option<Dentry>),
) -> SysResult {
    let ns = super::ns::find(cx.kr(), Some(vfs), kind, id).ok_or(Errno::ENOENT)?;
    if matches!(&ns, NsRef::Mnt(m) if cx.mnt_ns() >= m.id) {
        return Err(Errno::EINVAL);
    }
    check_mnt(cx, vfs, target.mnt())?;
    may_mount_on(&target)?;
    if vfs.is_dir(&cx.view(vfs), &target)? {
        return Err(Errno::ENOTDIR);
    }
    let targets = plan_attach(cx, vfs, (&target, at.as_ref()), 1, 1)?;
    let fs = Fs::Nsfs;
    let id = vfs.add_mount(fs, src, (target, at), 0, b"nsfs".to_vec(), Some(fs.dev()));
    vfs.update_mount(id, |m| m.pin = Some(ns));
    propagate(cx, vfs, id, &targets);
    Ok(0)
}

/// Remount: changes the mount's flags. With `data` (no `MS_BIND`, Linux's `do_remount`) the
/// instance changes too, for every mount of it: its superblock flags `sb`, and for tmpfs the size
/// and inode count in the options ([`remount_tmpfs`]); that needs `CAP_SYS_ADMIN` over the user
/// namespace owning the instance ([`Mount::owner`]). Without it (`do_reconfigure_mnt`) only the
/// mount's flags change. Going read-only while files are open for writing is EBUSY: through this
/// mount for `MS_BIND` (`mnt_make_readonly`), through any mount of the same instance otherwise
/// (`sb_prepare_remount_readonly`).
fn remount(
    cx: &mut Cx<'_>,
    target: &Node,
    flags: u64,
    keep_atime: bool,
    data: Option<(&[u8], u64)>,
) -> SysResult {
    let vfs = cx.vfs()?;
    let id = vfs.mount_root(target).ok_or(Errno::EINVAL)?;
    check_mnt(cx, &vfs, id)?;
    let m = vfs.mount(id).ok_or(Errno::EINVAL)?;
    let flags = if keep_atime {
        (flags & !ATIME) | (m.flags & ATIME)
    } else {
        flags
    };
    // Flags locked by a less privileged mount namespace stay (Linux's can_change_locked_flags,
    // before the superblock is touched)
    if !m.keeps_locked(flags) {
        return Err(Errno::EPERM);
    }
    // Without MS_BIND the instance changes, which needs CAP_SYS_ADMIN over the user namespace
    // owning it (6.1's do_remount: after parsing the options, before reconfigure_super's writer
    // check), so root of a user namespace cannot remount the boot root or a shared tmpfs
    if let Some((data, _)) = data {
        if m.fs == Fs::Tmpfs {
            tmpfs_options(data, &cx.cred())?;
        }
        let init = UserNs::init();
        if !cx
            .cred()
            .ns_capable(m.owner.as_ref().unwrap_or(&init), cap::SYS_ADMIN)
        {
            return Err(Errno::EPERM);
        }
    }
    // Going read-only: the superblock while it is not busy (sb_prepare_remount_readonly), or just
    // this mount while it has no writers (mnt_make_readonly)
    let sb_ro = vfs.sb_readonly(&m);
    let busy = match data {
        Some((_, sb)) if sb & ms::RDONLY != 0 && !sb_ro => sb_busy(cx.kr(), &vfs, m.dev),
        None if flags & ms::RDONLY != 0 && m.flags & ms::RDONLY == 0 => {
            writers(cx.kr()).contains(&id)
        }
        _ => false,
    };
    if busy {
        return Err(Errno::EBUSY);
    }
    // An overlay without an upper layer stays read-only (6.1's ovl_remount)
    if data.is_some()
        && m.fs == Fs::Overlay
        && flags & ms::RDONLY == 0
        && vfs
            .overlay()
            .instance(m.dev)
            .is_some_and(|i| i.upper.is_none())
    {
        return Err(Errno::EROFS);
    }
    // Without MS_BIND the superblock changes too: a tmpfs's size and inode count; on error the
    // mount's flags do not change either
    if let Some((data, _)) = data
        && m.fs == Fs::Tmpfs
    {
        super::fs::evict_unlinked_tmpfs(cx.kr(), &vfs);
        remount_tmpfs(&vfs, m.dev, data)?;
    }
    if let Some((_, sb)) = data {
        let old = vfs.sb_flags(&m);
        vfs.set_sb_flags(m.dev, (old & !ms::REMOUNT_SB) | (sb & ms::REMOUNT_SB));
    }
    vfs.update_mount(id, |m| m.flags = flags);
    // Once the root filesystem becomes nosymfollow, resolution without the BKL is no longer
    // possible
    cx.shared.fast_changed();
    Ok(0)
}

/// Changes a tmpfs's superblock on remount (Linux 6.1's `shmem_reconfigure`): when a nonzero
/// `size=` or `nr_inodes=` is given, an unlimited value cannot become limited and a limit cannot
/// go below what is already used (both EINVAL); the given size and inode count (0 makes it
/// unlimited) and inode32/64 are applied as given; `mode=`, `uid=` and `gid=` stay unchanged.
fn remount_tmpfs(vfs: &Vfs, dev: u64, data: &[u8]) -> Result<(), Errno> {
    let o = parse_tmpfs(data)?;
    vfs.tmpfs_reconfigure(dev, |p, pages, inodes| {
        if let Some(b) = o.blocks.filter(|&b| b != 0)
            && (p.blocks == 0 || b < pages)
        {
            return Err(Errno::EINVAL);
        }
        if let Some(n) = o.inodes.filter(|&n| n != 0)
            && (p.inodes == 0 || n < inodes)
        {
            return Err(Errno::EINVAL);
        }
        p.blocks = o.blocks.unwrap_or(p.blocks);
        p.inodes = o.inodes.unwrap_or(p.inodes);
        p.inode64 = o.inode64.unwrap_or(p.inode64);
        Ok(())
    })
}

/// Changes the propagation type (Linux's `do_change_type`) of the mount whose root `target` is,
/// attached in any namespace or detached, and with `MS_REC` of the mounts below it; mounts and
/// unmounts made afterwards propagate by the new types ([`crate::vfs::Propagation`]).
fn change_type(cx: &mut Cx<'_>, target: &Node, flags: u64) -> SysResult {
    let vfs = cx.vfs()?;
    let id = vfs.any_mount_root(target).ok_or(Errno::EINVAL)?;
    let kind = propagation_type(flags & !(MS_REC | MS_SILENT)).ok_or(Errno::EINVAL)?;
    vfs.set_propagation(id, kind, flags & MS_REC != 0);
    Ok(0)
}

/// The propagation type of exactly one of `MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` and
/// `MS_UNBINDABLE` (`flags_to_propagation_type`).
fn propagation_type(flags: u64) -> Option<PropagationType> {
    match flags {
        MS_SHARED => Some(PropagationType::Shared),
        MS_SLAVE => Some(PropagationType::Slave),
        MS_PRIVATE => Some(PropagationType::Private),
        MS_UNBINDABLE => Some(PropagationType::Unbindable),
        _ => None,
    }
}

/// `MS_MOVE` (Linux's `do_move_mount`): moves mount `source`, with the mounts inside it, onto
/// `target`. The source must be the root of a mount and not the root of a mount tree, and the
/// target must not be inside it.
fn move_mount(
    cx: &mut Cx<'_>,
    source: Option<&[u8]>,
    (target, at): (Node, Option<Dentry>),
) -> SysResult {
    let source = source.filter(|s| !s.is_empty()).ok_or(Errno::EINVAL)?;
    let src = lookup_at(cx, AT_FDCWD, source, true)?;
    move_tree(cx, &src, (target, at))
}

/// The tmpfs mount options that were given (the `shmem_options` parsed by Linux 6.1's
/// `shmem_parse_one`). Unknown options are EINVAL.
#[derive(Default)]
struct TmpfsOptions {
    perm: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// Number of pages and of inodes (0 is unlimited).
    blocks: Option<u64>,
    inodes: Option<u64>,
    inode64: Option<bool>,
}

fn parse_tmpfs(data: &[u8]) -> Result<TmpfsOptions, Errno> {
    const PAGE: u64 = crate::vfs::TMPFS_PAGE;
    let mut o = TmpfsOptions::default();
    for opt in data.split(|&b| b == b',').filter(|o| !o.is_empty()) {
        let (key, value) = match opt.iter().position(|&b| b == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        let id = |v: &[u8]| {
            parse_num(v)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|&n| n != u32::MAX)
                .ok_or(Errno::EINVAL)
        };
        match (key, value) {
            (b"size", Some(v)) => {
                let (n, rest) = memparse(v)?;
                let bytes = match rest {
                    b"" => n,
                    b"%" => n.saturating_mul(appine_hal::memory_info().0) / 100,
                    _ => return Err(Errno::EINVAL),
                };
                o.blocks = Some(bytes.div_ceil(PAGE));
            }
            (b"nr_blocks", Some(v)) => match memparse(v)? {
                (n, b"") => o.blocks = Some(n),
                _ => return Err(Errno::EINVAL),
            },
            (b"nr_inodes", Some(v)) => match memparse(v)? {
                (n, b"") => o.inodes = Some(n),
                _ => return Err(Errno::EINVAL),
            },
            (b"mode", Some(v)) => {
                let s = std::str::from_utf8(v).map_err(|_| Errno::EINVAL)?;
                o.perm = Some(u32::from_str_radix(s, 8).map_err(|_| Errno::EINVAL)? & 0o7777);
            }
            (b"uid", Some(v)) => o.uid = Some(id(v)?),
            (b"gid", Some(v)) => o.gid = Some(id(v)?),
            (b"inode64", None) => o.inode64 = Some(true),
            (b"inode32", None) => o.inode64 = Some(false),
            (
                b"huge",
                Some(b"never" | b"always" | b"within_size" | b"advise" | b"deny" | b"force"),
            ) => {}
            (b"mpol", Some(_)) => {}
            // Generic superblock flags (`vfs_parse_sb_flag`); mount(8) turns them into MS_* flags
            // anyway
            (
                b"ro" | b"rw" | b"sync" | b"async" | b"dirsync" | b"mand" | b"nomand" | b"lazytime"
                | b"nolazytime" | b"posixacl" | b"noposixacl" | b"silent" | b"loud",
                None,
            ) => {}
            _ => {
                let name = String::from_utf8_lossy(opt);
                crate::debug::log(format_args!("tmpfs: unknown parameter {name}"));
                return Err(Errno::EINVAL);
            }
        }
    }
    Ok(o)
}

/// An unsigned number, with the same prefixes as C's `strtoull(…, 0)` (`0x` hexadecimal, `0`
/// octal).
fn parse_num(s: &[u8]) -> Option<u64> {
    let (n, rest) = leading_num(s)?;
    rest.is_empty().then_some(n)
}

/// Linux's `memparse`: the number may be followed by K, M, G, T, P or E (case-insensitive).
/// Returns the rest.
fn memparse(s: &[u8]) -> Result<(u64, &[u8]), Errno> {
    let (n, rest) = leading_num(s).ok_or(Errno::EINVAL)?;
    let shift = match rest.first().map(u8::to_ascii_uppercase) {
        Some(b'K') => 10,
        Some(b'M') => 20,
        Some(b'G') => 30,
        Some(b'T') => 40,
        Some(b'P') => 50,
        Some(b'E') => 60,
        _ => return Ok((n, rest)),
    };
    Ok((n.saturating_mul(1 << shift), &rest[1..]))
}

/// The leading unsigned number and the rest.
fn leading_num(s: &[u8]) -> Option<(u64, &[u8])> {
    let (radix, digits) = match s {
        [b'0', b'x' | b'X', rest @ ..] => (16, rest),
        [b'0', rest @ ..] if !rest.is_empty() => (8, rest),
        _ => (10, s),
    };
    let end = digits
        .iter()
        .position(|&b| !(b as char).is_digit(radix))
        .unwrap_or(digits.len());
    let n = std::str::from_utf8(&digits[..end]).ok()?;
    let n = if n.is_empty() && radix == 8 {
        0
    } else {
        u64::from_str_radix(n, radix).ok()?
    };
    Some((n, &digits[end..]))
}

// ---- The new mount API (open_tree, move_mount, mount_setattr) ----

const OPEN_TREE_CLONE: u32 = 1;
const OPEN_TREE_CLOEXEC: u32 = crate::fd::oflags::O_CLOEXEC;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32 = 0x800;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_RECURSIVE: u32 = 0x8000;

/// move_mount flags (`MOVE_MOUNT_*`).
mod move_flags {
    pub const F_SYMLINKS: u32 = 1;
    pub const F_EMPTY_PATH: u32 = 4;
    pub const T_SYMLINKS: u32 = 0x10;
    pub const T_EMPTY_PATH: u32 = 0x40;
    pub const SET_GROUP: u32 = 0x100;
    /// All that 6.1 knows (`MOVE_MOUNT__MASK`).
    pub const MASK: u32 = 0x177;
}

/// Mount attributes (`MOUNT_ATTR_*`).
mod attr {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const ATIME: u64 = 0x70;
    pub const NOATIME: u64 = 0x10;
    pub const STRICTATIME: u64 = 0x20;
    pub const NODIRATIME: u64 = 0x80;
    pub const IDMAP: u64 = 0x10_0000;
    pub const NOSYMFOLLOW: u64 = 0x20_0000;
    pub const VALID: u64 =
        RDONLY | NOSUID | NODEV | NOEXEC | ATIME | NODIRATIME | IDMAP | NOSYMFOLLOW;
}

/// open_tree(2) (Linux 6.1's `open_tree`, `open_detached_copy`): without `OPEN_TREE_CLONE` it is
/// just an O_PATH fd; with it, it needs `CAP_SYS_ADMIN` and bind-mounts a copy of that path
/// (with the mounts below it under `AT_RECURSIVE`) in an anonymous mount namespace, mounted
/// nowhere; the fd points at its root, move_mount attaches it, and it is torn down if closed
/// without being attached. The source must be mounted in the caller's namespace (EINVAL).
pub(super) fn open_tree(cx: &mut Cx<'_>, dirfd: i32, path: u64, flags: u32) -> SysResult {
    let valid = AT_EMPTY_PATH
        | AT_NO_AUTOMOUNT
        | AT_RECURSIVE
        | AT_SYMLINK_NOFOLLOW
        | OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC;
    if flags & !valid != 0 || flags & (AT_RECURSIVE | OPEN_TREE_CLONE) == AT_RECURSIVE {
        return Err(Errno::EINVAL);
    }
    let clone = flags & OPEN_TREE_CLONE != 0;
    if clone && !may_mount(cx) {
        return Err(Errno::EPERM);
    }
    let (node, found) = walk_at(
        cx,
        (dirfd, path),
        flags & AT_EMPTY_PATH != 0,
        flags & AT_SYMLINK_NOFOLLOW == 0,
    )?;
    let o_path = crate::fd::oflags::O_PATH;
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    let attached_ns = matches!(node, Node::Pseudo(_, PseudoNode::NsFile(..)))
        && vfs
            .mount(node.mnt())
            .is_some_and(|m| m.fs == Fs::Nsfs && m.root == node);
    let file = if clone {
        let (ns, id) = if let Node::Pseudo(_, PseudoNode::NsFile(kind, ns_id)) = node
            && !attached_ns
        {
            // Namespace files not rooted at an attached nsfs mount (procfs, detached, or
            // NS_GET_USERNS/NS_GET_PARENT) live on Linux's internal `nsfs_mnt`: clone as an nsfs
            // mount pinning the namespace. `mnt_ns_loop` is checked on attach in `move_tree`.
            let pinned = super::ns::find(cx.kr(), Some(&vfs), kind, ns_id).ok_or(Errno::ENOENT)?;
            let ns = alloc_anon_ns(cx, &vfs)?;
            let id = vfs.clone_ns_mount(&node, pinned, ns.id);
            (ns, id)
        } else {
            if vfs.propagation(node.mnt()).unbindable {
                return Err(Errno::EINVAL);
            }
            // Linux 6.1's open_detached_copy skips check_mnt for nsfs files (`NSFS_MAGIC`).
            if !attached_ns {
                check_mnt(cx, &vfs, node.mnt())?;
            }
            if flags & AT_RECURSIVE == 0 && has_locked_children(&vfs, &view, &node) {
                return Err(Errno::EINVAL);
            }
            let dir = vfs.is_dir(&view, &node)?;
            let ns = alloc_anon_ns(cx, &vfs)?;
            let view = cx.view(&vfs);
            // Note the mounts inside the source before mounting (as in bind)
            let inside = if flags & AT_RECURSIVE != 0 {
                vfs.mounts()
            } else {
                Vec::new()
            };
            let plan = plan_copies(&vfs, &view, &inside, &node)?;
            let id = vfs.clone_mount(&node, found.filter(|_| !dir && !attached_ns), ns.id)?;
            vfs.add_copies(id, &plan);
            (ns, id)
        };
        let file = crate::fd::OpenFile::new(crate::fd::FileKind::Path(node.in_mount(id)), o_path);
        file.borrow_mut().tree = Some(ns);
        cx.shared.fast_changed();
        file
    } else {
        let path = if let Node::Pseudo(mnt, p @ PseudoNode::NsFile(..)) = &node
            && !attached_ns
        {
            Some(Rc::from(view.name(*mnt, p)))
        } else {
            vfs.found_path(&view, &cx.root(), &node, found.as_ref())
                .ok()
                .map(Rc::from)
        };
        crate::fd::OpenFile::with_path(crate::fd::FileKind::Path(node), o_path, path)
    };
    file.borrow_mut().pin_fuse_path(&vfs)?;
    let cloexec = flags & OPEN_TREE_CLOEXEC != 0;
    Ok(cx.install_fd(file, cloexec)? as u64)
}

/// move_mount(2) (Linux 6.1): needs `CAP_SYS_ADMIN`; source and target are each resolved from a
/// directory fd (with `F_EMPTY_PATH`/`T_EMPTY_PATH` they may be the fd itself, with
/// `F_SYMLINKS`/`T_SYMLINKS` the last symlink is followed), and the move works as `MS_MOVE`
/// ([`move_tree`]). With `MOVE_MOUNT_SET_GROUP` it instead copies `from`'s peer/slave sharing
/// group to private mount `to` (Linux 6.1's `do_set_group`).
pub(super) fn sys_move_mount(
    cx: &mut Cx<'_>,
    from: (i32, u64),
    to: (i32, u64),
    flags: u32,
) -> SysResult {
    use move_flags::*;
    if !may_mount(cx) {
        return Err(Errno::EPERM);
    }
    if flags & !MASK != 0 {
        return Err(Errno::EINVAL);
    }
    let (src, _) = walk_at(cx, from, flags & F_EMPTY_PATH != 0, flags & F_SYMLINKS != 0)?;
    let target = walk_at(cx, to, flags & T_EMPTY_PATH != 0, flags & T_SYMLINKS != 0)?;
    if flags & SET_GROUP != 0 {
        return set_group(cx, &src, &target.0);
    }
    move_tree(cx, &src, target)
}

/// `move_mount(MOVE_MOUNT_SET_GROUP)` (Linux 6.1's `do_set_group`): copies the propagation peer
/// group (or slave relationship, including shared-to-slave across different owning user
/// namespaces) from attached shared/slave mount `src` to attached private mount `target` on the
/// same filesystem instance whose root lies at or under `src`'s root.
fn set_group(cx: &mut Cx<'_>, src: &Node, target: &Node) -> SysResult {
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    let from = vfs
        .mount_root(src)
        .and_then(|id| vfs.mount(id))
        .ok_or(Errno::EINVAL)?;
    let to = vfs
        .mount_root(target)
        .and_then(|id| vfs.mount(id))
        .ok_or(Errno::EINVAL)?;
    let (Some(from_ns), Some(to_ns)) = (vfs.find_ns(from.ns), vfs.find_ns(to.ns)) else {
        return Err(Errno::EINVAL);
    };
    if from_ns.anon || to_ns.anon {
        return Err(Errno::EINVAL);
    }
    if !cx.cred().ns_capable(&from_ns.owner, cap::SYS_ADMIN)
        || !cx.cred().ns_capable(&to_ns.owner, cap::SYS_ADMIN)
    {
        return Err(Errno::EPERM);
    }
    if from.fs != to.fs || from.dev != to.dev {
        return Err(Errno::EINVAL);
    }
    let to_in_from = to.root.clone().in_mount(from.id);
    if to_in_from != from.root && !vfs.is_under(&view, &to_in_from, &from.root) {
        return Err(Errno::EINVAL);
    }
    if to.prop.group != 0 || to.prop.master != 0 {
        return Err(Errno::EINVAL);
    }
    if from.prop.group == 0 && from.prop.master == 0 {
        return Err(Errno::EINVAL);
    }
    let prop = if from_ns.owner.id == to_ns.owner.id {
        from.prop.of_bind()
    } else {
        from.prop.of_slave_copy()
    };
    vfs.set_mount_prop(to.id, prop);
    cx.shared.fast_changed();
    Ok(0)
}

/// mount_setattr(2) (Linux 6.1's `mount_setattr`, `build_mount_kattr`): changes the flags of a
/// mount (with those below it under `AT_RECURSIVE`). `struct mount_attr` is at least 32 bytes,
/// and anything beyond must be 0; changing the access time requires giving the whole
/// `MOUNT_ATTR__ATIME` in attr_clr as well. A propagation type is set after the flags, as
/// `mount_setattr_commit` does. Idmapped mounts (`MOUNT_ATTR_IDMAP`) are
/// EINVAL after the userns fd is checked, the same as for a filesystem that does not support
/// them.
pub(super) fn mount_setattr(
    cx: &mut Cx<'_>,
    (dirfd, path): (i32, u64),
    flags: u32,
    uattr: u64,
    size: usize,
) -> SysResult {
    if flags & !(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT) != 0 {
        return Err(Errno::EINVAL);
    }
    if size > 4096 {
        return Err(Errno::E2BIG);
    }
    if size < 32 {
        return Err(Errno::EINVAL);
    }
    if !may_mount(cx) {
        return Err(Errno::EPERM);
    }
    let mut raw = vec![0u8; size];
    cx.mm()
        .read(crate::uaccess::UserSlice::new(uattr, size), &mut raw)?;
    if raw[32..].iter().any(|&b| b != 0) {
        return Err(Errno::E2BIG);
    }
    let field = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
    let (set, clr, propagation, userns_fd) = (field(0), field(1), field(2), field(3));
    if set == 0 && clr == 0 && propagation == 0 {
        return Ok(0);
    }
    if ![0, MS_UNBINDABLE, MS_PRIVATE, MS_SLAVE, MS_SHARED].contains(&propagation)
        || (set | clr) >> 32 != 0
        || (set | clr) & !attr::VALID != 0
    {
        return Err(Errno::EINVAL);
    }
    // Access time: to change it, attr_clr gives the whole MOUNT_ATTR__ATIME and attr_set one of
    // the three
    let atime = if clr & attr::ATIME != 0 {
        if clr & attr::ATIME != attr::ATIME {
            return Err(Errno::EINVAL);
        }
        match set & attr::ATIME {
            0 => Some(ms::RELATIME),
            attr::NOATIME => Some(ms::NOATIME),
            attr::STRICTATIME => Some(0),
            _ => return Err(Errno::EINVAL),
        }
    } else if set & attr::ATIME != 0 {
        return Err(Errno::EINVAL);
    } else {
        None
    };
    if (set | clr) & attr::IDMAP != 0 {
        if clr & attr::IDMAP != 0 || userns_fd > i32::MAX as u64 {
            return Err(Errno::EINVAL);
        }
        let file = cx.fds().get(userns_fd as i32).map_err(|_| Errno::EBADF)?;
        let ns = match &file.borrow().kind {
            crate::fd::FileKind::Proc {
                ns: Some(NsRef::User(ns)),
                ..
            } => ns.clone(),
            _ => return Err(Errno::EINVAL),
        };
        if Rc::ptr_eq(&ns, &crate::cred::UserNs::init()) {
            return Err(Errno::EPERM);
        }
        return Err(Errno::EINVAL);
    }
    let (node, _) = walk_at(
        cx,
        (dirfd, path),
        flags & AT_EMPTY_PATH != 0,
        flags & AT_SYMLINK_NOFOLLOW == 0,
    )?;
    let vfs = cx.vfs()?;
    let id = vfs.mount_root(&node).ok_or(Errno::EINVAL)?;
    // In the caller's namespace, or the root of a tree copied by open_tree and not yet attached
    // (Linux 6.1's do_mount_setattr: exempt only a mount without a parent in an anonymous ns)
    if anon_root_ns(&vfs, id).is_none() {
        check_mnt(cx, &vfs, id)?;
    }
    let bit = |a: u64, m: u64| if set & a != 0 { m } else { 0 };
    let set_ms = bit(attr::RDONLY, ms::RDONLY)
        | bit(attr::NOSUID, ms::NOSUID)
        | bit(attr::NODEV, ms::NODEV)
        | bit(attr::NOEXEC, ms::NOEXEC)
        | bit(attr::NODIRATIME, ms::NODIRATIME)
        | bit(attr::NOSYMFOLLOW, ms::NOSYMFOLLOW);
    let cleared = |a: u64, m: u64| if clr & a != 0 { m } else { 0 };
    let clr_ms = cleared(attr::RDONLY, ms::RDONLY)
        | cleared(attr::NOSUID, ms::NOSUID)
        | cleared(attr::NODEV, ms::NODEV)
        | cleared(attr::NOEXEC, ms::NOEXEC)
        | cleared(attr::NODIRATIME, ms::NODIRATIME)
        | cleared(attr::NOSYMFOLLOW, ms::NOSYMFOLLOW);
    let recursive = flags & AT_RECURSIVE != 0;
    let changed = |m: &Mount| {
        let mut f = (m.flags & !clr_ms) | set_ms;
        if let Some(a) = atime {
            f = (f & !(ms::RELATIME | ms::NOATIME)) | a;
        }
        f
    };
    // Every mount is checked before any changes (mount_setattr_prepare): locked flags stay, and
    // a mount with files open for writing cannot become read-only (EBUSY, mnt_hold_writers);
    // flags and propagation then apply in one pass with a single fast-path rebuild.
    vfs.set_mount_attrs(
        id,
        recursive,
        changed,
        set_ms & ms::RDONLY != 0,
        || writers(cx.kr()),
        propagation_type(propagation),
    )?;
    cx.shared.fast_changed();
    Ok(0)
}

/// A path argument of the new mount API (Linux 6.1's `user_path_at`): resolves `path` from
/// `dirfd` (with `empty` it may be empty, meaning `dirfd` itself), following mount points only
/// during component lookups (`Vfs::walk`), not when the target is reached without a lookup (an
/// `AT_EMPTY_PATH` fd, `.`, `/`, or a magic link). Returns the node and the dentry it was found at.
fn walk_at(
    cx: &Cx<'_>,
    (dirfd, path): (i32, u64),
    empty: bool,
    follow: bool,
) -> Result<(Node, Option<Dentry>), Errno> {
    let path = cx.mm().read_cstr(path, super::PATH_MAX - 1)?;
    let vfs = cx.vfs()?;
    if path.is_empty() {
        if !empty {
            return Err(Errno::ENOENT);
        }
        if dirfd == AT_FDCWD {
            return Ok((cx.cwd(), None));
        }
        let file = cx.fds().get(dirfd)?;
        let f = file.borrow();
        let node = f.node().ok_or(Errno::EBADF)?;
        let view = cx.view(&vfs);
        let dir = vfs.is_dir(&view, &node).unwrap_or(true);
        let at = f.current_dentry().filter(|_| !dir && !f.dentry_unlinked());
        return Ok((node, at));
    }
    let start = start_dir(cx, dirfd, &path)?;
    vfs.walk(
        &cx.view(&vfs),
        &cx.cred(),
        &cx.root(),
        &start,
        &path,
        follow,
    )
}

// ---- pivot_root and umount2 ----

/// pivot_root(2) (Linux 6.1's `pivot_root`): the mount of `new_root` takes the place of the mount
/// the caller's root directory is in, and the old root is mounted on `put_old`; processes whose
/// root directory or cwd was the old root directory switch to `new_root` (`chroot_fs_refs`).
pub(super) fn pivot_root(cx: &mut Cx<'_>, new_root: u64, put_old: u64) -> SysResult {
    if !may_mount(cx) {
        return Err(Errno::EPERM);
    }
    // Each path is looked up as a directory before the next (LOOKUP_DIRECTORY): a file as new_root
    // is ENOTDIR whatever put_old is
    let dir = |cx: &mut Cx<'_>, path: u64| {
        let path = read_path(cx, path)?;
        let node = lookup_at(cx, AT_FDCWD, &path, true)?;
        let vfs = cx.vfs()?;
        if !vfs.is_dir(&cx.view(&vfs), &node)? {
            return Err(Errno::ENOTDIR);
        }
        Ok(node)
    };
    let new = dir(cx, new_root)?;
    let old = dir(cx, put_old)?;
    let root = cx.root();
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    // When something is mounted on put_old, use the topmost one (lock_mount)
    let old = vfs.mounted(old);
    check_mnt(cx, &vfs, new.mnt())?;
    check_mnt(cx, &vfs, root.mnt())?;
    check_mnt(cx, &vfs, old.mnt())?;
    let (Some(new_mnt), Some(root_mnt)) = (vfs.mount(new.mnt()), vfs.mount(root.mnt())) else {
        return Err(Errno::EINVAL);
    };
    // Nothing shared may be involved: put_old's mount, or the parents of new_root and of the root
    let shared = |id: Option<MountId>| id.is_some_and(|id| vfs.propagation(id).group != 0);
    if shared(Some(old.mnt())) || shared(new_mnt.parent()) || shared(root_mnt.parent()) {
        return Err(Errno::EINVAL);
    }
    if new_mnt.locks & lock::MOUNT != 0 {
        return Err(Errno::EINVAL);
    }
    // Deleted directories (d_unlinked)
    for node in [&new, &old] {
        if let Node::Store(_, ino) = node
            && vfs.store().stat(*ino)?.nlink == 0
        {
            return Err(Errno::ENOENT);
        }
    }
    if new_mnt.id == root_mnt.id || old.mnt() == root_mnt.id {
        return Err(Errno::EBUSY);
    }
    // The root directory and new_root must both be mount roots, put_old must be below new_root,
    // and new_root must be below the root directory
    if root_mnt.root != root
        || new_mnt.root != new
        || !vfs.is_under(&view, &old, &new)
        || !vfs.is_under(&view, &new, &root)
    {
        return Err(Errno::EINVAL);
    }
    vfs.move_mount(new_mnt.id, None);
    vfs.move_mount(root_mnt.id, Some((old, None)));
    vfs.move_mount(new_mnt.id, root_mnt.point.map(|point| (point, root_mnt.at)));
    // The lock moves with the root: the old root, now on put_old, can be unmounted (how
    // sandboxes drop it), the new one cannot
    if root_mnt.locks & lock::MOUNT != 0 {
        vfs.update_mount(new_mnt.id, |m| m.locks |= lock::MOUNT);
        vfs.update_mount(root_mnt.id, |m| m.locks &= !lock::MOUNT);
    }
    for task in cx.kr().tasks.values() {
        let res = task.res.borrow();
        let mut fs = res.fs.borrow_mut();
        if fs.root == root {
            fs.set_root(new.clone());
        }
        if fs.cwd == root {
            fs.set_cwd(new.clone());
        }
    }
    cx.shared.fast_changed();
    Ok(0)
}

pub(super) fn umount2(cx: &mut Cx<'_>, target: u64, flags: u32) -> SysResult {
    if flags & !(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW) != 0 {
        return Err(Errno::EINVAL);
    }
    let path = read_path(cx, target)?;
    let start = start_dir(cx, AT_FDCWD, &path)?;
    let vfs = cx.vfs()?;
    let node = vfs.resolve_mountpoint(
        &cx.view(&vfs),
        &cx.cred(),
        &cx.root(),
        &start,
        &path,
        flags & UMOUNT_NOFOLLOW == 0,
    )?;
    if !may_mount(cx) || (flags & MNT_FORCE != 0 && !cx.cred().capable(cap::SYS_ADMIN)) {
        return Err(Errno::EPERM);
    }
    // Paths such as `.` and the cwd also unmount what is mounted on them (LOOKUP_MOUNTPOINT)
    let node = vfs.mounted(node);
    let id = vfs.mount_root(&node).ok_or(Errno::EINVAL)?;
    check_mnt(cx, &vfs, id)?;
    // A mount locked in place stays (Linux's can_umount)
    if vfs.mount(id).is_some_and(|m| m.locks & lock::MOUNT != 0) {
        return Err(Errno::EINVAL);
    }
    let own_root = id == cx.root().mnt();
    let detach = flags & MNT_DETACH != 0;
    if flags & MNT_EXPIRE != 0 {
        if own_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return Err(Errno::EINVAL);
        }
        if busy(cx, &vfs, id) {
            return Err(Errno::EBUSY);
        }
        // The first time only marks it; if nobody has accessed it since (clearing the mark in
        // Vfs::touch_mount), the next time unmounts it
        if !vfs.mount(id).is_some_and(|m| m.expiring) {
            vfs.set_expiring(id);
            return Err(Errno::EAGAIN);
        }
    }
    // Linux's fuse_umount_begin aborts the instance even if an open file keeps the mount busy.
    if flags & MNT_FORCE != 0
        && let Node::Fuse(_, root) = node
    {
        vfs.fuse().conn_of(root)?.borrow_mut().abort();
    }
    // The root of a mount tree cannot be unmounted; the mount the caller's root directory is in
    // can only be unmounted with MNT_DETACH (without it, Linux remounts the root filesystem
    // read-only)
    if vfs.mount(id).is_some_and(|m| m.point.is_none()) {
        return Err(if detach { Errno::EINVAL } else { Errno::EBUSY });
    }
    if !detach && (own_root || busy(cx, &vfs, id) || vfs.propagated_busy(id, &in_use(cx.kr()))) {
        return Err(Errno::EBUSY);
    }
    vfs.umount_tree(id);
    vfs.collect(&in_use(cx.kr()));
    cx.shared.fast_changed();
    Ok(0)
}

/// Mount `id` is in use: other mounts are mounted inside it, or a process's root directory, cwd
/// or open file is in it (terminals opened through paths in devpts count too).
fn busy(cx: &Cx<'_>, vfs: &Vfs, id: MountId) -> bool {
    !vfs.children(id).is_empty() || in_use(cx.kr()).contains(&id)
}

/// When a thread exits: a mount namespace no longer used (the last process using it exited)
/// takes its mounts down, and the detached mounts whose last use were the thread's files or
/// directories go ([`collect_released`]).
pub(crate) fn collect_unused(k: &crate::kernel::Kernel, vfs: &Vfs) {
    super::fs::evict_unlinked_tmpfs(k, vfs);
    if vfs.released_detached() || vfs.has_dead_ns() {
        collect_now(k, vfs);
    }
}

/// At the end of a syscall: a detached mount this thread let go of the last use of, or an
/// unattached anonymous mount namespace whose last open_tree fd closed, goes
/// ([`crate::vfs::released`]; a lazily unmounted FUSE mount then aborts its connection, so its
/// daemon exits).
pub(super) fn collect_released(k: &crate::kernel::Kernel, vfs: &Vfs) {
    super::fs::evict_unlinked_tmpfs(k, vfs);
    if vfs.released_detached() || vfs.has_dead_ns() {
        collect_now(k, vfs);
    }
}

/// At the end of a syscall, once enough overlay names have been removed or the live node cache
/// outgrows its bound: drops removed and excess unused nodes nothing can use any more
/// ([`overlay::Overlays::sweep`]). Kept are the nodes processes' roots and cwds are, mounts'
/// roots, points and recorded file-mount directories (`Mount::at`, `Mount::root_at`), and inotify
/// watches; open files and the programs processes run (`/proc/<pid>/exe`) hold their own
/// ([`overlay::Hold`]). A system call another thread is in may hold nodes it looked up while it
/// waits, so it keeps those removed or touched since it began, unless it waits only on files it
/// holds ([`waits_on_files_only`]): a long wait4, epoll_wait or read keeps nothing.
pub(super) fn sweep_overlays(cx: &Cx<'_>) {
    let Ok(vfs) = cx.vfs() else {
        return;
    };
    if !vfs.overlay().wants_sweep() {
        return;
    }
    let ovl = |n: &Node| match n {
        Node::Overlay(_, o) => Some(*o),
        _ => None,
    };
    let k = cx.kr();
    let mut keep = HashSet::new();
    let mut oldest = u64::MAX;
    for task in k.tasks.values() {
        let (began, nr) = task.syscall.get();
        if began != 0 && !Rc::ptr_eq(task, cx.task) && !waits_on_files_only(nr) {
            oldest = oldest.min(began);
        }
        // Something is borrowed (not expected between syscalls): another time
        let Ok(res) = task.res.try_borrow() else {
            return;
        };
        let Ok(fs) = res.fs.try_borrow() else {
            return;
        };
        keep.extend(ovl(&fs.root));
        keep.extend(ovl(&fs.cwd));
    }
    keep.extend(vfs.mount_nodes().iter().filter_map(ovl));
    let Ok(inotify) = k.inotify.try_borrow() else {
        return;
    };
    keep.extend(inotify.watched().filter_map(overlay::of_key));
    drop(inotify);
    vfs.sweep_overlays(&keep, oldest);
}

/// Whether system call `nr` waits (with the BKL released) only on files it holds or on nothing,
/// never holding a node it looked up by path: reads and writes, polls and epoll, waits for
/// children and signals, sleeps and futexes, locks, socket receives and accepts, message queues
/// and semaphores, AIO events.
fn waits_on_files_only(nr: u64) -> bool {
    // read to tee (63–77) are reads and writes, sendfile, pselect6, ppoll, signalfd4 and splice
    (63..=77).contains(&nr)
        || [
            4, 22, 25, 29, 32, 82, 83, 95, 98, 101, 115, 133, 137, 182, 183, 188, 189, 192, 193,
            202, 207, 212, 242, 243, 260, 285, 292, 441, 449,
        ]
        .contains(&nr)
}

fn collect_now(k: &crate::kernel::Kernel, vfs: &Vfs) {
    match try_in_use(k) {
        Some(used) => vfs.collect(&used),
        // Something is borrowed (not expected between syscalls): retry on the next pass on any
        // thread
        None => vfs.defer_collect(),
    }
}

/// Mounts held by tasks and by files being transferred over AF_UNIX sockets.
fn in_use(k: &crate::kernel::Kernel) -> HashSet<MountId> {
    try_in_use(k).expect("mount holders are available during unmount")
}

/// [`in_use`], or None when a holder is borrowed during teardown.
fn try_in_use(k: &crate::kernel::Kernel) -> Option<HashSet<MountId>> {
    let mut used = HashSet::new();
    let mut seen_mm = HashSet::new();
    for task in k.tasks.values() {
        let res = task.res.try_borrow().ok()?;
        {
            let fs = res.fs.try_borrow().ok()?;
            used.insert(fs.root.mnt());
            used.insert(fs.cwd.mnt());
        }
        if seen_mm.insert(Rc::as_ptr(&res.mm) as usize) {
            let mm = res.mm.try_borrow().ok()?;
            mm.mapped_mounts(&mut used);
        }
        let fds = res.fds.try_borrow().ok()?;
        for file in fds.open_fds().into_iter().filter_map(|fd| fds.get(fd).ok()) {
            note_file_mount(&file, &mut used)?;
        }
    }
    for file in crate::unix::try_inflight_files(k)? {
        note_file_mount(&file, &mut used)?;
    }
    for file in k.loops.try_backing_files()? {
        note_file_mount(&file, &mut used)?;
    }
    for group in k.groups.values() {
        let g = group.try_borrow().ok()?;
        if !g.threads.is_empty()
            && let Some(exe) = &g.exe
            && let Some(mnt) = exe.mnt()
        {
            used.insert(mnt);
        }
    }
    Some(used)
}

fn note_file_mount(file: &crate::fd::FileRef, used: &mut HashSet<MountId>) -> Option<()> {
    let file = file.try_borrow().ok()?;
    if let Some(node) = file.node() {
        used.insert(node.mnt());
    } else if matches!(file.kind, FileKind::MessageQueue(_)) && !file.pseudo {
        used.insert(file.mnt);
    }
    if let FileKind::Pty(end) = &file.kind
        && end.pin
    {
        used.insert(end.mnt);
    }
    Some(())
}

/// The mounts with files open for writing through them (Linux's `mnt_get_writers`): regular,
/// FUSE and synthetic files opened with write access in some process's fd table, or backing a loop
/// device opened writable; devices, FIFOs and sockets do not count (`special_file`), nor do
/// memfds, which Linux keeps on an internal tmpfs (here they have the store's root mount).
fn writers(k: &crate::kernel::Kernel) -> HashSet<MountId> {
    let writes = |f: &crate::fd::OpenFile| {
        f.writable()
            && match &f.kind {
                FileKind::Regular { ino, .. } => !k.seals.contains_key(ino),
                FileKind::Proc { .. } | FileKind::Fuse(_) => true,
                _ => false,
            }
    };
    let mut mounts = HashSet::new();
    for task in k.tasks.values() {
        let res = task.res.borrow();
        let fds = res.fds.borrow();
        for file in fds.open_fds().into_iter().filter_map(|fd| fds.get(fd).ok()) {
            let f = file.borrow();
            if writes(&f)
                && let Some(node) = f.node()
            {
                mounts.insert(node.mnt());
            }
        }
    }
    for file in k.loops.backing_files() {
        let f = file.borrow();
        if writes(&f)
            && let Some(node) = f.node()
        {
            mounts.insert(node.mnt());
        }
    }
    mounts
}

/// Whether instance `dev` cannot turn read-only (6.1's `sb_prepare_remount_readonly`, EBUSY): a
/// file of it is open for writing through any of its mounts, attached or detached ([`writers`]), or
/// a file of it whose last name was removed is still in use (Linux's `s_remove_count`, inodes
/// with no links not yet evicted): open (in an fd table, in flight in an AF_UNIX message, or
/// backing a loop device), mapped in an address space (store, tmpfs, overlay, or FUSE), a task's
/// root or cwd, or a running program. memfds do not count (as in [`writers`]).
fn sb_busy(k: &crate::kernel::Kernel, vfs: &Vfs, dev: u64) -> bool {
    let of_dev = |mnt: MountId| vfs.mount_dev(mnt) == Some(dev);
    if writers(k).into_iter().any(of_dev) {
        return true;
    }
    let removed = |node: &Node| {
        let gone = match node {
            Node::Store(_, ino) => {
                !k.seals.contains_key(ino) && vfs.store().attrs(*ino).is_ok_and(|st| st.nlink == 0)
            }
            Node::Overlay(_, o) => !vfs.overlay().linked(*o),
            Node::Fuse(_, f) => vfs.fuse().get(*f).is_some_and(|n| n.unlinked),
            Node::Pseudo(..) => false,
        };
        gone && of_dev(node.mnt())
    };
    let file_removed = |file: &crate::fd::FileRef| {
        file.try_borrow()
            .is_ok_and(|f| f.node().is_some_and(|n| removed(&n)))
    };
    let mut files = k.open_files();
    files.extend(crate::unix::inflight_files(k));
    files.extend(k.loops.backing_files());
    if files.iter().any(file_removed) {
        return true;
    }
    let mut seen_mm = HashSet::new();
    let mut mapped = Vec::new();
    let mut mapped_fuse = Vec::new();
    for task in k.tasks.values() {
        let res = task.res.borrow();
        {
            let fs = res.fs.borrow();
            if removed(&fs.root) || removed(&fs.cwd) {
                return true;
            }
        }
        if seen_mm.insert(Rc::as_ptr(&res.mm) as usize) {
            let mm = res.mm.borrow();
            mapped.clear();
            mapped_fuse.clear();
            mm.mapped_file_inos(&mut mapped, &mut mapped_fuse);
            if mapped
                .iter()
                .any(|&(mnt, ino)| removed(&Node::Store(mnt, ino)))
                || mapped_fuse.iter().any(file_removed)
            {
                return true;
            }
        }
        let exe = k
            .groups
            .get(&task.tgid)
            .and_then(|g| g.borrow().exe.clone());
        if exe.is_some_and(|e| {
            e.node
                .is_some_and(|(mnt, ino)| removed(&Node::Store(mnt, ino)))
                || e.ovl
                    .as_ref()
                    .is_some_and(|(mnt, o, _)| removed(&Node::Overlay(*mnt, *o)))
        }) {
            return true;
        }
    }
    false
}

// ---- Shared helpers ----

/// The mounts below `root` in the mount `root` is in (those in `snapshot`), to be copied the same
/// way into a new mount (Linux's `copy_tree`; [`Vfs::add_copies`] adds them): each after its
/// parent, in the order recursion would visit them, with the index of its parent in the plan
/// (None for a mount directly in the new one). The mounts are indexed by parent first, so planning
/// n copies is O(n); a scan of the whole snapshot per mount made a recursive bind of a tree onto
/// itself quadratic, and each such bind holds the BKL.
fn plan_copies<'a>(
    vfs: &Vfs,
    ps: &dyn Pseudo,
    snapshot: &'a [Mount],
    root: &Node,
) -> Result<Vec<(Option<usize>, &'a Mount)>, Errno> {
    let mut children: HashMap<MountId, Vec<&Mount>> = HashMap::new();
    for m in snapshot {
        if let Some(parent) = m.parent() {
            children.entry(parent).or_default().push(m);
        }
    }
    // The children of mount `of` to copy: those with a point, mounted under `root` (a mount on a
    // file searches upwards from the directory it was mounted through), except unbindable ones and
    // what is below them (copy_tree); an unbindable one locked in place cannot be left out without
    // uncovering what it hides (EPERM)
    let locked_unbindable = std::cell::Cell::new(false);
    let below = |of: MountId, root: &Node| -> Vec<&'a Mount> {
        children
            .get(&of)
            .into_iter()
            .flatten()
            .copied()
            .filter(|c| {
                c.point.as_ref().is_some_and(|point| {
                    let from = c.at.as_ref().map_or(point, |(dir, _)| dir);
                    point == root || vfs.is_under(ps, from, root)
                })
            })
            .filter(|c| {
                if c.prop.unbindable && c.locks & lock::MOUNT != 0 {
                    locked_unbindable.set(true);
                }
                !c.prop.unbindable
            })
            .collect()
    };
    let mut plan = Vec::new();
    let mut stack: Vec<(Option<usize>, &Mount)> = below(root.mnt(), root)
        .into_iter()
        .rev()
        .map(|c| (None, c))
        .collect();
    while let Some((parent, c)) = stack.pop() {
        let index = plan.len();
        plan.push((parent, c));
        stack.extend(
            below(c.id, &c.root)
                .into_iter()
                .rev()
                .map(|g| (Some(index), g)),
        );
    }
    if locked_unbindable.get() {
        return Err(Errno::EPERM);
    }
    Ok(plan)
}

/// Before a tree of `size` mounts is attached on `place`: where it is to be copied as well
/// ([`Vfs::propagation_targets`]), after checking that the namespace of the mount `place` is in
/// (gaining `own` mounts, 0 when the tree is in it already) and the namespace of every target
/// (gaining a copy of the tree for each) stay within `fs.mount-max` (Linux's `count_mounts` in
/// `attach_recursive_mnt` and `propagate_one`), otherwise ENOSPC with nothing changed.
fn plan_attach(
    cx: &Cx<'_>,
    vfs: &Vfs,
    place: (&Node, Option<&Dentry>),
    own: usize,
    size: usize,
) -> Result<Vec<Target>, Errno> {
    let targets = vfs.propagation_targets(&cx.view(vfs), place);
    let mut added: HashMap<u64, usize> = HashMap::new();
    if let Some(ns) = vfs.mount_ns(place.0.mnt()) {
        *added.entry(ns).or_default() += own;
    }
    for t in &targets {
        *added.entry(t.ns).or_default() += size;
    }
    if vfs.any_ns_over(&added, cx.kr().mount_max) {
        return Err(Errno::ENOSPC);
    }
    Ok(targets)
}

/// Mount `id` was attached where [`plan_attach`] planned `targets`: copies of its tree go to
/// each ([`Vfs::propagate`]), locked in namespaces not owned by the caller's mount namespace's
/// owner.
fn propagate(cx: &Cx<'_>, vfs: &Vfs, id: MountId, targets: &[Target]) {
    let owner = cx.t.fs.borrow().mnt_ns.owner.id;
    vfs.propagate(id, targets, owner);
    cx.shared.fast_changed();
}

/// Moves the mount rooted at `src` onto `target` (Linux's `do_move_mount`, shared by `MS_MOVE` and
/// move_mount): `src` must be the root of a mount attached in the caller's namespace, or the root
/// of a tree copied by open_tree and not yet attached (it is attached, and the tree enters the
/// caller's namespace). The target must be in the caller's namespace, must be a directory if and
/// only if `src` is (EINVAL), and must not be inside the mount being moved (ELOOP).
fn move_tree(cx: &mut Cx<'_>, src: &Node, (target, at): (Node, Option<Dentry>)) -> SysResult {
    let vfs = cx.vfs()?;
    let view = cx.view(&vfs);
    // Lift target to the topmost mount (Linux's lock_mount in do_move_mount): mount(2)'s MS_MOVE
    // already lifted it, while move_mount(2)'s walk_at leaves no-lookup targets unlifted.
    let top = vfs.mounted(target.clone());
    let at = at.filter(|_| top == target);
    let target = top;
    // The root of a mount tree is also mounted (on the invisible rootfs); when it is moved the
    // target is always inside it, which is the ELOOP below
    let id = vfs.mount_root(src).ok_or(Errno::EINVAL)?;
    let anon_ns = anon_root_ns(&vfs, id);
    if anon_ns.is_none() {
        check_mnt(cx, &vfs, id)?;
    }
    check_mnt(cx, &vfs, target.mnt())?;
    if vfs.mount(id).is_some_and(|m| m.locks & lock::MOUNT != 0) {
        return Err(Errno::EINVAL);
    }
    if vfs.is_dir(&view, src)? != vfs.is_dir(&view, &target)? {
        return Err(Errno::EINVAL);
    }
    may_mount_on(&target)?;
    // A mount in a shared parent does not move, nor a tree holding an unbindable mount onto a
    // shared mount (do_move_mount)
    let parent = vfs.mount(id).and_then(|m| m.parent());
    if anon_ns.is_none() && parent.is_some_and(|p| vfs.propagation(p).group != 0) {
        return Err(Errno::EINVAL);
    }
    if vfs.propagation(target.mnt()).group != 0 && vfs.subtree_has_unbindable(id) {
        return Err(Errno::EINVAL);
    }
    // Prevent mount-namespace reference cycles (Linux 6.1's mnt_ns_loop in do_move_mount): a mount
    // pinning a mount namespace can only be attached into namespaces strictly older than it.
    let subtree = vfs.subtree(id);
    let min_pinned = subtree
        .iter()
        .filter_map(|&mid| match vfs.mount(mid)?.pin {
            Some(NsRef::Mnt(pinned)) => Some(pinned.id),
            _ => None,
        })
        .min();
    let caller_ns = cx.mnt_ns();
    if min_pinned.is_some_and(|p| caller_ns >= p) {
        return Err(Errno::EINVAL);
    }
    // An attached tree is in the namespace already; its copies count anyway
    let targets = if let Some(ns_id) = anon_ns {
        let size = vfs.count_in(ns_id);
        plan_attach(cx, &vfs, (&target, at.as_ref()), size, size)?
    } else {
        if vfs.is_under(&view, &target, src) {
            return Err(Errno::ELOOP);
        }
        plan_attach(cx, &vfs, (&target, at.as_ref()), 0, subtree.len())?
    };
    if min_pinned.is_some_and(|p| targets.iter().any(|t| t.ns >= p)) {
        return Err(Errno::EINVAL);
    }
    if let Some(ns_id) = anon_ns {
        vfs.attach_tree(id, (target, at), cx.mnt_ns());
        // Free the emptied anonymous namespace immediately (Linux 6.1's do_move_mount calls
        // put_mnt_ns) so it stops counting against max_mnt_namespaces while the open_tree fd
        // stays open
        release_anon_ns(cx.kr(), ns_id);
    } else {
        vfs.move_mount(id, Some((target, at)));
    }
    vfs.attached(id);
    propagate(cx, &vfs, id, &targets);
    Ok(0)
}

/// Allocates and accounts an anonymous mount namespace for `open_tree(OPEN_TREE_CLONE)`
/// (`alloc_mnt_ns` counts against `max_mnt_namespaces`).
fn alloc_anon_ns(cx: &mut Cx<'_>, vfs: &Vfs) -> Result<Rc<MntNs>, Errno> {
    let owner = cx.t.fs.borrow().mnt_ns.owner.clone();
    let euid = cx.cred().euid;
    super::ns::check_counts(cx.k(), &[Counted::Mnt], &owner, euid)?;
    let ns = vfs.anon_ns(owner.clone());
    super::ns::count(cx.k(), Counted::Mnt, &owner, euid, ns.clone());
    Ok(ns)
}

/// If `id` is the parentless root of an unattached anonymous (`open_tree`) namespace, returns
/// that namespace's id (Linux 6.1's `is_anon_ns` + `!mnt_has_parent`).
fn anon_root_ns(vfs: &Vfs, id: MountId) -> Option<u64> {
    let m = vfs.mount(id)?;
    (m.point.is_none() && vfs.find_ns(m.ns).is_some_and(|ns| ns.anon)).then_some(m.ns)
}

/// Drops the anonymous mount namespace `ns_id` from any open `open_tree(OPEN_TREE_CLONE)` file
/// once its mounts have been attached into a real namespace.
fn release_anon_ns(k: &crate::kernel::Kernel, ns_id: u64) {
    let mut files = k.open_files();
    files.extend(crate::unix::inflight_files(k));
    for file in files {
        if let Ok(mut f) = file.try_borrow_mut()
            && f.tree.as_ref().is_some_and(|ns| ns.id == ns_id)
        {
            f.tree = None;
        }
    }
}

/// Whether mounts may be changed (Linux's `may_mount`): `CAP_SYS_ADMIN` in the owner (a user
/// namespace) of the mount namespace.
fn may_mount(cx: &Cx<'_>) -> bool {
    let owner = cx.t.fs.borrow().mnt_ns.owner.clone();
    cx.cred().ns_capable(&owner, cap::SYS_ADMIN)
}

/// Mount points that must be ENOENT (Linux's `lock_mount`): nameless open files such as deleted
/// files and pipes reached through `/proc/<pid>/fd/<n>` or `exe`; the entries in `/proc/<pid>/fd`
/// and `fdinfo` themselves (reached through an `O_PATH` fd pointing at them; not usable as mount
/// points since Linux 6.12, LTP's mount08).
fn may_mount_on(target: &Node) -> Result<(), Errno> {
    match target {
        Node::Pseudo(
            _,
            PseudoNode::OpenFd(..)
            | PseudoNode::OpenExe(_)
            | PseudoNode::Fd(..)
            | PseudoNode::FdInfo(..),
        ) => Err(Errno::ENOENT),
        _ => Ok(()),
    }
}

/// Mount `id` is attached to the tree and in the caller's mount namespace (Linux's `check_mnt`);
/// otherwise EINVAL.
fn check_mnt(cx: &Cx<'_>, vfs: &Vfs, id: MountId) -> Result<(), Errno> {
    match vfs.mount_ns(id) {
        Some(ns) if ns == cx.mnt_ns() => Ok(()),
        _ => Err(Errno::EINVAL),
    }
}
