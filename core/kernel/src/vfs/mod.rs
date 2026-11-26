//! The virtual filesystem (the kernel/vfs map).
//!
//! The root filesystem is the inode store, and the device nodes in `/dev` live in the store too
//! ([`dev`]). procfs, devpts, sysfs and cgroup2 are synthetic filesystems: their content comes
//! from kernel state and is provided by the kernel layer through [`Pseudo`]. At boot they are
//! mounted on `/proc`, `/dev/pts`, `/sys` and `/sys/fs/cgroup`, and later mount(2) can mount
//! them on other directories; directories and files both in the store and in synthetic
//! filesystems can be bind-mounted ([`Mount`]). A tmpfs is a tree in the store that does not hang
//! under the root directory ([`Vfs::new_tmpfs`]), deleted when its last mount goes. Nodes carry
//! the mount they are in (Linux's `struct path`); `..` and getcwd go back up through mount
//! points, and mount flags (read-only, noexec and so on) follow the mount reached through. Path
//! resolution runs over the whole tree and follows at most 40 levels of symlinks; every store
//! directory passed needs search permission. A process's root can be replaced by chroot and
//! pivot_root: absolute paths start from it, and `..` never goes past it.

pub(crate) mod acl;
pub mod browse;
pub mod dev;
pub mod fuse;
pub mod import;
pub mod overlay;
pub mod store;

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use crate::cell::RefCell;
use crate::cred::{Cred, MAY_EXEC};
use crate::errno::Errno;
pub(crate) use crate::pseudo::PseudoNode;
use store::{Ino, ROOT, Stat, Store, mode};

/// Maximum number of symlinks followed, the same as Linux's MAXSYMLINKS.
pub(crate) const MAX_SYMLINKS: u32 = 40;
/// Maximum length of a path component (`NAME_MAX`).
const NAME_MAX: usize = 255;

/// A node in the filesystem tree plus the mount it was reached through (Linux's `struct path`):
/// one directory mounted (bound) in two places is two nodes, and `..` from each goes back to its
/// own mount point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Node {
    /// An inode in the inode store.
    Store(MountId, Ino),
    /// A node in a synthetic filesystem.
    Pseudo(MountId, PseudoNode),
    /// A node in an overlay ([`overlay`]): the store inodes behind it are looked up through
    /// [`Vfs::overlay`].
    Overlay(MountId, overlay::OvlId),
    /// A node in a FUSE filesystem ([`fuse`]): its daemon's node id and cached attributes are
    /// looked up through [`Vfs::fuse`].
    Fuse(MountId, fuse::FuseId),
}

impl Node {
    /// The root directory at boot.
    pub const ROOT: Node = Node::Store(ROOT_MOUNT, ROOT);

    /// The mount reached through.
    pub(crate) fn mnt(&self) -> MountId {
        match self {
            Node::Store(id, _) | Node::Pseudo(id, _) | Node::Overlay(id, _) | Node::Fuse(id, _) => {
                *id
            }
        }
    }

    /// The store inode; None for nodes in synthetic filesystems, overlays (an overlay node's
    /// store inodes are in lower layers that must not change, see [`Vfs::overlay`]) and FUSE.
    pub(crate) fn ino(&self) -> Option<Ino> {
        match self {
            Node::Store(_, ino) => Some(*ino),
            Node::Pseudo(..) | Node::Overlay(..) | Node::Fuse(..) => None,
        }
    }

    /// The node of the same file reached through mount `id`.
    pub(crate) fn in_mount(self, id: MountId) -> Node {
        match self {
            Node::Store(_, ino) => Node::Store(id, ino),
            Node::Pseudo(_, p) => Node::Pseudo(id, p),
            Node::Overlay(_, o) => Node::Overlay(id, o),
            Node::Fuse(_, f) => Node::Fuse(id, f),
        }
    }
}

/// A directory and one name in it.
pub(crate) type Dentry = (Node, Vec<u8>);

/// The final component, including a removed name reached through an open file's magic link.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct WalkDentry {
    pub entry: Dentry,
    pub unlinked: bool,
}

/// Where a mount is mounted: [`Mount::point`] and [`Mount::at`].
type Place = (Option<Node>, Option<Dentry>);

/// Mount id (the first column of mountinfo, `mnt_id` in fdinfo), numbered across all mount
/// namespaces together.
pub(crate) type MountId = u32;

/// Device number of the mqueue filesystem of the boot IPC namespace (0:19).
pub(crate) const MQUEUE_DEV: u64 = 0x13;
/// Id of the boot mount namespace: the inode number in `/proc/<pid>/ns/mnt`, the same as is
/// common on Linux.
pub(crate) const INIT_MNT_NS: u64 = 4_026_531_841;

/// A mount namespace (Linux's `struct mnt_namespace`): only an id; each mount records which
/// namespace it belongs to ([`Mount::ns`]). A process's `FsContext` holds it; after the last
/// reference goes, the next cleanup ([`Vfs::collect`]) detaches all its mounts.
#[derive(Debug)]
pub(crate) struct MntNs {
    pub id: u64,
    /// Owner: the user namespace it was created in (mounting needs `CAP_SYS_ADMIN` there,
    /// Linux's `may_mount`).
    pub owner: std::rc::Rc<crate::cred::UserNs>,
    /// Anonymous: the namespace of a tree copied by open_tree(`OPEN_TREE_CLONE`) and not yet
    /// attached; no process is in it, and it is held by an open file ([`Vfs::anon_ns`]).
    pub anon: bool,
}

/// Allocates a new namespace id (Linux's `proc_alloc_inum`, shared by all kinds of namespace).
pub(crate) fn new_ns_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(4_026_532_160);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
/// The root filesystem (the inode store).
pub(crate) const ROOT_MOUNT: MountId = 1;
/// The procfs mounted on `/proc` at boot.
pub(crate) const PROC_MOUNT: MountId = 2;
/// The devpts mounted on `/dev/pts` at boot.
pub(crate) const PTS_MOUNT: MountId = 3;
/// The sysfs mounted on `/sys` at boot.
pub(crate) const SYS_MOUNT: MountId = 4;
/// `mnt_id` in fdinfo of open files that are in no filesystem (pipes, sockets and so on).
pub(crate) const ANON_MOUNT: MountId = 5;
/// The cgroup2 mounted on `/sys/fs/cgroup` at boot.
pub(crate) const CGROUP_MOUNT: MountId = 6;
/// The tmpfs mounted on `/dev` at boot (Linux's devtmpfs, the tmpfs container runtimes mount).
pub(crate) const DEV_MOUNT: MountId = 7;
/// The tmpfs mounted on `/dev/shm` at boot.
pub(crate) const SHM_MOUNT: MountId = 8;
/// The mqueue mounted on `/dev/mqueue` at boot.
pub(crate) const MQUEUE_MOUNT: MountId = 9;
/// The tmpfs mounted on `/run` at boot.
pub(crate) const RUN_MOUNT: MountId = 10;

/// Kinds of filesystem: the inode store and several synthetic filesystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Fs {
    /// The inode store (the root filesystem).
    Store,
    /// tmpfs: a tree in the store that does not hang under the root directory
    /// ([`Vfs::new_tmpfs`]).
    Tmpfs,
    /// procfs.
    Proc,
    /// devpts.
    Pts,
    /// sysfs.
    Sys,
    /// cgroup2 (`crate::cgroup`).
    Cgroup,
    /// nsfs: the filesystem namespace files (what following `/proc/<pid>/ns/*` gives) are in. It
    /// cannot be mounted; only namespace files bind-mounted elsewhere are in the mount table.
    Nsfs,
    /// mqueue: the POSIX message queues (`crate::syscall::mqueue`) of the IPC namespace of the
    /// process that mounts it. One instance per namespace (Linux's `get_tree_keyed`); the mount
    /// keeps that namespace alive.
    Mqueue,
    /// overlayfs ([`overlay`]): store directories merged into one tree, a new instance on every
    /// mount.
    Overlay,
    /// FUSE ([`fuse`]): a filesystem a guest process serves through `/dev/fuse`, a new instance
    /// (connection) on every mount.
    Fuse,
}

impl Fs {
    /// Filesystem types mount(2) can newly mount (the same names as in `/proc/filesystems`).
    pub(crate) fn from_type(name: &[u8]) -> Option<Fs> {
        match name {
            b"proc" => Some(Fs::Proc),
            b"devpts" => Some(Fs::Pts),
            b"sysfs" => Some(Fs::Sys),
            b"cgroup2" => Some(Fs::Cgroup),
            b"tmpfs" => Some(Fs::Tmpfs),
            b"mqueue" => Some(Fs::Mqueue),
            b"overlay" => Some(Fs::Overlay),
            // `fuse.<subtype>` is fuse with that subtype (Linux's `FS_HAS_SUBTYPE`)
            b"fuse" => Some(Fs::Fuse),
            n if n.starts_with(b"fuse.") => Some(Fs::Fuse),
            _ => None,
        }
    }

    /// Name of the filesystem type.
    pub(crate) const fn type_name(self) -> &'static str {
        match self {
            Fs::Store => "ext4",
            Fs::Tmpfs => "tmpfs",
            Fs::Proc => "proc",
            Fs::Pts => "devpts",
            Fs::Sys => "sysfs",
            Fs::Cgroup => "cgroup2",
            Fs::Nsfs => "nsfs",
            Fs::Mqueue => "mqueue",
            Fs::Overlay => "overlay",
            Fs::Fuse => "fuse",
        }
    }

    /// Device number of the instance mounted at boot (stat's `st_dev`, the third column of
    /// mountinfo).
    pub(crate) const fn dev(self) -> u64 {
        match self {
            Fs::Store => ROOT_DEV,
            // No boot instance; allocated separately on each mount
            Fs::Tmpfs | Fs::Overlay | Fs::Fuse => 0,
            Fs::Proc => 0x17,
            Fs::Pts => 0x18,
            Fs::Sys => 0x16,
            Fs::Cgroup => 0x1a,
            // As on Linux
            Fs::Nsfs => 0x4,
            // The boot IPC namespace's; other namespaces' are allocated separately
            // ([`Vfs::mq_dev`])
            Fs::Mqueue => MQUEUE_DEV,
        }
    }

    /// Every mount is a new instance (procfs since Linux 5.8, devpts since 4.7): another one can
    /// be mounted at the same place. sysfs and cgroup2 have only one instance per namespace, and
    /// mounting again on the root of the same mount is EBUSY.
    pub(crate) const fn new_instance(self) -> bool {
        matches!(
            self,
            Fs::Proc | Fs::Pts | Fs::Tmpfs | Fs::Overlay | Fs::Fuse
        )
    }

    /// Newly mounted instances have their own device numbers: procfs, tmpfs, devpts (each
    /// instance has its own set of terminals, and the device number is the instance number,
    /// [`crate::tty::PtsOptions`]), overlay and FUSE (a FUSE connection mounted again keeps its
    /// number).
    pub(crate) const fn own_dev(self) -> bool {
        matches!(
            self,
            Fs::Proc | Fs::Tmpfs | Fs::Pts | Fs::Overlay | Fs::Fuse
        )
    }

    /// Superblock options (the part after `rw` in the last column of mountinfo).
    pub(crate) const fn options(self) -> &'static str {
        match self {
            Fs::Cgroup => ",nsdelegate,memory_recursiveprot",
            // Per instance for tmpfs, devpts, overlays and FUSE ([`Vfs::sb_options`])
            Fs::Store
            | Fs::Tmpfs
            | Fs::Pts
            | Fs::Proc
            | Fs::Sys
            | Fs::Nsfs
            | Fs::Mqueue
            | Fs::Overlay
            | Fs::Fuse => "",
        }
    }

    /// The filesystem's root directory (mount id 0, replaced by the new mount's when mounted).
    /// The roots of tmpfs, overlay and FUSE instances are created at mount time
    /// ([`Vfs::new_tmpfs`], [`Vfs::new_overlay`], [`Vfs::new_fuse`]) and nsfs cannot be mounted;
    /// none of them uses this.
    pub(crate) fn root(self) -> Node {
        Node::Pseudo(
            0,
            match self {
                Fs::Store | Fs::Tmpfs | Fs::Overlay | Fs::Fuse => return Node::Store(0, ROOT),
                Fs::Proc | Fs::Nsfs => PseudoNode::ProcRoot,
                // Replaced by the new instance's when mounted
                Fs::Pts => PseudoNode::PtsRoot(crate::tty::BOOT_PTS),
                Fs::Sys => PseudoNode::SysRoot,
                // Replaced by the root of the caller's cgroup namespace when mounted
                Fs::Cgroup => PseudoNode::Cgroup(crate::cgroup::ROOT, b"", 0),
                // Replaced by the caller's IPC namespace's when mounted
                Fs::Mqueue => PseudoNode::MqRoot(crate::nsproxy::INIT_IPC_NS),
            },
        )
    }
}

/// Mount flags: the same values as mount(2)'s `MS_*`.
pub(crate) mod ms {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const NOSYMFOLLOW: u64 = 0x100;
    pub const NOATIME: u64 = 0x400;
    pub const NODIRATIME: u64 = 0x800;
    pub const RELATIME: u64 = 1 << 21;
    pub const SYNCHRONOUS: u64 = 0x10;
    pub const MANDLOCK: u64 = 0x40;
    pub const DIRSYNC: u64 = 0x80;
    pub const LAZYTIME: u64 = 1 << 25;
    /// Those kept on the mount (the ones matching Linux's `MNT_*`).
    pub const PER_MOUNT: u64 =
        RDONLY | NOSUID | NODEV | NOEXEC | NOSYMFOLLOW | NOATIME | NODIRATIME | RELATIME;
    /// Those kept on the filesystem instance (Linux's `SB_*` of a new superblock); read-only is
    /// both a mount flag and a superblock flag.
    pub const PER_SB: u64 = RDONLY | SYNCHRONOUS | MANDLOCK | DIRSYNC | LAZYTIME;
    /// The superblock flags a remount without `MS_BIND` sets (Linux's `MS_RMT_MASK`): not
    /// dirsync.
    pub const REMOUNT_SB: u64 = RDONLY | SYNCHRONOUS | MANDLOCK | LAZYTIME;
}

/// Locks on a mount (Linux's `MNT_LOCKED` and `MNT_LOCK_*`, kept in [`Mount::locks`]): a mount
/// namespace copied into one owned by another user namespace (Linux's `lock_mnt_tree`) locks
/// every mount, so a user privileged only there cannot uncover what a mount hides or loosen the
/// flags it was given.
pub(crate) mod lock {
    /// The mount cannot be unmounted, moved or used as pivot_root's `new_root`, and a
    /// non-recursive bind of a directory it is mounted under is EINVAL (it would uncover it).
    pub const MOUNT: u64 = 1;
    /// Flags a remount or mount_setattr cannot clear (EPERM).
    pub const READONLY: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOSUID: u64 = 8;
    pub const NOEXEC: u64 = 0x10;
    /// The access-time flags cannot change.
    pub const ATIME: u64 = 0x20;
}

/// Mount flags of the root filesystem: `rw,relatime`.
pub(crate) const ROOT_FLAGS: u64 = ms::RELATIME;
/// Device number the root filesystem (the inode store) reports (8:1).
pub(crate) const ROOT_DEV: u64 = 0x801;

/// A mount (Linux's `struct mount`): `root` in filesystem `fs` appears at `point`.
#[derive(Debug, Clone)]
pub(crate) struct Mount {
    pub id: MountId,
    /// The mount namespace it belongs to ([`MntNs::id`]).
    pub ns: u64,
    pub fs: Fs,
    /// Root of the part the mount sees (a node reached through this mount): the filesystem's
    /// root directory, or for a bind mount the directory or file that was bound.
    pub root: Node,
    /// Mount point: a directory in another mount (a file when a file is bind-mounted). The root
    /// of the mount tree (the store at boot, the one swapped in after pivot_root) and detached
    /// mounts have none; on Linux the former is mounted on the invisible rootfs.
    pub point: Option<Node>,
    /// When the mount point is a file in the store, its directory and name: a file can have
    /// several links and no unique parent directory, so the path is computed from this one,
    /// recorded at mount time.
    pub at: Option<Dentry>,
    /// When a file in the store is bind-mounted, the directory and name it was found at (the
    /// fourth column of mountinfo is computed from it); once the root's name is removed, where
    /// it was ([`Vfs::roots_removed`]).
    pub root_at: Option<Dentry>,
    /// The root's name has been removed (Linux's `d_unlinked` mount root): mountinfo shows its
    /// former path followed by `//deleted`.
    pub root_gone: bool,
    /// Flags from [`ms`].
    pub flags: u64,
    /// Device number of the instance ([`Fs::own_dev`]).
    pub dev: u64,
    /// mount(2)'s source (the tenth column of mountinfo).
    pub source: Vec<u8>,
    /// Marked by `umount2(MNT_EXPIRE)`: detached the next time.
    pub expiring: bool,
    /// A namespace file bind-mounted elsewhere ([`Fs::Nsfs`]): it keeps that namespace alive.
    pub pin: Option<crate::nsproxy::NsRef>,
    /// Bits from [`lock`].
    pub locks: u64,
    /// Its propagation type: shared (in a peer group), a slave, unbindable ([`Propagation`]).
    pub prop: Propagation,
    /// The user namespace owning the instance (Linux's `s_user_ns`), None for the initial one: a
    /// remount without `MS_BIND` needs `CAP_SYS_ADMIN` over it.
    pub owner: Option<std::rc::Rc<crate::cred::UserNs>>,
}

/// A mount's propagation (Linux's `mnt_group_id`, `mnt_master` and `MNT_UNBINDABLE`, by
/// `fs/pnode.c`'s rules): recorded, changed and shown in mountinfo, and followed by mount and
/// unmount events ([`Vfs::propagation_targets`], [`Vfs::propagate`], [`Vfs::umount_tree`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Propagation {
    /// The peer group of a shared mount (`shared:N`), 0 when not shared.
    pub group: u32,
    /// The peer group it is a slave of (`master:N`), 0 when not a slave.
    pub master: u32,
    pub unbindable: bool,
}

/// A mount a tree attached elsewhere is copied to ([`Vfs::propagation_targets`]): the place
/// there, its namespace and own peer group, and the chain of groups from its master up to the
/// group the tree was attached in (empty for a peer of that mount).
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub ns: u64,
    pub point: Node,
    pub at: Option<Dentry>,
    group: u32,
    masters: Vec<u32>,
}

/// What `MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` and `MS_UNBINDABLE` make a mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PropagationType {
    Shared,
    Slave,
    Private,
    Unbindable,
}

impl Propagation {
    /// A bind's (Linux's `clone_mnt` without flags): a peer of a shared source, a slave of the
    /// same master as a slave one.
    pub(crate) fn of_bind(self) -> Propagation {
        Propagation {
            unbindable: false,
            ..self
        }
    }

    /// A copy into a less privileged mount namespace (`CL_SHARED_TO_SLAVE`): a shared mount's
    /// copy is a slave of its peer group.
    pub(crate) fn of_slave_copy(self) -> Propagation {
        match self.group {
            0 => Propagation {
                unbindable: false,
                ..self
            },
            g => Propagation {
                group: 0,
                master: g,
                unbindable: false,
            },
        }
    }
}

impl Mount {
    /// Whether flags `flags` keep everything this mount has locked (Linux's
    /// `can_change_locked_flags`): a remount or mount_setattr to anything else is EPERM.
    pub(crate) fn keeps_locked(&self, flags: u64) -> bool {
        let kept = |l: u64, f: u64| self.locks & l == 0 || flags & f != 0;
        const ATIME: u64 = ms::NOATIME | ms::NODIRATIME | ms::RELATIME;
        kept(lock::READONLY, ms::RDONLY)
            && kept(lock::NODEV, ms::NODEV)
            && kept(lock::NOSUID, ms::NOSUID)
            && kept(lock::NOEXEC, ms::NOEXEC)
            && (self.locks & lock::ATIME == 0 || self.flags & ATIME == flags & ATIME)
    }

    /// The mount the mount point is in (the second column of mountinfo); the root of the mount
    /// tree and detached mounts have none.
    pub(crate) fn parent(&self) -> Option<MountId> {
        self.point.as_ref().map(Node::mnt)
    }
}

/// Directory structure of a synthetic filesystem (implemented by the kernel layer, with content
/// from kernel state).
pub(crate) trait Pseudo {
    /// Parent directory; None for the root.
    fn parent(&self, node: &PseudoNode) -> Option<PseudoNode>;
    /// The node's name in its parent directory. `mnt` is the mount the node is in: pids in
    /// procfs follow the pid namespace of the mount's instance.
    fn name(&self, mnt: MountId, node: &PseudoNode) -> Vec<u8>;
    /// Looks up in a directory.
    fn lookup(&self, mnt: MountId, dir: &PseudoNode, name: &[u8]) -> Result<PseudoNode, Errno>;
    /// File type bits (the `S_IFMT` part).
    fn kind(&self, node: &PseudoNode) -> Result<u32, Errno>;
    /// Contents of a symlink.
    fn readlink(&self, mnt: MountId, node: &PseudoNode) -> Result<Vec<u8>, Errno>;
    /// The node a "magic link" (`/proc/<pid>/fd/<n>` and the like) leads to directly when
    /// followed, without resolving its contents; None when it is not a magic link, an error
    /// (EACCES) when following is not allowed. `mnt` is the mount the link is in.
    fn follow(&self, mnt: MountId, node: &PseudoNode) -> Option<Result<Node, Errno>>;
    /// Through which name in which directory the open file a magic link points at was opened (a
    /// file that is not a directory has no unique parent directory; when it is a mount point,
    /// mountinfo's path is computed from this).
    fn follow_dentry(&self, _node: &PseudoNode) -> Option<WalkDentry> {
        None
    }
    /// Whether this is a Linux magic link (`nd_jump_link`): openat2's `RESOLVE_NO_MAGICLINKS`
    /// and scoped resolution do not follow them. Includes those [`Pseudo::follow`] jumps to
    /// directly, and also those resolved here by content that Linux jumps to directly
    /// (`/proc/<pid>/exe`).
    fn magic(&self, _node: &PseudoNode) -> bool {
        false
    }
    /// Whether `fs.protected_symlinks` is on ([`Vfs::may_follow_link`]).
    fn protected_symlinks(&self) -> bool {
        false
    }
    /// Path resolution found no `name` in directory `dir` (ENOENT): the view counts the names
    /// Linux would have as unimplemented paths ([`crate::stub`]).
    fn missing(&self, _dir: &Node, _name: &[u8]) {}
    /// The attributes search permission on directory `node` is checked against; None for
    /// directories anyone may search.
    fn searched(&self, _node: &PseudoNode) -> Option<store::Stat> {
        None
    }
}

/// The `resolve` of openat2's `struct open_how` (Linux's `RESOLVE_*`, matching path
/// resolution's `LOOKUP_NO_XDEV` and the like).
pub(crate) mod resolve {
    /// No crossing mounts (bind mounts included): going in or out through mount points, `..`
    /// past a mount's root, symlinks to absolute paths that jump to another mount, and magic
    /// links are all EXDEV.
    pub const NO_XDEV: u64 = 0x01;
    /// Do not follow magic links (ELOOP).
    pub const NO_MAGICLINKS: u64 = 0x02;
    /// Do not follow any symlink (ELOOP).
    pub const NO_SYMLINKS: u64 = 0x04;
    /// Do not leave the start: absolute paths, symlinks to absolute paths, `..` at the start and
    /// magic links are all EXDEV.
    pub const BENEATH: u64 = 0x08;
    /// Treat the start as the root directory: absolute paths and symlinks to absolute paths
    /// count from the start, and `..` at the start stays put; magic links are EXDEV.
    pub const IN_ROOT: u64 = 0x10;
    /// Resolve only from the cache (without blocking).
    pub const CACHED: u64 = 0x20;
    pub const ALL: u64 = 0x3f;
    /// Scoped (`LOOKUP_IS_SCOPED`): the root is the start.
    pub const SCOPED: u64 = BENEATH | IN_ROOT;
}

#[derive(Hash, Eq, PartialEq)]
enum AnonKey {
    Pipe(u64),
    Socket(u64),
}

pub(crate) enum AnonTarget {
    Pipe(Rc<RefCell<crate::pipe::Pipe>>),
    Socket(Rc<RefCell<crate::net::Socket>>),
}

enum AnonWeak {
    Pipe(Weak<RefCell<crate::pipe::Pipe>>),
    Socket(Weak<RefCell<crate::net::Socket>>),
}

struct AnonEntry {
    attrs: AnonAttrs,
    object: AnonWeak,
}

#[derive(Clone, Copy)]
pub(crate) struct AnonAttrs {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime_ns: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}

impl AnonTarget {
    fn key(&self) -> AnonKey {
        match self {
            Self::Pipe(p) => AnonKey::Pipe(p.borrow().ino),
            Self::Socket(s) => AnonKey::Socket(crate::pseudo::socket_ino(s)),
        }
    }

    fn entry(&self, cred: &Cred) -> AnonEntry {
        let (mode, uid, gid, now, object) = match self {
            Self::Pipe(p) => (
                mode::S_IFIFO | 0o600,
                cred.fsuid,
                cred.fsgid,
                crate::tty::wall_ns(),
                AnonWeak::Pipe(Rc::downgrade(p)),
            ),
            Self::Socket(s) => {
                let sock = s.borrow();
                (
                    mode::S_IFSOCK | 0o777,
                    sock.uid(),
                    sock.gid(),
                    0,
                    AnonWeak::Socket(Rc::downgrade(s)),
                )
            }
        };
        AnonEntry {
            object,
            attrs: AnonAttrs {
                mode,
                uid,
                gid,
                atime_ns: now,
                mtime_ns: now,
                ctime_ns: now,
            },
        }
    }

    pub(crate) fn stat(&self, vfs: Option<&Vfs>, cred: &Cred) -> Stat {
        let attrs = match vfs {
            Some(vfs) => vfs.anon_attrs(self, cred, |a| *a),
            None => self.entry(cred).attrs,
        };
        let ino = match self.key() {
            AnonKey::Pipe(i) | AnonKey::Socket(i) => i,
        };
        Stat {
            ino,
            nlink: 1,
            mode: attrs.mode,
            uid: attrs.uid,
            gid: attrs.gid,
            atime_ns: attrs.atime_ns,
            mtime_ns: attrs.mtime_ns,
            ctime_ns: attrs.ctime_ns,
            ..Stat::default()
        }
    }
}

/// A virtual filesystem instance.
pub struct Vfs {
    anon: RefCell<HashMap<AnonKey, AnonEntry>>,
    anon_prune_at: std::cell::Cell<usize>,
    store: Store,
    /// Sparse lengths that the store filesystem could not represent for a memfd.
    memfd_sizes: RefCell<HashMap<Ino, u64>>,
    tmpfs_file_ranges: RefCell<HashMap<Ino, TmpfsFileRanges>>,
    /// The mount table: the boot ones and those mount(2) mounted later, in mount order.
    mounts: RefCell<Mounts>,
    /// Regenerated whenever the mount table changes.
    cached: RefCell<Cached>,
    /// Recently executed program files ([`Vfs::executable`]).
    executables: crate::loader::ExeCache,
    /// The boot mount namespace.
    init_ns: std::rc::Rc<MntNs>,
    /// Mount namespaces created later: once all references to one are gone, cleanup detaches
    /// its mounts.
    namespaces: RefCell<Vec<std::rc::Weak<MntNs>>>,
    /// Overlay instances and their nodes.
    overlays: RefCell<overlay::Overlays>,
    /// FUSE connections and their nodes.
    fuse: RefCell<fuse::Fuses>,
    /// Per-mount-namespace change counters (Linux's `mnt_ns->event` / `touch_mnt_namespace`),
    /// keyed by namespace id, for polling `/proc/<pid>/mounts` and `mountinfo`
    /// ([`crate::fd::ProcEvent`]). Pruned in [`Vfs::collect`] once a namespace dies.
    ns_events: RefCell<HashMap<u64, std::rc::Rc<std::cell::Cell<u64>>>>,
    /// Number of attached mounts currently carrying an `MNT_EXPIRE` mark; avoids borrowing the
    /// mount table on path lookups when none are marked.
    expiring: std::cell::Cell<usize>,
    /// Former names of removed store directories still referenced by a task's cwd, root or open
    /// directory/path descriptor (or an ancestor of one), so `d_path` ([`Vfs::path_of`]) can
    /// reconstruct `<path> (deleted)` after `rmdir` or an overwriting `rename`.
    removed_dirs: RefCell<HashMap<Ino, Vec<u8>>>,
}

/// Position of a live mount in [`Mounts::list`] or [`Mounts::detached`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MountLoc {
    Attached(usize),
    Detached(usize),
}

struct Mounts {
    /// Attached mounts, in mount order (the mountinfo order); the first is the root of the mount
    /// tree, and it is not moved even when that is no longer true after pivot_root.
    list: Vec<Mount>,
    /// Detached mounts (`MNT_DETACH`) that still have a process's root, current directory or
    /// open files in them: their nodes keep working, and the mount's root has no parent unless
    /// the mount is locked in place on a detached parent ([`detach`]; [`Vfs::collect`] removes the
    /// unused ones).
    detached: Vec<Mount>,
    /// Live mounts (attached and detached) indexed by id for O(1) lookup.
    by_id: HashMap<MountId, MountLoc>,
    /// Direct children of each mount (`m.parent() == Some(parent)` with `parent != m.id`),
    /// across attached and detached mounts, kept in mount order.
    children: HashMap<MountId, Vec<MountId>>,
    /// The id of the next mount. Ids of detached mounts are never reused: files still open and
    /// current directories after the detach keep the old id, which must not count toward a new
    /// mount.
    next: MountId,
    /// Device number of the next new instance (from 0:48, avoiding [`Fs::dev`] and those pipes,
    /// sockets and so on use).
    next_dev: u64,
    /// tmpfs instances, by device number (bind mounts share their source's device number).
    tmpfs: std::collections::HashMap<u64, Tmpfs>,
    /// The pid namespace (the mounting process's) of each procfs instance mounted by mount(2),
    /// by device number; the boot one and those not recorded use the boot pid namespace.
    proc_ns: std::collections::HashMap<u64, std::rc::Rc<crate::pidns::PidNs>>,
    /// The network namespace (the mounting process's) of each non-initial sysfs instance, by
    /// device number; the boot instance and mounts in the initial network namespace use
    /// [`Fs::Sys`]'s boot device and are not recorded here.
    sys_ns: std::collections::HashMap<u64, std::rc::Rc<crate::nsproxy::NetNs>>,
    /// Device numbers of each IPC namespace's mqueue instance ([`Vfs::mq_dev`]), by namespace
    /// id.
    mq_dev: std::collections::HashMap<u64, u64>,
    /// Options of devpts instances mounted by mount(2), by device number (the boot one is not
    /// here).
    devpts: std::collections::HashMap<u64, crate::tty::PtsOptions>,
    /// Superblock flags ([`ms::PER_SB`]) of filesystem instances, by device number: given when an
    /// instance was mounted, changed by a remount without `MS_BIND`; absent is none (the boot
    /// instances).
    sb_flags: std::collections::HashMap<u64, u64>,
    /// Detached mounts need collection on the next syscall/exit pass (set when removing a mount
    /// point detaches mounts in other namespaces, or when an earlier collection found tables
    /// borrowed). Stored kernel-wide so a retiring pool thread never loses the retry.
    collect_pending: bool,
}

impl Mounts {
    fn get(&self, id: MountId) -> Option<&Mount> {
        match self.by_id.get(&id).copied()? {
            MountLoc::Attached(i) => self.list.get(i),
            MountLoc::Detached(i) => self.detached.get(i),
        }
    }

    fn get_attached(&self, id: MountId) -> Option<&Mount> {
        match self.by_id.get(&id).copied()? {
            MountLoc::Attached(i) => self.list.get(i),
            MountLoc::Detached(_) => None,
        }
    }

    fn get_mut(&mut self, id: MountId) -> Option<&mut Mount> {
        match self.by_id.get(&id).copied()? {
            MountLoc::Attached(i) => self.list.get_mut(i),
            MountLoc::Detached(i) => self.detached.get_mut(i),
        }
    }

    fn get_attached_mut(&mut self, id: MountId) -> Option<&mut Mount> {
        match self.by_id.get(&id).copied()? {
            MountLoc::Attached(i) => self.list.get_mut(i),
            MountLoc::Detached(_) => None,
        }
    }

    fn loc_key(&self, id: MountId) -> (u8, usize) {
        match self.by_id.get(&id).copied() {
            Some(MountLoc::Attached(i)) => (0, i),
            Some(MountLoc::Detached(i)) => (1, i),
            None => (2, 0),
        }
    }

    fn link_child(&mut self, parent: MountId, child: MountId) {
        let key = self.loc_key(child);
        let fast_append = self
            .children
            .get(&parent)
            .and_then(|kids| kids.last().copied())
            .is_none_or(|last| self.loc_key(last) < key);
        if fast_append {
            self.children.entry(parent).or_default().push(child);
            return;
        }
        let pos = self.children[&parent]
            .binary_search_by_key(&key, |&c| self.loc_key(c))
            .unwrap_or_else(|p| p);
        self.children.entry(parent).or_default().insert(pos, child);
    }

    fn unlink_child(&mut self, parent: MountId, child: MountId) {
        if let Some(kids) = self.children.get_mut(&parent) {
            if let Some(pos) = kids.iter().position(|&c| c == child) {
                kids.remove(pos);
            }
            if kids.is_empty() {
                self.children.remove(&parent);
            }
        }
    }

    fn push_attached(&mut self, m: Mount) {
        let idx = self.list.len();
        let id = m.id;
        let parent = m.parent().filter(|&p| p != id);
        self.by_id.insert(id, MountLoc::Attached(idx));
        self.list.push(m);
        if let Some(parent) = parent {
            self.link_child(parent, id);
        }
    }

    fn set_point(&mut self, id: MountId, point: Option<Node>, at: Option<Dentry>) {
        let Some(m) = self.get_mut(id) else {
            return;
        };
        let old_parent = m.parent().filter(|&p| p != id);
        let new_parent = point.as_ref().map(Node::mnt).filter(|&p| p != id);
        m.point = point;
        m.at = at;
        if old_parent != new_parent {
            if let Some(p) = old_parent {
                self.unlink_child(p, id);
            }
            if let Some(p) = new_parent {
                self.link_child(p, id);
            }
        }
    }

    fn rebuild_index(&mut self) {
        self.by_id.clear();
        self.by_id.reserve(self.list.len() + self.detached.len());
        self.children.clear();
        for (i, m) in self.list.iter().enumerate() {
            self.by_id.insert(m.id, MountLoc::Attached(i));
            if let Some(parent) = m.parent().filter(|&p| p != m.id) {
                self.children.entry(parent).or_default().push(m.id);
            }
        }
        for (i, m) in self.detached.iter().enumerate() {
            self.by_id.insert(m.id, MountLoc::Detached(i));
            if let Some(parent) = m.parent().filter(|&p| p != m.id) {
                self.children.entry(parent).or_default().push(m.id);
            }
        }
    }

    #[cfg(test)]
    fn verify_index(&self) {
        let mut expected_by_id = HashMap::with_capacity(self.list.len() + self.detached.len());
        let mut expected_children: HashMap<MountId, Vec<MountId>> = HashMap::new();
        for (i, m) in self.list.iter().enumerate() {
            expected_by_id.insert(m.id, MountLoc::Attached(i));
            if let Some(parent) = m.parent().filter(|&p| p != m.id) {
                expected_children.entry(parent).or_default().push(m.id);
            }
        }
        for (i, m) in self.detached.iter().enumerate() {
            expected_by_id.insert(m.id, MountLoc::Detached(i));
            if let Some(parent) = m.parent().filter(|&p| p != m.id) {
                expected_children.entry(parent).or_default().push(m.id);
            }
        }
        assert_eq!(self.by_id, expected_by_id);
        assert_eq!(self.children, expected_children);
    }

    /// A boot mount: root `root` of filesystem `fs` (device number `dev`) mounted on `point`;
    /// not mounted when there is no mount point.
    fn boot(
        &mut self,
        id: MountId,
        (fs, root, dev): (Fs, Node, u64),
        point: Option<Node>,
        flags: u64,
        source: &[u8],
    ) {
        let Some(point) = point else {
            crate::debug::log(format_args!("no mount point for {fs:?}"));
            return;
        };
        self.push_attached(Mount {
            id,
            ns: INIT_MNT_NS,
            fs,
            root,
            point: Some(point),
            at: None,
            root_at: None,
            root_gone: false,
            flags,
            dev,
            source: source.to_vec(),
            expiring: false,
            pin: None,
            locks: 0,
            prop: Propagation::default(),
            owner: None,
        });
    }

    /// A tmpfs mounted at boot (the same as [`Vfs::new_tmpfs`], except that the mount id is
    /// fixed); returns its root directory.
    fn boot_tmpfs(
        &mut self,
        store: &Store,
        id: MountId,
        point: Node,
        flags: u64,
        source: &[u8],
        params: TmpfsParams,
    ) -> Result<Ino, Errno> {
        let root = store.create_detached_dir(params.perm, params.uid, params.gid)?;
        let dev = self.next_dev;
        self.next_dev += 1;
        let fs = (Fs::Tmpfs, Node::Store(id, root), dev);
        self.boot(id, fs, Some(point), flags, source);
        // Usage is counted when needed ([`dev::populate`] created nodes in it)
        let used = None;
        let changed = false;
        self.tmpfs.insert(
            dev,
            Tmpfs {
                root,
                params,
                used,
                changed,
                unlinked: Default::default(),
            },
        );
        Ok(root)
    }

    /// Mount points in the store; no-BKL resolution hands back to normal resolution when it
    /// meets one. When the boot root filesystem is not the root of the mount tree (after
    /// pivot_root), its root directory counts too: `..` has to leave through its mount point.
    fn store_points(&self) -> Arc<[Ino]> {
        let top = self
            .get_attached(ROOT_MOUNT)
            .is_some_and(|m| m.point.is_none());
        self.list
            .iter()
            .filter_map(|m| match m.point {
                Some(Node::Store(_, ino)) => Some(ino),
                _ => None,
            })
            .chain((!top).then_some(ROOT))
            .collect()
    }

    /// The boot root filesystem is still attached and not nosymfollow: no-BKL resolution walks
    /// only inside it.
    fn fast_usable(&self) -> bool {
        self.get_attached(ROOT_MOUNT)
            .is_some_and(|m| m.flags & ms::NOSYMFOLLOW == 0)
    }
}

/// tmpfs accounts usage in pages; the page size (guest pages).
pub(crate) const TMPFS_PAGE: u64 = 4096;

/// Count unallocated guest pages in a host file range, or return the first page that would
/// exceed the budget. FIEMAP includes unwritten reservations and excludes filesystem metadata.
/// None means the object filesystem needs the SEEK_DATA/st_blocks fallback.
fn fiemap_holes(host: &std::fs::File, from: u64, to: u64, budget: u64) -> Option<Result<u64, u64>> {
    use std::os::fd::AsRawFd;
    const FS_IOC_FIEMAP: u64 = 0xc020660b;
    const COUNT: usize = 32;
    const HEADER: usize = 32;
    const EXTENT: usize = 56;
    let last = to.div_ceil(TMPFS_PAGE);
    let mut page = from / TMPFS_PAGE;
    let mut holes = 0;
    while page < last {
        let pos = page * TMPFS_PAGE;
        let mut buf = [0u8; HEADER + COUNT * EXTENT];
        buf[..8].copy_from_slice(&pos.to_ne_bytes());
        buf[8..16].copy_from_slice(&(to - pos).to_ne_bytes());
        buf[24..28].copy_from_slice(&(COUNT as u32).to_ne_bytes());
        appine_hal::ioctl(host.as_raw_fd(), FS_IOC_FIEMAP, &mut buf).ok()?;
        let count = u32::from_ne_bytes(buf[20..24].try_into().ok()?) as usize;
        let old = page;
        for extent in buf[HEADER..].chunks_exact(EXTENT).take(count) {
            let start = u64::from_ne_bytes(extent[..8].try_into().ok()?);
            let len = u64::from_ne_bytes(extent[16..24].try_into().ok()?);
            let gap = last.min(start / TMPFS_PAGE).saturating_sub(page);
            if gap > budget - holes {
                return Some(Err((page + budget - holes) * TMPFS_PAGE));
            }
            holes += gap;
            page = page
                .max(start.saturating_add(len).div_ceil(TMPFS_PAGE))
                .min(last);
        }
        if count < COUNT {
            let gap = last - page;
            return Some(if gap > budget - holes {
                Err((page + budget - holes) * TMPFS_PAGE)
            } else {
                Ok(holes + gap)
            });
        }
        if page <= old {
            return None;
        }
    }
    Some(Ok(holes))
}

/// How many pages of `[from, to)` in host file `host` (`size` bytes long) would need storage
/// when written: holes and pages past the end, found with the host's `SEEK_DATA` and
/// `SEEK_HOLE` (a page holding any data needs none; a host that cannot tell has data everywhere
/// before the end). When more than `budget` are needed, `Err` gives the offset of the first page
/// that no longer fits.
fn seek_holes(
    host: &std::fs::File,
    size: u64,
    from: u64,
    to: u64,
    budget: u64,
) -> Result<u64, u64> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(host);
    let end = to.div_ceil(TMPFS_PAGE);
    let mut page = from / TMPFS_PAGE;
    let mut needed = 0;
    while page < end {
        let at = page * TMPFS_PAGE;
        let data = if at >= size {
            end
        } else {
            match appine_hal::lseek(fd, at as i64, libc::SEEK_DATA) {
                Ok(d) => d / TMPFS_PAGE,
                Err(e) if e == Errno::ENXIO.0 => end,
                Err(_) => page,
            }
        };
        let holes = data.min(end) - page;
        if needed + holes > budget {
            return Err((page + budget - needed) * TMPFS_PAGE);
        }
        needed += holes;
        if data >= end {
            break;
        }
        let hole = appine_hal::lseek(fd, (data * TMPFS_PAGE) as i64, libc::SEEK_HOLE)
            .unwrap_or(size)
            .div_ceil(TMPFS_PAGE);
        page = hole.max(data + 1);
    }
    Ok(needed)
}

/// Page-aligned byte ranges in a tmpfs inode, sorted and coalesced. A single large
/// KEEP_SIZE reservation needs only one entry, including beyond the current EOF.
#[derive(Clone, Default)]
struct PageRuns(Vec<std::ops::Range<u64>>);

impl PageRuns {
    fn add(&mut self, start: u64, end: u64) {
        let lo = self.0.partition_point(|r| r.end < start);
        let hi = self.0.partition_point(|r| r.start <= end);
        let merged = if lo < hi {
            start.min(self.0[lo].start)..end.max(self.0[hi - 1].end)
        } else {
            start..end
        };
        self.0.splice(lo..hi, std::iter::once(merged));
    }

    fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let lo = self.0.partition_point(|r| r.end <= start);
        let hi = self.0.partition_point(|r| r.start < end);
        if lo < hi {
            let head = self.0[lo].start..start;
            let tail = end..self.0[hi - 1].end;
            self.0
                .splice(lo..hi, [head, tail].into_iter().filter(|r| !r.is_empty()));
        }
    }

    /// The first run containing or following this offset.
    fn next(&self, offset: u64) -> Option<&std::ops::Range<u64>> {
        self.0.get(self.0.partition_point(|r| r.end <= offset))
    }

    /// Count missing pages, consulting the host only in gaps between guest allocations.
    fn holes(
        &self,
        from: u64,
        to: u64,
        budget: u64,
        mut missing: impl FnMut(u64, u64, u64) -> Result<u64, u64>,
    ) -> Result<u64, u64> {
        let mut at = from / TMPFS_PAGE * TMPFS_PAGE;
        let mut holes = 0;
        let mut gap = |lo, hi| -> Result<(), u64> {
            let left = budget - holes;
            holes += missing(lo, hi, left)?;
            Ok(())
        };
        let first = self.0.partition_point(|r| r.end <= at);
        for r in self.0[first..].iter().take_while(|r| r.start < to) {
            if at < r.start {
                gap(at, r.start)?;
            }
            at = r.end;
        }
        if at < to {
            gap(at, to)?;
        }
        Ok(holes)
    }
}

#[derive(Default)]
struct TmpfsFileRanges {
    /// Includes reserved pages that are still holes for SEEK_DATA.
    allocated: PageRuns,
    /// Pages instantiated by mapped access even if their backing bytes are still sparse.
    data: PageRuns,
    dev: u64,
}

/// Some hosts emulate fallocate by allocating from byte zero even for a nonzero range.
/// Use logical reservations alone when the object cannot describe physical extents.
pub(crate) fn tmpfs_host_reservations(host: &std::fs::File, offset: u64) -> bool {
    fiemap_holes(host, offset, offset + 1, 0).is_some()
}

fn object_pages(host: &std::fs::File) -> Result<u64, Errno> {
    use std::os::unix::fs::MetadataExt;
    // KEEP_SIZE reservations can extend beyond EOF.
    const END: u64 = 1 << 63;
    if let Some(Ok(holes)) = fiemap_holes(host, 0, END, u64::MAX) {
        Ok(END / TMPFS_PAGE - holes)
    } else {
        Ok(host
            .metadata()
            .map_err(mapping_errno)?
            .blocks()
            .div_ceil(TMPFS_PAGE / 512))
    }
}

/// The object pinned by a tmpfs VMA. Faults allocate one guest page under the BKL,
/// before an engine or kernel memory access can use the host mapping.
pub(crate) struct TmpfsMapping {
    vfs: std::rc::Rc<Vfs>,
    dev: u64,
    pub(crate) ino: Ino,
    file: std::fs::File,
}

impl TmpfsMapping {
    pub(crate) fn new(
        vfs: std::rc::Rc<Vfs>,
        dev: u64,
        ino: Ino,
        fd: i32,
    ) -> Result<std::rc::Rc<Self>, Errno> {
        // Even a read fault into a sparse shmem file instantiates a page. Open the actual
        // mapped object, including an unlinked one, independently of the guest fd's mode.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/self/fd/{fd}"))
            .map_err(mapping_errno)?;
        Ok(std::rc::Rc::new(Self {
            vfs,
            dev,
            ino,
            file,
        }))
    }

    pub(crate) fn punch(&self, offset: u64, len: u64) -> Result<(), Errno> {
        use std::os::fd::AsRawFd;
        let before = self.vfs.tmpfs_file_pages(self.ino, &self.file)?;
        appine_hal::fallocate(
            self.file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset,
            len,
        )
        .map_err(Errno)?;
        self.vfs.tmpfs_forget_pages(self.ino, offset, offset + len);
        let after = self.vfs.tmpfs_file_pages(self.ino, &self.file)?;
        self.vfs
            .tmpfs_charge(self.dev, after as i64 - before as i64, 0);
        self.vfs.tmpfs_update_unlinked(self.dev, self.ino, after);
        Ok(())
    }

    pub(crate) fn fault(&self, offset: u64, shared_write: bool) -> Result<(), Errno> {
        use std::os::fd::AsRawFd;
        let fd = self.file.as_raw_fd();
        let size = self.file.metadata().map_err(mapping_errno)?.len();
        if offset >= size {
            return Err(Errno::EFAULT);
        }
        let end = offset + TMPFS_PAGE;
        let data = appine_hal::lseek(fd, offset as i64, libc::SEEK_DATA);
        let has_data = data.is_ok_and(|d| d < end);
        let missing = !has_data
            && self
                .vfs
                .tmpfs_missing(self.ino, &self.file, size, offset, end, 0)
                .is_err();
        if missing {
            self.vfs.tmpfs_check(self.dev, 1, 0)?;
        }
        if shared_write {
            if !has_data && tmpfs_host_reservations(&self.file, offset) {
                // Reserve storage without overwriting bytes another guest CPU could be writing.
                match appine_hal::fallocate(fd, libc::FALLOC_FL_KEEP_SIZE, offset, TMPFS_PAGE) {
                    Ok(()) | Err(libc::EOPNOTSUPP) => {}
                    Err(e) => return Err(Errno(e)),
                }
            }
            // Some hosts defer mmap write timestamps until writeback. Publish the first
            // shared write fault on the filesystem clock before granting a writable PTE.
            appine_hal::set_times_fd(fd, None, Some(appine_hal::TIME_NOW)).map_err(Errno)?;
        }
        if has_data {
            return Ok(());
        }
        // A shmem fault instantiates this page for subsequent stats and seeks, including
        // private reads. Pure reads and private stores leave the backing file's times alone.
        self.vfs
            .tmpfs_record_pages(self.dev, self.ino, offset, end, true);
        if missing {
            self.vfs.tmpfs_charge(self.dev, 1, 0);
            if let Some(t) = self.vfs.mounts.borrow_mut().tmpfs.get_mut(&self.dev)
                && let Some(file) = t.unlinked.get_mut(&self.ino)
            {
                file.pages += 1;
            }
        }
        Ok(())
    }
}

fn mapping_errno(e: std::io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(libc::EIO))
}

/// tmpfs superblock parameters (these fields of Linux's `shmem_sb_info`): set by mount(2)'s
/// options at mount time; a remount can change the size, the inode count and inode32/64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TmpfsParams {
    /// Permissions, owner and group of the root directory (used only at mount time).
    pub perm: u32,
    pub uid: u32,
    pub gid: u32,
    /// Maximum pages and inodes; 0 is unlimited (`size=0`, `nr_inodes=0`).
    pub blocks: u64,
    pub inodes: u64,
    /// `inode64` (the default) or `inode32`.
    pub inode64: bool,
}

impl TmpfsParams {
    /// A tmpfs mounted at boot: the root directory has permissions `perm` and belongs to root,
    /// and the size and inode count are the defaults.
    fn boot(perm: u32) -> TmpfsParams {
        TmpfsParams {
            perm,
            uid: 0,
            gid: 0,
            blocks: Self::default_limit(),
            inodes: Self::default_limit(),
            inode64: true,
        }
    }

    /// Superblock options in mountinfo (like `,size=1024k,mode=755,inode64`, Linux's
    /// `shmem_show_options`): size and inode count are written only when not the defaults, the
    /// permissions only when not 1777 and owner and group only when not 0, and last comes
    /// `inode64` or `inode32`.
    pub fn options(&self) -> String {
        let default = Self::default_limit();
        let mut s = String::new();
        if self.blocks != default {
            s += &format!(",size={}k", self.blocks * (TMPFS_PAGE / 1024));
        }
        if self.inodes != default {
            s += &format!(",nr_inodes={}", self.inodes);
        }
        if self.perm != 0o1777 {
            s += &format!(",mode={:03o}", self.perm);
        }
        if self.uid != 0 {
            s += &format!(",uid={}", self.uid);
        }
        if self.gid != 0 {
            s += &format!(",gid={}", self.gid);
        }
        s += if self.inode64 { ",inode64" } else { ",inode32" };
        s
    }

    /// Default page and inode counts: half of physical memory (Linux's
    /// `shmem_default_max_blocks` and `shmem_default_max_inodes`, which are equal without high
    /// memory).
    pub fn default_limit() -> u64 {
        appine_hal::memory_info().0 / 2 / TMPFS_PAGE
    }
}

/// A tmpfs instance (Linux's superblock): at mount time a directory not hanging under the root
/// is created in the store ([`Store::create_detached_dir`]), and when its mounts and bind mounts
/// are all gone it is deleted with everything in it. Data is stored in host files as usual and
/// takes no app memory. Usage is limited by page and inode counts as on Linux
/// ([`Vfs::tmpfs_usage`]).
pub(crate) struct Tmpfs {
    /// The root directory.
    pub root: Ino,
    pub params: TmpfsParams,
    /// Recorded usage (pages, inodes), updated on create, delete, write and truncate, and counted
    /// afresh at statfs ([`Vfs::count_tmpfs`]); None means count it the next time it is needed.
    used: Option<(u64, u64)>,
    /// The recorded usage changed since it was last counted, so it may have drifted (for example
    /// through shared mappings): [`Vfs::tmpfs_recount`].
    changed: bool,
    /// Regular files whose last link was removed while still open or mapped, mapped to their last
    /// known page count: their pages and one inode stay charged until their last user closes them
    /// ([`Vfs::evict_tmpfs`]), matching Linux's `shmem_evict_inode`.
    unlinked: HashMap<Ino, UnlinkedTmpfs>,
}

struct UnlinkedTmpfs {
    pages: u64,
    /// O_PATH descriptions carry a node, so retain the backing object across store reaping.
    object: std::fs::File,
}

/// What no-BKL path resolution needs (`syscall::fast`): the store's metadata cache and the mount
/// points.
#[derive(Clone)]
pub(crate) struct Cached {
    meta: Arc<store::Meta>,
    mounts: Arc<[Ino]>,
    /// The root filesystem's mount ([`ROOT_MOUNT`]) is still attached and not nosymfollow: only
    /// threads whose root and current directory are in it can resolve without the BKL.
    pub(crate) usable: bool,
}

impl Cached {
    /// Resolves a path and gets its metadata using only the metadata cache: equivalent to
    /// [`Vfs::resolve`] with credentials that have `CAP_DAC_READ_SEARCH` (no search permission
    /// check) plus [`Store::stat`]. `root` and `cwd` are store directories. Returns None when the
    /// path enters a synthetic filesystem or something needed is not in the cache; the caller
    /// then resolves normally holding the BKL (filling the cache along the way).
    pub(crate) fn stat(
        &self,
        root: Ino,
        cwd: Ino,
        path: &[u8],
        follow: bool,
    ) -> Option<Result<Stat, Errno>> {
        let r = self.meta.reader()?;
        match self.walk(&r, root, cwd, path, follow)? {
            // The no-BKL statx encoder takes only the basic stat bytes. Let the syscall
            // carry the inode flags through resolution when any statx attribute is set.
            Ok(ino) => r
                .stat(ino)
                .filter(|st| st.flags & store::inode_flags::STATX == 0)
                .map(Ok),
            Err(e) => Some(Err(e)),
        }
    }

    /// Corresponds one to one with [`Vfs::walk_in`].
    fn walk(
        &self,
        r: &store::Reader<'_>,
        root: Ino,
        cwd: Ino,
        path: &[u8],
        follow: bool,
    ) -> Option<Result<Ino, Errno>> {
        if path.is_empty() {
            return Some(Err(Errno::ENOENT));
        }
        let mut dir = if path[0] == b'/' { root } else { cwd };
        // Components not yet handled, with the next one on top of the stack; allocates no
        // memory, and leaves it to normal resolution when they do not fit
        let mut pending = Pending::default();
        pending.push(path)?;
        let mut links = 0;
        while let Some(comp) = pending.pop() {
            if comp.is_empty() {
                if r.kind(dir)? != mode::S_IFDIR {
                    return Some(Err(Errno::ENOTDIR));
                }
                continue;
            }
            let last = pending.is_empty();
            let trailing = last || (pending.len == 1 && pending.comps[0].is_empty());
            if comp.len() > NAME_MAX {
                return Some(Err(Errno::ENAMETOOLONG));
            }
            if r.kind(dir)? != mode::S_IFDIR {
                return Some(Err(Errno::ENOTDIR));
            }
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                if dir != root {
                    dir = r.parent(dir)?;
                }
                // Something is mounted on the parent directory (the current directory is under
                // a mount point mounted later)
                if self.mounts.contains(&dir) {
                    return None;
                }
                continue;
            }
            let Some(node) = r.lookup(dir, comp)? else {
                return Some(Err(Errno::ENOENT));
            };
            if self.mounts.contains(&node) {
                return None;
            }
            if r.kind(node)? == mode::S_IFLNK && (!last || follow) {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Some(Err(Errno::ELOOP));
                }
                // fs.protected_symlinks depends on the credentials ([`Vfs::may_follow_link`]):
                // links in sticky, world-writable directories whose owner differs from the
                // directory's are left to normal resolution (including trailing `/` like `link/`)
                let sticky_shared = mode::S_ISVTX | 0o002;
                if trailing
                    && r.stat(dir)?.mode & sticky_shared == sticky_shared
                    && r.stat(dir)?.uid != r.stat(node)?.uid
                {
                    return None;
                }
                let target = r.readlink(node)?;
                if target.first() == Some(&b'/') {
                    dir = root;
                }
                pending.push(target)?;
                continue;
            }
            dir = node;
        }
        Some(Ok(dir))
    }
}

/// Path components [`Cached::walk`] has not handled yet (the result of [`components`] in
/// reverse).
struct Pending<'p> {
    comps: [&'p [u8]; 64],
    len: usize,
}

impl Default for Pending<'_> {
    fn default() -> Self {
        Pending {
            comps: [&[]; 64],
            len: 0,
        }
    }
}

impl<'p> Pending<'p> {
    /// Puts `path`'s components at the front; returns None when they do not fit. An empty slice
    /// marks a trailing `/` (forcing a directory while keeping the preceding component trailing
    /// for `protected_symlinks`).
    fn push(&mut self, path: &'p [u8]) -> Option<()> {
        if path.ends_with(b"/") {
            self.push_one(b"")?;
        }
        for c in path.rsplit(|&b| b == b'/').filter(|c| !c.is_empty()) {
            self.push_one(c)?;
        }
        Some(())
    }

    fn push_one(&mut self, comp: &'p [u8]) -> Option<()> {
        *self.comps.get_mut(self.len)? = comp;
        self.len += 1;
        Some(())
    }

    fn pop(&mut self) -> Option<&'p [u8]> {
        self.len = self.len.checked_sub(1)?;
        Some(self.comps[self.len])
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Vfs {
    pub(crate) fn anon_attrs<R>(
        &self,
        target: &AnonTarget,
        cred: &Cred,
        f: impl FnOnce(&mut AnonAttrs) -> R,
    ) -> R {
        let mut table = self.anon.borrow_mut();
        let key = target.key();
        if let Some(entry) = table.get_mut(&key) {
            return f(&mut entry.attrs);
        }
        // A weak socket reference reserves its allocation (and therefore its inode number).
        // Base the next sweep on live entries, amortizing the scan across insertions.
        if table.len() >= self.anon_prune_at.get() {
            table.retain(|_, e| match &e.object {
                AnonWeak::Pipe(p) => p.strong_count() != 0,
                AnonWeak::Socket(s) => s.strong_count() != 0,
            });
            self.anon_prune_at
                .set(256.max(table.len().saturating_mul(2)));
        }
        f(&mut table.entry(key).or_insert_with(|| target.entry(cred)).attrs)
    }

    pub(crate) fn pipe_io_time(&self, pipe: &crate::pipe::Pipe, write: bool) {
        // A named FIFO uses a store inode number, which can equal an anonymous pipe number.
        if pipe.fifo.is_some() {
            return;
        }
        if let Some(entry) = self.anon.borrow_mut().get_mut(&AnonKey::Pipe(pipe.ino)) {
            let now = crate::tty::wall_ns();
            if write {
                entry.attrs.mtime_ns = now;
                entry.attrs.ctime_ns = now;
            } else {
                entry.attrs.atime_ns = now;
            }
        }
    }

    /// Opens the inode store in `dir` as the root filesystem, adds the standard device nodes,
    /// and mounts the boot filesystems (the same as systemd and container runtimes mount):
    /// procfs; a tmpfs on `/dev` (the standard device nodes are created in it,
    /// [`dev::populate`]) with devpts, the `/dev/shm` tmpfs and mqueue in it; sysfs and cgroup2;
    /// the `/run` tmpfs.
    /// At boot (when no other process is using this store) it also empties /dev/shm and /run in
    /// the store: no tmpfs used to be mounted on them, and the shared memory and pid files left
    /// there must not stay.
    pub fn open(dir: &Path) -> Result<Vfs, Errno> {
        Self::open_with_gpu(dir, false)
    }

    pub(crate) fn open_with_gpu(dir: &Path, gpu: bool) -> Result<Vfs, Errno> {
        let store = Store::open(dir, &[b"dev/shm", b"run"])?;
        if let Err(e) = dev::ensure_dev_nodes(&store) {
            crate::debug::log(format_args!("cannot create the device nodes: {e}"));
        }
        if let Err(e) = ensure_resolv_conf(&store) {
            crate::debug::log(format_args!("cannot create /etc/resolv.conf: {e}"));
        }
        // The same as Linux distributions' default mount options
        let flags = ms::NOSUID | ms::NODEV | ms::NOEXEC | ms::RELATIME;
        let mut mounts = Mounts {
            list: vec![Mount {
                id: ROOT_MOUNT,
                ns: INIT_MNT_NS,
                fs: Fs::Store,
                root: Node::ROOT,
                point: None,
                at: None,
                root_at: None,
                root_gone: false,
                flags: ROOT_FLAGS,
                dev: ROOT_DEV,
                source: b"appine".to_vec(),
                expiring: false,
                pin: None,
                locks: 0,
                prop: Propagation::default(),
                owner: None,
            }],
            detached: Vec::new(),
            by_id: HashMap::from([(ROOT_MOUNT, MountLoc::Attached(0))]),
            children: HashMap::new(),
            next: RUN_MOUNT + 1,
            next_dev: 0x30,
            tmpfs: Default::default(),
            proc_ns: Default::default(),
            sys_ns: Default::default(),
            mq_dev: Default::default(),
            devpts: Default::default(),
            sb_flags: Default::default(),
            collect_pending: false,
        };
        // The directory named `name` under directory `dir` in mount `mnt`
        let subdir = |dir: Option<&Node>, name: &[u8]| -> Option<Node> {
            let &Node::Store(mnt, dir) = dir? else {
                return None;
            };
            let ino = store.lookup(dir, name).ok().flatten()?;
            store
                .stat(ino)
                .is_ok_and(|st| st.is_dir())
                .then_some(Node::Store(mnt, ino))
        };
        let root = Some(Node::ROOT);
        let pseudo = |id: MountId, fs: Fs| (fs, fs.root().in_mount(id), fs.dev());
        mounts.boot(
            PROC_MOUNT,
            pseudo(PROC_MOUNT, Fs::Proc),
            subdir(root.as_ref(), b"proc"),
            flags,
            b"proc",
        );
        // /dev: falls back to the store directory when the tmpfs cannot be created
        let dev = subdir(root.as_ref(), b"dev").map(|point| {
            let r = mounts.boot_tmpfs(
                &store,
                DEV_MOUNT,
                point.clone(),
                ms::NOSUID | ms::RELATIME,
                b"tmpfs",
                TmpfsParams::boot(0o755),
            );
            match r.and_then(|ino| dev::populate(&store, ino).map(|()| ino)) {
                Ok(ino) => Node::Store(DEV_MOUNT, ino),
                Err(e) => {
                    crate::debug::log(format_args!("cannot mount /dev: {e}"));
                    mounts.list.retain(|m| m.id != DEV_MOUNT);
                    mounts.rebuild_index();
                    point
                }
            }
        });
        if gpu {
            if let Some(Node::Store(DEV_MOUNT, ino)) = &dev {
                dev::populate_gpu(&store, *ino)?;
            } else {
                return Err(Errno::ENODEV);
            }
        }
        mounts.boot(
            PTS_MOUNT,
            pseudo(PTS_MOUNT, Fs::Pts),
            subdir(dev.as_ref(), b"pts"),
            flags & !ms::NODEV,
            b"devpts",
        );
        if let Some(point) = subdir(dev.as_ref(), b"shm") {
            let params = TmpfsParams::boot(0o1777);
            let flags = ms::NOSUID | ms::NODEV | ms::RELATIME;
            if let Err(e) = mounts.boot_tmpfs(&store, SHM_MOUNT, point, flags, b"shm", params) {
                crate::debug::log(format_args!("cannot mount /dev/shm: {e}"));
            }
        }
        mounts.boot(
            MQUEUE_MOUNT,
            pseudo(MQUEUE_MOUNT, Fs::Mqueue),
            subdir(dev.as_ref(), b"mqueue"),
            flags,
            b"mqueue",
        );
        mounts.boot(
            SYS_MOUNT,
            pseudo(SYS_MOUNT, Fs::Sys),
            subdir(root.as_ref(), b"sys"),
            flags,
            b"sysfs",
        );
        // cgroup2 is mounted on sysfs's fs/cgroup and is writable as on a Linux host: dockerd and
        // runc create the containers' cgroups in it
        if mounts.list.iter().any(|m| m.id == SYS_MOUNT) {
            mounts.boot(
                CGROUP_MOUNT,
                pseudo(CGROUP_MOUNT, Fs::Cgroup),
                Some(Node::Pseudo(SYS_MOUNT, crate::pseudo::CGROUP_POINT)),
                flags,
                b"cgroup",
            );
        }
        // /run: as systemd and OpenRC mount it, 20% of physical memory and 800k inodes
        if let Some(point) = subdir(root.as_ref(), b"run") {
            let params = TmpfsParams {
                blocks: appine_hal::memory_info().0 / 5 / TMPFS_PAGE,
                inodes: 800 << 10,
                ..TmpfsParams::boot(0o755)
            };
            let flags = ms::NOSUID | ms::NODEV | ms::RELATIME;
            if let Err(e) = mounts.boot_tmpfs(&store, RUN_MOUNT, point, flags, b"tmpfs", params) {
                crate::debug::log(format_args!("cannot mount /run: {e}"));
            }
        }
        let cached = Cached {
            meta: store.meta().clone(),
            mounts: mounts.store_points(),
            usable: mounts.fast_usable(),
        };
        Ok(Vfs {
            store,
            mounts: RefCell::new(mounts),
            cached: RefCell::new(cached),
            executables: Default::default(),
            init_ns: std::rc::Rc::new(MntNs {
                id: INIT_MNT_NS,
                owner: crate::cred::UserNs::init(),
                anon: false,
            }),
            namespaces: Default::default(),
            overlays: Default::default(),
            fuse: Default::default(),
            ns_events: RefCell::new(HashMap::from([(
                INIT_MNT_NS,
                std::rc::Rc::new(std::cell::Cell::new(1)),
            )])),
            expiring: std::cell::Cell::new(0),
            anon: RefCell::default(),
            anon_prune_at: std::cell::Cell::new(256),
            removed_dirs: RefCell::default(),
            memfd_sizes: RefCell::default(),
            tmpfs_file_ranges: RefCell::default(),
        })
    }

    /// Opens the regular file `ino` in the store as a file to execute
    /// ([`crate::loader::ExeCache`]).
    pub(crate) fn executable(&self, ino: Ino) -> Result<crate::loader::Executable, Errno> {
        self.executables
            .open(ino, || self.store.open_object(ino, false))
    }

    /// Inode `ino`'s data moved to another object: the recorded program file of it goes.
    pub(crate) fn forget_executable(&self, ino: Ino) {
        self.executables.forget(ino);
    }

    /// Drops the recorded program files (when host memory is tight).
    pub(crate) fn trim(&self) {
        self.executables.clear();
    }

    /// The underlying inode store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// What no-BKL path resolution needs. Must be fetched again after the mount table changes
    /// ([`Shared::fast_changed`]).
    ///
    /// [`Shared::fast_changed`]: crate::kernel::Shared::fast_changed
    pub(crate) fn cached(&self) -> Cached {
        self.cached.borrow().clone()
    }

    // ---- Path resolution ----

    /// Resolves a path with credentials `cred` and root directory `root`. With `follow` false a
    /// symlink in the last component is not followed (lstat, readlink and so on).
    pub(crate) fn resolve(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
        follow: bool,
    ) -> Result<Node, Errno> {
        self.walk(ps, cred, root, cwd, path, follow)
            .map(|(node, _)| node)
    }

    /// [`resolve`](Self::resolve), also returning the directory and name where the result was
    /// last found; there are none when the result came through `.`, `..`, the root directory or
    /// a link in a synthetic filesystem.
    pub(crate) fn walk(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
        follow: bool,
    ) -> Result<(Node, Option<Dentry>), Errno> {
        self.walk_resolve(ps, cred, root, cwd, path, follow, 0)
            .map(|(node, found)| (node, found.map(|d| d.entry)))
    }

    /// [`resolve`](Self::resolve) for `umount2` (Linux's `LOOKUP_MOUNTPOINT` + `mntput_no_expire`):
    /// resolves the target path without clearing `MNT_EXPIRE` marks on the looked-up mount.
    pub(crate) fn resolve_mountpoint(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
        follow: bool,
    ) -> Result<Node, Errno> {
        self.store
            .snapshot(|_| self.walk_in(ps, cred, root, cwd, path, follow, 0, false))
            .map(|(node, _)| node)
    }

    /// [`walk`](Self::walk) with openat2's restrictions ([`resolve`]). With a scope (`BENEATH`,
    /// `IN_ROOT`) `root` is the start.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn walk_resolve(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
        follow: bool,
        flags: u64,
    ) -> Result<(Node, Option<WalkDentry>), Errno> {
        self.store
            .snapshot(|_| self.walk_in(ps, cred, root, cwd, path, follow, flags, true))
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_in(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
        follow: bool,
        flags: u64,
        touch: bool,
    ) -> Result<(Node, Option<WalkDentry>), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        // A leading / jumps to the root (path_init's nd_jump_root): not allowed under BENEATH;
        // under IN_ROOT the root is the start; NO_XDEV only governs jumps during resolution
        let mut dir = if path[0] == b'/' {
            if flags & resolve::BENEATH != 0 {
                return Err(Errno::EXDEV);
            }
            root.clone()
        } else {
            cwd.clone()
        };
        if touch {
            self.touch_mount(dir.mnt());
        }
        // Whether Linux's nd->root has been taken: absolute paths and scoped resolution take it
        // at the start, otherwise it is taken at the first `..` or the first jump to the root.
        // Under NO_XDEV a jump to the root (a symlink to an absolute path) before it is taken is
        // always EXDEV: nd_jump_root compares the current mount with the empty nd->root.mnt
        let mut root_set = path[0] == b'/' || flags & resolve::SCOPED != 0;
        let mut found = None;
        let mut pending = components(path);
        let mut links = 0;
        while let Some(step) = pending.pop_front() {
            let comp = match step {
                Step::TrailingSlash => {
                    if !self.is_dir(ps, &dir)? {
                        return Err(Errno::ENOTDIR);
                    }
                    self.may_search(ps, cred, &dir)?;
                    continue;
                }
                Step::Name(comp) => comp,
            };
            let last = pending.is_empty();
            let trailing =
                last || (pending.len() == 1 && matches!(pending[0], Step::TrailingSlash));
            if comp.len() > NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
            // The node before every component (including . and ..) must be a directory: file/.
            // and file/ are ENOTDIR
            if !self.is_dir(ps, &dir)? {
                return Err(Errno::ENOTDIR);
            }
            self.may_search(ps, cred, &dir)?;
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                // At the start (follow_dotdot's in_root): BENEATH cannot get out; going past a
                // mount's root, or back to a directory with something mounted on it (entering
                // that mount), crosses mounts
                if dir == *root && flags & resolve::BENEATH != 0 {
                    return Err(Errno::EXDEV);
                }
                root_set = true;
                let up = self.dotdot(ps, root, dir.clone())?;
                if flags & resolve::NO_XDEV != 0 && up.mnt() != dir.mnt() {
                    return Err(Errno::EXDEV);
                }
                dir = up;
                if touch {
                    self.touch_mount(dir.mnt());
                }
                found = None;
                continue;
            }
            let node = match self.lookup_walk(ps, &dir, &comp, &pending) {
                Err(e) if e == Errno::ENOENT => {
                    ps.missing(&dir, &comp);
                    return Err(e);
                }
                r => r?,
            };
            if touch {
                self.touch_mount(node.mnt());
            }
            // Something is mounted on the name: enter that mount (traverse_mounts)
            if flags & resolve::NO_XDEV != 0 && node.mnt() != dir.mnt() {
                return Err(Errno::EXDEV);
            }
            if self.kind(ps, &node)? == mode::S_IFLNK && (!last || follow) {
                links += 1;
                if links > MAX_SYMLINKS {
                    return Err(Errno::ELOOP);
                }
                // fs.protected_symlinks applies to the last component, including one followed by
                // trailing `/` (pick_link's WALK_TRAILING), before nosymfollow
                if trailing
                    && ps.protected_symlinks()
                    && let (Node::Store(_, link), Node::Store(_, parent)) = (&node, &dir)
                {
                    self.may_follow_link(cred, *parent, *link)?;
                }
                // Symlinks (magic links included) in a nosymfollow mount, and any symlink under
                // RESOLVE_NO_SYMLINKS, are not followed (Linux's pick_link)
                if flags & resolve::NO_SYMLINKS != 0
                    || self
                        .mount_flags(&node)
                        .is_some_and(|f| f & ms::NOSYMFOLLOW != 0)
                {
                    return Err(Errno::ELOOP);
                }
                // Magic links (nd_jump_link): first check whether that process may be viewed,
                // then the restrictions
                let magic = matches!(&node, Node::Pseudo(_, p) if ps.magic(p));
                let jump = match &node {
                    Node::Pseudo(id, p) => ps.follow(*id, p).transpose()?,
                    Node::Store(..) | Node::Overlay(..) | Node::Fuse(..) => None,
                };
                if magic {
                    if flags & resolve::NO_MAGICLINKS != 0 {
                        return Err(Errno::ELOOP);
                    }
                    if let Some(target) = &jump
                        && flags & resolve::NO_XDEV != 0
                        && target.mnt() != dir.mnt()
                    {
                        return Err(Errno::EXDEV);
                    }
                    if flags & resolve::SCOPED != 0 {
                        return Err(Errno::EXDEV);
                    }
                }
                if let (Node::Pseudo(_, p), Some(target)) = (&node, jump) {
                    dir = target;
                    if touch {
                        self.touch_mount(dir.mnt());
                    }
                    found = if last { ps.follow_dentry(p) } else { None };
                    continue;
                }
                let target = self.readlink(ps, &node)?;
                // Symlinks to absolute paths (nd_jump_root): not allowed under BENEATH; under
                // NO_XDEV the root must already have been taken and be in the same mount as the
                // link's directory
                if target.first() == Some(&b'/') {
                    if flags & resolve::BENEATH != 0
                        || (flags & resolve::NO_XDEV != 0 && (!root_set || dir.mnt() != root.mnt()))
                    {
                        return Err(Errno::EXDEV);
                    }
                    root_set = true;
                    dir = root.clone();
                    found = None;
                }
                for c in components(&target).into_iter().rev() {
                    pending.push_front(c);
                }
                continue;
            }
            found = Some(WalkDentry {
                entry: (std::mem::replace(&mut dir, node), comp),
                unlinked: false,
            });
        }
        Ok((dir, found))
    }

    /// Whether a process with credentials `cred` can look up in directory `dir`. Directories of
    /// synthetic filesystems can unless their view says otherwise ([`Pseudo::searched`]: cgroup
    /// directories).
    fn may_search(&self, ps: &dyn Pseudo, cred: &Cred, dir: &Node) -> Result<(), Errno> {
        match dir {
            Node::Pseudo(_, p) if !cred.searches_all() => match ps.searched(p) {
                Some(st) => cred.permission(&st, MAY_EXEC),
                None => Ok(()),
            },
            Node::Store(_, ino) if !cred.searches_all() => {
                cred.permission(&self.store.stat(*ino)?, MAY_EXEC)
            }
            Node::Overlay(_, o) if !cred.searches_all() => {
                let real = self.overlays.borrow().node(*o).real();
                cred.permission(&self.store.attrs(real)?, MAY_EXEC)
            }
            Node::Fuse(_, f) => self.fuse_permission(cred, *f, MAY_EXEC),
            _ => Ok(()),
        }
    }

    /// Whether a process with credentials `cred` may access FUSE node `id` with `mask` (6.1's
    /// `fuse_permission` without `MAY_ACCESS` or `MAY_CHDIR`): never unless the mount allows that
    /// process; then with `default_permissions` as the node's attributes say (fetched again when
    /// they are out of date, [`fuse::need`]), and without it as the daemon decides, except that
    /// executing a regular file needs some execute bit.
    pub(crate) fn fuse_permission(
        &self,
        cred: &Cred,
        id: fuse::FuseId,
        mask: u32,
    ) -> Result<(), Errno> {
        let (allowed, default_permissions) = {
            let f = self.fuse.borrow();
            let conn = f.conn_of(id)?;
            let c = conn.borrow();
            (c.allows(cred), c.opts.default_permissions)
        };
        if !allowed {
            return Err(Errno::EACCES);
        }
        let exec_regular =
            mask & MAY_EXEC != 0 && self.fuse.borrow().node(id).kind() == mode::S_IFREG;
        if default_permissions {
            if cred.searches_all() && !exec_regular && mask & !MAY_EXEC == 0 {
                return Ok(());
            }
            return cred.permission(&fuse::cached_attr(self, id)?.stat(), mask);
        }
        if exec_regular && fuse::cached_attr(self, id)?.mode & 0o111 == 0 {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// `..` in a path (Linux's `follow_dotdot`): stays put at the root directory; at a mount's
    /// root it first goes back to the mount point (one level at a time through stacked mounts),
    /// then takes the parent, and enters the mount on the parent when something is mounted there.
    fn dotdot(&self, ps: &dyn Pseudo, root: &Node, mut dir: Node) -> Result<Node, Errno> {
        loop {
            if dir == *root {
                return Ok(dir);
            }
            match self.point_of(&dir) {
                Some(point) => dir = point,
                None => break,
            }
        }
        let up = self.parent_in_fs(ps, &dir)?;
        // A directory renamed out of a bind's subtree through another mount is disconnected from
        // the bind: its parent is not visible through it (Linux's path_connected)
        if let Node::Store(mnt, up_ino) = up
            && let Some(Node::Store(_, top)) = self.with_mount(mnt, |m| m.root.clone())
            && top != ROOT
            && !self.store_below(up_ino, top)
        {
            return Err(Errno::ENOENT);
        }
        Ok(self.mounted(up))
    }

    /// Whether store directory `dir` is `top` or inside it (Linux's `is_subdir`).
    fn store_below(&self, mut dir: Ino, top: Ino) -> bool {
        loop {
            if dir == top {
                return true;
            }
            match self.store.parent(dir) {
                Ok(up) if up != dir => dir = up,
                _ => return false,
            }
        }
    }

    /// Whether, with `fs.protected_symlinks` on, symlink `link` in directory `dir` may be
    /// followed (Linux's `may_follow_link`): someone else's link in a sticky, world-writable
    /// directory (/tmp) is followed only when the link's owner is the directory's owner, for root
    /// too; otherwise EACCES.
    fn may_follow_link(&self, cred: &Cred, dir: Ino, link: Ino) -> Result<(), Errno> {
        let link = self.store.stat(link)?;
        if link.uid == cred.fsuid {
            return Ok(());
        }
        let dir = self.store.stat(dir)?;
        let sticky_shared = mode::S_ISVTX | 0o002;
        if dir.mode & sticky_shared != sticky_shared || dir.uid == link.uid {
            return Ok(());
        }
        Err(Errno::EACCES)
    }

    /// Resolves the parent directory of a path, returning the parent and the last component
    /// (with trailing `/` removed).
    ///
    /// The last component may be `.` or `..`, for the caller to handle; for the path `/` it
    /// returns `(ROOT, ".")`.
    pub(crate) fn resolve_parent<'p>(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &'p [u8],
    ) -> Result<(Node, &'p [u8]), Errno> {
        self.resolve_parent_with(ps, cred, root, cwd, path, 0)
    }

    /// [`resolve_parent`](Self::resolve_parent) with openat2's restrictions ([`resolve`]).
    pub(crate) fn resolve_parent_with<'p>(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &'p [u8],
        flags: u64,
    ) -> Result<(Node, &'p [u8]), Errno> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let end = path.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
        let trimmed = &path[..end];
        if trimmed.is_empty() {
            if flags & resolve::BENEATH != 0 {
                return Err(Errno::EXDEV);
            }
            return Ok((root.clone(), b"."));
        }
        let (dir, name) = match trimmed.iter().rposition(|&b| b == b'/') {
            Some(i) => (
                self.walk_resolve(ps, cred, root, cwd, &trimmed[..=i], true, flags)?
                    .0,
                &trimmed[i + 1..],
            ),
            None => (cwd.clone(), trimmed),
        };
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if !self.is_dir(ps, &dir)? {
            return Err(Errno::ENOTDIR);
        }
        Ok((dir, name))
    }

    /// The absolute path of the file a path points at, with all symlinks resolved
    /// ([`found_path`](Self::found_path)).
    #[cfg(test)]
    pub(crate) fn real_path(
        &self,
        ps: &dyn Pseudo,
        cred: &Cred,
        root: &Node,
        cwd: &Node,
        path: &[u8],
    ) -> Result<Vec<u8>, Errno> {
        let (node, found) = self.walk(ps, cred, root, cwd, path, true)?;
        self.found_path(ps, root, &node, found.as_ref())
    }

    /// The absolute path of the `node` [`walk`](Self::walk) found, computed from the directory
    /// and name `found` where it was last found, with all symlinks resolved (`/proc/<pid>/exe`,
    /// as with Linux's `d_path`). A file reached through `/proc/<pid>/fd/<n>`, whose name is
    /// unknown, reports ENOENT.
    pub(crate) fn found_path(
        &self,
        ps: &dyn Pseudo,
        root: &Node,
        node: &Node,
        found: Option<&Dentry>,
    ) -> Result<Vec<u8>, Errno> {
        match found {
            Some((dir, name)) => {
                let mounts = self.mounts.borrow();
                let (mut p, _, deleted) =
                    self.reach_in(ps, root, dir, |id| mounts.get(id), true)?;
                if p != b"/" {
                    p.push(b'/');
                }
                p.extend_from_slice(name);
                if deleted {
                    p.extend_from_slice(b" (deleted)");
                }
                Ok(p)
            }
            None if self.is_dir(ps, node)? => self.path_of(ps, root, node),
            None => Err(Errno::ENOENT),
        }
    }

    /// The absolute path of a directory relative to root `root` (Linux's `d_path`:
    /// `/proc/<pid>/cwd`, `/proc/<pid>/root`, the path recorded for open files). A directory not
    /// under `root` gets no mark, as on Linux, and the path counts from the store's root; in a
    /// detached mount it counts from that mount's root. A removed directory gets ` (deleted)`
    /// appended instead of failing with ENOENT. Use [`reach`](Self::reach) when a removed
    /// directory must fail with ENOENT (getcwd) or to know whether it is reachable.
    pub(crate) fn path_of(
        &self,
        ps: &dyn Pseudo,
        root: &Node,
        dir: &Node,
    ) -> Result<Vec<u8>, Errno> {
        let mounts = self.mounts.borrow();
        let (mut path, _, deleted) = self.reach_in(ps, root, dir, |id| mounts.get(id), true)?;
        if deleted {
            path.extend_from_slice(b" (deleted)");
        }
        Ok(path)
    }

    /// [`path_of`](Self::path_of) for live directories, also returning whether it is reachable
    /// from `root`: when it is not, getcwd starts with `(unreachable)` and mountinfo does not
    /// list it; a removed directory returns ENOENT.
    pub(crate) fn reach(
        &self,
        ps: &dyn Pseudo,
        root: &Node,
        dir: &Node,
    ) -> Result<(Vec<u8>, bool), Errno> {
        let mounts = self.mounts.borrow();
        let (path, reached, _) = self.reach_in(ps, root, dir, |id| mounts.get(id), false)?;
        Ok((path, reached))
    }

    /// Records the former name of a removed store directory while referenced.
    pub(crate) fn record_removed_dir(&self, ino: Ino, name: &[u8]) {
        self.removed_dirs.borrow_mut().insert(ino, name.to_vec());
    }

    /// Whether any removed store directory names are currently tracked.
    pub(crate) fn has_removed_dirs(&self) -> bool {
        !self.removed_dirs.borrow().is_empty()
    }

    /// Whether `ino` is the parent of a currently tracked removed store directory.
    pub(crate) fn is_removed_dir_parent(&self, ino: Ino) -> bool {
        self.removed_dirs
            .borrow()
            .keys()
            .any(|&child| self.store.parent(child).ok() == Some(ino))
    }

    /// Drops removed-directory names that are no longer referenced by `kept` or their ancestors.
    pub(crate) fn prune_removed_dirs(&self, kept: &std::collections::HashSet<Ino>) {
        if self.removed_dirs.borrow().is_empty() {
            return;
        }
        let mut removed = self.removed_dirs.borrow_mut();
        let mut live = std::collections::HashSet::new();
        for &ino in kept {
            let mut cur = ino;
            while removed.contains_key(&cur) && live.insert(cur) {
                match self.store.parent(cur) {
                    Ok(parent) if parent != cur => cur = parent,
                    _ => break,
                }
            }
        }
        removed.retain(|ino, _| live.contains(ino));
    }

    /// Attached mounts in mount namespace `ns`, in mount order, each with its mount point's path
    /// from `root` when reachable from it (mountinfo). Mounts are looked up by id in O(1) through
    /// `Mounts::by_id`: a scan of the table at each step up made listing a large table quadratic
    /// (65,000 mounts took 17 s under the BKL, and busybox's umount reads the list).
    pub(crate) fn mounts_from(
        &self,
        ps: &dyn Pseudo,
        root: &Node,
        ns: u64,
    ) -> Vec<(Mount, Option<Vec<u8>>)> {
        let mounts = self.mounts.borrow();
        mounts
            .list
            .iter()
            .filter(|m| m.ns == ns)
            .map(|m| {
                let path = match self.reach_in(ps, root, &m.root, |id| mounts.get(id), false) {
                    Ok((path, true, _)) => Some(path),
                    _ => None,
                };
                (m.clone(), path)
            })
            .collect()
    }

    /// Whether directory `node` itself has been unlinked (for the `cur == *root` case where the
    /// climb loop exits immediately).
    fn is_dir_deleted(&self, node: &Node) -> bool {
        match node {
            Node::Store(_, ino) => {
                *ino != ROOT
                    && self.store.parent(*ino).ok().is_some_and(|p| p != *ino)
                    && self.store.attrs(*ino).is_ok_and(|st| st.nlink == 0)
            }
            Node::Overlay(_, o) => {
                let ovl = self.overlays.borrow();
                ovl.parent(*o) != *o && !ovl.linked(*o)
            }
            Node::Fuse(_, f) => self
                .fuse
                .borrow()
                .get(*f)
                .is_some_and(|n| n.parent != *f && n.unlinked),
            Node::Pseudo(..) => false,
        }
    }

    /// [`reach`](Self::reach), looking mounts (attached or detached) up by id through `find`.
    /// When `allow_deleted` is true, removed directories are reconstructed from their former names
    /// and flagged via the third tuple element; when false, a removed directory returns ENOENT.
    fn reach_in<'m>(
        &self,
        ps: &dyn Pseudo,
        root: &Node,
        dir: &Node,
        find: impl Fn(MountId) -> Option<&'m Mount>,
        allow_deleted: bool,
    ) -> Result<(Vec<u8>, bool, bool), Errno> {
        let mut names = Vec::new();
        let mut cur = dir.clone();
        let mut reached = true;
        let mut deleted = false;
        if cur == *root && self.is_dir_deleted(&cur) {
            if !allow_deleted {
                return Err(Errno::ENOENT);
            }
            deleted = true;
        }
        loop {
            if cur == *root {
                break;
            }
            let mount = find(cur.mnt()).filter(|m| m.root == cur);
            // The root of a mount with a mount point (detached ones have none)
            if let Some(point) = mount.and_then(|m| m.point.clone()) {
                match mount.and_then(|m| m.at.clone()) {
                    // Mounted on a file: through the directory and name recorded at mount
                    // time
                    Some((dir, name)) => {
                        names.push(name);
                        cur = dir;
                    }
                    None => cur = point,
                }
                continue;
            }
            // The root of the mount tree, or the root of a detached mount
            if mount.is_some() {
                reached = false;
                break;
            }
            match cur {
                // Renamed and no longer in the part the mount sees
                Node::Store(_, ROOT) => {
                    reached = false;
                    break;
                }
                Node::Store(id, ino) => {
                    let parent = self.store.parent(ino)?;
                    // The root of a tmpfs: its parent is itself
                    if parent == ino {
                        reached = false;
                        break;
                    }
                    match self.store.name_of(parent, ino)? {
                        Some(name) => names.push(name),
                        None => {
                            if !allow_deleted {
                                return Err(Errno::ENOENT);
                            }
                            let name = self
                                .removed_dirs
                                .borrow()
                                .get(&ino)
                                .cloned()
                                .ok_or(Errno::ENOENT)?;
                            deleted = true;
                            names.push(name);
                        }
                    }
                    cur = Node::Store(id, parent);
                }
                Node::Pseudo(id, p) => match ps.parent(&p) {
                    Some(up) => {
                        names.push(ps.name(id, &p));
                        cur = Node::Pseudo(id, up);
                    }
                    // The root of a detached mount (MNT_DETACH)
                    None => {
                        reached = false;
                        break;
                    }
                },
                Node::Overlay(id, o) => {
                    let ovl = self.overlays.borrow();
                    let up = ovl.parent(o);
                    // The root of an instance whose mount is not this one
                    if up == o {
                        reached = false;
                        break;
                    }
                    // A removed directory, as in the store
                    if !ovl.linked(o) {
                        if !allow_deleted {
                            return Err(Errno::ENOENT);
                        }
                        deleted = true;
                    }
                    names.push(ovl.node(o).name.clone());
                    cur = Node::Overlay(id, up);
                }
                Node::Fuse(id, f) => {
                    let fuse = self.fuse.borrow();
                    let Some(n) = fuse.get(f) else {
                        reached = false;
                        break;
                    };
                    // The root of an instance whose mount is not this one
                    if n.parent == f {
                        reached = false;
                        break;
                    }
                    if n.unlinked {
                        if !allow_deleted {
                            return Err(Errno::ENOENT);
                        }
                        deleted = true;
                    }
                    names.push(n.name.clone());
                    cur = Node::Fuse(id, n.parent);
                }
            }
        }
        let mut out = Vec::new();
        if names.is_empty() {
            out.push(b'/');
        }
        for name in names.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(name);
        }
        Ok((out, reached, deleted))
    }

    /// Whether it is a directory.
    pub(crate) fn is_dir(&self, ps: &dyn Pseudo, node: &Node) -> Result<bool, Errno> {
        Ok(self.kind(ps, node)? == mode::S_IFDIR)
    }

    /// The node's file type bits.
    pub(crate) fn kind(&self, ps: &dyn Pseudo, node: &Node) -> Result<u32, Errno> {
        match node {
            Node::Store(_, ino) => self.store.kind(*ino),
            Node::Pseudo(_, p) => ps.kind(p),
            Node::Overlay(_, o) => self.store.kind(self.overlays.borrow().node(*o).real()),
            Node::Fuse(_, f) => Ok(self.fuse.borrow().get(*f).ok_or(Errno::ENOTCONN)?.kind()),
        }
    }

    /// Directory `dir` already has `name` (`.` and `..` always exist): before creating in it,
    /// ahead of the check whether the directory can be modified (Linux's `filename_create`).
    pub(crate) fn has_child(&self, ps: &dyn Pseudo, dir: &Node, name: &[u8]) -> bool {
        name == b"." || name == b".." || self.lookup(ps, dir, name).is_ok()
    }

    /// Looks up a name (not `.` or `..`) in a directory.
    fn lookup(&self, ps: &dyn Pseudo, dir: &Node, name: &[u8]) -> Result<Node, Errno> {
        let child = match dir {
            Node::Store(id, ino) => {
                Node::Store(*id, self.store.lookup(*ino, name)?.ok_or(Errno::ENOENT)?)
            }
            Node::Pseudo(id, p) => Node::Pseudo(*id, ps.lookup(*id, p, name)?),
            Node::Overlay(id, o) => Node::Overlay(
                *id,
                self.overlays.borrow_mut().lookup(&self.store, *o, name)?,
            ),
            Node::Fuse(id, f) => Node::Fuse(*id, self.fuse_child(*f, name)?),
        };
        Ok(self.mounted(child))
    }

    /// Looks up a name during [`walk_in`], batching consecutive uncached plain FUSE components
    /// into one [`fuse::Query::LookupWalk`] retry so multi-component walks stay O(n) instead of
    /// restarting from the root on every component.
    fn lookup_walk(
        &self,
        ps: &dyn Pseudo,
        dir: &Node,
        name: &[u8],
        pending: &VecDeque<Step>,
    ) -> Result<Node, Errno> {
        let Node::Fuse(mnt, f) = *dir else {
            return self.lookup(ps, dir, name);
        };
        if name.len() > fuse::NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if let Some(res) = self.fuse.borrow().cached_child(f, name) {
            return Ok(self.mounted(Node::Fuse(mnt, res?)));
        }
        let mut extra = pending
            .iter()
            .map_while(|step| match step {
                Step::Name(c)
                    if !c.is_empty()
                        && c.as_slice() != b"."
                        && c.as_slice() != b".."
                        && c.len() <= fuse::NAME_MAX =>
                {
                    Some(c)
                }
                _ => None,
            })
            .peekable();
        let q = if extra.peek().is_none() {
            fuse::Query::Lookup(f, name.to_vec())
        } else {
            let mut names = vec![name.to_vec()];
            names.extend(extra.cloned());
            fuse::Query::LookupWalk { mnt, dir: f, names }
        };
        Err(fuse::need(q))
    }

    /// `name` in FUSE directory `dir` from the cache, or a retry to look it up ([`fuse::need`]).
    pub(crate) fn fuse_child(&self, dir: fuse::FuseId, name: &[u8]) -> Result<fuse::FuseId, Errno> {
        if name.len() > fuse::NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        match self.fuse.borrow().cached_child(dir, name) {
            Some(res) => res,
            None => Err(fuse::need(fuse::Query::Lookup(dir, name.to_vec()))),
        }
    }

    /// When something is mounted on the node, replaces it with the root of the mount on it; with
    /// several mounts stacked, keeps going up to the topmost one (Linux's `follow_mount`).
    pub(crate) fn mounted(&self, node: Node) -> Node {
        let mounts = self.mounts.borrow();
        let mut node = node;
        // Detached mounts have a mount point only while they stay on a detached parent
        // ([`detach`]), so only nodes of detached mounts find them
        let on = |node: &Node| {
            mounts
                .list
                .iter()
                .rev()
                .chain(mounts.detached.iter().rev())
                .find(|m| m.point.as_ref() == Some(node))
        };
        for _ in 0..8 {
            match on(&node) {
                Some(m) => node = m.root.clone(),
                None => return node,
            }
        }
        // A deep stack (propagation can pile thousands of mounts on one directory) is climbed
        // through an index built once, the later mount on a point winning as above.
        // PinnedNet/PinnedIpc/PinnedUts/PinnedPid inside PseudoNode hash and compare only by
        // immutable namespace id.
        #[allow(clippy::mutable_key_type)]
        let mut tops: HashMap<&Node, &Node> = HashMap::new();
        for m in mounts.detached.iter().chain(&mounts.list) {
            if let Some(point) = &m.point {
                tops.insert(point, &m.root);
            }
        }
        for _ in 0..=tops.len() {
            match tops.get(&node) {
                Some(root) => node = (*root).clone(),
                None => break,
            }
        }
        node
    }

    /// Contents of a symlink.
    pub(crate) fn readlink(&self, ps: &dyn Pseudo, node: &Node) -> Result<Vec<u8>, Errno> {
        match node {
            Node::Store(_, ino) => self.store.readlink(*ino),
            Node::Pseudo(id, p) => ps.readlink(*id, p),
            Node::Overlay(_, o) => self.store.readlink(self.overlays.borrow().node(*o).real()),
            Node::Fuse(_, f) => match self.fuse.borrow().link(*f) {
                Some(target) => Ok(target.to_vec()),
                None => Err(fuse::need(fuse::Query::Readlink(*f))),
            },
        }
    }

    /// The directory's parent; the parent of a mount's root is the mount point's parent
    /// (getdents's `..`).
    pub(crate) fn parent(&self, ps: &dyn Pseudo, dir: &Node) -> Result<Node, Errno> {
        let mut dir = dir.clone();
        while let Some(point) = self.point_of(&dir) {
            dir = point;
        }
        self.parent_in_fs(ps, &dir)
    }

    /// `node` is `top` or below it: searched upwards through mount points (Linux's
    /// `is_path_reachable`). Mounts on files go through the directory recorded at mount time.
    pub(crate) fn is_under(&self, ps: &dyn Pseudo, node: &Node, top: &Node) -> bool {
        let mut cur = node.clone();
        loop {
            if cur == *top {
                return true;
            }
            if let Some((point, at)) = self.root_point(&cur) {
                cur = match at {
                    Some((dir, _)) if point != *top => dir,
                    _ => point,
                };
                continue;
            }
            match self.parent_in_fs(ps, &cur) {
                Ok(up) if up != cur => cur = up,
                _ => return false,
            }
        }
    }

    /// When `node` is the root of a mount, that mount's mount point.
    fn point_of(&self, node: &Node) -> Option<Node> {
        self.root_point(node).map(|(point, _)| point)
    }

    /// The parent directory within the same mount. A mount's root has no parent and is its own:
    /// the root of the mount tree and the root of a detached mount (`MNT_DETACH`), and inside a
    /// bind mount nothing outside the bound directory is visible.
    fn parent_in_fs(&self, ps: &dyn Pseudo, dir: &Node) -> Result<Node, Errno> {
        if self.is_mount_root(dir) {
            return Ok(dir.clone());
        }
        Ok(match dir {
            Node::Store(id, ino) => Node::Store(*id, self.store.parent(*ino)?),
            Node::Pseudo(id, p) => ps.parent(p).map_or(dir.clone(), |up| Node::Pseudo(*id, up)),
            Node::Overlay(id, o) => Node::Overlay(*id, self.overlays.borrow().parent(*o)),
            Node::Fuse(id, f) => Node::Fuse(
                *id,
                self.fuse.borrow().get(*f).ok_or(Errno::ENOTCONN)?.parent,
            ),
        })
    }

    /// When `node` is the root of a mount with a mount point (an attached one, or a detached one
    /// still on its detached parent), the mount point and [`Mount::at`].
    fn root_point(&self, node: &Node) -> Option<(Node, Option<Dentry>)> {
        let mounts = self.mounts.borrow();
        let m = mounts.get(node.mnt())?;
        if m.root != *node {
            return None;
        }
        Some((m.point.clone()?, m.at.clone()))
    }

    /// `node` is the root of the mount it is in (attached and detached ones both count).
    fn is_mount_root(&self, node: &Node) -> bool {
        self.with_mount(node.mnt(), |m| m.root == *node)
            .unwrap_or(false)
    }

    // ---- Mount table (mount(2), umount2(2), pivot_root(2), mountinfo) ----

    /// Attached mounts, in mount order. The first is the boot root filesystem ([`ROOT_MOUNT`]),
    /// which after pivot_root may be mounted elsewhere or detached.
    pub(crate) fn mounts(&self) -> Vec<Mount> {
        self.mounts.borrow().list.clone()
    }

    /// Every node referenced by any mount, attached or detached: mount roots, mount points, and
    /// the recorded parent directories of mounts on or of files (`Mount::at`, `Mount::root_at`).
    pub(crate) fn mount_nodes(&self) -> Vec<Node> {
        let mounts = self.mounts.borrow();
        mounts
            .list
            .iter()
            .chain(&mounts.detached)
            .flat_map(|m| {
                [
                    Some(m.root.clone()),
                    m.point.clone(),
                    m.at.as_ref().map(|(dir, _)| dir.clone()),
                    m.root_at.as_ref().map(|(dir, _)| dir.clone()),
                ]
            })
            .flatten()
            .collect()
    }

    /// Attached mounts in mount namespace `ns`, in mount order.
    #[cfg(test)]
    fn mounts_in(&self, ns: u64) -> Vec<Mount> {
        let mounts = self.mounts.borrow();
        mounts.list.iter().filter(|m| m.ns == ns).cloned().collect()
    }

    /// How many mounts mount namespace `ns` holds (for `fs.mount-max`).
    pub(crate) fn count_in(&self, ns: u64) -> usize {
        self.mounts
            .borrow()
            .list
            .iter()
            .filter(|m| m.ns == ns)
            .count()
    }

    /// The boot mount namespace.
    pub(crate) fn init_ns(&self) -> std::rc::Rc<MntNs> {
        self.init_ns.clone()
    }

    /// The namespace kept by the namespace file with id `id` bind-mounted elsewhere
    /// ([`Mount::pin`]; those in detached mounts still in use count too).
    pub(crate) fn pinned_ns(&self, id: u64) -> Option<crate::nsproxy::NsRef> {
        let mounts = self.mounts.borrow();
        mounts
            .list
            .iter()
            .chain(&mounts.detached)
            .filter_map(|m| m.pin.as_ref())
            .find(|r| r.id() == id)
            .cloned()
    }

    /// The mount namespace with id `id` that is still in use (a process is in it, or a
    /// namespace file keeps it).
    pub(crate) fn find_ns(&self, id: u64) -> Option<std::rc::Rc<MntNs>> {
        if id == INIT_MNT_NS {
            return Some(self.init_ns.clone());
        }
        let namespaces = self.namespaces.borrow();
        namespaces
            .iter()
            .filter_map(std::rc::Weak::upgrade)
            .find(|ns| ns.id == id)
    }

    /// Copies all attached mounts of mount namespace `from` into a new namespace owned by user
    /// namespace `owner` (Linux's `copy_mnt_ns`). Returns the new namespace and a map from old
    /// mount ids to new ones, which the caller uses to move processes' root and current
    /// directories onto the new mounts. When `owner` is not the owner of `from`, every copy is
    /// locked ([`lock`], Linux's `lock_mnt_tree`): the mount and its read-only, nodev, nosuid,
    /// noexec and access-time flags.
    pub(crate) fn copy_ns(
        &self,
        from: u64,
        owner: std::rc::Rc<crate::cred::UserNs>,
    ) -> (
        std::rc::Rc<MntNs>,
        std::collections::HashMap<MountId, MountId>,
    ) {
        let lock_all = self
            .find_ns(from)
            .is_some_and(|old| old.owner.id != owner.id);
        let ns = std::rc::Rc::new(MntNs {
            id: new_ns_id(),
            owner,
            anon: false,
        });
        let mut mounts = self.mounts.borrow_mut();
        let mut old: Vec<Mount> = mounts
            .list
            .iter()
            .filter(|m| m.ns == from)
            .cloned()
            .collect();
        // A mount namespace file bound elsewhere and the mounts on it are not copied (Linux's
        // copy_tree without CL_COPY_MNT_NS_FILE): the new namespace is newer than it, and
        // keeping it could form a cycle
        let mut skip = std::collections::HashSet::new();
        let mut queue: Vec<MountId> = old
            .iter()
            .filter(|m| matches!(m.pin, Some(crate::nsproxy::NsRef::Mnt(_))))
            .map(|m| m.id)
            .collect();
        while let Some(id) = queue.pop() {
            if skip.insert(id)
                && let Some(kids) = mounts.children.get(&id)
            {
                queue.extend_from_slice(kids);
            }
        }
        old.retain(|m| !skip.contains(&m.id));
        // Allocate the ids before copying: after MS_MOVE or pivot_root, the mount a mount point
        // is in may have been mounted later than it
        let mut map = std::collections::HashMap::new();
        for m in &old {
            map.insert(m.id, mounts.next);
            mounts.next += 1;
        }
        let tag = |n: &Node| {
            n.clone()
                .in_mount(map.get(&n.mnt()).copied().unwrap_or(n.mnt()))
        };
        for m in old {
            let locks = if lock_all {
                locked_tree(m.flags, m.locks)
            } else {
                m.locks
            };
            let copy = Mount {
                id: map[&m.id],
                ns: ns.id,
                root: tag(&m.root),
                point: m.point.as_ref().map(tag),
                at: m.at.as_ref().map(|(d, n)| (tag(d), n.clone())),
                root_at: m.root_at.as_ref().map(|(d, n)| (tag(d), n.clone())),
                root_gone: m.root_gone,
                expiring: false,
                locks,
                // Copies of shared mounts are their peers, or in a less privileged namespace
                // their slaves (copy_mnt_ns's CL_SHARED_TO_SLAVE)
                prop: if lock_all {
                    m.prop.of_slave_copy()
                } else {
                    m.prop
                },
                ..m
            };
            mounts.push_attached(copy);
        }
        drop(mounts);
        self.namespaces
            .borrow_mut()
            .push(std::rc::Rc::downgrade(&ns));
        self.rebuild_cached();
        (ns, map)
    }

    /// A new anonymous mount namespace (Linux's `alloc_mnt_ns(.., true)`): holds a tree copied
    /// by open_tree and is held by an open file; once that is closed and nothing uses it, the
    /// next cleanup ([`Vfs::collect`]) tears down its mounts.
    pub(crate) fn anon_ns(&self, owner: std::rc::Rc<crate::cred::UserNs>) -> std::rc::Rc<MntNs> {
        let ns = std::rc::Rc::new(MntNs {
            id: new_ns_id(),
            owner,
            anon: true,
        });
        self.namespaces
            .borrow_mut()
            .push(std::rc::Rc::downgrade(&ns));
        ns
    }

    /// open_tree(`OPEN_TREE_CLONE`): binds a copy of `src` (with the filesystem, flags and
    /// device number of the mount it is in) in anonymous namespace `ns`, mounted nowhere, as
    /// that namespace's root. `found` is the directory and name where a bound file was found.
    /// Returns the new mount.
    pub(crate) fn clone_mount(
        &self,
        src: &Node,
        found: Option<Dentry>,
        ns: u64,
    ) -> Result<MountId, Errno> {
        let m = self.mount(src.mnt()).ok_or(Errno::EINVAL)?;
        let mut mounts = self.mounts.borrow_mut();
        let id = mounts.next;
        mounts.next += 1;
        mounts.push_attached(Mount {
            id,
            ns,
            root: src.clone().in_mount(id),
            point: None,
            at: None,
            root_at: found,
            root_gone: false,
            expiring: false,
            // As in __do_loopback, the copy's own root is not locked (the mounts copied below it
            // keep their locks)
            locks: m.locks & !lock::MOUNT,
            prop: m.prop.of_bind(),
            ..m
        });
        drop(mounts);
        self.rebuild_cached();
        Ok(id)
    }

    /// open_tree(`OPEN_TREE_CLONE`) on a namespace file not rooted at an attached nsfs mount:
    /// creates an nsfs mount in anonymous namespace `ns`, mounted nowhere, pinning `pin`.
    pub(crate) fn clone_ns_mount(
        &self,
        src: &Node,
        pin: crate::nsproxy::NsRef,
        ns: u64,
    ) -> MountId {
        let mut mounts = self.mounts.borrow_mut();
        let id = mounts.next;
        mounts.next += 1;
        mounts.push_attached(Mount {
            id,
            ns,
            fs: Fs::Nsfs,
            root: src.clone().in_mount(id),
            point: None,
            at: None,
            root_at: None,
            root_gone: false,
            flags: 0,
            dev: Fs::Nsfs.dev(),
            source: b"nsfs".to_vec(),
            expiring: false,
            pin: Some(pin),
            locks: 0,
            prop: Propagation::default(),
            owner: None,
        });
        drop(mounts);
        self.rebuild_cached();
        id
    }

    /// move_mount attaching a tree copied by open_tree: the root is mounted on `point`, and all
    /// mounts in the tree move into namespace `to`.
    pub(crate) fn attach_tree(&self, root: MountId, (point, at): (Node, Option<Dentry>), to: u64) {
        let mut mounts = self.mounts.borrow_mut();
        let from = mounts.get_attached(root).map(|m| m.ns);
        for m in mounts.list.iter_mut().filter(|m| Some(m.ns) == from) {
            m.ns = to;
        }
        if matches!(mounts.by_id.get(&root), Some(MountLoc::Attached(_))) {
            let at = at.filter(|_| matches!(point, Node::Store(..)));
            mounts.set_point(root, Some(point), at);
        }
        drop(mounts);
        self.mounts_changed_ns([to]);
    }

    /// Mount `id` and the mounts below it (level by level downwards, mount_setattr's
    /// `AT_RECURSIVE`).
    pub(crate) fn subtree(&self, id: MountId) -> Vec<MountId> {
        self.mounts.borrow().attached_subtree(id)
    }

    /// Whether attached mount `id` or any attached mount below it is unbindable (Linux's
    /// `do_move_mount` check when moving onto a shared mount).
    pub(crate) fn subtree_has_unbindable(&self, id: MountId) -> bool {
        let mounts = self.mounts.borrow();
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            let Some(m) = mounts.get_attached(cur) else {
                continue;
            };
            if m.prop.unbindable {
                return true;
            }
            if let Some(kids) = mounts.children.get(&cur) {
                stack.extend_from_slice(kids);
            }
        }
        false
    }

    /// Whether adding `added[ns]` attached mounts to each namespace `ns` would exceed `limit`
    /// (`fs.mount-max`), counted in a single pass over the attached list.
    pub(crate) fn any_ns_over(&self, added: &HashMap<u64, usize>, limit: usize) -> bool {
        if added.values().all(|&n| n == 0) {
            return false;
        }
        let mut counts: HashMap<u64, usize> = HashMap::with_capacity(added.len());
        for m in &self.mounts.borrow().list {
            if added.get(&m.ns).is_some_and(|&n| n > 0) {
                *counts.entry(m.ns).or_default() += 1;
            }
        }
        added
            .iter()
            .any(|(&ns, &n)| n > 0 && counts.get(&ns).copied().unwrap_or(0) + n > limit)
    }

    /// The root directory of mount namespace `ns` (the root of the mount tree's root, or the
    /// topmost mount on it when something is mounted there).
    pub(crate) fn ns_root(&self, ns: u64) -> Option<Node> {
        let root = {
            let mounts = self.mounts.borrow();
            let m = mounts
                .list
                .iter()
                .find(|m| m.ns == ns && m.point.is_none())?;
            m.root.clone()
        };
        Some(self.mounted(root))
    }

    /// The namespace mount `id` belongs to; None for detached ones (Linux's `check_mnt`).
    pub(crate) fn mount_ns(&self, id: MountId) -> Option<u64> {
        self.mounts.borrow().get_attached(id).map(|m| m.ns)
    }

    /// The attached mount with id `id`; None for detached ones.
    pub(crate) fn mount(&self, id: MountId) -> Option<Mount> {
        self.mounts.borrow().get_attached(id).cloned()
    }

    /// When `node` is the root of an attached mount, that mount's id.
    pub(crate) fn mount_root(&self, node: &Node) -> Option<MountId> {
        self.mounts
            .borrow()
            .get_attached(node.mnt())
            .filter(|m| m.root == *node)
            .map(|m| m.id)
    }

    /// Some mount is mounted on `node`.
    #[cfg(test)]
    fn is_mount_point(&self, node: &Node) -> bool {
        self.mounts
            .borrow()
            .list
            .iter()
            .any(|m| m.point.as_ref() == Some(node))
    }

    /// A mount of namespace `ns` is on `name` (inode `ino`) in store directory `dir`: rmdir,
    /// rename or unlink of it is EBUSY (Linux's `is_local_mountpoint`, which looks only at the
    /// caller's namespace). Mounts on files tell hard links apart by the directory and name
    /// where the file was found ([`Mount::at`]).
    pub(crate) fn is_store_point(&self, (ino, dir, name): (Ino, Ino, &[u8]), ns: u64) -> bool {
        self.mounts
            .borrow()
            .list
            .iter()
            .any(|m| m.ns == ns && on_entry(m, (ino, dir, name)))
    }

    /// `name` (inode `ino`) in store directory `dir` was deleted (rmdir, unlink, overwritten by
    /// rename): all mounts on it in other namespaces are detached (Linux's `detach_mounts`), and
    /// scheduled for collection at the end of the syscall.
    pub(crate) fn detach_store_point(&self, (ino, dir, name): (Ino, Ino, &[u8])) {
        let mut mounts = self.mounts.borrow_mut();
        let roots: Vec<MountId> = mounts
            .list
            .iter()
            .filter(|m| on_entry(m, (ino, dir, name)))
            .map(|m| m.id)
            .collect();
        if roots.is_empty() {
            return;
        }
        let mut gone = std::collections::HashSet::new();
        for id in roots {
            if !gone.contains(&id) {
                gone.extend(mounts.attached_subtree(id));
            }
        }
        let affected: std::collections::HashSet<u64> = mounts
            .list
            .iter()
            .filter(|m| gone.contains(&m.id))
            .map(|m| m.ns)
            .collect();
        detach(&mut mounts, |m| gone.contains(&m.id));
        mounts.collect_pending = true;
        drop(mounts);
        self.mounts_changed_ns(affected);
    }

    /// Overlay node `id` was deleted (rmdir, unlink, overwritten by rename): all mounts on it in
    /// other namespaces are detached (Linux's `detach_mounts`), scheduled for collection at the
    /// end of the syscall, and any mount rooted at `id` is marked gone (`//deleted`).
    fn detach_overlay_point(&self, id: overlay::OvlId) {
        let mut mounts = self.mounts.borrow_mut();
        {
            let Mounts { list, detached, .. } = &mut *mounts;
            for m in list.iter_mut().chain(detached.iter_mut()) {
                if matches!(m.root, Node::Overlay(_, o) if o == id) {
                    m.root_gone = true;
                }
            }
        }
        let roots: Vec<MountId> = mounts
            .list
            .iter()
            .filter(|m| matches!(m.point, Some(Node::Overlay(_, o)) if o == id))
            .map(|m| m.id)
            .collect();
        if roots.is_empty() {
            return;
        }
        let mut gone = std::collections::HashSet::new();
        for root in roots {
            if !gone.contains(&root) {
                gone.extend(mounts.attached_subtree(root));
            }
        }
        let affected: std::collections::HashSet<u64> = mounts
            .list
            .iter()
            .filter(|m| gone.contains(&m.id))
            .map(|m| m.ns)
            .collect();
        detach(&mut mounts, |m| gone.contains(&m.id));
        mounts.collect_pending = true;
        drop(mounts);
        self.mounts_changed_ns(affected);
    }

    /// `name` (inode `ino`) in store directory `dir` was deleted: the mounts, in any namespace or
    /// detached, whose root is that name keep where it was and are marked gone
    /// ([`Mount::root_gone`]). A bound file is matched by the name it was found at; a root
    /// recorded without one (a directory, which has a single name) once the inode has no links
    /// left.
    pub(crate) fn roots_removed(&self, (ino, dir, name): (Ino, Ino, &[u8])) {
        let unlinked = self.store.stat(ino).map_or(true, |st| st.nlink == 0);
        let mut mounts = self.mounts.borrow_mut();
        let Mounts { list, detached, .. } = &mut *mounts;
        for m in list.iter_mut().chain(detached.iter_mut()) {
            let Node::Store(mnt, root) = m.root else {
                continue;
            };
            if root != ino || m.root_gone {
                continue;
            }
            match &m.root_at {
                Some((d, n)) => m.root_gone = d.ino() == Some(dir) && n.as_slice() == name,
                None if unlinked => {
                    m.root_at = Some((Node::Store(mnt, dir), name.to_vec()));
                    m.root_gone = true;
                }
                None => {}
            }
        }
    }

    /// The device number of mount `id`'s instance, attached or detached; None once the mount is
    /// gone (unlike [`Vfs::dev_of`], which then falls back to the boot instance's).
    pub(crate) fn mount_dev(&self, id: MountId) -> Option<u64> {
        self.with_mount(id, |m| m.dev)
    }

    /// The device number of `node` (stat's `st_dev`): that of the mount it is in; when the mount
    /// is unknown, that of the boot instance.
    pub(crate) fn dev_of(&self, node: &Node) -> u64 {
        self.with_mount(node.mnt(), |m| m.dev)
            .unwrap_or_else(|| match node {
                Node::Store(..) => ROOT_DEV,
                Node::Pseudo(_, p) => crate::pseudo::fs_of(p).dev(),
                Node::Overlay(_, o) => self.overlays.borrow().node(*o).dev,
                Node::Fuse(_, f) => self.fuse.borrow().get(*f).map_or(0, |n| n.dev),
            })
    }

    /// When `node` is in tmpfs, that instance's device number (used by [`Vfs::tmpfs_usage`] and
    /// others).
    pub(crate) fn tmpfs_dev(&self, node: &Node) -> Option<u64> {
        (self.fs_of(node) == Fs::Tmpfs).then(|| self.dev_of(node))
    }

    /// The store inode at the root of the superblock (filesystem instance) containing store
    /// `node`: `ROOT` for the root filesystem and the instance's detached root inode for tmpfs.
    pub(crate) fn store_sb_root(&self, node: &Node) -> Option<Ino> {
        let Node::Store(mnt, _) = *node else {
            return None;
        };
        let (fs, dev) = self.with_mount(mnt, |m| (m.fs, m.dev))?;
        match fs {
            Fs::Store => Some(ROOT),
            Fs::Tmpfs => self.mounts.borrow().tmpfs.get(&dev).map(|t| t.root),
            _ => None,
        }
    }

    /// Charge a mapped overlay file to the tmpfs layer that supplies its data.
    pub(crate) fn mapped_tmpfs_dev(&self, node: &Node, ino: Ino) -> Option<u64> {
        let Node::Overlay(_, id) = node else {
            return self.tmpfs_dev(node);
        };
        let overlays = self.overlay();
        let n = overlays.node(*id);
        let instance = overlays.instance(n.dev)?;
        if instance.pins.is_empty() {
            return None;
        }
        let parent = overlays.node(n.parent);
        let mut dir = parent
            .upper
            .into_iter()
            .chain(parent.lower.iter().copied())
            .find(|&dir| self.store.lookup(dir, &n.name) == Ok(Some(ino)));
        let mounts = self.mounts.borrow();
        if dir.is_none() {
            return mounts
                .tmpfs
                .iter()
                .find(|(_, t)| t.unlinked.contains_key(&ino))
                .map(|(&dev, _)| dev);
        }
        while let Some(here) = dir {
            if let Some((&dev, _)) = mounts.tmpfs.iter().find(|(_, t)| t.root == here) {
                return Some(dev);
            }
            dir = self.store.parent(here).ok().filter(|&next| next != here);
        }
        None
    }

    /// The kind of filesystem `node` is in.
    pub(crate) fn fs_of(&self, node: &Node) -> Fs {
        self.with_mount(node.mnt(), |m| m.fs)
            .unwrap_or_else(|| match node {
                Node::Store(..) => Fs::Store,
                Node::Pseudo(_, p) => crate::pseudo::fs_of(p),
                Node::Overlay(..) => Fs::Overlay,
                Node::Fuse(..) => Fs::Fuse,
            })
    }

    pub(crate) fn tmpfs_record_pages(&self, dev: u64, ino: Ino, start: u64, end: u64, data: bool) {
        let start = start / TMPFS_PAGE * TMPFS_PAGE;
        let end = end.next_multiple_of(TMPFS_PAGE);
        let mut files = self.tmpfs_file_ranges.borrow_mut();
        let r = files.entry(ino).or_insert_with(|| TmpfsFileRanges {
            dev,
            ..Default::default()
        });
        r.allocated.add(start, end);
        if data {
            r.data.add(start, end);
        }
    }

    pub(crate) fn tmpfs_forget_pages(&self, ino: Ino, start: u64, end: u64) {
        let mut files = self.tmpfs_file_ranges.borrow_mut();
        if let Some(r) = files.get_mut(&ino) {
            let start = start.next_multiple_of(TMPFS_PAGE);
            let end = end / TMPFS_PAGE * TMPFS_PAGE;
            r.allocated.remove(start, end);
            r.data.remove(start, end);
            if r.allocated.0.is_empty() {
                files.remove(&ino);
            }
        }
    }

    pub(crate) fn tmpfs_missing(
        &self,
        ino: Ino,
        host: &std::fs::File,
        size: u64,
        from: u64,
        to: u64,
        budget: u64,
    ) -> Result<u64, u64> {
        let files = self.tmpfs_file_ranges.borrow();
        let empty = PageRuns::default();
        files
            .get(&ino)
            .map_or(&empty, |r| &r.allocated)
            .holes(from, to, budget, |lo, hi, left| {
                fiemap_holes(host, lo, hi, left)
                    .unwrap_or_else(|| seek_holes(host, size, lo, hi, left))
            })
    }

    pub(crate) fn tmpfs_file_pages(&self, ino: Ino, host: &std::fs::File) -> Result<u64, Errno> {
        if !self.tmpfs_file_ranges.borrow().contains_key(&ino) {
            return object_pages(host);
        }
        const END: u64 = 1 << 63;
        let size = host.metadata().map_err(mapping_errno)?.len();
        let holes = self
            .tmpfs_missing(ino, host, size, 0, END, u64::MAX)
            .expect("unlimited page budget");
        Ok(END / TMPFS_PAGE - holes)
    }

    /// A tmpfs upper copies data within EOF. Unwritten lower reservations do not transfer.
    pub(crate) fn tmpfs_copy_pages(&self, st: &Stat) -> Result<Option<u64>, Errno> {
        let files = self.tmpfs_file_ranges.borrow();
        let Some(file) = files.get(&st.ino) else {
            return Ok(None);
        };
        let host = self.store.open_object(st.ino, false)?;
        let holes = file
            .data
            .holes(0, st.size, u64::MAX, |lo, hi, left| {
                seek_holes(&host, st.size, lo, hi, left)
            })
            .expect("unlimited page budget");
        Ok(Some(st.size.div_ceil(TMPFS_PAGE) - holes))
    }

    pub(crate) fn tmpfs_copy_mapped_data(&self, dev: u64, lower: Ino, upper: Ino) {
        let mut files = self.tmpfs_file_ranges.borrow_mut();
        if let Some(r) = files.get(&lower)
            && !r.data.0.is_empty()
        {
            let data = r.data.clone();
            files.insert(
                upper,
                TmpfsFileRanges {
                    dev,
                    allocated: data.clone(),
                    data,
                },
            );
        }
    }

    pub(crate) fn memfd_size(&self, ino: Ino) -> Option<u64> {
        self.memfd_sizes.borrow().get(&ino).copied()
    }

    pub(crate) fn set_memfd_size(&self, ino: Ino, len: u64) {
        self.memfd_sizes.borrow_mut().insert(ino, len);
    }

    pub(crate) fn clear_memfd_size(&self, ino: Ino) {
        self.memfd_sizes.borrow_mut().remove(&ino);
    }

    pub(crate) fn closed_memfd_sizes(&self, closed: impl Fn(&Ino) -> bool) -> Vec<Ino> {
        self.memfd_sizes
            .borrow()
            .keys()
            .copied()
            .filter(closed)
            .collect()
    }

    /// SEEK_DATA and SEEK_HOLE see the union of host data and pages instantiated by a
    /// mapped access. Unwritten fallocate reservations remain holes until first touched.
    pub(crate) fn seek_data_or_hole(
        &self,
        ino: Ino,
        fd: i32,
        mut at: u64,
        end: u64,
        whence: i32,
    ) -> Result<u64, Errno> {
        let files = self.tmpfs_file_ranges.borrow();
        let data = files.get(&ino).map(|r| &r.data);
        loop {
            let found = match appine_hal::lseek(fd, at as i64, whence) {
                Ok(pos) => pos,
                Err(libc::ENXIO) => end,
                Err(_) if whence == libc::SEEK_DATA => at,
                Err(_) => end,
            };
            if whence == libc::SEEK_DATA {
                let next = data
                    .and_then(|d| d.next(at))
                    .map_or(found, |r| found.min(r.start.max(at)));
                return if next < end {
                    Ok(next)
                } else {
                    Err(Errno::ENXIO)
                };
            }
            match data.and_then(|d| d.next(found)) {
                Some(r) if r.contains(&found) && r.end < end => at = r.end,
                Some(r) if r.contains(&found) => return Ok(end),
                _ => return Ok(found),
            }
        }
    }

    pub(crate) fn tmpfs_stat_blocks(
        &self,
        ino: Ino,
        host: Option<&std::fs::File>,
        st: &mut Stat,
    ) -> Result<(), Errno> {
        if self.tmpfs_file_ranges.borrow().contains_key(&ino) {
            let opened;
            let f = match host {
                Some(f) => f,
                None => {
                    opened = self.store.open_object(ino, false)?;
                    &opened
                }
            };
            st.blocks = Some(self.tmpfs_file_pages(ino, f)? * (TMPFS_PAGE / 512));
        }
        Ok(())
    }

    /// Whether `pages` more pages and `inodes` more inodes fit in tmpfs instance `dev` (Linux's
    /// `shmem_reserve_inode`, `shmem_inode_acct_block`): ENOSPC when they do not, also once
    /// counted again ([`Vfs::tmpfs_recount`]). When they fit, the caller accounts after it is done
    /// ([`Vfs::tmpfs_charge`]).
    pub(crate) fn tmpfs_check(&self, dev: u64, pages: u64, inodes: u64) -> Result<(), Errno> {
        loop {
            let (p, used_pages, used_inodes) = self.tmpfs_usage(dev, false)?;
            let over = |max: u64, used: u64, more: u64| max != 0 && more > 0 && used + more > max;
            if over(p.blocks, used_pages, pages) || over(p.inodes, used_inodes, inodes) {
                if self.tmpfs_recount(dev)? {
                    continue;
                }
                return Err(Errno::ENOSPC);
            }
            return Ok(());
        }
    }

    /// Before refusing or cutting short a change for lack of room in tmpfs instance `dev`: counts
    /// its usage afresh when the recorded one changed since it was last counted, so drift cannot
    /// make it full; returns whether it did, so the caller looks again. A full instance is counted
    /// once, not at every refused change.
    pub(crate) fn tmpfs_recount(&self, dev: u64) -> Result<bool, Errno> {
        let changed = self
            .mounts
            .borrow()
            .tmpfs
            .get(&dev)
            .is_some_and(|t| t.changed);
        if changed {
            self.tmpfs_usage(dev, true)?;
        }
        Ok(changed)
    }

    /// How many pages a file in tmpfs instance `dev` can still use: the `own` pages it already
    /// has plus those not used up. None when unlimited.
    pub(crate) fn tmpfs_room(&self, dev: u64, own: u64) -> Result<Option<u64>, Errno> {
        let (p, used, _) = self.tmpfs_usage(dev, false)?;
        Ok((p.blocks != 0).then(|| (p.blocks + own).saturating_sub(used)))
    }

    /// Records that the usage of tmpfs instance `dev` changed (after create, delete, write,
    /// truncate). Does nothing when it has not been counted yet; it is counted when needed.
    pub(crate) fn tmpfs_charge(&self, dev: u64, pages: i64, inodes: i64) {
        if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev)
            && let Some((p, i)) = &mut t.used
        {
            *p = p.saturating_add_signed(pages);
            *i = i.saturating_add_signed(inodes);
            t.changed = true;
        }
    }

    /// Regular file `ino` in tmpfs instance `dev` lost its last link while still open or mapped:
    /// keeps its `pages` and one inode charged until its last user goes away
    /// ([`Vfs::evict_tmpfs`]).
    pub(crate) fn tmpfs_unlinked(&self, dev: u64, ino: Ino, pages: u64, object: std::fs::File) {
        if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev) {
            t.unlinked.insert(ino, UnlinkedTmpfs { pages, object });
        }
    }

    /// Updates the recorded page count of unlinked-but-open tmpfs file `ino` after a write,
    /// truncation or hole punch.
    pub(crate) fn tmpfs_update_unlinked(&self, dev: u64, ino: Ino, pages: u64) {
        if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev)
            && let Some(p) = t.unlinked.get_mut(&ino)
        {
            p.pages = pages;
        }
    }

    /// Removes an unlinked tmpfs `O_TMPFILE` from the unlinked table once `linkat` attaches it
    /// to the directory tree; its inode and page charges remain in `used` via the new tree entry.
    pub(crate) fn tmpfs_take_unlinked(&self, dev: u64, ino: Ino) {
        if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev) {
            t.unlinked.remove(&ino);
        }
    }

    /// Whether any tmpfs instance currently tracks unlinked regular files still held open or
    /// mapped.
    pub(crate) fn has_unlinked_tmpfs(&self) -> bool {
        self.mounts
            .borrow()
            .tmpfs
            .values()
            .any(|t| !t.unlinked.is_empty())
    }

    /// Metadata after the last unlink, including after the store reaps the object name.
    pub(crate) fn unlinked_tmpfs_stat(&self, ino: Ino) -> Option<Result<Stat, Errno>> {
        let mounts = self.mounts.borrow();
        let file = mounts.tmpfs.values().find_map(|t| t.unlinked.get(&ino))?;
        Some(self.store.stat_open(ino, &file.object).and_then(|mut st| {
            self.tmpfs_stat_blocks(ino, Some(&file.object), &mut st)?;
            Ok(st)
        }))
    }

    /// Refresh charges through the pinned objects and drop those with no guest references.
    pub(crate) fn evict_tmpfs(&self, live: &std::collections::HashSet<Ino>) {
        let mut mounts = self.mounts.borrow_mut();
        for t in mounts.tmpfs.values_mut() {
            let mut drop_inodes = 0u64;
            let mut delta_pages = 0i64;
            t.unlinked.retain(|ino, file| {
                if live.contains(ino) {
                    if let Ok(actual) = self.tmpfs_file_pages(*ino, &file.object) {
                        delta_pages += actual as i64 - file.pages as i64;
                        file.pages = actual;
                    }
                    true
                } else {
                    self.tmpfs_file_ranges.borrow_mut().remove(ino);
                    delta_pages -= file.pages as i64;
                    drop_inodes += 1;
                    false
                }
            });
            if (delta_pages != 0 || drop_inodes != 0)
                && let Some((p, i)) = &mut t.used
            {
                *p = p.saturating_add_signed(delta_pages);
                *i = i.saturating_sub(drop_inodes);
                t.changed = true;
            }
        }
    }

    /// Changes the parameters of tmpfs instance `dev` on remount: `f` gets the parameters and
    /// the current usage (pages, inodes); on error nothing changes.
    pub(crate) fn tmpfs_reconfigure(
        &self,
        dev: u64,
        f: impl FnOnce(&mut TmpfsParams, u64, u64) -> Result<(), Errno>,
    ) -> Result<(), Errno> {
        let (mut params, pages, inodes) = self.tmpfs_usage(dev, true)?;
        f(&mut params, pages, inodes)?;
        if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev) {
            t.params = params;
        }
        Ok(())
    }

    /// Parameters and usage (pages, inodes) of tmpfs instance `dev`. Usage is counted as in
    /// Linux's tmpfs: the root directory and every name take one inode each (hard links too;
    /// Linux's `shmem_link` takes another for each link), regular files by the pages their
    /// objects take on the host (holes take none, as in Linux's tmpfs), long symlinks one page.
    /// With `fresh` it recounts (statfs, remount: changes that bypass the accounting, such as
    /// direct changes to the store or writes through shared mappings, are included too);
    /// otherwise it uses the recorded usage and counts only when none is recorded.
    pub(crate) fn tmpfs_usage(
        &self,
        dev: u64,
        fresh: bool,
    ) -> Result<(TmpfsParams, u64, u64), Errno> {
        let (params, root, used, unlinked) = {
            let mounts = self.mounts.borrow();
            let t = mounts.tmpfs.get(&dev).ok_or(Errno::EINVAL)?;
            (
                t.params.clone(),
                t.root,
                t.used,
                (
                    t.unlinked.values().map(|f| f.pages).sum(),
                    t.unlinked.len() as u64,
                ),
            )
        };
        let (pages, inodes) = match used {
            Some(u) if !fresh => u,
            _ => {
                let u = self.count_tmpfs(root, unlinked)?;
                if let Some(t) = self.mounts.borrow_mut().tmpfs.get_mut(&dev) {
                    t.used = Some(u);
                    t.changed = false;
                }
                u
            }
        };
        Ok((params, pages, inodes))
    }

    /// Counts the usage of the tmpfs rooted at `root` (pages, inodes; see [`Vfs::tmpfs_usage`]),
    /// including unlinked regular files still held open or mapped (`unlinked`).
    fn count_tmpfs(&self, root: Ino, unlinked: (u64, u64)) -> Result<(u64, u64), Errno> {
        let (mut pages, mut inodes) = (0, 1);
        let mut seen = std::collections::HashSet::new();
        let mut dirs = vec![root];
        while let Some(dir) = dirs.pop() {
            for e in self.store.readdir(dir)? {
                if e.ino == dir {
                    continue;
                }
                inodes += 1;
                match e.mode & mode::S_IFMT {
                    mode::S_IFDIR => dirs.push(e.ino),
                    mode::S_IFREG | mode::S_IFLNK if seen.insert(e.ino) => {
                        pages += self.tmpfs_pages(&self.store.stat(e.ino)?);
                    }
                    _ => {}
                }
            }
        }
        pages += unlinked.0;
        inodes += unlinked.1;
        Ok((pages, inodes))
    }

    /// The mount's superblock options (the part after `rw` in the last column of mountinfo).
    pub(crate) fn sb_options(&self, m: &Mount) -> String {
        match m.fs {
            Fs::Pts => self.devpts_options(m.dev).show(),
            Fs::Overlay => self
                .overlays
                .borrow()
                .instance(m.dev)
                .map_or_else(String::new, |i| i.options.show()),
            Fs::Tmpfs => self
                .mounts
                .borrow()
                .tmpfs
                .get(&m.dev)
                .map_or_else(String::new, |t| t.params.options()),
            Fs::Fuse => self
                .fuse
                .borrow()
                .conn(m.dev)
                .map_or_else(String::new, |c| {
                    let c = c.borrow();
                    c.opts.show(c.user_ns())
                }),
            fs => fs.options().to_owned(),
        }
    }

    /// The mount's filesystem type as mountinfo shows it: a FUSE mount with a subtype shows
    /// `fuse.<subtype>` (Linux's `show_type`).
    pub(crate) fn type_of(&self, m: &Mount) -> String {
        let name = m.fs.type_name().to_owned();
        if m.fs != Fs::Fuse {
            return name;
        }
        let subtype = self
            .fuse
            .borrow()
            .conn(m.dev)
            .and_then(|c| c.borrow().opts.subtype.clone());
        match subtype {
            Some(s) => format!("{name}.{}", String::from_utf8_lossy(&s)),
            None => name,
        }
    }

    /// Options of devpts instance `dev` (the boot instance, and one with no mount left, get the
    /// boot options).
    pub(crate) fn devpts_options(&self, dev: u64) -> crate::tty::PtsOptions {
        self.mounts
            .borrow()
            .devpts
            .get(&dev)
            .copied()
            .unwrap_or(crate::tty::PtsOptions::BOOT)
    }

    /// Records the options of newly mounted devpts instance `dev`.
    pub(crate) fn set_devpts_options(&self, dev: u64, opts: crate::tty::PtsOptions) {
        self.mounts.borrow_mut().devpts.insert(dev, opts);
    }

    /// Flags of the mount `node` is in; None when the mount is unknown.
    pub(crate) fn mount_flags(&self, node: &Node) -> Option<u64> {
        self.with_mount(node.mnt(), |m| m.flags)
    }

    /// Account a store file read or directory listing on its open mount.
    pub(crate) fn accessed(&self, mnt: MountId, ino: Ino, file: Option<&std::fs::File>) {
        let skip = ms::RDONLY | ms::NOATIME | if file.is_none() { ms::NODIRATIME } else { 0 };
        let flags = self.with_mount(mnt, |m| m.flags | (self.sb_flags(m) & ms::RDONLY));
        if let Some(flags) = flags
            && flags & skip == 0
        {
            let _ = self.store.accessed(ino, file, flags & ms::RELATIME != 0);
        }
    }

    /// `node` is in a read-only mount or filesystem: changing it is EROFS.
    pub(crate) fn readonly(&self, node: &Node) -> bool {
        self.mount_flags(node).is_some_and(|f| f & ms::RDONLY != 0) || self.sb_readonly_node(node)
    }

    /// `node`'s filesystem instance itself is read-only (Linux's `sb_rdonly`), regardless of the
    /// mount's own flags.
    pub(crate) fn sb_readonly_node(&self, node: &Node) -> bool {
        self.with_mount(node.mnt(), |m| self.sb_readonly(m)) == Some(true)
    }

    /// Mount `m`'s filesystem itself is read-only (Linux's `sb_rdonly`), whatever the mount's
    /// flags.
    pub(crate) fn sb_readonly(&self, m: &Mount) -> bool {
        self.sb_flags(m) & ms::RDONLY != 0
    }

    /// The superblock flags of mount `m`'s filesystem ([`ms::PER_SB`]): those it was mounted or
    /// last remounted with (shared by every bind of it), read-only too for an overlay without an
    /// upper layer.
    pub(crate) fn sb_flags(&self, m: &Mount) -> u64 {
        let flags = self
            .mounts
            .borrow()
            .sb_flags
            .get(&m.dev)
            .copied()
            .unwrap_or(0);
        let lower_only = m.fs == Fs::Overlay
            && self
                .overlays
                .borrow()
                .instance(m.dev)
                .is_some_and(|i| i.upper.is_none());
        flags | if lower_only { ms::RDONLY } else { 0 }
    }

    /// Sets the superblock flags of the filesystem instance with device number `dev` (a new
    /// instance, or a remount without `MS_BIND`).
    pub(crate) fn set_sb_flags(&self, dev: u64, flags: u64) {
        self.mounts
            .borrow_mut()
            .sb_flags
            .insert(dev, flags & ms::PER_SB);
    }

    /// The path in the filesystem of the part the mount sees (the fourth column of mountinfo:
    /// which directory or file a bind mount bound).
    /// A root whose name was removed shows that path followed by `//deleted`, as Linux's
    /// `dentry_path` shows an unlinked dentry.
    pub(crate) fn root_path(&self, ps: &dyn Pseudo, m: &Mount) -> Vec<u8> {
        let mut p = match &m.root_at {
            Some((dir, name)) => {
                let mut p = self.fs_path(ps, dir);
                if p != b"/" {
                    p.push(b'/');
                }
                p.extend_from_slice(name);
                p
            }
            None => self.fs_path(ps, &m.root),
        };
        if m.root_gone {
            p.extend_from_slice(b"//deleted");
        }
        p
    }

    /// The directory's path in its filesystem. Namespace files look like `net:[number]` (Linux
    /// nsfs's `d_dname`), with no leading `/`.
    fn fs_path(&self, ps: &dyn Pseudo, node: &Node) -> Vec<u8> {
        let mut names = Vec::new();
        match node {
            Node::Pseudo(id, p @ PseudoNode::NsFile(..)) => return ps.name(*id, p),
            Node::Store(_, ino) => {
                let mut cur = *ino;
                while cur != ROOT {
                    let Ok(up) = self.store.parent(cur) else {
                        break;
                    };
                    match self.store.name_of(up, cur) {
                        Ok(Some(name)) => names.push(name),
                        _ => break,
                    }
                    cur = up;
                }
            }
            Node::Pseudo(id, p) => {
                let mut cur = p.clone();
                while let Some(up) = ps.parent(&cur) {
                    names.push(ps.name(*id, &cur));
                    cur = up;
                }
            }
            Node::Overlay(_, o) => {
                let ovl = self.overlays.borrow();
                let mut cur = *o;
                while ovl.parent(cur) != cur {
                    names.push(ovl.node(cur).name.clone());
                    cur = ovl.parent(cur);
                }
            }
            Node::Fuse(_, f) => {
                let fuse = self.fuse.borrow();
                let mut cur = *f;
                while let Some(n) = fuse.get(cur)
                    && n.parent != cur
                {
                    names.push(n.name.clone());
                    cur = n.parent;
                }
            }
        }
        if names.is_empty() {
            return b"/".to_vec();
        }
        names
            .iter()
            .rev()
            .flat_map(|n| [&b"/"[..], n].concat())
            .collect()
    }

    /// Mounts a new tmpfs instance (whose root directory is created here), returning the new
    /// mount's id.
    pub(crate) fn new_tmpfs(
        &self,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        params: TmpfsParams,
    ) -> Result<MountId, Errno> {
        let root = self
            .store
            .create_detached_dir(params.perm, params.uid, params.gid)?;
        let id = self.add_mount(Fs::Tmpfs, Node::Store(0, root), point, flags, source, None);
        let mut mounts = self.mounts.borrow_mut();
        let dev = mounts.get_attached(id).map_or(0, |m| m.dev);
        mounts.tmpfs.insert(
            dev,
            Tmpfs {
                root,
                params,
                // Only the root directory
                used: Some((0, 1)),
                changed: false,
                unlinked: Default::default(),
            },
        );
        Ok(id)
    }

    /// Mounts a new overlay instance of `layers` (store directories) with options `options` for
    /// a mounter with filesystem IDs `mounter`, returning the new mount's id; `pins` are the tmpfs
    /// instances the layers are in, which stay while it does. An overlay without an upper layer is
    /// read-only ([`Vfs::sb_readonly`]).
    pub(crate) fn new_overlay(
        &self,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        (layers, mounter, pins): (overlay::Layers, (u32, u32), Vec<u64>),
        options: overlay::Options,
    ) -> MountId {
        let id = self.add_mount(Fs::Overlay, Node::ROOT, point, flags, source, None);
        let dev = self.with_mount(id, |m| m.dev).unwrap_or(0);
        let root = self
            .overlays
            .borrow_mut()
            .add_instance(dev, layers, (mounter, pins), options);
        self.update_mount(id, |m| m.root = Node::Overlay(id, root));
        id
    }

    /// The overlay instances and their nodes (an overlay node's store inodes, its instance's
    /// layers and options).
    pub(crate) fn overlay(&self) -> crate::cell::Ref<'_, overlay::Overlays> {
        self.overlays.borrow()
    }

    /// Drops removed and excess unused overlay nodes nothing uses any more
    /// ([`overlay::Overlays::sweep`]).
    pub(crate) fn sweep_overlays(
        &self,
        keep: &std::collections::HashSet<overlay::OvlId>,
        oldest: u64,
    ) -> usize {
        self.overlays.borrow_mut().sweep(keep, oldest)
    }

    /// Exposes a host shared-storage directory in the boot namespace, preserving the store
    /// entries covered by its mounts. The host root is opened only when a guest accesses it.
    pub(crate) fn mount_shared_storage(&self, path: &Path) -> Result<(), Errno> {
        let cred = Cred::root();
        let mut conn = fuse::Conn::shared_storage(0, path, &cred, crate::pidns::PidNs::init())?;
        if self
            .mounts
            .borrow()
            .list
            .iter()
            .any(|m| m.source == b"shared_storage")
        {
            return Err(Errno::EBUSY);
        }
        let ps = crate::pseudo::Offline::Boot;
        let (point, alias) = self.store.transaction(|store| {
            let mut dir = ROOT;
            let mut parent = ROOT;
            for name in [b"storage".as_slice(), b"emulated", b"0"] {
                parent = dir;
                dir = match store.lookup(dir, name)? {
                    Some(ino) if store.kind(ino)? == mode::S_IFDIR => ino,
                    Some(_) => return Err(Errno::ENOTDIR),
                    None => store.mkdir(dir, name, 0o755, 0, 0)?,
                };
            }
            let target = Node::Store(ROOT_MOUNT, dir);
            let point = (
                target.clone(),
                Some((Node::Store(ROOT_MOUNT, parent), b"0".to_vec())),
            );
            let alias = match store.lookup(ROOT, b"sdcard")? {
                None => {
                    store.symlink(ROOT, b"sdcard", b"/storage/emulated/0", 0, 0)?;
                    None
                }
                Some(ino) if store.kind(ino)? == mode::S_IFDIR => Some((
                    Node::Store(ROOT_MOUNT, ino),
                    Some((Node::ROOT, b"sdcard".to_vec())),
                )),
                Some(ino) if store.kind(ino)? == mode::S_IFLNK => {
                    let (node, _) =
                        self.walk(&ps, &cred, &Node::ROOT, &Node::ROOT, b"/sdcard", true)?;
                    if node == target {
                        None
                    } else {
                        return Err(Errno::EEXIST);
                    }
                }
                Some(_) => return Err(Errno::EEXIST),
            };
            Ok((point, alias))
        })?;
        let flags = ms::NOSUID | ms::NODEV | ms::NOEXEC | ms::RELATIME;
        let (id, connection) = self.new_fuse(point, flags, b"shared_storage".to_vec(), |dev| {
            conn.dev = dev;
            conn
        });
        let dev = connection.borrow().dev;
        self.set_sb_flags(dev, 0);
        self.update_mount(id, |m| m.owner = None);
        if let Some(alias) = alias {
            self.add_fuse_mount(alias, flags, b"shared_storage".to_vec(), dev)?;
        }
        Ok(())
    }

    /// Mounts a new FUSE instance served through connection `conn` (whose device number is
    /// filled in here), returning the new mount's id and the connection; INIT is queued by the
    /// caller.
    pub(crate) fn new_fuse(
        &self,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        conn: impl FnOnce(u64) -> fuse::Conn,
    ) -> (MountId, std::rc::Rc<RefCell<fuse::Conn>>) {
        let id = self.add_mount(Fs::Fuse, Node::ROOT, point, flags, source, None);
        let dev = self.with_mount(id, |m| m.dev).unwrap_or(0);
        let conn = std::rc::Rc::new(RefCell::new(conn(dev)));
        let root = self.fuse.borrow_mut().add(conn.clone());
        self.update_mount(id, |m| m.root = Node::Fuse(id, root));
        (id, conn)
    }

    /// Mounts FUSE instance `dev` once more (mount(2) given a device file already attached to its
    /// connection), at its root.
    pub(crate) fn add_fuse_mount(
        &self,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        dev: u64,
    ) -> Result<MountId, Errno> {
        let root = self.fuse.borrow().root_of(dev).ok_or(Errno::ENOTCONN)?;
        let id = self.add_mount(Fs::Fuse, Node::ROOT, point, flags, source, Some(dev));
        self.update_mount(id, |m| m.root = Node::Fuse(id, root));
        Ok(id)
    }

    /// The FUSE connections and their nodes.
    pub(crate) fn fuse(&self) -> crate::cell::Ref<'_, fuse::Fuses> {
        self.fuse.borrow()
    }

    pub(crate) fn fuse_mut(&self) -> crate::cell::RefMut<'_, fuse::Fuses> {
        self.fuse.borrow_mut()
    }

    /// Metadata of overlay node `o` ([`overlay::Overlays::stat`]).
    pub(crate) fn overlay_stat(&self, o: overlay::OvlId) -> Result<Stat, Errno> {
        self.overlays.borrow().stat(&self.store, o)
    }

    /// Overlay node `o`'s upper inode, copied up first if needed ([`overlay::Overlays::upper_of`]).
    pub(crate) fn overlay_upper(
        &self,
        o: overlay::OvlId,
        what: overlay::CopyUp,
    ) -> Result<Ino, Errno> {
        self.overlays.borrow_mut().upper_of(&self.store, o, what)
    }

    /// Removes `name` from overlay directory `dir` ([`overlay::Overlays::remove`]) and detaches
    /// any mounts in other namespaces on the removed overlay node.
    pub(crate) fn overlay_remove(
        &self,
        dir: overlay::OvlId,
        name: &[u8],
        rmdir: bool,
    ) -> Result<(), Errno> {
        let gone = self
            .overlays
            .borrow_mut()
            .remove(&self.store, dir, name, rmdir)?;
        self.detach_overlay_point(gone);
        Ok(())
    }

    /// Renames within one overlay ([`overlay::Overlays::rename`]) and detaches any mounts in
    /// other namespaces on an overwritten destination overlay node.
    pub(crate) fn overlay_rename(
        &self,
        old: (overlay::OvlId, &[u8]),
        new: (overlay::OvlId, &[u8]),
        flags: (bool, bool),
    ) -> Result<(), Errno> {
        if let Some(replaced) = self
            .overlays
            .borrow_mut()
            .rename(&self.store, old, new, flags)?
        {
            self.detach_overlay_point(replaced);
        }
        Ok(())
    }

    /// The node named `name` in overlay directory `dir` reached through mount `mnt` (not lifted
    /// to what is mounted on it).
    pub(crate) fn overlay_child(
        &self,
        (mnt, dir): (MountId, overlay::OvlId),
        name: &[u8],
    ) -> Result<Node, Errno> {
        let o = self.overlays.borrow_mut().lookup(&self.store, dir, name)?;
        Ok(Node::Overlay(mnt, o))
    }

    /// When mount `mnt` is an overlay, the prefix of the attributes it keeps for itself
    /// ([`overlay::Options::private_prefix`]).
    pub(crate) fn overlay_prefix(&self, mnt: MountId) -> Option<&'static [u8]> {
        let dev = self.with_mount(mnt, |m| (m.fs == Fs::Overlay).then_some(m.dev))??;
        let ovl = self.overlays.borrow();
        Some(ovl.instance(dev)?.options.private_prefix())
    }

    /// Some mount of namespace `ns` is on `node` (Linux's `is_local_mountpoint`). For overlay
    /// nodes, matches by overlay dentry across any bind mount of that overlay in `ns`.
    pub(crate) fn is_point_in(&self, node: &Node, ns: u64) -> bool {
        self.mounts.borrow().list.iter().any(|m| {
            m.ns == ns
                && match (node, &m.point) {
                    (Node::Overlay(_, a), Some(Node::Overlay(_, b))) => a == b,
                    (_, p) => p.as_ref() == Some(node),
                }
        })
    }

    /// The entries of overlay directory `o` ([`overlay::Overlays::readdir`]).
    pub(crate) fn overlay_readdir(&self, o: overlay::OvlId) -> Result<Vec<store::DirEntry>, Errno> {
        self.overlays.borrow().readdir(&self.store, o)
    }

    /// Mounts `root` in filesystem `fs` ([`Fs::root`], or a node reached through another mount)
    /// on `point`, returning the new mount's id. With `dev` None a device number is allocated
    /// ([`Fs::own_dev`]); bind mounts use the source's. When `point` is a file in the store,
    /// `at` is the directory and name where it was found ([`Mount::at`]).
    pub(crate) fn add_mount(
        &self,
        fs: Fs,
        root: Node,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        dev: Option<u64>,
    ) -> MountId {
        self.add_mount_inner((fs, root), point, flags, source, dev, true)
    }

    /// Like [`Vfs::add_mount`], leaving propagation at default and skipping `mounts_changed` for
    /// a caller (`bind`) that sets the source's locks and propagation, adds copies, and then calls
    /// [`Vfs::attached`] once.
    pub(crate) fn add_mount_unattached(
        &self,
        fs: Fs,
        root: Node,
        point: (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        dev: Option<u64>,
    ) -> MountId {
        self.add_mount_inner((fs, root), point, flags, source, dev, false)
    }

    fn add_mount_inner(
        &self,
        (fs, root): (Fs, Node),
        (point, at): (Node, Option<Dentry>),
        flags: u64,
        source: Vec<u8>,
        dev: Option<u64>,
        attach: bool,
    ) -> MountId {
        let mut mounts = self.mounts.borrow_mut();
        let id = mounts.next;
        mounts.next += 1;
        let dev = dev.unwrap_or_else(|| {
            mounts.next_dev += 1;
            mounts.next_dev - 1
        });
        let at = at.filter(|_| matches!(point, Node::Store(..)));
        // The new mount belongs to the namespace of the mount its mount point is in, and is
        // private unless mounted under a shared mount (no children exist yet for a brand-new id)
        let (ns, parent_shared) = mounts
            .get(point.mnt())
            .map_or((INIT_MNT_NS, false), |m| (m.ns, m.prop.group != 0));
        let prop = if attach && parent_shared {
            Propagation {
                group: GroupAlloc::of(&mounts).take(),
                master: 0,
                unbindable: false,
            }
        } else {
            Propagation::default()
        };
        mounts.push_attached(Mount {
            id,
            ns,
            fs,
            root: root.in_mount(id),
            point: Some(point),
            at,
            root_at: None,
            root_gone: false,
            flags: flags & ms::PER_MOUNT,
            dev,
            source,
            expiring: false,
            pin: None,
            locks: 0,
            prop,
            owner: None,
        });
        drop(mounts);
        if attach {
            self.mounts_changed_ns([ns]);
        }
        id
    }

    /// When mount `id` is a procfs instance, the pid namespace of the process that mounted it
    /// (None for the boot one).
    pub(crate) fn proc_pid_ns(&self, id: MountId) -> Option<std::rc::Rc<crate::pidns::PidNs>> {
        let mounts = self.mounts.borrow();
        let m = mounts.get(id)?;
        mounts.proc_ns.get(&m.dev).cloned()
    }

    /// When mount `id` is a non-initial sysfs instance, the network namespace of the process that
    /// mounted it (None for the boot instance and mounts in the initial network namespace).
    pub(crate) fn sys_net_ns(&self, id: MountId) -> Option<std::rc::Rc<crate::nsproxy::NetNs>> {
        let mounts = self.mounts.borrow();
        let m = mounts.get(id)?;
        mounts.sys_ns.get(&m.dev).cloned()
    }

    /// Adds copies of mounts below mount `to` at once (Linux's `copy_tree`, for recursive binds and
    /// open_tree): `plan` lists the mounts to copy, each after its parent, with the index in `plan`
    /// of its parent's copy (None for `to` itself). Each copy is mounted at the same place in its
    /// parent's copy, with the same filesystem, root, flags, device, source and pin, in the
    /// namespace of `to`. Done in one pass, so that copying n mounts costs O(n).
    pub(crate) fn add_copies(&self, to: MountId, plan: &[(Option<usize>, &Mount)]) {
        if plan.is_empty() {
            return;
        }
        let mut mounts = self.mounts.borrow_mut();
        let ns = mounts.get(to).map_or(INIT_MNT_NS, |m| m.ns);
        let mut ids: Vec<MountId> = Vec::with_capacity(plan.len());
        for (parent, c) in plan {
            let parent = parent.map_or(to, |i| ids[i]);
            // The plan has no mount without a point; one would leave its children to its parent
            let Some(point) = &c.point else {
                ids.push(parent);
                continue;
            };
            let id = mounts.next;
            mounts.next += 1;
            let point = point.clone().in_mount(parent);
            let at =
                c.at.clone()
                    .map(|(dir, name)| (dir.in_mount(parent), name))
                    .filter(|_| matches!(point, Node::Store(..)));
            mounts.push_attached(Mount {
                id,
                ns,
                fs: c.fs,
                root: c.root.clone().in_mount(id),
                point: Some(point),
                at,
                root_at: c.root_at.clone(),
                root_gone: c.root_gone,
                flags: c.flags & ms::PER_MOUNT,
                dev: c.dev,
                source: c.source.clone(),
                expiring: false,
                pin: c.pin.clone(),
                locks: c.locks,
                prop: c.prop.of_bind(),
                owner: c.owner.clone(),
            });
            ids.push(id);
        }
        drop(mounts);
        self.mounts_changed_ns([ns]);
    }

    /// Device number of the mqueue instance of IPC namespace `ns` (reported by nodes in the
    /// mqueue filesystem and by fds from mq_open): [`MQUEUE_DEV`] for the boot namespace,
    /// others allocated on first use.
    pub(crate) fn mq_dev(&self, ns: u64) -> u64 {
        if ns == crate::nsproxy::INIT_IPC_NS {
            return MQUEUE_DEV;
        }
        let mut mounts = self.mounts.borrow_mut();
        if let Some(&dev) = mounts.mq_dev.get(&ns) {
            return dev;
        }
        mounts.next_dev += 1;
        let dev = mounts.next_dev - 1;
        mounts.mq_dev.insert(ns, dev);
        dev
    }

    /// New procfs instance `id` belongs to pid namespace `ns`.
    pub(crate) fn set_proc_pid_ns(&self, id: MountId, ns: std::rc::Rc<crate::pidns::PidNs>) {
        let mut mounts = self.mounts.borrow_mut();
        if let Some(dev) = mounts.get_attached(id).map(|m| m.dev) {
            mounts.proc_ns.insert(dev, ns);
        }
    }

    /// Device number of the sysfs instance for network namespace `net`: [`Fs::Sys`]'s boot device
    /// for the initial network namespace, or one device per non-initial network namespace (reused
    /// while a sysfs mount of that namespace exists, matching Linux's `sget_fc` keyed by `net`).
    pub(crate) fn sys_dev(&self, net: &std::rc::Rc<crate::nsproxy::NetNs>) -> u64 {
        if net.id == crate::nsproxy::INIT_NET_NS {
            return Fs::Sys.dev();
        }
        let mut mounts = self.mounts.borrow_mut();
        if let Some((&dev, _)) = mounts.sys_ns.iter().find(|(_, n)| n.id == net.id) {
            return dev;
        }
        mounts.next_dev += 1;
        let dev = mounts.next_dev - 1;
        mounts.sys_ns.insert(dev, net.clone());
        dev
    }

    /// Mounts mounted directly in mount `id`, in mount order.
    pub(crate) fn children(&self, id: MountId) -> Vec<Mount> {
        let mounts = self.mounts.borrow();
        mounts
            .children
            .get(&id)
            .into_iter()
            .flatten()
            .filter_map(|&cid| mounts.get_attached(cid).cloned())
            .collect()
    }

    /// Detaches mount `id` and all mounts inside it (Linux's `umount_tree`): none of them is
    /// mounted on another mount any more, and each one's root has no parent.
    #[cfg(test)]
    fn remove_mount(&self, id: MountId) {
        let mut mounts = self.mounts.borrow_mut();
        let ns = mounts.get_attached(id).map(|m| m.ns);
        let gone: std::collections::HashSet<MountId> =
            mounts.attached_subtree(id).into_iter().collect();
        detach(&mut mounts, |m| gone.contains(&m.id));
        drop(mounts);
        self.mounts_changed_ns(ns);
    }

    /// Marks that detached mounts need collection on the next pass (used when a collection found
    /// task tables borrowed).
    pub(crate) fn defer_collect(&self) {
        self.mounts.borrow_mut().collect_pending = true;
    }

    /// Whether a mount this thread let go of since the last call ([`released`]) is detached, or a
    /// kernel-wide collection retry was scheduled, so that [`Vfs::collect`] may now drop it.
    pub(crate) fn released_detached(&self) -> bool {
        let released = RELEASED.with(|r| std::mem::take(&mut *r.borrow_mut()));
        let mut mounts = self.mounts.borrow_mut();
        let pending = std::mem::take(&mut mounts.collect_pending);
        if pending {
            return true;
        }
        if released.is_empty() {
            return false;
        }
        let any = released[0] == ANY_MOUNT;
        mounts
            .detached
            .iter()
            .any(|m| any || released.contains(&m.id))
    }

    /// Drops detached mounts not in `in_use` (no process's root or current directory and no
    /// open file is in them) and not connected below one that is. tmpfs instances no mount can
    /// see any more are deleted with their files.
    pub(crate) fn collect(&self, in_use: &std::collections::HashSet<MountId>) {
        self.mounts.borrow_mut().collect_pending = false;
        // Mount namespaces nobody uses: all their mounts are detached
        self.namespaces
            .borrow_mut()
            .retain(|w| w.strong_count() > 0);
        let live: std::collections::HashSet<u64> = self
            .namespaces
            .borrow()
            .iter()
            .filter_map(std::rc::Weak::upgrade)
            .map(|ns| ns.id)
            .chain([INIT_MNT_NS])
            .collect();
        self.ns_events
            .borrow_mut()
            .retain(|id, _| live.contains(id));
        if self
            .mounts
            .borrow()
            .list
            .iter()
            .any(|m| !live.contains(&m.ns))
        {
            let mut mounts = self.mounts.borrow_mut();
            detach(&mut mounts, |m| !live.contains(&m.ns));
            drop(mounts);
            self.rebuild_cached();
        }
        let gone: Vec<Ino> = {
            let mut mounts = self.mounts.borrow_mut();
            if !mounts.detached.is_empty() {
                keep_used(&mut mounts.detached, in_use);
                mounts.rebuild_index();
            }
            // Overlays without a mount go, and the tmpfs instances the others' layers are in stay
            let overlays: std::collections::HashSet<u64> = mounts
                .list
                .iter()
                .chain(&mounts.detached)
                .filter(|m| m.fs == Fs::Overlay)
                .map(|m| m.dev)
                .collect();
            let mut ovl = self.overlays.borrow_mut();
            for dev in ovl.devs() {
                if !overlays.contains(&dev) {
                    ovl.remove_instance(dev);
                }
            }
            let devs_of = |mounts: &Mounts, fs| -> std::collections::HashSet<u64> {
                mounts
                    .list
                    .iter()
                    .chain(&mounts.detached)
                    .filter(|m| m.fs == fs)
                    .map(|m| m.dev)
                    .collect()
            };
            // A FUSE instance without a mount aborts its connection, so its daemon's reads fail
            // and it exits (6.1's `fuse_sb_destroy`)
            let fuses = devs_of(&mounts, Fs::Fuse);
            let mut fuse = self.fuse.borrow_mut();
            for dev in fuse.devs() {
                if !fuses.contains(&dev) {
                    fuse.remove(dev);
                }
            }
            drop(fuse);
            let mut live = devs_of(&mounts, Fs::Tmpfs);
            live.extend(ovl.pinned());
            drop(ovl);
            let dead: std::collections::HashSet<u64> = mounts
                .tmpfs
                .keys()
                .filter(|dev| !live.contains(dev))
                .copied()
                .collect();
            let procs = devs_of(&mounts, Fs::Proc);
            mounts.proc_ns.retain(|dev, _| procs.contains(dev));
            let syss = devs_of(&mounts, Fs::Sys);
            mounts.sys_ns.retain(|dev, _| syss.contains(dev));
            let pts = devs_of(&mounts, Fs::Pts);
            mounts.devpts.retain(|dev, _| pts.contains(dev));
            self.tmpfs_file_ranges
                .borrow_mut()
                .retain(|_, file| !dead.contains(&file.dev));
            dead.iter()
                .filter_map(|dev| mounts.tmpfs.remove(dev))
                .map(|t| t.root)
                .collect()
        };
        for root in gone {
            if let Err(e) = self.store.remove_detached_dir(root) {
                crate::debug::log(format_args!("cannot remove tmpfs {root}: {e}"));
            }
        }
        // The dropped mounts included a mount namespace file bound elsewhere: that namespace may
        // now be unused too
        if self.has_dead_ns() {
            self.collect(in_use);
        }
    }

    /// Some mount namespace has no references left while its mounts are not yet detached:
    /// cleanup must handle it.
    pub(crate) fn has_dead_ns(&self) -> bool {
        self.namespaces
            .borrow()
            .iter()
            .any(|w| w.strong_count() == 0)
    }

    /// Moves attached mount `id` onto `point` (`MS_MOVE`, pivot_root); None makes it the root
    /// of the mount tree.
    pub(crate) fn move_mount(&self, id: MountId, point: Option<(Node, Option<Dentry>)>) {
        let mut mounts = self.mounts.borrow_mut();
        let ns = mounts.get_attached(id).map(|m| m.ns);
        if ns.is_some() {
            let (point, at) = match point {
                Some((p, at)) => {
                    let at = at.filter(|_| matches!(p, Node::Store(..)));
                    (Some(p), at)
                }
                None => (None, None),
            };
            mounts.set_point(id, point, at);
        }
        drop(mounts);
        self.mounts_changed_ns(ns);
    }

    /// Records in which directory and under which name a bind-mounted file was found
    /// ([`Mount::root_at`]).
    pub(crate) fn set_root_at(&self, id: MountId, at: Option<Dentry>) {
        self.update_mount(id, |m| m.root_at = at);
    }

    /// Changes the propagation type of mount `id` (attached or detached), and with `recursive` of
    /// the mounts below it (Linux's `do_change_type`; for `Shared` every mount first gets a peer
    /// group of its own, `invent_group_ids`). Propagation-only changes do not bump mount
    /// namespace event counters (Linux's `do_change_type` does not call `touch_mnt_namespace`).
    pub(crate) fn set_propagation(&self, id: MountId, kind: PropagationType, recursive: bool) {
        let mut mounts = self.mounts.borrow_mut();
        let ids = if recursive {
            mounts.subtree(id)
        } else {
            vec![id]
        };
        mounts.change_propagations(&ids, kind);
    }

    /// Copies propagation group/master onto attached mount `id` (`move_mount(MOVE_MOUNT_SET_GROUP)`).
    /// Propagation-only, so it does not bump mount namespace event counters.
    pub(crate) fn set_mount_prop(&self, id: MountId, prop: Propagation) {
        if let Some(m) = self.mounts.borrow_mut().get_attached_mut(id) {
            m.prop = prop;
        }
    }

    /// Mount `id` was just attached (a new mount, a bind, a move): under a shared parent it and
    /// the mounts below it become shared, each without a peer group getting one of its own (6.1's
    /// `attach_recursive_mnt`; [`Vfs::propagate`] then copies them to the parent's peers and
    /// slaves).
    pub(crate) fn attached(&self, id: MountId) {
        let mut mounts = self.mounts.borrow_mut();
        let Some(parent) = mounts.get(id).and_then(Mount::parent) else {
            return;
        };
        if mounts.get(parent).is_none_or(|m| m.prop.group == 0) {
            return;
        }
        let ids = mounts.subtree(id);
        mounts.change_propagations(&ids, PropagationType::Shared);
    }

    /// The propagation of mount `id` (attached or detached).
    pub(crate) fn propagation(&self, id: MountId) -> Propagation {
        self.mounts
            .borrow()
            .get(id)
            .map_or_else(Propagation::default, |m| m.prop)
    }

    /// Builds a propagation [`Index`] over `list`, excluding mounts in live anonymous namespaces
    /// (unattached `open_tree(OPEN_TREE_CLONE)` trees, Linux's `IS_MNT_NEW`).
    fn prop_index(&self, list: &[Mount]) -> Index {
        let anon: std::collections::HashSet<u64> = self
            .namespaces
            .borrow()
            .iter()
            .filter_map(std::rc::Weak::upgrade)
            .filter(|ns| ns.anon)
            .map(|ns| ns.id)
            .collect();
        Index::of(list, &anon)
    }

    /// `start` (mount-id 0) and every ancestor directory above it within its underlying
    /// filesystem, stopping at the filesystem root (or on error / cycle).
    // PinnedNet/PinnedIpc/PinnedUts/PinnedPid inside PseudoNode hash and compare only by immutable
    // namespace id.
    #[allow(clippy::mutable_key_type)]
    fn fs_ancestors(&self, ps: &dyn Pseudo, start: &Node) -> std::collections::HashSet<Node> {
        let mut ancestors = std::collections::HashSet::new();
        let mut cur = start.clone();
        while ancestors.insert(cur.clone()) {
            let up = match &cur {
                Node::Store(id, ino) => match self.store.parent(*ino) {
                    Ok(p) => Node::Store(*id, p),
                    Err(_) => break,
                },
                Node::Pseudo(id, p) => match ps.parent(p) {
                    Some(up) => Node::Pseudo(*id, up),
                    None => break,
                },
                Node::Overlay(id, o) => Node::Overlay(*id, self.overlays.borrow().parent(*o)),
                Node::Fuse(id, f) => match self.fuse.borrow().get(*f) {
                    Some(n) => Node::Fuse(*id, n.parent),
                    None => break,
                },
            };
            if up == cur {
                break;
            }
            cur = up;
        }
        ancestors
    }

    // ---- Propagation of mount events (fs/pnode.c) ----

    /// The mounts a tree attached on `point` (`at` when it is a file in the store) gets copied to
    /// (Linux's `propagate_mnt`): when the mount `point` is in is shared, its peers and slaves,
    /// recursively, that see the mount point (`propagate_one` skips the others), each with the
    /// place there. Planned before attaching, so a new mount's or a bind's own mounts are not
    /// among them; a moved attached tree or an open_tree clone is already in the table, and a mount
    /// of its own that the place propagates to is one (it gets one copy of the tree).
    pub(crate) fn propagation_targets(
        &self,
        ps: &dyn Pseudo,
        (point, at): (&Node, Option<&Dentry>),
    ) -> Vec<Target> {
        let planned: Vec<(MountId, u64, Node, u32, Vec<u32>)> = {
            let mounts = self.mounts.borrow();
            let index = self.prop_index(&mounts.list);
            index
                .propagation_of(&mounts.list, point.mnt())
                .into_iter()
                .map(|(i, masters)| {
                    let m = &mounts.list[i];
                    (m.id, m.ns, m.root.clone(), m.prop.group, masters)
                })
                .collect()
        };
        if planned.is_empty() {
            return Vec::new();
        }
        // Every target mount sees the same underlying filesystem instance, and `from` and `root`
        // are both inside that mount (`root == m.root`), so reachability only walks up the
        // underlying filesystem without crossing mount boundaries; precomputing the ancestor set
        // of `from` once keeps filtering O(depth + targets).
        let from_base = at.filter(|_| matches!(point, Node::Store(..))).map_or_else(
            || point.clone().in_mount(0),
            |(dir, _)| dir.clone().in_mount(0),
        );
        #[allow(clippy::mutable_key_type)]
        let ancestors = self.fs_ancestors(ps, &from_base);
        planned
            .into_iter()
            .filter_map(|(mount, ns, root, group, masters)| {
                let point = point.clone().in_mount(mount);
                let on_root = point == root;
                // On the mount's root the directory it was found in is outside the mount
                let at = at
                    .filter(|_| matches!(point, Node::Store(..)) && !on_root)
                    .map(|(dir, name)| (dir.clone().in_mount(mount), name.clone()));
                let seen = on_root || ancestors.contains(&root.in_mount(0));
                seen.then_some(Target {
                    ns,
                    point,
                    at,
                    group,
                    masters,
                })
            })
            .collect()
    }

    /// Mount `id` and the mounts below it were attached where `targets` were planned
    /// ([`Vfs::propagation_targets`]): each target gets a copy of the tree at the same place
    /// (the rest of Linux's `propagate_one` and `attach_recursive_mnt`). A copy in a peer of the
    /// parent is a peer of the original; one in a slave is a slave of the copy in the nearest group
    /// above it that got one (of the original when none did), and when that slave is shared, the
    /// copies in its group are peers of each other. A mount already on that place is moved onto
    /// the copy's root (tucked under it). In a namespace owned by another user namespace than
    /// `owner` (the caller's mount namespace's) every copy is locked (`lock_mnt_tree`); the root of
    /// each copy is never locked in place.
    pub(crate) fn propagate(&self, id: MountId, targets: &[Target], owner: u64) {
        if targets.is_empty() {
            return;
        }
        let mut owners: HashMap<u64, u64> = HashMap::from([(INIT_MNT_NS, self.init_ns.owner.id)]);
        for ns in self
            .namespaces
            .borrow()
            .iter()
            .filter_map(std::rc::Weak::upgrade)
        {
            owners.insert(ns.id, ns.owner.id);
        }
        let mut mounts = self.mounts.borrow_mut();
        // The tree in the order to copy it (each after its parent), with each one's parent index
        let tree: Vec<Mount> = mounts
            .attached_subtree(id)
            .into_iter()
            .filter_map(|mid| mounts.get_attached(mid).cloned())
            .collect();
        let in_tree: HashMap<MountId, usize> =
            tree.iter().enumerate().map(|(i, m)| (m.id, i)).collect();
        let parents: Vec<Option<usize>> = tree
            .iter()
            .map(|m| {
                (m.id != id)
                    .then(|| m.parent().and_then(|p| in_tree.get(&p).copied()))
                    .flatten()
            })
            .collect();
        // What is on each place now: a copy goes under it
        let index = self.prop_index(&mounts.list);
        // The groups of the copies made in each group of the propagation tree, by position in
        // the tree; the parent's own group has the original
        let top = tree[0]
            .parent()
            .and_then(|p| mounts.get_attached(p))
            .map_or(0, |m| m.prop.group);
        let mut copies: HashMap<u32, Vec<u32>> =
            HashMap::from([(top, tree.iter().map(|m| m.prop.group).collect())]);
        let mut groups = GroupAlloc::of(&mounts);
        for t in targets {
            let props: Vec<Propagation> = if t.masters.is_empty() {
                tree.iter().map(|m| m.prop.of_bind()).collect()
            } else {
                let masters = t
                    .masters
                    .iter()
                    .find_map(|g| copies.get(g))
                    .cloned()
                    .unwrap_or_default();
                let own: Vec<u32> = match t.group {
                    0 => vec![0; tree.len()],
                    g => copies
                        .entry(g)
                        .or_insert_with(|| tree.iter().map(|_| groups.take()).collect())
                        .clone(),
                };
                masters
                    .into_iter()
                    .zip(own)
                    .map(|(master, group)| Propagation {
                        group,
                        master,
                        unbindable: false,
                    })
                    .collect()
            };
            let lock = owners.get(&t.ns).copied() != Some(owner);
            let mut ids: Vec<MountId> = Vec::with_capacity(tree.len());
            for (i, m) in tree.iter().enumerate() {
                let new = mounts.next;
                mounts.next += 1;
                let (point, at) = match parents[i] {
                    None => (t.point.clone(), t.at.clone()),
                    Some(p) => (
                        m.point.clone().unwrap_or(Node::ROOT).in_mount(ids[p]),
                        m.at.clone().map(|(dir, name)| (dir.in_mount(ids[p]), name)),
                    ),
                };
                let mut locks = if lock {
                    locked_tree(m.flags, m.locks)
                } else {
                    m.locks
                };
                if i == 0 {
                    locks &= !lock::MOUNT;
                }
                mounts.push_attached(Mount {
                    id: new,
                    ns: t.ns,
                    root: m.root.clone().in_mount(new),
                    point: Some(point),
                    at,
                    expiring: false,
                    locks,
                    prop: props.get(i).copied().unwrap_or_default(),
                    ..m.clone()
                });
                ids.push(new);
            }
            if let Some(q) = index.at_place(&mounts.list, &t.point, t.at.as_ref()) {
                let q_id = mounts.list[q].id;
                let root = tree[0].root.clone().in_mount(ids[0]);
                mounts.set_point(q_id, Some(root), None);
            }
        }
        let affected: std::collections::HashSet<u64> = targets.iter().map(|t| t.ns).collect();
        drop(mounts);
        self.mounts_changed_ns(affected);
    }

    /// Whether unmounting mount `id` without `MNT_DETACH` would take down a mount in use
    /// elsewhere (Linux's `propagate_mount_busy`): in each mount its parent propagates to, the
    /// mount on the same place, when nothing is mounted on it except one mount covering its root,
    /// is in `in_use`.
    pub(crate) fn propagated_busy(
        &self,
        id: MountId,
        in_use: &std::collections::HashSet<MountId>,
    ) -> bool {
        let mounts = self.mounts.borrow();
        let index = self.prop_index(&mounts.list);
        let Some(m) = index.pos.get(&id).map(|&i| &mounts.list[i]) else {
            return false;
        };
        let Some(parent) = m.parent() else {
            return false;
        };
        index
            .propagation_of(&mounts.list, parent)
            .iter()
            .any(|&(to, _)| {
                let Some(c) = index.on_spot(&mounts.list, m, mounts.list[to].id) else {
                    return false;
                };
                let kids = index.children(c.id);
                let topper =
                    kids.len() == 1 && mounts.list[kids[0]].point.as_ref() == Some(&c.root);
                (kids.is_empty() || topper) && in_use.contains(&c.id)
            })
    }

    /// Unmounts mount `id` and the mounts below it (Linux's `umount_tree` with
    /// `UMOUNT_PROPAGATE`): for each of them whose parent is shared, the mount on the same place
    /// in each mount the parent's group propagates to goes too (`propagate_umount`), once nothing
    /// is mounted on it but mounts going with it and one mount covering its root, and unless it
    /// is locked in place; what stays but was mounted on a mount that goes (one covering its
    /// root) moves to the place of the nearest mount above it that stays (`restore_mounts`).
    pub(crate) fn umount_tree(&self, id: MountId) {
        let mut mounts = self.mounts.borrow_mut();
        let order = mounts.attached_subtree(id);
        let list = &mounts.list;
        let index = self.prop_index(list);
        let gone: std::collections::HashSet<MountId> = order.iter().copied().collect();
        // The mounts on the same places elsewhere, each place of a peer group visited once.
        // PinnedNet/PinnedIpc/PinnedUts/PinnedPid inside PseudoNode hash and compare only by
        // immutable namespace id.
        #[allow(clippy::mutable_key_type)]
        let mut visited = std::collections::HashSet::new();
        let mut candidates: Vec<usize> = Vec::new();
        let mut is_candidate = std::collections::HashSet::new();
        for m in order.iter().rev().filter_map(|m| index.pos.get(m)) {
            let m = &list[*m];
            let Some(parent) = m.parent().and_then(|p| index.pos.get(&p)) else {
                continue;
            };
            let group = list[*parent].prop.group;
            if group == 0 {
                continue;
            }
            let place = (
                m.point.clone().map(|p| p.in_mount(0)),
                m.at.clone().map(|(dir, name)| (dir.in_mount(0), name)),
            );
            if !visited.insert((group, place)) {
                continue;
            }
            for to in index.group_tree(list, group) {
                if let Some(c) = index.on_spot(list, m, list[to].id)
                    && !gone.contains(&c.id)
                    && is_candidate.insert(c.id)
                {
                    candidates.push(index.pos[&c.id]);
                }
            }
        }
        // Marked: nothing is mounted on it but one covering its root, mounts going with the tree
        // and marked mounts; deepest first, each marked one letting its parent be checked again
        let covers = |c: usize, k: usize| list[k].point.as_ref() == Some(&list[c].root);
        let mut blocking: HashMap<usize, usize> = HashMap::new();
        let mut ready: Vec<usize> = Vec::new();
        for &c in &candidates {
            let n = index
                .children(list[c].id)
                .iter()
                .filter(|&&k| !covers(c, k) && !gone.contains(&list[k].id))
                .count();
            blocking.insert(c, n);
            if n == 0 {
                ready.push(c);
            }
        }
        let mut marked = std::collections::HashSet::new();
        while let Some(c) = ready.pop() {
            if !marked.insert(c) {
                continue;
            }
            if let Some(&p) = list[c].parent().and_then(|p| index.pos.get(&p))
                && !covers(p, c)
                && let Some(n) = blocking.get_mut(&p)
            {
                *n -= 1;
                if *n == 0 {
                    ready.push(p);
                }
            }
        }
        // The marked ones not locked in place go, with everything mounted on them but what covers
        // a root
        let mut out: std::collections::HashSet<MountId> = gone.clone();
        let mut extra: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|c| marked.contains(c) && list[*c].locks & lock::MOUNT == 0)
            .collect();
        while let Some(c) = extra.pop() {
            if !out.insert(list[c].id) {
                continue;
            }
            extra.extend(
                index
                    .children(list[c].id)
                    .iter()
                    .filter(|&&k| !covers(c, k)),
            );
        }
        // What stays but was mounted on one that goes moves up
        let mut moves: Vec<(usize, Place)> = Vec::new();
        for &o in &out {
            for &k in index.children(o) {
                if out.contains(&list[k].id) {
                    continue;
                }
                let mut spot = (list[k].point.clone(), list[k].at.clone());
                let mut up = index.pos.get(&o).copied();
                while let Some(p) = up.filter(|&p| out.contains(&list[p].id)) {
                    spot = (list[p].point.clone(), list[p].at.clone());
                    up = list[p].parent().and_then(|q| index.pos.get(&q)).copied();
                }
                moves.push((k, spot));
            }
        }
        for (k, (point, at)) in moves {
            (mounts.list[k].point, mounts.list[k].at) = (point, at);
        }
        let affected: std::collections::HashSet<u64> = mounts
            .list
            .iter()
            .filter(|m| out.contains(&m.id))
            .map(|m| m.ns)
            .collect();
        detach(&mut mounts, |m| out.contains(&m.id));
        drop(mounts);
        self.mounts_changed_ns(affected);
    }

    /// The mount whose root `node` is, attached or detached.
    pub(crate) fn any_mount_root(&self, node: &Node) -> Option<MountId> {
        self.mounts
            .borrow()
            .get(node.mnt())
            .filter(|m| m.root == *node)
            .map(|m| m.id)
    }

    /// Marks attached mount `id` as expiring (`umount2(MNT_EXPIRE)`).
    pub(crate) fn set_expiring(&self, id: MountId) {
        let mut mounts = self.mounts.borrow_mut();
        if let Some(m) = mounts.get_attached_mut(id)
            && !m.expiring
        {
            m.expiring = true;
            self.expiring.set(self.expiring.get() + 1);
        }
    }

    /// Clears the `MNT_EXPIRE` mark on attached mount `id` when accessed (Linux's `mntput`).
    pub(crate) fn touch_mount(&self, id: MountId) {
        if self.expiring.get() == 0 {
            return;
        }
        let mut mounts = self.mounts.borrow_mut();
        if let Some(m) = mounts.get_attached_mut(id)
            && m.expiring
        {
            m.expiring = false;
            self.expiring.set(self.expiring.get().saturating_sub(1));
        }
    }

    /// Changes attached mount `id` through `f` (its flags, the MNT_EXPIRE mark, its locks and the
    /// like), keeping only per-mount flags, and reports a mount change. Must not alter `id` or
    /// `point` (use [`Vfs::move_mount`] for mount-point changes).
    pub(crate) fn update_mount(&self, id: MountId, f: impl FnOnce(&mut Mount)) {
        let ns = if let Some(m) = self.mounts.borrow_mut().get_attached_mut(id) {
            let old_parent = m.parent();
            f(m);
            debug_assert_eq!(m.id, id);
            debug_assert_eq!(m.parent(), old_parent);
            m.flags &= ms::PER_MOUNT;
            Some(m.ns)
        } else {
            None
        };
        self.mounts_changed_ns(ns);
    }

    /// Applies `mount_setattr(2)` to attached mount `id` (and the attached mounts below it when
    /// `recursive` is set): validates locked flags (`EPERM`) and writers for mounts turning
    /// read-only (`EBUSY`, computed lazily via `open_writers`) before mutating anything, updates
    /// flags and optional propagation in one pass, and rebuilds the fast path's mount points once
    /// at the end. Propagation-only calls do not bump mount namespace event counters.
    pub(crate) fn set_mount_attrs(
        &self,
        id: MountId,
        recursive: bool,
        changed: impl Fn(&Mount) -> u64,
        making_readonly: bool,
        open_writers: impl FnOnce() -> std::collections::HashSet<MountId>,
        propagation: Option<PropagationType>,
    ) -> Result<(), Errno> {
        let (targets, turning_ro) = {
            let mounts = self.mounts.borrow();
            let targets = if recursive {
                mounts.attached_subtree(id)
            } else {
                vec![id]
            };
            let mut turning_ro = Vec::new();
            for &t in &targets {
                let Some(m) = mounts.get_attached(t) else {
                    continue;
                };
                if !m.keeps_locked(changed(m)) {
                    return Err(Errno::EPERM);
                }
                if making_readonly && m.flags & ms::RDONLY == 0 {
                    turning_ro.push(t);
                }
            }
            (targets, turning_ro)
        };
        if !turning_ro.is_empty() {
            let writers = open_writers();
            if turning_ro.iter().any(|t| writers.contains(t)) {
                return Err(Errno::EBUSY);
            }
        }
        let mut mounts = self.mounts.borrow_mut();
        let mut flags_changed = false;
        let mut ns = None;
        for &t in &targets {
            if let Some(m) = mounts.get_attached_mut(t) {
                ns = Some(m.ns);
                let next = changed(m) & ms::PER_MOUNT;
                if next != m.flags {
                    m.flags = next;
                    flags_changed = true;
                }
            }
        }
        if let Some(kind) = propagation {
            mounts.change_propagations(&targets, kind);
        }
        drop(mounts);
        if flags_changed {
            self.mounts_changed_ns(ns);
        }
        Ok(())
    }

    /// Runs `f` on the mount with id `id` (attached or detached).
    fn with_mount<T>(&self, id: MountId, f: impl FnOnce(&Mount) -> T) -> Option<T> {
        self.mounts.borrow().get(id).map(f)
    }

    /// Rebuilds the mount-point cache used by no-BKL path resolution without bumping any
    /// namespace's poll event counter.
    fn rebuild_cached(&self) {
        let (points, usable, expiring) = {
            let mounts = self.mounts.borrow();
            (
                mounts.store_points(),
                mounts.fast_usable(),
                mounts.list.iter().filter(|m| m.expiring).count(),
            )
        };
        self.expiring.set(expiring);
        let mut cached = self.cached.borrow_mut();
        cached.mounts = points;
        cached.usable = usable;
    }

    /// The mount table changed in namespaces `nss`: rebuilds the no-BKL path cache (the caller
    /// separately calls [`Shared::fast_changed`](crate::kernel::Shared::fast_changed)) and bumps
    /// each affected namespace's event counter (Linux's `touch_mnt_namespace`) so readers polling
    /// its mounts/mountinfo wake with `POLLPRI|POLLERR`.
    fn mounts_changed_ns(&self, nss: impl IntoIterator<Item = u64>) {
        self.rebuild_cached();
        let mut seen = std::collections::HashSet::new();
        for ns_id in nss {
            if seen.insert(ns_id) && self.find_ns(ns_id).is_some_and(|ns| !ns.anon) {
                let counter = self.mount_events_of(ns_id);
                counter.set(counter.get() + 1);
                crate::kernel::request_wake_object(crate::kernel::wake::of_value(&*counter));
            }
        }
    }

    /// The change counter for mount namespace `ns` (Linux's `mnt_ns->event`).
    pub(crate) fn mount_events_of(&self, ns: u64) -> std::rc::Rc<std::cell::Cell<u64>> {
        self.ns_events
            .borrow_mut()
            .entry(ns)
            .or_insert_with(|| std::rc::Rc::new(std::cell::Cell::new(1)))
            .clone()
    }
}

/// When there is no `/etc/resolv.conf`, writes one pointing at the DNS stub (the kernel/net
/// map); an existing one is left alone.
fn ensure_resolv_conf(store: &Store) -> Result<(), Errno> {
    let Some(etc) = store.lookup(ROOT, b"etc")? else {
        return Ok(());
    };
    if store.lookup(etc, b"resolv.conf")?.is_some() {
        return Ok(());
    }
    write_file(
        store,
        b"/etc/resolv.conf",
        b"nameserver 127.0.0.53\n",
        0o644,
        false,
    )
}

fn validate_host_path(path: &[u8]) -> Result<(), Errno> {
    if !path.starts_with(b"/") || path.contains(&0) {
        return Err(Errno::EINVAL);
    }
    for name in path.split(|&b| b == b'/') {
        if name == b".." {
            return Err(Errno::EINVAL);
        }
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
    }
    Ok(())
}

/// Writes a regular file in the store (for the host to prepare configuration files): missing
/// parent directories are created too (0755, owned by root), and symlinks in the path are not
/// followed. When the file already exists, it is left alone if `overwrite` is false, otherwise its
/// contents are replaced (permission bits and owner unchanged). New files are owned by root.
pub fn write_file(
    store: &Store,
    path: &[u8],
    data: &[u8],
    mode: u32,
    overwrite: bool,
) -> Result<(), Errno> {
    write_file_owned(store, path, data, mode, overwrite, 0, 0)
}

/// Like [`write_file`], creating a new regular file owned by `uid` and `gid` (missing parent
/// directories still belong to root).
pub fn write_file_owned(
    store: &Store,
    path: &[u8],
    data: &[u8],
    mode: u32,
    overwrite: bool,
    uid: u32,
    gid: u32,
) -> Result<(), Errno> {
    use std::io::Write;
    validate_host_path(path)?;
    let comps: Vec<Vec<u8>> = split(path).collect();
    let (name, dirs) = comps.split_last().ok_or(Errno::EINVAL)?;
    let mut dir = ROOT;
    for c in dirs {
        dir = match store.lookup(dir, c)? {
            Some(ino) if store.kind(ino)? == mode::S_IFDIR => ino,
            Some(_) => return Err(Errno::ENOTDIR),
            None => store.mkdir(dir, c, 0o755, 0, 0)?,
        };
    }
    let mut file = match store.lookup(dir, name)? {
        Some(_) if !overwrite => return Ok(()),
        Some(ino) if store.kind(ino)? == mode::S_IFREG => {
            store.truncate(ino, 0)?;
            store.open_object(ino, true)?
        }
        Some(_) => return Err(Errno::EEXIST),
        None => store.create_file(dir, name, mode & 0o7777, uid, gid)?.1,
    };
    file.write_all(data)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))
}

/// Reads a regular file in the store (for the host to look at configuration files, such as the
/// accounts in `/etc/passwd` listed in settings): symlinks in the path are not followed (as in
/// [`write_file`]); a missing file is `ENOENT`, and one that is not a regular file `EINVAL`.
pub fn read_file(store: &Store, path: &[u8]) -> Result<Vec<u8>, Errno> {
    use std::io::Read;
    let mut data = Vec::new();
    open_config_file(store, path)?
        .read_to_end(&mut data)
        .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
    Ok(data)
}

fn open_config_file(store: &Store, path: &[u8]) -> Result<std::fs::File, Errno> {
    validate_host_path(path)?;
    let mut ino = ROOT;
    for c in split(path) {
        if store.kind(ino)? != mode::S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        ino = store.lookup(ino, &c)?.ok_or(Errno::ENOENT)?;
    }
    if store.kind(ino)? != mode::S_IFREG {
        return Err(Errno::EINVAL);
    }
    store.open_object(ino, false)
}

enum Step {
    Name(Vec<u8>),
    /// Synthetic step for a trailing `/` (forces a directory and follows a trailing symlink while
    /// preserving `WALK_TRAILING` for `fs.protected_symlinks`).
    TrailingSlash,
}

/// Components for path resolution: `.` is kept, and with a trailing `/` a [`Step::TrailingSlash`]
/// is added so the preceding node must be a directory and a symlink in the last component is
/// followed too (as on Linux) while still treated as trailing for `protected_symlinks`.
fn components(path: &[u8]) -> VecDeque<Step> {
    let mut comps: VecDeque<Step> = path
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .map(|c| Step::Name(c.to_vec()))
        .collect();
    if path.ends_with(b"/") {
        comps.push_back(Step::TrailingSlash);
    }
    comps
}

/// Splits path components, dropping empty components and `.`.
fn split(path: &[u8]) -> impl DoubleEndedIterator<Item = Vec<u8>> + '_ {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(<[u8]>::to_vec)
}

thread_local! {
    /// The mounts of the open files, current directories and roots this thread let go of since
    /// [`Vfs::released_detached`] last looked ([`released`]); [`ANY_MOUNT`] alone when more went.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static RELEASED: std::cell::RefCell<Vec<MountId>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// [`RELEASED`] held too many: any detached mount may have lost its last use.
pub(crate) const ANY_MOUNT: MountId = MountId::MAX;

/// An open file, current directory or root in mount `mnt` went away. When that was the last use
/// of a detached mount, the mount goes at the end of the syscall or of the thread (Linux drops
/// it with its last reference, so a lazily unmounted FUSE mount aborts its connection then and
/// its daemon exits; `syscall::mount::collect_unused`).
pub(crate) fn released(mnt: MountId) {
    RELEASED.with(|r| {
        let Ok(mut r) = r.try_borrow_mut() else {
            return;
        };
        if r.first() == Some(&ANY_MOUNT) || r.contains(&mnt) {
            return;
        }
        if r.len() < 16 {
            r.push(mnt);
        } else {
            *r = vec![ANY_MOUNT];
        }
    });
}

/// The locks of a mount made for a less privileged user namespace (Linux's `lock_mnt_tree`): it
/// is locked in place, its access-time flags are locked, and so are its read-only, nodev, nosuid
/// and noexec flags where set.
fn locked_tree(flags: u64, locks: u64) -> u64 {
    let mut locks = locks | lock::MOUNT | lock::ATIME;
    for (f, l) in [
        (ms::RDONLY, lock::READONLY),
        (ms::NODEV, lock::NODEV),
        (ms::NOSUID, lock::NOSUID),
        (ms::NOEXEC, lock::NOEXEC),
    ] {
        if flags & f != 0 {
            locks |= l;
        }
    }
    locks
}

/// Moves the attached mounts that `gone` picks to the detached list (Linux's `umount_tree`
/// without `UMOUNT_SYNC`): each is disconnected from its mount point, except a mount locked in
/// place whose parent is detached with it, which stays on that parent (`disconnect_mount`), so an
/// fd kept in the detached tree still finds it there and cannot reach what it covers.
fn detach(mounts: &mut Mounts, gone: impl Fn(&Mount) -> bool) {
    let list = std::mem::take(&mut mounts.list);
    let (out, keep): (Vec<_>, Vec<_>) = list.into_iter().partition(|m| gone(m));
    mounts.list = keep;
    let ids: std::collections::HashSet<MountId> = out.iter().map(|m| m.id).collect();
    for mut m in out {
        let connected =
            m.locks & lock::MOUNT != 0 && m.parent().is_some_and(|p| p != m.id && ids.contains(&p));
        if !connected {
            m.point = None;
            m.at = None;
        }
        mounts.detached.push(m);
    }
    mounts.rebuild_index();
    // Unmounted mounts leave their peer groups (umount_tree's change_mnt_propagation(MS_PRIVATE))
    mounts.make_private(&ids);
}

// ---- Propagation types (fs/pnode.c) ----

impl Mounts {
    fn all(&self) -> impl Iterator<Item = &Mount> {
        self.list.iter().chain(&self.detached)
    }

    /// Mount `id` and the mounts below it (attached or detached), level by level downwards.
    fn subtree(&self, id: MountId) -> Vec<MountId> {
        let mut out = vec![id];
        let mut i = 0;
        while let Some(&parent) = out.get(i) {
            if let Some(kids) = self.children.get(&parent) {
                out.extend_from_slice(kids);
            }
            i += 1;
        }
        out
    }

    /// Attached mount `id` and the attached mounts below it, level by level downwards.
    fn attached_subtree(&self, id: MountId) -> Vec<MountId> {
        let mut out = vec![id];
        let mut i = 0;
        while let Some(&parent) = out.get(i) {
            if let Some(kids) = self.children.get(&parent) {
                out.extend(
                    kids.iter()
                        .copied()
                        .filter(|&k| matches!(self.by_id.get(&k), Some(MountLoc::Attached(_)))),
                );
            }
            i += 1;
        }
        out
    }

    /// Changes the propagation type of every mount in `ids` (Linux's `change_mnt_propagation`).
    /// For `Shared`, each mount without a peer group gets the smallest unused group id in `ids`
    /// order (`invent_group_ids`). For `Slave`, `Private` and `Unbindable`, peer groups left
    /// without members hand their slaves up to their own master (transitively) in O(N) total.
    fn change_propagations(&mut self, ids: &[MountId], kind: PropagationType) {
        if ids.is_empty() {
            return;
        }
        if kind == PropagationType::Shared {
            let needs_group = ids
                .iter()
                .any(|&id| self.get(id).is_some_and(|m| m.prop.group == 0));
            let mut groups = needs_group.then(|| GroupAlloc::of(self));
            for &id in ids {
                if let Some(m) = self.get_mut(id) {
                    if m.prop.group == 0 {
                        m.prop.group = groups.as_mut().unwrap().take();
                    }
                    m.prop.unbindable = false;
                }
            }
            return;
        }
        let target: std::collections::HashSet<MountId> = ids.iter().copied().collect();
        self.leave_groups(&target, kind);
    }

    /// Applies `Slave`, `Private` or `Unbindable` to every mount in `target` at once: any peer
    /// group left without surviving members hands its slaves to its own master, and on up when
    /// that group is left empty too (matching Linux's `do_make_slave` per mount).
    fn leave_groups(&mut self, target: &std::collections::HashSet<MountId>, kind: PropagationType) {
        debug_assert_ne!(kind, PropagationType::Shared);
        let mut left: HashMap<u32, u32> = HashMap::new();
        for &id in target {
            let Some(m) = self.get_mut(id) else {
                continue;
            };
            let old_group = m.prop.group;
            let old_master = m.prop.master;
            if old_group != 0 {
                left.insert(old_group, old_master);
            }
            match kind {
                PropagationType::Slave => {
                    if old_group != 0 {
                        m.prop.group = 0;
                        m.prop.master = old_group;
                    }
                }
                PropagationType::Private => m.prop = Propagation::default(),
                PropagationType::Unbindable => {
                    m.prop = Propagation {
                        group: 0,
                        master: 0,
                        unbindable: true,
                    };
                }
                PropagationType::Shared => unreachable!(),
            }
        }
        if left.is_empty() {
            return;
        }
        let alive: std::collections::HashSet<u32> = self
            .all()
            .map(|m| m.prop.group)
            .filter(|&g| g != 0)
            .collect();
        left.retain(|g, _| !alive.contains(g));
        if left.is_empty() {
            return;
        }
        let mut resolved: HashMap<u32, Option<u32>> = HashMap::with_capacity(left.len());
        let mut resolve = |g: u32| -> u32 {
            if let Some(Some(r)) = resolved.get(&g) {
                return *r;
            }
            let mut path = Vec::new();
            let mut cur = g;
            let dest = loop {
                if let Some(&state) = resolved.get(&cur) {
                    break state.unwrap_or(0);
                }
                match left.get(&cur) {
                    Some(&up) => {
                        resolved.insert(cur, None);
                        path.push(cur);
                        cur = up;
                    }
                    None => break cur,
                }
            };
            for node in path {
                resolved.insert(node, Some(dest));
            }
            dest
        };
        for m in self.list.iter_mut().chain(self.detached.iter_mut()) {
            if left.contains_key(&m.prop.master) {
                m.prop.master = resolve(m.prop.master);
            }
        }
    }

    /// Unmounted mounts `ids` all become private at once (`umount_tree`'s
    /// `change_mnt_propagation(MS_PRIVATE)` for each): a peer group left without members hands its
    /// slaves to its own master, and on up when that group is left empty too.
    fn make_private(&mut self, ids: &std::collections::HashSet<MountId>) {
        self.leave_groups(ids, PropagationType::Private);
    }
}

/// Peer group numbers handed out during one change (`mnt_alloc_group_id`: the smallest free one
/// each time), without scanning every mount for each one.
struct GroupAlloc {
    used: std::collections::HashSet<u32>,
    next: u32,
}

impl GroupAlloc {
    fn of(mounts: &Mounts) -> GroupAlloc {
        GroupAlloc {
            used: mounts
                .all()
                .flat_map(|m| [m.prop.group, m.prop.master])
                .collect(),
            next: 1,
        }
    }

    fn take(&mut self) -> u32 {
        while self.used.contains(&self.next) {
            self.next += 1;
        }
        self.used.insert(self.next);
        self.next
    }
}

/// Lookups over the attached mounts (`Mounts::list`), built once for an operation that visits
/// many of them: a peer group grown to thousands of mounts would make a scan per visit quadratic.
struct Index {
    /// Position in the list of each mount.
    pos: HashMap<MountId, usize>,
    /// The members of each peer group.
    members: HashMap<u32, Vec<usize>>,
    /// The slaves of each peer group.
    slaves: HashMap<u32, Vec<usize>>,
    /// The mounts mounted in each mount.
    children: HashMap<MountId, Vec<usize>>,
    /// The mounts on each mount point.
    spots: HashMap<Node, Vec<usize>>,
}

impl Index {
    fn of(list: &[Mount], anon: &std::collections::HashSet<u64>) -> Index {
        let mut index = Index {
            pos: HashMap::with_capacity(list.len()),
            members: HashMap::new(),
            slaves: HashMap::new(),
            children: HashMap::new(),
            spots: HashMap::new(),
        };
        for (i, m) in list.iter().enumerate() {
            index.pos.insert(m.id, i);
            if !anon.contains(&m.ns) {
                if m.prop.group != 0 {
                    index.members.entry(m.prop.group).or_default().push(i);
                }
                if m.prop.master != 0 {
                    index.slaves.entry(m.prop.master).or_default().push(i);
                }
            }
            if let Some(parent) = m.parent().filter(|&p| p != m.id) {
                index.children.entry(parent).or_default().push(i);
            }
            if let Some(point) = &m.point {
                index.spots.entry(point.clone()).or_default().push(i);
            }
        }
        index
    }

    fn children(&self, of: MountId) -> &[usize] {
        self.children.get(&of).map_or(&[], Vec::as_slice)
    }

    /// The mount in mount `to` on the place where `m` is in its parent.
    fn on_spot<'a>(&self, list: &'a [Mount], m: &Mount, to: MountId) -> Option<&'a Mount> {
        let point = m.point.clone()?.in_mount(to);
        let at = m.at.clone().map(|(dir, name)| (dir.in_mount(to), name));
        self.at_place(list, &point, at.as_ref()).map(|i| &list[i])
    }

    /// The mount on `point`: of several (links of one file), the one found through `at`, else
    /// the first (a directory has one place; `at` is kept for directories too, in the parent
    /// mount when the point is a mount's root).
    fn at_place(&self, list: &[Mount], point: &Node, at: Option<&Dentry>) -> Option<usize> {
        let found = self.spots.get(point)?;
        found
            .iter()
            .copied()
            .find(|&i| list[i].at.as_ref() == at)
            .or_else(|| found.first().copied())
    }

    /// The mounts an event in mount `of` propagates to, in the order of Linux's `propagate_mnt`:
    /// its peers, then the slaves of its group, each slave group with its members together and
    /// followed by its own slaves (depth first). Each comes with the chain of groups from its
    /// master up to `of`'s group, empty for a peer. None when `of` is not shared.
    fn propagation_of(&self, list: &[Mount], of: MountId) -> Vec<(usize, Vec<u32>)> {
        let Some(top) = self
            .pos
            .get(&of)
            .map(|&i| list[i].prop.group)
            .filter(|&g| g != 0)
        else {
            return Vec::new();
        };
        let mut out: Vec<(usize, Vec<u32>)> = self.members[&top]
            .iter()
            .filter(|&&i| list[i].id != of)
            .map(|&i| (i, Vec::new()))
            .collect();
        let mut seen = std::collections::HashSet::from([top]);
        self.slaves_of(list, &[top], &mut seen, &mut out);
        out
    }

    /// The slaves of group `chain[0]` for [`Index::propagation_of`], `chain` leading up to the
    /// group of the event.
    fn slaves_of(
        &self,
        list: &[Mount],
        chain: &[u32],
        seen: &mut std::collections::HashSet<u32>,
        out: &mut Vec<(usize, Vec<u32>)>,
    ) {
        for &i in self.slaves.get(&chain[0]).into_iter().flatten() {
            match list[i].prop.group {
                0 => out.push((i, chain.to_vec())),
                group if seen.insert(group) => {
                    out.extend(self.members[&group].iter().map(|&p| (p, chain.to_vec())));
                    let below: Vec<u32> = std::iter::once(group)
                        .chain(chain.iter().copied())
                        .collect();
                    self.slaves_of(list, &below, seen, out);
                }
                _ => {}
            }
        }
    }

    /// The members of peer group `group` and every mount it propagates to.
    fn group_tree(&self, list: &[Mount], group: u32) -> Vec<usize> {
        let Some(first) = self.members.get(&group).and_then(|m| m.first()) else {
            return Vec::new();
        };
        let mut out = vec![*first];
        out.extend(
            self.propagation_of(list, list[*first].id)
                .into_iter()
                .map(|(i, _)| i),
        );
        out
    }
}

/// Keeps the detached mounts that are in `in_use`, with the mounts still connected below them
/// ([`detach`]); a connected mount whose parent goes is disconnected, as one holding its own
/// reference outlives its parent on Linux.
fn keep_used(detached: &mut Vec<Mount>, in_use: &std::collections::HashSet<MountId>) {
    let mut children: HashMap<MountId, Vec<MountId>> = HashMap::new();
    let mut keep: std::collections::HashSet<MountId> = std::collections::HashSet::new();
    let mut stack: Vec<MountId> = Vec::new();
    for m in detached.iter() {
        if let Some(p) = m.parent().filter(|&p| p != m.id) {
            children.entry(p).or_default().push(m.id);
        }
        if in_use.contains(&m.id) && keep.insert(m.id) {
            stack.push(m.id);
        }
    }
    while let Some(id) = stack.pop() {
        if let Some(kids) = children.get(&id) {
            for &k in kids {
                if keep.insert(k) {
                    stack.push(k);
                }
            }
        }
    }
    detached.retain(|m| keep.contains(&m.id));
    for m in detached.iter_mut() {
        if m.parent().is_some_and(|p| !keep.contains(&p)) {
            m.point = None;
            m.at = None;
        }
    }
}

/// Mount `m` is mounted on `name` (inode `ino`) in store directory `dir`.
fn on_entry(m: &Mount, (ino, dir, name): (Ino, Ino, &[u8])) -> bool {
    matches!(m.point, Some(Node::Store(_, i)) if i == ino)
        && m.at
            .as_ref()
            .is_none_or(|(d, n)| d.ino() == Some(dir) && n == name)
}

impl Vfs {
    /// Pages one inode takes in tmpfs: regular files by the storage their object takes (holes take
    /// none), symlinks one page when the target is 128 bytes or more (Linux's `SHORT_SYMLINK_LEN`;
    /// short ones live in the inode), others none.
    pub(crate) fn tmpfs_pages(&self, st: &Stat) -> u64 {
        match st.kind() {
            mode::S_IFREG => self
                .store
                .open_object(st.ino, false)
                .and_then(|f| self.tmpfs_file_pages(st.ino, &f))
                .unwrap_or_else(|_| {
                    st.blocks.map_or(st.size.div_ceil(TMPFS_PAGE), |b| {
                        b.div_ceil(TMPFS_PAGE / 512)
                    })
                }),
            mode::S_IFLNK => u64::from(st.size >= 128),
            _ => 0,
        }
    }
}

/// Normalizes an absolute path lexically: drops `.` and empty components, and steps back for
/// `..` (without following symlinks).
pub(crate) fn normalize(path: &[u8]) -> Vec<u8> {
    let mut comps: Vec<&[u8]> = Vec::new();
    for c in path.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                comps.pop();
            }
            c => comps.push(c),
        }
    }
    if comps.is_empty() {
        return b"/".to_vec();
    }
    let mut out = Vec::new();
    for c in comps {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The synthetic filesystems all have only an empty root directory; procfs also has the two
    /// directory levels `sys/kernel/`.
    struct Empty;

    const SYS: PseudoNode = PseudoNode::Static(b"sys/");
    const KERNEL: PseudoNode = PseudoNode::Static(b"sys/kernel/");

    impl Pseudo for Empty {
        fn parent(&self, node: &PseudoNode) -> Option<PseudoNode> {
            match node {
                PseudoNode::Static(b"sys/kernel/") => Some(SYS),
                PseudoNode::Static(_) => Some(PseudoNode::ProcRoot),
                _ => None,
            }
        }
        fn name(&self, _: MountId, node: &PseudoNode) -> Vec<u8> {
            match node {
                PseudoNode::Static(b"sys/kernel/") => b"kernel".to_vec(),
                PseudoNode::Static(_) => b"sys".to_vec(),
                _ => Vec::new(),
            }
        }
        fn lookup(&self, _: MountId, dir: &PseudoNode, name: &[u8]) -> Result<PseudoNode, Errno> {
            match (dir, name) {
                (PseudoNode::ProcRoot, b"sys") => Ok(SYS),
                (PseudoNode::Static(b"sys/"), b"kernel") => Ok(KERNEL),
                _ => Err(Errno::ENOENT),
            }
        }
        fn kind(&self, _: &PseudoNode) -> Result<u32, Errno> {
            Ok(mode::S_IFDIR)
        }
        fn readlink(&self, _: MountId, _: &PseudoNode) -> Result<Vec<u8>, Errno> {
            Err(Errno::EINVAL)
        }
        fn follow(&self, _: MountId, _: &PseudoNode) -> Option<Result<Node, Errno>> {
            None
        }
    }

    fn sample(name: &str) -> (Vfs, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("appine-vfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let bin = s.mkdir(ROOT, b"bin", 0o755, 0, 0).unwrap();
        let usr = s.mkdir(ROOT, b"usr", 0o755, 0, 0).unwrap();
        let ubin = s.mkdir(usr, b"bin", 0o755, 0, 0).unwrap();
        s.mkdir(ROOT, b"proc", 0o555, 0, 0).unwrap();
        s.create_file(bin, b"busybox", 0o755, 0, 0).unwrap();
        s.symlink(ubin, b"env", b"/bin/busybox", 0, 0).unwrap();
        s.symlink(ubin, b"rel", b"../../bin/busybox", 0, 0).unwrap();
        s.symlink(ROOT, b"loop", b"loop", 0, 0).unwrap();
        s.symlink(ROOT, b"bindir", b"bin", 0, 0).unwrap();
        s.symlink(ROOT, b"slash", b"bin/busybox/", 0, 0).unwrap();
        drop(s);
        (Vfs::open(&dir).unwrap(), dir)
    }

    #[test]
    fn anonymous_metadata_prunes_dead_objects_and_ignores_named_fifos() {
        use crate::pipe::{PIPE_BUF, Pipe, PipeEnd};
        let (vfs, dir) = sample("anonymous-inodes");
        let (r, _w) = PipeEnd::pair(PIPE_BUF);
        let fifo = Pipe::fifo(r.pipe.borrow().ino, PIPE_BUF);
        let live = AnonTarget::Pipe(r.pipe.clone());
        let cred = Cred::root();
        vfs.anon_attrs(&live, &cred, |a| a.atime_ns = 1);
        vfs.pipe_io_time(&fifo.borrow(), false);
        for _ in 0..512 {
            let (r, _) = PipeEnd::pair(PIPE_BUF);
            vfs.anon_attrs(&AnonTarget::Pipe(r.pipe.clone()), &cred, |_| ());
        }
        assert!(vfs.anon.borrow().len() <= 256);
        assert_eq!(live.stat(Some(&vfs), &cred).atime_ns, 1);
        drop(vfs);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn host_configuration_paths_are_validated_before_creation() {
        let (vfs, dir) = sample("config-paths");
        let store = vfs.store();
        let write = |path: &[u8]| write_file_owned(store, path, b"dns", 0o644, true, 123, 456);
        for path in [
            b"etc/resolv.conf".as_slice(),
            b"/new/name\0",
            b"/new/../name",
        ] {
            assert_eq!(write(path), Err(Errno::EINVAL));
            assert_eq!(read_file(store, path), Err(Errno::EINVAL));
        }
        let mut path = b"/new/".to_vec();
        path.extend([b'x'; NAME_MAX + 1]);
        assert_eq!(write(&path), Err(Errno::ENAMETOOLONG));
        assert_eq!(read_file(store, &path), Err(Errno::ENAMETOOLONG));
        assert_eq!(store.lookup(ROOT, b"new"), Ok(None));
        path.pop();
        write(&path).unwrap();
        write(b"/etc/resolv.conf").unwrap();
        assert_eq!(read_file(store, b"/etc/resolv.conf").unwrap(), b"dns");
        drop(vfs);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn openat2_resolve_flags_limit_the_walk() {
        // In sample: /usr/bin/env -> /bin/busybox, /usr/bin/rel -> ../../bin/busybox,
        // /bindir -> bin; procfs is mounted on /proc
        let (vfs, dir) = sample("openat2");
        let ps = &Empty;
        let cred = &Cred::root();
        let root = Node::ROOT;
        let usr = vfs.resolve(ps, cred, &root, &root, b"/usr", true).unwrap();
        let ubin = vfs
            .resolve(ps, cred, &root, &root, b"/usr/bin", true)
            .unwrap();
        let busybox = vfs
            .resolve(ps, cred, &root, &root, b"/bin/busybox", true)
            .unwrap();
        // With a scope the root is the start
        let scoped = |start: &Node, p: &[u8], flags| {
            vfs.walk_resolve(ps, cred, start, start, p, true, flags)
                .map(|(n, _)| n)
        };
        let plain = |start: &Node, p: &[u8], flags| {
            vfs.walk_resolve(ps, cred, &root, start, p, true, flags)
                .map(|(n, _)| n)
        };
        use resolve::*;
        // BENEATH: absolute paths, .. leaving the start, symlinks to absolute paths and relative
        // links leaving the start are all EXDEV
        assert_eq!(scoped(&usr, b"bin", BENEATH), Ok(ubin.clone()));
        assert_eq!(scoped(&usr, b"bin/..", BENEATH), Ok(usr.clone()));
        assert_eq!(scoped(&usr, b"..", BENEATH), Err(Errno::EXDEV));
        assert_eq!(scoped(&usr, b"/bin", BENEATH), Err(Errno::EXDEV));
        assert_eq!(scoped(&usr, b"bin/env", BENEATH), Err(Errno::EXDEV));
        assert_eq!(scoped(&usr, b"bin/rel", BENEATH), Err(Errno::EXDEV));
        assert_eq!(scoped(&root, b"usr/bin/rel", BENEATH), Ok(busybox.clone()));
        // IN_ROOT: the start is treated as the root, .. stops at the start, and absolute paths
        // count from the start
        assert_eq!(scoped(&usr, b"..", IN_ROOT), Ok(usr.clone()));
        assert_eq!(scoped(&usr, b"/bin", IN_ROOT), Ok(ubin.clone()));
        assert_eq!(scoped(&usr, b"../../bin", IN_ROOT), Ok(ubin.clone()));
        assert_eq!(scoped(&usr, b"bin/env", IN_ROOT), Err(Errno::ENOENT));
        // NO_SYMLINKS: symlinks along the way and at the end are ELOOP; not following the last
        // one works as usual
        assert_eq!(
            plain(&root, b"/bindir/busybox", NO_SYMLINKS),
            Err(Errno::ELOOP)
        );
        assert_eq!(
            plain(&root, b"/usr/bin/env", NO_SYMLINKS),
            Err(Errno::ELOOP)
        );
        assert!(
            vfs.walk_resolve(ps, cred, &root, &root, b"/usr/bin/env", false, NO_SYMLINKS)
                .is_ok()
        );
        // NO_XDEV: entering or leaving mounts is EXDEV; so is jumping to the root before the
        // root has been taken
        assert_eq!(plain(&root, b"/proc", NO_XDEV), Err(Errno::EXDEV));
        assert_eq!(plain(&root, b"/usr/bin/env", NO_XDEV), Ok(busybox.clone()));
        assert_eq!(plain(&ubin, b"env", NO_XDEV), Err(Errno::EXDEV));
        assert_eq!(plain(&ubin, b"../bin/env", NO_XDEV), Ok(busybox.clone()));
        let proc = plain(&root, b"/proc", 0).unwrap();
        assert_eq!(plain(&proc, b"..", NO_XDEV), Err(Errno::EXDEV));
        // The parent directory for creation is restricted too
        assert_eq!(
            vfs.resolve_parent_with(ps, cred, &usr, &usr, b"/x", BENEATH),
            Err(Errno::EXDEV)
        );
        assert_eq!(
            vfs.resolve_parent_with(ps, cred, &usr, &usr, b"/x", IN_ROOT),
            Ok((usr.clone(), &b"x"[..]))
        );
        drop(vfs);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resolves_paths_and_symlinks() {
        let (vfs, dir) = sample("resolve");
        let ps = &Empty;
        let root_cred = Cred::root();
        let cred = &root_cred;
        let r = |cwd: &Node, p: &[u8], follow| vfs.resolve(ps, cred, &Node::ROOT, cwd, p, follow);
        let root = Node::ROOT;
        let busybox = r(&root, b"/bin/busybox", true).unwrap();
        assert_eq!(r(&root, b"/usr/bin/env", true).unwrap(), busybox);
        assert_eq!(r(&root, b"/usr/bin/rel", true).unwrap(), busybox);
        assert_eq!(r(&root, b"/bindir/busybox", false).unwrap(), busybox);
        assert_eq!(
            r(&root, b"//usr/./bin/../../bin/busybox", true).unwrap(),
            busybox
        );
        let usr = r(&root, b"usr", true).unwrap();
        assert_eq!(r(&usr, b"../bin/busybox", true).unwrap(), busybox);
        assert_eq!(r(&root, b"/..", true).unwrap(), root);

        let env = r(&root, b"/usr/bin/env", false).unwrap();
        assert_eq!(vfs.kind(ps, &env).unwrap(), mode::S_IFLNK);
        assert_eq!(r(&root, b"/loop", true), Err(Errno::ELOOP));
        assert_eq!(r(&root, b"/missing", true), Err(Errno::ENOENT));
        assert_eq!(r(&root, b"/bin/busybox/x", true), Err(Errno::ENOTDIR));
        assert_eq!(r(&root, b"/bin/busybox/", true), Err(Errno::ENOTDIR));
        // There must also be a directory before . and ..; a symlink target ending in / likewise
        // requires a directory
        assert_eq!(r(&root, b"/bin/busybox/.", true), Err(Errno::ENOTDIR));
        assert_eq!(r(&root, b"/bin/busybox/..", true), Err(Errno::ENOTDIR));
        assert_eq!(r(&root, b"/slash", true), Err(Errno::ENOTDIR));
        assert_eq!(
            vfs.kind(ps, &r(&root, b"/slash", false).unwrap()).unwrap(),
            mode::S_IFLNK
        );
        assert_eq!(
            r(&root, b"/bindir/", false).unwrap(),
            r(&root, b"/bin", true).unwrap()
        );
        assert_eq!(r(&root, b"/", true).unwrap(), root);
        assert_eq!(r(&root, b"", true), Err(Errno::ENOENT));

        let ubin = r(&root, b"/usr/bin", true).unwrap();
        assert_eq!(
            vfs.resolve_parent(ps, cred, &Node::ROOT, &root, b"/usr/bin/new")
                .unwrap(),
            (ubin.clone(), &b"new"[..])
        );
        assert_eq!(
            vfs.resolve_parent(ps, cred, &Node::ROOT, &usr, b"bin//")
                .unwrap(),
            (usr.clone(), &b"bin"[..])
        );
        assert_eq!(
            vfs.resolve_parent(ps, cred, &Node::ROOT, &usr, b"///")
                .unwrap(),
            (root.clone(), &b"."[..])
        );
        assert_eq!(
            vfs.resolve_parent(ps, cred, &Node::ROOT, &root, b"/bin/busybox/x"),
            Err(Errno::ENOTDIR)
        );
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &ubin).unwrap(), b"/usr/bin");
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &root).unwrap(), b"/");

        // The path after resolving symlinks (/proc/<pid>/exe)
        let real = |cwd: &Node, p: &[u8]| vfs.real_path(ps, cred, &Node::ROOT, cwd, p);
        for p in [
            &b"/usr/bin/env"[..],
            b"/usr/bin/rel",
            b"/bindir/busybox",
            b"/bin/busybox",
        ] {
            assert_eq!(real(&root, p).unwrap(), b"/bin/busybox");
        }
        assert_eq!(real(&usr, b"bin/rel").unwrap(), b"/bin/busybox");
        assert_eq!(real(&usr, b"../bindir/").unwrap(), b"/bin");
        assert_eq!(real(&ubin, b".").unwrap(), b"/usr/bin");
        assert_eq!(real(&ubin, b"..").unwrap(), b"/usr");
        assert_eq!(real(&root, b"/").unwrap(), b"/");
        assert_eq!(real(&root, b"/missing"), Err(Errno::ENOENT));

        // /proc is a mount point: going in reaches the synthetic filesystem's root, and `..`
        // returns to the store's root directory
        let proc = r(&root, b"/proc", true).unwrap();
        assert_eq!(proc, Node::Pseudo(PROC_MOUNT, PseudoNode::ProcRoot));
        assert_eq!(r(&proc, b"..", true).unwrap(), root);
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &proc).unwrap(), b"/proc");
        // Device nodes are in the tmpfs mounted on /dev at boot, and /dev/pts is mounted inside
        // it
        assert!(matches!(
            r(&root, b"/dev/null", true).unwrap(),
            Node::Store(DEV_MOUNT, _)
        ));
        let dev = r(&root, b"/dev", true).unwrap();
        assert!(matches!(dev, Node::Store(DEV_MOUNT, _)));
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &dev).unwrap(), b"/dev");
        assert_eq!(r(&dev, b"..", true).unwrap(), root);
        let pts = r(&root, b"/dev/pts", true).unwrap();
        assert_eq!(
            pts,
            Node::Pseudo(PTS_MOUNT, PseudoNode::PtsRoot(crate::tty::BOOT_PTS))
        );
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &pts).unwrap(), b"/dev/pts");
        assert!(matches!(
            r(&root, b"/run", true).unwrap(),
            Node::Store(RUN_MOUNT, _)
        ));
        assert!(matches!(
            r(&root, b"/dev/shm/..", true).unwrap(),
            Node::Store(DEV_MOUNT, _)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolves_from_the_cache_like_the_full_walk() {
        let (vfs, dir) = sample("cached");
        let ps = &Empty;
        let cred = &Cred::root();
        let cached = vfs.cached();
        let usr = match vfs.resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true) {
            Ok(Node::Store(_, ino)) => ino,
            other => panic!("{other:?}"),
        };
        let paths: [&[u8]; 20] = [
            b"/bin/busybox",
            b"/usr/bin/env",
            b"/usr/bin/rel",
            b"/bindir/busybox",
            b"//usr/./bin/../../bin/busybox",
            b"../bin/busybox",
            b"/..",
            b"/loop",
            b"/missing",
            b"/bin/missing/x",
            b"/bin/busybox/x",
            b"/bin/busybox/",
            b"/bin/busybox/.",
            b"/bin/busybox/..",
            b"/slash",
            b"/bindir/",
            b"/",
            b"bin",
            b"bin/rel",
            b"./bin/../../bindir/",
        ];
        for follow in [true, false] {
            for cwd in [ROOT, usr] {
                for p in paths {
                    let full = vfs
                        .resolve(
                            ps,
                            cred,
                            &Node::ROOT,
                            &Node::Store(ROOT_MOUNT, cwd),
                            p,
                            follow,
                        )
                        .and_then(|n| match n {
                            Node::Store(_, ino) => vfs.store().stat(ino),
                            Node::Pseudo(..) | Node::Overlay(..) | Node::Fuse(..) => {
                                unreachable!()
                            }
                        });
                    // Normal resolution filled everything needed into the cache; afterwards the
                    // cache alone gives the same result
                    assert_eq!(
                        cached.stat(ROOT, cwd, p, follow),
                        Some(full),
                        "{} from {cwd}, follow {follow}",
                        String::from_utf8_lossy(p)
                    );
                }
            }
        }
        // Synthetic filesystems are left to normal resolution
        assert_eq!(cached.stat(ROOT, ROOT, b"/proc", true), None);
        assert_eq!(cached.stat(ROOT, ROOT, b"/dev/pts/0", true), None);
        // Names never resolved are also left to normal resolution
        assert_eq!(cached.stat(ROOT, ROOT, b"/bin/sh", true), None);
        // After a change the old entry is not used
        let bin = match vfs.resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/bin", true) {
            Ok(Node::Store(_, ino)) => ino,
            other => panic!("{other:?}"),
        };
        vfs.store().unlink(bin, b"busybox").unwrap();
        assert_eq!(cached.stat(ROOT, ROOT, b"/bin/busybox", true), None);
        assert_eq!(cached.stat(ROOT, usr, b"bin/env", true), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mounts_on_other_directories() {
        let (vfs, dir) = sample("mounts");
        let ps = &Empty;
        let cred = &Cred::root();
        let r = |root: &Node, cwd: &Node, p: &[u8]| vfs.resolve(ps, cred, root, cwd, p, true);
        let root = Node::ROOT;
        let usr = r(&root, &root, b"/usr").unwrap();
        let ubin = r(&root, &root, b"/usr/bin").unwrap();
        let bin = r(&root, &root, b"/bin").unwrap();
        let proc = r(&root, &root, b"/proc").unwrap();

        // Mount a procfs on /usr/bin: going in reaches its root, paths go through the mount
        // point, and `..` returns to /usr
        let id = vfs.add_mount(
            Fs::Proc,
            Fs::Proc.root(),
            (ubin.clone(), None),
            0,
            b"p".to_vec(),
            None,
        );
        let top = Node::Pseudo(id, PseudoNode::ProcRoot);
        assert_eq!(r(&root, &root, b"/usr/bin").unwrap(), top);
        let kernel = r(&root, &root, b"/usr/bin/sys/kernel").unwrap();
        assert_eq!(kernel, Node::Pseudo(id, KERNEL));
        assert_eq!(
            vfs.path_of(ps, &root, &kernel).unwrap(),
            b"/usr/bin/sys/kernel"
        );
        assert_eq!(r(&root, &kernel, b"../../..").unwrap(), usr);
        assert_eq!(vfs.parent(ps, &top).unwrap(), usr);
        // The same directory in the boot /proc is another node, and `..` returns to /proc
        let proc_sys = r(&root, &root, b"/proc/sys").unwrap();
        assert_eq!(proc_sys, Node::Pseudo(PROC_MOUNT, SYS));
        assert_eq!(r(&root, &proc_sys, b"..").unwrap(), proc);
        // The root changed to /usr: paths are relative to it, `..` does not go past it, and
        // anything outside the root is unreachable
        assert_eq!(vfs.path_of(ps, &usr, &kernel).unwrap(), b"/bin/sys/kernel");
        assert_eq!(r(&usr, &kernel, b"../../../../..").unwrap(), usr);
        assert_eq!(r(&usr, &usr, b"/bin/sys").unwrap(), Node::Pseudo(id, SYS));
        assert_eq!(
            vfs.reach(ps, &usr, &proc_sys).unwrap(),
            (b"/proc/sys".to_vec(), false)
        );
        assert_eq!(
            vfs.reach(ps, &usr, &kernel).unwrap(),
            (b"/bin/sys/kernel".to_vec(), true)
        );

        // Bind-mount sys/ in procfs: what is seen is that directory, and `..` returns to the
        // mount point's parent
        let b = vfs.add_mount(
            Fs::Proc,
            Node::Pseudo(0, SYS),
            (bin.clone(), None),
            0,
            b"p".to_vec(),
            Some(Fs::Proc.dev()),
        );
        let bound = Node::Pseudo(b, KERNEL);
        assert_eq!(r(&root, &root, b"/bin/kernel").unwrap(), bound);
        assert_eq!(vfs.path_of(ps, &root, &bound).unwrap(), b"/bin/kernel");
        assert_eq!(r(&root, &bound, b"../..").unwrap(), root);
        assert!(vfs.is_mount_point(&bin));
        assert_eq!(vfs.mount_root(&Node::Pseudo(b, SYS)), Some(b));
        assert_eq!(vfs.mount_root(&bound), None);
        assert_eq!(vfs.mount_root(&root), Some(ROOT_MOUNT));
        assert_eq!(vfs.mount_root(&usr), None);
        // The new instance has its own device number; bind mounts use the source's
        assert_eq!(vfs.dev_of(&proc_sys), Fs::Proc.dev());
        assert_ne!(vfs.dev_of(&kernel), Fs::Proc.dev());
        assert_eq!(vfs.dev_of(&bound), Fs::Proc.dev());

        // Stacked mounts: the topmost one is visible, and `..` goes back level by level to the
        // mount point
        let s = vfs.add_mount(
            Fs::Pts,
            Fs::Pts.root(),
            (top.clone(), None),
            0,
            b"d".to_vec(),
            None,
        );
        assert_eq!(
            r(&root, &root, b"/usr/bin").unwrap(),
            Node::Pseudo(s, PseudoNode::PtsRoot(crate::tty::BOOT_PTS))
        );
        assert_eq!(r(&root, &root, b"/usr/bin/..").unwrap(), usr);
        let ids = |list: Vec<Mount>| list.iter().map(|m| m.id).collect::<Vec<_>>();
        assert_eq!(ids(vfs.children(id)), [s]);
        assert_eq!(
            ids(vfs.children(ROOT_MOUNT)),
            [PROC_MOUNT, DEV_MOUNT, SYS_MOUNT, RUN_MOUNT, id, b]
        );
        assert_eq!(
            ids(vfs.children(DEV_MOUNT)),
            [PTS_MOUNT, SHM_MOUNT, MQUEUE_MOUNT]
        );
        assert_eq!(ids(vfs.children(SYS_MOUNT)), [CGROUP_MOUNT]);

        // No-BKL resolution hands mount points to normal resolution, also when the current
        // directory's parent is a mount point
        let cached = vfs.cached();
        let ino = |n: &Node| match n {
            Node::Store(_, i) => *i,
            Node::Pseudo(..) | Node::Overlay(..) | Node::Fuse(..) => unreachable!(),
        };
        assert_eq!(cached.stat(ROOT, ROOT, b"/bin", true), None);
        assert_eq!(cached.stat(ROOT, ROOT, b"/bin/../usr", true), None);
        let lib = vfs.store().mkdir(ino(&ubin), b"lib", 0o755, 0, 0).unwrap();
        assert_eq!(
            r(&root, &Node::Store(ROOT_MOUNT, lib), b"..").unwrap(),
            r(&root, &root, b"/usr/bin").unwrap()
        );
        assert_eq!(cached.stat(ROOT, lib, b"..", true), None);

        // Detach id and what is stacked on it: the store directory is visible again. Nodes
        // still inside stay in the detached mount, whose root has no parent, and their paths
        // are unreachable
        vfs.remove_mount(id);
        assert_eq!(r(&root, &root, b"/usr/bin").unwrap(), ubin);
        assert!(vfs.mount(s).is_none());
        assert_eq!(r(&root, &kernel, b"..").unwrap(), Node::Pseudo(id, SYS));
        assert_eq!(
            r(&root, &kernel, b"../../..").unwrap(),
            Node::Pseudo(id, PseudoNode::ProcRoot)
        );
        assert_eq!(
            vfs.reach(ps, &root, &kernel).unwrap(),
            (b"/sys/kernel".to_vec(), false)
        );
        assert_eq!(
            vfs.cached().stat(ROOT, lib, b"..", true),
            Some(vfs.store().stat(ino(&ubin)))
        );
        // Ids of detached mounts are not reused
        assert!(vfs.add_mount(Fs::Sys, Fs::Sys.root(), (usr, None), 0, Vec::new(), None) > s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn propagates_binds_to_peers() {
        // /usr bound onto itself and made shared, then bound onto /bin (its peer): a mount on
        // /usr is copied onto the peer's root, and unmounting it takes the copy down too
        let (vfs, _dir) = sample("propagate");
        let ps = &Empty;
        let cred = &Cred::root();
        let r = |p: &[u8]| {
            vfs.resolve(ps, cred, &Node::ROOT, &Node::ROOT, p, true)
                .unwrap()
        };
        let (usr, bin, ubin) = (r(b"/usr"), r(b"/bin"), r(b"/usr/bin"));
        let ino = |n: &Node| n.ino().unwrap();
        let bind = |src: &Node, at: &Node| {
            let id = vfs.add_mount(
                Fs::Store,
                src.clone(),
                (at.clone(), None),
                0,
                Vec::new(),
                Some(ROOT_DEV),
            );
            let prop = vfs.propagation(src.mnt()).of_bind();
            vfs.update_mount(id, |m| m.prop = prop);
            vfs.attached(id);
            id
        };
        let shared = bind(&usr, &usr);
        vfs.set_propagation(shared, PropagationType::Shared, false);
        let top = Node::Store(shared, ino(&usr));
        let peer = bind(&top, &bin);
        assert_eq!(vfs.propagation(peer).group, vfs.propagation(shared).group);
        let targets = vfs.propagation_targets(ps, (&top, None));
        assert_eq!(targets.len(), 1, "{targets:?}");
        let id = bind(&ubin, &top);
        vfs.propagate(id, &targets, 0);
        let copy = vfs.mounted(Node::Store(peer, ino(&usr)));
        assert_eq!(copy.ino(), Some(ino(&ubin)));
        assert_ne!(copy.mnt(), id);
        assert_eq!(r(b"/bin"), copy);
        vfs.umount_tree(id);
        assert_eq!(r(b"/bin"), Node::Store(peer, ino(&usr)));
    }

    #[test]
    fn binds_store_directories() {
        let (vfs, dir) = sample("binds");
        let ps = &Empty;
        let cred = &Cred::root();
        let r = |root: &Node, cwd: &Node, p: &[u8]| vfs.resolve(ps, cred, root, cwd, p, true);
        let root = Node::ROOT;
        let usr = r(&root, &root, b"/usr").unwrap();
        let ubin = r(&root, &root, b"/usr/bin").unwrap();
        let bin = r(&root, &root, b"/bin").unwrap();
        let busybox = r(&root, &root, b"/bin/busybox").unwrap();
        let ino = |n: &Node| n.ino().unwrap();

        // /usr bound onto /bin: going in reaches /usr through the new mount, `..` returns to
        // the mount point's parent, and paths go through the mount point
        let id = vfs.add_mount(
            Fs::Store,
            usr.clone(),
            (bin.clone(), None),
            ms::RELATIME,
            b"appine".to_vec(),
            Some(ROOT_DEV),
        );
        let top = Node::Store(id, ino(&usr));
        assert_eq!(r(&root, &root, b"/bin").unwrap(), top);
        let inner = r(&root, &root, b"/bin/bin").unwrap();
        assert_eq!(inner, Node::Store(id, ino(&ubin)));
        assert_ne!(inner, ubin);
        assert_eq!(vfs.path_of(ps, &root, &inner).unwrap(), b"/bin/bin");
        assert_eq!(vfs.path_of(ps, &root, &ubin).unwrap(), b"/usr/bin");
        assert_eq!(r(&root, &inner, b"..").unwrap(), top);
        assert_eq!(r(&root, &inner, b"../..").unwrap(), root);
        assert_eq!(vfs.parent(ps, &top).unwrap(), root);
        // Symlinks reached through the mount resolve along the mount's paths: /bin/bin/rel is
        // ../../bin/busybox, which after reaching the mount's root goes back to the store's
        // root, and entering /bin from there is this mount again
        assert_eq!(
            r(&root, &root, b"/bin/bin/rel"),
            Err(Errno::ENOENT),
            "/bin is now /usr, which has no busybox"
        );
        assert_eq!(vfs.mount_root(&top), Some(id));
        assert_eq!(vfs.mount_root(&inner), None);
        assert!(vfs.is_mount_point(&bin));
        assert!(!vfs.is_mount_point(&Node::Store(id, ino(&bin))));
        assert!(vfs.is_store_point((ino(&bin), ino(&usr), b"bin"), INIT_MNT_NS));
        assert_eq!(vfs.dev_of(&inner), ROOT_DEV);
        assert_eq!(vfs.root_path(ps, &vfs.mount(id).unwrap()), b"/usr");
        assert!(vfs.is_under(ps, &inner, &root));
        assert!(vfs.is_under(ps, &inner, &top));
        assert!(!vfs.is_under(ps, &inner, &usr));
        // The root changed to a directory inside the mount: `..` does not go past it, and
        // nothing outside can be reached
        assert_eq!(r(&inner, &inner, b"/..").unwrap(), inner);
        assert_eq!(
            vfs.reach(ps, &inner, &top).unwrap(),
            (b"/bin".to_vec(), false)
        );

        // Read-only: flags follow the mount reached through
        vfs.update_mount(id, |m| m.flags |= ms::RDONLY);
        assert!(vfs.readonly(&inner));
        assert!(!vfs.readonly(&ubin));

        // A file bound onto a file: the path follows the directory and name at mount time
        let (f, at) = vfs
            .walk(ps, cred, &root, &root, b"/usr/bin/env", false)
            .unwrap();
        let fb = vfs.add_mount(
            Fs::Store,
            busybox.clone(),
            (f, at),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        let bound = vfs
            .walk(ps, cred, &root, &root, b"/usr/bin/env", false)
            .unwrap();
        assert_eq!(bound.0, Node::Store(fb, ino(&busybox)));
        assert_eq!(vfs.path_of(ps, &root, &ubin).unwrap(), b"/usr/bin");
        assert_eq!(
            vfs.reach(ps, &root, &bound.0).unwrap(),
            (b"/usr/bin/env".to_vec(), true)
        );

        // Moved onto /proc: /bin is the original directory again
        let proc_top = r(&root, &root, b"/proc").unwrap();
        vfs.move_mount(id, Some((proc_top.clone(), None)));
        assert_eq!(r(&root, &root, b"/bin").unwrap(), bin);
        assert_eq!(r(&root, &root, b"/proc/bin").unwrap(), inner);
        assert_eq!(vfs.path_of(ps, &root, &inner).unwrap(), b"/proc/bin");

        // Detached: nodes inside keep working, and the mount's root has no parent and cannot
        // reach the root directory; the record is dropped once nobody uses it
        vfs.remove_mount(id);
        assert_eq!(r(&root, &root, b"/proc").unwrap(), proc_top);
        assert_eq!(r(&root, &inner, b"../../..").unwrap(), top);
        assert_eq!(
            vfs.reach(ps, &root, &inner).unwrap(),
            (b"/bin".to_vec(), false)
        );
        assert!(vfs.readonly(&inner));
        vfs.collect(&std::collections::HashSet::new());
        assert!(!vfs.readonly(&inner));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmpfs_lives_while_mounted() {
        let (vfs, dir) = sample("tmpfs");
        let ps = &Empty;
        let cred = &Cred::root();
        let r = |p: &[u8]| vfs.resolve(ps, cred, &Node::ROOT, &Node::ROOT, p, true);
        let usr = r(b"/usr").unwrap();
        let bin = r(b"/bin").unwrap();
        let params = TmpfsParams {
            perm: 0o755,
            uid: 0,
            gid: 0,
            blocks: TmpfsParams::default_limit(),
            inodes: TmpfsParams::default_limit(),
            inode64: true,
        };
        let a = vfs
            .new_tmpfs((usr.clone(), None), 0, b"t".to_vec(), params)
            .unwrap();
        let top = r(b"/usr").unwrap();
        assert_eq!(top.mnt(), a);
        assert_eq!(vfs.fs_of(&top), Fs::Tmpfs);
        assert_ne!(vfs.dev_of(&top), ROOT_DEV);
        assert_eq!(vfs.sb_options(&vfs.mount(a).unwrap()), ",mode=755,inode64");
        let root = top.ino().unwrap();
        let sub = vfs.store().mkdir(root, b"sub", 0o755, 0, 0).unwrap();
        let (f, _) = vfs.store().create_file(sub, b"f", 0o644, 0, 0).unwrap();
        // Above the tmpfs root is the mount point; paths inside go through it
        assert_eq!(r(b"/usr/sub/..").unwrap(), top);
        assert_eq!(r(b"/usr/..").unwrap(), Node::ROOT);
        assert_eq!(
            vfs.path_of(ps, &Node::ROOT, &Node::Store(a, sub)).unwrap(),
            b"/usr/sub"
        );
        // A subdirectory bound elsewhere keeps it alive
        let b = vfs.add_mount(
            Fs::Tmpfs,
            Node::Store(a, sub),
            (bin, None),
            0,
            Vec::new(),
            Some(vfs.dev_of(&top)),
        );
        assert_eq!(vfs.root_path(ps, &vfs.mount(b).unwrap()), b"/sub");
        vfs.remove_mount(a);
        vfs.collect(&std::collections::HashSet::new());
        assert_eq!(vfs.store().stat(f).unwrap().nlink, 1);
        assert_eq!(r(b"/bin/f").unwrap(), Node::Store(b, f));
        // All gone: deleted together with everything inside
        vfs.remove_mount(b);
        vfs.collect(&std::collections::HashSet::new());
        assert_eq!(vfs.store().stat(f).unwrap().nlink, 0);
        assert_eq!(vfs.store().stat(root).unwrap().nlink, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copies_and_drops_mount_namespaces() {
        let (vfs, dir) = sample("mntns");
        let ps = &Empty;
        let cred = &Cred::root();
        let usr = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true)
            .unwrap();
        let before = vfs.mounts_in(INIT_MNT_NS);
        // The copied namespace: mounts correspond one to one with new ids, and mount points and
        // root directories follow
        let (ns, map) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let copied = vfs.mounts_in(ns.id);
        assert_eq!(copied.len(), before.len());
        assert!(copied.iter().all(|m| !map.contains_key(&m.id)));
        let root = vfs.ns_root(ns.id).unwrap();
        assert_eq!(root, Node::Store(map[&ROOT_MOUNT], ROOT));
        let proc = vfs.resolve(ps, cred, &root, &root, b"/proc", true).unwrap();
        assert_eq!(proc, Node::Pseudo(map[&PROC_MOUNT], PseudoNode::ProcRoot));
        assert_eq!(vfs.mount_ns(proc.mnt()), Some(ns.id));
        // A tmpfs mounted in the new namespace is only there
        let point = vfs.resolve(ps, cred, &root, &root, b"/usr", true).unwrap();
        let params = TmpfsParams {
            perm: 0o1777,
            uid: 0,
            gid: 0,
            blocks: TmpfsParams::default_limit(),
            inodes: TmpfsParams::default_limit(),
            inode64: true,
        };
        let t = vfs.new_tmpfs((point, None), 0, Vec::new(), params).unwrap();
        assert_eq!(vfs.mount_ns(t), Some(ns.id));
        let troot = vfs.mount(t).unwrap().root.ino().unwrap();
        assert_eq!(
            vfs.resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true),
            Ok(usr)
        );
        // No longer used: cleanup detaches its mounts, and the tmpfs is deleted with them
        assert!(!vfs.has_dead_ns());
        drop(ns);
        assert!(vfs.has_dead_ns());
        vfs.collect(&std::collections::HashSet::new());
        assert!(!vfs.has_dead_ns());
        assert!(vfs.mount(t).is_none());
        assert_eq!(vfs.store().stat(troot).unwrap().nlink, 0);
        assert_eq!(vfs.mounts_in(INIT_MNT_NS).len(), before.len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sysfs_net_ns_tagged_per_mount_and_pruned_on_collect() {
        let (vfs, dir) = sample("sysfs-net");
        let init_net = crate::nsproxy::NsProxy::init().net;
        assert_eq!(vfs.sys_dev(&init_net), Fs::Sys.dev());
        assert!(vfs.sys_net_ns(SYS_MOUNT).is_none());

        let net_b = std::rc::Rc::new(crate::nsproxy::NetNs {
            id: new_ns_id(),
            owner: crate::cred::UserNs::init(),
            host_net: Some([0, 1]),
            lo: Default::default(),
            devs: Default::default(),
            nft: Default::default(),
            listeners: Default::default(),
        });
        let dev_b = vfs.sys_dev(&net_b);
        assert_ne!(dev_b, Fs::Sys.dev());
        // A second lookup for the same network namespace reuses the device number.
        assert_eq!(vfs.sys_dev(&net_b), dev_b);

        let usr = Node::Store(
            ROOT_MOUNT,
            vfs.store().lookup(ROOT, b"usr").unwrap().unwrap(),
        );
        let mnt_b = vfs.add_mount(
            Fs::Sys,
            Fs::Sys.root(),
            (usr, None),
            0,
            Vec::new(),
            Some(dev_b),
        );
        assert_eq!(vfs.sys_net_ns(mnt_b).map(|n| n.id), Some(net_b.id));

        // Unmounting and collecting drops the sysfs netns mapping.
        vfs.umount_tree(mnt_b);
        assert_eq!(vfs.sys_net_ns(mnt_b).map(|n| n.id), Some(net_b.id));
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.sys_net_ns(mnt_b).is_none());
        assert!(vfs.mounts.borrow().sys_ns.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bound_namespace_files_keep_namespaces() {
        let (vfs, dir) = sample("nsfs");
        let (pin, _) = vfs.store().create_file(ROOT, b"pin", 0o444, 0, 0).unwrap();
        let point = (
            Node::Store(ROOT_MOUNT, pin),
            Some((Node::ROOT, b"pin".to_vec())),
        );
        let before = vfs.mounts_in(INIT_MNT_NS).len();
        // A file of new mount namespace A bound into the boot namespace
        let (a, _) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let a_id = a.id;
        let file = Node::Pseudo(
            PROC_MOUNT,
            PseudoNode::NsFile(crate::pseudo::NsKind::Mnt, a_id),
        );
        let fs = Fs::Nsfs;
        let id = vfs.add_mount(fs, file, point, 0, b"nsfs".to_vec(), Some(fs.dev()));
        vfs.update_mount(id, |m| m.pin = Some(crate::nsproxy::NsRef::Mnt(a.clone())));
        // Copying the boot namespace leaves it out (otherwise A would keep itself alive through
        // the copied mount)
        let (c, _) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let copied = vfs.mounts_in(c.id);
        assert_eq!(copied.len(), before);
        assert!(copied.iter().all(|m| m.pin.is_none()));
        // No processes left in A: the mount keeps it
        drop(a);
        assert!(!vfs.has_dead_ns());
        assert!(vfs.find_ns(a_id).is_some());
        assert_eq!(vfs.pinned_ns(a_id).map(|r| r.id()), Some(a_id));
        // Cleanup after detaching: A is gone with its mounts
        vfs.remove_mount(id);
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.find_ns(a_id).is_none());
        assert!(vfs.mounts_in(a_id).is_empty());
        assert!(vfs.pinned_ns(a_id).is_none());
        assert_eq!(vfs.mounts_in(c.id).len(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmpfs_counts_pages_and_inodes() {
        let (vfs, dir) = sample("tmpfs-usage");
        let ps = &Empty;
        let cred = &Cred::root();
        let usr = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true)
            .unwrap();
        let params = TmpfsParams {
            perm: 0o1777,
            uid: 0,
            gid: 0,
            blocks: 4,
            inodes: 5,
            inode64: true,
        };
        let id = vfs.new_tmpfs((usr, None), 0, Vec::new(), params).unwrap();
        let m = vfs.mount(id).unwrap();
        let (root, dev) = (m.root.ino().unwrap(), m.dev);
        assert_eq!(vfs.sb_options(&m), ",size=16k,nr_inodes=5,inode64");
        let usage = |fresh| {
            let (_, pages, inodes) = vfs.tmpfs_usage(dev, fresh).unwrap();
            (pages, inodes)
        };
        // Only the root directory
        assert_eq!(usage(true), (0, 1));
        // A directory, a file of two written pages and another link to it, and a long symlink:
        // one inode per name, and pages counted once per file as its object takes them (holes
        // would take none)
        let sub = vfs.store().mkdir(root, b"sub", 0o755, 0, 0).unwrap();
        let (f, file) = vfs.store().create_file(sub, b"f", 0o644, 0, 0).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&file, &[1; 5000], 0).unwrap();
        vfs.store().link(root, b"g", f).unwrap();
        vfs.store().symlink(root, b"s", &[b'x'; 200], 0, 0).unwrap();
        assert_eq!(
            usage(false),
            (0, 1),
            "changing the store directly is not accounted"
        );
        assert_eq!(usage(true), (3, 5));
        assert_eq!(vfs.tmpfs_check(dev, 0, 1), Err(Errno::ENOSPC));
        assert_eq!(vfs.tmpfs_check(dev, 2, 0), Err(Errno::ENOSPC));
        assert_eq!(vfs.tmpfs_check(dev, 1, 0), Ok(()));
        // f had two pages, plus the one page not used up
        assert_eq!(vfs.tmpfs_room(dev, 2), Ok(Some(3)));
        vfs.tmpfs_charge(dev, 1, 0);
        assert_eq!(usage(false), (4, 5));
        assert_eq!(vfs.tmpfs_room(dev, 2), Ok(Some(2)));
        // A refusal counts again first when the recorded usage changed since the last count (here
        // the stray charge above), and only then
        assert_eq!(vfs.tmpfs_check(dev, 1, 0), Ok(()));
        assert_eq!(usage(false), (3, 5));
        assert_eq!(vfs.tmpfs_recount(dev), Ok(false));
        // Counted afresh: the recorded usage follows
        assert_eq!(usage(true), (3, 5));
        assert_eq!(usage(false), (3, 5));
        // Remount: cannot go below the usage
        let shrink = |blocks| {
            vfs.tmpfs_reconfigure(dev, |p, pages, _| {
                if blocks < pages {
                    return Err(Errno::EINVAL);
                }
                p.blocks = blocks;
                Ok(())
            })
        };
        assert_eq!(shrink(2), Err(Errno::EINVAL));
        assert_eq!(shrink(3), Ok(()));
        assert_eq!(vfs.sb_options(&m), ",size=12k,nr_inodes=5,inode64");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn anonymous_ns_mounts_are_skipped_by_propagation() {
        let (vfs, dir) = sample("anon-prop");
        let ps = &Empty;
        let cred = &Cred::root();
        let usr = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true)
            .unwrap();
        let sub = vfs
            .store()
            .mkdir(usr.ino().unwrap(), b"sub", 0o755, 0, 0)
            .unwrap();
        let point = Node::Store(ROOT_MOUNT, sub);
        // Make / shared and clone it into an anonymous open_tree namespace
        vfs.set_propagation(ROOT_MOUNT, PropagationType::Shared, false);
        let anon = vfs.anon_ns(crate::cred::UserNs::init());
        let cloned = vfs.clone_mount(&Node::ROOT, None, anon.id).unwrap();
        assert!(vfs.propagation(cloned).group != 0);
        // Mounting under / must NOT propagate into the unattached anonymous clone
        assert!(vfs.propagation_targets(ps, (&point, None)).is_empty());
        // Mounting on /usr/sub in INIT_MNT_NS and unmounting must NOT touch the clone
        let sub_mnt = vfs.add_mount(
            Fs::Store,
            point.clone(),
            (point.clone(), None),
            0,
            Vec::new(),
            None,
        );
        let in_use = std::collections::HashSet::from([cloned]);
        assert!(!vfs.propagated_busy(sub_mnt, &in_use));
        vfs.umount_tree(sub_mnt);
        assert!(vfs.mount(cloned).is_some());
        drop(anon);
        assert!(vfs.has_dead_ns());
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.mount(cloned).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detach_store_point_and_defer_collect_schedule_collection() {
        let (vfs, dir) = sample("detach-collect");
        let point_ino = vfs.store().mkdir(ROOT, b"mp", 0o755, 0, 0).unwrap();
        let (ns, map) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let other_root = map[&ROOT_MOUNT];
        let mp = Node::Store(other_root, point_ino);
        let params = TmpfsParams {
            perm: 0o1777,
            uid: 0,
            gid: 0,
            blocks: 4,
            inodes: 4,
            inode64: true,
        };
        let t = vfs
            .new_tmpfs(
                (mp, Some((Node::Store(other_root, ROOT), b"mp".to_vec()))),
                0,
                Vec::new(),
                params,
            )
            .unwrap();
        assert!(!vfs.released_detached());
        vfs.detach_store_point((point_ino, ROOT, b"mp"));
        assert!(vfs.released_detached());
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.mount(t).is_none());
        // defer_collect works across threads (kernel-wide flag, not thread-local)
        vfs.defer_collect();
        assert!(vfs.released_detached());
        assert!(!vfs.released_detached());
        drop(ns);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_symlinks_applies_to_trailing_slash() {
        struct Protected;
        impl Pseudo for Protected {
            fn parent(&self, node: &PseudoNode) -> Option<PseudoNode> {
                Empty.parent(node)
            }
            fn name(&self, mnt: MountId, node: &PseudoNode) -> Vec<u8> {
                Empty.name(mnt, node)
            }
            fn lookup(
                &self,
                mnt: MountId,
                dir: &PseudoNode,
                name: &[u8],
            ) -> Result<PseudoNode, Errno> {
                Empty.lookup(mnt, dir, name)
            }
            fn kind(&self, node: &PseudoNode) -> Result<u32, Errno> {
                Empty.kind(node)
            }
            fn readlink(&self, mnt: MountId, node: &PseudoNode) -> Result<Vec<u8>, Errno> {
                Empty.readlink(mnt, node)
            }
            fn follow(&self, mnt: MountId, node: &PseudoNode) -> Option<Result<Node, Errno>> {
                Empty.follow(mnt, node)
            }
            fn protected_symlinks(&self) -> bool {
                true
            }
        }
        let (vfs, dir) = sample("prot-sym-slash");
        let tmp = vfs.store().mkdir(ROOT, b"sticky", 0o1777, 0, 0).unwrap();
        vfs.store()
            .symlink(tmp, b"link", b"/usr", 1000, 1000)
            .unwrap();
        let mut other = Cred::root();
        other.fsuid = 2000;
        other.fsgid = 2000;
        other.cap_effective = 0;
        // Both `/sticky/link` and `/sticky/link/` must be refused with EACCES
        assert_eq!(
            vfs.resolve(
                &Protected,
                &other,
                &Node::ROOT,
                &Node::ROOT,
                b"/sticky/link",
                true
            ),
            Err(Errno::EACCES)
        );
        assert_eq!(
            vfs.resolve(
                &Protected,
                &other,
                &Node::ROOT,
                &Node::ROOT,
                b"/sticky/link/",
                false
            ),
            Err(Errno::EACCES)
        );
        // Fast-path Cached::stat must also defer `/sticky/link/` to normal resolution (None)
        let _ = vfs.store().stat(tmp);
        let cached = vfs.cached();
        assert!(cached.stat(ROOT, ROOT, b"/sticky/link/", false).is_none());
        // Owner can still follow `/sticky/link/`
        let mut owner = other.clone();
        owner.fsuid = 1000;
        assert!(
            vfs.resolve(
                &Protected,
                &owner,
                &Node::ROOT,
                &Node::ROOT,
                b"/sticky/link/",
                false
            )
            .is_ok()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normalizes_paths_lexically() {
        assert_eq!(normalize(b"/a/./b//../c"), b"/a/c");
        assert_eq!(normalize(b"/../.."), b"/");
        assert_eq!(normalize(b"/tmp/x/"), b"/tmp/x");
    }

    #[test]
    fn mnt_expire_preserved_by_mountpoint_lookup_and_cleared_by_normal_access() {
        let (vfs, dir) = sample("mnt-expire");
        let ps = &Empty;
        let cred = &Cred::root();
        let mp = vfs.store().mkdir(ROOT, b"mp", 0o755, 0, 0).unwrap();
        let point = Node::Store(ROOT_MOUNT, mp);
        let id = vfs
            .new_tmpfs((point, None), 0, Vec::new(), TmpfsParams::boot(0o1777))
            .unwrap();
        assert!(!vfs.mount(id).unwrap().expiring);
        vfs.set_expiring(id);
        assert!(vfs.mount(id).unwrap().expiring);

        // umount2's mountpoint lookup must not clear the MNT_EXPIRE mark.
        let resolved = vfs
            .resolve_mountpoint(ps, cred, &Node::ROOT, &Node::ROOT, b"/mp", true)
            .unwrap();
        assert_eq!(resolved.mnt(), id);
        assert!(vfs.mount(id).unwrap().expiring);

        // Normal path lookup touching the mount clears the MNT_EXPIRE mark.
        let accessed = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/mp", true)
            .unwrap();
        assert_eq!(accessed.mnt(), id);
        assert!(!vfs.mount(id).unwrap().expiring);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn batch_propagation_preserves_pnode_semantics_and_index() {
        let (vfs, dir) = sample("batch-prop");
        let ps = &Empty;
        let cred = &Cred::root();
        let usr = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true)
            .unwrap();
        let bin = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/bin", true)
            .unwrap();
        let sub = vfs
            .store()
            .mkdir(usr.ino().unwrap(), b"sub", 0o755, 0, 0)
            .unwrap();
        let sub_node = Node::Store(ROOT_MOUNT, sub);

        let bind_mount = |src: &Node, at: &Node| {
            let id = vfs.add_mount_unattached(
                Fs::Store,
                src.clone(),
                (at.clone(), None),
                0,
                Vec::new(),
                Some(ROOT_DEV),
            );
            let prop = vfs.propagation(src.mnt()).of_bind();
            vfs.update_mount(id, |m| m.prop = prop);
            vfs.attached(id);
            id
        };

        // Create a surviving peer group G0 (outside_peer + root_a), a child group G1 slaved to G0,
        // and a grandchild group G2 slaved to G1 with an external slave ext_slave outside the subtree.
        let outside_peer = bind_mount(&bin, &bin);
        vfs.set_propagation(outside_peer, PropagationType::Shared, false);
        let g0 = vfs.propagation(outside_peer).group;
        assert_ne!(g0, 0);

        let root_a = bind_mount(&Node::Store(outside_peer, bin.ino().unwrap()), &usr);
        assert_eq!(vfs.propagation(root_a).group, g0);

        let child_b = vfs.add_mount(
            Fs::Store,
            sub_node.clone(),
            (Node::Store(root_a, bin.ino().unwrap()), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        // Make child_b a shared slave of G0 (group G1, master G0)
        vfs.update_mount(child_b, |m| {
            m.prop = Propagation {
                group: 0,
                master: g0,
                unbindable: false,
            };
        });
        vfs.set_propagation(child_b, PropagationType::Shared, false);
        let g1 = vfs.propagation(child_b).group;
        assert_ne!(g1, 0);
        assert_eq!(vfs.propagation(child_b).master, g0);

        // Grandchild C is a shared slave of G1 (group G2, master G1)
        let child_c = vfs.add_mount(
            Fs::Store,
            sub_node.clone(),
            (Node::Store(child_b, sub), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(child_c, |m| {
            m.prop = Propagation {
                group: 0,
                master: g1,
                unbindable: false,
            };
        });
        vfs.set_propagation(child_c, PropagationType::Shared, false);
        let g2 = vfs.propagation(child_c).group;
        assert_ne!(g2, 0);
        assert_eq!(vfs.propagation(child_c).master, g1);

        // External slave of G2 outside root_a's subtree
        let ext_slave = vfs.add_mount(
            Fs::Store,
            bin.clone(),
            (sub_node.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(ext_slave, |m| {
            m.prop = Propagation {
                group: 0,
                master: g2,
                unbindable: false,
            };
        });

        // An unbindable leaf inside child_c must stay unbindable under Slave
        let unbind_leaf = vfs.add_mount(
            Fs::Store,
            bin.clone(),
            (Node::Store(child_c, sub), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.set_propagation(unbind_leaf, PropagationType::Unbindable, false);
        assert!(vfs.subtree_has_unbindable(root_a));
        assert!(!vfs.subtree_has_unbindable(outside_peer));

        // Recursive MS_SLAVE on root_a:
        // - root_a leaves G0, which still has outside_peer -> root_a becomes slave of G0
        // - child_b empties G1 (master G0) and child_c empties G2 (master G1) -> both and
        //   ext_slave transitively reparent their master to G0!
        // - unbind_leaf stays unbindable.
        vfs.set_propagation(root_a, PropagationType::Slave, true);
        assert_eq!(
            vfs.propagation(root_a),
            Propagation {
                group: 0,
                master: g0,
                unbindable: false,
            }
        );
        assert_eq!(
            vfs.propagation(child_b),
            Propagation {
                group: 0,
                master: g0,
                unbindable: false,
            }
        );
        assert_eq!(
            vfs.propagation(child_c),
            Propagation {
                group: 0,
                master: g0,
                unbindable: false,
            }
        );
        assert_eq!(
            vfs.propagation(ext_slave),
            Propagation {
                group: 0,
                master: g0,
                unbindable: false,
            }
        );
        assert_eq!(
            vfs.propagation(unbind_leaf),
            Propagation {
                group: 0,
                master: 0,
                unbindable: true,
            }
        );

        // Recursive MS_SHARED on root_a assigns fresh groups to all 4 mounts and clears unbindable
        vfs.set_propagation(root_a, PropagationType::Shared, true);
        assert!(!vfs.subtree_has_unbindable(root_a));
        for id in [root_a, child_b, child_c, unbind_leaf] {
            assert_ne!(vfs.propagation(id).group, 0);
            assert!(!vfs.propagation(id).unbindable);
        }

        // Now make outside_peer private (emptying G0): all slaves of G0 (including ext_slave)
        // must become master=0.
        vfs.set_propagation(outside_peer, PropagationType::Private, false);
        assert_eq!(vfs.propagation(ext_slave).master, 0);
        assert_eq!(vfs.propagation(root_a).master, 0);

        // Recursive MS_PRIVATE on root_a clears all groups & masters in the subtree
        vfs.set_propagation(root_a, PropagationType::Private, true);
        for id in [root_a, child_b, child_c, unbind_leaf] {
            assert_eq!(vfs.propagation(id), Propagation::default());
        }

        // Verify set_mount_attrs checks locks (EPERM) and writers (EBUSY) atomically before
        // mutating anything, and bumps mount_events only once on success.
        vfs.update_mount(child_c, |m| m.locks |= lock::NOEXEC);
        let before_events = vfs.mount_events_of(INIT_MNT_NS).get();
        let mut writers_called = false;
        assert_eq!(
            vfs.set_mount_attrs(
                root_a,
                true,
                |m| (m.flags | ms::RDONLY) & !ms::NOEXEC,
                true,
                || {
                    writers_called = true;
                    std::collections::HashSet::new()
                },
                Some(PropagationType::Shared),
            ),
            Err(Errno::EPERM)
        );
        assert!(!writers_called, "EPERM must short-circuit before writers");
        assert_eq!(vfs.mount_events_of(INIT_MNT_NS).get(), before_events);
        assert_eq!(vfs.mount(root_a).unwrap().flags & ms::RDONLY, 0);

        // Clear lock and fail with EBUSY due to an open writer on child_c
        vfs.update_mount(child_c, |m| m.locks &= !lock::NOEXEC);
        let before_events = vfs.mount_events_of(INIT_MNT_NS).get();
        assert_eq!(
            vfs.set_mount_attrs(
                root_a,
                true,
                |m| m.flags | ms::RDONLY,
                true,
                || std::collections::HashSet::from([child_c]),
                Some(PropagationType::Shared),
            ),
            Err(Errno::EBUSY)
        );
        assert_eq!(vfs.mount_events_of(INIT_MNT_NS).get(), before_events);
        assert_eq!(vfs.mount(root_a).unwrap().flags & ms::RDONLY, 0);

        // Succeed: every mount in subtree updated, propagation applied, single mounts_changed_ns()
        assert_eq!(
            vfs.set_mount_attrs(
                root_a,
                true,
                |m| m.flags | ms::RDONLY | ms::NODEV,
                true,
                std::collections::HashSet::new,
                Some(PropagationType::Shared),
            ),
            Ok(())
        );
        assert_eq!(
            vfs.mount_events_of(INIT_MNT_NS).get(),
            before_events + 1,
            "recursive mount_setattr must rebuild fast-path mount points only once"
        );
        for id in [root_a, child_b, child_c, unbind_leaf] {
            let m = vfs.mount(id).unwrap();
            assert_eq!(m.flags & (ms::RDONLY | ms::NODEV), ms::RDONLY | ms::NODEV);
            assert_ne!(m.prop.group, 0);
        }

        // propagation_targets filters by visibility: a peer rooted at /bin must not receive
        // mounts under /usr/sub, while peers rooted at / or /usr do, and a peer rooted at
        // /usr/sub itself receives it with at=None.
        vfs.set_propagation(ROOT_MOUNT, PropagationType::Shared, false);
        let g_root = vfs.propagation(ROOT_MOUNT).group;
        let peer_root = vfs.add_mount_unattached(
            Fs::Store,
            Node::ROOT,
            (bin.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(peer_root, |m| {
            m.prop = Propagation {
                group: g_root,
                master: 0,
                unbindable: false,
            };
        });
        let peer_usr = vfs.add_mount_unattached(
            Fs::Store,
            usr.clone(),
            (bin.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(peer_usr, |m| {
            m.prop = Propagation {
                group: g_root,
                master: 0,
                unbindable: false,
            };
        });
        let peer_sub = vfs.add_mount_unattached(
            Fs::Store,
            sub_node.clone(),
            (bin.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(peer_sub, |m| {
            m.prop = Propagation {
                group: g_root,
                master: 0,
                unbindable: false,
            };
        });
        let peer_bin = vfs.add_mount_unattached(
            Fs::Store,
            bin.clone(),
            (bin.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.update_mount(peer_bin, |m| {
            m.prop = Propagation {
                group: g_root,
                master: 0,
                unbindable: false,
            };
        });
        let at_entry = (usr.clone(), b"sub".to_vec());
        let targets = vfs.propagation_targets(ps, (&sub_node, Some(&at_entry)));
        let target_mnts: Vec<MountId> = targets.iter().map(|t| t.point.mnt()).collect();
        assert_eq!(target_mnts, vec![peer_root, peer_usr, peer_sub]);
        assert!(targets[0].at.is_some());
        assert!(targets[1].at.is_some());
        assert!(targets[2].at.is_none(), "on_root target must clear at");

        vfs.mounts.borrow().verify_index();
        vfs.umount_tree(root_a);
        vfs.mounts.borrow().verify_index();
        vfs.collect(&std::collections::HashSet::new());
        vfs.mounts.borrow().verify_index();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_mount_tree_operations_avoid_quadratic_stalls() {
        let (vfs, dir) = sample("mount-scale");
        let ps = &Empty;
        let cred = &Cred::root();
        let usr = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/usr", true)
            .unwrap();
        let bin = vfs
            .resolve(ps, cred, &Node::ROOT, &Node::ROOT, b"/bin", true)
            .unwrap();
        let sub = vfs
            .store()
            .mkdir(usr.ino().unwrap(), b"sub", 0o755, 0, 0)
            .unwrap();
        let sub_node = Node::Store(ROOT_MOUNT, sub);

        const N: usize = 800;

        // Build an 800-mount subtree under a single root (mix of chain + fanout)
        let tree_root = vfs.add_mount(
            Fs::Store,
            usr.clone(),
            (usr.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        let mut parent = tree_root;
        let mut last = tree_root;
        for i in 0..N {
            let point = Node::Store(parent, sub);
            let m = vfs.add_mount_unattached(
                Fs::Store,
                usr.clone(),
                (point, None),
                0,
                Vec::new(),
                Some(ROOT_DEV),
            );
            last = m;
            // Create both depth and branching
            if i % 4 == 0 {
                parent = m;
            }
        }
        vfs.mounts.borrow().verify_index();
        assert_eq!(vfs.subtree(tree_root).len(), N + 1);

        let start = std::time::Instant::now();

        // 1. Recursive set_propagation across all 801 mounts (Shared -> Slave -> Unbindable -> Private)
        vfs.set_propagation(tree_root, PropagationType::Shared, true);
        assert_ne!(vfs.propagation(last).group, 0);
        vfs.set_propagation(tree_root, PropagationType::Slave, true);
        assert_eq!(vfs.propagation(last).group, 0);
        vfs.set_propagation(tree_root, PropagationType::Unbindable, true);
        assert!(vfs.subtree_has_unbindable(tree_root));
        vfs.set_propagation(tree_root, PropagationType::Private, true);
        assert!(!vfs.subtree_has_unbindable(tree_root));

        // 2. attached() on the 801-mount subtree under a shared parent
        vfs.set_propagation(ROOT_MOUNT, PropagationType::Shared, false);
        vfs.attached(tree_root);
        assert_ne!(vfs.propagation(tree_root).group, 0);
        assert_ne!(vfs.propagation(last).group, 0);

        // 3. move_tree's unbindable check (full negative scan, then deep positive hit)
        assert!(!vfs.subtree_has_unbindable(tree_root));
        vfs.set_propagation(last, PropagationType::Unbindable, false);
        assert!(vfs.subtree_has_unbindable(tree_root));
        vfs.set_propagation(last, PropagationType::Private, false);

        // 4. mount_setattr(AT_RECURSIVE) with flags + propagation in one pass and one rebuild
        let events_before = vfs.mount_events_of(INIT_MNT_NS).get();
        vfs.set_mount_attrs(
            tree_root,
            true,
            |m| m.flags | ms::RDONLY | ms::NOSUID,
            true,
            std::collections::HashSet::new,
            Some(PropagationType::Shared),
        )
        .unwrap();
        assert_eq!(vfs.mount_events_of(INIT_MNT_NS).get(), events_before + 1);
        assert_eq!(
            vfs.mount(last).unwrap().flags & (ms::RDONLY | ms::NOSUID),
            ms::RDONLY | ms::NOSUID
        );

        // 5. move_mount of the 801-mount tree root
        vfs.move_mount(tree_root, Some((bin.clone(), None)));
        vfs.mounts.borrow().verify_index();
        assert_eq!(vfs.mount(tree_root).unwrap().parent(), Some(ROOT_MOUNT));

        // 6. Recursive bind copy (add_copies + attached) of the 801-mount tree onto /bin
        let bind_root = vfs.add_mount_unattached(
            Fs::Store,
            usr.clone(),
            (bin.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        {
            let snapshot = vfs.mounts();
            let sub_ids = vfs.subtree(tree_root);
            let mut by_id: HashMap<MountId, &Mount> = snapshot.iter().map(|m| (m.id, m)).collect();
            let mut plan_idx: HashMap<MountId, usize> = HashMap::new();
            let mut plan: Vec<(Option<usize>, &Mount)> = Vec::with_capacity(sub_ids.len() - 1);
            for &mid in &sub_ids[1..] {
                let m = by_id.remove(&mid).unwrap();
                let parent_idx = m.parent().and_then(|p| plan_idx.get(&p).copied());
                plan_idx.insert(mid, plan.len());
                plan.push((parent_idx, m));
            }
            vfs.add_copies(bind_root, &plan);
        }
        vfs.attached(bind_root);
        assert_eq!(vfs.subtree(bind_root).len(), N + 1);
        vfs.mounts.borrow().verify_index();
        vfs.umount_tree(bind_root);
        vfs.mounts.borrow().verify_index();

        // 7. propagation_targets across 800 peers (half rooted at /usr seeing /usr/sub, half at /bin)
        let shared_root = vfs.add_mount(
            Fs::Store,
            Node::ROOT,
            (sub_node.clone(), None),
            0,
            Vec::new(),
            Some(ROOT_DEV),
        );
        vfs.set_propagation(shared_root, PropagationType::Shared, false);
        let peer_group = vfs.propagation(shared_root).group;
        {
            let mut mounts = vfs.mounts.borrow_mut();
            for i in 0..N {
                let id = mounts.next;
                mounts.next += 1;
                let root = if i % 2 == 0 { usr.clone() } else { bin.clone() };
                mounts.push_attached(Mount {
                    id,
                    ns: INIT_MNT_NS,
                    fs: Fs::Store,
                    root: root.in_mount(id),
                    point: Some(Node::Store(ROOT_MOUNT, sub)),
                    at: None,
                    root_at: None,
                    root_gone: false,
                    flags: 0,
                    dev: ROOT_DEV,
                    source: Vec::new(),
                    expiring: false,
                    pin: None,
                    locks: 0,
                    prop: Propagation {
                        group: peer_group,
                        master: 0,
                        unbindable: false,
                    },
                    owner: None,
                });
            }
        }
        let targets = vfs.propagation_targets(
            ps,
            (
                &Node::Store(shared_root, sub),
                Some(&(
                    Node::Store(shared_root, usr.ino().unwrap()),
                    b"sub".to_vec(),
                )),
            ),
        );
        assert_eq!(targets.len(), N / 2);

        // Clean unmount & index verification
        vfs.umount_tree(tree_root);
        vfs.mounts.borrow().verify_index();
        vfs.collect(&std::collections::HashSet::new());
        vfs.mounts.borrow().verify_index();

        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "800-mount operations took {elapsed:?}, expected well below stall threshold"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removed_dir_path_of_vs_reach() {
        let (vfs, dir) = sample("rmcwd");
        let ps = &Empty;
        let a = vfs.store().mkdir(ROOT, b"a", 0o755, 0, 0).unwrap();
        let b = vfs.store().mkdir(a, b"b", 0o755, 0, 0).unwrap();
        let node_b = Node::Store(ROOT_MOUNT, b);
        assert_eq!(vfs.path_of(ps, &Node::ROOT, &node_b).unwrap(), b"/a/b");

        // Remove b: reach (getcwd) returns ENOENT while path_of (/proc/<pid>/cwd) appends " (deleted)".
        vfs.store().rmdir(a, b"b").unwrap();
        vfs.record_removed_dir(b, b"b");
        assert_eq!(vfs.reach(ps, &Node::ROOT, &node_b), Err(Errno::ENOENT));
        assert_eq!(
            vfs.path_of(ps, &Node::ROOT, &node_b).unwrap(),
            b"/a/b (deleted)"
        );

        // Renaming the surviving parent updates the reconstructed path dynamically.
        vfs.store()
            .rename(ROOT, b"a", ROOT, b"a2", false, false)
            .unwrap();
        assert_eq!(
            vfs.path_of(ps, &Node::ROOT, &node_b).unwrap(),
            b"/a2/b (deleted)"
        );

        // Removing the parent too preserves the full nested path.
        assert!(vfs.is_removed_dir_parent(a));
        vfs.store().rmdir(ROOT, b"a2").unwrap();
        vfs.record_removed_dir(a, b"a2");
        assert_eq!(vfs.reach(ps, &Node::ROOT, &node_b), Err(Errno::ENOENT));
        assert_eq!(
            vfs.path_of(ps, &Node::ROOT, &node_b).unwrap(),
            b"/a2/b (deleted)"
        );

        // Chroot equal to the deleted directory itself: reach is ENOENT, path_of is "/ (deleted)".
        assert_eq!(vfs.reach(ps, &node_b, &node_b), Err(Errno::ENOENT));
        assert_eq!(vfs.path_of(ps, &node_b, &node_b).unwrap(), b"/ (deleted)");

        // Pruning drops entries once nothing references them.
        vfs.prune_removed_dirs(&std::collections::HashSet::from([b]));
        assert!(vfs.has_removed_dirs());
        vfs.prune_removed_dirs(&std::collections::HashSet::new());
        assert!(!vfs.has_removed_dirs());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clone_ns_mount_pins_and_collects_namespaces() {
        let (vfs, dir) = sample("open-tree-nsfs");
        let (pin, _) = vfs.store().create_file(ROOT, b"pin", 0o444, 0, 0).unwrap();
        let point = (
            Node::Store(ROOT_MOUNT, pin),
            Some((Node::ROOT, b"pin".to_vec())),
        );
        // 1. Unattached clone_ns_mount keeps namespace alive and releases it when anon_ns drops.
        let (ns1, _) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let ns1_id = ns1.id;
        let anon1 = vfs.anon_ns(crate::cred::UserNs::init());
        let src1 = Node::Pseudo(
            PROC_MOUNT,
            PseudoNode::NsFile(crate::pseudo::NsKind::Mnt, ns1_id),
        );
        let mid1 = vfs.clone_ns_mount(&src1, crate::nsproxy::NsRef::Mnt(ns1.clone()), anon1.id);
        let m1 = vfs.mount(mid1).unwrap();
        assert_eq!(m1.fs, Fs::Nsfs);
        assert_eq!(m1.dev, Fs::Nsfs.dev());
        assert_eq!(m1.source, b"nsfs");
        assert_eq!(m1.flags, 0);
        assert!(m1.point.is_none());
        assert!(m1.root_at.is_none());
        assert_eq!(m1.pin.as_ref().map(|r| r.id()), Some(ns1_id));
        drop(m1);
        drop(ns1);
        assert!(vfs.find_ns(ns1_id).is_some());
        assert_eq!(vfs.pinned_ns(ns1_id).map(|r| r.id()), Some(ns1_id));
        drop(anon1);
        assert!(vfs.has_dead_ns());
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.find_ns(ns1_id).is_none());
        assert!(vfs.pinned_ns(ns1_id).is_none());

        // 2. Attaching a clone_ns_mount keeps the pinned namespace alive after anon_ns drops,
        //    and detaching releases it.
        let (ns2, _) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let ns2_id = ns2.id;
        let anon2 = vfs.anon_ns(crate::cred::UserNs::init());
        let src2 = Node::Pseudo(
            PROC_MOUNT,
            PseudoNode::NsFile(crate::pseudo::NsKind::Mnt, ns2_id),
        );
        let mid2 = vfs.clone_ns_mount(&src2, crate::nsproxy::NsRef::Mnt(ns2.clone()), anon2.id);
        drop(ns2);
        vfs.attach_tree(mid2, point, INIT_MNT_NS);
        drop(anon2);
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.find_ns(ns2_id).is_some());
        assert_eq!(vfs.pinned_ns(ns2_id).map(|r| r.id()), Some(ns2_id));
        assert_eq!(vfs.mount(mid2).unwrap().ns, INIT_MNT_NS);
        vfs.remove_mount(mid2);
        vfs.collect(&std::collections::HashSet::new());
        assert!(vfs.find_ns(ns2_id).is_none());
        assert!(vfs.pinned_ns(ns2_id).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlay_remove_and_rename_detach_other_ns_mounts() {
        let (vfs, dir) = sample("overlay-detach");
        let store = vfs.store();
        let lower = store.mkdir(ROOT, b"l", 0o755, 0, 0).unwrap();
        let l_rm = store.mkdir(lower, b"l_rm", 0o755, 0, 0).unwrap();
        let _ = l_rm;
        let upper = store.mkdir(ROOT, b"u", 0o755, 0, 0).unwrap();
        let work = store.mkdir(ROOT, b"w", 0o755, 0, 0).unwrap();
        let mp = store.mkdir(ROOT, b"m", 0o755, 0, 0).unwrap();

        let ovl_mnt = vfs.new_overlay(
            (Node::Store(ROOT_MOUNT, mp), None),
            0,
            b"overlay".to_vec(),
            ((Some(upper), vec![lower]), (0, 0), Vec::new()),
            overlay::Options::default(),
        );
        let Node::Overlay(_, ovl_root) = vfs.mount(ovl_mnt).unwrap().root else {
            panic!("expected overlay root");
        };
        store.mkdir(upper, b"u_rm", 0o755, 0, 0).unwrap();
        store.mkdir(upper, b"u_src", 0o755, 0, 0).unwrap();
        store.mkdir(upper, b"u_dst", 0o755, 0, 0).unwrap();

        let (ns2, map) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let ovl_mnt2 = map[&ovl_mnt];
        let u_rm2 = vfs.overlay_child((ovl_mnt2, ovl_root), b"u_rm").unwrap();
        let l_rm2 = vfs.overlay_child((ovl_mnt2, ovl_root), b"l_rm").unwrap();
        let u_src2 = vfs.overlay_child((ovl_mnt2, ovl_root), b"u_src").unwrap();
        let u_dst2 = vfs.overlay_child((ovl_mnt2, ovl_root), b"u_dst").unwrap();

        let m_urm = vfs
            .new_tmpfs(
                (u_rm2.clone(), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();
        let m_lrm = vfs
            .new_tmpfs(
                (l_rm2.clone(), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();
        let m_usrc = vfs
            .new_tmpfs(
                (u_src2.clone(), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();
        let m_udst = vfs
            .new_tmpfs(
                (u_dst2.clone(), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();

        // is_point_in reports busy only in ns2 (including across a bind mount in ns2), not init ns
        let u_rm1 = vfs.overlay_child((ovl_mnt, ovl_root), b"u_rm").unwrap();
        assert!(!vfs.is_point_in(&u_rm1, INIT_MNT_NS));
        assert!(vfs.is_point_in(&u_rm2, ns2.id));
        assert!(vfs.is_point_in(&u_rm1, ns2.id));

        let init_ev = vfs.mount_events_of(INIT_MNT_NS).get();
        let ns2_ev = vfs.mount_events_of(ns2.id).get();

        // Removing upper and lower overlay dirs detaches ns2's mounts on them and notifies only ns2
        vfs.overlay_remove(ovl_root, b"u_rm", true).unwrap();
        vfs.overlay_remove(ovl_root, b"l_rm", true).unwrap();
        assert!(vfs.mount(m_urm).is_none());
        assert!(vfs.mount(m_lrm).is_none());
        assert_eq!(vfs.mount_events_of(INIT_MNT_NS).get(), init_ev);
        assert!(vfs.mount_events_of(ns2.id).get() > ns2_ev);
        assert!(vfs.released_detached());

        // Overwriting rename detaches ns2's mount on old u_dst while keeping the mount on u_src
        let ns2_ev2 = vfs.mount_events_of(ns2.id).get();
        vfs.overlay_rename((ovl_root, b"u_src"), (ovl_root, b"u_dst"), (false, false))
            .unwrap();
        assert!(vfs.mount(m_udst).is_none());
        assert!(vfs.mount(m_usrc).is_some());
        assert_eq!(vfs.mount_events_of(INIT_MNT_NS).get(), init_ev);
        assert!(vfs.mount_events_of(ns2.id).get() > ns2_ev2);

        let _ = work;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mount_events_are_per_namespace_and_ignore_propagation_only_changes() {
        let (vfs, dir) = sample("mnt-events-ns");
        let store = vfs.store();
        let a = store.mkdir(ROOT, b"a", 0o755, 0, 0).unwrap();
        let b = store.mkdir(ROOT, b"b", 0o755, 0, 0).unwrap();

        let (ns2, map) = vfs.copy_ns(INIT_MNT_NS, crate::cred::UserNs::init());
        let root2 = map[&ROOT_MOUNT];

        let init_ev = vfs.mount_events_of(INIT_MNT_NS);
        let ns2_ev = vfs.mount_events_of(ns2.id);

        // Mounting in ns2 bumps only ns2, not init_ns
        let i0 = init_ev.get();
        let n0 = ns2_ev.get();
        let m2 = vfs
            .new_tmpfs(
                (Node::Store(root2, a), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();
        assert_eq!(init_ev.get(), i0);
        assert_eq!(ns2_ev.get(), n0 + 1);

        // Mounting in init_ns bumps only init_ns, not ns2
        let m1 = vfs
            .new_tmpfs(
                (Node::Store(ROOT_MOUNT, b), None),
                0,
                b"t".to_vec(),
                TmpfsParams::boot(0o755),
            )
            .unwrap();
        assert_eq!(init_ev.get(), i0 + 1);
        assert_eq!(ns2_ev.get(), n0 + 1);

        // Propagation-only changes (set_propagation, set_mount_prop, propagation-only
        // set_mount_attrs) do not bump either namespace's counter
        let i1 = init_ev.get();
        let n1 = ns2_ev.get();
        vfs.set_propagation(m1, PropagationType::Shared, false);
        vfs.set_propagation(m1, PropagationType::Slave, false);
        vfs.set_propagation(m1, PropagationType::Unbindable, false);
        vfs.set_propagation(m1, PropagationType::Private, false);
        vfs.set_mount_prop(m2, Propagation::default());
        vfs.set_mount_attrs(
            m1,
            false,
            |m| m.flags,
            false,
            std::collections::HashSet::new,
            Some(PropagationType::Shared),
        )
        .unwrap();
        assert_eq!(init_ev.get(), i1);
        assert_eq!(ns2_ev.get(), n1);

        // Flag-changing set_mount_attrs bumps only that mount's namespace
        vfs.set_mount_attrs(
            m1,
            false,
            |m| m.flags | ms::NOEXEC,
            false,
            std::collections::HashSet::new,
            None,
        )
        .unwrap();
        assert_eq!(init_ev.get(), i1 + 1);
        assert_eq!(ns2_ev.get(), n1);

        // Unmounting m2 bumps only ns2
        vfs.umount_tree(m2);
        assert_eq!(init_ev.get(), i1 + 1);
        assert_eq!(ns2_ev.get(), n1 + 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
