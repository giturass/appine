//! overlayfs (Linux 6.1's `fs/overlayfs`, the kernel/overlay map): a filesystem that shows several
//! store directories (layers) merged into one tree. The lower layers are read-only; a name in a
//! higher layer hides the same name below it, a whiteout (a character device 0:0) hides it
//! without showing anything, and a directory marked opaque (`trusted.overlay.opaque` = `y`, or
//! `user.overlay.opaque` with `userxattr`) is not merged with the directories below it.
//!
//! Every layer is a directory in the inode store, so an overlay node refers to the store inodes
//! behind it ([`OvlNode`]) and reads go to the topmost of them. Nodes are created as names are
//! looked up and kept per directory and name (Linux's overlay dentries), so an active path gives
//! the same node; they are dropped with their instance ([`Overlays::remove_instance`]), a node
//! whose name was removed (unlinked, or replaced by a rename) is dropped once nothing can use it
//! any more, and unused live nodes are evicted least-recently-used once the cache outgrows
//! [`NODES_MAX`] ([`Overlays::sweep`]).
//!
//! Changes go to the upper layer. What they change is first copied up ([`Overlays::upper_of`]):
//! its parent directories, then itself with its data, attributes and times, each in one store
//! transaction where Linux builds the copy in the work directory and renames it into place.
//! Removing a name the lower layers have leaves a whiteout in its place, a directory made where
//! one was removed is opaque, and a directory with lower layers cannot be renamed (EXDEV, Linux
//! without `redirect_dir`).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, PoisonError};

use super::store::{DirEntry, Ino, Stat, Store, mode};
use crate::errno::Errno;

/// An overlay node's number (in [`super::Node::Overlay`]), unique across all instances and never
/// reused.
pub(crate) type OvlId = u64;

/// The number that stands for node `id` in tables keyed by store inode number (locks, inotify
/// watches): its id with the top two bits 10, which store inode numbers never have (FUSE keys
/// have 11, cgroup2 files' 01).
pub(crate) const fn key(id: OvlId) -> Ino {
    1 << 63 | id
}

/// The node a [`key`] stands for; None for a store inode number or another kind of key.
pub(crate) const fn of_key(key: Ino) -> Option<OvlId> {
    if key >> 62 == 2 {
        Some(key & !(1 << 63))
    } else {
        None
    }
}

/// An instance's layers: the upper layer's root directory (None for a read-only overlay) and the
/// lower layers' root directories, topmost first.
pub(crate) type Layers = (Option<Ino>, Vec<Ino>);

/// Most layers one overlay may stack (Linux's `OVL_MAX_STACK`).
const MAX_STACK: usize = 500;

/// Removed nodes kept before a sweep is tried ([`Overlays::wants_sweep`]); after a sweep the next
/// one waits for twice as many as were left, so nodes still in use are not scanned again and
/// again.
const ORPHANS_MIN: usize = 1024;
/// Live nodes the cache keeps before evicting unused ones least recently looked up
/// ([`Overlays::sweep`]).
const NODES_MAX: usize = 1 << 14;
/// Target node count after a size-triggered live eviction (3/4 of [`NODES_MAX`]).
const NODES_TARGET: usize = NODES_MAX / 4 * 3;
/// Minimum headroom above live pinned nodes before triggering another size sweep (1/4 of
/// [`NODES_MAX`]).
const NODES_HEADROOM: usize = NODES_MAX / 4;

/// Every overlay instance and the nodes looked up in them.
#[derive(Default)]
pub(crate) struct Overlays {
    /// Instances by device number (bind mounts of an overlay share their source's).
    instances: HashMap<u64, Instance>,
    nodes: HashMap<OvlId, OvlNode>,
    next: OvlId,
    /// Logical LRU clock incremented on node creation and lookup.
    clock: u64,
    /// Nodes whose name was removed, with the [`crate::task::SYSCALLS`] count when it was: no
    /// lookup finds them again, and they go once nothing uses them ([`Overlays::sweep`]).
    orphans: Vec<(OvlId, u64)>,
    /// The number of orphans at which the next sweep is tried (0 meaning [`ORPHANS_MIN`]).
    sweep_at: usize,
    /// The total node count above which the next live-cache sweep is tried (0 meaning
    /// [`NODES_MAX`]).
    nodes_sweep_at: usize,
}

/// Open files holding each overlay node ([`Hold`]): their nodes are never swept. One table for
/// every kernel in the process, since an open file does not know its kernel; a number held in
/// another kernel only keeps a node of the same number a little longer.
static HELD: Mutex<BTreeMap<OvlId, usize>> = Mutex::new(BTreeMap::new());

/// An open file's claim on an overlay node (the node it was opened through, the directory it was
/// opened in), or a running program's (`/proc/<pid>/exe`): while one exists, [`Overlays::sweep`]
/// keeps the node, wherever the open file is (fd tables, `SCM_RIGHTS` messages in flight, epoll
/// sets, AIO, loop devices).
pub(crate) struct Hold(OvlId);

impl Hold {
    pub(crate) fn new(id: OvlId) -> Hold {
        *HELD
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id)
            .or_default() += 1;
        Hold(id)
    }

    /// Snapshot of all overlay nodes currently held by an open file or running program.
    fn snapshot() -> HashSet<OvlId> {
        HELD.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = held.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.0);
            }
        }
    }
}

/// One overlay instance (Linux's overlay superblock).
pub(crate) struct Instance {
    /// The upper layer's root directory, where changes go; None for a read-only overlay.
    pub upper: Option<Ino>,
    /// Mounted lower directories against which persistent origin handles are resolved.
    lower_roots: Vec<Ino>,
    /// The mounter's filesystem user and group IDs (kernel IDs): whiteouts belong to them, as
    /// Linux makes them with the mounter's credentials.
    pub mounter: (u32, u32),
    /// Device numbers of the tmpfs instances its layers are in: they stay while it does, as
    /// Linux's overlay keeps private mounts of its layers.
    pub pins: Vec<u64>,
    /// Options as given.
    pub options: Options,
    /// Copied-up upper inodes mapped to the lower inode they were copied up from, so evicting an
    /// unused copied-up node does not change its shown inode number while the mount lasts.
    origins: HashMap<Ino, Ino>,
}

// Store inode numbers are unique across layers. Check the magic and exact length before
// resolving the inode under a mounted lower root, including after a lower directory is moved.
const ORIGIN_V1: &[u8] = b"OVL\x01";

fn private_xattr(store: &Store, ino: Ino, name: &[u8]) -> Result<Option<Vec<u8>>, Errno> {
    match store.get_xattr(ino, name) {
        Ok(value) => Ok(Some(value)),
        Err(Errno::ENODATA) => Ok(None),
        Err(e) => Err(e),
    }
}

fn has_marker(store: &Store, ino: Ino, name: &[u8]) -> Result<bool, Errno> {
    Ok(private_xattr(store, ino, name)?.as_deref() == Some(b"y"))
}

impl Instance {
    fn origin(&self, store: &Store, upper: Ino, kind: u32) -> Result<Option<Ino>, Errno> {
        if let Some(&origin) = self.origins.get(&upper) {
            return Ok(Some(origin));
        }
        let name = self.options.private_name(b"origin");
        let Some(handle) = private_xattr(store, upper, &name)? else {
            return Ok(None);
        };
        let Some(bytes) = handle
            .strip_prefix(ORIGIN_V1)
            .and_then(|b| b.try_into().ok())
        else {
            return Ok(None);
        };
        let lower = Ino::from_le_bytes(bytes);
        // Copy-up allocates the upper after the lower. Its surviving row also prevents SQLite
        // from reusing a deleted lower's smaller rowid after boot cleanup.
        if lower == 0 || lower >= upper {
            return Ok(None);
        }
        let st = match store.attrs(lower) {
            Ok(st) => st,
            Err(Errno::ENOENT) => return Ok(None),
            Err(e) => return Err(e),
        };
        // ovl_getattr checks the lower link count: adding an upper hard link preserves st_ino.
        if st.kind() != kind || (!st.is_dir() && st.nlink != 1) {
            return Ok(None);
        }
        let Some(mut dir) = store.linked_dir(&st)? else {
            return Ok(None);
        };
        loop {
            if self.lower_roots.contains(&dir) {
                return Ok(Some(lower));
            }
            let parent = store.parent(dir)?;
            if parent == dir {
                return Ok(None);
            }
            dir = parent;
        }
    }

    fn mark_impure(&self, store: &Store, dir: Ino) -> Result<(), Errno> {
        let name = self.options.private_name(b"impure");
        if !has_marker(store, dir, &name)? {
            store.set_xattr(dir, &name, b"y", false, false)?;
        }
        Ok(())
    }
}

/// An overlay node: the store inodes behind one name (Linux's `ovl_entry`).
pub(crate) struct OvlNode {
    /// Device number of its instance.
    pub dev: u64,
    /// The directory it was found in; the root's is itself.
    pub parent: OvlId,
    /// The name it was found under; empty for the root.
    pub name: Vec<u8>,
    /// The inode in the upper layer.
    pub upper: Option<Ino>,
    /// Inodes in the lower layers, topmost first: for a directory every lower directory merged
    /// into it, for anything else only the topmost one, and none when the upper inode hides them.
    pub lower: Vec<Ino>,
    /// Validated copy-up origin used by stat and open-file metadata.
    origin: Option<Ino>,
    /// Nodes already looked up in it, by name.
    children: HashMap<Vec<u8>, OvlId>,
    /// [`Overlays::clock`] when it was last created or looked up: the oldest go first.
    seen: u64,
    /// [`crate::task::SYSCALLS`] when it was last created, looked up or accessed: nodes touched
    /// during another thread's in-flight path syscall are kept from live eviction.
    touched: Cell<u64>,
}

impl OvlNode {
    /// The store inode reads go to: the upper one, or the topmost lower one.
    pub(crate) fn real(&self) -> Ino {
        self.upper.or(self.lower.first().copied()).unwrap_or(0)
    }

    /// Whether it is a merged directory: more than one layer shows a directory under its name
    /// (Linux's `OVL_TYPE_MERGE`).
    fn merged(&self) -> bool {
        self.lower.len() + usize::from(self.upper.is_some()) > 1
    }
}

/// mount(2) options of an overlay (Linux 6.1's `ovl_config`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Options {
    /// `lowerdir=` as given (escaped `:` included).
    pub lowerdir: Vec<u8>,
    /// `upperdir=` as given.
    pub upperdir: Option<Vec<u8>>,
    /// `workdir=` as given.
    pub workdir: Option<Vec<u8>>,
    /// `redirect_dir=` when given.
    pub redirect_dir: Option<Vec<u8>>,
    pub default_permissions: bool,
    /// `index=`, `nfs_export=`, `xino=`, `metacopy=`, `uuid=` when given.
    pub index: Option<bool>,
    pub nfs_export: Option<bool>,
    pub xino: Option<Vec<u8>>,
    pub metacopy: Option<bool>,
    pub uuid: Option<bool>,
    pub volatile: bool,
    /// The private attributes are `user.overlay.*` instead of `trusted.overlay.*`.
    pub userxattr: bool,
}

impl Options {
    /// Parses mount(2)'s data as 6.1's `ovl_parse_opt` does: options are separated by commas
    /// that no backslash escapes, empty ones are skipped, anything unknown or without its value
    /// is EINVAL, and a later option replaces an earlier one.
    pub(crate) fn parse(data: &[u8]) -> Result<Options, Errno> {
        let mut o = Options::default();
        let mut redirect_given = false;
        for opt in split_escaped(data, b',') {
            if opt.is_empty() {
                continue;
            }
            let (key, value) = match opt.iter().position(|&b| b == b'=') {
                Some(i) => (&opt[..i], Some(&opt[i + 1..])),
                None => (&opt[..], None),
            };
            let on_off = |v: Option<&[u8]>| match v {
                Some(b"on") => Ok(true),
                Some(b"off") => Ok(false),
                _ => Err(Errno::EINVAL),
            };
            match (key, value) {
                (b"lowerdir", Some(v)) => o.lowerdir = v.to_vec(),
                (b"upperdir", Some(v)) => o.upperdir = Some(v.to_vec()),
                (b"workdir", Some(v)) => o.workdir = Some(v.to_vec()),
                (b"default_permissions", None) => o.default_permissions = true,
                (b"redirect_dir", Some(v)) => {
                    if !matches!(v, b"on" | b"off" | b"follow" | b"nofollow") {
                        return Err(Errno::EINVAL);
                    }
                    o.redirect_dir = Some(v.to_vec());
                    redirect_given = true;
                }
                (b"index", v) => o.index = Some(on_off(v)?),
                (b"uuid", v) => o.uuid = Some(on_off(v)?),
                (b"nfs_export", v) => o.nfs_export = Some(on_off(v)?),
                (b"userxattr", None) => o.userxattr = true,
                (b"xino", Some(v @ (b"on" | b"off" | b"auto"))) => o.xino = Some(v.to_vec()),
                (b"metacopy", v) => o.metacopy = Some(on_off(v)?),
                (b"volatile", None) => o.volatile = true,
                _ => return Err(Errno::EINVAL),
            }
        }
        // Workdir, index and volatile mean nothing without an upper layer (ignored, as in 6.1)
        if o.upperdir.is_none() {
            o.workdir = None;
            o.index = None;
            o.volatile = false;
        }
        // metacopy=on needs redirect_dir, nfs_export=on needs index and excludes metacopy, and
        // userxattr excludes all three
        let redirect_off = matches!(o.redirect_dir.as_deref(), Some(b"off" | b"nofollow"));
        if o.metacopy == Some(true) && redirect_given && redirect_off {
            return Err(Errno::EINVAL);
        }
        if o.nfs_export == Some(true) && (o.index == Some(false) || o.metacopy == Some(true)) {
            return Err(Errno::EINVAL);
        }
        if o.userxattr
            && (o.index == Some(true)
                || o.metacopy == Some(true)
                || o.redirect_dir.as_deref() == Some(b"on"))
        {
            return Err(Errno::EINVAL);
        }
        Ok(o)
    }

    /// The lower layers' paths: `lowerdir=` split at colons no backslash escapes, unescaped
    /// (6.1's `ovl_split_lowerdirs` and `ovl_unescape`). EINVAL for an empty one or more than
    /// [`MAX_STACK`].
    pub(crate) fn lower_paths(&self) -> Result<Vec<Vec<u8>>, Errno> {
        if self.lowerdir.is_empty() {
            return Err(Errno::EINVAL);
        }
        let paths: Vec<Vec<u8>> = split_escaped(&self.lowerdir, b':')
            .map(|p| unescape(&p))
            .collect();
        if paths.len() > MAX_STACK || paths.iter().any(Vec::is_empty) {
            return Err(Errno::EINVAL);
        }
        Ok(paths)
    }

    /// The upper layer's path, unescaped.
    pub(crate) fn upper_path(&self) -> Option<Vec<u8>> {
        self.upperdir.as_deref().map(unescape)
    }

    /// The work directory's path, unescaped.
    pub(crate) fn work_path(&self) -> Option<Vec<u8>> {
        self.workdir.as_deref().map(unescape)
    }

    /// The superblock options mountinfo shows after `ro`/`rw` (6.1's `ovl_show_options`):
    /// `lowerdir`, `upperdir` and `workdir` as given, then what differs from the defaults
    /// (redirect_dir follow, index, nfs_export, metacopy and xino off).
    pub(crate) fn show(&self) -> String {
        let mut s = String::new();
        let mut add = |key: &str, value: &[u8]| {
            s.push(',');
            s.push_str(key);
            if !value.is_empty() {
                s.push('=');
                s.push_str(&escape_option(value));
            }
        };
        add("lowerdir", &self.lowerdir);
        if let (Some(upper), Some(work)) = (&self.upperdir, &self.workdir) {
            add("upperdir", upper);
            add("workdir", work);
        }
        if self.default_permissions {
            add("default_permissions", b"");
        }
        if let Some(r) = self.redirect_dir.as_deref().filter(|r| *r != b"follow") {
            add("redirect_dir", r);
        }
        if self.index == Some(true) {
            add("index", b"on");
        }
        if self.uuid == Some(false) {
            add("uuid", b"off");
        }
        if self.nfs_export == Some(true) {
            add("nfs_export", b"on");
        }
        if self.metacopy == Some(true) {
            add("metacopy", b"on");
        }
        if self.volatile {
            add("volatile", b"");
        }
        if self.userxattr {
            add("userxattr", b"");
        }
        s
    }

    /// The prefix of the attributes overlayfs keeps for itself.
    pub(crate) fn private_prefix(&self) -> &'static [u8] {
        if self.userxattr {
            b"user.overlay."
        } else {
            b"trusted.overlay."
        }
    }

    fn private_name(&self, suffix: &[u8]) -> Vec<u8> {
        [self.private_prefix(), suffix].concat()
    }
}

/// An option's value as mountinfo shows it (Linux's `seq_show_option`): commas, equals signs,
/// spaces, tabs, newlines and backslashes as octal escapes.
fn escape_option(value: &[u8]) -> String {
    let mut out = Vec::with_capacity(value.len());
    for &b in value {
        match b {
            b',' | b'=' | b' ' | b'\t' | b'\n' | b'\\' => {
                out.extend_from_slice(format!("\\{b:03o}").as_bytes())
            }
            _ => out.push(b),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits at `sep` where no backslash escapes it (the backslashes stay).
fn split_escaped(s: &[u8], sep: u8) -> impl Iterator<Item = Vec<u8>> + '_ {
    let mut rest = Some(s);
    std::iter::from_fn(move || {
        let s = rest?;
        let mut i = 0;
        while i < s.len() {
            match s[i] {
                b'\\' => i += 2,
                b if b == sep => {
                    rest = Some(&s[i + 1..]);
                    return Some(s[..i].to_vec());
                }
                _ => i += 1,
            }
        }
        rest = None;
        Some(s.to_vec())
    })
}

/// Removes the backslashes escaping the next byte.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.iter();
    while let Some(&b) = it.next() {
        match b {
            b'\\' => out.extend(it.next()),
            _ => out.push(b),
        }
    }
    out
}

/// A whiteout: a character device with device number 0:0.
fn is_whiteout(st: &Stat) -> bool {
    st.kind() == mode::S_IFCHR && st.rdev == 0
}

/// Store directory `dir` has a whiteout named `name`.
pub(crate) fn whiteout_at(store: &Store, dir: Ino, name: &[u8]) -> Result<bool, Errno> {
    match store.lookup(dir, name)? {
        Some(ino) => Ok(is_whiteout(&store.attrs(ino)?)),
        None => Ok(false),
    }
}

/// What a copy-up copies (6.1's `ovl_copy_up_flags`): a file about to be truncated to 0 by
/// `O_TRUNC` needs no data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyUp {
    /// Everything, a regular file's data by sharing the lower object until either is written.
    All,
    /// Everything, a regular file's data copied now: the lower object may still be written in
    /// place (`syscall::fs::copy_up`).
    Copied,
    NoData,
}

/// A directory entry that may be a whiteout (only character devices can be).
fn maybe_whiteout(store: &Store, e: &DirEntry) -> Result<bool, Errno> {
    Ok(e.mode & mode::S_IFMT == mode::S_IFCHR && is_whiteout(&store.attrs(e.ino)?))
}

impl Overlays {
    /// Records a new instance with device number `dev` and returns its root node. `upper` is the
    /// upper layer's root, `lower` the lower layers' roots, topmost first.
    pub(crate) fn add_instance(
        &mut self,
        dev: u64,
        (upper, lower): Layers,
        (mounter, pins): ((u32, u32), Vec<u64>),
        options: Options,
    ) -> OvlId {
        let root = self.add_node(OvlNode {
            dev,
            parent: 0,
            name: Vec::new(),
            upper,
            lower: lower.clone(),
            origin: None,
            children: HashMap::new(),
            seen: 0,
            touched: Cell::new(0),
        });
        self.node_mut(root).parent = root;
        self.instances.insert(
            dev,
            Instance {
                upper,
                lower_roots: lower,
                mounter,
                pins,
                options,
                origins: HashMap::new(),
            },
        );
        root
    }

    /// Next node count above which [`Overlays::wants_sweep`] should trigger a live-cache sweep,
    /// given `live` nodes remaining: at least [`NODES_MAX`], and at least 25% (or
    /// [`NODES_HEADROOM`]) above `live` so working sets larger than [`NODES_MAX`] do not rescan on
    /// every lookup.
    fn next_nodes_sweep_at(live: usize) -> usize {
        let headroom = (live / 4).max(NODES_HEADROOM);
        NODES_MAX.max(live.saturating_add(headroom))
    }

    /// Forgets instance `dev` and all its nodes (its last mount is gone).
    pub(crate) fn remove_instance(&mut self, dev: u64) {
        if self.instances.remove(&dev).is_some() {
            self.nodes.retain(|_, n| n.dev != dev);
            let nodes = &self.nodes;
            self.orphans.retain(|(id, _)| nodes.contains_key(id));
            self.nodes_sweep_at = self
                .nodes_sweep_at
                .min(Self::next_nodes_sweep_at(self.nodes.len()));
        }
    }

    /// Node `id` lost its name: lookups no longer find it, and it can go once nothing uses it.
    fn orphan(&mut self, id: OvlId) {
        let now = crate::task::SYSCALLS.load(Ordering::Relaxed);
        self.orphans.push((id, now));
    }

    /// Whether enough removed nodes have gathered or the live node cache outgrew its bound to try
    /// a [`Overlays::sweep`].
    pub(crate) fn wants_sweep(&self) -> bool {
        self.orphans.len() >= self.sweep_at.max(ORPHANS_MIN)
            || self.nodes.len() > self.nodes_sweep_at.max(NODES_MAX)
    }

    /// Drops removed nodes nothing can use any more (with what lies below them) and, when total
    /// cached nodes still exceed [`NODES_MAX`], evicts unused live leaf nodes least recently
    /// looked up down to [`NODES_TARGET`]; returns how many nodes went. A node stays while it, or
    /// a node below it (whose parent links lead to it), is an instance root, in `keep` (processes'
    /// roots and cwds, mounts' roots/points/recorded file-mount directories, inotify watches),
    /// held by an open file or a running program ([`Hold`]), or removed/touched at or after
    /// `oldest`, the [`crate::task::SYSCALLS`] number of the earliest system call still running in
    /// another thread that may hold nodes it looked up.
    pub(crate) fn sweep(&mut self, keep: &HashSet<OvlId>, oldest: u64) -> usize {
        let held = Hold::snapshot();
        let orphans = std::mem::take(&mut self.orphans);
        let removed: HashMap<OvlId, u64> = orphans.iter().copied().collect();
        // Removed nodes are no longer their directories' children: index them by parent
        let mut under: HashMap<OvlId, Vec<OvlId>> = HashMap::new();
        for &(id, _) in &orphans {
            if let Some(n) = self.nodes.get(&id) {
                under.entry(n.parent).or_default().push(id);
            }
        }
        let mut gone = 0;
        for &(top, _) in &orphans {
            if !self.nodes.contains_key(&top) {
                continue;
            }
            let (mut stack, mut tree) = (vec![top], Vec::new());
            let free = loop {
                let Some(id) = stack.pop() else {
                    break true;
                };
                if keep.contains(&id)
                    || removed.get(&id).is_some_and(|&at| at >= oldest)
                    || held.contains(&id)
                {
                    break false;
                }
                tree.push(id);
                if let Some(n) = self.nodes.get(&id) {
                    stack.extend(n.children.values());
                }
                stack.extend(under.get(&id).into_iter().flatten());
            };
            if free {
                for id in tree {
                    gone += usize::from(self.nodes.remove(&id).is_some());
                }
            }
        }
        let nodes = &self.nodes;
        self.orphans = orphans
            .into_iter()
            .filter(|(id, _)| nodes.contains_key(id))
            .collect();
        self.sweep_at = 2 * self.orphans.len();

        if self.nodes.len() <= NODES_MAX {
            self.nodes_sweep_at = self
                .nodes_sweep_at
                .min(Self::next_nodes_sweep_at(self.nodes.len()));
            return gone;
        }
        let mut pinned: HashSet<OvlId> = keep
            .iter()
            .copied()
            .filter(|id| self.nodes.contains_key(id))
            .collect();
        for &id in &held {
            if self.nodes.contains_key(&id) {
                pinned.insert(id);
            }
        }
        for &(id, _) in &self.orphans {
            pinned.insert(id);
        }
        for (&id, n) in &self.nodes {
            if n.parent == id || n.touched.get() >= oldest {
                pinned.insert(id);
            }
        }
        // Keep every ancestor of a pinned node so parent links and copy-ups never see a gap
        let seeds: Vec<OvlId> = pinned.iter().copied().collect();
        for mut x in seeds {
            while let Some(n) = self.nodes.get(&x) {
                if n.parent == x || !pinned.insert(n.parent) {
                    break;
                }
                x = n.parent;
            }
        }
        // Surviving orphan subtrees are managed by the orphan sweep above
        if !self.orphans.is_empty() {
            let mut stack: Vec<OvlId> = self.orphans.iter().map(|&(id, _)| id).collect();
            while let Some(id) = stack.pop() {
                if let Some(n) = self.nodes.get(&id) {
                    for &child in n.children.values() {
                        if pinned.insert(child) {
                            stack.push(child);
                        }
                    }
                }
            }
        }
        // Evict unused leaves, least recently looked up first; a directory whose last child goes
        // becomes a leaf on the next iteration
        while self.nodes.len() > NODES_TARGET {
            let mut leaves: Vec<(u64, OvlId)> = self
                .nodes
                .iter()
                .filter(|(id, n)| !pinned.contains(id) && n.children.is_empty())
                .map(|(&id, n)| (n.seen, id))
                .collect();
            if leaves.is_empty() {
                break;
            }
            leaves.sort_unstable();
            leaves.truncate(self.nodes.len() - NODES_TARGET);
            for (_, id) in leaves {
                let n = self.nodes.remove(&id).unwrap();
                if let Some(p) = self.nodes.get_mut(&n.parent)
                    && p.children.get(&n.name) == Some(&id)
                {
                    p.children.remove(&n.name);
                }
                gone += 1;
            }
        }
        self.nodes_sweep_at = Self::next_nodes_sweep_at(self.nodes.len());
        gone
    }

    /// Device numbers of the instances.
    pub(crate) fn devs(&self) -> Vec<u64> {
        self.instances.keys().copied().collect()
    }

    /// Instance `dev`.
    pub(crate) fn instance(&self, dev: u64) -> Option<&Instance> {
        self.instances.get(&dev)
    }

    /// Node `id`.
    pub(crate) fn node(&self, id: OvlId) -> &OvlNode {
        let n = &self.nodes[&id];
        n.touched.set(crate::task::SYSCALLS.load(Ordering::Relaxed));
        n
    }

    fn node_mut(&mut self, id: OvlId) -> &mut OvlNode {
        let n = self.nodes.get_mut(&id).expect("overlay node");
        n.touched.set(crate::task::SYSCALLS.load(Ordering::Relaxed));
        n
    }

    fn add_node(&mut self, mut node: OvlNode) -> OvlId {
        self.next += 1;
        self.clock += 1;
        node.seen = self.clock;
        node.touched
            .set(crate::task::SYSCALLS.load(Ordering::Relaxed));
        self.nodes.insert(self.next, node);
        self.next
    }

    /// The options of the instance node `id` is in.
    pub(crate) fn options_of(&self, id: OvlId) -> &Options {
        &self.instances[&self.node(id).dev].options
    }

    /// Looks up `name` (not `.` or `..`) in directory `dir` (6.1's `ovl_lookup`): the upper layer
    /// first, then each lower directory merged into `dir`, stopping at a whiteout, at anything
    /// that is not a directory, and after an opaque directory; something that is not a directory
    /// below a directory is not seen. ENOENT when no layer has the name.
    pub(crate) fn lookup(
        &mut self,
        store: &Store,
        dir: OvlId,
        name: &[u8],
    ) -> Result<OvlId, Errno> {
        let d = self.node(dir);
        let options = self.options_of(dir);
        let opaque = |ino| has_marker(store, ino, &options.private_name(b"opaque"));
        let mut upper = None;
        let mut origin = None;
        let mut stop = false;
        if let Some(u) = d.upper
            && let Some(c) = store.lookup(u, name)?
        {
            let st = store.attrs(c)?;
            if is_whiteout(&st) {
                return Err(Errno::ENOENT);
            }
            origin = self.instances[&d.dev].origin(store, c, st.kind())?;
            upper = Some(c);
            stop = !st.is_dir() || opaque(c)?;
        }
        let mut lower = Vec::new();
        if !stop {
            for &l in &d.lower {
                let Some(c) = store.lookup(l, name)? else {
                    continue;
                };
                let st = store.attrs(c)?;
                if is_whiteout(&st) {
                    break;
                }
                if !st.is_dir() {
                    if upper.is_none() && lower.is_empty() {
                        lower.push(c);
                    }
                    break;
                }
                lower.push(c);
                if opaque(c)? {
                    break;
                }
            }
        }
        if upper.is_none() && lower.is_empty() {
            return Err(Errno::ENOENT);
        }
        let dev = d.dev;
        let child = d.children.get(name).copied();
        if let (Some(u), Some(l)) = (upper, origin) {
            self.instances.get_mut(&dev).unwrap().origins.insert(u, l);
        }
        if let Some(id) = child {
            self.clock += 1;
            let seen = self.clock;
            let n = self.node_mut(id);
            n.origin = origin;
            n.upper = upper;
            n.lower = lower;
            n.seen = seen;
            self.node_mut(dir).seen = seen;
            return Ok(id);
        }
        let id = self.add_node(OvlNode {
            dev,
            parent: dir,
            name: name.to_vec(),
            upper,
            lower,
            origin,
            children: HashMap::new(),
            seen: 0,
            touched: Cell::new(0),
        });
        let seen = self.clock;
        let parent = self.node_mut(dir);
        parent.seen = seen;
        parent.children.insert(name.to_vec(), id);
        Ok(id)
    }

    /// The entries of directory `dir`, without `.` and `..` and sorted by name (6.1's
    /// `ovl_dir_read_merged`): each name from the highest layer that has it, whiteouts hiding the
    /// names below them, each entry's inode number the one stat shows.
    pub(crate) fn readdir(&self, store: &Store, dir: OvlId) -> Result<Vec<DirEntry>, Errno> {
        let d = self.node(dir);
        let instance = &self.instances[&d.dev];
        let impure = match d.upper {
            Some(u) => has_marker(store, u, &instance.options.private_name(b"impure"))?,
            None => false,
        };
        let layers = d.upper.iter().chain(&d.lower);
        let mut seen: std::collections::BTreeMap<Vec<u8>, Option<DirEntry>> = Default::default();
        for &layer in layers {
            let is_upper = d.upper == Some(layer);
            for e in store.readdir(layer)? {
                if seen.contains_key(&e.name) {
                    continue;
                }
                let mut shown = (!maybe_whiteout(store, &e)?).then(|| e.clone());
                // A copied-up entry shows the number stat shows
                if let Some(shown) = &mut shown
                    && is_upper
                {
                    // In a pure directory a previously looked-up name can also cache the absence
                    // of an origin. On a cold listing check even entries without a parent marker.
                    let cached = d.children.get(&e.name).map(|id| &self.nodes[id]);
                    let origin = match cached {
                        Some(n) if !impure && n.upper == Some(e.ino) => n.origin,
                        _ => instance.origin(store, e.ino, e.mode & mode::S_IFMT)?,
                    };
                    shown.ino = origin.unwrap_or(e.ino);
                }
                seen.insert(e.name, shown);
            }
        }
        Ok(seen.into_values().flatten().collect())
    }

    /// Metadata of node `id` (6.1's `ovl_getattr`): the topmost inode's, with the inode number
    /// of the upper inode or else the topmost lower one (of the lower one a copy-up came from,
    /// [`OvlNode::origin`]), and one link for a merged directory.
    pub(crate) fn stat(&self, store: &Store, id: OvlId) -> Result<Stat, Errno> {
        let n = self.node(id);
        let mut st = store.stat(n.real())?;
        if st.is_dir() && n.merged() {
            st.nlink = 1;
        }
        if let Some(origin) = n.origin {
            st.ino = origin;
        }
        Ok(st)
    }

    /// The inode number stat shows for node `id` ([`Overlays::stat`]).
    pub(crate) fn shown_ino(&self, id: OvlId) -> Ino {
        let n = self.node(id);
        n.origin.unwrap_or(n.real())
    }

    /// The tmpfs instances (device numbers) the layers of live instances are in.
    pub(crate) fn pinned(&self) -> impl Iterator<Item = u64> + '_ {
        self.instances.values().flat_map(|i| i.pins.iter().copied())
    }

    /// The instance node `id` is in.
    pub(crate) fn instance_of(&self, id: OvlId) -> &Instance {
        &self.instances[&self.node(id).dev]
    }

    /// Whether a lower layer shows `name` in directory `dir` (6.1's `ovl_lower_positive`): the
    /// topmost lower directory merged into `dir` that has the name decides, and a whiteout
    /// there hides it.
    pub(crate) fn lower_has(&self, store: &Store, dir: OvlId, name: &[u8]) -> Result<bool, Errno> {
        for &l in &self.node(dir).lower {
            if let Some(c) = store.lookup(l, name)? {
                return Ok(!is_whiteout(&store.attrs(c)?));
            }
        }
        Ok(false)
    }

    /// Node `id`'s upper inode, copying it up first when it has none (6.1's `ovl_copy_up`):
    /// its parent directories, then itself as the topmost lower inode is, with its mode, owner,
    /// attributes other than the overlay's own, times and, unless `what` says otherwise, data;
    /// the parent's times stay as they were. EROFS without an upper layer.
    pub(crate) fn upper_of(
        &mut self,
        store: &Store,
        id: OvlId,
        what: CopyUp,
    ) -> Result<Ino, Errno> {
        if let Some(upper) = self.node(id).upper {
            return Ok(upper);
        }
        if self.instance_of(id).upper.is_none() {
            return Err(Errno::EROFS);
        }
        let parent = self.node(id).parent;
        if parent == id {
            return Err(Errno::EIO);
        }
        let dir = self.upper_of(store, parent, CopyUp::All)?;
        let n = self.node(id);
        let lower = *n.lower.first().ok_or(Errno::EIO)?;
        let name = n.name.clone();
        let options = self.options_of(id);
        let st = store.stat(lower)?;
        let record_origin = st.is_dir() || st.nlink == 1;
        let upper = store.transaction(|s| {
            let pst = s.stat(dir)?;
            let perm = st.mode & 0o7777;
            let ino = match st.kind() {
                mode::S_IFDIR => s.mkdir(dir, &name, perm, st.uid, st.gid)?,
                // The data is not copied: the upper file shares the lower one's object until
                // it is written (Store::share), as overlayfs on a filesystem with reflinks
                // clones it (6.1's ovl_copy_up_data, through vfs_clone_file_range)
                mode::S_IFREG => {
                    let (ino, file) = s.create_file(dir, &name, perm, st.uid, st.gid)?;
                    match what {
                        CopyUp::All if s.try_share(lower, ino)? => {}
                        CopyUp::All | CopyUp::Copied => {
                            let from = s.open_object(lower, false)?;
                            let len = from
                                .metadata()
                                .map_err(|e| e.raw_os_error().map_or(Errno::EIO, Errno))?;
                            let len = len.len();
                            super::store::copy_object(&from, &file, len)?;
                        }
                        CopyUp::NoData => {}
                    }
                    ino
                }
                mode::S_IFLNK => s.symlink(dir, &name, &s.readlink(lower)?, st.uid, st.gid)?,
                kind => s.mknod(dir, &name, kind | perm, st.rdev, st.uid, st.gid)?,
            };
            for x in s.list_xattr(lower)? {
                if !x.starts_with(options.private_prefix()) {
                    s.set_xattr(ino, &x, &s.get_xattr(lower, &x)?, false, false)?;
                }
            }
            s.set_flags(ino, st.flags)?;
            if record_origin {
                let handle = [ORIGIN_V1, &lower.to_le_bytes()].concat();
                s.set_xattr(ino, &options.private_name(b"origin"), &handle, false, false)?;
                self.instance_of(id).mark_impure(s, dir)?;
            }
            let at = super::store::FileTime::At;
            s.set_times(ino, Some(at(st.atime_ns)), Some(at(st.mtime_ns)))?;
            s.set_times(dir, Some(at(pst.atime_ns)), Some(at(pst.mtime_ns)))?;
            Ok(ino)
        })?;
        let dev = self.node(id).dev;
        self.clock += 1;
        let seen = self.clock;
        let n = self.node_mut(id);
        n.upper = Some(upper);
        n.seen = seen;
        if record_origin {
            n.origin = Some(lower);
        }
        if !st.is_dir() {
            n.lower.clear();
        }
        if record_origin {
            self.instances
                .get_mut(&dev)
                .unwrap()
                .origins
                .insert(upper, lower);
        }
        Ok(upper)
    }

    /// Mark a directory receiving a name for an inode with a copy-up origin.
    pub(crate) fn mark_origin_parent(
        &self,
        store: &Store,
        id: OvlId,
        dir: Ino,
    ) -> Result<(), Errno> {
        let n = self.node(id);
        let instance = &self.instances[&n.dev];
        if n.origin.is_some()
            || private_xattr(store, n.real(), &instance.options.private_name(b"origin"))?.is_some()
        {
            instance.mark_impure(store, dir)?;
        }
        Ok(())
    }

    /// Makes a whiteout named `name` in store directory `dir` for node `id`'s instance.
    fn whiteout(&self, s: &Store, id: OvlId, dir: Ino, name: &[u8]) -> Result<(), Errno> {
        let (uid, gid) = self.instance_of(id).mounter;
        s.mknod(dir, name, mode::S_IFCHR, 0, uid, gid).map(|_| ())
    }

    /// Removes `name` from directory `dir` (6.1's `ovl_do_remove`), once the caller has checked
    /// that it can go (with `rmdir`, an empty directory): the upper inode goes, with the
    /// whiteouts left in a directory, and a whiteout takes its place when a lower layer has the
    /// name. Returns the orphaned overlay node id so callers can detach mounts on it in other
    /// mount namespaces.
    pub(crate) fn remove(
        &mut self,
        store: &Store,
        dir: OvlId,
        name: &[u8],
        rmdir: bool,
    ) -> Result<OvlId, Errno> {
        let child = self.lookup(store, dir, name)?;
        let lower = self.lower_has(store, dir, name)?;
        let up = self.upper_of(store, dir, CopyUp::All)?;
        let child_upper = self.node(child).upper;
        store.transaction(|s| {
            match child_upper {
                Some(u) if rmdir => {
                    for e in s.readdir(u)? {
                        s.unlink(u, &e.name)?;
                    }
                    s.rmdir(up, name)?;
                }
                Some(_) => s.unlink(up, name)?,
                None => {}
            }
            if lower {
                self.whiteout(s, dir, up, name)?;
            }
            Ok(())
        })?;
        if let Some(u) = child_upper
            && (rmdir || !store.attrs(u).is_ok_and(|st| st.nlink > 0))
        {
            let dev = self.node(dir).dev;
            self.instances.get_mut(&dev).unwrap().origins.remove(&u);
        }
        self.node_mut(dir).children.remove(name);
        self.orphan(child);
        Ok(child)
    }

    /// Renames `old_name` in directory `old` to `new_name` in directory `new` (6.1's
    /// `ovl_rename`), once the caller has checked permissions: rules on the merged view first
    /// (ENOENT, EEXIST with `noreplace`, ENOTDIR, EISDIR, ENOTEMPTY), then EXDEV for a
    /// directory with lower layers, then everything involved is copied up and renamed in the
    /// upper layer, a whiteout left at the old name when a lower layer has it, and a directory
    /// moved into a merged one made opaque so it does not merge there. Returns the orphaned
    /// destination node id when an existing entry was overwritten without `RENAME_EXCHANGE`.
    pub(crate) fn rename(
        &mut self,
        store: &Store,
        (old, old_name): (OvlId, &[u8]),
        (new, new_name): (OvlId, &[u8]),
        (noreplace, exchange): (bool, bool),
    ) -> Result<Option<OvlId>, Errno> {
        let src = self.lookup(store, old, old_name)?;
        let dst = match self.lookup(store, new, new_name) {
            Ok(d) => Some(d),
            Err(Errno::ENOENT) if !exchange => None,
            Err(e) => return Err(e),
        };
        if dst == Some(src)
            || (!exchange && dst.is_some_and(|d| self.node(d).real() == self.node(src).real()))
        {
            return Ok(None);
        }
        let is_dir = |o: &Self, id| -> Result<bool, Errno> {
            Ok(store.kind(o.node(id).real())? == mode::S_IFDIR)
        };
        let src_dir = is_dir(self, src)?;
        if let Some(d) = dst {
            if noreplace {
                return Err(Errno::EEXIST);
            }
            let dst_dir = is_dir(self, d)?;
            if !exchange {
                match (src_dir, dst_dir) {
                    (true, false) => return Err(Errno::ENOTDIR),
                    (false, true) => return Err(Errno::EISDIR),
                    (true, true) if !self.readdir(store, d)?.is_empty() => {
                        return Err(Errno::ENOTEMPTY);
                    }
                    _ => {}
                }
            }
        }
        let has_lower = |o: &Self, id| -> Result<bool, Errno> {
            Ok(is_dir(o, id)? && !o.node(id).lower.is_empty())
        };
        if has_lower(self, src)? || (exchange && has_lower(self, dst.unwrap_or(src))?) {
            return Err(Errno::EXDEV);
        }
        let old_up = self.upper_of(store, old, CopyUp::All)?;
        let new_up = self.upper_of(store, new, CopyUp::All)?;
        let src_up = self.upper_of(store, src, CopyUp::All)?;
        let dst_up = match dst {
            Some(d) if exchange => Some(self.upper_of(store, d, CopyUp::All)?),
            Some(d) => self.node(d).upper,
            None => None,
        };
        let old_lower = !exchange && self.lower_has(store, old, old_name)?;
        // A directory moving into a merged one would merge with what the lower layers have under
        // its new name
        let opaque = self.options_of(src).private_name(b"opaque");
        let merged = |o: &Self, id: OvlId| !o.node(id).lower.is_empty();
        let src_opaque = src_dir && merged(self, new);
        let dst_opaque =
            exchange && dst.is_some_and(|d| is_dir(self, d).unwrap_or(false)) && merged(self, old);
        store.transaction(|s| {
            if dst.is_none() && whiteout_at(s, new_up, new_name)? {
                s.unlink(new_up, new_name)?;
            }
            // The directory being replaced may still hold whiteouts
            if !exchange
                && src_dir
                && let Some(du) = dst_up
            {
                for e in s.readdir(du)? {
                    s.unlink(du, &e.name)?;
                }
            }
            s.rename(old_up, old_name, new_up, new_name, false, exchange)?;
            if old_up != new_up {
                self.mark_origin_parent(s, src, new_up)?;
                if exchange && let Some(d) = dst {
                    self.mark_origin_parent(s, d, old_up)?;
                }
            }
            if old_lower {
                self.whiteout(s, src, old_up, old_name)?;
            }
            if src_opaque {
                s.set_xattr(src_up, &opaque, b"y", false, false)?;
            }
            if dst_opaque && let Some(du) = dst_up {
                s.set_xattr(du, &opaque, b"y", false, false)?;
            }
            Ok(())
        })?;
        if !exchange
            && let Some(du) = dst_up
            && !store.attrs(du).is_ok_and(|st| st.nlink > 0)
        {
            let dev = self.node(new).dev;
            self.instances.get_mut(&dev).unwrap().origins.remove(&du);
        }
        self.clock += 1;
        let seen = self.clock;
        self.node_mut(old).children.remove(old_name);
        let replaced = self.node_mut(new).children.remove(new_name);
        let n = self.node_mut(src);
        n.parent = new;
        n.name = new_name.to_vec();
        n.seen = seen;
        let new_dir = self.node_mut(new);
        new_dir.seen = seen;
        new_dir.children.insert(new_name.to_vec(), src);
        let orphaned = match replaced {
            Some(d) if exchange => {
                let n = self.node_mut(d);
                n.parent = old;
                n.name = old_name.to_vec();
                n.seen = seen;
                let old_dir = self.node_mut(old);
                old_dir.seen = seen;
                old_dir.children.insert(old_name.to_vec(), d);
                None
            }
            Some(d) => {
                self.orphan(d);
                Some(d)
            }
            None => None,
        };
        Ok(orphaned)
    }

    /// The node's parent directory (the root's is itself).
    pub(crate) fn parent(&self, id: OvlId) -> OvlId {
        self.node(id).parent
    }

    /// The store inode reads of node `id` go to ([`OvlNode::real`]); None once its instance is
    /// gone.
    pub(crate) fn real_of(&self, id: OvlId) -> Option<Ino> {
        self.nodes.get(&id).map(OvlNode::real)
    }

    /// Whether node `id` is still where it was looked up (Linux's hashed dentry): its directory
    /// still has it under its name. False once it was removed or replaced by a rename, and for a
    /// node of an instance that is gone.
    pub(crate) fn linked(&self, id: OvlId) -> bool {
        self.nodes.get(&id).is_some_and(|n| {
            n.parent == id
                || self
                    .nodes
                    .get(&n.parent)
                    .is_some_and(|p| p.children.get(&n.name) == Some(&id))
        })
    }

    /// Whether `name` is one of the attributes the instance of node `id` keeps for itself
    /// (`trusted.overlay.*`, or `user.overlay.*` with `userxattr`), which reads through the
    /// overlay never see.
    pub(crate) fn is_private_xattr(&self, id: OvlId, name: &[u8]) -> bool {
        name.starts_with(self.options_of(id).private_prefix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options_as_linux() {
        let o = Options::parse(b"lowerdir=a\\:b:c,,index=off,xino=auto").unwrap();
        assert_eq!(
            o.lower_paths().unwrap(),
            vec![b"a:b".to_vec(), b"c".to_vec()]
        );
        assert_eq!(o.index, None, "index means nothing without an upper layer");
        assert_eq!(Options::parse(b"lowerdir=a,bogus"), Err(Errno::EINVAL));
        assert_eq!(Options::parse(b"lowerdir"), Err(Errno::EINVAL));
        assert_eq!(Options::parse(b"redirect_dir=maybe"), Err(Errno::EINVAL));
        let o = Options::parse(b"lowerdir=a:,upperdir=u").unwrap();
        assert_eq!(o.lower_paths(), Err(Errno::EINVAL));
        assert_eq!(o.workdir, None);
        let o = Options::parse(b"upperdir=u,workdir=w,lowerdir=l,userxattr,volatile").unwrap();
        assert_eq!(
            o.show(),
            ",lowerdir=l,upperdir=u,workdir=w,volatile,userxattr"
        );
        assert_eq!(o.private_prefix(), b"user.overlay.");
        assert_eq!(
            Options::parse(b"lowerdir=l,upperdir=u,userxattr,index=on"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn merges_layers() {
        let dir = std::env::temp_dir().join(format!("appine-ovl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let root = super::super::store::ROOT;
        let a = s.mkdir(root, b"a", 0o755, 0, 0).unwrap();
        let b = s.mkdir(root, b"b", 0o755, 0, 0).unwrap();
        let ad = s.mkdir(a, b"d", 0o755, 0, 0).unwrap();
        let bd = s.mkdir(b, b"d", 0o755, 0, 0).unwrap();
        let ao = s.mkdir(a, b"o", 0o755, 0, 0).unwrap();
        let bo = s.mkdir(b, b"o", 0o755, 0, 0).unwrap();
        s.set_xattr(ao, b"trusted.overlay.opaque", b"y", false, false)
            .unwrap();
        let (af, _) = s.create_file(a, b"f", 0o644, 0, 0).unwrap();
        s.create_file(b, b"f", 0o644, 0, 0).unwrap();
        s.create_file(ad, b"x", 0o644, 0, 0).unwrap();
        s.create_file(bd, b"y", 0o644, 0, 0).unwrap();
        s.create_file(bo, b"z", 0o644, 0, 0).unwrap();
        s.mknod(a, b"gone", mode::S_IFCHR, 0, 0, 0).unwrap();
        s.create_file(b, b"gone", 0o644, 0, 0).unwrap();
        // A directory in a lower layer hidden by a file above it
        s.create_file(a, b"g", 0o644, 0, 0).unwrap();
        s.mkdir(b, b"g", 0o755, 0, 0).unwrap();
        let mut o = Overlays::default();
        let top = o.add_instance(
            0x30,
            (None, vec![a, b]),
            ((0, 0), Vec::new()),
            Options::default(),
        );
        let names = |o: &Overlays, d| -> Vec<Vec<u8>> {
            o.readdir(&s, d)
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect()
        };
        assert_eq!(names(&o, top), [&b"d"[..], b"f", b"g", b"o"]);
        let d = o.lookup(&s, top, b"d").unwrap();
        assert_eq!(o.node(d).lower, [ad, bd]);
        assert_eq!(names(&o, d), [b"x", b"y"]);
        assert_eq!(o.stat(&s, d).unwrap().nlink, 1);
        assert_eq!(o.stat(&s, d).unwrap().ino, ad);
        let od = o.lookup(&s, top, b"o").unwrap();
        assert_eq!(names(&o, od), [b"z"; 0]);
        assert_eq!(o.lookup(&s, od, b"z"), Err(Errno::ENOENT));
        assert_eq!(o.lookup(&s, top, b"gone"), Err(Errno::ENOENT));
        let f = o.lookup(&s, top, b"f").unwrap();
        assert_eq!(o.node(f).real(), af);
        let g = o.lookup(&s, top, b"g").unwrap();
        assert_eq!(o.node(g).lower.len(), 1);
        // Looked up again: the same node
        assert_eq!(o.lookup(&s, top, b"d").unwrap(), d);
        o.remove_instance(0x30);
        assert!(o.nodes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remount_validates_origin_under_a_live_lower_root() {
        use super::super::store::{FileTime::At, ROOT, inode_flags};

        let dir = std::env::temp_dir().join(format!("appine-ovl-origin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let layer = s.mkdir(ROOT, b"lower", 0o755, 0, 0).unwrap();
        let sub = s.mkdir(layer, b"sub", 0o755, 0, 0).unwrap();
        let other = s.mkdir(ROOT, b"other", 0o755, 0, 0).unwrap();
        let upper = s.mkdir(ROOT, b"upper", 0o755, 0, 0).unwrap();
        let (lower, _) = s.create_file(sub, b"f", 0o644, 0, 0).unwrap();
        s.set_flags(sub, inode_flags::NOATIME).unwrap();
        s.set_flags(lower, inode_flags::NODUMP).unwrap();
        s.set_times(upper, Some(At(100)), Some(At(200))).unwrap();
        let mount = |o: &mut Overlays, roots| {
            o.add_instance(
                1,
                (Some(upper), roots),
                ((0, 0), vec![]),
                Options::default(),
            )
        };
        let mut o = Overlays::default();
        let top = mount(&mut o, vec![layer]);
        let d = o.lookup(&s, top, b"sub").unwrap();
        let f = o.lookup(&s, d, b"f").unwrap();
        let copied = o.upper_of(&s, f, CopyUp::All).unwrap();
        assert_eq!(s.flags(o.node(d).real()).unwrap(), inode_flags::NOATIME);
        assert_eq!(s.flags(copied).unwrap(), inode_flags::NODUMP);
        let st = s.stat(upper).unwrap();
        assert_eq!((st.atime_ns, st.mtime_ns), (100, 200));
        o.rename(&s, (d, b"f"), (top, b"renamed"), (false, false))
            .unwrap();
        drop(o);

        let check = |roots, expected| {
            let mut o = Overlays::default();
            let top = mount(&mut o, roots);
            let listing = o.readdir(&s, top).unwrap();
            assert_eq!(
                listing.iter().find(|e| e.name == b"renamed").unwrap().ino,
                expected
            );
            let f = o.lookup(&s, top, b"renamed").unwrap();
            assert_eq!(o.stat(&s, f).unwrap().ino, expected);
            assert_eq!(o.shown_ino(f), expected);
        };
        check(vec![other], copied);
        check(vec![other, sub], lower);
        s.remove_xattr(upper, b"trusted.overlay.impure").unwrap();
        check(vec![layer], lower);

        let name = b"trusted.overlay.origin";
        let handle = s.get_xattr(copied, name).unwrap();
        let wrong_kind = [ORIGIN_V1, &sub.to_le_bytes()].concat();
        for malformed in [&b"old"[..], &handle[..handle.len() - 1], &wrong_kind] {
            s.set_xattr(copied, name, malformed, false, false).unwrap();
            check(vec![layer], copied);
        }
        s.set_xattr(copied, name, &handle, false, false).unwrap();
        s.link(sub, b"second", lower).unwrap();
        check(vec![layer], copied);
        s.unlink(sub, b"second").unwrap();
        check(vec![layer], lower);
        s.unlink(sub, b"f").unwrap();
        check(vec![layer], copied);
        drop(s);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A node stays linked while its directory has it: a rename moves it, removal and being
    /// replaced by a rename unlink it (inotify's `IN_EXCL_UNLINK` asks).
    #[test]
    fn nodes_stay_linked_until_removed_or_replaced() {
        let dir = std::env::temp_dir().join(format!("appine-ovl-linked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let root = super::super::store::ROOT;
        let l = s.mkdir(root, b"l", 0o755, 0, 0).unwrap();
        let u = s.mkdir(root, b"u", 0o755, 0, 0).unwrap();
        for name in [&b"f"[..], b"g", b"h"] {
            s.create_file(l, name, 0o644, 0, 0).unwrap();
        }
        let mut o = Overlays::default();
        let top = o.add_instance(
            0x31,
            (Some(u), vec![l]),
            ((0, 0), Vec::new()),
            Options::default(),
        );
        assert!(o.linked(top));
        let f = o.lookup(&s, top, b"f").unwrap();
        let g = o.lookup(&s, top, b"g").unwrap();
        assert!(o.linked(f) && o.linked(g));
        // Renaming a file onto another hard link of the same inode is a no-op.
        let f_up = o.upper_of(&s, f, CopyUp::All).unwrap();
        let top_up = o.upper_of(&s, top, CopyUp::All).unwrap();
        s.link(top_up, b"f_hard", f_up).unwrap();
        let f_hard = o.lookup(&s, top, b"f_hard").unwrap();
        assert_ne!(f_hard, f);
        assert_eq!(
            o.rename(&s, (top, b"f"), (top, b"f_hard"), (false, false))
                .unwrap(),
            None
        );
        assert!(o.linked(f) && o.linked(f_hard));
        o.remove(&s, top, b"f_hard", false).unwrap();
        assert!(!o.linked(f_hard) && o.linked(f));
        assert_eq!(s.attrs(f_up).unwrap().nlink, 1);
        o.rename(&s, (top, b"f"), (top, b"f2"), (false, false))
            .unwrap();
        assert!(o.linked(f));
        assert_eq!(o.node(f).name, b"f2");
        o.rename(&s, (top, b"h"), (top, b"g"), (false, false))
            .unwrap();
        assert!(!o.linked(g));
        o.remove(&s, top, b"f2", false).unwrap();
        assert!(!o.linked(f));
        // Keys never collide with store inode numbers, and give the node back
        assert_eq!(of_key(key(f)), Some(f));
        assert_eq!(of_key(f), None);
        o.remove_instance(0x31);
        assert!(!o.linked(top));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nodes of removed names go once nothing uses them: not while kept, held by an open file,
    /// below a kept or held node, or removed after another thread's system call began.
    #[test]
    fn removed_nodes_go_once_unused() {
        let dir = std::env::temp_dir().join(format!("appine-ovl-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let root = super::super::store::ROOT;
        let l = s.mkdir(root, b"l", 0o755, 0, 0).unwrap();
        let u = s.mkdir(root, b"u", 0o755, 0, 0).unwrap();
        let mut o = Overlays::default();
        let top = o.add_instance(
            0x32,
            (Some(u), vec![l]),
            ((0, 0), Vec::new()),
            Options::default(),
        );
        let create = |o: &mut Overlays, d: OvlId, name: &[u8]| {
            let up = o.upper_of(&s, d, CopyUp::All).unwrap();
            s.create_file(up, name, 0o644, 0, 0).unwrap();
            o.lookup(&s, d, name).unwrap()
        };
        // Files made and removed one after another: every node goes
        for i in 0..100 {
            let name = format!("tmp{i}");
            create(&mut o, top, name.as_bytes());
            o.remove(&s, top, name.as_bytes(), false).unwrap();
        }
        assert_eq!(o.orphans.len(), 100);
        let before = o.nodes.len();
        assert_eq!(o.sweep(&HashSet::new(), u64::MAX), 100);
        assert_eq!(o.nodes.len(), before - 100);
        assert!(o.orphans.is_empty());
        // A removed directory with a removed file below it held open, another kept as a cwd,
        // a file replaced by a rename while another thread's system call was running
        let up = o.upper_of(&s, top, CopyUp::All).unwrap();
        s.mkdir(up, b"d", 0o755, 0, 0).unwrap();
        let d = o.lookup(&s, top, b"d").unwrap();
        let f = create(&mut o, d, b"f");
        let hold = Hold::new(f);
        o.remove(&s, d, b"f", false).unwrap();
        o.remove(&s, top, b"d", true).unwrap();
        s.mkdir(up, b"cwd", 0o755, 0, 0).unwrap();
        let cwd = o.lookup(&s, top, b"cwd").unwrap();
        o.remove(&s, top, b"cwd", true).unwrap();
        let started = crate::task::SYSCALLS.fetch_add(1, Ordering::Relaxed) + 1;
        let g = create(&mut o, top, b"g");
        create(&mut o, top, b"h");
        o.rename(&s, (top, b"h"), (top, b"g"), (false, false))
            .unwrap();
        let keep = HashSet::from([cwd]);
        assert_eq!(o.sweep(&keep, started), 0);
        assert!([d, f, cwd, g].iter().all(|n| o.nodes.contains_key(n)));
        // A path-based truncate still holds its own node after an independent lease holder
        // closes. The hold alone must suffice once there is no syscall age protection.
        let truncating = Hold::new(g);
        drop(hold);
        assert_eq!(o.sweep(&HashSet::new(), u64::MAX), 3);
        assert!(o.nodes.contains_key(&g));
        drop(truncating);
        assert_eq!(o.sweep(&HashSet::new(), u64::MAX), 1);
        assert!([d, f, cwd, g].iter().all(|n| !o.nodes.contains_key(n)));
        assert!(o.linked(top) && o.orphans.is_empty());
        // A blocking open keeps its original parent even after its target moves elsewhere.
        s.mkdir(up, b"from", 0o755, 0, 0).unwrap();
        let from = o.lookup(&s, top, b"from").unwrap();
        let target = create(&mut o, from, b"file");
        let target_hold = Hold::new(target);
        let parent_hold = Hold::new(from);
        o.rename(&s, (from, b"file"), (top, b"moved"), (false, false))
            .unwrap();
        o.remove(&s, top, b"from", true).unwrap();
        assert_eq!(o.sweep(&HashSet::new(), u64::MAX), 0);
        drop(parent_hold);
        assert_eq!(o.sweep(&HashSet::new(), u64::MAX), 1);
        assert!(o.linked(target));
        drop(target_hold);
        o.remove_instance(0x32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unused live nodes are evicted least-recently-used once the cache outgrows `NODES_MAX`,
    /// keeping roots, held/kept nodes, their ancestors, in-flight syscall nodes, and copied-up
    /// origin inode numbers across eviction, and backing off `nodes_sweep_at` when live pinned
    /// nodes exceed `NODES_MAX`.
    #[test]
    fn live_nodes_bounded_and_preserve_invariants() {
        let dir = std::env::temp_dir().join(format!("appine-ovl-bound-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let root = super::super::store::ROOT;
        let l = s.mkdir(root, b"l", 0o755, 0, 0).unwrap();
        let u = s.mkdir(root, b"u", 0o755, 0, 0).unwrap();

        // Subdirectories and files in lower layer
        let keep_dir = s.mkdir(l, b"keep_dir", 0o755, 0, 0).unwrap();
        let (keep_file_ino, _) = s.create_file(keep_dir, b"held", 0o644, 0, 0).unwrap();
        let watch_dir = s.mkdir(l, b"watch_dir", 0o755, 0, 0).unwrap();
        s.create_file(watch_dir, b"watched", 0o644, 0, 0).unwrap();
        let (copied_lower_ino, _) = s.create_file(l, b"copied", 0o644, 0, 0).unwrap();
        let temp_dir = s.mkdir(l, b"temp_dir", 0o755, 0, 0).unwrap();
        s.create_file(temp_dir, b"temp_leaf", 0o644, 0, 0).unwrap();

        // Populate enough distinct files across buckets to cross NODES_MAX
        let total = NODES_MAX + 600;
        let mut buckets = Vec::new();
        for b in 0..32 {
            let name = format!("b{b}");
            buckets.push(s.mkdir(l, name.as_bytes(), 0o755, 0, 0).unwrap());
        }
        s.transaction(|s| {
            for i in 0..total {
                let name = format!("f{i}");
                s.create_file(buckets[i % buckets.len()], name.as_bytes(), 0o644, 0, 0)?;
            }
            Ok(())
        })
        .unwrap();

        let mut o = Overlays::default();
        let top = o.add_instance(
            0x33,
            (Some(u), vec![l]),
            ((0, 0), Vec::new()),
            Options::default(),
        );

        // Pin one file with Hold (in keep_dir), one with keep (watch_dir/watched), copy up one
        // unused file to check origin persistence, and look up an unused subdirectory tree.
        let kd = o.lookup(&s, top, b"keep_dir").unwrap();
        let kf = o.lookup(&s, kd, b"held").unwrap();
        let hold = Hold::new(kf);
        let wd = o.lookup(&s, top, b"watch_dir").unwrap();
        let wf = o.lookup(&s, wd, b"watched").unwrap();
        let cf = o.lookup(&s, top, b"copied").unwrap();
        let copied_upper = o.upper_of(&s, cf, CopyUp::All).unwrap();
        assert_ne!(copied_upper, copied_lower_ino);
        assert_eq!(o.stat(&s, cf).unwrap().ino, copied_lower_ino);
        let td = o.lookup(&s, top, b"temp_dir").unwrap();
        let tf = o.lookup(&s, td, b"temp_leaf").unwrap();

        // Walk all buckets and files
        let mut bucket_ids = Vec::new();
        for b in 0..32 {
            let name = format!("b{b}");
            bucket_ids.push(o.lookup(&s, top, name.as_bytes()).unwrap());
        }
        let mut last_id = 0;
        for i in 0..total {
            let name = format!("f{i}");
            last_id = o
                .lookup(&s, bucket_ids[i % bucket_ids.len()], name.as_bytes())
                .unwrap();
        }
        assert!(o.wants_sweep());

        // Touch one node during a simulated in-flight syscall on another thread
        let inflight_start = crate::task::SYSCALLS.fetch_add(1, Ordering::Relaxed) + 1;
        let inflight_file = o.lookup(&s, bucket_ids[0], b"f0").unwrap();
        let keep = HashSet::from([wf]);

        let evicted = o.sweep(&keep, inflight_start);
        assert!(evicted > 0);
        assert_eq!(o.nodes.len(), NODES_TARGET);
        assert!(!o.wants_sweep());

        // Root, held file + parent, kept file + parent, most-recent node, and in-flight node stay
        for id in [top, kd, kf, wd, wf, last_id, inflight_file] {
            assert!(o.nodes.contains_key(&id), "node {id} should have stayed");
            assert!(o.linked(id), "node {id} should still be linked");
        }
        assert_eq!(o.node(kf).real(), keep_file_ino);

        // Earliest unused leaves (including temp_leaf and copied) were evicted; temp_dir is now an
        // empty leaf and goes on the next sweep once the cache fills again
        assert!(!o.nodes.contains_key(&tf));
        assert!(!o.nodes.contains_key(&cf));
        assert!(o.nodes.contains_key(&td));
        for i in 0..NODES_HEADROOM + 64 {
            let name = format!("f{i}");
            o.lookup(&s, bucket_ids[i % bucket_ids.len()], name.as_bytes())
                .unwrap();
        }
        assert!(o.wants_sweep());
        let evicted_dir = o.sweep(&keep, u64::MAX);
        assert!(evicted_dir > 0);
        assert_eq!(o.nodes.len(), NODES_TARGET);
        assert!(
            !o.nodes.contains_key(&td),
            "empty unused directory should be evicted once it becomes a leaf"
        );

        // Re-looking up the evicted copied-up file restores its origin inode number in stat and
        // readdir!
        let readdir_ino = o
            .readdir(&s, top)
            .unwrap()
            .into_iter()
            .find(|e| e.name == b"copied")
            .unwrap()
            .ino;
        assert_eq!(readdir_ino, copied_lower_ino);
        let cf2 = o.lookup(&s, top, b"copied").unwrap();
        assert_ne!(cf2, cf);
        assert_eq!(o.node(cf2).upper, Some(copied_upper));
        assert_eq!(o.stat(&s, cf2).unwrap().ino, copied_lower_ino);
        assert!(o.linked(cf2));

        // Re-looking up an evicted directory and its leaf works cleanly
        let td2 = o.lookup(&s, top, b"temp_dir").unwrap();
        let tf2 = o.lookup(&s, td2, b"temp_leaf").unwrap();
        assert!(o.linked(td2) && o.linked(tf2));

        // Backoff when pinned nodes exceed NODES_MAX: does not rescan on every lookup
        let mut all_pinned: HashSet<OvlId> = o.nodes.keys().copied().collect();
        for i in 0..total {
            let b_name = format!("b{}", i % bucket_ids.len());
            let bd = o.lookup(&s, top, b_name.as_bytes()).unwrap();
            let name = format!("f{i}");
            let id = o.lookup(&s, bd, name.as_bytes()).unwrap();
            all_pinned.insert(id);
        }
        assert!(o.nodes.len() > NODES_MAX);
        assert!(o.wants_sweep());
        assert_eq!(o.sweep(&all_pinned, u64::MAX), 0);
        assert!(
            !o.wants_sweep(),
            "nodes_sweep_at should back off above pinned working set"
        );

        // Once unpinned, an explicit sweep reclaims back down to NODES_TARGET
        let evicted2 = o.sweep(&HashSet::new(), u64::MAX);
        assert!(evicted2 > 0);
        assert_eq!(o.nodes.len(), NODES_TARGET);
        assert!(!o.wants_sweep());

        drop(hold);
        o.remove_instance(0x33);
        assert!(o.nodes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
