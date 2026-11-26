//! cgroup v2 (the kernel/cgroup map): a cgroup tree in `/sys/fs/cgroup`.
//!
//! It started as a way to tell runtimes the app's memory limit: the JVM's default heap is 1/4 of
//! physical memory and Node.js sets V8's heap limit from physical memory, but the guest can only
//! use up to the OOM killer's limit (half of physical memory by default, [`crate::oom`]), so
//! several runtimes using it all up get killed. In containers they compute from the cgroup's
//! `memory.max` instead: the JVM's container support (UseContainerSupport), and Node.js through
//! libuv's `uv_get_constrained_memory`.
//!
//! The root cgroup looks like the root of a docker container using a cgroup namespace, with the
//! cpuset, cpu, memory and pids controllers all on, and only `cgroup.procs`, `cgroup.threads` and
//! `cgroup.subtree_control` writable (but it is the real root, so controllers can be enabled even
//! with processes in it):
//!
//! - `memory.max` is the OOM killer's limit and `memory.current` the app memory it measures (the
//!   host's anonymous memory, including what is swapped out to zram, so `memory.swap.max` is 0);
//!   `memory.stat` splits it into anonymous and shared memory, and `memory.events` counts limit
//!   overruns and kills;
//! - no CPU quota or weight: `cpu.max` is `max 100000`, and the cpuset is every CPU the guest sees;
//! - `pids.current` is the guest's task count (zombie processes included), `pids.max` is unlimited
//!   (the limits are threads-max and `RLIMIT_NPROC`).
//!
//! Child cgroups can be created below it (as dockerd, runc, crun and systemd do to manage
//! containers and services); processes migrate through `cgroup.procs` and follow their parent on
//! fork, and `/proc/<pid>/cgroup` is the path relative to the root of the reader's cgroup
//! namespace. A child cgroup's controllers follow its parent's `cgroup.subtree_control`, with the
//! same rules as Linux 6.1 (no internal processes, controllers in use cannot be disabled). Limits
//! are checked in Linux's format and recorded, and read back as written: `pids.max` stops fork
//! and thread creation ([`pids_charge`]), `memory.max` is checked periodically by the OOM killer
//! ([`crate::oom`]), `memory.high` records `high` events and triggers DBT pool/code-view reclaim
//! without killing, `cpuset.cpus` enforces hierarchical effective CPU masks on task scheduling and
//! affinity, and `cpu.max`/`cpu.weight`/`memory.low`/`memory.min` are stored without enforcement;
//! `cgroup.freeze` freezes the processes in the subtree (threads stop before returning to the
//! guest, and waiting syscalls return as if interrupted by a signal and restart after thaw);
//! `cgroup.kill` kills the processes in the whole subtree. The files Linux notifies of changes
//! (`cgroup.events`, `memory.events`, `memory.events.local`, `pids.events`) report them to poll
//! (`POLLPRI`) and inotify (`IN_MODIFY`) while something watches them ([`notify_changes`]).

use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use crate::cred::Cred;
use crate::errno::Errno;
use std::rc::Rc;

use crate::cell::RefCell;
use crate::kernel::{Cx, INIT, Kernel, Tid};
use crate::oom::Events;
use crate::process::ThreadGroup;
use crate::vfs::store::{Stat, mode};

/// The root cgroup's id (also its inode number, 1 as on Linux).
pub(crate) const ROOT: u64 = 1;

/// Linux's cgroup v2 controllers (in ssid order) and whether Appine has them: `cgroup.controllers`
/// lists them in this order; writing any other name to `subtree_control` is EINVAL, and writing
/// one Appine lacks is ENOENT.
const CONTROLLERS: [(&str, bool); 8] = [
    ("cpuset", true),
    ("cpu", true),
    ("io", false),
    ("memory", true),
    ("hugetlb", false),
    ("pids", true),
    ("rdma", false),
    ("misc", false),
];

/// The controllers Appine has (bits in [`CONTROLLERS`]).
const AVAILABLE: u32 = 1 << CPUSET | 1 << 1 | 1 << MEMORY | 1 << PIDS;
/// The positions of the cpuset, memory and pids controllers in [`CONTROLLERS`].
const CPUSET: usize = 0;
const MEMORY: usize = 3;
const PIDS: usize = 5;

/// The files in a cgroup directory: name, permission bits, and which controller they belong to
/// (None is a core file that every cgroup has). Sorted by name (the readdir order).
pub(crate) const FILES: [(&[u8], u32, Option<usize>); 39] = [
    (b"cgroup.controllers", 0o444, None),
    (b"cgroup.events", 0o444, None),
    (b"cgroup.freeze", 0o644, None),
    (b"cgroup.kill", 0o200, None),
    (b"cgroup.max.depth", 0o644, None),
    (b"cgroup.max.descendants", 0o644, None),
    (b"cgroup.procs", 0o644, None),
    (b"cgroup.stat", 0o444, None),
    (b"cgroup.subtree_control", 0o644, None),
    (b"cgroup.threads", 0o644, None),
    (b"cgroup.type", 0o644, None),
    (b"cpu.idle", 0o644, Some(1)),
    (b"cpu.max", 0o644, Some(1)),
    (b"cpu.max.burst", 0o644, Some(1)),
    (b"cpu.stat", 0o444, None),
    (b"cpu.weight", 0o644, Some(1)),
    (b"cpu.weight.nice", 0o644, Some(1)),
    (b"cpuset.cpus", 0o644, Some(0)),
    (b"cpuset.cpus.effective", 0o444, Some(0)),
    (b"cpuset.cpus.partition", 0o644, Some(0)),
    (b"cpuset.mems", 0o644, Some(0)),
    (b"cpuset.mems.effective", 0o444, Some(0)),
    (b"memory.current", 0o444, Some(3)),
    (b"memory.events", 0o444, Some(3)),
    (b"memory.events.local", 0o444, Some(3)),
    (b"memory.high", 0o644, Some(3)),
    (b"memory.low", 0o644, Some(3)),
    (b"memory.max", 0o644, Some(3)),
    (b"memory.min", 0o644, Some(3)),
    (b"memory.oom.group", 0o644, Some(3)),
    (b"memory.peak", 0o444, Some(3)),
    (b"memory.stat", 0o444, Some(3)),
    (b"memory.swap.current", 0o444, Some(3)),
    (b"memory.swap.events", 0o444, Some(3)),
    (b"memory.swap.high", 0o644, Some(3)),
    (b"memory.swap.max", 0o644, Some(3)),
    (b"pids.current", 0o444, Some(5)),
    (b"pids.events", 0o444, Some(5)),
    (b"pids.max", 0o644, Some(5)),
];

/// The index of interface file `name` in [`FILES`]; None when it is not a cgroup file.
fn file_index(name: &[u8]) -> Option<usize> {
    FILES.iter().position(|f| f.0 == name)
}

/// The permission bits of file `name`; None when it is not a cgroup file.
pub(crate) fn file_mode(name: &[u8]) -> Option<u32> {
    FILES.iter().find(|f| f.0 == name).map(|f| f.1)
}

// ---- The cgroup tree ----

/// One cgroup.
pub(crate) struct Cgroup {
    /// Name in the parent directory (empty for the root).
    pub name: Vec<u8>,
    pub parent: Option<u64>,
    /// Child cgroups: name → id.
    pub children: BTreeMap<Vec<u8>, u64>,
    /// `cgroup.subtree_control`: the controllers enabled for child cgroups (bits in
    /// [`CONTROLLERS`]).
    pub subtree_control: u32,
    /// Generation of the controller files exposed in children. A removed node stays dead.
    generations: [u64; CONTROLLERS.len()],
    /// Default kernfs attributes at mkdir. An attribute change affects only the named node.
    creator: (u32, u32),
    dir_mode: u32,
    created_ns: i64,
    attrs: BTreeMap<&'static [u8], Stat>,
    /// Bitmask of interface files (indexed by [`FILES`]) that have been looked up or opened
    /// (emulating Linux dcache dentry instantiation for directory-watch `kernfs_notify`).
    instantiated: Cell<u64>,
    /// Values of the interface files written (the limits), in the format Linux shows; files not
    /// written show their defaults.
    pub values: BTreeMap<&'static [u8], String>,
    /// Number of forks that failed because of the pids limit (the max of `pids.events`, recorded
    /// on the forking cgroup or on its nearest ancestor with pids enabled, not propagated upwards,
    /// as in Linux 6.1).
    pub pids_events: u64,
    /// `memory.events`: the number of times this cgroup and those below it exceeded their limit,
    /// needed to kill a process, and killed one.
    pub mem_events: Events,
    /// `memory.events.local`: counting only this cgroup's own.
    pub mem_events_local: Events,
    /// `memory.peak`: the largest subtree usage measured (bytes). The root's is measured by the
    /// OOM killer.
    pub mem_peak: Cell<u64>,
    /// Usage at the last `high` event, reset to zero when usage returns to or below `memory.high`.
    mem_high_last: Cell<u64>,
    /// `cgroup.freeze`: this cgroup itself asks to be frozen (an ancestor's also freezes it,
    /// [`Cgroups::freezing`]).
    pub freeze: bool,
    /// The attached device filter programs ([`crate::bpf`]), in attach order.
    pub device_progs: Vec<Rc<crate::bpf::Prog>>,
    /// The flags they were attached with (`BPF_F_ALLOW_OVERRIDE`, `BPF_F_ALLOW_MULTI`); 0 after
    /// all are detached.
    pub device_flags: u32,
}

impl Cgroup {
    fn new(name: Vec<u8>, parent: Option<u64>, (uid, gid): (u32, u32), mode: u32) -> Cgroup {
        Cgroup {
            name,
            parent,
            children: BTreeMap::new(),
            subtree_control: 0,
            generations: [0; CONTROLLERS.len()],
            creator: (uid, gid),
            dir_mode: mode,
            created_ns: crate::tty::wall_ns(),
            attrs: BTreeMap::new(),
            instantiated: Cell::new(0),
            values: BTreeMap::new(),
            pids_events: 0,
            mem_events: Events::default(),
            mem_events_local: Events::default(),
            mem_peak: Cell::new(0),
            mem_high_last: Cell::new(0),
            freeze: false,
            device_progs: Vec::new(),
            device_flags: 0,
        }
    }

    pub(crate) fn mark_instantiated(&self, name: &[u8]) {
        if let Some(i) = file_index(name) {
            self.instantiated.set(self.instantiated.get() | (1u64 << i));
        }
    }

    pub(crate) fn is_instantiated(&self, name: &[u8]) -> bool {
        file_index(name).is_some_and(|i| self.instantiated.get() & (1u64 << i) != 0)
    }

    fn initial_attrs(&self, name: &[u8]) -> Result<Stat, Errno> {
        let mode = if name.is_empty() {
            mode::S_IFDIR | self.dir_mode
        } else {
            mode::S_IFREG | file_mode(name).ok_or(Errno::ENOENT)?
        };
        Ok(self.node_attrs(mode, self.creator))
    }

    fn node_attrs(&self, mode: u32, (uid, gid): (u32, u32)) -> Stat {
        let dir = mode & mode::S_IFMT == mode::S_IFDIR;
        Stat {
            mode,
            uid,
            gid,
            nlink: if dir { 2 } else { 1 },
            size: if dir { 0 } else { 4096 },
            atime_ns: self.created_ns,
            mtime_ns: self.created_ns,
            ctime_ns: self.created_ns,
            ..Stat::default()
        }
    }

    /// Remove a disabled controller's files and create newly enabled files as the writer.
    fn update_controller_files(&mut self, enable: u32, disable: u32, owner: (u32, u32)) {
        for (idx, (name, perm, ctl)) in FILES.iter().copied().enumerate() {
            let Some(ctl) = ctl else { continue };
            if disable & (1 << ctl) != 0 {
                self.attrs.remove(name);
                self.values.remove(name);
                self.instantiated
                    .set(self.instantiated.get() & !(1u64 << idx));
            } else if enable & (1 << ctl) != 0 && self.creator != owner {
                self.attrs
                    .insert(name, self.node_attrs(mode::S_IFREG | perm, owner));
            }
        }
    }

    pub(crate) fn attrs(&self, name: &[u8]) -> Result<Stat, Errno> {
        match self.attrs.get(name) {
            Some(st) => Ok(st.clone()),
            None => self.initial_attrs(name),
        }
    }
}

/// All cgroups, by id. Ids are never reused.
pub(crate) struct Cgroups {
    pub map: BTreeMap<u64, Cgroup>,
    next: u64,
    /// Last observation by cgroup and file. Replaced at the next open/watch or pruned
    /// on the next relevant change if the last observer went away.
    observed: HashMap<(u64, &'static [u8]), Observed>,
    /// At least one observed file needs checking.
    pending: Cell<bool>,
}

/// A notifying cgroup file being watched: what it showed at the last mutation, whether any
/// transition happened since the last checkpoint (preserving transient 0 -> 1 -> 0 changes), and
/// the counter its changes bump ([`crate::fd::ProcEvent`]).
struct Observed {
    dirty: Cell<bool>,
    changed: Cell<bool>,
    content: RefCell<Option<String>>,
    counter: Rc<Cell<u64>>,
}

impl Observed {
    /// An open fd holds a counter reference. Inotify can watch the file or its directory.
    fn is_watched(&self, k: &Kernel, id: u64, name: &[u8]) -> bool {
        if Rc::strong_count(&self.counter) > 1 {
            return true;
        }
        let watches = k.inotify.borrow();
        watches.watches(key(id, name)) || watches.watches(key(id, b""))
    }
}

impl Default for Cgroups {
    fn default() -> Cgroups {
        let root = Cgroup::new(Vec::new(), None, (0, 0), 0o755);
        Cgroups {
            map: BTreeMap::from([(ROOT, root)]),
            next: ROOT + 1,
            observed: HashMap::new(),
            pending: Cell::new(false),
        }
    }
}

/// The files whose changes Linux 6.1 notifies (`cgroup_file_notify`: populated and frozen, memory
/// events, pids events). Linux 6.1 does not notify `cgroup.stat`.
const NOTIFYING: [&[u8]; 4] = [
    b"cgroup.events",
    b"memory.events",
    b"memory.events.local",
    b"pids.events",
];

/// The number inotify keys cgroup file `name` of cgroup `id` by (its directory with an empty
/// name): the top two bits 01, which store inode numbers, overlay keys (10) and FUSE keys (11)
/// never have, then the cgroup id and the file's place in [`FILES`] (0 for the directory).
pub(crate) fn key(id: u64, name: &[u8]) -> u64 {
    let file = FILES.iter().position(|f| f.0 == name).map_or(0, |i| i + 1);
    1 << 62 | id << 8 | file as u64
}

/// Whether `key` is a cgroup file's ([`key`]).
pub(crate) const fn is_key(key: u64) -> bool {
    key >> 62 == 1
}

/// The change counter of file `name` of cgroup `id` for an open file or a direct inotify watch to
/// follow; None for a file Linux never notifies. Marks the file instantiated (looked up/opened)
/// and starts from the file's current contents so only later changes count.
pub(crate) fn observe(k: &mut Kernel, id: u64, name: &'static [u8]) -> Option<Rc<Cell<u64>>> {
    k.cgroups.file_looked_up(id, name);
    observe_inner(k, id, name)
}

fn observe_inner(k: &mut Kernel, id: u64, name: &'static [u8]) -> Option<Rc<Cell<u64>>> {
    if !NOTIFYING.contains(&name) {
        return None;
    }
    if let Some(observed) = k.cgroups.observed.get(&(id, name))
        && observed.is_watched(k, id, name)
    {
        return Some(observed.counter.clone());
    }
    let content = file(k, id, name, &|t| t).ok();
    let counter = Rc::new(Cell::new(1));
    k.cgroups.observed.insert(
        (id, name),
        Observed {
            dirty: Cell::new(false),
            changed: Cell::new(false),
            content: RefCell::new(content),
            counter: counter.clone(),
        },
    );
    Some(counter)
}

/// Registers every notifying file of cgroup `id` for a watch on its directory without marking
/// un-looked-up child files instantiated (matching Linux's dcache-gated directory `kernfs_notify`).
pub(crate) fn observe_all(k: &mut Kernel, id: u64) {
    let names: Vec<&'static [u8]> = k
        .cgroups
        .files(id)
        .filter_map(|(name, _)| NOTIFYING.contains(&name).then_some(name))
        .collect();
    for name in names {
        observe_inner(k, id, name);
    }
}

/// Records an exact-point transition for an observed notifying file `(id, name)`: updates its
/// stored snapshot immediately so transient changes that revert before the next checkpoint
/// (e.g. `populated` or `frozen` 0 -> 1 -> 0) are never missed.
fn record_change(k: &Kernel, id: u64, name: &'static [u8]) {
    let Some(observed) = k.cgroups.observed.get(&(id, name)) else {
        return;
    };
    let current = file(k, id, name, &|tid| tid).ok();
    let mut prev = observed.content.borrow_mut();
    if *prev != current {
        *prev = current;
        if prev.is_some() {
            observed.changed.set(true);
        } else {
            observed.dirty.set(true);
        }
        k.cgroups.pending.set(true);
    } else if prev.is_none() {
        observed.dirty.set(true);
        k.cgroups.pending.set(true);
    }
}

/// A member arrived, left, migrated or changed its freezer participation. Evaluates `cgroup.events`
/// immediately on observed ancestors so transient transitions between checkpoints are preserved.
/// Callers must not hold a mutable borrow on any `ThreadGroup`.
pub(crate) fn task_changed(k: &Kernel, id: u64) {
    if !k.cgroups.observed.is_empty() {
        for ancestor in k.cgroups.ancestors(id) {
            record_change(k, ancestor, b"cgroup.events");
        }
    }
}

/// A cgroup's `cgroup.freeze` changed: re-evaluates `cgroup.events` on observed cgroups in its
/// subtree immediately so transient freeze/thaw toggles between checkpoints are preserved.
fn freeze_changed(k: &Kernel, id: u64) {
    for &(child, name) in k.cgroups.observed.keys() {
        if name == b"cgroup.events" && k.cgroups.is_within(child, id) {
            record_change(k, child, name);
        }
    }
}

/// Processes pending changes at the existing syscall, exit, freezer and timer checkpoints.
/// Transitions were already captured at their exact mutation points, so transient 0 -> 1 -> 0
/// changes still produce a notification here; several changes before a checkpoint coalesce into
/// one poll-counter bump and one inotify event.
#[inline]
pub(crate) fn notify_changes(k: &mut Kernel) {
    if k.cgroups.pending.get() {
        flush_changes(k);
    }
}

fn flush_changes(k: &mut Kernel) {
    let mut files: Vec<_> = k
        .cgroups
        .observed
        .iter()
        .filter_map(|(&key, observed)| {
            (observed.changed.get() || observed.dirty.get()).then_some(key)
        })
        .collect();
    files.retain(|&(id, name)| refresh_observed(k, id, name));
    // If reading a file panics, the next checkpoint retries the remaining files.
    k.cgroups.pending.set(false);

    // Deliver after refreshing all counters, since delivery can consume a one-shot watch.
    // Directory watches only receive IN_MODIFY for child files whose dentry has been instantiated,
    // matching native Linux kernfs_notify.
    for (id, name) in files {
        let dir = k
            .cgroups
            .get(id)
            .is_some_and(|g| g.is_instantiated(name))
            .then_some((key(id, b""), name));
        crate::syscall::kernfs_modified(k, key(id, name), dir);
    }
}

/// Refreshes a dirty/changed file's poll counter and reports whether to send IN_MODIFY.
fn refresh_observed(k: &mut Kernel, id: u64, name: &'static [u8]) -> bool {
    let key = (id, name);
    if k.cgroups.observed[&key].is_watched(k, id, name)
        && let Ok(content) = file(k, id, name, &|tid| tid)
    {
        let observed = k.cgroups.observed.get_mut(&key).unwrap();
        let was_dirty = observed.dirty.replace(false);
        let mut changed = observed.changed.replace(false);
        if was_dirty {
            let mut prev = observed.content.borrow_mut();
            if prev.as_ref() != Some(&content) {
                *prev = Some(content);
                changed = true;
            }
        }
        if !changed {
            return false;
        }
        observed.counter.set(observed.counter.get() + 1);
        crate::kernel::request_wake_object(crate::kernel::wake::of_value(&*observed.counter));
        return true;
    }
    k.cgroups.observed.remove(&key);
    false
}

impl Cgroups {
    fn mark_dirty(&self, id: u64, name: &'static [u8]) {
        if let Some(observed) = self.observed.get(&(id, name)) {
            observed.dirty.set(true);
            self.pending.set(true);
        }
    }

    /// Marks interface file `name` of cgroup `id` as looked up (dentry instantiated), so a watch
    /// on the cgroup directory will receive `IN_MODIFY` notifications for later changes to it.
    pub(crate) fn file_looked_up(&self, id: u64, name: &[u8]) {
        if let Some(g) = self.map.get(&id) {
            g.mark_instantiated(name);
        }
    }

    /// Creates child cgroup `name` under `parent` (Linux's `cgroup_mkdir`), owned by `cred`'s
    /// fsuid and fsgid, with permission bits `mode` (umask applied). An existing name is EEXIST; a
    /// newline in the name is EINVAL; exceeding an ancestor's `cgroup.max.depth` or
    /// `cgroup.max.descendants` is EAGAIN.
    pub fn mkdir(
        &mut self,
        parent: u64,
        name: &[u8],
        cred: &Cred,
        mode: u32,
    ) -> Result<u64, Errno> {
        let p = self.map.get(&parent).ok_or(Errno::ENOENT)?;
        if p.children.contains_key(name) || self.has_file(parent, name) {
            return Err(Errno::EEXIST);
        }
        if name.contains(&b'\n') {
            return Err(Errno::EINVAL);
        }
        // For each ancestor a: the new cgroup's depth below it and the number of cgroups below it
        // must not exceed its limits
        for (depth, a) in self.ancestors(parent).enumerate() {
            let limit = |key: &[u8]| {
                self.map[&a]
                    .values
                    .get(key)
                    .and_then(|v| v.parse::<usize>().ok())
            };
            if limit(b"cgroup.max.depth").is_some_and(|m| depth + 1 > m)
                || limit(b"cgroup.max.descendants").is_some_and(|m| self.descendants(a) + 1 > m)
            {
                return Err(Errno::EAGAIN);
            }
        }
        let id = self.next;
        self.next += 1;
        self.map.insert(
            id,
            Cgroup::new(name.to_vec(), Some(parent), (cred.fsuid, cred.fsgid), mode),
        );
        self.map
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_vec(), id);
        Ok(id)
    }

    /// Visible interface files and their generations. A lookup captures both so an open fd
    /// cannot act on a controller file recreated under the same name.
    pub fn files(&self, id: u64) -> impl Iterator<Item = (&'static [u8], u64)> + '_ {
        let group = self.get(id);
        let parent = group.and_then(|g| self.get(g.parent?));
        FILES.iter().filter_map(move |&(name, _, controller)| {
            group?;
            let generation = match (parent, controller) {
                (Some(p), Some(ctl)) if p.subtree_control & (1 << ctl) != 0 => p.generations[ctl],
                (Some(_), Some(_)) => return None,
                _ => 0,
            };
            Some((name, generation))
        })
    }

    pub(crate) fn attrs_mut(&mut self, id: u64, name: &'static [u8]) -> Result<&mut Stat, Errno> {
        if !name.is_empty() && !self.has_file(id, name) {
            return Err(Errno::ENOENT);
        }
        let group = self.map.get_mut(&id).ok_or(Errno::ENOENT)?;
        let initial = group.initial_attrs(name)?;
        Ok(group.attrs.entry(name).or_insert(initial))
    }

    /// Whether cgroup `id` exposes an interface file with this name.
    pub(crate) fn has_file(&self, id: u64, name: &[u8]) -> bool {
        self.files(id).any(|(f, _)| f == name)
    }

    /// The controllers enabled in cgroup `id` (`cgroup.controllers`): all of them at the root,
    /// otherwise the parent cgroup's `subtree_control`.
    fn controllers(&self, id: u64) -> u32 {
        match self.map.get(&id).and_then(|g| g.parent) {
            None => AVAILABLE,
            Some(p) => self.map.get(&p).map_or(0, |g| g.subtree_control),
        }
    }

    /// The number of cgroups below `id` (not counting itself).
    fn descendants(&self, id: u64) -> usize {
        self.map.get(&id).map_or(0, |g| {
            g.children.values().map(|&c| 1 + self.descendants(c)).sum()
        })
    }

    /// `id` or one of its ancestors asks to be frozen (`cgroup.freeze`): the processes in it must
    /// stop.
    pub fn freezing(&self, id: u64) -> bool {
        self.ancestors(id)
            .any(|c| self.map.get(&c).is_some_and(|g| g.freeze))
    }

    /// `id` is below `top` (or is `top` itself).
    pub fn is_within(&self, id: u64, top: u64) -> bool {
        self.ancestors(id).any(|c| c == top)
    }

    /// The path of `id` relative to `root` (the cgroup namespace's root); when it is not below
    /// it, the path first goes up with `..` to the common ancestor, like Linux's
    /// `kernfs_path_from_node`.
    pub fn path(&self, id: u64, root: u64) -> String {
        let up: Vec<u64> = self.ancestors(root).collect();
        let mut down = Vec::new();
        let mut c = id;
        while !up.contains(&c) {
            down.push(c);
            match self.map.get(&c).and_then(|g| g.parent) {
                Some(p) => c = p,
                None => break,
            }
        }
        let mut parts: Vec<String> = up
            .iter()
            .take_while(|&&a| a != c)
            .map(|_| "..".to_owned())
            .collect();
        parts.extend(
            down.iter()
                .rev()
                .filter_map(|d| self.map.get(d))
                .map(|g| String::from_utf8_lossy(&g.name).into_owned()),
        );
        format!("/{}", parts.join("/"))
    }

    /// The nearest cgroup that `a` and `b` are both within.
    pub fn common_ancestor(&self, a: u64, b: u64) -> u64 {
        self.ancestors(a)
            .find(|&c| self.is_within(b, c))
            .unwrap_or(ROOT)
    }

    /// `id` and its ancestors, starting with itself.
    fn ancestors(&self, id: u64) -> impl Iterator<Item = u64> + '_ {
        std::iter::successors(Some(id), |&c| self.map.get(&c).and_then(|g| g.parent))
    }

    pub fn get(&self, id: u64) -> Option<&Cgroup> {
        self.map.get(&id)
    }
}

/// Removes cgroup `id` (Linux's `cgroup_rmdir`): EBUSY while it still has processes or child
/// cgroups; the root cannot be removed (EBUSY).
pub(crate) fn rmdir(k: &mut Kernel, id: u64) -> Result<(), Errno> {
    let g = k.cgroups.map.get(&id).ok_or(Errno::ENOENT)?;
    let Some(parent) = g.parent else {
        return Err(Errno::EBUSY);
    };
    if !g.children.is_empty() || populated(k, id) {
        return Err(Errno::EBUSY);
    }
    let name = g.name.clone();
    for name in NOTIFYING {
        k.cgroups.mark_dirty(id, name);
    }
    k.cgroups.map.remove(&id);
    if let Some(p) = k.cgroups.map.get_mut(&parent) {
        p.children.remove(&name);
    }
    Ok(())
}

// ---- Reading ----

/// `/proc/<pid>/cgroup`: the process's cgroup, relative to the root `root` of the reader's cgroup
/// namespace.
pub(crate) fn proc_cgroup(k: &Kernel, cgroup: u64, root: u64) -> String {
    format!("0::{}\n", k.cgroups.path(cgroup, root))
}

/// `/proc/cgroups`: under cgroup v2 every controller's hierarchy is 0 (the JVM uses this to
/// recognize cgroup v2), and num_cgroups is the number of cgroups. cpuacct is merged into cpu in
/// v2 but still listed.
pub(crate) fn proc_cgroups(k: &Kernel) -> String {
    let mut s = String::from("#subsys_name\thierarchy\tnum_cgroups\tenabled\n");
    let n = k.cgroups.map.len();
    for name in ["cpuset", "cpu", "cpuacct", "memory", "pids"] {
        writeln!(s, "{name}\t0\t{n}\t1").unwrap();
    }
    s
}

/// The contents of `<name>` in cgroup `id`; `ENODEV` when the cgroup has been removed or its
/// controller has been disabled (Linux's `kernfs_get_active`), and `EINVAL` for a write-only file
/// (`cgroup.kill`). `vnr` turns a global id into the reader's (0 for one its pid namespace cannot
/// see, as Linux's `task_pid_vnr` prints in `cgroup.procs` and `cgroup.threads`).
pub(crate) fn file(
    k: &Kernel,
    id: u64,
    name: &[u8],
    vnr: &dyn Fn(crate::kernel::Tid) -> crate::kernel::Tid,
) -> Result<String, Errno> {
    if !k.cgroups.has_file(id, name) {
        return Err(Errno::ENODEV);
    }
    let g = &k.cgroups.map[&id];
    let root = g.parent.is_none();
    let max = |v: u64| {
        if v == u64::MAX {
            "max".to_owned()
        } else {
            v.to_string()
        }
    };
    // Processes and threads in the subtree
    let in_tree = |c: u64| k.cgroups.is_within(c, id);
    let procs = || members(k).filter(|&(_, c)| c == id).map(|(t, _)| t);
    let tasks = || {
        k.tasks
            .iter()
            .filter(move |(_, t)| t.tgid != INIT && group_cgroup(k, t.tgid).is_some_and(in_tree))
    };
    if let Some(v) = g.values.get(name) {
        return Ok(format!("{v}\n"));
    }
    let s = match name {
        b"cgroup.controllers" => names(k.cgroups.controllers(id)),
        // A controller list ends with a newline only when it lists names (Linux's
        // cgroup_print_ss_mask)
        b"cgroup.subtree_control" if g.subtree_control == 0 => return Ok(String::new()),
        b"cgroup.subtree_control" => names(g.subtree_control),
        b"cgroup.type" => "domain".to_owned(),
        b"cgroup.procs" => list(procs().map(vnr)),
        b"cgroup.threads" => list(
            k.tasks
                .iter()
                .filter(|(_, t)| t.tgid != INIT && group_cgroup(k, t.tgid) == Some(id))
                .map(|(&tid, _)| vnr(tid)),
        ),
        b"cgroup.events" => format!(
            "populated {}\nfrozen {}",
            populated(k, id) as u8,
            frozen(k, id) as u8
        ),
        b"cgroup.freeze" => (g.freeze as u8).to_string(),
        b"cpu.idle" | b"cpu.max.burst" | b"cpu.weight.nice" => "0".to_owned(),
        b"memory.min" | b"memory.low" | b"memory.oom.group" | b"memory.swap.current" => {
            "0".to_owned()
        }
        b"cgroup.max.depth"
        | b"cgroup.max.descendants"
        | b"memory.high"
        | b"memory.swap.high"
        | b"pids.max" => "max".to_owned(),
        b"cgroup.stat" => format!(
            "nr_descendants {}\nnr_dying_descendants 0",
            k.cgroups.descendants(id)
        ),
        b"cpu.max" => "max 100000".to_owned(),
        b"cpu.weight" => "100".to_owned(),
        b"cpu.stat" => {
            let cpu = if root {
                k.tasks.values().fold(k.cpu, |sum, t| sum + t.cpu())
            } else {
                tasks().fold(Default::default(), |sum, (_, t)| sum + t.cpu())
            };
            format!(
                "usage_usec {}\nuser_usec {}\nsystem_usec {}\nnr_periods 0\nnr_throttled 0\n\
                 throttled_usec 0\nnr_bursts 0\nburst_usec 0",
                cpu.total_ns / 1000,
                cpu.user_ns() / 1000,
                cpu.sys_ns / 1000
            )
        }
        b"cpuset.cpus" | b"cpuset.mems" => String::new(),
        b"cpuset.cpus.effective" => format_cpu_list(effective_cpus(k, id)),
        b"cpuset.mems.effective" => "0".to_owned(),
        b"cpuset.cpus.partition" => "member".to_owned(),
        // The root's memory is the whole app's, measured by the OOM killer; a child cgroup's is
        // the sum of its processes' resident memory
        b"memory.current" if root => k.oom.measure().to_string(),
        b"memory.peak" if root => {
            k.oom.measure();
            k.oom.peak.get().to_string()
        }
        b"memory.current" => {
            let used = subtree_rss(k, id);
            g.mem_peak.set(g.mem_peak.get().max(used));
            used.to_string()
        }
        b"memory.peak" => {
            let used = subtree_rss(k, id);
            g.mem_peak.set(g.mem_peak.get().max(used));
            g.mem_peak.get().to_string()
        }
        b"memory.max" if root => max(k.oom.limit),
        b"memory.swap.max" if root => "0".to_owned(),
        b"memory.max" | b"memory.swap.max" => "max".to_owned(),
        b"memory.events" => events(&g.mem_events),
        b"memory.events.local" => events(&g.mem_events_local),
        b"memory.stat" if root => memory_stat(k),
        b"memory.stat" => child_memory_stat(k, id),
        b"memory.swap.events" => "high 0\nmax 0\nfail 0".to_owned(),
        b"pids.current" => pids_current(k, id).to_string(),
        b"pids.events" => format!("max {}", g.pids_events),
        // Write-only ones (cgroup.kill)
        _ => return Err(Errno::EINVAL),
    };
    Ok(s + "\n")
}

/// Lists the names in a controller bitmask in [`CONTROLLERS`] order, separated by spaces.
fn names(mask: u32) -> String {
    let names: Vec<&str> = CONTROLLERS
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & 1 << i != 0)
        .map(|(_, (n, _))| *n)
        .collect();
    names.join(" ")
}

/// One id per line, in increasing order.
fn list(ids: impl Iterator<Item = crate::kernel::Tid>) -> String {
    let mut ids: Vec<_> = ids.collect();
    ids.sort_unstable();
    let lines: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
    lines.join("\n")
}

/// `frozen` in `cgroup.events`: freezing is requested and the threads in the subtree have all
/// stopped too (exiting ones do not count). An empty cgroup that is asked to freeze is frozen.
fn frozen(k: &Kernel, id: u64) -> bool {
    k.cgroups.freezing(id)
        && k.tasks.values().all(|t| {
            t.tgid == INIT
                || t.frozen.get()
                || t.killed.get()
                || group_cgroup(k, t.tgid).is_none_or(|c| !k.cgroups.is_within(c, id))
        })
}

/// Freezer stops and vfork waits both contribute to the subtree's frozen state.
pub(crate) fn enter_frozen(cx: &Cx<'_>) {
    if !cx.task.frozen.replace(true) {
        let cg = cx.t.group.borrow().cgroup;
        task_changed(cx.kr(), cg);
    }
}

/// The contents of `memory.events` (`low` is always 0: there is no memory.low protection).
fn events(e: &Events) -> String {
    format!(
        "low 0\nhigh {}\nmax {}\noom {}\noom_kill {}\noom_group_kill {}",
        e.high, e.max, e.oom, e.oom_kill, e.oom_group_kill
    )
}

/// `memory.stat`, following Linux 6.1's `memory_stat_format` (for a configuration with swap and
/// transparent huge pages but no zswap), in bytes. Only the host process's anonymous memory can be
/// measured (the same as `memory.current`): private and swapped-out memory counts as anon, shared
/// as shmem (Linux's file includes shmem), all in active_anon; there is no reclaimable page cache,
/// so inactive_file is 0. .NET's GC computes usage as `memory.current` minus inactive_file, and
/// without this file looks only at its own process's RSS.
fn memory_stat(k: &Kernel) -> String {
    let u = crate::oom::app_memory().unwrap_or_default();
    memory_stat_with(u.anon + u.swap, u.shmem, subtree_pgtables(k, ROOT))
}

/// A child cgroup's `memory.stat`: resident memory counts as anonymous memory, plus allocated
/// soft-MMU page tables for the subtree.
fn child_memory_stat(k: &Kernel, id: u64) -> String {
    memory_stat_with(subtree_rss(k, id), 0, subtree_pgtables(k, id))
}

/// The format of [`memory_stat`]: anonymous memory `anon`, shared memory `shmem` and soft-MMU
/// `pagetables` (bytes).
fn memory_stat_with(anon: u64, shmem: u64, pagetables: u64) -> String {
    let mut s = String::new();
    let mut put = |name: &str, v: u64| writeln!(s, "{name} {v}").unwrap();
    for (name, v) in [("anon", anon), ("file", shmem)] {
        put(name, v);
    }
    for (name, v) in [
        ("kernel", 0),
        ("kernel_stack", 0),
        ("pagetables", pagetables),
        ("sec_pagetables", 0),
        ("percpu", 0),
        ("sock", 0),
        ("vmalloc", 0),
    ] {
        put(name, v);
    }
    put("shmem", shmem);
    for name in [
        "file_mapped",
        "file_dirty",
        "file_writeback",
        "swapcached",
        "anon_thp",
        "file_thp",
        "shmem_thp",
        "inactive_anon",
    ] {
        put(name, 0);
    }
    put("active_anon", anon + shmem);
    for name in [
        "inactive_file",
        "active_file",
        "unevictable",
        "slab_reclaimable",
        "slab_unreclaimable",
        "slab",
        "workingset_refault_anon",
        "workingset_refault_file",
        "workingset_activate_anon",
        "workingset_activate_file",
        "workingset_restore_anon",
        "workingset_restore_file",
        "workingset_nodereclaim",
        "pgscan",
        "pgsteal",
        "pgscan_kswapd",
        "pgscan_direct",
        "pgsteal_kswapd",
        "pgsteal_direct",
        "pgfault",
        "pgmajfault",
        "pgrefill",
        "pgactivate",
        "pgdeactivate",
        "pglazyfree",
        "pglazyfreed",
        "thp_fault_alloc",
        "thp_collapse_alloc",
    ] {
        put(name, 0);
    }
    s.pop();
    s
}

// ---- Writing ----

/// The writing process: its thread, its pid namespace (ids in cgroup.procs are in it, and 0 is
/// itself) and the root of its cgroup namespace; and the credentials the file was opened with
/// (migrations are checked with them, as Linux's `__cgroup_procs_write` does).
pub(crate) struct Writer<'a> {
    pub tid: Tid,
    pub pid_ns: &'a crate::pidns::PidNs,
    pub ns_root: u64,
    pub opener: &'a Cred,
    pub cred: &'a Cred,
}

/// Writes `<name>` in cgroup `id` (Linux 6.1's `cgroup_file_write` and each cftype's `write`).
pub(crate) fn write(
    k: &mut Kernel,
    w: &Writer<'_>,
    (id, name): (u64, &[u8]),
    data: &[u8],
) -> Result<(), Errno> {
    // A file of a removed cgroup or a disabled controller still open: every write is ENODEV
    // (kernfs_get_active fails), which container managers take as "cgroup/file gone"
    if !k.cgroups.has_file(id, name) {
        return Err(Errno::ENODEV);
    }
    // On a namespace root only cgroup.procs, cgroup.threads and cgroup.subtree_control may be
    // written, anything else is EPERM (nsdelegate). Appine's root looks like a container's root
    // and follows this too: writing its memory.max and the like would not change the OOM
    // killer's limit, so as in a container it is not allowed
    if (id == w.ns_root || id == ROOT)
        && !matches!(
            name,
            b"cgroup.procs" | b"cgroup.threads" | b"cgroup.subtree_control"
        )
    {
        return Err(Errno::EPERM);
    }
    // Files with no write callback (read-only files)
    if file_mode(name).is_none_or(|m| m & 0o200 == 0) {
        return Err(Errno::EINVAL);
    }
    let text = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    let word = text.trim();
    match name {
        b"cgroup.procs" | b"cgroup.threads" => {
            let n: i32 = word.parse().map_err(|_| Errno::EINVAL)?;
            let tid = match n {
                0 => w.tid,
                n if n < 0 => return Err(Errno::EINVAL),
                n => w.pid_ns.find(n).ok_or(Errno::ESRCH)?,
            };
            migrate(k, (tid, w.opener), (id, w.ns_root), name == b"cgroup.procs")
        }
        b"cgroup.subtree_control" => subtree_control(k, id, text, (w.cred.fsuid, w.cred.fsgid)),
        // An integer; anything other than 1 is ERANGE (Linux's cgroup_kill_write)
        b"cgroup.kill" => match word.parse::<i32>().map_err(|_| Errno::EINVAL)? {
            1 => {
                kill(k, id);
                Ok(())
            }
            _ => Err(Errno::ERANGE),
        },
        // 0 or 1; any other integer is ERANGE (Linux's cgroup_freeze_write)
        b"cgroup.freeze" => {
            let freeze = match word.parse::<i32>().map_err(|_| Errno::EINVAL)? {
                0 => false,
                1 => true,
                _ => return Err(Errno::ERANGE),
            };
            k.cgroups.map.get_mut(&id).ok_or(Errno::ENOENT)?.freeze = freeze;
            let groups: Vec<_> = k
                .groups
                .iter()
                .filter(|&(&tgid, g)| tgid != INIT && k.cgroups.is_within(g.borrow().cgroup, id))
                .map(|(_, g)| g.clone())
                .collect();
            for g in groups {
                refreeze(k, &g);
            }
            // Record exact transitions for observed descendants, including empty cgroups.
            freeze_changed(k, id);
            Ok(())
        }
        b"cgroup.type" => match word {
            "threaded" => Err(Errno::EOPNOTSUPP),
            _ => Err(Errno::EINVAL),
        },
        _ => {
            let g = k.cgroups.map.get_mut(&id).ok_or(Errno::ENOENT)?;
            let value = parse_value(name, word, g.values.get(name).map(String::as_str))?;
            let key = FILES.iter().find(|f| f.0 == name).ok_or(Errno::EINVAL)?.0;
            g.values.insert(key, value);
            match key {
                // Lowering memory.max: when usage is already over it, kill a process at once
                // (Linux's memory_max_write OOMs when it cannot reclaim, without recording a max
                // event).
                b"memory.max" => {
                    k.oom.recheck();
                    if let Ok(max) = g.values[key].parse::<u64>() {
                        let used = measure_memory(k, id);
                        if used > max {
                            crate::oom::out_of_memory(k, (id, used, max));
                        }
                    }
                }
                // Writing memory.high: recheck periodically, and if usage already exceeds a newly
                // lowered threshold, record a high event and reclaim immediately without killing.
                b"memory.high" => {
                    k.oom.recheck();
                    match g.values[key].parse::<u64>() {
                        Ok(high) => {
                            let used = measure_memory(k, id);
                            if note_memory_high_state(k, id, used, high) {
                                crate::oom::handle_memory_high(k, id);
                            }
                        }
                        Err(_) => g.mem_high_last.set(0),
                    }
                }
                b"cpuset.cpus" => {
                    apply_cpuset_subtree(k, id);
                }
                _ => {}
            }
            Ok(())
        }
    }
}

/// Migrates the process of thread `tid` (`procs`) or the thread itself to cgroup `dst` (Linux's
/// `__cgroup_procs_write`, `cgroup_attach_permissions`): a missing process is ESRCH; `cred`, the
/// file opener's, must be allowed to write the `cgroup.procs` of the nearest cgroup above both the
/// source and the destination (EACCES), so the owner of a delegated cgroup cannot pull in processes
/// from outside it; the source and the destination must both be under the root `ns_root` of the
/// writer's cgroup namespace (ENOENT); a destination with controllers enabled (other than the root)
/// cannot have processes (EBUSY); migrating a single thread between domain cgroups is EOPNOTSUPP.
/// The write permission on the destination's own file is checked when it is opened.
fn migrate(
    k: &mut Kernel,
    (tid, cred): (Tid, &Cred),
    (dst, ns_root): (u64, u64),
    procs: bool,
) -> Result<(), Errno> {
    let tgid = k.tasks.get(&tid).ok_or(Errno::ESRCH)?.tgid;
    if tgid == INIT {
        return Err(Errno::EINVAL);
    }
    let g = k.groups.get(&tgid).cloned().ok_or(Errno::ESRCH)?;
    let src = g.borrow().cgroup;
    may_write_procs(k, cred, k.cgroups.common_ancestor(src, dst))?;
    if !k.cgroups.is_within(src, ns_root) || !k.cgroups.is_within(dst, ns_root) {
        return Err(Errno::ENOENT);
    }
    let dst_cg = k.cgroups.get(dst).ok_or(Errno::ENOENT)?;
    if !procs {
        return if src == dst {
            Ok(())
        } else {
            Err(Errno::EOPNOTSUPP)
        };
    }
    if dst_cg.parent.is_some() && dst_cg.subtree_control != 0 {
        return Err(Errno::EBUSY);
    }
    g.borrow_mut().cgroup = dst;
    // Clamp the migrated process's affinity to the destination cgroup's effective cpuset.
    apply_cpuset_group(k, &g.borrow());
    // Migrating into a frozen cgroup stops the process, and migrating out lets it run on (Linux's
    // cgroup_freezer_migrate_task)
    refreeze(k, &g);
    task_changed(k, src);
    task_changed(k, dst);
    Ok(())
}

/// Writes `cgroup.subtree_control` (Linux's `cgroup_subtree_control_write`): `+name` and `-name`,
/// separated by whitespace. An unknown controller or a missing `+`/`-` is EINVAL; enabling one not
/// in `cgroup.controllers` is ENOENT; controllers cannot be enabled in a non-root cgroup that has
/// processes (EBUSY); one a child cgroup still has enabled cannot be disabled (EBUSY).
fn subtree_control(k: &mut Kernel, id: u64, text: &str, owner: (u32, u32)) -> Result<(), Errno> {
    let (mut enable, mut disable) = (0u32, 0u32);
    for tok in text.split_ascii_whitespace() {
        let (on, name) = match tok.split_at_checked(1) {
            Some(("+", name)) => (true, name),
            Some(("-", name)) => (false, name),
            _ => return Err(Errno::EINVAL),
        };
        let i = CONTROLLERS
            .iter()
            .position(|(n, _)| *n == name)
            .ok_or(Errno::EINVAL)?;
        if on {
            enable |= 1 << i;
            disable &= !(1 << i);
        } else {
            disable |= 1 << i;
            enable &= !(1 << i);
        }
    }
    let g = k.cgroups.get(id).ok_or(Errno::ENOENT)?;
    enable &= !g.subtree_control;
    disable &= g.subtree_control;
    if enable == 0 && disable == 0 {
        return Ok(());
    }
    if enable & !k.cgroups.controllers(id) != 0 {
        return Err(Errno::ENOENT);
    }
    let has_procs = members(k).any(|(_, c)| c == id);
    if enable != 0 && g.parent.is_some() && has_procs {
        return Err(Errno::EBUSY);
    }
    let children: Vec<u64> = g.children.values().copied().collect();
    if children.iter().any(|c| {
        k.cgroups
            .get(*c)
            .is_some_and(|c| c.subtree_control & disable != 0)
    }) {
        return Err(Errno::EBUSY);
    }
    let g = k.cgroups.map.get_mut(&id).unwrap();
    g.subtree_control = (g.subtree_control | enable) & !disable;
    for (ctl, generation) in g.generations.iter_mut().enumerate() {
        if enable & (1 << ctl) != 0 {
            *generation += 1;
        }
    }
    let adds_event_files = enable & ((1 << MEMORY) | (1 << PIDS)) != 0;
    for child_id in children {
        let child = k.cgroups.map.get_mut(&child_id).unwrap();
        child.update_controller_files(enable, disable, owner);
        if adds_event_files && k.inotify.borrow().watches(key(child_id, b"")) {
            observe_all(k, child_id);
        }
        if disable == 0 {
            continue;
        }
        // Drop the disabled controllers' state (Linux's css) and retire their observations.
        if disable & (1 << PIDS) != 0 {
            k.cgroups.mark_dirty(child_id, b"pids.events");
        }
        if disable & (1 << MEMORY) != 0 {
            k.cgroups.mark_dirty(child_id, b"memory.events");
            k.cgroups.mark_dirty(child_id, b"memory.events.local");
        }
        let Some(child) = k.cgroups.map.get_mut(&child_id) else {
            continue;
        };
        if disable & 1 << PIDS != 0 {
            child.pids_events = 0;
        }
        if disable & 1 << MEMORY != 0 {
            child.mem_events = Events::default();
            child.mem_events_local = Events::default();
            child.mem_peak.set(0);
            child.mem_high_last.set(0);
        }
        if disable & 1 << CPUSET != 0 {
            apply_cpuset_subtree(k, child_id);
        }
    }
    Ok(())
}

/// `cgroup.kill`: sends SIGKILL to every process in the subtree (Linux's `cgroup_kill`).
fn kill(k: &mut Kernel, id: u64) {
    let victims: Vec<Tid> = members(k)
        .filter(|&(_, c)| k.cgroups.is_within(c, id))
        .map(|(t, _)| t)
        .collect();
    for tgid in victims {
        crate::signal::send_to_group(
            k,
            tgid,
            crate::process::Signal::KILL,
            crate::signal::SigInfo::kernel(),
        );
    }
}

/// Whether process `group` should be frozen according to its cgroup ([`Cgroups::freezing`]): when
/// that changes, wakes its threads so that they stop before returning to the guest, or leave that
/// stop ([`crate::signal::deliver`]).
fn refreeze(k: &Kernel, group: &Rc<RefCell<ThreadGroup>>) {
    let freezing = k.cgroups.freezing(group.borrow().cgroup);
    let mut g = group.borrow_mut();
    if g.frozen == freezing {
        return;
    }
    g.frozen = freezing;
    for t in g.threads.iter().filter_map(|t| k.tasks.get(t)) {
        crate::signal::wake(t);
    }
}

/// Checks the values written to the limit interface files and converts them to the format read
/// back (Linux's page_counter_memparse, cpu_max_write and the like); `old` is the value stored
/// before, if any.
fn parse_value(name: &[u8], word: &str, old: Option<&str>) -> Result<String, Errno> {
    const PAGE: u64 = 4096;
    let int = |s: &str| s.parse::<i64>().map_err(|_| Errno::EINVAL);
    // memparse: suffixes such as K, M, G, T
    let bytes = |s: &str| -> Result<u64, Errno> {
        let (num, shift) = match s.char_indices().last() {
            Some((i, c)) if c.is_ascii_alphabetic() => {
                let shift = match c.to_ascii_lowercase() {
                    'k' => 10,
                    'm' => 20,
                    'g' => 30,
                    't' => 40,
                    'p' => 50,
                    'e' => 60,
                    _ => return Err(Errno::EINVAL),
                };
                (&s[..i], shift)
            }
            _ => (s, 0),
        };
        let n: u64 = num.parse().map_err(|_| Errno::EINVAL)?;
        Ok(n.saturating_mul(1 << shift))
    };
    let pages = |s: &str| -> Result<String, Errno> {
        if s == "max" {
            return Ok("max".to_owned());
        }
        Ok((bytes(s)? / PAGE * PAGE).to_string())
    };
    Ok(match name {
        b"memory.max" | b"memory.high" | b"memory.swap.max" | b"memory.swap.high" => pages(word)?,
        b"memory.low" | b"memory.min" => {
            if word == "max" {
                "max".to_owned()
            } else {
                (bytes(word)? / PAGE * PAGE).to_string()
            }
        }
        b"memory.oom.group" | b"cpu.idle" => match int(word)? {
            v @ (0 | 1) => v.to_string(),
            _ => return Err(Errno::EINVAL),
        },
        b"pids.max" if word == "max" => "max".to_owned(),
        b"pids.max" => match int(word)? {
            // PID_MAX_LIMIT (2^22) is accepted too (Linux's PIDS_MAX is that plus 1)
            v if (0..=1 << 22).contains(&v) => v.to_string(),
            _ => return Err(Errno::EINVAL),
        },
        // Negative numbers are ERANGE (Linux's cgroup_max_depth_write)
        b"cgroup.max.depth" | b"cgroup.max.descendants" if word == "max" => "max".to_owned(),
        b"cgroup.max.depth" | b"cgroup.max.descendants" => match word.parse::<i32>() {
            Ok(v) if v >= 0 => v.to_string(),
            Ok(_) => return Err(Errno::ERANGE),
            Err(_) => return Err(Errno::EINVAL),
        },
        b"cpu.weight" => match int(word)? {
            v @ 1..=10000 => v.to_string(),
            _ => return Err(Errno::ERANGE),
        },
        b"cpu.weight.nice" => match int(word)? {
            v @ -20..=19 => v.to_string(),
            _ => return Err(Errno::ERANGE),
        },
        b"cpu.max.burst" => match int(word)? {
            v if v >= 0 => v.to_string(),
            _ => return Err(Errno::EINVAL),
        },
        // `$MAX $PERIOD`: MAX is max or a number of microseconds; an omitted PERIOD keeps the
        // current one (cpu_max_write starts from tg_get_cfs_period), 100000 by default
        b"cpu.max" => {
            let mut it = word.split_ascii_whitespace();
            let quota = it.next().ok_or(Errno::EINVAL)?;
            let period = match it.next() {
                Some(p) => int(p)?,
                None => old
                    .and_then(|o| o.split_ascii_whitespace().nth(1))
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(100_000),
            };
            if it.next().is_some() || !(1000..=1_000_000).contains(&period) {
                return Err(Errno::EINVAL);
            }
            match quota {
                "max" => format!("max {period}"),
                q => match int(q)? {
                    q if q >= 1000 => format!("{q} {period}"),
                    _ => return Err(Errno::EINVAL),
                },
            }
        }
        b"cpuset.cpus" | b"cpuset.mems" => {
            let limit = if name == b"cpuset.cpus" {
                appine_hal::host_cpus().len() as i64
            } else {
                1
            };
            for part in word.split(',').filter(|p| !p.is_empty()) {
                let (a, b) = part.split_once('-').unwrap_or((part, part));
                let (a, b) = (int(a)?, int(b)?);
                if a > b || a < 0 || b >= limit {
                    return Err(Errno::EINVAL);
                }
            }
            word.to_owned()
        }
        b"cpuset.cpus.partition" => match word {
            "member" => "member".to_owned(),
            "root" | "isolated" => return Err(Errno::EINVAL),
            _ => return Err(Errno::EINVAL),
        },
        // Interfaces that cannot be written (cgroup.controllers, memory.current and the like)
        _ => return Err(Errno::EINVAL),
    })
}

// ---- Fork ----

/// Whether a child forked from cgroup `src` may be placed into cgroup `dst` by a caller with
/// credentials `cred` (clone3's `CLONE_INTO_CGROUP`, Linux's `cgroup_css_set_fork`): an already
/// removed one is ENODEV; the caller must be allowed to write the `cgroup.procs` of `dst` and of
/// the nearest cgroup above both (EACCES), as a migration through `cgroup.procs` would need; both
/// must be under the root `ns_root` of the caller's cgroup namespace (ENOENT); one with
/// controllers enabled (other than the root) cannot have processes (EBUSY).
pub(crate) fn may_enter(
    k: &Kernel,
    cred: &Cred,
    (src, dst): (u64, u64),
    ns_root: u64,
) -> Result<(), Errno> {
    let g = k.cgroups.get(dst).ok_or(Errno::ENODEV)?;
    may_write_procs(k, cred, dst)?;
    may_write_procs(k, cred, k.cgroups.common_ancestor(src, dst))?;
    if !k.cgroups.is_within(src, ns_root) || !k.cgroups.is_within(dst, ns_root) {
        return Err(Errno::ENOENT);
    }
    if g.parent.is_some() && g.subtree_control != 0 {
        return Err(Errno::EBUSY);
    }
    Ok(())
}

/// Whether `cred` may write cgroup `id`'s `cgroup.procs`, judged by the file's mode and owner as
/// an open for writing would be (Linux's `cgroup_may_write`).
fn may_write_procs(k: &Kernel, cred: &Cred, id: u64) -> Result<(), Errno> {
    let g = k.cgroups.get(id).ok_or(Errno::ENOENT)?;
    let st = g.attrs(b"cgroup.procs")?;
    cred.permission(&st, crate::cred::MAY_WRITE)
}

/// Before a forked task is placed into cgroup `dst` (Linux's `pids_can_fork`): the task count of
/// it and of every ancestor with pids enabled must not exceed `pids.max`; exceeding it is EAGAIN,
/// recorded in the `pids.events` of the nearest cgroup with pids enabled, with a kernel log
/// message the first time.
pub(crate) fn pids_charge(k: &mut Kernel, dst: u64) -> Result<(), Errno> {
    let enabled = |c: u64| k.cgroups.controllers(c) & 1 << PIDS != 0;
    let Some(css) = k.cgroups.ancestors(dst).find(|&c| enabled(c)) else {
        return Ok(());
    };
    let over = k.cgroups.ancestors(css).filter(|&c| enabled(c)).any(|c| {
        let limit = k.cgroups.map[&c].values.get(&b"pids.max"[..]);
        limit
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|max| pids_current(k, c) + 1 > max)
    });
    if !over {
        return Ok(());
    }
    let path = k.cgroups.path(css, ROOT);
    let g = k.cgroups.map.get_mut(&css).unwrap();
    g.pids_events += 1;
    if g.pids_events == 1 {
        crate::klog::printk(
            &k.klog,
            crate::klog::level::INFO,
            format_args!("cgroup: fork rejected by pids controller in {path}"),
        );
    }
    record_change(k, css, b"pids.events");
    Err(Errno::EAGAIN)
}

// ---- Cpuset ----

/// Online CPU bitmask matching the guest's host CPUs (1..=64).
pub(crate) fn online_cpus() -> u64 {
    let cpus = appine_hal::host_cpus().len().clamp(1, 64);
    if cpus == 64 {
        u64::MAX
    } else {
        (1u64 << cpus) - 1
    }
}

/// Parses a validated Linux CPU range list (e.g. `"0,2-3"`) into a 64-bit mask.
fn parse_cpu_mask(spec: &str) -> u64 {
    let mut mask = 0u64;
    for part in spec.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) else {
            continue;
        };
        if a > b || a >= 64 {
            continue;
        }
        for cpu in a..=b.min(63) {
            mask |= 1u64 << cpu;
        }
    }
    mask
}

/// Formats a non-zero CPU bitmask in canonical Linux range-list form (e.g. `"0-3"`, `"0,2-3"`).
fn format_cpu_list(mask: u64) -> String {
    let mut out = String::new();
    let mut i = 0u32;
    while i < 64 {
        if (mask >> i) & 1 == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i + 1 < 64 && (mask >> (i + 1)) & 1 != 0 {
            i += 1;
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == i {
            write!(out, "{start}").unwrap();
        } else {
            write!(out, "{start}-{i}").unwrap();
        }
        i += 1;
    }
    out
}

/// Effective `cpuset.cpus` mask for cgroup `id` (Linux 6.1's `compute_effective_cpumask`):
/// starts from online CPUs at the root and intersects with each descendant's configured
/// `cpuset.cpus` where the `cpuset` controller is enabled, falling back to the parent's effective
/// mask whenever a child's `cpuset.cpus` is empty or disjoint from its parent.
pub(crate) fn effective_cpus(k: &Kernel, id: u64) -> u64 {
    effective_cpus_within(k, id, online_cpus())
}

fn effective_cpus_within(k: &Kernel, id: u64, online: u64) -> u64 {
    let mut chain: Vec<u64> = k.cgroups.ancestors(id).collect();
    chain.reverse();
    let mut eff = online;
    for c in chain {
        if c == ROOT || k.cgroups.controllers(c) & (1 << CPUSET) == 0 {
            continue;
        }
        if let Some(spec) = k
            .cgroups
            .get(c)
            .and_then(|g| g.values.get(&b"cpuset.cpus"[..]))
        {
            let req = parse_cpu_mask(spec) & eff;
            if req != 0 {
                eff = req;
            }
        }
    }
    eff
}

/// Clamps thread affinity `mask` to cgroup `cgroup`'s effective `cpuset.cpus`, falling back to
/// the effective cpuset when the intersection is empty (matching Linux `set_cpus_allowed_ptr`).
pub(crate) fn clamp_affinity(k: &Kernel, cgroup: u64, mask: u64) -> u64 {
    let eff = effective_cpus(k, cgroup);
    let clamped = mask & eff;
    if clamped != 0 { clamped } else { eff }
}

/// Applies the effective `cpuset.cpus` mask to every live thread in the group.
fn apply_cpuset_group(k: &Kernel, g: &ThreadGroup) {
    let cg = g.cgroup;
    for tid in &g.threads {
        if let Some(t) = k.tasks.get(tid) {
            let clamped = clamp_affinity(k, cg, t.affinity.get());
            t.affinity.set(clamped);
            if t.host_tid.get() != 0 {
                appine_hal::set_thread_affinity(t.host_tid.get(), clamped);
            }
        }
    }
}

/// Re-clamps affinity of every live process in cgroup `id`'s subtree after a `cpuset.cpus` change
/// or `cpuset` controller disable.
fn apply_cpuset_subtree(k: &Kernel, id: u64) {
    for (&tgid, group) in &k.groups {
        if tgid == INIT {
            continue;
        }
        let g = group.borrow();
        if k.cgroups.is_within(g.cgroup, id) {
            apply_cpuset_group(k, &g);
        }
    }
}

// ---- OOM killer ----

/// The cgroups with `memory.max` set (and the memory controller enabled) and their limits
/// (bytes). The root's limit is the OOM killer's and is not included here.
pub(crate) fn memory_limits(k: &Kernel) -> Vec<(u64, u64)> {
    k.cgroups
        .map
        .iter()
        .filter(|&(&id, _)| id != ROOT && k.cgroups.controllers(id) & 1 << MEMORY != 0)
        .filter_map(|(&id, g)| Some((id, g.values.get(&b"memory.max"[..])?.parse().ok()?)))
        .collect()
}

/// The cgroups with numeric `memory.high` set (and the memory controller enabled) and their
/// thresholds (bytes).
pub(crate) fn memory_high_limits(k: &Kernel) -> Vec<(u64, u64)> {
    k.cgroups
        .map
        .iter()
        .filter(|&(&id, _)| id != ROOT && k.cgroups.controllers(id) & 1 << MEMORY != 0)
        .filter_map(|(&id, g)| Some((id, g.values.get(&b"memory.high"[..])?.parse().ok()?)))
        .collect()
}

/// Tracks whether cgroup `id` crossed above `memory.high` (or grew further while above it).
/// Returns `true` when a `high` event and reclaim pass should be triggered, and resets state once
/// usage returns at or below `high`.
pub(crate) fn note_memory_high_state(k: &Kernel, id: u64, used: u64, high: u64) -> bool {
    let Some(g) = k.cgroups.get(id) else {
        return false;
    };
    if used <= high {
        g.mem_high_last.set(0);
        false
    } else if used > g.mem_high_last.get() {
        g.mem_high_last.set(used);
        true
    } else {
        false
    }
}

/// Measures cgroup `id`'s memory usage (bytes), recording the peak on the way.
pub(crate) fn measure_memory(k: &Kernel, id: u64) -> u64 {
    let used = subtree_rss(k, id);
    if let Some(g) = k.cgroups.get(id) {
        g.mem_peak.set(g.mem_peak.get().max(used));
    }
    used
}

/// Records a memory event (Linux's `memcg_memory_event`): in `id`'s own `memory.events.local`
/// and in the `memory.events` of it and its ancestors.
pub(crate) fn memory_event(k: &mut Kernel, id: u64, f: impl Fn(&mut Events)) {
    let chain: Vec<u64> = k.cgroups.ancestors(id).collect();
    for c in chain {
        if let Some(g) = k.cgroups.map.get_mut(&c) {
            f(&mut g.mem_events);
            if c == id {
                f(&mut g.mem_events_local);
            }
        }
        if c == id {
            record_change(k, c, b"memory.events.local");
        }
        record_change(k, c, b"memory.events");
    }
}

/// The topmost cgroup with `memory.oom.group` set between process `victim`'s cgroup and the OOM
/// domain `domain` (Linux's `mem_cgroup_get_oom_group`): the processes in it are killed together.
pub(crate) fn oom_group(k: &Kernel, victim: u64, domain: u64) -> Option<u64> {
    if !k.cgroups.is_within(victim, domain) {
        return None;
    }
    let mut group = None;
    for c in k.cgroups.ancestors(victim) {
        let set = k.cgroups.map[&c].values.get(&b"memory.oom.group"[..]);
        if set.is_some_and(|v| v == "1") {
            group = Some(c);
        }
        if c == domain {
            break;
        }
    }
    group
}

// ---- Device programs ----

/// Whether programs may be attached to cgroup `id` (Linux's `hierarchy_allows_attach`): going
/// up, the first ancestor with programs attached must have attached them with `ALLOW_MULTI` or
/// `ALLOW_OVERRIDE`.
pub(crate) fn hierarchy_allows_attach(k: &Kernel, id: u64) -> bool {
    for c in k.cgroups.ancestors(id).skip(1) {
        let Some(g) = k.cgroups.get(c) else {
            continue;
        };
        if g.device_flags & crate::bpf::ALLOW_MULTI != 0 {
            return true;
        }
        if !g.device_progs.is_empty() {
            return g.device_flags & crate::bpf::ALLOW_OVERRIDE != 0;
        }
    }
    true
}

/// The programs to run when a process in cgroup `id` opens a device (Linux's
/// `compute_effective_progs`): going up from the cgroup itself, its own programs all count; once
/// there are some, an ancestor's count only when it attached them with `BPF_F_ALLOW_MULTI`.
pub(crate) fn effective_device_progs(k: &Kernel, id: u64) -> Vec<Rc<crate::bpf::Prog>> {
    let mut progs: Vec<Rc<crate::bpf::Prog>> = Vec::new();
    for c in k.cgroups.ancestors(id) {
        let Some(g) = k.cgroups.get(c) else {
            continue;
        };
        if !progs.is_empty() && g.device_flags & crate::bpf::ALLOW_MULTI == 0 {
            continue;
        }
        progs.extend(g.device_progs.iter().cloned());
    }
    progs
}

// ---- Members ----

/// The cgroup of process `tgid`.
fn group_cgroup(k: &Kernel, tgid: Tid) -> Option<u64> {
    k.groups.get(&tgid).map(|g| g.borrow().cgroup)
}

/// Cgroup `id` or one below it has live processes (`populated` in `cgroup.events`).
fn populated(k: &Kernel, id: u64) -> bool {
    members(k).any(|(_, c)| k.cgroups.is_within(c, id))
}

/// The resident memory of the processes in cgroup `id`'s subtree (bytes): a child cgroup's
/// `memory.current`. An address space several processes use (a vfork child and its parent,
/// `CLONE_VM`) counts once, and so does memory several address spaces share
/// ([`crate::mm::Usage`]: shared mappings, file pages, pages lent after fork), as Linux charges
/// each page once.
fn subtree_rss(k: &Kernel, id: u64) -> u64 {
    let mut usage = crate::mm::Usage::default();
    let mut seen = std::collections::HashSet::new();
    for (tgid, _) in members(k).filter(|&(_, c)| k.cgroups.is_within(c, id)) {
        let Some(g) = k.groups.get(&tgid) else {
            continue;
        };
        let g = g.borrow();
        let Some(task) = g.threads.first().and_then(|t| k.tasks.get(t)) else {
            continue;
        };
        let mm = task.res.borrow().mm.clone();
        if seen.insert(std::rc::Rc::as_ptr(&mm)) {
            usage.add(&mm.borrow());
        }
    }
    usage.pages() * 4096
}

/// Allocated soft-MMU page-table bytes across unique address spaces in cgroup `id`'s subtree.
fn subtree_pgtables(k: &Kernel, id: u64) -> u64 {
    let mut total = 0u64;
    let mut seen = std::collections::HashSet::new();
    for (tgid, _) in members(k).filter(|&(_, c)| k.cgroups.is_within(c, id)) {
        let Some(g) = k.groups.get(&tgid) else {
            continue;
        };
        let g = g.borrow();
        let Some(task) = g.threads.first().and_then(|t| k.tasks.get(t)) else {
            continue;
        };
        let mm = task.res.borrow().mm.clone();
        if seen.insert(std::rc::Rc::as_ptr(&mm)) {
            total = total.saturating_add(mm.borrow().pgtables_bytes());
        }
    }
    total
}

/// The number of tasks in cgroup `id`'s subtree (`pids.current`): as on Linux, tasks count until
/// they are reaped: a process's live threads, plus 1 when its main thread has exited (zombie
/// processes, processes whose main thread exited first).
fn pids_current(k: &Kernel, id: u64) -> usize {
    k.groups
        .iter()
        .filter(|&(&tgid, _)| tgid != INIT)
        .map(|(_, g)| g.borrow())
        .filter(|g| k.cgroups.is_within(g.cgroup, id))
        .map(|g| g.threads.len() + !g.threads.contains(&g.tgid) as usize)
        .sum()
}

/// The cgroups of processes still alive (with threads).
fn members(k: &Kernel) -> impl Iterator<Item = (Tid, u64)> + '_ {
    k.groups.iter().filter_map(|(&tgid, g)| {
        let g = g.borrow();
        (tgid != INIT && !g.threads.is_empty()).then_some((tgid, g.cgroup))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_notifications_follow_the_file_and_its_lifetime() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let child = k.cgroups.mkdir(ROOT, b"t", &Cred::root(), 0o755).unwrap();
        subtree_control(&mut k, ROOT, "+memory +pids", (0, 0)).unwrap();
        let root_events = observe(&mut k, ROOT, b"memory.events").unwrap();
        let root_local = observe(&mut k, ROOT, b"memory.events.local").unwrap();
        let local = observe(&mut k, child, b"memory.events.local").unwrap();
        let pids = observe(&mut k, child, b"pids.events").unwrap();

        memory_event(&mut k, child, |e| e.oom += 1);
        memory_event(&mut k, child, |e| e.oom += 1);
        notify_changes(&mut k);
        assert_eq!(
            (root_events.get(), root_local.get(), local.get()),
            (2, 1, 2)
        );
        assert_eq!(pids.get(), 1);

        k.cgroups
            .map
            .get_mut(&child)
            .unwrap()
            .values
            .insert(b"pids.max", "0".into());
        assert_eq!(pids_charge(&mut k, child), Err(Errno::EAGAIN));
        notify_changes(&mut k);
        assert_eq!(pids.get(), 2);

        subtree_control(&mut k, ROOT, "-memory", (0, 0)).unwrap();
        notify_changes(&mut k);
        subtree_control(&mut k, ROOT, "+memory", (0, 0)).unwrap();
        let reopened = observe(&mut k, child, b"memory.events.local").unwrap();
        memory_event(&mut k, child, |e| e.max += 1);
        notify_changes(&mut k);
        assert_eq!((local.get(), reopened.get(), root_events.get()), (2, 2, 3));
    }

    /// Creating child cgroups: duplicate names (including this cgroup's interface files) are
    /// EEXIST, newlines EINVAL; a child cgroup's files follow its parent's subtree_control; paths
    /// are relative to the namespace root, starting with `..` when not below it.
    #[test]
    fn tree_and_paths() {
        let mut c = Cgroups::default();
        let cred = Cred::root();
        let t = c.mkdir(ROOT, b"t", &cred, 0o755).unwrap();
        assert_eq!(c.mkdir(ROOT, b"t", &cred, 0o755), Err(Errno::EEXIST));
        assert_eq!(
            c.mkdir(ROOT, b"cgroup.procs", &cred, 0o755),
            Err(Errno::EEXIST)
        );
        assert_eq!(c.mkdir(ROOT, b"a\nb", &cred, 0o755), Err(Errno::EINVAL));
        // t has no memory enabled, so a child cgroup named memory.max can be created
        assert!(!c.has_file(t, b"memory.max"));
        assert!(c.mkdir(t, b"memory.max", &cred, 0o755).is_ok());
        c.map.get_mut(&ROOT).unwrap().subtree_control = 1 << 3;
        assert!(c.has_file(t, b"memory.max"));
        assert!(!c.has_file(t, b"pids.max"));
        let a = c.mkdir(t, b"a", &cred, 0o755).unwrap();
        let b = c.mkdir(t, b"b", &cred, 0o755).unwrap();
        assert_eq!(c.path(a, ROOT), "/t/a");
        assert_eq!(c.path(a, a), "/");
        assert_eq!(c.path(b, a), "/../b");
        assert_eq!(c.path(ROOT, a), "/../..");
        assert!(c.is_within(a, t) && !c.is_within(t, a));
        assert_eq!(c.descendants(ROOT), 4);
    }

    /// An ancestor's cgroup.max.depth and cgroup.max.descendants limit new cgroups (EAGAIN).
    #[test]
    fn depth_and_descendant_limits() {
        let mut c = Cgroups::default();
        let cred = Cred::root();
        let t = c.mkdir(ROOT, b"t", &cred, 0o755).unwrap();
        c.map
            .get_mut(&t)
            .unwrap()
            .values
            .insert(b"cgroup.max.depth", "1".to_owned());
        let a = c.mkdir(t, b"a", &cred, 0o755).unwrap();
        assert_eq!(c.mkdir(a, b"x", &cred, 0o755), Err(Errno::EAGAIN));
        let g = c.map.get_mut(&t).unwrap();
        g.values.remove(&b"cgroup.max.depth"[..]);
        g.values.insert(b"cgroup.max.descendants", "2".to_owned());
        assert!(c.mkdir(a, b"x", &cred, 0o755).is_ok());
        assert_eq!(c.mkdir(t, b"b", &cred, 0o755), Err(Errno::EAGAIN));
    }

    /// Interface file values are checked and converted in Linux's format.
    #[test]
    fn values() {
        assert_eq!(parse_value(b"memory.max", "1M", None).unwrap(), "1048576");
        assert_eq!(parse_value(b"memory.max", "5000", None).unwrap(), "4096");
        assert_eq!(parse_value(b"memory.max", "max", None).unwrap(), "max");
        assert_eq!(parse_value(b"memory.max", "1x", None), Err(Errno::EINVAL));
        assert_eq!(parse_value(b"pids.max", "-1", None), Err(Errno::EINVAL));
        assert_eq!(
            parse_value(b"pids.max", "4194304", None).unwrap(),
            "4194304"
        );
        assert_eq!(
            parse_value(b"pids.max", "4194305", None),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            parse_value(b"cgroup.max.depth", "-1", None),
            Err(Errno::ERANGE)
        );
        assert_eq!(parse_value(b"cpu.weight", "0", None), Err(Errno::ERANGE));
        assert_eq!(
            parse_value(b"cpu.max", "50000", None).unwrap(),
            "50000 100000"
        );
        assert_eq!(
            parse_value(b"cpu.max", "max 20000", None).unwrap(),
            "max 20000"
        );
        assert_eq!(parse_value(b"cpu.max", "500", None), Err(Errno::EINVAL));
        // A quota alone keeps the period stored before
        assert_eq!(
            parse_value(b"cpu.max", "50000", Some("max 20000")).unwrap(),
            "50000 20000"
        );
        assert_eq!(
            parse_value(b"cpu.max", "max", Some("30000 200000")).unwrap(),
            "max 200000"
        );
        assert_eq!(
            parse_value(b"memory.current", "1", None),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn disabled_controller_and_removed_cgroup_return_enodev() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let cred = Cred::root();
        let pid_ns = crate::pidns::PidNs::init();
        let writer = Writer {
            tid: 0,
            pid_ns: &pid_ns,
            ns_root: ROOT,
            opener: &cred,
            cred: &cred,
        };
        let child = k.cgroups.mkdir(ROOT, b"c", &cred, 0o755).unwrap();
        subtree_control(&mut k, ROOT, "+memory +pids", (0, 0)).unwrap();
        assert!(file(&k, child, b"memory.max", &|t| t).is_ok());
        assert_eq!(
            file(&k, child, b"cgroup.kill", &|t| t),
            Err(Errno::EINVAL),
            "write-only cgroup file stays EINVAL"
        );

        // Disabling a controller rejects writes and reads on held fds with ENODEV and stores nothing.
        subtree_control(&mut k, ROOT, "-memory", (0, 0)).unwrap();
        assert_eq!(
            write(&mut k, &writer, (child, b"memory.max"), b"4096\n"),
            Err(Errno::ENODEV)
        );
        assert_eq!(file(&k, child, b"memory.max", &|t| t), Err(Errno::ENODEV));
        assert!(
            !k.cgroups
                .get(child)
                .unwrap()
                .values
                .contains_key(&b"memory.max"[..])
        );

        // Removing the cgroup causes reads/writes on existing files to return ENODEV.
        rmdir(&mut k, child).unwrap();
        assert_eq!(file(&k, child, b"pids.max", &|t| t), Err(Errno::ENODEV));
        assert_eq!(
            write(&mut k, &writer, (child, b"pids.max"), b"10\n"),
            Err(Errno::ENODEV)
        );
    }

    fn add_test_task(
        k: &mut Kernel,
        tgid: i32,
        cgroup: u64,
    ) -> (
        Rc<RefCell<ThreadGroup>>,
        Rc<crate::task::Task>,
        appine_engine::Cpu,
    ) {
        use crate::fd::FdTable;
        use crate::mm::Mm;
        use crate::nsproxy::NsProxy;
        use crate::signal::{AltStack, SigHandlers};
        use crate::task::{FsContext, Task, TaskState};
        use crate::vfs::{INIT_MNT_NS, MntNs, Node};

        let mm = Mm::new().into_shared();
        let sighand = Rc::new(RefCell::new(SigHandlers::default()));
        let mut tg = ThreadGroup::new(tgid, INIT, sighand);
        tg.cgroup = cgroup;
        tg.threads.push(tgid);
        let group = Rc::new(RefCell::new(tg));
        let cpu = unsafe { appine_engine::Cpu::new(mm.borrow().mmu()) };
        let state = TaskState {
            mm,
            fds: Rc::new(RefCell::new(FdTable::new())),
            fs: Rc::new(RefCell::new(FsContext {
                root: Node::ROOT,
                cwd: Node::ROOT,
                umask: 0o022,
                mnt_ns: Rc::new(MntNs {
                    id: INIT_MNT_NS,
                    owner: crate::cred::UserNs::init(),
                    anon: false,
                }),
            })),
            group: group.clone(),
            vfs: None,
            altstack: AltStack::default(),
            clear_child_tid: 0,
            vfork_done: None,
            restart: None,
            fast_sleep: None,
            sem_undo: Rc::new(crate::ipc::SemUndo::new()),
        };
        let task = Task::new(
            tgid,
            tgid,
            &cpu,
            state,
            NsProxy::init(),
            0,
            *b"cg-test\0\0\0\0\0\0\0\0\0",
        )
        .unwrap();
        k.groups.insert(tgid, group.clone());
        k.tasks.insert(tgid, task.clone());
        (group, task, cpu)
    }

    #[test]
    fn transient_populated_and_frozen_transitions_are_not_missed() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let cred = Cred::root();
        let pid_ns = crate::pidns::PidNs::init();
        let writer = Writer {
            tid: 0,
            pid_ns: &pid_ns,
            ns_root: ROOT,
            opener: &cred,
            cred: &cred,
        };
        let cg = k.cgroups.mkdir(ROOT, b"transient", &cred, 0o755).unwrap();
        let events = observe(&mut k, cg, b"cgroup.events").unwrap();
        assert_eq!(events.get(), 1);

        // 1. Transient populated 0 -> 1 -> 0 before notify_changes must still trigger a notification.
        let (group, _task, _cpu) = add_test_task(&mut k, 100, cg);
        task_changed(&k, cg);
        group.borrow_mut().threads.clear();
        k.tasks.remove(&100);
        task_changed(&k, cg);
        notify_changes(&mut k);
        assert_eq!(
            events.get(),
            2,
            "transient populated 0 -> 1 -> 0 must not be lost before checkpoint"
        );

        // 2. Transient frozen 0 -> 1 -> 0 on an empty cgroup before notify_changes must still notify.
        write(&mut k, &writer, (cg, b"cgroup.freeze"), b"1\n").unwrap();
        write(&mut k, &writer, (cg, b"cgroup.freeze"), b"0\n").unwrap();
        notify_changes(&mut k);
        assert_eq!(
            events.get(),
            3,
            "transient frozen 0 -> 1 -> 0 must not be lost before checkpoint"
        );
    }

    #[test]
    fn cpuset_effective_inheritance_and_task_clamping() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let cred = Cred::root();
        let parent = k.cgroups.mkdir(ROOT, b"p", &cred, 0o755).unwrap();
        let child = k.cgroups.mkdir(parent, b"c", &cred, 0o755).unwrap();
        subtree_control(&mut k, ROOT, "+cpuset", (0, 0)).unwrap();
        subtree_control(&mut k, parent, "+cpuset", (0, 0)).unwrap();

        // Test hierarchical intersection and fallback against a synthetic 4-CPU online mask.
        let four_cpus = 0b1111u64;
        assert_eq!(effective_cpus_within(&k, parent, four_cpus), 0b1111);
        assert_eq!(format_cpu_list(0b1111), "0-3");
        assert_eq!(format_cpu_list(0b1101), "0,2-3");

        k.cgroups
            .map
            .get_mut(&parent)
            .unwrap()
            .values
            .insert(b"cpuset.cpus", "1-3".to_owned());
        assert_eq!(effective_cpus_within(&k, parent, four_cpus), 0b1110);
        // Empty child inherits parent effective mask.
        assert_eq!(effective_cpus_within(&k, child, four_cpus), 0b1110);

        // Child intersection narrows effective mask.
        k.cgroups
            .map
            .get_mut(&child)
            .unwrap()
            .values
            .insert(b"cpuset.cpus", "0,2".to_owned());
        assert_eq!(effective_cpus_within(&k, child, four_cpus), 0b0100);

        // Disjoint child falls back to parent effective mask (never empty).
        k.cgroups
            .map
            .get_mut(&child)
            .unwrap()
            .values
            .insert(b"cpuset.cpus", "0".to_owned());
        assert_eq!(effective_cpus_within(&k, child, four_cpus), 0b1110);

        // Real write on CPU 0 (valid on every host >= 1 CPU) updates cpuset.cpus.effective and
        // clamps live tasks in the subtree.
        let pid_ns = crate::pidns::PidNs::init();
        let writer = Writer {
            tid: 0,
            pid_ns: &pid_ns,
            ns_root: ROOT,
            opener: &cred,
            cred: &cred,
        };
        let (_g, task, _cpu) = add_test_task(&mut k, 200, child);
        task.affinity.set(online_cpus());
        write(&mut k, &writer, (parent, b"cpuset.cpus"), b"0\n").unwrap();
        assert_eq!(
            file(&k, parent, b"cpuset.cpus.effective", &|t| t).unwrap(),
            "0\n"
        );
        assert_eq!(
            file(&k, child, b"cpuset.cpus.effective", &|t| t).unwrap(),
            "0\n"
        );
        assert_eq!(task.affinity.get(), 1);
    }

    #[test]
    fn memory_high_write_records_event_without_killing() {
        let shared = crate::kernel::Shared::new(Kernel::new(crate::process::Tier::Interpreter));
        let mut k = shared.lock();
        let cred = Cred::root();
        let pid_ns = crate::pidns::PidNs::init();
        let writer = Writer {
            tid: 0,
            pid_ns: &pid_ns,
            ns_root: ROOT,
            opener: &cred,
            cred: &cred,
        };
        let cg = k.cgroups.mkdir(ROOT, b"mh", &cred, 0o755).unwrap();
        subtree_control(&mut k, ROOT, "+memory", (0, 0)).unwrap();

        let (group, task, _cpu) = add_test_task(&mut k, 210, cg);
        let mm = task.res.borrow().mm.clone();
        let addr = mm
            .borrow_mut()
            .mmap(
                0,
                32 * 4096,
                appine_engine::prot::READ | appine_engine::prot::WRITE,
                crate::mm::flags::MAP_PRIVATE | crate::mm::flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.borrow_mut()
            .write_kernel(addr, &vec![0x7au8; 32 * 4096])
            .unwrap();

        write(&mut k, &writer, (cg, b"memory.high"), b"16384\n").unwrap();
        assert!(group.borrow().exiting.is_none());
        let ev = file(&k, cg, b"memory.events", &|t| t).unwrap();
        assert!(ev.contains("high 1\n"), "expected high 1 in:\n{ev}");
        let local = file(&k, cg, b"memory.events.local", &|t| t).unwrap();
        assert!(local.contains("high 1\n"), "expected high 1 in:\n{local}");

        // Removing the threshold re-arms the event even if usage stays the same.
        write(&mut k, &writer, (cg, b"memory.high"), b"max").unwrap();
        write(&mut k, &writer, (cg, b"memory.high"), b"0").unwrap();
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events_local.high, 2);
    }
}
