//! Synthetic filesystems (the kernel/procfs map; `/proc/sys` sysctls are the kernel/sysctl map and
//! sysfs is the kernel/sysfs map): procfs, devpts, sysfs (CPU topology, network
//! interfaces) and cgroup2, mounted at boot on `/proc`, `/dev/pts`, `/sys` and `/sys/fs/cgroup`.
//!
//! Nodes are [`PseudoNode`]s, and the directory structure implements [`Pseudo`] through [`View`]
//! (a read-only view of kernel state taken while holding the BKL). A procfs file generates its
//! complete contents when opened ([`content`]), and later reads all work on that snapshot, with
//! the same effect as a Linux seq_file read in one go.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::ops::Range;
use std::rc::Rc;

use appine_engine::PAGE_SIZE;

use crate::cell::RefCell;
use crate::cred::{Cred, cap};
use crate::errno::Errno;
use crate::fd::{FileKind, OpenFile, oflags};
use crate::ipc;
use crate::kernel::{INIT, Kernel, Tid};
use crate::mm::Region;
use crate::net::{AF_INET, AF_INET6, Table};
use crate::pidns::PidNs;
use crate::process::{Signal, ThreadGroup};
use crate::signal::SigAction;
use crate::syscall::SocketRef;
use crate::task::Task;
use crate::tty::{PTS_MAJOR, Tty};
use crate::vfs::dev::{LOOP_MAJOR, rdev};
use crate::vfs::store::{DirEntry, Ino, Stat, Store, mode};
use crate::vfs::{Fs, MountId, Node, Pseudo, Vfs};

/// Global files under `/proc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Global {
    Cpuinfo,
    Meminfo,
    Stat,
    Uptime,
    Loadavg,
    Version,
    Filesystems,
    Cmdline,
    /// A symlink to `self/mounts`.
    Mounts,
    /// A symlink to `self/net`.
    Net,
    /// cgroup controllers ([`crate::cgroup`]).
    Cgroups,
    /// Memory counters, the host's when it can be read.
    Vmstat,
    /// Swap areas: the host's when it can be read, else none.
    Swaps,
    /// File locks and leases ([`crate::locks::proc_locks`]).
    Locks,
    /// syslog reading ([`crate::klog`]): the contents are not generated at open but taken at read
    /// time.
    Kmsg,
}

const GLOBALS: [(&[u8], Global); 15] = [
    (b"cpuinfo", Global::Cpuinfo),
    (b"meminfo", Global::Meminfo),
    (b"stat", Global::Stat),
    (b"uptime", Global::Uptime),
    (b"loadavg", Global::Loadavg),
    (b"version", Global::Version),
    (b"filesystems", Global::Filesystems),
    (b"cmdline", Global::Cmdline),
    (b"mounts", Global::Mounts),
    (b"net", Global::Net),
    (b"cgroups", Global::Cgroups),
    (b"kmsg", Global::Kmsg),
    (b"vmstat", Global::Vmstat),
    (b"swaps", Global::Swaps),
    (b"locks", Global::Locks),
];

/// Entries under `/proc/<pid>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Entry {
    Auxv,
    Stat,
    Status,
    Statm,
    Cmdline,
    Comm,
    Environ,
    Limits,
    /// Child processes the thread created (only under `task/<tid>/`, Linux's
    /// `CONFIG_PROC_CHILDREN`).
    Children,
    Maps,
    Mem,
    Smaps,
    SmapsRollup,
    Pagemap,
    Mounts,
    MountInfo,
    Cwd,
    Exe,
    Root,
    Fd,
    FdInfo,
    Task,
    /// Files of the process's network namespace ([`PROC_NET`]).
    Net,
    /// The OOM killer's score ([`crate::oom::proc_score`]).
    OomScore,
    OomScoreAdj,
    CoredumpFilter,
    /// The cgroup it is in ([`crate::cgroup`]).
    Cgroup,
    /// The namespace directory ([`NsKind`]).
    Ns,
    /// The user namespace's ID maps (user_namespaces(7)): `uid_map`, `gid_map`, `projid_map`,
    /// and `setgroups`.
    UidMap,
    GidMap,
    ProjidMap,
    Setgroups,
    /// The time namespace offsets for children ([`crate::nsproxy::TimeNs`]), only under
    /// `/proc/<pid>`.
    TimensOffsets,
    /// The syscall the thread is waiting in ([`crate::task::KernelEntry`]).
    Syscall,
}

/// Namespace kinds (the entries in `/proc/<pid>/ns`); every kind can be created by clone or
/// unshare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NsKind {
    Cgroup,
    Ipc,
    Mnt,
    Net,
    Pid,
    PidForChildren,
    Time,
    TimeForChildren,
    User,
    Uts,
}

impl NsKind {
    /// Sorted by name (the listing of `/proc/<pid>/ns`).
    pub(crate) const ALL: [NsKind; 10] = [
        NsKind::Cgroup,
        NsKind::Ipc,
        NsKind::Mnt,
        NsKind::Net,
        NsKind::Pid,
        NsKind::PidForChildren,
        NsKind::Time,
        NsKind::TimeForChildren,
        NsKind::User,
        NsKind::Uts,
    ];

    /// The name in `/proc/<pid>/ns`.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            NsKind::Cgroup => "cgroup",
            NsKind::Ipc => "ipc",
            NsKind::Mnt => "mnt",
            NsKind::Net => "net",
            NsKind::Pid => "pid",
            NsKind::PidForChildren => "pid_for_children",
            NsKind::Time => "time",
            NsKind::TimeForChildren => "time_for_children",
            NsKind::User => "user",
            NsKind::Uts => "uts",
        }
    }

    /// The type in the link contents (`*_for_children` is the same as its counterpart).
    pub(crate) const fn type_name(self) -> &'static str {
        match self {
            NsKind::PidForChildren => "pid",
            NsKind::TimeForChildren => "time",
            k => k.name(),
        }
    }

    /// setns's `nstype` (`CLONE_NEW*`).
    pub(crate) const fn clone_flag(self) -> u64 {
        match self {
            NsKind::Cgroup => 0x0200_0000,
            NsKind::Ipc => 0x0800_0000,
            NsKind::Mnt => 0x0002_0000,
            NsKind::Net => 0x4000_0000,
            NsKind::Pid | NsKind::PidForChildren => 0x2000_0000,
            NsKind::Time | NsKind::TimeForChildren => 0x80,
            NsKind::User => 0x1000_0000,
            NsKind::Uts => 0x0400_0000,
        }
    }

    /// The id (inode number) of this kind of namespace of thread `task`: for mount namespaces by
    /// its `FsContext`, for user namespaces by its credentials, for pid namespaces by its process
    /// and thread, and for the others by its [`crate::nsproxy::NsProxy`]. None when there is none
    /// (ENOENT).
    pub(crate) fn id_of(self, k: &Kernel, task: &Task) -> Option<u64> {
        let group = k.groups.get(&task.tgid);
        Some(match self {
            NsKind::Mnt => task.res.borrow().fs.borrow().mnt_ns.id,
            NsKind::User => group.map_or(crate::cred::INIT_USER_NS, |g| g.borrow().cred.user_ns.id),
            NsKind::Cgroup => task.ns.borrow().cgroup.id,
            NsKind::Ipc => task.ns.borrow().ipc.id,
            NsKind::Net => task.ns.borrow().net.id,
            NsKind::Pid => k.pid_ns_of(task.tgid).id,
            // None after unshare until a child is created (Linux's pidns_for_children_get looks
            // at child_reaper)
            NsKind::PidForChildren => {
                let ns = task.pid_ns_children.borrow().clone();
                let ns = ns.unwrap_or_else(|| k.pid_ns_of(task.tgid));
                if ns.level > 0 && ns.reaper.get().is_none() {
                    return None;
                }
                ns.id
            }
            NsKind::Time => task.ns.borrow().time.id,
            NsKind::TimeForChildren => task.ns.borrow().time_for_children.id,
            NsKind::Uts => task.ns.borrow().uts.id,
        })
    }
}

const ENTRIES: [(&[u8], Entry); 34] = [
    (b"auxv", Entry::Auxv),
    (b"stat", Entry::Stat),
    (b"status", Entry::Status),
    (b"statm", Entry::Statm),
    (b"cmdline", Entry::Cmdline),
    (b"comm", Entry::Comm),
    (b"syscall", Entry::Syscall),
    (b"environ", Entry::Environ),
    (b"limits", Entry::Limits),
    (b"children", Entry::Children),
    (b"maps", Entry::Maps),
    (b"mem", Entry::Mem),
    (b"smaps", Entry::Smaps),
    (b"smaps_rollup", Entry::SmapsRollup),
    (b"pagemap", Entry::Pagemap),
    (b"mounts", Entry::Mounts),
    (b"mountinfo", Entry::MountInfo),
    (b"cwd", Entry::Cwd),
    (b"exe", Entry::Exe),
    (b"root", Entry::Root),
    (b"fd", Entry::Fd),
    (b"fdinfo", Entry::FdInfo),
    (b"task", Entry::Task),
    (b"net", Entry::Net),
    (b"oom_score", Entry::OomScore),
    (b"oom_score_adj", Entry::OomScoreAdj),
    (b"coredump_filter", Entry::CoredumpFilter),
    (b"cgroup", Entry::Cgroup),
    (b"ns", Entry::Ns),
    (b"uid_map", Entry::UidMap),
    (b"gid_map", Entry::GidMap),
    (b"projid_map", Entry::ProjidMap),
    (b"setgroups", Entry::Setgroups),
    (b"timens_offsets", Entry::TimensOffsets),
];

/// The files under `/proc/<pid>/net`. As on Linux, `/proc/net` is a link to `self/net`.
const PROC_NET: [&[u8]; 18] = [
    b"arp",
    b"dev",
    b"icmp",
    b"icmp6",
    b"if_inet6",
    b"ipv6_route",
    b"netstat",
    b"raw",
    b"raw6",
    b"route",
    b"snmp",
    b"sockstat",
    b"sockstat6",
    b"tcp",
    b"tcp6",
    b"udp",
    b"udp6",
    b"unix",
];

/// Platform render-node paths exposed when the machine has a renderer.
const SYS_GPU: &[&[u8]] = &[
    b"bus/",
    b"bus/platform/",
    b"dev/char/",
    b"dev/char/226:128/",
    b"dev/char/226:128/device/",
    b"dev/char/226:128/device/drm/",
    b"dev/char/226:128/device/drm/renderD128/",
    b"dev/char/226:128/device/subsystem",
    b"dev/char/226:128/device/uevent",
];

/// The fixed directories and files under `/proc/sys` and `/proc/sysvipc` (paths relative to
/// `/proc`, directories ending in `/`). Those under `sys/net` follow the reader's network namespace
/// (as on Linux), and the directories under `ipv4/conf` and `ipv6/conf` are
/// [`PseudoNode::NetConf`].
const STATIC: [&[u8]; 133] = [
    b"sys/",
    b"sys/debug/",
    b"sys/debug/exception-trace",
    b"sys/fs/",
    b"sys/fs/aio-max-nr",
    b"sys/fs/aio-nr",
    b"sys/fs/file-max",
    b"sys/fs/inotify/",
    b"sys/fs/inotify/max_queued_events",
    b"sys/fs/inotify/max_user_instances",
    b"sys/fs/inotify/max_user_watches",
    b"sys/fs/lease-break-time",
    b"sys/fs/mount-max",
    b"sys/fs/mqueue/",
    b"sys/fs/mqueue/msg_default",
    b"sys/fs/mqueue/msg_max",
    b"sys/fs/mqueue/msgsize_default",
    b"sys/fs/mqueue/msgsize_max",
    b"sys/fs/mqueue/queues_max",
    b"sys/fs/nr_open",
    b"sys/fs/overflowgid",
    b"sys/fs/overflowuid",
    b"sys/fs/pipe-max-size",
    b"sys/fs/pipe-user-pages-hard",
    b"sys/fs/pipe-user-pages-soft",
    PROTECTED_FIFOS,
    b"sys/fs/protected_hardlinks",
    PROTECTED_REGULAR,
    b"sys/fs/protected_symlinks",
    b"sys/fs/suid_dumpable",
    b"sys/kernel/",
    b"sys/kernel/cap_last_cap",
    b"sys/kernel/core_pattern",
    b"sys/kernel/core_pipe_limit",
    b"sys/kernel/core_uses_pid",
    b"sys/kernel/dmesg_restrict",
    b"sys/kernel/domainname",
    b"sys/kernel/hostname",
    b"sys/kernel/hung_task_all_cpu_backtrace",
    b"sys/kernel/hung_task_check_count",
    b"sys/kernel/hung_task_check_interval_secs",
    b"sys/kernel/hung_task_panic",
    b"sys/kernel/hung_task_timeout_secs",
    b"sys/kernel/hung_task_warnings",
    b"sys/kernel/kptr_restrict",
    b"sys/kernel/modprobe",
    b"sys/kernel/modules_disabled",
    b"sys/kernel/msgmax",
    b"sys/kernel/msgmnb",
    b"sys/kernel/msgmni",
    b"sys/kernel/ngroups_max",
    b"sys/kernel/ns_last_pid",
    b"sys/kernel/osrelease",
    b"sys/kernel/ostype",
    b"sys/kernel/overflowgid",
    b"sys/kernel/overflowuid",
    b"sys/kernel/panic",
    b"sys/kernel/panic_on_oops",
    b"sys/kernel/perf_cpu_time_max_percent",
    b"sys/kernel/perf_event_max_contexts_per_stack",
    b"sys/kernel/perf_event_max_sample_rate",
    b"sys/kernel/perf_event_max_stack",
    b"sys/kernel/perf_event_mlock_kb",
    b"sys/kernel/perf_event_paranoid",
    b"sys/kernel/pid_max",
    b"sys/kernel/printk",
    b"sys/kernel/printk_devkmsg",
    b"sys/kernel/random/",
    b"sys/kernel/random/boot_id",
    b"sys/kernel/random/entropy_avail",
    b"sys/kernel/random/poolsize",
    b"sys/kernel/random/uuid",
    b"sys/kernel/randomize_va_space",
    b"sys/kernel/sched_rr_timeslice_ms",
    b"sys/kernel/sched_rt_period_us",
    b"sys/kernel/sched_rt_runtime_us",
    b"sys/kernel/sched_schedstats",
    b"sys/kernel/seccomp/",
    b"sys/kernel/seccomp/actions_avail",
    b"sys/kernel/seccomp/actions_logged",
    b"sys/kernel/sem",
    b"sys/kernel/shmall",
    b"sys/kernel/shmmax",
    b"sys/kernel/shmmni",
    b"sys/kernel/sysrq",
    b"sys/kernel/tainted",
    b"sys/kernel/threads-max",
    b"sys/kernel/unprivileged_bpf_disabled",
    b"sys/kernel/version",
    b"sys/net/",
    b"sys/net/bridge/",
    b"sys/net/bridge/bridge-nf-call-iptables",
    b"sys/net/core/",
    b"sys/net/core/somaxconn",
    b"sys/net/ipv4/",
    b"sys/net/ipv4/conf/",
    b"sys/net/ipv4/ip_forward",
    b"sys/net/ipv4/ip_local_port_range",
    b"sys/net/ipv4/ip_unprivileged_port_start",
    b"sys/net/ipv4/ping_group_range",
    b"sys/net/ipv6/",
    b"sys/net/ipv6/conf/",
    b"sys/net/unix/",
    b"sys/user/",
    b"sys/user/max_cgroup_namespaces",
    b"sys/user/max_ipc_namespaces",
    b"sys/user/max_mnt_namespaces",
    b"sys/user/max_net_namespaces",
    b"sys/user/max_pid_namespaces",
    b"sys/user/max_time_namespaces",
    b"sys/user/max_user_namespaces",
    b"sys/user/max_uts_namespaces",
    b"sys/vm/",
    b"sys/vm/dirty_background_bytes",
    b"sys/vm/dirty_background_ratio",
    b"sys/vm/dirty_bytes",
    b"sys/vm/dirty_expire_centisecs",
    b"sys/vm/dirty_ratio",
    b"sys/vm/dirty_writeback_centisecs",
    b"sys/vm/drop_caches",
    b"sys/vm/max_map_count",
    b"sys/vm/mmap_min_addr",
    b"sys/vm/mmap_rnd_bits",
    b"sys/vm/mmap_rnd_compat_bits",
    b"sys/vm/overcommit_memory",
    b"sys/vm/overcommit_ratio",
    b"sys/vm/page-cluster",
    b"sys/vm/swappiness",
    b"sys/vm/watermark_scale_factor",
    b"sysvipc/",
    b"sysvipc/msg",
    b"sysvipc/sem",
    b"sysvipc/shm",
];

/// `/proc/sys/fs/protected_{fifos,regular}` paths shared with `syscall::fs::may_create_in_sticky`.
pub(crate) const PROTECTED_FIFOS: &[u8] = b"sys/fs/protected_fifos";
pub(crate) const PROTECTED_REGULAR: &[u8] = b"sys/fs/protected_regular";

/// The sysctls procfs only records, so that `sysctl -p` setups, benchmark scripts and checkers find
/// them: (path relative to `/proc`, mode, default, lowest and highest value accepted), the range
/// being that of Linux 6.1's handler (any int for `proc_dointvec`). A write keeps the value in
/// `Kernel::sysctls` and changes nothing else, except those read via [`recorded_value`]
/// (`debug.exception-trace`, `fs.suid_dumpable`, `fs.protected_fifos`, `fs.protected_regular`,
/// `vm.dirty_writeback_centisecs`); `kernel.randomize_va_space` starts at 0 because Appine places
/// mappings at fixed addresses, and `debug.exception-trace` at arm64's 0
/// (`show_unhandled_signals`; x86 starts at 1).
pub(crate) const RECORDED: [(&[u8], u32, i64, i64, i64); 42] = {
    const INT_MIN: i64 = i32::MIN as i64;
    const INT_MAX: i64 = i32::MAX as i64;
    // LONG_MAX / HZ for the hung-task times (HZ 250, as on distribution arm64 kernels)
    const HUNG_MAX: i64 = i64::MAX / 250;
    [
        (b"sys/debug/exception-trace", 0o644, 0, INT_MIN, INT_MAX),
        (b"sys/fs/overflowgid", 0o644, 65534, 0, 65535),
        (b"sys/fs/overflowuid", 0o644, 65534, 0, 65535),
        (PROTECTED_FIFOS, 0o644, 1, 0, 2),
        (PROTECTED_REGULAR, 0o644, 2, 0, 2),
        (b"sys/fs/suid_dumpable", 0o644, 0, 0, 2),
        (b"sys/kernel/core_pipe_limit", 0o644, 0, INT_MIN, INT_MAX),
        (b"sys/kernel/hung_task_all_cpu_backtrace", 0o644, 0, 0, 1),
        (
            b"sys/kernel/hung_task_check_count",
            0o644,
            4194304,
            0,
            4194304,
        ),
        (
            b"sys/kernel/hung_task_check_interval_secs",
            0o644,
            0,
            0,
            HUNG_MAX,
        ),
        (b"sys/kernel/hung_task_panic", 0o644, 0, 0, 1),
        (
            b"sys/kernel/hung_task_timeout_secs",
            0o644,
            120,
            0,
            HUNG_MAX,
        ),
        (b"sys/kernel/hung_task_warnings", 0o644, 10, -1, INT_MAX),
        // Writing also needs CAP_SYS_ADMIN (proc_dointvec_minmax_sysadmin)
        (b"sys/kernel/kptr_restrict", 0o644, 0, 0, 2),
        // Only the change from 0 to 1 can be written
        (b"sys/kernel/modules_disabled", 0o644, 0, 1, 1),
        (b"sys/kernel/overflowgid", 0o644, 65534, 0, 65535),
        (b"sys/kernel/overflowuid", 0o644, 65534, 0, 65535),
        (b"sys/kernel/panic_on_oops", 0o644, 0, INT_MIN, INT_MAX),
        (b"sys/kernel/perf_cpu_time_max_percent", 0o644, 25, 0, 100),
        (
            b"sys/kernel/perf_event_max_contexts_per_stack",
            0o644,
            8,
            0,
            65535,
        ),
        (
            b"sys/kernel/perf_event_max_sample_rate",
            0o644,
            100000,
            1,
            INT_MAX,
        ),
        (
            b"sys/kernel/perf_event_max_stack",
            0o644,
            127,
            0,
            640 * 1024,
        ),
        (
            b"sys/kernel/perf_event_mlock_kb",
            0o644,
            516,
            INT_MIN,
            INT_MAX,
        ),
        (
            b"sys/kernel/perf_event_paranoid",
            0o644,
            2,
            INT_MIN,
            INT_MAX,
        ),
        (b"sys/kernel/randomize_va_space", 0o644, 0, INT_MIN, INT_MAX),
        (b"sys/kernel/sched_rt_period_us", 0o644, 1000000, 1, INT_MAX),
        (
            b"sys/kernel/sched_rt_runtime_us",
            0o644,
            950000,
            -1,
            INT_MAX,
        ),
        (b"sys/kernel/sched_schedstats", 0o644, 0, 0, 1),
        (b"sys/kernel/sysrq", 0o644, 1, INT_MIN, INT_MAX),
        (b"sys/vm/dirty_background_bytes", 0o644, 0, 1, i64::MAX),
        (b"sys/vm/dirty_background_ratio", 0o644, 10, 0, 100),
        (b"sys/vm/dirty_bytes", 0o644, 0, 8192, i64::MAX),
        (b"sys/vm/dirty_expire_centisecs", 0o644, 3000, 0, INT_MAX),
        (b"sys/vm/dirty_ratio", 0o644, 20, 0, 100),
        (
            b"sys/vm/dirty_writeback_centisecs",
            0o644,
            500,
            INT_MIN,
            INT_MAX,
        ),
        // Write-only; the host keeps the page cache, and FUSE nodes are forgotten (write)
        (b"sys/vm/drop_caches", 0o200, 0, 1, 4),
        (b"sys/vm/mmap_rnd_bits", 0o600, 18, 18, 33),
        (b"sys/vm/mmap_rnd_compat_bits", 0o600, 11, 11, 16),
        (b"sys/vm/overcommit_ratio", 0o644, 50, INT_MIN, INT_MAX),
        (b"sys/vm/page-cluster", 0o644, 3, 0, 31),
        (b"sys/vm/swappiness", 0o644, 60, 0, 200),
        (b"sys/vm/watermark_scale_factor", 0o644, 10, 1, 3000),
    ]
};

/// The [`RECORDED`] entry of a path.
fn recorded(path: &[u8]) -> Option<&'static (&'static [u8], u32, i64, i64, i64)> {
    RECORDED.iter().find(|e| e.0 == path)
}

/// The current value of a [`RECORDED`] sysctl: the one written last, or its default.
pub(crate) fn recorded_value(k: &Kernel, path: &[u8]) -> i64 {
    let (path, _, default, ..) = *recorded(path).expect("a recorded sysctl");
    k.sysctls.get(path).copied().unwrap_or(default)
}

/// The fixed directories and files under `/sys` (paths relative to `/sys`, directories ending in
/// `/`). CPU topology: busybox's `nproc --all`, lscpu and glibc's get_nprocs read them, and each
/// `cpu<n>` is a [`PseudoNode::SysCpu`]; network interfaces (btop reads the traffic counters),
/// each interface a [`PseudoNode::SysNet`]; overlayfs's module parameters (containerd adds
/// `index=off` when `index` exists, BuildKit `redirect_dir=off` when `redirect_dir` does).
const SYS_STATIC: [&[u8]; 25] = [
    b"block/",
    b"class/",
    b"class/net/",
    b"dev/",
    b"dev/block/",
    b"devices/",
    b"devices/system/",
    b"devices/system/cpu/",
    b"devices/system/cpu/offline",
    b"devices/system/cpu/online",
    b"devices/system/cpu/possible",
    b"devices/system/cpu/present",
    b"fs/",
    b"fs/cgroup/",
    b"module/",
    b"module/overlay/",
    b"module/overlay/parameters/",
    b"module/overlay/parameters/check_copy_up",
    b"module/overlay/parameters/index",
    b"module/overlay/parameters/metacopy",
    b"module/overlay/parameters/nfs_export",
    b"module/overlay/parameters/redirect_always_follow",
    b"module/overlay/parameters/redirect_dir",
    b"module/overlay/parameters/redirect_max",
    b"module/overlay/parameters/xino_auto",
];

/// `/sys/class/net`: the interfaces are under it.
const SYS_NET_DIR: &[u8] = b"class/net/";

/// `/sys/block`: the loop devices are under it.
const SYS_BLOCK_DIR: &[u8] = b"block/";

/// `/sys/dev/block`: links to block devices by major and minor number.
const SYS_DEV_BLOCK_DIR: &[u8] = b"dev/block/";

/// The directories and files under `/sys/block/loop<n>` (paths relative to the device directory),
/// with driver attributes from [`crate::syscall::Loops::sysfs_read`]. The `loop/` directory exists
/// only while the device is bound. Linux links to `/sys/devices/virtual/block` from `/sys/block`.
/// Appine uses plain directories, as for `/sys/class/net`.
const BLOCK_FILES: [&[u8]; 23] = [
    b"dev",
    b"removable",
    b"ro",
    b"size",
    b"uevent",
    b"loop/",
    b"loop/autoclear",
    b"loop/backing_file",
    b"loop/dio",
    b"loop/offset",
    b"loop/partscan",
    b"loop/sizelimit",
    b"queue/",
    b"queue/dma_alignment",
    b"queue/hw_sector_size",
    b"queue/logical_block_size",
    b"queue/max_sectors_kb",
    b"queue/minimum_io_size",
    b"queue/optimal_io_size",
    b"queue/physical_block_size",
    b"queue/read_ahead_kb",
    b"queue/rotational",
    b"queue/rq_affinity",
];

/// The directories and files under `/sys/class/net/<interface>` (paths relative to the interface
/// directory), with values from [`net_file`]. On Linux the interface directories are symlinks into
/// `/sys/devices`; here they are directories: the device paths on the host are not available.
const NET_FILES: [&[u8]; 36] = [
    b"addr_len",
    b"address",
    b"broadcast",
    b"carrier",
    b"flags",
    b"ifindex",
    b"iflink",
    b"mtu",
    b"operstate",
    b"tx_queue_len",
    b"type",
    b"statistics/",
    b"statistics/collisions",
    b"statistics/multicast",
    b"statistics/rx_bytes",
    b"statistics/rx_compressed",
    b"statistics/rx_crc_errors",
    b"statistics/rx_dropped",
    b"statistics/rx_errors",
    b"statistics/rx_fifo_errors",
    b"statistics/rx_frame_errors",
    b"statistics/rx_length_errors",
    b"statistics/rx_missed_errors",
    b"statistics/rx_nohandler",
    b"statistics/rx_over_errors",
    b"statistics/rx_packets",
    b"statistics/tx_aborted_errors",
    b"statistics/tx_bytes",
    b"statistics/tx_carrier_errors",
    b"statistics/tx_compressed",
    b"statistics/tx_dropped",
    b"statistics/tx_errors",
    b"statistics/tx_fifo_errors",
    b"statistics/tx_heartbeat_errors",
    b"statistics/tx_packets",
    b"statistics/tx_window_errors",
];

/// The extra ones under a bridge's `/sys/class/net/<interface>` (`brif/<port>` is a
/// [`PseudoNode::SysBrif`]). dockerd reads `bridge/stp_state` and the ports' `state`, waiting for
/// the ports to reach the forwarding state.
const BRIDGE_FILES: [&[u8]; 10] = [
    b"bridge/",
    b"bridge/ageing_time",
    b"bridge/bridge_id",
    b"bridge/forward_delay",
    b"bridge/hello_time",
    b"bridge/max_age",
    b"bridge/priority",
    b"bridge/root_id",
    b"bridge/stp_state",
    b"brif/",
];

/// The extra ones under a bridge port's `/sys/class/net/<interface>`.
const PORT_FILES: [&[u8]; 4] = [
    b"brport/",
    b"brport/path_cost",
    b"brport/priority",
    b"brport/state",
];

/// `/sys/devices/system/cpu`: each `cpu<n>` is under it.
const SYS_CPU_DIR: &[u8] = b"devices/system/cpu/";

/// The directories and files under `/sys/devices/system/cpu/cpu<n>` (paths relative to
/// `cpu<n>`).
const CPU_FILES: [&[u8]; 19] = [
    b"online",
    b"regs/",
    b"regs/identification/",
    b"regs/identification/midr_el1",
    b"regs/identification/revidr_el1",
    b"topology/",
    b"topology/cluster_cpus",
    b"topology/cluster_cpus_list",
    b"topology/cluster_id",
    b"topology/core_cpus",
    b"topology/core_cpus_list",
    b"topology/core_id",
    b"topology/core_siblings",
    b"topology/core_siblings_list",
    b"topology/package_cpus",
    b"topology/package_cpus_list",
    b"topology/physical_package_id",
    b"topology/thread_siblings",
    b"topology/thread_siblings_list",
];

/// The directories and files under `/sys/devices/system/cpu/cpu<n>` copied from the host: caches
/// (`cache/`) and frequencies (`cpufreq/`). They exist only when the corresponding host CPU has
/// them ([`host_cpu_has`]); the contents are the host's too, with the CPU numbers inside changed
/// to the guest's. lscpu, hwloc and OpenBLAS read the cache sizes, and Node.js's `os.cpus()`
/// reads `cpufreq/scaling_cur_freq`; on hosts without cpufreq (virtual machines) they are absent,
/// as on Linux.
const HOST_CPU_FILES: [&[u8]; 68] = [
    b"cache/",
    b"cache/index0/",
    b"cache/index0/allocation_policy",
    b"cache/index0/coherency_line_size",
    b"cache/index0/id",
    b"cache/index0/level",
    b"cache/index0/number_of_sets",
    b"cache/index0/physical_line_partition",
    b"cache/index0/shared_cpu_list",
    b"cache/index0/shared_cpu_map",
    b"cache/index0/size",
    b"cache/index0/type",
    b"cache/index0/ways_of_associativity",
    b"cache/index0/write_policy",
    b"cache/index1/",
    b"cache/index1/allocation_policy",
    b"cache/index1/coherency_line_size",
    b"cache/index1/id",
    b"cache/index1/level",
    b"cache/index1/number_of_sets",
    b"cache/index1/physical_line_partition",
    b"cache/index1/shared_cpu_list",
    b"cache/index1/shared_cpu_map",
    b"cache/index1/size",
    b"cache/index1/type",
    b"cache/index1/ways_of_associativity",
    b"cache/index1/write_policy",
    b"cache/index2/",
    b"cache/index2/allocation_policy",
    b"cache/index2/coherency_line_size",
    b"cache/index2/id",
    b"cache/index2/level",
    b"cache/index2/number_of_sets",
    b"cache/index2/physical_line_partition",
    b"cache/index2/shared_cpu_list",
    b"cache/index2/shared_cpu_map",
    b"cache/index2/size",
    b"cache/index2/type",
    b"cache/index2/ways_of_associativity",
    b"cache/index2/write_policy",
    b"cache/index3/",
    b"cache/index3/allocation_policy",
    b"cache/index3/coherency_line_size",
    b"cache/index3/id",
    b"cache/index3/level",
    b"cache/index3/number_of_sets",
    b"cache/index3/physical_line_partition",
    b"cache/index3/shared_cpu_list",
    b"cache/index3/shared_cpu_map",
    b"cache/index3/size",
    b"cache/index3/type",
    b"cache/index3/ways_of_associativity",
    b"cache/index3/write_policy",
    b"cpufreq/",
    b"cpufreq/affected_cpus",
    b"cpufreq/cpuinfo_cur_freq",
    b"cpufreq/cpuinfo_max_freq",
    b"cpufreq/cpuinfo_min_freq",
    b"cpufreq/cpuinfo_transition_latency",
    b"cpufreq/related_cpus",
    b"cpufreq/scaling_available_frequencies",
    b"cpufreq/scaling_available_governors",
    b"cpufreq/scaling_cur_freq",
    b"cpufreq/scaling_driver",
    b"cpufreq/scaling_governor",
    b"cpufreq/scaling_max_freq",
    b"cpufreq/scaling_min_freq",
    b"cpufreq/scaling_setspeed",
];

/// A process identity pinned by procfs nodes: `pid` (a thread id, usually the tgid) plus the
/// thread group's non-reusable [`ThreadGroup::serial`], so a held `/proc/<pid>` directory or
/// open file never resolves to a new process that later reuses the same pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ProcId {
    pub pid: Tid,
    pub serial: u64,
}

impl ProcId {
    fn of(pid: Tid, group: &ThreadGroup) -> ProcId {
        ProcId {
            pid,
            serial: group.serial,
        }
    }
}

macro_rules! pinned_ns {
    ($(#[$meta:meta])* $name:ident($inner:ty)) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub(crate) struct $name(pub(crate) Rc<$inner>);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0.id).finish()
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.id == other.0.id
            }
        }

        impl Eq for $name {}

        impl Hash for $name {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.id.hash(state);
            }
        }
    };
}

pinned_ns!(
    /// A network namespace pinned on a `/proc/sys/net/*` node at lookup time (Linux's
    /// `sysctl_table_root::lookup`), so an open descriptor keeps reading and writing that namespace
    /// even after the process changes network namespaces or passes the fd across namespaces.
    PinnedNet(crate::nsproxy::NetNs)
);

pinned_ns!(
    /// An IPC namespace pinned on a SysV/mqueue sysctl node at lookup time, so an open descriptor
    /// keeps reading and writing that namespace even when read or written from another IPC
    /// namespace.
    PinnedIpc(crate::nsproxy::IpcNs)
);

pinned_ns!(
    /// A UTS namespace pinned on `/proc/sys/kernel/{hostname,domainname}` at lookup time, so an
    /// open descriptor keeps reading and writing that namespace even after `unshare(CLONE_NEWUTS)`
    /// or passing the fd across namespaces.
    PinnedUts(crate::nsproxy::UtsNs)
);

pinned_ns!(
    /// A pid namespace pinned on `/proc/sys/kernel/ns_last_pid` at lookup time, so an open
    /// descriptor keeps reading and writing that namespace even when inherited or passed into
    /// another pid namespace.
    PinnedPid(PidNs)
);

/// Whether `path` in [`STATIC`] is a per-network-namespace sysctl file; excludes the
/// `/proc/sys/net/` directories themselves so relative lookups after `unshare(CLONE_NEWNET)`
/// resolve in the caller's current network namespace (matching Linux's `net_ctl_header_lookup`).
fn is_net_sysctl_path(path: &[u8]) -> bool {
    !path.ends_with(b"/") && path.starts_with(b"sys/net/")
}

/// Whether `path` in [`STATIC`] is a per-IPC-namespace sysctl file (SysV IPC or POSIX mqueue
/// limits); excludes the `sys/fs/mqueue/` directory itself.
fn is_ipc_sysctl_path(path: &[u8]) -> bool {
    !path.ends_with(b"/")
        && (path.starts_with(b"sys/fs/mqueue/")
            || matches!(
                path,
                b"sys/kernel/msgmax"
                    | b"sys/kernel/msgmnb"
                    | b"sys/kernel/msgmni"
                    | b"sys/kernel/sem"
                    | b"sys/kernel/shmall"
                    | b"sys/kernel/shmmax"
                    | b"sys/kernel/shmmni"
            ))
}

/// Whether `path` in [`STATIC`] is a per-UTS-namespace sysctl file.
fn is_uts_sysctl_path(path: &[u8]) -> bool {
    matches!(path, b"sys/kernel/hostname" | b"sys/kernel/domainname")
}

/// Whether `path` in [`STATIC`] is a per-pid-namespace sysctl file.
fn is_pid_sysctl_path(path: &[u8]) -> bool {
    path == b"sys/kernel/ns_last_pid"
}

/// A node in a synthetic filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum PseudoNode {
    /// The root directory of a devpts instance (its device number, [`crate::tty::PtsOptions`]),
    /// `/dev/pts`.
    PtsRoot(u64),
    /// A terminal in the instance, `/dev/pts/<n>`.
    Pts(u64, u32),
    /// The instance's ptmx, `/dev/pts/ptmx`.
    PtsPtmx(u64),
    /// `/proc`.
    ProcRoot,
    /// A global file under `/proc`.
    Global(Global),
    /// `/proc/self`.
    SelfLink,
    /// `/proc/thread-self`.
    ThreadSelf,
    /// A directory or file under `/proc/sys` or `/proc/sysvipc`, with values from [`STATIC`].
    /// Per-namespace sysctl paths use [`NetStatic`], [`IpcSysctl`], [`UtsSysctl`] and
    /// [`PidSysctl`] so their namespace stays pinned to the lookup/open namespace.
    Static(&'static [u8]),
    /// A static file under `/proc/sys/net/`, pinned to its lookup network namespace.
    NetStatic(&'static [u8], PinnedNet),
    /// A per-IPC-namespace sysctl under `/proc/sys/kernel/` or `/proc/sys/fs/mqueue/`, pinned to
    /// its lookup IPC namespace.
    IpcSysctl(&'static [u8], PinnedIpc),
    /// A per-UTS-namespace sysctl (`/proc/sys/kernel/hostname` or `domainname`), pinned to its
    /// lookup UTS namespace.
    UtsSysctl(&'static [u8], PinnedUts),
    /// A per-pid-namespace sysctl (`/proc/sys/kernel/ns_last_pid`), pinned to its lookup pid
    /// namespace.
    PidSysctl(&'static [u8], PinnedPid),
    /// `/proc/<pid>`; with `Some(tid)` as the second item it is `/proc/<pid>/task/<tid>`.
    Pid(ProcId, Option<Tid>),
    /// `/proc/<pid>/<entry>` (including those in the task subdirectories).
    Entry(ProcId, Option<Tid>, Entry),
    /// `/proc/<pid>/net/<name>` (including those in the task subdirectories), with names from
    /// [`PROC_NET`].
    Net(ProcId, Option<Tid>, &'static [u8]),
    /// `/proc/<pid>/fd/<n>` (or `/proc/<pid>/task/<tid>/fd/<n>`).
    Fd(ProcId, Option<Tid>, i32),
    /// The open file reached by following `/proc/<pid>/fd/<n>` (for those not in the store:
    /// pipes, host fds).
    OpenFd(ProcId, Option<Tid>, i32),
    /// The program file reached by following `/proc/<pid>/exe`, when it has been deleted and
    /// cannot be opened by inode ([`crate::process::ExeFile`]).
    OpenExe(ProcId),
    /// `/proc/<pid>/fdinfo/<n>` (or `/proc/<pid>/task/<tid>/fdinfo/<n>`).
    FdInfo(ProcId, Option<Tid>, i32),
    /// `/sys`.
    SysRoot,
    /// A directory or file under `/sys`, with values from [`SYS_STATIC`].
    Sys(&'static [u8]),
    /// `/sys/devices/system/cpu/cpu<n>` (empty path), or a directory or file under it (paths from
    /// [`CPU_FILES`]).
    SysCpu(u32, &'static [u8]),
    /// `/sys/class/net/<interface>` (empty path), or a directory or file under it (paths from
    /// [`NET_FILES`]); interfaces are recorded by their host interface index.
    SysNet(u32, &'static [u8]),
    /// `/sys/class/net/<bridge>/brif/<port>`: a link to `../../<port>/brport` (the interface
    /// indexes of the bridge and the port).
    SysBrif(u32, u32),
    /// `/sys/block/loop<n>` (empty path), or a directory or file under it (paths from
    /// [`BLOCK_FILES`]).
    SysBlock(u32, &'static [u8]),
    /// `/sys/dev/block/7:<n>`, a relative symlink to `/sys/block/loop<n>`.
    SysDevBlock(u32),
    /// A cgroup directory (empty name), or a file in it (names from [`crate::cgroup::FILES`]): the
    /// cgroup id and the file name.
    Cgroup(u64, &'static [u8], u64),
    /// `/proc/<pid>/ns/<kind>` (including those in the task subdirectories): a magic link to a
    /// namespace.
    Ns(ProcId, Option<Tid>, NsKind),
    /// The namespace reached by following `/proc/<pid>/ns/<kind>` (a file in Linux's nsfs), by id.
    NsFile(NsKind, u64),
    /// The root directory of an mqueue filesystem: the POSIX message queues of an IPC namespace
    /// (by id) ([`crate::syscall::MessageQueue`]).
    MqRoot(u64),
    /// A queue in an mqueue filesystem: the IPC namespace and the queue's inode number.
    Mq(u64, u64),
    /// `/proc/sys/net/ipv4/conf/<dir>` (first item false) or `ipv6/conf/<dir>` (empty name), or an
    /// entry under it (names from the [`crate::netconf`] tables), pinned to its lookup network
    /// namespace ([`crate::netdev::conf_read`]).
    NetConf(bool, crate::netdev::ConfDir, &'static [u8], PinnedNet),
    /// A sysctl under `/proc/sys/net/` (one in [`crate::netconf::SYSCTLS`], with paths like
    /// `ipv4/tcp_keepalive_time`), pinned to its lookup network namespace.
    NetSysctl(&'static str, PinnedNet),
}

/// The cgroup2 mount point `fs/cgroup` in sysfs (an empty directory when nothing is mounted).
pub(crate) const CGROUP_POINT: PseudoNode = PseudoNode::Sys(b"fs/cgroup/");

/// The `ipv4/conf` and `ipv6/conf` directories.
const NET_CONF4: &[u8] = b"sys/net/ipv4/conf/";
const NET_CONF6: &[u8] = b"sys/net/ipv6/conf/";

/// The entries in `/proc/<pid>/task/<tid>`: the thread's own, and those the same as the
/// process's (debuggers read a thread's maps and mem; `oom_score_adj` there sets the process's, as
/// Linux's tid_base_stuff has it).
const TASK_ENTRIES: [Entry; 30] = [
    Entry::Stat,
    Entry::Status,
    Entry::Statm,
    Entry::Comm,
    Entry::Syscall,
    Entry::Cmdline,
    Entry::Environ,
    Entry::Limits,
    Entry::Children,
    Entry::Auxv,
    Entry::Mem,
    Entry::Maps,
    Entry::Smaps,
    Entry::SmapsRollup,
    Entry::Mounts,
    Entry::MountInfo,
    Entry::Cwd,
    Entry::Exe,
    Entry::Root,
    Entry::Fd,
    Entry::FdInfo,
    Entry::Cgroup,
    Entry::OomScore,
    Entry::OomScoreAdj,
    Entry::Net,
    Entry::Ns,
    Entry::UidMap,
    Entry::GidMap,
    Entry::ProjidMap,
    Entry::Setgroups,
];

// ---- Lookup ----

/// A read-only view of kernel state taken while holding the BKL; `tid`/`tgid` is the thread
/// `self` points to.
pub(crate) struct View<'a> {
    pub k: &'a Kernel,
    pub vfs: &'a Vfs,
    pub tid: Tid,
    pub tgid: Tid,
    /// Credentials to read with instead of the process's: an open file's opener's, when its
    /// content is generated again ([`crate::fd::FileKind::Proc`]).
    pub cred: Option<Rc<Cred>>,
    /// An open walk can reopen an unlinked overlay object through its source descriptor.
    pub opening: bool,
}

/// A host path lookup without a guest task to resolve synthetic nodes.
pub(crate) enum Offline {
    /// Boot and host-spawned programs see empty synthetic root directories.
    Boot,
    /// An observation cannot treat a synthetic path as a missing store file.
    HostStat,
}

impl Pseudo for Offline {
    fn parent(&self, _: &PseudoNode) -> Option<PseudoNode> {
        None
    }
    fn name(&self, _: MountId, _: &PseudoNode) -> Vec<u8> {
        Vec::new()
    }
    fn lookup(&self, _: MountId, _: &PseudoNode, _: &[u8]) -> Result<PseudoNode, Errno> {
        Err(match self {
            Self::Boot => Errno::ENOENT,
            Self::HostStat => Errno::EOPNOTSUPP,
        })
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

impl<'a> View<'a> {
    /// The reader's root directory (the thread `self` points to): paths in procfs are shown
    /// relative to it.
    fn root(&self) -> Node {
        self.k
            .tasks
            .get(&self.tid)
            .map_or(Node::ROOT, |t| t.res.borrow().fs.borrow().root.clone())
    }

    fn group(&self, proc: ProcId) -> Option<Rc<RefCell<ThreadGroup>>> {
        group_of_id(self.k, proc).cloned()
    }

    /// The thread a pid directory stands for: the thread itself when `proc.pid` is a thread id, so
    /// the main thread for a process, and none once that has exited (procfs then shows it as a
    /// zombie).
    fn leader(&self, proc: ProcId) -> Option<Rc<Task>> {
        let g = self.group(proc)?;
        let threads = g.borrow().threads.clone();
        threads
            .iter()
            .find(|&&t| t == proc.pid)
            .and_then(|t| self.k.tasks.get(t).cloned())
    }

    /// The pid namespace of mount `mnt` (an instance of procfs): pids in directory names, links
    /// and files are counted in it (Linux's `proc_pid_ns`).
    pub(crate) fn pid_ns(&self, mnt: MountId) -> Rc<PidNs> {
        self.vfs.proc_pid_ns(mnt).unwrap_or_else(PidNs::init)
    }

    /// The last number allocated in the reader's pid namespace (`loadavg`; Linux uses the reader's
    /// namespace, not the mount's).
    fn last_pid(&self) -> Tid {
        last_pid_in(self.k, &self.k.pid_ns_of(self.tgid))
    }

    /// The reader's namespace proxy (of the thread `self` points to): used to pin per-namespace
    /// sysctls at lookup (`net`, `ipc`, `uts`) and to view `/proc/sysvipc`.
    pub(crate) fn ns(&self) -> crate::nsproxy::NsProxy {
        self.k
            .tasks
            .get(&self.tid)
            .map_or_else(|| self.k.init_ns.clone(), |t| t.ns.borrow().clone())
    }

    /// The network namespace of sysfs mount `mnt`: the mounting process's (Linux tags each sysfs
    /// superblock with its mounter's network namespace), or the initial network namespace for the
    /// boot mount.
    pub(crate) fn sys_net_ns(&self, mnt: MountId) -> Rc<crate::nsproxy::NetNs> {
        self.vfs
            .sys_net_ns(mnt)
            .unwrap_or_else(|| self.k.init_ns.net.clone())
    }

    /// The interface with index `index` in sysfs mount `mnt`'s network namespace (the host's or
    /// lo, and virtual devices).
    fn interface(&self, mnt: MountId, index: u32) -> Option<appine_hal::net::Interface> {
        crate::netdev::interfaces(&self.sys_net_ns(mnt))
            .into_iter()
            .find(|i| i.index == index)
    }

    /// Whether the interface with index `index` in sysfs mount `mnt`'s network namespace is a
    /// bridge, and whether it is a bridge port.
    fn bridge_roles(&self, mnt: MountId, index: u32) -> (bool, bool) {
        crate::netdev::views(&self.sys_net_ns(mnt))
            .into_iter()
            .find(|v| v.index == index)
            .map_or((false, false), |v| {
                (v.kind == crate::netdev::Kind::Bridge, v.master.is_some())
            })
    }

    /// The directory under `/proc/sys/net/ipv*/conf` still exists in `net` (the interface was not
    /// removed).
    fn conf_dir_exists_in(net: &crate::nsproxy::NetNs, dir: crate::netdev::ConfDir) -> bool {
        match dir {
            crate::netdev::ConfDir::Dev(i) => crate::netdev::interfaces(net)
                .into_iter()
                .any(|iface| iface.index == i),
            _ => true,
        }
    }

    /// Wraps a [`STATIC`] path, pinning the lookup's network, IPC, UTS or pid namespace when the
    /// entry is a per-namespace sysctl file.
    fn static_node(&self, path: &'static [u8]) -> PseudoNode {
        if is_net_sysctl_path(path) {
            PseudoNode::NetStatic(path, PinnedNet(self.ns().net))
        } else if is_ipc_sysctl_path(path) {
            PseudoNode::IpcSysctl(path, PinnedIpc(self.ns().ipc))
        } else if is_uts_sysctl_path(path) {
            PseudoNode::UtsSysctl(path, PinnedUts(self.ns().uts))
        } else if is_pid_sysctl_path(path) {
            PseudoNode::PidSysctl(path, PinnedPid(self.k.pid_ns_of(self.tgid)))
        } else {
            PseudoNode::Static(path)
        }
    }

    /// The root of the reader's cgroup namespace (a cgroup id).
    pub(crate) fn cgroup_root(&self) -> u64 {
        self.k
            .tasks
            .get(&self.tid)
            .map_or(crate::cgroup::ROOT, |t| t.ns.borrow().cgroup.root)
    }

    /// Nanoseconds since boot `ns` plus the boottime offset of the reader's time namespace
    /// (Linux's `timens_add_boottime_ns`: `/proc/uptime`, process start times; `/proc/stat`'s
    /// `btime` subtracts it), no less than 0.
    fn with_boot_offset(&self, ns: u64) -> u64 {
        let offset = self
            .k
            .tasks
            .get(&self.tid)
            .map_or(0, |t| t.ns.borrow().time.offset(7));
        (ns as i128 + offset as i128).clamp(0, u64::MAX as i128) as u64
    }

    /// The reader's credentials (of the thread `self` points to, or the opener's given with the
    /// view): IDs in procfs are translated through its user namespace.
    pub(crate) fn reader(&self) -> Cred {
        if let Some(c) = &self.cred {
            return (**c).clone();
        }
        self.k.cred_of(self.tid).unwrap_or_else(Cred::root)
    }

    /// `/proc/<pid>/task/<tid>` uses the given thread, otherwise the representative thread.
    fn task(&self, proc: ProcId, tid: Option<Tid>) -> Option<Rc<Task>> {
        match tid {
            Some(t) => {
                let tgid = self.group(proc)?.borrow().tgid;
                self.k.tasks.get(&t).cloned().filter(|t| t.tgid == tgid)
            }
            None => self.leader(proc),
        }
    }

    fn pid_exists(&self, proc: ProcId, tid: Option<Tid>) -> bool {
        pid_exists_in(self.k, proc, tid)
    }

    /// An open file of thread `tid` (or the representative thread of `proc`).
    pub(crate) fn open_file(
        &self,
        proc: ProcId,
        tid: Option<Tid>,
        fd: i32,
    ) -> Option<crate::fd::FileRef> {
        let task = self.task(proc, tid)?;
        let res = task.res.borrow();
        res.fds.borrow().get(fd).ok()
    }

    fn pty(&self, fs: u64, n: u32) -> Option<Rc<RefCell<Tty>>> {
        self.k.ptys.get(&(fs, n)).and_then(|w| w.upgrade())
    }
}

impl Pseudo for View<'_> {
    fn parent(&self, node: &PseudoNode) -> Option<PseudoNode> {
        use PseudoNode::*;
        Some(match node {
            PtsRoot(_) | ProcRoot | SysRoot | MqRoot(_) => return None,
            // A child cgroup's parent is its parent cgroup; the root has none
            Cgroup(id, b"", 0) => Cgroup(self.k.cgroups.get(*id)?.parent?, b"", 0),
            Mq(ns, _) => MqRoot(*ns),
            Pts(fs, _) | PtsPtmx(fs) => PtsRoot(*fs),
            Global(_) | SelfLink | ThreadSelf | Pid(_, None) => ProcRoot,
            Static(path)
            | NetStatic(path, _)
            | IpcSysctl(path, _)
            | UtsSysctl(path, _)
            | PidSysctl(path, _) => tree_parent(&STATIC, path).map_or(ProcRoot, Static),
            Sys(path) => tree_parent(&SYS_STATIC, path)
                .or_else(|| tree_parent(SYS_GPU, path))
                .map_or(SysRoot, Sys),
            SysCpu(_, b"") => Sys(SYS_CPU_DIR),
            SysCpu(n, path) => tree_parent(&CPU_FILES, path)
                .or_else(|| tree_parent(&HOST_CPU_FILES, path))
                .map_or(SysCpu(*n, b""), |p| SysCpu(*n, p)),
            SysNet(_, b"") => Sys(SYS_NET_DIR),
            SysNet(n, path) => tree_parent(&NET_FILES, path)
                .or_else(|| tree_parent(&BRIDGE_FILES, path))
                .or_else(|| tree_parent(&PORT_FILES, path))
                .map_or(SysNet(*n, b""), |p| SysNet(*n, p)),
            SysBrif(n, _) => SysNet(*n, b"brif/"),
            SysDevBlock(_) => Sys(SYS_DEV_BLOCK_DIR),
            SysBlock(_, b"") => Sys(SYS_BLOCK_DIR),
            SysBlock(n, path) => {
                tree_parent(&BLOCK_FILES, path).map_or(SysBlock(*n, b""), |p| SysBlock(*n, p))
            }
            Cgroup(id, _, _) => Cgroup(*id, b"", 0),
            NetConf(v6, _, b"", _) => Static(if *v6 { NET_CONF6 } else { NET_CONF4 }),
            NetSysctl(path, _) => {
                let dir = &path[..=path.find('/').unwrap_or(0)];
                tree_lookup(&STATIC, b"sys/net/", dir.trim_end_matches('/').as_bytes())
                    .map_or(ProcRoot, Static)
            }
            NetConf(v6, dir, _, net) => NetConf(*v6, *dir, b"", net.clone()),
            Pid(proc, Some(_)) => Entry(*proc, None, self::Entry::Task),
            Entry(proc, tid, _) => Pid(*proc, *tid),
            Net(proc, tid, _) => Entry(*proc, *tid, self::Entry::Net),
            Fd(proc, tid, _) | OpenFd(proc, tid, _) => Entry(*proc, *tid, self::Entry::Fd),
            OpenExe(proc) => Pid(*proc, None),
            FdInfo(proc, tid, _) => Entry(*proc, *tid, self::Entry::FdInfo),
            Ns(proc, tid, _) => Entry(*proc, *tid, self::Entry::Ns),
            NsFile(..) => return None,
        })
    }

    fn name(&self, mnt: MountId, node: &PseudoNode) -> Vec<u8> {
        use PseudoNode::*;
        match node {
            PtsRoot(_) => b"pts".to_vec(),
            ProcRoot => b"proc".to_vec(),
            Pts(_, n) => n.to_string().into_bytes(),
            PtsPtmx(_) => b"ptmx".to_vec(),
            Global(g) => GLOBALS.iter().find(|(_, x)| x == g).unwrap().0.to_vec(),
            SelfLink => b"self".to_vec(),
            ThreadSelf => b"thread-self".to_vec(),
            Static(path)
            | NetStatic(path, _)
            | IpcSysctl(path, _)
            | UtsSysctl(path, _)
            | PidSysctl(path, _)
            | Sys(path) => tree_name(path).to_vec(),
            SysRoot => b"sys".to_vec(),
            MqRoot(_) => b"mqueue".to_vec(),
            Mq(ns, ino) => self
                .k
                .ipcs
                .get(ns)
                .and_then(|(_, ipc)| crate::syscall::mqueue_find(ipc, *ino))
                .map_or_else(|| ino.to_string().into_bytes(), |(n, _)| n.to_vec()),
            SysCpu(n, b"") => format!("cpu{n}").into_bytes(),
            SysCpu(_, path) => tree_name(path).to_vec(),
            SysNet(n, b"") => self
                .interface(mnt, *n)
                .map_or_else(|| n.to_string(), |i| i.name)
                .into_bytes(),
            NetConf(_, dir, b"", net) => {
                crate::netdev::conf_dir_name(&net.0, *dir).unwrap_or_else(|| b"?".to_vec())
            }
            NetConf(_, _, name, _) => name.to_vec(),
            NetSysctl(path, _) => tree_name(path.as_bytes()).to_vec(),
            SysNet(_, path) => tree_name(path).to_vec(),
            SysBlock(n, b"") => format!("loop{n}").into_bytes(),
            SysDevBlock(n) => format!("{LOOP_MAJOR}:{n}").into_bytes(),
            SysBlock(_, path) => tree_name(path).to_vec(),
            SysBrif(_, p) => self
                .interface(mnt, *p)
                .map_or_else(|| p.to_string(), |i| i.name)
                .into_bytes(),
            Cgroup(crate::cgroup::ROOT, b"", 0) => b"cgroup".to_vec(),
            Cgroup(id, b"", 0) => self
                .k
                .cgroups
                .get(*id)
                .map_or_else(|| id.to_string().into_bytes(), |g| g.name.clone()),
            Cgroup(_, name, _) => name.to_vec(),
            Pid(proc, None) => self
                .pid_ns(mnt)
                .vnr(proc.pid)
                .unwrap_or(0)
                .to_string()
                .into_bytes(),
            Pid(_, Some(tid)) => self
                .pid_ns(mnt)
                .vnr(*tid)
                .unwrap_or(0)
                .to_string()
                .into_bytes(),
            Entry(_, _, e) => ENTRIES.iter().find(|(_, x)| x == e).unwrap().0.to_vec(),
            Net(_, _, name) => name.to_vec(),
            Fd(_, _, fd) | OpenFd(_, _, fd) | FdInfo(_, _, fd) => fd.to_string().into_bytes(),
            OpenExe(_) => b"exe".to_vec(),
            Ns(_, _, k) => k.name().as_bytes().to_vec(),
            NsFile(k, id) => format!("{}:[{id}]", k.type_name()).into_bytes(),
        }
    }

    fn lookup(&self, mnt: MountId, dir: &PseudoNode, name: &[u8]) -> Result<PseudoNode, Errno> {
        use PseudoNode::*;
        // fd and fdinfo of another process are open only to readers that pass the ptrace-read
        // check (Linux's 0500 directories with proc_fd_permission, and proc_fd_access_allowed);
        // a reaped process's directory falls through to ENOENT rather than EACCES
        if let Entry(proc, tid, self::Entry::Fd | self::Entry::FdInfo) = dir
            && self.pid_exists(*proc, *tid)
            && !self.may_read(*proc, *tid)
        {
            return Err(Errno::EACCES);
        }
        // The pid in the name is a number in the mount's pid namespace
        let global = |name: &[u8]| {
            let n = Tid::try_from(parse_num(name)?).ok()?;
            self.pid_ns(mnt).find(n)
        };
        let found = match dir {
            MqRoot(ns) => self
                .k
                .ipcs
                .get(ns)
                .and_then(|(_, ipc)| ipc.mqueues.get(name))
                .map(|q| Mq(*ns, q.borrow().ino)),
            PtsRoot(fs) => {
                if name == b"ptmx" {
                    Some(PtsPtmx(*fs))
                } else {
                    parse_num(name)
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|&n| self.pty(*fs, n).is_some())
                        .map(|n| Pts(*fs, n))
                }
            }
            ProcRoot => match name {
                b"self" => Some(SelfLink),
                b"thread-self" => Some(ThreadSelf),
                _ if tree_lookup(&STATIC, b"", name).is_some() => {
                    tree_lookup(&STATIC, b"", name).map(Static)
                }
                _ => GLOBALS
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, g)| Global(*g))
                    .or_else(|| {
                        let pid = global(name)?;
                        let g = group_of(self.k, pid)?;
                        Some(Pid(ProcId::of(pid, &g.borrow()), None))
                    }),
            },
            Static(path) if *path == NET_CONF4 || *path == NET_CONF6 => {
                let net = self.ns().net;
                crate::netdev::conf_dirs(&net)
                    .into_iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, d)| NetConf(*path == NET_CONF6, d, b"", PinnedNet(net)))
            }
            Static(path) => tree_lookup(&STATIC, path, name)
                .map(|p| self.static_node(p))
                .or_else(|| {
                    let rest = path.strip_prefix(b"sys/net/")?;
                    let full = [rest, name].concat();
                    let net = self.ns().net;
                    let init = net.host_net.is_none();
                    crate::netconf::sysctl(&full, init).map(|e| NetSysctl(e.0, PinnedNet(net)))
                }),
            NetConf(v6, dir, b"", net) => crate::netconf::table(*v6)
                .iter()
                .find(|(n, ..)| n.as_bytes() == name)
                .filter(|_| Self::conf_dir_exists_in(&net.0, *dir))
                .map(|(n, ..)| NetConf(*v6, *dir, n.as_bytes(), net.clone())),
            SysRoot => tree_lookup(&SYS_STATIC, b"", name)
                .or_else(|| {
                    self.k
                        .gpu
                        .as_ref()
                        .and_then(|_| tree_lookup(SYS_GPU, b"", name))
                })
                .map(Sys),
            Sys(path) => tree_lookup(&SYS_STATIC, path, name)
                .or_else(|| {
                    self.k
                        .gpu
                        .as_ref()
                        .and_then(|_| tree_lookup(SYS_GPU, path, name))
                })
                .map(Sys)
                .or_else(|| {
                    if *path == SYS_NET_DIR {
                        return crate::netdev::interfaces(&self.sys_net_ns(mnt))
                            .into_iter()
                            .find(|i| i.name.as_bytes() == name)
                            .map(|i| SysNet(i.index, b""));
                    }
                    if *path == SYS_BLOCK_DIR {
                        let n = name.strip_prefix(b"loop").and_then(parse_num)?;
                        let n = u32::try_from(n).ok()?;
                        return self
                            .k
                            .loops
                            .sysfs_exists(n, b"")
                            .then_some(SysBlock(n, b""));
                    }
                    if *path == SYS_DEV_BLOCK_DIR {
                        let colon = name.iter().position(|&b| b == b':')?;
                        let major = parse_num(&name[..colon])?;
                        let minor = u32::try_from(parse_num(&name[colon + 1..])?).ok()?;
                        return (major == i64::from(LOOP_MAJOR)
                            && self.k.loops.sysfs_exists(minor, b""))
                        .then_some(SysDevBlock(minor));
                    }
                    let n = name.strip_prefix(b"cpu").and_then(parse_num)?;
                    let n = u32::try_from(n).ok().filter(|&n| (n as usize) < cpus())?;
                    (*path == SYS_CPU_DIR).then_some(SysCpu(n, b""))
                }),
            // A child cgroup, or a file this cgroup has
            Cgroup(id, b"", 0) => self.k.cgroups.get(*id).and_then(|g| {
                g.children
                    .get(name)
                    .map(|&c| Cgroup(c, b"", 0))
                    .or_else(|| {
                        self.k.cgroups.files(*id).find(|(f, _)| *f == name).map(
                            |(f, generation)| {
                                self.k.cgroups.file_looked_up(*id, f);
                                Cgroup(*id, f, generation)
                            },
                        )
                    })
            }),
            SysCpu(n, path) => tree_lookup(&CPU_FILES, path, name)
                .or_else(|| {
                    tree_lookup(&HOST_CPU_FILES, path, name).filter(|p| host_cpu_has(*n, p))
                })
                .map(|p| SysCpu(*n, p)),
            SysNet(n, b"brif/") => crate::netdev::views(&self.sys_net_ns(mnt))
                .into_iter()
                .find(|v| v.master == Some(*n) && v.name == name)
                .map(|v| SysBrif(*n, v.index)),
            SysBlock(n, path) => tree_lookup(&BLOCK_FILES, path, name)
                .filter(|p| self.k.loops.sysfs_exists(*n, p))
                .map(|p| SysBlock(*n, p)),
            SysNet(n, path) => tree_lookup(&NET_FILES, path, name)
                .filter(|_| self.interface(mnt, *n).is_some())
                .or_else(|| {
                    let (bridge, port) = self.bridge_roles(mnt, *n);
                    tree_lookup(&BRIDGE_FILES, path, name)
                        .filter(|_| bridge)
                        .or_else(|| tree_lookup(&PORT_FILES, path, name).filter(|_| port))
                })
                .map(|p| SysNet(*n, p)),
            Pid(proc, tid) => {
                let allowed = |e: &self::Entry| in_pid_dir(*tid, e);
                ENTRIES
                    .iter()
                    .find(|(n, e)| *n == name && allowed(e))
                    .map(|(_, e)| Entry(*proc, *tid, *e))
                    .filter(|_| self.pid_exists(*proc, *tid))
            }
            // fd and fdinfo follow the thread's own fd table (which may differ from the group
            // leader's after clone without CLONE_FILES or unshare(CLONE_FILES))
            Entry(proc, tid, e @ (self::Entry::Fd | self::Entry::FdInfo)) => parse_num(name)
                .map(|fd| fd as i32)
                .filter(|&fd| self.open_file(*proc, *tid, fd).is_some())
                .map(|fd| match e {
                    self::Entry::Fd => Fd(*proc, *tid, fd),
                    _ => FdInfo(*proc, *tid, fd),
                }),
            Entry(proc, None, self::Entry::Task) => global(name)
                .filter(|&t| self.pid_exists(*proc, Some(t)))
                .map(|t| Pid(*proc, Some(t))),
            Entry(proc, tid, self::Entry::Net) => PROC_NET
                .iter()
                .find(|n| **n == name)
                .filter(|_| self.pid_exists(*proc, *tid))
                .map(|n| Net(*proc, *tid, n)),
            Entry(proc, tid, self::Entry::Ns) => NsKind::ALL
                .into_iter()
                .find(|k| k.name().as_bytes() == name)
                .filter(|_| self.pid_exists(*proc, *tid))
                .map(|k| Ns(*proc, *tid, k)),
            _ => return Err(Errno::ENOTDIR),
        };
        found.ok_or(Errno::ENOENT)
    }

    fn missing(&self, dir: &Node, name: &[u8]) {
        if let Some(path) = self.missing_path(dir, name) {
            let task = self.k.tasks.get(&self.tid).map(|t| &**t);
            crate::stub::record(self.k, task, self.tgid, crate::stub::Stub::Missing(path));
        }
    }

    fn kind(&self, node: &PseudoNode) -> Result<u32, Errno> {
        use PseudoNode::*;
        Ok(match node {
            PtsRoot(_) | ProcRoot | Pid(..) | SysRoot | MqRoot(_) => mode::S_IFDIR,
            Mq(..) => mode::S_IFREG,
            Sys(b"dev/char/226:128/device/subsystem") => mode::S_IFLNK,
            Static(p) | Sys(p) if p.ends_with(b"/") => mode::S_IFDIR,
            SysCpu(_, p) | SysNet(_, p) | SysBlock(_, p) if p.is_empty() || p.ends_with(b"/") => {
                mode::S_IFDIR
            }
            Cgroup(_, b"", 0) => mode::S_IFDIR,
            NetStatic(..) | NetSysctl(..) | IpcSysctl(..) | UtsSysctl(..) | PidSysctl(..) => {
                mode::S_IFREG
            }
            NetConf(_, dir, name, net) => {
                if !Self::conf_dir_exists_in(&net.0, *dir) {
                    return Err(Errno::ENOENT);
                }
                if name.is_empty() {
                    mode::S_IFDIR
                } else {
                    mode::S_IFREG
                }
            }
            Entry(
                _,
                _,
                self::Entry::Fd
                | self::Entry::FdInfo
                | self::Entry::Task
                | self::Entry::Net
                | self::Entry::Ns,
            ) => mode::S_IFDIR,
            Pts(..) | PtsPtmx(_) => mode::S_IFCHR,
            SelfLink | ThreadSelf | Fd(..) | Ns(..) | SysBrif(..) | SysDevBlock(_) => mode::S_IFLNK,
            Global(self::Global::Mounts | self::Global::Net) => mode::S_IFLNK,
            Entry(_, _, self::Entry::Cwd | self::Entry::Exe | self::Entry::Root) => mode::S_IFLNK,
            OpenFd(proc, tid, fd) => {
                let file = self.open_file(*proc, *tid, *fd).ok_or(Errno::ENOENT)?;
                let f = file.borrow();
                match &f.kind {
                    FileKind::Pipe(_) => mode::S_IFIFO,
                    FileKind::Socket(_) => mode::S_IFSOCK,
                    FileKind::Host(fd) => {
                        appine_hal::fstat(*fd).map_err(Errno)?.st_mode as u32 & mode::S_IFMT
                    }
                    _ => mode::S_IFREG,
                }
            }
            _ => mode::S_IFREG,
        })
    }

    fn readlink(&self, mnt: MountId, node: &PseudoNode) -> Result<Vec<u8>, Errno> {
        use PseudoNode::*;
        // Readers not visible in the mount's pid namespace have no self or thread-self (ENOENT)
        let ns = || self.pid_ns(mnt);
        match node {
            Sys(b"dev/char/226:128/device/subsystem") => Ok(b"/sys/bus/platform".to_vec()),
            SelfLink => Ok(ns()
                .vnr(self.tgid)
                .ok_or(Errno::ENOENT)?
                .to_string()
                .into_bytes()),
            ThreadSelf => {
                let ns = ns();
                let (tgid, tid) = (ns.vnr(self.tgid), ns.vnr(self.tid));
                let (Some(tgid), Some(tid)) = (tgid, tid) else {
                    return Err(Errno::ENOENT);
                };
                Ok(format!("{tgid}/task/{tid}").into_bytes())
            }
            Global(self::Global::Mounts) => Ok(b"self/mounts".to_vec()),
            Global(self::Global::Net) => Ok(b"self/net".to_vec()),
            Entry(proc, tid, self::Entry::Root) => {
                let task = self.task(*proc, *tid).ok_or(Errno::ENOENT)?;
                if !self.may_read(*proc, *tid) {
                    return Err(Errno::EACCES);
                }
                let root = task.res.borrow().fs.borrow().root.clone();
                self.vfs.path_of(self, &self.root(), &root)
            }
            // As with root and cwd, the reader must be able to see that process (Linux's
            // proc_pid_readlink and proc_pid_get_link both check proc_fd_access_allowed first).
            // After the program file is deleted it gets ` (deleted)`, as with fds
            Entry(proc, tid, self::Entry::Exe) => {
                let g = self.group(*proc).ok_or(Errno::ENOENT)?;
                if !self.may_read(*proc, *tid) {
                    return Err(Errno::EACCES);
                }
                // The program is the thread's address space's: an exited thread (the main thread
                // of a process living on, a zombie) has none
                if self.task(*proc, *tid).is_none() {
                    return Err(Errno::ENOENT);
                }
                let exe = g.borrow().exe.clone().ok_or(Errno::ENOENT)?;
                let path = exe.path.to_vec();
                Ok(match (exe.node, &exe.ovl) {
                    (Some((_, ino)), _) => mark_deleted(self.vfs.store(), ino, path),
                    // An overlay program whose name was removed
                    (None, Some((_, o, _))) if !self.vfs.overlay().linked(*o) => with_deleted(path),
                    _ => path,
                })
            }
            Entry(proc, tid, self::Entry::Cwd) => {
                let task = self.task(*proc, *tid).ok_or(Errno::ENOENT)?;
                if !self.may_read(*proc, *tid) {
                    return Err(Errno::EACCES);
                }
                let cwd = task.res.borrow().fs.borrow().cwd.clone();
                self.vfs.path_of(self, &self.root(), &cwd)
            }
            Fd(proc, tid, fd) => {
                let file = self.open_file(*proc, *tid, *fd).ok_or(Errno::ENOENT)?;
                if !self.may_read(*proc, *tid) {
                    return Err(Errno::EACCES);
                }
                let f = file.borrow();
                let name = self.fd_path(&f).unwrap_or_else(|| describe(&f));
                if f.dentry_unlinked() {
                    return Ok(with_deleted(name));
                }
                Ok(match &f.kind {
                    FileKind::Regular { ino, .. } => mark_deleted(self.vfs.store(), *ino, name),
                    _ => name,
                })
            }
            Ns(proc, tid, k) => {
                let task = self.task(*proc, *tid).ok_or(Errno::ENOENT)?;
                if !self.may_read(*proc, *tid) {
                    return Err(Errno::EACCES);
                }
                let id = k.id_of(self.k, &task).ok_or(Errno::ENOENT)?;
                Ok(self.name(mnt, &NsFile(*k, id)))
            }
            SysBrif(_, p) => {
                let i = self.interface(mnt, *p).ok_or(Errno::ENOENT)?;
                Ok(format!("../../{}/brport", i.name).into_bytes())
            }
            SysDevBlock(n) => {
                if !self.k.loops.sysfs_exists(*n, b"") {
                    return Err(Errno::ENOENT);
                }
                Ok(format!("../../block/loop{n}").into_bytes())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn follow_dentry(&self, node: &PseudoNode) -> Option<crate::vfs::WalkDentry> {
        if let PseudoNode::Entry(proc, _, Entry::Exe) = node {
            return Some(crate::vfs::WalkDentry {
                entry: self.group(*proc)?.borrow().exe.as_ref()?.dentry.clone()?,
                unlinked: false,
            });
        }
        let PseudoNode::Fd(proc, tid, fd) = node else {
            return None;
        };
        let file = self.open_file(*proc, *tid, *fd)?;
        let f = file.borrow();
        // Only files that are not directories want it (a directory's path is derived from its
        // parent)
        let dir = match &f.kind {
            FileKind::Path(n) => self.vfs.is_dir(self, n).unwrap_or(true),
            FileKind::Directory { .. } => true,
            _ => false,
        };
        Some(crate::vfs::WalkDentry {
            entry: f.current_dentry().filter(|_| !dir)?,
            unlinked: f.dentry_unlinked(),
        })
    }

    /// `/proc/<pid>/fd/<n>`, `ns/*`, `root`, `cwd`, `exe` (Linux's proc_pid_get_link and
    /// proc_ns_get_link both go through nd_jump_link). `/proc/self` and `thread-self` are ordinary
    /// links.
    fn magic(&self, node: &PseudoNode) -> bool {
        matches!(
            node,
            PseudoNode::Fd(..)
                | PseudoNode::Ns(..)
                | PseudoNode::Entry(_, _, Entry::Root | Entry::Cwd | Entry::Exe)
        )
    }

    fn protected_symlinks(&self) -> bool {
        self.k.protected_symlinks
    }

    /// A cgroup directory is searched by its mode, as kernfs checks it (mkdir gives it one).
    fn searched(&self, node: &PseudoNode) -> Option<Stat> {
        matches!(node, PseudoNode::Cgroup(_, b"", 0)).then(|| stat(self, node).ok())?
    }

    fn follow(&self, mnt: MountId, node: &PseudoNode) -> Option<Result<Node, Errno>> {
        match node {
            PseudoNode::Ns(proc, tid, k) => {
                let task = self.task(*proc, *tid)?;
                if !self.may_read(*proc, *tid) {
                    return Some(Err(Errno::EACCES));
                }
                let Some(id) = k.id_of(self.k, &task) else {
                    return Some(Err(Errno::ENOENT));
                };
                return Some(Ok(Node::Pseudo(mnt, PseudoNode::NsFile(*k, id))));
            }
            // The root and current directories point straight at that process's nodes (Linux's
            // proc_root_link, proc_cwd_link): through them one can get into other mount
            // namespaces and outside a chroot
            PseudoNode::Entry(proc, tid, e @ (Entry::Root | Entry::Cwd)) => {
                let task = self.task(*proc, *tid)?;
                if !self.may_read(*proc, *tid) {
                    return Some(Err(Errno::EACCES));
                }
                let res = task.res.borrow();
                let fs = res.fs.borrow();
                return Some(Ok(match e {
                    Entry::Root => fs.root.clone(),
                    _ => fs.cwd.clone(),
                }));
            }
            // The program file itself (Linux's proc_exe_link): still the original after being
            // renamed, deleted or replaced. A deleted one's object in the store is deleted too,
            // so it is opened through the recorded host file (OpenExe). Without a store (host
            // files for development) it is followed by the path read back
            PseudoNode::Entry(proc, tid, Entry::Exe) => {
                let g = self.group(*proc)?;
                if !self.may_read(*proc, *tid) {
                    return Some(Err(Errno::EACCES));
                }
                let exe = g.borrow().exe.clone();
                let Some(exe) = exe.filter(|_| self.task(*proc, *tid).is_some()) else {
                    return Some(Err(Errno::ENOENT));
                };
                // A deleted overlay executable keeps both its overlay identity and its host file.
                if let Some((m, o, _)) = &exe.ovl {
                    return Some(if self.vfs.overlay().linked(*o) {
                        Ok(Node::Overlay(*m, *o))
                    } else if exe.host.is_some() {
                        Ok(Node::Pseudo(mnt, PseudoNode::OpenExe(*proc)))
                    } else {
                        Err(Errno::ENOENT)
                    });
                }
                let (m, ino) = exe.node?;
                let deleted = self.vfs.store().attrs(ino).map_or(true, |st| st.nlink == 0);
                return Some(Ok(if deleted && exe.host.is_some() {
                    Node::Pseudo(mnt, PseudoNode::OpenExe(*proc))
                } else {
                    Node::Store(m, ino)
                }));
            }
            PseudoNode::Fd(proc, tid, _)
                if self.pid_exists(*proc, *tid) && !self.may_read(*proc, *tid) =>
            {
                return Some(Err(Errno::EACCES));
            }
            _ => {}
        }
        self.follow_fd(mnt, node).map(Ok)
    }
}

impl View<'_> {
    /// The path counted as unimplemented when path resolution finds no `name` in `dir`
    /// ([`Pseudo::missing`], Starnix's `not_found`): names Linux would have in the fixed parts of
    /// procfs and sysfs and in the `/dev` mounted at boot, with the numbers of processes, threads,
    /// CPUs, interfaces and loop devices replaced by placeholders. None where the absence is a
    /// fact rather than a gap: a process, thread, fd, terminal, message queue, cgroup, interface,
    /// CPU or loop device that does not exist, the files of a process that has gone, anything
    /// under a cgroup (the root and the other cgroups have different files) or outside these
    /// filesystems.
    fn missing_path(&self, dir: &Node, name: &[u8]) -> Option<String> {
        use PseudoNode::*;
        let numbered = |prefix: &[u8]| {
            name.strip_prefix(prefix)
                .is_some_and(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit))
        };
        let pid_dir = |tid: Option<Tid>| match tid {
            Some(_) => "/proc/<pid>/task/<tid>",
            None => "/proc/<pid>",
        };
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let name_text = text(name);
        let node = match dir {
            Node::Store(mnt, _) => {
                let dev = *mnt == crate::vfs::DEV_MOUNT
                    && self.vfs.mount_root(dir) == Some(crate::vfs::DEV_MOUNT);
                return dev.then(|| format!("/dev/{name_text}"));
            }
            Node::Pseudo(_, p) => p,
            Node::Overlay(..) | Node::Fuse(..) => return None,
        };
        Some(match node {
            ProcRoot if numbered(b"") => return None,
            ProcRoot => format!("/proc/{name_text}"),
            // Interfaces
            Static(path) if *path == NET_CONF4 || *path == NET_CONF6 => {
                return None;
            }
            Static(path) => format!("/proc/{}{name_text}", text(path)),
            NetConf(v6, _, b"", _) => {
                let v = if *v6 { 6 } else { 4 };
                format!("/proc/sys/net/ipv{v}/conf/<interface>/{name_text}")
            }
            Pid(pid, tid) if self.pid_exists(*pid, *tid) => {
                format!("{}/{name_text}", pid_dir(*tid))
            }
            Entry(pid, tid, self::Entry::Net) if self.pid_exists(*pid, *tid) => {
                format!("{}/net/{name_text}", pid_dir(*tid))
            }
            Entry(pid, tid, self::Entry::Ns) if self.pid_exists(*pid, *tid) => {
                format!("{}/ns/{name_text}", pid_dir(*tid))
            }
            SysRoot => format!("/sys/{name_text}"),
            // Interfaces, loop devices, CPUs
            Sys(SYS_NET_DIR | SYS_BLOCK_DIR | SYS_DEV_BLOCK_DIR) => return None,
            Sys(path) if *path == SYS_CPU_DIR && numbered(b"cpu") => return None,
            Sys(path) => format!("/sys/{}{name_text}", text(path)),
            SysCpu(_, path) => {
                format!("/sys/devices/system/cpu/cpu<n>/{}{name_text}", text(path))
            }
            // Bridge ports
            SysNet(_, b"brif/") => return None,
            SysNet(_, path) => format!("/sys/class/net/<interface>/{}{name_text}", text(path)),
            SysBlock(_, path) => format!("/sys/block/loop<n>/{}{name_text}", text(path)),
            _ => return None,
        })
    }

    /// Whether the reader may look at the root directory, current directory, program file, fds and
    /// namespaces of thread `tid` (or `proc.pid`) (Linux's
    /// `ptrace_may_access(PTRACE_MODE_READ_FSCREDS)`).
    fn may_read(&self, proc: ProcId, tid: Option<Tid>) -> bool {
        self.may_read_as(proc, tid, &self.reader())
    }

    /// [`View::may_read`] with the credentials `reader`.
    fn may_read_as(&self, proc: ProcId, tid: Option<Tid>, reader: &Cred) -> bool {
        let target = tid.unwrap_or(proc.pid);
        self.group(proc).is_some_and(|g| {
            let g = g.borrow();
            g.tgid == self.tgid
                || self
                    .k
                    .cred_of(target)
                    .is_some_and(|c| reader.may_ptrace(&c, g.dump_scope(), true))
        })
    }

    /// Current path of a named fd relative to the reader's root.
    fn fd_path(&self, f: &OpenFile) -> Option<Vec<u8>> {
        f.path.as_ref()?;
        let node = f.node()?;
        if matches!(node, Node::Pseudo(..)) {
            return None;
        }
        let root = self.root();
        let entry = f.current_dentry();
        match entry.as_ref() {
            // A mount root takes its name from the mount point.
            Some((dir, _)) if dir.mnt() != node.mnt() => self.vfs.path_of(self, &root, &node),
            found => self.vfs.found_path(self, &root, &node, found),
        }
        .ok()
    }

    /// The node reached by following `/proc/<pid>/fd/<n>` ([`Pseudo::follow`]).
    fn follow_fd(&self, mnt: MountId, node: &PseudoNode) -> Option<Node> {
        let PseudoNode::Fd(proc, tid, fd) = node else {
            return None;
        };
        let file = self.open_file(*proc, *tid, *fd)?;
        let f = file.borrow();
        // A file opened through an overlay leads back to its overlay node, never to the store
        // inode behind it (which may be in a lower layer)
        if let Some(o) = f.ovl {
            let ovl = self.vfs.overlay();
            // If the last upper link is gone, only the retained fd can supply its bytes.
            if self.opening
                && !ovl.linked(o)
                && ovl.node(o).upper.is_some()
                && f.regular_backing().is_some_and(|(ino, ..)| {
                    self.vfs.store().attrs(ino).is_ok_and(|st| st.nlink == 0)
                })
            {
                return Some(Node::Pseudo(mnt, PseudoNode::OpenFd(*proc, *tid, *fd)));
            }
            return Some(Node::Overlay(f.mnt, o));
        }
        // A deleted object can only be reopened through the handle this description holds.
        if let Some((ino, ..)) = f.regular_backing()
            && self.vfs.store().attrs(ino).is_ok_and(|st| st.nlink == 0)
        {
            return Some(Node::Pseudo(mnt, PseudoNode::OpenFd(*proc, *tid, *fd)));
        }
        Some(match &f.kind {
            FileKind::Regular { ino, .. } | FileKind::Device { ino, .. } => {
                Node::Store(f.mnt, *ino)
            }
            FileKind::Directory { node, .. } | FileKind::Path(node) => node.clone(),
            FileKind::Proc { mnt, node, .. } => Node::Pseudo(*mnt, node.clone()),
            // A slave device: its path in the devpts mount it was opened through (or the opened
            // `/dev/tty` / `/dev/console` node when the open file carries one)
            FileKind::Pty(end) if !end.master => f.node().unwrap_or_else(|| {
                let t = end.tty.borrow();
                Node::Pseudo(end.mnt, PseudoNode::Pts(t.fs, t.index))
            }),
            _ => Node::Pseudo(mnt, PseudoNode::OpenFd(*proc, *tid, *fd)),
        })
    }
}

/// The last pid allocated in `ns` (the root namespace lives on `Kernel`).
fn last_pid_in(k: &Kernel, ns: &PidNs) -> Tid {
    if ns.level == 0 {
        k.last_pid()
    } else {
        ns.last_pid()
    }
}

/// A number naming a pid or fd directory entry (Linux's `name_to_int`): decimal digits only, no
/// sign and no leading zero; anything above `i32::MAX` names nothing (no pid or fd is that large,
/// and it must not wrap to a small one).
fn parse_num(name: &[u8]) -> Option<i64> {
    if name.is_empty()
        || name.len() > 10
        || (name.len() > 1 && name[0] == b'0')
        || !name.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let n: i64 = std::str::from_utf8(name).ok()?.parse().ok()?;
    (n <= i64::from(i32::MAX)).then_some(n)
}

/// The target `/proc/<pid>/fd/<n>` shows: a path, or a description like `pipe:[ino]`.
pub(crate) fn describe(f: &OpenFile) -> Vec<u8> {
    if let Some(p) = &f.path {
        return p.to_vec();
    }
    match &f.kind {
        FileKind::Pipe(end) => format!("pipe:[{}]", end.pipe.borrow().ino).into_bytes(),
        FileKind::Pty(end) if end.master => b"/dev/ptmx".to_vec(),
        FileKind::Pty(end) => format!("/dev/pts/{}", end.tty.borrow().index).into_bytes(),
        FileKind::Socket(s) => format!("socket:[{}]", socket_ino(s)).into_bytes(),
        FileKind::Epoll(_) => b"anon_inode:[eventpoll]".to_vec(),
        FileKind::EventFd(_) => b"anon_inode:[eventfd]".to_vec(),
        FileKind::Inotify(_) => b"anon_inode:inotify".to_vec(),
        FileKind::Pidfd(_) => b"anon_inode:[pidfd]".to_vec(),
        FileKind::SeccompNotify(_) => b"anon_inode:seccomp notify".to_vec(),
        FileKind::Bpf(_) => b"anon_inode:bpf-prog".to_vec(),
        FileKind::TimerFd(_) => b"anon_inode:[timerfd]".to_vec(),
        FileKind::SignalFd(_) => b"anon_inode:[signalfd]".to_vec(),
        FileKind::Host(fd) => std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map(|p| {
                use std::os::unix::ffi::OsStringExt;
                p.into_os_string().into_vec()
            })
            .unwrap_or_else(|_| format!("host:[{fd}]").into_bytes()),
        _ => b"anon_inode:[unknown]".to_vec(),
    }
}

// ---- stat and readdir ----

/// The metadata of a synthetic node.
pub(crate) fn stat(ps: &View<'_>, node: &PseudoNode) -> Result<Stat, Errno> {
    // mqueue filesystem: owners, permissions and times are kept on the queues and the namespace
    match node {
        PseudoNode::Cgroup(id, name, _) => {
            if gone(ps.k, node) {
                return Err(Errno::ENODEV);
            }
            let mut st = ps.k.cgroups.get(*id).ok_or(Errno::ENOENT)?.attrs(name)?;
            st.ino = node_ino(node);
            return Ok(st);
        }
        PseudoNode::MqRoot(ns) => {
            let (_, ipc) = ps.k.ipcs.get(ns).ok_or(Errno::ENOENT)?;
            let mut st = ipc.mq_dir.borrow().stat(ipc.mqueues.len());
            st.ino = ino_of(node);
            return Ok(st);
        }
        PseudoNode::Mq(ns, ino) => {
            let (_, ipc) = ps.k.ipcs.get(ns).ok_or(Errno::ENOENT)?;
            let (_, q) = crate::syscall::mqueue_find(ipc, *ino).ok_or(Errno::ENOENT)?;
            return Ok(q.borrow().stat());
        }
        _ => {}
    }
    let kind = ps.kind(node)?;
    let sysfs = matches!(fs_of(node), Fs::Sys | Fs::Cgroup);
    let perm = match (kind, node) {
        (mode::S_IFDIR, _) if sysfs => 0o755,
        (mode::S_IFDIR, PseudoNode::PtsRoot(_)) => 0o755,
        (mode::S_IFDIR, PseudoNode::Entry(_, _, Entry::Fd | Entry::FdInfo | Entry::Ns)) => 0o500,
        (mode::S_IFDIR, _) => 0o555,
        // proc_fd_instantiate: read and search bits for a readable file, write and search for a
        // writable one (none for O_PATH)
        (_, PseudoNode::Fd(proc, tid, fd)) => ps.open_file(*proc, *tid, *fd).map_or(0, |f| {
            let f = f.borrow();
            (if f.readable() { 0o500 } else { 0 }) | if f.writable() { 0o300 } else { 0 }
        }),
        (mode::S_IFLNK, _) => 0o777,
        (_, PseudoNode::Pts(fs, n)) => pty(ps.k, *fs, *n).map_or(0o620, |t| t.borrow().mode),
        // ptmx's permission bits follow the instance's ptmxmode
        (_, PseudoNode::PtsPtmx(fs)) => {
            ps.k.vfs
                .as_ref()
                .map_or(0o666, |v| v.devpts_options(*fs).ptmxmode)
        }
        (_, PseudoNode::Entry(_, _, Entry::Mem)) => 0o600,
        (_, PseudoNode::NetSysctl(path, _)) => {
            u32::from(crate::netconf::sysctl(path.as_bytes(), true).map_or(0o444, |e| e.2))
        }
        (_, PseudoNode::Static(p)) if recorded(p).is_some() => recorded(p).map_or(0o444, |e| e.1),
        (_, n) if writable(n) => 0o644,
        (
            _,
            PseudoNode::Entry(_, _, Entry::Pagemap | Entry::Auxv | Entry::Environ | Entry::Syscall),
        ) => 0o400,
        (_, PseudoNode::Global(Global::Kmsg)) => 0o400,
        _ => 0o444,
    };
    let rdev_value = match node {
        PseudoNode::Pts(_, n) => rdev(PTS_MAJOR, *n),
        PseudoNode::PtsPtmx(_) => rdev(5, 2),
        _ => 0,
    };
    let now = crate::tty::wall_ns();
    let times = match node {
        PseudoNode::Pts(fs, n) => pty(ps.k, *fs, *n).map(|t| {
            let t = t.borrow();
            (t.atime_ns, t.mtime_ns, t.ctime_ns)
        }),
        _ => None,
    };
    let (atime_ns, mtime_ns, ctime_ns) = times.unwrap_or((now, now, now));
    // net.* sysctls belong to root of the user namespace owning the pinned network namespace,
    // when it maps one (net_ctl_set_ownership)
    let (uid, gid) = if let Some(owner) = pinned_net(node)
        .map(|n| n.0.owner.clone())
        .or_else(|| is_net_sysctl(node).then(|| ps.ns().net.owner.clone()))
    {
        (
            owner.uid_map.borrow().down(0).unwrap_or(0),
            owner.gid_map.borrow().down(0).unwrap_or(0),
        )
    } else {
        owner_of(ps.k, node)
    };
    // As in Linux's proc_task_getattr, the task directory's link count adds the number of
    // threads: Chromium's sandbox uses it to tell whether it is single-threaded, and the zygote
    // checks before fork that it is at least 3, crashing otherwise
    let nlink = match node {
        PseudoNode::Entry(pid, None, Entry::Task) => {
            2 + ps
                .group(*pid)
                .map_or(0, |g| thread_count(&g.borrow()) as u32)
        }
        _ if kind == mode::S_IFDIR => 2,
        _ => 1,
    };
    Ok(Stat {
        ino: node_ino(node),
        mode: kind | perm,
        nlink,
        uid,
        gid,
        rdev: rdev_value,
        // sysfs files report one page of size but take no blocks, as on Linux
        size: if sysfs && kind == mode::S_IFREG {
            4096
        } else {
            0
        },
        atime_ns,
        mtime_ns,
        ctime_ns,
        blocks: sysfs.then_some(0),
        ..Stat::default()
    })
}

/// The filesystem a node belongs to.
pub(crate) fn fs_of(node: &PseudoNode) -> Fs {
    match node {
        PseudoNode::PtsRoot(_) | PseudoNode::Pts(..) | PseudoNode::PtsPtmx(_) => Fs::Pts,
        PseudoNode::SysRoot
        | PseudoNode::Sys(_)
        | PseudoNode::SysCpu(..)
        | PseudoNode::SysNet(..)
        | PseudoNode::SysBrif(..)
        | PseudoNode::SysDevBlock(_)
        | PseudoNode::SysBlock(..) => Fs::Sys,
        PseudoNode::Cgroup(..) => Fs::Cgroup,
        PseudoNode::NsFile(..) => Fs::Nsfs,
        PseudoNode::MqRoot(_) | PseudoNode::Mq(..) => Fs::Mqueue,
        _ => Fs::Proc,
    }
}

/// For a node under `/proc/sys`, whether it is a `net.*` one; `None` for the rest of procfs.
/// Opening one follows `proc_sys_permission`'s rules.
pub(crate) fn sysctl_kind(node: &PseudoNode) -> Option<bool> {
    match node {
        PseudoNode::Static(p) if p.starts_with(b"sys/") => Some(is_net_sysctl(node)),
        PseudoNode::IpcSysctl(..) | PseudoNode::UtsSysctl(..) | PseudoNode::PidSysctl(..) => {
            Some(false)
        }
        PseudoNode::NetStatic(..) | PseudoNode::NetSysctl(..) | PseudoNode::NetConf(..) => {
            Some(true)
        }
        _ => None,
    }
}

/// The pinned network namespace of a `net.*` sysctl node, if any.
fn pinned_net(node: &PseudoNode) -> Option<&PinnedNet> {
    match node {
        PseudoNode::NetStatic(_, net)
        | PseudoNode::NetSysctl(_, net)
        | PseudoNode::NetConf(_, _, _, net) => Some(net),
        _ => None,
    }
}

/// A `net.*` sysctl (or directory) of a network namespace.
fn is_net_sysctl(node: &PseudoNode) -> bool {
    match node {
        PseudoNode::Static(p) => p.starts_with(b"sys/net/"),
        PseudoNode::NetStatic(..) | PseudoNode::NetSysctl(..) | PseudoNode::NetConf(..) => true,
        _ => false,
    }
}

/// A node's owner and group: under `/proc/<pid>` the effective user and group IDs of the thread
/// (`/proc/<pid>/task/<tid>`) or the main thread, for `/dev/pts/<n>` what is recorded on the
/// terminal ([`Tty::owner`]), and root for the rest.
fn owner_of(k: &Kernel, node: &PseudoNode) -> (u32, u32) {
    match node {
        // Files of a non-dumpable process belong to root in its user namespace (Linux's
        // task_dump_owner)
        PseudoNode::Pid(proc, tid)
        | PseudoNode::Entry(proc, tid, _)
        | PseudoNode::Fd(proc, tid, _)
        | PseudoNode::FdInfo(proc, tid, _)
        | PseudoNode::Ns(proc, tid, _) => dump_owner(k, *proc, *tid),
        PseudoNode::Pts(fs, n) => pty(k, *fs, *n).map_or((0, 0), |t| t.borrow().owner),
        _ => (0, 0),
    }
}

/// The owner of thread `tid` (or `proc.pid`)'s procfs files (Linux's `task_dump_owner`): its
/// effective user and group IDs, root in its user namespace when the process is not dumpable.
fn dump_owner(k: &Kernel, proc: ProcId, tid: Option<Tid>) -> (u32, u32) {
    let target = tid.unwrap_or(proc.pid);
    match (group_of_id(k, proc), k.cred_of(target)) {
        (Some(g), Some(c)) if g.borrow().dumpable => (c.euid, c.egid),
        (Some(_), Some(c)) => (c.uid_in(0).unwrap_or(0), c.gid_in(0).unwrap_or(0)),
        _ => (0, 0),
    }
}

/// The terminal of `/dev/pts/<n>`; None once it is closed.
pub(crate) fn pty(k: &Kernel, fs: u64, n: u32) -> Option<Rc<RefCell<Tty>>> {
    k.ptys.get(&(fs, n)).and_then(std::rc::Weak::upgrade)
}

/// The contents of a directory (without `.` and `..`).
pub(crate) fn readdir(
    ps: &View<'_>,
    mnt: MountId,
    dir: &PseudoNode,
) -> Result<Vec<DirEntry>, Errno> {
    use PseudoNode::*;
    let mut nodes: Vec<PseudoNode> = Vec::new();
    let ns = ps.pid_ns(mnt);
    match dir {
        MqRoot(ipc) => {
            if let Some((_, ipc_objects)) = ps.k.ipcs.get(ipc) {
                nodes.extend(
                    ipc_objects
                        .mqueues
                        .values()
                        .map(|q| Mq(*ipc, q.borrow().ino)),
                );
            }
        }
        PtsRoot(fs) => {
            nodes.push(PtsPtmx(*fs));
            nodes.extend(
                ps.k.ptys
                    .range((*fs, 0)..=(*fs, u32::MAX))
                    .filter(|(_, w)| w.upgrade().is_some())
                    .map(|((_, n), _)| Pts(*fs, *n)),
            );
        }
        ProcRoot => {
            nodes.extend([SelfLink, ThreadSelf]);
            nodes.extend(tree_children(&STATIC, b"").map(Static));
            nodes.extend(GLOBALS.iter().map(|(_, g)| Global(*g)));
            // Processes visible in the mount's pid namespace, sorted by their numbers there
            let mut pids: Vec<(Tid, ProcId)> =
                ps.k.groups
                    .iter()
                    .filter_map(|(&pid, g)| Some((ns.vnr(pid)?, ProcId::of(pid, &g.borrow()))))
                    .collect();
            pids.sort_unstable_by_key(|&(vnr, _)| vnr);
            nodes.extend(pids.into_iter().map(|(_, proc)| Pid(proc, None)));
        }
        Static(path) if *path == NET_CONF4 || *path == NET_CONF6 => {
            let v6 = *path == NET_CONF6;
            let net = ps.ns().net;
            nodes.extend(
                crate::netdev::conf_dirs(&net)
                    .into_iter()
                    .map(|(_, d)| NetConf(v6, d, b"", PinnedNet(net.clone()))),
            );
        }
        Static(path) => {
            nodes.extend(tree_children(&STATIC, path).map(|p| ps.static_node(p)));
            // The sysctls under /proc/sys/net/core, ipv4, ipv6 and unix
            if let Some(dir) = path.strip_prefix(b"sys/net/") {
                let net = ps.ns().net;
                let init = net.host_net.is_none();
                nodes.extend(
                    crate::netconf::SYSCTLS
                        .iter()
                        .filter(|(p, _, _, only)| {
                            (init || !only)
                                && p.as_bytes().starts_with(dir)
                                && !p.as_bytes()[dir.len()..].contains(&b'/')
                        })
                        .map(|e| NetSysctl(e.0, PinnedNet(net.clone()))),
                );
            }
        }
        NetConf(v6, dir, b"", net) => nodes.extend(
            crate::netconf::table(*v6)
                .iter()
                .map(|(n, ..)| NetConf(*v6, *dir, n.as_bytes(), net.clone())),
        ),
        SysRoot => {
            nodes.extend(tree_children(&SYS_STATIC, b"").map(Sys));
            if ps.k.gpu.is_some() {
                nodes.extend(tree_children(SYS_GPU, b"").map(Sys));
            }
        }
        Sys(path) => {
            nodes.extend(tree_children(&SYS_STATIC, path).map(Sys));
            if ps.k.gpu.is_some() {
                nodes.extend(tree_children(SYS_GPU, path).map(Sys));
            }
            if *path == SYS_CPU_DIR {
                nodes.extend((0..cpus() as u32).map(|n| SysCpu(n, b"")));
            }
            if *path == SYS_NET_DIR {
                nodes.extend(
                    crate::netdev::interfaces(&ps.sys_net_ns(mnt))
                        .iter()
                        .map(|i| SysNet(i.index, b"")),
                );
            }
            if *path == SYS_BLOCK_DIR {
                nodes.extend(ps.k.loops.numbers().into_iter().map(|n| SysBlock(n, b"")));
            }
            if *path == SYS_DEV_BLOCK_DIR {
                nodes.extend(ps.k.loops.numbers().into_iter().map(SysDevBlock));
            }
        }
        SysBlock(n, path) => nodes.extend(
            tree_children(&BLOCK_FILES, path)
                .filter(|p| ps.k.loops.sysfs_exists(*n, p))
                .map(|p| SysBlock(*n, p)),
        ),
        SysNet(n, b"brif/") => nodes.extend(
            crate::netdev::views(&ps.sys_net_ns(mnt))
                .into_iter()
                .filter(|v| v.master == Some(*n))
                .map(|v| SysBrif(*n, v.index)),
        ),
        SysNet(n, path) => {
            nodes.extend(tree_children(&NET_FILES, path).map(|p| SysNet(*n, p)));
            let (bridge, port) = ps.bridge_roles(mnt, *n);
            if bridge {
                nodes.extend(tree_children(&BRIDGE_FILES, path).map(|p| SysNet(*n, p)));
            }
            if port {
                nodes.extend(tree_children(&PORT_FILES, path).map(|p| SysNet(*n, p)));
            }
        }
        Cgroup(id, b"", 0) => {
            nodes.extend(
                ps.k.cgroups
                    .files(*id)
                    .map(|(f, generation)| Cgroup(*id, f, generation)),
            );
            if let Some(g) = ps.k.cgroups.get(*id) {
                nodes.extend(g.children.values().map(|&c| Cgroup(c, b"", 0)));
            }
        }
        SysCpu(n, path) => {
            nodes.extend(tree_children(&CPU_FILES, path).map(|p| SysCpu(*n, p)));
            nodes.extend(
                tree_children(&HOST_CPU_FILES, path)
                    .filter(|p| host_cpu_has(*n, p))
                    .map(|p| SysCpu(*n, p)),
            );
        }
        Entry(proc, tid, self::Entry::Net) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ENOENT);
            }
            nodes.extend(PROC_NET.iter().map(|n| Net(*proc, *tid, n)));
        }
        Entry(proc, tid, self::Entry::Ns) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ENOENT);
            }
            nodes.extend(NsKind::ALL.iter().map(|k| Ns(*proc, *tid, *k)));
        }
        Pid(proc, tid) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ENOENT);
            }
            nodes.extend(
                ENTRIES
                    .iter()
                    .filter(|(_, e)| in_pid_dir(*tid, e))
                    .map(|(_, e)| Entry(*proc, *tid, *e)),
            );
        }
        Entry(proc, tid, e @ (self::Entry::Fd | self::Entry::FdInfo)) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ENOENT);
            }
            if !ps.may_read(*proc, *tid) {
                return Err(Errno::EACCES);
            }
            if let Some(task) = ps.task(*proc, *tid) {
                let fds = task.res.borrow().fds.borrow().open_fds();
                nodes.extend(fds.into_iter().map(|fd| match e {
                    self::Entry::Fd => Fd(*proc, *tid, fd),
                    _ => FdInfo(*proc, *tid, fd),
                }));
            }
        }
        Entry(proc, None, self::Entry::Task) => {
            let g = ps.group(*proc).ok_or(Errno::ENOENT)?;
            let g = g.borrow();
            let zombie = g.leader_exit.is_some().then_some(g.tgid);
            nodes.extend(
                zombie
                    .into_iter()
                    .chain(g.threads.iter().copied())
                    .map(|t| Pid(*proc, Some(t))),
            );
        }
        _ => return Err(Errno::ENOTDIR),
    }
    nodes
        .into_iter()
        .map(|n| {
            Ok(DirEntry {
                name: ps.name(mnt, &n),
                ino: node_ino(&n),
                mode: ps.kind(&n).unwrap_or(mode::S_IFREG),
            })
        })
        .collect()
}

/// Whether `/proc/<pid>` (`tid` is None) or `/proc/<pid>/task/<tid>` has entry `e`: `children`
/// is only in the latter.
fn in_pid_dir(tid: Option<Tid>, e: &Entry) -> bool {
    match tid {
        None => *e != Entry::Children,
        Some(_) => TASK_ENTRIES.contains(e),
    }
}

/// The inode given by stat and readdir: for `/proc/<pid>` and the entries under it, [`ProcId`]
/// already carries the thread group's serial, so as on Linux the inode differs after a new
/// process reuses the pid and stays stable for a held fd after reap.
pub(crate) fn node_ino(node: &PseudoNode) -> u64 {
    match node {
        // A namespace's inode number is its id
        PseudoNode::NsFile(_, id) => *id,
        _ => ino_of(node),
    }
}

/// The inode number of a synthetic node: a hash of the node (stable within one run), avoiding 0.
/// Each filesystem's root directory is 1, as on Linux (procfs's `PROC_ROOT_INO`, the kernfs root,
/// the devpts root): runc checks it after opening `/proc` (pathrs-lite's `verifyProcRoot`) and
/// treats anything other than 1 as a replaced procfs. devpts follows Linux too: ptmx is 2, and
/// terminal n is n + 3.
pub(crate) fn ino_of(node: &PseudoNode) -> u64 {
    if matches!(
        node,
        PseudoNode::ProcRoot
            | PseudoNode::SysRoot
            | PseudoNode::PtsRoot(_)
            | PseudoNode::Cgroup(crate::cgroup::ROOT, b"", 0)
    ) {
        return 1;
    }
    match node {
        PseudoNode::PtsPtmx(_) => return 2,
        PseudoNode::Pts(_, n) => return *n as u64 + 3,
        _ => {}
    }
    // A queue uses its own number (it is also what fstat on an fd from mq_open shows)
    if let PseudoNode::Mq(_, ino) = node {
        return *ino;
    }
    // A namespace file's inode number is its namespace id (consistent with stat and node_ino).
    if let PseudoNode::NsFile(_, id) = node {
        return *id;
    }
    let mut h = std::hash::DefaultHasher::new();
    node.hash(&mut h);
    h.finish() | 1
}

// ---- File contents ----

/// Clock ticks (`sysconf(_SC_CLK_TCK)`).
const HZ: u64 = crate::loader::CLOCK_TICKS;

/// The procfs files that can be written.
pub(crate) fn writable(node: &PseudoNode) -> bool {
    if let PseudoNode::Cgroup(_, name, _) = node {
        return crate::cgroup::file_mode(name).is_some_and(|m| m & 0o200 != 0);
    }
    if let PseudoNode::NetConf(_, _, name, _) = node {
        return !name.is_empty() && !crate::netconf::read_only(name);
    }
    if let PseudoNode::NetSysctl(path, _) = node {
        return crate::netconf::sysctl(path.as_bytes(), true).is_some_and(|e| e.2 & 0o200 != 0);
    }
    if let PseudoNode::NetStatic(p, _) = node {
        return matches!(
            *p,
            b"sys/net/bridge/bridge-nf-call-iptables"
                | b"sys/net/core/somaxconn"
                | b"sys/net/ipv4/ip_forward"
                | b"sys/net/ipv4/ip_local_port_range"
                | b"sys/net/ipv4/ip_unprivileged_port_start"
                | b"sys/net/ipv4/ping_group_range"
        );
    }
    if matches!(
        node,
        PseudoNode::IpcSysctl(..) | PseudoNode::UtsSysctl(..) | PseudoNode::PidSysctl(..)
    ) {
        return true;
    }
    matches!(
        node,
        PseudoNode::Entry(_, None, Entry::CoredumpFilter | Entry::TimensOffsets)
            | PseudoNode::Entry(_, _, Entry::Comm | Entry::OomScoreAdj)
            | PseudoNode::Entry(_, _, Entry::Mem)
            | PseudoNode::Entry(_, _, Entry::UidMap | Entry::GidMap | Entry::Setgroups)
            | PseudoNode::Static(
                b"sys/kernel/pid_max"
                    | b"sys/kernel/threads-max"
                    | b"sys/kernel/core_pattern"
                    | b"sys/kernel/seccomp/actions_logged"
                    | b"sys/kernel/core_uses_pid"
                    | b"sys/kernel/dmesg_restrict"
                    | b"sys/kernel/panic"
                    | b"sys/kernel/unprivileged_bpf_disabled"
                    | b"sys/fs/protected_hardlinks"
                    | b"sys/fs/protected_symlinks"
                    | b"sys/kernel/printk"
                    | b"sys/kernel/printk_devkmsg"
                    | b"sys/fs/lease-break-time"
                    | b"sys/fs/aio-max-nr"
                    | b"sys/fs/mount-max"
                    | b"sys/fs/nr_open"
                    | b"sys/fs/pipe-max-size"
                    | b"sys/fs/inotify/max_queued_events"
                    | b"sys/fs/inotify/max_user_instances"
                    | b"sys/fs/inotify/max_user_watches"
                    | b"sys/vm/max_map_count"
                    | b"sys/vm/mmap_min_addr"
                    | b"sys/kernel/tainted"
                    | b"sys/kernel/modprobe"
                    | b"sys/vm/overcommit_memory"
            )
    ) || matches!(node, PseudoNode::Static(p)
        if p.starts_with(b"sys/user/max_") || recorded(p).is_some())
}

/// For a file that is not [`writable`] but that whoever passes its permission check (root, through
/// `CAP_DAC_OVERRIDE`) may still open for writing, the error each write then returns: procfs files
/// outside `/proc/sys`, as Linux's open checks only the mode there. Files of proc entries
/// (`/proc/cpuinfo`, `/proc/kmsg`, `/proc/sysvipc/*`, the single-record files of
/// `/proc/<pid>/net`) go through `proc_reg_write`, `EIO` without a write handler; per-process files
/// have no write operation, so `vfs_write` answers `EINVAL`. `None`: the open is refused
/// ([`open_unwritable`]).
pub(crate) fn unwritable_error(node: &PseudoNode) -> Option<Errno> {
    match node {
        PseudoNode::Global(_) => Some(Errno::EIO),
        PseudoNode::Net(_, _, name)
            if matches!(*name, b"netstat" | b"snmp" | b"sockstat" | b"sockstat6") =>
        {
            Some(Errno::EIO)
        }
        PseudoNode::Static(p) if p.starts_with(b"sysvipc/") => Some(Errno::EIO),
        PseudoNode::Entry(..) | PseudoNode::FdInfo(..) => Some(Errno::EINVAL),
        _ => None,
    }
}

/// An open asking for write permission (`for_write`: an access mode that writes, rather than
/// `O_TRUNC` alone) of a node that is not [`writable`], once its permission check has passed: Ok
/// opens it ([`unwritable_error`] says what its writes get), Err refuses it. `/proc/sys` decides by
/// the mode alone (`proc_sys_permission`, which refuses `O_TRUNC` too); sysfs (`kernfs_fop_open`)
/// and the other `/proc/<pid>/net` files (`seq_open_net`) refuse only an open for writing.
pub(crate) fn open_unwritable(node: &PseudoNode, for_write: bool) -> Result<(), Errno> {
    match node {
        PseudoNode::Static(p) if p.starts_with(b"sys/") => Err(Errno::EACCES),
        PseudoNode::NetStatic(..)
        | PseudoNode::IpcSysctl(..)
        | PseudoNode::UtsSysctl(..)
        | PseudoNode::PidSysctl(..)
        | PseudoNode::NetConf(..)
        | PseudoNode::NetSysctl(..) => Err(Errno::EACCES),
        _ if unwritable_error(node).is_some() || !for_write => Ok(()),
        _ => Err(Errno::EACCES),
    }
}

/// Files with a poll operation, which epoll accepts: procfs's global files, `/proc/sys`,
/// `/proc/sysvipc` and `/proc/<pid>/net` (`proc_reg_poll`, `proc_sys_poll`), mounts and mountinfo
/// (`mounts_poll`), and every sysfs and cgroup2 file (`kernfs_fop_poll`). The other per-process
/// files and nsfs have none (epoll_ctl's EPERM).
pub(crate) fn pollable(node: &PseudoNode) -> bool {
    use PseudoNode::*;
    matches!(
        node,
        Global(_)
            | Static(_)
            | NetStatic(..)
            | IpcSysctl(..)
            | UtsSysctl(..)
            | PidSysctl(..)
            | Net(..)
            | NetConf(..)
            | NetSysctl(..)
            | Entry(_, _, self::Entry::Mounts | self::Entry::MountInfo)
            | Sys(_)
            | SysCpu(..)
            | SysNet(..)
            | SysBlock(..)
            | Cgroup(..)
    )
}

/// Change-notification state attached to an open synthetic file (`open_pseudo`):
/// - `/proc/<pid>/mounts` and `mountinfo`: the target thread's mount namespace's event counter
///   (Linux's `mounts_open_common` -> `mnt_ns->event`),
/// - `/proc/sys/kernel/{hostname,domainname}`: the pinned UTS namespace's per-name counter
///   (Linux's `proc_uts_poll`),
/// - cgroup2 files: the cgroup file's observation counter (kernfs first-read rule),
/// - sysfs files: a constant kernfs counter (kernfs first-read rule).
pub(crate) fn poll_event(
    k: &mut Kernel,
    vfs: &Vfs,
    node: &PseudoNode,
) -> Option<crate::fd::ProcEvent> {
    match node {
        PseudoNode::Entry(proc, entry_tid, Entry::Mounts | Entry::MountInfo) => {
            let ns_id = group_of_id(k, *proc)
                .and_then(|g| {
                    let tgid = g.borrow().tgid;
                    let tid = entry_tid.unwrap_or(proc.pid);
                    k.tasks.get(&tid).filter(|t| t.tgid == tgid)
                })
                .map_or(crate::vfs::INIT_MNT_NS, |t| {
                    t.res.borrow().fs.borrow().mnt_ns.id
                });
            Some(crate::fd::ProcEvent::mounts(vfs.mount_events_of(ns_id)))
        }
        PseudoNode::UtsSysctl(path, uts) => {
            let counter = if *path == b"sys/kernel/hostname" {
                uts.0.hostname_event.clone()
            } else {
                uts.0.domainname_event.clone()
            };
            Some(crate::fd::ProcEvent::mounts(counter))
        }
        PseudoNode::Cgroup(id, name, _) if !name.is_empty() => Some(crate::fd::ProcEvent::kernfs(
            crate::cgroup::observe(k, *id, name)
                .unwrap_or_else(|| Rc::new(std::cell::Cell::new(1))),
        )),
        PseudoNode::Sys(_)
        | PseudoNode::SysCpu(..)
        | PseudoNode::SysNet(..)
        | PseudoNode::SysBlock(..) => Some(crate::fd::ProcEvent::kernfs(Rc::new(
            std::cell::Cell::new(1),
        ))),
        _ => None,
    }
}

/// Whether Linux 6.1 gives synthetic file `node` a `read_iter` (or, with `write`, a `write_iter`)
/// operation, required by native AIO (`io_submit` returns `EINVAL` without). Sysfs, cgroup2 and
/// `/proc/sys` (`kernfs_file_fops`, `proc_sys_file_operations`) implement both; procfs `seq_file`
/// views implement `read_iter` (`seq_read_iter`) only; `/proc/kmsg`, nsfs and custom procfs files
/// (`/proc/<pid>/mem`, `pagemap`, `cmdline`, `environ`, `auxv`, `oom_score_adj`,
/// `coredump_filter`) implement neither.
pub(crate) fn has_iter(node: &PseudoNode, write: bool) -> bool {
    use PseudoNode::*;
    match node {
        Sys(_) | SysCpu(..) | SysNet(..) | SysBlock(..) | Cgroup(..) | NetStatic(..)
        | IpcSysctl(..) | UtsSysctl(..) | PidSysctl(..) | NetConf(..) | NetSysctl(..) => true,
        Static(p) if p.starts_with(b"sys/") => true,
        Static(p) if p.starts_with(b"sysvipc/") => !write,
        Global(self::Global::Kmsg | self::Global::Mounts | self::Global::Net) => false,
        Global(_) | Net(..) | FdInfo(..) => !write,
        Entry(
            _,
            _,
            self::Entry::Mem
            | self::Entry::Pagemap
            | self::Entry::Cmdline
            | self::Entry::Environ
            | self::Entry::Auxv
            | self::Entry::OomScoreAdj
            | self::Entry::CoredumpFilter,
        ) => false,
        Entry(..) => !write,
        _ => false,
    }
}

/// Files that cannot be read: write-only cgroup files (`cgroup.kill`); as on Linux this is not
/// checked at open, and reading is EINVAL (`cgroup_seqfile_show` has no read callback).
pub(crate) fn unreadable(node: &PseudoNode) -> bool {
    matches!(node, PseudoNode::Cgroup(_, name, _)
        if crate::cgroup::file_mode(name).is_some_and(|m| m & 0o444 == 0))
        || matches!(node, PseudoNode::Static(b"sys/vm/drop_caches"))
}

/// The contents generated when a procfs file is opened.
pub(crate) fn content(ps: &View<'_>, mnt: MountId, node: &PseudoNode) -> Result<Vec<u8>, Errno> {
    use PseudoNode::*;
    let ns = ps.pid_ns(mnt);
    let s = match node {
        Global(g) => match g {
            self::Global::Cpuinfo => cpuinfo(),
            self::Global::Meminfo => meminfo(),
            self::Global::Vmstat => {
                vmstat(appine_hal::host_vmstat(), &appine_hal::host_meminfo())
            }
            // Like meminfo's swap lines, the host's (a container sees its host's); the guest cannot
            // swap on anything itself. Linux's swap_show header alone when the host hides it
            self::Global::Swaps => appine_hal::host_swaps().unwrap_or_else(|| {
                "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_owned()
            }),
            self::Global::Locks => crate::locks::proc_locks(ps.k, ps.vfs, &ns),
            self::Global::Stat => global_stat(ps),
            // Truncated to hundredths of a second, as in Linux's uptime_proc_show (rounding would
            // write x.996 seconds as the next second, more than sysinfo reports right after)
            self::Global::Uptime => {
                let hundredths =
                    |ns: u64| format!("{}.{:02}", ns / 1_000_000_000, ns / 10_000_000 % 100);
                // Idle time is not affected by the time namespace (Linux's uptime_proc_show)
                let idle = uptime_ns() * cpus() as u64;
                let up = ps.with_boot_offset(uptime_ns());
                format!("{} {}\n", hundredths(up), hundredths(idle))
            }
            self::Global::Loadavg => crate::loadavg::proc_loadavg(ps.k, ps.last_pid()),
            self::Global::Version => {
                "Linux version 6.1.0-appine (appine@localhost) #1 SMP PREEMPT appine\n".to_owned()
            }
            self::Global::Filesystems => {
                "nodev\tsysfs\nnodev\ttmpfs\n\text4\nnodev\tproc\nnodev\tdevpts\nnodev\tcgroup2\nnodev\tmqueue\nnodev\toverlay\nnodev\tfuse\n"
                    .to_owned()
            }
            self::Global::Cmdline => "appine\n".to_owned(),
            self::Global::Cgroups => crate::cgroup::proc_cgroups(ps.k),
            self::Global::Kmsg => String::new(),
            self::Global::Mounts | self::Global::Net => return Err(Errno::EINVAL),
        },
        // Those of the network namespace that process is in: the interfaces are the host's (lo in
        // a new one) plus virtual devices (crate::netdev), and only sockets created in it are
        // listed; in a new one the traffic and protocol counters are all 0 (crate::netns)
        Net(proc, tid, name) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ESRCH);
            }
            let full = ps
                .task(*proc, *tid)
                .map(|t| t.ns.borrow().net.clone())
                .or_else(|| {
                    let g = ps.group(*proc)?;
                    let g = g.borrow();
                    // Zombie leader: keep using the process's netns (prefer the leader's netns
                    // if still alive, else any live thread in the thread group) rather than
                    // falling back to the initial namespace.
                    g.leader_net
                        .as_ref()
                        .and_then(std::rc::Weak::upgrade)
                        .or_else(|| {
                            g.threads
                                .iter()
                                .find_map(|t| ps.k.tasks.get(t))
                                .map(|t| t.ns.borrow().net.clone())
                        })
                })
                .unwrap_or_else(|| ps.k.init_ns.net.clone());
            let net = Some(full.clone()).filter(|n| n.host_net.is_some());
            let id = net.as_ref().map_or(crate::nsproxy::INIT_NET_NS, |n| n.id);
            // The uid column is translated through the reader's user namespace (Linux's
            // seq_user_ns)
            let reader = ps.reader();
            let socks: Vec<(SocketRef, u32)> = sockets(ps.k)
                .into_iter()
                .filter_map(|s| {
                    let uid = {
                        let b = s.borrow();
                        if socket_net(&b) != id {
                            return None;
                        }
                        reader.uid_out(b.uid())
                    };
                    Some((s, uid))
                })
                .collect();
            let ifaces = crate::netdev::interfaces(&full);
            let world = ps.k.world();
            let quiet = crate::traffic::Protocols::default();
            let protocols = if net.is_some() {
                &quiet
            } else {
                &ps.k.traffic.protocols
            };
            let tables = || {
                let host = net.is_none().then(|| crate::route::host_routes(ps.k)).flatten();
                crate::netdev::tables(&full, host)
            };
            match &name[..] {
                b"arp" => crate::net::PROC_ARP.to_owned(),
                b"dev" => net_dev(ps.k, &ifaces, net.is_none()),
                b"netstat" => crate::net::proc_netstat(protocols),
                b"snmp" => {
                    let mut s = crate::net::proc_snmp(&socks, protocols);
                    // RFC 1213 ipForwarding: 1 when ip_forward is enabled in this netns, 2 when off
                    if crate::netdev::ip_forward(&full) != 0
                        && let Some(pos) = s.find("\nIp: 2 ")
                    {
                        s.replace_range(pos + 5..pos + 6, "1");
                    }
                    s
                }
                b"if_inet6" => net_if_inet6(&ifaces),
                b"route" => crate::route::proc_route(&tables()),
                b"ipv6_route" => crate::route::proc_ipv6_route(&tables()),
                b"sockstat" => crate::net::sockstat(&socks, false),
                b"sockstat6" => crate::net::sockstat(&socks, true),
                b"tcp" => crate::net::proc_listing(&socks, AF_INET, Table::Tcp, &ps.k.portmap, &world),
                b"tcp6" => crate::net::proc_listing(&socks, AF_INET6, Table::Tcp, &ps.k.portmap, &world),
                b"udp" => crate::net::proc_listing(&socks, AF_INET, Table::Udp, &ps.k.portmap, &world),
                b"udp6" => crate::net::proc_listing(&socks, AF_INET6, Table::Udp, &ps.k.portmap, &world),
                b"icmp" => crate::net::proc_listing(&socks, AF_INET, Table::Icmp, &ps.k.portmap, &world),
                b"icmp6" => crate::net::proc_listing(&socks, AF_INET6, Table::Icmp, &ps.k.portmap, &world),
                b"raw" => crate::net::proc_listing(&socks, AF_INET, Table::Raw, &ps.k.portmap, &world),
                b"raw6" => crate::net::proc_listing(&socks, AF_INET6, Table::Raw, &ps.k.portmap, &world),
                b"unix" => crate::unix::proc_listing(&socks),
                _ => return Err(Errno::ENOENT),
            }
        }
        NetStatic(path, net) => match &path[..] {
            b"sys/net/bridge/bridge-nf-call-iptables" => {
                format!("{}\n", u8::from(net.0.devs.borrow().conf.bridge_call_iptables))
            }
            b"sys/net/core/somaxconn" => format!("{}\n", net.0.devs.borrow().conf.somaxconn),
            b"sys/net/ipv4/ip_forward" => format!("{}\n", crate::netdev::ip_forward(&net.0)),
            b"sys/net/ipv4/ip_local_port_range" => {
                let (lo, hi) = net.0.devs.borrow().conf.port_range;
                format!("{lo}\t{hi}\n")
            }
            b"sys/net/ipv4/ip_unprivileged_port_start" => {
                format!("{}\n", net.0.devs.borrow().conf.prot_sock)
            }
            b"sys/net/ipv4/ping_group_range" => {
                // Kernel IDs, shown in the reader's namespace (65534 when unmapped)
                let (lo, hi) = net.0.devs.borrow().conf.ping_group;
                let r = ps.reader();
                format!("{}\t{}\n", r.gid_out(lo as u32), r.gid_out(hi as u32))
            }
            _ => return Err(Errno::EISDIR),
        },
        IpcSysctl(path, ipc) => {
            if let Some(name) = path.strip_prefix(b"sys/fs/mqueue/") {
                format!("{}\n", ps.k.ipc(ipc.0.id).mq_limits.get(name).unwrap_or(0))
            } else if let Some(name) = path.strip_prefix(b"sys/kernel/")
                && let Some(val) = ps.k.ipc(ipc.0.id).tunables.read(name)
            {
                val
            } else {
                return Err(Errno::EISDIR);
            }
        }
        UtsSysctl(path, uts) => match &path[..] {
            b"sys/kernel/domainname" => {
                format!("{}\n", String::from_utf8_lossy(&uts.0.domainname.borrow()))
            }
            b"sys/kernel/hostname" => {
                format!("{}\n", String::from_utf8_lossy(&uts.0.hostname.borrow()))
            }
            _ => return Err(Errno::EISDIR),
        },
        PidSysctl(b"sys/kernel/ns_last_pid", pid_ns) => {
            format!("{}\n", last_pid_in(ps.k, &pid_ns.0))
        }
        PidSysctl(..) => return Err(Errno::EISDIR),
        Static(path) => match &path[..] {
            b"sys/fs/file-max" => "9223372036854775807\n".to_owned(),
            b"sys/fs/lease-break-time" => format!("{}\n", ps.k.lease_break_time),
            b"sys/fs/aio-max-nr" => format!("{}\n", ps.k.aio_max_nr),
            b"sys/fs/aio-nr" => format!("{}\n", ps.k.aio_nr),
            b"sys/fs/inotify/max_queued_events" => {
                format!("{}\n", ps.k.inotify.borrow().max_queued)
            }
            b"sys/fs/inotify/max_user_instances" => {
                format!("{}\n", ps.k.inotify.borrow().max_instances)
            }
            b"sys/fs/inotify/max_user_watches" => {
                format!("{}\n", ps.k.inotify.borrow().max_watches)
            }
            b"sys/fs/nr_open" => format!("{}\n", ps.k.nr_open),
            b"sys/fs/mount-max" => format!("{}\n", ps.k.mount_max),
            b"sys/fs/pipe-max-size" => format!("{}\n", ps.k.pipe_max_size),
            b"sys/fs/pipe-user-pages-hard" => "0\n".to_owned(),
            b"sys/fs/pipe-user-pages-soft" => "16384\n".to_owned(),
            b"sys/kernel/cap_last_cap" => "40\n".to_owned(),
            b"sys/kernel/core_pattern" => {
                format!("{}\n", String::from_utf8_lossy(&ps.k.core_pattern))
            }
            b"sys/kernel/core_uses_pid" => format!("{}\n", ps.k.core_uses_pid as u8),
            b"sys/kernel/sched_rr_timeslice_ms" => "100\n".to_owned(),
            b"sysvipc/msg" | b"sysvipc/sem" | b"sysvipc/shm" => ipc::proc_listing(
                ps.k,
                ps.ns().ipc.id,
                &path[8..],
                &ps.reader(),
                &ps.k.pid_ns_of(ps.tgid),
            ),
            b"sys/kernel/tainted" => format!("{}\n", ps.k.tainted),
            b"sys/kernel/modprobe" => format!("{}\n", String::from_utf8_lossy(&ps.k.modprobe)),
            // Write-only (reading is EINVAL, `unreadable`)
            b"sys/vm/drop_caches" => String::new(),
            b"sys/kernel/threads-max" => format!("{}\n", ps.k.threads_max),
            b"sys/vm/max_map_count" => {
                format!(
                    "{}\n",
                    crate::mm::MAX_MAP_COUNT.load(std::sync::atomic::Ordering::Relaxed)
                )
            }
            b"sys/vm/mmap_min_addr" => {
                format!(
                    "{}\n",
                    crate::mm::MMAP_MIN_ADDR.load(std::sync::atomic::Ordering::Relaxed)
                )
            }
            b"sys/kernel/ngroups_max" => "65536\n".to_owned(),
            b"sys/kernel/seccomp/actions_avail" => crate::seccomp::actions_avail(),
            b"sys/kernel/seccomp/actions_logged" => crate::seccomp::actions_logged(ps.k),
            b"sys/kernel/osrelease" => "6.1.0-appine\n".to_owned(),
            b"sys/kernel/ostype" => "Linux\n".to_owned(),
            b"sys/kernel/pid_max" => format!("{}\n", ps.k.pid_max),
            b"sys/kernel/dmesg_restrict" => format!("{}\n", ps.k.dmesg_restrict as u8),
            b"sys/kernel/panic" => format!("{}\n", ps.k.panic),
            b"sys/kernel/unprivileged_bpf_disabled" => {
                format!("{}\n", ps.k.unprivileged_bpf_disabled)
            }
            b"sys/fs/protected_hardlinks" => format!("{}\n", ps.k.protected_hardlinks as u8),
            b"sys/fs/protected_symlinks" => format!("{}\n", ps.k.protected_symlinks as u8),
            b"sys/kernel/printk" => {
                let [a, b, c, d] = ps.k.printk;
                format!("{a}\t{b}\t{c}\t{d}\n")
            }
            b"sys/kernel/printk_devkmsg" => format!("{}\n", ps.k.klog.borrow().devkmsg.name()),
            // Limits on the namespaces of each kind created in the reader's user namespace and
            // below it (crate::nsproxy::Ucounts): half of threads-max in the initial one and
            // INT_MAX in the others unless written
            p if p.starts_with(b"sys/user/max_") => {
                let kind = crate::nsproxy::Counted::from_sysctl(&p[b"sys/user/".len()..])
                    .ok_or(Errno::ENOENT)?;
                let init = crate::nsproxy::default_ns_limit(ps.k.threads_max);
                let v = ps.k.ucounts.limit(ps.reader().user_ns.id, kind, init);
                format!("{v}\n")
            }
            b"sys/kernel/random/boot_id" => format!("{}\n", format_uuid(&ps.k.boot_id)),
            b"sys/kernel/random/entropy_avail" | b"sys/kernel/random/poolsize" => {
                format!("{}\n", crate::syscall::ENTROPY)
            }
            b"sys/kernel/random/uuid" => format!("{}\n", random_uuid()),
            b"sys/kernel/version" => "#1 SMP PREEMPT appine\n".to_owned(),
            b"sys/vm/overcommit_memory" => {
                format!(
                    "{}\n",
                    crate::mm::OVERCOMMIT_MEMORY.load(std::sync::atomic::Ordering::Relaxed)
                )
            }
            // The ID unmapped user and group IDs are shown as (Linux's default, 65534; bubblewrap
            // reads it at startup) and the other recorded sysctls
            p if recorded(p).is_some() => format!("{}\n", recorded_value(ps.k, p)),
            _ => return Err(Errno::EISDIR),
        },
        Entry(proc, tid, e) => {
            if !ps.pid_exists(*proc, *tid) {
                return Err(Errno::ESRCH);
            }
            let task = ps.task(*proc, *tid);
            match e {
                // These carry the thread's name as its bytes, which need not be UTF-8
                self::Entry::Stat => return pid_stat(ps, &ns, *proc, *tid),
                self::Entry::Status => return pid_status(ps, &ns, *proc, *tid),
                self::Entry::Statm => {
                    if let Some(t) = task.as_deref() {
                        let res = t.res.borrow();
                        let mm = res.mm.borrow();
                        let (anon, file, shmem) = mm.resident_split();
                        let shared = file + shmem;
                        let rss = anon + shared;
                        let layout = vm_layout(&mm);
                        let data_pages = (layout.data + layout.stack) / 4096;
                        format!(
                            "{} {rss} {shared} {} 0 {data_pages} 0\n",
                            layout.size / 4096,
                            layout.code_span / 4096,
                        )
                    } else {
                        "0 0 0 0 0 0 0\n".to_owned()
                    }
                }
                self::Entry::Comm => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    let mut name = comm_of(&g.borrow(), task.as_deref(), proc.pid, *tid);
                    name.push(b'\n');
                    return Ok(name);
                }
                // The thread's child processes not yet reaped, each followed by a space, with no
                // newline (Linux's children_seq_show)
                self::Entry::Children => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    let me = tid.unwrap_or(proc.pid);
                    let mut s = String::new();
                    for c in &g.borrow().children {
                        if ps
                            .k
                            .groups
                            .get(c)
                            .is_some_and(|g| g.borrow().parent_thread == me)
                        {
                            write!(s, "{} ", ns.vnr(*c).unwrap_or(0)).unwrap();
                        }
                    }
                    s
                }
                // Relative to the root of the reader's cgroup namespace
                self::Entry::Cgroup => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    let cgroup = g.borrow().cgroup;
                    crate::cgroup::proc_cgroup(ps.k, cgroup, ps.cgroup_root())
                }
                self::Entry::Cmdline => {
                    return Ok(task.map_or(Vec::new(), |t| guest_bytes(&t, |m| m.args)));
                }
                self::Entry::Environ => {
                    if !ps.may_read(*proc, *tid) {
                        return Err(Errno::EACCES);
                    }
                    return Ok(task.map_or(Vec::new(), |t| guest_bytes(&t, |m| m.env)));
                }
                self::Entry::Limits => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    limits(&g.borrow().rlimits)
                }
                self::Entry::Maps => task.map_or(String::new(), |t| maps(ps.vfs, &t)),
                self::Entry::Smaps => {
                    task.map_or(String::new(), |t| smaps(ps.vfs, &t, false))
                }
                self::Entry::SmapsRollup => {
                    task.map_or(String::new(), |t| smaps(ps.vfs, &t, true))
                }
                // Binary, computed from the read or write position (`read_pagemap`, `access_mem`).
                self::Entry::Pagemap | self::Entry::Mem => String::new(),
                self::Entry::Auxv => {
                    let auxv =
                        task.map_or_else(Vec::new, |t| t.res.borrow().mm.borrow().auxv.to_vec());
                    return Ok(auxv.iter().flat_map(|w| w.to_le_bytes()).collect());
                }
                self::Entry::Mounts | self::Entry::MountInfo => {
                    // An exited thread (a zombie, a main thread whose process lives on) has no
                    // namespaces left: EINVAL at open (mounts_open_common)
                    let t = task.ok_or(Errno::EINVAL)?;
                    let (root, ns) = {
                        let res = t.res.borrow();
                        let fs = res.fs.borrow();
                        (fs.root.clone(), fs.mnt_ns.id)
                    };
                    return Ok(mounts(ps, &root, ns, *e == self::Entry::MountInfo));
                }
                // Linux's proc_pid_syscall: "running" for a thread running guest code or kernel
                // code, and for one waiting in the kernel (or the reader itself) the syscall
                // number with x0 to x5, sp and pc, or a negative number with sp and pc outside a
                // syscall. An exited main thread (a zombie task on Linux) has no stack left: -1
                // with zeros; another thread that has gone is released at once (ESRCH). Like
                // lock_trace, it needs ptrace access to the thread itself, checked when read (open
                // generates nothing) with the reader's own credentials rather than the opener's
                self::Entry::Syscall => {
                    let me = ps.k.cred_of(ps.tid).unwrap_or_else(Cred::root);
                    let thread = tid.unwrap_or(proc.pid);
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    if task.is_none() && thread != g.borrow().tgid {
                        return Err(Errno::ESRCH);
                    }
                    if !ps.may_read_as(*proc, *tid, &me) {
                        return Err(Errno::EPERM);
                    }
                    let own = thread == ps.tid;
                    let running = task.is_some()
                        && !own
                        && state_of(ps, &g.borrow(), *proc, *tid).0 == 'R';
                    match task.as_deref().and_then(|t| t.sync.entry.get()) {
                        _ if running => "running\n".to_owned(),
                        Some([nr, a0, a1, a2, a3, a4, a5, sp, pc]) => {
                            // The number is the 32-bit w8, as arm64's syscallno is
                            let nr = nr as u32 as i32;
                            if nr < 0 {
                                format!("{nr} 0x{sp:x} 0x{pc:x}\n")
                            } else {
                                format!(
                                    "{nr} 0x{a0:x} 0x{a1:x} 0x{a2:x} 0x{a3:x} 0x{a4:x} 0x{a5:x} \
                                     0x{sp:x} 0x{pc:x}\n"
                                )
                            }
                        }
                        None => "-1 0x0 0x0\n".to_owned(),
                    }
                }
                self::Entry::OomScore => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    format!("{}\n", crate::oom::proc_score(ps.k, &g.borrow()))
                }
                self::Entry::OomScoreAdj => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    format!("{}\n", g.borrow().oom_score_adj)
                }
                // Linux's proc_timens_show_offsets: the one for children
                self::Entry::TimensOffsets => {
                    let t = task.ok_or(Errno::ESRCH)?;
                    let [mono, boot] = t.ns.borrow().time_for_children.offsets.get();
                    format!(
                        "{:<10} {:>10} {:>9}\n{:<10} {:>10} {:>9}\n",
                        "monotonic", mono.0, mono.1, "boottime", boot.0, boot.1
                    )
                }
                e @ (self::Entry::UidMap | self::Entry::GidMap | self::Entry::ProjidMap) => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    let ns = g.borrow().cred.user_ns.clone();
                    id_map(&ps.reader(), &ns, *e)
                }
                self::Entry::Setgroups => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    let allow = g.borrow().cred.user_ns.setgroups.get();
                    format!("{}\n", if allow { "allow" } else { "deny" })
                }
                self::Entry::CoredumpFilter => {
                    let g = ps.group(*proc).ok_or(Errno::ESRCH)?;
                    format!("{:08x}\n", g.borrow().coredump_filter)
                }
                _ => return Err(Errno::EINVAL),
            }
        }
        FdInfo(proc, tid, fd) => fdinfo(ps, &ns, *proc, *tid, *fd)?,
        Sys(path) => match &path[..] {
            b"dev/char/226:128/device/uevent" => "OF_FULLNAME=/appine-gpu\nOF_COMPATIBLE_N=1\nOF_COMPATIBLE_0=virtio,mmio\n".to_owned(),
            b"devices/system/cpu/online"
            | b"devices/system/cpu/possible"
            | b"devices/system/cpu/present" => cpu_list(0..cpus()),
            b"devices/system/cpu/offline" => "\n".to_owned(),
            // The defaults of 6.1's Kconfig, except redirect_always_follow which is N because
            // Appine does not follow trusted.overlay.redirect (no index, redirects, metacopy,
            // NFS export or xino)
            b"module/overlay/parameters/redirect_max" => "256\n".to_owned(),
            p if p.starts_with(b"module/overlay/parameters/") => "N\n".to_owned(),
            _ => return Err(Errno::EISDIR),
        },
        SysCpu(n, path) => cpu_file(*n as usize, path)?,
        SysNet(n, path) => net_file(ps.k, &ps.sys_net_ns(mnt), *n, path)?,
        SysBlock(n, b"uevent") => {
            if !ps.k.loops.sysfs_exists(*n, b"uevent") {
                return Err(Errno::ENOENT);
            }
            format!("MAJOR={LOOP_MAJOR}\nMINOR={n}\nDEVNAME=loop{n}\nDEVTYPE=disk\n")
        }
        SysBlock(n, path) => ps.k.loops.sysfs_read(*n, path).ok_or(Errno::EISDIR)?,
        NetConf(v6, dir, name, net) => crate::netdev::conf_read(&net.0, *v6, *dir, name)?,
        NetSysctl(path, net) => crate::netconf::sysctl_read(&net.0.devs.borrow().conf, path),
        // Removed cgroups / disabled controllers are ENODEV; write-only files are EINVAL
        Cgroup(_, b"", 0) => return Err(Errno::EISDIR),
        Cgroup(id, name, _) => {
            if gone(ps.k, node) { return Err(Errno::ENODEV); }
            // Ids as the reader's pid namespace sees them (task_pid_vnr: current's, not the
            // mount's)
            let ns = ps.k.pid_ns_of(ps.tgid);
            let vnr = |t| ns.vnr(t).unwrap_or(0);
            crate::cgroup::file(ps.k, *id, name, &vnr)?
        }
        // A namespace is opened only for setns; nothing can be read
        NsFile(..) => String::new(),
        _ => return Err(Errno::EINVAL),
    };
    Ok(s.into_bytes())
}

// ---- Per-process files ----

fn pid_stat(ps: &View<'_>, ns: &PidNs, proc: ProcId, tid: Option<Tid>) -> Result<Vec<u8>, Errno> {
    let g = ps.group(proc).ok_or(Errno::ESRCH)?;
    let g = g.borrow();
    let task = ps.task(proc, tid);
    let start_ticks = if tid.unwrap_or(proc.pid) == g.tgid {
        g.start_ticks
    } else {
        task.as_ref().map_or(g.start_ticks, |t| t.start_ticks)
    };
    let nice = task.as_ref().map_or(0, |t| t.nice.get());
    let (state, _) = state_of(ps, &g, proc, tid);
    let (tty_nr, tpgid) = ctty_info(ns, &g);
    let v = |p: Tid| ns.vnr(p).unwrap_or(0);
    let cpu = match (tid, &task, g.leader_exit) {
        (Some(_), Some(t), _) => t.cpu(),
        // The exited main thread's own time
        (Some(t), None, Some((_, cpu))) if t == g.tgid => cpu,
        _ => g.cpu(ps.k),
    };
    let (vsize, rss) = mem_of(task.as_deref());
    let (sigign, sigcgt) = sig_dispositions(&g);
    let (pending, blocked) = task.as_ref().map_or((0, 0), |t| {
        (t.pending.borrow().set() | g.pending.set(), t.sigmask.get())
    });
    // The layout goes only to readers passing the ptrace read check (6.1's do_task_stat):
    // others see 1 for the code's bounds and 0 for the rest
    let permitted = ps.may_read(proc, tid);
    let layout = task.as_ref().map(|t| {
        let res = t.res.borrow();
        let mm = res.mm.borrow();
        let (code, data) = (mm.code, mm.data);
        let rest = [mm.brk_start(), mm.args.0, mm.args.1, mm.env.0, mm.env.1];
        (code, mm.start_stack(), data, rest)
    });
    let (code, stack, tail) = match layout {
        Some((code, stack, data, rest)) if permitted => {
            let tail = [data.0, data.1, rest[0], rest[1], rest[2], rest[3], rest[4]];
            (code, stack, tail)
        }
        Some(_) => ((1, 1), 0, [0; 7]),
        None => ((0, 0), 0, [0; 7]),
    };
    // The name as raw bytes, as Linux's proc_task_name without escaping
    let mut out = format!("{} (", v(tid.unwrap_or(proc.pid))).into_bytes();
    out.extend(comm_of(&g, task.as_deref(), proc.pid, tid));
    let mut s = String::new();
    write!(
        s,
        ") {} {} {} {} {} {} 4194304 0 0 0 0 {} {} {} {} {} {} {} 0 {} {} {} 18446744073709551615",
        state,
        v(g.ppid),
        v(g.pgid),
        v(g.sid),
        tty_nr,
        tpgid,
        ticks(cpu.user_ns()),
        ticks(cpu.sys_ns),
        ticks(g.child_cpu.user_ns()),
        ticks(g.child_cpu.sys_ns),
        20 + nice,
        nice,
        thread_count(&g).max(1),
        ps.with_boot_offset(start_ticks * (1_000_000_000 / HZ)) / (1_000_000_000 / HZ),
        vsize,
        rss,
    )
    .unwrap();
    let tail = tail.map(|v| v.to_string()).join(" ");
    writeln!(
        s,
        " {} {} {stack} 0 0 {pending} {blocked} {sigign} {sigcgt} 0 0 0 {} 0 0 0 0 0 0 {tail} 0",
        code.0, code.1, g.exit_signal
    )
    .unwrap();
    out.extend(s.into_bytes());
    Ok(out)
}

/// The controlling terminal's device number and foreground process group (its number in pid
/// namespace `ns`).
fn ctty_info(ns: &PidNs, g: &ThreadGroup) -> (u64, i64) {
    match &g.ctty {
        Some(tty) => {
            let t = tty.borrow();
            let fg = t.fg.map_or(-1, |p| ns.vnr(p).unwrap_or(0) as i64);
            (rdev(PTS_MAJOR, t.index), fg)
        }
        None => (0, -1),
    }
}

fn pid_status(ps: &View<'_>, ns: &PidNs, proc: ProcId, tid: Option<Tid>) -> Result<Vec<u8>, Errno> {
    let g = ps.group(proc).ok_or(Errno::ESRCH)?;
    let g = g.borrow();
    let task = ps.task(proc, tid);
    let (state, state_name) = state_of(ps, &g, proc, tid);
    let (sigign, sigcgt) = sig_dispositions(&g);
    let (umask, fdsize) = task.as_ref().map_or((0o022, 0), |t| {
        let res = t.res.borrow();
        let fds = res.fds.borrow().open_fds().len();
        (res.fs.borrow().umask, fds.next_multiple_of(64))
    });
    let (pending, blocked) = task
        .as_ref()
        .map_or((0, 0), |t| (t.pending.borrow().set(), t.sigmask.get()));
    // The name as its bytes with only a newline and a backslash escaped (Linux's
    // proc_task_name with seq_escape_str(.., "\n\\"))
    let mut out = b"Name:\t".to_vec();
    for b in comm_of(&g, task.as_deref(), proc.pid, tid) {
        match b {
            b'\n' => out.extend(b"\\n"),
            b'\\' => out.extend(b"\\\\"),
            b => out.push(b),
        }
    }
    out.push(b'\n');
    let mut s = String::new();
    writeln!(s, "Umask:\t{umask:04o}").unwrap();
    writeln!(s, "State:\t{state} ({state_name})").unwrap();
    let v = |p: Tid| ns.vnr(p).unwrap_or(0);
    let tid = tid.unwrap_or(proc.pid);
    writeln!(s, "Tgid:\t{}\nNgid:\t0\nPid:\t{}", v(g.tgid), v(tid)).unwrap();
    let tracer = task.as_ref().and_then(|t| t.trace.borrow().tracer);
    writeln!(
        s,
        "PPid:\t{}\nTracerPid:\t{}",
        v(g.ppid),
        tracer.map_or(0, v)
    )
    .unwrap();
    // The thread's credentials, or the main thread's; IDs are translated through the reader's
    // user namespace (Linux's seq_user_ns)
    let c = &ps.k.cred_of(tid).unwrap_or_else(|| g.cred.clone());
    let r = ps.reader();
    let u = |k: u32| r.uid_out(k);
    let gi = |k: u32| r.gid_out(k);
    writeln!(
        s,
        "Uid:\t{}\t{}\t{}\t{}",
        u(c.ruid),
        u(c.euid),
        u(c.suid),
        u(c.fsuid)
    )
    .unwrap();
    writeln!(
        s,
        "Gid:\t{}\t{}\t{}\t{}",
        gi(c.rgid),
        gi(c.egid),
        gi(c.sgid),
        gi(c.fsgid)
    )
    .unwrap();
    let groups: Vec<String> = c.groups.iter().map(|&g| gi(g).to_string()).collect();
    writeln!(s, "FDSize:\t{fdsize}\nGroups:\t{}", groups.join(" ")).unwrap();
    // One column per level, from the mount's pid namespace down to the process's own
    let levels = g.pid_ns.levels_from(ns.level);
    let col = |p: Tid| -> String {
        levels
            .iter()
            .map(|n| format!("\t{}", n.vnr(p).unwrap_or(0)))
            .collect()
    };
    writeln!(
        s,
        "NStgid:{}\nNSpid:{}\nNSpgid:{}\nNSsid:{}",
        col(g.tgid),
        col(tid),
        col(g.pgid),
        col(g.sid)
    )
    .unwrap();
    if let Some(t) = task.as_deref() {
        let res = t.res.borrow();
        let mm = res.mm.borrow();
        let layout = vm_layout(&mm);
        let kb = layout.size / 1024;
        writeln!(s, "VmPeak:\t{kb:>8} kB\nVmSize:\t{kb:>8} kB").unwrap();
        writeln!(
            s,
            "VmLck:\t{:>8} kB\nVmPin:\t{:>8} kB",
            mm.locked_bytes() / 1024,
            0
        )
        .unwrap();
        // VmRSS is the sum of the three kinds, as on Linux
        let (anon, file, shmem) = mm.resident_split();
        let rss = anon + file + shmem;
        let hwm = g.maxrss_kb.max(rss * 4);
        writeln!(s, "VmHWM:\t{hwm:>8} kB\nVmRSS:\t{:>8} kB", rss * 4).unwrap();
        writeln!(
            s,
            "RssAnon:\t{:>8} kB\nRssFile:\t{:>8} kB\nRssShmem:\t{:>8} kB",
            anon * 4,
            file * 4,
            shmem * 4
        )
        .unwrap();
        // Linux 6.1's task_mem: VmData (private writable non-stack), VmStk (grows-down),
        // VmExe (code span capped by exec_vm), VmLib (remaining exec_vm), VmPTE (allocated
        // soft-MMU page tables) and VmSwap (exact pagemap swap when readable, else 0).
        let exe = layout.code_span.min(layout.exec);
        let lib = layout.exec.saturating_sub(exe);
        let pte_kb = mm.pgtables_bytes() / 1024;
        let swap_kb = mm.exact_swap_pages().unwrap_or(0) * 4;
        writeln!(
            s,
            "VmData:\t{:>8} kB\nVmStk:\t{:>8} kB\nVmExe:\t{:>8} kB\nVmLib:\t{:>8} kB\nVmPTE:\t{:>8} kB\nVmSwap:\t{:>8} kB",
            layout.data / 1024,
            layout.stack / 1024,
            exe / 1024,
            lib / 1024,
            pte_kb,
            swap_kb,
        )
        .unwrap();
    }
    writeln!(s, "Threads:\t{}", thread_count(&g).max(1)).unwrap();
    let limit = g.rlimits[crate::process::RLIMIT_SIGPENDING as usize].0;
    writeln!(s, "SigQ:\t{}/{limit}", crate::signal::queued(ps.k, &g)).unwrap();
    writeln!(
        s,
        "SigPnd:\t{pending:016x}\nShdPnd:\t{:016x}",
        g.pending.set()
    )
    .unwrap();
    writeln!(
        s,
        "SigBlk:\t{blocked:016x}\nSigIgn:\t{sigign:016x}\nSigCgt:\t{sigcgt:016x}"
    )
    .unwrap();
    writeln!(s, "CapInh:\t{:016x}", c.cap_inheritable).unwrap();
    writeln!(s, "CapPrm:\t{:016x}", c.cap_permitted).unwrap();
    writeln!(s, "CapEff:\t{:016x}", c.cap_effective).unwrap();
    writeln!(s, "CapBnd:\t{:016x}", c.cap_bounding).unwrap();
    writeln!(s, "CapAmb:\t{:016x}", c.cap_ambient).unwrap();
    let (seccomp, filters) = task.as_ref().map_or((0, 0), |t| {
        let s = t.seccomp.borrow();
        (s.mode, s.filters())
    });
    writeln!(
        s,
        "NoNewPrivs:\t{}\nSeccomp:\t{seccomp}\nSeccomp_filters:\t{filters}",
        task.as_ref()
            .map_or(g.leader_no_new_privs, |t| t.no_new_privs.get()) as u8
    )
    .unwrap();
    // The thread's affinity (the main thread's for the process), clamped to its cgroup's effective
    // cpuset (within the online CPUs)
    let allowed = match task.as_ref() {
        Some(t) => crate::cgroup::clamp_affinity(ps.k, g.cgroup, t.affinity.get()),
        None => crate::cgroup::effective_cpus(ps.k, g.cgroup),
    };
    let allowed: Vec<usize> = (0..64).filter(|b| allowed >> b & 1 != 0).collect();
    write!(s, "Cpus_allowed:\t{}", cpu_mask_of(&allowed)).unwrap();
    write!(s, "Cpus_allowed_list:\t{}", cpu_list_of(&allowed)).unwrap();
    // Each time a host thread goes to sleep (waits) is one voluntary switch: a thread that has
    // not been woken does not change
    let (vol, nonvol) = task.as_ref().map_or((0, 0), |t| {
        let (v, n) = appine_hal::thread_ctxt_switches(t.host_tid.get()).unwrap_or((0, 0));
        let (bv, bn) = t.ctxt_base.get();
        (v.saturating_sub(bv), n.saturating_sub(bn))
    });
    writeln!(
        s,
        "voluntary_ctxt_switches:\t{vol}\nnonvoluntary_ctxt_switches:\t{nonvol}"
    )
    .unwrap();
    out.extend(s.into_bytes());
    Ok(out)
}

/// The process state letter and name: Z zombie, t in a ptrace-stop, T stopped, S waiting in the
/// kernel, and R otherwise (running guest code or handling a syscall).
fn state_of(
    ps: &View<'_>,
    g: &ThreadGroup,
    proc: ProcId,
    tid: Option<Tid>,
) -> (char, &'static str) {
    // The whole process, or its main thread once that has exited (Linux keeps it as a zombie
    // task, and the process directory shows it)
    if g.zombie.is_some() || (tid.unwrap_or(proc.pid) == g.tgid && g.leader_exit.is_some()) {
        return ('Z', "zombie");
    }
    // Stopped in a ptrace-stop (also under PTRACE_LISTEN, as on Linux)
    if let Some(t) = ps.task(proc, tid)
        && t.trace.borrow().stop.is_some()
    {
        return ('t', "tracing stop");
    }
    if g.stopped {
        return ('T', "stopped");
    }
    // As on Linux, the state is the thread's (the main thread's for the process directory):
    // waiting in the kernel is S, and everything else (running guest code, handling a syscall,
    // just created and not yet run, woken but not yet running) is R
    if ps.task(proc, tid).is_some_and(|t| t.asleep()) {
        ('S', "sleeping")
    } else {
        ('R', "running")
    }
}

/// The threads of a process, counting an exited main thread until the process is reaped (Linux's
/// `nr_threads`).
fn thread_count(g: &ThreadGroup) -> usize {
    g.threads.len() + usize::from(g.leader_exit.is_some())
}

/// The name of the thread viewed (the main thread for the process directory): an exited main
/// thread keeps its name, as Linux's zombie task does.
fn comm_of(g: &ThreadGroup, task: Option<&Task>, pid: Tid, tid: Option<Tid>) -> Vec<u8> {
    let comm = match (task, g.leader_exit) {
        (Some(t), _) => t.comm.get(),
        (None, Some((comm, _))) if tid.unwrap_or(pid) == g.tgid => comm,
        _ => return comm_str(None, pid).into_bytes(),
    };
    let n = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    comm[..n].to_vec()
}

/// Virtual-memory breakdown matching Linux 6.1's `vm_stat_account` / `task_mem` / `task_statm`
/// (in bytes): total size, `data_vm` (private writable non-stack), `stack_vm` (grows-down),
/// `exec_vm` (executable non-writable non-stack), and the page-aligned code span (`[start_code,
/// end_code)`).
struct VmLayout {
    size: u64,
    data: u64,
    stack: u64,
    exec: u64,
    code_span: u64,
}

fn vm_layout(mm: &crate::mm::Mm) -> VmLayout {
    let size = mm.size();
    let stack = mm.stack_bytes();
    let mut main_stack = 0u64;
    let mut raw_data = 0u64;
    let mut exec = 0u64;
    for r in mm.regions() {
        let len = r.end.saturating_sub(r.start);
        if r.name.as_deref() == Some(b"[stack]") {
            main_stack = main_stack.saturating_add(len);
        } else if r.prot & 4 != 0 && r.prot & 2 == 0 {
            exec = exec.saturating_add(len);
        } else if r.prot & 2 != 0 && !r.shared {
            raw_data = raw_data.saturating_add(len);
        }
    }
    // Exclude any additional MAP_GROWSDOWN mappings already counted in `stack_bytes`.
    let extra_stack = stack.saturating_sub(main_stack);
    let data = raw_data.saturating_sub(extra_stack);
    let (code_start, code_end) = mm.code;
    let code_span = if code_end > code_start {
        (code_end.saturating_add(4095) & !4095u64).saturating_sub(code_start & !4095u64)
    } else {
        0
    };
    VmLayout {
        size,
        data,
        stack,
        exec,
        code_span,
    }
}

/// An address space's (total size, resident pages).
fn mem_of(task: Option<&Task>) -> (u64, u64) {
    let Some(t) = task else {
        return (0, 0);
    };
    let res = t.res.borrow();
    let mm = res.mm.borrow();
    (mm.size(), mm.resident_pages())
}

/// Signal disposition bitmaps: (ignored, caught).
fn sig_dispositions(g: &ThreadGroup) -> (u64, u64) {
    let sh = g.sighand.borrow();
    let (mut ign, mut cgt) = (0, 0);
    for n in 1..=Signal::MAX {
        let sig = Signal::new(n).unwrap();
        match sh.get(sig).handler {
            SigAction::IGNORE => ign |= sig.bit(),
            SigAction::DEFAULT => {}
            _ => cgt |= sig.bit(),
        }
    }
    (ign, cgt)
}

pub(crate) fn comm_str(task: Option<&Task>, pid: Tid) -> String {
    match task {
        Some(t) => {
            let c = t.comm.get();
            let n = c.iter().position(|&b| b == 0).unwrap_or(c.len());
            String::from_utf8_lossy(&c[..n]).into_owned()
        }
        None if pid == INIT => "init".to_owned(),
        None => String::new(),
    }
}

/// Reads `/proc/<pid>/environ` from the address space pinned at open (`proc_environ_operations`):
/// returns empty/EOF once the process has exited or replaced its address space via `execve`.
pub(crate) fn read_environ(mm: Option<&Rc<RefCell<crate::mm::Mm>>>) -> Vec<u8> {
    mm.map_or_else(Vec::new, |mm| mm_bytes(&mm.borrow(), |m| m.env))
}

/// A range of guest memory (cmdline, environ); empty when it cannot be read.
fn guest_bytes(task: &Task, range: fn(&crate::mm::Mm) -> (u64, u64)) -> Vec<u8> {
    let res = task.res.borrow();
    mm_bytes(&res.mm.borrow(), range)
}

fn mm_bytes(mm: &crate::mm::Mm, range: fn(&crate::mm::Mm) -> (u64, u64)) -> Vec<u8> {
    let (start, end) = range(mm);
    if end <= start || end - start > 1 << 20 {
        return Vec::new();
    }
    let mut buf = vec![0u8; (end - start) as usize];
    match mm.read(crate::uaccess::UserSlice::new(start, buf.len()), &mut buf) {
        Ok(()) => buf,
        Err(_) => Vec::new(),
    }
}

/// The names and units of the lines of `/proc/<pid>/limits`, in resource-number order (Linux's
/// `lnames`).
const LIMIT_NAMES: [(&str, &str); crate::process::RLIM_NLIMITS] = [
    ("Max cpu time", "seconds"),
    ("Max file size", "bytes"),
    ("Max data size", "bytes"),
    ("Max stack size", "bytes"),
    ("Max core file size", "bytes"),
    ("Max resident set", "bytes"),
    ("Max processes", "processes"),
    ("Max open files", "files"),
    ("Max locked memory", "bytes"),
    ("Max address space", "bytes"),
    ("Max file locks", "locks"),
    ("Max pending signals", "signals"),
    ("Max msgqueue size", "bytes"),
    ("Max nice priority", ""),
    ("Max realtime priority", ""),
    ("Max realtime timeout", "us"),
];

/// `/proc/<pid>/limits`: the same format as Linux's `proc_pid_limits`; lines without a unit still
/// keep the spaces after the hard limit at the end.
fn limits(rlimits: &[(u64, u64); crate::process::RLIM_NLIMITS]) -> String {
    let value = |v: u64| match v {
        u64::MAX => "unlimited".to_owned(),
        v => v.to_string(),
    };
    let mut s = format!(
        "{:<25} {:<20} {:<20} {:<10}\n",
        "Limit", "Soft Limit", "Hard Limit", "Units"
    );
    for ((name, unit), &(soft, hard)) in LIMIT_NAMES.iter().zip(rlimits) {
        write!(s, "{name:<25} {:<20} {:<20} ", value(soft), value(hard)).unwrap();
        if !unit.is_empty() {
            write!(s, "{unit:<10}").unwrap();
        }
        s.push('\n');
    }
    s
}

fn maps(vfs: &Vfs, task: &Task) -> String {
    let res = task.res.borrow();
    let mm = res.mm.borrow();
    let fuse_paths = crate::vfs::fuse::mapped_paths(&mm);
    mm.regions()
        .iter()
        .map(|r| map_line(vfs, r, &fuse_paths))
        .collect()
}

/// smaps counts, in kB. The host cannot tell which pages have been written: resident pages of
/// anonymous memory all count as dirty, and those of file mappings as clean. Pages of anonymous
/// memory shared with other address spaces after fork (copy-on-write) count as shared, with Pss
/// divided by the number of sharers ([`crate::mm::Mm::cow_shared`]); everything else counts as
/// private.
#[derive(Default)]
struct Usage {
    rss: u64,
    anon: u64,
    /// The part of `anon` shared with other address spaces.
    shared: u64,
    /// The bytes of `shared` after dividing.
    shared_pss: u64,
    file: u64,
    shmem: u64,
    locked: u64,
}

impl Usage {
    fn add(&mut self, o: &Usage) {
        self.rss += o.rss;
        self.anon += o.anon;
        self.shared += o.shared;
        self.shared_pss += o.shared_pss;
        self.file += o.file;
        self.shmem += o.shmem;
        self.locked += o.locked;
    }

    /// Linux's `__show_smap`: labels take 16 columns and numbers 8. As on Linux, Pss is summed in
    /// bytes first and converted to kB only at the end.
    fn write(&self, s: &mut String, rollup: bool) {
        let private = self.anon - self.shared;
        let pss_anon = private * 1024 + self.shared_pss;
        let pss_shmem = self.shmem * 1024;
        let dirty = private + self.shmem;
        // The Private_Hugetlb label takes one more column and the number one less, keeping the
        // total width
        let mut put = |label: &str, kb: u64| {
            let w = 24 - label.len().max(16);
            writeln!(s, "{label:<16}{kb:>w$} kB").unwrap()
        };
        put("Rss:", self.rss);
        put("Pss:", (pss_anon + pss_shmem) / 1024 + self.file);
        put("Pss_Dirty:", (pss_anon + pss_shmem) / 1024);
        if rollup {
            put("Pss_Anon:", pss_anon / 1024);
            put("Pss_File:", self.file);
            put("Pss_Shmem:", self.shmem);
        }
        put("Shared_Clean:", 0);
        put("Shared_Dirty:", self.shared);
        put("Private_Clean:", self.file);
        put("Private_Dirty:", dirty);
        put("Referenced:", self.rss);
        put("Anonymous:", self.anon);
        for label in [
            "LazyFree:",
            "AnonHugePages:",
            "ShmemPmdMapped:",
            "FilePmdMapped:",
        ] {
            put(label, 0);
        }
        put("Shared_Hugetlb:", 0);
        put("Private_Hugetlb:", 0);
        put("Swap:", 0);
        put("SwapPss:", 0);
        put("Locked:", self.locked);
    }
}

/// `/proc/<pid>/smaps`, or `smaps_rollup` with `rollup` (the total over all mappings). Resident
/// pages are counted in host memory (mincore).
fn smaps(vfs: &Vfs, task: &Task, rollup: bool) -> String {
    let res = task.res.borrow();
    let mm = res.mm.borrow();
    let regions = mm.regions();
    let mut s = String::new();
    let mut total = Usage::default();
    let fuse_paths = if rollup {
        HashSet::new()
    } else {
        crate::vfs::fuse::mapped_paths(&mm)
    };
    for r in &regions {
        let rss = mm.resident_in(r.start, r.end - r.start) * 4;
        let mut u = Usage {
            rss,
            locked: if r.locked { rss } else { 0 },
            ..Usage::default()
        };
        match (r.file, r.shared) {
            (Some(_), _) => u.file = rss,
            (None, true) => u.shmem = rss,
            (None, false) => {
                let (pages, pss) = mm.cow_shared(r.start, r.end);
                u.anon = rss;
                // Lent pages are usually resident; those swapped out to zram are not resident,
                // and so not shared either
                u.shared = (pages * 4).min(rss);
                u.shared_pss = pss.min(u.shared * 1024);
            }
        }
        total.add(&u);
        if rollup {
            continue;
        }
        s += &map_line(vfs, r, &fuse_paths);
        let kb = (r.end - r.start) / 1024;
        writeln!(s, "{:<16}{kb:>8} kB", "Size:").unwrap();
        writeln!(s, "{:<16}{:>8} kB", "KernelPageSize:", 4).unwrap();
        writeln!(s, "{:<16}{:>8} kB", "MMUPageSize:", 4).unwrap();
        u.write(&mut s, false);
        writeln!(s, "THPeligible:    0").unwrap();
        s += &vm_flags(r);
    }
    if rollup && let (Some(first), Some(last)) = (regions.first(), regions.last()) {
        let line = format!(
            "{:08x}-{:08x} ---p 00000000 00:00 0 ",
            first.start, last.end
        );
        writeln!(s, "{line:<73}[rollup]").unwrap();
        total.write(&mut s, true);
    }
    s
}

/// The VmFlags line of smaps, in Linux's flag-bit order.
fn vm_flags(r: &Region) -> String {
    let flags = [
        (r.prot & 1 != 0, "rd"),
        (r.prot & 2 != 0, "wr"),
        (r.prot & 4 != 0, "ex"),
        (r.shared, "sh"),
        (true, "mr"),
        (r.may_write, "mw"),
        (r.may_exec, "me"),
        (r.shared, "ms"),
        (r.name.as_deref() == Some(b"[stack]"), "gd"),
        (r.locked, "lo"),
        (r.dontfork, "dc"),
        // Commit-accounted: writable private anonymous mappings
        (r.file.is_none() && !r.shared && r.prot & 2 != 0, "ac"),
        (r.wipeonfork, "wf"),
        (r.dontdump, "dd"),
    ];
    let mut s = String::from("VmFlags: ");
    for (on, name) in flags {
        if on {
            s += name;
            s.push(' ');
        }
    }
    s.push('\n');
    s
}

/// One line of maps. As on Linux, lines without a name also end in a space, the name starts at
/// column 74, and a newline in a file's path is escaped as `\012` (seq_file_path).
fn map_line(vfs: &Vfs, r: &Region, fuse_paths: &HashSet<*const u8>) -> String {
    let perms = format!(
        "{}{}{}{}",
        if r.prot & 1 != 0 { 'r' } else { '-' },
        if r.prot & 2 != 0 { 'w' } else { '-' },
        if r.prot & 4 != 0 { 'x' } else { '-' },
        if r.shared { 's' } else { 'p' },
    );
    let fuse_mmap = r
        .name
        .as_ref()
        .is_some_and(|name| fuse_paths.contains(&name.as_ptr()));
    let (offset, dev, raw_ino) = match r.file {
        Some((offset, ino)) => (offset, "08:01", ino),
        None => (0, "00:00", 0),
    };
    // Exec labels carry keys for cache pinning and ETXTBSY. Ordinary FUSE mmap labels
    // already carry the daemon inode, which can have any of its high bits set.
    let image = crate::vfs::fuse::id_of(raw_ino).filter(|_| r.name.is_some() && !fuse_mmap);
    let ino = image.map_or(raw_ino, |id| vfs.fuse().get(id).map_or(0, |n| n.attr.ino));
    let line = format!(
        "{:08x}-{:08x} {perms} {offset:08x} {dev} {ino} ",
        r.start, r.end
    );
    match &r.name {
        Some(name) => {
            let name = match r.file {
                Some((_, ino)) => {
                    let path = if fuse_mmap || image.is_some() {
                        name.to_vec()
                    } else {
                        mark_deleted(vfs.store(), ino, name.to_vec())
                    };
                    let mut escaped = Vec::with_capacity(path.len());
                    for b in path {
                        match b {
                            b'\n' => escaped.extend_from_slice(b"\\012"),
                            b => escaped.push(b),
                        }
                    }
                    escaped
                }
                None => name.to_vec(),
            };
            format!("{line:<73}{}\n", String::from_utf8_lossy(&name))
        }
        None => format!("{line}\n"),
    }
}

/// As with Linux's `d_path`, deleted files (still open or mapped) get ` (deleted)` appended to
/// their path: `/proc/<pid>/fd/<n>`, maps, smaps. After the last name is removed in the store,
/// the inode's row stays with nlink = 0 until the store is next opened exclusively, so the check
/// uses nlink. An fd link also checks its open dentry when other hard links remain.
/// When dpkg replaces old libraries with rename, needrestart uses the suffix in maps to find
/// processes still using them.
pub(crate) fn mark_deleted(store: &Store, ino: Ino, name: Vec<u8>) -> Vec<u8> {
    if store.attrs(ino).is_ok_and(|st| st.nlink == 0) {
        with_deleted(name)
    } else {
        name
    }
}

/// `name` with ` (deleted)` appended, unless it already ends with it.
fn with_deleted(mut name: Vec<u8>) -> Vec<u8> {
    const DELETED: &[u8] = b" (deleted)";
    if !name.ends_with(DELETED) {
        name.extend_from_slice(DELETED);
    }
    name
}

/// Reads `/proc/<pid>/pagemap` (`mm` is the address space pinned at open; once it is released
/// reads get EOF): 8 bytes per page; the position and length must both be multiples of 8.
pub(crate) fn read_pagemap(
    mm: Option<Rc<RefCell<crate::mm::Mm>>>,
    buf: &mut [u8],
    pos: u64,
) -> Result<usize, Errno> {
    if !pos.is_multiple_of(8) || !buf.len().is_multiple_of(8) {
        return Err(Errno::EINVAL);
    }
    // The address space was released (process execed or exited after open): return EOF rather
    // than looking up a new image or a reused pid
    let Some(mm) = mm else {
        return Ok(0);
    };
    // The user address space is 48 bits
    let pages_total = 1u64 << (48 - 12);
    let first = pos / 8;
    let n = (buf.len() as u64 / 8).min(pages_total.saturating_sub(first)) as usize;
    let entries = mm.borrow().pagemap(first * 4096, n);
    for (i, e) in entries.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&e.to_le_bytes());
    }
    Ok(n * 8)
}

/// Transfers bytes through an open /proc/<pid>/mem, holding the address space at open for
/// this operation. Fill a cold FUSE page without holding an Mm borrow and retry that page.
/// An expired address space gives EOF. An inaccessible page gives EIO or the preceding count.
pub(crate) fn access_mem(
    cx: &mut crate::kernel::Cx<'_>,
    mm: Option<Rc<RefCell<crate::mm::Mm>>>,
    pos: u64,
    len: usize,
    mut transfer: impl FnMut(&mut crate::mm::Mm, u64, Range<usize>) -> Result<(), Errno>,
) -> Result<usize, Errno> {
    let Some(mm) = mm else { return Ok(0) };
    let limit = cx.stack_limit();
    let mut done = 0;
    while done < len {
        let Some(addr) = pos.checked_add(done as u64) else {
            break;
        };
        let n = ((PAGE_SIZE - addr % PAGE_SIZE) as usize).min(len - done);
        let result = crate::syscall::retry_user_pages(cx, Errno::EIO, |_| {
            let mut mm = mm.borrow_mut();
            match transfer(&mut mm, addr, done..done + n) {
                Err(Errno::EFAULT) if mm.grow_for(addr, n, limit) => {
                    transfer(&mut mm, addr, done..done + n)
                }
                result => result,
            }
        });
        if result.is_err() {
            break;
        }
        done += n;
    }
    if done == 0 && len != 0 {
        Err(Errno::EIO)
    } else {
        Ok(done)
    }
}

/// `/proc/<pid>/mounts` (`info` false) or `mountinfo`: as with Linux's `show_vfsmnt` and
/// `show_mountinfo`, lists the mounts in that process's mount namespace `ns` in mount order, with
/// mount points relative to its root directory `root`; those outside the root directory are not
/// listed (after chroot the mounts outside are invisible, the root filesystem included). Mount ids
/// match fdinfo's `mnt_id`, and device numbers match stat's `st_dev`.
fn mounts(ps: &View<'_>, root: &Node, ns: u64, info: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (m, point) in ps.vfs.mounts_from(ps, root, ns) {
        let Some(point) = point else {
            continue;
        };
        MountLine {
            id: m.id,
            // The root of the mount tree sits on the invisible rootfs (on Linux its id is not in
            // the list), so write 0
            parent: m.parent().unwrap_or(0),
            dev: m.dev,
            fs_root: ps.vfs.root_path(ps, &m),
            point,
            flags: m.flags,
            fstype: ps.vfs.type_of(&m),
            source: if m.source.is_empty() {
                b"none"
            } else {
                &m.source
            },
            options: ps.vfs.sb_options(&m),
            sb_flags: ps.vfs.sb_flags(&m),
            prop: m.prop,
        }
        .write(&mut out, info);
    }
    out
}

/// One line of mounts or mountinfo.
struct MountLine<'a> {
    id: crate::vfs::MountId,
    parent: crate::vfs::MountId,
    dev: u64,
    /// The path within the filesystem of the part the mount sees.
    fs_root: Vec<u8>,
    point: Vec<u8>,
    flags: u64,
    fstype: String,
    source: &'a [u8],
    /// Superblock options ([`crate::vfs::Vfs::sb_options`]).
    options: String,
    /// The filesystem's own flags ([`crate::vfs::Vfs::sb_flags`]): mountinfo shows them in the
    /// superblock options, mounts with the mount's.
    sb_flags: u64,
    /// Shown in mountinfo's optional fields.
    prop: crate::vfs::Propagation,
}

impl MountLine<'_> {
    fn write(&self, out: &mut Vec<u8>, info: bool) {
        use crate::vfs::ms;
        let (fstype, options) = (&self.fstype, &self.options);
        let sb_ro = self.sb_flags & ms::RDONLY != 0;
        let sb = if sb_ro { "ro" } else { "rw" };
        let sb_opts = sb_options(self.sb_flags);
        if info {
            let (id, parent) = (self.id, self.parent);
            let (major, minor) = (self.dev >> 8, self.dev & 0xff);
            out.extend_from_slice(format!("{id} {parent} {major}:{minor} ").as_bytes());
            out.extend(mangle(&self.fs_root));
            out.push(b' ');
            out.extend(mangle(&self.point));
            let opts = mount_options(self.flags);
            out.extend_from_slice(format!(" {opts}").as_bytes());
            // The optional fields (show_mountinfo): peer group, master, unbindable
            let p = self.prop;
            if p.group != 0 {
                out.extend_from_slice(format!(" shared:{}", p.group).as_bytes());
            }
            if p.master != 0 {
                out.extend_from_slice(format!(" master:{}", p.master).as_bytes());
            }
            if p.unbindable {
                out.extend_from_slice(b" unbindable");
            }
            out.extend_from_slice(format!(" - {fstype} ").as_bytes());
            out.extend(mangle(self.source));
            out.extend_from_slice(format!(" {sb}{sb_opts}{options}\n").as_bytes());
        } else {
            // show_vfsmnt: read-only if the mount or the filesystem is, the superblock's flags,
            // then the mount's
            let ro = if sb_ro { ms::RDONLY } else { 0 };
            let opts = mount_options(self.flags | ro);
            let (rw, mnt) = opts.split_at(2);
            out.extend(mangle(self.source));
            out.push(b' ');
            out.extend(mangle(&self.point));
            out.extend_from_slice(
                format!(" {fstype} {rw}{sb_opts}{mnt}{options} 0 0\n").as_bytes(),
            );
        }
    }
}

/// Mount options (the sixth column of mountinfo, Linux's `show_mnt_opts`).
fn mount_options(flags: u64) -> String {
    use crate::vfs::ms;
    let mut s = String::from(if flags & ms::RDONLY != 0 { "ro" } else { "rw" });
    for (bit, name) in [
        (ms::NOSUID, ",nosuid"),
        (ms::NODEV, ",nodev"),
        (ms::NOEXEC, ",noexec"),
        (ms::NOATIME, ",noatime"),
        (ms::NODIRATIME, ",nodiratime"),
        (ms::RELATIME, ",relatime"),
        (ms::NOSYMFOLLOW, ",nosymfollow"),
    ] {
        if flags & bit != 0 {
            s += name;
        }
    }
    s
}

/// The superblock's own options (Linux's `show_sb_opts`).
fn sb_options(sb: u64) -> String {
    use crate::vfs::ms;
    let mut s = String::new();
    for (bit, name) in [
        (ms::SYNCHRONOUS, ",sync"),
        (ms::DIRSYNC, ",dirsync"),
        (ms::MANDLOCK, ",mand"),
        (ms::LAZYTIME, ",lazytime"),
    ] {
        if sb & bit != 0 {
            s += name;
        }
    }
    s
}

/// As with Linux's `mangle`, writes spaces, tabs, newlines and backslashes as octal escapes.
fn mangle(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in s {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.extend_from_slice(format!("\\{b:03o}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

/// `/proc/<pid>/uid_map`, `gid_map`, `projid_map` (Linux's `uid_m_show`): each extent is "first ID
/// in the namespace, first ID in the parent, count", 10 columns each. The second column is
/// translated through the reader's namespace; when the reader is in this namespace itself,
/// through the parent's. Unmapped values are written as 4294967295. Only the boot-time namespace
/// has a projid_map.
fn id_map(reader: &Cred, ns: &Rc<crate::cred::UserNs>, e: Entry) -> String {
    let lower = match &ns.parent {
        Some(parent) if reader.user_ns.id == ns.id => parent.clone(),
        _ => reader.user_ns.clone(),
    };
    let (map, lower_map) = match e {
        Entry::GidMap => (ns.gid_map.borrow().clone(), lower.gid_map.borrow().clone()),
        Entry::UidMap => (ns.uid_map.borrow().clone(), lower.uid_map.borrow().clone()),
        _ if ns.level == 0 => return format!("{:>10} {:>10} {:>10}\n", 0, 0, u32::MAX),
        _ => return String::new(),
    };
    map.extents()
        .iter()
        .map(|&(first, k, count)| {
            let shown = lower_map.up(k).unwrap_or(u32::MAX);
            format!("{first:>10} {shown:>10} {count:>10}\n")
        })
        .collect()
}

/// `/proc/<pid>/fdinfo/<n>`: position, flags (plus close-on-exec; files opened with open carry
/// `O_LARGEFILE`), mount id, inode, the locks held through it, and the extra lines of eventfd,
/// inotify, pidfd, epoll, timerfd and signalfd.
fn fdinfo(
    ps: &View<'_>,
    ns: &PidNs,
    proc: ProcId,
    tid: Option<Tid>,
    fd: i32,
) -> Result<String, Errno> {
    if !ps.pid_exists(proc, tid) {
        return Err(Errno::ESRCH);
    }
    let task = ps.task(proc, tid).ok_or(Errno::ENOENT)?;
    let res = task.res.borrow();
    let fds = res.fds.borrow();
    let file = fds.get(fd).map_err(|_| Errno::ENOENT)?;
    let cloexec = if fds.cloexec(fd)? {
        oflags::O_CLOEXEC
    } else {
        0
    };
    let f = file.borrow();
    let mnt_id = f.mnt_id();
    let ino = match &f.kind {
        FileKind::Host(hfd) => appine_hal::fstat(*hfd).map_or(0, |st| st.st_ino),
        FileKind::MessageQueue(q) => q.borrow().stat().ino,
        _ => match f.node() {
            Some(Node::Store(_, ino)) => ino,
            Some(Node::Overlay(_, o)) => ps.vfs.overlay().shown_ino(o),
            Some(Node::Fuse(_, id)) => ps.vfs.fuse().get(id).map_or(0, |n| n.attr.ino),
            Some(Node::Pseudo(_, p)) => node_ino(&p),
            None => crate::syscall::dev_ino(&f).1,
        },
    };
    let mut s = format!(
        "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{mnt_id}\nino:\t{ino}\n",
        f.pos,
        f.flags | cloexec,
    );
    // Only files and tables that have taken locks can hold any (most fds have none)
    if f.holds_locks || fds.holds_locks {
        s += &crate::locks::fd_locks(ps.k, ps.vfs, ns, &res.fds, &file);
    }
    match &f.kind {
        FileKind::EventFd(e) => s += &format!("eventfd-count: {:16x}\n", e.borrow().count),
        FileKind::Inotify(i) => s += &i.borrow().fdinfo(),
        // The number in the mount's pid namespace (0 when not visible); NSpid goes on to list the
        // lower levels
        FileKind::Pidfd(p) => {
            let nr = if p.exited() {
                -1
            } else {
                ns.vnr(p.tgid).unwrap_or(0)
            };
            s += &format!("Pid:\t{nr}\nNSpid:\t{nr}");
            if nr > 0 {
                let levels = ps.k.pid_ns_of(p.tgid).levels_from(ns.level + 1);
                for n in levels {
                    s += &format!("\t{}", n.vnr(p.tgid).unwrap_or(0));
                }
            }
            s.push('\n');
        }
        FileKind::Epoll(e) => s += &e.borrow().fdinfo(),
        FileKind::TimerFd(t) => s += &t.borrow_mut().fdinfo(),
        FileKind::SignalFd(sfd) => s += &format!("sigmask:\t{:016x}\n", sfd.borrow().mask),
        _ => {}
    }
    Ok(s)
}

// ---- System-wide files ----

/// The names of the HWCAP bits in `/proc/cpuinfo` (Linux 6.1's `hwcap_str`), in bit order.
const HWCAP_NAMES: [&str; 30] = [
    "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2", "crc32", "atomics", "fphp",
    "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4",
    "asimddp", "sha512", "sve", "asimdfhm", "dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb",
];

/// Likewise, the names of the HWCAP2 bits, which come after HWCAP's.
const HWCAP2_NAMES: [&str; 20] = [
    "dcpodp",
    "sve2",
    "sveaes",
    "svepmull",
    "svebitperm",
    "svesha3",
    "svesm4",
    "flagm2",
    "frint",
    "svei8mm",
    "svef32mm",
    "svef64mm",
    "svebf16",
    "i8mm",
    "bf16",
    "dgh",
    "rng",
    "bti",
    "mte",
    "ecv",
];

fn cpuinfo() -> String {
    let named = |names: &'static [&'static str], caps: u64| {
        names
            .iter()
            .enumerate()
            .filter(move |(i, _)| caps & (1 << i) != 0)
            .map(|(_, n)| *n)
    };
    let features: Vec<&str> = named(&HWCAP_NAMES, appine_engine::guest_hwcap())
        .chain(named(&HWCAP2_NAMES, appine_engine::guest_hwcap2()))
        .collect();
    let midr = appine_engine::guest_midr();
    let mut s = String::new();
    for cpu in 0..cpus() {
        writeln!(s, "processor\t: {cpu}\nBogoMIPS\t: 100.00").unwrap();
        writeln!(s, "Features\t: {}", features.join(" ")).unwrap();
        writeln!(s, "CPU implementer\t: {:#04x}", (midr >> 24) & 0xff).unwrap();
        writeln!(s, "CPU architecture: 8").unwrap();
        writeln!(s, "CPU variant\t: {:#x}", (midr >> 20) & 0xf).unwrap();
        writeln!(s, "CPU part\t: {:#05x}", (midr >> 4) & 0xfff).unwrap();
        writeln!(s, "CPU revision\t: {}\n", midr & 0xf).unwrap();
    }
    s
}

/// `/proc/meminfo`: copied from the host (as in a docker container); for the limit the guest can
/// use, see the cgroup's `memory.max`. It used to be computed from sysinfo, with `MemAvailable`
/// equal to `MemFree` and all page cache counted as used.
fn meminfo() -> String {
    let m = appine_hal::host_meminfo();
    let mut s = String::new();
    for (name, bytes) in [
        ("MemTotal", m.total),
        ("MemFree", m.free),
        ("MemAvailable", m.available),
        ("Buffers", m.buffers),
        ("Cached", m.cached),
        ("SwapCached", m.swap_cached),
        ("Active", m.active),
        ("Inactive", m.inactive),
        ("SwapTotal", m.swap_total),
        ("SwapFree", m.swap_free),
        ("Dirty", m.dirty),
        ("AnonPages", m.anon_pages),
        ("Mapped", m.mapped),
        ("Shmem", m.shmem),
        ("Slab", m.slab),
        ("SReclaimable", m.sreclaimable),
    ] {
        writeln!(s, "{:<16}{:>8} kB", format!("{name}:"), bytes / 1024).unwrap();
    }
    s
}

/// `/proc/vmstat`: like `meminfo`, the host's figures (as a container sees its host's) when the
/// host lets the app read them; otherwise the page counts `meminfo` gives and the event counters
/// at 0, in Linux's order, so procps' vmstat and memory monitors still find the file.
fn vmstat(host: Option<String>, m: &appine_hal::MemInfo) -> String {
    if let Some(text) = host {
        return text;
    }
    let pages = |bytes: u64| bytes / 4096;
    let mut s = String::new();
    for (name, value) in [
        ("nr_free_pages", pages(m.free)),
        ("nr_slab_reclaimable", pages(m.sreclaimable)),
        (
            "nr_slab_unreclaimable",
            pages(m.slab.saturating_sub(m.sreclaimable)),
        ),
        ("nr_anon_pages", pages(m.anon_pages)),
        ("nr_mapped", pages(m.mapped)),
        ("nr_file_pages", pages(m.cached + m.buffers + m.swap_cached)),
        ("nr_dirty", pages(m.dirty)),
        ("nr_writeback", 0),
        ("nr_shmem", pages(m.shmem)),
        ("pgpgin", 0),
        ("pgpgout", 0),
        ("pswpin", 0),
        ("pswpout", 0),
        ("pgfault", 0),
        ("pgmajfault", 0),
        ("oom_kill", 0),
    ] {
        writeln!(s, "{name} {value}").unwrap();
    }
    s
}

fn global_stat(ps: &View<'_>) -> String {
    let n = cpus() as u64;
    let up = ticks(uptime_ns());
    let cpu = ps.k.tasks.values().fold(ps.k.cpu, |sum, t| sum + t.cpu());
    let (user, system) = (ticks(cpu.user_ns()), ticks(cpu.sys_ns));
    let idle = (up * n).saturating_sub(user + system);
    let running =
        ps.k.tasks
            .values()
            .filter(|t| t.sync.in_guest.load(std::sync::atomic::Ordering::Relaxed))
            .count();
    // Linux's getboottime64 (realtime minus boottime, subtracted in nanoseconds) moved back by the
    // reader's time-namespace boottime offset (timens_sub_boottime), so btime plus a start time
    // from /proc/<pid>/stat is the wall-clock start in any namespace (ps -o lstart). Truncating
    // both clocks to seconds before subtracting made btime alternate between two seconds.
    let now =
        appine_hal::clock_gettime(0).map_or(0, |(s, ns)| s as i128 * 1_000_000_000 + ns as i128);
    let btime = ((now - ps.with_boot_offset(uptime_ns()) as i128) / 1_000_000_000).max(0);
    let mut s = String::new();
    writeln!(s, "cpu  {user} 0 {system} {idle} 0 0 0 0 0 0").unwrap();
    for i in 0..n {
        writeln!(
            s,
            "cpu{i} {} 0 {} {} 0 0 0 0 0 0",
            user / n,
            system / n,
            idle / n
        )
        .unwrap();
    }
    writeln!(s, "intr 0\nctxt 0\nbtime {btime}\nprocesses {}", ps.k.forks).unwrap();
    // softirq is the total and then one count for each of Linux's 10 softirq types (show_stat);
    // parsers such as prometheus/procfs, which BuildKit reads it with, refuse fewer
    writeln!(
        s,
        "procs_running {}\nprocs_blocked 0\nsoftirq 0{}",
        running.max(1),
        " 0".repeat(10)
    )
    .unwrap();
    s
}

fn ticks(ns: u64) -> u64 {
    ns / (1_000_000_000 / HZ)
}

/// Nanoseconds since boot (CLOCK_BOOTTIME).
pub(crate) fn uptime_ns() -> u64 {
    appine_hal::clock_gettime(appine_hal::CLOCK_BOOTTIME)
        .map(|(s, ns)| s as u64 * 1_000_000_000 + ns as u64)
        .unwrap_or(0)
}

fn random_uuid() -> String {
    let mut b = [0u8; 16];
    let _ = appine_hal::fill_random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format_uuid(&b)
}

pub(crate) fn format_uuid(b: &[u8; 16]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

// ---- /proc/<pid>/net ----

/// All open sockets (each counted once), sorted by inode, including sockets that are only in
/// SCM_RIGHTS messages. Sockets waiting to be accepted do not count.
///
/// Does not borrow any socket `RefCell`, so callers such as netlink/nftables updates may walk the
/// list while holding a mutable borrow on a socket.
pub(crate) fn sockets(k: &Kernel) -> Vec<SocketRef> {
    let mut tables = HashSet::new();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for task in k.tasks.values() {
        let fds = task.res.borrow().fds.clone();
        if !tables.insert(Rc::as_ptr(&fds)) {
            continue;
        }
        let fds = fds.borrow();
        for file in fds.open_fds().into_iter().filter_map(|fd| fds.get(fd).ok()) {
            if let FileKind::Socket(s) = &file.borrow().kind
                && seen.insert(Rc::as_ptr(s))
            {
                out.push(s.clone());
            }
        }
    }
    // Those only in SCM_RIGHTS messages
    for s in crate::unix::inflight_sockets(k) {
        if seen.insert(Rc::as_ptr(&s)) {
            out.push(s);
        }
    }
    out.sort_by_key(socket_ino);
    out
}

/// A socket's inode number (fstat, the `socket:[n]` of `/proc/<pid>/fd`).
pub(crate) fn socket_ino(s: &SocketRef) -> u64 {
    Rc::as_ptr(s) as u64 >> 4
}

/// The id of the network namespace a socket is in.
fn socket_net(s: &crate::net::Socket) -> u64 {
    use crate::net::Socket;
    let net = match s {
        Socket::Inet(i) => i.net.as_ref(),
        Socket::Netlink(n) => n.net.as_ref(),
        Socket::Unix(u) => u.net.as_ref(),
    };
    net.map_or(crate::nsproxy::INIT_NET_NS, |n| n.id)
}

/// `/proc/net/dev`: interfaces `ifaces` with counters for the guest's own traffic
/// ([`crate::traffic`]; all 0 when `counted` is false), in the same format as Linux's
/// `dev_seq_printf_stats`.
fn net_dev(k: &Kernel, ifaces: &[appine_hal::net::Interface], counted: bool) -> String {
    let mut s = String::from(
        "Inter-|   Receive                                                |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast|\
         bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for i in ifaces {
        let st = if counted {
            k.traffic.get(&i.name)
        } else {
            Default::default()
        };
        writeln!(
            s,
            "{:>6}: {:>7} {:>7} {:>4} {:>4} {:>4} {:>5} {:>10} {:>9} {:>8} {:>7} {:>4} {:>4} {:>4} \
             {:>5} {:>7} {:>10}",
            i.name,
            st.rx_bytes,
            st.rx_packets,
            0,
            0,
            0,
            0,
            0,
            0,
            st.tx_bytes,
            st.tx_packets,
            0,
            0,
            0,
            0,
            0,
            0
        )
        .unwrap();
    }
    s
}

/// `/proc/net/if_inet6`: the IPv6 addresses on the host's interfaces, in the same format as
/// Linux's `if6_seq_show`. OpenJDK uses it to decide whether IPv6 exists (`IPv6_supported`), and
/// turns IPv6 off entirely when the file is missing or empty. The scope comes from the address,
/// as in Linux's `ipv6_addr_scope`; the flags are `IFA_F_PERMANENT`, as in the netlink replies
/// (getifaddrs cannot tell temporary addresses apart).
fn net_if_inet6(ifaces: &[appine_hal::net::Interface]) -> String {
    let mut s = String::new();
    for i in ifaces {
        for (_, addr, prefix) in i.addrs.iter().filter(|(f, ..)| *f == AF_INET6) {
            let scope = match addr[..] {
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => 0x10,
                [0xfe, b, ..] if b & 0xc0 == 0x80 => 0x20,
                [0xfe, b, ..] if b & 0xc0 == 0xc0 => 0x40,
                _ => 0,
            };
            let hex: String = addr.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(
                s,
                "{hex} {:02x} {prefix:02x} {scope:02x} 80 {:>8}",
                i.index, i.name
            )
            .unwrap();
        }
    }
    s
}

// ---- sysfs ----

/// The files under `/sys/class/net/<interface>`, with interfaces numbered as in the sysfs mount's
/// network namespace (the mounter's, as on Linux). As in the netlink replies, interface types are
/// only loopback and Ethernet; `flags` is `dev->flags` as on Linux, without state-derived bits
/// such as `IFF_RUNNING`. For virtual devices ([`crate::netdev`]) `iflink` is the veth peer, and
/// `operstate` can be lowerlayerdown.
fn net_file(
    k: &Kernel,
    ns: &crate::nsproxy::NetNs,
    index: u32,
    path: &[u8],
) -> Result<String, Errno> {
    const IFF_UP: u32 = 0x1;
    const IFF_LOOPBACK: u32 = 0x8;
    const IFF_RUNNING: u32 = 0x40;
    // IFF_RUNNING, IFF_LOWER_UP, IFF_DORMANT, IFF_ECHO (only dev_get_flags adds them)
    const STATE_FLAGS: u32 = 0x40 | 0x1_0000 | 0x2_0000 | 0x4_0000;
    let virt = crate::netdev::views(ns)
        .into_iter()
        .find(|v| v.index == index);
    if let Some(v) = virt {
        let mac = |m: [u8; 6]| {
            let hex: Vec<String> = m.iter().map(|b| format!("{b:02x}")).collect();
            format!("{}\n", hex.join(":"))
        };
        return Ok(match path {
            b"addr_len" => "6\n".to_owned(),
            b"address" => mac(v.mac),
            b"broadcast" => mac([0xff; 6]),
            b"carrier" if v.flags & IFF_UP == 0 => return Err(Errno::EINVAL),
            b"carrier" => format!("{}\n", u8::from(v.carrier)),
            b"flags" => format!("{:#x}\n", v.flags & !STATE_FLAGS),
            b"ifindex" => format!("{index}\n"),
            b"iflink" => format!("{}\n", v.link.as_ref().map_or(index, |l| l.0)),
            b"mtu" => format!("{}\n", v.mtu),
            b"operstate" => match v.operstate {
                0 => "unknown\n",
                3 => "lowerlayerdown\n",
                6 => "up\n",
                _ => "down\n",
            }
            .to_owned(),
            b"tx_queue_len" => format!("{}\n", v.txqlen),
            b"type" => "1\n".to_owned(),
            // Bridge parameters are all defaults, with STP off (crate::netdev::bridge_info)
            b"bridge/ageing_time" => "30000\n".to_owned(),
            b"bridge/forward_delay" => "1500\n".to_owned(),
            b"bridge/hello_time" => "200\n".to_owned(),
            b"bridge/max_age" => "2000\n".to_owned(),
            b"bridge/priority" => "32768\n".to_owned(),
            b"bridge/stp_state" => "0\n".to_owned(),
            b"bridge/bridge_id" | b"bridge/root_id" => {
                let hex: String = v.mac.iter().map(|b| format!("{b:02x}")).collect();
                format!("8000.{hex}\n")
            }
            b"brport/state" => format!("{}\n", v.port_state.unwrap_or(0)),
            b"brport/priority" => "32\n".to_owned(),
            b"brport/path_cost" => "2\n".to_owned(),
            p if p.starts_with(b"statistics/") && !p.ends_with(b"/") => "0\n".to_owned(),
            _ => return Err(Errno::EISDIR),
        });
    }
    // The interface is gone: on Linux the directory disappears with it, and files already open
    // read ENODEV
    let i = crate::netdev::base(ns)
        .into_iter()
        .find(|i| i.index == index)
        .ok_or(Errno::ENODEV)?;
    let loopback = i.flags & IFF_LOOPBACK != 0;
    let mac = |m: [u8; 6]| {
        let hex: Vec<String> = m.iter().map(|b| format!("{b:02x}")).collect();
        format!("{}\n", hex.join(":"))
    };
    // Host traffic counters and host tx_queue_len belong only to the initial network namespace;
    // a new network namespace's `lo` starts with zero counters and Linux's default txqlen 1000
    // (matching `/proc/net/dev` and rtnetlink)
    let init_ns = ns.host_net.is_none();
    let st = if init_ns {
        k.traffic.get(&i.name)
    } else {
        crate::traffic::IfStats::default()
    };
    Ok(match path {
        b"addr_len" => "6\n".to_owned(),
        b"address" => mac(i.mac.unwrap_or([0; 6])),
        b"broadcast" => mac(if loopback { [0; 6] } else { [0xff; 6] }),
        // On Linux reading carrier of a down interface is EINVAL
        b"carrier" if i.flags & IFF_UP == 0 => return Err(Errno::EINVAL),
        b"carrier" => format!("{}\n", u8::from(i.flags & IFF_RUNNING != 0)),
        b"flags" => format!("{:#x}\n", i.flags & !STATE_FLAGS),
        b"ifindex" | b"iflink" => format!("{index}\n"),
        b"mtu" => format!("{}\n", i.mtu),
        b"operstate" => match crate::net::operstate(&i) {
            0 => "unknown\n",
            6 => "up\n",
            _ => "down\n",
        }
        .to_owned(),
        b"tx_queue_len" => format!(
            "{}\n",
            if init_ns {
                appine_hal::net::tx_queue_len(&i.name).unwrap_or(1000)
            } else {
                1000
            }
        ),
        b"type" => format!("{}\n", if loopback { 772 } else { 1 }),
        b"statistics/rx_bytes" => format!("{}\n", st.rx_bytes),
        b"statistics/rx_packets" => format!("{}\n", st.rx_packets),
        b"statistics/tx_bytes" => format!("{}\n", st.tx_bytes),
        b"statistics/tx_packets" => format!("{}\n", st.tx_packets),
        p if p.starts_with(b"statistics/") && !p.ends_with(b"/") => "0\n".to_owned(),
        _ => return Err(Errno::EISDIR),
    })
}

/// The files under `/sys/devices/system/cpu/cpu<n>`. All CPUs are the same (in `/proc/cpuinfo`
/// too), each its own core, with no hyperthreading, all in one package.
fn cpu_file(n: usize, path: &[u8]) -> Result<String, Errno> {
    let all = 0..cpus();
    let me = n..n + 1;
    Ok(match path {
        b"online" => "1\n".to_owned(),
        b"regs/identification/midr_el1" => format!("0x{:016x}\n", appine_engine::guest_midr()),
        b"regs/identification/revidr_el1" => format!("0x{:016x}\n", 0),
        b"topology/cluster_id" => "-1\n".to_owned(),
        b"topology/core_id" => format!("{n}\n"),
        b"topology/physical_package_id" => "0\n".to_owned(),
        b"topology/cluster_cpus" | b"topology/core_cpus" | b"topology/thread_siblings" => {
            cpu_mask(me)
        }
        b"topology/cluster_cpus_list"
        | b"topology/core_cpus_list"
        | b"topology/thread_siblings_list" => cpu_list(me),
        b"topology/core_siblings" | b"topology/package_cpus" => cpu_mask(all),
        b"topology/core_siblings_list" | b"topology/package_cpus_list" => cpu_list(all),
        _ if HOST_CPU_FILES.contains(&path) => return host_cpu_file(n, path),
        _ => return Err(Errno::EISDIR),
    })
}

/// CPU list form (`%*pbl`): `0-3`, or `2` when there is only one.
fn cpu_list(set: Range<usize>) -> String {
    cpu_list_of(&set.collect::<Vec<_>>())
}

/// CPU mask form (`%*pb`): hexadecimal, comma-separated groups of 32 bits, with the highest group
/// zero-padded to enough digits for the total CPU count (`f` for 4 CPUs; with 8, cpu0 is `01`).
fn cpu_mask(set: Range<usize>) -> String {
    cpu_mask_of(&set.collect::<Vec<_>>())
}

/// Cache and frequency files copied from the host: host CPU numbers in CPU lists and masks are
/// changed to the guest's (CPUs the guest cannot use are removed).
fn host_cpu_file(n: usize, path: &[u8]) -> Result<String, Errno> {
    let rel = String::from_utf8_lossy(path).into_owned();
    let raw = host_cpu(n as u32)
        .and_then(|h| appine_hal::cpu_sysfs(h, &rel))
        .ok_or(Errno::ENOENT)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let guest = |host: Vec<usize>| -> Vec<usize> {
        let cpus = appine_hal::host_cpus();
        (0..cpus.len())
            .filter(|&i| host.contains(&cpus[i]))
            .collect()
    };
    Ok(match tree_name(path) {
        b"shared_cpu_list" => cpu_list_of(&guest(parse_cpu_list(text.trim()))),
        b"shared_cpu_map" => cpu_mask_of(&guest(parse_cpu_mask(text.trim()))),
        b"affected_cpus" | b"related_cpus" => {
            let host = text
                .split_whitespace()
                .filter_map(|w| w.parse().ok())
                .collect();
            let cpus: Vec<String> = guest(host).iter().map(usize::to_string).collect();
            format!("{}\n", cpus.join(" "))
        }
        _ => text,
    })
}

/// The CPUs in a CPU list (`0-3,5`).
fn parse_cpu_list(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        if let (Ok(a), Ok(b)) = (a.parse::<usize>(), b.parse::<usize>()) {
            out.extend(a..=b.min(a + 4096));
        }
    }
    out
}

/// The CPUs in a CPU mask (hexadecimal, comma-separated groups of 32 bits, high first).
fn parse_cpu_mask(s: &str) -> Vec<usize> {
    let words: Vec<u32> = s
        .split(',')
        .filter_map(|w| u32::from_str_radix(w, 16).ok())
        .collect();
    let mut out = Vec::new();
    for (i, w) in words.iter().rev().enumerate() {
        out.extend((0..32).filter(|b| w >> b & 1 != 0).map(|b| i * 32 + b));
    }
    out
}

/// Writes a set of CPUs (in increasing order) in CPU list form ([`cpu_list`], `0-1,3`).
fn cpu_list_of(cpus: &[usize]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let mut j = i;
        while j + 1 < cpus.len() && cpus[j + 1] == cpus[j] + 1 {
            j += 1;
        }
        parts.push(if i == j {
            cpus[i].to_string()
        } else {
            format!("{}-{}", cpus[i], cpus[j])
        });
        i = j + 1;
    }
    format!("{}\n", parts.join(","))
}

/// Writes a set of CPUs in CPU mask form ([`cpu_mask`]).
fn cpu_mask_of(cpus: &[usize]) -> String {
    cpu_mask_for(self::cpus(), cpus)
}

/// Writes a set of CPUs in CPU mask form for a system with `bits` CPUs (`%*pb`).
fn cpu_mask_for(bits: usize, cpus: &[usize]) -> String {
    let bits = bits.max(1);
    let groups = bits.div_ceil(32);
    let mut s = String::new();
    for g in (0..groups).rev() {
        let width = if g == groups - 1 {
            (bits - g * 32).div_ceil(4)
        } else {
            8
        };
        let word = cpus
            .iter()
            .filter(|&&c| c / 32 == g)
            .fold(0u32, |w, &c| w | 1 << (c % 32));
        if g != groups - 1 {
            s.push(',');
        }
        write!(s, "{word:0width$x}").unwrap();
    }
    s.push('\n');
    s
}

/// Whether the host CPU corresponding to `n` has `path` from [`HOST_CPU_FILES`] (relative to
/// `cpu<n>`, directories ending in `/`).
fn host_cpu_has(n: u32, path: &[u8]) -> bool {
    let rel = String::from_utf8_lossy(path.strip_suffix(b"/").unwrap_or(path)).into_owned();
    host_cpu(n).is_some_and(|h| appine_hal::cpu_sysfs(h, &rel).is_some())
}

/// The host CPU corresponding to guest CPU `n`.
fn host_cpu(n: u32) -> Option<usize> {
    appine_hal::host_cpus().get(n as usize).copied()
}

// ---- Writing ----

#[derive(Clone, Copy)]
enum SysctlWrite {
    // Signed ints, unsigned longs and strings (proc_dostring): update at 0, advance pos.
    Advance,
    // Linux 6.1's proc_douintvec and proc_dou8vec leave a successful initial write at zero.
    Unsigned,
    // addrconf returns one byte for a forwarding or linkdown fixup and restores the position.
    Ipv6Fixup,
    // Linux 6.1's proc_do_large_bitmap replaces at 0, ORs at nonzero offsets, and advances pos.
    Bitmap,
}

/// Position rule of a writable `/proc/sys` sysctl. Ordinary procfs and cgroup files return None.
fn sysctl_write(node: &PseudoNode) -> Option<SysctlWrite> {
    use SysctlWrite::*;
    if !writable(node) {
        return None;
    }
    let rule = match node {
        PseudoNode::Static(b"sys/fs/pipe-max-size") => Unsigned,
        PseudoNode::Static(p) if p.starts_with(b"sys/") => Advance,
        PseudoNode::UtsSysctl(..)
        | PseudoNode::IpcSysctl(..)
        | PseudoNode::PidSysctl(..)
        | PseudoNode::NetStatic(..) => Advance,
        PseudoNode::NetConf(true, dir, b"forwarding" | b"ignore_routes_with_linkdown", _)
            if *dir != crate::netdev::ConfDir::Default =>
        {
            Ipv6Fixup
        }
        PseudoNode::NetConf(
            true,
            _,
            b"addr_gen_mode"
            | b"ra_defrtr_metric"
            | b"ioam6_enabled"
            | b"ioam6_id"
            | b"ioam6_id_wide"
            | b"ndisc_evict_nocarrier",
            _,
        ) => Unsigned,
        PseudoNode::NetConf(..) => Advance,
        PseudoNode::NetSysctl(path, _) => match path.split_once('/')? {
            ("ipv4", "ip_local_reserved_ports") => Bitmap,
            (
                "ipv4",
                "tcp_congestion_control"
                | "tcp_fastopen_key"
                | "icmp_ratelimit"
                | "icmp_ratemask"
                | "igmp_max_memberships"
                | "igmp_max_msf"
                | "igmp_qrv"
                | "ipfrag_high_thresh"
                | "ipfrag_low_thresh"
                | "ipfrag_max_dist"
                | "ipfrag_time"
                | "tcp_adv_win_scale"
                | "tcp_base_mss"
                | "tcp_challenge_ack_limit"
                | "tcp_comp_sack_delay_ns"
                | "tcp_comp_sack_slack_ns"
                | "tcp_fastopen"
                | "tcp_fastopen_blackhole_timeout_sec"
                | "tcp_fin_timeout"
                | "tcp_invalid_ratelimit"
                | "tcp_keepalive_intvl"
                | "tcp_keepalive_time"
                | "tcp_limit_output_bytes"
                | "tcp_max_reordering"
                | "tcp_max_syn_backlog"
                | "tcp_max_tw_buckets"
                | "tcp_min_rtt_wlen"
                | "tcp_min_snd_mss"
                | "tcp_mtu_probe_floor"
                | "tcp_pacing_ca_ratio"
                | "tcp_pacing_ss_ratio"
                | "tcp_probe_threshold"
                | "tcp_reordering"
                | "tcp_rmem"
                | "tcp_wmem"
                | "udp_rmem_min"
                | "udp_wmem_min"
                | "xfrm4_gc_thresh",
            ) => Advance,
            ("ipv4", _) => Unsigned,
            (
                "ipv6",
                "anycast_src_echo_reply"
                | "auto_flowlabels"
                | "bindv6only"
                | "fib_multipath_hash_fields"
                | "fib_multipath_hash_policy"
                | "fib_notify_on_flag_change"
                | "flowlabel_consistency"
                | "flowlabel_state_ranges"
                | "fwmark_reflect"
                | "ioam6_id"
                | "ip_nonlocal_bind",
            ) => Unsigned,
            ("core", "txrehash" | "xfrm_aevent_etime" | "xfrm_aevent_rseqth") => Unsigned,
            _ => Advance,
        },
        _ => return None,
    };
    Some(rule)
}

pub(crate) fn is_sysctl_write(node: &PseudoNode) -> bool {
    sysctl_write(node).is_some()
}

/// Writes a synthetic file: cgroup files go to [`crate::cgroup::write`], the id maps,
/// `setgroups` and `timens_offsets` to their own writers, and the other writable files check the
/// value and record it (namespaced sysctls in the pinned lookup namespace); some recorded values
/// have no effect. `cred`, `ns` and `pid_ns` are the writer's, `opener` the credentials the file
/// was opened with. Returns the bytes consumed and the resulting position.
pub(crate) fn write(
    k: &mut Kernel,
    (tid, cred, opener): (Tid, &Cred, &Cred),
    (ns, pid_ns): (&crate::nsproxy::NsProxy, &PidNs),
    node: &PseudoNode,
    data: &[u8],
    (pos, count): (u64, usize),
) -> Result<(usize, u64), Errno> {
    // Opened for writing by root although not writable ([`unwritable_error`])
    if !writable(node) && !matches!(node, PseudoNode::Cgroup(..)) {
        return Err(unwritable_error(node).unwrap_or(Errno::EINVAL));
    }
    let required = match node {
        PseudoNode::Static(b"sys/vm/mmap_min_addr") => Some(cap::SYS_RAWIO),
        PseudoNode::Static(
            b"sys/kernel/dmesg_restrict"
            | b"sys/kernel/kptr_restrict"
            | b"sys/kernel/tainted"
            | b"sys/kernel/unprivileged_bpf_disabled",
        ) => Some(cap::SYS_ADMIN),
        _ => None,
    };
    if required.is_some_and(|cap| !cred.capable(cap)) {
        return Err(Errno::EPERM);
    }
    let sysctl = sysctl_write(node);
    let apply = match sysctl {
        None => true,
        Some(SysctlWrite::Bitmap) => !data.is_empty(),
        Some(_) => pos == 0 && !data.is_empty(),
    };
    if apply {
        write_value(k, (tid, cred, opener), (ns, pid_ns), node, data, pos)?;
    }
    // Linux 6.1 position/count rules: sysctls advance (except Unsigned at 0 and Ipv6Fixup);
    // uid_map/gid_map/setgroups and cgroup2 (kernfs) advance; oom_score_adj clamps to 12 and
    // preserves pos; comm, coredump_filter and timens_offsets return count and preserve pos.
    let result = match (sysctl, node) {
        (Some(SysctlWrite::Ipv6Fixup), _) => (count.min(1), pos),
        (Some(SysctlWrite::Unsigned), _) if pos == 0 => (count, pos),
        (Some(_), _)
        | (
            None,
            PseudoNode::Entry(_, _, Entry::UidMap | Entry::GidMap | Entry::Setgroups)
            | PseudoNode::Cgroup(..),
        ) => (count, pos + count as u64),
        (None, PseudoNode::Entry(_, _, Entry::OomScoreAdj)) => (count.min(12), pos),
        (None, _) => (count, pos),
    };
    Ok(result)
}

fn write_value(
    k: &mut Kernel,
    (tid, cred, opener): (Tid, &Cred, &Cred),
    (ns, pid_ns): (&crate::nsproxy::NsProxy, &PidNs),
    node: &PseudoNode,
    data: &[u8],
    pos: u64,
) -> Result<(), Errno> {
    match node {
        PseudoNode::Cgroup(id, name, _) => {
            if gone(k, node) {
                return Err(Errno::ENODEV);
            }
            let writer = crate::cgroup::Writer {
                cred,
                tid,
                pid_ns,
                ns_root: ns.cgroup.root,
                opener,
            };
            return crate::cgroup::write(k, &writer, (*id, name), data);
        }
        PseudoNode::Entry(proc, entry_tid, Entry::Comm) => {
            return write_comm(k, tid, *proc, *entry_tid, data);
        }
        PseudoNode::Entry(proc, _, e @ (Entry::UidMap | Entry::GidMap)) => {
            return write_id_map(k, (cred, opener), *proc, *e == Entry::GidMap, data, pos);
        }
        PseudoNode::Entry(proc, _, Entry::Setgroups) => {
            return write_setgroups(k, opener, *proc, data, pos);
        }
        PseudoNode::Entry(proc, None, Entry::TimensOffsets) => {
            return write_timens_offsets(k, opener, *proc, data, pos);
        }
        // Network namespace sysctls: the pinned lookup namespace (crate::netconf)
        PseudoNode::NetConf(v6, dir, name, net) => {
            return crate::netdev::conf_write(&net.0, *v6, *dir, name, data);
        }
        PseudoNode::NetSysctl(path, net) => {
            if *path == "ipv4/ip_local_reserved_ports" && pos != 0 {
                let mut devs = net.0.devs.borrow_mut();
                let current = crate::netconf::sysctl_read(&devs.conf, path);
                let merged = merge_port_bitmap(&current, data)?;
                return crate::netconf::sysctl_write(&mut devs.conf, path, merged.as_bytes());
            }
            return crate::netconf::sysctl_write(&mut net.0.devs.borrow_mut().conf, path, data);
        }
        PseudoNode::NetStatic(b"sys/net/ipv4/ip_forward", net) => {
            return crate::netdev::conf_write(
                &net.0,
                false,
                crate::netdev::ConfDir::All,
                b"forwarding",
                data,
            );
        }
        PseudoNode::NetStatic(b"sys/net/bridge/bridge-nf-call-iptables", net) => {
            let value =
                i32::try_from(crate::netconf::parse_int(data)?).map_err(|_| Errno::EINVAL)?;
            net.0.devs.borrow_mut().conf.bridge_call_iptables = value != 0;
            return Ok(());
        }
        PseudoNode::NetStatic(b"sys/net/core/somaxconn", net) => {
            let v = crate::netconf::parse_int(data)?;
            if !(0..=i32::MAX as i64).contains(&v) {
                return Err(Errno::EINVAL);
            }
            net.0.devs.borrow_mut().conf.somaxconn = v;
            return Ok(());
        }
        PseudoNode::NetStatic(b"sys/net/ipv4/ip_local_port_range", net) => {
            let mut d = net.0.devs.borrow_mut();
            d.conf.port_range = crate::netconf::parse_port_range(data, d.conf.prot_sock)?;
            return Ok(());
        }
        PseudoNode::NetStatic(b"sys/net/ipv4/ip_unprivileged_port_start", net) => {
            let mut d = net.0.devs.borrow_mut();
            d.conf.prot_sock = crate::netconf::parse_prot_sock(data, d.conf.port_range.0)?;
            return Ok(());
        }
        PseudoNode::NetStatic(b"sys/net/ipv4/ping_group_range", net) => {
            let r = crate::netconf::parse_ping_group(data, cred)?;
            net.0.devs.borrow_mut().conf.ping_group = r;
            return Ok(());
        }
        // IPC namespace sysctls: the pinned lookup namespace
        PseudoNode::IpcSysctl(path, ipc) => {
            if let Some(name) = path.strip_prefix(b"sys/kernel/")
                && k.ipc(ipc.0.id).tunables.read(name).is_some()
            {
                return k.ipc_mut(ipc.0.id).tunables.write(name, data);
            }
            if let Some(name) = path.strip_prefix(b"sys/fs/mqueue/")
                && let Some(slot) = k.ipc_mut(ipc.0.id).mq_limits.slot(name)
            {
                *slot = std::str::from_utf8(data)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .filter(|&v: &u64| v > 0)
                    .ok_or(Errno::EINVAL)?;
                return Ok(());
            }
            return Err(Errno::EINVAL);
        }
        // UTS namespace sysctls: the pinned lookup namespace; wakes pollers with POLLPRI
        PseudoNode::UtsSysctl(path, uts) => {
            let name = data.strip_suffix(b"\n").unwrap_or(data);
            if name.len() > crate::kernel::UTS_LEN {
                return Err(Errno::EINVAL);
            }
            if *path == b"sys/kernel/hostname" {
                uts.0.set_hostname(name.to_vec());
            } else {
                uts.0.set_domainname(name.to_vec());
            }
            return Ok(());
        }
        // Between 0 and pid_max, as on Linux (checkpoint/restore uses it to give a new process a
        // chosen pid); targets the pinned lookup pid namespace
        PseudoNode::PidSysctl(b"sys/kernel/ns_last_pid", pid_ns) => {
            let pid: i32 = std::str::from_utf8(data)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .filter(|&n| (0..=k.pid_max).contains(&n))
                .ok_or(Errno::EINVAL)?;
            if pid_ns.0.level == 0 {
                k.set_last_pid(pid);
            } else {
                pid_ns.0.set_last_pid(pid);
            }
            return Ok(());
        }
        _ => {}
    }
    // mmap_min_addr_handler: writing needs CAP_SYS_RAWIO
    if let PseudoNode::Static(b"sys/vm/mmap_min_addr") = node {
        let n: u64 = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(Errno::EINVAL)?;
        crate::mm::MMAP_MIN_ADDR.store(n, std::sync::atomic::Ordering::Relaxed);
    }
    // Dropping dentries and inodes (2, 3) forgets the FUSE nodes nothing uses; the host keeps
    // the page cache
    if let PseudoNode::Static(b"sys/vm/drop_caches") = node
        && let Some(v) = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
        && (1..=4).contains(&v)
    {
        crate::vfs::fuse::drop_caches(v);
    }
    if let PseudoNode::Static(b"sys/vm/max_map_count") = node {
        let n: usize = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n| n <= i32::MAX as usize)
            .ok_or(Errno::EINVAL)?;
        crate::mm::MAX_MAP_COUNT.store(n, std::sync::atomic::Ordering::Relaxed);
    }
    // Between 0 and INT_MAX, as on Linux; targets the opener's user namespace (matching reads,
    // which use the opener's credentials)
    if let PseudoNode::Static(path) = node
        && let Some(kind) = path
            .strip_prefix(b"sys/user/")
            .and_then(crate::nsproxy::Counted::from_sysctl)
    {
        let n: u32 = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n| n <= i32::MAX as u32)
            .ok_or(Errno::EINVAL)?;
        k.ucounts.set_limit(opener.user_ns.id, kind, n);
    }
    if let PseudoNode::Static(b"sys/fs/aio-max-nr") = node {
        k.aio_max_nr = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(Errno::EINVAL)?;
    }
    if let PseudoNode::Static(path) = node
        && let Some(name) = path.strip_prefix(b"sys/fs/inotify/")
    {
        // Negative numbers are not accepted, as on Linux
        let n: usize = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n| n <= i32::MAX as usize)
            .ok_or(Errno::EINVAL)?;
        let mut r = k.inotify.borrow_mut();
        match name {
            b"max_queued_events" => r.max_queued = n,
            b"max_user_instances" => r.max_instances = n,
            _ => r.max_watches = n,
        }
    }
    // Between MIN_THREADS and FUTEX_TID_MASK, as on Linux; RLIMIT_NPROC values already set are
    // unchanged
    if let PseudoNode::Static(b"sys/kernel/threads-max") = node {
        k.threads_max = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|n| (crate::process::MIN_THREADS..=0x3fff_ffff).contains(n))
            .ok_or(Errno::EINVAL)?;
    }
    if let PseudoNode::Static(b"sys/fs/lease-break-time") = node {
        k.lease_break_time = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(Errno::EINVAL)?;
    }
    // At least 1, at most INT_MAX (proc_dointvec_minmax with SYSCTL_ONE)
    if let PseudoNode::Static(b"sys/fs/mount-max") = node {
        k.mount_max = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|n| (1..=i32::MAX as usize).contains(n))
            .ok_or(Errno::EINVAL)?;
    }
    // The fd table's capacity is fixed: nr_open can be lowered but cannot exceed it
    if let PseudoNode::Static(b"sys/fs/nr_open") = node {
        k.nr_open = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|n| (64..=crate::fd::MAX_FDS).contains(n))
            .ok_or(Errno::EINVAL)?;
    }
    // As on Linux, rounded up to a power of two in pages; above 2^31 is EINVAL
    if let PseudoNode::Static(b"sys/fs/pipe-max-size") = node {
        let size: u64 = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|&n| n <= 1 << 31)
            .ok_or(Errno::EINVAL)?;
        k.pipe_max_size = (size as usize)
            .max(crate::pipe::PIPE_BUF)
            .next_power_of_two();
    }
    if let PseudoNode::Entry(proc, _, Entry::OomScoreAdj) = node {
        let value = kstrto(proc_number(data)?, true)?;
        if !(-1000..=1000).contains(&value) {
            return Err(Errno::EINVAL);
        }
        let value = value as i32;
        let group = group_of_id(k, *proc).ok_or(Errno::ESRCH)?;
        let mut g = group.borrow_mut();
        // As on Linux: going below the minimum needs CAP_SYS_RESOURCE, and with it the value
        // written also becomes the new minimum
        let privileged = cred.capable(cap::SYS_RESOURCE);
        if value < g.oom_score_adj_min && !privileged {
            return Err(Errno::EACCES);
        }
        g.oom_score_adj = value;
        if privileged {
            g.oom_score_adj_min = value;
        }
    }
    if let PseudoNode::Static(b"sys/kernel/seccomp/actions_logged") = node {
        crate::seccomp::set_actions_logged(k, cred, data)?;
    }
    // As with Linux's proc_dostring, an over-long value is truncated (core_pattern is at most
    // 127 bytes)
    if let PseudoNode::Static(b"sys/kernel/core_pattern") = node {
        let pattern = data.strip_suffix(b"\n").unwrap_or(data);
        let len = pattern.len().min(crate::coredump::PATTERN_MAX - 1);
        k.core_pattern = pattern[..len].to_vec();
    }
    // proc_dointvec_minmax_sysadmin: writing needs CAP_SYS_ADMIN in the boot-time namespace, and
    // only 0 or 1
    if let PseudoNode::Static(b"sys/kernel/dmesg_restrict") = node {
        k.dmesg_restrict = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            .filter(|v| (0..=1).contains(v))
            .ok_or(Errno::EINVAL)?
            == 1;
    }
    // proc_dointvec_minmax for one int (kernel.panic is a proc_dointvec with no range)
    let int_in = |range: std::ops::RangeInclusive<i64>| {
        crate::netconf::parse_int(data)
            .ok()
            .filter(|v| range.contains(v))
            .ok_or(Errno::EINVAL)
    };
    match node {
        PseudoNode::Static(b"sys/kernel/pid_max") => {
            k.pid_max =
                int_in(crate::kernel::pid_max_min() as i64..=crate::kernel::PID_MAX as i64)? as Tid;
        }
        PseudoNode::Static(b"sys/kernel/panic") => {
            k.panic = int_in(i32::MIN as i64..=i32::MAX as i64)? as i32;
        }
        PseudoNode::Static(b"sys/fs/protected_symlinks") => {
            k.protected_symlinks = int_in(0..=1)? == 1
        }
        // overcommit_policy_handler: 0 to 2; 1 turns off fork's commit check (crate::mm)
        PseudoNode::Static(b"sys/vm/overcommit_memory") => {
            let v = int_in(0..=2)? as u8;
            crate::mm::OVERCOMMIT_MEMORY.store(v, std::sync::atomic::Ordering::Relaxed);
        }
        // proc_taint: needs CAP_SYS_ADMIN, and the flags written (of the 19 defined) are added
        // to those already set, never cleared
        PseudoNode::Static(b"sys/kernel/tainted") => {
            let v: u64 = std::str::from_utf8(data)
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .ok_or(Errno::EINVAL)?;
            k.tainted |= v & ((1 << 19) - 1);
        }
        // proc_dostring: up to a newline, cut to KMOD_PATH_LEN - 1 bytes
        PseudoNode::Static(b"sys/kernel/modprobe") => {
            let end = data
                .iter()
                .position(|&b| b == b'\n' || b == 0)
                .unwrap_or(data.len());
            k.modprobe = data[..end.min(255)].to_vec();
        }
        PseudoNode::Static(p) if recorded(p).is_some() => {
            let (path, _, _, lo, hi) = *recorded(p).unwrap();
            let v = int_in(lo..=hi)?;
            k.sysctls.insert(path, v);
        }
        PseudoNode::Static(b"sys/fs/protected_hardlinks") => {
            k.protected_hardlinks = int_in(0..=1)? == 1;
        }
        // bpf_unpriv_handler: needs CAP_SYS_ADMIN, 0 to 2, and once set to 1 it cannot be changed
        // back (EPERM)
        PseudoNode::Static(b"sys/kernel/unprivileged_bpf_disabled") => {
            let v = int_in(0..=2)? as u8;
            if k.unprivileged_bpf_disabled == 1 && v != 1 {
                return Err(Errno::EPERM);
            }
            k.unprivileged_bpf_disabled = v;
        }
        _ => {}
    }
    // devkmsg_sysctl_set_loglvl: proc_dostring takes up to a newline or the 9th byte; the write
    // must be exactly one of on, off, ratelimit plus one byte (echo's newline), otherwise EINVAL
    // and unchanged
    if let PseudoNode::Static(b"sys/kernel/printk_devkmsg") = node {
        let value = &data[..data.len().min(9)];
        let value = &value[..value
            .iter()
            .position(|&b| b == 0 || b == b'\n')
            .unwrap_or(value.len())];
        let (mode, len) = if value.starts_with(b"on") {
            (crate::klog::Devkmsg::On, 2)
        } else if value.starts_with(b"off") {
            (crate::klog::Devkmsg::Off, 3)
        } else if value.starts_with(b"ratelimit") {
            (crate::klog::Devkmsg::Ratelimit, 9)
        } else {
            return Err(Errno::EINVAL);
        };
        if len + 1 != data.len() {
            return Err(Errno::EINVAL);
        }
        k.klog.borrow_mut().devkmsg = mode;
    }
    // proc_dointvec: writes the first few in order, at most four; EINVAL when the first is not a
    // number
    if let PseudoNode::Static(b"sys/kernel/printk") = node {
        let text = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let values: Vec<i32> = text
            .split_ascii_whitespace()
            .map_while(|t| t.parse().ok())
            .take(4)
            .collect();
        if values.is_empty() {
            return Err(Errno::EINVAL);
        }
        k.printk[..values.len()].copy_from_slice(&values);
    }
    if let PseudoNode::Static(b"sys/kernel/core_uses_pid") = node {
        let v: i64 = std::str::from_utf8(data)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(Errno::EINVAL)?;
        k.core_uses_pid = v != 0;
    }
    // Parsed the C way, as on Linux (`kstrtouint_from_user` base 0), keeping only 9 bits
    if let PseudoNode::Entry(proc, _, Entry::CoredumpFilter) = node {
        let trimmed = data.split(|&b| b == 0).next().unwrap_or(data);
        let text = std::str::from_utf8(trimmed)
            .map_err(|_| Errno::EINVAL)?
            .trim();
        let value = kstrto(text, false)?;
        let group = group_of_id(k, *proc).ok_or(Errno::ESRCH)?;
        group.borrow_mut().coredump_filter = value as u32 & 0x1ff;
    }
    Ok(())
}

/// Writes `/proc/<pid>/comm` or `/proc/<pid>/task/<tid>/comm` (Linux's `comm_write`): copies up to
/// 15 bytes up to the first NUL byte verbatim (trailing newlines are not stripped, matching
/// `set_task_comm` and `PR_SET_NAME`), and permits writes only to a task in the writer's own
/// thread group (`EINVAL` otherwise, `ESRCH` if the target thread is gone).
fn write_comm(
    k: &Kernel,
    writer_tid: Tid,
    proc: ProcId,
    entry_tid: Option<Tid>,
    data: &[u8],
) -> Result<(), Errno> {
    let group = group_of_id(k, proc).ok_or(Errno::ESRCH)?;
    let tgid = group.borrow().tgid;
    let target_tid = entry_tid.unwrap_or(proc.pid);
    let task = k.tasks.get(&target_tid).filter(|t| t.tgid == tgid).cloned();
    let zombie_leader =
        task.is_none() && target_tid == tgid && group.borrow().leader_exit.is_some();
    if task.is_none() && !zombie_leader {
        return Err(Errno::ESRCH);
    }
    let writer_tgid = k.tasks.get(&writer_tid).map(|t| t.tgid);
    if writer_tgid != Some(tgid) {
        return Err(Errno::EINVAL);
    }
    let raw = &data[..data.len().min(15)];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let mut comm = [0u8; 16];
    comm[..end].copy_from_slice(&raw[..end]);
    if let Some(t) = task {
        t.comm.set(comm);
    } else if let Some((ref mut c, _)) = group.borrow_mut().leader_exit {
        *c = comm;
    }
    Ok(())
}

/// Writes `/proc/<pid>/uid_map` or `gid_map` (Linux's `proc_uid_map_write` and `map_write`), with
/// the opener's credentials where Linux uses the file's: the initial namespace's maps cannot be
/// written, and the opener must be in that namespace or its parent (EPERM); a map can be written
/// only once and the opener needs `CAP_SYS_ADMIN` in that namespace (EPERM); bad contents are
/// EINVAL. Then `new_idmap_permitted`: mapping the parent's uid 0 needs `CAP_SETFCAP`, that the
/// creator had when the namespace was made if the opener is inside it, or that the opener has in
/// the parent otherwise (`verify_root_map`); the opener, owning the namespace, maps its own
/// effective ID as one extent of one (for gid_map, setgroups must first be written as deny), or
/// both writer and opener have `CAP_SETUID`/`CAP_SETGID` in the parent namespace; otherwise
/// EPERM. A second column unmapped in the parent is EPERM too. So a map file opened by an
/// unprivileged user and handed to a setuid program grants no more than the user could write.
fn write_id_map(
    k: &Kernel,
    (writer, opener): (&Cred, &Cred),
    proc: ProcId,
    gid: bool,
    data: &[u8],
    pos: u64,
) -> Result<(), Errno> {
    // Linux's map_write: only allows < PAGE_SIZE writes starting at offset 0 (so a second write
    // on the same fd without rewinding fails with EINVAL rather than EPERM).
    if pos != 0 || data.len() >= 4096 {
        return Err(Errno::EINVAL);
    }
    let g = group_of_id(k, proc).ok_or(Errno::ESRCH)?;
    let ns = g.borrow().cred.user_ns.clone();
    let parent = ns.parent.clone().ok_or(Errno::EPERM)?;
    if opener.user_ns.id != ns.id && opener.user_ns.id != parent.id {
        return Err(Errno::EPERM);
    }
    let map = if gid { &ns.gid_map } else { &ns.uid_map };
    if !map.borrow().extents().is_empty() || !opener.ns_capable(&ns, cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let new = crate::cred::IdMap::parse(data)?;
    let parent_map = if gid {
        parent.gid_map.borrow().clone()
    } else {
        parent.uid_map.borrow().clone()
    };
    if !gid && new.extents().iter().any(|&(_, lower, _)| lower == 0) {
        let setfcap = if opener.user_ns.id == ns.id {
            ns.parent_could_setfcap
        } else {
            opener.ns_capable(&parent, cap::SETFCAP)
        };
        if !setfcap {
            return Err(Errno::EPERM);
        }
    }
    let own = match new.extents() {
        &[(_, lower, 1)] if ns.owner == opener.euid => {
            if gid {
                !ns.setgroups.get() && parent_map.down(lower) == Some(opener.egid)
            } else {
                parent_map.down(lower) == Some(opener.euid)
            }
        }
        _ => false,
    };
    let setid = if gid { cap::SETGID } else { cap::SETUID };
    let capable = writer.ns_capable(&parent, setid) && opener.ns_capable(&parent, setid);
    if !own && !capable {
        return Err(Errno::EPERM);
    }
    let kernel = new.lower_to_kernel(&parent_map)?;
    *map.borrow_mut() = kernel;
    Ok(())
}

/// Writes `/proc/<pid>/setgroups` (Linux's `proc_setgroups_write`): "allow" or "deny", followed
/// only by whitespace (EINVAL); the opener needs `CAP_SYS_ADMIN` in that user namespace (checked
/// at open as Linux's `proc_setgroups_open` does, `EACCES`, and again here in case the process has
/// moved to another namespace since, EPERM). Once denied it cannot be allowed again, and it cannot
/// be denied after gid_map has been written (EPERM). Only writes starting at offset 0 are
/// accepted (EINVAL otherwise).
fn write_setgroups(
    k: &Kernel,
    opener: &Cred,
    proc: ProcId,
    data: &[u8],
    pos: u64,
) -> Result<(), Errno> {
    if pos != 0 {
        return Err(Errno::EINVAL);
    }
    let g = group_of_id(k, proc).ok_or(Errno::ESRCH)?;
    let ns = g.borrow().cred.user_ns.clone();
    if !opener.ns_capable(&ns, cap::SYS_ADMIN) {
        return Err(Errno::EPERM);
    }
    let (allow, rest) = if let Some(rest) = data.strip_prefix(b"allow") {
        (true, rest)
    } else if let Some(rest) = data.strip_prefix(b"deny") {
        (false, rest)
    } else {
        return Err(Errno::EINVAL);
    };
    if !rest.iter().all(u8::is_ascii_whitespace) {
        return Err(Errno::EINVAL);
    }
    if allow {
        if !ns.setgroups.get() {
            return Err(Errno::EPERM);
        }
    } else {
        if !ns.gid_map.borrow().extents().is_empty() {
            return Err(Errno::EPERM);
        }
        ns.setgroups.set(false);
    }
    Ok(())
}

/// Writes `/proc/<pid>/timens_offsets` (Linux 6.1's `timens_offsets_write`,
/// `proc_timens_set_offset`): one or two lines of `<clock> <seconds> <nanoseconds>`, where the
/// clock is `monotonic`, `boottime` or their numbers 1 and 7. Writes into the time namespace that
/// process uses for children: only writes at offset 0 and `< PAGE_SIZE` are accepted (`EINVAL`),
/// the opener needs `CAP_SYS_TIME` in its owner (EPERM; Linux's `file_ns_capable`), the clocks
/// with the offsets added must be within [0, KTIME_SEC_MAX / 2] (ERANGE), and once a process has
/// entered it is EACCES.
fn write_timens_offsets(
    k: &Kernel,
    cred: &Cred,
    proc: ProcId,
    data: &[u8],
    pos: u64,
) -> Result<(), Errno> {
    const KTIME_SEC_MAX: i64 = i64::MAX / 1_000_000_000;
    if pos != 0 || data.len() >= 4096 {
        return Err(Errno::EINVAL);
    }
    let text = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    let mut offsets = Vec::new();
    for line in text.split_terminator('\n') {
        let mut words = line.split_ascii_whitespace();
        let (Some(clock), Some(sec), Some(nsec)) = (words.next(), words.next(), words.next())
        else {
            return Err(Errno::EINVAL);
        };
        let sec: i64 = sec.parse().map_err(|_| Errno::EINVAL)?;
        let nsec: u64 = nsec.parse().map_err(|_| Errno::EINVAL)?;
        if nsec >= 1_000_000_000 {
            return Err(Errno::EINVAL);
        }
        let index = match clock {
            "monotonic" | "1" => 0,
            "boottime" | "7" => 1,
            _ => return Err(Errno::EINVAL),
        };
        offsets.push((index, (sec, nsec as i64)));
        if offsets.len() == 2 {
            break;
        }
    }
    let g = group_of_id(k, proc).ok_or(Errno::ESRCH)?;
    let tgid = g.borrow().tgid;
    let task = k
        .tasks
        .get(&proc.pid)
        .filter(|t| t.tgid == tgid)
        .ok_or(Errno::ESRCH)?;
    let ns = task.ns.borrow().time_for_children.clone();
    if !cred.ns_capable(&ns.owner, cap::SYS_TIME) {
        return Err(Errno::EPERM);
    }
    for &(index, (sec, nsec)) in &offsets {
        let clock = [1, appine_hal::CLOCK_BOOTTIME][index];
        let (now, now_ns) = appine_hal::clock_gettime(clock).map_err(Errno)?;
        if !(-KTIME_SEC_MAX..=KTIME_SEC_MAX).contains(&sec) {
            return Err(Errno::ERANGE);
        }
        let total = now + sec + (now_ns + nsec) / 1_000_000_000;
        if !(0..=KTIME_SEC_MAX / 2).contains(&total) {
            return Err(Errno::ERANGE);
        }
    }
    if ns.frozen.get() {
        return Err(Errno::EACCES);
    }
    let mut all = ns.offsets.get();
    for (index, value) in offsets {
        all[index] = value;
    }
    ns.offsets.set(all);
    Ok(())
}

/// Merges a nonzero-offset write to `net.ipv4.ip_local_reserved_ports` into the existing port
/// bitmap (Linux 6.1's `proc_do_large_bitmap`: offset 0 replaces, nonzero offsets OR into the
/// bitmap) and formats the sorted coalesced range list.
fn merge_port_bitmap(current: &str, data: &[u8]) -> Result<String, Errno> {
    let mut bits = vec![0u64; 1024]; // 65536 ports
    let parse_into = |text: &str, bits: &mut [u64]| -> Result<(), Errno> {
        let text = text.trim_end_matches(['\n', '\0']).trim();
        for part in text.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (lo, hi) = match part.split_once('-') {
                Some((a, b)) => {
                    let lo: u16 = a.trim().parse().map_err(|_| Errno::EINVAL)?;
                    let hi: u16 = b.trim().parse().map_err(|_| Errno::EINVAL)?;
                    if lo > hi {
                        return Err(Errno::EINVAL);
                    }
                    (lo, hi)
                }
                None => {
                    let p: u16 = part.parse().map_err(|_| Errno::EINVAL)?;
                    (p, p)
                }
            };
            for p in usize::from(lo)..=usize::from(hi) {
                bits[p / 64] |= 1u64 << (p % 64);
            }
        }
        Ok(())
    };
    let incoming = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
    parse_into(current, &mut bits)?;
    parse_into(incoming, &mut bits)?;
    let has = |p: usize| bits[p / 64] & (1u64 << (p % 64)) != 0;
    let mut ranges = Vec::new();
    let mut p = 0;
    while p < 65536 {
        if bits[p / 64] == 0 {
            p += 64 - (p % 64);
            continue;
        }
        if !has(p) {
            p += 1;
            continue;
        }
        let start = p;
        while p + 1 < 65536 && has(p + 1) {
            p += 1;
        }
        ranges.push(if start == p {
            start.to_string()
        } else {
            format!("{start}-{p}")
        });
        p += 1;
    }
    Ok(ranges.join(","))
}

/// The buffer of `/proc/<pid>/oom_score_adj`: as with Linux's `PROC_NUMBUF`, only the first 12
/// bytes up to a NUL are looked at (values runc writes end in a NUL), with whitespace stripped
/// from both ends (`strstrip`).
fn proc_number(data: &[u8]) -> Result<&str, Errno> {
    let data = &data[..data.len().min(12)];
    let data = data.split(|&b| b == 0).next().unwrap_or(data);
    Ok(std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?.trim())
}

/// Base 0 of Linux's `kstrtoint` (`signed`) and `kstrtouint`: a `0x` prefix is hexadecimal, a `0`
/// prefix octal, `+` is allowed, and signed ones also allow `-`. Non-numbers are EINVAL, values
/// beyond 32 bits ERANGE.
fn kstrto(s: &str, signed: bool) -> Result<i64, Errno> {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) if signed => (true, rest),
        _ => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) if h.starts_with(|c: char| c.is_ascii_hexdigit()) => (h, 16),
        _ if s.len() > 1 && s.starts_with('0') => (&s[1..], 8),
        _ => (s, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(Errno::EINVAL);
    }
    let v = u64::from_str_radix(digits, radix).map_err(|_| Errno::ERANGE)?;
    match (signed, neg) {
        (true, true) if v <= 1 << 31 => Ok(-(v as i64)),
        (true, false) if v <= i32::MAX as u64 => Ok(v as i64),
        (false, _) if v <= u32::MAX as u64 => Ok(v as i64),
        _ => Err(Errno::ERANGE),
    }
}

// ---- Shared helpers ----

/// The thread group a pid directory names. `/proc/<pid>` resolves any thread id, not only
/// thread group ids (Linux's `proc_pid_lookup` finds any task; readdir lists only the groups):
/// such a directory looks like its process's, seen through that thread (`status` and `comm` are
/// the thread's, `stat` adds up the whole group).
pub(crate) fn group_of(k: &Kernel, pid: Tid) -> Option<&Rc<RefCell<ThreadGroup>>> {
    k.groups
        .get(&pid)
        .or_else(|| k.groups.get(&k.tasks.get(&pid)?.tgid))
}

/// Like [`group_of`], additionally requiring the thread group's non-reusable serial to match
/// `proc.serial` so a held `/proc/<pid>` node never resolves to a new process reusing the pid.
pub(crate) fn group_of_id(k: &Kernel, proc: ProcId) -> Option<&Rc<RefCell<ThreadGroup>>> {
    group_of(k, proc.pid).filter(|g| g.borrow().serial == proc.serial)
}

fn pid_exists_in(k: &Kernel, proc: ProcId, tid: Option<Tid>) -> bool {
    match (group_of_id(k, proc), tid) {
        (None, _) => false,
        (Some(_), None) => true,
        // An exited main thread stays, as a zombie, until the process is reaped
        (Some(g), Some(t)) => {
            let g = g.borrow();
            g.threads.contains(&t) || (t == g.tgid && g.leader_exit.is_some())
        }
    }
}

/// Whether `node` refers to a process or thread that has been reaped (or exited, for a non-leader
/// thread), or to a cgroup file whose cgroup was removed or whose controller was disabled: reads
/// at offset 0 of an already-open file must fail with `ESRCH`/`ENODEV` instead of returning a
/// cached open-time snapshot.
pub(crate) fn gone(k: &Kernel, node: &PseudoNode) -> bool {
    match node {
        PseudoNode::Pid(proc, tid)
        | PseudoNode::Entry(proc, tid, _)
        | PseudoNode::Net(proc, tid, _)
        | PseudoNode::Fd(proc, tid, _)
        | PseudoNode::OpenFd(proc, tid, _)
        | PseudoNode::FdInfo(proc, tid, _)
        | PseudoNode::Ns(proc, tid, _) => !pid_exists_in(k, *proc, *tid),
        PseudoNode::OpenExe(proc) => group_of_id(k, *proc).is_none(),
        PseudoNode::Cgroup(id, name, generation) if !name.is_empty() => !k
            .cgroups
            .files(*id)
            .any(|entry| entry == (*name, *generation)),
        _ => false,
    }
}

fn cpus() -> usize {
    appine_hal::host_cpus().len()
}

/// The entry named `name` under directory `dir` (empty for the tree root) in a fixed directory
/// tree (paths relative to the tree root like [`STATIC`], directories ending in `/`).
fn tree_lookup(tree: &[&'static [u8]], dir: &[u8], name: &[u8]) -> Option<&'static [u8]> {
    tree.iter().copied().find(|p| {
        let p = p.strip_suffix(b"/").unwrap_or(p);
        p.len() == dir.len() + name.len() && p.starts_with(dir) && p.ends_with(name)
    })
}

/// The direct entries under directory `dir` in a fixed directory tree.
fn tree_children<'t>(
    tree: &'t [&'static [u8]],
    dir: &'t [u8],
) -> impl Iterator<Item = &'static [u8]> + 't {
    tree.iter().copied().filter(move |p| {
        let p = p.strip_suffix(b"/").unwrap_or(p);
        p.len() > dir.len() && p.starts_with(dir) && !p[dir.len()..].contains(&b'/')
    })
}

/// The parent directory in a fixed directory tree; None directly under the tree root.
fn tree_parent(tree: &[&'static [u8]], path: &[u8]) -> Option<&'static [u8]> {
    let p = path.strip_suffix(b"/").unwrap_or(path);
    let i = p.iter().rposition(|&b| b == b'/')?;
    tree.iter().copied().find(|q| *q == &p[..=i])
}

/// The last component of a path.
fn tree_name(path: &[u8]) -> &[u8] {
    let p = path.strip_suffix(b"/").unwrap_or(path);
    &p[p.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1)..]
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Number-taking /proc files: up to a NUL, only the first 12 bytes, base 0, beyond 32 bits is
    /// ERANGE.
    #[test]
    fn vmstat_without_the_host_file() {
        let m = appine_hal::MemInfo {
            free: 8192 * 4096,
            slab: 30 * 4096,
            sreclaimable: 10 * 4096,
            ..Default::default()
        };
        let text = vmstat(None, &m);
        assert!(text.starts_with("nr_free_pages 8192\n"));
        assert!(text.contains("\nnr_slab_unreclaimable 20\n"));
        for key in [
            "pgpgin",
            "pgpgout",
            "pswpin",
            "pswpout",
            "pgfault",
            "pgmajfault",
        ] {
            assert!(text.contains(&format!("\n{key} 0\n")), "{key}");
        }
        assert_eq!(vmstat(Some("pgpgin 5\n".into()), &m), "pgpgin 5\n");
    }

    #[test]
    fn proc_numbers() {
        let num = |d: &[u8], signed| kstrto(proc_number(d)?, signed);
        assert_eq!(num(b"0\0", true), Ok(0));
        assert_eq!(num(b"-500\0junk", true), Ok(-500));
        assert_eq!(num(b" 12\n", true), Ok(12));
        assert_eq!(num(b"+0x1f", false), Ok(31));
        assert_eq!(num(b"017", false), Ok(15));
        assert_eq!(num(b"0", false), Ok(0));
        assert_eq!(num(b"-1", false), Err(Errno::EINVAL));
        assert_eq!(num(b"-2147483648", true), Ok(-(1 << 31)));
        assert_eq!(num(b"2147483648", true), Err(Errno::ERANGE));
        assert_eq!(num(b"4294967296", false), Err(Errno::ERANGE));
        assert_eq!(num(b"08", false), Err(Errno::EINVAL));
        assert_eq!(num(b"0x", false), Err(Errno::EINVAL));
        assert_eq!(num(b"", true), Err(Errno::EINVAL));
        assert_eq!(num(b"1 2", true), Err(Errno::EINVAL));
        // Bytes from the 13th on are ignored
        assert_eq!(num(b"000000000001x", false), Ok(1));
    }

    #[test]
    fn cpu_lists_and_masks_round_trip() {
        assert_eq!(parse_cpu_list("0-2,5"), vec![0, 1, 2, 5]);
        assert_eq!(parse_cpu_list("7"), vec![7]);
        assert_eq!(parse_cpu_mask("00000001,0000000f"), vec![0, 1, 2, 3, 32]);
        assert_eq!(cpu_list_of(&[0, 1, 2, 5, 7, 8]), "0-2,5,7-8\n");
        assert_eq!(cpu_list_of(&[3]), "3\n");
        assert_eq!(cpu_list_of(&[]), "\n");
        assert_eq!(cpu_mask_for(1, &[0]), "1\n");
        assert_eq!(cpu_mask_for(4, &[0, 1, 2, 3]), "f\n");
        assert_eq!(cpu_mask_for(8, &[0]), "01\n");
        assert_eq!(cpu_mask_for(8, &[0, 1, 2, 3, 4, 5, 6, 7]), "ff\n");
        assert_eq!(cpu_mask_for(36, &[0, 1, 2, 3, 32]), "1,0000000f\n");
        assert_eq!(cpu_mask_for(64, &[0, 63]), "80000000,00000001\n");
    }

    #[test]
    fn aio_has_iter_matches_linux_procfs_and_kernfs() {
        // procfs non-seq_file entries refuse both read and write AIO.
        for e in [
            Entry::Mem,
            Entry::Pagemap,
            Entry::Cmdline,
            Entry::Environ,
            Entry::Auxv,
            Entry::OomScoreAdj,
            Entry::CoredumpFilter,
        ] {
            let node = PseudoNode::Entry(ProcId { pid: 1, serial: 1 }, None, e);
            assert!(!has_iter(&node, false), "{e:?} read");
            assert!(!has_iter(&node, true), "{e:?} write");
        }
        assert!(!has_iter(&PseudoNode::Global(Global::Kmsg), false));
        assert!(!has_iter(&PseudoNode::Global(Global::Kmsg), true));

        // procfs seq_file entries allow AIO read and refuse AIO write.
        let cpuinfo = PseudoNode::Global(Global::Cpuinfo);
        assert!(has_iter(&cpuinfo, false));
        assert!(!has_iter(&cpuinfo, true));
        let status = PseudoNode::Entry(ProcId { pid: 1, serial: 1 }, None, Entry::Status);
        assert!(has_iter(&status, false));
        assert!(!has_iter(&status, true));

        // sysctl, sysfs, and cgroup2 (kernfs) allow both AIO read and write.
        let sysctl = PseudoNode::Static(b"sys/kernel/ostype");
        assert!(has_iter(&sysctl, false));
        assert!(has_iter(&sysctl, true));
        let cg = PseudoNode::Cgroup(1, b"memory.max", 0);
        assert!(has_iter(&cg, false));
        assert!(has_iter(&cg, true));
    }

    #[test]
    fn ipc_and_net_sysctl_paths_exclude_directories() {
        assert!(!is_ipc_sysctl_path(b"sys/fs/mqueue/"));
        assert!(is_ipc_sysctl_path(b"sys/fs/mqueue/queues_max"));
        assert!(is_ipc_sysctl_path(b"sys/fs/mqueue/msg_max"));
        assert!(is_ipc_sysctl_path(b"sys/kernel/shmmax"));
        assert!(!is_ipc_sysctl_path(b"sys/kernel/"));

        assert!(!is_net_sysctl_path(b"sys/net/"));
        assert!(!is_net_sysctl_path(b"sys/net/core/"));
        assert!(!is_net_sysctl_path(b"sys/net/ipv4/"));
        assert!(!is_net_sysctl_path(b"sys/net/ipv4/conf/"));
        assert!(!is_net_sysctl_path(b"sys/net/unix/"));
        assert!(is_net_sysctl_path(b"sys/net/core/somaxconn"));
        assert!(is_net_sysctl_path(b"sys/net/ipv4/ip_forward"));

        assert!(is_uts_sysctl_path(b"sys/kernel/hostname"));
        assert!(is_uts_sysctl_path(b"sys/kernel/domainname"));
        assert!(!is_uts_sysctl_path(b"sys/kernel/"));
        assert!(is_pid_sysctl_path(b"sys/kernel/ns_last_pid"));
        assert!(!is_pid_sysctl_path(b"sys/kernel/pid_max"));

        let proc = ProcId { pid: 1, serial: 1 };
        assert!(writable(&PseudoNode::Entry(proc, None, Entry::Comm)));
        assert!(writable(&PseudoNode::Entry(proc, Some(2), Entry::Comm)));
        assert!(STATIC.contains(&PROTECTED_FIFOS));
        assert!(STATIC.contains(&PROTECTED_REGULAR));
        let k = Kernel::new(crate::process::Tier::Interpreter);
        assert_eq!(recorded_value(&k, PROTECTED_FIFOS), 1);
        assert_eq!(recorded_value(&k, PROTECTED_REGULAR), 2);
    }

    #[test]
    fn overlay_redirect_always_follow_reports_n() {
        let dir = std::env::temp_dir().join(format!("appine-pseudo-ovl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        drop(crate::vfs::store::Store::create(&dir).unwrap());
        let vfs = crate::vfs::Vfs::open(&dir).unwrap();
        let k = Kernel::new(crate::process::Tier::Interpreter);
        let view = View {
            k: &k,
            vfs: &vfs,
            tid: 1,
            tgid: 1,
            cred: None,
            opening: false,
        };
        assert_eq!(
            content(
                &view,
                crate::vfs::SYS_MOUNT,
                &PseudoNode::Sys(b"module/overlay/parameters/redirect_always_follow"),
            )
            .unwrap(),
            b"N\n"
        );
        assert_eq!(
            content(
                &view,
                crate::vfs::SYS_MOUNT,
                &PseudoNode::Sys(b"module/overlay/parameters/redirect_max"),
            )
            .unwrap(),
            b"256\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn string_bitmap_sysctl_and_synthetic_write_positions() {
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let cred = Cred::root();
        let ns = k.init_ns.clone();
        let pid_ns = PidNs::init();
        let uts = PinnedUts(ns.uts.clone());
        let net = PinnedNet(ns.net.clone());
        let hostname = PseudoNode::UtsSysctl(b"sys/kernel/hostname", uts.clone());
        let reserved = PseudoNode::NetSysctl("ipv4/ip_local_reserved_ports", net.clone());

        // String and bitmap sysctls are classified as sysctl writes (gathered writev + pos rules).
        for node in [
            hostname.clone(),
            reserved.clone(),
            PseudoNode::NetSysctl("ipv4/tcp_congestion_control", net.clone()),
            PseudoNode::Static(b"sys/kernel/core_pattern"),
            PseudoNode::Static(b"sys/kernel/modprobe"),
            PseudoNode::Static(b"sys/kernel/printk_devkmsg"),
            PseudoNode::Static(b"sys/kernel/seccomp/actions_logged"),
        ] {
            assert!(is_sysctl_write(&node));
        }

        // Bitmap merging helper for nonzero-offset writes to ip_local_reserved_ports.
        assert_eq!(merge_port_bitmap("1000\n", b"2000\n").unwrap(), "1000,2000");
        assert_eq!(
            merge_port_bitmap("1000-1005\n", b"1003-1010,500\n").unwrap(),
            "500,1000-1010"
        );
        assert_eq!(merge_port_bitmap("1000\n", b"\n").unwrap(), "1000");
        assert_eq!(merge_port_bitmap("1000\n", b"bad\n"), Err(Errno::EINVAL));
        assert_eq!(
            merge_port_bitmap("1000\n", b"2000-1000\n"),
            Err(Errno::EINVAL)
        );

        let sub = k
            .cgroups
            .mkdir(crate::cgroup::ROOT, b"sub", &cred, 0o755)
            .unwrap();
        let cg = PseudoNode::Cgroup(sub, b"cgroup.max.depth", 0);
        let mut do_write = |node: &PseudoNode, data: &[u8], pos: u64| {
            write(
                &mut k,
                (1, &cred, &cred),
                (&ns, &pid_ns),
                node,
                data,
                (pos, data.len()),
            )
        };
        let read_reserved = || {
            crate::netconf::sysctl_read(&net.0.devs.borrow().conf, "ipv4/ip_local_reserved_ports")
        };

        // String sysctl: offset 0 updates and advances pos; nonzero offset ignores and advances.
        let (n, pos) = do_write(&hostname, b"hostA\n", 0).unwrap();
        assert_eq!((n, pos), (6, 6));
        assert_eq!(uts.0.hostname.borrow().as_slice(), b"hostA");
        let (n, pos) = do_write(&hostname, b"hostB\n", pos).unwrap();
        assert_eq!((n, pos), (6, 12));
        assert_eq!(uts.0.hostname.borrow().as_slice(), b"hostA");

        // Bitmap sysctl: offset 0 replaces and advances pos; nonzero offset ORs into bitmap.
        let (n, pos) = do_write(&reserved, b"1000\n", 0).unwrap();
        assert_eq!((n, pos), (5, 5));
        assert_eq!(read_reserved(), "1000\n");
        let (n, pos) = do_write(&reserved, b"2000,1001\n", pos).unwrap();
        assert_eq!((n, pos), (10, 15));
        assert_eq!(read_reserved(), "1000-1001,2000\n");
        // Invalid write at nonzero offset fails with EINVAL and leaves value intact.
        assert_eq!(do_write(&reserved, b"oops\n", pos), Err(Errno::EINVAL));
        assert_eq!(read_reserved(), "1000-1001,2000\n");
        // Offset 0 replaces again.
        let (n, pos) = do_write(&reserved, b"3000\n", 0).unwrap();
        assert_eq!((n, pos), (5, 5));
        assert_eq!(read_reserved(), "3000\n");

        // Cgroup2 file write advances position (kernfs_fop_write_iter) and accepts subsequent writes.
        let (n, pos) = do_write(&cg, b"10\n", 0).unwrap();
        assert_eq!((n, pos), (3, 3));
        let (n, pos) = do_write(&cg, b"20\n", pos).unwrap();
        assert_eq!((n, pos), (3, 6));
    }

    #[test]
    fn nsfs_ino_of_and_dev_ino_match_stat() {
        let ns_node = PseudoNode::NsFile(NsKind::Net, 4_026_531_992);
        assert_eq!(node_ino(&ns_node), 4_026_531_992);
        assert_eq!(ino_of(&ns_node), 4_026_531_992);
        let file = OpenFile::new(
            FileKind::Proc {
                mnt: crate::vfs::PROC_MOUNT,
                node: ns_node,
                data: Vec::new(),
                fresh: false,
                mm: None,
                ns: None,
                klog: None,
                opener: Rc::new(Cred::root()),
                event: None,
            },
            oflags::O_RDONLY,
        );
        assert_eq!(
            crate::syscall::dev_ino(&file.borrow()),
            (Fs::Nsfs.dev(), 4_026_531_992)
        );
    }

    #[test]
    fn sockets_report_creator_uid_even_when_inflight() {
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let (_a, b) =
            crate::unix::UnixSocket::pair(crate::net::SOCK_DGRAM, crate::unix::Ucred::of(1, 0, 0));

        // Send a socket created by UID 2000 over SCM_RIGHTS so it is only in-flight (not in any
        // task's fd table).
        let mut payload = crate::unix::UnixSocket::new(crate::net::SOCK_STREAM);
        payload.uid = 2000;
        let payload_sock = Rc::new(RefCell::new(crate::net::Socket::Unix(payload)));
        let payload_file = OpenFile::new(FileKind::Socket(payload_sock.clone()), oflags::O_RDWR);

        b.rx.borrow_mut().push(crate::unix::Packet {
            data: b"hi".to_vec(),
            off: 0,
            fds: vec![payload_file],
            cred: crate::unix::Ucred::of(1, 0, 0),
            from: Vec::new(),
            outq: None,
        });
        k.unix_inflight.push(Rc::downgrade(&b.rx));

        // `sockets(&k)` must not borrow any socket RefCell (e.g. while a netlink socket is
        // mutably borrowed during `forward_all`).
        let listed = {
            let _held = payload_sock.borrow_mut();
            sockets(&k)
        };
        assert_eq!(listed.len(), 1);
        assert!(Rc::ptr_eq(&listed[0], &payload_sock));
        assert_eq!(listed[0].borrow().uid(), 2000);
    }

    #[test]
    fn vm_layout_matches_linux_status_and_statm_semantics() {
        use crate::mm::{Mm, flags};
        use appine_engine::prot;

        let mut mm = Mm::new();
        let mut map = |pages, p, f| {
            mm.mmap(0, pages * PAGE_SIZE, p, f | flags::MAP_ANONYMOUS, None)
                .unwrap()
        };
        // Private writable data (16 KiB), executable non-writable code (8 KiB),
        // shared writable (12 KiB, excluded from VmData), grows-down stack (8 KiB, in VmStk).
        let data = map(4, prot::READ | prot::WRITE, flags::MAP_PRIVATE);
        let code = map(2, prot::READ | prot::EXEC, flags::MAP_PRIVATE);
        map(3, prot::READ | prot::WRITE, flags::MAP_SHARED);
        let stack = map(2, prot::READ | prot::WRITE, flags::MAP_PRIVATE);
        mm.code = (code, code + PAGE_SIZE);
        mm.set_growsdown(stack);
        assert_ne!(data, 0);
        assert_ne!(stack, 0);

        let layout = vm_layout(&mm);
        assert_eq!(layout.size, 11 * PAGE_SIZE);
        assert_eq!(layout.data, 4 * PAGE_SIZE);
        assert_eq!(layout.stack, 2 * PAGE_SIZE);
        assert_eq!(layout.exec, 2 * PAGE_SIZE);
        assert_eq!(layout.code_span, PAGE_SIZE);
        // status VmExe = min(code_span, exec) = 4 KiB, VmLib = exec - VmExe = 4 KiB
        let exe = layout.code_span.min(layout.exec);
        let lib = layout.exec.saturating_sub(exe);
        assert_eq!(exe, PAGE_SIZE);
        assert_eq!(lib, PAGE_SIZE);
        // statm data field = (VmData + VmStk) in pages = 6
        assert_eq!((layout.data + layout.stack) / PAGE_SIZE, 6);
    }

    pub(crate) fn mm_with_env(env: &[u8]) -> (crate::mm::Mm, u64) {
        use crate::mm::{Mm, flags};
        use appine_engine::prot;
        let mut mm = Mm::new();
        let addr = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                prot::READ | prot::WRITE,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.write(
            crate::uaccess::UserSlice::new(addr + PAGE_SIZE, env.len()),
            env,
        )
        .unwrap();
        mm.env = (addr + PAGE_SIZE, addr + PAGE_SIZE + env.len() as u64);
        (mm, addr)
    }

    pub(crate) fn add_task(
        k: &mut Kernel,
        tid: Tid,
        uid: u32,
        dumpable: bool,
        env: &[u8],
    ) -> (ProcId, u64, appine_engine::Cpu) {
        use crate::process::ThreadGroup;
        use crate::signal::SigHandlers;
        let group = Rc::new(RefCell::new(ThreadGroup::new(
            tid,
            1,
            Rc::new(RefCell::new(SigHandlers::default())),
        )));
        group.borrow_mut().dumpable = dumpable;
        let mut cred = Cred::root();
        cred.user_ns = k.init_ns.ipc.owner.clone();
        if uid != 0 {
            cred.setgid(uid).unwrap();
            cred.setuid(uid).unwrap();
        }
        group.borrow_mut().cred = cred;
        let proc = ProcId::of(tid, &group.borrow());
        let (addr, cpu) = add_thread(k, tid, &group, env);
        k.groups.insert(tid, group);
        (proc, addr, cpu)
    }

    fn add_thread(
        k: &mut Kernel,
        tid: Tid,
        group: &Rc<RefCell<ThreadGroup>>,
        env: &[u8],
    ) -> (u64, appine_engine::Cpu) {
        use crate::task::{FsContext, Task, TaskState};
        use crate::vfs::{INIT_MNT_NS, MntNs, Node};

        let (mm, addr) = mm_with_env(env);
        let mm = mm.into_shared();
        let fds = Rc::new(RefCell::new(crate::fd::FdTable::new()));
        let fs = Rc::new(RefCell::new(FsContext {
            root: Node::ROOT,
            cwd: Node::ROOT,
            umask: 0o022,
            mnt_ns: Rc::new(MntNs {
                id: INIT_MNT_NS,
                owner: k.init_ns.ipc.owner.clone(),
                anon: false,
            }),
        }));
        let cpu = unsafe { appine_engine::Cpu::new(mm.borrow().mmu()) };
        let state = TaskState {
            mm,
            fds,
            fs,
            group: group.clone(),
            vfs: k.vfs.clone(),
            altstack: Default::default(),
            clear_child_tid: 0,
            vfork_done: None,
            restart: None,
            fast_sleep: None,
            sem_undo: Rc::new(crate::ipc::SemUndo::new()),
        };
        let task = Task::new(
            tid,
            group.borrow().tgid,
            &cpu,
            state,
            k.init_ns.clone(),
            0,
            [0; 16],
        )
        .unwrap();
        group.borrow_mut().threads.push(tid);
        k.tasks.insert(tid, task);
        (addr, cpu)
    }

    #[test]
    fn environ_fd_and_ns_modes_and_ptrace_access_match_linux() {
        let dir = std::env::temp_dir().join(format!(
            "appine-pseudo-environ-{}-{}",
            std::process::id(),
            crate::tty::wall_ns()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        drop(crate::vfs::store::Store::create(&dir).unwrap());
        let vfs = Rc::new(Vfs::open(&dir).unwrap());
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        k.vfs = Some(vfs.clone());

        let (root_proc, _, _c1) = add_task(&mut k, 10, 0, true, b"SECRET=root\0");
        let (alice_proc, _, _c2) = add_task(&mut k, 20, 1000, true, b"USER=alice\0");
        let (nondump_proc, _, _c3) = add_task(&mut k, 21, 1000, false, b"SECRET=nondump\0");

        let view_as = |tid: Tid| View {
            k: &k,
            vfs: &vfs,
            tid,
            tgid: tid,
            cred: None,
            opening: false,
        };

        // Modes: environ is 0o400, fd/ and ns/ are 0o500.
        let v_root = view_as(10);
        for (entry, mode) in [
            (Entry::Environ, mode::S_IFREG | 0o400),
            (Entry::Fd, mode::S_IFDIR | 0o500),
            (Entry::Ns, mode::S_IFDIR | 0o500),
        ] {
            assert_eq!(
                stat(&v_root, &PseudoNode::Entry(root_proc, None, entry))
                    .unwrap()
                    .mode,
                mode
            );
        }
        let environ = |reader: &View<'_>, target| {
            content(
                reader,
                crate::vfs::PROC_MOUNT,
                &PseudoNode::Entry(target, None, Entry::Environ),
            )
        };
        let v_alice = view_as(20);
        assert_eq!(environ(&v_alice, root_proc), Err(Errno::EACCES));
        assert_eq!(environ(&v_alice, nondump_proc), Err(Errno::EACCES));
        assert_eq!(environ(&v_alice, alice_proc).unwrap(), b"USER=alice\0");
        assert_eq!(environ(&v_root, alice_proc).unwrap(), b"USER=alice\0");

        // read_environ uses the pinned mm and yields EOF once the mm is gone.
        assert_eq!(
            read_environ(Some(&k.tasks[&20].res.borrow().mm)),
            b"USER=alice\0"
        );
        assert_eq!(read_environ(None), Vec::<u8>::new());

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn with_test_mount(name: &[u8], test: impl FnOnce(&Vfs)) {
        let dir = std::env::temp_dir().join(format!(
            "appine-pseudo-mount-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let store = Store::create(&dir).unwrap();
        store
            .mkdir(crate::vfs::store::ROOT, name, 0o755, 0, 0)
            .unwrap();
        drop(store);
        test(&Vfs::open(&dir).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn test_view<'a>(k: &'a Kernel, vfs: &'a Vfs) -> View<'a> {
        View {
            k,
            vfs,
            tid: INIT,
            tgid: INIT,
            cred: None,
            opening: false,
        }
    }

    #[test]
    fn fdinfo_and_namespace_link_owners_follow_target_credentials() {
        use crate::cred::{IdMap, UserNs};
        with_test_mount(b"proc", |vfs| {
            let mut k = Kernel::new(crate::process::Tier::Interpreter);
            let (proc, _, _leader_cpu) = add_task(&mut k, 10, 1000, true, b"");
            let group = k.groups[&10].clone();
            let (_, _worker_cpu) = add_thread(&mut k, 11, &group, b"");
            let user_ns = UserNs::child(&k.init_ns.ipc.owner, 1000, false);
            *user_ns.uid_map.borrow_mut() = IdMap::parse(b"0 2000 10").unwrap();
            *user_ns.gid_map.borrow_mut() = IdMap::parse(b"0 3000 10").unwrap();
            let mut worker = k.tasks[&11].cred.borrow_mut();
            worker.user_ns = user_ns;
            worker.euid = 2001;
            worker.egid = 3002;
            drop(worker);

            let view = test_view(&k, vfs);
            for (dumpable, leader_owner, worker_owner) in [
                (true, (1000, 1000), (2001, 3002)),
                (false, (0, 0), (2000, 3000)),
            ] {
                group.borrow_mut().dumpable = dumpable;
                for (tid, owner) in [(None, leader_owner), (Some(11), worker_owner)] {
                    let dir = PseudoNode::Entry(proc, tid, Entry::FdInfo);
                    assert_eq!(stat(&view, &dir).unwrap().mode, mode::S_IFDIR | 0o500);
                    for node in [
                        PseudoNode::FdInfo(proc, tid, 0),
                        PseudoNode::Ns(proc, tid, NsKind::Net),
                    ] {
                        let st = stat(&view, &node).unwrap();
                        assert_eq!((st.uid, st.gid), owner);
                    }
                }
                let nsfs = stat(&view, &PseudoNode::NsFile(NsKind::Net, k.init_ns.net.id)).unwrap();
                assert_eq!((nsfs.uid, nsfs.gid), (0, 0));
            }
            assert_eq!(
                stat(&view, &PseudoNode::PtsRoot(Fs::Pts.dev()))
                    .unwrap()
                    .mode,
                mode::S_IFDIR | 0o755
            );
        });
    }

    #[test]
    fn stat_start_time_follows_the_named_thread() {
        with_test_mount(b"proc", |vfs| {
            let mut k = Kernel::new(crate::process::Tier::Interpreter);
            let (_, _, _leader_cpu) = add_task(&mut k, 10, 0, true, b"");
            let group = k.groups[&10].clone();
            let (_, _worker_cpu) = add_thread(&mut k, 11, &group, b"");
            // Distinguish all three creation ticks even when the tasks were created in one tick.
            group.borrow_mut().start_ticks = 10;
            for (tid, ticks) in [(10, 11), (11, 20)] {
                Rc::get_mut(k.tasks.get_mut(&tid).unwrap())
                    .unwrap()
                    .start_ticks = ticks;
            }
            let view = test_view(&k, vfs);
            for (path, expected) in [
                (b"/proc/10/stat".as_slice(), 10),
                (b"/proc/10/task/10/stat", 10),
                (b"/proc/11/stat", 20),
                (b"/proc/10/task/11/stat", 20),
            ] {
                let Node::Pseudo(mnt, node) = vfs
                    .resolve(&view, &Cred::root(), &Node::ROOT, &Node::ROOT, path, true)
                    .unwrap()
                else {
                    panic!("expected a procfs stat file");
                };
                let line = String::from_utf8(content(&view, mnt, &node).unwrap()).unwrap();
                // Field 3 (state) follows the parenthesized comm. Field 22 is starttime.
                let (_, fields) = line.rsplit_once(')').unwrap();
                let start = fields.split_whitespace().nth(19).unwrap();
                assert_eq!(start.parse::<u64>().unwrap(), expected, "{path:?}");
            }
        });
    }

    #[test]
    fn loop_device_numbers_resolve_to_block_attributes() {
        use crate::vfs::SYS_MOUNT;
        with_test_mount(b"sys", |vfs| {
            let k = Kernel::new(crate::process::Tier::Interpreter);
            let view = test_view(&k, vfs);
            let resolve = |path: &[u8], follow| {
                vfs.resolve(&view, &Cred::root(), &Node::ROOT, &Node::ROOT, path, follow)
            };
            let dir = resolve(b"/sys/dev/block", true).unwrap();
            let Node::Pseudo(_, ref block) = dir else {
                panic!("expected sysfs");
            };
            let entries = readdir(&view, SYS_MOUNT, block).unwrap();
            let numbers = k.loops.numbers();
            assert_eq!(entries.len(), numbers.len());
            for (entry, n) in entries.iter().zip(numbers) {
                assert_eq!(entry.name, format!("7:{n}").as_bytes());
                assert_eq!(entry.mode, mode::S_IFLNK);
            }
            for name in [
                b"7".as_slice(),
                b"7:",
                b":0",
                b"07:0",
                b"7:00",
                b"7:+0",
                b"7:0:1",
                b"7:4294967296",
                b"8:1",
                b"7:99999",
            ] {
                assert_eq!(
                    view.lookup(SYS_MOUNT, block, name),
                    Err(Errno::ENOENT),
                    "{name:?}"
                );
            }
            assert_eq!(view.missing_path(&dir, b"8:1"), None);
            let Node::Pseudo(_, link) = resolve(b"/sys/dev/block/7:0", false).unwrap() else {
                panic!("expected sysfs");
            };
            assert_eq!(view.parent(&link).as_ref(), Some(block));
            assert_eq!(stat(&view, &link).unwrap().mode, mode::S_IFLNK | 0o777);
            assert_eq!(
                view.readlink(SYS_MOUNT, &link).unwrap(),
                b"../../block/loop0"
            );
            let direct = resolve(b"/sys/block/loop0/uevent", true).unwrap();
            assert_eq!(
                resolve(b"/sys/dev/block/7:0/uevent", true),
                Ok(direct.clone())
            );
            let Node::Pseudo(mnt, file) = direct else {
                panic!("expected sysfs");
            };
            assert_eq!(
                content(&view, mnt, &file).unwrap(),
                b"MAJOR=7\nMINOR=0\nDEVNAME=loop0\nDEVTYPE=disk\n"
            );
            let st = stat(&view, &file).unwrap();
            assert_eq!(
                (st.mode, st.size, st.blocks),
                (mode::S_IFREG | 0o444, 4096, Some(0))
            );
            assert!(pollable(&file) && has_iter(&file, false) && has_iter(&file, true));
            let queue_file = resolve(b"/sys/block/loop1/queue/rotational", true).unwrap();
            assert_eq!(
                resolve(b"/sys/dev/block/7:1/queue/rotational", true),
                Ok(queue_file)
            );
            let absent = 99999;
            assert_eq!(
                view.readlink(mnt, &PseudoNode::SysDevBlock(absent)),
                Err(Errno::ENOENT)
            );
            assert_eq!(
                content(&view, mnt, &PseudoNode::SysBlock(absent, b"uevent")),
                Err(Errno::ENOENT)
            );
        });
    }

    #[test]
    fn sys_dev_lists_each_available_directory_once() {
        use crate::gpu::{Context, Renderer};
        use crate::vfs::SYS_MOUNT;
        use std::sync::Arc;

        struct TestRenderer;
        impl Renderer for TestRenderer {
            fn capset(&self) -> &[u8] {
                &[]
            }
            fn open(&self) -> Result<Arc<dyn Context>, Errno> {
                unreachable!()
            }
        }
        with_test_mount(b"sys", |vfs| {
            let mut k = Kernel::new(crate::process::Tier::Interpreter);
            for gpu in [false, true] {
                k.gpu = gpu.then(|| Arc::new(TestRenderer) as Arc<dyn Renderer>);
                let view = test_view(&k, vfs);
                let root = PseudoNode::SysRoot;
                let dev = view.lookup(SYS_MOUNT, &root, b"dev").unwrap();
                assert_eq!(
                    readdir(&view, SYS_MOUNT, &root)
                        .unwrap()
                        .iter()
                        .filter(|e| e.name == b"dev")
                        .count(),
                    1
                );
                let names: Vec<_> = readdir(&view, SYS_MOUNT, &dev)
                    .unwrap()
                    .into_iter()
                    .map(|e| e.name)
                    .collect();
                let mut expected = vec![b"block".to_vec()];
                let block = view.lookup(SYS_MOUNT, &dev, b"block").unwrap();
                assert_eq!(view.parent(&block).as_ref(), Some(&dev));
                let char_dir = view.lookup(SYS_MOUNT, &dev, b"char");
                if gpu {
                    expected.push(b"char".to_vec());
                    assert_eq!(view.parent(&char_dir.unwrap()).as_ref(), Some(&dev));
                } else {
                    assert_eq!(char_dir, Err(Errno::ENOENT));
                }
                assert_eq!(names, expected);
            }
        });
    }
}
