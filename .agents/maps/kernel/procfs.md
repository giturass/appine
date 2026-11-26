# kernel/procfs Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/procfs.md` for the paired decision history (it still holds the decisions on cgroups/device BPF, `/proc/sys` sysctls and sysfs made before they were split out into `kernel/cgroup`, `kernel/sysctl` and `kernel/sysfs`).
>
> Verified: 2026-11-11 (full mapping: 6 research concerns; 22 claims checked by 3 independent verifiers — 19 confirmed and 3 partial, corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: fdinfo permissions, namespace-link ownership, devpts root mode and per-thread stat start times)

## Responsibilities

`kernel/procfs` provides the synthetic filesystem core and the non-sysctl/non-sysfs views,
generated live from kernel state with nothing stored:

- procfs: the per-process and per-thread trees, system-wide files, `/proc/sysvipc` and
  `/proc/<pid>/net`;
- devpts as a filesystem (instances, nodes, owners and modes), nsfs nodes and the node views of
  the mqueue filesystem;
- the shared synthetic-node framework (`PseudoNode`, `View`, `Offline`, snapshot generation,
  poll-event wiring and missing-path accounting) used by `kernel/sysctl` and `kernel/sysfs`;
- the cgroup2 node adapter: lookup, metadata, directory listing and dispatch to `kernel/cgroup`
  for interface-file content and writes, plus the procfs entries that show cgroup membership.

Root: `core/kernel/src/pseudo.rs`, except `kernel/sysctl`'s `/proc/sys` tables/variants/handlers
and `kernel/sysfs`'s sysfs tables/variants/section.

The cgroup tree, migration, controllers, change observation and device BPF belong to
`kernel/cgroup` (`cgroup.rs`, `bpf.rs`, `syscall/bpf.rs`); `/proc/sys` sysctls belong to
`kernel/sysctl`; `/sys` belongs to `kernel/sysfs`. The shared synthetic node and open/read/write
contracts remain here.

Outside the module: `/proc/sys` sysctls (`kernel/sysctl`); `/sys` (`kernel/sysfs`); the `Pseudo`
trait, the walker, mounts and mountinfo order and magic-link resolution (`kernel/vfs`);
open dispatch (`kernel/files`, `open_pseudo`) and read/write/lseek dispatch (`kernel/fileio`,
`refresh_pseudo`) for pseudo nodes (whose behaviour this map describes as procfs sees it); maps and `/proc/<pid>/mem` semantics
(`kernel/mm`, `kernel/ptrace`); smaps, pagemap and the Rss figures (`kernel/oom`); id maps,
`setgroups`, `timens_offsets`, `ns/*` and namespaces (`kernel/ns`); `children`, state letters and
the kernel-entry record behind `syscall` (`kernel/process`); `/proc/kmsg`, `/proc/version` and ABI
sysctls (`kernel/signal`); terminal behaviour (`kernel/tty`); network semantics behind `/proc/net`
(`kernel/net`, `kernel/route`, `kernel/netns`, `kernel/unix`); the OOM killer (`kernel/oom`); SysV
IPC and message queues (`kernel/ipc`); locks (`kernel/locks`); the mount table (`kernel/mount`).

## Key types

- `PseudoNode` — every synthetic node: devpts (`PtsRoot(dev)`, `Pts(dev, n)`, `PtsPtmx(dev)`),
  procfs (`ProcRoot`, `Global`, `SelfLink`, `ThreadSelf`, `Static(path)` for `/proc/sysvipc` plus
  `kernel/sysctl`'s `/proc/sys`, `Pid(ProcId, tid)`, `Entry(ProcId, tid, Entry)`, `Net`, `Fd(ProcId, tid, fd)`, `OpenFd`
  (the open file an fd link reaches when it is not in the store), `OpenExe` (a deleted program),
  `FdInfo(ProcId, tid, fd)`, `Ns` (the magic link), `NsFile(kind, id)` (the nsfs file), plus `kernel/sysctl`'s
  `NetConf`/`NetSysctl`), `kernel/sysfs`'s `Sys*` variants, `Cgroup(id, name)` (an empty name is
  the directory), and mqueue (`MqRoot`, `Mq`). Process-scoped variants carry `ProcId { pid, serial }`,
  pinning each handle to one thread-group instance even if the pid is later reused; nodes remain plain
  values resolved on each call.
- Tables: `GLOBALS` (15 top-level files), `ENTRIES` (34 per-process names), `TASK_ENTRIES` (the 30
  allowed under `task/<tid>`), `NsKind::ALL` (10), `PROC_NET` (18), and the `sysvipc/` entries of
  `STATIC`.
- `View` — a read-only view of the kernel for one reading thread (`tid`, `tgid`), taken under the
  BKL, with optional replacement credentials (`cred`, an opener's); implements `Pseudo`.
  `Offline::Boot` serves empty synthetic roots for boot and host spawns.
  `Offline::HostStat` reports synthetic child lookups as unavailable to host metadata samples.
- `FileKind::Proc` — an open synthetic file: mount, node, snapshot `data`, `fresh` flag, a weak
  address space for `mem`, `pagemap` and `environ`, the namespace reference of an nsfs file, the kernel-log reader for
  `/proc/kmsg`, the opener's credentials (`opener`, Linux's `f_cred`) and change state
  (`fd::ProcEvent`: a shared counter, what the file last reported and when its contents were
  made).
- `PtsOptions` (kept by the VFS per devpts instance) and the owner, mode and times kept on `Tty`.

## Public entry points

- `Pseudo for View`: `lookup`, `missing`, `parent`, `name`, `kind`, `readlink`, `follow`,
  `follow_dentry`, `magic`, `protected_symlinks`, `searched`.
- `pseudo::stat`, `node_ino`, `ino_of`, `fs_of`, `readdir`, `content`, `writable`, `unwritable_error`,
  `open_unwritable`, `unreadable`, `pollable`, `poll_event`, `has_iter`, `write`, `read_pagemap`,
  `access_mem`, `describe`, `sockets`, `socket_ino`, `pty`, `group_of`, `group_of_id`,
  `gone`, `comm_str`, `mark_deleted`, `uptime_ns`. (`sysctl_kind`/`recorded_value`/`RECORDED`
  belong to `kernel/sysctl`; `CGROUP_POINT` belongs to `kernel/sysfs`.)

## Data flow / lifecycle

### Instances, lookup and metadata

- Each procfs mount is a new instance with its own device; if the mounter is in a non-initial pid
  namespace, the instance is bound to it (by device, so bind mounts share it), otherwise it uses
  the initial one. Mount options (`hidepid`, `subset`) are ignored.
- `/proc` lookup tries `self`, `thread-self`, the top-level static directories (`sys/`,
  `sysvipc/`), the global files, then a pid; readdir lists them in that order, then the processes
  visible in the instance's namespace, sorted (zombies until reaped; threads are never listed). A
  pid name is mapped through that namespace and may name any thread (`group_of`): `/proc/<tid>` is
  its process's directory seen through that thread (`status`, `comm`, `cwd` and `fd/` are the
  thread's, `stat` adds up the group's CPU time, `task/` lists the group; its ptrace-gated entries
  open on the process's address space with the check made against that thread), and it
  disappears when the thread exits. `self`/`thread-self` are `ENOENT` for readers not visible in
  the instance.
  Numeric names (pids, fds, terminals) are decimal digits only, at most 10 without a leading zero
  and at most `i32::MAX` (Linux's `name_to_int`).
- `/proc/<pid>` has every `ENTRIES` name except `children`; `task/<tid>` has the `TASK_ENTRIES`
  (no `task`, `pagemap`, `coredump_filter` or `timens_offsets`, plus `children`); both list in
  `ENTRIES` order. `task/<n>` resolves for a live thread of the group or an exited main thread
  (`leader_exit`).
- Inode numbers hash the node (low bit set); roots are 1 (except the mqueue root); devpts `ptmx`
  is 2 and terminal n is n+3; nodes under a pid carry `ProcId { pid, serial }`, so both `node_ino`
  and `ino_of` mix in the thread group's serial and a reused pid gets new inodes; nsfs files use
  the namespace id in both `node_ino` and `ino_of`. Inodes are stable within one run.
- Because process-scoped nodes carry `ProcId { pid, serial }`, a held `/proc/<pid>` dirfd, `O_PATH`
  fd or open process file never resolves to a new process reusing that pid: once the pinned thread
  group is reaped, lookups and directory listings under it fail with `ENOENT` and offset-0 reads of
  open files fail with `ESRCH`.
- Directories default to 0555. Sysfs directories and the devpts root are 0755. Process and thread
  `fd/`, `fdinfo/` and `ns/` directories are 0500. Cgroup nodes use their current attributes.
  `fd/<n>` links use the open mode (0500 readable, 0300 writable, 0700 both, 0 for `O_PATH`).
  Other symlinks are 0777. `mem` is 0600. `syscall`, `pagemap`, `auxv`, `environ` and `/proc/kmsg`
  are 0400. Sysctls follow `kernel/sysctl`. Other writable files, including `comm`, are 0644 and
  other regular files are 0444. Devpts device nodes use the terminal's mode or `ptmxmode`.
- Owners: `Pid`, `Entry`, `Fd`, `FdInfo` and `Ns` belong to the named thread's euid/egid, or
  to root of those credentials' user namespace when the process is not dumpable; `net.*` sysctls
  follow `kernel/sysctl`; cgroup nodes have individual owners; terminals to their owner; the entries
  inside `net/`, nsfs files, reopened open files and everything else to root.
- Stat reports `st_blksize` 1024 for procfs and devpts paths, PTY masters and devpts slave fds.
  Other synthetic filesystems report 4096.
  Times are "now" except devpts terminals; directories have nlink 2 (`task/` 2
  plus threads, an exited main thread included); sizes are 0 except sysfs and cgroup2 files
  (4096).
- Names path resolution does not find (`View::missing`, Starnix's `not_found`) are counted as
  unimplemented paths (`kernel/signal`) when Linux would have them: under the procfs root (not
  numeric names), the fixed `/proc/sys` (`kernel/sysctl`) and `/proc/sysvipc` trees, an existing
  process's or thread's directory and its `net/` and `ns/`, the sysfs trees (`kernel/sysfs`), and
  at the root of the boot `/dev` tmpfs. Process, thread, CPU, interface and loop numbers become
  placeholders (`/proc/<pid>/task/<tid>/x`, `/sys/devices/system/cpu/cpu<n>/x`); fds, terminals,
  message queues, cgroups and the files of a process that has gone are never counted.

### Opening, reading and writing

- Open (`open_pseudo` in `kernel/files`), in order: `O_TRUNC` asks for write permission too; nsfs
  files refuse any write intent (`EPERM`, before DAC); `/proc/sys` uses `kernel/sysctl`'s
  permission rules instead of DAC; other nodes check DAC against the synthetic stat. Then: for
  `mem`, `auxv`, `environ`, `maps`, `smaps`, `smaps_rollup` and `pagemap`, the process must exist
  (found through `group_of_id` matching the pinned `ProcId`, else `ESRCH`) and the named thread pass one
  ptrace check with filesystem credentials and no read/attach distinction (`EACCES`, as Linux's
  `proc_mem_open`); `mem` and `pagemap` also need a live thread (`ESRCH`) and pin a weak reference
  to its address space (`Mm`) at open, while `environ` pins a weak `Mm` when live (leaving `None`
  for a zombie so open succeeds and reads EOF). Once the old address space is freed after exit or
  `execve`, an open `environ` fd returns EOF at every offset. Writing `setgroups`
  needs `CAP_SYS_ADMIN` in the process's user namespace (`EACCES`, `proc_setgroups_open`); devpts
  nodes on nodev mounts `EACCES`, then the cgroup device filter; `O_DIRECT` `EINVAL`; directories
  open read-only (`EISDIR` for a write mode); write modes on ro mounts `EROFS`.
- A node that is not writable still opens for writing when DAC passes (root) if it is a procfs
  file outside `/proc/sys`, and each write then fails: `EIO` for the files of proc entries (global
  files such as `cpuinfo` and `kmsg`, `/proc/sysvipc/*`, the single-record `netstat`, `snmp`,
  `sockstat` and `sockstat6` of `/proc/<pid>/net`; `proc_reg_write`), `EINVAL` for per-process and
  `fdinfo` files (no write operation). `/proc/sys` (`kernel/sysctl`) refuses it (`EACCES`,
  `O_TRUNC` included); sysfs (`kernel/sysfs`) and the other `/proc/<pid>/net` files (`seq_open_net`)
  refuse only a write access mode, so `O_TRUNC` alone opens them; cgroup files are checked by DAC
  only (a read-only one opens for root, and the write is `EINVAL`); creating names `EACCES`.
- The content is generated at open with the opener's credentials and marked `fresh`, except
  write-only files (`kernel/sysctl`, empty), a `NetConf` file whose generation fails (empty, the
  error reported by the first read) and `/proc/<pid>/syscall` (empty: it shows the thread when
  read, so `/proc/self/syscall` shows the read). Only a read or pread at offset 0 can regenerate:
  the first one keeps a fresh snapshot unless its change counter moved or the pinned process has
  been reaped (`pseudo::gone`, yielding `ESRCH`), later ones regenerate with
  the opener's credentials and the current reader's namespaces, root and cgroup root; reads
  elsewhere use the current snapshot while the pinned address space for `environ` is live.
  A first read at a non-zero offset leaves the snapshot fresh (only a write marks it stale). The opener's credentials include their user namespace, which
  translates the ids shown; pid numbers follow the mount's pid namespace. lseek
  (`SEEK_SET`/`CUR`/`END` against the snapshot length) never regenerates. `pagemap`, `mem` and
  `/proc/kmsg` are computed at read time (`mem` and `pagemap` from the address space held weakly
  since open, returning empty/EOF once freed or replaced by execve). Memory transfers fill missing
  FUSE pages one at a time, retaining the byte count across fills. Nsfs files cannot be read
  (`EINVAL`), nor can write-only files.
- Writes pass each chunk or iovec (one gathered input for `/proc/sys` sysctls, `kernel/sysctl`) to
  `pseudo::write` with the writer's credentials and namespaces (the id maps, `setgroups`,
  `timens_offsets` and cgroup migration also check the opener's), apply Linux 6.1 position rules —
  `mem`, `uid_map`/`gid_map` (`map_write`: requires offset 0 and `< 4096` bytes, else `EINVAL`),
  `setgroups` (`proc_setgroups_write`: requires offset 0, else `EINVAL`), cgroup2 files
  (`kernfs_fop_write_iter`) and advancing sysctls advance the open position; `timens_offsets`
  requires offset 0 and `< 4096` bytes (`EINVAL` otherwise) while keeping position unchanged;
  `comm`, `oom_score_adj` (consuming at most `PROC_NUMBUF - 1` = 12 bytes via `proc_number`/
  `kstrto`) and `coredump_filter` (consuming the full count via `kstrto`) leave the open position
  unchanged — and mark the snapshot stale.
- Change notifications (`fd::ProcEvent`, built by `pseudo::poll_event`): epoll accepts the files
  with a Linux poll operation (`pseudo::pollable`: global procfs files, `/proc/sys`,
  `/proc/sysvipc`, `/proc/<pid>/net`, mounts, mountinfo, every sysfs and cgroup2 file; other
  per-process files and nsfs are `EPERM`).
  mounts and mountinfo poll as `POLLIN|POLLRDNORM`, plus `POLLERR|POLLPRI` once the target
  thread's mount namespace (`Vfs::mount_events_of`, scoped per mount namespace and untouched by
  propagation-only changes) has changed since the open or since the last change a poll or epoll
  reported (reading does not take it in). `/proc/sys/kernel/{hostname,domainname}` similarly wake
  pollers with `POLLERR|POLLPRI` on per-name UTS changes (`kernel/sysctl`). sysfs (`kernel/sysfs`)
  and cgroup2 files poll as always readable and writable, plus `POLLERR|POLLPRI` before their first
  read from the start. Cgroup change observation, the four notifying files and their inotify keys
  belong to `kernel/cgroup`; the shared open/read path consumes its counters. Other synthetic files
  never report inotify events.

### Per-process files

- Entries: `auxv`, `stat`, `status`, `statm`, `cmdline`, `comm`, `syscall`, `environ`, `limits`,
  `maps`, `mem`, `smaps`, `smaps_rollup`, `pagemap`, `mounts`, `mountinfo`, `cwd`, `exe`,
  `root`, `fd/`, `fdinfo/`, `task/`, `net/`, `oom_score`, `oom_score_adj`, `coredump_filter`,
  `cgroup`, `ns/`, `uid_map`, `gid_map`, `projid_map`, `setgroups`, `timens_offsets`, and
  `children` under `task/<tid>` (its `oom_score` and `oom_score_adj` are the process's, and
  writing the latter sets the process's, as Linux's tid_base_stuff). Absent: `oom_adj`, `io`,
  `wchan`, `sched*`, `personality`, `loginuid`/`sessionid`, `attr/`, `stack`, `cpuset`,
  `mountstats`, `timerslack_ns`.
- `syscall` (Linux's `proc_pid_syscall`) reads `kernel/process`'s kernel-entry record: `running`
  for a live thread that is not the reader and whose state is R (in guest code or kernel code);
  for one waiting in the kernel, or the reader itself, the syscall number with x0 to x5, sp and pc
  (pc after the `svc`), or a negative number with sp and pc outside a syscall (a fault, a kick, or
  a stop in signal delivery, which forgets the syscall and shows the restart pc); `-1 0x0 0x0` for
  an exited main thread (a zombie) or no record; `ESRCH` once another thread has gone (Linux
  releases it at once). Like `lock_trace`, it needs ptrace access to that thread, checked when
  read with the reader's own credentials rather than the opener's (`EPERM`).
- `oom_score` is the OOM killer's badness scaled against the host's RAM plus swap (`kernel/oom`'s
  `proc_score`): 0 to 2000, 0 for the built-in init, `oom_score_adj` -1000, a process without
  live threads and a vfork child its parent still waits for.
- `stat`: all 52 fields; the layout fields (code bounds, start of stack, data bounds, start of
  heap, arguments, environment; `kernel/mm`) go to readers passing the ptrace read check with
  filesystem credentials (6.1's `do_task_stat`), others getting 1 for the code bounds and 0 for the
  rest (0 everywhere for a process without an address space); fault counters, `kstkesp`,
  `kstkeip`, `wchan`, `processor`, priority and policy are 0; the `signal` field is the thread's
  and the group's pending sets. Field 22 uses the named thread's creation time in ticks plus the reader's
  time-namespace boottime offset; the thread's or the group's CPU times depending on the view
  (`/proc/<tid>` the group's); `tty_nr` from the controlling terminal.
- `status`: the thread's ids (the main thread's for `/proc/<pid>`) translated into the reader's
  user namespace (the reading thread's credentials, or the opener's when regenerated),
  `NStgid`/`NSpid`/`NSpgid`/`NSsid` from the instance's namespace down, capabilities,
  the thread's `NoNewPrivs` (saved when the leader exits), `Seccomp`, signal masks (`SigPnd` the thread's, `ShdPnd` the group's); memory
  lines follow Linux 6.1's `vm_stat_account` / `task_mem` (`VmPeak` = `VmSize`, `VmHWM` from max RSS, `VmRSS` the sum of
  `RssAnon`, `RssFile` and `RssShmem` from `Mm::resident_split`, `VmData` the private writable non-stack
  mappings, `VmStk` the grows-down mappings, `VmExe` the page-aligned code span capped by executable
  non-writable mappings, `VmLib` the remaining executable non-writable mappings, `VmPTE` allocated
  soft-MMU page-table bytes and `VmSwap` exact pagemap swap when readable, otherwise zero; omitted
  with no live task); `FDSize` the open fds rounded up to 64;
  `Cpus_allowed` and `Cpus_allowed_list` show the thread's affinity (the main thread's in the
  process's `status`) clamped to the cgroup's effective cpuset as a hex mask (`cpu_mask_of`) and
  CPU list. `statm` is
  `size resident shared text 0 data 0` (matching Linux 6.1's `task_statm`: `resident` = `RssAnon +
  RssFile + RssShmem`, `shared` = `RssFile + RssShmem`, `text` = page-aligned code span, `data` =
  `VmData + VmStk` in pages).
- `maps` and `smaps` escape a newline in a mapped file's path as `\012` (Linux's
  `seq_file_path`); file mappings show device `08:01`; smaps counts anonymous resident pages as
  dirty, file pages as clean, and copy-on-write-shared pages as shared with a divided Pss.
- `cmdline`/`environ` copy the argument and environment ranges of the current mm (empty over
  1 MiB or when unreadable); `comm` is writable (0644) for tasks in the writer's thread group
  (Linux's `comm_write`: up to 15 bytes up to the first NUL verbatim, `EINVAL` across thread groups,
  `ESRCH` once exited); `limits` lists the rlimits. The thread name is
  bytes, not text: `comm` and `stat` give it as set, `status` escapes only a newline and a
  backslash (Linux's `proc_task_name`).
- `fd/` and `fdinfo/` list and inspect the fd table of the thread named: the main thread's for
  `/proc/<pid>`, and thread `tid`'s own table for `/proc/<tid>` and `/proc/<pid>/task/<tid>` (even
  when the thread unshared or cloned without `CLONE_FILES`); nodes under `task/<tid>/fd` and
  `task/<tid>/fdinfo` retain `tid`, so `..` leads back under `task/<tid>`. Listing and lookup in
  `fd/` and `fdinfo/` and reading or following `fd/N` need the ptrace read check with filesystem
  credentials (`EACCES`, Linux's `proc_fd_permission` and `proc_fd_access_allowed`), as do `root`,
  `cwd`, `exe`, `ns/*` and `stat`'s layout fields, checked against the target thread's credentials
  (`tid.unwrap_or(proc.pid)`); named fd links resolve their tracked parent and name against the reader's root.
  Renames follow the opened name. Unlinking it appends ` (deleted)` even with other hard links.
  An original `O_TMPFILE` fd keeps its `#<ino> (deleted)` name after linking.
  Reopening a deleted regular store file via `fd/N` with `O_PATH` pins its backing object.
  Stat and subsequent reopens keep the original inode across source-fd close and reuse.
  Synthetic descriptors and unreachable paths use their recorded description; `fdinfo/N` has `pos`, `flags` (octal, with
  `O_CLOEXEC`), `mnt_id`, `ino`, the `lock:` lines of the locks held through that open file
  (`kernel/locks`'s `fd_locks`; only for files or fd tables that have taken locks) and per-kind
  lines (eventfd count, inotify watches, epoll `tfd:` lines, timerfd clock and times, signalfd
  mask, pidfd pids).
- `exe` reads as the program's path recorded at execve, with ` (deleted)` once the file's last
  link is gone or, for a program found through an overlay, once that name is removed; following
  it reaches the program itself even after a rename (an overlay program through its overlay node)
  and a deleted program through the host file recorded at execve (`OpenExe`). Opening a removed
  overlay program retains the overlay mount and inode. An O_PATH reopen pins the object too.
- `mounts`/`mountinfo` come from the mount table (`kernel/mount`) for the thread's namespace and
  root (an exited thread has none: `EINVAL` at open, as `mounts_open_common`), each mount's type
  as `Vfs::type_of` gives it (`fuse.<subtype>` for a FUSE mount with a subtype); mountinfo's
  optional fields are `shared:N`, `master:N` and `unbindable` (no `propagate_from`), and its
  superblock options start with the instance's `ro`/`rw` and `sync`, `dirsync`, `mand`,
  `lazytime` (`Vfs::sb_flags`), which `mounts` puts after its `ro` (the mount's or the instance's)
  as `show_vfsmnt` does; `cgroup` is the path relative to the reader's cgroup-namespace root;
  `net/` uses the target's network namespace.
- Writable: `comm` (same thread group only, `EINVAL` otherwise, up to 15 bytes verbatim),
  `oom_score_adj` (-1000..1000; going below the minimum needs `CAP_SYS_RESOURCE`, and a
  privileged write sets the new minimum), `coredump_filter` (masked to 0x1ff), `mem`, the id maps,
  `setgroups`, `timens_offsets`.
- Zombies keep their group without tasks: stat/status work (state Z), cmdline/environ/auxv are
  empty, `fd/` is empty, `cwd`/`root`/`exe`/`ns` are `ENOENT`, `mounts`/`mountinfo` are `EINVAL`
  to open and `mem`/`pagemap` `ESRCH` (they use the address space of the thread named, which has
  none; native 6.8 answers the same). A main thread that has exited while other threads run is
  shown the same way, as Linux's zombie leader: `task/` still lists it (first), `task/<pid>` and
  the process directory report Z with its name (kept in the group) and its own CPU time for
  `task/<pid>/stat`, and `Threads`/`num_threads` and `task/`'s link count include it; the process
  directory no longer falls back to another thread.

### System-wide files and `/proc/<pid>/net`

- `meminfo`: 16 fields copied from the host's `/proc/meminfo` (falling back to host `sysinfo`), not
  clamped to cgroup limits. `vmstat`: the host's file when the app may read it, else the page
  counts meminfo gives (free, slab, anon, mapped, file, dirty, shmem) and the event counters
  procps reads at 0. `sysinfo(2)` takes memory from the host but uptime (with the time
  namespace offset), loads and the process count from the guest.
- `cpuinfo`: one block per guest CPU with the guest-visible hwcaps (HWCAP2 names up to 6.1's) and
  MIDR, BogoMIPS 100. `stat`: guest threads' CPU time (plus exited threads') with idle derived
  from uptime, split evenly over CPUs; `procs_running` counts threads in guest code (at least 1);
  `intr`, `ctxt`, `softirq` (the total and Linux's 10 types), `procs_blocked` are 0; `processes`
  counts every new task, threads included (Linux's `total_forks`); btime is recomputed per read.
  `uptime` includes the reader's boottime offset. `loadavg` comes from the guest's own load
  average. `filesystems` is a fixed list (`nodev fuse` included, no `fuseblk` or `fusectl`);
  `cmdline` is `appine`; `cgroups` reports the v1 controller names with hierarchy 0 and the total
  cgroup count. `mounts` and `net` link into `self`. `swaps` is the host's file when the app may
  read it (as meminfo's swap lines are the host's), otherwise Linux's header line alone; `locks`
  lists every lock and lease (`kernel/locks`'s `proc_locks`) with pids in the instance's pid
  namespace.
- Absent: `partitions`, `devices`, `diskstats`, `interrupts`, `modules`, `slabinfo`, `buddyinfo`,
  `sysrq-trigger`, `zoneinfo`, `pressure/*`, `kallsyms`.
- `/proc/<pid>/net/*` (`arp`, `dev`, `icmp`, `icmp6`, `if_inet6`, `ipv6_route`, `netstat`, `raw`,
  `raw6`, `route`, `snmp`, `sockstat`, `sockstat6`, `tcp`, `tcp6`, `udp`, `udp6`, `unix`) uses the
  target task's network namespace (falling back to `ThreadGroup::leader_net` or a live thread's
  network namespace when the main thread has exited as a zombie leader, before the initial
  namespace): sockets from every fd table plus in-flight AF_UNIX sockets,
  filtered by namespace, with each socket's creation-time `fsuid` (`sock_i_uid`, or the accepting
  task's `fsuid` for accepted sockets) mapped for the reader; host interface counters and routes only in
  the initial namespace (new namespaces show zeros); `snmp` reflects the namespace's IPv4
  `ip_forward` (`1` enabled, `2` disabled); `arp` is a header line.

### devpts, nsfs and mqueue nodes

- Each devpts mount is an instance (`PtsRoot(dev)`) with its own terminals and `PtsOptions`
  (`uid`, `gid`, `mode`, `ptmxmode`, `max`; defaults `mode=600,ptmxmode=000`; the boot instance
  `gid=5,mode=620,ptmxmode=666`; `newinstance` accepted and ignored; unknown options or unmapped
  ids `EINVAL`; remount does not change them; options are dropped with the instance's last mount,
  after which `BOOT`'s are reported).
- Opening `ptmx` (the instance's, or a `/dev/ptmx` node, which uses the devpts mounted on `pts`
  beside it) allocates the lowest free index (`ENOSPC` at `max`); the terminal's owner is the
  option's uid/gid or the opener's fsuid/fsgid, its mode the option's mode; chmod, chown and
  utimensat are stored on the terminal (on the root and `ptmx` they are `EACCES`). Nodes exist
  while the terminal does; readdir lists `ptmx` and every live terminal. Devices 136:n and 5:2;
  the root is 0755. fstat on a master fd always reports inode 2, mode 0666, rdev 5:2
  on the root filesystem's device, uid/gid 0 and zero times, whatever the instance and
  `ptmxmode`; a slave fd reports its terminal.
- nsfs: following `/proc/<pid>/ns/*` (after the ptrace-read check; `ENOENT` when the namespace has
  no id yet, as `pid_for_children` before its reaper) yields a regular 0444 file whose inode is
  the namespace id, device 0:4, statfs `NSFS_MAGIC`; opening finds the namespace among live ones,
  mount pins and other open nsfs files and keeps it alive; reading is `EINVAL`; bind-mounting it
  pins the namespace.
- mqueue: the root and queue nodes of an IPC namespace's queues take their stat from the queue
  directory and the queues; chmod, chown and utimensat are stored there.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/files` (pseudo open) and `kernel/fileio` (pseudo read/write/lseek); `kernel/vfs` (walker and magic links, pseudo
  stat/getdents, chmod/chown/utimensat on devpts nodes); `kernel/mount` (synthetic mounts, devpts
  options and `mount_events`); `kernel/ns` (unshare/setns, nsfs files); `kernel/poll` (epoll
  refusal and readiness); the machine (`Offline` for startup and metadata sampling); `kernel/signal` (`mark_deleted` for
  unhandled-exception reports); `kernel/net` (`sockets`, `socket_ino`); `kernel/sysctl` and
  `kernel/sysfs` (shared `View`, `FileKind::Proc` snapshot/regeneration, `tree_*` helpers and
  missing-path accounting).

### Outbound

- `kernel/sysctl` (`/proc/sys` tables, permission checks, content and writes) and `kernel/sysfs`
  (`/sys` tables, CPU/net/loop/GPU views).
- Kernel state: thread groups and tasks, credentials (`permission`, `may_ptrace`, `capable`,
  `uid_out`/`gid_out`), pid namespaces (`vnr`, `find`), nsproxy, `mm` (sizes, residency, argument
  ranges, pagemap, forced reads and writes for `mem`), the kernel-entry record (`TaskSync`), `signal`, `tty` (`Tty`
  owner/mode/times, `new_pty`), `net`/`route`/`netdev`/`unix`/`traffic`, `ipc` `/proc/sysvipc`,
  `mqueue` nodes, `seccomp`, `klog`, `loadavg`, the VFS (`reach`, `path_of`), the locks
  (`proc_locks` and `fd_locks`, `kernel/locks`), the mount table (`mounts_from`, devpts options;
  `kernel/mount`), the OOM killer (`proc_score`), unimplemented-path counting (`stub::record`).
- `kernel/cgroup`: cgroup directory lookup and metadata use `Cgroups` and `Cgroup::attrs`;
  `content` delegates to `file`, `proc_cgroup` and `proc_cgroups`; `write` supplies a `Writer`
  with the writer's namespaces and the opener's credentials. Device filtering and change
  observation are called by the file syscalls, not owned by this adapter.
- Host: `appine_hal` (`host_meminfo`, `host_vmstat`, `host_swaps`, `host_cpus`, `clock_gettime`,
  `thread_ctxt_switches`); the engine (`guest_hwcap*`, `guest_midr`).

## Invariants and gotchas

- Both leader stat paths use `ThreadGroup::start_ticks`, including after leader exit or takeover
  by execve. Both worker paths use `Task::start_ticks`.
- Content always reflects the kernel at generation time; nothing is cached across opens, and a
  regeneration uses the opener's credentials but the current reader's namespaces.
- `/proc/<pid>/net` uses the target's network namespace (while `/proc/sys` uses the reader's,
  `kernel/sysctl`).
- Cgroup node adapters must preserve `kernel/cgroup`'s directory modes, controller-dependent
  file visibility and opener-credential checks; policy changes belong in that module.
- Synthetic nodes have no store inode, so store-only operations (chown/chmod outside devpts, cgroup2 and
  mqueue, xattrs, links) fail on them.
- `fdinfo`'s `ino:`, epoll `tfd:` `ino`/`sdev`, and inotify watch `ino`/`sdev` all resolve mount
  devices via `Vfs::dev_of` (and `Fs::Nsfs.dev()` for nsfs files) and inode numbers via
  `node_ino`/`ino_of`, matching `stat` across later procfs instances and nsfs files.
- The kernel-entry record behind `syscall` is published with atomics and no sequence lock: a
  thread entering and leaving the kernel while another reads it could mix two entries, which only a
  thread shown as `running` can do.
- A dynamic directory added to a view must be excluded in `missing_path`, or each of its absent
  entries becomes a counted path (including dynamic directories owned by `kernel/sysctl` and
  `kernel/sysfs`).

## Confirmed bugs / technical debt

- **Inotify on synthetic files is partial:** synthetic files outside cgroup2's four notifying files
  report no inotify events (opens, reads, writes).
- **Fidelity gaps:** Procfs ignores mount options and omits many standard files.
- **`/proc/zoneinfo`, `/proc/pressure/*` and `/proc/kallsyms` are absent:** low-memory daemons
  (systemd-oomd and oomd need PSI's `/proc/pressure/memory` and its poll triggers), zone readers
  and symbol lookups (perf, bpftrace) find nothing.

## Open questions

- Should procfs honour `hidepid`/`subset` (containers sometimes mount with `hidepid=2`)?
- Should `meminfo`/`sysinfo` be clamped to cgroup `memory.max` (LXCFS style), or is following
  docker deliberate?
- Should `task/<tid>` have `pagemap`, as Linux's tid_base_stuff is believed to?

## To verify

- Whether reopening a deleted file through `/proc/<pid>/fd/N` (the open-file node) checks
  permission (pipes do not).
- Field-by-field fdinfo layouts against Linux (eventfd ids, timerfd formatting).
- The Linux 6.1 behaviour behind the items found by Starnix's syscall tests (a zombie leader's
  files, write opens of read-only proc files) was observed on a native 6.8 kernel and attributed
  to 6.1 from knowledge of the kernel; so was which write each kind of read-only file fails with.
