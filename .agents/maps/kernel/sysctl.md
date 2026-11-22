# kernel/sysctl Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/sysctl.md` for the paired decision history (not yet created; decisions from before the split are D16, D22 and the sysctl parts of D8, D9, D15, D21, D25, D28 and D31 in `.agents/decisions/kernel/procfs.md`).
>
> Verified: 2026-11-22 (split out of the kernel/procfs full mapping of 2026-11-11; the boundary was checked against the source at the split)

## Responsibilities

`kernel/sysctl` implements the `/proc/sys` sysctl hierarchy, its permission model, namespace
scoping, recorded sysctls and write handlers:

- the static `/proc/sys` tree, the 40 recorded sysctls (`RECORDED`) and per-interface/per-namespace
  network sysctls (`NetConf`, `NetSysctl`);
- `proc_sys_permission`/`test_perm` open checks, namespace ownership (`net_ctl_set_ownership`) and
  capability gates on writes;
- namespace scoping (IPC, UTS, pid, network, user) and kernel-wide sysctl reads and writes.

Root: in `core/kernel/src/pseudo.rs`, the `sys/*` entries of `STATIC`, `RECORDED`, `recorded`,
`recorded_value`, `NET_CONF4`, `NET_CONF6`, `PseudoNode::NetConf`, `PseudoNode::NetSysctl` (and
`PseudoNode::Static(b"sys/...")`), `sysctl_kind`, `is_net_sysctl`, and the `/proc/sys` arms of
`View`, `stat`, `owner_of`, `readdir`, `writable`, `unwritable_error`, `open_unwritable`,
`pollable`, `unreadable`, `content` and `write`.

Outside the module: the shared `Pseudo` / `View` / `FileKind::Proc` snapshot and regeneration
machinery, per-process/system-wide procfs files and `/proc/sysvipc` (`kernel/procfs`); open/read/
write dispatch (`kernel/files`); backing `netconf::SYSCTLS` and per-device conf storage
(`kernel/netns`); the subsystem limits and flags each sysctl mutates (`kernel/mm`, `kernel/mount`,
`kernel/ns`, `kernel/ipc`, `kernel/inotify`, `kernel/aio`, `kernel/locks`, `kernel/pipe`,
`kernel/process`, `kernel/signal`, `kernel/vfs`, `kernel/fuse`, `kernel/cgroup`).

## Key types

- `PseudoNode::Static(b"sys/...")` — fixed `/proc/sys` directories and files from `STATIC` (the
  non-`sysvipc/` portion of `STATIC`).
- `PseudoNode::NetConf(v6, dir, name)` — `/proc/sys/net/ipv4/conf/<dir>` and `ipv6/conf/<dir>`
  per-interface directories and entries (`NET_CONF4`, `NET_CONF6`, backed by `kernel/netns`).
- `PseudoNode::NetSysctl(path)` — 145 per-network-namespace sysctls backed by `netconf::SYSCTLS`
  (`kernel/netns`).
- `RECORDED` — 40 kernel-wide sysctls with Linux 6.1 modes, defaults and accepted ranges, stored in
  `Kernel::sysctls`.

## Public entry points

- `pseudo::sysctl_kind`, `pseudo::recorded_value`, `pseudo::RECORDED`.
- `/proc/sys` lookup, stat, readdir, open-writability, pollability, content generation and write
  arms inside `kernel/procfs`'s `View`, `stat`, `readdir`, `writable`, `open_unwritable`,
  `pollable`, `unreadable`, `content` and `write`.

## Data flow / lifecycle

### Permissions, modes and ownership

- Modes: recorded sysctls and `NetSysctl` entries use their table modes (`vm.drop_caches` 0200,
  `vm.mmap_rnd_bits` 0600); other writable sysctls are 0644; read-only sysctls are 0444;
  directories are 0555.
- Ownership: `net.*` sysctls belong to root of the user namespace owning the network namespace when
  it maps one (`net_ctl_set_ownership`); other `/proc/sys` entries belong to root.
- Open checks (`open_pseudo` in `kernel/files` using `sysctl_kind`): `O_TRUNC` asks for write
  permission too; `/proc/sys/user/max_*` skip DAC and need `CAP_SYS_RESOURCE` in the opener's own
  user namespace to open for writing; the rest of `/proc/sys` decides as
  `proc_sys_permission`/`test_perm` do, not by DAC: the mode's owner bits when euid is 0, the group
  bits when egid or a supplementary group is 0, the others' bits otherwise, capabilities aside; a
  `net.*` entry gives its owner bits to anyone with `CAP_NET_ADMIN` over the owner of the reader's
  network namespace (`net_ctl_permissions`, so root of a container writes its namespace's).
- Read-only `/proc/sys` files refuse write opens (`EACCES`, `O_TRUNC` included). Write-only files
  (`vm.drop_caches`) open empty and fail reads with `EINVAL`. A `NetConf` file whose generation
  fails opens empty and reports the error on the first read.
- `/proc/sys` files are pollable (`pseudo::pollable`) so epoll accepts them; missing names under
  the fixed `/proc/sys` tree (excluding interface names under `conf/`) are counted as unimplemented
  paths (`kernel/signal`).

### Namespace scoping and capability checks

- Reads follow the reading thread's namespaces and writes the writer's:
  - SysV IPC limits and `fs/mqueue/*` per IPC namespace;
  - `hostname`/`domainname` per UTS namespace (one trailing newline stripped, over 64 bytes
    `EINVAL`);
  - `ns_last_pid` per pid namespace (the process's, not the mount's);
  - `net.*` per network namespace (`ip_forward` aliases `conf/all/forwarding`; `NetConf` directories
    per interface; entries flagged init-only exist only in the initial namespace);
  - `user/max_*_namespaces` per user namespace (the reader's or writer's: the limits of
    `kernel/ns`'s namespace counts, `INT_MAX` by default in a new one, 0 to `INT_MAX`);
  - everything else kernel-wide (`max_map_count`, `mmap_min_addr`, inotify limits, `aio-max-nr`,
    `lease-break-time`, `nr_open`, `threads-max`, `mount-max` (1 to `INT_MAX`; the mount limit of
    `kernel/mount`), `pipe-max-size`, `core_pattern`, `core_uses_pid`,
    `protected_symlinks`/`hardlinks`, `printk*`, `panic`).
- Capability checks on writes (all in the initial user namespace via `Cred::capable`, so container
  root never passes): `dmesg_restrict`, `kernel.tainted`, `kptr_restrict`,
  `unprivileged_bpf_disabled` and seccomp `actions_logged` need `CAP_SYS_ADMIN`; `mmap_min_addr`
  needs `CAP_SYS_RAWIO`.
- Most sysctls parse decimal after trimming; writes do not advance the file position and mark the
  open file's snapshot stale (`kernel/procfs`).

### Recorded sysctls and constants

- Several writable sysctls are recorded without effect (`kernel.panic`, every `NetSysctl` entry,
  `ping_group_range`, `somaxconn`, `ip_local_port_range`; of the port sysctls only
  `ip_unprivileged_port_start` is used, by bind); `ping_group_range` keeps kernel group IDs, shown
  in the reader's user namespace (65534 when unmapped) and written from the writer's (an unmapped
  one is `EINVAL`); `kernel/pid_max` accepts writes and ignores them.
- The `RECORDED` table adds 40 more with Linux 6.1's modes, defaults and accepted ranges
  (`overflowuid`/`gid`, `vm.dirty_*`, `drop_caches`, `swappiness`, `overcommit_ratio`,
  `page-cluster`, `watermark_scale_factor`, `mmap_rnd_*bits`, `kernel.sysrq`, `randomize_va_space`
  (default 0: nothing is randomized), `kptr_restrict`, `perf_*`, `hung_task_*`, `sched_rt_*`,
  `sched_schedstats`, `panic_on_oops`, `core_pipe_limit`, `modules_disabled` (only 1 can be
  written), `fs.suid_dumpable`, `debug.exception-trace`), kept kernel-wide in `Kernel::sysctls` and
  read through `recorded_value`.
- All `RECORDED` entries change nothing except:
  - `debug.exception-trace` (default 0, arm64's `show_unhandled_signals`, or 1 when the host asks
    through `MachineOptions::exception_trace`, as the app does), which turns on `kernel/signal`'s
    unhandled-exception reports when non-zero;
  - `drop_caches` (write-only, reads `EINVAL`), whose 2 and 3 make `kernel/fuse` forget unused FUSE
    nodes at the end of the syscall (the host keeps the page cache).
- `kernel.modprobe` keeps a string, `kernel.tainted` only gains flags (of the 19 defined), and
  `vm.overcommit_memory` (0 to 2) is used: 1 turns off fork's commit check (`kernel/cow`).
- Constants: `file-max`, `cap_last_cap` 40, `ngroups_max`, `pid_max` 4194304, `osrelease`
  `6.1.0-appine`; `random/uuid` is fresh per read, `boot_id` fixed per boot, the entropy values 256.
- Absent: `sys/fs/file-nr`, `protected_regular`/`protected_fifos`, Yama.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/procfs`: dispatches `/proc/sys` lookup, stat, readdir, content generation and writes
  inside `pseudo.rs`.
- `kernel/files`: `open_pseudo` calls `sysctl_kind` and `open_unwritable` for `/proc/sys`
  permission checks.
- `kernel/signal`: `recorded_value` for `debug.exception-trace`.
- `kernel/cow` (`vm.overcommit_memory`), `kernel/vfs` (`protected_symlinks`/`hardlinks`),
  `kernel/mount` (`fs.mount-max`), `kernel/inotify`, `kernel/aio`, `kernel/locks`, `kernel/pipe`,
  `kernel/ipc`, `kernel/ns`, `kernel/mm`, `kernel/process`, `kernel/cgroup` (read/mutate the
  backing kernel fields exposed here).

### Outbound

- `kernel/procfs`: shared `View`, `FileKind::Proc` snapshot/regeneration, `tree_*` helpers and
  missing-path counting.
- `kernel/netns`: `netconf::SYSCTLS` and `netdev::conf_read`/write for `NetConf` and `NetSysctl`.
- `kernel/fuse` (`vfs::fuse::drop_caches`), `kernel/cred` (`capable`, `uid_out`/`gid_out`),
  `appine_hal` (`fill_random` for `random/uuid`).

## Invariants and gotchas

- `/proc/sys` lookups use the reader's namespaces (unlike `/proc/<pid>/net`, which uses the
  target's).
- `recorded_value` panics on a path missing from `RECORDED`, so callers (such as `kernel/signal`'s
  `EXCEPTION_TRACE`) must match its exact path string.
- A node classified by path prefix (`sys/net/`) in `sysctl_kind` / `is_net_sysctl` must stay
  accurate as new sysctl nodes are added.

## Confirmed bugs / technical debt

- **Regeneration uses the current reader's namespaces:** a file reread from offset 0 is generated in
  the reading task's namespaces, while Linux binds a network or IPC sysctl to the namespace it was
  looked up in, so a descriptor of `/proc/sys/net/*` or an IPC limit passed to a process in another
  namespace shows that namespace's value.
- **Sysctl poll never reports `POLLPRI`:** `hostname` and `domainname` never wake pollers on
  change.
- **Writes never advance a sysctl file's position:** repeated writes on one descriptor keep taking
  effect, where Linux ignores a strict-mode sysctl write at a non-zero position.
- **`kernel/pid_max` writes are ignored.**

## Open questions

- None.

## To verify

- Linux 6.1's permission rules for SysV IPC/mqueue sysctls in child user namespaces (believed to be
  refused until about 6.8).
- The Linux 6.1 `proc_sys_permission` behaviour found by Starnix's syscall tests was observed on a
  native 6.8 kernel and attributed to 6.1 from knowledge of the kernel.
- The bounds Linux puts on the mqueue, `aio-max-nr` and `lease-break-time` sysctls (Appine accepts
  any positive value, or any number).
