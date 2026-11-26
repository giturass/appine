# kernel/sysfs Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/sysfs.md` for the paired decision history (not yet created; decisions from before the split are D14, D29, D42 and the sysfs parts of D2, D3, D9, D25 and D31 in `.agents/decisions/kernel/procfs.md`).
>
> Verified: 2026-11-22 (split out of the kernel/procfs full mapping of 2026-11-11; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: loop-device number links under `/sys/dev/block/` and block `uevent` attributes)

## Responsibilities

`kernel/sysfs` implements the synthetic `/sys` filesystem tree:

- CPU topology and host-copied `cache/` and `cpufreq/` attributes under `/sys/devices/system/cpu/`;
- `/sys/class/net/<if>/` network interface, bridge (`bridge/`, `brif/`) and port (`brport/`) views;
- `/sys/block/loop<n>/` loop-device attributes and their device-number links under `/sys/dev/block/`;
- `/sys/module/overlay/parameters/` defaults, the `/sys/fs/cgroup/` mount point, and the
  conditional platform DRM render-node discovery hierarchy (`SYS_GPU`).

Root: in `core/kernel/src/pseudo.rs`, `SYS_GPU`, `SYS_STATIC`, `SYS_NET_DIR`, `SYS_BLOCK_DIR`, `SYS_DEV_BLOCK_DIR`,
`BLOCK_FILES`, `NET_FILES`, `BRIDGE_FILES`, `PORT_FILES`, `SYS_CPU_DIR`, `CPU_FILES`,
`HOST_CPU_FILES`, `CGROUP_POINT`, `PseudoNode::{SysRoot, Sys, SysCpu, SysNet, SysBrif, SysBlock, SysDevBlock}`,
the `sysfs` section (`net_file`, `cpu_file`, `cpu_list`, `cpu_mask`, `host_cpu_file`,
`parse_cpu_list`, `parse_cpu_mask`, `cpu_list_of`, `cpu_mask_of`, `host_cpu_has`, `host_cpu`), and
the sysfs arms of `View`, `stat`, `fs_of`, `readdir`, `node_ino`, `ino_of`, `open_unwritable`,
`pollable` and `content`.

Outside the module: the shared `Pseudo` / `View` / `FileKind::Proc` snapshot and poll-event
machinery (`kernel/procfs`); sysfs mounting and single-instance rules (`kernel/mount`); open
dispatch (`kernel/files`) and read dispatch (`kernel/fileio`); loop-device values (`kernel/loop`); network interface views and counters
(`kernel/net`, `kernel/netns`); the cgroup2 tree mounted on `fs/cgroup/` (`kernel/cgroup`); host
CPU and `tx_queue_len` helpers (`hal`).

## Key types

- `PseudoNode` variants: `SysRoot`, `Sys(path)`, `SysCpu(cpu, path)`, `SysNet(ifindex, path)`,
  `SysBrif(bridge, port)`, `SysBlock(loop_n, path)`, `SysDevBlock(loop_n)` and `CGROUP_POINT` (`Sys(b"fs/cgroup/")`).
- Tables: `SYS_STATIC` (25 fixed paths), `SYS_GPU` (conditional platform DRM render-node paths),
  `BLOCK_FILES` (23), `NET_FILES` (36), `BRIDGE_FILES` (10), `PORT_FILES` (4), `CPU_FILES` (19) and
  `HOST_CPU_FILES` (68).

## Public entry points

- `pseudo::CGROUP_POINT`.
- Sysfs lookup, stat, readdir, open-writability, pollability and content generation inside
  `kernel/procfs`'s `View`, `stat`, `fs_of`, `readdir`, `open_unwritable`, `pollable` and `content`.

## Data flow / lifecycle

### Tree layout and read-only rules

- Tree: `block/`, `class/net/`, `dev/block/`, `devices/system/cpu/`, the empty `fs/cgroup/` mount point, and
  `module/overlay/parameters/` matching what `kernel/overlay` does (`redirect_max` 256,
  `redirect_always_follow`, `check_copy_up`, `index`, `metacopy`, `nfs_export`, `redirect_dir`,
  `xino_auto` N; containerd adds `index=off` and BuildKit `redirect_dir=off` because the files
  exist).
- `SYS_GPU` supplies the platform bus and `dev/char/226:128/device` paths on renderer-enabled
  kernels: `libdrm` enumerates `drm/renderD128`, reads the `subsystem` link to `/sys/bus/platform`,
  and reads the device-tree name and compatible string from `uevent`.
- Absent: `kernel/`, other modules, `dev/char/` and `bus/` on kernels without a renderer,
  `firmware/`, `power/`, NUMA nodes and other classes.
- Modes and metadata: directories are 0755, files 0444 with reported size 4096 and `st_blksize`
  4096, owned by root, root inode 1.
- sysfs is read-only (write opens `EACCES`, chmod/chown `EACCES`; like `kernfs_fop_open`, it
  refuses only a write access mode so `O_TRUNC` alone opens); one instance per network namespace
  (the boot device in the initial namespace and a per-namespace device otherwise, `Vfs::sys_dev`),
  so stacking a sysfs mount of the same network namespace on its own root is `EBUSY` while mounting
  sysfs in a different network namespace succeeds; mounting it needs `CAP_SYS_ADMIN` over the owner
  of the caller's network namespace (`kernel/mount`).
- Every sysfs file is pollable (`pseudo::pollable`): always readable and writable, plus
  `POLLERR|POLLPRI` before its first read from offset 0 (`fd::ProcEvent`).
- Missing names under the fixed sysfs tree (not interfaces, loop devices or `cpu<n>` names) and
  inside a CPU's, interface's (not `brif/`) or loop device's directory are counted as unimplemented
  paths (`kernel/signal`).

### CPUs, network interfaces and loop devices

- `/sys/devices/system/cpu/`: `online`, `possible`, `present`, `offline`, and one `cpu<n>/` per
  guest CPU with synthesized `topology/` (each CPU its own core, one package) and
  `regs/identification/`; `cache/` and `cpufreq/` files are copied from the host when the host lets
  the app read them (CPU numbers translated, missing files absent).
- The guest CPU count is a snapshot of the host process's affinity at kernel creation (capped at
  64); the same count drives sysfs, `/proc/cpuinfo`, `/proc/stat`, `status`, `sched_getaffinity`
  and cgroup `cpuset`; guest CPU `i` is host CPU `host_cpus()[i]`.
- `/sys/class/net/<if>/` follows the sysfs mount's network namespace (`View::sys_net_ns`, tagged at
  mount time via `Vfs::sys_net_ns`, falling back to the initial network namespace for the boot
  mount); interfaces are directories
  (Linux uses symlinks into `/sys/devices`); bridges have `bridge/` and `brif/` (symlinks to the
  ports' `brport/`), ports `brport/`; byte and packet counters from `k.traffic` and host
  `tx_queue_len` are read only in the initial network namespace (`ns.host_net.is_none()`), while new
  network namespaces report zero statistics and `tx_queue_len` 1000; `carrier` of a down interface
  is `EINVAL`, a removed interface `ENODEV`.
- `/sys/block/loop<n>/` exists for every loop device (`kernel/loop`): `dev`, `removable`, `ro`,
  `size` (sectors), `queue/` (logical, physical, minimum and hardware sector sizes, optimal I/O 0,
  `dma_alignment` 511, `rotational`, `read_ahead_kb`, `max_sectors_kb`, `rq_affinity`), and while
  the device is bound `loop/` (`backing_file` as the backing open file's display path, `offset`,
  `sizelimit`, `autoclear`, `partscan`, `dio`). These values come from `Loops::sysfs_read`. Device
  directories are directories rather than symlinks into `/sys/devices/virtual/block`.
- `/sys/dev/block/7:<n>` links to `../../block/loop<n>` for each existing loop device, bound or
  unbound. Both paths reach the same `uevent` file. Its four lines give `MAJOR=7`, `MINOR=<n>`,
  `DEVNAME=loop<n>` and `DEVTYPE=disk`. Lookup, readlink and uevent generation check device existence.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/procfs`: dispatches sysfs lookup, stat, readdir, open-writability, pollability and
  content generation inside `pseudo.rs`.
- `kernel/mount`: mounts `/sys` and `/sys/fs/cgroup` (using `CGROUP_POINT`).
- `kernel/files` and `kernel/fileio`: opens (`open_pseudo`) and reads sysfs files.

### Outbound

- `kernel/procfs`: shared `View`, `FileKind::Proc` snapshot/poll-event handling, `tree_*` helpers
  and missing-path counting.
- `kernel/loop` (`Loops::numbers`, `sysfs_exists`, `sysfs_read`), `kernel/net` (`Traffic` interface
  counters), `kernel/netns` (interface/bridge/port views), `engine` (`guest_midr`), `appine_hal`
  (`host_cpus`, `cpu_sysfs`, `tx_queue_len`).

## Invariants and gotchas

- The guest CPU count (`cpus()`) must stay consistent with `/proc/cpuinfo`, `/proc/stat`, `status`,
  `sched_getaffinity` and cgroup `cpuset`.
- Device numbers advertised by `SYS_GPU` (`226:128`) must match `/dev/dri/renderD128` (`kernel/vfs`
  and `kernel/files`).
- `SYS_STATIC` supplies the shared `dev/` parent. `SYS_GPU` adds `dev/char/` when a renderer is present.
- Dynamic sysfs directories (`brif/`, interfaces, loop devices, `dev/block/`, `cpu<n>`) must stay excluded in
  `missing_path` (`kernel/procfs`), or each absent entry becomes a counted unimplemented path.

## Confirmed bugs / technical debt

- **Root filesystem backing device:** the inode store reports device `8:1` but has no backing
  block device. Probes for `/sys/dev/block/8:1` return `ENOENT`.
- **Fidelity gaps:** interfaces and loop devices are directories rather than symlinks into
  `/sys/devices`; `kernel/`, other modules, `firmware/`, `power/` and NUMA nodes are absent.

## Open questions

- None.
