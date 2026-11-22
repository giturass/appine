# kernel/sysfs Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/sysfs.md` for the paired decision history (not yet created; decisions from before the split are D14, D29, D42 and the sysfs parts of D2, D3, D9, D25 and D31 in `.agents/decisions/kernel/procfs.md`).
>
> Verified: 2026-11-22 (split out of the kernel/procfs full mapping of 2026-11-11; the boundary was checked against the source at the split)

## Responsibilities

`kernel/sysfs` implements the synthetic `/sys` filesystem tree:

- CPU topology and host-copied `cache/` and `cpufreq/` attributes under `/sys/devices/system/cpu/`;
- `/sys/class/net/<if>/` network interface, bridge (`bridge/`, `brif/`) and port (`brport/`) views;
- `/sys/block/loop<n>/` loop-device attributes;
- `/sys/module/overlay/parameters/` defaults, the `/sys/fs/cgroup/` mount point, and the
  conditional platform DRM render-node discovery hierarchy (`SYS_GPU`).

Root: in `core/kernel/src/pseudo.rs`, `SYS_GPU`, `SYS_STATIC`, `SYS_NET_DIR`, `SYS_BLOCK_DIR`,
`BLOCK_FILES`, `NET_FILES`, `BRIDGE_FILES`, `PORT_FILES`, `SYS_CPU_DIR`, `CPU_FILES`,
`HOST_CPU_FILES`, `CGROUP_POINT`, `PseudoNode::{SysRoot, Sys, SysCpu, SysNet, SysBrif, SysBlock}`,
the `sysfs` section (`net_file`, `cpu_file`, `cpu_list`, `cpu_mask`, `host_cpu_file`,
`parse_cpu_list`, `parse_cpu_mask`, `cpu_list_of`, `cpu_mask_of`, `host_cpu_has`, `host_cpu`), and
the sysfs arms of `View`, `stat`, `fs_of`, `readdir`, `node_ino`, `ino_of`, `open_unwritable`,
`pollable` and `content`.

Outside the module: the shared `Pseudo` / `View` / `FileKind::Proc` snapshot and poll-event
machinery (`kernel/procfs`); sysfs mounting and single-instance rules (`kernel/mount`); open/read
dispatch (`kernel/files`); loop-device values (`kernel/loop`); network interface views and counters
(`kernel/net`, `kernel/netns`); the cgroup2 tree mounted on `fs/cgroup/` (`kernel/cgroup`); host
CPU and `tx_queue_len` helpers (`hal`).

## Key types

- `PseudoNode` variants: `SysRoot`, `Sys(path)`, `SysCpu(cpu, path)`, `SysNet(ifindex, path)`,
  `SysBrif(bridge, port)`, `SysBlock(loop_n, path)`; `CGROUP_POINT` (`Sys(b"fs/cgroup/")`).
- Tables: `SYS_STATIC` (23 fixed paths), `SYS_GPU` (conditional platform DRM render-node paths),
  `BLOCK_FILES` (22), `NET_FILES` (36), `BRIDGE_FILES` (10), `PORT_FILES` (4), `CPU_FILES` (19) and
  `HOST_CPU_FILES` (68).

## Public entry points

- `pseudo::CGROUP_POINT`.
- Sysfs lookup, stat, readdir, open-writability, pollability and content generation inside
  `kernel/procfs`'s `View`, `stat`, `fs_of`, `readdir`, `open_unwritable`, `pollable` and `content`.

## Data flow / lifecycle

### Tree layout and read-only rules

- Tree: `block/`, `class/net/`, `devices/system/cpu/`, the empty `fs/cgroup/` mount point, and
  `module/overlay/parameters/` with Linux 6.1's Kconfig defaults, which match what `kernel/overlay`
  does (`redirect_always_follow` Y, `redirect_max` 256, `check_copy_up`, `index`, `metacopy`,
  `nfs_export`, `redirect_dir`, `xino_auto` N; containerd adds `index=off` and BuildKit
  `redirect_dir=off` because the files exist).
- `SYS_GPU` supplies the platform bus and `dev/char/226:128/device` paths on renderer-enabled
  kernels: `libdrm` enumerates `drm/renderD128`, reads the `subsystem` link to `/sys/bus/platform`,
  and reads the device-tree name and compatible string from `uevent`.
- Absent: `kernel/`, other modules, `dev/` (outside `SYS_GPU`), `bus/` (outside `SYS_GPU`),
  `firmware/`, `power/`, NUMA nodes, other classes or block `uevent` files.
- Modes and metadata: directories are 0755, files 0444 with reported size 4096 and `st_blksize`
  4096, owned by root, root inode 1.
- sysfs is read-only (write opens `EACCES`, chmod/chown `EACCES`; like `kernfs_fop_open`, it
  refuses only a write access mode so `O_TRUNC` alone opens); one instance, so new mounts share the
  boot device and stacking on its root is `EBUSY`; mounting it needs `CAP_SYS_ADMIN` over the owner
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
- `/sys/class/net/<if>/` follows the reader thread's network namespace; interfaces are directories
  (Linux uses symlinks into `/sys/devices`); bridges have `bridge/` and `brif/` (symlinks to the
  ports' `brport/`), ports `brport/`; only byte and packet counters of host interfaces and `lo` are
  real; `carrier` of a down interface is `EINVAL`, a removed interface `ENODEV`.
- `/sys/block/loop<n>/` exists for every loop device (`kernel/loop`): `dev`, `removable`, `ro`,
  `size` (sectors), `queue/` (logical, physical, minimum and hardware sector sizes, optimal I/O 0,
  `dma_alignment` 511, `rotational`, `read_ahead_kb`, `max_sectors_kb`, `rq_affinity`), and while
  the device is bound `loop/` (`backing_file` as the backing open file's display path, `offset`,
  `sizelimit`, `autoclear`, `partscan`, `dio`). Values come from `Loops::sysfs_read`; device
  directories are directories rather than symlinks into `/sys/devices/virtual/block`.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/procfs`: dispatches sysfs lookup, stat, readdir, open-writability, pollability and
  content generation inside `pseudo.rs`.
- `kernel/mount`: mounts `/sys` and `/sys/fs/cgroup` (using `CGROUP_POINT`).
- `kernel/files`: opens and reads sysfs files through `open_pseudo`.

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
- Dynamic sysfs directories (`brif/`, interfaces, loop devices, `cpu<n>`) must stay excluded in
  `missing_path` (`kernel/procfs`), or each absent entry becomes a counted unimplemented path.

## Confirmed bugs / technical debt

- **No `/sys/dev/block` or block `uevent`s:** tools that go from a device number to sysfs
  (`tst_find_backing_dev`, so LTP ioctl_loop05; udev-style lookups) find nothing, and the root
  filesystem has no block device behind it at all.
- **`/sys/class/net/<if>/statistics` leaks the initial namespace's counters:** host-interface and
  `lo` counters are read by name from the kernel-wide traffic table without a namespace check, so a
  new namespace's `lo` shows the initial loopback's counts, while `/proc/net/dev` and netlink show
  zeros there.
- **Fidelity gaps:** `/sys/class/net` follows the reader rather than the mounter's network
  namespace; interfaces and loop devices are directories rather than symlinks into `/sys/devices`;
  `kernel/`, other modules, `firmware/`, `power/` and NUMA nodes are absent.

## Open questions

- Should `/sys/class/net` follow the mounter's network namespace, as Linux tags sysfs mounts?
