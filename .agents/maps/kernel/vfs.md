# kernel/vfs Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/vfs.md` for the paired decision history (it still holds the decisions on mounts, inotify, AIO, loop devices, timerfd, overlayfs, locks, pipes, xattrs, open files and file I/O made before they were split out; the last two are listed in `kernel/files`'s and `kernel/fileio`'s maps).
>
> Verified: 2026-11-12 (full mapping: 6 research concerns; 46 claims checked by 3 independent verifiers — 36 confirmed and 10 partial, all corrected below; new bugs and fidelity gaps recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's inode-flag enforcement in xattr/ACL and `MAP_SHARED` paths and socket creation gid alongside the retained host shared-storage FUSE routing)

## Responsibilities

`kernel/vfs` is the layer between file-related syscalls and the filesystems behind them (the inode
store and the synthetic filesystems):

- path resolution into mount-aware nodes (Linux `struct path`): symlinks, `..` across mounts,
  search permission, `protected_symlinks`, magic links, openat2's `RESOLVE_*`;
- mount and superblock flag checks in file operations, and what removing or renaming a mount point
  does;
- tmpfs instances and their accounting;
- namespace and metadata syscalls: stat, statfs, access, attribute changes, creating, removing,
  linking and renaming names, getdents64, the cwd and root;
- device nodes (populating `/dev`) and the `Device` numbers;
- calling the inotify hooks where Linux's fsnotify does.

Root: `core/kernel/src/vfs/mod.rs` (except the mount table and the overlay methods), `vfs/dev.rs`,
`syscall/fs.rs` (except `kernel/files`' and `kernel/fileio`'s parts, its overlay functions, `flock`, the fcntl lock
commands and the pipe, FIFO and splice code: what remains is `getdents64`, the sections Metadata,
stat, Changing the namespace, chmod, chown and utimensat, Paths and tmpfs accounting, and the other
shared helpers), and in `syscall/mount.rs` the tmpfs options.

Outside the module: fd tables, open files and opening including devices by number (`kernel/files`);
data I/O, clones and unsharing, truncation, lseek, cache hints and syncing (`kernel/fileio`); the mount table, mount
syscalls and mount namespaces (`kernel/mount`); overlayfs mounts, lookups, copy-up and its removal
and rename (`kernel/overlay`, branched to from here); advisory locks and leases (`kernel/locks`);
pipes, FIFOs and splice (`kernel/pipe`); extended attributes (`kernel/xattr`); store semantics
(`kernel/store`); FUSE connections, their node cache and the file syscalls on FUSE nodes
(`kernel/fuse`, dispatched to from here); procfs/devpts content and cgroup2 node adapters
(`kernel/procfs`), `/proc/sys` sysctls (`kernel/sysctl`) and sysfs (`kernel/sysfs`); cgroup policy and device BPF (`kernel/cgroup`);
terminals (`kernel/tty`); sockets (`kernel/net`, `kernel/unix`); poll/epoll, eventfd and timerfd
(`kernel/poll`); inotify instances, watches and event rules (`kernel/inotify`); native AIO
(`kernel/aio`); loop devices (`kernel/loop`); message queues (`kernel/ipc`); the BKL and the no-BKL
fast path (`kernel/process`); namespaces (`kernel/ns`); execve (`kernel/exec`); credentials and file
capabilities (`kernel/cred`).

## Key types

- `Node` — `Store(MountId, Ino)`, `Pseudo(MountId, PseudoNode)`, `Overlay(MountId, OvlId)` or
  `Fuse(MountId, FuseId)`; the mount is part of its identity, so one directory mounted twice is
  two nodes. `Node::ino` is Some only for store nodes. `Dentry = (Node, name)` is where a result
  was last found.
- `Pseudo` trait — what a synthetic filesystem offers the walker: lookup, parent, name, kind,
  readlink, `follow`/`follow_dentry` (magic-link jumps), `magic`, `protected_symlinks`, `missing`
  (told of each name not found), `searched` (cgroup directories' search check); procfs's `View`
  implements it, and `Offline` (empty synthetic roots) before the kernel starts.
- `resolve` — openat2's `RESOLVE_*` bits; `SCOPED = BENEATH | IN_ROOT`.
- `Vfs` — the store handle, the mount table (`kernel/mount`'s `Mount`, `Mounts`, `Fs`, `MntNs`,
  `Index`, `GroupAlloc`), the no-BKL resolver state, the executable cache, the namespaces, the
  overlay and FUSE tables, the anonymous pipe and socket inode attributes, and the mount event counter.
- `TmpfsParams` / `Tmpfs` — options, usage in pages and inodes (`None` until first counted) with a
  changed mark, and `unlinked: HashMap<Ino, u64>` tracking the last known page count of unlinked
  regular files still open, mapped or executing.
- `Cached` / `Pending` — the fast-path stat resolver without the BKL (reads the store's metadata
  cache under its read lock; 64-component stack), with the store inodes that are mount points.
- `Device` — Null, Zero, Full, Random, Kmsg, LoopControl, Loop (`kernel/loop`'s; tty, ptmx, pts
  and `/dev/fuse` are routed before it).
- `fs::Attrs` — what chmod, chown and utimensat act on: Store, Overlay, Pts, Anon (sockets and
  anonymous pipes), Mq, MqDir (the mqueue root), Cgroup, Fuse.

## Public entry points

- **Resolution**: `Vfs::resolve`, `walk`, `walk_resolve(…, follow, flags)`, `resolve_parent`,
  `resolve_parent_with`, `found_path`, `path_of`, `reach`, `mounts_from`; `start_dir`,
  `lookup_at`, `parent_at`, `create_parent_at` in `syscall/fs.rs`; `Cached::stat` (fast path).
- **Instances**: `new_tmpfs`, `tmpfs_*`, `new_fuse`, `add_fuse_mount`, `fuse`/`fuse_mut`,
  `fuse_child`, `fuse_permission`. The mount table's methods and the mount syscalls are
  `kernel/mount`'s, the overlay methods `kernel/overlay`'s.
- **Metadata**: `newfstatat`/`fstat`/`statx`, `statfs`/`fstatfs`, `fchmod*`, `fchown*`,
  `utimensat`, `faccessat`/`faccessat2`, `umask`, `mkdirat`, `mknodat`, `unlinkat`,
  `renameat2`, `linkat`, `symlinkat`, `readlinkat`, `getdents64`, `getcwd`, `chdir`/`fchdir`,
  `chroot`.
- **Devices**: `dev::ensure_dev_nodes` (store `/dev`, at import and every boot), `dev::populate`
  (boot `/dev` tmpfs), `Device::from_rdev`.
- **Kernel-internal**: `dev_ino` (epoll fdinfo and the lock listings of sockets and PTYs); for `kernel/files` and `kernel/fileio`,
  `may_create`, `display_path`, `file_stat` and the tmpfs hooks.

## Data flow / lifecycle

### Path resolution

- Start (`start_dir`): an empty path is `ENOENT` before the dirfd is examined; absolute paths
  start at the process root, `AT_FDCWD` at the cwd; otherwise a closed fd is `EBADF`, and a
  non-directory or an fd without a node (anonymous pipes, sockets, PTYs, host fds, anonymous
  inodes, message queues) `ENOTDIR`. `AT_EMPTY_PATH` takes the fd's node or the cwd (`EBADF`
  without a node); stat with an empty path stats the fd itself.
- `walk_resolve` runs `walk_in` in one store read snapshot. Empty components are dropped; a
  trailing `/` appends a `Step::TrailingSlash` sentinel (an empty slice in `Cached`), forcing a
  directory and following a trailing symlink while still classifying it as trailing for
  `protected_symlinks`.
- Per component, in order: over 255 bytes `ENAMETOOLONG`; not a directory `ENOTDIR`; search
  permission, also for `.` and `..`: on store directories and the store directory behind an overlay
  one unless the credentials have `CAP_DAC_READ_SEARCH` or `CAP_DAC_OVERRIDE` in the initial user
  namespace, on cgroup directories (`Pseudo::searched`; other synthetic directories never), and on
  FUSE directories through `fuse_permission` (allow_other first, for everyone); `.` is skipped; `..`
  (`dotdot`) stays at the process root without lifting, climbs stacked mount points at a mount root,
  takes the parent within the mount (a namespace-tree or detached root stays put; a parent outside
  the subtree of a bind's root, as after a rename through another mount, is `ENOENT`:
  `path_connected`) and enters anything mounted there; other names are looked up and lifted to the
  topmost mount stacked on the result. `NO_XDEV` makes a `..` or lookup that changes mount `EXDEV`,
  `BENEATH` a `..` from the start. A FUSE lookup or readlink reads `kernel/fuse`'s cache or fails
  with the internal `FUSE_RETRY`: the dispatcher asks the connection's guest daemon or host server
  and reruns the syscall (`EIO` after
  16384 reruns). A name not found is first passed to `Pseudo::missing` (only here), so procfs counts
  fixed names Linux has under `/proc` and `/sys` and names directly in the boot `/dev`
  (`kernel/signal`'s unimplemented paths).
- Symlinks (intermediate, or last with `follow`): over 40 `ELOOP`; `protected_symlinks` (default
  on) for a last-component or trailing-slash (`link/`) store link in a store directory (`EACCES`);
  `NO_SYMLINKS` or
  nosymfollow `ELOOP`; then procfs's `follow`, which refuses magic links to readers failing the
  access check (`EACCES`; `fd/` and `fdinfo/` also refuse lookup and listing); for magic links
  (`/proc/<pid>/fd/*`, `cwd`, `root`, `exe`, `ns/*`) `NO_MAGICLINKS` `ELOOP`, `NO_XDEV` to another
  mount and scoped resolution `EXDEV`. They jump to the process's root or cwd, an nsfs node in the
  procfs mount, the program's overlay or store node (a deleted program with a host file:
  `OpenExe`), and for `fd/N` to the overlay node of a file opened through an overlay, the store
  node of a linked regular file or device, the node of a directory, `O_PATH` or procfs file, a PTY
  slave's devpts node, or otherwise the open file (`OpenFd`: deleted and memfd files, pipes,
  sockets, PTY masters, host fds, FUSE files, `/dev/fuse`, anonymous inodes), whose reopen is
  `ENXIO` unless it is a regular file, pipe or host fd. An open walk also uses `OpenFd` for a
  pinned overlay file whose last upper link is gone. The new fd keeps the overlay identity.
  Ordinary absolute targets restart at the root (`EXDEV` under `BENEATH`, or under `NO_XDEV`
  when the root was not yet taken or the link is on another mount). Relative targets continue
  from the link's directory.
- openat2: `open_how` under 24 bytes `EINVAL`, over 4096 or with a nonzero tail `E2BIG`; flags,
  resolve bits, mode and the `O_TMPFILE` and `O_PATH` combinations follow 6.1's
  `build_open_flags`; `BENEATH|IN_ROOT` `EINVAL`; scoped resolution starts at the dirfd, `IN_ROOT`
  absolute paths too. `RESOLVE_CACHED` is only a pre-check (`EAGAIN` for create, truncate,
  `O_TMPFILE` and, through 6.1's macro comparison, `O_DIRECTORY`), then a normal walk, which still
  asks the FUSE connection's server on a miss.
- Creation (`resolve_parent_with`): trailing slashes trimmed (only slashes: the root and `.`), a
  prefix walked with follow; a slash-free name returns the dirfd's directory or the cwd without a
  search check (callers check); then `ENAMETOOLONG` and `ENOTDIR`; a last `.`/`..` is left to the
  caller.
- `O_CREAT`: `O_EXCL` turns follow off and any existing name is `EEXIST`; on `ENOENT` a loop runs:
  a trailing `/` or last `.`/`..` `EISDIR`, the mqueue root creates a queue, a cgroup directory
  `EACCES` (`EROFS` read-only) and other synthetic directories `store_dir`'s
  `EROFS`/`EPERM`/`EACCES`, dangling store, overlay and FUSE symlinks are followed to create their
  targets (a fresh 40-link count; `NO_SYMLINKS`/nosymfollow `ELOOP`; `NO_XDEV`'s root-taken rule
  approximated), a FUSE directory asks the connection's server.
- Back to paths: `reach` climbs through mount points (or the recorded dentry for mounts on files)
  and stops as unreachable at a namespace-tree root, detached root, tmpfs root, the store root
  inside a bind, a parentless synthetic node, another mount's overlay or FUSE root, or a forgotten
  FUSE node; a deleted directory (a store one keeps its row without a name while
  `Vfs::removed_dirs` tracks its former name as long as a task's cwd, root or open directory/path
  fd references it, an overlay one once its name is removed, and a FUSE one once `unlinked` is
  set) is `ENOENT` for getcwd (`reach`), while `path_of` (`/proc/<pid>/{cwd,root}`) reconstructs
  the path and appends ` (deleted)`. mountinfo's `mounts_from`
  does the same for every mount through an index built once and skips unreachable mounts. `getcwd`
  prefixes `(unreachable)`; `/proc/<pid>/{cwd,root}` are computed live against the reader's root;
  `/proc/<pid>/fd/N` follows renames of the opened name through its current dentry, relative to
  the reader's root. If the path cannot be reconstructed, procfs uses the fd's saved path or
  description. It appends ` (deleted)` when the opened name was unlinked or a regular file's nlink is 0.
- `Cached` (no-BKL newfstatat and statx) runs only when the thread's root is in the root
  filesystem's mount, the credentials search everything, that mount is attached and not
  nosymfollow, the fast epoch is current, the flags are valid, the thread is not syscall-traced,
  stepping or filtered by seccomp, and the path is non-empty, under `PATH_MAX`, and absolute or
  `AT_FDCWD`-relative with the cwd in that mount. It gives up on a stale cache generation, any
  miss, over 64 pending components, a store inode that is a mount point (the store root after
  `pivot_root` too), a host stat error and a trailing link in a sticky world-writable directory of
  another owner; it never enters synthetic filesystems or overlays, makes no search check, and
  falls back for store inodes with statx-visible inode flags. It otherwise mirrors `walk_in`. Mount table changes call `mounts_changed` (also bumping the mount
  event counter mounts and mountinfo poll); chdir, fchdir, chroot, setns, credential and fs-context
  changes and the mount syscalls call `fast_changed`, and threads take a new snapshot after a BKL
  entry when the epoch moved.

### Mount flags and mount points in file operations

- This module reads `kernel/mount`'s table while resolving and checks its flags where Linux does.
  ro of the mount or the filesystem (`readonly` includes `sb_readonly`: the instance's flag, kept
  by device number, or an overlay without an upper layer; a memfd is never read-only) is `EROFS`:
  in creation after search and `EEXIST`, before directory write permission; in unlink and rmdir
  after the `.`/`..` checks, before lookup; in rename after `EXDEV` and the `.`/`..` checks; in
  attribute changes before permission; in truncate after the type checks; in write opens of
  regular files before permission for read-only instances (`sb_readonly_node`, `O_TRUNC` and
  overlay opens), and after permission and `O_NOATIME` for read-only bind mounts on writable
  instances. noexec: exec `EACCES` after the execute check, `access`/`faccessat(X_OK)` on a
  regular non-memfd file `EACCES`, `PROT_EXEC` mmap `EPERM` (a memfd checked against the root
  mount), and such a mapping cannot gain `PROT_EXEC` through mprotect (`EACCES`); exec never treats
  memfds as noexec. nosuid: exec ignores set-id bits and file caps
  (always for FUSE programs). nodev: device opens `EACCES` (store, overlay, FUSE and devpts
  nodes); mknod is unaffected. nosymfollow: `ELOOP`, and on the root filesystem it turns off
  `Cached`. Store file reads and mappings and store directory listings honor the description's
  `O_NOATIME` and current mount flags. Read-only mounts, mount noatime and inode `FS_NOATIME_FL` suppress updates, nodiratime
  suppresses directory updates, and relatime compares atime to mtime, ctime and a 24-hour age.
  The sync, dirsync, mand and lazytime flags are recorded and reported (mountinfo, statfs).
- Removing or renaming a mount point in the caller's namespace is `EBUSY` (rename: either name);
  mounts on it in other namespaces are detached after the change (rename: only on the replaced
  target). Removing the name a mount's root is (a bound directory once its nlink is 0, or the name
  a bound file was found at, even with links left) marks that mount, attached or detached
  (`roots_removed`), and mountinfo then shows the former path plus `//deleted`. Unlinking a shared
  file to nlink 0 (or renaming over it) while nothing has it open or mapped releases its object at
  once (`release_if_closed`). Rename and link across mounts are `EXDEV`, even between binds of one
  filesystem.

### tmpfs

- An instance is a detached store directory (`create_detached_dir`); files are ordinary objects.
  Options follow 6.1's `shmem_parse_one`: `size=` with suffixes or `%`, `nr_blocks=`, `nr_inodes=`,
  octal `mode=`, `uid=` and `gid=` (C-style numbers in the mounter's user namespace, stored as
  kernel IDs; unmapped there or `u32::MAX` `EINVAL`, a remount's too), `inode32`/`inode64` (shown
  only), `huge=` (only Linux's values) and `mpol=` ignored, generic words such as `ro` ignored,
  anything else `EINVAL`; the root defaults to 1777 owned by the mounter's fsuid/fsgid. mountinfo
  shows `size=` and `nr_inodes=` when not default, `mode=` when not 1777, `uid=`/`gid=` when not 0,
  then `inode64` or `inode32`. A remount parses before its `CAP_SYS_ADMIN` check, then checks
  writers, and takes only the limits (0 is unlimited) and `inode32|64`; turning an unlimited
  instance limited, or going below what is in use, is `EINVAL`.
- Boot instances (`/dev` 0755 nosuid, `/dev/shm` 1777 nosuid,nodev, `/run` 0755 nosuid,nodev with
  20% of RAM and 800Ki inodes) start uncounted: charges are dropped until the first count, at a
  create, write, fallocate or mapping allocation check, a statfs or a remount.
- Accounting per instance: one inode per name plus the root (creates, links, AF_UNIX binds);
  regular files by the union of host extents and guest allocations. Per-inode ranges distinguish
  fallocate reservations from pages instantiated by a mapping. Either consumes quota once.
  A mapped read instantiates its page without changing mtime or ctime. Growth by truncation is
  free and punching whole pages releases them. Symlinks of 128 bytes or more take one page.
  Limits default to half of RAM in pages and inodes; 0 is unlimited. Creates need room (`ENOSPC`, after
  `may_create`); a write needs room only for pages outside both recorded allocations and host extents
  (FIEMAP or a `SEEK_DATA` fallback). Writes stop at the first page that cannot fit. A fallocate reservation needs
  room for the whole range. Truncation is unlimited; a removal gives back one inode and its pages at the last link, unless the regular
  file is still open, mapped or executing (`file_in_use`), in which case its pages and inode stay
  charged in `Tmpfs::unlinked`. A pinned object supports stats through the last `O_PATH` fd.
  Unlinked files are updated on subsequent writes/truncates, included in counts and
  recounts, and evicted by `evict_unlinked_tmpfs` at syscall/thread release, execve close-on-exec,
  statfs and remount. Both statfs and remount recount the tree; a create, write or reservation about to
  be refused or cut recounts once
  when usage changed since the last count. Overlay writes charge a tmpfs upper, and mappings
  charge the layer supplying the mapped inode. Memfds and boot `/dev` loop nodes bypass the
  ordinary per-operation hooks.

### Metadata and namespace syscalls

- Stat: asm-generic `struct stat`, uid/gid mapped into the caller's user namespace; `st_dev` from
  the mount for store, overlay and synthetic nodes, nsfs's own for namespace files, fixed
  anonymous devices for pipes, sockets and anonymous inodes, the queue
  filesystem's for message queues, the devpts instance's for an open PTY slave, and the root
  filesystem's on the fast path (which resolves only there); `st_blksize` 4096 (1024 for procfs
  and devpts nodes, including devpts PTY masters and slaves). A store or overlay ptmx master
  reports the opened device node, including its inode, block size, ownership and timestamps.
  A master without an opened node keeps the synthetic ptmx identity. Ordinary files and host fds report the host’s `st_blocks`. Tracked
  tmpfs files count host extents and logical guest pages together. Other nodes use size (sysfs
  files 0; symlinks under 60 bytes on the
  root filesystem or 128 elsewhere live in the inode); directories report size 4096 on the root
  filesystem. newfstatat and statx accept `AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH`,
  `AT_NO_AUTOMOUNT` and the `AT_STATX_*` sync flags. newfstatat accepts both sync bits together.
  statx rejects that combination with `EINVAL` and reports `STATX_BASIC_STATS | STATX_MNT_ID` with
  `stx_mnt_id` set from the resolved node's or fd's `MountId` (`ROOT_MOUNT` on the fast path,
  `ANON_MOUNT` for node-less fds, matching mountinfo and fdinfo). Store and overlay stats
  advertise immutable, append-only and nodump in `stx_attributes_mask` and report the set bits
  in `stx_attributes`.
- `FS_IOC_GETFLAGS` and `FS_IOC_SETFLAGS` operate on a four-byte value for store, tmpfs,
  memfd and overlay regular files and directories. The store persists immutable, append-only,
  nodump and noatime in its inode row. Legacy stores start with zero flags. New named inodes
  and unnamed temporary files inherit nodump and noatime from the creating directory.
  An overlay reads the topmost inode and writes the upper inode after copy-up.
  Changing flags requires ownership or `CAP_FOWNER`; toggling immutable or append-only also
  requires `CAP_LINUX_IMMUTABLE` in the initial user namespace. A successful set updates ctime.
- Immutable inodes reject write access, including writable opens and `faccessat(W_OK)`.
  Append-only directories accept new names. Removing a name or replacing it checks both the
  directory and the victim for immutable and append-only. Hard links check the source too.
  Immutable and append-only files reject truncation, chmod, chown, explicit timestamp changes,
  xattr and POSIX ACL mutations (`kernel/xattr`), and writable shared mappings (`kernel/mm`).
  Both timestamps may be set to now on an append-only inode with the usual permissions.
  Descriptor writes check current flags, including after a writable open. Append-only forces
  writes to EOF and prevents toggling `O_APPEND`. Range copies check the destination before
  transferring data.
- statfs: the store reports ext4's magic with the host's `statvfs` of the objects directory, tmpfs
  its magic and limits (recounted), an overlay overlayfs's magic with the store's capacity, FUSE
  what the connection's server answers, synthetic nodes the magic of their kind with zero sizes; `f_flags` from
  the mount plus the filesystem's read-only, sync and mand (nsfs only `ST_VALID`). fstatfs of an
  anonymous pipe reports pipefs, of a named FIFO its underlying filesystem, of a message queue
  mqueue, of other node-less fds the root filesystem's figures.
- access/faccessat: real IDs unless `AT_EACCESS` (capabilities only when the real uid is root in
  the caller's namespace); FUSE nodes ask `kernel/fuse` even for `F_OK`; otherwise `F_OK` returns
  right after the lookup; `EACCES` for `X_OK` on regular files (excluding memfds) in a `noexec`
  mount (FUSE and non-FUSE); `EROFS` for `W_OK` after the permission check, on regular files,
  directories and symlinks only.
- chmod drops `S_ISGID` when the caller is outside the file's group without `CAP_FSETID` over
  it; on a memfd sealed with `F_SEAL_EXEC` changing an execute bit is `EPERM` after the owner check
  (6.3's `shmem_setattr`). chown needs mapped IDs (`EINVAL`) and `CAP_CHOWN` over the file or an
  owner keeping the uid and choosing one of its groups (-1 always passes). On a store or overlay
  non-directory it then clears setuid, setgid when group-executable or when the caller is outside
  the file's group without `CAP_FSETID` (6.2's `setattr_should_drop_sgid`), and file caps; when a
  set-id bit would go the caller must be the owner or have `CAP_FOWNER` (`EPERM`, bits kept), so
  `chown(-1, -1)` by another user fails on `su` but succeeds on a file with only caps (which lose
  them, as on Linux). Writes and truncation clear set-id bits through `kernel/fileio`'s
  `remove_privs`.
- utimensat accepts write permission for NULL times or two `UTIME_NOW` fields. Two `UTIME_OMIT`
  fields succeed after resolution. Explicit times and mixed NOW/OMIT require the owner or
  `CAP_FOWNER` where the kernel checks permissions. On synthetic nodes other than devpts terminals,
  message queues, the mqueue root and cgroup2, chmod, chown and utimensat are `EROFS` on a read-only mount and `EACCES` otherwise by path,
  `EBADF` by fd before any `EROFS`. Anonymous pipes and sockets share their VFS attributes
  across descriptors, including followed proc fd links. `fchownat` and `utimensat` accept
  empty paths with `AT_EMPTY_PATH`; Linux 6.1's `fchmodat` has no flags argument.
- An anonymous pipe starts at mode 0600 with the creator's fsuid/fsgid and the creation time.
  Successful ordinary reads update atime and writes update mtime and ctime. A socket starts at
  mode 0777 with its creation/accept-time fsuid and fsgid recorded on the socket and zero
  timestamps. Once initialized, chmod, chown and utimens share
  the stored attributes. Socket chown also updates the uid and gid recorded on the socket (used by
  procfs and standalone guests). Weak object references
  preserve identity until dead entries are pruned as the table grows.
- mknodat, after resolution and the `.`/`..` `EEXIST`: regular, char, block, FIFO, socket
  (directory `EPERM`, other types `EINVAL`); devices need `CAP_MKNOD` in the initial namespace and
  pass the device filter (whiteouts exempt; a whiteout on an overlay `EPERM`). unlinkat tries the
  mqueue root, cgroup2, overlay and FUSE paths first; in other synthetic directories it is
  `EROFS`/`EACCES` before the `.`/`..` and `ENOENT` checks. renameat2 takes `RENAME_NOREPLACE` and
  `RENAME_EXCHANGE` (`RENAME_WHITEOUT` `EINVAL`); `EXDEV` comes before the `.`/`..` checks (a
  source `.`/`..` `EBUSY`; a destination one `EEXIST` with `RENAME_NOREPLACE`, else `EBUSY`); the
  store checks mount writability before looking up the source. It then checks `NOREPLACE`,
  a missing exchange target, trailing slashes and ancestor moves before the same-inode no-op.
  Moving into the source subtree is `EINVAL`. Replacing an ancestor is `ENOTEMPTY` or, for an
  exchange, `EINVAL`. Directory write, sticky and inode flag checks follow the no-op. The target
  type check precedes reparenting permission and mount-point checks. In synthetic filesystems (`vfs_rename`
  order): read-only mount `EROFS`, missing source `ENOENT` (in procfs a missing destination too),
  `RENAME_NOREPLACE` onto an existing name `EEXIST`, a name onto itself 0; otherwise the mqueue
  root and cgroup2 `EPERM`, others `EACCES` without write and search permission on the source
  directory, `EPERM` with it.
- linkat: `AT_EMPTY_PATH` without `CAP_DAC_READ_SEARCH` is `ENOENT` (`do_linkat`); an existing name
  in a synthetic destination is `EEXIST`, then synthetic or mixed nodes `EXDEV`; then `.`/`..`,
  search, `EEXIST` and `EROFS`, `EXDEV` across mounts, `protected_hardlinks` (judged on the database
  row), directory write permission and tmpfs room; a magic link followed with `AT_SYMLINK_FOLLOW`
  reaches the same store node, a deleted file's link the store node on the mount it was opened
  through, a memfd's nothing (`EXDEV`); a source with link count 0 is `ENOENT` unless it is an
  unlinked `O_TMPFILE` created without `O_EXCL` (materializing it clears its linkable state and
  removes it from `Tmpfs::unlinked` without double-charging an inode); no `EMLINK` limit.
- getdents64 takes the listing (with `.` and `..`) on the first call and refreshes it only after an
  lseek lands on 0; `d_off` is index+1. `O_PATH` `EBADF`, a non-directory `ENOTDIR`, a removed
  store directory `ENOENT`; while entries remain, a count above `INT_MAX` or a buffer too small for
  the next entry `EINVAL`; an unwritable buffer returns the whole entries before it (`EFAULT` when
  none). Seeking a directory is `kernel/fileio`'s lseek.
- chdir/fchdir/chroot check search on store, overlay, FUSE and cgroup directories; chroot then
  needs `CAP_SYS_CHROOT` in the caller's user namespace. umask lives in the fs context.
- `protected_symlinks`, `protected_hardlinks` and `protected_fifos` default to 1, and
  `protected_regular` defaults to 2 (`may_create_in_sticky` on `O_CREAT` opens of existing regular
  files and FIFOs in sticky world-writable or, at level 2, group-writable directories, reading
  `Kernel::sysctls` for `/proc/sys/fs/protected_{regular,fifos}`).

### Devices

- On renderer-enabled machines `populate_gpu` creates `dri/renderD128` as character device
  226:128, mode 0666, in the boot devtmpfs. Each machine gets a fresh mount.

- `ensure_dev_nodes` creates missing `/proc` and `/sys` (0555) and `/run` (0755) in the store root
  and a missing `/dev` (0755), then, when `/dev` is a directory, `dev::populate`, which (also for
  the boot `/dev` tmpfs) creates the missing names, all root's: `null`, `zero`, `full`, `random`,
  `urandom`, `tty`, `ptmx`, `fuse` 0666, `kmsg` 0644, `console` 0600, `loop-control` and
  `loop0`–`loop7` 0660 group `disk` (gid 6), the `fd`/`stdin`/`stdout`/`stderr` links into
  `/proc/self/fd`, and `pts` (0755), `shm` (1777) and `mqueue` (0755).
- Opening devices by number and their ioctls are `kernel/files`'; their reads and writes are
  `kernel/fileio`'s.

## Dependencies (inbound / outbound)

### Inbound

- The syscall dispatcher.
- `kernel/files` and `kernel/fileio`: resolution and creation (`start_dir`, `lookup_at`,
  `may_create`), mount-flag checks, the tmpfs hooks, `released`, `display_path`, `Device` and `file_stat`.
- `kernel/process`: fs contexts at clone, the fast-path `Cached` resolver; `kernel/ns`: fs-context
  copies at unshare; `kernel/exec`: mount-flag checks.
- `kernel/mount`: walks; new tmpfs and FUSE instances and tmpfs reconfiguration.
- `kernel/overlay`: the tmpfs instances its layers are in; `kernel/xattr`: resolution and mount
  flags.
- `kernel/mm`: mmap `PROT_EXEC` on noexec.
- `kernel/sysctl`: sysctls for `protected_*`; `kernel/unix`: AF_UNIX bind creating store nodes.
- `kernel/poll` and `kernel/locks`: `dev_ino`; `kernel/inotify`: overlay keys, second walks; `kernel/fuse`: the walk.
- The machine at boot (`/dev` nodes).

### Outbound

- `kernel/mount`: the mount table resolution lifts through and climbs out of; mount and
  superblock flags; detaching mount points at unlink and rename; `released` when an open file, cwd
  or root in a detached mount goes.
- `kernel/store`: lookups, snapshots, namespace changes, detached directories, `fs_stats`, the
  metadata cache reader.
- `kernel/files`: open files and fd tables behind fd-based calls and dirfds; `kernel/fileio`:
  `opens_of` before an unlinked file's object is released; `kernel/mm`'s `maps_file` for the same check.
- `kernel/inotify` (the hooks, `renamed`, `deleted`), `kernel/overlay` (overlay nodes in every file
  operation; the sweep at syscall end), and `kernel/fuse` (everything on FUSE nodes).
- `kernel/procfs` (the `Pseudo` views, `pseudo::stat`, writability), `kernel/tty` (devpts),
  `kernel/ipc` (mqueue objects).
- `kernel/cgroup`: `bpf::check_device`, cgroup mkdir/rmdir.
- Credentials (`permission`, `owns`, `capable_wrt`, `new_owner`, `for_access`),
  `pidns`/`nsproxy`; `kernel/signal`'s `stub` for devices without a driver.
- `appine_hal` (`statvfs`, `memory_info`).

## Invariants and gotchas

- A node's mount is part of its identity: `..`, root checks, `BENEATH`, `EXDEV` and busy checks
  all compare mounts, so binds of one filesystem are distinct.
- A `Node` value alone does not pin a FUSE cache entry. FUSE path descriptors pin the entry for
  their lifetime. Other long-lived holders such as cwds, mounts and inotify watches participate
  in the FUSE sweep's in-use scan.
- `mounted()` matches a whole node, so a mount on a file shows through every hard link to it in
  that mount; the process root itself is never lifted (a mount on `/` is not seen by absolute
  lookups or `..`).
- `Cached` trusts its list of store mount points: every path that adds a mount point or changes
  the root mount's attachment or nosymfollow must call `fast_changed`.
- Synthetic directories are searchable by everyone except cgroup directories (their mkdir mode);
  procfs gates per-process data in readlink/follow.
- Every file operation keeps `kernel/overlay`'s rules for overlay nodes: no `Node::Store` is ever
  kept for an overlay file's store inode (changes go through a copy-up), every open file naming an
  overlay node holds it, and a syscall that waits while keeping a looked-up node stays out of
  `waits_on_files_only`.
- File operations added here must call `kernel/inotify`'s hooks where Linux's fsnotify does,
  passing an overlay node's key (`key_of`), never the store inode behind it; every rename that
  moves open files scans them all, even with no watches.
- A path that changes a store regular file or creates or removes a name must call the tmpfs hooks
  (`tmpfs_size`/`tmpfs_resized`, `tmpfs_reserve`/`tmpfs_created`, `tmpfs_victim`/`tmpfs_removed`),
  or usage drifts until the next full count; this binds `kernel/fileio`'s writes and size changes
  too.
- Calls here that borrow an open file (fd-based metadata, dirfds) follow `kernel/files`' rule: no
  borrow of an open file is held across a BKL release or a wait.
- A walk may fail with the internal `FUSE_RETRY`: code that swallows walk errors (`.ok()`,
  `has_child`) must not turn it into "not found" where that changes what is done, and nothing that
  changes state may come before a walk that can need it.

## Confirmed bugs / technical debt

- statx has no btime or `STATX_DIOALIGN`.
- **Scoped openat2 never returns `EAGAIN`:** the walk is atomic under the BKL, so a `..` walked
  while another thread mounts or renames never asks the caller to retry. Safe.
- Standalone guests running without a VFS lack the shared anonymous attribute table.

## Open questions

- Is skipping search permission on synthetic directories other than cgroup ones intended (only
  `/proc/<pid>/fd` and `fdinfo` gate access, by the ptrace-read check)?

## To verify

- None.
