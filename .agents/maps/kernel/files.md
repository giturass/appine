# kernel/files Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/files.md` for the paired decision history (it still holds the decisions on file data I/O, clones/unsharing, size changes and syncing made before they were split out into `kernel/fileio`; pre-split decisions from `kernel/vfs` are D5, D17, D26, D27, D34, D41, D44, D55, the owner half of D25, the `open_pseudo` half of D19 and the open-check parts of D36 in `.agents/decisions/kernel/vfs.md`).
>
> Verified: 2026-11-12 (split out of the kernel/vfs full mapping of 2026-11-12; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: implement Linux 6.1 `O_TMPFILE` support for store and tmpfs directories, and pin weak `Mm` on `/proc/<pid>/environ`)

## Responsibilities

`kernel/files` is what open files are, how they are opened and how they are controlled:

- fd tables and open file descriptions, open flags, `fcntl` and the generic ioctls;
- opening a path (the checks and the file each node kind gives), magic-link reopens, file handles
  and `memfd_create`, and each open file's inotify `Opened` record;
- opening character devices by device number, random ioctls, and render-node DRM ioctls (`gpu.rs`,
  `syscall/gpu.rs`).

Root: `core/kernel/src/gpu.rs`, `syscall/gpu.rs`, `core/kernel/src/fd.rs` (its `EventFd` and
`TimerFd` are described by `kernel/poll`), and in `syscall/fs.rs` the section Opening, closing,
duplicating (except `write_at`, `clone_range` and the `FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE`
ioctl arms in `kernel/fileio`, `open_overlay`, `flock`, the fcntl lock commands, `pipe2`,
`open_fifo` and the pipe-size fcntl commands), and the shared helpers `executing` and
`open_for_write`.

Outside the module: file data I/O, `lseek`, clones/unsharing, truncation, `fallocate`, cache hints
and syncing (`kernel/fileio`); path resolution, mount-flag checks, tmpfs accounting, metadata and
namespace syscalls, `getdents64`, `/dev` population and the `Device` numbers (`kernel/vfs`); the
mount table (`kernel/mount`); overlay opens and copy-up (`kernel/overlay`); locks and leases
(`kernel/locks`); pipes, FIFOs and splice (`kernel/pipe`); FUSE opens and I/O (`kernel/fuse`);
store objects (`kernel/store`); socket I/O (`kernel/net`, `kernel/unix`); poll bookkeeping, eventfd
and timerfd (`kernel/poll`); inotify (`kernel/inotify`); native AIO (`kernel/aio`); loop devices
(`kernel/loop`); terminals (`kernel/tty`); synthetic file content (`kernel/procfs`,
`kernel/sysctl`, `kernel/sysfs`).

## Key types

- `FdTable` — slots (`FileRef` and `cloexec`), reserved fds and `holds_locks`.
- `OpenFile` (`FileRef = Rc<RefCell<OpenFile>>`) — kind, mode and status flags, position and
  `pos_busy` (0 free, 1 taken, 2 with waiters; used by `kernel/fileio`), display path, dentry,
  mount (the root mount unless
  the open set one), `F_SETOWN*` owner with the setter's uids, `F_SETSIG` signal, poll bookkeeping
  (`kernel/poll`), the inotify `Opened` record, lock ownership, open_tree namespace (`tree`),
  `pseudo` (a memfd or `mq_open` descriptor: not a writer or mount holder; memfd seals in
  `Kernel::seals`), `ovl` and `ovl_holds` (the overlay
  node behind a file opened through an overlay, and its `Hold`s), and old host handles kept until
  close: `ovl_lower` (after a copy-up) and `retired` (after `rehome`).
- `FileKind` — Host, Regular, Directory, Path, Pipe, Device, Render, Pty, Socket, Epoll, EventFd,
  TimerFd, SignalFd, Inotify, Pidfd, MessageQueue, SeccompNotify, Bpf, Proc, Fuse and FuseDev (a
  FUSE directory is a Directory with the daemon's handle). Regular carries `cow`: writable, but the
  handle only reads because the file shares its object, so its first change gives the file an
  object of its own (`kernel/fileio`); set at open, by `rehome` and by `follow_copy_up`, cleared by
  `rehome`.
- `ProcEvent` — change counters given at open to mounts, mountinfo, cgroup2 and sysfs files.
- `StoreOpen` — how `open_store` reached the inode: found by path (every check), created by this
  open (none), or a nameless file reopened through a magic link (every check, through its own host
  handle; a memfd never read-only).
- `Renderer`, `Context`, `Mapping` (`gpu.rs`) — host render-node interfaces used by `syscall/gpu.rs`
  and retained by `kernel/hostmem`'s GPU mappings.

## Public entry points

- **fds and control**: `openat`, `openat2`, `name_to_handle_at`, `open_by_handle_at`, `close`,
  `close_range`, `dup`/`dup3`, `fcntl`, `memfd_create`; ioctls `FIOCLEX`/`FIONCLEX`/`FIONBIO`/
  `FIOASYNC`/`FIONREAD`, random ioctls, render-node DRM ioctls (`syscall/gpu.rs`), and the dispatch
  of other ioctls by kind (including `FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE` to `kernel/fileio`).
- **Kernel-internal**: `create_exclusive`, `unlink_path`, `close_replaced` (seccomp's ADDFD),
  `FdTable::with_host_stdio` (boot), `FdTable::reserve`/`fill`/`unreserve` (accept4 and AF_UNIX ancillary delivery), `open_mask`,
  `executing`, `open_for_write`.

## Data flow / lifecycle

### fd tables and open files

- Allocation searches from the requested minimum up to the receiving process's soft
  `RLIMIT_NOFILE`, returning `EMFILE` if no slot is free. An invalid `F_DUPFD` minimum gives
  `EINVAL` and a dup3 target at or above the limit gives `EBADF`. prlimit sets the target thread
  group's limits and refuses a hard limit over `nr_open` (`EPERM`). Processes sharing a table
  through `CLONE_FILES` can have different limits. accept4 reserves an fd before waiting.
  AF_UNIX recvmsg reserves the numbers encoded in `SCM_RIGHTS` until output is written.
  New fds skip a reserved slot until `fill` or `unreserve` ends the reservation. While reserved,
  dup3 and seccomp's `SECCOMP_ADDFD_FLAG_SETFD` report `EBUSY`, other lookups see it closed and
  fork does not copy it. Installing or reserving a descriptor grows the table's logical capacity
  (at least 64, rounded up to a power of two, capped at `nr_open` rounded up to 64; expanding to
  `fd >= nr_open` fails with `EMFILE`, or `EBADF` for `dup3`). Closing or cancelling a reservation
  retains this capacity for `pselect6`. arm64 has no dup2.
- dup and fork share one `OpenFile` (offset and status flags shared). Clone without `CLONE_FILES`
  sizes the copy from the highest open or reserved fd, copies open slots, and resets
  `holds_locks`. Every thread holds two references to its
  table: `unshare(CLONE_FILES)`, execve (after the other threads are gone) and
  `CLOSE_RANGE_UNSHARE` copy only when there are more; a copy is a new owner of POSIX locks, so an
  unshared table keeps its locks. Both `unshare(CLONE_FILES)` and `CLOSE_RANGE_UNSHARE` return
  `EMFILE` when the required slot count rounded up to 64 passes `nr_open`. The close-range
  copy excludes the range being closed when sizing it, and includes fds only marked close-on-exec. execve
  then applies close-on-exec.
- Closing (close, dup3 over an fd, close_range, close-on-exec) removes the slot, runs
  `locks::closed`, `mqueue_closed`, flushes a FUSE file (close returns the flush's error, the
  others ignore it) and `unix::released`; the last reference's `Drop` tells `vfs::released` its
  mount, its node's mount when different, `ANY_MOUNT` when `tree` was set (and a pinned PTY's
  devpts mount), wakes host-socket (not AF_UNIX) waiters, wakes lock
  waiters when the file held locks, and drops the `Opened` record (`IN_CLOSE_*` when any watch
  exists). A table's drop wakes lock waiters when it held locks. A file seccomp's
  `SECCOMP_ADDFD_FLAG_SETFD` replaces in another process's table is closed as that process's (its
  locks, message-queue notifications and FUSE flush; `close_replaced`).
- Open keeps the access mode, `O_APPEND`, `O_NONBLOCK`, `O_PATH`, `O_DSYNC`, `__O_SYNC`,
  `O_ASYNC`, `O_DIRECT`, `O_NOATIME`, `O_DIRECTORY`, `O_NOFOLLOW` and `__O_TMPFILE` (`kept`; with `O_PATH` only
  `O_PATH|O_DIRECTORY|O_NOFOLLOW`), and every other open adds `O_LARGEFILE`. An `O_PATH` fd
  takes only `F_DUPFD`, `F_DUPFD_CLOEXEC`, `F_GETFD`, `F_SETFD` and `F_GETFL` (else `EBADF`), and
  flock on it is `EBADF`. `F_SETFL` changes `O_APPEND|O_NONBLOCK|O_ASYNC|O_DIRECT|O_NOATIME`
  (fasync registration on `O_ASYNC`, ownership check when enabling `O_NOATIME` on store or overlay files, no `O_DIRECT` check). Access mode 3 needs read and write permission but
  makes the file neither readable nor writable (`OPEN_FMODE`). Unknown fcntl commands are `EINVAL`,
  counted as unimplemented paths.
- Owners: `F_SETOWN`/`F_GETOWN` (translated by the dispatcher's `pid_args` in a non-initial pid
  namespace: the argument, -1 included as process group 1, and the result), `F_SETOWN_EX`/
  `F_GETOWN_EX` and, on sockets only, `FIOSETOWN`/`SIOCSPGRP`, `FIOGETOWN`/`SIOCGPGRP` (translating
  themselves). Owners are global ids with the setter's real and effective uid for the delivery
  check (`kernel/poll`); an unknown or invisible number is `ESRCH` (`find_vpid`), 0 removes the
  owner, an owner outside the caller's namespace reads as 0, `F_SETOWN(INT_MIN)` is `EINVAL`.
  fcntl also handles `F_SETSIG`, pipe size and seals.
- memfd_create takes 6.3's `MFD_NOEXEC_SEAL` (mode 0666, sealed with `F_SEAL_EXEC`, sealing
  allowed) or `MFD_EXEC` (0777), not both (`EINVAL`); `MFD_HUGETLB` and names of 249 bytes or more
  are `EINVAL`; the path is `/memfd:<name> (deleted)`. `F_ADD_SEALS` with `F_SEAL_EXEC` on a memfd
  with an execute bit also adds the shrink, grow, write and future-write seals
  (`memfd_add_seals`); `F_SEAL_WRITE` with a writable shared mapping is `EBUSY`.
- An ordinary tmpfs file has a fixed `F_SEAL_SEAL`: `F_GET_SEALS` returns it and adding a
  valid seal fails with `EPERM`. Only memfds need entries in `Kernel::seals`.
- Boot: with host stdio, fds 0–2 wrap the host's fds (`FileKind::Host`); with a console, one PTY
  slave description on all three.
- ioctl: `O_PATH` is `EBADF`; then render-node DRM requests (`'d'`, `syscall/gpu.rs`),
  `FIOCLEX`/`FIONCLEX`/`FIONBIO`/`FIOASYNC`, the clone and dedupe requests (`kernel/fileio`),
  socket owners and `FIONREAD` on regular inodes (store, tmpfs, procfs, sysfs, nsfs, FUSE
  files and message queues whose stat is a regular file: the size less the position, as an int,
  negative past the end) come before dispatch by kind (nsfs, `/dev/fuse`, seccomp
  listeners, terminals, sockets, loop devices, pipe and inotify `FIONREAD`, the random device);
  host fds pass only 15 termios, termios2, window-size and `FIONREAD` requests to the host.
  Anything else is `ENOTTY`, counted as an unimplemented path unless Linux refuses it there too
  (terminal requests on other files).

### Opening

- `open_path_with` (openat, openat2, `create_exclusive`): resolve through `kernel/vfs` (openat2's
  rules and `O_CREAT`'s creation loop are in its map); on create, `may_create` (search, `EEXIST`,
  `EROFS`, write+search) and create with the requested mode limited by the parent default ACL or the
  umask (`kernel/cred`: setgid stripped before the umask, setgid directories); a just-created file
  skips permission checks and truncation. `O_PATH` gives a `FileKind::Path` (`O_DIRECTORY` on a
  non-directory `ENOTDIR`). Store, overlay, FUSE and mqueue-mount nodes (`PseudoNode::Mq`) set the
  file's mount. O_PATH pins queue inodes and quota, FUSE cache entries, and the object of a deleted
  file or executable reopened through procfs. Overlay reopens keep the overlay node as well.
  A direct `mq_open` marks its descriptor `pseudo` for the internal mqueue instance.
- Store nodes (`open_store`), unless just created: symlink `ELOOP`; a directory with write access,
  `O_CREAT` or `O_TRUNC` `EISDIR`; a regular file with `O_TRUNC` `EROFS` on ro, else it adds
  `MAY_WRITE`; a regular file opened for writing on a read-only instance (`sb_rdonly`) `EROFS`
  before DAC permission (`sb_permission`); devices on nodev `EACCES`; permission; the cgroup BPF
  device filter (not for device number 0); `O_NOATIME` by a non-owner without `CAP_FOWNER`
  `EPERM`; a regular file opened for writing on a read-only bind mount `EROFS`. Then always: the `O_DIRECT` rule; `EISDIR` for directories and `ENOTDIR`
  for `O_DIRECTORY` (after the checks above, where `do_open` checks before `may_open`); unless
  just created, writing an executing file `ETXTBSY` and lease breaks; `O_TRUNC` removes set-id bits
  and truncates (`kernel/fileio`), with `O_RDONLY` too (through a writable handle of its own), a
  held file first getting an empty object of its own (`kernel/fileio`'s `make_private`); any other
  write open of a held file gets a read-only handle on the shared object, marked `cow`. Then by
  type: regular files open the host object, character devices by device number (Character devices
  below), block devices as loop devices (major 7, `kernel/loop`; others `ENXIO`), FIFOs the shared
  pipe (access mode 3 `EINVAL`), sockets `ENXIO`.
- FUSE nodes are opened and created by `kernel/fuse` (the daemon's open and create); a file
  created that way is not checked again.
- Pseudo nodes: nsfs writes `EPERM` first; permission from the synthetic stat, except `/proc/sys`
  (`kernel/sysctl`'s `test_perm` and `net.*`/`user.max_*` rules); `O_TRUNC` asks
  for write; the ptrace read check for `mem`, `auxv`, `environ`, `maps`, `smaps`, `smaps_rollup`
  and `pagemap` (the process found through `pseudo::group_of_id` matching the pinned `ProcId`, so
  `/proc/<tid>` works and a reused pid does not match; `mem` and `pagemap` of a gone thread `ESRCH`,
  both pinning a weak `Mm` at open; `environ` also pins a weak `Mm` when live and reads EOF for a
  zombie or once the `Mm` is freed or replaced by `execve`); `setgroups` writes also need `CAP_SYS_ADMIN` over the
  target's user namespace; nodev and the device filter for PTYs; `O_DIRECT` `EINVAL`;
  `EISDIR`/`ENOTDIR`/`EROFS`; `EACCES` for writes the filesystem does not allow except read-only
  procfs files outside `/proc/sys`, which root opens and whose writes fail (`kernel/procfs`).
  Content is generated at open, and the opener's credentials are kept for regeneration and id-map
  writes.
- Magic links to nameless targets — `/proc/<pid>/fd/N` of a deleted or memfd file, a pipe or a host
  fd (`OpenFd`), `/proc/<pid>/exe` of a deleted program (`OpenExe`) — skip the synthetic stat and
  go to `reopen`/`reopen_exe`: a regular file checks seals (`kernel/fileio`) for `O_TRUNC` with a
  write mode, then gets `open_store`'s checks on the mount it was opened or run through
  (`StoreOpen::Reopened`, through a duplicate of its host handle, or a writable one opened through
  the host's `/proc/self/fd`); pipes reopen a new end and host fds the same fd, with no check. The
  new description takes the original's mount and display path (`/memfd:<name> (deleted)`,
  `pipe:[<n>]`) and records an `Opened`; unlike the memfd it reopens it is not `pseudo`, so it
  counts as a writer (exec `ETXTBSY`) as on Linux. Linked targets resolve to store or overlay
  nodes and get the normal checks. Named FIFO opens and reopens each retain a last-close record.
- File handles: `name_to_handle_at` (`AT_SYMLINK_FOLLOW`, `AT_EMPTY_PATH`, and 6.5's
  `AT_HANDLE_FID` ignored) encodes store nodes only (else `EOPNOTSUPP`) as 8 bytes of type 1 holding
  the inode number, and returns the mount id; over 128 bytes is `EINVAL`, too small `EOVERFLOW`.
  `open_by_handle_at` needs `CAP_DAC_READ_SEARCH` in the initial user namespace (`EPERM`), a size
  of 1 to 128 (`EINVAL`) and a mount fd on a store node; a wrong handle, a missing or unlinked
  inode, or an inode belonging to a different store/tmpfs superblock (`Vfs::store_sb_root` vs
  `Store::tree_root`) is `ESTALE`. It opens the inode on that mount through `open_store` with every
  check, or as an `O_PATH` fd, emitting `IN_OPEN` (and `IN_MODIFY` on `O_TRUNC`) and attaching an
  inotify `Opened` record, without a display path or validation of other open flags.
- Opens through a path of a regular file, device, directory (store, overlay, FUSE, cgroup2), FUSE
  file or cgroup2 file, as well as `open_by_handle_at`, `O_TMPFILE` and `memfd_create`, record an inotify
  `Opened` (`kernel/inotify`), watches or not. `O_TMPFILE` (`open_tmpfile`, Linux 6.1's `do_tmpfile`/
  `vfs_tmpfile`) is supported on store and tmpfs directories (invalid flag combinations `EINVAL`,
  non-directories `ENOTDIR`, read-only mounts `EROFS`, missing `MAY_WRITE|MAY_EXEC` `EACCES`,
  unsupported filesystems `EOPNOTSUPP`, `O_DIRECT` on tmpfs `EINVAL`); it creates an unlinked
  `nlink == 0` regular file inheriting ownership/umask/default ACLs, tracks tmpfs quota in
  `Tmpfs::unlinked`, allows linking once via `linkat` (`AT_EMPTY_PATH` with `CAP_DAC_READ_SEARCH`,
  or `/proc/self/fd/N` with `AT_SYMLINK_FOLLOW`) unless `O_EXCL` was set, and reaps unlinked
  host objects via `Store::release_tmpfile` when the last reference closes. `O_DIRECT` (6.1's `direct_IO` check, before
  the file's own open) passes regular files on mounts other than tmpfs, block devices and sockets;
  directories, tmpfs files, character devices, FIFOs and synthetic files are `EINVAL`.

### Character devices

- `syscall/gpu.rs` handles render node 226:128. Each open file description owns its context,
  ring count and GEM handle table. Dup and fork share them. DRM version and capset queries precede
  context initialization. Blob creation provides an opaque mmap offset, execbuffer captures the
  command and referenced mappings before unlocking, and GEM close removes the guest handle.
  Host operations use the `Renderer`, `Context` and `Mapping` interfaces in `gpu.rs`.
- Opening dispatches by device number for store and overlay nodes anywhere and handle opens (device
  nodes in FUSE filesystems are `ENXIO`), after nodev (`EACCES`), permission and the cgroup BPF
  device filter: 5:0 and 5:1 the controlling terminal, 5:2 the ptmx of the devpts beside the node
  (`ENOENT` without a `pts` there, `ENODEV` when it is not devpts or the node's directory is not a
  store directory; the boot devpts when no directory was recorded), major 136 a boot devpts slave,
  1:3/5/7/8/9/11 `kernel/vfs`'s `Device` (`/dev/kmsg`: `EPERM` when devkmsg is off, syslog
  permission to read), 10:237 loop-control and block 7:N (`kernel/loop`), 10:229 `/dev/fuse`
  (`kernel/fuse`), 226:128 render node (`syscall/gpu.rs`); other character devices and block majors
  `ENXIO`, counted as unimplemented paths. An opened PTY retains the store or overlay device
  node's lock identity independently of the terminal it serves.
- Random-device ioctls follow `random_ioctl` (entropy count fixed at 256; changing ones need
  `CAP_SYS_ADMIN` in the initial namespace). Character-device reads and writes belong to
  `kernel/fileio`.

## Dependencies (inbound / outbound)

### Inbound

- The syscall dispatcher (with `pid_args` for `F_SETOWN`/`F_GETOWN`).
- `kernel/fileio`: `FdTable`, `OpenFile`, `FileKind` (`pos_busy`, `cow`, `retired`), `io_file`,
  `executing`, and `ioctl` dispatch for `FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE`.
- `kernel/process`: fd tables at clone, prlimit; `kernel/ns`: fd-table copies at unshare;
  `kernel/exec`: execve's fd-table handling, `open_for_write`.
- `kernel/vfs`: open files and fd tables behind fd-based metadata calls, dirfds and getdents64.
- `kernel/mount`: the fd tables its busy and writer checks scan.
- `kernel/overlay`: `open_store`; `kernel/locks`: fd tables, open files, `lock_ino`;
  `kernel/pipe`: `FileKind::Pipe`, fcntl/ioctl/close dispatch; `kernel/hostmem`: `gpu::Mapping`.
- `kernel/procfs`: fd links and fdinfo; `kernel/net`: accept4's reserved fds, socket ioctls;
  `kernel/unix`: pending `SCM_RIGHTS` reservations.
- `kernel/poll`: poll/epoll reading open files, `EventFd`/`TimerFd`.
- `kernel/inotify`: `Opened` on open/close, `FIONREAD`; `kernel/aio`, `kernel/loop` and
  `kernel/fuse`: fd lookup, `open_mask`, `executing`, `open_for_write`.
- `kernel/ipc` (queue fds), seccomp (added fds, `close_replaced`), core dumps (`create_exclusive`,
  `unlink_path`), and the machine at boot (host stdio).

### Outbound

- `kernel/fileio`: `clone_range`, `FIDEDUPERANGE`, `make_private`, `remove_privs`, `truncating`,
  `seals_permit` (for `O_TRUNC`).
- `kernel/vfs`: path resolution and creation (`start_dir`, `lookup_at`, `may_create`), the
  read-only, nodev and other mount-flag checks, the tmpfs hooks, `vfs::released`,
  `display_path`, `Device` and the device numbers opens dispatch on, `file_stat` for `FIONREAD`.
- `kernel/store`: objects and anonymous memfds.
- `kernel/inotify` (the hooks, `opened`), `kernel/overlay` (opens through an overlay),
  `kernel/locks` (fcntl lock commands, `locks::closed`, `break_leases`), `kernel/pipe` (pipes,
  FIFOs, pipe-size fcntl), `kernel/loop`, and `kernel/fuse` (opens, flushes, `/dev/fuse` ioctls).
- `kernel/cgroup` (device BPF checks, cgroup file-change observation and keys).
- `kernel/procfs`, `kernel/sysctl`, `kernel/sysfs` (synthetic opens and content), `kernel/tty`
  (terminal opens and ioctls), `kernel/ipc` (mqueue opens and close), `kernel/poll` (fasync),
  `kernel/net` (socket ioctls), `kernel/unix` (files in flight, `released`), `kernel/mm`
  (`writably_maps` for `F_SEAL_WRITE`).
- Credentials (`permission`, `owns`, `capable_wrt`, `new_owner`), `pidns`, `kernel/signal`'s `stub`
  for unimplemented fcntl commands and ioctls, and `appine_hal` (host ioctls).

## Invariants and gotchas

- Opening walks through `kernel/vfs`'s resolver, which may fail with the internal `FUSE_RETRY`
  (see its map): nothing that changes state may come before a walk that can need it.
- Every file operation keeps `kernel/overlay`'s rules for overlay nodes: no `Node::Store` is ever
  kept for an overlay file's store inode (changes go through a copy-up), every open file naming an
  overlay node holds it, and a syscall that waits while keeping a looked-up node stays out of
  `waits_on_files_only`.
- Every open records an `Opened` (`kernel/inotify`), and file operations added here call its hooks
  where Linux's fsnotify does, passing an overlay node's key (`key_of`).
- `kernel/aio`'s `has_iter` and `has_fsync` must follow new `FileKind`s and devices.
- `open_store` skips its checks only for a file this open created (`StoreOpen::Created`); reopens
  through `/proc/<pid>/fd` and `exe` get them, so a check added there must also hold for a nameless
  file opened through its host handle (a memfd has no store object, no mount of the store).
- An `O_TRUNC` open must keep `kernel/fileio`'s object-unsharing, privilege-removal and truncation
  rules and `kernel/vfs`'s tmpfs hooks; no code may hold an `OpenFile` borrow across a BKL release
  or wait (`kernel/fileio`'s `rehome` skips borrowed descriptions), and handles retired by `rehome`
  or `follow_copy_up` stay on `OpenFile` until close.

## Confirmed bugs / technical debt

- None.

## Open questions

- Should `O_TMPFILE` also be extended to overlayfs and FUSE directories?
