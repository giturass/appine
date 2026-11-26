# kernel/fileio Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/fileio.md` for the paired decision history (not yet created; decisions from before the split are D3, D4 and the truncate-through-fd-link half of D2 in `.agents/decisions/kernel/files.md`, plus D11, D22, D24, D29, D33, D45, the `write_sync` half of D17, the write-path half of D41 and the file I/O halves of D36 and D37 in `.agents/decisions/kernel/vfs.md`).
>
> Verified: 2026-11-23 (split out of the kernel/files map, which was split out of the kernel/vfs full mapping of 2026-11-12; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: logical memfd lengths, sparse reads and copies, read range checks and final-reference cleanup)

## Responsibilities

`kernel/fileio` implements data I/O, seeking, size changes, cache hints, syncing and object sharing/unsharing on open files:

- data I/O: regular files through host `pread`/`pwrite` without the BKL behind the `f_pos_lock`
  emulation, per-kind read and write paths (including character devices, host stdio and synthetic
  files), `readv`/`writev`, `preadv2`/`pwritev2`, `sendfile` and `copy_file_range`;
- clones (`FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE` and whole-file `copy_file_range`) sharing store
  objects, and giving a shared file an object of its own before it changes (`prepare_write`,
  `make_private`, `rehome`);
- `lseek`, `truncate`, `ftruncate`, `fallocate`, cache hints and syncing (`fadvise64`,
  `sync_file_range`, `readahead`, `cachestat`, `fsync`/`fdatasync`, `sync`/`syncfs`).

Root: in `core/kernel/src/syscall/fs.rs`, `write_at`, `clone_range` and the
`FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE` arms of `ioctl`, the section Reading and writing (except
`follow_copy_up` and `copy_up` in `kernel/overlay`, and the pipe reads and writes and the splice
block in `kernel/pipe`), `lseek`, the sections Cache hints and syncing and truncate and fallocate,
and the shared helpers `check_seals`, `seals_permit`, `remove_privs` and `truncating`.

Outside the module: fd tables, `OpenFile`/`FileKind`, path opening, fcntl/ioctl dispatch and
render-node/random ioctls (`kernel/files`); path resolution, mount-flag checks, tmpfs accounting,
metadata/namespace syscalls and `getdents64` (`kernel/vfs`); overlay copy-up (`kernel/overlay`);
locks and lease breaks (`kernel/locks`); pipes, FIFOs and splice (`kernel/pipe`); FUSE file I/O and
flushes (`kernel/fuse`); store objects, sharing and WAL sync (`kernel/store`); socket I/O
(`kernel/net`, `kernel/unix`); eventfd/timerfd readiness (`kernel/poll`); inotify hooks
(`kernel/inotify`); native AIO (`kernel/aio`); loop device I/O (`kernel/loop`); terminals
(`kernel/tty`); synthetic file regeneration/writes (`kernel/procfs`, `kernel/sysctl`,
`kernel/sysfs`); VMA truncation and remapping (`kernel/mm`).

## Key types

- `IoPath` — the route of one I/O call, chosen so no borrow of the open file is held during I/O
  (`Local` uses `unlocked_io` for regular files and holds the BKL for other local files,
  tmpfs writes and regular-file appends).
- `Kernel::unsharing` — inodes `make_private` is copying with the BKL released.
- Shared `OpenFile` state owned by `kernel/files` and driven here: `pos`, `pos_busy` (0 free, 1
  taken, 2 with waiters), `FileKind::Regular { cow, .. }` and `retired` old host handles kept until
  close after `rehome`.

## Public entry points

- **Data I/O and seeking**: `read`/`write`, `pread`/`pwrite`, `readv`/`writev`,
  `preadv2`/`pwritev2` (`pvectored`), `lseek`, `sendfile`, `copy_file_range`; `FICLONE`/
  `FICLONERANGE` (`clone_range`) and `FIDEDUPERANGE` dispatched from `kernel/files`'s `ioctl`.
- **Size changes, cache hints and syncing**: `truncate`, `ftruncate`, `fallocate`, `fadvise64`,
  `sync_file_range` (`cache_hint`), `readahead`, `cachestat` (a 6.5 call), `fsync`/`fdatasync`,
  `sync`, `syncfs`.
- **Kernel-internal**: `write_at` (core dumps), `prepare_write`, `make_private`, `host_unshared`
  (from `kernel/inotify`'s `host_change`), `IoFlags`, `read_file`/`read_file_with`,
  `write_file`/`write_file_with`, `read_bytes`, `write_bytes`, `write_sync`,
  `vectored`/`vectored_with`, `fsync`, `has_fsync`, `seekable`, `append_offset` (`kernel/aio`,
  `kernel/loop`), `check_fsize`, `fsize_room` (`kernel/fuse`), `check_seals`, `seals_permit`,
  `remove_privs`, `truncating` (`kernel/files`'s `O_TRUNC`, `kernel/vfs` and FUSE mapped backing), `opens_of`.

## Data flow / lifecycle

### Data I/O

- read and pread send sockets to `kernel/net` first (even for 0 bytes); otherwise they read in
  pieces of 64 KiB (8 MiB for FUSE files and `/dev/fuse`), looping until the buffer is full only
  for regular files, synthetic files other than `/proc/kmsg`, `/dev/zero`, `/dev/full`, random
  and loop devices; pipes, terminals, host fds and FUSE files return after one piece. write and
  pwrite check mode first, then copy and write a piece at a time, stopping at a short write.
- A regular-file read checks the signed offset plus the full scalar count (before `MAX_RW_COUNT`)
  or imported iovec total before copying any bytes. Overflow gives `EINVAL`, including at EOF.
  A memfd with a logical length reads its host prefix followed by zeros through logical EOF.
  Stat, `FIONREAD`, seals and `SEEK_END` use the greater of host and logical size. Beyond host
  EOF, `SEEK_HOLE` returns the requested offset within the file and `SEEK_DATA` gives `ENXIO`.
- `/dev/zero`, `/dev/full` and the random devices fill the whole buffer per read; randomness comes
  from the host's `getrandom(2)` with no flags; writes to the random devices are discarded, to
  `/dev/full` `ENOSPC`.
- Without an explicit offset, regular files, FUSE files and `/proc/<pid>/mem` serialize position updates with `pos_busy`
  (`PosGuard`/`TwoPosGuard`, emulating `f_pos_lock`): `read_file`/`write_file` loops, synchronous
  `writev`, `lseek`, `sendfile`, `copy_file_range` (including `try_share`
  and `copy_regular`), and `splice` into a file hold `pos_busy` across their position work so
  unlocked I/O cannot overwrite a sought or advanced position. Loop devices and other synthetic files
  move their position without it.
- write and writev check `RLIMIT_FSIZE` once for the whole call (cut, or `SIGXFSZ` and `EFBIG` at
  or past it), so a piece or iovec ending at the limit only shortens the call. A write at the
  position of a regular file (not `O_APPEND`) takes `pos_busy` before its checks and holds it to
  the end (`write_local`); each piece checks `RLIMIT_FSIZE`, tmpfs room and seals at its position,
  calls `prepare_write` and `remove_privs`, writes, and charges tmpfs. Tmpfs writes hold the BKL
  from the final room check through charging, including a fresh check after copy-up. Writes and
  truncation call `remove_privs` (`CAP_FSETID` checked via `capable_wrt`), which clears setgid with group exec or
  when the caller is not in the file's group and lacks `CAP_FSETID` (Linux 6.2+, aligned with
  chown).
- `O_APPEND` writes run under the BKL at the effective file length; `pwrite` on an `O_APPEND` file
  appends too unless `RWF_NOAPPEND` (6.9's flag, honoured only with an explicit offset; FUSE files
  ignore it). `preadv2`/`pwritev2` support `RWF_HIPRI`, `RWF_DSYNC`, `RWF_SYNC`, `RWF_NOWAIT`,
  `RWF_APPEND` and `RWF_NOAPPEND` (per-request via `IoFlags`, without mutating the open file's
  status flags) and refuse unknown flags (`EOPNOTSUPP`, before the fd lookup). After each write,
  `writev` (once after all iovecs rather than per-iovec), `sendfile`, `copy_file_range` and
  `splice` call, `write_sync` syncs a regular store file's object (fdatasync for `O_DSYNC`/
  `RWF_DSYNC`, fsync for `O_SYNC`/`RWF_SYNC`, BKL released) or a FUSE file (`FUSE_FSYNC`); a sync
  error after writing is propagated cleanly. Host fds, core dumps and loop writes are not synced.
- Zero-length scalar reads check the fd, positional I/O and read mode. Empty reads on pipes and regular files complete immediately. Directories return `EISDIR`, epoll and short fixed-size device reads return `EINVAL`. Socket reads retain their message semantics.
- Host stdio fds (`FileKind::Host`): regular host files support positional I/O (`pread`/`pwrite`,
  `preadv`/`pwritev`) and loop to fill on read without polling; non-regular host fds (pipes,
  terminals, sockets) return `ESPIPE` on positional I/O, poll `POLLIN`/`POLLOUT` via `wait_host`
  (honouring guest `O_NONBLOCK`, interruptible by guest signals, writing in `PIPE_BUF` chunks so
  blocked writes do not stall in the host kernel) and turn `EPIPE` into `SIGPIPE`; lseek reaches
  the host.
- `SEEK_DATA` and `SEEK_HOLE` query host extents and include tmpfs pages instantiated by mapped
  access. Recorded fallocate reservations start as holes. Offsets outside the file
  give `ENXIO`. A host without sparse seeks assumes data up to EOF. lseek on a directory takes `SEEK_SET` and `SEEK_CUR`
  everywhere (except `FOPEN_NONSEEKABLE`/`FOPEN_STREAM` FUSE directories, which return `ESPIPE`);
  `SEEK_END`, `SEEK_DATA` and `SEEK_HOLE` count from the end as the filesystem's `llseek` does:
  store directories end at the largest position (ext4's hashed directories), procfs, sysfs and
  cgroup2 at 0, FUSE directories at the directory inode's size (via `kernel/fuse`, refreshing
  stale attributes with `FUSE_GETATTR`), and every other filesystem refuses them (`EINVAL`).
- readv and writev follow Linux's `read_iter`/`write_iter` split: pipes, terminals and sockets
  (and eventfd reads) do one read or write over all iovecs (one read of up to 64 KiB scattered in
  order; writes in 64 KiB pieces across iovecs until one is short; sockets through `kernel/net`),
  so a pipe readv returns what was there and small pipe writes stay atomic; `/dev/fuse` does the
  same in pieces of up to 8 MiB, since a FUSE message moves whole, and a `/dev/kmsg` writev is one
  record. Writable `/proc/sys` sysctl writes (numeric, string and bitmap) parse all iovecs as one
  value. Host stdio fds that are not regular
  files on the host take the pipe path. Everything else
  goes iovec by iovec and stops at an incomplete one, as Linux does for files with only
  `read`/`write`. Over 1024 iovecs or a total over `isize::MAX` is `EINVAL`, and accepted iovecs
  (as well as scalar `read`/`write`/`pread`/`pwrite`, `sendfile`, `copy_file_range` and
  `copy_data`) are capped at `MAX_RW_COUNT` (`0x7ffff000`, dropping trailing iovecs beyond the
  cap); a total of 0 returns 0 after the offset and mode checks.
- A copy to or from the guest buffer that faults grows a grows-down mapping below it
  (`kernel/mm`) and retries (not for vmsplice's write side or a `/dev/kmsg` writev). A read whose
  buffer faults partway returns the bytes before the faulting page (`EFAULT` when none): regular
  and FUSE files move the position back past what was not copied (`give_back`: never further than
  the read moved it, so FUSE stream files keep theirs), other files keep what they
  consumed (pipe and terminal data, synthetic and loop positions). Writes copy one piece at a time,
  all or nothing, so a fault fails with `EFAULT` only in the first piece (a pipe writev also writes
  the iovecs before the faulting one); earlier pieces stay written and count.
- `sendfile` (input a regular file, a seekable FUSE file or a device that can be spliced from, so
  not `/dev/null`, else `EINVAL`; an output other than a pipe that is `O_APPEND` or cannot be
  spliced into, such as `/dev/full` or an eventfd, `EINVAL` with the input position unchanged,
  as `do_splice_direct`; both ends judged by `kernel/pipe`'s `splice_reads`/`splice_writes`) and
  `copy_file_range` between distinct regular store files use the
  host's sendfile without the BKL (`copy_regular`, capped at `MAX_RW_COUNT`), falling back to
  chunked copies for an `O_APPEND` output, the same inode, a file without a host handle (devices;
  FUSE files, which copy_file_range takes as regular and copies block by block, as 6.1 falls back
  without `FUSE_COPY_FILE_RANGE`), a memfd input with a logical length, a sealed or tmpfs output, or host
  `EINVAL`/`ENOSYS`/`EOPNOTSUPP`/`EXDEV`. The fallbacks move the input position back over what was
  not written, never further than the read moved it (devices keep their positions), and an error
  after some bytes were copied returns those bytes. A pipe destination for sendfile uses the same
  slot reservation and source page boundaries as splice. `copy_file_range` checks fds, offsets, then
  flags (`EINVAL`), then in `generic_copy_file_checks` order per file (a non-regular input before a
  directory output): directories `EISDIR`, other non-regular files `EINVAL`, modes and `O_APPEND`
  `EBADF`, different devices `EXDEV` (the mounts' device numbers; a memfd counts as the root
  filesystem), wrapping ranges `EOVERFLOW`, then the length cut to the input's end, `RLIMIT_FSIZE`
  and the largest file size (`EFBIG`), overlap in one file `EINVAL`, negative positions `EINVAL`.

### Size changes, cache hints and syncing

- `fallocate` looks up the fd first (`EBADF` on closed/`O_PATH` fds), then validates offset/len
  (`EINVAL`), generic mode flags (`EOPNOTSUPP`), writability (`EBADF`), file type (pipes `ESPIPE`,
  directories `EISDIR`, sockets and other non-regular files `ENODEV`), and `EFBIG` (`offset + len`
  overflow), then calls `prepare_write`, filesystem-specific mode checks (0, `KEEP_SIZE`,
  `PUNCH_HOLE` with `KEEP_SIZE`, and `ZERO_RANGE` outside tmpfs), `RLIMIT_FSIZE`, seals and tmpfs
  room. Tmpfs records the reserved range against guest quota
  and extends the file when needed. Leaving host holes sparse keeps untouched reservations out of
  `SEEK_DATA` and overlay copy-up. A later write can still exhaust the host disk. Hole punching
  revokes tmpfs mappings' translations before releasing the backing pages. Other allocations,
  punches and zeroing use host fallocate, with a zeroing or lengthening fallback.
- truncate: `EISDIR`, `EINVAL` for non-regular, `EROFS`, write permission (a synthetic regular file
  then succeeds unchanged), `ETXTBSY`, `RLIMIT_FSIZE`, then leases (6.1 breaks leases before
  `inode_newsize_ok`), seals, `make_private`, unmapping the dropped tail (busy address spaces
  skipped) and the host truncation. A deleted file or memfd reached through `/proc/<pid>/fd/N` is
  truncated itself: its store inode on the mount it was opened through, through the description's
  host handle when the store has no object (a memfd's), a memfd never read-only; ftruncate breaks
  leases for a writable regular file, then `prepare_write`, then `EINVAL` unless writable and
  regular (`EBADF` on `O_PATH`), `RLIMIT_FSIZE` and seals, with no `ETXTBSY` check.
- If host truncation returns `EFBIG` for a memfd, the VFS records the requested length through
  `i64::MAX` and requests a host timestamp update. An ordinary successful truncation clears
  the override. The unlinked-inode sweep releases it after the last open description, mapping or
  executable reference goes away. Hole punches in the logical tail need no data allocation.
- Cache hints and syncing: fadvise64 rejects `O_PATH` fds with `EBADF` (via `io_file`) before
  returning `ESPIPE` on pipes and sockets and `EINVAL` for a negative length or unknown advice,
  else a no-op; sync_file_range rejects `O_PATH` fds with `EBADF` before validating flags/range,
  passes regular files and bound writable loop devices with flags to the host (clamped to the loop
  device's size and offset), directories and unbound/read-only loop devices succeed, other files
  are `ESPIPE`; readahead accepts readable regular files;
  cachestat asks the host for regular files and reports zeros for others. fsync and fdatasync
  (regular files, directories, host fds, FUSE files and loop devices, else `EINVAL`) sync the host
  object with the BKL released (FUSE through the daemon, loop devices their backing file, host fds
  not at all), then commit the store and wait for its WAL; sync and syncfs also sync the whole
  host filesystem holding the store.

### Clones and unsharing

- Writes to a held file, truncation, allocation and mapping through a store descriptor give the inode an
  object of its own. Guest unsharing copies outside the BKL while other writers wait. Back under
  the BKL it prepares replacement handles for open descriptions before publishing the copy,
  abandons it on failure and retries if the original object changed. Replaced handles remain
  open until description close for I/O in flight. A Files app unshare rehomes descriptions
  during change replay. Settling a held inode restores atime and mtime on the host object and can
  advance ctime, even for a read-only mapping. Before exposing a store mapping, the kernel reconciles
  open descriptions with its pinned host object.
- Clones: copy_file_range from offset 0 to offset 0 of a whole non-empty input into an output no
  longer than it, and FICLONE or FICLONERANGE doing the same, share the input's object
  (`try_share`) unless either is not a regular store file, a memfd, opened through an overlay or on
  tmpfs, both are one inode, the input is deleted, open for writing in this kernel by a description
  not marked `cow`, either object has a store mapping pin, either file is open for writing by
  the Files app (`host_writing`), or the output is mapped (privately too), sealed or being
  unshared; then they copy. The output's set-id bits go first and its descriptions move to the
  shared object (`rehome`); copy_file_range returns the whole length at once and advances the
  positions. FICLONE/FICLONERANGE check in 6.1's order: different mounts (memfds on their own)
  `EXDEV`, directories `EISDIR`, other non-regular files `EINVAL`, modes and `O_APPEND` `EBADF`,
  memfds, overlay and tmpfs files `EOPNOTSUPP` (no remap_file_range), negative or wrapping ranges
  `EINVAL`; length 0 reaches the input's end (nothing at the end, `EINVAL` past it); unaligned
  offsets, an input offset at or past the end, a length cut by the end or `RLIMIT_FSIZE` (at or
  past it `SIGXFSZ` and `EFBIG`) or unaligned short of the end, and overlapping ranges in one file
  are `EINVAL`. Other ranges are copied in `MAX_RW_COUNT` pieces. `FIDEDUPERANGE` checks its
  reserved fields (`EINVAL`), directories (`EISDIR`) and other non-regular files (`EINVAL`), then
  is `EOPNOTSUPP`.
- An overlay copy-up shares the lower file's object too, through `kernel/overlay`'s `copy_up`,
  which copies the data instead when the lower object has a mapping pin or a host writer, and rehomes
  the lower file's descriptions open for writing.

## Dependencies (inbound / outbound)

### Inbound

- The syscall dispatcher (`read`/`write`/`pread`/`pwrite`/`readv`/`writev`/`preadv2`/`pwritev2`,
  `lseek`, `sendfile`, `copy_file_range`, `truncate`/`ftruncate`/`fallocate`, `fadvise64`,
  `sync_file_range`, `readahead`, `cachestat`, `fsync`/`fdatasync`, `sync`/`syncfs`).
- `kernel/files`: `ioctl` dispatch for `FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE`, plus `O_TRUNC`'s
  calls to `make_private`, `remove_privs`, `truncating` and `seals_permit`.
- `kernel/vfs`: `opens_of` before releasing an unlinked file's object, and `remove_privs` shared
  privileges rule.
- `kernel/overlay`: `prepare_write`, `rehome` after copy-up; `kernel/pipe`: file checks and the
  read and write paths of a splice's other end; `kernel/mm`: `make_private` and `reconcile_mapping` for
  store mappings.
- `kernel/inotify`: `host_unshared`; `kernel/aio` and `kernel/loop`: `IoFlags`, `read_file`/
  `read_file_with`, `write_file`/`write_file_with`, `read_bytes`, `write_bytes`, `write_sync`,
  `vectored`/`vectored_with`, `fsync`, `has_fsync`, `seekable`, `append_offset`; `kernel/fuse`:
  `check_fsize`, `fsize_room`, `PosGuard` and `truncating`; core dumps (`write_at`).

### Outbound

- `kernel/files`: `FdTable`, `OpenFile` (`pos_busy`, `cow`, `retired`), `FileKind`, `executing`,
  `io_file`.
- `kernel/vfs`: path resolution for `truncate`, mount-flag checks (`readonly`), tmpfs hooks
  (`tmpfs_write_room`, `tmpfs_size`, `tmpfs_resized`), `Device`.
- `kernel/store`: host objects, sharing and unsharing, commits, WAL sync and host filesystem sync.
- `kernel/inotify` (I/O and modify hooks), `kernel/overlay` (`follow_copy_up`), `kernel/locks`
  (`break_leases`), `kernel/pipe` (pipe read/write, `splice_reads`/`splice_writes` for sendfile),
  `kernel/loop` (backing I/O and flush), `kernel/fuse` (FUSE file I/O and fsync).
- `kernel/cgroup` (file-change observation), `kernel/oom` (`recheck` after cgroup `memory.max`
  writes), `kernel/procfs`, `kernel/sysctl`, `kernel/sysfs` (synthetic content regeneration and
  writes), `kernel/tty` (terminal read/write), `kernel/ipc` (mqueue reads), `kernel/poll` (eventfd
  and timerfd reads), `kernel/net` (socket I/O), `kernel/unix` (files in flight for `opens_of`).
- `kernel/mm`: `grow_for` on buffer faults, `writably_maps`, `maps_file` and `file_truncated`.
- Credentials (`permission`, `CAP_FSETID`), signals (`SIGPIPE`, `SIGXFSZ`), `appine_hal` (pread,
  pwrite, poll, lseek, fsync, `copy_file`, fallocate, `sync_file_range`, `cachestat`,
  `fill_random`), and the kernel's wake objects and `Cx::unlocked`.

## Invariants and gotchas

- A path that changes a store regular file's size or pages must call `kernel/vfs`'s tmpfs hooks
  (`tmpfs_size`/`tmpfs_resized`, the write-room check), or usage drifts until the next full count.
- `kernel/aio`'s `has_iter` and `has_fsync` must follow new `FileKind`s and devices.
- A held file's object is shared and must never be written in place: every path that changes a
  regular file calls `prepare_write` (or `make_private`) first, with no borrow of the open file
  held, and takes the host fd only afterwards. A `cow` description's handle is read-only, so a
  path that forgets fails with `EBADF` instead of writing other files' data; a description made
  writable before its file became shared is not `cow` and must be rehomed when it does.
- A description's host handle can be replaced (`rehome`, `follow_copy_up`) while I/O without the
  BKL still uses the old fd number: old handles are kept until the description closes.
- `rehome` skips descriptions borrowed at that moment, and a skipped read-only one would keep
  reading the old object, so no code may hold a borrow of an open file across a BKL release or a
  wait (checking builds assert it).
- Unlocked I/O snapshots the position before releasing the BKL and writes it back afterwards, so
  other code that moves the position must take `pos_busy` (`take_pos`/`release_pos`) or accept
  being overwritten; a rollback moves it back only as far as the read moved it (`give_back`).
- File operations here call `kernel/inotify` hooks where Linux's fsnotify does, passing an overlay
  node's key (`key_of`), and obey `kernel/overlay`'s rule never to mutate a layer's `Node::Store`
  directly.

## Confirmed bugs / technical debt

- Memfd writes and file-backed mappings still require host-representable backing at the target
  offset. The logical-size fallback supplies sparse data to descriptor reads and copies.
- **Clone fidelity:** FICLONE and FICLONERANGE work on a store that reports ext4's magic (ext4
  says `EOPNOTSUPP`); partial ranges are copied, not shared; `FIDEDUPERANGE` is `EOPNOTSUPP`.

## Open questions

- None.
