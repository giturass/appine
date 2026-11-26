# kernel/locks Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/locks.md` for the paired decision history (decisions from before the split are D12, D43 and the lock-range half of D25 in `.agents/decisions/kernel/vfs.md`).
>
> Verified: 2026-11-11 (split out of the kernel/vfs full mapping of 2026-11-10; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: blocked flock waiters and lease acquisition order in `/proc/locks`)

## Responsibilities

`kernel/locks` is advisory file locking and leases (6.1's `fs/locks.c`):

- `flock` locks, one per open file;
- POSIX record locks owned by fd tables and OFD locks owned by open files, in one table: ranges,
  splitting and merging, conflicts, waiting and deadlock detection;
- leases and their breaks on conflicting opens and truncation;
- the lock listings of `/proc/locks` and fdinfo.

Root: `core/kernel/src/locks.rs`, `syscall/lease.rs`, and in `syscall/fs.rs` `flock` and the
fcntl lock commands (`record_lock`).

Outside the module: closing fds and open files, which call `locks::closed`, and opens calling
`break_leases` (`kernel/files`), plus truncations calling `break_leases` (`kernel/fileio`); the lock keys of overlay and FUSE nodes
(`lock_ino`, `kernel/files`); owners and the signals a lease break sends (`kernel/files`'
`F_SETOWN`, `kernel/signal`); the procfs files that show the listings (`kernel/procfs`).

## Key types

- `Locks` (owners `Posix(Weak<FdTable>)` or `Ofd(Weak<OpenFile>)`, taking `file: Weak<OpenFile>`,
  ranges, taker's pid, acquisition `seq`, per-thread `Waiter`s keyed by `tid`).
- `Flocks` stores `FlockHolder`s with acquisition sequence numbers and per-thread `FlockWaiter`s
  with the requested mode, a weak open file reference and the requester's tgid.
- `Kernel::leases` registers each `Lease` by inode. A lease keeps its setter's pid and acquisition
  sequence number across type changes.
- `Flocks` and the record-lock table use the same `LockKey` for filesystem nodes, pipes, sockets and devpts inodes.
- `FdTable::holds_locks`, and lock ownership in `OpenFile` (`kernel/files`).

## Public entry points

- **Syscalls**: `flock`, fcntl lock commands (`F_GETLK`, `F_SETLK`, `F_SETLKW` and their OFD
  forms), `F_SETLEASE`/`F_GETLEASE`.
- **Kernel-internal**: `locks::closed` (every close path), `lease::break_leases` (opens and
  truncation); `locks::proc_locks`, `locks::fd_locks` (for `kernel/procfs`).

## Data flow / lifecycle

### Locks and leases

- All in-process. Locks key on the store inode (bind mounts share them), on an overlay node with
  the top bit set, or on a FUSE node's key (top two bits; `OpenFile::lock_ino`), the daemon never
  asked; leases key on `lease::key_of` — the overlay node's key (`overlay::key`) for overlay
  regular files so leases survive copy-up and break before copy-up on write opens and truncations,
  or the store inode otherwise (FUSE files `EINVAL`). The host
  `flock` is used only by the store itself. `flock` and fcntl locks are separate tables.
- The ends of an anonymous pipe share one pipefs lock key. A socket has its own sockfs key.
  PTYs opened through a store or overlay device node use that node's lock key. Direct devpts
  opens key on the instance and inode, so independent opens of its ptmx conflict, as do
  independent opens of the same slave. Named FIFOs keep their filesystem keys.
- `flock`: each open file owns its lock, including through dup or fork. Conversion drops the old
  mode before trying the new one, including on `LOCK_NB` failure (`EAGAIN`). Unlock or the last
  close releases the lock. Dead holders and keys are swept as the table grows. On an `O_PATH` fd
  flock is `EBADF`. A blocking request registers its thread while waiting and clears the waiter
  on acquisition, interruption or a wait error.
- POSIX locks belong to the fd table and go with any close of the file in that table (close,
  close_range, dup2 replacement, close-on-exec, seccomp addfd); OFD locks belong to the open file;
  both kinds share one table and conflict. Ranges follow `flock64_to_posix_lock`: a start past
  `OFFSET_MAX` `EOVERFLOW`, below 0 `EINVAL`; a positive length may end at `OFFSET_MAX`
  (`EOVERFLOW` past it), 0 means to the end and beyond, a negative one covers the bytes before the
  start (`EINVAL` below 0). Ranges split and merge; `F_SETLKW` detects deadlocks for POSIX requests
  only (`EDEADLK`; the chain may pass through OFD waiters, which Linux excludes) and waits on the
  lock channel. Closing an `O_PATH` descriptor preserves POSIX locks. Files without a lock key
  (for example eventfds) still succeed silently and `F_GETLK` reports unlocked. The record-lock
  table reclaims dead owners across keys as it grows.
- Clone without `CLONE_FILES` copies the slots and resets `holds_locks`; a copied table (also from
  unshare, execve or `CLOSE_RANGE_UNSHARE`) is a new owner of POSIX locks, so an unshared table
  keeps its locks. The last reference to an open file wakes lock waiters when it held locks.
- Leases (regular files, owner or `CAP_LEASE`): read leases need no writers, write leases no
  other opens. Opening for write or truncating breaks all leases, opening for read breaks write
  leases: the file's owner gets `F_SETSIG`'s signal or `SIGIO` (setting a lease makes the setter
  owner unless one exists, `lease_setup`); a nonblocking open is `EAGAIN`, others wait until the
  holder downgrades or `lease-break-time` (45 s) forces it. `F_NOTIFY` (dnotify) is `EINVAL`.

### Listings

- Listing (6.1's `lock_get_status`): `/proc/locks` lists every flock, POSIX and OFD lock and lease
  newest first by a shared acquisition sequence as
  `FLOCK  ADVISORY  `, `POSIX  ADVISORY  `, `OFDLCK ADVISORY  ` or
  `LEASE  ACTIVE    `/`LEASE  BREAKING  `, the type (a lease being broken shows its target type),
  the taker's pid (the caller's tgid at flock, F_SETLK or F_SETLEASE; -1 for OFD locks), the device
  and inode fstat shows through the holding open file (the shown inode on overlayfs, the cached
  inode on FUSE, the pipefs inode for an anonymous pipe, sockfs or PTY fstat identity for those
  files), and the range with an inclusive end (`EOF` from `OFFSET_MAX`) or `0 EOF`, with blocked
  `flock`, `F_SETLKW` and `F_OFD_SETLKW` waiters immediately below their first conflicting live
  lock (`<pos>: -> ...`, omitted when either the blocker or waiter is invisible in the reader's
  pid namespace).
  `/proc/locks` numbers lines by position, omitting entries without a shown identity without
  advancing the count and leaving out (numbers included) locks whose pid the reader's procfs cannot
  see; fdinfo numbers from 1 (in per-inode order: flock, POSIX/OFD, lease) the held locks taken
  through that open file (`fl_file`, matching Linux's `show_fd_locks`).

## Dependencies (inbound / outbound)

### Inbound

- `kernel/files`: fcntl's dispatch, every close path (`locks::closed`), opens (`break_leases`),
  the last reference to an open file; `kernel/fileio`: truncation (`break_leases`).
- `kernel/procfs`: `/proc/locks` and fdinfo `lock:` lines; `kernel/sysctl`: the `lease-break-time`
  sysctl.
- `kernel/overlay` and `kernel/fuse`: the nodes whose keys locks use.

### Outbound

- `kernel/files`: fd tables, open files, `lock_ino`, the file's owner for lease-break signals.
- `kernel/process` (the lock wake channel and waits), `kernel/signal` (`SIGIO` and `F_SETSIG`
  signals), `kernel/cred` (`CAP_LEASE`, ownership), `kernel/ns` (pids the reader can see).

## Invariants and gotchas

- Locks and leases are keyed by inode and live in one kernel; other kernels and the host do not
  see them.
- A lease-break wait keeps the opener's looked-up node; this is safe for overlay nodes only
  because an open is outside `waits_on_files_only` (`kernel/overlay`).

## Confirmed bugs / technical debt

- None recorded.

## Open questions

- None recorded.

## To verify

- The full mapping's Linux 6.1 comparisons still need source verification outside flock waiter
  conflicts and in-place lease type changes.
