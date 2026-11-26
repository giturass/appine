# kernel/store Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/store.md` for the paired decision history.
>
> Verified: 2026-11-26 (namespace and cache, object sharing and lifetimes, transaction and recovery ordering, import and provider authorization checked against the store and its callers)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: WAL sync and transaction ordering during exclusive boot cleanup)

## Responsibilities

`kernel/store` is the guest root filesystem's backing store, the "inode store": an SQLite database
holding the whole namespace and non-data metadata, plus one host file per regular file. It
provides:

- namespace and metadata operations (lookup, stat, create, link, unlink, rename, xattrs, times,
  tmpfs trees, memfd-style anonymous files);
- regular files sharing one object until one of them is changed (the whole-file reflink behind
  FICLONE, copy_file_range and overlay copy-up);
- atomic operations, deferred commits, and power-loss ordering that mimics ext4;
- an in-memory metadata cache readable without the BKL;
- sharing one store between the kernel and host-side callers (the app's DocumentsProvider);
- importing a rootfs tarball, and a path-based browse API for the host.

Root: `core/kernel/src/vfs/store.rs`, `vfs/import.rs`, `vfs/browse.rs`, and the host wrappers in
`core/kernel/src/lib.rs` (`import_rootfs`, `sync_store`, `browse`, `browse_changing`,
`write_file`, `read_file`).

Outside the module: path resolution, the no-BKL resolver and namespace and metadata syscalls
(`kernel/vfs`), opening host objects/memfds (`kernel/files`), file I/O and moving open files to an unshared object (`kernel/fileio`), mounts
(`kernel/mount`),
synthetic filesystems (`kernel/procfs`), the BKL and fast path (`kernel/process`), the Android
provider and rootfs installation UI (`android`).

## Key types

- `Store` — one SQLite connection with transaction state: pending deferred transaction, `writing`
  flag, `doomed` objects to delete after commit, `replaced` files to flush before commit, `created`
  objects to unlink on savepoint rollback, the waker, the read-snapshot state, the owning kernel
  id, changed directories, cached `store_id` (`objects/` dev/ino), `writable_maps` (inodes
  excluded from `relatime` caching because they may be mutated via writable shared mappings),
  `pending_release` (deleted held regular files awaiting release once closed/unmapped),
  and linkable tmpfile state with its transaction undo log.
- `Meta` — state shared with readers and the reaper thread: the cache behind an `RwLock`, the
  commit counter, the reaper queue, the WAL path and durability watermark.
- `Stat` includes the store inode’s access and default ACLs; `DirEntry`, `FileTime` (`Now` or `At(ns)`), the `mode` constants; `Ino = u64`, `ROOT = 1`.
- `Commits` — 32 bytes of the `lock` file mapped shared: commit counter, packed connection state
  (active open connections in the low 32 bits, monotonic open epoch in the high 32 bits), and the
  range of inode numbers allocated by uncommitted transactions.
- `Cache` — dentries (including negative entries), database rows with where each regular file's
  data and times are (`Data`: object number, held timestamp and guest atime),
  symlink targets, `..` parents, names (for getcwd), directory listings, the set of inodes with
  file capabilities, and `relatime_fresh` (plus a 1-entry `last_relatime` fast slot) caching
  inodes whose guest atime is strictly newer than mtime and ctime for the current connection state.
- `Unshare` — a held file's private copy in the making: the shared object open for reading, the
  new one open for writing, the length to copy, and both numbers.
- `Fill` — an entry created by an operation, inserted into the cache only if the operation
  succeeds (at most 64 per operation).
- `Op` — savepoint guard; rolls back, discards fills, truncates `replaced`, and unlinks `created`
  objects on failure or unwinding.
- `Reader` — a read-locked view of the cache for threads without the BKL.
- `Reaper` — the background thread that deletes objects and checkpoints the WAL.
- `ImportReport`; `browse::Change` (created, removed, moved, opened, written), `browse::Entry`.

## Public entry points

- **Lifecycle**: `Store::create(dir)` (new store, `EEXIST` if one exists), `Store::open(dir,
  volatile)`, `Drop` (final commit, reaper join), `guard_with_bkl`.
- **Reads**: `lookup`, `name_of`, `stat`, `stat_open`, `attrs`, `kind`, `readlink`, `parent`,
  `tree_root`, `readdir`, xattr reads, `has_file_caps`, `fs_stats`; `snapshot` (one read transaction);
  `Meta::reader` (no-BKL).
- **Objects**: `open_object`, `open_object_append`, `truncate` (each makes a held file private
  first when it writes), `copy_object` (data with holes).
- **Shared objects**: `share`, `held`, `unshare` with `finish_unshare` or `abandon_unshare` (the
  copy in between is the caller's, so the kernel can release the BKL), `make_private` (all three
  in one, the BKL held), `release`.
- **Changes**: `mkdir`, `create_file`, `create_anonymous`, `create_tmpfile`, `release_tmpfile`, `symlink`, `mknod`, `link`, `unlink`,
  `rmdir`, `rename` (no-replace, exchange), `create_detached_dir`/`remove_detached_dir`,
  `set_mode`, `set_owner`, `set_owner_mode`, `set_flags`/`set_flags_open`, `remove_privs`, xattr writes, `set_mtime`,
  `set_times`, `set_times_open`, `accessed`, `object_modified`; `transaction`.
- **Durability**: `commit`, `commit_due`, `set_waker`, `Meta::sync_metadata`, `Meta::sync_all`.
- **Host-facing**: `import_rootfs`, `sync_store`, `browse` (stat, list, open, text sniffing,
  search), `browse_changing` (create, import a file, remove, rename, move, open for writing, written),
  `take_changed_dirs`.

## Data flow / lifecycle

### On-disk layout and schema

- A store directory holds `meta.db` (SQLite, WAL mode), `objects/` and `lock`.
- Tables: `inodes` (mode, owner, nlink, `..` parent for directories, rdev, mtime/ctime/atime,
  inode flags migrated on open, symlink targets), `dentries` (indexed on `ino` via `dentries_ino`), `xattrs`, `detached_roots` (tmpfs roots and file-import staging directories),
  `shared` (regular files whose data is not plainly their own object: the object's number and a saved timestamp marking it held),
  and `document_generations` (retired document names with a unique parent/name index).
  The `shared` table also has an index on object. Tables and indexes are created with `IF NOT EXISTS`, so
  older stores gain `shared`, `dentries_ino` and `inodes.flags` when opened.
- Pragmas: `journal_mode = WAL`, `synchronous = NORMAL`, `journal_size_limit = 8 MB`, a 10 s busy
  timeout, a statement cache.
- `Store::create` writes the root directory (0755, its own parent).

### Objects and metadata ownership

- Each regular file's data is `objects/<ino>` (mode 0600), or the object `shared` names for it,
  always opened by number relative to an `O_PATH` directory fd, never by path. Directories,
  symlinks, device nodes, FIFOs and sockets exist only in the database.
- Unshared regular files take size, mtime, ctime and the allocated block count (`Stat::blocks`, so
  holes take no storage) from the host object; a metadata change to a
  regular file chmods the object back to 0600 so the host bumps its ctime (one clock per file); the
  database ctime column is reported only while the file is held. Time changes use
  the host's `utimensat` on the object by number, except an empty-path change on a (non-`O_PATH`)
  regular-file fd, which uses `futimens`.
- Guest atime lives in `inodes.atime_ns`. On older stores, unshared objects retain their host atime
  until first opened. The upgrade copies held times from `shared`. Other inodes start from row mtime.
  Regular-file creation and subsequent access use the backing filesystem clock. An access
  updates only guest atime. Under `relatime`, once an inode's atime is verified strictly newer than
  both mtime and ctime, warm reads skip SQLite and host `fstat` while within the 24-hour window;
  directories and held regular files also skip host `fstat` on a miss because their timestamps live
  in SQLite. Other inode types keep all three timestamps in the database.
  Symlinks report the target length as size and mode 0777.
- Reads and writes go straight to the host fd (`pread`/`pwrite`); copies between two regular files
  use the host's `sendfile`.

### Shared objects

- `share(src, dst)` makes `dst` use `src`'s object, in one operation: a source not yet held moves
  its mtime and ctime into its row and initializes the held record with its guest atime; the
  destination keeps its access time, its modification and change times become now, and its old
  object is doomed when no row uses it. Both rows are then held. A deleted source is `ENOENT` (its
  object may already be queued for the reaper). The caller guarantees nothing writes the source's
  object in place and nothing maps the destination.
- A held file reports its own times from the database and its size and blocks from the shared object.
  For a current timestamp the store touches the host `objects/` directory and reads its ctime. This
  keeps regular files on the filesystem clock through copy-up and leaves other sharers' times intact.
- `unshare(ino, keep)` before a held file changes: when no other row uses its object, the file
  settles in place (the object's atime and mtime set from the database, the row deleted when the
  object is its own number, else its held marker cleared) and nothing is returned; otherwise an
  inode row with no links is inserted only to number a new empty object, returned with the length
  to copy (all, or what a truncation keeps). `finish_unshare` then points the row at the new object,
  settles its times, dooms the old object if unused and queues the file in `replaced`, so its data
  is flushed before the commit that records it; it is `EAGAIN` (the copy removed) when the row no
  longer uses the object it was copied from. `make_private` loops over the three with the copy done
  in place.
- `open_object` for writing, `open_object_append` and `truncate` call `make_private` first, so host
  callers (the browse API, `write_file`) never write a shared object. When a Files app open
  unshares the file, its change replay (also on failure after publication) refreshes the file's open
  descriptions to its current object. Private and shared store mmaps hold a flock on their backing descriptor.
  `mapping_object` acquires it under the store write transaction, and `try_share` probes both
  objects in that transaction, falling back to a byte copy when a pin exists. Provider write
  opens also pin their descriptor. Provider truncation clips live guest mappings before shrink.
- Objects the provider handed out for writing are recorded process-wide (`HOST_WRITERS`: the
  store's identity, the object, the path it was opened by) from `open_write` until `written`
  reports the close by the same path, whatever became of the file; `host_writing` tells the kernel
  not to share such an object with another file, as the provider's writes would reach both. A
  close that is never reported keeps its object out of sharing (only copies are made).

### Namespace operations

- Every operation is atomic. Hardlinks are several dentries for one inode (directories cannot be
  linked, `EPERM`). A zero-link inode gives `ENOENT` except for the first link of an
  `O_TMPFILE` created without `O_EXCL`. Its object survives until that link or its final reference.
  Rolling back the operation or commit also restores linkability.
- Errors: `EEXIST` (name taken, no-replace rename, `XATTR_CREATE`), `ENOTDIR`, `ENOENT` (missing name,
  creating inside a deleted directory), `EISDIR` (unlink of a directory), `EBUSY` (rmdir of root),
  `ENOTEMPTY`, `EINVAL` (moving a directory under itself), `ENODATA` (missing xattr); SQLite errors
  become `EIO`. Cross-device checks belong to the syscall layer.
- Inode numbers are allocated by SQLite (`max(rowid) + 1`, no AUTOINCREMENT); a leftover object
  under a reused number is truncated and reused.
- Removing a regular file's last link leaves the row with nlink 0 and queues the object for deletion
  after commit when no other row uses it (open host fds keep working); a held file instead keeps
  its row in `shared` and records its inode in `pending_release` until `release` (called by the
  kernel on unlink/rename when already closed, on post-syscall/thread-exit/`execve` sweeps once
  its last open fd, mapping or executable reference closes, and before `make_private`) or the next
  boot, so remaining sharers settle in place on their next write instead of copying. rmdir likewise
  leaves an nlink-0 row. Rows stay until
  the next boot cleanup, so numbers are not reused while the store runs; after boot, numbers above
  the highest surviving row (and numbers of rolled-back inserts) are reused.
- tmpfs trees and file-import staging directories are detached directories (their own parent) recorded in
  `detached_roots`; their files are ordinary objects.
- `create_anonymous` (memfd) creates an nlink-0 row owned by the given ids (`memfd_create` passes
  the caller's fsuid and fsgid) and an object that is unlinked at once, so only the returned fd
  holds the data.

### Transactions and deferred commits

- The first write opens `BEGIN IMMEDIATE`; each operation runs in a `SAVEPOINT` (single statements
  run without one; nested operations join the enclosing one). Failure or a kernel-layer panic rolls
  back only that savepoint.
- The transaction is committed at most 5 ms later: at the end of an operation if it is overdue, or by
  the timer thread through `commit_due` (signalled via the waker). It is committed immediately when
  another connection is open (`users > 1`), and by guest fsync/sync, `Machine::sync`, `trim_memory`,
  and machine/store teardown.
- A failed `COMMIT` rolls back the whole transaction, clears the cache and removes the objects
  created by it; every deferred operation in it is lost.
- After a successful commit the uncommitted-inode range is cleared, the commit counter bumped, and
  doomed objects handed to the reaper.

### Power-loss ordering

- Commits write WAL frames without syncing; the WAL and objects reach disk independently. Three
  orderings mimic ext4 (`data=ordered`, `auto_da_alloc`):
  - `fsync`/`fdatasync`: sync a regular file's object (BKL released; directories skip this, host
    fds return 0), commit (BKL held), then sync the WAL (BKL released); `sync`/`syncfs`: commit,
    then `syncfs` the host filesystem; synchronous writes (`O_SYNC`/`O_DSYNC` files, `pwritev2`
    with `RWF_SYNC`/`RWF_DSYNC`) sync the object only;
    `Machine::sync` and `trim_memory` only commit (protection against being killed, not against
    power loss).
  - A regular file renamed over an existing name (not exchanges, not symlinks) has its data
    flushed before the commit containing the rename (`sync_file_range` + `fdatasync` per file, or
    one `syncfs` beyond 16 files), done inside the commit with the BKL held; errors are only logged
    and the first `fdatasync` error skips the remaining files.
  - The background reaper and inline fallback delete doomed objects only after the commit that
    made them unused is durable. `Meta::sync_metadata` skips the WAL flush if there have
    been no commits since the last sync. If syncing still fails at teardown, the objects and
    their nlink-0 rows survive for boot cleanup.
  - A held file's private copy is flushed before the commit that points it there, through the same
    `replaced` list as a rename-over.
- New regular files' objects exist immediately; the `lock` header records the uncommitted inode
  range so the next exclusive open can delete objects without rows. On a different host boot
  (or first use with no boot marker), recovery compares the numbered objects with the database,
  including shared-object references. It syncs the WAL before deleting unused objects and
  records the boot token after the scan. If the host hides its boot ID, each process uses its
  own token. The original 32-byte shared header stays at the front of the lock file.

### Reaper and checkpoints

- Each store connection, including a short-lived host connection, starts and joins its own reaper.
  A failed WAL sync leaves the objects queued. The retry delay doubles from 50 ms to 1 s.
  A successful external `Meta::sync_metadata` or `Meta::sync_all` wakes a pending retry immediately.
  On shutdown the reaper bypasses the delay and exits if the final sync fails. When unlinking an
  object it pins the host inode with `O_PATH` across `unlink_at` and clears any `kernel/hostmem`
  `WRITABLY_SHARED` tracking after a successful unlink.
- Checkpoints continue during backoff. The reaper lazily opens a separate connection for PASSIVE
  checkpoints when the WAL grows 1000 pages since the last request, or after 100 ms without commits
  if at least 1000 pages remain in the WAL and some frames still need backfilling. At 10,000 pages
  the committing thread checkpoints in place. If the reaper thread could not start, SQLite keeps
  its auto-checkpoint and the store retries `inline_pending` deletions on later commits and at
  shutdown.

### Opening and boot cleanup

- Every connection takes a shared `flock` on `lock`. If it can get the lock exclusively (nobody else
  has the store open), it resets `users`, reconciles objects when the boot token changes, removes
  objects in the recorded uncommitted range that have no row, and syncs the previous run's WAL.
- In one transaction it empties the volatile directories (the kernel passes `/dev/shm` and `/run`,
  host-side openers pass none), removes detached trees, then drops the `shared` rows of deleted
  files. It removes nlink-0 rows whose numbers no remaining share uses, their objects, and any
  formerly shared objects that no live file needs. It strips the removed numbers from the doomed
  list before the transaction can commit, even when cleanup exceeds the commit delay.
- After committing, it downgrades to a shared lock and increments `users`. If others are open it
  waits (`BEGIN IMMEDIATE; COMMIT`) for their deferred transaction.

### Metadata cache

- Caches dentries (including names that do not exist), database rows (with the `shared` row
  joined in), symlink targets, `..` parents, names, directory listings, the file-capability set, and
  `relatime_fresh` (with a 1-entry `last_relatime` fast slot). The row caches decoded POSIX ACLs. Other xattr values, emptiness checks
  and regular-file sizes and mtime/ctime are not cached.
- `relatime_fresh` records an inode's `atime_ns` only when `atime > mtime && atime > ctime`, no
  other connection is open (`active_users <= 1`), no Files app writer is open on this store
  (`HOST_WRITERS`), and the inode has no `writable_maps` mark. Writable mapping opens, memfds,
  and exclusive tmpfiles set that mark. Inode mutations (`touch_ino`), direct host-object modifications
  (`object_modified` from writes, truncates, fallocate, copies, and mtime-only `set_times`),
  foreign commits, or any other connection joining the store (via the open epoch packed into word 1
  of `lock`) invalidate cached `relatime` entries.
- Reads hit the cache first; on a miss the database is queried and the result inserted only if the
  commit counter did not move. Inside a `snapshot` all misses share one lazily started read
  transaction (path walks and the following stat).
- Writes invalidate the affected entries as they happen (names and listings of the directory; the
  row, target and parent of the inode); entries created by a successful operation are inserted
  afterwards (fills are discarded on rollback). There is no eviction: after 131,072 fills the whole
  cache is cleared.
- The cache is labelled with the commit count it matches. A commit by this connection advances the
  label; any other change of the shared counter (another connection's commit) clears everything,
  checked lazily on each query, reader and commit. A failed commit clears it too.
- Only the BKL-holding thread mutates the cache, under the write lock. Threads without the BKL use
  `Meta::reader` (read lock), which refuses when the counter moved; the no-BKL resolver falls back
  to the BKL path on any miss. Regular-file stats in a reader query the host while holding the lock.

### Sharing the store

- Connections, not processes, are counted in `users`. The kernel and the app's DocumentsProvider run
  in the same process; each host call (`browse`, `browse_changing`, `write_file`, `read_file`) opens
  its own connection. An Android import opens this connection for local publication after staging provider data. While multiple
  connections are open, every operation commits immediately. A count leaked by a crash can only persist while another process holds the shared lock (e.g. several
  `appine-run` processes on one store), so on Android the next open is exclusive and resets it.
- Changes recorded by `browse_changing`, including changes completed before an error, are replayed
  to running kernels of the same store in this process
  (found in the machine's registry), under their BKL, as inotify events. Directories the guest
  changes are recorded (up to 256 per poll, starting from the first poll) and handed to the
  provider through `Machine::take_changed_dirs`, which maps them to paths (deleted and tmpfs
  directories drop out).

### Import

- `import_rootfs` creates a new store and imports a gzip-compressed tar together with the device
  and mount-point skeleton (`/proc`, `/sys`, `/run`, `/dev`) in one `Store::transaction` (so a
  failure in either rolls back the whole import and unlinks created objects): paths are normalised
  (`..` is `EINVAL`), missing parents created as 0755 root, directories' attributes applied (also
  onto an existing non-directory of that name) and their mtimes set last; files, symlinks,
  hardlinks (to earlier entries, retaining their metadata), device nodes and FIFOs are created with their mode bits (setuid
  included), numeric owner and whole-second mtime; a non-directory entry whose name already exists
  aborts with `EEXIST`; PAX `SCHILY.xattr.*` extended attributes in supported namespaces
  (`security.*` including validated v2/v3 `security.capability`, `trusted.*`, `user.*` on regular
  files and directories, and validated POSIX ACLs under `system.*`) are preserved, while
  unsupported/invalid xattrs and other PAX metadata are skipped. Whiteout names follow their tar entry type. Afterwards the host
  calls `sync_store` (host `syncfs`). The Android caller imports into
  a temporary store directory that is discarded before a retry.

### Browse API

- Paths resolve like `realpath` inside the guest tree (links followed, at most 40). Only directories
  and regular files are visible; mounts are not.
- Reads accept any guest path. Text sniffing reads the first 4 KB. The Android caller limits each batch to
  1000 files and caps search at 50,000 entries.
- Provider writes require an absolute, NUL-free `top`. The kernel resolves symlinks and accepts
  directories at or below `/root` or `/home/<user>`. A regular `/etc/passwd` can also authorize
  a directory at or below a resolved, absolute home for UID 1000 or higher. Empty shells,
  `/sbin/nologin`, `/usr/sbin/nologin`, and `false` under `/bin`, `/usr/bin` or `/sbin` do
  not qualify. The filesystem root, `/home` itself, and trees under `bin`, `sbin`, `usr`, `lib`,
  `lib64`, `etc`, `proc`, `sys`, `dev`, `run`, `boot`, `var`, `tmp`, `opt`, `srv`, `mnt`,
  `media` and `lost+found` are denied even if an account names them. Denial is `EACCES`.
  A missing path returns `ENOENT` and a non-directory returns `ENOTDIR`.
- Create, import, remove, rename, move and writable open check the real target or its parent
  against the authorized top within the mutation transaction. Removal and moves preserve the
  top itself. Create numbers name collisions and moves refuse to overwrite an existing entry.
  Tree removal is atomic. Provider writes skip guest permission checks and
  preserve setuid/setgid. A writable open clears file capabilities in the transaction that pins
  the object, before truncation or fd handoff. Subsequent host writes use the returned description directly.
- Removing or moving a source entry retires its document IDs atomically with the namespace change.
  `document_generations` reads one SQLite snapshot per batch, looking up the newest retired
  (parent inode, name) along the resolved path, including symlinks and their targets.
- `import_file` creates a file in a detached directory and commits before calling its writer.
  The store stays open during the copy and holds no SQLite writer lock. After syncing the object,
  it checks that the account's home still resolves to the original directory, renames the file
  there without replacement (numbering collisions as in `create`), and retires the staging
  directory in one transaction. Only a committed import reports `Created`, `Opened` and `Written`.
  Errors clean up the staging tree, and boot reclaims one abandoned by process death.
- A provider write reports `Opened`, writes the object directly, and reports `Written` on close if
  the path still resolves within the authorized tree (`IN_MODIFY`, `IN_CLOSE_WRITE` in the guest).
  Close clears the host-writer record before revalidating the path.
- Host configuration reads and writes accept absolute, NUL-free paths without `..` components.
  Components over 255 bytes return `ENAMETOOLONG`. Validation precedes directory creation.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/vfs` (path walks, namespace and metadata syscalls, tmpfs instances, the no-BKL
  resolver), `kernel/files` (opening objects and memfds), `kernel/fileio` (sharing, unsharing and
  syncs), `kernel/mount`
  (`Vfs::open`'s boot with the volatile list), `kernel/process` (`syscall::fast`), the machine
  (waker, timer `commit_due`, `sync`, `trim_memory`, teardown, the store registry,
  `take_changed_dirs`), `kernel/inotify` (`host_change`), host wrappers in `lib.rs` (JNI and
  `appine-run`).

### Outbound

- rusqlite with bundled SQLite (WAL hook, checkpoints); `appine_hal` (`open_at`, `stat_at`,
  `chmod_at`, `unlink_at`, times, `flock`, `map_file`, `fsync`, `syncfs`, `sync_file_range`,
  `statvfs`); the `tar` and `flate2` crates; `kernel::bkl_holder`; `bug::catch` (`kernel/bug`);
  `mm::forget_writably_shared` (`kernel/hostmem`).

## Invariants and gotchas

- The commit counter is bumped only after `COMMIT` succeeds; the reaper and the cache both rely on
  this ordering.
- Cache contents always describe the database at the commit count they are labelled with; fills
  whose query raced a commit are dropped.
- Only the thread holding the owning kernel's BKL may use a kernel's `Store` (checked in debug and
  `borrow-check` builds).
- Objects are always addressed by inode number, never by guest path.
- Committed inode numbers are reused only after boot cleanup has deleted their rows. Boot cleanup therefore
  deletes those objects itself and must hand none of their numbers to the reaper, which unlinks
  `objects/<ino>` without checking whose it is; the boot-cleanup debt below records a violation.
- A number some `shared` row uses as its object keeps its inode row (live, deleted, or one that only
  numbers a copy) at boot, so no new file gets it while the object lives.
- When two or more rows use one object, every one of them is held, and nothing may write that
  object in place; a row never just repeats a plain file (object its own number, not held).
- A number becomes a shared object only along with a `shared` row for its own file, so a plain
  file's object is never used by another row.
- A crash that leaves `users` too high disables deferred commits until the next exclusive open.

- A failed `COMMIT` loses every deferred operation already reported as successful (the documented
  cost of deferral; only host I/O errors or a full disk trigger it).
- Cached directory listings are not invalidated by chmod/chown, so their permission bits can be
  stale; every current caller uses only the file-type bits.

## Confirmed bugs / technical debt

- If boot cleanup rolls back or loses its commit after unlinking a host object, SQLite can restore
  the volatile dentry that pointed to it. An opener that omits that volatile directory can then
  see the name with its object missing.
- **Whole-file sharing:** the first change to a file sharing its object copies all of it, where
  btrfs and XFS copy only the extents written.


## Open questions

- None.

## To verify

- The crash test covers ext4 hosts only; whether a durable commit implies a durable object dentry on
  f2fs (common on phones) is not checked.
