# kernel/fuse Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/fuse.md` for the paired decision history.
>
> Verified: 2026-11-09 (full mapping: 3 research concerns; 14 claims checked by 2 independent verifiers — 10 confirmed and 4 partial, all corrected below; the bugs the research and verification found (umount races, parent loops, program copies, interrupts, oversized requests, open ENOSYS, clone ioctl, subtypes, xattr rules, link order, appends, mmap errors) fixed before this line)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's page cache, shared-mapping writeback, directory locks and batched lookups merged with the retained host shared-storage server, whose replies now complete through `Conn::answer`)

## Responsibilities

`kernel/fuse` implements the FUSE connection and file-operation machinery, following Linux 6.1's
`fs/fuse` for guest daemons (sshfs, rclone mount, fuse-overlayfs and libfuse programs) served through
`/dev/fuse`, and using the same machinery for an in-process host shared-storage server. It provides:

- the connection (`Conn`): mount options, `FUSE_INIT` negotiation, the request queue, requests in
  Linux's wire format matched with replies by `unique`, interrupts, notifications, and aborting;
- the `/dev/fuse` device file: attaching to a connection, read, write, readv/writev, splice, poll
  and the clone ioctl;
- a cache of what the server said about nodes, names, attributes and links (`Fuses`), which path
  resolution reads under the BKL, and the retry that fetches what it lacks;
- the file syscalls on FUSE nodes and open FUSE files: open and create, reads and writes,
  directory listing, namespace changes, attribute and xattr changes, statfs, access, fsync,
  fallocate, flushing and releasing, demand reads and writeback for shared mappings, and
  program snapshots for execve;
- forgetting nodes nothing uses (`FUSE_FORGET`);
- descriptor-anchored host shared-storage operations with Android's host permissions.

Root: `core/kernel/src/vfs/fuse.rs` (connection, device, cache, retries, request helpers),
`core/kernel/src/vfs/fuse/host.rs` (the host server) and `core/kernel/src/syscall/fuse.rs`
(the file syscalls on FUSE nodes).

Outside the module: the walker, mount table, fd tables and the dispatch of every file syscall
(`kernel/vfs`, `kernel/files` and `kernel/fileio`, which hand FUSE nodes and files to this module), the syscall
dispatcher's retry loop (`kernel/process`), execve (`kernel/exec`), poll and epoll (`kernel/poll`),
the VMAs and host backing for mapped data (`kernel/mm`), mountinfo (`kernel/procfs`).

## Key types

- `Conn` (`Rc<RefCell<Conn>>`) — one connection (Linux's `fuse_conn` with its input queue): the
  instance's device number and `Options`, the mounter's user and pid namespaces, the INIT state
  (waiting, ready, refused), `aborted`, what INIT negotiated (`minor`, accepted `flags`,
  `max_write`, `max_read`), `no` (operations the daemon answered ENOSYS to), the number of attached
  device files, the next `unique` (even, from 2), the queues `pending` and `interrupts` plus
  `requests` by unique, the `forgets` to send with Linux's `forget_batch`, `opens`, the open
  handles of each node id, `doomed`, the node ids marked for prompt forgetting (either kept at
  `drop_caches` only for a release in flight, or whose last link was removed through the mount),
  `rename_busy`, which serializes cross-directory directory moves on the instance, and an
  optional `Arc<host::Host>` (`host`) when served in process.
- `Req` — the whole message, its state (`Pending` until read or host dispatch, `Sent` until answered, `Done` with
  the reply or error), whether nobody waits for it (`background`: INIT, RELEASE, periodic
  writeback), optional `BgWriteback` RAII guard (clearing `FillPages::bg_busy` on drop), and
  whether its caller was interrupted.
- `Options` — `fd`, `rootmode`, `user_id`/`group_id` (kernel IDs), `default_permissions`,
  `allow_other`, `max_read`, `subtype`.
- `DevFile` (`FileKind::FuseDev`) — the connection once attached (None before), the device node it
  was opened through, the opener's user namespace.
- `Fuses` (in `Vfs`) — connections by device number, `Node`s by `FuseId`, the node of each
  (device, daemon node id), a `clock` counting entries, `sweep_at` (the high-water mark above
  which new entries ask for a sweep), and `mapped`/`next_writeback` (tracking mapped nodes for
  periodic dirty-page writeback).
- `FuseId` — a node's number, never reused; `Node::Fuse(MountId, FuseId)` in the VFS. `key(id)` is
  `3 << 62 | id`, its number in tables keyed by inode (locks, inotify watches, a program's inode,
  AF_UNIX path socket bindings).
- `Node` — device and daemon node id, the directory and name it was last found under (a root's
  parent is itself), the last attributes (`Attr`, owners as kernel IDs) with their validity,
  `attr_seen` (whether prior attributes exist for `FUSE_AUTO_INVAL_DATA` comparison) and the
  syscall that fetched them, the directory's cached names (node, or None for a missing name, with
  validity and syscall), a symlink target read in this syscall, `nlookup` (entries the daemon
  returned for it) and `seen` (the clock when last entered). It also holds `io_busy` (serializing
  fills, writeback, writes and size changes), `dir_busy`/`dir_waiters` (serializing
  directory-modifying operations and keeping waited directories pinned against eviction), a weak
  reference to live mapped pages, a weak reference (`sock_pin`) pinning bound AF_UNIX sockets
  against eviction, and a pinned writable mapping if teardown writeback needs a retry.
- `Entry` — a `fuse_entry_out`: node id (0 for a missing name), attributes, both validities.
- `Query` — what a walk lacked: `Lookup`, `LookupWalk` (batching consecutive uncached plain
  components in one retry), `Getattr` (with optional open file handle), `Readlink`, `Program`.
- `Handle` (`FileKind::Fuse`, or a FUSE `Directory`'s `fuse`) — Linux's `fuse_file`: connection,
  node, node id, the daemon's file handle, the `FOPEN_*` flags, the open flags sent,
  directory or not, and `no_release` when no open was made. Every handle is counted in its
  connection's `opens` (`counted`) until dropped.
- `Fill` pins the open file used by a mapping. Its `FillPages` is shared by mappings of the same
  node, including those opened through a hard link or bind mount.
- `SWEEP`, `DROP` — atomics asking for a sweep of the node cache at the end of a syscall, and for
  dropping every unused node (`drop_caches`).
- `Io` (syscall side) — a copy of a handle's fields, taken so no borrow is held while waiting.
- `SetAttr` — the fields a `FUSE_SETATTR` sets; times as leave, now, or a value.
- `Errno::FUSE_RETRY` (600) — internal: a walk needs a reply; never returned to the guest.
- `host::Host` / `State` — a mutex-protected host root, O_PATH anchors indexed by host device and
  inode, lookup counts and open file/directory handles; all access runs outside the BKL.

## Public entry points

- Connection and device (`vfs::fuse`): `Options::parse`/`show`, `Conn::new`/`shared_storage`/`allows`/`abort`,
  `send_init`, `call`, `call_as`, `background`, `dev_read`, `dev_write`, `DevFile` (`new`,
  `attach`, `readiness`, `object`), `atomic_o_trunc`, `dont_mask`.
- Cache and retries: `Fuses` (`add`, `remove`, `root_of`, `conn`, `conn_of`, `get`, `node`,
  `cached_child`, `enter`, `enter_negative`, `forget_child`, `moved`, `is_within`, `set_attr`,
  `stale`, `link`, `set_link`, `evict`, `unlinked`, `pin_socket`, `track_mapped`), `token`,
  `new_syscall`, `need`, `serve`, `program`, `lookup`, `getattr`, `getattr_no_inval`,
  `cached_attr`, `cached_attr_fh`, `target`, `key`, `id_of`, `drop_caches`, `flush_dirty`.
- Request helpers: `open`, `read`, `write`, `readdir`, `statfs`, `access`, `getxattr`,
  `lock_owner`, `snapshot`.
- File syscalls (`syscall::fuse`): `open`, `create`, `make`, `remove`, `rename_at`,
  `setattr`, `read`, `write`, `lseek`, `fill_dir`, `fsync`, `fallocate`, `flush`, `flush_all`,
  `flush_at_exit`, `stat`, `stat_fh`, `statfs`, `access`, `may_chdir`, `xattr_permission`,
  `set_xattr`, `parent`, `mkdir`, `mknod`, `bind_socket`, `symlink`, `link`, `unlink`, `truncate`,
  `ftruncate`, `file_io`, `io_of`, `map_fill`, `fill`, `prefault`, `prefault_range`,
  `prefault_iov`, `sweep`, `dev_ioctl`, `seekable`, `checks_permissions`.
- VFS hooks this module relies on: `Vfs::new_fuse`, `add_fuse_mount`, `fuse`/`fuse_mut`,
  `fuse_child`, `fuse_permission`, `type_of`, `mount_nodes`.

## Data flow / lifecycle

### Mounting and the connection

- Opening the node with device number 10:229 (`/dev/fuse`, 0666 in the boot `/dev` and the
  store's) gives a `DevFile` with no connection: read and write are EPERM, poll only `POLLERR`,
  seeking ESPIPE.
- mount(2) of type `fuse` or `fuse.<subtype>` (6.1's `fuse_get_tree`, `fuse_fill_super`): an empty
  subtype, or a `subtype=` option as well, is EINVAL; options as `Options::parse` (the VFS's
  superblock words skipped, unknown options, bad numbers, a type Linux does not know as
  `rootmode`, unmapped IDs and `blksize` EINVAL). An `fd` that is not open is EINVAL. One already
  attached to a connection mounts that instance again while it exists (ENOTCONN otherwise),
  ignoring the values of the other options and needing none of them. Otherwise `rootmode`,
  `user_id` and `group_id` are required and the file must be a `/dev/fuse` opened in the mounter's
  user namespace (EINVAL).
- A new instance gets its own device number, a connection, and a root node (node id 1, the type of
  `rootmode`, attributes not fetched); the device file is attached and `FUSE_INIT` queued
  (7.37, 128 KiB readahead, the offered flags). The mount does not wait for INIT.
- Offered: `ATOMIC_O_TRUNC`, `EXPORT_SUPPORT`, `BIG_WRITES`, `DONT_MASK`, `AUTO_INVAL_DATA`,
  `NO_OPEN_SUPPORT`, `PARALLEL_DIROPS`, `HANDLE_KILLPRIV`, `MAX_PAGES`, `NO_OPENDIR_SUPPORT`
  (libfuse 3.17 ends the session when a filesystem wants an unoffered flag, and fuse-overlayfs
  always wants `DONT_MASK`). Not offered: `ASYNC_READ` (read(2) is not read ahead, and sshfs reads
  ahead itself only when it is not offered), writeback cache, readdirplus, POSIX and flock locks,
  splice (libfuse decides splice by itself).
- The INIT reply: an error or another major version refuses the connection (every request is then
  ECONNREFUSED); otherwise accepted flags are those offered, pages per request 32 (or the reply's
  `max_pages` clamped to 1–256 with `MAX_PAGES`), `max_write` the reply's within one page and that
  many pages, `max_read` the option's within the same bounds. A short reply from an old daemon
  counts its missing fields as 0.
- mountinfo shows the type with its subtype and the options `user_id`, `group_id` (in the
  mounter's namespace), `default_permissions`, `allow_other`, `max_read` (at least 4096) when
  given. statfs reports `FUSE_SUPER_MAGIC`; `/proc/filesystems` lists `nodev fuse`.
- A forced unmount aborts the whole connection before the mount's busy check. The last attached
  device file closing also aborts it, as does `Vfs::collect` when no attached or detached mount of
  the instance remains. Collection also removes the instance and its cached nodes. Aborting wakes readers,
  pollers and callers waiting for INIT or a reply. Requests not yet answered end with ECONNABORTED,
  new ones are ENOTCONN, the daemon's reads ENODEV and writes ENOENT, poll `POLLERR`.

### Host shared storage

- `kernel/mount` creates `Conn::shared_storage`: subtype `shared_storage`, `allow_other`, no
  `default_permissions`, already Ready at the current protocol version, with `ATOMIC_O_TRUNC`,
  `BIG_WRITES` and 128 KiB request limits. It needs no device file or INIT exchange.
- The trusted root path must be absolute and contain no NUL. It is opened lazily as an O_PATH
  directory; failed host opens leave it unopened so later operations retry after a permission grant
  or directory creation. Once opened, the root remains anchored to that directory.
- LOOKUP opens one validated name relative to its parent's descriptor with O_PATH and O_NOFOLLOW.
  Host symlink text is returned by READLINK and followed by the guest walker. Reopens use
  `/proc/self/fd`, preserving open inodes across host rename, replacement and unlink. Ordinary host
  I/O opens only regular files and directories.
- Namespace operations, reads/writes, truncate/timestamps, directory cookies, fsync, statfs, seek
  and fallocate use host descriptors. WRITE applies the current guest append flag and uses a host
  append write when set. Host errors are returned as guest errnos.
- Attributes expose host inode numbers, matching readdir, with guest uid/gid zero and only ordinary
  permission/type bits. Guest ownership or permission changes are rejected unless they match that
  presented metadata; no host ownership or privileged mode bits are applied. New files use at most
  0666 and directories 0777, with umasks. Hard links and xattr writes are EOPNOTSUPP; xattr reads
  report ENODATA and lists are empty, so host capabilities and SELinux labels stay hidden.
- Entry and attribute validity is zero: later syscalls query again to see other apps' changes.
  Guest users share the Android app's host access; inotify still reports only changes made through
  this kernel.
- Host handles are opened with `FOPEN_DIRECT_IO`: shared mmap is refused (ENODEV), so a host
  connection has no dirty mapped pages and no periodic background writeback is queued on it.
  Private mappings fill through ordinary `request` calls.

### Requests and waiting

- `call` waits until INIT has been answered (only a kill stops that), queues the request with the
  caller's filesystem IDs mapped into the connection's user namespace (overflow IDs when unmapped)
  and its thread id in the connection's pid namespace (0 when not visible), wakes the readers and
  waits with the BKL released. `FUSE_ACCESS` carries the IDs of the credentials it is asked for
  (`call_as`): the real ones for access(2) without `AT_EACCESS`.
- Waiting (6.1's `request_wait_answer`): a signal marks the request interrupted; once the daemon
  holds it a `FUSE_INTERRUPT` is queued (at once, or when the daemon reads an already-interrupted
  request) and the wait goes on. A killed thread takes back a request not yet read (EINTR), except
  a forced one (flush, teardown writeback or a core-dump fill); one already read, or forced, is waited for until
  answered or aborted (after an interrupt), unless the system is stopping, when it is left to the
  daemon and the call is EINTR.
- One wake object per side: every reply wakes every waiter of the connection, every new request
  every reader.
- For a host connection, `request` drains pending messages and forgets, marks requests Sent and
  keeps them in `Conn.requests`, then uses `Cx::unlocked` for the host mutex and dispatch. Replies
  use the same `Conn::answer` path as device replies (request accounting included, and a
  background-writeback reply it hands back is finished with `finish_bg_writeback`); an abort that
  won the race keeps its error.
  Keeping Sent requests lets eviction retain their nodes while the BKL is released.
- `background` queues RELEASE and RELEASEDIR with nobody waiting (an open file's last reference
  dropping), unless the connection is refused or aborted; their replies are dropped. When the
  connection is borrowed as the last reference goes, the release and the node's open count wait in
  a per-thread queue (`Released`) that `flush_released` empties at the end of the syscall or at
  thread exit, with the BKL held.

### The device

- read (6.1's `fuse_dev_do_read`): the buffer must hold 8 KiB and a whole write request (EINVAL,
  checked first); then ENODEV once aborted; interrupts for requests still held go first, then
  forgets (all of them while no request is pending, otherwise up to 16 before the next request and
  then 8 requests in a row: `FUSE_FORGET` for one, `FUSE_BATCH_FORGET` for several from a 7.16 or
  later daemon, neither answered, each taking a unique), then the oldest request, which becomes
  `Sent`. A request too large for the buffer ends with EIO (E2BIG
  for SETXATTR) and the next is taken. Nothing to read: EAGAIN when nonblocking, `ERESTARTSYS` on a
  signal, otherwise it waits.
- write (`fuse_dev_do_write`): shorter than a header or a length unlike the write's is EINVAL;
  ENOENT once aborted; unique 0 is a notification; an error must come alone and be a negative errno
  above -512 (EINVAL); then an interrupt's reply must be for a request still held (ENOENT) and a
  bare header (EINVAL), ENOSYS stopping interrupts, EAGAIN queuing it again, any other error
  accepted; a reply to anything but a held request is ENOENT. An ENOSYS reply marks the operation in `no`. The INIT reply is taken by the
  connection.
- `INVAL_INODE` expires attributes. A nonnegative offset also invalidates overlapping mapped
  pages across all address spaces. A nonpositive length covers the remainder of the file.
  `INVAL_ENTRY` and `DELETE` drop the name and directory attributes. `STORE` updates cached
  `FillPages` (and `attr.size` if extended) directly—populating whole or EOF-tail cold pages
  without `FUSE_READ`, updating resident pages and clean baselines, and invalidating Tier 1
  executable code translations when resident bytes change. `POLL` is accepted, and `RETRIEVE`
  returns ENOSYS.
- read, write, readv and writev of the device move one whole message (up to 8 MiB); splice into a
  pipe takes one whole request (the device's own `O_NONBLOCK`, EIO when the pipe lacks room, the
  request then lost as in Linux). Splice from a pipe validates the header against the bytes
  available up to the requested length. A mismatch returns EINVAL and leaves the pipe intact.
- poll: always writable, readable while a request, a forget, or an interrupt for a held request waits,
  `POLLERR` once aborted or unattached.
- `FUSE_DEV_IOC_CLONE` attaches an unattached device file to the connection of another, both
  opened in one user namespace; anything else, a bad fd included, is EINVAL.

### The node cache and retries

- Each syscall gets a new token (`new_syscall`, which also drops the program copies of the last
  one). A cached name or attribute is usable while its validity lasts, or when its fetch token is
  at least the current nonzero syscall token; symlink text follows the same token rule without a
  timed validity. Thus a later-started overlapping syscall can fill a zero-validity cache for an
  earlier walk without erasing its retry progress; explicit invalidation still removes validity.
- A walk in a FUSE directory reads the cache: `fuse_child` / `lookup_walk` for a name, the cached
  type for `is_dir` and symlinks, the cached parent for `..` (no `..` lookup is ever sent), the
  cached link for a target. When a walk misses cache on a plain component, `lookup_walk` batches
  consecutive plain components (`!= "."`, `!= ".."`, `<= NAME_MAX`) into `Query::LookupWalk`, so
  multi-component cold FUSE paths resolve in O(n) RPCs and a single retry instead of restarting
  from the root per component; `serve` stops the batch on non-directories, symlinks, mount points,
  search-permission failure, signal/kill, or lookup error. What it lacks becomes a `Query` (`need`)
  and the internal `FUSE_RETRY`; the dispatcher calls `serve` with the BKL released and caches the
  answer, then runs the syscall again (at most 16384 times, then EIO). A lookup's ENOENT is cached
  as a missing name for this syscall (a node id of 0 for its validity); non-`ENOENT` lookup errors
  (other than `EINTR`) are cached in thread-local `LOOKUP_ERRORS` for the current syscall so walks
  and syscall handlers receive the error directly and can tolerate it when Linux VFS rules allow.
  `new_syscall` clears `LOOKUP_ERRORS`.
- `enter` caches a lookup's or creation's entry: the root's node id is EIO, a known node id keeps
  its node (a directory moves under its new parent, the root never moves), a known node id of
  another type gets a new node, and a directory that would move into itself or below is ELOOP, so
  parents never loop. `moved`
  records a directory renamed through the mount, unless that would loop.
- Changes made through the mount update the cache after the daemon's reply: creations stale the
  directory and enter the new name; removals forget the name and stale the directory and the
  node; renames forget both names, stale both directories and move a directory; writes,
  truncation, fallocate, xattr changes and links stale the node; SETATTR caches its reply.
- Every entry accepted counts a lookup on its node (`nlookup`), even one refused as a loop; the
  root's node id counts none.
- Forgetting (6.1 evicting unused inodes): when an entry takes the cache past `sweep_at` (starting
  at 16384), an unlinked/rmdir'd/overwritten node loses its last link, a doomed node's last open
  handle or request finishes, or a write of 2 or 3 to `vm.drop_caches` runs, `SWEEP` is set and the
  dispatcher calls `sweep` at the end of a syscall. It keeps what `in_use` finds (every task's root
  and cwd, the node of every open file in every fd table, O_PATH ones included, every running
  program's key and mapped interpreter key, every mount's root and point attached or detached, every inotify watch), each
  connection's roots, nodes with an open handle, live O_PATH description, bound AF_UNIX socket
  (`sock_pin`), or active/waited lock (`io_busy`, `dir_busy`, `dir_waiters`), and nodes a request
  in flight refers to (its node, a rename's other directory, or a link's file). It keeps their
  ancestor
  directories and retries if it finds a borrow. `evict` first forgets unused `doomed` nodes (and any
  unused cached descendants of a doomed directory) leaves-first without waiting for 16384 nodes,
  then runs bulk LRU eviction only on `drop_caches` (all unused nodes) or while the cache still
  exceeds 16384 (down to 12288, leaves first, oldest entered first). After a bulk trim or
  `drop_caches`, `sweep_at` is set to `max(16384, live + max(live / 4, 4096))` so working sets above
  16384 do not rescan on every new entry, and resets back toward 16384 as nodes drop or an instance
  is removed. A forgotten node leaves the table and the node-id index, the names naming it go with
  negative entries no longer valid, and its `nlookup` is queued as a forget and the readers woken. A
  node id looked up again is a new node (and reusing a doomed node id for any type clears its doom).
- A node `unlink`, `rmdir`, or non-exchange overwriting `rename` removes the last link of (cached
  `nlink` decremented, always last for directories) is doomed in `Conn::doomed` and swept at once if
  unused. If held open or busy in flight, it stays alive and doomed until closed and its
  `FUSE_RELEASE`/`RELEASEDIR` reply (or `no_release` handle drop, or last non-open request reply)
  schedules a sweep; one held solely by an `O_PATH` pin, cwd, mount or watch stays alive and is
  forgotten on the next sweep once released. Likewise, a node `drop_caches` keeps only for a release
  in flight loses its names and is doomed until that release ends unless a lookup saves it.

### Permission

- `fuse_permission` (6.1's `fuse_permission`): EACCES, root included, unless the mount allows the
  process (with `allow_other`, anyone in the mounter's user namespace or one below; otherwise only
  a process whose real, effective and saved user and group IDs are the mounter's). Namespace IDs
  are compared, since the initial namespace may be represented by distinct Rc copies. Then with
  `default_permissions` the cached attributes decide (fetched again when out of date; callers able
  to search everything need none for a search); without it only executing a regular file is
  checked (some execute bit).
- access(2), chdir, fchdir and chroot: the mount's check, then the cached attributes with
  `default_permissions`, otherwise the daemon's answer to `FUSE_ACCESS` (a daemon without it
  allows).
- stat is EACCES for a process the mount does not allow; statfs gives it only the magic. `fstat`,
  `AT_EMPTY_PATH` stats (`newfstatat`/`statx`), `/proc/<pid>/fd` stats, `copy_file_range`, `mmap`,
  and fd-based `setattr` attribute fetches on an open FUSE regular file (with `!no_release`) pass
  its open file handle (`FUSE_GETATTR_FH`) when refreshing stale attributes (directories and
  `O_PATH` descriptors do not).

### Opening and creating

- Open (6.1's `may_open`, `fuse_open_common`): a symlink ELOOP; a directory with write access,
  `O_CREAT` or `O_TRUNC` EISDIR; `O_TRUNC` on a read-only mount or instance (`readonly`) EROFS; a
  device on a nodev mount EACCES; permission; `O_NOATIME` by a non-owner EPERM; a write open of a
  regular file on a read-only mount or instance EROFS;
  writing a program being run ETXTBSY; `O_DIRECTORY` on a non-directory ENOTDIR. Then
  `FUSE_OPENDIR` or `FUSE_OPEN` with the open flags less `O_CREAT`, `O_EXCL`, `O_NOCTTY` (and
  `O_TRUNC` without `ATOMIC_O_TRUNC`, which then is a SETATTR after the open). An ENOSYS answer
  means no open is needed, now and later (cached pages retained, no handle or release). Device nodes, FIFOs and
  sockets in a FUSE filesystem cannot be opened (ENXIO).
- Create (`O_CREAT` of a missing name, 6.1's `fuse_create_open`): EROFS, the directory's write and
  search permission, then `FUSE_CREATE` (mode with the umask applied unless `DONT_MASK`, which
  sends it beside), or from a daemon without it `FUSE_MKNOD` and an open. Without `O_EXCL`, an
  EEXIST (another process created the name since the walk; Linux holds the directory's lock across
  both) forgets the missing name and runs the syscall again, which then opens the file.
- Successful regular-file OPEN and CREATE replies retain mapped pages with `FOPEN_KEEP_CACHE`.
  Clearing the flag invalidates all mapped pages of that inode, including through another name.
  An atomic truncating open or create shrinks the mapped backing to zero even with the flag set.

### Reading, writing and positions

- read and write go to the daemon in requests of the negotiated size, stopping at a short reply;
  errors after the first piece return what was done. One guest read or write moves up to 8 MiB.
  Reads overlay unacknowledged mapped stores on the reply. Writes update resident mapped bytes and
  their writeback baseline for exactly the range accepted by the daemon.
- A file opened `FOPEN_STREAM` has no position (offset 0); with `FOPEN_NONSEEKABLE` or `STREAM`,
  pread, pwrite and lseek are ESPIPE.
- The position is taken as unlocked I/O takes it (`pos_busy`) and advanced past what moved; a
  fault while copying out moves it back.
- A write with `O_APPEND` (as the open file's flags are now) asks the daemon for the size first
  and writes there, one append per node at a time from the size to the write (the node's
  `io_busy` flag also orders fills, mapped reads, writeback and size changes); `RLIMIT_FSIZE` cuts
  writes (`SIGXFSZ` and EFBIG at the limit). WRITE carries the file's current flags, including
  fcntl changes.
- lseek takes `pos_busy` (`PosGuard`): `SEEK_END` from the daemon's size, `SEEK_DATA`/`SEEK_HOLE`
  through `FUSE_LSEEK` (a daemon without it has data up to the end).
- `O_SYNC`/`O_DSYNC`/`RWF_SYNC`/`RWF_DSYNC` writes (including `sendfile`, `copy_file_range` and
  `splice`) sync via `FUSE_FSYNC` (`write_sync`).
- copy_file_range and splice treat FUSE files like regular ones and copy block by block.

### Directories

- getdents64 lists through `FUSE_READDIR` a page at a time on the first call and after a seek to
  0, keeping the daemon's own `.` and `..`; an empty name, one over 1024 bytes or with `/` is EIO.
  Directory `lseek` follows 6.1's `generic_file_llseek` on `fuse_dir_operations`: `SEEK_SET`,
  `SEEK_CUR`, `SEEK_END` and `SEEK_DATA`/`SEEK_HOLE` counted from the directory inode's size
  (fetching stale attributes via `FUSE_GETATTR` without `FUSE_GETATTR_FH`, never `FUSE_LSEEK`),
  resetting cached entries on a seek to 0; `FOPEN_NONSEEKABLE` and `FOPEN_STREAM` directories
  return `ESPIPE`.

### Namespace changes

- Directory-modifying operations (`create` including its `MKNOD` fallback, `mkdir`, `mknod`,
  `symlink`, `link`, `unlink`, `rmdir`, `rename`) serialize per directory under `Node::dir_busy`
  (Linux's directory `i_rwsem`), sleeping on `wake::LOCK` (killable, RAII-released on error, abort
  or kill, with `dir_waiters` preventing eviction while waiting). Operations in different
  directories run concurrently. Cross-directory `rename` locks both directories in canonical
  `FuseId` order (`lo < hi`) to prevent deadlock; cross-directory directory moves also acquire
  `Conn::rename_busy` first and re-check `is_within` under the locks to prevent cycles.
- mkdir, mknod (devices need `CAP_MKNOD` and the cgroup device BPF filter unless character 0:0
  whiteout), symlink: `.`, `..` or an existing name
  EEXIST, then EROFS, then the directory's permission; the reply's type must be the one asked
  (EIO). mkdir keeps the permission and sticky bits.
- link (6.1's `do_linkat`): EEXIST, EROFS, EXDEV unless both on one mount, `protected_hardlinks`
  on the cached attributes with read and write permission as the mount decides, the directory's
  permission, EPERM for a directory.
- unlink and rmdir: `.`/`..` rules, EROFS, the lookup, a trailing slash, the directory's
  permission, the sticky rule (with `default_permissions`), the type, a mount point EBUSY; the
  daemon answers ENOTEMPTY.
- rename: EXDEV across mounts, `.`/`..`, EROFS, the lookups, `NOREPLACE` and `EXCHANGE`
  preconditions, both directories' permission and sticky rules, type compatibility, mount points
  EBUSY, a directory under itself EINVAL; then `FUSE_RENAME`, or `FUSE_RENAME2` with flags (EINVAL
  from a daemon without it).

### Attributes and xattrs

- chmod, chown, utimensat, truncate and ftruncate are `FUSE_SETATTR` (with the open file's handle
  when changed through one); EROFS and the mount's check come first, and only with
  `default_permissions` the owner, group and capability rules. truncate and fallocate apply
  `RLIMIT_FSIZE`; fallocate takes only `KEEP_SIZE` and a hole with it (EOPNOTSUPP otherwise or from
  a daemon without it).
- xattrs: `trusted.*` needs `CAP_SYS_ADMIN` (hidden otherwise), `user.*` only on regular files and
  directories, owner-only in a sticky directory, and the mount's permission; `security.capability`
  writes need `CAP_SETFCAP` over the file, other `security.*` writes `CAP_SYS_ADMIN`. Values are
  passed through unconverted; listxattr passes the daemon's list as it is; a daemon without an
  operation gives EOPNOTSUPP.

### Closing, flushing and releasing

- close(2) sends `FUSE_FLUSH` and returns its error; descriptors replaced by dup2, closed by
  close_range or on exec are flushed with errors ignored; at exit the last thread using an fd table
  flushes its FUSE files. A flush is forced: a killed process still waits for it. No flush with `FOPEN_NOFLUSH`, without an open, or from a daemon
  without it. The open file's last reference queues `FUSE_RELEASE` or `FUSE_RELEASEDIR` in the
  background.

### Mappings and programs

- mmap of a FUSE file pins its open handle. The first mapping creates a sparse memfd at the
  inode's cached size. Later mappings reuse its pages at file offsets. A shared writable mapping
  requires a readable and writable descriptor, including write permission added with mprotect.
  A noexec mount still refuses execution and a direct-I/O handle refuses shared mmap with ENODEV.
- `MS_SYNC` writes contiguous runs of changed bytes in range and waits for a data sync.
  Matching bytes between runs stay untouched on the daemon. File sync and close write
  back the inode before the daemon sync or flush. Unmap (including fixed replacement) writes back
  removed shared ranges with write access. Exec and thread exit flush shared ranges of the old mm.
  In addition, `machine::timers()` calls `fuse::flush_dirty` at the interval configured by
  `/proc/sys/vm/dirty_writeback_centisecs` (default 500 = 5 s, disabled when `<= 0`) to queue
  asynchronous background `FUSE_WRITE` requests (`FUSE_WRITE_CACHE`) for dirty mapped byte runs;
  `FillPages::bg_busy` (released via `BgWriteback`'s `Drop` on reply, error, oversized drop, or
  abort) serializes background writeback with foreground `with_io`. A short write keeps
  unacknowledged bytes dirty. Failed teardown retains a writable handle and cached data for a later
  sync.
- Writes, truncate, atomic truncating open and fallocate through the mount update the backing.
  Shrink revokes guest translations before resizing the memfd. Hole punching also clears resident
  mapped bytes. Private host mappings keep their own modified pages.
- Data invalidation from a notification, open, or `FUSE_AUTO_INVAL_DATA` (when negotiated and
  `LOOKUP`/`GETATTR` reports changed `size` or `mtime` on an existing node) revokes translations
  without waiting for the inode I/O lock. The next fill rechecks size and merges unacknowledged
  mapped stores with fresh daemon data. A fill discards replies overtaken by either kind of
  invalidation.
- Pages are read as they are touched (`fill`: `FUSE_READ` through the mapped file's handle, the
  BKL released): on a guest fault, on a kernel copy failing with `FUSE_RETRY`, before I/O,
  offset-updating, polling, fd-creating, and socket syscalls for their buffers (`prefault`), and
  for `mlock`/`mlock2`/`mlockall`, `MADV_WILLNEED`, `MADV_POPULATE_*`, `MAP_POPULATE`/`MAP_LOCKED`,
  and `remap_file_pages`. Proc memory transfers and stateful result copies retry cold pages locally.
  Core dumps force fills for selected file pages and ELF header checks after group exit. If only
  the dumping process holds the device, its cold pages are unavailable. How much one fault reads is
  `kernel/mm`'s (`Fill::window`).
- AF_UNIX `bind` in a FUSE directory (`bind_socket`) creates the socket entry with `FUSE_MKNOD`
  (`S_IFSOCK | (0o777 & !umask)`), maps `EEXIST` and trailing slashes to `EADDRINUSE`, and pins the
  node via `Node::sock_pin` so `connect` finds the bound socket by `key(id)` across cache eviction.
- execve of a FUSE program (or interpreter) reads it whole into a memfd through a retry
  (`Query::Program`, one copy per file per syscall), runs it as from a nosuid mount, and gives it
  its node's key as the internal image inode. The main program's key enforces ETXTBSY.
  Procfs resolves image keys to daemon inodes for maps and smaps and skips the store's
  deleted-file lookup for FUSE paths. Ordinary FUSE mappings already carry the daemon inode.

### inotify

- When the daemon accepts a program open, `serve` reports it to the exec attempt before
  fetching attributes or copying data. A subsequent read failure still delivers open and close.
  The successful retry reuses the same open.

- Watches key FUSE nodes by `key`; reads and writes report `IN_ACCESS`/`IN_MODIFY`, opens (with
  `IN_MODIFY` on `O_TRUNC`) and closes through the open file's record, creations `IN_CREATE` (once
  even on the MKNOD fallback via `make_node`), attribute and xattr changes (`chmod`, `chown`,
  `utimensat`, `setxattr`, `removexattr`) `IN_ATTRIB`/`IN_ACCESS`/`IN_MODIFY`, truncations and
  `fallocate` `IN_MODIFY`, removals `IN_ATTRIB`, delete-self and `IN_DELETE`, renames the moved
  pair and move-self (a replaced name's delete-self only for its last link). Unlinks and
  overwriting renames call `inotify::unlinked` so `IN_EXCL_UNLINK` filters unlinked FUSE names
  without dropping linked child events. Only changes made through this kernel are seen.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/mount`: mount(2) (`fuse_mount`), host shared-storage attachment and collection.
- `kernel/vfs`: the walk (`fuse_child`, `fuse_permission`, kind, readlink, parents) and the FUSE
  branches of getdents, stat, statfs, access, chdir and the attribute and namespace syscalls.
- `kernel/files`: opening `/dev/fuse`, the FUSE branches of open and the close paths;
  `kernel/fileio`: the I/O routes, readv/writev, lseek, fsync and copy_file_range; `kernel/pipe` and `kernel/xattr`: those of
  splice and the xattr calls.
- `kernel/process`: the dispatcher's retry loop (`new_syscall`, `serve`), thread exit
  (`flush_at_exit`).
- `kernel/exec`: execve (`open_fuse`, close-on-exec flush).
- `kernel/mm` (`map_fill` for mmap, `fill` from the fault path), `kernel/poll` (device readiness
  and wake object), `kernel/procfs` (mountinfo type and options, mapping inodes), `kernel/sysctl` (`drop_caches`).
- The dispatcher: `fill` and `prefault` for mapped pages, `sweep` after every syscall.
- `kernel/net` calls `fill` for socket output copies, including payload, address, control data
  and message header fields. recvmmsg also fills pages when importing the current record.

### Outbound

- `kernel/process`: the wait API (`wait_object`, wake objects), `interrupted`, `killed`,
  `stopping`.
- `kernel/mount`: the mount table (`readonly`, `mount_flags`, `is_point_in`, `dev_of`).
- `kernel/vfs`: `resolve_parent`, `encode_stat`; `kernel/files`: `open_mask`, `executing`;
  `kernel/fileio`: `check_fsize`, `fsize_room`, `PosGuard` and `truncating`.
- `kernel/inotify`: the hooks for FUSE namespace changes.
- `kernel/cred`: `Cred`, user namespace ID maps, `permission`, `owns`, `may_delete`,
  `capable_wrt`; `kernel/cgroup`: `check_device` for `mknod`.
- `kernel/signal`: `SIGXFSZ` through the VFS's `file_too_big`.
- `hal`: `memfd` for program copies and mapping fills.
- Host libc and `std::fs`: descriptor-based shared-storage operations and metadata.
- `kernel/mm`: `Fill` and `FillPages` for reads and dirty byte runs, and `Mm::invalidate_fill` for notification and open-time shootdowns.
- The task table, fd tables, mm `exe` and `mapped_inos`, `Vfs::mount_nodes` and `kernel/inotify`'s registry
  (`watched`) for `in_use`.

## Invariants and gotchas

- A syscall handler may run many times for one syscall: nothing that changes state (a request
  other than a query, a cache update the daemon did not answer for) may come before a walk or
  cached attribute that can need a retry. Every change request here comes after its handler's
  walks, permission and attribute checks.
- Code that swallows walk errors (`.ok()`, `has_child`) must not turn `FUSE_RETRY` into "not
  found" where that changes what is done; `fuse_permission` results must pass it through.
- No borrow may be held across `call` (it waits): handles are copied into `Io`. An umount may
  remove the instance while a request is answered, so after a reply the panicking `Fuses::node`
  is used only behind a fresh existence check: code needing the node fails with ENOTCONN
  (`getattr`, `setattr`, `enter`), cache updates skip a vanished node, and a removal counts a
  vanished child as its last link.
- `enter` and `moved` keep parents free of loops; everything that climbs parents (`reach`,
  `fs_path`, `is_within`, `is_under`) depends on it.
- Uniques are even, so the low bit marks interrupt replies.
- Store inode numbers (below 2^62), overlay keys (top bits 10), FUSE keys (11) and cgroup2 files'
  inotify keys (01) must never collide.
- The type of a node never changes; a reply giving another type is EIO (getattr, setattr) or a new
  node (lookup).
- Nodes are forgotten only between syscalls (`sweep`), so a `FuseId` in a syscall's locals stays
  valid. A path description from open or open_tree holds a shared pin for its cache entry,
  including while its only reference is in an AF_UNIX message. Other holders across waits need
  a daemon handle, a pending request or a reference visible to `in_use`.

## Confirmed bugs / technical debt

- **Host releases wait for another request:** background RELEASE/RELEASEDIR and FORGET queues are
  drained by the next host request; the final unused host handles and anchors can stay open until
  another shared-storage operation or connection teardown.
- **Locks stay local:** POSIX, OFD and flock locks on FUSE files work only between processes of this
  kernel; the daemon never sees them.
- **Missing pieces:** no `fuseblk` (ntfs-3g), no fusectl (`/sys/fs/fuse/connections` and its
  `abort`), no `FUSE_IOCTL`, `FUSE_POLL`, `FUSE_COPY_FILE_RANGE`, `FUSE_TMPFILE` or notify
  retrieve; device nodes and FIFOs on FUSE cannot be opened (ENXIO).
- **Programs:** set-id bits and file capabilities of FUSE programs never apply (even on a mount
  without nosuid), and `/proc/<pid>/exe` is followed by path.

## Open questions

- Would readdirplus benefit sshfs and rclone workloads?

## To verify

- The Linux 6.1 behaviour cited above comes from knowledge of `fs/fuse` without a source checkout;
  what the `fuse` and `fuse-tools` differential cases exercise was observed on a native 6.8 kernel
  (fuse-overlayfs, sshfs, rclone, mount option errors, `/dev/fuse` before a mount, the clone
  ioctl, ETXTBSY, `RLIMIT_FSIZE`, mapped pages, which nodes `drop_caches` forgets), while
  interrupts, oversized requests, notifications other than `INVAL_INODE`, refused INIT, the `max_read` shown, the forget
  interleaving and `FOPEN_DIRECT_IO` mappings were not (a 6.6+ kernel lets libfuse 3.17 map
  direct-I/O files shared).
