# kernel/overlay Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/overlay.md` for the paired decision history (decisions from before the split are D39, D40 and D49 in `.agents/decisions/kernel/vfs.md`, and D45 and D46 in `.agents/decisions/kernel/process.md`).
>
> Verified: 2026-11-11 (split out of the kernel/vfs full mapping of 2026-11-10; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: persistent copy-up origins, impure directories, inode flags and scoped node holds)

## Responsibilities

`kernel/overlay` is overlayfs (6.1's `fs/overlayfs`), a third kind of VFS node beside store and
synthetic nodes:

- mount(2) of type `overlay`: options, layers and their checks, the work directory, read-only
  instances without an upper layer, and the superblock options mountinfo shows;
- lookup through the layers (whiteouts, opaque directories), node identity and lifetime, and the
  sweep of removed nodes;
- readdir merging, stat, statfs and the overlay's own xattrs;
- copy-up, and creating, removing and renaming through an overlay;
- opening files through an overlay and following a file to its copy.

Root: `core/kernel/src/vfs/overlay.rs`; the overlay methods of `Vfs` in `vfs/mod.rs` (`new_overlay`
to `overlay_readdir`, `sweep_overlays`); in `syscall/fs.rs` `open_overlay`, `follow_copy_up`,
`copy_up`, `unlink_overlay`, `link_overlay` and `rename_overlay`; in `syscall/mount.rs` the overlay
options (`overlay_layers`, `overlay_dir`) and the node sweep at syscall end.

Outside the module: the walk, attribute and namespace syscalls that branch into this module, and
the rules every file operation keeps for overlay nodes (`kernel/vfs`); opens (`kernel/files`) and
truncations (`kernel/fileio`) that branch into it; store transactions,
objects shared by copy-up and whiteout inodes (`kernel/store`); the mount table, `collect` and
mountinfo (`kernel/mount`); inotify on overlay nodes (`kernel/inotify`); locks keyed on overlay
nodes (`kernel/locks`); syscall numbering for the sweep (`kernel/process`); a program's `exe_file`
holding its node (`kernel/exec`).

## Key types

- `Overlays` (`vfs/overlay.rs`) — `Instance`s by device number (upper and lower roots, the mounter's IDs, the
  tmpfs instances its layers are in, `Options`, and `origins` mapping copied-up upper inodes to
  validated lower origins for this mount) and `OvlNode`s by `OvlId` (Linux's
  overlay dentry: parent and name, upper inode, lower inodes — every merged lower directory for a
  directory, the topmost otherwise — `origin`, children looked up, LRU `seen` clock, and `touched`
  syscall stamp), plus orphans stamped with the syscall count and the orphan/live sweep thresholds
  (`ORPHANS_MIN` = 1024, `NODES_MAX` = 16384, `NODES_TARGET` = 12288). Ids are per kernel, never
  reused.
- `overlay::Hold` — an open file's or running program's claim on an overlay node, in one static
  table for every kernel in the process (a hold in another kernel can only delay a sweep).
- `Node::Overlay(MountId, OvlId)` (`kernel/vfs`); `OpenFile::ovl`, `ovl_holds` and `ovl_lower`;
  `fs::Attrs::Overlay`.

## Public entry points

- **Instances and nodes**: `Vfs::new_overlay`, `overlay`, `overlay_stat`, `overlay_readdir`,
  `overlay_upper`, `overlay_remove`, `overlay_rename`, `overlay_child`, `overlay_prefix`,
  `sweep_overlays`; `Overlays::upper_of` (copy-up), `remove`, `rename`.
- **Syscall paths**: mount(2) of type `overlay`; `open_overlay`, `follow_copy_up`, `copy_up`,
  `unlink_overlay`, `link_overlay`, `rename_overlay`; overlay branches of creation, attribute
  changes and readdir in `kernel/vfs`, of opening in `kernel/files`, of truncate in
  `kernel/fileio`, of `mmap` in `kernel/mm` (`syscall/mem.rs`), and of xattr calls in
  `kernel/xattr`.

## Data flow / lifecycle

### Mounting

- mount(2) of type `overlay` follows 6.1's `ovl_parse_opt` and `ovl_fill_super`: options split at
  unescaped commas, empty ones skipped, unknown ones or missing values `EINVAL`, the last of a
  repeated one wins; `workdir`, `index` and `volatile` without `upperdir` ignored; conflicting
  `metacopy`, `nfs_export`, `index`, `redirect_dir` and `userxattr` `EINVAL`, the accepted ones
  changing nothing else. `lowerdir` is split first at unescaped colons (missing, an empty
  component or over 500 `EINVAL`). Then upper layer and work directory: both or neither, non-empty,
  upper not on a read-only mount, both on one mount, neither inside the other (`EINVAL`); without
  an upper layer at least two lower layers (`EINVAL`); each lower layer then resolves, none inside
  the upper layer or work directory (`ELOOP`). Each layer resolves from the caller's root and cwd,
  following links, and must be a store directory on a mount of the caller's namespace with no
  locked mount under it (`EINVAL`, also for synthetic or overlay directories;
  `clone_private_mount`'s checks). The work directory gets an empty `work` (mode 0, the
  mounter's; an old one removed) that nothing uses: copy-up builds in place in one store
  transaction. An instance keeps the tmpfs instances its layers are in from being collected.
- Without an upper layer it is read-only as a filesystem (`sb_readonly`): `ro` in mountinfo's
  superblock options (the mount's own flags as given), read-only in `/proc/<pid>/mounts` and
  statfs; every change is `EROFS` after creation's `EEXIST`, also through a bind remounted
  read-write, and remounting it read-write is `EROFS`. Superblock options are `lowerdir`,
  `upperdir`, `workdir` as given, then what differs from 6.1's defaults (`ovl_show_options`;
  `xino` parsed, never shown), escaped as `seq_show_option` does.

### Lookup and node lifetime

- Lookup (`ovl_lookup`): the upper inode, then each lower directory merged into the parent; a
  whiteout (char 0:0) is `ENOENT`; a non-directory ends the search and hides what is below a
  directory; an opaque directory (`trusted.overlay.opaque` = `y`, or `user.overlay.opaque` with
  `userxattr`, in any layer) ends it after itself. One directory and name give one node, its
  inodes refreshed on each lookup. An upper origin handle encodes `OVL`, version 1 and a little-endian
  lower store inode. On a cache miss the inode must be older than the upper, live, of the same type
  and under a mounted lower root. A non-directory must have one lower link. Invalid handles are ignored.
  Mounts inside a layer are not seen through the overlay.
- Node lifetime: active nodes stay cached while referenced; unused live nodes and removed nodes are
  reclaimed by `sweep_overlays` at the end of a syscall. A removed name (unlink, rmdir, a replacing
  rename) makes it an orphan no lookup finds; once 1024 orphans gather (then twice as many as the
  last sweep left), or once total cached nodes exceed `NODES_MAX` (16384; backing off with at least
  25% / `NODES_HEADROOM` above remaining live nodes when the pinned working set exceeds
  `NODES_MAX`), `sweep_overlays` runs:
  - an orphan goes, with every node below it, unless it or a node below is held (`Hold`), is a
    process's root or cwd, a mount's root, point or recorded file-mount directory (`Mount::at`,
    `Mount::root_at`, detached ones too via `Vfs::mount_nodes`), watched by inotify, or was
    removed at or after another thread's syscall began — unless that syscall waits only on files it
    holds (`waits_on_files_only`: I/O, polls, child and signal waits, sleeps, futexes, locks,
    receives and accepts, fcntl, ioctl, fsync, copy_file_range, IPC, AIO events), as
    `kernel/process` numbers syscalls;
  - when total cached nodes still exceed `NODES_MAX`, unused live leaf nodes are evicted
    least-recently-used down to `NODES_TARGET` (12288) and detached from their parent's `children`,
    keeping instance roots, all kept/held/orphan nodes, any node touched at or after `oldest`
    (every `Overlays::node`/`node_mut`/`add_node` stamps `touched`; `open_overlay` also holds a
    scoped `Hold` on the node and its original overlay parent across lease breaks and FIFO opens),
    all ancestors of pinned nodes and surviving orphan subtrees; `Instance::origins` preserves copied-up upper-to-lower inode numbers
    across eviction for both `stat` and `readdir` while mounted.
  A sweep gives up for the round when a task's resources or the inotify registry are borrowed. An
  instance and its nodes go in `kernel/mount`'s `collect` once it has no mount. After an
  executable's name is removed, opening its procfs exe link reads the pinned host file and keeps
  the overlay node for metadata and locks. Write opens and truncation still check the mount and
  executable.

### readdir, stat and xattrs

- readdir merges the layers' entries sorted by name (even from one layer), the highest layer's
  entry per name, whiteouts hiding names below, each inode number the one stat shows. Stat is the
  topmost inode's with the overlay's device number and the inode number of the lower inode a
  directory, or a file with one lower link, was copied up from. In impure upper directories, including
  merged ones, readdir resolves upper entries from cached or persisted origins. A cold listing also
  checks entries in an unmarked directory. Additional upper hard links retain the same number. A merged directory
  reports one link. Reads, readlink, exec, search permission and xattr reads use the topmost
  inode; the overlay's own attributes (`trusted.overlay.*`, `user.overlay.*` with `userxattr`) are
  `EOPNOTSUPP` to get or set (`ovl_own_xattr_get`/`_set`) and hidden from listings. statfs reports
  overlayfs's magic with the store's capacity, even with the upper layer on a tmpfs.

### Copy-up

- Copy-up (`Overlays::upper_of`, `ovl_copy_up`): parents first, then the node as its topmost lower
  inode is (directory; regular file sharing the lower object, as 6.1 clones with reflink; symlink;
  special file), with mode (set-id bits too), owner, inode flags, non-overlay attributes and times in one store
  transaction. For a directory or a singly linked lower file it also writes `trusted.overlay.origin`
  on the upper and `trusted.overlay.impure=y` on the parent before restoring its times. Both use
  `user.overlay.*` with `userxattr`. Sharing marks both inodes held, so a later write
  open of either first gives it an object of its own. The syscalls copy up through
  `syscall::fs::copy_up`, which, as `try_share` does, copies a regular file's data instead
  (`CopyUp::Copied`) when a writable shared mapping or the Files app could write the lower object in
  place. A tmpfs upper also copies a lower inode with tracked tmpfs pages. It carries over
  instantiated pages within EOF and leaves unused reservations in the lower layer. The store also falls
  back to copying if either object carries a store mapping pin,
  including a read-only mapping in another kernel. After sharing it rehomes the lower file's descriptions open for writing (`cow`); a rename
  copies up the files it moves that way first. A non-directory then forgets its lower inodes; a
  copied-up directory keeps them and stays merged (one link, rename `EXDEV`). A file opened with
  `O_TRUNC` or truncated to 0 is copied without data. chmod, chown, utimensat (`Attrs::Overlay`),
  setxattr, removexattr, truncate and write opens check `EROFS` and permission on what the overlay
  shows (the last two also check `ETXTBSY` against the backing inode and the running overlay node across copy-up), copy up only then, and
  change the upper inode. utimensat by fd goes by number, never through the open (possibly lower)
  object.

### Creating, removing and renaming

- Creating (`may_create_overlay`, `check_overlay_create_tmpfs`, `create_dir`, `create_in`):
  permissions, `EEXIST`, trailing slash, whiteout/`CAP_MKNOD` and upper-layer tmpfs room are
  checked before copying up parent directories, so refused creations leave parents uncopied. Then
  the directory is copied up (charging upper-layer tmpfs when applicable via
  `overlay_upper_charged`), a whiteout of the name does not count as existing and is replaced in
  the same transaction (net zero tmpfs inodes), and a directory made in its place is opaque
  (`ovl_create_over_whiteout`); this covers open with `O_CREAT` (the new file is the overlay's
  node, so it locks with later opens), mkdir, mknod, symlink, link (the file copied up and linked
  there) and AF_UNIX bind (connect finds the upper inode). mknod of a whiteout through an overlay
  is `EPERM` (`ovl_mknod`).
- Removing (`unlink_overlay`, `Overlays::remove`; do_unlinkat's and do_rmdir's order, `may_delete`
  on what the overlay shows, a mount of the caller's namespace on it — including on a bind mount of
  the same overlay via `Vfs::is_point_in` — `EBUSY`, rmdir of a directory
  not shown empty `ENOTEMPTY`): upper-layer tmpfs room for parent copy-up and any new whiteout is
  checked before removal and charged/refunded afterwards (keeping unlinked-open regular files
  charged until close); the upper inode goes with the whiteouts left in a directory, a whiteout
  owned by the mounter replaces it when a lower layer has the name, and `Vfs::overlay_remove`
  detaches other namespaces' mounts on the removed node (`Vfs::detach_overlay_point`, also marking
  mounts rooted at it `root_gone`).
- Renaming (`rename_overlay`, `Overlays::rename`; may_rename's checks on what the overlay shows,
  mount points `EBUSY`, then `ENOENT`, `EEXIST`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY` on the merged
  view): a directory with lower layers (merged or lower only) is `EXDEV` (6.1 without
  `redirect_dir`; with `RENAME_EXCHANGE` the destination too), so tools fall back to copying;
  otherwise both sides are copied up and renamed in the upper layer (with upper-layer tmpfs
  accounting for parent copy-ups, replaced entries and whiteouts), a whiteout at the new name or
  left in a replaced directory is removed first, a whiteout is left at the old name when a lower
  layer has it, a directory moved into a merged one becomes opaque (with exchange, the other
  too). Link and cross-directory rename mark the receiving upper directory impure in the namespace
  transaction when the incoming inode has an origin, including the reverse move in an exchange.
  `Vfs::overlay_rename` detaches other namespaces' mounts on an overwritten destination
  (`Vfs::detach_overlay_point`) while mounts on the renamed source follow its moved node.

### Opening

- Opening goes through `open_store_with` on the topmost inode; a directory stays an overlay node
  for getdents, fchdir and `*at` calls. Regular files, devices, FIFOs and `O_PATH`
  descriptors with a pinned backing file record the node in
  `OpenFile::ovl`, so `OpenFile::node`, fchmod-like calls and `/proc/<pid>/fd` give the overlay
  node; fstat of a regular file shows the node's inode number, and of a device or FIFO shows the
  overlay node's stat and device (`overlay_stat` and `dev_of`, consistent with `stat` across
  copy-up). `O_DIRECT` is decided by the mount's filesystem, so overlay files pass it even with
  the upper layer on a tmpfs. A file opened before its copy-up switches to the upper object on its
  next read, fstat, lseek, copy out or `mmap` (`follow_copy_up`, matching 6.1's `ovl_real_fdget`
  and `ovl_mmap` calling `ovl_realfile`; a writable one marked `cow` while the upper file is held),
  keeping the lower object open until close (`OpenFile::ovl_lower`); `mmap` also unshares a
  copied-up upper object through `mapping_object` / `make_private` before mapping, while a mapping
  already created before copy-up keeps the lower object isolated (its store mapping pin forces
  copy-up to copy instead of sharing). Both locks (`lock_ino`) and leases (`lease::key_of`) key on
  the overlay node (`overlay::key`), with write opens and truncations breaking leases before
  copy-up. Writes, truncations, fallocate and copy-ups whose upper layer is on tmpfs
  (`backing_tmpfs_dev`) are checked and charged against that tmpfs instance.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/vfs`: the walk, creation, attribute changes, readdir, stat and statfs on overlay nodes;
  `kernel/files`: opening them; `kernel/fileio`: truncating them; `kernel/xattr`: xattr calls on overlay nodes.
- `kernel/mount`: mount(2) of type `overlay`, `collect`, mountinfo's superblock options.
- The syscall dispatcher (the sweep at syscall end; `Task::syscall` numbering, `kernel/process`),
  `kernel/exec` (`ExeFile` holding a program's node), `kernel/inotify` (overlay keys),
  `kernel/locks` (`lock_ino`), `kernel/unix` (bind and connect through an overlay).

### Outbound

- `kernel/store`: lookups in each layer, one transaction per copy-up, shared objects, whiteouts,
  xattrs.
- `kernel/files`: `open_store`; `kernel/fileio`: `prepare_write`; `kernel/vfs`: the tmpfs instances its layers are
  in.
- `kernel/mount` (layer checks, `clone_private_mount`'s rules, `mount_nodes`), `kernel/cred` (permission and
  ownership on what the overlay shows), every task's root and cwd and the inotify registry for the
  sweep.

## Invariants and gotchas

- An overlay node's store inodes may be in lower layers that must never change, so `Node::ino` is
  None for it and nothing may turn an overlay file's store inode back into a `Node::Store`: an
  open file reaches its node through `OpenFile::ovl`, and every change goes through a copy-up
  (`create_dir`, `Attrs::Overlay`, the overlay's removal and rename); `store_dir` refuses overlay
  directories (`EXDEV`). A `Node::Store` of an overlay mount and its upper inode is built only
  inside one call (`create_parent_at`'s result, the tmpfs accounting helpers, `file_stat`,
  truncate, `may_create`), for mount flags and accounting, and never stored.
- Overlay nodes live while their names do, and a removed one while anything may use it: every
  open file naming one must hold it (`OpenFile::hold`, or the kind's node at creation), as
  `ExeFile` holds a program's, and every other long-lived holder must be in the sweep's scan.
  Path-based truncate holds its node from the lease break through copy-up. A syscall that carries an
  unheld overlay node across a BKL release must stay outside `waits_on_files_only`.

## Confirmed bugs / technical debt

- **Overlay gaps**, one per line:
  - an overlay cannot be a layer (Linux accepts one as a lower layer);
  - removed nodes can outlive their last holder while another path syscall runs. The age guard
    protects `syscall::proc::exec`'s walked node through unlocked ELF loading, sibling-thread waits
    and close-on-exec FUSE flushes until `ExeFile::new` installs its hold. A relative FUSE create in
    `open_path_with` can also retain an overlay start directory for the later `display_path` fallback.
  - the no-BKL stat never serves overlay paths;
  - each whiteout has its own SQLite character-device inode (0:0) with no host object; Linux can share one.
  - a lower layer's `trusted.overlay.redirect` is not followed (sysfs reports
    `redirect_always_follow` as N; nothing Appine runs writes one).

## Open questions

- None recorded.

## To verify

- The original full mapping used kernel knowledge for its Linux 6.1 comparisons. The lower-link
  condition in `ovl_getattr` and stale-origin handling in `ovl_check_origin` have since been checked against source.
