# Open files (kernel/files) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/files"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)
>
> Decisions on open files made before kernel/files was split from kernel/vfs keep their `kernel/vfs` tags and live in `.agents/decisions/kernel/vfs.md`: D5, D11, D17, D22, D24, D26, D27, D29, D33, D34, D41, D44, D45, the owner half of D25, the `open_pseudo` half of D19 and the file I/O halves of D36 and D37; the pre-split fd reservation decision is D55.

## Active

### D1: kernel/files owns fd tables, open descriptions, opening and control

- **What**: kernel/files covers `gpu.rs`, `syscall/gpu.rs`, `fd.rs` except eventfd/timerfd, the Opening, closing, duplicating section of `syscall/fs.rs` (excluding `write_at`, `clone_range`, clone/dedupe ioctl arms, overlay, lock and pipe code) and shared helpers `executing` and `open_for_write`, after splitting data I/O, size changes, syncing and object sharing into `kernel/fileio`.
- **Why**: `kernel/files.md` reached 79.9% of a single read while combining open-file lifecycle and control with file data I/O, size changes, syncing and object sharing.
- **Tradeoffs**: Changes spanning `OpenFile` fields (`pos_busy`, `cow`, `retired`), `O_TRUNC` or `FICLONE` ioctl dispatch now read both `kernel/files` and `kernel/fileio`, and pre-split decisions remain in `.agents/decisions/kernel/files.md` and `.agents/decisions/kernel/vfs.md`.
- **Watch out**: Open-file changes must stay aligned with `kernel/fileio` (`OpenFile` borrow-across-BKL-release rules, `O_TRUNC` unsharing/truncation hooks, clone ioctl dispatch), `kernel/vfs` (resolution, mount flags, tmpfs accounting), `kernel/cgroup` (device checks and observation) and `kernel/procfs` (synthetic opens).
- **Source**: ce193253; 20137e4c; cf029f9a; d053be24; 39e55b4b; 4fcd3e13

### D2: Reopens retain their mount and normal open checks

- **What**: `StoreOpen` routes reopens through open checks on their original mount with the path and IN_OPEN event, keeps reopened memfds as writers, and lets truncate through fd links use the open handle for deleted files and memfds.
- **Why**: Procfs reopens bypassed mount and open restrictions, while truncating deleted files or memfds through fd links did nothing.
- **Tradeoffs**: Reopens now expose normal EROFS, O_NOATIME, ETXTBSY and lease errors, and writable memfd reopens block execution.
- **Watch out**: Container runtimes reopening through `/proc/self/fd` can now receive errors they previously bypassed.
- **Source**: 01bfd882; 20137e4c; d053be24; 39e55b4b

### D3: File I/O preserves position ownership and partial progress

- **What**: Writes acquire `pos_busy` before checks and apply RLIMIT_FSIZE once per call, rollbacks are bounded by actual movement, copy_data returns progress, ftruncate waits without a held borrow, and make_private rehomes only held or COW objects.
- **Why**: Chunked writes, device reads and truncation could miscount progress, signal spuriously, deadlock or leak host fds.
- **Tradeoffs**: The existing lseek race outside `pos_busy` remains.
- **Watch out**: New I/O paths must preserve the same position, borrow and partial-progress rules.
- **Source**: 01bfd882; 20137e4c; d053be24; 39e55b4b

### D4: sendfile shares directional splice checks

- **What**: sendfile requires a seekable, splice-readable input and a splice-writable output unless the output is a pipe, using kernel/pipe’s predicates.
- **Why**: A separate permissive kind list returned the wrong errors for devices and unsupported outputs.
- **Tradeoffs**: Unsupported ends fail before reading, and FUSE inputs use the chunked fallback.
- **Watch out**: Programs expecting ENOSPC from sendfile into `/dev/full` now receive EINVAL.
- **Source**: 01bfd882; 20137e4c; d053be24; 39e55b4b

### D5: Replacing an fd closes it in the target process context

- **What**: The shared `close_replaced` helper releases locks, mqueue notifications, FUSE flush ownership and Unix references using the target table and tgid, including seccomp ADDFD.
- **Why**: ADDFD previously closed the target’s old fd as the supervisor.
- **Tradeoffs**: The replacement paths share an additional helper.
- **Watch out**: Future fd replacement paths must use the same target-context close.
- **Source**: 01bfd882; 20137e4c; d053be24; 39e55b4b

### D6: Render-node open descriptions carry per-open virtio-gpu context state

- **What**: `gpu.rs` and `syscall/gpu.rs` provide the virtio-gpu render ioctl subset with per-open context state, guest resource handles and capability reporting on the open file description.
- **Why**: Packaged Mesa Venus expects standard virtio-gpu render ioctls without modifying the guest driver.
- **Tradeoffs**: PRIME and kernel syncobj ioctls stay outside the implemented subset.
- **Watch out**: Future Mesa versions may issue additional render ioctls.
- **Source**: 87c7d9db

### D7: `open_pseudo` pins weak `Mm` on `pagemap` and passes `ThreadGroup` to `mqueue_closed`

- **What**: `open_pseudo` pins a weak `Mm` on `FileKind::Proc::mm` for both `Entry::Mem` and `Entry::Pagemap` and resolves targets via `group_of_id`, while `close`, `close_range`, `dup3` and `close_replaced` pass `&Rc<RefCell<ThreadGroup>>` to `mqueue_closed`.
- **Why**: `Entry::Pagemap` previously stayed unpinned across `execve` and PID reuse, and `open_pseudo`, `reopen` and `mqueue_closed` callers relied on bare PIDs.
- **Tradeoffs**: Open `pagemap` descriptors retain a weak `Mm` reference until closed.
- **Watch out**: `Entry::Pagemap` shares weak `Mm` lifetime semantics with `Entry::Mem`, returning EOF once the target address space is released.
- **Source**: b51818cf

### D8: `OpenFile::drop` releases node mounts and anonymous `open_tree` namespaces, and mqueue opens record their mount

- **What**: `OpenFile::drop` releases `node.mnt()` when distinct from `self.mnt` and `ANY_MOUNT` when `self.tree` is set, and `open_path_with` sets `file.mnt` for `PseudoNode::Mq` opens.
- **Why**: `O_PATH`, synthetic, overlay-directory, `open_tree` and mqueue fds previously kept `ROOT_MOUNT` and failed to trigger detached or anonymous mount collection on close.
- **Tradeoffs**: Dropping an `open_tree` fd with `tree` set always triggers a `collect_released` pass at syscall end even if the clone was already attached.
- **Watch out**: Future pseudo nodes backed by user-visible mounts that should block `umount2` need matching `file.mnt` assignment or `try_in_use` handling.
- **Source**: 0e02d7cd

### D9: `F_GETFL` preserves open-time status flags and `CLOSE_RANGE_UNSHARE` enforces `nr_open`

- **What**: `kept(flags)` retains `O_ASYNC | O_DIRECT | O_NOATIME | O_DIRECTORY | O_NOFOLLOW` (and `O_PATH | O_DIRECTORY | O_NOFOLLOW` for `O_PATH`), `F_SETFL` registers fasync whenever `O_ASYNC` is set, and `CLOSE_RANGE_UNSHARE` enforces `nr_open` (`EMFILE`) before cloning a shared `FdTable`.
- **Why**: `F_GETFL` previously stripped open-time flags that Linux retains in `do_dentry_open`, and `CLOSE_RANGE_UNSHARE` skipped `nr_open` checks.
- **Tradeoffs**: `F_GETFL` now exposes open-time flags such as `O_DIRECTORY` and `O_NOFOLLOW`.
- **Watch out**: Internal callers checking `f.flags` must continue masking the specific bits they care about rather than comparing the full flags word for equality.
- **Source**: ab694aab

### D10: `open_path_with` shares `resolve_create_parent` for `O_CREAT` parent resolution

- **What**: `open_path_with` routes `O_CREAT` parent-directory resolution and trailing-slash/overlay setup through the shared `resolve_create_parent` helper in `syscall/fs.rs`.
- **Why**: Inline creation-parent resolution duplicated logic already shared with namespace-creation syscalls.
- **Tradeoffs**: `open_path_with` creation setup is coupled to `resolve_create_parent`'s error ordering.
- **Watch out**: Changes to `resolve_create_parent` error ordering affect `openat`/`openat2` `O_CREAT` paths alongside `mkdirat`, `mknodat` and `symlinkat`.
- **Source**: 3a90a0ef

### D11: Document `F_GET_SEALS` `EINVAL` gap on ordinary tmpfs files

- **What**: `.agents/maps/kernel/files.md` records that `F_GET_SEALS` returns `EINVAL` on ordinary tmpfs files where Linux returns `F_SEAL_SEAL`.
- **Why**: `MemfdTest.TmpfsFilesHaveSealSeal` skips on the default test directory and exposed the tmpfs difference on both tiers.
- **Tradeoffs**: The gVisor `memfd` program remains outside the regular differential suite.
- **Watch out**: Testing a future fix requires a tmpfs test directory.
- **Source**: 48f1c17e

## Superseded

- ~~`kernel/files` combined open descriptions, opening, data I/O, lseek, syncing, truncation, fallocate and shared helpers (D1, ce193253)~~ → replaced by **D1** in 4fcd3e13 (2026-11-23)
