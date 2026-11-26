# File data I/O (kernel/fileio) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/fileio"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)
>
> Decisions on file data I/O made before kernel/fileio was split from kernel/files (and before kernel/files was split from kernel/vfs) keep their parent tags and live in `.agents/decisions/kernel/files.md` (D3, D4 and the truncate-through-fd-link half of D2) and `.agents/decisions/kernel/vfs.md` (D11, D22, D24, D29, D33, D45, the `write_sync` half of D17, the write-path half of D41 and the file I/O halves of D36 and D37).

## Active

### D1: kernel/fileio owns file data I/O, size changes, syncing and object sharing

- **What**: `kernel/fileio` covers `write_at`, `clone_range`, the `FICLONE`/`FICLONERANGE`/`FIDEDUPERANGE` ioctl arms, Reading and writing (excluding overlay copy-up, pipe reads/writes and splice), `lseek`, Cache hints and syncing, truncate and fallocate, and shared helpers `check_seals`, `seals_permit`, `remove_privs` and `truncating` in `syscall/fs.rs`.
- **Why**: Separating file data I/O, seeking, size changes, cache hints, syncing and object sharing/unsharing from `kernel/files` keeps both maps well within the single-read budget.
- **Tradeoffs**: Pre-split decision history remains in `.agents/decisions/kernel/files.md` and `.agents/decisions/kernel/vfs.md`.
- **Watch out**: Changes touching `OpenFile` position locking (`pos_busy`), `cow`/`retired` handles, `O_TRUNC` or clone ioctl dispatch require reading `kernel/fileio` together with `kernel/files`.
- **Source**: 4fcd3e13

### D2: Pagemap reads use the pinned `Mm` and offset-0 procfs reads check for gone processes

- **What**: `IoPath::Pagemap` carries `Option<Rc<RefCell<Mm>>>` upgraded from `FileKind::Proc::mm` (returning EOF once released), and `refresh_pseudo` skips its `fresh` fast-path when `pseudo::gone` is true so `pseudo::content` returns `ESRCH`.
- **Why**: `IoPath::Pagemap` previously looked up the live task by `Tid` on every read, and `refresh_pseudo` could serve stale open-time content at offset 0 for an already-reaped process.
- **Tradeoffs**: The first read at offset 0 of a process procfs file performs one `pseudo::gone` check under the BKL.
- **Watch out**: Non-zero offset reads still serve the existing snapshot buffer per Linux `seq_file` behavior, while only offset-0 reads regenerate and report `ESRCH`.
- **Source**: b51818cf

### D3: Per-request `IoFlags` thread `RWF_NOWAIT` and `RWF_APPEND` through AIO and `preadv2`/`pwritev2`

- **What**: `IoFlags { nowait, append }` and `read_file_with`/`write_file_with`/`vectored_with` thread per-request `RWF_NOWAIT` and `RWF_APPEND` through regular-file and FUSE I/O for native AIO and `preadv2`/`pwritev2` (`pvectored`) without mutating `OpenFile::flags`.
- **Why**: Native AIO needed per-request `RWF_NOWAIT` and `RWF_APPEND` without mutating the shared open file description, and `preadv2`/`pwritev2` previously rejected both flags.
- **Tradeoffs**: Internal helper signatures in `syscall/fs.rs` and `syscall/fuse.rs` are slightly wider while existing callers stay on `IoFlags::default()`.
- **Watch out**: Future per-request I/O flags should extend `IoFlags` rather than mutating shared `OpenFile::flags`.
- **Source**: 15347732, ab694aab

### D4: RAII `PosGuard` and `TwoPosGuard` serialize `f_pos_lock` updates across file I/O

- **What**: `PosGuard` (`lock_if`, `lock_if_with`, `lock_positioned`) and pointer-ordered `TwoPosGuard` serialize `pos_busy` across `lseek`, `read_file`, `write_file`, `writev`, `sendfile`, `copy_file_range`, `copy_data` and `splice`, keeping `take_pos`/`release_pos` private (alongside `open_tmpfs_size` for overlay-aware tmpfs size queries).
- **Why**: `lseek` and other position-moving paths raced with unlocked I/O, and regular-file and FUSE paths previously duplicated raw acquire/release logic.
- **Tradeoffs**: Holding `pos_busy` across multi-piece calls serializes concurrent position-based operations on one description, and external callers (`kernel/fuse`) acquire `f_pos_lock` exclusively through RAII `PosGuard`.
- **Watch out**: Helpers called while a `PosGuard` is held must receive `pos_held = true` to avoid self-deadlock, and any future non-RAII unlock pattern would need an explicit `PosGuard` method.
- **Source**: ab694aab, 3a90a0ef

### D5: Synchronous `writev` and kernel copies flush once via `write_sync` and propagate errors

- **What**: `vectored_inner` invokes `write_sync` once after the iovec loop and returns sync errors cleanly, and `sendfile`, `copy_file_range` and `splice` call `write_sync` for `O_SYNC`/`O_DSYNC` destinations.
- **Why**: Synchronous `writev` previously synced per iovec while masking sync errors, and kernel copy paths did not sync `O_SYNC`/`O_DSYNC` outputs.
- **Tradeoffs**: Multi-iovec synchronous writes defer syncing until after all iovecs rather than flushing per iovec.
- **Watch out**: Any new write or copy path targeting store or FUSE files must call `write_sync` and propagate its error.
- **Source**: ab694aab

### D6: `remove_privs` aligns non-exec `S_ISGID` clearing on writes with Linux 6.2+ `chown`

- **What**: `remove_privs` checks `CAP_FSETID` with `capable_wrt` and clears non-exec `S_ISGID` on writes when the caller is neither in the file's group nor holds `CAP_FSETID`.
- **Why**: Write-path `remove_privs` previously cleared `S_ISGID` only when the group execute bit was set, diverging from `chown` and Linux 6.2+.
- **Tradeoffs**: Setgid clearing relies on `Store::remove_privs` accepting `keep_sgid` atomically alongside mode and capability removal.
- **Watch out**: Privilege-removal rules must stay aligned between `syscall/fs.rs` and `Store::remove_privs` across writes, truncation and `chown`.
- **Source**: ab694aab

### D7: Document `EFBIG` on `INT64_MAX` memfd `ftruncate` on the development store

- **What**: `.agents/maps/kernel/fileio.md` records that extending a memfd to `INT64_MAX` with `ftruncate` returns `EFBIG` on the development store, whereas native Linux accepts that length.
- **Why**: `Pread64Test.Overflow` exposed a memfd size limit during `ftruncate` because memfds use unlinked store objects.
- **Tradeoffs**: `pread64_test` remains outside the regular gVisor differential suite.
- **Watch out**: The maximum object size may vary with the store's backing filesystem.
- **Source**: 48f1c17e
