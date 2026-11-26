# kernel/mm Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/mm.md` for the paired decision history (it still holds the decisions on the soft-MMU, the OOM killer, fork/copy-on-write and host backing made before they were split out into `kernel/mmu`, `kernel/oom`, `kernel/cow` and `kernel/hostmem`).
>
> Verified: 2026-11-10 (full mapping: 6 research concerns; 18 claims checked by 3 independent verifiers — 13 confirmed and 5 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification of regular-file `MAP_SHARED` `FS_IMMUTABLE_FL`/`FS_APPEND_FL` checks, and anonymous fault fills, mprotect ordering and munmap errors for fork CoW pages)

## Responsibilities

`kernel/mm` implements Linux address-space and VMA semantics on top of `kernel/mmu`'s soft-MMU and
`kernel/hostmem`'s host backing: per-process `Mm`/VMA tables, memory syscalls, brk, stack growth,
guest fault policy, `[vvar]`/vDSO mapping, file EOF/truncation/object-move updates, on-demand FUSE
mappings (`Fill`), kernel guest access (`UserSlice`) and `/proc/<pid>/maps`/core-dump views.

Root: `core/kernel/src/mm.rs` (excluding `kernel/mmu`'s entry population/consistency/code groups,
`kernel/oom`'s resident-memory measures/`Mm::release`, `kernel/cow`'s `fork`/`Copy-on-write`, and
`kernel/hostmem`'s `Host backing`), `core/kernel/src/syscall/mem.rs` (excluding `process_mrelease`),
`core/kernel/src/uaccess.rs` (`UserSlice`), the page-fault branch in `task.rs`, and `Cx` stack-growth
helpers in `kernel.rs`.

Outside the module: `kernel/cow`, `kernel/hostmem`, `kernel/mmu`, `kernel/oom`, `engine`,
`engine/dbt`, `kernel/ipc`, `kernel/futex`, `kernel/exec`, `kernel/time`, `kernel/procfs`,
`kernel/cgroup`, `kernel/signal`, `kernel/vdso`, `kernel/fuse`, `kernel/fileio` and `core/hal`.

## Key types

### Address space

- `Mm` — per-process guest address space (`Rc<RefCell<Mm>>` under the BKL; built unlocked at execve):
  owns `mmu` (dropped first), `vmas: BTreeMap<start, Vma>`, deferred-release `graveyard`, layout
  bounds (`brk_start`, `brk`, `mmap_top`, `start_stack`, `stack_low`), non-reused `id`, `shared_maps`
  (shared writable ranges for the fast futex path), FUSE-fill flag, loader/procfs/vDSO/membarrier/
  `mlockall` metadata, and per-mm handles for `kernel/mmu`, `kernel/cow` and `kernel/hostmem`.
- `Vma` — one guest mapping: range, guest prot, `Backing`, `may_write`/`may_exec`,
  `Arc<HostRegion>` (`kernel/hostmem`) + host pointer, file metadata (`file_len`, identity/version,
  mapped-file fd, display `name`/`ino`, optional `MountPin` `mnt` whose drop reports to
  `vfs::released`), SysV `shm`, optional `Fill`, and Linux VMA flags (locked, sticky `written`,
  growsdown, dump/fork/noreserve, sticky commit charge `accounted`, anonymous page offset
  `anon_pgoff`, logical `has_anon_vma` and fork identity `anon`).
- `Fill` pins the mapping's FUSE open. All its VMA pieces share that handle. Mappings of one
  FUSE inode share `FillPages`, including its sparse memfd, current size, filled runs and
  read-ahead state. It tracks previously filled pages, shared-write baselines and writable opens.
- `same_vma` joins adjacent pieces when their backing, permissions and permission limits, lock,
  grows-down, dump/fork flags, noreserve, charge, name and fork identity agree. Private anonymous
  offsets must be contiguous and the pieces must agree on whether they have an anon_vma. File mappings also require matching host and guest inode identities,
  contiguous file offsets and compatible FUSE opens and page caches. File-less shared mappings
  must be contiguous in one host region with the same SysV attachment.
- `Backing` — `Anonymous` (private anonymous, private `/dev/zero`), `PrivateFile` (private file
  mapping), `Shared` (shared file, shared anonymous, shared `/dev/zero`, GPU or SysV shm; also
  `[vvar]`, whose host memory is shared with forked children).
- `flags` — guest ABI values of the `MAP_*` flags the mm interprets.
- `Refill` (private-file piece remapped at old address after `MREMAP_DONTUNMAP`), `Reread` (written
  private-file piece reread after `MADV_DONTNEED`/`MADV_DONTNEED_LOCKED`), `AdviseRange`
  (host-page-aligned slice of a retained `Arc<HostRegion>` for unlocked non-destructive `madvise`),
  and `PopulateWalk`/`PopulateStep` (resumable state and unlocked `MADV_WILLNEED`/FUSE `Fill`
  yields for `MADV_POPULATE_READ`/`MADV_POPULATE_WRITE`).
- `WANTED` (thread-local) — the page of a `Fill` a kernel access found not read, for the dispatcher
  or a local result copy to service (`take_wanted`).
- `UserSlice` — an unchecked guest range passed to kernel-side accessors.

### Introspection

- `Region` — one `/proc/<pid>/maps` / `smaps` line.
- `DumpRegion`, `dump_filter` — core-dump segments and the `coredump_filter` bits (default `0x33`).

## Public entry points

- **Syscalls** (`syscall/mem.rs` → `Mm`): `mmap`, `mmap_fill`, `munmap`, `protect` (mprotect),
  `mremap` (`mremap_dontunmap`), `remap_file_pages`, `msync`, `madvise`, `mlock`/`mlock2`/
  `munlock`, `mlockall`/`munlockall`, `mincore`, `brk`. (`process_madvise` is `ENOSYS`;
  `process_mrelease` is `kernel/oom`'s; `mmap_gpu` backing is `kernel/hostmem`'s.)
- **execve / loader / faults**: `Mm::new`, `share_files`, `into_shared`, `set_layout`,
  `map_anonymous`, `map_vvar`, `find_free`, `set_brk`, `map_stack`, `set_start_stack`, `label`,
  `vdso_syscalls`; `fill_wanted`, `fault_past_eof`, `Cx::grow_stack`/`grow_stack_to`/`grow_for`,
  `is_mapped` (`cow_break` is `kernel/cow`'s; `mmu().translate`/`fault_in` `kernel/mmu`'s).
- **FUSE fills & kernel access**: `FillPages::new`/`size`/`has`/`window`/`window_from`/`store`/
  `notify_store`/`has_tracked`/`fd`, `take_wanted`, `has_fills`, `first_unread`,
  `next_unread_fill`, `invalidate_fill`, `invalidate_fill_code`; `read`, `write` (breaks CoW via
  `kernel/cow`), `translate` (no CoW break), `read_cstr`, `read_force`, `write_kernel`,
  `write_force`, `populate_mlock_step`, `mapped_above`, `check_mapped`.
- **Files, shm, futex & introspection**: `futex_key`, `shared_maps`, `id`; `file_truncated`,
  `writably_maps`, `maps_file`, `maps_ino`, `mapped_inos`, `set_mnt`, `mapped_mounts`,
  `next_msync`, `residency_chunk`; `attach_shm`/`detach_shm`/`shm_attachments`;
  `regions`, `residency`, `size`, `locked_bytes`/`locked_in`, `dump_regions`, `dump_page`.

## Data flow / lifecycle

### Creation and layout

- execve builds a fresh `Mm` (with a fresh `Loans` table) that shares the kernel-wide `FileMaps`;
  the loader fills it with the BKL released, and after the point of no return it is shared and
  installed.
- `set_layout` sets `mmap_top` from the `RLIMIT_STACK` at execve (capped at 8 MB for a secure
  exec): `STACK_TOP` minus the limit plus the stack guard gap, clamped between 1 GB + 8 MB and 5/6
  of the address space. An unlimited stack still gives a top-down layout with the largest gap.
- `STACK_TOP` is `1 << 47`. A position-independent main program loads at `0x5555_5555_0000`.
  Non-fixed `mmap` allocates top-down from `mmap_top` (`find_free`), 2 MB-aligning mappings ≥
  `LEAF_SPAN` (2 MB) when VA space permits (falling back to page alignment) to form `kernel/mmu` L2
  superpages, skipping `stack_guard_gap` (256 pages) below grows-down VMAs, floored at
  `vm.mmap_min_addr` (`MMAP_MIN_ADDR`, 32768, ≥1 page; global, writable with `CAP_SYS_RAWIO`).
- `map_stack` maps the arguments and auxv plus 128 KB (capped at the page-aligned limit, never
  below what the arguments use) at the top of one `MAP_NORESERVE` host region of
  `max(min(RLIMIT_STACK, 8 MB), mapped length)`, leaving the rest below as reserved growth room.

### vDSO and `[vvar]`

- The loader maps the vDSO image (`kernel/vdso`) as private anonymous memory written by the
  kernel. When the image is the host's vDSO, `map_vvar` first maps `[vvar]` right below it, as
  long as the host's vvar mappings and at the same distance, since the host's code addresses its
  data relative to itself: a `Shared` VMA, readable only (`may_write` and `may_exec` false, so
  mprotect asking for more is `EACCES`), on a `foreign` `HostRegion` (`kernel/hostmem`) at the
  host's vvar address. Only its first `data` bytes (the clock data the host's code reads) count as
  contents and get entries; the rest behaves like a file mapping past EOF (`SIGBUS`), as the
  time-namespace page does on Linux outside a time namespace.
- `[vvar]` is shared with forked children like any shared mapping, cannot be written by ptrace
  (`write_force` refuses shared mappings without write permission), cannot grow (`EFAULT`, checked
  before looking for room, Linux's `VM_DONTEXPAND`) or be duplicated by mremap (`EINVAL`), counts
  in no resident-memory measure, writes nothing to core files, and shows as private `r--p` in maps.
- `vdso_svc` says whether the vDSO's clock functions are svc stubs: set at execve for the built
  image, and by `vdso_syscalls` once a process using the address space enters a time namespace
  with offsets, which writes the stubs over the host image's clock entries (`write_kernel`) and
  queues the vDSO for code invalidation. It is copied at fork and never cleared.

### mmap and brk

- The syscall checks, in order: unknown prot bits (`PROT_BTI` and `PROT_MTE` included, `EINVAL`),
  an unaligned offset (`EINVAL`), the map type (`MAP_SHARED_VALIDATE` with unknown flags
  `EOPNOTSUPP`), `MAP_SHARED | MAP_ANONYMOUS | MAP_GROWSDOWN` (`EINVAL`), a fixed address below
  `vm.mmap_min_addr` without `CAP_SYS_RAWIO` (`EPERM`; for an anonymous mapping only with a
  non-zero length; for a file after its `EBADF` and zero-length `EINVAL`), then the file's own
  rules (a FUSE mapping gets its `Fill`; regular store mappings check access, noexec, inode flags
  — rejecting `MAP_SHARED` on a writable fd of an `FS_APPEND_FL` inode with `EACCES`, rejecting
  `MAP_SHARED | PROT_WRITE` on an `FS_IMMUTABLE_FL` inode with `EPERM`, and clearing `may_write` on
  read-only `MAP_SHARED` mappings of protected inodes so later `mprotect(PROT_WRITE)` returns
  `EACCES` — and seals before unsharing and pinning the store object), and `MAP_LOCKED` (`EPERM` when `RLIMIT_MEMLOCK` is
  0 without `CAP_IPC_LOCK`, `EAGAIN` above limit) or `mlockall(MCL_FUTURE)` (`EAGAIN` above limit).
  Private anonymous mappings record grows-down and lock flags at creation. After the mapping:
  `reap_shm` for `MAP_FIXED`, the label, write and exec denials, locking, and population
  (`MAP_POPULATE`, `MAP_LOCKED`; a FUSE mapping's pages are read then).
- Lengths round up to a page; zero or overflow is `EINVAL`.
- With personality(2)'s `READ_IMPLIES_EXEC` (which every execve clears, as arm64's
  `SET_PERSONALITY` does), a readable mmap is made executable unless it maps a file on a noexec
  mount (do_mmap), mprotect adds execution to each VMA that may execute (`may_exec`, as
  do_mprotect_pkey does per VMA, so one call can leave mixed permissions), and brk's heap is
  executable (arm64's `VM_DATA_DEFAULT_FLAGS`); a heap grown with other permissions than its last
  part becomes a VMA of its own.
- `MAP_FIXED` / `MAP_FIXED_NOREPLACE`: the address must be aligned and the end at most `1 << 48`
  (`EINVAL`, after the syscall's `EPERM`). `NOREPLACE` on an occupied range is `EEXIST`; otherwise
  the old range is unmapped first, before host allocation, the permission check, the fd copy and
  the map-count check, so a later failure leaves a hole.
- A hint is rounded down to a page and raised to `vm.mmap_min_addr` (Linux's `round_hint_to_min`),
  and used if it ends at or below `mmap_top`, is free, and stays clear of the guard gap below a
  grows-down VMA above it.
- Host backing, `FileMaps` sharing, content-version trust, 16 KB alignment and commit accounting
  belong to `kernel/hostmem`. A FUSE file maps its inode's memfd with the permissions of the
  guest open, without a content version or `FileMaps` entry. Its `file_len` stays zero.
- `new_vma` initializes `locked` from `mlockall(MCL_FUTURE)`. Once the mapping has its file
  and page-tracking state, `insert_vma` enforces `vm.max_map_count` (default 65530, writable
  through procfs) and builds the initial page-table entries (`kernel/mmu`). A new private
  anonymous mapping starts with `anon_pgoff = start / PAGE_SIZE`. Until its first write,
  reads can translate through write-protected entries and leave its anonymous RSS at zero.
- `brk`: below `brk_start` returns the current break; growth needs the range free; it grows in
  place inside the heap's host region when the last part is anonymous, unnamed, with the heap's
  permissions, charge and VMA flags and no other VMA on that host range (discarding the host range
  first), else at the first heap page reserves 256 MB (`MAP_NORESERVE`) for growth of at most that,
  else falls back to a separate accounted anonymous mapping. Shrinking unmaps. brk ignores
  `mmap_top`, the guard gap and `vm.mmap_min_addr`, and there is no `RLIMIT_DATA` or `RLIMIT_AS`
  enforcement; under `mlockall(MCL_FUTURE)`, growth enforces `RLIMIT_MEMLOCK` (returning the old
  break on failure) and populates new pages unless `MCL_ONFAULT`.

### Mappings read on demand (`Fill`)

- Page-table entries build eagerly for small/executable mappings and lazily otherwise (`kernel/mmu`);
  `PROT_NONE` gets none. FUSE and tmpfs mappings have their own fault paths. Without host pagemap,
  ordinary private file mappings prefill reads and record private host pages on first write.
- A file backed by tmpfs pins its mapped object. Each fault admits one guest page against the
  backing mount’s quota before installing a translation. A read fault installs a read-only entry.
  The first shared write publishes the backing file's mtime and ctime. Private mappings track written pages
  independently of the file. Hole punching and `MADV_REMOVE` revoke aliases before freeing pages.
- A `Fill` VMA keeps `file_len` 0, so `map_pages` and every other path sizing by `file_len`
  (mprotect, mremap, fork, populate, truncation) build none of its entries, even when executable;
  only `fault_in` does, for a page already read, and then for the runs read within its 2 MB leaf
  range. A FUSE `INVAL_INODE` notification expires cached attributes. With a nonnegative offset,
  it also revokes page-table entries and executable translations for the affected pages in every
  address space that maps them, then marks those pages stale in `FillPages`.
  A subsequent fill refreshes the EOF, including for a fault beyond the old end. Shared writable
  aliases get a baseline so writeback can send only contiguous runs of changed bytes.
- Reading a page (`kernel/fuse`'s `fill`): `Fill::window` picks the pages not read around it
  (normally 32 starting 16 before it; from it, twice the last read when it continues that read or
  twice the run read just before it, between 32 and 512), clipped to the runs already read and
  EOF; the daemon is asked with the BKL released, and `store` writes the pages still missing into
  the memfd with `pwrite`, recording the whole window only when the reply reaches `Fill::size`,
  the single page on confirmed 0-byte EOF, and otherwise only complete pages returned (`kernel/fuse`
  retries from `window_from(page)` when backward read-around stopped short and loops on partial-page
  replies until a full page or EOF). A refill merges local shared stores with the new daemon bytes.
  Private host copies retain their contents.
- A kernel access (`read`, `write`, `read_cstr`, `write_kernel`) meeting a page of a `Fill` mapping
  not yet read fails with the internal `FUSE_RETRY` and records the page in `WANTED`; the syscall
  dispatcher normally reads it and runs the syscall again (`kernel/process`). Socket result
  copies fill pages locally after recvfrom, recvmsg and accept4 have obtained their result;
  recvmmsg handles missing pages within the current record. `read` and `write` go page by page, so a copy can stop partway. `write_kernel` checks
  the whole range first (any permission,
  `PROT_NONE` fills included), before changing anything, and gives `PROT_NONE` anonymous memory it
  writes prot-0 entries.
- Debugger reads (`read_force`) walk page by page without changing VMA permissions. CoW loans
  read the owner's page and untouched anonymous reservations read as zeros. File growth refreshes
  the accessible extent. Holes and foreign vvar pages stop the read. A missing FUSE page requests a fill.

### Guest page faults (task run loop, under the BKL, in this order)

1. A write fault where `cow_break` (`kernel/cow`) succeeds → re-execute.
2. The page now translates (another thread fixed it while this one waited for the BKL) → re-execute.
3. `try_fault_in` (`kernel/mmu`) succeeds → re-execute. The first private anonymous write
   records an identity for the logical VMA and upgrades present entries of the faulting host
   piece. Anonymous leaf-window fills skip CoW pages. A read or execute fault on a missing CoW
   page installs only its owner-backed entry with write permission stripped. A tmpfs page allocation failure delivers
   `SIGBUS` / `BUS_ADRERR`.
4. A page of a `Fill` mapping not yet read and allowing the access (`fill_wanted`) → read it through
   the daemon (above) and re-execute; a signal arriving before the daemon took the read is
   delivered first and the access faults again; a read error → `SIGBUS` / `BUS_ADRERR`.
5. `fault_past_eof`: checks VMA permissions first (`v.prot & need == 0` falls through to step 7's
   `SIGSEGV` / `SEGV_ACCERR`); otherwise past EOF in an ordinary file mapping whose file has grown →
   map the new part and re-execute (a `Fill` obtains its current EOF from the shared backing); otherwise past EOF
   → `SIGBUS` / `BUS_ADRERR`.
6. Stack growth (`grow_down`) succeeds → re-execute.
7. Otherwise `SIGSEGV`: `SEGV_ACCERR` if the address is mapped, else `SEGV_MAPERR`.

"Re-execute" forces no signal and leaves the PC on the faulting instruction (already-pending
signals may still be delivered).

### munmap, mprotect, mremap

- VMAs are only ever split (`split_at` advances file or anonymous page offsets and host pointers), never merged;
  `same_vma` tells which pieces Linux would have as one VMA.
- `munmap`: an unaligned address, zero or overflowing length or an end past 2^48 is `EINVAL`;
  `ENOMEM` can result from a three-way VMA split at `vm.max_map_count`, a failed CoW recall or
  a page-table allocation during superpage demotion. It moves removed host
  regions to the `graveyard`, clears `vdso` when overlapping it, sets `dirty`, records executable
  ranges in `code_ranges`, returns borrowed pages (`kernel/cow`), and the syscall reaps SysV
  segments left without attachments.
- `mprotect` (`protect`, Linux's `do_mprotect_pkey`): unknown prot bits (`PROT_SEM` included) or
  both grows bits are `EINVAL` at once; an unaligned address is `EINVAL`; then a length of 0
  succeeds and an overflowing one is `ENOMEM`. The VMAs from the first one ending above the
  address are changed in turn; a gap (`ENOMEM`) or a VMA refusing the permissions
  (`may_write`/`may_exec`, `EACCES`) stops it with the VMAs before it already changed. With
  `PROT_GROWSDOWN` the range starts at the start of the Linux VMA holding that first VMA, which
  must grow down (`EINVAL`; `ENOMEM` if it starts at or above the end), so it reaches the parts the
  mapping grew by; `PROT_GROWSUP` is `EINVAL` once the range is found. A `cow` VMA is copied
  (`unshare` remaps ordinary files and copies private pages as at fork; a `Fill` VMA maps its host file privately again, copies the pages
  it changed after reading them and drops its entries) before it becomes writable, and a
  `reserved` region gets real host memory (`back_reserved`) before it becomes accessible.
  Adding private write permission sets the commit charge unless the mapping has `MAP_NORESERVE`.
  The charge survives later permission changes. Tracked file pages revoke their entries on a protection change.
  For other mappings, a successful permission downgrade sets `dirty`. Before granting access to a private anonymous VMA
  with fork CoW pages, mprotect installs their owner-backed entries under the old non-writable
  permissions. It then changes the range permissions and grants write only outside the CoW pages.
  A failed permission change preserves the VMA prot and queues any needed rollback invalidation.
- `mremap`: the syscall checks the flags (`MREMAP_DONTUNMAP` needs equal lengths) and gives `EPERM`
  for a fixed target below `vm.mmap_min_addr` before anything else. Then Linux's order: no mapping
  at the old address is `EFAULT`; a `MREMAP_FIXED` target is validated (`EINVAL`) and unmapped and
  a shrunk tail unmapped; then the rest of the old range must lie in one Linux VMA (`EFAULT`,
  `same_vma`, as Linux before 6.17). Shrinking without a target only unmaps the tail. Growing in
  place needs the old end to be a VMA end, free space above and a new end at or below `mmap_top`.
  Reservations grow without host memory. Shared anonymous and SysV mappings extend the same
  VMA, with contents capped at the original backing extent. A backed private anonymous tail
  can reuse spare bytes when its host region has a single strong reference. It discards those
  bytes before mapping them. Other supported mappings allocate a continuation piece with the next offset
  and the source flags. A file or FUSE continuation maps the next part of the same file.
  Private anonymous moves preserve offsets across all pieces of a faulted logical VMA.
  For a logical VMA without an anonymous identity the destination address supplies the new
  offset, so it can join compatible neighbours. In either case an extension continues from
  the moved tail. Growing or duplicating (`old_len == 0`) a locked VMA enforces `RLIMIT_MEMLOCK` (`EAGAIN`, after
  any `MREMAP_FIXED` target unmap) and populates the added pages unless `MCL_ONFAULT`. Shared
  anonymous memory and SysV
  segments retain their backing region across shrink, growth and moves. Regrown pages alias the
  original bytes up to the region's end and fault with `SIGBUS` beyond it. A move settles CoW
  (`kernel/cow`), re-points host memory, moves PTEs, updates SysV shm attach bases (`v.shm`),
  and updates `vdso` when the whole vDSO moves (or clears it on a partial move).
- A move (growing with `MREMAP_MAYMOVE` and no room in place, `MREMAP_FIXED`,
  `MREMAP_DONTUNMAP`) is `ENOMEM` before anything changes unless the address space stays more
  than three VMAs below `vm.max_map_count` (`move_room`, 6.1's `move_vma`), with two more for a
  target's unmapping (`mremap_to`); the moved pieces go back in without the count check
  (`place_moved_vma`). A partial PTE move on allocation failure is reversed into the retained
  source tables before the temporary destination ranges are withdrawn. Executable ranges at
  the temporary destination are queued for invalidation.
- `MREMAP_DONTUNMAP` follows 6.1's order: no mapping at the old address `EFAULT`, the target
  `EINVAL`, the margin `ENOMEM`, the target unmapped, the one-VMA rule `EFAULT`; it splits nothing
  before these, then checks room for the endpoint splits and the actual remnant count.
  At the old address one empty anonymous VMA starts with the old address's page offset
  and no anon_vma. A partial remnant has a boundary with faulted source fragments until
  a later merge. A private FUSE remnant remaps the same memfd, retaining its fill
  and zero `file_len`. Ordinary private files produce one `Refill` per compatible run of
  retained descriptors, mount pins, tmpfs mappings and interpreter opens. The syscall
  maps those descriptors even after unlink. Shared aliases coalesce over contiguous spans
  in the same host region and attachment with compatible pins and one accessible prefix.
  All remnants keep their source permissions, commit charge and non-lock flags. The syscall calls
  `reap_shm`. `shmat` also refuses non-zero fixed addresses below `vm.mmap_min_addr` without
  `CAP_SYS_RAWIO` (`EPERM`).
- `mremap` with an old length of 0 duplicates (6.1's "duplicate shm area"): the VMA holding the
  address (`EFAULT` if none) must be shared (`EINVAL`; a `MREMAP_FIXED` target is validated and
  unmapped before this check), and without `MREMAP_MAYMOVE` it is `ENOMEM`; no margin is asked. A
  shared file mapping maps the file again from the address's offset for the new length; shared
  anonymous memory and System V segments get a VMA on the same host memory, which may run past the
  source VMA to the end of the region and past that has no contents (`SIGBUS`). A segment's copy is
  a new attach base, so it counts as one more attachment and shmdt at its address detaches it.
- `remap_file_pages`: a non-zero prot is `EINVAL`; start and size are rounded down; the range must
  lie in contiguous shared pieces of one host file with matching protections. FUSE pieces must
  also retain the same open handle and access limits (`EINVAL` on mismatch; shared anonymous memory
  and segments are refused); it maps the file again with `MAP_SHARED | MAP_FIXED`, keeping the
  label, FUSE page source, exec denial and lock, and populates unless `MAP_NONBLOCK`.
- `msync`: flags and alignment `EINVAL`, overflow `ENOMEM`, zero-length succeeds; walks VMAs in
  order via `next_msync`, skipping unmapped gaps (returning `ENOMEM` at the end), stopping on
  `MS_INVALIDATE` over a locked VMA with `EBUSY` (preceding earlier gaps), and under `MS_SYNC`
  syncing each shared host file slice with the BKL released (retaining `Arc<HostRegion>`) and
  writing changed shared FUSE pages to the daemon before requesting a data sync. `mincore`:
  alignment `EINVAL`, range overflow or above `1 << VA_BITS` `ENOMEM`, `vec` above `1 << VA_BITS`
  `EFAULT`; walks contiguous mapped VMAs from `addr` in chunks of at most `PAGE_SIZE` pages
  (`residency_chunk`), writing each chunk to `vec` without growing the stack and stopping at the
  first unmapped page (`ENOMEM`) or write fault (`EFAULT`); reserved pages report 0 and borrowed
  pages 1.
- `mlock`/`mlock2`/`munlock` follow `do_mlock` / `apply_vma_lock_flags`: the length plus the offset
  in the page is page-aligned with wrapping arithmetic; after mlock's `RLIMIT_MEMLOCK` check
  (`EPERM` with a limit of 0, `ENOMEM` above it; skipped with `CAP_IPC_LOCK`) a range that wraps
  past the end is `EINVAL` and an empty one succeeds; `set_locked` walks contiguous mapped VMAs
  from `start` and stops at the first unmapped gap (`ENOMEM`, leaving earlier contiguous VMAs
  updated, later VMAs untouched, and skipping population); on a fully mapped lock without
  `MLOCK_ONFAULT`, `populate_range` (`populate_mlock_step`) fetches missing FUSE `Fill` pages
  unlocked via `fuse::fill` (`ENOMEM` on daemon read error, `EINTR` on kill), stops at the first
  `PROT_NONE` VMA (`ENOMEM`, leaving the range locked), skips read-only private anonymous VMAs so
  RSS stays 0 and CoW stays intact, and settles CoW plus atomically write-faults writable private
  anonymous VMAs so real private host pages are resident. `mlockall(MCL_CURRENT)` checks the whole
  size (`PROT_NONE` reservations included) against the limit, locks every VMA and populates
  (including cold FUSE `Fill` pages, ignoring errors) unless `MCL_ONFAULT`; `MCL_FUTURE` without
  `MCL_CURRENT` checks only `RLIMIT_MEMLOCK != 0` (`EPERM` when 0 without `CAP_IPC_LOCK`), and new
  mappings (`mmap`, `brk` growth, `shmat`) and growth of locked VMAs (`mremap`, `grow_down` stack
  growth) enforce `RLIMIT_MEMLOCK`.
- `madvise`: alignment/length/unknown advice (counted as unimplemented) `EINVAL`; length 0 succeeds.
  Walks mapped VMAs in order like Linux 6.1's `do_madvise`: unmapped gaps are skipped and reported
  as `ENOMEM` at the end, while per-VMA errors (`EINVAL` on locked/foreign/GPU VMAs for
  `MADV_DONTNEED`/`FREE`/`COLD`/`PAGEOUT`, foreign/GPU for `MADV_DONTNEED_LOCKED`, non-private-anon
  or `[vdso]` for `MADV_FREE`, non-private-anon for `MADV_WIPEONFORK`, `EINVAL`/`EACCES` for
  `MADV_REMOVE`, `EINVAL`/`EFAULT` for `MADV_POPULATE_READ`/`WRITE`, or split `ENOMEM`) stop
  immediately (overriding earlier gaps) while leaving earlier mapped portions applied. Flag advice
  (`DONTDUMP`/`DODUMP`, `WIPEONFORK`/`KEEPONFORK`, `DONTFORK`/`DOFORK`) splits each mapped VMA at
  slice ends and sets the flag. `MADV_COLD`/`MADV_PAGEOUT` (`check_lru`) and `MADV_FREE`
  (`check_free`) validate every mapped VMA in range via `check_vmas`. Non-destructive hints
  (`NORMAL`/`RANDOM`/`SEQUENTIAL`/`WILLNEED`) prefill RO non-FUSE file soft PTEs up to 4 GB/call
  for `WILLNEED` (`prefill_file_ptes`), fetch missing FUSE `Fill` pages unlocked for `WILLNEED`
  (`willneed_fuse` → `next_unread_fill` + `fuse::fill`, advisory regardless of guest `prot`), and
  forward non-FUSE ranges to `appine_hal::advise` unlocked via coalesced `AdviseRange`s clipped to
  `file_len` (skipping reserved/foreign/GPU/`Fill` VMAs; `NORMAL`/`RANDOM`/`SEQUENTIAL` file-backed
  only; `WILLNEED` skips untouched anon) before reporting any gap as `ENOMEM`.
- `MADV_POPULATE_READ` / `MADV_POPULATE_WRITE` (`madvise_populate` → `populate_step`): check guest
  `PROT_READ`/`PROT_WRITE` and refuse `[vvar]`/GPU (`EINVAL`), refresh stale file extents, fault
  tmpfs (charging quota and updating shared write times) and software-tracked private files, read
  missing FUSE `Fill` pages unlocked (`EINTR` on signal, `EFAULT` on read error or past EOF), warm
  regular file slices ≥ 64 KB with unlocked `MADV_WILLNEED`, preserve CoW on `POPULATE_READ` while
  settling CoW and atomically write-faulting (`populate_write_host`) on `POPULATE_WRITE`, install
  missing soft PTEs, and stop with `EFAULT` at the first page past EOF.
- `MADV_DONTNEED` / `MADV_DONTNEED_LOCKED` (`discard_range`): `MADV_DONTNEED_LOCKED` allows
  `mlock`'d VMAs without unlocking them; both refuse foreign (`[vvar]`) and GPU VMAs (`EINVAL`).
  Private anon returns to host and zeroes (CoW settled via `kernel/cow`); written private file
  pages before EOF unshare first if marked `cow` (so reverting never corrupts a fork peer), then
  revert via `kernel/hostmem`'s `discard_file_host` (whole host pages) and `Reread`s read from the
  store (`fill_private`, zeros past EOF or open failure; `Fill` partial host pages reread from its
  memfd so entries stay). Executable ranges queue code invalidation; shared/unwritten VMAs
  untouched; vDSO refills from kernel image (with svc stubs when `vdso_svc`).
- `MADV_REMOVE` (`remove`): per-VMA check (`EINVAL` on locked, private anon or GPU; `EACCES` on
  other private or never-writable, 6.7); shared host ranges use `remove_host`, tmpfs and FUSE
  ranges punch holes through tmpfs / the daemon. Neither path requests code invalidation.

### Stack growth

- `grow_down` refuses pages below `vm.mmap_min_addr` and addresses already mapped. It applies when
  the nearest VMA at or above the address is `growsdown`. It refuses if the single nearest VMA
  below is non-growsdown, accessible and closer than 256 pages (`stack_guard_gap`; a `PROT_NONE` or
  growsdown neighbour is not looked past), if the new stack size exceeds the current
  `RLIMIT_STACK`, or if the growsdown VMA is locked and growth would exceed `RLIMIT_MEMLOCK`.
  Otherwise it extends into the reserved room below, or maps a new chunk in a host
  allocation of `clamp(size, grow, limit − size)` bytes (exactly the growth if that fails) with the
  chunk at its top, so the VMA count grows only logarithmically; the chunk takes the flags of the
  VMA above it and needs room for one more VMA.
- The kernel grows a stack itself at syscall entry when SP is below the main stack (arm64 has no
  red zone), before writing a signal frame, and when a kernel access to unmapped memory fails
  (`grow_for`, as Linux's fault handler does): the shared syscall helpers (`get`/`put`), read,
  write and readv buffers, getdents64, vmsplice, waitid and FUSE's device ioctls and prefault go
  through `Cx::read_user`/`write_user`, and `/proc/<pid>/mem` accesses grow within the accessor's
  `RLIMIT_STACK`. Other direct `Mm::read`/`write` callers do not grow it.
- `MAP_GROWSDOWN` is honoured only for private anonymous mappings (including private `/dev/zero`);
  `MAP_SHARED | MAP_ANONYMOUS` with it is `EINVAL`, and file or shared `/dev/zero` mappings ignore
  it. An mmap'd growsdown VMA has no reserved room, so its first growth maps a new chunk.

### Files: EOF and truncation

- Whole pages past EOF have no entries. Ordinary shared and private mappings keep the file open
  across descriptor close, VMA splits, fork and mremap. Private mappings share a retained descriptor
  per host inode across a fork family. A store pin takes precedence over an unpinned descriptor from
  the ELF loader. Guest instruction faults and kernel copies retried through
  `grow_for` check the current extent. If a private mapping has anonymous or shared read-only backing after fork,
  caching or mprotect, only the previously inaccessible tail gets a fresh private host mapping.
- truncate, ftruncate and `O_TRUNC` that shorten a file first call `file_truncated` on every
  address space (entries past the new end are removed, executable ranges are queued for
  invalidation, `dirty` is set; a `Fill` uses its old logical extent) and sync each one that changed, the
  current one included (one that cannot be borrowed is skipped), and only then shorten the host
  file: no thread can reach the dropped tail through a stale translation, so an access there faults
  into the kernel and gets the guest's `SIGBUS` once the BKL is free. A host truncation that then
  fails leaves the mappings' EOF at the requested length.
- Private and shared mmap of a named store file first give the inode its own backing object, including
  on read-only opens. The VMA retains a duplicate of its locked open description. Splits, fork
  and mremap keep the pin. Cached host views use a separate open description. Clones and overlay
  copy-up copy bytes when either object is pinned.
  A Files app truncate clips affected address spaces in each running kernel before the host
  shrink; guest faults can then observe EOF or regrowth. Private mappings retain their backing.

### Introspection and teardown

- After guest exec, `exe_open` holds the main program's inotify open record. Fork shares it.
  Non-overlay file-backed interpreter VMAs share their open record across splits and fork.
  Their last unmap releases it. Leaving the address space with no users releases its remaining exec opens.

- `regions` labels each VMA (file name, else `[stack]` for the VMA containing `start_stack` and the
  contiguous same-prot growsdown VMAs below it, else `[vdso]`, else `[vvar]` for the foreign VMA,
  else `[heap]` inside `[brk_start, brk)`) and joins adjacent pieces of one Linux VMA (`same_vma`,
  plus the same label). procfs escapes a newline in a file name as `\012`.
- `dump_regions` applies `coredump_filter` and `MADV_DONTDUMP` (the vDSO is dumped whole anyway; a
  written private file VMA follows `ANON_PRIVATE`; ELF headers' first pages follow their own bit)
  and writes nothing of `[vvar]`; the core-dump writer leaves holes where `residency` reports pages
  absent in sparse regions. For private anonymous memory, `ANON_PRIVATE` selects every piece
  of a logical VMA with an anon_vma. FUSE mappings fetch missing pages before ELF checks and segment writes.
- `Mm` drop leaves its code group (`kernel/mmu`), releases CoW (`kernel/cow`), defers the page
  table (`kernel/hostmem`), then drops VMAs and graveyard. RSS measures live in `kernel/oom`.

## Dependencies (inbound / outbound)

### Inbound

- `syscall/mem.rs`, `syscall/mod.rs` (stack growth at entry, `take_wanted`), `kernel/fuse` (`Fill`,
  `prefault`, `invalidate_fill`), `kernel/process`/`kernel/exec`/`kernel/ns`/`kernel/signal` (execve, setns
  `vdso_syscalls`, faults, `Cx` stack growth, signal frames), `kernel/ptrace` (`read_force`, `write_force`),
  `kernel/futex` (`futex_key`, `translate`, `id`, `shared_maps`), `kernel/ipc` (`attach/detach_shm`),
  `kernel/files`/`kernel/fileio` (`ETXTBSY`, seals, truncation, clones, unsharing), `kernel/procfs`,
  `kernel/oom`, `kernel/mmu` (VMAs/EOF/sync inputs), `kernel/cow`.

### Outbound

- `kernel/cow` (`cow_break`, `cow_settle`, `cow_unmap`/`give_back`, `cow_pages`/`cow_entries`/
  `write_around`, `discard_unlent`, `return_loans`); `kernel/hostmem` (`HostRegion`, `FileMaps`,
  `content_version`, `WRITABLY_SHARED`, `discard_host`/`discard_file_host`/`remove_host`,
  `mmap_gpu`); `kernel/mmu` (PTE builders/movers, `sync`, `quiesce`, `shootdown`, code groups).
- `appine_hal` (`populate`, `fstat`, `msync`, `advise`, `mincore`, memfds,
  `page_size`); `kernel/vdso` (image/svc image, clocks, host vvar); `kernel/fuse` (`Fill::source`);
  `kernel/vfs`/`kernel/fileio`/`kernel/mount`/`kernel/cred`/`kernel/ipc` (`reap_shm`).

## Invariants and gotchas

- Follow `kernel/mmu` (release host memory only after thread flushes; keep PTEs valid at each step
  since `shootdown` does not pause threads; record `dirty`/`graveyard`/`code_ranges` for `sync`),
  `kernel/cow` (never write lent/borrowed pages in place; break/settle CoW before mutating), and
  `kernel/hostmem` (never dereference `RESERVED_HOST`; never discard/unmap `foreign`/`gpu` regions;
  release via `HostRegion` drop).
- A `Fill` VMA has `file_len` 0 and entries only for valid pages. A previously filled page can
  retain private CoW data after invalidation. Fork and unshare compare all previously filled
  pages within EOF when copying private contents to a new host file mapping.
- Every private anonymous page with content has a PTE (except borrowed pages in `PROT_NONE`, which
  `kernel/cow` adds): kernel writes, mlock and `MAP_POPULATE` fill entries, mremap moves them, and
  `PROT_NONE` keeps prot-0 entries (`kernel/cow` lending and `kernel/oom` RSS rely on this).
- `Mm` (`Rc<RefCell>`) is BKL-only (checking builds assert no borrow across BKL release);
  `shared_maps` is shared across threads for the fast futex path. `install_vma`, `grow_tail` and `move_range`
  publish writable shared ranges in `shared_maps` before installing or moving PTEs (rolling back if
  `map_pages` fails), and `munmap`, `move_range`, and `deny_write` prune removed/non-writable
  ranges after old PTEs are gone.
- The host's `vm.max_map_count` is shared by the whole app process, so the guest limit is enforced
  per address space.
- VMAs never merge; adjacent anonymous VMAs are separate host mappings and are only joined (as
  `same_vma`) for display, mremap's one-VMA rule, `PROT_GROWSDOWN`, fork's `anon` identities and
  fork's commit estimate. Code creating a VMA that continues another (stack
  chunks, mremap growth) must copy the flags `same_vma` compares.
- Guest pages are always 4 KB (`AT_PAGESZ` 4096) whatever the host page size.
- Host `mincore` reports pages swapped to zram as absent; RSS (`kernel/oom`), mincore(2), pagemap
  and core-dump holes still use mincore.

## Confirmed bugs / technical debt

- In-place growth still costs a host piece and a VMA slot for a file mapping or when a backed
  private anonymous tail lacks exclusively held spare backing. A split sibling, loan, active
  host advice or pending graveyard release can keep the region shared. Moving the host allocation
  would invalidate live guest translations or loans. Shared-file DONTUNMAP aliases spanning
  distinct host regions retain one remnant per compatible region.
- Appine creates a fresh anonymous remnant even on a partial DONTUNMAP or a move of a previously
  relocated mapping. Linux 6.1 unlinks the old anon_vma only on a whole-VMA move and retains the
  old page offset.
- A failure in `Mmu::unmap` can interrupt munmap after it has taken borrowed records
  and removed the current VMA. A failed superpage demotion can leave surviving PTEs without
  their backing records.

## Open questions

- Why is `STACK_TOP` `1 << 47` while the page table covers 48 bits and `MAP_FIXED` may reach
  `1 << 48`?
