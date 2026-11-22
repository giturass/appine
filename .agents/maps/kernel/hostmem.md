# kernel/hostmem Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/hostmem.md` for the paired decision history (not yet created; decisions from before the split are D2, D3, D12, D14, D15, D17, D30, D45, D47 and the host-backing parts of D4, D18, D20, D27, D33 and D38 in `.agents/decisions/kernel/mm.md`).
>
> Verified: 2026-11-22 (split out of the kernel/mm full mapping of 2026-11-10 and its later maintenance; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-22 (targeted verification: HostRegion used-range tracking for oversized stack/heap reservations and recycled's `< 2 MB` `MAX_DISCARD` cap)

## Responsibilities

`kernel/hostmem` manages the host virtual memory backing every guest VMA inside the single app
host process:

- `HostRegion` ownership across anonymous, file, reserved (`PROT_NONE`), foreign (`[vvar]`) and
  coherent GPU mappings;
- kernel-wide read-only file-mapping sharing (`FileMaps`) and file content-version trust
  (`content::version`, `WRITABLY_SHARED`);
- host commit-accounting rules, 16 KB host-page alignment for file mappings and `SharedMemory`
  segments;
- process-wide anonymous range recycling (`recycled`) and pre-mapped `fork` pools (`spare`,
  `Carved`);
- BKL-deferred host unmapping and page-table freeing (`Unmapped`, `UNMAPPED`, `UNMAPPING`,
  `defer_unmaps`, `release_unmapped`);
- host-page-aware discard, hole-punching and non-zero copy primitives (`discard_host`,
  `discard_file_host`, `remove_host`, `copy_nonzero_pages`).

Root: in `core/kernel/src/mm.rs`, the `Host backing` section (`RESERVED_HOST`, `HostRegion`,
`SharedMemory`, `FileMaps`, `FileMap`, `content_version`, `content`/`WRITABLY_SHARED`, `Carved`,
`spare`, `Unmapped`/`UNMAPPED`/`UNMAPPING`, `defer_unmaps`, `release_unmapped`, `recycled`,
`discard_host`, `discard_file_host`, `remove_host`, `copy_nonzero_pages`) plus `Mm::mmap_gpu`'s
host-mapping retention contract.

Outside the module: VMA management, memory syscalls, fault policy and `[vvar]`/`Fill` semantics
(`kernel/mm`); `fork` and page-granular copy-on-write (`kernel/cow`); soft page tables and
shootdowns (`kernel/mmu`); resident-memory measures and the OOM killer (`kernel/oom`); BKL
acquisition/release (`kernel/process`); SysV IPC segment lifecycle (`kernel/ipc`); host
mmap/munmap/madvise wrappers (`hal`); GPU renderer mappings (`kernel/files`, `android/native`).

## Key types

- `HostRegion` — owns one host range (`base`, `len`). `anonymous: Some(reserve)` marks a private
  anonymous range that is recycled on drop; `used_start`/`used_end` (`AtomicUsize`) track the
  monotonic byte-offset hull of slices exposed to any VMA (full `0..len` by default, empty
  `len..0` for oversized stack/heap reservations via `new_anonymous_reserved` /
  `spare::anonymous_reserved`, widened by `note_used` on `insert`, `place_vma`, `extend_down` and
  `grow_heap`). `reserved` marks a `PROT_NONE` placeholder with no
  host memory, whose base is the fake address `RESERVED_HOST` (bit 55 set, in the host kernel
  half) and is never dereferenced. `foreign` marks host memory the kernel layer does not own and
  only reads (the host's vvar pages behind `[vvar]`): never unmapped or recycled. `gpu` holds an
  `Arc<dyn gpu::Mapping>` for coherent Vulkan render-node buffers: never unmapped or recycled
  here; the mapping owner releases the storage when dropped.
- `SharedMemory` — host backing of a SysV shm segment (private anonymous host memory, always
  commit-accounted).
- `FileMaps` — kernel-wide LRU cache (at most 128 `FileMap` entries) of read-only private file
  mappings, shared by all address spaces, keyed by `(device, inode, offset, length, ctime, size)`.
- `content` / `WRITABLY_SHARED` — process-wide set of `(dev, ino)` pairs that have ever been
  mapped shared from a writably opened descriptor (never cleared), plus `content_version` checking
  ctime stability.
- `recycled` — process-wide reuse pool of private anonymous host ranges keyed by `(len, reserve)`:
  at most 256 MB in total and 32 ranges per key; on return (`recycled::put`), discards only the
  host-page-aligned `[used_start, used_end)` sub-range (skipping `MADV_DONTNEED` if nothing was
  exposed) and keeps the range only when that host-aligned discard span is strictly below
  `MAX_DISCARD` (2 MB, one 4 KB-page arm64 PMD) and `MADV_DONTNEED` succeeds (otherwise unmaps).
- `spare` — pre-mapped `MAP_NORESERVE` host pieces that `kernel/cow`'s `fork` takes while holding
  the BKL: two per length, at most eight lengths (least recently wanted evicted), falling back to
  `recycled` and then a host mmap.
- `Carved` — map of small child VMA starts to `(Arc<HostRegion>, host)` pieces carved from one
  `spare` region at fork.
- `Unmapped` / `UNMAPPED` / `UNMAPPING` — thread-local list of host ranges, anonymous ranges and
  page tables (`Mmu`) whose release is deferred while the BKL is held, and a global atomic byte
  count of what is still pending (page tables not counted).

## Public entry points

- **BKL hooks** (`kernel/process`): `defer_unmaps` when the BKL is taken; `release_unmapped`, then
  `spare::refill` when it is released.
- **Machine** (`kernel/boot`, `android/service`): `FileMaps::clear` from `Machine::trim_memory`.
- **SysV shm** (`kernel/ipc`): `SharedMemory::new`, `SharedMemory::len`.
- **Code groups and files** (`kernel/mm`, `kernel/mmu`): `content_version`,
  `FileMaps::get`/`insert`, `UNMAPPING` (read by `kernel/oom`).
- **Internal mm / cow primitives**: `HostRegion::reserved`, `spare::anonymous` /
  `spare::anonymous_reserved`, `recycled::take`/`put`, `discard_host`, `discard_file_host`,
  `remove_host`, `copy_nonzero_pages`, `Mm::mmap_gpu`.

## Data flow / lifecycle

### Host backing allocation and sharing

- All anonymous guest memory, private or shared (shared anonymous mappings, SysV shm), is private
  anonymous host memory: guest processes sharing it hold the same `Arc<HostRegion>` inside the one
  app process.
- Host backing by mapping kind (`kernel/mm` dispatches into these backing rules):
  - private anonymous `PROT_NONE` (not grows-down) → a `reserved` `HostRegion` (no host address
    space; backed only when made accessible or written by the kernel);
  - other private anonymous, shared anonymous and SysV shm → `recycled::take`, else a new host
    private anonymous mapping;
  - read-only private file with a trusted content version → a `FileMaps` hit (VMA marked `cow`),
    or a new read-only host mapping inserted into the cache (verified bundled musl executable
    mappings map their immutable `memfd` snapshot and share it through `FileMaps` under the
    snapshot's own device and inode);
  - other file mappings → host `mmap` of the store file's host object (read-write for private
    mappings);
  - a FUSE file → host `mmap` of its `Fill`'s memfd (`kernel/mm`);
  - a GPU mapping (`Mm::mmap_gpu`) → a shared, non-executable guest VMA over a page-aligned host
    mapping whose `HostRegion` retains the `gpu::Mapping` through fork, VMA splits, GEM close and
    TLB shootdown (growth and hole punching refused).
- A file has no trusted content version while its ctime is within the last 2 s, or once it has
  been mapped shared from a writably opened descriptor (`WRITABLY_SHARED`, never cleared, recorded
  even when the mmap then fails; sealed memfds count as not writable).
- Shared file mappings map the same host object file with host `MAP_SHARED`, so they stay coherent
  with `read`/`write`, which go to that file through the host page cache.
- On a 16 KB-page host, a file mapping covers the 16 KB-aligned host range around the target and
  points the VMA at the right 4 KB offset inside it.
- Host commit accounting: anonymous memory is requested as accounted only when the guest mapping
  is writable and not `MAP_NORESERVE` (Linux's `shmem_acct_size` also skips `VM_NORESERVE` for
  shared anonymous memory); SysV shm is always accounted. The main stack, stack chunks, the heap
  reservation and fork's `spare` and carved pieces are always host `MAP_NORESERVE`.

### Host-page discard and hole-punching

- `discard_file_host` passes whole host pages to host `MADV_DONTNEED` and returns the unaligned
  head/tail pieces (on 16 KB hosts, or the whole range if the host refuses). `discard_host` zeroes
  those partial pieces for anonymous memory; `kernel/mm`'s `MADV_DONTNEED` re-reads them from the
  store file for private file mappings.
- `remove_host` passes whole host pages to host `MADV_REMOVE` and zeroes partial host-page edges
  (or the whole range if the host refuses).

### Release of host memory

- Regions stay in `Mm::graveyard` (`kernel/mm`) until `kernel/mmu`'s `sync` has quiesced the other
  threads, so guest data races never touch memory already returned to the host.
- A `HostRegion` dropped while the BKL is held is queued in `UNMAPPED` and counted in `UNMAPPING`
  (`reserved`, `foreign` and `gpu` regions return immediately without unmapping or recycling).
- When the BKL is released (`release_unmapped`), deferred page tables (`Mmu`) are freed first,
  anonymous ranges go back to `recycled::put` one at a time (discarding only their host-aligned
  `[used_start, used_end)` sub-range with host `MADV_DONTNEED` and keeping them when that discard
  is strictly below 2 MB and within the 256 MB / 32-per-key caps, otherwise unmapping), file ranges
  are sorted and unmapped in coalesced contiguous runs, `UNMAPPING` is decremented with `Release`
  ordering, and then `spare::refill` tops the fork pool back up.
- Under the BKL, `kernel/cow`'s `fork` still calls host mmap when a needed length is missing from
  both `spare` and `recycled` (and for private mappings over 1 MB or growsdown VMAs without
  reserved room when `recycled` has no match), and `spare::anonymous` still unmaps inline the
  pieces of a length evicted from `spare`.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/mm`: allocates/drops `HostRegion`s, looks up and inserts `FileMaps`, checks
  `content_version` / records `WRITABLY_SHARED`, calls `discard_host`/`discard_file_host`/
  `remove_host`, installs `Mm::mmap_gpu`.
- `kernel/cow`: calls `spare::anonymous`, `Mm::new_anonymous`, `discard_host`,
  `copy_nonzero_pages`; borrowed pages hold `Arc<HostRegion>`.
- `kernel/process`: BKL hooks (`defer_unmaps`, `release_unmapped`, `spare::refill`).
- `kernel/oom`: checks `UNMAPPING` before running an OOM round; reads `FileMaps` and `HostRegion`
  flags (`reserved`, `foreign`).
- `kernel/ipc`: `SharedMemory::new` / `len`.
- `kernel/boot` / `Machine`: initial `FileMaps`, `FileMaps::clear` in `Machine::trim_memory`.
- `kernel/mmu`: `Mmu` dropped via `Unmapped::mmus` when `Mm` drops under the BKL.

### Outbound

- `appine_hal`: `map_anonymous`, `map_file`, `unmap`, `discard`, `remove`, `fstat`, `page_size`.
- `kernel/files`: `crate::gpu::Mapping` trait retained by `HostRegion::gpu`.

## Invariants and gotchas

- `RESERVED_HOST` (bit 55 set) is a fake base used only for VMA offset arithmetic and must never
  be dereferenced; any path accessing host memory must back a reserved VMA (`back_reserved`) or
  skip it first.
- `foreign` (`[vvar]`) and `gpu` regions must never be unmapped, recycled or discarded on drop,
  and any path touching a `Shared` VMA's host memory must respect `foreign` and `gpu`
  restrictions.
- Anonymous regions placed in `recycled` must succeed at host `MADV_DONTNEED` over their entire
  exposed `[used_start, used_end)` range first so guests never observe stale data from a prior
  process; a failed discard unmaps instead. Any path that allocates an oversized reservation with
  an empty used range (`new_anonymous_reserved` / `spare::anonymous_reserved`) or grows into one
  in place must call `HostRegion::note_used` before exposing or touching those pages.
- `recycled::put` keeps the host-page-aligned `MADV_DONTNEED` span strictly below `MAX_DISCARD`
  (2 MB, one 4 KB-page arm64 PMD) and unmaps regions at or above that threshold, avoiding a
  Linux 6.18–7.x arm64 minor page-fault livelock when full-PMD `MADV_DONTNEED` reclaims empty
  PTE tables on reused stack/heap regions.
- Any new path that frees host memory under the BKL must drop `HostRegion` (so `UNMAPPED` /
  `UNMAPPING` tracks it); `kernel/oom` relies on `UNMAPPING` to avoid killing while releases are
  still pending.
- All guest processes live in the one app process, and every guest mapping except a
  never-accessible `PROT_NONE` reservation and `[vvar]` takes host address space (some more than
  their size: the heap's and stacks' reservations, file mappings rounded to host pages). On hosts
  with a 39-bit user address space (512 GB, every 4 KB-page GKI kernel) they must all fit in it:
  large writable mappings such as ASan's shadow memory cannot be mapped there, and the guest
  address space is not shrunk to match.
- `FileMaps` keys verified bundled musl snapshots by their immutable memfd `(st_dev, st_ino)`,
  relying on the process-wide `OnceLock<Arc<BundledLibc>>` keeping the memfd open so its identity
  is never reused.

## Open questions

- Should `WRITABLY_SHARED` ever be cleared (for example when the inode is deleted)?

## To verify

- Whether the host kernel commit-accounts the read-write `MAP_PRIVATE` host file mappings used for
  private file VMAs that miss `FileMaps`: depends on host kernel rules, not repository code.
- Real 16 KiB-page hardware coverage for `Mm::mmap_gpu` coherent renderer mappings and 16 KB
  partial-page discard/re-read paths.
