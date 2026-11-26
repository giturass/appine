# Host backing and deferred release (kernel/hostmem) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/hostmem"`
>
> Last distilled: 2026-11-23 (HEAD = cc72b093)
>
> Decisions on kernel/hostmem made before it was split from kernel/mm keep their `kernel/mm` tags and live in `.agents/decisions/kernel/mm.md`: D2, D3, D12, D14, D15, D17, D30, D45, D47 and the host-backing parts of D4, D18, D20, D27, D33 and D38.

## Active

### D1: Host memory backing, caches and deferred unmapping have a dedicated module

- **What**: kernel/hostmem owns the `Host backing` section of `core/kernel/src/mm.rs` (`RESERVED_HOST`, `HostRegion`, `SharedMemory`, `FileMaps`, `FileMap`, `content_version`, `content`/`WRITABLY_SHARED`, `Carved`, `spare`, `Unmapped`/`UNMAPPED`/`UNMAPPING`, `defer_unmaps`, `release_unmapped`, `recycled`, `discard_host`, `discard_file_host`, `remove_host`, `copy_nonzero_pages`) plus `Mm::mmap_gpu`'s host-mapping retention contract.
- **Why**: Host-memory ownership, `FileMaps` sharing, anonymous recycling, fork spare pools and BKL-deferred unmapping (~590 lines in `mm.rs`) needed a dedicated map.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/mm.md`, and fork's spare pool lives alongside recycling and deferred unmapping rather than in `kernel/cow`.
- **Watch out**: Changes to VMA allocation, `MADV_DONTNEED`/`MADV_REMOVE`, BKL deferral, OOM `UNMAPPING` checks or GPU backing retention require reading `kernel/hostmem` alongside `kernel/mm`, `kernel/cow`, `kernel/process` or `kernel/oom`.
- **Source**: 610d623f

### D2: Anonymous recycling discards only exposed sub-PMD ranges and unmaps at 2 MiB

- **What**: `HostRegion` tracks an atomic `[used_start, used_end)` hull (empty on `new_anonymous_reserved` and `spare::anonymous_reserved`, widened via `note_used` on `insert`, `place_vma`, `extend_down` and `grow_heap`), so `recycled::put` discards only the host-page-aligned used slice and unmaps regions whose aligned discard reaches `MAX_DISCARD` (2 MiB).
- **Why**: Full-region `MADV_DONTNEED` across recycled 8 MiB stacks spanned four 2 MiB arm64 PMDs and triggered a 3.6–3.7M `minflt/s` host page-fault livelock on Linux 6.18–7.x arm64 CI runners upon stack reuse.
- **Tradeoffs**: Regions that actually expose `>= 2 MiB` fall back to `munmap` instead of recycling, and anonymous VMA insertions or in-place growths perform two relaxed atomic updates.
- **Watch out**: Any new path allocating reserved anonymous regions or growing one in place without calling `note_used` risks leaving stale data across reuse, and guest `madvise(MADV_DONTNEED) >= 2 MiB` through `discard_file_host` remains unchunked.
- **Source**: 23e3b01e

## Superseded

- ~~Whole-region `MADV_DONTNEED` recycling regardless of size in `kernel/mm` D14 (round 109)~~ → narrowed by **D2** in 23e3b01e (2026-11-22, cross-module predecessor in `.agents/decisions/kernel/mm.md`)
