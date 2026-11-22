# Host backing and deferred release (kernel/hostmem) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/hostmem"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/hostmem made before it was split from kernel/mm keep their `kernel/mm` tags and live in `.agents/decisions/kernel/mm.md`: D2, D3, D12, D14, D15, D17, D30, D45, D47 and the host-backing parts of D4, D18, D20, D27, D33 and D38.

## Active

### D1: Host memory backing, caches and deferred unmapping have a dedicated module

- **What**: kernel/hostmem owns the `Host backing` section of `core/kernel/src/mm.rs` (`RESERVED_HOST`, `HostRegion`, `SharedMemory`, `FileMaps`, `FileMap`, `content_version`, `content`/`WRITABLY_SHARED`, `Carved`, `spare`, `Unmapped`/`UNMAPPED`/`UNMAPPING`, `defer_unmaps`, `release_unmapped`, `recycled`, `discard_host`, `discard_file_host`, `remove_host`, `copy_nonzero_pages`) plus `Mm::mmap_gpu`'s host-mapping retention contract.
- **Why**: Host-memory ownership, `FileMaps` sharing, anonymous recycling, fork spare pools and BKL-deferred unmapping (~590 lines in `mm.rs`) needed a dedicated map.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/mm.md`, and fork's spare pool lives alongside recycling and deferred unmapping rather than in `kernel/cow`.
- **Watch out**: Changes to VMA allocation, `MADV_DONTNEED`/`MADV_REMOVE`, BKL deferral, OOM `UNMAPPING` checks or GPU backing retention require reading `kernel/hostmem` alongside `kernel/mm`, `kernel/cow`, `kernel/process` or `kernel/oom`.
- **Source**: 610d623f
