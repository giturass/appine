# Fork and copy-on-write (kernel/cow) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/cow"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/cow made before it was split from kernel/mm keep their `kernel/mm` tags and live in `.agents/decisions/kernel/mm.md`: D6, D10, D11, D19, D24, D25 and the fork/copy-on-write parts of D15, D16, D18, D20, D22, D31 and D39.

## Active

### D1: Fork and page-granular copy-on-write have a dedicated module

- **What**: kernel/cow owns the `fork` section (`Mm::fork`, `commit_too_big`, `carve`, `spare_below`) and the `Copy-on-write` section (`MmRef`, `Loan`, `PageHasher`, `Loans`, `Runs`, `Borrowed`, `Cow` and CoW `impl Mm` methods except `kernel/mmu`'s `shootdown`) in `core/kernel/src/mm.rs`.
- **Why**: Fork and page-granular copy-on-write (~820 lines across two contiguous sections of `mm.rs`) needed a focused map of their own.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/mm.md`, and section boundaries inside `mm.rs` live in `.agents/MODULES.md`.
- **Watch out**: Changes to `mprotect`, `munmap`, `mremap`, `MADV_DONTNEED`, `Mm::write`, futex writes or fork carving require reading `kernel/cow` alongside `kernel/mm` or `kernel/hostmem`.
- **Source**: 610d623f
