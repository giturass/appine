# Tier 1 dynamic binary translator (engine/dbt) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: engine/dbt"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on engine/dbt made before it was split from engine keep their `engine` tags and live in `.agents/decisions/engine.md`: D6–D10, D13–D16, D18, D23, D25, D27–D29, and the Tier 1 halves of D2, D5, D17, D20, D22 and D24.

## Active

### D1: Tier 1 dynamic binary translation has a dedicated module

- **What**: engine/dbt owns `dbt.c`, `emit.h`, the Tier 1 sections of `engine.h` and `core/engine/src/lib.rs`, and `core/engine/tests/dbt.rs`, while Tier 0 execution, CPU state and the fault guard stay in `engine` and the soft-MMU in `kernel/mmu`.
- **Why**: The 5,250-line Tier 1 translator needed its own map with headroom for ongoing optimization work.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/engine.md`, and shared header and Rust binding files span `engine`, `kernel/mmu` and `engine/dbt`.
- **Watch out**: Keep `struct appine_cpu` layout, TLB entry format and guarded-run lock registration synchronized with `engine` and `kernel/mmu`.
- **Source**: e4d7bbe5
