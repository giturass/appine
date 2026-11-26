# Tier 1 dynamic binary translator (engine/dbt) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: engine/dbt"`
>
> Last distilled: 2026-11-23 (HEAD = cc72b093)
>
> Decisions on engine/dbt made before it was split from engine keep their `engine` tags and live in `.agents/decisions/engine.md`: D6–D10, D13–D16, D18, D23, D25, D27–D29, and the Tier 1 halves of D2, D5, D17, D20, D22 and D24.

## Active

### D1: Tier 1 dynamic binary translation has a dedicated module

- **What**: engine/dbt owns `dbt.c`, `emit.h`, the Tier 1 sections of `engine.h` and `core/engine/src/lib.rs`, and `core/engine/tests/dbt.rs`, while Tier 0 execution, CPU state and the fault guard stay in `engine` and the soft-MMU in `kernel/mmu`.
- **Why**: The 5,250-line Tier 1 translator needed its own map with headroom for ongoing optimization work.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/engine.md`, and shared header and Rust binding files span `engine`, `kernel/mmu` and `engine/dbt`.
- **Watch out**: Keep `struct appine_cpu` layout, TLB entry format and guarded-run lock registration synchronized with `engine` and `kernel/mmu`.
- **Source**: e4d7bbe5

### D2: Tier 1 memop extension directions are tracked in a standalone handoff document

- **What**: `docs/dbt-memop-extensions.md` records the source-verified Tier 1 memop baseline, three prioritized extension directions, non-goal boundaries and a profiling-first verification checklist.
- **Why**: Multi-step memop optimization work needed a persisted design baseline and ABI pitfall reference outside conversation history and the module map.
- **Tradeoffs**: Adds a planning document outside `.agents/maps/` that must be updated or retired as directions land.
- **Watch out**: Re-verify the documented baseline against `.agents/maps/engine/dbt.md` and `loader.rs` before implementing deferred directions.
- **Source**: 30e42030

### D3: Shared in-cache routines accelerate same-page memops and `exec_memop` scans up to 64 MiB

- **What**: `emit_routines` emits shared in-cache same-page helpers for `memset`, overlap-safe `memcpy`/`memmove` (`n >= 32`), 8-byte `memcmp` (`n >= 8`) and first-page SWAR `memchr` (`n >= 1`, including `SIZE_MAX`) through a predicted-return tail with 4-bit routine relocations, while `exec_memop` scans `memchr`/`strncmp` up to a 64 MiB budget instead of rejecting large `n` upfront and warms the data TLB for untagged addresses on completion.
- **Why**: Same-page 128 B–4 KiB musl memops paid full `V0`–`V31` exit/enter costs, 32–127 B calls and bytewise `memcmp` went unaccelerated, and `strnlen(..., SIZE_MAX)` triggered excessive `R_INTERP` exits.
- **Tradeoffs**: Adds ~0.9 KB of per-instance startup routines, borrows `cpu->x[3..9]` scratch slots inside helpers, and remains scoped to registered bundled-musl symbols.
- **Watch out**: Keep `emit_routines` well under `MAX_BLOCK_WORDS` and synchronize 4-bit `TO_*` tags and `X0`–`X9` scratch assumptions with `struct appine_cpu` across both Default and Go register sets.
- **Source**: 7438389e

### D4: `llama.cpp` CPU optimizations follow a profiling-driven roadmap in `docs/llama-cpp-cpu-perf.md`

- **What**: `docs/llama-cpp-cpu-perf.md` records native-versus-Appine prefill/decode profiling, hot-loop disassemblies and A/B regression plans, reprioritizing verbatim `YIELD` and grouping first, strip-mined fast loops second (split into `flash_attn` Phase 2B-1 and `tinyBLAS::gemm_bloc` Phase 2B-2), and elevating 2 MiB superpages/STLB (Direction 3A) ahead of or alongside Phase 2B-2.
- **Why**: Real profiling showed 92.8–95.2% of decode time in translated blocks and 75–80% of post-2B-1 Q4_0 prefill overhead in 4 KiB fast-loop page crossings and `emit_refill`, contradicting the initial unprofiled order.
- **Tradeoffs**: Maintains a standalone roadmap outside the module maps and defers either F16 prefill or Q4_0 page-crossing wins depending on which step lands first.
- **Watch out**: Profiling used Qwen2.5-0.5B on an Apple Silicon Linux VM, so larger models and narrower mobile cores can shift the balance between `emit_refill` and in-block checks and should be re-profiled against current maps before further changes.
- **Source**: 9542b3db, f1142ce8, 3098de19, 681b4572

### D5: Tier 1 emits `YIELD` verbatim and raises block and grouping limits

- **What**: Tier 1 emits `YIELD` verbatim, raises `MAX_BLOCK_INSNS` to 256 (with 32 B bitfield-packed blocks, lazy guest snapshotting and unchanged 4096-word / 96 MiB limits), widens concurrent grouping to 8 slots and 32 members via bitmasks, tracks depth-1 block-local affine aliases, and allows stolen-register bases, matching `M_REG` accesses and aligned SP-led groups.
- **Why**: Unrolled GEMM/GEMV loops hit the 64-instruction cap, 4-slot grouping ceiling, affine/stolen-base/`M_REG` gaps and NOP-dropped `YIELD` hints without wanting extra translation cost on cold compiler blocks.
- **Tradeoffs**: Uses ~36 KiB of per-thread scratch workspace, translates ~1.3% more fall-through instructions in branchy code, and adds complexity to `plan_group` and `affine_update`.
- **Watch out**: Any missed register-kill, SP-alignment, 24-bit offset or 32-bit `UXTW` wrap guard can misgroup accesses or leave stale bases across Default and Go register sets.
- **Source**: 011b7445

### D6: Strided self-loops compile strip-mined native fast loops ahead of checked bodies

- **What**: Single-block constant-stride self-loops—including cross-4 KiB-code-page fast loops with single-page slow fallbacks and exact page-1 invalidation—emit an NZCV-free strip-mined native fast loop supporting up to 7 root pointers, 16 access streams (`M_REG`, derived shifted indices, register strides and 16-byte-aligned zero-stride SP frames), loop-local write-before-read NZCV, and up to 6 pinned stolen GPRs via `T0`/`T1` and borrowed unused host registers, bounded by `nwatch == 0` and `KICK_BUDGET` (12,288 guest instructions) and counted in `DbtStats::fast_loops`.
- **Why**: Hot ggml and `tinyBLAS::gemm_bloc` inner loops still paid per-iteration inline soft-TLB checks, group spills, stolen-register reloads and kick checks after block grouping.
- **Tradeoffs**: Adds ~100–400 host words per matched loop (up to 128 bail slots), always runs at least one final or boundary iteration in the checked loop, skips parking cross-page blocks on recheck, and raises the worst-case fast-loop kick budget to 12,288 guest instructions.
- **Watch out**: Missed pointer-opacity or read-before-write alias checks, NZCV or bound-overflow bugs, borrowed host-register clobbering, SP alignment/contiguity gaps or missed page-1 invalidation across `install`, `template_fetch` and `invalidate_locked` can corrupt guest state or run stale code, and unkept `appine_dbt_free` flushes must clear `nogroup_count` and `strikes`.
- **Source**: 49585f4e, 669f3edb, 2ce97315

### D7: Tier 1 leverages 2 MiB `stlb` runways, sequential TLB prefill and 2 MiB `exec_memop` spans

- **What**: Leaving the ordinary 4 KiB inline TLB hit sequence unchanged, `emit_fill` stops at L2 `PTE_SUPER` to populate `stlb` and batch-prefill up to 8 contiguous 4 KiB TLB slots on sequential misses, `emit_fast_loop` probes `stlb` before `tlb` for a 2 MiB runway with 34-bit reciprocal division and a `MUL` register-stride fast path, and `memop_check_range`/`exec_memop` translate up to 2 MiB per step.
- **Why**: 4 KiB page-crossing exits in fast loops and `emit_refill` misses accounted for most of the remaining Q4_0 prefill and decode overhead, while non-ML workloads could not regress on inline hits.
- **Tradeoffs**: Enlarges fast-loop prologues (~42 words/stream budget) and `emit_refill` stubs, and writes up to 7 extra TLB slots on sequential misses.
- **Watch out**: Register-stride `MUL` overflow or reciprocal-division rounding errors over 2 MiB spans could overestimate `safe_iters` and fault late, requiring coverage for boundary crossings, non-power-of-2 strides, TBI, watchpoints and superpage demotion across Default and Go register sets.
- **Source**: 42d49fc0

### D8: Tier 1 C sources are split into flat sibling `dbt*.{c,h}` translation units

- **What**: `core/engine/src/c/dbt.c` is split into flat sibling files (`dbt_internal.h`, `dbt_translate.c`, `dbt_group.c`, `dbt_loop.c`, `dbt_routines.c`, `dbt_cache.c` and `dbt.c`) using `dbt_`-prefixed cross-unit symbols, `static inline` hot emitter primitives in `dbt_internal.h` and `#ifdef DBT_SUPPORTED` guards on helper units.
- **Why**: Recent Tier 1 optimizations grew `dbt.c` to 8,207 lines, making navigation and maintenance disproportionate to sibling files in `core/engine/src/c/`.
- **Tradeoffs**: Cross-unit calls are no longer eligible for single-TU static inlining without LTO, and `dbt_internal.h` must stay synchronized across all six C files.
- **Watch out**: Keep cross-TU helpers `dbt_`-prefixed and `#ifdef DBT_SUPPORTED`-guarded so unprefixed symbols do not leak and non-ARM64 host builds keep compiling under `-Wall -Wextra -Werror`.
- **Source**: cc72b093

## Superseded

- ~~Initial unprofiled execution order in `docs/llama-cpp-cpu-perf.md` (9542b3db)~~ → replaced by **D4** in f1142ce8 (2026-11-22)
- ~~64-instruction block cap, 4-slot/16-member non-stolen immediate-only grouping and NOP-dropped `YIELD` in `engine` D10 (round 27)~~ → replaced by **D5** in 011b7445 (2026-11-22, cross-module predecessor in `.agents/decisions/engine.md`)
- ~~Keeping 2 MiB superpages deferred to Step 3 behind Phase 2B in 3098de19~~ → replaced by **D4** in 681b4572 (2026-11-23)
