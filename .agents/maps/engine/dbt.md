# engine/dbt Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/engine/dbt.md` for the paired decision history (decisions from before the split remain in `.agents/decisions/engine.md`: D6–D10, D13–D16, D18, D23, D25, D27–D29, and the Tier 1 halves of D2, D5, D17, D20, D22 and D24).
>
> Verified: 2026-11-23 (full mapping: 5 research concerns; 18 claims checked by 3 independent verifiers — 15 confirmed and 3 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: reclaim pooled instances, detached threads and template arena pages under memory pressure)

## Responsibilities

`engine/dbt` is Appine's Tier 1 same-ISA dynamic binary translator for guest aarch64 user code:

- translating guest basic blocks into a shared W^X code cache: ALU, FP, NEON and barrier
  instructions are copied verbatim (renaming stolen registers), memory accesses get inline
  soft-TLB checks with grouped same-base/affine/`M_REG` checks and a shared out-of-line refill
  routine, canonical constant-stride and register-stride self-loops get guarded strip-mined native
  fast loops, and blocks link directly or through per-thread jump caches and a shadow return stack;
- executing translated code under `engine`'s host fault guard, accelerating registered libc memops
  through in-cache same-page helpers and page-validated host routines, re-entering Tier 0 for any
  untranslated instruction, and keeping exceptions precise;
- lock-free translation-table lookups, batched forwarding-stub retirement, content-based and
  `ic ivau` invalidation, the process-global template arena, instance/thread pooling with stale
  reuse and lazy page revival, code-group sharing (`DbtSpace` / `Dbt`), and periodic unmapping of
  written code pages.

Root: `core/engine/src/c/dbt.c`, `core/engine/src/c/dbt_internal.h`,
`core/engine/src/c/dbt_translate.c`, `core/engine/src/c/dbt_group.c`,
`core/engine/src/c/dbt_loop.c`, `core/engine/src/c/dbt_routines.c`,
`core/engine/src/c/dbt_cache.c`, `core/engine/src/c/emit.h`, the Tier 1 section of
`core/engine/include/appine/engine.h`, the `Tier 1` section of `core/engine/src/lib.rs`
(`DbtStats`, `DbtRegs`, `DbtMemop`, `DbtSource`, `DbtSpace`, `Dbt`, `trim_dbt_pool`,
`unmap_written_code`, `written_code_bytes`), and `core/engine/tests/dbt.rs`.

Outside the module: the Tier 0 interpreter and whitelist semantic reference, CPU state layout,
native stubs, CPU features, the host fault guard and `tests/lockstep` (`engine`); the radix page
table, TLB/STLB layout and code-group policy (`kernel/mmu`); tier selection and the guest run loop
(`kernel/process`); libc memop discovery, `APPINE_DBT_REGS` parsing and Go build-ID detection
(`kernel/exec`); periodic `unmap_written_code`, `written_code_bytes` accounting and `trim_dbt_pool`
triggers (`kernel/oom`).

## Key types

- `DbtSpace` (`struct appine_dbt`, `Arc`-wrapped, `Send + Sync`) — one translation instance shared
  by every thread of an address space and every member of a code group: 128 MB W^X code cache
  with shared routines at its base, dirty-page `struct written` bitmap, lock-free translation
  table, block log (`struct block`), saved guest words, per-page block buckets and parked counts,
  `cross_page_blocks`, stale-reuse `sources`/`trusted`/`parkable` lists (up to 64 each), immutable
  sorted `shared_ranges` and `memop_table` (with `older` chains), ungroup `strikes[64]` ring
  (`strikes_next`) and `nogroup[64]` ring, register set, lock/flush/generation/poisoned state, and
  `pool.all` links.
- `Dbt` (`struct appine_dbt_thread`, `Send`) — one thread's attachment: `Arc<DbtSpace>`, code-group
  tag, atomic active `cpu`, 4096-entry direct-mapped jump cache (`jc`), 1 KB-aligned 64-entry
  shadow return stack (`rs`), statistics (`DbtStats`), and lock-free translation workspace
  (`xlate`, `scratch`, `probe` CPU, 4096-entry `defined` cache, `prep`).
- `struct block` (32 bytes) — guest `pc`, entry `code` (NULL when dead), page-bucket chain index,
  `words` offset, 11-bit `nguest`, 1-bit `parked`, 16-bit `tag`, and saved `first` word for revival.
- `struct table` / `struct slot` — open-addressed hash table (`2^12..2^19` slots) keyed by
  `pc | (tag << 48)` and hashed on `pc` only; retired entries become tombstones (`JC_EMPTY = 1`).
- `DbtRegs` / `struct regs` — host register assignment fixed per instance: `Default` (`CTX=x28`,
  `T0..T2=x16/x17/x27`, `SP_HOST=x26`; stolen `x16–x18, x26–x28`) or `Go` (`CTX=x25`,
  `T0..T2=x21/x22/x23`, `SP_HOST=x24`; stolen `x18, x21–x25`).
- `DbtMemop` (`struct appine_dbt_memop`) — registered libc memop `(pc, kind)` (`memcpy`, `memset`,
  `memmove`, `memcmp`, `memchr`, `strncmp`; up to `APPINE_DBT_MEMOPS` = 32).
- `DbtSource` — trusted code range: `start`, `len` and 5-word identity (`dev`, `ino`, `off`,
  `ctime`, `size`; all-ones for the vDSO).
- `struct template` / static `templates` — process-global 32 MB anonymous bump arena with 65,536
  buckets across 64 shard locks plus `arena_lock`, sharing translated blocks across instances.
- Static `pool` — up to 16 pooled `appine_dbt` instances (64 MB kept-code budget), up to 8 spare
  `appine_dbt_thread`s, and the `pool.all` list of all live and pooled instances.

## Public entry points

- **Instances and threads**: `DbtSpace::new(key, regs)`, `set_sources`, `set_memops`, `trust`,
  `retire_outside`, `share`, `new_tag`; `Dbt::new`, `with_regs`, `attach(space, tag)`, `run(cpu)`,
  `flush`, `invalidate(cpu, start, len)`, `stats`.
- **Process-wide memory management**: `trim_dbt_pool`, `unmap_written_code`, `written_code_bytes`.
- Non-aarch64-Linux builds compile stub entry points (`appine_dbt_run` delegates to
  `appine_cpu_run`).

## Data flow / lifecycle

### Register convention and FP state

- Non-stolen guest GPRs live in same-numbered host registers; stolen registers live in `cpu->x[]`
  and are loaded into `{T0, T1, T2}` and written back around rewritten instructions (instructions
  with >3 distinct stolen GPRs fall back to Tier 0). Host `x18` (Android shadow call stack) is
  never touched. Guest SP lives in `SP_HOST` (`x26`/`x24`), so SP-based operands rename directly.
- Guest NZCV lives in host NZCV; all DBT-emitted helper code is strictly NZCV-free (`emit.h` omits
  flag-setting integer ALU encodings).
- `d->enter(cpu, code)` saves host `x19–x30`, `d8–d15` and host FPCR (176-byte frame), loads guest
  FPCR, FPSR, NZCV, `V0–V31`, non-stolen GPRs and `SP_HOST`, and jumps to `code`. `d->exit` saves
  `T0/T1/T2` (`pc`, `dbt_site`, `dbt_reason`), NZCV, non-stolen GPRs, `SP_HOST`, `V0–V31` and
  host FPSR (not FPCR, since translated code never alters host FPCR), restores host state and
  returns. `appine_dbt_run` syncs host `PSTATE.DIT` via `appine_sync_dit` on entry.

### Blocks and instruction handling

- Every block begins with a 2-word entry kick check (`ENTRY_CHECK_WORDS = 2`), holds up to 256
  guest instructions (`MAX_BLOCK_INSNS`), and stops before exceeding 4096 host words
  (`MAX_BLOCK_WORDS`), 256 stubs, 512 fixups, 516 relocations, or the 4 KiB guest page boundary
  (ending with an inline `R_CHAIN_FWD` stub; only matched cross-page fast loops additionally cover
  words in the immediately following executable page, tracked in `block::nguest`). Guest words are
  snapshotted lazily (32 words initially, extended in 64-word chunks). Terminators are `B`, `BL`,
  `BR`, `BLR`, `RET`, `SVC #0` and `R_INTERP` fallbacks; conditional branches, `DSB`/`ISB` and
  `MSR FPCR` emit deferred side-exit stubs and continue on fall-through.
- Whitelist parity with Tier 0: SIMD/FP data processing (`bits 28:25 & 7 == 7`) checks
  `appine_has(FP|ASIMD) && appine_native_available() && appine_simd_dp_decode` directly; all other
  instructions check `dbt_tier0_defined` (running `appine_interp_exec` on a per-thread probe CPU
  with `mmu == NULL`, cached in a 4096-entry direct-mapped cache). Rejected instructions emit
  `R_INTERP`.
- Lowering:
  - integer ALU, FlagM (`CFINV`/`XAFLAG`/`AXFLAG`/`RMIF`/`SETF8`/`SETF16`), FP/NEON DP and
    barriers copy verbatim (renaming stolen/SP operands); `DSB` and `ISB` check `cpu->ivau_page`
    and side-exit `R_CODE` at `pc + 4` when non-zero;
  - `ADR`/`ADRP` emit `emit_mov_const`; block-local `konst` tracks `ADR`/`ADRP` plus flagless
    `ADD Xd, Xn, #imm{, lsl #12}` for constant-slot TLB checks; `affine` tracks depth-1 affine
    relations for grouping;
  - loads/stores take the inline TLB or grouped path; `PRFM`/`PRFUM` emit nothing;
  - `SVC #0` exits `R_SVC` inline at `pc + 4`; non-zero `SVC`, `BRK` and `DIT` writes go to Tier 0;
  - `MRS FPCR` and `MRS`/`MSR TPIDR_EL0` access `struct appine_cpu`; `MRS DCZID_EL0` loads 4;
    `NZCV` (R/W), `FPSR` (R), `CNTVCT`/`CNTVCTSS`/`CNTFRQ` (R) execute natively; `MSR FPCR` stays
    inline when `(val & fpcr_write_mask()) == cpu->fpcr` and exits `R_INTERP` otherwise; `MSR FPSR`
    and other system registers go to Tier 0;
  - `HINT` space (NOP, PAC/BTI hints) emits nothing except `YIELD` (`0xd503203f`), copied verbatim;
    non-hint PAC is undefined in Tier 0;
  - `DC CVAC`/`CVAU`/`CIVAC`/`CVAP`/`CVADP` and `IC IVAU` do 1-byte read TLB checks; `IC IVAU`
    untags and records `cpu->ivau_page` (page 0 or a second differing page exits `R_INTERP`);
    `DC ZVA` zeroes 64 aligned bytes via four `STP XZR, XZR` after a write TLB check; `CLREX`
    clears `cpu->excl_size`;
  - exclusives and atomics: untag TBI top byte, check SP alignment and natural alignment (`R_INTERP`
    on misalignment), and do an `in_granule` TLB check. `LDXR`/`LDAXR` load and record
    `excl_addr`/`excl_value`/`excl_size`; `STXR`/`STLXR` verify the monitor and run an inline
    `ldaxr`/`stlxr` CAS loop (borrowing an unused `x0..x2` saved in `cpu->x[]` if `rt` is stolen);
    `LDAR`/`STLR`, `LDAPR`, `LDAPUR*`/`STLUR*`, `CAS`, `CASP` (when `size < 2` and data pairs
    `rs`/`rs + 1`/`rt`/`rt + 1` are non-stolen; a stolen base `rn` is handled inline) and LSE
    `LD<op>`/`SWP` run natively on `[T2]`; `LDXP`/`STXP` and `CASP` with stolen data-pair registers
    go to Tier 0.

### Memory access and grouped checks

- Inline accesses cover integer LDR/STR (immediate, pre/post-index, register-offset, literal),
  LDP/STP/LDNP/STNP/LDPSW, SIMD single/pair/literal, and `LD1–LD4`/`ST1–ST4` (multiple, single
  lane, replicate, post-index).
- Hit path indexes `cpu->tlb[4096]` by the **last byte's** 12-bit page number and compares the
  stored tag (`~vpn`, 0 = invalid) via `EON` against the **first byte's** page number (`T0 >> 12`),
  rejecting misses, TBI top-byte mismatches and cross-page accesses in one `CBNZ`. Single-register
  ops access `[T2, T0]` directly; pairs and structures add `T0` into `T2` first. Variants:
  parallel last-byte calculation for `|imm + bytes - 1| < 4096`; `in_granule` skipping the last-byte
  add for 1-byte accesses, aligned 16-byte SP accesses and atomics; constant TLB slot offset for
  `M_LITERAL` and `konst`-tracked single-page accesses. SP 16-byte alignment is checked once per
  block (`x->sp_aligned`) and cleared only when SP moves by a non-multiple of 16.
- Refill stubs (5 words, never merged) carry `info` (`bytes - 1`, `fail` reason `R_INTERP` or
  `R_UNGROUP`, resume delta) and guest `pc` to shared routines `d->refill[0]` (read) and
  `d->refill[1]` (write). The routine saves host `x0–x5` into `cpu->x[0..5]`, fails on
  `cpu->nwatch != 0` or non-zero bits `55:48` at either endpoint, and walks the 4-level radix page
  table via plain address-dependent loads. Write refills require `PROT_READ | PROT_WRITE` (serving
  atomics and grouped reads). When L2 carries `PTE_SUPER`, refill skips L3, populates 2 MiB
  `cpu->stlb` (`stlb_used`), and—if preceding 4 KiB slot `(vpn - 1)` holds a matching tag and
  addend—batch-prefills up to 8 contiguous 4 KiB slots within the same 64-entry `tlb_used` word.
  Cross-page accesses probe/fill both ends and succeed only when both have equal addends
  (contiguous host memory). Failures exit cleanly to `d->exit` before modifying guest state.
- Grouped checks (`dbt_group.c`): up to 8 concurrent active groups (`cpu->dbt_groups[8]`, tracked
  by `active_groups` and 256-bit `grouped_bits`), each covering at most 512 bytes (`hi - lo <= 512`)
  and 32 members (at least 2), with offsets inside `±8 MiB`. Non-`M_REG` groups track block-local
  affine aliases (`ADD`/`SUB` imm, `MOV`, pre/post writebacks); SP members join only an SP-led
  group while SP stays 16-byte aligned. `M_REG` groups match `(rn, rm, option, shift)` and track
  constant `rn` updates and 64-bit `LSL`/`SXTX` `rm` updates. Allowed intervening ops are ALU,
  `ADR`/`ADRP`, SIMD DP, conditional branches, hints, barriers/`CLREX`, prefetches and other
  non-atomic memory ops (spilling/reloading `T2` via `dbt_groups[slot]` when clobbered). Stolen
  bases compute into `T0` and recover `host(base)` into `T2`. Leader refill failures exit
  `R_UNGROUP`: unless `c->nwatch != 0`, `dbt_ungroup` searches the 64-entry `strikes[64]` ring
  linearly on the cold slow path, recording a first miss in the first empty slot (or overwriting
  FIFO via `strikes_next`) so alternating leaders cannot collide, and on the second miss clears the
  slot, appends `pc` to the 64-entry FIFO `nogroup` ring (disabling grouping for 256 bytes,
  versioned into template keys via `dbt_nogroup_key`), and retires blocks covering `pc` in its page
  bucket.

### Strip-mined native fast loops

- For non-memop blocks whose prefix `0..back_idx` forms a self-loop within one page or crossing at
  most one 4 KiB code page boundary (next page executable and matching shared-group status; slow
  fallback stays single-page), `dbt_try_fast_loop` recognizes `FL_COUNTDOWN` (`SUB`/`SUBS` `#1..4096`
  + `CBNZ`/`B.NE`/`PL`/`HI`/`GE`/`GT`) and `FL_CMP_INC` (`CMP` reg/imm + `B.NE`/`LT`/`LE`/`GT`/`GE`/
  `LO`/`LS`/`HI`/`HS`, including 64-bit `ADD` + 32-bit compare and 64-bit affine-derived compare
  `d = c + cmp_off`) loops with no internal branches, calls, syscalls, barriers, hints, atomics,
  `M_LITERAL`, `ADR`/`ADRP`, FlagM, SP DP, read-before-write NZCV, or >2 distinct stolen GPRs per
  instruction.
- Supports up to 7 pointer-opaque root bases (including zero-stride `M_OFFSET` SP bases and live
  end-of-iteration affine aliases not read before write) and up to 16 coalesced streams (offset/pre/
  post-index, `M_REG` with loop-invariant/induction/derived shifted-sum `(r0 + r1 + off) << 0..4`
  indices, and post-access register strides `ADD Xd, Xd, Xm`, requiring at least one positive-stride
  stream and total estimated size `<= 1500` words).
- The strictly NZCV-free prologue checks `nwatch == 0` (and 16-byte SP alignment when SP is used),
  computes remaining back-edges clamped to `KICK_BUDGET` (`32..256` iterations, capped at 12,288
  guest instructions), stores `safe_iters` in `dbt_groups[7]`, validates zero-stride streams with a
  dual-endpoint 4 KiB TLB contiguity check, and probes positive-stride streams in 2 MiB `stlb` then
  4 KiB `tlb` (storing root addends in `dbt_groups[0..6]`, using `MUL` then `UDIV` for register
  strides `< 2 MiB`, and shifts or exact 34-bit reciprocal multiplication for constant strides).
  Any miss, `safe_iters < 2`, or stride failure bails to the checked loop.
- On entry it adds addends to roots, pins all touched stolen GPRs (up to 6: first 2 in `T0`/`T1`,
  extra borrowing unused non-stolen host registers saved in their dead `cpu->x[]` slots; or falls
  back to per-instruction `T0`/`T1` loads skipping write-only `Rd`), runs `safe_iters` iterations
  counted in `T2` (omitting the loop-closing `CMP` while allowing loop-local write-before-read NZCV
  ops), flushes written pinned registers, restores borrowed registers, subtracts addends from roots
  and live aliases, re-emits any omitted `FL_CMP_INC` compare once for exact NZCV, and falls
  through to the standard checked loop for at least one final/boundary iteration. Matched blocks
  increment `DbtStats::fast_loops` (preserved in templates).

### Control flow

- Direct branches link by patching `b -> b` (CMODX-safe). At install time (`dbt_link_block`),
  deferred side-exit stubs (conditional branches) are linked eagerly when targets exist (and
  single-site conditional branches relinked directly before publication); inline unconditional
  `B`/`BL`, fallthrough `R_CHAIN_FWD`, and `BL`/`BLR` landing pads link lazily on first execution.
  Runtime patching enforces matching `generation`, `target != patch_site`, and no shared->private
  link; conditional-branch relinking always runs under `d->lock` with `can_relink_branch` and
  finishes full icache sync before unlocking. Because conditional branches are not CMODX-safe on
  ARM64, shared (`tag == 0`, `LINK_SHARED`) blocks require being the sole attached thread on the
  entire `DbtSpace` (including threads of other code-group members, which execute the same shared
  blocks; `d->nthreads == 1` is only a lock-free hint before taking `d->lock`), whereas private
  tagged blocks (`tag != 0`, `!LINK_SHARED`) are unreachable from other tags and only require being
  the sole attached thread of `t->tag`.
  Unconditional `b -> b` patching uses lazy cache maintenance unless the patching thread hits an
  already-patched site (`dbt_sync_all`).
- Forward direct links skip the 2-word entry kick check (`code + 2`); backward/self links and
  indirect jumps land at `code + 0`, so every loop checks `pending`.
- Indirect branches (`BR`/`BLR`/`RET`) probe the thread's 4096-entry direct-mapped jump cache
  (`t->jc`); misses branch to in-cache `d->lookup`, which brackets a lock-free `d->table` probe
  with odd/even `stlr` increments of `cpu->dbt_lookup_seq` (excluding misaligned, `>= 2^48`, and
  `pc == 0`), fills `t->jc` and jumps directly on hit, or exits `R_LOOKUP`.
- Shadow return stack: `BL`/`BLR` emit a host `BL` over an `R_CHAIN` landing pad and push
  `(pc + 4, landing_pad)` onto the 1 KB-aligned 64-entry ring `t->rs` (wrapping via `BFXIL`);
  `RET X30` compares the top against `x30`, pops and executes host `RET T2` on hit, or falls back
  to the jump cache. Empty slots point at `d->rs_miss` -> `d->lookup`.

### Dispatcher and libc memops

- `appine_dbt_run` delegates directly to `appine_cpu_run` when `d->poisoned`, syncs `DIT`,
  publishes `t->cpu` (`SEQ_CST`), and runs `dbt_run` under `appine_guard_run`. A host fault returns
  `APPINE_EXIT_HOST_FAULT`, sets `d->poisoned = true`, wakes parked flush waiters and clears the
  global template arena (`dbt_template_clear(false)`).
- Each `dbt_run` iteration: join (`park`) or perform (`flush_world`) a pending flush; catch up
  generation (reset `rs`, clear dirty `jc`); on consuming `c->pending`, clear `excl_size` and return
  `APPINE_EXIT_KICK`. Otherwise, try lock-free `dbt_table_lookup`. On a miss with non-zero
  `page_parked`, lock and call `dbt_revive`; else lock-free
  `prepare` + locked `install` (re-verifying guest words and `memop_kind`), or `appine_interp_step`
  for unfetchable PCs; fill jump cache if requested; call `enter(c, code)` and dispatch the exit:
  - `R_CHAIN`/`R_CHAIN_FWD`: record patch site/branch delta/shared flag for next lookup;
  - `R_LOOKUP`: request jump-cache fill on next lookup;
  - `R_UNGROUP`: call `dbt_ungroup` if `!c->nwatch`, then fall through to Tier 0 (skipping memop);
  - `R_INTERP`: for exact `R_INTERP` at a registered shared/ungrouped memop PC, try `exec_memop`
    (on hit, pop matching `dbt_rs` top and set `pc = x30`); else run `appine_interp_step`
    (absorbing `APPINE_EXIT_CODE` in place via `code_changed`, returning other non-`NONE` exits to
    the kernel, and falling through to `R_CODE` if `c->ivau_page != 0` remains);
  - `R_CODE`: invalidate `c->ivau_page` in place and clear it;
  - `R_SVC`: clear `exit_info` and `excl_size`, return `APPINE_EXIT_SVC`;
  - `R_KICK`: loop back to flush/pending checks.
- Libc memops (`memcpy`, `memset`, `memmove`, `memcmp`, `memchr`, `strncmp`; up to 32 sorted in
  immutable `memop_table`): `appine_dbt_set_memops` publishes the new table (`RELEASE`, chaining old
  tables on `older` until `drop_memops`) before retiring changed/added/removed PCs. Private tagged
  blocks ignore memops; memop blocks bypass templates and fast loops, recheck `memop_kind` under
  `d->lock` at `install`, and are retired before pooling in `appine_dbt_free`.
  - In-cache same-page helpers at the base of the code cache (`dbt_routines.c`, borrowing
    `cpu->x[3..9]`, preserving non-return regs and NZCV, returning via predicted-return
    `d->memop_ret`): `memset` and overlap-safe `memcpy`/`memmove` (`x2 >= 32`), 8-byte `memcmp`
    (`x2 >= 8`), and first-page SWAR `memchr` (`x2 >= 1`, including `SIZE_MAX`). On cross-page,
    TLB miss or watchpoints they jump to fallback `x2 >= 128` -> `R_INTERP` (else guest code);
    `strncmp` checks `x2 >= 128` directly.
  - Out-of-line `exec_memop` (`dbt.c`): declines on `nwatch != 0`; translates 2 MiB L2 superpage or
    4 KiB L3 spans via `appine_mmu_lookup_super` with TBI untagged; caps `memset`/`memcpy`/`memmove`/
    `memcmp` at 64 MiB while scanning `memchr`/`strncmp` up to a 64 MiB budget (handling `SIZE_MAX`);
    pre-validates mutating ranges before writing; translates compare/scan ranges lazily; preserves
    TBI tag in `memchr` result; warms 4 KiB `tlb` and 2 MiB `stlb` via `appine_tlb_fill` for
    untagged 48-bit addresses (except `strncmp`).

### Code cache, table, sharing and invalidation

- The 128 MB code cache is mapped twice via `appine_map_code` (`MAP_SHARED|MAP_ANONYMOUS` +
  `mremap` RX alias; `MAP_PRIVATE` RWX fallback) and bump-allocated. Dead blocks reclaim no code
  space until a full flush. For W^X caches, `note_written` sets per-host-page dirty bits;
  `unmap_written_code` walks `pool.all` and calls `MADV_DONTNEED` on the writable alias to eliminate
  host RssShmem double-counting, while `written_code_bytes` reports currently mapped writable bytes.
  Opt-in `APPINE_PERF_MAP` appends block symbols to `/tmp/perf-<pid>.map` under its own lock.
- Lock-free table: C readers load `code` (`ACQUIRE`) then `pc` (`RELAXED`); `emit_lookup` uses plain
  `ldp` excluding `pc == 0`. Table replacement waits for active odd `dbt_lookup_seq` readers before
  `munmap`. Starts at `2^12` slots, doubles up to `2^19` (`TABLE_LIMIT = 393,216`) at 3/4 load (or
  rebuilds in place if tombstones >= half of occupied or at max size). Block-log compaction runs at
  limit when `>= 1/8` of records are dead.
- Retiring blocks (`dbt_retire_add`/`dbt_retire_flush`, batched up to 32) emits 16-word forwarding
  stubs (`R_CHAIN` + `LINK_SHARED` for tag 0), syncs them, patches `code[0]` and `code[2]` to jump
  to the stub, syncs entries, and writes tombstones (`JC_EMPTY`). Full flush (`flush_world`) kicks
  other active threads, waits until all leave `dbt_run` or `park()`, clears touched slots/buckets,
  resets `used_words = routine_words`, bumps `generation`, and broadcasts `d->flushed`.
- Templates: 32 MB anonymous arena (`65,536` buckets, 64 shard locks, `arena_lock`, max 4 versions
  per `pc`), keyed by `(pc, nogroup_key, regs, shared, guest words)`; cross-page templates validate
  page 1 on fetch. A full arena triggers `dbt_template_clear(true)`, which rewinds the allocator
  and keeps the pages resident for reuse. The high-water mark covers all allocations since the
  last pressure trim, including earlier generations.
- Pool: up to 16 `appine_dbt` instances (64 MB kept code budget) and 8 spare threads. Non-poisoned
  instances with non-zero `key`, `<= 131,072` blocks, `<= 64 MB` code, no `flush_wanted` (and
  fitting the 64 MB budget above 32 MB) drop shared/memop/private state and stay cached as `stale`;
  otherwise they flush (clearing `nogroup_count`, `strikes` and `strikes_next`), shrink table to `2^12`, and
  `MADV_REMOVE`/`MADV_FREE`/`MADV_DONTNEED` backing memory. `DbtSpace::new` prefers MRU matching
  `(key, regs)`, else an empty instance (regenerating routines if `regs` differs), else allocates.
  `trim_dbt_pool` drains `pool.free` and `pool.threads` under `pool.lock`, then releases the
  evicted instances and detached workspaces outside the lock. `dbt_template_trim` then takes
  shard locks in ascending order followed by `arena_lock` (guarded together), clears the bucket
  array if the cursor is nonzero, and applies `MADV_DONTNEED` through the arena high-water mark.
  When both the cursor and high-water mark are zero, template trim skips the locks and buckets.
- Stale reuse: `trust` marks exact `DbtSource` matches trusted and prior `set_sources` ranges
  parkable. First `dbt_run` runs `dbt_recheck`: unmapped single-page parkable blocks are parked;
  cross-page and other mismatches are invalidated; if non-parkable mismatches exceed half of live
  blocks, a full flush is requested instead. First lookup miss on a page with `page_parked > 0`
  calls `dbt_revive`, restoring matching blocks in batches of 32 and relinking tombstones in place
  (skipping and killing any parked block whose key is already live; `dbt_table_insert` also kills
  any parked duplicate in the page bucket when installing a fresh block).
- Code groups: `new_tag` issues `1..65535` (0 when exhausted); `share` publishes immutable sorted
  `shared_ranges` (tag 0 vs private `tag`); `retire_outside` retires tag-0 blocks outside shared
  ranges before multi-member sharing.
- Invalidation (`dbt_invalidate_locked`): with `mmu != NULL` (always true from Rust
  `Dbt::invalidate`; C also supports `NULL` for unconditional invalidation including parked blocks),
  compares saved words (across both pages for cross-page blocks) and leaves parked blocks alone.
  Ranges spanning `> 256` pages (`last - first >= INVALIDATE_MAX_PAGES`) or wrapping around scan
  `blocks[]` linearly; non-wrapping ranges of `<= 256` pages scan page buckets `[first..last]`
  (plus `first - 1` when `first > 0 && cross_page_blocks > 0`), unlinking dead records. `ic ivau`
  invalidates in place via `R_CODE` / absorbed `APPINE_EXIT_CODE`.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/process`: task run loop (`Dbt::attach`/`run`/`invalidate`/`flush`, exit handling,
  leftover `ivau_page`, kicks).
- `kernel/mmu`: `DbtSpace` lifecycle, code groups (`new_tag`/`share`/`retire_outside`), stale reuse
  (`set_sources`/`trust`), and `set_memops`.
- `kernel/exec`: `DbtRegs` selection (Go build-ID / `APPINE_DBT_REGS`) and bundled musl `DbtMemop`
  discovery.
- `kernel/oom` uses `written_code_bytes` for RSS accounting and periodically calls
  `unmap_written_code`. Root pressure and cgroup `memory.high` trigger both `trim_dbt_pool` and
  `unmap_written_code`. The host can also trigger `trim_dbt_pool` through `Machine::trim_memory`.
- `engine` tests (`core/engine/tests/dbt.rs`) and `tests/lockstep`.

### Outbound

- `engine`: `struct appine_cpu` layout (`dbt_*`, `dbt_groups[8]`, `ivau_page`, `excl_*`, `tlb`,
  `tlb_used`, `stlb`, `stlb_used`, `nwatch`), `appine_interp_step`/`exec`, `appine_simd_dp_decode`,
  `appine_has`/`appine_has2`/`appine_native_available`, `fpcr_write_mask`, `appine_sync_dit`,
  `appine_cpu_run`/`kick`/`init`, `appine_map_code`/`unmap_code`, `appine_guard_run`/`hold`/
  `hold_fn`/`drop`/`fail`, and `sync_code_ranges`/`publish_code_lazily`.
- `kernel/mmu`: 4-level 9-bit radix page-table layout (`PTE_SUPER_BIT`, `APPINE_PROT_*`),
  `appine_mmu_translate`, `appine_mmu_lookup_super`, and `appine_tlb_fill`.
- Host: `mmap`/`mremap`/`madvise`/`munmap`, pthreads (mutexes, condvars), icache maintenance, and
  opt-in `APPINE_PERF_MAP` (`/tmp/perf-<pid>.map`).

## Invariants and gotchas

- Tier 1 must match Tier 0 on every instruction via `dbt_tier0_defined` and
  `appine_simd_dp_decode`; precise guest exceptions come from checking before mutating, never from
  catching host signals.
- While translated code runs, `struct appine_cpu` does not hold live guest registers (routines also
  borrow `cpu->x[0..9]`, safe only because neither `Default` nor `Go` steals `x0..x15`, and `STXR`
  borrows `x0..x2`). `struct appine_cpu` offsets (`TLB_OFF`, `STLB_OFF`, `dbt_groups`) are pinned
  by `_Static_assert`s.
- Guest FPCR stays unchanged during translated execution (changed masked writes exit `R_INTERP`),
  so `d->exit` intentionally does not save host FPCR. Host `x18` is never touched.
- Write TLB refills unconditionally require `APPINE_PROT_READ | APPINE_PROT_WRITE` so write-only
  pages always fall back to Tier 0 and write-half hits safely serve atomics and grouped reads.
- Every lock acquired inside `appine_guard_run` must be registered with `appine_guard_hold`/
  `hold_fn` (within `MAX_LOCKS = 4`), and guarded paths must not call `malloc` (sole exception:
  opt-in `APPINE_PERF_MAP` in `install`).
- Code inspection reads through the execute alias (`*site`), never `rw(d, site)`, to avoid host
  read fault-around faulting untracked pages into the writable W^X alias.
- `emit_lookup` excludes `pc == 0` so an unordered `ldp` racing `dbt_table_insert` cannot match
  new `code` with an empty slot's `key == 0`.
- `table_relink` must reuse a parked block's original tombstone slot so `dbt_flush_locked` (which
  clears only `table_used` indices) does not leak tombstones.
- Known-address TLB checks rely on exact block-local `konst` invalidation; a stale constant would
  bypass cross-page detection.
- `set_memops` publishes `d->memops` before retiring blocks and `install` rechecks `memop_kind`
  under `d->lock`, preventing stale memop blocks across updates or pooling.
- `d->cross_page_blocks` is incremented on insert and only recomputed on compaction or cleared on
  full flush, so small-range invalidation may conservatively scan bucket `first - 1` after cross-page
  blocks are retired. Cross-page blocks are never parked, and `dbt_ungroup` only scans one page
  bucket because fast loops never emit `R_UNGROUP`.
- `appine_dbt_run` absorbs `R_CODE` and Tier 0 `APPINE_EXIT_CODE` in place, but returns immediately
  on other Tier 0 exits leaving any pending `c->ivau_page` for the kernel caller to invalidate.
- `dbt_routines.c` has a minor comment/code discrepancy (`emit_refill` comment says `x0–x4` while
  saving `x0–x5`), and `dbt_internal.h` says groups cover `GROUP_SPAN` plus one access while
  `dbt_group.c` enforces `hi - lo <= 512` total.

## Confirmed bugs / technical debt

None.

## Open questions

None.

## To verify

- Template copies reproduce a fresh translation exactly; there is no runtime self-check.
- Tier 1's page-table walk uses plain, address-dependent loads where `mmu.c` uses acquire loads;
  only architectural reasoning in comments argues they are equivalent.
