# Extending Tier 1 `memop` Acceleration

> Handoff / future-work design note (no code changes yet).
> Grounded in `core/engine/src/c/dbt.c`, `core/engine/include/appine/engine.h`,
> `core/kernel/src/loader.rs`, `core/kernel/src/mm.rs`, and `.agents/maps/engine/dbt.md`
> as of 2026-11-22.

## Current baseline

Tier 1 (`engine/dbt`) currently accelerates six length-bounded musl memory/string primitives by
intercepting their entry PCs and executing page-validated host libc calls when the byte count is
large enough to amortize a dispatcher exit:

- **Discovery and trust (`core/kernel/src/loader.rs`, `core/kernel/src/mm.rs`)**:
  `bundled_libc` verifies the bundled Alpine `ld-musl-aarch64.so.1` against a pinned size and
  SHA-256 (`BUNDLED_LIBC_SIZE`, `BUNDLED_LIBC_SHA256`), copies it into an immutable `memfd`
  snapshot (`BundledLibc`), parses `STT_FUNC` symbols in executable `PT_LOAD` segments for
  `memcpy`, `memset`, `memmove`, `memcmp`, `memchr`, and `strncmp`, and registers their runtime
  entry PCs via `DbtSpace::set_memops` (`appine_dbt_set_memops`, max `APPINE_DBT_MEMOPS` = 32).
- **Publication and retirement (`core/engine/src/c/dbt.c`)**:
  `appine_dbt_set_memops` sorts and deduplicates `(pc, kind)` into an immutable `struct memop_table`,
  publishes it with release semantics to `d->memops` (retiring older tables on `older` until
  `drop_memops`), and retires any existing translation whose registration changed (`retire_pc`).
  `appine_dbt_free` retires all memop-specialized blocks and calls `drop_memops` before returning
  an instance to the pool.
- **Translation-time gating (`prepare`, `install`)**:
  For shared or ungrouped blocks (`p->tag == 0`), `prepare` probes `find_memop(d, pc)`. When
  registered, the block bypasses both `template_fetch` and `template_store` and emits a
  2-instruction threshold gate right after the entry kick check:
  ```asm
  ubfx T0, X2, #7, #57       // test X2 >= 128 without modifying NZCV
  cbnz T0, R_INTERP_stub
  ```
  `install` rechecks `find_memop(d, p->pc)` under `d->lock` before publishing the block.
- **Runtime execution and fallback (`exec_memop`, `R_INTERP` in `appine_dbt_run`)**:
  On a pure `R_INTERP` exit at a registered PC (excluding `R_UNGROUP` fallthrough and private
  code-group blocks), `exec_memop` checks `c->nwatch == 0` and `n <= MEMOP_MAX_BYTES` (64 MiB),
  untags TBI pointers, pre-validates every guest page for mutating ops (`memop_check_range`) to
  preserve precise faults, runs host `memset`/`memmove`/`memcmp`/`memchr` page-by-page via
  `appine_mmu_translate`, pops the shadow return stack (`c->dbt_rs`) if its top matches `X30`, and
  sets `c->pc = c->x[30]`. Any failure returns `false` and falls straight through to
  `appine_interp_step(c)` (Tier 0) with zero guest-visible side effects.

### Why the pattern works

In a same-ISA pass-through DBT, register ALU/FP/NEON instructions already run at near-native speed.
The dominant overhead in bulk memory routines is executing a soft-TLB check every 8–16 bytes.
Batching memory work turns per-access TLB checks into one `appine_mmu_translate` per 4 KiB guest
page plus host SIMD loops, while keeping precise guest exceptions via pre-validation and Tier 0
fallback.

---

## Candidate extension directions

### Direction 1: Broaden registered-entry memops (lowest risk)

Extend the existing `(pc, kind)` registration pipeline to cover more high-memory-bandwidth routines.

1. **Additional musl primitives**
   - *Length-bounded*: `strnlen` (length in `X1`), `memrchr`, `mempcpy`, `bzero` (length in `X1`).
     Requires parameterizing which guest register the translation-time threshold gate tests instead
     of hardcoding `X2` in `prepare`.
   - *Unbounded string ops* (`strlen`, `strchr`, `strcmp`): no upfront length register exists, so an
     unconditional `R_INTERP` exit will regress short strings (the common case). Only worth pursuing
     if paired with an inline first-chunk probe in translated code (exit only when no NUL/match is
     found in the first 32–64 bytes) and backed by profiling.
2. **Non-musl runtimes and libraries**
   - **Go runtime** (`runtime.memmove`, `runtime.memclrNoHeapPointers`, `runtime.memequal`):
     `engine/dbt` already special-cases Go binaries (`APPINE_DBT_REGS_GO` via Go build-ID detection).
     Go programs bypass musl and spend substantial time in their own statically linked memory
     helpers (using arm64 register ABI). Because Go binaries are statically linked, whole-file
     SHA-256 verification does not apply; safe admission requires matching the ELF symbol plus a
     verified instruction-byte fingerprint (or curated runtime routine hashes), leveraging the
     fact that `dbt.c` already snapshots and re-verifies guest words (`p->words`).
   - **Bundled `zlib` (`crc32`, `adler32`)**: if a pinned shared library exists in the rootfs,
     read-only page-chunked checksums fit the exact `memop_check_range` + host implementation model
     with no write-side fault hazards.

**Key files**: `core/engine/include/appine/engine.h`, `core/engine/src/lib.rs`,
`core/engine/src/c/dbt.c`, `core/kernel/src/loader.rs`, `core/kernel/src/mm.rs`.

---

### Direction 2: Move acceleration into Tier 1 codegen (highest upside, libc-agnostic)

The current approach has two structural ceilings: (a) taking `R_INTERP` pays a full `exit`/`enter`
transition (saving/restoring `V0–V31`, `FPSR`, `NZCV`, and host callee-saved registers), forcing
the 128-byte threshold; (b) it misses HotSpot JIT stubs (`arraycopy`/`fill`), GCC/Clang inlined
loops, and statically linked C/Rust/Go binaries.

#### 2A. In-cache same-page fast path (lowering the threshold)
- Add lightweight helper routines alongside `refill` at the head of the code cache (`emit_routines`).
- For a registered `memcpy`/`memset`/`memmove`, check in generated code whether `[dst, dst+n)` (and
  `[src, src+n)`) stay within a single guest page and hit the inline data TLB (plus `nwatch == 0`,
  already guaranteed because watched pages are never placed in the TLB).
- If they hit, run a tight host loop directly on the translated host pointers without leaving
  translated code (no full `V0–V31` save/restore) and return via the shadow return stack (`ret`).
- On cross-page spans or TLB miss, fall back to the existing `R_INTERP` -> `exec_memop` path.
- Expected effect: profitable threshold drops from `128 B` to roughly `32–64 B`.

#### 2B. Tight-loop idiom recognition (replacing symbol coupling)
- `plan_group` (`core/engine/src/c/dbt.c`) already amortizes TLB checks across straight-line
  same-base accesses inside one basic block (up to `GROUP_SPAN` = 512 B, `GROUP_MAX` = 16).
- Extend `prepare` to recognize canonical single-block self-loops (back-edge targeting `x->pc`):
  post-index `ldr`/`str`/`ldp`/`stp` or `dc zva` zeroing loops with a monotonic counter and simple
  branch termination (`subs` + `b.ne`, `cbnz`, `cmp` + `b.lo`/`b.ne`).
- Emit a loop-entry prologue that computes the safe in-page iteration count (`min(remaining,
  bytes_to_page_end / stride)`), performs one TLB check per pointer for that chunk, and executes a
  native host loop (or calls the in-cache helper) before updating guest registers.
- On TLB miss, aliasing/overlap ambiguity, or watchpoint, fall back to the normal translated loop or
  Tier 0, preserving exact fault addresses and architectural state.
- Expected effect: automatically accelerates HotSpot JIT array stubs, static Rust/Go/C binaries,
  and compiler-inlined loops with zero loader/SHA-256 coupling.

**Invariants to preserve**:
- Must work identically under both `APPINE_DBT_REGS_DEFAULT` and `APPINE_DBT_REGS_GO` (respecting
  stolen registers and never touching host `X18`).
- Must not break template arena reuse (`template_fetch`/`template_store`) or CMODX concurrent
  patching rules.
- Must remain compatible with `nogroup` strike-out / precise faults and `c->nwatch != 0`.

---

### Direction 3: Chunked, kick-responsive `exec_memop` (removing the 64 MiB cap)

Currently `exec_memop` rejects `n > MEMOP_MAX_BYTES` (64 MiB) so a single call cannot starve
`c->pending` kicks (signals, full code-cache flushes).

- Process large ranges in chunks (e.g., 1–4 MiB) and poll `__atomic_load_n(&c->pending,
  __ATOMIC_RELAXED)` between chunks.
- **Important ABI pitfall to handle carefully**:
  - Read-only primitives (`memcmp`, `memchr`, `strncmp`) have no guest memory side effects and can
    cleanly abort back to Tier 0 or resume.
  - Mutating primitives (`memset`, `memcpy`, `memmove`) must return the **original `dst`** in `X0`
    per C ABI. Therefore, if a mutating `exec_memop` yields mid-operation on a kick, it **cannot**
    simply advance `X0` and leave `c->pc` at the function entry — doing so would corrupt the final
    return value in `X0` (and for overlapping `memmove`, change overlap direction).
  - Safe ways to handle mutating kicks:
    1. Keep the kick check only before the first write (keeps current semantics) or
    2. Service `pending` inside `appine_dbt_run` only by returning `APPINE_EXIT_KICK` after saving
       internal resume state (not recommended: leaks engine state across signal delivery / `ptrace`
       inspection), or
    3. Use a bounded slice size (e.g., 64 MiB is already ~5–15 ms on mobile DRAM) and only relax
       the cap for read-only ops or verify whether >64 MiB ops actually occur in target workloads
       before adding complexity.

---

## Non-goals / boundaries

Do **not** extend this mechanism to:

- **Compute-bound functions (`libm`, AES/SHA inner rounds, FFT)**: same-ISA DBT already executes
  FP/NEON/Crypto instructions verbatim. Exiting to host C adds overhead and risks `FPCR`/`FPSR`
  edge-case divergence.
- **Stateful or callback-bearing library calls (`malloc`/`free`, `pthread_mutex_*`, `qsort`)**:
  `exec_memop` runs inside `engine`'s host fault guard (must not allocate host memory or call back
  into the kernel layer), and intercepting guest allocator/lock internals couples correctness to
  private libc data structures and signal/fork semantics.

---

## Profiling results (2026-11-22)

Measured in the `appine-dev` ARM64 Linux VM (release `appine-run`, `/bench/store` and `/bench/jvm`
using the SHA-256-verified Alpine 3.24.3 `ld-musl-aarch64.so.1`) with temporary env-gated probes
(reverted after collection) across six representative workloads:

- `gcc-lvm`: `gcc -std=gnu99 -O2 -c lvm.c -o /tmp/lvm.o` (Lua 5.4.7)
- `python`: `python3 -c 'import json, re, subprocess, asyncio; print(sum(i*i%7 for i in range(1500000)))'`
- `gobuild`: cold `go build` of a `fmt.Println` module (`/root/gobuild.sh`)
- `node`: `node -e` filling a 1 MiB `Uint8Array` 20 times + `JSON.stringify` of 15,000 objects
- `gzip`: `gzip -c /root/lua.tar > /dev/null`
- `mvn-warm`: warm offline Maven package build (`/root/mvn-warm.sh` on OpenJDK 21)

### 1. Zero-perturbation wall-clock A/B (`R_INTERP` threshold sweep)

Best of 2 runs per threshold (milliseconds; `off` disables memop gating completely):

| Workload | `off` | `128` (current) | `64` | `32` |
|---|---:|---:|---:|---:|
| `gcc-lvm` | **2171** | 2181 (+10) | 2202 (+31) | 2220 (+49) |
| `python` | **521** | 524 (+3) | 529 (+8) | 524 (+3) |
| `gobuild` | **4644** | 4999 | 4732 | 4705 |
| `node` | 240 | 233 (−3%) | 235 | **209 (−13%)** |
| `gzip` | 126 | **124** | 125 | 125 |
| `mvn-warm` | **5666** | 5744 (+78) | 5728 (+62) | 5787 (+121) |

The current `R_INTERP` exit path at `128 B` is neutral to slightly slower on `gcc-lvm` and
`mvn-warm`, and lowering the `R_INTERP` threshold to `64`/`32 B` regresses them further. Only
`node` (which performs repeated 1 MiB `Uint8Array.fill` calls) benefits from the current path.

### 2. Musl `memop` call volume, size buckets, and same-page rates

All calls intercepted (`threshold = 0`, semantics unchanged):

| Workload | Op | Total calls | `32–127 B` (same-page) | `128 B–4 KiB` (same-page) | `>4 KiB` | `>64 MiB` | `exec_memop` ok / fail |
|---|---|---:|---:|---:|---:|---:|---:|
| `mvn-warm` | `memset` | 8,363,379 | 2,791,706 (**98.9%**) | 1,449,140 (**83.5%**) | 37,855 | 0 | 1,486,992 / 3 |
| `mvn-warm` | `memcpy` | 4,124,283 | 803,566 (**98.3%**) | 210,862 (**76.0%**) | 7,751 | 0 | 218,613 / 0 |
| `mvn-warm` | `memmove` | 124,530 | 33,419 (**98.2%**) | 36,828 (**75.9%**) | 4,621 | 0 | 41,449 / 0 |
| `mvn-warm` | `memcmp` | **29,959,397** | 6,278,128 (**98.3%**) | 9,910 (**95.6%**) | 2 | 0 | 9,912 / 0 |
| `mvn-warm` | `memchr` | 1,019,980 | 510,548 (**99.0%**) | 40,572 (**99.3%**) | 491 | **57,109** | **41,063 / 57,109** |
| `gcc-lvm` | `memset` | 705,250 | 253,322 (**97.8%**) | 184,617 (**96.0%**) | 3,302 | 0 | 187,909 / 10 |
| `gcc-lvm` | `memcpy` | 987,190 | 184,538 (**98.4%**) | 86,359 (**91.4%**) | 452 | 0 | 86,809 / 2 |
| `gcc-lvm` | `memcmp` | 528,546 | 19,878 (**100%**) | 0 | 0 | 0 | 0 / 0 |
| `gcc-lvm` | `memchr` | 6,257 | 4 | 2 | 23 | **6,028** | **25 / 6,028** |
| `python` | `memcpy`+`memset` | 141,663 | 36,877 (**98.4%**) | 19,680 (**88.8%**) | 152 | 0 | 19,832 / 0 |
| `python` | `memcmp` | 267,211 | 931 | 1,012 (**100%**) | 0 | 0 | 1,012 / 0 |
| `node` | `memcpy`+`memset` | 72,954 | 28,475 (**98.8%**) | 4,115 (**93.7%**) | 447 | 0 | 4,562 / 0 |
| `node` | `memcmp` | 81,076 | 26,903 (**99.4%**) | 1 | 0 | 0 | 1 / 0 |

Direction 1a candidates across all six workloads:

- `bzero`: **0 calls** total.
- `memrchr`: at most 90 calls (`mvn-warm`), all `<64 B`.
- `mempcpy`: at most 547 calls (`mvn-warm`), >95% `<16 B`.
- `strnlen`: calls `memchr` internally in musl (and accounts for the `>64 MiB` `SIZE_MAX` calls).
- `strlen` / `strchr` / `strcmp`: 90–99.9% `<32 B` (`mvn-warm` `strcmp`: 1,055,822 calls, 98.2%
  `<16 B`; `strlen`: 188,188 calls, only 26 `>=128 B`; `gcc-lvm` `strlen`: 94% `<16 B`, `strcmp`:
  99.9% `<16 B`).

### 3. Tight single-block self-loops vs. total dynamic inline TLB checks

Dynamic inline soft-TLB checks executed inside single-block self-loops (`<=32` guest instructions
with a direct back-edge to the block's own start PC):

| Workload | Total dynamic TLB checks | Tight self-loops | Write-only | Read+write | Read-only | Notable top self-loops |
|---|---:|---:|---:|---:|---:|---|
| `gcc-lvm` | 2.58 B | 6.75% | **0.12%** | 4.21% | 2.42% | Compiler IR / bitmap / list walks |
| `python` | 0.59 B | 1.26% | **0.00%** | 0.96% | 0.30% | #3 musl byte-by-byte `memcmp` (0.09%) |
| `gobuild` | 13.64 B | 8.66% | **0.19%** | 6.82% | 1.65% | Go `duffzero` (0.96%) + `memclr` (0.10%) + `memmove` (0.08%) + `memequal` (0.08%) ≈ **1.22%** |
| `node` | 0.08 B | 10.91% | **0.25%** | 6.27% | 4.40% | V8 string/hash loops + #12 musl `memcmp` |
| `gzip` | 0.15 B | 7.51% | **0.02%** | 7.47% | 0.02% | LZ77 hash-chain & window slide |
| `mvn-warm` | 17.18 B | 12.43% | **0.09%** | 9.20% | 3.14% | HotSpot C++/GC loops + #5 musl `memcmp` (0.35%) |

### Key findings

1. **Why current `R_INTERP` memop stalls on real builds**: 82.4% (`mvn-warm`, 1.45M calls) to 93.2%
   (`gcc-lvm`, 256K calls) of `>=128 B` calls are **same-page `128 B–4 KiB`** transfers. Each takes
   a full `exit`/`enter` (saving/restoring `V0–V31` = 512 B, `FPSR`, `NZCV`, `FPCR`, GPRs) plus two
   radix page-table walks for mutating ops (`memop_check_range` + the copy loop), outweighing the
   saved soft-TLB checks at 128–512 B.
2. **Existing `memchr(..., SIZE_MAX)` trap**: musl's `strnlen(..., SIZE_MAX)` calls
   `memchr(s, 0, SIZE_MAX)`, which passes `n >= 128`, pays a full `R_INTERP` transition, and is
   immediately rejected by `rem > MEMOP_MAX_BYTES` (`mvn-warm`: 57,109 wasted exits, 58% fail rate;
   `gcc-lvm`: 6,028 wasted exits, 99.6% fail rate).
3. **Direction 2A has huge volume — and should include `memcmp`**: `32–4095 B` calls are 76–99%
   same-page across `memset`, `memcpy`, `memmove`, `memcmp`, and `memchr`. Moreover, musl aarch64's
   `memcmp` is a **1-byte-per-iteration C loop** (`ldrb`/`ldrb`, 2 TLB checks per byte) that shows
   up in the top self-loops of `mvn-warm` (29.96M calls, #5 self-loop), `python` (#3), and `node`
   (#12). An in-cache same-page 8-byte-step `memcmp` fast path (down to 8–16 B) targets massive
   unaccelerated volume.
4. **Direction 1a, 1b (Go), 2B, and 3 are low-priority by data**:
   - Direction 1a (`bzero`/`memrchr`/`mempcpy`/`strlen`/`strchr`/`strcmp`): negligible large-call
     volume.
   - Direction 1b (Go runtime): the 4 Go helpers total ~1.22% of `gobuild`'s dynamic TLB checks.
   - Direction 2B: write-only tight self-loops are `<=0.25%` everywhere, and most hot self-loops in
     `gcc`/`mvn`/`node`/`gobuild` are pointer-chasing or hash-table walks rather than canonical
     bulk copy loops.
   - Direction 3: **0 real `>64 MiB` calls** occurred across all six workloads (only `SIZE_MAX`
     sentinels in `memchr`).

---

## Suggested execution order & verification

1. **Step 0 (Done — 2026-11-22)**: Profiling completed (results above).
2. **Step 1 (Done — 2026-11-22)**: Fixed the `memchr`/`strncmp` `SIZE_MAX` budget rejection and
   implemented Direction 2A in-cache same-page helpers (`memset`, overlap-safe `memcpy`/`memmove`,
   8-byte `memcmp`, first-page SWAR `memchr`, plus TLB warming on `exec_memop`).
   - Strict same-session alternating A/B (`HEAD` vs. `2A`, best of 3 runs):
     - `mvn-warm`: `5959 ms -> 5840 ms` (**−2.0%**, median `6038 -> 5911 ms`, `−2.1%`; `exits_interp`
       dropped to 13,614 from >57,000 `memchr` failures alone)
     - `gcc-lvm`: `2439 ms -> 2420 ms` (**−0.8%**, median `2450 -> 2426 ms`, `−1.0%`; `exits_interp`
       dropped to 1,953 from >6,000 `memchr` failures alone)
     - `node`: `215 ms -> 214 ms` (median `226 -> 218 ms`, `−3.5%`)
     - `python`: `553 ms -> 554 ms` (neutral)
   - Guest musl microbenchmark (500,000 calls): `memset 256 B` `18 -> 2 ms` (**9.0×**),
     `memcpy 256 B` `22 -> 4 ms` (**5.5×**), `memcmp 48 B` `28 -> 3 ms` (**9.3×**),
     `memcmp 256 B` `19 -> 7 ms` (**2.7×**), `memchr(..., SIZE_MAX)` @200 B `29 -> 7 ms` (**4.1×**).
3. **Remaining directions (deferred unless new workload evidence justifies them)**:
   - Direction 1a (extra musl ops), Direction 1b (Go runtime), Direction 2B (tight-loop idiom
     recognition), and Direction 3 (>64 MiB chunking). If Debian/Ubuntu glibc workloads become a
     priority later, extending Direction 2A's registered symbols to pinned glibc binaries will
     likely yield a higher return per line of complexity than Direction 2B.
4. **Verification checklist**:
   - Unit & integration tests in `core/engine/tests/dbt.rs` covering: `< threshold`, `== threshold`,
     `> threshold`, unaligned/cross-page boundaries, overlapping `memmove` (both directions),
     read-only/unmapped tail pages (precise fault with zero partial writes), `memchr` with
     `n = SIZE_MAX` / `> MEMOP_MAX_BYTES`, TBI tagged pointers, active watchpoints (`nwatch != 0`),
     shadow return stack alignment (`dbt_rs`), code-group shared vs. private blocks, concurrent
     `set_memops` updates, and instance pool reuse.
   - Differential lockstep tests (`tests/lockstep`) and both `Default` and `Go` register sets.
   - Re-run the wall-clock A/B across `gcc-lvm`, `python`, `node`, and `mvn-warm` to verify net
     speedup over `th=off`.
   - Update `.agents/maps/engine/dbt.md` via the `map-module` skill once implemented.
