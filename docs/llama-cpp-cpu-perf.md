# Optimizing CPU Performance for `llama.cpp`

> **Status**: Steps 0–3 completed (Step 0 profiling, Step 1, Phase 2A, Phase 2B-1, Post-2B-1 profiling, Direction 3A, Phase 2B-2, and Direction 3B — 2026-11-22–23). Direction 5.2–5.4 remain open/deferred.
>
> **Scope**: CPU-only `llama.cpp` inference under Appine Tier 1 (Vulkan GPU offload is out of scope; see `docs/mobile-gpu.md`), subject to strict non-regression on general workloads (`gcc`, `python`, `node`, `go build`, `mvn-warm`, process spawning).
>
> **Key references**: `core/engine/src/c/{dbt.c,features.c,mmu.c,cpu.c,internal.h}`, `core/engine/include/appine/engine.h`, `core/engine/src/lib.rs`, `core/hal/src/lib.rs`, `core/kernel/src/{mm.rs,syscall/mem.rs,syscall/fast.rs,syscall/sched.rs}`, `docs/rounds/{27-interleaved-checks,30-translated-access,31-superblocks,141-fp16-jscvt}.md`, `docs/mobile-gpu.md`, `docs/dbt-memop-extensions.md`, and `.agents/maps/{engine,engine/dbt,kernel/mmu,kernel/mm,kernel/futex,kernel/sysfs,kernel/exec}.md`.

---

## Summary & current progress

### End-to-end throughput progression (Qwen2.5-0.5B, ARM64 Linux VM)

| Workload | Native (t/s) | Step 0 baseline (t/s) | Step 0 slowdown | Post-optimization (t/s) | Slowdown vs. native |
|---|---:|---:|---:|---:|---:|
| Q4_0 `pp512` `-t 1` | 285.42 ± 1.44 | 189.26 ± 1.31 | 1.51× | 259.52 (3A) / 255.68 (2B-2) | **~1.10–1.12×** |
| Q4_0 `tg128` `-t 1` | 110.07 ± 0.11 | 81.95 ± 0.92 | 1.34× | 101.63 (3A) / 93.45 (2B-2) | **~1.08×** |
| Q4_0 `pp128` `-t 4` | 1159.98 ± 0.41 | 847.70 ± 3.72 | 1.37× | 980.02 (2B-1) / 973.6 (3B) | **~1.18–1.19×** |
| Q4_0 `pp512` `-t 4` | 1027.65 ± 3.47 | 707.10 ± 3.75 | 1.45× | 978.24 (3A) / 958.2 (3B) | **~1.05–1.07×** |
| Q4_0 `tg128` `-t 4` | 225.25 ± 0.46 | 177.91 ± 10.12 | 1.21–1.27× | 207.10 (peak 213.14, 3A) / 208.0 (3B) | **~1.06–1.09×** |
| F16 `pp128` `-t 4` | 377.45 ± 2.07 | 225.43 ± 1.71 | 1.64–1.67× | 323.96 (2B-2) / 329.6 (3B) | **~1.15–1.16×** |
| F16 `tg32` `-t 4` | 91.13 ± 0.52 | 72.09 ± 0.23 | 1.13–1.26× | 86.45 (3A) / 86.9 (3B) | **~1.05×** |
| Non-ML `appine-bench` (geomean) | — | 1.71× | — | 1.68× (2B-2) | **No regression** |

*Note: Absolute `llama-bench` numbers vary slightly across VM sessions; see the same-session alternating A/B tables in [Implementation log & A/B results](#implementation-log--ab-results) for controlled per-step deltas.*

### Optimization track status

| Track | Scope | Status | Completed |
|---|---|---|---|
| **Step 0** | Profiling baseline, hot-loop disassembly, ISA tier & big.LITTLE audit | Done | 2026-11-22 |
| **Direction 1** | Relax Tier 1 block & `plan_group` limits (`MAX_BLOCK_INSNS`, `GROUP_SLOTS`, affine aliases, `M_REG`/stolen bases) | Done (Step 1) | 2026-11-22 |
| **Direction 2** | Verify `ggml-cpu` ISA tier selection (`I8MM` / `BF16` vs. `SVE`) | Investigated (no SVE needed) | 2026-11-22 |
| **Direction 3A** | L2 2 MiB superpages, 2 MiB `stlb` / fast-loop span, sequential TLB prefill, bulk `exec_memop` | Done | 2026-11-23 |
| **Direction 3B** | Unlocked `madvise` forwarding, widened 16 MiB RO file `fault_in`, soft-PTE prefill | Done | 2026-11-23 |
| **Direction 4** | Strip-mined in-page / superpage fast loops (2A core, 2B-1 `flash_attn` + pinning, 2B-2 `gemm_bloc` + cross-page) | Done (2A, 2B-1, 2B-2) | 2026-11-22–23 |
| **Direction 5.1** | Emit host `YIELD` (`0xd503203f`) verbatim | Done (Step 1) | 2026-11-22 |
| **Direction 5.2–5.4** | On-device big.LITTLE topology audit, `--poll 0`/OpenMP `futex` profiling, glibc `memop` coverage | Open / deferred | — |

---

## Scope, workload regimes & initial baseline

This note covers optimization directions for **CPU-only `llama.cpp` inference** inside Appine (Vulkan GPU offload is out of scope for now; see `docs/mobile-gpu.md` for current mobile driver issues that leave CPU inference as the primary reliable path on phones). Every direction is evaluated under a strict non-regression constraint: general workloads (`gcc`, `python`, `node`, `go build`, `mvn-warm`, process spawning) must not regress.

### Prior measurements and two runtime regimes

- **Prior ratios** (`docs/rounds/141-fp16-jscvt.md`, Apple Silicon VM, 4 threads, `llama-bench -p 128 -n 32`):
  - Qwen2.5-0.5B F16: prompt `1.64×` native, generation `1.22×` native.
  - Qwen2.5-0.5B Q4_0: prompt `1.38×` native, generation `1.21×` native.
  - Standalone 4096-element F16 dot-product microbenchmark (`ggml_vec_dot_f16`): `2.1×` slower than native (`0.069` vs. `0.0326` ns/element), attributed to inline soft-MMU checks. On narrower mobile cores (Cortex-A715/A720/X3/X4 vs. wide Apple Silicon), extra host instructions per load cost proportionally more.
- **Two distinct runtime regimes in `llama.cpp`**:
  1. **Prompt processing (prefill, `pp128`/`pp512`)** — compute- and L1/L2-bound tiled GEMM / `vec_dot` kernels (`SDOT`/`SMMLA`/`FMLA`/`BFDOT`). Overhead comes mainly from per-load inline soft-MMU checks in unrolled SIMD loops and from whether `ggml` selects an `I8MM`/`BF16` backend tier.
  2. **Token generation (decode, `tg32`/`tg128`)** — memory-streaming and barrier-bound. Every generated token streams through the entire model's weights (~350 MB for 0.5B Q4_0, ~900 MB for 1.5B, ~2–4 GB for 3B–7B), whereas the per-thread 4 KiB data TLB covers only **16 MiB** (`APPINE_TLB_ENTRIES = 4096` × 4 KiB in `core/engine/include/appine/engine.h`). Decoding a 1.5B–7B model therefore triggers hundreds of thousands to ~1M soft-TLB misses per token, plus frequent 4 KiB page crossings on unaligned quantized blocks (`block_q4_0` = 18 B, `block_q8_0` = 34 B, `block_q4_K` = 144 B).

### Initial engine and kernel baseline (pre-optimization, 2026-11-22)

- **ISA features (`core/engine/src/c/features.c`)**: Appine advertises `FP`, `ASIMD`, `ASIMDDP` (DotProd), `FPHP`/`ASIMDHP` (FP16), `ASIMDFHM`, `ASIMDRDM`, `FCMA`, `I8MM`, `BF16`, `FRINTTS`, `ATOMICS` (LSE), `LRCPC`/`ILRCPC`, crypto/CRC, `FLAGM`/`FLAGM2`, `SB`, `DCPOP`/`DCPODP`, `DIT`, and `ECV`. It does **not** advertise `SVE`/`SVE2`, `SME`/`SME2`, `LSE2` (`uscat`), or `EBF16`.
- **Tier 1 translation (`core/engine/src/c/dbt.c`, prior to Step 1)**:
  - `MAX_BLOCK_INSNS = 64` (blocks also ended at 4 KiB code page boundaries).
  - `plan_group` shared one TLB check across same-base accesses inside a block up to `GROUP_SPAN = 512` B, `GROUP_MAX = 16` accesses, and `GROUP_SLOTS = 4` concurrent base slots (`struct appine_cpu::dbt_groups[4]`).
  - `emit_refill` handled TLB misses and cross-page checks in translated code by saving `X0–X4`, checking `nwatch`, walking the 4-level radix page table (`MMU_LEVELS = 4`, `LEAF_SPAN = 2 MiB`), filling both read and write TLB halves, updating `tlb_used`, and returning via `br T1`.
  - `HINT` space (`0xd503201f`, including `YIELD` = `0xd503203f`) emitted no instructions.
- **Kernel layer (prior to Direction 3B)**:
  - Private `FUTEX_WAIT`/`FUTEX_WAKE` and `sched_yield` run on the no-BKL fast path (`core/kernel/src/syscall/fast.rs`), backed by a global `Futexes` mutex/linear list and per-thread `eventfd` + `poll()`.
  - `sched_setaffinity` is forwarded to host threads (`core/kernel/src/syscall/sched.rs`); `/sys/devices/system/cpu/` exposes synthesized `topology/` and host-copied `cache/` and `cpufreq/` (`.agents/maps/kernel/sysfs.md`).
  - `madvise` ignored `MADV_WILLNEED`, `MADV_SEQUENTIAL`, `MADV_RANDOM`, and `MADV_POPULATE_*` (`core/kernel/src/syscall/mem.rs`); mappings > 1 MiB populated soft page-table entries on demand in 2 MiB chunks via `Mm::fault_in` under the BKL (`core/kernel/src/mm.rs`).
  - Length-gated `memop` acceleration matches only the pinned Alpine musl SHA-256 (`.agents/maps/kernel/exec.md`).

---

## Step 0 profiling baseline (2026-11-22)

**Testbed**: Development ARM64 Linux VM (Apple Silicon host, 8 vCPUs, kernel `6.8.0-117-generic`), `llama.cpp` v0.8.0 multi-variant build (`GGML_CPU_ALL_VARIANTS=ON`, Alpine musl), release `appine-run --tier 1` on `/bench/store` vs. native `appine-difftest:latest` Alpine container.

### 1. Native vs. Appine Tier 1 throughput (`libggml-cpu-armv8.2_2.so`)

| Model & workload | Native (t/s) | Appine Tier 1 (t/s) | Slowdown (Native / Appine) |
|---|---:|---:|---:|
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 285.42 ± 1.44 | 189.26 ± 1.31 | **1.51×** |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 1` | 110.07 ± 0.11 | 81.95 ± 0.92 | **1.34×** |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 1159.98 ± 0.41 | 847.70 ± 3.72 | **1.37×** |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 1027.65 ± 3.47 | 707.10 ± 3.75 | **1.45×** |
| Qwen2.5-0.5B Q4_0 `tg32` `-t 4` | 226.78 ± 4.10 | 188.01 ± 10.04 | **1.21×** |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 225.25 ± 0.46 | 177.91 ± 10.12 (186.74 in perf run) | **1.21–1.27×** |
| Qwen2.5-0.5B F16 `pp128` `-t 4` | 377.45 ± 2.07 | 225.43 ± 1.71 (230.02 in perf run) | **1.64–1.67×** |
| Qwen2.5-0.5B F16 `tg32` `-t 4` | 91.13 ± 0.52 | 72.09 ± 0.23 (80.74 in perf run) | **1.13–1.26×** |

### 2. CPU time breakdown (`APPINE_PERF_MAP=1 perf record -e task-clock -F 999`)

| Workload | `dbt_blocks` | `dbt_shared_routines` (`emit_refill` etc.) | Linux kernel | Host (`appine-run` / libc) |
|---|---:|---:|---:|---:|
| Q4_0 prefill (`pp512 -t 4 -r 3`, 12,087 samples) | **95.15%** | 2.57% | 1.42% | 0.85% |
| Q4_0 decode (`tg128 -t 4 -r 3`, 8,197 samples) | **95.21%** | **1.99%** | 1.68% | 1.12% |
| F16 prefill (`pp128 -t 4 -r 3`, 9,333 samples) | **92.75%** | 4.96% (`refill[1]` write cross-page = 3.33%) | 0.96% | 1.33% |
| F16 decode (`tg32 -t 4 -r 3`, 1.17 GiB, 5,151 samples) | **94.18%** | **2.62%** | 1.75% | 1.46% |

Key `--stats` and startup observations across all 7 baseline runs:

- **Tier 0 / syscall overhead is negligible**: `tier 0 fallback` is 38–40 instructions (`0.0%`), `exits: interp` is 47–263, `code cache flushes` is 0, `groups undone` is 3–7. `exits: svc` is virtually identical between `-t 1` (8,484 / 8,579) and `-t 4` (8,515 / 8,614), confirming that with `llama.cpp`'s default `--poll 50`, `futex`/`sched_yield` syscalls are not a bottleneck.
- **Static grouping coverage**: `memory (inline)` is ~34.0–34.5% of translated guest instructions, with `sharing a check` at 14.4–15.3% (~44% of memory instructions grouped).
- **`emit_refill` is minor even on 1.17 GiB streaming decode**: `dbt_shared_routines` totals only 1.99% on Q4_0 decode and 2.62% on 1.17 GiB F16 decode (read refill ~1.8–2.3%). The 3.33% write refill (`+0x440..+0x57f`) in F16 prefill is not streaming weight misses; it comes from `tinyBLAS::gemm_bloc` spilling 384 B (`stp q0..q31, [sp, #0..352]`) on every inner iteration when that grouped stack frame straddles a 4 KiB page boundary.
- **Startup / `fault_in`**: End-to-end wall time for `-p 1 -n 0 -t 4 -r 1` on the 1.17 GiB F16 model is 392–401 ms (cold vs. warm), with host userspace (`appine-run` including `fault_in`, `dbt_run`, `prepare`, `sqlite3`) totaling 0.85–1.46% across the benchmark runs.

### 3. Hot translated inner loops (`libggml-cpu-armv8.2_2.so`, guest base `0x7fffbe594000`)

Over **75–85%** of total runtime concentrates in 7 concrete inner loops:

| # | Workload | Kernel | Offset range | Share of CPU | Primary bottleneck |
|---:|---|---|---|---:|---|
| 1 | Q4_0 prefill | `ggml_gemm_q4_0_4x4_q8_0` | `0xba094..0xba490` | **49.2%** | Hits all 4 Direction 1 limits (256 insns, 5 bases, stolen `x28`, derived `x20`) |
| 2 | Q4_0 prefill | `ggml_compute_forward_flash_attn_ext_tiled` | `0x6f260`, `0x6f5a0`, `0x6ed64` | **28.7%** | Short strided loops with stolen regs, `M_REG`, register stride (needs Dir. 4) |
| 3 | Q4_0 decode | `ggml_gemv_q4_0_4x4_q8_0` | `0xb5c00..0xb5c84` | **39.7%** | Already grouped; ~16 extra host insns/iter from 2 TLB checks + kick check |
| 4 | Q4_0 decode | `ggml_gemv_q8_0_4x4_q8_0` | `0xb9480..0xb94e4` | **21.9%** | `mov x5, x2` alias blocks grouping; per-iter TLB + kick checks |
| 5 | All | `ggml_barrier` | `0x152f8` | **1.5–14.3%** | 4-insn spin loop with dropped `yield` (`0xd503203f`) |
| 6 | F16 prefill | `tinyBLAS::gemm_bloc<4,6>` + `<4,5>` | `0x9dff0..0x9e104`, `0x9e600..0x9e6f0` | **78.0%** | 4 KiB code-page split, 10 `M_REG` rows, 12 `stp [sp]` spills (`refill[1]`) |
| 7 | F16 decode | `ggml_vec_dot_f16` | `0x67de0..0x67e0c` | **72.1%** | 12-insn loop paying ~20 extra host insns/iter (`dbt_groups` + TLB + kick) |

Detailed loop anatomy:

1. **`ggml_gemm_q4_0_4x4_q8_0` (`0xba094..0xba490`, 49.2% of Q4_0 prefill)**:
   - One **256-instruction** straight-line inner loop (`subs x24, x24, #1; b.gt ba094`), initially split into **5 blocks** (`ba094` 14.3%, `ba194` 11.7%, `ba294` 10.3%, `ba394` 12.7%, `ba494` 0.7%) by `MAX_BLOCK_INSNS = 64`, severing `[x23]`, `[x22]`, and `[x21]` groups across block boundaries.
   - Hit **all four** Direction 1 limits simultaneously: 256-insn body > `MAX_BLOCK_INSNS` (64); 5 live base pointers (`x28`, `x25`, `x23`, `x22`, `x21`) > `GROUP_SLOTS` (4); activation pointer in stolen register **`x28` (`CTX`)** (`ldr q, [x28, #0/16/32/48]`) forcing 5 redundant `ctx->x[28]` loads + TLB checks; scale load via derived pointer **`sub x20, x28, #8; ldr d17, [x20]`**.
   - Pure read-only constant-stride self-loop (`x28 += 0x48`, `x25/x23/x22/x21 += 0x88`).
2. **`ggml_compute_forward_flash_attn_ext_tiled` (28.7% of Q4_0 prefill)**:
   - Three compact 10–11 instruction strided self-loops: `0x6f260` (12.7%, stolen `x17` post-index `ldp q28, q31, [x17], #256` + `M_REG` `ldr s23, [x2, x28, lsl #2]` with stolen `x28` + `ld1r [x2]`), `0x6f5a0` (8.8%, `add x4, x4, x26` with stolen `x26`), and `0x6ed64` (4.2%, `M_REG` `ldr h31, [x1, x6, lsl #1]` + `str s31, [x2, x6, lsl #2]`).
   - Too short and heterogeneous for `plan_group` alone; requires **Direction 4**.
3. **`ggml_gemv_q4_0_4x4_q8_0` (`0xb5c00..0xb5c84`, 39.7% of Q4_0 decode)**:
   - 34-instruction single-block self-loop (`x2 += 34` with 3 loads, `x0 += 72` with 5 loads, `cmp w6, w5; b.gt`).
   - Already fully grouped at baseline (2 bases, no stolen regs, non-interleaved, <64 insns). Direction 1 gives essentially zero gain here; remaining overhead (~16 extra host insns per 34-insn iteration from 2 group TLB checks + 1 kick check) requires **Direction 4**.
4. **`ggml_gemv_q8_0_4x4_q8_0` (`0xb9480..0xb94e4`, 21.9% of Q4_0 decode)**:
   - 26-instruction single-block self-loop (Qwen 0.5B's `output.weight` is `Q8_0`): `x0 += 0x22`, `x2 += 0x88`, with **`mov x5, x2`** aliasing `x2` for `ld1 {v28..v31}, [x5], #64` and `ld1 {v24..v27}, [x5]`.
   - Tracking **`MOV Xd, Xn`** (`ORR Xd, XZR, Xn`, zero-offset affine alias) merges `[x2, #-8]` with both `[x5]` `ld1`s; **Direction 4** removes the remaining per-iteration TLB and kick checks.
5. **`ggml_barrier` (`0x152f8`, 14.3% Q4_0 decode, 5.3% F16 decode, 2.2% Q4_0 prefill, 1.5% F16 prefill)**:
   - Exact 4-instruction spin loop: `152f8: yield; ldr w0, [x1]; cmp w3, w0; b.eq 152f8`. Dropping `yield` (`0xd503203f`) directly matches Direction 5.1.
6. **`tinyBLAS::gemm_bloc<4, 6>` (`0x9dff0..0x9e104`, 65.1%) + `<4, 5>` (`0x9e600..0x9e6f0`, 12.9%) (78.0% of F16 prefill)**:
   - 69-instruction inner loop (`9dff0..9e104`): split at the 4 KiB code page boundary `9e000` (2.6% + 56.9%) and again at `9e100` (5.7%, just `cmp x11, x3; b.gt`) by `MAX_BLOCK_INSNS = 64`.
   - Loads 10 distinct matrix rows via `M_REG` (`ldr q, [x2, x3/x6/x5/x4]` and `[x1, x7/x3/x6/x5/x4]`, each advancing +16 B/iter via `x0 += 8` shifted `<< 1`, using stolen `x16`/`x17`/`x18`), plus 12 `stp q, [sp, #0..352]` stores per iteration (triggering the 3.33% `refill[1]` cross-page overhead).
7. **`ggml_vec_dot_f16` (`0x67de0..0x67e0c`, 72.1% of F16 decode)**:
   - 12-instruction single-block self-loop (`ldp`×2 on `x2 += 64` interleaved with `ldp`×2 on `x4 += 64`, 4× `fmla v*.8h`, `cmp x6, x2; b.ne`).
   - Already grouped, yet interleaving forces `dbt_groups` spill/reload + 2 group TLB checks + kick check (~20 extra host instructions on top of 12 guest instructions). Ideal **Direction 4** target (up to 64 native iterations per 4 KiB page).

### 4. ISA tier (Direction 2) & real-device big.LITTLE audit (Direction 5.2)

- **ISA tier**: `GGML_BACKEND_DEBUG=1` confirms both native and Appine load `libggml-cpu-armv8.2_2.so`. In upstream `ggml/src/CMakeLists.txt` (`CMAKE_SYSTEM_NAME MATCHES "Linux"`), `armv8.6_1` requires `DOTPROD FP16_VECTOR_ARITHMETIC SVE MATMUL_INT8` (there is no non-SVE `MATMUL_INT8` Linux variant, whereas Android defines `android_armv8.6_1` without `SVE`). Neither the Apple Silicon Linux VM nor the tested Galaxy S23 (`SM-S9110`, Snapdragon 8 Gen 2) exposes `sve` in host `/proc/cpuinfo` (both expose `i8mm bf16` only). This confirms **no SVE implementation is needed**; unlocking `I8MM` is a build/packaging choice (`-DGGML_NATIVE=ON` or a non-SVE `I8MM` backend variant).
- **Android big.LITTLE (`SM-S9110`, Snapdragon 8 Gen 2)**: Host topology is 3× Cortex-A510 (`cpu0–2`, `cpu_capacity=266`, 2.02 GHz) + 4× Cortex-A715/A710 (`cpu3–6`, `cpu_capacity=811`, 2.80 GHz) + 1× Cortex-X3 (`cpu7`, `cpu_capacity=1024`, 3.36 GHz); `cpu_capacity` and `cpufreq/cpuinfo_max_freq` carry SELinux label `u:object_r:sysfs_devices_system_cpu:s0`. Upstream `llama.cpp` (`common/common.cpp`'s `common_cpu_get_num_math()`) only reads `/sys/devices/system/cpu/cpuN/topology/thread_siblings` on ARM Linux to count physical cores and does not read `cpu_capacity` or `midr_el1` to pin threads.

---

## Optimization roadmap & design

### Direction 1: Relax Tier 1 block & `plan_group` limits *(Completed — Step 1)*

Unrolled `ggml-cpu` dot-product and tiled GEMM inner loops routinely hit four artificial ceilings in `core/engine/src/c/dbt.c` that rarely trigger on branchy integer code:

1. **Decouple block length from the hard `MAX_BLOCK_INSNS = 64` cap**
   - Unrolled `vec_dot` and `4×4`/`4×8`/`8×8` GEMM inner loops often span 60–200 straight-line guest instructions, most of which are 1:1 verbatim NEON arithmetic (`sdot`, `smmla`, `fmla`). Splitting a loop body at 64 guest instructions terminates every active `plan_group` and forces every live base pointer to re-run a full 6-instruction inline TLB check in the next block.
   - **Approach**: Stop translating a block based on remaining host-word / stub / fixup budget (keeping `MAX_BLOCK_WORDS` within `REFILL_RESUME_SHIFT` and `BRANCH_MASK`) and raise the guest instruction cap toward the `uint8_t block::nguest` limit (reviewing `WORDS_LIMIT` and `nogroup()`'s `4 * MAX_BLOCK_INSNS` span so memory bounds and strike-out windows stay sane).
   - **Non-regression**: Branchy workloads (`gcc`, `python`, `node`, JVM) have short basic blocks (typically 5–15 instructions) and are unaffected.
2. **Expand `GROUP_SLOTS` from 4 to 8**
   - Tiled GEMM microkernels (`4×8`, `8×8`) interleave 4–8 weight row pointers plus activation and output pointers in a single loop body. Once 4 slots are occupied, the 5th+ base pointers cannot group at all and pay a full inline TLB check on every load.
   - **Layout verification**: In `struct appine_cpu` (`core/engine/include/appine/engine.h`), `offsetof(struct appine_cpu, tlb)` was **448 B** (`dbt_groups[4]` occupied bytes `416..448`). The `ldp` constraint is `TLB_OFF % 16 == 0 && TLB_OFF + 16 <= 504`, leaving **40 bytes of unused headroom**. Expanding to `uint64_t dbt_groups[8]` moves `TLB_OFF` to **480 B** (`480 + 16 = 496 <= 504`) with **zero change** to TLB addressing instructions (mirrored in `core/engine/src/lib.rs` so `layout_matches` passes).
   - **Non-regression**: Workloads with `<= 4` concurrent groups never touch the extra slots.
3. **Track affine derived base pointers (`ADD`/`SUB Xd, Xn, #imm` and `MOV Xd, Xm`) in `plan_group`**
   - Quantized blocks such as `block_q4_0` (18 B) and `block_q8_0` (34 B) are not 16-byte aligned. Because AArch64's unsigned-offset `LDR Qt, [Xn, #uimm]` requires 16-byte alignment, `LDUR` only reaches `[-256, +255]`, and `LD1` has no immediate offset at all, compilers frequently materialize derived pointers (`add x9, x0, #18; ldr q0, [x9, #2]` or `add x9, x0, #2; ld1 {v0.16b}, [x9]`).
   - Previously `keeps_group` only tracked in-place updates (`Rd == Rn`), so writing `x9 = x0 + const` caused `plan_group` to treat `[x9]` as an unrelated base and mark `x0`'s group `clobbered`.
   - **Approach**: During `plan_group` lookahead, track block-local affine aliases (`r_derived = rn + const_imm`, cleared whenever `r_derived` is overwritten) and fold accesses through `r_derived` into `rn`'s group with adjusted `off`.
   - **Non-regression**: Pure translation-time analysis; emits fewer runtime instructions and also helps struct sub-pointer accesses in `gcc`/`python`.
4. **Extend grouping to `M_REG` and stolen-register bases**
   - Previously `lead->mode == M_REG`, `m.mode == M_REG`, and `is_stolen(rn)` could not lead or join groups. Indexed vector loops (`ldr q0, [x0, x8]`) sharing the same `(base, index)` and register-starved GEMM kernels assigning a pointer to `x16`/`x17`/`x26`/`x27`/`x28` lost all grouping. Allowing stolen bases to lead (loading `rn` once for the group check and reusing `T2`/`dbt_groups[slot]` while `rn` is unmodified) removes both redundant TLB checks and redundant `ctx->x[rn]` loads.

**Key files**: `core/engine/src/c/dbt.c`, `core/engine/include/appine/engine.h`, `core/engine/src/lib.rs`, `core/engine/tests/dbt.rs`.

---

### Direction 2: Verify & unblock `ggml-cpu` ISA tier selection *(Investigated — Step 0)*

- Appine already implements and advertises `ASIMDDP`, `FP16`, `FHM`, `I8MM` (`SMMLA`/`UMMLA`, roughly 2× `SDOT` throughput on Q4_0/Q4_K/Q8_0 prefill), and `BF16` (`BFDOT`/`BFMMLA`).
- `docs/rounds/141-fp16-jscvt.md` noted that in `GGML_CPU_ALL_VARIANTS=ON` multi-variant builds, the Linux `I8MM` tier (`armv8.6_1`) also requires `SVE`, trapping Appine on `armv8.2_2`.
- **Outcome (Step 0)**: Both native and Appine load `libggml-cpu-armv8.2_2.so` because neither Apple Silicon Linux VMs nor Snapdragon 8 Gen 2 expose `SVE`. **No SVE implementation is needed**; enabling `I8MM` is purely a build/packaging option (`-DGGML_NATIVE=ON` or a non-SVE `I8MM` backend variant).

---

### Direction 3: Reduce streaming soft-TLB miss & cold-fault overhead *(Completed — 3A & 3B)*

> **Hard constraint**: `docs/rounds/27-interleaved-checks.md` and `docs/rounds/30-translated-access.md` proved that adding even **one instruction** to the ordinary inline 4 KiB TLB hit path regresses `gcc` and `python`. All work in this direction stays strictly off the inline 4 KiB hit path.

#### 3A. Refill-path sequential TLB prefill & L2 2 MiB superpage entries

- **Problem**: `emit_refill` runs ~55–65 instructions plus a 4-level radix walk and `tlb_used` RMW on every 4 KiB miss. Streaming 0.5B–7B weights exceeds the 16 MiB TLB on every token, and unaligned quantized blocks / grouped checks (`144–512 B`) cross 4 KiB boundaries frequently, hitting the `cross` refill path even when both pages are warm.
- **Approach**:
  1. *Sequential batch prefill inside `emit_refill`*: Once the walk reaches the L3 leaf table (512 adjacent 4 KiB PTEs covering 2 MiB in contiguous cache lines), check whether the preceding TLB slot `(idx - 1)` is valid with the **same `addend`** (indicating sequential streaming). Only when that signal holds, fill the next `k` (4–8) contiguous same-addend, same-permission 4 KiB slots (16–32 KiB) inside one 64-entry `tlb_used` word, eliminating 75–87% of refill entries on linear scans without polluting random pointer-chasing workloads (`gcc`, `python`).
  2. *L2 2 MiB superpage entries in `kernel/mmu`*: Since `LEAF_SPAN` is already 2 MiB (`mmu.c`) and large file/tensor mappings are backed by a single contiguous `HostRegion` with uniform permissions, an L2 entry covering a fully contiguous, uniform-prot, non-CoW 2 MiB span is tagged (`PTE_SUPER`) as a 2 MiB leaf. `emit_refill` stops one level early, and a per-CPU 2 MiB superpage TLB (`cpu->stlb`) gives fast loops a 2 MiB runway instead of 4 KiB. Any partial `mprotect`, `munmap`, or CoW split inside that 2 MiB range transparently demotes the L2 entry to a normal 512-entry L3 table under the BKL.
- **Non-regression**: Zero change to the inline 4 KiB TLB hit sequence; random-access misses do not trigger batch prefill.

#### 3B. Forward `madvise` hints & widen read-only file `fault_in` windows

- **Problem**: `core/kernel/src/syscall/mem.rs` ignored `MADV_WILLNEED`, `MADV_SEQUENTIAL`, and `MADV_POPULATE_READ` (which `llama.cpp`'s `llama-mmap.cpp` issues on GGUF model mappings). Moreover, `Mm::fault_in` (`core/kernel/src/mm.rs`) filled only one 2 MiB leaf table per guest fault under the BKL, so 4–8 threads scanning a 1–4 GiB model on first inference serialized 500–2000 guest page faults on the BKL.
- **Approach**:
  1. Forward `MADV_NORMAL` / `MADV_RANDOM` / `MADV_SEQUENTIAL` / `MADV_WILLNEED` / `MADV_POPULATE_READ` to host `libc::madvise` **after releasing the BKL** (so host readahead never stalls other guest threads).
  2. For large read-only file VMAs (or ranges explicitly hinted with `MADV_WILLNEED` / `MADV_POPULATE_READ`), widen `fault_in`'s soft-PTE fill span from 2 MiB to 16 MiB and prefill aligned 2 MiB L2 superpages (soft PTEs only — does not touch host pages or inflate RSS, and leaves anonymous reservations like ASan's 2 MiB demand granularity untouched).
- **Non-regression**: Zero impact on anonymous allocations, `fork`, or small-file workloads; improves model cold-load and time-to-first-token (TTFT).

**Key files**: `core/engine/src/c/dbt.c`, `core/engine/src/c/mmu.c`, `core/kernel/src/mm.rs`, `core/kernel/src/syscall/mem.rs`, `core/hal/src/lib.rs`.

---

### Direction 4: Strip-mined in-page / superpage fast loops for strided SIMD self-loops *(Completed — Phases 2A, 2B-1, 2B-2)*

`docs/dbt-memop-extensions.md` (Direction 2B) measured that write-only tight self-loops account for `<= 0.25%` of dynamic TLB checks on `gcc`/`python`/`go`/`node`/`mvn-warm` and rightly deferred tight-loop recognition for general integer workloads. **`llama.cpp` is the opposite regime**: a handful of strided NEON compute loops (`ggml_vec_dot_*`, `ggml_gemm_*`, `flash_attn`, `tinyBLAS::gemm_bloc`, `rms_norm`, `silu`, `rope`, `softmax`, `quantize_row_*`) dominate total execution time.

- **Approach**:
  - In `prepare()`, detect canonical single-block (or cross-4 KiB-code-page) self-loops (`back-edge == x->pc`) whose memory operands use constant-stride or loop-invariant-stride induction pointers (`base_i += stride_i`), with a simple monotonic trip counter (`subs`/`b.ne`, `cbnz`, `cmp`/`b.lo`, etc.), no calls/syscalls/atomics, and no aliased writes that could mutate control/pointer state.
  - Emit a guarded fast-loop prologue:
    1. If `cpu->nwatch != 0`, skip straight to the standard translated loop.
    2. For each induction base `base_i`, probe `cpu->stlb` (2 MiB superpage) first and fall back to `cpu->tlb` (4 KiB), computing how many iterations fit before crossing the verified boundary: `iters_i = bytes_remaining_i / stride_i`.
    3. Compute `safe_iters = min(remaining_trips, min_i(iters_i), KICK_BUDGET)` where `KICK_BUDGET` caps time between `pending` checks so `quiesce`/signals remain responsive within microseconds.
    4. If `safe_iters >= 2`, add each `addend_i` into `base_i` (converting guest pointers to host pointers), execute the **native inner loop** with **zero TLB checks and zero kick checks** for `safe_iters` iterations, then subtract `addend_i` to restore exact guest pointers and fall through to the standard checked loop for page crossings, tail iterations, or kicks.
- **Expected impact**: Inside matched `ggml` kernels, removes ~100% of soft-MMU and kick-check overhead, pushing inner-loop speed close to `1.0×` native across all quantization formats and `llama.cpp` versions (and also accelerating `ffmpeg`, `OpenBLAS`, `numpy`, `zlib`).
- **Non-regression**: Strictly zero code or runtime change for any block that does not match the static loop pattern.
- **Invariants preserved**:
  - Precise exceptions: all accessed bytes across `safe_iters` are verified before the first iteration; any miss or fault falls back to the standard checked loop before mutating guest state.
  - Respect D6 (`X18` untouched, inserted prologue/epilogue never clobbers live guest `NZCV`), both `APPINE_DBT_REGS_DEFAULT` and `APPINE_DBT_REGS_GO`, and template arena compatibility.
  - Aliasing safety: per-iteration memory order in the verbatim native loop is identical because only address translation is hoisted.
  - `c->nwatch != 0` always bypasses the fast loop.

---

### Direction 5: Threadpool sync, `YIELD`, big.LITTLE topology & glibc `memop` polish *(5.1 Done; 5.2–5.4 Open)*

1. **Emit host `YIELD` verbatim instead of dropping it *(Completed — Step 1)***
   - Previously `(insn & 0xfffff01f) == 0xd503201f` emitted nothing for all `HINT` encodings. `ggml_threadpool`'s spin-wait barrier executes `yield` (`0xd503203f`); erasing it turned spin-waits into tight zero-yield loops that contend for memory bandwidth and accelerate thermal throttling on phones (`docs/mobile-gpu.md` observed thermal status rising `0 → 2` on S25 Ultra during `llama-bench`).
   - Special-casing `insn == 0xd503203f` copies `yield` verbatim with zero impact on non-spinning workloads.
2. **Audit big.LITTLE CPU topology visibility on real phones *(Open)***
   - Because `ggml_threadpool` synchronizes all worker threads at every op barrier (hundreds per token), a single thread scheduled onto a LITTLE core drags down overall throughput 2–3×.
   - `sched_setaffinity` and host `cpufreq/`/`cache/` are wired up, but `topology/` is synthesized (no `cluster_cpus` or `cpu_capacity`), `host_midr` is read once globally on a single core (`features.c`) so every `/sys/.../cpu<n>/regs/identification/midr_el1` returns the same value, and Android SELinux may deny reading host `cpufreq`. Verify on device what `llama.cpp` sees and whether worker threads stay on big/mid cores.
3. **Profile `futex` barrier overhead under `--poll 0` / OpenMP *(Open)***
   - Private `FUTEX_WAIT`/`FUTEX_WAKE` bypass the BKL (`core/kernel/src/syscall/fast.rs`), but share a single `Shared::futexes` mutex + linear list and wake threads via per-thread `eventfd` writes + `poll()` (`.agents/maps/kernel/futex.md`).
   - With `llama.cpp`'s default `--poll 50` spinning, futex traffic is negligible (confirmed in Step 0); with OpenMP or `--poll 0`, barrier wakeups can be frequent. Only replace `eventfd`/global-list with bucketed queues + host `SYS_futex` if profiling shows `futex` is a material fraction of decode time.
4. **Broaden `memop` coverage beyond Alpine musl *(Open — see `docs/dbt-memop-extensions.md`)***
   - Alpine guests benefit from in-cache same-page `memcpy`/`memset`/`memmove` helpers and (as of Direction 3A) bulk 2 MiB superpage `exec_memop`; Debian/glibc guests currently do not because only the pinned Alpine musl SHA-256 is recognized.

---

## Implementation log & A/B results

Entries below are listed in **chronological execution order**, matching each same-session alternating A/B comparison baseline (`2 rounds × -r 3`, release `appine-run --tier 1` on `/bench/store`).

### Step 0 — Initial profiling (2026-11-22)

Established the baseline measurements and hot-loop inventory in [Step 0 profiling baseline](#step-0-profiling-baseline-2026-11-22): 92.8–95.2% of CPU time sits inside 7 translated hot loops, `emit_refill` is only 2.0–2.6% on decode (even for 1.17 GiB F16), `futex`/Tier 0 exits are negligible, and `libggml-cpu-armv8.2_2.so` is selected identically on native and Appine because host CPUs lack `sve`.

---

### Step 1 — Direction 5.1 (`YIELD`) & Direction 1 (block / `plan_group` limits) (2026-11-22)

**Changes**:
- Emitted `yield` (`0xd503203f`) verbatim (Direction 5.1).
- Implemented full Direction 1 in `core/engine/src/c/dbt.c`, `core/engine/include/appine/engine.h`, and `core/engine/src/lib.rs`: `MAX_BLOCK_INSNS = 256` with budget-based stopping and lazy 32/64-word guest snapshotting, `GROUP_SLOTS` `4 → 8` and `GROUP_MAX` `16 → 32`, block-local affine alias tracking for `ADD`/`SUB #imm` and `MOV Xd, Xm` before and after leaders, stolen-register base grouping, and `M_REG` grouping.

**Same-session alternating A/B results vs. Step 0**:

Static check-sharing jumped from ~44–45% to **48–51%** of inline memory instructions across all runs (`23,661 → 27,618` on Q4_0 `-t 1`, `28,796 → 34,911` on Q4_0 `-t 4`, `27,529 → 32,933` on F16 `-t 4`).

| Model & workload | Step 0 (t/s) | Step 1 (t/s) | Delta |
|---|---:|---:|---:|
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 190.7 | 197.8 | **+3.7%** |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 849.9 | 871.8 | **+2.6%** |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 718.9 | 727.3 | **+1.2%** |
| Qwen2.5-0.5B Q4_0 `tg32` `-t 4` | 180.6 | 184.2 | **+2.0%** |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 178.9 | 180.4 | **+0.8%** |
| Qwen2.5-0.5B F16 `pp128` `-t 4` | 224.5 | 228.6 | **+1.8%** |
| Qwen2.5-0.5B F16 `tg32` `-t 4` | 73.9 | 72.9 | flat (noise) |

**Non-ML & takeaway**:
- `appine-bench` Tier 1 geomean `1.71× → 1.70×` (`vm` `1.89× → 1.80×`); `gcc-lua`, `python-loop`, `spawnbench`, and `gobuild` all noise-identical or slightly faster (lazy `fetch_guest`, `affine_valid == 0` fast return, and `active_groups`/`grouped_bits` eliminated cold-translation overhead on `gcc-lua`).
- Confirmed Step 0's diagnosis: on wide Apple Silicon cores, removing grouping gaps delivers modest (+1–4%) gains, and breaking past the remaining 1.2–1.6× gap requires **Direction 4 (strip-mined fast loops)**.

---

### Phase 2A — Single-block constant-stride fast loops (2026-11-22)

**Changes**:
- Implemented single-block constant-stride self-loop recognition (`analyze_fast_loop` / `emit_fast_loop` in `core/engine/src/c/dbt.c`), covering countdown loops (`SUBS`/`SUB` + `B.NE`/`B.HI`/`B.GT`/`B.GE`/`B.PL`/`CBNZ`) and incrementing compare loops (`CMP` reg/imm + `B.NE`/`B.GT`/`B.LT`/`B.GE`/`B.LE`/`B.HI`/`B.LO`/`B.HS`/`B.LS`).
- Supports up to 7 induction pointers (including stolen-register bases, negative offsets, non-power-of-2 strides, and live end-of-iteration affine aliases restored on exit), probing TLB before page division, preserving exact NZCV/TBI/watchpoints/faults/kick latency (`KICK_BUDGET` 32–256), and recording `fast_loops` in `DbtStats`/templates/`appine-run --stats`.
- Matched all 4 initial target kernels (`ggml_vec_dot_f16`, `ggml_gemv_q4_0_4x4_q8_0`, `ggml_gemv_q8_0_4x4_q8_0`, `ggml_gemm_q4_0_4x4_q8_0`): **56** fast loops on Q4_0, **46** on F16.

**Same-session alternating A/B results vs. Step 1**:

| Model & workload | Step 1 (t/s) | Phase 2A (t/s) | Delta | vs. native |
|---|---:|---:|---:|---:|
| Qwen2.5-0.5B Q4_0 `tg128` `-t 1` | 88.56 | 101.41 | **+14.5%** | **1.09×** (was 1.34×) |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 209.10 | 212.19 | **+1.5%** | **1.06×** |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 893.3 | 905.3 | **+1.3%** | — |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 743.3 | 759.3 | **+2.2%** | — |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 202.3 | 204.8 | **+1.2%** | — |
| Qwen2.5-0.5B F16 `tg32` `-t 1` | 29.57 | 35.31 | **+19.4%** | — |
| Qwen2.5-0.5B F16 `tg32` `-t 4` (1.17 GiB) | 83.50 | 87.21 | **+4.4%** | **1.05×** |

**Verification & non-ML**: `appine-bench` Tier 1 geomean `1.69×` (vs. `1.70×` in Step 1); 200,000-iteration `appine-lockstep` passed under both `Default` and `Go` register sets.

**Post-2A prefill diagnosis** (`perf record -e task-clock -F 999`, Native vs. Appine Phase 2A on Qwen2.5-0.5B Q4_0 `pp512 -t 1 -r 3`, `7,434` vs. `10,325` samples, `284.0` vs. `208.0 t/s`):
- **`ggml_gemm_q4_0_4x4_q8_0`** is already `1.08×` native (`4,899 → 5,295` samples, `+396 ms` = **13.7%** of the `+2,891 ms` total gap). Host-offset histogram of `0xba094` (761 words, 5,098 samples) splits into ~68% fast loop body, ~25% slow loop body, and ~6% prologue/epilogue because 5 independent pointers (`4×136 B + 1×72 B` per iter) cross a 4 KiB page boundary every ~6.6 iterations on average (`K = 896 → 28` iters).
- **`ggml_compute_forward_flash_attn_ext_tiled`** is `~2.1×` slower than native (`1,624 → ~3,400+` samples, `~+1,800 ms` = **~62%** of the remaining gap).
- **All other code** (`softmax`, `quantize`, `swiglu`, `rms_norm`, `refill`, host/kernel) accounts for `911 → ~1,630` samples (`~24%` of the gap).

---

### Phase 2B-1 — `flash_attn` single-block fast loops & stolen-register pinning (2026-11-22)

**Changes** (`core/engine/src/c/dbt.c`):
- Multi-stream access tracking (`FAST_LOOP_MAX_STREAMS = 12`) over root base pointers (`FAST_LOOP_MAX_PTRS = 7`), verifying shared `addend` across same-base streams (`[x2]` + `[x2, x28, lsl #2]` in `0x6f260`, read+write `[x14, x0]` in `0x6f804`).
- `M_REG` support for induction base + loop-invariant index (`0x6f260`, any extend option) and loop-invariant base + 64-bit `LSL`/`SXTX` induction index (`0x6ed64`, `0x6f804`), plus 64-bit `ADD Xc, Xc, #imm` counters with 32-bit `CMP Wb, Wc`.
- Loop-invariant register strides (`ADD Xd, Xd, Xm` in `0x6f5a0`, `0x6f608`, `0x6f7a0`), using AArch64 `UDIV` in the prologue so zero, negative, and `> avail` strides bail via `cbz` with zero extra branches.
- Loop-local write-before-read NZCV (`FCMP`/`FCMPE` + `CSET`/`FCSEL` in `0x6ed64` and `0x6f3a0`), keeping `SUBS` flags intact and re-emitting the omitted `FL_CMP_INC` `CMP` once in the epilogue so pre-`fcmp` faults observe exact iteration-end NZCV.
- Loop-wide pinning of `<= 2` distinct stolen GPRs into `{T0, T1}` across the fast body (load once in commit, flush only written regs in epilogue), removing all per-iteration `CTX` loads/stores in `0x6f260` (`x17`, `x28`), `0x6f5a0` (`x26`), and `ggml_gemm_q4_0_4x4_q8_0` (`x28`).
- Matched all 5 `flash_attn` loops (`0x6ed64`, `0x6f260`, `0x6f3a0`, `0x6f5a0`, `0x6f804`): `fast loops` rose `56 → 64` on Q4_0 `pp512`.

**Same-session alternating A/B results vs. Phase 2A**:

| Model & workload | Phase 2A (t/s) | Phase 2B-1 (t/s) | Delta | vs. native |
|---|---:|---:|---:|---:|
| Qwen2.5-0.5B Q4_0 `pp128` `-t 1` | 263.97 | 282.39 | **+7.0%** | — |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 201.10 | 231.85 | **+15.3%** | **1.23×** (was 1.51×) |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 1` | 96.66 | 97.86 | **+1.2%** | — |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 895.64 | 980.02 | **+9.4%** | **1.18×** (was 1.37×) |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 737.88 | 844.46 | **+14.4%** | **1.22×** (was 1.45×) |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 183.83 | 184.88 | +0.6% | — |
| Qwen2.5-0.5B F16 `pp128` `-t 4` | 228.86 | 235.85 | **+3.1%** | — |
| Qwen2.5-0.5B F16 `tg32` `-t 4` | 74.29 | 72.63 | flat (±2.5 noise) | — |

**Verification & non-ML**: `appine-engine` 80/80, `guest_programs` 26/26, `rootfs_programs` 73/73, 200k-iteration `appine-lockstep` under both `Default` and `Go` (0 mismatches), `appine-bench` Tier 1 geomean **1.69×** (unchanged vs. Phase 2A).

**Post-2B-1 profiling diagnosis** (`perf record -e task-clock -F 999`, Native vs. Appine Phase 2B-1 across all 6 Qwen2.5-0.5B workloads):
- **Q4_0 prefill** (`pp512 -t 1`: `7,317 → 9,111`, `+1,794` samples; `pp512 -t 4`: `8,232 → 10,304`, `+2,072` samples) — ~75–80% of the remaining gap is caused by the **4 KiB page boundary**, not unmatched loops:
  - `ggml_compute_forward_flash_attn_ext_tiled` (`1,598 → 2,220`, `+622` = **+34.7%** of `-t 1` gap, `1.39×`; `-t 4`: `+706` = **+34.1%**, `1.42×`): 32 B offset histograms show `0x6f5a0` (838 samples) spends **35.9%** (301 samples) in its `UDIV` prologue and `0x6f260` (764 samples) spends **29.5%** (225 samples) in prologue + **20.8%** (159 samples) in epilogue/slow loop. Both loops (and `0x6f1a0`, 117 samples) stride by **256 B/iter** over a 64-iter inner loop, forcing a 4 KiB page-crossing bail every **16 iterations** (4× per call).
  - `ggml_gemm_q4_0_4x4_q8_0` (`4,842 → 5,362`, `+520` = **+29.0%** of `-t 1` gap, `1.11×`; `-t 4`: `+635` = **+30.6%**, `1.12×`): `0xba094` (5,144 samples) spends **30.2%** outside its fast body (`1,059` slow loop [20.6%] + `333` prologue [6.5%] + `162` epilogue [3.1%]) because 5 pointers (`4×136 B + 1×72 B`) cross a 4 KiB page every ~6.6 iterations.
  - `dbt_shared_routines` (`emit_refill`): `+230` (**+12.8%** of `-t 1` gap, 2.52% total) and `+308` (**+14.9%** of `-t 4` gap, 2.99% total).
  - Remaining non-fast-loop kernels are small and fragmented (`rms_norm_mul_fused` `+70` [+3.9%, `0x7c34c` blocked only by `ldr x0, [sp, #192]`], `swiglu` `+35` [+2.0%, mid-loop overflow branch], `rope` `+22` [+1.2%], `repack_q8_0` `+14` [+0.8%]; `soft_max` `0.97×` and `quantize_mat_q8_0` `1.03×` are already at native speed).
- **Decode** (`q4_tg128 -t 1`/`-t 4`, `f16_tg32 -t 4`): Core GEMV/dot kernels are already at native speed (`gemv_q4_0` `0.94×` at `-t 4` / `1.08×` at `-t 1`, `gemv_q8_0` `0.96×` / `1.01×`, `vec_dot_f16` `0.98×`). The largest single Appine-side overhead is `dbt_shared_routines` (`emit_refill`: 2.71% / `+210` samples = **23.5%** of `q4_tg128 -t 4` gap; 3.45% / `+146` = 18.4% at `-t 1`; 2.65% / `+135` = **21.3%** of `f16_tg32 -t 4` gap), followed by non-tiled `flash_attn_ext` (`+91`/`+99`), `ggml_barrier` (`+143` at `-t 4`), and outer dispatch/startup.
- **F16 prefill** (`f16_pp128 -t 4`: `5,583 → 8,987`, `+3,404` samples, `1.61×`): Concentrated in `tinyBLAS::gemm_bloc<4,6>` (`4,133 → 6,136`, `+2,003` = **58.8%** of gap, `1.48×`), `tinyBLAS::gemm_bloc<4,5>` (`733 → 1,196`, `+463` = **13.6%**, `1.63×`), and `dbt_shared_routines` (`+498` = 14.6%, of which `328` samples [3.65% total CPU, **9.6%** of gap] are `refill[1]` cross-page writes from `gemm_bloc`'s `stp q, [sp, #0..352]`) — **~82%** of the F16 prefill gap combined.

---

### Direction 3A — L2 2 MiB superpages, 2 MiB fast-loop span & sequential TLB prefill (2026-11-23)

**Changes**:
- **`kernel/mmu`** (`core/engine/src/c/mmu.c`, `internal.h`, `cpu.c`, `engine.h`, `lib.rs`):
  - Tagged L2 2 MiB leaf entries (`PTE_SUPER` = bit 3; table pointers guaranteed `>= 16`-byte aligned; host base only needs 4 KiB alignment), created automatically in `store_range` for aligned 2 MiB spans (and promoting all-zero L3 tables left behind by earlier small unmaps, keeping up to 256 retired L3 tables alive until `appine_mmu_free` for lock-free walker safety).
  - Transparent lock-free demotion (`demote_l2`) on partial `unmap`/`protect`/`map`/`move`, and whole-2 MiB fast paths for aligned `unmap`/`protect`/`move`.
  - Per-CPU 1024-entry direct-mapped 2 MiB superpage TLB (`cpu->stlb`, 2 GiB coverage, 4 KiB-aligned, tracked via `stlb_used[16]` so unused pages take 0 RSS), populated in `appine_tlb_fill` and `emit_fill` when `nwatch == 0` and flushed alongside `tlb`.
- **`kernel/mm`** (`core/kernel/src/mm.rs`):
  - `Mm::find_free` 2 MiB-aligns mappings of length `>= LEAF_SPAN` (2 MiB) when VA space permits (falling back to 4 KiB alignment if fragmented), preventing unaligned VMA heads (notably `ggml`'s 2.52 MiB `work_data` buffer) from falling into 4 KiB L3 tables.
- **`engine/dbt`** (`core/engine/src/c/dbt.c`):
  - `emit_fill` stops at L2 on `PTE_SUPER`, populates `cpu->stlb`, and when the preceding 4 KiB TLB slot holds `(vpn - 1)` with the same addend, batch-prefills up to 8 contiguous 4 KiB slots inside the same 64-entry `tlb_used` word (single `tlb_used` RMW). Ordinary inline 4 KiB TLB hit path is completely untouched.
  - `emit_fast_loop` probes `cpu->stlb` first for a 2 MiB `avail` runway (falling back to the 4 KiB `cpu->tlb` for non-superpage ranges), adds a `MUL` fast path for register strides (`(safe_iters - 1) * sr <= avail`, eliminating `UDIV` on the ~99% non-boundary case), and widens non-power-of-2 constant-stride reciprocal division to 34-bit shift (exact for `avail < 2 MiB`, `stride <= 4095`).
  - `memop_check_range` / `exec_memop` check and copy/scan in up to 2 MiB superpage spans.

**Same-session alternating A/B results vs. Phase 2B-1** (`-p 128,512 -n 128` for Q4_0; `-p 128 -n 32` / `-p 0 -n 32` for F16):

| Model & workload | Phase 2B-1 (t/s) | Direction 3A (t/s) | Delta | Notes / vs. native |
|---|---:|---:|---:|---|
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 230.70 | 259.52 | **+12.5%** | **1.10×** native (was 1.51×) |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 876.84 | 978.24 | **+11.6%** | **1.05×** native (was 1.45×) |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 1` | 97.94 | 101.63 | **+3.8%** | **1.08×** native |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 201.65 | 207.10 | **+2.7%** | peak 213.14 (**1.06×** native) |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 1` | 284.43 | 286.17 | flat | `work_data` < 2 MiB (4 KiB fallback) |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 985.63 | 980.51 | flat | `work_data` < 2 MiB (4 KiB fallback) |
| Qwen2.5-0.5B F16 `tg32` `-t 4` | 81.06 | 86.45 | **+6.7%** | **1.05×** native |
| Qwen2.5-0.5B F16 `tg32` `-t 1` | 35.04 | 35.29 | +0.7% | up to 35.90 t/s |
| Qwen2.5-0.5B F16 `pp128` `-t 4` | 240.28 | 238.45 | flat | awaited Phase 2B-2 (`gemm_bloc`) |

**Verification & non-ML**: `appine-engine` 82/82 (including new L2 superpage/demotion/promotion and Tier 1 superpage/prefill/fast-loop/memop tests), `appine-kernel` `mm::tests` 46/46, `guest_programs` 26/26, `rootfs_programs` 73/73, 200k-iteration `appine-lockstep` under both `Default` and `Go` (0 mismatches), `appine-bench` Tier 1 geomean **1.69×** (unchanged vs. Phase 2B-1), `python3`/`gcc`/`gobuild` noise-identical.

---

### Phase 2B-2 — `tinyBLAS::gemm_bloc` fast loops & cross-code-page support (2026-11-23)

**Changes** (`core/engine/src/c/dbt.c`):
- Symbolic derived 64-bit shifted-sum indices (`ADD Xd, Xn, Xm` + `LSL Xd, Xn, #1..4` → `idx_reg`/`idx_reg2`/`idx_shift` in `fast_stream`), raising `FAST_LOOP_MAX_STREAMS` from 12 to 16 so all 11 streams of `gemm_bloc<4,6>` (4 on `x2`, 6 on `x1`, 1 on `sp`) share only 3 base pointers (`x1`, `x2`, `sp`).
- Derived 64-bit `FL_CMP_INC` compare operands (`add x3, x0, #15; add x0, x0, #8; ... cmp x11, x3; b.gt`), computing `v_0 = cnt_reg + cmp_off` in the prologue for unified exact wraparound semantics.
- Zero-stride `M_OFFSET` `sp` root pointers (`[sp, #0..352]`) with a 2-instruction 16-byte SP alignment check and a dual-endpoint 4 KiB TLB contiguity check (`first` + `last` with identical addend), running cross-4 KiB stack frames natively and eliminating F16 prefill's 3.65% `refill[1]` cross-page write overhead.
- Generalized loop-wide stolen-register pinning: pins up to 6 stolen GPRs (first 2 in `T0`/`T1`, additional ones borrowing unused non-stolen host registers saved/restored in their dead `cpu->x[]` slots — covering `gemm_bloc<4,6>`'s 3 read-only stolen GPRs `x16/x17/x18` and `<4,5>`'s 4 stolen GPRs `x16/x17/x27/x28` with zero inner-loop `CTX` traffic), skipped write-only `Rd` loads in `emit_fast_operands`, and raised the `KICK_BUDGET` instruction cap from 8,192 to 12,288 so `K = 896` (112 iters) runs in one fast-loop pass.
- Cross-4 KiB-code-page fast-loop support (`gemm_bloc<4,6>` at `0x9dff0..0x9e104` crossing `0x9e000`): slow body stays strictly single-page while `fetch_guest_fast` peeks lazily into the next executable page (matching shared-group status), and `install`, `template_fetch`, `block_matches`, `recheck`, `appine_dbt_retire_outside`, and `invalidate_locked` (checking bucket `first - 1` when `cross_page_blocks > 0`) maintain exact page-1 invalidation and template reuse. Also fixed a pre-existing pool hygiene bug in `appine_dbt_free` where emptied instances did not clear `nogroup_count`/`strikes`.
- Matched `gemm_bloc<4,6>` and `gemm_bloc<4,5>`: `fast loops` rose `46 → 121` on F16 `pp128`, `64 → 129` on Q4_0.

**Same-session alternating A/B results vs. Direction 3A**:

| Model & workload | Direction 3A (t/s) | Phase 2B-2 (t/s) | Delta | vs. native |
|---|---:|---:|---:|---:|
| Qwen2.5-0.5B F16 `pp128` `-t 1` | 53.88 | 84.44 | **+56.7%** | — |
| Qwen2.5-0.5B F16 `pp128` `-t 4` | 233.81 | 323.96 | **+38.6%** | **1.16×** (was 1.64–1.67×) |
| Qwen2.5-0.5B F16 `pp512` `-t 4` | 235.15 | 328.79 | **+39.8%** | — |
| Qwen2.5-0.5B F16 `tg32` `-t 1` | 34.26 | 34.20 | flat | — |
| Qwen2.5-0.5B F16 `tg32` `-t 4` | 74.89 | 72.66 | flat (noise) | — |
| Qwen2.5-0.5B Q4_0 `pp128` `-t 4` | 965.66 | 968.70 | +0.3% | — |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 4` | 951.17 | 954.70 | +0.4% | — |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 4` | 179.84 | 181.28 | +0.8% | — |
| Qwen2.5-0.5B Q4_0 `pp512` `-t 1` | 256.35 | 255.68 | flat | — |
| Qwen2.5-0.5B Q4_0 `tg128` `-t 1` | 95.41 | 93.45 | flat (noise) | — |

**Verification & non-ML**: `appine-engine` 83/83 (including `fast_loop_gemm_bloc_derived_index_sp_and_cross_page` covering derived shifted indices, derived compares, >2 stolen GPRs with borrowed-reg preservation, contiguous/scattered/misaligned/RO SP, non-contiguous cross-code-page loops, template reuse, page-1 data fault, page-1 code rewrite invalidation, and page-1 unmap invalidation), `guest_programs` 26/26, `rootfs_programs` 73/73, 200k-iteration `appine-lockstep` under both `Default` and `Go` (0 mismatches), idle `appine-bench` Tier 1 geomean **1.68×** (vs. `1.69×` in Direction 3A), `python3` noise-identical.

---

### Direction 3B — Unlocked `madvise` forwarding & widened read-only file `fault_in` (2026-11-23)

**Changes**:
- **`hal`** (`core/hal/src/lib.rs`): Added `appine_hal::advise(ptr, len, advice)` wrapping non-destructive host `madvise(2)` hints on host-page-aligned slices.
- **`kernel/mm` & `kernel/mmu`** (`core/kernel/src/mm.rs`, `core/kernel/src/syscall/mem.rs`):
  - `madvise` forwards `MADV_NORMAL`, `MADV_RANDOM`, `MADV_SEQUENTIAL`, `MADV_WILLNEED`, and `MADV_POPULATE_READ` (mapped to host `MADV_WILLNEED` for compatibility with older Android `< 5.14` kernels without inflating anonymous RSS) to `appine_hal::advise` **after releasing the BKL** (`Cx::unlocked`), retaining each VMA's `Arc<HostRegion>` in `AdviseRange` so concurrent unmaps cannot invalidate host ranges mid-call. Skips reserved, foreign (`[vvar]`), GPU, and FUSE `Fill` VMAs; clips file ranges to `file_len`; coalesces adjacent slices sharing one `HostRegion`; restricts `NORMAL`/`RANDOM`/`SEQUENTIAL` to file-backed host mappings (never splitting anonymous/recycled host VMAs); and skips untouched anonymous VMAs on `WILLNEED`/`POPULATE_READ`.
  - Widened `Mm::fault_in` from 2 MiB (`LEAF_SPAN`) to **16 MiB** (`FILE_FAULT_SPAN = 8 * LEAF_SPAN`) for read-only non-FUSE file mappings (both `PrivateFile` and `Shared` — `llama-bench` maps GGUF weights `MAP_SHARED | PROT_READ`), leaving anonymous and writable mappings at 2 MiB.
  - Added `Mm::prefill_file_ptes` on `MADV_WILLNEED` / `MADV_POPULATE_READ` (capped at 4 GiB per call, filling aligned 2 MiB L2 superpage entries without touching host pages or mapping past EOF).

**Verification & sanity run**:
- `cargo clippy -p appine-hal -p appine-kernel -p appine-run --all-targets -- -D warnings`
- `appine-kernel` 272/272 (including 48/48 `mm::tests` with `fault_in_widens_read_only_file_mappings_only` and `madvise_prefill_and_ranges_respect_vma_kinds_and_eof`), `guest_programs` 26/26, `rootfs_programs` 73/73, `scripts/difftest` (`compat`, `compat4`, `compat6`, `edge-cases`, `fork`, `fuse`).
- `llama-bench` on `/bench/store`: `APPINE_STRACE=1` confirmed `madvise(MADV_WILLNEED)` on 1.17 GiB F16 completes in `< 0.1 ms`; F16 `pp128 -t 4` `329.6 t/s`, `tg32 -t 4` `86.9 t/s`; Q4_0 `pp128 / pp512 / tg128 -t 4` `973.6 / 958.2 / 208.0 t/s`.

---

## Non-goals & rejected directions

- **Modifying the ordinary inline 4 KiB TLB hit sequence**: Tested in Rounds 27 and 30; even +1 instruction regresses `gcc` and `python`.
- **Implementing `SVE`/`SVE2` or `SME`/`SME2` as a first step**: Unlike NEON extensions (which reuse `V0–V31` and only need whitelisting in `simd.c`), SVE/SME add `Z0–Z31`, `P0–P15`, `FFR`, `ZA`, `prctl(PR_SVE_SET_VL)`, signal-frame `sve_context`, ptrace regsets, and predicated/gather-scatter soft-MMU translation. Unconditionally saving SVE state in `enter`/`exit` would also regress every syscall-heavy workload unless made lazy. Moreover, most mobile ARMv9 cores (Cortex-X3/X4/A715/A720) implement 128-bit SVE (same width as NEON). Revisit only if profiling confirms `SVE` is the sole blocker for `I8MM` in target distro packages and rebuilding/reconfiguring is not viable.
- **Symbol/SHA-256 native hooks for `ggml_vec_dot_*` kernels**: `llama.cpp` updates frequently, supports dozens of quantization formats, and relies heavily on compiler inlining. Generic Tier 1 grouping + streaming loop optimization delivers durable gains across all formats and workloads.
- **Superblocks across calls and unconditional forward jumps**: Measured in Round 31 (`docs/rounds/31-superblocks.md`) at `<= 2%` gain with a warm-compile `gcc` regression.
- **Fixed-offset direct guest-to-host memory mapping (eliminating soft-MMU)**: Analyzed in Round 30 as incompatible with Android GKI's 39-bit user VA (512 GiB shared across all guest processes), 16 KiB host pages, and precise fault recovery.
- **Concurrent direct relinking of conditional branches (`nthreads > 1`)**: Prohibited by ARM CMODX rules (`core/engine/src/c/dbt.c`); backward edges of single-block loops already link directly at `link_block` time before publication.

---

## Verification & non-regression gates

Standard gates applied to every optimization step (and required for any follow-up work under Direction 5.2–5.4):

1. **Unit & integration tests**: `core/engine/tests/dbt.rs` (block length boundary, 5–8 interleaved groups, derived pointers, `M_REG`/stolen groups, cross-page faults, watchpoints, TBI tags, L2 superpage demotion on `mprotect`/`munmap`/CoW, strip-mined loop exact faults & kick responsiveness), `appine-kernel` `mm::tests`, `guest_programs`, `rootfs_programs`, and `scripts/difftest`.
2. **Lockstep verification**: `tests/lockstep` (`appine-lockstep`, 200k iterations) under both `Default` and `Go` register sets with 0 mismatches.
3. **Same-session alternating A/B benchmarks**: `llama-bench` (`pp128`/`pp512`, `tg32`/`tg128`, Q4_0/Q4_K_M/F16, `-t 1` & `-t 4`) **and** non-ML regression suite (`appine-bench`, `gcc-lvm`, `python`, `node`, `mvn-warm`, `spawnbench`).
4. **Module map hygiene**: Update `.agents/maps/engine/dbt.md` (and `kernel/mmu.md` / `kernel/mm.md` when touched) via `map-module` once changes land.
