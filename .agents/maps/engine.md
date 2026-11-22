# engine Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/engine.md` for the paired decision history (it still holds the decisions on the Tier 1 dynamic binary translator made before it was split out into `engine/dbt`).
>
> Verified: 2026-11-03 (full mapping: 6 research concerns; 23 claims checked by 3 independent verifiers — 14 confirmed and 9 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-21 (targeted verification only since the full mapping; latest change: split the Tier 1 dynamic binary translator into engine/dbt)

## Responsibilities

`engine` executes guest aarch64 user code inside the app process and defines the shared engine
contract on which `engine/dbt` builds. Downloaded code may only run under an interpreter or
translator, so the engine never jumps to guest code directly:

- **Tier 0** (`interp.c`, `simd.c`, `atomic.c`, `native.c`, `cpu.c`) interprets one instruction at
  a time. It handles cold code, single-stepping and hardware breakpoints, executes every instruction
  `engine/dbt` hands back, and is the semantic reference (`engine/dbt` asks it whether an encoding
  is defined).
- The public CPU contract (`include/appine/engine.h`, Rust bindings in `src/lib.rs`): the
  per-thread CPU state, exit reasons, the kick handle and hardware debug slots.
- CPU feature advertisement and ID-register emulation (`features.c`).
- The host fault guard (`guard.c`), which turns a host fault or internal check failure inside
  engine code (both Tier 0 and `engine/dbt`) into an exit.

Root: `core/engine/` except `kernel/mmu`'s page table and TLB fill/flush and `engine/dbt`'s Tier 1
translator (`interp.c`, `simd.c`, `atomic.c`, `native.c`, `cpu.c`, `features.c`, `guard.c`,
`internal.h`, `build.rs`, `include/appine/engine.h` except its MMU and Tier 1 sections, `src/lib.rs`
except its Page table and Tier 1 sections, `tests/interp.rs`, `tests/guard.rs`) plus
`tests/lockstep`.

Outside the module: the Tier 1 dynamic binary translator, its code cache, templates, pooling and
`DbtSpace`/`Dbt` bindings (`engine/dbt`); the radix page table (`mmu.c`), the TLB entry layout and
Tier 0 TLB fill/flush, and the mm-side code-group policy (`kernel/mmu`); the kernel layer decides
which tier runs and what each exit means to the guest (`kernel/process`). Build:
`core/engine/build.rs` compiles the C files with the `cc` crate (`-std=c17`, warnings as errors);
non-aarch64 hosts get stubs (no native stubs, no Tier 1, only CPUID advertised).

## Key types

- `struct appine_cpu` / `CpuState` — one per guest thread: X0–X30, SP, PC, NZCV, FPCR, FPSR,
  TPIDR_EL0, exit and fault information, the `pending` kick flag, the bound page table, the
  exclusive monitor (`excl_addr`, `excl_value`, `excl_size`; size 0 means none), Tier 1 scratch and
  group slots (`dbt_groups[4]`), `ivau_page`, the data TLB (4096) and ITLB (512), V0–V31,
  `tlb_used`, DIT, and 16 hardware breakpoint and 16 watchpoint slots. Fields before the TLB are
  addressed by `engine/dbt` with immediate offsets.
- `Cpu` — owns one state (pooled: up to 8 spares); `Send`, not `Sync`.
- `Kicker` — raw handle whose only operation, `kick`, sets `pending`; the one thread-safe call.
- `Exit` — `Svc{imm}`, `Undefined{insn}`, `Breakpoint{imm}`, `Fault{addr, access, kind}`, `Kick`,
  `InvalidateCode{addr}`, `HostFault{signal, code, addr, pc}`. `FaultKind`: page, alignment,
  stack alignment, watchpoint, hardware breakpoint. `Access`: read, write, exec.

## Public entry points

- **CPU**: `Cpu::new`, `reset`, `run` (guarded loop until an exit), `step` (one instruction, ignores
  kicks), `exec_insn` (run a given word; tests and lockstep only), `translate`, `tlb_flush`,
  `state`/`state_mut`, `kicker`; `CpuState::set_hw_debug`, `hw_breakpoints_active`.
- **Process-wide**: `install_fault_guard`, `guest_hwcap`, `guest_hwcap2`, `guest_midr`,
  `layout_matches`.
- **C-internal** (used across engine files and by `engine/dbt`):
  `appine_interp_step`/`appine_interp_exec`, `appine_native_exec`, `appine_simd_dp_decode`,
  `appine_atomic_exec`, `appine_id_register`, `appine_guard_run`/`hold`/`hold_fn`/`drop`/`fail`,
  `appine_map_code`; `appine_guard_selftest` for the unit test.

## Data flow / lifecycle

### Tier selection (decided by the kernel run loop)

- Tier 1 (`engine/dbt`) runs when the address space has a `DbtSpace`; Tier 0 (`Cpu::run`) runs when
  there is no instance, when hardware breakpoints are set, and when the instance is poisoned;
  `Cpu::step` is used for single-stepping.
- `engine/dbt` itself executes any instruction it does not translate by calling Tier 0 for that one
  instruction.

### CPU state and exits

- `Cpu::new` takes a pooled state or maps a new one and zeroes everything before the TLB, the
  V registers and the debug slots, flushing only used TLB entries.
- `run` syncs host PSTATE.DIT with the guest's, arms the fault guard, and loops; each iteration
  consumes `pending` (a kick ends the run with `Kick`) and executes one instruction.
- The C exit code is decoded from the state's exit and fault fields; `HostFault` reads the
  thread's last recorded host fault. Exit code 0 or an unknown code panics.
- The kernel collects `ivau_page` on every exit and turns `Undefined` into `SIGILL`/`ILL_ILLOPC`.

### Tier 0 execution

- Step order: PC alignment (alignment fault), hardware breakpoint (before executing), instruction
  fetch through the ITLB (exec page fault), then decode. During a run, an aligned PC with no
  hardware breakpoints can reuse the last code page's address offset. The run loop still checks
  for a kick before fetching each instruction word from guest memory. Every exit discards the
  offset so the next run observes any intervening TLB flush.
- Decoding is hand-written mask tests and `switch` on encoding fields, dispatching first on bits
  28:25 (data processing immediate, branches and system, data processing register, loads and
  stores, SIMD and FP data processing); everything else is undefined.
- ADD/SUB immediate and shifted or extended register forms compute NZCV only when the S bit is
  set. With S clear, immediate and extended forms can write SP and shifted forms discard a write
  to register 31.
- A failing or undefined instruction leaves PC and registers untouched; only `svc` and `ic ivau`
  exits advance PC.
- Data addresses have the top byte ignored (TBI); PC and branch targets are not untagged.
- Memory accesses check every page touched before copying anything, so a fault has no side
  effects; SP-based accesses require 16-byte SP alignment; watchpoints are checked on every access.
- Ordinary single-register integer loads and stores use fixed-width copies on same-page data TLB hits
  when the thread has no watchpoints. Misses, cross-page accesses and watched threads use the
  shared memory helpers.
- System registers: NZCV, FPCR (writes masked to AHP, DN, FZ, RMode and, with FP16, FZ16), FPSR
  (cumulative flags only) and TPIDR_EL0 are read-write; TPIDRRO_EL0 reads 0; DCZID_EL0 reads 4
  (64-byte blocks); CTR_EL0 reads `0x8444c004` (DIC = IDC = 0, so guests must issue `ic ivau`);
  CNTVCT and CNTFRQ read the host, and so does CNTVCTSS (no `isb`) when ECV is offered; DIT is
  feature-gated; the ID space comes from the feature set; anything else is undefined.
- HINT space (NOP, YIELD, `PACIASP`/`AUTIASP`, BTI) is a no-op; non-hint PAC (PACGA, one-source
  PAC, BRAA/BLRAA/RETAA) and HLT are undefined. DMB and DSB are full fences; ISB is a no-op.
- `dc zva` zeroes 64 bytes and needs write permission; other DC operations and `ic ivau` only check
  read permission; `ic ivau` always exits with `InvalidateCode` in Tier 0. PRFM touches nothing.

### Native stubs and FP state

- SIMD and FP data processing, CRC32 and the LSE atomics run as cached host "native stubs": C
  decides whether the encoding is whitelisted, translates the address and moves registers, and a
  generated stub executes the same instruction on the host with general-register fields remapped to
  host temporaries (address fields replaced by a translated host pointer).
- The stub cache is one process-global 2 MB code region (W^X double mapping) with a 4096-slot
  table; it is flushed entirely when half full or out of space. Stubs run under a read lock
  (registered with the fault guard); generating a stub takes the write lock.
- Vector ADD/SUB and the three-register bitwise instructions use caller-saved V0–V2 for their
  operands. BSL, BIT and BIF also load the old destination. Each writes back the full destination
  vector, including the cleared upper half for 64-bit forms.
- The other SIMD/FP stubs save host d8–d15 and FPCR, load guest FPCR, FPSR, NZCV and V0–V31,
  execute one instruction, write V, FPSR and NZCV back, and restore the host FPCR.
- SIMD and FP loads and stores are implemented in C through the soft-MMU, checking every page first.
  Multiple-structure LD1/ST1 copy one 8- or 16-byte register at a time after checking the whole
  range for page faults and watchpoints. Interleaved LD2–LD4/ST2–ST4 copy one element at a time.
- If native stubs are unavailable, those instructions are undefined and no SIMD or FP feature is
  advertised.

### Exclusives and atomics (Tier 0)

- LDXR records address, size and the loaded value; STXR succeeds only if address and size match
  and a compare-and-swap against the recorded value succeeds on the host address (ABA allowed).
  Every STXR clears the monitor; CLREX and `svc` clear it. Natural alignment is required.
- 16-byte pairs use host `ldaxp`/`stlxp`; LDAR/STLR are C acquire/release accesses; LDAPR
  and LDAPUR are implemented as acquire; LSE and CAS/CASP run as native stubs on the translated
  host pointer. (`engine/dbt` implements the same compare-and-swap semantics inline for Tier 1.)

### CPU features and ID registers

- Guest features = host features ∩ Tier 0's implemented set ∩ the whitelist, computed once.
  CPUID is always advertised. The implemented set (FP, ASIMD, AES, PMULL, SHA1/2/3/512, CRC32,
  ATOMICS, ASIMDDP, LRCPC, ILRCPC, FPHP/ASIMDHP, JSCVT, ASIMDRDM, FCMA, ASIMDFHM, and in HWCAP2 I8MM,
  BF16, FRINT) is intersected with the host's and offered only if the host has FP and ASIMD and
  native stubs work. FlagM, FlagM2, SB, DCPOP, DCPODP, DIT and ECV (HWCAP2, the self-synchronized
  counter `CNTVCTSS_EL0`, which the host's vDSO reads instead of `CNTVCT_EL0` on hosts that have
  it; guests run that code, `kernel/vdso`) are offered from host support regardless of that gate.
- Dependencies: SHA3 and SHA512 only together and with SHA2; FPHP and ASIMDHP together; FHM needs
  FPHP; LRCPC2 needs LRCPC; FlagM2 needs FlagM; DCPODP needs DCPOP. Not implemented: LSE2, SM3/SM4,
  SVE/SME, PAC (PACA/PACG), BTI, MTE.
- Adding a SIMD/FP extension only needs whitelisting its encodings: Tier 0 executes them through
  native stubs and `engine/dbt` copies them.
- The same set feeds `AT_HWCAP`/`AT_HWCAP2`, `/proc/cpuinfo` and `mrs` of the ID registers
  (op0=3, op1=0, CRn=0, CRm 0–7): MIDR is the host value (0 if the host does not advertise CPUID),
  MPIDR has only bit 31, PFR0 (AArch64-only EL0/EL1 plus FP, AdvSIMD, DIT) and ISAR0/ISAR1 are
  derived from the set, every other register in that range reads 0; CRm 8–15 is undefined.
- DIT is kept in the CPU state; the host thread's DIT follows the guest's at each entry.

### Host fault guard

- `install_fault_guard` installs SIGSEGV, SIGBUS and SIGILL handlers (chained after ART's); the
  machine installs it only when kernel bugs are contained (release builds by default, or
  `APPINE_ON_BUG`). During a guarded run, a host fault with `si_code > 0` long-jumps back: the host
  FPCR is restored, registered locks are released newest first (the outer four of those held;
  deeper ones are counted so drops still pair), the signal is unblocked, and the run returns
  `HostFault`. The locks taken during a run are registered: the native-stub lock, plus `engine/dbt`'s
  instance, template and perf-map locks. Other faults are reported to stderr and passed to the
  previous handler. If the per-thread guard cannot be allocated, the run proceeds unguarded.
- Guarded code must not allocate or call back into the kernel layer (`engine/dbt`'s opt-in
  `APPINE_PERF_MAP` is the one documented exception).
- Guest state is not reconstructed from the host context; after a host fault the kernel kills the
  guest process (`kernel/bug`), and `engine/dbt` poisons the Tier 1 instance and clears the template
  arena.
- Internal overflow checks (native stub length and `engine/dbt`'s translation/stub checks) call
  `appine_guard_fail`: under an armed guard the run ends as after a host fault, recorded as
  `SIGABRT` with the caller's address; with no guard armed (debug builds, unguarded calls) it
  aborts as before. The checks run during stub generation and translation, where only registered
  locks are held.

## Dependencies (inbound / outbound)

### Inbound

- `engine/dbt`: `struct appine_cpu` layout, `appine_interp_step`/`exec`, `appine_simd_dp_decode`,
  `appine_map_code` and the fault guard (`appine_guard_run`/`hold`/`hold_fn`/`drop`/`fail`).
- `kernel/process`: task run loop (`Cpu::run`/`step`, exit handling, `ivau_page`, kicks).
- `kernel/mmu`: `Cpu::tlb_flush`, `Kicker`; `kernel/exec` (`AT_HWCAP`); `kernel/signal` and
  `kernel/ptrace` (FP registers, kicks, hardware debug slots); `kernel/procfs` (`/proc/cpuinfo`,
  MIDR); `kernel/boot` (`install_fault_guard`).
- Tests: `core/engine/tests/interp.rs`, `guard.rs` and `tests/lockstep` (random instruction
  sequences compared between hardware, Tier 0 and Tier 1; the whitelist check against `llvm-mc`,
  which runs only on Linux aarch64 and is skipped without `llvm-mc`).

### Outbound

- `kernel/mmu` structures: the page table (`appine_mmu_translate`), the TLB entry layout and
  `tlb_used`.
- Host: `getauxval`, `mrs midr_el1`/`fpcr`/`cntvct_el0`/`cntvctss_el0`/`cntfrq_el0`, `msr dit`,
  `mmap`/`mremap`/`madvise`, pthreads (locks, once, TLS), `sigaction`/`sigsetjmp`/`siglongjmp`,
  instruction-cache maintenance.

## Invariants and gotchas

- Both tiers must agree on every instruction: Tier 0 defines the accepted encoding set and SIMD
  whitelist decoder that `engine/dbt` relies on. Encodings outside the whitelist are undefined in
  both tiers.
- Fields before the TLB in `struct appine_cpu` must stay within immediate reach of `engine/dbt`'s
  loads, and the TLB must be 16-byte aligned; the Rust mirror is checked by `layout_matches` (size
  plus eight field offsets, in a unit test).
- Watched pages never enter the TLB (read half absent for load watchpoints, write half for any),
  and hardware breakpoints are checked only in Tier 0.
- `Kicker::kick` is the only operation allowed from other threads; it is safe only while the `Cpu`
  is alive. The kernel guarantees this by kicking only under the BKL, only tasks it still lists or
  registered users of an address space, and by removing a thread from both before its `Cpu` is
  freed; `Cpu::reset` (execve) zeroes `pending`, and the kernel re-kicks afterwards if the task was
  interrupted. `engine/dbt`'s own flush kick may race a reset harmlessly.
- Atomic instructions act directly on host memory reached through the page table, so threads and
  processes sharing a page get correct atomicity for free.
- The `llvm-mc` whitelist check follows LLVM on should-be-one fields: exclusives and LDAR/STLR
  ignore them, CAS/CASP require Rt2 all ones.

## Confirmed bugs / technical debt

- **The kernel drops page-zero invalidation from pure Tier 0:** its code-change path filters out
  zero even for an explicit `InvalidateCode` exit. A single-stepped write and cache flush on
  page zero can therefore leave stale code when execution returns to Tier 1 (`engine/dbt`'s own
  dispatcher handles page zero directly).
- **Unallocated ID registers read 0:** `mrs` of CRm=1 and unallocated CRm=0 registers returns 0
  where Linux 6.1 delivers `SIGILL`.

## Open questions

- Is it intended that FAULT, KICK and signal exits leave the exclusive monitor set (architecturally
  an exception return clears it)? The compare-and-swap semantics make this mostly harmless.
- Should FPCR written by sigreturn or ptrace be masked like `msr fpcr` in Tier 0?

## To verify

- Tagged branch targets fault in both tiers (the PC is never untagged). Whether this diverges from
  Linux 6.1 depends on whether it leaves TBID0 clear for EL0 (instruction addresses then also
  ignore the top byte); needs the Linux source.
- `layout_matches` checks only the size and eight field offsets and runs only in a unit test; other
  mirrored fields are covered only indirectly.
