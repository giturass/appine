# engine/dbt Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/engine/dbt.md` for the paired decision history (not yet created; decisions from before the split are D6–D10, D13–D16, D18, D23, D25, D27–D29, and the Tier 1 halves of D2, D5, D17, D20, D22 and D24 in `.agents/decisions/engine.md`).
>
> Verified: 2026-11-21 (split out of the engine full mapping of 2026-11-03; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-22 (targeted verification only since the full mapping; latest change: in-cache same-page memop fast paths, memchr/strncmp budget handling, and 4-bit routine relocations)

## Responsibilities

`engine/dbt` is Appine's Tier 1 same-ISA dynamic binary translator for guest aarch64 user code:

- translating guest basic blocks into a shared W^X code cache: most ALU, FP, NEON and barrier
  instructions are copied verbatim (renaming stolen registers), memory accesses get inline
  soft-TLB checks with grouped same-base checks and a shared out-of-line refill routine, and
  blocks are linked directly or through jump caches and a shadow return stack;
- executing translated code under `engine`'s host fault guard, handling length-gated libc memops,
  re-entering Tier 0 for any instruction Tier 1 does not translate, and keeping exceptions precise;
- lock-free translation-table lookups, content-based invalidation and forwarding stubs, the
  process-global template arena, instance pooling, code-group sharing (`DbtSpace` / `Dbt`), and
  periodic unmapping of written code pages.

Root: `core/engine/src/c/dbt.c`, `core/engine/src/c/emit.h`, the Tier 1 section of
`core/engine/include/appine/engine.h`, the `Tier 1` section of `core/engine/src/lib.rs`
(`DbtStats`, `DbtRegs`, `DbtMemop`, `DbtSource`, `DbtSpace`, `Dbt`, `trim_dbt_pool`,
`unmap_written_code`, `written_code_bytes`), and `core/engine/tests/dbt.rs`.

Outside the module: the Tier 0 interpreter and whitelist semantic reference, CPU state layout,
native stubs, CPU features, the host fault guard and `tests/lockstep` (`engine`); the radix page
table, TLB layout and code-group policy (`kernel/mmu`); tier selection and the guest run loop
(`kernel/process`); libc memop discovery and Go build-ID detection (`kernel/exec`); periodic
`unmap_written_code` and `written_code_bytes` accounting (`kernel/oom`).

## Key types

- `DbtSpace` (`struct appine_dbt`) — one translation instance: 128 MB code cache with the shared
  routines at its start, the lock-free translation table, block records, saved guest words,
  per-page block buckets, the shared-range list, the immutable sorted memop table (`memop_table`),
  the register set, the lock, flush state, trust sources, and the poisoned flag. Shared by every
  thread of an address space and by every member of a code group.
- `DbtMemop` (`struct appine_dbt_memop`) — a registered libc memop entry `(pc, kind)` (`memcpy`,
  `memset`, `memmove`, `memcmp`, `memchr`, `strncmp`; up to `APPINE_DBT_MEMOPS` = 32).
- `Dbt` (`struct appine_dbt_thread`) — one thread's attachment: its tag, 4096-entry jump cache,
  64-entry shadow return stack, statistics (`DbtStats`), and a private translation workspace.
- `struct block` — guest pc, entry in the code cache (NULL when dead), saved guest words, parked
  flag, tag.
- `struct table` / `struct slot` — open-addressed table keyed by `pc | tag << 48`, hashed on pc
  only; removed entries become tombstones.
- `DbtRegs` / `struct regs` — the host register assignment: `Default` (context x28, temporaries
  x16/x17/x27, guest SP in x26) or `Go` (context x25, temporaries x21/x22/x23, SP in x24).
- `DbtSource` — a trusted code range: start, length and an identity (device, inode, offset, ctime,
  size; all-ones for the vDSO).
- Templates — a process-global 32 MB arena of translated blocks shared by all instances.
- The instance pool — up to 16 retired instances (64 MB of kept code) and 8 spare thread parts.

## Public entry points

- **Instances and threads**: `DbtSpace::new(key, regs)`, `set_sources`, `set_memops`, `trust`,
  `retire_outside`, `share`, `new_tag`; `Dbt::new`, `with_regs`, `attach(space, tag)`, `run(cpu)`,
  `flush`, `recheck`, `invalidate(cpu, start, len)`, `stats`.
- **Process-wide memory management**: `trim_dbt_pool`, `unmap_written_code`,
  `written_code_bytes`.

## Data flow / lifecycle

### Register convention and FP state

- Guest registers live in the same-numbered host registers, except the "stolen" ones, which live
  in the CPU state: X16, X17, X18, X26, X27, X28 for the default set; X18 and X21–X25 for the Go
  set. Host x18 (the Android platform register) is never touched.
- A stolen operand is loaded into a temporary, the instruction is re-encoded to use it, and the
  result is written back; an instruction with more than three distinct stolen registers goes to
  Tier 0. Guest SP lives in a host register, so SP-based accesses and writebacks need no extra
  loads.
- Inserted code never changes NZCV (it uses `cbnz`, `tbnz`, `eor`/`eon` instead of compares).
- The set is fixed per instance at creation: the loader picks `Go` when the executable carries a Go
  build-ID note (`APPINE_DBT_REGS=go|default` overrides); routines and templates are generated per
  set.
- Tier 1's enter routine saves host d8–d15 and FPCR and loads guest FPCR, FPSR, NZCV and V0–V31
  for a whole run; its exit routine stores V0–V31, FPSR and NZCV and restores host state.

### Blocks and instruction handling

- A block starts with a two-word kick check, holds at most 64 guest instructions, and never crosses
  a guest page (a forward chain exit to the next pc ends it). It ends at B, BL, SVC, BR/BLR/RET and
  at any instruction handed to Tier 0; conditional branches become side exits and translation
  continues on the fall-through path.
- Every non-SIMD instruction must first be accepted by Tier 0 (`tier0_defined`, which runs the word
  on a probe CPU with no page table and caches the answer per instruction word in a 4096-entry
  per-thread cache); SIMD data processing uses Tier 0's whitelist decoder directly (`engine`).
  Anything not accepted ends the block with an exit to Tier 0.
- Handling:
  - register-only ALU, FP and NEON instructions and barriers are copied verbatim (operands renamed
    when stolen); DSB and ISB check `ivau_page` after executing the barrier;
  - ADR/ADRP and literal loads become constants based on the guest PC; registers set by ADR/ADRP
    (plus immediate adds) are tracked as known constants within the block, cleared conservatively;
  - loads and stores get the inline TLB path (below); PRFM emits nothing;
  - `svc #0` exits to the kernel inline; other `svc` immediates, BRK, and PSTATE writes other than
    FlagM go to Tier 0;
  - `mrs fpcr` and `mrs`/`msr tpidr_el0` use the guest CPU state. `mrs dczid_el0` becomes the
    constant 4. `mrs fpsr` reads the host FPSR, including flags raised earlier in the block.
    NZCV, CNTVCT, CNTVCTSS and CNTFRQ accesses also run natively after the Tier 0 whitelist
    check. An FPCR write stays in the block if its masked value equals the saved guest FPCR.
    Changed FPCR writes, FPSR writes and other system registers go to Tier 0;
  - HINT space, including PAC and BTI hints, emits nothing; authenticated branches go to Tier 0;
  - DC CVAC/CVAU/CIVAC/CVAP/CVADP and `ic ivau` only check read access; `ic ivau` records its page
    in `ivau_page` (page zero or a second, different page exits to Tier 0); `dc zva` zeroes via the
    translated address; CLREX clears `excl_size`;
  - exclusives and atomics: LDXR loads from the host address after the TLB check (LDAXR with
    `ldar`); STXR checks the monitor and runs an `ldaxr`/`stlxr` compare-and-swap loop with no
    memory access in between, borrowing an unused guest register (saved in its own CPU slot) when
    the value to store is in a stolen register. LDAR/STLR, LDAPR, LDAPUR/STLUR, CAS and LSE run
    natively on the host address. LDXP/STXP, CASP with stolen operands, and misaligned atomics go
    to Tier 0.
- Exit stubs carry the guest pc, the patch site and a packed reason word back to the dispatcher.

### Memory access

- Handled inline: integer LDR/STR in all immediate, pre/post-index and register-offset forms,
  literal loads, LDP/STP/LDNP/LDPSW, SIMD single-register, pair and literal forms, and LD1–LD4 /
  ST1–ST4 (multiple, single lane, replicate, with post-index). Others go to Tier 0.
- Hit path for an 8-byte read with the default registers (x16 holds the guest address):

  ```asm
  add  x17, x16, #7            // last byte
  ubfx x17, x17, #12, #12      // low 12 bits of its page number → TLB index
  add  x17, x28, x17, lsl #5   // x28 points at the CPU state
  ldp  x17, x27, [x17, #TLB]   // tag (inverted page number), addend
  eon  x17, x17, x16, lsr #12  // compare with the first byte's page; never equal across pages
  cbnz x17, refill_stub
  ldr  x0, [x27, x16]          // host address = addend + guest address
  ```

- The entry is chosen by the last byte's page and the tag compared with the first byte's page, so a
  cross-page access never hits inline. Variants of the listing: for immediate offsets within
  ±4 KB the last-byte address is computed from the base in parallel with the access address;
  1-byte accesses, and accesses known to stay inside one aligned 16 bytes (SP-based after the
  alignment check, atomics), use the first byte's page directly; pairs and structure accesses add
  the address into the addend register and access through it.
- Known addresses (ADR/ADRP-derived bases, literals) use a constant TLB slot; the tag is still
  compared with the real address.
- SP alignment is checked once per block and not again while SP only changes by multiples of 16.
- A miss branches to a per-access 5-word refill stub (`adr`, branch to the routine, an info word
  with size, failure reason and resume offset, and the guest pc), then to a shared refill routine in
  the code cache. The routine borrows the CPU state's X0–X4 slots as scratch, fails whenever any
  watchpoint is set or either endpoint exceeds 48 bits after ignoring its top byte. The page-table
  walk uses plain loads and low address bits. The TLB tag and addend use the full guest page base,
  so another access with the same top byte can hit inline. Atomics untag their effective address
  before lookup. Filling a write entry requires read and write permission because grouped accesses
  and atomics can also read. The refill records the slot in `tlb_used` and resumes. A cross-page
  access succeeds only if both pages are permitted and have the same addend (contiguous host memory).
- On failure the stub exits to the dispatcher and Tier 0 executes the instruction. Nothing guest
  visible has happened before the exit, so exceptions are precise.
- Grouped checks: several accesses in a block with the same base share one check. The leader checks
  the whole range (at most 512 bytes, at most 16 members) and leaves the host base in a temporary;
  members access `[T2, #offset]`. Between members only instructions that do not write the base
  (constant adjustments are tracked), SIMD data processing, conditional branches, hints, barriers,
  CLREX and accesses on other bases are allowed; an access on another base makes the next member
  reload the host base from one of four slots in the CPU state. Atomics, unconditional branches and
  other system instructions end a group; literal, register-offset, register-writeback and
  stolen-base accesses cannot lead; a register-writeback member must be last.
- A group check failure exits to Tier 0, which runs the leader. The first failure of a leader is
  recorded (64-entry direct map keyed by pc); the second retires the blocks containing it (or
  requests a full flush if a retirement cannot be placed) and stops grouping for leaders in the
  following 256 bytes (64-entry ring; templates are versioned by it). Failures while watchpoints
  are set are not counted.

### Control flow

- Direct branches are linked by patching a `b`: a link stub starts with a branch to its next word,
  which is rewritten to branch to the target block (concurrent `b`→`b` patching is allowed by
  CMODX). Conditional branches are rewritten directly only while one thread is attached to the
  instance.
- At install time only conditional side exits whose target is already translated are linked; other
  exits are linked by the dispatcher the first time they are taken.
- A patched link point only gets cache maintenance (no wait, no `isb`); the patching thread enters
  the target directly, others may run the old code briefly and still reach the target through the
  dispatcher.
- Indirect branches (`br`, `blr`, `ret`) probe the thread's 4096-entry jump cache in generated
  code; on a miss an in-cache lookup routine probes the shared table (and fills the jump cache)
  before exiting to the dispatcher.
- Return prediction: `bl`/`blr` become a host `bl` that skips a landing pad and push
  (guest return address, landing pad) onto the 64-entry shadow return stack; `ret x30` pops when the
  top matches x30 and returns with a host `ret`. Mismatches (longjmp, signal handlers, coroutines)
  and `ret` through other registers use the jump cache. The stack is reset when the translations are
  flushed.
- Kick checks: every block entry checks `pending`; forward direct links skip the check, so every
  loop passes through at least one check. The dispatcher also checks before entering code.
- Stubs keep their data (guest pc, reason) in data words at their end, read by the routines.

### Dispatcher

- `appine_dbt_run` runs under `engine`'s fault guard; a poisoned instance runs Tier 0 for the whole
  call.
- Each iteration: join or perform a pending flush, catch up with the instance's generation (reset
  the return stack, clear the jump cache), return `Kick` if pending, look up the block without a
  lock, revive parked blocks of that page if any, otherwise translate and install, then enter.
- Exit reasons: chain (patch the link point), lookup (fill the jump cache), ungroup (record the group
  failure, then run Tier 0), interp (for a pure `R_INTERP` exit at a registered memop PC on a shared
  or ungrouped block, run `exec_memop`: pre-validating guest pages with TBI untagged, capping
  mutating/fixed-length ops at 64 MB while scanning `memchr`/`strncmp` up to a 64 MB budget even
  for `SIZE_MAX`, skipping on watchpoints or missing permissions, warming the data TLB for untagged
  addresses so subsequent same-page calls stay in-cache, popping the shadow return stack when its
  top matches `x30`, and returning to `x30`; otherwise run one instruction in Tier 0, then
  invalidate any recorded `ivau_page` in place), code (invalidate the pending page after a
  translated DSB/ISB, then look up the next PC), svc (clear the monitor, return `Svc`), kick (loop).
  Tier 0's own exits are returned to the kernel, except `ic ivau`, which is absorbed in place.
- A host fault inside the run marks the instance poisoned and clears the template arena.

### Code cache, table and memory

- The code cache is 128 MB (the reach of `b`), mapped twice from one shared anonymous region with
  `mremap` (read-write for writing, read-execute for running; read-write-execute if the host
  refuses) and bump-allocated. Dead blocks free no code; only a full flush reclaims space.
- Translation happens without the lock in the thread's own workspace; under the lock `install`
  re-compares the guest words (retranslating if they changed), copies the code, fixes routine
  branches, links known exits, syncs the instruction cache and only then publishes the block in the
  table. A thread alone in the instance syncs the new block and a pending link point together.
- The table is read without locks: insertion only fills empty slots (pc before code), removal only
  writes tombstones (never reused, except that relinking a parked block reuses its own tombstone),
  and readers announce themselves with a per-CPU sequence count so a replaced table is freed only
  after they finish. The C reader loads code with acquire before the key; the generated lookup
  routine loads both with one plain `ldp` and leaves pc 0 to the dispatcher, since a torn read can
  pair new code with an empty slot's key 0.
- Sizing: a new or emptied instance starts at 2^12 slots (a kept pooled instance keeps its size).
  At 3/4 occupancy the table doubles up to 2^19, or is rebuilt at the same size when tombstones are
  at least half of the occupied slots or it is already at 2^19; if load is still at 3/4 a full flush
  follows. The block log is compacted (records only) when it reaches its limit with enough dead
  records.
- Retiring a block writes a 16-word forwarding stub, rewrites the block's entry to branch to it,
  then tombstones the table entry. Jump-cache entries are not cleared; they reach the forwarder.
  Translating the pc again patches the old entry to the new block.
- A full flush is triggered by a full code cache, a table that cannot be kept below 3/4 load, a block
  log at its limit with fewer than 1/8 of its records dead (or a failed compaction), no room for a
  forwarding stub, a recheck with too many mismatches, or `Dbt::flush` (which only requests it). It
  kicks the other threads running in the dispatcher, waits until each is parked or has left it,
  clears the table and records, resets the cache allocation and bumps the generation. Dropping an
  instance without keeping its translations also flushes it.
- Pages written through the read-write view are tracked; `unmap_written_code` drops their host page
  table entries (content kept) because the host counts pages touched through both views twice. The
  kernel's timer thread calls it every second while guest threads run (and once after they all go
  idle), and the OOM and cgroup measurements subtract `written_code_bytes` (`kernel/oom`).

### Sharing translations

- A block's translation depends only on its guest pc, its guest instruction words, the register set
  and whether it is shared (except blocks at registered memop PCs, which dispatch same-page calls to
  in-cache helpers at the head of the code cache — `memset` and overlap-safe `memcpy`/`memmove` for
  `x2 >= 32`, 8-byte `memcmp` for `x2 >= 8`, and first-page SWAR `memchr` for `x2 >= 1` — preserving
  non-return guest registers and NZCV and returning through a shared predicted-return tail, falling
  back on cross-page spans, TLB misses or watchpoints to an `x2 >= 128` `R_INTERP` exit or guest
  code, while `strncmp` uses the `x2 >= 128` gate directly; all memop blocks bypass both
  `template_fetch` and `template_store`, are retired on `set_memops` changes and before pooling in
  `appine_dbt_free`, and are ignored for private tagged blocks in a code group); the words are saved
  and re-compared at install, recheck, revive and content-based invalidation. Installation also
  compares the memop registration captured during preparation with the current registration under
  the DBT lock.
- Threads of one address space share one instance; each has its own jump cache, return stack,
  statistics and workspace.
- Code groups (engine side): members share one instance. Blocks in ranges registered with `share`
  are shared (tag 0); other blocks are private to the member that translated them (key
  `pc | tag << 48`, tags from `new_tag`). Lookup finds either; shared blocks never link to private
  ones, so such exits go through the dispatcher.
- Templates: every translated block is stored in a process-global 32 MB arena (64K buckets, 64 shard
  locks, at most 4 versions per pc), keyed by pc and matched on guest words, register set, the
  ungroup state and the shared flag. Another instance copies a matching template into its own cache
  and re-points only the branches to routines. The arena is cleared when full and on a host fault.
- Pool: a dropped instance that is not poisoned is kept (marked stale, private blocks dropped) if it
  has a key, at most 131072 block records (dead ones included) and 64 MB of code, no pending flush,
  and, above 32 MB, fits in the remaining 64 MB code budget; otherwise it is flushed. A poisoned
  instance is released. The pool holds 16 instances, evicting empty ones first, then the least
  recently used. `DbtSpace::new` takes the newest pooled instance with the same key and register
  set, else the first emptied one (regenerating routines if the register set differs), else a new
  one.
- Reuse of a stale instance: `trust` (only on a stale instance) marks ranges whose start, length and
  identity match exactly as trusted, and makes the previous user's `set_sources` ranges parkable.
  On the first run `recheck` skips trusted blocks and compares the rest. A mismatching block whose
  page has no executable mapping and that lies within a parkable range is parked, and revived
  (whole page re-checked) the first time that page is executed; other mismatches are retired; if
  non-parkable mismatches exceed half of the live blocks, nothing is retired and a full flush is
  requested instead.

### Invalidation

- The kernel replays its code-change log through `Dbt::invalidate(cpu, start, len)`, or calls
  `Dbt::flush` when the log no longer covers what the thread missed (`kernel/mmu`).
- Invalidation with a CPU is by content: blocks whose saved words differ from current memory, or
  whose page no longer has an executable mapping, are retired; parked blocks are left alone.
  Without a CPU every block in the range is retired and parked ones are killed. Ranges spanning more
  than 256 pages (or wrapping) scan every block; blocks of every group member are compared against
  the caller's memory (no tag filter).
- A small-range invalidation unlinks dead block records from each page bucket it visits. Parked
  blocks stay in the bucket for revival. Compaction reclaims dead records in the block log.
- `ic ivau` in Tier 1 records the untagged page. Tier 0 handles page zero (the pending-page
  sentinel) or a second, different page and returns its address explicitly to the dispatcher.
  After a translated `dsb`/`isb`, a dedicated exit invalidates any pending page in place before
  resuming at the following PC. The kernel collects a pending page left at another exit.
- `retire_outside` (first join of a group) and `ungroup` also retire blocks.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/process`: task run loop (`Dbt::attach`/`run`, exit handling, `ivau_page`, kicks).
- `kernel/mmu`: `DbtSpace` creation, code groups, `trust`/`share`/`retire_outside`/`set_sources`/
  `set_memops`, `Dbt::invalidate`/`flush`.
- `kernel/exec`: register-set selection (`DbtRegs::Go`) and musl memop discovery (`DbtMemop`).
- `kernel/oom`: `unmap_written_code` and `written_code_bytes` (timer thread and memory accounting);
  `Machine::trim_memory` (`trim_dbt_pool`).
- `engine` tests and `tests/lockstep` (hardware / Tier 0 / Tier 1 instruction comparison).

### Outbound

- `engine`: `struct appine_cpu` layout and fields before the TLB (`dbt_groups`, `ivau_page`,
  `excl_*`), `appine_interp_step`/`exec`, `appine_simd_dp_decode`, `appine_map_code`, and the host
  fault guard (`appine_guard_run`/`hold`/`hold_fn`/`drop`/`fail`).
- `kernel/mmu`: the radix page-table layout walked by the refill routine, the TLB entry layout and
  `tlb_used`.
- Host: `mmap`/`mremap`/`madvise`, pthreads (locks, once), instruction-cache maintenance,
  `APPINE_DBT_REGS` and opt-in `APPINE_PERF_MAP` (`/tmp/perf-<pid>.map`).

## Invariants and gotchas

- Tier 1 must agree with `engine`'s Tier 0 on every instruction: it copies or translates only what
  Tier 0 accepts, and SIMD data processing uses Tier 0's whitelist decoder.
- Precise guest exceptions come from checking before acting (TLB checks, alignment checks, Tier 0
  fallback), not from host signals: a host fault in translated code is never mapped back to guest
  state.
- While translated code runs, `struct appine_cpu` does not hold the guest's registers (routines
  also borrow its X0–X9 slots); it is consistent only after an exit.
- Fields before the TLB in `struct appine_cpu` (`engine`) must stay within immediate reach of
  Tier 1 loads, and the TLB must stay 16-byte aligned.
- Tier 1's refill fails while any watchpoint is set, so all watched accesses run in Tier 0;
  hardware breakpoints are checked only in Tier 0.
- Code memory is reclaimed only by a full flush, which happens only after every other thread has
  left translated code.
- Guest FPCR stays constant until translated code exits. A changed masked FPCR write takes an
  interpreter exit, so Tier 1's exit does not save FPCR. Tier 0 handles all FPSR writes, and the
  host FPSR is left holding the guest's value.
- Every lock taken during a guarded run (instance lock, template bucket shard, template arena lock,
  `template_clear`'s 64 shard locks via `hold_fn`, perf-map lock) must be registered with `engine`'s
  fault guard; guarded code must not allocate or call back into the kernel layer (except opt-in
  `APPINE_PERF_MAP` in `install`).
- Templates are copied, never referenced, so dropping the arena never invalidates running code.
- Known-address checks are safe only because constant tracking is exact: it is reset at every block
  start and cleared by any instruction that may write a tracked register. A stale constant would let
  a real cross-page access alias the constant slot and pass with only its first page checked.
- `set_memops` publication and install-time kind recheck must run before code publication so stale
  memop blocks cannot survive a registration update or cross-process pooling.

## Confirmed bugs / technical debt

- **Lock-free conditional-branch relinking races a new thread:** the `nthreads == 1` check is not
  serialized with `attach`, and the kernel attaches new threads and code-group members without
  stopping running ones, so a conditional branch can be rewritten while another thread executes it
  (architecturally unpredictable; in practice old and new targets behave the same).
- **Test-only API:** `Dbt::recheck` is called only by `core/engine/tests/dbt.rs`; the kernel's exec
  path reaches the same check through instances taken from the pool.

## Open questions

- Is it intended that threads of other code-group members disable direct conditional-branch
  patching for the whole instance?
- Can `revive` restore a parked block whose pc already has a newer translation, leaving two table
  entries for one key?
- Two group leaders that alternate failing in the same strike slot are never ungrouped; accepted?
- Should the template arena ever be trimmed under memory pressure?

## To verify

- Template copies reproduce a fresh translation exactly; there is no runtime self-check.
- Tier 1's page-table walk uses plain, address-dependent loads where `mmu.c` uses acquire loads;
  only a code comment argues they are equivalent.
