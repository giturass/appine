# kernel/mmu Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/mmu.md` for the paired decision history (decisions from before the split are D1, D13, D16, D39 and the page-table half of D4 in `.agents/decisions/kernel/mm.md`).
>
> Verified: 2026-11-11 (split out of the kernel/mm full mapping of 2026-11-10; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: untouched private anonymous mappings prefill without write permission until first write fault, and executable unmaps/growth/rollbacks record `exec_changed` and `code_ranges`)

## Responsibilities

`kernel/mmu` is the soft-MMU under `kernel/mm`'s address spaces: how a guest address becomes a
host address, and how every thread of an address space sees changes. It does not emulate ARM
hardware translation (no TTBR, descriptor formats, TLBI/ASID, exception levels or physical address
layer):

- the software radix page table of each address space and its entries;
- populating entries, eagerly or on first access (`fault_in`);
- the per-thread software TLB and its Tier 0 refill;
- multi-thread consistency: `sync`, `quiesce` and `shootdown`, and the generation counters the run
  loop reads;
- the code-change log that Tier 1 translations consume, and code groups (address spaces sharing
  one translation space).

Root:

- `core/engine/src/c/mmu.c` and the `Mmu` wrapper in `core/engine/src/lib.rs` — the radix page
  table.
- `core/engine/src/c/cpu.c` and `core/engine/src/c/internal.h` — the per-thread software TLB and
  Tier 0 refill.
- In `core/kernel/src/mm.rs`: the `Consistency and code` section, and the `Mm` methods that fill
  entries (`map_pages`, `prefill_pages`, `fault_in`) and keep threads consistent (`add_user`,
  `remove_user`, `generations`, `code_space`, `invalidate_code`, `sync`, `quiesce`, `shootdown`).

Outside the module: VMAs, the fault policy and what each change records for `sync` (`kernel/mm`);
`fork` and copy-on-write (`kernel/cow`); host backing and deferred unmapping (`kernel/hostmem`);
the run loop that reads the counters (`kernel/process`); the Tier 1 translator with its inline TLB
fast path and refill (`engine/dbt`).

## Key types

### Translation

- `struct appine_mmu` / `Mmu` — 4-level radix tree, 512 entries per level, covering 48-bit guest
  addresses; each leaf table spans 2 MB. An L2 entry can also be a 2 MB leaf superpage
  (`4 KB-aligned host base | R/W/X | PTE_SUPER`, bit 3; intermediate table pointers are at least
  16-byte aligned so bits 3..0 are 0). Whole 2 MB spans written to empty L2 slots, existing
  superpages, or all-zero L3 tables (up to 256 retired L3 tables kept alive per `appine_mmu` until
  destruction for concurrent walkers) become superpages; partial `unmap`/`protect`/`map`/`move`
  demote an L2 superpage atomically into a populated 512-entry L3 table before modifying it. A 4 KB
  leaf entry is a 4 KB-aligned host page address ORed with R/W/X bits; 0 means absent, and prot 0
  with a nonzero address means "present, no access". `Mmu` is neither `Send` nor `Sync`;
  `map`/`unmap`/`protect`/`move_entries` take `&mut`, while
  `fill_shared`/`map_shared`/`protect_shared`/`next_present`/`translate`/`table_bytes`/`table_pages`
  take `&self` so CoW and memory accounting can query or edit another address space's table
  (`table_bytes` counts all allocated 4 KiB radix tables — root, intermediate, active and retired
  L3 tables — monotonically until destruction). Guest address spaces only fill empty slots
  (`fill_shared`, `map_shared` for CoW); the replacing `map` serves the vDSO's own probe table.
- `struct appine_tlb_entry` — data TLB entry `{read tag, read addend, write tag, write addend}`,
  4096 direct-mapped 4 KB entries (`tlb`, tracked by `tlb_used`) plus 1024 direct-mapped 2 MB
  superpage entries (`stlb`, 4 KB-aligned, covering 2 GB, tracked by `stlb_used`) per thread; tag
  is the inverted page (or 2 MB superpage) number and 0 is invalid, so zeroed memory is an empty
  TLB.
- `struct appine_itlb_entry` — 512-entry instruction TLB, used only by Tier 0 instruction fetch.

### Consistency and code

- `TaskSync` — per-thread `in_guest` flag plus a `Kicker` (sticky: a CPU not running returns at
  its next run), shared without the BKL.
- `Generations` — clones of the three counters (`tlb`, `code`, `space`) and the code log; the run
  loop reads them without the BKL.
- `CodeLog` — log of `(generation, start, len)` code changes covering the last 4096 code
  generations.
- `CodeSpace` — the Tier 1 translation space (`DbtSpace`) used by an `Mm`, with its tag and the last
  code generation applied to that space.
- `CodeGroup` / `CodeGroups` — groups of address spaces running the same executable that share one
  `DbtSpace` (at most 256 registered trusted ranges, which only grow; each member's private
  executable ranges as claims under its tag; admitted shared `memops`); the kernel keeps a list of
  weak references, pruned when a group is founded.
- `Mm`'s consistency fields (`kernel/mm`): `dirty`, the `graveyard`, `code_ranges`,
  `exec_changed`, the users and the code-group membership.

## Public entry points

- **Threads and the run loop**: `add_user`, `remove_user`, `generations`, `code_space`,
  `invalidate_code`; `Cpu::tlb_flush`.
- **After changes**: `sync` (after BKL syscalls, `ic ivau` exits, `write_force`, truncation and
  file moves), `quiesce` (fork, membarrier, `sync`), `shootdown` (CoW re-pointing an entry).
- **Entries**: `fault_in` (the fault path), `mmu().translate`, `map_pages` and `prefill_pages`
  (inside `kernel/mm`).
- **Tier 0**: `appine_tlb_fill` on a TLB miss.

## Data flow / lifecycle

### Page-table entries

- `map_pages` builds entries eagerly for new mappings when the part of the VMA before EOF is at
  most 1 MB, or when the mapping is executable and not private anonymous (file mappings, shared
  anonymous, SysV shm), using `Vma::prefill_prot` (which strips `PROT_WRITE` on unwritten private
  anonymous pieces and software-tracked file mappings so the first store traps). Tmpfs file mappings wait for per-page quota admission. `PROT_NONE` mappings get none. If building them fails it removes every
  entry of the range. For existing or already-moved VMAs (`mprotect` out of `PROT_NONE`, `mremap`
  moves), `prefill_pages` performs the same eager `fill_shared` as best-effort without unmapping
  on failure, leaving existing entries intact so any unfilled pages fault in on demand.
- Larger mappings are filled on demand by `fault_in` (`try_fault_in`). It fails if no VMA covers the page, the page
  is at or past EOF, the VMA prot (with write implying read) lacks the access, or the page already
  has an entry that already permits the access (or a prot-0 entry, or a CoW page on write). On the
  first write to an unwritten private anonymous piece (`prepare_anon_write`), it marks the piece
  written, attaches `has_anon_vma` across the logical VMA, and enables write permission on existing
  entries via `protect_shared` (no TLB flush needed) before filling any absent leaf. Otherwise it fills every empty slot of the 2 MB leaf range
  — or 16 MB (`FILE_FAULT_SPAN`, 8 leaf spans) for read-only non-FUSE file mappings — clipped to
  the VMA and EOF; existing entries are left alone and no flush is needed. A `Fill` VMA gets
  entries only for pages already read (`kernel/mm`). Tmpfs admits a single page. A read fault leaves it write-protected, and its first
  store goes through shared write admission or private CoW. A permission change revokes its entries. `MADV_POPULATE_READ` faults tmpfs pages
  explicitly. On hosts without readable pagemap, ordinary private files prefill read permissions and
  admit writes one guest page at a time, recording the underlying host CoW page. For non-tmpfs,
  non-FUSE files, `MADV_POPULATE_READ` and `MADV_WILLNEED` can prefill read-only soft PTEs
  (up to 4 GB per call) via `fill_shared` without touching host pages.
- `mprotect` to `PROT_NONE` keeps entries with prot 0 (the host page keeps its content); changing
  back rewrites the kept entries (keeping write stripped on unwritten private anonymous pieces until
  their first store) and fills the rest under the eager rule above, otherwise on demand.
- Execute-only mappings (`PROT_EXEC` without `PROT_READ`) do not gain read permission: data loads
  and kernel reads fault, instruction fetch works.

### The TLB

- Tier 0 looks up the data TLB in C (data addresses untagged first) and calls `appine_tlb_fill` on
  a miss. The fill fails if the entry is absent or lacks the needed bit. A data fill sets both
  halves at once, leaving the read half invalid on pages with a load watchpoint and the write half
  invalid on pages with any watchpoint or without read permission (Tier 1 can use a write entry
  for a group that also reads). It records the slot in `tlb_used`, stores `addend =
  host page − guest page base`, and when the lookup hit an L2 superpage with no watchpoints active,
  also populates `stlb` and `stlb_used` (consumed by Tier 1 fast loops). Exec fills only the ITLB.
  Tier 1's refill defers to Tier 0 whenever any watchpoint is set. Its data entries (and `stlb`
  entries) can include the guest pointer's top byte in both the inverted page number and the page
  base used for the addend. Tier 0's untagged lookup then misses and refills the same slot.
- Cross-page accesses of up to 16 bytes look up both pages before copying anything; a failing
  second page reports the start of that page as the fault address.
- A TLB flush clears only the slots marked in `tlb_used` and `stlb_used`, plus the whole ITLB; CPU
  states kept for reuse (up to 8) are cleared the same way.

### Consistency: shootdown and code invalidation

- Mutators run under the BKL and only record what changed: `dirty` (unmap, mremap moves, permission
  downgrades, fork lending, `unshare`, truncation, leaving a code group), the
  `graveyard` (always together with `dirty`), `code_ranges` (executable ranges unmapped, moved,
  grown, re-protected, discarded, rolled back or truncated, and invalidations), and `exec_changed`
  (executable VMAs inserted, unmapped, re-protected, grown or rolled back, and kernel writes into
  them).
- `Mm::sync` runs after every syscall that takes the BKL (except exit, `exit_group`,
  `rt_sigreturn`, a successful execve or execveat, a syscall a tracer or seccomp skipped, and a
  kill at the entry stop; the no-BKL fast path never changes the mm), on `ic ivau` exits (and any
  exit with an `ivau` page pending), after `write_force`, and on every address space a truncation
  changed. It re-checks the code group, prunes `Mm::memops` against invalidated or
  non-exec/writable/written ranges and syncs group-admitted or sole-space memops to
  `DbtSpace::set_memops`; returns when nothing is dirty and no code changed; publishes `code_ranges`
  to the `CodeLog` and bumps the code generation; returns if nothing is dirty and the graveyard is
  empty; otherwise bumps the TLB generation (when dirty), runs `quiesce`, and clears the graveyard.
- `quiesce` kicks every other user of the mm and spins until none is in guest code. When a
  Files app open truncates a mapped object, `sync_except(None)` includes
  every guest thread in the shootdown before the host file shrinks. The kick is
  sticky, so a thread returning from a no-BKL fast syscall stops at its next guest entry. fork and
  membarrier quiesce too.
- `shootdown` is the immediate form used when a PTE is re-pointed (CoW copy, return of a borrowed
  page): with users, it bumps the TLB generation, kicks only users in guest code, and waits until
  none is in guest code, kicking again any it still finds there (one that entered after the first
  kicks, which nothing else would stop). It does not hold users back: one that enters guest code
  after the wait has passed it (such as a thread waking from a no-BKL fast-path sleep) runs with a
  flushed TLB while the caller still holds the BKL.
- The run loop sets `in_guest`, then reads the counters (a SeqCst store-then-load pairing with the
  mutator's bump-then-read). If `space` changed it re-attaches to a new `CodeSpace` (when it had a
  translator) and looks again on the next pass; if `tlb` changed it flushes its TLB; if `code`
  changed it invalidates Tier 1 blocks for the ranges its space has not yet applied (once per
  space), or flushes all translations when the log no longer covers them.
- Other threads see code-only changes on their next guest entry. A registered caller can force
  context synchronization with `PRIVATE_EXPEDITED_SYNC_CORE`. Tier 1 handles `ic ivau` inside
  the translator. The log carries mapping changes, Tier 0 invalidations and leftover `ivau` pages.
- `membarrier` fences the caller before and after quiescing the target address spaces. The private
  commands target the caller's space and require the matching registration (`EPERM`).
  `GLOBAL` visits every live address space in the guest kernel once. `GLOBAL_EXPEDITED` quiesces
  only those registered to receive it, including when the caller is unregistered.

### Code groups (mm side of translation sharing)

- The first thread to run an `Mm` (and after exec) calls `code_space`: for its executable it takes a
  tag in an open group with the same key (a group out of tags is closed) and joins if `admit`
  accepts its layout (its private executable ranges overlap no registered range or other member's
  claims, and the shared sources it adds are the same file, version and placement, at most 256 in
  all; a second member makes the group retire blocks outside the consistent layout once); else it
  founds a new group with its own `DbtSpace`, unshareable from the start when its layout has more
  than 256 ranges or no tag is left. A failed admission does not give its tag back.
- After any executable change, `sync` re-runs `admit`. A member that no longer fits becomes
  `unshareable` (sticky) and drops its claims: a sole member closes the group, retires the shared
  blocks outside those of its mappings that agree with the registered ranges, and keeps the space;
  otherwise it leaves, drops its `CodeSpace`, bumps the space generation and sets `dirty`, so
  `sync` quiesces. Registered ranges never shrink.
- A forked child starts outside any group with its parent's executable and may join any open
  group for it. On drop a member leaves the group (its claims released, the group neither closed
  nor its ranges unregistered); only the last member (or a sole non-group owner) calls `set_sources`
  on the `DbtSpace`, recording the group's registered file-backed ranges (`CodeGroup::file_sources`,
  excluding the vDSO sentinel) so an exiting member never clobbers a live group's sources or drops
  ranges registered by other members.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/mm`: every VMA change (`map_pages`, the recorded `dirty`, `graveyard`, `code_ranges`
  and `exec_changed`), the fault path (`fault_in`), `Mm` drop (leaving the code group);
  `kernel/cow`: CoW (`shootdown`, `fill_shared`, `map_shared`, `protect_shared`); `kernel/hostmem`:
  deferred `Mmu` destruction (`Unmapped::mmus`).
- `kernel/process`: the run loop (`in_guest`, `generations`, TLB flushes, code invalidation, `ic
  ivau`), the dispatcher (`sync` after BKL syscalls), membarrier (`quiesce`), users at thread start
  and exit.
- The fast path reads entries through the CPU's `translate`.

### Outbound

- `appine_engine` (`engine` and `engine/dbt`): `Mmu`, `Cpu::tlb_flush`, `Kicker`, `DbtSpace`/`Dbt`
  (trust, new_tag, share, retire_outside, set_sources, set_memops, invalidate, flush).
- The Tier 1 translator depends on the page-table geometry, the PTE bit layout, the TLB entry
  layout and offsets, `tlb_used`, and the watchpoint count.

## Invariants and gotchas

- Only the kernel layer modifies page tables, serialised by the BKL. Other threads may walk them
  concurrently: entries are loaded with acquire and stored with release, new tables start zeroed,
  and no table (intermediate or leaf) is freed before the page table itself is destroyed, which is
  deferred until the BKL is released.
- After an unmap, a permission downgrade or re-pointing an entry, every other thread of the address
  space must flush before the old host memory is released. Adding permissions never requires a
  flush: a stale TLB half only misses.
- Only `quiesce` (sticky kicks to every user) keeps other threads out of guest code until the BKL
  is released; after a `shootdown` other threads may run guest code at once, so every page-table
  change made under the BKL must leave entries valid for guest code at each step.
- Waiting for users to leave guest code (`quiesce`, `shootdown`) holds the BKL, so it must kick
  every user it waits for: an unkicked one may run guest code indefinitely, such as a spin waiting
  for a thread that waits for that BKL, and the whole kernel stops (LTP shmctl05). Kicks are sticky,
  so a kicked thread stops at its next guest entry too.
- Kicking a thread is safe only because a thread removes itself from `users` under the BKL before
  its CPU state is destroyed.
- Page-table memory only grows over an address space's lifetime.
- `CodeGroup` uses `Rc`/`RefCell` and is correct only under the BKL; the counters, `CodeLog`,
  `TaskSync` and `CodeSpace` are shared across threads.

## Confirmed bugs / technical debt

- None.

## Open questions

- None.

## To verify

- Linux 6.1 arm64 semantics for `PROT_EXEC`-only mappings (execute-only with Enhanced PAN, or
  exec implying read): needs the Linux 6.1 source to decide whether Appine's execute-only behaviour
  matches.
- That Tier 1's dependency-ordered (non-acquire) page-table walk is safe against concurrent entry
  stores: only a code comment claims it; the translator is outside this module.
- That `Dbt::invalidate` by range is correct for code-group members whose address spaces differ:
  translator internals, outside this module.
