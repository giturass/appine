# Soft-MMU (kernel/mmu) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/mmu"`
>
> Last distilled: 2026-11-23 (HEAD = cc72b093)
>
> Soft-MMU decisions made before kernel/mmu was split from kernel/mm keep their `kernel/mm` tags and live in `.agents/decisions/kernel/mm.md`: D1, D13, D16, D39 and the page-table half of D4.

## Active

### D1: kernel/mmu is split out of kernel/mm
- **What**: kernel/mmu owns `mmu.c` and the `Mmu` wrapper, the software TLB in `cpu.c` and `internal.h`, and in `mm.rs` the Consistency and code section and the `Mm` methods that fill entries (`map_pages`, `fault_in`) and keep threads consistent (users, generations, code spaces, `sync`, `quiesce`, `shootdown`), and the engine map's references to the page table and code groups point here.
- **Why**: The page table, TLB and consistency machinery are a contract with the engine and the run loop whose changes rarely need the VMA syscalls' detail, and the mm map (69.6 KB) could not be read in one Read.
- **Tradeoffs**: Every VMA change records what kernel/mmu acts on, so changes to unmapping or permissions still read both maps.
- **Watch out**: A VMA change that skips recording for `sync` because the rule now lives in this map; the map keeps open the bug of entries dropped when a host allocation fails.
- **Source**: 44a21b7

### D2: Unwatched scalar hits use a fixed-width same-page copy

- **What**: Tier 0 computes the candidate host address alongside the shared tag check and uses a fixed-width copy for an unwatched scalar hit on one page.
- **Why**: Generic copies and slow-path stack setup cost time on ordinary hits.
- **Tradeoffs**: The outlined miss path can repeat the probe, and the probe expression also affects instruction-fetch code generation.
- **Watch out**: Use the candidate only after a hit and handle faults and watchpoints before register or memory writeback.
- **Source**: 16914003

### D3: Tier 1 retains the top byte in data TLB entries

- **What**: Cache the full guest page base in the tag and addend, walk the low 48 bits, and require both read and write permission for a cached write.
- **Why**: Tagged pointers otherwise missed repeatedly, and grouped or atomic operations can use a write entry to read.
- **Tradeoffs**: Aliases with different top bytes compete for a slot, and raw write-only mappings take the Tier 0 store path.
- **Watch out**: Check endpoints and watchpoints before access and use untagged addresses for exclusive monitors and instruction-cache invalidation.
- **Source**: 8bc0e63b

### D4: `CodeGroup` tracks admitted shared memops separately from per-process `Mm::memops`

- **What**: `CodeGroup::memops` tracks admitted shared memops restricted to `group.ranges`, merged during `Mm::sync` and `Mm::code_space`, and marks `memops_dirty` when a sole member leaves a closed group so its `DbtSpace` switches back to `Mm::memops`.
- **Why**: Pushing one member's `Mm::memops` onto a shared `DbtSpace` overwrote peers' registrations and could expose private mappings across members.
- **Tradeoffs**: Memops in private executable mappings of a `CodeGroup` member are not accelerated until that member leaves the group.
- **Watch out**: Like `CodeGroup::ranges`, `CodeGroup::memops` grows monotonically while shared; members remapping conflicting code at those addresses still leave the group via `check_code_group`.
- **Source**: 9b3b6860

### D5: Memop entry points register only for executable mappings of the verified bundled libc snapshot

- **What**: `mm.rs` maps the shared in-process SHA-256-verified bundled libc snapshot and registers Tier 1 memop entry points only for executable mappings of that snapshot.
- **Why**: The executable mapping must execute the exact bytes that passed SHA-256 verification rather than a mutable original file.
- **Tradeoffs**: Maintains one shared in-process snapshot of the bundled libc (shared via `FileMaps` per kernel/mm D47).
- **Watch out**: Preserve translation invalidation whenever executable mappings change.
- **Source**: 6b59a1b4

### D6: Soft page tables support 2 MiB L2 superpages with atomic demotion and a 1024-entry `stlb`

- **What**: L2 entries encode 4 KiB-host-aligned 2 MiB superpages via `PTE_SUPER` (bit 3, with `>= 16`-byte aligned tables), `demote_l2` atomically publishes a populated 512-entry L3 table on partial mutation, `store_range` promotes empty/superpage/all-zero-L3 slots while retiring up to 256 empty L3 tables per `appine_mmu` until free, and a 1024-entry `stlb` plus `stlb_used[16]` sits at the tail of `struct appine_cpu`, flushed by `appine_cpu_tlb_flush` and bypassed when `nwatch != 0`.
- **Why**: 4 KiB-only L3 leaves forced 512 walks per 2 MiB and capped fast-loop spans at 4 KiB across large contiguous model weights and scratch buffers.
- **Tradeoffs**: Adds 16 KiB of virtual `struct appine_cpu` tail per thread (zero RSS unless touched), retains up to 256 retired L3 tables (<= 1 MiB) per address space until teardown, and allocates one L3 table on partial-mutation demotion.
- **Watch out**: Any missed `stlb` flush on demotion/unmap/protect, unaligned table pointer colliding with `PTE_SUPER` or watchpoint entry entering `stlb` can leave stale translations or miss watchpoints.
- **Source**: 42d49fc0

### D7: Read-only non-FUSE file faults fill 16 MiB soft page-table spans

- **What**: `Mm::fault_in` uses `FILE_FAULT_SPAN` (16 MiB, clipped to VMA and EOF) for read-only non-FUSE `PrivateFile` and `Shared` mappings while keeping `LEAF_SPAN` (2 MiB) for anonymous, writable and FUSE `Fill` mappings.
- **Why**: Filling only one 2 MiB `LEAF_SPAN` per fault serialized multi-threaded scans of 1–4 GiB read-only model mappings on the BKL when `MAP_POPULATE` or `MADV_WILLNEED` was absent, whereas aligned read-only spans now promote to L2 superpages without allocating L3 tables or touching host memory.
- **Tradeoffs**: Unaligned fixed read-only file mappings can allocate up to 8 L3 leaf tables (32 KiB) on first fault, and writable or FUSE file mappings keep 2 MiB demand granularity.
- **Watch out**: Relies on file mappings staying outside `Mm::touched_windows`; any future RSS or fork accounting that scans soft PTEs on read-only file mappings must account for 16 MiB fault and `MADV_WILLNEED` prefill spans.
- **Source**: d0945a96
