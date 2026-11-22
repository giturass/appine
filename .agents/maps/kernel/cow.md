# kernel/cow Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/cow.md` for the paired decision history (not yet created; decisions from before the split are D6, D10, D11, D19, D24, D25 and the fork/copy-on-write parts of D15, D16, D18, D20, D22, D31 and D39 in `.agents/decisions/kernel/mm.md`).
>
> Verified: 2026-11-22 (split out of the kernel/mm full mapping of 2026-11-10 and its later maintenance; the boundary was checked against the source at the split)

## Responsibilities

`kernel/cow` implements address-space `fork` and page-granular copy-on-write in the soft page
tables:

- `Mm::fork`: commit estimation (`commit_too_big`), `anon_vma_fork` identity assignment, per-VMA
  host backing selection and carving, and lending written private anonymous pages;
- the fork-family loan table (`Loans` / `Loan`) and per-address-space `lent`/`borrowed` sets
  (`Cow`);
- copy-on-write fault breaking (`cow_break`), owner-side recall (`recall`), borrower
  materialization (`materialize`), loan return and owner repossession (`return_loans`,
  `repossess`);
- the copy-on-write helpers called by VMA mutations and teardown (`cow_settle`,
  `cow_unmap`/`give_back`, `cow_pages`/`cow_entries`/`write_around`, `discard_unlent`).

Root: in `core/kernel/src/mm.rs`, the `fork` section (`Mm::fork`, `commit_too_big`, `carve`,
`spare_below`) and the `Copy-on-write` section (`MmRef`, `Loan`, `PageHasher`, `Loans`, `Runs`,
`Borrowed`, `Cow`, and the CoW `impl Mm` methods except `shootdown`, which belongs to
`kernel/mmu`).

Outside the module: address-space layout, VMA syscalls, fault dispatch order and kernel-memory
access (`kernel/mm`); host memory allocation, `spare` pools, `Carved`, `FileMaps` and deferred
release (`kernel/hostmem`); page-table population, `shootdown`, `quiesce`, `sync` and code groups
(`kernel/mmu`); resident-memory accounting and `Mm::release` (`kernel/oom`); clone/fork process
orchestration (`kernel/process`); futex key selection (`kernel/futex`).

## Key types

- `Loan` — one lent host page: its owner (`None` for an orphan) and its borrowers (`first` inline
  without allocation, plus `others`; their count is the page's map count for smaps).
- `Loans` — `HashMap<host page address, Loan>` shared by a whole fork family (execve starts a
  fresh one), hashed with a multiplicative `PageHasher`.
- `Cow` — per-mm sets of guest pages it has `lent` and has `borrowed`; `Borrowed` keeps the
  owner's `HostRegion` alive.
- `Runs` — coalesces consecutive pages into runs for PTE updates; a run never crosses a VMA.
- `MmRef` — weak self-handle (`me`) recorded in loans.

## Public entry points

- **Process creation** (`kernel/process`): `Mm::fork`.
- **Faults and writes** (`kernel/mm`, `kernel/futex`, task run loop): `Mm::cow_break`.
- **VMA mutations and teardown** (`kernel/mm`): `cow_settle` (mremap moves, `MADV_DONTNEED`,
  `write_kernel`, `write_force`), `cow_unmap` and `give_back` (munmap), `cow_pages`, `cow_entries`
  and `write_around` (mprotect), `discard_unlent` and `return_loans` (`Drop for Mm`).

## Data flow / lifecycle

### fork

- The caller quiesces the parent (`kernel/mmu`), then `fork` checks commit unless
  `vm.overcommit_memory` is 1 (`commit_too_big`: counts private, currently writable,
  non-`MAP_NORESERVE`, non-dontfork VMAs the child gets, merging adjacent ones the way Linux
  `vma_merge` would; `ENOMEM` when one exceeds RAM plus swap; a limit of 0 disables it; mode 2's
  strict accounting is not emulated). `fork` cannot fail after lending starts; the parent's TLB
  flush waits for its `sync`.
- The child keeps the parent's membarrier registrations (Linux copies `membarrier_state`) and
  `memops`; execve starts a fresh `Mm` without them.
- Each child VMA with contents of its own gets a new `anon` identity, shared by the pieces of one
  Linux VMA (Linux's `anon_vma_fork`), so it no longer joins its neighbours while the parent's
  pieces still do: a written anonymous VMA, or a written private file VMA when a page of its host
  region holds a private copy (host pagemap: present without the file bit, or swapped; unreadable
  pagemap counts as yes).
- Per VMA (`MADV_DONTFORK` VMAs are skipped; the child's VMAs keep `dontdump` and `wipeonfork`):
  - shared mappings, reservations and read-only private file mappings share the parent's region;
    read-only private file VMAs are marked `cow` on both sides;
  - non-growsdown, non-reserved, non-heap anonymous or writable private-file VMAs of at most 1 MB
    are carved (`carve`) from one `spare` region (`kernel/hostmem`);
  - the heap (the anonymous VMA at the page-aligned `brk_start`, at most 256 MB) gets a `spare`
    region of 256 MB; a growsdown anonymous VMA with reserved room below (`spare_below`) gets a
    `spare` region of room plus length; everything else gets new anonymous memory
    (`kernel/hostmem`);
  - private anonymous VMAs that were ever written are lent, except `MADV_WIPEONFORK` ones, where
    the child keeps its own all-zero memory; never-written ones need nothing;
  - writable private file VMAs are copied page by page up to EOF, skipping all-zero pages
    (`copy_nonzero_pages`); a `Fill` one instead maps its host file privately again and copies the
    pages read that differ from it, keeping the same fill (pages either side reads later reach
    both), and is never carved.

### Lending and copy-on-write

- Lending (`lend`): VMAs of at most 16 pages lend every page. Larger ones read the host
  `/proc/self/pagemap` only over 2 MB leaf windows that have entries or CoW pages
  (`touched_windows`, merged up to 1 GB); untouched pages are known zero and the child keeps its
  own. If pagemap is unreadable, every page in the windows is lent. Pages the parent itself
  borrowed are re-lent from their owner. Parent and child get read-only entries for the lent pages
  (none for `PROT_NONE` VMAs; a later mprotect rebuilds them).
- Borrower write (`cow_break`): only for a writable private anonymous VMA whose page is borrowed
  or lent. A borrowed page is copied into the VMA's own slot (`materialize`), re-mapped with the
  VMA prot, the borrower's threads are shot down (`kernel/mmu`), and the loan is returned.
- Owner write, munmap, mremap move or `MADV_DONTNEED` of a lent page (`recall`): every borrower
  copies first (interrupting its guest threads), then the owner gets write permission back
  (`repossess`).
- Borrower munmap (`cow_unmap`/`give_back`) returns borrowed pages without copying; borrower
  mremap and `MADV_DONTNEED` copy first (`cow_settle`).
- When the last borrower returns a page (`return_loans`), the owner's entries are restored at once
  (`repossess`), in runs that never cross VMAs, without a flush.
- mprotect over CoW pages (`cow_pages`, `cow_entries`, `write_around`) never gives a CoW page
  write permission or a borrowed page an entry at the borrower's own host page, not even between
  steps (see `kernel/mm`'s mprotect), since other threads may run guest code meanwhile.
- Futex keys of private memory are the address space's id and the address, so computing a key does
  not copy a borrowed page (writing the word, as PI locks, robust lists and `FUTEX_WAKE_OP` do,
  breaks CoW); see `kernel/futex` and `kernel/mm`.
- Kernel writes (`kernel/mm`): `Mm::write` breaks CoW per page; `write_kernel` and `write_force`
  settle CoW (`cow_settle`). No-BKL fast-path writes go through the CPU's `translate(WRITE)` and
  fall back to the BKL path on failure.
- Owner destruction (`Drop for Mm`, exit/exec): borrowed pages are returned. If it has lent pages,
  their loans become orphans held by the borrowers' `Arc<HostRegion>`, and every non-lent page of
  its written private anonymous VMAs is discarded (`discard_unlent`). Lent or borrowed pages are
  never written in place, even by a sole orphan borrower.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/process`: `Mm::fork` during `clone` without `CLONE_VM`, after `kernel/mmu`'s `quiesce`;
  task run loop calls `cow_break` first on write faults.
- `kernel/mm`: VMA mutations and teardown (`cow_settle`, `cow_unmap`/`give_back`,
  `cow_pages`/`cow_entries`/`write_around`, `discard_unlent`, `return_loans`), `Mm::write`
  (`cow_break`).
- `kernel/futex`: `cow_break` before writing private futex words (PI locks, robust lists,
  `FUTEX_WAKE_OP`).
- `kernel/oom`: reads `Cow` sets and `Loans` (map counts for smaps, `Usage` borrowed spans,
  `Mm::release` detaching borrowed pages and leaving lent ones).

### Outbound

- `kernel/mm`: `Mm` fields (`vmas`, `me`, `dirty`, `shared_maps`, layout/exec fields), `same_vma`,
  `insert`, `fill_copy`, `note_shared_maps`, `OVERCOMMIT_MEMORY`.
- `kernel/hostmem`: `HostRegion`, `spare::anonymous`, `Carved`, `Mm::new_anonymous`,
  `discard_host`, `copy_nonzero_pages`.
- `kernel/mmu`: `Mmu::map_shared`, `Mmu::protect`, `Mmu::protect_shared`, `shootdown`,
  `touched_windows` (relying on page-table entries for non-zero pages).
- `appine_hal`: `ram_and_swap`, `page_size`, `touched_pages`, `has_private_pages`.

## Invariants and gotchas

- Lent and borrowed pages are never writable in place. `Mm::translate` (`kernel/mm`) does not
  break CoW, so any kernel code that writes guest memory through it must handle CoW pages itself.
- Every private anonymous page with content has a page-table entry, except borrowed pages in a
  `PROT_NONE` VMA (which fork's window search adds from the CoW sets). `fork`'s lending relies on
  `kernel/mm` keeping this invariant across kernel writes, mlock, `MAP_POPULATE`, mremap and
  `PROT_NONE`.
- `Loans` and `Cow` use `Rc`/`RefCell` and are correct only under the BKL; checking builds assert
  no borrow is held across a BKL release.
- CoW never mutably borrows two address spaces at once: borrower-side loan returns run inside the
  borrower's own operation or drop, and owner-side `recall` only takes shared borrows of
  borrowers. The `try_borrow` guard in `return_loans` is therefore defensive (see the latent
  hazard below).
- Host `mincore` reports pages swapped to zram as absent, which is why `fork`'s touched-page check
  reads `/proc/self/pagemap` instead.
- `fork` cannot fail after lending starts; all host allocations (`carve`, `spare::anonymous`,
  `new_anonymous`, `fill_copy`, `child.insert`) run before `lend`.

## Confirmed bugs / technical debt

- **Latent CoW leak:** if `return_loans` ever ran while the owner was mutably borrowed, the page
  would stay in the owner's `lent` set without a loan; a fork in that state would give the child a
  loan-less borrowed entry and the owner's next write would show in the child. Unreachable today,
  and the guard's comment cites a path (`recall`) that never reaches it.
- **A written private file mapping marked `cow` at fork is not reverted by `MADV_DONTNEED`:** fork
  marks every read-only private file VMA `cow`, written or not, and `kernel/mm`'s `discard` skips
  `cow` VMAs, so the written data stays in both processes.
- **`anon_vma` and commit approximation at fork:** anonymous memory that has been writable counts
  as having an `anon_vma` although Linux creates one only at the first write fault, and
  `commit_too_big` checks only current permissions rather than Linux's sticky `VM_ACCOUNT`.

## Open questions

None.
