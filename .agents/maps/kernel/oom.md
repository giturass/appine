# kernel/oom Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/oom.md` for the paired decision history (decisions from before the split are D26, D29, D32, D35 and D44 in `.agents/decisions/kernel/mm.md`).
>
> Verified: 2026-11-11 (split out of the kernel/mm full mapping of 2026-11-10 and its later maintenance; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: root pressure reclaims idle DBT caches and writable aliases while retaining live code-group translations)

## Responsibilities

`kernel/oom` measures guest memory and keeps the app under its memory limit (6.1's
`mm/oom_kill.c`, and the RSS figures of `fs/proc/task_mmu.c`):

- resident memory of an address space for procfs (status, statm, smaps, pagemap), rusage peaks,
  OOM victim scores and the kill log, and of several address spaces together for child cgroups;
- the OOM killer: the app-wide and cgroup limits, polling, victim choice, kills, `memory.events`
  and `memory.oom.group`, and `/proc/<pid>/oom_score`;
- `process_mrelease`, freeing an exiting process's private memory before its threads are gone;
- the periodic release of Tier 1 code written through the writable view.

Root: `core/kernel/src/oom.rs`; in `mm.rs` the resident-memory measures (`resident_in`,
`cow_shared`, `pagemap`, `stack_bytes`, `resident_pages`, `peak_resident_pages`, `resident_split`,
`Usage`) and `Mm::release`; process_mrelease's syscall in `syscall/mem.rs`.

Outside the module: VMAs (`kernel/mm`), host backing and `UNMAPPING` (`kernel/hostmem`), and
copy-on-write sets and loans (`kernel/cow`), which the measures read;
the timer thread that runs the check and the stop/resume of periodic checks (`kernel/time`);
the cgroup tree, its memory files and controller (`kernel/cgroup`); the procfs files that print the
measures (`kernel/procfs`); group exit and kill reports (`kernel/signal`, `kernel/process`).

## Key types

- `RssPlan`, `FileResidency` — one RSS sample plan, and a process-wide cache of file-mapping
  residency (1 s, 1024 entries, emptied when full).
- `Usage` — the resident memory of several address spaces together (a child cgroup's): their host
  spans and the file pieces already counted.
- `Oom` (`Kernel::oom`) — the app-wide limit (`u64::MAX` is none), the root's peak, the next check
  deadline (`None`: at the next wake, at start, after a `memory.max` write, or while every task
  sleeps), the last victim and when it was picked, the victims that outlived their second
  (`stuck`), and the next code-view release.
- `Events` — a cgroup's `memory.events` counters (`high`, `max`, `oom`, `oom_kill`,
  `oom_group_kill`), kept hierarchical and local.
- Intervals: 20 ms, 5 ms above 3/4 of a limit, at least 20 times the measurement's own time; 1 s
  victim timeout and code-view interval.

## Public entry points

- **Measures**: `resident_in`, `cow_shared`, `pagemap`, `stack_bytes`, `resident_pages`,
  `resident_split`, `peak_resident_pages`, `pgtables_bytes`, `pgtables_pages`, `exact_swap_pages`,
  `swappable_nonresident_pages`; `Usage::add` and `pages` (child cgroups).
- **OOM killer**: `oom::check` and `oom::unmap_code_views` (timer thread), `out_of_memory` (also
  from a lowered cgroup `memory.max`), `handle_memory_high` (when usage exceeds `memory.high`),
  `Oom::{measure, recheck}`, `default_limit`, `app_memory`; `Shared::resume_checks` from the run
  loop; `oom::proc_score` for `/proc/<pid>/oom_score`.
- **process_mrelease**: the syscall, and `Mm::release` on another process's address space.

## Data flow / lifecycle

### Resident memory

- Residency comes from host pointers, never from guest addresses: host `mincore`, except that
  `resident_in` (smaps) counts file mappings by host pagemap presence or swap (falling back to
  `mincore`; readahead fills the page cache around touched pages) and a borrowed page only when the
  owner's host page is resident. `resident_pages` and `resident_split` count every borrowed page.
  Reserved VMAs and `[vvar]` never count. Shared anonymous mappings contribute only pages within
  their original backing region, even after mremap grows the guest range beyond it.
- `stack_bytes` (VmStk) sums the grows-down VMAs; `cow_shared` counts pages with more than one user
  for smaps' shared lines and divides them for Pss.
- `resident_split` (status's `VmRSS` as their sum, and `RssAnon`/`RssFile`/`RssShmem`) measures each
  VMA as `resident_pages` does and sorts it: private anonymous memory, borrowed pages and written
  private file mappings as anonymous (all of a written file mapping, where Linux counts only its
  copied pages), shared anonymous memory, SysV shm, memfds and deleted files as shmem
  (`shmem_like`, also used by core dumps' `ANON_SHARED`), other file mappings as file.
- `resident_pages` (statm, stat, OOM victim choice) skips `[vvar]` and private anonymous VMAs never
  writable nor written by the kernel, measures private anonymous VMAs over 1 MB only over windows
  with entries, and uses the 1 s file-residency cache for unwritten private file mappings and all
  shared mappings with a file identity (so they can lag by a second). `resident_in` (smaps, OOM
  kill log) uses the same windows, skips never-written private anonymous VMAs, excludes
  `cow.borrowed` pages from the VMA's own host mincore pass so borrowed pages are never
  double-counted, and uses no cache.
- `Usage` (child cgroups' usage) measures address spaces as `resident_pages` does, but together:
  each file piece measured from the page cache counts once (device, inode, offset and length, so
  overlapping but different pieces of one file count separately), and the other spans, with every
  borrowed page as the owner's host page, are united before one mincore pass, so shared anonymous
  memory, SysV shm, `FileMaps` mappings and pages lent for copy-on-write, which are the same host
  pages in every address space, count once, and a borrowed page counts only while resident.
- `peak_resident_pages` feeds `ru_maxrss` and VmHWM, assuming spans totalling at most 256 pages
  are resident instead of measuring them; it is sampled at last-thread exit, before execve (cheaply
  for a process younger than a tick that has not execed), on getrusage (at most every 10 ms, not
  for `RUSAGE_CHILDREN`) and on process_mrelease.
- `pagemap` marks resident private anonymous pages present and exclusive unless CoW-lent
  (`cow.lent`, present only), borrowed pages present only, every other mapping's pages (shared
  anonymous, shm, memfd, written private file pages included) present by `mincore` and file-backed,
  and reports no frame numbers.

### OOM killer

- All guest memory is host memory of the one app process, and Android's low-memory killer would end
  the whole app, so the OOM killer keeps the app under its own limit by ending guest processes.
  Guest accesses to host-backed pages never reach the kernel layer, so it polls.
- The limit is set once at start from `MachineOptions.memory_limit`: none given (the Android host,
  and the CLI's default) means half of the host's total RAM, or no limit if that reads 0; the CLI's
  `--memory-limit none` means no limit. The guest cannot change it (the root's `memory.max` is
  `EPERM`); the kernel turns it off for good if the usage cannot be read or the check panics (child
  cgroups' limits stay).
- The root (whole-app) usage is the app process's host RssAnon + RssShmem + VmSwap (VmRSS and no
  shmem on kernels without RssAnon), minus Tier 1 code written through the writable view and not
  yet unmapped: it includes translations and kernel-layer metadata and excludes host file pages.
  A child cgroup with the memory controller enabled and a numeric `memory.max` uses `Usage` over
  its processes' address spaces, each address space once (a vfork child and its parent,
  `CLONE_VM` processes).
- `check` runs under the BKL each time the timer thread wakes. With no root limit and no cgroup
  `memory.max` or `memory.high` limit it does nothing; otherwise it measures every 20 ms, every
  5 ms once a scope is above 3/4 of its limit, and never more often than 20 times the measurement's
  own time. The root is measured first. When usage exceeds `k.oom.limit`, `measure_root` calls
  `trim_dbt_pool` to free pooled instances, spare threads and resident template arena pages,
  then `unmap_written_code` to drop writable W^X aliases from host RssShmem. The root footprint
  already discounts those aliases. The check uses the post-reclaim measurement when available
  and falls back to the original sample if the second read fails.
  Child cgroup measurements are deduplicated across `memory.max` and `memory.high` within a round.
  Exceeding `memory.high` (when `UNMAPPING == 0`, on new crossings or continued growth) records a
  `high` event and runs `handle_memory_high` (`trim_dbt_pool` and `unmap_written_code`) without
  killing any process. `memory.max` checks stop at the first scope over its limit, so one OOM
  scope is handled per round. Writing `memory.max` or `memory.high` forces an immediate round.
- When every task is sleeping (a thread in `Cx::unlocked` counts as sleeping), `check` stops
  through `Shared::stop_checks`: it sets `checks_idle` and then looks at the tasks again, clearing
  the flag and going on if one woke meanwhile. Every guest thread clears its `sleeping` flag and
  then calls `resume_checks` at the top of each run-loop iteration, which signals the timer thread
  if the flag was set; with all these accesses SeqCst a waking thread is never missed (the
  code-view release and load-average sampling stop the same way).
- An over-limit round still measures but is skipped while `UNMAPPING` (`kernel/hostmem`'s pending
  host releases) is nonzero or the last victim, picked under 1 s ago, still has threads; otherwise it
  records a `max` event and calls `out_of_memory`. Lowering a child's `memory.max` below its usage
  calls `out_of_memory` once at once, without a `max` event or the `UNMAPPING` check.
- `select` considers every process except tgid 1 (the built-in init), `oom_score_adj` -1000,
  processes outside the over-limit cgroup, zombies, a vfork child whose parent thread still waits
  for it with the same address space (Linux's `in_vfork`: ending it frees nothing, and with its
  parent's memory and a higher tgid it would win), and every victim that outlived its second and
  still has threads (kept in a list until it exits). The score (`badness_with`, Linux's
  `oom_badness`) is `resident_pages + swap_pages + pgtables_pages + adj * (total / 1000)`,
  unclamped, with `total` the larger of RAM and the limit for the root, the cgroup's limit
  otherwise; on equal scores the later (higher tgid) wins, as `oom_evaluate_task` keeps the last
  one not below the best. `pgtables_pages` comes from `appine_engine::Mmu::table_pages` (also
  reported in `/proc/<pid>/status` `VmPTE`, OOM kill log `pgtables`, and `memory.stat`
  `pagetables`). `swap_pages` uses exact `/proc/self/pagemap` swap bits (`Mm::exact_swap_pages`,
  also reported in `VmSwap`) when pagemap is readable; when pagemap is unreadable (SELinux-enforced
  Android hosts), it is 0 whenever host `VmSwap == 0`, and otherwise distributes host `VmSwap`
  proportionally across all live guest `Mm`s' `swappable_nonresident_pages` (present soft-MMU
  entries in written private anonymous VMAs plus CoW-borrowed pages that `mincore` reports
  non-resident, capped so total attributed swap never exceeds host `VmSwap`, and excluding
  unmapped, never-written, file-backed, and `MADV_DONTNEED`-discarded pages whose soft PTEs are
  zapped by `Mm::discard_range`). With no eligible process nothing is killed or logged.
- `/proc/<pid>/oom_score` (`proc_score`, Linux's `proc_oom_score`) is the same badness with
  `total` the host's RAM plus swap, as `(1000 + badness * 1000 / total) * 2 / 3` (0 to 2000), and
  0 for the processes `select` never takes (init, -1000, no live thread, a vfork child).
- The kill records `oom` on the domain and its ancestors; a victim already exiting is reaped when
  eligible and waited for. Otherwise the group gets `SIGKILL` (`group_exit`), its cgroup and
  ancestors count `oom_kill`, host stderr gets a line, the kernel log gets Linux's memcg lines
  (`memory: usage …`, `oom-kill:constraint=CONSTRAINT_MEMCG,…`, `Memory cgroup out of memory:
  Killed process …`; the app-wide limit appears as a memcg OOM; the log's anonymous, file and shmem
  split goes by mapping kind, so memfds show as file), and the app gets a `KillReason::OutOfMemory`
  report. With `memory.oom.group` on the victim's cgroup or an ancestor up to the domain, every
  other live process of the topmost such cgroup except init and -1000 ones is killed too (stuck
  victims included); the victim is logged and counted twice, as Linux's `mem_cgroup_scan_tasks`
  does. After all kills and RSS logs in the round finish, `reap` invokes `Mm::release` (the same
  release path as `process_mrelease`) once per distinct address space when the killed process and
  every other live process sharing its address space are irreversibly exiting as a whole and not
  writing a core dump (`will_free_mem`, skipping live `vfork`/`CLONE_VM` sharers, partial
  single-thread exits and borrowed `Mm`s), sampling each sharing process's peak RSS first so
  `ru_maxrss` is preserved.
- `unmap_code_views` runs on the timer thread whether or not there is a limit: at once after a
  resume from idle, then once a second while any task runs, and once more when everything is idle,
  it calls `appine_engine::unmap_written_code`, because translation-cache pages written through the
  writable W^X view count twice in RssShmem. It is timed rather than continuous because each unmap
  makes the next write to every such page fault again.

### process_mrelease

- The syscall (Linux 6.1's `mm/oom_kill.c`): any flag is `EINVAL`; the fd must be a pidfd (a
  `/proc/<pid>` directory is `EBADF`, unlike pidfd_send_signal), whose process has not been
  reaped and still has a thread in the task table (`ESRCH` otherwise: zombies, Linux's
  `find_lock_task_mm`); that process must satisfy `will_free_mem` (not writing a core file, and
  either group exit started via `exit_group`/`SIGKILL`/fatal signal/OOM kill, a single-thread
  `exit(2)` with no zombie leader and `threads.len() == 1`, or a deliverable non-coredumping fatal
  signal pending for an unblocked untraced thread as Linux's `complete_signal` starts group exit on
  send), and so must every other process whose first live thread uses the same
  address space (`task_will_free_mem`), else `EINVAL`. It succeeds again on a second call. The
  process's peak resident memory is sampled first, so its `ru_maxrss` keeps what it used; if its
  address space is borrowed elsewhere at that moment nothing is released and 0 is returned.
- `Mm::release` (Linux's `__oom_reap_task_mm` over anonymous and private VMAs) leaves the VMAs, and
  so maps, unchanged and skips executable mappings (their translations, the vDSO, and pages they
  borrowed) and `PROT_NONE` reservations. Borrowed pages are re-pointed at the VMA's own page and
  returned without copying (one shootdown, the owners getting write permission back); lent pages
  stay for their borrowers; the other pages of written private anonymous VMAs go back to the host
  (reading zero); written private file VMAs go back to the file in whole host pages of a host file
  mapping (partial host pages kept) or, copied into anonymous memory, to zeros. A thread of the
  process still running reads what is left; on Linux any fault there is `SIGBUS` (`MMF_UNSTABLE`).

## Dependencies (inbound / outbound)

### Inbound

- `kernel/time`: the timer thread (`check`, `unmap_code_views`) and its idle handshake;
  `kernel/process`: the run loop calling `resume_checks`.
- `kernel/procfs`: status, statm, stat, smaps, pagemap and `oom_score`.
- `kernel/cgroup`: the cgroup files (`measure`, `limit`, peak, `app_memory`, `Events`,
  `out_of_memory` for a lowered `memory.max`).
- `kernel/fileio`: the write path's `recheck` after writing cgroup `memory.max`.
- rusage and exit (`peak_resident_pages`), `Machine` (the memory limit at start), the
  process_mrelease syscall.

### Outbound

- `kernel/mm`: VMAs and `shmem_like`; `kernel/cow`: CoW sets and loans; `kernel/hostmem`:
  `FileMaps`, `UNMAPPING`, `HostRegion` flags; `shootdown` (`kernel/mmu`) for borrowed pages a
  release re-points.
- `appine_hal` (`memory_usage` from `/proc/self/status`, `memory_info`, `mincore` and pagemap
  reads), `engine/dbt` (`written_code_bytes`, `unmap_written_code`, `trim_dbt_pool`), `kernel/cgroup` (`memory_limits`,
  `measure_memory`, `memory_event`, `oom_group`), `signal::group_exit`, the kernel log (`printk`)
  and kill reports (`bug::record_kill`, `kernel/bug`).

## Invariants and gotchas

- The OOM killer uses two measures: the root counts the whole app process (translations, metadata,
  swap, no file pages), while cgroups and victim scores count guest resident pages (file pages
  included, swap excluded; shared pages once per cgroup, but once per process in victim scores).
- The code-group registry holds weak references. When the last sharer releases a `DbtSpace`,
  its cached translations become eligible for pool reclaim. Flushing a live space synchronously
  under the BKL would require kicking runners and waiting for them, risking a watchdog stall.
  A null thread CPU also occurs during syscalls, including while waiting for the BKL. Keeping
  live blocks lets all sharers continue running without retranslating after each 5 ms pressure poll.
- The OOM killer polls, so a process that allocates and exits within one interval is never seen,
  and under Tier 1 a guest can touch gigabytes between polls: the limit needs headroom.
- The OOM killer acts on no measurement while `UNMAPPING` is nonzero.
- `failcnt` in the OOM log is the domain's hierarchical `max` count, including its descendants'.
- The measures rely on `kernel/mm`'s rule that every private anonymous page with content has a
  page-table entry: windows without entries are not measured.

## Confirmed bugs / technical debt

- **SELinux-blocked pagemap swap attribution is heuristic:** on Android hosts where SELinux blocks
  `/proc/self/pagemap` and host `VmSwap > 0`, `mincore` cannot distinguish swapped-out private
  anonymous pages from never-touched pages inside an eagerly-mapped (<= 1 MiB) or 2 MiB
  demand-filled written private anonymous span. OOM scoring mitigates this by bounding and scaling
  per-`Mm` candidates against host `VmSwap` (returning 0 when `VmSwap == 0` and excluding
  unmapped, never-written, file, and `MADV_DONTNEED`-zapped pages), while `/proc/<pid>/status`
  `VmSwap` reports 0 when pagemap is unreadable.

## Open questions

None.

## To verify

- None beyond the full mapping's: the Linux 6.1 comparisons here were checked from knowledge of the
  kernel, not against its source.
