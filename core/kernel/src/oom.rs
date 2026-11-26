//! The guest's own OOM killer (the kernel/oom map, design doc §12 item 4).
//!
//! Android's LMK sees only the app process: under memory pressure it kills the whole app, and all
//! sessions are lost together. So the app process's anonymous memory gets a limit (by default half
//! of physical memory), and when it is exceeded a guest process is picked and ended with SIGKILL,
//! as Linux's OOM killer does. What is measured is the anonymous memory of the whole host process
//! ([`app_memory`]): that is what the LMK looks at, and besides the guest's private and shared
//! memory it includes the translation cache and metadata cache the kernel layer spends on the
//! guest; the host's file pages (files in the store, mapped programs) can be reclaimed and do not
//! count.
//!
//! The host kernel handles the guest touching new pages directly, and the kernel layer does not
//! see those page faults, so it can only check periodically: while some guest thread is not waiting
//! in the kernel, the timer thread measures every 20 milliseconds (one read of `/proc/self/status`
//! takes about 2 microseconds), and every 5 milliseconds once usage passes 3/4 of the limit; when
//! all are waiting, memory cannot grow any more, so it stops, and is woken again when some thread
//! is about to go on running guest code ([`Shared::resume_checks`]). A program allocating memory
//! nonstop can use tens of MB more before it is noticed (under Tier 1 it can touch several GB of
//! new pages per second), so the limit must leave headroom. After ending a process, it waits until
//! its threads have all exited and its memory has gone back to the host before deciding whether to
//! end the next one.
//!
//! cgroups with `memory.max` set ([`crate::cgroup`]) are checked along with it: the resident memory
//! of the processes in the subtree is measured (mincore: a process of tens of MB takes one or two
//! hundred microseconds, and one with many mappings like node at 200 MB takes over a millisecond,
//! so only cgroups with a limit are measured, and the interval is at least 20 times the time
//! taken), and when it is over, as with Linux's memcg OOM, a process below the cgroup is picked and
//! ended, together with that group under `memory.oom.group`.

use std::cell::Cell;
use std::rc::{Rc, Weak};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use appine_engine::PAGE_SIZE;

use crate::cell::RefCell;
use crate::cgroup::ROOT;
use crate::kernel::{INIT, Kernel, Shared};
use crate::process::{ExitStatus, Signal, ThreadGroup};

/// Interval between checks while some thread is running.
const INTERVAL: Duration = Duration::from_millis(20);
/// Interval between checks once usage passes 3/4 of the limit.
const NEAR_INTERVAL: Duration = Duration::from_millis(5);
/// The check interval is at least this many times the time one check takes (measuring a cgroup's
/// memory needs mincore; see [`check`]).
const MEASURE_SHARE: u32 = 20;
/// When an ended process has not finished exiting after this long (stuck in host I/O), it is no
/// longer waited for; about the time Linux's oom_reaper takes to give up on a process.
const VICTIM_TIMEOUT: Duration = Duration::from_secs(1);
/// The lower bound of `oom_score_adj`: such processes are never picked.
const OOM_SCORE_ADJ_MIN: i32 = -1000;
/// How often the pages the code cache has written in the writable view are torn down
/// ([`unmap_code_views`]).
const CODE_VIEW_INTERVAL: Duration = Duration::from_secs(1);

/// The OOM killer's state, in [`Kernel`].
pub(crate) struct Oom {
    /// The limit (bytes); `u64::MAX` means no limit.
    pub limit: u64,
    /// The highest usage measured (`/sys/fs/cgroup/memory.peak`).
    pub peak: Cell<u64>,
    /// When the next check is due; None means all threads are waiting and checks have stopped.
    next: Option<Instant>,
    /// The process ended most recently, and when it was ended.
    victim: Option<(Weak<RefCell<ThreadGroup>>, Instant)>,
    /// Victims still not done exiting after [`VICTIM_TIMEOUT`] (stuck in host I/O): never waited
    /// for or picked again.
    stuck: Vec<Weak<RefCell<ThreadGroup>>>,
    /// When the code cache's writable view is next torn down; None means all threads are waiting
    /// and it has stopped.
    code_views: Option<Instant>,
}

impl Default for Oom {
    fn default() -> Oom {
        Oom {
            limit: u64::MAX,
            peak: Cell::new(0),
            next: None,
            victim: None,
            stuck: Vec::new(),
            code_views: None,
        }
    }
}

impl Oom {
    /// The app's current memory usage (0 when it cannot be measured), noting the peak on the way.
    pub fn measure(&self) -> u64 {
        let used = footprint().unwrap_or(0);
        self.note(used);
        used
    }

    fn note(&self, used: u64) {
        self.peak.set(self.peak.get().max(used));
    }

    /// A cgroup's `memory.max` changed: check at the next wakeup (the new limit may already be
    /// exceeded).
    pub fn recheck(&mut self) {
        self.next = None;
    }
}

/// The counts in `memory.events`: how often usage exceeded `memory.high` (`high`), how often usage
/// was measured over `memory.max` and so a process had to be picked and ended (`max`, not counted
/// while the one picked last time has not finished exiting), how many times the OOM killer fired
/// (`oom`), how many processes were ended (`oom_kill`), and how often a whole group was ended
/// because of `memory.oom.group` (`oom_group_kill`). Recorded on the cgroup
/// ([`crate::cgroup::memory_event`]); those for the app's limit are recorded on the root.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Events {
    pub high: u64,
    pub max: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub oom_group_kill: u64,
}

/// The default limit: half of the host's physical memory.
pub(crate) fn default_limit() -> u64 {
    match appine_hal::memory_info().0 {
        0 => u64::MAX,
        total => total / 2,
    }
}

/// Called each time the timer thread wakes up: when a check is due, measures the app's memory and
/// the memory of the cgroups with `memory.max` or `memory.high` set. Exceeding `memory.high`
/// records a `high` event and reclaims unused Tier 1 pool/code-view memory without killing;
/// exceeding `memory.max` (or the app limit) ends a guest process (for a cgroup, picked from
/// inside it). Returns when the next check is due.
pub(crate) fn check(k: &mut Kernel, shared: &Shared) -> Option<Instant> {
    let limits = crate::cgroup::memory_limits(k);
    let high_limits = crate::cgroup::memory_high_limits(k);
    if k.oom.limit == u64::MAX && limits.is_empty() && high_limits.is_empty() {
        return None;
    }
    let now = Instant::now();
    if let Some(next) = k.oom.next
        && now < next
    {
        return Some(next);
    }
    if shared.stop_checks(|| all_sleeping(k)) {
        k.oom.next = None;
        return None;
    }
    // The scope that is over (the root being the whole app), usage, limit
    let mut over = None;
    let mut near = false;
    if k.oom.limit != u64::MAX {
        match measure_root(&k.oom, k.oom.limit, footprint, reclaim_dbt_memory) {
            Some(used) => {
                near = used > k.oom.limit / 4 * 3;
                if used > k.oom.limit {
                    over = Some((ROOT, used, k.oom.limit));
                }
            }
            None => {
                eprintln!("appine: cannot measure the memory use, the memory limit is off");
                k.oom.limit = u64::MAX;
            }
        }
    }
    // A cgroup with both limits uses the same usage sample for both checks.
    let mut measured = std::collections::HashMap::new();
    for (id, max) in limits {
        if over.is_some() {
            break;
        }
        let used = crate::cgroup::measure_memory(k, id);
        if !high_limits.is_empty() {
            measured.insert(id, used);
        }
        near |= used > max / 4 * 3;
        if used > max {
            over = Some((id, used, max));
        }
    }
    let unmapping = crate::mm::UNMAPPING.load(Ordering::Acquire) != 0;
    let mut high_over = Vec::new();
    for (id, high) in high_limits {
        let used = measured
            .get(&id)
            .copied()
            .unwrap_or_else(|| crate::cgroup::measure_memory(k, id));
        near |= used > high / 4 * 3;
        if !unmapping && crate::cgroup::note_memory_high_state(k, id, used, high) {
            high_over.push(id);
        }
    }
    for id in high_over {
        handle_memory_high(k, id);
    }
    // Measuring cgroups holds the BKL, and takes a millisecond or two with many processes and large
    // mappings: the interval is at least MEASURE_SHARE times this check's duration, taking no more
    // than 1/MEASURE_SHARE of the BKL's time
    let interval = if near { NEAR_INTERVAL } else { INTERVAL };
    k.oom.next = Some(now + interval.max(now.elapsed() * MEASURE_SHARE));
    // The memory of a process that just exited goes back to the host only after it releases the
    // BKL (mm::release_unmapped)
    let Some((domain, used, limit)) = over else {
        return k.oom.next;
    };
    // The process picked last time is still exiting: its memory will be back soon, so this does
    // not count as hitting the limit again
    if unmapping || waiting_for_victim(k, now) {
        return k.oom.next;
    }
    crate::cgroup::memory_event(k, domain, |e| e.max += 1);
    out_of_memory(k, (domain, used, limit));
    k.oom.next
}

/// Records a cgroup's `memory.high` event and reclaims idle Tier 1 memory and writable aliases.
pub(crate) fn handle_memory_high(k: &mut Kernel, id: u64) {
    crate::cgroup::memory_event(k, id, |e| e.high += 1);
    reclaim_dbt_memory();
}

/// Live code groups keep their translations. Flushing them would wait for runners under the BKL.
fn reclaim_dbt_memory() {
    appine_engine::trim_dbt_pool();
    appine_engine::unmap_written_code();
}

/// Records each whole-app sample in the peak. Above the limit, reclaims memory and returns
/// the latest successful sample.
fn measure_root(
    oom: &Oom,
    limit: u64,
    measure: impl Fn() -> Option<u64>,
    reclaim: impl FnOnce(),
) -> Option<u64> {
    let sample = || measure().inspect(|&used| oom.note(used));
    let used = sample()?;
    if used <= limit {
        return Some(used);
    }
    reclaim();
    sample().or(Some(used))
}

/// The app's memory usage (bytes): the sum of the items of [`app_memory`]. Returns None when it
/// cannot be read.
fn footprint() -> Option<u64> {
    app_memory().map(|u| u.anon + u.shmem + u.swap)
}

/// The app's memory usage, item by item ([`appine_hal::memory_usage`]). Pages Tier 1's code cache
/// has written in the writable view and that are not torn down yet ([`unmap_code_views`]) count
/// twice in the host's RssShmem, so one count is subtracted.
pub(crate) fn app_memory() -> Option<appine_hal::MemoryUsage> {
    let mut u = appine_hal::memory_usage()?;
    u.shmem = u.shmem.saturating_sub(appine_engine::written_code_bytes());
    Some(u)
}

/// Usage `used` of OOM scope `domain` (a cgroup, the root being the whole app) exceeds limit
/// `limit`: picks a process below it and ends it (Linux's `out_of_memory`, `oom_kill_process`),
/// together with that group under `memory.oom.group`. While the process picked last time has not
/// finished exiting it waits for it (its memory will be back soon); one still not done after the
/// timeout (stuck in host I/O) is no longer waited for, nor picked again, however many others are
/// picked after it.
pub(crate) fn out_of_memory(k: &mut Kernel, (domain, used, limit): (u64, u64, u64)) {
    let now = Instant::now();
    if waiting_for_victim(k, now) {
        return;
    }
    let alive = |w: &Weak<RefCell<ThreadGroup>>| {
        w.upgrade().is_some_and(|g| !g.borrow().threads.is_empty())
    };
    if let Some((v, _)) = k.oom.victim.take()
        && alive(&v)
    {
        k.oom.stuck.push(v);
    }
    k.oom.stuck.retain(alive);
    let stuck: Vec<_> = k.oom.stuck.iter().filter_map(Weak::upgrade).collect();
    let Some((victim, rss)) = select(k, &stuck, (domain, limit)) else {
        return;
    };
    crate::cgroup::memory_event(k, domain, |e| e.oom += 1);
    k.oom.victim = Some((Rc::downgrade(&victim), now));
    // One already exiting (exit_group, a fatal signal) need not be ended; as on Linux, reap its
    // private memory when safe and wait for it to finish exiting.
    if victim.borrow().exiting.is_some() {
        let mut reaped = Vec::new();
        reap(k, &victim, &mut reaped);
        return;
    }
    {
        let g = victim.borrow();
        let task = g.threads.first().and_then(|t| k.tasks.get(t));
        eprintln!(
            "appine: out of memory: killed process {} ({}) rss:{}kB oom_score_adj:{}; \
             {} memory {}kB, limit {}kB",
            g.tgid,
            crate::pseudo::comm_str(task.map(|t| &**t), g.tgid),
            rss * PAGE_SIZE / 1024,
            g.oom_score_adj,
            if domain == ROOT {
                "App".to_owned()
            } else {
                format!("cgroup {}", k.cgroups.path(domain, ROOT))
            },
            used / 1024,
            limit / 1024,
        );
        log_kill(k, &g, task.map(|t| &**t), (domain, used, limit));
        let comm = crate::pseudo::comm_str(task.map(|t| &**t), g.tgid);
        crate::bug::record_kill(k, g.tgid, comm, oom_reason(k, domain, used, limit));
    }
    let group = crate::cgroup::oom_group(k, victim.borrow().cgroup, domain);
    kill(k, &victim);
    let mut killed = vec![victim.clone()];
    // memory.oom.group: the processes in that cgroup are ended along with it (Linux's
    // mem_cgroup_scan_tasks, counting the picked one again too), except those whose oom_score_adj
    // is the lower bound
    if let Some(group) = group {
        crate::cgroup::memory_event(k, group, |e| e.oom_group_kill += 1);
        let members: Vec<_> = k
            .groups
            .values()
            .filter(|g| {
                let g = g.borrow();
                g.tgid != INIT
                    && !g.threads.is_empty()
                    && g.oom_score_adj != OOM_SCORE_ADJ_MIN
                    && k.cgroups.is_within(g.cgroup, group)
            })
            .cloned()
            .collect();
        for g in members {
            {
                let gb = g.borrow();
                let task = gb.threads.first().and_then(|t| k.tasks.get(t));
                log_killed(k, &gb, task.map(|t| &**t));
                // The picked one was already reported above
                if !Rc::ptr_eq(&g, &victim) {
                    let comm = crate::pseudo::comm_str(task.map(|t| &**t), gb.tgid);
                    let reason = oom_reason(k, domain, used, limit);
                    crate::bug::record_kill(k, gb.tgid, comm, reason);
                }
            }
            kill(k, &g);
            if !Rc::ptr_eq(&g, &victim) {
                killed.push(g);
            }
        }
    }
    // Reap private memory after all kills and RSS logs in this round have finished so processes
    // sharing an address space inside a memory.oom.group cgroup are all marked exiting first.
    let mut reaped = Vec::new();
    for g in &killed {
        reap(k, g, &mut reaped);
    }
}

/// How swap pages are attributed per guest `Mm` during OOM scoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwapContext {
    /// `/proc/self/pagemap` is readable: count exact swapped entries per `Mm`.
    Exact,
    /// `/proc/self/pagemap` is unreadable, and host `VmSwap` is 0: no process has swapped pages.
    Zero,
    /// `/proc/self/pagemap` is unreadable (SELinux-enforced Android hosts) and host `VmSwap > 0`:
    /// attribute `host_swap_pages` conservatively across live guest address spaces proportionally to
    /// their non-resident mapped private anonymous pages (`total_cand`), capped by `host_swap_pages`.
    Fallback {
        host_swap_pages: u64,
        total_cand: u64,
    },
}

/// Conservative per-`Mm` swap estimate when `/proc/self/pagemap` is unreadable:
/// - Always 0 when `host_swap_pages == 0`, `cand == 0`, or `total_cand == 0`.
/// - Never exceeds `cand` or `host_swap_pages`, and the sum across all processes never exceeds
///   `host_swap_pages`.
fn estimate_swap_share(cand: u64, total_cand: u64, host_swap_pages: u64) -> u64 {
    if host_swap_pages == 0 || cand == 0 || total_cand == 0 {
        return 0;
    }
    if total_cand <= host_swap_pages {
        cand
    } else {
        ((cand as u128 * host_swap_pages as u128) / total_cand as u128) as u64
    }
}

/// Builds the swap attribution context once per scoring pass. When pagemap is unreadable and host
/// `VmSwap > 0`, scans all unique live guest `Mm`s (including `-1000` protected processes so their
/// swap is not misattributed to eligible processes).
fn swap_context(k: &Kernel) -> SwapContext {
    if appine_hal::pagemap_readable() {
        return SwapContext::Exact;
    }
    let host_swap_pages = app_memory().map_or(0, |u| u.swap / PAGE_SIZE);
    fallback_swap_context(k, host_swap_pages)
}

fn fallback_swap_context(k: &Kernel, host_swap_pages: u64) -> SwapContext {
    if host_swap_pages == 0 {
        return SwapContext::Zero;
    }
    let mut seen = std::collections::HashSet::new();
    let mut total_cand = 0u64;
    for group in k.groups.values() {
        let Ok(g) = group.try_borrow() else {
            continue;
        };
        let Ok(Some(mm)) = group_mm(k, &g) else {
            continue;
        };
        if seen.insert(Rc::as_ptr(&mm))
            && let Ok(mm_ref) = mm.try_borrow()
        {
            total_cand = total_cand.saturating_add(mm_ref.swappable_nonresident_pages());
        }
    }
    SwapContext::Fallback {
        host_swap_pages,
        total_cand,
    }
}

fn swap_pages_for_mm(mm: &crate::mm::Mm, ctx: SwapContext) -> u64 {
    match ctx {
        SwapContext::Exact => mm.exact_swap_pages().unwrap_or(0),
        SwapContext::Zero => 0,
        SwapContext::Fallback {
            host_swap_pages,
            total_cand,
        } => estimate_swap_share(
            mm.swappable_nonresident_pages(),
            total_cand,
            host_swap_pages,
        ),
    }
}

/// Picks the process to end (skipping those in `skip`): the OOM scope is cgroup `domain` (the root
/// being the whole app), and the pick is among the processes below it, by Linux 6.1's oom_badness:
/// resident pages plus swap pages plus page-table pages plus `oom_score_adj` times a thousandth of
/// the limit `limit` in pages (for the root, the larger of physical memory and the limit; 1000
/// equals everything, so such a process is always picked first), unclamped; on equal scores the
/// later process wins, as `oom_evaluate_task` keeps the last one not below the best. Returns the
/// process and its resident 4K page count.
fn select(
    k: &Kernel,
    skip: &[Rc<RefCell<ThreadGroup>>],
    (domain, limit): (u64, u64),
) -> Option<(Rc<RefCell<ThreadGroup>>, u64)> {
    select_with(k, skip, (domain, limit), swap_context(k))
}

fn select_with(
    k: &Kernel,
    skip: &[Rc<RefCell<ThreadGroup>>],
    (domain, limit): (u64, u64),
    swap_ctx: SwapContext,
) -> Option<(Rc<RefCell<ThreadGroup>>, u64)> {
    let total = if domain == ROOT {
        appine_hal::memory_info().0.max(limit)
    } else {
        limit
    };
    let total = (total / PAGE_SIZE) as i64;
    let mut best: Option<(Rc<RefCell<ThreadGroup>>, i64, u64)> = None;
    for group in k.groups.values() {
        if skip.iter().any(|s| Rc::ptr_eq(s, group)) {
            continue;
        }
        let g = group.borrow();
        if !k.cgroups.is_within(g.cgroup, domain) {
            continue;
        }
        let Some((points, rss)) = badness_with(k, &g, total, swap_ctx) else {
            continue;
        };
        if best.as_ref().is_none_or(|b| points >= b.1) {
            best = Some((group.clone(), points, rss));
        }
    }
    best.map(|(g, _, rss)| (g, rss))
}

/// Linux's `oom_badness` for process `g` against `total` pages: its resident pages plus swap pages
/// plus allocated soft-MMU page-table pages plus its `oom_score_adj` times a thousandth of
/// `total`, and the resident pages; None for a process never picked (the built-in init,
/// `oom_score_adj` -1000, no live thread, a vfork child still sharing its parent's address space).
///
/// Swap attribution uses exact `/proc/self/pagemap` swap bits when readable; when pagemap is
/// blocked by SELinux on Android hosts and host `VmSwap > 0`, it falls back to a conservative
/// proportional estimate bounded by host `VmSwap` over non-resident mapped private anonymous pages
/// (excluding unmapped and `MADV_DONTNEED`-discarded pages).
fn badness_with(
    k: &Kernel,
    g: &ThreadGroup,
    total: i64,
    swap_ctx: SwapContext,
) -> Option<(i64, u64)> {
    if g.tgid == INIT || g.oom_score_adj == OOM_SCORE_ADJ_MIN {
        return None;
    }
    let task = g.threads.first().and_then(|t| k.tasks.get(t))?;
    let mm = task.res.borrow().mm.clone();
    // Linux's in_vfork: ending it frees nothing, and with the same memory and score it would win
    // over its parent as the later process (posix_spawn's child before it execs)
    let parent = k.tasks.get(&g.parent_thread);
    if task.vfork.get() && parent.is_some_and(|p| Rc::ptr_eq(&p.res.borrow().mm, &mm)) {
        return None;
    }
    let mm_ref = mm.borrow();
    let rss = mm_ref.resident_pages();
    let swap = swap_pages_for_mm(&mm_ref, swap_ctx);
    let pgtables = mm_ref.pgtables_pages();
    let mem_pages = rss.saturating_add(swap).saturating_add(pgtables);
    Some((
        mem_pages as i64 + g.oom_score_adj as i64 * (total / 1000),
        rss,
    ))
}

/// `/proc/<pid>/oom_score` (Linux's `proc_oom_score`): the badness against the host's RAM plus swap,
/// scaled into 0 to 2000 (1000 + badness × 1000 / total, times 2/3), and 0 for a process never
/// picked.
pub(crate) fn proc_score(k: &Kernel, g: &ThreadGroup) -> u64 {
    let total = (appine_hal::ram_and_swap() / PAGE_SIZE).max(1) as i64;
    let swap_ctx = swap_context(k);
    badness_with(k, g, total, swap_ctx).map_or(0, |(b, _)| {
        ((1000 + b * 1000 / total) * 2 / 3).max(0) as u64
    })
}

/// Writes to the kernel log when ending a process ([`crate::klog`]): to the guest, the app's limit
/// is the `memory.max` of the cgroup it is in, so this writes as Linux's memcg OOM does (the first
/// line of `mem_cgroup_print_oom_meminfo`, `dump_oom_summary`, `__oom_kill_process`), and `dmesg`
/// shows who was ended and why. The call stack, the table of processes and the like are left out.
/// Resident pages are split by kind of mapping (counted by host memory, as smaps does), and
/// `pgtables` reports the address space's allocated soft-MMU page tables.
fn log_kill(
    k: &Kernel,
    g: &ThreadGroup,
    task: Option<&crate::task::Task>,
    (domain, used, limit): (u64, u64, u64),
) {
    use crate::klog::{level, printk};
    let comm = crate::pseudo::comm_str(task, g.tgid);
    let (pid, uid) = (g.tgid, g.cred.ruid);
    let failcnt = k.cgroups.get(domain).map_or(0, |c| c.mem_events.max);
    let log = &k.klog;
    printk(
        log,
        level::INFO,
        format_args!(
            "memory: usage {}kB, limit {}kB, failcnt {failcnt}",
            used / 1024,
            limit / 1024,
        ),
    );
    printk(
        log,
        level::INFO,
        format_args!(
            "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,\
             oom_memcg={},task_memcg={},task={comm},pid={pid},uid={uid}",
            k.cgroups.path(domain, ROOT),
            k.cgroups.path(g.cgroup, ROOT),
        ),
    );
    log_killed(k, g, task);
}

/// The line about ending one process (`__oom_kill_process`). Resident pages are split by kind of
/// mapping (counted by host memory, as smaps does), and `pgtables` reports allocated soft-MMU
/// page tables.
fn log_killed(k: &Kernel, g: &ThreadGroup, task: Option<&crate::task::Task>) {
    let comm = crate::pseudo::comm_str(task, g.tgid);
    let (pid, uid) = (g.tgid, g.cred.ruid);
    let (mut vm, mut anon, mut file, mut shmem, mut pgtables) = (0, 0, 0, 0, 0);
    if let Some(t) = task {
        let res = t.res.borrow();
        let mm = res.mm.borrow();
        vm = mm.size() / 1024;
        pgtables = mm.pgtables_bytes() / 1024;
        for r in mm.regions() {
            let pages = mm.resident_in(r.start, r.end - r.start);
            match (r.file, r.shared) {
                (Some(_), _) => file += pages * 4,
                (None, true) => shmem += pages * 4,
                (None, false) => anon += pages * 4,
            }
        }
    }
    crate::klog::printk(
        &k.klog,
        crate::klog::level::ERR,
        format_args!(
            "Memory cgroup out of memory: Killed process {pid} ({comm}) total-vm:{vm}kB, \
             anon-rss:{anon}kB, file-rss:{file}kB, shmem-rss:{shmem}kB, UID:{uid} \
             pgtables:{pgtables}kB oom_score_adj:{}",
            g.oom_score_adj
        ),
    );
}

/// The report for the app ([`crate::bug::KillReport`]): the app's limit, or which cgroup's
/// `memory.max`.
fn oom_reason(k: &Kernel, domain: u64, used: u64, limit: u64) -> crate::bug::KillReason {
    crate::bug::KillReason::OutOfMemory {
        cgroup: (domain != ROOT).then(|| k.cgroups.path(domain, ROOT)),
        used,
        limit,
    }
}

/// Ends process `g` with SIGKILL and counts it in the `oom_kill` of its cgroup (one already exiting
/// counts too, as on Linux).
fn kill(k: &mut Kernel, g: &Rc<RefCell<ThreadGroup>>) {
    let cgroup = g.borrow().cgroup;
    if g.borrow().exiting.is_none() {
        let status = ExitStatus::Signaled {
            signal: Signal::KILL,
            pc: None,
            fault_addr: None,
            core_dumped: false,
        };
        crate::signal::group_exit(k, g, status);
    }
    crate::cgroup::memory_event(k, cgroup, |e| e.oom_kill += 1);
}

/// The address space of process `g`'s first live thread: `Ok(None)` when `g` has no live thread in
/// `k.tasks`, `Err(())` when that thread's resources are currently borrowed.
fn group_mm(k: &Kernel, g: &ThreadGroup) -> Result<Option<Rc<RefCell<crate::mm::Mm>>>, ()> {
    let Some(task) = g.threads.iter().find_map(|t| k.tasks.get(t)) else {
        return Ok(None);
    };
    let res = task.res.try_borrow().map_err(|_| ())?;
    Ok(Some(res.mm.clone()))
}

/// Whether process `g` is irreversibly exiting as a whole and not writing a core dump (Linux 6.1's
/// `task_will_free_mem` without treating an undelivered signal as guaranteed exit; shared by OOM
/// reaping and `process_mrelease`).
pub(crate) fn will_free_mem(k: &Kernel, g: &ThreadGroup) -> bool {
    if g.core.is_some() {
        return false;
    }
    g.exiting.is_some()
        && (!g.single_exit
            || (g.leader_exit.is_none() && g.threads.len() == 1)
            || g.threads
                .iter()
                .any(|tid| k.tasks.get(tid).is_some_and(|t| t.killed.get())))
}

/// Reaps `group`'s private memory via [`crate::mm::Mm::release`] (Linux's `oom_reaper`, reusing
/// the same release path as `process_mrelease`) when `group` and every other process sharing its
/// address space satisfy [`will_free_mem`] (no core dump in progress, no live `vfork`/`CLONE_VM`
/// sharer) and the address space is not borrowed. Samples peak RSS on every sharing process first
/// so `ru_maxrss` is preserved.
fn reap(
    k: &Kernel,
    group: &Rc<RefCell<ThreadGroup>>,
    reaped: &mut Vec<Rc<RefCell<crate::mm::Mm>>>,
) -> bool {
    let Ok(gb) = group.try_borrow() else {
        return false;
    };
    let Ok(Some(mm)) = group_mm(k, &gb) else {
        return false;
    };
    if reaped.iter().any(|m| Rc::ptr_eq(m, &mm)) {
        return true;
    }
    if !will_free_mem(k, &gb) {
        return false;
    }
    drop(gb);
    let mut sharers = Vec::new();
    for g in k.groups.values() {
        if Rc::ptr_eq(g, group) {
            continue;
        }
        let Ok(other) = g.try_borrow() else {
            return false;
        };
        let Ok(other_mm) = group_mm(k, &other) else {
            return false;
        };
        if other_mm.is_some_and(|m| Rc::ptr_eq(&m, &mm)) {
            if !will_free_mem(k, &other) {
                return false;
            }
            sharers.push(g.clone());
        }
    }
    // Sample peak resident memory before releasing private pages so wait's ru_maxrss keeps what
    // each exiting process used.
    {
        let Ok(mm_ref) = mm.try_borrow() else {
            return false;
        };
        if let Ok(mut g) = group.try_borrow_mut() {
            g.sample_rss(&mm_ref);
        } else {
            return false;
        }
        for s in &sharers {
            if let Ok(mut sb) = s.try_borrow_mut() {
                sb.sample_rss(&mm_ref);
            } else {
                return false;
            }
        }
    }
    let released = if let Ok(mut m) = mm.try_borrow_mut() {
        m.release();
        true
    } else {
        false
    };
    if released {
        reaped.push(mm);
    }
    released
}

/// The process picked last time has not finished exiting, and [`VICTIM_TIMEOUT`] has not passed
/// yet.
fn waiting_for_victim(k: &Kernel, now: Instant) -> bool {
    matches!(&k.oom.victim, Some((victim, at))
        if now < *at + VICTIM_TIMEOUT
            && victim.upgrade().is_some_and(|g| !g.borrow().threads.is_empty()))
}

/// Called each time the timer thread wakes up: while some guest thread is running, tears down the
/// pages Tier 1's code cache has written in the writable view once a second, and once more after
/// all threads are waiting, then stops ([`appine_engine::unmap_written_code`]). The code cache is
/// mapped twice for W^X, and the host's RSS counts pages per mapping, so a page touched in both
/// views counts twice: translations count double in the app usage measured above ([`app_memory`]
/// subtracts the ones not torn down yet) and in the RSS the LMK looks at. Tearing down by time
/// rather than by how much was written: JIT workloads backfill links and invalidate blocks in
/// thousands of different pages per second, and after a teardown every write to those pages takes
/// a page fault again. Returns when the next one is due.
pub(crate) fn unmap_code_views(k: &mut Kernel, shared: &Shared) -> Option<Instant> {
    let now = Instant::now();
    if let Some(next) = k.oom.code_views
        && now < next
    {
        return Some(next);
    }
    let idle = all_sleeping(k);
    // Woken by something else after stopping: no thread ran meanwhile, so there are no newly
    // written pages
    if !idle || k.oom.code_views.is_some() {
        appine_engine::unmap_written_code();
    }
    if idle && shared.stop_checks(|| all_sleeping(k)) {
        k.oom.code_views = None;
        return None;
    }
    k.oom.code_views = Some(now + CODE_VIEW_INTERVAL);
    k.oom.code_views
}

/// All guest threads are waiting in the kernel: memory will not grow any more, and the code cache
/// will not be written either.
fn all_sleeping(k: &Kernel) -> bool {
    k.tasks.values().all(|t| t.sleeping.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd::FdTable;
    use crate::mm::{Mm, flags};
    use crate::nsproxy::NsProxy;
    use crate::process::Tier;
    use crate::signal::{AltStack, SigHandlers};
    use crate::task::{FsContext, Task, TaskState};
    use crate::vfs::{INIT_MNT_NS, MntNs, Node};
    use appine_engine::{Cpu, prot};

    /// Creates a synthetic process in `k` with `mm` and a live thread (returns its group, task,
    /// and the `Cpu` whose `Kicker` the task references).
    fn add_process(
        k: &mut Kernel,
        tgid: i32,
        ppid: i32,
        cgroup: u64,
        mm: Rc<RefCell<Mm>>,
    ) -> (Rc<RefCell<ThreadGroup>>, Rc<Task>, Cpu) {
        let sighand = Rc::new(RefCell::new(SigHandlers::default()));
        let mut tg = ThreadGroup::new(tgid, ppid, sighand);
        tg.cgroup = cgroup;
        tg.threads.push(tgid);
        let group = Rc::new(RefCell::new(tg));
        let cpu = unsafe { Cpu::new(mm.borrow().mmu()) };
        let state = TaskState {
            mm: mm.clone(),
            fds: Rc::new(RefCell::new(FdTable::new())),
            fs: Rc::new(RefCell::new(FsContext {
                root: Node::ROOT,
                cwd: Node::ROOT,
                umask: 0o022,
                mnt_ns: Rc::new(MntNs {
                    id: INIT_MNT_NS,
                    owner: crate::cred::UserNs::init(),
                    anon: false,
                }),
            })),
            group: group.clone(),
            vfs: None,
            altstack: AltStack::default(),
            clear_child_tid: 0,
            vfork_done: None,
            restart: None,
            fast_sleep: None,
            sem_undo: Rc::new(crate::ipc::SemUndo::new()),
        };
        let task = Task::new(
            tgid,
            tgid,
            &cpu,
            state,
            NsProxy::init(),
            0,
            *b"oom-test\0\0\0\0\0\0\0\0",
        )
        .unwrap();
        k.groups.insert(tgid, group.clone());
        k.tasks.insert(tgid, task.clone());
        (group, task, cpu)
    }

    /// Maps `pages` of private anonymous RW memory in `mm` and writes `byte` to every page so all
    /// pages are resident.
    fn dirty_anon(mm: &Rc<RefCell<Mm>>, pages: u64, byte: u8) -> u64 {
        let rw = prot::READ | prot::WRITE;
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let addr = mm
            .borrow_mut()
            .mmap(0, pages * PAGE_SIZE, rw, anon, None)
            .unwrap();
        let buf = vec![byte; (pages * PAGE_SIZE) as usize];
        mm.borrow_mut().write_kernel(addr, &buf).unwrap();
        addr
    }

    fn read_byte(mm: &Rc<RefCell<Mm>>, addr: u64) -> u8 {
        let mut b = [0u8; 1];
        mm.borrow()
            .read(crate::uaccess::UserSlice::new(addr, 1), &mut b)
            .unwrap();
        b[0]
    }

    #[test]
    fn oom_reaps_killed_victim_immediately() {
        let mut k = Kernel::new(Tier::Interpreter);
        let mm = Mm::new().into_shared();
        let addr = dirty_anon(&mm, 64, 0x5a);
        assert!(mm.borrow().resident_pages() >= 64);
        let (victim, task, _cpu) = add_process(&mut k, 10, INIT, ROOT, mm.clone());

        out_of_memory(&mut k, (ROOT, 1 << 20, 512 << 10));

        assert!(victim.borrow().exiting.is_some());
        assert!(task.killed.get());
        // Even while the victim's thread stays in k.tasks (stuck in exit), private memory is freed
        // immediately and ru_maxrss keeps the pre-reap peak.
        assert_eq!(mm.borrow().resident_pages(), 0);
        assert!(victim.borrow().maxrss_kb >= 64 * 4);
        assert_eq!(read_byte(&mm, addr), 0);
    }

    #[test]
    fn oom_reaps_already_exiting_victim() {
        let mut k = Kernel::new(Tier::Interpreter);
        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 64, 0x33);
        let (victim, _task, _cpu) = add_process(&mut k, 11, INIT, ROOT, mm.clone());
        victim.borrow_mut().exiting = Some(ExitStatus::Exited(0));

        out_of_memory(&mut k, (ROOT, 1 << 20, 512 << 10));

        assert_eq!(mm.borrow().resident_pages(), 0);
        assert!(victim.borrow().maxrss_kb >= 64 * 4);
        // An already-exiting victim is waited for and reaped without incrementing oom_kill.
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.oom, 1);
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.oom_kill, 0);
    }

    #[test]
    fn oom_does_not_reap_shared_mm_with_live_vfork_sharer() {
        let mut k = Kernel::new(Tier::Interpreter);
        let mm = Mm::new().into_shared();
        let addr = dirty_anon(&mm, 64, 0x42);
        let (parent, _ptask, _pcpu) = add_process(&mut k, 20, INIT, ROOT, mm.clone());
        let (child, ctask, _ccpu) = add_process(&mut k, 21, 20, ROOT, mm.clone());
        child.borrow_mut().parent_thread = 20;
        ctask.vfork.set(true);

        out_of_memory(&mut k, (ROOT, 1 << 20, 512 << 10));

        // Parent is picked and killed (vfork child is skipped), but mm stays intact for child.
        assert!(parent.borrow().exiting.is_some());
        assert!(child.borrow().exiting.is_none());
        assert!(mm.borrow().resident_pages() >= 64);
        assert_eq!(read_byte(&mm, addr), 0x42);
    }

    #[test]
    fn oom_group_kill_reaps_shared_mm_when_all_sharers_killed() {
        let mut k = Kernel::new(Tier::Interpreter);
        let cg = k
            .cgroups
            .mkdir(ROOT, b"grp", &crate::cred::Cred::root(), 0o755)
            .unwrap();
        // Enable memory controller (1 << 3) on root so grp's memory.oom.group is active.
        k.cgroups.map.get_mut(&ROOT).unwrap().subtree_control = 1 << 3;
        k.cgroups
            .map
            .get_mut(&cg)
            .unwrap()
            .values
            .insert(b"memory.oom.group", "1".to_owned());

        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 64, 0x77);
        let (parent, _ptask, _pcpu) = add_process(&mut k, 30, INIT, cg, mm.clone());
        let (child, ctask, _ccpu) = add_process(&mut k, 31, 30, cg, mm.clone());
        child.borrow_mut().parent_thread = 30;
        ctask.vfork.set(true);

        out_of_memory(&mut k, (cg, 1 << 20, 64 << 10));

        assert!(parent.borrow().exiting.is_some());
        assert!(child.borrow().exiting.is_some());
        assert!(parent.borrow().maxrss_kb >= 64 * 4);
        assert!(child.borrow().maxrss_kb >= 64 * 4);
        assert_eq!(mm.borrow().resident_pages(), 0);
    }

    #[test]
    fn oom_skips_reap_for_coredump_partial_single_exit_and_borrowed_mm() {
        // 1. Core dump in progress
        let mut k = Kernel::new(Tier::Interpreter);
        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 32, 0x11);
        let (g, _t, _cpu) = add_process(&mut k, 40, INIT, ROOT, mm.clone());
        {
            let mut gb = g.borrow_mut();
            gb.exiting = Some(ExitStatus::Signaled {
                signal: Signal::SEGV,
                pc: None,
                fault_addr: None,
                core_dumped: true,
            });
            gb.core = Some(Vec::new());
        }
        let mut reaped = Vec::new();
        assert!(!reap(&k, &g, &mut reaped));
        assert!(mm.borrow().resident_pages() >= 32);

        // 2. Partial single-thread exit(2) with another live thread
        {
            let mut gb = g.borrow_mut();
            gb.core = None;
            gb.single_exit = true;
            gb.threads.push(41);
        }
        assert!(!reap(&k, &g, &mut reaped));
        assert!(mm.borrow().resident_pages() >= 32);

        // 3. Borrowed Mm is skipped without panicking
        {
            let mut gb = g.borrow_mut();
            gb.single_exit = false;
            gb.threads.truncate(1);
        }
        {
            let _held = mm.borrow();
            assert!(!reap(&k, &g, &mut reaped));
        }
        // Once unborrowed, reaping succeeds
        assert!(reap(&k, &g, &mut reaped));
        assert_eq!(mm.borrow().resident_pages(), 0);
    }

    #[test]
    fn measure_root_trims_only_over_limit_and_avoids_kill_when_reclaimed() {
        let oom = Oom::default();
        let trimmed = Cell::new(0u32);
        // Under limit: trim is not called
        let got = measure_root(&oom, 100, || Some(80), || trimmed.set(trimmed.get() + 1));
        assert_eq!(got, Some(80));
        assert_eq!(trimmed.get(), 0);
        assert_eq!(oom.peak.get(), 80);

        // Over limit, trim brings usage below limit
        let used = Cell::new(140u64);
        let got = measure_root(
            &oom,
            100,
            || Some(used.get()),
            || {
                trimmed.set(trimmed.get() + 1);
                used.set(90);
            },
        );
        assert_eq!(got, Some(90));
        assert_eq!(trimmed.get(), 1);
        assert_eq!(oom.peak.get(), 140);

        // Over limit, trim leaves usage still above limit
        used.set(160);
        let got = measure_root(
            &oom,
            100,
            || Some(used.get()),
            || {
                trimmed.set(trimmed.get() + 1);
                used.set(120);
            },
        );
        assert_eq!(got, Some(120));
        assert_eq!(trimmed.get(), 2);
        assert_eq!(oom.peak.get(), 160);

        // A failed post-reclaim read leaves the original over-limit sample in force.
        let reading = Cell::new(Some(180));
        assert_eq!(
            measure_root(&oom, 100, || reading.get(), || reading.set(None)),
            Some(180)
        );
        assert_eq!(oom.peak.get(), 180);
    }

    // Root footprint and the DBT caches are process-wide. Run each real-pressure measurement
    // alone so unrelated kernel tests cannot trigger a kill or discard its written aliases.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    fn isolated_pressure_test() -> bool {
        if std::env::var_os("APPINE_TEST_OOM_CHILD").is_some() {
            return true;
        }
        let thread = std::thread::current();
        let name = thread.name().unwrap();
        assert!(name.starts_with("oom::tests::"));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name])
            .env("APPINE_TEST_OOM_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        false
    }

    #[test]
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    fn oom_check_trims_real_dbt_pool_under_root_pressure() {
        use appine_engine::{Dbt, DbtRegs, DbtSpace, Mmu};

        if !isolated_pressure_test() {
            return;
        }
        let shared = Shared::new(Kernel::new(Tier::Dbt));
        let mut k = shared.lock();
        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 4, 0xaa);
        let (victim, _task, _cpu) = add_process(&mut k, 50, INIT, ROOT, mm.clone());

        // Start from a clean pool so we can observe real pooled DBT memory being reclaimed.
        appine_engine::trim_dbt_pool();
        let baseline = footprint().expect("footprint readable on Linux");

        // Populate the DBT pool with keyed instances containing translated blocks: each distinct
        // key keeps its code cache + translation tables in the pool when dropped.
        let mut mmu = Mmu::new();
        let code_len = 16 * PAGE_SIZE as usize;
        let code = appine_hal::map_anonymous(code_len, false).unwrap();
        // Fill 16 pages of `add x0, x0, #1` ending in `svc #0` so Tier 1 translates many blocks.
        let words =
            unsafe { std::slice::from_raw_parts_mut(code.as_ptr().cast::<u32>(), code_len / 4) };
        let n = words.len();
        for w in &mut words[..n - 1] {
            *w = 0x9100_0400; // add x0, x0, #1
        }
        words[n - 1] = 0xd400_0001; // svc #0
        let gva = 0x40_0000u64;
        unsafe {
            mmu.map(gva, code, code_len as u64, prot::READ | prot::EXEC)
                .unwrap();
        }
        for key in 1u64..=8 {
            let space = DbtSpace::new(key, DbtRegs::Default).unwrap();
            let mut dbt = Dbt::attach(&space, 0).unwrap();
            let mut cpu = unsafe { Cpu::new(&mmu) };
            cpu.state_mut().pc = gva;
            let _ = dbt.run(&mut cpu);
            drop(dbt);
            drop(space);
        }
        unsafe { appine_hal::unmap(code, code_len) };

        let with_pool = footprint().unwrap();
        assert!(
            with_pool > baseline,
            "pooled DBT instances should increase footprint: baseline={baseline}, with_pool={with_pool}"
        );

        // Set the limit halfway into the measured pool growth. Reclaim should spare the guest.
        let limit = baseline + (with_pool - baseline) / 2;
        k.oom.limit = limit;

        let _ = check(&mut k, &shared);

        let after = footprint().unwrap();
        assert!(
            after <= limit,
            "trim_dbt_pool during oom::check should drop footprint below limit: \
             baseline={baseline}, with_pool={with_pool}, limit={limit}, after={after}"
        );
        assert!(
            victim.borrow().exiting.is_none(),
            "guest process must not be killed when DBT pool trimming restores headroom"
        );
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.oom, 0);
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.oom_kill, 0);
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fn root_pressure_reclaims_idle_dbt_memory_of_a_live_guest() {
        use appine_engine::{Dbt, Exit};

        if !isolated_pressure_test() {
            return;
        }
        let shared = Shared::new(Kernel::new(Tier::Dbt));
        let mut k = shared.lock();
        let mm = Mm::new().into_shared();
        let (guest, _task, mut cpu) = add_process(&mut k, 50, INIT, ROOT, mm.clone());
        let pages = 512;
        let start = mm
            .borrow_mut()
            .mmap(
                0,
                pages * PAGE_SIZE,
                prot::READ | prot::EXEC,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        let mut code = 0x9100_0400u32.to_le_bytes().repeat(PAGE_SIZE as usize / 4); // add x0, x0, #1
        code[PAGE_SIZE as usize - 4..].copy_from_slice(&0xd400_0001u32.to_le_bytes()); // svc #0
        let space = mm.borrow_mut().code_space(&k.code_groups).unwrap();
        let mut threads: Vec<_> = (0..8)
            .map(|_| Dbt::attach(&space.space, space.tag).unwrap())
            .collect();
        let mut run = |dbt: &mut Dbt, pc| {
            cpu.state_mut().pc = pc;
            cpu.state_mut().x[0] = 1;
            assert!(matches!(dbt.run(&mut cpu), Exit::Svc { imm: 0 }));
            assert_eq!(cpu.state().x[0], PAGE_SIZE / 4);
        };
        for page in 0..pages {
            let pc = start + page * PAGE_SIZE;
            mm.borrow_mut().write_kernel(pc, &code).unwrap();
            run(&mut threads[page as usize % 8], pc);
        }
        drop(threads);
        assert!(appine_engine::written_code_bytes() > 0);
        // Only the guest's live instance exists. Templates account for over 4 MiB. Releasing
        // eight detached threads also unmaps at least their eight 64 KiB jump caches.
        let virtual_bytes = || {
            let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
            statm
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                * appine_hal::page_size()
        };
        let mapped = virtual_bytes();
        k.oom.limit = footprint().unwrap() - (2 << 20);
        check(&mut k, &shared);
        assert_eq!(appine_engine::written_code_bytes(), 0);
        assert!(virtual_bytes() + 8 * 64 * 1024 <= mapped);
        let after = footprint().unwrap();
        assert!(
            after <= k.oom.limit,
            "footprint {after} exceeds {}",
            k.oom.limit
        );
        assert!(guest.borrow().exiting.is_none());
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.oom_kill, 0);

        let mut live = Dbt::attach(&space.space, space.tag).unwrap();
        run(&mut live, start);
        assert_eq!(live.stats().blocks, 0);
        let mut fresh = Dbt::new().unwrap();
        run(&mut fresh, start);
        assert!(fresh.stats().blocks > 0);
        assert_eq!(fresh.stats().blocks_shared, 0);
    }

    #[test]
    fn oom_badness_includes_pgtables_and_log_reports_real_pgtables() {
        let mut k = Kernel::new(Tier::Interpreter);
        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 8, 0x22);
        let expected_pgtables_pages = mm.borrow().pgtables_pages();
        let expected_pgtables_kb = mm.borrow().pgtables_bytes() / 1024;
        assert!(expected_pgtables_pages >= 4);

        let (victim, _task, _cpu) = add_process(&mut k, 60, INIT, ROOT, mm.clone());
        let (points, rss) = badness_with(&k, &victim.borrow(), 100_000, SwapContext::Zero).unwrap();
        assert_eq!(points, (rss + expected_pgtables_pages) as i64);

        out_of_memory(&mut k, (ROOT, 1 << 20, 64 << 10));
        let log = String::from_utf8(k.klog.borrow_mut().read_all(4096, false)).unwrap();
        let needle = format!("pgtables:{expected_pgtables_kb}kB");
        assert!(
            log.contains(&needle),
            "expected OOM kill log to contain {needle}, got:\n{log}"
        );
    }

    #[test]
    fn fallback_swap_estimation_safety_and_proportional_bounds() {
        // 1. Pure proportional bound properties
        assert_eq!(estimate_swap_share(100, 100, 0), 0);
        assert_eq!(estimate_swap_share(0, 100, 50), 0);
        assert_eq!(estimate_swap_share(30, 50, 100), 30);
        assert_eq!(estimate_swap_share(20, 50, 100), 20);
        // When total candidates exceed host VmSwap, shares scale proportionally and sum <= host_swap.
        let s1 = estimate_swap_share(300, 400, 100);
        let s2 = estimate_swap_share(100, 400, 100);
        assert_eq!((s1, s2), (75, 25));
        assert!(s1 + s2 <= 100);

        // 2. End-to-end victim selection with fallback swap attribution:
        //    - Process A maps 128 pages of private anon RW (eagerly mapped soft PTEs, untouched on
        //      host so mincore reports non-resident, simulating swapped-out pages).
        //    - Process B dirties 16 pages (resident) and calls MADV_DONTNEED on another 128 pages
        //      (must NOT count as swapped!).
        //    - With host_swap == 0, B beats A.
        //    - With host_swap == 128 pages, A beats B because A gets attributed the host swap
        //      while B's MADV_DONTNEED pages contribute 0 candidates.
        let mut k = Kernel::new(Tier::Interpreter);
        let rw = prot::READ | prot::WRITE;
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;

        let mm_a = Mm::new().into_shared();
        let a = mm_a
            .borrow_mut()
            .mmap(0, 128 * PAGE_SIZE, rw, anon, None)
            .unwrap();
        // Admit the first write without executing the retried store. The VMA can now
        // contribute candidates while all its host pages are still nonresident.
        assert!(mm_a.borrow().fault_in(a, prot::WRITE));
        assert_eq!(mm_a.borrow().resident_pages(), 0);
        assert_eq!(mm_a.borrow().swappable_nonresident_pages(), 128);

        let mm_b = Mm::new().into_shared();
        let _b_res = dirty_anon(&mm_b, 16, 0x11);
        let b_disc = dirty_anon(&mm_b, 128, 0x22);
        let (_, res) = mm_b
            .borrow_mut()
            .discard_range(b_disc, 128 * PAGE_SIZE, false);
        res.unwrap();
        assert_eq!(mm_b.borrow().swappable_nonresident_pages(), 0);

        let (proc_a, _ta, _ca) = add_process(&mut k, 70, INIT, ROOT, mm_a);
        let (proc_b, _tb, _cb) = add_process(&mut k, 71, INIT, ROOT, mm_b);

        // Host VmSwap == 0 -> fallback attributes 0 swap -> resident B wins over non-resident A.
        let ctx_zero = fallback_swap_context(&k, 0);
        assert_eq!(ctx_zero, SwapContext::Zero);
        let (picked_zero, _) = select_with(&k, &[], (ROOT, 1 << 30), ctx_zero).unwrap();
        assert!(Rc::ptr_eq(&picked_zero, &proc_b));

        // Host VmSwap == 128 pages -> A receives full attribution (B's MADV_DONTNEED is 0) -> A wins.
        let ctx_swap = fallback_swap_context(&k, 128);
        assert_eq!(
            ctx_swap,
            SwapContext::Fallback {
                host_swap_pages: 128,
                total_cand: 128,
            }
        );
        let (picked_swap, _) = select_with(&k, &[], (ROOT, 1 << 30), ctx_swap).unwrap();
        assert!(Rc::ptr_eq(&picked_swap, &proc_a));
    }

    #[test]
    fn memory_high_records_event_reclaims_and_does_not_kill() {
        let shared = Shared::new(Kernel::new(Tier::Interpreter));
        let mut k = shared.lock();
        let cg = k
            .cgroups
            .mkdir(ROOT, b"high_cg", &crate::cred::Cred::root(), 0o755)
            .unwrap();
        // Enable memory controller (1 << 3) on root.
        k.cgroups.map.get_mut(&ROOT).unwrap().subtree_control = 1 << 3;
        k.cgroups
            .map
            .get_mut(&cg)
            .unwrap()
            .values
            .insert(b"memory.high", (16 * PAGE_SIZE).to_string());

        let mm = Mm::new().into_shared();
        let _addr = dirty_anon(&mm, 32, 0x3c);
        let (proc_g, _task, _cpu) = add_process(&mut k, 80, INIT, cg, mm.clone());

        let next = check(&mut k, &shared);
        assert!(next.is_some());
        assert!(
            proc_g.borrow().exiting.is_none(),
            "memory.high must not OOM-kill processes"
        );
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events.high, 1);
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events_local.high, 1);
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events.high, 1);
        assert_eq!(k.cgroups.get(ROOT).unwrap().mem_events_local.high, 0);
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events.oom, 0);

        // Steady usage on the next check does not spam `high` events.
        k.oom.recheck();
        let _ = check(&mut k, &shared);
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events.high, 1);

        // Growing further above memory.high records another `high` event.
        let _more = dirty_anon(&mm, 16, 0x4d);
        k.oom.recheck();
        let _ = check(&mut k, &shared);
        assert_eq!(k.cgroups.get(cg).unwrap().mem_events.high, 2);
        assert!(proc_g.borrow().exiting.is_none());
    }
}
