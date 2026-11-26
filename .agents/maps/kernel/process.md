# kernel/process Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/process.md` for the paired decision history (it still holds the decisions on execve, namespaces, futexes, time, boot, and bug containment / the BKL watchdog made before they were split out into `kernel/exec`, `kernel/ns`, `kernel/futex`, `kernel/time`, `kernel/boot` and `kernel/bug`).
>
> Verified: 2026-11-10 (full mapping: 6 research concerns; 18 claims checked by 3 independent verifiers — 10 confirmed and 8 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: reap dead IPC namespaces in post-syscall sweeps, after exit mount collection, and on BKL release)

## Responsibilities

`kernel/process` runs guest threads and processes inside the app's single host process: task/group
lifecycle (`clone`/`clone3`, run loop, exit, reaping, `wait`, process groups/sessions, pidfds), the
BKL and borrow checks, syscall dispatch hooks, the no-BKL fast path, unified wait/wake-up,
host-facing `Machine` process stats/signals/waits, scheduling parameters on host threads, and the
remaining process-wide calls in `syscall/misc.rs` (CPU accounting, rusage/rlimits, host/domain
names, sysinfo, getcpu, getrandom).

Root: `core/kernel/src/task.rs`, `process.rs`, `kernel.rs` (excluding `kernel/boot`'s `INIT`,
`kernel/time`'s `stop_checks`/`resume_checks`, and `kernel/bug`'s `Hold`/`HoldSample`/`Entry`/
`Doing`/`doing`/`done`), `cell.rs`, `syscall/proc.rs` (excluding execve/unshare), `syscall/fast.rs`
(excluding futex), `machine.rs` (excluding `kernel/boot`'s lifecycle, `kernel/time`'s `timers`,
`kernel/bug`'s `take_kills`/`stall`), `syscall/sched.rs`, `syscall/mod.rs` dispatcher (excluding
`kernel/signal`'s restart/ENOSYS, `kernel/time`'s time helpers, `kernel/bug`'s `TEST_SYSCALL`), and
`syscall/misc.rs`'s remaining process-wide calls (excluding `kernel/time`, `kernel/boot`,
`kernel/signal`, `kernel/futex`, `kernel/ns`; membarrier/umask/cap-seccomp prctls live in
`kernel/mmu`/`kernel/vfs`/`kernel/cred`).

Outside the module: `kernel/bug`, `kernel/time`, `kernel/boot`, `kernel/exec`, `kernel/ns`,
`kernel/futex`, `kernel/mm`, `kernel/cow`, `kernel/hostmem`, `engine`, `engine/dbt`, `kernel/signal`,
`kernel/ptrace`, `kernel/cred`, `kernel/mount`, `kernel/netns`, `kernel/cgroup`, `kernel/procfs`
and `kernel/oom`.

## Key types

### Tasks and processes

- `Task` — per-thread state: `tid` (`Cell`, changed by non-leader execve), unique serial, creds,
  `killed`/`frozen`/`pdeathsig`/exit status/`vfork`/`syscall` (`SYSCALLS` seq + nr), CPU/ctx-switch
  bases + host tid, scheduling params (nice/policy/deadline/uclamp/timer-slack/affinity/ioprio),
  wake `event`/`sleeping`, `pid_ns_children`/`NsProxy`, `TaskRes` (procfs snapshot of mm/fds/fs),
  and thread-private `TaskState` (mm, fds, `FsContext`, group, `sem_undo`, altstack,
  `clear_child_tid`, vfork completion, restart block, `fast_sleep`).
- `TaskSync` — lock-free `in_guest` flag, engine `Kicker` (`kernel/mmu` shootdowns), and atomic
  `KernelEntry` (last syscall nr or -1, x0–x5, sp, pc; read by `/proc/<pid>/syscall`).
- `ThreadGroup` — one process: tgid, ppid, `parent_thread` (the creating thread, Linux
  `real_parent`), pgid, sid, live `threads` (leader first while alive), `children` (zombies
  included), `exiting` / `leader_status` / `zombie` / `leader_exit`, `exit_signal`, own and
  children's CPU time and max RSS, `child_subreaper`, rlimits, the main thread's credentials (what
  other processes go by, kept after it ends), pid namespace, cgroup, tracers of its exit, AIO,
  controlling terminal and `tty_old_pgrp`, timers.
- Default rlimits: stack 8 MB (hard unlimited), core 0, open files 1024/4096, memlock 8 MB, nproc
  half of threads-max, pending signals 16384, message queues 819200 (charged on queue creation by `kernel/ipc`), nice and
  real-time priority 0, the rest unlimited.
- `ExitStatus` — exited with a code or killed by a signal (with pc, fault address, core dump);
  encoded for wait.
- `CpuTime` — total nanoseconds from the host thread CPU clock and system nanoseconds from
  `getrusage` (the calling thread) or the host's `/proc` (another thread), each kept monotonic.
- `task::pool` — pooled host threads (at most 8 idle, kept 5 s; work handed out under the BKL
  starts after it is released).
- `Kernel` — BKL-guarded global state (tasks, groups, waiters, pid allocator, namespaces, init,
  power, watched processes, `kernel/bug` kill reports); `Shared` — BKL mutex, `Hold`/spinner/stall
  (`kernel/bug`), fast-path epoch, futex lock/queue, timer event, DNS answers, idle-check flag;
  `Bkl` — lock guard running release-time work on `Drop`; `Cx` — syscall/signal context holding `Bkl`.

### Waiting and the fast path

- `wake` channels: `FILE`, `OTHER`, `CHILD`, `WATCHED`, `EXITED`, `LOCK`, `SIGNAL` (plus the
  internal `OBJECTS`); `wake::Object` is the address of a value (inside a `RefCell`, or a plain
  counter).
- Waiter — (event, interest channels, optional sorted object list), stored in `Kernel::waiters`.
- `fast::Fast` — a thread's fast-path record (epoch, tracing, resolved root and cwd, tid, CPU-clock
  base, address-space id and its shared writable mappings, vDSO address, time-namespace offsets).

## Public entry points

- **Syscalls**: `clone` (220), `clone3`, `exit`, `exit_group`, `set_tid_address`, `wait4`, `waitid`,
  `getpriority`/`setpriority`, `ioprio_*`, `sched_*`, `setsid`/`setpgid`/`getpgid`/`getsid`,
  `pidfd_open`/`pidfd_getfd`, `kcmp`, `prctl` (`PDEATHSIG`, `CHILD_SUBREAPER`), `times`, `getrusage`,
  `prlimit`, `personality`, `sethostname`/`setdomainname`, `getcpu`, `sysinfo`, `getrandom`.
- **Internal & host (`Machine`)**: `task::start`, `thread_main` → `run` → `exit`, `finish_group`,
  `Shared::lock`, `block`/`block_for`, `Cx::wait*`/`unlocked`, `request_wake*`,
  `signal_later`/`flush_signals`, `Shared::fast_changed`; `Machine::{processes, cpu_time_ns, rootfs_stats, wait,
  try_wait, wait_or_power, signal}` (lifecycle in `kernel/boot`; `take_kills`/`stall` in
  `kernel/bug`); procfs `threads-max`, `/proc/<pid>/task/<tid>/children`.

## Data flow / lifecycle

### Tasks and host threads

- `Machine::cpu_time_ns` sums `Kernel.cpu.total_ns` (exited) and live tasks' `cpu_ns` under the BKL
  without `/proc` or hot-loop instrumentation (UI/timer CPU excluded; exit-stage panics can skip
  credit, so callers compare deltas).
- `Machine::rootfs_stats` samples store and overlay paths under one BKL hold without clearing
  mount expiry marks. It follows symlinks, reports missing paths separately and returns an
  error when guest-only filesystem state is needed.
- Each guest thread runs on its own host pthread, scheduled by the host kernel. A finished thread's
  host thread is pooled (at most 8 idle, 5 s) and its engine CPU state goes to the engine's spare
  list (up to 8), so creating threads rarely creates host threads.
- A thread starting on a host thread records the host CPU-clock, system-time and context-switch
  bases and its host tid, and re-applies its nice and I/O priority, and its affinity when that is
  restricted or the host thread was reused.

### clone

- Global ids come from `alloc_tid`: the numbers after the last one, up to `PID_MAX - 1`, then from
  300 again (Linux's `RESERVED_PIDS`); `PID_MAX` itself is never handed out, and `ns_last_pid`
  writes move the start (the global one at level 0, else the namespace's own).
- `clone` takes the low 32 bits of the flags (`CLONE_PIDFD` with `CLONE_PARENT_SETTID` is
  `EINVAL`, as the pidfd shares that slot); `clone3` refuses a size below 64 (`EINVAL`), above a
  page or with a non-zero tail (`E2BIG`), unknown flags, `CLONE_DETACHED`, exit signals above 64 or
  with `CLONE_THREAD`/`CLONE_PARENT`, a stack without a size, and bad `set_tid` or cgroup
  arguments. There are no separate fork or vfork syscalls on aarch64.
- Invalid combinations are `EINVAL` (a thread without shared signal handlers, shared handlers
  without shared memory, `CLONE_PIDFD` with a thread or `CLONE_DETACHED`, `CLONE_PARENT` from a
  pid-namespace init, a thread with `CLONE_NEWPID` or another pid namespace for children,
  `CLONE_NEWIPC` with `CLONE_SYSVSEM`, `CLONE_NEWNS` or `CLONE_NEWUSER` with a shared fs,
  `CLONE_NEWUSER` with a thread); a thread put into another cgroup is `EOPNOTSUPP`.
- Limits: `RLIMIT_NPROC` counts live threads per kernel real uid across all user namespaces (not
  for real uid 0 or with `CAP_SYS_RESOURCE`/`CAP_SYS_ADMIN`); `threads-max` applies to root too
  (`EAGAIN`) and counts live tasks only (default: physical memory in MB, at most half the host fd
  limit, at least 20, 4096 if memory is unknown; writable in 20..=0x3fffffff); the cgroup
  `pids.max` and freezer are checked; then a pid is chosen. Host-launched processes
  (`Machine::spawn`) are a trusted path and skip these limits.
- The child's address space is shared (`CLONE_VM`) or quiesced and forked (`kernel/cow`); fds and fs
  are shared or copied. A new process gets `ppid` and `parent_thread` from the caller (or the
  caller's parent with `CLONE_PARENT`, which also gives it the caller's process's exit signal, as
  Linux's `copy_process` does). A fresh CPU state copies the parent's registers (x0 = 0), the new
  stack and TLS; a `CLONE_VM` thread that is not a vfork child gets no alternate stack. The task
  inherits the creator's signal mask, comm, credentials, scheduling, seccomp and ptrace options.
- Registration: the pid is registered (in every pid-namespace level), the parent/child tid and
  pidfd are written, then `task::start` queues the host thread and inserts the task into the group,
  the address space's users and the kernel's task table (the thread runs once the BKL is
  released); a failure releases the pid and the pidfd. Then the group is registered with its
  parent, the ptrace fork event reported and, for vfork, the parent waits (interest none) until the
  child execs or exits, or it is killed; until the completion is signalled (`release_mm`, at
  execve or exit) the child's `Task::vfork` is set, so the OOM killer can pass it over
  (`kernel/mm`). The waiting parent counts as frozen for `cgroup.events` (`Task::frozen`, as
  Linux's `wait_for_vfork_done`), and stays counted after the wait while its cgroup is freezing,
  until it stops on the way out (`kernel/cgroup`).

### Run loop

- Each pass: resume periodic checks, mark in-guest (clearing `KernelEntry`, recorded on every exit
  before the fast path), handle generation changes (re-attach DBT on code-space change, flush TLB,
  invalidate translations), then execute via `Cpu::step` (single-step), `engine/dbt` (attached, no
  HW breakpoints), or `Cpu::run` (`engine`).
- `Svc` tries the fast path unlocked first; all other exits record `Entry` for `kernel/bug`, take
  the BKL, and dispatch: killed exits, code invalidations, syscalls, kicks (signals), undef
  (`SIGILL`), breakpoints/watchpoints (`SIGTRAP`), alignment (`SIGBUS`), host faults/panics
  (`kernel/bug` kills process), and page faults (`kernel/mm`: CoW break, already present, fault in,
  FUSE fill, past-EOF `SIGBUS`/remap, stack growth, else `SIGSEGV`).
- The result (`Continue`, `Exec`, `Exit`) decides the next step; `Exec` re-attaches the translator
  for the new address space. After each BKL-path handling the fast-path record is rebuilt if the
  epoch moved. On `Exit`, still under the BKL, the last thread using its fd table flushes the FUSE
  files in it (`kernel/fuse`) before `task::exit` drops the table.

### Syscall dispatch

- Under the BKL: the ptrace entry stop and seccomp, pid arguments translated into global pids
  (invisible ones become "no pid"), a fresh FUSE token, the buffers of read, write, pread64,
  pwrite64 and the vector forms read into FUSE mappings (`kernel/fuse`'s `prefault`, since those
  consume input before copying), then the handler. A handler failing with the internal
  `FUSE_RETRY` (a walk needed a FUSE daemon's reply, or a copy met a page of a FUSE mapping not yet
  read, `kernel/mm`'s `Fill`) makes the dispatcher ask for it with the BKL released and run the
  handler again from the start, at most 16384 times (then `EIO`); a page that cannot be read ends
  the syscall with `EFAULT` (`ERESTARTSYS` when a signal took the read back). ptrace's stops and
  seccomp see one syscall.
- From the token until the sweeps the thread records the syscall in `Task::syscall`
  (`InSyscall`, numbered by the global `SYSCALLS` count, cleared on every way out), so the overlay
  sweep can tell which syscalls began before a removal.
- After the handler: released FUSE files are flushed, deferred AF_UNIX cycle collection runs
  (`unix::collect_deferred`), removed FUSE mappings complete writeback and the node cache may be swept
  (`kernel/fuse`'s `sweep`), detached mounts whose last use the syscall let go of are collected,
  dead IPC namespaces are reaped (`Kernel::collect_ipc`), removed overlay nodes are swept
  (`kernel/overlay`), and pending cgroup2 file changes checked
  (`cgroup::notify_changes`, also run at thread exit, freezer stops and by the timer thread); then
  results are translated out (invisible pids become 0), edge-triggered readiness is re-armed after
  reads, x0 is set, `Mm::sync` runs, then the exit stop and signal delivery. A successful `execve`
  or `execveat` runs the sweeps, drops `InSyscall`, and runs `Mm::sync` on the new address space
  before `exec_done`. `exit`, `exit_group` and `rt_sigreturn` return before the sweeps and
  `Mm::sync`.
- A guest page fault on a FUSE mapping's page not yet read reads it with the BKL released before
  re-executing (`kernel/mm`'s fault order).

### Exit and reaping

- `exit` sets the thread's status (the leader's also records `leader_status`); `exit_group` and
  fatal signals set the group's `exiting` status once, mark every thread killed and wake them.
  Before any `PTRACE_EVENT_EXIT`, `begin_exit` (idempotent) makes the last thread to start exiting
  fill in the group status (Linux 6.1 `synchronize_group_exit`).
- `task::exit` runs in `bug::catch`-contained stages (`kernel/bug`): core-dump regs, stats/CPU time,
  `leader_exit`, last-thread RSS sample, `release_mm` (robust list, shared-mm `clear_child_tid` wake,
  vfork completion, leave mm users; on panic vfork completion and user removal re-run idempotently
  before killing the process), ptrace/seccomp cleanup, shared FUSE mapping writeback, task/pid removal, `futex::pi_owners_exited`,
  SysV shm reap (`kernel/ipc`), non-last thread `sem_undo` release (if last holder) and child
  handoff (`pdeathsig`) + signal retargeting or last-thread `finish_group`, mqueue notification
  flush, namespace reset/drop under BKL, FUSE flush, unix-GC (when `last || fds_gone ||
  unix::take_deferred()`), mount collection (`collect_unused`), IPC collection (`collect_ipc`),
  cgroup change checks, and `EXITED` wake; CPU
  state frees after BKL release.
- `finish_group`, each step contained: release AIO; reparent children to the nearest
  `PR_SET_CHILD_SUBREAPER` ancestor in the same pid-namespace level that still has live threads
  (one in the middle of exiting can be chosen, as on Linux), else the pid-namespace init while it
  has not exited and the namespace is not dead, else the virtual init (children get `exit_signal =
  SIGCHLD`; zombies handed to the virtual init are freed at once, others reported to their new
  parent, and zombies still held for a tracer keep their pending wait); send `PR_SET_PDEATHSIG` signals (keyed to the creating thread); release SysV IPC and,
  for a session leader, the controlling terminal (`kernel/tty`).
- When a pid-namespace init exits, the namespace is marked dead (registering a pid in it is then
  `ENOMEM`) and every other member gets `SIGKILL`; the init's own children, and the orphans other
  members leave while they die (unless a live subreaper in the level takes them), go to the
  virtual init, which frees them at once, as Linux's exiting init reaps them, and its exit is
  reported only once all other members are reaped (it stays registered meanwhile).
- Reporting: the status is `exiting` or the leader's; it is reported to a tracer or the parent (a
  process traced by another process is held as a zombie for the tracer and handed to its parent
  once the tracer takes it). When the tracer itself adopts a pending zombie, its ordinary wait
  consumes the already reported exit once. Children of a missing parent or virtual init are reaped
  immediately. An untraced `SIGCHLD` child is also reaped for explicit `SIG_IGN` or `SA_NOCLDWAIT`.
  Explicit ignore suppresses the exit notification, while `SA_NOCLDWAIT` alone still sends it.
  Other children remain waitable and notify their parent when their exit signal is nonzero. Orphaned process
  groups with a stopped member get SIGHUP/SIGCONT. A `CHILD` wake follows (`WATCHED` too for a
  process the host watches).
- `wait4`/`waitid` (option checks; `waitid` takes `P_PIDFD`, where a reaped process is `ECHILD`
  and a nonblocking pidfd without `WNOHANG` `EAGAIN`, and `WNOWAIT`) scan `children` (filtered by
  the target and `__WNOTHREAD`, and by exit signal as Linux's `eligible_child`: without `__WALL`,
  only children reporting with `SIGCHLD`, or with `__WCLONE` only the others; a child the caller
  traces always counts): a zombie is reaped (its CPU time and max RSS added to the waiter's
  children totals; one whose exit a tracer has yet to take counts for any wait but is not shown),
  then stop and
  continue reports, then tracees; nothing matching is `ECHILD`, and a zombie counts only for a wait
  that takes exits (so waiting for stops and continues of children that have all exited is
  `ECHILD`); otherwise the waiter blocks on `CHILD` and restarts if interrupted.
  After selecting an event, wait4 and waitid retain the result while filling cold FUSE output
  pages. A failed result copy returns `EFAULT` after any requested event consumption.
- An exited leader keeps its tgid registered until the group is reaped. Its task leaves the task
  table like any thread, but the group records its name and own CPU time (`leader_exit`, cleared
  when a non-main thread's execve takes the tgid), and procfs shows it as a zombie thread until
  the group is reaped, as Linux keeps the leader as a zombie task.

### The BKL

- One mutex over `Kernel`. Kernel objects are shared with `Rc` and the kernel's own `RefCell`; their
  counts and borrow flags are not atomic, so even cloning or dropping them needs the BKL.
- Held: for every guest exit except fast-path syscalls (syscalls, faults, kicks, signal
  delivery), by the timer thread while it works, and by host-facing `Machine` calls. Not held while
  running guest code.
- Released inside a syscall only by the wait primitives and `Cx::unlocked`, whose closure must be
  `Send` and so cannot touch kernel objects. Uses of `unlocked`: host fd and host stdio I/O,
  regular-file reads and writes other than `O_APPEND` writes (calls without an explicit offset
  one per open file at a time, like `f_pos_lock`), fsync, sync and syncfs (the store's WAL wait
  included) and `O_SYNC`/`O_DSYNC` write syncs, `sync_file_range`, `MS_SYNC` msync,
  copy_file_range/sendfile copies between regular files, giving a held store file an object of
  its own, the execve image build, `sched_yield` when the fast path cannot take it, and a test
  hook. A guard re-takes the BKL
  on return and on unwinding.
- Acquisition: try once; otherwise up to half the host CPUs (1 to 4) spin for at most about 30 µs,
  reading only the `held` flag; the rest sleep on the mutex (a poisoned one is accepted). The new
  holder sets `held`, updates `Hold` (`kernel/bug`, relaxed same-cache-line stores, no clock read),
  marks BKL ownership and defers host unmaps (`kernel/hostmem`).
- Release (`Drop for Bkl`), in order: hang up closed terminals (contained), reap any dead IPC
  namespaces (`collect_ipc`, contained), match pending wake
  requests against waiters (inside `bug::catch`; on panic, wakes all waiters directly so the BKL is
  always unlocked), clear `held`, unlock, clear the thread's held marker, notify pooled
  host threads, signal the matched events, release deferred host memory and refill fork spares
  (`kernel/hostmem`).
- Waits outside a syscall context (the timer thread, `Machine::wait_*`, the terminal bridge) call
  `block`/`block_for` directly; they hold no kernel objects while the BKL is released.
- Borrow checks: the kernel's `RefCell` counts borrows per thread; every `block_for` (also the
  timer thread's and host waits) and `Cx::unlocked` assert the count is zero. Always on in debug
  builds; in release builds with the `borrow-check` feature (enabled for `appine-run` and the debug
  app). The inode store also checks that its owning kernel's BKL is held.

### Fast path (`syscall::fast`)

- Without the BKL, a thread can run `futex` (WAIT, WAKE and the BITSET forms with a non-zero
  bitset, `FUTEX_CLOCK_REALTIME` only with WAIT_BITSET, on a 4-byte-aligned address that
  translates writable and is not in a shared mapping that may be written), `nanosleep`,
  `clock_nanosleep` (REALTIME, MONOTONIC, BOOTTIME), `clock_gettime` (host clocks with time-ns
  offsets, or own CPU clock by namespace tid), `clock_getres`, `gettimeofday`, `sched_yield`
  (yields the host thread, not counted as running guest code meanwhile), and `newfstatat`/`statx`
  (absolute or `AT_FDCWD`-relative paths, when the root is the root mount's store directory, the
  root mount is usable, the walk stays in the store's metadata cache and crosses no other mount,
  and the credentials can skip search-permission checks).
- It is off while strace-tracing, under `PTRACE_SYSCALL`, single-stepping, or with a pending
  `ivau_page`; with seccomp only for numbers the filter always allows, and for the vDSO stubs'
  reads of clocks Linux's vDSO reads in user space (`kernel/vdso`).
- The per-thread record is built under the BKL and rebuilt when a global epoch moves, bumped by
  `fast_changed` (chdir, chroot, credential and fs changes, mounts, setns, execve, time-namespace
  entry); a call that cannot complete falls back to the BKL path (writes to guest memory it made
  stay). Panics kill the process (`kernel/bug`).
- Fast futex (`kernel/futex`) shares the BKL queue/lock; wakes flush immediately. Early-woken timed
  waits (`futex`, `nanosleep`, `clock_nanosleep`) pass their deadline in `fast_sleep` so BKL
  fallback reuses it (and computes remaining time) without re-reading guest memory; the run loop
  clears it after BKL dispatch even if skipped/renumbered by seccomp or ptrace.

### Waiting and waking

- A guest thread never blocks in a host syscall: every wait is one host `poll()` on the thread's own
  event (an eventfd) plus the host fds it waits on, with the deadline as timeout. Wall-clock
  deadlines (sleeps, futex and mqueue timeouts, timers) are `Expiry` values turned into an instant
  at each wait and checked with their own clock, so a wait woken after the realtime or boottime
  clock jumped (the host's clock set, or the device resuming) waits again for the right time;
  relative `CLOCK_BOOTTIME` sleeps count the time the device slept.
- `block_for`: register the waiter (unless its interest is empty), release the BKL, poll, re-take
  the BKL, clear the event, deregister. Host `EINTR` counts as a wake. Callers re-check their
  condition, deadline and interruption. Guest time validation/saturation belongs to `kernel/time`.
- Wake requests made under the BKL are recorded per thread (several kernel instances may share the
  host process) as channels and objects; requests made without holding the BKL (`HELD == 0`, e.g.
  standalone unit tests) are ignored rather than stored in a cross-kernel global fallback.
  At BKL release, a waiter fires if its interest shares a channel with the request, or if objects
  changed and it is `FILE`-interested with no object list or a matching object. Matched events are
  signalled after unlocking, so woken threads do not immediately sleep on the BKL (a wall-clock
  jump signals every task's event directly, and the fast path's sleeps clear their own).
- Objects: waiters register what they wait on (pipes, PTYs, eventfd, timerfd, inotify, signalfd,
  epoll, socket queues, message queues, seccomp notifications, kernel log, FUSE connections, host
  consoles); poll/select/epoll register each watched file's objects, and AIO's io_getevents its
  context and its pending polls' files; a wait on host fds alone registers an empty list. SysV IPC,
  SIGCONT of a stopped group, a host terminal closing and machine teardown still wake everyone.
- Signals: waking a task kicks its CPU (so running guest code exits) and signals its event (so a
  sleeper wakes); a signal blocked everywhere only requests `SIGNAL`.
- `/proc/<pid>/stat` shows S while a thread waits and R once its event is signalled, before it
  re-takes the BKL (like `try_to_wake_up`). A thread woken by host-fd readiness or a timeout reads S
  until it re-takes the BKL; fast-path sleeps read R as soon as they return; a thread in
  `Cx::unlocked` reads S only while its event is unsignalled. The process line uses the main
  thread, Z once it has exited (even while other threads run, as on Linux); group zombie (Z), the
  thread's ptrace stop (t) and group stop (T) take precedence.
- Pipes wake like Linux: a write wakes readers only if the pipe was empty; a read wakes writers only
  when it releases a page slot from a full pipe. Moving a whole slot to another pipe also wakes writers.

### Scheduling and TLS

- nice, CPU affinity and I/O priority are per thread (I/O priority shared under `CLONE_IO`) and
  applied to the host thread; raising priority floors at host nice -4 (never above Android's
  display threads); `SCHED_IDLE` maps to host nice 19; real-time policies are only recorded and
  always need `CAP_SYS_NICE` in the initial namespace (`RLIMIT_RTPRIO` is not consulted),
  `SCHED_DEADLINE` also the same owner; a real-time I/O class (needing `CAP_SYS_ADMIN` or
  `CAP_SYS_NICE`) becomes best-effort on the host. Reset-on-fork turns a real-time child into
  `SCHED_OTHER` with nice 0 and clamps others' nice to at least 0.
- `sched_setattr` reads structures of 48 to 4096 bytes (0 meaning 48; a larger one with non-zero
  bytes past 56 is `E2BIG` with the size written back) and takes Linux 6.1's flags:
  `SCHED_FLAG_KEEP_POLICY` keeps the current policy, `SCHED_FLAG_KEEP_PARAMS` changes neither
  parameters nor policy (only reset-on-fork and the clamps), `SCHED_RESET_ON_FORK` inside the
  policy is `EINVAL`, a nice value beyond `RLIMIT_NICE` is `EPERM` (`EACCES` from setpriority),
  and only `SCHED_OTHER` and `SCHED_BATCH` take the nice value (`SCHED_IDLE` keeps the thread's);
  the utilization clamps are checked against 1024 and, each given or current, against each other,
  and only recorded per thread (copied at clone, reset by `SCHED_RESET_ON_FORK`, read back by
  `sched_getattr`, which always reports the nice value); the deadline flags are accepted unused.
  Without `CAP_SYS_NICE`, leaving `SCHED_IDLE` needs the `RLIMIT_NICE` that allows the current
  nice value, and reset-on-fork cannot be cleared (`EPERM`, for sched_setscheduler too).
- Changing another user's thread: setpriority and sched_setaffinity need the same effective user
  ID (as the target's effective or real one) or `CAP_SYS_NICE` over the target's user namespace
  (`set_one_prio`, `sched_setaffinity`), so root of a container may change its processes';
  sched_setscheduler and sched_setattr need the same owner or `CAP_SYS_NICE` in the initial
  namespace (`__sched_setscheduler`), as does raising priority beyond `RLIMIT_NICE` (`can_nice`);
  ioprio_set needs the target's real uid to be the caller's effective or real one, or initial
  `CAP_SYS_NICE`. `PRIO_USER` translates its uid through the caller's user namespace and skips
  processes the caller cannot see; `KCMP_IO` compares the shared I/O contexts.
- Guest CPUs are the host's allowed CPUs (up to 64); `sched_yield` yields the host thread, on the
  fast path or, while tracing or with a seccomp filter to run, with the BKL released.
- The guest's `tpidr_el0` is a field of the CPU state; the host `TPIDR_EL0` is never changed, so
  ART's signal chain always sees bionic's value.

### Other calls in `syscall/misc.rs`

- `sethostname`/`setdomainname` update the caller's UTS namespace (`CAP_SYS_ADMIN` over owner →
  `EPERM`, length not in 0..=64 → `EINVAL`); `getcpu` returns the lowest affinity CPU and node 0
  (skipping null pointers); `getrandom` accepts `GRND_NONBLOCK`/`RANDOM`/`INSECURE` (not `RANDOM`|
  `INSECURE`, else `EINVAL`), copying 64 KiB host chunks nonblockingly (partial count on later fault).

## Dependencies (inbound / outbound)

### Inbound

- `syscall/mod.rs`, `kernel/boot`, `kernel/time`, `kernel/bug`, CLI/Android hosts (`Machine` stats/
  waits), `kernel/signal`/`kernel/ptrace`, `kernel/procfs`, blocking syscalls (wait API),
  `kernel/mmu` (`TaskSync` kicks, `quiesce`), `kernel/mount` (`fast_changed`), `kernel/exec`,
  `kernel/ns`, and `kernel/tty`'s terminal bridge (`block_for`).

### Outbound

- `engine`/`engine/dbt` (`Cpu`, `Kicker`, `guest_hwcap`, spare CPUs, `Dbt`); `kernel/bug` (`catch`,
  `kill`, `fails`, `test_hook`, `Hold`, `doing`/`done`); `kernel/mm`/`kernel/cow`/`kernel/hostmem`/
  `kernel/mmu` (`translate`, `fork`, `cow_break`, `defer_unmaps`/`release_unmapped`/`spare::refill`,
  `quiesce`, `sync`, generations); `kernel/exec`, `kernel/ns`, `kernel/futex`, `kernel/time`,
  `kernel/boot` (virtual init fallback reaper).
- `kernel/vfs` (`Cached` resolver), `kernel/mount`, `kernel/fuse` (retries, prefault, sweeps, exit
  flush), `kernel/cred`, `kernel/cgroup`, `kernel/ipc`, `kernel/aio`, `kernel/oom`, `kernel/signal`;
  `appine_hal` (`poll`, `Event`, thread clocks/rusage, nice/affinity/ioprio, CPUs, random),
  `std::thread`/`Mutex`.

## Invariants and gotchas

- Lock order is BKL, then the futex lock; never the reverse.
- Kernel objects (`Rc`/`RefCell`) may be touched, cloned or dropped only under the BKL; a thread
  must not hold a kernel-cell borrow when it releases the BKL.
- Wake-ups are signalled only after the BKL is released, and events are level-triggered and cleared
  only after re-taking it, so every waiter must loop and re-check its condition. A wait with no
  interest is woken only by a direct signal (futex wakes, signals, clock jumps).
- A task leaves the kernel's task table and its address space's users under the BKL before its CPU
  state is freed; kicks rely on this.
- `begin_exit` is idempotent and runs before any `PTRACE_EVENT_EXIT`.
- The fast path must leave guest memory untouched after it stops being "in guest", because
  `Mm::sync` waits only for threads in guest code; the futex and clock fast paths do not check the
  epoch, relying on the thread that changed state being the one that refreshes.
- BKL-path entries must call `kernel::doing`/`done`, and BKL acquisition must update `Hold` on one
  cache line (`kernel/bug` watchdog). Guest times must use `kernel/time`'s `timespec`, and the run
  loop must call `Shared::resume_checks` before guest execution.
- Syscall handlers may rerun on `FUSE_RETRY` (walks or FUSE-mapping copies): mutate nothing before
  the last walk (`kernel/exec` mutates nothing before killing other threads). Prefault I/O
  buffers ahead of side effects or service missing pages within the handler, as `kernel/net`
  does when a receive has already consumed data.
- Between syscalls no FUSE node is held by the finishing thread, which is when `sweep` may forget
  nodes; a node another thread holds must be found by `kernel/fuse`'s `in_use` scan, an open
  handle or a request in flight.
- Removed overlay nodes stay for syscalls started before removal unless listed in `kernel/overlay`'s
  `waits_on_files_only` (never add a wait holding a looked-up node there).

## Confirmed bugs / technical debt

- None recorded.

## Open questions

- Is counting `RLIMIT_NPROC` by kernel uid across user namespaces, and never consulting
  `RLIMIT_RTPRIO`, intended?

## To verify

- Linux 6.1 comparisons resting on kernel knowledge rather than source (`eligible_child`,
  `copy_process` exit signals, `zap_pid_ns_processes`, `sched_setattr` keep/uclamp
  flags, `INIT_RLIMITS`); items from Starnix tests were also observed on native Linux 6.8.
