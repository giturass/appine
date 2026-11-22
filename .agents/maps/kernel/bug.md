# kernel/bug Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/bug.md` for the paired decision history (not yet created; decisions from before the split are D29, D38, D56, and the bug-containment, watchdog and test-hook parts of D14, D18 and D53 in `.agents/decisions/kernel/process.md`).
>
> Verified: 2026-11-21 (split out of the kernel/process full mapping of 2026-11-10; the boundary was checked against the source at the split)

## Responsibilities

`kernel/bug` isolates kernel-layer and engine faults to the offending guest process and monitors
long holds of the big kernel lock:

- panic containment (`bug::catch`, `bug::host_call`, panic hook) so a kernel-layer panic or engine
  `Exit::HostFault` ends only the affected guest process with `SIGSEGV` (or returns a host error)
  when containment is enabled;
- kill reports (`Kernel::kills`, `Machine::take_kills`) recording both internal bugs (with panic
  location, recent kernel log lines and top unimplemented paths) and OOM kills for the host app;
- the BKL watchdog (`Watchdog`, `Hold`, `HoldSample`, `Entry`, `Doing`, `Machine::stall`) that
  samples BKL holds without taking the BKL, reports stalls to stderr and the host, and drains
  end-of-hold records into the kernel log in FIFO order;
- debug / `test-hooks` fault-injection syscall (`0xa991`) and test switches (`trap`, `fails`,
  `host_refuses_tcp_filters`).

Root: `core/kernel/src/bug.rs`, `core/kernel/src/watchdog.rs`, `Hold`/`HoldSample`/`Entry`/
`Doing`/`doing`/`done` in `core/kernel/src/kernel.rs`, `Machine::take_kills` and `Machine::stall`
in `core/kernel/src/machine.rs`, and the `TEST_SYSCALL` (`0xa991`) dispatch arm in
`core/kernel/src/syscall/mod.rs`.

Outside the module: BKL acquisition/release, task/group exit, syscall dispatch and the run loop
(`kernel/process`); `Machine` lifecycle starting and stopping the watchdog (`kernel/boot`);
engine fault guard producing `Exit::HostFault` (`engine`, `engine/dbt`); OOM victim selection
calling `bug::record_kill` (`kernel/oom`); kernel log storage and `stub::top` (`kernel/signal`);
host polling, in-tab messages and notifications (`android/service`, `android/reports`,
`android/native`).

## Key types

- `KillReport` / `KillReason` (`Bug`, `OutOfMemory`) — queued on `Kernel::kills` (at most 32,
  oldest dropped), carrying pid, comm, controlling console number when on an app console, and the
  reason payload.
- `Hold` — one cache-line (`#[repr(C, align(64))]`) written by each holder on taking the BKL: the
  `held` hint, wrapping acquisition `count`, holder's `host_tid`, and its guest thread's `Entry`
  (`tid`, `tgid`, `comm`, `Doing`, `pc`); `HoldSample` — one lock-free read of it.
- `Entry` / `Doing` (`Nothing`, `Start`, `Syscall(u64)`, `Fault`, `Kick`, `Exception`, `Exit`) —
  thread-local record of what a guest thread entered the kernel for, updated by `kernel::doing` /
  `kernel::done`.
- `watchdog::Watchdog` — owns the `bkl-watchdog` thread for one kernel, stopped and joined last in
  `Drop for Machine`.
- `watchdog::Stall` — a hold reported as too long: monotonic `id` per kernel, elapsed `seconds`,
  the report line, and the ended kernel-log record once the hold finishes.
- `Trap` (debug / `test-hooks` only) — planted one-shot fault points armed by syscall `0xa991`.

## Public entry points

- **Containment and kills**: `bug::contain`, `bug::catch`, `bug::host_call`, `bug::kill`,
  `bug::kill_process`, `bug::record_kill` (also called by `kernel/oom`), `bug::report`,
  `bug::install_panic_hook`.
- **BKL holder tracking and watchdog**: `kernel::doing`, `kernel::done`, `Hold::sample`,
  `Watchdog::start` (called by `Machine::start`, `kernel/boot`).
- **Host-facing** (`Machine`): `take_kills`, `stall` (returns latest `Stall` without taking the
  BKL).
- **Test hooks** (debug and `test-hooks` builds): syscall `0xa991` (`bug::TEST_SYSCALL` →
  `bug::test_hook`), `bug::trap`, `bug::trap_finish`, `bug::fails`,
  `bug::host_refuses_tcp_filters`.

## Data flow / lifecycle

### Kernel bugs and kill reports

- Containment (`bug::contain`) is on with `APPINE_ON_BUG=kill`, off with `abort`, and otherwise on
  in release builds and off in debug builds. `catch` runs kernel code under `catch_unwind`; with
  containment off a panic aborts the host process (`appine: internal error, aborting`).
- Where a panic is caught and what it ends: every entry of a guest thread into the kernel, thread
  start and each step of thread exit end that thread's process (in `task::exit`'s first stage, a
  second `bug::catch` salvages idempotent `vfork` completion and `remove_user` before the kill);
  each step of process finish is only reported and the next step goes on; the timer thread's
  handling of one process's timers ends that process, while a panic in the memory-limit check or
  signal-driven I/O turns that feature off; `host_call` around `Machine` methods and the library's
  other public functions makes the call return an error (a console's call also hangs up that
  console). Taking the BKL after a caught panic ignores its poison flag (`Shared::lock`,
  `kernel/process`). An engine host fault (`Exit::HostFault`) ends the process the same way.
- `kill` (a thread's own bug) and `kill_process` (the timer thread's) write one report line to
  stderr (pid, comm, the thread and its last guest pc for `kill`, what failed, and the panic's
  message and location) and to the kernel log at `KERN_ERR`, one record per line, record a kill
  report, and end the whole thread group with `SIGSEGV` (no core dump). The panic hook
  (`install_panic_hook`, once per host process, chained to the previous hook) keeps each thread's
  latest panic message (up to 1000 bytes) and location for that report.
- Kill reports (`Kernel::kills`, at most 32, the oldest dropped) carry the pid, comm, the console
  number when the process's controlling terminal is one of the app's consoles, and the reason:
  `Bug` (the report, the 10 kernel log records before it plus itself, and the most-reached
  unimplemented paths from `stub::top`) or `OutOfMemory` (from the OOM killer, `kernel/oom`). The
  host takes them with `Machine::take_kills` (`android/service`, `android/reports`).
- Test hooks exist only in debug builds and with the `test-hooks` feature, and answer `ENOSYS`
  unless `APPINE_TEST_HOOKS=1`. Syscall `0xa991` with `what` 1 to 14 panics at once, points a page
  at an inaccessible host page so the engine faults on the host, or plants a panic that fires once
  (`trap`) at the thread's exit, the next thread start, the next timer handling, the next host
  call, a step of process finish, right after releasing the BKL, the next no-BKL syscall or a futex
  wait; it can also act as if the host's wall clock jumped, hold the BKL for `addr` milliseconds
  for the watchdog's tests, make the next host thread for a guest thread fail to be created
  (`fails`: `task::start` returns `EAGAIN` for a clone or a host spawn), or, until turned off again
  (`addr` 0), act as a host that refuses `SO_ATTACH_FILTER` on TCP sockets
  (`host_refuses_tcp_filters`, read by `kernel/net`). Any other `what` is `EINVAL`.

### BKL watchdog

- A guest thread records what it is in the kernel for in a thread-local `Entry` (`kernel::doing`):
  starting, a syscall number (low 56 bits of x8), a memory fault, a kick, another exception, or
  ending; with its tid, tgid, comm and pc at that entry. It is set before each BKL-path entry (and
  before the fast path's panic kill), kept across the BKL re-takes inside that entry, and cleared
  when the host thread finishes the guest thread (`kernel::done`). Threads running no guest thread
  (the timer thread, host calls, the watchdog) record none.
- `Machine::start` (`kernel/boot`) starts a host thread `bkl-watchdog` that never takes the BKL to
  look: every fifth of the threshold (10 s; `APPINE_BKL_WATCHDOG` in seconds, 0 turns it off) it
  samples `Hold`; the same sample (count, host tid, entry) seen for the threshold is one hold that
  lasted too long. A sample torn by a new holder differs and only looks like another hold.
- On reaching the threshold, without the BKL: one line on stderr naming the guest process (pid and
  comm), thread, what it entered for and its pc, or else the host thread, plus the holder's host
  thread name and activity (running, in host syscall n, or its scheduler state); the same line
  becomes the latest `Stall` (ids count from 1 per kernel; seconds updated at each look).
- When a later look sees the lock free or another hold: at once a line naming the holder and the
  total seconds on stderr and in the `Stall`, and the same line queued for a single on-demand
  thread (`bkl-watchdog-log`) that drains queued records as `KERN_ERR` entries in FIFO order once
  it gets the BKL, so the watchdog goes on looking, and reports the next hold, while that holder
  keeps it (a panic writing it is only reported; when the thread cannot start the queued records
  are dropped). Durations count from the first look, so they are right to within one look. Nothing
  is ended.
- `Machine::stall` returns the latest `Stall` without the BKL; the watchdog is stopped and joined
  last in `Drop for Machine` (`kernel/boot`).

## Dependencies (inbound / outbound)

### Inbound

- `kernel/process` (BKL acquisition writes `Hold`, task run loop / exit / `finish_group` call
  `doing`/`done` and `bug::catch`/`kill`/`fails`, syscall dispatch routes `0xa991`).
- `kernel/boot` (`Machine::start` starts `Watchdog`, `Drop for Machine` stops it last,
  `bug::host_call` wraps host calls).
- `kernel/time` (timer thread uses `bug::catch` and `bug::kill_process`), `kernel/oom`
  (`bug::record_kill`), `kernel/store` (`bug::catch`), `kernel/net` (`host_refuses_tcp_filters`).
- Hosts (`android/native`, `android/service`, `android/reports`, `harness/cli`): `take_kills`,
  `stall`, `install_panic_hook`.

### Outbound

- `kernel/process` (`Shared::lock`, `Kernel`, `ThreadGroup`, `Task`, `force_fatal` via
  `kernel/signal`).
- `kernel/signal` (`klog::printk`, `stub::top`, `force_fatal`).
- `appine_hal`: host thread activity and name for watchdog reports; `std::panic::catch_unwind`,
  `std::thread`.

## Invariants and gotchas

- `Hold` is written on every BKL acquisition (`kernel/process`): anything added to it must stay on
  its cache line and cost a plain relaxed store, or every syscall pays. A thread that takes the
  BKL outside an entry after running guest code (the run loop's translator re-attach) is attributed
  to its previous entry.
- `Machine::stall` and the `bkl-watchdog` sampling loop must never take the BKL, so they remain
  responsive while a hold is stuck; end-of-hold kernel logging runs asynchronously on the single
  `bkl-watchdog-log` drainer thread.
- Test hooks such as `REFUSE_TCP_FILTERS` (`what = 14`) persist process-wide until explicitly
  turned off (`addr = 0`), so tests must reset them before later sockets in the same run.

## Open questions

None.
