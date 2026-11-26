# kernel/signal Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/signal.md` for the paired decision history, including pre-split decisions for kernel/ptrace and kernel/vdso.
>
> Verified: 2026-11-23 (full mapping: 5 research concerns; 16 claims checked by 3 independent verifiers — 12 confirmed and 4 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: page-fault ESRs reflect populated page-table entries)

## Responsibilities

`kernel/signal` covers how guest code is interrupted, notified, faulted and dumped, plus the
guest-facing Linux 6.1 ABI contract, unimplemented-path telemetry and host debug tracing:

- signal state, generation, queueing, job control, delivery, shared-pending retargeting, signal
  syscalls, `SignalFd`, and signal transitions across `clone`/`unshare`/`execve`;
- arm64 Linux signal frames, `rt_sigreturn`, syscall restart (`orig_x0`, `ERESTART*`,
  `restart_syscall`), synchronous engine fault-to-signal mapping, and `arm64_show_signal`
  unhandled-exception reporting;
- integration with `kernel/vdso`'s sigreturn trampoline and `kernel/ptrace`'s delivery/group stops;
- arm64 ELF core dumps (`coredump.rs`);
- the printk-style kernel log (`/dev/kmsg`, `syslog(2)`, `/proc/kmsg`);
- the Linux 6.1 ABI contract (`uname`, `Errno`, `ENOSYS` policy, time-modification refusals),
  unimplemented-path tracking (`Stubs`), and host-stderr debug/strace output (`APPINE_LOG`,
  `APPINE_STRACE`).

Root: `core/kernel/src/signal.rs`, `syscall/sig.rs`, `coredump.rs`, `klog.rs`, `stub.rs`,
`errno.rs`, `debug.rs`, `SignalFd` in `fd.rs`/`syscall/sig.rs`, restart and unimplemented-syscall
handling in `syscall/mod.rs`, the fault-to-signal branch of `task.rs`, and `uname`, `syslog`,
`adjtimex`, clock setting and `restart_syscall` in `syscall/misc.rs`.

Outside the module: waking and scheduling (`kernel/process`), namespace translation (`kernel/ns`),
CPU state, kicks and the host fault guard (`engine`), page-fault classification (`kernel/mm`),
seccomp and access policy (`kernel/cred`), procfs/sysctl/sysfs views (`kernel/procfs`,
`kernel/sysctl`, `kernel/sysfs`), ptrace and `process_vm` (`kernel/ptrace`), and vDSO image
construction (`kernel/vdso`).

## Key types

- `SigAction` — `handler`, `flags`, `restorer`, `mask`, `immutable` (`SA_IMMUTABLE`, set by
  `force_fatal`); `SigHandlers` — 64-entry disposition table shared under `CLONE_SIGHAND`.
- `SigInfo` — `code`, `fields: InfoFields` (`None`, `Kill`, `Child`, `Queue`, `Timer`, `Fault`,
  `Poll`, `Sys`, `Raw`, `User`), synthesized `esr`, `sender` tid, `uid_ns`/`kuid`; encodes 128-byte
  Linux `siginfo_t`.
- `Pending` — 64-bit `set`, 31 standard `SigInfo` slots (first-sender coalescing), FIFO `queue` for
  RT signals (32–64), and monotonic `arrivals` counter for signalfd `EPOLLET`; per thread and per
  thread group.
- `AltStack` — per-thread `{ sp, size, flags }` (`SS_DISABLE`, `SS_AUTODISARM`; `SS_ONSTACK`
  computed dynamically); `MINSIGSTKSZ = 5120`, `MIN_SIGSTKSZ = 4720` (`AT_MINSIGSTKSZ`).
- `SignalFd` (`fd.rs`) — `mask` (excluding unblockable signals) and `Weak<RefCell<ThreadGroup>>`.
- `Restart` (`syscall/misc.rs`) — `Sleep { deadline, rem }` or `Futex { ... }` stored in
  `TaskState::restart`.
- `coredump::ThreadCore` & `CoreWriter` — per-thread register/hw-debug/CPU snapshot and
  `RLIMIT_CORE`-bounded sparse writer.
- `klog::Klog`, `Record`, `Devkmsg`, `KmsgFile`, `Ratelimit` — 128 KiB / 4096-record ring buffer,
  per-open `/dev/kmsg` state and 10-per-5 s rate limiter (shared by `Kernel::unhandled_rs`).
- `stub::Stub` & `Stubs` (`Kernel::stubs`) — 8 unimplemented-path variants (`Syscall`, `Prctl`,
  `Fcntl`, `Ioctl`, `Madvise`, `Futex`, `Missing`, `Device`) capped at 128 distinct entries plus
  `dropped` count.
- `Errno(i32)` (`errno.rs`) — guest Linux errnos (1–125), internal restart codes `ERESTARTSYS`
  (512), `ERESTARTNOINTR` (513), `ERESTARTNOHAND` (514), `ERESTART_RESTARTBLOCK` (516), and
  internal `FUSE_RETRY` (600); `to_syscall_return` encodes `-errno`.

## Public entry points

- **Signal syscalls**: `kill`, `tkill`, `tgkill`, `rt_sigqueueinfo`, `rt_tgsigqueueinfo`,
  `pidfd_send_signal`, `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `rt_sigsuspend`,
  `rt_sigtimedwait`, `sigaltstack`, `signalfd4` (and `signalfd_read`), `rt_sigreturn` (139),
  `restart_syscall` (128).
- **Kernel-internal signal API**: `send_to_task`, `send_to_group`, `send_to_pgrp`,
  `send_cpu_timer`, `force`, `force_fatal`, `group_exit`, `can_queue`, `wake`, `interrupted`,
  `take`, `deliver`, `retarget`, `show_unhandled`, `abort_name`, `trap::*`.
- **Core dumps**: `coredump::dumps_core`, `coredump::dump`, `ThreadCore::of`.
- **Kernel log**: `klog::printk`, `klog::emit`, `Klog::upcoming_seq`/`lines_from` (bug reports),
  `/dev/kmsg`, `/proc/kmsg`, `syslog(2)` (`do_syslog`, `check_syslog_permissions`).
- **ABI, stubs and debug**: `uname`, `settimeofday`, `clock_settime`, `adjtimex`, `clock_adjtime`,
  dispatcher default `ENOSYS` arm; `stub::{hit, record, ioctl, file_kind, top}`;
  `debug::{log, tracing, trace_start, trace_syscall}`.

## Data flow / lifecycle

### Sending and queueing signals

- Permissions (`may_kill` / `Cred::may_signal`): same thread group, `euid`/`ruid` matching target
  `suid`/`ruid` or `CAP_KILL` over target's user namespace, or `SIGCONT` within the same session.
  `tkill`/`tgkill`/`rt_tgsigqueueinfo` check target thread credentials; `kill`/`rt_sigqueueinfo`/
  `pidfd_send_signal` check the thread group's main-thread credentials; `kill(1, ...)` checks
  against `Cred::root()`.
- Target preparation (`for_target`): retargets `si_uid` across user namespaces (65534 overflow),
  translates kernel-populated `si_pid` (`InfoFields::Kill`) into the target's pid namespace at all
  levels and hides `si_pid` to 0 when the sender is invisible there, and drops default-handled
  signals aimed at a non-killable child pid-namespace init (unless forced `SIGKILL`/`SIGSTOP` from
  an ancestor namespace or `SI_KERNEL`).
- `SIGKILL` skips queueing and calls `group_exit` (sets `exiting`, marks cgroup observation via
  `cgroups.task_changed`, sets `killed = true` and wakes all live threads).
- Stop/cont mutual discard (`prepare`): stop signals (`19..=22`) discard pending `SIGCONT`;
  `SIGCONT` discards pending stop signals, ends group stop (`CLD_CONTINUED` only if the stop had
  completed, clears `stop_pending`, `trace.group_stop`, wakes `PTRACE_LISTEN` threads). Ignored
  unblocked untraced signals are discarded at send time (`send_group` checks `threads.first()`).
- Queueing: standard signals (1–31) coalesce, keeping the first sender's `SigInfo`; RT signals
  (32–64) queue FIFO bounded per thread group by `RLIMIT_SIGPENDING` (default 16384). On overflow,
  `SI_TIMER` overrides the limit and still queues with its `SigInfo` preserved (matching Linux
  6.1's preallocated `send_sigqueue`); `SI_USER` (`kill`, `pdeathsig`) and `SI_KERNEL` still set
  the pending bit without `SigInfo`; other RT senders (`SI_MESGQ`, `CLD_*`, `POLL_*`) fail to
  queue instead of delivering corrupted `SI_USER` info (`F_SETSIG` falls back to `SIGIO` with
  `SI_KERNEL`, matching Linux 6.1's `send_sigio_to_task`), while `tkill`/`tgkill` on RT signals and
  `rt_sigqueueinfo`/`rt_tgsigqueueinfo`/`pidfd_send_signal` with non-`SI_USER` `uinfo` return
  `EAGAIN`.
- Waking & retargeting: `send_to_task` wakes the thread if unblocked; `send_group` picks the first
  thread with the signal unmasked and not in a ptrace stop (`send_cpu_timer` rotates among running
  unmasked threads via a global counter); if none qualifies, requests `wake::SIGNAL`. `retarget`
  wakes siblings (skipping ptrace-stopped threads) for group-pending signals blocked by the current
  thread at the end of `deliver` and for all group-pending signals on non-last thread exit.

### Delivery and syscall restart

- `deliver(cx, cpu, syscall)` runs before returning to guest code (after syscalls, kicks, faults,
  sigreturn and exec). When `syscall == true`, BEFORE checking `killed`, it rewinds any restart
  code (`-ERESTARTSYS`, `-ERESTARTNOINTR`, `-ERESTARTNOHAND`, `-ERESTART_RESTARTBLOCK`: restores
  `x0 = orig_x0`, `pc -= 4` onto `svc`) and calls `KernelEntry::forget_syscall` so `/proc/<pid>/
  syscall` shows `-1` with current `sp` and rewound `pc`. When a tracer or seccomp skips a syscall
  via `NO_SYSCALL`, `syscall::dispatch` calls `forget_syscall` and passes `syscall = false` (matching
  arm64 Linux `in_syscall(regs) == false` so `-512..-516` in `x0` never rewinds `pc`), except for a
  signal-interrupted `SECCOMP_RET_USER_NOTIF` (`Verdict::Restart`) which still passes `syscall = true`.
- Loop: waits while `(g.stopped && !traced) || g.frozen` (entering cgroup freeze via
  `cgroup::enter_frozen` and notifying observations); handles ptrace group-stop and trap checks;
  dequeues thread-pending before group-pending, synchronous signals (`SEGV`/`BUS`/`ILL`/`TRAP`/
  `FPE`/`SYS`) before lowest number (updating POSIX timer overrun on `SI_TIMER`); offers ptrace
  signal-delivery stop unless `act.immutable`.
- Dispositions: ignored/default-ignored/unkillable-init -> continue; default stop -> drop if
  orphaned pgrp (except `SIGSTOP`), else `group_stop` (marks stopped, sets `stop_pending` on
  running threads, wakes siblings, and notifies parent with `CLD_STOPPED` once all threads stop
  via `participate_group_stop`; if already stopped, re-enters silently without re-notifying);
  default fatal -> `group_exit`, `coredump::dump` if first exit and core-generating,
  `ptrace::exit`, return `Flow::Exit`; handler -> frame setup.
- First-handler restart rules: if PC is still at `cont - 4`, `ERESTARTNOHAND`,
  `ERESTART_RESTARTBLOCK`, and `ERESTARTSYS` without `SA_RESTART` become `-EINTR` at `cont`;
  `ERESTARTNOINTR` (produced by `futex_lock_pi`) and `ERESTARTSYS` with `SA_RESTART` stay rewound.
  `restart` is decided once by the first signal taken, even if frame setup fails, and clears
  `TaskState::restart` whenever `ERESTART_RESTARTBLOCK` is turned into `EINTR` or abandoned.
- After frame setup: mask becomes `(mask | act.mask | (sig unless SA_NODEFER)) & !UNBLOCKABLE`;
  `SA_RESETHAND` resets `act.handler` to `DEFAULT`. Loop repeats to stack further signals.
- Post-loop: if no handler ran, restores `saved_sigmask` (from `rt_sigsuspend`/`ppoll`/`pselect6`/
  `epoll_pwait`), retargets still-blocked group-pending signals, and for `ERESTART_RESTARTBLOCK`
  sets `x8 = 128` (`NR_RESTART_SYSCALL`) so re-executing `svc` runs `misc::restart_syscall` to
  resume `TaskState::restart` (`Sleep` or `Futex`, else `EINTR`). If a handler ran while
  single-stepping, invokes `ptrace::handler_entered`.

### Signal frames, `rt_sigreturn` and synchronous faults

- `setup_frame` builds a 16-byte-aligned 4704-byte arm64 Linux layout (`4688`-byte `rt_sigframe` +
  `16`-byte `frame_record { fp, lr }`, `AT_MINSIGSTKSZ = 4720`, `sigaltstack` minimum `5120`):
  `siginfo_t`, `ucontext_t` (`uc_stack`, `uc_sigmask`), `sigcontext` (`fault_address`, `x0..x30`,
  `sp`, `pc`, `pstate` with NZCV and DIT), and `__reserved` containing 528-byte `fpsimd_context`
  always, 16-byte `esr_context` when `info.esr != 0`, and null terminator (no SVE/ZA). Switches to
  `altstack` top when `SA_ONSTACK` is set, enabled, and not already on it; calls `cx.grow_stack`
  before `mm.write`; `SS_AUTODISARM` clears `altstack` after write regardless of `SA_ONSTACK`.
  Sets `x0 = sig`, `x1`/`x2` under `SA_SIGINFO`, `sp = frame`, `x29 = record`, `x30 = sa_restorer`
  or vDSO `__kernel_rt_sigreturn`, `pc = handler`.
- Unwritable frame: restores any swapped `saved_sigmask`, leaves mask/handler unchanged, does not
  call `show_unhandled`, and forces `SIGSEGV` (`SI_KERNEL`) via `force_fatal` if `sig == SIGSEGV`
  else `force` (catchable on an altstack).
- `rt_sigreturn` (nr 139, returning directly from `syscall::dispatch`): validates before mutating —
  16-byte-aligned SP, 4688 readable bytes, `pstate & (0x1f | 0x3c0) == 0` (EL0t AArch64 with DAIF
  clear), valid 16-byte-aligned `>= 16` `__reserved` records with exactly one 528-byte
  `fpsimd_context`, at most one 16-byte `esr_context`, other magics `EINVAL`. Restores GPRs, SP,
  PC, pstate (`NZCV`, plus `DIT` if advertised), FPSR, FPCR (masked with `appine_engine::fpcr_write_mask`), V0–V31, `sigmask` and `altstack`
  (ignoring altstack errors). A bad frame leaves state intact, calls `show_unhandled` with
  `illegal memory access` (logging original `x0`), forces `SIGSEGV` at SP (`SEGV_ACCERR` if
  `Mm::mapped_above`, else `SEGV_MAPERR`), and then sets `x0 = 0`; both valid and bad paths run
  `ptrace::syscall_exit` when traced, invoke `ptrace::syscall_stepped`, and call
  `deliver(..., false)`.
- Synchronous faults (`task::handle`, after recoverable CoW / demand-page / FUSE-fill / EOF-growth
  / stack-growth checks): `Exit::Undefined` -> `SIGILL`/`ILL_ILLOPC` (no ESR);
  `Exit::Breakpoint` -> `SIGTRAP`/`TRAP_BRKPT` (no ESR); `Watchpoint`/`HwBreakpoint` ->
  `SIGTRAP`/`TRAP_HWBKPT` (no ESR); `Alignment`/`StackAlignment` -> `SIGBUS`/`BUS_ADRALN` (EC 0x24
  FSC 0x21 + WnR, EC 0x22, or EC 0x26). Past-EOF and failed backing-page fills raise
  `SIGBUS`/`BUS_ADRERR` with a translation FSC. Other unrecoverable page faults raise `SIGSEGV`
  with `SEGV_ACCERR` inside a VMA or `SEGV_MAPERR` outside. A denied access to a populated leaf
  with permissions gives FSC 0x0f. An absent or `PROT_NONE` leaf gives a translation FSC
  (0x04–0x07) based on the deepest table shared with a populated entry. A fault address outside
  the 48-bit range after the engine handles data tags gives FSC 0x04. Instruction aborts use
  EC 0x20 and data aborts EC 0x24 with WnR set on writes. `force` resets blocked/ignored
  handlers to default, marks non-traced default killable, unblocks, and queues on `task.pending`.
- `show_unhandled` (`arm64_show_signal`): runs before `force` when `debug.exception-trace` is
  non-zero (default 0; 1 under `MachineOptions::exception_trace`), handler is default/ignored and
  thread is untraced, rate-limited to 10 per 5 s kernel-wide (`Kernel::unhandled_rs`, logging
  suppressed count at `WARNING`). Emits `INFO` summary (omitting ESR when 0, with first VMA ending
  above `pc` via `find_vma` semantics) and register dump at `printk[1] & 7`. Excluded for seccomp
  `SIGSYS`, unwritable frames, single-step traps and post-PONR execve kills.

### Signal syscalls, `SignalFd` and clone/exec transitions

- `rt_sigaction`: `size == 8`; rejects setting (`act != 0`) `SIGKILL`/`SIGSTOP` or any
  `immutable` signal (querying with `act == 0` is allowed); masks flags with `UAPI_SA_FLAGS`
  (so `SA_UNSUPPORTED` probes see 5.11+); becoming ignored discards pending instances across all
  thread groups sharing `sighand` (`CLONE_SIGHAND`) and their threads.
- `rt_sigprocmask` (`size == 8`), `rt_sigpending` (`size <= 8`), `rt_sigsuspend` (`saved_sigmask`,
  `ERESTARTNOHAND`), `rt_sigtimedwait` (`signal::take`, `EAGAIN`, `EINTR` on other signals),
  `sigaltstack` (`SS_DISABLE`/`SS_ONSTACK`/`SS_AUTODISARM`, min 5120).
  Once `rt_sigtimedwait` takes a signal, it retains the selected siginfo across FUSE page fills
  while copying to the caller.
- Senders: `kill` handles virtual PID 1 (`k.init_handlers` -> `inittab::Power`), `pid > 0`
  (accepting any tid -> its group, including zombies), `0`, `-1` (all except init and self), and
  `< -1`; `tkill`/`tgkill` send `SI_TKILL`; `rt_sigqueueinfo`/`rt_tgsigqueueinfo`/
  `pidfd_send_signal` (supporting `Pidfd` and `/proc/<tid>` directory fds with `Weak` group check)
  preserve `InfoFields::User` (`si_errno`, `si_pid`/`si_uid`, bytes 24..48).
- `signalfd4`: opened `O_RDWR` (writes `EINVAL`, seeks `ESPIPE`, AIO `EINVAL`); reads dequeue
  matching signals from calling thread then group in 128-byte `signalfd_siginfo` layout; polls
  `POLLIN` alone (using `task::current()` on guest threads, fallback `group` off-thread) with
  `wake::SIGNAL` and `wake::of(s)` for mask updates.
- `execve`/`execveat`: unshares `sighand`, calls `reset_on_exec` (caught -> default, `SIG_IGN`
  preserved), clears `altstack`, `TaskState::restart` and `saved_sigmask`, preserves `sigmask` and
  pending signals, and self-kicks if interrupted. `clone`/`clone3`: inherits `sigmask`, starts with
  empty pending;
  `CLONE_SIGHAND` shares handlers, `CLONE_CLEAR_SIGHAND` resets them; `CLONE_VM && !CLONE_VFORK`
  clears `altstack`. `unshare(CLONE_SIGHAND)` succeeds only when already unshared.

### Core dumps

- Triggered on default action of `SIGQUIT`, `SIGILL`, `SIGTRAP`, `SIGABRT`, `SIGBUS`, `SIGFPE`,
  `SIGSEGV`, `SIGXCPU`, `SIGXFSZ` or `SIGSYS` as the group's first exit when `RLIMIT_CORE >=
  PAGE_SIZE` and `dumpable_mode() != SUID_DUMP_DISABLE` (`0`). Pipe `core_pattern` (`|...`) is
  unsupported (debug-logged and skipped).
- Arms `group.core` under BKL before releasing BKL to wait uninterruptibly on `wake::EXITED` while
  siblings save `ThreadCore` in `task::exit`.
- Expands `core_pattern` (max 127 B, root-writable 0644 sysctl: `%%`, `%p`, `%P`, `%i`, `%I`,
  `%u`, `%g`, `%s`, `%t`, `%h`, `%e`, `%E`, `%c`, `%d`) plus `.pid` when `core_uses_pid` and no
  pid token. Under `SUID_DUMP_ROOT` (`2`, set from `/proc/sys/fs/suid_dumpable`), non-pipe patterns
  must be absolute paths (relative paths log a `WARNING` to `klog` and skip), existing files are
  not unlinked (`O_EXCL` prevents clobbering), and `fsuid` is temporarily overridden to root (`0`).
  Regular dumps (`1`) unlink an existing name in cwd first. Creation always uses fixed mode `0600`
  ignoring the process `umask` (via a private `FsContext` with `umask: 0`) and `O_CREAT|O_EXCL|
  O_NOFOLLOW`; writes honour both `RLIMIT_CORE` and `RLIMIT_FSIZE`.
- Writes 64-bit LE arm64 `ET_CORE` (supporting `PN_XNUM` overflow): `PT_NOTE` (`NT_PRSTATUS`,
  `NT_PRPSINFO`, `NT_SIGINFO`, `NT_AUXV`, `NT_FILE`, `NT_PRFPREG`, `NT_ARM_TLS`,
  `NT_ARM_HW_BREAK`, `NT_ARM_HW_WATCH`, `NT_ARM_SYSTEM_CALL`) and `PT_LOAD` filtered by
  `/proc/<pid>/coredump_filter` (cold FUSE pages are filled before ELF checks and data copies; `CoreWriter` caps
  non-hole bytes at `RLIMIT_CORE`). Creating the file sets `WCOREDUMP` (`0x80`) and `CLD_DUMPED`.

### Kernel log

- `Klog` ring buffer: `128 KiB` data ring (charging `(8 + text.len()).div_ceil(8) * 8` bytes per
  record), max `4096` records, NUL-cut and capped at `991` bytes, monotonic timestamps, oldest
  evicted first; unfinalized trailing record (no `\n`) hidden by `visible()` until another record
  arrives. `LOG_CONT` is never set (no continuation merging), and `printk_time` defaults to `true`
  with no sysfs knob exposing it.
- Kernel writers: `KmsgFile::drop` ratelimit warning, `CAP_SYS_ADMIN` syslog deprecation warning,
  `show_unhandled`, seccomp `audit: type=1326` records (`KERN_NOTICE`), `suid_dumpable=2` unsafe
  `core_pattern` warning, OOM killer, `bug::log` (also reads back via `lines_from`), BKL watchdog,
  cgroup pids fork rejection, and low-port remap notice. Host kernel log is not exposed.
- `/dev/kmsg` (char `1:11`, 0644): per-open sequence, `EPIPE` on evicted records, `EINVAL` on a
  non-zero short read buffer (record still consumed; zero-length `read` returns `Ok(0)` early),
  offset-0 seeks (`SEEK_SET`/`SEEK_DATA`/`SEEK_END`), write prefix `<pri>` parsing (`> 992` ->
  `EINVAL`, 10/5 s ratelimit reporting drops on close; zero-length `write` logs an empty
  unfinalized record while zero-total `writev` returns 0 without logging, matching Linux 6.1's
  `vfs_write` vs `do_iter_write`), polls `POLLIN|POLLRDNORM` (+ `POLLERR|POLLPRI` on missed
  records). `printk_devkmsg=off` makes open `EPERM`.
- `syslog(2)` & `/proc/kmsg` (0400): share `syslog_seq`/`syslog_partial` cursor; `READ_ALL`/
  `READ_CLEAR`/`CLEAR` use `clear_seq`; actions 6/7/8 update `Kernel::printk` console loglevel
  state (no console sink). Permissions enforce `dmesg_restrict`, `CAP_SYSLOG`, and deprecated
  `CAP_SYS_ADMIN` fallback (one-time warning).

### ABI contract, unimplemented paths and debug tracing

- `uname` reports `Linux`, UTS nodename, `6.1.0-appine`, `#1 SMP PREEMPT appine`, `aarch64`, UTS
  domainname, matching `/proc/version` and `/proc/sys/kernel/{osrelease,ostype,version}`.
  Unspecified behavior targets Linux 6.1 (with deliberate newer exceptions: `cachestat`,
  `/proc/<pid>/fd` mount points, time-ns relaxations, `RWF_NOAPPEND`, `nlctrl`).
- Unknown syscalls return `ENOSYS` from `syscall::dispatch`'s default arm and record
  `Stub::Syscall(nr)` (except `NO_SYSCALL` = `u64::MAX`). `FUSE_RETRY` (600) is absorbed in
  `syscall::dispatch`'s retry loop (max 16384 retries -> `EIO`).
- Host time is read-only: `settimeofday` validates `tv`/`tz` pointers (`EFAULT`) and
  `tv_sec`/`tv_usec` ranges (`EINVAL`) before returning `EPERM`; `clock_settime` validates
  timespec then returns `EPERM` for `CLOCK_REALTIME` and valid CPU clocks and `EINVAL` for
  others; `adjtimex`/`clock_adjtime` allow read-only queries (`appine_hal::adjtimex_query`: host
  `SYS_adjtimex` on Linux, synthesized `STA_UNSYNC`/`TIME_ERROR` on Android to avoid app seccomp
  `SIGSYS`) and return `EPERM` on modifying modes.
- `Stubs` (`Kernel::stubs`): tracks up to `128` distinct unimplemented paths (syscalls, prctl,
  fcntl, ioctls by file kind including `virtio_gpu`, madvise, futex, missing `/proc`/`/sys`/`/dev`
  paths, driverless devices) in first-hit order with call count and first-caller comm, dropping
  new distinct names past 128 (`dropped` counter). `stub::ioctl` filters out `'T'`-type ioctls on
  non-terminals except `TIOCOUTQ` on sockets and `FIOQSIZE` on regular/dir/pseudo files. First hit
  logs to stderr under `APPINE_LOG`; `stub::top` supplies the 10 most-called paths to
  `KillReason::Bug::stubs`.
- `APPINE_LOG` and `APPINE_STRACE` are cached once per host process (`OnceLock`, non-empty and
  `!= "0"`). `debug::log` writes `appine: ...` to host stderr. `APPINE_STRACE` disables
  `syscall::fast` and prints `{at} [{tid}] {nr}({args}) = {res} <{ms}>` after pid translation and
  before `signal::deliver` (thus showing raw `-512`, `-513`, `-514` and `-516` restart codes);
  `exit`, `exit_group`, `rt_sigreturn`, successful `execve`, successful `execveat`,
  ptrace/seccomp-skipped syscalls, and syscalls terminated at ptrace-entry or seccomp check return
  before printing.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/process`: `syscall::dispatch`, `exec_done`, `task::handle`, `task::exit`, `clone`/
  `unshare`/`execve`, `syscall::fast::Fast` (`debug::tracing`).
- Signal/klog/stub callers across the kernel: `kernel/time`, `kernel/tty`, `kernel/cred`
  (seccomp), `kernel/oom`, `kernel/bug` (`stub::top`, `klog::lines_from`, `watchdog`),
  `kernel/cgroup`, `kernel/net`, `kernel/files`, `kernel/mm`, `kernel/futex`, `kernel/loop`,
  `kernel/procfs`, `kernel/sysctl`, `kernel/sysfs`.

### Outbound

- `kernel/process`, `kernel/ns`, `kernel/boot`, `kernel/cgroup`: `ThreadGroup`, `Task`, `PidNs`,
  `UtsNs`, `INIT`/`Power`, `cgroup::{task_changed, enter_frozen, notify_changes}`, waking.
- `kernel/mm`: `read`/`write`, `grow_stack`/`grow_stack_to`, `is_mapped`/`mapped_above`/`regions`,
  `dump_regions`/`dump_page`/`residency`/`auxv`/`args`.
- `kernel/ptrace`: `traced`, `group_stop`, `trap`, `signal_stop`, `handler_entered`,
  `syscall_exit`, `exit`, `pstate_of`/`set_pstate`, `encode_regset`.
- `kernel/vdso`: `vdso::sigreturn_offset()`.
- `kernel/vfs`/`kernel/files`/`kernel/cred`/`kernel/sysctl`/`kernel/procfs`/`hal`/`engine`:
  `create_exclusive`/`unlink_path`/`write_at`, `Cred::may_signal`/`capable`/`uid_out`,
  `recorded_value`/`mark_deleted`/`comm_str`, `appine_hal::{clock_gettime, adjtimex_query}`,
  `appine_engine::{Cpu, CpuState, Kicker}`.

## Invariants and gotchas

- Signals deliver only at the kernel boundary; asynchronous delivery relies on engine kicks.
- `SIGKILL` and `SIGSTOP` can never be blocked, caught or ignored; `SA_IMMUTABLE` skips ptrace
  signal-delivery stops.
- The vDSO sigreturn trampoline bytes (`mov x8, #139; svc #0`) are ABI and must not change.
- `deliver` rewinds restart codes and calls `forget_syscall` before checking `killed`, ensuring
  core dumps and `PTRACE_EVENT_EXIT` observe `orig_x0` and PC at `svc`.
- `coredump::dump` arms `group.core` under BKL before waiting uninterruptibly on `wake::EXITED`;
  `stub::record` and `klog::emit` use `try_borrow_mut()` to avoid re-entrant panics.
- Version literal `"6.1.0-appine"` is duplicated across `syscall/misc.rs`, `pseudo.rs` and
  `signal.rs` (and `"#1 SMP PREEMPT appine"` across `syscall/misc.rs` and `pseudo.rs`, while
  `signal.rs` prints `#1`) and must be updated together.
- `APPINE_LOG` and `APPINE_STRACE` are read once per host process (`OnceLock`); `android`
  `adjtimex` must stay synthesized because Android app seccomp kills `SYS_adjtimex` with `SIGSYS`.

## Confirmed bugs / technical debt

- Translation FSCs reflect the soft-MMU's population. Small mappings can already have entries
  before their first access. `next_present` counts leaves whose permissions were cleared but
  cannot distinguish an empty intermediate table retained after unmap from an absent table.

## Open questions

- Is per-thread-group (instead of per-user) `RLIMIT_SIGPENDING` accounting an intended
  simplification?
- Should `Klog::printk_time` be exposed under `/sys/module/printk/parameters/time`, or remain
  fixed `true`?

## To verify

- Linux 6.1 behavioral comparisons (`legacy_queue`, `retarget_shared_pending`, `force_sigsegv`,
  `do_undefinstr`, `UAPI_SA_FLAGS`, `format_corename`, sysctl `test_perm`, time-setting check
  order) come from kernel knowledge rather than a Linux source checkout.
