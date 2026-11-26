# kernel/poll Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/poll.md` for the paired decision history (timerfd's decisions from before it moved here are D23 and the timerfd halves of D16 and D41 in `.agents/decisions/kernel/vfs.md`).
>
> Verified: 2026-11-17 (full mapping: 3 research concerns, 14 claims checked by 2 independent verifiers)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: fall back to `SIGIO` with `SI_KERNEL` when an `F_SETSIG` RT signal fails on `RLIMIT_SIGPENDING` overflow)

## Responsibilities

`kernel/poll` implements I/O multiplexing inside the kernel layer:

- the readiness model shared by every multiplexer (`readiness`, `arrivals`, `wake_objects`);
- ppoll and pselect6;
- epoll, including Linux's `EPOLLET` timing, nested epolls, `EPOLLONESHOT` and
  `EPOLLEXCLUSIVE`;
- eventfd2 and timerfd;
- signal-driven I/O (`O_ASYNC`, `F_SETOWN*`, `F_SETSIG`) checked by the timer thread.

Root: `core/kernel/src/syscall/poll.rs` and `syscall/timerfd.rs` (the `EventFd` and `TimerFd` state
lives in `fd.rs`, a `kernel/files` file).

Outside the module: the wait mechanism, wake objects and the BKL (`kernel/process`);
the timer thread (`kernel/time`); per-kind readiness of sockets (`kernel/net`, `kernel/rawicmp`, `kernel/netlink`, `kernel/unix`),
terminals (`kernel/tty`), pipes (`kernel/pipe`), inotify (`kernel/inotify`), signalfd
(`kernel/signal`), message queues (`kernel/ipc`) and seccomp notify (`kernel/cred`); fcntl and ioctl
entry points (`kernel/files`) and the read paths (`kernel/fileio`); clock bases, `Expiry` and the wall-clock jump
count (`itimer`, `kernel/time`); signal delivery (`kernel/signal`).

## Key types

- `Waits` — one blocking wait: host fds with events, in-process wake objects, tracked epolls
  joined on `Epoll::waiters`, pidfd/signalfd flags (CHILD/SIGNAL channels), the earliest timerfd
  deadline, edge state, gated files.
- `Interest` — one watched file of an epoll: weak open file, events, data, `armed` (ONESHOT),
  `seen`/`drained`/`arrivals` snapshots for edge triggering, nested-generation share, captured
  `fdinfo_id` `(sdev, ino)`, `exclusive_order` (monotonic registration order for `EPOLLEXCLUSIVE`),
  slot `epoch`, `WatchMode` (`WakeObjects` / `HostEpoll` / `Dynamic`), and cached scan host fd.
- `Epoll` — slab of interests with O(1) `(fd, file_ptr)` index, event-driven `ready_queue`
  (`VecDeque<usize>`), `dynamic` fallback list, lazy `appine_hal::HostEpoll` for host-backed
  sockets/fences, round-robin `cursor` (for dynamic/untracked scans), `base` generation, sticky
  `edge_watched`, weak `parents` (parent epolls watching this epoll, for top-down nesting checks),
  `waiters`, and weak handle to `Kernel::epoll_watches`.
- `EpollWatches` — per-kernel (`Kernel::epoll_watches`) wake-object, per-file (`drained` /
  shared `HostEdges`), and edge-triggered pipe (`arrived`) subscription map marking matching
  tracked epoll slots dirty and waking their `waiters` (and ancestors) in O(subscribers).
- `HostPollBatch` — host poll slots paired with interest indices and guest-known bits for one scan.
- `HostEdges` (on `OpenFile`) — a private edge-triggered host epoll on one host fd, accumulating
  read/write arrivals.
- `OpenFile` fields used here: `drained` (per direction), `reads`, `exclusive_claim`, `owner`,
  `sig`, `host_edges`.
- `ExGate` — per-file queue of sleeping exclusive `GateWaiter`s (`event`, `wanted` mask, `seen`
  bits, and stable registration `order`) plus the last generation seen (`Kernel::ex_gates`).
- `Fasync` — one `O_ASYNC` file: weak open file, fd, last events, counter snapshots
  (`Kernel::fasync`).
- `EventFd` (in `fd.rs`) — counter, semaphore flag, `writes`/`reads` generations.
- `TimerFd` (in `fd.rs`) — clock, the next expiration (`itimer::Expiry` on the clock's base; None
  when not armed), interval, unread expirations, `fired` (the edge generation, incremented once
  per due update and once per newly observed cancellation), the `TFD_TIMER_CANCEL_ON_SET` state
  (the wall-clock jump count when set and whether a jump is pending) and the last settime flags
  (fdinfo). `update` adds elapsed expirations when the timer is read, polled or queried.

## Public entry points

- Syscalls: `ppoll` (73), `pselect6` (72), `epoll_create1` (20), `epoll_ctl` (21), `epoll_pwait`
  (22), `epoll_pwait2` (441), `eventfd2` (19), `timerfd_create` (85), `timerfd_settime` (86),
  `timerfd_gettime` (87); eventfd read/write and timerfd read through `IoPath::EventFd` and
  `IoPath::TimerFd`; `TimerFd::fdinfo` for `kernel/procfs`.
- Shared helpers: `readiness`, `poll_once`, `poll_now`, `arrivals`, `wake_objects`, `host_fd`,
  `set_temp_mask`/`restore_mask`, `deadline_ms`/`deadline_ts` (also used by AIO); for AIO's
  pending polls, `wait_aio_polls` (io_getevents) and `watch_aio_poll` (the timer thread).
- Hooks: `drained` (from the dispatcher after read-like and write-like syscalls), `arrived` (pipe
  writes to a non-empty pipe), `register_fasync` (fcntl/ioctl), `check_exclusive` and
  `check_fasync` (timer thread), `send_to_owner`, `Epoll::fdinfo`, `Epoll::target` (kcmp).

## Data flow / lifecycle

### The readiness contract

- `GpuFence` carries the host read end of a completion pipe. Poll and epoll monitor it through
  the same host-fd wait path as sockets. A retirement byte signals completion. Closing the writer
  before retirement reports hangup without readable data.

- `readiness(file)` is one `match` over `FileKind` returning known events and an optional host fd.
  Host stdio and ordinary inet sockets supply an fd. Queued DNS answers on an untapped UDP socket
  supply guest bits alone. A tapped UDP socket can supply both guest bits and its host fd. Other
  readiness sources include pipes (a write end `POLLOUT` with
  a free page slot, plus `POLLERR` without readers, as `pipe_poll`) and eventfd inline; timerfd
  (expirations), inotify, signalfd, pidfd (exited), epoll (nested, up to 4 levels), PTYs
  (`tty::readiness`), sockets (`net::readiness` → unix, netlink, inet, raw ICMP), message queues,
  seccomp notify, kmsg, `/dev/fuse` (`kernel/fuse`: always writable, readable while a request or
  interrupt waits, only `POLLERR` once aborted or before a mount attached it; it lists its
  connection's reader object); synthetic files with change notifications (`fd::ProcEvent`:
  mounts and mountinfo `POLLIN|POLLRDNORM`, sysfs and cgroup2 files readable and writable, both
  plus `POLLERR|POLLPRI` while changed, their counter as wake object and read arrival,
  `kernel/procfs`, `kernel/sysfs` and `kernel/cgroup`); `O_PATH` files `POLLNVAL`; everything else (regular files,
  directories, other devices, other synthetic files, bpf) is always readable and writable. A report of `POLLPRI` or
  `POLLERR` from mounts or mountinfo, by ppoll, pselect6 or epoll, takes the change in
  (`took_change`, as `mounts_poll` does). The bits are each Linux
  poll operation's: eventfd, timerfd and signalfd report `POLLIN`/`POLLOUT` without the
  `RDNORM`/`WRNORM` bits, an epoll `POLLIN|POLLRDNORM`.
- `poll_now` adds a zero-timeout host poll for the host fd (and its `HostEdges`), keeping
  `POLLERR`/`POLLHUP`/`POLLNVAL` regardless of the requested mask.
- `arrivals(file)` gives monotonic `[in, out]` generation counters (plus host edges);
  `wake_objects(file)` the objects every state change wakes.

### Waiting

- `Waits` reuses the host fds discovered during an empty `ppoll`/`pselect6` scan (`add_with_host`)
  and `Interest::cached_host` on dynamic/untracked epoll slots rather than recomputing `readiness`
  when building a blocking wait. For tracked epolls, `Waits::add_epoll_rc` joins `ep.waiters`
  (woken directly by `EpollWatches` and `epoll_ctl`) and passes the single `host_epoll` fd for all
  tracked host sockets instead of copying and sorting every idle interest's wake objects or host
  fds. It calls the kernel's wait: the BKL is dropped around one host poll of all host fds plus
  the thread's event fd; the timeout is the earliest of the deadline and any timerfd deadline;
  pidfd and signalfd waits also listen on the CHILD and SIGNAL channels. Spurious wakeups just
  rescan. The BKL is held for every scan.
- AIO uses the same `Waits`: io_getevents waits on its pending polls' files plus the context's wake
  object (`wait_aio_polls`), and the timer thread takes each eventfd-signalling poll's host fds and
  timerfd expiration (`watch_aio_poll`), relying on its all-channel interest for the rest.

### ppoll and pselect6

- `wait_ready` scans all items once, batching every host-backed fd into a single zero-timeout
  `appine_hal::poll` (`poll_host_batch`, with per-fd fallback if the batch fails), and reuses the
  discovered host fds when constructing `Waits` on an empty scan.
- ppoll: `nfds` above the soft `RLIMIT_NOFILE` `EINVAL`; timespec validated (`EINVAL`) and, as
  in every timed wait here, saturated at `KTIME_MAX` (the `kernel/time` map); each fd
  looked up once (closed → `POLLNVAL`, negative → ignored); revents written back and counted,
  also when the wait is interrupted (zeros, before the error is returned, as `do_sys_poll`).
- pselect6: `nfds` negative `EINVAL`, otherwise clamped to the fd table's retained capacity
  (`FdTable::capacity`, including previously occupied slots), so bits above it are neither read
  nor written back; sets read in 64-bit words; read → `IN|RDNORM|HUP|ERR|NVAL`, write →
  `OUT|WRNORM|ERR|NVAL`, except → `PRI|NVAL` (an `O_PATH` fd is ready in every set); a set bit on a
  closed fd `EBADF`; results rebuilt per set (one count per bit). Only events in an fd's sets end
  the wait: a hangup or error outside them is not counted, and its host fd is left out of the
  host poll (which would always report it) while its in-process objects are still waited on.
- Both: temporary signal mask (size 8, SIGKILL/SIGSTOP removed; kept on `ERESTARTNOHAND`/`EINTR`
  so the handler runs with it); loop scan → return if ready or past the deadline → interrupted →
  `ERESTARTNOHAND` → wait; remaining time written back whenever a nonzero timeout was given (a
  failing write turns the restart into `EINTR`); restarts re-read the remaining time.

### epoll

- `epoll_create1`: only `O_CLOEXEC` (else `EINVAL`); attaches the epoll to `Kernel::epoll_watches`.
- `epoll_ctl` checks in Linux 6.1's order: the event is copied first except for DEL (`EFAULT`);
  epfd, then the target (`EBADF`; `O_PATH` `EBADF`); a target that cannot be polled — regular
  files, directories, synthetic files without a Linux poll operation (`pseudo::pollable`),
  `/dev/null|zero|full`, loop devices and `/dev/loop-control` — `EPERM`; epfd not an epoll, or the target itself, `EINVAL`;
  `EPOLLEXCLUSIVE` only on ADD, not on epolls, and not with ONESHOT/RDHUP/PRI (`EINVAL`); on ADD
  a cycle or combined nesting depth (receiving epoll's `parents` ancestor depth plus the target's
  subtree depth) exceeding `MAX_NESTS` (4) gives `ELOOP`, and adding/deleting a nested epoll
  registers/removes one matching weak ref in the inner epoll's `parents`. Interests are keyed by
  (fd, open file) in an O(1) index over a slab;
  ADD `EEXIST`, MOD replaces (re-arms; MOD of an exclusive interest `EINVAL`), DEL, missing
  `ENOENT`. After initial validation, ctl prunes any dead entry at the matching key (and amortizes
  full slab pruning on growth), captures `(sdev, ino)` via `Vfs` for `Epoll::fdinfo` (matching
  `stat` for tmpfs, overlay, FUSE, synthetic mounts, message queues, host fds and anonymous files,
  encoded as Linux's internal `(major << 20) | minor`), registers/updates `EpollWatches` and
  `HostEpoll`, and signals waiters.
- Interests hold weak references: they live while any fd or fork copy holds the open file and are
  skipped once it is gone (pruned lazily when touched or on amortized slab growth). Fork shares
  the epoll.
- `epoll_pwait`/`epoll_pwait2`: `maxevents` ≤ 0 or too large `EINVAL`; an events buffer reaching
  past the user address space (2^48) `EFAULT` before epfd is looked at (`access_ok`; whether it
  is mapped is seen only at the copy-out); tracked epolls pull ready host fds via one zero-timeout
  `HostEpoll::wait_now`, drain only queued entries from `ready_queue` (re-queuing ready entries at
  the tail until `reported` confirms copy-out for `EFAULT` safety and round-robin fairness), and
  scan the `dynamic` list (timers, signalfds, pidfds, nested epolls, `EPOLLEXCLUSIVE`, host stdio,
  `udp_tap` sockets, duplicate/non-epollable host fds, and unconnected or datagram AF_UNIX sockets); return if
  anything is ready or past the deadline; interrupted → `EINTR` (never restarted; the temporary
  mask is kept); otherwise wait. Each 16-byte `epoll_event` is copied out to guest memory before
  `reported` marks it (ONESHOT disarmed, ET `seen` advanced, `HostEpoll` mask synced, exclusive
  claim taken, mounts change consumed); on `EFAULT`, a partial count is returned if any event was
  already written, else `EFAULT`, leaving unwritten events intact.
- Dynamic and untracked scans with `maxevents > 1` batch eligible level-triggered host fds in a
  zero-timeout poll (`HostPollBatch`), preserving per-interest masks and guest-known bits with
  per-fd fallback on batch failure. When one epoll consumes a shared `HostEdges` event,
  `EpollWatches::notify_file` marks other epolls watching that open file dirty so they still see
  the incremented arrival count.
- Edge triggering: each interest compares the file's per-direction drain counts and arrival
  generations with its snapshots; a direction that was drained or received new data clears its
  reported bits; an interest fires only for bits not yet reported. Host fds with edge-triggered
  or exclusive interests (or in an edge-watched epoll) get a private edge-triggered host epoll
  (`HostEdges`) so each host arrival counts. While waiting, reported-and-still-ready bits are left
  out (and `HostEpoll` unarms `fd` once `POLLHUP`/`POLLERR` is seen, keeping `HostEdges` armed,
  avoiding busy loops); drains (`EpollWatches::notify_file`) and non-empty pipe arrivals
  (`EpollWatches::notify_et_pipes`) mark tracked interests dirty and wake waiters. A pipe's read
  end counts writes as arrivals. Its write end counts reads that free a slot from a full pipe,
  whole slots moved by pipe-to-pipe splice and successful resizes (`Pipe::room`). Drains are
  counted for read, readv, accept, recv* and write, writev, send*, sendfile, splice, tee when they
  return `EAGAIN`, and for short read, write, recvfrom and sendto (pread/pwrite and their vector
  forms never count; tee's write-side entry reads the length argument instead of `fd_out`).
- Nested epolls: an inner epoll's generation is its `base` plus every interest's share. Only live,
  armed entries refresh their shares, and removal transfers the previous share to `base`. The
  generation counts on the read side only. Edge-watching an inner epoll propagates host
  edge watching inward (and registers inner `HostEdges` and `et_pipes`). An epoll fd reports
  `POLLIN|POLLRDNORM` (6.1's ep_eventpoll_poll).
- `EPOLLEXCLUSIVE`: an edge is the file's drain and arrival counts; each edge is claimed by one
  epoll (level-triggered exclusive interests keep reporting to the claiming epoll). Exclusive
  waiters queue on the file's `ExGate` in ascending `exclusive_order` (assigned monotonically at
  `EPOLL_CTL_ADD`, preserving Linux's stable wait-queue order instead of rotating woken waiters to
  the back) with their `wanted` mask and `seen` bits, and the timer thread (subscribed to every
  kernel change while gates exist, to the host edges, and woken at the next expiry of a gated
  timerfd) wakes the first waiter whose requested ready bits are unmasked for the changed
  read/write direction(s) when a new edge appears. A host fd for which edge tracking could not be
  installed uses the direct wait path.

### eventfd

- `eventfd2` flags `EFD_SEMAPHORE|O_CLOEXEC|O_NONBLOCK` (else `EINVAL`). Read: buffer under 8
  `EINVAL`; takes the count (or 1 in semaphore mode) or blocks/`EAGAIN`/`ERESTARTSYS`. Write: under
  8 bytes or `u64::MAX` `EINVAL`; blocks or `EAGAIN` until the sum fits below `u64::MAX`; writing 0
  still counts as an arrival. Readiness: `POLLIN` when nonzero, `POLLOUT` below `u64::MAX - 1`
  (no `RDNORM`/`WRNORM`, as eventfd_poll); never `POLLERR`. Generations `[writes, reads]`.
- An AIO completion with `IOCB_FLAG_RESFD` increments the counter up to `u64::MAX - 1`, advances
  the write generation even at that cap, and wakes the object.

### timerfd

- `timerfd_create`: realtime, monotonic, boottime and the two alarm clocks (others `EINVAL`),
  flags `O_CLOEXEC|O_NONBLOCK` (`EINVAL`); the alarm clocks need `CAP_WAKE_ALARM` in the initial
  namespace (`EPERM`), at creation and again at every settime. The file opens read-write as
  `anon_inode_getfd` gives it, so a write is `EINVAL` (no write operation), not `EBADF`.
- `timerfd_settime`: flags `TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET` (`EINVAL`); another kind of
  fd `EINVAL`; timespecs go through the shared `timespec()` helper (`EINVAL` for negative seconds
  or nanoseconds out of range), so no deadline can overflow. It writes the old value first, then
  resets the expiration count and records the flags; a zero value disarms. Expirations are kept on
  the clock's base: relative realtime and monotonic on the host's monotonic clock, absolute
  realtime on its realtime clock, boottime on its boottime clock; an alarm clock reads as its
  ordinary one, and absolute times are first moved out of the caller's time namespace. Setting
  wakes the timer's object, so waits using the old deadline compute it again.
- `TFD_TIMER_CANCEL_ON_SET` applies only to an absolute realtime timer: it records the wall-clock
  jump count; after a jump (the host's clock set, or the device resuming) the timer counts one
  expiration. The next read drops unread expirations, preserves any future deadline and returns
  `ECANCELED`. The guest cannot set the clock itself.
- read: a buffer under 8 bytes is `EINVAL`; returns the expirations passed (taking them), or waits
  on the timer's object with its deadline as the timeout (`EAGAIN` when nonblocking,
  `ERESTARTSYS` on a signal). A periodic timer advances by whole intervals, counting each.
  `timerfd_gettime` gives the interval and the time left (zeros when not armed).
- Readiness is `POLLIN` alone while expirations are pending (timerfd_poll); waits that include a
  timerfd take its next expiration as a deadline (see Waiting), as do exclusive gates and AIO
  polls watched by the timer thread.

### Signal-driven I/O

- Turning `O_ASYNC` on (`F_SETFL`, `FIOASYNC`) registers a `Fasync` entry only for the kinds whose
  Linux file operations have fasync (pipes and FIFOs, sockets, terminals, inotify, host fds); other
  kinds keep the flag and never raise `SIGIO`. Registering snapshots the current events (already-ready events are not signalled) and waking the timer
  thread.
- The timer thread's `check_fasync` drops entries whose file is gone or no longer `O_ASYNC`,
  clears reported read/write bits when the counters moved (`drained`, `reads` — bumped by read-file
  syscalls only — and arrivals), computes new events, adds host fds' not-yet-ready bits to its
  host poll, and sends: `SIGIO` with kernel siginfo, or the `F_SETSIG` signal with `POLL_*` code,
  band (Linux's band table) and fd (falling back to `SIGIO` with `SI_KERNEL` if an RT `F_SETSIG`
  signal fails to queue on `RLIMIT_SIGPENDING` overflow, matching Linux 6.1's `send_sigio_to_task`).
  Owners are a thread, process or process group
  (`send_to_owner`), stored as global ids with the setter's real and effective user IDs; a thread
  owner, or a process through its main thread's credentials (the process's once that thread is
  gone), gets the signal only when that effective ID is root or either ID is its real or saved user
  ID (Linux's `sigio_perm`, checked for each process of a group).

## Dependencies (inbound / outbound)

### Inbound

- The syscall dispatcher (also the drain hook after I/O syscalls; timerfd reads through
  `kernel/fileio`'s read path); `kernel/procfs` (timerfd fdinfo); `kernel/aio` (`poll_once`,
  `wait_aio_polls`, `watch_aio_poll`, masks, resfd eventfds); the timer thread (`check_exclusive`,
  `check_fasync`); fcntl/ioctl (`register_fasync`); pipe writes (`arrived`); lease breaks
  (`send_to_owner`); fdinfo and kcmp.

### Outbound

- `itimer` (`Expiry`, `clock_epoch`) and the time-namespace offsets for timerfd; `CAP_WAKE_ALARM`
  (`kernel/cred`).
- The kernel's waits (`wait_objects`, `block_for`, `interrupted`), wake objects and channels,
  `edge_waiters`; `appine_hal::poll` and `appine_hal::Edges` (host epoll); per-kind readiness
  functions in `net`, `unix`, `tty`, `kernel/inotify`, signalfd, message queues, seccomp; signals
  (`send_to_task`, `send_to_group`, `send_to_pgrp`).

## Invariants and gotchas

- Readiness checks can update timerfd expirations, rebase the shared syslog cursor after records
  were overwritten, and dispatch host errors on tapped UDP sockets. A scan must preserve any
  guest-known readiness bits returned alongside a host fd.
- Generation counters only grow; anything that changes readiness must bump a counter and wake its
  object, or edge-triggered waiters miss events.
- Without `HostEdges` (host regular files) only drains re-arm host-fd edges.

## Confirmed bugs / technical debt

- None.

## Open questions

- None.

## To verify

- Linux 6.1 comparisons above come from knowledge of `fs/select.c`, `fs/eventpoll.c`,
  `fs/eventfd.c`, `fs/timerfd.c`, `fs/fcntl.c` and `fs/pipe.c`, not a source checkout; the bits
  anonymous fds report were also observed on a native 6.8 kernel.
