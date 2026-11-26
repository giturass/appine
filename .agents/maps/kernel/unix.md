# kernel/unix Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/unix.md` for the paired decision history.
>
> Verified: 2026-11-23 (full mapping: 4 research concerns; 12 claims checked by 2 independent verifiers — 10 confirmed and 2 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: receive-time sender addresses, cross-netns pending embryos in `/proc/net/unix`, `truesize` accounting for `SIOCOUTQ`/datagrams/seqpacket, and Linux-verified `SOCK_SEQPACKET` `EPIPE` without `SIGPIPE`)

## Responsibilities

`kernel/unix` emulates `AF_UNIX` sockets entirely inside the kernel layer, never touching host
sockets:

- stream, datagram and seqpacket sockets and `socketpair`;
- pathname names (`S_IFSOCK` nodes in the store/overlay), abstract names and autobind;
- connection lifecycle: `listen`, `connect`, `accept`, `shutdown`, `close`/`Drop`;
- data transfer with merge/boundary rules, `SCM_RIGHTS` with guest open files, `SCM_CREDENTIALS`
  and `SO_PEERCRED` with guest ids;
- socket options, poll/epoll readiness, wake objects, edge-triggered arrivals, `FIONREAD`/`SIOCOUTQ`, and
  `/proc/net/unix` enumeration;
- a `unix_gc`-style collector breaking `Rc` cycles through in-flight `SCM_RIGHTS` messages, plus
  in-flight snapshots for `/proc/net/unix`, unmount, detached mount collection, read-only remounts
  and host-unshare rehoming.

Root: `core/kernel/src/unix.rs`, `core/kernel/src/syscall/unix.rs`.

Outside the module: the generic socket syscalls, address/msghdr marshaling and `SockOpts` that
dispatch here (`kernel/net`); creating socket nodes and path resolution (`kernel/vfs`,
`kernel/store`, `kernel/overlay`); fd tables (`kernel/files`); poll/epoll mechanics
(`kernel/poll`); `/proc/net` file structure (`kernel/procfs`); waiting (`kernel/process`).

## Key types

- `UnixSocket` — socket type (`ty`), shared bound address cell `addr: AddrRef` (`Rc<RefCell<Vec<u8>>>`), `link: Link`, datagram/listener-wait
  channel `rx: ChannelRef`, `peer_cred: Option<Ucred>`, `rcvtimeo`/`sndtimeo`,
  `shut_wr`, `connections` arrival counter, `embryo` flag (unaccepted server end), `net:
  Option<Rc<NetNs>>` (`Some` only for non-initial netns), recorded generic `SockOpts`
  (`kernel/net`), and `outq: Rc<SenderState>` (sharing the live `addr: AddrRef` and `SIOCOUTQ`
  `truesize` counter with outgoing packets).
- `Link` — `None`, `Listening { backlog, pending, cred }`, `Stream { rx, tx, peer_addr }`,
  `Dgram { tx: Weak<RefCell<Channel>>, peer_addr }`, where `peer_addr: AddrRef` shares the peer's
  address cell so post-connect `bind()` is visible to `accept()` and `getpeername()`.
- `Channel` (`ChannelRef = Rc<RefCell<Channel>>`) — one direction: `packets: VecDeque<Packet>`,
  the receiving socket's `passcred`, `bytes` (payload bytes for `FIONREAD` and stream `CAPACITY =
  212_992`), `truesize` (queued packet `truesize` sum for `has_packet_room()` and `writable()`),
  `eof`, `closed`, `arrivals`/`taken`, `max_qlen`
  (datagram queue cap, default `10`), `peer: Option<Weak<RefCell<Channel>>>` (set by
  `set_dgram_link`; `None` unconnected, `Some` connected so `may_receive_from` distinguishes
  unconnected from connected to a dead third socket), `established` (Linux's datagram
  `TCP_ESTABLISHED` state for `/proc/net/unix`), and `reset` (one-shot pending `ECONNRESET`).
  `Packet` holds `data`, `off`, `fds: Vec<FileRef>`, `cred: Ucred`, fallback `from: Vec<u8>`, and
  `outq: Option<Rc<SenderState>>` (resolving `addr` at receive time and uncharging
  `packet_truesize(data.len())` (>= 768 B) when popped/dropped).
  `Received` holds `data`, untruncated `len`, `fds`, `cred` and `from`.
- `Ucred` — kernel-space `(pid, uid, gid)` (global tgid, kuid, kgid) with 12-byte LE encoding.
- `Name` — `Path(Ino)` or `Abstract(net_id, ty, bytes)`; `Names` (`Kernel::unix`) maps `Name` to
  `Weak<RefCell<Socket>>`, holds the kernel-wide `next_auto` counter, and tracks pending
  unaccepted server `embryos: Vec<Weak<RefCell<Socket>>>` so `inflight_sockets` surfaces them to
  `/proc/net/unix` under each embryo's own network namespace without borrowing any socket `RefCell`.
- `Kernel::unix_sending` holds weak references to `SendingRights`. A send with SCM_RIGHTS owns its
  files from control-message validation until the first packet takes them or the send fails.
- `Kernel::unix_inflight` — `Vec<Weak<RefCell<Channel>>>` of channels carrying `SCM_RIGHTS` fds.
- `Kernel::unix_receiving` holds weak references to `PendingRights` deliveries. Each delivery owns
  its files and reserved descriptor numbers until recvmsg finishes its output copies.

## Public entry points

- `syscall::unix::{socket, pair, max_dgram_qlen, bind, listen, accept, connect, send, recv,
  recv_into, setsockopt, getsockopt, sockname, shutdown}`, dispatched from
  `kernel/net`'s socket syscalls and socket read/write/splice paths.
- `UnixSocket::{readiness, wake_objects, arrivals, unread, outq}` for `kernel/poll`, `FIONREAD`
  and `SIOCOUTQ`.
- `unix::released` (from `close`, `close_range`, `dup3`, `close_replaced`/seccomp `addfd`,
  `execve`/`execveat`, `deliver` `MSG_CTRUNC`/`EMFILE`, AIO `io_cancel`/`released`),
  `unix::defer_collect`/`take_deferred`/`collect_deferred`/`is_unix_file` (`UnixSocket::drop`,
  AIO `complete_polls`/`check_polls`, syscall dispatch end), `unix::collect` (also at `task::exit`
  when `last || fds_gone || take_deferred()`), `unix::proc_listing`, `unix::inflight_sockets`
  (`/proc/net/unix`) and `unix::inflight_files` (`sb_busy` remount checks and `opens_of`
  host-unshare rehoming). Mount accounting uses `try_inflight_files` so teardown can retry if a
  channel is borrowed.

## Data flow / lifecycle

### Creating sockets and naming

- `socket` / `socketpair`: protocol must be 0 or `AF_UNIX` (1), else `EPROTONOSUPPORT`; types are
  `SOCK_STREAM`, `SOCK_DGRAM`, `SOCK_SEQPACKET` (`SOCK_RAW` maps to `SOCK_DGRAM`; others
  `ESOCKTNOSUPPORT`). Non-initial network namespaces are recorded on `u.net`, and `max_qlen` is
  initialized from the caller's `net.unix.max_dgram_qlen` sysctl (default 10). `socketpair`
  connects both ends (using `set_dgram_link` for datagrams so `rx.peer` exempts the peer from
  `max_qlen`) and stamps both with `cx.ucred()` (`tgid`, `euid`, `egid`).
- Addresses: generic `read_addr` caps at 128 bytes (`EINVAL`); `parse` requires `2..=110` bytes
  and `AF_UNIX`. Length 2 is unnamed; leading NUL in `sun_path` is abstract (all bytes kept);
  otherwise a pathname cut at the first NUL.
- `bind`: already bound -> `EINVAL`.
  - Unnamed: `Names::autobind` tries up to `2^20` sequential `\0%05x` names (starting at `\000001`)
    per `(net_id, ty)`, returning `ENOSPC` when exhausted.
  - Abstract: inserts `Name::Abstract(net_id, ty, bytes)` (`EADDRINUSE` while a live socket of
    the same namespace and type holds it).
  - Pathname: calls `reject_trailing_slash` (`ENOENT` if missing, `EADDRINUSE` if existing),
    resolves parent via `create_parent_at` (copying up overlay parent if needed), rejects
    `.`/`..` (`EADDRINUSE`), runs `may_create` (`MAY_EXEC`, `!exists_in` -> `EADDRINUSE`, `!ro` ->
    `EROFS`, `MAY_WRITE|MAY_EXEC`), limits mode 0777 by the parent default ACL or umask with setgid-directory rules, reserves
    tmpfs room (`ENOSPC`), creates an `S_IFSOCK` inode, emits `IN_CREATE` (including on overlay
    dir), and inserts `Name::Path(ino)`.
- With `SO_PASSCRED` enabled, an unnamed socket autobinds on connect to a valid peer address.
  Datagram sends and connected seqpacket sends also autobind, so a receiver can reply to the
  sender's abstract address. Enabling the option alone leaves the socket unnamed.
- Path names key strictly by store `Ino` (shared across network namespaces, surviving hard links,
  bind mounts and renames; inode stays on disk after socket drop); abstract/autobind names scope by
  `(net_id, ty)` and expire with their `Weak` reference.

### Connections, shutdown and close

- `listen`: datagram -> `EOPNOTSUPP`; unbound or connected -> `EINVAL`; backlog clamped to 4096
  (negative -> 4096). Records `cx.ucred()` on every call; re-listening with a larger backlog wakes
  blocked connectors on `u.rx`.
- `connect` (stream/seqpacket): listening -> `EINVAL`, already connected -> `EISCONN`. Resolves
  target by abstract `(net_id, ty, bytes)` or by pathname (following symlinks; checks `MAY_WRITE`
  `EACCES` before `S_IFSOCK` `ECONNREFUSED`; wrong Unix type -> `EPROTOTYPE`;
  self or not listening -> `ECONNREFUSED`). When `pending.len() <= backlog` (capacity `backlog +
  1`), creates a server embryo (`embryo = true`, inheriting the *client's* `net`, listener's
  `addr`, and exchanging `cx.ucred()`/`server_cred`), pushes it onto `pending`, bumps
  `server.connections` and wakes both `server.rx` and `client.rx`. Full backlog blocks via `block`
  bounded by `SO_SNDTIMEO`.
- `accept`: non-listening -> `EINVAL`; pops front embryo, clears `embryo`, inherits listener's
  `SO_PASSCRED` (not timeouts or `SockOpts`), wakes `u.rx`, and returns peer name (2-byte
  `unnamed()` when client unbound). Waits bounded by `SO_RCVTIMEO`.
- Datagram connect is non-blocking. `connect` handles `AF_UNSPEC` before autobind and
  disconnects via `set_dgram_link(Link::None)`. Otherwise `connect_dgram` resolves the target (`EPROTOTYPE` if not
  datagram; self-connect allowed), checks `unix_may_send` (target connected to another socket ->
  `EPERM`), and installs `Link::Dgram` (does not set `peer_cred`). `set_dgram_link` marks both
  ends `established = true` on connect; when leaving a different previous peer (disconnect,
  reconnect to another peer, or dead-peer disconnect on send), it purges `self.rx` (returning any
  `SCM_RIGHTS` fds to release after borrows end and waking writers), clears the previous peer's
  `established` if that peer is unconnected, and if `self.rx` had unread messages and the previous
  peer is still connected back to this socket, sets `reset = true` (`ECONNRESET`) and wakes it
  (Linux's `unix_dgram_disconnected`).
- `shutdown`: `how` outside `0..=2` -> `EINVAL`; succeeds on any state. On `Link::Stream`,
  `SHUT_RD` sets `rx.eof = true` and `rx.closed = true` (peer writes get `EPIPE`), `SHUT_WR` sets
  `tx.eof = true` (peer reads EOF and polls `POLLIN|POLLRDHUP`, plus `POLLHUP` once both sides are
  shut); on unconnected/listening/datagram sockets, `SHUT_RD` sets `self.rx.eof` and `SHUT_WR`
  sets local `self.shut_wr`.
- `close` / `Drop`: wakes waiters; on `Link::Stream`, sets `tx.eof = true`, sets `tx.reset |=
  self.embryo || !rx.packets.is_empty()`, and discards `rx` (dropping queued packets *after*
  releasing all `RefCell` borrows). Dropping a listener drops all pending embryos (each setting
  `reset = true` on its client). Peer observes `reset` once as `ECONNRESET` on `recv` (before
  queued data on `SOCK_SEQPACKET` and `SOCK_DGRAM`, after draining on `SOCK_STREAM`) or
  `SO_ERROR`, and `POLLERR` until consumed. Closing a datagram socket never resets a connected
  peer (next send disconnects it with `ECONNREFUSED` and purges its own queue, then `ENOTCONN`).

### Sending, receiving and ancillary data

- Control messages on send (`rights`): 16-byte headers, 8-byte alignment, front-end cap 4096 B
  (data capped at `MSG_MAX = 1 MiB` per call); trailing 1..15 bytes ignored; invalid header lengths
  (`len < 16 || len > remaining`) -> `EINVAL`; non-`SOL_SOCKET` control messages are skipped after
  length validation (matching Linux's `__scm_send`); unknown `SOL_SOCKET` types -> `EINVAL`.
  `SCM_RIGHTS`: at most `253` fds total (`EINVAL`/`EBADF`).
  `SCM_CREDENTIALS`: exact length 28; validates `uid_in`/`gid_in` (`EINVAL`), pid/uid/gid match or
  `CAP_SYS_ADMIN` (over `pid_ns.owner`)/`CAP_SETUID`/`CAP_SETGID` (`EPERM`), and live task
  existence (`ESRCH`). Explicit credentials are recorded on the packet. Otherwise each enqueue
  records the sender's tgid and real uid/gid if either endpoint has `SO_PASSCRED` enabled or the
  receiving connection is awaiting accept. Other packets carry `Ucred::UNSTAMPED`.
- Send paths (each packet shares the sender's `AddrRef`, so `recvfrom`/`recvmsg` read the
  sender's current bound address at receive time even if bound after send or closed before receive):
  - `SOCK_STREAM`: destination address -> `EISCONN` (connected) or `EOPNOTSUPP` (unconnected);
    peer gone -> `epipe` (`EPIPE` + `SIGPIPE` unless `MSG_NOSIGNAL`) or partial count; loops pushing
    available space (files attached to first chunk; a zero-byte send carrying files requires
    `c.space() > 0` and, when `c.bytes == 0`, `c.has_packet_room()`, waiting or returning `EAGAIN`
    when full) and blocking on `tx`.
  - `SOCK_SEQPACKET` (never raises `SIGPIPE`, matching Linux's `unix_seqpacket_sendmsg` ->
    `unix_dgram_sendmsg`): ignores destination address; peer gone / `SHUT_WR` -> `EPIPE` without
    `SIGPIPE`; `len > DGRAM_MAX_LEN (212_960)` -> `EMSGSIZE`; waits until `c.has_packet_room()`
    (`c.truesize < CAPACITY`).
  - `SOCK_DGRAM` (never raises `SIGPIPE`): local `shut_wr` -> `EPIPE`; dead connected peer
    disconnects (`ECONNREFUSED`, then `ENOTCONN`); both addressed and connected unaddressed sends
    check `unix_may_send` (`c.may_receive_from(&own_rx)`, `EPERM`);
    target `c.eof` (`SHUT_RD`) -> `EPIPE`; `len > DGRAM_MAX_LEN (212_960)` -> `EMSGSIZE`; waits
    until `c.has_packet_room()` (`c.truesize < CAPACITY`) and `!c.holds_back(&own_rx)` (holding
    more than `max_qlen` packets unless target is connected back to sender, so `max_qlen + 1` queue
    and the next waits).
- Receive paths:
  - `SOCK_STREAM` (`unix::recv_into`, used by `recvmsg`, `recvfrom`, `read` and `readv`): peeks from
    `Channel` and copies into guest iovecs via `net::scatter_partial` *before* consuming, consuming
    only the copied byte count on partial copy fault (leaving unread bytes intact) or `EFAULT` when
    nothing was copied. `MSG_TRUNC` is ignored on `SOCK_STREAM` (matching Linux's
    `unix_stream_read_generic`, unlike TCP). `MSG_WAITALL` loops until full (capped at 1 MiB), receipt of files,
    a credential change once the read has taken credentials, reset (left pending on a partial read),
    EOF or error/timeout. A waiting read can start taking credentials when the option is enabled.
    Once taken, they delimit the rest of that read even if the option is then disabled.
  - `Channel::read_stream` merges packets in order, taking `from` from the first packet, stopping
    after a packet with `fds`. When the receiver has `SO_PASSCRED` enabled, it also stops before
    a packet whose `cred` differs. Zero-length non-`MSG_PEEK` `recv*` on a non-empty queue returns 0
    immediately while taking the head packet's `fds` (whereas zero-length `read` short-circuits in
    `net::rw` and zero-length `readv` short-circuits earlier in `fs::vectored`). `MSG_PEEK` clones
    `fds` without consuming or waking writers.
  - `SOCK_DGRAM` / `SOCK_SEQPACKET` (`Channel::read_packet`): peeks/copies into user iovecs, setting
    `MSG_TRUNC` when truncated and returning full `m.len` when input `flags & MSG_TRUNC != 0`; on
    `EFAULT` consumes and drops the packet (releasing any `fds` via `unix::released`), while
    `FUSE_RETRY` leaves it queued for retry.
- Ancillary delivery (`deliver` / `put_cmsg`): `SCM_CREDENTIALS` first when `passcred` is set
  (translated via `pid_out`, `uid_out`/`gid_out` with overflow 65534; truncated with `MSG_CTRUNC`
  if buffer is 16..27 B), then `SCM_RIGHTS` reserving as many descriptor numbers as fit.
  Enabling `SO_PASSCRED` after enqueue reports pid 0 and overflow uid/gid for unstamped packets.
  A NULL control buffer supplies zero room. Buffer and fd limits set `MSG_CTRUNC` and excess
  files are released. Reserved numbers remain unavailable to other threads during a FUSE fill.
  After the control and header copies succeed, recvmsg installs each file with the requested
  `MSG_CMSG_CLOEXEC`. An unwritable control buffer drops the reservations and returns the data
  with `MSG_CTRUNC` and zero control length. A failing header copy also releases the reservations.
- `block()` interruption: timed waits (`SO_RCVTIMEO`/`SO_SNDTIMEO`) interrupted by a signal return
  `EINTR`; untimed waits return `ERESTARTSYS` (partial stream sends and `MSG_WAITALL` reads return
  moved bytes instead).

### Options, readiness and `/proc/net/unix`

- `setsockopt` / `getsockopt`: non-`SOL_SOCKET` -> `EOPNOTSUPP`. Handles `SO_PASSCRED`,
  `SO_RCVTIMEO`/`SO_SNDTIMEO` (plus `*_NEW` folded in `kernel/net`, shared `net::timeval`),
  `SO_TYPE`, `SO_DOMAIN` (1), `SO_PROTOCOL` (0), `SO_ERROR` (consumes pending `ECONNRESET` once
  via `receive_queue()` for stream, seqpacket and datagram sockets), `SO_ACCEPTCONN`,
  `SO_PEERCRED` (listener's `listen`-time creds or `u.peer_cred` set by
  `socketpair`/`connect_stream` and never cleared or updated by `connect_dgram`, translated into
  caller namespaces; `(0, -1, -1)` when `None`, such as unconnected or `connect_dgram`-connected
  `socket()`-created datagrams, while `socketpair(SOCK_DGRAM)` sockets keep their original creds
  across `AF_UNSPEC` disconnect or reconnection), and recorded generic `SockOpts` (buffer sizes,
  `SO_RCVLOWAT`, linger, keepalive, priority, etc., with no runtime effect). `setsockopt` rejects
  read-only `SO_SNDLOWAT`, `SO_ACCEPTCONN` and `SO_PEERCRED` (as well as `SO_TYPE`, `SO_ERROR`,
  `SO_PROTOCOL`, `SO_DOMAIN` via `SockOpts`) with `EINVAL` for `< 4` bytes and `ENOPROTOOPT`
  otherwise; other unknown `SOL_SOCKET` names are silently ignored by `setsockopt` and return
  `ENOPROTOOPT` from `getsockopt`. `getsockname`/`getpeername` return `u.name()`/`peer_name()`
  (reading the live shared `AddrRef`; `ENOTCONN` if unconnected/listening).
- Readiness: `POLLIN|POLLRDNORM` on queued data, EOF or pending accepts; `POLLOUT|POLLWRNORM` when
  `truesize * 2 <= CAPACITY` for datagram/seqpacket (`packet_budget`) or `bytes * 4 <= CAPACITY`
  (plus `truesize * 2 <= CAPACITY` when `bytes == 0`) for stream (or `tx.closed`, or unconnected
  stream with `POLLHUP`), and for connected datagrams when peer is neither full nor `holds_back`
  (ignoring peer `SHUT_RD`, matching Linux's `unix_dgram_poll`); `POLLRDHUP`/`POLLHUP` from shutdown
  state;
  `POLLERR` while `rx.reset` is set (on stream, seqpacket and datagram sockets). `wake_objects`
  registers `self.rx` plus `Stream`'s `rx`/`tx` or live `Dgram` `tx`; `arrivals` exposes
  `[connections, 0]` for listeners and `[rx.arrivals, tx.taken]` for channels. `FIONREAD` uses
  `unread()` (`rx.bytes` payload bytes for stream/seqpacket, head packet length for datagram,
  `EINVAL` for listener); `SIOCOUTQ` (`TIOCOUTQ`) uses `outq()` (queued packet `truesize` bytes
  sent by this socket still in peer buffers, >= 768 B per packet; 0 on listeners).
- `/proc/net/unix`: collects sockets from all tasks' fd tables plus `unix::inflight_sockets` (which
  includes both `SCM_RIGHTS` in-flight sockets and tracked pending server embryos from
  `Names::embryos`), filtered by target task's netns, sorted by `socket_ino`. State 1 for
  unconnected/listening (`Flags = 0x10000` on listeners), 3 for connected streams and datagram
  sockets with `rx.established`, and state 2 (`Inode = 0`, listener address) for `u.embryo` rows in
  each embryo's own (connector's) network namespace; abstract names printed with `@` (interior NULs
  as `@`).

### Garbage collection (`unix::collect`)

- Channels carrying `SCM_RIGHTS` register weak refs in `Kernel::unix_inflight` via `note_inflight`.
  File and socket snapshots include pending sends, queued packets and pending recvmsg deliveries.
  Pending sends and deliveries hold external references for cycle collection. A failed send that
  still owns files, or a cancelled delivery holding a Unix socket, schedules deferred collection.
- `unix::released` drops closed files and runs `unix::collect` when any was an AF_UNIX socket
  (called from `close`, `close_range`, `dup3`, `close_replaced`/seccomp `addfd`, `exec`, AIO
  `io_cancel`/`released`, `deliver` truncation, datagram `EFAULT` drop). `UnixSocket::drop` (when
  dropping packets carrying `fds` or pending embryos) and AIO `complete_polls` set a thread-local
  `DEFERRED_COLLECT` flag (`defer_collect`), drained via `collect_deferred` at the end of syscall
  dispatch (covering `accept4` address-write failures and socket drops) and in AIO `check_polls`;
  `task::exit` runs `collect` whenever `(last || fds_gone || take_deferred()) && !unix_inflight.is_empty()`
  (covering non-last thread exit after `unshare(CLONE_FILES)`), and `collect` loops while
  `take_deferred()` handles cascading drops.
- Algorithm: prunes dead/fd-free channels; counts in-flight references per `FileRef`; selects
  AF_UNIX candidates where `Rc::strong_count(f) == inflight_count + 1`; subtracts references from
  candidates' own `inboxes` (`u.rx`, `Stream::rx`, and pending embryos' `Stream::rx`); marks
  candidates with remaining external refs and all transitively reachable candidates; empties
  unreachable candidates' inboxes into a local `garbage: Vec<Packet>` and drops `inflight` then
  `garbage` after releasing all borrows.
- Epoll `Interest`/`ExGate`/`Fasync`, OFD locks and inotify `doomed` hold `Weak<RefCell<OpenFile>>`
  so they never pin cycles; `socket_of` (all socket syscalls), `read_file`/`write_file`/
  `splice_read`, `ppoll`/`pselect6`, `epoll` `EPOLLEXCLUSIVE` waits, `sendmsg` passed `files` and
  AIO `PendingPoll` hold strong `FileRef`s.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/net`: socket syscalls, `Socket::Unix`, `rw`, ioctl (`FIONREAD`), readiness/wake/arrivals,
  `accept4` fd reservation and `recvmsg` installation of pending rights.
- `kernel/files` (`close`, `close_range`, `dup3`, `close_replaced`, `OpenFile::drop`, `splice_read`,
  `opens_of` -> `inflight_files`), `kernel/exec` (`exec` cloexec), `kernel/process` (last-thread
  `task::exit`), `kernel/cred` (seccomp `addfd`), `kernel/mount` (busy checks and collection),
  `kernel/procfs` (`/proc/net/unix`).

### Outbound

- `kernel/vfs`, `kernel/store`, `kernel/overlay`, `kernel/inotify`: `create_parent_at`,
  `lookup_at`, `may_create`, `create_in`, `tmpfs_reserve`/`tmpfs_created`, `created_events`,
  `mknod`.
- `kernel/net`: `SockOpts`, `Message`, `put_cmsg`, `epipe`, `timeval`, `netconf::sysctl_read`.
- `kernel/files`, `kernel/cred`, `kernel/ns`, `kernel/process`, `kernel/signal`, `kernel/procfs`:
  `FdTable`, `Cred`, `PidNs`/`NetNs`, `Cx::wait_objects`/`interrupted`, `request_wake_object`,
  `pseudo::socket_ino`.

## Invariants and gotchas

- All `Rc`/`RefCell` counts, `unix_inflight` mutations and `collect` runs assume the single-threaded
  BKL. `UnixSocket::drop` and `unix::collect` must drop queued `Packet`s only after all `RefCell`
  borrows end to avoid double-borrow panics when `SCM_RIGHTS` files drop sibling sockets.
- `OpenFile::drop` skips `wake::of(s)` for `Socket::Unix` because `UnixSocket::drop` wakes its own
  channels.
- `Ucred` always stores global `pid` and kernel `uid`/`gid`, translating into the reader's pid and
  user namespaces only at delivery (`SCM_CREDENTIALS`, `SO_PEERCRED`).
- Accepted sockets inherit the *connector's* `NetNs`, not the listener's. Pathname sockets cross
  network namespaces; abstract/autobind names isolate by `(net_id, ty)`.
- Zero-length `read` short-circuits in `net::rw` and zero-length `readv` short-circuits earlier in
  `fs::vectored` without detaching head `SCM_RIGHTS` fds, whereas zero-length non-`MSG_PEEK`
  `recv`/`recvfrom`/`recvmsg` detaches them.
- `unix::collect` emptying an unreachable stream socket's inbox before `UnixSocket::drop` suppresses
  `ECONNRESET` to an open peer (the peer sees EOF instead).

## Confirmed bugs / technical debt

- **Smaller Linux divergences:** `SO_SNDBUF`/`SO_RCVBUF` and `SO_RCVLOWAT` are recorded only (the
  channel capacity stays `CAPACITY = 212_992`); `packet_truesize` approximates Linux's slab/page
  buckets rather than exact kernel `sk_buff` allocations for payloads above 4 KiB, and `SOCK_STREAM`
  write room still caps by payload `CAPACITY` rather than `truesize`.

## Open questions

None currently recorded.

## To verify

- Linux 6.1 comparisons above for receive-time sender addresses, `SOCK_SEQPACKET` `SIGPIPE`,
  `SIOCOUTQ`/`truesize` and `DGRAM_MAX_LEN` were verified empirically against Linux; differential
  tests cover common paths natively.
