# kernel/rawicmp Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/rawicmp.md` for the paired decision history (not yet created; decisions from before the split are D2, D22 and the raw-ICMP parts of D9, D12, D18 and D19 in `.agents/decisions/kernel/net.md`).
>
> Verified: 2026-11-22 (split out of the kernel/net full mapping of 2026-11-11; the boundary was checked against the source at the split)

## Responsibilities

`kernel/rawicmp` emulates guest raw ICMP and ICMPv6 sockets on unprivileged host ping sockets,
including traceroute's ICMP errors:

- per-socket raw ICMP state (`ICMP_FILTER`, guest `IP_RECVTTL`/`IP_PKTINFO`/`IP_RECVERR`/
  `IPV6_CHECKSUM`, echo-id tracking);
- per-namespace aggregation points (`Tap`) on a host epoll watching ping sockets and TTL-limited
  UDP probe sockets;
- rebuilding full ICMP error messages, restoring guest echo ids, synthesizing IPv4 headers and
  fanning messages out to every matching raw socket in the namespace;
- the raw-ICMP receive and error-draining paths (`raw_recv`, `take_errors`).

Root: `core/kernel/src/rawicmp.rs`, and `raw_recv` and `take_errors` in
`core/kernel/src/syscall/net.rs`.

Outside the module: socket creation, bind/getsockname/option/send/recv/readiness dispatch and
`InetSocket` fields (`kernel/net`); namespace address translation (`kernel/netns`); the timer
thread's periodic tap polling (`kernel/time`); poll/epoll readiness plumbing (`kernel/poll`); host
socket and epoll `Watch` wrappers (`hal`).

## Key types

- `RawIcmp` — per raw socket: family, last guest echo id, `ICMP_FILTER`, guest `IP_RECVTTL`,
  `IP_PKTINFO` and `IP_RECVERR`, `IPV6_CHECKSUM`, and its `Tap`.
- `Tap` — per-namespace aggregation point on a host epoll: sources and receivers; held weakly in
  `Kernel::icmp_taps`.
- `Source` — one host fd watched by a `Tap` (a raw socket's ping socket, or an error-only UDP
  socket that set a TTL).
- `Receiver` — per raw socket delivery state: data queue, byte count, arrivals and error queue
  (`Item` / `ErrItem`).

## Public entry points

- `rawicmp::{tap_for, register, udp_setsockopt, before_io, untap, dispatch, check_taps}` and
  `RawIcmp::{sent, setsockopt, getsockopt, present}`.
- `raw_recv` and `take_errors` in `core/kernel/src/syscall/net.rs` (called from `kernel/net`'s
  socket receive and send/option paths).

## Data flow / lifecycle

### Creation, binding and options

- `kernel/net`'s `socket` creates a raw ICMP (`AF_INET`, `IPPROTO_ICMP`) or raw ICMPv6 (`AF_INET6`,
  `IPPROTO_ICMPV6`) socket when the caller has `CAP_NET_RAW` over the network namespace's owner: it
  opens a host ping socket (host `SOCK_DGRAM`) with host `IP_RECVTTL`, `IP_PKTINFO` and
  `IP_RECVERR` (or `IPV6_RECVERR`), and registers it with its namespace's `Tap` (created on demand;
  the timer thread waits on every `Tap`'s epoll fd and dispatches them all on each wake).
- Binding drops the port (an already-bound raw socket bound again to the same address succeeds
  without binding again on the host); getsockname reports the protocol number; `SO_TYPE` reports
  `SOCK_RAW`. nftables nat and filters do not apply to raw ICMP sockets; namespace address
  translation does.
- Raw ICMP options (`RawIcmp::setsockopt`/`getsockopt`): `ICMP_FILTER`, `IP_RECVTTL`, `IP_PKTINFO`,
  `IP_RECVERR`/`IPV6_RECVERR`, `IPV6_CHECKSUM` (recorded only); other `SOL_RAW` names are
  `ENOPROTOOPT`. `SO_ERROR` reports pending ICMP errors first.

### Sending and UDP probe tapping

- Sending records the guest's echo id (`RawIcmp::sent`: one per socket, the last echo request of
  8 bytes or more sent, recorded even if the send fails) and passes the ICMP message to the host
  unchanged (no IP header); the host enforces echo-only and rewrites the id. An ICMP error already
  recorded for the socket fails the send; a host error that ICMP can cause makes `kernel/net` drain
  the socket (`take_errors`) and retry once.
- On UDP sockets, `IP_TTL`/`IPV6_UNICAST_HOPS` is recorded for the taps (still passed to the host),
  and `IP_RECVERR`/`IPV6_RECVERR` is intercepted while a tap watches the socket (`udp_setsockopt`).
- UDP sockets that set a TTL are tapped lazily at their next send, recv or `SO_ERROR` (`before_io`)
  when a raw socket of the same family exists in the namespace and the guest has not enabled
  `IP_RECVERR` itself: host `IP_RECVERR` is turned on and the fd becomes an error-only source;
  connected UDP sockets sending elsewhere are reconnected on the host; the tap is removed (`untap`)
  when the guest turns `IP_RECVERR` on, or at the next I/O once no raw socket is left.

### Dispatch and receiving

- `dispatch` drains error queues (skipping non-ICMP entries) and rebuilds whole ICMP error messages
  (quoted IP header, quoted UDP header or echo request with the guest id restored, checksums),
  applies Linux's `sk_err`/`IP_RECVERR` rules (with `IP_RECVERR` every error is queued, at most
  64; without it only hard errors from the connected peer set the socket error), then drains echo
  replies, restoring an id that is some raw socket's host ident to that socket's last guest id.
  Every live raw socket of the same family whose `ICMP_FILTER` passes gets a copy of replies and
  errors (queue capped at 212992 bytes of ICMP data, overflow dropped).
- `raw_recv` / `RawIcmp::present` prepends a synthesized IPv4 header (TTL from the host, protocol
  1, translated source, `IP_PKTINFO` destination, checksum) or returns ICMPv6 as is;
  `IP_PKTINFO`/`IP_TTL` control messages only when enabled, other control messages only for what
  reached the socket's own ping socket; `MSG_TRUNC`/`MSG_CTRUNC` as Linux; `MSG_ERRQUEUE` returns
  the socket's own errors (`EAGAIN` at once when there are none).
- Readiness comes from the receiver queues (`POLLOUT` always, `POLLERR` while errors are pending).

## Dependencies (inbound / outbound)

### Inbound

- `kernel/net`: socket creation, bind, getsockname, options (`ICMP_*`/`SOL_RAW`, `SO_ERROR`,
  `SO_TYPE`, UDP TTL/`IP_RECVERR` hooks), send (`before_io`, `sent`, `take_errors`), recv
  (`raw_recv`), readiness and `InetSocket` drop cleanup (`untap`).
- `kernel/time`: the timer thread watches every `Tap`'s epoll fd and calls `check_taps`.

### Outbound

- `appine_hal::net` (host socket calls and epoll `Watch`).
- `kernel/net`: `InetSocket` fields, message/msghdr helpers, waits and wake objects.
- `kernel/netns`: address translation (`from_host`).

## Invariants and gotchas

- The raw ICMP id rewrite assumes one echo id per raw socket (the last one sent).
- `dispatch` of the raw ICMP taps must run with no socket borrowed.

## Confirmed bugs / technical debt

- **Raw ICMP keeps one echo id per socket:** every reply to a socket's ping ident is rewritten to
  the last id that socket sent, so programs using several ids on one socket (liboping) see them
  collapse; the queue cap ignores `SO_RCVBUF` and drops silently.
- **A raw ICMP socket shut down for reading still waits in recv:** the aggregation point's receive
  path does not look at the read shutdown, so a blocking recv with nothing queued sleeps until a
  reply, a timeout or a signal, where Linux's `skb_recv_datagram` returns 0 at once (and wakes
  receivers already waiting); only internet datagram sockets on host sockets return 0.
- **A raw socket cannot be bound to another address:** Linux's `raw_bind` lets a raw socket be
  bound any number of times; the host ping socket that emulates a raw ICMP socket refuses a second
  bind, so binding it again succeeds only for the address it already has (`EINVAL` otherwise).

## Open questions

- None.

## To verify

- That the host ping socket rewrites the id, rejects non-echo types and refuses a second bind.
