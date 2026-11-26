# kernel/rawicmp Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/rawicmp.md` for the paired decision history (not yet created; decisions from before the split are D2, D22 and the raw-ICMP parts of D9, D12, D18 and D19 in `.agents/decisions/kernel/net.md`).
>
> Verified: 2026-11-22 (split out of the kernel/net full mapping of 2026-11-11; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: raw ICMP receive queue honors `SO_RCVBUF`, and rebinding to another address atomically replaces the host ping socket with copied options)

## Responsibilities

`kernel/rawicmp` emulates guest raw ICMP and ICMPv6 sockets on unprivileged host ping sockets,
including traceroute's ICMP errors:

- per-socket raw ICMP state (`ICMP_FILTER`, guest `IP_RECVTTL`/`IP_PKTINFO`/`IP_RECVERR`/
  `IPV6_CHECKSUM`);
- per-namespace aggregation points (`Tap`) on a host epoll watching ping sockets and TTL-limited
  UDP probe sockets, tracking guest echo ids and sequences;
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

- `RawIcmp` — per raw socket: family, `ICMP_FILTER`, guest `IP_RECVTTL`,
  `IP_PKTINFO` and `IP_RECVERR`, `IPV6_CHECKSUM`, cached `SO_RCVBUF` byte limit (`rcvbuf`), and
  its `Tap`.
- `Tap` — per-namespace aggregation point on a host epoll: sources and receivers; held weakly in
  `Kernel::icmp_taps`. Its `Echoes` history matches wire sequences to successful requests.
- `Source` — one host fd watched by a `Tap` (a raw socket's ping socket, or an error-only UDP
  socket that set a TTL).
- `Receiver` — per raw socket delivery state: data queue, byte count, arrivals and error queue
  (`Item` / `ErrItem`).

## Public entry points

- `rawicmp::{tap_for, register, replace_source, udp_setsockopt, before_io, untap, dispatch, check_taps}` and
  `RawIcmp::{send, setsockopt, getsockopt, sync_rcvbuf, rcvbuf, present}`.
- `raw_recv` and `take_errors` in `core/kernel/src/syscall/net.rs` (called from `kernel/net`'s
  socket receive and send/option paths).

## Data flow / lifecycle

### Creation, binding and options

- `kernel/net`'s `socket` creates a raw ICMP (`AF_INET`, `IPPROTO_ICMP`) or raw ICMPv6 (`AF_INET6`,
  `IPPROTO_ICMPV6`) socket when the caller has `CAP_NET_RAW` over the network namespace's owner: it
  opens a host ping socket (host `SOCK_DGRAM`) with host `IP_RECVTTL`, `IP_PKTINFO` and
  `IP_RECVERR` (or `IPV6_RECVERR`), and registers it with its namespace's `Tap` (created on demand;
  the timer thread waits on every `Tap`'s epoll fd and dispatches them all on each wake).
- Binding drops the port. A connected raw socket (`peer.is_some()`) refuses rebind with `EINVAL`
  as in Linux's `raw_bind`/`rawv6_bind`; an already-bound unconnected raw socket bound again to the
  same host address succeeds without replacing the host fd (updating `any`/`vaddr` in new
  namespaces), while binding to a different host address atomically creates and binds a replacement
  host ping socket with host options copied (`SO_RCVBUF`/`SO_SNDBUF` halved to compensate for Linux
  doubling, socket/IP/IPv6 options, `SO_BINDTODEVICE`, classic BPF filter and lock), drains `old_fd`
  outside the socket borrow, swaps the source fd in `Tap` (`replace_source`, keeping the receiver
  queue intact), and closes `old_fd`. getsockname reports the protocol number; `SO_TYPE` reports
  `SOCK_RAW`. nftables nat and filters do not apply to raw ICMP sockets; namespace address
  translation does.
- Raw ICMP options (`RawIcmp::setsockopt`/`getsockopt`): `ICMP_FILTER`, `IP_RECVTTL`, `IP_PKTINFO`,
  `IP_RECVERR`/`IPV6_RECVERR`, `IPV6_CHECKSUM` (recorded only); other `SOL_RAW` names are
  `ENOPROTOOPT`. `SO_ERROR` reports pending ICMP errors first.

### Sending and UDP probe tapping

- `RawIcmp::send` gives each echo request a sequence on the wire. The host supplies its ping
  socket id and checksum. Each successful send records the family, host id, guest id and guest
  sequence in the namespace's tap before another thread can receive the reply. An ICMP error already
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
  replies. The wire sequence, family and host ping ident select the guest id and sequence for
  replies, quoted echo requests and original datagrams returned by `MSG_ERRQUEUE`.
  Every live raw socket of the same family whose `ICMP_FILTER` passes gets a copy of replies and
  errors (queue capped by the socket's `SO_RCVBUF`, synced from the host ping socket on create,
  `SO_RCVBUF`/`SO_RCVBUFFORCE`, and rebind; an empty queue always admits one packet, and overflow
  is dropped silently).
- `raw_recv` / `RawIcmp::present` prepends a synthesized IPv4 header (TTL from the host, protocol
  1, translated source, `IP_PKTINFO` destination, checksum) or returns ICMPv6 as is;
  `IP_PKTINFO`/`IP_TTL` control messages only when enabled, other control messages only for what
  reached the socket's own ping socket; `MSG_TRUNC`/`MSG_CTRUNC` as Linux; `MSG_ERRQUEUE` returns
  the socket's own errors (`EAGAIN` at once when there are none).
- Readiness comes from the receiver queues (`POLLOUT` always, `POLLIN | POLLRDNORM` when queued or
  `rd_shut` is set, `POLLERR` while errors are pending). On `SHUT_RD`, `shutdown` wakes waiting
  receivers and a blocking `raw_recv` with an empty queue returns 0 at once (nonblocking stays
  `EAGAIN`).

## Dependencies (inbound / outbound)

### Inbound

- `kernel/net`: socket creation, bind, getsockname, options (`ICMP_*`/`SOL_RAW`, `SO_ERROR`,
  `SO_TYPE`, UDP TTL/`IP_RECVERR` hooks), send (`before_io`, `RawIcmp::send`, `take_errors`), recv
  (`raw_recv`), readiness and `InetSocket` drop cleanup (`untap`).
- `kernel/time`: the timer thread watches every `Tap`'s epoll fd and calls `check_taps`.

### Outbound

- `appine_hal::net` (host socket calls and epoll `Watch`).
- `kernel/net`: `InetSocket` fields, message/msghdr helpers, waits and wake objects.
- `kernel/netns`: address translation (`from_host`).

## Invariants and gotchas

- A tap keeps the latest 65,536 successful echoes across its sockets. Duplicate and reordered
  replies use the same mapping. A reply delayed past reuse of its 16-bit wire sequence can no
  longer be distinguished from a newer request with the same family and host ping ident.
- `dispatch` of the raw ICMP taps must run with no socket borrowed.

## Confirmed bugs / technical debt

- None currently recorded. (Host-level privileged options such as `SO_PRIORITY > 6` or
  `IP_TRANSPARENT` are still subject to host-socket passthrough semantics; see `kernel/net`.)

## Open questions

- None.

## To verify

- That the host ping socket rewrites the id, rejects non-echo types and refuses a second bind.
