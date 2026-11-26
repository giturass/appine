# kernel/netlink Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/netlink.md` for the paired decision history; decisions from before the split are D3, D24, D26 and the netlink halves of D19 and D23 in `.agents/decisions/kernel/net.md`.
>
> Verified: 2026-11-11 (split out of the kernel/net full mapping of 2026-11-11; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: `NETLINK_GET_STRICT_CHK` header checks and dump filtering, query/attribute validation, `NETLINK_CAP_ACK`/`EXT_ACK` on query/genl errors, single IPv6 `RTM_GETADDR`, and `nlctrl` `GETPOLICY` dumps)

## Responsibilities

`kernel/netlink` implements AF_NETLINK sockets in process, with every reply synthesized and queued
on the socket:

- `NETLINK_ROUTE`: queries answered from the host's interfaces, the routing table and the virtual
  devices; change requests handed to `kernel/netns`'s device layer; link, address and route
  notifications;
- `NETLINK_GENERIC` with `nlctrl` only;
- the `NETLINK_NETFILTER` entry point to nftables;
- `NETLINK_SOCK_DIAG`, refusing every query as a 6.1 kernel without its diag modules does;
- `NETLINK_KOBJECT_UEVENT` sockets that never receive.

Root: in `core/kernel/src/net.rs` the sections netlink, rtnetlink notifications,
`NETLINK_GENERIC`, Netlink messages and `NETLINK_SOCK_DIAG`; in `core/kernel/src/syscall/net.rs`
the `netlink_*` socket functions (`netlink_bind`, `netlink_connect`, `netlink_autobind`,
`netlink_admin`, `netlink_listen_unprivileged`, `netlink_setsockopt`, `netlink_getsockopt`), the
netlink section (`netlink_send`, `rtnl_watched`, `CHANGING_IOCTLS`, `rtnl_notify`, `KernelHost`)
and the `Socket::Netlink` arms of the socket calls.

Outside the module: the socket syscalls' dispatch, the generic `SOL_SOCKET` options (`SockOpts`),
traffic counters, the timeout parser and the ioctls that changing ioctls wrap (`kernel/net`); the
routing table with its route and rule messages and `ip route get` (`kernel/route`); the device
layer and namespace ids (`kernel/netns`), nftables (`kernel/nft`); mq_notify (`kernel/ipc`); readiness plumbing
(`kernel/poll`). `net.rs`'s unit-test module, which also tests netlink, stays with `kernel/net`.

## Key types

- `NetlinkSocket` — protocol, type, `pid`, connected `dst_pid`/`dst_group`, reply/notification
  queue (`VecDeque<NetlinkItem>`: atomic `Datagram(Vec<u8>, group)` entries or resumable
  `Dump(NetlinkDump)` entries—either `DumpMessages` or `nft::SetElemDump`—packed on demand to
  each receive buffer) and `queued_bytes` (capped against `SO_RCVBUF`), arrival counter,
  `overrun`, `rcvtimeo`/`sndtimeo`, namespace, `ext_ack`/`cap_ack`, joined groups, the other
  `SOL_NETLINK` flags (bit n for option n), `passcred`, `SockOpts`. `Kernel::rtnl_sockets` holds
  every netlink socket weakly (for unique `nl_pid` checks and peer delivery across protocols, as
  well as `NETLINK_ROUTE` notifications).
- `Host` trait (interfaces, stats, routes, `tx_queue_len`, `ip_forward`, `route_localnet`, uid;
  with defaults configure, `peer_net`, links, tables, `all_interfaces`, `init_net`, `net_admin`,
  netfilter), implemented by `KernelHost` (kernel, credentials, namespace, pid namespace, fds, the
  namespaces `watched` for notifications and the `notes` a request caused); `Link` (host interface
  or virtual device); `Snapshot` (a namespace's link, address and route message bodies);
  `NotifyCause`, `RtnlNote` and `ConfigureResult` (carrying per-request seq/port/flags and
  `NLM_F_ECHO` messages).

## Public entry points

- The `Socket::Netlink` arms of `socket`, `bind` (`netlink_bind`), `connect`
  (`netlink_connect`), `getsockname`/`getpeername`, `listen`, `accept4`, `shutdown`,
  `setsockopt`/`getsockopt` (`netlink_setsockopt`/`netlink_getsockopt`), send (`netlink_send`),
  recv, `FIONREAD` and readiness.
- `NetlinkSocket::handle` (`route_request`, `generic_request`, `sock_diag_request`,
  `Host::netfilter`); `NetlinkSocket::{subscribed, notify, ngroups, sockaddr}`.
- Notifications: `rtnl_watched` and `rtnl_notify` (around rtnetlink sends and the changing
  socket ioctls), `KernelHost::{snapshots, changed_since, configure}`, `Snapshot::{take,
  changes}`.
- Helpers other modules use: `configure_host_link` (`kernel/netns`'s device layer), `message`
  and `attr` (the device layer, namespace routes and `kernel/route`).

## Data flow / lifecycle

### Sockets

- `socket`: `SOCK_RAW`/`SOCK_DGRAM` with ROUTE, SOCK_DIAG, NETFILTER, KOBJECT_UEVENT or GENERIC
  (others `EPROTONOSUPPORT`, other types `ESOCKTNOSUPPORT`); netlink sockets join `rtnl_sockets`.
  socketpair is `EOPNOTSUPP` (`kernel/net`).
- bind (Linux's `netlink_bind`): a whole `sockaddr_nl` of `AF_NETLINK` (`EINVAL`); groups need a
  protocol anyone may join (all but `NETLINK_NETFILTER`) or `CAP_NET_ADMIN` over the namespace
  owner, as do rtnetlink's multicast-routing groups (`EPERM`), and are cut to the protocol's
  count (36 for `NETLINK_ROUTE`, 32 for the others); a bound socket must keep its `nl_pid`
  (`EINVAL`); an unbound one takes the given id (`EADDRINUSE` if another socket of the same
  protocol and namespace already holds it) or, for 0, an unused autobind id (the caller's tgid in
  its pid namespace first, then a distinct negative id starting at `-4097`); the groups replace the
  first 32 joined, and getsockname reports them. connect (`netlink_connect`): `AF_UNSPEC`
  disconnects (clearing `dst_pid` and `dst_group`), otherwise a whole
  `sockaddr_nl` (`EINVAL`), a port or group needing `CAP_NET_ADMIN` (`EPERM`); `dst_pid` and
  `dst_group` (lowest set bit, 1-based) are recorded and reported by getpeername. connect and send
  autobind an unbound socket via the same unique allocator. shutdown returns `EOPNOTSUPP`; listen
  and accept `EOPNOTSUPP`.
- send validates `msg_name` (`EINVAL` on short or non-`AF_NETLINK` addresses; `EPERM` without
  `CAP_NET_ADMIN` when targeting a non-zero port or group), falling back to the connected
  `(dst_pid, dst_group)` when no address is given; control data and flags are ignored. Messages
  addressed to the kernel `(0, 0)` are handled synchronously (a message under 16 bytes or
  overrunning the datagram ends the batch), queuing reply datagrams with group 0; unicast
  `dst_pid != 0` delivers to the matching peer netlink socket (`ECONNREFUSED` if none);
  `NETLINK_NETFILTER` hands the whole datagram to nftables (and a
  change of the initial namespace's ruleset re-runs the inbound forwarding hooks);
  `NETLINK_KOBJECT_UEVENT` swallows it. recv first takes a pending overrun (`ENOBUFS` once), then
  dequeues one datagram (`dequeue(max, peek)`): atomic `Datagram` items pop whole (cloned on
  `MSG_PEEK`), while resumable `Dump` items pack as many consecutive messages from the current
  section as fit in `min(max, 32768)` bytes on demand (always emitting at least one atomic
  message so an oversized single message reports `MSG_TRUNC` and its full length without losing
  subsequent dump entries, and leaving state intact on `MSG_PEEK`, including 0-byte
  `MSG_PEEK|MSG_TRUNC` probes; advancing a non-empty dump bumps `arrivals` for `EPOLLET`); source
  `{AF_NETLINK, 0, group mask}`; with `NETLINK_PKTINFO` a pktinfo control
  message (the group, 0 for answers), then with `SO_PASSCRED` the kernel's credentials (pid 0, uid
  and gid 0 as the receiver sees them), cut as `put_cmsg` cuts them; with nothing queued,
  nonblocking, `MSG_DONTWAIT`, `MSG_ERRQUEUE` or an expired `SO_RCVTIMEO` give `EAGAIN` and a
  signal `ERESTARTSYS`. Readiness: `POLLOUT` always, `POLLIN` with data, `POLLERR` while an
  overrun is pending. `FIONREAD` is `ENOTTY`, as on Linux.
- Options: `SOL_SOCKET` reports the type, protocol, `AF_NETLINK`, `SO_PASSCRED`, the timeouts
  (`SO_SNDTIMEO` only recorded), `SO_ERROR` (takes a pending overrun's `ENOBUFS`, else 0),
  `SO_ACCEPTCONN` 0, `SO_PEERCRED` pid 0 and uid/gid -1, and the `SockOpts` ones; other names are
  accepted and ignored by setsockopt and `ENOPROTOOPT` to getsockopt. `SOL_NETLINK` (value read
  only when a whole int): `NETLINK_ADD_MEMBERSHIP`/`DROP` (permission as for bind; the set is
  allocated first, then group 0 or beyond the count `EINVAL`), `NETLINK_LIST_MEMBERSHIPS` (32-bit
  words while they fit, optlen the whole set's size, 0 before any group), and the flags
  `NETLINK_PKTINFO`, `BROADCAST_ERROR`, `NO_ENOBUFS`, `LISTEN_ALL_NSID` (`CAP_NET_BROADCAST` over
  the namespace owner), `CAP_ACK`, `EXT_ACK`, `GET_STRICT_CHK` (reading one needs room for an int,
  `EINVAL`); `NETLINK_PKTINFO` adds the control message, `NETLINK_CAP_ACK` and `NETLINK_EXT_ACK`
  shape error acks across rtnetlink changes and queries, `NETLINK_GENERIC`, nftables and
  `NETLINK_SOCK_DIAG` (plus `NLMSG_DONE` dump-error extack TLVs), `NETLINK_GET_STRICT_CHK`
  enforces Linux 6.1/6.8 header/attribute checks and header-based dump filtering, and
  `NETLINK_NO_ENOBUFS` affects overruns; the others are only recorded; other names and levels
  `ENOPROTOOPT`.

### rtnetlink notifications

- Every `NETLINK_ROUTE` socket is registered (weakly) in `Kernel::rtnl_sockets`. A send on
  `NETLINK_ROUTE` first collects the namespaces that have a socket in the link, IPv4/IPv6 address
  or IPv4/IPv6 route groups (1, 5, 7, 9, 11), the sender included; for a change request
  (`RTM_NEW`/`DEL`/`SETLINK`, `NEW`/`DELADDR`, `NEW`/`DELROUTE`) `KernelHost::configure`
  snapshots each watched namespace (plus the caller's own namespace when an address or route
  request sets `NLM_F_ECHO`)
  before and after the device layer runs it, even when it fails (a request
  can change another namespace: moving a link, a veth's peer); a socket ioctl that may change an
  interface, address or route (`SIOCSIF*`, `SIOCDIFADDR`, `SIOCADDRT`/`SIOCDELRT`) is wrapped the
  same way.
- The difference becomes messages in Linux's order: new or changed links (`RTM_NEWLINK`,
  statistics ignored), addresses gone and new, routes gone and new (an address with the same
  family, prefix length, interface and addresses, or a route with the same family, destination
  length, TOS, table, destination and priority, that changed in place is only new, as `ip route
  replace` is), links gone. `Snapshot::changes` attaches Linux 6.1 header metadata from
  `NotifyCause`: IPv4 `RTM_NEWADDR`/`RTM_DELADDR` and IPv4+IPv6 `RTM_NEWROUTE`/`RTM_DELROUTE`
  directly caused by the netlink request copy `(req.seq, sender.pid)` and honour `NLM_F_ECHO`,
  whereas all link notifications (`RTM_NEWLINK`/`RTM_DELLINK`), side-effect kernel notifications
  (e.g. routes added by `RTM_NEWADDR`) and IPv6 address notifications keep `seq=0, port=0` and
  are not echoed. `RTM_NEWROUTE` carries `NLM_F_REPLACE` on an in-place replace with `NLM_F_REPLACE`,
  `NLM_F_CREATE|NLM_F_APPEND` on append, and `NLM_F_CREATE|NLM_F_EXCL` otherwise (including
  kernel-added routes). Echoed `(msg, group)` datagrams are queued on the sender before the
  `NLMSG_ERROR` ACK; after the sender's borrow ends, `rtnl_notify` broadcasts each notification to
  every registered socket of that namespace that joined the group (skipping the sender for already
  echoed notifications so subscribed senders do not receive duplicates) and wakes them.
- All queued messages (rtnetlink notifications, query answers, nftables replies, peer unicast
  deliveries and mq_notify cookies) are charged `len + 256` bytes against `SO_RCVBUF` (an empty
  queue still accepts one message); overflow drops the message and, unless `NETLINK_NO_ENOBUFS` is
  set, records `overrun` (`ENOBUFS`).

### `NETLINK_ROUTE`

- Handled rtnetlink requests require `NLM_F_REQUEST` (and `ty >= NLMSG_MIN_TYPE`); messages without
  it are skipped and acked with 0 only on `NLM_F_ACK`.
- Change requests (`NEW`/`DEL`/`SET` for links, addresses, routes) need `CAP_NET_ADMIN` over the
  namespace owner and go to `kernel/netns`'s device layer; other change types Linux 6.1 knows (up
  to `RTM_MAX`) are `EPERM` without it and `EOPNOTSUPP` with it (host interfaces cannot be
  changed; requests that change nothing succeed). Errors are acked through `ack_ext`, successes
  only on `NLM_F_ACK`.
- Queries: link dumps (filtered by master and kind; under `NETLINK_GET_STRICT_CHK`, validates
  16-byte `ifinfomsg` with zeroed fields and strict allowed attributes `IFLA_MASTER`,
  `IFLA_LINKINFO`, `IFLA_EXT_MASK`, `IFLA_TARGET_NETNSID`), single links by index or name
  (validating 16-byte `ifinfomsg` and attribute sizes: `ERANGE`/`EINVAL`, `ENODEV`), address dumps
  (per family, IPv4 first; under `NETLINK_GET_STRICT_CHK`, validates 8-byte `ifaddrmsg`, filters
  by `ifa_index` with `NLM_F_DUMP_FILTERED` or `ENODEV`, rejects unknown/leftover attributes),
  single IPv6 `RTM_GETADDR` (validating 8-byte `ifaddrmsg` and 16-byte `IFA_LOCAL`/`IFA_ADDRESS`
  with `EINVAL`/`ERANGE`/`EADDRNOTAVAIL`; non-IPv6 `EOPNOTSUPP`), route dumps (per family; under
  `NETLINK_GET_STRICT_CHK`, validates 12-byte `rtmsg` flags/fields and strict attributes, filters
  by `rtm_table`/`RTA_TABLE`, `rtm_protocol`, `rtm_type`, `RTA_OIF`, and `RTM_F_CLONED`, returning
  `ENOENT` for missing per-family tables and `ENODEV` for unknown `RTA_OIF`) and `ip route get`
  (built by `kernel/route`, validating 12-byte `rtmsg` and IPv4/IPv6 attribute lengths: `ERANGE`
  for short IPv4 `RTA_DST`/`RTA_SRC`/`RTA_FLOW`/u32 attrs and IPv6 `RTA_IIF`/u32 attrs, `EINVAL`
  for short IPv6 `RTA_DST`/`RTA_SRC`, using leading bytes when oversized), rule dumps (under
  `NETLINK_GET_STRICT_CHK`, validates 12-byte zeroed `fib_rule_hdr` and no attributes;
  `NLMSG_DONE` with `-EAFNOSUPPORT` for families without rules), nsid (by pid or fd, validating
  4-byte `NETNSA_*` attributes with `ERANGE`), neighbour dumps (empty; under
  `NETLINK_GET_STRICT_CHK`, validates 12-byte `ndmsg` and `NDA_IFINDEX`/`NDA_MASTER`/
  `NDA_FLAGS_EXT`) and single neighbour gets (validating header length, `ndm_state`/`ndm_type`,
  family `EAFNOSUPPORT`, `NDA_DST` length `EINVAL` and ifindex `ENODEV`/`EINVAL` before `ENOENT`);
  others `EOPNOTSUPP`; all query errors honour `NETLINK_CAP_ACK` and `NETLINK_EXT_ACK` (dump
  errors return `NLMSG_DONE` with negative errno and optional extack TLV); control messages are
  acked only on `NLM_F_ACK`.
- Link, address, route, rule and neighbour dumps are queued as resumable `DumpMessages` (keeping
  Linux 6.1's per-family section boundaries and trailing `NLMSG_DONE` section) and packed on
  demand to each `recv`/`recvmsg` buffer size (capped at 32 KiB), so both small buffers (e.g.
  512 B) and page-sized buffers (Go's `syscall.NetlinkRIB`, behind `net.Interfaces`) receive whole
  multipart messages without losing entries.
- In the initial namespace interfaces and addresses come from the host's `getifaddrs` (MTU fixed,
  MAC from `AF_PACKET` entries, host statistics and queue length) plus its virtual devices; new
  namespaces see only their own devices, with zero statistics and a queue length of 1000.

### `NETLINK_GENERIC`, `NETLINK_SOCK_DIAG` and the others

- `NETLINK_GENERIC`: `nlctrl` only, modelled on 6.8 (the differential tests run on a 6.8 host,
  where 6.1 would report a different maxattr): a short header `EINVAL`, invalid `CTRL_ATTR_*`
  sizes `ERANGE`, unknown families `ENOENT`, with all errors honouring `NETLINK_CAP_ACK` and
  `NETLINK_EXT_ACK` (including `NLMSGERR_ATTR_OFFS` for unknown `CTRL_ATTR_OP`); `GETFAMILY`
  resolves `CTRL_ATTR_FAMILY_NAME` over `CTRL_ATTR_FAMILY_ID` when both are given; `GETPOLICY`
  (dump only) checks `CTRL_ATTR_FAMILY_ID` before `CTRL_ATTR_FAMILY_NAME` (`EINVAL` without a
  family, `ENOENT` for another family or unknown `CTRL_ATTR_OP`) and dumps `nlctrl`'s own Linux
  6.8 operation policies; the `GETFAMILY` and `GETPOLICY` dumps are resumable and share a datagram
  with `NLMSG_DONE` when both fit in the caller's buffer (splitting across receives otherwise).
- `NETLINK_SOCK_DIAG` answers as 6.1 does without any family diag module (`sock_diag_rcv_msg`):
  the old `TCPDIAG_GETSOCK`/`DCCPDIAG_GETSOCK` `EOPNOTSUPP`; `SOCK_DIAG_BY_FAMILY` and
  `SOCK_DESTROY` `EINVAL` for a body under two bytes or a family at or past `AF_MAX` (46), else
  `ENOENT`; other types `EINVAL`; each as an error ack honouring `NETLINK_CAP_ACK`, non-requests
  and control messages acked only on `NLM_F_ACK`. iproute2's ss takes `ENOENT`/`EOPNOTSUPP` there
  silently and reads `/proc/net` instead.
- `NETLINK_NETFILTER` goes to nftables (`kernel/nft`). `NETLINK_KOBJECT_UEVENT` never receives.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/net`: the socket syscalls dispatch netlink sockets here (creation, names, options,
  send, recv, readiness), and its ioctl path runs the changing ioctls between `rtnl_watched` and
  `rtnl_notify`.
- `kernel/netns`: the device layer calls `configure_host_link` and builds netlink messages with
  `message` and `attr`; `kernel/nft` uses the same encoding for ruleset replies.
- `kernel/route`: `route.rs` encodes route messages with `message` and `attr`.
- `kernel/ipc`: mq_notify queues `SIGEV_THREAD` cookies on a netlink socket.
- `kernel/poll` through `kernel/net`'s readiness.

### Outbound

- `kernel/net`: `SockOpts`, the timeout parser, traffic counters for link statistics, and the
  inbound forwarding hooks (`forward_all`) after an initial-namespace ruleset change.
- `kernel/route`: `route_message`, `get` and `rule_messages`.
- `kernel/netns`: `netdev::{request, base, views, tables, interfaces, nsid, nsid_alloc}`.
- `kernel/nft`: `nft::handle`.
- `appine_hal::net` (`interfaces` through `getifaddrs`, `tx_queue_len`); credentials
  (`ns_capable`); the kernel's waits and wake objects.

## Invariants and gotchas

- Netlink replies are snapshots taken at send time; notifications are differences between
  snapshots, so what a request changes counts, not how (several steps of one request collapse,
  and a namespace nobody listens to is never snapshotted).
- Notifications are queued only after the sender's borrow ends, and `rtnl_watched` skips sockets
  it cannot borrow.
- Every `NETLINK_ROUTE` send walks `rtnl_sockets`, and each change request with a listener renders
  the watched namespaces' link, address and route messages twice.

## Confirmed bugs / technical debt

- **Only rtnetlink link, address and route changes are notified:** groups other than rtnetlink's
  link, address and route ones (neighbours, rules, netconf, nsid, other protocols) never receive
  anything; changes made through sysctls (`disable_ipv6`) or to the host's own interfaces (boot
  namespace) are not notified.

## Open questions

None.

## To verify

- "Byte-identical to Linux" for link, address, route and rule messages beyond the differential
  cases that compare dumps: link messages omit `IFLA_AF_SPEC` and use a fixed MTU.
