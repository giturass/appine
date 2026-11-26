# kernel/netns Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/netns.md` for the paired decision history, including pre-split decisions for kernel/nft.
>
> Verified: 2026-11-03 (full mapping: 6 research concerns; 19 claims checked by 3 independent verifiers — 13 confirmed and 6 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: full `127.0.0.0/8` loopback range in non-init namespaces and Linux 6.1 `RTA_DST`/`RTA_GATEWAY`/`RTA_PREFSRC` length handling in `RTM_NEWROUTE`/`RTM_DELROUTE`)

## Responsibilities

`kernel/netns` emulates Linux network namespaces without a network stack of its own: guest sockets
stay host sockets, and everything a namespace changes is applied at the socket boundary. It
provides:

- network namespaces as host loopback blocks, with address translation in both directions;
- namespace-local ports and listener registration (`ECONNREFUSED`, UDP drops);
- virtual devices (bridge, veth, dummy) with addresses, routes and sysctls, and the mapping of
  their IPv4 addresses to host loopback addresses;
- namespace-path construction and socket-boundary integration for `kernel/nft` evaluation;
- forwarding of connections from outside Appine to published (DNAT) ports.

Root: `core/kernel/src/netns.rs`, `netdev.rs`, `forward.rs`, `netconf.rs`.

Outside the module: the socket syscalls that call into it, host interfaces and low-port
mapping in the initial namespace (`kernel/net`); routing tables (`kernel/route`); netlink socket
mechanics (`kernel/netlink`); nftables rulesets, requests and expression evaluation (`kernel/nft`,
`nft.rs`); creating and entering namespaces, nsproxy and `/proc/<pid>/ns` (`kernel/ns`); `/proc/net`
(`kernel/procfs`), `/proc/sys/net` (`kernel/sysctl`) and `/sys/class/net` (`kernel/sysfs`); host
sockets (`hal`).

## Key types

- `NetNs` (in nsproxy) — id, owner user namespace, `host_net` (the 127.a.b block; `None` for the
  initial namespace, which is the host network), `lo` (`Loopback`: up, IPv4 addresses, `::1`,
  MTU, `self_udp`), `devs` (`Devices`), `nft` (`Nft`), `listeners` (`Bindings`).
- `World` — every live namespace (initial first), built per call; `Use` (`Bind` → `EADDRNOTAVAIL`,
  `Reach` → `ENETUNREACH`); `Mapped` (host address, target namespace, implicit-bind source,
  virtual address, `isolated` flag for initial-ns attempts to reach an allocated container
  `127.a.b.x` block); `Role` (`Peer` or `Local`).
- `Bindings` / `Binding` / `NewBinding` / `BindAddr` / `BindReq` — per-namespace registry of bound TCP/UDP sockets
  (id, protocol, guest port, normalized guest `BindAddr`: `AnyV4`/`AnyV6`/`V4`/`V6`, `v6only`,
  `bound_dev_if`, live `SO_REUSEADDR`/`SO_REUSEPORT`, `euid`, `listening`, `accepted`, host
  IP/port, `wide`) plus a 10 s
  `LINGER` reverse table `(proto, host_ip, host_port) → (guest_port, BindAddr)`.
- `Devices` — devices, index counter, routes through virtual devices (`Rt`), `NetConf`, nsids,
  `hostmap` (`HostMap`: initial namespace bidirectional virtual IPv4 ↔ 127.255.0.1..=127.255.255.254
  with O(1) lookup, FIFO slot recycling, and `EADDRNOTAVAIL` on exhaustion); `Dev` (index, name, kind,
  up, flags, MTU, MAC, txqlen, group, alias, peer/master as weak references, IPv4/IPv6 addresses,
  per-device settings, carrier counters); `View` (read-only snapshot for netlink, procfs, sysfs).
- `NetConf` / `Conf` — interface and namespace sysctls (`all`, `default`, per device; host
  interfaces and lo keyed by index).
- `forward::Forwarder` (per kernel; one host thread), `Shared`, `Target` (protocol, host
  destination, source address), `Handle` (in `InetSocket::fwd`, supporting in-place `update(Option<Target>)`),
  `PortEntry`, `Conn`, `Relay`, the global
  `OUTSIDE` registry (127.254.x.y → real client address and port).
- `netns::NatPacket`, `NatResult` (`Pass`, `Dnat`, `Block`), `Flow`, `Step` — synthetic packet construction and hook routing into `kernel/nft`.

## Public entry points

- Namespaces: `Kernel::new_net_ns`, `Kernel::world`, `FIRST_BLOCK`; translation `to_host`,
  `init_to_host`, `is_foreign_loopback`, `from_host`, `from_host_peer`, `from_self`, `toward_self`,
  `implicit_bind`, `local_toward`, `entering`, `owner_of_host`, `host_ipv4`, `with_host_endpoint`;
  bindings & listeners
  `bind_conflict`, `listen_conflict`, `shared_host_port`, `add_binding`, `add_ephemeral`,
  `remove_binding`, `set_listening`, `set_reuse`, `set_bound_dev`, `resolve_target`, `lookup_host`.
- Devices: `netdev::request` (rtnetlink changes), `link_message`, `addr_messages`, `nsid`,
  `nsid_alloc`, `ioctl`, `ifconf`, readers (`views`, `interfaces`, `base`, `tables`, `entries`,
  `local_v4`, `route_v4`, `routes_v6`, `first_v4`), sysctls (`conf_dirs`, `conf_read`,
  `conf_write`, `ip_forward`), `Devices::for_new_ns`.
- Forwarding: `forward_target`/`forward_socket`/`forward_all` (in the socket layer),
  `Forwarder::add`, `forward::run`, `outside_peer`.
- nftables integration: `output_nat`, `prerouting_nat`, `path_filter`, `external_nat`,
  `external_filter` call `kernel/nft` with the namespace path and synthetic packet.

## Data flow / lifecycle

### Namespaces

- Created by clone/unshare with `CLONE_NEWNET` (`CAP_SYS_ADMIN` in the new credentials' user
  namespace). The block is the first n in `FIRST_BLOCK..=65535` (`2..=65535`, reserving
  `127.0.0.0/24` and `127.0.1.0/24` for initial-ns loopback including `127.0.0.1`, `127.0.0.53`,
  and Debian's `127.0.1.1`) whose bytes [a, b] are free and not 255 (reserved for the initial
  namespace's virtual addresses) or 254 (outside clients); the first namespace gets 127.0.2.0/24;
  no free block is `ENOMEM`; a block is reused once its namespace is dropped. lo starts down
  without addresses; IPv4 sysctls are copied from the initial namespace, IPv6 ones start at
  defaults.
- The kernel holds weak references; threads' nsproxies, sockets (inet, netlink, unix) and
  namespace files keep a namespace alive. A socket keeps the namespace it was created in, even
  after setns. Dropping a namespace drops its devices; a veth whose peer died is pruned lazily.

### Address translation

- Binding in a new namespace: the wildcard and `::` → 127.a.b.1 (flag `any`); `127.0.0.1..=253` →
  `127.a.b.1..=253` (bindable even with lo down), and all other `127.0.0.0/8` addresses (including
  `127.0.1.1`, `127.1.2.3`, and `127.0.0.254` so it does not collide with `SELF_VIA_VADDR`) →
  `127.a.b.1` with `vaddr` recording the exact guest IP (`Bindings` separates host ports per guest
  address); the namespace's own virtual IPv4 address → 127.a.b.1 (recording `vaddr`); anything else
  `EADDRNOTAVAIL`. IPv6 `::1`/`::` become `::ffff:127.a.b.1` (host sockets stay dual-stack). A
  wildcard UDP bind to port 0 gets a real host wildcard bind (`wide`) so it can also reach outside.
- Reaching from a new namespace: any `127.0.0.0/8` address needs lo up and a covering address
  (`127.0.0.1..=253` → `127.a.b.1..=253`, others → `127.a.b.1` and resolved to the matching
  listener's host port via `Bindings`); `::1` needs lo up
  with IPv6; the own virtual address → 127.a.b.1 with source 127.a.b.254; another namespace's
  virtual address (through a route over a virtual device) → its 127.c.d.1, or 127.255.x.y for the
  initial namespace's; an address nobody owns, routed through a gateway, goes to the host network
  unchanged (the host binds the source); a miss on a directly connected subnet `EHOSTUNREACH`; no
  route `ENETUNREACH`. Only IPv4 virtual addresses are mapped; IPv6 virtual addresses cannot be
  bound or reached — in a new namespace IPv6 destinations matching any route over a virtual device
  (on-link and link-local included) are handed to the host network, and in the initial namespace
  all IPv6 goes to the host unchanged.
- Unbound sockets are bound implicitly before connect, sendto or listen: 127.a.b.1 (or
  `::ffff:127.a.b.1`; host `::1` for ICMPv6; 127.a.b.254 for UDP to the own virtual address); none
  when the destination goes to the host network.
- The initial namespace: its virtual addresses map to 127.255.x.y entries in `HostMap` (allocated
  on demand in O(1), reclaimed when deleted from all virtual devices or when a device is deleted,
  moved out or pruned, and recycled FIFO; all 65,534 slots full returns `EADDRNOTAVAIL`);
  destinations in other namespaces (via virtual-device routes) map to their 127.c.d.1; direct
  initial-ns guest attempts on any `127.a.b.x` (including IPv4-mapped `::ffff:127.a.b.x`) whose
  `[a, b]` block is currently allocated to another namespace are rejected on `bind`
  (`EADDRNOTAVAIL`) and marked `Mapped::isolated` on `Reach` (TCP `connect`/`MSG_FASTOPEN` return
  `ECONNREFUSED`, UDP `sendto` drops silently and UDP `connect` records a blocked peer without
  touching the host, raw/other sockets return `ENETUNREACH`, and `forward_target` refuses isolated
  DNAT targets); `127.0.0.1`, `127.0.1.1`, unallocated loopback addresses and everything else pass
  through unchanged.
- Back to the guest (`from_host` / `from_host_peer`, by who is looking): wildcard for `any`
  sockets; 127.254.x.y → the real outside client; for peers in a new namespace, `from_host_peer`
  first checks `lookup_host` so bindings on a specific virtual or loopback IPv4 address sharing
  127.a.b.1 report their exact guest IP; own 127.a.b.x → 127.0.0.x (`::1` for IPv6 sockets at .1,
  except `::ffff:127.0.0.1` binds which record `vaddr`); 127.a.b.254 → the first virtual address;
  another namespace's 127.c.d.1 → that namespace's address facing the viewer; 127.255.x.y → the
  initial namespace's virtual address; non-loopback local ends → the namespace's route source
  toward the peer.
- `/proc/<pid>/net` lists the sockets created in the target's namespace, translated through each
  socket's own namespace.

### Ports and listeners in a namespace

- Every bound TCP/MPTCP and UDP socket in a new namespace is tracked in `NetNs::listeners`
  (`Bindings`) by `(proto, guest_port)` with its normalized guest `BindAddr`, `v6only`, live
  `SO_REUSEADDR`/`SO_REUSEPORT`, creator `euid`, `listening`/`accepted` state, and host endpoint
  `(host_ip, host_port, wide)`.
- Guest-level conflict checks run BEFORE host `bind()` (`bind_conflict`) and BEFORE TCP `listen()`
  (`listen_conflict`), matching Linux 6.1's `inet_csk_bind_conflict` and `udp_lib_lport_inuse`:
  two bindings overlap iff their covered IPv4 or IPv6 sets intersect and their `bound_dev_if`
  constraints are compatible (`addrs_overlap`: `0.0.0.0`
  and IPv6-only `[::]` are disjoint, `127.0.0.1` and `<vaddr>` or `[::1]` are disjoint, bindings
  pinned to distinct devices are disjoint, while
  `0.0.0.0` + `127.0.0.2` and IPv6-only `[::]` + dual-stack `[::]` overlap); overlapping binds
  return `EADDRINUSE` unless both set `SO_REUSEADDR` (for UDP, or for TCP when the existing socket
  is not `TCP_LISTEN`) or both set `SO_REUSEPORT` with the same `euid`. `IPV6_V6ONLY` refuses
  IPv4-mapped binds and post-bind changes with `EINVAL`; `setsockopt(SO_REUSEADDR|SO_REUSEPORT)`
  updates the live `Binding`, `SO_BINDTODEVICE`/`SO_BINDTOIFINDEX` updates `bound_dev_if` via
  `set_bound_dev`, and `shutdown(SHUT_RD|SHUT_RDWR)` clears `listening` without
  releasing the port.
- Host-port separation: explicit nonzero binds get a host-assigned port (`bind(..., 0)`) per
  distinct guest bind target `(proto, guest_port, addr, v6only, host_ip)`, so `127.0.0.1:P`,
  `<vaddr>:P`, multiple virtual IPs, `[::1]:P`, `0.0.0.0:P`, and `[::]:P` never collide on
  `127.a.b.1`; only sockets joining the exact same non-`wide`, non-`accepted` target via
  `SO_REUSEPORT` (same `euid`) or UDP `SO_REUSEADDR` share a host port (`shared_host_port`).
  `bind(0)`, implicit binds, and host autobinds register through `add_ephemeral`, which remaps the
  guest port away from any active bound guest port for `proto` in the namespace (within
  `ip_local_port_range`) and blocks conflicting explicit binds. Accepted TCP child sockets register
  as non-listening `accepted` bindings. Removed bindings linger 10 s (`LINGER`) for reverse
  `(proto, host_ip, host_port)` translation (`lookup_host`).
- `resolve_target` routes TCP connects, UDP sends, and `forward_target` DNAT probes into a new
  namespace to the best matching active listener's `(host_ip, host_port)` (exact guest address
  beats wildcard; pure IPv6 prefers `v6only` wildcard; `wide` sockets route via `127.a.b.1`). A
  TCP connect with no match returns `ECONNREFUSED` before the host is asked; a UDP sendto with no
  match is dropped silently (reporting success). Targets in the initial namespace are not checked.
- Connected UDP sockets record their filter verdict and target namespace listener at connect — both
  host-wide sockets (`vconn`, which discard foreign sources on receive) and namespace-bound sockets
  — and address-less sends re-resolve the target listener's `(host_ip, host_port)` (updating
  `vconn` or reconnecting the host socket across connect-before-bind and server close/rebind).
- Accepted sockets inherit `local_map`, `vaddr`, `euid`, `v6only`, and namespace; their peer is
  translated via `from_host_peer`; getsockname reports the wildcard until a connect, then the
  facing address.

### Virtual devices

- Kinds: bridge, veth, dummy (others `EOPNOTSUPP`); bridges cannot move between namespaces.
  Changes need `CAP_NET_ADMIN` over the namespace owner (and over a target namespace named by
  `IFLA_NET_NS_PID`/`FD`; `IFLA_TARGET_NETNSID` `EOPNOTSUPP`).
- Create: validate kind, MAC (6 bytes, unicast) and MTU range; default names `bridge%d`,
  `veth%d`, `dummy%d` (lowest free); long names `ERANGE`/`EINVAL`; duplicates `EEXIST`; a taken
  requested index `EBUSY`; indexes above the host's largest in the initial namespace, from 2 in new
  ones; random locally administered MAC, MTU 1500, txqlen 1000; veth peers registered first
  (possibly in another namespace) and paired; then flags and master (failure deletes the device).
- Change (`do_setlink` order, earlier changes kept on a later error): namespace move (down,
  detached, addresses and routes cleared, renamed or `EEXIST` on a name clash), MAC, MTU (below
  1280 tears IPv6 down), group, rename (`EBUSY` while up), alias, flags, master (`ELOOP` for a
  bridge under a bridge, `EOPNOTSUPP` for non-bridge masters), carrier (dummy only), txqlen.
  Host interfaces in the initial namespace accept only no-op requests; lo in a new namespace
  supports up/down and MTU; deleting lo or host interfaces `EOPNOTSUPP`.
- Carrier and operstate: veth when both ends are up; bridges when a port forwards (after the first
  computation); dummy always. IPv6 setup on carrier: multicast and link-local routes, an EUI-64
  link-local address (unless `addr_gen_mode` 1), no DAD.
- IPv4 addresses: same-subnet extras become secondary; duplicates `EEXIST` unless replacing; local
  route always, subnet and broadcast routes while up; deleting a primary deletes its secondaries.
  IPv6 addresses: `EACCES` with IPv6 disabled; removed on down unless `keep_addr_on_down`.
- Routes: unicast only, table ≤ 255, address-attribute lengths match Linux 6.1 (`rtm_ipv4_policy` /
  `rtm_ipv6_policy` + `rtm_to_fib6_config`: IPv4 `RTA_DST`/`RTA_GATEWAY`/`RTA_PREFSRC` < 4 bytes
  `ERANGE` and ≥ 4 uses first 4 bytes; IPv6 `RTA_GATEWAY` < 16 bytes `ERANGE` and ≥ 16 uses first
  16 bytes; IPv6 `RTA_DST` < `ceil(dst_len / 8)` bytes `EINVAL` and zero-pads up to 16 bytes; IPv6
  `RTA_PREFSRC` < 16 bytes `EINVAL` and ≥ 16 uses first 16 bytes), next hop an up virtual device (host interfaces and lo
  `EOPNOTSUPP`), all-zero `RTA_GATEWAY` counts as no gateway, gateways without a device resolve to
  the first (lowest-index) matching longest-prefix subnet, IPv6 link-local gateways with an explicit
  up device are accepted without routing-table lookup (working without carrier; `EINVAL` without a
  device), other gateways must be on-link (`ENETUNREACH` for IPv4, `EHOSTUNREACH` for IPv6) unless
  `RTNH_F_ONLINK`, which needs a
  device that is up (`ENODEV`, `ENETDOWN`) and, for IPv4, a scope below link and a gateway that is
  not local, broadcast or multicast (`EINVAL`), and shows in dumps; flags as `fib_table_insert`; deleting a
  missing route `EOPNOTSUPP` in the initial namespace, `ESRCH` elsewhere; dumps merge with the host
  or lo routes.
- Sysctls: 33 IPv4 and 58 IPv6 settings per device plus `all`/`default`; effective are
  `disable_ipv6`, `addr_gen_mode` (only "none"), `keep_addr_on_down` and IPv4 `default`
  propagation; IPv6 `mtu` and `stable_secret` are checked and stored only; `forwarding`/
  `ip_forward` are stored only (traffic through a gateway always flows as if routing and NAT were
  on).
- ioctls: get/set flags, MTU, name, hardware address, txqlen, and the address getters; address
  setters `EPERM`. Statistics of virtual devices are zero.

### nftables integration

- At connect and at every sendto with an address (connected UDP: once at connect), the socket
  layer builds a fake packet (addresses, protocol, ports, uid/gid, mark, interfaces, ct state) and
  runs one hook's base chains of the matching families in priority order:
  1. OUTPUT nat of the sender (TCP/UDP/MPTCP, IPv4 and IPv6);
  2. IPv4 PREROUTING nat of the entered namespace (the target or the initial namespace on the
     way out). On-link traffic between veth endpoints whose peers share a bridge first passes
     that bridge owner's PREROUTING when its `bridge-nf-call-iptables` is enabled. A bridge DNAT
     can change which namespace is entered next; the endpoint can apply its own DNAT;
  3. filter chains along the path (IPv4 only): the sender's OUTPUT, then per step PREROUTING
     filter chains (split at `NF_IP_PRI_NAT_DST = -100` as Linux netfilter does, so chains with
     `priority < -100` see the pre-DNAT destination and chains at `priority >= -100` see the
     post-DNAT destination, carrying `meta mark set` into the step's next hook) and the step's own
     hook — INPUT on lo, the initial namespace's INPUT or FORWARD, the target's INPUT. On a 2-hop
     routed path where only the target DNATs, the initial namespace sees the pre-DNAT destination. A
     filtered bridge hop sees its logical bridge interface and its own post-DNAT destination on
     FORWARD (INPUT for local delivery). Routed traffic still takes its usual hooks when bridge
     filtering is disabled. The mark is cleared outside the sender.
  POSTROUTING (nat and filter), INPUT-hook nat and arp/bridge/netdev tables are never evaluated.
  (Inbound forwarding's probe can evaluate IPv6 PREROUTING nat.)
- Effects: nat-chain drops and rejects flow into the same verdict handling as filter chains
  (`NatResult::Block` → `Routed::verdict`, with `on_output` set for OUTPUT and false for
  PREROUTING): a TCP reject returns its errno at once (RST → `ECONNREFUSED`, ICMP codes mapped), a
  TCP drop connects to a blackhole listener so it times out like Linux's retransmissions, UDP
  `connect` succeeds (recording the blocked verdict) and UDP sends fail with `EPERM` on OUTPUT or
  drop silently on PREROUTING/INPUT/FORWARD; DNAT rewrites the destination (and may move it to
  another namespace); `meta mark set` updates the mark.
- `tracks()` (any conntrack-using table) decides whether `SO_ORIGINAL_DST` answers.
- Expression and control-plane details are in `kernel/nft`; initial-namespace commits
  trigger the socket layer's forwarding refresh.

### Forwarding from outside

- Candidates: initial-namespace TCP listeners and UDP sockets bound to a nonzero port (not raw)
  when the initial namespace has PREROUTING nat. A synthetic packet from 192.0.2.1:40000 to the
  socket's port (wildcards become the first non-loopback IPv4 interface address) runs PREROUTING
  nat; a DNAT result is translated to the target's host address and gateway source, filtered
  through the initial namespace's PREROUTING (split around DNAT priority) and FORWARD/INPUT and
  the target's PREROUTING/INPUT chains (a drop or reject means no
  forwarding), and target endpoints in new namespaces are resolved via `resolve_target` (or
  initial-namespace low ports via `portmap`). Re-evaluated on listen (both initial and new
  namespaces), UDP bind, initial-namespace nft commits and explicit-port binds in namespaces (when
  PREROUTING nat exists) — not on interface address changes or container-namespace filter changes. A dual-stack
  AF_INET6 wildcard listener (`!IPV6_V6ONLY`) falls back to probing IPv4 PREROUTING nat when the
  IPv6 probe does not match, so IPv4 DNAT rules forward it.
- One host thread (`forward`, no BKL) owns dups of the selected host sockets: it accepts up to 64
  connections per round up to `MAX_CONNS` (256) concurrent forwarded TCP connections (omitting TCP
  listeners from `poll` while at cap so accept sockets do not busy-loop), opens a nonblocking
  connection to the target with a `CONNECT_TIMEOUT` (10 s; client input is not polled until the
  outbound connect completes, while client `POLLERR`/`POLLHUP` aborts early), and copies both ways
  with 64 KiB buffers, propagating half-close with `SHUT_WR`; errors close both ends, and so does a
  side that reports an error or hangs up after its end of file before it was shut for writing (a
  reset half-closed side). A listener that polls readable while its first accept fails with anything
  but `EAGAIN` (out of fds, shut down) is left out of the poll for 1 s; a failing poll waits 100 ms.
  UDP uses one relay socket per client address (120 s idle), capped at `MAX_UDP_RELAYS` (256;
  datagrams from new clients while at cap are drained and dropped without opening fds, while
  existing relays stay active), replies sent from the held port.
- Real client address: for IPv4, non-loopback TCP clients and IPv4 targets the relay binds a
  127.254.x.y address with the client's port and records it, so accept, getpeername and
  `/proc/net` in the container report the real client; loopback, IPv6 and UDP clients see the
  gateway. The global record is removed when the forwarded connection closes, while accepted guest
  sockets cache the resolved real client address in `track.outside_peer` so getpeername and
  `/proc/net/tcp` preserve it across `CLOSE_WAIT` until the guest socket closes.
- On rule changes, non-deferred handles are updated in place via `Handle::update(Option<Target>)`:
  established forwarded TCP connections stay, and existing UDP relays of that port stay alive to
  deliver in-flight replies until idle expiry (120 s), hard socket error, or guest socket close;
  pausing a UDP handle (`None`) stops polling `port_fd` for `POLLIN` so new datagrams go to the
  guest, while closing the guest socket (`Handle::drop`) tears down its UDP relays. Ordinary
  listeners share the accept queue with the guest. For a host-refused RET 0, the socket layer
  supplies a separate listener for DNAT and shuts it down on withdrawal. The port stays bound on
  the deferred guest fd.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/net` (bind, listen, connect, accept, send, recv, getsockname/getpeername, forward targets,
  `SO_ORIGINAL_DST`, `SIOCADDRT`/`SIOCDELRT` through `netdev::request`); `kernel/netlink`
  (device configuration); `kernel/ns` (clone/unshare/setns
  create and enter namespaces); `kernel/procfs` (`/proc/net`), `kernel/sysctl` (`/proc/sys/net`),
  `kernel/sysfs` (`/sys/class/net`); the machine (the forwarder per kernel).

### Outbound

- `appine_hal::net` (host sockets, host interfaces, poll, dup, events); `kernel/net`'s portmap;
  `kernel/route` (`route::merge`, `attrs`); `kernel/netlink`'s encoding (`message`, `attr`,
  `configure_host_link`); credentials (`ns_capable`); the kernel
  log; `std::thread` for the forwarder.
- `kernel/nft` owns each namespace's ruleset; this module builds packets and selects hooks,
  applies verdicts and translates DNAT destinations. Forwarding probes use the same evaluator.

## Invariants and gotchas

- Isolation is guest-side only: initial-namespace guests cannot directly bind, connect, or send
  to any container's allocated `127.a.b.x` block (`init_to_host` / `is_foreign_loopback`), but
  other apps on the host device can still reach host loopback sockets directly.
- Namespace translation depends on who is looking; every address leaving the kernel layer must be
  translated for the viewing socket's namespace.
- Wildcard, 127.0.0.1, `::1` and the namespace's virtual addresses share host IP 127.a.b.1, but
  each distinct guest bind target receives its own host port in `NetNs::listeners` (`Bindings`),
  which governs conflict checks, target resolution and peer reverse translation.
- Device snapshots (`View`) hold their veth peer's namespace alive; devices refer to each other only
  weakly.
- The forwarder never takes the BKL and touches only host fds and its own shared state.

## Confirmed bugs / technical debt

- **No TUN/TAP device:** `/dev/net/tun` does not exist (there is no network stack to attach a tap
  device to), so pasta and slirp4netns cannot start: rootless podman's default network, its port
  publishing and `--network slirp4netns` fail, and rootless containers work only with
  `--network host` (the Android app makes that rootless podman's default, `android/setup`).
- **Namespace isolation is guest-side only:** although initial-namespace guests are blocked from
  directly accessing allocated container `127.a.b.x` blocks, other apps on the host device can
  still reach a container's host loopback sockets directly.
- **Smaller deviations:** IPv6 on virtual devices is unusable and on-link IPv6 is handed to the
  host. `kernel/nft` records the unsupported POSTROUTING, SNAT and MASQUERADE effects.

## Open questions

- Should forwarded connections be torn down when the DNAT rule disappears?

## To verify

- How docker (with and without docker-proxy) and podman listeners interact with the dual-stack
  forwarding gap on a real device.
