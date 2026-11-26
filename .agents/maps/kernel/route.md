# kernel/route Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/kernel/route.md` for the paired decision history (not yet created; decisions from before the split are D4 and the routing parts of D3, D9 and D12 in `.agents/decisions/kernel/net.md`).
>
> Verified: 2026-11-22 (split out of the kernel/net full mapping of 2026-11-11; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-25 (targeted verification only since the split; latest change: `RTA_IIF` input-route lookups in `route::get`)

## Responsibilities

`kernel/route` synthesizes and queries the guest's routing tables and default FIB rules:

- assembling the main and local routing tables from Android `LinkProperties` routes, the host's
  `/proc/net/route`/`ipv6_route`, or interface-address synthesis, merged with virtual-device routes;
- answering `ip route get` lookups and encoding the `RTM_GETROUTE` and `RTM_GETRULE` messages that
  `kernel/netlink` sends;
- rendering `/proc/net/route` and `/proc/net/ipv6_route`.

Root: `core/kernel/src/route.rs`.

Outside the module: `Machine::set_routes` storage in `machine.rs` (`kernel/process`); netlink
socket transport, dump packing and `message`/`attr` builders (`kernel/netlink`); virtual-device
routes and namespace route configuration (`kernel/netns`); legacy `SIOCADDRT`/`SIOCDELRT` socket
ioctls (`kernel/net`); host route and source-address queries (`hal`); Android default-network route
callbacks (`android/service`, `android/native`).

## Key types

- `route::Entry` — one routing-table entry (`host` marks entries whose source the host chooses).

## Public entry points

- `route::{tables, merge, get, route_message, rule_messages, proc_route, proc_ipv6_route,
  host_routes}`.
- `Machine::set_routes` (in `machine.rs`, feeding the host route list used by `tables` and
  `host_routes`).

## Data flow / lifecycle

### Main and local tables

- Main table: the host's routes from `Machine::set_routes` (Android: the default network's
  `LinkProperties.getRoutes()`, unicast only on Android 13 and later, IPv4 metric 0 and IPv6 1024
  for the default route, 256 otherwise; an empty list on network loss, which leaves the main table
  empty), else the host's `/proc/net/route` and `/proc/net/ipv6_route` (reject, local, multicast
  and cache routes dropped; an empty file gives an empty table), else, when those cannot be read,
  synthesized from interface addresses with a default route on the interface the host would use.
- Local table: local, broadcast, loopback, IPv6 local and multicast entries derived from addresses
  of interfaces that are up.
- Virtual-device routes (`kernel/netns`) are merged in (`merge`); new namespaces have no host main
  table.

### Lookups, netlink messages and `/proc/net`

- `ip route get` (`route::get`): families other than IPv4 and IPv6 are `EOPNOTSUPP`; `RTA_IIF`
  performs Linux 6.1 input-route lookups (`ENODEV` for unknown `iif`; IPv4 requires a valid
  non-martian `RTA_SRC` and checks `route_localnet` for loopback `EINVAL`, returns `EXDEV` if
  `iif` is down or lacks an IPv4 address, returns `EHOSTUNREACH` for forwarded routes when
  `ip_forward` is 0, routes local/broadcast input via `lo` with `RTA_IIF` and without
  `RTA_PREFSRC`/`RTA_UID`; IPv6 rejects `::1` on non-`lo` `iif` with `ENETUNREACH`, omits
  `RTA_PREFSRC`, and keeps `RTA_IIF` including under `RTM_F_FIB_MATCH`); for output lookups,
  local-table hits are answered in process, virtual routes and new namespaces choose the source
  themselves, otherwise the source is `RTA_SRC` or what the host chooses by connecting a UDP
  socket (`appine_hal::net::source_for`), and the interface and gateway follow; a 464xlat
  fallback covers hosts with no main route; `RTM_F_FIB_MATCH` returns the matched route with its
  own table, while other IPv4 answers always name table main.
- Rules (`rule_messages`): IPv4 0/32766/32767, IPv6 0/32766, and the multicast routing families'
  32767.
- `kernel/netlink` sends these route (`route_message`), `ip route get` (`get`) and rule
  (`rule_messages`) messages.
- `/proc/net/route` (`proc_route`) lists the IPv4 main table's unicast routes and
  `/proc/net/ipv6_route` (`proc_ipv6_route`) the IPv6 main and local tables.

## Dependencies (inbound / outbound)

### Inbound

- `kernel/netlink`: `tables`, `merge`, `route_message`, `get` and `rule_messages` for
  `RTM_GETROUTE`/`RTM_GETRULE` replies and rtnetlink change-notification diffs.
- `kernel/procfs`: `proc_route` and `proc_ipv6_route` for `/proc/<pid>/net/route` and `ipv6_route`.
- `kernel/net`: `tables` / `host_routes` for traffic default-interface resolution and route helpers.
- `android/service` / `android/native` (via `Machine::set_routes`): pushes Android default-network
  routes into the kernel.

### Outbound

- `appine_hal::net`: `routes`, `source_for`, `Interface`, `Route`.
- `kernel/netlink`: `message` and `attr` helpers used to encode route and rule netlink messages.
- `kernel/netns`: virtual-device route inputs merged into the namespace's tables.

## Invariants and gotchas

- Passing an empty route list via `Machine::set_routes` empties the main table rather than falling
  back to interface-address synthesis.
- Dump ordering follows Linux's FIB dumps (IPv4 destination ascending with longer prefixes first;
  IPv6 fib6 post-order; main table before local table), and rtnetlink change notifications rely on
  dump encoding being deterministic across calls (`kernel/netlink`).

## Confirmed bugs / technical debt

- None.

## Open questions

- None.
