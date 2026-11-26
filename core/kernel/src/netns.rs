//! New network namespaces ([`NetNs`]): each starts with only the loopback interface lo (virtual
//! devices are in [`crate::netdev`]).
//!
//! Sockets stay host sockets, and addresses are translated at the syscall boundary: the guest's
//! 127.0.0.1..=253 map to the host's 127.a.b.1..=253 given to this namespace, other 127.0.0.0/8
//! addresses and the wildcard address bind 127.a.b.1 (with `vaddr` and `Bindings` preserving each
//! distinct guest address), and AF_INET6 ::1 and :: are the IPv4-mapped ::ffff:127.a.b.1 (host
//! sockets do not set `IPV6_V6ONLY`). As seen on Linux, 127.0.0.0/8 can be bound even while lo is
//! down or has no address, but is reachable only while lo is up with an address covering it.
//! Virtual addresses and routed destinations are translated as [`to_host`] describes; other
//! addresses cannot be bound (EADDRNOTAVAIL) or reached (ENETUNREACH). A socket that connects,
//! sends or listens without being bound is first bound to 127.a.b.1, so that the host does not
//! bind it to all interfaces instead.
//!
//! lo's configuration is read and written through netlink (`RTM_NEWADDR`, `RTM_DELADDR`,
//! `RTM_NEWLINK`) and interface ioctls, which is how bubblewrap brings lo up.

use std::borrow::Cow;
use std::rc::Rc;

use crate::cred::{Cred, cap};
use crate::errno::Errno;
use crate::nsproxy::{Loopback, NetNs};
use appine_hal::net::Interface;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IFF_UP: u32 = 0x1;
const IFF_LOOPBACK: u32 = 0x8;
const IFF_RUNNING: u32 = 0x40;
const IFF_LOWER_UP: u32 = 0x10000;
/// Interface index of lo in a new namespace.
pub(crate) const LO_INDEX: u32 = 1;
const LOOPBACK6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// All network namespaces (address translation looks at virtual addresses in other
/// namespaces): the first is the initial one.
pub(crate) struct World {
    pub all: Vec<Rc<NetNs>>,
}

/// First `u16` block index (`[a, b]` in `127.a.b.0/24`) allocated to new network namespaces:
/// `0` (`127.0.0.0/24`) is standard loopback (`127.0.0.1`, DNS stub `127.0.0.53`) and `1`
/// (`127.0.1.0/24`) is reserved for initial-namespace loopback (including Debian's `127.0.1.1`
/// hostname convention), so container blocks start at `127.0.2.0/24`.
pub(crate) const FIRST_BLOCK: u16 = 2;

/// Host loopback block for the virtual addresses of the initial namespace: 127.255.0.0/16 (the
/// blocks 127.a.b.0/24 of new namespaces never use 255 for a).
pub(crate) const INIT_BLOCK: u8 = 255;

/// 127.a.b.254, which a new namespace binds as the source when connecting to its own virtual
/// address: translated back, it is this namespace's virtual address (guest `127.0.0.254` maps onto
/// `127.a.b.1` with `vaddr` so it never collides with this host address).
const SELF_VIA_VADDR: u8 = 254;

impl World {
    pub(crate) fn init(&self) -> &Rc<NetNs> {
        &self.all[0]
    }

    /// Which new namespace the host loopback block 127.a.b.0/24 belongs to.
    fn by_block(&self, a: u8, b: u8) -> Option<&Rc<NetNs>> {
        self.all.iter().find(|n| n.host_net == Some([a, b]))
    }

    /// Which namespace (other than `me`) has virtual address `ip`: when several do, the one in a
    /// subnet `me` has a directly connected route to.
    fn owner(&self, me: &NetNs, ip: [u8; 4]) -> Option<&Rc<NetNs>> {
        let mut found = self.all.iter().filter(|n| {
            !std::ptr::eq(n.as_ref(), me)
                && crate::netdev::local_v4(n).iter().any(|(a, _)| *a == ip)
        });
        let first = found.next()?;
        let mut rest = std::iter::once(first).chain(found);
        let direct = connected(me);
        Some(
            rest.find(|_| direct.iter().any(|&(net, p)| covers(net, p, ip)))
                .unwrap_or(first),
        )
    }
}

// ---- Translation to the host ----

/// What a guest address is used for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Use {
    /// bind: must be a local address (EADDRNOTAVAIL otherwise); the wildcard address also works.
    Bind,
    /// connect, sendto: must be reachable (ENETUNREACH otherwise).
    Reach,
}

/// A guest address translated to the host's, the result of [`to_host`].
pub(crate) struct Mapped {
    pub addr: Vec<u8>,
    /// The network namespace of the destination (low-port mapping goes by it); None means it is
    /// handed to the host network (going out through the default route, or not a virtual address
    /// in the initial namespace).
    pub target: Option<Rc<NetNs>>,
    /// Host address (port 0) an unbound socket is bound to first: in a new namespace, its
    /// 127.a.b.1; in the initial namespace connecting to another namespace, the host address of
    /// the virtual address facing the other side.
    pub source: Option<Vec<u8>>,
    /// Bound to a virtual address in a new namespace (127.a.b.1 on the host; getsockname reports
    /// the virtual address).
    pub vaddr: Option<[u8; 4]>,
    /// True when an initial-namespace guest tried to reach a host loopback address (`127.a.b.x`)
    /// currently allocated to another network namespace: must be refused/dropped at the socket
    /// layer instead of reaching the host socket directly.
    pub isolated: bool,
}

impl Mapped {
    fn plain(addr: &[u8]) -> Mapped {
        Mapped {
            addr: addr.to_vec(),
            target: None,
            source: None,
            vaddr: None,
            isolated: false,
        }
    }
}

/// Whether `addr` in `me` is a direct initial-namespace attempt to access a host loopback block
/// (`127.a.b.x`, including IPv4-mapped IPv6) currently allocated to another network namespace.
pub(crate) fn is_foreign_loopback(w: &World, me: &NetNs, addr: &[u8]) -> bool {
    me.host_net.is_none()
        && ipv4_of(addr).is_some_and(|ip| ip[0] == 127 && w.by_block(ip[1], ip[2]).is_some())
}

/// Translates an address given by the guest to the host's (bind, connect, sendto). Addresses
/// that are neither IPv4 nor IPv6 (AF_UNSPEC disconnects) are returned unchanged.
///
/// A new network namespace (127.a.b.0/24):
/// - 127.0.0.x is 127.a.b.x, the wildcard address is allowed only for bind, and 127.0.0.x is
///   unreachable while lo is down or has no address ([`Loopback::has_v4`]); ::1 and :: are the
///   IPv4-mapped 127.a.b.1. `icmp6` means an ICMPv6 socket: it cannot send to IPv4-mapped
///   addresses, so ::1 becomes the host's real ::1 (echo is answered by the host kernel), and the
///   wildcard address is bound to ::1 as well.
/// - Addresses on its own virtual devices are 127.a.b.1 too (the same as the wildcard address, so
///   a service listening on the wildcard address is reachable through any of them).
/// - Another namespace's virtual address: needs a route through a virtual device (ENETUNREACH
///   without one) and becomes that namespace's 127.c.d.1; those of the initial namespace become
///   its 127.255.x.y.
/// - An address that is nobody's virtual address: reachable through a route via a gateway (the
///   default route), it is handed to the host network unchanged; missing from a directly
///   connected subnet, EHOSTUNREACH; with no route, ENETUNREACH.
/// - Other addresses cannot be bound (EADDRNOTAVAIL).
///
/// The initial namespace: its own virtual addresses become 127.255.x.y; another namespace's
/// virtual addresses reachable through a route over a virtual device are handled as above; the
/// rest are unchanged.
pub(crate) fn to_host(
    w: &World,
    me: &Rc<NetNs>,
    addr: &[u8],
    usage: Use,
    icmp6: bool,
) -> Result<Mapped, Errno> {
    let Some([a, b]) = me.host_net else {
        return init_to_host(w, me, addr, usage);
    };
    let lo = me.lo.borrow();
    let fail = || match usage {
        Use::Bind => Errno::EADDRNOTAVAIL,
        Use::Reach => Errno::ENETUNREACH,
    };
    let block = |x: u8| [127, a, b, x];
    let src = || implicit_bind(me, family(addr).unwrap_or(AF_INET), icmp6);
    let mapped_to = |ip: [u8; 4], target: &Rc<NetNs>, vaddr| Mapped {
        addr: with_ipv4(addr, ip),
        target: Some(target.clone()),
        source: src(),
        vaddr,
        isolated: false,
    };
    match family(addr) {
        Some(AF_INET6) if addr.len() >= 24 && icmp6 => {
            let ip = &addr[8..24];
            if ip == LOOPBACK6 && !(lo.up && lo.v6) {
                return Err(Errno::EADDRNOTAVAIL);
            }
            if !(ip == LOOPBACK6 || ip == [0; 16] && usage == Use::Bind) {
                return Err(fail());
            }
            let mut out = addr.to_vec();
            out[8..24].copy_from_slice(&LOOPBACK6);
            if let Some(s) = out.get_mut(24..28) {
                s.fill(0);
            }
            Ok(Mapped {
                target: Some(me.clone()),
                source: src(),
                ..Mapped::plain(&out)
            })
        }
        Some(AF_INET6) if addr.len() >= 24 && mapped(&addr[8..24]).is_none() => {
            let ip: [u8; 16] = addr[8..24].try_into().unwrap();
            if ip == [0; 16] && usage == Use::Bind {
                return Ok(mapped_to(block(1), me, None));
            }
            if ip == LOOPBACK6 {
                // Without ::1 a connection cannot choose a source address
                if !(lo.up && lo.v6) {
                    return Err(Errno::EADDRNOTAVAIL);
                }
                return Ok(mapped_to(block(1), me, None));
            }
            // Other IPv6 addresses: those going out through a route over a virtual device are
            // handed to the host network
            if usage == Use::Reach && crate::netdev::routes_v6(me, &ip) {
                return Ok(Mapped::plain(addr));
            }
            Err(fail())
        }
        Some(AF_INET | AF_INET6) if ipv4_of(addr).is_some() => {
            let ip = ipv4_of(addr).unwrap();
            if ip == [0; 4] {
                return match usage {
                    Use::Bind => Ok(mapped_to(block(1), me, None)),
                    Use::Reach => Err(fail()),
                };
            }
            if ip[0] == 127 {
                if !lo.has_v4(ip, usage) {
                    return Err(fail());
                }
                // Keep the direct host suffixes below SELF_VIA_VADDR. Other loopback
                // addresses share .1, with Bindings separating their host ports.
                let direct = ip[..3] == [127, 0, 0] && (1..SELF_VIA_VADDR).contains(&ip[3]);
                let host_ip = block(if direct { ip[3] } else { 1 });
                let vaddr = (usage == Use::Bind
                    && (!direct || (family(addr) == Some(AF_INET6) && ip[3] == 1)))
                    .then_some(ip);
                return Ok(mapped_to(host_ip, me, vaddr));
            }
            drop(lo);
            if crate::netdev::local_v4(me).iter().any(|(x, _)| *x == ip) {
                if usage == Use::Bind {
                    return Ok(mapped_to(block(1), me, Some(ip)));
                }
                // Connecting to its own virtual address: the source is bound to 127.a.b.254, and
                // both ends translate back to the virtual address
                let mut m = mapped_to(block(1), me, None);
                m.source = m.source.map(|s| with_ipv4(&s, block(SELF_VIA_VADDR)));
                return Ok(m);
            }
            if usage == Use::Bind {
                return Err(fail());
            }
            let route = crate::netdev::route_v4(me, ip).ok_or_else(fail)?;
            match w.owner(me, ip) {
                Some(m) => Ok(mapped_to(host_of(w, m, ip)?, m, None)),
                // Handed to the host network (going out through the gateway): no loopback address
                // is bound first, or the traffic could not get out
                None if route.gateway.is_some() => Ok(Mapped::plain(addr)),
                None => Err(Errno::EHOSTUNREACH),
            }
        }
        Some(AF_INET | AF_INET6) => Err(Errno::EINVAL),
        _ => Ok(Mapped::plain(addr)),
    }
}

/// [`to_host`] in the initial namespace.
fn init_to_host(w: &World, me: &Rc<NetNs>, addr: &[u8], usage: Use) -> Result<Mapped, Errno> {
    let Some(ip) = ipv4_of(addr).filter(|ip| *ip != [0; 4]) else {
        return Ok(Mapped::plain(addr));
    };
    if ip[0] == 127 {
        return match (w.by_block(ip[1], ip[2]).is_some(), usage) {
            (true, Use::Bind) => Err(Errno::EADDRNOTAVAIL),
            (true, Use::Reach) => Ok(Mapped {
                isolated: true,
                ..Mapped::plain(addr)
            }),
            (false, _) => Ok(Mapped::plain(addr)),
        };
    }
    if crate::netdev::local_v4(me).iter().any(|(x, _)| *x == ip) {
        return Ok(Mapped {
            addr: with_ipv4(addr, init_host(me, ip)?),
            target: Some(me.clone()),
            source: None,
            vaddr: None,
            isolated: false,
        });
    }
    if usage == Use::Bind {
        return Ok(Mapped::plain(addr));
    }
    // Only routes through virtual devices count: the host's subnets belong to the host
    let Some(route) = crate::netdev::route_v4(me, ip) else {
        return Ok(Mapped::plain(addr));
    };
    match w.owner(me, ip) {
        Some(m) => {
            let src = source(me, ip)
                .map(|s| init_host(me, s).map(|h| with_ipv4(&any_like(addr), h)))
                .transpose()?;
            Ok(Mapped {
                addr: with_ipv4(addr, host_of(w, m, ip)?),
                target: Some(m.clone()),
                source: src,
                vaddr: None,
                isolated: false,
            })
        }
        None if route.gateway.is_none() => Err(Errno::EHOSTUNREACH),
        None => Ok(Mapped::plain(addr)),
    }
}

/// The wildcard address of the same family as `addr`, with port 0.
pub(crate) fn any_like(addr: &[u8]) -> Vec<u8> {
    let mut s = vec![
        0u8;
        if family(addr) == Some(AF_INET6) {
            28
        } else {
            16
        }
    ];
    s[..2].copy_from_slice(&addr[..2]);
    s
}

/// The host address (port 0) an unbound socket is bound to first.
pub(crate) fn implicit_bind(ns: &NetNs, family: i32, icmp6: bool) -> Option<Vec<u8>> {
    let [a, b] = ns.host_net?;
    Some(if icmp6 {
        let mut s = vec![0u8; 28];
        s[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        s[8..24].copy_from_slice(&LOOPBACK6);
        s
    } else if family == AF_INET6 {
        let mut s = vec![0u8; 28];
        s[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        s[18..20].copy_from_slice(&[0xff, 0xff]);
        s[20..24].copy_from_slice(&[127, a, b, 1]);
        s
    } else {
        let mut s = vec![0u8; 16];
        s[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        s[4..8].copy_from_slice(&[127, a, b, 1]);
        s
    })
}

impl Loopback {
    /// Whether IPv4 loopback address `ip` may be used this way: as seen on Linux, 127.0.0.0/8 can
    /// always be bound (even while lo is down or has no address), and is reachable only when lo
    /// is up and the address's subnet is configured on it.
    fn has_v4(&self, ip: [u8; 4], usage: Use) -> bool {
        let covered = |&(a, len): &([u8; 4], u8)| {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from_be_bytes(a) & mask == u32::from_be_bytes(ip) & mask
        };
        match usage {
            Use::Bind => true,
            Use::Reach => self.up && self.v4.iter().any(covered),
        }
    }
}

/// The host address of virtual address `ip` in another namespace `m`: 127.c.d.1 for a new
/// namespace, 127.255.x.y for the initial one.
fn host_of(w: &World, m: &NetNs, ip: [u8; 4]) -> Result<[u8; 4], Errno> {
    match m.host_net {
        Some([c, d]) => Ok([127, c, d, 1]),
        None => init_host(w.init(), ip),
    }
}

/// The host loopback address (127.255.x.y) of virtual address `v` in the initial namespace,
/// allocated if there is none. Returns `EADDRNOTAVAIL` when all 65,534 slots in `127.255.0.0/16`
/// are already in use.
pub(crate) fn init_host(init: &NetNs, v: [u8; 4]) -> Result<[u8; 4], Errno> {
    let mut d = init.devs.borrow_mut();
    if let Some(h) = d.hostmap.get_or_alloc(v) {
        return Ok(h);
    }
    // Reclaim any veths whose peer namespace has already been dropped before declaring exhaustion.
    d.prune();
    d.hostmap.get_or_alloc(v).ok_or(Errno::EADDRNOTAVAIL)
}

// ---- Translation back to the guest ----

/// The role of a host address ([`from_host`]).
pub(crate) enum Role<'a> {
    /// The peer.
    Peer,
    /// The local end: whether the guest bound the wildcard address and is not connected yet
    /// (reporting the wildcard address), the virtual address it is bound to (127.a.b.1 on the
    /// host), and the peer's host address (the local address facing it).
    Local {
        any: bool,
        vaddr: Option<[u8; 4]>,
        peer: Option<&'a [u8]>,
    },
}

/// Translates an address given by the host (local or peer) to what processes in `me` see: its own
/// block 127.a.b.x is 127.0.0.x (127.a.b.1 may also be the IPv4 127.0.0.1 or the ::1 that was
/// connected to, decided by the address family when it cannot be told apart), another
/// namespace's 127.c.d.1 is that namespace's virtual address facing `me`, and 127.255.x.y is a
/// virtual address of the initial namespace. For a connection in a new namespace going out
/// through the host network, the local host address becomes the source address this namespace
/// uses toward the peer. For `icmp6` see [`to_host`].
pub(crate) fn from_host(
    w: &World,
    me: &NetNs,
    addr: &[u8],
    role: Role<'_>,
    icmp6: bool,
) -> Vec<u8> {
    let any = matches!(role, Role::Local { any: true, .. });
    let mut out = addr.to_vec();
    if any && matches!(family(addr), Some(AF_INET | AF_INET6)) {
        let range = if family(addr) == Some(AF_INET) {
            4..8
        } else {
            8..24
        };
        if let Some(s) = out.get_mut(range) {
            s.fill(0);
        }
        return out;
    }
    if icmp6 && family(addr) == Some(AF_INET6) {
        return out;
    }
    let Some(x) = ipv4_of(addr) else {
        return out;
    };
    if x == [0; 4] {
        return out;
    }
    // A connection forwarded in from outside (crate::forward): the client's real address and port
    if x[..2] == [127, crate::forward::OUTSIDE_BLOCK]
        && let Some((ip, port)) =
            crate::forward::outside_peer(x, u16::from_be_bytes([addr[2], addr[3]]))
    {
        out = with_ipv4(addr, ip);
        out[2..4].copy_from_slice(&port.to_be_bytes());
        return out;
    }
    let guest_of_peer = |p: &[u8]| from_host(w, me, p, Role::Peer, icmp6);
    match me.host_net {
        Some([a, b]) => {
            if x[..3] == [127, a, b] {
                let first = || crate::netdev::local_v4(me).first().map(|(v, _)| *v);
                if x[3] == SELF_VIA_VADDR
                    && let Some(v) = first()
                {
                    return with_ipv4(addr, v);
                }
                if let Role::Local { vaddr, peer, .. } = &role {
                    if let Some(v) = vaddr.filter(|_| x[3] == 1) {
                        return with_ipv4(addr, v);
                    }
                    // Connected to its own virtual address: the local end is the virtual address
                    // too
                    if peer.and_then(ipv4_of) == Some([127, a, b, SELF_VIA_VADDR])
                        && let Some(v) = first()
                    {
                        return with_ipv4(addr, v);
                    }
                    // Connected from another namespace: the local end is the address facing the
                    // other side
                    let remote = peer
                        .and_then(ipv4_of)
                        .filter(|p| p[0] != 127 || p[1..3] != [a, b]);
                    if remote.is_some()
                        && let Some(g) = peer.map(guest_of_peer).as_deref().and_then(ipv4_of)
                        && let Some(s) = source(me, g)
                    {
                        return with_ipv4(addr, s);
                    }
                }
                if family(addr) == Some(AF_INET) {
                    out[4..8].copy_from_slice(&[127, 0, 0, x[3]]);
                } else if x[3] == 1 {
                    // 127.a.b.1 is the guest's ::1 (or possibly the IPv4 127.0.0.1 that was
                    // connected to)
                    out[8..24].copy_from_slice(&LOOPBACK6);
                } else {
                    out[20..24].copy_from_slice(&[127, 0, 0, x[3]]);
                }
                return out;
            }
            if let Some(g) = remote_guest(w, me, x) {
                return with_ipv4(addr, g);
            }
            // A connection going out through the host network: the local end is this
            // namespace's source address
            if x[0] != 127
                && let Role::Local { peer, .. } = &role
                && let Some(s) = peer
                    .and_then(ipv4_of)
                    .and_then(|p| source(me, p))
                    .or_else(|| crate::netdev::local_v4(me).first().map(|(a, _)| *a))
            {
                return with_ipv4(addr, s);
            }
            out
        }
        None => remote_guest(w, me, x).map_or(out, |g| with_ipv4(addr, g)),
    }
}

/// The virtual address seen in `me` for another namespace's loopback address on the host
/// (127.c.d.1, 127.255.x.y).
fn remote_guest(w: &World, me: &NetNs, x: [u8; 4]) -> Option<[u8; 4]> {
    if x[0] != 127 {
        return None;
    }
    if x[1] == INIT_BLOCK {
        return init_guest(w.init(), x);
    }
    let m = w.by_block(x[1], x[2]).filter(|_| x[3] == 1)?;
    facing(m, me)
}

/// Which virtual address in the initial namespace the host's 127.255.x.y stands for.
fn init_guest(init: &NetNs, h: [u8; 4]) -> Option<[u8; 4]> {
    init.devs.borrow().hostmap.guest_of(h)
}

/// The virtual address of `m` that faces `me`: one in a subnet `me` has a directly connected
/// route to, otherwise the first.
fn facing(m: &NetNs, me: &NetNs) -> Option<[u8; 4]> {
    let mine = crate::netdev::local_v4(m);
    let direct = connected(me);
    mine.iter()
        .find(|(a, _)| direct.iter().any(|&(net, p)| covers(net, p, *a)))
        .or(mine.first())
        .map(|(a, _)| *a)
}

/// The local end in `me` when sending to guest address `peer`: `local` (the local end on the
/// host, whose port is kept) with the source address used toward the peer.
pub(crate) fn local_toward(me: &NetNs, local: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
    let ip = ipv4_of(peer)?;
    let src = source(me, ip)?;
    Some(with_ipv4(local, src))
}

/// Translates a host peer address `host_addr` (with host port intact) into the guest peer address
/// seen by `me`, performing at most one `owner_of_host` + `lookup_host` lookup.
///
/// When `host_addr` has an inet port and is not in the outside-client block (`127.254.0.0/16`),
/// calls `resolve_port(owner, ns_guest_port, host_port)` to choose the guest port to substitute.
/// When `host_addr` belongs to a new network namespace whose binding records a specific IPv4
/// address (e.g. a virtual-device IP or `127.0.0.1` sharing host `127.a.b.1`), reports that exact
/// guest IP rather than collapsing it through `127.a.b.1`.
pub(crate) fn from_host_peer(
    w: &World,
    me: &NetNs,
    proto: i32,
    host_addr: &[u8],
    self_peer: bool,
    icmp6: bool,
    resolve_port: impl FnOnce(Option<&NetNs>, Option<u16>, u16) -> Option<u16>,
) -> Vec<u8> {
    let host_port = matches!(family(host_addr), Some(AF_INET | AF_INET6))
        .then(|| {
            host_addr
                .get(2..4)
                .map(|p| u16::from_be_bytes([p[0], p[1]]))
        })
        .flatten();
    let host_ip = ipv4_of(host_addr);
    let outside = host_ip.is_some_and(|ip| ip[..2] == [127, crate::forward::OUTSIDE_BLOCK]);
    let owner = (!outside).then(|| owner_of_host(w, host_addr)).flatten();
    let ns_entry = owner
        .as_deref()
        .filter(|o| o.host_net.is_some())
        .and_then(|o| lookup_host(o, proto, host_ip?, host_port?).map(|e| (o, e)));
    let guest_port = if outside {
        None
    } else {
        host_port.and_then(|p| resolve_port(owner.as_deref(), ns_entry.map(|(_, (g, _))| g), p))
    };
    let mut out = if !icmp6
        && let Some((o, (_, BindAddr::V4(v)))) = ns_entry
        && (v[0] != 127 || std::ptr::eq(o, me))
    {
        with_ipv4(host_addr, v)
    } else if self_peer && let Some(v) = from_self(me, host_addr) {
        v
    } else {
        from_host(w, me, host_addr, Role::Peer, icmp6)
    };
    if let Some(g) = guest_port
        && out.len() >= 4
    {
        out[2..4].copy_from_slice(&g.to_be_bytes());
    }
    out
}

// ---- Bindings and listeners ----

/// How long after a binding in a new network namespace is removed its `(proto, host_ip, host_port)`
/// still translates back to its guest port and address (for in-flight UDP replies after close).
const LINGER: std::time::Duration = std::time::Duration::from_secs(10);

/// Normalized guest bind address of a socket in a new network namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BindAddr {
    /// IPv4 wildcard (`0.0.0.0`, or `::ffff:0.0.0.0` on AF_INET6).
    AnyV4,
    /// IPv6 wildcard (`::` on AF_INET6; dual-stack unless `v6only` is set).
    AnyV6,
    /// Specific IPv4 address (`127.0.0.x` or a virtual-device IPv4 address, including IPv4-mapped).
    V4([u8; 4]),
    /// Specific non-mapped IPv6 address (e.g. `::1`).
    V6([u8; 16]),
}

impl BindAddr {
    /// Parses a guest inet sockaddr into its normalized [`BindAddr`].
    pub(crate) fn from_guest(addr: &[u8]) -> Option<BindAddr> {
        match family(addr) {
            Some(AF_INET) if addr.len() >= 8 => {
                let ip: [u8; 4] = addr[4..8].try_into().ok()?;
                Some(if ip == [0; 4] {
                    BindAddr::AnyV4
                } else {
                    BindAddr::V4(ip)
                })
            }
            Some(AF_INET6) if addr.len() >= 24 => {
                if let Some(v4) = mapped(&addr[8..24]) {
                    Some(if v4 == [0; 4] {
                        BindAddr::AnyV4
                    } else {
                        BindAddr::V4(v4)
                    })
                } else {
                    let ip: [u8; 16] = addr[8..24].try_into().ok()?;
                    Some(if ip == [0; 16] {
                        BindAddr::AnyV6
                    } else {
                        BindAddr::V6(ip)
                    })
                }
            }
            _ => None,
        }
    }
}

/// Whether two guest bindings can match the same incoming destination (Linux 6.1's
/// `ipv4_rcv_saddr_equal` / `ipv6_rcv_saddr_equal`).
fn addrs_overlap(a: BindAddr, a_v6only: bool, b: BindAddr, b_v6only: bool) -> bool {
    #[derive(Clone, Copy)]
    enum Cover<T> {
        None,
        One(T),
        All,
    }
    fn overlap<T: PartialEq>(x: Cover<T>, y: Cover<T>) -> bool {
        match (x, y) {
            (Cover::None, _) | (_, Cover::None) => false,
            (Cover::All, _) | (_, Cover::All) => true,
            (Cover::One(p), Cover::One(q)) => p == q,
        }
    }
    let v4 = |addr: BindAddr, v6only: bool| match addr {
        BindAddr::AnyV4 => Cover::All,
        BindAddr::AnyV6 if !v6only => Cover::All,
        BindAddr::V4(ip) => Cover::One(ip),
        BindAddr::AnyV6 | BindAddr::V6(_) => Cover::None,
    };
    let v6 = |addr: BindAddr| match addr {
        BindAddr::AnyV6 => Cover::All,
        BindAddr::V6(ip) => Cover::One(ip),
        BindAddr::AnyV4 | BindAddr::V4(_) => Cover::None,
    };
    overlap(v4(a, a_v6only), v4(b, b_v6only)) || overlap(v6(a), v6(b))
}

/// Parameters of a candidate bind or listen conflict check in a new network namespace.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BindReq {
    pub proto: i32,
    pub guest_port: u16,
    pub addr: BindAddr,
    pub v6only: bool,
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub euid: u32,
    pub bound_dev_if: i32,
}

/// Parameters for registering a bound TCP or UDP socket in a new network namespace
/// ([`add_binding`], [`add_ephemeral`]).
#[derive(Debug, Clone)]
pub(crate) struct NewBinding {
    /// Protocol (`IPPROTO_TCP` for TCP/MPTCP, `IPPROTO_UDP` for UDP).
    pub proto: i32,
    /// Normalized guest bind address.
    pub addr: BindAddr,
    /// `IPV6_V6ONLY` recorded on the guest AF_INET6 socket.
    pub v6only: bool,
    /// Live `SO_REUSEADDR`.
    pub reuseaddr: bool,
    /// Live `SO_REUSEPORT`.
    pub reuseport: bool,
    /// Socket owner's effective UID (`sock_i_uid`, for `SO_REUSEPORT` matching).
    pub euid: u32,
    /// Bound device interface index (`SO_BINDTODEVICE` / `SO_BINDTOIFINDEX`, 0 if unbound).
    pub bound_dev_if: i32,
    /// Actively receiving inbound traffic: TCP `TCP_LISTEN`, or any bound UDP socket.
    pub listening: bool,
    /// Accepted TCP child socket (bound to the listener's port, not accepting new SYNs).
    pub accepted: bool,
    /// Host IPv4 address bound on the host (`[0; 4]` for `wide` host-wildcard UDP sockets).
    pub host_ip: [u8; 4],
    /// Host port bound on the host.
    pub host_port: u16,
    /// Bound to the host wildcard address (`0.0.0.0` / `::`), reachable via `127.a.b.1`.
    pub wide: bool,
}

/// One bound TCP or UDP socket in a new network namespace.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    /// Unique identifier stored in [`crate::net::InetSocket::listener`].
    id: u64,
    /// Guest port (nonzero).
    guest_port: u16,
    proto: i32,
    addr: BindAddr,
    v6only: bool,
    reuseaddr: bool,
    reuseport: bool,
    euid: u32,
    bound_dev_if: i32,
    listening: bool,
    accepted: bool,
    host_ip: [u8; 4],
    host_port: u16,
    wide: bool,
}

#[derive(Debug, Clone)]
struct Lingered {
    guest_port: u16,
    addr: BindAddr,
    released: std::time::Instant,
}

/// Per-namespace table of bound TCP/UDP sockets and host-port mappings in a new network namespace.
#[derive(Debug, Default)]
pub(crate) struct Bindings {
    entries: Vec<Binding>,
    /// Recently released `(proto, host_ip, host_port)` entries kept for [`LINGER`].
    linger: std::collections::HashMap<(i32, [u8; 4], u16), Lingered>,
}

/// Whether `req` conflicts with any existing binding in `me` (excluding `skip_id`, used when a
/// bound TCP socket enters `listen`), matching Linux 6.1's `inet_csk_bind_conflict` (TCP) and
/// `udp_lib_lport_inuse` (UDP).
pub(crate) fn bind_conflict(me: &NetNs, req: &BindReq, skip_id: Option<u64>) -> bool {
    let is_tcp = req.proto == crate::net::IPPROTO_TCP;
    me.listeners.borrow().entries.iter().any(|b| {
        if Some(b.id) == skip_id || b.proto != req.proto || b.guest_port != req.guest_port {
            return false;
        }
        // Sockets bound to two distinct devices never conflict (Linux's inet_csk_bind_conflict /
        // udp_lib_lport_inuse).
        if req.bound_dev_if != 0 && b.bound_dev_if != 0 && req.bound_dev_if != b.bound_dev_if {
            return false;
        }
        if !addrs_overlap(req.addr, req.v6only, b.addr, b.v6only) {
            return false;
        }
        let reuse_ok = req.reuseaddr && b.reuseaddr && !(is_tcp && b.listening);
        let rport_ok = req.reuseport && b.reuseport && req.euid == b.euid;
        !reuse_ok && !rport_ok
    })
}

/// Checks whether the already-registered TCP binding `id` conflicts with any other binding in `me`
/// upon entering `TCP_LISTEN` (e.g. two `SO_REUSEADDR` sockets bound to overlapping addresses when
/// the second calls `listen()`).
pub(crate) fn listen_conflict(me: &NetNs, id: std::num::NonZeroU64) -> bool {
    let req = {
        let b = me.listeners.borrow();
        b.entries
            .iter()
            .find(|e| e.id == id.get())
            .map(|e| BindReq {
                proto: e.proto,
                guest_port: e.guest_port,
                addr: e.addr,
                v6only: e.v6only,
                reuseaddr: e.reuseaddr,
                reuseport: e.reuseport,
                euid: e.euid,
                bound_dev_if: e.bound_dev_if,
            })
    };
    req.is_some_and(|r| bind_conflict(me, &r, Some(id.get())))
}

/// Returns an existing host port to share when `req` joins the exact same host endpoint as a
/// compatible `SO_REUSEPORT` (or UDP `SO_REUSEADDR`) socket in `me`. Distinct guest addresses
/// (such as `127.0.0.1` vs `<vaddr>`, `0.0.0.0` vs `[::]`, `::1` vs `127.0.0.1`) always receive
/// distinct host ports so they never collide on `127.a.b.1`.
pub(crate) fn shared_host_port(me: &NetNs, req: &BindReq, host_ip: [u8; 4]) -> Option<u16> {
    let is_udp = req.proto == crate::net::IPPROTO_UDP;
    me.listeners.borrow().entries.iter().rev().find_map(|b| {
        if b.proto != req.proto
            || b.guest_port != req.guest_port
            || b.addr != req.addr
            || b.v6only != req.v6only
            || b.bound_dev_if != req.bound_dev_if
            || b.host_ip != host_ip
            || b.wide
            || b.accepted
        {
            return None;
        }
        let share = (req.reuseport && b.reuseport && req.euid == b.euid)
            || (is_udp && req.reuseaddr && b.reuseaddr);
        share.then_some(b.host_port)
    })
}

/// Registers a bound socket in `me` at `guest_port` and returns its unique binding ID.
pub(crate) fn add_binding(me: &NetNs, guest_port: u16, entry: NewBinding) -> std::num::NonZeroU64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let binding = Binding {
        id,
        guest_port,
        proto: entry.proto,
        addr: entry.addr,
        v6only: entry.v6only,
        reuseaddr: entry.reuseaddr,
        reuseport: entry.reuseport,
        euid: entry.euid,
        bound_dev_if: entry.bound_dev_if,
        listening: entry.listening,
        accepted: entry.accepted,
        host_ip: entry.host_ip,
        host_port: entry.host_port,
        wide: entry.wide,
    };
    let mut b = me.listeners.borrow_mut();
    b.linger
        .remove(&(binding.proto, binding.host_ip, binding.host_port));
    b.entries.push(binding);
    std::num::NonZeroU64::new(id).expect("starts at 1")
}

/// Registers an ephemeral bind (`bind(0)` or implicit bind) in `me`, remapping `entry.host_port`
/// into `range` (then `1024..=65535`, then `1..1024`) if `entry.host_port` already aliases any
/// bound guest port for `entry.proto` in `me`.
pub(crate) fn add_ephemeral(
    me: &NetNs,
    entry: NewBinding,
    range: (u16, u16),
) -> (u16, std::num::NonZeroU64) {
    let guest_port = {
        let b = me.listeners.borrow();
        let in_use = |p: u16| {
            b.entries
                .iter()
                .any(|e| e.proto == entry.proto && e.guest_port == p)
        };
        if !in_use(entry.host_port) {
            entry.host_port
        } else {
            let (lo, hi) = (range.0.min(range.1).max(1), range.0.max(range.1).max(1));
            let start = entry.host_port.clamp(lo, hi);
            (start..=hi)
                .chain(lo..start)
                .chain(1024..=u16::MAX)
                .chain(1..1024)
                .find(|&p| !in_use(p))
                .unwrap_or(entry.host_port)
        }
    };
    let id = add_binding(me, guest_port, entry);
    (guest_port, id)
}

/// Removes binding `id` from `me` on socket close, keeping its `(proto, host_ip, host_port)`
/// reverse mapping for [`LINGER`] if no other live binding still holds that host endpoint.
pub(crate) fn remove_binding(me: &NetNs, id: std::num::NonZeroU64) {
    let Ok(mut b) = me.listeners.try_borrow_mut() else {
        return;
    };
    let Some(pos) = b.entries.iter().position(|e| e.id == id.get()) else {
        return;
    };
    let removed = b.entries.swap_remove(pos);
    let still_live = b.entries.iter().any(|e| {
        e.proto == removed.proto && e.host_ip == removed.host_ip && e.host_port == removed.host_port
    });
    if !still_live {
        let now = std::time::Instant::now();
        b.linger
            .retain(|_, v| now.duration_since(v.released) < LINGER);
        b.linger.insert(
            (removed.proto, removed.host_ip, removed.host_port),
            Lingered {
                guest_port: removed.guest_port,
                addr: removed.addr,
                released: now,
            },
        );
    }
}

/// Updates the `listening` state of binding `id` (TCP `listen()` / `shutdown()`).
pub(crate) fn set_listening(me: &NetNs, id: std::num::NonZeroU64, listening: bool) {
    if let Some(e) = me
        .listeners
        .borrow_mut()
        .entries
        .iter_mut()
        .find(|e| e.id == id.get())
    {
        e.listening = listening;
    }
}

/// Updates `SO_REUSEADDR` (`reuseport == false`) or `SO_REUSEPORT` (`reuseport == true`) on
/// binding `id`.
pub(crate) fn set_reuse(me: &NetNs, id: std::num::NonZeroU64, reuseport: bool, on: bool) {
    if let Some(e) = me
        .listeners
        .borrow_mut()
        .entries
        .iter_mut()
        .find(|e| e.id == id.get())
    {
        if reuseport {
            e.reuseport = on;
        } else {
            e.reuseaddr = on;
        }
    }
}

/// Updates the `SO_BINDTODEVICE` / `SO_BINDTOIFINDEX` index on binding `id`.
pub(crate) fn set_bound_dev(me: &NetNs, id: std::num::NonZeroU64, bound_dev_if: i32) {
    if let Some(e) = me
        .listeners
        .borrow_mut()
        .entries
        .iter_mut()
        .find(|e| e.id == id.get())
    {
        e.bound_dev_if = bound_dev_if;
    }
}

/// Resolves guest destination `dst` (as seen in new network namespace `t`) for `proto`
/// (`IPPROTO_TCP` or `IPPROTO_UDP`) to the host `(host_ip, host_port)` of the best matching
/// active listener (TCP `TCP_LISTEN`, or any bound UDP socket). Exact address matches and
/// device-bound listeners matching `dst`'s owning interface take priority over wildcards.
/// Returns `None` when no matching listener exists.
pub(crate) fn resolve_target(t: &NetNs, proto: i32, dst: &[u8]) -> Option<([u8; 4], u16)> {
    let [a, b] = t.host_net?;
    let port = dst.get(2..4).map(|p| u16::from_be_bytes([p[0], p[1]]))?;
    let want_v4 = ipv4_of(dst);
    let want_v6: Option<[u8; 16]> = if want_v4.is_none() && family(dst) == Some(AF_INET6) {
        dst.get(8..24).and_then(|s| s.try_into().ok())
    } else {
        None
    };
    if want_v4.is_none() && want_v6.is_none() {
        return None;
    }
    let has_dev_bound =
        t.listeners.borrow().entries.iter().any(|e| {
            e.proto == proto && e.guest_port == port && e.listening && e.bound_dev_if != 0
        });
    let dst_if: Option<i32> = if !has_dev_bound {
        None
    } else if want_v4.is_some_and(|ip| ip[0] == 127)
        || want_v6 == Some(std::net::Ipv6Addr::LOCALHOST.octets())
    {
        Some(LO_INDEX as i32)
    } else {
        let want: &[u8] = want_v4
            .as_ref()
            .map_or_else(|| want_v6.as_ref().unwrap().as_slice(), |ip| ip.as_slice());
        crate::netdev::interfaces(t)
            .into_iter()
            .find(|i| i.addrs.iter().any(|(_, addr, _)| addr.as_slice() == want))
            .map(|i| i.index as i32)
    };
    let dev_ok =
        |e: &Binding| e.bound_dev_if == 0 || dst_if.is_none_or(|idx| e.bound_dev_if == idx);
    let bindings = t.listeners.borrow();
    let endpoint = |e: &Binding| {
        let ip = if e.wide { [127, a, b, 1] } else { e.host_ip };
        (ip, e.host_port)
    };
    // Prefer device-bound matches over unbound matches within each address-specificity tier.
    let pick = |pred: &dyn Fn(&Binding) -> bool| -> Option<&Binding> {
        let mut best: Option<&Binding> = None;
        for e in bindings.entries.iter().rev() {
            if e.proto != proto || e.guest_port != port || !e.listening || !dev_ok(e) || !pred(e) {
                continue;
            }
            if dst_if.is_some_and(|idx| e.bound_dev_if == idx) {
                return Some(e);
            }
            if best.is_none() {
                best = Some(e);
            }
        }
        best
    };
    // Pass 1: exact address match takes priority over wildcard (Linux __inet_lookup_listener)
    if let Some(e) = pick(&|e| match (want_v4, want_v6, e.addr) {
        (Some(ip), _, BindAddr::V4(bound)) => ip == bound,
        (_, Some(ip), BindAddr::V6(bound)) => ip == bound,
        _ => false,
    }) {
        return Some(endpoint(e));
    }
    // Pass 2: wildcard match
    if want_v4.is_some() {
        return pick(&|e| {
            matches!(
                (e.addr, e.v6only),
                (BindAddr::AnyV4, _) | (BindAddr::AnyV6, false)
            )
        })
        .map(endpoint);
    }
    // Pure IPv6 destination: prefer IPv6-only wildcard before dual-stack wildcard
    pick(&|e| e.addr == BindAddr::AnyV6 && e.v6only)
        .or_else(|| pick(&|e| e.addr == BindAddr::AnyV6))
        .map(endpoint)
}

/// Whether a TCP socket (with `udp`, a bound UDP socket) in new network namespace `t` is
/// listening on guest address `dst` (a sockaddr as seen in `t`).
#[cfg(test)]
fn listening(t: &NetNs, dst: &[u8], udp: bool) -> bool {
    if dst.len() < 4 || !is_inet(dst) {
        return true;
    }
    let proto = if udp {
        crate::net::IPPROTO_UDP
    } else {
        crate::net::IPPROTO_TCP
    };
    resolve_target(t, proto, dst).is_some()
}

/// Looks up the guest `(guest_port, BindAddr)` for a host `(proto, host_ip, host_port)` in new
/// network namespace `owner` (checking live bindings, then recently released [`LINGER`] entries).
pub(crate) fn lookup_host(
    owner: &NetNs,
    proto: i32,
    host_ip: [u8; 4],
    host_port: u16,
) -> Option<(u16, BindAddr)> {
    let b = owner.listeners.borrow();
    if let Some(e) = b
        .entries
        .iter()
        .rev()
        .find(|e| e.proto == proto && e.host_port == host_port && e.host_ip == host_ip)
        .or_else(|| {
            b.entries
                .iter()
                .rev()
                .find(|e| e.proto == proto && e.host_port == host_port && e.wide)
        })
    {
        return Some((e.guest_port, e.addr));
    }
    let entry = b
        .linger
        .get(&(proto, host_ip, host_port))
        .or_else(|| b.linger.get(&(proto, [0; 4], host_port)))
        .filter(|l| l.released.elapsed() < LINGER)?;
    Some((entry.guest_port, entry.addr))
}

/// Extracts the IPv4 address from a host sockaddr (IPv4-mapped IPv6 included), or `[0; 4]` for
/// wildcards / non-IPv4 addresses.
pub(crate) fn host_ipv4(addr: &[u8]) -> [u8; 4] {
    ipv4_of(addr).unwrap_or([0; 4])
}

/// Rewrites `addr`'s IPv4 (or IPv4-mapped IPv6) address to `ip` and its port to `port`.
pub(crate) fn with_host_endpoint(addr: &[u8], ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut out = with_ipv4(addr, ip);
    if out.len() >= 4 {
        out[2..4].copy_from_slice(&port.to_be_bytes());
    }
    out
}

// ---- Sending to its own virtual address ----

/// Whether host address `host` is `me`'s 127.a.b.254 (the source bound when sending to its own
/// virtual address).
pub(crate) fn is_self_source(me: &NetNs, host: &[u8]) -> bool {
    matches!((me.host_net, ipv4_of(host)), (Some([a, b]), Some(x)) if x == [127, a, b, SELF_VIA_VADDR])
}

/// A datagram in `me` sent to its own virtual address `dst` (the guest's): when the port is that
/// of a socket bound to 127.a.b.254 ([`crate::nsproxy::Loopback::self_udp`], a client that sent to
/// its own virtual address, so this is the reply to it), the host destination `host` becomes
/// 127.a.b.254.
pub(crate) fn toward_self(me: &NetNs, dst: &[u8], host: Vec<u8>) -> Vec<u8> {
    let (Some([a, b]), Some(ip)) = (me.host_net, ipv4_of(dst)) else {
        return host;
    };
    let port = u16::from_be_bytes([dst[2], dst[3]]);
    if me.lo.borrow().self_udp.contains(&port)
        && crate::netdev::local_v4(me).iter().any(|(x, _)| *x == ip)
    {
        return with_ipv4(&host, [127, a, b, SELF_VIA_VADDR]);
    }
    host
}

/// A socket bound to 127.a.b.254 receives a datagram from 127.a.b.1 (`host` is the source): the
/// other side sent it to its own virtual address, so the source is that address too
/// ([`toward_self`]).
pub(crate) fn from_self(me: &NetNs, host: &[u8]) -> Option<Vec<u8>> {
    let ([a, b], x) = (me.host_net?, ipv4_of(host)?);
    if x != [127, a, b, 1] {
        return None;
    }
    let v = crate::netdev::local_v4(me).first()?.0;
    Some(with_ipv4(host, v))
}

// ---- OUTPUT and PREROUTING nat ----

/// Result of evaluating a nat hook (`output_nat`, `prerouting_nat`).
pub(crate) enum NatResult {
    /// Accepted without address translation.
    Pass,
    /// Destination rewritten to this guest sockaddr.
    Dnat(Vec<u8>),
    /// Dropped or rejected by a nat chain; handled with Linux's verdict rules (TCP times out on
    /// drop or fails immediately on reject; UDP connect is unaffected while sends fail on OUTPUT
    /// or drop silently on PREROUTING).
    Block(crate::nft::Outcome),
}

/// nftables OUTPUT nat ([`crate::nft::Nft::nat`]): a connection or datagram in `me` with protocol
/// `proto` (TCP, UDP) to guest address `dst` (a sockaddr). `vaddr` is the virtual address the
/// socket is bound to (the source; chosen by route when absent), `sport` is the local port, and
/// `mark` is the socket's `SO_MARK`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn output_nat(
    me: &NetNs,
    proto: u8,
    vaddr: Option<[u8; 4]>,
    sport: impl FnOnce() -> u16,
    dst: &[u8],
    uid: u32,
    gid: u32,
    mark: u32,
) -> Result<NatResult, Errno> {
    if !me.nft.borrow().has_nat(crate::nft::HOOK_LOCAL_OUT) {
        return Ok(NatResult::Pass);
    }
    let Some((ip, _)) = nat_ip(dst) else {
        return Ok(NatResult::Pass);
    };
    let src = match vaddr {
        Some(v) if ip.len() == 4 => v.to_vec(),
        _ if is_loopback(&ip) => ip.clone(),
        _ if ip.len() == 4 => source(me, ip[..4].try_into().unwrap())
            .unwrap_or_default()
            .to_vec(),
        _ => vec![0; 16],
    };
    let packet = NatPacket {
        hook: crate::nft::HOOK_LOCAL_OUT,
        proto,
        src,
        sport: sport(),
        uid,
        gid,
        iif: None,
        ct_state: crate::nft::CT_NEW,
        original_dst: None,
        mark,
    };
    hook_nat(me, &packet, dst)
}

/// The logical ingress interface for IPv4 hooks on a bridge, including unnumbered bridges.
pub(crate) struct BridgeHop {
    pub ns: Rc<NetNs>,
    pub iif: crate::nft::Iif,
    /// Destination after the bridge's own PREROUTING, before the endpoint's rules.
    pub dst: Vec<u8>,
}

pub(crate) fn bridge_hop(me: &NetNs, m: &Mapped, dst: &[u8]) -> Option<BridgeHop> {
    let target = m.target.as_ref()?;
    if std::ptr::eq(me, target.as_ref()) {
        return None;
    }
    let bridge = crate::netdev::shared_bridge(me, target, ipv4_of(dst)?)?;
    let dev = bridge.borrow();
    let ns = dev.ns.upgrade()?;
    if !ns.devs.borrow().conf.bridge_call_iptables {
        return None;
    }
    let iif = crate::nft::Iif {
        index: dev.index,
        name: dev.name.clone(),
        addr: dev.v4.first().map(|a| a.local.to_vec()).unwrap_or_default(),
    };
    Some(BridgeHop {
        ns,
        iif,
        dst: dst.to_vec(),
    })
}

/// The other namespace that a connection or datagram in `me` to guest address `dst` (already
/// translated to the host's `m`) enters, whose PREROUTING must run ([`prerouting_nat`]):
/// - the destination is in another namespace (a virtual address);
/// - going out through the host network from a new namespace enters the initial namespace when
///   the gateway is its address (a container reaching the outside through the outer bridge), or
///   the destination is one of its local addresses (a host address: a container connecting to a
///   port published on an outer address). With REDIRECT and DNAT in the outer PREROUTING for
///   traffic from the bridge, a container's outside connections and DNS can be transparently
///   proxied or hijacked. When the gateway is in another namespace (a router-like "container"),
///   nobody's PREROUTING is passed.
pub(crate) fn entering(w: &World, me: &Rc<NetNs>, m: &Mapped, dst: &[u8]) -> Option<Rc<NetNs>> {
    match &m.target {
        Some(t) if !Rc::ptr_eq(t, me) => Some(t.clone()),
        Some(_) => None,
        None => {
            let init = w.init();
            if me.host_net.is_none() || !init.nft.borrow().has_nat(crate::nft::HOOK_PRE_ROUTING) {
                return None;
            }
            let ip = ipv4_of(dst)?;
            let via_init = crate::netdev::route_v4(me, ip)
                .and_then(|e| <[u8; 4]>::try_from(e.gateway?.as_slice()).ok())
                .and_then(|gw| w.owner(me, gw))
                .is_some_and(|o| Rc::ptr_eq(o, init));
            (via_init || local_v4(init, ip)).then(|| init.clone())
        }
    }
}

/// A connection or datagram entering `t` from another namespace `from` (to an address of `t`,
/// guest sockaddr `dst`; virtual addresses are the same for everyone) passes `t`'s PREROUTING nat:
/// returns the new destination as seen in `t` when DNATed. The source address is the one `from`
/// chooses toward it, and the input interface is the interface in `t` facing that source.
pub(crate) fn prerouting_nat(
    from: &NetNs,
    t: &NetNs,
    proto: u8,
    sport: u16,
    dst: &[u8],
    ingress: Option<&crate::nft::Iif>,
) -> Result<NatResult, Errno> {
    if !t.nft.borrow().has_nat(crate::nft::HOOK_PRE_ROUTING) {
        return Ok(NatResult::Pass);
    }
    let Some((ip, true)) = nat_ip(dst) else {
        return Ok(NatResult::Pass);
    };
    let src = source(from, ip[..4].try_into().unwrap()).unwrap_or_default();
    let iif = ingress.cloned().unwrap_or_else(|| iif_facing(t, src));
    let packet = NatPacket {
        hook: crate::nft::HOOK_PRE_ROUTING,
        proto,
        src: src.to_vec(),
        sport,
        uid: 0,
        gid: 0,
        iif: Some(iif),
        ct_state: crate::nft::CT_NEW,
        original_dst: None,
        mark: 0,
    };
    hook_nat(t, &packet, dst)
}

// ---- Filter chains along the path ----

const HOOK_LOCAL_IN: u32 = 1;
const HOOK_FORWARD: u32 = 2;

/// One namespace a packet enters in turn in [`path_filter`]: the hook, the input interface and
/// the output interface (on FORWARD).
struct Step<'a> {
    ns: &'a Rc<NetNs>,
    hook: u32,
    iif: crate::nft::Iif,
    oif: Option<Vec<u8>>,
}

impl<'a> Step<'a> {
    fn input(ns: &'a Rc<NetNs>, iif: crate::nft::Iif) -> Self {
        Self {
            ns,
            hook: HOOK_LOCAL_IN,
            iif,
            oif: None,
        }
    }

    fn forward(ns: &'a Rc<NetNs>, iif: crate::nft::Iif, oif: Vec<u8>) -> Self {
        Self {
            ns,
            hook: HOOK_FORWARD,
            iif,
            oif: Some(oif),
        }
    }
}

/// Arguments of [`path_filter`]: what the packet looks like.
pub(crate) struct Flow<'a> {
    pub proto: u8,
    /// The virtual address the socket is bound to (the source; chosen by route when absent).
    pub vaddr: Option<[u8; 4]>,
    pub sport: u16,
    /// The destination as seen in `me` after OUTPUT nat.
    pub dst: &'a [u8],
    pub bridge: Option<&'a BridgeHop>,
    pub origs: &'a [(u64, Vec<u8>)],
    /// As seen on arrival in the destination's namespace (after PREROUTING nat).
    pub there: &'a [u8],
    pub uid: u32,
    pub gid: u32,
    /// UDP replying to a peer it has received from (conntrack ESTABLISHED).
    pub established: bool,
    /// The socket's `SO_MARK`: packets on OUTPUT and those coming back to their own namespace
    /// through lo carry it; it is cleared when entering another namespace through a veth.
    pub mark: u32,
}

/// The filter chains a connection or datagram sent by a socket in `me` passes
/// (docs/rounds/175-filter.md), IPv4 only:
///
/// 1. `me`'s OUTPUT.
/// 2. From a new namespace, through the initial namespace: going out to the host network (`t` is
///    None) takes its FORWARD, with a host interface as the output; going to it takes INPUT; going
///    to another namespace whose destination is not in `me`'s directly connected subnets (through
///    a gateway) takes FORWARD. A switched IPv4 flow with bridge filtering enabled takes the
///    bridge owner's hooks using the logical bridge as its interface.
/// 3. On arrival in the destination's namespace `t`: INPUT (for the initial namespace see above).
///
/// On entering a namespace, the filter chains on its PREROUTING (the raw table and the like) come
/// first. Returns the result and whether it was dropped or rejected on OUTPUT.
pub(crate) fn path_filter(
    w: &World,
    me: &Rc<NetNs>,
    t: Option<&Rc<NetNs>>,
    f: &Flow<'_>,
) -> (crate::nft::Outcome, bool) {
    use crate::nft::{HOOK_LOCAL_OUT, HOOK_PRE_ROUTING, Outcome};
    let ct_state = if f.established {
        crate::nft::CT_ESTABLISHED
    } else {
        crate::nft::CT_NEW
    };
    let (Some(ip), Some(final_ip)) = (ipv4_of(f.dst), ipv4_of(f.there)) else {
        return (Outcome::Accept, false);
    };
    let src = match f.vaddr {
        Some(v) => v,
        None if ip[0] == 127 => ip,
        None => source(me, ip).unwrap_or([0; 4]),
    };
    let packet = |hook: u32, iif: Option<crate::nft::Iif>, ns: &NetNs, mark: u32| NatPacket {
        hook,
        proto: f.proto,
        src: src.to_vec(),
        sport: f.sport,
        uid: f.uid,
        gid: f.gid,
        iif,
        ct_state,
        original_dst: f
            .origs
            .iter()
            .rfind(|(id, _)| *id == ns.id)
            .and_then(|(_, addr)| nat_ip(addr).map(|(ip, _)| ip)),
        mark,
    };
    let pass = |o: &Outcome| matches!(o, Outcome::Accept | Outcome::Dnat(..));
    // 1. OUTPUT
    let mut out_mark = f.mark;
    if me.nft.borrow().has_filter(HOOK_LOCAL_OUT) {
        let (o, m) = hook_filter(me, &packet(HOOK_LOCAL_OUT, None, me, out_mark), f.dst, None);
        out_mark = m;
        if !pass(&o) {
            return (o, true);
        }
    }
    let steps = filter_steps(w.init(), me, t, f.bridge, src, ip, final_ip);
    let step_count = steps.len();
    let init_dnated = f.bridge.is_none()
        && !Rc::ptr_eq(w.init(), me)
        && f.origs.iter().any(|(id, _)| *id == w.init().id);
    for (idx, Step { ns, hook, iif, oif }) in steps.into_iter().enumerate() {
        let (pre_dst, post_dst) = match f.bridge {
            Some(b) if Rc::ptr_eq(&b.ns, ns) => (f.dst, b.dst.as_slice()),
            Some(b) => (b.dst.as_slice(), f.there),
            None if step_count == 2 => match (init_dnated, idx) {
                (true, 0) => (f.dst, f.there),
                (true, _) => (f.there, f.there),
                (false, 0) => (f.dst, f.dst),
                (false, _) => (f.dst, f.there),
            },
            None => (f.dst, f.there),
        };
        let (pre, this) = {
            let nft = ns.nft.borrow();
            (nft.has_filter(HOOK_PRE_ROUTING), nft.has_filter(hook))
        };
        let mut mark = if Rc::ptr_eq(ns, me) { out_mark } else { 0 };
        // What a namespace sends to itself over loopback also passes PREROUTING, as on Linux.
        // Chains ordered before NF_IP_PRI_NAT_DST (-100) see the pre-DNAT destination; chains at
        // or after -100 see the post-DNAT destination.
        if pre {
            let dnated = pre_dst != post_dst && f.origs.iter().any(|(id, _)| *id == ns.id);
            let (o, m) = hook_filter_prerouting(
                ns,
                &packet(HOOK_PRE_ROUTING, Some(iif.clone()), ns, mark),
                pre_dst,
                post_dst,
                dnated,
            );
            mark = m;
            if !pass(&o) {
                return (o, false);
            }
        }
        if this {
            let (o, _) = hook_filter(ns, &packet(hook, Some(iif), ns, mark), post_dst, oif);
            if !pass(&o) {
                return (o, false);
            }
        }
    }
    (Outcome::Accept, false)
}

/// Namespaces visited after OUTPUT. A switched packet enters the bridge owner's hooks
/// only when bridge netfilter is enabled. A routed packet follows its gateway.
fn filter_steps<'a>(
    init: &'a Rc<NetNs>,
    me: &'a Rc<NetNs>,
    target: Option<&'a Rc<NetNs>>,
    bridge: Option<&'a BridgeHop>,
    src: [u8; 4],
    dst: [u8; 4],
    final_dst: [u8; 4],
) -> Vec<Step<'a>> {
    let mut steps = Vec::new();
    if let Some(bridge) = bridge {
        let bridge_dst = ipv4_of(&bridge.dst).unwrap();
        if bridge_dst != dst && (bridge_dst[0] == 127 || local_v4(&bridge.ns, bridge_dst)) {
            return vec![Step::input(&bridge.ns, bridge.iif.clone())];
        }
        let oif = if bridge_dst == dst {
            bridge.iif.name.clone()
        } else {
            iif_facing(&bridge.ns, bridge_dst).name
        };
        steps.push(Step::forward(&bridge.ns, bridge.iif.clone(), oif));
    } else {
        let new_ns = me.host_net.is_some();
        let Some(target) = target else {
            if new_ns {
                let oif = outer_iface(init).map(|(i, _)| i.name).unwrap_or_default();
                steps.push(Step::forward(init, iif_facing(init, src), oif));
            }
            return steps;
        };
        // A published port can DNAT back to the sender via the initial namespace.
        if Rc::ptr_eq(target, me) && !(new_ns && dst != final_dst && local_v4(init, dst)) {
            let lo = crate::nft::Iif {
                index: 1,
                name: b"lo".to_vec(),
                addr: vec![127, 0, 0, 1],
            };
            return vec![Step::input(me, lo)];
        }
        if new_ns && !Rc::ptr_eq(target, init) {
            let on_link = crate::netdev::route_v4(me, dst).is_some_and(|e| e.gateway.is_none())
                && !local_v4(init, dst);
            if !on_link {
                steps.push(Step::forward(
                    init,
                    iif_facing(init, src),
                    iif_facing(init, final_dst).name,
                ));
            }
        }
    }
    if let Some(target) = target {
        steps.push(Step::input(target, iif_facing(target, src)));
    }
    steps
}

/// Whether an interface in this namespace owns the IPv4 address.
fn local_v4(ns: &NetNs, ip: [u8; 4]) -> bool {
    crate::netdev::interfaces(ns)
        .iter()
        .any(|i| i.addrs.iter().any(|(_, a, _)| a[..] == ip[..]))
}

// ---- Forwarding from outside ----

/// Source address of packets from outside (TEST-NET-1).
const EXTERNAL: [u8; 4] = [192, 0, 2, 1];

/// The PREROUTING nat result for a connection from outside the host (another device, another app
/// on the phone) to `dst` listening in the initial namespace `init` (a guest sockaddr, with the
/// wildcard address replaced by one of the host's addresses): the source is taken to be 192.0.2.1
/// (TEST-NET-1), and the input interface is the host's first non-loopback interface with an IPv4
/// address. Returns the probe address and its DNAT destination.
pub(crate) fn external_nat(init: &NetNs, proto: u8, dst: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if !init.nft.borrow().has_nat(crate::nft::HOOK_PRE_ROUTING) {
        return None;
    }
    let outer = outer_iface(init);
    let mut dst = dst.to_vec();
    if ipv4_of(&dst) == Some([0; 4]) {
        dst = with_ipv4(&dst, outer.as_ref().map_or([127, 0, 0, 1], |(_, a)| *a));
    }
    let packet = NatPacket {
        hook: crate::nft::HOOK_PRE_ROUTING,
        proto,
        src: EXTERNAL.to_vec(),
        sport: 40000,
        uid: 0,
        gid: 0,
        iif: Some(outer.map(|(i, _)| i).unwrap_or_default()),
        ct_state: crate::nft::CT_NEW,
        original_dst: None,
        mark: 0,
    };
    let NatResult::Dnat(translated) = hook_nat(init, &packet, &dst).ok()? else {
        return None;
    };
    Some((dst, translated))
}

/// Forwarding from outside the host through the initial namespace `init` to the DNAT
/// destination `there` (a guest address in namespace `t`): passes `init`'s PREROUTING filter
/// chains (pre-DNAT chains seeing `original`, post-DNAT chains seeing `there`), `init`'s FORWARD
/// (or INPUT when staying in `init`), and the filter chains on `t`'s PREROUTING and INPUT; what is
/// dropped or rejected is not forwarded.
pub(crate) fn external_filter(
    init: &NetNs,
    t: Option<&NetNs>,
    proto: u8,
    original: &[u8],
    there: &[u8],
) -> bool {
    use crate::nft::{HOOK_PRE_ROUTING, Outcome};
    let Some(ip) = ipv4_of(there) else {
        return true;
    };
    let packet = |hook: u32, iif: crate::nft::Iif, ns: &NetNs, mark: u32| NatPacket {
        hook,
        proto,
        src: EXTERNAL.to_vec(),
        sport: 40000,
        uid: 0,
        gid: 0,
        iif: Some(iif),
        ct_state: crate::nft::CT_NEW,
        original_dst: if std::ptr::eq(ns, init) {
            nat_ip(original).map(|(ip, _)| ip)
        } else {
            None
        },
        mark,
    };
    let pass = |o: Outcome| matches!(o, Outcome::Accept | Outcome::Dnat(..));
    let outer = outer_iface(init).map(|(i, _)| i).unwrap_or_default();
    let mut init_mark = 0;
    if init.nft.borrow().has_filter(HOOK_PRE_ROUTING) {
        let (o, m) = hook_filter_prerouting(
            init,
            &packet(HOOK_PRE_ROUTING, outer.clone(), init, 0),
            original,
            there,
            original != there,
        );
        init_mark = m;
        if !pass(o) {
            return false;
        }
    }
    if let Some(t) = t.filter(|t| !std::ptr::eq(*t, init)) {
        if init.nft.borrow().has_filter(HOOK_FORWARD) {
            let oif = iif_facing(init, ip).name;
            let (o, _) = hook_filter(
                init,
                &packet(HOOK_FORWARD, outer, init, init_mark),
                there,
                Some(oif),
            );
            if !pass(o) {
                return false;
            }
        }
        let iif = iif_facing(t, EXTERNAL);
        let mut t_mark = 0;
        for hook in [HOOK_PRE_ROUTING, HOOK_LOCAL_IN] {
            if t.nft.borrow().has_filter(hook) {
                let (o, m) = hook_filter(t, &packet(hook, iif.clone(), t, t_mark), there, None);
                t_mark = m;
                if !pass(o) {
                    return false;
                }
            }
        }
    } else if init.nft.borrow().has_filter(HOOK_LOCAL_IN) {
        let (o, _) = hook_filter(
            init,
            &packet(HOOK_LOCAL_IN, outer, init, init_mark),
            there,
            None,
        );
        if !pass(o) {
            return false;
        }
    }
    true
}

// ---- Synthetic packets ----

/// The parts of a synthetic packet besides the socket ([`hook_nat`]).
struct NatPacket {
    hook: u32,
    proto: u8,
    src: Vec<u8>,
    sport: u16,
    uid: u32,
    gid: u32,
    iif: Option<crate::nft::Iif>,
    ct_state: u32,
    /// Pre-DNAT destination in this namespace, when translated.
    original_dst: Option<Vec<u8>>,
    /// The packet's initial mark ([`crate::nft::Packet::mark`]).
    mark: u32,
}

impl NatPacket {
    fn as_nft<'a>(
        &'a self,
        src: &'a [u8],
        dst: &'a [u8],
        original_dst: &'a [u8],
        dport: u16,
        addr_type: &'a dyn Fn(&[u8]) -> u32,
        oif: &'a dyn Fn() -> (u32, Vec<u8>),
    ) -> crate::nft::Packet<'a> {
        crate::nft::Packet {
            src,
            dst,
            original_dst,
            proto: self.proto,
            sport: self.sport,
            dport,
            uid: self.uid,
            gid: self.gid,
            addr_type,
            oif,
            hook: self.hook,
            iif: self.iif.clone(),
            ct_state: self.ct_state,
            mark: self.mark,
        }
    }
}

fn is_local(ns: &NetNs, a: &[u8]) -> bool {
    is_loopback(a)
        || crate::netdev::interfaces(ns)
            .iter()
            .any(|i| i.addrs.iter().any(|(_, x, _)| x == a))
}

fn packet_src(src: &[u8], dst_len: usize) -> Cow<'_, [u8]> {
    if src.len() == dst_len {
        Cow::Borrowed(src)
    } else {
        Cow::Owned(vec![0; dst_len])
    }
}

/// nat on hook `p.hook` of `ns` ([`crate::nft::Nft::nat`]): for a packet to guest address `dst`,
/// returns the new destination when DNATed (keeping the port when it is not changed), or the
/// drop/reject verdict when blocked.
fn hook_nat(ns: &NetNs, p: &NatPacket, dst: &[u8]) -> Result<NatResult, Errno> {
    let Some((_, v4)) = nat_ip(dst) else {
        return Ok(NatResult::Pass);
    };
    match hook_eval(ns, p, dst, None, false).0 {
        crate::nft::Outcome::Accept => Ok(NatResult::Pass),
        o @ (crate::nft::Outcome::Drop | crate::nft::Outcome::Reject(_)) => Ok(NatResult::Block(o)),
        crate::nft::Outcome::Dnat(a, port) => {
            let mut out = if v4 {
                with_ipv4(dst, a[..4].try_into().map_err(|_| Errno::EINVAL)?)
            } else {
                let mut o = dst.to_vec();
                o[8..24].copy_from_slice(&a);
                o
            };
            if let Some(port) = port {
                out[2..4].copy_from_slice(&port.to_be_bytes());
            }
            Ok(NatResult::Dnat(out))
        }
    }
}

/// Runs the filter chains on hook `p.hook` of `ns`, returning the verdict and resulting mark.
fn hook_filter(
    ns: &NetNs,
    p: &NatPacket,
    dst: &[u8],
    oif: Option<Vec<u8>>,
) -> (crate::nft::Outcome, u32) {
    hook_eval(ns, p, dst, oif, true)
}

/// Runs the PREROUTING filter chains of `ns`, giving chains ordered before `NF_IP_PRI_NAT_DST`
/// (`-100`) the pre-DNAT destination `pre_dst` (when `dnated`) and chains at or after `-100` the
/// post-DNAT destination `post_dst`.
fn hook_filter_prerouting(
    ns: &NetNs,
    p: &NatPacket,
    pre_dst: &[u8],
    post_dst: &[u8],
    dnated: bool,
) -> (crate::nft::Outcome, u32) {
    let Some((post_ip, _)) = nat_ip(post_dst) else {
        return (crate::nft::Outcome::Accept, p.mark);
    };
    let post_port = u16::from_be_bytes([post_dst[2], post_dst[3]]);
    let (pre_ip, pre_port) = nat_ip(pre_dst).map_or_else(
        || (post_ip.clone(), post_port),
        |(ip, _)| (ip, u16::from_be_bytes([pre_dst[2], pre_dst[3]])),
    );
    let pre_src = packet_src(&p.src, pre_ip.len());
    let post_src = packet_src(&p.src, post_ip.len());
    let addr_type = |a: &[u8]| crate::nft::addr_type(a, |x| is_local(ns, x));
    let no_oif = || (0, Vec::new());
    let pre_packet = p.as_nft(&pre_src, &pre_ip, &pre_ip, pre_port, &addr_type, &no_oif);
    let orig = p.original_dst.as_deref().unwrap_or(&pre_ip);
    let post_packet = p.as_nft(&post_src, &post_ip, orig, post_port, &addr_type, &no_oif);
    ns.nft
        .borrow()
        .filter_prerouting(&pre_packet, &post_packet, dnated)
}

/// Builds a packet to `dst` from `p` and runs the filter chains (`filter`) or the nat chains on
/// hook `p.hook` of `ns`. `oif` is the name of a given output interface (on FORWARD); with None,
/// it is chosen by route.
fn hook_eval(
    ns: &NetNs,
    p: &NatPacket,
    dst: &[u8],
    oif: Option<Vec<u8>>,
    filter: bool,
) -> (crate::nft::Outcome, u32) {
    let Some((ip, v4)) = nat_ip(dst) else {
        return (crate::nft::Outcome::Accept, p.mark);
    };
    let src = packet_src(&p.src, ip.len());
    let addr_type = |a: &[u8]| crate::nft::addr_type(a, |x| is_local(ns, x));
    // Index and name of the output interface: by name when one is given (on FORWARD), lo for
    // local addresses, otherwise by route
    let oif = || -> (u32, Vec<u8>) {
        let found = |f: &dyn Fn(&appine_hal::net::Interface) -> bool| {
            crate::netdev::interfaces(ns)
                .into_iter()
                .find(|i| f(i))
                .map(|i| (i.index, i.name.into_bytes()))
        };
        if let Some(o) = &oif {
            return found(&|i| i.name.as_bytes() == &o[..]).unwrap_or((0, o.clone()));
        }
        if is_local(ns, &ip) {
            return found(&|i| i.name == "lo").unwrap_or((1, b"lo".to_vec()));
        }
        let index = v4
            .then(|| crate::netdev::route_v4(ns, ip[..4].try_into().unwrap()))
            .flatten()
            .map(|e| e.index);
        found(&|i| Some(i.index) == index).unwrap_or_default()
    };
    let packet = p.as_nft(
        &src,
        &ip,
        p.original_dst.as_deref().unwrap_or(&ip),
        u16::from_be_bytes([dst[2], dst[3]]),
        &addr_type,
        &oif,
    );
    let nft = ns.nft.borrow();
    if filter {
        nft.filter_with_mark(&packet)
    } else {
        (nft.nat(&packet), p.mark)
    }
}

/// Which kind of packet a sockaddr is judged as: (address, is IPv4). IPv4-mapped IPv6 addresses
/// count as IPv4 packets.
fn nat_ip(dst: &[u8]) -> Option<(Vec<u8>, bool)> {
    match (family(dst), ipv4_of(dst)) {
        (Some(AF_INET | AF_INET6), Some(x)) => Some((x.to_vec(), true)),
        (Some(AF_INET6), None) if dst.len() >= 24 => Some((dst[8..24].to_vec(), false)),
        _ => None,
    }
}

fn is_loopback(a: &[u8]) -> bool {
    (a.len() == 4 && a[0] == 127) || a == std::net::Ipv6Addr::LOCALHOST.octets()
}

/// The interface in `t` facing IPv4 address `src` (the one packets from `src` come in on): the
/// one with the directly connected subnet, otherwise the default route's output interface.
fn iif_facing(t: &NetNs, src: [u8; 4]) -> crate::nft::Iif {
    let Some(e) = crate::netdev::route_v4(t, src) else {
        return Default::default();
    };
    let name = crate::netdev::interfaces(t)
        .into_iter()
        .find(|i| i.index == e.index)
        .map(|i| i.name.into_bytes())
        .unwrap_or_default();
    crate::nft::Iif {
        index: e.index,
        name,
        addr: crate::netdev::first_v4(t, e.index)
            .map(|a| a.to_vec())
            .unwrap_or_default(),
    }
}

/// The host's first non-loopback interface with an IPv4 address: the input interface of packets
/// from outside and the output interface of packets going outside.
fn outer_iface(init: &NetNs) -> Option<(crate::nft::Iif, [u8; 4])> {
    crate::netdev::interfaces(init).into_iter().find_map(|i| {
        let a = i
            .addrs
            .iter()
            .find(|(f, a, _)| *f == AF_INET && a.len() == 4 && a[0] != 127)?;
        let addr: [u8; 4] = a.1[..].try_into().ok()?;
        Some((
            crate::nft::Iif {
                index: i.index,
                name: i.name.clone().into_bytes(),
                addr: addr.to_vec(),
            },
            addr,
        ))
    })
}

// ---- Address helpers ----

/// The namespace a host address belongs to (the low-port mapping registry goes by it,
/// [`crate::portmap`]): another namespace's block gives that namespace, 127.255.x.y the initial
/// one; anything else None (the socket's own namespace is used).
pub(crate) fn owner_of_host(w: &World, addr: &[u8]) -> Option<Rc<NetNs>> {
    let x = ipv4_of(addr).filter(|x| x[0] == 127)?;
    if x[1] == INIT_BLOCK {
        return Some(w.init().clone());
    }
    w.by_block(x[1], x[2]).cloned()
}

/// Whether it is an IPv4 or IPv6 address.
pub(crate) fn is_inet(addr: &[u8]) -> bool {
    matches!(family(addr), Some(AF_INET | AF_INET6))
}

/// Whether the guest bound a wildcard address (0.0.0.0, ::, ::ffff:0.0.0.0).
pub(crate) fn is_any(addr: &[u8]) -> bool {
    match family(addr) {
        Some(AF_INET) => addr.get(4..8) == Some(&[0; 4]),
        Some(AF_INET6) => addr
            .get(8..24)
            .is_some_and(|ip| ip == [0; 16] || mapped(ip) == Some([0; 4])),
        _ => false,
    }
}

/// The source address when `me` sends to `ip` (`inet_select_addr`): the route's preferred
/// source, otherwise an address on the outgoing interface, otherwise `me`'s first virtual
/// address.
fn source(me: &NetNs, ip: [u8; 4]) -> Option<[u8; 4]> {
    let r = crate::netdev::route_v4(me, ip);
    r.as_ref()
        .and_then(|r| r.prefsrc.as_deref())
        .and_then(|p| p.try_into().ok())
        .or_else(|| r.and_then(|r| crate::netdev::first_v4(me, r.index)))
        .or_else(|| crate::netdev::local_v4(me).first().map(|(a, _)| *a))
}

/// The directly connected subnets in `me` (routes on virtual devices with no gateway, not /32).
fn connected(me: &NetNs) -> Vec<([u8; 4], u8)> {
    crate::netdev::entries(me)
        .into_iter()
        .filter(|e| e.family == AF_INET && e.table == 254 && e.gateway.is_none() && e.prefix < 32)
        .filter_map(|e| Some((<[u8; 4]>::try_from(&e.dst[..]).ok()?, e.prefix)))
        .collect()
}

fn covers(net: [u8; 4], prefix: u8, ip: [u8; 4]) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from_be_bytes(net) & mask == u32::from_be_bytes(ip) & mask
}

/// The IPv4 address in a sockaddr (for an IPv4-mapped IPv6 address, the IPv4 part).
fn ipv4_of(addr: &[u8]) -> Option<[u8; 4]> {
    match family(addr) {
        Some(AF_INET) if addr.len() >= 8 => addr[4..8].try_into().ok(),
        Some(AF_INET6) if addr.len() >= 24 => mapped(&addr[8..24]),
        _ => None,
    }
}

/// Replaces the IPv4 address in a sockaddr with `ip` (written IPv4-mapped for AF_INET6, with the
/// scope id cleared).
fn with_ipv4(addr: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let mut out = addr.to_vec();
    if family(addr) == Some(AF_INET) {
        out[4..8].copy_from_slice(&ip);
    } else {
        out[8..18].fill(0);
        out[18..20].copy_from_slice(&[0xff, 0xff]);
        out[20..24].copy_from_slice(&ip);
        if let Some(s) = out.get_mut(24..28) {
            s.fill(0);
        }
    }
    out
}

fn family(addr: &[u8]) -> Option<i32> {
    addr.get(..2)
        .map(|b| i32::from(u16::from_le_bytes([b[0], b[1]])))
}

fn mapped(ip: &[u8]) -> Option<[u8; 4]> {
    (ip[..10] == [0; 10] && ip[10..12] == [0xff, 0xff]).then(|| ip[12..16].try_into().unwrap())
}

// ---- lo configuration ----

/// A netlink request that modifies lo (the whole message): `RTM_NEWADDR`, `RTM_DELADDR`,
/// `RTM_NEWLINK` (`RTM_SETLINK`). None means it is none of these; Some holds the error code (0 is
/// success). Needs `CAP_NET_ADMIN` in the namespace's owner (EPERM; Linux's
/// `netlink_net_capable`).
pub(crate) fn configure(ns: &NetNs, cred: &Cred, req: &[u8]) -> Option<i32> {
    const RTM_NEWLINK: u16 = 16;
    const RTM_SETLINK: u16 = 19;
    const RTM_NEWADDR: u16 = 20;
    const RTM_DELADDR: u16 = 21;
    const NLM_F_EXCL: u16 = 0x200;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;
    let ty = u16::from_le_bytes([req[4], req[5]]);
    if !matches!(ty, RTM_NEWLINK | RTM_SETLINK | RTM_NEWADDR | RTM_DELADDR) {
        return None;
    }
    if !cred.ns_capable(&ns.owner, cap::NET_ADMIN) {
        return Some(Errno::EPERM.0);
    }
    let body = &req[16..];
    let mut lo = ns.lo.borrow_mut();
    Some(match ty {
        // struct ifinfomsg: address family, type, index, flags, flags to change
        RTM_NEWLINK | RTM_SETLINK => {
            let Some(b) = body.get(..16) else {
                return Some(Errno::EINVAL.0);
            };
            let index = i32::from_le_bytes(b[4..8].try_into().unwrap());
            let flags = u32::from_le_bytes(b[8..12].try_into().unwrap());
            let change = u32::from_le_bytes(b[12..16].try_into().unwrap());
            if index != LO_INDEX as i32 {
                return Some(Errno::ENODEV.0);
            }
            if change & IFF_UP != 0 || change == 0 {
                set_up(&mut lo, flags & IFF_UP != 0);
            }
            0
        }
        // struct ifaddrmsg: address family, prefix length, flags, scope, index, followed by
        // IFA_LOCAL, IFA_ADDRESS
        _ => {
            let Some(b) = body.get(..8) else {
                return Some(Errno::EINVAL.0);
            };
            let (family, prefix) = (i32::from(b[0]), b[1]);
            let index = u32::from_le_bytes(b[4..8].try_into().unwrap());
            if index != LO_INDEX {
                return Some(Errno::ENODEV.0);
            }
            let attrs = crate::route::attrs(&body[8..]);
            let addr = attrs
                .iter()
                .find(|(t, _)| *t == IFA_LOCAL)
                .or_else(|| attrs.iter().find(|(t, _)| *t == IFA_ADDRESS))
                .map(|(_, d)| d.to_vec());
            let excl = u16::from_le_bytes([req[6], req[7]]) & NLM_F_EXCL != 0;
            match (family, addr) {
                (AF_INET, Some(a)) if a.len() == 4 && prefix <= 32 => {
                    let a: [u8; 4] = a.try_into().unwrap();
                    let at = lo.v4.iter().position(|(x, _)| *x == a);
                    match (ty, at) {
                        (RTM_NEWADDR, Some(_)) if excl => Errno::EEXIST.0,
                        (RTM_NEWADDR, Some(i)) => {
                            lo.v4[i].1 = prefix;
                            0
                        }
                        (RTM_NEWADDR, None) => {
                            lo.v4.push((a, prefix));
                            0
                        }
                        (_, Some(i)) => {
                            lo.v4.remove(i);
                            0
                        }
                        (_, None) => Errno::EADDRNOTAVAIL.0,
                    }
                }
                (AF_INET6, Some(a)) if a == LOOPBACK6 => match (ty, lo.v6) {
                    (RTM_NEWADDR, true) if excl => Errno::EEXIST.0,
                    (RTM_NEWADDR, _) => {
                        lo.v6 = true;
                        0
                    }
                    (_, true) => {
                        lo.v6 = false;
                        0
                    }
                    (_, false) => Errno::EADDRNOTAVAIL.0,
                },
                // Other IPv6 addresses cannot reach the host, so they cannot be configured
                (AF_INET6, Some(_)) => Errno::EOPNOTSUPP.0,
                (AF_INET | AF_INET6, _) => Errno::EINVAL.0,
                _ => Errno::EAFNOSUPPORT.0,
            }
        }
    })
}

/// Interface ioctls (`struct ifreq`, 40 bytes, the first 16 the name): a new namespace has only
/// lo. None means it is not handled here.
pub(crate) fn interface_ioctl(
    ns: &NetNs,
    cred: &Cred,
    request: u32,
    ifr: &mut [u8; 40],
) -> Option<Result<(), Errno>> {
    const SIOCGIFNAME: u32 = 0x8910;
    const SIOCGIFFLAGS: u32 = 0x8913;
    const SIOCSIFFLAGS: u32 = 0x8914;
    const SIOCGIFADDR: u32 = 0x8915;
    const SIOCGIFNETMASK: u32 = 0x891b;
    const SIOCGIFMTU: u32 = 0x8921;
    const SIOCSIFMTU: u32 = 0x8922;
    const SIOCGIFHWADDR: u32 = 0x8927;
    const SIOCGIFINDEX: u32 = 0x8933;
    const SIOCGIFTXQLEN: u32 = 0x8942;
    const ARPHRD_LOOPBACK: u16 = 772;
    let name = ifr[..16].split(|&c| c == 0).next().unwrap_or_default();
    if request == SIOCGIFNAME {
        let index = i32::from_le_bytes(ifr[16..20].try_into().unwrap());
        if index != LO_INDEX as i32 {
            return Some(Err(Errno::ENODEV));
        }
        ifr[..16].fill(0);
        ifr[..2].copy_from_slice(b"lo");
        return Some(Ok(()));
    }
    let known = [
        SIOCGIFFLAGS,
        SIOCSIFFLAGS,
        SIOCSIFMTU,
        SIOCGIFADDR,
        SIOCGIFNETMASK,
        SIOCGIFMTU,
        SIOCGIFHWADDR,
        SIOCGIFINDEX,
        SIOCGIFTXQLEN,
    ];
    if !known.contains(&request) {
        return None;
    }
    if name != b"lo" {
        return Some(Err(Errno::ENODEV));
    }
    let lo_if = lo_interface(ns);
    let data = &mut ifr[16..];
    if matches!(request, SIOCSIFFLAGS | SIOCSIFMTU) {
        if !cred.ns_capable(&ns.owner, cap::NET_ADMIN) {
            return Some(Err(Errno::EPERM));
        }
        let mut lo = ns.lo.borrow_mut();
        if request == SIOCSIFFLAGS {
            let flags = u16::from_le_bytes([data[0], data[1]]);
            set_up(&mut lo, u32::from(flags) & IFF_UP != 0);
        } else {
            // As with Linux's dev_set_mtu, not below the IPv4 minimum of 68 (loopback has no
            // upper bound)
            let mtu = i32::from_le_bytes(data[..4].try_into().unwrap());
            if mtu < 68 {
                return Some(Err(Errno::EINVAL));
            }
            lo.mtu = Some(mtu as u32);
        }
        return Some(Ok(()));
    }
    data.fill(0);
    let sockaddr = |data: &mut [u8], a: [u8; 4]| {
        data[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        data[4..8].copy_from_slice(&a);
    };
    match request {
        SIOCGIFFLAGS => data[..2].copy_from_slice(&(lo_if.flags as u16).to_le_bytes()),
        SIOCGIFADDR | SIOCGIFNETMASK => {
            let Some(&(a, len)) = ns.lo.borrow().v4.first() else {
                return Some(Err(Errno::EADDRNOTAVAIL));
            };
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            let value = if request == SIOCGIFADDR {
                a
            } else {
                mask.to_be_bytes()
            };
            sockaddr(data, value);
        }
        SIOCGIFMTU => data[..4].copy_from_slice(&(lo_if.mtu as i32).to_le_bytes()),
        SIOCGIFHWADDR => data[..2].copy_from_slice(&ARPHRD_LOOPBACK.to_le_bytes()),
        SIOCGIFINDEX => data[..4].copy_from_slice(&(LO_INDEX as i32).to_le_bytes()),
        _ => data[..4].copy_from_slice(&1000i32.to_le_bytes()),
    }
    Some(Ok(()))
}

/// The lo interface (for netlink and procfs answers).
pub(crate) fn lo_interface(ns: &NetNs) -> Interface {
    let lo = ns.lo.borrow();
    let mut addrs: Vec<(i32, Vec<u8>, u8)> = lo
        .v4
        .iter()
        .map(|(a, len)| (AF_INET, a.to_vec(), *len))
        .collect();
    if lo.v6 {
        addrs.push((AF_INET6, LOOPBACK6.to_vec(), 128));
    }
    Interface {
        name: "lo".into(),
        index: LO_INDEX,
        flags: if lo.up {
            IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP
        } else {
            IFF_LOOPBACK
        },
        mtu: lo.mtu.unwrap_or(65536),
        mac: None,
        addrs,
    }
}

/// Brings lo up or down (`RTM_NEWLINK`, `SIOCSIFFLAGS`): bringing it up adds 127.0.0.1/8 when
/// it has no IPv4 address (Linux's `inetdev_event`), and adds ::1 (addrconf); bringing it down
/// removes ::1 with it.
pub(crate) fn set_up(lo: &mut Loopback, up: bool) {
    if up && !lo.up {
        if lo.v4.is_empty() {
            lo.v4.push(([127, 0, 0, 1], 8));
        }
        lo.v6 = true;
    } else if !up {
        lo.v6 = false;
    }
    lo.up = up;
}

/// `SIOCGIFCONF`: lo while it is up with an IPv4 address (Linux's `inet_gifconf` lists only IPv4
/// addresses).
pub(crate) fn ifconf(ns: &NetNs) -> Vec<u8> {
    let lo = ns.lo.borrow();
    let mut out = Vec::new();
    for (a, _) in lo.v4.iter().filter(|_| lo.up) {
        let mut r = [0u8; 40];
        r[..2].copy_from_slice(b"lo");
        r[16..18].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        r[20..24].copy_from_slice(a);
        out.extend_from_slice(&r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::RefCell;

    fn ns() -> NetNs {
        NetNs {
            id: 1,
            owner: crate::cred::UserNs::init(),
            host_net: Some([1, 2]),
            lo: Default::default(),
            devs: Default::default(),
            nft: Default::default(),
            listeners: Default::default(),
        }
    }

    fn v4(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut s = vec![0u8; 16];
        s[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
        s[2..4].copy_from_slice(&port.to_be_bytes());
        s[4..8].copy_from_slice(&ip);
        s
    }

    fn v6(ip: [u8; 16], port: u16) -> Vec<u8> {
        let mut s = vec![0u8; 28];
        s[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
        s[2..4].copy_from_slice(&port.to_be_bytes());
        s[8..24].copy_from_slice(&ip);
        s
    }

    fn up(ns: &NetNs) {
        set_up(&mut ns.lo.borrow_mut(), true);
    }

    /// Connections forwarded in from outside (127.254.x.y, crate::forward): the peer is reported
    /// as the client's real address and port; unchanged when the host port does not match.
    #[test]
    fn outside_peers_show_the_real_client() {
        let n = Rc::new(ns());
        let w = World {
            all: vec![crate::nsproxy::NsProxy::init().net, n.clone()],
        };
        crate::forward::record_outside_for_test(
            [127, 254, 200, 7],
            [192, 168, 1, 50],
            51000,
            51000,
        );
        let got = from_host(&w, &n, &v4([127, 254, 200, 7], 51000), Role::Peer, false);
        assert_eq!(got, v4([192, 168, 1, 50], 51000));
        let other = from_host(&w, &n, &v4([127, 254, 200, 7], 51001), Role::Peer, false);
        assert_ne!(other[4..8], [192, 168, 1, 50]);
    }

    fn bind_listener(
        ns: &NetNs,
        proto: i32,
        port: u16,
        addr: BindAddr,
        v6only: bool,
        host_ip: [u8; 4],
        host_port: u16,
    ) -> std::num::NonZeroU64 {
        add_binding(
            ns,
            port,
            NewBinding {
                proto,
                addr,
                v6only,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
                listening: true,
                accepted: false,
                host_ip,
                host_port,
                wide: false,
            },
        )
    }

    /// Listener resolution: wildcard addresses go by address family and `IPV6_V6ONLY`; exact
    /// guest addresses take priority over wildcards and return their own distinct host endpoints
    /// (`127.0.0.1:P` vs `<vaddr>:P` vs `[::1]:P` vs `0.0.0.0:P`).
    #[test]
    fn listeners_match_like_linux() {
        let n = ns();
        let tcp = crate::net::IPPROTO_TCP;
        let udp = crate::net::IPPROTO_UDP;
        let eth0 = [10, 9, 0, 2];
        let eth1 = [10, 9, 1, 2];
        let bind = |proto, port, addr, v6only, host_ip, host_port| {
            bind_listener(&n, proto, port, addr, v6only, host_ip, host_port)
        };
        let a = bind(tcp, 7000, BindAddr::AnyV4, false, [127, 1, 2, 1], 41000);
        bind(tcp, 7001, BindAddr::AnyV6, true, [127, 1, 2, 1], 41001);
        bind(
            tcp,
            7002,
            BindAddr::V4([127, 0, 0, 1]),
            false,
            [127, 1, 2, 1],
            41002,
        );
        bind(tcp, 7003, BindAddr::V4(eth0), false, [127, 1, 2, 1], 41003);
        bind(
            tcp,
            7004,
            BindAddr::V6(LOOPBACK6),
            false,
            [127, 1, 2, 1],
            41004,
        );
        // 0.0.0.0: any IPv4 works, pure IPv6 does not
        assert_eq!(
            resolve_target(&n, tcp, &v4(eth0, 7000)),
            Some(([127, 1, 2, 1], 41000))
        );
        assert!(listening(&n, &v4([127, 0, 0, 1], 7000), false));
        assert!(!listening(&n, &v6(LOOPBACK6, 7000), false));
        // [::] with IPV6_V6ONLY: only IPv6
        assert_eq!(
            resolve_target(&n, tcp, &v6(LOOPBACK6, 7001)),
            Some(([127, 1, 2, 1], 41001))
        );
        assert!(!listening(&n, &v4(eth0, 7001), false));
        // 127.0.0.1, eth0's address and ::1 accept only what is sent to them
        assert!(listening(&n, &v4([127, 0, 0, 1], 7002), false));
        assert!(!listening(&n, &v4(eth0, 7002), false));
        assert!(listening(&n, &v4(eth0, 7003), false));
        assert!(!listening(&n, &v4([127, 0, 0, 1], 7003), false));
        assert!(listening(&n, &v6(LOOPBACK6, 7004), false));
        assert!(!listening(&n, &v4([127, 0, 0, 1], 7004), false));
        // Same port on 127.0.0.1, eth0, eth1 and ::1 each resolve to their own distinct host port
        bind(
            tcp,
            8080,
            BindAddr::V4([127, 0, 0, 1]),
            false,
            [127, 1, 2, 1],
            42001,
        );
        bind(tcp, 8080, BindAddr::V4(eth0), false, [127, 1, 2, 1], 42002);
        bind(tcp, 8080, BindAddr::V4(eth1), false, [127, 1, 2, 1], 42003);
        bind(
            tcp,
            8080,
            BindAddr::V6(LOOPBACK6),
            false,
            [127, 1, 2, 1],
            42004,
        );
        assert_eq!(
            resolve_target(&n, tcp, &v4([127, 0, 0, 1], 8080)),
            Some(([127, 1, 2, 1], 42001))
        );
        assert_eq!(
            resolve_target(&n, tcp, &v4(eth0, 8080)),
            Some(([127, 1, 2, 1], 42002))
        );
        assert_eq!(
            resolve_target(&n, tcp, &v4(eth1, 8080)),
            Some(([127, 1, 2, 1], 42003))
        );
        assert_eq!(
            resolve_target(&n, tcp, &v6(LOOPBACK6, 8080)),
            Some(([127, 1, 2, 1], 42004))
        );
        // 0.0.0.0:P + [::]:P (v6only) coexist on separate host ports; IPv4 hits 0.0.0.0, IPv6 hits [::]
        bind(tcp, 80, BindAddr::AnyV4, false, [127, 1, 2, 1], 43001);
        bind(tcp, 80, BindAddr::AnyV6, true, [127, 1, 2, 1], 43002);
        assert_eq!(
            resolve_target(&n, tcp, &v4(eth0, 80)),
            Some(([127, 1, 2, 1], 43001))
        );
        assert_eq!(
            resolve_target(&n, tcp, &v6(LOOPBACK6, 80)),
            Some(([127, 1, 2, 1], 43002))
        );
        // Exact match takes precedence over wildcard (e.g. UDP SO_REUSEADDR 0.0.0.0 + eth0)
        bind(udp, 5353, BindAddr::AnyV4, false, [127, 1, 2, 1], 44001);
        bind(udp, 5353, BindAddr::V4(eth0), false, [127, 1, 2, 1], 44002);
        assert_eq!(
            resolve_target(&n, udp, &v4(eth0, 5353)),
            Some(([127, 1, 2, 1], 44002))
        );
        assert_eq!(
            resolve_target(&n, udp, &v4([127, 0, 0, 1], 5353)),
            Some(([127, 1, 2, 1], 44001))
        );
        // UDP and TCP are registered separately
        assert!(listening(&n, &v4(eth0, 5353), true));
        assert!(!listening(&n, &v4(eth0, 5353), false));
        assert!(!listening(&n, &v4(eth0, 7000), true));
        // A port nobody listens on; and none after removal either
        assert!(!listening(&n, &v4(eth0, 7999), false));
        remove_binding(&n, a);
        assert!(!listening(&n, &v4(eth0, 7000), false));
    }

    /// Linux 6.1 guest-address bind and listen conflict rules (`inet_csk_bind_conflict` and
    /// `udp_lib_lport_inuse`) in a new network namespace.
    #[test]
    fn bind_and_listen_conflicts_match_linux() {
        let tcp = crate::net::IPPROTO_TCP;
        let udp = crate::net::IPPROTO_UDP;
        let vaddr = [10, 50, 0, 2];

        // Overlap matrix
        assert!(addrs_overlap(
            BindAddr::AnyV4,
            false,
            BindAddr::V4([127, 0, 0, 2]),
            false
        ));
        assert!(addrs_overlap(
            BindAddr::AnyV4,
            false,
            BindAddr::AnyV6,
            false
        ));
        assert!(!addrs_overlap(
            BindAddr::AnyV4,
            false,
            BindAddr::AnyV6,
            true
        ));
        assert!(addrs_overlap(BindAddr::AnyV6, true, BindAddr::AnyV6, false));
        assert!(addrs_overlap(
            BindAddr::AnyV6,
            true,
            BindAddr::V6(LOOPBACK6),
            false
        ));
        assert!(!addrs_overlap(
            BindAddr::AnyV6,
            true,
            BindAddr::V4(vaddr),
            false
        ));
        assert!(addrs_overlap(
            BindAddr::AnyV6,
            false,
            BindAddr::V4(vaddr),
            false
        ));
        assert!(!addrs_overlap(
            BindAddr::V4([127, 0, 0, 1]),
            false,
            BindAddr::V4(vaddr),
            false
        ));
        assert!(!addrs_overlap(
            BindAddr::V4([127, 0, 0, 1]),
            false,
            BindAddr::V6(LOOPBACK6),
            false
        ));

        let n = ns();
        let req = |proto, port, addr, v6only, reuseaddr, reuseport, euid| BindReq {
            proto,
            guest_port: port,
            addr,
            v6only,
            reuseaddr,
            reuseport,
            euid,
            bound_dev_if: 0,
        };
        let insert = |r: BindReq, listening, host_ip, host_port| {
            add_binding(
                &n,
                r.guest_port,
                NewBinding {
                    proto: r.proto,
                    addr: r.addr,
                    v6only: r.v6only,
                    reuseaddr: r.reuseaddr,
                    reuseport: r.reuseport,
                    euid: r.euid,
                    bound_dev_if: r.bound_dev_if,
                    listening,
                    accepted: false,
                    host_ip,
                    host_port,
                    wide: false,
                },
            )
        };

        // 1. 0.0.0.0:9000 + 127.0.0.2:9000 conflicts without reuse, and even with SO_REUSEADDR
        //    once listening; allowed with SO_REUSEPORT for the same euid, refused for another euid.
        let r_any = req(tcp, 9000, BindAddr::AnyV4, false, true, false, 0);
        let id_any = insert(r_any, false, [127, 1, 2, 1], 45000);
        // Without SO_REUSEADDR on the second socket -> conflict
        assert!(bind_conflict(
            &n,
            &req(
                tcp,
                9000,
                BindAddr::V4([127, 0, 0, 2]),
                false,
                false,
                false,
                0
            ),
            None
        ));
        // With SO_REUSEADDR on both while first is NOT listening -> allowed at bind
        let r_lo2 = req(
            tcp,
            9000,
            BindAddr::V4([127, 0, 0, 2]),
            false,
            true,
            false,
            0,
        );
        assert!(!bind_conflict(&n, &r_lo2, None));
        let id_lo2 = insert(r_lo2, false, [127, 1, 2, 2], 45001);
        // First enters listen -> allowed (second is not listening)
        assert!(!listen_conflict(&n, id_any));
        set_listening(&n, id_any, true);
        // Second enters listen -> conflict (first is now TCP_LISTEN)
        assert!(listen_conflict(&n, id_lo2));
        // Third socket with SO_REUSEADDR binding 127.0.0.2:9000 -> conflict (first is TCP_LISTEN)
        assert!(bind_conflict(&n, &r_lo2, None));
        remove_binding(&n, id_any);
        remove_binding(&n, id_lo2);

        // 2. IPv6-only [::]:9001 + dual-stack [::]:9001 conflicts (both directions), while
        //    0.0.0.0:9001 + IPv6-only [::]:9001 succeeds.
        let r_v6only = req(tcp, 9001, BindAddr::AnyV6, true, false, false, 0);
        let id_v6only = insert(r_v6only, true, [127, 1, 2, 1], 45010);
        assert!(bind_conflict(
            &n,
            &req(tcp, 9001, BindAddr::AnyV6, false, false, false, 0),
            None
        ));
        assert!(!bind_conflict(
            &n,
            &req(tcp, 9001, BindAddr::AnyV4, false, false, false, 0),
            None
        ));
        remove_binding(&n, id_v6only);

        // 3. 127.0.0.1:9002 + <vaddr>:9002 succeeds with no reuse options and never shares a port.
        let r_lo1 = req(
            tcp,
            9002,
            BindAddr::V4([127, 0, 0, 1]),
            false,
            false,
            false,
            0,
        );
        let id_lo1 = insert(r_lo1, true, [127, 1, 2, 1], 45020);
        let r_v = req(tcp, 9002, BindAddr::V4(vaddr), false, false, false, 0);
        assert!(!bind_conflict(&n, &r_v, None));
        assert_eq!(shared_host_port(&n, &r_v, [127, 1, 2, 1]), None);
        remove_binding(&n, id_lo1);

        // 4. SO_REUSEPORT: same euid allowed and shares host port only for exact same bind target;
        //    different euid conflicts.
        let r_rp1 = req(tcp, 9003, BindAddr::V4(vaddr), false, false, true, 1000);
        let id_rp1 = insert(r_rp1, true, [127, 1, 2, 1], 45030);
        assert!(!bind_conflict(&n, &r_rp1, None));
        assert_eq!(shared_host_port(&n, &r_rp1, [127, 1, 2, 1]), Some(45030));
        // Different euid -> conflict
        assert!(bind_conflict(
            &n,
            &req(tcp, 9003, BindAddr::V4(vaddr), false, false, true, 1001),
            None
        ));
        // Overlapping 0.0.0.0 with SO_REUSEPORT & same euid -> allowed, distinct host port
        let r_rp_any = req(tcp, 9003, BindAddr::AnyV4, false, false, true, 1000);
        assert!(!bind_conflict(&n, &r_rp_any, None));
        assert_eq!(shared_host_port(&n, &r_rp_any, [127, 1, 2, 1]), None);
        remove_binding(&n, id_rp1);

        // 5. UDP: SO_REUSEADDR allows overlapping binds even while bound; without it, conflicts.
        let u_any = req(udp, 9004, BindAddr::AnyV4, false, true, false, 0);
        let id_u = insert(u_any, true, [127, 1, 2, 1], 45040);
        assert!(bind_conflict(
            &n,
            &req(
                udp,
                9004,
                BindAddr::V4([127, 0, 0, 2]),
                false,
                false,
                false,
                0
            ),
            None
        ));
        assert!(!bind_conflict(
            &n,
            &req(
                udp,
                9004,
                BindAddr::V4([127, 0, 0, 2]),
                false,
                true,
                false,
                0
            ),
            None
        ));
        // Turning SO_REUSEADDR off dynamically causes later binds to conflict
        set_reuse(&n, id_u, false, false);
        assert!(bind_conflict(
            &n,
            &req(
                udp,
                9004,
                BindAddr::V4([127, 0, 0, 2]),
                false,
                true,
                false,
                0
            ),
            None
        ));
        remove_binding(&n, id_u);
    }

    /// Ephemeral binds avoid aliasing explicit guest ports, block conflicting explicit binds until
    /// released, and reverse lookups preserve both guest port and bound virtual address across
    /// the 10 s linger window.
    #[test]
    fn ephemeral_non_aliasing_and_reverse_lookup_linger() {
        let n = Rc::new(ns());
        let tcp = crate::net::IPPROTO_TCP;
        let udp = crate::net::IPPROTO_UDP;
        let vaddr = [10, 50, 0, 2];

        let exp = add_binding(
            &n,
            40000,
            NewBinding {
                proto: tcp,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
                listening: true,
                accepted: false,
                host_ip: [127, 1, 2, 1],
                host_port: 51000,
                wide: false,
            },
        );
        let (g_eph, eph) = add_ephemeral(
            &n,
            NewBinding {
                proto: tcp,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
                listening: false,
                accepted: false,
                host_ip: [127, 1, 2, 1],
                host_port: 40000,
                wide: false,
            },
            (40000, 40010),
        );
        assert_ne!(g_eph, 40000);
        assert!((40000..=40010).contains(&g_eph));
        assert_eq!(
            lookup_host(&n, tcp, [127, 1, 2, 1], 40000),
            Some((g_eph, BindAddr::V4([127, 0, 0, 1])))
        );
        assert!(bind_conflict(
            &n,
            &BindReq {
                proto: tcp,
                guest_port: g_eph,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
            },
            None
        ));
        remove_binding(&n, eph);
        assert!(!bind_conflict(
            &n,
            &BindReq {
                proto: tcp,
                guest_port: g_eph,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
            },
            None
        ));
        remove_binding(&n, exp);

        // UDP reverse lookup distinguishes 127.0.0.1 vs <vaddr> even after socket close (LINGER)
        let u_lo = add_binding(
            &n,
            8080,
            NewBinding {
                proto: udp,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
                listening: true,
                accepted: false,
                host_ip: [127, 1, 2, 1],
                host_port: 52001,
                wide: false,
            },
        );
        let u_va = add_binding(
            &n,
            8080,
            NewBinding {
                proto: udp,
                addr: BindAddr::V4(vaddr),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
                listening: true,
                accepted: false,
                host_ip: [127, 1, 2, 1],
                host_port: 52002,
                wide: false,
            },
        );
        let w = World {
            all: vec![crate::nsproxy::NsProxy::init().net, n.clone()],
        };
        assert_eq!(
            from_host_peer(
                &w,
                &n,
                udp,
                &v4([127, 1, 2, 1], 52001),
                true,
                false,
                |_, g, _| g,
            ),
            v4([127, 0, 0, 1], 8080)
        );
        assert_eq!(
            from_host_peer(
                &w,
                &n,
                udp,
                &v4([127, 1, 2, 1], 52002),
                false,
                false,
                |_, g, _| g,
            ),
            v4(vaddr, 8080)
        );
        remove_binding(&n, u_lo);
        remove_binding(&n, u_va);
        // Still translates during LINGER window
        assert_eq!(
            lookup_host(&n, udp, [127, 1, 2, 1], 52002),
            Some((8080, BindAddr::V4(vaddr)))
        );
    }

    /// Translation in a world of only the initial namespace and `ns` (addresses only).
    fn th(ns: &Rc<NetNs>, addr: &[u8], usage: Use, icmp6: bool) -> Result<Vec<u8>, Errno> {
        let w = World {
            all: vec![crate::nsproxy::NsProxy::init().net, ns.clone()],
        };
        to_host(&w, ns, addr, usage, icmp6).map(|m| m.addr)
    }

    fn fh(ns: &Rc<NetNs>, addr: &[u8], any: bool, icmp6: bool) -> Vec<u8> {
        let w = World {
            all: vec![crate::nsproxy::NsProxy::init().net, ns.clone()],
        };
        let role = if any {
            Role::Local {
                any: true,
                vaddr: None,
                peer: None,
            }
        } else {
            Role::Peer
        };
        from_host(&w, ns, addr, role, icmp6)
    }

    #[test]
    fn loopback_addresses_map_to_the_namespace_range() {
        let ns = Rc::new(ns());
        // lo still down: the wildcard address and 127.0.0.1 can be bound, but neither 127.0.0.1
        // nor ::1 can be reached; outside addresses are never reachable
        assert_eq!(
            th(&ns, &v4([0; 4], 80), Use::Bind, false).unwrap(),
            v4([127, 1, 2, 1], 80)
        );
        assert_eq!(
            th(&ns, &v4([127, 0, 0, 1], 80), Use::Bind, false).unwrap(),
            v4([127, 1, 2, 1], 80)
        );
        assert_eq!(
            th(&ns, &v4([127, 0, 0, 1], 80), Use::Reach, false),
            Err(Errno::ENETUNREACH)
        );
        assert_eq!(
            th(&ns, &v6(LOOPBACK6, 80), Use::Reach, false),
            Err(Errno::EADDRNOTAVAIL)
        );
        up(&ns);
        assert_eq!(ns.lo.borrow().v4, [([127, 0, 0, 1], 8)]);
        assert_eq!(
            th(&ns, &v4([127, 0, 0, 1], 80), Use::Reach, false).unwrap(),
            v4([127, 1, 2, 1], 80)
        );
        assert_eq!(
            th(&ns, &v4([127, 0, 0, 9], 80), Use::Bind, false).unwrap(),
            v4([127, 1, 2, 9], 80)
        );
        assert_eq!(
            th(&ns, &v4([8, 8, 8, 8], 53), Use::Reach, false),
            Err(Errno::ENETUNREACH)
        );
        // ::1 and :: are the IPv4-mapped 127.a.b.1, and back again ::1
        let mapped = {
            let mut ip = [0u8; 16];
            ip[10..12].copy_from_slice(&[0xff, 0xff]);
            ip[12..].copy_from_slice(&[127, 1, 2, 1]);
            ip
        };
        assert_eq!(
            th(&ns, &v6(LOOPBACK6, 80), Use::Reach, false).unwrap(),
            v6(mapped, 80)
        );
        assert_eq!(
            th(&ns, &v6([0; 16], 80), Use::Bind, false).unwrap(),
            v6(mapped, 80)
        );
        assert_eq!(fh(&ns, &v6(mapped, 80), false, false), v6(LOOPBACK6, 80));
        assert_eq!(fh(&ns, &v6(mapped, 80), true, false), v6([0; 16], 80));
        assert_eq!(
            fh(&ns, &v4([127, 1, 2, 7], 9), false, false),
            v4([127, 0, 0, 7], 9)
        );
        assert_eq!(fh(&ns, &v4([127, 1, 2, 1], 9), true, false), v4([0; 4], 9));
        let mut doc = [0u8; 16];
        doc[0] = 0x20;
        assert_eq!(
            th(&ns, &v6(doc, 80), Use::Reach, false),
            Err(Errno::ENETUNREACH)
        );
        // ICMPv6 sockets: ::1 is the host's ::1, the wildcard address is bound to it too, and
        // others are still unreachable
        assert_eq!(
            th(&ns, &v6(LOOPBACK6, 0), Use::Reach, true).unwrap(),
            v6(LOOPBACK6, 0)
        );
        assert_eq!(
            th(&ns, &v6([0; 16], 0), Use::Bind, true).unwrap(),
            v6(LOOPBACK6, 0)
        );
        assert_eq!(
            th(&ns, &v6(doc, 0), Use::Reach, true),
            Err(Errno::ENETUNREACH)
        );
        assert_eq!(fh(&ns, &v6(LOOPBACK6, 0), false, true), v6(LOOPBACK6, 0));
        assert_eq!(fh(&ns, &v6(LOOPBACK6, 0), true, true), v6([0; 16], 0));
        // The initial namespace does not translate
        let init = crate::nsproxy::NsProxy::init().net;
        assert_eq!(
            th(&init, &v4([8, 8, 8, 8], 53), Use::Reach, false).unwrap(),
            v4([8, 8, 8, 8], 53)
        );
        let _ = Rc::clone(&init);
    }

    #[test]
    fn loopback_aliases_share_host_ip_and_keep_guest_endpoints() {
        let ns = Rc::new(ns());
        up(&ns);
        // Every shared host address must round-trip through the bound guest address,
        // including IPv4-mapped IPv6 and the suffix reserved for the virtual address.
        let w = World {
            all: vec![crate::nsproxy::NsProxy::init().net, ns.clone()],
        };
        let host_ip = [127, 1, 2, 1];
        for ip in [
            [127, 0, 0, 0],
            [127, 0, 1, 1],
            [127, 1, 0, 1],
            [127, 1, 2, 3],
            [127, 0, 0, 254],
            [127, 0, 0, 255],
            [127, 255, 255, 254],
        ] {
            let mapped6 = |ip| v6(std::net::Ipv4Addr::from(ip).to_ipv6_mapped().octets(), 80);
            for (guest, host) in [
                (v4(ip, 80), v4(host_ip, 80)),
                (mapped6(ip), mapped6(host_ip)),
            ] {
                let m = to_host(&w, &ns, &guest, Use::Bind, false).unwrap();
                assert_eq!(m.addr, host);
                assert_eq!(m.vaddr, Some(ip));
                let role = Role::Local {
                    any: false,
                    vaddr: m.vaddr,
                    peer: None,
                };
                assert_eq!(from_host(&w, &ns, &host, role, false), guest);
                let reach = to_host(&w, &ns, &guest, Use::Reach, false).unwrap();
                assert_eq!(reach.addr, host);
                assert!(Rc::ptr_eq(reach.target.as_ref().unwrap(), &ns));
            }
        }
        assert_eq!(
            th(&ns, &v4([127, 0, 0, 253], 80), Use::Bind, false),
            Ok(v4([127, 1, 2, 253], 80))
        );
        ns.lo.borrow_mut().v4 = vec![([127, 0, 0, 1], 24)];
        let outside = v4([127, 0, 1, 1], 80);
        assert!(th(&ns, &outside, Use::Bind, false).is_ok());
        assert_eq!(
            th(&ns, &outside, Use::Reach, false),
            Err(Errno::ENETUNREACH)
        );
        ns.lo.borrow_mut().v4 = vec![([127, 0, 0, 1], 8)];

        let tcp = crate::net::IPPROTO_TCP;
        let listeners = [([127, 0, 1, 1], 49101), ([127, 1, 2, 3], 49102)];
        for (ip, port) in listeners {
            bind_listener(&ns, tcp, 8080, BindAddr::V4(ip), false, host_ip, port);
        }
        assert!(!bind_conflict(
            &ns,
            &BindReq {
                proto: tcp,
                guest_port: 8080,
                addr: BindAddr::V4([127, 0, 0, 1]),
                v6only: false,
                reuseaddr: false,
                reuseport: false,
                euid: 0,
                bound_dev_if: 0,
            },
            None,
        ));
        for (ip, port) in listeners {
            let guest = v4(ip, 8080);
            assert_eq!(resolve_target(&ns, tcp, &guest), Some((host_ip, port)));
            assert_eq!(
                from_host_peer(&w, &ns, tcp, &v4(host_ip, port), false, false, |_, g, _| g),
                guest
            );
        }
    }

    #[test]
    fn virtual_addresses_map_across_namespaces() {
        let init = crate::nsproxy::NsProxy::init().net;
        let net = |b: u8| {
            Rc::new(NetNs {
                id: u64::from(b),
                owner: crate::cred::UserNs::init(),
                host_net: Some([7, b]),
                lo: Default::default(),
                devs: RefCell::new(crate::netdev::Devices::for_new_ns(&Default::default())),
                nft: Default::default(),
                listeners: Default::default(),
            })
        };
        let (a, b) = (net(1), net(2));
        let gw = [10, 50, 0, 1];
        crate::netdev::test_dev(&init, "br0", gw, 24, None);
        crate::netdev::test_dev(&a, "eth0", [10, 50, 0, 2], 24, Some(gw));
        crate::netdev::test_dev(&b, "eth0", [10, 50, 0, 3], 24, Some(gw));
        let w = World {
            all: vec![init.clone(), a.clone(), b.clone()],
        };
        let reach = |me: &Rc<NetNs>, ip| to_host(&w, me, &v4(ip, 80), Use::Reach, false);
        let target = |m: &Mapped| m.target.as_ref().map(|t| t.id);
        // Another container, the gateway, outside, and an address missing from a directly
        // connected subnet
        let m = reach(&a, [10, 50, 0, 3]).unwrap();
        assert_eq!(
            (m.addr.clone(), target(&m)),
            (v4([127, 7, 2, 1], 80), Some(2))
        );
        assert_eq!(m.source, Some(v4([127, 7, 1, 1], 0)));
        let m = reach(&a, gw).unwrap();
        assert_eq!(m.addr, v4([127, INIT_BLOCK, 0, 1], 80));
        let m = reach(&a, [8, 8, 8, 8]).unwrap();
        assert_eq!(
            (m.addr.clone(), m.target.is_none(), m.source),
            (v4([8, 8, 8, 8], 80), true, None)
        );
        assert_eq!(reach(&a, [10, 50, 0, 9]).err(), Some(Errno::EHOSTUNREACH));
        // Binding its own address: 127.a.b.1 on the host, recording the virtual address; others'
        // cannot be bound
        let m = to_host(&w, &a, &v4([10, 50, 0, 2], 80), Use::Bind, false).unwrap();
        assert_eq!(
            (m.addr, m.vaddr),
            (v4([127, 7, 1, 1], 80), Some([10, 50, 0, 2]))
        );
        assert_eq!(
            to_host(&w, &a, &v4([10, 50, 0, 3], 80), Use::Bind, false).err(),
            Some(Errno::EADDRNOTAVAIL)
        );
        // The initial namespace: connecting to a container first binds the host counterpart of
        // the gateway address, and binding its own address binds to that too
        let m = reach(&init, [10, 50, 0, 2]).unwrap();
        assert_eq!(m.addr, v4([127, 7, 1, 1], 80));
        assert_eq!(m.source, Some(v4([127, INIT_BLOCK, 0, 1], 0)));
        let m = to_host(&w, &init, &v4(gw, 53), Use::Bind, false).unwrap();
        assert_eq!(m.addr, v4([127, INIT_BLOCK, 0, 1], 53));
        assert_eq!(
            reach(&init, [8, 8, 8, 8]).unwrap().addr,
            v4([8, 8, 8, 8], 80)
        );
        // The other way: another namespace's block and 127.255.x.y translate back to virtual
        // addresses; the local end faces the other side
        let peer = |me: &NetNs, x| from_host(&w, me, &v4(x, 9), Role::Peer, false);
        assert_eq!(peer(&b, [127, 7, 1, 1]), v4([10, 50, 0, 2], 9));
        assert_eq!(peer(&a, [127, INIT_BLOCK, 0, 1]), v4(gw, 9));
        assert_eq!(peer(&init, [127, 7, 2, 1]), v4([10, 50, 0, 3], 9));
        assert_eq!(peer(&a, [8, 8, 4, 4]), v4([8, 8, 4, 4], 9));
        let local = |me: &NetNs, x, p| {
            let p = v4(p, 1);
            let role = Role::Local {
                any: false,
                vaddr: None,
                peer: Some(&p),
            };
            from_host(&w, me, &v4(x, 9), role, false)
        };
        assert_eq!(
            local(&a, [127, 7, 1, 1], [127, 7, 2, 1]),
            v4([10, 50, 0, 2], 9)
        );
        assert_eq!(
            local(&a, [192, 168, 1, 5], [8, 8, 8, 8]),
            v4([10, 50, 0, 2], 9)
        );
        // Without a default route, outside is unreachable
        let mut r = vec![AF_INET as u8, 0, 0, 0, 254, 0, 255, 0, 0, 0, 0, 0];
        crate::net::attr(&mut r, 5, &gw);
        let del = crate::net::message(25, 1, 1, 0, &r);
        let none = |_: u16, _: u32| -> Result<Rc<NetNs>, Errno> { Err(Errno::ESRCH) };
        crate::netdev::request(&a, &Cred::root(), &del, &none)
            .unwrap()
            .unwrap();
        assert_eq!(reach(&a, [8, 8, 8, 8]).err(), Some(Errno::ENETUNREACH));
    }

    #[test]
    fn netlink_configures_lo() {
        let ns = ns();
        let root = Cred::root();
        let msg = |ty: u16, flags: u16, body: &[u8]| {
            let mut m = crate::net::message(ty, flags | 1, 1, 0, body);
            m.truncate(16 + body.len());
            m
        };
        // bwrap's loopback_setup: add 127.0.0.1/8 first, then bring lo up
        let mut addr = vec![AF_INET as u8, 8, 0x80, 254, 1, 0, 0, 0];
        crate::net::attr(&mut addr, 2, &[127, 0, 0, 1]);
        crate::net::attr(&mut addr, 1, &[127, 0, 0, 1]);
        assert_eq!(configure(&ns, &root, &msg(20, 0x600, &addr)), Some(0));
        assert_eq!(
            configure(&ns, &root, &msg(20, 0x600, &addr)),
            Some(Errno::EEXIST.0)
        );
        let mut link = vec![0u8; 16];
        link[4..8].copy_from_slice(&1i32.to_le_bytes());
        link[8..12].copy_from_slice(&IFF_UP.to_le_bytes());
        link[12..16].copy_from_slice(&IFF_UP.to_le_bytes());
        assert_eq!(configure(&ns, &root, &msg(16, 0, &link)), Some(0));
        let lo = lo_interface(&ns);
        assert_eq!(lo.flags & IFF_UP, IFF_UP);
        assert_eq!(lo.addrs.len(), 2);
        // There are no other interfaces; without CAP_NET_ADMIN nothing can be configured
        link[4..8].copy_from_slice(&2i32.to_le_bytes());
        assert_eq!(
            configure(&ns, &root, &msg(16, 0, &link)),
            Some(Errno::ENODEV.0)
        );
        let mut nobody = Cred::root();
        nobody.cap_effective = 0;
        assert_eq!(
            configure(&ns, &nobody, &msg(16, 0, &link)),
            Some(Errno::EPERM.0)
        );
        assert_eq!(configure(&ns, &root, &msg(18, 0, &link)), None);
    }

    /// Deleting IPv4 addresses (including secondaries with their primary), deleting or moving a
    /// virtual device, or dropping a veth peer's namespace reclaims initial-namespace `hostmap`
    /// entries so slots recycle cleanly past the 65,534-slot address space without leaking.
    #[test]
    fn hostmap_reclaims_and_recycles_on_addr_and_dev_removal() {
        let init = crate::nsproxy::NsProxy::init().net;
        let child = Rc::new(ns());
        let w = World {
            all: vec![init.clone(), child.clone()],
        };
        let root = Cred::root();
        let resolve_child = |_: u16, id: u32| -> Result<Rc<NetNs>, Errno> {
            if id == child.id as u32 {
                Ok(child.clone())
            } else {
                Err(Errno::ESRCH)
            }
        };
        let send = |target_ns: &Rc<NetNs>, ty: u16, flags: u16, body: &[u8]| {
            let req = crate::net::message(ty, flags | 1, 1, 0, body);
            crate::netdev::request(target_ns, &root, &req, &resolve_child)
                .unwrap()
                .unwrap();
        };
        let add_dummy = |name: &str| -> u32 {
            let mut p = vec![0u8; 16];
            let mut n = name.as_bytes().to_vec();
            n.push(0);
            crate::net::attr(&mut p, 3, &n); // IFLA_IFNAME
            let mut li = Vec::new();
            crate::net::attr(&mut li, 1, b"dummy"); // IFLA_INFO_KIND
            crate::net::attr(&mut p, 18, &li); // IFLA_LINKINFO
            send(&init, 16, 0x600, &p); // RTM_NEWLINK, CREATE|EXCL
            crate::netdev::views(&init)
                .into_iter()
                .find(|v| v.name == name.as_bytes())
                .unwrap()
                .index
        };
        let add_ip = |idx: u32, ip: [u8; 4], prefix: u8| {
            let mut p = vec![AF_INET as u8, prefix, 0, 0];
            p.extend_from_slice(&idx.to_le_bytes());
            crate::net::attr(&mut p, 2, &ip); // IFA_LOCAL
            crate::net::attr(&mut p, 1, &ip); // IFA_ADDRESS
            send(&init, 20, 0x600, &p); // RTM_NEWADDR
        };
        let del_ip = |idx: u32, ip: [u8; 4], prefix: u8| {
            let mut p = vec![AF_INET as u8, prefix, 0, 0];
            p.extend_from_slice(&idx.to_le_bytes());
            crate::net::attr(&mut p, 2, &ip); // IFA_LOCAL
            crate::net::attr(&mut p, 1, &ip); // IFA_ADDRESS
            send(&init, 21, 0, &p); // RTM_DELADDR
        };
        let del_link = |idx: u32| {
            let mut p = vec![0u8; 16];
            p[4..8].copy_from_slice(&(idx as i32).to_le_bytes());
            send(&init, 17, 0, &p); // RTM_DELLINK
        };

        // 1. Primary + secondary deletion reclaims both entries.
        let d0 = add_dummy("hm0");
        let ip1 = [10, 90, 0, 1];
        let ip2 = [10, 90, 0, 2];
        let ip3 = [10, 90, 0, 3];
        add_ip(d0, ip1, 24);
        add_ip(d0, ip2, 24);
        let h1 = to_host(&w, &init, &v4(ip1, 80), Use::Bind, false)
            .unwrap()
            .addr;
        let h2 = to_host(&w, &init, &v4(ip2, 80), Use::Bind, false)
            .unwrap()
            .addr;
        let h1_ip: [u8; 4] = h1[4..8].try_into().unwrap();
        let h2_ip: [u8; 4] = h2[4..8].try_into().unwrap();
        assert_ne!(h1_ip, h2_ip);
        assert_eq!(init.devs.borrow().hostmap.len(), 2);
        assert_eq!(init_guest(&init, h1_ip), Some(ip1));
        assert_eq!(init_guest(&init, h2_ip), Some(ip2));

        del_ip(d0, ip2, 24);
        assert_eq!(init.devs.borrow().hostmap.len(), 1);
        assert_eq!(init_guest(&init, h2_ip), None);
        assert_eq!(init_guest(&init, h1_ip), Some(ip1));

        // Deleting primary also removes secondary ip3 and reclaims both.
        add_ip(d0, ip3, 24);
        let _ = to_host(&w, &init, &v4(ip3, 80), Use::Bind, false).unwrap();
        assert_eq!(init.devs.borrow().hostmap.len(), 2);
        del_ip(d0, ip1, 24);
        assert_eq!(init.devs.borrow().hostmap.len(), 0);

        // 2. Shared address across two devices is kept until the last device holding it goes away.
        let d1 = add_dummy("hm1");
        let shared = [10, 91, 0, 1];
        add_ip(d0, shared, 24);
        add_ip(d1, shared, 24);
        let hs = init_host(&init, shared).unwrap();
        del_link(d0);
        assert_eq!(init.devs.borrow().hostmap.len(), 1);
        assert_eq!(init_host(&init, shared).unwrap(), hs);
        del_link(d1);
        assert_eq!(init.devs.borrow().hostmap.len(), 0);
        assert_eq!(init_guest(&init, hs), None);

        // 3. Moving a device out of the initial namespace reclaims its hostmap entries.
        let d2 = add_dummy("hm2");
        let moved_ip = [10, 92, 0, 1];
        add_ip(d2, moved_ip, 24);
        let hm = init_host(&init, moved_ip).unwrap();
        assert_eq!(init.devs.borrow().hostmap.len(), 1);
        let mut mv = vec![0u8; 16];
        mv[4..8].copy_from_slice(&(d2 as i32).to_le_bytes());
        crate::net::attr(&mut mv, 19, &(child.id as u32).to_le_bytes()); // IFLA_NET_NS_PID
        send(&init, 19, 0, &mv); // RTM_SETLINK
        assert_eq!(init.devs.borrow().hostmap.len(), 0);
        assert_eq!(init_guest(&init, hm), None);

        // 4. Dropping a veth peer's namespace prunes the init-ns veth and reclaims its hostmap.
        let peer_ns = Rc::new(NetNs {
            id: 42,
            owner: crate::cred::UserNs::init(),
            host_net: Some([8, 42]),
            lo: Default::default(),
            devs: RefCell::new(crate::netdev::Devices::for_new_ns(&Default::default())),
            nft: Default::default(),
            listeners: Default::default(),
        });
        let mut peer_info = vec![0u8; 16];
        crate::net::attr(&mut peer_info, 3, b"vp1\0");
        crate::net::attr(&mut peer_info, 19, &(peer_ns.id as u32).to_le_bytes());
        let mut veth_data = Vec::new();
        crate::net::attr(&mut veth_data, 1, &peer_info); // VETH_INFO_PEER
        let mut li = Vec::new();
        crate::net::attr(&mut li, 1, b"veth");
        crate::net::attr(&mut li, 2, &veth_data); // IFLA_INFO_DATA
        let mut veth_req = vec![0u8; 16];
        crate::net::attr(&mut veth_req, 3, b"vp0\0");
        crate::net::attr(&mut veth_req, 18, &li);
        let resolve_peer = |_: u16, id: u32| -> Result<Rc<NetNs>, Errno> {
            if id == peer_ns.id as u32 {
                Ok(peer_ns.clone())
            } else {
                Err(Errno::ESRCH)
            }
        };
        let req = crate::net::message(16, 0x601, 1, 0, &veth_req);
        crate::netdev::request(&init, &root, &req, &resolve_peer)
            .unwrap()
            .unwrap();
        let vp0 = crate::netdev::views(&init)
            .into_iter()
            .find(|v| v.name == b"vp0")
            .unwrap()
            .index;
        let veth_ip = [10, 93, 0, 1];
        add_ip(vp0, veth_ip, 24);
        let hv = init_host(&init, veth_ip).unwrap();
        assert_eq!(init.devs.borrow().hostmap.len(), 1);
        drop(peer_ns);
        let _ = crate::netdev::views(&init);
        assert_eq!(init.devs.borrow().hostmap.len(), 0);
        assert_eq!(init_guest(&init, hv), None);

        // 5. Recycling past MAX_SLOT (65,534) add/delete cycles never leaks or exhausts.
        let total = usize::from(crate::netdev::HostMap::MAX_SLOT) + 2000;
        let mut seen_recycled = false;
        let first_host = init
            .devs
            .borrow_mut()
            .hostmap
            .get_or_alloc([10, 0, 0, 1])
            .unwrap();
        assert!(init.devs.borrow_mut().hostmap.remove([10, 0, 0, 1]));
        for i in 1..=total {
            let ip = [
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ];
            let h = init
                .devs
                .borrow_mut()
                .hostmap
                .get_or_alloc(ip)
                .expect("recycled slot must be available");
            if h == first_host {
                seen_recycled = true;
            }
            assert_eq!(init_guest(&init, h), Some(ip));
            assert!(init.devs.borrow_mut().hostmap.remove(ip));
        }
        assert!(seen_recycled, "freed slot must eventually be recycled");
        assert_eq!(init.devs.borrow().hostmap.len(), 0);
    }

    /// Exhausting all 65,534 slots of `hostmap` returns `EADDRNOTAVAIL` instead of colliding on
    /// `127.255.0.1`, preserves O(1) lookup of existing mappings, and recovers once a slot is
    /// freed.
    #[test]
    fn hostmap_exhaustion_fails_without_colliding() {
        let init = crate::nsproxy::NsProxy::init().net;
        let max = usize::from(crate::netdev::HostMap::MAX_SLOT);
        let mut first_host = [0u8; 4];
        let mut last_host = [0u8; 4];
        let mut seen = std::collections::HashSet::with_capacity(max);

        for i in 0..max {
            let ip = [10, 100, (i >> 8) as u8, (i & 0xff) as u8];
            let h = init_host(&init, ip).expect("slot within capacity");
            assert_eq!(h[..2], [127, INIT_BLOCK]);
            assert_ne!(
                &h[2..],
                &[0, 0],
                "network address .0.0 must never be allocated"
            );
            assert_ne!(
                &h[2..],
                &[255, 255],
                "broadcast address .255.255 must never be allocated"
            );
            assert!(seen.insert(h), "duplicate hostmap allocation {h:?}");
            if i == 0 {
                first_host = h;
            }
            if i + 1 == max {
                last_host = h;
            }
        }
        assert_eq!(init.devs.borrow().hostmap.len(), max);

        // Existing entries still resolve in O(1) in both directions even when full.
        assert_eq!(init_host(&init, [10, 100, 0, 0]), Ok(first_host));
        assert_eq!(
            init_host(
                &init,
                [10, 100, ((max - 1) >> 8) as u8, ((max - 1) & 0xff) as u8]
            ),
            Ok(last_host)
        );
        assert_eq!(init_guest(&init, first_host), Some([10, 100, 0, 0]));
        assert_eq!(
            init_guest(&init, last_host),
            Some([10, 100, ((max - 1) >> 8) as u8, ((max - 1) & 0xff) as u8])
        );

        // Overflowing fails cleanly with EADDRNOTAVAIL and does not overwrite 127.255.0.1.
        let extra = [10, 200, 0, 1];
        assert_eq!(init_host(&init, extra), Err(Errno::EADDRNOTAVAIL));
        assert_eq!(init_guest(&init, first_host), Some([10, 100, 0, 0]));

        // Reaching or binding `extra` via `to_host` propagates EADDRNOTAVAIL instead of
        // misrouting to 127.255.0.1.
        crate::netdev::test_dev(&init, "ex0", extra, 24, None);
        let a = Rc::new(ns());
        crate::netdev::test_dev(&a, "eth0", [10, 200, 0, 2], 24, Some(extra));
        let w = World {
            all: vec![init.clone(), a.clone()],
        };
        assert_eq!(
            to_host(&w, &init, &v4(extra, 80), Use::Bind, false).err(),
            Some(Errno::EADDRNOTAVAIL)
        );
        assert_eq!(
            to_host(&w, &a, &v4(extra, 80), Use::Reach, false).err(),
            Some(Errno::EADDRNOTAVAIL)
        );

        // Freeing one slot allows the new mapping to succeed using that reclaimed slot.
        assert!(init.devs.borrow_mut().hostmap.remove([10, 100, 0, 0]));
        let reused = to_host(&w, &init, &v4(extra, 80), Use::Bind, false)
            .unwrap()
            .addr;
        assert_eq!(&reused[4..8], &first_host);
        assert_eq!(init_guest(&init, first_host), Some(extra));
    }

    /// Initial-namespace isolation of allocated container `127.a.b.x` blocks: container blocks start
    /// at `127.0.2.0/24` (preserving `127.0.0.1` and Debian's `127.0.1.1`), direct initial-ns
    /// access to an active container's `127.a.b.x` (IPv4 or IPv4-mapped IPv6) is isolated/refused,
    /// while unallocated loopback and routed container virtual IPs continue to work.
    #[test]
    fn initial_netns_isolates_allocated_container_loopback_blocks() {
        let mut k = crate::kernel::Kernel::new(crate::process::Tier::Interpreter);
        let init = k.init_ns.net.clone();
        let owner = crate::cred::UserNs::init();
        let c1 = k.new_net_ns(owner.clone()).unwrap();
        let c2 = k.new_net_ns(owner).unwrap();
        // First container starts at 127.0.2.0/24 so 127.0.1.1 stays free for init-ns.
        assert_eq!(c1.host_net, Some([0, 2]));
        assert_eq!(c2.host_net, Some([0, 3]));
        crate::netdev::test_dev(&init, "br0", [10, 75, 0, 1], 24, None);
        crate::netdev::test_dev(&c1, "eth0", [10, 75, 0, 2], 24, Some([10, 75, 0, 1]));

        let w = k.world();
        let v4_mapped = |ip: [u8; 4], port: u16| {
            let mut a = [0u8; 16];
            a[10..12].copy_from_slice(&[0xff, 0xff]);
            a[12..16].copy_from_slice(&ip);
            v6(a, port)
        };

        // Standard loopback (127.0.0.1), Debian 127.0.1.1, and unallocated 127.0.99.1 stay open.
        for ip in [[127, 0, 0, 1], [127, 0, 1, 1], [127, 0, 99, 1]] {
            for addr in [v4(ip, 8080), v4_mapped(ip, 8080)] {
                assert!(!is_foreign_loopback(&w, &init, &addr));
                for usage in [Use::Bind, Use::Reach] {
                    assert!(!to_host(&w, &init, &addr, usage, false).unwrap().isolated);
                }
            }
        }

        // Allocated container blocks (127.0.2.x, 127.0.3.x) are isolated from initial-ns guests
        // for both IPv4 and IPv4-mapped IPv6, and cannot be bound by initial-ns guests.
        for ip in [[127, 0, 2, 1], [127, 0, 2, 42], [127, 0, 3, 1]] {
            for addr in [v4(ip, 8080), v4_mapped(ip, 8080)] {
                assert!(is_foreign_loopback(&w, &init, &addr));
                assert_eq!(
                    to_host(&w, &init, &addr, Use::Bind, false).err(),
                    Some(Errno::EADDRNOTAVAIL)
                );
                assert!(
                    to_host(&w, &init, &addr, Use::Reach, false)
                        .unwrap()
                        .isolated
                );
            }
        }

        // Reaching c1 via its virtual IP still translates to 127.0.2.1 with isolated == false.
        let routed = to_host(&w, &init, &v4([10, 75, 0, 2], 8080), Use::Reach, false).unwrap();
        assert!(!routed.isolated);
        assert_eq!(&routed.addr[4..8], &[127, 0, 2, 1]);
        assert!(Rc::ptr_eq(routed.target.as_ref().unwrap(), &c1));

        // Dropping c2 frees 127.0.3.0/24 so initial-ns can use it as normal unallocated loopback.
        drop(w);
        drop(c2);
        let w2 = k.world();
        assert!(!is_foreign_loopback(&w2, &init, &v4([127, 0, 3, 1], 8080)));
        assert!(
            !to_host(&w2, &init, &v4([127, 0, 3, 1], 8080), Use::Reach, false)
                .unwrap()
                .isolated
        );
    }

    /// PREROUTING filter chains ordered before a namespace's DNAT see the pre-DNAT destination
    /// while chains ordered after DNAT see the post-DNAT destination, in both `path_filter`
    /// (single-hop and 2-hop routed via `init`) and `external_filter`.
    #[test]
    fn prerouting_filter_chains_respect_dnat_priority() {
        use crate::nft::HOOK_PRE_ROUTING;
        use crate::nft::tests::{
            batch, chain_msg, daddr, dnat_to, dport, drop_expr, peer, reject_rst, rule_msg,
            table_msg,
        };

        let root = Cred::root();
        let apply = |ns: &NetNs, msgs: &[Vec<u8>]| {
            let replies = crate::nft::handle(ns, &root, &batch(msgs), &peer());
            assert!(
                replies.is_empty(),
                "nft batch failed ({} replies)",
                replies.len()
            );
        };
        let chain =
            |tbl, name, prio, ty| chain_msg(2, tbl, name, Some((HOOK_PRE_ROUTING, prio, ty)));

        let init = crate::nsproxy::NsProxy::init().net;
        let mk_ns = |id: u64, b: u8| {
            Rc::new(NetNs {
                id,
                owner: crate::cred::UserNs::init(),
                host_net: Some([9, b]),
                lo: Default::default(),
                devs: RefCell::new(crate::netdev::Devices::for_new_ns(&Default::default())),
                nft: Default::default(),
                listeners: Default::default(),
            })
        };
        let a = mk_ns(10, 1);
        let b = mk_ns(11, 2);
        let gw0 = [10, 80, 0, 1];
        let gw1 = [10, 81, 0, 1];
        let a_ip = [10, 80, 0, 2];
        let b_ip = [10, 81, 0, 3];
        crate::netdev::test_dev(&init, "br0", gw0, 24, None);
        crate::netdev::test_dev(&init, "br1", gw1, 24, None);
        crate::netdev::test_dev(&a, "eth0", a_ip, 24, Some(gw0));
        crate::netdev::test_dev(&b, "eth0", b_ip, 24, Some(gw1));
        let w = World {
            all: vec![init.clone(), a.clone(), b.clone()],
        };

        let filter_dnat = |nat_ns: &NetNs, dst: Vec<u8>| {
            let NatResult::Dnat(there) = prerouting_nat(&a, nat_ns, 6, 40000, &dst, None).unwrap()
            else {
                panic!("expected DNAT");
            };
            let origs = vec![(nat_ns.id, dst.clone())];
            let flow = Flow {
                proto: 6,
                vaddr: Some(a_ip),
                sport: 40000,
                dst: &dst,
                bridge: None,
                origs: &origs,
                there: &there,
                uid: 0,
                gid: 0,
                established: false,
                mark: 0,
            };
            path_filter(&w, &a, Some(&b), &flow)
        };

        // Case 1: init DNATs 10.80.0.1:8080..8082 -> 10.81.0.3:80..82 at priority -100, and has:
        // - raw (-300): drops dport 80 (must NOT match pre-DNAT 8080), rejects dport 8081
        // - post (0): drops dport 8080 (must NOT match post-DNAT 80), rejects dport 8082->82
        apply(
            &init,
            &[
                table_msg(2, b"t"),
                chain(b"t", b"raw", -300, b"filter"),
                chain(b"t", b"nat", -100, b"nat"),
                chain(b"t", b"post", 0, b"filter"),
                rule_msg(
                    2,
                    b"t",
                    b"nat",
                    &[&dport(8080)[..], &dnat_to(b_ip, 80)].concat(),
                ),
                rule_msg(
                    2,
                    b"t",
                    b"nat",
                    &[&dport(8081)[..], &dnat_to(b_ip, 81)].concat(),
                ),
                rule_msg(
                    2,
                    b"t",
                    b"nat",
                    &[&dport(8082)[..], &dnat_to(b_ip, 82)].concat(),
                ),
                rule_msg(2, b"t", b"raw", &[&dport(80)[..], &[drop_expr()]].concat()),
                rule_msg(
                    2,
                    b"t",
                    b"raw",
                    &[&daddr(gw0)[..], &dport(8081), &[reject_rst()]].concat(),
                ),
                rule_msg(
                    2,
                    b"t",
                    b"post",
                    &[&dport(8080)[..], &[drop_expr()]].concat(),
                ),
                rule_msg(
                    2,
                    b"t",
                    b"post",
                    &[&daddr(b_ip)[..], &dport(82), &[reject_rst()]].concat(),
                ),
            ],
        );

        // 8080 -> 80: passes both raw (-300, sees 8080 != 80) and post (0, sees 80 != 8080).
        assert_eq!(
            filter_dnat(&init, v4(gw0, 8080)),
            (crate::nft::Outcome::Accept, false)
        );
        // 8081 -> 81: raw (-300) sees pre-DNAT 10.80.0.1:8081 and rejects.
        assert_eq!(
            filter_dnat(&init, v4(gw0, 8081)),
            (crate::nft::Outcome::Reject(Errno::ECONNREFUSED.0), false)
        );
        // 8082 -> 82: post (0) sees post-DNAT 10.81.0.3:82 and rejects.
        assert_eq!(
            filter_dnat(&init, v4(gw0, 8082)),
            (crate::nft::Outcome::Reject(Errno::ECONNREFUSED.0), false)
        );

        // Case 2: external_nat + external_filter also splits init's PREROUTING filter chains.
        for (port, allow) in [(8080, true), (8081, false), (8082, false)] {
            let (orig, dnat) = external_nat(&init, 6, &v4(gw0, port)).unwrap();
            assert_eq!(external_filter(&init, Some(&b), 6, &orig, &dnat), allow);
        }

        // Case 3: A -> init -> B where B (not init) DNATs 9000 -> 9001; init sees pre-DNAT 9000,
        // B's pre-DNAT chain (-150) sees 9000, and B's post-DNAT chain (0) sees 9001.
        apply(
            &b,
            &[
                table_msg(2, b"tb"),
                chain(b"tb", b"pre", -150, b"filter"),
                chain(b"tb", b"nat", -100, b"nat"),
                chain(b"tb", b"post", 0, b"filter"),
                rule_msg(
                    2,
                    b"tb",
                    b"nat",
                    &[&dport(9000)[..], &dnat_to(b_ip, 9001)].concat(),
                ),
                rule_msg(
                    2,
                    b"tb",
                    b"pre",
                    &[&dport(9001)[..], &[drop_expr()]].concat(),
                ),
                rule_msg(
                    2,
                    b"tb",
                    b"post",
                    &[&dport(9000)[..], &[drop_expr()]].concat(),
                ),
            ],
        );
        assert_eq!(
            filter_dnat(&b, v4(b_ip, 9000)),
            (crate::nft::Outcome::Accept, false)
        );
    }
}
