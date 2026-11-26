//! Connections from outside the host to published ports (docs/rounds/173-port-forwarding.md).
//!
//! When the initial namespace has PREROUTING DNAT rules (ports published by podman or docker), a
//! connection from outside Appine (another device, a browser on the phone) to that port on the
//! host reaches the socket the guest is listening on in the host (the one podman holds the port
//! with and never accepts on). Such a socket is duplicated and handed to the host thread here: it
//! accepts connections, connects to the DNAT destination (the container's loopback address on the
//! host) and copies data between the two, acting as a docker-proxy inside the kernel layer. UDP is
//! forwarded through one host socket per source, closed after two minutes idle.
//!
//! When the outside client is IPv4 and not a loopback address (another device), the forwarded
//! connection first binds a 127.254.x.y address and the client's port before connecting, and
//! records it ([`outside_peer`]): accept and getpeername in the container see the client's real
//! address, as with DNAT on Linux (docs/rounds/176-real-client-address.md). Connections from
//! loopback addresses (other apps on the phone, a browser opening localhost) still bind the
//! gateway's address on the host: on Linux, when a published port is reached from the same
//! machine, netavark masquerades and docker goes through docker-proxy, so the container sees the
//! gateway too.
//!
//! The thread only touches host fds and never takes the BKL. Which ports to forward and where to
//! is computed from the rules by `syscall::net` and handed over ([`Forwarder::add`]); dropping the
//! [`Handle`] when the socket closes or the rules change stops the forwarding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POLLIN: i16 = 0x1;
const POLLOUT: i16 = 0x4;
const POLLERR: i16 = 0x8;
const POLLHUP: i16 = 0x10;
const EINTR: i32 = 4;
const EAGAIN: i32 = 11;
const EINPROGRESS: i32 = 115;
const ECONNRESET: i32 = 104;
const SOL_SOCKET: i32 = 1;
const SO_ERROR: i32 = 4;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SHUT_WR: i32 = 1;
/// Most bytes buffered per direction (when full, reading pauses).
const BUFFER: usize = 64 * 1024;
/// Maximum concurrent forwarded TCP connections across all forwarded ports.
const MAX_CONNS: usize = 256;
/// Maximum concurrent UDP forwarding sockets across all forwarded ports.
const MAX_UDP_RELAYS: usize = 256;
/// How long a nonblocking outbound TCP connect may remain in progress before it is closed.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a UDP forwarding socket may stay idle before it is closed (docker-proxy: 90 seconds).
const UDP_IDLE: Duration = Duration::from_secs(120);
/// How long a listening socket that is readable while accept fails (out of fds, shut down) is left
/// out of the poll, so the thread does not spin on it.
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);
/// How long the thread waits after poll itself fails (too many fds, out of memory) before trying
/// again.
const POLL_BACKOFF: Duration = Duration::from_millis(100);

/// Resource limits and timeouts enforced by the forwarding thread.
#[derive(Clone, Copy)]
struct Limits {
    max_conns: usize,
    max_relays: usize,
    connect_timeout: Duration,
    udp_idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_conns: MAX_CONNS,
            max_relays: MAX_UDP_RELAYS,
            connect_timeout: CONNECT_TIMEOUT,
            udp_idle: UDP_IDLE,
        }
    }
}

// ---- Forwarding thread ----

/// A port to forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub udp: bool,
    /// Destination on the host (sockaddr).
    pub addr: Vec<u8>,
    /// Host address bound (port 0) before connecting: the source the container sees (the initial
    /// namespace's address facing it).
    pub source: Option<Vec<u8>>,
}

/// The forwarding thread and the ports handed to it.
#[derive(Default)]
pub(crate) struct Forwarder {
    shared: Arc<Shared>,
}

impl Forwarder {
    #[cfg(test)]
    fn with_limits(limits: Limits) -> Self {
        Self {
            shared: Arc::new(Shared {
                limits,
                ..Shared::default()
            }),
        }
    }

    /// Forwards `fd`, listening on the host (a TCP listening socket, a bound UDP socket), to
    /// `target`.
    pub(crate) fn add(&self, fd: i32, target: Target) -> Result<Handle, i32> {
        let event = match self.shared.event.get() {
            Some(e) => e,
            None => {
                let e = appine_hal::Event::new()?;
                let _ = self.shared.event.set(e);
                self.shared.event.get().unwrap()
            }
        };
        let dup = appine_hal::dup(fd)?;
        let mut st = self.shared.state.lock().unwrap();
        st.next += 1;
        let id = st.next;
        st.ports.insert(
            id,
            PortEntry {
                fd: dup,
                target: Some(target.clone()),
            },
        );
        if !st.running {
            let shared = self.shared.clone();
            let spawned = std::thread::Builder::new()
                .name("forward".into())
                .spawn(move || run(&shared));
            if spawned.is_err() {
                st.ports.remove(&id);
                appine_hal::net::close(dup);
                return Err(11);
            }
            st.running = true;
        }
        drop(st);
        event.signal();
        Ok(Handle {
            shared: self.shared.clone(),
            id,
            target: Some(target),
        })
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.shared.state.lock().unwrap().stop = true;
        if let Some(e) = self.shared.event.get() {
            e.signal();
        }
    }
}

#[derive(Clone)]
struct PortEntry {
    fd: i32,
    /// `None` when the port's forwarding rule was withdrawn while the guest socket stays open:
    /// no new traffic is read from `fd`, while active UDP relays still deliver in-flight replies
    /// back through `fd` until idle expiry or socket close.
    target: Option<Target>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    event: std::sync::OnceLock<appine_hal::Event>,
    limits: Limits,
    /// Host tid of the forwarding thread, for tests measuring its CPU time without scanning other
    /// threads that may exit concurrently.
    #[cfg(test)]
    tid: std::sync::OnceLock<i32>,
}

#[derive(Default)]
struct State {
    next: u64,
    /// Ports to forward: the duplicated listening fd and its current destination.
    ports: HashMap<u64, PortEntry>,
    /// Duplicated fds of ports no longer forwarded: the thread closes them (it may be polling
    /// them).
    closing: Vec<i32>,
    running: bool,
    /// The kernel is gone ([`Forwarder`] was dropped): the thread closes the fds it holds and
    /// exits.
    stop: bool,
}

/// One forwarded port: forwarding stops when it is dropped.
pub(crate) struct Handle {
    shared: Arc<Shared>,
    id: u64,
    pub target: Option<Target>,
}

impl Handle {
    /// Updates this port's forwarding target in place without replacing the handle or cutting
    /// active UDP relays. Passing `None` stops reading new datagrams/connections from the port
    /// while letting active UDP relays continue delivering replies until idle expiry or drop.
    pub(crate) fn update(&mut self, target: Option<Target>) {
        if self.target == target {
            return;
        }
        self.target = target.clone();
        let mut st = self.shared.state.lock().unwrap();
        if let Some(entry) = st.ports.get_mut(&self.id) {
            entry.target = target;
        }
        drop(st);
        if let Some(e) = self.shared.event.get() {
            e.signal();
        }
    }
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("id", &self.id)
            .field("target", &self.target)
            .finish()
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let mut st = self.shared.state.lock().unwrap();
        if let Some(entry) = st.ports.remove(&self.id) {
            st.closing.push(entry.fd);
        }
        drop(st);
        if let Some(e) = self.shared.event.get() {
            e.signal();
        }
    }
}

/// One forwarded TCP connection.
struct Conn {
    client: i32,
    upstream: i32,
    /// The bound 127.254.x.y ([`outside_peer`]); its record is removed when the connection ends.
    outside: Option<[u8; 4]>,
    /// The connection to the destination has completed.
    ready: bool,
    /// When the nonblocking outbound connect started (used to expire stalled connects while
    /// `!ready`).
    connect_started: Instant,
    to_up: Vec<u8>,
    to_client: Vec<u8>,
    client_eof: bool,
    up_eof: bool,
    /// shutdown(SHUT_WR) already done toward the other side.
    up_shut: bool,
    client_shut: bool,
}

impl Conn {
    fn done(&self) -> bool {
        self.client_eof && self.up_eof && self.to_up.is_empty() && self.to_client.is_empty()
    }

    fn close(&self) {
        appine_hal::net::close(self.client);
        appine_hal::net::close(self.upstream);
        if let Some(a) = self.outside {
            forget_outside(a);
        }
    }
}

/// UDP: the forwarding socket of one source.
struct Relay {
    fd: i32,
    port: u64,
    client: Vec<u8>,
    last: Instant,
}

/// The forwarding thread.
fn run(shared: &Shared) {
    #[cfg(test)]
    let _ = shared.tid.set(appine_hal::gettid());
    let limits = shared.limits;
    let event = shared.event.get().expect("event before thread");
    let mut ports: HashMap<u64, PortEntry> = HashMap::new();
    let mut conns: Vec<Conn> = Vec::new();
    let mut relays: Vec<Relay> = Vec::new();
    // Ports whose accept failed while they polled readable, and until when they are left out
    let mut stalled: HashMap<u64, Instant> = HashMap::new();
    loop {
        // Take the ports handed over; close those whose handle was dropped, and their UDP
        // forwarding sockets too
        {
            event.clear();
            let mut st = shared.state.lock().unwrap();
            for fd in st.closing.drain(..) {
                ports.retain(|_, e| e.fd != fd);
                appine_hal::net::close(fd);
            }
            ports = st.ports.clone();
            if st.stop {
                for entry in st.ports.values() {
                    appine_hal::net::close(entry.fd);
                }
                st.ports.clear();
                st.running = false;
                drop(st);
                for c in &conns {
                    c.close();
                }
                for r in &relays {
                    appine_hal::net::close(r.fd);
                }
                return;
            }
        }
        let now = Instant::now();
        conns.retain(|c| {
            let expired = !c.ready
                && now.saturating_duration_since(c.connect_started) >= limits.connect_timeout;
            if expired {
                c.close();
            }
            !expired
        });
        relays.retain(|r| {
            let keep = ports.contains_key(&r.port)
                && now.saturating_duration_since(r.last) < limits.udp_idle;
            if !keep {
                appine_hal::net::close(r.fd);
            }
            keep
        });
        stalled
            .retain(|id, until| ports.get(id).is_some_and(|e| e.target.is_some()) && *until > now);
        // What to wait for: the event, every active port (omitting paused/stalled ones, and
        // omitting TCP listeners while at the connection cap so the accept socket does not
        // busy-loop), both sides of every connection, every UDP forwarding socket
        let at_conn_cap = conns.len() >= limits.max_conns;
        let mut fds: Vec<(i32, i16, i16)> = vec![(event.fd(), POLLIN, 0)];
        let order: Vec<(u64, i32, bool)> = ports
            .iter()
            .filter_map(|(id, e)| {
                let t = e.target.as_ref()?;
                (!stalled.contains_key(id) && (t.udp || !at_conn_cap)).then_some((*id, e.fd, t.udp))
            })
            .collect();
        fds.extend(order.iter().map(|&(_, fd, _)| (fd, POLLIN, 0)));
        for c in &conns {
            let mut ce = 0;
            if c.ready {
                if !c.client_eof && c.to_up.len() < BUFFER {
                    ce |= POLLIN;
                }
                if !c.to_client.is_empty() {
                    ce |= POLLOUT;
                }
            }
            let mut ue = 0;
            if !c.ready {
                ue |= POLLOUT;
            } else {
                if !c.up_eof && c.to_client.len() < BUFFER {
                    ue |= POLLIN;
                }
                if !c.to_up.is_empty() {
                    ue |= POLLOUT;
                }
            }
            fds.push((c.client, ce, 0));
            fds.push((c.upstream, ue, 0));
        }
        fds.extend(relays.iter().map(|r| (r.fd, POLLIN, 0)));
        // Connections accepted below are not in this round
        let polled_conns = conns.len();
        let idle = (!relays.is_empty()).then(|| limits.udp_idle.min(Duration::from_secs(5)));
        let resume = stalled
            .values()
            .min()
            .map(|t| t.saturating_duration_since(now));
        let connect_wait = conns
            .iter()
            .filter(|c| !c.ready)
            .map(|c| {
                limits
                    .connect_timeout
                    .saturating_sub(now.saturating_duration_since(c.connect_started))
            })
            .min();
        let timeout = [idle, resume, connect_wait].into_iter().flatten().min();
        match appine_hal::poll(&mut fds, timeout) {
            Ok(_) => {}
            Err(EINTR) => continue,
            Err(_) => {
                std::thread::sleep(POLL_BACKOFF);
                continue;
            }
        }
        // Send polled UDP replies back to the source before datagrams() can mutate `relays`
        // (via swap_remove on send error or push on a new client).
        let relays_at = 1 + order.len() + 2 * polled_conns;
        relay_replies(&mut relays, &fds[relays_at..], &ports);
        let mut at = 1;
        // Ports: accept connections, receive datagrams
        for &(id, fd, udp) in &order {
            let ready = fds[at].2 != 0;
            at += 1;
            if !ready {
                continue;
            }
            let Some(target) = ports[&id].target.as_ref() else {
                continue;
            };
            if udp {
                datagrams(id, fd, target, &mut relays, limits.max_relays);
                continue;
            }
            // Accept at most 64 at a time so the other connections do not starve, stopping once
            // the concurrent connection cap is reached
            for n in 0..64 {
                if conns.len() >= limits.max_conns {
                    break;
                }
                let (client, from) = match appine_hal::net::accept(fd) {
                    Ok(c) => c,
                    // Readable but nothing taken: out of fds, or a listener shut down (readable
                    // for good); leave it out of the poll for a while
                    Err(e) if n == 0 && e != EAGAIN => {
                        stalled.insert(id, Instant::now() + ACCEPT_BACKOFF);
                        break;
                    }
                    Err(_) => break,
                };
                match open(target, outside_client(&from)) {
                    Ok((upstream, ready, outside)) => conns.push(Conn {
                        client,
                        upstream,
                        outside,
                        ready,
                        connect_started: Instant::now(),
                        to_up: Vec::new(),
                        to_client: Vec::new(),
                        client_eof: false,
                        up_eof: false,
                        up_shut: false,
                        client_shut: false,
                    }),
                    // The destination cannot be reached: the client sees the connection closed
                    Err(_) => appine_hal::net::close(client),
                }
            }
        }
        // Connections
        let mut broken = vec![false; conns.len()];
        for (k, c) in conns.iter_mut().enumerate().take(polled_conns) {
            let (cr, ur) = (fds[at + 2 * k].2, fds[at + 2 * k + 1].2);
            let r = step(c, cr, ur);
            broken[k] = r.is_err() || c.done();
        }
        let mut i = 0;
        conns.retain(|c| {
            let gone = broken[i];
            i += 1;
            if gone {
                c.close();
            }
            !gone
        });
    }
}

/// Events ready on one connection (`cr` on the client side, `ur` on the destination side).
fn step(c: &mut Conn, cr: i16, ur: i16) -> Result<(), i32> {
    if !c.ready {
        if cr & (POLLERR | POLLHUP) != 0 {
            return Err(ECONNRESET);
        }
        if ur == 0 {
            return Ok(());
        }
        let err = appine_hal::net::getsockopt(c.upstream, SOL_SOCKET, SO_ERROR, 4)?;
        match i32::from_le_bytes(err[..4].try_into().unwrap()) {
            0 => c.ready = true,
            e => return Err(e),
        }
    }
    // A side that reports an error, or hangs up after its end of file while it may still be written
    // to, was reset: nothing more goes through it. Neither direction is polled for input after end
    // of file, so a reset of a half-closed side would otherwise show at every poll
    for (fd, r, eof, shut) in [
        (c.client, cr, c.client_eof, c.client_shut),
        (c.upstream, ur, c.up_eof, c.up_shut),
    ] {
        if r & POLLERR != 0 {
            let err = appine_hal::net::getsockopt(fd, SOL_SOCKET, SO_ERROR, 4)?;
            match i32::from_le_bytes(err[..4].try_into().unwrap()) {
                0 => {}
                e => return Err(e),
            }
        }
        if r & POLLHUP != 0 && eof && !shut {
            return Err(ECONNRESET);
        }
    }
    if cr & (POLLIN | POLLHUP | POLLERR) != 0 && !c.client_eof {
        c.client_eof = !fill(c.client, &mut c.to_up)?;
    }
    if ur & (POLLIN | POLLHUP | POLLERR) != 0 && !c.up_eof {
        c.up_eof = !fill(c.upstream, &mut c.to_client)?;
    }
    drain(c.upstream, &mut c.to_up)?;
    drain(c.client, &mut c.to_client)?;
    // One side reached its end and all its data went across: half-close toward the other side
    if c.client_eof && c.to_up.is_empty() && !c.up_shut {
        let _ = appine_hal::net::shutdown(c.upstream, SHUT_WR);
        c.up_shut = true;
    }
    if c.up_eof && c.to_client.is_empty() && !c.client_shut {
        let _ = appine_hal::net::shutdown(c.client, SHUT_WR);
        c.client_shut = true;
    }
    Ok(())
}

/// Reads from `fd` into `buf` (up to [`BUFFER`]): end of file is Ok(false).
fn fill(fd: i32, buf: &mut Vec<u8>) -> Result<bool, i32> {
    let mut chunk = vec![0u8; BUFFER - buf.len()];
    match appine_hal::read(fd, &mut chunk) {
        Ok(0) => Ok(false),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(true)
        }
        Err(EAGAIN) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Writes `buf` to `fd` (whatever cannot be written stays).
fn drain(fd: i32, buf: &mut Vec<u8>) -> Result<(), i32> {
    while !buf.is_empty() {
        match appine_hal::net::sendmsg(fd, buf, &[], &[], 0) {
            Ok(n) => {
                buf.drain(..n);
            }
            Err(EAGAIN) => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Datagrams received on a UDP port: finds (or opens, up to `max_relays`) the forwarding socket
/// of the source and sends them to the destination. Datagrams from new sources while at the cap
/// are drained and dropped so the UDP socket does not busy-loop or leak fds.
fn datagrams(id: u64, fd: i32, target: &Target, relays: &mut Vec<Relay>, max_relays: usize) {
    let mut buf = vec![0u8; 65536];
    for _ in 0..64 {
        let Ok(m) = appine_hal::net::recvmsg(fd, &mut buf, 0, 0) else {
            break;
        };
        let data = &buf[..m.len.min(buf.len())];
        if let Some(i) = relays
            .iter()
            .position(|r| r.port == id && r.client == m.addr)
        {
            relays[i].last = Instant::now();
            match appine_hal::net::sendmsg(relays[i].fd, data, &[], &[], 0) {
                Ok(_) | Err(EAGAIN) => continue,
                Err(_) => {
                    // The old upstream stopped listening (e.g. ICMP port unreachable after a
                    // rule/container change): close the dead relay and open a fresh one to the
                    // current target.
                    let dead = relays.swap_remove(i);
                    appine_hal::net::close(dead.fd);
                }
            }
        }
        if relays.len() >= max_relays {
            continue;
        }
        // UDP still binds the gateway's address: datagrams the container sends back to
        // the real address must go back through the forwarding socket, and the address
        // mapping has no entry for that direction
        let Ok((rfd, _, _)) = open(target, None) else {
            continue;
        };
        let _ = appine_hal::net::sendmsg(rfd, data, &[], &[], 0);
        relays.push(Relay {
            fd: rfd,
            port: id,
            client: m.addr,
            last: Instant::now(),
        });
    }
}

/// Forwards polled UDP upstream replies back to their original clients, dropping any relay whose
/// upstream socket reports a hard error (e.g. ECONNREFUSED after the target stopped listening).
fn relay_replies(
    relays: &mut Vec<Relay>,
    polled: &[(i32, i16, i16)],
    ports: &HashMap<u64, PortEntry>,
) {
    let mut k = 0;
    let mut buf: Option<Vec<u8>> = None;
    relays.retain_mut(|r| {
        let revents = polled[k].2;
        k += 1;
        if revents == 0 {
            return true;
        }
        let Some(entry) = ports.get(&r.port) else {
            return true;
        };
        let buf = buf.get_or_insert_with(|| vec![0u8; 65536]);
        loop {
            match appine_hal::net::recvmsg(r.fd, buf, 0, 0) {
                Ok(m) => {
                    let _ = appine_hal::net::sendmsg(
                        entry.fd,
                        &buf[..m.len.min(buf.len())],
                        &r.client,
                        &[],
                        0,
                    );
                    r.last = Instant::now();
                }
                Err(EAGAIN) => return true,
                Err(_) => {
                    appine_hal::net::close(r.fd);
                    return false;
                }
            }
        }
    });
}

/// Creates a host socket connecting to `t` (nonblocking; the connection may still be in
/// progress) and returns (fd, connected, bound 127.254.x.y). When `client` is an outside client's
/// IPv4 address and port, first binds a 127.254.x.y address and that port (letting the host choose
/// if the port cannot be bound) and records it; otherwise binds `t.source`.
fn open(t: &Target, client: Option<([u8; 4], u16)>) -> Result<(i32, bool, Option<[u8; 4]>), i32> {
    let fd = appine_hal::net::socket(
        family(&t.addr),
        if t.udp { SOCK_DGRAM } else { SOCK_STREAM },
        0,
    )?;
    let mut outside = None;
    let bound = match client.filter(|_| family(&t.addr) == 2) {
        Some((ip, port)) => {
            let Some(host) = take_outside() else {
                appine_hal::net::close(fd);
                return Err(EAGAIN);
            };
            let at = |p: u16| appine_hal::net::sockaddr(std::net::SocketAddr::from((host, p)));
            let r =
                appine_hal::net::bind(fd, &at(port)).or_else(|_| appine_hal::net::bind(fd, &at(0)));
            if r.is_ok() {
                let hport = appine_hal::net::sockname(fd, false)
                    .ok()
                    .map_or(0, |a| u16::from_be_bytes([a[2], a[3]]));
                record_outside(host, ip, port, hport);
                outside = Some(host);
            }
            r
        }
        None => t
            .source
            .as_ref()
            .map_or(Ok(()), |src| appine_hal::net::bind(fd, src)),
    };
    if let Err(e) = bound {
        appine_hal::net::close(fd);
        return Err(e);
    }
    match appine_hal::net::connect(fd, &t.addr) {
        Ok(()) => Ok((fd, true, outside)),
        Err(EINPROGRESS) => Ok((fd, false, outside)),
        Err(e) => {
            appine_hal::net::close(fd);
            if let Some(a) = outside {
                forget_outside(a);
            }
            Err(e)
        }
    }
}

// ---- Real client address ----

/// 127.254.0.0/16 on the host is kept for connections forwarded in from outside (blocks of new
/// network namespaces never take it).
pub(crate) const OUTSIDE_BLOCK: u8 = 254;

/// Host address bound by a connection forwarded in from outside → (client address, client port,
/// bound host port). One per process: addresses come from a process-wide counter, so they never
/// repeat.
static OUTSIDE: Mutex<Option<Outside>> = Mutex::new(None);

#[derive(Default)]
struct Outside {
    next: u16,
    peers: HashMap<[u8; 4], ([u8; 4], u16, u16)>,
}

/// The IPv4 address and port in an accepted client address: for an IPv4-mapped IPv6 address, the
/// IPv4 part; None for loopback addresses and pure IPv6.
fn outside_client(addr: &[u8]) -> Option<([u8; 4], u16)> {
    const MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    let port = u16::from_be_bytes([*addr.get(2)?, *addr.get(3)?]);
    let ip: [u8; 4] = match family(addr) {
        2 => addr.get(4..8)?.try_into().ok()?,
        10 if addr.get(8..20)? == MAPPED => addr.get(20..24)?.try_into().ok()?,
        _ => return None,
    };
    (ip[0] != 127).then_some((ip, port))
}

/// Gives a connection from outside a 127.254.x.y address (skipping .0.0), or `None` if all
/// 65,535 addresses are currently in use.
fn take_outside() -> Option<[u8; 4]> {
    let mut g = OUTSIDE.lock().unwrap();
    let o = g.get_or_insert_with(Default::default);
    for _ in 0..u16::MAX {
        o.next = o.next.wrapping_add(1);
        if o.next == 0 {
            continue;
        }
        let [a, b] = o.next.to_be_bytes();
        let addr = [127, OUTSIDE_BLOCK, a, b];
        if !o.peers.contains_key(&addr) {
            return Some(addr);
        }
    }
    None
}

fn record_outside(host: [u8; 4], client: [u8; 4], cport: u16, hport: u16) {
    let mut g = OUTSIDE.lock().unwrap();
    g.get_or_insert_with(Default::default)
        .peers
        .insert(host, (client, cport, hport));
}

/// Records a connection forwarded in from outside, in tests ([`outside_peer`]).
#[cfg(test)]
pub(crate) fn record_outside_for_test(host: [u8; 4], client: [u8; 4], cport: u16, hport: u16) {
    record_outside(host, client, cport, hport);
}

/// The client's real address and port, when host address `host` (127.254.x.y) and port `port`
/// belong to a connection forwarded in from outside.
pub(crate) fn outside_peer(host: [u8; 4], port: u16) -> Option<([u8; 4], u16)> {
    let g = OUTSIDE.lock().unwrap();
    let &(ip, cport, hport) = g.as_ref()?.peers.get(&host)?;
    (hport == port).then_some((ip, cport))
}

fn forget_outside(host: [u8; 4]) {
    if let Some(o) = OUTSIDE.lock().unwrap().as_mut() {
        o.peers.remove(&host);
    }
}

fn family(addr: &[u8]) -> i32 {
    i32::from(u16::from_le_bytes([addr[0], addr[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AF_INET: i32 = 2;

    fn loopback(port: u16) -> Vec<u8> {
        appine_hal::net::sockaddr(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn port(fd: i32) -> u16 {
        let a = appine_hal::net::sockname(fd, false).unwrap();
        u16::from_be_bytes([a[2], a[3]])
    }

    /// Waits, blocking, until the fd is ready (used in tests).
    fn wait(fd: i32, ev: i16) {
        let mut f = [(fd, ev, 0)];
        appine_hal::poll(&mut f, Some(Duration::from_secs(5))).unwrap();
        assert_ne!(f[0].2, 0, "timed out");
    }

    /// TCP: an outside connection to the listening socket gets its data to the destination and
    /// the reply back, and both sides end after closing.
    #[test]
    fn tcp_is_forwarded() {
        let server = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        appine_hal::net::listen(server, 8).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        appine_hal::net::listen(held, 8).unwrap();
        let f = Forwarder::default();
        let h = f
            .add(
                held,
                Target {
                    udp: false,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();
        // The "outside" client
        let c = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c, &loopback(port(held)));
        wait(server, POLLIN);
        let (s, _) = appine_hal::net::accept(server).unwrap();
        wait(c, POLLOUT);
        appine_hal::net::sendmsg(c, b"ping", &[], &[], 0).unwrap();
        wait(s, POLLIN);
        let mut buf = [0u8; 16];
        assert_eq!(appine_hal::read(s, &mut buf), Ok(4));
        assert_eq!(&buf[..4], b"ping");
        appine_hal::net::sendmsg(s, b"pong!", &[], &[], 0).unwrap();
        appine_hal::net::close(s);
        wait(c, POLLIN);
        assert_eq!(appine_hal::read(c, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"pong!");
        // The destination closed: the client reads end of file
        wait(c, POLLIN);
        assert_eq!(appine_hal::read(c, &mut buf), Ok(0));
        // No longer forwarded: incoming connections are not accepted by anyone
        drop(h);
        std::thread::sleep(Duration::from_millis(100));
        let c2 = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c2, &loopback(port(held)));
        let mut f2 = [(server, POLLIN, 0)];
        appine_hal::poll(&mut f2, Some(Duration::from_millis(300))).unwrap();
        assert_eq!(f2[0].2, 0);
        for fd in [server, held, c, c2] {
            appine_hal::net::close(fd);
        }
    }

    /// An outside client (not a loopback address): the forwarded connection binds a 127.254.x.y
    /// address and the client's port and records the client's real address; the record is
    /// removed when the connection ends.
    #[test]
    fn outside_clients_keep_their_address() {
        // Use a non-loopback IPv4 address of the host as the outside client; skip the test if
        // there is none
        let Some(ip) = appine_hal::net::interfaces().iter().find_map(|i| {
            i.addrs
                .iter()
                .find(|(f, a, _)| *f == AF_INET && a.len() == 4 && a[0] != 127)
                .map(|(_, a, _)| <[u8; 4]>::try_from(&a[..]).unwrap())
        }) else {
            return;
        };
        let at =
            |ip: [u8; 4], p: u16| appine_hal::net::sockaddr(std::net::SocketAddr::from((ip, p)));
        let server = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        appine_hal::net::listen(server, 8).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held, &at([0; 4], 0)).unwrap();
        appine_hal::net::listen(held, 8).unwrap();
        let f = Forwarder::default();
        let _h = f
            .add(
                held,
                Target {
                    udp: false,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();
        let c = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(c, &at(ip, 0)).unwrap();
        let _ = appine_hal::net::connect(c, &at(ip, port(held)));
        wait(server, POLLIN);
        let (s, peer) = appine_hal::net::accept(server).unwrap();
        let host: [u8; 4] = peer[4..8].try_into().unwrap();
        let hport = u16::from_be_bytes([peer[2], peer[3]]);
        assert_eq!(host[..2], [127, OUTSIDE_BLOCK]);
        // What is bound is the client's port
        assert_eq!(hport, port(c));
        assert_eq!(outside_peer(host, hport), Some((ip, port(c))));
        assert_eq!(outside_peer(host, hport.wrapping_add(1)), None);
        // After both sides close, the record is gone
        appine_hal::net::close(c);
        appine_hal::net::close(s);
        for _ in 0..50 {
            if outside_peer(host, hport).is_none() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(outside_peer(host, hport), None);
        // A connection from a loopback address is not an outside client
        assert_eq!(outside_client(&loopback(4000)), None);
        appine_hal::net::close(server);
        appine_hal::net::close(held);
    }

    /// CPU time (clock ticks) of host thread `tid` of this process, on Linux hosts.
    fn thread_ticks(tid: i32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
        let (_, rest) = stat.rsplit_once(") ")?;
        let f: Vec<&str> = rest.split(' ').collect();
        Some(f[11].parse::<u64>().ok()? + f[12].parse::<u64>().ok()?)
    }

    /// A connection whose client half-closed and then reset is closed toward the destination at
    /// once, and a listening socket that stays readable while accept fails (shut down) is left
    /// out of the poll for a while: neither makes the thread spin.
    #[test]
    fn resets_and_dead_listeners_do_not_spin() {
        let server = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        appine_hal::net::listen(server, 8).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        appine_hal::net::listen(held, 8).unwrap();
        let f = Forwarder::default();
        let _h = f
            .add(
                held,
                Target {
                    udp: false,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();
        let c = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c, &loopback(port(held)));
        wait(server, POLLIN);
        let (s, _) = appine_hal::net::accept(server).unwrap();
        wait(c, POLLOUT);
        appine_hal::net::sendmsg(c, b"x", &[], &[], 0).unwrap();
        appine_hal::net::shutdown(c, SHUT_WR).unwrap();
        let mut buf = [0u8; 16];
        wait(s, POLLIN);
        assert_eq!(appine_hal::read(s, &mut buf), Ok(1));
        wait(s, POLLIN);
        assert_eq!(appine_hal::read(s, &mut buf), Ok(0));
        let tid = *f.shared.tid.get().expect("forwarding thread started");
        let idle = |what: &str| {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(before) = thread_ticks(tid) {
                std::thread::sleep(Duration::from_millis(500));
                let used = thread_ticks(tid).unwrap() - before;
                assert!(
                    used < 10,
                    "{what}: the forwarding thread used {used} ticks in 0.5 s"
                );
            }
        };
        // The client resets (SO_LINGER with a zero timeout) after its half-close
        let linger = [1i32.to_le_bytes(), 0i32.to_le_bytes()].concat();
        appine_hal::net::setsockopt(c, SOL_SOCKET, 13, &linger).unwrap();
        appine_hal::net::close(c);
        idle("reset");
        // A listener shut down for reading polls readable for good while accept fails
        appine_hal::net::shutdown(held, 0).unwrap();
        idle("shut-down listener");
        for fd in [server, held, s] {
            appine_hal::net::close(fd);
        }
    }

    /// UDP: datagrams go to the destination, and replies go back to the source from the
    /// listening socket.
    #[test]
    fn udp_is_forwarded() {
        let server = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        let f = Forwarder::default();
        let _h = f
            .add(
                held,
                Target {
                    udp: true,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();
        let c = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::sendmsg(c, b"query", &loopback(port(held)), &[], 0).unwrap();
        wait(server, POLLIN);
        let mut buf = [0u8; 64];
        let m = appine_hal::net::recvmsg(server, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..m.len], b"query");
        appine_hal::net::sendmsg(server, b"answer", &m.addr, &[], 0).unwrap();
        wait(c, POLLIN);
        let r = appine_hal::net::recvmsg(c, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..r.len], b"answer");
        // The reply comes from the port the client sent to
        assert_eq!(r.addr[2..8], loopback(port(held))[2..8]);
        for fd in [server, held, c] {
            appine_hal::net::close(fd);
        }
    }

    /// Updating a forwarded UDP port's target in place (rule change or pause/resume) preserves
    /// active UDP relays so in-flight replies still reach the client, while new clients follow
    /// the updated target and pausing stops stealing new datagrams from the guest socket.
    #[test]
    fn udp_relays_survive_rule_updates_and_pause() {
        let srv1 = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(srv1, &loopback(0)).unwrap();
        let srv2 = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(srv2, &loopback(0)).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        let f = Forwarder::default();
        let mut h = f
            .add(
                held,
                Target {
                    udp: true,
                    addr: loopback(port(srv1)),
                    source: None,
                },
            )
            .unwrap();
        let c1 = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        let c2 = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        let dst = loopback(port(held));
        let mut buf = [0u8; 64];

        // c1 starts a UDP relay to srv1, then the rule changes to srv2 before srv1 replies.
        appine_hal::net::sendmsg(c1, b"q1", &dst, &[], 0).unwrap();
        wait(srv1, POLLIN);
        let m1 = appine_hal::net::recvmsg(srv1, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..m1.len], b"q1");

        h.update(Some(Target {
            udp: true,
            addr: loopback(port(srv2)),
            source: None,
        }));
        std::thread::sleep(Duration::from_millis(50));

        // srv1's reply to c1 still flows back through the preserved relay.
        appine_hal::net::sendmsg(srv1, b"a1", &m1.addr, &[], 0).unwrap();
        wait(c1, POLLIN);
        let r1 = appine_hal::net::recvmsg(c1, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..r1.len], b"a1");

        // A new client c2 routes to the updated target srv2.
        appine_hal::net::sendmsg(c2, b"q2", &dst, &[], 0).unwrap();
        wait(srv2, POLLIN);
        let m2 = appine_hal::net::recvmsg(srv2, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..m2.len], b"q2");

        // Pausing (rule removed while socket stays open) lets in-flight reply from srv2 reach c2,
        // while new datagrams on `held` are NOT stolen by the forwarder and stay readable on `held`.
        h.update(None);
        std::thread::sleep(Duration::from_millis(50));
        appine_hal::net::sendmsg(srv2, b"a2", &m2.addr, &[], 0).unwrap();
        wait(c2, POLLIN);
        let r2 = appine_hal::net::recvmsg(c2, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..r2.len], b"a2");

        appine_hal::net::sendmsg(c2, b"direct", &dst, &[], 0).unwrap();
        wait(held, POLLIN);
        let direct = appine_hal::net::recvmsg(held, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..direct.len], b"direct");

        // Dropping the handle (socket closed) tears down all relays cleanly.
        drop(h);
        std::thread::sleep(Duration::from_millis(50));
        for fd in [srv1, srv2, held, c1, c2] {
            appine_hal::net::close(fd);
        }
    }

    /// TCP connection cap: once `max_conns` connections are active, further incoming connections
    /// wait without spinning the forwarding thread until a slot frees up.
    #[test]
    fn tcp_connection_cap_enforced_without_spinning() {
        let server = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        appine_hal::net::listen(server, 16).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        appine_hal::net::listen(held, 16).unwrap();
        let f = Forwarder::with_limits(Limits {
            max_conns: 2,
            max_relays: 2,
            connect_timeout: Duration::from_secs(5),
            udp_idle: UDP_IDLE,
        });
        let _h = f
            .add(
                held,
                Target {
                    udp: false,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();

        let connect_pair = || {
            let c = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
            let _ = appine_hal::net::connect(c, &loopback(port(held)));
            wait(server, POLLIN);
            let (s, _) = appine_hal::net::accept(server).unwrap();
            wait(c, POLLOUT);
            (c, s)
        };
        let (c1, s1) = connect_pair();
        let (c2, s2) = connect_pair();

        // A third client connects while at cap: it must not be forwarded yet and must not cause
        // the forwarding thread to spin on the readable listener.
        let c3 = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c3, &loopback(port(held)));
        let mut p = [(server, POLLIN, 0)];
        appine_hal::poll(&mut p, Some(Duration::from_millis(200))).unwrap();
        assert_eq!(p[0].2, 0, "cap exceeded: third connection was forwarded");

        let tid = *f.shared.tid.get().expect("forwarding thread started");
        if let Some(before) = thread_ticks(tid) {
            std::thread::sleep(Duration::from_millis(400));
            let used = thread_ticks(tid).unwrap() - before;
            assert!(
                used < 10,
                "tcp cap spin: forwarding thread used {used} ticks in 0.4 s"
            );
        }

        // Closing one active connection frees a slot and lets the third connection through.
        appine_hal::net::close(c1);
        appine_hal::net::close(s1);
        wait(server, POLLIN);
        let (s3, _) = appine_hal::net::accept(server).unwrap();
        wait(c3, POLLOUT);
        appine_hal::net::sendmsg(c3, b"third", &[], &[], 0).unwrap();
        wait(s3, POLLIN);
        let mut buf = [0u8; 16];
        assert_eq!(appine_hal::read(s3, &mut buf), Ok(5));
        assert_eq!(&buf[..5], b"third");

        for fd in [server, held, c2, s2, c3, s3] {
            appine_hal::net::close(fd);
        }
    }

    /// UDP relay cap: once `max_relays` sources are active, datagrams from additional sources are
    /// dropped cleanly while existing relays keep working, and new sources work after idle expiry.
    #[test]
    fn udp_relay_cap_drops_excess_clients_gracefully() {
        let server = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        let held = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
        appine_hal::net::bind(held, &loopback(0)).unwrap();
        let f = Forwarder::with_limits(Limits {
            max_conns: 2,
            max_relays: 2,
            connect_timeout: Duration::from_secs(5),
            udp_idle: Duration::from_millis(250),
        });
        let _h = f
            .add(
                held,
                Target {
                    udp: true,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();

        let mk_client = || {
            let c = appine_hal::net::socket(AF_INET, SOCK_DGRAM, 0).unwrap();
            appine_hal::net::bind(c, &loopback(0)).unwrap();
            c
        };
        let (c1, c2, c3) = (mk_client(), mk_client(), mk_client());
        let dst = loopback(port(held));
        let mut buf = [0u8; 64];

        for (c, msg, rep) in [
            (c1, b"one".as_slice(), b"r1".as_slice()),
            (c2, b"two", b"r2"),
        ] {
            appine_hal::net::sendmsg(c, msg, &dst, &[], 0).unwrap();
            wait(server, POLLIN);
            let m = appine_hal::net::recvmsg(server, &mut buf, 0, 0).unwrap();
            assert_eq!(&buf[..m.len], msg);
            appine_hal::net::sendmsg(server, rep, &m.addr, &[], 0).unwrap();
            wait(c, POLLIN);
            let r = appine_hal::net::recvmsg(c, &mut buf, 0, 0).unwrap();
            assert_eq!(&buf[..r.len], rep);
        }

        // At cap: datagrams from c3 are dropped without leaking fds or stalling c1.
        appine_hal::net::sendmsg(c3, b"drop1", &dst, &[], 0).unwrap();
        appine_hal::net::sendmsg(c3, b"drop2", &dst, &[], 0).unwrap();
        let mut p = [(server, POLLIN, 0)];
        appine_hal::poll(&mut p, Some(Duration::from_millis(120))).unwrap();
        assert_eq!(p[0].2, 0, "excess UDP client bypassed relay cap");

        // Existing relay c1 continues working while at cap.
        appine_hal::net::sendmsg(c1, b"keep", &dst, &[], 0).unwrap();
        wait(server, POLLIN);
        let m = appine_hal::net::recvmsg(server, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..m.len], b"keep");

        // Once relays expire after udp_idle, c3 can open a relay and exchange datagrams.
        std::thread::sleep(Duration::from_millis(350));
        appine_hal::net::sendmsg(c3, b"three", &dst, &[], 0).unwrap();
        wait(server, POLLIN);
        let m = appine_hal::net::recvmsg(server, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..m.len], b"three");
        appine_hal::net::sendmsg(server, b"r3", &m.addr, &[], 0).unwrap();
        wait(c3, POLLIN);
        let r = appine_hal::net::recvmsg(c3, &mut buf, 0, 0).unwrap();
        assert_eq!(&buf[..r.len], b"r3");

        for fd in [server, held, c1, c2, c3] {
            appine_hal::net::close(fd);
        }
    }

    /// Connect timeout: a nonblocking outbound connect that stalls in progress is closed after
    /// `connect_timeout` without spinning (even if the client already sent data), freeing its slot.
    #[test]
    fn stalled_connect_expires_on_connect_timeout() {
        // Create a loopback listener with backlog 1 and saturate its accept queue without
        // accepting so subsequent nonblocking connects stay in EINPROGRESS (Linux drops SYNs when
        // the accept queue is full).
        let blackhole = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(blackhole, &loopback(0)).unwrap();
        appine_hal::net::listen(blackhole, 1).unwrap();
        let bh_addr = loopback(port(blackhole));
        let mut fillers = Vec::new();
        let mut saturated = false;
        for _ in 0..64 {
            let s = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
            match appine_hal::net::connect(s, &bh_addr) {
                Ok(()) => fillers.push(s),
                Err(EINPROGRESS) => {
                    let mut p = [(s, POLLOUT, 0)];
                    appine_hal::poll(&mut p, Some(Duration::from_millis(30))).unwrap();
                    if p[0].2 == 0 {
                        appine_hal::net::close(s);
                        saturated = true;
                        break;
                    }
                    fillers.push(s);
                }
                Err(_) => {
                    appine_hal::net::close(s);
                    break;
                }
            }
        }
        assert!(
            saturated,
            "failed to saturate loopback listen backlog to simulate stalled connect"
        );

        let held_bh = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held_bh, &loopback(0)).unwrap();
        appine_hal::net::listen(held_bh, 8).unwrap();

        let server = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(server, &loopback(0)).unwrap();
        appine_hal::net::listen(server, 8).unwrap();
        let held_ok = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        appine_hal::net::bind(held_ok, &loopback(0)).unwrap();
        appine_hal::net::listen(held_ok, 8).unwrap();

        let timeout = Duration::from_millis(250);
        let f = Forwarder::with_limits(Limits {
            max_conns: 1,
            max_relays: 1,
            connect_timeout: timeout,
            udp_idle: UDP_IDLE,
        });
        let _h_bh = f
            .add(
                held_bh,
                Target {
                    udp: false,
                    addr: bh_addr,
                    source: None,
                },
            )
            .unwrap();
        let _h_ok = f
            .add(
                held_ok,
                Target {
                    udp: false,
                    addr: loopback(port(server)),
                    source: None,
                },
            )
            .unwrap();

        // Connect to the stalled target and send data immediately to verify client POLLIN does not
        // busy-loop while the outbound connect is still pending.
        let c = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c, &loopback(port(held_bh)));
        wait(c, POLLOUT);
        let started = Instant::now();
        appine_hal::net::sendmsg(c, b"waiting", &[], &[], 0).unwrap();
        // Wait for the thread to record its tid, then snapshot CPU ticks while waiting for expiry.
        let tid = loop {
            if let Some(&t) = f.shared.tid.get() {
                break t;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let ticks_before = thread_ticks(tid);

        // The forwarder should close `c` when `connect_timeout` elapses.
        let mut p = [(c, POLLIN, 0)];
        appine_hal::poll(&mut p, Some(Duration::from_secs(2))).unwrap();
        assert_ne!(p[0].2, 0, "stalled outbound connect did not time out");
        let elapsed = started.elapsed();
        let mut buf = [0u8; 16];
        let r = appine_hal::read(c, &mut buf);
        assert!(
            matches!(r, Ok(0) | Err(ECONNRESET)),
            "expected EOF/reset after connect timeout, got {r:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(150) && elapsed < Duration::from_secs(2),
            "unexpected connect timeout duration: {elapsed:?}"
        );
        if let Some(before) = ticks_before {
            let used = thread_ticks(tid).unwrap() - before;
            assert!(
                used < 10,
                "stalled connect spin: forwarding thread used {used} ticks"
            );
        }

        // The single connection slot (max_conns = 1) must now be free for a healthy target.
        let c2 = appine_hal::net::socket(AF_INET, SOCK_STREAM, 0).unwrap();
        let _ = appine_hal::net::connect(c2, &loopback(port(held_ok)));
        wait(server, POLLIN);
        let (s2, _) = appine_hal::net::accept(server).unwrap();
        wait(c2, POLLOUT);
        appine_hal::net::sendmsg(c2, b"ok", &[], &[], 0).unwrap();
        wait(s2, POLLIN);
        assert_eq!(appine_hal::read(s2, &mut buf), Ok(2));
        assert_eq!(&buf[..2], b"ok");

        for fd in [blackhole, held_bh, server, held_ok, c, c2, s2] {
            appine_hal::net::close(fd);
        }
        for fd in fillers {
            appine_hal::net::close(fd);
        }
    }
}
