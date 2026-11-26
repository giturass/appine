//! AF_UNIX socket syscalls (the data structures are in [`crate::unix`]).
//!
//! [`super::net`] passes calls here when it finds the socket is AF_UNIX. Blocking operations use
//! [`Cx::wait_objects`] to wait for other threads to change a channel's state (they all request a
//! wake of that channel, see [`UnixSocket::wake_objects`]); they can be interrupted by signals and
//! time out according to `SO_RCVTIMEO`/`SO_SNDTIMEO`.

use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use super::fs::{AT_FDCWD, create_parent_at, lookup_at};
use super::net::{Message, SocketRef, epipe, timeval};
use crate::cell::RefCell;
use crate::cred::cap;
use crate::errno::Errno;
use crate::fd::FileRef;
use crate::kernel::{Cx, Kernel, request_wake_object, wake};
use crate::net::{AF_UNIX, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, Socket};
use crate::unix::{
    ChannelRef, DGRAM_MAX_LEN, Link, Name, Packet, Received, SOCK_SEQPACKET, SOCKADDR_UN_LEN,
    SenderState, SendingRights, Ucred, UnixSocket, packet_truesize, unnamed,
};
use crate::vfs::Node;
use crate::vfs::store::mode;

const SOL_SOCKET: i32 = 1;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_PASSCRED: i32 = 16;
const SO_PEERCRED: i32 = 17;
const SO_SNDLOWAT: i32 = 19;
const SO_RCVTIMEO: i32 = 20;
const SO_SNDTIMEO: i32 = 21;
const SO_ACCEPTCONN: i32 = 30;
const SO_PROTOCOL: i32 = 38;
const SO_DOMAIN: i32 = 39;

const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
/// The most open files one message passes (Linux's `SCM_MAX_FD`).
const SCM_MAX_FD: usize = 253;

const MSG_PEEK: u32 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_TRUNC: u32 = 0x20;
const MSG_DONTWAIT: u32 = 0x40;
const MSG_WAITALL: u32 = 0x100;

/// The length of a `cmsghdr` (64-bit).
const CMSG_HDR: usize = 16;
/// The upper limit of the listen backlog (`SOMAXCONN`).
const SOMAXCONN: usize = 4096;

// ---- Creating sockets ----

/// Creates an AF_UNIX socket.
pub(super) fn socket(ty: i32, protocol: i32) -> Result<Socket, Errno> {
    Ok(Socket::Unix(UnixSocket::new(socket_type(ty, protocol)?)))
}

/// socketpair(2): two sockets connected to each other.
pub(super) fn pair(cx: &Cx<'_>, ty: i32, protocol: i32) -> Result<(Socket, Socket), Errno> {
    let (mut a, mut b) = UnixSocket::pair(socket_type(ty, protocol)?, cx.ucred());
    let qlen = max_dgram_qlen(cx);
    let cred = cx.cred();
    for s in [&mut a, &mut b] {
        s.set_max_qlen(qlen);
        s.uid = cred.fsuid;
        s.gid = cred.fsgid;
    }
    let net = cx.task.ns.borrow().net.clone();
    if net.host_net.is_some() {
        a.net = Some(net.clone());
        b.net = Some(net);
    }
    Ok((Socket::Unix(a), Socket::Unix(b)))
}

/// `net.unix.max_dgram_qlen` of the caller's network namespace, which a datagram socket takes when
/// created (Linux's `unix_create1`).
pub(super) fn max_dgram_qlen(cx: &Cx<'_>) -> i64 {
    let net = cx.task.ns.borrow().net.clone();
    let conf = &net.devs.borrow().conf;
    crate::netconf::sysctl_read(conf, "unix/max_dgram_qlen")
        .trim()
        .parse()
        .unwrap_or(crate::unix::MAX_DGRAM_QLEN as i64)
}

/// Checks the socket type and protocol and returns the actual type.
fn socket_type(ty: i32, protocol: i32) -> Result<i32, Errno> {
    if protocol != 0 && protocol != AF_UNIX {
        return Err(Errno::EPROTONOSUPPORT);
    }
    match ty {
        SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET => Ok(ty),
        // As on Linux, SOCK_RAW is treated as datagram
        SOCK_RAW => Ok(SOCK_DGRAM),
        _ => Err(Errno::ESOCKTNOSUPPORT),
    }
}

// ---- Names and connections ----

pub(super) fn bind(cx: &mut Cx<'_>, sock: &SocketRef, addr: &[u8]) -> Result<(), Errno> {
    if with(sock, |u| !u.addr.borrow().is_empty()) {
        return Err(Errno::EINVAL);
    }
    bind_addr(cx, sock, parse(addr)?)
}

fn bind_addr(cx: &mut Cx<'_>, sock: &SocketRef, addr: Addr<'_>) -> Result<(), Errno> {
    let mut bound = unnamed();
    let (net, ty) = with(sock, |u| (u.net_id(), u.ty));
    match addr {
        Addr::Unnamed => {
            let path = cx.k().unix.autobind(net, ty, sock).ok_or(Errno::ENOSPC)?;
            bound.extend_from_slice(&path);
        }
        Addr::Abstract(p) => {
            if !cx
                .k()
                .unix
                .insert(Name::Abstract(net, ty, p.to_vec()), sock)
            {
                return Err(Errno::EADDRINUSE);
            }
            bound.extend_from_slice(p);
        }
        Addr::Path(p) => {
            // As on Linux, create a socket node in the file system; fail when it already
            // exists. When the path is / or ends with ., it refers to an existing directory
            let key = if let Some(key) = super::fuse::bind_socket(cx, p, sock)? {
                key
            } else {
                let in_use = |e: Errno| {
                    if e == Errno::EEXIST {
                        Errno::EADDRINUSE
                    } else {
                        e
                    }
                };
                let (mnt, dir, name, ovl) = create_parent_at(cx, AT_FDCWD, p).map_err(in_use)?;
                if name == b"." || name == b".." {
                    return Err(Errno::EADDRINUSE);
                }
                let vfs = cx.vfs()?;
                super::fs::reject_trailing_slash(&vfs, (mnt, dir), name, p).map_err(in_use)?;
                let cred = cx.cred();
                let dir_st =
                    super::fs::may_create(&vfs, &cred, (mnt, dir), name).map_err(in_use)?;
                let (uid, gid, perm) = cred.new_owner(&dir_st, 0o777, cx.umask(), false);
                let tmpfs = super::fs::tmpfs_reserve(&vfs, (mnt, dir), 0)?;
                let ino = super::fs::create_in(
                    &vfs,
                    (mnt, dir),
                    name,
                    dir_st.default_acl.as_deref(),
                    || {
                        vfs.store()
                            .mknod(dir, name, mode::S_IFSOCK | perm, 0, uid, gid)
                    },
                    |&ino| ino,
                )
                .map_err(in_use)?;
                super::fs::tmpfs_created(&vfs, tmpfs, 0);
                super::fs::created_events(cx.kr(), (dir, ovl), name, 0);
                ino
            };
            cx.k().unix.insert(Name::Path(key), sock);
            bound.extend_from_slice(p);
            bound.push(0);
        }
    }
    with(sock, |u| *u.addr.borrow_mut() = bound);
    Ok(())
}

/// Linux assigns a reply address before looking up the peer, even if that lookup fails.
fn autobind_passcred(cx: &mut Cx<'_>, sock: &SocketRef, peer: Option<&[u8]>) -> Result<(), Errno> {
    let needs_name = with(sock, |u| {
        u.addr.borrow().is_empty() && u.receive_queue().borrow().passcred
    });
    if !needs_name {
        return Ok(());
    }
    if let Some(peer) = peer
        && matches!(parse(peer)?, Addr::Unnamed)
    {
        return Err(Errno::EINVAL);
    }
    bind_addr(cx, sock, Addr::Unnamed)
}

pub(super) fn listen(u: &mut UnixSocket, backlog: i32, cred: Ucred) -> Result<(), Errno> {
    let backlog = usize::try_from(backlog).map_or(SOMAXCONN, |b| b.min(SOMAXCONN));
    if u.ty == SOCK_DGRAM {
        return Err(Errno::EOPNOTSUPP);
    }
    if u.addr.borrow().is_empty() {
        return Err(Errno::EINVAL);
    }
    match &mut u.link {
        Link::None => {
            u.link = Link::Listening {
                backlog,
                pending: Default::default(),
                cred,
            };
            Ok(())
        }
        // unix_listen: every listen records the credentials again, and a larger backlog wakes the
        // connectors waiting for room
        Link::Listening {
            backlog: b,
            cred: c,
            ..
        } => {
            if backlog > *b {
                request_wake_object(wake::of(&u.rx));
            }
            *b = backlog;
            *c = cred;
            Ok(())
        }
        _ => Err(Errno::EINVAL),
    }
}

pub(super) fn accept(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
) -> Result<(SocketRef, Vec<u8>), Errno> {
    let (timeout, queue) = with(sock, |u| (u.rcvtimeo, u.rx.clone()));
    let deadline = deadline(timeout);
    loop {
        let new = with(sock, |u| match &mut u.link {
            Link::Listening { pending, .. } => Ok(pending.pop_front()),
            _ => Err(Errno::EINVAL),
        })?;
        if let Some(new) = new {
            let passcred = with(sock, |u| u.receive_queue().borrow().passcred);
            let cred = cx.cred();
            with(&new, |u| {
                u.embryo = false;
                u.uid = cred.fsuid;
                u.gid = cred.fsgid;
                u.receive_queue().borrow_mut().passcred = passcred;
            });
            cx.k().unix.remove_embryo(&new);
            // Connects waiting for room in the backlog can go on now
            request_wake_object(wake::of(&queue));
            let peer = with(&new, |u| u.peer_name()).unwrap_or_else(unnamed);
            return Ok((new, peer));
        }
        block(cx, nonblock, deadline, &queue)?;
    }
}

pub(super) fn connect(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    addr: &[u8],
) -> Result<(), Errno> {
    let (ty, timeout) = with(sock, |u| (u.ty, u.sndtimeo));
    if ty == SOCK_DGRAM && addr.starts_with(&[0, 0]) {
        // AF_UNSPEC disconnects without choosing a local name.
        relink_dgram(cx, sock, Link::None);
        return Ok(());
    }
    autobind_passcred(cx, sock, Some(addr))?;
    if ty == SOCK_DGRAM {
        return connect_dgram(cx, sock, addr);
    }
    let cred = cx.ucred();
    let deadline = deadline(timeout);
    loop {
        with(sock, |u| match u.link {
            Link::None => Ok(()),
            Link::Listening { .. } => Err(Errno::EINVAL),
            _ => Err(Errno::EISCONN),
        })?;
        let target = find(cx, sock, addr)?;
        if Rc::ptr_eq(&target, sock) {
            return Err(Errno::ECONNREFUSED);
        }
        let queue = {
            let mut t = target.borrow_mut();
            let Socket::Unix(server) = &mut *t else {
                return Err(Errno::ECONNREFUSED);
            };
            if server.ty != ty {
                return Err(Errno::EPROTOTYPE);
            }
            let Link::Listening {
                backlog,
                pending,
                cred: server_cred,
            } = &mut server.link
            else {
                return Err(Errno::ECONNREFUSED);
            };
            // As on Linux, at most backlog + 1 connections wait for accept
            if pending.len() <= *backlog {
                let (end, own) = with(sock, |u| {
                    (
                        u.connect_stream(&server.addr, *server_cred, cred),
                        wake::of(&u.rx),
                    )
                });
                let embryo = Rc::new(RefCell::new(Socket::Unix(end)));
                pending.push_back(embryo.clone());
                server.connections += 1;
                request_wake_object(wake::of(&server.rx));
                // Connected: threads polling this socket registered its own receive queue
                request_wake_object(own);
                drop(t);
                cx.k().unix.add_embryo(&embryo);
                return Ok(());
            }
            server.rx.clone()
        };
        block(cx, nonblock, deadline, &queue)?;
    }
}

fn connect_dgram(cx: &mut Cx<'_>, sock: &SocketRef, addr: &[u8]) -> Result<(), Errno> {
    let target = find(cx, sock, addr)?;
    let own_rx = with(sock, |u| Rc::downgrade(&u.rx));
    let link = match &*target.borrow() {
        // unix_may_send: a peer connected to another socket takes nothing from this one
        Socket::Unix(p) if p.ty == SOCK_DGRAM => match &p.link {
            Link::Dgram { tx, .. } if !Weak::ptr_eq(tx, &own_rx) => return Err(Errno::EPERM),
            _ => Link::Dgram {
                tx: Rc::downgrade(&p.rx),
                peer_addr: p.addr.clone(),
            },
        },
        Socket::Unix(_) => return Err(Errno::EPROTOTYPE),
        _ => return Err(Errno::ECONNREFUSED),
    };
    relink_dgram(cx, sock, link);
    Ok(())
}

/// Replaces a datagram socket's link and releases any purged `SCM_RIGHTS` files after borrows end.
fn relink_dgram(cx: &mut Cx<'_>, sock: &SocketRef, link: Link) {
    let dropped = with(sock, |u| u.set_dgram_link(link));
    if !dropped.is_empty() {
        crate::unix::released(cx.k(), dropped);
    }
}

// ---- Sending and receiving ----

pub(super) fn send(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    data: &[u8],
    addr: &[u8],
    control: &[u8],
    flags: u32,
) -> Result<usize, Errno> {
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let (files, declared) = rights(cx, control)?;
    let mut files = SendingRights::track(cx.k(), files);
    let (ty, timeout) = with(sock, |u| (u.ty, u.sndtimeo));
    let deadline = deadline(timeout);
    if ty == SOCK_DGRAM {
        return send_dgram(cx, sock, nonblock, deadline, data, addr, files, declared);
    }
    if ty == SOCK_SEQPACKET && with(sock, |u| matches!(u.link, Link::Stream { .. })) {
        autobind_passcred(cx, sock, None)?;
    }
    let outq = with(sock, |u| u.outq.clone());
    // A stream socket takes no destination (unix_stream_sendmsg); seqpacket ignores it
    if ty == SOCK_STREAM && !addr.is_empty() {
        let connected = with(sock, |u| matches!(u.link, Link::Stream { .. }));
        return Err(if connected {
            Errno::EISCONN
        } else {
            Errno::EOPNOTSUPP
        });
    }
    let mut done = 0;
    loop {
        let (tx, passcred) = with(sock, |u| match &u.link {
            Link::Stream { rx, tx, .. } => Ok((tx.clone(), rx.borrow().passcred)),
            _ => Err(Errno::ENOTCONN),
        })?;
        {
            let mut c = tx.borrow_mut();
            if c.eof || c.closed {
                drop(c);
                return if done > 0 {
                    Ok(done)
                } else if ty == SOCK_SEQPACKET {
                    // Linux's unix_seqpacket_sendmsg delegates to unix_dgram_sendmsg, which
                    // returns EPIPE without raising SIGPIPE.
                    Err(Errno::EPIPE)
                } else {
                    Err(epipe(cx, flags))
                };
            }
            let cred = packet_cred(cx, declared, passcred || c.passcred);
            if ty == SOCK_SEQPACKET {
                if data.len() > DGRAM_MAX_LEN {
                    return Err(Errno::EMSGSIZE);
                }
                if c.has_packet_room() {
                    c.push(packet(cx.k(), &tx, data, files, cred, &outq));
                    return Ok(data.len());
                }
            } else {
                if data.is_empty() && files.is_none() {
                    return Ok(0);
                }
                // A stream socket may queue only part of it; open files go with the first part.
                // Even a zero-byte send carrying SCM_RIGHTS must wait when the channel is full.
                let n = c.space().min(data.len() - done);
                if n > 0
                    || (data.is_empty() && c.space() > 0 && (c.bytes > 0 || c.has_packet_room()))
                {
                    c.push(packet(
                        cx.k(),
                        &tx,
                        &data[done..done + n],
                        files.take(),
                        cred,
                        &outq,
                    ));
                    done += n;
                    if done == data.len() {
                        return Ok(done);
                    }
                    continue;
                }
            }
        }
        if let Err(e) = block(cx, nonblock, deadline, &tx) {
            return if done > 0 { Ok(done) } else { Err(e) };
        }
    }
}

/// Parses sendmsg's control messages, taking out the open files `SCM_RIGHTS` passes and the
/// credentials `SCM_CREDENTIALS` declares (kernel IDs, global pid). Non-`SOL_SOCKET` control
/// messages are skipped after length validation (Linux's `__scm_send`).
fn rights(cx: &Cx<'_>, control: &[u8]) -> Result<(Vec<FileRef>, Option<Ucred>), Errno> {
    let mut files = Vec::new();
    let mut declared = None;
    let mut off = 0;
    while off + CMSG_HDR <= control.len() {
        let h = &control[off..];
        let len = u64::from_le_bytes(h[..8].try_into().unwrap()) as usize;
        let level = i32::from_le_bytes(h[8..12].try_into().unwrap());
        let ty = i32::from_le_bytes(h[12..16].try_into().unwrap());
        if len < CMSG_HDR || len > h.len() {
            return Err(Errno::EINVAL);
        }
        if level != SOL_SOCKET {
            off += len.next_multiple_of(8);
            continue;
        }
        match ty {
            SCM_RIGHTS => {
                let n = (len - CMSG_HDR) / 4;
                if files.len() + n > SCM_MAX_FD {
                    return Err(Errno::EINVAL);
                }
                for fd in h[CMSG_HDR..CMSG_HDR + n * 4].chunks_exact(4) {
                    files.push(cx.fds().get(i32::from_le_bytes(fd.try_into().unwrap()))?);
                }
            }
            SCM_CREDENTIALS => {
                if len != CMSG_HDR + 12 {
                    return Err(Errno::EINVAL);
                }
                let word = |i: usize| {
                    u32::from_le_bytes(
                        h[CMSG_HDR + i * 4..CMSG_HDR + i * 4 + 4]
                            .try_into()
                            .unwrap(),
                    )
                };
                declared = Some(check_creds(cx, word(0) as i32, word(1), word(2))?);
            }
            _ => return Err(Errno::EINVAL),
        }
        off += len.next_multiple_of(8);
    }
    Ok((files, declared))
}

/// The credentials the sender declares in `SCM_CREDENTIALS` (Linux's `scm_check_creds` and
/// `__scm_send`): the IDs must have a mapping in the sender's own namespace (EINVAL); the pid must
/// be the sender's own, or the sender must have CAP_SYS_ADMIN over the owner of its pid namespace;
/// the user ID must be one of its real, effective and saved ones, or it must have CAP_SETUID, and
/// likewise for the group ID (CAP_SETGID), otherwise EPERM; a pid that does not exist is ESRCH.
fn check_creds(cx: &Cx<'_>, pid: i32, uid: u32, gid: u32) -> Result<Ucred, Errno> {
    let c = cx.cred();
    let (Some(kuid), Some(kgid)) = (c.uid_in(uid), c.gid_in(gid)) else {
        return Err(Errno::EINVAL);
    };
    let pid_ok = pid == cx.pid_out(cx.tgid()) || c.ns_capable(&cx.pid_ns().owner, cap::SYS_ADMIN);
    let uid_ok = [c.ruid, c.euid, c.suid].contains(&kuid) || c.capable_here(cap::SETUID);
    let gid_ok = [c.rgid, c.egid, c.sgid].contains(&kgid) || c.capable_here(cap::SETGID);
    if !(pid_ok && uid_ok && gid_ok) {
        return Err(Errno::EPERM);
    }
    let global = cx.pid_in(pid);
    if pid <= 0 || !cx.kr().tasks.contains_key(&global) {
        return Err(Errno::ESRCH);
    }
    Ok(Ucred::of(global, kuid, kgid))
}

#[allow(clippy::too_many_arguments)]
fn send_dgram(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    deadline: Option<Instant>,
    data: &[u8],
    addr: &[u8],
    files: Option<Rc<SendingRights>>,
    declared: Option<Ucred>,
) -> Result<usize, Errno> {
    let destination = (!addr.is_empty()).then_some(addr);
    if destination.is_some() || with(sock, |u| matches!(u.link, Link::Dgram { .. })) {
        autobind_passcred(cx, sock, destination)?;
    }
    let (own_rx, outq, connected, shut_wr) = with(sock, |u| {
        let connected = match &u.link {
            Link::Dgram { tx, .. } => Some(tx.clone()),
            _ => None,
        };
        (Rc::downgrade(&u.rx), u.outq.clone(), connected, u.shut_wr)
    });
    // Datagram sends never raise SIGPIPE (only unix_stream_sendmsg sends it)
    if shut_wr {
        return Err(Errno::EPIPE);
    }
    let rx: ChannelRef = if let Some(tx) = connected.as_ref().filter(|_| addr.is_empty()) {
        let Some(rx) = tx.upgrade() else {
            return Err(disconnect_dead_dgram(cx, sock, tx));
        };
        // unix_may_send: even for a previously connected peer, if it has since connected to a
        // third socket it rejects datagrams from this one
        if !rx.borrow().may_receive_from(&own_rx) {
            return Err(Errno::EPERM);
        }
        rx
    } else if addr.is_empty() {
        return Err(Errno::ENOTCONN);
    } else {
        let target = find(cx, sock, addr)?;
        let t = target.borrow();
        let Socket::Unix(p) = &*t else {
            return Err(Errno::ECONNREFUSED);
        };
        if p.ty != SOCK_DGRAM {
            return Err(Errno::EPROTOTYPE);
        }
        // When the peer is connected to another socket it receives only datagrams from that socket
        if let Link::Dgram { tx, .. } = &p.link
            && !Weak::ptr_eq(tx, &own_rx)
        {
            return Err(Errno::EPERM);
        }
        p.rx.clone()
    };
    if data.len() > DGRAM_MAX_LEN {
        return Err(Errno::EMSGSIZE);
    }
    loop {
        // A datagram socket may be sending to itself.
        let passcred = with(sock, |u| u.rx.borrow().passcred);
        {
            let mut c = rx.borrow_mut();
            if c.closed {
                drop(c);
                return Err(match connected.as_ref().filter(|_| addr.is_empty()) {
                    Some(tx) => disconnect_dead_dgram(cx, sock, tx),
                    None => Errno::ECONNREFUSED,
                });
            }
            // The receiver has shut down reading (RCV_SHUTDOWN): EPIPE, without SIGPIPE
            if c.eof {
                return Err(Errno::EPIPE);
            }
            // Room in the peer's queue (truesize budget) and, unless the receiver is connected
            // back to this socket, below max_dgram_qlen (unix_dgram_sendmsg's unix_recvq_full wait)
            if c.has_packet_room() && !c.holds_back(&own_rx) {
                let cred = packet_cred(cx, declared, passcred || c.passcred);
                c.push(packet(cx.k(), &rx, data, files, cred, &outq));
                return Ok(data.len());
            }
        }
        block(cx, nonblock, deadline, &rx)?;
    }
}

/// unix_dgram_sendmsg: sending to a dead connected peer disconnects the socket, ECONNREFUSED
/// this time and ENOTCONN from then on.
fn disconnect_dead_dgram(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    tx: &Weak<RefCell<crate::unix::Channel>>,
) -> Errno {
    let dropped = with(sock, |u| {
        if matches!(&u.link, Link::Dgram { tx: t, .. } if Weak::ptr_eq(t, tx)) {
            u.set_dgram_link(Link::None)
        } else {
            Vec::new()
        }
    });
    if !dropped.is_empty() {
        crate::unix::released(cx.k(), dropped);
    }
    Errno::ECONNREFUSED
}

/// Record explicit credentials, or the sender's real IDs when either endpoint requests them.
fn packet_cred(cx: &Cx<'_>, declared: Option<Ucred>, passcred: bool) -> Ucred {
    declared
        .or_else(|| passcred.then(|| cx.scm_cred()))
        .unwrap_or(Ucred::UNSTAMPED)
}

fn packet(
    k: &mut Kernel,
    channel: &ChannelRef,
    data: &[u8],
    rights: Option<Rc<SendingRights>>,
    cred: Ucred,
    sender: &Rc<SenderState>,
) -> Packet {
    Packet {
        data: data.to_vec(),
        off: 0,
        fds: rights
            .map(|r| r.into_packet(k, channel))
            .unwrap_or_default(),
        cred,
        from: Vec::new(),
        outq: Some(sender.charge(packet_truesize(data.len()))),
    }
}

pub(super) fn recv(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    max: usize,
    control_len: usize,
    flags: u32,
) -> Result<Message, Errno> {
    let (_, m) = recv_inner(cx, sock, nonblock, max, None, control_len, flags)?;
    Ok(m)
}

/// Receives from an AF_UNIX socket directly into guest `iovecs`: stream bytes are copied to user
/// memory before being consumed from the channel so a copy fault never loses stream data, while a
/// faulting datagram/seqpacket is dropped (as Linux's `unix_dgram_recvmsg` does) unless the fault
/// is `FUSE_RETRY`. Returns `(copied_bytes, message)` with `message.data` empty and `message.len`
/// holding the untruncated length for `MSG_TRUNC`.
pub(super) fn recv_into(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    iovecs: &[(u64, usize)],
    control_len: usize,
    flags: u32,
) -> Result<(usize, Message), Errno> {
    let total: usize = iovecs.iter().map(|v| v.1).sum();
    let max = total.min(super::net::MSG_MAX);
    recv_inner(cx, sock, nonblock, max, Some(iovecs), control_len, flags)
}

fn recv_inner(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    nonblock: bool,
    max: usize,
    iovecs: Option<&[(u64, usize)]>,
    control_len: usize,
    flags: u32,
) -> Result<(usize, Message), Errno> {
    let nonblock = nonblock || flags & MSG_DONTWAIT != 0;
    let peek = flags & MSG_PEEK != 0;
    let (ty, timeout) = with(sock, |u| (u.ty, u.rcvtimeo));
    let deadline = deadline(timeout);
    if ty == SOCK_STREAM {
        recv_stream(
            cx,
            sock,
            (nonblock, peek, deadline),
            max,
            iovecs,
            control_len,
            flags,
        )
    } else {
        recv_packet(
            cx,
            sock,
            (nonblock, peek, deadline),
            max,
            iovecs,
            control_len,
        )
    }
}

fn empty_message() -> Message {
    Message {
        data: Vec::new(),
        len: 0,
        addr: Vec::new(),
        control: Vec::new(),
        rights: None,
        flags: 0,
    }
}

fn rx_channel(sock: &SocketRef) -> Result<ChannelRef, Errno> {
    with(sock, |u| match &u.link {
        Link::Listening { .. } => Err(Errno::EINVAL),
        Link::None if u.ty != SOCK_DGRAM => Err(Errno::ENOTCONN),
        _ => Ok(u.receive_queue().clone()),
    })
}

fn recv_stream(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    (nonblock, peek, deadline): (bool, bool, Option<Instant>),
    max: usize,
    iovecs: Option<&[(u64, usize)]>,
    control_len: usize,
    flags: u32,
) -> Result<(usize, Message), Errno> {
    let wait_all = flags & MSG_WAITALL != 0 && !peek;
    // Bytes and ancillary data already read under MSG_WAITALL.
    let mut part: Option<Received> = None;
    // Once this read takes credentials, their boundary survives a wait and any later option change.
    let mut checked_cred = None;
    let rx = rx_channel(sock)?;
    let finish = |cx: &mut Cx<'_>, r: Received| {
        let passcred = rx.borrow().passcred;
        Ok((r.len, deliver(cx, r, false, passcred, control_len)))
    };
    loop {
        let passcred = checked_cred.is_some() || rx.borrow().passcred;
        let copied = part.as_ref().map_or(0, |r| r.len);
        let room = max - copied;
        let (preview, cred_break, eof, reset) = {
            let mut c = rx.borrow_mut();
            let queued = !c.packets.is_empty();
            let cred_break =
                checked_cred.is_some_and(|cred| c.packets.front().is_some_and(|h| h.cred != cred));
            let preview = if cred_break {
                None
            } else {
                Some(c.read_stream(room, true, passcred))
                    .filter(|r| !r.data.is_empty() || !r.fds.is_empty() || (room == 0 && queued))
            };
            // Keep a pending ECONNRESET intact when returning partial MSG_WAITALL data so the
            // next read reports it instead of seeing EOF
            let reset = preview.is_none()
                && !cred_break
                && if part.is_some() {
                    c.reset
                } else {
                    c.take_reset()
                };
            (preview, cred_break, c.eof, reset)
        };
        if cred_break {
            return finish(cx, part.unwrap());
        }
        if let Some(pre) = preview {
            let n = if let Some(vecs) = iovecs {
                match super::net::scatter_partial(cx, vecs, copied, &pre.data) {
                    Ok(n) => n,
                    Err(e) => {
                        return match part {
                            Some(r) => finish(cx, r),
                            None => Err(e),
                        };
                    }
                }
            } else {
                pre.len
            };
            let short_fault = n < pre.len;
            let mut taken = if peek {
                pre
            } else {
                drop(pre);
                let take_max = if short_fault { n } else { room };
                rx.borrow_mut().read_stream(take_max, false, passcred)
            };
            if iovecs.is_some() {
                taken.data.clear();
            }
            taken.len = copied + n;
            if passcred {
                checked_cred = Some(taken.cred);
            }
            let mut r = match part.take() {
                Some(mut p) => {
                    p.data.extend_from_slice(&taken.data);
                    p.len = taken.len;
                    p.fds.extend(taken.fds);
                    p
                }
                None => taken,
            };
            r.cred = checked_cred.unwrap_or(Ucred::UNSTAMPED);
            if short_fault || !wait_all || r.len >= max || !r.fds.is_empty() {
                return finish(cx, r);
            }
            part = Some(r);
            continue;
        }
        if reset {
            return match part.take() {
                Some(r) => finish(cx, r),
                None => Err(Errno::ECONNRESET),
            };
        }
        if eof {
            return match part.take() {
                Some(r) => finish(cx, r),
                None => Ok((0, empty_message())),
            };
        }
        if let Err(e) = block(cx, nonblock, deadline, &rx) {
            return match part.take() {
                Some(r) => finish(cx, r),
                None => Err(e),
            };
        }
    }
}

fn recv_packet(
    cx: &mut Cx<'_>,
    sock: &SocketRef,
    (nonblock, peek, deadline): (bool, bool, Option<Instant>),
    max: usize,
    iovecs: Option<&[(u64, usize)]>,
    control_len: usize,
) -> Result<(usize, Message), Errno> {
    loop {
        let rx = rx_channel(sock)?;
        let (preview, eof) = {
            let mut c = rx.borrow_mut();
            // A connection reset by the peer (Linux's sk_err): datagram and seqpacket sockets
            // report it before what is queued (__skb_try_recv_datagram)
            if c.take_reset() {
                return Err(Errno::ECONNRESET);
            }
            let preview = c.read_packet(max, true);
            (preview, c.eof)
        };
        if let Some(pre) = preview {
            if let Some(vecs) = iovecs
                && let Err(e) =
                    super::net::scatter(vecs, 0, &pre.data, |dst, bytes| cx.mm().write(dst, bytes))
            {
                if e == Errno::FUSE_RETRY {
                    return Err(Errno::FUSE_RETRY);
                }
                drop(pre);
                if !peek
                    && let Some(dropped) = rx.borrow_mut().read_packet(0, false)
                    && !dropped.fds.is_empty()
                {
                    crate::unix::released(cx.k(), dropped.fds);
                }
                return Err(e);
            }
            let mut r = if peek {
                pre
            } else {
                drop(pre);
                rx.borrow_mut().read_packet(max, false).unwrap()
            };
            let n = r.data.len();
            let truncated = r.len > n;
            if iovecs.is_some() {
                r.data.clear();
            }
            let passcred = rx.borrow().passcred;
            return Ok((n, deliver(cx, r, truncated, passcred, control_len)));
        }
        if eof {
            return Ok((0, empty_message()));
        }
        block(cx, nonblock, deadline, &rx)?;
    }
}

/// Hands the data read to the guest: attaches the credentials and reserves slots for passed files
/// into the current process's fd table, as Linux's `scm_recv` fills a control buffer of
/// `control_len` bytes: the credentials cut to what fits (`put_cmsg`), then as many files as fit
/// after a header (`scm_detach_fds`); what does not fit is dropped and `MSG_CTRUNC` is set.
fn deliver(
    cx: &mut Cx<'_>,
    r: Received,
    truncated: bool,
    passcred: bool,
    control_len: usize,
) -> Message {
    let mut control = Vec::new();
    let mut room = control_len;
    let mut out_flags = if truncated { MSG_TRUNC } else { 0 };
    if passcred {
        // pid and IDs as the receiver sees them (Linux's scm_recv uses pid_vnr, from_kuid_munged)
        let me = cx.cred();
        let cred = Ucred {
            pid: cx.pid_out(r.cred.pid),
            uid: me.uid_out(r.cred.uid),
            gid: me.gid_out(r.cred.gid),
        };
        let data = cred.encode();
        super::net::put_cmsg(
            &mut control,
            &mut room,
            &mut out_flags,
            SOL_SOCKET,
            SCM_CREDENTIALS,
            &data,
        );
    }
    let rights = if r.fds.is_empty() {
        None
    } else {
        let mut pending = crate::unix::PendingRights::new(&cx.t.fds);
        let fit = room.saturating_sub(CMSG_HDR) / 4;
        let mut fds = Vec::new();
        let mut files = r.fds.into_iter();
        let mut dropped = Vec::new();
        for file in files.by_ref().take(fit) {
            let Ok(fd) = cx.reserve_fd() else {
                dropped.push(file);
                break;
            };
            pending.push(fd, file);
            fds.extend_from_slice(&fd.to_le_bytes());
        }
        dropped.extend(files);
        if !dropped.is_empty() {
            out_flags |= MSG_CTRUNC;
            crate::unix::released(cx.k(), dropped);
        }
        if !fds.is_empty() {
            super::net::put_cmsg(
                &mut control,
                &mut room,
                &mut out_flags,
                SOL_SOCKET,
                SCM_RIGHTS,
                &fds,
            );
        }
        pending.track(cx.k())
    };
    Message {
        data: r.data,
        len: r.len,
        addr: r.from,
        control,
        flags: out_flags,
        rights,
    }
}

// ---- Options and shutdown ----

/// `privileged` is (`CAP_NET_ADMIN` in the initial user namespace, whether a priority outside
/// 0..=6 is allowed), for [`SockOpts::set`](crate::net::SockOpts::set).
pub(super) fn setsockopt(
    u: &mut UnixSocket,
    level: i32,
    name: i32,
    value: &[u8],
    (admin, net_admin): (bool, bool),
) -> Result<(), Errno> {
    if level != SOL_SOCKET {
        return Err(Errno::EOPNOTSUPP);
    }
    match name {
        SO_PASSCRED => {
            u.receive_queue().borrow_mut().passcred = value.get(..4).ok_or(Errno::EINVAL)? != [0; 4]
        }
        SO_RCVTIMEO => u.rcvtimeo = timeval(value)?,
        SO_SNDTIMEO => u.sndtimeo = timeval(value)?,
        // Read-only options (Linux's sk_setsockopt checks optlen < sizeof(int) before ENOPROTOOPT)
        SO_SNDLOWAT | SO_ACCEPTCONN | SO_PEERCRED => {
            value.get(..4).ok_or(Errno::EINVAL)?;
            return Err(Errno::ENOPROTOOPT);
        }
        // Buffer sizes, lingering and the like are only recorded; other options are accepted
        // without effect
        _ => {
            if let Some(r) = u.opts.set(name, value, admin, net_admin) {
                r?;
            }
        }
    }
    Ok(())
}

/// `pid_ns` and `cred` are the caller's pid namespace and credentials: `SO_PEERCRED`'s pid and IDs
/// are translated by them (Linux's `cred_to_ucred`).
pub(super) fn getsockopt(
    u: &UnixSocket,
    level: i32,
    name: i32,
    pid_ns: &crate::pidns::PidNs,
    cred: &crate::cred::Cred,
) -> Result<Vec<u8>, Errno> {
    if level != SOL_SOCKET {
        return Err(Errno::EOPNOTSUPP);
    }
    let int = |v: i32| v.to_le_bytes().to_vec();
    Ok(match name {
        SO_TYPE => int(u.ty),
        SO_PROTOCOL => int(0),
        // A connection reset by the peer, reported once (sock_error)
        SO_ERROR => {
            if u.receive_queue().borrow_mut().take_reset() {
                int(Errno::ECONNRESET.0)
            } else {
                int(0)
            }
        }
        SO_DOMAIN => int(AF_UNIX),
        SO_PASSCRED => int(u.receive_queue().borrow().passcred as i32),
        SO_ACCEPTCONN => int(matches!(u.link, Link::Listening { .. }) as i32),
        SO_RCVTIMEO => encode_timeval(u.rcvtimeo),
        SO_SNDTIMEO => encode_timeval(u.sndtimeo),
        // A listener's are its own, recorded at listen; without a peer, as Linux's cred_to_ucred
        // without credentials: pid 0, uid and gid -1
        SO_PEERCRED => match &u.link {
            Link::Listening { cred, .. } => Some(*cred),
            _ => u.peer_cred,
        }
        .map(|c| Ucred {
            pid: pid_ns.vnr(c.pid).unwrap_or(0),
            uid: cred.uid_out(c.uid),
            gid: cred.gid_out(c.gid),
        })
        .unwrap_or(Ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        })
        .encode()
        .to_vec(),
        _ => return u.opts.get(name).ok_or(Errno::ENOPROTOOPT),
    })
}

fn encode_timeval(t: Option<Duration>) -> Vec<u8> {
    let t = t.unwrap_or_default();
    let mut b = (t.as_secs() as i64).to_le_bytes().to_vec();
    b.extend_from_slice(&(t.subsec_micros() as i64).to_le_bytes());
    b
}

pub(super) fn sockname(u: &UnixSocket, peer: bool) -> Result<Vec<u8>, Errno> {
    if peer {
        u.peer_name().ok_or(Errno::ENOTCONN)
    } else {
        Ok(u.name())
    }
}

pub(super) fn shutdown(u: &mut UnixSocket, how: i32) -> Result<(), Errno> {
    // Linux 6.1's unix_shutdown records the flags on any socket, connected or not
    if !(0..=2).contains(&how) {
        return Err(Errno::EINVAL);
    }
    u.shutdown(how);
    Ok(())
}

// ---- Addresses and waiting ----

/// An address given by the guest.
enum Addr<'a> {
    /// Only the address family: bind autobinds.
    Unnamed,
    /// A path (without the trailing NUL).
    Path(&'a [u8]),
    /// An abstract address: all bytes of `sun_path`.
    Abstract(&'a [u8]),
}

/// Finds the socket bound at an address (abstract addresses are looked up in the network
/// namespace of `sock`).
fn find(cx: &Cx<'_>, sock: &SocketRef, addr: &[u8]) -> Result<SocketRef, Errno> {
    let name = match parse(addr)? {
        Addr::Unnamed => return Err(Errno::EINVAL),
        Addr::Abstract(p) => {
            let (net, ty) = with(sock, |u| (u.net_id(), u.ty));
            Name::Abstract(net, ty, p.to_vec())
        }
        Addr::Path(p) => {
            let node = lookup_at(cx, AT_FDCWD, p, true)?;
            let vfs = cx.vfs()?;
            // Linux's unix_find_bsd checks MAY_WRITE before S_ISSOCK (EACCES before ECONNREFUSED)
            let ino = match node {
                Node::Fuse(_, f) => {
                    vfs.fuse_permission(&cx.cred(), f, crate::cred::MAY_WRITE)?;
                    if vfs.fuse().get(f).ok_or(Errno::ENOTCONN)?.kind() != mode::S_IFSOCK {
                        return Err(Errno::ECONNREFUSED);
                    }
                    return cx
                        .kr()
                        .unix
                        .lookup(&Name::Path(crate::vfs::fuse::key(f)))
                        .ok_or(Errno::ECONNREFUSED);
                }
                Node::Pseudo(_, p) => {
                    let st = crate::pseudo::stat(&cx.view(&vfs), &p)?;
                    cx.cred().permission(&st, crate::cred::MAY_WRITE)?;
                    return Err(Errno::ECONNREFUSED);
                }
                Node::Store(_, ino) => ino,
                // The socket file behind an overlay's node (in the upper layer when it was
                // bound through the overlay)
                Node::Overlay(_, o) => vfs.overlay().node(o).real(),
            };
            let st = vfs.store().stat(ino)?;
            cx.cred().permission(&st, crate::cred::MAY_WRITE)?;
            if st.mode & mode::S_IFMT != mode::S_IFSOCK {
                return Err(Errno::ECONNREFUSED);
            }
            Name::Path(ino)
        }
    };
    cx.kr().unix.lookup(&name).ok_or(Errno::ECONNREFUSED)
}

fn parse(addr: &[u8]) -> Result<Addr<'_>, Errno> {
    if addr.len() < 2 || addr.len() > SOCKADDR_UN_LEN {
        return Err(Errno::EINVAL);
    }
    if u16::from_le_bytes([addr[0], addr[1]]) as i32 != AF_UNIX {
        return Err(Errno::EINVAL);
    }
    let path = &addr[2..];
    Ok(match path.first() {
        None => Addr::Unnamed,
        Some(0) => Addr::Abstract(path),
        Some(_) => Addr::Path(&path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())]),
    })
}

/// Borrows the internal state of an AF_UNIX socket.
fn with<R>(sock: &SocketRef, f: impl FnOnce(&mut UnixSocket) -> R) -> R {
    match &mut *sock.borrow_mut() {
        Socket::Unix(u) => f(u),
        _ => unreachable!("not an AF_UNIX socket"),
    }
}

fn deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.map(|t| Instant::now() + t)
}

/// The common part of blocking operations: EAGAIN when nonblocking or timed out; on a signal,
/// EINTR when `SO_RCVTIMEO`/`SO_SNDTIMEO` set a deadline and ERESTARTSYS otherwise (Linux's
/// `sock_intr_errno`), so a timed wait is never restarted with its whole timeout again; otherwise
/// wait until some thread changes the state of channel `on` (a listening socket's connection
/// queue is recorded on its receive queue).
fn block(
    cx: &mut Cx<'_>,
    nonblock: bool,
    deadline: Option<Instant>,
    on: &ChannelRef,
) -> Result<(), Errno> {
    if nonblock || deadline.is_some_and(|d| Instant::now() >= d) {
        return Err(Errno::EAGAIN);
    }
    if cx.interrupted() {
        return Err(if deadline.is_some() {
            Errno::EINTR
        } else {
            Errno::ERESTARTSYS
        });
    }
    cx.wait_objects(deadline, &mut [], wake::FILE, &[wake::of(on)])
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::fd::{FdTable, FileKind, OpenFile, oflags};
    use crate::kernel::{Kernel, Shared};
    use crate::mm::Mm;
    use crate::process::{RLIMIT_NOFILE, ThreadGroup, Tier};
    use crate::signal::SigHandlers;
    use crate::task::{FsContext, Task, TaskState};
    use crate::vfs::{INIT_MNT_NS, MntNs, Node};

    #[test]
    fn accept4_and_scm_rights_respect_lowered_nr_open() {
        let shared = Arc::new(Shared::new(Kernel::new(Tier::Interpreter)));
        let _cpu = {
            let mut k = shared.lock();
            let group = Rc::new(RefCell::new(ThreadGroup::new(
                10,
                1,
                Rc::new(RefCell::new(SigHandlers::default())),
            )));
            group.borrow_mut().rlimits[RLIMIT_NOFILE as usize] = (4096, 4096);
            let mm = Mm::new().into_shared();
            let fds = Rc::new(RefCell::new(FdTable::with_host_stdio()));
            let fs = Rc::new(RefCell::new(FsContext {
                root: Node::ROOT,
                cwd: Node::ROOT,
                umask: 0o022,
                mnt_ns: Rc::new(MntNs {
                    id: INIT_MNT_NS,
                    owner: crate::cred::UserNs::init(),
                    anon: false,
                }),
            }));
            let cpu = unsafe { appine_engine::Cpu::new(mm.borrow().mmu()) };
            let state = TaskState {
                mm,
                fds,
                fs,
                group: group.clone(),
                vfs: None,
                altstack: Default::default(),
                clear_child_tid: 0,
                vfork_done: None,
                restart: None,
                fast_sleep: None,
                sem_undo: Rc::new(crate::ipc::SemUndo::new()),
            };
            let task = Task::new(10, 10, &cpu, state, k.init_ns.clone(), 0, [0; 16]).unwrap();
            group.borrow_mut().threads.push(10);
            k.groups.insert(10, group);
            k.tasks.insert(10, task.clone());

            let mut t = task.state.borrow_mut();
            let mut cx = Cx::new(&shared, k, &task, &mut t);

            // Set up a listening AF_UNIX stream socket with two pending client connections.
            let srv: SocketRef = Rc::new(RefCell::new(socket(SOCK_STREAM, 0).unwrap()));
            let mut addr = (AF_UNIX as u16).to_le_bytes().to_vec();
            addr.extend_from_slice(b"\0nr-open-reserve-test");
            bind(&mut cx, &srv, &addr).unwrap();
            with(&srv, |u| listen(u, 4, cx.ucred())).unwrap();
            let srv_fd = cx
                .install_fd(OpenFile::new(FileKind::Socket(srv), oflags::O_RDWR), true)
                .unwrap();

            let mut clients = Vec::new();
            for _ in 0..2 {
                let cli: SocketRef = Rc::new(RefCell::new(socket(SOCK_STREAM, 0).unwrap()));
                connect(&mut cx, &cli, true, &addr).unwrap();
                clients.push(cli);
            }

            // Lower nr_open to 64 while RLIMIT_NOFILE stays 4096, and occupy all slots 0..64.
            cx.k().nr_open = 64;
            let filler = cx.fds().get(1).unwrap();
            let mut spare = -1;
            for fd in 0..64 {
                if cx.fds().get(fd).is_err() {
                    assert_eq!(cx.install_fd(filler.clone(), true), Ok(fd));
                    spare = fd;
                }
            }
            assert!(spare >= 0);
            assert_eq!(cx.fds().capacity(), 64);

            let accept = |cx: &mut Cx<'_>| {
                super::super::net::accept4(cx, srv_fd, 0, 0, oflags::O_NONBLOCK | oflags::O_CLOEXEC)
            };
            let recv = |cx: &mut Cx<'_>, byte: u8, fds: Vec<FileRef>| {
                deliver(
                    cx,
                    Received {
                        data: vec![byte],
                        len: 1,
                        fds,
                        cred: Ucred::UNSTAMPED,
                        from: Vec::new(),
                    },
                    false,
                    false,
                    64,
                )
            };

            // accept4 must fail with EMFILE and keep table capacity at 64.
            assert_eq!(accept(&mut cx), Err(Errno::EMFILE));
            assert_eq!(cx.fds().capacity(), 64);

            // SCM_RIGHTS with 0 free slots < 64 sets MSG_CTRUNC and delivers no descriptors.
            let msg = recv(&mut cx, b'x', vec![filler.clone(), filler.clone()]);
            assert_ne!(msg.flags & MSG_CTRUNC, 0);
            assert!(msg.control.is_empty());
            assert!(msg.rights.is_none());
            assert_eq!(cx.fds().capacity(), 64);

            // Free one slot below 64: SCM_RIGHTS reserves that slot and truncates the second fd.
            cx.fds_mut().close(spare).unwrap();
            let msg = recv(&mut cx, b'y', vec![filler.clone(), filler.clone()]);
            assert_ne!(msg.flags & MSG_CTRUNC, 0);
            assert_eq!(msg.control.len(), CMSG_HDR + 4 + 4); // 16-byte header + 1 fd + 4-byte align
            assert_eq!(
                i32::from_le_bytes(msg.control[CMSG_HDR..CMSG_HDR + 4].try_into().unwrap()),
                spare
            );
            assert_eq!(cx.fds().capacity(), 64);
            // Dropping PendingRights unreserves `spare` cleanly.
            drop(msg.rights);
            assert_eq!(cx.fds().get(64).err(), Some(Errno::EBADF));

            // Now accept4 succeeds in `spare` without expanding past 64.
            assert_eq!(accept(&mut cx), Ok(spare as u64));
            assert_eq!(cx.fds().capacity(), 64);

            // Expanding across 128 with nr_open = 192 caps capacity at 192 (not 256) for both
            // accept4 and SCM_RIGHTS.
            cx.k().nr_open = 192;
            for fd in 64..128 {
                assert_eq!(cx.install_fd(filler.clone(), true), Ok(fd));
            }
            assert_eq!(cx.fds().capacity(), 128);
            assert_eq!(accept(&mut cx), Ok(128));
            assert_eq!(cx.fds().capacity(), 192);

            for fd in 129..192 {
                assert_eq!(cx.install_fd(filler.clone(), true), Ok(fd));
            }
            let msg = recv(&mut cx, b'z', vec![filler.clone()]);
            assert_ne!(msg.flags & MSG_CTRUNC, 0);
            assert!(msg.control.is_empty());
            assert!(msg.rights.is_none());
            assert_eq!(cx.fds().capacity(), 192);

            drop(clients);
            drop(cx);
            cpu
        };
    }

    #[test]
    fn seqpacket_epipe_omits_sigpipe_while_stream_raises_it() {
        use crate::process::Signal;

        let mut k = Kernel::new(Tier::Interpreter);
        let (_, _, _cpu) = crate::pseudo::tests::add_task(&mut k, 10, 0, true, b"");
        let shared = Arc::new(Shared::new(k));
        let k = shared.lock();
        let task = k.tasks[&10].clone();
        let mut state = task.state.borrow_mut();
        let mut cx = Cx::new(&shared, k, &task, &mut state);

        // SOCK_SEQPACKET: EPIPE without SIGPIPE on peer close, peer SHUT_RD, and local SHUT_WR.
        for mode in 0..3 {
            let (sa, sb) = pair(&cx, SOCK_SEQPACKET, 0).unwrap();
            let a = Rc::new(RefCell::new(sa));
            let b = Rc::new(RefCell::new(sb));
            match mode {
                0 => drop(b),
                1 => with(&b, |u| shutdown(u, 0).unwrap()),
                _ => with(&a, |u| shutdown(u, 1).unwrap()),
            }
            assert_eq!(
                send(&mut cx, &a, true, b"x", &[], &[], 0),
                Err(Errno::EPIPE)
            );
            assert_eq!(task.pending.borrow().set() & Signal::PIPE.bit(), 0);
        }

        // SOCK_STREAM: EPIPE raises SIGPIPE when MSG_NOSIGNAL is not set.
        let (sa, sb) = pair(&cx, SOCK_STREAM, 0).unwrap();
        let a = Rc::new(RefCell::new(sa));
        drop(sb);
        assert_eq!(
            send(&mut cx, &a, true, b"x", &[], &[], 0),
            Err(Errno::EPIPE)
        );
        assert_ne!(task.pending.borrow().set() & Signal::PIPE.bit(), 0);
    }
}
