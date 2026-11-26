# docker-run-options: --privileged
# Differential tests for networking fixes:
# - rtnetlink notifications: seq/port, NLM_F_CREATE|EXCL / NLM_F_REPLACE on routes, and NLM_F_ECHO
# - ip route get with iif (IPv4 and IPv6, local, forwarding with ip_forward 0/1, fibmatch, errors)
# - SO_BINDTODEVICE / SO_BINDTOIFINDEX against guest netns virtual devices
# - nat-chain drop and reject on OUTPUT and PREROUTING (TCP timeout/reject, UDP connect + send)
set -e
cd /tmp

echo "== 1. rtnetlink seq/port/flags and NLM_F_ECHO"
unshare -n python3 - <<'PY'
import select, socket, struct, subprocess
subprocess.run("echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad; ip link set lo up; ip link add d0 type dummy; ip link set d0 up", shell=True, check=True)
d0 = socket.if_nametoindex("d0")
ALL = 0x1 | 0x10 | 0x40 | 0x100 | 0x400
mon = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
mon.bind((0, ALL))
tx = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
tx.bind((0, 0))
txs = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
txs.bind((0, ALL))
tx_pid = tx.getsockname()[0]
txs_pid = txs.getsockname()[0]
def ptag(p):
    if p == 0: return "0"
    if p == tx_pid: return "TX"
    if p == txs_pid: return "TXS"
    return f"OTHER({p})"
def attr(t, d):
    b = struct.pack("HH", 4 + len(d), t) + d
    return b + b"\0" * ((-len(b)) & 3)
def rx(tag, s, sort_out=False):
    lines = []
    while select.select([s], [], [], 0.08)[0]:
        d, addr = s.recvfrom(8192)
        off = 0
        while off + 16 <= len(d):
            l, ty, fl, seq, pid = struct.unpack_from("IHHII", d, off)
            if l < 16 or off + l > len(d): break
            if ty == 2:
                err = struct.unpack_from("i", d, off + 16)[0]
                lines.append(f"  [{tag}] ACK err={err} seq={seq} pid={ptag(pid)} grp={addr[1]:#x}")
            else:
                lines.append(f"  [{tag}] ty={ty} fl={fl:#x} seq={seq} pid={ptag(pid)} grp={addr[1]:#x}")
            off += (l + 3) & ~3
    if sort_out:
        lines = sorted(set(lines))
    for line in lines:
        print(line)
def send_nl(s, ty, fl, seq, body):
    s.send(struct.pack("IHHII", 16 + len(body), ty, fl, seq, 0) + body)

print("-- NEWADDR v4 ECHO|ACK")
a4 = struct.pack("BBBBI", 2, 24, 0, 0, d0) + attr(2, socket.inet_aton("10.1.0.1")) + attr(1, socket.inet_aton("10.1.0.1"))
send_nl(tx, 20, 1|4|8|0x600, 101, a4)
rx("tx", tx); rx("mon", mon, sort_out=True); rx("txs", txs, sort_out=True)

print("-- NEWROUTE v4 CREATE|EXCL|ECHO|ACK")
r4 = struct.pack("BBBBBBBBI", 2, 24, 0, 0, 254, 3, 253, 1, 0) + attr(1, socket.inet_aton("10.9.0.0")) + attr(4, struct.pack("i", d0))
send_nl(tx, 24, 1|4|8|0x600, 102, r4)
rx("tx", tx); rx("mon", mon); rx("txs", txs)

print("-- NEWROUTE v4 REPLACE|CREATE|ECHO|ACK (subscribed txs)")
r4b = struct.pack("BBBBBBBBI", 2, 24, 0, 0, 254, 4, 253, 1, 0) + attr(1, socket.inet_aton("10.9.0.0")) + attr(4, struct.pack("i", d0))
send_nl(txs, 24, 1|4|8|0x500, 103, r4b)
rx("txs", txs); rx("mon", mon)

print("-- DELROUTE v4 ECHO|ACK")
send_nl(tx, 25, 1|4|8, 104, r4b)
rx("tx", tx); rx("mon", mon); rx("txs", txs)

print("-- NEWROUTE v6 CREATE|EXCL|ECHO|ACK")
r6 = struct.pack("BBBBBBBBI", 10, 64, 0, 0, 254, 3, 0, 1, 0) + attr(1, socket.inet_pton(10, "fd01::")) + attr(4, struct.pack("i", d0))
send_nl(tx, 24, 1|4|8|0x600, 105, r6)
rx("tx", tx); rx("mon", mon); rx("txs", txs)

print("-- DELROUTE v6 ECHO|ACK")
send_nl(tx, 25, 1|4|8, 106, r6)
rx("tx", tx); rx("mon", mon); rx("txs", txs)

print("-- DELADDR v4 ECHO|ACK")
send_nl(tx, 21, 1|4|8, 107, a4)
rx("tx", tx); rx("mon", mon, sort_out=True); rx("txs", txs, sort_out=True)
PY

echo "== 2. ip route get with iif"
unshare -n sh -c '
echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad
ip link set lo up
ip link add d0 type dummy; ip link set d0 up
ip link add d1 type dummy; ip link set d1 up
ip addr add 10.1.0.1/24 dev d0
ip addr add 10.2.0.1/24 dev d1
ip -6 addr add fd00::1/64 dev d0 nodad
ip -6 addr add fd01::1/64 dev d1 nodad
ip route add default via 10.2.0.254 dev d1
ip route add 10.9.0.0/16 dev d1
ip -6 route add fd09::/64 via fd01::9 dev d1
echo 0 > /proc/sys/net/ipv4/ip_forward
# Down/unaddressed iif (EXDEV on Linux 6.1/6.8, collapsed to EINVAL on newer kernels after
# ip_route_input_rcu switched to skb_drop_reason) is covered in tests/guest/net_regressions.c.
for cmd in \
  "ip route get 10.1.0.1 from 10.1.0.5 iif d0" \
  "ip route get 10.1.0.1 iif d0" \
  "ip route get 10.9.0.5 from 10.1.0.5 iif d0" \
  "ip route get 10.1.0.255 from 10.1.0.5 iif d0" \
  "ip route get 127.0.0.1 from 10.1.0.5 iif d0" \
  "ip -6 route get fd00::1 from fd00::5 iif d0" \
  "ip -6 route get fd09::5 from fd00::5 iif d0" \
  "ip -6 route get fd09::5 iif d0" \
  "ip -6 route get ::1 from fd00::5 iif d0" \
  "ip -6 route get ::1 from ::1 iif lo" \
  "ip -6 route get fibmatch fd09::5 from fd00::5 iif d0"
do
  echo "CMD: $cmd"
  $cmd 2>&1 || echo "  EXIT=$?"
done
echo 1 > /proc/sys/net/ipv4/ip_forward
for cmd in \
  "ip route get 10.9.0.5 from 10.1.0.5 iif d0" \
  "ip route get 1.1.1.1 from 10.1.0.5 iif d0" \
  "ip route get fibmatch 10.9.0.5 from 10.1.0.5 iif d0"
do
  echo "CMD: $cmd"
  $cmd 2>&1 || echo "  EXIT=$?"
done
'

echo "== 3. SO_BINDTODEVICE / SO_BINDTOIFINDEX in new netns"
unshare -n python3 - <<'PY'
import errno, os, socket, struct, subprocess
subprocess.run("ip link set lo up; ip link add d0 type dummy; ip link set d0 up; ip addr add 10.1.0.1/24 dev d0; ip link add d1 type dummy; ip link set d1 up; ip addr add 10.2.0.1/24 dev d1", shell=True, check=True)
SO_BINDTODEVICE = 25
SO_BINDTOIFINDEX = 62
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for name in [b"eth0\0", b"nosuch\0", b"d0\0", b"d0", b"", b"\0"]:
    try:
        s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, name)
        g = s.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)
        gi = struct.unpack("i", s.getsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4))[0]
        print(f"set({name!r}) -> ok get={g!r} idx={gi}")
    except OSError as e:
        print(f"set({name!r}) -> {errno.errorcode.get(e.errno, e.errno)}")
s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"d0\0")
for l in [1, 15, 16]:
    try:
        print(f"get({l}) -> {s.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, l)!r}")
    except OSError as e:
        print(f"get({l}) -> {errno.errorcode.get(e.errno, e.errno)}")
subprocess.run("ip link set d0 down; ip link set d0 name d9; ip link set d9 up", shell=True, check=True)
print("after rename:", repr(s.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)))
subprocess.run("ip link del d9", shell=True, check=True)
try:
    print("after del:", repr(s.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16)))
except OSError as e:
    print("after del:", errno.errorcode.get(e.errno, e.errno))
print("after del idx:", struct.unpack("i", s.getsockopt(socket.SOL_SOCKET, SO_BINDTOIFINDEX, 4))[0])
s.close()
os.setgid(65534); os.setuid(65534)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, b"d1\0")
print("unpriv bind d1: ok")
for label, val in [("rebind lo", b"lo\0"), ("unbind", b""), ("nosuch", b"nosuch\0")]:
    try:
        u.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, val)
        print(f"unpriv {label}: ok")
    except OSError as e:
        print(f"unpriv {label}: {errno.errorcode.get(e.errno, e.errno)}")
u.close()
PY

echo "== 4. nat-chain drop and reject"
unshare -n sh -s <<'INNER'
ip link set lo up
nft -f - <<'NFT'
table ip t {
  chain out {
    type nat hook output priority dstnat; policy accept;
    tcp dport 1 dnat to 127.0.0.1:2
    tcp dport 19001 drop
    udp dport 19001 drop
    tcp dport 19002 reject
    udp dport 19002 reject
    tcp dport 19003 reject with tcp reset
  }
}
NFT
python3 - <<'PY'
import errno, socket, time
for p in (19001, 19002, 19003):
    st = socket.socket(); st.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    st.bind(("127.0.0.1", p)); st.listen()
    su = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); su.bind(("127.0.0.1", p))
    c = socket.socket(); c.settimeout(0.8); t0 = time.monotonic()
    try: c.connect(("127.0.0.1", p)); print(f"OUT {p} tcp: OK")
    except TimeoutError:
        w = "after waiting" if time.monotonic() - t0 >= 0.5 else "at once"
        print(f"OUT {p} tcp: TIMEOUT ({w})")
    except OSError as e: print(f"OUT {p} tcp: {errno.errorcode.get(e.errno, e.errno)}")
    c.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.connect(("127.0.0.1", p)); print(f"OUT {p} udp_connect: OK")
        try: print(f"OUT {p} udp_conn_send: OK({u.send(b'x')})")
        except OSError as e: print(f"OUT {p} udp_conn_send: {errno.errorcode.get(e.errno, e.errno)}")
    except OSError as e: print(f"OUT {p} udp_connect: {errno.errorcode.get(e.errno, e.errno)}")
    u.close()
    u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: print(f"OUT {p} udp_sendto: OK({u2.sendto(b'x', ('127.0.0.1', p))})")
    except OSError as e: print(f"OUT {p} udp_sendto: {errno.errorcode.get(e.errno, e.errno)}")
    u2.close()
    st.close(); su.close()
PY
INNER

ip link add br0 type bridge; ip addr add 10.62.0.1/24 dev br0; ip link set br0 up
unshare -n sleep 60 &
P=$!
sleep 0.2
ip link add v0 type veth peer name eth0 netns $P
ip link set v0 master br0; ip link set v0 up
nsenter -t $P -n sh -c 'ip link set lo up; ip link set eth0 up; ip addr add 10.62.0.2/24 dev eth0; ip route add default via 10.62.0.1'
sleep 1
nsenter -t $P -n python3 -c '
import socket, time
socks = []
for p in (19001, 19002, 19003):
    st = socket.socket(); st.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    st.bind(("0.0.0.0", p)); st.listen(); socks.append(st)
    su = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); su.bind(("0.0.0.0", p)); socks.append(su)
time.sleep(20)
' &
SRV=$!
sleep 0.3
nsenter -t $P -n nft -f - <<'NFT'
table ip t {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 1 dnat to 10.62.0.2:2
    tcp dport 19001 drop
    udp dport 19001 drop
    tcp dport 19002 reject
    udp dport 19002 reject
    tcp dport 19003 reject with tcp reset
  }
}
NFT
python3 - <<'PY'
import errno, socket, time
for p in (19001, 19002, 19003):
    c = socket.socket(); c.settimeout(0.8); t0 = time.monotonic()
    try: c.connect(("10.62.0.2", p)); print(f"PRE {p} tcp: OK")
    except TimeoutError:
        w = "after waiting" if time.monotonic() - t0 >= 0.5 else "at once"
        print(f"PRE {p} tcp: TIMEOUT ({w})")
    except OSError as e: print(f"PRE {p} tcp: {errno.errorcode.get(e.errno, e.errno)}")
    c.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.connect(("10.62.0.2", p)); print(f"PRE {p} udp_connect: OK")
        try: print(f"PRE {p} udp_conn_send: OK({u.send(b'x')})")
        except OSError as e: print(f"PRE {p} udp_conn_send: {errno.errorcode.get(e.errno, e.errno)}")
    except OSError as e: print(f"PRE {p} udp_connect: {errno.errorcode.get(e.errno, e.errno)}")
    u.close()
    u2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: print(f"PRE {p} udp_sendto: OK({u2.sendto(b'x', ('10.62.0.2', p))})")
    except OSError as e: print(f"PRE {p} udp_sendto: {errno.errorcode.get(e.errno, e.errno)}")
    u2.close()
PY
kill $SRV $P 2>/dev/null || true
ip link del br0
