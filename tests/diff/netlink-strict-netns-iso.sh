# docker-run-options: --privileged
# Differential tests for:
# 1. Netlink NETLINK_GET_STRICT_CHK header checks and dump filtering (links, addresses, routes,
#    rules, neigh), request/attribute validation (RTM_GETLINK, single IPv6 RTM_GETADDR, ip route
#    get IPv4/IPv6 RTA_DST/RTA_FLOW/RTA_IIF, RTM_GETNSID), NETLINK_CAP_ACK / NETLINK_EXT_ACK on
#    query and generic-netlink errors, and nlctrl GETPOLICY dump (CTRL_ATTR_FAMILY_ID before name).
# 2. Initial-netns guest-side isolation of container 127.a.b.x loopback blocks while preserving
#    initial-ns loopback (127.0.0.1, 127.0.1.1, unallocated 127.0.99.1) and DNAT forwarding.
set -e
cd /tmp

echo "== 1. Netlink strict checks, validation, CAP_ACK/EXT_ACK, and nlctrl GETPOLICY"
unshare -n python3 - <<'PY'
import errno, socket, struct, subprocess

subprocess.run(
    "echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad;"
    "ip link set lo up;"
    "ip link add d0 type dummy; ip link set d0 up;"
    "ip addr add 10.74.0.1/24 dev d0;"
    "ip -6 addr add fd74::1/64 dev d0 nodad;"
    "ip route add 10.74.9.0/24 dev d0",
    shell=True,
    check=True,
)
lo_idx = socket.if_nametoindex("lo")
d0_idx = socket.if_nametoindex("d0")

NETLINK_ROUTE = 0
NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_CAP_ACK = 10
NETLINK_EXT_ACK = 11
NETLINK_GET_STRICT_CHK = 12
NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3

def attr(t, d):
    b = struct.pack("HH", 4 + len(d), t) + d
    return b + b"\0" * ((-len(b)) & 3)

def nl_req(ty, flags, body, seq=1):
    return struct.pack("IHHII", 16 + len(body), ty, flags, seq, 0) + body

def ask(proto, req, strict=False, cap=False, ext=False):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, proto)
    if strict: s.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
    if cap: s.setsockopt(SOL_NETLINK, NETLINK_CAP_ACK, 1)
    if ext: s.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
    s.settimeout(0.5)
    s.send(req)
    msgs = []
    while True:
        try:
            d = s.recv(65536)
        except TimeoutError:
            break
        off = 0
        done = False
        while off + 16 <= len(d):
            l, ty, fl, seq, pid = struct.unpack_from("IHHII", d, off)
            body = d[off+16:off+l]
            if ty == NLMSG_ERROR:
                err = struct.unpack_from("i", body, 0)[0]
                has_ext = bool(fl & 0x200)
                capped = bool(fl & 0x100)
                msgs.append(("ERR", errno.errorcode.get(-err, -err), capped, has_ext))
                done = True
            elif ty == NLMSG_DONE:
                err = struct.unpack_from("i", body, 0)[0] if len(body) >= 4 else 0
                msgs.append(("DONE", "OK" if err == 0 else errno.errorcode.get(-err, -err), bool(fl & 0x20), bool(fl & 0x200)))
                done = True
            else:
                msgs.append((ty, bool(fl & 0x20), body))
            off += (l + 3) & ~3
        if done or not any(m[0] not in ("ERR", "DONE") for m in msgs):
            break
    s.close()
    return msgs

def show_err(label, proto, req, cap=True, ext=True):
    print(f"  {label}: {ask(proto, req, cap=cap, ext=ext)}")

def ifi(idx=0):
    return struct.pack("BBHiII", 0, 0, 0, idx, 0, 0)

def ifa(fam, plen=0, idx=0):
    return struct.pack("BBBBI", fam, plen, 0, 0, idx)

def rtm(fam, dst_len=0, table=0, scope=0, flags=0):
    return struct.pack("BBBBBBBBI", fam, dst_len, 0, 0, table, 0, scope, 0, flags)

def genl(cmd):
    return struct.pack("BBH", cmd, 2, 0)

print("-- CAP_ACK / EXT_ACK and query validation")
show_err("GETLINK bad idx (cap+ext)", NETLINK_ROUTE, nl_req(18, NLM_F_REQUEST, ifi(9999)))
show_err("GETLINK short 2B (cap+ext)", NETLINK_ROUTE, nl_req(18, NLM_F_REQUEST, b"\0\0"))
show_err("GETLINK empty IFNAME", NETLINK_ROUTE, nl_req(18, NLM_F_REQUEST, ifi() + attr(3, b"")))
show_err("GETLINK long IFNAME 17B", NETLINK_ROUTE, nl_req(18, NLM_F_REQUEST, ifi() + attr(3, b"a"*17)))
show_err("GETLINK short MASTER 2B", NETLINK_ROUTE, nl_req(18, NLM_F_REQUEST, ifi(lo_idx) + attr(10, b"\x01\x00")))
show_err("GETADDR v4 single", NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, ifa(2, 0, lo_idx)))
show_err("GETADDR v6 short 4B", NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, b"\x0a\0\0\0"))
show_err("GETADDR v6 no addr", NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, ifa(10, 0, lo_idx)))
show_err("GETADDR v6 short IFA_ADDRESS", NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, ifa(10, 0, lo_idx) + attr(1, b"\0"*4)))
show_err("GETADDR v6 missing ::2", NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, ifa(10, 128, lo_idx) + attr(1, socket.inet_pton(10, "::2"))))
r = ask(NETLINK_ROUTE, nl_req(22, NLM_F_REQUEST, ifa(10, 128, lo_idx) + attr(1, socket.inet_pton(10, "::1"))))
print(f"  GETADDR v6 ::1: ty={r[0][0]} fam={r[0][2][0]} prefix={r[0][2][1]}")

rt4 = rtm(2, 32)
rt6 = rtm(10, 128)
show_err("GETROUTE v4 short hdr", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, b"\x02\0\0\0"))
show_err("GETROUTE v4 short RTA_DST", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt4 + attr(1, b"\x7f\x00")))
show_err("GETROUTE v4 short RTA_FLOW", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt4 + attr(1, b"\x7f\0\0\1") + attr(11, b"\x01\x00")))
show_err("GETROUTE v4 short RTA_IIF", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt4 + attr(1, b"\x7f\0\0\1") + attr(3, b"\x01\x00")))
r = ask(NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt4 + attr(1, b"\x7f\0\0\1\xaa\xbb\xcc\xdd")))
print(f"  GETROUTE v4 8B RTA_DST: ty={r[0][0]}")
show_err("GETROUTE v6 short RTA_DST", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt6 + attr(1, b"\0"*4)))
show_err("GETROUTE v6 short RTA_SRC", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt6 + attr(1, socket.inet_pton(10, "::1")) + attr(2, b"\0"*4)))
show_err("GETROUTE v6 short RTA_IIF", NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt6 + attr(1, socket.inet_pton(10, "::1")) + attr(3, b"\x01\x00")))
r = ask(NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt6 + attr(1, socket.inet_pton(10, "::1") + b"\xaa\xbb\xcc\xdd")))
print(f"  GETROUTE v6 20B RTA_DST: ty={r[0][0]}")
r = ask(NETLINK_ROUTE, nl_req(26, NLM_F_REQUEST, rt6 + attr(1, socket.inet_pton(10, "::1")) + attr(11, b"\x01\x00")))
print(f"  GETROUTE v6 short RTA_FLOW: ty={r[0][0]}")

show_err("GETNSID empty", NETLINK_ROUTE, nl_req(90, NLM_F_REQUEST, b"\0"*4))
show_err("GETNSID short PID", NETLINK_ROUTE, nl_req(90, NLM_F_REQUEST, b"\0"*4 + attr(2, b"\x01\x00")))

print("-- NETLINK_GET_STRICT_CHK dumps & filtering")
def dump_summary(label, ty, body, strict=True):
    res = ask(NETLINK_ROUTE, nl_req(ty, NLM_F_REQUEST|NLM_F_DUMP, body), strict=strict, cap=True, ext=True)
    items = [m for m in res if m[0] not in ("ERR", "DONE")]
    done = res[-1] if res else None
    print(f"  {label}: n={len(items)} item_filt={items[0][1] if items else None} done={done}")

dump_summary("LINK strict 4B", 18, b"\0"*4)
dump_summary("LINK strict idx=1", 18, ifi(lo_idx))
dump_summary("LINK strict bad MASTER 2B", 18, ifi() + attr(10, b"\x01\x00"))
dump_summary("LINK strict unknown IFNAME", 18, ifi() + attr(3, b"lo\0"))
dump_summary("LINK strict kind=dummy", 18, ifi() + attr(18, attr(1, b"dummy\0")))
dump_summary("LINK strict all", 18, ifi())

dump_summary("ADDR strict 4B", 22, b"\x02\0\0\0")
dump_summary("ADDR strict prefix=8", 22, ifa(2, 8))
dump_summary("ADDR strict 16B ifinfomsg", 22, b"\x02" + b"\0"*15)
dump_summary("ADDR strict d0 v4", 22, ifa(2, 0, d0_idx))
dump_summary("ADDR strict lo unspec", 22, ifa(0, 0, lo_idx))
dump_summary("ADDR strict bad idx 999", 22, ifa(2, 0, 999))

dump_summary("ROUTE strict 4B", 26, b"\x02\0\0\0")
dump_summary("ROUTE strict 16B ifinfomsg", 26, b"\x02" + b"\0"*15)
dump_summary("ROUTE strict scope=254", 26, rtm(2, scope=254))
dump_summary("ROUTE strict bad flag=1", 26, rtm(2, flags=1))
dump_summary("ROUTE strict CLONED", 26, rtm(2, flags=0x200))
dump_summary("ROUTE strict table=254 v4", 26, rtm(2, table=254))
dump_summary("ROUTE strict table=100 v4", 26, rtm(2, table=100))
dump_summary("ROUTE strict RTA_OIF=d0 v4", 26, rtm(2, table=254) + attr(4, struct.pack("I", d0_idx)))
dump_summary("ROUTE strict RTA_OIF=999 v4", 26, rtm(2) + attr(4, struct.pack("I", 999)))
dump_summary("ROUTE strict RTA_OIF 2B", 26, rtm(2) + attr(4, b"\x01\x00"))
dump_summary("ROUTE strict RTA_DST unsup", 26, rtm(2) + attr(1, b"\x7f\0\0\1"))

dump_summary("RULE strict 4B", 34, b"\x02\0\0\0")
dump_summary("RULE strict table=254", 34, rtm(2, table=254))
dump_summary("RULE strict 16B ifinfomsg", 34, b"\x02" + b"\0"*15)
dump_summary("RULE strict v4 ok", 34, rtm(2))
dump_summary("RULE strict bad fam 99", 34, rtm(99))

dump_summary("NEIGH strict 4B", 30, b"\x02\0\0\0")
dump_summary("NEIGH strict idx=1", 30, struct.pack("BBHiHBB", 2,0,0,lo_idx,0,0,0))
dump_summary("NEIGH strict v4 ok", 30, rtm(2))

print("-- NETLINK_GENERIC CAP_ACK/EXT_ACK & nlctrl GETPOLICY")
show_err("GENL unknown fam", NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST, genl(3) + attr(2, b"no_such\0")))
show_err("GENL short id 1B", NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST, genl(3) + attr(1, b"\x10")))
show_err("GENL GETPOLICY id=99 name=nlctrl", NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST|NLM_F_DUMP, genl(10) + attr(1, struct.pack("H", 99)) + attr(2, b"nlctrl\0")))
show_err("GENL GETFAMILY id=16 name=bad", NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST, genl(3) + attr(1, struct.pack("H", 16)) + attr(2, b"bad\0")))
show_err("GENL GETPOLICY op=99", NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST|NLM_F_DUMP, genl(10) + attr(1, struct.pack("H", 16)) + attr(10, struct.pack("I", 99))))
for label, body in [
    ("GETPOLICY all by id", genl(10) + attr(1, struct.pack("H", 16))),
    ("GETPOLICY all by name", genl(10) + attr(2, b"nlctrl\0")),
    ("GETPOLICY id=16 name=bad", genl(10) + attr(1, struct.pack("H", 16)) + attr(2, b"bad\0")),
    ("GETPOLICY op=3", genl(10) + attr(1, struct.pack("H", 16)) + attr(10, struct.pack("I", 3))),
    ("GETPOLICY op=10", genl(10) + attr(1, struct.pack("H", 16)) + attr(10, struct.pack("I", 10))),
]:
    res = ask(NETLINK_GENERIC, nl_req(16, NLM_F_REQUEST|NLM_F_DUMP, body))
    payloads = [m[2].hex() for m in res if m[0] not in ("ERR", "DONE")]
    print(f"  {label}: n={len(payloads)} done={res[-1]} first={payloads[0] if payloads else None} last={payloads[-1] if payloads else None}")
PY

echo "== 2. Initial-netns isolation of container 127.a.b.x loopback blocks"
ip link add br75 type bridge
ip addr add 10.75.0.1/24 dev br75
ip link set br75 up
unshare -n sleep 60 &
CPID=$!
sleep 0.2
ip link add veth75 type veth peer name eth0 netns $CPID
ip link set veth75 master br75
ip link set veth75 up
nsenter -t $CPID -n sh -c 'ip link set lo up; ip link set eth0 up; ip addr add 10.75.0.2/24 dev eth0; ip route add default via 10.75.0.1'
sleep 0.5

# Container runs:
# - private TCP + UDP servers on 127.0.0.1:17501 (must NOT be reachable from init-ns via 127.a.b.1)
# - public TCP server on 0.0.0.0:17502 (reachable via 10.75.0.2 and via init-ns DNAT forwarding)
rm -f /tmp/c_ready /tmp/c_log
nsenter -t $CPID -n python3 - <<'PY' &
import select, socket, time
ts_priv = socket.socket(); ts_priv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ts_priv.bind(("127.0.0.1", 17501)); ts_priv.listen(5)
us_priv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
us_priv.bind(("127.0.0.1", 17501))
ts_pub = socket.socket(); ts_pub.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ts_pub.bind(("0.0.0.0", 17502)); ts_pub.listen(5)
open("/tmp/c_ready", "w").close()
priv_hits = []
end = time.monotonic() + 10
while time.monotonic() < end:
    r, _, _ = select.select([ts_priv, us_priv, ts_pub], [], [], 0.2)
    for s in r:
        if s is ts_priv:
            c, peer = s.accept()
            data = c.recv(64).decode()
            priv_hits.append(f"tcp:{data}")
            c.sendall(b"priv-tcp-ok")
            c.close()
        elif s is us_priv:
            data, peer = s.recvfrom(64)
            priv_hits.append(f"udp:{data.decode()}")
            s.sendto(b"priv-udp-ok", peer)
        elif s is ts_pub:
            c, peer = s.accept()
            data = c.recv(64).decode()
            c.sendall(f"pub:{data}".encode())
            c.close()
    try:
        open("/tmp/c_stop").close()
        break
    except FileNotFoundError:
        pass
with open("/tmp/c_log", "w") as f:
    for h in priv_hits:
        f.write(h + "\n")
PY
SRVPID=$!
for i in $(seq 50); do [ -f /tmp/c_ready ] && break; sleep 0.1; done

# Publish 17502 on init-ns via PREROUTING + OUTPUT DNAT (with route_localnet + masquerade so
# native Linux routes replies from 10.75.0.2 back to 127.0.0.1)
echo 1 > /proc/sys/net/ipv4/conf/br75/route_localnet
nft -f - <<'NFT'
table ip nat75 {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport 17502 dnat to 10.75.0.2:17502
  }
  chain out {
    type nat hook output priority dstnat; policy accept;
    ip daddr 127.0.0.1 tcp dport 17502 dnat to 10.75.0.2:17502
  }
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "br75" masquerade
  }
}
NFT

python3 - <<'PY'
import errno, socket, time

# Normal initial-ns loopback on 127.0.0.1, 127.0.1.1 (Debian hostname), and unallocated 127.0.99.1
for label, ip, port in [
    ("init-lo 127.0.0.1", "127.0.0.1", 17503),
    ("init-lo 127.0.1.1", "127.0.1.1", 17504),
    ("init-lo 127.0.99.1", "127.0.99.1", 17505),
]:
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ip, port)); srv.listen(1)
    cli = socket.socket(); cli.settimeout(2)
    cli.connect((ip, port))
    acc, _ = srv.accept()
    cli.sendall(b"ok"); got = acc.recv(16)
    print(f"{label}: {got.decode()}")
    acc.close(); cli.close(); srv.close()

# Direct probes from init-ns to container loopback block candidates (127.0.1.1, 127.0.2.1, 127.0.3.1,
# plus IPv4-mapped ::ffff:127.0.2.1): TCP must be ECONNREFUSED; UDP must not reach container!
for ip in ("127.0.1.1", "127.0.2.1", "127.0.3.1"):
    c = socket.socket(); c.settimeout(1)
    try:
        c.connect((ip, 17501))
        print(f"probe tcp {ip}: LEAKED")
    except OSError as e:
        print(f"probe tcp {ip}: {errno.errorcode.get(e.errno, e.errno)}")
    c.close()
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(0.2)
    n = u.sendto(f"leak-u-{ip}".encode(), (ip, 17501))
    try:
        d, _ = u.recvfrom(64)
        print(f"probe udp-sendto {ip}: LEAKED({d})")
    except OSError:
        print(f"probe udp-sendto {ip}: blocked(sent={n})")
    u.close()
    uc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); uc.settimeout(0.2)
    uc.connect((ip, 17501))
    n = uc.send(f"leak-c-{ip}".encode())
    try:
        d = uc.recv(64)
        print(f"probe udp-conn {ip}: LEAKED({d})")
    except OSError:
        print(f"probe udp-conn {ip}: blocked(sent={n})")
    uc.close()

# IPv4-mapped IPv6 probe to ::ffff:127.0.2.1
c6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM); c6.settimeout(1)
try:
    c6.connect(("::ffff:127.0.2.1", 17501))
    print("probe tcp6 ::ffff:127.0.2.1: LEAKED")
except OSError as e:
    print(f"probe tcp6 ::ffff:127.0.2.1: {errno.errorcode.get(e.errno, e.errno)}")
c6.close()

# Published/routed container port via virtual IP and via OUTPUT DNAT still works!
for label, ip in [("virt 10.75.0.2", "10.75.0.2"), ("dnat 127.0.0.1", "127.0.0.1")]:
    c = socket.socket(); c.settimeout(2)
    c.connect((ip, 17502))
    c.sendall(label.encode())
    print(f"pub {label}: {c.recv(64).decode()}")
    c.close()
PY

# Container itself can still reach its own 127.0.0.1:17501 (TCP + UDP)
nsenter -t $CPID -n python3 - <<'PY'
import socket
c = socket.socket(); c.settimeout(2)
c.connect(("127.0.0.1", 17501))
c.sendall(b"self-tcp")
print("container self tcp:", c.recv(64).decode())
c.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(2)
u.sendto(b"self-udp", ("127.0.0.1", 17501))
print("container self udp:", u.recvfrom(64)[0].decode())
u.close()
PY

touch /tmp/c_stop
wait $SRVPID
echo "container priv hits:"
cat /tmp/c_log
rm -f /tmp/c_stop /tmp/c_ready /tmp/c_log
nft delete table ip nat75
kill $CPID 2>/dev/null || true
ip link del br75
