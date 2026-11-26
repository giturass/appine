# docker-run-options: --privileged
# Differential tests for netns/nft PREROUTING priority, process_vm_readv/writev check order,
# and setgroups / PR_CAPBSET_DROP errno ordering against native Linux.
set -e
cd /tmp

echo "== 1. PREROUTING filter priority vs DNAT"
echo 1 > /proc/sys/net/ipv4/ip_forward
ip link add br0 address 02:00:00:00:90:01 type bridge
ip addr add 10.90.0.1/24 dev br0
ip link set br0 up
ip link add br1 address 02:00:00:00:91:01 type bridge
ip addr add 10.91.0.1/24 dev br1
ip link set br1 up

container() {
    unshare -n sleep 600 &
    eval "$1=$!"
    sleep 0.3
    ip link add "veth$1" type veth peer name eth0 netns "$(eval echo \$$1)"
    ip link set "veth$1" master "$2"
    ip link set "veth$1" up
    nsenter -t "$(eval echo \$$1)" -n sh -c "ip link set lo up; ip link set eth0 up; ip addr add $3/24 dev eth0; ip route add default via $4"
}
container A br0 10.90.0.2 10.90.0.1
container B br1 10.91.0.3 10.91.0.1
sleep 1

cat > /tmp/srv.py <<'PY'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen()
open(sys.argv[2], "w").close()
while True:
    c, _ = s.accept()
    c.sendall(f"port-{sys.argv[1]}".encode())
    c.close()
PY
cat > /tmp/cli.py <<'PY'
import errno, socket, sys
addr, port, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = socket.socket()
c.settimeout(1.5)
try:
    c.connect((addr, port))
    print(f"{label}: OK {c.recv(64).decode()}")
except TimeoutError:
    print(f"{label}: TIMEOUT")
except OSError as e:
    print(f"{label}: {errno.errorcode.get(e.errno, e.errno)}")
finally:
    c.close()
PY

servers=""
for p in 80 81 82 90 91; do
    rm -f "/tmp/ready-$p"
    nsenter -t "$B" -n python3 /tmp/srv.py "$p" "/tmp/ready-$p" &
    servers="$servers $!"
    for i in $(seq 100); do [ -f "/tmp/ready-$p" ] && break; sleep 0.05; done
done

# Outer (init) PREROUTING:
# - raw (-300): sees pre-DNAT destination (10.90.0.1:808x). Drops dport 80 (must NOT fire on 8080->80),
#   rejects 10.90.0.1:8081 (must fire on 8081->81), sets mark 0x22 on 8082.
# - nat (-100): DNATs 8080->B:80, 8081->B:81, 8082->B:82.
# - post (0): sees post-DNAT destination (10.91.0.3:8x). Drops dport 8080 (must NOT fire on 8080->80),
#   rejects mark 0x22 + 10.91.0.3:82 (must fire on 8082->82).
nft -f - <<'NFT'
table ip t {
    chain raw {
        type filter hook prerouting priority raw; policy accept;
        tcp dport 80 drop
        ip daddr 10.90.0.1 tcp dport 8081 reject with tcp reset
        ip daddr 10.90.0.1 tcp dport 8082 meta mark set 0x22
    }
    chain nat {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "br0" tcp dport 8080 dnat to 10.91.0.3:80
        iifname "br0" tcp dport 8081 dnat to 10.91.0.3:81
        iifname "br0" tcp dport 8082 dnat to 10.91.0.3:82
    }
    chain post {
        type filter hook prerouting priority filter; policy accept;
        tcp dport 8080 drop
        meta mark 0x22 ip daddr 10.91.0.3 tcp dport 82 reject with tcp reset
    }
}
NFT

nsenter -t "$A" -n python3 /tmp/cli.py 10.90.0.1 8080 "init-dnat-pass-8080"
nsenter -t "$A" -n python3 /tmp/cli.py 10.90.0.1 8081 "init-dnat-pre-reject-8081"
nsenter -t "$A" -n python3 /tmp/cli.py 10.90.0.1 8082 "init-dnat-post-reject-8082"

# Boundary around NF_IP_PRI_NAT_DST (-100) on B, even with a nat chain declared at priority +50:
# - f_m101 (-101 < -100): sees pre-DNAT destination (9090/9091), drops dport 90 (must NOT fire on
#   9090->90), rejects dport 9091 (must fire on 9091->91).
# - f_0 (0 >= -100): sees post-DNAT destination (90/91), drops dport 9090 (must NOT fire on 9090->90).
# - n50 (priority 50): DNATs 9090->90, 9091->91.
nsenter -t "$B" -n nft -f - <<'NFT'
table ip tb {
    chain f_m101 {
        type filter hook prerouting priority -101; policy accept;
        tcp dport 90 drop
        tcp dport 9091 reject with tcp reset
    }
    chain f_0 {
        type filter hook prerouting priority 0; policy accept;
        tcp dport 9090 drop
    }
    chain n50 {
        type nat hook prerouting priority 50; policy accept;
        tcp dport 9090 redirect to :90
        tcp dport 9091 redirect to :91
    }
}
NFT

nsenter -t "$A" -n python3 /tmp/cli.py 10.91.0.3 9090 "b-natdst-boundary-pass-9090"
nsenter -t "$A" -n python3 /tmp/cli.py 10.91.0.3 9091 "b-natdst-boundary-pre-reject-9091"

kill $servers "$A" "$B" 2>/dev/null || true
wait $servers "$A" "$B" 2>/dev/null || true
nft delete table ip t
ip link del br0
ip link del br1

echo "== 2. process_vm_readv/writev, setgroups, and PR_CAPBSET_DROP check orders"
python3 - <<'PY'
import ctypes, errno, os

libc = ctypes.CDLL(None, use_errno=True)
class Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

SYS_process_vm_readv = 270
SYS_process_vm_writev = 271
SYS_setgroups = 159
SYS_prctl = 167
PR_CAPBSET_DROP = 24
CLONE_NEWUSER = 0x10000000

def sc(nr, *args):
    ctypes.set_errno(0)
    r = libc.syscall(nr, *[ctypes.c_ulong(a & ((1 << 64) - 1)) for a in args])
    e = ctypes.get_errno()
    return r, (errno.errorcode.get(e, str(e)) if r < 0 else "OK")

buf = ctypes.create_string_buffer(16)
l0 = (Iovec * 1)(Iovec(ctypes.addressof(buf), 0))
l1 = (Iovec * 1)(Iovec(ctypes.addressof(buf), 4))
r0 = (Iovec * 1)(Iovec(ctypes.addressof(buf), 0))
r1 = (Iovec * 1)(Iovec(ctypes.addressof(buf), 4))
pid = os.getpid()

for name, nr, args in [
    ("readv flags!=0 liovcnt=0", SYS_process_vm_readv, (pid, 0, 0, 0, 0, 1)),
    ("readv liovcnt=0 riovcnt=1025", SYS_process_vm_readv, (-1, 1, 0, 1, 1025, 0)),
    ("readv l0 riovcnt=1025", SYS_process_vm_readv, (-1, ctypes.addressof(l0), 1, 1, 1025, 0)),
    ("writev l0 riovcnt=1025", SYS_process_vm_writev, (-1, ctypes.addressof(l0), 1, 1, 1025, 0)),
    ("readv l1 riovcnt=0", SYS_process_vm_readv, (-1, ctypes.addressof(l1), 1, 1, 0, 0)),
    ("readv l1 r0", SYS_process_vm_readv, (-1, ctypes.addressof(l1), 1, ctypes.addressof(r0), 1, 0)),
    ("readv l1 riovcnt=1025", SYS_process_vm_readv, (-1, ctypes.addressof(l1), 1, 1, 1025, 0)),
    ("readv l1 rvec=bad", SYS_process_vm_readv, (-1, ctypes.addressof(l1), 1, 1, 1, 0)),
    ("readv l1 r1 pid=-1", SYS_process_vm_readv, (-1, ctypes.addressof(l1), 1, ctypes.addressof(r1), 1, 0)),
    ("readv liovcnt=1025", SYS_process_vm_readv, (-1, 1, 1025, 0, 0, 0)),
]:
    print(f"pvm {name}: {sc(nr, *args)}", flush=True)

for name, nr, args in [
    ("root setgroups(-1, bad)", SYS_setgroups, (-1, 1)),
    ("root setgroups(65537, bad)", SYS_setgroups, (65537, 1)),
    ("root setgroups(0, bad)", SYS_setgroups, (0, 1)),
    ("root setgroups(1, bad)", SYS_setgroups, (1, 1)),
    ("root PR_CAPBSET_DROP(41)", SYS_prctl, (PR_CAPBSET_DROP, 41, 0, 0, 0)),
    ("root PR_CAPBSET_DROP(-1)", SYS_prctl, (PR_CAPBSET_DROP, -1, 0, 0, 0)),
]:
    print(f"cred {name}: {sc(nr, *args)}", flush=True)

c = os.fork()
if c == 0:
    os.setgid(65534)
    os.setuid(65534)
    for name, nr, args in [
        ("unpriv setgroups(-1, bad)", SYS_setgroups, (-1, 1)),
        ("unpriv setgroups(65537, bad)", SYS_setgroups, (65537, 1)),
        ("unpriv setgroups(1, bad)", SYS_setgroups, (1, 1)),
        ("unpriv setgroups(0, null)", SYS_setgroups, (0, 0)),
        ("unpriv PR_CAPBSET_DROP(41)", SYS_prctl, (PR_CAPBSET_DROP, 41, 0, 0, 0)),
        ("unpriv PR_CAPBSET_DROP(-1)", SYS_prctl, (PR_CAPBSET_DROP, -1, 0, 0, 0)),
        ("unpriv PR_CAPBSET_DROP(0)", SYS_prctl, (PR_CAPBSET_DROP, 0, 0, 0, 0)),
    ]:
        print(f"cred {name}: {sc(nr, *args)}", flush=True)
    os._exit(0)
os.waitpid(c, 0)

c2 = os.fork()
if c2 == 0:
    libc.unshare(CLONE_NEWUSER)
    # No gid_map written yet: may_setgroups() is false -> EPERM before EINVAL/EFAULT
    print(f"userns nomap setgroups(-1, bad): {sc(SYS_setgroups, -1, 1)}", flush=True)
    print(f"userns nomap setgroups(1, bad): {sc(SYS_setgroups, 1, 1)}", flush=True)
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny\n")
    with open("/proc/self/gid_map", "w") as f:
        f.write("0 0 1\n")
    # setgroups=deny with gid_map written: still EPERM before EINVAL/EFAULT
    print(f"userns deny setgroups(-1, bad): {sc(SYS_setgroups, -1, 1)}", flush=True)
    print(f"userns deny setgroups(1, bad): {sc(SYS_setgroups, 1, 1)}", flush=True)
    os._exit(0)
os.waitpid(c2, 0)
PY
