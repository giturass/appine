# docker-run-options: --cap-add SYS_ADMIN --security-opt apparmor=unconfined
# Regression difftest for procfs socket UID (sock_i_uid), nsfs/second-procfs inotify/fdinfo
# dev/ino, statm vs status VmData consistency, overlay hardlink/upper-layer inotify, and POSIX
# lock fdinfo + F_SETLKW waiters in /proc/locks.
set -eu
python3 - <<'PY'
import ctypes, fcntl, mmap, os, re, select, signal, socket, struct, subprocess, sys, time

libc = ctypes.CDLL(None, use_errno=True)

# 1. /proc/net/tcp reports the creator's fsuid (sock_i_uid) while in-flight in SCM_RIGHTS and
#    after transfer to a process with a different UID.
def tcp_uid(port):
    with open("/proc/net/tcp") as f:
        for line in f.read().splitlines()[1:]:
            w = line.split()
            if int(w[1].split(":")[1], 16) == port:
                return int(w[7])
    return None

pa, pb = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
r1, w1 = os.pipe()
r2, w2 = os.pipe()
sys.stdout.flush()
child = os.fork()
if child == 0:
    os.close(pa.fileno()); os.close(r1); os.close(w2)
    os.setresuid(1000, 1000, 1000)
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.bind(("127.0.0.1", 0))
    t.listen(1)
    port = t.getsockname()[1]
    pb.sendmsg([struct.pack("i", port)],
               [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", t.fileno()))])
    t.close()
    os.write(w1, b"1")
    os.read(r2, 1)
    os._exit(0)
os.close(pb.fileno()); os.close(w1); os.close(r2)
os.read(r1, 1)
# Creator closed its fd and socket is only in-flight in SCM_RIGHTS; still owned by UID 1000.
msg, anc, _, _ = pa.recvmsg(16, socket.CMSG_SPACE(4), socket.MSG_PEEK)
port = struct.unpack("i", msg)[0]
print("tcp uid inflight:", tcp_uid(port))
msg, anc, _, _ = pa.recvmsg(16, socket.CMSG_SPACE(4))
tfd = struct.unpack("i", anc[0][2][:4])[0]
# Now held only by root (UID 0); still reports creator's UID 1000.
print("tcp uid received:", tcp_uid(port))
os.close(tfd)
os.write(w2, b"1")
os.waitpid(child, 0)
pa.close(); os.close(r1); os.close(w2)

# 2. inotify fdinfo and /proc/self/fdinfo ino match stat for nsfs and a second procfs mount.
ifd = libc.inotify_init1(os.O_NONBLOCK)
ns_path = "/proc/self/ns/net"
ns_st = os.stat(ns_path)
ns_wd = libc.inotify_add_watch(ifd, ns_path.encode(), 0xfff)
ns_fd = os.open(ns_path, os.O_RDONLY)
os.makedirs("/tmp/proc2", exist_ok=True)
subprocess.check_call(["mount", "-t", "proc", "proc", "/tmp/proc2"])
p2_path = "/tmp/proc2/self/mounts"
p2_st = os.stat(p2_path)
p2_wd = libc.inotify_add_watch(ifd, p2_path.encode(), 0xfff)
ep = select.epoll()
p2_fd = os.open(p2_path, os.O_RDONLY)
ep.register(p2_fd, select.EPOLLIN)

def check_inotify(wd, st):
    dev = (os.major(st.st_dev) << 20) | os.minor(st.st_dev)
    for line in open(f"/proc/self/fdinfo/{ifd}"):
        if line.startswith(f"inotify wd:{wd:x} "):
            f = dict(x.split(":", 1) for x in line.split()[1:6])
            return int(f["ino"], 16) == st.st_ino, int(f["sdev"], 16) == dev
    return False, False

def check_epoll(fd, st):
    dev = (os.major(st.st_dev) << 20) | os.minor(st.st_dev)
    for line in open(f"/proc/self/fdinfo/{ep.fileno()}"):
        m = re.match(r"tfd:\s*(\d+)\s+events:\s*\S+\s+data:\s*\S+\s+pos:\d+\s+ino:([0-9a-f]+)\s+sdev:([0-9a-f]+)", line)
        if m and int(m.group(1)) == fd:
            return int(m.group(2), 16) == st.st_ino, int(m.group(3), 16) == dev
    return False, False

ns_fdinfo_ino = None
for line in open(f"/proc/self/fdinfo/{ns_fd}"):
    if line.startswith("ino:\t"):
        ns_fdinfo_ino = int(line.split()[1])
print("nsfs inotify:", check_inotify(ns_wd, ns_st), "fdinfo ino:", ns_fdinfo_ino == ns_st.st_ino)
print("proc2 inotify:", check_inotify(p2_wd, p2_st), "epoll:", check_epoll(p2_fd, p2_st))
ep.close(); os.close(p2_fd); os.close(ns_fd); os.close(ifd)
subprocess.check_call(["umount", "/tmp/proc2"])
os.rmdir("/tmp/proc2")

# 3. /proc/self/statm vs /proc/self/status consistency.
def read_vm():
    # Read statm and status back to back with no allocations in between.
    statm = [int(x) for x in open("/proc/self/statm").read().split()]
    st = {}
    for line in open("/proc/self/status"):
        for k in ("VmSize", "VmData", "VmStk", "VmExe", "VmLib"):
            if line.startswith(k + ":\t"):
                st[k] = int(line.split()[1])
    return statm, st

m_priv = mmap.mmap(-1, 64 * 1024, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
m_shr = mmap.mmap(-1, 64 * 1024, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS)
statm, st = read_vm()
print("statm size==VmSize:", statm[0] * 4 == st["VmSize"],
      "statm data==VmData+VmStk:", statm[5] * 4 == st["VmData"] + st["VmStk"],
      "VmData<VmSize:", st["VmData"] < st["VmSize"],
      "VmExe>0:", st["VmExe"] > 0)
m_priv.close(); m_shr.close()

# 4. POSIX lock shows in fdinfo of the open file that took it, and F_SETLKW waiters show `->`.
lk_path = "/tmp/proc_locks_reg"
open(lk_path, "w").close()
f1 = os.open(lk_path, os.O_RDWR)
f2 = os.open(lk_path, os.O_RDWR)
fcntl.fcntl(f2, fcntl.F_SETLK, struct.pack("hhqqi", fcntl.F_WRLCK, 0, 10, 20, 0))
f1_locks = [l for l in open(f"/proc/self/fdinfo/{f1}") if l.startswith("lock:")]
f2_locks = [l for l in open(f"/proc/self/fdinfo/{f2}") if l.startswith("lock:")]
print("posix fdinfo f1 empty:", len(f1_locks) == 0, "f2 count:", len(f2_locks))
ino = str(os.fstat(f2).st_ino)
r, w = os.pipe()
sys.stdout.flush()
waiter = os.fork()
if waiter == 0:
    os.close(r)
    cf = os.open(lk_path, os.O_RDWR)
    def on_sig(*a):
        raise InterruptedError()
    signal.signal(signal.SIGUSR1, on_sig)
    os.write(w, b"1")
    try:
        fcntl.fcntl(cf, fcntl.F_SETLKW, struct.pack("hhqqi", fcntl.F_WRLCK, 0, 15, 30, 0))
    except InterruptedError:
        pass
    os._exit(0)
os.close(w)
os.read(r, 1)
# Wait until waiter's `->` line appears in /proc/locks (up to 1s).
found = []
for _ in range(50):
    lines = [l for l in open("/proc/locks").read().splitlines() if f":{ino} " in l]
    if any("-> POSIX" in l for l in lines):
        found = lines
        break
    time.sleep(0.02)
owner_pos = waiter_pos = None
for l in found:
    m = re.match(r"(\d+): (-> )?POSIX  ADVISORY  WRITE (\d+) \S+ (\d+) (\d+)$", l)
    if m:
        pos, arrow, pid, s, e = m.groups()
        if arrow is None and int(pid) == os.getpid() and (s, e) == ("10", "29"):
            owner_pos = pos
        if arrow == "-> " and int(pid) == waiter and (s, e) == ("15", "44"):
            waiter_pos = pos
print("proc/locks waiter matched:", owner_pos is not None and owner_pos == waiter_pos)
os.kill(waiter, signal.SIGUSR1)
os.waitpid(waiter, 0)
after = [l for l in open("/proc/locks").read().splitlines() if f":{ino} " in l and "->" in l]
print("waiter cleared after signal:", len(after) == 0)
os.close(f1); os.close(f2); os.unlink(lk_path)

# 5. Overlay hardlink removal (no false IN_DELETE_SELF while another link exists) & upper-layer
#    watches seeing attribute changes, hardlinks, renames, and removals through overlay.
os.makedirs("/tmp/ovl_hl", exist_ok=True)
subprocess.check_call(["mount", "-t", "tmpfs", "tmpfs", "/tmp/ovl_hl"])
for d in ("l/d", "u", "w", "m"):
    os.makedirs(f"/tmp/ovl_hl/{d}", exist_ok=True)
open("/tmp/ovl_hl/l/d/f", "w").write("hello\n")
subprocess.check_call(["mount", "-t", "overlay", "overlay", "-o",
                       "lowerdir=/tmp/ovl_hl/l,upperdir=/tmp/ovl_hl/u,workdir=/tmp/ovl_hl/w",
                       "/tmp/ovl_hl/m"])
ifd = libc.inotify_init1(os.O_NONBLOCK)
wf = libc.inotify_add_watch(ifd, b"/tmp/ovl_hl/m/d/f", 0xfff)
os.link("/tmp/ovl_hl/m/d/f", "/tmp/ovl_hl/m/d/lnk")
# Drain link events
try: os.read(ifd, 65536)
except BlockingIOError: pass
os.unlink("/tmp/ovl_hl/m/d/f")
data = os.read(ifd, 65536)
masks = []
i = 0
while i < len(data):
    wd, mask, cookie, n = struct.unpack_from("iIII", data, i)
    i += 16 + n
    if wd == wf:
        masks.append(mask)
print("unlink with remaining hardlink has ATTRIB, no DELETE_SELF:",
      any(m & 0x4 for m in masks), not any(m & 0x400 for m in masks))

# Upper-layer watches see chmod/utime/link/rename/unlink of an upper-created file through overlay.
open("/tmp/ovl_hl/m/d/u1", "w").write("upper\n")
wu_dir = libc.inotify_add_watch(ifd, b"/tmp/ovl_hl/u/d", 0xfff)
wu_file = libc.inotify_add_watch(ifd, b"/tmp/ovl_hl/u/d/u1", 0xfff)
def read_events(target_wd):
    try: raw = os.read(ifd, 65536)
    except BlockingIOError: raw = b""
    out = []
    pos = 0
    while pos < len(raw):
        wd, mask, cookie, n = struct.unpack_from("iIII", raw, pos)
        name = raw[pos + 16:pos + 16 + n].rstrip(b"\0").decode()
        pos += 16 + n
        if wd == target_wd:
            out.append((mask, name))
    return out
read_events(-1)
os.chmod("/tmp/ovl_hl/m/d/u1", 0o600)
print("upper chmod ATTRIB:", any(m & 0x4 for m, _ in read_events(wu_file)))
os.utime("/tmp/ovl_hl/m/d/u1", (1, 2))
print("upper utime ATTRIB:", any(m & 0x4 for m, _ in read_events(wu_file)))
os.link("/tmp/ovl_hl/m/d/u1", "/tmp/ovl_hl/m/d/u1_lnk")
ev = read_events(wu_dir)
print("upper link CREATE:", any((m & 0x100) and nm == "u1_lnk" for m, nm in ev))
os.unlink("/tmp/ovl_hl/m/d/u1_lnk")
ev = read_events(wu_dir)
print("upper unlink DELETE:", any((m & 0x200) and nm == "u1_lnk" for m, nm in ev))
os.rename("/tmp/ovl_hl/m/d/u1", "/tmp/ovl_hl/m/d/u2")
ev = read_events(wu_dir)
print("upper rename MOVED_FROM+TO:",
      any((m & 0x40) and nm == "u1" for m, nm in ev),
      any((m & 0x80) and nm == "u2" for m, nm in ev))
os.close(ifd)
subprocess.check_call(["umount", "/tmp/ovl_hl/m"])
subprocess.check_call(["umount", "/tmp/ovl_hl"])
os.rmdir("/tmp/ovl_hl")
PY
