# docker-run-options: --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined
# FUSE through fuse-overlayfs (libfuse 3.17, which reads requests with splice and writes data
# replies through vmsplice and splice): the mount and its line in mountinfo, lookups, stat,
# readdir, symlinks, reads and writes (one larger than a request), O_APPEND (two processes appending
# at once) and O_TRUNC, creating,
# renaming and removing files and directories, links, chmod, truncate and times, xattrs, statfs,
# running a script and a program from the mount, mappings (read page by page as they are touched:
# far-apart pages, read(2) and write(2) on mapped buffers, fork, MADV_DONTNEED, mremap,
# MAP_POPULATE, SIGBUS past the end, a library loaded from the mount), nodes forgotten after
# drop_caches unless open or a current directory (a daemon of its own), the errors the daemon and the
# kernel return, the daemon leaving when the mount goes and when a lazily unmounted one is no
# longer used, ENOTCONN once the daemon is killed, and
# the errors of mount options and of /dev/fuse before a mount. The layers are on one tmpfs on
# both sides. Not compared: inode numbers (fuse-overlayfs takes them from the layers' files) and
# times
cd /tmp
umount -l /tmp/fuse/m 2>/dev/null
umount -l /tmp/fuse 2>/dev/null
rm -rf fuse
mkdir fuse
mount -t tmpfs tmpfs fuse
cd fuse
mkdir -p l/sub u w m
echo hello > l/a.txt
echo deep > l/sub/b
ln -s a.txt l/link
printf '#!/bin/sh\necho script ran "$@"\n' > l/s.sh
chmod 755 l/s.sh
cp /bin/busybox l/busybox
fuse-overlayfs -o lowerdir=/tmp/fuse/l,upperdir=/tmp/fuse/u,workdir=/tmp/fuse/w m || exit 1
echo "-- mountinfo"
awk '$5 == "/tmp/fuse/m" { for (i = 1; $i != "-"; i++); print $6, $(i + 1), $(i + 2), $(i + 3) }' \
    /proc/self/mountinfo
echo "-- read"
ls -a m | sort
ls -l m | awk 'NR > 1 { print $1, $3, $4, ($1 ~ /^d/ ? "-" : $5), $9, $10, $11 }' | sort -k5
cat m/a.txt m/sub/b m/link
readlink m/link
stat -c '%n %F %a %h %u %g' m m/a.txt m/sub m/link
stat -c '%n %s' m/a.txt m/link
stat -f -c '%t %b %l' m | awk '{ print $1, ($2 > 0), $3 }'
test -e m/missing || echo "missing: no"
cat m/missing 2>&1
cat m/a.txt/x 2>&1
echo "-- write"
echo one > m/new
echo two >> m/new
cat m/new
printf abcdefghij > m/trunc
: > m/trunc
stat -c '%n %s' m/trunc
printf 0123456789 > m/t2
truncate -s 4 m/t2
cat m/t2; echo
truncate -s 8 m/t2
od -An -c m/t2
dd if=/dev/urandom of=/tmp/fuse/big bs=1024 count=700 2>/dev/null
cp /tmp/fuse/big m/big
cmp /tmp/fuse/big m/big && echo "big: same"
stat -c '%n %s' m/big
python3 -c '
import os
fd = os.open("/tmp/fuse/m/new", os.O_RDWR)
os.lseek(fd, 1, 0)
os.write(fd, b"X")
print(os.pread(fd, 3, 0), os.lseek(fd, 0, 2), os.fstat(fd).st_size)
os.close(fd)
fd = os.open("/tmp/fuse/m/a.txt", os.O_WRONLY | os.O_APPEND)
os.write(fd, b"more\n")
os.close(fd)
'
cat m/a.txt
cat l/a.txt
echo "-- namespace"
mkdir m/d m/d/e
mkdir m/d 2>&1
echo f > m/d/f
mv m/d/f m/d/g
mv m/new m/d/
ls m/d | sort
rmdir m/d 2>&1
ln m/d/g m/d/h
stat -c '%n %h' m/d/g
ln -s ../a.txt m/d/sl
cat m/d/sl
rm m/d/g m/d/sl
rmdir m/d/e
rm m/link
ls m m/d | sort
mv m/sub m/sub2
cat m/sub2/b
cd m/sub2 && pwd && cd /tmp/fuse
python3 -c '
import os
os.chdir("/tmp/fuse/m/d")
print(os.getcwd())
os.rename("/tmp/fuse/m/d", "/tmp/fuse/m/d2")
print(os.getcwd())
for f, n in [(os.rename, ("/tmp/fuse/m/d2", "/tmp/fuse/m/d2/x")), (os.rmdir, ("/tmp/fuse/m",)),
             (os.unlink, ("/tmp/fuse/m/sub2",)), (os.mkdir, ("/tmp/fuse/m/no/x",))]:
    try:
        f(*n)
    except OSError as e:
        print(f.__name__, e.strerror)
'
echo "-- attributes"
chmod 640 m/a.txt
stat -c '%n %a' m/a.txt
chown 1:2 m/trunc
stat -c '%n %u %g' m/trunc
touch -d '2001-02-03 04:05:06' m/trunc
stat -c '%n %Y' m/trunc
python3 -c '
import os
p = "/tmp/fuse/m/trunc"
os.setxattr(p, "user.note", b"kept")
print(os.getxattr(p, "user.note"), "user.note" in os.listxattr(p))
os.removexattr(p, "user.note")
try:
    os.getxattr(p, "user.note")
except OSError as e:
    print("getxattr", e.strerror)
'
python3 -c '
import fcntl, os, resource, signal
p = "/tmp/fuse/m/new2"
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"ab")
fcntl.fcntl(fd, fcntl.F_SETFL, os.O_APPEND)
os.lseek(fd, 0, 0)
os.write(fd, b"cd")
fcntl.fcntl(fd, fcntl.F_SETFL, 0)
os.lseek(fd, 0, 0)
os.write(fd, b"X")
os.close(fd)
print(open(p, "rb").read())
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
resource.setrlimit(resource.RLIMIT_FSIZE, (6, hard))
fd = os.open(p, os.O_WRONLY)
print("write past the limit:", os.pwrite(fd, b"123456", 2))
try:
    os.pwrite(fd, b"7", 6)
except OSError as e:
    print("write at the limit:", e.strerror)
os.close(fd)
resource.setrlimit(resource.RLIMIT_FSIZE, (hard, hard))
fd = os.open(p, os.O_RDWR)
os.posix_fallocate(fd, 0, 100)
print("fallocated:", os.fstat(fd).st_size)
os.close(fd)
'
# Two processes appending at once: no line lands on another
for i in 1 2; do
    (for j in $(seq 200); do echo "writer $i line $j" >> m/log; done) &
done
wait
echo "appended: $(wc -l < m/log) lines, $(sort -u m/log | wc -l) distinct"
echo "-- programs and mappings"
m/s.sh arg
m/busybox echo "busybox ran"
printf '#!/tmp/fuse/m/busybox sh\necho "interpreter on the mount"\n' > m/i.sh
chmod 755 m/i.sh
m/i.sh
cp m/busybox m/sleep
m/sleep 2 &
sleep 0.5
python3 -c '
import os
try:
    os.open("/tmp/fuse/m/sleep", os.O_WRONLY)
except OSError as e:
    print("writing a running program:", e.strerror)
fd = os.open("/tmp/fuse/m/s.sh", os.O_WRONLY)
try:
    os.execv("/tmp/fuse/m/s.sh", ["s.sh"])
except OSError as e:
    print("running a file open for writing:", e.strerror)
'
wait
python3 -c '
import mmap
with open("/tmp/fuse/m/sub2/b", "rb") as f:
    m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    print(m[:4])
    for flags, prot in [(mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE),
                        (mmap.MAP_PRIVATE, mmap.PROT_READ | mmap.PROT_EXEC)]:
        try:
            mmap.mmap(f.fileno(), 0, flags=flags, prot=prot)
            print("mapped")
        except OSError as e:
            print("mmap:", e.strerror)
'
mount -o remount,noexec m
python3 -c '
import mmap
with open("/tmp/fuse/m/sub2/b", "rb") as f:
    try:
        mmap.mmap(f.fileno(), 0, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_EXEC)
    except OSError as e:
        print("noexec mmap:", e.strerror)
'
mount -o remount,exec m
echo "-- mappings read on demand"
python3 -c '
import ctypes, hashlib, os, signal
libc = ctypes.CDLL(None, use_errno=True)
vp, sz = ctypes.c_void_p, ctypes.c_size_t
libc.mmap.restype = libc.mremap.restype = vp
libc.mmap.argtypes = [vp, sz, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mremap.argtypes = [vp, sz, sz, ctypes.c_int]
libc.madvise.argtypes = [vp, sz, ctypes.c_int]
libc.read.argtypes = libc.write.argtypes = [ctypes.c_int, vp, sz]
libc.read.restype = libc.write.restype = ctypes.c_ssize_t
R, W, SHARED, PRIVATE, POPULATE, P = 1, 2, 1, 2, 0x8000, 4096
data = b"".join(hashlib.sha256(b"%d" % i).digest() * 128 for i in range(768)) + b"tail"
with open("/tmp/fuse/m/big", "wb") as f:
    f.write(data)
fd = os.open("/tmp/fuse/m/big", os.O_RDWR)
def page(a, p):
    return ctypes.string_at(a + p * P, P)
def same(a, pages):
    return all(page(a, p) == data[p * P:(p + 1) * P] for p in pages)
a = libc.mmap(None, len(data), R, SHARED, fd, 0)
print("pages far apart:", same(a, [700, 3, 512, 255, 0, 767]))
whole = hashlib.sha256(ctypes.string_at(a, len(data))).digest()
print("whole:", whole == hashlib.sha256(data).digest(), page(a, 768)[:6])
b = libc.mmap(None, len(data), R, PRIVATE, fd, 0)
out = os.open("/tmp/fuse/out", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
n = libc.write(out, b + 5 * P + 7, 40 * P)
print("write(2) from it:", n, os.pread(out, 40 * P, 0) == data[5 * P + 7:45 * P + 7])
c = libc.mmap(None, len(data), R | W, PRIVATE, fd, 0)
os.lseek(out, 0, 0)
n = libc.read(out, c + 300 * P + 10, 6)
want = data[300 * P:300 * P + 10] + data[5 * P + 7:5 * P + 13] + data[300 * P + 16:301 * P]
print("read(2) into it:", n, page(c, 300) == want)
ctypes.memmove(c + 400 * P, b"parent", 6)
pid = os.fork()
if pid == 0:
    ok = page(c, 400)[:6] == b"parent" and same(c, [401, 600])
    ctypes.memmove(c + 401 * P, b"child", 5)
    os._exit(0 if ok else 1)
_, status = os.waitpid(pid, 0)
print("fork:", os.waitstatus_to_exitcode(status), same(c, [401]))
libc.madvise(c + 400 * P, P, 4)
print("MADV_DONTNEED:", same(c, [400]))
d = libc.mmap(None, 8 * P, R, PRIVATE, fd, 100 * P)
d = libc.mremap(d, 8 * P, 64 * P, 1)
print("mremap:", ctypes.string_at(d + 60 * P, P) == data[160 * P:161 * P])
e = libc.mmap(None, len(data) + 3 * P, R, PRIVATE | POPULATE, fd, 0)
print("MAP_POPULATE:", same(e, [2, 766]))
pid = os.fork()
if pid == 0:
    ctypes.string_at(e + 770 * P, 1)
    os._exit(0)
_, status = os.waitpid(pid, 0)
print("past the end:", signal.Signals(os.WTERMSIG(status)).name)
'
# Independent mappings and descriptor I/O share the inode, including across processes.
python3 - <<'PYTEST' || exit 1
import mmap, os, signal, sqlite3, subprocess, sys

p = mmap.PAGESIZE
path = "m/mapped"
fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
os.ftruncate(fd, 2 * p)
ro = os.open(path, os.O_RDONLY)
reader = mmap.mmap(ro, p, access=mmap.ACCESS_READ, offset=p)
assert reader[0] == 0
writer = mmap.mmap(fd, 2 * p)
writer[p] = 41
assert reader[0] == 41 and os.pread(ro, 1, p) == b")"
os.pwrite(fd, b"B", p + 1)
assert reader[:2] == writer[p:p+2] == b")B"
writer.flush()
with open("u/mapped", "rb") as upper:
    upper.seek(p)
    assert upper.read(2) == b")B"
# A private store stays private, including across later descriptor writes to the same page.
private = mmap.mmap(fd, p, access=mmap.ACCESS_COPY, offset=p)
private[0] = 90
os.pwrite(fd, b"x", p + 1)
assert private[:2] == b"ZB" and reader[:2] == b")x"
private.close()
os.pwrite(fd, b"B", p + 1)
# Removing a populated page must invalidate the child's translations as well as the parent's.
ready, notify = os.pipe()
resume, go = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(ready)
    os.close(go)
    assert writer[p] == 41
    os.write(notify, b"r")
    os.read(resume, 1)
    writer[p]
    os._exit(1)
os.close(notify)
os.close(resume)
assert os.read(ready, 1) == b"r"
os.ftruncate(fd, p)
os.write(go, b"g")
assert os.waitpid(pid, 0)[1] & 127 == signal.SIGBUS
for pipe in (ready, go):
    os.close(pipe)
os.ftruncate(fd, 2 * p)
assert reader[:3] == bytes(3)
writer[p:p+3] = b"old"
writer.madvise(mmap.MADV_REMOVE, p, p)
assert reader[:3] == bytes(3) and os.pread(fd, 3, p) == bytes(3)
writer[p:p+2] = b")B"
os.fsync(fd)
with open("u/mapped", "rb") as upper:
    upper.seek(p)
    assert upper.read(2) == b")B"
os.close(fd)
writer[p+2] = 67
writer.close()
reader.close()
os.close(ro)
with open(path, "rb") as f:
    f.seek(p)
    assert f.read(3) == b")BC"
# Exit and exec must persist the final store even after the original descriptor is closed.
for finish in ('os._exit(0)', 'os.execl("/bin/true", "true")'):
    pid = os.fork()
    if pid == 0:
        child_fd = os.open(path, os.O_RDWR)
        last = mmap.mmap(child_fd, p, trackfd=False)
        os.close(child_fd)
        last[:4] = b"exit"
        exec(finish)
    assert os.waitpid(pid, 0)[1] == 0
    with open("u/mapped", "r+b") as upper:
        assert upper.read(4) == b"exit"
        upper.seek(0)
        upper.write(bytes(4))
os.unlink(path)
print("shared mmap and descriptor I/O: ok", flush=True)

db = "m/mapped.db"
def connect():
    return sqlite3.connect(db, isolation_level=None)
parent = connect()
assert parent.execute("pragma journal_mode=wal").fetchone() == ("wal",)
parent.execute("create table t (n integer)")
parent.execute("insert into t values(1)")
parent.execute("begin")
def rows(conn):
    return conn.execute("select n from t order by n").fetchall()
assert rows(parent) == [(1,)]
# Exec gives the writer a fresh SQLite process and a separate mapping of the WAL index.
subprocess.run([sys.executable, "-c",
    "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
    "c.execute('insert into t values(2)'); c.commit(); c.close()", db], check=True)
assert rows(parent) == [(1,)]
parent.execute("commit")
assert rows(parent) == [(1,), (2,)]
assert parent.execute("pragma wal_checkpoint(truncate)").fetchone() == (0, 0, 0)
assert parent.execute("pragma integrity_check").fetchone() == ("ok",)
parent.close()
os.unlink(db)
print("SQLite WAL snapshot, checkpoint and integrity: ok")
PYTEST
cp /usr/lib/libz.so.1 m/libz.so.1
python3 -c '
import ctypes, zlib
z = ctypes.CDLL("/tmp/fuse/m/libz.so.1")
z.zlibVersion.restype = ctypes.c_char_p
print("a library from the mount:", z.zlibVersion().decode() == zlib.ZLIB_RUNTIME_VERSION)
'
rm m/big m/libz.so.1 out
echo "-- upper layer"
# Without RENAME_WHITEOUT (Appine) fuse-overlayfs leaves .wh. files instead of whiteout devices
find u ! -type c ! -name '.wh.*' | sort | sed 's/^/  /'
echo "-- unmount"
umount m && echo unmounted
sleep 1
pgrep -x fuse-overlayfs || echo "daemon gone"
echo "-- daemon killed"
fuse-overlayfs -o lowerdir=/tmp/fuse/l,upperdir=/tmp/fuse/u,workdir=/tmp/fuse/w m
cat m/a.txt
stat -c %F m
pkill -9 -x fuse-overlayfs
sleep 1
ls m 2>&1
stat m 2>&1 | head -1
umount m && echo unmounted
echo "-- lazy unmount"
# The connection lasts while a file or a current directory is in the detached mount, and is
# aborted (the daemon exits) when the last one goes
fuse-overlayfs -o lowerdir=/tmp/fuse/l,upperdir=/tmp/fuse/u,workdir=/tmp/fuse/w m || exit 1
exec 3< m/a.txt
umount -l m && echo detached
sleep 1
pgrep -x fuse-overlayfs > /dev/null && echo "daemon still serving"
cat <&3
exec 3<&-
sleep 1
pgrep -x fuse-overlayfs || echo "daemon gone"
fuse-overlayfs -o lowerdir=/tmp/fuse/l,upperdir=/tmp/fuse/u,workdir=/tmp/fuse/w m || exit 1
sh -c 'cd /tmp/fuse/m && umount -l /tmp/fuse/m && echo "detached from inside"
sleep 1
pgrep -x fuse-overlayfs > /dev/null && echo "daemon still serving"
head -1 a.txt'
sleep 1
pgrep -x fuse-overlayfs || echo "daemon gone"
echo "-- forgetting nodes"
# A daemon speaking the protocol itself, recording for each name the lookups not yet forgotten
cat > fz.py <<'EOF'
import ctypes, os, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open("/dev/fuse", os.O_RDWR)
opts = b"fd=%d,rootmode=40000,user_id=0,group_id=0" % fd
if libc.mount(b"fz", b"/tmp/fuse/z", b"fuse.fz", 0, opts) != 0:
    sys.exit("mount: %d" % ctypes.get_errno())
names = {1: {b"d": 2, b"f1": 3, b"f2": 4, b"f3": 5}, 2: {b"g": 6}}
label = {2: "d", 3: "f1", 4: "f2", 5: "f3", 6: "g"}
held = {n: 0 for n in label}
backing = os.open("fz-data", os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
os.ftruncate(backing, 8192)
def attr(n):
    mode = 0o40755 if n in names else 0o100644
    size = os.fstat(backing).st_size if n == 3 else 1 if n == 5 else 0
    if n == 5:
        mode = 0o100755
    return struct.pack("<6Q4x4x4xIIIIIII", n, size, 0, 0, 0, 0, mode, 1, 0, 0, 0, 4096, 0)
def state():
    with open("/tmp/fuse/zs.new", "w") as f:
        f.write("".join("%s %d\n" % (label[n], held[n]) for n in sorted(label)))
    os.rename("/tmp/fuse/zs.new", "/tmp/fuse/zs")
def reply(unique, error=0, body=b""):
    os.write(fd, struct.pack("<IiQ", 16 + len(body), -error, unique) + body)
while True:
    try:
        m = os.read(fd, 1 << 17)
    except OSError:
        break
    _, op, unique, node = struct.unpack_from("<IIQQ", m)
    body = m[40:]
    if op == 26:
        reply(unique, body=struct.pack("<IIIIHHIIHHI28x", 7, 31, 0, 0, 0, 0, 4096, 1, 0, 0, 0))
    elif op == 1:
        child = names.get(node, {}).get(body.rstrip(b"\0"))
        if child is None:
            reply(unique, 2)
            continue
        held[child] += 1
        state()
        reply(unique, body=struct.pack("<QQQQII", child, 0, 3600, 3600, 0, 0) + attr(child))
    elif op == 3:
        reply(unique, body=struct.pack("<QII", 3600, 0, 0) + attr(node))
    elif op in (14, 27):
        # Read-only opens of f1 keep its cached pages. A read/write open drops them.
        flags = struct.unpack_from("<I", body)[0]
        keep = node == 3 and flags & os.O_ACCMODE == os.O_RDONLY
        reply(unique, body=struct.pack("<QII", 0, 2 if keep else 0, 0))
    elif op == 15 and node == 3:
        _, offset, length = struct.unpack_from("<QQI", body)
        reply(unique, body=os.pread(backing, length, offset))
    elif op == 16 and node == 3:
        _, offset, length = struct.unpack_from("<QQI", body)
        n = os.pwrite(backing, body[40:40 + length], offset)
        reply(unique, body=struct.pack("<II", n, 0))
    elif op == 16 and node == 4:
        # The control inode supplies offsets for a notification about the separate data inode.
        offset, length = struct.unpack_from("<qq", body, 40)
        reply(0, -2, struct.pack("<Qqq", 3, offset, length))
        reply(unique, body=struct.pack("<II", 16, 0))
    elif op == 15 and node == 5:
        reply(unique, 5)  # EIO reading the executable
    elif op in (18, 29, 25):
        reply(unique)
    elif op == 2:
        held[node] -= struct.unpack_from("<Q", body)[0]
        state()
    elif op == 42:
        count = struct.unpack_from("<I", body)[0]
        for i in range(count):
            n, k = struct.unpack_from("<QQ", body, 8 + 16 * i)
            held[n] -= k
        state()
    elif op != 36:
        reply(unique, 38)
open("/tmp/fuse/fz-exited", "w").close()
EOF
mkdir z
python3 fz.py &
for i in 1 2 3 4 5 6 7 8 9 10; do
    grep -q ' /tmp/fuse/z ' /proc/self/mountinfo && break
    sleep 0.5
done
# Both processes have already installed translations when the daemon invalidates a single page.
python3 - <<'PYINVAL' || exit 1
import mmap, os, struct
data = os.open("z/f1", os.O_RDONLY)
view = mmap.mmap(data, 8192, access=mmap.ACCESS_READ)
control = os.open("z/f2", os.O_WRONLY)
backing = os.open("fz-data", os.O_RDWR)
ready, signal_ready = os.pipe()
go, signal_go = os.pipe()
assert (view[0], view[4096]) == (0, 0)
pid = os.fork()
if pid == 0:
    try:
        assert (view[0], view[4096]) == (0, 0)
        os.write(signal_ready, b"r")
        os.close(signal_go)
        assert os.read(go, 1) == b"g"
        os._exit(0 if (view[0], view[4096]) == (0, 66) else 1)
    except BaseException:
        os._exit(2)
os.close(signal_ready)
os.close(go)
assert os.read(ready, 1) == b"r"
os.pwrite(backing, b"A", 0)
os.pwrite(backing, b"B", 4096)
def notify(offset, length):
    assert os.pwrite(control, struct.pack("<qq", offset, length), 0) == 16
notify(-1, 0)
assert (view[0], view[4096]) == (0, 0)
notify(4097, 1)
os.write(signal_go, b"g")
assert os.waitpid(pid, 0)[1] == 0
assert (view[0], view[4096]) == (0, 66)
notify(0, 0)
assert (view[0], view[4096]) == (65, 66)
view.close()
print("FUSE inode invalidation refreshed both mappings in range")

writer = os.open("z/f1", os.O_RDWR)
with mmap.mmap(writer, 8192, access=mmap.ACCESS_WRITE) as shared:
    assert shared[0:1] == b"A"
    os.pwrite(backing, b"C", 0)
    kept = os.open("z/f1", os.O_RDONLY)
    assert shared[0:1] == b"A"
    shared[4096:4097] = b"D"
    reopened = os.open("z/f1", os.O_RDWR)
    with mmap.mmap(reopened, 8192, access=mmap.ACCESS_READ) as second:
        assert shared[0:1] == second[0:1] == b"C"
        assert shared[4096:4097] == second[4096:4097] == b"D"
    shared.flush()
    assert os.pread(backing, 1, 4096) == b"D"
    os.close(reopened)
    os.close(kept)
os.close(writer)
print("FUSE reopen honored KEEP_CACHE and preserved dirty data")
PYINVAL
# A retry opens the shebang interpreter on FUSE, then the daemon fails its first read.
# Both files have been opened, and only the outer script supplied any bytes.
printf '#!/tmp/fuse/z/f3\n' > launch
chmod 755 launch
python3 - <<'PYEXEC'
import ctypes, errno, os, struct
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_NONBLOCK)
names = {}
for target in (b"launch", b"z/f3"):
    wd = libc.inotify_add_watch(fd, target, 0x31)
    assert wd >= 0
    names[wd] = target.decode()
try:
    os.execv("./launch", ["launch"])
except OSError as exc:
    print("FUSE exec error:", errno.errorcode[exc.errno])
events = os.read(fd, 4096)
for wd, mask, _, _ in struct.iter_unpack("iIII", events):
    print("FUSE exec event:", names[wd], hex(mask))
os.close(fd)
PYEXEC
stat -c %n z/f1 z/f2 z/f3 z/d/g
exec 3< z/f2
(cd z/d && sleep 3) &
sleeper=$!
sleep 1
# FUSE_FORGET has no reply, so the daemon records a forget some time after drop_caches: wait up
# to 5 s for the counts Linux leaves before printing them
settle() {
    for i in $(seq 50); do
        [ "$(cat zs)" = "$1" ] && break
        sleep 0.1
    done
    cat zs
}
# Docker mounts /proc/sys read-only
mount -o remount,rw /proc/sys 2>/dev/null
# What nothing uses goes; the open file and the current directory stay
echo 2 > /proc/sys/vm/drop_caches
settle "$(printf 'd 1\nf1 0\nf2 1\nf3 0\ng 0')"
exec 3<&-
wait $sleeper
echo 2 > /proc/sys/vm/drop_caches
settle "$(printf 'd 0\nf1 0\nf2 0\nf3 0\ng 0')"
# Only the socket message holds the path when the node cache is reclaimed.
python3 - <<'PYRIGHTS'
import ctypes, os, socket
libc = ctypes.CDLL(None, use_errno=True)
sender, receiver = socket.socketpair()
for fd in (os.open("z/f1", os.O_PATH), libc.syscall(428, -100, b"z/f2", 0)):  # open_tree
    ino = os.fstat(fd).st_ino
    socket.send_fds(sender, [b"x"], [fd])
    os.close(fd)
    with open("/proc/sys/vm/drop_caches", "w") as drop:
        drop.write("2")
    _, (fd,), _, _ = socket.recv_fds(receiver, 1, 1)
    print("received O_PATH keeps inode", os.fstat(fd).st_ino == ino)
    os.close(fd)
sender.close()
receiver.close()
PYRIGHTS
echo 2 > /proc/sys/vm/drop_caches
settle "$(printf 'd 0\nf1 0\nf2 0\nf3 0\ng 0')"
# Only sendmsg, then its queued message, holds this mount. After a lazy detach, its
# daemon serves the received fd until the last unread copy is discarded.
python3 - <<'PYMOUNT' || exit 1
import ctypes, errno, os, socket, threading, time
libc = ctypes.CDLL(None, use_errno=True)
sender, receiver = socket.socketpair()
receiver.settimeout(5)
filled = 0
while True:
    try:
        filled += sender.send(b"x" * 16384, socket.MSG_DONTWAIT)
    except BlockingIOError:
        break
fd = os.open("z/f1", os.O_PATH)
ino = os.fstat(fd).st_ino
worker = threading.Thread(target=socket.send_fds, args=(sender, [b"r"], [fd]), daemon=True)
worker.start()
task = "/proc/self/task/%d/" % worker.native_id
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    with open(task + "stat") as st, open(task + "syscall") as call:
        if st.read().rsplit(")", 1)[1].split()[0] == "S" and call.read().split()[0] == "211":
            break
    time.sleep(0.01)
else:
    raise RuntimeError("sender did not block in sendmsg")
os.close(fd)
def expect_busy(stage):
    r = libc.umount2(b"z", 0)
    assert r == -1 and ctypes.get_errno() == errno.EBUSY, (stage, r, ctypes.get_errno())
    print("mount busy", stage)
expect_busy("during send")
while filled:
    filled -= len(receiver.recv(min(filled, 65536)))
worker.join(5)
assert not worker.is_alive()
expect_busy("while queued")
assert libc.umount2(b"z", 2) == 0  # MNT_DETACH
_, (fd,), _, _ = socket.recv_fds(receiver, 1, 1)
assert os.fstat(fd).st_ino == ino
socket.send_fds(sender, [b"d"], [fd])
os.close(fd)
receiver.close()
sender.close()
deadline = time.monotonic() + 5
while not os.path.exists("fz-exited"):
    if time.monotonic() >= deadline:
        raise RuntimeError("FUSE daemon still serving after last queued fd was discarded")
    time.sleep(0.01)
print("detached mount released")
PYMOUNT
rm -f fz.py fz-data zs fz-exited
echo "-- mount errors"
python3 -c '
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
def mount(data, fstype=b"fuse"):
    r = libc.mount(b"none", b"/tmp/fuse/m", fstype, 0, data)
    print(fstype.decode(), data.decode(), "->", "ok" if r == 0 else errno.errorcode[ctypes.get_errno()])
    if r == 0:
        libc.umount2(b"/tmp/fuse/m", 2)
fd = os.open("/dev/fuse", os.O_RDWR)
for call in [lambda: os.read(fd, 8192), lambda: os.write(fd, bytes(16))]:
    try:
        call()
    except OSError as e:
        print("unattached /dev/fuse:", errno.errorcode[e.errno])
mount(b"rootmode=40000,user_id=0,group_id=0")
mount(b"fd=%d,user_id=0,group_id=0" % fd)
mount(b"fd=%d,rootmode=40000,user_id=0,group_id=0,bogus" % fd)
mount(b"fd=%d,rootmode=170000,user_id=0,group_id=0" % fd)
mount(b"fd=0,rootmode=40000,user_id=0,group_id=0")
mount(b"fd=99,rootmode=40000,user_id=0,group_id=0")
mount(b"fd=%d,rootmode=40000,user_id=0,group_id=0" % fd, b"fuse.")
mount(b"fd=%d,rootmode=40000,user_id=0,group_id=0,blksize=4096" % fd)
mount(b"fd=%d,rootmode=40000,user_id=0,group_id=0,subtype=x" % fd, b"fuse.test")
import fcntl, struct
other = os.open("/dev/fuse", os.O_RDWR)
# A clone from an unattached one is left out: EINVAL in 6.1 and 6.8, EPERM in the newer kernel
# of CI (tests/guest/linux61.c checks the 6.1 answer)
try:
    fcntl.ioctl(other, 0x8004e500, struct.pack("I", 99))
except OSError as e:
    print("clone of a bad fd:", errno.errorcode[e.errno])
mount(b"fd=%d,rootmode=40000,user_id=0,group_id=0" % fd, b"fuse.test")
mount(b"fd=%d" % fd)
try:
    os.read(fd, 100)
except OSError as e:
    print("short read:", errno.errorcode[e.errno])
'
cd /tmp
umount fuse
