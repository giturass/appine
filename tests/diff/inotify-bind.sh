# docker-run-options: --cap-add SYS_ADMIN --security-opt apparmor=unconfined
# Watches follow the inode through a bind mount. Separate procfs instances have distinct roots.
set -eu
cd /tmp
mkdir original alias proc-bind proc-new
touch original/file
mount --bind original alias
mount --bind /proc proc-bind
mount -t proc proc proc-new

python3 - <<'PY'
import ctypes
import errno
import os
import struct

libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(os.O_NONBLOCK)
assert fd >= 0
MODIFY, ATTRIB, IGNORED = 0x2, 0x4, 0x8000
MASK_CREATE, MASK_ADD = 0x10000000, 0x20000000

def watch(path, mask):
    return libc.inotify_add_watch(fd, path, mask)

def events():
    # File watches report fixed-size events with no filename.
    return list(struct.iter_unpack("iIII", os.read(fd, 4096)))

wd = watch(b"original/file", MODIFY)
assert wd >= 0
assert watch(b"alias/file", MODIFY | MASK_CREATE) == -1
assert ctypes.get_errno() == errno.EEXIST
assert watch(b"alias/file", ATTRIB | MASK_ADD) == wd
with open("alias/file", "ab") as f:
    f.write(b"x")
os.chmod("original/file", 0o600)
assert events() == [(wd, MODIFY, 0, 0), (wd, ATTRIB, 0, 0)]

assert watch(b"alias/file", ATTRIB) == wd
with open("original/file", "ab") as f:
    f.write(b"y")
assert libc.inotify_rm_watch(fd, wd) == 0
assert events() == [(wd, IGNORED, 0, 0)]

proc = watch(b"/proc", ATTRIB)
assert proc >= 0
assert watch(b"proc-bind", ATTRIB) == proc
other = watch(b"proc-new", ATTRIB)
assert other >= 0 and other != proc

# Keep the nsfs inode alive between lookups through the two procfs instances.
pin = os.open("/proc/self/ns/mnt", os.O_RDONLY)
ns = watch(b"/proc/self/ns/mnt", ATTRIB)
assert ns >= 0
assert watch(b"proc-new/self/ns/mnt", ATTRIB) == ns
os.close(pin)
print("bind watch identity and masks ok")
PY
