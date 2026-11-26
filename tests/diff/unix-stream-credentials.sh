# AF_UNIX credentials at enqueue and across peeks, MSG_WAITALL and SO_PASSCRED changes.
python3 - <<'PY'
import array, fcntl, os, socket, struct, termios, time

own = struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
anonymous = struct.pack("3i", 0, 65534, 65534)

def check(passcred, wait_for_reader, toggle=False):
    reader, writer = socket.socketpair()
    reader.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, passcred)
    writer.sendall(b"a")
    child = os.fork()
    if child == 0:
        try:
            if wait_for_reader:
                # Send after MSG_WAITALL consumes the first byte and has to wait for the next.
                queued = array.array("i", [0])
                deadline = time.monotonic() + 10
                while True:
                    fcntl.ioctl(reader, termios.FIONREAD, queued, True)
                    if queued[0] == 0:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(0.001)
            if toggle:
                reader.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, not passcred)
            writer.sendall(b"b")
        finally:
            writer.shutdown(socket.SHUT_WR)
        os._exit(0)

    expected = b"a" if passcred else b"ab"
    if not wait_for_reader:
        assert os.waitpid(child, 0)[1] == 0
        assert reader.recv(2, socket.MSG_PEEK) == expected
    data, control, _, _ = reader.recvmsg(2, socket.CMSG_SPACE(12), socket.MSG_WAITALL)
    assert data == expected, (passcred, wait_for_reader, data)
    child_cred = struct.pack("3i", child, os.getuid(), os.getgid())
    if toggle and not passcred:
        assert control == [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, child_cred)]
    elif passcred and not toggle:
        assert control == [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, own)]
    else:
        assert not control
    if passcred:
        reader.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        data, control, _, _ = reader.recvmsg(1, socket.CMSG_SPACE(12))
        assert data == b"b"
        expected_cred = anonymous if toggle else child_cred
        assert control == [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, expected_cred)]
    if wait_for_reader:
        assert os.waitpid(child, 0)[1] == 0
    reader.close()
    writer.close()

for passcred in (False, True):
    for wait_for_reader in (False, True):
        check(passcred, wait_for_reader)
    check(passcred, wait_for_reader=True, toggle=True)

def expect(reader, data, cred, flags=0):
    # A nonblocking read makes an unexpected merge or split fail without hanging.
    msg, control, _, _ = reader.recvmsg(32, socket.CMSG_SPACE(12), flags | socket.MSG_DONTWAIT)
    assert (msg, control) == (data, [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, cred)])

for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET, socket.SOCK_DGRAM):
    reader, writer = socket.socketpair(socket.AF_UNIX, kind)
    writer.send(b"a")
    child = os.fork()
    if child == 0:
        writer.send(b"b")
        os._exit(0)
    assert os.waitpid(child, 0)[1] == 0
    # Request credentials on the sender only, then send declared credentials with both ends off.
    writer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    writer.send(b"c")
    writer.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 0)
    writer.sendmsg([b"d"], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, own)])
    reader.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    if kind == socket.SOCK_STREAM:
        expect(reader, b"ab", anonymous, socket.MSG_PEEK)
        expect(reader, b"ab", anonymous)
        expect(reader, b"cd", own)
    else:
        for data, cred in ((b"a", anonymous), (b"b", anonymous), (b"c", own), (b"d", own)):
            expect(reader, data, cred)
    reader.close()
    writer.close()

# A datagram sent to the same socket shares its sender and receiver queue.
with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
    sock.bind(b"\0self-passcred-" + str(os.getpid()).encode())
    sock.sendto(b"a", sock.getsockname())
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    sock.sendto(b"b", sock.getsockname())
    expect(sock, b"a", anonymous)
    expect(sock, b"b", own)

# A pending connection records credentials before accept, even with SO_PASSCRED off.
for kind in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET):
    with socket.socket(socket.AF_UNIX, kind) as listener, socket.socket(socket.AF_UNIX, kind) as writer:
        listener.bind(b"\0passcred-" + str(os.getpid()).encode())
        listener.listen()
        writer.connect(listener.getsockname())
        writer.send(b"a")
        reader, _ = listener.accept()
        with reader:
            writer.send(b"b")
            reader.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            expect(reader, b"a", own)
            expect(reader, b"b", anonymous)
print("Unix stream credential boundaries ok")
PY
