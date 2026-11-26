# AF_UNIX: connected datagram disconnect/reconnect ECONNRESET and queue purge, /proc/net/unix
# datagram states, datagram POLLOUT vs peer SHUT_RD, SOCK_STREAM MSG_TRUNC, SIOCOUTQ (TIOCOUTQ),
# read-only setsockopt (SO_SNDLOWAT/SO_ACCEPTCONN/SO_PEERCRED), and skipping non-SOL_SOCKET cmsgs.
set -e
cd /tmp
cat > unix_fixes.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SIOCOUTQ
#define SIOCOUTQ TIOCOUTQ
#endif

static int poll_ev(int s)
{
    struct pollfd p = {s, POLLIN | POLLOUT | POLLRDHUP | POLLERR | POLLHUP, 0};
    poll(&p, 1, 0);
    return p.revents;
}

static int so_err(int s)
{
    int e = -1;
    socklen_t l = sizeof e;
    getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &l);
    return e;
}

static socklen_t mkabs(struct sockaddr_un *a, const char *n)
{
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    strcpy(a->sun_path + 1, n);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(n));
}

static int proc_state(int s)
{
    struct stat st;
    if (fstat(s, &st) != 0)
        return -1;
    FILE *f = fopen("/proc/net/unix", "r");
    if (!f)
        return -2;
    char line[512];
    int found = -3;
    while (fgets(line, sizeof line, f)) {
        unsigned long long ino;
        unsigned flags, ty, state;
        if (sscanf(line, "%*x: %*x %*x %x %x %x %llu", &flags, &ty, &state, &ino) == 4 &&
            ino == (unsigned long long)st.st_ino) {
            found = (int)state;
            break;
        }
    }
    fclose(f);
    return found;
}

static volatile sig_atomic_t got_sigpipe = 0;
static void on_sigpipe(int s)
{
    (void)s;
    got_sigpipe++;
}

static void show_addr(const char *tag, const struct sockaddr_un *a, socklen_t l)
{
    if (l <= 2)
        printf("%s: len=%u (unnamed)\n", tag, (unsigned)l);
    else if (a->sun_path[0] == 0)
        printf("%s: len=%u @%.*s\n", tag, (unsigned)l, (int)(l - 3), a->sun_path + 1);
    else
        printf("%s: len=%u %.*s\n", tag, (unsigned)l, (int)(l - 2), a->sun_path);
}

static void show_outq(const char *tag, int s)
{
    int v = -1;
    errno = 0;
    int r = ioctl(s, SIOCOUTQ, &v);
    if (r < 0)
        printf("outq %s: err=%s\n", tag, strerror(errno));
    else
        printf("outq %s: ok nonzero=%d\n", tag, v > 0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sockaddr_un sa, sb, sc, unspec = {.sun_family = AF_UNSPEC};
    char buf[32];

    /* 1. Datagram POLLOUT vs peer SHUT_RD */
    printf("-- dgram pollout\n");
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        printf("pair init: %#x\n", poll_ev(sv[0]));
        shutdown(sv[1], SHUT_RD);
        printf("pair peer SHUT_RD: %#x\n", poll_ev(sv[0]));
        close(sv[0]);
        close(sv[1]);

        int a = socket(AF_UNIX, SOCK_DGRAM, 0);
        int b = socket(AF_UNIX, SOCK_DGRAM, 0);
        socklen_t lb = mkabs(&sb, "ufix_poll_b");
        bind(b, (struct sockaddr *)&sb, lb);
        connect(a, (struct sockaddr *)&sb, lb);
        while (send(a, "x", 1, MSG_DONTWAIT) == 1) {
        }
        printf("unidir full: %#x\n", poll_ev(a));
        shutdown(b, SHUT_RD);
        printf("unidir full + peer SHUT_RD: %#x\n", poll_ev(a));
        errno = 0;
        ssize_t sr = send(a, "x", 1, MSG_DONTWAIT);
        printf("unidir send after peer SHUT_RD: %zd %s\n", sr, sr < 0 ? strerror(errno) : "");
        close(a);
        close(b);
    }

    /* 2. Connected datagram disconnect/reconnect ECONNRESET + /proc/net/unix states */
    printf("-- dgram reset & proc\n");
    {
        int a = socket(AF_UNIX, SOCK_DGRAM, 0);
        int b = socket(AF_UNIX, SOCK_DGRAM, 0);
        int c = socket(AF_UNIX, SOCK_DGRAM, 0);
        socklen_t la = mkabs(&sa, "ufix_r_a");
        socklen_t lb = mkabs(&sb, "ufix_r_b");
        socklen_t lc = mkabs(&sc, "ufix_r_c");
        bind(a, (struct sockaddr *)&sa, la);
        bind(b, (struct sockaddr *)&sb, lb);
        bind(c, (struct sockaddr *)&sc, lc);
        printf("init st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b), proc_state(c));

        connect(a, (struct sockaddr *)&sb, lb);
        printf("a->b st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b), proc_state(c));

        connect(c, (struct sockaddr *)&sb, lb);
        printf("a->b,c->b st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b), proc_state(c));

        connect(a, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("after a AF_UNSPEC st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b),
               proc_state(c));

        connect(c, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("after c AF_UNSPEC st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b),
               proc_state(c));

        /* Mutual a <-> b: unread in b + b AF_UNSPEC resets a and purges b */
        connect(a, (struct sockaddr *)&sb, lb);
        connect(b, (struct sockaddr *)&sa, la);
        send(b, "for_a", 5, 0);
        send(a, "for_b", 5, 0);
        /* Reconnecting to the same peer does not purge or reset */
        connect(b, (struct sockaddr *)&sa, la);
        printf("same-peer reconnect: a_ev=%#x a_err=%d\n", poll_ev(a), so_err(a));

        connect(b, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("after b AF_UNSPEC st: a=%d b=%d\n", proc_state(a), proc_state(b));
        printf("after b AF_UNSPEC: a_ev=%#x\n", poll_ev(a));
        errno = 0;
        ssize_t r1 = recv(a, buf, sizeof buf, MSG_DONTWAIT);
        printf("a recv1: %zd %s\n", r1, r1 < 0 ? strerror(errno) : "");
        errno = 0;
        ssize_t r2 = recv(a, buf, sizeof buf, MSG_DONTWAIT);
        printf("a recv2: %zd %.*s\n", r2, (int)(r2 > 0 ? r2 : 0), buf);
        errno = 0;
        ssize_t rb = recv(b, buf, sizeof buf, MSG_DONTWAIT);
        printf("b purged recv: %zd %s\n", rb, rb < 0 ? strerror(errno) : "");

        /* Empty b + b AF_UNSPEC does not reset a */
        connect(b, (struct sockaddr *)&sa, la);
        connect(b, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("empty b AF_UNSPEC: a_ev=%#x a_err=%d\n", poll_ev(a), so_err(a));

        /* Mutual a <-> b: unread in b + b reconnect -> c resets a */
        connect(b, (struct sockaddr *)&sa, la);
        send(a, "for_b2", 6, 0);
        connect(b, (struct sockaddr *)&sc, lc);
        printf("b reconnect->c st: a=%d b=%d c=%d\n", proc_state(a), proc_state(b), proc_state(c));
        printf("b reconnect->c: a_ev=%#x a_err=%d a_err2=%d\n", poll_ev(a), so_err(a), so_err(a));

        /* Unidirectional b -> a (a not connected to b): purges b, no reset on a */
        connect(a, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        connect(b, (struct sockaddr *)&sa, la);
        sendto(a, "uni", 3, 0, (struct sockaddr *)&sb, lb);
        connect(b, (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("unidir b->a AF_UNSPEC: a_ev=%#x a_err=%d b_recv=%zd\n", poll_ev(a), so_err(a),
               recv(b, buf, sizeof buf, MSG_DONTWAIT));

        close(a);
        close(b);
        close(c);

        /* socketpair(DGRAM): sv[1] AF_UNSPEC with unread resets sv[0]; close does not */
        int sv[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        printf("sp init st: %d %d\n", proc_state(sv[0]), proc_state(sv[1]));
        send(sv[0], "hi", 2, 0);
        connect(sv[1], (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        printf("sp sv[1] AF_UNSPEC: st=(%d,%d) ev=%#x err=%d\n", proc_state(sv[0]),
               proc_state(sv[1]), poll_ev(sv[0]), so_err(sv[0]));
        close(sv[0]);
        close(sv[1]);

        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        send(sv[0], "hi", 2, 0);
        send(sv[1], "for0", 4, 0);
        close(sv[1]);
        printf("sp peer close: st=%d ev=%#x err=%d\n", proc_state(sv[0]), poll_ev(sv[0]),
               so_err(sv[0]));
        errno = 0;
        ssize_t sr = send(sv[0], "x", 1, MSG_DONTWAIT);
        printf("sp send to dead peer: %zd %s, st=%d, recv=%zd\n", sr,
               sr < 0 ? strerror(errno) : "", proc_state(sv[0]),
               recv(sv[0], buf, sizeof buf, MSG_DONTWAIT));
        close(sv[0]);
    }

    /* 3. SOCK_STREAM MSG_TRUNC (Linux af_unix ignores MSG_TRUNC on SOCK_STREAM) */
    printf("-- stream MSG_TRUNC\n");
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        write(sv[0], "0123456789", 10);
        memset(buf, 'X', sizeof buf);
        ssize_t n = recv(sv[1], buf, 4, MSG_TRUNC);
        printf("recv MSG_TRUNC(4): %zd %.4s\n", n, buf);
        errno = 0;
        n = recv(sv[1], NULL, 3, MSG_TRUNC);
        printf("recv NULL MSG_TRUNC(3): %zd %s\n", n, n < 0 ? strerror(errno) : "");
        struct iovec iov = {buf, 3};
        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};
        n = recvmsg(sv[1], &msg, MSG_TRUNC);
        printf("recvmsg MSG_TRUNC(3): %zd flags=%#x %.3s\n", n, msg.msg_flags, buf);
        n = recvfrom(sv[1], buf, 10, MSG_TRUNC, NULL, NULL);
        printf("recvfrom rest: %zd %.3s\n", n, buf);
        close(sv[0]);
        close(sv[1]);
    }

    /* 4. SIOCOUTQ (TIOCOUTQ) */
    printf("-- SIOCOUTQ\n");
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
        show_outq("stream empty", sv[0]);
        write(sv[0], "hello", 5);
        show_outq("stream sender", sv[0]);
        show_outq("stream receiver", sv[1]);
        read(sv[1], buf, 2);
        show_outq("stream after partial read", sv[0]);
        read(sv[1], buf, 3);
        show_outq("stream after full read", sv[0]);
        write(sv[0], "bye", 3);
        close(sv[1]);
        show_outq("stream after peer close", sv[0]);
        close(sv[0]);

        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        show_outq("dgram empty", sv[0]);
        write(sv[0], "hello", 5);
        show_outq("dgram sender", sv[0]);
        connect(sv[1], (struct sockaddr *)&unspec, sizeof unspec.sun_family);
        show_outq("dgram after peer purge", sv[0]);
        close(sv[0]);
        close(sv[1]);

        int a = socket(AF_UNIX, SOCK_DGRAM, 0), b = socket(AF_UNIX, SOCK_DGRAM, 0);
        socklen_t lb = mkabs(&sb, "ufix_outq_b");
        bind(b, (struct sockaddr *)&sb, lb);
        sendto(a, "hello", 5, 0, (struct sockaddr *)&sb, lb);
        show_outq("unconn dgram after sendto", a);
        recv(b, buf, sizeof buf, 0);
        show_outq("unconn dgram after recv", a);
        close(a);
        close(b);

        int l = socket(AF_UNIX, SOCK_STREAM, 0);
        socklen_t la = mkabs(&sa, "ufix_outq_l");
        bind(l, (struct sockaddr *)&sa, la);
        listen(l, 1);
        show_outq("listener", l);
        errno = 0;
        int r = ioctl(l, SIOCOUTQ, (void *)0x1000);
        printf("outq bad ptr: %d %s\n", r, r < 0 ? strerror(errno) : "");
        close(l);
    }

    /* 5. Read-only setsockopt options */
    printf("-- readonly setsockopt\n");
    {
        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        int opts[] = {SO_SNDLOWAT, SO_ACCEPTCONN, SO_PEERCRED};
        const char *names[] = {"SO_SNDLOWAT", "SO_ACCEPTCONN", "SO_PEERCRED"};
        int v = 1;
        for (int i = 0; i < 3; i++) {
            errno = 0;
            int r4 = setsockopt(s, SOL_SOCKET, opts[i], &v, sizeof v);
            int e4 = errno;
            errno = 0;
            int r0 = setsockopt(s, SOL_SOCKET, opts[i], &v, 0);
            int e0 = errno;
            printf("%s: len4=(%d,%s) len0=(%d,%s)\n", names[i], r4, strerror(e4), r0, strerror(e0));
        }
        close(s);
    }

    /* 6. Non-SOL_SOCKET control messages */
    printf("-- non-SOL_SOCKET cmsg\n");
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        char ch = 'A';
        struct iovec iov = {&ch, 1};
        char cbuf[CMSG_SPACE(sizeof(int))];
        memset(cbuf, 0, sizeof cbuf);
        struct msghdr msg = {
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = cbuf,
            .msg_controllen = sizeof cbuf,
        };
        struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = 999;
        cm->cmsg_type = 42;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        errno = 0;
        ssize_t r = sendmsg(sv[0], &msg, 0);
        printf("non-SOL_SOCKET: %zd %s\n", r, r < 0 ? strerror(errno) : "");

        cm->cmsg_len = 4;
        errno = 0;
        r = sendmsg(sv[0], &msg, 0);
        printf("non-SOL_SOCKET bad len: %zd %s\n", r, r < 0 ? strerror(errno) : "");

        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = 999;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        errno = 0;
        r = sendmsg(sv[0], &msg, 0);
        printf("SOL_SOCKET unknown type: %zd %s\n", r, r < 0 ? strerror(errno) : "");

        /* Non-SOL_SOCKET followed by SCM_RIGHTS: skipped cleanly, fd still delivered */
        char cbuf2[CMSG_SPACE(sizeof(int)) * 2];
        memset(cbuf2, 0, sizeof cbuf2);
        msg.msg_control = cbuf2;
        msg.msg_controllen = sizeof cbuf2;
        cm = CMSG_FIRSTHDR(&msg);
        cm->cmsg_level = 999;
        cm->cmsg_type = 42;
        cm->cmsg_len = CMSG_LEN(sizeof(int));
        struct cmsghdr *cm2 = CMSG_NXTHDR(&msg, cm);
        cm2->cmsg_level = SOL_SOCKET;
        cm2->cmsg_type = SCM_RIGHTS;
        cm2->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(cm2), &sv[0], sizeof(int));
        errno = 0;
        r = sendmsg(sv[0], &msg, 0);
        printf("non-SOL_SOCKET + SCM_RIGHTS: %zd %s\n", r, r < 0 ? strerror(errno) : "");

        /* Drain first packet, then verify second packet carried the fd */
        recv(sv[1], buf, sizeof buf, 0);
        char rcbuf[CMSG_SPACE(sizeof(int))];
        struct iovec riov = {buf, sizeof buf};
        struct msghdr rmsg = {
            .msg_iov = &riov,
            .msg_iovlen = 1,
            .msg_control = rcbuf,
            .msg_controllen = sizeof rcbuf,
        };
        r = recvmsg(sv[1], &rmsg, 0);
        struct cmsghdr *rcm = CMSG_FIRSTHDR(&rmsg);
        int got_fd = -1;
        if (rcm && rcm->cmsg_level == SOL_SOCKET && rcm->cmsg_type == SCM_RIGHTS)
            memcpy(&got_fd, CMSG_DATA(rcm), sizeof(int));
        printf("received fd valid: %d (data=%zd)\n", got_fd >= 0, r);
        if (got_fd >= 0)
            close(got_fd);
        close(sv[0]);
        close(sv[1]);
    }

    /* 7. Receive-time sender address, zero-byte SIOCOUTQ/queue cap, and SEQPACKET SIGPIPE */
    printf("-- recv-time addr & seqpacket sigpipe\n");
    {
        struct sockaddr_un got;
        socklen_t lg;
        int types[3] = {SOCK_DGRAM, SOCK_STREAM, SOCK_SEQPACKET};
        const char *tnames[3] = {"dgram", "stream", "seqpacket"};
        for (int i = 0; i < 3; i++) {
            char sn[32], cn[32];
            snprintf(sn, sizeof sn, "ufix_rt_s_%s", tnames[i]);
            snprintf(cn, sizeof cn, "ufix_rt_c_%s", tnames[i]);
            socklen_t lsa = mkabs(&sa, sn);
            socklen_t lsb = mkabs(&sb, cn);
            if (types[i] == SOCK_DGRAM) {
                int srv = socket(AF_UNIX, SOCK_DGRAM, 0);
                int cli = socket(AF_UNIX, SOCK_DGRAM, 0);
                bind(srv, (struct sockaddr *)&sa, lsa);
                sendto(cli, "hi", 2, 0, (struct sockaddr *)&sa, lsa);
                bind(cli, (struct sockaddr *)&sb, lsb);
                lg = sizeof got;
                memset(&got, 0, sizeof got);
                recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr *)&got, &lg);
                show_addr("dgram send->bind->recvfrom", &got, lg);
                sendto(cli, "bye", 3, 0, (struct sockaddr *)&sa, lsa);
                close(cli);
                lg = sizeof got;
                memset(&got, 0, sizeof got);
                recvfrom(srv, buf, sizeof buf, 0, (struct sockaddr *)&got, &lg);
                show_addr("dgram bind->send->close->recvfrom", &got, lg);
                close(srv);
            } else {
                int srv = socket(AF_UNIX, types[i], 0);
                int cli = socket(AF_UNIX, types[i], 0);
                bind(srv, (struct sockaddr *)&sa, lsa);
                listen(srv, 4);
                connect(cli, (struct sockaddr *)&sa, lsa);
                send(cli, "hi", 2, 0);
                bind(cli, (struct sockaddr *)&sb, lsb);
                lg = sizeof got;
                memset(&got, 0, sizeof got);
                int acc = accept(srv, (struct sockaddr *)&got, &lg);
                char tag[64];
                snprintf(tag, sizeof tag, "%s accept", tnames[i]);
                show_addr(tag, &got, lg);
                lg = sizeof got;
                memset(&got, 0, sizeof got);
                getpeername(acc, (struct sockaddr *)&got, &lg);
                snprintf(tag, sizeof tag, "%s getpeername", tnames[i]);
                show_addr(tag, &got, lg);
                lg = sizeof got;
                memset(&got, 0, sizeof got);
                recvfrom(acc, buf, sizeof buf, 0, (struct sockaddr *)&got, &lg);
                snprintf(tag, sizeof tag, "%s recvfrom", tnames[i]);
                show_addr(tag, &got, lg);
                close(cli);
                close(acc);
                close(srv);
            }
        }

        /* Zero-byte datagram/seqpacket SIOCOUTQ is nonzero and bounded by truesize */
        int sv[2];
        socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
        send(sv[0], "", 0, MSG_DONTWAIT);
        show_outq("dgram 0B", sv[0]);
        int n = 1;
        while (n < 2000 && send(sv[0], "", 0, MSG_DONTWAIT) == 0)
            n++;
        printf("dgram 0B bounded=%d pollout=%d\n", n < 2000, !!(poll_ev(sv[0]) & POLLOUT));
        close(sv[0]);
        close(sv[1]);

        /* SOCK_SEQPACKET EPIPE does not raise SIGPIPE */
        signal(SIGPIPE, on_sigpipe);
        for (int c = 0; c < 3; c++) {
            socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
            if (c == 0)
                close(sv[1]);
            else if (c == 1)
                shutdown(sv[1], SHUT_RD);
            else
                shutdown(sv[0], SHUT_WR);
            got_sigpipe = 0;
            errno = 0;
            ssize_t r = send(sv[0], "x", 1, 0);
            printf("seqpacket case=%d: r=%zd err=%s sigpipe=%d\n", c, r,
                   r < 0 ? strerror(errno) : "ok", (int)got_sigpipe);
            close(sv[0]);
            if (c != 0)
                close(sv[1]);
        }
    }
    return 0;
}
C
gcc -O1 -Wall -o unix_fixes unix_fixes.c
./unix_fixes
rm -f unix_fixes unix_fixes.c
