/*
 * Classic BPF filters on TCP sockets when the host refuses them. A host with Linux 5d39580f68e6
 * lets only CAP_NET_ADMIN attach SO_ATTACH_FILTER to a TCP socket, and the app never has it, so
 * Appine enforces supported constant verdicts itself. A test hook of debug builds (appine-run sets
 * APPINE_TEST_HOOKS=1) makes any host act that way. With the hook on, a guest with CAP_NET_ADMIN
 * attaches, reads back, replaces and detaches the program as on Linux, sockets accepted from a
 * listener inherit it, a locked filter cannot be changed, a bad program is still refused, and
 * without CAP_NET_ADMIN the attach is EPERM. Prints "all ok" when every check passes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sockfilter.h"

/* linux/capability.h */
#define CAP_VERSION_3 0x20080522
#define CAP_NET_ADMIN 12
struct cap_header {
    uint32_t version;
    int pid;
};
struct cap_data {
    uint32_t effective, permitted, inheritable;
};

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL line %d: ", __LINE__);                                                    \
            printf(__VA_ARGS__);                                                                   \
            printf(" (errno %d)\n", errno);                                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static struct sock_filter drop[1] = {{BPF_RET | BPF_K, 0, 0, 0}};
static struct sock_filter partial = {BPF_RET | BPF_K, 0, 0, 8};
static struct sock_filter pass[2] = {{BPF_LD | BPF_W | BPF_LEN, 0, 0, 0},
                                     {BPF_RET | BPF_K, 0, 0, 0xffffffff}};

static int attach(int fd, struct sock_filter *insns, unsigned short n, socklen_t len)
{
    struct sock_fprog prog = {n, insns};
    return setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, len);
}

/* The program's count by SO_GET_FILTER with room for `room` instructions, copied into `out`;
 * -1 with errno on failure */
static int get(int fd, struct sock_filter *out, socklen_t room)
{
    socklen_t len = room;
    if (getsockopt(fd, SOL_SOCKET, SO_GET_FILTER, out, &len) != 0)
        return -1;
    return (int)len;
}

static int tcp(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0, "socket");
    return fd;
}

static void hook(int on)
{
    CHECK(syscall(TEST_SYSCALL, HOOK_REFUSE_TCP_FILTERS, on) == 0, "hook %d", on);
}

static void test_deferred_listen(void)
{
    /* A filtered listener reserves the port, but cannot queue a connection for detach. */
    int gated = tcp();
    int one = 1;
    CHECK(setsockopt(gated, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "reuse");
    CHECK(attach(gated, drop, 1, sizeof(struct sock_fprog)) == 0, "install drop");
    CHECK(listen(gated, -1) == 0, "deferred listen");
    struct sockaddr_in local;
    socklen_t size = sizeof local;
    CHECK(getsockname(gated, (void *)&local, &size) == 0 && local.sin_port, "autobind");
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int client = tcp();
    CHECK(connect(client, (void *)&local, size) < 0 && errno == ECONNREFUSED, "closed port");
    close(client);
    int competitor = tcp();
    CHECK(setsockopt(competitor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "reuse peer");
    CHECK(bind(competitor, (void *)&local, size) < 0 && errno == EADDRINUSE, "reserved port");
    close(competitor);
    struct pollfd pfd = {.fd = gated, .events = POLLIN | POLLOUT};
    CHECK(poll(&pfd, 1, 0) == 0, "filtered readiness");
    CHECK(fcntl(gated, F_SETFL, O_NONBLOCK) == 0, "nonblock");
    CHECK(accept(gated, NULL, NULL) < 0 && errno == EAGAIN, "filtered accept");
    CHECK(attach(gated, &partial, 1, sizeof(struct sock_fprog)) < 0 && errno == EOPNOTSUPP,
          "unsupported replacement");
    CHECK(setsockopt(gated, SOL_SOCKET, SO_DETACH_FILTER, &one, sizeof one) == 0, "open port");
    CHECK(accept(gated, NULL, NULL) < 0 && errno == EAGAIN, "empty on detach");
    client = tcp();
    CHECK(connect(client, (void *)&local, size) == 0, "open connection");
    int peer = accept(gated, NULL, NULL);
    CHECK(peer >= 0, "accept after detach");
    CHECK(attach(peer, drop, 1, sizeof(struct sock_fprog)) < 0 && errno == EOPNOTSUPP,
          "connected drop");
    close(peer);
    close(client);
    close(gated);
}

static void test_deferred_shutdown(void)
{
    int one = 1;
    int stopped = tcp();
    CHECK(attach(stopped, drop, 1, sizeof(struct sock_fprog)) == 0, "attach before shutdown");
    CHECK(listen(stopped, 1) == 0, "listen before shutdown");
    CHECK(shutdown(stopped, SHUT_WR) == 0, "listener write shutdown");
    int listening = 0;
    socklen_t size = sizeof listening;
    CHECK(getsockopt(stopped, SOL_SOCKET, SO_ACCEPTCONN, &listening, &size) == 0 && listening,
          "still listening");
    struct timeval tv = {.tv_usec = 30000};
    CHECK(setsockopt(stopped, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0, "accept timeout");
    CHECK(accept(stopped, NULL, NULL) < 0 && errno == EAGAIN, "timed accept under RET 0");
    CHECK(shutdown(stopped, SHUT_RD) == 0, "listener read shutdown");
    CHECK(getsockopt(stopped, SOL_SOCKET, SO_ACCEPTCONN, &listening, &size) == 0 && !listening,
          "not listening after shutdown");
    CHECK(setsockopt(stopped, SOL_SOCKET, SO_DETACH_FILTER, &one, sizeof one) == 0,
          "detach after shutdown");
    CHECK(accept(stopped, NULL, NULL) < 0 && errno == EINVAL, "detach did not reopen");
    close(stopped);
}

static void test_activation_conflict(void)
{
    /* A pre-existing shared bind can prevent activation. Keep RET 0 for a later retry. */
    int gated = tcp(), competitor = tcp();
    int one = 1;
    struct sock_filter got[1];
    CHECK(setsockopt(gated, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "shared bind");
    CHECK(setsockopt(competitor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) == 0, "shared peer");
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof local;
    CHECK(bind(gated, (void *)&local, size) == 0, "bind before attach");
    CHECK(getsockname(gated, (void *)&local, &size) == 0, "shared address");
    CHECK(bind(competitor, (void *)&local, size) == 0 && listen(competitor, 1) == 0,
          "prior listener");
    CHECK(attach(gated, drop, 1, sizeof(struct sock_fprog)) == 0 && listen(gated, 1) == 0,
          "hold already bound port");
    CHECK(setsockopt(gated, SOL_SOCKET, SO_DETACH_FILTER, &one, sizeof one) < 0 &&
              errno == EADDRINUSE, "activation conflict");
    CHECK(get(gated, got, 1) == 1 && memcmp(got, drop, sizeof drop) == 0, "kept on conflict");
    close(competitor);
    CHECK(setsockopt(gated, SOL_SOCKET, SO_DETACH_FILTER, &one, sizeof one) == 0,
          "retry activation");
    close(gated);
}

int main(void)
{
    struct sock_filter got[4];
    if (getuid() != 0) {
        printf("skipped: not root\n");
        return 0;
    }
    alarm(30);
    hook(1);

    test_deferred_listen();
    test_deferred_shutdown();
    test_activation_conflict();

    /* Attach, read back, replace */
    int s = tcp();
    CHECK(attach(s, drop, 1, sizeof(struct sock_fprog)) == 0, "attach drop");
    CHECK(get(s, NULL, 0) == 1, "count");
    memset(got, 0, sizeof got);
    CHECK(get(s, got, 1) == 1 && memcmp(got, drop, sizeof drop) == 0, "read back");
    CHECK(attach(s, pass, 2, sizeof(struct sock_fprog)) == 0, "replace");
    CHECK(get(s, got, 1) == -1 && errno == EINVAL, "short room");
    CHECK(get(s, got, 4) == 2 && memcmp(got, pass, sizeof pass) == 0, "read replaced");
    printf("ok attach\n");

    /* Refused attaches leave the program alone */
    struct sock_filter bad[1] = {{0xffff, 0, 0, 0}};
    CHECK(attach(s, drop, 1, 15) == -1 && errno == EINVAL, "optlen 15");
    CHECK(attach(s, drop, 1, 3) == -1 && errno == EINVAL, "optlen 3");
    CHECK(attach(s, drop, 0, sizeof(struct sock_fprog)) == -1 && errno == EINVAL, "count 0");
    CHECK(attach(s, NULL, 1, sizeof(struct sock_fprog)) == -1 && errno == EINVAL, "no program");
    CHECK(attach(s, bad, 1, sizeof(struct sock_fprog)) == -1 && errno == EINVAL, "bad opcode");
    CHECK(attach(s, (struct sock_filter *)8, 1, sizeof(struct sock_fprog)) == -1 &&
              errno == EFAULT,
          "bad pointer");
    CHECK(get(s, got, 4) == 2, "kept after refusals");
    printf("ok refused\n");

    /* Detach */
    CHECK(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &(int){0}, sizeof(int)) == 0, "detach");
    CHECK(get(s, got, 4) == 0, "none after detach");
    CHECK(setsockopt(s, SOL_SOCKET, SO_DETACH_FILTER, &(int){0}, sizeof(int)) == -1 &&
              errno == ENOENT,
          "detach twice");
    printf("ok detach\n");

    /* Accepted sockets inherit the listener's program */
    int l = tcp();
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof a;
    CHECK(bind(l, (struct sockaddr *)&a, sizeof a) == 0, "bind");
    CHECK(getsockname(l, (struct sockaddr *)&a, &al) == 0, "getsockname");
    CHECK(attach(l, pass, 2, sizeof(struct sock_fprog)) == 0, "attach listener");
    CHECK(listen(l, 1) == 0, "listen");
    int c = tcp();
    CHECK(connect(c, (struct sockaddr *)&a, sizeof a) == 0, "connect");
    int n = accept(l, NULL, NULL);
    CHECK(n >= 0, "accept");
    CHECK(get(n, got, 4) == 2 && memcmp(got, pass, sizeof pass) == 0, "inherited");
    CHECK(get(c, got, 4) == 0, "client has none");
    printf("ok accept\n");

    /* A locked filter can be neither replaced nor detached */
    CHECK(setsockopt(n, SOL_SOCKET, SO_LOCK_FILTER, &(int){1}, sizeof(int)) == 0, "lock");
    CHECK(attach(n, drop, 1, sizeof(struct sock_fprog)) == -1 && errno == EPERM, "attach locked");
    CHECK(setsockopt(n, SOL_SOCKET, SO_DETACH_FILTER, &(int){0}, sizeof(int)) == -1 &&
              errno == EPERM,
          "detach locked");
    CHECK(get(n, got, 4) == 2, "still there");
    printf("ok lock\n");

    /* Without CAP_NET_ADMIN a TCP filter is EPERM before anything else; UDP needs nothing */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct cap_header h = {CAP_VERSION_3, 0};
        struct cap_data d[2];
        CHECK(syscall(SYS_capget, &h, d) == 0, "capget");
        d[CAP_NET_ADMIN / 32].effective &= ~(1u << (CAP_NET_ADMIN % 32));
        CHECK(syscall(SYS_capset, &h, d) == 0, "capset");
        int t = tcp();
        CHECK(attach(t, drop, 1, sizeof(struct sock_fprog)) == -1 && errno == EPERM, "no cap");
        CHECK(attach(t, drop, 1, 15) == -1 && errno == EPERM, "no cap, bad optlen");
        int u = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(attach(u, drop, 1, sizeof(struct sock_fprog)) == 0, "udp without the cap");
        exit(0);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child");
    printf("ok capability\n");

    hook(0);
    /* On a host permitting TCP attachment, ordinary filters still go to the host.
     * On a restricted host an unsupported verdict must leave the socket unfiltered. */
    int native = tcp();
    int result = attach(native, &partial, 1, sizeof(struct sock_fprog));
    if (result == 0) {
        CHECK(get(native, got, 1) == 1 && got[0].k == partial.k, "native partial filter");
    } else {
        CHECK(errno == EOPNOTSUPP && get(native, NULL, 0) == 0, "unsupported partial filter");
    }
    close(native);
    printf("all ok\n");
    return 0;
}
