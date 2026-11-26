/*
 * Regression tests for poll/epoll optimization and correctness fixes:
 * - EPOLLEXCLUSIVE gates preserve Linux's stable waiter queue order (re-entering waiters keep
 *   their registration position instead of rotating behind later waiters);
 * - Event-driven epoll ready list and HostEpoll handle large idle sets with LT, ET, ONESHOT,
 *   nesting, non-empty pipe arrivals, shared-socket multi-epoll ET, duplicate host fds,
 *   round-robin maxevents fairness, and EFAULT/partial copy preservation;
 * - Batched ppoll and pselect6 handle large host-socket sets and blocking waits without
 *   spinning on unrequested POLLHUP/POLLERR;
 * - Epoll fdinfo reports accurate sdev/ino consistent with fstat for tmpfs, rootfs, and overlayfs.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL: ");                                                             \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, " (errno %d)\n", errno);                                               \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1U << 28)
#endif

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void wait_thread_sleeping(int tid)
{
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", tid);
    for (int tries = 0; tries < 500; tries++) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                char *rp = strrchr(buf, ')');
                if (rp && rp[1] == ' ' && rp[2] == 'S') {
                    sleep_ms(10);
                    return;
                }
            }
        }
        sleep_ms(5);
    }
}

/* 1. EPOLLEXCLUSIVE stable waiter queue order */
struct stable_arg {
    int ep;
    int efd;
    atomic_int *stop;
    atomic_int *wakes;
    atomic_int *tid;
    atomic_int *hold;
};

static void *stable_worker(void *p)
{
    struct stable_arg *a = p;
    struct epoll_event ev;
    atomic_store(a->tid, (int)syscall(SYS_gettid));
    while (!atomic_load(a->stop)) {
        int n = epoll_wait(a->ep, &ev, 1, 5000);
        if (n == 1) {
            if (ev.data.u64 == 99)
                break;
            uint64_t v = 0;
            (void)read(a->efd, &v, sizeof(v));
            atomic_fetch_add(a->wakes, 1);
            while (atomic_load(a->hold))
                sleep_ms(5);
        }
    }
    return NULL;
}

static void test_exclusive_stable_order(void)
{
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    int stop_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(efd >= 0 && stop_fd >= 0, "eventfd");
    int ep0 = epoll_create1(EPOLL_CLOEXEC);
    int ep1 = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep0 >= 0 && ep1 >= 0, "epoll_create1");

    /* Register ep0 first, then ep1 second */
    struct epoll_event ev = {.events = EPOLLIN | EPOLLEXCLUSIVE, .data.u64 = 0};
    CHECK(epoll_ctl(ep0, EPOLL_CTL_ADD, efd, &ev) == 0, "add ep0");
    ev.data.u64 = 1;
    CHECK(epoll_ctl(ep1, EPOLL_CTL_ADD, efd, &ev) == 0, "add ep1");
    struct epoll_event sev = {.events = EPOLLIN, .data.u64 = 99};
    CHECK(epoll_ctl(ep0, EPOLL_CTL_ADD, stop_fd, &sev) == 0, "add stop0");
    CHECK(epoll_ctl(ep1, EPOLL_CTL_ADD, stop_fd, &sev) == 0, "add stop1");

    atomic_int stop = 0, wakes0 = 0, wakes1 = 0, tid0 = 0, tid1 = 0, hold0 = 0, hold1 = 0;
    struct stable_arg a0 = {ep0, efd, &stop, &wakes0, &tid0, &hold0};
    struct stable_arg a1 = {ep1, efd, &stop, &wakes1, &tid1, &hold1};
    pthread_t t0, t1;
    CHECK(pthread_create(&t0, NULL, stable_worker, &a0) == 0, "create t0");
    CHECK(pthread_create(&t1, NULL, stable_worker, &a1) == 0, "create t1");
    while (!atomic_load(&tid0) || !atomic_load(&tid1))
        sleep_ms(5);
    wait_thread_sleeping(atomic_load(&tid0));
    wait_thread_sleeping(atomic_load(&tid1));

    /* Send 5 spaced events: worker 0 must stay at the head and get all 5 (no rotation) */
    for (int i = 1; i <= 5; i++) {
        uint64_t one = 1;
        CHECK(write(efd, &one, sizeof(one)) == 8, "write efd %d", i);
        for (int tries = 0; tries < 200 && atomic_load(&wakes0) < i; tries++)
            sleep_ms(5);
        CHECK(atomic_load(&wakes0) == i, "expected wakes0=%d got %d (wakes1=%d)",
              i, atomic_load(&wakes0), atomic_load(&wakes1));
        wait_thread_sleeping(atomic_load(&tid0));
    }
    CHECK(atomic_load(&wakes1) == 0, "worker 1 should not be woken while worker 0 stays at head (got %d)",
          atomic_load(&wakes1));

    /* Now hold worker 0 outside epoll_wait; the next event must wake worker 1 */
    atomic_store(&hold0, 1);
    uint64_t one = 1;
    CHECK(write(efd, &one, sizeof(one)) == 8, "write efd for busy w0");
    for (int tries = 0; tries < 200 && atomic_load(&wakes0) < 6; tries++)
        sleep_ms(5);
    CHECK(atomic_load(&wakes0) == 6, "w0 should take 6th wake");
    sleep_ms(20);
    CHECK(write(efd, &one, sizeof(one)) == 8, "write efd while w0 busy");
    for (int tries = 0; tries < 200 && atomic_load(&wakes1) < 1; tries++)
        sleep_ms(5);
    CHECK(atomic_load(&wakes1) == 1, "w1 should wake while w0 is busy (got %d)",
          atomic_load(&wakes1));

    atomic_store(&hold0, 0);
    atomic_store(&stop, 1);
    CHECK(write(stop_fd, &one, sizeof(one)) == 8, "wake stop");
    pthread_join(t0, NULL);
    pthread_join(t1, NULL);
    close(ep0);
    close(ep1);
    close(stop_fd);
    close(efd);
}

/* 2. Tracked epoll ready list, HostEpoll, multi-epoll ET, pipe arrived, ONESHOT, nesting */
static void test_tracked_epoll_semantics(void)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1");

    /* Register 256 idle eventfds and 64 idle UDP sockets */
    int idle_efds[256];
    int idle_udps[64];
    for (int i = 0; i < 256; i++) {
        idle_efds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        CHECK(idle_efds[i] >= 0, "idle efd %d", i);
        struct epoll_event ev = {.events = EPOLLIN | (i % 2 ? EPOLLET : 0), .data.u64 = (uint64_t)i};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, idle_efds[i], &ev) == 0, "add idle efd %d", i);
    }
    for (int i = 0; i < 64; i++) {
        idle_udps[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(idle_udps[i] >= 0, "idle udp %d", i);
        struct epoll_event ev = {.events = EPOLLIN | (i % 2 ? EPOLLET : 0), .data.u64 = 1000 + (uint64_t)i};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, idle_udps[i], &ev) == 0, "add idle udp %d", i);
    }

    /* Active non-empty pipe ET (tests poll::arrived on tracked epoll) */
    int p[2];
    CHECK(pipe2(p, O_NONBLOCK | O_CLOEXEC) == 0, "pipe2");
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.u64 = 5000};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == 0, "add pipe");

    /* Active UDP socket + duplicate fd in same epoll + second ET epoll sharing same open file */
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof(a);
    CHECK(bind(s, (void *)&a, sizeof(a)) == 0, "bind udp");
    CHECK(getsockname(s, (void *)&a, &al) == 0, "getsockname");
    int c = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(connect(c, (void *)&a, sizeof(a)) == 0, "connect udp");
    int s_dup = dup(s);
    CHECK(s_dup >= 0, "dup udp");

    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 6000;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s, &ev) == 0, "add udp");
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = 6001;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, s_dup, &ev) == 0, "add dup udp");

    int ep2 = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep2 >= 0, "epoll_create1 ep2");
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 6002;
    CHECK(epoll_ctl(ep2, EPOLL_CTL_ADD, s, &ev) == 0, "add udp to ep2");

    struct epoll_event out[8];
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "initial empty ep");
    CHECK(epoll_wait(ep2, out, 8, 0) == 0, "initial empty ep2");

    /* Non-empty pipe double write: both writes must fire ET */
    CHECK(write(p[1], "a", 1) == 1, "pipe write 1");
    CHECK(epoll_wait(ep, out, 8, 0) == 1 && out[0].data.u64 == 5000, "pipe ET 1");
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "pipe ET quiet 1");
    CHECK(write(p[1], "b", 1) == 1, "pipe write 2 (non-empty)");
    CHECK(epoll_wait(ep, out, 8, 0) == 1 && out[0].data.u64 == 5000, "pipe ET 2");
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "pipe ET quiet 2");

    /* UDP send: fires on ep (both s ET and s_dup ONESHOT) AND on ep2 (shared HostEdges!) */
    CHECK(send(c, "1", 1, 0) == 1, "udp send 1");
    int n = epoll_wait(ep, out, 8, 1000);
    CHECK(n == 2, "expected 2 events on ep (got %d)", n);
    /* ep2 MUST also see the edge even though ep already polled HostEdges! */
    n = epoll_wait(ep2, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6002, "ep2 must also fire ET (got %d)", n);
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "ep quiet after ET + ONESHOT");
    CHECK(epoll_wait(ep2, out, 8, 0) == 0, "ep2 quiet after ET");

    /* Second UDP packet without draining: both ep (ET) and ep2 (ET) must fire again, s_dup stays disarmed */
    CHECK(send(c, "2", 1, 0) == 1, "udp send 2");
    n = epoll_wait(ep, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6000, "second packet fires s ET only (got %d)", n);
    n = epoll_wait(ep2, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6002, "second packet fires ep2 ET (got %d)", n);

    /* Re-arm s_dup via EPOLL_CTL_MOD: must fire immediately since data is queued */
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = 6001;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, s_dup, &ev) == 0, "rearm s_dup");
    n = epoll_wait(ep, out, 8, 0);
    CHECK(n == 1 && out[0].data.u64 == 6001, "rearmed s_dup fires immediately");

    /* Drain UDP until EAGAIN, send again: both ep and ep2 fire */
    char buf[16];
    while (recv(s, buf, sizeof(buf), 0) > 0)
        ;
    CHECK(errno == EAGAIN, "expected EAGAIN draining udp");
    CHECK(epoll_wait(ep, out, 8, 0) == 0, "ep empty after drain");
    CHECK(send(c, "3", 1, 0) == 1, "udp send 3");
    n = epoll_wait(ep, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6000, "udp fires after drain");
    n = epoll_wait(ep2, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6002, "ep2 fires after drain");

    /* Dynamic epoll (EPOLLEXCLUSIVE | EPOLLET) paired with HostEpoll (EPOLLET) on the same UDP socket:
     * probing the Dynamic epoll first must still notify the sibling HostEpoll epoll. */
    int ep_dyn = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep_dyn >= 0, "epoll_create1 ep_dyn");
    ev.events = EPOLLIN | EPOLLEXCLUSIVE | EPOLLET;
    ev.data.u64 = 6003;
    CHECK(epoll_ctl(ep_dyn, EPOLL_CTL_ADD, s_dup, &ev) == 0, "add s_dup exclusive to ep_dyn");
    CHECK(send(c, "4", 1, 0) == 1, "udp send 4");
    /* Probe ep_dyn (Dynamic) FIRST: drains HostEdges; ep (HostEpoll) and ep2 MUST still fire! */
    n = epoll_wait(ep_dyn, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6003, "ep_dyn fires first (got %d)", n);
    n = epoll_wait(ep, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6000, "ep (HostEpoll) must still fire after Dynamic consumed HostEdges (got %d)", n);
    n = epoll_wait(ep2, out, 8, 1000);
    CHECK(n == 1 && out[0].data.u64 == 6002, "ep2 (HostEpoll) must still fire after Dynamic consumed HostEdges (got %d)", n);
    close(ep_dyn);

    /* Connected AF_UNIX SOCK_DGRAM disconnect/reconnect waking EPOLLOUT */
    {
        int ua = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        int ub = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(ua >= 0 && ub >= 0, "unix dgram sockets");
        struct sockaddr_un baddr;
        memset(&baddr, 0, sizeof(baddr));
        baddr.sun_family = AF_UNIX;
        memcpy(baddr.sun_path + 1, "poll_opt_dgram_b", 16);
        socklen_t blen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + 16);
        CHECK(bind(ub, (void *)&baddr, blen) == 0, "bind ub");
        CHECK(connect(ua, (void *)&baddr, blen) == 0, "connect ua -> ub");
        /* Fill ub's receive queue until EAGAIN */
        char chunk[4096];
        memset(chunk, 'x', sizeof(chunk));
        while (send(ua, chunk, sizeof(chunk), 0) > 0)
            ;
        CHECK(errno == EAGAIN, "expected EAGAIN filling unix dgram");
        int uep = epoll_create1(EPOLL_CLOEXEC);
        ev.events = EPOLLOUT;
        ev.data.u64 = 7777;
        CHECK(epoll_ctl(uep, EPOLL_CTL_ADD, ua, &ev) == 0, "add full unix dgram");
        CHECK(epoll_wait(uep, out, 4, 0) == 0, "full unix dgram must not be writable");
        /* Disconnect with AF_UNSPEC: ua immediately becomes writable again */
        struct sockaddr unspec;
        memset(&unspec, 0, sizeof(unspec));
        unspec.sa_family = AF_UNSPEC;
        CHECK(connect(ua, &unspec, sizeof(unspec)) == 0, "disconnect ua");
        n = epoll_wait(uep, out, 4, 0);
        CHECK(n == 1 && (out[0].events & EPOLLOUT) && out[0].data.u64 == 7777,
              "disconnected unix dgram must report EPOLLOUT (got %d)", n);
        close(uep);
        close(ua);
        close(ub);
    }

    /* Round-robin fairness with maxevents = 1 across 3 ready LT eventfds */
    int rr[3];
    int rrep = epoll_create1(EPOLL_CLOEXEC);
    for (int i = 0; i < 3; i++) {
        rr[i] = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
        ev.events = EPOLLIN;
        ev.data.u64 = (uint64_t)(10 + i);
        CHECK(epoll_ctl(rrep, EPOLL_CTL_ADD, rr[i], &ev) == 0, "add rr %d", i);
    }
    int seen_rr[3] = {0, 0, 0};
    for (int i = 0; i < 6; i++) {
        CHECK(epoll_wait(rrep, out, 1, 0) == 1, "rr wait %d", i);
        int idx = (int)out[0].data.u64 - 10;
        CHECK(idx >= 0 && idx < 3, "rr data %d", idx);
        seen_rr[idx]++;
    }
    CHECK(seen_rr[0] == 2 && seen_rr[1] == 2 && seen_rr[2] == 2,
          "expected equal round-robin counts (got %d,%d,%d)", seen_rr[0], seen_rr[1], seen_rr[2]);
    for (int i = 0; i < 3; i++)
        close(rr[i]);
    close(rrep);

    close(ep2);
    close(s_dup);
    close(s);
    close(c);
    close(p[0]);
    close(p[1]);
    for (int i = 0; i < 64; i++)
        close(idle_udps[i]);
    for (int i = 0; i < 256; i++)
        close(idle_efds[i]);
    close(ep);
}

/* 3. Batched ppoll and pselect6 */
struct wake_udp_arg {
    int c;
};
static void *wake_udp_thread(void *p)
{
    struct wake_udp_arg *a = p;
    sleep_ms(30);
    (void)send(a->c, "z", 1, 0);
    return NULL;
}

static void test_batched_ppoll_and_pselect6(void)
{
    int idle[64];
    struct pollfd pfds[65];
    for (int i = 0; i < 64; i++) {
        idle[i] = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(idle[i] >= 0, "idle udp");
        pfds[i].fd = idle[i];
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof(a);
    CHECK(bind(s, (void *)&a, sizeof(a)) == 0, "bind");
    CHECK(getsockname(s, (void *)&a, &al) == 0, "getsockname");
    int c = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    CHECK(connect(c, (void *)&a, sizeof(a)) == 0, "connect");
    pfds[64].fd = s;
    pfds[64].events = POLLIN;
    pfds[64].revents = 0;

    /* Blocking poll with 64 idle host sockets + 1 woken host socket */
    struct wake_udp_arg arg = {.c = c};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, wake_udp_thread, &arg) == 0, "create wake thread");
    int n = poll(pfds, 65, 2000);
    CHECK(n == 1 && (pfds[64].revents & POLLIN), "batched poll blocking wake (n=%d revents=%#x)",
          n, pfds[64].revents);
    pthread_join(th, NULL);
    char buf[8];
    CHECK(recv(s, buf, sizeof(buf), 0) == 1, "recv");
    CHECK(poll(pfds, 65, 0) == 0, "batched poll empty");

    /* pselect6 with same sockets */
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxfd = s;
    for (int i = 0; i < 64; i++) {
        FD_SET(idle[i], &rfds);
        if (idle[i] > maxfd)
            maxfd = idle[i];
    }
    FD_SET(s, &rfds);
    struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};
    CHECK(pthread_create(&th, NULL, wake_udp_thread, &arg) == 0, "create wake thread 2");
    n = pselect(maxfd + 1, &rfds, NULL, NULL, &ts, NULL);
    CHECK(n == 1 && FD_ISSET(s, &rfds), "batched pselect blocking wake (n=%d)", n);
    pthread_join(th, NULL);

    close(s);
    close(c);
    for (int i = 0; i < 64; i++)
        close(idle[i]);
}

/* 4. Epoll fdinfo sdev/ino for rootfs, tmpfs, and overlayfs */
static void check_epoll_fdinfo_entry(int ep, int target_fd, const char *label)
{
    struct stat st;
    CHECK(fstat(target_fd, &st) == 0, "fstat %s", label);
    unsigned long expected_sdev = ((unsigned long)major(st.st_dev) << 20) | (unsigned long)minor(st.st_dev);
    unsigned long expected_ino = (unsigned long)st.st_ino;

    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", ep);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL, "open %s", path);
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        int tfd = -1;
        unsigned long ino = 0, sdev = 0;
        if (sscanf(line, "tfd: %d events: %*x data: %*x pos:%*d ino:%lx sdev:%lx", &tfd, &ino, &sdev) == 3 &&
            tfd == target_fd) {
            CHECK(sdev == expected_sdev, "%s sdev mismatch: got %#lx expected %#lx (st_dev=%#lx)",
                  label, sdev, expected_sdev, (unsigned long)st.st_dev);
            CHECK(ino == expected_ino, "%s ino mismatch: got %#lx expected %#lx",
                  label, ino, expected_ino);
            found = 1;
            break;
        }
    }
    fclose(f);
    CHECK(found, "%s tfd %d not found in fdinfo", label, target_fd);
}

static void test_epoll_fdinfo_devices(void)
{
    mkdir("/tmp", 0755);
    mkdir("/tmp/ep_tmpfs", 0755);
    CHECK(mount("tmpfs", "/tmp/ep_tmpfs", "tmpfs", 0, NULL) == 0, "mount tmpfs");

    /* FIFO on rootfs */
    unlink("/tmp/ep_root_fifo");
    CHECK(mkfifo("/tmp/ep_root_fifo", 0600) == 0, "mkfifo root");
    int root_fd = open("/tmp/ep_root_fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(root_fd >= 0, "open root fifo");

    /* FIFO on tmpfs */
    CHECK(mkfifo("/tmp/ep_tmpfs/fifo", 0600) == 0, "mkfifo tmpfs");
    int tmp_fd = open("/tmp/ep_tmpfs/fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(tmp_fd >= 0, "open tmpfs fifo");

    struct stat root_st, tmp_st;
    CHECK(fstat(root_fd, &root_st) == 0 && fstat(tmp_fd, &tmp_st) == 0, "fstat root/tmp");
    CHECK(root_st.st_dev != tmp_st.st_dev, "tmpfs dev must differ from rootfs dev");

    /* FIFO on overlayfs (both lower and upper) */
    mkdir("/tmp/ep_ovl_low", 0755);
    mkdir("/tmp/ep_ovl_up", 0755);
    mkdir("/tmp/ep_ovl_work", 0755);
    mkdir("/tmp/ep_ovl_mnt", 0755);
    CHECK(mkfifo("/tmp/ep_ovl_low/low_fifo", 0600) == 0, "mkfifo low");
    CHECK(mount("overlay", "/tmp/ep_ovl_mnt", "overlay", 0,
                "lowerdir=/tmp/ep_ovl_low,upperdir=/tmp/ep_ovl_up,workdir=/tmp/ep_ovl_work") == 0,
          "mount overlay");
    int ovl_low_fd = open("/tmp/ep_ovl_mnt/low_fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(ovl_low_fd >= 0, "open overlay lower fifo");
    CHECK(mkfifo("/tmp/ep_ovl_mnt/up_fifo", 0600) == 0, "mkfifo overlay upper");
    int ovl_up_fd = open("/tmp/ep_ovl_mnt/up_fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    CHECK(ovl_up_fd >= 0, "open overlay upper fifo");

    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1");
    struct epoll_event ev = {.events = EPOLLIN};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, root_fd, &ev) == 0, "add root fifo");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, tmp_fd, &ev) == 0, "add tmpfs fifo");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ovl_low_fd, &ev) == 0, "add ovl low fifo");
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ovl_up_fd, &ev) == 0, "add ovl up fifo");

    check_epoll_fdinfo_entry(ep, root_fd, "rootfs fifo");
    check_epoll_fdinfo_entry(ep, tmp_fd, "tmpfs fifo");
    check_epoll_fdinfo_entry(ep, ovl_low_fd, "overlay lower fifo");
    check_epoll_fdinfo_entry(ep, ovl_up_fd, "overlay upper fifo");

    close(ep);
    close(ovl_up_fd);
    close(ovl_low_fd);
    close(tmp_fd);
    close(root_fd);
    umount2("/tmp/ep_ovl_mnt", MNT_DETACH);
    umount2("/tmp/ep_tmpfs", MNT_DETACH);
}

int main(void)
{
    struct rlimit rl = {4096, 4096};
    setrlimit(RLIMIT_NOFILE, &rl);
    test_exclusive_stable_order();
    test_tracked_epoll_semantics();
    test_batched_ppoll_and_pselect6();
    test_epoll_fdinfo_devices();
    printf("poll_opt: all ok\n");
    return 0;
}
