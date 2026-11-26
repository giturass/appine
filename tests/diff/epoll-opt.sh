# Differential test for poll/epoll optimization and correctness fixes:
# - EPOLLEXCLUSIVE stable waiter queue order (no rotation across wakeups)
# - Epoll fdinfo sdev/ino consistency with fstat for tmpfs and rootfs FIFOs
# - Multi-epoll EPOLLET on shared TCP socket (including HostEpoll + Dynamic sibling)
set -e
cd /tmp
cat > epoll_opt.c <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1U << 28)
#endif

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Wait until thread `tid` is sleeping in the kernel (state 'S' in /proc/self/task/<tid>/stat). */
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

struct excl_arg {
    int ep, efd;
    atomic_int *stop, *wakes, *tid;
};

static void *excl_loop(void *p)
{
    struct excl_arg *a = p;
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
        }
    }
    return NULL;
}

static void check_fdinfo(const char *label, const char *fifo_path)
{
    unlink(fifo_path);
    if (mkfifo(fifo_path, 0600) != 0) {
        printf("%s: mkfifo failed\n", label);
        return;
    }
    int fd = open(fifo_path, O_RDWR | O_NONBLOCK);
    struct stat st;
    fstat(fd, &st);
    unsigned long exp_sdev = ((unsigned long)major(st.st_dev) << 20) | (unsigned long)minor(st.st_dev);
    unsigned long exp_ino = (unsigned long)st.st_ino;
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN};
    epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    char path[64], line[256];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", ep);
    FILE *f = fopen(path, "r");
    int sdev_ok = 0, ino_ok = 0;
    while (f && fgets(line, sizeof(line), f)) {
        int tfd = -1;
        unsigned long ino = 0, sdev = 0;
        if (sscanf(line, "tfd: %d events: %*x data: %*x pos:%*d ino:%lx sdev:%lx", &tfd, &ino, &sdev) == 3 &&
            tfd == fd) {
            sdev_ok = (sdev == exp_sdev);
            ino_ok = (ino == exp_ino);
            break;
        }
    }
    if (f)
        fclose(f);
    printf("fdinfo %-6s sdev_ok=%d ino_ok=%d\n", label, sdev_ok, ino_ok);
    close(ep);
    close(fd);
    unlink(fifo_path);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* 1. Stable EPOLLEXCLUSIVE waiter order */
    int efd = eventfd(0, EFD_NONBLOCK);
    int stop_fd = eventfd(0, EFD_NONBLOCK);
    int ep0 = epoll_create1(0), ep1 = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN | EPOLLEXCLUSIVE, .data.u64 = 1};
    epoll_ctl(ep0, EPOLL_CTL_ADD, efd, &ev);
    epoll_ctl(ep1, EPOLL_CTL_ADD, efd, &ev);
    struct epoll_event sev = {.events = EPOLLIN, .data.u64 = 99};
    epoll_ctl(ep0, EPOLL_CTL_ADD, stop_fd, &sev);
    epoll_ctl(ep1, EPOLL_CTL_ADD, stop_fd, &sev);

    atomic_int stop = 0, w0 = 0, w1 = 0, tid0 = 0, tid1 = 0;
    struct excl_arg a0 = {ep0, efd, &stop, &w0, &tid0};
    struct excl_arg a1 = {ep1, efd, &stop, &w1, &tid1};
    pthread_t t0, t1;
    pthread_create(&t0, NULL, excl_loop, &a0);
    pthread_create(&t1, NULL, excl_loop, &a1);
    while (!atomic_load(&tid0) || !atomic_load(&tid1))
        sleep_ms(5);
    wait_thread_sleeping(atomic_load(&tid0));
    wait_thread_sleeping(atomic_load(&tid1));
    for (int i = 1; i <= 4; i++) {
        uint64_t one = 1;
        write(efd, &one, 8);
        for (int tries = 0; tries < 400 && atomic_load(&w0) + atomic_load(&w1) < i; tries++)
            sleep_ms(5);
        wait_thread_sleeping(atomic_load(&tid0));
    }
    atomic_store(&stop, 1);
    uint64_t done = 1;
    write(stop_fd, &done, 8);
    pthread_join(t0, NULL);
    pthread_join(t1, NULL);
    printf("exclusive stable: w0=%d w1=%d\n", atomic_load(&w0), atomic_load(&w1));
    close(ep0);
    close(ep1);
    close(stop_fd);
    close(efd);

    /* 2. Epoll fdinfo sdev/ino on tmpfs (/dev/shm) and /tmp */
    check_fdinfo("tmpfs", "/dev/shm/ep_opt_fifo");
    check_fdinfo("tmp", "/tmp/ep_opt_fifo");

    /* 3. Two epolls sharing one TCP socket with EPOLLET (HostEpoll + Dynamic dup/exclusive) */
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t al = sizeof(a);
    bind(l, (void *)&a, sizeof(a));
    listen(l, 4);
    getsockname(l, (void *)&a, &al);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    connect(c, (void *)&a, sizeof(a));
    int sv = accept(l, NULL, NULL);
    int sv_dup = dup(sv);
    int e1 = epoll_create1(0), e2 = epoll_create1(0);
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 1;
    epoll_ctl(e1, EPOLL_CTL_ADD, sv, &ev);
    /* e1 watches sv via HostEpoll, e2 watches sv_dup via Dynamic; probe e2 first on packet 2 */
    ev.events = EPOLLIN | EPOLLEXCLUSIVE | EPOLLET;
    ev.data.u64 = 2;
    epoll_ctl(e2, EPOLL_CTL_ADD, sv_dup, &ev);
    struct epoll_event out;
    write(c, "a", 1);
    int a1r = epoll_wait(e1, &out, 1, 500);
    int a2r = epoll_wait(e2, &out, 1, 500);
    write(c, "b", 1);
    /* Dynamic epoll (e2) consumes HostEdges first: e1 (HostEpoll) MUST still fire! */
    int b2r = epoll_wait(e2, &out, 1, 500);
    int b1r = epoll_wait(e1, &out, 1, 500);
    int q1 = epoll_wait(e1, &out, 1, 20);
    int q2 = epoll_wait(e2, &out, 1, 20);
    printf("shared tcp ET: first=%d,%d again=%d,%d quiet=%d,%d\n", a1r, a2r, b2r, b1r, q1, q2);
    close(e1);
    close(e2);
    close(sv_dup);
    close(sv);
    close(c);
    close(l);
    return 0;
}
C
gcc -O1 -o epoll_opt epoll_opt.c -lpthread
./epoll_opt
