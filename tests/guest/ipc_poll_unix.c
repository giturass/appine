/*
 * Regression tests for Package 2 (poll/aio/futex/unix/ipc/mqueue):
 * - epoll_pwait preserves EPOLLONESHOT/EPOLLET events on EFAULT and returns partial counts on
 *   page-boundary copy faults without dropping remaining events;
 * - epoll top-down nesting enforces MAX_NESTS (ELOOP) while permitting non-epoll leaves and
 *   restoring headroom after EPOLL_CTL_DEL;
 * - EPOLLEXCLUSIVE gates filter waiters by direction and wanted mask so a read-side edge skips
 *   a POLLOUT-only waiter and wakes a POLLIN waiter;
 * - io_getevents interrupted by a signal returns already-queued events instead of EINTR (and
 *   returns EINTR when none are queued);
 * - AIO RWF_APPEND and RWF_NOWAIT apply per-request without mutating O_APPEND/O_NONBLOCK on the
 *   shared open file;
 * - a robust PI futex held across execve wakes a blocked FUTEX_LOCK_PI waiter with FUTEX_OWNER_DIED;
 * - connected AF_UNIX SOCK_DGRAM send returns EPERM after the peer reconnects to a third socket;
 * - AF_UNIX pathname bind rejects trailing slashes (ENOENT / EADDRINUSE) and pathname connect
 *   checks MAY_WRITE (EACCES) before S_IFSOCK (ECONNREFUSED);
 * - AF_UNIX stream recv/read preserves unread data across EFAULT and partial page-boundary copy
 *   faults, and MSG_WAITALL preserves pending ECONNRESET for the next read;
 * - AF_UNIX datagram recvmsg drops the datagram on EFAULT;
 * - zero-byte AF_UNIX stream sendmsg carrying SCM_RIGHTS returns EAGAIN when the buffer is full;
 * - AF_UNIX cycle GC runs on non-close drop paths (MSG_CTRUNC, accept4 addr-write fault, non-last
 *   thread exit after unshare(CLONE_FILES), AIO io_destroy dropping PendingPoll);
 * - SysV SEM_UNDO lists follow CLONE_SYSVSEM / unshare(CLONE_SYSVSEM | CLONE_NEWIPC) semantics;
 * - SysV semmns and shmall sysctl limits are enforced (ENOSPC);
 * - POSIX mqueue mq_open/mq_unlink honour mq_dir permissions and only apply sticky checks when
 *   S_ISVTX is set.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
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
#ifndef SYS_io_setup
#define SYS_io_setup 0
#endif
#ifndef SYS_io_destroy
#define SYS_io_destroy 1
#endif
#ifndef SYS_io_submit
#define SYS_io_submit 2
#endif
#ifndef SYS_io_cancel
#define SYS_io_cancel 3
#endif
#ifndef SYS_io_getevents
#define SYS_io_getevents 4
#endif
#ifndef SYS_futex
#define SYS_futex 98
#endif
#ifndef SYS_set_robust_list
#define SYS_set_robust_list 99
#endif
#ifndef SYS_mq_open
#define SYS_mq_open 180
#endif
#ifndef SYS_mq_unlink
#define SYS_mq_unlink 181
#endif
#ifndef SYS_gettid
#define SYS_gettid 178
#endif

#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_WAITERS 0x80000000U
#define FUTEX_OWNER_DIED 0x40000000U
#define FUTEX_TID_MASK 0x3fffffffU

#define IOCB_CMD_PREAD 0
#define IOCB_CMD_PWRITE 1
#define IOCB_CMD_POLL 5
#define RWF_NOWAIT 0x8U
#define RWF_APPEND 0x10U

struct linux_iocb {
    uint64_t aio_data;
    uint32_t aio_key;
    uint32_t aio_rw_flags;
    uint16_t aio_lio_opcode;
    int16_t aio_reqprio;
    uint32_t aio_fildes;
    uint64_t aio_buf;
    uint64_t aio_nbytes;
    int64_t aio_offset;
    uint64_t aio_reserved2;
    uint32_t aio_flags;
    uint32_t aio_resfd;
};

struct linux_io_event {
    uint64_t data;
    uint64_t obj;
    int64_t res;
    int64_t res2;
};

struct linux_robust_list {
    struct linux_robust_list *next;
};

struct linux_robust_list_head {
    struct linux_robust_list list;
    long futex_offset;
    struct linux_robust_list *list_op_pending;
};

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static void write_proc_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    CHECK(fd >= 0, "open %s for write", path);
    ssize_t n = write(fd, s, strlen(s));
    CHECK(n == (ssize_t)strlen(s), "write %s", path);
    close(fd);
}

static void wait_ok(pid_t pid, const char *label)
{
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid %s", label);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "%s failed (status=0x%x)", label, st);
}

static int send_fd(int sock, int fd_to_send, const char *payload, size_t len, int flags)
{
    char cbuf[CMSG_SPACE(sizeof(int))];
    memset(cbuf, 0, sizeof(cbuf));
    struct iovec iov = {.iov_base = (void *)payload, .iov_len = len};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd_to_send, sizeof(int));
    return (int)sendmsg(sock, &msg, flags);
}

/* 1. epoll_pwait EFAULT and partial page-boundary copy */
static void test_epoll_efault_and_partial_copy(void)
{
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0, "epoll_create1");
    int e1 = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
    int e2 = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(e1 >= 0 && e2 >= 0, "eventfd");

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = 1;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, e1, &ev) == 0, "add e1");
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 2;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, e2, &ev) == 0, "add e2");

    /* Unmapped output buffer: must return EFAULT without disarming ONESHOT or consuming ET */
    errno = 0;
    int r = epoll_pwait(ep, (struct epoll_event *)0x1000, 2, 0, NULL);
    CHECK(r == -1 && errno == EFAULT, "epoll_pwait EFAULT (r=%d)", r);

    struct epoll_event out[2];
    r = epoll_pwait(ep, out, 2, 0, NULL);
    CHECK(r == 2, "both events must survive EFAULT (got %d)", r);
    CHECK((out[0].data.u64 == 1 && out[1].data.u64 == 2) ||
              (out[0].data.u64 == 2 && out[1].data.u64 == 1),
          "unexpected event data after EFAULT");

    /* Re-arm e1 and trigger a new edge on e2 */
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = 11;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, e1, &ev) == 0, "rearm e1");
    uint64_t one = 1;
    CHECK(write(e2, &one, sizeof(one)) == (ssize_t)sizeof(one), "write e2");
    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 22;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, e2, &ev) == 0, "mod e2");

    /* 2 pages: second page PROT_NONE; place array so entry 0 fits and entry 1 faults */
    size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *pages = mmap(NULL, pgsz * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED, "mmap 2 pages");
    CHECK(mprotect(pages + pgsz, pgsz, PROT_NONE) == 0, "mprotect guard page");

    struct epoll_event *half = (struct epoll_event *)(pages + pgsz - sizeof(struct epoll_event));
    r = epoll_pwait(ep, half, 2, 0, NULL);
    CHECK(r == 1, "partial page-boundary epoll_pwait must return 1 (got %d)", r);
    uint64_t first = half[0].data.u64;
    CHECK(first == 11 || first == 22, "unexpected first partial event %llu", (unsigned long long)first);

    /* The second event must still be pending and reported cleanly */
    r = epoll_pwait(ep, out, 2, 0, NULL);
    CHECK(r == 1, "remaining event after partial copy must be delivered (got %d)", r);
    CHECK(out[0].data.u64 == (first == 11 ? 22 : 11),
          "wrong remaining event %llu", (unsigned long long)out[0].data.u64);

    /* Neither should re-fire */
    r = epoll_pwait(ep, out, 2, 0, NULL);
    CHECK(r == 0, "events should now be consumed (got %d)", r);

    munmap(pages, pgsz * 2);
    close(e1);
    close(e2);
    close(ep);
}

/* 2. Top-down epoll nesting depth limit */
static void test_epoll_top_down_nesting(void)
{
    int eps[6];
    for (int i = 0; i < 6; i++) {
        eps[i] = epoll_create1(EPOLL_CLOEXEC);
        CHECK(eps[i] >= 0, "epoll_create1 %d", i);
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0};
    /* Build top-down chain: e0 -> e1 -> e2 -> e3 -> e4 (depth 4 = MAX_NESTS) */
    for (int i = 0; i < 4; i++) {
        CHECK(epoll_ctl(eps[i], EPOLL_CTL_ADD, eps[i + 1], &ev) == 0,
              "top-down add e%d -> e%d", i, i + 1);
    }
    /* Adding e5 under e4 makes depth 5 > MAX_NESTS: must fail with ELOOP */
    errno = 0;
    CHECK(epoll_ctl(eps[4], EPOLL_CTL_ADD, eps[5], &ev) == -1 && errno == ELOOP,
          "depth 5 top-down epoll must fail with ELOOP");

    /* A non-epoll leaf at e4 is still allowed and propagates readiness to e0 */
    int p[2];
    CHECK(pipe2(p, O_CLOEXEC) == 0, "pipe2");
    CHECK(epoll_ctl(eps[4], EPOLL_CTL_ADD, p[0], &ev) == 0, "add pipe leaf to e4");
    CHECK(write(p[1], "x", 1) == 1, "write pipe");
    struct epoll_event out;
    CHECK(epoll_wait(eps[0], &out, 1, 0) == 1 && (out.events & EPOLLIN),
          "pipe readiness should propagate through depth-4 epoll chain");

    /* Removing e1 from e0 frees one level so e4 -> e5 now succeeds */
    CHECK(epoll_ctl(eps[0], EPOLL_CTL_DEL, eps[1], NULL) == 0, "del e1 from e0");
    CHECK(epoll_ctl(eps[4], EPOLL_CTL_ADD, eps[5], &ev) == 0,
          "e4 -> e5 must succeed after removing e0 -> e1");

    close(p[0]);
    close(p[1]);
    for (int i = 0; i < 6; i++)
        close(eps[i]);
}

/* 3. Direction-aware EPOLLEXCLUSIVE gates */
struct excl_arg {
    int ep;
    int got;
    uint32_t events;
};

static void *excl_waiter_thread(void *arg)
{
    struct excl_arg *a = arg;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    a->got = epoll_wait(a->ep, &ev, 1, 3000);
    a->events = ev.events;
    return NULL;
}

static void test_epoll_exclusive_direction(void)
{
    int efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(efd >= 0, "eventfd");
    int ep_out = epoll_create1(EPOLL_CLOEXEC);
    int ep_in = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep_out >= 0 && ep_in >= 0, "epoll_create1");

    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET | EPOLLEXCLUSIVE;
    ev.data.u64 = 1;
    CHECK(epoll_ctl(ep_out, EPOLL_CTL_ADD, efd, &ev) == 0, "add ep_out");
    /* Drain initial POLLOUT edge on ep_out */
    CHECK(epoll_wait(ep_out, &ev, 1, 0) == 1 && (ev.events & EPOLLOUT), "drain initial POLLOUT");

    ev.events = EPOLLIN | EPOLLEXCLUSIVE;
    ev.data.u64 = 2;
    CHECK(epoll_ctl(ep_in, EPOLL_CTL_ADD, efd, &ev) == 0, "add ep_in");

    struct excl_arg a_out = {.ep = ep_out, .got = -99, .events = 0};
    struct excl_arg a_in = {.ep = ep_in, .got = -99, .events = 0};
    pthread_t t_out, t_in;
    CHECK(pthread_create(&t_out, NULL, excl_waiter_thread, &a_out) == 0, "spawn t_out");
    sleep_ms(30);
    CHECK(pthread_create(&t_in, NULL, excl_waiter_thread, &a_in) == 0, "spawn t_in");
    sleep_ms(30);

    /* Read-side edge: must skip t_out (POLLOUT|EPOLLET) and wake t_in (POLLIN) */
    uint64_t one = 1;
    CHECK(write(efd, &one, sizeof(one)) == (ssize_t)sizeof(one), "write efd");
    CHECK(pthread_join(t_in, NULL) == 0, "join t_in");
    CHECK(a_in.got == 1 && (a_in.events & EPOLLIN),
          "POLLIN exclusive waiter must wake on read edge (got=%d ev=0x%x)", a_in.got, a_in.events);

    /* Drain efd (write-side edge) to wake t_out */
    uint64_t val = 0;
    CHECK(read(efd, &val, sizeof(val)) == (ssize_t)sizeof(val), "read efd");
    CHECK(pthread_join(t_out, NULL) == 0, "join t_out");
    CHECK(a_out.got == 1 && (a_out.events & EPOLLOUT),
          "POLLOUT exclusive waiter must wake on write edge (got=%d ev=0x%x)", a_out.got, a_out.events);

    close(ep_out);
    close(ep_in);
    close(efd);
}

/* 4. AIO io_getevents EINTR with queued events + per-request RWF_APPEND/RWF_NOWAIT */
static volatile sig_atomic_t got_sigusr1 = 0;

static void sigusr1_handler(int sig)
{
    (void)sig;
    got_sigusr1 = 1;
}

static void *signal_main_thread(void *arg)
{
    pthread_t target = *(pthread_t *)arg;
    sleep_ms(40);
    pthread_kill(target, SIGUSR1);
    return NULL;
}

static void test_aio_eintr_and_per_request_flags(void)
{
    int fd = open("/tmp/aio_rwf", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(fd >= 0, "open /tmp/aio_rwf");
    CHECK(write(fd, "hello", 5) == 5, "seed aio file");
    int orig_fl = fcntl(fd, F_GETFL);
    CHECK((orig_fl & (O_APPEND | O_NONBLOCK)) == 0, "file starts without O_APPEND/O_NONBLOCK");

    uint64_t ctx = 0;
    CHECK(syscall(SYS_io_setup, 8, &ctx) == 0, "io_setup");

    /* RWF_APPEND at offset 0 must append without setting O_APPEND on the file */
    char bang = '!';
    struct linux_iocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_data = 101;
    cb.aio_lio_opcode = IOCB_CMD_PWRITE;
    cb.aio_rw_flags = RWF_APPEND;
    cb.aio_fildes = (uint32_t)fd;
    cb.aio_buf = (uint64_t)(uintptr_t)&bang;
    cb.aio_nbytes = 1;
    cb.aio_offset = 0;
    struct linux_iocb *cbs[2] = {&cb, NULL};
    CHECK(syscall(SYS_io_submit, ctx, 1, cbs) == 1, "io_submit RWF_APPEND");

    struct linux_io_event evs[2];
    CHECK(syscall(SYS_io_getevents, ctx, 1, 1, evs, NULL) == 1, "io_getevents RWF_APPEND");
    CHECK(evs[0].data == 101 && evs[0].res == 1, "RWF_APPEND res=%lld", (long long)evs[0].res);
    CHECK(fcntl(fd, F_GETFL) == orig_fl, "RWF_APPEND must not mutate file flags");

    char verify[16] = {0};
    CHECK(pread(fd, verify, sizeof(verify), 0) == 6 && memcmp(verify, "hello!", 6) == 0,
          "RWF_APPEND content mismatch: '%s'", verify);

    /* RWF_NOWAIT on an empty blocking pipe must return -EAGAIN without setting O_NONBLOCK */
    int p[2];
    CHECK(pipe2(p, O_CLOEXEC) == 0, "pipe2 aio");
    int p_fl = fcntl(p[0], F_GETFL);
    CHECK((p_fl & O_NONBLOCK) == 0, "pipe starts blocking");

    char pbuf[4];
    memset(&cb, 0, sizeof(cb));
    cb.aio_data = 102;
    cb.aio_lio_opcode = IOCB_CMD_PREAD;
    cb.aio_rw_flags = RWF_NOWAIT;
    cb.aio_fildes = (uint32_t)p[0];
    cb.aio_buf = (uint64_t)(uintptr_t)pbuf;
    cb.aio_nbytes = sizeof(pbuf);
    cb.aio_offset = 0;
    CHECK(syscall(SYS_io_submit, ctx, 1, cbs) == 1, "io_submit RWF_NOWAIT");
    CHECK(syscall(SYS_io_getevents, ctx, 1, 1, evs, NULL) == 1, "io_getevents RWF_NOWAIT");
    CHECK(evs[0].data == 102 && evs[0].res == -EAGAIN,
          "RWF_NOWAIT on empty pipe must return -EAGAIN (got %lld)", (long long)evs[0].res);
    CHECK(fcntl(p[0], F_GETFL) == p_fl, "RWF_NOWAIT must not mutate pipe O_NONBLOCK");

    /* io_getevents EINTR with queued events returns queued count instead of EINTR */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr1_handler;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction SIGUSR1");

    struct linux_iocb cb_wr, cb_poll;
    memset(&cb_wr, 0, sizeof(cb_wr));
    cb_wr.aio_data = 201;
    cb_wr.aio_lio_opcode = IOCB_CMD_PWRITE;
    cb_wr.aio_fildes = (uint32_t)fd;
    cb_wr.aio_buf = (uint64_t)(uintptr_t)&bang;
    cb_wr.aio_nbytes = 1;
    cb_wr.aio_offset = 6;

    memset(&cb_poll, 0, sizeof(cb_poll));
    cb_poll.aio_data = 202;
    cb_poll.aio_lio_opcode = IOCB_CMD_POLL;
    cb_poll.aio_fildes = (uint32_t)p[0];
    cb_poll.aio_buf = POLLIN;

    cbs[0] = &cb_wr;
    cbs[1] = &cb_poll;
    CHECK(syscall(SYS_io_submit, ctx, 2, cbs) == 2, "io_submit write+poll");

    pthread_t self = pthread_self();
    pthread_t kicker;
    got_sigusr1 = 0;
    CHECK(pthread_create(&kicker, NULL, signal_main_thread, &self) == 0, "spawn kicker 1");
    long got = syscall(SYS_io_getevents, ctx, 2, 2, evs, NULL);
    CHECK(pthread_join(kicker, NULL) == 0, "join kicker 1");
    CHECK(got_sigusr1 == 1, "SIGUSR1 should have fired");
    CHECK(got == 1 && evs[0].data == 201,
          "io_getevents interrupted with 1 queued event must return 1 (got %ld)", got);

    /* With 0 events queued, signal interruption must return EINTR */
    got_sigusr1 = 0;
    CHECK(pthread_create(&kicker, NULL, signal_main_thread, &self) == 0, "spawn kicker 2");
    errno = 0;
    got = syscall(SYS_io_getevents, ctx, 1, 1, evs, NULL);
    int saved = errno;
    CHECK(pthread_join(kicker, NULL) == 0, "join kicker 2");
    CHECK(got == -1 && saved == EINTR,
          "io_getevents interrupted with 0 queued events must return EINTR (got=%ld errno=%d)",
          got, saved);

    CHECK(syscall(SYS_io_destroy, ctx) == 0, "io_destroy");
    close(p[0]);
    close(p[1]);
    close(fd);
    unlink("/tmp/aio_rwf");
}

/* 5. Robust PI futex held across execve */
struct pi_shared {
    struct linux_robust_list_head head;
    struct {
        struct linux_robust_list node;
        uint32_t lock;
    } entry;
};

static void test_pi_futex_execve_handover(const char *self_path)
{
    struct pi_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sh != MAP_FAILED, "mmap pi_shared");
    memset(sh, 0, sizeof(*sh));

    int ready_pipe[2];
    CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0, "pipe2 pi");

    pid_t child = fork();
    CHECK(child >= 0, "fork pi");
    if (child == 0) {
        close(ready_pipe[0]);
        sh->head.list.next = &sh->head.list;
        sh->head.futex_offset = (long)((char *)&sh->entry.lock - (char *)&sh->entry.node);
        sh->head.list_op_pending = NULL;
        CHECK(syscall(SYS_set_robust_list, &sh->head, sizeof(sh->head)) == 0, "set_robust_list");

        /* Acquire PI futex and link it onto our robust list */
        CHECK(syscall(SYS_futex, &sh->entry.lock, FUTEX_LOCK_PI, 0, NULL, NULL, 0) == 0,
              "child FUTEX_LOCK_PI");
        sh->entry.node.next = &sh->head.list;
        sh->head.list.next = &sh->entry.node;

        char c = '1';
        CHECK(write(ready_pipe[1], &c, 1) == 1, "signal parent");
        close(ready_pipe[1]);

        /* Wait until parent is blocked in FUTEX_LOCK_PI (FUTEX_WAITERS bit set) */
        for (int i = 0; i < 500; i++) {
            if (__atomic_load_n(&sh->entry.lock, __ATOMIC_ACQUIRE) & FUTEX_WAITERS)
                break;
            sleep_ms(5);
        }
        CHECK((__atomic_load_n(&sh->entry.lock, __ATOMIC_ACQUIRE) & FUTEX_WAITERS) != 0,
              "parent never set FUTEX_WAITERS");

        execl(self_path, self_path, "--exit-ok", (char *)NULL);
        _exit(127);
    }

    close(ready_pipe[1]);
    char c = 0;
    CHECK(read(ready_pipe[0], &c, 1) == 1, "wait child lock");
    close(ready_pipe[0]);

    /* Block in FUTEX_LOCK_PI until child's execve hands ownership over with FUTEX_OWNER_DIED */
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_REALTIME, &ts) == 0, "clock_gettime");
    ts.tv_sec += 5;
    long r = syscall(SYS_futex, &sh->entry.lock, FUTEX_LOCK_PI, 0, &ts, NULL, 0);
    CHECK(r == 0, "parent FUTEX_LOCK_PI must wake on child execve (r=%ld)", r);
    uint32_t v = __atomic_load_n(&sh->entry.lock, __ATOMIC_ACQUIRE);
    uint32_t my_tid = (uint32_t)syscall(SYS_gettid);
    CHECK((v & FUTEX_OWNER_DIED) != 0, "expected FUTEX_OWNER_DIED after execve (v=0x%x)", v);
    CHECK((v & FUTEX_TID_MASK) == my_tid, "expected owner=%u got %u", my_tid, v & FUTEX_TID_MASK);
    CHECK(syscall(SYS_futex, &sh->entry.lock, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0) == 0,
          "parent FUTEX_UNLOCK_PI");

    wait_ok(child, "pi execve child");
    munmap(sh, 4096);
}

/* 6. AF_UNIX connected dgram unix_may_send, trailing slash bind, connect MAY_WRITE order */
static void make_abstract(struct sockaddr_un *sa, socklen_t *len, const char *name)
{
    memset(sa, 0, sizeof(*sa));
    sa->sun_family = AF_UNIX;
    sa->sun_path[0] = '\0';
    size_t n = strlen(name);
    memcpy(sa->sun_path + 1, name, n);
    *len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

static void test_passcred_autobind(void)
{
    struct sockaddr_un peer, sender, local;
    const socklen_t unnamed_len = offsetof(struct sockaddr_un, sun_path);
    const socklen_t autobound_len = unnamed_len + 6; /* leading NUL and five hex digits */
    const int on = 1;
    socklen_t peer_len;
    make_abstract(&peer, &peer_len, "passcred-reply");
    int server = socket(AF_UNIX, SOCK_DGRAM, 0);
    CHECK(server >= 0 && bind(server, (struct sockaddr *)&peer, peer_len) == 0, "bind server");
    for (int connected = 0; connected <= 1; connected++) {
        int client = socket(AF_UNIX, SOCK_DGRAM, 0);
        socklen_t len = sizeof(local);
        CHECK(client >= 0 && setsockopt(client, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == 0,
              "enable credentials");
        CHECK(getsockname(client, (struct sockaddr *)&local, &len) == 0 &&
              len == unnamed_len, "setsockopt alone leaves client unnamed");
        if (connected) {
            CHECK(connect(client, (struct sockaddr *)&peer, peer_len) == 0, "connect client");
            len = sizeof(local);
            CHECK(getsockname(client, (struct sockaddr *)&local, &len) == 0 &&
                  len == autobound_len, "connect autobinds");
            CHECK(send(client, "x", 1, 0) == 1, "send on connected socket");
        } else {
            CHECK(sendto(client, "x", 1, 0, (struct sockaddr *)&peer, peer_len) == 1, "sendto");
        }
        char c;
        socklen_t sender_len = sizeof(sender);
        CHECK(recvfrom(server, &c, 1, MSG_DONTWAIT, (struct sockaddr *)&sender, &sender_len) == 1 &&
              c == 'x', "receive request");
        len = sizeof(local);
        CHECK(getsockname(client, (struct sockaddr *)&local, &len) == 0 &&
              len == autobound_len && local.sun_path[0] == 0 &&
              len == sender_len && memcmp(&sender, &local, len) == 0, "sender has autobound name");
        CHECK(sendto(server, "y", 1, 0, (struct sockaddr *)&sender, sender_len) == 1 &&
              recv(client, &c, 1, MSG_DONTWAIT) == 1 && c == 'y', "reply to autobound client");
        close(client);
    }
    close(server);

    /* A seqpacket send uses the datagram autobind rule. A stream send on a pair stays unnamed. */
    const int types[] = {SOCK_STREAM, SOCK_SEQPACKET};
    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        int pair[2];
        CHECK(socketpair(AF_UNIX, types[i], 0, pair) == 0 &&
              setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &on, sizeof(on)) == 0 &&
              send(pair[0], "x", 1, 0) == 1, "send on credential-enabled socketpair");
        socklen_t len = sizeof(local);
        CHECK(getsockname(pair[0], (struct sockaddr *)&local, &len) == 0 &&
              len == (types[i] == SOCK_SEQPACKET ? autobound_len : unnamed_len),
              "socketpair autobind by type");
        close(pair[0]);
        close(pair[1]);
    }
}

static void test_unix_dgram_may_send_and_paths(void)
{
    int a = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int b = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int c = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(a >= 0 && b >= 0 && c >= 0, "unix dgram sockets");

    struct sockaddr_un sa_a, sa_b, sa_c;
    socklen_t la, lb, lc;
    make_abstract(&sa_a, &la, "pkg2_dgram_a");
    make_abstract(&sa_b, &lb, "pkg2_dgram_b");
    make_abstract(&sa_c, &lc, "pkg2_dgram_c");
    CHECK(bind(a, (struct sockaddr *)&sa_a, la) == 0, "bind a");
    CHECK(bind(b, (struct sockaddr *)&sa_b, lb) == 0, "bind b");
    CHECK(bind(c, (struct sockaddr *)&sa_c, lc) == 0, "bind c");

    CHECK(connect(a, (struct sockaddr *)&sa_b, lb) == 0, "connect a->b");
    CHECK(connect(b, (struct sockaddr *)&sa_a, la) == 0, "connect b->a");
    CHECK(send(a, "hi", 2, MSG_DONTWAIT) == 2, "send a->b while mutually connected");
    char buf[8];
    CHECK(recv(b, buf, sizeof(buf), MSG_DONTWAIT) == 2, "recv b");

    /* Reconnect b to c: a's connected send to b must now fail with EPERM */
    CHECK(connect(b, (struct sockaddr *)&sa_c, lc) == 0, "reconnect b->c");
    errno = 0;
    CHECK(send(a, "no", 2, MSG_DONTWAIT) == -1 && errno == EPERM,
          "connected dgram send must fail with EPERM after peer reconnects");

    /* Closing c still leaves b not connected back to a */
    close(c);
    errno = 0;
    CHECK(send(a, "no", 2, MSG_DONTWAIT) == -1 && errno == EPERM,
          "connected dgram send must still fail with EPERM after peer's new target closes");
    close(a);
    close(b);

    /* Pathname bind with trailing slash: ENOENT for missing, EADDRINUSE for existing */
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(s >= 0, "unix stream socket");
    struct sockaddr_un sp;
    memset(&sp, 0, sizeof(sp));
    sp.sun_family = AF_UNIX;
    strcpy(sp.sun_path, "/tmp/missing_unix_sock/");
    errno = 0;
    CHECK(bind(s, (struct sockaddr *)&sp, sizeof(sp)) == -1 && errno == ENOENT,
          "bind missing trailing slash must return ENOENT");
    struct stat st;
    CHECK(stat("/tmp/missing_unix_sock", &st) == -1 && errno == ENOENT,
          "missing trailing slash bind must not create node");

    CHECK(mkdir("/tmp/exist_unix_dir", 0755) == 0, "mkdir exist_unix_dir");
    strcpy(sp.sun_path, "/tmp/exist_unix_dir/");
    errno = 0;
    CHECK(bind(s, (struct sockaddr *)&sp, sizeof(sp)) == -1 && errno == EADDRINUSE,
          "bind existing dir trailing slash must return EADDRINUSE");
    rmdir("/tmp/exist_unix_dir");
    close(s);

    /* Pathname connect checks MAY_WRITE (EACCES) before S_IFSOCK (ECONNREFUSED) */
    int rfd = open("/tmp/not_a_unix_sock", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    CHECK(rfd >= 0, "create regular file");
    close(rfd);

    pid_t pid = fork();
    CHECK(pid >= 0, "fork connect EACCES");
    if (pid == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "drop to uid 1000");
        int cs = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(cs >= 0, "socket");
        struct sockaddr_un target;
        memset(&target, 0, sizeof(target));
        target.sun_family = AF_UNIX;
        strcpy(target.sun_path, "/tmp/not_a_unix_sock");
        errno = 0;
        CHECK(connect(cs, (struct sockaddr *)&target, sizeof(target)) == -1 && errno == EACCES,
              "connect to unwritable non-socket must return EACCES");
        _exit(0);
    }
    wait_ok(pid, "connect EACCES child");

    CHECK(chmod("/tmp/not_a_unix_sock", 0666) == 0, "chmod 0666");
    pid = fork();
    CHECK(pid >= 0, "fork connect ECONNREFUSED");
    if (pid == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "drop to uid 1000");
        int cs = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(cs >= 0, "socket");
        struct sockaddr_un target;
        memset(&target, 0, sizeof(target));
        target.sun_family = AF_UNIX;
        strcpy(target.sun_path, "/tmp/not_a_unix_sock");
        errno = 0;
        CHECK(connect(cs, (struct sockaddr *)&target, sizeof(target)) == -1 &&
                  errno == ECONNREFUSED,
              "connect to writable non-socket must return ECONNREFUSED");
        _exit(0);
    }
    wait_ok(pid, "connect ECONNREFUSED child");
    unlink("/tmp/not_a_unix_sock");
}

/* 7. AF_UNIX stream/dgram copy-faults, MSG_WAITALL reset, zero-byte SCM_RIGHTS when full */
static void test_unix_stream_dgram_faults_and_zero_byte_scm(void)
{
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == 0, "socketpair stream");
    CHECK(write(sv[0], "abcdefgh", 8) == 8, "write abcdefgh");

    /* EFAULT on recv and recvmsg must preserve all 8 bytes */
    errno = 0;
    CHECK(recv(sv[1], (void *)0x1000, 8, MSG_DONTWAIT) == -1 && errno == EFAULT,
          "stream recv EFAULT");
    struct iovec bad_iov = {.iov_base = (void *)0x1000, .iov_len = 8};
    struct msghdr bad_msg;
    memset(&bad_msg, 0, sizeof(bad_msg));
    bad_msg.msg_iov = &bad_iov;
    bad_msg.msg_iovlen = 1;
    errno = 0;
    CHECK(recvmsg(sv[1], &bad_msg, MSG_DONTWAIT) == -1 && errno == EFAULT,
          "stream recvmsg EFAULT");

    /* Partial page-boundary read: 4 bytes copied, remaining 4 preserved */
    size_t pgsz = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *pages = mmap(NULL, pgsz * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pages != MAP_FAILED, "mmap unix guard");
    CHECK(mprotect(pages + pgsz, pgsz, PROT_NONE) == 0, "mprotect guard");
    char *half = (char *)(pages + pgsz - 4);
    ssize_t n = read(sv[1], half, 8);
    CHECK(n == 4 && memcmp(half, "abcd", 4) == 0, "partial stream read got %zd", n);
    char rest[16] = {0};
    n = read(sv[1], rest, 8);
    CHECK(n == 4 && memcmp(rest, "efgh", 4) == 0, "remaining stream read got %zd '%s'", n, rest);
    munmap(pages, pgsz * 2);
    close(sv[0]);
    close(sv[1]);

    /* MSG_WAITALL returns queued bytes and preserves pending ECONNRESET for the next read */
    int sv2[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv2) == 0, "socketpair reset");
    CHECK(write(sv2[0], "hello", 5) == 5, "write hello");
    CHECK(write(sv2[1], "unread", 6) == 6, "leave unread data in peer rx");
    close(sv2[0]); /* peer closes with unread data -> sets reset on sv2[1] */
    memset(rest, 0, sizeof(rest));
    n = recv(sv2[1], rest, 10, MSG_WAITALL);
    CHECK(n == 5 && memcmp(rest, "hello", 5) == 0, "MSG_WAITALL first read got %zd", n);
    errno = 0;
    n = recv(sv2[1], rest, 10, 0);
    CHECK(n == -1 && errno == ECONNRESET, "next read after MSG_WAITALL must see ECONNRESET (n=%zd)", n);
    close(sv2[1]);

    /* Datagram recvmsg onto unmapped buffer returns EFAULT and drops the datagram;
     * non-truncated recvmsg must not set MSG_TRUNC, while truncated recvmsg must set it */
    int dv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, dv) == 0, "socketpair dgram");
    CHECK(send(dv[0], "dropme", 6, 0) == 6, "send dropme");
    CHECK(send(dv[0], "second", 6, 0) == 6, "send second");
    CHECK(send(dv[0], "truncate_me", 11, 0) == 11, "send truncate_me");
    errno = 0;
    CHECK(recvmsg(dv[1], &bad_msg, MSG_DONTWAIT) == -1 && errno == EFAULT,
          "dgram recvmsg EFAULT");
    memset(rest, 0, sizeof(rest));
    struct iovec ok_iov = {.iov_base = rest, .iov_len = sizeof(rest)};
    struct msghdr ok_msg;
    memset(&ok_msg, 0, sizeof(ok_msg));
    ok_msg.msg_iov = &ok_iov;
    ok_msg.msg_iovlen = 1;
    n = recvmsg(dv[1], &ok_msg, MSG_DONTWAIT);
    CHECK(n == 6 && memcmp(rest, "second", 6) == 0 && (ok_msg.msg_flags & MSG_TRUNC) == 0,
          "non-truncated dgram recvmsg must be 'second' without MSG_TRUNC (n=%zd flags=0x%x)",
          n, ok_msg.msg_flags);
    ok_iov.iov_len = 4;
    ok_msg.msg_flags = 0;
    n = recvmsg(dv[1], &ok_msg, MSG_DONTWAIT | MSG_TRUNC);
    CHECK(n == 11 && memcmp(rest, "trun", 4) == 0 && (ok_msg.msg_flags & MSG_TRUNC) != 0,
          "truncated dgram recvmsg must report full len and MSG_TRUNC (n=%zd flags=0x%x)",
          n, ok_msg.msg_flags);
    close(dv[0]);
    close(dv[1]);

    /* Zero-byte stream sendmsg carrying SCM_RIGHTS returns EAGAIN when buffer is full */
    int sv3[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv3) == 0, "socketpair full");
    char chunk[4096];
    memset(chunk, 'A', sizeof(chunk));
    while (send(sv3[0], chunk, sizeof(chunk), MSG_DONTWAIT) > 0)
        ;
    CHECK(errno == EAGAIN, "fill sv3 until EAGAIN");

    int p[2];
    CHECK(pipe2(p, O_CLOEXEC) == 0, "pipe2 scm");
    errno = 0;
    CHECK(send_fd(sv3[0], p[0], "", 0, MSG_DONTWAIT) == -1 && errno == EAGAIN,
          "zero-byte SCM_RIGHTS send on full stream must return EAGAIN");

    /* Drain room and retry: must now succeed and deliver the fd */
    CHECK(recv(sv3[1], chunk, sizeof(chunk), MSG_DONTWAIT) > 0, "drain sv3");
    CHECK(send_fd(sv3[0], p[0], "", 0, MSG_DONTWAIT) == 0,
          "zero-byte SCM_RIGHTS send with room must succeed");
    close(p[0]);
    close(p[1]);
    close(sv3[0]);
    close(sv3[1]);
}

/* 8. AF_UNIX cycle GC on non-close drop paths */
static void make_self_cycle(int cyc[2])
{
    CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, cyc) == 0, "socketpair cyc");
    CHECK(send_fd(cyc[0], cyc[1], "c", 1, 0) == 1, "send cyc[1] into itself");
}

static void assert_collected_eof(int probe_fd, const char *label)
{
    char ch = 0;
    ssize_t n = recv(probe_fd, &ch, 1, MSG_DONTWAIT);
    CHECK(n == 0, "%s: expected cycle to be collected (peer EOF), got n=%zd", label, n);
}

struct unshare_files_arg {
    int cyc_fd;
    int ready_pipe[2];
    int go_pipe[2];
};

static void *unshare_files_thread(void *arg)
{
    struct unshare_files_arg *a = arg;
    CHECK(unshare(CLONE_FILES) == 0, "thread unshare(CLONE_FILES)");
    char c = '1';
    CHECK(write(a->ready_pipe[1], &c, 1) == 1, "signal unshared");
    CHECK(read(a->go_pipe[0], &c, 1) == 1, "wait main close");
    /* Thread exits without explicitly closing cyc_fd; its unshared fd table drops on exit */
    return NULL;
}

static void test_unix_gc_non_close_paths(void)
{
    /* (a) MSG_CTRUNC dropping the last external ref to a cycle */
    {
        int cyc[2], outer[2];
        make_self_cycle(cyc);
        CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, outer) == 0, "socketpair outer");
        CHECK(send_fd(outer[0], cyc[1], "o", 1, 0) == 1, "send cyc[1] via outer");
        close(cyc[1]);

        char b = 0;
        struct iovec iov = {.iov_base = &b, .iov_len = 1};
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        /* msg_controllen = 0 -> MSG_CTRUNC drops cyc[1], while MSG_TRUNC must stay clear */
        CHECK(recvmsg(outer[1], &msg, MSG_DONTWAIT) == 1, "recvmsg MSG_CTRUNC");
        CHECK((msg.msg_flags & MSG_CTRUNC) != 0 && (msg.msg_flags & MSG_TRUNC) == 0,
              "expected MSG_CTRUNC without MSG_TRUNC (flags=0x%x)", msg.msg_flags);
        assert_collected_eof(cyc[0], "MSG_CTRUNC GC");
        close(cyc[0]);
        close(outer[0]);
        close(outer[1]);
    }

    /* (b) accept4 addr-write EFAULT dropping an embryo holding a cycle */
    {
        int cyc[2];
        make_self_cycle(cyc);
        int lst = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        int cli = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(lst >= 0 && cli >= 0, "listen/client sockets");
        struct sockaddr_un sa;
        socklen_t sl;
        make_abstract(&sa, &sl, "pkg2_accept_gc");
        CHECK(bind(lst, (struct sockaddr *)&sa, sl) == 0, "bind lst");
        CHECK(listen(lst, 4) == 0, "listen");
        CHECK(connect(cli, (struct sockaddr *)&sa, sl) == 0, "connect cli");
        CHECK(send_fd(cli, cyc[1], "e", 1, 0) == 1, "send cyc[1] into embryo");
        close(cyc[1]);
        close(cli);

        /* Embryo is popped and dropped when writing peer addr to 0x1000 faults */
        socklen_t bad_len = sizeof(struct sockaddr_un);
        errno = 0;
        CHECK(accept4(lst, (struct sockaddr *)0x1000, &bad_len, SOCK_CLOEXEC) == -1 &&
                  errno == EFAULT,
              "accept4 bad addr must return EFAULT");
        assert_collected_eof(cyc[0], "accept4 EFAULT GC");
        close(cyc[0]);
        close(lst);
    }

    /* (c) Non-last thread exiting after unshare(CLONE_FILES) */
    {
        int cyc[2];
        make_self_cycle(cyc);
        struct unshare_files_arg a;
        a.cyc_fd = cyc[1];
        CHECK(pipe2(a.ready_pipe, O_CLOEXEC) == 0, "pipe ready");
        CHECK(pipe2(a.go_pipe, O_CLOEXEC) == 0, "pipe go");
        pthread_t th;
        CHECK(pthread_create(&th, NULL, unshare_files_thread, &a) == 0, "spawn unshare thread");
        char c = 0;
        CHECK(read(a.ready_pipe[0], &c, 1) == 1, "wait thread unshared");
        close(cyc[1]); /* main drops its ref; only the thread's unshared fd table holds cyc[1] */
        CHECK(write(a.go_pipe[1], &c, 1) == 1, "let thread exit");
        CHECK(pthread_join(th, NULL) == 0, "join unshare thread");
        assert_collected_eof(cyc[0], "unshare(CLONE_FILES) non-last thread exit GC");
        close(cyc[0]);
        close(a.ready_pipe[0]);
        close(a.ready_pipe[1]);
        close(a.go_pipe[0]);
        close(a.go_pipe[1]);
    }

    /* (d) AIO io_destroy dropping a PendingPoll holding a unix socket cycle */
    {
        int cyc[2];
        make_self_cycle(cyc);
        uint64_t ctx = 0;
        CHECK(syscall(SYS_io_setup, 4, &ctx) == 0, "io_setup gc");
        struct linux_iocb cb;
        memset(&cb, 0, sizeof(cb));
        cb.aio_data = 301;
        cb.aio_lio_opcode = IOCB_CMD_POLL;
        cb.aio_fildes = (uint32_t)cyc[1];
        cb.aio_buf = POLLPRI; /* stays pending */
        struct linux_iocb *cbs[1] = {&cb};
        CHECK(syscall(SYS_io_submit, ctx, 1, cbs) == 1, "io_submit poll on cyc[1]");
        close(cyc[1]);

        /* PendingPoll still keeps cyc[1] alive */
        char ch = 0;
        errno = 0;
        CHECK(recv(cyc[0], &ch, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "PendingPoll should still hold cyc[1] alive");

        CHECK(syscall(SYS_io_destroy, ctx) == 0, "io_destroy gc");
        assert_collected_eof(cyc[0], "AIO io_destroy GC");
        close(cyc[0]);
    }
}

/* 9. SysV SEM_UNDO sharing and semmns/shmall enforcement */
struct sem_thread_arg {
    int semid;
    int unshare_flags;
    short op;
};

static void *sem_unshare_thread(void *arg)
{
    struct sem_thread_arg *a = arg;
    CHECK(unshare(a->unshare_flags) == 0, "unshare(0x%x)", a->unshare_flags);
    if (a->op != 0) {
        struct sembuf sb = {.sem_num = 0, .sem_op = a->op, .sem_flg = SEM_UNDO};
        CHECK(semop(a->semid, &sb, 1) == 0, "thread semop");
    }
    return NULL;
}

static void test_sysv_sem_undo_and_limits(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork sysv ipc");
    if (pid != 0) {
        wait_ok(pid, "sysv ipc child");
        return;
    }

    CHECK(unshare(CLONE_NEWIPC) == 0, "unshare(CLONE_NEWIPC)");
    int semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    CHECK(semid >= 0, "semget");
    CHECK(semctl(semid, 0, SETVAL, 10) == 0, "SETVAL 10");

    /* Main thread records +5 in the shared SEM_UNDO list */
    struct sembuf sb = {.sem_num = 0, .sem_op = 5, .sem_flg = SEM_UNDO};
    CHECK(semop(semid, &sb, 1) == 0, "main semop +5");
    CHECK(semctl(semid, 0, GETVAL) == 15, "val should be 15");

    /* Thread 1 unshares CLONE_SYSVSEM, adds +7 with SEM_UNDO, and exits:
     * only Thread 1's +7 is undone; main's +5 remains. */
    struct sem_thread_arg a1 = {.semid = semid, .unshare_flags = CLONE_SYSVSEM, .op = 7};
    pthread_t t1;
    CHECK(pthread_create(&t1, NULL, sem_unshare_thread, &a1) == 0, "spawn t1");
    CHECK(pthread_join(t1, NULL) == 0, "join t1");
    int v = semctl(semid, 0, GETVAL);
    CHECK(v == 15, "after CLONE_SYSVSEM thread exit, val must be 15 (got %d)", v);

    /* Thread 2 unshares CLONE_NEWIPC and exits: must NOT undo main's +5 */
    struct sem_thread_arg a2 = {.semid = semid, .unshare_flags = CLONE_NEWIPC, .op = 0};
    pthread_t t2;
    CHECK(pthread_create(&t2, NULL, sem_unshare_thread, &a2) == 0, "spawn t2");
    CHECK(pthread_join(t2, NULL) == 0, "join t2");
    v = semctl(semid, 0, GETVAL);
    CHECK(v == 15, "after CLONE_NEWIPC thread exit, val must remain 15 (got %d)", v);

    /* semmns enforcement: 1 sem already used; cap semmns = 3 */
    write_proc_str("/proc/sys/kernel/sem", "250 3 32 128\n");
    int s2 = semget(IPC_PRIVATE, 2, IPC_CREAT | 0600);
    CHECK(s2 >= 0, "semget 2 (total 3 <= semmns=3)");
    errno = 0;
    CHECK(semget(IPC_PRIVATE, 1, IPC_CREAT | 0600) == -1 && errno == ENOSPC,
          "semget exceeding semmns must return ENOSPC");

    /* shmall enforcement: cap shmall = 2 pages */
    write_proc_str("/proc/sys/kernel/shmall", "2\n");
    int sh1 = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    CHECK(sh1 >= 0, "shmget 1 page");
    errno = 0;
    CHECK(shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600) == -1 && errno == ENOSPC,
          "shmget 2 more pages (> shmall=2) must return ENOSPC");
    int sh2 = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    CHECK(sh2 >= 0, "shmget 2nd page (total 2 <= shmall=2)");
    errno = 0;
    CHECK(shmget(IPC_PRIVATE, 1, IPC_CREAT | 0600) == -1 && errno == ENOSPC,
          "shmget 1 byte exceeding shmall must return ENOSPC");

    _exit(0);
}

/* 10. POSIX mqueue mq_dir permissions and sticky bit */
static void test_mqueue_root_perms_and_sticky(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork mqueue");
    if (pid != 0) {
        wait_ok(pid, "mqueue child");
        return;
    }

    CHECK(unshare(CLONE_NEWIPC | CLONE_NEWNS) == 0, "unshare ipc+ns");
    mkdir("/tmp/mq_mnt", 0755);
    CHECK(mount("none", "/tmp/mq_mnt", "mqueue", 0, NULL) == 0, "mount mqueue");

    /* A default queue costs 10 * (8192 + 48 + 48) bytes on arm64. Its inode remains
     * charged after unlink until the last open reference is dropped. */
    struct rlimit original;
    CHECK(getrlimit(RLIMIT_MSGQUEUE, &original) == 0, "get message queue limit");
    struct rlimit one = original;
    one.rlim_cur = 10 * (8192 + 48 + 48);
    CHECK(setrlimit(RLIMIT_MSGQUEUE, &one) == 0, "set one-queue limit");
    int charged = syscall(SYS_mq_open, "charged", O_CREAT | O_RDWR, 0600, NULL);
    CHECK(charged >= 0, "create at limit");
    int pin = open("/tmp/mq_mnt/charged", O_PATH);
    CHECK(pin >= 0, "pin queue inode");
    CHECK(syscall(SYS_mq_unlink, "charged") == 0, "unlink charged queue");
    CHECK(open("/tmp/mq_mnt/next", O_CREAT | O_RDWR, 0600) < 0 && errno == EMFILE,
          "mounted mqueue must include unlinked queue charge");
    close(charged);
    CHECK(open("/tmp/mq_mnt/next", O_CREAT | O_RDWR, 0600) < 0 && errno == EMFILE,
          "O_PATH alone must retain queue charge");
    close(pin);
    charged = open("/tmp/mq_mnt/next", O_CREAT | O_RDWR, 0600);
    CHECK(charged >= 0, "last close releases charge");
    close(charged);
    CHECK(syscall(SYS_mq_unlink, "next") == 0, "unlink named queue");
    CHECK(setrlimit(RLIMIT_MSGQUEUE, &original) == 0, "restore message queue limit");

    /* Root creates queue q1 owned by uid 0 with mode 0666 (umask 0 so others have rw) */
    umask(0);
    long q1 = syscall(SYS_mq_open, "q1", O_CREAT | O_RDWR, 0666, NULL);
    CHECK(q1 >= 0, "mq_open create q1");
    close((int)q1);

    /* chmod mq_dir to 0555: non-root can open existing q1, cannot create q2 or unlink q1 */
    CHECK(chmod("/tmp/mq_mnt", 0555) == 0, "chmod mq_mnt 0555");
    pid_t c = fork();
    CHECK(c >= 0, "fork mq 0555");
    if (c == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "uid 1000");
        long fd = syscall(SYS_mq_open, "q1", O_RDWR, 0, NULL);
        CHECK(fd >= 0, "0555 mq_dir must allow opening existing queue");
        close((int)fd);
        errno = 0;
        CHECK(syscall(SYS_mq_open, "q2", O_CREAT | O_RDWR, 0666, NULL) == -1 && errno == EACCES,
              "0555 mq_dir must reject mq_open(O_CREAT) with EACCES");
        errno = 0;
        CHECK(syscall(SYS_mq_unlink, "q1") == -1 && errno == EACCES,
              "0555 mq_dir must reject mq_unlink with EACCES");
        _exit(0);
    }
    wait_ok(c, "mq 0555 child");

    /* chmod mq_dir to 0000: non-root cannot even look up q1 */
    CHECK(chmod("/tmp/mq_mnt", 0000) == 0, "chmod mq_mnt 0000");
    c = fork();
    CHECK(c >= 0, "fork mq 0000");
    if (c == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "uid 1000");
        errno = 0;
        CHECK(syscall(SYS_mq_open, "q1", O_RDWR, 0, NULL) == -1 && errno == EACCES,
              "0000 mq_dir must reject mq_open lookup with EACCES");
        errno = 0;
        CHECK(syscall(SYS_mq_unlink, "q1") == -1 && errno == EACCES,
              "0000 mq_dir must reject mq_unlink lookup with EACCES");
        _exit(0);
    }
    wait_ok(c, "mq 0000 child");

    /* chmod mq_dir to 1777 (sticky): uid 1000 cannot unlink root-owned q1 */
    CHECK(chmod("/tmp/mq_mnt", 01777) == 0, "chmod mq_mnt 1777");
    c = fork();
    CHECK(c >= 0, "fork mq 1777");
    if (c == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "uid 1000");
        errno = 0;
        CHECK(syscall(SYS_mq_unlink, "q1") == -1 && (errno == EPERM || errno == EACCES),
              "1777 sticky mq_dir must reject non-owner mq_unlink");
        errno = 0;
        CHECK(unlink("/tmp/mq_mnt/q1") == -1 && (errno == EPERM || errno == EACCES),
              "1777 sticky mq_dir must reject non-owner unlink");
        _exit(0);
    }
    wait_ok(c, "mq 1777 child");

    /* chmod mq_dir to 0777 (non-sticky): uid 1000 CAN unlink root-owned q1 */
    CHECK(chmod("/tmp/mq_mnt", 0777) == 0, "chmod mq_mnt 0777");
    c = fork();
    CHECK(c >= 0, "fork mq 0777");
    if (c == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0, "uid 1000");
        CHECK(syscall(SYS_mq_unlink, "q1") == 0,
              "0777 non-sticky mq_dir must allow non-owner mq_unlink");
        _exit(0);
    }
    wait_ok(c, "mq 0777 child");

    _exit(0);
}

static int select_high_fd(int fd)
{
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval timeout = {0};
    return select(fd + 1, &readfds, NULL, NULL, &timeout);
}

static void test_select_closed_high_fd(void)
{
    int fd = fcntl(STDIN_FILENO, F_DUPFD, 200);
    CHECK(fd == 200, "allocate high fd for select");
    CHECK(close(fd) == 0, "close high fd");
    CHECK(select_high_fd(fd) == -1 && errno == EBADF, "select detects closed high fd");

    pid_t child = fork();
    CHECK(child >= 0, "fork with empty high fd slots");
    if (child == 0) {
        CHECK(select_high_fd(fd) == 0, "child fd table fits its open fds");
        _exit(0);
    }
    wait_ok(child, "select after fork");
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--exit-ok") == 0)
        return 0;

    mkdir("/tmp", 01777);

    test_select_closed_high_fd();
    test_epoll_efault_and_partial_copy();
    test_epoll_top_down_nesting();
    test_epoll_exclusive_direction();
    test_aio_eintr_and_per_request_flags();
    test_pi_futex_execve_handover(argv[0]);
    test_passcred_autobind();
    test_unix_dgram_may_send_and_paths();
    test_unix_stream_dgram_faults_and_zero_byte_scm();
    test_unix_gc_non_close_paths();
    test_sysv_sem_undo_and_limits();
    test_mqueue_root_perms_and_sticky();

    printf("all ok\n");
    return 0;
}
