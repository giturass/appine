# Pipe readiness, shrinking and tail merging when a page slot holds only a few bytes.
set -eu
cd /tmp
cat > pipe-slots.c <<'C'
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

enum { page = 4096 };
static char data[20 * page] __attribute__((aligned(page)));

static int writable(int fd)
{
    struct pollfd p = {.fd = fd, .events = POLLOUT};
    assert(poll(&p, 1, 0) >= 0);
    return !!(p.revents & POLLOUT);
}

static void make_pipe(int p[2], int pages)
{
    assert(pipe2(p, O_NONBLOCK) == 0);
    assert(fcntl(p[1], F_SETPIPE_SZ, pages * page) == pages * page);
}

int main(void)
{
    int file = open("pipe-source", O_CREAT | O_TRUNC | O_RDWR, 0600);
    assert(file >= 0 && ftruncate(file, 2 * page) == 0);
    for (int kind = 0; kind < 4; kind++) {
        int p[2], dst[2], bytes;
        make_pipe(p, 2);
        make_pipe(dst, 1);
        off_t off = page - 2;
        if (kind == 0) {
            assert(splice(file, &off, p[1], NULL, 4, 0) == 4);
        } else if (kind == 1) {
            assert(sendfile(p[1], file, &off, 4) == 4);
        } else if (kind == 2) {
            struct iovec v = {data + page - 2, 4};
            assert(vmsplice(p[1], &v, 1, 0) == 4);
        } else {
            struct iovec v[] = {{data, 2}, {data + 2, 2}};
            assert(vmsplice(p[1], v, 2, 0) == 4);
        }
        assert(ioctl(p[0], FIONREAD, &bytes) == 0 && bytes == 4);
        int shrink = fcntl(p[1], F_SETPIPE_SZ, page);
        int busy = shrink == -1 && errno == EBUSY;
        printf("%d full %d busy %d\n", kind, !writable(p[1]), busy);
        int ep = epoll_create1(0);
        struct epoll_event event = {.events = EPOLLOUT | EPOLLET};
        assert(epoll_ctl(ep, EPOLL_CTL_ADD, p[1], &event) == 0);
        printf("initial edge %d\n", epoll_wait(ep, &event, 1, 0));
        printf("tee bytes %zd\n", tee(p[0], dst[1], 4, SPLICE_F_NONBLOCK));
        assert(read(p[0], data, 1) == 1);
        printf("partial edge %d\n", epoll_wait(ep, &event, 1, 0));
        assert(read(p[0], data, 1) == 1);
        int edge = epoll_wait(ep, &event, 1, 0);
        printf("slot freed edge %d shrink %d\n", edge,
               fcntl(p[1], F_SETPIPE_SZ, page) == page);
        close(ep); close(dst[0]); close(dst[1]); close(p[0]); close(p[1]);
    }

    int src[2], dst[2];
    make_pipe(src, 2);
    make_pipe(dst, 1);
    assert(write(src[1], "a", 1) == 1);
    int ep = epoll_create1(0);
    struct epoll_event event = {.events = EPOLLOUT | EPOLLET};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, src[1], &event) == 0);
    assert(epoll_wait(ep, &event, 1, 0) == 1);
    assert(fcntl(src[1], F_SETPIPE_SZ, 2 * page) == 2 * page);
    printf("resize while ready edge %d\n", epoll_wait(ep, &event, 1, 0));
    assert(splice(src[0], NULL, dst[1], NULL, 1, 0) == 1);
    printf("whole slot moved while ready edge %d\n", epoll_wait(ep, &event, 1, 0));
    off_t eof = 2 * page;
    assert(splice(file, &eof, src[1], NULL, 2 * page, 0) == 0);
    printf("empty splice releases slots %zd\n", write(src[1], data, 2 * page));
    close(ep); close(src[0]); close(src[1]); close(dst[0]); close(dst[1]);

    // Only a whole slot moved by splice retains the anonymous writer's merge flag.
    for (int op = 0; op < 3; op++) {
        int src[2], dst[2];
        make_pipe(src, 1);
        make_pipe(dst, 1);
        assert(write(src[1], "abc", 3) == 3);
        ssize_t moved = op == 0 ? tee(src[0], dst[1], 3, 0)
                                : splice(src[0], NULL, dst[1], NULL, op == 1 ? 2 : 3, 0);
        ssize_t appended = write(dst[1], "x", 1);
        char copy[8] = {0};
        assert(read(dst[0], copy, sizeof copy) > 0);
        printf("transfer %d moved %zd appended %zd data %s\n", op, moved, appended, copy);
        close(src[0]); close(src[1]); close(dst[0]); close(dst[1]);
    }

    int p[2];
    make_pipe(p, 1);
    assert(write(p[1], data, page - 2) == page - 2);
    printf("anonymous full %d merged %zd\n", !writable(p[1]), write(p[1], data, 2));
    assert(read(p[0], data, page - 1) == page - 1);
    ssize_t n = write(p[1], data, 1);
    printf("consumed prefix unavailable %d\n", n == -1 && errno == EAGAIN);
    assert(read(p[0], data, 1) == 1);
    printf("empty writable %d\n", writable(p[1]));
    assert(write(p[1], data, 1) == 1);
    n = write(p[1], data, 17 * page + 3);
    printf("large write merged prefix %zd\n", n);
    // The file-position lock must be available to the reverse splice that frees the slot.
    close(p[0]); close(p[1]);
    assert(pipe(p) == 0 && fcntl(p[1], F_SETPIPE_SZ, page) == page);
    assert(write(p[1], "d", 1) == 1);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        alarm(4);
        _exit(splice(file, NULL, p[1], NULL, 1, 0) == 1 ? 0 : 1);
    }
    usleep(50000);
    alarm(5);
    assert(splice(p[0], NULL, file, NULL, 1, 0) == 1);
    int status;
    assert(waitpid(pid, &status, 0) == pid);
    alarm(0);
    printf("reverse splice completed %d\n", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}
C
gcc -Wall -O2 -o pipe-slots pipe-slots.c
./pipe-slots
