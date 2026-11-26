/*
 * Guest test program for host stdio (appine-run --no-pty):
 * - "regular": stdin and stdout are regular host files; pread/preadv/pwrite/pwritev work at
 *   explicit offsets without changing file positions.
 * - "pipe-intr": stdin and stdout are host pipes; pread/pwrite return ESPIPE, a blocked write
 *   to a full host pipe is interrupted promptly by SIGALRM (returning partial bytes or EINTR),
 *   and O_NONBLOCK write to a full host pipe returns EAGAIN.
 * - "share-release": creates /tmp/a, clones it to /tmp/b with FICLONE, opens /tmp/a, unlinks
 *   /tmp/a while open, closes /tmp/a, then writes /tmp/b (the host verifies no copy object was
 *   created in the store).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);                                   \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, " (errno=%d: %s)\n", errno, strerror(errno));                          \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

#define FICLONE 0x40049409

static volatile sig_atomic_t got_alarm = 0;

static void on_alarm(int sig)
{
    (void)sig;
    got_alarm = 1;
}

static void test_regular(void)
{
    char buf[16] = {0};
    off_t p0 = lseek(0, 0, SEEK_CUR);
    CHECK(p0 == 0, "initial stdin pos %lld", (long long)p0);
    CHECK(pread(0, buf, 5, 6) == 5 && memcmp(buf, "world", 5) == 0, "pread stdin");
    CHECK(lseek(0, 0, SEEK_CUR) == 0, "pread must not move stdin pos");

    char a[3] = {0}, b[3] = {0};
    struct iovec rin[2] = {{a, 3}, {b, 3}};
    CHECK(preadv(0, rin, 2, 1) == 6 && memcmp(a, "ell", 3) == 0 && memcmp(b, "o w", 3) == 0,
          "preadv stdin");
    CHECK(lseek(0, 0, SEEK_CUR) == 0, "preadv must not move stdin pos");

    CHECK(pwrite(1, "WORLD", 5, 6) == 5, "pwrite stdout");
    CHECK(lseek(1, 0, SEEK_CUR) == 0, "pwrite must not move stdout pos");
    struct iovec wout[2] = {{"HE", 2}, {"LLO ", 4}};
    CHECK(pwritev(1, wout, 2, 0) == 6, "pwritev stdout");
    CHECK(lseek(1, 0, SEEK_CUR) == 0, "pwritev must not move stdout pos");
}

static void test_pipe_intr(void)
{
    char tmp[8];
    errno = 0;
    CHECK(pread(0, tmp, sizeof tmp, 0) == -1 && errno == ESPIPE, "pread on host pipe");
    errno = 0;
    CHECK(pwrite(1, "x", 1, 0) == -1 && errno == ESPIPE, "pwrite on host pipe");

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    /* No SA_RESTART: blocked write must return EINTR (or partial count). */
    CHECK(sigaction(SIGALRM, &sa, NULL) == 0, "sigaction SIGALRM");

    /* Fill the host stdout pipe (using O_NONBLOCK first to know it's full, then blocking). */
    int orig = fcntl(1, F_GETFL);
    CHECK(orig >= 0, "F_GETFL stdout");
    CHECK(fcntl(1, F_SETFL, orig | O_NONBLOCK) == 0, "set O_NONBLOCK stdout");
    static char block[4096];
    memset(block, 'A', sizeof block);
    ssize_t filled = 0;
    for (;;) {
        ssize_t n = write(1, block, sizeof block);
        if (n < 0) {
            CHECK(errno == EAGAIN, "nonblocking host pipe write expected EAGAIN");
            break;
        }
        filled += n;
        CHECK(filled <= 4 * 1024 * 1024, "pipe never filled?");
    }
    CHECK(filled > 0, "filled host pipe");

    /* Now switch back to blocking and confirm SIGALRM interrupts the blocked write. */
    CHECK(fcntl(1, F_SETFL, orig & ~O_NONBLOCK) == 0, "clear O_NONBLOCK stdout");
    got_alarm = 0;
    alarm(1);
    errno = 0;
    ssize_t r = write(1, block, sizeof block);
    int err = errno;
    alarm(0);
    CHECK(got_alarm == 1, "SIGALRM must fire");
    CHECK(r == -1 && err == EINTR, "blocked write expected EINTR, got r=%zd err=%d", r, err);
}

static void test_share_release(void)
{
    CHECK(mkdir("/tmp", 0777) == 0 || errno == EEXIST, "mkdir /tmp");
    int a = open("/tmp/share_a", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(a >= 0, "create /tmp/share_a");
    char payload[8192];
    memset(payload, 'S', sizeof payload);
    CHECK(write(a, payload, sizeof payload) == (ssize_t)sizeof payload, "write /tmp/share_a");
    close(a);

    int src = open("/tmp/share_a", O_RDONLY);
    int b = open("/tmp/share_b", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(src >= 0 && b >= 0, "open share_a and share_b");
    CHECK(ioctl(b, FICLONE, src) == 0, "FICLONE share_a -> share_b");

    /* Unlink share_a while still open, then close it so its shared hold is released. */
    CHECK(unlink("/tmp/share_a") == 0, "unlink share_a while open");
    CHECK(close(src) == 0, "close unlinked share_a");

    /* Writing share_b should settle in place without creating a new copy object. */
    CHECK(pwrite(b, "Z", 1, 0) == 1, "write share_b");
    char got[2] = {0};
    CHECK(pread(b, got, 2, 0) == 2 && got[0] == 'Z' && got[1] == 'S', "verify share_b data");
    close(b);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2, "usage: hoststdio <regular|pipe-intr|share-release>");
    if (strcmp(argv[1], "regular") == 0)
        test_regular();
    else if (strcmp(argv[1], "pipe-intr") == 0)
        test_pipe_intr();
    else if (strcmp(argv[1], "share-release") == 0)
        test_share_release();
    else
        CHECK(0, "unknown mode %s", argv[1]);
    return 0;
}
