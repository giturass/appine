/* Regression tests for post-syscall sweeps on successful execve/execveat:
 * 1. execve closing an O_PATH|O_CLOEXEC fd on a detached FUSE mount collects the mount without
 *    any subsequent BKL syscall in the exec'd program.
 * 2. execveat(AT_EMPTY_PATH) closing an O_PATH|O_CLOEXEC fd on a detached FUSE mount does the same.
 * 3. execve closing an unattached open_tree(OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC) fd on a detached
 *    FUSE mount collects the dead anonymous mount namespace immediately.
 * 4. execve into a doomed ELF still runs the sweeps and terminates cleanly with SIGSEGV.
 * 5. execve closing an O_CLOEXEC AF_UNIX in-flight cycle reclaims the cycle and closes its
 *    carried pipe write end without any subsequent BKL syscall.
 * 6. Under ptrace (PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD), sweeps complete before the
 *    PTRACE_EVENT_EXEC stop and ptrace stops remain intact.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef SYS_execveat
#define SYS_execveat 281
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define CHECK(cond, fmt, ...)                                                      \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d %s)\n", __FILE__,       \
                    __LINE__, ##__VA_ARGS__, errno, strerror(errno));              \
            _exit(1);                                                              \
        }                                                                          \
    } while (0)

struct fuse_in_hdr {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint16_t total_extlen;
    uint16_t padding;
};
_Static_assert(sizeof(struct fuse_in_hdr) == 40, "fuse_in_hdr size");

struct fuse_out_hdr {
    uint32_t len;
    int32_t error;
    uint64_t unique;
};

struct fuse_attr {
    uint64_t ino;
    uint64_t size;
    uint64_t blocks;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
    uint32_t atimensec;
    uint32_t mtimensec;
    uint32_t ctimensec;
    uint32_t mode;
    uint32_t nlink;
    uint32_t uid;
    uint32_t gid;
    uint32_t rdev;
    uint32_t blksize;
    uint32_t flags;
};

struct fuse_entry_out {
    uint64_t nodeid;
    uint64_t generation;
    uint64_t entry_valid;
    uint64_t attr_valid;
    uint32_t entry_valid_nsec;
    uint32_t attr_valid_nsec;
    struct fuse_attr attr;
};

struct fuse_attr_out {
    uint64_t attr_valid;
    uint32_t attr_valid_nsec;
    uint32_t dummy;
    struct fuse_attr attr;
};

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    uint32_t padding;
};

struct fuse_ctx {
    int devfd;
    int done_pipe[2];
    _Atomic int aborted;
};

struct sync_page {
    int ready;
    int go;
};

static void sleep_ms(long ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
        ;
}

static void put_u16(uint8_t *p, uint16_t v) { memcpy(p, &v, sizeof(v)); }
static void put_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static void put_u64(uint8_t *p, uint64_t v) { memcpy(p, &v, sizeof(v)); }

/* Writes a minimal static aarch64 ELF whose only instruction is `b #0` (zero syscalls).
 * When `doomed` is non-zero, `p_offset` disagrees with `p_vaddr` mod page so execve marks
 * the image doomed and kills the process with forced SIGSEGV. */
static void write_elf(const char *path, int doomed)
{
    uint8_t elf[124];
    memset(elf, 0, sizeof(elf));
    elf[0] = 0x7f;
    elf[1] = 'E';
    elf[2] = 'L';
    elf[3] = 'F';
    elf[4] = 2; /* ELFCLASS64 */
    elf[5] = 1; /* ELFDATA2LSB */
    elf[6] = 1; /* EV_CURRENT */
    put_u16(elf + 16, 2);        /* ET_EXEC */
    put_u16(elf + 18, 183);      /* EM_AARCH64 */
    put_u32(elf + 20, 1);        /* EV_CURRENT */
    put_u64(elf + 24, 0x400078); /* e_entry */
    put_u64(elf + 32, 64);       /* e_phoff */
    put_u16(elf + 52, 64);       /* e_ehsize */
    put_u16(elf + 54, 56);       /* e_phentsize */
    put_u16(elf + 56, 1);        /* e_phnum */

    put_u32(elf + 64, 1);                     /* PT_LOAD */
    put_u32(elf + 68, 5);                     /* PF_R | PF_X */
    put_u64(elf + 72, doomed ? 1 : 0);        /* p_offset */
    put_u64(elf + 80, 0x400000);              /* p_vaddr */
    put_u64(elf + 88, 0x400000);              /* p_paddr */
    put_u64(elf + 96, sizeof(elf));           /* p_filesz */
    put_u64(elf + 104, sizeof(elf));          /* p_memsz */
    put_u64(elf + 112, 4096);                 /* p_align */

    put_u32(elf + 120, 0x14000000u); /* aarch64: b #0 */

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    CHECK(fd >= 0, "create %s", path);
    CHECK(write(fd, elf, sizeof(elf)) == (ssize_t)sizeof(elf), "write %s", path);
    CHECK(close(fd) == 0, "close %s", path);
}

static void *fuse_daemon(void *arg)
{
    struct fuse_ctx *ctx = (struct fuse_ctx *)arg;
    uint8_t buf[16384];
    uint8_t out[16384];
    for (;;) {
        ssize_t n = read(ctx->devfd, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(struct fuse_in_hdr)) {
            ctx->aborted = 1;
            char b = 1;
            (void)write(ctx->done_pipe[1], &b, 1);
            break;
        }
        struct fuse_in_hdr in;
        memcpy(&in, buf, sizeof(in));

        memset(out, 0, sizeof(struct fuse_out_hdr));
        struct fuse_out_hdr *hdr = (struct fuse_out_hdr *)out;
        hdr->unique = in.unique;

        if (in.opcode == 26 /* FUSE_INIT */) {
            uint32_t init_out[16];
            memset(init_out, 0, sizeof(init_out));
            init_out[0] = 7;
            init_out[1] = 37;
            init_out[6] = 65536;
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(init_out));
            memcpy(out + sizeof(*hdr), init_out, sizeof(init_out));
        } else if (in.opcode == 3 /* FUSE_GETATTR */) {
            struct fuse_attr_out a;
            memset(&a, 0, sizeof(a));
            a.attr.ino = in.nodeid;
            if (in.nodeid == 1) {
                a.attr.mode = S_IFDIR | 0755;
                a.attr.nlink = 2;
            } else {
                a.attr.mode = S_IFREG | 0444;
                a.attr.nlink = 1;
                a.attr.size = 4096;
            }
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(a));
            memcpy(out + sizeof(*hdr), &a, sizeof(a));
        } else if (in.opcode == 1 /* FUSE_LOOKUP */) {
            const char *name = (const char *)(buf + sizeof(in));
            if (strcmp(name, "data") == 0) {
                struct fuse_entry_out e;
                memset(&e, 0, sizeof(e));
                e.nodeid = 2;
                e.entry_valid = 60;
                e.attr_valid = 60;
                e.attr.ino = 2;
                e.attr.mode = S_IFREG | 0444;
                e.attr.nlink = 1;
                e.attr.size = 4096;
                hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(e));
                memcpy(out + sizeof(*hdr), &e, sizeof(e));
            } else {
                hdr->len = (uint32_t)sizeof(*hdr);
                hdr->error = -ENOENT;
            }
        } else if (in.opcode == 14 /* FUSE_OPEN */) {
            struct fuse_open_out o;
            memset(&o, 0, sizeof(o));
            o.fh = 1;
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(o));
            memcpy(out + sizeof(*hdr), &o, sizeof(o));
        } else if (in.opcode == 18 /* FUSE_RELEASE */ || in.opcode == 25 /* FUSE_FLUSH */) {
            hdr->len = (uint32_t)sizeof(*hdr);
        } else {
            hdr->len = (uint32_t)sizeof(*hdr);
            hdr->error = -ENOSYS;
        }
        (void)write(ctx->devfd, out, hdr->len);
    }
    return NULL;
}

static pthread_t mount_fuse(const char *path, struct fuse_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    CHECK(mkdir(path, 0755) == 0, "mkdir %s", path);
    CHECK(pipe2(ctx->done_pipe, O_CLOEXEC) == 0, "pipe2");
    ctx->devfd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    CHECK(ctx->devfd >= 0, "open /dev/fuse");
    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40755,user_id=0,group_id=0", ctx->devfd);
    CHECK(mount("f", path, "fuse", 0, opts) == 0, "mount %s", path);
    pthread_t th;
    CHECK(pthread_create(&th, NULL, fuse_daemon, ctx) == 0, "pthread_create");
    return th;
}

static void unmount_cleanup(pthread_t th, struct fuse_ctx *ctx, const char *path)
{
    CHECK(pthread_join(th, NULL) == 0, "pthread_join");
    CHECK(ctx->aborted == 1, "daemon must have observed abort for %s", path);
    close(ctx->devfd);
    close(ctx->done_pipe[0]);
    close(ctx->done_pipe[1]);
    rmdir(path);
}

static void test_detached_fuse_exec(
    const char *label,
    const char *mnt,
    const char *elf_path,
    int use_open_tree,
    int use_execveat,
    int doomed)
{
    struct fuse_ctx ctx;
    pthread_t th = mount_fuse(mnt, &ctx);

    int pfd;
    if (use_open_tree) {
        pfd = (int)syscall(SYS_open_tree, AT_FDCWD, mnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(pfd >= 0, "%s: open_tree clone", label);
    } else {
        char data_path[128];
        snprintf(data_path, sizeof(data_path), "%s/data", mnt);
        pfd = open(data_path, O_PATH | O_CLOEXEC);
        CHECK(pfd >= 0, "%s: open O_PATH|O_CLOEXEC", label);
    }
    CHECK(umount2(mnt, MNT_DETACH) == 0, "%s: lazy umount", label);
    CHECK(!ctx.aborted, "%s: mount must stay alive while O_CLOEXEC fd is open", label);

    int exec_fd = -1;
    if (use_execveat) {
        exec_fd = open(elf_path, O_RDONLY | O_CLOEXEC);
        CHECK(exec_fd >= 0, "%s: open exec_fd", label);
    }

    struct sync_page *sync = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sync != MAP_FAILED, "%s: mmap sync", label);

    pid_t pid = fork();
    CHECK(pid >= 0, "%s: fork", label);
    if (pid == 0) {
        close(ctx.devfd);
        close(ctx.done_pipe[0]);
        close(ctx.done_pipe[1]);
        __atomic_store_n(&sync->ready, 1, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&sync->go, __ATOMIC_ACQUIRE))
            sleep_ms(2);
        /* Give the parent time to enter poll() so no unrelated BKL syscall runs after exec. */
        sleep_ms(60);
        char *const argv[] = {"spin", NULL};
        char *const envp[] = {NULL};
        if (use_execveat)
            syscall(SYS_execveat, exec_fd, "", argv, envp, AT_EMPTY_PATH);
        else
            syscall(SYS_execve, elf_path, argv, envp);
        _exit(99);
    }

    while (!__atomic_load_n(&sync->ready, __ATOMIC_ACQUIRE))
        sleep_ms(2);
    close(pfd);
    if (exec_fd >= 0)
        close(exec_fd);
    CHECK(!ctx.aborted, "%s: mount must stay alive while child holds O_CLOEXEC fd", label);

    struct pollfd p = {.fd = ctx.done_pipe[0], .events = POLLIN};
    __atomic_store_n(&sync->go, 1, __ATOMIC_RELEASE);
    /* No other BKL syscall runs in parent, daemon, or exec'd child (`b #0`). */
    int pr = poll(&p, 1, 1500);
    if (!doomed) {
        kill(pid, SIGKILL);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "%s: waitpid", label);
    munmap(sync, 4096);

    CHECK(pr == 1 && (p.revents & POLLIN),
          "%s: detached FUSE mount was not collected on successful exec (poll=%d revents=0x%x)",
          label, pr, p.revents);
    if (doomed) {
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV,
              "%s: doomed exec must die with SIGSEGV (status=0x%x)", label, st);
    } else {
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL,
              "%s: spinning exec'd child must remain alive until SIGKILL (status=0x%x)", label, st);
    }

    unmount_cleanup(th, &ctx, mnt);
}

static void send_fds(int sock, const int *fds, size_t n)
{
    char data = 'x';
    struct iovec iov = {.iov_base = &data, .iov_len = 1};
    union {
        char buf[CMSG_SPACE(sizeof(int) * 2)];
        struct cmsghdr align;
    } ctrl;
    memset(&ctrl, 0, sizeof(ctrl));
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl.buf,
        .msg_controllen = CMSG_SPACE(sizeof(int) * n),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * n);
    CHECK(sendmsg(sock, &msg, 0) == 1, "sendmsg SCM_RIGHTS");
}

static void test_unix_cycle_cloexec(const char *elf_path)
{
    int p[2];
    CHECK(pipe2(p, O_CLOEXEC) == 0, "pipe2 unix cycle");
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sv) == 0, "socketpair");

    /* Form an in-flight cycle (sv[0] <-> sv[1]) that also carries p[1]. */
    int fds0[2] = {sv[1], p[1]};
    send_fds(sv[0], fds0, 2);
    send_fds(sv[1], &sv[0], 1);
    close(p[1]);

    struct sync_page *sync = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sync != MAP_FAILED, "mmap sync unix");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork unix cycle");
    if (pid == 0) {
        close(p[0]);
        __atomic_store_n(&sync->ready, 1, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&sync->go, __ATOMIC_ACQUIRE))
            sleep_ms(2);
        sleep_ms(60);
        char *const argv[] = {"spin", NULL};
        char *const envp[] = {NULL};
        syscall(SYS_execve, elf_path, argv, envp);
        _exit(99);
    }

    while (!__atomic_load_n(&sync->ready, __ATOMIC_ACQUIRE))
        sleep_ms(2);
    close(sv[0]);
    close(sv[1]);

    struct pollfd pfd = {.fd = p[0], .events = POLLIN};
    CHECK(poll(&pfd, 1, 0) == 0, "pipe write end must stay open while child holds cycle");

    __atomic_store_n(&sync->go, 1, __ATOMIC_RELEASE);
    int pr = poll(&pfd, 1, 1500);
    kill(pid, SIGKILL);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid unix cycle");
    munmap(sync, 4096);
    close(p[0]);

    CHECK(pr == 1 && (pfd.revents & POLLHUP),
          "AF_UNIX cycle closed by O_CLOEXEC during execve must release pipe (poll=%d revents=0x%x)",
          pr, pfd.revents);
}

static void test_ptrace_exec_sweeps_before_stop(const char *elf_path)
{
    const char *mnt = "/tmp/exec_ptrace_fuse";
    struct fuse_ctx ctx;
    pthread_t th = mount_fuse(mnt, &ctx);

    int pfd = open("/tmp/exec_ptrace_fuse/data", O_PATH | O_CLOEXEC);
    CHECK(pfd >= 0, "ptrace: open O_PATH|O_CLOEXEC");
    CHECK(umount2(mnt, MNT_DETACH) == 0, "ptrace: lazy umount");

    pid_t pid = fork();
    CHECK(pid >= 0, "ptrace: fork");
    if (pid == 0) {
        close(ctx.devfd);
        close(ctx.done_pipe[0]);
        close(ctx.done_pipe[1]);
        CHECK(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "PTRACE_TRACEME");
        raise(SIGSTOP);
        char *const argv[] = {"spin", NULL};
        char *const envp[] = {NULL};
        syscall(SYS_execve, elf_path, argv, envp);
        _exit(99);
    }

    close(pfd);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP,
          "ptrace: initial SIGSTOP");
    CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL,
                 (void *)(PTRACE_O_TRACEEXEC | PTRACE_O_TRACESYSGOOD)) == 0,
          "PTRACE_SETOPTIONS");

    /* Run to execve entry stop, then to PTRACE_EVENT_EXEC stop. */
    int saw_exec_event = 0;
    for (int step = 0; step < 32; step++) {
        CHECK(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0, "PTRACE_SYSCALL");
        CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st), "ptrace wait step %d", step);
        if ((st >> 8) == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) {
            saw_exec_event = 1;
            break;
        }
    }
    CHECK(saw_exec_event, "expected PTRACE_EVENT_EXEC stop");

    /* Sweeps must have run before exec_done's PTRACE_EVENT_EXEC stop. */
    struct pollfd dp = {.fd = ctx.done_pipe[0], .events = POLLIN};
    int pr = poll(&dp, 1, 1500);
    CHECK(pr == 1 && (dp.revents & POLLIN),
          "ptrace: detached FUSE mount must be collected before PTRACE_EVENT_EXEC (poll=%d)", pr);

    /* Continue through syscall exit stop and verify it still arrives cleanly. */
    CHECK(ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == 0, "PTRACE_SYSCALL after exec event");
    CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80),
          "ptrace: expected syscall-exit stop after PTRACE_EVENT_EXEC (status=0x%x)", st);

    kill(pid, SIGKILL);
    CHECK(waitpid(pid, &st, 0) == pid, "ptrace: reap");
    unmount_cleanup(th, &ctx, mnt);
}

int main(void)
{
    CHECK(mkdir("/tmp", 0755) == 0 || errno == EEXIST, "mkdir /tmp");
    const char *spin_elf = "/tmp/spin_elf";
    const char *doomed_elf = "/tmp/doomed_elf";
    write_elf(spin_elf, 0);
    write_elf(doomed_elf, 1);

    test_detached_fuse_exec("execve+O_PATH", "/tmp/exec_fuse_opath", spin_elf, 0, 0, 0);
    test_detached_fuse_exec("execveat+O_PATH", "/tmp/execveat_fuse_opath", spin_elf, 0, 1, 0);
    test_detached_fuse_exec("execve+open_tree", "/tmp/exec_fuse_opentree", spin_elf, 1, 0, 0);
    test_detached_fuse_exec("execve+doomed", "/tmp/exec_fuse_doomed", doomed_elf, 0, 0, 1);
    test_unix_cycle_cloexec(spin_elf);
    test_ptrace_exec_sweeps_before_stop(spin_elf);

    unlink(spin_elf);
    unlink(doomed_elf);
    puts("all ok");
    return 0;
}
