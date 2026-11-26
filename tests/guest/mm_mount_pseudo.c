/*
 * Regression tests for mount, procfs, sysctl, cgroup, AIO, mm, CoW, OOM and exec:
 *  1. mount_setattr enforces caller's-namespace check on child mounts of an open_tree anon clone
 *     (exempting only the parentless anon root);
 *  2. move_mount attaching an open_tree clone releases its max_mnt_namespaces count immediately
 *     even while the open_tree fd remains open;
 *  3. MNT_EXPIRE marks are cleared by normal mount access/lookup (umount2 mark-then-expire);
 *  4. move_mount(MOVE_MOUNT_SET_GROUP) joins a private mount to a shared/slave peer group;
 *  5. /proc/<pid>/net entries of a process with an exited (zombie) main thread use its netns;
 *  6. /proc/net/snmp reflects the namespace's ipv4 ip_forward (1 enabled, 2 disabled);
 *  7. /proc/sys/{net,ipc,uts,pid,user} sysctls stay pinned to the namespace captured at lookup
 *     time (plus writable /proc/<pid>/comm, Cpus_allowed mask, and sysfs netns tagging);
 *  8. Cgroup writes/reads on a disabled controller or removed cgroup return ENODEV without storing;
 *  9. Native AIO refuses procfs files without read_iter/write_iter (/proc/self/mem, pagemap) with
 *     EINVAL while allowing seq_file and sysctl reads;
 * 10. Past-EOF faults check VMA permissions before EOF (SIGSEGV/SEGV_ACCERR vs SIGBUS/BUS_ADRERR);
 * 11. mlock/mlock2 over PROT_NONE locks range, stops populating at PROT_NONE, returns ENOMEM;
 *     read-only anon mlock does not inflate RSS; post-fork writable anon mlock breaks CoW cleanly;
 * 12. MADV_DONTNEED on a written private file mapping marked cow at fork reverts without
 *     corrupting the peer;
 * 13. process_mrelease handles pending deliverable fatal signals (SIGTERM) and rejects single-thread
 *     exit in a zombie-leader thread group (matching Linux 6.1);
 * 14. Secure exec computes the argument limit before clamping the 8 MiB stack limit (up to 6 MiB).
 * 15. /proc/self/auxv matches the auxiliary vector on the initial stack through AT_NULL.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL: ");                                                             \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, " (errno %d: %s)\n", errno, strerror(errno));                          \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

#define CHECK_ERR(expr, want, ...)                                                                 \
    do {                                                                                           \
        errno = 0;                                                                                 \
        long _r = (long)(expr);                                                                    \
        CHECK(_r < 0 && errno == (want), __VA_ARGS__);                                             \
    } while (0)

#ifndef MNT_EXPIRE
#define MNT_EXPIRE 4
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100
#endif
#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif
#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 1
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT 0x00000040
#endif
#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
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
#ifndef SYS_io_getevents
#define SYS_io_getevents 4
#endif
#ifndef SYS_name_to_handle_at
#define SYS_name_to_handle_at 264
#endif
#ifndef SYS_open_by_handle_at
#define SYS_open_by_handle_at 265
#endif
#ifndef SYS_mlock2
#define SYS_mlock2 284
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef SYS_process_mrelease
#define SYS_process_mrelease 448
#endif

struct k_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

struct k_iocb {
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

struct k_io_event {
    uint64_t data;
    uint64_t obj;
    int64_t res;
    int64_t res2;
};

#define IOCB_CMD_PREAD 0
#define IOCB_CMD_PWRITE 1

static void write_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    CHECK(fd >= 0, "open %s for write", path);
    ssize_t n = write(fd, s, strlen(s));
    CHECK(n == (ssize_t)strlen(s), "write %s", path);
    close(fd);
}

static void write_all(int fd, const void *buf, size_t len, const char *label)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const uint8_t *)buf + off, len - off);
        CHECK(n > 0, "write %s", label);
        off += (size_t)n;
    }
}

static void write_file_bytes(const char *path, const void *buf, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    CHECK(fd >= 0, "open %s", path);
    write_all(fd, buf, len, path);
    close(fd);
}

static void read_str(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s for read", path);
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        CHECK(n >= 0, "read %s", path);
        if (n == 0)
            break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
}

static void pread_str(int fd, char *buf, size_t cap)
{
    ssize_t n = pread(fd, buf, cap - 1, 0);
    CHECK(n >= 0, "pread fd %d", fd);
    buf[n] = '\0';
}

static void check_pread_eq(int fd, const char *want, const char *label)
{
    char got[64];
    pread_str(fd, got, sizeof(got));
    CHECK(strcmp(got, want) == 0, "%s: expected %s, got %s", label, want, got);
}

static void wait_ok(pid_t pid, const char *label)
{
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid %s", label);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "%s failed (status=0x%x)", label, st);
}

static void wait_leader_zombie(pid_t pid)
{
    char stat_path[64], buf[4096];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    for (int i = 0; i < 200; i++) {
        read_str(stat_path, buf, sizeof(buf));
        char *rp = strrchr(buf, ')');
        if (rp && rp[1] == ' ' && rp[2] == 'Z')
            return;
        usleep(5000);
    }
    CHECK(0, "leader %d did not become zombie", pid);
}

static void copy_file(const char *src, const char *dst, mode_t mode)
{
    int in = open(src, O_RDONLY);
    CHECK(in >= 0, "open %s", src);
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    CHECK(out >= 0, "create %s", dst);
    uint8_t buf[16384];
    for (;;) {
        ssize_t n = read(in, buf, sizeof(buf));
        CHECK(n >= 0, "read %s", src);
        if (n == 0)
            break;
        write_all(out, buf, (size_t)n, dst);
    }
    close(in);
    close(out);
}

/* 1. mount_setattr enforces caller's-namespace check on child mounts of an anon clone */
static void test_mount_setattr_anon_child(void)
{
    CHECK(mkdir("/tmp/ms_root", 0755) == 0, "mkdir ms_root");
    CHECK(mount("tmpfs", "/tmp/ms_root", "tmpfs", 0, "size=64k") == 0, "mount ms_root");
    CHECK(mkdir("/tmp/ms_root/sub", 0755) == 0, "mkdir ms_root/sub");
    CHECK(mount("tmpfs", "/tmp/ms_root/sub", "tmpfs", 0, "size=64k") == 0, "mount ms_root/sub");

    int tfd = (int)syscall(SYS_open_tree, AT_FDCWD, "/tmp/ms_root",
                           OPEN_TREE_CLONE | AT_RECURSIVE | OPEN_TREE_CLOEXEC);
    CHECK(tfd >= 0, "open_tree recursive clone");

    struct k_mount_attr ma = {
        .attr_set = MOUNT_ATTR_NOATIME,
        .attr_clr = MOUNT_ATTR__ATIME,
        .propagation = 0,
        .userns_fd = 0,
    };
    /* Parentless root of the anonymous namespace is exempt and succeeds */
    CHECK(syscall(SYS_mount_setattr, tfd, "", AT_EMPTY_PATH, &ma, sizeof(ma)) == 0,
          "mount_setattr on anon root must succeed");

    /* Child mount inside the anonymous namespace is NOT exempt -> EINVAL */
    CHECK_ERR(syscall(SYS_mount_setattr, tfd, "sub", 0, &ma, sizeof(ma)), EINVAL,
              "mount_setattr on anon child by path must be EINVAL");

    int subfd = openat(tfd, "sub", O_PATH | O_CLOEXEC);
    CHECK(subfd >= 0, "openat sub inside anon clone");
    CHECK_ERR(syscall(SYS_mount_setattr, subfd, "", AT_EMPTY_PATH, &ma, sizeof(ma)), EINVAL,
              "mount_setattr on anon child fd must be EINVAL");

    close(subfd);
    close(tfd);
    CHECK(umount2("/tmp/ms_root/sub", 0) == 0, "umount ms_root/sub");
    CHECK(umount2("/tmp/ms_root", 0) == 0, "umount ms_root");
    rmdir("/tmp/ms_root");
}

/* 2. move_mount attaching open_tree clone releases max_mnt_namespaces while fd stays open */
static void test_open_tree_attach_releases_mnt_ns_count(void)
{
    CHECK(mkdir("/tmp/ot_src", 0755) == 0, "mkdir ot_src");
    CHECK(mkdir("/tmp/ot_dst", 0755) == 0, "mkdir ot_dst");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork open_tree ns count");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0, "unshare user+mnt");
        write_str("/proc/self/setgroups", "deny\n");
        write_str("/proc/self/uid_map", "0 0 1\n");
        write_str("/proc/self/gid_map", "0 0 1\n");
        /* Allow this userns at most 2 mount namespaces: current + 1 open_tree clone */
        write_str("/proc/sys/user/max_mnt_namespaces", "2\n");
        CHECK(mount("tmpfs", "/tmp/ot_src", "tmpfs", 0, "size=64k") == 0, "mount ot_src");

        int tfd1 = (int)syscall(SYS_open_tree, AT_FDCWD, "/tmp/ot_src",
                                OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(tfd1 >= 0, "open_tree #1");

        CHECK_ERR(syscall(SYS_open_tree, AT_FDCWD, "/tmp/ot_src",
                          OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC),
                  ENOSPC, "open_tree #2 while #1 unattached must be ENOSPC");

        /* Attach tfd1 while keeping tfd1 open: anonymous ns count must be released immediately */
        CHECK(syscall(SYS_move_mount, tfd1, "", AT_FDCWD, "/tmp/ot_dst",
                      MOVE_MOUNT_F_EMPTY_PATH) == 0,
              "move_mount attach tfd1");

        int tfd2 = (int)syscall(SYS_open_tree, AT_FDCWD, "/tmp/ot_src",
                                OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(tfd2 >= 0, "open_tree #2 after attaching #1 must succeed while #1 stays open");

        close(tfd2);
        close(tfd1);
        CHECK(umount2("/tmp/ot_dst", 0) == 0, "umount ot_dst");
        CHECK(umount2("/tmp/ot_src", 0) == 0, "umount ot_src");
        _exit(0);
    }
    wait_ok(pid, "open_tree attach releases mnt_ns count");
    rmdir("/tmp/ot_dst");
    rmdir("/tmp/ot_src");
}

/* 3. MNT_EXPIRE mark is cleared by mount access/lookup */
static void test_mnt_expire_cleared_on_access(void)
{
    CHECK(mkdir("/tmp/exp_mp", 0755) == 0, "mkdir exp_mp");
    CHECK(mount("tmpfs", "/tmp/exp_mp", "tmpfs", 0, "size=64k") == 0, "mount exp_mp");
    write_file_bytes("/tmp/exp_mp/f", "hi", 2, 0644);

    /* First MNT_EXPIRE marks the mount and returns EAGAIN */
    CHECK_ERR(umount2("/tmp/exp_mp", MNT_EXPIRE), EAGAIN,
              "first MNT_EXPIRE must return EAGAIN");

    /* Accessing a file inside the mount clears the MNT_EXPIRE mark */
    struct stat st;
    CHECK(stat("/tmp/exp_mp/f", &st) == 0, "stat file inside mount");
    CHECK_ERR(umount2("/tmp/exp_mp", MNT_EXPIRE), EAGAIN,
              "MNT_EXPIRE after file access must return EAGAIN again");

    /* Accessing the mount root itself also clears the mark */
    CHECK(stat("/tmp/exp_mp", &st) == 0, "stat mount root");
    CHECK_ERR(umount2("/tmp/exp_mp", MNT_EXPIRE), EAGAIN,
              "MNT_EXPIRE after root access must return EAGAIN again");

    /* Immediate second MNT_EXPIRE with no intervening access unmounts */
    CHECK(umount2("/tmp/exp_mp", MNT_EXPIRE) == 0, "second consecutive MNT_EXPIRE must succeed");
    rmdir("/tmp/exp_mp");
}

/* 4. move_mount(MOVE_MOUNT_SET_GROUP) joins peer group and propagates */
static void test_move_mount_set_group(void)
{
    CHECK(mkdir("/tmp/sg_src", 0755) == 0, "mkdir sg_src");
    CHECK(mkdir("/tmp/sg_dst", 0755) == 0, "mkdir sg_dst");
    CHECK(mkdir("/tmp/sg_other", 0755) == 0, "mkdir sg_other");

    CHECK(mount("tmpfs", "/tmp/sg_src", "tmpfs", 0, "size=64k") == 0, "mount sg_src");
    CHECK(mount(NULL, "/tmp/sg_src", NULL, MS_PRIVATE, NULL) == 0, "make sg_src private");
    CHECK(mkdir("/tmp/sg_src/sub", 0755) == 0, "mkdir sg_src/sub");
    CHECK(mount("/tmp/sg_src", "/tmp/sg_dst", NULL, MS_BIND, NULL) == 0, "bind sg_src -> sg_dst");
    CHECK(mount(NULL, "/tmp/sg_dst", NULL, MS_PRIVATE, NULL) == 0, "make sg_dst private");
    CHECK(mount("tmpfs", "/tmp/sg_other", "tmpfs", 0, "size=64k") == 0, "mount sg_other");
    CHECK(mount(NULL, "/tmp/sg_other", NULL, MS_PRIVATE, NULL) == 0, "make sg_other private");

    /* Source is private -> EINVAL */
    CHECK_ERR(syscall(SYS_move_mount, AT_FDCWD, "/tmp/sg_src", AT_FDCWD, "/tmp/sg_dst",
                      MOVE_MOUNT_SET_GROUP),
              EINVAL, "SET_GROUP from private source must be EINVAL");

    /* Make source shared; different superblock must still fail with EINVAL */
    CHECK(mount(NULL, "/tmp/sg_src", NULL, MS_SHARED, NULL) == 0, "make sg_src shared");
    CHECK_ERR(syscall(SYS_move_mount, AT_FDCWD, "/tmp/sg_src", AT_FDCWD, "/tmp/sg_other",
                      MOVE_MOUNT_SET_GROUP),
              EINVAL, "SET_GROUP across different superblocks must be EINVAL");

    /* Join sg_dst to sg_src's peer group */
    CHECK(syscall(SYS_move_mount, AT_FDCWD, "/tmp/sg_src", AT_FDCWD, "/tmp/sg_dst",
                  MOVE_MOUNT_SET_GROUP) == 0,
          "SET_GROUP must succeed");

    /* Target is no longer private -> EINVAL */
    CHECK_ERR(syscall(SYS_move_mount, AT_FDCWD, "/tmp/sg_src", AT_FDCWD, "/tmp/sg_dst",
                      MOVE_MOUNT_SET_GROUP),
              EINVAL, "SET_GROUP on already-shared target must be EINVAL");

    /* Verify mount propagation from sg_src/sub to sg_dst/sub */
    CHECK(mount("tmpfs", "/tmp/sg_src/sub", "tmpfs", 0, "size=64k") == 0, "mount sg_src/sub");
    write_file_bytes("/tmp/sg_src/sub/probe", "ok", 2, 0644);
    struct stat st;
    CHECK(stat("/tmp/sg_dst/sub/probe", &st) == 0, "submount must propagate to sg_dst/sub");
    CHECK(umount2("/tmp/sg_src/sub", 0) == 0, "umount sg_src/sub");
    CHECK_ERR(stat("/tmp/sg_dst/sub/probe", &st), ENOENT,
              "unmount must propagate to sg_dst/sub");

    CHECK(umount2("/tmp/sg_other", 0) == 0, "umount sg_other");
    CHECK(umount2("/tmp/sg_dst", 0) == 0, "umount sg_dst");
    CHECK(umount2("/tmp/sg_src", 0) == 0, "umount sg_src");
    rmdir("/tmp/sg_other");
    rmdir("/tmp/sg_dst");
    rmdir("/tmp/sg_src");
}

/* 5. /proc/<pid>/net entries with exited (zombie) main thread use process's netns */
struct zombie_net_args {
    int ready_fd;
    int done_fd;
    int sock_fd;
};

static void *zombie_net_worker(void *arg)
{
    struct zombie_net_args *a = arg;
    char c = '1';
    CHECK(write(a->ready_fd, &c, 1) == 1, "worker ready");
    CHECK(read(a->done_fd, &c, 1) == 1, "worker wait done");
    close(a->sock_fd);
    return NULL;
}

static void test_proc_pid_net_zombie_leader(void)
{
    int ready[2], done[2];
    CHECK(pipe(ready) == 0 && pipe(done) == 0, "pipe");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork zombie netns");
    if (pid == 0) {
        close(ready[0]);
        close(done[1]);
        CHECK(unshare(CLONE_NEWNET) == 0, "unshare CLONE_NEWNET");
        write_str("/proc/sys/net/ipv4/ip_forward", "1\n");

        int s = socket(AF_INET, SOCK_DGRAM, 0);
        CHECK(s >= 0, "udp socket");
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = htons(43219); /* 0xA8D3 */
        CHECK(bind(s, (struct sockaddr *)&sin, sizeof(sin)) == 0, "bind udp 43219");

        static struct zombie_net_args args;
        args.ready_fd = ready[1];
        args.done_fd = done[0];
        args.sock_fd = s;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, zombie_net_worker, &args) == 0, "pthread_create");
        pthread_detach(th);
        /* Exit ONLY the main thread so it becomes a zombie leader while worker stays alive */
        syscall(SYS_exit, 0);
        _exit(99);
    }
    close(ready[1]);
    close(done[0]);
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait worker ready");
    close(ready[0]);

    wait_leader_zombie(pid);

    char udp_path[64], snmp_path[64], buf[4096];
    snprintf(udp_path, sizeof(udp_path), "/proc/%d/net/udp", pid);
    snprintf(snmp_path, sizeof(snmp_path), "/proc/%d/net/snmp", pid);

    read_str(udp_path, buf, sizeof(buf));
    CHECK(strstr(buf, ":A8D3 ") != NULL,
          "/proc/<pid>/net/udp with zombie leader missed child netns socket: %s", buf);

    read_str(snmp_path, buf, sizeof(buf));
    CHECK(strstr(buf, "\nIp: 1 ") != NULL,
          "/proc/<pid>/net/snmp with zombie leader fell back to init netns: %s", buf);

    CHECK(write(done[1], "x", 1) == 1, "release worker");
    close(done[1]);
    wait_ok(pid, "zombie leader netns child");
}

/* 6. /proc/net/snmp reflects ipv4 ip_forward (1 enabled, 2 disabled) */
static void test_proc_net_snmp_forwarding(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork snmp");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWNET) == 0, "unshare CLONE_NEWNET");
        char buf[4096];
        read_str("/proc/net/snmp", buf, sizeof(buf));
        CHECK(strstr(buf, "\nIp: 2 ") != NULL, "default snmp Forwarding must be 2: %s", buf);

        write_str("/proc/sys/net/ipv4/ip_forward", "1\n");
        read_str("/proc/net/snmp", buf, sizeof(buf));
        CHECK(strstr(buf, "\nIp: 1 ") != NULL, "enabled ip_forward snmp Forwarding must be 1: %s",
              buf);

        write_str("/proc/sys/net/ipv4/ip_forward", "0\n");
        read_str("/proc/net/snmp", buf, sizeof(buf));
        CHECK(strstr(buf, "\nIp: 2 ") != NULL, "disabled ip_forward snmp Forwarding must be 2: %s",
              buf);
        _exit(0);
    }
    wait_ok(pid, "snmp forwarding");
}

static void test_sysctl_write_position(void)
{
    const char *path = "/proc/sys/net/core/somaxconn";
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0, "open somaxconn");
    char saved[32], value[32];
    pread_str(fd, saved, sizeof(saved));
    struct iovec bad[] = {{"10", 2}, {(void *)1, 1}};
    CHECK_ERR(writev(fd, bad, 2), EFAULT, "reject unreadable second iovec");
    CHECK(lseek(fd, 0, SEEK_CUR) == 0, "failed write preserves offset");
    pread_str(fd, value, sizeof(value));
    CHECK(strcmp(value, saved) == 0, "failed write leaves sysctl value intact");
    struct iovec parts[] = {{"10", 2}, {"1", 1}};
    CHECK(writev(fd, parts, 2) == 3, "write fragmented number");
    CHECK(lseek(fd, 0, SEEK_CUR) == 3, "first sysctl write advances offset");
    CHECK(write(fd, "invalid", 7) == 7 && lseek(fd, 0, SEEK_CUR) == 10,
          "nonzero offset consumes input");
    pread_str(fd, value, sizeof(value));
    CHECK(strcmp(value, "101\n") == 0, "second write preserved first value");
    CHECK(pwrite(fd, saved, strlen(saved), 0) == (ssize_t)strlen(saved), "restore somaxconn");
    CHECK(lseek(fd, 0, SEEK_CUR) == 10, "pwrite preserves open offset");
    pread_str(fd, value, sizeof(value));
    CHECK(strcmp(value, saved) == 0, "positioned write at zero took effect");
    close(fd);

    fd = open("/proc/sys/net/ipv4/tcp_timestamps", O_RDWR);
    CHECK(fd >= 0, "open unsigned sysctl");
    pread_str(fd, saved, sizeof(saved));
    CHECK(write(fd, "0", 1) == 1 && write(fd, "1", 1) == 1, "repeat unsigned writes");
    pread_str(fd, value, sizeof(value));
    CHECK(strcmp(value, "1\n") == 0 && lseek(fd, 0, SEEK_CUR) == 0,
          "unsigned writes at zero keep the offset");
    CHECK(write(fd, saved, strlen(saved)) == (ssize_t)strlen(saved), "restore tcp_timestamps");
    close(fd);

    /* String sysctl (hostname) & bitmap sysctl (ip_local_reserved_ports) in isolated ns */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork string/bitmap sysctl test");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWUSER | CLONE_NEWTIME) == 0,
              "unshare uts+net+user+time");

        /* setgroups advances offset and rejects nonzero offset with EINVAL */
        int sg = open("/proc/self/setgroups", O_RDWR);
        CHECK(sg >= 0, "open setgroups");
        CHECK(write(sg, "allow\n", 6) == 6 && lseek(sg, 0, SEEK_CUR) == 6,
              "setgroups write advances offset");
        CHECK_ERR(write(sg, "deny\n", 5), EINVAL, "setgroups nonzero offset must fail EINVAL");
        CHECK(pwrite(sg, "deny\n", 5, 0) == 5 && lseek(sg, 0, SEEK_CUR) == 6,
              "setgroups pwrite at 0 succeeds and preserves offset");
        close(sg);

        /* timens_offsets rejects nonzero offset with EINVAL and leaves offset at 0 */
        int tn = open("/proc/self/timens_offsets", O_RDWR);
        CHECK(tn >= 0, "open timens_offsets");
        CHECK_ERR(pwrite(tn, "monotonic 1 0\n", 14, 1), EINVAL,
                  "timens_offsets nonzero offset must fail EINVAL");
        CHECK(write(tn, "monotonic 1 0\n", 14) == 14 && lseek(tn, 0, SEEK_CUR) == 0,
              "timens_offsets keeps offset at 0");
        CHECK(write(tn, "boottime 2 0\n", 13) == 13 && lseek(tn, 0, SEEK_CUR) == 0,
              "second timens_offsets write succeeds at offset 0");
        close(tn);

        /* oom_score_adj clamps return to 12 and keeps offset 0; coredump_filter returns full count */
        int oom = open("/proc/self/oom_score_adj", O_RDWR);
        CHECK(oom >= 0, "open oom_score_adj");
        CHECK(write(oom, "0000000000015\n", 14) == 12 && lseek(oom, 0, SEEK_CUR) == 0,
              "oom_score_adj clamps return to 12 and keeps offset 0");
        close(oom);

        int cdf = open("/proc/self/coredump_filter", O_RDWR);
        CHECK(cdf >= 0, "open coredump_filter");
        CHECK(write(cdf, "000000000033\n", 13) == 13 && lseek(cdf, 0, SEEK_CUR) == 0,
              "coredump_filter returns full count and keeps offset 0");
        close(cdf);

        /* String sysctl: gathered writev, advances offset, ignores nonzero offset */
        int hfd = open("/proc/sys/kernel/hostname", O_RDWR);
        CHECK(hfd >= 0, "open hostname");
        struct iovec hp[] = {{"host", 4}, {"A\n", 2}};
        CHECK(writev(hfd, hp, 2) == 6 && lseek(hfd, 0, SEEK_CUR) == 6,
              "hostname writev advances offset");
        check_pread_eq(hfd, "hostA\n", "hostname writev");
        CHECK(write(hfd, "hostB\n", 6) == 6 && lseek(hfd, 0, SEEK_CUR) == 12,
              "hostname nonzero offset consumes input and advances");
        check_pread_eq(hfd, "hostA\n", "hostname nonzero offset preserved");
        CHECK(pwrite(hfd, "hostC\n", 6, 0) == 6 && lseek(hfd, 0, SEEK_CUR) == 12,
              "hostname pwrite at 0 updates and preserves offset");
        check_pread_eq(hfd, "hostC\n", "hostname pwrite");
        close(hfd);

        /* Bitmap sysctl: offset 0 replaces, nonzero offset ORs/merges, invalid nonzero -> EINVAL */
        int pfd = open("/proc/sys/net/ipv4/ip_local_reserved_ports", O_RDWR);
        CHECK(pfd >= 0, "open ip_local_reserved_ports");
        CHECK(write(pfd, "1000\n", 5) == 5 && lseek(pfd, 0, SEEK_CUR) == 5,
              "bitmap write at 0 advances offset");
        check_pread_eq(pfd, "1000\n", "bitmap initial");
        CHECK(write(pfd, "2000,1001\n", 10) == 10 && lseek(pfd, 0, SEEK_CUR) == 15,
              "bitmap write at nonzero offset merges and advances");
        check_pread_eq(pfd, "1000-1001,2000\n", "bitmap merged");
        CHECK_ERR(write(pfd, "bad\n", 4), EINVAL, "invalid bitmap write at nonzero offset");
        CHECK(lseek(pfd, 0, SEEK_CUR) == 15, "failed bitmap write preserves offset");
        CHECK(pwrite(pfd, "3000\n", 5, 0) == 5 && lseek(pfd, 0, SEEK_CUR) == 15,
              "bitmap pwrite at 0 replaces and preserves offset");
        check_pread_eq(pfd, "3000\n", "bitmap replaced");
        close(pfd);

        _exit(0);
    }
    wait_ok(pid, "string/bitmap sysctl and proc write positions");

    /* Cgroup2 file write advances position (kernfs_fop_write_iter) */
    CHECK(mkdir("/sys/fs/cgroup/pos_cg", 0755) == 0, "mkdir pos_cg");
    int cgfd = open("/sys/fs/cgroup/pos_cg/cgroup.max.depth", O_RDWR);
    CHECK(cgfd >= 0, "open cgroup.max.depth");
    CHECK(write(cgfd, "10\n", 3) == 3 && lseek(cgfd, 0, SEEK_CUR) == 3,
          "cgroup write #1 advances pos");
    CHECK(write(cgfd, "20\n", 3) == 3 && lseek(cgfd, 0, SEEK_CUR) == 6,
          "cgroup write #2 advances pos");
    check_pread_eq(cgfd, "20\n", "cgroup write #2 applied");
    close(cgfd);
    CHECK(rmdir("/sys/fs/cgroup/pos_cg") == 0, "rmdir pos_cg");
}

static void test_overlay_redirect_always_follow(void)
{
    char buf[32];
    read_str("/sys/module/overlay/parameters/redirect_always_follow", buf, sizeof(buf));
    CHECK(strcmp(buf, "N\n") == 0,
          "redirect_always_follow must report N, got %s", buf);
}

static void test_open_by_handle_at_superblock_boundary(void)
{
    struct {
        unsigned int handle_bytes;
        int handle_type;
        unsigned char f_handle[16];
    } h_root = {.handle_bytes = 16}, h_t1 = {.handle_bytes = 16},
      h_forged = {.handle_bytes = 8, .handle_type = 1};
    int mnt_id = 0;

    static const char *const dirs[] = {
        "/tmp/obh_root_bind",
        "/tmp/obh_t1",
        "/tmp/obh_t1_bind",
        "/tmp/obh_t2",
    };
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
        CHECK(mkdir(dirs[i], 0755) == 0, "mkdir %s", dirs[i]);
    CHECK(mount("/tmp", dirs[0], NULL, MS_BIND, NULL) == 0, "bind rootfs");
    CHECK(mount("tmpfs", dirs[1], "tmpfs", 0, "size=64k") == 0, "mount t1");
    CHECK(mount(dirs[1], dirs[2], NULL, MS_BIND, NULL) == 0, "bind t1");
    CHECK(mount("tmpfs", dirs[3], "tmpfs", 0, "size=64k") == 0, "mount t2");

    write_file_bytes("/tmp/obh_root_file", "root-data", 9, 0644);
    write_file_bytes("/tmp/obh_t1/file", "t1-data", 7, 0644);

    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/tmp/obh_root_file", &h_root, &mnt_id, 0) == 0,
          "name_to_handle_at rootfs file");
    CHECK(syscall(SYS_name_to_handle_at, AT_FDCWD, "/tmp/obh_t1/file", &h_t1, &mnt_id, 0) == 0,
          "name_to_handle_at t1 file");

    int fd_root = open("/tmp", O_RDONLY | O_DIRECTORY);
    int fd_root_bind = open(dirs[0], O_RDONLY | O_DIRECTORY);
    int fd_t1 = open(dirs[1], O_RDONLY | O_DIRECTORY);
    int fd_t1_bind = open(dirs[2], O_RDONLY | O_DIRECTORY);
    int fd_t2 = open(dirs[3], O_RDONLY | O_DIRECTORY);
    CHECK(fd_root >= 0 && fd_root_bind >= 0 && fd_t1 >= 0 && fd_t1_bind >= 0 && fd_t2 >= 0,
          "open mount fds");

    /* Same superblock (including bind mounts) succeeds */
    int o = (int)syscall(SYS_open_by_handle_at, fd_root, &h_root, O_RDONLY);
    CHECK(o >= 0, "open root handle via root fd");
    check_pread_eq(o, "root-data", "root handle content");
    close(o);

    o = (int)syscall(SYS_open_by_handle_at, fd_root_bind, &h_root, O_RDONLY);
    CHECK(o >= 0, "open root handle via root bind fd");
    close(o);

    o = (int)syscall(SYS_open_by_handle_at, fd_t1, &h_t1, O_RDONLY);
    CHECK(o >= 0, "open t1 handle via t1 fd");
    check_pread_eq(o, "t1-data", "t1 handle content");
    close(o);

    o = (int)syscall(SYS_open_by_handle_at, fd_t1_bind, &h_t1, O_RDONLY);
    CHECK(o >= 0, "open t1 handle via t1 bind fd");
    close(o);

    /* Cross-superblock handles must fail with ESTALE */
    CHECK_ERR(syscall(SYS_open_by_handle_at, fd_t1, &h_root, O_RDONLY), ESTALE,
              "root handle via tmpfs1 fd must be ESTALE");
    CHECK_ERR(syscall(SYS_open_by_handle_at, fd_root, &h_t1, O_RDONLY), ESTALE,
              "tmpfs1 handle via root fd must be ESTALE");
    CHECK_ERR(syscall(SYS_open_by_handle_at, fd_t2, &h_t1, O_RDONLY), ESTALE,
              "tmpfs1 handle via tmpfs2 fd must be ESTALE");

    /* Crafted handle naming rootfs inode 1 opened via tmpfs1 must be ESTALE */
    uint64_t root_ino = 1;
    memcpy(h_forged.f_handle, &root_ino, sizeof(root_ino));
    CHECK_ERR(syscall(SYS_open_by_handle_at, fd_t1, &h_forged, O_RDONLY), ESTALE,
              "forged rootfs ino=1 handle via tmpfs1 fd must be ESTALE");

    int fds[] = {fd_t2, fd_t1_bind, fd_t1, fd_root_bind, fd_root};
    for (size_t i = 0; i < sizeof(fds) / sizeof(fds[0]); i++)
        close(fds[i]);
    unlink("/tmp/obh_root_file");
    for (size_t i = sizeof(dirs) / sizeof(dirs[0]); i-- > 0;) {
        CHECK(umount2(dirs[i], 0) == 0, "umount %s", dirs[i]);
        rmdir(dirs[i]);
    }
}

/* 7. /proc/sys/net and IPC sysctls pin namespace at open/lookup time */
static void test_sysctl_namespace_pinning(void)
{
    static const struct {
        const char *path;
        const char *val_a;
        const char *val_b;
        const char *val_a2;
    } cases[] = {
        {"/proc/sys/net/ipv4/ip_forward", "1\n", "0\n", "0\n"},
        {"/proc/sys/net/core/somaxconn", "8192\n", "4096\n", "9000\n"},
        {"/proc/sys/kernel/shmmax", "12345678\n", "87654321\n", "22222222\n"},
        {"/proc/sys/fs/mqueue/queues_max", "512\n", "128\n", "768\n"},
    };
    const size_t ncases = sizeof(cases) / sizeof(cases[0]);

    pid_t pid = fork();
    CHECK(pid >= 0, "fork sysctl pin");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWNET | CLONE_NEWIPC) == 0, "unshare ns A");
        struct stat st;
        CHECK(stat("/proc/sys/fs/mqueue", &st) == 0 && S_ISDIR(st.st_mode),
              "/proc/sys/fs/mqueue must remain a directory");
        CHECK(chdir("/proc/sys/net") == 0, "chdir /proc/sys/net");

        write_str("ipv4/tcp_keepalive_time", "600\n");
        int keepalive_fd = open("ipv4/tcp_keepalive_time", O_RDWR);
        CHECK(keepalive_fd >= 0, "open relative ipv4/tcp_keepalive_time in ns A");

        int fds[4];
        for (size_t i = 0; i < ncases; i++) {
            write_str(cases[i].path, cases[i].val_a);
            fds[i] = open(cases[i].path, O_RDWR);
            CHECK(fds[i] >= 0, "open %s in ns A", cases[i].path);
        }

        /* Switch into a new netns and ipcns while keeping cwd = /proc/sys/net */
        CHECK(unshare(CLONE_NEWNET | CLONE_NEWIPC) == 0, "unshare ns B");

        char buf[128];
        /* Relative lookups from /proc/sys/net must resolve in ns B, not ns A */
        read_str("ipv4/tcp_keepalive_time", buf, sizeof(buf));
        CHECK(strcmp(buf, "7200\n") == 0,
              "relative ipv4/tcp_keepalive_time in ns B must be default 7200, got %s", buf);
        pread_str(keepalive_fd, buf, sizeof(buf));
        CHECK(strcmp(buf, "600\n") == 0,
              "pinned ipv4/tcp_keepalive_time fd must stay 600, got %s", buf);
        close(keepalive_fd);

        for (size_t i = 0; i < ncases; i++)
            write_str(cases[i].path, cases[i].val_b);

        read_str("core/somaxconn", buf, sizeof(buf));
        CHECK(strcmp(buf, "4096\n") == 0,
              "relative core/somaxconn in ns B must be 4096, got %s", buf);

        for (size_t i = 0; i < ncases; i++) {
            pread_str(fds[i], buf, sizeof(buf));
            CHECK(strcmp(buf, cases[i].val_a) == 0, "pinned %s expected %s, got %s",
                  cases[i].path, cases[i].val_a, buf);

            /* Writes through pinned fds update ns A without touching ns B */
            size_t len = strlen(cases[i].val_a2);
            CHECK(pwrite(fds[i], cases[i].val_a2, len, 0) == (ssize_t)len,
                  "pwrite pinned %s", cases[i].path);

            read_str(cases[i].path, buf, sizeof(buf));
            CHECK(strcmp(buf, cases[i].val_b) == 0, "ns B %s must remain %s, got %s",
                  cases[i].path, cases[i].val_b, buf);

            pread_str(fds[i], buf, sizeof(buf));
            CHECK(strcmp(buf, cases[i].val_a2) == 0, "ns A %s must be %s, got %s",
                  cases[i].path, cases[i].val_a2, buf);
            close(fds[i]);
        }

        /* UTS sysctls pin lookup UTS namespace while /proc/sys/kernel stays unpinned */
        CHECK(unshare(CLONE_NEWUTS) == 0, "unshare uts A");
        CHECK(chdir("/proc/sys/kernel") == 0, "chdir /proc/sys/kernel");
        write_str("hostname", "uts-host-a\n");
        write_str("domainname", "uts-dom-a\n");
        int hfd = open("hostname", O_RDWR);
        int dfd = open("domainname", O_RDWR);
        CHECK(hfd >= 0 && dfd >= 0, "open uts sysctls in uts A");

        CHECK(unshare(CLONE_NEWUTS) == 0, "unshare uts B");
        write_str("hostname", "uts-host-b\n");
        write_str("domainname", "uts-dom-b\n");
        pread_str(hfd, buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-host-a\n") == 0, "pinned hostname expected uts-host-a, got %s", buf);
        pread_str(dfd, buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-dom-a\n") == 0, "pinned domainname expected uts-dom-a, got %s", buf);
        CHECK(pwrite(hfd, "uts-host-a2\n", 12, 0) == 12, "pwrite pinned hostname");
        CHECK(pwrite(dfd, "uts-dom-a2\n", 11, 0) == 11, "pwrite pinned domainname");
        read_str("hostname", buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-host-b\n") == 0, "uts B hostname must remain uts-host-b, got %s",
              buf);
        read_str("domainname", buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-dom-b\n") == 0, "uts B domainname must remain uts-dom-b, got %s",
              buf);
        pread_str(hfd, buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-host-a2\n") == 0, "uts A hostname must be uts-host-a2, got %s", buf);
        pread_str(dfd, buf, sizeof(buf));
        CHECK(strcmp(buf, "uts-dom-a2\n") == 0, "uts A domainname must be uts-dom-a2, got %s", buf);
        close(hfd);
        close(dfd);

        /* User-namespace sysctl pins open/lookup user namespace across nested unshare(CLONE_NEWUSER) */
        pid_t uchild = fork();
        CHECK(uchild >= 0, "fork userns child");
        if (uchild == 0) {
            CHECK(unshare(CLONE_NEWUSER) == 0, "unshare userns A");
            write_str("/proc/self/setgroups", "deny\n");
            write_str("/proc/self/uid_map", "0 0 1\n");
            write_str("/proc/self/gid_map", "0 0 1\n");
            write_str("/proc/sys/user/max_uts_namespaces", "111\n");
            int ufd = open("/proc/sys/user/max_uts_namespaces", O_RDWR);
            CHECK(ufd >= 0, "open max_uts_namespaces in userns A");

            CHECK(unshare(CLONE_NEWUSER) == 0, "unshare userns B");
            write_str("/proc/self/setgroups", "deny\n");
            write_str("/proc/self/uid_map", "0 0 1\n");
            write_str("/proc/self/gid_map", "0 0 1\n");
            write_str("/proc/sys/user/max_uts_namespaces", "222\n");

            pread_str(ufd, buf, sizeof(buf));
            CHECK(strcmp(buf, "111\n") == 0, "pinned userns A limit expected 111, got %s", buf);
            CHECK(pwrite(ufd, "333\n", 4, 0) == 4, "pwrite pinned userns A limit");
            read_str("/proc/sys/user/max_uts_namespaces", buf, sizeof(buf));
            CHECK(strcmp(buf, "222\n") == 0, "userns B limit must remain 222, got %s", buf);
            pread_str(ufd, buf, sizeof(buf));
            CHECK(strcmp(buf, "333\n") == 0, "pinned userns A limit must be 333, got %s", buf);
            close(ufd);
            _exit(0);
        }
        wait_ok(uchild, "userns sysctl pinning child");

        /* Pid sysctl pins lookup pid namespace across fork into a child pid namespace */
        int pfd = open("/proc/sys/kernel/ns_last_pid", O_RDWR);
        CHECK(pfd >= 0, "open ns_last_pid in parent pidns");
        CHECK(pwrite(pfd, "420\n", 4, 0) == 4, "seed parent ns_last_pid");
        CHECK(unshare(CLONE_NEWPID) == 0, "unshare CLONE_NEWPID");
        pid_t pchild = fork();
        CHECK(pchild >= 0, "fork pidns child");
        if (pchild == 0) {
            write_str("/proc/sys/kernel/ns_last_pid", "77\n");
            pread_str(pfd, buf, sizeof(buf));
            CHECK(strcmp(buf, "77\n") != 0,
                  "pinned parent ns_last_pid must not read child pidns value 77");
            CHECK(pwrite(pfd, "450\n", 4, 0) == 4, "pwrite pinned parent ns_last_pid");
            read_str("/proc/sys/kernel/ns_last_pid", buf, sizeof(buf));
            CHECK(strcmp(buf, "77\n") == 0, "child ns_last_pid must remain 77, got %s", buf);
            pread_str(pfd, buf, sizeof(buf));
            CHECK(strcmp(buf, "450\n") == 0, "pinned parent ns_last_pid expected 450, got %s", buf);
            close(pfd);
            _exit(0);
        }
        close(pfd);
        wait_ok(pchild, "pidns sysctl pinning child");

        _exit(0);
    }
    wait_ok(pid, "sysctl namespace pinning");
}

/* 8. Cgroup writes/reads on disabled controller or removed cgroup return ENODEV */
static void test_cgroup_enodev(void)
{
    write_str("/sys/fs/cgroup/cgroup.subtree_control", "+memory +pids\n");
    CHECK(mkdir("/sys/fs/cgroup/cg_test", 0755) == 0, "mkdir cg_test");

    int mfd = open("/sys/fs/cgroup/cg_test/memory.max", O_RDWR);
    int pfd = open("/sys/fs/cgroup/cg_test/pids.max", O_RDWR);
    CHECK(mfd >= 0 && pfd >= 0, "open cgroup files");

    char buf[64];
    pread_str(mfd, buf, sizeof(buf));
    CHECK(strcmp(buf, "max\n") == 0, "initial memory.max expected max, got %s", buf);

    /* Disable memory controller: writes and offset-0 reads on held fd must return ENODEV */
    write_str("/sys/fs/cgroup/cgroup.subtree_control", "-memory\n");
    CHECK_ERR(pwrite(mfd, "4096\n", 5, 0), ENODEV,
              "write to disabled memory.max must return ENODEV");
    CHECK_ERR(pread(mfd, buf, sizeof(buf), 0), ENODEV,
              "read from disabled memory.max must return ENODEV");

    /* Re-enable memory controller: value must still be "max" (failed write stored nothing) */
    write_str("/sys/fs/cgroup/cgroup.subtree_control", "+memory\n");
    CHECK_ERR(fchmod(mfd, 0600), ENODEV, "old fd must not chmod replacement");
    CHECK_ERR(pwrite(mfd, "4096\n", 5, 0), ENODEV, "old fd must not write replacement");
    read_str("/sys/fs/cgroup/cg_test/memory.max", buf, sizeof(buf));
    CHECK(strcmp(buf, "max\n") == 0, "memory.max after failed write expected max, got %s", buf);

    /* Remove cgroup: offset-0 read and write on held pfd must return ENODEV */
    CHECK(rmdir("/sys/fs/cgroup/cg_test") == 0, "rmdir cg_test");
    CHECK_ERR(pread(pfd, buf, sizeof(buf), 0), ENODEV,
              "read from removed cgroup file must return ENODEV");
    CHECK_ERR(pwrite(pfd, "10\n", 3, 0), ENODEV,
              "write to removed cgroup file must return ENODEV");

    close(mfd);
    close(pfd);
    write_str("/sys/fs/cgroup/cgroup.subtree_control", "-memory -pids\n");
}

/* A directory and its interface files can be delegated independently. */
static void test_cgroup_delegation(void)
{
    const char *base = "/sys/fs/cgroup/delegate";
    CHECK(mkdir(base, 0755) == 0, "create delegation root");
    int dir = open(base, O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 0 && fchown(dir, 1000, 1000) == 0, "delegate directory by fd");
    struct stat st;
    CHECK(fstatat(dir, "cgroup.procs", &st, 0) == 0 && st.st_uid == 0,
          "chown directory preserves interface owners");
    int procs = openat(dir, "cgroup.procs", O_RDWR);
    CHECK(procs >= 0 && fchown(procs, 1000, 1000) == 0 && fchmod(procs, 0600) == 0,
          "delegate membership file");
    CHECK(fstat(procs, &st) == 0 && st.st_uid == 1000 && (st.st_mode & 0777) == 0600,
          "descriptor reports delegated attributes");
    pid_t child = fork();
    CHECK(child >= 0, "fork delegate");
    if (child == 0) {
        /* Enter the subtree with the original credentials before running as its delegate. */
        write_str("/sys/fs/cgroup/delegate/cgroup.procs", "0");
        CHECK(setgid(1000) == 0 && setuid(1000) == 0, "become delegate");
        CHECK(mkdirat(dir, "child", 0755) == 0, "create delegated child");
        CHECK(fstatat(dir, "child/cgroup.procs", &st, 0) == 0 && st.st_uid == 1000,
              "new files belong to creator");
        write_str("/sys/fs/cgroup/delegate/child/cgroup.procs", "0");
        CHECK_ERR(openat(dir, "cgroup.max.depth", O_WRONLY), EACCES, "nondelegated file stays protected");
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "delegate creates child and migrates");
    close(procs);
    CHECK(unlinkat(dir, "child", AT_REMOVEDIR) == 0, "remove delegated child");
    close(dir);
    CHECK(rmdir(base) == 0, "remove delegated root");
}

/* 9. Native AIO refuses procfs files without read_iter/write_iter */
static long aio_submit_one(unsigned long ctx, uint16_t op, int fd, void *buf, uint64_t nbytes,
                           int64_t offset)
{
    struct k_iocb cb = {
        .aio_lio_opcode = op,
        .aio_fildes = (uint32_t)fd,
        .aio_buf = (uint64_t)(uintptr_t)buf,
        .aio_nbytes = nbytes,
        .aio_offset = offset,
    };
    struct k_iocb *cbs[1] = {&cb};
    return syscall(SYS_io_submit, ctx, 1L, cbs);
}

static void test_aio_procfs_has_iter(void)
{
    unsigned long ctx = 0;
    CHECK(syscall(SYS_io_setup, 8, &ctx) == 0, "io_setup");

    int mem_fd = open("/proc/self/mem", O_RDWR);
    int pm_fd = open("/proc/self/pagemap", O_RDONLY);
    int cpu_fd = open("/proc/cpuinfo", O_RDONLY);
    int os_fd = open("/proc/sys/kernel/ostype", O_RDONLY);
    CHECK(mem_fd >= 0 && pm_fd >= 0 && cpu_fd >= 0 && os_fd >= 0, "open procfs files for aio");

    char buf[128];
    uint64_t dummy = 0x123456789abcdef0ULL;
    int64_t dummy_off = (int64_t)(uintptr_t)&dummy;

    CHECK_ERR(aio_submit_one(ctx, IOCB_CMD_PREAD, mem_fd, buf, sizeof(dummy), dummy_off), EINVAL,
              "AIO PREAD on /proc/self/mem must be EINVAL");
    CHECK_ERR(aio_submit_one(ctx, IOCB_CMD_PWRITE, mem_fd, buf, sizeof(dummy), dummy_off), EINVAL,
              "AIO PWRITE on /proc/self/mem must be EINVAL");
    CHECK_ERR(aio_submit_one(ctx, IOCB_CMD_PREAD, pm_fd, buf, 8, 0), EINVAL,
              "AIO PREAD on /proc/self/pagemap must be EINVAL");

    /* /proc/cpuinfo (seq_file) and /proc/sys/kernel/ostype (sysctl) PREAD succeed */
    struct k_io_event ev;
    CHECK(aio_submit_one(ctx, IOCB_CMD_PREAD, cpu_fd, buf, sizeof(buf), 0) == 1,
          "AIO PREAD on /proc/cpuinfo");
    CHECK(syscall(SYS_io_getevents, ctx, 1L, 1L, &ev, NULL) == 1 && ev.res > 0,
          "io_getevents /proc/cpuinfo");

    CHECK(aio_submit_one(ctx, IOCB_CMD_PREAD, os_fd, buf, sizeof(buf), 0) == 1,
          "AIO PREAD on /proc/sys/kernel/ostype");
    CHECK(syscall(SYS_io_getevents, ctx, 1L, 1L, &ev, NULL) == 1 && ev.res > 0,
          "io_getevents ostype");

    close(mem_fd);
    close(pm_fd);
    close(cpu_fd);
    close(os_fd);
    CHECK(syscall(SYS_io_destroy, ctx) == 0, "io_destroy");
}

/* 10. Past-EOF faults check VMA permissions before EOF */
static sigjmp_buf fault_jmp;
static volatile int fault_sig;
static volatile int fault_code;

static void fault_handler(int sig, siginfo_t *si, void *ucontext)
{
    (void)ucontext;
    fault_sig = sig;
    fault_code = si->si_code;
    siglongjmp(fault_jmp, 1);
}

static void expect_fault(volatile uint8_t *p, int write_op, int want_sig, int want_code,
                         const char *label)
{
    fault_sig = 0;
    fault_code = 0;
    if (sigsetjmp(fault_jmp, 1) == 0) {
        if (write_op)
            *p = 1;
        else
            (void)*p;
        CHECK(0, "%s must fault", label);
    }
    CHECK(fault_sig == want_sig && fault_code == want_code,
          "%s expected sig=%d code=%d, got sig=%d code=%d",
          label, want_sig, want_code, fault_sig, fault_code);
}

static void test_past_eof_fault_permissions(void)
{
    uint8_t page[4096];
    memset(page, 0x55, sizeof(page));
    write_file_bytes("/tmp/eof_perm", page, sizeof(page), 0644);
    int fd = open("/tmp/eof_perm", O_RDONLY);
    CHECK(fd >= 0, "open eof_perm");

    struct sigaction sa, old_segv, old_bus;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGSEGV, &sa, &old_segv) == 0, "sigaction SIGSEGV");
    CHECK(sigaction(SIGBUS, &sa, &old_bus) == 0, "sigaction SIGBUS");

    /* PROT_NONE past EOF -> SIGSEGV / SEGV_ACCERR */
    volatile uint8_t *p_none = mmap(NULL, 8192, PROT_NONE, MAP_PRIVATE, fd, 0);
    CHECK(p_none != MAP_FAILED, "mmap PROT_NONE");
    expect_fault(&p_none[4096], 0, SIGSEGV, SEGV_ACCERR, "PROT_NONE past-EOF read");
    munmap((void *)p_none, 8192);

    /* PROT_READ past EOF: write -> SIGSEGV/SEGV_ACCERR, read -> SIGBUS/BUS_ADRERR */
    volatile uint8_t *p_ro = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(p_ro != MAP_FAILED, "mmap PROT_READ");
    expect_fault(&p_ro[4096], 1, SIGSEGV, SEGV_ACCERR, "PROT_READ past-EOF write");
    expect_fault(&p_ro[4096], 0, SIGBUS, BUS_ADRERR, "PROT_READ past-EOF read");
    munmap((void *)p_ro, 8192);

    CHECK(sigaction(SIGSEGV, &old_segv, NULL) == 0, "restore SIGSEGV");
    CHECK(sigaction(SIGBUS, &old_bus, NULL) == 0, "restore SIGBUS");
    close(fd);
    unlink("/tmp/eof_perm");
}

/* 11. mlock/mlock2 over PROT_NONE, read-only anon RSS, and post-fork CoW */
static long read_smaps_kb(void *addr, const char *key, int *has_lo)
{
    FILE *f = fopen("/proc/self/smaps", "r");
    CHECK(f != NULL, "fopen smaps");
    unsigned long target = (unsigned long)(uintptr_t)addr;
    char line[512];
    int in_vma = 0;
    long val = -1;
    if (has_lo)
        *has_lo = 0;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        unsigned long s = 0, e = 0;
        if (sscanf(line, "%lx-%lx ", &s, &e) == 2 && strchr(line, '-')) {
            if (in_vma)
                break;
            in_vma = (target >= s && target < e);
        } else if (in_vma) {
            if (strncmp(line, key, klen) == 0) {
                val = strtol(line + klen, NULL, 10);
            } else if (has_lo && strncmp(line, "VmFlags:", 8) == 0) {
                if (strstr(line, " lo") != NULL)
                    *has_lo = 1;
            }
        }
    }
    fclose(f);
    CHECK(val >= 0, "smaps key %s not found for %p", key, addr);
    return val;
}

static void test_mlock_semantics(void)
{
    /* Part A: mlock across [RW, PROT_NONE, RW] stops populating at PROT_NONE and returns ENOMEM */
    uint8_t *p = mmap(NULL, 3 * 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap 3 pages");
    CHECK(mprotect(p + 4096, 4096, PROT_NONE) == 0, "mprotect middle PROT_NONE");

    CHECK_ERR(mlock(p, 3 * 4096), ENOMEM, "mlock over PROT_NONE must return ENOMEM");
    int lo0 = 0, lo1 = 0, lo2 = 0;
    long rss0 = read_smaps_kb(p, "Rss:", &lo0);
    long rss1 = read_smaps_kb(p + 4096, "Rss:", &lo1);
    long rss2 = read_smaps_kb(p + 8192, "Rss:", &lo2);
    CHECK(lo0 && lo1 && lo2, "all 3 VMAs must be locked (lo=%d,%d,%d)", lo0, lo1, lo2);
    CHECK(rss0 >= 4, "first RW VMA before PROT_NONE must be populated (rss0=%ld)", rss0);
    CHECK(rss1 == 0 && rss2 == 0,
          "PROT_NONE and trailing RW VMA must stay unpopulated (rss1=%ld rss2=%ld)", rss1, rss2);
    CHECK(munlock(p, 3 * 4096) == 0, "munlock 3 pages");
    CHECK(munmap(p, 3 * 4096) == 0, "munmap 3 pages");

    /* Part B: mlock2 with MLOCK_ONFAULT over PROT_NONE succeeds */
    uint8_t *pn = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(pn != MAP_FAILED, "mmap PROT_NONE");
    CHECK(syscall(SYS_mlock2, pn, 4096, MLOCK_ONFAULT) == 0,
          "mlock2(MLOCK_ONFAULT) over PROT_NONE must succeed");
    CHECK(munmap(pn, 4096) == 0, "munmap PROT_NONE");

    /* Part C: mlock on read-only anonymous mapping does not inflate RSS */
    uint8_t *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(ro != MAP_FAILED, "mmap RO anon");
    CHECK(mlock(ro, 4096) == 0, "mlock RO anon");
    long ro_rss = read_smaps_kb(ro, "Rss:", NULL);
    CHECK(ro_rss == 0, "RO anon mlock must keep Rss == 0 (got %ld)", ro_rss);
    CHECK(munmap(ro, 4096) == 0, "munmap RO anon");

    /* Part D: post-fork writable anon mlock breaks CoW without double-counting RSS */
    uint8_t *q = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(q != MAP_FAILED, "mmap CoW page");
    q[0] = 0x42;
    pid_t pid = fork();
    CHECK(pid >= 0, "fork mlock cow");
    if (pid == 0) {
        CHECK(mlock(q, 4096) == 0, "child mlock CoW page");
        long rss = read_smaps_kb(q, "Rss:", NULL);
        long pdirty = read_smaps_kb(q, "Private_Dirty:", NULL);
        long sdirty = read_smaps_kb(q, "Shared_Dirty:", NULL);
        CHECK(rss == 4 && pdirty == 4 && sdirty == 0,
              "post-fork mlock expected Rss=4 Private_Dirty=4 Shared_Dirty=0, got %ld/%ld/%ld",
              rss, pdirty, sdirty);
        CHECK(q[0] == 0x42, "CoW data preserved");
        _exit(0);
    }
    wait_ok(pid, "mlock cow child");
    CHECK(munmap(q, 4096) == 0, "munmap CoW page");
}

/* 12. MADV_DONTNEED on written private file mapping marked cow at fork */
static void test_madv_dontneed_cow_private_file(void)
{
    uint8_t orig[4096];
    memset(orig, 'A', sizeof(orig));
    write_file_bytes("/tmp/madv_cow", orig, sizeof(orig), 0644);
    int fd = open("/tmp/madv_cow", O_RDONLY);
    CHECK(fd >= 0, "open madv_cow");

    uint8_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED, "mmap private file");
    p[0] = 'B';
    p[1] = 'C';
    /* Drop write permission before fork so fork marks the written PrivateFile VMA cow */
    CHECK(mprotect(p, 4096, PROT_READ) == 0, "mprotect PROT_READ");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork madv cow");
    if (pid == 0) {
        CHECK(madvise(p, 4096, MADV_DONTNEED) == 0, "child MADV_DONTNEED");
        CHECK(p[0] == 'A' && p[1] == 'A',
              "child MADV_DONTNEED must revert to file contents, got %c%c", p[0], p[1]);
        _exit(0);
    }
    wait_ok(pid, "madv cow child");
    CHECK(p[0] == 'B' && p[1] == 'C', "parent mapping must stay uncorrupted, got %c%c", p[0], p[1]);

    munmap(p, 4096);
    close(fd);
    unlink("/tmp/madv_cow");
}

/* 13. process_mrelease: pending deliverable fatal signal + zombie-leader thread group */
struct mrel_args {
    int ready_fd;
    int go_fd;
    pid_t tid;
};

static void *mrel_worker(void *arg)
{
    struct mrel_args *a = arg;
    a->tid = (pid_t)syscall(SYS_gettid);
    char c = '1';
    CHECK(write(a->ready_fd, &c, 1) == 1, "mrel worker ready");
    CHECK(read(a->go_fd, &c, 1) == 1, "mrel worker go");
    syscall(SYS_exit, 0);
    return NULL;
}

static void test_process_mrelease(void)
{
    /* Part A: blocked SIGTERM -> EINVAL; unblocked deliverable SIGTERM on stopped task -> 0 */
    int ready[2];
    CHECK(pipe(ready) == 0, "pipe");
    pid_t blocked = fork();
    CHECK(blocked >= 0, "fork blocked sigterm");
    if (blocked == 0) {
        close(ready[0]);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGTERM);
        CHECK(sigprocmask(SIG_BLOCK, &set, NULL) == 0, "block SIGTERM");
        char c = '1';
        CHECK(write(ready[1], &c, 1) == 1, "ready");
        pause();
        _exit(0);
    }
    close(ready[1]);
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait blocked ready");
    close(ready[0]);

    int pfd = (int)syscall(SYS_pidfd_open, blocked, 0);
    CHECK(pfd >= 0, "pidfd_open blocked");
    CHECK(kill(blocked, SIGTERM) == 0, "send blocked SIGTERM");
    CHECK_ERR(syscall(SYS_process_mrelease, pfd, 0), EINVAL,
              "process_mrelease with blocked SIGTERM must be EINVAL");
    CHECK(kill(blocked, SIGKILL) == 0, "kill blocked");
    int st = 0;
    CHECK(waitpid(blocked, &st, 0) == blocked, "wait blocked");
    close(pfd);

    /* Unblocked deliverable SIGTERM on a SIGSTOP-stopped process -> succeeds (0) */
    CHECK(pipe(ready) == 0, "pipe");
    pid_t stopped = fork();
    CHECK(stopped >= 0, "fork stopped sigterm");
    if (stopped == 0) {
        close(ready[0]);
        uint8_t *buf = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(buf != MAP_FAILED, "mmap child mem");
        memset(buf, 0x77, 65536);
        char b = '1';
        CHECK(write(ready[1], &b, 1) == 1, "ready");
        /* Use kill() directly rather than raise(): musl's raise() masks all app signals around tkill */
        CHECK(kill(getpid(), SIGSTOP) == 0, "self SIGSTOP");
        pause();
        _exit(0);
    }
    close(ready[1]);
    CHECK(read(ready[0], &c, 1) == 1, "wait stopped ready");
    close(ready[0]);
    CHECK(waitpid(stopped, &st, WUNTRACED) == stopped && WIFSTOPPED(st),
          "waitpid WUNTRACED stopped");

    pfd = (int)syscall(SYS_pidfd_open, stopped, 0);
    CHECK(pfd >= 0, "pidfd_open stopped");
    CHECK(kill(stopped, SIGTERM) == 0, "send deliverable SIGTERM");
    CHECK(syscall(SYS_process_mrelease, pfd, 0) == 0,
          "process_mrelease right after deliverable SIGTERM must succeed");
    CHECK(kill(stopped, SIGKILL) == 0, "kill stopped");
    CHECK(waitpid(stopped, &st, 0) == stopped, "reap stopped");
    close(pfd);

    /* Part B: zombie-leader thread group whose last thread calls exit(2) -> EINVAL */
    int go[2], tid_pipe[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0 && pipe(tid_pipe) == 0, "pipes");
    pid_t zl = fork();
    CHECK(zl >= 0, "fork zombie leader mrelease");
    if (zl == 0) {
        close(ready[0]);
        close(go[1]);
        close(tid_pipe[0]);
        static struct mrel_args a;
        a.ready_fd = ready[1];
        a.go_fd = go[0];
        a.tid = 0;
        pthread_t th;
        CHECK(pthread_create(&th, NULL, mrel_worker, &a) == 0, "pthread_create mrel");
        pthread_detach(th);
        /* Wait briefly until worker stores its tid and signals parent; send tid via pipe */
        while (__atomic_load_n(&a.tid, __ATOMIC_ACQUIRE) == 0)
            usleep(1000);
        CHECK(write(tid_pipe[1], &a.tid, sizeof(a.tid)) == (ssize_t)sizeof(a.tid), "write tid");
        close(tid_pipe[1]);
        /* Main thread exits on its own -> zombie leader */
        syscall(SYS_exit, 0);
        _exit(99);
    }
    close(ready[1]);
    close(go[0]);
    close(tid_pipe[1]);
    pid_t wtid = 0;
    CHECK(read(ready[0], &c, 1) == 1, "wait mrel worker ready");
    CHECK(read(tid_pipe[0], &wtid, sizeof(wtid)) == (ssize_t)sizeof(wtid), "read worker tid");
    close(ready[0]);
    close(tid_pipe[0]);

    wait_leader_zombie(zl);

    /* Attach ptrace with PTRACE_O_TRACEEXIT to catch the last worker inside SYS_exit */
    CHECK(ptrace(PTRACE_ATTACH, wtid, 0, 0) == 0, "ptrace attach worker");
    CHECK(waitpid(wtid, &st, __WALL) == wtid && WIFSTOPPED(st), "wait attach stop");
    CHECK(ptrace(PTRACE_SETOPTIONS, wtid, 0, (void *)(uintptr_t)PTRACE_O_TRACEEXIT) == 0,
          "ptrace PTRACE_O_TRACEEXIT");
    CHECK(ptrace(PTRACE_CONT, wtid, 0, 0) == 0, "ptrace cont worker");
    CHECK(write(go[1], "x", 1) == 1, "signal worker exit");
    close(go[1]);

    CHECK(waitpid(wtid, &st, __WALL) == wtid && WIFSTOPPED(st) &&
              ((st >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))),
          "wait PTRACE_EVENT_EXIT (st=0x%x)", st);

    pfd = (int)syscall(SYS_pidfd_open, zl, 0);
    CHECK(pfd >= 0, "pidfd_open zombie-leader");
    CHECK_ERR(syscall(SYS_process_mrelease, pfd, 0), EINVAL,
              "process_mrelease on zombie-leader thread group in exit(2) must be EINVAL");

    CHECK(ptrace(PTRACE_CONT, wtid, 0, 0) == 0, "ptrace release worker");
    CHECK(waitpid(zl, &st, 0) == zl, "reap zombie-leader");
    close(pfd);
}

/* 14. Secure exec computes arg limit before clamping 8 MiB stack limit */
static void test_secure_exec_arg_limit(const char *self_path)
{
    copy_file(self_path, "/tmp/suid_exec", 04755);
    CHECK(chown("/tmp/suid_exec", 0, 0) == 0, "chown suid_exec");
    CHECK(chmod("/tmp/suid_exec", 04755) == 0, "chmod 04755 suid_exec");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork secure exec");
    if (pid == 0) {
        struct rlimit rl = {.rlim_cur = 32UL << 20, .rlim_max = 32UL << 20};
        CHECK(setrlimit(RLIMIT_STACK, &rl) == 0, "setrlimit RLIMIT_STACK 32M");
        CHECK(setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0,
              "drop uid to 1000");

        /* 48 args * 64 KiB = 3 MiB (> 2 MiB post-clamp limit, < 6 MiB pre-clamp limit) */
        const int nargs = 48;
        char *chunk = malloc(65536);
        CHECK(chunk != NULL, "malloc chunk");
        memset(chunk, 'x', 65535);
        chunk[65535] = '\0';

        char **argv = calloc((size_t)(nargs + 3), sizeof(char *));
        CHECK(argv != NULL, "calloc argv");
        argv[0] = "/tmp/suid_exec";
        argv[1] = "--check-secure";
        for (int i = 0; i < nargs; i++)
            argv[2 + i] = chunk;
        argv[2 + nargs] = NULL;

        execv("/tmp/suid_exec", argv);
        fprintf(stderr, "FAIL: secure execv with 3 MiB args failed: %s\n", strerror(errno));
        _exit(1);
    }
    wait_ok(pid, "secure exec 3 MiB args");
    unlink("/tmp/suid_exec");
}

struct comm_worker_args {
    int ready_fd;
    int done_fd;
    pid_t tid;
};

static void *comm_worker(void *arg)
{
    struct comm_worker_args *a = arg;
    a->tid = (pid_t)syscall(SYS_gettid);
    char b = 'r';
    CHECK(write(a->ready_fd, &b, 1) == 1, "comm worker ready");
    CHECK(read(a->done_fd, &b, 1) == 1, "comm worker wait");
    return NULL;
}

static void test_proc_comm_write(void)
{
    struct stat st;
    CHECK(stat("/proc/self/comm", &st) == 0, "stat /proc/self/comm");
    CHECK((st.st_mode & 0777) == 0644, "expected /proc/self/comm mode 0644, got %04o",
          st.st_mode & 0777);

    char orig[16] = {0};
    CHECK(prctl(PR_GET_NAME, orig, 0, 0, 0) == 0, "PR_GET_NAME");

    /* Write verbatim, matching Linux comm_write (no newline strip, 15-byte truncation, NUL stop) */
    int fd = open("/proc/self/comm", O_RDWR);
    CHECK(fd >= 0, "open /proc/self/comm O_RDWR");
    CHECK(write(fd, "myproc", 6) == 6, "write comm");
    char buf[64], prname[16];
    pread_str(fd, buf, sizeof(buf));
    CHECK(strcmp(buf, "myproc\n") == 0, "comm expected myproc\\n, got %s", buf);
    memset(prname, 0, sizeof(prname));
    CHECK(prctl(PR_GET_NAME, prname, 0, 0, 0) == 0, "PR_GET_NAME after write");
    CHECK(strcmp(prname, "myproc") == 0, "PR_GET_NAME expected myproc, got %s", prname);

    /* Trailing newline is stored verbatim (just like Linux comm_write) and escaped in status */
    CHECK(write(fd, "abc\n", 4) == 4, "write comm with newline");
    pread_str(fd, buf, sizeof(buf));
    CHECK(strcmp(buf, "abc\n\n") == 0, "comm with newline expected abc\\n\\n, got %s", buf);
    char status[4096];
    read_str("/proc/self/status", status, sizeof(status));
    CHECK(strstr(status, "Name:\tabc\\n\n") != NULL, "status must escape newline in Name: %s",
          status);

    /* 15-byte truncation returns full count */
    CHECK(write(fd, "0123456789abcdef\n", 17) == 17, "write long comm");
    pread_str(fd, buf, sizeof(buf));
    CHECK(strcmp(buf, "0123456789abcde\n") == 0, "long comm expected 15 bytes, got %s", buf);

    /* NUL terminates the stored name */
    CHECK(write(fd, "xy\0z", 4) == 4, "write comm with NUL");
    pread_str(fd, buf, sizeof(buf));
    CHECK(strcmp(buf, "xy\n") == 0, "NUL comm expected xy\\n, got %s", buf);

    /* Sibling thread in the same thread group can be renamed via /proc/self/task/<tid>/comm */
    int ready[2], done[2];
    CHECK(pipe(ready) == 0 && pipe(done) == 0, "pipes for comm worker");
    struct comm_worker_args wa = {.ready_fd = ready[1], .done_fd = done[0], .tid = 0};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, comm_worker, &wa) == 0, "pthread_create comm_worker");
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait comm worker");
    char tpath[64];
    snprintf(tpath, sizeof(tpath), "/proc/self/task/%d/comm", (int)wa.tid);
    CHECK(stat(tpath, &st) == 0 && (st.st_mode & 0777) == 0644, "task comm mode 0644");
    int tfd = open(tpath, O_RDWR);
    CHECK(tfd >= 0, "open sibling task comm");
    CHECK(write(tfd, "worker7", 7) == 7, "write sibling task comm");
    pread_str(tfd, buf, sizeof(buf));
    CHECK(strcmp(buf, "worker7\n") == 0, "sibling comm expected worker7\\n, got %s", buf);
    pread_str(fd, buf, sizeof(buf));
    CHECK(strcmp(buf, "xy\n") == 0, "main thread comm must remain xy\\n, got %s", buf);
    close(tfd);
    CHECK(write(done[1], "x", 1) == 1, "release comm worker");
    CHECK(pthread_join(th, NULL) == 0, "join comm worker");
    close(ready[0]);
    close(ready[1]);
    close(done[0]);
    close(done[1]);

    /* Writing another process's comm fails with EINVAL; after reap fails with ESRCH */
    int p2[2];
    CHECK(pipe(p2) == 0, "pipe for other proc comm");
    pid_t child = fork();
    CHECK(child >= 0, "fork other proc comm");
    if (child == 0) {
        close(p2[1]);
        char b;
        (void)read(p2[0], &b, 1);
        _exit(0);
    }
    close(p2[0]);
    char opath[64];
    snprintf(opath, sizeof(opath), "/proc/%d/comm", (int)child);
    int ofd = open(opath, O_WRONLY);
    CHECK(ofd >= 0, "open other process comm");
    CHECK_ERR(write(ofd, "nope", 4), EINVAL, "writing other process comm must fail with EINVAL");
    close(p2[1]);
    wait_ok(child, "other proc comm child");
    CHECK_ERR(write(ofd, "gone", 4), ESRCH, "writing reaped process comm must fail with ESRCH");
    close(ofd);

    /* Restore original name */
    CHECK(write(fd, orig, strlen(orig)) == (ssize_t)strlen(orig), "restore comm");
    close(fd);
}

static void test_proc_status_cpus_allowed(void)
{
    cpu_set_t saved;
    CPU_ZERO(&saved);
    CHECK(sched_getaffinity(0, sizeof(saved), &saved) == 0, "sched_getaffinity");

    char status[4096];
    read_str("/proc/self/status", status, sizeof(status));
    const char *mask_line = strstr(status, "\nCpus_allowed:\t");
    CHECK(mask_line != NULL, "status missing Cpus_allowed: line: %s", status);
    const char *mask_end = strchr(mask_line + 1, '\n');
    CHECK(mask_end != NULL, "unterminated Cpus_allowed line");
    CHECK(strncmp(mask_end + 1, "Cpus_allowed_list:\t", 19) == 0,
          "Cpus_allowed_list must immediately follow Cpus_allowed");

    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(0, &one);
    CHECK(sched_setaffinity(0, sizeof(one), &one) == 0, "sched_setaffinity cpu 0");
    read_str("/proc/self/status", status, sizeof(status));
    mask_line = strstr(status, "\nCpus_allowed:\t");
    CHECK(mask_line != NULL, "status missing Cpus_allowed after setaffinity");
    mask_line += strlen("\nCpus_allowed:\t");
    mask_end = strchr(mask_line, '\n');
    CHECK(mask_end != NULL && mask_end > mask_line, "invalid Cpus_allowed value");
    /* With only CPU 0 allowed, every hex digit except the final '1' must be '0' or ',' */
    for (const char *p = mask_line; p + 1 < mask_end; p++) {
        CHECK(*p == '0' || *p == ',', "unexpected digit in cpu-0 Cpus_allowed: %.*s",
              (int)(mask_end - mask_line), mask_line);
    }
    CHECK(mask_end[-1] == '1', "expected final hex digit 1 in cpu-0 Cpus_allowed: %.*s",
          (int)(mask_end - mask_line), mask_line);
    CHECK(strncmp(mask_end + 1, "Cpus_allowed_list:\t0\n", 21) == 0,
          "expected Cpus_allowed_list 0 after setaffinity");

    CHECK(sched_setaffinity(0, sizeof(saved), &saved) == 0, "restore sched_setaffinity");
}

static void set_lo_mtu(int mtu)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(s >= 0, "socket for SIOCSIFMTU");
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, "lo");
    ifr.ifr_mtu = mtu;
    CHECK(ioctl(s, SIOCSIFMTU, &ifr) == 0, "SIOCSIFMTU lo=%d", mtu);
    close(s);
}

static void test_sysfs_net_follows_mounter_ns(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork sysfs netns");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWNS | CLONE_NEWNET) == 0, "unshare mnt+net B");
        set_lo_mtu(16384);

        const char *sys_b = "/tmp/sys_net_b";
        const char *sys_b_bind = "/tmp/sys_net_b_bind";
        const char *sys_c = "/tmp/sys_net_c";
        CHECK(mkdir(sys_b, 0755) == 0 || errno == EEXIST, "mkdir sys_b");
        CHECK(mkdir(sys_b_bind, 0755) == 0 || errno == EEXIST, "mkdir sys_b_bind");
        CHECK(mkdir(sys_c, 0755) == 0 || errno == EEXIST, "mkdir sys_c");

        CHECK(mount("sysfs", sys_b, "sysfs", 0, NULL) == 0, "mount sysfs B");
        CHECK_ERR(mount("sysfs", sys_b, "sysfs", 0, NULL), EBUSY,
                  "stacking same-netns sysfs must return EBUSY");
        CHECK(mount(sys_b, sys_b_bind, NULL, MS_BIND, NULL) == 0, "bind mount sysfs B");

        struct stat st_boot, st_b, st_mtu;
        CHECK(stat("/sys", &st_boot) == 0 && stat(sys_b, &st_b) == 0, "stat sysfs mounts");
        CHECK(st_boot.st_dev != st_b.st_dev, "new netns sysfs must have distinct st_dev");
        CHECK(stat("/tmp/sys_net_b/class/net/lo/mtu", &st_mtu) == 0 && st_mtu.st_size == 4096 &&
                  st_mtu.st_blocks == 0,
              "non-initial sysfs regular file must report size 4096 and 0 blocks");

        /* Switch into netns C with a different lo MTU */
        CHECK(unshare(CLONE_NEWNET) == 0, "unshare net C");
        set_lo_mtu(32768);
        CHECK(mount("sysfs", sys_c, "sysfs", 0, NULL) == 0, "mount sysfs C");

        char buf[64];
        read_str("/tmp/sys_net_b/class/net/lo/mtu", buf, sizeof(buf));
        CHECK(strcmp(buf, "16384\n") == 0, "sys_b must follow mounter netns B (16384), got %s",
              buf);
        read_str("/tmp/sys_net_b_bind/class/net/lo/mtu", buf, sizeof(buf));
        CHECK(strcmp(buf, "16384\n") == 0,
              "bind of sys_b must follow mounter netns B (16384), got %s", buf);
        read_str("/tmp/sys_net_c/class/net/lo/mtu", buf, sizeof(buf));
        CHECK(strcmp(buf, "32768\n") == 0, "sys_c must follow mounter netns C (32768), got %s",
              buf);

        /* Mounting a fresh sysfs over boot /sys in netns C succeeds (different instance) */
        CHECK(mount("sysfs", "/sys", "sysfs", 0, NULL) == 0, "mount netns C sysfs over /sys");
        read_str("/sys/class/net/lo/mtu", buf, sizeof(buf));
        CHECK(strcmp(buf, "32768\n") == 0, "remounted /sys must see netns C (32768), got %s", buf);
        CHECK_ERR(mount("sysfs", "/sys", "sysfs", 0, NULL), EBUSY,
                  "stacking netns C sysfs on itself must return EBUSY");

        CHECK(umount2(sys_b_bind, 0) == 0, "umount sys_b_bind");
        CHECK(umount2(sys_b, 0) == 0, "umount sys_b");
        CHECK(umount2(sys_c, 0) == 0, "umount sys_c");
        rmdir(sys_b_bind);
        rmdir(sys_b);
        rmdir(sys_c);
        _exit(0);
    }
    wait_ok(pid, "sysfs netns mounter");
}

static void test_proc_self_auxv(char **envp)
{
    while (*envp)
        envp++;
    const Elf64_auxv_t *stack = (const Elf64_auxv_t *)(envp + 1);
    FILE *proc = fopen("/proc/self/auxv", "rb");
    CHECK(proc != NULL, "open /proc/self/auxv");
    Elf64_auxv_t entry;
    do {
        CHECK(fread(&entry, sizeof entry, 1, proc) == 1, "read auxv entry");
        CHECK(entry.a_type == stack->a_type && entry.a_un.a_val == stack->a_un.a_val,
              "auxv mismatch: proc (%lu, %#lx), stack (%lu, %#lx)",
              (unsigned long)entry.a_type, (unsigned long)entry.a_un.a_val,
              (unsigned long)stack->a_type, (unsigned long)stack->a_un.a_val);
        stack++;
    } while (entry.a_type != AT_NULL);
    CHECK(fgetc(proc) == EOF && !ferror(proc), "expected EOF after AT_NULL");
    fclose(proc);
}

int main(int argc, char **argv, char **envp)
{
    test_proc_self_auxv(envp);
    if (argc >= 2 && strcmp(argv[1], "--check-secure") == 0) {
        CHECK(geteuid() == 0, "setuid helper expected euid 0, got %d", (int)geteuid());
        CHECK(getauxval(AT_SECURE) == 1, "expected AT_SECURE == 1");
        struct rlimit rl;
        CHECK(getrlimit(RLIMIT_STACK, &rl) == 0, "getrlimit RLIMIT_STACK");
        CHECK(rl.rlim_cur == (8UL << 20),
              "expected clamped RLIMIT_STACK == 8 MiB, got %lu", (unsigned long)rl.rlim_cur);
        CHECK(argc == 50, "expected 50 args, got %d", argc);
        return 0;
    }

    CHECK(mkdir("/tmp", 01777) == 0 || errno == EEXIST, "mkdir /tmp");

    test_mount_setattr_anon_child();
    test_open_tree_attach_releases_mnt_ns_count();
    test_mnt_expire_cleared_on_access();
    test_move_mount_set_group();
    test_proc_pid_net_zombie_leader();
    test_proc_net_snmp_forwarding();
    test_sysctl_write_position();
    test_overlay_redirect_always_follow();
    test_open_by_handle_at_superblock_boundary();
    test_sysctl_namespace_pinning();
    test_proc_comm_write();
    test_proc_status_cpus_allowed();
    test_sysfs_net_follows_mounter_ns();
    test_cgroup_enodev();
    test_cgroup_delegation();
    test_aio_procfs_has_iter();
    test_past_eof_fault_permissions();
    test_mlock_semantics();
    test_madv_dontneed_cow_private_file();
    test_process_mrelease();
    test_secure_exec_arg_limit(argv[0]);

    printf("all ok\n");
    return 0;
}
