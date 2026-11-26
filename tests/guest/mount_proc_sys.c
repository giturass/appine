/*
 * Standalone guest regression tests for mount, overlay, procfs, and sysctl fixes:
 *   1. kernel/overlay: detaching other mount namespaces' mounts on removed/overwritten overlay
 *      names (upper dir, lower dir, file, overwriting rename) while keeping moved mounts on
 *      renamed sources and reporting EBUSY on same-namespace bind mounts.
 *   2. kernel/mount:
 *      - sb_busy (remount,ro) accounts for deleted files that are only mapped (tmpfs + FUSE)
 *        and deleted open/cwd FUSE files;
 *      - loop devices' backing files mark their mount busy for umount2 and release detached
 *        mounts on unbind.
 *   3. kernel/procfs: /proc/mounts and /proc/<pid>/mountinfo change notifications are scoped per
 *      mount namespace and do not fire on propagation-only changes (mount MS_SHARED/MS_PRIVATE/
 *      MS_SLAVE/MS_UNBINDABLE, propagation-only mount_setattr, MOVE_MOUNT_SET_GROUP).
 *   4. kernel/procfs: second write to uid_map / gid_map on the same fd fails with EINVAL
 *      (advancing file position like Linux's map_write), while rewriting at offset 0 or on a
 *      new fd fails with EPERM.
 *   5. kernel/sysctl:
 *      - /proc/sys/kernel/pid_max writes take effect (bounds, readback, PID wrap, EAGAIN on
 *        exhaustion, ns_last_pid bound, clone3 set_tid bound);
 *      - /proc/sys/kernel/{hostname,domainname} changes (via sysctl and sethostname/
 *        setdomainname) wake poll/epoll waiters with POLLPRI|POLLERR, scoped per name and per
 *        UTS namespace, consumed on poll and not cleared by read.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#define FUSE_KERNEL_VERSION 7
#define FUSE_KERNEL_MINOR_VERSION 36
#define FUSE_LOOKUP 1
#define FUSE_FORGET 2
#define FUSE_GETATTR 3
#define FUSE_UNLINK 10
#define FUSE_OPEN 14
#define FUSE_READ 15
#define FUSE_RELEASE 18
#define FUSE_FLUSH 25
#define FUSE_INIT 26
#define FUSE_BATCH_FORGET 42

struct fuse_in_header {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

struct fuse_out_header {
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

struct fuse_read_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t unused[7];
};

#define CHECK(cond, fmt, ...)                                                        \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "FAIL (%s:%d): " fmt " (errno=%d: %s)\n",                \
                    __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno));      \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#define MOVE_MOUNT_SET_GROUP 0x00000100
#endif

struct k_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

struct k_clone_args {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

#define LOOP_SET_FD 0x4C00
#define LOOP_CLR_FD 0x4C01
#define LOOP_CTL_GET_FREE 0x4C82

static void write_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "open %s for write", path);
    ssize_t n = write(fd, s, strlen(s));
    CHECK(n == (ssize_t)strlen(s), "write %s", path);
    CHECK(close(fd) == 0, "close %s", path);
}

static int try_write_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    ssize_t n = write(fd, s, strlen(s));
    int saved = errno;
    close(fd);
    errno = saved;
    return n == (ssize_t)strlen(s) ? 0 : -1;
}

static void read_str(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s for read", path);
    ssize_t n = read(fd, buf, sz - 1);
    CHECK(n >= 0, "read %s", path);
    buf[n] = '\0';
    CHECK(close(fd) == 0, "close %s", path);
}

static int poll_pri(int fd, int timeout_ms)
{
    struct pollfd p = {.fd = fd, .events = POLLPRI};
    int r = poll(&p, 1, timeout_ms);
    CHECK(r >= 0, "poll");
    return r > 0 ? p.revents : 0;
}

/* ---- 1. kernel/overlay: detach other namespaces' mounts on removed/renamed overlay names ---- */

static void test_overlay_detach(void)
{
    CHECK(mkdir("/tmp/ovld", 0755) == 0, "mkdir /tmp/ovld");
    CHECK(mount("tmpfs", "/tmp/ovld", "tmpfs", 0, NULL) == 0, "mount tmpfs");
    CHECK(mkdir("/tmp/ovld/lower", 0755) == 0, "mkdir lower");
    CHECK(mkdir("/tmp/ovld/lower/l_rm", 0755) == 0, "mkdir l_rm");
    write_str("/tmp/ovld/lower/f_rm", "rm");
    write_str("/tmp/ovld/lower/f_dst", "dst");
    write_str("/tmp/ovld/lower/f_src", "src");
    CHECK(mkdir("/tmp/ovld/upper", 0755) == 0, "mkdir upper");
    CHECK(mkdir("/tmp/ovld/work", 0755) == 0, "mkdir work");
    CHECK(mkdir("/tmp/ovld/m", 0755) == 0, "mkdir m");
    CHECK(mkdir("/tmp/ovld/m_bind", 0755) == 0, "mkdir m_bind");
    write_str("/tmp/ovld/hostfile", "bind-src");

    CHECK(mount("overlay", "/tmp/ovld/m", "overlay", 0,
                "lowerdir=/tmp/ovld/lower,upperdir=/tmp/ovld/upper,workdir=/tmp/ovld/work") == 0,
          "mount overlay");
    CHECK(mkdir("/tmp/ovld/m/u_rm", 0755) == 0, "mkdir u_rm");
    CHECK(mkdir("/tmp/ovld/m/u_dst", 0755) == 0, "mkdir u_dst");
    CHECK(mkdir("/tmp/ovld/m/u_src", 0755) == 0, "mkdir u_src");
    CHECK(mkdir("/tmp/ovld/m/local_mp", 0755) == 0, "mkdir local_mp");

    /* Same-namespace bind mount: a mount on the bind copy blocks rmdir on the original with EBUSY */
    CHECK(mount("/tmp/ovld/m", "/tmp/ovld/m_bind", NULL, MS_BIND, NULL) == 0, "bind overlay");
    CHECK(mount("tmpfs", "/tmp/ovld/m_bind/local_mp", "tmpfs", 0, NULL) == 0, "mount local_mp");
    errno = 0;
    CHECK(rmdir("/tmp/ovld/m/local_mp") == -1 && errno == EBUSY,
          "rmdir through original mount must fail EBUSY when bind copy has mount");
    CHECK(umount("/tmp/ovld/m_bind/local_mp") == 0, "umount local_mp");
    CHECK(umount("/tmp/ovld/m_bind") == 0, "umount m_bind");

    /* Cross-namespace detach on rmdir, unlink, and overwriting rename */
    int p1[2], p2[2];
    CHECK(pipe(p1) == 0 && pipe(p2) == 0, "pipes");
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(p1[0]);
        close(p2[1]);
        CHECK(unshare(CLONE_NEWNS) == 0, "child unshare CLONE_NEWNS");
        CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "child private /");
        CHECK(mount("tmpfs", "/tmp/ovld/m/u_rm", "tmpfs", 0, NULL) == 0, "mount u_rm");
        CHECK(mount("tmpfs", "/tmp/ovld/m/l_rm", "tmpfs", 0, NULL) == 0, "mount l_rm");
        CHECK(mount("tmpfs", "/tmp/ovld/m/u_dst", "tmpfs", 0, NULL) == 0, "mount u_dst");
        CHECK(mount("tmpfs", "/tmp/ovld/m/u_src", "tmpfs", 0, NULL) == 0, "mount u_src");
        CHECK(mount("/tmp/ovld/hostfile", "/tmp/ovld/m/f_rm", NULL, MS_BIND, NULL) == 0, "bind f_rm");
        CHECK(mount("/tmp/ovld/hostfile", "/tmp/ovld/m/f_dst", NULL, MS_BIND, NULL) == 0, "bind f_dst");
        CHECK(mount("/tmp/ovld/hostfile", "/tmp/ovld/m/f_src", NULL, MS_BIND, NULL) == 0, "bind f_src");
        CHECK(write(p1[1], "1", 1) == 1, "signal parent");
        char ch;
        CHECK(read(p2[0], &ch, 1) == 1, "wait parent");

        char buf[16384];
        read_str("/proc/self/mountinfo", buf, sizeof(buf));
        CHECK(strstr(buf, " /tmp/ovld/m/u_rm ") == NULL, "u_rm mount must be detached");
        CHECK(strstr(buf, " /tmp/ovld/m/l_rm ") == NULL, "l_rm mount must be detached");
        CHECK(strstr(buf, " /tmp/ovld/m/f_rm ") == NULL, "f_rm mount must be detached");
        CHECK(strstr(buf, " /tmp/ovld/m/u_src ") == NULL, "u_src mount must move to u_dst");
        CHECK(strstr(buf, " /tmp/ovld/m/f_src ") == NULL, "f_src mount must move to f_dst");
        /* Exactly one mount on u_dst (the moved u_src mount; old u_dst mount detached) */
        char *p_udst = strstr(buf, " /tmp/ovld/m/u_dst ");
        CHECK(p_udst != NULL && strstr(p_udst + 1, " /tmp/ovld/m/u_dst ") == NULL,
              "u_dst must have exactly 1 surviving mount");
        char *p_fdst = strstr(buf, " /tmp/ovld/m/f_dst ");
        CHECK(p_fdst != NULL && strstr(p_fdst + 1, " /tmp/ovld/m/f_dst ") == NULL,
              "f_dst must have exactly 1 surviving mount");
        _exit(0);
    }
    close(p1[1]);
    close(p2[0]);
    char ch;
    CHECK(read(p1[0], &ch, 1) == 1, "wait child mount");
    CHECK(rmdir("/tmp/ovld/m/u_rm") == 0, "rmdir u_rm");
    CHECK(rmdir("/tmp/ovld/m/l_rm") == 0, "rmdir l_rm");
    CHECK(unlink("/tmp/ovld/m/f_rm") == 0, "unlink f_rm");
    CHECK(rename("/tmp/ovld/m/u_src", "/tmp/ovld/m/u_dst") == 0, "rename u_src -> u_dst");
    CHECK(rename("/tmp/ovld/m/f_src", "/tmp/ovld/m/f_dst") == 0, "rename f_src -> f_dst");
    CHECK(write(p2[1], "1", 1) == 1, "signal child check");
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "overlay detach child failed (status=%d)", status);
    close(p1[0]);
    close(p2[1]);
    CHECK(umount("/tmp/ovld/m") == 0, "umount overlay");
    CHECK(umount("/tmp/ovld") == 0, "umount tmpfs");
    printf("overlay_detach ok\n");
}

/* ---- 2. kernel/mount: sb_busy (mapped deleted + FUSE deleted) and loop umount2 busy ---- */

struct fuse_state {
    int fd;
    int file_present;
};

static void fuse_reply(int fd, uint64_t unique, int32_t err, const void *body, size_t len)
{
    struct {
        struct fuse_out_header h;
        char buf[512];
    } msg;
    msg.h.len = (uint32_t)(sizeof(msg.h) + len);
    msg.h.error = err;
    msg.h.unique = unique;
    if (len > 0)
        memcpy(msg.buf, body, len);
    ssize_t r = write(fd, &msg, msg.h.len);
    (void)r;
}

static void fill_fuse_attr(struct fuse_attr *a, uint64_t ino, uint32_t mode, uint32_t nlink, uint64_t size)
{
    memset(a, 0, sizeof(*a));
    a->ino = ino;
    a->mode = mode;
    a->nlink = nlink;
    a->size = size;
    a->blksize = 4096;
}

static void *fuse_daemon(void *arg)
{
    struct fuse_state *st = arg;
    char req[8192];
    for (;;) {
        ssize_t n = read(st->fd, req, sizeof(req));
        if (n < (ssize_t)sizeof(struct fuse_in_header))
            break;
        struct fuse_in_header *in = (struct fuse_in_header *)req;
        const char *body = req + sizeof(*in);
        switch (in->opcode) {
        case FUSE_INIT: {
            struct fuse_init_out out;
            memset(&out, 0, sizeof(out));
            out.major = FUSE_KERNEL_VERSION;
            out.minor = FUSE_KERNEL_MINOR_VERSION;
            out.max_write = 4096;
            fuse_reply(st->fd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_LOOKUP: {
            if (in->nodeid == 1 && st->file_present && strcmp(body, "f") == 0) {
                struct fuse_entry_out out;
                memset(&out, 0, sizeof(out));
                out.nodeid = 2;
                out.generation = 1;
                out.entry_valid = 60;
                out.attr_valid = 60;
                fill_fuse_attr(&out.attr, 2, S_IFREG | 0644, 1, 4096);
                fuse_reply(st->fd, in->unique, 0, &out, sizeof(out));
            } else {
                fuse_reply(st->fd, in->unique, -ENOENT, NULL, 0);
            }
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out out;
            memset(&out, 0, sizeof(out));
            out.attr_valid = 60;
            if (in->nodeid == 1)
                fill_fuse_attr(&out.attr, 1, S_IFDIR | 0755, 2, 0);
            else
                fill_fuse_attr(&out.attr, 2, S_IFREG | 0644, st->file_present ? 1 : 0, 4096);
            fuse_reply(st->fd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out out;
            memset(&out, 0, sizeof(out));
            out.fh = 7;
            fuse_reply(st->fd, in->unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_READ: {
            const struct fuse_read_in *ri = (const struct fuse_read_in *)body;
            size_t len = ri->size;
            if (ri->offset >= 4096)
                len = 0;
            else if (ri->offset + len > 4096)
                len = 4096 - (size_t)ri->offset;
            char *buf = calloc(1, sizeof(struct fuse_out_header) + len);
            struct fuse_out_header *h = (struct fuse_out_header *)buf;
            h->len = (uint32_t)(sizeof(*h) + len);
            h->error = 0;
            h->unique = in->unique;
            memset(buf + sizeof(*h), 'Z', len);
            ssize_t r = write(st->fd, buf, h->len);
            (void)r;
            free(buf);
            break;
        }
        case FUSE_UNLINK: {
            if (in->nodeid == 1 && st->file_present && strcmp(body, "f") == 0) {
                st->file_present = 0;
                fuse_reply(st->fd, in->unique, 0, NULL, 0);
            } else {
                fuse_reply(st->fd, in->unique, -ENOENT, NULL, 0);
            }
            break;
        }
        case FUSE_FLUSH:
        case FUSE_RELEASE:
            fuse_reply(st->fd, in->unique, 0, NULL, 0);
            break;
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            break;
        default:
            fuse_reply(st->fd, in->unique, -ENOSYS, NULL, 0);
            break;
        }
    }
    return NULL;
}

static void test_sb_busy_and_loop_umount(void)
{
    /* 2a. Deleted file that is only mapped blocks remount,ro with EBUSY */
    CHECK(mkdir("/tmp/sbm", 0755) == 0, "mkdir /tmp/sbm");
    CHECK(mount("tmpfs", "/tmp/sbm", "tmpfs", 0, NULL) == 0, "mount sbm");
    int fd = open("/tmp/sbm/del", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0, "open del");
    char page[4096];
    memset(page, 'A', sizeof(page));
    CHECK(write(fd, page, sizeof(page)) == sizeof(page), "write del");
    void *map = mmap(NULL, sizeof(page), PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(map != MAP_FAILED, "mmap del");
    CHECK(close(fd) == 0, "close del");
    CHECK(unlink("/tmp/sbm/del") == 0, "unlink del");
    errno = 0;
    CHECK(mount(NULL, "/tmp/sbm", NULL, MS_REMOUNT | MS_RDONLY, NULL) == -1 && errno == EBUSY,
          "remount,ro with only-mapped deleted file must fail EBUSY");
    CHECK(munmap(map, sizeof(page)) == 0, "munmap del");
    CHECK(mount(NULL, "/tmp/sbm", NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0,
          "remount,ro after munmap must succeed");
    CHECK(umount("/tmp/sbm") == 0, "umount sbm");

    /* 2b. Deleted FUSE file (open fd AND only-mapped) blocks remount,ro with EBUSY */
    CHECK(mkdir("/tmp/sbf", 0755) == 0, "mkdir /tmp/sbf");
    int ffd = open("/dev/fuse", O_RDWR);
    CHECK(ffd >= 0, "open /dev/fuse");
    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=0,group_id=0", ffd);
    CHECK(mount("testfuse", "/tmp/sbf", "fuse", 0, opts) == 0, "mount fuse");
    struct fuse_state fst = {.fd = ffd, .file_present = 1};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, fuse_daemon, &fst) == 0, "start fuse daemon");

    /* Deleted open FUSE file (read-only fd, not a writer) */
    int f1 = open("/tmp/sbf/f", O_RDONLY);
    CHECK(f1 >= 0, "open fuse f");
    CHECK(unlink("/tmp/sbf/f") == 0, "unlink fuse f");
    errno = 0;
    CHECK(mount(NULL, "/tmp/sbf", NULL, MS_REMOUNT | MS_RDONLY, NULL) == -1 && errno == EBUSY,
          "remount,ro with deleted open FUSE file must fail EBUSY");
    CHECK(close(f1) == 0, "close fuse f");
    CHECK(mount(NULL, "/tmp/sbf", NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0,
          "remount,ro after closing deleted FUSE file must succeed");

    /* Remount rw, restore file in daemon, map + close + unlink -> only-mapped deleted FUSE file */
    CHECK(mount(NULL, "/tmp/sbf", NULL, MS_REMOUNT, NULL) == 0, "remount fuse rw");
    fst.file_present = 1;
    int f2 = open("/tmp/sbf/f", O_RDONLY);
    CHECK(f2 >= 0, "reopen fuse f");
    char *fmap = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f2, 0);
    CHECK(fmap != MAP_FAILED, "mmap fuse f");
    CHECK(fmap[0] == 'Z', "read mapped fuse byte");
    CHECK(close(f2) == 0, "close fuse f2");
    CHECK(unlink("/tmp/sbf/f") == 0, "unlink fuse f2");
    errno = 0;
    CHECK(mount(NULL, "/tmp/sbf", NULL, MS_REMOUNT | MS_RDONLY, NULL) == -1 && errno == EBUSY,
          "remount,ro with only-mapped deleted FUSE file must fail EBUSY");
    CHECK(munmap(fmap, 4096) == 0, "munmap fuse f");
    CHECK(mount(NULL, "/tmp/sbf", NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0,
          "remount,ro after munmap of deleted FUSE file must succeed");

    CHECK(umount("/tmp/sbf") == 0, "umount fuse");
    pthread_join(th, NULL);
    close(ffd);

    /* 2c. Loop device backing file makes its mount busy for umount2 */
    CHECK(mkdir("/tmp/loopmnt", 0755) == 0, "mkdir /tmp/loopmnt");
    CHECK(mount("tmpfs", "/tmp/loopmnt", "tmpfs", 0, NULL) == 0, "mount loopmnt");
    int img = open("/tmp/loopmnt/img", O_CREAT | O_RDWR, 0644);
    CHECK(img >= 0, "create loop backing file");
    CHECK(ftruncate(img, 65536) == 0, "ftruncate img");

    int ctl = open("/dev/loop-control", O_RDWR);
    CHECK(ctl >= 0, "open /dev/loop-control");
    int idx = ioctl(ctl, LOOP_CTL_GET_FREE);
    CHECK(idx >= 0, "LOOP_CTL_GET_FREE");
    char lpath[64];
    snprintf(lpath, sizeof(lpath), "/dev/loop%d", idx);
    int lfd = open(lpath, O_RDWR);
    CHECK(lfd >= 0, "open %s", lpath);
    CHECK(ioctl(lfd, LOOP_SET_FD, img) == 0, "LOOP_SET_FD");
    CHECK(close(img) == 0, "close backing fd");

    errno = 0;
    CHECK(umount("/tmp/loopmnt") == -1 && errno == EBUSY,
          "umount must fail EBUSY while loop device holds backing file");
    CHECK(ioctl(lfd, LOOP_CLR_FD, 0) == 0, "LOOP_CLR_FD");
    CHECK(umount("/tmp/loopmnt") == 0, "umount after LOOP_CLR_FD must succeed");

    /* Also verify MNT_DETACH + unbind releases cleanly */
    CHECK(mount("tmpfs", "/tmp/loopmnt", "tmpfs", 0, NULL) == 0, "remount loopmnt");
    img = open("/tmp/loopmnt/img2", O_CREAT | O_RDWR, 0644);
    CHECK(img >= 0 && ftruncate(img, 4096) == 0, "create img2");
    CHECK(ioctl(lfd, LOOP_SET_FD, img) == 0, "LOOP_SET_FD 2");
    CHECK(close(img) == 0, "close img2");
    CHECK(umount2("/tmp/loopmnt", MNT_DETACH) == 0, "umount2 MNT_DETACH with loop");
    CHECK(ioctl(lfd, LOOP_CLR_FD, 0) == 0, "LOOP_CLR_FD after detach");
    close(lfd);
    close(ctl);
    printf("sb_busy_and_loop_umount ok\n");
}

/* ---- 3. kernel/procfs: per-mntns mountinfo/mounts poll + silent propagation changes ---- */

static void test_mountinfo_poll_scoping(void)
{
    int mi = open("/proc/self/mountinfo", O_RDONLY);
    int mo = open("/proc/mounts", O_RDONLY);
    CHECK(mi >= 0 && mo >= 0, "open mountinfo/mounts");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0, "initial mountinfo clean");
    CHECK((poll_pri(mo, 0) & (POLLPRI | POLLERR)) == 0, "initial mounts clean");

    CHECK(mkdir("/tmp/pm", 0755) == 0, "mkdir /tmp/pm");
    CHECK(mkdir("/tmp/pm2", 0755) == 0, "mkdir /tmp/pm2");
    CHECK(mount("tmpfs", "/tmp/pm", "tmpfs", 0, NULL) == 0, "mount pm");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR), "mount triggers mountinfo");
    CHECK((poll_pri(mo, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR), "mount triggers mounts");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0, "mountinfo consumed");
    CHECK((poll_pri(mo, 0) & (POLLPRI | POLLERR)) == 0, "mounts consumed");

    /* Propagation-only mount(2) calls must not trigger POLLPRI */
    CHECK(mount(NULL, "/tmp/pm", NULL, MS_SHARED, NULL) == 0, "make shared");
    CHECK(mount(NULL, "/tmp/pm", NULL, MS_SLAVE, NULL) == 0, "make slave");
    CHECK(mount(NULL, "/tmp/pm", NULL, MS_UNBINDABLE, NULL) == 0, "make unbindable");
    CHECK(mount(NULL, "/tmp/pm", NULL, MS_PRIVATE, NULL) == 0, "make private");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0, "propagation-only mount(2) must not trigger mountinfo");
    CHECK((poll_pri(mo, 0) & (POLLPRI | POLLERR)) == 0, "propagation-only mount(2) must not trigger mounts");

    /* Propagation-only mount_setattr must not trigger POLLPRI */
    struct k_mount_attr ma = {.attr_set = 0, .attr_clr = 0, .propagation = MS_SHARED, .userns_fd = 0};
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, "/tmp/pm", 0, &ma, sizeof(ma)) == 0,
          "propagation-only mount_setattr");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0, "propagation-only mount_setattr must not trigger");

    /* MOVE_MOUNT_SET_GROUP must not trigger POLLPRI */
    CHECK(mount("/tmp/pm", "/tmp/pm2", NULL, MS_BIND, NULL) == 0, "bind pm2");
    CHECK(mount(NULL, "/tmp/pm2", NULL, MS_PRIVATE, NULL) == 0, "make pm2 private");
    (void)poll_pri(mi, 0);
    (void)poll_pri(mo, 0);
    CHECK(syscall(SYS_move_mount, AT_FDCWD, "/tmp/pm", AT_FDCWD, "/tmp/pm2", MOVE_MOUNT_SET_GROUP) == 0,
          "MOVE_MOUNT_SET_GROUP");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0, "MOVE_MOUNT_SET_GROUP must not trigger");

    /* Flag-changing mount_setattr MUST trigger POLLPRI */
    ma.attr_set = MOUNT_ATTR_NOEXEC;
    ma.propagation = 0;
    CHECK(syscall(SYS_mount_setattr, AT_FDCWD, "/tmp/pm2", 0, &ma, sizeof(ma)) == 0,
          "flag-changing mount_setattr");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
          "flag-changing mount_setattr must trigger mountinfo");
    (void)poll_pri(mo, 0);

    /* Mount changes in another mount namespace must NOT trigger parent's mountinfo/mounts */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork mntns child");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWNS) == 0, "child unshare CLONE_NEWNS");
        CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "child private");
        int cmi = open("/proc/self/mountinfo", O_RDONLY);
        CHECK(cmi >= 0, "child open mountinfo");
        CHECK((poll_pri(cmi, 0) & (POLLPRI | POLLERR)) == 0, "child initial clean");
        CHECK(mkdir("/tmp/child_mp", 0755) == 0 || errno == EEXIST, "mkdir child_mp");
        CHECK(mount("tmpfs", "/tmp/child_mp", "tmpfs", 0, NULL) == 0, "child mount");
        CHECK((poll_pri(cmi, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
              "child mount must trigger child mountinfo");
        CHECK(umount("/tmp/child_mp") == 0, "child umount");
        CHECK((poll_pri(cmi, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
              "child umount must trigger child mountinfo");
        close(cmi);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "mntns child failed");
    CHECK((poll_pri(mi, 0) & (POLLPRI | POLLERR)) == 0,
          "other mntns mount/umount must not trigger parent mountinfo");
    CHECK((poll_pri(mo, 0) & (POLLPRI | POLLERR)) == 0,
          "other mntns mount/umount must not trigger parent mounts");

    CHECK(umount("/tmp/pm2") == 0, "umount pm2");
    CHECK(umount("/tmp/pm") == 0, "umount pm");
    close(mi);
    close(mo);
    printf("mountinfo_poll_scoping ok\n");
}

/* ---- 4. kernel/procfs: uid_map / gid_map second write returns EINVAL on same fd ---- */

static void test_id_map_second_write(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork userns");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWUSER) == 0, "unshare CLONE_NEWUSER");
        write_str("/proc/self/setgroups", "deny\n");

        const char *maps[2] = {"/proc/self/uid_map", "/proc/self/gid_map"};
        for (int i = 0; i < 2; i++) {
            int fd = open(maps[i], O_WRONLY);
            CHECK(fd >= 0, "open %s", maps[i]);
            ssize_t n = write(fd, "0 0 1\n", 6);
            CHECK(n == 6, "first write to %s", maps[i]);
            off_t pos = lseek(fd, 0, SEEK_CUR);
            CHECK(pos == 6, "position after first write to %s (got %ld)", maps[i], (long)pos);

            errno = 0;
            CHECK(write(fd, "1 1 1\n", 6) == -1 && errno == EINVAL,
                  "second write on same fd to %s must fail EINVAL", maps[i]);

            CHECK(lseek(fd, 0, SEEK_SET) == 0, "lseek 0 on %s", maps[i]);
            errno = 0;
            CHECK(write(fd, "1 1 1\n", 6) == -1 && errno == EPERM,
                  "rewound second write to %s must fail EPERM", maps[i]);
            close(fd);

            int fd2 = open(maps[i], O_WRONLY);
            CHECK(fd2 >= 0, "reopen %s", maps[i]);
            errno = 0;
            CHECK(write(fd2, "1 1 1\n", 6) == -1 && errno == EPERM,
                  "second write on new fd to %s must fail EPERM", maps[i]);
            close(fd2);
        }
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "id_map child failed");
    printf("id_map_second_write ok\n");
}

/* ---- 5a. kernel/sysctl: /proc/sys/kernel/pid_max takes effect ---- */

static void test_pid_max(void)
{
    char orig[64], cur[64];
    read_str("/proc/sys/kernel/pid_max", orig, sizeof(orig));
    CHECK(strcmp(orig, "4194304\n") == 0, "default pid_max=%s", orig);

    /* Out-of-range writes fail EINVAL and leave value unchanged */
    errno = 0;
    CHECK(try_write_str("/proc/sys/kernel/pid_max", "300\n") == -1 && errno == EINVAL,
          "pid_max=300 must fail EINVAL");
    errno = 0;
    CHECK(try_write_str("/proc/sys/kernel/pid_max", "0\n") == -1 && errno == EINVAL,
          "pid_max=0 must fail EINVAL");
    errno = 0;
    CHECK(try_write_str("/proc/sys/kernel/pid_max", "4194305\n") == -1 && errno == EINVAL,
          "pid_max=4194305 must fail EINVAL");
    read_str("/proc/sys/kernel/pid_max", cur, sizeof(cur));
    CHECK(strcmp(cur, orig) == 0, "pid_max unchanged after invalid writes");

    /* Lower pid_max and verify readback, ns_last_pid bound, clone3 set_tid bound, wrap & EAGAIN */
    CHECK(try_write_str("/proc/sys/kernel/pid_max", "305\n") == 0, "set pid_max=305");
    read_str("/proc/sys/kernel/pid_max", cur, sizeof(cur));
    CHECK(strcmp(cur, "305\n") == 0, "pid_max readback=%s", cur);

    errno = 0;
    CHECK(try_write_str("/proc/sys/kernel/ns_last_pid", "306\n") == -1 && errno == EINVAL,
          "ns_last_pid > pid_max must fail EINVAL");

    pid_t bad_tid = 305;
    struct k_clone_args ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = SIGCHLD;
    ca.set_tid = (uint64_t)(uintptr_t)&bad_tid;
    ca.set_tid_size = 1;
    errno = 0;
    CHECK(syscall(SYS_clone3, &ca, sizeof(ca)) == -1 && errno == EINVAL,
          "clone3 set_tid == pid_max must fail EINVAL");

    CHECK(try_write_str("/proc/sys/kernel/ns_last_pid", "303\n") == 0, "set ns_last_pid=303");

    /* Spawn 5 sleeping children to occupy all of [300, 305) */
    int hold[2];
    CHECK(pipe(hold) == 0, "hold pipe");
    pid_t kids[5];
    int nkids = 0;
    for (int i = 0; i < 5; i++) {
        pid_t c = fork();
        CHECK(c >= 0, "fork child %d", i);
        if (c == 0) {
            close(hold[1]);
            char b;
            (void)read(hold[0], &b, 1);
            _exit(0);
        }
        CHECK(c >= 300 && c < 305, "allocated pid %d out of [300, 305)", c);
        kids[nkids++] = c;
    }
    /* Next fork must fail with EAGAIN because [300, 305) is full */
    errno = 0;
    CHECK(fork() == -1 && errno == EAGAIN, "fork past pid_max saturation must fail EAGAIN");

    close(hold[1]);
    close(hold[0]);
    for (int i = 0; i < nkids; i++)
        CHECK(waitpid(kids[i], NULL, 0) == kids[i], "reap child %d", i);

    CHECK(try_write_str("/proc/sys/kernel/pid_max", orig) == 0, "restore pid_max");
    printf("pid_max ok\n");
}

/* ---- 5b. kernel/sysctl: hostname / domainname wake pollers with POLLPRI ---- */

struct wait_arg {
    int fd;
    int use_epoll;
    int revents;
};

static void *wait_pri_thread(void *arg)
{
    struct wait_arg *w = arg;
    if (w->use_epoll) {
        int ep = epoll_create1(0);
        CHECK(ep >= 0, "epoll_create1");
        struct epoll_event ev = {.events = EPOLLPRI, .data.fd = w->fd};
        CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, w->fd, &ev) == 0, "epoll_ctl ADD");
        struct epoll_event out;
        int n = epoll_wait(ep, &out, 1, 2000);
        CHECK(n == 1, "epoll_wait timed out");
        w->revents = (int)out.events;
        close(ep);
    } else {
        struct pollfd p = {.fd = w->fd, .events = POLLPRI};
        int n = poll(&p, 1, 2000);
        CHECK(n == 1, "poll timed out");
        w->revents = p.revents;
    }
    return NULL;
}

static void test_uts_poll_pri(void)
{
    int hfd = open("/proc/sys/kernel/hostname", O_RDONLY);
    int dfd = open("/proc/sys/kernel/domainname", O_RDONLY);
    CHECK(hfd >= 0 && dfd >= 0, "open hostname/domainname");
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0, "initial hostname clean");
    CHECK((poll_pri(dfd, 0) & (POLLPRI | POLLERR)) == 0, "initial domainname clean");

    /* 1. Blocking epoll_wait(EPOLLPRI) wakes on sysctl write to hostname */
    struct wait_arg wa = {.fd = hfd, .use_epoll = 1, .revents = 0};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, wait_pri_thread, &wa) == 0, "start epoll waiter");
    usleep(30000);
    CHECK(try_write_str("/proc/sys/kernel/hostname", "host-sysctl\n") == 0, "write hostname");
    pthread_join(th, NULL);
    CHECK((wa.revents & (EPOLLPRI | EPOLLERR)) == (EPOLLPRI | EPOLLERR),
          "hostname epoll revents=%#x", wa.revents);
    /* Consumed by epoll; domainname untouched */
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0, "hostname consumed");
    CHECK((poll_pri(dfd, 0) & (POLLPRI | POLLERR)) == 0, "domainname unaffected by hostname write");

    /* 2. sethostname(2) triggers POLLPRI, and reading before poll does not clear it */
    CHECK(sethostname("host-sys", 8) == 0, "sethostname");
    char buf[64];
    CHECK(lseek(hfd, 0, SEEK_SET) == 0, "lseek hfd");
    ssize_t rn = read(hfd, buf, sizeof(buf) - 1);
    CHECK(rn > 0, "read hfd");
    buf[rn] = '\0';
    CHECK(strcmp(buf, "host-sys\n") == 0, "read updated hostname=%s", buf);
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
          "read must not clear hostname POLLPRI");
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0, "consumed after poll");

    /* 3. Blocking poll(POLLPRI) wakes on setdomainname(2) */
    struct wait_arg wb = {.fd = dfd, .use_epoll = 0, .revents = 0};
    CHECK(pthread_create(&th, NULL, wait_pri_thread, &wb) == 0, "start poll waiter");
    usleep(30000);
    CHECK(setdomainname("dom-sys", 7) == 0, "setdomainname");
    pthread_join(th, NULL);
    CHECK((wb.revents & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
          "domainname poll revents=%#x", wb.revents);
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0, "hostname unaffected by domainname");
    CHECK((poll_pri(dfd, 0) & (POLLPRI | POLLERR)) == 0, "domainname consumed");

    /* 4. Per-UTS-namespace isolation */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork utsns");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWUTS) == 0, "child unshare CLONE_NEWUTS");
        int chfd = open("/proc/sys/kernel/hostname", O_RDONLY);
        CHECK(chfd >= 0, "child open hostname");
        CHECK((poll_pri(chfd, 0) & (POLLPRI | POLLERR)) == 0, "child hostname initial clean");
        CHECK(sethostname("child-uts", 9) == 0, "child sethostname");
        CHECK((poll_pri(chfd, 0) & (POLLPRI | POLLERR)) == (POLLPRI | POLLERR),
              "child hostname poll must trigger");
        /* Inherited parent hfd is pinned to parent UTS ns -> must not trigger */
        CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0,
              "parent hostname fd must not trigger from child UTS ns");
        close(chfd);
        _exit(0);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "uts child failed");
    CHECK((poll_pri(hfd, 0) & (POLLPRI | POLLERR)) == 0,
          "parent hostname fd unaffected by child UTS ns");

    close(hfd);
    close(dfd);
    printf("uts_poll_pri ok\n");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    CHECK(mkdir("/tmp", 0777) == 0 || errno == EEXIST, "mkdir /tmp");
    test_overlay_detach();
    test_sb_busy_and_loop_umount();
    test_mountinfo_poll_scoping();
    test_id_map_second_write();
    test_pid_max();
    test_uts_poll_pri();
    printf("all ok\n");
    return 0;
}
