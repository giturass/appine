/*
 * Regression tests for Linux 6.1 new mount API semantics (open_tree, move_mount, mount_setattr):
 *  1. No-lookup paths (AT_EMPTY_PATH fd, ".", "/") do not lift to overmounts in open_tree,
 *     move_mount (source and MOVE_MOUNT_SET_GROUP), and mount_setattr, while named lookups
 *     (including with AT_NO_AUTOMOUNT) and move_mount's attachment target (lock_mount) do lift;
 *  2. open_tree(OPEN_TREE_CLONE) + move_mount of /proc/<pid>/ns/<kind> creates an nsfs mount pinning
 *     the namespace across process exit (including open nsfd, existing nsfs bind mount, and
 *     NS_GET_USERNS from an attached nsfs mount), and move_mount enforces mnt_ns_loop against
 *     self/older/shared-cycle mount namespaces.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif
#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP 0x00000100
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef NS_GET_USERNS
#define NS_GET_USERNS 0xb701
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_move_mount
#define SYS_move_mount 429
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

struct k_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

struct paused_child {
    pid_t pid;
    int go_fd;
};

static long do_open_tree(int dfd, const char *p, unsigned int flags)
{
    return syscall(SYS_open_tree, dfd, p, flags);
}

static long do_move_mount(int fdfd, const char *fp, int tdfd, const char *tp, unsigned int flags)
{
    return syscall(SYS_move_mount, fdfd, fp, tdfd, tp, flags);
}

static long do_mount_setattr(int dfd, const char *p, unsigned int flags, struct k_mount_attr *ma)
{
    return syscall(SYS_mount_setattr, dfd, p, flags, ma, sizeof(*ma));
}

static void mount_tmpfs(const char *path)
{
    CHECK(mount("tmpfs", path, "tmpfs", 0, "size=64k") == 0, "mount tmpfs %s", path);
}

static void touch_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0, "create %s", path);
    if (content && *content) {
        size_t n = strlen(content);
        CHECK(write(fd, content, n) == (ssize_t)n, "write %s", path);
    }
    close(fd);
}

static int has_entry(int dirfd, const char *name)
{
    struct stat st;
    return fstatat(dirfd, name, &st, 0) == 0;
}

static void wait_ok(pid_t pid, const char *label)
{
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid, "waitpid %s", label);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "%s exited abnormally (status=%#x)", label, status);
}

static struct paused_child spawn_paused(void (*setup)(void), const char *label)
{
    int rdy[2], go[2];
    CHECK(pipe(rdy) == 0 && pipe(go) == 0, "pipes %s", label);
    pid_t pid = fork();
    CHECK(pid >= 0, "fork %s", label);
    if (pid == 0) {
        close(rdy[0]);
        close(go[1]);
        setup();
        CHECK(write(rdy[1], "R", 1) == 1, "%s ready", label);
        char c;
        CHECK(read(go[0], &c, 1) == 1, "%s wait", label);
        _exit(0);
    }
    close(rdy[1]);
    close(go[0]);
    char c;
    CHECK(read(rdy[0], &c, 1) == 1, "read %s ready", label);
    close(rdy[0]);
    return (struct paused_child){.pid = pid, .go_fd = go[1]};
}

static void release_child(struct paused_child child, const char *label)
{
    CHECK(write(child.go_fd, "G", 1) == 1, "release %s", label);
    close(child.go_fd);
    wait_ok(child.pid, label);
}

static void check_open_tree_view(int dfd, const char *path, unsigned int flags,
                                 const char *present, const char *absent, const char *label)
{
    int fd = (int)do_open_tree(dfd, path, flags);
    CHECK(fd >= 0, "%s", label);
    CHECK(has_entry(fd, present) && !has_entry(fd, absent),
          "%s: expected %s without %s", label, present, absent);
    close(fd);
}

static void clone_and_attach(int src_dfd, const char *src_path, unsigned int ot_flags,
                             int dst_dfd, const char *dst_path, unsigned int mm_flags,
                             const char *label)
{
    int tfd = (int)do_open_tree(src_dfd, src_path, ot_flags | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    CHECK(tfd >= 0, "open_tree CLONE (%s)", label);
    CHECK(do_move_mount(tfd, "", dst_dfd, dst_path, mm_flags | MOVE_MOUNT_F_EMPTY_PATH) == 0,
          "move_mount (%s)", label);
    close(tfd);
}

static void check_mountinfo(const char *target, const char *root_prefix, const char *must_contain)
{
    FILE *mi = fopen("/proc/self/mountinfo", "r");
    CHECK(mi != NULL, "open mountinfo for %s", target);
    int found = 0;
    char line[512];
    while (fgets(line, sizeof(line), mi)) {
        char root_col[64], mp[128];
        if (sscanf(line, "%*s %*s %*s %63s %127s", root_col, mp) == 2 &&
            strcmp(mp, target) == 0) {
            CHECK(strncmp(root_col, root_prefix, strlen(root_prefix)) == 0,
                  "mountinfo root for %s must start with %s, got %s",
                  target, root_prefix, root_col);
            if (must_contain) {
                CHECK(strstr(line, must_contain) != NULL,
                      "mountinfo for %s missing '%s', got: %s", target, must_contain, line);
            }
            found = 1;
        }
    }
    fclose(mi);
    CHECK(found, "%s not found in mountinfo", target);
}

/* 1. open_tree on overmounted dirfd: AT_EMPTY_PATH, ".", "/", AT_NO_AUTOMOUNT, AT_RECURSIVE */
static void test_open_tree_no_lift(void)
{
    CHECK(mkdir("/tmp/ot_ov", 0755) == 0, "mkdir ot_ov");
    CHECK(mkdir("/tmp/ot_ov_dst", 0755) == 0, "mkdir ot_ov_dst");
    mount_tmpfs("/tmp/ot_ov");
    touch_file("/tmp/ot_ov/under", "u");

    int fd_under = open("/tmp/ot_ov", O_RDONLY | O_DIRECTORY);
    CHECK(fd_under >= 0, "open fd_under");

    /* Overmount /tmp/ot_ov with a second tmpfs */
    mount_tmpfs("/tmp/ot_ov");
    touch_file("/tmp/ot_ov/over", "o");

    /* Plain and CLONE open_tree via AT_EMPTY_PATH and "." stay on under; named lookup lifts */
    check_open_tree_view(fd_under, "", AT_EMPTY_PATH | OPEN_TREE_CLOEXEC,
                         "under", "over", "plain open_tree AT_EMPTY_PATH");
    check_open_tree_view(fd_under, ".", OPEN_TREE_CLOEXEC,
                         "under", "over", "plain open_tree '.'");
    check_open_tree_view(AT_FDCWD, "/tmp/ot_ov", AT_NO_AUTOMOUNT | OPEN_TREE_CLOEXEC,
                         "over", "under", "named lookup with AT_NO_AUTOMOUNT");
    check_open_tree_view(fd_under, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
                         "under", "over", "open_tree CLONE AT_EMPTY_PATH");
    check_open_tree_view(fd_under, ".", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
                         "under", "over", "open_tree CLONE '.'");

    /* AT_FDCWD with "." / "" while cwd is on underlying mount stays on underlying mount */
    pid_t cwd_pid = fork();
    CHECK(cwd_pid >= 0, "fork cwd test");
    if (cwd_pid == 0) {
        CHECK(fchdir(fd_under) == 0, "fchdir fd_under");
        check_open_tree_view(AT_FDCWD, "", AT_EMPTY_PATH | OPEN_TREE_CLONE,
                             "under", "over", "open_tree AT_FDCWD empty");
        check_open_tree_view(AT_FDCWD, ".", OPEN_TREE_CLONE,
                             "under", "over", "open_tree AT_FDCWD '.'");
        _exit(0);
    }
    wait_ok(cwd_pid, "open_tree AT_FDCWD");

    /* Recursive clone of overmounted fd_under includes the overmount on the clone root;
     * move_mount must not lift c_rec to the child overmount so attaching succeeds. */
    int c_rec = (int)do_open_tree(fd_under, "",
                                  AT_EMPTY_PATH | OPEN_TREE_CLONE | AT_RECURSIVE | OPEN_TREE_CLOEXEC);
    CHECK(c_rec >= 0, "open_tree recursive clone of overmounted fd_under");
    CHECK(has_entry(c_rec, "under") && !has_entry(c_rec, "over"),
          "recursive clone fd points at underlying clone root");
    CHECK(do_move_mount(c_rec, "", AT_FDCWD, "/tmp/ot_ov_dst", MOVE_MOUNT_F_EMPTY_PATH) == 0,
          "move_mount recursive clone with overmount on clone root");
    close(c_rec);
    CHECK(access("/tmp/ot_ov_dst/over", F_OK) == 0 && access("/tmp/ot_ov_dst/under", F_OK) != 0,
          "attached recursive clone shows overmount on top");
    CHECK(umount2("/tmp/ot_ov_dst", 0) == 0, "umount copied overmount");
    CHECK(access("/tmp/ot_ov_dst/under", F_OK) == 0,
          "unmounting copied overmount reveals underlying clone");
    CHECK(umount2("/tmp/ot_ov_dst", 0) == 0, "umount underlying clone");

    /* "/" when root itself is overmounted stays on process root mount */
    pid_t root_pid = fork();
    CHECK(root_pid >= 0, "fork root overmount test");
    if (root_pid == 0) {
        CHECK(unshare(CLONE_NEWNS) == 0, "unshare mntns");
        CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "make private");
        CHECK(mkdir("/tmp/root_box", 0755) == 0, "mkdir root_box");
        mount_tmpfs("/tmp/root_box");
        touch_file("/tmp/root_box/root_under", "ru");
        CHECK(chroot("/tmp/root_box") == 0, "chroot");
        CHECK(chdir("/") == 0, "chdir /");
        mount_tmpfs("/");
        int rt = (int)do_open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(rt >= 0, "open_tree '/'");
        CHECK(has_entry(rt, "root_under"), "open_tree '/' must stay on underlying root mount");
        close(rt);
        struct k_mount_attr ma = {.attr_set = MOUNT_ATTR_RDONLY};
        CHECK(do_mount_setattr(AT_FDCWD, "/", 0, &ma) == 0, "mount_setattr '/' RDONLY");
        CHECK_ERR(open("/try_write", O_WRONLY | O_CREAT, 0644), EROFS,
                  "write on underlying '/' after mount_setattr RDONLY must be EROFS");
        _exit(0);
    }
    wait_ok(root_pid, "root overmount '/'");

    close(fd_under);
    CHECK(umount2("/tmp/ot_ov", 0) == 0, "umount over");
    CHECK(umount2("/tmp/ot_ov", 0) == 0, "umount under");
    rmdir("/tmp/ot_ov_dst");
    rmdir("/tmp/ot_ov");
}

/* 2. move_mount and mount_setattr on overmounted dirfds (plain dir vs mount root, target lift, SET_GROUP) */
static void test_move_mount_and_setattr_no_lift(void)
{
    /* 2a. Plain directory (not a mount root) that is later overmounted */
    CHECK(mkdir("/tmp/ov_plain", 0755) == 0, "mkdir ov_plain");
    CHECK(mkdir("/tmp/ov_dst", 0755) == 0, "mkdir ov_dst");
    int fd_plain = open("/tmp/ov_plain", O_RDONLY | O_DIRECTORY);
    CHECK(fd_plain >= 0, "open fd_plain");
    mount_tmpfs("/tmp/ov_plain");
    touch_file("/tmp/ov_plain/top", "t");

    /* move_mount source and mount_setattr must not lift fd_plain to the overmount -> EINVAL */
    CHECK_ERR(do_move_mount(fd_plain, "", AT_FDCWD, "/tmp/ov_dst", MOVE_MOUNT_F_EMPTY_PATH),
              EINVAL, "move_mount F_EMPTY_PATH on overmounted plain dir must be EINVAL");
    CHECK_ERR(do_move_mount(fd_plain, ".", AT_FDCWD, "/tmp/ov_dst", 0),
              EINVAL, "move_mount '.' on overmounted plain dir must be EINVAL");
    struct k_mount_attr ma_ro = {.attr_set = MOUNT_ATTR_RDONLY};
    CHECK_ERR(do_mount_setattr(fd_plain, "", AT_EMPTY_PATH, &ma_ro),
              EINVAL, "mount_setattr AT_EMPTY_PATH on overmounted plain dir must be EINVAL");
    CHECK_ERR(do_mount_setattr(fd_plain, ".", 0, &ma_ro),
              EINVAL, "mount_setattr '.' on overmounted plain dir must be EINVAL");

    /* move_mount TARGET (T_EMPTY_PATH) DOES lift (lock_mount) to stack on top of overmount */
    CHECK(mkdir("/tmp/ov_src3", 0755) == 0, "mkdir ov_src3");
    mount_tmpfs("/tmp/ov_src3");
    touch_file("/tmp/ov_src3/third", "3");
    clone_and_attach(AT_FDCWD, "/tmp/ov_src3", 0, fd_plain, "", MOVE_MOUNT_T_EMPTY_PATH,
                     "stack third on overmounted fd_plain");
    CHECK(access("/tmp/ov_plain/third", F_OK) == 0 && access("/tmp/ov_plain/top", F_OK) != 0,
          "third mount must be topmost on /tmp/ov_plain");
    CHECK(umount2("/tmp/ov_plain", 0) == 0, "umount third");
    CHECK(access("/tmp/ov_plain/top", F_OK) == 0,
          "unmounting third reveals second (properly stacked)");
    CHECK(umount2("/tmp/ov_plain", 0) == 0, "umount second");
    CHECK(umount2("/tmp/ov_src3", 0) == 0, "umount ov_src3");
    close(fd_plain);
    rmdir("/tmp/ov_src3");
    rmdir("/tmp/ov_plain");

    /* 2b. Mount root A overmounted by B: mount_setattr, move_mount, and MOVE_MOUNT_SET_GROUP */
    CHECK(mkdir("/tmp/ov_ab", 0755) == 0, "mkdir ov_ab");
    mount_tmpfs("/tmp/ov_ab");
    CHECK(mount(NULL, "/tmp/ov_ab", NULL, MS_PRIVATE, NULL) == 0, "make A private");
    touch_file("/tmp/ov_ab/in_a", "a");
    int fd_a = open("/tmp/ov_ab", O_RDONLY | O_DIRECTORY);
    CHECK(fd_a >= 0, "open fd_a");

    mount_tmpfs("/tmp/ov_ab");
    touch_file("/tmp/ov_ab/in_b", "b");

    /* mount_setattr(fd_a, "", AT_EMPTY_PATH, RDONLY) makes A read-only while B stays writable */
    CHECK(do_mount_setattr(fd_a, "", AT_EMPTY_PATH, &ma_ro) == 0, "mount_setattr fd_a RDONLY");
    CHECK_ERR(openat(fd_a, "w_a", O_WRONLY | O_CREAT, 0644), EROFS,
              "A must be read-only after mount_setattr(fd_a, empty)");
    int wb = open("/tmp/ov_ab/w_b", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(wb >= 0, "B must remain writable after mount_setattr(fd_a, empty)");
    close(wb);

    /* mount_setattr(fd_a, ".", 0, clear RDONLY) restores A to writable */
    struct k_mount_attr ma_rw = {.attr_clr = MOUNT_ATTR_RDONLY};
    CHECK(do_mount_setattr(fd_a, ".", 0, &ma_rw) == 0, "mount_setattr fd_a '.' RW");
    int wa = openat(fd_a, "w_a2", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(wa >= 0, "A must be writable again after mount_setattr(fd_a, '.')");
    close(wa);

    /* MOVE_MOUNT_SET_GROUP on overmounted fd_a targets A (not B) */
    CHECK(mkdir("/tmp/ov_ab_peer", 0755) == 0, "mkdir ov_ab_peer");
    CHECK(mkdirat(fd_a, "sub", 0755) == 0, "mkdir A/sub");
    clone_and_attach(fd_a, "", AT_EMPTY_PATH, AT_FDCWD, "/tmp/ov_ab_peer", 0, "attach A peer");
    CHECK(mount(NULL, "/tmp/ov_ab_peer", NULL, MS_SHARED, NULL) == 0, "make peer shared");
    /* If SET_GROUP wrongly lifted fd_a to B (different tmpfs superblock), it would fail EINVAL. */
    CHECK(do_move_mount(AT_FDCWD, "/tmp/ov_ab_peer", fd_a, "",
                        MOVE_MOUNT_T_EMPTY_PATH | MOVE_MOUNT_SET_GROUP) == 0,
          "SET_GROUP on overmounted fd_a must target A, not B");
    mount_tmpfs("/tmp/ov_ab_peer/sub");
    touch_file("/tmp/ov_ab_peer/sub/prop", "p");
    CHECK(has_entry(fd_a, "sub/prop"), "submount must propagate to underlying mount A");
    CHECK(umount2("/tmp/ov_ab_peer/sub", 0) == 0, "umount peer/sub");
    CHECK(umount2("/tmp/ov_ab_peer", 0) == 0, "umount peer");
    rmdir("/tmp/ov_ab_peer");

    /* move_mount(fd_a, "", AT_FDCWD, "/tmp/ov_dst", F_EMPTY_PATH) moves A with B riding on top */
    CHECK(do_move_mount(fd_a, "", AT_FDCWD, "/tmp/ov_dst", MOVE_MOUNT_F_EMPTY_PATH) == 0,
          "move_mount fd_a must move A (carrying B)");
    close(fd_a);
    CHECK(access("/tmp/ov_ab/in_a", F_OK) != 0 && access("/tmp/ov_ab/in_b", F_OK) != 0,
          "/tmp/ov_ab must be empty after moving A+B");
    CHECK(access("/tmp/ov_dst/in_b", F_OK) == 0, "/tmp/ov_dst must show B on top");
    CHECK(umount2("/tmp/ov_dst", 0) == 0, "umount B from ov_dst");
    CHECK(access("/tmp/ov_dst/in_a", F_OK) == 0,
          "unmounting B from ov_dst must reveal A underneath");
    CHECK(umount2("/tmp/ov_dst", 0) == 0, "umount A from ov_dst");

    rmdir("/tmp/ov_ab");
    rmdir("/tmp/ov_dst");
}

static void setup_four_ns_child(void)
{
    CHECK(unshare(CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS) == 0, "child unshare");
    CHECK(sethostname("ot-pinned", 9) == 0, "sethostname");
    CHECK(shmget(0x6162, 4096, IPC_CREAT | IPC_EXCL | 0600) >= 0, "shmget");
    mount_tmpfs("/tmp/ns_mnt_dir");
    touch_file("/tmp/ns_mnt_dir/secret", "ok");
}

/* 3a. open_tree(OPEN_TREE_CLONE) + move_mount pins net/uts/ipc/mnt namespaces across exit */
static void test_open_tree_nsfs_pinning(void)
{
    const char *kinds[4] = {"net", "uts", "ipc", "mnt"};
    for (int i = 0; i < 4; i++) {
        char p[64];
        snprintf(p, sizeof(p), "/tmp/ns_pin/%s", kinds[i]);
        touch_file(p, "");
    }
    touch_file("/tmp/ns_pin/uts_reclone", "");
    touch_file("/tmp/ns_pin/uts_from_fd", "");

    struct paused_child child = spawn_paused(setup_four_ns_child, "ns holder");

    int tfds[4];
    ino_t child_inos[4];
    for (int i = 0; i < 4; i++) {
        char p[64];
        snprintf(p, sizeof(p), "/proc/%d/ns/%s", (int)child.pid, kinds[i]);
        struct stat st;
        CHECK(stat(p, &st) == 0, "stat %s", p);
        child_inos[i] = st.st_ino;
        tfds[i] = (int)do_open_tree(AT_FDCWD, p, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(tfds[i] >= 0, "open_tree CLONE %s", p);
    }
    char uts_proc[64];
    snprintf(uts_proc, sizeof(uts_proc), "/proc/%d/ns/uts", (int)child.pid);
    int uts_nsfd = open(uts_proc, O_RDONLY | O_CLOEXEC);
    CHECK(uts_nsfd >= 0, "open uts_nsfd");

    /* Child exits and is reaped BEFORE move_mount: unattached clones must pin the namespaces */
    release_child(child, "ns holder");

    for (int i = 0; i < 4; i++) {
        char dst[64];
        snprintf(dst, sizeof(dst), "/tmp/ns_pin/%s", kinds[i]);
        CHECK(do_move_mount(tfds[i], "", AT_FDCWD, dst, MOVE_MOUNT_F_EMPTY_PATH) == 0,
              "move_mount %s", dst);
        close(tfds[i]);
    }

    struct stat own_net, pin_net;
    CHECK(stat("/proc/self/ns/net", &own_net) == 0, "stat own net");
    CHECK(stat("/tmp/ns_pin/net", &pin_net) == 0, "stat pin net");
    CHECK(pin_net.st_dev == own_net.st_dev, "pin net st_dev must match nsfs st_dev");
    CHECK(pin_net.st_ino == child_inos[0], "pin net st_ino must match child's netns");
    check_mountinfo("/tmp/ns_pin/net", "net:[", " - nsfs nsfs ");

    /* Clone from an open nsfd (AT_EMPTY_PATH) and from an existing attached nsfs bind mount */
    clone_and_attach(uts_nsfd, "", AT_EMPTY_PATH, AT_FDCWD, "/tmp/ns_pin/uts_from_fd", 0,
                     "clone from open nsfd");
    close(uts_nsfd);
    clone_and_attach(AT_FDCWD, "/tmp/ns_pin/uts", 0, AT_FDCWD, "/tmp/ns_pin/uts_reclone", 0,
                     "reclone attached nsfs mount");
    CHECK(umount2("/tmp/ns_pin/uts", 0) == 0, "umount original uts pin");

    /* Enter every pinned namespace in a fresh child via setns and verify state survived exit */
    pid_t enter = fork();
    CHECK(enter >= 0, "fork setns verifier");
    if (enter == 0) {
        int fd_net = open("/tmp/ns_pin/net", O_RDONLY);
        int fd_uts = open("/tmp/ns_pin/uts_reclone", O_RDONLY);
        int fd_uts2 = open("/tmp/ns_pin/uts_from_fd", O_RDONLY);
        int fd_ipc = open("/tmp/ns_pin/ipc", O_RDONLY);
        int fd_mnt = open("/tmp/ns_pin/mnt", O_RDONLY);
        CHECK(fd_net >= 0 && fd_uts >= 0 && fd_uts2 >= 0 && fd_ipc >= 0 && fd_mnt >= 0,
              "open pinned ns files");
        CHECK(setns(fd_net, CLONE_NEWNET) == 0, "setns net");
        struct stat cur_net;
        CHECK(stat("/proc/self/ns/net", &cur_net) == 0 && cur_net.st_ino == child_inos[0],
              "entered netns inode mismatch");

        CHECK(setns(fd_uts, CLONE_NEWUTS) == 0, "setns uts_reclone");
        char host[64] = "";
        CHECK(gethostname(host, sizeof(host)) == 0 && strcmp(host, "ot-pinned") == 0,
              "entered utsns hostname mismatch: %s", host);
        CHECK(setns(fd_uts2, CLONE_NEWUTS) == 0, "setns uts_from_fd");

        CHECK(setns(fd_ipc, CLONE_NEWIPC) == 0, "setns ipc");
        CHECK(shmget(0x6162, 0, 0) >= 0, "pinned ipc shm segment missing");

        CHECK(setns(fd_mnt, CLONE_NEWNS) == 0, "setns mnt");
        CHECK(access("/tmp/ns_mnt_dir/secret", F_OK) == 0, "pinned mntns file missing");

        close(fd_net);
        close(fd_uts);
        close(fd_uts2);
        close(fd_ipc);
        close(fd_mnt);
        _exit(0);
    }
    wait_ok(enter, "setns pinned namespaces");

    CHECK(umount2("/tmp/ns_pin/net", 0) == 0, "umount net");
    CHECK(umount2("/tmp/ns_pin/ipc", 0) == 0, "umount ipc");
    CHECK(umount2("/tmp/ns_pin/mnt", 0) == 0, "umount mnt");
    CHECK(umount2("/tmp/ns_pin/uts_reclone", 0) == 0, "umount uts_reclone");
    CHECK(umount2("/tmp/ns_pin/uts_from_fd", 0) == 0, "umount uts_from_fd");
}

static void setup_unshare_mnt_child(void)
{
    CHECK(unshare(CLONE_NEWNS) == 0, "peer child unshare");
}

/* 3b. mnt_ns_loop checks in move_mount (self, older parent, and shared propagation cycle) */
static void test_open_tree_mnt_ns_loop(void)
{
    /* (a) open_tree(CLONE) of own /proc/self/ns/mnt succeeds, but move_mount into own ns -> EINVAL */
    touch_file("/tmp/ns_pin/loop_self", "");
    int t_self = (int)do_open_tree(AT_FDCWD, "/proc/self/ns/mnt",
                                   OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    CHECK(t_self >= 0, "open_tree CLONE /proc/self/ns/mnt");
    CHECK_ERR(do_move_mount(t_self, "", AT_FDCWD, "/tmp/ns_pin/loop_self",
                            MOVE_MOUNT_F_EMPTY_PATH),
              EINVAL, "move_mount of self mntns must fail with EINVAL (mnt_ns_loop)");
    close(t_self);

    /* (b) Child in newer mntns cannot attach parent's older mntns via open_tree + move_mount */
    pid_t parent_pid = getpid();
    pid_t newer = fork();
    CHECK(newer >= 0, "fork newer mntns");
    if (newer == 0) {
        CHECK(unshare(CLONE_NEWNS) == 0, "child unshare mntns");
        char pp[64];
        snprintf(pp, sizeof(pp), "/proc/%d/ns/mnt", (int)parent_pid);
        int t_old = (int)do_open_tree(AT_FDCWD, pp, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        CHECK(t_old >= 0, "open_tree CLONE parent mntns");
        touch_file("/tmp/ns_pin/loop_old", "");
        CHECK_ERR(do_move_mount(t_old, "", AT_FDCWD, "/tmp/ns_pin/loop_old",
                                MOVE_MOUNT_F_EMPTY_PATH),
                  EINVAL, "move_mount of older mntns into newer mntns must be EINVAL");
        close(t_old);
        _exit(0);
    }
    wait_ok(newer, "newer mntns loop check");

    /* (c) Attaching a child's mntns onto a shared mount propagating back into that child -> EINVAL */
    CHECK(mkdir("/tmp/ns_shared", 0755) == 0, "mkdir ns_shared");
    mount_tmpfs("/tmp/ns_shared");
    CHECK(mount(NULL, "/tmp/ns_shared", NULL, MS_SHARED, NULL) == 0, "make ns_shared shared");
    touch_file("/tmp/ns_shared/pin", "");

    struct paused_child peer = spawn_paused(setup_unshare_mnt_child, "shared peer");
    char peer_mnt[64];
    snprintf(peer_mnt, sizeof(peer_mnt), "/proc/%d/ns/mnt", (int)peer.pid);
    int t_peer_mnt = (int)do_open_tree(AT_FDCWD, peer_mnt, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    CHECK(t_peer_mnt >= 0, "open_tree CLONE peer_child mntns");
    CHECK_ERR(do_move_mount(t_peer_mnt, "", AT_FDCWD, "/tmp/ns_shared/pin",
                            MOVE_MOUNT_F_EMPTY_PATH),
              EINVAL, "move_mount of child mntns propagating back to child must be EINVAL");
    close(t_peer_mnt);
    release_child(peer, "shared peer");
    CHECK(umount2("/tmp/ns_shared", 0) == 0, "umount ns_shared");
    rmdir("/tmp/ns_shared");
}

static void setup_user_uts_child(void)
{
    CHECK(unshare(CLONE_NEWUSER | CLONE_NEWUTS) == 0, "unshare user+uts");
    touch_file("/proc/self/setgroups", "deny");
    touch_file("/proc/self/uid_map", "0 0 1\n");
    touch_file("/proc/self/gid_map", "0 0 1\n");
}

/* 3c. NS_GET_USERNS from an attached Fs::Nsfs mount reuses its mount id with a different NsFile */
static void test_open_tree_derived_userns(void)
{
    touch_file("/tmp/ns_pin/u_uts", "");
    touch_file("/tmp/ns_pin/u_user", "");

    struct paused_child uchild = spawn_paused(setup_user_uts_child, "userns child");
    char u_uts_p[64], u_user_p[64];
    snprintf(u_uts_p, sizeof(u_uts_p), "/proc/%d/ns/uts", (int)uchild.pid);
    snprintf(u_user_p, sizeof(u_user_p), "/proc/%d/ns/user", (int)uchild.pid);
    struct stat want_user_st;
    CHECK(stat(u_user_p, &want_user_st) == 0, "stat child userns");
    clone_and_attach(AT_FDCWD, u_uts_p, 0, AT_FDCWD, "/tmp/ns_pin/u_uts", 0, "attach u_uts");
    release_child(uchild, "userns child");

    int attached_uts_fd = open("/tmp/ns_pin/u_uts", O_RDONLY | O_CLOEXEC);
    CHECK(attached_uts_fd >= 0, "open attached u_uts");
    int derived_user_fd = ioctl(attached_uts_fd, NS_GET_USERNS);
    CHECK(derived_user_fd >= 0, "ioctl NS_GET_USERNS on attached nsfs mount");
    close(attached_uts_fd);

    /* Plain open_tree on derived_user_fd keeps `user:[...]` fd link name */
    int plain_user = (int)do_open_tree(derived_user_fd, "", AT_EMPTY_PATH | OPEN_TREE_CLOEXEC);
    CHECK(plain_user >= 0, "plain open_tree on NS_GET_USERNS fd");
    char fdlink_path[64], fdlink_val[64];
    snprintf(fdlink_path, sizeof(fdlink_path), "/proc/self/fd/%d", plain_user);
    ssize_t nlink = readlink(fdlink_path, fdlink_val, sizeof(fdlink_val) - 1);
    CHECK(nlink > 0, "readlink plain_user");
    fdlink_val[nlink] = '\0';
    CHECK(strncmp(fdlink_val, "user:[", 6) == 0,
          "plain open_tree on NS_GET_USERNS fd must have user:[...] path, got %s", fdlink_val);
    close(plain_user);

    /* Clone derived_user_fd and attach it; unmount u_uts so only u_user pins the userns */
    clone_and_attach(derived_user_fd, "", AT_EMPTY_PATH, AT_FDCWD, "/tmp/ns_pin/u_user", 0,
                     "clone derived userns");
    close(derived_user_fd);
    CHECK(umount2("/tmp/ns_pin/u_uts", 0) == 0, "umount u_uts");

    check_mountinfo("/tmp/ns_pin/u_user", "user:[", " - nsfs nsfs ");

    pid_t ucheck = fork();
    CHECK(ucheck >= 0, "fork userns setns check");
    if (ucheck == 0) {
        int ufd = open("/tmp/ns_pin/u_user", O_RDONLY);
        CHECK(ufd >= 0, "open u_user");
        struct stat st;
        CHECK(fstat(ufd, &st) == 0 && st.st_ino == want_user_st.st_ino,
              "u_user inode mismatch");
        CHECK(setns(ufd, CLONE_NEWUSER) == 0, "setns derived userns");
        close(ufd);
        _exit(0);
    }
    wait_ok(ucheck, "setns derived userns");
    CHECK(umount2("/tmp/ns_pin/u_user", 0) == 0, "umount u_user");
}

int main(void)
{
    CHECK(mkdir("/tmp", 01777) == 0 || errno == EEXIST, "mkdir /tmp");

    test_open_tree_no_lift();
    test_move_mount_and_setattr_no_lift();

    CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0, "make / private");
    CHECK(mkdir("/tmp/ns_pin", 0755) == 0, "mkdir ns_pin");
    CHECK(mkdir("/tmp/ns_mnt_dir", 0755) == 0, "mkdir ns_mnt_dir");
    test_open_tree_nsfs_pinning();
    test_open_tree_mnt_ns_loop();
    test_open_tree_derived_userns();

    printf("all ok\n");
    return 0;
}
