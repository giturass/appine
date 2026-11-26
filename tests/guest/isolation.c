/*
 * Regression tests for kernel namespace isolation, credentials and PID-reuse fixes:
 * - /proc/<pid>/pagemap pins Mm at open (returns EOF after execve instead of reading new image);
 * - /proc/<pid>/task/<tid>/fd and fdinfo show the thread's own fd table and keep task/<tid> parent;
 * - held /proc/<pid> dirfd and unread /proc/<pid>/status reject reaped process (ENOENT/ESRCH) and
 *   never follow a new process that reuses the same PID;
 * - /proc/sysvipc/{msg,shm} translate PIDs into the reader's pidns and expose SHM_LOCKED (02000);
 * - mq_notify does not signal or block (EBUSY) a new process reusing an exited registrant's TGID;
 * - setns into a foreign user namespace clears dumpable and pdeathsig (while owner keeps them);
 * - access(2) honours SECBIT_NO_SETUID_FIXUP;
 * - pidfd setns combining CLONE_NEWNS with another ns while sharing CLONE_FS switches only caller;
 * - /sys/class/net/lo/statistics and tx_queue_len do not leak init netns values into new netns;
 * - FUSE mknod runs cgroup device BPF filter and does not exempt block 0:0 (only char 0:0 whiteout).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
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

#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 28
#endif
#ifndef SECBIT_NO_SETUID_FIXUP
#define SECBIT_NO_SETUID_FIXUP (1 << 2)
#endif
#ifndef SECBIT_KEEP_CAPS
#define SECBIT_KEEP_CAPS (1 << 4)
#endif

static void write_file_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    CHECK(fd >= 0, "open %s for write", path);
    ssize_t n = write(fd, s, strlen(s));
    CHECK(n == (ssize_t)strlen(s), "write %s", path);
    close(fd);
}

static void read_file_str(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s for read", path);
    ssize_t n = read(fd, buf, cap - 1);
    CHECK(n >= 0, "read %s", path);
    buf[n] = '\0';
    close(fd);
}

static void read_link_str(const char *path, char *buf, size_t cap)
{
    ssize_t n = readlink(path, buf, cap - 1);
    CHECK(n > 0, "readlink %s", path);
    buf[n] = '\0';
}

static void set_next_pid(pid_t target)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%d\n", target - 1);
    write_file_str("/proc/sys/kernel/ns_last_pid", buf);
}

static void wait_ok(pid_t pid, const char *label)
{
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid %s", label);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "%s exited abnormally (status=0x%x)", label, st);
}

/* 1. /proc/<pid>/pagemap pins Mm at open (EOF after execve) */
static void test_pagemap_pins_mm(const char *self_path)
{
    int go[2], ready[2];
    CHECK(pipe(go) == 0 && pipe(ready) == 0, "pipe");
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(go[1]);
        close(ready[0]);
        char c = '1';
        CHECK(write(ready[1], &c, 1) == 1, "child ready");
        close(ready[1]);
        CHECK(read(go[0], &c, 1) == 1, "child go");
        close(go[0]);
        char *argv[] = {(char *)self_path, "--exit-ok", NULL};
        execv(self_path, argv);
        _exit(99);
    }
    close(go[0]);
    close(ready[1]);
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "parent ready");
    close(ready[0]);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
    int pm = open(path, O_RDONLY);
    CHECK(pm >= 0, "open %s", path);
    uint64_t entry = 0;
    CHECK(pread(pm, &entry, sizeof(entry), 0) == (ssize_t)sizeof(entry), "initial pagemap read");

    /* Let child exec into a new Mm and wait until it exits */
    CHECK(write(go[1], "g", 1) == 1, "signal exec");
    close(go[1]);
    wait_ok(pid, "pagemap child");

    /* Old Mm was released at exec/exit: pinned pagemap fd must return EOF (0) */
    CHECK(pread(pm, &entry, sizeof(entry), 0) == 0, "pagemap after exec/exit must be EOF");
    close(pm);
}

/* 2. /proc/<pid>/task/<tid>/fd and fdinfo show the thread's own fd table */
struct fd_thread_args {
    int ready_fd;
    int done_fd;
    pid_t tid;
};

static void *per_thread_fd_worker(void *arg)
{
    struct fd_thread_args *a = arg;
    CHECK(unshare(CLONE_FILES) == 0, "thread unshare(CLONE_FILES)");
    int p[2];
    CHECK(pipe(p) == 0, "thread pipe");
    CHECK(dup2(p[0], 77) == 77, "dup2 to 77");
    close(p[0]);
    close(p[1]);
    a->tid = (pid_t)syscall(SYS_gettid);
    char c = '1';
    CHECK(write(a->ready_fd, &c, 1) == 1, "thread ready");
    CHECK(read(a->done_fd, &c, 1) == 1, "thread wait done");
    close(77);
    return NULL;
}

static void test_task_per_thread_fd(void)
{
    int ready[2], done[2];
    CHECK(pipe(ready) == 0 && pipe(done) == 0, "pipe");
    struct fd_thread_args args = {.ready_fd = ready[1], .done_fd = done[0], .tid = 0};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, per_thread_fd_worker, &args) == 0, "pthread_create");

    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait thread ready");

    /* Main process fd table must NOT have fd 77 */
    char path[128], linkbuf[128], info[256];
    snprintf(path, sizeof(path), "/proc/%d/fd/77", getpid());
    errno = 0;
    CHECK(readlink(path, linkbuf, sizeof(linkbuf) - 1) < 0 && errno == ENOENT,
          "leader /proc/pid/fd/77 must not exist");

    /* Thread's task/<tid>/fd/77 and fdinfo/77 MUST exist */
    snprintf(path, sizeof(path), "/proc/%d/task/%d/fd/77", getpid(), args.tid);
    read_link_str(path, linkbuf, sizeof(linkbuf));
    CHECK(strncmp(linkbuf, "pipe:[", 6) == 0, "expected pipe link, got %s", linkbuf);

    snprintf(path, sizeof(path), "/proc/%d/task/%d/fdinfo/77", getpid(), args.tid);
    read_file_str(path, info, sizeof(info));
    CHECK(strstr(info, "pos:\t") != NULL, "fdinfo missing pos: %s", info);

    /* Listing task/<tid>/fd must include "77" */
    snprintf(path, sizeof(path), "/proc/%d/task/%d/fd", getpid(), args.tid);
    DIR *d = opendir(path);
    CHECK(d != NULL, "opendir %s", path);
    int found77 = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, "77") == 0)
            found77 = 1;
    }
    closedir(d);
    CHECK(found77, "readdir %s did not list 77", path);

    CHECK(write(done[1], "x", 1) == 1, "signal thread done");
    CHECK(pthread_join(th, NULL) == 0, "pthread_join");
    close(ready[0]);
    close(ready[1]);
    close(done[0]);
    close(done[1]);
}

/* 3. Held /proc/<pid> dirfd and unread /proc/<pid>/status across reap and PID reuse */
static void test_reaped_proc_pid_reuse(void)
{
    int go[2];
    CHECK(pipe(go) == 0, "pipe");
    pid_t pid_a = fork();
    CHECK(pid_a >= 0, "fork A");
    if (pid_a == 0) {
        close(go[1]);
        char c;
        (void)read(go[0], &c, 1);
        _exit(0);
    }
    close(go[0]);

    char pdir[64], pstat[64];
    snprintf(pdir, sizeof(pdir), "/proc/%d", pid_a);
    snprintf(pstat, sizeof(pstat), "/proc/%d/status", pid_a);
    int dirfd = open(pdir, O_RDONLY | O_DIRECTORY);
    int statfd = open(pstat, O_RDONLY);
    CHECK(dirfd >= 0 && statfd >= 0, "open %s / %s", pdir, pstat);

    /* Let A exit and reap it */
    close(go[1]);
    wait_ok(pid_a, "child A");

    /* First read on unread statfd must fail with ESRCH (not return cached open snapshot) */
    char buf[512];
    errno = 0;
    CHECK(read(statfd, buf, sizeof(buf)) < 0 && errno == ESRCH,
          "first read of reaped status expected ESRCH");

    /* Listing held dirfd must fail with ENOENT */
    errno = 0;
    CHECK(syscall(SYS_getdents64, dirfd, buf, sizeof(buf)) < 0 && errno == ENOENT,
          "getdents64 on reaped /proc/pid expected ENOENT");

    /* Lookup through held dirfd must fail with ENOENT */
    errno = 0;
    CHECK(openat(dirfd, "status", O_RDONLY) < 0 && errno == ENOENT,
          "openat on reaped /proc/pid expected ENOENT");

    /* Reuse the exact same PID for child B */
    int go_b[2];
    CHECK(pipe(go_b) == 0, "pipe B");
    set_next_pid(pid_a);
    pid_t pid_b = fork();
    CHECK(pid_b >= 0, "fork B");
    if (pid_b == 0) {
        close(go_b[1]);
        char c;
        (void)read(go_b[0], &c, 1);
        _exit(0);
    }
    close(go_b[0]);
    CHECK(pid_b == pid_a, "expected pid reuse %d, got %d", pid_a, pid_b);

    /* Held dirfd and statfd from A must NEVER see B */
    errno = 0;
    CHECK(openat(dirfd, "status", O_RDONLY) < 0 && errno == ENOENT,
          "openat on old dirfd saw reused pid B");
    errno = 0;
    CHECK(syscall(SYS_getdents64, dirfd, buf, sizeof(buf)) < 0 && errno == ENOENT,
          "getdents64 on old dirfd saw reused pid B");
    errno = 0;
    CHECK(pread(statfd, buf, sizeof(buf), 0) < 0 && errno == ESRCH,
          "pread on old statfd saw reused pid B");

    /* Fresh lookup of /proc/<pid_b>/status must succeed */
    read_file_str(pstat, buf, sizeof(buf));
    CHECK(strstr(buf, "Tgid:") != NULL, "fresh status of B failed");

    close(dirfd);
    close(statfd);
    close(go_b[1]);
    wait_ok(pid_b, "child B");
}

/* 4. /proc/sysvipc/{msg,shm} PID translation and SHM_LOCKED */
static void test_sysvipc_pidns_and_shm_locked(void)
{
    int parent_shm = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    CHECK(parent_shm >= 0, "parent shmget");

    pid_t pid = fork();
    CHECK(pid >= 0, "fork pidns outer");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWPID) == 0, "unshare(CLONE_NEWPID)");
        pid_t inner = fork();
        CHECK(inner >= 0, "fork pidns inner");
        if (inner == 0) {
            CHECK(getpid() == 1, "expected pid 1 in child pidns, got %d", getpid());
            int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
            CHECK(shmid >= 0, "child shmget");
            CHECK(shmctl(shmid, SHM_LOCK, NULL) == 0, "SHM_LOCK");

            int msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
            CHECK(msqid >= 0, "child msgget");
            struct {
                long mtype;
                char text[4];
            } m = {.mtype = 1, .text = "hi"};
            CHECK(msgsnd(msqid, &m, 2, 0) == 0, "msgsnd");

            char buf[4096];
            read_file_str("/proc/sysvipc/shm", buf, sizeof(buf));
            int saw_child = 0, saw_parent = 0;
            char *line = strtok(buf, "\n");
            while ((line = strtok(NULL, "\n")) != NULL) {
                int key, id, perms, cpid, lpid;
                unsigned long size;
                if (sscanf(line, "%d %d %o %lu %d %d", &key, &id, &perms, &size, &cpid, &lpid)
                    == 6) {
                    if (id == shmid) {
                        CHECK(perms == 02600, "expected shm perms 02600 (SHM_LOCKED), got %o",
                              perms);
                        CHECK(cpid == 1, "expected child shm cpid 1, got %d", cpid);
                        saw_child = 1;
                    } else if (id == parent_shm) {
                        CHECK(cpid == 0, "expected parent shm cpid 0 in child pidns, got %d", cpid);
                        saw_parent = 1;
                    }
                }
            }
            CHECK(saw_child && saw_parent, "missing shm rows (child=%d parent=%d)", saw_child,
                  saw_parent);

            read_file_str("/proc/sysvipc/msg", buf, sizeof(buf));
            int saw_msg = 0;
            line = strtok(buf, "\n");
            while ((line = strtok(NULL, "\n")) != NULL) {
                int key, id, perms, lspid, lrpid;
                unsigned long cbytes, qnum;
                if (sscanf(line, "%d %d %o %lu %lu %d %d", &key, &id, &perms, &cbytes, &qnum,
                           &lspid, &lrpid)
                    == 7) {
                    if (id == msqid) {
                        CHECK(lspid == 1, "expected msg lspid 1, got %d", lspid);
                        saw_msg = 1;
                    }
                }
            }
            CHECK(saw_msg, "missing msg row");

            CHECK(shmctl(shmid, IPC_RMID, NULL) == 0, "shmctl RMID");
            CHECK(msgctl(msqid, IPC_RMID, NULL) == 0, "msgctl RMID");
            _exit(0);
        }
        wait_ok(inner, "sysvipc inner");
        _exit(0);
    }
    wait_ok(pid, "sysvipc outer");
    CHECK(shmctl(parent_shm, IPC_RMID, NULL) == 0, "parent shmctl RMID");
}

/* 5. mq_notify does not signal or block a new process reusing an exited registrant's TGID */
static volatile sig_atomic_t mq_got_usr1 = 0;
static void mq_usr1_handler(int sig)
{
    (void)sig;
    mq_got_usr1++;
}

struct raw_sigevent {
    uint64_t value;
    int32_t signo;
    int32_t notify;
    uint8_t pad[48];
};

static void test_mq_notify_reused_tgid(void)
{
    const char *q1_name = "/appine_iso_q1";
    const char *q2_name = "/appine_iso_q2";
    syscall(SYS_mq_unlink, q1_name);
    syscall(SYS_mq_unlink, q2_name);

    int q1 = (int)syscall(SYS_mq_open, q1_name, O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
    int q2 = (int)syscall(SYS_mq_open, q2_name, O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
    CHECK(q1 >= 0 && q2 >= 0, "mq_open");

    /* Fork child A sharing the fd table (CLONE_FILES) so its exit does not drop the fd table */
    pid_t pid_a = (pid_t)syscall(SYS_clone, (unsigned long)(CLONE_FILES | SIGCHLD), 0, 0, 0, 0);
    CHECK(pid_a >= 0, "clone CLONE_FILES");
    if (pid_a == 0) {
        struct raw_sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.signo = SIGUSR1;
        sev.notify = 0; /* SIGEV_SIGNAL */
        CHECK(syscall(SYS_mq_notify, q1, &sev) == 0, "A mq_notify q1");
        CHECK(syscall(SYS_mq_notify, q2, &sev) == 0, "A mq_notify q2");
        _exit(0);
    }
    wait_ok(pid_a, "mq registrant A");

    /* Reuse A's exact TGID for child B */
    int ready[2], go[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0, "pipe");
    set_next_pid(pid_a);
    pid_t pid_b = fork();
    CHECK(pid_b >= 0, "fork B");
    if (pid_b == 0) {
        close(ready[0]);
        close(go[1]);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = mq_usr1_handler;
        CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");

        /* Registering on q2 must succeed (A is dead, even though B has A's tgid) */
        struct raw_sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.signo = SIGUSR1;
        sev.notify = 0;
        CHECK(syscall(SYS_mq_notify, q2, &sev) == 0, "B mq_notify q2 must not EBUSY");

        char c = 'r';
        CHECK(write(ready[1], &c, 1) == 1, "B ready");
        CHECK(read(go[0], &c, 1) == 1, "B wait");
        /* Sending on q1 must NOT have delivered SIGUSR1 to B */
        CHECK(mq_got_usr1 == 0, "B received stale SIGUSR1 from A's mq_notify");
        _exit(0);
    }
    close(ready[1]);
    close(go[0]);
    CHECK(pid_b == pid_a, "expected mq pid reuse %d, got %d", pid_a, pid_b);

    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait B ready");
    CHECK(syscall(SYS_mq_timedsend, q1, "msg", 3, 0, NULL) == 0, "mq_timedsend q1");
    CHECK(write(go[1], "g", 1) == 1, "release B");
    close(ready[0]);
    close(go[1]);
    wait_ok(pid_b, "mq child B");

    close(q1);
    close(q2);
    syscall(SYS_mq_unlink, q1_name);
    syscall(SYS_mq_unlink, q2_name);
}

/* 6. setns into foreign userns clears dumpable and pdeathsig (while owner keeps them) */
static void test_setns_foreign_userns_dumpable(void)
{
    int ready[2], done[2];
    CHECK(pipe(ready) == 0 && pipe(done) == 0, "pipe");
    pid_t holder = fork();
    CHECK(holder >= 0, "fork userns holder");
    if (holder == 0) {
        close(ready[0]);
        close(done[1]);
        CHECK(setresgid(1000, 1000, 1000) == 0, "setresgid 1000");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid 1000");
        CHECK(unshare(CLONE_NEWUSER) == 0, "holder unshare(CLONE_NEWUSER)");
        char c = '1';
        CHECK(write(ready[1], &c, 1) == 1, "holder ready");
        (void)read(done[0], &c, 1);
        _exit(0);
    }
    close(ready[1]);
    close(done[0]);
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait holder ready");
    close(ready[0]);

    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/user", holder);
    int nsfd = open(ns_path, O_RDONLY);
    CHECK(nsfd >= 0, "open %s", ns_path);

    /* Case A: root (euid 0) enters foreign uid-1000 userns -> dumpable & pdeathsig cleared */
    pid_t foreign = fork();
    CHECK(foreign >= 0, "fork foreign");
    if (foreign == 0) {
        CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0, "PR_SET_DUMPABLE");
        CHECK(prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == 0, "PR_SET_PDEATHSIG");
        CHECK(syscall(SYS_setns, nsfd, CLONE_NEWUSER) == 0, "foreign setns");
        int dump = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        int pdeath = -1;
        CHECK(prctl(PR_GET_PDEATHSIG, &pdeath, 0, 0, 0) == 0, "PR_GET_PDEATHSIG");
        CHECK(dump == 0, "foreign setns kept dumpable=%d", dump);
        CHECK(pdeath == 0, "foreign setns kept pdeathsig=%d", pdeath);
        _exit(0);
    }
    wait_ok(foreign, "foreign setns");

    /* Case B: uid 1000 (the namespace owner) enters its own userns -> keeps dumpable & pdeathsig */
    pid_t owner = fork();
    CHECK(owner >= 0, "fork owner");
    if (owner == 0) {
        CHECK(setresgid(1000, 1000, 1000) == 0, "owner setresgid");
        CHECK(setresuid(1000, 1000, 1000) == 0, "owner setresuid");
        CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0, "owner PR_SET_DUMPABLE");
        CHECK(prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) == 0, "owner PR_SET_PDEATHSIG");
        CHECK(syscall(SYS_setns, nsfd, CLONE_NEWUSER) == 0, "owner setns");
        int dump = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
        int pdeath = -1;
        CHECK(prctl(PR_GET_PDEATHSIG, &pdeath, 0, 0, 0) == 0, "owner PR_GET_PDEATHSIG");
        CHECK(dump == 1, "owner setns lost dumpable=%d", dump);
        CHECK(pdeath == SIGTERM, "owner setns lost pdeathsig=%d", pdeath);
        _exit(0);
    }
    wait_ok(owner, "owner setns");

    close(nsfd);
    close(done[1]);
    wait_ok(holder, "userns holder");
}

/* 7. access(2) honours SECBIT_NO_SETUID_FIXUP */
static void test_access_no_setuid_fixup(void)
{
    const char *path = "/tmp/root_only_access";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(fd >= 0, "create %s", path);
    close(fd);

    pid_t pid = fork();
    CHECK(pid >= 0, "fork access child");
    if (pid == 0) {
        CHECK(prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP | SECBIT_KEEP_CAPS, 0, 0, 0) == 0,
              "PR_SET_SECUREBITS");
        CHECK(setresgid(1000, 1000, 1000) == 0, "setresgid");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        /* With SECBIT_NO_SETUID_FIXUP, CAP_DAC_OVERRIDE remains effective in access(2) */
        CHECK(faccessat(AT_FDCWD, path, R_OK, 0) == 0,
              "faccessat with SECBIT_NO_SETUID_FIXUP should succeed");

        /* Clearing SECBIT_NO_SETUID_FIXUP makes non-root real uid drop caps in access(2) */
        CHECK(prctl(PR_SET_SECUREBITS, 0, 0, 0, 0) == 0, "clear securebits");
        errno = 0;
        CHECK(faccessat(AT_FDCWD, path, R_OK, 0) < 0 && errno == EACCES,
              "faccessat without SECBIT_NO_SETUID_FIXUP should fail EACCES");
        _exit(0);
    }
    wait_ok(pid, "access child");
    unlink(path);
}

/* 8. pidfd setns(CLONE_NEWNS | CLONE_NEWUTS) with shared CLONE_FS switches only caller */
struct setns_thread_args {
    int pidfd;
    char target_mnt[64];
    char orig_mnt[64];
    int done_fd;
};

static void *setns_shared_fs_worker(void *arg)
{
    struct setns_thread_args *a = arg;
    CHECK(syscall(SYS_setns, a->pidfd, CLONE_NEWNS | CLONE_NEWUTS) == 0,
          "worker pidfd setns(NEWNS|NEWUTS)");
    char cur[64];
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/task/%ld/ns/mnt", getpid(), (long)syscall(SYS_gettid));
    read_link_str(p, cur, sizeof(cur));
    CHECK(strcmp(cur, a->target_mnt) == 0, "worker mnt ns expected %s got %s", a->target_mnt, cur);
    char c = '1';
    CHECK(write(a->done_fd, &c, 1) == 1, "worker done");
    return NULL;
}

static void test_pidfd_setns_mnt_shared_fs(void)
{
    int ready[2], stop[2];
    CHECK(pipe(ready) == 0 && pipe(stop) == 0, "pipe");
    pid_t target = fork();
    CHECK(target >= 0, "fork setns target");
    if (target == 0) {
        close(ready[0]);
        close(stop[1]);
        CHECK(unshare(CLONE_NEWNS | CLONE_NEWUTS) == 0, "target unshare");
        char c = '1';
        CHECK(write(ready[1], &c, 1) == 1, "target ready");
        (void)read(stop[0], &c, 1);
        _exit(0);
    }
    close(ready[1]);
    close(stop[0]);
    char c;
    CHECK(read(ready[0], &c, 1) == 1, "wait target");
    close(ready[0]);

    int pidfd = (int)syscall(SYS_pidfd_open, target, 0);
    CHECK(pidfd >= 0, "pidfd_open");

    struct setns_thread_args args;
    memset(&args, 0, sizeof(args));
    args.pidfd = pidfd;
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/ns/mnt", target);
    read_link_str(p, args.target_mnt, sizeof(args.target_mnt));

    read_link_str("/proc/self/ns/mnt", args.orig_mnt, sizeof(args.orig_mnt));
    CHECK(strcmp(args.orig_mnt, args.target_mnt) != 0, "expected distinct mnt namespaces");

    int done[2];
    CHECK(pipe(done) == 0, "pipe done");
    args.done_fd = done[1];
    pthread_t th;
    CHECK(pthread_create(&th, NULL, setns_shared_fs_worker, &args) == 0, "pthread_create");
    CHECK(read(done[0], &c, 1) == 1, "wait worker");
    CHECK(pthread_join(th, NULL) == 0, "pthread_join");
    close(done[0]);
    close(done[1]);

    /* Main thread sharing CLONE_FS must still be in its original mount namespace */
    char after[64];
    read_link_str("/proc/self/ns/mnt", after, sizeof(after));
    CHECK(strcmp(after, args.orig_mnt) == 0,
          "main thread mnt ns was mutated from %s to %s", args.orig_mnt, after);

    close(pidfd);
    close(stop[1]);
    wait_ok(target, "setns target");
}

/* 9. /sys/class/net/lo/statistics and tx_queue_len do not leak init netns */
static void test_sysfs_lo_stats_isolated(void)
{
    /* Generate loopback traffic in the initial network namespace */
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(srv >= 0 && cli >= 0, "udp sockets");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0, "bind lo");
    socklen_t alen = sizeof(addr);
    CHECK(getsockname(srv, (struct sockaddr *)&addr, &alen) == 0, "getsockname");
    const char msg[] = "loopback-traffic-probe";
    CHECK(sendto(cli, msg, sizeof(msg), 0, (struct sockaddr *)&addr, alen) == (ssize_t)sizeof(msg),
          "sendto lo");
    char rbuf[64];
    CHECK(recv(srv, rbuf, sizeof(rbuf), 0) == (ssize_t)sizeof(msg), "recv lo");
    close(srv);
    close(cli);

    char val[64];
    read_file_str("/sys/class/net/lo/statistics/tx_bytes", val, sizeof(val));
    CHECK(strtoull(val, NULL, 10) > 0, "expected init netns lo tx_bytes > 0, got %s", val);

    pid_t pid = fork();
    CHECK(pid >= 0, "fork netns child");
    if (pid == 0) {
        CHECK(unshare(CLONE_NEWNS | CLONE_NEWNET) == 0, "unshare(CLONE_NEWNS | CLONE_NEWNET)");
        /* Boot /sys stays tagged with the initial netns until sysfs is remounted in the new netns */
        read_file_str("/sys/class/net/lo/statistics/tx_bytes", val, sizeof(val));
        CHECK(strtoull(val, NULL, 10) > 0,
              "boot /sys before remount must still reflect init netns tx_bytes > 0, got %s", val);
        CHECK(mount("sysfs", "/sys", "sysfs", 0, NULL) == 0, "mount fresh sysfs in new netns");
        const char *stat_files[] = {
            "/sys/class/net/lo/statistics/tx_bytes",
            "/sys/class/net/lo/statistics/rx_bytes",
            "/sys/class/net/lo/statistics/tx_packets",
            "/sys/class/net/lo/statistics/rx_packets",
        };
        for (size_t i = 0; i < 4; i++) {
            read_file_str(stat_files[i], val, sizeof(val));
            CHECK(strcmp(val, "0\n") == 0, "new netns %s leaked %s", stat_files[i], val);
        }
        read_file_str("/sys/class/net/lo/tx_queue_len", val, sizeof(val));
        CHECK(strcmp(val, "1000\n") == 0, "new netns lo tx_queue_len expected 1000, got %s", val);
        _exit(0);
    }
    wait_ok(pid, "netns sysfs child");
}

/* 10. FUSE mknod runs cgroup device BPF and only exempts char 0:0 whiteout (not block 0:0) */
struct fuse_in_hdr {
    uint32_t len;
    uint32_t opcode;
    uint64_t unique;
    uint64_t nodeid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pid;
    uint32_t padding;
};

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

struct fuse_daemon_ctx {
    int devfd;
    volatile int mknod_count;
    volatile int stop;
};

static void *fuse_daemon(void *arg)
{
    struct fuse_daemon_ctx *ctx = arg;
    uint8_t buf[16384];
    while (!ctx->stop) {
        struct pollfd pfd = {.fd = ctx->devfd, .events = POLLIN};
        int pr = poll(&pfd, 1, 20);
        if (pr == 0)
            continue;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            break;
        ssize_t n = read(ctx->devfd, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(struct fuse_in_hdr))
            break;
        struct fuse_in_hdr in;
        memcpy(&in, buf, sizeof(in));

        uint8_t out[256];
        memset(out, 0, sizeof(out));
        struct fuse_out_hdr *hdr = (struct fuse_out_hdr *)out;
        hdr->unique = in.unique;

        if (in.opcode == 26 /* FUSE_INIT */) {
            uint32_t init_out[16];
            memset(init_out, 0, sizeof(init_out));
            init_out[0] = 7;    /* major */
            init_out[1] = 37;   /* minor */
            init_out[6] = 4096; /* max_write */
            hdr->len = sizeof(*hdr) + sizeof(init_out);
            memcpy(out + sizeof(*hdr), init_out, sizeof(init_out));
        } else if (in.opcode == 3 /* FUSE_GETATTR */) {
            struct fuse_attr_out a;
            memset(&a, 0, sizeof(a));
            a.attr.ino = in.nodeid;
            a.attr.mode = S_IFDIR | 0777;
            a.attr.nlink = 2;
            hdr->len = sizeof(*hdr) + sizeof(a);
            memcpy(out + sizeof(*hdr), &a, sizeof(a));
        } else if (in.opcode == 1 /* FUSE_LOOKUP */) {
            hdr->len = sizeof(*hdr);
            hdr->error = -ENOENT;
        } else if (in.opcode == 8 /* FUSE_MKNOD */) {
            ctx->mknod_count++;
            struct fuse_entry_out e;
            memset(&e, 0, sizeof(e));
            e.nodeid = 2 + (uint64_t)ctx->mknod_count;
            e.attr.ino = e.nodeid;
            e.attr.mode = S_IFCHR | 0600;
            e.attr.nlink = 1;
            hdr->len = sizeof(*hdr) + sizeof(e);
            memcpy(out + sizeof(*hdr), &e, sizeof(e));
        } else {
            hdr->len = sizeof(*hdr);
            hdr->error = -ENOSYS;
        }
        (void)write(ctx->devfd, out, hdr->len);
    }
    return NULL;
}

static void test_fuse_mknod_bpf_and_block_zero(void)
{
    const char *mnt = "/tmp/fuse_mknod_test";
    mkdir(mnt, 0777);
    int devfd = open("/dev/fuse", O_RDWR);
    CHECK(devfd >= 0, "open /dev/fuse");

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40777,user_id=0,group_id=0,allow_other", devfd);
    CHECK(mount("testfuse", mnt, "fuse", 0, opts) == 0, "mount fuse");

    struct fuse_daemon_ctx ctx = {.devfd = devfd, .mknod_count = 0, .stop = 0};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, fuse_daemon, &ctx) == 0, "start fuse daemon");

    /* Part A: unprivileged user without CAP_MKNOD:
     * - S_IFBLK 0:0 must be EPERM (not exempted as whiteout)
     * - S_IFCHR 0:0 (whiteout) must succeed and reach daemon */
    pid_t unpriv = fork();
    CHECK(unpriv >= 0, "fork unpriv fuse");
    if (unpriv == 0) {
        CHECK(setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0, "drop priv");
        errno = 0;
        CHECK(mknodat(AT_FDCWD, "/tmp/fuse_mknod_test/blk0", S_IFBLK | 0600, makedev(0, 0)) < 0
                  && errno == EPERM,
              "unpriv FUSE block 0:0 must be EPERM");
        CHECK(mknodat(AT_FDCWD, "/tmp/fuse_mknod_test/wh0", S_IFCHR | 0600, makedev(0, 0)) == 0,
              "unpriv FUSE char 0:0 whiteout must succeed");
        _exit(0);
    }
    wait_ok(unpriv, "unpriv fuse mknod");
    CHECK(ctx.mknod_count == 1, "expected 1 FUSE_MKNOD from whiteout, got %d", ctx.mknod_count);

    /* Part B: privileged user inside cgroup with deny-all BPF_PROG_TYPE_CGROUP_DEVICE:
     * - S_IFCHR 1:3 and S_IFBLK 0:0 must fail EPERM before reaching daemon
     * - S_IFCHR 0:0 whiteout bypasses device filter and succeeds */
    const char *cg = "/sys/fs/cgroup/iso_fuse_dev";
    mkdir(cg, 0755);
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    CHECK(cgfd >= 0, "open cgroup %s", cg);

    uint64_t insns[2] = {
        0x00000000000000b7ULL, /* r0 = 0 (deny) */
        0x0000000000000095ULL, /* exit */
    };
    uint8_t load_attr[144];
    memset(load_attr, 0, sizeof(load_attr));
    uint32_t prog_type = 15; /* BPF_PROG_TYPE_CGROUP_DEVICE */
    uint32_t insn_cnt = 2;
    uint64_t insns_ptr = (uint64_t)(uintptr_t)insns;
    uint64_t lic_ptr = (uint64_t)(uintptr_t)"GPL";
    memcpy(load_attr + 0, &prog_type, 4);
    memcpy(load_attr + 4, &insn_cnt, 4);
    memcpy(load_attr + 8, &insns_ptr, 8);
    memcpy(load_attr + 16, &lic_ptr, 8);
    int progfd = (int)syscall(SYS_bpf, 5 /* BPF_PROG_LOAD */, load_attr, sizeof(load_attr));
    CHECK(progfd >= 0, "BPF_PROG_LOAD");

    uint32_t attach_attr[8];
    memset(attach_attr, 0, sizeof(attach_attr));
    attach_attr[0] = (uint32_t)cgfd;
    attach_attr[1] = (uint32_t)progfd;
    attach_attr[2] = 6; /* BPF_CGROUP_DEVICE */
    CHECK(syscall(SYS_bpf, 8 /* BPF_PROG_ATTACH */, attach_attr, sizeof(attach_attr)) == 0,
          "BPF_PROG_ATTACH");

    pid_t caged = fork();
    CHECK(caged >= 0, "fork caged fuse");
    if (caged == 0) {
        char procs[128], me[32];
        snprintf(procs, sizeof(procs), "%s/cgroup.procs", cg);
        snprintf(me, sizeof(me), "%d\n", getpid());
        write_file_str(procs, me);

        errno = 0;
        CHECK(mknodat(AT_FDCWD, "/tmp/fuse_mknod_test/chr13", S_IFCHR | 0600, makedev(1, 3)) < 0
                  && errno == EPERM,
              "caged FUSE char 1:3 must be EPERM");
        errno = 0;
        CHECK(mknodat(AT_FDCWD, "/tmp/fuse_mknod_test/blk0_root", S_IFBLK | 0600, makedev(0, 0)) < 0
                  && errno == EPERM,
              "caged FUSE block 0:0 must be EPERM");
        CHECK(mknodat(AT_FDCWD, "/tmp/fuse_mknod_test/wh1", S_IFCHR | 0600, makedev(0, 0)) == 0,
              "caged FUSE char 0:0 whiteout must succeed");
        _exit(0);
    }
    wait_ok(caged, "caged fuse mknod");
    CHECK(ctx.mknod_count == 2, "expected 2 FUSE_MKNODs total, got %d", ctx.mknod_count);

    close(progfd);
    close(cgfd);
    rmdir(cg);
    ctx.stop = 1;
    CHECK(umount2(mnt, 0) == 0, "umount fuse");
    pthread_join(th, NULL);
    close(devfd);
    rmdir(mnt);
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--exit-ok") == 0)
        return 0;

    mkdir("/tmp", 01777);

    test_pagemap_pins_mm(argv[0]);
    test_task_per_thread_fd();
    test_reaped_proc_pid_reuse();
    test_sysvipc_pidns_and_shm_locked();
    test_mq_notify_reused_tgid();
    test_setns_foreign_userns_dumpable();
    test_access_no_setuid_fixup();
    test_pidfd_setns_mnt_shared_fs();
    test_sysfs_lo_stats_isolated();
    test_fuse_mknod_bpf_and_block_zero();

    printf("all ok\n");
    return 0;
}
