/*
 * Standalone guest regression tests for kernel/oom victim reaping:
 * 1. An already-exiting victim stopped at PTRACE_EVENT_EXIT has its private memory reaped
 *    immediately when cgroup memory.max triggers OOM, keeping /proc/<pid>/maps and ru_maxrss.
 * 2. A live victim killed by lowering cgroup memory.max dies by SIGKILL with ru_maxrss preserved
 *    and memory.events updated.
 * 3. A vfork parent killed by OOM does NOT have its shared address space reaped while the vfork
 *    child is still running.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, fmt, ...)                                                      \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d %s)\n", __FILE__,       \
                    __LINE__, ##__VA_ARGS__, errno, strerror(errno));              \
            _exit(1);                                                              \
        }                                                                          \
    } while (0)

static void write_str(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    CHECK(fd >= 0, "open %s", path);
    size_t n = strlen(s);
    ssize_t w = write(fd, s, n);
    CHECK(w == (ssize_t)n, "write %s (%zd/%zu)", path, w, n);
    close(fd);
}

static size_t read_str(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s", path);
    size_t total = 0;
    while (total + 1 < cap) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n <= 0)
            break;
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
    return total;
}

static uint64_t read_u64(const char *path)
{
    char buf[128];
    read_str(path, buf, sizeof(buf));
    return strtoull(buf, NULL, 10);
}

static long proc_rss_kb(pid_t pid)
{
    char path[64], buf[8192];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    read_str(path, buf, sizeof(buf));
    char *p = strstr(buf, "VmRSS:");
    CHECK(p != NULL, "VmRSS missing in %s", path);
    return strtol(p + 6, NULL, 10);
}

static int count_lines(const char *path)
{
    static char buf[65536];
    read_str(path, buf, sizeof(buf));
    int lines = 0;
    for (char *p = buf; *p; p++) {
        if (*p == '\n')
            lines++;
    }
    return lines;
}

static void test_reap_exiting_ptrace(void)
{
    const char *cg = "/sys/fs/cgroup/oom_reap_exiting";
    char procs[128], maxf[128], curf[128], mapsf[64];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", cg);
    snprintf(maxf, sizeof(maxf), "%s/memory.max", cg);
    snprintf(curf, sizeof(curf), "%s/memory.current", cg);

    CHECK(mkdir(cg, 0755) == 0, "mkdir %s", cg);
    const size_t sz = 32u << 20;

    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        write_str(procs, "0\n");
        char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(buf != MAP_FAILED, "mmap");
        memset(buf, 0x5a, sz);
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        raise(SIGSTOP);
        _exit(0);
    }

    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP,
          "expected SIGSTOP, st=0x%x", st);
    CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)PTRACE_O_TRACEEXIT) == 0,
          "PTRACE_SETOPTIONS");
    CHECK(ptrace(PTRACE_CONT, pid, 0, 0) == 0, "PTRACE_CONT");
    CHECK(waitpid(pid, &st, 0) == pid && (st >> 8) == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)),
          "expected PTRACE_EVENT_EXIT, st=0x%x", st);

    snprintf(mapsf, sizeof(mapsf), "/proc/%d/maps", pid);
    int maps_before = count_lines(mapsf);
    long rss_before = proc_rss_kb(pid);
    uint64_t cur_before = read_u64(curf);
    CHECK(rss_before >= 28000, "rss_before=%ld too small", rss_before);
    CHECK(cur_before >= (28u << 20), "cur_before=%llu too small", (unsigned long long)cur_before);

    /* Lowering memory.max triggers out_of_memory immediately and reaps the exiting victim. */
    write_str(maxf, "4194304\n");

    long rss_after = proc_rss_kb(pid);
    uint64_t cur_after = read_u64(curf);
    int maps_after = count_lines(mapsf);
    CHECK(rss_before - rss_after >= 28000, "expected >=28MB reaped: before=%ld after=%ld",
          rss_before, rss_after);
    CHECK(cur_after <= (4u << 20), "expected memory.current <= 4MB after reap: %llu",
          (unsigned long long)cur_after);
    CHECK(maps_after == maps_before, "maps changed on reap: %d -> %d", maps_before, maps_after);

    CHECK(ptrace(PTRACE_CONT, pid, 0, 0) == 0, "PTRACE_CONT exit");
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    CHECK(wait4(pid, &st, 0, &ru) == pid, "wait4");
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "unexpected exit status 0x%x", st);
    CHECK(ru.ru_maxrss >= 28000, "ru_maxrss=%ld should preserve pre-reap peak", ru.ru_maxrss);
    CHECK(rmdir(cg) == 0, "rmdir %s", cg);
}

static void test_reap_killed_victim(void)
{
    const char *cg = "/sys/fs/cgroup/oom_reap_killed";
    char procs[128], maxf[128], evf[128], ev[512];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", cg);
    snprintf(maxf, sizeof(maxf), "%s/memory.max", cg);
    snprintf(evf, sizeof(evf), "%s/memory.events", cg);

    CHECK(mkdir(cg, 0755) == 0, "mkdir %s", cg);
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe");

    const size_t sz = 32u << 20;
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(pfd[0]);
        write_str(procs, "0\n");
        char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(buf != MAP_FAILED, "mmap");
        memset(buf, 0x33, sz);
        char c = 'R';
        CHECK(write(pfd[1], &c, 1) == 1, "write ready");
        close(pfd[1]);
        for (;;)
            pause();
    }

    close(pfd[1]);
    char c = 0;
    CHECK(read(pfd[0], &c, 1) == 1 && c == 'R', "read ready");
    close(pfd[0]);

    write_str(maxf, "4194304\n");

    int st = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof(ru));
    CHECK(wait4(pid, &st, 0, &ru) == pid, "wait4");
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "expected SIGKILL, st=0x%x", st);
    CHECK(ru.ru_maxrss >= 28000, "ru_maxrss=%ld should preserve pre-reap peak", ru.ru_maxrss);
    read_str(evf, ev, sizeof(ev));
    CHECK(strstr(ev, "oom 1\n") != NULL && strstr(ev, "oom_kill 1\n") != NULL,
          "unexpected memory.events:\n%s", ev);
    CHECK(rmdir(cg) == 0, "rmdir %s", cg);
}

static void test_vfork_sharer_not_corrupted(void)
{
    const char *cg = "/sys/fs/cgroup/oom_reap_vfork";
    char procs[128], maxf[128];
    snprintf(procs, sizeof(procs), "%s/cgroup.procs", cg);
    snprintf(maxf, sizeof(maxf), "%s/memory.max", cg);

    CHECK(mkdir(cg, 0755) == 0, "mkdir %s", cg);
    int ready[2], go[2], res[2];
    CHECK(pipe(ready) == 0 && pipe(go) == 0 && pipe(res) == 0, "pipes");

    const size_t sz = 32u << 20;
    pid_t parent = fork();
    CHECK(parent >= 0, "fork parent");
    if (parent == 0) {
        close(ready[0]);
        close(go[1]);
        close(res[0]);
        write_str(procs, "0\n");
        volatile unsigned char *buf =
            mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(buf != MAP_FAILED, "mmap");
        memset((void *)buf, 0x42, sz);

        pid_t child = vfork();
        if (child == 0) {
            /*
             * Exempt the vfork child from follow-up OOM ticks after parent exits: parent is still
             * killed by /oom_reap_vfork's memory.max, while child stays in the same cgroup as a
             * live sharer so reap() must leave their shared address space intact.
             */
            int adj = open("/proc/self/oom_score_adj", O_WRONLY);
            if (adj < 0 || write(adj, "-1000\n", 6) != 6 || close(adj) != 0)
                _exit(5);
            char b = 'R';
            if (write(ready[1], &b, 1) != 1)
                _exit(2);
            if (read(go[0], &b, 1) != 1)
                _exit(3);
            char ok = (buf[0] == 0x42 && buf[sz / 2] == 0x42 && buf[sz - 4096] == 0x42) ? 'K' : 'Z';
            if (write(res[1], &ok, 1) != 1)
                _exit(4);
            _exit(0);
        }
        /* vfork parent was killed by OOM while child ran; if we somehow survive, fail */
        _exit(99);
    }

    close(ready[1]);
    close(go[0]);
    close(res[1]);

    char b = 0;
    CHECK(read(ready[0], &b, 1) == 1 && b == 'R', "read ready");
    close(ready[0]);

    /* Kill the vfork parent while its child still runs sharing the same address space. */
    write_str(maxf, "4194304\n");

    b = 'G';
    CHECK(write(go[1], &b, 1) == 1, "write go");
    close(go[1]);

    char ok = 0;
    CHECK(read(res[0], &ok, 1) == 1, "read res");
    CHECK(ok == 'K', "vfork child saw corrupted/reaped memory: %c", ok);

    int st = 0;
    CHECK(waitpid(parent, &st, 0) == parent, "waitpid parent");
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "expected parent SIGKILL, st=0x%x", st);
    /* Wait for child to close res[1] on exit before removing the cgroup. */
    char eof = 0;
    CHECK(read(res[0], &eof, 1) == 0, "wait child exit");
    close(res[0]);
    CHECK(rmdir(cg) == 0, "rmdir %s", cg);
}

int main(void)
{
    write_str("/sys/fs/cgroup/cgroup.subtree_control", "+memory\n");
    test_reap_exiting_ptrace();
    test_reap_killed_victim();
    test_vfork_sharer_not_corrupted();
    printf("all ok\n");
    return 0;
}
