# mlockall(MCL_FUTURE) and MAP_LOCKED RLIMIT_MEMLOCK enforcement across mmap, brk, mremap,
# MAP_GROWSDOWN stack growth, and shmat (matching Linux 6.1 without CAP_IPC_LOCK).
cd /tmp
cat > /tmp/mlock_future.c <<'C'
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static sigjmp_buf env;
static void on_sig(int s) { siglongjmp(env, s); }
static char altstack[65536];
static long pg;

static const char *map_status(void *p) { return p == MAP_FAILED ? strerror(errno) : "OK"; }

static void install_segv(void)
{
    stack_t ss = {.ss_sp = altstack, .ss_size = sizeof(altstack), .ss_flags = 0};
    sigaltstack(&ss, NULL);
    struct sigaction sa = {.sa_handler = on_sig, .sa_flags = SA_ONSTACK};
    sigaction(SIGSEGV, &sa, NULL);
}

static const char *touch(char *p)
{
    if (sigsetjmp(env, 1) == 0) {
        *(volatile char *)p = 1;
        return "OK";
    }
    return "SIGSEGV";
}

static void drop_ipc_lock_and_limit(rlim_t lim)
{
    /* Drop CAP_IPC_LOCK (bit 14) so RLIMIT_MEMLOCK is enforced even as root */
    struct { uint32_t version; int pid; } h = {0x20080522, 0};
    struct { uint32_t effective, permitted, inheritable; } d[2];
    syscall(SYS_capget, &h, d);
    d[0].effective &= ~(1u << 14);
    d[0].permitted &= ~(1u << 14);
    syscall(SYS_capset, &h, d);
    struct rlimit rl = {lim, lim};
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        perror("setrlimit");
        _exit(1);
    }
}

static void run_case(const char *name, void (*fn)(void))
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("[%s] ", name);
        fn();
        fflush(stdout);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        printf("[%s] abnormal exit 0x%x\n", name, st);
}

static void case_map_locked_zero(void)
{
    drop_ipc_lock_and_limit(0);
    /* Raw SYS_mmap avoids musl's wrapper turning EPERM into ENOMEM on anonymous mmap */
    errno = 0;
    long r = syscall(SYS_mmap, 0, pg, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("lim0=%s\n", r == -1 ? strerror(errno) : "OK");
}

static void case_map_locked_over(void)
{
    drop_ipc_lock_and_limit(2 * pg);
    errno = 0;
    void *p = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
    printf("over=%s\n", map_status(p));
}

static void case_mcl_future_mmap(void)
{
    drop_ipc_lock_and_limit(4 * pg);
    printf("mlockall=%d ", mlockall(MCL_FUTURE));
    void *p1 = mmap(NULL, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("p1=%s ", map_status(p1));
    errno = 0;
    void *p2 = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("p2=%s ", map_status(p2));
    errno = 0;
    void *p3 = mmap(NULL, 2 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("prot_none=%s ", map_status(p3));
    errno = 0;
    void *p4 = mmap(p1, 3 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    printf("fixed_over=%s ", map_status(p4));
    /* Lower RLIMIT_MEMLOCK to 0 while MCL_FUTURE is active */
    struct rlimit zero = {0, 0};
    setrlimit(RLIMIT_MEMLOCK, &zero);
    errno = 0;
    void *p5 = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("after_lim0=%s\n", map_status(p5));
}

static void case_mcl_future_brk(void)
{
    drop_ipc_lock_and_limit(2 * pg);
    uintptr_t b0 = (uintptr_t)syscall(SYS_brk, 0);
    if (b0 % (uintptr_t)pg)
        b0 = (uintptr_t)syscall(SYS_brk, (b0 + pg - 1) & ~(uintptr_t)(pg - 1));
    mlockall(MCL_FUTURE);
    uintptr_t b1 = (uintptr_t)syscall(SYS_brk, b0 + 2 * (uintptr_t)pg);
    uintptr_t b2 = (uintptr_t)syscall(SYS_brk, b1 + (uintptr_t)pg);
    uintptr_t b3 = (uintptr_t)syscall(SYS_brk, b0);
    printf("grow2=%ld grow3=%ld shrink=%ld\n",
           (long)(b1 - b0) / pg,
           (long)(b2 - b1) / pg,
           (long)(b3 - b0) / pg);
}

static void case_mcl_future_mremap(void)
{
    void *unlk = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *dst = mmap(NULL, 3 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    drop_ipc_lock_and_limit(3 * pg);
    mlockall(MCL_FUTURE);
    void *lk = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    errno = 0;
    void *r1 = mremap(lk, 2 * pg, 4 * pg, MREMAP_MAYMOVE);
    printf("grow_locked=%s ", map_status(r1));
    errno = 0;
    void *r2 = mremap(unlk, pg, 4 * pg, MREMAP_MAYMOVE);
    printf("grow_unlocked=%s ", map_status(r2));
    void *sh = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    errno = 0;
    void *r3 = mremap(sh, 0, pg, MREMAP_MAYMOVE);
    printf("dup_locked=%s ", map_status(r3));
    /* MREMAP_FIXED over a locked target is omitted: Linux 6.1/6.8 unmaps the target before
     * checking RLIMIT_MEMLOCK in vma_to_resize (OK; covered by kernel/mm unit tests), while
     * 6.17+/7.x checks mlock_future_ok in check_prep_vma first (EAGAIN). Over an unlocked
     * target both kernels agree on EAGAIN. */
    errno = 0;
    void *r4 = mremap(lk, 2 * pg, 3 * pg, MREMAP_MAYMOVE | MREMAP_FIXED, dst);
    printf("fixed_over_unlocked=%s\n", map_status(r4));
}

static void case_mcl_future_stack(void)
{
    char *g = mmap(NULL, 512 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(g, 512 * pg);
    drop_ipc_lock_and_limit(2 * pg);
    mlockall(MCL_FUTURE);
    char *stk = mmap(g + 511 * pg, pg, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED, -1, 0);
    printf("stk=%s ", map_status(stk));
    install_segv();
    printf("grow1=%s ", touch(stk - pg));
    printf("grow2=%s\n", touch(stk - 2 * pg));
}

static void case_mcl_future_unlocked_stack(void)
{
    char *g = mmap(NULL, 512 * pg, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(g, 512 * pg);
    char *stk = mmap(g + 511 * pg, pg, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_FIXED, -1, 0);
    drop_ipc_lock_and_limit(pg);
    mlockall(MCL_FUTURE);
    install_segv();
    printf("unlocked_grow2=%s\n", touch(stk - 2 * pg));
}

static void case_mcl_future_shmat(void)
{
    int id = shmget(IPC_PRIVATE, 3 * pg, IPC_CREAT | 0600);
    drop_ipc_lock_and_limit(2 * pg);
    mlockall(MCL_FUTURE);
    errno = 0;
    void *p = shmat(id, NULL, 0);
    printf("shmat=%s\n", p == (void *)-1 ? strerror(errno) : "OK");
    shmctl(id, IPC_RMID, NULL);
}

static void case_mcl_future_when_over_limit(void)
{
    drop_ipc_lock_and_limit(4 * pg);
    void *p = mmap(NULL, 4 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mlock(p, 4 * pg);
    struct rlimit rl = {2 * pg, 2 * pg};
    setrlimit(RLIMIT_MEMLOCK, &rl);
    errno = 0;
    int r = mlockall(MCL_FUTURE);
    printf("mlockall_future_over=%d(%s)\n", r, r ? strerror(errno) : "ok");
}

int main(void)
{
    pg = sysconf(_SC_PAGESIZE);
    run_case("map_locked_zero", case_map_locked_zero);
    run_case("map_locked_over", case_map_locked_over);
    run_case("mcl_future_mmap", case_mcl_future_mmap);
    run_case("mcl_future_brk", case_mcl_future_brk);
    run_case("mcl_future_mremap", case_mcl_future_mremap);
    run_case("mcl_future_stack", case_mcl_future_stack);
    run_case("mcl_future_unlocked_stack", case_mcl_future_unlocked_stack);
    run_case("mcl_future_shmat", case_mcl_future_shmat);
    run_case("mcl_future_over", case_mcl_future_when_over_limit);
    return 0;
}
C
gcc -O1 -o /tmp/mlock_future /tmp/mlock_future.c && /tmp/mlock_future
rm -f /tmp/mlock_future /tmp/mlock_future.c
