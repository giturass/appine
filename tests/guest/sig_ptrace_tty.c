/*
 * Regression tests for kernel/signal, kernel/ptrace, kernel/tty, and kernel/time:
 * - group_stop notifies parent with CLD_STOPPED only after all threads in the group have stopped;
 * - SIGILL from an undefined instruction omits esr_context in the arm64 signal frame;
 * - rt_sigaction setting SIG_IGN discards pending signals in sibling CLONE_SIGHAND groups;
 * - rt_sigreturn rejects non-zero DAIF pstate bits and invalid/duplicate ESR_MAGIC records;
 * - settimeofday validates tv/tz arguments before EPERM, and clock_settime returns EPERM on CPU
 *   clocks;
 * - PTRACE_DETACH at an attach-time group stop re-enters group stop silently without duplicate
 *   CLD_STOPPED;
 * - PTRACE_SINGLESTEP over skipped syscall (-1), rt_sigreturn, and execve stops at syscall return
 *   rather than one instruction late;
 * - PTRACE_EVENT_EXIT is emitted for sibling threads killed by exit_group and for the leader
 *   killed by a non-leader execve;
 * - process_vm_readv/writev with non-empty local vector and zero remote bytes return 0 before PID
 *   lookup / access checks;
 * - TIOCSCTTY returns EPERM to a non-leader even when the terminal is already its ctty;
 * - TIOCSPGRP returns ESRCH for unknown pgid, checks EFAULT/EINVAL before ENOTTY, and returns
 *   ENOTTY (not EIO) for orphaned background callers;
 * - PTY slave writes clamp ONLCR and XTABS expansion to the 64 KiB output buffer limit;
 * - opening /dev/tty (5:0) and /dev/console (5:1) preserves their device identity while routing
 *   terminal operations to the controlling terminal;
 * - an exited (zombie) main thread's CPU clock remains readable and stopped until reaped.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL (%s:%d): ", __func__, __LINE__);                                 \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, " (errno %d)\n", errno);                                               \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

#define CHECK_ERR(expr, expected_err, ...)                                                         \
    do {                                                                                           \
        errno = 0;                                                                                 \
        long _rc = (long)(expr);                                                                   \
        CHECK(_rc == -1 && errno == (expected_err), __VA_ARGS__);                                  \
    } while (0)

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef FPSIMD_MAGIC
#define FPSIMD_MAGIC 0x46508001U
#endif
#ifndef ESR_MAGIC
#define ESR_MAGIC 0x45535201U
#endif
#ifndef PTRACE_SEIZE
#define PTRACE_SEIZE 0x4206
#endif
#ifndef PTRACE_O_TRACECLONE
#define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC 0x00000010
#endif
#ifndef PTRACE_O_TRACEEXIT
#define PTRACE_O_TRACEEXIT 0x00000040
#endif
#ifndef PTRACE_EVENT_CLONE
#define PTRACE_EVENT_CLONE 3
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC 4
#endif
#ifndef PTRACE_EVENT_EXIT
#define PTRACE_EVENT_EXIT 6
#endif
#ifndef SYS_timer_create
#define SYS_timer_create 107
#endif
#ifndef SYS_timer_settime
#define SYS_timer_settime 110
#endif
#ifndef SYS_timer_delete
#define SYS_timer_delete 111
#endif
#ifndef SYS_settimeofday
#define SYS_settimeofday 170
#endif
#ifndef SYS_mq_open
#define SYS_mq_open 180
#endif
#ifndef SYS_mq_unlink
#define SYS_mq_unlink 181
#endif
#ifndef SYS_mq_timedsend
#define SYS_mq_timedsend 182
#endif
#ifndef SYS_mq_notify
#define SYS_mq_notify 184
#endif
#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 270
#endif
#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev 271
#endif

struct arm64_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct aarch64_ctx_hdr {
    uint32_t magic;
    uint32_t size;
};

static int get_regs(pid_t pid, struct arm64_regs *r)
{
    struct iovec iov = {.iov_base = r, .iov_len = sizeof(*r)};
    return (int)ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

static int set_regs(pid_t pid, const struct arm64_regs *r)
{
    struct iovec iov = {.iov_base = (void *)r, .iov_len = sizeof(*r)};
    return (int)ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov);
}

static int set_syscallno(pid_t pid, int nr)
{
    struct iovec iov = {.iov_base = &nr, .iov_len = sizeof(nr)};
    return (int)ptrace(PTRACE_SETREGSET, pid, (void *)(uintptr_t)NT_ARM_SYSTEM_CALL, &iov);
}

static unsigned long get_eventmsg(pid_t pid)
{
    unsigned long msg = 0;
    CHECK(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) == 0, "GETEVENTMSG %d", pid);
    return msg;
}

static void wait_stop(pid_t pid, int sig)
{
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st) && WSTOPSIG(st) == sig,
          "expected pid %d stop sig %d, got 0x%x", pid, sig, st);
}

static void wait_exit(pid_t pid, int code)
{
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == code,
          "expected pid %d exit %d, got 0x%x", pid, code, st);
}

static void msleep(int ms)
{
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* ---- 1. group_stop waits for all sibling threads before CLD_STOPPED ---- */

struct stop_shared {
    _Atomic int ready;
    _Atomic uint64_t ticks;
};

static void *spinner_thread(void *arg)
{
    struct stop_shared *sh = arg;
    atomic_store_explicit(&sh->ready, 1, memory_order_release);
    for (;;) {
        atomic_fetch_add_explicit(&sh->ticks, 1, memory_order_relaxed);
    }
    return NULL;
}

static void test_group_stop_waits_for_all_threads(void)
{
    struct stop_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(sh != MAP_FAILED, "mmap shared");
    atomic_init(&sh->ready, 0);
    atomic_init(&sh->ticks, 0);

    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        pthread_t th;
        CHECK(pthread_create(&th, NULL, spinner_thread, sh) == 0, "pthread_create");
        while (atomic_load_explicit(&sh->ready, memory_order_acquire) == 0) {
            sched_yield();
        }
        for (;;) {
            pause();
        }
    }

    while (atomic_load_explicit(&sh->ready, memory_order_acquire) == 0) {
        msleep(1);
    }
    /* Ensure sibling thread is actively spinning before stopping the group. */
    uint64_t t0 = atomic_load_explicit(&sh->ticks, memory_order_relaxed);
    while (atomic_load_explicit(&sh->ticks, memory_order_relaxed) == t0) {
        msleep(1);
    }

    CHECK(kill(pid, SIGSTOP) == 0, "kill SIGSTOP");
    int st = 0;
    CHECK(waitpid(pid, &st, WUNTRACED) == pid, "waitpid WUNTRACED");
    CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP, "expected SIGSTOP stop, got 0x%x", st);

    /* Once CLD_STOPPED / waitpid reports stopped, the spinning sibling must already be stopped. */
    uint64_t frozen = atomic_load_explicit(&sh->ticks, memory_order_acquire);
    msleep(40);
    uint64_t after = atomic_load_explicit(&sh->ticks, memory_order_acquire);
    CHECK(frozen == after, "sibling kept running after CLD_STOPPED (%llu -> %llu)",
          (unsigned long long)frozen, (unsigned long long)after);

    CHECK(kill(pid, SIGKILL) == 0, "kill SIGKILL");
    CHECK(waitpid(pid, &st, 0) == pid, "waitpid reap");
    munmap(sh, 4096);
}

/* ---- 2. SIGILL from undefined instruction omits esr_context ---- */

static volatile sig_atomic_t sigill_seen = 0;
static volatile sig_atomic_t sigill_had_fpsimd = 0;
static volatile sig_atomic_t sigill_had_esr = 0;

static void on_sigill(int sig, siginfo_t *info, void *uctx)
{
    (void)sig;
    (void)info;
    ucontext_t *uc = uctx;
    sigill_seen = 1;
    const uint8_t *p = (const uint8_t *)uc->uc_mcontext.__reserved;
    size_t off = 0;
    while (off + sizeof(struct aarch64_ctx_hdr) <= sizeof(uc->uc_mcontext.__reserved)) {
        struct aarch64_ctx_hdr h;
        memcpy(&h, p + off, sizeof(h));
        if (h.magic == 0 && h.size == 0) {
            break;
        }
        if (h.magic == FPSIMD_MAGIC) {
            sigill_had_fpsimd = 1;
        } else if (h.magic == ESR_MAGIC) {
            sigill_had_esr = 1;
        }
        if (h.size < sizeof(h)) {
            break;
        }
        off += h.size;
    }
    uc->uc_mcontext.pc += 4;
}

static void test_sigill_omits_esr_context(void)
{
    struct sigaction sa = {0}, old = {0};
    sa.sa_sigaction = on_sigill;
    sa.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGILL, &sa, &old) == 0, "sigaction SIGILL");

    sigill_seen = 0;
    sigill_had_fpsimd = 0;
    sigill_had_esr = 0;
    __asm__ volatile(".inst 0x00000000" ::: "memory");

    CHECK(sigaction(SIGILL, &old, NULL) == 0, "restore SIGILL");
    CHECK(sigill_seen == 1, "SIGILL handler did not run");
    CHECK(sigill_had_fpsimd == 1, "SIGILL frame missing fpsimd_context");
    CHECK(sigill_had_esr == 0, "SIGILL from undefined insn must omit esr_context");
}

/* ---- 3. rt_sigaction SIG_IGN discards pending signals across CLONE_SIGHAND groups ---- */

struct sighand_shared {
    _Atomic int state;
    _Atomic int still_pending;
};

static int sighand_child_fn(void *arg)
{
    struct sighand_shared *sh = arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
        _exit(2);
    }
    atomic_store_explicit(&sh->state, 1, memory_order_release);
    /* Wait for parent to send SIGUSR1 and then ignore it. */
    while (atomic_load_explicit(&sh->state, memory_order_acquire) < 2) {
        msleep(1);
    }
    sigset_t pend;
    sigemptyset(&pend);
    if (sigpending(&pend) != 0) {
        _exit(3);
    }
    atomic_store_explicit(&sh->still_pending, sigismember(&pend, SIGUSR1) ? 1 : 0,
                          memory_order_release);
    _exit(0);
}

static void test_sigaction_clone_sighand_discard(void)
{
    struct sighand_shared sh;
    atomic_init(&sh.state, 0);
    atomic_init(&sh.still_pending, -1);

    size_t stack_sz = 64 * 1024;
    void *stack = mmap(NULL, stack_sz, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(stack != MAP_FAILED, "mmap clone stack");

    /* Ensure SIGUSR1 is not ignored so parent can queue it while blocked in child. */
    struct sigaction sa = {0}, old = {0};
    sa.sa_handler = SIG_DFL;
    CHECK(sigaction(SIGUSR1, &sa, &old) == 0, "sigaction SIGUSR1 DFL");

    pid_t child = clone(sighand_child_fn, (char *)stack + stack_sz,
                        CLONE_VM | CLONE_SIGHAND | SIGCHLD, &sh);
    CHECK(child > 0, "clone CLONE_VM|CLONE_SIGHAND");

    while (atomic_load_explicit(&sh.state, memory_order_acquire) < 1) {
        msleep(1);
    }
    CHECK(kill(child, SIGUSR1) == 0, "kill(child, SIGUSR1)");
    msleep(5);

    /* Parent sets SIGUSR1 to SIG_IGN; child shares sighand, so child's pending SIGUSR1 must go. */
    sa.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction SIGUSR1 IGN");

    atomic_store_explicit(&sh.state, 2, memory_order_release);
    wait_exit(child, 0);
    CHECK(atomic_load_explicit(&sh.still_pending, memory_order_acquire) == 0,
          "pending SIGUSR1 in sibling CLONE_SIGHAND group was not discarded");

    CHECK(sigaction(SIGUSR1, &old, NULL) == 0, "restore SIGUSR1");
    munmap(stack, stack_sz);
}

/* ---- 4. rt_sigreturn rejects DAIF bits and bogus/duplicate ESR_MAGIC ---- */

static sigjmp_buf sigret_jmp;
static volatile sig_atomic_t sigret_mode = 0;
static volatile sig_atomic_t sigret_got_segv = 0;

static void on_sigret_segv(int sig)
{
    (void)sig;
    sigret_got_segv = 1;
    siglongjmp(sigret_jmp, 1);
}

static void on_sigret_usr1(int sig, siginfo_t *info, void *uctx)
{
    (void)sig;
    (void)info;
    ucontext_t *uc = uctx;
    if (sigret_mode == 1) {
        /* Set IRQ mask bit (I = 1<<7 = 0x80) in pstate. */
        uc->uc_mcontext.pstate |= 0x80ULL;
        return;
    }
    uint8_t *p = (uint8_t *)uc->uc_mcontext.__reserved;
    struct aarch64_ctx_hdr h, end = {.magic = 0, .size = 0};
    memcpy(&h, p, sizeof(h));
    if (h.magic != FPSIMD_MAGIC || h.size + 48 > sizeof(uc->uc_mcontext.__reserved)) {
        return;
    }
    if (sigret_mode == 2) {
        /* Append an oversized ESR_MAGIC record (size 32 != 16) after fpsimd_context. */
        struct aarch64_ctx_hdr bad = {.magic = ESR_MAGIC, .size = 32};
        memcpy(p + h.size, &bad, sizeof(bad));
    } else if (sigret_mode == 3) {
        /* Append duplicate valid-sized ESR_MAGIC records after fpsimd_context. */
        struct aarch64_ctx_hdr esr = {.magic = ESR_MAGIC, .size = 16};
        memcpy(p + h.size, &esr, sizeof(esr));
        memcpy(p + h.size + 16, &esr, sizeof(esr));
    }
    memcpy(p + h.size + 32, &end, sizeof(end));
}

static void test_sigreturn_validation(void)
{
    struct sigaction sa_segv = {0}, old_segv = {0};
    sa_segv.sa_handler = on_sigret_segv;
    CHECK(sigaction(SIGSEGV, &sa_segv, &old_segv) == 0, "sigaction SIGSEGV");

    struct sigaction sa_usr1 = {0}, old_usr1 = {0};
    sa_usr1.sa_sigaction = on_sigret_usr1;
    sa_usr1.sa_flags = SA_SIGINFO;
    CHECK(sigaction(SIGUSR1, &sa_usr1, &old_usr1) == 0, "sigaction SIGUSR1");

    for (int mode = 1; mode <= 3; mode++) {
        sigret_mode = mode;
        sigret_got_segv = 0;
        if (sigsetjmp(sigret_jmp, 1) == 0) {
            raise(SIGUSR1);
        }
        CHECK(sigret_got_segv == 1, "rt_sigreturn mode %d must force SIGSEGV", mode);
    }

    CHECK(sigaction(SIGUSR1, &old_usr1, NULL) == 0, "restore SIGUSR1");
    CHECK(sigaction(SIGSEGV, &old_segv, NULL) == 0, "restore SIGSEGV");
}

/* ---- 5. settimeofday validation and clock_settime on CPU clocks ---- */

static void test_time_setting_errors(void)
{
    struct timeval tv;
    struct timezone tz = {0, 0};

    tv.tv_sec = 100;
    tv.tv_usec = 1000000;
    CHECK_ERR(syscall(SYS_settimeofday, &tv, NULL), EINVAL, "settimeofday usec=1000000 -> EINVAL");

    tv.tv_sec = 100;
    tv.tv_usec = -1;
    CHECK_ERR(syscall(SYS_settimeofday, &tv, NULL), EINVAL, "settimeofday usec=-1 -> EINVAL");

    tv.tv_sec = -1;
    tv.tv_usec = 0;
    CHECK_ERR(syscall(SYS_settimeofday, &tv, NULL), EINVAL, "settimeofday sec=-1 -> EINVAL");

    CHECK_ERR(syscall(SYS_settimeofday, (void *)0x10, NULL), EFAULT, "settimeofday bad tv -> EFAULT");
    CHECK_ERR(syscall(SYS_settimeofday, NULL, (void *)0x10), EFAULT, "settimeofday bad tz -> EFAULT");

    tv.tv_sec = 100;
    tv.tv_usec = 500;
    CHECK_ERR(syscall(SYS_settimeofday, &tv, &tz), EPERM, "settimeofday valid -> EPERM");
    CHECK_ERR(syscall(SYS_settimeofday, NULL, NULL), EPERM, "settimeofday(NULL, NULL) -> EPERM");

    struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};
    CHECK_ERR(clock_settime(CLOCK_PROCESS_CPUTIME_ID, &ts), EPERM,
              "clock_settime(CLOCK_PROCESS_CPUTIME_ID) -> EPERM");
    CHECK_ERR(clock_settime(CLOCK_THREAD_CPUTIME_ID, &ts), EPERM,
              "clock_settime(CLOCK_THREAD_CPUTIME_ID) -> EPERM");

    clockid_t pid_clk = 0;
    CHECK(clock_getcpuclockid(getpid(), &pid_clk) == 0, "clock_getcpuclockid(self)");
    CHECK_ERR(clock_settime(pid_clk, &ts), EPERM, "clock_settime(pid cpu clock) -> EPERM");

    clockid_t bad_clk = (clockid_t)((~(uint32_t)999999U << 3) | 2U);
    CHECK_ERR(clock_settime(bad_clk, &ts), EINVAL,
              "clock_settime(nonexistent pid cpu clock) -> EINVAL");
    CHECK_ERR(clock_settime(CLOCK_MONOTONIC, &ts), EINVAL,
              "clock_settime(CLOCK_MONOTONIC) -> EINVAL");
}

/* ---- 6. Detach at attach-time group stop does not duplicate CLD_STOPPED ---- */

static void test_ptrace_detach_at_attach_group_stop(void)
{
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe");

    pid_t child = fork();
    CHECK(child >= 0, "fork child");
    if (child == 0) {
        close(pfd[0]);
        /* Put child in its own process group so it is not an orphaned pgrp (SIGTSTP stops it). */
        CHECK(setpgid(0, 0) == 0, "setpgid");
        raise(SIGTSTP);
        /* After parent resumes us with SIGCONT, signal readiness and exit 0. */
        char c = 'k';
        (void)write(pfd[1], &c, 1);
        _exit(0);
    }
    close(pfd[1]);

    int st = 0;
    CHECK(waitpid(child, &st, WUNTRACED) == child, "parent waitpid WUNTRACED");
    CHECK(WIFSTOPPED(st) && WSTOPSIG(st) == SIGTSTP, "child stopped by SIGTSTP");

    /* A separate tracer attaches to the already-stopped child, observes the group stop,
     * and detaches without continuing the group. */
    pid_t tracer = fork();
    CHECK(tracer >= 0, "fork tracer");
    if (tracer == 0) {
        CHECK(ptrace(PTRACE_ATTACH, child, 0, 0) == 0, "PTRACE_ATTACH");
        wait_stop(child, SIGTSTP);
        CHECK(ptrace(PTRACE_DETACH, child, 0, 0) == 0, "PTRACE_DETACH");
        _exit(0);
    }

    wait_exit(tracer, 0);

    /* Give the detached child time to settle; parent must NOT see a second stop report. */
    msleep(20);
    pid_t r = waitpid(child, &st, WUNTRACED | WNOHANG);
    CHECK(r == 0, "duplicate CLD_STOPPED after PTRACE_DETACH: waitpid=%d st=0x%x", r, st);

    /* Resume child with SIGCONT and confirm it runs and exits cleanly. */
    CHECK(kill(child, SIGCONT) == 0, "kill SIGCONT");
    char buf = 0;
    CHECK(read(pfd[0], &buf, 1) == 1, "read child post-SIGCONT byte");
    close(pfd[0]);
    wait_exit(child, 0);
}

/* ---- 7. Single-step over skipped syscall (-1), rt_sigreturn, and execve ---- */

static void test_singlestep_skipped_syscall(void)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        kill(getpid(), SIGSTOP);
        register uint64_t x8 __asm__("x8") = SYS_getpid;
        register int64_t x0 __asm__("x0") = 0;
        __asm__ volatile(
            "svc #0\n"
            "nop\n"
            "nop\n"
            : "+r"(x0)
            : "r"(x8)
            : "memory");
        _exit(x0 == -EPERM ? 0 : 2);
    }

    wait_stop(child, SIGSTOP);

    /* Run until syscall entry of getpid. */
    struct arm64_regs entry_regs;
    for (;;) {
        CHECK(ptrace(PTRACE_SYSCALL, child, 0, 0) == 0, "PTRACE_SYSCALL");
        wait_stop(child, SIGTRAP);
        CHECK(get_regs(child, &entry_regs) == 0, "get_regs entry");
        if (entry_regs.regs[8] == SYS_getpid) {
            break;
        }
    }
    uint64_t after_svc_pc = entry_regs.pc;

    /* Skip syscall by setting nr = -1 and return value x0 = -EPERM, then SINGLESTEP. */
    CHECK(set_syscallno(child, -1) == 0, "set_syscallno(-1)");
    entry_regs.regs[0] = (uint64_t)(int64_t)(-EPERM);
    CHECK(set_regs(child, &entry_regs) == 0, "set_regs x0=-EPERM");
    CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0, "PTRACE_SINGLESTEP over skipped svc");

    wait_stop(child, SIGTRAP);
    struct arm64_regs step_regs;
    CHECK(get_regs(child, &step_regs) == 0, "get_regs step");
    CHECK(step_regs.pc == after_svc_pc,
          "single-step over skipped syscall reported late: pc=0x%llx expected 0x%llx",
          (unsigned long long)step_regs.pc, (unsigned long long)after_svc_pc);

    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");
    wait_exit(child, 0);
}

static volatile sig_atomic_t step_sigret_hit = 0;
static void on_step_usr1(int sig)
{
    (void)sig;
    step_sigret_hit = 1;
}

static void test_singlestep_rt_sigreturn(void)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        struct sigaction sa = {0};
        sa.sa_handler = on_step_usr1;
        CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        kill(getpid(), SIGSTOP);
        __asm__ volatile(
            "nop\n"
            "nop\n"
            "nop\n"
            ::: "memory");
        _exit(step_sigret_hit ? 0 : 2);
    }

    wait_stop(child, SIGSTOP);

    struct arm64_regs before_sig;
    CHECK(get_regs(child, &before_sig) == 0, "get_regs before SIGUSR1");
    uint64_t expected_return_pc = before_sig.pc;

    /* Inject SIGUSR1 while single-stepping -> stops at first instruction of handler. */
    CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, (void *)(uintptr_t)SIGUSR1) == 0,
          "PTRACE_SINGLESTEP with SIGUSR1");
    wait_stop(child, SIGTRAP);
    struct arm64_regs hregs;
    CHECK(get_regs(child, &hregs) == 0, "get_regs handler entry");
    CHECK(hregs.pc == (uint64_t)(uintptr_t)on_step_usr1,
          "expected handler entry 0x%llx, got 0x%llx",
          (unsigned long long)(uintptr_t)on_step_usr1, (unsigned long long)hregs.pc);

    /* Single-step through the handler and the vDSO sigreturn trampoline until pc returns to
     * expected_return_pc; if rt_sigreturn skipped syscall_stepped, the first stop back in main
     * code would be at expected_return_pc + 4 instead of expected_return_pc! */
    bool returned_exact = false;
    for (int i = 0; i < 400; i++) {
        struct arm64_regs r;
        CHECK(get_regs(child, &r) == 0, "get_regs step");
        if (r.pc == expected_return_pc) {
            returned_exact = true;
            break;
        }
        CHECK(r.pc != expected_return_pc + 4,
              "single-step over rt_sigreturn stopped one instruction late (pc=0x%llx expected 0x%llx)",
              (unsigned long long)r.pc, (unsigned long long)expected_return_pc);
        CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0, "PTRACE_SINGLESTEP");
        wait_stop(child, SIGTRAP);
    }
    CHECK(returned_exact, "did not observe exact return PC from rt_sigreturn");

    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");
    wait_exit(child, 0);
}

static uint64_t elf_entry_of(const char *path)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s", path);
    Elf64_Ehdr eh;
    CHECK(read(fd, &eh, sizeof(eh)) == (ssize_t)sizeof(eh), "read ehdr");
    close(fd);
    return eh.e_entry;
}

static void test_singlestep_execve(const char *self)
{
    uint64_t entry = elf_entry_of(self);
    int sync_p[2];
    CHECK(pipe(sync_p) == 0, "pipe");

    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        close(sync_p[1]);
        char c;
        CHECK(read(sync_p[0], &c, 1) == 1, "wait seize");
        close(sync_p[0]);
        /* Stop so tracer can switch to PTRACE_SINGLESTEP right before execve svc. */
        kill(getpid(), SIGSTOP);
        char *argv[] = {(char *)self, "--exec-helper", NULL};
        char *envp[] = {NULL};
        syscall(SYS_execve, self, argv, envp);
        _exit(99);
    }
    close(sync_p[0]);

    /* Seize WITHOUT PTRACE_O_TRACEEXEC so execve itself does not emit SIGTRAP or EVENT_EXEC;
     * single-step over execve must still stop right at the new image's entry point. */
    CHECK(ptrace(PTRACE_SEIZE, child, 0, 0) == 0, "PTRACE_SEIZE");
    char go = 1;
    CHECK(write(sync_p[1], &go, 1) == 1, "signal child");
    close(sync_p[1]);

    wait_stop(child, SIGSTOP);
    /* Suppress SIGSTOP and step until we hit execve's entry point. */
    CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0, "start SINGLESTEP");

    bool hit_entry = false;
    for (int i = 0; i < 600; i++) {
        wait_stop(child, SIGTRAP);
        struct arm64_regs r;
        CHECK(get_regs(child, &r) == 0, "get_regs");
        if (r.pc == entry) {
            hit_entry = true;
            break;
        }
        CHECK(r.pc != entry + 4,
              "single-step over execve stopped one instruction late (pc=0x%llx entry=0x%llx)",
              (unsigned long long)r.pc, (unsigned long long)entry);
        CHECK(ptrace(PTRACE_SINGLESTEP, child, 0, 0) == 0, "PTRACE_SINGLESTEP");
    }
    CHECK(hit_entry, "did not observe stop at exact execve entry 0x%llx",
          (unsigned long long)entry);

    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");
    wait_exit(child, 42);
}

/* ---- 8. PTRACE_EVENT_EXIT for exit_group siblings and non-leader execve ---- */

static _Atomic int exit_group_th_ready = 0;

static void *sleep_forever(void *arg)
{
    (void)arg;
    atomic_store_explicit(&exit_group_th_ready, 1, memory_order_release);
    for (;;) {
        pause();
    }
    return NULL;
}

static void test_ptrace_event_exit_on_exit_group(void)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        raise(SIGSTOP);
        pthread_t th;
        CHECK(pthread_create(&th, NULL, sleep_forever, NULL) == 0, "pthread_create");
        while (atomic_load_explicit(&exit_group_th_ready, memory_order_acquire) == 0) {
            msleep(1);
        }
        syscall(SYS_exit_group, 7);
        _exit(1);
    }

    wait_stop(child, SIGSTOP);
    CHECK(ptrace(PTRACE_SETOPTIONS, child, 0,
                 (void *)(uintptr_t)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT)) == 0,
          "PTRACE_SETOPTIONS");
    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");

    pid_t sibling = -1;
    int exit_events = 0;
    bool saw_leader_exit = false;
    bool saw_sibling_exit = false;
    bool leader_reaped = false;

    while (!leader_reaped) {
        int st = 0;
        pid_t w = waitpid(-1, &st, __WALL);
        CHECK(w > 0, "waitpid __WALL");
        if (WIFEXITED(st)) {
            if (w == child) {
                CHECK(WEXITSTATUS(st) == 7, "leader exit status %d", WEXITSTATUS(st));
                leader_reaped = true;
            }
            continue;
        }
        CHECK(WIFSTOPPED(st), "unexpected status 0x%x for %d", st, w);
        int ev = st >> 16;
        if (ev == PTRACE_EVENT_CLONE) {
            sibling = (pid_t)get_eventmsg(w);
        } else if (ev == PTRACE_EVENT_EXIT) {
            unsigned long msg = get_eventmsg(w);
            CHECK(msg == (7UL << 8), "expected exit_group eventmsg 0x700, got 0x%lx (pid %d)",
                  msg, w);
            exit_events++;
            if (w == child) {
                saw_leader_exit = true;
            } else if (w == sibling) {
                saw_sibling_exit = true;
            }
        }
        int sig = WSTOPSIG(st);
        int inject = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
        CHECK(ptrace(PTRACE_CONT, w, 0, (void *)(uintptr_t)inject) == 0, "PTRACE_CONT %d", w);
    }

    CHECK(sibling > 0, "never saw clone sibling");
    CHECK(saw_leader_exit && saw_sibling_exit && exit_events == 2,
          "expected PTRACE_EVENT_EXIT for both leader and sibling (leader=%d sibling=%d count=%d)",
          saw_leader_exit, saw_sibling_exit, exit_events);
}

static void *nonleader_exec_thread(void *arg)
{
    const char *self = arg;
    char *argv[] = {(char *)self, "--exec-helper", NULL};
    char *envp[] = {NULL};
    syscall(SYS_execve, self, argv, envp);
    _exit(99);
}

static void test_ptrace_event_exit_on_nonleader_execve(const char *self)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        raise(SIGSTOP);
        pthread_t th;
        CHECK(pthread_create(&th, NULL, nonleader_exec_thread, (void *)self) == 0,
              "pthread_create");
        for (;;) {
            pause();
        }
    }

    wait_stop(child, SIGSTOP);
    CHECK(ptrace(PTRACE_SETOPTIONS, child, 0,
                 (void *)(uintptr_t)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
                                     PTRACE_O_TRACEEXIT)) == 0,
          "PTRACE_SETOPTIONS");
    CHECK(ptrace(PTRACE_CONT, child, 0, 0) == 0, "PTRACE_CONT");

    pid_t worker = -1;
    bool saw_leader_exit_event = false;
    bool saw_exec_event = false;
    bool done = false;

    while (!done) {
        int st = 0;
        pid_t w = waitpid(-1, &st, __WALL);
        CHECK(w > 0, "waitpid __WALL");
        if (WIFEXITED(st)) {
            if (w == child) {
                CHECK(WEXITSTATUS(st) == 42, "exec helper exit status %d", WEXITSTATUS(st));
                done = true;
            }
            continue;
        }
        CHECK(WIFSTOPPED(st), "unexpected status 0x%x for %d", st, w);
        int ev = st >> 16;
        if (ev == PTRACE_EVENT_CLONE) {
            worker = (pid_t)get_eventmsg(w);
        } else if (ev == PTRACE_EVENT_EXIT && w == child && !saw_exec_event) {
            unsigned long msg = get_eventmsg(w);
            CHECK(msg == 0, "leader killed by non-leader execve should report msg 0, got 0x%lx",
                  msg);
            saw_leader_exit_event = true;
        } else if (ev == PTRACE_EVENT_EXEC) {
            unsigned long msg = get_eventmsg(w);
            CHECK(w == child, "execing thread should take over leader pid %d (got %d)", child, w);
            CHECK((pid_t)msg == worker, "exec eventmsg should be former tid %d (got %lu)",
                  worker, msg);
            CHECK(saw_leader_exit_event,
                  "leader PTRACE_EVENT_EXIT must arrive before PTRACE_EVENT_EXEC");
            saw_exec_event = true;
        }
        int sig = WSTOPSIG(st);
        int inject = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
        CHECK(ptrace(PTRACE_CONT, w, 0, (void *)(uintptr_t)inject) == 0, "PTRACE_CONT %d", w);
    }

    CHECK(saw_leader_exit_event && saw_exec_event,
          "missing events: leader_exit=%d exec=%d", saw_leader_exit_event, saw_exec_event);
}

/* ---- 9. process_vm_readv/writev zero remote bytes before PID/permission checks ---- */

static void test_process_vm_zero_remote(void)
{
    char buf[16] = {0};
    struct iovec local = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct iovec remote_zero = {.iov_base = (void *)0x1000, .iov_len = 0};
    long syscalls[2] = {SYS_process_vm_readv, SYS_process_vm_writev};

    for (int i = 0; i < 2; i++) {
        for (unsigned long rcnt = 0; rcnt <= 1; rcnt++) {
            errno = 0;
            CHECK(syscall(syscalls[i], 999999, &local, 1, &remote_zero, rcnt, 0) == 0,
                  "process_vm syscall %ld (rcnt=%lu) must return 0 before ESRCH",
                  syscalls[i], rcnt);
        }
    }
}

/* ---- 10 & 11. TIOCSCTTY non-leader & TIOCSPGRP error codes ---- */

static int open_pty_pair(int *master_out, int *slave_out, int slave_flags)
{
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (m < 0) {
        return -1;
    }
    int unlock = 0;
    if (ioctl(m, TIOCSPTLCK, &unlock) != 0) {
        close(m);
        return -1;
    }
    unsigned int ptn = 0;
    if (ioctl(m, TIOCGPTN, &ptn) != 0) {
        close(m);
        return -1;
    }
    char path[64];
    snprintf(path, sizeof(path), "/dev/pts/%u", ptn);
    int s = open(path, slave_flags);
    if (s < 0) {
        close(m);
        return -1;
    }
    *master_out = m;
    *slave_out = s;
    return 0;
}

static void check_fd_link(int fd, const char *expected)
{
    char proc_path[64], link_buf[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc_path, link_buf, sizeof(link_buf) - 1);
    CHECK(n > 0, "readlink %s", proc_path);
    link_buf[n] = '\0';
    CHECK(strcmp(link_buf, expected) == 0, "readlink %s expected '%s', got '%s'", proc_path,
          expected, link_buf);
}

static void check_ctty_identity(int fd, const char *path, unsigned int want_minor,
                                const struct stat *path_st, const struct stat *pts_st)
{
    struct stat st;
    CHECK(fstat(fd, &st) == 0, "fstat %s", path);
    CHECK(S_ISCHR(st.st_mode), "%s fstat is char dev", path);
    CHECK(major(st.st_rdev) == 5 && minor(st.st_rdev) == want_minor, "%s rdev is 5:%u (got %u:%u)",
          path, want_minor, major(st.st_rdev), minor(st.st_rdev));
    CHECK(st.st_dev == path_st->st_dev && st.st_dev != pts_st->st_dev, "%s st_dev matches /dev",
          path);
    CHECK(st.st_ino == path_st->st_ino && st.st_ino != pts_st->st_ino, "%s st_ino matches %s", path,
          path);
    CHECK(st.st_mode == path_st->st_mode, "%s st_mode matches", path);
    CHECK(st.st_uid == path_st->st_uid && st.st_gid == path_st->st_gid, "%s owner matches", path);
    check_fd_link(fd, path);
    char *tn = ttyname(fd);
    CHECK(tn && strcmp(tn, path) == 0, "ttyname %s (got %s)", path, tn ? tn : "(null)");
    CHECK(isatty(fd) == 1, "isatty %s", path);
}

static void test_tty_device_identity(void)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork tty device identity");
    if (child == 0) {
        CHECK(setsid() > 0, "setsid");
        /* Without a controlling terminal, opening /dev/tty or /dev/console fails with ENXIO. */
        CHECK_ERR(open("/dev/tty", O_RDWR), ENXIO, "open /dev/tty without ctty");
        CHECK_ERR(open("/dev/console", O_RDWR), ENXIO, "open /dev/console without ctty");

        int m = -1, s = -1;
        CHECK(open_pty_pair(&m, &s, O_RDWR) == 0, "open controlling tty");

        unsigned int ptn = 9999;
        CHECK(ioctl(m, TIOCGPTN, &ptn) == 0, "TIOCGPTN on master");
        char pts_path[64];
        snprintf(pts_path, sizeof(pts_path), "/dev/pts/%u", ptn);

        struct stat pts_st, tty_path_st, con_path_st;
        CHECK(fstat(s, &pts_st) == 0, "fstat pts slave");
        CHECK(S_ISCHR(pts_st.st_mode), "pts slave is char dev");
        CHECK(major(pts_st.st_rdev) == 136 && minor(pts_st.st_rdev) == ptn,
              "pts slave rdev 136:%u", ptn);
        unsigned int dev;
        CHECK(ioctl(m, TIOCGDEV, &dev) == 0 && dev == pts_st.st_rdev, "master TIOCGDEV");
        CHECK(ioctl(s, TIOCGDEV, &dev) == 0 && dev == pts_st.st_rdev, "slave TIOCGDEV");
        CHECK(stat("/dev/tty", &tty_path_st) == 0, "stat /dev/tty");
        CHECK(stat("/dev/console", &con_path_st) == 0, "stat /dev/console");

        /* Opening /dev/tty preserves /dev/tty's device identity (5:0). */
        int tty_fd = open("/dev/tty", O_RDWR);
        CHECK(tty_fd >= 0, "open /dev/tty");
        CHECK(ioctl(tty_fd, TIOCGDEV, &dev) == 0 && dev == pts_st.st_rdev, "ctty TIOCGDEV");
        check_ctty_identity(tty_fd, "/dev/tty", 0, &tty_path_st, &pts_st);

        /* statx(AT_EMPTY_PATH) agrees with fstat on /dev/tty. */
        unsigned char stx[256];
        memset(stx, 0, sizeof(stx));
        CHECK(syscall(SYS_statx, tty_fd, "", AT_EMPTY_PATH, 0x7ffU, stx) == 0,
              "statx /dev/tty");
        uint64_t stx_ino;
        uint32_t stx_rdev_maj, stx_rdev_min, stx_dev_maj, stx_dev_min;
        memcpy(&stx_ino, stx + 32, sizeof(stx_ino));
        memcpy(&stx_rdev_maj, stx + 128, sizeof(stx_rdev_maj));
        memcpy(&stx_rdev_min, stx + 132, sizeof(stx_rdev_min));
        memcpy(&stx_dev_maj, stx + 136, sizeof(stx_dev_maj));
        memcpy(&stx_dev_min, stx + 140, sizeof(stx_dev_min));
        CHECK(stx_ino == tty_path_st.st_ino && stx_rdev_maj == 5 && stx_rdev_min == 0 &&
                  stx_dev_maj == major(tty_path_st.st_dev) &&
                  stx_dev_min == minor(tty_path_st.st_dev),
              "statx /dev/tty matches /dev/tty");

        /* fstatfs and fdinfo on /dev/tty. */
        struct statfs dev_sfs, tty_sfs;
        CHECK(statfs("/dev/tty", &dev_sfs) == 0 && fstatfs(tty_fd, &tty_sfs) == 0 &&
                  tty_sfs.f_type == dev_sfs.f_type,
              "fstatfs /dev/tty matches /dev");

        char proc_path[64];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fdinfo/%d", tty_fd);
        int fi = open(proc_path, O_RDONLY);
        CHECK(fi >= 0, "open fdinfo for /dev/tty");
        char fibuf[512];
        ssize_t fn = read(fi, fibuf, sizeof(fibuf) - 1);
        close(fi);
        CHECK(fn > 0, "read fdinfo for /dev/tty");
        fibuf[fn] = '\0';
        char expected_ino[64];
        snprintf(expected_ino, sizeof(expected_ino), "ino:\t%lu\n",
                 (unsigned long)tty_path_st.st_ino);
        CHECK(strstr(fibuf, expected_ino) != NULL, "fdinfo reports /dev/tty ino");

        /* Master-only ioctl stays ENOTTY; job control and I/O route to the ctty. */
        unsigned int dummy_ptn = 0;
        CHECK_ERR(ioctl(tty_fd, TIOCGPTN, &dummy_ptn), ENOTTY, "TIOCGPTN on /dev/tty");
        pid_t pg = 0, sid = 0;
        CHECK(ioctl(tty_fd, TIOCGPGRP, &pg) == 0 && pg == getpgrp(), "TIOCGPGRP on /dev/tty");
        CHECK(ioctl(tty_fd, TIOCGSID, &sid) == 0 && sid == getsid(0), "TIOCGSID on /dev/tty");

        CHECK(write(m, "hi\n", 3) == 3, "master write to /dev/tty");
        struct pollfd pf = {.fd = tty_fd, .events = POLLIN};
        CHECK(poll(&pf, 1, 1000) == 1 && (pf.revents & POLLIN) != 0, "poll /dev/tty POLLIN");
        char buf[32] = {0};
        CHECK(read(tty_fd, buf, sizeof(buf)) == 3 && memcmp(buf, "hi\n", 3) == 0,
              "read from /dev/tty");
        CHECK(write(tty_fd, "yo", 2) == 2, "write to /dev/tty");
        /* Drain echo ("hi\r\n") + "yo" from master. */
        char mbuf[32] = {0};
        size_t got = 0;
        while (got < 6) {
            ssize_t r = read(m, mbuf + got, sizeof(mbuf) - got);
            CHECK(r > 0, "master read from /dev/tty");
            got += (size_t)r;
        }
        CHECK(got == 6 && memcmp(mbuf + 4, "yo", 2) == 0, "master saw /dev/tty write");

        /* fchmod on /dev/tty acts on /dev/tty, not /dev/pts/N. */
        CHECK(fchmod(tty_fd, 0660) == 0, "fchmod /dev/tty");
        struct stat after_tty, after_pts;
        CHECK(stat("/dev/tty", &after_tty) == 0 && (after_tty.st_mode & 07777) == 0660,
              "/dev/tty mode changed");
        CHECK(stat(pts_path, &after_pts) == 0 && (after_pts.st_mode & 07777) == 0620,
              "/dev/pts/N mode unchanged");
        CHECK(fchmod(tty_fd, 0666) == 0, "restore /dev/tty mode");

        /* Opening /dev/console preserves /dev/console's device identity (5:1). */
        int con_fd = open("/dev/console", O_RDWR);
        CHECK(con_fd >= 0, "open /dev/console");
        check_ctty_identity(con_fd, "/dev/console", 1, &con_path_st, &pts_st);
        CHECK(write(m, "ok\n", 3) == 3, "master write to /dev/console");
        CHECK(read(con_fd, buf, sizeof(buf)) == 3 && memcmp(buf, "ok\n", 3) == 0,
              "read from /dev/console");

        /* Custom mknod 5:0 device node on rootfs keeps its identity across rename and unlink. */
        CHECK(mkdir("/tmp", 0777) == 0 || errno == EEXIST, "mkdir /tmp");
        const char *custom = "/tmp/custom_ctty";
        const char *custom2 = "/tmp/custom_ctty2";
        (void)unlink(custom);
        (void)unlink(custom2);
        CHECK(mknod(custom, S_IFCHR | 0640, makedev(5, 0)) == 0, "mknod custom 5:0");
        struct stat custom_path_st;
        CHECK(stat(custom, &custom_path_st) == 0, "stat custom 5:0");
        int custom_fd = open(custom, O_RDWR);
        CHECK(custom_fd >= 0, "open custom 5:0");
        struct stat custom_st;
        CHECK(fstat(custom_fd, &custom_st) == 0 && custom_st.st_ino == custom_path_st.st_ino &&
                  custom_st.st_dev == custom_path_st.st_dev &&
                  custom_st.st_dev != tty_path_st.st_dev &&
                  major(custom_st.st_rdev) == 5 && minor(custom_st.st_rdev) == 0 &&
                  (custom_st.st_mode & 07777) == 0640,
              "fstat custom 5:0");
        char *tn = ttyname(custom_fd);
        CHECK(tn && strcmp(tn, custom) == 0, "ttyname custom 5:0");
        CHECK(rename(custom, custom2) == 0, "rename custom 5:0");
        check_fd_link(custom_fd, custom2);
        CHECK(unlink(custom2) == 0, "unlink custom 5:0");
        CHECK(fstat(custom_fd, &custom_st) == 0 && custom_st.st_nlink == 0 &&
                  major(custom_st.st_rdev) == 5 && minor(custom_st.st_rdev) == 0,
              "fstat unlinked custom 5:0");
        check_fd_link(custom_fd, "/tmp/custom_ctty2 (deleted)");
        close(custom_fd);

        /* Direct /dev/pts/N slave still reports 136:N and /dev/pts/N. */
        tn = ttyname(s);
        CHECK(tn && strcmp(tn, pts_path) == 0, "ttyname pts slave (got %s)", tn ? tn : "(null)");
        CHECK(fstat(s, &pts_st) == 0 && major(pts_st.st_rdev) == 136 &&
                  minor(pts_st.st_rdev) == ptn,
              "fstat pts slave still 136:%u", ptn);

        /* After master close (hangup), /dev/tty reads EOF and still stats as 5:0. */
        CHECK(signal(SIGHUP, SIG_IGN) != SIG_ERR, "ignore SIGHUP before hangup");
        close(m);
        CHECK(read(tty_fd, buf, sizeof(buf)) == 0, "hung /dev/tty reads EOF");
        struct stat tty_st;
        CHECK(fstat(tty_fd, &tty_st) == 0 && major(tty_st.st_rdev) == 5 &&
                  minor(tty_st.st_rdev) == 0 && tty_st.st_ino == tty_path_st.st_ino,
              "hung /dev/tty keeps 5:0 fstat");

        close(con_fd);
        close(tty_fd);
        close(s);
        _exit(0);
    }
    wait_exit(child, 0);
}

static void test_tty_exclusive(void)
{
    pid_t child = fork();
    CHECK(child >= 0, "fork exclusive tty");
    if (child == 0) {
        CHECK(setsid() > 0, "setsid");
        int m, s, bit;
        CHECK(open_pty_pair(&m, &s, O_RDWR) == 0, "open controlling tty");
        char *path = ptsname(m);
        CHECK(path && chmod(path, 0666) == 0, "allow unprivileged slave open");
        CHECK(ioctl(m, TIOCEXCL) == 0 && ioctl(s, TIOCGEXCL, &bit) == 0 && bit == 0,
              "master exclusivity is separate");
        CHECK(ioctl(s, TIOCEXCL) == 0 && ioctl(s, TIOCGEXCL, &bit) == 0 && bit == 1,
              "exclusive slave");
        int admin = open(path, O_RDWR);
        CHECK(admin >= 0, "privileged reopen");
        close(admin);
        CHECK(setuid(1000) == 0, "drop privileges");
        CHECK_ERR(open(path, O_RDWR), EBUSY, "exclusive slave path");
        CHECK_ERR(open("/dev/tty", O_RDWR), EBUSY, "exclusive controlling tty");
        CHECK_ERR(ioctl(m, TIOCGPTPEER, O_RDWR), EBUSY, "exclusive peer");
        int flags = O_PATH | O_CLOEXEC | O_NONBLOCK;
        int pathfd = ioctl(m, TIOCGPTPEER, flags);
        CHECK(pathfd >= 0 && fcntl(pathfd, F_GETFL) == flags &&
                  fcntl(pathfd, F_GETFD) == FD_CLOEXEC, "path-only peer flags");
        close(pathfd);
        CHECK(ioctl(s, TIOCNXCL) == 0 && ioctl(s, TIOCGEXCL, &bit) == 0 && bit == 0,
              "clear slave exclusivity");
        CHECK(open(path, O_RDWR) >= 0, "reopen after clearing");
        _exit(0);
    }
    wait_exit(child, 0);
}

static volatile sig_atomic_t break_ttou;

static void on_break_ttou(int sig)
{
    break_ttou = sig;
}

static void test_tty_job_control_ioctls(void)
{
    /* Test TIOCSCTTY and TIOCSPGRP in a fresh session. */
    pid_t leader = fork();
    CHECK(leader >= 0, "fork leader");
    if (leader == 0) {
        CHECK(setsid() > 0, "setsid");
        int m = -1, s = -1;
        CHECK(open_pty_pair(&m, &s, O_RDWR) == 0, "open_pty_pair");

        /* Session leader calling TIOCSCTTY on its own ctty succeeds. */
        CHECK(ioctl(s, TIOCSCTTY, 0) == 0, "leader TIOCSCTTY own ctty");

        /* PTYs accept break requests on either end. Only the controlling slave checks
         * the caller's foreground process group. */
        const int breaks[] = {TIOCSBRK, TIOCCBRK, TCSBRK, TCSBRKP};
        for (size_t i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
            CHECK(ioctl(m, breaks[i], 0) == 0 && ioctl(s, breaks[i], 0) == 0,
                  "foreground break ioctl %#x", breaks[i]);
        }
        pid_t bg = fork();
        CHECK(bg >= 0, "fork background break caller");
        if (bg == 0) {
            struct sigaction sa = {.sa_handler = on_break_ttou};
            CHECK(sigaction(SIGTTOU, &sa, NULL) == 0, "catch SIGTTOU");
            CHECK(setpgid(0, 0) == 0, "background setpgid");
            for (size_t i = 0; i < sizeof(breaks) / sizeof(breaks[0]); i++) {
                break_ttou = 0;
                CHECK(ioctl(m, breaks[i], 0) == 0 && !break_ttou, "master break %#x", breaks[i]);
                CHECK_ERR(ioctl(s, breaks[i], 0), EINTR, "background slave break %#x", breaks[i]);
                CHECK(break_ttou == SIGTTOU, "slave break %#x sends SIGTTOU", breaks[i]);
            }
            _exit(0);
        }
        wait_exit(bg, 0);

        /* TIOCSPGRP with pgid=0 or nonexistent pgid returns ESRCH. */
        pid_t pg = 0;
        CHECK_ERR(ioctl(s, TIOCSPGRP, &pg), ESRCH, "TIOCSPGRP(0) -> ESRCH");
        pg = 999999;
        CHECK_ERR(ioctl(s, TIOCSPGRP, &pg), ESRCH, "TIOCSPGRP(unknown) -> ESRCH");

        /* TIOCSPGRP with a pgid in another session returns EPERM. */
        pid_t parent_pg = getpgid(getppid());
        CHECK_ERR(ioctl(s, TIOCSPGRP, &parent_pg), EPERM, "TIOCSPGRP(other session) -> EPERM");

        /* Non-ctty PTY: bad pointer -> EFAULT, negative -> EINVAL, valid -> ENOTTY. */
        int m2 = -1, s2 = -1;
        CHECK(open_pty_pair(&m2, &s2, O_RDWR | O_NOCTTY) == 0, "open second pty");
        CHECK_ERR(ioctl(s2, TIOCSPGRP, (void *)0x10), EFAULT,
                  "non-ctty TIOCSPGRP bad ptr -> EFAULT");
        pg = -1;
        CHECK_ERR(ioctl(s2, TIOCSPGRP, &pg), EINVAL, "non-ctty TIOCSPGRP negative -> EINVAL");
        pg = getpgrp();
        CHECK_ERR(ioctl(s2, TIOCSPGRP, &pg), ENOTTY, "non-ctty TIOCSPGRP valid -> ENOTTY");
        close(m2);
        close(s2);

        /* Non-leader child inherits ctty: TIOCSCTTY must return EPERM (not 0). */
        pid_t nonleader = fork();
        CHECK(nonleader >= 0, "fork nonleader");
        if (nonleader == 0) {
            CHECK_ERR(ioctl(s, TIOCSCTTY, 0), EPERM, "non-leader TIOCSCTTY on own ctty -> EPERM");
            _exit(0);
        }
        wait_exit(nonleader, 0);

        /* Orphaned background process group calling TIOCSPGRP gets ENOTTY (not EIO). */
        int pfd[2];
        CHECK(pipe(pfd) == 0, "pipe");
        pid_t mid = fork();
        CHECK(mid >= 0, "fork mid");
        if (mid == 0) {
            close(pfd[0]);
            /* Put grandchild in its own pgrp within the same session, then exit mid so grandchild's
             * parent becomes init (different session) -> orphaned pgrp! */
            pid_t mid_pid = getpid();
            pid_t gc = fork();
            CHECK(gc >= 0, "fork grandchild");
            if (gc == 0) {
                CHECK(setpgid(0, 0) == 0, "grandchild setpgid");
                /* Wait until mid exits and we are reparented away from mid. */
                while (getppid() == mid_pid) {
                    msleep(1);
                }
                pid_t mypg = getpgrp();
                errno = 0;
                int rc = ioctl(s, TIOCSPGRP, &mypg);
                int err = errno;
                int out[2] = {rc, err};
                CHECK(write(pfd[1], out, sizeof(out)) == (ssize_t)sizeof(out), "write result");
                _exit(0);
            }
            (void)setpgid(gc, gc);
            close(pfd[1]);
            _exit(0);
        }
        close(pfd[1]);
        wait_exit(mid, 0);
        int res[2] = {0, 0};
        CHECK(read(pfd[0], res, sizeof(res)) == (ssize_t)sizeof(res), "read orphan result");
        close(pfd[0]);
        CHECK(res[0] == -1 && res[1] == ENOTTY,
              "orphaned background TIOCSPGRP expected -1/ENOTTY, got %d/%d", res[0], res[1]);

        /* Closing the last master sends SIGHUP to the session leader; ignore it before cleanup. */
        signal(SIGHUP, SIG_IGN);
        close(s);
        close(m);
        _exit(0);
    }

    wait_exit(leader, 0);
}

/* ---- 12. PTY slave write clamps ONLCR and XTABS expansion to OUTPUT_MAX ---- */

static size_t drain_fd(int fd)
{
    size_t total = 0;
    char tmp[4096];
    for (;;) {
        ssize_t n = read(fd, tmp, sizeof(tmp));
        if (n < 0 && errno == EAGAIN)
            return total;
        CHECK(n > 0, "drain master output");
        total += (size_t)n;
    }
}

static void test_tty_output_clamp(void)
{
    int m = -1, s = -1;
    CHECK(open_pty_pair(&m, &s, O_RDWR | O_NOCTTY | O_NONBLOCK) == 0, "open_pty_pair");
    int fl = fcntl(m, F_GETFL);
    CHECK(fl >= 0 && fcntl(m, F_SETFL, fl | O_NONBLOCK) == 0, "master O_NONBLOCK");

    struct termios tio;
    CHECK(tcgetattr(s, &tio) == 0, "tcgetattr");
    tio.c_oflag = OPOST | ONLCR | XTABS;
    CHECK(tcsetattr(s, TCSANOW, &tio) == 0, "tcsetattr");

    int queued;
    CHECK(write(m, "in\n", 3) == 3, "write canonical input");
    CHECK(ioctl(s, FIONREAD, &queued) == 0 && queued == 3, "slave FIONREAD");
    CHECK(ioctl(m, FIONREAD, &queued) == 0 && queued == 4, "master FIONREAD counts echo");
    CHECK(ioctl(m, TIOCOUTQ, &queued) == 0 && queued == 0, "master TIOCOUTQ");
    queued = -1;
    CHECK(ioctl(s, TIOCOUTQ, &queued) == 0 && queued == 0, "slave TIOCOUTQ");
    CHECK(drain_fd(m) == 4, "drain echoed line");

    /* Fill with newlines: ONLCR doubles bytes, so output queue must never exceed 65536. */
    char *nls = malloc(65536);
    CHECK(nls != NULL, "malloc");
    memset(nls, '\n', 65536);
    ssize_t w = write(s, nls, 65536);
    CHECK(w == 32768, "ONLCR write expected 32768, got %zd", w);
    CHECK(ioctl(m, FIONREAD, &queued) == 0 && queued == 4095,
          "master FIONREAD at capacity, got %d", queued);

    /* With 1 byte free, writing '\n' must return EAGAIN and not overshoot 65536. */
    char one;
    CHECK(read(m, &one, 1) == 1, "read 1 byte");
    CHECK_ERR(write(s, "\n", 1), EAGAIN, "ONLCR write with 1 byte free must return EAGAIN");
    CHECK(drain_fd(m) == 65535, "remaining ONLCR output");

    /* Fill with tabs from column 0: XTABS expands each tab to 8 spaces -> at most 8192 tabs. */
    CHECK(write(s, "\r", 1) == 1, "reset column");
    CHECK(drain_fd(m) == 1, "drain carriage return");
    memset(nls, '\t', 65536);
    w = write(s, nls, 65536);
    CHECK(w == 8192, "XTABS write expected 8192, got %zd", w);
    CHECK(drain_fd(m) == 65536, "expanded XTABS output");

    free(nls);
    close(s);
    close(m);
}

/* ---- 13. Exited (zombie) main thread's CPU clock stays readable & stopped until reaped ---- */

static void *keep_process_alive(void *arg)
{
    int release_fd = (int)(intptr_t)arg;
    /* Wait until parent tells us to exit. */
    char c;
    (void)read(release_fd, &c, 1);
    _exit(0);
}

static clockid_t thread_cpu_clock(pid_t tid)
{
    /* MAKE_THREAD_CPUCLOCK(tid, CPUCLOCK_SCHED) = (~tid << 3) | 4 | 2 */
    return (clockid_t)((~(uint32_t)tid << 3) | 6U);
}

static void test_zombie_leader_cpu_clock(void)
{
    int p_ready[2], p_go[2], p_release[2];
    CHECK(pipe(p_ready) == 0 && pipe(p_go) == 0 && pipe(p_release) == 0, "pipes");

    pid_t child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0) {
        close(p_ready[0]);
        close(p_go[1]);
        close(p_release[1]);
        /* Burn a tiny bit of CPU so leader's CPU clock is > 0. */
        volatile uint64_t spin = 0;
        for (int i = 0; i < 200000; i++) {
            spin += (uint64_t)i;
        }
        (void)spin;

        pthread_t th;
        CHECK(pthread_create(&th, NULL, keep_process_alive, (void *)(intptr_t)p_release[0]) == 0,
              "pthread_create");

        /* Tell parent we're ready so parent can create a POSIX timer on our thread CPU clock
         * before we exit. */
        char c = 1;
        CHECK(write(p_ready[1], &c, 1) == 1, "signal ready");
        CHECK(read(p_go[0], &c, 1) == 1, "wait go");
        close(p_ready[1]);
        close(p_go[0]);
        /* Exit ONLY the main thread so it becomes a zombie leader while the worker runs. */
        syscall(SYS_exit, 0);
        __builtin_unreachable();
    }
    close(p_ready[1]);
    close(p_go[0]);
    close(p_release[0]);

    char c;
    CHECK(read(p_ready[0], &c, 1) == 1, "read ready");
    close(p_ready[0]);

    clockid_t clk = thread_cpu_clock(child);
    struct timespec t_live = {0};
    CHECK(clock_gettime(clk, &t_live) == 0, "clock_gettime live leader");

    /* Create and arm a POSIX timer on the leader's thread CPU clock while alive. */
    timer_t tid_timer;
    struct sigevent sev = {0};
    sev.sigev_notify = SIGEV_NONE;
    CHECK(timer_create(clk, &sev, &tid_timer) == 0, "timer_create on leader clock");
    struct itimerspec its = {
        .it_interval = {.tv_sec = 0, .tv_nsec = 50000000},
        .it_value = {.tv_sec = 10, .tv_nsec = 0},
    };
    CHECK(timer_settime(tid_timer, 0, &its, NULL) == 0, "timer_settime live leader");

    /* Let the leader exit while its worker thread keeps the process alive. */
    CHECK(write(p_go[1], &c, 1) == 1, "tell leader to exit");
    close(p_go[1]);

    /* Wait for leader to become a zombie (check /proc/<child>/stat shows 'Z' or sleep briefly). */
    for (int i = 0; i < 200; i++) {
        char path[64], buf[256];
        snprintf(path, sizeof(path), "/proc/%d/stat", child);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                char *rp = strrchr(buf, ')');
                if (rp && rp[1] == ' ' && rp[2] == 'Z') {
                    break;
                }
            }
        }
        msleep(2);
    }

    /* Zombie leader's thread CPU clock must STILL be readable, non-decreasing, and stopped! */
    struct timespec t_z1 = {0}, t_z2 = {0};
    CHECK(clock_gettime(clk, &t_z1) == 0, "clock_gettime zombie leader while worker runs");
    msleep(15);
    CHECK(clock_gettime(clk, &t_z2) == 0, "clock_gettime zombie leader second read");
    CHECK(t_z1.tv_sec == t_z2.tv_sec && t_z1.tv_nsec == t_z2.tv_nsec,
          "zombie leader CPU clock must be stopped");

    /* Timer on zombie leader must still report remaining time and accept timer_settime! */
    struct itimerspec cur = {0};
    CHECK(timer_gettime(tid_timer, &cur) == 0, "timer_gettime on zombie leader");
    CHECK(cur.it_value.tv_sec > 0 || cur.it_value.tv_nsec > 0,
          "timer_gettime on zombie leader must not read all zeros");
    CHECK(cur.it_interval.tv_nsec == 50000000, "timer_gettime interval preserved");
    CHECK(timer_settime(tid_timer, 0, &its, NULL) == 0,
          "timer_settime on zombie leader must succeed (not ESRCH)");

    /* Also verify creating a NEW timer on an already-zombie leader works. */
    timer_t tid_timer2;
    CHECK(timer_create(clk, &sev, &tid_timer2) == 0, "timer_create on zombie leader");
    CHECK(timer_delete(tid_timer2) == 0, "timer_delete second timer");

    /* Now release the worker so the whole process exits, then reap it. */
    CHECK(write(p_release[1], &c, 1) == 1, "release worker");
    close(p_release[1]);
    wait_exit(child, 0);

    /* Once reaped, the leader's CPU clock and timer are gone. */
    CHECK_ERR(clock_gettime(clk, &t_z1), EINVAL, "clock_gettime after reap must return EINVAL");
    CHECK_ERR(timer_settime(tid_timer, 0, &its, NULL), ESRCH,
              "timer_settime after reap must return ESRCH");
    CHECK(timer_gettime(tid_timer, &cur) == 0 &&
          cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec == 0 &&
          cur.it_interval.tv_sec == 0 && cur.it_interval.tv_nsec == 0,
          "timer_gettime after reap must read all zeros");
    CHECK(timer_delete(tid_timer) == 0, "timer_delete");
}

/* ---- Local seccomp UAPI definitions (musl has no linux/seccomp.h) ---- */

struct sc_sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};
struct sc_sock_fprog {
    unsigned short len;
    struct sc_sock_filter *filter;
};
struct sc_seccomp_data {
    int nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
};
struct sc_notif {
    uint64_t id;
    uint32_t pid, flags;
    struct sc_seccomp_data data;
};
struct sc_notif_resp {
    uint64_t id;
    int64_t val;
    int32_t error;
    uint32_t flags;
};

#define SC_BPF_LD   0x00
#define SC_BPF_JMP  0x05
#define SC_BPF_RET  0x06
#define SC_BPF_W    0x00
#define SC_BPF_ABS  0x20
#define SC_BPF_JEQ  0x10
#define SC_BPF_K    0x00
#define SC_STMT(c, k) {(uint16_t)(c), 0, 0, (uint32_t)(k)}
#define SC_JUMP(c, k, t, f) {(uint16_t)(c), (t), (f), (uint32_t)(k)}
#define SC_RET_ERRNO      0x00050000U
#define SC_RET_USER_NOTIF 0x7fc00000U
#define SC_RET_LOG        0x7ffc0000U
#define SC_RET_ALLOW      0x7fff0000U
#define SC_FLAG_LOG          2U
#define SC_FLAG_NEW_LISTENER 8U
#define SC_NOTIF_RECV 0xc0502100U
#define SC_NOTIF_SEND 0xc0182101U

struct sc_pt_regs {
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
};

static volatile sig_atomic_t g_skip_usr1 = 0;
static void on_skip_usr1(int sig)
{
    (void)sig;
    g_skip_usr1++;
}

static long raw_svc_getpid(void)
{
    register long x8 __asm__("x8") = SYS_getpid;
    register long x0 __asm__("x0") = 0x1234;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
    return x0;
}

static void send_fd_over_unix(int sock, int fd)
{
    char c = 'x';
    struct iovec iov = {&c, 1};
    char ctrl[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    CHECK(sendmsg(sock, &msg, 0) == 1, "sendmsg fd");
}

static int recv_fd_over_unix(int sock)
{
    char c = 0;
    struct iovec iov = {&c, 1};
    char ctrl[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl;
    msg.msg_controllen = sizeof(ctrl);
    CHECK(recvmsg(sock, &msg, 0) == 1, "recvmsg fd");
    struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
    CHECK(cm && cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS, "cmsg");
    int fd = -1;
    memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    return fd;
}

static void write_str_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    CHECK(fd >= 0, "open %s", path);
    ssize_t len = (ssize_t)strlen(s);
    CHECK(write(fd, s, (size_t)len) == len, "write %s", path);
    close(fd);
}

/*
 * 1. Skipped syscalls (NO_SYSCALL via ptrace or seccomp) must pass syscall=false to
 * signal::deliver so x0=-512..-516 does not rewind pc; interrupted USER_NOTIF still restarts.
 */
static void test_skipped_syscall_no_restart(void)
{
    /* Case A: tracer skips SYS_getpid with NO_SYSCALL and writes -512 (-ERESTARTSYS) + SIGUSR1,
     * and then skips a second SYS_getpid with -513 (-ERESTARTNOINTR) and no signal. */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        g_skip_usr1 = 0;
        struct sigaction sa = {0};
        sa.sa_handler = on_skip_usr1;
        sa.sa_flags = SA_RESTART;
        CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
        CHECK(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0, "PTRACE_TRACEME");
        raise(SIGSTOP);
        long r1 = raw_svc_getpid();
        CHECK(r1 == -512, "ptrace skip -512 got %ld", r1);
        CHECK(g_skip_usr1 == 1, "expected 1 SIGUSR1, got %d", (int)g_skip_usr1);
        long r2 = raw_svc_getpid();
        CHECK(r2 == -513, "ptrace skip -513 got %ld", r2);
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFSTOPPED(st), "initial stop");
    CHECK(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == 0, "setoptions");
    CHECK(ptrace(PTRACE_SYSCALL, pid, 0, 0) == 0, "cont1");
    int skips = 0;
    for (;;) {
        CHECK(waitpid(pid, &st, 0) == pid, "waitpid");
        if (WIFEXITED(st)) {
            CHECK(WEXITSTATUS(st) == 0, "child exit %d", WEXITSTATUS(st));
            break;
        }
        CHECK(WIFSTOPPED(st), "unexpected status %#x", st);
        int sig = WSTOPSIG(st);
        if (sig == (SIGTRAP | 0x80)) {
            int scno = 0;
            struct iovec siov = {&scno, sizeof(scno)};
            CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &siov) == 0,
                  "get scno");
            if (scno == SYS_getpid) {
                int neg1 = -1;
                struct iovec niov = {&neg1, sizeof(neg1)};
                CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_ARM_SYSTEM_CALL, &niov) == 0,
                      "set NO_SYSCALL");
                struct sc_pt_regs regs;
                struct iovec riov = {&regs, sizeof(regs)};
                CHECK(ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &riov) == 0, "get regs");
                regs.regs[0] = (skips == 0) ? (uint64_t)(-512LL) : (uint64_t)(-513LL);
                CHECK(ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &riov) == 0, "set regs");
                if (skips == 0)
                    CHECK(kill(pid, SIGUSR1) == 0, "kill SIGUSR1");
                skips++;
            }
            CHECK(ptrace(PTRACE_SYSCALL, pid, 0, 0) == 0, "syscall cont");
        } else {
            CHECK(ptrace(PTRACE_SYSCALL, pid, 0, sig) == 0, "sig cont");
        }
    }
    CHECK(skips == 2, "expected 2 skipped syscalls (no rewind), got %d", skips);

    /* Case B: seccomp SECCOMP_RET_ERRNO | 512 must return -512 without rewinding pc. */
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ERRNO | 512),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        CHECK(syscall(SYS_seccomp, 1, 0, &p) == 0, "seccomp errno 512");
        errno = 0;
        long r = syscall(SYS_getppid);
        CHECK(r == -1 && errno == 512, "seccomp ERRNO|512 got r=%ld errno=%d", r, errno);
        _exit(0);
    }
    wait_exit(pid, 0);

    /* Case C: interrupted SECCOMP_RET_USER_NOTIF with SA_RESTART must still restart. */
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(sv[0]);
        g_skip_usr1 = 0;
        struct sigaction sa = {0};
        sa.sa_handler = on_skip_usr1;
        sa.sa_flags = SA_RESTART;
        CHECK(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction");
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_USER_NOTIF),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        int l = (int)syscall(SYS_seccomp, 1, SC_FLAG_NEW_LISTENER, &p);
        CHECK(l >= 0, "seccomp listener");
        send_fd_over_unix(sv[1], l);
        close(l);
        close(sv[1]);
        long r = syscall(SYS_getppid);
        CHECK(r == 77 && g_skip_usr1 == 1, "restarted notif got r=%ld usr1=%d", r, (int)g_skip_usr1);
        _exit(0);
    }
    close(sv[1]);
    int lfd = recv_fd_over_unix(sv[0]);
    close(sv[0]);
    struct sc_notif n1 = {0};
    CHECK(ioctl(lfd, SC_NOTIF_RECV, &n1) == 0, "notif recv 1");
    CHECK(kill(pid, SIGUSR1) == 0, "kill SIGUSR1");
    struct sc_notif n2 = {0};
    CHECK(ioctl(lfd, SC_NOTIF_RECV, &n2) == 0, "notif recv 2 (restarted)");
    CHECK(n2.id != n1.id, "restarted notif id");
    struct sc_notif_resp resp = {n2.id, 77, 0, 0};
    CHECK(ioctl(lfd, SC_NOTIF_SEND, &resp) == 0, "notif send");
    close(lfd);
    wait_exit(pid, 0);
}

/*
 * 2. Core dumps ignore umask (always 0600), honor RLIMIT_FSIZE, and follow /proc/sys/fs/suid_dumpable
 * (0 = disable, 1 = user, 2 = root/suidsafe with absolute core_pattern and no overwrite).
 */
static void test_coredump_umask_fsize_suid_dumpable(void)
{
    const char *dir = "/tmp/coredump-reg";
    mkdir(dir, 0777);
    CHECK(chmod(dir, 0777) == 0, "chmod dir");
    char old_cwd[256];
    CHECK(getcwd(old_cwd, sizeof(old_cwd)) != NULL, "getcwd");
    CHECK(chdir(dir) == 0, "chdir");
    write_str_file("/proc/sys/kernel/core_pattern", "core\n");
    write_str_file("/proc/sys/fs/suid_dumpable", "0\n");

    /* A. umask(0777) must still produce mode 0600 core file. */
    unlink("/tmp/coredump-reg/core");
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        umask(0777);
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit core");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WCOREDUMP(st), "umask dump");
    struct stat sb;
    CHECK(stat("/tmp/coredump-reg/core", &sb) == 0, "stat core");
    CHECK((sb.st_mode & 0777) == 0600, "core mode %04o expected 0600", sb.st_mode & 0777);
    unlink("/tmp/coredump-reg/core");

    /* B. RLIMIT_FSIZE truncates the core file. */
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl_c = {RLIM_INFINITY, RLIM_INFINITY};
        struct rlimit rl_f = {4096, 4096};
        CHECK(setrlimit(RLIMIT_CORE, &rl_c) == 0, "setrlimit core");
        CHECK(setrlimit(RLIMIT_FSIZE, &rl_f) == 0, "setrlimit fsize");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WCOREDUMP(st), "fsize dump");
    CHECK(stat("/tmp/coredump-reg/core", &sb) == 0 && sb.st_size > 0 && sb.st_size <= 4096,
          "fsize core size %ld", (long)sb.st_size);
    unlink("/tmp/coredump-reg/core");

    /* C. fs/suid_dumpable = 0: setresuid(1000) sets dumpable=0, no core dumped. */
    write_str_file("/proc/sys/fs/suid_dumpable", "0\n");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        CHECK(prctl(PR_GET_DUMPABLE) == 0, "suid_dumpable=0 get");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && !WCOREDUMP(st), "suid=0 no dump");
    CHECK(stat("/tmp/coredump-reg/core", &sb) == -1 && errno == ENOENT, "suid=0 no file");

    /* D. fs/suid_dumpable = 1: setresuid(1000) sets dumpable=1, core owned by uid 1000. */
    write_str_file("/proc/sys/fs/suid_dumpable", "1\n");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        CHECK(prctl(PR_GET_DUMPABLE) == 1, "suid_dumpable=1 get");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WCOREDUMP(st), "suid=1 dump");
    CHECK(stat("/tmp/coredump-reg/core", &sb) == 0 && sb.st_uid == 1000 &&
              (sb.st_mode & 0777) == 0600,
          "suid=1 uid=%u mode=%04o", sb.st_uid, sb.st_mode & 0777);
    unlink("/tmp/coredump-reg/core");

    /* E. fs/suid_dumpable = 2: setresuid(1000) sets dumpable=2; PR_SET_DUMPABLE(2) is EINVAL;
     * /proc/<pid> belongs to root; relative core_pattern refuses dump; absolute core_pattern dumps
     * root-owned 0600 core with %d=2 and refuses to overwrite an existing file. */
    write_str_file("/proc/sys/fs/suid_dumpable", "2\n");
    int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    CHECK(kmsg >= 0 && lseek(kmsg, 0, SEEK_END) >= 0, "open kmsg");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        CHECK(prctl(PR_GET_DUMPABLE) == 2, "suid_dumpable=2 get");
        CHECK_ERR(prctl(PR_SET_DUMPABLE, 2), EINVAL, "PR_SET_DUMPABLE(2) must fail EINVAL");
        struct stat psb;
        CHECK(stat("/proc/self", &psb) == 0 && psb.st_uid == 0,
              "/proc/self uid=%u expected 0 under suid_dumpable=2", psb.st_uid);
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && !WCOREDUMP(st),
          "suid=2 relative pattern must not dump");
    char kbuf[2048];
    int saw_warn = 0;
    for (;;) {
        ssize_t n = read(kmsg, kbuf, sizeof(kbuf) - 1);
        if (n <= 0)
            break;
        kbuf[n] = 0;
        if (strstr(kbuf, "Unsafe core_pattern used with fs.suid_dumpable=2"))
            saw_warn = 1;
    }
    CHECK(saw_warn, "expected klog warning for relative core_pattern with suid_dumpable=2");
    close(kmsg);

    write_str_file("/proc/sys/kernel/core_pattern", "/tmp/coredump-reg/suid.%p.%d\n");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && WCOREDUMP(st),
          "suid=2 absolute pattern must dump");
    char path[128];
    snprintf(path, sizeof(path), "/tmp/coredump-reg/suid.%d.2", pid);
    CHECK(stat(path, &sb) == 0 && sb.st_uid == 0 && (sb.st_mode & 0777) == 0600,
          "suid=2 core %s uid=%u mode=%04o", path, sb.st_uid, sb.st_mode & 0777);
    unlink(path);

    /* Existing file at fixed absolute path must NOT be unlinked/overwritten under suid_dumpable=2. */
    write_str_file("/proc/sys/kernel/core_pattern", "/tmp/coredump-reg/existing\n");
    int efd = open("/tmp/coredump-reg/existing", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    CHECK(efd >= 0 && write(efd, "keep", 4) == 4, "create existing");
    close(efd);
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_CORE, &rl) == 0, "setrlimit");
        CHECK(setresuid(1000, 1000, 1000) == 0, "setresuid");
        *(volatile int *)0 = 1;
        _exit(0);
    }
    CHECK(waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) && !WCOREDUMP(st),
          "suid=2 must not overwrite existing");
    efd = open("/tmp/coredump-reg/existing", O_RDONLY);
    char keep[8] = {0};
    CHECK(efd >= 0 && read(efd, keep, sizeof(keep)) == 4 && memcmp(keep, "keep", 4) == 0,
          "existing file preserved");
    close(efd);
    unlink("/tmp/coredump-reg/existing");

    write_str_file("/proc/sys/kernel/core_pattern", "core\n");
    write_str_file("/proc/sys/fs/suid_dumpable", "0\n");
    CHECK(chdir(old_cwd) == 0, "restore cwd");
}

static int find_kmsg_audit(int kmsg, const char *needle1, const char *needle2)
{
    char buf[2048];
    int found = 0;
    for (;;) {
        ssize_t n = read(kmsg, buf, sizeof(buf) - 1);
        if (n < 0 && errno == EAGAIN)
            break;
        CHECK(n > 0, "read kmsg");
        buf[n] = 0;
        if (strstr(buf, "audit: type=1326 ") && strstr(buf, needle1) && strstr(buf, needle2)) {
            CHECK((atoi(buf) & 7) == 5, "expected KERN_NOTICE (5), got %d: %s", atoi(buf) & 7, buf);
            found++;
        }
    }
    return found;
}

/*
 * 3. Seccomp logged actions emit Linux-style audit: type=1326 records to guest klog, including
 * SECCOMP_RET_USER_NOTIF when SECCOMP_FILTER_FLAG_LOG is set, and honor actions_logged.
 */
static void test_seccomp_klog_and_user_notif_log(void)
{
    int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
    CHECK(kmsg >= 0 && lseek(kmsg, 0, SEEK_END) >= 0, "open kmsg");

    char nr_needle[32];
    snprintf(nr_needle, sizeof(nr_needle), "syscall=%d ", SYS_getppid);

    /* A. SECCOMP_RET_LOG always logs to klog. */
    pid_t pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_LOG),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        CHECK(syscall(SYS_seccomp, 1, 0, &p) == 0, "seccomp RET_LOG");
        (void)syscall(SYS_getppid);
        _exit(0);
    }
    wait_exit(pid, 0);
    CHECK(find_kmsg_audit(kmsg, nr_needle, "code=0x7ffc0000") == 1, "RET_LOG kmsg");

    /* B. SECCOMP_RET_ERRNO without FLAG_LOG does NOT log; with FLAG_LOG DOES log. */
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ERRNO | EPERM),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        CHECK(syscall(SYS_seccomp, 1, 0, &p) == 0, "seccomp ERRNO no-log");
        CHECK_ERR(syscall(SYS_getppid), EPERM, "ERRNO no-log");
        _exit(0);
    }
    wait_exit(pid, 0);
    CHECK(find_kmsg_audit(kmsg, nr_needle, "code=0x50000") == 0, "ERRNO without FLAG_LOG");

    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ERRNO | EPERM),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        CHECK(syscall(SYS_seccomp, 1, SC_FLAG_LOG, &p) == 0, "seccomp ERRNO FLAG_LOG");
        CHECK_ERR(syscall(SYS_getppid), EPERM, "ERRNO FLAG_LOG");
        _exit(0);
    }
    wait_exit(pid, 0);
    CHECK(find_kmsg_audit(kmsg, nr_needle, "code=0x50000") == 1, "ERRNO with FLAG_LOG");

    /* C. SECCOMP_RET_USER_NOTIF with FLAG_LOG logs to klog. */
    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        close(sv[0]);
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_USER_NOTIF),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        int l = (int)syscall(SYS_seccomp, 1, SC_FLAG_NEW_LISTENER | SC_FLAG_LOG, &p);
        CHECK(l >= 0, "seccomp USER_NOTIF FLAG_LOG");
        send_fd_over_unix(sv[1], l);
        close(l);
        close(sv[1]);
        CHECK(syscall(SYS_getppid) == 55, "USER_NOTIF reply");
        _exit(0);
    }
    close(sv[1]);
    int lfd = recv_fd_over_unix(sv[0]);
    close(sv[0]);
    struct sc_notif n = {0};
    CHECK(ioctl(lfd, SC_NOTIF_RECV, &n) == 0, "notif recv");
    struct sc_notif_resp resp = {n.id, 55, 0, 0};
    CHECK(ioctl(lfd, SC_NOTIF_SEND, &resp) == 0, "notif send");
    close(lfd);
    wait_exit(pid, 0);
    CHECK(find_kmsg_audit(kmsg, nr_needle, "code=0x7fc00000") == 1, "USER_NOTIF with FLAG_LOG");

    /* D. actions_logged suppresses disabled actions. */
    write_str_file("/proc/sys/kernel/seccomp/actions_logged", "kill_process kill_thread\n");
    pid = fork();
    CHECK(pid >= 0, "fork");
    if (pid == 0) {
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "nnp");
        struct sc_sock_filter f[] = {
            SC_STMT(SC_BPF_LD | SC_BPF_W | SC_BPF_ABS, offsetof(struct sc_seccomp_data, nr)),
            SC_JUMP(SC_BPF_JMP | SC_BPF_JEQ | SC_BPF_K, SYS_getppid, 0, 1),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_LOG),
            SC_STMT(SC_BPF_RET | SC_BPF_K, SC_RET_ALLOW),
        };
        struct sc_sock_fprog p = {4, f};
        CHECK(syscall(SYS_seccomp, 1, 0, &p) == 0, "seccomp RET_LOG suppressed");
        (void)syscall(SYS_getppid);
        _exit(0);
    }
    wait_exit(pid, 0);
    CHECK(find_kmsg_audit(kmsg, nr_needle, "code=0x7ffc0000") == 0, "RET_LOG suppressed");
    write_str_file("/proc/sys/kernel/seccomp/actions_logged",
                   "kill_process kill_thread trap errno user_notif trace log\n");
    close(kmsg);
}

/*
 * 4. MRS of unallocated CRm=0 and CRm=1 ID registers delivers SIGILL in both Tier 0 and Tier 1,
 * while MIDR_EL1, MPIDR_EL1, and REVIDR_EL1 succeed.
 */
static void test_mrs_unallocated_id_regs_sigill(void)
{
    uint64_t midr = 0, mpidr = 0, revidr = 0x1234;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(mpidr));
    __asm__ volatile("mrs %0, s3_0_c0_c0_6" : "=r"(revidr)); /* REVIDR_EL1 */
    (void)midr;
    CHECK(mpidr == (1ULL << 31), "mpidr %#lx", (unsigned long)mpidr);
    CHECK(revidr == 0, "revidr %#lx", (unsigned long)revidr);

    const uint32_t bad_insns[] = {
        0xd5380020U, /* mrs x0, s3_0_c0_c0_1 */
        0xd53800e0U, /* mrs x0, s3_0_c0_c0_7 */
        0xd5380100U, /* mrs x0, s3_0_c0_c1_0 */
        0xd53801e0U, /* mrs x0, s3_0_c0_c1_7 */
    };
    for (size_t i = 0; i < sizeof(bad_insns) / sizeof(bad_insns[0]); i++) {
        pid_t pid = fork();
        CHECK(pid >= 0, "fork");
        if (pid == 0) {
            uint32_t *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            CHECK(code != MAP_FAILED, "mmap");
            code[0] = bad_insns[i];
            code[1] = 0xd65f03c0U; /* ret */
            __builtin___clear_cache((char *)code, (char *)code + 8);
            ((void (*)(void))code)();
            _exit(0);
        }
        int st = 0;
        CHECK(waitpid(pid, &st, 0) == pid, "waitpid");
        CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGILL,
              "insn %#x expected SIGILL, got status %#x", bad_insns[i], st);
    }
}

/* RT signals when RLIMIT_SIGPENDING is full: POSIX timer preserves SI_TIMER SigInfo,
 * mq_notify is dropped rather than corrupted to SI_USER, F_SETSIG falls back to SIGIO/SI_KERNEL,
 * and kill still sets the pending bit with default SI_USER. */
static void test_rt_signal_rlimit_sigpending(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork rt rlimit test");
    if (pid == 0) {
        int rt0 = SIGRTMIN;
        int rt_timer = SIGRTMIN + 1;
        int rt_mq = SIGRTMIN + 2;
        int rt_io = SIGRTMIN + 3;
        int rt_kill = SIGRTMIN + 4;

        sigset_t set;
        sigemptyset(&set);
        int sigs[] = {SIGIO, rt0, rt_timer, rt_mq, rt_io, rt_kill};
        for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
            sigaddset(&set, sigs[i]);
        CHECK(sigprocmask(SIG_BLOCK, &set, NULL) == 0, "block test signals");

        /* Create POSIX timer before lowering RLIMIT_SIGPENDING */
        int timer_id = -1;
        struct k_sigevent {
            union sigval sigev_value;
            int sigev_signo;
            int sigev_notify;
            char pad[48];
        };
        struct k_sigevent sev = {
            .sigev_value.sival_int = 4242, .sigev_signo = rt_timer, .sigev_notify = 0};
        CHECK(syscall(SYS_timer_create, CLOCK_MONOTONIC, &sev, &timer_id) == 0, "timer_create");

        /* Create POSIX mqueue and register mq_notify */
        struct {
            long mq_flags, mq_maxmsg, mq_msgsize, mq_curmsgs;
            long reserved[4];
        } attr = {.mq_maxmsg = 4, .mq_msgsize = 16};
        int mq = (int)syscall(SYS_mq_open, "rt_rlimit_test", O_CREAT | O_RDWR, 0600, &attr);
        CHECK(mq >= 0, "mq_open");
        syscall(SYS_mq_unlink, "rt_rlimit_test");
        struct k_sigevent mq_sev = {
            .sigev_value.sival_int = 7777, .sigev_signo = rt_mq, .sigev_notify = 0};
        CHECK(syscall(SYS_mq_notify, mq, &mq_sev) == 0, "mq_notify");

        /* Lower RLIMIT_SIGPENDING to 1 and fill that 1 slot with sigqueue */
        struct rlimit rl = {1, 1};
        CHECK(setrlimit(RLIMIT_SIGPENDING, &rl) == 0, "setrlimit RLIMIT_SIGPENDING");
        union sigval sv = {.sival_int = 111};
        CHECK(sigqueue(getpid(), rt0, sv) == 0, "first sigqueue fills slot");
        CHECK(sigqueue(getpid(), rt0, sv) < 0 && errno == EAGAIN, "second sigqueue -> EAGAIN");

        /* 1. Fire POSIX timer while queue is full */
        struct itimerspec its = {{0, 0}, {0, 1000000}};
        CHECK(syscall(SYS_timer_settime, timer_id, 0, &its, NULL) == 0, "timer_settime");
        usleep(20000);

        /* 2. Fire mq_notify while queue is full */
        CHECK(syscall(SYS_mq_timedsend, mq, "hi", 2, 0, NULL) == 0, "mq_timedsend");

        /* 3. Fire F_SETSIG (O_ASYNC pipe) while queue is full */
        int pfd[2];
        CHECK(pipe(pfd) == 0, "pipe");
        CHECK(fcntl(pfd[0], F_SETOWN, getpid()) == 0, "F_SETOWN");
        CHECK(fcntl(pfd[0], F_SETSIG, rt_io) == 0, "F_SETSIG");
        CHECK(fcntl(pfd[0], F_SETFL, O_ASYNC) == 0, "O_ASYNC");
        CHECK(write(pfd[1], "x", 1) == 1, "write pipe");
        usleep(20000);

        /* 4. Fire kill() on RT signal while queue is full */
        CHECK(kill(getpid(), rt_kill) == 0, "kill RT");

        int got_rt0 = 0, got_timer = 0, got_mq = 0, got_rt_io = 0, got_sigio = 0, got_kill = 0;
        struct timespec zero = {0, 0};
        for (;;) {
            siginfo_t si;
            memset(&si, 0, sizeof(si));
            int s = sigtimedwait(&set, &si, &zero);
            if (s < 0)
                break;
            if (s == rt0) {
                CHECK(si.si_code == SI_QUEUE && si.si_value.sival_int == 111, "rt0 siginfo");
                got_rt0++;
            } else if (s == rt_timer) {
                CHECK(si.si_code == SI_TIMER && si.si_value.sival_int == 4242,
                      "timer lost siginfo: code=%d val=%d", si.si_code, si.si_value.sival_int);
                got_timer++;
            } else if (s == rt_mq) {
                got_mq++;
            } else if (s == rt_io) {
                got_rt_io++;
            } else if (s == SIGIO) {
                CHECK(si.si_code == SI_KERNEL, "SIGIO fallback expected SI_KERNEL, got %d",
                      si.si_code);
                got_sigio++;
            } else if (s == rt_kill) {
                CHECK(si.si_code == SI_USER && si.si_pid == 0 && si.si_uid == 0,
                      "kill overflow expected SI_USER/0/0, got %d/%d/%u", si.si_code, si.si_pid,
                      si.si_uid);
                got_kill++;
            }
        }
        CHECK(got_rt0 == 1, "expected 1 rt0, got %d", got_rt0);
        CHECK(got_timer == 1, "expected 1 timer with SI_TIMER, got %d", got_timer);
        CHECK(got_mq == 0, "expected mq_notify dropped on full queue, got %d", got_mq);
        CHECK(got_rt_io == 0 && got_sigio == 1,
              "expected F_SETSIG fallback to SIGIO (rt_io=%d sigio=%d)", got_rt_io, got_sigio);
        CHECK(got_kill == 1, "expected 1 kill overflow, got %d", got_kill);

        close(pfd[0]);
        close(pfd[1]);
        close(mq);
        syscall(SYS_timer_delete, timer_id);
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0,
          "rt rlimit child failed (status=%#x)", st);
}

/* ---- Local exclusive monitor across signals and transparent CoW ---- */

enum { VALUE_A = 17, VALUE_B = 29 };
static volatile sig_atomic_t exclusive_target, got_sig;
struct exclusive_sender {
    _Atomic int ready;
    pthread_t receiver;
};

static void exclusive_handler(int sig, siginfo_t *info, void *ctx)
{
    if (sig == SIGSEGV) {
        if (info->si_code != SEGV_MAPERR || info->si_addr != NULL)
            _exit(2);
        ((ucontext_t *)ctx)->uc_mcontext.pc += 4;
    }
    exclusive_target = VALUE_B;
    exclusive_target = VALUE_A;
    got_sig = 1;
}

static void *send_exclusive_signal(void *arg)
{
    struct exclusive_sender *sender = arg;
    while (!atomic_load_explicit(&sender->ready, memory_order_acquire))
        sched_yield();
    CHECK(pthread_kill(sender->receiver, SIGUSR1) == 0, "send SIGUSR1");
    return NULL;
}

static int exclusive_store(volatile sig_atomic_t *target)
{
    int loaded, status;
    __asm__ volatile("ldaxr %w0, [%2]\n"
                     "stlxr %w1, %w3, [%2]"
                     : "=&r"(loaded), "=&r"(status)
                     : "r"(target), "r"(VALUE_B)
                     : "memory");
    CHECK(loaded == VALUE_A, "LDAXR read %d", loaded);
    return status;
}

static void test_exclusive_monitor(void)
{
    exclusive_target = VALUE_A;
    CHECK(exclusive_store(&exclusive_target) == 0 && exclusive_target == VALUE_B,
          "uninterrupted STLXR");

    struct sigaction sa = {.sa_sigaction = exclusive_handler, .sa_flags = SA_SIGINFO};
    struct sigaction old_segv, old_usr1;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGSEGV, &sa, &old_segv) == 0, "install exclusive SIGSEGV handler");
    exclusive_target = VALUE_A;
    got_sig = 0;
    int loaded, status;
    __asm__ volatile("ldaxr %w0, [%2]\n"
                     "ldr wzr, [%3]\n"
                     "stlxr %w1, %w4, [%2]"
                     : "=&r"(loaded), "=&r"(status)
                     : "r"(&exclusive_target), "r"((uintptr_t)0), "r"(VALUE_B)
                     : "memory");
    CHECK(got_sig && loaded == VALUE_A && status == 1 && exclusive_target == VALUE_A,
          "STLXR after SIGSEGV returned %d", status);
    CHECK(sigaction(SIGSEGV, &old_segv, NULL) == 0, "restore SIGSEGV");

    CHECK(sigaction(SIGUSR1, &sa, &old_usr1) == 0, "install exclusive SIGUSR1 handler");
    got_sig = 0;
    struct exclusive_sender sender = {.receiver = pthread_self()};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, send_exclusive_signal, &sender) == 0, "create sender");
    /* Publish readiness after LDAXR. Only the receiver's signal handler releases the loop. */
    __asm__ volatile("ldaxr %w[loaded], [%[target]]\n"
                     "stlr %w[one], [%[ready]]\n"
                     "1: ldr %w[status], [%[got]]\n"
                     "cbz %w[status], 1b\n"
                     "stlxr %w[status], %w[value], [%[target]]"
                     : [loaded] "=&r"(loaded), [status] "=&r"(status)
                     : [target] "r"(&exclusive_target), [value] "r"(VALUE_B),
                       [ready] "r"(&sender.ready), [got] "r"(&got_sig), [one] "r"(1)
                     : "memory");
    CHECK(loaded == VALUE_A && status == 1 && exclusive_target == VALUE_A,
          "STLXR after SIGUSR1 returned %d", status);
    CHECK(pthread_join(thread, NULL) == 0, "join sender");
    CHECK(sigaction(SIGUSR1, &old_usr1, NULL) == 0, "restore SIGUSR1");

    volatile sig_atomic_t *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED, "mmap private page");
    *page = VALUE_A;
    pid_t child = fork();
    CHECK(child >= 0, "fork CoW child");
    if (child == 0) {
        CHECK(exclusive_store(page) == 1 && *page == VALUE_A, "STLXR across CoW fault");
        CHECK(exclusive_store(page) == 0 && *page == VALUE_B, "STLXR after CoW retry");
        _exit(0);
    }
    wait_exit(child, 0);
    CHECK(*page == VALUE_A, "child changed parent's page");
    CHECK(munmap((void *)page, 4096) == 0, "munmap private page");
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--exec-helper") == 0) {
        return 42;
    }
    const char *self = argv[0];

    test_exclusive_monitor();
    test_group_stop_waits_for_all_threads();
    test_sigill_omits_esr_context();
    test_sigaction_clone_sighand_discard();
    test_sigreturn_validation();
    test_time_setting_errors();
    test_ptrace_detach_at_attach_group_stop();
    test_singlestep_skipped_syscall();
    test_singlestep_rt_sigreturn();
    test_singlestep_execve(self);
    test_ptrace_event_exit_on_exit_group();
    test_ptrace_event_exit_on_nonleader_execve(self);
    test_process_vm_zero_remote();
    test_tty_device_identity();
    test_tty_exclusive();
    test_tty_job_control_ioctls();
    test_tty_output_clamp();
    test_zombie_leader_cpu_clock();
    test_skipped_syscall_no_restart();
    test_coredump_umask_fsize_suid_dumpable();
    test_seccomp_klog_and_user_notif_log();
    test_mrs_unallocated_id_regs_sigill();
    test_rt_signal_rlimit_sigpending();

    puts("all ok");
    return 0;
}
