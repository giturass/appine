# Separate processes sharing an fd table retain their own RLIMIT_NOFILE.
set -eu
cd /tmp
cat > nofile.c <<'C'
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    const int shared = 32;
    struct rlimit original, current;
    assert(getrlimit(RLIMIT_NOFILE, &original) == 0 && original.rlim_cur > shared + 1);
    pid_t child = syscall(SYS_clone, CLONE_FILES | SIGCHLD, 0, 0, 0, 0);
    assert(child >= 0);
    if (child == 0) {
        assert(dup3(1, shared, O_CLOEXEC) == shared);
        struct rlimit low = original;
        low.rlim_cur = 0;
        assert(setrlimit(RLIMIT_NOFILE, &low) == 0);
        assert(dup(1) == -1 && errno == EMFILE);
        assert(fcntl(1, F_DUPFD, 0) == -1 && errno == EINVAL);
        assert(dup3(1, shared, 0) == -1 && errno == EBADF);
        _exit(0);
    }
    int status;
    assert(waitpid(child, &status, 0) == child && status == 0);
    assert(getrlimit(RLIMIT_NOFILE, &current) == 0 && current.rlim_cur == original.rlim_cur);
    assert(fcntl(shared, F_GETFD) == FD_CLOEXEC);
    assert(dup(shared) >= 0);
    assert(fcntl(shared, F_DUPFD, shared + 1) >= shared + 1);
    assert(dup3(1, shared, 0) == shared);
    puts("shared fd table, independent limits");
    return 0;
}
C
cc -o nofile nofile.c
./nofile
rm -f nofile nofile.c
