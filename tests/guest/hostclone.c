/*
 * Guest test program for clones and the Files app writing the same files: build with musl-gcc
 * -static and run it copied into the store. "clone SRC DST" clones SRC onto DST (FICLONE); "hold
 * DST SRC" maps both clones for reading and waits for the host to write DST before reading again.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

/* From <linux/fs.h> */
#define FICLONE 0x40049409

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "clone") == 0) {
        int src = open(argv[2], O_RDONLY);
        int dst = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (src < 0 || dst < 0 || ioctl(dst, FICLONE, src) != 0) {
            perror("clone");
            return 1;
        }
        printf("cloned\n");
        return 0;
    }
    if (argc == 4 && (strcmp(argv[1], "hold") == 0 || strcmp(argv[1], "hold-truncate") == 0)) {
        int fd = open(argv[2], O_RDONLY);
        int src = open(argv[3], O_RDONLY);
        char *dst_map = mmap(NULL, 5, PROT_READ, MAP_SHARED, fd, 0);
        char *src_map = mmap(NULL, 5, PROT_READ, MAP_SHARED, src, 0);
        if (dst_map == MAP_FAILED || src_map == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        printf("holding %.4s %.4s\n", dst_map, src_map);
        fflush(stdout);
        if (getchar() == EOF)
            return 1;
        if (strcmp(argv[1], "hold-truncate") == 0) {
            pid_t child = fork();
            if (child < 0) return 1;
            if (child == 0) _exit(*(volatile char *)dst_map);
            int status;
            if (waitpid(child, &status, 0) < 0 || !WIFSIGNALED(status) || WTERMSIG(status) != SIGBUS)
                return 1;
            puts("tail faulted");
            fflush(stdout);
            if (getchar() == EOF) return 1;
        }
        char buf[5];
        if (pread(fd, buf, sizeof buf, 0) != sizeof buf)
            return 1;
        printf("read %.4s mapped %.4s source %.4s\n", buf, dst_map, src_map);
        return 0;
    }
    fprintf(stderr, "usage: hostclone clone SRC DST | hold DST SRC\n");
    return 2;
}
