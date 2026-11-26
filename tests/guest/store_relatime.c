/*
 * Regression tests for kernel/store relatime caching and single-touch-per-syscall atime semantics:
 *  1. relatime updates when atime <= mtime, atime <= ctime, or now - atime >= 24h, stays unchanged
 *     on warm repeated reads, and updates again after write, chmod, utimensat, truncate, ftruncate,
 *     fallocate, and writable MAP_SHARED mmap (tmpfs).
 *  2. O_NOATIME, MS_NOATIME, MS_STRICTATIME, MS_RDONLY, and cross-mount interaction.
 *  3. Multi-chunk reads across 256 KiB (4 x 64 KiB IO_CHUNK): read, pread, readv (including
 *     leading zero-length iovec), sendfile (regular->regular and regular->pipe), and
 *     copy_file_range (share, copy_regular, tmpfs fallback), plus 0-length no-op checks and
 *     copy_file_range output cache invalidation.
 *  4. Optional "bench" mode: measures 3 rounds of 10,000 warm 1-byte preads (relatime vs O_NOATIME).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define CHECK(cond, fmt, ...)                                                                      \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d %s)\n", __FILE__, __LINE__,             \
                    ##__VA_ARGS__, errno, strerror(errno));                                        \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void tick(void)
{
    /* Advance past coarse host filesystem timestamp ticks. */
    struct timespec ts = {0, 25000000};
    nanosleep(&ts, NULL);
}

static int64_t ts_ns(struct timespec ts)
{
    return (int64_t)ts.tv_sec * 1000000000LL + (int64_t)ts.tv_nsec;
}

static int64_t stat_atime(const char *path)
{
    struct stat st;
    CHECK(stat(path, &st) == 0, "stat %s", path);
    return ts_ns(st.st_atim);
}

static int64_t fstat_atime(int fd)
{
    struct stat st;
    CHECK(fstat(fd, &st) == 0, "fstat %d", fd);
    return ts_ns(st.st_atim);
}

static ssize_t do_copy_file_range(int in_fd, off_t *off_in, int out_fd, off_t *off_out, size_t len)
{
    return (ssize_t)syscall(SYS_copy_file_range, in_fd, off_in, out_fd, off_out, len, 0);
}

static void test_relatime_lifecycle(void)
{
    const char *path = "/tmp/relatime_test/life";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(fd >= 0, "create life");
    CHECK(write(fd, "hello world", 11) == 11, "initial write");

    /* Advance past creation tick so first relatime read makes atime > mtime && atime > ctime. */
    tick();
    char buf[16];
    CHECK(pread(fd, buf, 5, 0) == 5, "first relatime pread");
    struct stat st;
    CHECK(fstat(fd, &st) == 0, "fstat after first read");
    int64_t a1 = ts_ns(st.st_atim);
    CHECK(a1 > ts_ns(st.st_mtim) && a1 > ts_ns(st.st_ctim),
          "first relatime read must advance atime past mtime/ctime");

    /* Warm repeated reads must not advance atime. */
    tick();
    for (int i = 0; i < 50; i++) {
        CHECK(pread(fd, buf, 1, 0) == 1, "warm pread %d", i);
    }
    CHECK(fstat_atime(fd) == a1, "warm relatime reads must keep atime unchanged");

    /* 1. write() invalidates cached relatime -> next read advances atime. */
    tick();
    CHECK(pwrite(fd, "!", 1, 0) == 1, "pwrite");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after pwrite");
    int64_t a2 = fstat_atime(fd);
    CHECK(a2 > a1, "read after write must advance atime");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1 && fstat_atime(fd) == a2,
          "second read after write must keep atime unchanged");

    /* 2. chmod() bumps ctime only -> next read advances atime. */
    tick();
    CHECK(chmod(path, 0600) == 0, "chmod");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after chmod");
    int64_t a3 = fstat_atime(fd);
    CHECK(a3 > a2, "read after chmod must advance atime");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1 && fstat_atime(fd) == a3,
          "second read after chmod must keep atime unchanged");

    /* 3. utimensat() with UTIME_OMIT atime and UTIME_NOW mtime -> next read advances atime. */
    tick();
    struct timespec mtime_only[2] = {{0, UTIME_OMIT}, {0, UTIME_NOW}};
    CHECK(utimensat(AT_FDCWD, path, mtime_only, 0) == 0, "utimensat mtime-only");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after utimensat mtime-only");
    int64_t a4 = fstat_atime(fd);
    CHECK(a4 > a3, "read after mtime-only utimensat must advance atime");

    /* 4. utimensat() setting an old atime (>24h ago) -> next read advances atime. */
    struct timespec old_times[2] = {{1000, 0}, {500, 0}};
    CHECK(utimensat(AT_FDCWD, path, old_times, 0) == 0, "utimensat old atime");
    CHECK(fstat_atime(fd) == 1000LL * 1000000000LL, "atime set to 1000s");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after old atime");
    int64_t a5 = fstat_atime(fd);
    CHECK(a5 > 1000LL * 1000000000LL, "read after >24h old atime must advance atime");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1 && fstat_atime(fd) == a5,
          "second read after old-atime refresh must keep atime unchanged");

    /* 5. ftruncate() invalidates cached relatime -> next read advances atime. */
    tick();
    CHECK(ftruncate(fd, 6) == 0, "ftruncate");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after ftruncate");
    int64_t a6 = fstat_atime(fd);
    CHECK(a6 > a5, "read after ftruncate must advance atime");

    /* 6. truncate() by path invalidates cached relatime -> next read advances atime. */
    tick();
    CHECK(truncate(path, 4) == 0, "truncate");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after truncate");
    int64_t a7 = fstat_atime(fd);
    CHECK(a7 > a6, "read after truncate must advance atime");

    /* 7. fallocate() invalidates cached relatime -> next read advances atime. */
    tick();
    CHECK(fallocate(fd, 0, 0, 4096) == 0, "fallocate");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after fallocate");
    int64_t a8 = fstat_atime(fd);
    CHECK(a8 > a7, "read after fallocate must advance atime");

    /* 8. Hard link unlink bumps ctime -> next read on open fd advances atime. */
    const char *alias = "/tmp/relatime_test/life_link";
    CHECK(link(path, alias) == 0, "link");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after link");
    int64_t a9 = fstat_atime(fd);
    CHECK(a9 > a8, "read after link must advance atime");
    tick();
    CHECK(unlink(alias) == 0, "unlink alias");
    tick();
    CHECK(pread(fd, buf, 1, 0) == 1, "pread after unlink");
    int64_t a10 = fstat_atime(fd);
    CHECK(a10 > a9, "read after unlink must advance atime");

    close(fd);
}

static void test_tmpfs_writable_mmap_invalidation(void)
{
    CHECK(mkdir("/tmp/relatime_tmpfs", 0755) == 0, "mkdir relatime_tmpfs");
    CHECK(mount("tmpfs", "/tmp/relatime_tmpfs", "tmpfs", MS_RELATIME, "size=1M") == 0,
          "mount tmpfs relatime");
    const char *path = "/tmp/relatime_tmpfs/mapped";
    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(fd >= 0 && ftruncate(fd, 4096) == 0, "create tmpfs file");

    tick();
    char c;
    CHECK(pread(fd, &c, 1, 0) == 1, "warm read before mmap");
    int64_t a1 = fstat_atime(fd);

    char *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(map != MAP_FAILED, "mmap MAP_SHARED PROT_WRITE");
    tick();
    map[0] = 'Z';
    CHECK(msync(map, 4096, MS_SYNC) == 0, "msync");

    tick();
    CHECK(pread(fd, &c, 1, 0) == 1 && c == 'Z', "pread after shared mmap write");
    int64_t a2 = fstat_atime(fd);
    CHECK(a2 > a1, "read after writable MAP_SHARED write must advance atime");

    munmap(map, 4096);
    close(fd);
    CHECK(umount2("/tmp/relatime_tmpfs", 0) == 0, "umount tmpfs");
}

static void test_mount_policies(void)
{
    CHECK(mkdir("/tmp/relatime_mnt", 0755) == 0, "mkdir mnt base");
    CHECK(mkdir("/tmp/relatime_mnt/src", 0755) == 0, "mkdir src");
    CHECK(mkdir("/tmp/relatime_mnt/rel", 0755) == 0, "mkdir rel");
    CHECK(mkdir("/tmp/relatime_mnt/strict", 0755) == 0, "mkdir strict");
    CHECK(mkdir("/tmp/relatime_mnt/noa", 0755) == 0, "mkdir noa");
    CHECK(mkdir("/tmp/relatime_mnt/ro", 0755) == 0, "mkdir ro");

    const char *src_file = "/tmp/relatime_mnt/src/f";
    int wfd = open(src_file, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(wfd >= 0 && write(wfd, "ABCDEFGH", 8) == 8, "create policy file");

    /* Bind-mount with distinct per-mount atime flags. */
    const struct {
        const char *dst;
        unsigned long flags;
    } mounts[] = {
        {"/tmp/relatime_mnt/rel", MS_RELATIME},
        {"/tmp/relatime_mnt/strict", MS_STRICTATIME},
        {"/tmp/relatime_mnt/noa", MS_NOATIME},
        {"/tmp/relatime_mnt/ro", MS_RDONLY | MS_STRICTATIME},
    };
    for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); i++) {
        CHECK(mount("/tmp/relatime_mnt/src", mounts[i].dst, NULL, MS_BIND, NULL) == 0,
              "bind %s", mounts[i].dst);
        CHECK(mount(NULL, mounts[i].dst, NULL, MS_BIND | MS_REMOUNT | mounts[i].flags, NULL) == 0,
              "remount %s", mounts[i].dst);
    }

    int fd_rel = open("/tmp/relatime_mnt/rel/f", O_RDONLY);
    int fd_strict = open("/tmp/relatime_mnt/strict/f", O_RDONLY);
    int fd_noa = open("/tmp/relatime_mnt/noa/f", O_RDONLY);
    int fd_ro = open("/tmp/relatime_mnt/ro/f", O_RDONLY);
    int fd_onoatime = open("/tmp/relatime_mnt/strict/f", O_RDONLY | O_NOATIME);
    CHECK(fd_rel >= 0 && fd_strict >= 0 && fd_noa >= 0 && fd_ro >= 0 && fd_onoatime >= 0,
          "open mount fds");

    char c;
    struct timespec old[2] = {{10, 0}, {20, 0}};
    CHECK(futimens(wfd, old) == 0, "reset old times");

    /* MS_NOATIME, MS_RDONLY, and O_NOATIME must not advance atime even when atime <= mtime. */
    tick();
    CHECK(pread(fd_noa, &c, 1, 0) == 1 && stat_atime(src_file) == 10LL * 1000000000LL,
          "MS_NOATIME must not update atime");
    CHECK(pread(fd_ro, &c, 1, 0) == 1 && stat_atime(src_file) == 10LL * 1000000000LL,
          "MS_RDONLY must not update atime");
    CHECK(pread(fd_onoatime, &c, 1, 0) == 1 && stat_atime(src_file) == 10LL * 1000000000LL,
          "O_NOATIME on MS_STRICTATIME must not update atime");

    /* MS_RELATIME updates once, then caches. */
    CHECK(pread(fd_rel, &c, 1, 0) == 1, "relatime read 1");
    int64_t a_rel = stat_atime(src_file);
    CHECK(a_rel > 20LL * 1000000000LL, "MS_RELATIME advances atime when due");
    tick();
    CHECK(pread(fd_rel, &c, 1, 0) == 1 && stat_atime(src_file) == a_rel,
          "MS_RELATIME warm read keeps atime");

    /* MS_STRICTATIME must bypass relatime cache and advance on every read. */
    tick();
    CHECK(pread(fd_strict, &c, 1, 0) == 1, "strict read 1");
    int64_t a_s1 = stat_atime(src_file);
    CHECK(a_s1 > a_rel, "MS_STRICTATIME advances atime past cached relatime");
    tick();
    CHECK(pread(fd_strict, &c, 1, 0) == 1, "strict read 2");
    int64_t a_s2 = stat_atime(src_file);
    CHECK(a_s2 > a_s1, "MS_STRICTATIME advances atime on second read");

    /* Switching back to MS_RELATIME sees fresh atime and does not advance. */
    tick();
    CHECK(pread(fd_rel, &c, 1, 0) == 1 && stat_atime(src_file) == a_s2,
          "MS_RELATIME after MS_STRICTATIME keeps fresh atime");

    close(fd_rel);
    close(fd_strict);
    close(fd_noa);
    close(fd_ro);
    close(fd_onoatime);
    close(wfd);
    for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); i++) {
        CHECK(umount2(mounts[i].dst, 0) == 0, "umount %s", mounts[i].dst);
    }
}

static void reset_old(int fd)
{
    struct timespec old[2] = {{100, 0}, {200, 0}};
    CHECK(futimens(fd, old) == 0, "futimens reset_old");
    tick();
}

static void test_multichunk_reads(void)
{
    const size_t total = 256 * 1024; /* 4 x 64 KiB IO_CHUNK */
    unsigned char *src_data = malloc(total);
    unsigned char *dst_buf = malloc(total);
    CHECK(src_data && dst_buf, "malloc 256 KiB");
    for (size_t i = 0; i < total; i++) {
        src_data[i] = (unsigned char)((i * 31 + 7) & 0xff);
    }

    const char *src_path = "/tmp/relatime_test/big_src";
    const char *dst_path = "/tmp/relatime_test/big_dst";
    int sfd = open(src_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(sfd >= 0, "create big_src");
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(sfd, src_data + written, total - written);
        CHECK(n > 0, "write big_src");
        written += (size_t)n;
    }

    /* 0-length read / pread / readv must not advance atime. */
    reset_old(sfd);
    CHECK(read(sfd, dst_buf, 0) == 0 && fstat_atime(sfd) == 100LL * 1000000000LL,
          "0-byte read must not update atime");
    CHECK(pread(sfd, dst_buf, 0, 0) == 0 && fstat_atime(sfd) == 100LL * 1000000000LL,
          "0-byte pread must not update atime");
    struct iovec ziov = {.iov_base = dst_buf, .iov_len = 0};
    CHECK(readv(sfd, &ziov, 1) == 0 && fstat_atime(sfd) == 100LL * 1000000000LL,
          "0-byte readv must not update atime");

    /* 1. Multi-chunk read() (4 chunks) */
    reset_old(sfd);
    CHECK(lseek(sfd, 0, SEEK_SET) == 0, "lseek 0");
    memset(dst_buf, 0, total);
    CHECK(read(sfd, dst_buf, total) == (ssize_t)total, "256 KiB read");
    CHECK(memcmp(dst_buf, src_data, total) == 0, "read data matches");
    int64_t a = fstat_atime(sfd);
    CHECK(a > 200LL * 1000000000LL, "multi-chunk read updates atime");
    tick();
    CHECK(lseek(sfd, 0, SEEK_SET) == 0 && read(sfd, dst_buf, total) == (ssize_t)total &&
              fstat_atime(sfd) == a,
          "warm multi-chunk read keeps atime");

    /* 2. Multi-chunk pread() */
    reset_old(sfd);
    memset(dst_buf, 0, total);
    CHECK(pread(sfd, dst_buf, total, 0) == (ssize_t)total, "256 KiB pread");
    CHECK(memcmp(dst_buf, src_data, total) == 0, "pread data matches");
    a = fstat_atime(sfd);
    CHECK(a > 200LL * 1000000000LL, "multi-chunk pread updates atime");

    /* 3. Multi-iovec readv() with leading zero-length iovec + 4 x 64 KiB iovecs */
    reset_old(sfd);
    memset(dst_buf, 0, total);
    struct iovec iovs[5];
    iovs[0].iov_base = dst_buf;
    iovs[0].iov_len = 0;
    for (int i = 0; i < 4; i++) {
        iovs[i + 1].iov_base = dst_buf + (size_t)i * 65536;
        iovs[i + 1].iov_len = 65536;
    }
    CHECK(lseek(sfd, 0, SEEK_SET) == 0, "lseek for readv");
    CHECK(readv(sfd, iovs, 5) == (ssize_t)total, "256 KiB readv");
    CHECK(memcmp(dst_buf, src_data, total) == 0, "readv data matches");
    a = fstat_atime(sfd);
    CHECK(a > 200LL * 1000000000LL, "multi-iovec readv updates atime");
    tick();
    CHECK(lseek(sfd, 0, SEEK_SET) == 0 && readv(sfd, iovs, 5) == (ssize_t)total &&
              fstat_atime(sfd) == a,
          "warm readv keeps atime");

    /* 4. sendfile() regular -> regular (copy_regular) and 0-len no-op */
    int dfd = open(dst_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(dfd >= 0, "create big_dst");
    reset_old(sfd);
    off_t off = 0;
    CHECK(sendfile(dfd, sfd, &off, 0) == 0 && fstat_atime(sfd) == 100LL * 1000000000LL,
          "0-byte sendfile must not update atime");
    CHECK(sendfile(dfd, sfd, &off, total) == (ssize_t)total, "sendfile regular->regular");
    CHECK(fstat_atime(sfd) > 200LL * 1000000000LL, "sendfile regular->regular updates src atime");

    /* sendfile() into dst must invalidate dst's relatime cache too. */
    tick();
    char c;
    CHECK(pread(dfd, &c, 1, 0) == 1, "warm dst relatime");
    int64_t da1 = fstat_atime(dfd);
    tick();
    off = 0;
    CHECK(lseek(dfd, 0, SEEK_SET) == 0 && sendfile(dfd, sfd, &off, 4096) == 4096,
          "sendfile overwrite dst");
    tick();
    CHECK(pread(dfd, &c, 1, 0) == 1 && fstat_atime(dfd) > da1,
          "read of sendfile destination advances atime");

    /* 5. sendfile() regular -> pipe */
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    reset_old(sfd);
    off = 0;
    CHECK(sendfile(p[1], sfd, &off, 4096) == 4096, "sendfile regular->pipe");
    CHECK(fstat_atime(sfd) > 200LL * 1000000000LL, "sendfile regular->pipe updates src atime");
    CHECK(read(p[0], dst_buf, 4096) == 4096 && memcmp(dst_buf, src_data, 4096) == 0,
          "pipe data matches");
    close(p[0]);
    close(p[1]);

    /* 6. copy_file_range() whole-file (try_share path) and partial (copy_regular path) */
    const char *cfr_path = "/tmp/relatime_test/cfr_dst";
    int cfd = open(cfr_path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(cfd >= 0, "create cfr_dst");
    /* Use a read-only src fd so try_share is eligible (no non-cow writer open). */
    close(sfd);
    int sro = open(src_path, O_RDONLY);
    CHECK(sro >= 0, "open big_src O_RDONLY");
    struct timespec old[2] = {{100, 0}, {200, 0}};
    CHECK(utimensat(AT_FDCWD, src_path, old, 0) == 0, "reset big_src old");
    tick();
    off_t in_off = 0, out_off = 0;
    CHECK(do_copy_file_range(sro, &in_off, cfd, &out_off, 0) == 0 &&
              fstat_atime(sro) == 100LL * 1000000000LL,
          "0-byte copy_file_range must not update atime");
    CHECK(do_copy_file_range(sro, &in_off, cfd, &out_off, total) == (ssize_t)total,
          "whole-file copy_file_range");
    CHECK(fstat_atime(sro) > 200LL * 1000000000LL,
          "whole-file copy_file_range updates src atime");

    /* Partial copy_file_range (copy_regular path) */
    CHECK(utimensat(AT_FDCWD, src_path, old, 0) == 0, "reset big_src for partial cfr");
    tick();
    in_off = 4096;
    out_off = 0;
    CHECK(do_copy_file_range(sro, &in_off, cfd, &out_off, total - 4096) ==
              (ssize_t)(total - 4096),
          "partial copy_file_range");
    CHECK(fstat_atime(sro) > 200LL * 1000000000LL,
          "partial copy_file_range updates src atime");

    /* 7. copy_file_range() on tmpfs (chunked fallback loop) */
    CHECK(mkdir("/tmp/relatime_cfr_tmpfs", 0755) == 0, "mkdir cfr_tmpfs");
    CHECK(mount("tmpfs", "/tmp/relatime_cfr_tmpfs", "tmpfs", MS_RELATIME, "size=2M") == 0,
          "mount cfr_tmpfs");
    int tsrc = open("/tmp/relatime_cfr_tmpfs/src", O_CREAT | O_RDWR | O_TRUNC, 0644);
    int tdst = open("/tmp/relatime_cfr_tmpfs/dst", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(tsrc >= 0 && tdst >= 0, "open tmpfs cfr files");
    written = 0;
    while (written < total) {
        ssize_t n = write(tsrc, src_data + written, total - written);
        CHECK(n > 0, "write tmpfs src");
        written += (size_t)n;
    }
    reset_old(tsrc);
    in_off = 0;
    out_off = 0;
    CHECK(do_copy_file_range(tsrc, &in_off, tdst, &out_off, total) == (ssize_t)total,
          "tmpfs chunked copy_file_range");
    CHECK(fstat_atime(tsrc) > 200LL * 1000000000LL,
          "tmpfs chunked copy_file_range updates src atime");
    memset(dst_buf, 0, total);
    CHECK(pread(tdst, dst_buf, total, 0) == (ssize_t)total && memcmp(dst_buf, src_data, total) == 0,
          "tmpfs copy_file_range data matches");

    close(tsrc);
    close(tdst);
    CHECK(umount2("/tmp/relatime_cfr_tmpfs", 0) == 0, "umount cfr_tmpfs");
    close(sro);
    close(dfd);
    close(cfd);
    free(src_data);
    free(dst_buf);
}

static double measure_pread(int fd, int iters)
{
    char c;
    CHECK(pread(fd, &c, 1, 0) == 1, "bench warmup pread");
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iters; i++) {
        CHECK(pread(fd, &c, 1, 0) == 1, "bench pread");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = (double)(t1.tv_sec - t0.tv_sec) * 1e9 + (double)(t1.tv_nsec - t0.tv_nsec);
    return ns / iters / 1e3;
}

static void run_bench(void)
{
    int wfd = open("/tmp/relatime_bench_file", O_CREAT | O_RDWR | O_TRUNC, 0644);
    CHECK(wfd >= 0 && write(wfd, "X", 1) == 1, "bench create");
    close(wfd);
    tick();
    int r_rel = open("/tmp/relatime_bench_file", O_RDONLY);
    int r_noa = open("/tmp/relatime_bench_file", O_RDONLY | O_NOATIME);
    CHECK(r_rel >= 0 && r_noa >= 0, "bench open");
    char c;
    CHECK(pread(r_rel, &c, 1, 0) == 1, "bench settle");
    for (int round = 1; round <= 3; round++) {
        double rel = measure_pread(r_rel, 10000);
        double noa = measure_pread(r_noa, 10000);
        printf("round %d: relatime=%.3f us/pread  O_NOATIME=%.3f us/pread  diff=%.3f us\n",
               round, rel, noa, rel - noa);
    }
    close(r_rel);
    close(r_noa);
}

int main(int argc, char **argv)
{
    CHECK(mkdir("/tmp", 0777) == 0 || errno == EEXIST, "mkdir /tmp");
    if (argc == 2 && strcmp(argv[1], "bench") == 0) {
        run_bench();
        return 0;
    }
    CHECK(mkdir("/tmp/relatime_test", 0755) == 0 || errno == EEXIST, "mkdir relatime_test");

    test_relatime_lifecycle();
    test_tmpfs_writable_mmap_invalidation();
    test_mount_policies();
    test_multichunk_reads();

    printf("all ok\n");
    return 0;
}
