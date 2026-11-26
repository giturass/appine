/*
 * Standalone guest regression tests for kernel/overlay Batch-2 fixes:
 *   1. Bounded live overlay node cache: walking > NODES_MAX (16,384) distinct existing names
 *      while mounted evicts unused live nodes without breaking open fds, cwds, inotify watches,
 *      copied-up origin inode numbers, or re-lookups of evicted names.
 *   2. mmap consistency after copy-up: mmap (MAP_PRIVATE and MAP_SHARED) on an fd opened before
 *      copy-up follows copy-up to the upper object (write copy-up, truncate copy-up, metadata-only
 *      copy-up followed by write, and store-lower/tmpfs-upper), while a mapping already created
 *      before copy-up keeps the lower object isolated from upper writes.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

#define CHECK(cond, fmt, ...)                                                        \
    do {                                                                             \
        if (!(cond)) {                                                               \
            fprintf(stderr, "FAIL (%s:%d): " fmt " (errno=%d: %s)\n",                \
                    __FILE__, __LINE__, ##__VA_ARGS__, errno, strerror(errno));      \
            exit(1);                                                                 \
        }                                                                            \
    } while (0)

static void write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        CHECK(n > 0, "write");
        p += n;
        len -= (size_t)n;
    }
}

static void create_file(const char *path, const char *data, mode_t mode)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
    CHECK(fd >= 0, "create %s", path);
    if (data && data[0] != '\0')
        write_all(fd, data, strlen(data));
    CHECK(close(fd) == 0, "close %s", path);
}

static void read_file_str(const char *path, char *buf, size_t sz)
{
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open %s", path);
    ssize_t n = read(fd, buf, sz - 1);
    CHECK(n >= 0, "read %s", path);
    buf[n] = '\0';
    CHECK(close(fd) == 0, "close %s", path);
}

static ino_t readdir_ino(const char *dir_path, const char *target)
{
    DIR *d = opendir(dir_path);
    CHECK(d != NULL, "opendir %s", dir_path);
    ino_t found = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, target) == 0) {
            found = de->d_ino;
            break;
        }
    }
    CHECK(closedir(d) == 0, "closedir %s", dir_path);
    return found;
}

static void test_bounded_overlay_node_cache(void)
{
    CHECK(mkdir("/tmp/ovl_evict", 0755) == 0 || errno == EEXIST, "mkdir base");
    CHECK(mount("tmpfs", "/tmp/ovl_evict", "tmpfs", 0, "nr_inodes=40000") == 0,
          "mount tmpfs workspace");
    CHECK(mkdir("/tmp/ovl_evict/l", 0755) == 0, "mkdir l");
    CHECK(mkdir("/tmp/ovl_evict/u", 0755) == 0, "mkdir u");
    CHECK(mkdir("/tmp/ovl_evict/w", 0755) == 0, "mkdir w");
    CHECK(mkdir("/tmp/ovl_evict/m", 0755) == 0, "mkdir m");

    CHECK(mkdir("/tmp/ovl_evict/l/keep_dir", 0755) == 0, "mkdir keep_dir");
    create_file("/tmp/ovl_evict/l/keep_dir/open_file", "keep-open-data", 0644);
    CHECK(mkdir("/tmp/ovl_evict/l/cwd_dir", 0755) == 0, "mkdir cwd_dir");
    CHECK(mkdir("/tmp/ovl_evict/l/watch_dir", 0755) == 0, "mkdir watch_dir");
    create_file("/tmp/ovl_evict/l/watch_dir/target", "watch-init", 0644);
    create_file("/tmp/ovl_evict/l/copied", "copied-init", 0644);

    /* Create 18,000 files across 60 buckets (> NODES_MAX = 16,384) */
    const int nbuckets = 60;
    const int per_bucket = 300;
    char path[256];
    for (int b = 0; b < nbuckets; b++) {
        snprintf(path, sizeof(path), "/tmp/ovl_evict/l/b%02d", b);
        CHECK(mkdir(path, 0755) == 0, "mkdir bucket %d", b);
        for (int i = 0; i < per_bucket; i++) {
            snprintf(path, sizeof(path), "/tmp/ovl_evict/l/b%02d/f%03d", b, i);
            int fd = open(path, O_CREAT | O_WRONLY, 0644);
            CHECK(fd >= 0, "create %s", path);
            close(fd);
        }
    }

    CHECK(mount("overlay", "/tmp/ovl_evict/m", "overlay", 0,
                "lowerdir=/tmp/ovl_evict/l,upperdir=/tmp/ovl_evict/u,workdir=/tmp/ovl_evict/w") == 0,
          "mount overlay");

    /* Establish live references before walking */
    int open_fd = open("/tmp/ovl_evict/m/keep_dir/open_file", O_RDONLY);
    CHECK(open_fd >= 0, "open keep_dir/open_file");
    struct stat open_st_before;
    CHECK(fstat(open_fd, &open_st_before) == 0, "fstat open_fd before");

    int dir_fd = open("/tmp/ovl_evict/m/keep_dir", O_RDONLY | O_DIRECTORY);
    CHECK(dir_fd >= 0, "open keep_dir");

    char saved_cwd[256];
    CHECK(getcwd(saved_cwd, sizeof(saved_cwd)) != NULL, "save cwd");
    CHECK(chdir("/tmp/ovl_evict/m/cwd_dir") == 0, "chdir cwd_dir");

    int inot_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    CHECK(inot_fd >= 0, "inotify_init1");
    int wd_dir = inotify_add_watch(inot_fd, "/tmp/ovl_evict/m/watch_dir", IN_CREATE | IN_MODIFY);
    CHECK(wd_dir >= 0, "inotify_add_watch dir");
    int wd_file = inotify_add_watch(inot_fd, "/tmp/ovl_evict/m/watch_dir/target", IN_MODIFY);
    CHECK(wd_file >= 0, "inotify_add_watch file");

    /* Copy up /tmp/ovl_evict/m/copied and record its origin inode number before walking */
    struct stat copied_st_before;
    CHECK(stat("/tmp/ovl_evict/m/copied", &copied_st_before) == 0, "stat copied before");
    CHECK(chmod("/tmp/ovl_evict/m/copied", 0600) == 0, "chmod copied (copy-up)");
    struct stat copied_st_up;
    CHECK(stat("/tmp/ovl_evict/m/copied", &copied_st_up) == 0, "stat copied after copy-up");
    CHECK(copied_st_up.st_ino == copied_st_before.st_ino,
          "copied-up file keeps origin st_ino before walk");

    /* Walk all 18,000 files through the overlay, triggering multiple live-node sweeps */
    struct stat st;
    for (int b = 0; b < nbuckets; b++) {
        for (int i = 0; i < per_bucket; i++) {
            snprintf(path, sizeof(path), "/tmp/ovl_evict/m/b%02d/f%03d", b, i);
            CHECK(lstat(path, &st) == 0, "lstat %s", path);
            CHECK(st.st_dev == open_st_before.st_dev, "overlay dev mismatch on %s", path);
        }
    }

    /* Verify active open fd, dirfd, cwd, inotify watches, and copied-up origin all survived */
    struct stat open_st_after;
    CHECK(fstat(open_fd, &open_st_after) == 0, "fstat open_fd after walk");
    CHECK(open_st_after.st_dev == open_st_before.st_dev &&
              open_st_after.st_ino == open_st_before.st_ino,
          "open_fd stat identity changed across eviction");
    char buf[64];
    ssize_t n = pread(open_fd, buf, sizeof(buf) - 1, 0);
    CHECK(n == 14 && memcmp(buf, "keep-open-data", 14) == 0, "open_fd content mismatch");

    int via_dir = openat(dir_fd, "open_file", O_RDONLY);
    CHECK(via_dir >= 0, "openat via keep_dir after walk");
    CHECK(close(via_dir) == 0, "close via_dir");

    char cur_cwd[256];
    CHECK(getcwd(cur_cwd, sizeof(cur_cwd)) != NULL, "getcwd after walk");
    CHECK(strcmp(cur_cwd, "/tmp/ovl_evict/m/cwd_dir") == 0,
          "cwd changed after walk: got %s", cur_cwd);

    /* Trigger inotify events on watched dir and file */
    create_file("/tmp/ovl_evict/m/watch_dir/new_entry", "hi", 0644);
    int wf = open("/tmp/ovl_evict/m/watch_dir/target", O_WRONLY | O_TRUNC);
    CHECK(wf >= 0, "open watched target for write");
    write_all(wf, "changed", 7);
    CHECK(close(wf) == 0, "close watched target");

    char evbuf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    ssize_t evlen = read(inot_fd, evbuf, sizeof(evbuf));
    CHECK(evlen > 0, "expected inotify events after walk");
    int saw_create = 0, saw_file_mod = 0;
    for (ssize_t off = 0; off < evlen;) {
        const struct inotify_event *ev = (const struct inotify_event *)(evbuf + off);
        if (ev->wd == wd_dir && (ev->mask & IN_CREATE) && strcmp(ev->name, "new_entry") == 0)
            saw_create = 1;
        if (ev->wd == wd_file && (ev->mask & IN_MODIFY))
            saw_file_mod = 1;
        off += (ssize_t)(sizeof(*ev) + ev->len);
    }
    CHECK(saw_create, "dir inotify watch missed IN_CREATE after eviction");
    CHECK(saw_file_mod, "file inotify watch missed IN_MODIFY after eviction");

    /* Copied-up file (evicted during the walk) still reports its origin ino in stat and readdir */
    struct stat copied_st_after;
    CHECK(stat("/tmp/ovl_evict/m/copied", &copied_st_after) == 0, "stat copied after walk");
    CHECK(copied_st_after.st_ino == copied_st_before.st_ino,
          "copied-up file lost origin st_ino after eviction (%lu vs %lu)",
          (unsigned long)copied_st_after.st_ino, (unsigned long)copied_st_before.st_ino);
    CHECK(readdir_ino("/tmp/ovl_evict/m", "copied") == copied_st_before.st_ino,
          "readdir d_ino disagrees with origin st_ino after eviction");

    /* Earliest walked (evicted) entries can be looked up, copied up, renamed, and unlinked */
    CHECK(stat("/tmp/ovl_evict/m/b00/f000", &st) == 0, "re-stat evicted entry");
    int ef = open("/tmp/ovl_evict/m/b00/f000", O_WRONLY);
    CHECK(ef >= 0, "copy-up evicted entry");
    write_all(ef, "evicted-ok", 10);
    CHECK(close(ef) == 0, "close evicted entry");
    CHECK(rename("/tmp/ovl_evict/m/b00/f000", "/tmp/ovl_evict/m/b00/f000_renamed") == 0,
          "rename evicted entry");
    read_file_str("/tmp/ovl_evict/m/b00/f000_renamed", buf, sizeof(buf));
    CHECK(strcmp(buf, "evicted-ok") == 0, "renamed evicted content mismatch: %s", buf);
    CHECK(unlink("/tmp/ovl_evict/m/b00/f000_renamed") == 0, "unlink evicted entry");

    /* Clean up */
    CHECK(chdir(saved_cwd) == 0, "restore cwd");
    CHECK(close(inot_fd) == 0, "close inot_fd");
    CHECK(close(dir_fd) == 0, "close dir_fd");
    CHECK(close(open_fd) == 0, "close open_fd");
    CHECK(umount2("/tmp/ovl_evict/m", 0) == 0, "umount overlay");
    CHECK(umount2("/tmp/ovl_evict", 0) == 0, "umount tmpfs");
    CHECK(rmdir("/tmp/ovl_evict") == 0, "rmdir base");
}

static void run_mmap_copy_up_suite(const char *base, int upper_on_tmpfs)
{
    char lower[128], upper[128], work[128], merged[128], opts[512];
    char p_l[256], p_m[256], p_u[256];

    CHECK(mkdir(base, 0755) == 0, "mkdir %s", base);
    snprintf(lower, sizeof(lower), "%s/l", base);
    snprintf(upper, sizeof(upper), "%s/u", base);
    snprintf(work, sizeof(work), "%s/w", base);
    snprintf(merged, sizeof(merged), "%s/m", base);
    CHECK(mkdir(lower, 0755) == 0, "mkdir lower");
    CHECK(mkdir(upper, 0755) == 0, "mkdir upper");
    CHECK(mkdir(merged, 0755) == 0, "mkdir merged");
    if (upper_on_tmpfs) {
        CHECK(mount("tmpfs", upper, "tmpfs", 0, "size=4m") == 0, "mount tmpfs upper");
        snprintf(work, sizeof(work), "%s/u/work", base);
        char real_upper[128];
        snprintf(real_upper, sizeof(real_upper), "%s/u/up", base);
        CHECK(mkdir(real_upper, 0755) == 0, "mkdir tmpfs up");
        CHECK(mkdir(work, 0755) == 0, "mkdir tmpfs work");
        snprintf(upper, sizeof(upper), "%s", real_upper);
    } else {
        CHECK(mkdir(work, 0755) == 0, "mkdir work");
    }

    snprintf(p_l, sizeof(p_l), "%s/f1", lower);
    create_file(p_l, "LOWER_DATA_0123456789", 0644);
    snprintf(p_l, sizeof(p_l), "%s/f2", lower);
    {
        int fd = open(p_l, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        CHECK(fd >= 0, "create f2");
        char page[4096];
        memset(page, 'A', sizeof(page));
        write_all(fd, page, sizeof(page));
        close(fd);
    }
    snprintf(p_l, sizeof(p_l), "%s/f3", lower);
    create_file(p_l, "META_LOWER_ORIGINAL", 0644);
    snprintf(p_l, sizeof(p_l), "%s/f4", lower);
    create_file(p_l, "BEFORE_COPYUP_LOWER", 0644);

    snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);
    CHECK(mount("overlay", merged, "overlay", 0, opts) == 0, "mount overlay %s", base);

    /* Subtest 2a: open O_RDONLY before copy-up -> write via another fd -> mmap on pre-copy-up fd */
    snprintf(p_m, sizeof(p_m), "%s/f1", merged);
    int rfd1 = open(p_m, O_RDONLY);
    CHECK(rfd1 >= 0, "open f1 O_RDONLY before copy-up");

    int wfd1 = open(p_m, O_WRONLY);
    CHECK(wfd1 >= 0, "open f1 O_WRONLY (copy-up)");
    write_all(wfd1, "UPPER_DATA_ABCDEFGHIJ", 21);
    CHECK(close(wfd1) == 0, "close wfd1");

    /* First operation on rfd1 is mmap (no prior read/fstat/lseek) */
    char *mp1_priv = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, rfd1, 0);
    CHECK(mp1_priv != MAP_FAILED, "mmap MAP_PRIVATE on pre-copy-up fd");
    CHECK(memcmp(mp1_priv, "UPPER_DATA_ABCDEFGHIJ", 21) == 0,
          "MAP_PRIVATE on pre-copy-up fd saw stale lower: %.21s", mp1_priv);

    char *mp1_shared = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd1, 0);
    CHECK(mp1_shared != MAP_FAILED, "mmap MAP_SHARED on pre-copy-up fd");
    CHECK(memcmp(mp1_shared, "UPPER_DATA_ABCDEFGHIJ", 21) == 0,
          "MAP_SHARED on pre-copy-up fd saw stale lower: %.21s", mp1_shared);

    /* Subsequent writes through overlay must be visible in MAP_SHARED mapping */
    wfd1 = open(p_m, O_WRONLY);
    CHECK(wfd1 >= 0, "reopen f1 O_WRONLY");
    write_all(wfd1, "SECOND_UPD_9876543210", 21);
    CHECK(close(wfd1) == 0, "close wfd1 second");
    CHECK(memcmp(mp1_shared, "SECOND_UPD_9876543210", 21) == 0,
          "MAP_SHARED did not observe post-mmap write: %.21s", mp1_shared);

    CHECK(munmap(mp1_shared, 4096) == 0, "munmap mp1_shared");
    CHECK(munmap(mp1_priv, 4096) == 0, "munmap mp1_priv");
    CHECK(close(rfd1) == 0, "close rfd1");

    /* Verify lower f1 is completely untouched */
    char checkbuf[64];
    snprintf(p_l, sizeof(p_l), "%s/f1", lower);
    read_file_str(p_l, checkbuf, sizeof(checkbuf));
    CHECK(strcmp(checkbuf, "LOWER_DATA_0123456789") == 0,
          "lower f1 was modified: %s", checkbuf);

    /* Subtest 2b: truncate copy-up -> mmap on pre-copy-up fd */
    snprintf(p_m, sizeof(p_m), "%s/f2", merged);
    int rfd2 = open(p_m, O_RDONLY);
    CHECK(rfd2 >= 0, "open f2 O_RDONLY before truncate");
    CHECK(truncate(p_m, 0) == 0, "truncate f2 to 0");
    int wfd2 = open(p_m, O_WRONLY);
    CHECK(wfd2 >= 0, "open f2 O_WRONLY");
    write_all(wfd2, "TRUNC_UPPER", 11);
    CHECK(close(wfd2) == 0, "close wfd2");

    char *mp2 = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, rfd2, 0);
    CHECK(mp2 != MAP_FAILED, "mmap f2 after truncate copy-up");
    CHECK(memcmp(mp2, "TRUNC_UPPER", 11) == 0 && mp2[11] == '\0' && mp2[100] == '\0',
          "mmap f2 saw stale pre-truncate data");
    CHECK(munmap(mp2, 4096) == 0, "munmap mp2");
    CHECK(close(rfd2) == 0, "close rfd2");

    /* Subtest 2c: metadata-only copy-up (sharing lower object) -> MAP_SHARED on pre-copy-up fd ->
     * later write unshares upper and is visible in MAP_SHARED while lower stays intact */
    snprintf(p_m, sizeof(p_m), "%s/f3", merged);
    int rfd3 = open(p_m, O_RDONLY);
    CHECK(rfd3 >= 0, "open f3 O_RDONLY before chmod");
    CHECK(chmod(p_m, 0600) == 0, "chmod f3 (metadata copy-up)");

    char *mp3 = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd3, 0);
    CHECK(mp3 != MAP_FAILED, "mmap MAP_SHARED f3 after metadata copy-up");
    CHECK(memcmp(mp3, "META_LOWER_ORIGINAL", 19) == 0,
          "mp3 initial data wrong: %.19s", mp3);

    int wfd3 = open(p_m, O_WRONLY);
    CHECK(wfd3 >= 0, "open f3 O_WRONLY after mmap");
    write_all(wfd3, "META_UPPER_MODIFIED", 19);
    CHECK(close(wfd3) == 0, "close wfd3");
    CHECK(memcmp(mp3, "META_UPPER_MODIFIED", 19) == 0,
          "MAP_SHARED after metadata copy-up missed write: %.19s", mp3);

    CHECK(munmap(mp3, 4096) == 0, "munmap mp3");
    CHECK(close(rfd3) == 0, "close rfd3");

    snprintf(p_l, sizeof(p_l), "%s/f3", lower);
    read_file_str(p_l, checkbuf, sizeof(checkbuf));
    CHECK(strcmp(checkbuf, "META_LOWER_ORIGINAL") == 0,
          "lower f3 was modified: %s", checkbuf);

    /* Subtest 2d: existing mapping created BEFORE copy-up stays isolated; new mmap on same fd
     * AFTER copy-up follows copy-up to upper */
    snprintf(p_m, sizeof(p_m), "%s/f4", merged);
    int rfd4 = open(p_m, O_RDONLY);
    CHECK(rfd4 >= 0, "open f4 O_RDONLY");
    char *mp4_before = mmap(NULL, 4096, PROT_READ, MAP_SHARED, rfd4, 0);
    CHECK(mp4_before != MAP_FAILED, "mmap f4 before copy-up");
    CHECK(memcmp(mp4_before, "BEFORE_COPYUP_LOWER", 19) == 0,
          "mp4_before wrong: %.19s", mp4_before);

    int wfd4 = open(p_m, O_WRONLY);
    CHECK(wfd4 >= 0, "open f4 O_WRONLY");
    write_all(wfd4, "AFTER_COPYUP_UPPER!", 19);
    CHECK(close(wfd4) == 0, "close wfd4");

    /* Pre-copy-up mapping stays isolated with lower data */
    CHECK(memcmp(mp4_before, "BEFORE_COPYUP_LOWER", 19) == 0,
          "pre-copy-up mapping was corrupted by upper write: %.19s", mp4_before);

    /* New mapping on the same fd after copy-up sees upper data */
    char *mp4_after = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, rfd4, 0);
    CHECK(mp4_after != MAP_FAILED, "mmap f4 after copy-up");
    CHECK(memcmp(mp4_after, "AFTER_COPYUP_UPPER!", 19) == 0,
          "post-copy-up mmap on same fd saw stale lower: %.19s", mp4_after);

    /* O_RDONLY fd must still reject MAP_SHARED|PROT_WRITE with EACCES after copy-up */
    void *bad = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, rfd4, 0);
    CHECK(bad == MAP_FAILED && errno == EACCES, "MAP_SHARED|PROT_WRITE on O_RDONLY must EACCES");

    CHECK(munmap(mp4_after, 4096) == 0, "munmap mp4_after");
    CHECK(munmap(mp4_before, 4096) == 0, "munmap mp4_before");
    CHECK(close(rfd4) == 0, "close rfd4");

    snprintf(p_l, sizeof(p_l), "%s/f4", lower);
    read_file_str(p_l, checkbuf, sizeof(checkbuf));
    CHECK(strcmp(checkbuf, "BEFORE_COPYUP_LOWER") == 0,
          "lower f4 was modified: %s", checkbuf);

    /* Sanity check upper file exists */
    snprintf(p_u, sizeof(p_u), "%s/f4", upper);
    read_file_str(p_u, checkbuf, sizeof(checkbuf));
    CHECK(strcmp(checkbuf, "AFTER_COPYUP_UPPER!") == 0,
          "upper f4 mismatch: %s", checkbuf);

    CHECK(umount2(merged, 0) == 0, "umount overlay %s", base);
    if (upper_on_tmpfs) {
        char upper_mnt[128];
        snprintf(upper_mnt, sizeof(upper_mnt), "%s/u", base);
        CHECK(umount2(upper_mnt, 0) == 0, "umount tmpfs upper %s", base);
    }
}

int main(void)
{
    CHECK(mkdir("/tmp", 0777) == 0 || errno == EEXIST, "mkdir /tmp");
    test_bounded_overlay_node_cache();
    run_mmap_copy_up_suite("/tmp/ovl_mmap_store", 0);
    run_mmap_copy_up_suite("/tmp/ovl_mmap_tmpfs", 1);
    printf("all ok\n");
    return 0;
}
