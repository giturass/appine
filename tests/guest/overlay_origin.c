#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

static ino_t inode(const char *path)
{
    struct stat st;
    assert(stat(path, &st) == 0);
    return st.st_ino;
}

/* Read the listing before stat can populate the overlay's origin cache. */
static void check_entry(const char *dir, const char *name, ino_t ino)
{
    DIR *d = opendir(dir);
    assert(d);
    struct dirent *e;
    do {
        e = readdir(d);
    } while (e && strcmp(e->d_name, name));
    assert(e && e->d_ino == ino);
    struct stat st;
    assert(fstatat(dirfd(d), name, &st, 0) == 0 && st.st_ino == ino);
    assert(closedir(d) == 0);
}

static void private_attr(const char *path, const char *name)
{
    char buf[512];
    assert(getxattr(path, name, buf, sizeof(buf)) == -1 && errno == EOPNOTSUPP);
    ssize_t n = listxattr(path, buf, sizeof(buf));
    assert(n >= 0);
    for (ssize_t i = 0; i < n; i += strlen(buf + i) + 1)
        assert(strcmp(buf + i, name));
}

static void exercise(int user)
{
    const char *options = user ? "lowerdir=l,upperdir=u,workdir=w,userxattr"
                               : "lowerdir=l,upperdir=u,workdir=w";
    const char *origin = user ? "user.overlay.origin" : "trusted.overlay.origin";
    const char *impure = user ? "user.overlay.impure" : "trusted.overlay.impure";
    assert(mkdir("l", 0755) == 0 && mkdir("u", 0755) == 0);
    assert(mkdir("w", 0755) == 0 && mkdir("m", 0755) == 0);
    assert(mkdir("l/d", 0755) == 0 && mkdir("u/to", 0755) == 0);
    assert(mkdir("u/links", 0755) == 0 && mkdir("u/exchange", 0755) == 0);
    assert(close(creat("u/exchange/plain", 0644)) == 0);
    assert(close(creat("l/f", 0644)) == 0);
    ino_t file = inode("l/f"), dir = inode("l/d");
    assert(mount("overlay", "m", "overlay", 0, options) == 0);
    assert(chmod("m/d", 0700) == 0 && chmod("m/f", 0600) == 0);
    check_entry("m", "d", dir);
    check_entry("m", "f", file);
    assert(rename("m/f", "m/to/moved") == 0);
    assert(link("m/to/moved", "m/links/alias") == 0);
    assert(umount("m") == 0);

    char marker;
    assert(getxattr("u/to/moved", origin, NULL, 0) > 0);
    assert(getxattr("u/d", origin, NULL, 0) > 0);
    assert(getxattr("u", impure, &marker, 1) == 1 && marker == 'y');
    assert(getxattr("u/to", impure, &marker, 1) == 1 && marker == 'y');
    assert(getxattr("u/links", impure, &marker, 1) == 1 && marker == 'y');

    assert(mount("overlay", "m", "overlay", 0, options) == 0);
    check_entry("m", "d", dir);
    check_entry("m/to", "moved", file);
    check_entry("m/links", "alias", file);
    private_attr("m/d", origin);
    private_attr("m/to/moved", origin);
    private_attr("m", impure);
    private_attr("m/to", impure);
    /* The destination carries the origin back into the source directory on exchange. */
    assert(syscall(SYS_renameat2, AT_FDCWD, "m/exchange/plain", AT_FDCWD, "m/links/alias",
                   RENAME_EXCHANGE) == 0);
    assert(umount("m") == 0);
    assert(getxattr("u/exchange", impure, &marker, 1) == 1 && marker == 'y');
    assert(mount("overlay", "m", "overlay", 0, options) == 0);
    check_entry("m/exchange", "plain", file);
    assert(umount("m") == 0);
}

int main(void)
{
    assert(mkdir("/trusted", 0755) == 0 && chdir("/trusted") == 0);
    exercise(0);
    assert(mkdir("/user", 0755) == 0 && chdir("/user") == 0);
    exercise(1);
    puts("all ok");
    return 0;
}
