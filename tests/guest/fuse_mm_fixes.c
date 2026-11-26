/*
 * End-to-end regression tests for FUSE and FUSE-mm fixes (both Tier 0 and Tier 1):
 * 1. AF_UNIX bind/listen/connect/send/recv in a FUSE directory (via FUSE_MKNOD), duplicate bind
 *    EADDRINUSE, and node survival across drop_caches while bound.
 * 2. Batched multi-component uncached FUSE lookup walks (exact LOOKUP count without O(n^2)
 *    restarts) and non-ENOENT lookup error propagation/tolerance.
 * 3. Periodic dirty-page writeback via dirty_writeback_centisecs (real kernel timer thread
 *    writing modified shared mmap bytes without msync/munmap).
 * 4. FUSE_NOTIFY_STORE populating cold pages without FUSE_READ and updating resident data +
 *    executable code (Tier 1 code-cache invalidation).
 * 5. FUSE_AUTO_INVAL_DATA refreshing resident mappings when GETATTR sees updated mtime.
 * 6. mlock, mlock2, mlockall, and madvise(MADV_WILLNEED) fetching cold FUSE demand-read pages.
 * 7. Syscall prefault / local result-copy retry safety on cold FUSE mappings:
 *    - epoll_pwait (EPOLLONESHOT) writing events into cold FUSE page
 *    - sendfile and copy_file_range updating cold FUSE-mapped *offset
 *    - getrandom (>64 KiB) into cold FUSE pages without short count
 *    - readv with cold FUSE-mapped iovec array
 *    - pipe2 and socketpair writing fds into cold FUSE pages
 *    - io_setup / io_submit / io_getevents with cold FUSE buffers (no -600 in io_event.res)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(cond, fmt, ...)                                                                      \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d: %s)\n", __FILE__, __LINE__,            \
                    ##__VA_ARGS__, errno, strerror(errno));                                        \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

#ifndef SYS_copy_file_range
#define SYS_copy_file_range 285
#endif
#ifndef SYS_io_setup
#define SYS_io_setup 0
#endif
#ifndef SYS_io_destroy
#define SYS_io_destroy 1
#endif
#ifndef SYS_io_submit
#define SYS_io_submit 2
#endif
#ifndef SYS_io_getevents
#define SYS_io_getevents 4
#endif
#ifndef SYS_mlock2
#define SYS_mlock2 284
#endif

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

struct fuse_init_in {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
};

struct fuse_init_out {
    uint32_t major;
    uint32_t minor;
    uint32_t max_readahead;
    uint32_t flags;
    uint16_t max_background;
    uint16_t congestion_threshold;
    uint32_t max_write;
    uint32_t time_gran;
    uint16_t max_pages;
    uint16_t map_alignment;
    uint32_t flags2;
    uint32_t unused[7];
};

struct fuse_mknod_in {
    uint32_t mode;
    uint32_t rdev;
    uint32_t umask;
    uint32_t padding;
};

struct fuse_open_out {
    uint64_t fh;
    uint32_t open_flags;
    uint32_t padding;
};

struct fuse_read_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t read_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_write_in {
    uint64_t fh;
    uint64_t offset;
    uint32_t size;
    uint32_t write_flags;
    uint64_t lock_owner;
    uint32_t flags;
    uint32_t padding;
};

struct fuse_write_out {
    uint32_t size;
    uint32_t padding;
};

struct fuse_notify_store_out {
    uint64_t nodeid;
    uint64_t offset;
    uint32_t size;
    uint32_t padding;
};

/* Minimal Linux 6.1 AIO structs */
struct my_iocb {
    uint64_t aio_data;
    uint32_t aio_key;
    uint32_t aio_rw_flags;
    uint16_t aio_lio_opcode;
    int16_t aio_reqprio;
    uint32_t aio_fildes;
    uint64_t aio_buf;
    uint64_t aio_nbytes;
    int64_t aio_offset;
    uint64_t aio_reserved2;
    uint32_t aio_flags;
    uint32_t aio_resfd;
};

struct my_io_event {
    uint64_t data;
    uint64_t obj;
    int64_t res;
    int64_t res2;
};

enum {
    FUSE_LOOKUP = 1,
    FUSE_FORGET = 2,
    FUSE_GETATTR = 3,
    FUSE_MKNOD = 8,
    FUSE_UNLINK = 10,
    FUSE_OPEN = 14,
    FUSE_READ = 15,
    FUSE_WRITE = 16,
    FUSE_RELEASE = 18,
    FUSE_FLUSH = 25,
    FUSE_INIT = 26,
    FUSE_BATCH_FORGET = 42,
    FUSE_AUTO_INVAL_DATA = (1u << 12),
    FUSE_NOTIFY_STORE = 4,
};

enum {
    NODE_D1 = 10,
    NODE_D2 = 11,
    NODE_D3 = 12,
    NODE_D4 = 13,
    NODE_DEEP = 14,
    NODE_SOCK = 20,
    NODE_WB = 30,
    NODE_STORE_COLD = 31,
    NODE_STORE_CODE = 32,
    NODE_INVAL = 33,
    NODE_WILLNEED = 34,
    NODE_MLOCK = 35,
    NODE_MLOCKALL = 36,
    NODE_SCRATCH = 37,
};

static int g_fuse_fd = -1;
static atomic_int g_stop = 0;
static atomic_int g_sock_created = 0;
static atomic_uint g_sock_mode = 0;
static atomic_int g_deep_lookups = 0;
static atomic_int g_wb_writes = 0;
static atomic_int g_wb_matched = 0;
static atomic_int g_inval_ver = 0;
static atomic_int g_willneed_reads = 0;
static atomic_int g_mlock_reads = 0;
static atomic_int g_mlockall_reads = 0;
static atomic_int g_store_cold_reads = 0;

static uint8_t g_wb_buf[8192];
static pthread_mutex_t g_wb_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_reply_mu = PTHREAD_MUTEX_INITIALIZER;

static void fill_attr(struct fuse_attr *a, uint64_t ino, uint32_t mode, uint64_t size,
                      uint64_t mtime) {
    memset(a, 0, sizeof(*a));
    a->ino = ino;
    a->size = size;
    a->mode = mode;
    a->nlink = S_ISDIR(mode) ? 2 : 1;
    a->blksize = 4096;
    a->mtime = mtime;
    a->ctime = mtime;
}

static void reply_raw(uint64_t unique, int32_t err, const void *body, size_t body_len) {
    static uint8_t buf[131072];
    pthread_mutex_lock(&g_reply_mu);
    struct fuse_out_hdr hdr = {
        .len = (uint32_t)(sizeof(hdr) + body_len),
        .error = err,
        .unique = unique,
    };
    memcpy(buf, &hdr, sizeof(hdr));
    if (body_len)
        memcpy(buf + sizeof(hdr), body, body_len);
    ssize_t n = write(g_fuse_fd, buf, sizeof(hdr) + body_len);
    (void)n;
    pthread_mutex_unlock(&g_reply_mu);
}

static void send_notify_store(uint64_t nodeid, uint64_t offset, const void *data, uint32_t size) {
    static uint8_t body[16384];
    struct fuse_notify_store_out st = {
        .nodeid = nodeid,
        .offset = offset,
        .size = size,
        .padding = 0,
    };
    memcpy(body, &st, sizeof(st));
    memcpy(body + sizeof(st), data, size);
    reply_raw(0, FUSE_NOTIFY_STORE, body, sizeof(st) + size);
}

static uint64_t node_size(uint64_t id) {
    switch (id) {
    case NODE_WB:
        return 8192;
    case NODE_STORE_COLD:
        return 4096;
    case NODE_STORE_CODE:
        return 4096;
    case NODE_INVAL:
        return 4096;
    case NODE_WILLNEED:
        return 8192;
    case NODE_MLOCK:
        return 256 * 1024;
    case NODE_MLOCKALL:
        return 4096;
    case NODE_SCRATCH:
        return 256 * 1024;
    default:
        return 4096;
    }
}

static uint32_t node_mode(uint64_t id) {
    switch (id) {
    case 1:
    case NODE_D1:
    case NODE_D2:
    case NODE_D3:
    case NODE_D4:
        return S_IFDIR | 0755;
    case NODE_SOCK:
        return S_IFSOCK | (atomic_load(&g_sock_mode) & 0777);
    case NODE_STORE_CODE:
        return S_IFREG | 0755;
    default:
        return S_IFREG | 0666;
    }
}

static void *daemon_thread(void *arg) {
    (void)arg;
    static uint8_t req[131072];
    for (;;) {
        ssize_t n = read(g_fuse_fd, req, sizeof(req));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ENODEV || atomic_load(&g_stop))
                break;
            continue;
        }
        if ((size_t)n < sizeof(struct fuse_in_hdr))
            continue;
        struct fuse_in_hdr hdr;
        memcpy(&hdr, req, sizeof(hdr));
        const uint8_t *in = req + sizeof(hdr);

        switch (hdr.opcode) {
        case FUSE_INIT: {
            struct fuse_init_in init_in;
            memcpy(&init_in, in, sizeof(init_in));
            struct fuse_init_out out;
            memset(&out, 0, sizeof(out));
            out.major = 7;
            out.minor = 37;
            out.flags = init_in.flags & FUSE_AUTO_INVAL_DATA;
            out.max_write = 65536;
            out.time_gran = 1;
            reply_raw(hdr.unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_FORGET:
        case FUSE_BATCH_FORGET:
            break;
        case FUSE_LOOKUP: {
            const char *name = (const char *)in;
            uint64_t child = 0;
            uint64_t valid = 60;
            if (hdr.nodeid == 1 && strcmp(name, "d1") == 0) {
                atomic_fetch_add(&g_deep_lookups, 1);
                child = NODE_D1;
                valid = 0;
            } else if (hdr.nodeid == NODE_D1 && strcmp(name, "d2") == 0) {
                atomic_fetch_add(&g_deep_lookups, 1);
                child = NODE_D2;
                valid = 0;
            } else if (hdr.nodeid == NODE_D2 && strcmp(name, "d3") == 0) {
                atomic_fetch_add(&g_deep_lookups, 1);
                child = NODE_D3;
                valid = 0;
            } else if (hdr.nodeid == NODE_D3 && strcmp(name, "d4") == 0) {
                atomic_fetch_add(&g_deep_lookups, 1);
                child = NODE_D4;
                valid = 0;
            } else if (hdr.nodeid == NODE_D4 && strcmp(name, "deep") == 0) {
                atomic_fetch_add(&g_deep_lookups, 1);
                child = NODE_DEEP;
                valid = 0;
            } else if (hdr.nodeid == 1 && strcmp(name, "eio_err") == 0) {
                reply_raw(hdr.unique, -EIO, NULL, 0);
                break;
            } else if (hdr.nodeid == 1 && strcmp(name, "test.sock") == 0 &&
                       atomic_load(&g_sock_created)) {
                child = NODE_SOCK;
            } else if (hdr.nodeid == 1 && strcmp(name, "wb") == 0) {
                child = NODE_WB;
            } else if (hdr.nodeid == 1 && strcmp(name, "store_cold") == 0) {
                child = NODE_STORE_COLD;
            } else if (hdr.nodeid == 1 && strcmp(name, "store_code") == 0) {
                child = NODE_STORE_CODE;
            } else if (hdr.nodeid == 1 && strcmp(name, "inval") == 0) {
                child = NODE_INVAL;
                valid = 0;
            } else if (hdr.nodeid == 1 && strcmp(name, "willneed") == 0) {
                child = NODE_WILLNEED;
            } else if (hdr.nodeid == 1 && strcmp(name, "mlock") == 0) {
                child = NODE_MLOCK;
            } else if (hdr.nodeid == 1 && strcmp(name, "mlockall") == 0) {
                child = NODE_MLOCKALL;
            } else if (hdr.nodeid == 1 && strcmp(name, "scratch") == 0) {
                child = NODE_SCRATCH;
            }

            if (child == 0) {
                reply_raw(hdr.unique, -ENOENT, NULL, 0);
            } else {
                struct fuse_entry_out e;
                memset(&e, 0, sizeof(e));
                e.nodeid = child;
                e.entry_valid = valid;
                e.attr_valid = valid;
                uint64_t mt = (child == NODE_INVAL) ? (100 + (uint64_t)atomic_load(&g_inval_ver)) : 10;
                fill_attr(&e.attr, child, node_mode(child), node_size(child), mt);
                reply_raw(hdr.unique, 0, &e, sizeof(e));
            }
            break;
        }
        case FUSE_MKNOD: {
            struct fuse_mknod_in mk;
            memcpy(&mk, in, sizeof(mk));
            const char *name = (const char *)(in + sizeof(mk));
            if (hdr.nodeid == 1 && strcmp(name, "test.sock") == 0 && S_ISSOCK(mk.mode)) {
                atomic_store(&g_sock_mode, mk.mode);
                atomic_store(&g_sock_created, 1);
                struct fuse_entry_out e;
                memset(&e, 0, sizeof(e));
                e.nodeid = NODE_SOCK;
                e.entry_valid = 60;
                e.attr_valid = 60;
                fill_attr(&e.attr, NODE_SOCK, mk.mode, 0, 10);
                reply_raw(hdr.unique, 0, &e, sizeof(e));
            } else {
                reply_raw(hdr.unique, -EINVAL, NULL, 0);
            }
            break;
        }
        case FUSE_UNLINK: {
            const char *name = (const char *)in;
            if (hdr.nodeid == 1 && strcmp(name, "test.sock") == 0) {
                atomic_store(&g_sock_created, 0);
                reply_raw(hdr.unique, 0, NULL, 0);
            } else {
                reply_raw(hdr.unique, -ENOENT, NULL, 0);
            }
            break;
        }
        case FUSE_GETATTR: {
            struct fuse_attr_out a;
            memset(&a, 0, sizeof(a));
            a.attr_valid = (hdr.nodeid == NODE_INVAL) ? 0 : 60;
            uint64_t mt = (hdr.nodeid == NODE_INVAL) ? (100 + (uint64_t)atomic_load(&g_inval_ver)) : 10;
            fill_attr(&a.attr, hdr.nodeid, node_mode(hdr.nodeid), node_size(hdr.nodeid), mt);
            reply_raw(hdr.unique, 0, &a, sizeof(a));
            break;
        }
        case FUSE_OPEN: {
            struct fuse_open_out o = {.fh = hdr.nodeid, .open_flags = 0, .padding = 0};
            reply_raw(hdr.unique, 0, &o, sizeof(o));
            break;
        }
        case FUSE_READ: {
            struct fuse_read_in r;
            memcpy(&r, in, sizeof(r));
            static uint8_t data[131072];
            size_t sz = r.size;
            uint64_t fsz = node_size(hdr.nodeid);
            if (r.offset >= fsz) {
                sz = 0;
            } else if (r.offset + sz > fsz) {
                sz = (size_t)(fsz - r.offset);
            }
            if (hdr.nodeid == NODE_WB) {
                pthread_mutex_lock(&g_wb_mu);
                memcpy(data, g_wb_buf + r.offset, sz);
                pthread_mutex_unlock(&g_wb_mu);
            } else if (hdr.nodeid == NODE_STORE_COLD) {
                atomic_fetch_add(&g_store_cold_reads, 1);
                memset(data, 'X', sz);
            } else if (hdr.nodeid == NODE_STORE_CODE) {
                memset(data, 0, sz);
                /* mov w0, #11; ret (aarch64) */
                if (r.offset == 0 && sz >= 8) {
                    uint32_t insns[2] = {0x52800160u, 0xd65f03c0u};
                    memcpy(data, insns, sizeof(insns));
                }
            } else if (hdr.nodeid == NODE_INVAL) {
                int v = atomic_load(&g_inval_ver);
                memset(data, v == 0 ? 'O' : 'N', sz);
            } else if (hdr.nodeid == NODE_WILLNEED) {
                atomic_fetch_add(&g_willneed_reads, (int)sz);
                memset(data, 'W', sz);
            } else if (hdr.nodeid == NODE_MLOCK) {
                atomic_fetch_add(&g_mlock_reads, 1);
                memset(data, 'M', sz);
            } else if (hdr.nodeid == NODE_MLOCKALL) {
                atomic_fetch_add(&g_mlockall_reads, 1);
                memset(data, 'L', sz);
            } else {
                memset(data, 0, sz);
            }
            reply_raw(hdr.unique, 0, data, sz);
            break;
        }
        case FUSE_WRITE: {
            struct fuse_write_in w;
            memcpy(&w, in, sizeof(w));
            const uint8_t *payload = in + sizeof(w);
            if (hdr.nodeid == NODE_WB && w.offset + w.size <= sizeof(g_wb_buf)) {
                pthread_mutex_lock(&g_wb_mu);
                memcpy(g_wb_buf + w.offset, payload, w.size);
                if (memcmp(g_wb_buf + 32, "AUTO_WB_OK!", 11) == 0)
                    atomic_store(&g_wb_matched, 1);
                pthread_mutex_unlock(&g_wb_mu);
                atomic_fetch_add(&g_wb_writes, 1);
            }
            struct fuse_write_out out = {.size = w.size, .padding = 0};
            reply_raw(hdr.unique, 0, &out, sizeof(out));
            break;
        }
        case FUSE_FLUSH:
        case FUSE_RELEASE:
            reply_raw(hdr.unique, 0, NULL, 0);
            break;
        default:
            reply_raw(hdr.unique, -ENOSYS, NULL, 0);
            break;
        }
    }
    return NULL;
}

static void test_unix_bind_in_fuse(const char *mnt) {
    char spath[256];
    snprintf(spath, sizeof(spath), "%s/test.sock", mnt);

    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(srv >= 0, "socket");
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, spath);
    CHECK(bind(srv, (struct sockaddr *)&sa, sizeof(sa)) == 0, "bind on FUSE failed");
    CHECK(listen(srv, 4) == 0, "listen");

    /* Duplicate bind -> EADDRINUSE */
    int dup = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(dup >= 0, "dup socket");
    errno = 0;
    CHECK(bind(dup, (struct sockaddr *)&sa, sizeof(sa)) == -1 && errno == EADDRINUSE,
          "duplicate bind should fail with EADDRINUSE");
    close(dup);

    /* drop_caches while bound must not evict the socket binding */
    int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (dc >= 0) {
        CHECK(write(dc, "2", 1) == 1, "drop_caches");
        close(dc);
    }

    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(cli >= 0, "client socket");
    CHECK(connect(cli, (struct sockaddr *)&sa, sizeof(sa)) == 0, "connect on FUSE socket failed");
    int acc = accept(srv, NULL, NULL);
    CHECK(acc >= 0, "accept");
    CHECK(send(cli, "ping", 4, 0) == 4, "send");
    char rbuf[8] = {0};
    CHECK(recv(acc, rbuf, 4, 0) == 4 && memcmp(rbuf, "ping", 4) == 0, "recv mismatch");
    close(acc);
    close(cli);
    close(srv);
    CHECK(unlink(spath) == 0, "unlink FUSE socket");
}

static void test_lookup_walk_and_errors(const char *mnt) {
    char deep[256];
    snprintf(deep, sizeof(deep), "%s/d1/d2/d3/d4/deep", mnt);
    atomic_store(&g_deep_lookups, 0);
    struct stat st;
    CHECK(stat(deep, &st) == 0, "stat deep FUSE path");
    CHECK(st.st_ino == NODE_DEEP, "deep ino mismatch");
    CHECK(atomic_load(&g_deep_lookups) == 5, "expected exactly 5 LOOKUPs, got %d",
          atomic_load(&g_deep_lookups));

    char eio_path[256];
    snprintf(eio_path, sizeof(eio_path), "%s/eio_err", mnt);
    errno = 0;
    CHECK(stat(eio_path, &st) == -1 && errno == EIO, "expected EIO on lookup error");
}

static void test_periodic_writeback(const char *mnt) {
    /* Configure a short 50ms periodic writeback interval before dirtying. */
    int sc = open("/proc/sys/vm/dirty_writeback_centisecs", O_WRONLY);
    CHECK(sc >= 0, "open dirty_writeback_centisecs");
    CHECK(write(sc, "5\n", 2) == 2, "write dirty_writeback_centisecs");
    close(sc);

    char path[256];
    snprintf(path, sizeof(path), "%s/wb", mnt);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0, "open wb");
    char *p = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(p != MAP_FAILED, "mmap wb");

    /* Write via guest store without calling msync or munmap. */
    memcpy(p + 32, "AUTO_WB_OK!", 11);

    /* Wait up to 2s for periodic background writeback from the timer thread. */
    for (int i = 0; i < 200 && !atomic_load(&g_wb_matched); i++)
        usleep(10000);
    CHECK(atomic_load(&g_wb_matched) == 1,
          "periodic dirty-page writeback did not flush mapped writes (writes=%d)",
          atomic_load(&g_wb_writes));
    munmap(p, 8192);
    close(fd);
}

static void test_notify_store_and_auto_inval(const char *mnt) {
    /* 1. FUSE_NOTIFY_STORE supplies cold page 0 without FUSE_READ. */
    char path[256];
    snprintf(path, sizeof(path), "%s/store_cold", mnt);
    int fd = open(path, O_RDWR);
    CHECK(fd >= 0, "open store_cold");
    char *p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(p != MAP_FAILED, "mmap store_cold");
    uint8_t page[4096];
    memset(page, 'S', sizeof(page));
    send_notify_store(NODE_STORE_COLD, 0, page, sizeof(page));
    CHECK(p[0] == 'S' && p[4095] == 'S', "notify_store cold data mismatch");
    CHECK(atomic_load(&g_store_cold_reads) == 0, "notify_store should avoid FUSE_READ");
    munmap(p, 4096);
    close(fd);

    /* 2. FUSE_NOTIFY_STORE invalidates Tier 1 executable code cache. */
    snprintf(path, sizeof(path), "%s/store_code", mnt);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open store_code");
    void *code = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
    CHECK(code != MAP_FAILED, "mmap store_code");
    int (*fn)(void) = (int (*)(void))code;
    /* Execute repeatedly so Tier 1 JIT compiles it if running under Tier 1. */
    for (int i = 0; i < 64; i++)
        CHECK(fn() == 11, "initial code returned %d", fn());
    /* Update code to `mov w0, #42; ret` via FUSE_NOTIFY_STORE. */
    uint32_t insns[2] = {0x52800540u, 0xd65f03c0u};
    send_notify_store(NODE_STORE_CODE, 0, insns, sizeof(insns));
    __builtin___clear_cache((char *)code, (char *)code + 8);
    CHECK(fn() == 42, "updated code after FUSE_NOTIFY_STORE returned %d", fn());
    munmap(code, 4096);
    close(fd);

    /* 3. FUSE_AUTO_INVAL_DATA refreshes resident mapping on GETATTR mtime change. */
    snprintf(path, sizeof(path), "%s/inval", mnt);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open inval");
    p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(p != MAP_FAILED, "mmap inval");
    CHECK(p[0] == 'O', "initial inval byte=%c", p[0]);
    atomic_store(&g_inval_ver, 1);
    struct stat st;
    CHECK(fstat(fd, &st) == 0, "fstat inval");
    CHECK(p[0] == 'N', "expected refreshed byte 'N', got '%c'", p[0]);
    munmap(p, 4096);
    close(fd);
}

static void test_mlock_and_willneed(const char *mnt) {
    char path[256];

    /* 1. madvise(MADV_WILLNEED) fetches cold FUSE pages. */
    snprintf(path, sizeof(path), "%s/willneed", mnt);
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open willneed");
    char *p = mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED, "mmap willneed");
    CHECK(atomic_load(&g_willneed_reads) == 0, "willneed should start cold");
    CHECK(madvise(p, 8192, MADV_WILLNEED) == 0, "madvise(MADV_WILLNEED)");
    CHECK(atomic_load(&g_willneed_reads) >= 8192, "expected >=8192 bytes read for willneed, got %d",
          atomic_load(&g_willneed_reads));
    unsigned char vec[2] = {0, 0};
    CHECK(mincore(p, 8192, vec) == 0, "mincore");
    CHECK((vec[0] & 1) && (vec[1] & 1), "willneed pages not resident");
    munmap(p, 8192);
    close(fd);

    /* 2. mlock and mlock2 fetch cold FUSE pages (far apart to avoid readahead overlap). */
    snprintf(path, sizeof(path), "%s/mlock", mnt);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open mlock");
    p = mmap(NULL, 256 * 1024, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED, "mmap mlock");
    CHECK(atomic_load(&g_mlock_reads) == 0, "mlock should start cold");
    CHECK(mlock(p, 4096) == 0, "mlock page 0");
    int r1 = atomic_load(&g_mlock_reads);
    CHECK(r1 >= 1, "expected >=1 read for mlock page 0");
    CHECK(syscall(SYS_mlock2, p + 63 * 4096, 4096, 0) == 0, "mlock2 page 63");
    CHECK(atomic_load(&g_mlock_reads) > r1, "expected another read for mlock2 page 63");
    CHECK(munlock(p, 256 * 1024) == 0, "munlock");
    munmap(p, 256 * 1024);
    close(fd);

    /* 3. mlockall(MCL_CURRENT) fetches cold FUSE pages. */
    snprintf(path, sizeof(path), "%s/mlockall", mnt);
    fd = open(path, O_RDONLY);
    CHECK(fd >= 0, "open mlockall");
    p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    CHECK(p != MAP_FAILED, "mmap mlockall");
    CHECK(atomic_load(&g_mlockall_reads) == 0, "mlockall should start cold");
    CHECK(mlockall(MCL_CURRENT) == 0, "mlockall");
    CHECK(atomic_load(&g_mlockall_reads) >= 1, "mlockall did not fetch cold FUSE page");
    CHECK(munlockall() == 0, "munlockall");
    munmap(p, 4096);
    close(fd);
}

static void test_syscall_cold_fuse_buffers(const char *mnt) {
    char path[256];
    snprintf(path, sizeof(path), "%s/scratch", mnt);
    int sfd = open(path, O_RDWR);
    CHECK(sfd >= 0, "open scratch");
    /* Use MAP_PRIVATE so each page starts cold and writes stay local without dirtying daemon. */
    uint8_t *base = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE, sfd, 0);
    CHECK(base != MAP_FAILED, "mmap scratch");

    /* Page 0: epoll_pwait (EPOLLONESHOT) writing event into cold FUSE page. */
    int pfd[2];
    CHECK(pipe(pfd) == 0, "pipe");
    CHECK(write(pfd[1], "x", 1) == 1, "pipe write");
    int ep = epoll_create1(0);
    CHECK(ep >= 0, "epoll_create1");
    struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT, .data.u64 = 0x12345678ULL};
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, pfd[0], &ev) == 0, "epoll_ctl");
    struct epoll_event *cold_ev = (struct epoll_event *)(base + 0 * 4096);
    CHECK(epoll_wait(ep, cold_ev, 1, 1000) == 1, "epoll_wait into cold FUSE page");
    CHECK(cold_ev->data.u64 == 0x12345678ULL, "epoll event data mismatch");
    close(ep);
    close(pfd[0]);
    close(pfd[1]);

    /* Page 1: sendfile updating cold FUSE-mapped *offset. */
    int tmp = open("/tmp/sf_src", O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(tmp >= 0, "open sf_src");
    CHECK(write(tmp, "0123456789abcdef", 16) == 16, "write sf_src");
    CHECK(pipe(pfd) == 0, "pipe for sendfile");
    off_t *cold_off = (off_t *)(base + 1 * 4096);
    /* Page 1 is still cold! sendfile reads 0 and advances *cold_off to 6. */
    ssize_t sf = sendfile(pfd[1], tmp, cold_off, 6);
    CHECK(sf == 6, "sendfile returned %zd", sf);
    CHECK(*cold_off == 6, "sendfile cold *offset=%lld", (long long)*cold_off);
    char sbuf[16] = {0};
    CHECK(read(pfd[0], sbuf, 16) == 6 && memcmp(sbuf, "012345", 6) == 0, "sendfile data");
    close(pfd[0]);
    close(pfd[1]);

    /* Page 2: copy_file_range updating cold FUSE-mapped *off_in and *off_out. */
    int dst = open("/tmp/cfr_dst", O_CREAT | O_RDWR | O_TRUNC, 0600);
    CHECK(dst >= 0, "open cfr_dst");
    off_t *cfr_in = (off_t *)(base + 2 * 4096);
    off_t *cfr_out = (off_t *)(base + 3 * 4096);
    ssize_t cf = syscall(SYS_copy_file_range, tmp, cfr_in, dst, cfr_out, 8, 0);
    CHECK(cf == 8, "copy_file_range returned %zd", cf);
    CHECK(*cfr_in == 8 && *cfr_out == 8, "copy_file_range offsets %lld/%lld", (long long)*cfr_in,
          (long long)*cfr_out);
    close(tmp);
    close(dst);

    /* Pages 4..5: pipe2 and socketpair writing fds into cold FUSE pages. */
    int *cold_pipe = (int *)(base + 4 * 4096);
    CHECK(pipe2(cold_pipe, O_CLOEXEC) == 0, "pipe2 into cold FUSE page");
    close(cold_pipe[0]);
    close(cold_pipe[1]);
    int *cold_sp = (int *)(base + 5 * 4096);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, cold_sp) == 0, "socketpair into cold FUSE page");
    close(cold_sp[0]);
    close(cold_sp[1]);

    /* Pages 6..8: readv with cold FUSE-mapped iovec array AND cold FUSE destination page. */
    CHECK(pipe(pfd) == 0, "pipe for readv");
    CHECK(write(pfd[1], "HELLO_IOV", 9) == 9, "write pipe");
    struct iovec *cold_iov = (struct iovec *)(base + 6 * 4096);
    /* Page 6 holds the iovec; page 7 stays cold until readv prefaults it. */
    cold_iov[0].iov_base = base + 7 * 4096;
    cold_iov[0].iov_len = 9;
    ssize_t rv = readv(pfd[0], cold_iov, 1);
    CHECK(rv == 9 && memcmp(base + 7 * 4096, "HELLO_IOV", 9) == 0, "readv cold dst");
    close(pfd[0]);
    close(pfd[1]);

    /* Pages 10..29: getrandom > 64 KiB (70000 bytes) into cold FUSE pages -> full count. */
    uint8_t *gr_buf = base + 10 * 4096;
    ssize_t gr = getrandom(gr_buf, 70000, 0);
    CHECK(gr == 70000, "getrandom into cold FUSE pages returned short count %zd", gr);

    /* Pages 32..35: AIO io_submit + io_getevents with cold FUSE buffer & event output. */
    uint64_t ctx = 0;
    CHECK(syscall(SYS_io_setup, 4, &ctx) == 0, "io_setup");
    CHECK(pipe(pfd) == 0, "pipe for aio");
    CHECK(write(pfd[1], "AIO_DATA", 8) == 8, "write pipe for aio");
    struct my_iocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_data = 0xCAFEULL;
    cb.aio_lio_opcode = 0; /* IOCB_CMD_PREAD */
    cb.aio_fildes = (uint32_t)pfd[0];
    cb.aio_buf = (uint64_t)(base + 32 * 4096); /* cold FUSE page */
    cb.aio_nbytes = 8;
    cb.aio_offset = 0;
    struct my_iocb *cbs[1] = {&cb};
    CHECK(syscall(SYS_io_submit, ctx, 1L, cbs) == 1, "io_submit");
    struct my_io_event *cold_aio_ev = (struct my_io_event *)(base + 33 * 4096);
    CHECK(syscall(SYS_io_getevents, ctx, 1L, 1L, cold_aio_ev, NULL) == 1, "io_getevents");
    CHECK(cold_aio_ev->data == 0xCAFEULL && cold_aio_ev->res == 8,
          "aio event mismatch: data=%llu res=%lld", (unsigned long long)cold_aio_ev->data,
          (long long)cold_aio_ev->res);
    CHECK(memcmp(base + 32 * 4096, "AIO_DATA", 8) == 0, "aio buffer data mismatch");
    CHECK(syscall(SYS_io_destroy, ctx) == 0, "io_destroy");
    close(pfd[0]);
    close(pfd[1]);

    munmap(base, 256 * 1024);
    close(sfd);
}

int main(void) {
    const char *mnt = "/tmp/fuse_mm_fixes";
    mkdir("/tmp", 0755);
    mkdir(mnt, 0755);

    g_fuse_fd = open("/dev/fuse", O_RDWR);
    CHECK(g_fuse_fd >= 0, "open /dev/fuse");

    pthread_t th;
    CHECK(pthread_create(&th, NULL, daemon_thread, NULL) == 0, "pthread_create");

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other", g_fuse_fd);
    CHECK(mount("fuse_mm_fixes", mnt, "fuse", 0, opts) == 0, "mount fuse");

    test_unix_bind_in_fuse(mnt);
    test_lookup_walk_and_errors(mnt);
    test_periodic_writeback(mnt);
    test_notify_store_and_auto_inval(mnt);
    test_mlock_and_willneed(mnt);
    test_syscall_cold_fuse_buffers(mnt);

    atomic_store(&g_stop, 1);
    umount2(mnt, MNT_DETACH);
    close(g_fuse_fd);
    pthread_join(th, NULL);

    printf("all ok\n");
    return 0;
}
