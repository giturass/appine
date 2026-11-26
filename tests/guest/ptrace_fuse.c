/*
 * Regression tests for PTRACE_PEEKTEXT/PEEKDATA, PTRACE_POKETEXT/POKEDATA, and
 * process_vm_readv/process_vm_writev on cold (unpopulated) FUSE-mapped pages.
 *
 * Covers:
 * 1. PTRACE_PEEKDATA/PEEKTEXT on cold private, shared, PROT_NONE, cross-page, and cold
 *    tracer-destination FUSE mappings.
 * 2. PTRACE_POKEDATA/POKETEXT on cold private (non-writable, forked CoW, and executable code),
 *    cold shared writable/read-only, and EOF-straddling FUSE mappings, including warm code
 *    re-patching (Tier 1 invalidation).
 * 3. process_vm_readv/writev on cold private/shared remote and local FUSE pages, preserving
 *    ordinary permission checks (EFAULT on PROT_NONE / read-only write).
 * 4. FUSE daemon read error returns EIO (not EFAULT) for PEEK/POKE.
 * 5. Tracee killed with SIGKILL or detached with PTRACE_DETACH while a tracer thread is blocked
 *    waiting for a FUSE demand fill returns ESRCH cleanly without corrupting memory.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(cond, fmt, ...)                                                                      \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "FAIL %s:%d: " fmt " (errno=%d: %s)\n", __FILE__, __LINE__,            \
                    ##__VA_ARGS__, errno, strerror(errno));                                        \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

#ifndef SYS_ptrace
#define SYS_ptrace 117
#endif
#ifndef SYS_process_vm_readv
#define SYS_process_vm_readv 270
#endif
#ifndef SYS_process_vm_writev
#define SYS_process_vm_writev 271
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

enum node_id {
    NODE_PEEK_PRIV = 2,
    NODE_PEEK_SHARED,
    NODE_PEEK_NONE,
    NODE_PEEK_DST,
    NODE_POKE_PRIV,
    NODE_POKE_COW,
    NODE_POKE_EXEC,
    NODE_POKE_SHARED_RW,
    NODE_POKE_SHARED_RO,
    NODE_POKE_EOF,
    NODE_PVM_R_PRIV,
    NODE_PVM_R_SHARED,
    NODE_PVM_R_NONE,
    NODE_PVM_LOCAL_DST,
    NODE_PVM_LOCAL_SRC,
    NODE_PVM_W_PRIV,
    NODE_PVM_W_SHARED,
    NODE_PVM_W_RO,
    NODE_ERR_IO,
    NODE_SLOW_KILL,
    NODE_SLOW_DETACH,
};

struct file_spec {
    uint64_t nodeid;
    const char *name;
    uint64_t size;
    uint8_t fill_byte;
};

static const struct file_spec FILES[] = {
    {NODE_PEEK_PRIV, "peek-priv", 8192, 0x11},
    {NODE_PEEK_SHARED, "peek-shared", 4096, 0x33},
    {NODE_PEEK_NONE, "peek-none", 4096, 0x44},
    {NODE_PEEK_DST, "peek-dst", 4096, 0x45},
    {NODE_POKE_PRIV, "poke-priv", 4096, 0x55},
    {NODE_POKE_COW, "poke-cow", 4096, 0x66},
    {NODE_POKE_EXEC, "poke-exec", 4096, 0x00},
    {NODE_POKE_SHARED_RW, "poke-shared-rw", 4096, 0x77},
    {NODE_POKE_SHARED_RO, "poke-shared-ro", 4096, 0x88},
    {NODE_POKE_EOF, "poke-eof", 4096, 0x99},
    {NODE_PVM_R_PRIV, "pvm-r-priv", 4096, 0xa1},
    {NODE_PVM_R_SHARED, "pvm-r-shared", 4096, 0xa2},
    {NODE_PVM_R_NONE, "pvm-r-none", 4096, 0xa3},
    {NODE_PVM_LOCAL_DST, "pvm-local-dst", 4096, 0xa4},
    {NODE_PVM_LOCAL_SRC, "pvm-local-src", 4096, 0xa5},
    {NODE_PVM_W_PRIV, "pvm-w-priv", 4096, 0xa6},
    {NODE_PVM_W_SHARED, "pvm-w-shared", 4096, 0xa7},
    {NODE_PVM_W_RO, "pvm-w-ro", 4096, 0xa8},
    {NODE_ERR_IO, "err-io", 4096, 0xe0},
    {NODE_SLOW_KILL, "slow-kill", 4096, 0xb1},
    {NODE_SLOW_DETACH, "slow-detach", 4096, 0xb2},
};

static const struct file_spec *find_by_name(const char *name)
{
    for (size_t i = 0; i < sizeof(FILES) / sizeof(FILES[0]); i++) {
        if (strcmp(FILES[i].name, name) == 0)
            return &FILES[i];
    }
    return NULL;
}

static const struct file_spec *find_by_id(uint64_t id)
{
    for (size_t i = 0; i < sizeof(FILES) / sizeof(FILES[0]); i++) {
        if (FILES[i].nodeid == id)
            return &FILES[i];
    }
    return NULL;
}

struct fuse_ctx {
    int devfd;
    _Atomic int read_ops;
    int kill_entered[2];
    int kill_release[2];
    int detach_entered[2];
    int detach_release[2];
};

static void fill_page_bytes(uint64_t nodeid, uint64_t offset, uint8_t *dst, size_t len)
{
    const struct file_spec *spec = find_by_id(nodeid);
    CHECK(spec != NULL, "unknown FUSE node %llu", (unsigned long long)nodeid);
    if (nodeid == NODE_PEEK_PRIV) {
        for (size_t i = 0; i < len; i++) {
            uint64_t pos = offset + i;
            dst[i] = (pos < 4096) ? 0x11 : 0x22;
        }
        return;
    }
    if (nodeid == NODE_POKE_EXEC) {
        /* Page full of NOPs, with: mov w0, #11; ret at offset 0. */
        uint32_t page[1024];
        for (size_t i = 0; i < 1024; i++)
            page[i] = 0xd503201fu; /* nop */
        page[0] = 0x52800160u;     /* mov w0, #11 */
        page[1] = 0xd65f03c0u;     /* ret */
        memcpy(dst, ((uint8_t *)page) + offset, len);
        return;
    }
    memset(dst, spec->fill_byte, len);
}

static void *fuse_daemon(void *arg)
{
    struct fuse_ctx *ctx = (struct fuse_ctx *)arg;
    uint8_t buf[16384];
    uint8_t out[16384];
    for (;;) {
        ssize_t n = read(ctx->devfd, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(struct fuse_in_hdr))
            break;
        struct fuse_in_hdr in;
        memcpy(&in, buf, sizeof(in));

        memset(out, 0, sizeof(struct fuse_out_hdr));
        struct fuse_out_hdr *hdr = (struct fuse_out_hdr *)out;
        hdr->unique = in.unique;

        if (in.opcode == 26 /* FUSE_INIT */) {
            uint32_t init_out[16];
            memset(init_out, 0, sizeof(init_out));
            init_out[0] = 7;
            init_out[1] = 37;
            init_out[6] = 65536;
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(init_out));
            memcpy(out + sizeof(*hdr), init_out, sizeof(init_out));
        } else if (in.opcode == 3 /* FUSE_GETATTR */) {
            struct fuse_attr_out a;
            memset(&a, 0, sizeof(a));
            a.attr.ino = in.nodeid;
            if (in.nodeid == 1) {
                a.attr.mode = S_IFDIR | 0755;
                a.attr.nlink = 2;
            } else {
                const struct file_spec *spec = find_by_id(in.nodeid);
                a.attr.mode = S_IFREG | 0755;
                a.attr.nlink = 1;
                a.attr.size = spec ? spec->size : 0;
            }
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(a));
            memcpy(out + sizeof(*hdr), &a, sizeof(a));
        } else if (in.opcode == 1 /* FUSE_LOOKUP */) {
            const char *name = (const char *)(buf + sizeof(in));
            const struct file_spec *spec = find_by_name(name);
            if (spec) {
                struct fuse_entry_out e;
                memset(&e, 0, sizeof(e));
                e.nodeid = spec->nodeid;
                e.entry_valid = 60;
                e.attr_valid = 60;
                e.attr.ino = spec->nodeid;
                e.attr.mode = S_IFREG | 0755;
                e.attr.nlink = 1;
                e.attr.size = spec->size;
                hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(e));
                memcpy(out + sizeof(*hdr), &e, sizeof(e));
            } else {
                hdr->len = (uint32_t)sizeof(*hdr);
                hdr->error = -ENOENT;
            }
        } else if (in.opcode == 14 /* FUSE_OPEN */) {
            struct fuse_open_out o;
            memset(&o, 0, sizeof(o));
            o.fh = in.nodeid;
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(o));
            memcpy(out + sizeof(*hdr), &o, sizeof(o));
        } else if (in.opcode == 15 /* FUSE_READ */) {
            ctx->read_ops++;
            if (in.nodeid == NODE_ERR_IO) {
                hdr->len = (uint32_t)sizeof(*hdr);
                hdr->error = -EIO;
                (void)write(ctx->devfd, out, hdr->len);
                continue;
            }
            if (in.nodeid == NODE_SLOW_KILL) {
                char sig = 'K';
                CHECK(write(ctx->kill_entered[1], &sig, 1) == 1, "signal slow-kill entered");
                CHECK(read(ctx->kill_release[0], &sig, 1) == 1, "wait slow-kill release");
            } else if (in.nodeid == NODE_SLOW_DETACH) {
                char sig = 'D';
                CHECK(write(ctx->detach_entered[1], &sig, 1) == 1, "signal slow-detach entered");
                CHECK(read(ctx->detach_release[0], &sig, 1) == 1, "wait slow-detach release");
            }
            struct fuse_read_in ri;
            memcpy(&ri, buf + sizeof(in), sizeof(ri));
            const struct file_spec *spec = find_by_id(in.nodeid);
            size_t avail = (spec && ri.offset < spec->size) ? (size_t)(spec->size - ri.offset) : 0;
            size_t want = ri.size;
            if (want > avail)
                want = avail;
            /* Cap NODE_PEEK_PRIV replies to one page so cross-page PEEK hits two cold fills. */
            if (in.nodeid == NODE_PEEK_PRIV && want > 4096)
                want = 4096;
            if (want > sizeof(out) - sizeof(*hdr))
                want = sizeof(out) - sizeof(*hdr);
            if (want > 0)
                fill_page_bytes(in.nodeid, ri.offset, out + sizeof(*hdr), want);
            hdr->len = (uint32_t)(sizeof(*hdr) + want);
        } else if (in.opcode == 16 /* FUSE_WRITE */) {
            struct fuse_write_in wi;
            memcpy(&wi, buf + sizeof(in), sizeof(wi));
            struct fuse_write_out wo = {.size = wi.size, .padding = 0};
            hdr->len = (uint32_t)(sizeof(*hdr) + sizeof(wo));
            memcpy(out + sizeof(*hdr), &wo, sizeof(wo));
        } else if (in.opcode == 18 /* FUSE_RELEASE */ || in.opcode == 25 /* FUSE_FLUSH */ ||
                   in.opcode == 20 /* FUSE_FSYNC */) {
            hdr->len = (uint32_t)sizeof(*hdr);
        } else {
            hdr->len = (uint32_t)sizeof(*hdr);
            hdr->error = -ENOSYS;
        }
        (void)write(ctx->devfd, out, hdr->len);
    }
    return NULL;
}

static long raw_ptrace(long req, pid_t pid, void *addr, void *data)
{
    return syscall(SYS_ptrace, req, (long)pid, addr, data);
}

static uint64_t u64_repeat(uint8_t b)
{
    uint64_t v = 0;
    memset(&v, b, sizeof(v));
    return v;
}

static void *map_fuse(int dir, const char *name, size_t len, int prot, int flags, int open_flags)
{
    int fd = openat(dir, name, open_flags);
    CHECK(fd >= 0, "openat %s", name);
    void *p = mmap(NULL, len, prot, flags, fd, 0);
    CHECK(p != MAP_FAILED, "mmap %s", name);
    close(fd);
    return p;
}

struct map_addrs {
    uintptr_t peek_priv;
    uintptr_t peek_shared;
    uintptr_t peek_none;
    uintptr_t poke_priv;
    uintptr_t poke_cow;
    uintptr_t poke_exec;
    uintptr_t poke_shared_rw;
    uintptr_t poke_shared_ro;
    uintptr_t poke_eof;
    uintptr_t pvm_r_priv;
    uintptr_t pvm_r_shared;
    uintptr_t pvm_r_none;
    uintptr_t pvm_w_priv;
    uintptr_t pvm_w_shared;
    uintptr_t pvm_w_ro;
    uintptr_t err_io;
};

static void test_peek_poke_and_process_vm(int dir, struct fuse_ctx *ctx)
{
    /* Map poke-cow in parent BEFORE fork so both share the read-only private FUSE VMA (cow=true). */
    uint8_t *parent_cow = map_fuse(dir, "poke-cow", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
    /* Independent shared view of poke-shared-rw to observe tracer pokes. */
    uint8_t *parent_shared_rw =
        map_fuse(dir, "poke-shared-rw", 4096, PROT_READ | PROT_WRITE, MAP_SHARED, O_RDWR);
    /* Independent shared view of pvm-w-shared. */
    uint8_t *parent_pvm_shared =
        map_fuse(dir, "pvm-w-shared", 4096, PROT_READ | PROT_WRITE, MAP_SHARED, O_RDWR);

    int addr_pipe[2];
    CHECK(pipe(addr_pipe) == 0, "pipe");

    pid_t child = fork();
    CHECK(child >= 0, "fork tracee");
    if (child == 0) {
        close(addr_pipe[0]);
        CHECK(raw_ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "PTRACE_TRACEME");

        struct map_addrs m;
        m.peek_priv = (uintptr_t)map_fuse(dir, "peek-priv", 8192, PROT_READ, MAP_PRIVATE, O_RDONLY);
        m.peek_shared =
            (uintptr_t)map_fuse(dir, "peek-shared", 4096, PROT_READ, MAP_SHARED, O_RDONLY);
        m.peek_none = (uintptr_t)map_fuse(dir, "peek-none", 4096, PROT_NONE, MAP_PRIVATE, O_RDONLY);
        m.poke_priv = (uintptr_t)map_fuse(dir, "poke-priv", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
        m.poke_cow = (uintptr_t)parent_cow;
        m.poke_exec = (uintptr_t)map_fuse(dir, "poke-exec", 4096, PROT_READ | PROT_EXEC,
                                          MAP_PRIVATE, O_RDONLY);
        m.poke_shared_rw = (uintptr_t)map_fuse(dir, "poke-shared-rw", 4096, PROT_READ | PROT_WRITE,
                                               MAP_SHARED, O_RDWR);
        m.poke_shared_ro =
            (uintptr_t)map_fuse(dir, "poke-shared-ro", 4096, PROT_READ, MAP_SHARED, O_RDONLY);
        m.poke_eof = (uintptr_t)map_fuse(dir, "poke-eof", 8192, PROT_READ, MAP_PRIVATE, O_RDONLY);
        m.pvm_r_priv =
            (uintptr_t)map_fuse(dir, "pvm-r-priv", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
        m.pvm_r_shared =
            (uintptr_t)map_fuse(dir, "pvm-r-shared", 4096, PROT_READ, MAP_SHARED, O_RDONLY);
        m.pvm_r_none =
            (uintptr_t)map_fuse(dir, "pvm-r-none", 4096, PROT_NONE, MAP_PRIVATE, O_RDONLY);
        m.pvm_w_priv = (uintptr_t)map_fuse(dir, "pvm-w-priv", 4096, PROT_READ | PROT_WRITE,
                                           MAP_PRIVATE, O_RDONLY);
        m.pvm_w_shared = (uintptr_t)map_fuse(dir, "pvm-w-shared", 4096, PROT_READ | PROT_WRITE,
                                             MAP_SHARED, O_RDWR);
        m.pvm_w_ro = (uintptr_t)map_fuse(dir, "pvm-w-ro", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
        m.err_io = (uintptr_t)map_fuse(dir, "err-io", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);

        CHECK(write(addr_pipe[1], &m, sizeof(m)) == sizeof(m), "send map_addrs");
        close(addr_pipe[1]);

        /* Stop 1: all FUSE mappings above are completely cold! */
        raise(SIGSTOP);

        /* Verify tracee observes the poked bytes and preserved surrounding bytes. */
        const uint8_t *pp = (const uint8_t *)m.poke_priv;
        uint64_t got = 0;
        memcpy(&got, pp + 8, 8);
        CHECK(pp[0] == 0x55 && got == 0x0123456789abcdefULL && pp[16] == 0x55,
              "tracee poke-priv mismatch: [0]=%#x got=%#llx [16]=%#x", pp[0],
              (unsigned long long)got, pp[16]);

        const uint8_t *pc = (const uint8_t *)m.poke_cow;
        memcpy(&got, pc + 8, 8);
        CHECK(pc[0] == 0x66 && got == 0xfedcba9876543210ULL && pc[16] == 0x66,
              "tracee poke-cow mismatch: [0]=%#x got=%#llx [16]=%#x", pc[0],
              (unsigned long long)got, pc[16]);

        const uint8_t *ps = (const uint8_t *)m.poke_shared_rw;
        memcpy(&got, ps + 8, 8);
        CHECK(ps[0] == 0x77 && got == 0xdeadbeefcafebabeULL && ps[16] == 0x77,
              "tracee poke-shared-rw mismatch");

        /* Verify tracee observes process_vm_writev modifications and surrounding bytes. */
        const uint8_t *pw = (const uint8_t *)m.pvm_w_priv;
        CHECK(pw[0] == 0xa6 && memcmp(pw + 16, "PVM-PRIV", 8) == 0 && pw[24] == 0xa6,
              "tracee pvm-w-priv mismatch");
        const uint8_t *pws = (const uint8_t *)m.pvm_w_shared;
        CHECK(pws[0] == 0xa7 && memcmp(pws + 16, "PVM-SHRD", 8) == 0 && pws[24] == 0xa7,
              "tracee pvm-w-shared mismatch");

        /* Execute cold-patched code page: must return 42 (not original 11). */
        int (*fn)(void) = (int (*)(void))m.poke_exec;
        int r1 = fn();
        CHECK(r1 == 42, "cold-patched poke-exec returned %d, expected 42", r1);

        /* Stop 2: code page is now warm (translated in Tier 1); tracer will re-patch it. */
        raise(SIGSTOP);

        int r2 = fn();
        CHECK(r2 == 77, "warm-repatched poke-exec returned %d, expected 77", r2);

        _exit(0);
    }

    close(addr_pipe[1]);
    struct map_addrs m;
    CHECK(read(addr_pipe[0], &m, sizeof(m)) == sizeof(m), "read map_addrs");
    close(addr_pipe[0]);

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP,
          "wait stop 1");

    int reads_before = ctx->read_ops;

    /* 1a. PTRACE_PEEKDATA on cold private FUSE page (cross-page straddling page 0 and page 1). */
    uint64_t word = 0;
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)(m.peek_priv + 4092), &word) == 0,
          "PEEKDATA cross-page cold private");
    CHECK(word == 0x2222222211111111ULL, "cross-page peek got %#llx", (unsigned long long)word);
    CHECK(ctx->read_ops - reads_before >= 2, "expected >=2 FUSE reads for cross-page cold peek");

    /* 1b. PTRACE_PEEKTEXT on cold shared FUSE page. */
    word = 0;
    CHECK(raw_ptrace(PTRACE_PEEKTEXT, child, (void *)m.peek_shared, &word) == 0,
          "PEEKTEXT cold shared");
    CHECK(word == u64_repeat(0x33), "peek shared got %#llx", (unsigned long long)word);

    /* 1c. PTRACE_PEEKDATA on cold PROT_NONE private FUSE page (FOLL_FORCE). */
    word = 0;
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)m.peek_none, &word) == 0,
          "PEEKDATA cold PROT_NONE");
    CHECK(word == u64_repeat(0x44), "peek PROT_NONE got %#llx", (unsigned long long)word);

    /* 1d. PTRACE_PEEKDATA writing result into a cold FUSE page in the TRACER's own mm. */
    uint64_t *tracer_dst =
        map_fuse(dir, "peek-dst", 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, O_RDONLY);
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)m.peek_shared, tracer_dst + 1) == 0,
          "PEEKDATA into cold tracer FUSE page");
    CHECK(tracer_dst[0] == u64_repeat(0x45) && tracer_dst[1] == u64_repeat(0x33) &&
              tracer_dst[2] == u64_repeat(0x45),
          "tracer cold dst mismatch");
    munmap(tracer_dst, 4096);

    /* 2a. PTRACE_POKEDATA on cold private non-writable FUSE page. */
    uint64_t poke_val1 = 0x0123456789abcdefULL;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)(m.poke_priv + 8), (void *)poke_val1) == 0,
          "POKEDATA cold private RO");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)m.poke_priv, &word) == 0 &&
              word == u64_repeat(0x55),
          "poke-priv offset 0 must keep FUSE data");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)(m.poke_priv + 8), &word) == 0 &&
              word == poke_val1,
          "poke-priv offset 8 must read back written word");

    /* 2b. PTRACE_POKEDATA on cold forked CoW private non-writable FUSE page. */
    uint64_t poke_val2 = 0xfedcba9876543210ULL;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)(m.poke_cow + 8), (void *)poke_val2) == 0,
          "POKEDATA cold forked CoW private RO");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)(m.poke_cow + 8), &word) == 0 &&
              word == poke_val2,
          "poke-cow child readback");
    /* Parent's copy must NOT be affected by child's private CoW poke! */
    uint64_t parent_word = 0;
    memcpy(&parent_word, parent_cow + 8, 8);
    CHECK(parent_word == u64_repeat(0x66), "parent CoW page corrupted: %#llx",
          (unsigned long long)parent_word);

    /* 2c. PTRACE_POKETEXT on cold private RX executable FUSE page (mov w0,#11;ret -> mov w0,#42;ret). */
    uint64_t patched_code1 = ((uint64_t)0xd65f03c0u << 32) | 0x52800540u;
    CHECK(raw_ptrace(PTRACE_POKETEXT, child, (void *)m.poke_exec, (void *)patched_code1) == 0,
          "POKETEXT cold private RX");
    CHECK(raw_ptrace(PTRACE_PEEKTEXT, child, (void *)m.poke_exec, &word) == 0 &&
              word == patched_code1,
          "POKETEXT cold readback");

    /* 2d. PTRACE_POKEDATA on cold shared RW FUSE page (succeeds) and shared RO (EIO). */
    uint64_t poke_val3 = 0xdeadbeefcafebabeULL;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)(m.poke_shared_rw + 8), (void *)poke_val3) ==
              0,
          "POKEDATA cold shared RW");
    uint64_t shared_seen = 0;
    memcpy(&shared_seen, parent_shared_rw + 8, 8);
    CHECK(shared_seen == poke_val3 && parent_shared_rw[0] == 0x77,
          "parent shared view must observe poked word and preserved surrounding bytes");

    errno = 0;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)m.poke_shared_ro, (void *)poke_val3) == -1 &&
              errno == EIO,
          "POKEDATA on cold shared RO must fail with EIO");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)m.poke_shared_ro, &word) == 0 &&
              word == u64_repeat(0x88),
          "PEEKDATA on cold shared RO must succeed");

    /* 2e. Cross-page PTRACE_POKEDATA straddling EOF must fail with EIO and leave no partial write. */
    errno = 0;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)(m.poke_eof + 4092),
                     (void *)0x1122334455667788ULL) == -1 &&
              errno == EIO,
          "POKEDATA straddling EOF must return EIO");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)(m.poke_eof + 4088), &word) == 0 &&
              word == u64_repeat(0x99),
          "failed EOF-straddling POKEDATA must not partially write before EOF (got %#llx)",
          (unsigned long long)word);

    /* 3a. process_vm_readv on cold remote private, shared, PROT_NONE, and cold local destination. */
    uint8_t local_buf[16];
    memset(local_buf, 0, sizeof(local_buf));
    struct iovec liov = {.iov_base = local_buf, .iov_len = 8};
    struct iovec riov = {.iov_base = (void *)m.pvm_r_priv, .iov_len = 8};
    CHECK(syscall(SYS_process_vm_readv, child, &liov, 1, &riov, 1, 0) == 8,
          "process_vm_readv cold private");
    CHECK(memcmp(local_buf, "\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1", 8) == 0,
          "process_vm_readv cold private content");

    /* Cold remote shared -> cold local FUSE destination. */
    uint8_t *pvm_local_dst =
        map_fuse(dir, "pvm-local-dst", 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, O_RDONLY);
    liov.iov_base = pvm_local_dst + 8;
    liov.iov_len = 8;
    riov.iov_base = (void *)m.pvm_r_shared;
    riov.iov_len = 8;
    CHECK(syscall(SYS_process_vm_readv, child, &liov, 1, &riov, 1, 0) == 8,
          "process_vm_readv cold shared -> cold local");
    CHECK(pvm_local_dst[0] == 0xa4 &&
              memcmp(pvm_local_dst + 8, "\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2", 8) == 0 &&
              pvm_local_dst[16] == 0xa4,
          "process_vm_readv cold local content");
    munmap(pvm_local_dst, 4096);

    /* PROT_NONE must still return EFAULT for process_vm_readv (plain permissions). */
    liov.iov_base = local_buf;
    liov.iov_len = 8;
    riov.iov_base = (void *)m.pvm_r_none;
    riov.iov_len = 8;
    errno = 0;
    CHECK(syscall(SYS_process_vm_readv, child, &liov, 1, &riov, 1, 0) == -1 && errno == EFAULT,
          "process_vm_readv on cold PROT_NONE must return EFAULT");

    /* 3b. process_vm_writev: cold local FUSE src -> cold remote private RW, shared RW, and RO. */
    uint8_t *pvm_local_src =
        map_fuse(dir, "pvm-local-src", 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, O_RDONLY);
    /* Write payload into local FUSE page (triggers fill if needed), or keep cold for read test:
     * First test cold local -> cold remote private RW (writes 8 bytes of 0xa5), then overwrite
     * with "PVM-PRIV" for tracee check. */
    liov.iov_base = pvm_local_src;
    liov.iov_len = 8;
    riov.iov_base = (void *)(m.pvm_w_priv + 32);
    riov.iov_len = 8;
    CHECK(syscall(SYS_process_vm_writev, child, &liov, 1, &riov, 1, 0) == 8,
          "process_vm_writev cold local -> cold remote private RW");
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)(m.pvm_w_priv + 32), &word) == 0 &&
              word == u64_repeat(0xa5),
          "process_vm_writev cold local content");
    munmap(pvm_local_src, 4096);

    liov.iov_base = (void *)"PVM-PRIV";
    liov.iov_len = 8;
    riov.iov_base = (void *)(m.pvm_w_priv + 16);
    riov.iov_len = 8;
    CHECK(syscall(SYS_process_vm_writev, child, &liov, 1, &riov, 1, 0) == 8,
          "process_vm_writev private payload");

    liov.iov_base = (void *)"PVM-SHRD";
    liov.iov_len = 8;
    riov.iov_base = (void *)(m.pvm_w_shared + 16);
    riov.iov_len = 8;
    CHECK(syscall(SYS_process_vm_writev, child, &liov, 1, &riov, 1, 0) == 8,
          "process_vm_writev cold remote shared RW");
    CHECK(memcmp(parent_pvm_shared + 16, "PVM-SHRD", 8) == 0 && parent_pvm_shared[0] == 0xa7,
          "shared view of process_vm_writev");

    liov.iov_base = (void *)"NO-WRITE";
    liov.iov_len = 8;
    riov.iov_base = (void *)m.pvm_w_ro;
    riov.iov_len = 8;
    errno = 0;
    CHECK(syscall(SYS_process_vm_writev, child, &liov, 1, &riov, 1, 0) == -1 && errno == EFAULT,
          "process_vm_writev on cold private RO must return EFAULT");

    /* 4. FUSE daemon -EIO must surface as EIO (not EFAULT) on both PEEK and POKE. */
    errno = 0;
    CHECK(raw_ptrace(PTRACE_PEEKDATA, child, (void *)m.err_io, &word) == -1 && errno == EIO,
          "PEEKDATA daemon EIO must return EIO");
    errno = 0;
    CHECK(raw_ptrace(PTRACE_POKEDATA, child, (void *)m.err_io, (void *)0x1234ULL) == -1 &&
              errno == EIO,
          "POKEDATA daemon EIO must return EIO");

    /* Resume tracee for Stop 1 checks + execution of cold-patched code. */
    CHECK(raw_ptrace(PTRACE_CONT, child, NULL, NULL) == 0, "PTRACE_CONT 1");
    CHECK(waitpid(child, &status, 0) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP,
          "wait stop 2");

    /* Re-patch warm executable page: mov w0, #77; ret. */
    uint64_t patched_code2 = ((uint64_t)0xd65f03c0u << 32) | 0x528009a0u;
    CHECK(raw_ptrace(PTRACE_POKETEXT, child, (void *)m.poke_exec, (void *)patched_code2) == 0,
          "POKETEXT warm private RX");
    CHECK(raw_ptrace(PTRACE_CONT, child, NULL, NULL) == 0, "PTRACE_CONT 2");
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "tracee exited cleanly (status=%#x)", status);

    munmap(parent_cow, 4096);
    munmap(parent_shared_rw, 4096);
    munmap(parent_pvm_shared, 4096);
}

struct worker_arg {
    long req;
    pid_t pid;
    uintptr_t addr;
    uint64_t poke_val;
    long ret;
    int err;
};

static void *ptrace_worker(void *arg)
{
    struct worker_arg *w = (struct worker_arg *)arg;
    uint64_t out = 0;
    errno = 0;
    if (w->req == PTRACE_PEEKDATA)
        w->ret = raw_ptrace(PTRACE_PEEKDATA, w->pid, (void *)w->addr, &out);
    else
        w->ret = raw_ptrace(PTRACE_POKEDATA, w->pid, (void *)w->addr, (void *)w->poke_val);
    w->err = errno;
    return NULL;
}

static void test_kill_during_fuse_fill(int dir, struct fuse_ctx *ctx)
{
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    pid_t child = fork();
    CHECK(child >= 0, "fork slow-kill tracee");
    if (child == 0) {
        close(p[0]);
        CHECK(raw_ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "PTRACE_TRACEME");
        uintptr_t addr =
            (uintptr_t)map_fuse(dir, "slow-kill", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
        CHECK(write(p[1], &addr, sizeof(addr)) == sizeof(addr), "send slow-kill addr");
        close(p[1]);
        raise(SIGSTOP);
        _exit(0);
    }
    close(p[1]);
    uintptr_t addr = 0;
    CHECK(read(p[0], &addr, sizeof(addr)) == sizeof(addr), "read slow-kill addr");
    close(p[0]);

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP,
          "wait slow-kill stop");

    struct worker_arg w = {.req = PTRACE_PEEKDATA, .pid = child, .addr = addr};
    pthread_t th;
    CHECK(pthread_create(&th, NULL, ptrace_worker, &w) == 0, "start peek worker");

    /* Wait until FUSE daemon has received FUSE_READ (tracer thread released BKL). */
    char sig = 0;
    CHECK(read(ctx->kill_entered[0], &sig, 1) == 1 && sig == 'K', "daemon received slow-kill read");

    /* Kill and reap the tracee while the tracer thread is blocked inside fuse::fill! */
    CHECK(kill(child, SIGKILL) == 0, "kill tracee during fill");
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
          "reap killed tracee");

    /* Release the FUSE daemon so fuse::fill finishes and tracer re-acquires BKL. */
    CHECK(write(ctx->kill_release[1], &sig, 1) == 1, "release slow-kill daemon");
    CHECK(pthread_join(th, NULL) == 0, "join peek worker");
    CHECK(w.ret == -1 && w.err == ESRCH,
          "PEEKDATA after tracee killed during fill: ret=%ld err=%d (expected ESRCH)", w.ret,
          w.err);
}

static void test_detach_during_fuse_fill(int dir, struct fuse_ctx *ctx)
{
    int p[2];
    CHECK(pipe(p) == 0, "pipe");
    pid_t child = fork();
    CHECK(child >= 0, "fork slow-detach tracee");
    if (child == 0) {
        close(p[0]);
        CHECK(raw_ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "PTRACE_TRACEME");
        uint8_t *buf = map_fuse(dir, "slow-detach", 4096, PROT_READ, MAP_PRIVATE, O_RDONLY);
        uintptr_t addr = (uintptr_t)buf;
        CHECK(write(p[1], &addr, sizeof(addr)) == sizeof(addr), "send slow-detach addr");
        close(p[1]);
        raise(SIGSTOP);
        /* After detach, the aborted POKEDATA must NOT have modified our page! */
        uint64_t val = 0;
        memcpy(&val, buf, 8);
        CHECK(val == u64_repeat(0xb2),
              "detached tracee observed poked value %#llx instead of original 0xb2",
              (unsigned long long)val);
        _exit(0);
    }
    close(p[1]);
    uintptr_t addr = 0;
    CHECK(read(p[0], &addr, sizeof(addr)) == sizeof(addr), "read slow-detach addr");
    close(p[0]);

    int status = 0;
    CHECK(waitpid(child, &status, 0) == child && WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP,
          "wait slow-detach stop");

    struct worker_arg w = {
        .req = PTRACE_POKEDATA,
        .pid = child,
        .addr = addr,
        .poke_val = 0xbadc0ffee0ddf00dULL,
    };
    pthread_t th;
    CHECK(pthread_create(&th, NULL, ptrace_worker, &w) == 0, "start poke worker");

    char sig = 0;
    CHECK(read(ctx->detach_entered[0], &sig, 1) == 1 && sig == 'D',
          "daemon received slow-detach read");

    /* Detach the tracee while the worker thread is blocked in fuse::fill! */
    CHECK(raw_ptrace(PTRACE_DETACH, child, NULL, NULL) == 0, "PTRACE_DETACH during fill");

    /* Release the FUSE daemon so fuse::fill finishes and worker re-validates tracee. */
    CHECK(write(ctx->detach_release[1], &sig, 1) == 1, "release slow-detach daemon");
    CHECK(pthread_join(th, NULL) == 0, "join poke worker");
    CHECK(w.ret == -1 && w.err == ESRCH,
          "POKEDATA after tracee detached during fill: ret=%ld err=%d (expected ESRCH)", w.ret,
          w.err);

    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "detached tracee exited cleanly (status=%#x)", status);
}

int main(void)
{
    const char *mnt = "/tmp/ptrace_fuse";
    CHECK(mkdir("/tmp", 0755) == 0 || errno == EEXIST, "mkdir /tmp");
    CHECK(mkdir(mnt, 0755) == 0 || errno == EEXIST, "mkdir %s", mnt);

    struct fuse_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    CHECK(pipe(ctx.kill_entered) == 0 && pipe(ctx.kill_release) == 0, "kill pipes");
    CHECK(pipe(ctx.detach_entered) == 0 && pipe(ctx.detach_release) == 0, "detach pipes");
    ctx.devfd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    CHECK(ctx.devfd >= 0, "open /dev/fuse");

    char opts[128];
    snprintf(opts, sizeof(opts), "fd=%d,rootmode=40755,user_id=0,group_id=0,allow_other", ctx.devfd);
    CHECK(mount("f", mnt, "fuse", 0, opts) == 0, "mount fuse");

    pthread_t daemon;
    CHECK(pthread_create(&daemon, NULL, fuse_daemon, &ctx) == 0, "start fuse daemon");

    int dir = open(mnt, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(dir >= 0, "open fuse mount dir");

    test_peek_poke_and_process_vm(dir, &ctx);
    test_kill_during_fuse_fill(dir, &ctx);
    test_detach_during_fuse_fill(dir, &ctx);

    close(dir);
    CHECK(umount2(mnt, MNT_DETACH) == 0, "umount fuse");
    close(ctx.devfd);
    pthread_join(daemon, NULL);
    close(ctx.kill_entered[0]);
    close(ctx.kill_entered[1]);
    close(ctx.kill_release[0]);
    close(ctx.kill_release[1]);
    close(ctx.detach_entered[0]);
    close(ctx.detach_entered[1]);
    close(ctx.detach_release[0]);
    close(ctx.detach_release[1]);
    rmdir(mnt);

    printf("all ok\n");
    return 0;
}
