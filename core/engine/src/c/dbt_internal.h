/*
 * Internal definitions shared across Tier 1 DBT translation units (`dbt*.c`).
 * See `.agents/maps/engine/dbt.md` for the architecture and invariants.
 */
#ifndef APPINE_ENGINE_DBT_INTERNAL_H
#define APPINE_ENGINE_DBT_INTERNAL_H

#include <stddef.h>
#include <stdlib.h>

#include "emit.h"
#include "internal.h"

#if defined(__aarch64__) && defined(__linux__)
#define DBT_SUPPORTED 1
#endif

#ifdef DBT_SUPPORTED

#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define BIT(x, n) ((unsigned)(((x) >> (n)) & 1u))
#define FIELD(x, hi, lo) ((unsigned)(((x) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1)))

/* Shared by all threads of an address space; JIT workloads need room for more than a hundred
 * thousand live blocks. A block's jumps to the routines at the start of the cache and the links
 * between blocks are each one b, whose range is ±128 MB, so it cannot be larger */
#define CODE_CACHE_BYTES (UINT64_C(128) << 20)
#define MAX_BLOCK_INSNS 256
_Static_assert(CODE_CACHE_BYTES <= (UINT64_C(128) << 20), "the offset range of b");
/* Host code buffer is fixed at 4096 words so conditional-branch stub distances fit in BRANCH_MASK
 * and TBZ/TBNZ imm14; prepare() stops adding guest instructions before the worst-case margin would
 * exceed MAX_BLOCK_WORDS, MAX_STUBS, MAX_FIXUPS or MAX_RELOCS. */
#define MAX_BLOCK_WORDS 4096
#define MAX_STUBS 256
#define MAX_FIXUPS 512
#define INSN_MAX_WORDS 64
#define INSN_MAX_STUBS 2
#define INSN_MAX_FIXUPS 4
/* The translation table starts at 2^12 entries, doubles when three quarters full, and has at most
 * 2^19 entries: the table is spread by hash, so if a short-lived process's few hundred blocks were
 * put in the largest table, every block would touch a new page of memory. All threads of an
 * address space share one table, and JIT workloads (the JVM) have more than a hundred thousand
 * live blocks */
#define TABLE_MIN_BITS 12
#define TABLE_BITS 19
#define TABLE_SIZE (1u << TABLE_BITS)
#define TABLE_LIMIT (TABLE_SIZE / 4 * 3)
#define JC_BITS 12
#define JC_SIZE (1u << JC_BITS)
/* Key of a tombstone in the translation table: misaligned, and lookups exclude misaligned pcs
 * first (table_find_for, emit_lookup), so it is never found. Empty jump-cache entries use jc_empty
 * instead */
#define JC_EMPTY UINT64_C(1)
/* Stack frame of the enter routine: x19–x30, host FPCR, d8–d15 */
#define FRAME_BYTES 176

/*
 * Host registers: CTX points to struct appine_cpu, T0, T1 and T2 are temporaries, and SP_HOST
 * holds the guest SP. Which set an instance uses is chosen at creation (appine_dbt_new), and
 * routines, translations and templates are all generated for it, so these names can only be used
 * where there is an `x` (struct xlate *). The same-numbered guest registers and X18 are the stolen
 * registers (is_stolen).
 *
 * The Go compiler uses X28 as the current goroutine (g), X27 as the assembler's temporary and X26
 * as the closure context, and the stack check in function prologues uses X16: in a native
 * `go build`, compile spends 15.5% of its execution time on instructions that use the default
 * set's stolen registers (5.2% for gcc's cc1), while X19–X25 together account for less than 1.5%
 * (register allocation starts from the low numbers). So Go programs steal X21–X25 instead (the
 * engine map).
 */
struct regs {
    unsigned ctx, t0, t1, t2, sp;
};

#define CTX (x->d->r->ctx)
#define T0 (x->d->r->t0)
#define T1 (x->d->r->t1)
#define T2 (x->d->r->t2)
#define SP_HOST (x->d->r->sp)
#define REG_SP 32 /* pseudo register number: guest SP */

/* Exit reasons (returning from translated code to the dispatcher). R_CHAIN_FWD is a forward
 * direct branch, which when linked skips the kick check at the target block's entry: block start
 * addresses strictly increase along forward edges, so every loop has at least one edge that passes
 * a check. R_UNGROUP is a group of accesses sharing one check that failed it (see plan_group);
 * as with R_INTERP, Tier 0 executes this one instruction */
enum { R_CODE, R_CHAIN, R_CHAIN_FWD, R_LOOKUP, R_INTERP, R_SVC, R_KICK, R_UNGROUP };

/* The other kind of stub besides exit stubs: on a TLB miss it enters the refill routine and exits
 * only if the refill fails (R_INTERP or R_UNGROUP) */
#define STUB_REFILL (R_UNGROUP + 1)

/* The most words one stub takes: a link stub takes 5 words (6 when the pc does not fit in 48
 * bits), an exit stub 4 (5), a refill stub 5 */
#define MAX_STUB_WORDS 6

/* In an exit stub's data word the pc takes the low 48 bits, and the high 16 bits are the exit
 * reason (emit_link_stub) */
#define PACKED_PC_BITS 48

/* The info word in a refill stub (emit_refill_stub): the low 12 bits are the byte count minus one
 * (a group of accesses sharing a check covers at most GROUP_SPAN plus one more access), the next
 * 3 bits are the exit reason if the refill fails, and the high 17 bits are the distance in words
 * of the access itself from the info word (signed) */
#define REFILL_REASON_SHIFT 12
#define REFILL_RESUME_SHIFT 15
_Static_assert(MAX_BLOCK_WORDS < 1u << (31 - REFILL_RESUME_SHIFT), "the access's distance in words from the info word must fit in it");

/* Words taken by the kick check at a block's entry */
#define ENTRY_CHECK_WORDS 2

/* The low 3 bits of an exit reason are R_*; a link stub carries in the high bits the distance in
 * words from the conditional branch that jumps to it to the stub (0 means none), and link stubs of
 * shared blocks (TAG_SHIFT) also carry LINK_SHARED: they can only link to shared blocks */
#define REASON_BITS 3
#define REASON_MASK ((1u << REASON_BITS) - 1)
#define BRANCH_MASK (MAX_BLOCK_WORDS - 1)
#define LINK_SHARED (1u << 15)
_Static_assert(R_UNGROUP <= REASON_MASK, "the exit reason goes in the low 3 bits");
_Static_assert((MAX_BLOCK_WORDS & BRANCH_MASK) == 0 && MAX_BLOCK_WORDS << REASON_BITS <= LINK_SHARED,
               "the conditional branch's distance to the stub and LINK_SHARED must fit in a movz immediate");

#define SYSREG_NZCV 0xda10
#define SYSREG_FPCR 0xda20
#define SYSREG_FPSR 0xda21
#define SYSREG_TPIDR_EL0 0xde82
#define SYSREG_DCZID_EL0 0xd807
#define SYSREG_CNTFRQ_EL0 0xdf00
#define SYSREG_CNTVCT_EL0 0xdf02
#define SYSREG_CNTVCTSS_EL0 0xdf06

/* Block size of DC ZVA, matching the DCZID_EL0 that Tier 0 reports */
#define DCZ_BLOCK 64
#define DCZID_VALUE 4

#define TLB_BITS 12
#define TLB_OFF offsetof(struct appine_cpu, tlb)
#define STLB_BITS 10
#define STLB_OFF offsetof(struct appine_cpu, stlb)
_Static_assert(APPINE_TLB_ENTRIES == 1u << TLB_BITS, "the TLB index is fixed at 12 bits in generated code");
_Static_assert(APPINE_STLB_ENTRIES == 1u << STLB_BITS, "the STLB index is fixed at 10 bits in generated code");
_Static_assert(sizeof(struct appine_tlb_entry) == 32, "generated code addresses TLB entries as 32 bytes each");
_Static_assert(TLB_OFF % 16 == 0 && TLB_OFF + 16 <= 504, "the TLB must be addressable by ldp's 7-bit scaled immediate");
_Static_assert((STLB_OFF & 0xfff) == 0 && (STLB_OFF >> 12) <= 0xfff,
               "STLB must be 4 KB-aligned within one shifted add immediate");
_Static_assert(offsetof(struct appine_cpu, dbt_rs) < TLB_OFF, "dbt_rs is also read and written directly with ldr/str");
_Static_assert(offsetof(struct appine_cpu, dbt_jump_cache) < TLB_OFF,
               "fields that generated code reads and writes directly with ldr/str must precede the TLB");

struct slot {
    uint64_t pc;
    uint32_t *code;
};

/*
 * Translation table: guest pc → translation, open addressing. The dispatcher looks it up without
 * the lock (table_lookup), so: insertion only uses empty slots (pc written first, then code), and
 * invalidation only changes the pc into a tombstone — a thread that read the old code enters the
 * invalidated block's entry, which jumps to the forwarding stub and exits with the original pc;
 * tombstones are not reused and are removed when the table grows or is rebuilt at the same size.
 * After the table is replaced, the old one is freed only once the threads looking it up have
 * finished (table_publish).
 */
struct table {
    unsigned bits;
    unsigned shift; /* 64 - bits: the index is the pc's hash shifted right by this many bits */
    uint64_t mask;  /* 2^bits - 1 */
    struct slot slots[];
};
#define GOLDEN UINT64_C(0x9e3779b97f4a7c15)

/*
 * Shadow return stack: each entry is (guest return address, host landing pad); the 64-entry ring
 * buffer is aligned to its own size, so push and pop change only the low RS_SHIFT bits of the top
 * pointer (bfxil, which does not touch the condition flags).
 */
#define RS_SHIFT 10
#define RS_ENTRIES ((1u << RS_SHIFT) / 16)

/*
 * When several address spaces of the same program share one instance (the kernel layer's
 * CodeGroup), blocks in the trusted file mappings registered with the group (appine_dbt_share) are
 * valid for every member and go into the translation table by pc; blocks elsewhere (JIT-generated
 * or written code) are valid only for the member that translated them, and their key in the table
 * is pc | the member's tag << TAG_SHIFT. A guest pc has only 48 bits and there are no blocks above
 * that (excluded before the lookup), so the two kinds of key never coincide. Both kinds are hashed
 * by pc, and one linear probe finds both the shared blocks and this member's private ones: with
 * two separate probes, JIT code would take one more cache miss on every jump-cache miss. Shared
 * blocks do not link to private blocks (LINK_SHARED). Tags are allocated by the instance
 * (appine_dbt_new_tag); when the instance returns to the pool its private blocks are removed
 * (drop_private) and tags are allocated from the start again. Tag 0 means not in a group, and all
 * blocks are keyed by pc.
 */
#define TAG_SHIFT APPINE_VA_BITS
#define TAG_MAX 0xffffu
#define PC_MASK ((UINT64_C(1) << TAG_SHIFT) - 1)

/* When invalidating translations, find the blocks that start in a guest page by that page
 * (appine_dbt_invalidate) */
#define PAGE_BUCKET_BITS 14
#define INVALIDATE_MAX_PAGES 256 /* beyond this many pages, look at every block in turn */

struct block {
    uint64_t pc;
    uint32_t *code;  /* NULL once invalidated */
    uint32_t next;   /* previous block in the same bucket (index plus 1), 0 if none */
    uint32_t words;  /* where the guest words at translation time sit in words (for recheck) */
    uint32_t nguest : 11; /* number of guest instructions (1..1024) */
    /* Parked (revive): the entry jumps to the forwarding stub like an invalidated block's, and the
     * code is still there */
    uint32_t parked : 1;
    uint32_t tag : 16; /* tag of the member owning a private block; 0 for shared ones (TAG_SHIFT) */
    uint32_t first;    /* the instruction after the entry check, which is rewritten when parked */
};
_Static_assert(MAX_BLOCK_INSNS <= 1024, "nguest of struct block");
_Static_assert(sizeof(struct block) == 32, "struct block layout");

/* A block's key in the translation table */
static inline uint64_t tagged(uint64_t pc, unsigned tag)
{
    return pc | (uint64_t)tag << TAG_SHIFT;
}

static inline uint64_t block_key(const struct block *b)
{
    return tagged(b->pc, b->tag);
}

/* After a group of accesses fails the shared check a second time, the leader's pc is recorded
 * here, and on retranslation neither it nor the accesses after it in the same block lead a group
 * any more; when full, the oldest entries are overwritten first. A first failure is recorded in
 * the 64-entry strikes ring (searched linearly on the cold R_UNGROUP path, reusing cleared slots
 * before overwriting FIFO so alternating leaders never collide). */
#define NOGROUP_MAX 64
#define NOGROUP_SPAN 256 /* bytes after a failed leader where grouping stays disabled */
#define STRIKES 64

/* Capacity of d->words (guest words kept for recheck/invalidation); kept fixed so longer blocks do
 * not bloat VA reservations, and checked in install() before appending */
#define WORDS_LIMIT ((size_t)TABLE_LIMIT * 64)
/* The most blocks kept when returning to the pool: checking is much cheaper than copying templates
 * and linking again (one node startup has about 50,000 blocks); beyond that they are mostly
 * JIT-generated code that will most likely not match next time */
#define KEEP_MAX_BLOCKS 131072

/*
 * The translations of one address space (code cache, translation table, various records), shared
 * by all threads in that address space (appine_dbt_attach): multi-threaded programs (the Go
 * compiler, the JVM) used to translate the same code once per thread, doing translation, template
 * copying, linking and instruction-cache syncing several times over, each with its own code cache.
 *
 * Apart from the dispatcher's table lookups, all reads and writes hold lock. A full flush must wait
 * for all threads to leave translated code: the initiating thread kicks the other threads and waits
 * until each has stopped in the dispatcher (parked) or left dbt_run; see flush_world.
 */
struct appine_dbt {
    /* Host register assignment (one set in reg_sets); routines and translations are all generated
     * for it */
    const struct regs *r;
    uint32_t *cache;    /* address for execution; every code pointer points here */
    intptr_t rw_delta;  /* writable alias minus execution address; 0 when mapped directly as RWX */
    struct written *written; /* pages written in the writable alias (note_written); NULL for RWX */
    /* The list pool.all linking all instances (live and pooled), walked by
     * appine_dbt_unmap_written. Read and written while holding pool.lock; prev_instance is NULL
     * when not in the list */
    struct appine_dbt *next_instance, **prev_instance;
    size_t cache_words;
    size_t used_words;
    size_t routine_words;
    uint32_t *enter;
    uint32_t *exit;
    uint32_t *exit_stub; /* entry exit stubs jump to (emit_link_stub), followed directly by exit */
    uint32_t *exit_full; /* same, for pcs that do not fit in 48 bits */
    uint32_t *refill[2]; /* TLB refill routines: read, write */
    uint32_t *lookup;    /* routine that looks up the table on a jump-cache miss (emit_lookup) */
    uint32_t *rs_miss;   /* landing pad of empty shadow return stack entries: looks up guest x30 */
    uint32_t *memop_ret; /* shared predicted return tail for in-cache memop helpers */
    uint32_t *memop_memset;
    uint32_t *memop_memmove;
    uint32_t *memop_memcmp;
    uint32_t *memop_memchr;
    struct table *table; /* read with __atomic_load_n when not holding the lock */
    uint32_t *table_used; /* slots used, in insertion order, at most TABLE_LIMIT of them */
    size_t table_count;
    size_t table_occupied; /* non-empty slots in the table: live blocks and tombstones */
    size_t table_dead;     /* the tombstones among them */
    struct block *blocks; /* one-to-one with table_used, recorded in translation order */
    size_t blocks_dead;   /* those already invalidated */
    size_t nparked;       /* those parked (revive) */
    uint32_t *words;      /* blocks' guest instruction words at translation, mapped on demand */
    size_t words_used;
    /* Address space changed (taken from the pool after exec or fork); check before the next run */
    bool stale;
    /* The mappings the translations are in, recorded before returning to the pool
     * (appine_dbt_set_sources) */
    struct appine_dbt_source sources[APPINE_DBT_SOURCES];
    unsigned nsources;
    /* Ranges [start, end) the next check need not look at (appine_dbt_trust) */
    uint64_t trusted[APPINE_DBT_SOURCES][2];
    unsigned ntrusted;
    /* The previous user's file mappings [start, end): blocks in them that are not mapped yet are
     * parked during the check (recheck) */
    uint64_t parkable[APPINE_DBT_SOURCES][2];
    unsigned nparkable;
    /* A host fault occurred while running (APPINE_EXIT_HOST_FAULT): the tables may be only half
     * updated, so they are no longer used */
    bool poisoned;
    uint32_t *page_head;  /* hash of a guest page → list head in blocks (index plus 1) */
    uint32_t *page_parked; /* same hash: parked count, read lock-free if a lookup fails (revive) */
    size_t cross_page_blocks; /* live blocks whose fast-loop words cross into the next guest page */
    /* The group's registered mappings (appine_dbt_share), sorted by start and non-overlapping;
     * read without the lock. A replaced old array hangs off the new one's older and is freed when
     * the instance returns to the pool */
    struct shared_ranges *shared;
    /* Registered libc memop entry PCs (appine_dbt_set_memops), sorted by pc; read without the lock
     * and retired onto older like shared */
    struct memop_table *memops;
    unsigned next_tag; /* next tag that can be allocated (appine_dbt_new_tag) */
    uint64_t nogroup[NOGROUP_MAX];
    unsigned nogroup_count;
    uint64_t strikes[STRIKES];
    unsigned strikes_next;
    /* Incremented on every flush: invalidates links not yet patched, and threads use it to clear
     * their own jump cache and shadow return stack */
    uint64_t generation;
    size_t high_words; /* the most code-cache words ever used */

    pthread_mutex_t lock;
    pthread_cond_t flushed; /* a full flush has finished (or the instance was poisoned) */
    struct appine_dbt_thread *threads; /* attached threads */
    unsigned nthreads;                 /* their number (read atomically) */
    bool flushing;     /* a thread waits for the others to stop for a full flush (atomic read) */
    /* A full flush is wanted: the caller asked for one, or a forwarding stub did not fit when
     * invalidating (read atomically) */
    bool flush_wanted;
    /* Statistics of the lock holder: translations and invalidations are charged to it; spare_stats
     * is this instance's own sink when no thread owns the lock */
    struct appine_dbt_stats *st;
    struct appine_dbt_stats spare_stats;
};

/* Registered mappings: [r[i][0], r[i][1]), sorted by start and non-overlapping */
struct shared_ranges {
    struct shared_ranges *older;
    unsigned n;
    uint64_t r[][2];
};

/* Registered memop entry PCs, sorted by pc */
struct memop_table {
    struct memop_table *older;
    unsigned n;
    struct appine_dbt_memop ops[];
};

/* Whether pc is in a registered mapping (without the lock) */
static inline bool in_shared(const struct appine_dbt *d, uint64_t pc)
{
    const struct shared_ranges *s = __atomic_load_n(&d->shared, __ATOMIC_ACQUIRE);
    if (!s)
        return false;
    unsigned lo = 0, hi = s->n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (pc < s->r[mid][0])
            hi = mid;
        else if (pc >= s->r[mid][1])
            lo = mid + 1;
        else
            return true;
    }
    return false;
}


/* The part a thread uses to run in an address space: jump cache, shadow return stack and
 * statistics */
struct appine_dbt_thread {
    struct appine_dbt *d;
    unsigned tag; /* the group tag of the thread's address space, 0 if not in a group (TAG_SHIFT) */
    struct appine_dbt_thread *next; /* d->threads list, read and written holding d->lock */
    struct appine_cpu *cpu; /* cpu running in dbt_run or NULL (atomic): a full flush kicks it */
    bool parked;            /* stopped in park for a full flush (accessed holding d->lock) */
    uint64_t generation;    /* the d->generation that jc and rs correspond to */
    struct slot *jc;        /* jump cache for indirect branches, direct-mapped */
    bool jc_dirty;
    uint64_t (*rs)[2]; /* shadow return stack */
    struct appine_dbt_stats stats;
    /* Workspace for translating without the lock (prepare): the translation in progress, the
     * generated code and the result */
    struct xlate *xlate;
    uint32_t *scratch;
    struct appine_cpu *probe;
    uint64_t *defined; /* results of tier0_defined, per instruction word (DEFINED_CACHE entries) */
    struct prep *prep;
};

/* ---- Emitter ---- */

enum fixup_kind { FIX_IMM19, FIX_IMM14 };

struct stub {
    unsigned reason; /* R_* or STUB_REFILL; for R_LOOKUP the target pc is already in T0 */
    uint64_t pc;
    uint32_t *addr;
    /* Refill stubs: where execution continues after a successful refill (the access after the TLB
     * check), the byte count and direction of the access, and the exit reason on failure */
    uint32_t *resume;
    unsigned bytes;
    bool write;
    unsigned fail;
    /* The number of branches jumping to this stub and the position of one of them (filled in when
     * emitting stubs) */
    unsigned sites;
    const uint32_t *branch;
};

struct fixup {
    uint32_t *site;
    enum fixup_kind kind;
    unsigned stub;
};

/*
 * One direct-branch exit of a block (a link stub): the stub's offset in words from the block
 * start, the offset in words from the block start of the only conditional branch that jumps to it
 * (NO_BRANCH if none), and the target pc. If the target is already translated when the block is
 * built, it is linked right away (link_block), saving the exit to the dispatcher the first time
 * execution gets here and a separate instruction-cache sync (the dsb after ic ivau waits for the
 * invalidation broadcast to complete, about 0.1 microseconds each time)
 */
struct link {
    uint32_t stub; /* LINK_FWD: forward, skips the kick check at the target block's entry */
    uint32_t branch;
    uint64_t pc;
};
#define LINK_FWD (UINT32_C(1) << 31)
#define NO_BRANCH UINT32_MAX

/* A b to a routine: its offset must be recomputed for the new position when a translation
 * template is copied */
enum {
    TO_EXIT,
    TO_REFILL_READ,
    TO_REFILL_WRITE,
    TO_LOOKUP,
    TO_EXIT_FULL,
    TO_MEMOP_MEMSET,
    TO_MEMOP_MEMMOVE,
    TO_MEMOP_MEMCMP,
    TO_MEMOP_MEMCHR,
};

/* The most bytes and the most accesses one group of accesses sharing a check may cover, and the
 * most groups at once (plan_group) */
#define GROUP_SPAN 512
#define GROUP_MAX 32
#define GROUP_SLOTS 8
_Static_assert(sizeof(((struct appine_cpu *)0)->dbt_groups) == GROUP_SLOTS * 8, "one slot per group");
#define MAX_RELOCS (MAX_STUBS * 2 + 4)

struct xlate {
    struct appine_dbt *d;
    uint32_t *buf;
    /* Write address minus buf: 0 when translating into the thread's scratch area, rw_delta when
     * writing the code cache directly */
    intptr_t wdelta;
    struct appine_dbt_stats *st; /* whom the translation statistics are charged to */
    struct appine_cpu *probe;    /* used to ask Tier 0 whether it recognizes an instruction */
    uint64_t *defined;           /* its answers, cached per instruction word */
    size_t n;
    struct stub stubs[MAX_STUBS];
    unsigned nstubs;
    struct fixup fixups[MAX_FIXUPS];
    unsigned nfixups;
    uint32_t relocs[MAX_RELOCS]; /* index << 4 | TO_* */
    unsigned nrelocs;
    /* The block being translated: start pc, guest instruction source (in mapped guest page),
     * lazily snapshotted words in prep->words (first `copied` words valid), index of the current
     * instruction, and the most instructions the block may have in the first page */
    uint64_t pc;
    const uint32_t *src;
    const struct appine_mmu *mmu; /* for lazy next-page fetch in cross-page fast loops */
    const uint32_t *src1;         /* second guest page (pc & ~PAGE_MASK) + 4096, or NULL */
    uint32_t *words;
    unsigned copied, idx, limit;
    bool tried_src1;
    /* This block goes into the translation table by pc (TAG_SHIFT), and its link stubs carry
     * LINK_SHARED */
    bool shared;
    /* SP's alignment was already checked in this block, and SP has since changed only by
     * multiples of 16 */
    bool sp_aligned;
    /* General registers in this block whose values are known at translation time (set by
     * ADR/ADRP, plus immediates added to them); bit r stands for Xr, and the values are in kval
     * (konst_update) */
    uint32_t konst;
    uint64_t kval[31];
    /* Block-local affine relations: when bit r of affine_valid is set (0..30 = X0..X30, 31 = SP),
     * register r equals root register affine_base[r] + affine_off[r] (depth-1 tree; affine_update).
     * Used by plan_group so derived pointers created before a leader still share its TLB check. */
    uint32_t affine_valid;
    uint8_t affine_base[32];
    int64_t affine_off[32];
    /* Groups of accesses sharing a check (plan_group): the members not translated yet. A group's
     * host base is in T2, or spilled to the cpu's dbt_groups[group index] */
    struct group {
        unsigned n, next;
        unsigned idx[GROUP_MAX];
        int32_t off[GROUP_MAX]; /* relative to the base before the leader executes */
        bool reload[GROUP_MAX]; /* T2 used earlier: get the host base back from the slot first */
        int32_t lo;             /* range the whole group covers, also relative to that base */
        unsigned bytes;
        bool write;
        bool spill; /* some member reloads: the leader stores the host base in the slot */
    } groups[GROUP_SLOTS];
    uint8_t active_groups;    /* bit i set => groups[i] still has untranslated members */
    uint64_t grouped_bits[4]; /* bit j set => guest instruction j belongs to an active group */
    int t2_group; /* which group's host base T2 holds now, -1 for none */
};
_Static_assert(GROUP_SLOTS <= 8, "active_groups bitmask");
_Static_assert(MAX_BLOCK_INSNS <= 256, "grouped_bits bitmask");

/* Return guest instruction `idx` of the block, lazily extending the snapshot in x->words in
 * 64-word chunks so short blocks do not copy 256 words up front */
static inline uint32_t fetch_guest(struct xlate *x, unsigned idx)
{
    if (UNLIKELY(idx >= x->copied)) {
        unsigned want = x->copied + 64;
        if (want > x->limit)
            want = x->limit;
        memcpy(x->words + x->copied, x->src + x->copied, (want - x->copied) * 4);
        x->copied = want;
    }
    return x->words[idx];
}


/* Write address of code (the writable alias of the W^X double mapping) */
static inline uint32_t *rw(const struct appine_dbt *d, const uint32_t *p)
{
    return (uint32_t *)((uintptr_t)p + (uintptr_t)d->rw_delta);
}

/*
 * The host's RSS counts pages per mapping: a code-cache page touched through both the write and
 * the execute view counts twice, so the code cache is counted double in RssShmem, in the RSS the
 * LMK looks at and in the usage the memory limit measures. So the pages written in the writable
 * view are recorded, and the kernel layer's timer thread drops their page-table entries once a
 * second (appine_dbt_unmap_written): MADV_DONTNEED on shared memory only removes the mapping and
 * keeps the content, and the next write faults once more. Dropping is by time, not by amount: JIT
 * workloads patch links and invalidate blocks in thousands of different pages per second, and
 * when dropping by amount (once every 256 KB accumulated) those pages faulted again and again and
 * Maven was 3% slower. Threads patching links without the lock also write, so the bitmap and the
 * count are atomic; recording one page too many or too few only affects when dropping happens.
 */
struct written {
    unsigned pages; /* number of pages set in bits (atomic) */
    bool dropping;  /* a thread is dropping them (atomic) */
    /* Host pages written in the writable view and not dropped yet */
    uint64_t bits[CODE_CACHE_BYTES / 4096 / 64];
};

/* Pieces of code collected to be synced together (sync_code_ranges) */
struct syncs {
    void *start[3], *end[3];
    unsigned n;
};

static inline void emit(struct xlate *x, uint32_t insn)
{
    if (x->n < MAX_BLOCK_WORDS)
        *(uint32_t *)((uintptr_t)&x->buf[x->n] + (uintptr_t)x->wdelta) = insn;
    x->n++;
}

static inline uint32_t *here(struct xlate *x)
{
    return &x->buf[x->n];
}

static inline uint32_t *routine(const struct appine_dbt *d, unsigned to)
{
    switch (to) {
    case TO_EXIT:
        return d->exit_stub;
    case TO_EXIT_FULL:
        return d->exit_full;
    case TO_LOOKUP:
        return d->lookup;
    case TO_MEMOP_MEMSET:
        return d->memop_memset;
    case TO_MEMOP_MEMMOVE:
        return d->memop_memmove;
    case TO_MEMOP_MEMCMP:
        return d->memop_memcmp;
    case TO_MEMOP_MEMCHR:
        return d->memop_memchr;
    default:
        return d->refill[to - TO_REFILL_READ];
    }
}

/* A b to a routine: TO_EXIT is the exit entry used by stubs (exit_stub, see emit_link_stub) */
static inline void emit_to_routine(struct xlate *x, unsigned to)
{
    if (x->nrelocs < MAX_RELOCS)
        x->relocs[x->nrelocs] = (uint32_t)x->n << 4 | to;
    x->nrelocs++; /* overflow is checked by prepare() */
    emit(x, enc_b((intptr_t)routine(x->d, to) - (intptr_t)here(x)));
}

static inline void emit_mov_const(struct xlate *x, unsigned rd, uint64_t v)
{
    if (v == 0) {
        emit(x, enc_movz(rd, 0, 0));
        return;
    }
    bool first = true;
    for (unsigned hw = 0; hw < 4; hw++) {
        uint32_t part = (uint32_t)(v >> (16 * hw)) & 0xffff;
        if (!part)
            continue;
        emit(x, first ? enc_movz(rd, part, hw) : enc_movk(rd, part, hw));
        first = false;
    }
}

/* rd = rn + imm, without changing the condition flags; requires |imm| < 2^24; rn cannot be 31 */
static inline void emit_add_const(struct xlate *x, unsigned rd, unsigned rn, int64_t imm)
{
    if (imm == 0) {
        if (rd != rn)
            emit(x, enc_mov(rd, rn));
        return;
    }
    bool sub = imm < 0;
    uint64_t a = sub ? (uint64_t)-imm : (uint64_t)imm;
    uint32_t hi = (uint32_t)(a >> 12), lo = (uint32_t)(a & 0xfff);
    unsigned src = rn;
    if (hi) {
        emit(x, sub ? enc_sub_imm(rd, src, hi, 1) : enc_add_imm(rd, src, hi, 1));
        src = rd;
    }
    if (lo)
        emit(x, sub ? enc_sub_imm(rd, src, lo, 0) : enc_add_imm(rd, src, lo, 0));
}

/* Whether guest Xr is a stolen register */
static inline bool stolen_in(const struct regs *regs, unsigned r)
{
    return r == 18 || r == regs->ctx || r == regs->t0 || r == regs->t1 || r == regs->t2 || r == regs->sp;
}
#define is_stolen(g) stolen_in(x->d->r, g)

static inline size_t guest_off(unsigned r)
{
    return r == REG_SP ? offsetof(struct appine_cpu, sp) : offsetof(struct appine_cpu, x) + 8 * r;
}

static inline void emit_load_guest(struct xlate *x, unsigned host, unsigned guest)
{
    emit(x, enc_ldr_x(host, CTX, guest_off(guest)));
}

static inline void emit_store_guest(struct xlate *x, unsigned host, unsigned guest)
{
    emit(x, enc_str_x(host, CTX, guest_off(guest)));
}

/* ---- Exit stubs ---- */

/*
 * Exit stubs hand the exit routine T0 = guest pc, T1 = patch site, T2 = exit reason
 * (emit_routines). The guest pc is a 48-bit address that would take three or four movs to build
 * as an immediate, so it is kept together with the exit reason in the two data words at the end
 * of the stub (the reason in the high 16 bits), and read by the routine's stub entry (exit_stub):
 *
 *     [b 4]   adr T1, 0   b exit_stub   .quad reason << 48 | pc
 *
 * The first instruction of a link stub is a b to the next instruction, and linking rewrites it
 * into a b straight to the target block: other threads may be executing it, and changing a b into
 * a b is a concurrent modification the architecture allows (the CMODX rules of the ARM ARM). The
 * routine hands T1 minus 4 to the dispatcher: for a link stub that is its patch site; for other
 * stubs the dispatcher does not look at it. branch is the only conditional branch that jumps to
 * this stub, and when linking, if the target is within its offset range it is made to jump there
 * directly (only when there are no other threads, see dbt_run). When the computed branch target is
 * beyond 48 bits (the guest jumping there can only fault), the reason is passed separately with a
 * movz to exit_full.
 */
static inline void emit_link_stub(struct xlate *x, unsigned reason, uint64_t pc, const uint32_t *branch)
{
    unsigned delta = branch ? (unsigned)(here(x) - branch) : 0;
    if (reason == R_LOOKUP) { /* target pc already in T0: look it up in translated code first */
        emit_to_routine(x, TO_LOOKUP);
        return;
    }
    if (reason == R_CHAIN || reason == R_CHAIN_FWD)
        emit(x, enc_b(4));
    emit(x, enc_adr_self(T1));
    uint64_t code = reason | delta << REASON_BITS;
    if ((reason == R_CHAIN || reason == R_CHAIN_FWD) && x->shared)
        code |= LINK_SHARED;
    if (pc >> PACKED_PC_BITS == 0) {
        emit_to_routine(x, TO_EXIT);
        pc |= code << PACKED_PC_BITS;
    } else {
        emit(x, enc_movz(T2, (unsigned)code, 0));
        emit_to_routine(x, TO_EXIT_FULL);
    }
    emit(x, (uint32_t)pc);
    emit(x, (uint32_t)(pc >> 32));
}

static inline void emit_exit_stub(struct xlate *x, unsigned reason, uint64_t pc)
{
    emit_link_stub(x, reason, pc, NULL);
}

/* Emit a conditional branch (offset patched later) whose target is an exit stub */
static inline void emit_to_stub(struct xlate *x, uint32_t insn, enum fixup_kind kind, unsigned reason, uint64_t pc)
{
    unsigned i;
    for (i = 0; i < x->nstubs; i++) {
        if (x->stubs[i].reason == reason && x->stubs[i].pc == pc)
            break;
    }
    if (i == x->nstubs) {
        if (x->nstubs < MAX_STUBS)
            x->stubs[i] = (struct stub){.reason = reason, .pc = pc};
        x->nstubs++; /* overflow is checked by prepare() */
    }
    if (x->nfixups < MAX_FIXUPS)
        x->fixups[x->nfixups++] = (struct fixup){here(x), kind, i};
    else
        x->nfixups++; /* record the overflow; prepare() checks it */
    emit(x, insn);
}

/* Patch the offset of a b/cbz/cbnz/tbz/tbnz */
static inline void patch_branch(intptr_t wdelta, uint32_t *site, const uint32_t *target)
{
    uint32_t off = (uint32_t)(target - site), *w = (uint32_t *)((uintptr_t)site + (uintptr_t)wdelta);
    if ((*w & 0x7c000000) == 0x14000000)
        *w |= off & 0x3ffffff;
    else if ((*w & 0x7e000000) == 0x36000000)
        *w |= (off & 0x3fff) << 5;
    else
        *w |= (off & 0x7ffff) << 5;
}

/* A local branch within the block; an overflowed block is never used (prepare() checks), it just
 * must not write out of bounds */
static inline void patch_local(struct xlate *x, uint32_t *site, const uint32_t *target)
{
    if (site < x->buf + MAX_BLOCK_WORDS)
        patch_branch(x->wdelta, site, target);
}

/* ---- Shared instruction-decoder and cache data structures ---- */

struct operands {
    unsigned n;
    unsigned pos[4]; /* start bit of the field */
    bool sp[4];      /* whether 31 means SP */
    bool writes_rd;  /* the Rd field at pos[0] == 0 is written */
};

static inline void add_operand(struct operands *o, unsigned pos, bool sp)
{
    o->pos[o->n] = pos;
    o->sp[o->n] = sp;
    o->n++;
}

enum mem_mode { M_OFFSET, M_PRE, M_POST, M_REG, M_LITERAL };

struct memop {
    enum mem_mode mode;
    bool load, pair, prefetch;
    bool simd;      /* Rt/Rt2 are SIMD&FP registers */
    bool structure; /* LD1–LD4/ST1–ST4: final lacks only Rn */
    bool wb_reg;    /* writeback adds Xm instead of imm */
    unsigned size;  /* log2 of one element's byte count */
    unsigned bytes; /* total bytes accessed, for structure */
    unsigned rt, rt2, rn, rm, option, shift;
    int64_t imm;    /* the absolute address for M_LITERAL */
    uint32_t final; /* template of the final access instruction, with register fields 0 */
};

/* Byte count of an access */
static inline unsigned memop_bytes(const struct memop *m)
{
    return m->structure ? m->bytes : (m->pair ? 2u : 1u) << m->size;
}

/* Whether instruction j is already claimed by an active group in x->groups */
static inline bool is_grouped_idx(const struct xlate *x, unsigned j)
{
    return ((x->grouped_bits[j >> 6] >> (j & 63)) & 1) != 0;
}

static inline int64_t sext(uint64_t v, unsigned bits)
{
    return (int64_t)(v << (64 - bits)) >> (64 - bits);
}

#define DEFINED_CACHE 4096
#define TABLE_BYTES(bits) (sizeof(struct table) + (sizeof(struct slot) << (bits)))

static inline unsigned page_bucket(uint64_t page)
{
    return (unsigned)((page * UINT64_C(0x9e3779b97f4a7c15)) >> (64 - PAGE_BUCKET_BITS));
}

/* Special value in table_used: this block is invalidated and was not put in when the table was
 * rebuilt */
#define SLOT_NONE UINT32_MAX

#define RETIRE_BATCH 32

struct retire_batch {
    unsigned n;
    struct block *blocks[RETIRE_BATCH];
    bool park[RETIRE_BATCH];
    uint32_t *fwd_start;
};

/*
 * A block that is prepared but not yet installed in the code cache (prepare translates without
 * the lock, install puts it in with the lock held): the generated host instructions are in the
 * thread's scratch area, the positions of the b instructions to routines are in relocs, and the
 * exits are in links.
 */
struct prep {
    uint64_t pc;
    unsigned tag; /* private block: tag of the member it belongs to (TAG_SHIFT) */
    uint32_t memop_kind; /* registration observed while translating */
    const uint32_t *guest;  /* host location of page 0 guest words: compared again before installing */
    const uint32_t *guest1; /* host location of page 1 guest words when nguest crosses a page, else NULL */
    uint32_t nguest;
    uint32_t words[MAX_BLOCK_INSNS]; /* guest instruction words read at translation */
    const uint32_t *host;
    uint32_t nhost;
    uint32_t relocs[MAX_RELOCS];
    unsigned nrelocs;
    struct link links[MAX_STUBS];
    unsigned nlinks;
};

/* ---- Cross-unit internal entry points ---- */

/* dbt_translate.c */
bool dbt_dp_operands(uint32_t insn, struct operands *o);
bool dbt_decode_memop(uint32_t insn, uint64_t pc, struct memop *m);
bool dbt_decode_simd_memop(uint32_t insn, uint64_t pc, struct memop *m);
void dbt_emit_tlb_check(struct xlate *x, uint64_t pc, unsigned bytes, bool write, bool in_granule,
                        bool last_ready, unsigned fail);
void dbt_emit_tlb_check_known(struct xlate *x, uint64_t pc, uint64_t addr, unsigned bytes, bool write,
                              unsigned fail);
bool dbt_known_address(const struct xlate *x, unsigned rn, int64_t imm, unsigned bytes, uint64_t *addr);
bool dbt_emit_address_imm(struct xlate *x, unsigned base, int64_t imm, unsigned bytes, bool in_granule);
void dbt_emit_sp_check(struct xlate *x, uint64_t pc);
void dbt_sp_moved(struct xlate *x, int64_t delta);
bool dbt_is_atomic(uint32_t insn);
bool dbt_tier0_defined(struct appine_cpu *probe, uint64_t *cache, uint32_t insn, uint64_t pc);
bool dbt_translate_insn(struct xlate *x, uint32_t insn, uint64_t pc);

/* dbt_group.c */
int dbt_plan_group(struct xlate *x, const struct memop *lead);
void dbt_emit_member(struct xlate *x, const struct memop *m, int64_t off);
void dbt_emit_group(struct xlate *x, const struct memop *lead, uint64_t pc, int slot);

/* dbt_loop.c: returns cross-page fast-loop nguest if a cross-page loop was emitted, else 0 */
uint32_t dbt_try_fast_loop(struct xlate *x);

/* dbt_routines.c */
void dbt_emit_routines(struct appine_dbt *d);

/* dbt_cache.c */
size_t dbt_host_page_size(void);
void dbt_drop_written(const struct appine_dbt *d);
void dbt_sync_range(const struct appine_dbt *d, const uint32_t *start, const uint32_t *end);
void dbt_publish_link(const struct appine_dbt *d, uint32_t *site);
void dbt_sync_all(const struct appine_dbt *d, struct syncs *s);
bool dbt_relink_word(const struct appine_dbt *d, uint32_t *site, const uint32_t *target);
void *dbt_zalloc(size_t bytes);
void dbt_release_pages(void *p, size_t bytes);
void dbt_zfree(void *p, size_t bytes);
struct table *dbt_table_new(unsigned bits);
uint32_t *dbt_table_find_for(const struct table *t, uint64_t pc, unsigned tag, unsigned *found);
uint32_t *dbt_table_lookup(struct appine_dbt *d, struct appine_cpu *c, uint64_t pc, unsigned *found);
bool dbt_table_resize(struct appine_dbt *d, unsigned bits);
void dbt_table_insert(struct appine_dbt *d, uint64_t pc, unsigned tag, uint32_t *code,
                      const uint32_t *guest, uint32_t nguest);
void dbt_table_remove(struct appine_dbt *d, uint64_t key);
void dbt_link_block(const struct appine_dbt *d, uint32_t *code, uint64_t pc, unsigned tag,
                    const struct link *links, unsigned n);
void dbt_clear_jump_cache(struct appine_dbt_thread *t);
void dbt_rs_reset(struct appine_dbt_thread *t);
void dbt_thread_catch_up(struct appine_dbt_thread *t);
bool dbt_compact_blocks(struct appine_dbt *d);
void dbt_flush_locked(struct appine_dbt *d);
void dbt_retire_flush(struct appine_dbt *d, struct retire_batch *r);
void dbt_kill_parked(struct appine_dbt *d, struct block *b);
bool dbt_retire_add(struct appine_dbt *d, struct retire_batch *r, struct block *b, bool park);
bool dbt_retire_pc(struct appine_dbt *d, struct retire_batch *r, uint64_t pc);
void dbt_invalidate_locked(struct appine_dbt *d, const struct appine_mmu *mmu, uint64_t start,
                           uint64_t len);
void dbt_ungroup(struct appine_dbt *d, uint64_t pc);
void dbt_recheck(struct appine_dbt *d, const struct appine_cpu *c);
void dbt_revive(struct appine_dbt *d, const struct appine_cpu *c, uint64_t pc);
uint64_t dbt_nogroup_key(const struct appine_dbt *d, uint64_t pc);
bool dbt_template_fetch(uint64_t pc, const uint32_t *src, uint32_t *words, unsigned *copied,
                        unsigned limit0, const struct appine_mmu *mmu, const struct appine_dbt *d,
                        uint64_t key, const struct regs *r, bool shared, struct prep *p,
                        uint32_t *scratch, struct appine_dbt_stats *st);
void dbt_template_clear(bool if_full);
void dbt_template_trim(void);
void dbt_template_store(uint64_t pc, const uint32_t *guest, uint32_t nguest, uint64_t key,
                        const struct xlate *x, const struct appine_dbt_stats *before,
                        const struct link *links, unsigned nlinks);
void dbt_perf_map(const void *code, size_t bytes, uint64_t pc);

#endif /* DBT_SUPPORTED */
#endif /* APPINE_ENGINE_DBT_INTERNAL_H */
