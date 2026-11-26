/*
 * Tier 1: a same-ISA pass-through DBT (the engine/dbt map: `.agents/maps/engine/dbt.md`).
 *
 * Register convention while translated code runs (this is the default set; Go programs use
 * another set, see struct regs):
 *   - guest X0–X15, X19–X25, X29 and X30 live in the same-numbered host registers, and guest SP
 *     lives in host X26;
 *   - host X28 points to struct appine_cpu; host X16, X17 and X27 are temporaries;
 *   - host X18 is the platform register (on Android, the shadow call stack pointer bionic sets up
 *     for each thread), and translated code does not touch it: the host's signal handlers may use
 *     it at any time;
 *   - guest X16, X17, X18, X26, X27 and X28 are kept in the cpu struct ("stolen registers"), and
 *     instructions that reference them are rewritten before they run. SP appears in 17% of
 *     instructions (function prologues and epilogues), and X26 is the least used callee-saved
 *     register in compiler-generated code (less than a tenth of SP in gcc's cc1), so host X26 is
 *     given to SP. The host registers are a convention only among pieces of translated code and
 *     have nothing to do with the host calling convention: translated code calls no host
 *     functions, and the enter routine saves all callee-saved registers;
 *   - guest NZCV is host NZCV, so inserted code never changes the condition flags;
 *   - guest V0–V31, FPCR and FPSR are the host's V0–V31, FPCR and FPSR, and SIMD&FP
 *     data-processing instructions run verbatim.
 *
 * Memory-access instructions are rewritten into the inline TLB fast path; a TLB miss or a
 * cross-page access enters the refill routine, and a failed refill (unmapped, no permission and so
 * on) or a misaligned SP exits to the dispatcher, where Tier 0 executes this one instruction (at
 * that point the instruction has had no side effect at all). Direct branches jump directly through
 * block links; indirect branches first look up the jump cache. Function calls push the shadow
 * return stack, and RET looks at the top of the stack first (emit_call). Instructions Tier 0 does
 * not recognize are likewise handed to Tier 0, which keeps the two tiers' whitelists exactly the
 * same (the engine and engine/dbt maps).
 *
 * Translations never invalidate themselves; see appine_dbt_invalidate(). The code cache is
 * double-mapped W^X.
 */
#define _GNU_SOURCE /* needed for madvise, mremap and their flags under -std=c17 */
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

static const struct regs reg_sets[] = {
    [APPINE_DBT_REGS_DEFAULT] = {.ctx = 28, .t0 = 16, .t1 = 17, .t2 = 27, .sp = 26},
    [APPINE_DBT_REGS_GO] = {.ctx = 25, .t0 = 21, .t1 = 22, .t2 = 23, .sp = 24},
};

/* Registered memop kind for pc, or APPINE_MEMOP_NONE (without the lock) */
static uint32_t find_memop(const struct appine_dbt *d, uint64_t pc)
{
    const struct memop_table *m = __atomic_load_n(&d->memops, __ATOMIC_ACQUIRE);
    if (!m || !m->n)
        return APPINE_MEMOP_NONE;
    unsigned lo = 0, hi = m->n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (pc < m->ops[mid].pc)
            hi = mid;
        else if (pc > m->ops[mid].pc)
            lo = mid + 1;
        else
            return m->ops[mid].kind;
    }
    return APPINE_MEMOP_NONE;
}


static void sync_add(struct syncs *s, const uint32_t *start, const uint32_t *end)
{
    s->start[s->n] = (void *)start;
    s->end[s->n] = (void *)end;
    s->n++;
}

/*
 * Refill stub: T1 points to the info word and the refill routine is entered; the info word is
 * followed by this instruction's guest pc. On success the routine sets T2 = addend and jumps back
 * to the access itself; on failure it exits with the pc and the reason in the info word, and
 * Tier 0 executes this instruction.
 *
 *     adr T1, 8   b <refill routine>   .word info   .quad pc
 */
static void emit_refill_stub(struct xlate *x, const struct stub *s)
{
    if (s->bytes > 1u << REFILL_REASON_SHIFT || s->fail >> (REFILL_RESUME_SHIFT - REFILL_REASON_SHIFT))
        appine_guard_fail(); /* the info word cannot hold it: an engine bug */
    emit(x, enc_adr(T1, 8));
    emit_to_routine(x, s->write ? TO_REFILL_WRITE : TO_REFILL_READ);
    intptr_t resume = s->resume - here(x);
    emit(x, (uint32_t)resume << REFILL_RESUME_SHIFT | s->fail << REFILL_REASON_SHIFT | (s->bytes - 1));
    emit(x, (uint32_t)s->pc);
    emit(x, (uint32_t)(s->pc >> 32));
}

/* Return values of install: the code cache or the translation table is full and a full flush
 * (flush_world) is needed first; the guest code was rewritten after translation and must be
 * retranslated */
#define NEED_FLUSH ((uint32_t *)(uintptr_t)1)
#define STALE ((uint32_t *)(uintptr_t)2)

/* A block built by install but not yet put in the translation table: it can only be put in after
 * the instruction cache is synced, since other threads look up the table without the lock */
struct fresh {
    uint64_t pc;
    unsigned tag;
    uint32_t *code;
    const uint32_t *guest;
    uint32_t nguest;
};

/*
 * Without the lock: translate the block starting at pc into the thread's scratch area (or copy a
 * template), recording the result in t->prep. Translation takes the longest, and when translating
 * under the lock the JVM's main thread often had to wait for the compiler threads. The guest
 * instruction words are copied first and then translated, and the copy is compared with memory
 * before installing (install). Returns false if the instructions cannot be fetched.
 */
static bool prepare(struct appine_dbt_thread *t, struct appine_cpu *c, uint64_t pc)
{
    struct appine_dbt *d = t->d;
    struct prep *p = t->prep;
    /* A block does not cross a page (it ends at a page boundary), and the whole page has the same
     * permissions */
    const uint32_t *page = NULL;
    if (!(pc & 3))
        page = appine_mmu_translate(c->mmu, pc & ~PAGE_MASK, APPINE_PROT_EXEC);
    if (!page)
        return false;
    unsigned limit = (unsigned)((APPINE_PAGE_SIZE - (pc & PAGE_MASK)) / 4);
    if (limit > MAX_BLOCK_INSNS)
        limit = MAX_BLOCK_INSNS;
    p->pc = pc;
    /* Blocks a group member translates outside the registered mappings are valid only for that
     * member (TAG_SHIFT) */
    p->tag = t->tag && !in_shared(d, pc) ? t->tag : 0;
    p->guest = page + (pc & PAGE_MASK) / 4;
    p->guest1 = NULL;
    unsigned copied = limit < 32 ? limit : 32;
    memcpy(p->words, p->guest, copied * 4);
    p->nlinks = 0;
    /* Read the grouping records without the lock: reading stale ones only affects grouping, which
     * is undone again when a check fails (ungroup) */
    uint64_t key = d->nogroup_count ? dbt_nogroup_key(d, pc) : 0;
    /* Blocks at registered memop entry PCs emit a threshold check and bypass the process-global
     * template arena so they never pollute other address spaces or miss the check. In a code group,
     * only shared (tag 0) mappings carry group-admitted memops. */
    uint32_t memop_kind = p->tag ? APPINE_MEMOP_NONE : find_memop(d, pc);
    p->memop_kind = memop_kind;
    t->stats.blocks++;
    if (!memop_kind &&
        dbt_template_fetch(pc, p->guest, p->words, &copied, limit, c->mmu, d, key, d->r, !p->tag, p,
                       t->scratch, &t->stats))
        return true;

    struct appine_dbt_stats before = t->stats;
    struct xlate *x = t->xlate;
    x->d = d;
    x->buf = t->scratch;
    x->wdelta = 0;
    x->st = &t->stats;
    x->probe = t->probe;
    x->defined = t->defined;
    x->n = 0;
    x->nstubs = 0;
    x->nfixups = 0;
    x->nrelocs = 0;
    x->pc = pc;
    x->src = p->guest;
    x->mmu = c->mmu;
    x->src1 = NULL;
    x->words = p->words;
    x->copied = copied;
    x->limit = limit;
    x->tried_src1 = false;
    x->shared = !p->tag;
    x->sp_aligned = false;
    x->konst = 0;
    x->affine_valid = 0;
    x->active_groups = 0;
    memset(x->grouped_bits, 0, sizeof(x->grouped_bits));
    x->t2_group = -1;

    /* Check for a kick at the block entry, so that linked loops can be kicked too */
    emit(x, enc_ldr_x(T0, CTX, offsetof(struct appine_cpu, pending)));
    emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_KICK, pc);
    _Static_assert(ENTRY_CHECK_WORDS == 2, "the length of the block entry check");

    uint32_t fl_nguest = 0;
    if (!memop_kind) {
        fl_nguest = dbt_try_fast_loop(x);
        if (fl_nguest)
            p->guest1 = x->src1;
    }

    if (memop_kind) {
        /* Try the in-cache same-page fast path first (avoiding exit/enter and V0-V31 spill/reload
         * while preserving NZCV and all non-return guest registers); on cross-page, TLB miss, or
         * watched pages, fall back to R_INTERP (n >= 128) or guest code (n < 128). */
        switch (memop_kind) {
        case APPINE_MEMOP_MEMSET:
        case APPINE_MEMOP_MEMCPY:
        case APPINE_MEMOP_MEMMOVE: {
            emit(x, enc_ubfx(T1, 2, 5, 59)); /* n >= 32 */
            uint32_t *tiny = here(x);
            emit(x, enc_cbz_x(T1));
            emit(x, enc_adr(T0, 8));
            emit_to_routine(x, memop_kind == APPINE_MEMOP_MEMSET ? TO_MEMOP_MEMSET : TO_MEMOP_MEMMOVE);
            emit(x, enc_ubfx(T0, 2, 7, 57));
            emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_INTERP, pc);
            patch_local(x, tiny, here(x));
            break;
        }
        case APPINE_MEMOP_MEMCMP: {
            emit(x, enc_ubfx(T1, 2, 3, 61)); /* n >= 8 */
            uint32_t *tiny = here(x);
            emit(x, enc_cbz_x(T1));
            emit(x, enc_adr(T0, 8));
            emit_to_routine(x, TO_MEMOP_MEMCMP);
            emit(x, enc_ubfx(T0, 2, 7, 57));
            emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_INTERP, pc);
            patch_local(x, tiny, here(x));
            break;
        }
        case APPINE_MEMOP_MEMCHR: {
            uint32_t *tiny = here(x);
            emit(x, enc_cbz_x(2)); /* n == 0 stays in guest code */
            emit(x, enc_adr(T0, 8));
            emit_to_routine(x, TO_MEMOP_MEMCHR);
            emit(x, enc_ubfx(T0, 2, 7, 57));
            emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_INTERP, pc);
            patch_local(x, tiny, here(x));
            break;
        }
        default:
            emit(x, enc_ubfx(T0, 2, 7, 57));
            emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_INTERP, pc);
            break;
        }
    }

    uint32_t nguest = 0;
    for (;; nguest++) {
        uint64_t va = pc + 4ull * nguest;
        bool budget_full =
            nguest > 0 &&
            (x->n + (size_t)(x->nstubs + INSN_MAX_STUBS) * MAX_STUB_WORDS + INSN_MAX_WORDS > MAX_BLOCK_WORDS ||
             x->nstubs + INSN_MAX_STUBS > MAX_STUBS ||
             x->nfixups + INSN_MAX_FIXUPS > MAX_FIXUPS ||
             x->nrelocs + x->nstubs + INSN_MAX_STUBS + 2 > MAX_RELOCS);
        if (nguest == MAX_BLOCK_INSNS || budget_full || (nguest > 0 && (va & PAGE_MASK) == 0)) {
            emit_exit_stub(x, R_CHAIN_FWD, va);
            break;
        }
        x->st->insns++;
        x->idx = nguest;
        if (!dbt_translate_insn(x, fetch_guest(x, nguest), va)) {
            nguest++;
            break;
        }
    }

    /* A wrong upper-bound estimate is an engine bug: stop before writing out of bounds */
    if (x->nstubs > MAX_STUBS || x->nfixups > MAX_FIXUPS ||
        x->n + (size_t)x->nstubs * MAX_STUB_WORDS > MAX_BLOCK_WORDS)
        appine_guard_fail();
    for (unsigned i = 0; i < x->nstubs; i++)
        x->stubs[i].sites = 0;
    for (unsigned k = 0; k < x->nfixups; k++) {
        struct stub *s = &x->stubs[x->fixups[k].stub];
        s->branch = x->fixups[k].site;
        s->sites++;
    }
    for (unsigned i = 0; i < x->nstubs; i++) {
        struct stub *s = &x->stubs[i];
        s->addr = here(x);
        if (s->reason == STUB_REFILL) {
            emit_refill_stub(x, s);
            continue;
        }
        bool link = s->reason == R_CHAIN || s->reason == R_CHAIN_FWD;
        emit_link_stub(x, s->reason, s->pc, link && s->sites == 1 ? s->branch : NULL);
        if (link)
            p->links[p->nlinks++] = (struct link){
                (uint32_t)(s->addr - x->buf) | (s->reason == R_CHAIN_FWD ? LINK_FWD : 0),
                s->sites == 1 ? (uint32_t)(s->branch - x->buf) : NO_BRANCH, s->pc};
    }
    for (unsigned i = 0; i < x->nfixups; i++) {
        struct fixup *f = &x->fixups[i];
        intptr_t off = (intptr_t)x->stubs[f->stub].addr - (intptr_t)f->site;
        if (f->kind == FIX_IMM19)
            *f->site |= ((uint32_t)(off >> 2) & 0x7ffff) << 5;
        else
            *f->site |= ((uint32_t)(off >> 2) & 0x3fff) << 5;
    }

    if (x->nrelocs > MAX_RELOCS)
        appine_guard_fail();
    uint32_t total_nguest = fl_nguest > nguest ? fl_nguest : nguest;
    if (!memop_kind)
        dbt_template_store(pc, p->words, total_nguest, key, x, &before, p->links, p->nlinks);
    p->nguest = total_nguest;
    p->host = x->buf;
    p->nhost = (uint32_t)x->n;
    memcpy(p->relocs, x->relocs, x->nrelocs * 4);
    p->nrelocs = x->nrelocs;
    return true;
}

/*
 * With the lock held: install a prepared block (prepare) in the code cache and link the exits
 * that are already translated. The new code's range is recorded in `sync` and the block in `f`,
 * and the caller puts it in the translation table (table_insert) after syncing the instruction
 * cache.
 */
static uint32_t *install(struct appine_dbt *d, const struct prep *p, struct syncs *sync, struct fresh *f)
{
    /* This block was not in the cache when another thread changed its code or registration.
     * Recheck both under the lock before publishing it. */
    uint32_t memop_kind = p->tag ? APPINE_MEMOP_NONE : find_memop(d, p->pc);
    unsigned n0 = (unsigned)((APPINE_PAGE_SIZE - (p->pc & PAGE_MASK)) / 4);
    bool words_match = p->nguest <= n0
                           ? memcmp(p->guest, p->words, p->nguest * 4) == 0
                           : (p->guest1 != NULL && memcmp(p->guest, p->words, n0 * 4) == 0 &&
                              memcmp(p->guest1, p->words + n0, (p->nguest - n0) * 4) == 0);
    if (memop_kind != p->memop_kind || !words_match)
        return STALE;
    /* When three quarters of the table are non-empty, rebuild it at the same size if tombstones
     * are at least half, otherwise double it; when blocks is full, remove the invalidated blocks'
     * records, or do a full flush if few are invalidated */
    if (d->table_count == TABLE_LIMIT &&
        (d->blocks_dead * 8 < d->table_count || !dbt_compact_blocks(d)))
        return NEED_FLUSH;
    if (d->words_used + p->nguest > WORDS_LIMIT &&
        (d->blocks_dead * 8 < d->table_count || !dbt_compact_blocks(d) ||
         d->words_used + p->nguest > WORDS_LIMIT))
        return NEED_FLUSH;
    unsigned bits = d->table->bits;
    if (d->table_occupied >= ((size_t)3 << bits) / 4) {
        bool purge = d->table_dead * 2 >= d->table_occupied || bits == TABLE_BITS;
        if (!dbt_table_resize(d, purge ? bits : bits + 1) ||
            d->table_occupied >= ((size_t)3 << d->table->bits) / 4)
            return NEED_FLUSH;
    }
    if (d->used_words + p->nhost > d->cache_words)
        return NEED_FLUSH;
    uint32_t *code = d->cache + d->used_words;
    memcpy(rw(d, code), p->host, p->nhost * 4);
    for (unsigned i = 0; i < p->nrelocs; i++) {
        uint32_t *site = code + (p->relocs[i] >> 4);
        *rw(d, site) = enc_b((intptr_t)routine(d, p->relocs[i] & 15) - (intptr_t)site);
    }
    d->used_words += p->nhost;
    dbt_link_block(d, code, p->pc, p->tag, p->links, p->nlinks);
    dbt_perf_map(code, p->nhost * 4, p->pc);
    sync_add(sync, code, code + p->nhost);
    *f = (struct fresh){p->pc, p->tag, code, p->words, p->nguest};
    return code;
}


/*
 * Instances no longer in use (their address space is gone) go into a small pool for new address
 * spaces to reuse: short-lived processes then need not map the code cache and the tables anew
 * each time and then fault on the first write to every page. Instances with few translations are
 * kept, distinguished by program (a key the caller gives; the kernel layer uses the executable's
 * inode): when the same program runs again (busybox exec'd over and over by a shell script, go
 * build's compiles one after another, repeated `node -e`), it takes back the translations it
 * left and keeps using them after checking them (the register assignment must also be the same);
 * without one of the same key it takes an empty one or creates one, rather than clearing what
 * other programs left. When several processes run the same program at once each takes an
 * instance, so the pool must have room for them. The total code kept in the pool is capped, and
 * when the cap is exceeded the least recently used go first. An emptied instance marks the used
 * part of its code cache MADV_FREE, so the host can reclaim it directly under memory pressure (a
 * later write just faults again). The thread parts (jump cache, shadow return stack) have a pool
 * of their own.
 */
#define POOL_SIZE 16
#define POOL_KEEP_WORDS ((size_t)(64u << 20) / 4) /* at most 64 MB of code kept in the pool */
#define THREAD_POOL_SIZE 8

static struct {
    pthread_mutex_t lock;
    struct pooled {
        struct appine_dbt *d;
        uint64_t key;  /* which program's translations are kept; 0 if emptied */
        uint64_t when; /* order of arrival, to remove the least recently used */
    } free[POOL_SIZE];
    unsigned n;
    uint64_t clock;
    size_t kept_words; /* code kept in the pool */
    struct appine_dbt_thread *threads[THREAD_POOL_SIZE];
    unsigned nthreads;
    struct appine_dbt *all; /* all instances */
} pool = {.lock = PTHREAD_MUTEX_INITIALIZER};

/* Take entry i out of the pool. Pool lock held */
static struct appine_dbt *pool_take(unsigned i)
{
    struct appine_dbt *d = pool.free[i].d;
    if (pool.free[i].key)
        pool.kept_words -= d->used_words - d->routine_words;
    pool.free[i] = pool.free[--pool.n];
    return d;
}

/* Free the registered ranges (appine_dbt_share), the current list and every replaced one, and
 * clear d->shared; no thread is using this instance */
static void drop_shared(struct appine_dbt *d)
{
    for (struct shared_ranges *s = d->shared, *older; s; s = older) {
        older = s->older;
        free(s);
    }
    d->shared = NULL;
}

/* Free the registered memop tables (appine_dbt_set_memops) and clear d->memops; no thread is using
 * this instance */
static void drop_memops(struct appine_dbt *d)
{
    for (struct memop_table *m = d->memops, *older; m; m = older) {
        older = m->older;
        free(m);
    }
    d->memops = NULL;
}


static void release(struct appine_dbt *d)
{
    drop_shared(d);
    drop_memops(d);
    pthread_mutex_lock(&pool.lock);
    if (d->prev_instance) {
        *d->prev_instance = d->next_instance;
        if (d->next_instance)
            d->next_instance->prev_instance = d->prev_instance;
    }
    pthread_mutex_unlock(&pool.lock);
    if (d->cache)
        appine_unmap_code(d->cache, CODE_CACHE_BYTES, d->rw_delta);
    dbt_zfree(d->written, sizeof(*d->written));
    if (d->table)
        dbt_zfree(d->table, TABLE_BYTES(d->table->bits));
    dbt_zfree(d->table_used, TABLE_LIMIT * sizeof(*d->table_used));
    dbt_zfree(d->blocks, TABLE_LIMIT * sizeof(*d->blocks));
    dbt_zfree(d->words, WORDS_LIMIT * sizeof(*d->words));
    dbt_zfree(d->page_head, sizeof(*d->page_head) << PAGE_BUCKET_BITS);
    dbt_zfree(d->page_parked, sizeof(*d->page_parked) << PAGE_BUCKET_BITS);
    pthread_mutex_destroy(&d->lock);
    pthread_cond_destroy(&d->flushed);
    dbt_zfree(d, sizeof(*d));
}

struct appine_dbt *appine_dbt_new(uint64_t key, enum appine_dbt_regs regs)
{
    const struct regs *r = &reg_sets[regs];
    pthread_mutex_lock(&pool.lock);
    int best = -1;
    for (unsigned i = 0; i < pool.n; i++) {
        bool same = key && pool.free[i].key == key && pool.free[i].d->r == r;
        bool empty = !pool.free[i].key;
        if ((same && (best < 0 || pool.free[best].key != key || pool.free[i].when > pool.free[best].when)) ||
            (empty && best < 0))
            best = (int)i;
    }
    struct appine_dbt *d = best >= 0 ? pool_take((unsigned)best) : NULL;
    pthread_mutex_unlock(&pool.lock);
    if (d && d->r != r) { /* an empty instance: regenerate the routines for this register set */
        d->r = r;
        dbt_emit_routines(d);
    }
    if (d)
        return d;

    d = dbt_zalloc(sizeof(*d));
    if (!d)
        return NULL;
    pthread_mutex_init(&d->lock, NULL);
    pthread_cond_init(&d->flushed, NULL);
    d->st = &d->spare_stats;
    d->cache = appine_map_code(CODE_CACHE_BYTES, &d->rw_delta);
    if (d->cache && d->rw_delta)
        d->written = dbt_zalloc(sizeof(*d->written));
    d->table = dbt_table_new(TABLE_MIN_BITS);
    d->table_used = dbt_zalloc(TABLE_LIMIT * sizeof(*d->table_used));
    d->blocks = dbt_zalloc(TABLE_LIMIT * sizeof(*d->blocks));
    d->words = dbt_zalloc(WORDS_LIMIT * sizeof(*d->words));
    d->page_head = dbt_zalloc(sizeof(*d->page_head) << PAGE_BUCKET_BITS);
    d->page_parked = dbt_zalloc(sizeof(*d->page_parked) << PAGE_BUCKET_BITS);
    if (!d->cache || (d->rw_delta && !d->written) || !d->table || !d->table_used || !d->blocks ||
        !d->words || !d->page_head || !d->page_parked) {
        release(d);
        return NULL;
    }
    d->cache_words = CODE_CACHE_BYTES / 4;
    d->r = r;
    d->next_tag = 1;
    dbt_emit_routines(d);
    pthread_mutex_lock(&pool.lock);
    d->next_instance = pool.all;
    if (pool.all)
        pool.all->prev_instance = &d->next_instance;
    d->prev_instance = &pool.all;
    pool.all = d;
    pthread_mutex_unlock(&pool.lock);
    return d;
}

/*
 * When returning to the pool with translations kept, remove the members' private blocks, so tags
 * can be allocated from the start again. Only private blocks of the same member link to them
 * (shared blocks do not link to private blocks), and no threads are attached, so no forwarding
 * stubs are needed
 */
static void drop_private(struct appine_dbt *d)
{
    for (size_t i = 0; i < d->table_count; i++) {
        struct block *b = &d->blocks[i];
        if (!b->tag || !b->code)
            continue;
        if (b->parked) {
            dbt_kill_parked(d, b);
            continue;
        }
        dbt_table_remove(d, block_key(b));
        b->code = NULL;
        d->blocks_dead++;
    }
}

/* Put back into the pool: no threads are attached, so it can be flushed directly */
void appine_dbt_free(struct appine_dbt *d, uint64_t key)
{
    if (!d)
        return;
    if (d->poisoned) {
        release(d);
        return;
    }
    d->st = &d->spare_stats;
    size_t words = d->used_words - d->routine_words;
    /* Keep the translations when there are not many blocks: checking them once before the next
     * user running the same program runs (recheck) is much cheaper than copying templates block by
     * block, relinking and syncing the instruction cache */
    bool keep = key && d->table_count <= KEEP_MAX_BLOCKS && words <= POOL_KEEP_WORDS && !d->flush_wanted;
    /* A large instance using more than half of the pool (one JVM run takes 40–50 MB) is kept only
     * if it does not push others out: otherwise one java run would push out all the translations
     * left by frequently used programs such as node and python */
    if (keep && words > POOL_KEEP_WORDS / 2) {
        pthread_mutex_lock(&pool.lock);
        keep = pool.kept_words + words <= POOL_KEEP_WORDS;
        pthread_mutex_unlock(&pool.lock);
    }
    drop_shared(d);
    /* Retire any memop-specialized blocks before returning the instance to the pool so the next
     * user never inherits memop checks from the previous address space. */
    if (keep && d->memops && d->memops->n) {
        struct retire_batch r = {.n = 0};
        for (unsigned i = 0; i < d->memops->n; i++) {
            if (!dbt_retire_pc(d, &r, d->memops->ops[i].pc)) {
                keep = false;
                break;
            }
        }
        if (keep) {
            dbt_retire_flush(d, &r);
            words = d->used_words - d->routine_words;
            if (words > POOL_KEEP_WORDS)
                keep = false;
        }
    }
    drop_memops(d);
    if (keep) {
        drop_private(d);
        d->stale = d->table_count > 0;
    } else {
        key = 0;
        words = 0;
        size_t nblocks = d->table_count, nguest = d->words_used;
        dbt_flush_locked(d);
        d->nogroup_count = 0;
        memset(d->strikes, 0, sizeof(d->strikes));
        d->strikes_next = 0;
        if (d->table->bits > TABLE_MIN_BITS) /* next user is most likely a short-lived process */
            dbt_table_resize(d, TABLE_MIN_BITS);
        /* Block records and instruction words are mapped in advance at their limits, and the used
         * parts keep occupying memory: return them too */
        dbt_release_pages(d->blocks, nblocks * sizeof(*d->blocks));
        dbt_release_pages(d->table_used, nblocks * sizeof(*d->table_used));
        dbt_release_pages(d->words, nguest * sizeof(*d->words));
        /*
         * Keep the pages holding the enter/exit routines, and hand the rest of the used part to
         * the host to reclaim: private mappings use MADV_FREE, reclaimed only under memory
         * pressure; double-mapped shared memory does not support it and can only be freed at once
         * with MADV_REMOVE
         */
        uintptr_t page = dbt_host_page_size();
        uintptr_t start = ((uintptr_t)rw(d, d->cache + d->routine_words) + page - 1) & ~(page - 1);
        uintptr_t end = ((uintptr_t)rw(d, d->cache + d->high_words) + page - 1) & ~(page - 1);
        if (end > start)
            madvise((void *)start, end - start, d->rw_delta ? MADV_REMOVE : MADV_FREE);
        d->high_words = 0;
        dbt_drop_written(d); /* the routines' pages, and the recorded page count */
    }
    d->next_tag = 1; /* all tagged blocks have been removed */
    /* Make room: the pool is full, or the kept code exceeds the limit. Remove empty ones first
     * (rebuilding them is cheap), then the least recently used */
    struct appine_dbt *evicted[POOL_SIZE];
    unsigned nevicted = 0;
    pthread_mutex_lock(&pool.lock);
    while (pool.n && (pool.n == POOL_SIZE || pool.kept_words + words > POOL_KEEP_WORDS)) {
        /* When making room for code, removing empty ones does not help */
        bool need_code = pool.kept_words + words > POOL_KEEP_WORDS;
        int victim = -1;
        for (unsigned i = 0; i < pool.n; i++) {
            bool empty = !pool.free[i].key;
            if (need_code && empty)
                continue;
            if (victim < 0) {
                victim = (int)i;
                continue;
            }
            bool victim_empty = !pool.free[victim].key;
            if (empty != victim_empty ? empty : pool.free[i].when < pool.free[victim].when)
                victim = (int)i;
        }
        if (victim < 0)
            break;
        evicted[nevicted++] = pool_take((unsigned)victim);
    }
    pool.free[pool.n++] = (struct pooled){d, key, ++pool.clock};
    pool.kept_words += words;
    pthread_mutex_unlock(&pool.lock);
    for (unsigned i = 0; i < nevicted; i++)
        release(evicted[i]);
}

/* Drop the pages written in the writable view of every instance's code cache (see the comment
 * before struct written) */
void appine_dbt_unmap_written(void)
{
    pthread_mutex_lock(&pool.lock);
    for (struct appine_dbt *d = pool.all; d; d = d->next_instance)
        dbt_drop_written(d);
    pthread_mutex_unlock(&pool.lock);
}

/* Total bytes of the pages written in the writable view and not dropped yet: they count twice in
 * the host's RSS */
uint64_t appine_dbt_written_bytes(void)
{
    uint64_t pages = 0;
    pthread_mutex_lock(&pool.lock);
    for (struct appine_dbt *d = pool.all; d; d = d->next_instance)
        if (d->written)
            pages += __atomic_load_n(&d->written->pages, __ATOMIC_RELAXED);
    pthread_mutex_unlock(&pool.lock);
    return pages * dbt_host_page_size();
}

static void release_thread(struct appine_dbt_thread *t)
{
    dbt_zfree(t->jc, JC_SIZE * sizeof(*t->jc));
    dbt_zfree(t->rs, APPINE_PAGE_SIZE);
    free(t->xlate);
    dbt_zfree(t->scratch, MAX_BLOCK_WORDS * sizeof(*t->scratch));
    dbt_zfree(t->probe, sizeof(*t->probe));
    dbt_zfree(t->defined, DEFINED_CACHE * sizeof(*t->defined));
    free(t->prep);
    dbt_zfree(t, sizeof(*t));
}

/* Detach both idle pools in one pass. Freeing and template trimming take their own locks. */
void appine_dbt_trim(void)
{
    struct appine_dbt *evicted[POOL_SIZE];
    struct appine_dbt_thread *evicted_threads[THREAD_POOL_SIZE];
    unsigned n = 0, nthreads = 0;
    pthread_mutex_lock(&pool.lock);
    while (pool.n)
        evicted[n++] = pool_take(pool.n - 1);
    while (pool.nthreads)
        evicted_threads[nthreads++] = pool.threads[--pool.nthreads];
    pthread_mutex_unlock(&pool.lock);
    for (unsigned i = 0; i < n; i++)
        release(evicted[i]);
    for (unsigned i = 0; i < nthreads; i++)
        release_thread(evicted_threads[i]);
    dbt_template_trim();
}

/* Take d's lock, recording whom this round's translations and invalidations are charged to. The
 * lock is always held only briefly (installing a block, invalidating a batch of blocks), so spin
 * for a while first rather than sleep and be woken again (tens of microseconds each time in a
 * virtual machine) */
static void lock_dbt(struct appine_dbt *d, struct appine_dbt_stats *st)
{
    unsigned spin = 0;
    while (pthread_mutex_trylock(&d->lock) != 0) {
        if (++spin == 200) {
            pthread_mutex_lock(&d->lock);
            break;
        }
        __asm__ volatile("yield");
    }
    appine_guard_hold(&d->lock, false);
    d->st = st;
}

static void unlock_dbt(struct appine_dbt *d)
{
    appine_guard_drop();
    pthread_mutex_unlock(&d->lock);
}

unsigned appine_dbt_new_tag(struct appine_dbt *d)
{
    pthread_mutex_lock(&d->lock);
    unsigned tag = d->next_tag <= TAG_MAX ? d->next_tag++ : 0;
    pthread_mutex_unlock(&d->lock);
    return tag;
}

static int range_cmp(const void *a, const void *b)
{
    uint64_t x = ((const uint64_t *)a)[0], y = ((const uint64_t *)b)[0];
    return x < y ? -1 : x > y;
}

void appine_dbt_share(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    struct shared_ranges *r = malloc(sizeof(*r) + n * sizeof(r->r[0]));
    if (!r) /* keep the old ranges: blocks outside them count as private, only less is shared */
        return;
    for (size_t i = 0; i < n; i++) {
        r->r[i][0] = s[i].start;
        r->r[i][1] = s[i].start + s[i].len;
    }
    qsort(r->r, n, sizeof(r->r[0]), range_cmp);
    unsigned m = 0; /* merge overlapping and adjacent ones into one range */
    for (size_t i = 0; i < n; i++) {
        if (m && r->r[i][0] <= r->r[m - 1][1]) {
            if (r->r[i][1] > r->r[m - 1][1])
                r->r[m - 1][1] = r->r[i][1];
        } else {
            r->r[m][0] = r->r[i][0];
            r->r[m][1] = r->r[i][1];
            m++;
        }
    }
    r->n = m;
    pthread_mutex_lock(&d->lock);
    r->older = d->shared;
    __atomic_store_n(&d->shared, r, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&d->lock);
}

struct appine_dbt_thread *appine_dbt_attach(struct appine_dbt *d, unsigned tag)
{
    pthread_mutex_lock(&pool.lock);
    struct appine_dbt_thread *t = pool.nthreads ? pool.threads[--pool.nthreads] : NULL;
    pthread_mutex_unlock(&pool.lock);
    if (!t) {
        t = dbt_zalloc(sizeof(*t));
        if (!t)
            return NULL;
        t->jc = dbt_zalloc(JC_SIZE * sizeof(*t->jc));
        t->rs = dbt_zalloc(APPINE_PAGE_SIZE); /* page-aligned, and so also 1 KB-aligned */
        t->xlate = malloc(sizeof(*t->xlate));
        t->scratch = dbt_zalloc(MAX_BLOCK_WORDS * sizeof(*t->scratch));
        t->probe = dbt_zalloc(sizeof(*t->probe)); /* TLB is over 100 KB; unused pages take no memory */
        t->defined = dbt_zalloc(DEFINED_CACHE * sizeof(*t->defined));
        t->prep = malloc(sizeof(*t->prep));
        if (!t->jc || !t->rs || !t->xlate || !t->scratch || !t->probe || !t->defined || !t->prep) {
            release_thread(t);
            return NULL;
        }
        appine_cpu_init(t->probe, NULL);
        t->jc_dirty = true;
    }
    t->d = d;
    t->tag = tag;
    t->cpu = NULL;
    t->parked = false;
    t->stats = (struct appine_dbt_stats){0};
    if (t->jc_dirty)
        dbt_clear_jump_cache(t);
    lock_dbt(d, &t->stats);
    t->generation = d->generation;
    dbt_rs_reset(t);
    t->next = d->threads;
    d->threads = t;
    __atomic_store_n(&d->nthreads, d->nthreads + 1, __ATOMIC_RELAXED);
    unlock_dbt(d);
    return t;
}

void appine_dbt_detach(struct appine_dbt_thread *t)
{
    if (!t)
        return;
    struct appine_dbt *d = t->d;
    lock_dbt(d, &d->spare_stats);
    for (struct appine_dbt_thread **p = &d->threads; *p; p = &(*p)->next) {
        if (*p == t) {
            *p = t->next;
            __atomic_store_n(&d->nthreads, d->nthreads - 1, __ATOMIC_RELAXED);
            break;
        }
    }
    unlock_dbt(d);
    pthread_mutex_lock(&pool.lock);
    bool keep = pool.nthreads < THREAD_POOL_SIZE;
    if (keep)
        pool.threads[pool.nthreads++] = t;
    pthread_mutex_unlock(&pool.lock);
    if (!keep)
        release_thread(t);
}

void appine_dbt_flush(struct appine_dbt_thread *t)
{
    __atomic_store_n(&t->d->flush_wanted, true, __ATOMIC_SEQ_CST);
}

void appine_dbt_invalidate(struct appine_dbt_thread *t, const struct appine_cpu *cpu, uint64_t start,
                           uint64_t len)
{
    lock_dbt(t->d, &t->stats);
    dbt_invalidate_locked(t->d, cpu ? cpu->mmu : NULL, start, len);
    unlock_dbt(t->d);
}


void appine_dbt_set_sources(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    pthread_mutex_lock(&d->lock);
    /* What does not fit is not recorded: blocks in unrecorded mappings are checked as usual */
    d->nsources = n < APPINE_DBT_SOURCES ? (unsigned)n : APPINE_DBT_SOURCES;
    memcpy(d->sources, s, d->nsources * sizeof(*s));
    pthread_mutex_unlock(&d->lock);
}

static int memop_cmp(const void *a, const void *b)
{
    uint64_t x = ((const struct appine_dbt_memop *)a)->pc;
    uint64_t y = ((const struct appine_dbt_memop *)b)->pc;
    return x < y ? -1 : x > y;
}

void appine_dbt_set_memops(struct appine_dbt *d, const struct appine_dbt_memop *ops, size_t n)
{
    if (!d)
        return;
    struct appine_dbt_memop sorted[APPINE_DBT_MEMOPS];
    unsigned count = 0;
    for (size_t i = 0; i < n && count < APPINE_DBT_MEMOPS; i++) {
        uint64_t pc = ops[i].pc;
        uint32_t kind = ops[i].kind;
        if (!kind || kind > APPINE_MEMOP_STRNCMP || (pc & (3 | ~PC_MASK)))
            continue;
        sorted[count++] = (struct appine_dbt_memop){.pc = pc, .kind = kind, .reserved = 0};
    }
    if (count > 1) {
        qsort(sorted, count, sizeof(sorted[0]), memop_cmp);
        unsigned unique = 1;
        for (unsigned i = 1; i < count; i++) {
            if (sorted[i].pc != sorted[unique - 1].pc)
                sorted[unique++] = sorted[i];
        }
        count = unique;
    }
    struct memop_table *m = malloc(sizeof(*m) + count * sizeof(m->ops[0]));
    if (!m)
        return;
    m->n = count;
    if (count)
        memcpy(m->ops, sorted, count * sizeof(m->ops[0]));

    pthread_mutex_lock(&d->lock);
    struct memop_table *old = d->memops;
    unsigned old_n = old ? old->n : 0;
    if (old_n == count && (!count || memcmp(old->ops, m->ops, count * sizeof(m->ops[0])) == 0)) {
        pthread_mutex_unlock(&d->lock);
        free(m);
        return;
    }
    /* Publish the new table before retiring changed blocks so any thread retranslating a retired
     * block sees the updated registrations, and any in-flight R_INTERP at a removed PC sees NONE. */
    m->older = old;
    __atomic_store_n(&d->memops, m, __ATOMIC_RELEASE);
    d->st = &d->spare_stats;
    struct retire_batch r = {.n = 0};
    unsigned oi = 0, ni = 0;
    bool ok = true;
    while (ok && (oi < old_n || ni < count)) {
        uint64_t pc;
        if (oi < old_n && ni < count && old->ops[oi].pc == m->ops[ni].pc) {
            bool same = old->ops[oi].kind == m->ops[ni].kind;
            pc = m->ops[ni].pc;
            oi++;
            ni++;
            if (same)
                continue;
        } else if (ni >= count || (oi < old_n && old->ops[oi].pc < m->ops[ni].pc)) {
            pc = old->ops[oi++].pc;
        } else {
            pc = m->ops[ni++].pc;
        }
        ok = dbt_retire_pc(d, &r, pc);
    }
    if (!ok)
        __atomic_store_n(&d->flush_wanted, true, __ATOMIC_SEQ_CST);
    dbt_retire_flush(d, &r);
    pthread_mutex_unlock(&d->lock);
}

#define MEMOP_MAX_BYTES (UINT64_C(64) << 20)

static uint8_t *memop_translate_span(const struct appine_mmu *mmu, uint64_t addr, uint32_t prot,
                                     uint64_t *span_out)
{
    bool is_super = false;
    uintptr_t pte = appine_mmu_lookup_super(mmu, addr, &is_super);
    if (!(pte & PTE_PROT_MASK) || (pte & prot) != prot)
        return NULL;
    uintptr_t base = pte & ~(uintptr_t)PAGE_MASK;
    if (is_super) {
        uint64_t off = addr & MMU_SUPER_MASK;
        *span_out = MMU_SUPER_SIZE - off;
        return (uint8_t *)(base + off);
    }
    uint64_t off = addr & PAGE_MASK;
    *span_out = APPINE_PAGE_SIZE - off;
    return (uint8_t *)(base + off);
}

static uint8_t *memop_translate_span_back(const struct appine_mmu *mmu, uint64_t end_addr,
                                          uint32_t prot, uint64_t *span_out)
{
    uint64_t last = end_addr - 1;
    bool is_super = false;
    uintptr_t pte = appine_mmu_lookup_super(mmu, last, &is_super);
    if (!(pte & PTE_PROT_MASK) || (pte & prot) != prot)
        return NULL;
    uintptr_t base = pte & ~(uintptr_t)PAGE_MASK;
    if (is_super) {
        uint64_t off = last & MMU_SUPER_MASK;
        *span_out = off + 1;
        return (uint8_t *)(base + off + 1);
    }
    uint64_t off = last & PAGE_MASK;
    *span_out = off + 1;
    return (uint8_t *)(base + off + 1);
}

static bool memop_check_range(const struct appine_mmu *mmu, uint64_t addr, uint64_t n, uint32_t prot)
{
    if (n == 0)
        return true;
    if (addr + n < addr)
        return false;
    uint64_t cur = addr, rem = n;
    while (rem > 0) {
        uint64_t span = 0;
        if (!memop_translate_span(mmu, cur, prot, &span))
            return false;
        if (span >= rem)
            return true;
        cur += span;
        rem -= span;
    }
    return true;
}

static inline void memop_warm_tlb(struct appine_cpu *c, uint64_t raw_va, uint32_t access)
{
    /* Only warm untagged 48-bit VAs so the TLB tag matches inline checks (emit_refill stores
     * top-byte tags in the TLB tag and folds them into the addend). */
    if ((raw_va >> APPINE_VA_BITS) == 0)
        appine_tlb_fill(c, raw_va, access);
}

static bool exec_memop(struct appine_cpu *c, uint32_t kind)
{
    if (UNLIKELY(c->nwatch != 0))
        return false;
    const struct appine_mmu *mmu = c->mmu;
    switch (kind) {
    case APPINE_MEMOP_MEMSET: {
        uint64_t raw_dst = c->x[0], dst = untag(raw_dst), n = c->x[2];
        int val = (int)(c->x[1] & 0xff);
        if (n > MEMOP_MAX_BYTES || !memop_check_range(mmu, dst, n, APPINE_PROT_WRITE))
            return false;
        uint64_t cur = dst, rem = n;
        while (rem > 0) {
            uint64_t chunk = 0;
            uint8_t *hp = memop_translate_span(mmu, cur, APPINE_PROT_WRITE, &chunk);
            if (UNLIKELY(!hp))
                return false;
            if (chunk > rem)
                chunk = rem;
            memset(hp, val, chunk);
            cur += chunk;
            rem -= chunk;
        }
        if (n > 0)
            memop_warm_tlb(c, raw_dst, APPINE_ACCESS_WRITE);
        return true;
    }
    case APPINE_MEMOP_MEMCPY:
    case APPINE_MEMOP_MEMMOVE: {
        uint64_t raw_dst = c->x[0], raw_src = c->x[1];
        uint64_t dst = untag(raw_dst), src = untag(raw_src), n = c->x[2];
        if (n > MEMOP_MAX_BYTES)
            return false;
        if (n == 0)
            return true;
        if (!memop_check_range(mmu, dst, n, APPINE_PROT_WRITE) ||
            !memop_check_range(mmu, src, n, APPINE_PROT_READ))
            return false;
        if (dst == src) {
            memop_warm_tlb(c, raw_dst, APPINE_ACCESS_WRITE);
            return true;
        }
        if (dst > src && dst < src + n) {
            uint64_t rem = n;
            while (rem > 0) {
                uint64_t d_span = 0, s_span = 0;
                uint8_t *dh_end = memop_translate_span_back(mmu, dst + rem, APPINE_PROT_WRITE, &d_span);
                uint8_t *sh_end = memop_translate_span_back(mmu, src + rem, APPINE_PROT_READ, &s_span);
                if (UNLIKELY(!dh_end || !sh_end))
                    return false;
                uint64_t chunk = d_span < s_span ? d_span : s_span;
                if (chunk > rem)
                    chunk = rem;
                memmove(dh_end - chunk, sh_end - chunk, chunk);
                rem -= chunk;
            }
        } else {
            uint64_t d_cur = dst, s_cur = src, rem = n;
            while (rem > 0) {
                uint64_t d_span = 0, s_span = 0;
                uint8_t *dh = memop_translate_span(mmu, d_cur, APPINE_PROT_WRITE, &d_span);
                uint8_t *sh = memop_translate_span(mmu, s_cur, APPINE_PROT_READ, &s_span);
                if (UNLIKELY(!dh || !sh))
                    return false;
                uint64_t chunk = d_span < s_span ? d_span : s_span;
                if (chunk > rem)
                    chunk = rem;
                memmove(dh, sh, chunk);
                d_cur += chunk;
                s_cur += chunk;
                rem -= chunk;
            }
        }
        memop_warm_tlb(c, raw_dst, APPINE_ACCESS_WRITE);
        memop_warm_tlb(c, raw_src, APPINE_ACCESS_READ);
        return true;
    }
    case APPINE_MEMOP_MEMCMP: {
        uint64_t raw_a = c->x[0], raw_b = c->x[1];
        uint64_t a_cur = untag(raw_a), b_cur = untag(raw_b), rem = c->x[2];
        if (rem > MEMOP_MAX_BYTES)
            return false;
        while (rem > 0) {
            uint64_t a_span = 0, b_span = 0;
            uint8_t *ah = memop_translate_span(mmu, a_cur, APPINE_PROT_READ, &a_span);
            uint8_t *bh = memop_translate_span(mmu, b_cur, APPINE_PROT_READ, &b_span);
            if (UNLIKELY(!ah || !bh))
                return false;
            uint64_t chunk = a_span < b_span ? a_span : b_span;
            if (chunk > rem)
                chunk = rem;
            int r = memcmp(ah, bh, chunk);
            if (r != 0) {
                memop_warm_tlb(c, raw_a, APPINE_ACCESS_READ);
                memop_warm_tlb(c, raw_b, APPINE_ACCESS_READ);
                c->x[0] = (uint64_t)(int64_t)r;
                return true;
            }
            a_cur += chunk;
            b_cur += chunk;
            rem -= chunk;
        }
        if (c->x[2] > 0) {
            memop_warm_tlb(c, raw_a, APPINE_ACCESS_READ);
            memop_warm_tlb(c, raw_b, APPINE_ACCESS_READ);
        }
        c->x[0] = 0;
        return true;
    }
    case APPINE_MEMOP_MEMCHR: {
        uint64_t base = c->x[0], start = untag(base), cur = start, total = c->x[2];
        int ch = (int)(c->x[1] & 0xff);
        /* Scan up to MEMOP_MAX_BYTES even when callers pass SIZE_MAX (e.g., musl strnlen); only
         * fall back to guest code if the budget is exhausted without finding a match. */
        uint64_t rem = total > MEMOP_MAX_BYTES ? MEMOP_MAX_BYTES : total;
        while (rem > 0) {
            uint64_t chunk = 0;
            uint8_t *hp = memop_translate_span(mmu, cur, APPINE_PROT_READ, &chunk);
            if (UNLIKELY(!hp))
                return false;
            if (chunk > rem)
                chunk = rem;
            uint8_t *f = (uint8_t *)memchr(hp, ch, chunk);
            if (f) {
                memop_warm_tlb(c, base, APPINE_ACCESS_READ);
                c->x[0] = base + (cur - start) + (uint64_t)(f - hp);
                return true;
            }
            cur += chunk;
            rem -= chunk;
        }
        if (total > MEMOP_MAX_BYTES)
            return false;
        if (total > 0)
            memop_warm_tlb(c, base, APPINE_ACCESS_READ);
        c->x[0] = 0;
        return true;
    }
    case APPINE_MEMOP_STRNCMP: {
        uint64_t a_cur = untag(c->x[0]), b_cur = untag(c->x[1]), total = c->x[2];
        uint64_t rem = total > MEMOP_MAX_BYTES ? MEMOP_MAX_BYTES : total;
        while (rem > 0) {
            uint64_t a_span = 0, b_span = 0;
            uint8_t *ah = memop_translate_span(mmu, a_cur, APPINE_PROT_READ, &a_span);
            uint8_t *bh = memop_translate_span(mmu, b_cur, APPINE_PROT_READ, &b_span);
            if (UNLIKELY(!ah || !bh))
                return false;
            uint64_t chunk = a_span < b_span ? a_span : b_span;
            if (chunk > rem)
                chunk = rem;
            uint8_t *za = (uint8_t *)memchr(ah, 0, chunk);
            uint64_t span = za ? (uint64_t)(za - ah) + 1 : chunk;
            int r = memcmp(ah, bh, span);
            if (r != 0) {
                c->x[0] = (uint64_t)(int64_t)r;
                return true;
            }
            if (za) {
                c->x[0] = 0;
                return true;
            }
            a_cur += chunk;
            b_cur += chunk;
            rem -= chunk;
        }
        if (total > MEMOP_MAX_BYTES)
            return false;
        c->x[0] = 0;
        return true;
    }
    default:
        return false;
    }
}

void appine_dbt_trust(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    pthread_mutex_lock(&d->lock);
    d->ntrusted = 0;
    for (size_t i = 0; d->stale && i < n; i++) {
        for (unsigned j = 0; j < d->nsources; j++) {
            if (!memcmp(&s[i], &d->sources[j], sizeof(*s)) && d->ntrusted < APPINE_DBT_SOURCES) {
                d->trusted[d->ntrusted][0] = s[i].start;
                d->trusted[d->ntrusted][1] = s[i].start + s[i].len;
                d->ntrusted++;
                break;
            }
        }
    }
    /* What was recorded is used only once: it is recorded again when this address space stops
     * being used. All of it is recorded as parkable ranges (recheck) */
    for (unsigned j = 0; j < d->nsources; j++) {
        d->parkable[j][0] = d->sources[j].start;
        d->parkable[j][1] = d->sources[j].start + d->sources[j].len;
    }
    d->nparkable = d->stale ? d->nsources : 0;
    d->nsources = 0;
    pthread_mutex_unlock(&d->lock);
}

void appine_dbt_retire_outside(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    pthread_mutex_lock(&d->lock);
    d->st = &d->spare_stats; /* the previous thread holding the lock may have detached already */
    struct retire_batch r = {.n = 0};
    for (size_t i = 0; i < d->table_count; i++) {
        struct block *b = &d->blocks[i];
        if (!b->code || b->tag) /* private blocks are found only by their member */
            continue;
        bool inside = false;
        for (size_t j = 0; j < n && !inside; j++)
            inside = b->pc >= s[j].start && b->pc + (uint64_t)b->nguest * 4 <= s[j].start + s[j].len;
        if (inside)
            continue;
        if (b->parked) {
            dbt_kill_parked(d, b);
        } else if (!dbt_retire_add(d, &r, b, false)) {
            __atomic_store_n(&d->flush_wanted, true, __ATOMIC_SEQ_CST);
            break;
        }
    }
    dbt_retire_flush(d, &r);
    pthread_mutex_unlock(&d->lock);
}

/* Stop and wait for another thread to finish a full flush. Lock held, released while waiting */
static void park(struct appine_dbt *d, struct appine_dbt_thread *self)
{
    self->parked = true;
    while (__atomic_load_n(&d->flushing, __ATOMIC_ACQUIRE) && !d->poisoned)
        pthread_cond_wait(&d->flushed, &d->lock);
    self->parked = false;
}

/* Whether a thread other than self is in dbt_run and not stopped in park. Lock held */
static bool others_running(const struct appine_dbt *d, const struct appine_dbt_thread *self)
{
    for (const struct appine_dbt_thread *t = d->threads; t; t = t->next)
        if (t != self && !t->parked && __atomic_load_n(&t->cpu, __ATOMIC_SEQ_CST))
            return true;
    return false;
}

/*
 * Full flush: kick the other threads in dbt_run, wait until they have all stopped (park) or left
 * dbt_run, then flush. Entered and returned with the lock held; the lock is released while
 * waiting so that other threads can reach park. If a thread is already doing it, stop along with
 * the others and wait for it.
 *
 * flushing is set before looking at each thread's cpu, and a thread registers its cpu before
 * looking at flushing: either this side kicks it, or it sees flushing and stops by itself. While
 * waiting, each thread's cpu and parked are checked with the lock held: parked only changes under
 * the lock, and a stopped thread does not leave before the flush ends.
 *
 * Previously two shared counters (threads in dbt_run, stopped threads) were changed atomically on
 * every entry into and exit from dbt_run: when several threads of one address space entered and
 * left often (every system call is one), that cache line bounced between cores, and with 8
 * threads reading the clock at the same time each read went from 94 ns to 844 ns. Now entry and
 * exit only write the thread's own cpu.
 */
static void flush_world(struct appine_dbt *d, struct appine_dbt_thread *self)
{
    if (__atomic_load_n(&d->flushing, __ATOMIC_RELAXED)) {
        park(d, self);
        return;
    }
    __atomic_store_n(&d->flushing, true, __ATOMIC_SEQ_CST);
    for (struct appine_dbt_thread *t = d->threads; t; t = t->next) {
        struct appine_cpu *c = __atomic_load_n(&t->cpu, __ATOMIC_SEQ_CST);
        if (t != self && c)
            appine_cpu_kick(c);
    }
    while (others_running(d, self)) {
        unlock_dbt(d);
        sched_yield();
        lock_dbt(d, &self->stats);
    }
    dbt_flush_locked(d);
    __atomic_store_n(&d->flushing, false, __ATOMIC_SEQ_CST);
    pthread_cond_broadcast(&d->flushed);
}

/* The guest changed code in the page containing `addr` (ic ivau): invalidate the blocks in it
 * whose instruction words changed */
static void code_changed(struct appine_dbt_thread *t, const struct appine_cpu *c, uint64_t addr)
{
    lock_dbt(t->d, &t->stats);
    dbt_invalidate_locked(t->d, c->mmu, addr & ~(uint64_t)PAGE_MASK, APPINE_PAGE_SIZE);
    unlock_dbt(t->d);
}

/*
 * Whether modifying a conditional branch (B.cond, CBZ/CBNZ, TBZ/TBNZ) is safe under aarch64 CMODX:
 * conditional branches are not among the instructions CMODX allows to be modified concurrently
 * with execution.
 * - Shared blocks (tag == 0, LINK_SHARED) can be executed by every thread attached to d (including
 *   threads of other code-group members), so relinking requires being the sole attached thread on
 *   the entire instance.
 * - Private blocks (tag != 0, !LINK_SHARED) are only visible in d->table and linkable by threads
 *   with the same tag, so relinking only requires being the sole attached thread of t->tag.
 * Lock held.
 */
static bool can_relink_branch(const struct appine_dbt *d, const struct appine_dbt_thread *t,
                              bool shared)
{
    if (shared || !t->tag)
        return d->threads == t && !t->next;
    for (const struct appine_dbt_thread *o = d->threads; o; o = o->next)
        if (o != t && o->tag == t->tag)
            return false;
    return true;
}

/* Patch an already-translated link point; when branch_site is non-NULL the caller holds d->lock
 * with no concurrent reader of that branch (can_relink_branch), and icache sync finishes before
 * returning */
static void patch_existing_link(const struct appine_dbt *d, uint32_t *site, uint32_t *branch_site,
                                const uint32_t *target)
{
    uint32_t b = enc_b((intptr_t)target - (intptr_t)site);
    /* Read through the execution address; see relink_word */
    bool again = __atomic_load_n(site, __ATOMIC_RELAXED) == b;
    __atomic_store_n(rw(d, site), b, __ATOMIC_RELAXED);
    bool branch = branch_site && dbt_relink_word(d, branch_site, target);
    if (again || branch) {
        /* Already changed (yet this thread still executed the old instruction), or a non-CMODX
         * conditional branch was rewritten: do one full sync */
        struct syncs sync = {.n = 0};
        sync_add(&sync, site, site + 1);
        if (branch)
            sync_add(&sync, branch_site, branch_site + 1);
        dbt_sync_all(d, &sync);
    } else {
        dbt_publish_link(d, site);
    }
}

static enum appine_exit dbt_run(void *ctx, struct appine_cpu *c)
{
    struct appine_dbt_thread *t = ctx;
    struct appine_dbt *d = t->d;
    uint64_t (*enter)(struct appine_cpu *, uint32_t *) =
        (uint64_t(*)(struct appine_cpu *, uint32_t *))(uintptr_t)d->enter;
    uint32_t *patch_site = NULL, *patch_branch_site = NULL;
    uint64_t patch_generation = 0;
    bool patch_forward = false, patch_shared = false;
    bool fill_jump_cache = false;

    if (UNLIKELY(d->stale)) {
        lock_dbt(d, &t->stats);
        if (d->stale)
            dbt_recheck(d, c);
        unlock_dbt(d);
    }
    c->dbt_jump_cache = t->jc;
    c->dbt_tag = t->tag;
    t->jc_dirty = true; /* the lookup routine fills it */
    if (((uintptr_t)c->dbt_rs & ~(uintptr_t)((1u << RS_SHIFT) - 1)) != (uintptr_t)t->rs)
        c->dbt_rs = t->rs;
    for (;;) {
        /* Someone wants a full flush: stop along with the others, or do it ourselves */
        if (UNLIKELY(__atomic_load_n(&d->flushing, __ATOMIC_SEQ_CST) ||
                     __atomic_load_n(&d->flush_wanted, __ATOMIC_SEQ_CST))) {
            lock_dbt(d, &t->stats);
            if (d->flushing)
                park(d, t);
            else if (d->flush_wanted)
                flush_world(d, t);
            unlock_dbt(d);
            patch_site = NULL;
        }
        dbt_thread_catch_up(t);
        if (UNLIKELY(__atomic_load_n(&c->pending, __ATOMIC_RELAXED)) &&
            __atomic_exchange_n(&c->pending, 0, __ATOMIC_ACQUIRE)) {
            clear_exclusive(c);
            return APPINE_EXIT_KICK;
        }

        /* Tag of the found block: shared blocks do not link to private blocks (LINK_SHARED) */
        unsigned found;
        uint32_t *code = dbt_table_lookup(d, c, c->pc, &found);
        if (!code && __atomic_load_n(&d->page_parked[page_bucket(c->pc >> APPINE_PAGE_SHIFT)],
                                     __ATOMIC_RELAXED)) {
            lock_dbt(d, &t->stats);
            if (!__atomic_load_n(&d->flushing, __ATOMIC_RELAXED) && !d->flush_wanted) {
                code = dbt_table_find_for(d->table, c->pc, t->tag, &found);
                if (!code) {
                    dbt_revive(d, c, c->pc);
                    code = dbt_table_find_for(d->table, c->pc, t->tag, &found);
                }
            }
            unlock_dbt(d);
        }
        if (!code) {
            /* Translate without the lock, install with it */
            bool fetched = prepare(t, c, c->pc);
            lock_dbt(d, &t->stats);
            if (__atomic_load_n(&d->flushing, __ATOMIC_RELAXED) || d->flush_wanted) {
                unlock_dbt(d);
                continue;
            }
            struct syncs sync = {.n = 0};
            struct fresh f = {.code = NULL};
            /* When this is the only thread, sync the new block and the link point together once;
             * otherwise sync the new block first and put it in the table, only after which other
             * threads can jump there */
            bool alone = d->threads == t && !t->next;
            /* Another thread may have just installed the same block */
            code = dbt_table_find_for(d->table, c->pc, t->tag, &found);
            if (!code && fetched) {
                code = install(d, t->prep, &sync, &f);
                found = t->prep->tag;
                if (code == NEED_FLUSH) {
                    flush_world(d, t);
                    unlock_dbt(d);
                    patch_site = NULL;
                    continue;
                }
                if (code == STALE) {
                    unlock_dbt(d);
                    continue;
                }
                if (!alone) {
                    dbt_sync_all(d, &sync);
                    dbt_table_insert(d, f.pc, f.tag, f.code, f.guest, f.nguest);
                }
            }
            /* While the lock is held the table has only live blocks: the patch target is never an
             * invalidated block (whose entry jumps to itself) */
            uint32_t *target = code && patch_forward ? code + ENTRY_CHECK_WORDS : code;
            if (code && patch_site && patch_generation == d->generation && target != patch_site &&
                !(patch_shared && found)) {
                *rw(d, patch_site) = enc_b((intptr_t)target - (intptr_t)patch_site);
                /* Conditional branches are not among the instructions CMODX allows to be modified
                 * concurrently: only relink when no other thread can execute this block, and finish
                 * icache sync before unlocking so no newly attached thread can fetch it
                 * concurrently */
                bool branch = patch_branch_site && can_relink_branch(d, t, patch_shared) &&
                              dbt_relink_word(d, patch_branch_site, target);
                if (sync.n || branch) {
                    sync_add(&sync, patch_site, patch_site + 1);
                    if (branch)
                        sync_add(&sync, patch_branch_site, patch_branch_site + 1);
                } else {
                    dbt_publish_link(d, patch_site);
                }
            }
            dbt_sync_all(d, &sync);
            if (f.code && alone)
                dbt_table_insert(d, f.pc, f.tag, f.code, f.guest, f.nguest);
            unlock_dbt(d);
            patch_site = NULL;
        } else if (patch_site) {
            /*
             * The target is already translated: patch the link without the lock. Changing a b
             * into a b may be done concurrently; a full flush waits for this thread to stop, so
             * it cannot happen at the same time. The lock-free lookup may have found a block that
             * was just invalidated. Linking to it is harmless, since its entry jumps to its
             * forwarding stub, which still exits to here; the case to avoid is the block whose
             * old entry is the patch site itself (its forwarding stub's exit brought us here),
             * where the patch would make the entry branch to itself (hence target != patch_site)
             */
            uint32_t *target = patch_forward ? code + ENTRY_CHECK_WORDS : code;
            if (patch_branch_site &&
                ((!patch_shared && t->tag) ||
                 __atomic_load_n(&d->nthreads, __ATOMIC_RELAXED) == 1)) {
                /* Conditional branches are not CMODX-safe: serialize against appine_dbt_attach
                 * under d->lock and finish icache sync before unlocking */
                lock_dbt(d, &t->stats);
                if (!__atomic_load_n(&d->flushing, __ATOMIC_RELAXED) &&
                    patch_generation == d->generation && target != patch_site &&
                    !(patch_shared && found)) {
                    bool relink = can_relink_branch(d, t, patch_shared);
                    patch_existing_link(d, patch_site, relink ? patch_branch_site : NULL, target);
                }
                unlock_dbt(d);
            } else if (patch_generation == __atomic_load_n(&d->generation, __ATOMIC_ACQUIRE) &&
                       target != patch_site && !(patch_shared && found)) {
                patch_existing_link(d, patch_site, NULL, target);
            }
            patch_site = NULL;
        }
        if (!code) { /* cannot fetch: let Tier 0 report the precise fault */
            enum appine_exit r = appine_interp_step(c);
            if (r != APPINE_EXIT_NONE)
                return r;
            continue;
        }
        if (fill_jump_cache) {
            t->jc[(c->pc >> 2) & (JC_SIZE - 1)] = (struct slot){c->pc, code};
            t->jc_dirty = true;
            fill_jump_cache = false;
        }

        uint64_t reason = enter(c, code);
        switch (reason & REASON_MASK) {
        case R_CHAIN:
        case R_CHAIN_FWD:
            t->stats.exits_chain++;
            patch_site = (uint32_t *)(uintptr_t)c->dbt_site;
            patch_branch_site = reason >> REASON_BITS & BRANCH_MASK
                                    ? patch_site - (reason >> REASON_BITS & BRANCH_MASK)
                                    : NULL;
            patch_shared = reason & LINK_SHARED;
            patch_generation = __atomic_load_n(&d->generation, __ATOMIC_RELAXED);
            patch_forward = (reason & REASON_MASK) == R_CHAIN_FWD;
            break;
        case R_LOOKUP:
            t->stats.exits_lookup++;
            fill_jump_cache = true;
            break;
        case R_UNGROUP:
            /* With watchpoints the refill always fails (emit_refill), which does not mean this
             * group of accesses cannot share a check */
            if (!c->nwatch) {
                lock_dbt(d, &t->stats);
                dbt_ungroup(d, c->pc);
                unlock_dbt(d);
            }
            /* fallthrough */
        case R_INTERP: {
            if ((reason & REASON_MASK) == R_INTERP && (!t->tag || in_shared(d, c->pc))) {
                uint32_t kind = find_memop(d, c->pc);
                if (kind && exec_memop(c, kind)) {
                    /* Pop the caller's predicted return if it matches X30, keeping the shadow
                     * return stack aligned after bypassing the guest RET. */
                    uint64_t *top = (uint64_t *)c->dbt_rs;
                    if (top && top[0] == c->x[30]) {
                        uintptr_t p = (uintptr_t)top;
                        uintptr_t mask = (1u << RS_SHIFT) - 1;
                        c->dbt_rs = (void *)((p & ~mask) | ((p - 16) & mask));
                    }
                    c->pc = c->x[30];
                    break;
                }
            }
            t->stats.exits_interp++;
            enum appine_exit r = appine_interp_step(c);
            /*
             * When Tier 0 executes ic ivau on a second page, invalidate both pages. The
             * translations are shared, so invalidating once in place by content is enough, without
             * exiting to the caller. The invalidated blocks' entries jump to the forwarding
             * stubs, and other threads see that the next time they enter them (on hardware they
             * may likewise still execute old instructions before a context synchronization).
             * HotSpot does an ic ivau and a dsb for every code change, 80,000 times per Maven
             * build, and exiting for each one would take the BKL and log the change before coming
             * back to invalidate
             */
            if (r == APPINE_EXIT_CODE)
                code_changed(t, c, c->fault_addr);
            else if (r != APPINE_EXIT_NONE)
                return r;
            if (LIKELY(!c->ivau_page))
                break;
        }
        /* fallthrough */
        case R_CODE:
            code_changed(t, c, c->ivau_page);
            c->ivau_page = 0;
            break;
        case R_SVC:
            t->stats.exits_svc++;
            c->exit_info = 0;
            clear_exclusive(c);
            return APPINE_EXIT_SVC;
        default:
            t->stats.exits_kick++;
            break;
        }
    }
}

enum appine_exit appine_dbt_run(struct appine_dbt_thread *t, struct appine_cpu *c)
{
    struct appine_dbt *d = t->d;
    /* A host fault poisoned this instance: the remaining threads run in Tier 0 until the process
     * is killed */
    if (UNLIKELY(d->poisoned))
        return appine_cpu_run(c);
    appine_sync_dit(c);
    /* Register the cpu first, then look at flushing (see flush_world) */
    __atomic_store_n(&t->cpu, c, __ATOMIC_SEQ_CST);
    enum appine_exit r = appine_guard_run(dbt_run, t, c);
    if (UNLIKELY(r == APPINE_EXIT_HOST_FAULT)) {
        /* The guard has already released the locks held. Threads stopped waiting for a flush
         * must not wait forever */
        pthread_mutex_lock(&d->lock);
        d->poisoned = true;
        __atomic_store_n(&d->flushing, false, __ATOMIC_SEQ_CST);
        pthread_cond_broadcast(&d->flushed);
        pthread_mutex_unlock(&d->lock);
        dbt_template_clear(false);
    }
    __atomic_store_n(&t->cpu, NULL, __ATOMIC_RELEASE);
    return r;
}

void appine_dbt_get_stats(const struct appine_dbt_thread *t, struct appine_dbt_stats *out)
{
    *out = t->stats;
}


#else /* !DBT_SUPPORTED */

struct appine_dbt *appine_dbt_new(uint64_t key, enum appine_dbt_regs regs)
{
    (void)key;
    (void)regs;
    return NULL;
}

void appine_dbt_free(struct appine_dbt *d, uint64_t key)
{
    (void)d;
    (void)key;
}

void appine_dbt_trim(void)
{
}

void appine_dbt_unmap_written(void)
{
}

uint64_t appine_dbt_written_bytes(void)
{
    return 0;
}

void appine_dbt_set_sources(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    (void)d;
    (void)s;
    (void)n;
}

void appine_dbt_set_memops(struct appine_dbt *d, const struct appine_dbt_memop *ops, size_t n)
{
    (void)d;
    (void)ops;
    (void)n;
}

void appine_dbt_trust(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    (void)d;
    (void)s;
    (void)n;
}

void appine_dbt_retire_outside(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    (void)d;
    (void)s;
    (void)n;
}

unsigned appine_dbt_new_tag(struct appine_dbt *d)
{
    (void)d;
    return 0;
}

void appine_dbt_share(struct appine_dbt *d, const struct appine_dbt_source *s, size_t n)
{
    (void)d;
    (void)s;
    (void)n;
}

struct appine_dbt_thread *appine_dbt_attach(struct appine_dbt *d, unsigned tag)
{
    (void)d;
    (void)tag;
    return NULL;
}

void appine_dbt_detach(struct appine_dbt_thread *t)
{
    (void)t;
}

void appine_dbt_flush(struct appine_dbt_thread *t)
{
    (void)t;
}

void appine_dbt_invalidate(struct appine_dbt_thread *t, const struct appine_cpu *cpu, uint64_t start,
                           uint64_t len)
{
    (void)t;
    (void)cpu;
    (void)start;
    (void)len;
}

enum appine_exit appine_dbt_run(struct appine_dbt_thread *t, struct appine_cpu *c)
{
    (void)t;
    return appine_cpu_run(c);
}

void appine_dbt_get_stats(const struct appine_dbt_thread *t, struct appine_dbt_stats *out)
{
    (void)t;
    memset(out, 0, sizeof(*out));
}

#endif
