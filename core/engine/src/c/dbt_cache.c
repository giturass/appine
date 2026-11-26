/*
 * Tier 1 code-cache management: W^X written-page tracking and cache sync, lock-free translation
 * table, block linking, retirement, content-based invalidation, recheck/revive, and the
 * process-global translation template arena.
 */
#define _GNU_SOURCE
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

static inline bool block_cross_page(uint64_t pc, uint32_t nguest)
{
    return nguest > 0 && ((pc + 4ull * nguest - 1) >> APPINE_PAGE_SHIFT) != (pc >> APPINE_PAGE_SHIFT);
}

/* Host page size (4K, 16K): madvise ranges must be aligned to it */
size_t dbt_host_page_size(void)
{
    static size_t cached;
    size_t page = __atomic_load_n(&cached, __ATOMIC_RELAXED);
    if (!page) {
        page = (size_t)sysconf(_SC_PAGESIZE);
        __atomic_store_n(&cached, page, __ATOMIC_RELAXED);
    }
    return page;
}


/* Drop the pages recorded in the writable view */
void dbt_drop_written(const struct appine_dbt *d)
{
    struct written *w = d->written;
    if (!w || !__atomic_load_n(&w->pages, __ATOMIC_RELAXED) ||
        __atomic_exchange_n(&w->dropping, true, __ATOMIC_ACQUIRE))
        return;
    size_t lo = SIZE_MAX, hi = 0;
    unsigned n = 0;
    for (size_t i = 0; i < sizeof(w->bits) / sizeof(w->bits[0]); i++) {
        uint64_t bits = __atomic_exchange_n(&w->bits[i], 0, __ATOMIC_RELAXED);
        if (!bits)
            continue;
        n += (unsigned)__builtin_popcountll(bits);
        if (lo == SIZE_MAX)
            lo = i * 64 + (size_t)__builtin_ctzll(bits);
        hi = i * 64 + 63 - (size_t)__builtin_clzll(bits);
    }
    if (n) {
        __atomic_sub_fetch(&w->pages, n, __ATOMIC_RELAXED);
        size_t page = dbt_host_page_size();
        madvise((char *)rw(d, d->cache) + lo * page, (hi - lo + 1) * page, MADV_DONTNEED);
    }
    __atomic_store_n(&w->dropping, false, __ATOMIC_RELEASE);
}

/* [start, end) (execution addresses) was written through the writable view */
static void note_written(const struct appine_dbt *d, const void *start, const void *end)
{
    struct written *w = d->written;
    if (!w || start == end)
        return;
    size_t page = dbt_host_page_size();
    size_t first = ((uintptr_t)start - (uintptr_t)d->cache) / page;
    size_t last = ((uintptr_t)end - 1 - (uintptr_t)d->cache) / page;
    for (size_t p = first; p <= last; p++) {
        uint64_t bit = UINT64_C(1) << (p & 63);
        if (!(__atomic_load_n(&w->bits[p / 64], __ATOMIC_RELAXED) & bit) &&
            !(__atomic_fetch_or(&w->bits[p / 64], bit, __ATOMIC_RELAXED) & bit))
            __atomic_add_fetch(&w->pages, 1, __ATOMIC_RELAXED);
    }
}

/* Make instruction fetch see several pieces of code after they are written */
static void sync_written(const struct appine_dbt *d, void *const *start, void *const *end, unsigned n)
{
    sync_code_ranges(start, end, n, d->rw_delta);
    for (unsigned i = 0; i < n; i++)
        note_written(d, start[i], end[i]);
}

/* Make instruction fetch see the new code after [start, end) is written */
void dbt_sync_range(const struct appine_dbt *d, const uint32_t *start, const uint32_t *end)
{
    void *s = (void *)start, *e = (void *)end;
    sync_written(d, &s, &e, 1);
}

/*
 * Do not wait for a rewritten link point to take effect: the rewriting thread goes on directly
 * into the target block and does not need the new instruction; other threads (and this one later)
 * execute the old instruction until they see the new one, jump to the exit routine, and the
 * dispatcher finds the target block just the same, with the same result. Cache maintenance is
 * still done and the new instruction is seen sooner or later, only without waiting for the dsb or
 * doing an isb: at java startup each block is linked once or twice, and a full sync each time
 * waits for the invalidation broadcast to complete, which took a fifth of the startup time.
 */
void dbt_publish_link(const struct appine_dbt *d, uint32_t *site)
{
    publish_code_lazily(site, site + 1, d->rw_delta);
    note_written(d, site, site + 1);
}


void dbt_sync_all(const struct appine_dbt *d, struct syncs *s)
{
    if (s->n)
        sync_written(d, s->start, s->end, s->n);
    s->n = 0;
}


/* ---- Translation table and code cache ---- */

/* Point a conditional branch directly at the target block; if that is out of its offset range,
 * leave it unchanged (it still goes through the stub) and return false.
 * Does not sync the instruction cache */
bool dbt_relink_word(const struct appine_dbt *d, uint32_t *site, const uint32_t *target)
{
    /* Read through the execution address: a read fault on the writable alias makes the host also
     * map a dozen or so nearby pages (fault-around), which are not recorded in struct written */
    uint32_t insn = *site;
    bool test = (insn & 0x7e000000) == 0x36000000; /* TBZ/TBNZ: 14-bit offset, others 19 bits */
    intptr_t off = target - site, limit = (intptr_t)1 << (test ? 13 : 18);
    if (off < -limit || off >= limit)
        return false;
    uint32_t mask = (test ? 0x3fffu : 0x7ffffu) << 5;
    *rw(d, site) = (insn & ~mask) | (((uint32_t)off << 5) & mask);
    return true;
}

/*
 * The instance and its tables are allocated with mmap, which guarantees zeroed pages committed on
 * demand: one instance per address space, one jump cache per thread, and the tables are allocated
 * at their largest size, with most pages never touched. calloc does not necessarily do this (glibc
 * raises the mmap threshold after a block of the same size has been freed, and then allocates from
 * the heap and zeroes byte by byte).
 */
void *dbt_zalloc(size_t bytes)
{
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* Return the first `bytes` bytes of memory from zalloc to the host; later reads see 0 */
void dbt_release_pages(void *p, size_t bytes)
{
    size_t page = dbt_host_page_size();
    if (bytes)
        madvise(p, (bytes + page - 1) & ~(page - 1), MADV_DONTNEED);
}

void dbt_zfree(void *p, size_t bytes)
{
    if (p)
        munmap(p, bytes);
}


/* Index of a key: a tagged key is hashed by its pc, in the same probe sequence as the shared block
 * of the same pc (TAG_SHIFT) */
static size_t table_index(const struct table *t, uint64_t key)
{
    return (size_t)((((key & PC_MASK) >> 2) * GOLDEN) >> t->shift);
}

static size_t table_mask(const struct table *t)
{
    return (size_t)t->mask;
}

/* Allocate an empty table of 2^bits entries */
struct table *dbt_table_new(unsigned bits)
{
    struct table *t = dbt_zalloc(TABLE_BYTES(bits));
    if (t) {
        t->bits = bits;
        t->shift = 64 - bits;
        t->mask = (UINT64_C(1) << bits) - 1;
    }
    return t;
}

/*
 * Find in t the block executed at pc by the member with tag `tag` (0 when not in a group): a
 * shared one or one private to it (TAG_SHIFT), with `*found` set to the found block's tag; when
 * both exist (private blocks translated before the registered range grew), either is correct.
 * Called directly while holding the lock; without the lock, through table_lookup. Misaligned pcs
 * and pcs beyond 48 bits have no blocks (Tier 0 reports the fault), and must not be compared with
 * the tombstones' JC_EMPTY or other members' keys either
 */
uint32_t *dbt_table_find_for(const struct table *t, uint64_t pc, unsigned tag, unsigned *found)
{
    *found = 0;
    if (pc & (3 | ~PC_MASK))
        return NULL;
    uint64_t mine = tagged(pc, tag);
    for (size_t i = table_index(t, pc);; i = (i + 1) & table_mask(t)) {
        /* Insertion writes the key before code: once code reads non-NULL, the key is the matching
         * one */
        uint32_t *code = __atomic_load_n(&t->slots[i].code, __ATOMIC_ACQUIRE);
        if (!code)
            return NULL;
        uint64_t key = __atomic_load_n(&t->slots[i].pc, __ATOMIC_RELAXED);
        if (key == pc || key == mine) {
            *found = key == pc ? 0 : tag;
            return code;
        }
    }
}

/*
 * The dispatcher and the lookup routine (emit_lookup) look up the table without the lock: while
 * the cpu's dbt_lookup_seq is odd, a replaced old table is not freed (table_publish)
 */
uint32_t *dbt_table_lookup(struct appine_dbt *d, struct appine_cpu *c, uint64_t pc, unsigned *found)
{
    __atomic_store_n(&c->dbt_lookup_seq, c->dbt_lookup_seq + 1, __ATOMIC_SEQ_CST);
    uint32_t *code = dbt_table_find_for(__atomic_load_n(&d->table, __ATOMIC_SEQ_CST), pc, c->dbt_tag, found);
    __atomic_store_n(&c->dbt_lookup_seq, c->dbt_lookup_seq + 1, __ATOMIC_RELEASE);
    return code;
}

/* Install the new table, and free the old one once the threads looking it up have finished. Lock
 * held */
static void table_publish(struct appine_dbt *d, struct table *table)
{
    struct table *old = d->table;
    __atomic_store_n(&d->table, table, __ATOMIC_SEQ_CST);
    /* Threads not in dbt_run do not look up the table; those entering later register their cpu
     * before reading table, so they read the new table */
    for (struct appine_dbt_thread *t = d->threads; t; t = t->next) {
        struct appine_cpu *c = __atomic_load_n(&t->cpu, __ATOMIC_SEQ_CST);
        if (!c)
            continue;
        unsigned seq = __atomic_load_n(&c->dbt_lookup_seq, __ATOMIC_SEQ_CST);
        while ((seq & 1) && __atomic_load_n(&c->dbt_lookup_seq, __ATOMIC_ACQUIRE) == seq)
            __asm__ volatile("yield");
    }
    dbt_zfree(old, TABLE_BYTES(old->bits));
}

/*
 * A block just built whose instruction cache is not synced yet (start pc `pc`; a private block
 * belongs to member `tag`): exits whose target is already translated are linked directly, the
 * same as the linking the dispatcher does the first time an exit is taken (R_CHAIN in dbt_run).
 * Shared blocks only link to shared blocks (TAG_SHIFT). The changes are synced together with the
 * whole block. Lock held
 */
void dbt_link_block(const struct appine_dbt *d, uint32_t *code, uint64_t pc, unsigned tag,
                       const struct link *links, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        const struct link *l = &links[i];
        unsigned found;
        uint32_t *target = l->pc == pc ? code : dbt_table_find_for(d->table, l->pc, tag, &found);
        if (!target)
            continue;
        if (l->stub & LINK_FWD)
            target += ENTRY_CHECK_WORDS;
        uint32_t *site = code + (l->stub & ~LINK_FWD);
        *rw(d, site) = enc_b((intptr_t)target - (intptr_t)site);
        if (l->branch != NO_BRANCH)
            dbt_relink_word(d, code + l->branch, target);
    }
}


/* Put the live blocks into a new table of 2^bits entries in their original insertion order,
 * leaving out invalidated blocks (tombstones), with table_used and blocks keeping matching
 * indices; returns false if allocation fails, leaving the original table unchanged. Lock held */
static void table_rebuild(struct appine_dbt *d, struct table *table);

bool dbt_table_resize(struct appine_dbt *d, unsigned bits)
{
    struct table *table = dbt_table_new(bits);
    if (!table)
        return false;
    table_rebuild(d, table);
    return true;
}

/* Fill the newly allocated table from blocks and install it (table_resize) */
static void table_rebuild(struct appine_dbt *d, struct table *table)
{
    size_t occupied = 0;
    for (size_t k = 0; k < d->table_count; k++) {
        const struct block *b = &d->blocks[k];
        if (!b->code || b->parked) {
            d->table_used[k] = SLOT_NONE;
            continue;
        }
        size_t i = table_index(table, block_key(b));
        while (table->slots[i].code)
            i = (i + 1) & table_mask(table);
        table->slots[i] = (struct slot){block_key(b), b->code};
        d->table_used[k] = (uint32_t)i;
        occupied++;
    }
    d->table_occupied = occupied;
    d->table_dead = 0;
    table_publish(d, table);
}

/* Insert only when pc is not in the table (a private block belongs to member `tag`), using only
 * empty slots (see struct table). Lock held */
void dbt_table_insert(struct appine_dbt *d, uint64_t pc, unsigned tag, uint32_t *code,
                         const uint32_t *guest, uint32_t nguest)
{
    struct table *t = d->table;
    size_t i = table_index(t, tagged(pc, tag));
    while (t->slots[i].code)
        i = (i + 1) & table_mask(t);
    d->table_occupied++;
    __atomic_store_n(&t->slots[i].pc, tagged(pc, tag), __ATOMIC_RELAXED);
    __atomic_store_n(&t->slots[i].code, code, __ATOMIC_RELEASE);
    unsigned h = page_bucket(pc >> APPINE_PAGE_SHIFT);
    /* If a parked block for the same key was left behind when dbt_revive stopped early at high
     * table load, retire it now so a later revive cannot insert a duplicate key */
    if (UNLIKELY(d->page_parked[h])) {
        for (uint32_t j = d->page_head[h]; j; j = d->blocks[j - 1].next) {
            struct block *old = &d->blocks[j - 1];
            if (old->parked && old->pc == pc && old->tag == tag)
                dbt_kill_parked(d, old);
        }
    }
    memcpy(d->words + d->words_used, guest, nguest * 4);
    d->blocks[d->table_count] =
        (struct block){pc, code, d->page_head[h], (uint32_t)d->words_used, nguest, 0, (uint16_t)tag, 0};
    d->words_used += nguest;
    if (block_cross_page(pc, nguest))
        d->cross_page_blocks++;
    d->table_used[d->table_count++] = (uint32_t)i;
    d->page_head[h] = (uint32_t)d->table_count;
}

/*
 * Remove the block with key `key` from the translation table, leaving a tombstone that never
 * hits. Old entries in the threads' jump caches need not be removed: they point to the
 * invalidated block's entry, which jumps to the forwarding stub. Lock held
 */
void dbt_table_remove(struct appine_dbt *d, uint64_t key)
{
    struct table *t = d->table;
    for (size_t i = table_index(t, key); t->slots[i].code; i = (i + 1) & table_mask(t)) {
        if (t->slots[i].pc == key) {
            __atomic_store_n(&t->slots[i].pc, JC_EMPTY, __ATOMIC_RELEASE);
            d->table_dead++;
            break;
        }
    }
}

/*
 * The pc of jump-cache entry i when it is empty: misaligned, and the index computed from it is
 * not i, so wherever the guest jumps it never hits an empty entry (translated code jumps straight
 * to code on a hit, and an empty entry's code is NULL). If they all used the same misaligned
 * value, a jump to that address would hit the entry at its index
 */
static uint64_t jc_empty(unsigned i)
{
    return (uint64_t)((i + 1) & (JC_SIZE - 1)) << 2 | 1;
}

void dbt_clear_jump_cache(struct appine_dbt_thread *t)
{
    for (unsigned i = 0; i < JC_SIZE; i++)
        t->jc[i] = (struct slot){jc_empty(i), NULL};
    t->jc_dirty = false;
}

/* Replace the whole shadow return stack with empty entries: the code holding the landing pads is
 * about to be overwritten */
void dbt_rs_reset(struct appine_dbt_thread *t)
{
    for (unsigned i = 0; i < RS_ENTRIES; i++) {
        t->rs[i][0] = 1; /* misaligned, never a RET target; if matched, rs_miss still looks up */
        t->rs[i][1] = (uint64_t)(uintptr_t)t->d->rs_miss;
    }
}

/* The code cache has been fully flushed (generation changed): the thread's own jump cache and
 * shadow return stack point to old code */
void dbt_thread_catch_up(struct appine_dbt_thread *t)
{
    uint64_t g = __atomic_load_n(&t->d->generation, __ATOMIC_ACQUIRE);
    if (t->generation != g) {
        t->generation = g;
        dbt_rs_reset(t);
        if (t->jc_dirty)
            dbt_clear_jump_cache(t);
    }
}

/*
 * blocks is full, but mostly with invalidated blocks (a JIT repeatedly rewriting and
 * retranslating the same code): remove their records, then rebuild the translation table at the
 * same size to remove the tombstones, with no full flush needed. The invalidated blocks' code stays
 * in the code cache, and their entries still jump to the forwarding stubs. Lock held; returns
 * false if allocating the new table fails
 */
bool dbt_compact_blocks(struct appine_dbt *d)
{
    struct table *table = dbt_table_new(d->table->bits);
    if (!table)
        return false;
    size_t n = 0, words = 0, cross = 0;
    memset(d->page_head, 0, sizeof(*d->page_head) << PAGE_BUCKET_BITS);
    for (size_t k = 0; k < d->table_count; k++) {
        struct block b = d->blocks[k];
        if (!b.code)
            continue;
        memmove(d->words + words, d->words + b.words, b.nguest * 4);
        b.words = (uint32_t)words;
        words += b.nguest;
        if (block_cross_page(b.pc, b.nguest))
            cross++;
        unsigned h = page_bucket(b.pc >> APPINE_PAGE_SHIFT);
        b.next = d->page_head[h];
        d->blocks[n++] = b;
        d->page_head[h] = (uint32_t)n;
    }
    d->table_count = n;
    d->words_used = words;
    d->cross_page_blocks = cross;
    d->blocks_dead = 0;
    table_rebuild(d, table);
    return true;
}

/*
 * Discard all translations. Lock held, and no other thread is in translated code or looking up
 * the table without the lock: they have all stopped in the dispatcher, or are not in dbt_run
 * (flush_world).
 */
void dbt_flush_locked(struct appine_dbt *d)
{
    if (d->used_words > d->high_words)
        d->high_words = d->used_words;
    struct table *t = d->table;
    for (size_t i = 0; i < d->table_count; i++) {
        if (d->table_used[i] != SLOT_NONE)
            t->slots[d->table_used[i]] = (struct slot){0, NULL};
        d->page_head[page_bucket(d->blocks[i].pc >> APPINE_PAGE_SHIFT)] = 0;
        d->page_parked[page_bucket(d->blocks[i].pc >> APPINE_PAGE_SHIFT)] = 0;
    }
    d->table_count = d->table_occupied = d->table_dead = d->blocks_dead = d->nparked = 0;
    d->words_used = 0;
    d->cross_page_blocks = 0;
    d->stale = false;
    d->nsources = d->ntrusted = d->nparkable = 0;
    d->flush_wanted = false;
    d->used_words = d->routine_words;
    __atomic_store_n(&d->generation, d->generation + 1, __ATOMIC_RELEASE);
    d->st->flushes++;
}

/*
 * Keep invalidated blocks from being executed: the entry (two places, before and after the kick
 * check) is changed to jump to a forwarding stub. The forwarding stub exits with R_CHAIN and the
 * old entry as the patch site, so after retranslation the old entry jumps directly to the new
 * block, and branches of other blocks linked to the old entry need not be found and rewritten.
 * Another thread may be executing this block: it still runs to the end of the block, just as on
 * hardware another core may still execute old instructions before a context synchronization.
 *
 * The forwarding stubs must be synced before the entries can jump to them, and every sync waits
 * for the instruction cache's invalidation broadcast to complete, so blocks are done in batches:
 * retire_add writes the forwarding stub, and retire_flush syncs all forwarding stubs, changes all
 * entries, then syncs once more.
 * Lock held
 */

void dbt_retire_flush(struct appine_dbt *d, struct retire_batch *r)
{
    if (!r->n)
        return;
    void *start[RETIRE_BATCH], *end[RETIRE_BATCH];
    start[0] = r->fwd_start;
    end[0] = d->cache + d->used_words;
    sync_written(d, start, end, 1);
    uint32_t *fwd = r->fwd_start;
    for (unsigned i = 0; i < r->n; i++) {
        uint32_t *code = r->blocks[i]->code;
        if (r->park[i])
            r->blocks[i]->first = code[ENTRY_CHECK_WORDS];
        *rw(d, code) = enc_b((intptr_t)fwd - (intptr_t)code);
        *rw(d, code + ENTRY_CHECK_WORDS) = enc_b(-ENTRY_CHECK_WORDS * 4);
        start[i] = code;
        end[i] = code + ENTRY_CHECK_WORDS + 1;
        fwd += 16;
    }
    sync_written(d, start, end, r->n);
    for (unsigned i = 0; i < r->n; i++) {
        struct block *b = r->blocks[i];
        dbt_table_remove(d, block_key(b));
        if (r->park[i]) {
            b->parked = 1;
            d->nparked++;
            d->page_parked[page_bucket(b->pc >> APPINE_PAGE_SHIFT)]++;
            continue;
        }
        b->code = NULL;
        d->blocks_dead++;
        d->st->invalidated++;
    }
    r->n = 0;
}

/* Invalidate a parked block: its entry already jumps to the forwarding stub */
void dbt_kill_parked(struct appine_dbt *d, struct block *b)
{
    b->parked = 0;
    b->code = NULL;
    d->nparked--;
    d->page_parked[page_bucket(b->pc >> APPINE_PAGE_SHIFT)]--;
    d->blocks_dead++;
    d->st->invalidated++;
}

/* Invalidate b: write its forwarding stub first (16 words each), and leave the entry for
 * retire_flush to change together with the others. With `park` it is only parked (revive).
 * Returns false if the code cache has no room for the forwarding stub */
bool dbt_retire_add(struct appine_dbt *d, struct retire_batch *r, struct block *b, bool park)
{
    if (r->n == RETIRE_BATCH)
        dbt_retire_flush(d, r);
    if (d->used_words + 16 > d->cache_words)
        return false;
    struct xlate fwd = {.d = d, .buf = d->cache + d->used_words, .wdelta = d->rw_delta, .st = d->st},
                 *x = &fwd;
    emit_mov_const(x, T1, (uint64_t)(uintptr_t)b->code);
    emit_mov_const(x, T0, b->pc);
    emit(x, enc_movz(T2, R_CHAIN | (b->tag ? 0 : LINK_SHARED), 0));
    emit(x, enc_b((intptr_t)d->exit - (intptr_t)here(x)));
    while (x->n < 16)
        emit(x, enc_b(4)); /* padding: forwarding stubs are laid out every 16 words */
    d->used_words += x->n;
    if (!r->n)
        r->fwd_start = x->buf;
    r->park[r->n] = park;
    r->blocks[r->n++] = b;
    return true;
}

static bool block_matches(const struct appine_dbt *d, const struct appine_mmu *mmu,
                          const struct block *b, uint64_t *page, const uint32_t **host);

/*
 * Invalidate the blocks that start in the pages covered by [start, start + len); if a forwarding
 * stub does not fit, request a full flush instead, done by the next thread to enter the
 * dispatcher. With `mmu`, only blocks whose guest instruction words differ from the current ones
 * are invalidated (a translation depends only on the pc and the instruction words; literals are
 * also read only at run time): a JIT rewriting one piece of code issues ic ivau for only a line or
 * two, while ic ivau is recorded per page, so blocks of other methods in the same page remain
 * usable. HotSpot keeps rewriting inline caches and method entries, and invalidating the whole
 * page each time would retranslate 310,000 blocks per Maven build. After an unmap or the removal
 * of exec permission the page has no executable mapping, and all its blocks are invalidated.
 * Parked blocks are left alone: they are checked anyway when revived. Without `mmu` every block
 * in the range is invalidated, parked ones included. Lock held
 */
void dbt_invalidate_locked(struct appine_dbt *d, const struct appine_mmu *mmu, uint64_t start,
                              uint64_t len)
{
    if (!len)
        return;
    uint64_t end = start + len - 1, first = start >> APPINE_PAGE_SHIFT, last = end >> APPINE_PAGE_SHIFT;
    if (end < start)
        last = UINT64_MAX >> APPINE_PAGE_SHIFT;
    /* A very large range (unmapping a library): look at every block in turn, which is cheaper
     * than a full flush, and other threads need not retranslate either. Blocks do not cross pages,
     * so compare page by page */
    struct retire_batch r = {.n = 0};
    uint64_t seen = 1; /* misaligned, never equal to any page */
    const uint32_t *host = NULL;
    if (end < start || last - first >= INVALIDATE_MAX_PAGES) {
        for (size_t i = 0; i < d->table_count; i++) {
            struct block *b = &d->blocks[i];
            if (!b->code)
                continue;
            uint64_t b_first = b->pc >> APPINE_PAGE_SHIFT;
            uint64_t b_last = (b->pc + 4ull * b->nguest - 1) >> APPINE_PAGE_SHIFT;
            if (b_last < first || b_first > last)
                continue;
            if (b->parked) {
                if (!mmu)
                    dbt_kill_parked(d, b);
            } else if (mmu && block_matches(d, mmu, b, &seen, &host)) {
                continue;
            } else if (!dbt_retire_add(d, &r, b, false)) {
                goto full;
            }
        }
        dbt_retire_flush(d, &r);
        return;
    }
    if (first > 0 && d->cross_page_blocks > 0) {
        uint64_t prev = first - 1;
        uint32_t *link = &d->page_head[page_bucket(prev)];
        while (*link) {
            struct block *b = &d->blocks[*link - 1];
            if (!b->code) {
                *link = b->next;
                continue;
            }
            link = &b->next;
            if (b->pc >> APPINE_PAGE_SHIFT != prev ||
                ((b->pc + 4ull * b->nguest - 1) >> APPINE_PAGE_SHIFT) < first)
                continue;
            if (b->parked) {
                if (!mmu)
                    dbt_kill_parked(d, b);
            } else if (mmu && block_matches(d, mmu, b, &seen, &host)) {
                continue;
            } else if (!dbt_retire_add(d, &r, b, false)) {
                goto full;
            }
        }
    }
    for (uint64_t page = first; page <= last; page++) {
        uint32_t *link = &d->page_head[page_bucket(page)];
        while (*link) {
            struct block *b = &d->blocks[*link - 1];
            /* A JIT may rewrite one block thousands of times between compactions. */
            if (!b->code) {
                *link = b->next;
                continue;
            }
            link = &b->next;
            if (b->pc >> APPINE_PAGE_SHIFT != page)
                continue;
            if (b->parked) {
                if (!mmu)
                    dbt_kill_parked(d, b);
            } else if (mmu && block_matches(d, mmu, b, &seen, &host)) {
                continue;
            } else if (!dbt_retire_add(d, &r, b, false)) {
                goto full;
            }
        }
    }
    dbt_retire_flush(d, &r);
    return;
full:
    dbt_retire_flush(d, &r);
    __atomic_store_n(&d->flush_wanted, true, __ATOMIC_SEQ_CST);
}

/*
 * Leader `pc` failed the shared check, and the dispatcher has Tier 0 execute the leader. The first
 * time it is only recorded: cases such as the stack not having grown that far yet are resolved
 * once the members' own accesses have run. The second time it goes into nogroup and the blocks
 * containing it are invalidated (blocks do not cross pages, so they are all in its page's
 * bucket), and on retranslation it is no longer grouped. Lock held
 */
void dbt_ungroup(struct appine_dbt *d, uint64_t pc)
{
    int empty = -1;
    for (unsigned i = 0; i < STRIKES; i++) {
        if (d->strikes[i] == pc) {
            d->strikes[i] = 0;
            goto ungroup;
        }
        if (empty < 0 && d->strikes[i] == 0)
            empty = (int)i;
    }
    unsigned slot = empty >= 0 ? (unsigned)empty : d->strikes_next++ % STRIKES;
    d->strikes[slot] = pc;
    return;
ungroup:
    d->nogroup[d->nogroup_count++ % NOGROUP_MAX] = pc;
    d->st->ungrouped++;
    uint64_t page = pc >> APPINE_PAGE_SHIFT;
    struct retire_batch r = {.n = 0};
    for (uint32_t i = d->page_head[page_bucket(page)]; i; i = d->blocks[i - 1].next) {
        struct block *b = &d->blocks[i - 1];
        if (!b->code || b->pc > pc || pc >= b->pc + 4ull * b->nguest)
            continue;
        if (b->parked) {
            dbt_kill_parked(d, b);
        } else if (!dbt_retire_add(d, &r, b, false)) {
            __atomic_store_n(&d->flush_wanted, true, __ATOMIC_SEQ_CST);
            break;
        }
    }
    dbt_retire_flush(d, &r);
}


/* Retire every live or parked block starting at `pc`. Returns false if the code cache has no room
 * for a forwarding stub. Lock held (or no threads attached). */
bool dbt_retire_pc(struct appine_dbt *d, struct retire_batch *r, uint64_t pc)
{
    uint64_t page = pc >> APPINE_PAGE_SHIFT;
    for (uint32_t i = d->page_head[page_bucket(page)]; i; i = d->blocks[i - 1].next) {
        struct block *b = &d->blocks[i - 1];
        if (!b->code || b->pc != pc)
            continue;
        if (b->parked) {
            dbt_kill_parked(d, b);
        } else if (!dbt_retire_add(d, r, b, false)) {
            return false;
        }
    }
    return true;
}


/* Whether a block's guest instruction words at translation equal those at the same address in
 * `mmu` now; `page`/`host` remember the page looked up last time */
static bool block_matches(const struct appine_dbt *d, const struct appine_mmu *mmu,
                          const struct block *b, uint64_t *page, const uint32_t **host)
{
    uint64_t p = b->pc & ~PAGE_MASK;
    unsigned off = (unsigned)((b->pc & PAGE_MASK) / 4);
    unsigned n0 = (unsigned)(APPINE_PAGE_SIZE / 4) - off;
    if (p != *page) {
        *page = p;
        *host = appine_mmu_translate(mmu, p, APPINE_PROT_EXEC);
    }
    if (!*host)
        return false;
    if (LIKELY(b->nguest <= n0))
        return memcmp(*host + off, d->words + b->words, b->nguest * 4) == 0;
    if (memcmp(*host + off, d->words + b->words, n0 * 4) != 0)
        return false;
    uint64_t p1 = p + APPINE_PAGE_SIZE;
    *page = p1;
    *host = appine_mmu_translate(mmu, p1, APPINE_PROT_EXEC);
    return *host && memcmp(*host, d->words + b->words + n0, (b->nguest - n0) * 4) == 0;
}

/* The block lies entirely within one of the previous user's file mappings (recorded by
 * appine_dbt_trust): while its page is not mapped yet it is worth parking, since the same content
 * will most likely be mapped back later; blocks in anonymous memory (JIT-generated code) will
 * most likely not match next time */
static bool block_parkable(const struct appine_dbt *d, const struct block *b)
{
    for (unsigned i = 0; i < d->nparkable; i++) {
        if (b->pc >= d->parkable[i][0] && b->pc + (uint64_t)b->nguest * 4 <= d->parkable[i][1])
            return true;
    }
    return false;
}

/* The block lies entirely within a range given by appine_dbt_trust */
static bool block_trusted(const struct appine_dbt *d, const struct block *b)
{
    for (unsigned i = 0; i < d->ntrusted; i++) {
        if (b->pc >= d->trusted[i][0] && b->pc + (uint64_t)b->nguest * 4 <= d->trusted[i][1])
            return true;
    }
    return false;
}

/*
 * After an instance changes address space and before its first run: check the guest instruction
 * words block by block and invalidate those that do not match. It is the same check as when
 * copying a translation template, only done all at once, saving the per-block copying, relinking
 * and instruction-cache syncing. When most do not match (another program was exec'd), request a
 * full flush. Lock held
 */
void dbt_recheck(struct appine_dbt *d, const struct appine_cpu *c)
{
    d->stale = false;
    size_t live = 0, bad = 0, unmapped = 0;
    uint64_t page = 1; /* misaligned, never equal to any page */
    const uint32_t *host = NULL;
    for (size_t i = 0; i < d->table_count; i++) {
        const struct block *b = &d->blocks[i];
        if (b->code && !b->parked) {
            live++;
            if (!block_trusted(d, b) && !block_matches(d, c->mmu, b, &page, &host)) {
                bool park = !host && !block_cross_page(b->pc, b->nguest) && block_parkable(d, b);
                bad += !park;
                unmapped += park;
            }
        }
    }
    if (bad * 2 > live) {
        d->ntrusted = d->nparkable = 0;
        d->flush_wanted = true;
        return;
    }
    /* Blocks whose page is not mapped yet (shared libraries wait for the dynamic linker to load
     * them; at this point there are only the program and the dynamic linker) are parked and
     * checked the first time they are executed (revive): previously they were all invalidated,
     * and every node startup copied six or seven thousand blocks from templates again */
    page = 1;
    struct retire_batch r = {.n = 0};
    for (size_t i = 0; (bad || unmapped) && i < d->table_count; i++) {
        struct block *b = &d->blocks[i];
        if (b->code && !b->parked && !block_trusted(d, b) &&
            !block_matches(d, c->mmu, b, &page, &host)) {
            bool park = !host && !block_cross_page(b->pc, b->nguest) && block_parkable(d, b);
            if (!dbt_retire_add(d, &r, b, park)) {
                d->flush_wanted = true;
                break;
            }
            if (park)
                unmapped--;
            else
                bad--;
        }
    }
    dbt_retire_flush(d, &r);
    d->ntrusted = d->nparkable = 0;
}

/*
 * Put a parked block back into the translation table (revive). If the tombstone left when it was
 * parked is still there (the table has not been rebuilt since), restore it in place: the code has
 * not changed, so a thread looking up the table without the lock is right whichever of the before
 * and after states it reads. If it were inserted into another empty slot, no record would point
 * to that tombstone any more, and after a full flush (flush_locked only clears the slots recorded
 * in table_used) it would still occupy its slot without being counted; with repeated parking,
 * reviving and flushing, the table would fill up, and neither insertion nor lookup would find an
 * empty slot. Lock held
 */
static bool table_has_key(const struct table *t, uint64_t key)
{
    for (size_t i = table_index(t, key); t->slots[i].code; i = (i + 1) & table_mask(t))
        if (t->slots[i].pc == key)
            return true;
    return false;
}

static void table_relink(struct appine_dbt *d, size_t k)
{
    struct table *t = d->table;
    const struct block *b = &d->blocks[k];
    size_t i = d->table_used[k];
    if (i != SLOT_NONE && t->slots[i].pc == JC_EMPTY && t->slots[i].code == b->code) {
        d->table_dead--;
        __atomic_store_n(&t->slots[i].pc, block_key(b), __ATOMIC_RELEASE);
        return;
    }
    i = table_index(t, block_key(b));
    while (t->slots[i].code)
        i = (i + 1) & table_mask(t);
    d->table_occupied++;
    __atomic_store_n(&t->slots[i].pc, block_key(b), __ATOMIC_RELAXED);
    __atomic_store_n(&t->slots[i].code, b->code, __ATOMIC_RELEASE);
    d->table_used[k] = (uint32_t)i;
}

/*
 * The dispatcher did not find pc, and its page has parked blocks (recheck): check the parked
 * blocks of the same page together; those whose guest instruction words match the current ones
 * get their entries restored and go back into the table, with no retranslation or template copy
 * needed; those that do not match are invalidated. A page at a time: each parked block exits here
 * through the forwarding stub the first time it is executed, and when reviving them one by one,
 * those exits alone would use up the time saved. Links to a parked block always jump to its
 * entry, which while parked exits here through the forwarding stub, so code that has not been
 * checked is never executed. When the table is too full nothing is revived, and the normal
 * translation path grows the table. Lock held
 */
/* Sync the revived batch first, then put it into the table; only then can other threads jump
 * there */
static void revive_flush(struct appine_dbt *d, const uint32_t *idx, unsigned n)
{
    if (!n)
        return;
    void *start[RETIRE_BATCH], *end[RETIRE_BATCH];
    for (unsigned k = 0; k < n; k++) {
        start[k] = d->blocks[idx[k]].code;
        end[k] = d->blocks[idx[k]].code + ENTRY_CHECK_WORDS + 1;
    }
    sync_written(d, start, end, n);
    for (unsigned k = 0; k < n; k++)
        table_relink(d, idx[k]);
}

void dbt_revive(struct appine_dbt *d, const struct appine_cpu *c, uint64_t pc)
{
    uint64_t page = pc >> APPINE_PAGE_SHIFT, p = 1;
    const uint32_t *host = NULL;
    uint32_t idx[RETIRE_BATCH];
    unsigned n = 0;
    /* The first instruction of the entry check is the same for every block (prepare), so it need
     * not be recorded separately */
    uint32_t check = enc_ldr_x(d->r->t0, d->r->ctx, offsetof(struct appine_cpu, pending));
    for (uint32_t i = d->page_head[page_bucket(page)]; i; i = d->blocks[i - 1].next) {
        struct block *b = &d->blocks[i - 1];
        if (!b->parked || b->pc >> APPINE_PAGE_SHIFT != page)
            continue;
        if (table_has_key(d->table, block_key(b))) {
            dbt_kill_parked(d, b);
            continue;
        }
        if (!block_matches(d, c->mmu, b, &p, &host)) {
            /* The page has no entry yet (large mappings fill entries on demand): keep it; when
             * the dispatcher cannot fetch the instruction, Tier 0 reports the page fault, and it
             * comes back after the kernel layer fills in the entry */
            if (!host)
                break;
            dbt_kill_parked(d, b);
            continue;
        }
        if (d->table_occupied + n >= ((size_t)3 << d->table->bits) / 4)
            break;
        if (n == RETIRE_BATCH) {
            revive_flush(d, idx, n);
            n = 0;
        }
        *rw(d, b->code) = check;
        *rw(d, b->code + ENTRY_CHECK_WORDS) = b->first;
        b->parked = 0;
        d->nparked--;
        d->page_parked[page_bucket(page)]--;
        idx[n++] = i - 1;
    }
    revive_flush(d, idx, n);
}


/* ---- Translation templates: shared by all instances (the engine/dbt map) ---- */

/*
 * A block's translation depends only on its guest pc and the instruction words it translated
 * (plus the global feature set and the instance's register assignment), not on the process or
 * the mappings. Every translated block is stored as a template; when another instance (that of
 * another address space: the threads of one address space, and the address spaces of one code
 * group, share one instance) translates the same pc, it first compares the instruction words
 * recorded in the template with those in its own memory, and if they match it copies the template
 * into its own code cache, recomputing only the few b instructions that jump to routines. Links
 * between blocks are patched in each copy, so different processes mapping different code at the
 * same address do not affect each other. When the template arena is full it is discarded
 * entirely, since instances only copy templates and never reference them.
 *
 * All threads of all processes use the templates, and with a single lock, workloads such as go
 * build that start compiler processes concurrently spent a tenth of their time on the lock, so
 * locking is sharded by bucket; allocating from the template arena uses another lock held only
 * briefly, and discarding everything holds all the locks (shards first, then allocation, the same
 * order as when storing a template).
 */
#define TEMPLATE_BYTES (UINT64_C(32) << 20)
#define TEMPLATE_BUCKET_BITS 16
#define TEMPLATE_SHARDS 64
/* The most versions kept for one pc: when a JIT repeatedly rewrites the same code, only the newest
 * few are kept */
#define TEMPLATES_PER_PC 4

struct template {
    struct template *next;
    uint64_t pc;
    uint64_t key; /* grouping records used during translation (nogroup_key) */
    const struct regs *r;
    bool shared; /* a shared block (its link stubs carry LINK_SHARED) */
    uint32_t nguest, nhost, nrelocs, nlinks;
    uint32_t copied, remapped, memory, fallback, grouped, fast_loops; /* statistics, added up when copied */
    /* Guest instruction words, host instruction words, relocations, links (4 words each, see
     * struct link) */
    uint32_t words[];
};

static struct {
    struct {
        pthread_mutex_t lock;
        char pad[64 - sizeof(pthread_mutex_t) % 64]; /* one cache line each */
    } shards[TEMPLATE_SHARDS]; /* shard i covers buckets whose index mod TEMPLATE_SHARDS is i */
    pthread_mutex_t arena_lock;
    uint8_t *arena; /* mapped on first use, cleared when full */
    size_t used;
    size_t high; /* furthest allocation since the last memory-pressure trim */
    bool full; /* full: cleared after the threads storing templates release their shard locks */
    struct template *buckets[1u << TEMPLATE_BUCKET_BITS];
} templates = {
    .shards = {[0 ... TEMPLATE_SHARDS - 1] = {.lock = PTHREAD_MUTEX_INITIALIZER}},
    .arena_lock = PTHREAD_MUTEX_INITIALIZER,
};

static unsigned template_index(uint64_t pc)
{
    return (unsigned)(((pc >> 2) * UINT64_C(0x9e3779b97f4a7c15)) >> (64 - TEMPLATE_BUCKET_BITS));
}

static struct template **template_bucket(uint64_t pc)
{
    return &templates.buckets[template_index(pc)];
}

/* The lock of pc's bucket, also registered with the guard */
static pthread_mutex_t *template_lock(uint64_t pc)
{
    pthread_mutex_t *lock = &templates.shards[template_index(pc) % TEMPLATE_SHARDS].lock;
    pthread_mutex_lock(lock);
    appine_guard_hold(lock, false);
    return lock;
}

static void template_unlock(pthread_mutex_t *lock)
{
    appine_guard_drop();
    pthread_mutex_unlock(lock);
}

/*
 * The grouping records that translating the block starting at pc uses (those recorded by ungroup
 * that affect leaders after pc in this page): if the instance's records differ, the translated
 * block may differ too, so translation templates are versioned by it. 0 if there are none.
 */
uint64_t dbt_nogroup_key(const struct appine_dbt *d, uint64_t pc)
{
    uint64_t key = 0, end = (pc | PAGE_MASK) + 1;
    unsigned n = d->nogroup_count < NOGROUP_MAX ? d->nogroup_count : NOGROUP_MAX;
    for (unsigned i = 0; i < n; i++) {
        uint64_t q = d->nogroup[i];
        if (q + NOGROUP_SPAN > pc && q < end)
            key += (q * UINT64_C(0x9e3779b97f4a7c15)) | 1;
    }
    return key;
}

/* The caller holds the lock of pc's shard */
static struct template *template_find(uint64_t pc, const uint32_t *guest, uint32_t nguest, uint64_t key,
                                      const struct regs *r, bool shared)
{
    for (struct template *t = *template_bucket(pc); t; t = t->next) {
        if (t->pc == pc && t->nguest == nguest && t->key == key && t->r == r && t->shared == shared &&
            memcmp(t->words, guest, t->nguest * 4) == 0)
            return t;
    }
    return NULL;
}

/* Same as template_find, extending the caller's snapshot in `words` lazily past 64 words only when
 * a longer template exists at `pc` (and into the next page when a cross-page fast-loop template
 * exists at `pc`). */
static struct template *template_find_fetch(uint64_t pc, const uint32_t *src, uint32_t *words,
                                            unsigned *copied, unsigned limit0,
                                            const struct appine_mmu *mmu, const struct appine_dbt *d,
                                            const uint32_t **guest1_out, uint64_t key,
                                            const struct regs *r, bool shared)
{
    const uint32_t *src1 = NULL;
    bool tried_src1 = false;
    for (struct template *t = *template_bucket(pc); t; t = t->next) {
        if (t->pc != pc || t->key != key || t->r != r || t->shared != shared ||
            t->nguest > MAX_BLOCK_INSNS)
            continue;
        if (t->nguest > limit0) {
            if (!tried_src1) {
                tried_src1 = true;
                uint64_t next_page = (pc & ~PAGE_MASK) + APPINE_PAGE_SIZE;
                if (next_page > pc && next_page < (UINT64_C(1) << APPINE_VA_BITS) &&
                    (!shared || !__atomic_load_n(&d->shared, __ATOMIC_ACQUIRE) ||
                     in_shared(d, next_page)))
                    src1 = appine_mmu_translate(mmu, next_page, APPINE_PROT_EXEC);
            }
            if (!src1)
                continue;
            if (*copied < limit0) {
                memcpy(words + *copied, src + *copied, (limit0 - *copied) * 4);
                *copied = limit0;
            }
            if (t->nguest > *copied) {
                memcpy(words + *copied, src1 + (*copied - limit0), (t->nguest - *copied) * 4);
                *copied = t->nguest;
            }
        } else if (t->nguest > *copied) {
            memcpy(words + *copied, src + *copied, (t->nguest - *copied) * 4);
            *copied = t->nguest;
        }
        if (memcmp(t->words, words, t->nguest * 4) == 0) {
            *guest1_out = t->nguest > limit0 ? src1 : NULL;
            return t;
        }
    }
    if (*copied > limit0)
        *copied = limit0;
    return NULL;
}


/* If there is a template matching `words` (lazily extended from `src` up to `limit0`, or into
 * page 1 for cross-page fast-loop templates), copy it into the thread's scratch area and record
 * it in p */
bool dbt_template_fetch(uint64_t pc, const uint32_t *src, uint32_t *words, unsigned *copied,
                           unsigned limit0, const struct appine_mmu *mmu, const struct appine_dbt *d,
                           uint64_t key, const struct regs *r, bool shared, struct prep *p,
                           uint32_t *scratch, struct appine_dbt_stats *st)
{
    pthread_mutex_t *lock = template_lock(pc);
    const uint32_t *guest1 = NULL;
    struct template *t =
        template_find_fetch(pc, src, words, copied, limit0, mmu, d, &guest1, key, r, shared);
    if (t) {
        const uint32_t *host = t->words + t->nguest, *relocs = host + t->nhost;
        memcpy(scratch, host, t->nhost * 4);
        memcpy(p->relocs, relocs, t->nrelocs * 4);
        p->guest1 = guest1;
        p->host = scratch;
        p->nhost = t->nhost;
        p->nrelocs = t->nrelocs;
        p->nguest = t->nguest;
        const uint32_t *l = relocs + t->nrelocs;
        for (uint32_t i = 0; i < t->nlinks; i++, l += 4)
            p->links[i] = (struct link){l[0], l[1], (uint64_t)l[3] << 32 | l[2]};
        p->nlinks = t->nlinks;
        st->insns += t->nguest;
        st->insns_copied += t->copied;
        st->insns_remapped += t->remapped;
        st->insns_memory += t->memory;
        st->insns_fallback += t->fallback;
        st->insns_grouped += t->grouped;
        st->fast_loops += t->fast_loops;
        st->blocks_shared++;
    }
    template_unlock(lock);
    return t != NULL;
}

/* Allocate `bytes` bytes from the template arena; when full, return NULL and mark it to be
 * cleared. The caller holds one of the shard locks */
static void *template_alloc(size_t bytes)
{
    void *p = NULL;
    pthread_mutex_lock(&templates.arena_lock);
    appine_guard_hold(&templates.arena_lock, false);
    if (!templates.arena) {
        void *m = mmap(NULL, TEMPLATE_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        templates.arena = m == MAP_FAILED ? NULL : m;
    }
    size_t used = __atomic_load_n(&templates.used, __ATOMIC_RELAXED);
    if (templates.arena && bytes <= TEMPLATE_BYTES - used) {
        p = templates.arena + used;
        used += bytes;
        __atomic_store_n(&templates.used, used, __ATOMIC_RELEASE);
        if (used > __atomic_load_n(&templates.high, __ATOMIC_RELAXED))
            __atomic_store_n(&templates.high, used, __ATOMIC_RELEASE);
    } else if (templates.arena) {
        __atomic_store_n(&templates.full, true, __ATOMIC_RELAXED);
    }
    appine_guard_drop();
    pthread_mutex_unlock(&templates.arena_lock);
    return p;
}

/* Release every template lock, as template_clear takes them (also after a host fault) */
static void template_unlock_all(void *unused)
{
    (void)unused;
    pthread_mutex_unlock(&templates.arena_lock);
    for (unsigned i = TEMPLATE_SHARDS; i-- > 0;)
        pthread_mutex_unlock(&templates.shards[i].lock);
}

static void template_lock_all(void)
{
    for (unsigned i = 0; i < TEMPLATE_SHARDS; i++)
        pthread_mutex_lock(&templates.shards[i].lock);
    pthread_mutex_lock(&templates.arena_lock);
    appine_guard_hold_fn(NULL, template_unlock_all);
}

/* All template locks held. Leave the pages resident for the next generation. */
static void template_reset(void)
{
    if (__atomic_load_n(&templates.used, __ATOMIC_RELAXED))
        memset(templates.buckets, 0, sizeof(templates.buckets));
    __atomic_store_n(&templates.used, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&templates.full, false, __ATOMIC_RELAXED);
}

/* Discard all translation templates after filling the arena or encountering a host fault. */
void dbt_template_clear(bool if_full)
{
    template_lock_all();
    if (!if_full || __atomic_load_n(&templates.full, __ATOMIC_RELAXED))
        template_reset();
    appine_guard_drop();
    template_unlock_all(NULL);
}

/* Called without the pool or instance lock. A previous reset may have rewound used while
 * leaving an entire generation resident. */
void dbt_template_trim(void)
{
    if (__atomic_load_n(&templates.used, __ATOMIC_ACQUIRE) == 0 &&
        __atomic_load_n(&templates.high, __ATOMIC_ACQUIRE) == 0)
        return;
    template_lock_all();
    template_reset();
    size_t high = __atomic_load_n(&templates.high, __ATOMIC_RELAXED);
    if (templates.arena && high) {
        dbt_release_pages(templates.arena, high);
        __atomic_store_n(&templates.high, 0, __ATOMIC_RELEASE);
    }
    appine_guard_drop();
    template_unlock_all(NULL);
}

/* Store a just-translated block whose links have not been patched yet as a template */
void dbt_template_store(uint64_t pc, const uint32_t *guest, uint32_t nguest, uint64_t key,
                           const struct xlate *x, const struct appine_dbt_stats *before,
                           const struct link *links, unsigned nlinks)
{
    const struct appine_dbt_stats *after = x->st;
    size_t bytes = sizeof(struct template) + 4 * (nguest + x->n + x->nrelocs + 4 * nlinks);
    bytes = (bytes + 7) & ~(size_t)7;
    pthread_mutex_t *lock = template_lock(pc);
    struct template *t =
        template_find(pc, guest, nguest, key, x->d->r, x->shared) ? NULL : template_alloc(bytes);
    if (t) {
        *t = (struct template){
            .pc = pc,
            .key = key,
            .r = x->d->r,
            .shared = x->shared,
            .nguest = nguest,
            .nhost = (uint32_t)x->n,
            .nrelocs = x->nrelocs,
            .nlinks = nlinks,
            .copied = (uint32_t)(after->insns_copied - before->insns_copied),
            .remapped = (uint32_t)(after->insns_remapped - before->insns_remapped),
            .memory = (uint32_t)(after->insns_memory - before->insns_memory),
            .fallback = (uint32_t)(after->insns_fallback - before->insns_fallback),
            .grouped = (uint32_t)(after->insns_grouped - before->insns_grouped),
            .fast_loops = (uint32_t)(after->fast_loops - before->fast_loops),
        };
        memcpy(t->words, guest, 4 * nguest);
        memcpy(t->words + nguest, x->buf, 4 * x->n);
        memcpy(t->words + nguest + x->n, x->relocs, 4 * x->nrelocs);
        uint32_t *l = t->words + nguest + x->n + x->nrelocs;
        for (unsigned i = 0; i < nlinks; i++, l += 4) {
            l[0] = links[i].stub;
            l[1] = links[i].branch;
            l[2] = (uint32_t)links[i].pc;
            l[3] = (uint32_t)(links[i].pc >> 32);
        }
        struct template **b = template_bucket(pc);
        t->next = *b;
        *b = t;
        /* Newest first: old versions of the same pc beyond the limit (regardless of register
         * assignment) are unlinked from the chain (their space is reclaimed when the template
         * arena is cleared) */
        unsigned versions = 0;
        for (struct template **p = &t->next; *p;) {
            if ((*p)->pc == pc && ++versions >= TEMPLATES_PER_PC)
                *p = (*p)->next;
            else
                p = &(*p)->next;
        }
    }
    template_unlock(lock);
    if (__atomic_load_n(&templates.full, __ATOMIC_RELAXED))
        dbt_template_clear(true);
}

/*
 * For profiling: when the environment variable APPINE_PERF_MAP is set, write each block's
 * location in the code cache to /tmp/perf-<pid>.map, which perf report uses to attribute samples
 * to guest pcs (g_<pc>). Without the variable it costs only one extra check.
 */
void dbt_perf_map(const void *code, size_t bytes, uint64_t pc)
{
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static FILE *file;
    static int enabled = -1;
    if (__atomic_load_n(&enabled, __ATOMIC_RELAXED) == 0)
        return;
    pthread_mutex_lock(&lock);
    appine_guard_hold(&lock, false);
    if (__atomic_load_n(&enabled, __ATOMIC_RELAXED) < 0) {
        int on = getenv("APPINE_PERF_MAP") != NULL;
        if (on) {
            char path[64];
            snprintf(path, sizeof path, "/tmp/perf-%d.map", (int)getpid());
            file = fopen(path, "w");
        }
        __atomic_store_n(&enabled, on, __ATOMIC_RELAXED);
    }
    if (file) {
        fprintf(file, "%lx %zx g_%lx\n", (unsigned long)(uintptr_t)code, bytes,
                (unsigned long)pc);
        fflush(file);
    }
    appine_guard_drop();
    pthread_mutex_unlock(&lock);
}


#endif /* DBT_SUPPORTED */
