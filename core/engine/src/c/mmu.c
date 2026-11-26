/*
 * soft-MMU page table (the kernel/mmu map): a 4-level radix tree with 512 entries per level,
 * covering a 48-bit guest address space. Intermediate entries point to the next level's table;
 * leaf entries are a host page address | permission bits. The tree is walked only on a TLB miss.
 *
 * Entries are built on demand: the kernel layer builds them in advance only for small mappings,
 * and large ones get a whole leaf table filled at the guest's first access (appine_mmu_fill), so
 * the page table grows with the memory touched, not with the mapping size. A walk over a range
 * skips a missing intermediate table by the whole span of the missing level (one entry covers
 * 2 MB, 1 GB or 512 GB).
 *
 * Concurrency: only the kernel layer modifies the table, while holding the BKL, but other threads
 * sharing the address space may walk it at the same time (TLB misses). So entries are always read
 * and written atomically: new intermediate tables are linked in with release semantics and read
 * with acquire semantics while walking. Intermediate tables are not freed before the mmu is
 * destroyed.
 */
#define _DEFAULT_SOURCE /* needed for posix_memalign under -std=c17 */
#include <stdbool.h>
#include <stdlib.h>

#include "internal.h"

#define LEVELS MMU_LEVELS
#define LEVEL_BITS MMU_LEVEL_BITS
#define LEVEL_ENTRIES (1u << LEVEL_BITS)
/* Bytes covered by one leaf table (2 MiB, one L2 entry) */
#define LEAF_SPAN MMU_SUPER_SIZE
_Static_assert(LEAF_SPAN == ((uint64_t)APPINE_PAGE_SIZE << LEVEL_BITS), "L2 superpage matches leaf table span");

static unsigned level_shift(int level)
{
    return APPINE_PAGE_SHIFT + LEVEL_BITS * (LEVELS - 1 - level);
}

static unsigned level_index(uint64_t gva, int level)
{
    return (unsigned)(gva >> level_shift(level)) & (LEVEL_ENTRIES - 1);
}

static uintptr_t *alloc_table(struct appine_mmu *mmu)
{
    uintptr_t *p = calloc(LEVEL_ENTRIES, sizeof(uintptr_t));
    if (UNLIKELY((uintptr_t)p & (PTE_SUPER | PTE_PROT_MASK))) {
        free(p);
        void *aligned = NULL;
        if (posix_memalign(&aligned, 16, LEVEL_ENTRIES * sizeof(uintptr_t)) != 0)
            return NULL;
        memset(aligned, 0, LEVEL_ENTRIES * sizeof(uintptr_t));
        p = aligned;
    }
    if (p)
        __atomic_fetch_add(&mmu->tables, 1, __ATOMIC_RELAXED);
    return p;
}

static uintptr_t load_entry(const uintptr_t *slot)
{
    return __atomic_load_n(slot, __ATOMIC_ACQUIRE);
}

static void store_entry(uintptr_t *slot, uintptr_t v)
{
    __atomic_store_n(slot, v, __ATOMIC_RELEASE);
}

static void free_table(uintptr_t *table, int level)
{
    if (level < LEVELS - 1) {
        for (unsigned i = 0; i < LEVEL_ENTRIES; i++) {
            uintptr_t v = table[i];
            if (v && !(level == LEVELS - 2 && (v & PTE_SUPER)))
                free_table((uintptr_t *)v, level + 1);
        }
    }
    free(table);
}

/*
 * Return the L2 slot covering gva (walking levels 0 and 1) without allocating. If an intermediate
 * table is missing, return NULL and set *hole_end to the end of the range from gva that has no
 * entries at all (aligned to the missing level, at most 2^48).
 */
static uintptr_t *l2_slot_find(const struct appine_mmu *mmu, uint64_t gva, uint64_t *hole_end)
{
    uintptr_t *table = mmu->root;
    for (int level = 0; level < LEVELS - 2; level++) {
        uintptr_t *slot = &table[level_index(gva, level)];
        uintptr_t next = load_entry(slot);
        if (!next) {
            unsigned shift = level_shift(level);
            *hole_end = ((gva >> shift) + 1) << shift;
            return NULL;
        }
        table = (uintptr_t *)next;
    }
    return &table[level_index(gva, LEVELS - 2)];
}

/* Return the L2 slot covering gva, allocating missing intermediate tables along the way. */
static uintptr_t *l2_slot_alloc(struct appine_mmu *mmu, uint64_t gva)
{
    uintptr_t *table = mmu->root;
    for (int level = 0; level < LEVELS - 2; level++) {
        uintptr_t *slot = &table[level_index(gva, level)];
        uintptr_t next = load_entry(slot);
        if (!next) {
            uintptr_t *fresh = alloc_table(mmu);
            if (!fresh)
                return NULL;
            next = (uintptr_t)fresh;
            store_entry(slot, next);
        }
        table = (uintptr_t *)next;
    }
    return &table[level_index(gva, LEVELS - 2)];
}

/*
 * Demote a 2 MiB L2 superpage entry into a 512-entry L3 table holding identical 4 KiB entries,
 * then publish it atomically. Concurrent walkers see either the old superpage or the fully
 * populated L3 table with identical mappings.
 */
static uintptr_t *demote_l2(struct appine_mmu *mmu, uintptr_t *l2_slot, uintptr_t super)
{
    uintptr_t *l3 = alloc_table(mmu);
    if (!l3)
        return NULL;
    uintptr_t base = super & ~(uintptr_t)PAGE_MASK;
    uintptr_t prot = super & (uintptr_t)PTE_PROT_MASK;
    for (unsigned i = 0; i < LEVEL_ENTRIES; i++)
        l3[i] = (base + ((uintptr_t)i << APPINE_PAGE_SHIFT)) | prot;
    store_entry(l2_slot, (uintptr_t)l3);
    return l3;
}

/* Return an L3 table for l2_slot, allocating one if empty or demoting if it is a superpage. */
static uintptr_t *ensure_l3(struct appine_mmu *mmu, uintptr_t *l2_slot)
{
    uintptr_t cur = load_entry(l2_slot);
    if (!cur) {
        uintptr_t *fresh = alloc_table(mmu);
        if (!fresh)
            return NULL;
        store_entry(l2_slot, (uintptr_t)fresh);
        return fresh;
    }
    if (cur & PTE_SUPER)
        return demote_l2(mmu, l2_slot, cur);
    return (uintptr_t *)cur;
}

/* End of the range covered by gva's leaf table, at most end */
static uint64_t leaf_end(uint64_t gva, uint64_t end)
{
    uint64_t e = (gva | (LEAF_SPAN - 1)) + 1;
    return e < end ? e : end;
}

static bool range_ok(uint64_t gva, uint64_t len)
{
    uint64_t limit = UINT64_C(1) << APPINE_VA_BITS;
    return (gva & PAGE_MASK) == 0 && (len & PAGE_MASK) == 0 && gva <= limit && len <= limit - gva;
}

struct appine_mmu *appine_mmu_new(void)
{
    struct appine_mmu *mmu = calloc(1, sizeof(*mmu));
    if (!mmu)
        return NULL;
    mmu->root = alloc_table(mmu);
    if (!mmu->root) {
        free(mmu);
        return NULL;
    }
    return mmu;
}

uint64_t appine_mmu_table_bytes(const struct appine_mmu *mmu)
{
    if (!mmu)
        return 0;
    return (uint64_t)__atomic_load_n(&mmu->tables, __ATOMIC_RELAXED) *
           (LEVEL_ENTRIES * sizeof(uintptr_t));
}

/* Cap on retired empty L3 tables kept until appine_mmu_free (bounds memory under adversarial
 * small/2M mmap churn to at most 1 MiB per address space). */
#define MAX_RETIRED_L3 256

static bool l3_is_empty(const uintptr_t *l3)
{
    for (unsigned i = 0; i < LEVEL_ENTRIES; i++) {
        if (load_entry(&l3[i]))
            return false;
    }
    return true;
}

static bool retire_l3(struct appine_mmu *mmu, uintptr_t *l3)
{
    if (mmu->nretired >= MAX_RETIRED_L3)
        return false;
    if (mmu->nretired == mmu->cap_retired) {
        size_t cap = mmu->cap_retired ? mmu->cap_retired * 2 : 16;
        if (cap > MAX_RETIRED_L3)
            cap = MAX_RETIRED_L3;
        uintptr_t **next = realloc(mmu->retired, cap * sizeof(*next));
        if (!next)
            return false;
        mmu->retired = next;
        mmu->cap_retired = cap;
    }
    mmu->retired[mmu->nretired++] = l3;
    return true;
}

void appine_mmu_free(struct appine_mmu *mmu)
{
    if (!mmu)
        return;
    free_table(mmu->root, 0);
    for (size_t i = 0; i < mmu->nretired; i++)
        free(mmu->retired[i]);
    free(mmu->retired);
    free(mmu);
}

/* map and fill: with only_empty, existing entries (including ones with permission 0) stay as they
 * are. Whole 2 MiB leaf spans that are empty (or backed by an all-zero L3 table left by an earlier
 * small unmap, or already a superpage) are stored as L2 superpages. */
static int store_range(struct appine_mmu *mmu, uint64_t gva, void *host, uint64_t len,
                       uint32_t prot, bool only_empty)
{
    uintptr_t h = (uintptr_t)host;
    if (!range_ok(gva, len) || (h & PAGE_MASK) || !h || (prot & ~PTE_PROT_MASK))
        return APPINE_EINVAL;
    uint64_t end = gva + len;
    for (uint64_t va = gva; va < end;) {
        uintptr_t *l2_slot = l2_slot_alloc(mmu, va);
        if (!l2_slot)
            return APPINE_ENOMEM;
        uint64_t stop = leaf_end(va, end);
        uintptr_t cur = load_entry(l2_slot);
        bool full_leaf = (va & MMU_SUPER_MASK) == 0 && (stop - va) == LEAF_SPAN;
        if (full_leaf && (!cur || (cur & PTE_SUPER))) {
            if (!only_empty || !cur)
                store_entry(l2_slot, (h + (va - gva)) | prot | PTE_SUPER);
            va = stop;
            continue;
        }
        if (full_leaf && l3_is_empty((const uintptr_t *)cur) && retire_l3(mmu, (uintptr_t *)cur)) {
            store_entry(l2_slot, (h + (va - gva)) | prot | PTE_SUPER);
            va = stop;
            continue;
        }
        if (only_empty && (cur & PTE_SUPER)) {
            va = stop;
            continue;
        }
        uintptr_t *table = ensure_l3(mmu, l2_slot);
        if (!table)
            return APPINE_ENOMEM;
        for (; va < stop; va += APPINE_PAGE_SIZE) {
            uintptr_t *slot = &table[level_index(va, LEVELS - 1)];
            if (!only_empty || !load_entry(slot))
                store_entry(slot, (h + (va - gva)) | prot);
        }
    }
    return APPINE_OK;
}

int appine_mmu_map(struct appine_mmu *mmu, uint64_t gva, void *host, uint64_t len, uint32_t prot)
{
    return store_range(mmu, gva, host, len, prot, false);
}

int appine_mmu_fill(struct appine_mmu *mmu, uint64_t gva, void *host, uint64_t len, uint32_t prot)
{
    return store_range(mmu, gva, host, len, prot, true);
}

int appine_mmu_unmap(struct appine_mmu *mmu, uint64_t gva, uint64_t len)
{
    if (!range_ok(gva, len))
        return APPINE_EINVAL;
    uint64_t end = gva + len;
    for (uint64_t va = gva; va < end;) {
        uintptr_t *l2_slot = l2_slot_find(mmu, va, &va);
        if (!l2_slot)
            continue;
        uint64_t stop = leaf_end(va, end);
        uintptr_t cur = load_entry(l2_slot);
        if (!cur) {
            va = stop;
            continue;
        }
        uintptr_t *table;
        if (cur & PTE_SUPER) {
            if ((va & MMU_SUPER_MASK) == 0 && (stop - va) == LEAF_SPAN) {
                store_entry(l2_slot, 0);
                va = stop;
                continue;
            }
            table = demote_l2(mmu, l2_slot, cur);
            if (!table)
                return APPINE_ENOMEM;
        } else {
            table = (uintptr_t *)cur;
        }
        for (; va < stop; va += APPINE_PAGE_SIZE)
            store_entry(&table[level_index(va, LEVELS - 1)], 0);
    }
    return APPINE_OK;
}

int appine_mmu_protect(struct appine_mmu *mmu, uint64_t gva, uint64_t len, uint32_t prot)
{
    if (!range_ok(gva, len) || (prot & ~PTE_PROT_MASK))
        return APPINE_EINVAL;
    uint64_t end = gva + len;
    for (uint64_t va = gva; va < end;) {
        uintptr_t *l2_slot = l2_slot_find(mmu, va, &va);
        if (!l2_slot)
            continue;
        uint64_t stop = leaf_end(va, end);
        uintptr_t cur = load_entry(l2_slot);
        if (!cur) {
            va = stop;
            continue;
        }
        uintptr_t *table;
        if (cur & PTE_SUPER) {
            if ((va & MMU_SUPER_MASK) == 0 && (stop - va) == LEAF_SPAN) {
                store_entry(l2_slot, (cur & ~(uintptr_t)PTE_PROT_MASK) | prot);
                va = stop;
                continue;
            }
            table = demote_l2(mmu, l2_slot, cur);
            if (!table)
                return APPINE_ENOMEM;
        } else {
            table = (uintptr_t *)cur;
        }
        for (; va < stop; va += APPINE_PAGE_SIZE) {
            uintptr_t *slot = &table[level_index(va, LEVELS - 1)];
            uintptr_t old = load_entry(slot);
            if (old)
                store_entry(slot, (old & ~(uintptr_t)PTE_PROT_MASK) | prot);
        }
    }
    return APPINE_OK;
}

int appine_mmu_move(struct appine_mmu *mmu, uint64_t from, uint64_t to, uint64_t len)
{
    if (!range_ok(from, len) || !range_ok(to, len) || (from < to + len && to < from + len))
        return APPINE_EINVAL;
    uint64_t end = from + len;
    for (uint64_t va = from; va < end;) {
        uintptr_t *l2_slot = l2_slot_find(mmu, va, &va);
        if (!l2_slot)
            continue;
        uint64_t stop = leaf_end(va, end);
        uintptr_t cur = load_entry(l2_slot);
        if (!cur) {
            va = stop;
            continue;
        }
        if ((cur & PTE_SUPER) && (va & MMU_SUPER_MASK) == 0 && (stop - va) == LEAF_SPAN) {
            uint64_t dst = to + (va - from);
            if ((dst & MMU_SUPER_MASK) == 0) {
                uintptr_t *dst_l2 = l2_slot_alloc(mmu, dst);
                if (!dst_l2)
                    return APPINE_ENOMEM;
                uintptr_t dcur = load_entry(dst_l2);
                if (!dcur || (dcur & PTE_SUPER)) {
                    store_entry(dst_l2, cur);
                    store_entry(l2_slot, 0);
                    va = stop;
                    continue;
                }
            }
        }
        uintptr_t *table = (cur & PTE_SUPER) ? demote_l2(mmu, l2_slot, cur) : (uintptr_t *)cur;
        if (!table)
            return APPINE_ENOMEM;
        for (; va < stop; va += APPINE_PAGE_SIZE) {
            uintptr_t *slot = &table[level_index(va, LEVELS - 1)];
            uintptr_t v = load_entry(slot);
            if (!v)
                continue;
            uint64_t dst = to + (va - from);
            uintptr_t *dst_l2 = l2_slot_alloc(mmu, dst);
            if (!dst_l2)
                return APPINE_ENOMEM;
            uintptr_t *target = ensure_l3(mmu, dst_l2);
            if (!target)
                return APPINE_ENOMEM;
            store_entry(&target[level_index(dst, LEVELS - 1)], v);
            store_entry(slot, 0);
        }
    }
    return APPINE_OK;
}

uint64_t appine_mmu_next_present(const struct appine_mmu *mmu, uint64_t gva, uint64_t end)
{
    uint64_t limit = UINT64_C(1) << APPINE_VA_BITS;
    if (end > limit)
        end = limit;
    for (uint64_t va = gva & ~(uint64_t)PAGE_MASK; va < end;) {
        uintptr_t *l2_slot = l2_slot_find(mmu, va, &va);
        if (!l2_slot)
            continue;
        uint64_t stop = leaf_end(va, end);
        uintptr_t cur = load_entry(l2_slot);
        if (!cur) {
            va = stop;
            continue;
        }
        if (cur & PTE_SUPER)
            return va;
        const uintptr_t *table = (const uintptr_t *)cur;
        for (; va < stop; va += APPINE_PAGE_SIZE) {
            if (load_entry(&table[level_index(va, LEVELS - 1)]))
                return va;
        }
    }
    return end;
}

uintptr_t appine_mmu_lookup_super(const struct appine_mmu *mmu, uint64_t gva, bool *is_super)
{
    *is_super = false;
    if (!mmu || (gva >> APPINE_VA_BITS))
        return 0;
    const uintptr_t *table = mmu->root;
    for (int level = 0; level < LEVELS - 1; level++) {
        uintptr_t next = load_entry(&table[level_index(gva, level)]);
        if (!next)
            return 0;
        if (level == LEVELS - 2 && (next & PTE_SUPER)) {
            *is_super = true;
            return next;
        }
        table = (const uintptr_t *)next;
    }
    return load_entry(&table[level_index(gva, LEVELS - 1)]);
}

uintptr_t appine_mmu_lookup_pte(const struct appine_mmu *mmu, uint64_t gva)
{
    bool is_super = false;
    uintptr_t entry = appine_mmu_lookup_super(mmu, gva, &is_super);
    if (!is_super)
        return entry;
    return ((entry & ~(uintptr_t)PAGE_MASK) + (gva & (LEAF_SPAN - APPINE_PAGE_SIZE))) |
           (entry & (uintptr_t)PTE_PROT_MASK);
}

void *appine_mmu_translate(const struct appine_mmu *mmu, uint64_t gva, uint32_t required_prot)
{
    uintptr_t pte = appine_mmu_lookup_pte(mmu, gva);
    /* An entry with permission 0 (a PROT_NONE page keeping its host page) cannot be accessed, and
     * does not count as mapped even when 0 is passed */
    if (!(pte & PTE_PROT_MASK) || (pte & required_prot) != required_prot)
        return NULL;
    return (void *)((pte & ~(uintptr_t)PAGE_MASK) + (gva & PAGE_MASK));
}
