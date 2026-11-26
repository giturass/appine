/*
 * Tier 1 shared code-cache routines placed at the start of every instance's code cache:
 * enter/exit, soft-TLB refill (with 2 MiB STLB and 4 KiB batch prefill), jump-cache miss lookup,
 * and in-cache same-page memop fast-path helpers.
 */
#define _GNU_SOURCE
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

/* Each of three page walks can fail at any level or on the permission checks (4 KiB or 2 MiB). */
struct refill_fails {
    uint32_t *site[3 * (MMU_LEVELS + 3) + 4];
    unsigned n;
};

static void emit_to_fail(struct xlate *x, struct refill_fails *f, uint32_t insn)
{
    if (f->n >= sizeof(f->site) / sizeof(f->site[0]))
        appine_guard_fail();
    f->site[f->n++] = here(x);
    emit(x, insn);
}

/*
 * Walk the page table with mmu.c's structure and fill the page containing address `a` (T0 or x3)
 * into the TLB: the tags of the read and write halves are filled separately according to the leaf
 * entry's permissions, and tlb_used is recorded at the same time, as in Tier 0's appine_tlb_fill.
 * For 2 MiB L2 superpages (PTE_SUPER_BIT), skips L3, populates cpu->stlb, and when the preceding
 * 4 KiB TLB slot holds (vpn - 1) with the same addend, batch-prefills up to 8 contiguous 4 KiB
 * slots within the same 64-entry tlb_used word.
 * Jumps to failure if unmapped or lacking the permission this access needs. Afterwards
 * x2 = addend; uses up x0, x1, x4, x5 and T2, and preserves x3, T0 and T1.
 */
static void emit_fill(struct xlate *x, unsigned a, bool write, struct refill_fails *f)
{
    size_t used = offsetof(struct appine_cpu, tlb_used);
    size_t sused = offsetof(struct appine_cpu, stlb_used);
    emit(x, enc_ldr_x(0, CTX, offsetof(struct appine_cpu, mmu)));
    emit(x, enc_ldr_x(0, 0, offsetof(struct appine_mmu, root)));
    /* An intermediate entry is the address of the next level's table; loads through the address
     * dependency are ordered just like mmu.c's acquire loads */
    for (unsigned level = 0; level < MMU_LEVELS - 1; level++) {
        emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT + MMU_LEVEL_BITS * (MMU_LEVELS - 1 - level),
                         MMU_LEVEL_BITS));
        emit(x, enc_ldr_x_index(0, 0, 1));
        emit_to_fail(x, f, enc_cbz_x(0));
    }
    uint32_t *is_super = here(x);
    emit(x, enc_tbnz(0, PTE_SUPER_BIT));

    /* Standard 4 KiB L3 leaf lookup */
    emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT, MMU_LEVEL_BITS));
    emit(x, enc_ldr_x_index(0, 0, 1));
    /* Leaf entry = host page address | permission bits; an unmapped one is 0, which the permission
     * check rules out as well */
    emit_to_fail(x, f, enc_tbz(0, 0));
    if (write) /* the write half also serves atomic and grouped reads */
        emit_to_fail(x, f, enc_tbz(0, 1));
    _Static_assert(APPINE_PROT_READ == 1 && APPINE_PROT_WRITE == 2, "the positions of the permission bits");
    emit(x, enc_and_clear_low(1, a, APPINE_PAGE_SHIFT));
    emit(x, enc_and_clear_low(2, 0, APPINE_PAGE_SHIFT));
    emit(x, enc_sub_reg(2, 2, 1)); /* addend */
    emit(x, enc_ubfx(4, a, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT)); /* page number */
    emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(1, CTX, 1, 5));
    for (unsigned half = 0; half < 2; half++) {
        /* tag = (0 - 1) & ~page number with the permission, else 0 & ~page number = TLB_INVALID */
        emit(x, enc_ubfx(T2, 0, half, 1));
        emit(x, enc_sub_reg(T2, 31, T2));
        emit(x, enc_bic_reg(T2, T2, 4));
        emit(x, enc_stp_x(T2, 2, 1, (int)(TLB_OFF + 16 * half)));
    }
    /* tlb_used[index / 64] |= 1 << (index % 64) */
    emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT + 6, TLB_BITS - 6));
    emit(x, enc_add_lsl(1, CTX, 1, 3));
    emit_add_const(x, 1, 1, (int64_t)(used & ~(size_t)0xfff));
    emit(x, enc_ldr_x(T2, 1, used & 0xfff));
    emit(x, enc_ubfx(4, a, APPINE_PAGE_SHIFT, 6));
    emit(x, enc_movz(0, 1, 0));
    emit(x, enc_lslv(0, 0, 4));
    emit(x, enc_orr_reg(T2, T2, 0));
    emit(x, enc_str_x(T2, 1, used & 0xfff));
    uint32_t *done_4k = here(x);
    emit(x, enc_b(0));

    /* L2 2 MiB superpage leaf: skip L3, populate cpu->stlb, and prefill sequentially */
    patch_branch(x->wdelta, is_super, here(x));
    emit_to_fail(x, f, enc_tbz(0, 0));
    if (write)
        emit_to_fail(x, f, enc_tbz(0, 1));
    emit(x, enc_and_clear_low(1, a, MMU_SUPER_SHIFT));
    emit(x, enc_and_clear_low(2, 0, APPINE_PAGE_SHIFT));
    emit(x, enc_sub_reg(2, 2, 1)); /* addend for entire 2 MiB superpage */
    emit(x, enc_ubfx(T2, 0, 1, 1));
    emit(x, enc_sub_reg(T2, 31, T2)); /* w_mask: all-1s if writable, else 0 */

    /* Populate cpu->stlb[sidx] and stlb_used */
    emit(x, enc_ubfx(4, a, MMU_SUPER_SHIFT, 64 - MMU_SUPER_SHIFT)); /* svpn (keeps top byte) */
    emit(x, enc_eon_lsr(5, 31, 4, 0));                              /* stag_read = ~svpn */
    emit(x, enc_and_low(4, 4, STLB_BITS));                          /* sidx */
    emit(x, enc_add_imm(1, CTX, (uint32_t)(STLB_OFF >> 12), 1));
    emit(x, enc_add_lsl(1, 1, 4, 5));
    emit(x, enc_stp_x(5, 2, 1, 0));
    emit(x, enc_and_reg(5, 5, T2));
    emit(x, enc_stp_x(5, 2, 1, 16));
    emit(x, enc_ubfx(1, 4, 6, STLB_BITS - 6));
    emit(x, enc_add_lsl(1, CTX, 1, 3));
    emit_add_const(x, 1, 1, (int64_t)(sused & ~(size_t)0xfff));
    emit(x, enc_ldr_x(5, 1, sused & 0xfff));
    emit(x, enc_and_low(4, 4, 6));
    emit(x, enc_movz(0, 1, 0));
    emit(x, enc_lslv(0, 0, 4));
    emit(x, enc_orr_reg(5, 5, 0));
    emit(x, enc_str_x(5, 1, sused & 0xfff));

    /* Detect sequential streaming: preceding 4 KiB slot holds (vpn - 1) with the same addend */
    emit(x, enc_ubfx(4, a, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT)); /* vpn */
    emit(x, enc_eon_lsr(5, 31, 4, 0));                                  /* r_tag = ~vpn */
    emit(x, enc_sub_imm(1, 4, 1, 0));
    emit(x, enc_and_low(1, 1, TLB_BITS));
    emit(x, enc_add_lsl(1, CTX, 1, 5));
    emit(x, enc_ldp_x(0, 1, 1, (int)TLB_OFF)); /* prev_tag_read, prev_addend_read */
    emit(x, enc_sub_imm(0, 0, 1, 0));
    emit(x, enc_eor_lsr(0, 0, 5, 0));
    emit(x, enc_eor_lsr(1, 1, 2, 0));
    emit(x, enc_orr_reg(0, 0, 1));
    uint32_t *non_seq = here(x);
    emit(x, enc_cbnz_x(0));

    /* Sequential batch prefill: up to 8 contiguous 4 KiB slots inside the same 64-entry tlb_used
     * word (strictly within this 2 MiB superpage) */
    emit(x, enc_and_low(0, 4, 6)); /* bit = idx & 63 */
    emit(x, enc_movz(1, 64, 0));
    emit(x, enc_sub_reg(1, 1, 0)); /* rem = 64 - bit (1..64) */
    emit(x, enc_sub_imm(0, 1, 9, 0));
    uint32_t *keep_rem = here(x);
    emit(x, enc_tbnz(0, 63));
    emit(x, enc_movz(1, 8, 0));
    patch_branch(x->wdelta, keep_rem, here(x));
    emit(x, enc_and_low(0, 4, TLB_BITS));
    emit(x, enc_add_lsl(0, CTX, 0, 5));
    uint32_t *batch_loop = here(x);
    emit(x, enc_and_reg(4, 5, T2));
    emit(x, enc_stp_x(5, 2, 0, (int)TLB_OFF));
    emit(x, enc_stp_x(4, 2, 0, (int)(TLB_OFF + 16)));
    emit(x, enc_add_imm(0, 0, 32, 0));
    emit(x, enc_sub_imm(5, 5, 1, 0));
    emit(x, enc_sub_imm(1, 1, 1, 0));
    uint32_t *batch_back = here(x);
    emit(x, enc_cbnz_x(1));
    patch_branch(x->wdelta, batch_back, batch_loop);
    emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT + 6, TLB_BITS - 6));
    emit(x, enc_add_lsl(1, CTX, 1, 3));
    emit_add_const(x, 1, 1, (int64_t)(used & ~(size_t)0xfff));
    emit(x, enc_ldr_x(T2, 1, used & 0xfff));
    emit(x, enc_ubfx(4, a, APPINE_PAGE_SHIFT, 6));
    emit(x, enc_movz(0, 0xff, 0));
    emit(x, enc_lslv(0, 0, 4));
    emit(x, enc_orr_reg(T2, T2, 0));
    emit(x, enc_str_x(T2, 1, used & 0xfff));
    uint32_t *done_batch = here(x);
    emit(x, enc_b(0));

    /* Non-sequential superpage miss: fill only the accessed 4 KiB slot */
    patch_branch(x->wdelta, non_seq, here(x));
    emit(x, enc_and_low(1, 4, TLB_BITS));
    emit(x, enc_add_lsl(1, CTX, 1, 5));
    emit(x, enc_and_reg(4, 5, T2));
    emit(x, enc_stp_x(5, 2, 1, (int)TLB_OFF));
    emit(x, enc_stp_x(4, 2, 1, (int)(TLB_OFF + 16)));
    emit(x, enc_ubfx(1, a, APPINE_PAGE_SHIFT + 6, TLB_BITS - 6));
    emit(x, enc_add_lsl(1, CTX, 1, 3));
    emit_add_const(x, 1, 1, (int64_t)(used & ~(size_t)0xfff));
    emit(x, enc_ldr_x(T2, 1, used & 0xfff));
    emit(x, enc_ubfx(4, a, APPINE_PAGE_SHIFT, 6));
    emit(x, enc_movz(0, 1, 0));
    emit(x, enc_lslv(0, 0, 4));
    emit(x, enc_orr_reg(T2, T2, 0));
    emit(x, enc_str_x(T2, 1, used & 0xfff));

    uint32_t *done_fill = here(x);
    patch_branch(x->wdelta, done_4k, done_fill);
    patch_branch(x->wdelta, done_batch, done_fill);
}

/* Look up the page of address `a` in the TLB: on a hit the `addend` register = addend, otherwise
 * jump to `miss` (offset patched later); uses up x0 */
static uint32_t *emit_probe(struct xlate *x, unsigned a, unsigned addend, bool write)
{
    emit(x, enc_ubfx(0, a, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(0, CTX, 0, 5));
    emit(x, enc_ldp_x(0, addend, 0, (int)TLB_OFF + (write ? 16 : 0)));
    emit(x, enc_eon_lsr(0, 0, a, APPINE_PAGE_SHIFT));
    uint32_t *miss = here(x);
    emit(x, enc_cbnz_x(0));
    return miss;
}

/*
 * TLB refill routine: a TLB miss or a cross-page access is handled in translated code, without
 * exiting to the dispatcher. Entry: T0 = guest address, T1 points to the refill stub's info word
 * (emit_refill_stub). On success T2 = addend and it returns to the access itself; on failure it
 * exits with the reason in the info word.
 *
 * Without a page crossing, the entry is filled from the page table. Across pages both pages must
 * have the permission this access needs and the host addresses must be contiguous (both pages
 * have the same addend; all pages in one host mapping do), and then the whole access is still
 * done on the host in one go: when both pages are in the TLB only the two entries are compared,
 * and a page that is not is filled first. A function whose stack frame crosses a page accesses it
 * this way on every call, so this cannot fall back to Tier 0.
 *
 * The page-table indices ignore the top byte. Keep it in the TLB tag and subtract the full guest
 * page base in the addend. A hit for this tag then yields an untagged host address. A different top
 * byte at the same slot misses. Bits 55:48 must still be zero at both ends of the access.
 *
 * Borrows the x0–x4 slots in the cpu struct to save host x0–x4: while translated code runs these
 * slots do not hold the guest's values, and the exit routine writes them again.
 */
static uint32_t *emit_refill(struct xlate *x, bool write)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    struct refill_fails f = {.n = 0};

    emit(x, enc_stp_x(0, 1, CTX, (int)x0));
    emit(x, enc_stp_x(2, 3, CTX, (int)x0 + 16));
    emit(x, enc_stp_x(4, 5, CTX, (int)x0 + 32));
    /* With watchpoints (set by ptrace), do not fill from the page table: watched pages must not
     * enter the TLB. Tier 0 executes this instruction instead; it checks the watchpoints and fills
     * the TLB by appine_tlb_fill's rules, so unwatched pages hit as usual afterwards */
    size_t nwatch = offsetof(struct appine_cpu, nwatch);
    emit_add_const(x, 0, CTX, (int64_t)(nwatch & ~(size_t)0xfff));
    emit(x, enc_ldr_w(0, 0, nwatch & 0xfff));
    emit_to_fail(x, &f, enc_cbnz_x(0));
    emit(x, enc_ldr_w(3, T1, 0));
    emit(x, enc_ubfx(3, 3, 0, REFILL_REASON_SHIFT));
    emit(x, enc_add_lsl(3, T0, 3, 0)); /* last byte */
    /* Check both ends: adding the byte count can carry into or out of the address space. */
    emit(x, enc_orr_reg(0, T0, 3));
    emit(x, enc_ubfx(0, 0, APPINE_VA_BITS, DATA_TAG_SHIFT - APPINE_VA_BITS));
    emit_to_fail(x, &f, enc_cbnz_x(0));
    emit(x, enc_eor_lsr(0, T0, 3, 0));
    emit(x, enc_ubfx(0, 0, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *cross = here(x);
    emit(x, enc_cbnz_x(0));

    emit_fill(x, T0, write, &f);
    emit(x, enc_mov(T2, 2));
    uint32_t *done = here(x);
    emit(x, enc_ldr_w(0, T1, 0));
    emit(x, enc_sbfx(0, 0, REFILL_RESUME_SHIFT, 32 - REFILL_RESUME_SHIFT));
    emit(x, enc_add_lsl(T1, T1, 0, 2));
    emit(x, enc_ldp_x(0, 1, CTX, (int)x0));
    emit(x, enc_ldp_x(2, 3, CTX, (int)x0 + 16));
    emit(x, enc_ldp_x(4, 5, CTX, (int)x0 + 32));
    emit(x, enc_br(T1));

    /* Cross-page: x1, x2 = the two pages' addends */
    uint32_t *probe = here(x);
    patch_branch(x->wdelta, cross, probe);
    uint32_t *miss[2];
    miss[0] = emit_probe(x, T0, 1, write);
    miss[1] = emit_probe(x, 3, 2, write);
    emit(x, enc_sub_reg(0, 2, 1));
    emit_to_fail(x, &f, enc_cbnz_x(0));
    emit(x, enc_mov(T2, 1));
    emit(x, enc_b((intptr_t)done - (intptr_t)here(x)));
    for (unsigned i = 0; i < 2; i++) {
        patch_branch(x->wdelta, miss[i], here(x));
        emit_fill(x, i ? 3 : T0, write, &f);
        emit(x, enc_b((intptr_t)probe - (intptr_t)here(x)));
    }

    for (unsigned i = 0; i < f.n; i++)
        patch_branch(x->wdelta, f.site[i], here(x));
    emit(x, enc_ldr_w(0, T1, 0));
    emit(x, enc_ubfx(T2, 0, REFILL_REASON_SHIFT, REFILL_RESUME_SHIFT - REFILL_REASON_SHIFT));
    emit(x, enc_ldur_x(T0, T1, 4));
    emit(x, enc_ldp_x(0, 1, CTX, (int)x0));
    emit(x, enc_ldp_x(2, 3, CTX, (int)x0 + 16));
    emit(x, enc_ldp_x(4, 5, CTX, (int)x0 + 32));
    emit(x, enc_b((intptr_t)x->d->exit - (intptr_t)here(x)));
    return entry;
}

/* Increment the cpu's dbt_lookup_seq (uses up x1 and x2); see table_lookup */
static void emit_seq_step(struct xlate *x)
{
    size_t seq = offsetof(struct appine_cpu, dbt_lookup_seq);
    emit(x, enc_ldr_w(2, CTX, seq));
    emit(x, enc_add_imm(2, 2, 1, 0));
    emit_add_const(x, 1, CTX, (int64_t)seq);
    emit(x, enc_stlr(2, 2, 1));
}

/*
 * Lookup routine for jump-cache misses: T0 = guest pc. Like table_lookup it looks up this address
 * space's shared translation table without the lock; if found, it fills the thread's jump cache
 * and jumps there, and only if not found does it exit to the dispatcher to translate (R_LOOKUP).
 * Previously every miss exited and saved and restored all registers, more than six million times
 * in one Maven build for JIT workloads. Borrows the x0–x3 slots in the cpu struct to save host
 * x0–x3; see emit_refill.
 */
static uint32_t *emit_lookup(struct xlate *x, struct appine_dbt *d)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    emit(x, enc_stp_x(0, 1, CTX, (int)x0));
    emit(x, enc_stp_x(2, 3, CTX, (int)x0 + 16));
    /* Read the table only after the sequence number has become odd: an stlr and a later ldar are
     * ordered */
    emit_seq_step(x);
    /* Misaligned pcs and pcs beyond 48 bits go to the dispatcher; see table_find_for. So does pc
     * 0: the ldp below reads key and code in no particular order, and racing an insertion it can
     * pair the new code with the empty slot's key 0, which only pc 0 would match */
    emit(x, enc_and_ror(2, T0, 2 + 64 - TAG_SHIFT, 64 - TAG_SHIFT));
    uint32_t *invalid = here(x);
    emit(x, enc_cbnz_x(2));
    uint32_t *zero = here(x);
    emit(x, enc_cbz_x(T0));
    /* x1 = this member's tag << TAG_SHIFT: an entry whose key XOR pc is 0 is a shared block, and
     * one where it equals x1 is this member's private block */
    emit(x, enc_ldr_w(1, CTX, offsetof(struct appine_cpu, dbt_tag)));
    emit(x, enc_orr_lsl(1, 31, 1, TAG_SHIFT));
    emit_mov_const(x, 0, (uint64_t)(uintptr_t)&d->table);
    emit(x, enc_ldar(3, 0, 0));
    emit(x, enc_ldr_w(2, 0, offsetof(struct table, shift)));
    emit(x, enc_ldr_x(3, 0, offsetof(struct table, mask)));
    emit(x, enc_add_imm(0, 0, offsetof(struct table, slots), 0));
    emit(x, enc_ubfx(T1, T0, 2, TAG_SHIFT - 2));
    emit_mov_const(x, T2, GOLDEN);
    emit(x, enc_mul(T1, T1, T2));
    emit(x, enc_lsrv(T1, T1, 2));
    /* Linear probing: x2 = the entry's key, T2 = code */
    uint32_t *loop = here(x);
    emit(x, enc_add_lsl(T2, 0, T1, 4));
    emit(x, enc_ldp_x(2, T2, T2, 0));
    uint32_t *miss = here(x);
    emit(x, enc_cbz_x(T2));
    emit(x, enc_eor_lsr(2, 2, T0, 0));
    uint32_t *found[2] = {here(x)};
    emit(x, enc_cbz_x(2));
    emit(x, enc_eor_lsr(2, 2, 1, 0));
    found[1] = here(x);
    emit(x, enc_cbz_x(2));
    emit(x, enc_add_imm(T1, T1, 1, 0));
    emit(x, enc_and_reg(T1, T1, 3));
    emit(x, enc_b((intptr_t)loop - (intptr_t)here(x)));

    patch_branch(x->wdelta, found[0], here(x));
    patch_branch(x->wdelta, found[1], here(x));
    emit_seq_step(x);
    emit(x, enc_ldr_x(0, CTX, offsetof(struct appine_cpu, dbt_jump_cache)));
    emit(x, enc_ubfx(1, T0, 2, JC_BITS));
    emit(x, enc_add_lsl(0, 0, 1, 4));
    emit(x, enc_stp_x(T0, T2, 0, 0));
    emit(x, enc_mov(T1, T2));
    emit(x, enc_ldp_x(0, 1, CTX, (int)x0));
    emit(x, enc_ldp_x(2, 3, CTX, (int)x0 + 16));
    emit(x, enc_br(T1));

    patch_branch(x->wdelta, miss, here(x));
    patch_branch(x->wdelta, invalid, here(x));
    patch_branch(x->wdelta, zero, here(x));
    emit_seq_step(x);
    emit(x, enc_ldp_x(0, 1, CTX, (int)x0));
    emit(x, enc_ldp_x(2, 3, CTX, (int)x0 + 16));
    emit(x, enc_movz(T1, 0, 0));
    emit(x, enc_movz(T2, R_LOOKUP, 0));
    emit(x, enc_b((intptr_t)d->exit - (intptr_t)here(x)));
    return entry;
}

/* Move the guest registers kept in same-numbered host registers to or from the cpu struct (`base`
 * points to x[0]): two adjacent ones use one ldp/stp */
static void move_guest_regs(struct xlate *x, unsigned base, bool store)
{
    for (unsigned r = 0; r < 31; r++) {
        if (is_stolen(r))
            continue;
        if (r < 30 && !is_stolen(r + 1)) {
            emit(x, store ? enc_stp_x(r, r + 1, base, (int)(8 * r)) : enc_ldp_x(r, r + 1, base, (int)(8 * r)));
            r++;
        } else {
            emit(x, store ? enc_str_x(r, base, 8 * r) : enc_ldr_x(r, base, 8 * r));
        }
    }
}

/*
 * Shared predicted return tail for in-cache memop helpers: X0 holds the return value, all other
 * guest registers and NZCV are preserved. On shadow return stack mismatch (e.g., tail call), falls
 * through to d->rs_miss (which looks up X30 in the translation table).
 */
static uint32_t *emit_memop_ret(struct xlate *x, struct appine_dbt *d)
{
    size_t rs = offsetof(struct appine_cpu, dbt_rs);
    uint32_t *entry = here(x);
    emit(x, enc_ldr_x(T1, CTX, rs));
    emit(x, enc_ldp_x(T0, T2, T1, 0));
    emit(x, enc_eor_lsr(T0, T0, 30, 0));
    uint32_t *miss = here(x);
    emit(x, enc_cbnz_x(T0));
    patch_branch(x->wdelta, miss, d->rs_miss);
    emit(x, enc_sub_imm(T0, T1, 16, 0));
    emit(x, enc_bfxil_low(T1, T0, RS_SHIFT));
    emit(x, enc_str_x(T1, CTX, rs));
    emit(x, enc_ret_reg(T2));
    return entry;
}

/*
 * In-cache same-page memset (n >= 32, n <= 4096): X0 = dst, X1 = c, X2 = n, T0 = fallback PC.
 * Validates 1 <= n <= 4096 and same-page write TLB hit (which also excludes watched and read-only
 * pages) before touching any guest register or memory. Preserves X0..X30 and NZCV.
 */
static uint32_t *emit_memop_memset(struct xlate *x, struct appine_dbt *d)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    emit(x, enc_sub_imm(T1, 2, 1, 0)); /* n - 1 */
    emit(x, enc_ubfx(T2, T1, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *fail0 = here(x);
    emit(x, enc_cbnz_x(T2)); /* n == 0 or n > 4096 */
    emit(x, enc_add_lsl(T1, 0, T1, 0)); /* dst + n - 1 */
    emit(x, enc_ubfx(T1, T1, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)(TLB_OFF + 16))); /* tag_write, addend_write */
    emit(x, enc_eon_lsr(T1, T1, 0, APPINE_PAGE_SHIFT));
    uint32_t *fail1 = here(x);
    emit(x, enc_cbnz_x(T1));

    emit(x, enc_stp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_and_low(3, 1, 8));
    emit(x, enc_orr_lsl(3, 3, 3, 8));
    emit(x, enc_orr_lsl(3, 3, 3, 16));
    emit(x, enc_orr_lsl(3, 3, 3, 32));
    emit(x, enc_add_lsl(T1, T2, 0, 0)); /* host_dst */
    emit(x, enc_add_lsl(T2, T1, 2, 0)); /* host_end */
    /* Overlapping final 32 bytes (safe for all n >= 32) */
    emit(x, enc_stp_x(3, 3, T2, -32));
    emit(x, enc_stp_x(3, 3, T2, -16));
    emit(x, enc_sub_imm(4, 2, 1, 0)); /* n - 1 */
    emit(x, enc_ubfx(T2, 4, 6, 58));  /* (n - 1) / 64 */
    uint32_t *no64 = here(x);
    emit(x, enc_cbz_x(T2));
    uint32_t *loop64 = here(x);
    emit(x, enc_stp_x(3, 3, T1, 0));
    emit(x, enc_stp_x(3, 3, T1, 16));
    emit(x, enc_stp_x(3, 3, T1, 32));
    emit(x, enc_stp_x(3, 3, T1, 48));
    emit(x, enc_add_imm(T1, T1, 64, 0));
    emit(x, enc_sub_imm(T2, T2, 1, 0));
    uint32_t *back64 = here(x);
    emit(x, enc_cbnz_x(T2));
    patch_branch(x->wdelta, back64, loop64);
    patch_branch(x->wdelta, no64, here(x));
    uint32_t *no32 = here(x);
    emit(x, enc_tbz(4, 5));
    emit(x, enc_stp_x(3, 3, T1, 0));
    emit(x, enc_stp_x(3, 3, T1, 16));
    patch_branch(x->wdelta, no32, here(x));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    uint32_t *fail = here(x);
    patch_branch(x->wdelta, fail0, fail);
    patch_branch(x->wdelta, fail1, fail);
    emit(x, enc_br(T0));
    return entry;
}

/*
 * In-cache same-page memcpy/memmove (n >= 32, n <= 4096): X0 = dst, X1 = src, X2 = n,
 * T0 = fallback PC. Overlap-safe for both forward and backward moves, including shared-page host
 * aliases. Preserves X0..X30 and NZCV.
 */
static uint32_t *emit_memop_memmove(struct xlate *x, struct appine_dbt *d)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    emit(x, enc_sub_imm(T1, 2, 1, 0));
    emit(x, enc_ubfx(T2, T1, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *fail0 = here(x);
    emit(x, enc_cbnz_x(T2));
    /* dst write-TLB check */
    emit(x, enc_add_lsl(T1, 0, T1, 0));
    emit(x, enc_ubfx(T1, T1, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)(TLB_OFF + 16)));
    emit(x, enc_eon_lsr(T1, T1, 0, APPINE_PAGE_SHIFT));
    uint32_t *fail1 = here(x);
    emit(x, enc_cbnz_x(T1));
    emit(x, enc_stp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_add_lsl(3, T2, 0, 0)); /* x3 = host_dst */
    /* src read-TLB check */
    emit(x, enc_sub_imm(T1, 2, 1, 0));
    emit(x, enc_add_lsl(T1, 1, T1, 0));
    emit(x, enc_ubfx(T1, T1, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF));
    emit(x, enc_eon_lsr(T1, T1, 1, APPINE_PAGE_SHIFT));
    uint32_t *fail2 = here(x);
    emit(x, enc_cbnz_x(T1));

    emit(x, enc_stp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_add_lsl(4, T2, 1, 0)); /* x4 = host_src */
    emit(x, enc_sub_reg(T1, 3, 4));    /* diff = host_dst - host_src */
    uint32_t *same = here(x);
    emit(x, enc_cbz_x(T1));
    emit(x, enc_ubfx(T2, T1, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *go_fwd = here(x);
    emit(x, enc_cbnz_x(T2)); /* diff >= 4096 (incl. host_dst < host_src) -> forward */
    emit(x, enc_sub_reg(T2, T1, 2));
    uint32_t *go_bwd = here(x);
    emit(x, enc_tbnz(T2, 63)); /* 0 < diff < n -> backward */

    /* Forward copy (32 B chunks, reading before writing, then 16/8/4/2/1 tail) */
    patch_branch(x->wdelta, go_fwd, here(x));
    emit(x, enc_ubfx(T0, 2, 5, 59));
    uint32_t *fwd_no32 = here(x);
    emit(x, enc_cbz_x(T0));
    uint32_t *fwd_loop = here(x);
    emit(x, enc_ldp_x_post(5, 6, 4, 16));
    emit(x, enc_ldp_x_post(T1, T2, 4, 16));
    emit(x, enc_stp_x_post(5, 6, 3, 16));
    emit(x, enc_stp_x_post(T1, T2, 3, 16));
    emit(x, enc_sub_imm(T0, T0, 1, 0));
    uint32_t *fwd_back = here(x);
    emit(x, enc_cbnz_x(T0));
    patch_branch(x->wdelta, fwd_back, fwd_loop);
    patch_branch(x->wdelta, fwd_no32, here(x));
    uint32_t *f16 = here(x);
    emit(x, enc_tbz(2, 4));
    emit(x, enc_ldp_x_post(5, 6, 4, 16));
    emit(x, enc_stp_x_post(5, 6, 3, 16));
    patch_branch(x->wdelta, f16, here(x));
    uint32_t *f8 = here(x);
    emit(x, enc_tbz(2, 3));
    emit(x, enc_ldr_post(3, 5, 4, 8));
    emit(x, enc_str_post(3, 5, 3, 8));
    patch_branch(x->wdelta, f8, here(x));
    uint32_t *f4 = here(x);
    emit(x, enc_tbz(2, 2));
    emit(x, enc_ldr_post(2, 5, 4, 4));
    emit(x, enc_str_post(2, 5, 3, 4));
    patch_branch(x->wdelta, f4, here(x));
    uint32_t *f2 = here(x);
    emit(x, enc_tbz(2, 1));
    emit(x, enc_ldr_post(1, 5, 4, 2));
    emit(x, enc_str_post(1, 5, 3, 2));
    patch_branch(x->wdelta, f2, here(x));
    uint32_t *f1 = here(x);
    emit(x, enc_tbz(2, 0));
    emit(x, enc_ldr_size(0, 5, 4));
    emit(x, enc_str_size(0, 5, 3));
    patch_branch(x->wdelta, f1, here(x));
    uint32_t *fwd_done = here(x);
    emit(x, enc_b(0));

    /* Backward copy (0 < host_dst - host_src < n) */
    patch_branch(x->wdelta, go_bwd, here(x));
    emit(x, enc_add_lsl(3, 3, 2, 0));
    emit(x, enc_add_lsl(4, 4, 2, 0));
    emit(x, enc_ubfx(T0, 2, 5, 59));
    uint32_t *bwd_no32 = here(x);
    emit(x, enc_cbz_x(T0));
    uint32_t *bwd_loop = here(x);
    emit(x, enc_ldp_x(5, 6, 4, -32));
    emit(x, enc_ldp_x(T1, T2, 4, -16));
    emit(x, enc_sub_imm(4, 4, 32, 0));
    emit(x, enc_stp_x(5, 6, 3, -32));
    emit(x, enc_stp_x(T1, T2, 3, -16));
    emit(x, enc_sub_imm(3, 3, 32, 0));
    emit(x, enc_sub_imm(T0, T0, 1, 0));
    uint32_t *bwd_back = here(x);
    emit(x, enc_cbnz_x(T0));
    patch_branch(x->wdelta, bwd_back, bwd_loop);
    patch_branch(x->wdelta, bwd_no32, here(x));
    uint32_t *b16 = here(x);
    emit(x, enc_tbz(2, 4));
    emit(x, enc_ldp_x(5, 6, 4, -16));
    emit(x, enc_sub_imm(4, 4, 16, 0));
    emit(x, enc_stp_x(5, 6, 3, -16));
    emit(x, enc_sub_imm(3, 3, 16, 0));
    patch_branch(x->wdelta, b16, here(x));
    uint32_t *b8 = here(x);
    emit(x, enc_tbz(2, 3));
    emit(x, enc_ldur_size(3, 5, 4, -8));
    emit(x, enc_sub_imm(4, 4, 8, 0));
    emit(x, enc_stur_size(3, 5, 3, -8));
    emit(x, enc_sub_imm(3, 3, 8, 0));
    patch_branch(x->wdelta, b8, here(x));
    uint32_t *b4 = here(x);
    emit(x, enc_tbz(2, 2));
    emit(x, enc_ldur_size(2, 5, 4, -4));
    emit(x, enc_sub_imm(4, 4, 4, 0));
    emit(x, enc_stur_size(2, 5, 3, -4));
    emit(x, enc_sub_imm(3, 3, 4, 0));
    patch_branch(x->wdelta, b4, here(x));
    uint32_t *b2 = here(x);
    emit(x, enc_tbz(2, 1));
    emit(x, enc_ldur_size(1, 5, 4, -2));
    emit(x, enc_sub_imm(4, 4, 2, 0));
    emit(x, enc_stur_size(1, 5, 3, -2));
    emit(x, enc_sub_imm(3, 3, 2, 0));
    patch_branch(x->wdelta, b2, here(x));
    uint32_t *b1 = here(x);
    emit(x, enc_tbz(2, 0));
    emit(x, enc_ldur_size(0, 5, 4, -1));
    emit(x, enc_stur_size(0, 5, 3, -1));
    patch_branch(x->wdelta, b1, here(x));

    uint32_t *done = here(x);
    patch_branch(x->wdelta, same, done);
    patch_branch(x->wdelta, fwd_done, done);
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    patch_branch(x->wdelta, fail2, here(x));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    uint32_t *fail = here(x);
    patch_branch(x->wdelta, fail0, fail);
    patch_branch(x->wdelta, fail1, fail);
    emit(x, enc_br(T0));
    return entry;
}

/*
 * In-cache same-page memcmp (n >= 8, n <= 4096): X0 = a, X1 = b, X2 = n, T0 = fallback PC.
 * Compares 8 bytes per iteration (with an overlapping final 8-byte read when n & 7 != 0) and
 * returns the exact signed byte difference in X0. Preserves X1..X30 and NZCV.
 */
static uint32_t *emit_memop_memcmp(struct xlate *x, struct appine_dbt *d)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    emit(x, enc_sub_imm(T1, 2, 1, 0));
    emit(x, enc_ubfx(T2, T1, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *fail0 = here(x);
    emit(x, enc_cbnz_x(T2));
    /* a read-TLB check */
    emit(x, enc_add_lsl(T1, 0, T1, 0));
    emit(x, enc_ubfx(T1, T1, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF));
    emit(x, enc_eon_lsr(T1, T1, 0, APPINE_PAGE_SHIFT));
    uint32_t *fail1 = here(x);
    emit(x, enc_cbnz_x(T1));
    emit(x, enc_stp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_add_lsl(3, T2, 0, 0)); /* x3 = host_a */
    /* b read-TLB check */
    emit(x, enc_sub_imm(T1, 2, 1, 0));
    emit(x, enc_add_lsl(T1, 1, T1, 0));
    emit(x, enc_ubfx(T1, T1, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF));
    emit(x, enc_eon_lsr(T1, T1, 1, APPINE_PAGE_SHIFT));
    uint32_t *fail2 = here(x);
    emit(x, enc_cbnz_x(T1));

    emit(x, enc_stp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_add_lsl(4, T2, 1, 0)); /* x4 = host_b */
    emit(x, enc_eor_lsr(T1, 3, 4, 0));
    uint32_t *same = here(x);
    emit(x, enc_cbz_x(T1));
    emit(x, enc_ubfx(T1, 2, 3, 61)); /* count8 = n / 8 (always >= 1) */
    uint32_t *loop8 = here(x);
    emit(x, enc_ldr_post(3, 5, 3, 8));
    emit(x, enc_ldr_post(3, 6, 4, 8));
    emit(x, enc_eor_lsr(T2, 5, 6, 0));
    uint32_t *diff0 = here(x);
    emit(x, enc_cbnz_x(T2));
    emit(x, enc_sub_imm(T1, T1, 1, 0));
    uint32_t *back8 = here(x);
    emit(x, enc_cbnz_x(T1));
    patch_branch(x->wdelta, back8, loop8);

    emit(x, enc_and_low(T1, 2, 3)); /* n & 7 */
    uint32_t *eq_tail = here(x);
    emit(x, enc_cbz_x(T1));
    emit(x, enc_add_lsl(3, 3, T1, 0));
    emit(x, enc_add_lsl(4, 4, T1, 0));
    emit(x, enc_ldur_size(3, 5, 3, -8));
    emit(x, enc_ldur_size(3, 6, 4, -8));
    emit(x, enc_eor_lsr(T2, 5, 6, 0));
    uint32_t *diff1 = here(x);
    emit(x, enc_cbnz_x(T2));

    uint32_t *equal = here(x);
    patch_branch(x->wdelta, same, equal);
    patch_branch(x->wdelta, eq_tail, equal);
    emit(x, enc_movz(0, 0, 0));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    uint32_t *diff = here(x);
    patch_branch(x->wdelta, diff0, diff);
    patch_branch(x->wdelta, diff1, diff);
    emit(x, enc_rbit_x(T2, T2));
    emit(x, enc_clz_x(T2, T2));
    emit(x, enc_and_clear_low(T2, T2, 3)); /* shift = 8 * first_diff_byte */
    emit(x, enc_lsrv(5, 5, T2));
    emit(x, enc_lsrv(6, 6, T2));
    emit(x, enc_and_low(5, 5, 8));
    emit(x, enc_and_low(6, 6, 8));
    emit(x, enc_sub_reg(0, 5, 6));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    patch_branch(x->wdelta, fail2, here(x));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    uint32_t *fail = here(x);
    patch_branch(x->wdelta, fail0, fail);
    patch_branch(x->wdelta, fail1, fail);
    emit(x, enc_br(T0));
    return entry;
}

/*
 * In-cache first-page memchr (n >= 1, including n = SIZE_MAX from strnlen): X0 = s, X1 = c,
 * X2 = n, T0 = fallback PC. Scans min(n, bytes_to_page_end) bytes via 8-byte SWAR; returns X0 + off
 * (preserving any TBI tag) on match, 0 if n stayed within the page, or jumps to fallback with all
 * guest registers untouched if the search reaches the next page.
 */
static uint32_t *emit_memop_memchr(struct xlate *x, struct appine_dbt *d)
{
    size_t x0 = offsetof(struct appine_cpu, x);
    uint32_t *entry = here(x);
    emit(x, enc_ubfx(T1, 0, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF));
    emit(x, enc_eon_lsr(T1, T1, 0, APPINE_PAGE_SHIFT));
    uint32_t *fail = here(x);
    emit(x, enc_cbnz_x(T1));

    emit(x, enc_stp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_stp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_stp_x(7, T0, CTX, (int)x0 + 56)); /* x7 + fallback PC */
    emit(x, enc_add_lsl(7, T2, 0, 0));            /* x7 = host_s */
    emit(x, enc_mov(T0, 7));                      /* T0 = cur */

    /* T1 = min(X2, 4096 - (X0 & 4095)), always in [1, 4096] */
    emit(x, enc_and_low(T1, 0, APPINE_PAGE_SHIFT));
    emit(x, enc_movz(T2, APPINE_PAGE_SIZE, 0));
    emit(x, enc_sub_reg(T1, T2, T1));
    emit(x, enc_ubfx(T2, 2, APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
    uint32_t *bip0 = here(x);
    emit(x, enc_cbnz_x(T2));
    emit(x, enc_sub_reg(T2, 2, T1));
    uint32_t *bip1 = here(x);
    emit(x, enc_tbz(T2, 63));
    emit(x, enc_mov(T1, 2));
    uint32_t *have_lim = here(x);
    patch_branch(x->wdelta, bip0, have_lim);
    patch_branch(x->wdelta, bip1, have_lim);
    emit(x, enc_str_x(T1, CTX, x0 + 72)); /* save limit */

    emit(x, enc_and_low(3, 1, 8));
    emit(x, enc_orr_lsl(3, 3, 3, 8));
    emit(x, enc_orr_lsl(3, 3, 3, 16));
    emit(x, enc_orr_lsl(3, 3, 3, 32));
    emit_mov_const(x, 4, UINT64_C(0x0101010101010101));
    emit(x, enc_orr_lsl(5, 31, 4, 7)); /* 0x8080808080808080 */

    emit(x, enc_ubfx(T2, T1, 3, 61)); /* count8 = limit / 8 */
    uint32_t *no8 = here(x);
    emit(x, enc_cbz_x(T2));
    uint32_t *loop8 = here(x);
    emit(x, enc_ldr_post(3, 6, T0, 8));
    emit(x, enc_eor_lsr(6, 6, 3, 0));
    emit(x, enc_sub_reg(T1, 6, 4));
    emit(x, enc_bic_reg(T1, T1, 6));
    emit(x, enc_and_reg(T1, T1, 5));
    uint32_t *hit_word = here(x);
    emit(x, enc_cbnz_x(T1));
    emit(x, enc_sub_imm(T2, T2, 1, 0));
    uint32_t *back8 = here(x);
    emit(x, enc_cbnz_x(T2));
    patch_branch(x->wdelta, back8, loop8);

    patch_branch(x->wdelta, no8, here(x));
    emit(x, enc_ldr_x(T2, CTX, x0 + 72));
    emit(x, enc_and_low(T2, T2, 3)); /* limit & 7 */
    uint32_t *no1 = here(x);
    emit(x, enc_cbz_x(T2));
    emit(x, enc_and_low(3, 1, 8));
    uint32_t *loop1 = here(x);
    emit(x, enc_ldr_post(0, 6, T0, 1));
    emit(x, enc_eor_lsr(6, 6, 3, 0));
    uint32_t *hit_byte = here(x);
    emit(x, enc_cbz_x(6));
    emit(x, enc_sub_imm(T2, T2, 1, 0));
    uint32_t *back1 = here(x);
    emit(x, enc_cbnz_x(T2));
    patch_branch(x->wdelta, back1, loop1);

    /* Not found in first page: return NULL if n == limit, else fall back for cross-page scan */
    patch_branch(x->wdelta, no1, here(x));
    emit(x, enc_ldr_x(T1, CTX, x0 + 72));
    emit(x, enc_sub_reg(T1, 2, T1));
    uint32_t *cross = here(x);
    emit(x, enc_cbnz_x(T1));
    emit(x, enc_movz(0, 0, 0));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_ldr_x(7, CTX, x0 + 56));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    patch_branch(x->wdelta, cross, here(x));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_ldp_x(7, T0, CTX, (int)x0 + 56));
    patch_branch(x->wdelta, fail, here(x));
    emit(x, enc_br(T0));

    patch_branch(x->wdelta, hit_word, here(x));
    emit(x, enc_rbit_x(T1, T1));
    emit(x, enc_clz_x(T1, T1));
    emit(x, enc_ubfx(T1, T1, 3, 61)); /* byte index 0..7 */
    emit(x, enc_sub_imm(T0, T0, 8, 0));
    emit(x, enc_sub_reg(T0, T0, 7));
    emit(x, enc_add_lsl(T0, T0, T1, 0));
    emit(x, enc_add_lsl(0, 0, T0, 0));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_ldr_x(7, CTX, x0 + 56));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));

    patch_branch(x->wdelta, hit_byte, here(x));
    emit(x, enc_sub_imm(T0, T0, 1, 0));
    emit(x, enc_sub_reg(T0, T0, 7));
    emit(x, enc_add_lsl(0, 0, T0, 0));
    emit(x, enc_ldp_x(3, 4, CTX, (int)x0 + 24));
    emit(x, enc_ldp_x(5, 6, CTX, (int)x0 + 40));
    emit(x, enc_ldr_x(7, CTX, x0 + 56));
    emit(x, enc_b((intptr_t)d->memop_ret - (intptr_t)here(x)));
    return entry;
}

/* The enter and exit routines: placed at the start of the code cache, so that every exit stub can
 * reach them with one b */
void dbt_emit_routines(struct appine_dbt *d)
{
    struct xlate routines = {.d = d, .buf = d->cache, .wdelta = d->rw_delta, .st = d->st}, *x = &routines;
    size_t x0 = offsetof(struct appine_cpu, x), v0 = offsetof(struct appine_cpu, v);

    /* uint64_t enter(struct appine_cpu *cpu, uint32_t *code): save the callee-saved registers
     * (including d8–d15) and the host FPCR. Frame layout: x29/x30, the five pairs of x27–x19, 8
     * unused bytes, host FPCR (+104), d8–d15 (+112) */
    d->enter = here(x);
    emit(x, enc_stp_x_pre(29, 30, 31, -FRAME_BYTES));
    emit(x, enc_stp_x(27, 28, 31, 16));
    emit(x, enc_stp_x(25, 26, 31, 32));
    emit(x, enc_stp_x(23, 24, 31, 48));
    emit(x, enc_stp_x(21, 22, 31, 64));
    emit(x, enc_stp_x(19, 20, 31, 80));
    for (unsigned r = 8; r < 16; r += 2)
        emit(x, enc_stp_d(r, r + 1, 31, (int)(112 + 8 * (r - 8))));
    emit(x, enc_mrs_fpcr(T1));
    emit(x, enc_str_x(T1, 31, 104));
    emit(x, enc_mov(CTX, 0));
    emit(x, enc_mov(T0, 1));
    /* The guest's FP state stays in host registers throughout translated code (the engine/dbt map) */
    emit(x, enc_ldr_x(T1, CTX, offsetof(struct appine_cpu, fpcr)));
    emit(x, enc_msr_fpcr(T1));
    emit(x, enc_ldr_x(T1, CTX, offsetof(struct appine_cpu, fpsr)));
    emit(x, enc_msr_fpsr(T1));
    emit(x, enc_ldr_x(T1, CTX, offsetof(struct appine_cpu, nzcv)));
    emit(x, enc_msr_nzcv(T1));
    emit_add_const(x, T1, CTX, (int64_t)v0);
    for (unsigned q = 0; q < 32; q += 2)
        emit(x, enc_ldp_q(q, q + 1, T1, (int)(16 * q)));
    emit_add_const(x, T1, CTX, (int64_t)x0);
    move_guest_regs(x, T1, false);
    emit(x, enc_ldr_x(SP_HOST, CTX, offsetof(struct appine_cpu, sp)));
    emit(x, enc_br(T0));

    /* The two entries used by stubs: T1 points to the adr in the stub, and the pc is in the data
     * words at the end of the stub (emit_link_stub) */
    d->exit_full = here(x);
    emit(x, enc_ldur_x(T0, T1, 12));
    uint32_t *join = here(x);
    emit(x, enc_b(0));
    d->exit_stub = here(x);
    emit(x, enc_ldur_x(T0, T1, 8));
    emit(x, enc_ubfx(T2, T0, PACKED_PC_BITS, 64 - PACKED_PC_BITS));
    emit(x, enc_and_low(T0, T0, PACKED_PC_BITS));
    patch_branch(x->wdelta, join, here(x));
    emit(x, enc_sub_imm(T1, T1, 4, 0));
    /* Exit: T0 = guest pc, T1 = patch site (meaningful only for link stubs), T2 = reason */
    d->exit = here(x);
    emit(x, enc_str_x(T0, CTX, offsetof(struct appine_cpu, pc)));
    emit(x, enc_str_x(T1, CTX, offsetof(struct appine_cpu, dbt_site)));
    emit(x, enc_str_x(T2, CTX, offsetof(struct appine_cpu, dbt_reason)));
    emit(x, enc_mrs_nzcv(T0));
    emit(x, enc_str_x(T0, CTX, offsetof(struct appine_cpu, nzcv)));
    emit_add_const(x, T1, CTX, (int64_t)x0);
    move_guest_regs(x, T1, true);
    emit(x, enc_str_x(SP_HOST, CTX, offsetof(struct appine_cpu, sp)));
    emit_add_const(x, T1, CTX, (int64_t)v0);
    for (unsigned q = 0; q < 32; q += 2)
        emit(x, enc_stp_q(q, q + 1, T1, (int)(16 * q)));
    emit(x, enc_mrs_fpsr(T0));
    emit(x, enc_str_x(T0, CTX, offsetof(struct appine_cpu, fpsr)));
    emit(x, enc_ldr_x(T0, 31, 104));
    emit(x, enc_msr_fpcr(T0));
    emit(x, enc_mov(0, T2));
    for (unsigned r = 8; r < 16; r += 2)
        emit(x, enc_ldp_d(r, r + 1, 31, (int)(112 + 8 * (r - 8))));
    emit(x, enc_ldp_x(19, 20, 31, 80));
    emit(x, enc_ldp_x(21, 22, 31, 64));
    emit(x, enc_ldp_x(23, 24, 31, 48));
    emit(x, enc_ldp_x(25, 26, 31, 32));
    emit(x, enc_ldp_x(27, 28, 31, 16));
    emit(x, enc_ldp_x_post(29, 30, 31, FRAME_BYTES));
    emit(x, enc_ret());

    d->refill[0] = emit_refill(x, false);
    d->refill[1] = emit_refill(x, true);
    d->lookup = emit_lookup(x, d);

    /* Landing pad of empty shadow return stack entries: look up by guest x30, as for an indirect
     * branch that misses the jump cache */
    d->rs_miss = here(x);
    emit(x, enc_mov(T0, 30));
    emit(x, enc_b((intptr_t)d->lookup - (intptr_t)here(x)));

    d->memop_ret = emit_memop_ret(x, d);
    d->memop_memset = emit_memop_memset(x, d);
    d->memop_memmove = emit_memop_memmove(x, d);
    d->memop_memcmp = emit_memop_memcmp(x, d);
    d->memop_memchr = emit_memop_memchr(x, d);

    if (x->n >= MAX_BLOCK_WORDS)
        appine_guard_fail();
    d->routine_words = d->used_words = x->n;
    dbt_sync_range(d, d->cache, d->cache + x->n);
}

#endif /* DBT_SUPPORTED */
