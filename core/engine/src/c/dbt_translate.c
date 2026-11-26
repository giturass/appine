/*
 * Tier 1 instruction translator: data processing, inline soft-TLB memory accesses, exclusives and
 * atomics, branches, system instructions, and block-local constant/affine tracking.
 */
#define _GNU_SOURCE
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

/* The instruction at pc jumps directly to target */
static unsigned chain_reason(uint64_t pc, uint64_t target)
{
    return target > pc ? R_CHAIN_FWD : R_CHAIN;
}

/* Branch to the refill stub on a TLB miss: one per memory-access instruction, not merged with
 * other stubs. After a successful refill, execution continues at the next instruction (the access
 * itself) */
static void emit_to_refill(struct xlate *x, uint64_t pc, unsigned bytes, bool write, unsigned fail)
{
    if (x->nstubs < MAX_STUBS)
        x->stubs[x->nstubs] = (struct stub){.reason = STUB_REFILL,
                                            .pc = pc,
                                            .resume = here(x) + 1,
                                            .bytes = bytes,
                                            .write = write,
                                            .fail = fail};
    if (x->nfixups < MAX_FIXUPS)
        x->fixups[x->nfixups] = (struct fixup){here(x), FIX_IMM19, x->nstubs};
    x->nstubs++;
    x->nfixups++; /* overflow is checked by prepare() */
    emit(x, enc_cbnz_x(T1));
}

static bool fallback(struct xlate *x, uint64_t pc)
{
    x->st->insns_fallback++;
    emit_exit_stub(x, R_INTERP, pc);
    return false;
}

/* ---- Data processing: copy verbatim or rewrite stolen registers ---- */


/* List the register fields of a data-processing instruction; Tier 0 has already confirmed that the
 * encoding is valid */
bool dbt_dp_operands(uint32_t insn, struct operands *o)
{
    o->n = 0;
    o->writes_rd = true;
    if (FIELD(insn, 28, 26) == 4) { /* immediate */
        switch (FIELD(insn, 25, 23)) {
        case 2: /* ADD/SUB (immediate) */
            add_operand(o, 0, !BIT(insn, 29));
            add_operand(o, 5, true);
            return true;
        case 4: /* logical (immediate) */
            add_operand(o, 0, FIELD(insn, 30, 29) != 3);
            add_operand(o, 5, false);
            return true;
        case 5: /* MOVN/MOVZ/MOVK */
            add_operand(o, 0, false);
            return true;
        case 6: /* bitfield */
            add_operand(o, 0, false);
            add_operand(o, 5, false);
            return true;
        case 7: /* EXTR */
            add_operand(o, 0, false);
            add_operand(o, 5, false);
            add_operand(o, 16, false);
            return true;
        default:
            return false;
        }
    }
    unsigned op2 = FIELD(insn, 24, 21);
    if (!BIT(insn, 28)) {
        bool extended = (op2 & 9) == 9;
        add_operand(o, 0, extended && !BIT(insn, 29));
        add_operand(o, 5, extended);
        add_operand(o, 16, false);
        return true;
    }
    switch (op2) {
    case 0: /* ADC/SBC */
        if (FIELD(insn, 15, 10)) { /* RMIF, SETF8, SETF16 (FlagM): only read Rn, only write flags */
            o->writes_rd = false;
            add_operand(o, 5, false);
            return true;
        }
        /* fallthrough */
    case 4: /* the CSEL family */
        add_operand(o, 0, false);
        add_operand(o, 5, false);
        add_operand(o, 16, false);
        return true;
    case 2: /* CCMP/CCMN: no Rd, bits 4:0 are nzcv */
        o->writes_rd = false;
        add_operand(o, 5, false);
        if (!BIT(insn, 11))
            add_operand(o, 16, false);
        return true;
    case 6:
        add_operand(o, 0, false);
        add_operand(o, 5, false);
        if (!BIT(insn, 30))
            add_operand(o, 16, false);
        return true;
    default:
        if (!(op2 & 8))
            return false;
        add_operand(o, 0, false);
        add_operand(o, 5, false);
        add_operand(o, 16, false);
        add_operand(o, 10, false);
        return true;
    }
}

/* Replace stolen guest registers with temporaries: load them from the cpu struct first, and write
 * Rd back after execution */
static bool emit_operands(struct xlate *x, uint32_t insn, const struct operands *o)
{
    const unsigned pool[3] = {T0, T1, T2};
    unsigned guest[3], nmap = 0, rd_host = 0, rd_guest = 0;
    bool rd_stolen = false;
    uint32_t out = insn;
    bool renamed = false;
    for (unsigned i = 0; i < o->n; i++) {
        unsigned r = (insn >> o->pos[i]) & 31;
        if (r == 31 && o->sp[i]) { /* SP is already in a host register; just change the number */
            out = (out & ~(31u << o->pos[i])) | SP_HOST << o->pos[i];
            renamed = true;
            continue;
        }
        unsigned g = r;
        if (!is_stolen(g))
            continue;
        unsigned k;
        for (k = 0; k < nmap && guest[k] != g; k++)
            ;
        if (k == nmap) {
            if (nmap == 3)
                return false;
            guest[nmap++] = g;
        }
        out = (out & ~(31u << o->pos[i])) | pool[k] << o->pos[i];
        if (o->pos[i] == 0 && o->writes_rd) {
            rd_stolen = true;
            rd_host = pool[k];
            rd_guest = g;
        }
    }
    if (nmap == 0 && !renamed) {
        emit(x, insn);
        x->st->insns_copied++;
        return true;
    }
    if (nmap == 3)
        x->t2_group = -1; /* later members get the host base back from the slot (plan_group) */
    for (unsigned k = 0; k < nmap; k++)
        emit_load_guest(x, pool[k], guest[k]);
    emit(x, out);
    if (rd_stolen)
        emit_store_guest(x, rd_host, rd_guest);
    x->st->insns_remapped++;
    return true;
}

/* ADR/ADRP: the result is a compile-time constant */
static void emit_pcrel(struct xlate *x, uint32_t insn, uint64_t pc)
{
    unsigned rd = insn & 31;
    uint64_t imm = ((uint64_t)FIELD(insn, 23, 5) << 2) | FIELD(insn, 30, 29);
    int64_t off = (int64_t)(imm << 43) >> 43;
    uint64_t v = BIT(insn, 31) ? (pc & ~UINT64_C(0xfff)) + ((uint64_t)off << 12) : pc + (uint64_t)off;
    x->st->insns_remapped++;
    if (rd == 31)
        return;
    if (is_stolen(rd)) {
        emit_mov_const(x, T0, v);
        emit_store_guest(x, T0, rd);
    } else {
        emit_mov_const(x, rd, v);
    }
}

/* ---- Memory access: the inline TLB fast path ---- */


bool dbt_decode_memop(uint32_t insn, uint64_t pc, struct memop *m)
{
    unsigned size = FIELD(insn, 31, 30), opc = FIELD(insn, 23, 22);
    *m = (struct memop){.rt = insn & 31, .rn = FIELD(insn, 9, 5), .size = size};
    if (BIT(insn, 26))
        return false;
    if ((insn & 0x3b000000) == 0x18000000) { /* LDR (literal), bits 31:30 are opc */
        static const unsigned sizes[3] = {2, 3, 2}, opcs[3] = {1, 1, 2};
        m->mode = M_LITERAL;
        m->imm = (int64_t)(pc + (uint64_t)(((int64_t)((uint64_t)FIELD(insn, 23, 5) << 45) >> 45) * 4));
        if (size == 3) {
            m->prefetch = true;
            return true;
        }
        m->load = true;
        m->size = sizes[size];
        m->final = enc_ldst_regoff(sizes[size], opcs[size], 0, 0, 0);
        return true;
    }
    if ((insn & 0x3a000000) == 0x28000000) { /* LDP/STP/LDPSW */
        unsigned idx = FIELD(insn, 24, 23);
        m->pair = true;
        m->load = BIT(insn, 22);
        m->rt2 = FIELD(insn, 14, 10);
        m->size = size == 2 ? 3 : 2;
        m->imm = ((int64_t)((uint64_t)FIELD(insn, 21, 15) << 57) >> 57) * (1 << m->size);
        m->mode = idx == 1 ? M_POST : idx == 3 ? M_PRE : M_OFFSET;
        m->final = (insn & 0xc0400000) | 0x29000000; /* signed-offset form, offset 0 */
        return true;
    }
    if (BIT(insn, 29) != 1 || FIELD(insn, 28, 27) != 3)
        return false;
    m->load = opc != 0;
    m->prefetch = size == 3 && opc == 2;
    m->final = enc_ldst_regoff(size, opc, 0, 0, 0);
    if ((insn & 0x3b000000) == 0x39000000) {
        m->mode = M_OFFSET;
        m->imm = (int64_t)FIELD(insn, 21, 10) << size;
        return true;
    }
    if ((insn & 0x3b200000) == 0x38000000) {
        unsigned op = FIELD(insn, 11, 10);
        m->imm = (int64_t)((uint64_t)FIELD(insn, 20, 12) << 55) >> 55;
        m->mode = op == 1 ? M_POST : op == 3 ? M_PRE : M_OFFSET;
        return true;
    }
    if ((insn & 0x3b200c00) == 0x38200800) {
        m->mode = M_REG;
        m->rm = FIELD(insn, 20, 16);
        m->option = FIELD(insn, 15, 13);
        m->shift = BIT(insn, 12) ? size : 0;
        return true;
    }
    return false;
}

/* Total bytes accessed by LD1–LD4/ST1–ST4; Tier 0 has already confirmed that the encoding is
 * valid */
static unsigned structure_bytes(uint32_t insn)
{
    unsigned q = BIT(insn, 30), opcode = FIELD(insn, 15, 12), size = FIELD(insn, 11, 10);
    if (!BIT(insn, 24)) { /* multiple structures: opcode maps to rpt × selem registers */
        static const uint8_t regs[16] = {[0x0] = 4, [0x2] = 4, [0x4] = 3, [0x6] = 3,
                                         [0x7] = 1, [0x8] = 2, [0xa] = 2};
        return regs[opcode] * (q ? 16u : 8u);
    }
    unsigned selem = ((opcode >> 1 & 1) << 1 | BIT(insn, 21)) + 1, scale = opcode >> 2;
    if (scale == 3) /* LD1R–LD4R */
        scale = size;
    else if (scale == 2 && (size & 1))
        scale = 3;
    return selem << scale;
}

/* SIMD&FP memory access (bit 26 set): decoded the same way as Tier 0's appine_simd_ldst */
bool dbt_decode_simd_memop(uint32_t insn, uint64_t pc, struct memop *m)
{
    unsigned size = FIELD(insn, 31, 30), opc = FIELD(insn, 23, 22);
    *m = (struct memop){.simd = true, .rt = insn & 31, .rn = FIELD(insn, 9, 5)};
    if ((insn & 0xbe000000) == 0x0c000000) { /* LD1–LD4/ST1–ST4 */
        m->structure = true;
        m->load = BIT(insn, 22);
        m->bytes = structure_bytes(insn);
        m->rm = FIELD(insn, 20, 16);
        m->mode = BIT(insn, 23) ? M_POST : M_OFFSET;
        if (m->mode == M_POST) {
            m->wb_reg = m->rm != 31;
            m->imm = m->bytes;
        }
        /* Change to the form without writeback, with Rn replaced by the host address */
        m->final = insn & ~(1u << 23 | 31u << 16 | 31u << 5);
        return true;
    }
    if ((insn & 0x3f000000) == 0x1c000000) { /* LDR (literal): bits 31:30 are opc */
        m->mode = M_LITERAL;
        m->imm = (int64_t)(pc + (uint64_t)(((int64_t)((uint64_t)FIELD(insn, 23, 5) << 45) >> 45) * 4));
        m->load = true;
        m->size = 2 + size;
        m->final = size == 2 ? enc_ldst_regoff(0, 3, 0, 0, 0) : enc_ldst_regoff(2 + size, 1, 0, 0, 0);
        m->final |= 1u << 26;
        return true;
    }
    if ((insn & 0x3e000000) == 0x2c000000) { /* LDP/STP/LDNP/STNP */
        unsigned idx = FIELD(insn, 24, 23);
        m->pair = true;
        m->load = BIT(insn, 22);
        m->rt2 = FIELD(insn, 14, 10);
        m->size = 2 + size;
        m->imm = ((int64_t)((uint64_t)FIELD(insn, 21, 15) << 57) >> 57) * (1 << m->size);
        m->mode = idx == 1 ? M_POST : idx == 3 ? M_PRE : M_OFFSET;
        m->final = (insn & 0xc0400000) | 0x2d000000; /* signed-offset form, offset 0 */
        return true;
    }
    /* Single register: size = 00 with opc = 1x is the 128-bit Q register */
    m->load = opc & 1;
    m->size = (size == 0 && (opc & 2)) ? 4 : size;
    m->final = enc_ldst_regoff(size, opc, 0, 0, 0) | 1u << 26;
    if ((insn & 0x3f000000) == 0x3d000000) {
        m->mode = M_OFFSET;
        m->imm = (int64_t)FIELD(insn, 21, 10) << m->size;
        return true;
    }
    if ((insn & 0x3f200000) == 0x3c000000) {
        unsigned op = FIELD(insn, 11, 10);
        m->imm = (int64_t)((uint64_t)FIELD(insn, 20, 12) << 55) >> 55;
        m->mode = op == 1 ? M_POST : op == 3 ? M_PRE : M_OFFSET;
        return true;
    }
    if ((insn & 0x3f200c00) == 0x3c200800) {
        m->mode = M_REG;
        m->rm = FIELD(insn, 20, 16);
        m->option = FIELD(insn, 15, 13);
        m->shift = BIT(insn, 12) ? m->size : 0;
        return true;
    }
    return false;
}

/*
 * Look up the TLB with T0 = guest address; on a hit T2 = addend. Take the entry of the page of
 * the last byte and compare it with the page of the first byte: the TLB is direct-mapped, so for
 * a cross-page access the first page's page number cannot appear in the next page's entry, and
 * this one comparison also rules out cross-page accesses. A miss or a cross-page access enters the
 * refill routine, and a failed refill exits with `fail`. `in_granule` means the access lies within
 * one aligned 16 bytes and cannot cross a page, so the first byte's page can be used directly.
 * `last_ready` means the caller has already computed the last byte's address into T1
 * ([`emit_address_imm`]).
 */
void dbt_emit_tlb_check(struct xlate *x, uint64_t pc, unsigned bytes, bool write, bool in_granule,
                           bool last_ready, unsigned fail)
{
    x->t2_group = -1;
    unsigned last = T0;
    if (last_ready) {
        last = T1;
    } else if (bytes > 1 && !in_granule) {
        emit(x, enc_add_imm(T1, T0, bytes - 1, 0));
        last = T1;
    }
    emit(x, enc_ubfx(T1, last, APPINE_PAGE_SHIFT, TLB_BITS));
    emit(x, enc_add_lsl(T1, CTX, T1, 5));
    emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF + (write ? 16 : 0)));
    emit(x, enc_eon_lsr(T1, T1, T0, APPINE_PAGE_SHIFT)); /* tag is the inverted page number */
    emit_to_refill(x, pc, bytes, write, fail);
}

/*
 * The access's guest address is known at translation time (`addr`, also in T0, and the access
 * does not cross a page): the entry's position is a constant, so loading the entry need not wait
 * for T0 to be computed (global variables: for an access after ADRP, T0 waits for the few movks
 * ADRP was turned into).
 */
void dbt_emit_tlb_check_known(struct xlate *x, uint64_t pc, uint64_t addr, unsigned bytes, bool write,
                                 unsigned fail)
{
    x->t2_group = -1;
    uint64_t off = TLB_OFF + ((addr >> APPINE_PAGE_SHIFT) & (APPINE_TLB_ENTRIES - 1)) * 32 + (write ? 16 : 0);
    int64_t lo = (int64_t)(off & 0xfff);
    uint64_t hi = off - (uint64_t)lo;
    if (lo > 504 && lo >= 4096 - 512) { /* ldp offsets are -512..504 */
        hi += 4096;
        lo -= 4096;
    }
    unsigned b = CTX;
    if (hi) {
        emit(x, enc_add_imm(T1, CTX, (uint32_t)(hi >> 12), 1));
        b = T1;
    }
    if (lo > 504) {
        emit(x, enc_add_imm(T1, b, (uint32_t)lo, 0));
        b = T1;
        lo = 0;
    }
    emit(x, enc_ldp_x(T1, T2, b, (int)lo));
    emit(x, enc_eon_lsr(T1, T1, T0, APPINE_PAGE_SHIFT)); /* tag is the inverted page number */
    emit_to_refill(x, pc, bytes, write, fail);
}

/* The guest address of a `bytes`-byte access at offset `imm` from register `rn`, whose value is
 * known; returns false if the register's value is not known or the access crosses a page */
bool dbt_known_address(const struct xlate *x, unsigned rn, int64_t imm, unsigned bytes, uint64_t *addr)
{
    if (rn > 30 || !(x->konst >> rn & 1))
        return false;
    *addr = x->kval[rn] + (uint64_t)imm;
    return ((*addr ^ (*addr + bytes - 1)) >> APPINE_PAGE_SHIFT) == 0;
}

/*
 * T0 = base + imm. When the last byte's page is needed, T1 = base + imm + bytes - 1 is computed
 * straight from the base, not through T0: the TLB index need not wait for T0, which takes one
 * step off the access's dependency chain (pointer-chasing loads go through the whole chain every
 * time), with the same instruction count. Returns whether T1 has been computed.
 */
bool dbt_emit_address_imm(struct xlate *x, unsigned base, int64_t imm, unsigned bytes, bool in_granule)
{
    int64_t last = imm + (int64_t)bytes - 1;
    bool fold = bytes > 1 && !in_granule && last > -4096 && last < 4096;
    if (fold)
        emit(x, last >= 0 ? enc_add_imm(T1, base, (uint32_t)last, 0) : enc_sub_imm(T1, base, (uint32_t)-last, 0));
    emit_add_const(x, T0, base, imm);
    return fold;
}


/* Check SP's alignment before an SP-based access; not needed if it was already checked in this
 * block and SP has since changed only by multiples of 16 */
void dbt_emit_sp_check(struct xlate *x, uint64_t pc)
{
    if (x->sp_aligned)
        return;
    emit(x, enc_and_low(T1, SP_HOST, 4));
    emit_to_stub(x, enc_cbnz_x(T1), FIX_IMM19, R_INTERP, pc);
    x->sp_aligned = true;
}

/* Whether SP is still aligned after it changes by `delta` */
void dbt_sp_moved(struct xlate *x, int64_t delta)
{
    if (delta & 15)
        x->sp_aligned = false;
}


static void emit_memop(struct xlate *x, const struct memop *m, uint64_t pc)
{
    unsigned rn = m->rn == 31 ? REG_SP : m->rn;
    int slot = dbt_plan_group(x, m);
    if (slot >= 0) {
        dbt_emit_group(x, m, pc, slot);
        return;
    }

    /* 1. guest address → T0 */
    bool in_granule = false, last_ready = false, known = false;
    uint64_t addr = 0;
    if (m->mode == M_LITERAL) {
        emit_mov_const(x, T0, (uint64_t)m->imm);
        addr = (uint64_t)m->imm;
        known = ((addr ^ (addr + memop_bytes(m) - 1)) >> APPINE_PAGE_SHIFT) == 0;
    } else {
        unsigned base = rn == REG_SP ? SP_HOST : rn;
        if (rn == REG_SP) { /* SP must be 16-byte aligned */
            dbt_emit_sp_check(x, pc);
            int64_t off = m->mode == M_POST ? 0 : m->imm;
            in_granule = m->mode != M_REG && (off & 15) + memop_bytes(m) <= 16;
        } else if (is_stolen(rn)) {
            emit_load_guest(x, T0, rn);
            base = T0;
        }
        switch (m->mode) {
        case M_REG: {
            unsigned idx = m->rm;
            if (is_stolen(idx)) {
                emit_load_guest(x, T1, idx);
                idx = T1;
            }
            emit(x, enc_add_ext(T0, base, idx, m->option, m->shift));
            break;
        }
        case M_POST:
            last_ready = dbt_emit_address_imm(x, base, 0, memop_bytes(m), in_granule);
            break;
        default:
            known = m->mode == M_OFFSET && dbt_known_address(x, m->rn, m->imm, memop_bytes(m), &addr);
            if (known)
                emit_add_const(x, T0, base, m->imm);
            else
                last_ready = dbt_emit_address_imm(x, base, m->imm, memop_bytes(m), in_granule);
            break;
        }
    }

    /* 2. TLB */
    if (known)
        dbt_emit_tlb_check_known(x, pc, addr, memop_bytes(m), !m->load, R_INTERP);
    else
        dbt_emit_tlb_check(x, pc, memop_bytes(m), !m->load, in_granule, last_ready, R_INTERP);

    /* 3. Access host memory */
    if (m->structure) {
        emit(x, enc_add_lsl(T2, T2, T0, 0));
        emit(x, m->final | T2 << 5);
    } else if (!m->pair) {
        if (m->simd || !is_stolen(m->rt)) {
            emit(x, m->final | T0 << 16 | T2 << 5 | m->rt);
        } else if (m->load) {
            emit(x, m->final | T0 << 16 | T2 << 5 | T1);
            emit_store_guest(x, T1, m->rt);
        } else {
            emit_load_guest(x, T1, m->rt);
            emit(x, m->final | T0 << 16 | T2 << 5 | T1);
        }
    } else {
        emit(x, enc_add_lsl(T2, T2, T0, 0));
        bool s1 = !m->simd && is_stolen(m->rt), s2 = !m->simd && is_stolen(m->rt2);
        unsigned h1 = s1 ? T0 : m->rt, h2 = s2 ? T1 : m->rt2;
        if (!m->load) {
            if (s1)
                emit_load_guest(x, T0, m->rt);
            if (s2)
                emit_load_guest(x, T1, m->rt2);
        }
        emit(x, m->final | h2 << 10 | T2 << 5 | h1);
        if (m->load) {
            if (s1)
                emit_store_guest(x, T0, m->rt);
            if (s2)
                emit_store_guest(x, T1, m->rt2);
        }
    }

    /* 4. Base writeback */
    if (m->mode == M_PRE || m->mode == M_POST) {
        unsigned inc = m->rm, dst = rn == REG_SP ? SP_HOST : is_stolen(rn) ? T0 : rn;
        if (m->wb_reg && is_stolen(inc)) {
            emit_load_guest(x, T1, inc);
            inc = T1;
        }
        if (dst == T0)
            emit_load_guest(x, T0, rn);
        if (m->wb_reg)
            emit(x, enc_add_lsl(dst, dst, inc, 0));
        else
            emit_add_const(x, dst, dst, m->imm);
        if (dst == T0)
            emit_store_guest(x, T0, rn);
        if (rn == REG_SP)
            dbt_sp_moved(x, m->wb_reg ? 1 : m->imm);
    }
    x->st->insns_memory++;
}


/* ---- Exclusive accesses, acquire/release, LSE atomics (the engine/dbt map) ---- */

/*
 * Address of an atomic access, the same as Tier 0's atomic_target: natural alignment is required
 * (so it never crosses a page), and with SP as the base SP must be 16-byte aligned; otherwise
 * Tier 0 is left to report the alignment fault. Afterwards T0 = guest address and T2 = host
 * address.
 */
static void emit_atomic_address_off(struct xlate *x, unsigned rn, int64_t off, unsigned bytes,
                                    bool write, uint64_t pc)
{
    unsigned base = rn == 31 ? SP_HOST : rn;
    if (rn == 31)
        dbt_emit_sp_check(x, pc);
    else if (is_stolen(rn)) {
        emit_load_guest(x, T0, rn);
        base = T0;
    }
    if (off) {
        emit_add_const(x, T0, base, off);
        base = T0;
    }
    /* Match Tier 0's exclusive monitor even if LDXR and STXR use different tags. */
    emit(x, enc_and_low(T0, base, DATA_TAG_SHIFT));
    if (bytes > 1) {
        emit(x, enc_and_low(T1, T0, (unsigned)__builtin_ctz(bytes)));
        emit_to_stub(x, enc_cbnz_x(T1), FIX_IMM19, R_INTERP, pc);
    }
    dbt_emit_tlb_check(x, pc, bytes, write, true, false, R_INTERP);
    emit(x, enc_add_lsl(T2, T2, T0, 0));
    x->st->insns_memory++;
}

static void emit_atomic_address(struct xlate *x, unsigned rn, unsigned bytes, bool write, uint64_t pc)
{
    emit_atomic_address_off(x, rn, 0, bytes, write, pc);
}

struct atomic_operand {
    unsigned pos;
    bool in, out;
};

/* Execute verbatim on host address T2: stolen register operands are replaced by T0 and T1 */
static void emit_on_host_address(struct xlate *x, uint32_t insn, const struct atomic_operand *ops,
                                 unsigned n)
{
    const unsigned pool[2] = {T0, T1};
    uint32_t out = (insn & ~(31u << 5)) | T2 << 5;
    for (unsigned i = 0; i < n; i++) {
        unsigned r = (insn >> ops[i].pos) & 31;
        if (!is_stolen(r))
            continue;
        out = (out & ~(31u << ops[i].pos)) | pool[i] << ops[i].pos;
        if (ops[i].in)
            emit_load_guest(x, pool[i], r);
    }
    emit(x, out);
    for (unsigned i = 0; i < n; i++) {
        unsigned r = (insn >> ops[i].pos) & 31;
        if (is_stolen(r) && ops[i].out)
            emit_store_guest(x, pool[i], r);
    }
}

/* Write STXR's status: 0 for success, 1 for failure */
static void emit_status(struct xlate *x, unsigned rs, unsigned v)
{
    if (rs == 31)
        return;
    unsigned h = is_stolen(rs) ? T0 : rs;
    emit(x, enc_movz(h, v, 0));
    if (h == T0)
        emit_store_guest(x, T0, rs);
}

/*
 * LDXR/STXR are rewritten into a compare-and-swap (the same as Tier 0): LDXR records the address,
 * the size and the value it read; STXR first confirms that the exclusive marker is for the same
 * address and the same size, then does a CAS on the host address with ldaxr/stlxr. Between the two
 * instructions there is only register arithmetic, so the host's exclusive monitor is not cleared
 * by our own memory accesses.
 */
static bool translate_exclusive(struct xlate *x, uint32_t insn, uint64_t pc)
{
    unsigned size = FIELD(insn, 31, 30), bytes = 1u << size;
    unsigned rs = FIELD(insn, 20, 16), rn = FIELD(insn, 9, 5), rt = insn & 31;
    size_t addr = offsetof(struct appine_cpu, excl_addr), value = offsetof(struct appine_cpu, excl_value),
           len = offsetof(struct appine_cpu, excl_size);

    if (BIT(insn, 22)) { /* LDXR/LDAXR */
        unsigned h = (rt == 31 || is_stolen(rt)) ? T1 : rt;
        emit_atomic_address(x, rn, bytes, false, pc);
        emit(x, BIT(insn, 15) ? enc_ldar(size, h, T2) : enc_ldr_size(size, h, T2));
        emit(x, enc_str_x(T0, CTX, addr));
        emit(x, enc_str_x(h, CTX, value));
        emit(x, enc_movz(T0, bytes, 0));
        emit(x, enc_str_w(T0, CTX, len));
        if (h == T1 && rt != 31)
            emit_store_guest(x, T1, rt);
        return true;
    }

    emit_atomic_address(x, rn, bytes, true, pc);
    /*
     * The value to store is in a stolen register (libgcc's outline atomics all write it this way:
     * on Alpine they do not recognize LSE and always take the LL/SC loop): T0, T1 and T2 are all
     * in use in the CAS loop, so a guest register this instruction does not use is borrowed to
     * hold it. The borrowed register is first saved into its own slot in the cpu struct (unused
     * while translated code runs) and restored afterwards; nothing exits in between, and a host
     * fault does not restore guest state from the ucontext either (guard.c), so nobody can see
     * that it was borrowed. Previously the whole instruction went to Tier 0, exiting more than ten
     * thousand times on every node startup.
     */
    unsigned v = rt, borrow = 0;
    if (is_stolen(rt)) {
        while (borrow == rn || borrow == rs)
            borrow++;
        emit_store_guest(x, borrow, borrow);
        emit_load_guest(x, borrow, rt);
        v = borrow;
    }
    uint32_t *mismatch[2], *differ, *done;
    emit(x, enc_ldr_x(T1, CTX, addr));
    emit(x, enc_eor_lsr(T1, T1, T0, 0));
    mismatch[0] = here(x);
    emit(x, enc_cbnz_x(T1));
    emit(x, enc_ldr_w(T1, CTX, len));
    emit(x, enc_sub_imm(T1, T1, bytes, 0));
    mismatch[1] = here(x);
    emit(x, enc_cbnz_x(T1));
    uint32_t *loop = here(x);
    emit(x, enc_ldr_x(T1, CTX, value));
    emit(x, enc_ldaxr(size, T0, T2));
    emit(x, enc_eor_lsr(T0, T0, T1, 0));
    differ = here(x);
    emit(x, enc_cbnz_x(T0));
    emit(x, enc_stlxr(size, T1, v, T2));
    uint32_t *again = here(x);
    emit(x, enc_cbnz_x(T1));
    patch_local(x, again, loop);
    emit_status(x, rs, 0);
    done = here(x);
    emit(x, enc_b(0));
    patch_local(x, differ, here(x));
    emit(x, enc_clrex());
    patch_local(x, mismatch[0], here(x));
    patch_local(x, mismatch[1], here(x));
    emit_status(x, rs, 1);
    patch_local(x, done, here(x));
    if (v != rt)
        emit_load_guest(x, borrow, borrow);
    emit(x, enc_str_w(31, CTX, len));
    return true;
}

bool dbt_is_atomic(uint32_t insn)
{
    return (insn & 0x3f000000) == 0x08000000 || ((insn & 0x3f200c00) == 0x38200000 && !BIT(insn, 26)) ||
           (insn & 0x3f200c00) == 0x19000000;
}

/* The encoding has been confirmed valid by tier0_defined; when false is returned, no instruction
 * has been emitted yet */
static bool translate_atomic(struct xlate *x, uint32_t insn, uint64_t pc)
{
    unsigned size = FIELD(insn, 31, 30), rn = FIELD(insn, 9, 5);
    /* LRCPC2's LDAPUR* and STLUR*: check base plus offset, and execute verbatim on the host
     * address with the offset removed */
    if ((insn & 0x3f200c00) == 0x19000000) {
        bool load = FIELD(insn, 23, 22) != 0;
        int64_t off = (int64_t)((uint64_t)FIELD(insn, 20, 12) << 55) >> 55;
        struct atomic_operand rt = {0, !load, load};
        emit_atomic_address_off(x, rn, off, 1u << size, !load, pc);
        emit_on_host_address(x, insn & ~(0x1ffu << 12), &rt, 1);
        return true;
    }
    if ((insn & 0x3f000000) == 0x08000000) {
        unsigned o2 = BIT(insn, 23), o1 = BIT(insn, 21);
        if (!o2 && !o1)
            return translate_exclusive(x, insn, pc);
        if (!o2) { /* LDXP/STXP (size ≥ 2) go to Tier 0; neither CASP register pair may be stolen */
            unsigned rs = FIELD(insn, 20, 16), rt = insn & 31;
            if (size >= 2 || is_stolen(rs) || is_stolen(rs + 1) || is_stolen(rt) || is_stolen(rt + 1))
                return false;
            emit_atomic_address(x, rn, 8u << size, true, pc);
            emit(x, (insn & ~(31u << 5)) | T2 << 5);
            return true;
        }
        if (!o1) { /* LDAR/STLR */
            bool load = BIT(insn, 22);
            struct atomic_operand rt = {0, !load, load};
            emit_atomic_address(x, rn, 1u << size, !load, pc);
            emit_on_host_address(x, insn, &rt, 1);
            return true;
        }
        /* CAS: Rs is the compare value and also receives the old value */
        struct atomic_operand ops[2] = {{16, true, true}, {0, true, false}};
        emit_atomic_address(x, rn, 1u << size, true, pc);
        emit_on_host_address(x, insn, ops, 2);
        return true;
    }
    /* LDAPR (LRCPC; Tier 0 has confirmed the host has it): executed verbatim on the host address
     * like LDAR; Rs is not an operand */
    if ((insn & 0x3ffffc00) == 0x38bfc000) {
        struct atomic_operand rt = {0, false, true};
        emit_atomic_address(x, rn, 1u << size, false, pc);
        emit_on_host_address(x, insn, &rt, 1);
        return true;
    }
    /* LD<op>, SWP */
    struct atomic_operand ops[2] = {{16, true, false}, {0, false, true}};
    emit_atomic_address(x, rn, 1u << size, true, pc);
    emit_on_host_address(x, insn, ops, 2);
    return true;
}

/* ---- Branches and system instructions ---- */
/* The five FlagM and FlagM2 instructions: RMIF, SETF8/SETF16, CFINV, XAFLAG, AXFLAG. They all
 * change only NZCV, and in translated code the guest's NZCV is the host's (advertising them means
 * the host has them), so they run verbatim */
static bool is_flagm(uint32_t insn)
{
    return (insn & 0xffe07c10) == 0xba000400 || (insn & 0xffffbc1f) == 0x3a00080d ||
           insn == 0xd500401f || insn == 0xd500403f || insn == 0xd500405f;
}


/*
 * Function calls (BL, BLR): a host bl skips the "landing pad" right after it, so the host's
 * return address stack records the landing pad; the landing pad is a link stub linked to the
 * block at the guest return address. The bl's target pushes (guest return address, landing pad)
 * onto the shadow return stack and sets guest x30 to the return address. The caller then emits
 * the code that jumps to the callee (T0 unchanged).
 *
 * When RET sees that the guest address at the top of the stack equals x30, it pops and jumps
 * back to the landing pad with a host ret, predicted by the host's return address stack; when
 * they differ (longjmp, signal handlers, coroutine switches) it looks up the jump cache as usual.
 * Every entry in the stack jumps to code that continues at the guest address it records (empty
 * entries jump to rs_miss), so whatever the guest sets x30 to, it never jumps to the wrong
 * place.
 */
static void emit_call(struct xlate *x, uint64_t pc)
{
    size_t rs = offsetof(struct appine_cpu, dbt_rs);
    uint32_t *site = here(x);
    emit(x, enc_bl(0));
    emit_exit_stub(x, R_CHAIN, pc + 4); /* landing pad */
    patch_local(x, site, here(x));
    emit(x, enc_ldr_x(T1, CTX, rs));
    emit(x, enc_add_imm(T2, T1, 16, 0));
    emit(x, enc_bfxil_low(T1, T2, RS_SHIFT));
    emit(x, enc_str_x(T1, CTX, rs));
    /* Host x30 is the landing pad, and the guest return address is in the data words at its end
     * (emit_link_stub) */
    if ((pc + 4) >> PACKED_PC_BITS == 0) {
        emit(x, enc_ldur_x(T2, 30, 12));
        emit(x, enc_and_low(T2, T2, PACKED_PC_BITS));
    } else {
        emit(x, enc_ldur_x(T2, 30, 16));
    }
    emit(x, enc_stp_x(T2, 30, T1, 0));
    emit(x, enc_mov(30, T2));
}

/* RET: when the top of the stack matches, pop and jump back to the landing pad; otherwise fall
 * through to the jump-cache lookup after it */
static void emit_predicted_return(struct xlate *x)
{
    size_t rs = offsetof(struct appine_cpu, dbt_rs);
    emit(x, enc_ldr_x(T1, CTX, rs));
    emit(x, enc_ldp_x(T0, T2, T1, 0));
    emit(x, enc_eor_lsr(T0, T0, 30, 0));
    uint32_t *miss = here(x);
    emit(x, enc_cbnz_x(T0));
    emit(x, enc_sub_imm(T0, T1, 16, 0));
    emit(x, enc_bfxil_low(T1, T0, RS_SHIFT));
    emit(x, enc_str_x(T1, CTX, rs));
    emit(x, enc_ret_reg(T2));
    patch_local(x, miss, here(x));
}

/* Replace a conditional branch's register operand with a directly readable host register */
static uint32_t branch_operand(struct xlate *x, uint32_t insn)
{
    unsigned rt = insn & 31;
    if (!is_stolen(rt))
        return insn;
    emit_load_guest(x, T0, rt);
    return (insn & ~31u) | T0;
}

/* Copy an X register operand to T0. Register 31 denotes XZR here. */
static void emit_xreg_to_t0(struct xlate *x, unsigned reg)
{
    if (reg == 31)
        emit(x, enc_movz(T0, 0, 0));
    else if (is_stolen(reg))
        emit_load_guest(x, T0, reg);
    else
        emit(x, enc_mov(T0, reg));
}

/* A changed FPCR needs Tier 0 to set the guest mode for the next entry. */
static void emit_fpcr_write_check(struct xlate *x, unsigned src, uint64_t pc)
{
    emit_mov_const(x, T1, fpcr_write_mask());
    emit(x, enc_and_reg(T1, src, T1));
    emit(x, enc_ldr_x(T0, CTX, offsetof(struct appine_cpu, fpcr)));
    emit(x, enc_eor_lsr(T1, T1, T0, 0));
    emit_to_stub(x, enc_cbnz_x(T1), FIX_IMM19, R_INTERP, pc);
}

static bool translate_branch_sys(struct xlate *x, uint32_t insn, uint64_t pc)
{
    if ((insn & 0x7c000000) == 0x14000000) { /* B / BL */
        uint64_t target = pc + (uint64_t)(sext(FIELD(insn, 25, 0), 26) * 4);
        if (BIT(insn, 31))
            emit_call(x, pc);
        emit_exit_stub(x, chain_reason(pc, target), target);
        return false;
    }
    if ((insn & 0xff000010) == 0x54000000 || (insn & 0x7e000000) == 0x34000000) { /* B.cond/CBZ/CBNZ */
        uint64_t target = pc + (uint64_t)(sext(FIELD(insn, 23, 5), 19) * 4);
        /* Bits 4:0 of B.cond are the condition code, kept as is; CBZ/CBNZ's are a register */
        uint32_t base = BIT(insn, 30) ? insn : branch_operand(x, insn);
        emit_to_stub(x, base & ~(0x7ffffu << 5), FIX_IMM19, chain_reason(pc, target), target);
        return true; /* the not-taken side is translated next; the taken side is a side exit */
    }
    if ((insn & 0x7e000000) == 0x36000000) { /* TBZ/TBNZ */
        uint64_t target = pc + (uint64_t)(sext(FIELD(insn, 18, 5), 14) * 4);
        uint32_t base = branch_operand(x, insn) & ~(0x3fffu << 5);
        emit_to_stub(x, base, FIX_IMM14, chain_reason(pc, target), target);
        return true;
    }
    if (insn == 0xd4000001) { /* SVC #0 */
        emit_exit_stub(x, R_SVC, pc + 4);
        return false;
    }
    if ((insn & 0xfffff01f) == 0xd503201f) { /* HINT: NOP, except YIELD which runs verbatim */
        if (insn == 0xd503203f) {
            emit(x, insn);
            x->st->insns_copied++;
        }
        return true;
    }
    if (is_flagm(insn)) { /* CFINV, XAFLAG, AXFLAG: whitelist already confirmed by Tier 0 */
        emit(x, insn);
        x->st->insns_copied++;
        return true;
    }
    /* Barriers (including SB): the whitelist has already been confirmed by Tier 0 */
    if ((insn & 0xfffff01f) == 0xd503301f) {
        unsigned op2 = FIELD(insn, 7, 5);
        if (op2 == 2) { /* CLREX: clear the guest's exclusive marker */
            emit(x, enc_str_w(31, CTX, offsetof(struct appine_cpu, excl_size)));
            x->st->insns_remapped++;
            return true;
        }
        /* Complete the barrier before resuming at pc + 4 with any changed blocks retired. */
        emit(x, insn);
        if (op2 == 4 || op2 == 6) {
            emit(x, enc_ldr_x(T0, CTX, offsetof(struct appine_cpu, ivau_page)));
            emit_to_stub(x, enc_cbnz_x(T0), FIX_IMM19, R_CODE, pc + 4);
        }
        x->st->insns_copied++;
        return true;
    }
    if ((insn & 0xffd00000) == 0xd5100000) { /* MRS/MSR */
        bool read = BIT(insn, 21);
        unsigned rt = insn & 31;
        unsigned sysreg = FIELD(insn, 20, 5);
        switch (sysreg) {
        case SYSREG_FPSR:
            /* Read the flags raised by translated FP instructions. Tier 0 masks writes. */
            if (!read)
                return fallback(x, pc);
            /* fallthrough */
        case SYSREG_NZCV:
        /* tier0_defined rejects writes to the timers. */
        case SYSREG_CNTFRQ_EL0:
        case SYSREG_CNTVCT_EL0:
        case SYSREG_CNTVCTSS_EL0: {
            struct operands o = {.n = 1, .pos = {0}, .sp = {false}, .writes_rd = read};
            return emit_operands(x, insn, &o) || fallback(x, pc);
        }
        case SYSREG_FPCR:
        case SYSREG_TPIDR_EL0: {
            bool fpcr = sysreg == SYSREG_FPCR;
            size_t off = fpcr ? offsetof(struct appine_cpu, fpcr) : offsetof(struct appine_cpu, tpidr_el0);
            unsigned h = is_stolen(rt) ? T0 : rt;
            if (!read) {
                if (h == T0)
                    emit_load_guest(x, T0, rt);
                if (fpcr)
                    emit_fpcr_write_check(x, h, pc);
                else
                    emit(x, enc_str_x(h, CTX, off));
            } else if (rt != 31) {
                emit(x, enc_ldr_x(h, CTX, off));
                if (h == T0)
                    emit_store_guest(x, T0, rt);
            }
            x->st->insns_remapped++;
            return true;
        }
        case SYSREG_DCZID_EL0: /* read-only, writes already rejected by tier0_defined */
            if (rt != 31) {
                unsigned h = is_stolen(rt) ? T0 : rt;
                emit(x, enc_movz(h, DCZID_VALUE, 0));
                if (h == T0)
                    emit_store_guest(x, T0, rt);
            }
            x->st->insns_remapped++;
            return true;
        default:
            return fallback(x, pc);
        }
    }
    /* DC ZVA: zero the whole block containing the address; a block is always within one page */
    if ((insn & 0xffffffe0) == 0xd50b7420) {
        emit_xreg_to_t0(x, insn & 31);
        emit(x, enc_and_clear_low(T0, T0, 6));
        _Static_assert(DCZ_BLOCK == 64, "the block size of DC ZVA");
        dbt_emit_tlb_check(x, pc, DCZ_BLOCK, true, false, false, R_INTERP);
        emit(x, enc_add_lsl(T2, T2, T0, 0));
        for (int off = 0; off < DCZ_BLOCK; off += 16)
            emit(x, enc_stp_x(31, 31, T2, off));
        x->st->insns_memory++;
        return true;
    }
    /*
     * DC CVAC, DC CVAU, DC CIVAC, DC CVAP, DC CVADP, IC IVAU: as in Tier 0, the address is only
     * checked for read access (the DC CVAP and CVADP features have been confirmed by Tier 0).
     * ic ivau does not exit on every instruction: it records its page (a JIT flushing its cache
     * executes dozens of them per page), and the next dsb or isb exits so that dbt_run
     * invalidates the page's translations in place, in one go; when another page is already
     * recorded, Tier 0 executes this one, and dbt_run invalidates both pages right after it.
     */
    uint32_t cmo = insn & 0xffffffe0;
    if (cmo == 0xd50b7a20 || cmo == 0xd50b7b20 || cmo == 0xd50b7e20 || cmo == 0xd50b7520 ||
        cmo == 0xd50b7c20 || cmo == 0xd50b7d20) {
        emit_xreg_to_t0(x, insn & 31);
        dbt_emit_tlb_check(x, pc, 1, false, true, false, R_INTERP);
        if (cmo == 0xd50b7520) {
            emit(x, enc_and_ror(T0, T0, DATA_TAG_SHIFT - APPINE_PAGE_SHIFT, 64 - APPINE_PAGE_SHIFT));
            /* Zero means no pending page. Tier 0 returns this address explicitly. */
            emit_to_stub(x, enc_cbz_x(T0), FIX_IMM19, R_INTERP, pc);
            emit(x, enc_ldr_x(T1, CTX, offsetof(struct appine_cpu, ivau_page)));
            emit(x, enc_eor_lsr(T2, T1, T0, 0));
            uint32_t *same_page = here(x);
            emit(x, enc_cbz_x(T2));
            emit_to_stub(x, enc_cbnz_x(T1), FIX_IMM19, R_INTERP, pc);
            emit(x, enc_str_x(T0, CTX, offsetof(struct appine_cpu, ivau_page)));
            patch_local(x, same_page, here(x));
        }
        x->st->insns_memory++;
        return true;
    }
    uint32_t reg_branch = insn & 0xfffffc1f;
    if (reg_branch == 0xd61f0000 || reg_branch == 0xd63f0000 || reg_branch == 0xd65f0000) {
        /* BR/BLR/RET: put the target in T0 first, then look up the jump cache */
        unsigned rn = FIELD(insn, 9, 5);
        if (reg_branch == 0xd65f0000 && rn == 30)
            emit_predicted_return(x);
        emit_xreg_to_t0(x, rn);
        if (reg_branch == 0xd63f0000)
            emit_call(x, pc);
        emit(x, enc_ldr_x(T1, CTX, offsetof(struct appine_cpu, dbt_jump_cache)));
        emit(x, enc_ubfx(T2, T0, 2, JC_BITS));
        emit(x, enc_add_lsl(T1, T1, T2, 4));
        emit(x, enc_ldp_x(T2, T1, T1, 0));
        emit(x, enc_eor_lsr(T2, T2, T0, 0));
        emit_to_stub(x, enc_cbnz_x(T2), FIX_IMM19, R_LOOKUP, 0);
        emit(x, enc_br(T1));
        return false;
    }
    return fallback(x, pc);
}

/*
 * Ask Tier 0 whether it recognizes this instruction (the two tiers' whitelists must agree, see
 * the engine and engine/dbt maps). The answer depends only on the instruction word and is cached by it in `cache`
 * (direct-mapped, each entry is 1 << 40 | instruction word << 1 | answer): Tier 0 has to execute
 * the instruction to find out, and asking once for every instruction translated at java startup
 * took two percentage points.
 */

bool dbt_tier0_defined(struct appine_cpu *probe, uint64_t *cache, uint32_t insn, uint64_t pc)
{
    uint64_t *e = &cache[(insn * UINT32_C(0x9e3779b1)) >> 20];
    if ((*e >> 1) == ((uint64_t)1 << 39 | insn))
        return *e & 1;
    probe->pc = pc;
    probe->sp = 0;
    bool ok = appine_interp_exec(probe, insn) != APPINE_EXIT_UNDEF;
    *e = (uint64_t)1 << 40 | (uint64_t)insn << 1 | ok;
    return ok;
}

/*
 * SIMD&FP data processing: the whitelist decision shares appine_simd_dp_decode with Tier 0. V
 * registers need no rewriting; only general-register operands may be stolen registers. It does
 * not go through tier0_defined, to avoid generating a native stub for every instruction.
 */
static bool translate_simd_dp(struct xlate *x, uint32_t insn)
{
    struct native_desc nd;
    if (!appine_has(APPINE_HWCAP_FP | APPINE_HWCAP_ASIMD) || !appine_native_available() ||
        !appine_simd_dp_decode(insn, &nd))
        return false;
    struct operands o = {.n = 0, .writes_rd = false};
    for (unsigned i = 0; i < nd.n; i++) {
        add_operand(&o, nd.gpr[i].pos, false);
        if (nd.gpr[i].pos == 0 && nd.gpr[i].store)
            o.writes_rd = true;
    }
    return emit_operands(x, insn, &o);
}

/* Translate one instruction; returning false means the block ends here */
static bool translate_insn_body(struct xlate *x, uint32_t insn, uint64_t pc);


/*
 * Which registers have known values after this instruction (xlate.konst): ADR/ADRP set constants,
 * adding an immediate to a known value keeps it known, and other instructions that may write
 * general registers invalidate them. Anything uncertain is treated as writing all of them.
 */
static void konst_update(struct xlate *x, uint32_t insn, uint64_t pc)
{
    unsigned rd = insn & 31, rn = FIELD(insn, 9, 5);
    uint32_t kill = 1u << rd;
    if (is_flagm(insn)) /* writes only flags */
        return;
    if (FIELD(insn, 28, 24) == 0x10) { /* ADR/ADRP */
        uint64_t imm = ((uint64_t)FIELD(insn, 23, 5) << 2) | FIELD(insn, 30, 29);
        int64_t off = (int64_t)(imm << 43) >> 43;
        if (rd != 31) {
            x->konst |= 1u << rd;
            x->kval[rd] = BIT(insn, 31) ? (pc & ~UINT64_C(0xfff)) + ((uint64_t)off << 12) : pc + (uint64_t)off;
        }
        return;
    }
    if ((insn & 0xff800000) == 0x91000000 && rd != 31 && rn != 31 && (x->konst >> rn & 1)) {
        /* ADD Xd, Xn, #imm{, lsl #12} (does not set flags) */
        x->kval[rd] = x->kval[rn] + ((uint64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0));
        x->konst |= 1u << rd;
        return;
    }
    switch (FIELD(insn, 28, 25)) {
    case 0x8:
    case 0x9:
    case 0x5:
    case 0xd:
    case 0x7:
    case 0xf: /* data processing (SIMD ones may also write general registers, e.g. UMOV) */
        break;
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe: {
        struct memop m;
        if (dbt_is_atomic(insn)) { /* Rt, Rs, plus one more for pairs */
            unsigned rs = FIELD(insn, 20, 16);
            kill |= 3u << rd | 3u << rs;
            break;
        }
        if (!(BIT(insn, 26) ? dbt_decode_simd_memop(insn, pc, &m) : dbt_decode_memop(insn, pc, &m))) {
            kill = ~0u;
            break;
        }
        kill = 0;
        if (m.load && !m.simd && !m.prefetch) {
            kill |= 1u << m.rt;
            if (m.pair)
                kill |= 1u << m.rt2;
        }
        if (m.mode == M_PRE || m.mode == M_POST)
            kill |= 1u << m.rn;
        break;
    }
    default:
        /* Conditional branches, CBZ, TBZ, HINT and barriers write no registers; the rest (MRS,
         * BL and so on) are uncertain */
        if ((insn & 0xff000010) == 0x54000000 || (insn & 0x7e000000) == 0x34000000 ||
            (insn & 0x7e000000) == 0x36000000 || (insn & 0xfffff01f) == 0xd503201f ||
            (insn & 0xfffff01f) == 0xd503301f)
            kill = 0;
        else
            kill = ~0u;
        break;
    }
    x->konst &= ~kill;
}

static void affine_kill(struct xlate *x, unsigned r)
{
    x->affine_valid &= ~(1u << r);
    for (uint32_t bits = x->affine_valid; bits; bits &= bits - 1) {
        unsigned k = (unsigned)__builtin_ctz(bits);
        if (x->affine_base[k] == r)
            x->affine_valid &= ~(1u << k);
    }
}

static void affine_add_inplace(struct xlate *x, unsigned r, int64_t imm)
{
    if ((x->affine_valid >> r) & 1) {
        x->affine_off[r] += imm;
        return;
    }
    for (uint32_t bits = x->affine_valid; bits; bits &= bits - 1) {
        unsigned k = (unsigned)__builtin_ctz(bits);
        if (x->affine_base[k] == r)
            x->affine_off[k] -= imm;
    }
}

static void affine_set(struct xlate *x, unsigned rd, unsigned rn, int64_t imm)
{
    unsigned base = ((x->affine_valid >> rn) & 1) ? x->affine_base[rn] : rn;
    int64_t off = ((x->affine_valid >> rn) & 1) ? x->affine_off[rn] + imm : imm;
    if (base == rd) {
        affine_add_inplace(x, rd, off);
        return;
    }
    affine_kill(x, rd);
    x->affine_base[rd] = (uint8_t)base;
    x->affine_off[rd] = off;
    x->affine_valid |= 1u << rd;
}

/* Maintain block-local affine register relations (ADD/SUB #imm, MOV Xd, Xm, immediate writeback);
 * bit 31 represents SP. Anything uncertain clears all relations conservatively. */
static void affine_update(struct xlate *x, uint32_t insn, uint64_t pc)
{
    unsigned rd = insn & 31, rn = FIELD(insn, 9, 5);
    uint32_t op = insn & 0xff800000;
    if (op == 0x91000000 || op == 0xd1000000) { /* ADD/SUB Xd, Xn, #imm{, lsl #12} (31 = SP) */
        int64_t imm = (int64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0);
        if (op == 0xd1000000)
            imm = -imm;
        if (rd == rn) {
            if (x->affine_valid)
                affine_add_inplace(x, rd, imm);
        } else {
            affine_set(x, rd, rn, imm);
        }
        return;
    }
    if ((insn & 0xffe0ffe0) == 0xaa0003e0) { /* MOV Xd, Xm (ORR Xd, XZR, Xm; 31 = XZR) */
        unsigned rm = FIELD(insn, 20, 16);
        if (rd < 31) {
            if (rm < 31) {
                if (rd != rm)
                    affine_set(x, rd, rm, 0);
            } else if (x->affine_valid) {
                affine_kill(x, rd);
            }
        }
        return;
    }
    if (!x->affine_valid || is_flagm(insn))
        return;
    if (FIELD(insn, 28, 24) == 0x10) { /* ADR/ADRP */
        if (rd < 31)
            affine_kill(x, rd);
        return;
    }
    switch (FIELD(insn, 28, 25)) {
    case 0x8:
    case 0x9:
    case 0x5:
    case 0xd: {
        struct operands o;
        if (!dbt_dp_operands(insn, &o))
            x->affine_valid = 0;
        else if (o.writes_rd && (rd < 31 || o.sp[0]))
            affine_kill(x, rd);
        break;
    }
    case 0x7:
    case 0xf: {
        struct native_desc nd;
        if (!appine_simd_dp_decode(insn, &nd)) {
            x->affine_valid = 0;
        } else {
            for (unsigned i = 0; i < nd.n; i++) {
                if (nd.gpr[i].store) {
                    unsigned r = (insn >> nd.gpr[i].pos) & 31;
                    if (r < 31)
                        affine_kill(x, r);
                }
            }
        }
        break;
    }
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe: {
        struct memop m;
        if (dbt_is_atomic(insn)) {
            unsigned rs = FIELD(insn, 20, 16);
            if (rd < 31)
                affine_kill(x, rd);
            if (rd + 1 < 31)
                affine_kill(x, rd + 1);
            if (rs < 31)
                affine_kill(x, rs);
            if (rs + 1 < 31)
                affine_kill(x, rs + 1);
            break;
        }
        if (!(BIT(insn, 26) ? dbt_decode_simd_memop(insn, pc, &m) : dbt_decode_memop(insn, pc, &m))) {
            x->affine_valid = 0;
            break;
        }
        if (m.prefetch)
            break;
        if (m.load && !m.simd) {
            if (m.rt < 31)
                affine_kill(x, m.rt);
            if (m.pair && m.rt2 < 31)
                affine_kill(x, m.rt2);
        }
        if (m.mode == M_PRE || m.mode == M_POST) {
            if (m.wb_reg)
                affine_kill(x, m.rn);
            else
                affine_add_inplace(x, m.rn, m.imm);
        }
        break;
    }
    default:
        if (!((insn & 0xff000010) == 0x54000000 || (insn & 0x7e000000) == 0x34000000 ||
              (insn & 0x7e000000) == 0x36000000 || (insn & 0xfffff01f) == 0xd503201f ||
              (insn & 0xfffff01f) == 0xd503301f))
            x->affine_valid = 0;
        break;
    }
}

bool dbt_translate_insn(struct xlate *x, uint32_t insn, uint64_t pc)
{
    bool r = translate_insn_body(x, insn, pc);
    konst_update(x, insn, pc);
    affine_update(x, insn, pc);
    return r;
}

static bool translate_insn_body(struct xlate *x, uint32_t insn, uint64_t pc)
{
    if ((FIELD(insn, 28, 25) & 7) == 7)
        return translate_simd_dp(x, insn) || fallback(x, pc);
    if (!dbt_tier0_defined(x->probe, x->defined, insn, pc))
        return fallback(x, pc);
    switch (FIELD(insn, 28, 25)) {
    case 0x8:
    case 0x9:
        if (FIELD(insn, 28, 24) == 0x10) {
            emit_pcrel(x, insn, pc);
            return true;
        }
        /* fallthrough */
    case 0x5:
    case 0xd: {
        struct operands o;
        if (!dbt_dp_operands(insn, &o) || !emit_operands(x, insn, &o))
            return fallback(x, pc);
        if (o.writes_rd && o.sp[0] && (insn & 31) == 31) { /* wrote SP */
            uint32_t op = insn & 0xff800000;
            if ((op == 0x91000000 || op == 0xd1000000) && FIELD(insn, 9, 5) == 31)
                dbt_sp_moved(x, (int64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0));
            else
                x->sp_aligned = false;
        }
        return true;
    }
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe: {
        if (dbt_is_atomic(insn))
            return translate_atomic(x, insn, pc) || fallback(x, pc);
        struct memop m;
        if (!(BIT(insn, 26) ? dbt_decode_simd_memop(insn, pc, &m) : dbt_decode_memop(insn, pc, &m)))
            return fallback(x, pc);
        if (m.prefetch)
            return true;
        if (x->active_groups && is_grouped_idx(x, x->idx)) {
            for (unsigned mask = x->active_groups; mask; mask &= mask - 1) {
                int i = __builtin_ctz(mask);
                struct group *g = &x->groups[i];
                if (x->idx != g->idx[g->next])
                    continue;
                if (g->reload[g->next]) {
                    size_t off = offsetof(struct appine_cpu, dbt_groups) + 8 * (size_t)i;
                    emit(x, enc_ldr_x(T2, CTX, off));
                    x->t2_group = i;
                } else if (x->t2_group != i) {
                    appine_guard_fail(); /* plan_group ensures nothing used T2 before a member not
                                          * marked reload */
                }
                dbt_emit_member(x, &m, g->off[g->next++]);
                if (g->next >= g->n)
                    x->active_groups &= (uint8_t)~(1u << i);
                x->st->insns_grouped++;
                return true;
            }
        }
        emit_memop(x, &m, pc);
        return true;
    }
    case 0xa:
    case 0xb:
        return translate_branch_sys(x, insn, pc);
    default:
        return fallback(x, pc);
    }
}


#endif /* DBT_SUPPORTED */
