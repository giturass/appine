/*
 * Tier 1 grouped soft-TLB checks: coalesce multiple memory accesses sharing a base or affine
 * alias into one range check with up to GROUP_SLOTS interleaved active groups.
 */
#define _GNU_SOURCE
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

/* ---- A group of accesses sharing one TLB check ---- */

/*
 * Several accesses in the same block based on the same register (function prologues and
 * epilogues, several fields of a struct) share one check: the leader checks the range the whole
 * group covers, after which T2 = the host address for the base's value before the leader
 * executes, and members access [T2, #offset] directly. Between members there may only be
 * instructions that do not write the base (except adding or subtracting a constant, whose
 * accumulated offset is recorded) and conditional branches, and SP may only change by multiples
 * of 16 (the leader's alignment check then also holds for the members).
 *
 * Other accesses (of other groups, or ungrouped) and instructions that use T2 may sit between
 * members: the leader stores the host base in the cpu's dbt_groups[slot], and the members after
 * them reload it first. The slot's address is a constant and can be loaded early, so members'
 * accesses need not wait for a TLB lookup: in python's interpreter loop, accesses on the stack
 * frame and code object bases interleave, and previously not one of a dozen or so checks in a
 * block could be saved. Mappings do not change while a block executes (the TLB is only refilled),
 * so the host base stays valid until the base changes. At most GROUP_SLOTS groups at once.
 *
 * Across pages the refill routine handles both pages, and the check fails if the host addresses
 * are not contiguous. Members after a conditional branch do not necessarily execute, and the
 * covered range may also include pages they cannot access, so a failed check exits with
 * R_UNGROUP and Tier 0 executes the leader; the second failure of the same leader invalidates this
 * block, and on retranslation it is no longer grouped (ungroup).
 */


/* A member's access instruction: host address = Rn + off, with the Rn and Rt fields 0. Returns
 * false if the immediate does not fit */
static bool member_insn(const struct memop *m, int64_t off, uint32_t *out)
{
    unsigned sz = m->size;
    if (m->structure) { /* LD1–LD4/ST1–ST4 have no offset */
        *out = m->final;
        return off == 0;
    }
    if (m->pair) {
        if (off & ((1 << sz) - 1) || off < -64 * (1 << sz) || off > 63 * (1 << sz))
            return false;
        *out = m->final | ((uint32_t)(off >> sz) & 0x7f) << 15;
        return true;
    }
    uint32_t common = m->final & 0xc4c00000; /* size, V, opc */
    if (off >= 0 && !(off & ((1 << sz) - 1)) && off >> sz < 4096) { /* unsigned offset */
        *out = common | 0x39000000 | (uint32_t)(off >> sz) << 10;
        return true;
    }
    if (off >= -256 && off < 256) { /* LDUR/STUR */
        *out = common | 0x38000000 | ((uint32_t)off & 0x1ff) << 12;
        return true;
    }
    return false;
}

/* The register borrowed for the host address when the immediate does not fit: a stolen Rt uses T1
 * (T0 and T1 for a pair) */
static unsigned member_scratch(const struct xlate *x, const struct memop *m)
{
    return m->pair && !m->simd && is_stolen(m->rt) ? T1 : T0;
}

static bool member_fits(const struct xlate *x, const struct memop *m, int64_t off)
{
    uint32_t insn = 0;
    if (member_insn(m, off, &insn))
        return true;
    return !(m->pair && !m->simd && is_stolen(m->rt) && is_stolen(m->rt2));
}

/* Whether the access at pc may lead a group: a recorded leader and anything within NOGROUP_SPAN
 * bytes after it may not, since its former members would most likely fail the check for the same
 * reason */
static bool nogroup(const struct appine_dbt *d, uint64_t pc)
{
    unsigned n = d->nogroup_count < NOGROUP_MAX ? d->nogroup_count : NOGROUP_MAX;
    for (unsigned i = 0; i < n; i++) {
        if (pc - d->nogroup[i] < NOGROUP_SPAN)
            return true;
    }
    return false;
}


/* Stolen registers are replaced by T0, T1, T2 in turn (emit_operands): three of them use T2 */
static bool uses_t2(const struct xlate *x, uint32_t insn, const struct operands *o)
{
    unsigned stolen[3], nstolen = 0;
    for (unsigned i = 0; i < o->n; i++) {
        unsigned r = (insn >> o->pos[i]) & 31, k;
        if ((r == 31 && o->sp[i]) || !is_stolen(r))
            continue;
        for (k = 0; k < nstolen && stolen[k] != r; k++)
            ;
        if (k == nstolen && nstolen++ == 2)
            return true;
        stolen[k] = r;
    }
    return false;
}

/*
 * Advance affine alias tracking (bit r set in *alias_mask => register r equals leader's base +
 * alias_off[r], with bit 31 = SP) across a non-memory instruction. Returns 0 if the instruction
 * ends the group or leaves no live aliases, 1 if allowed without touching T2, or 2 if it uses T2.
 */
static int keeps_group_step(const struct xlate *x, uint32_t insn, uint32_t *alias_mask,
                            int64_t alias_off[32])
{
    unsigned top = FIELD(insn, 28, 25);
    struct operands o = {.n = 0};
    if ((top & 7) == 7) { /* SIMD&FP data processing: only general-register operands matter */
        struct native_desc nd;
        if (!appine_simd_dp_decode(insn, &nd))
            return 0;
        for (unsigned i = 0; i < nd.n; i++) {
            add_operand(&o, nd.gpr[i].pos, false);
            if (nd.gpr[i].store) {
                unsigned r = (insn >> nd.gpr[i].pos) & 31;
                if (r < 31)
                    *alias_mask &= ~(1u << r);
            }
        }
        return *alias_mask ? (uses_t2(x, insn, &o) ? 2 : 1) : 0;
    }
    if (top == 0x8 || top == 0x9 || top == 0x5 || top == 0xd) {
        if (FIELD(insn, 28, 24) == 0x10) { /* ADR/ADRP: a stolen Rd only uses T0 */
            unsigned rd = insn & 31;
            if (rd < 31)
                *alias_mask &= ~(1u << rd);
            return *alias_mask != 0;
        }
        if (!dbt_dp_operands(insn, &o))
            return 0;
        uint32_t op = insn & 0xff800000;
        unsigned rd = insn & 31;
        if (op == 0x91000000 || op == 0xd1000000) { /* ADD/SUB Xd, Xn, #imm{, lsl #12} (31 = SP) */
            unsigned src = FIELD(insn, 9, 5);
            if ((*alias_mask >> src) & 1) {
                int64_t imm = (int64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0);
                alias_off[rd] = alias_off[src] + (op == 0xd1000000 ? -imm : imm);
                *alias_mask |= 1u << rd;
            } else {
                *alias_mask &= ~(1u << rd);
            }
        } else if ((insn & 0xffe0ffe0) == 0xaa0003e0) { /* MOV Xd, Xm (ORR Xd, XZR, Xm; 31 = XZR) */
            unsigned rm = FIELD(insn, 20, 16);
            if (rd < 31) {
                if (rm < 31 && ((*alias_mask >> rm) & 1)) {
                    alias_off[rd] = alias_off[rm];
                    *alias_mask |= 1u << rd;
                } else {
                    *alias_mask &= ~(1u << rd);
                }
            }
        } else if (o.writes_rd && (rd < 31 || o.sp[0])) {
            *alias_mask &= ~(1u << rd);
        }
        return *alias_mask ? (uses_t2(x, insn, &o) ? 2 : 1) : 0;
    }
    return (insn & 0xff000010) == 0x54000000 || /* B.cond */
           (insn & 0x7e000000) == 0x34000000 || /* CBZ/CBNZ */
           (insn & 0x7e000000) == 0x36000000 || /* TBZ/TBNZ */
           (insn & 0xfffff01f) == 0xd503201f || /* HINT */
           (insn & 0xfffff01f) == 0xd503301f;   /* barriers, CLREX */
}

/* Same as keeps_group_step, for register-offset (M_REG) groups with fixed (rn, rm, option, shift) */
static int keeps_group_reg(const struct xlate *x, uint32_t insn, unsigned rn, unsigned rm,
                           unsigned option, unsigned shift, int64_t *delta)
{
    unsigned top = FIELD(insn, 28, 25);
    struct operands o = {.n = 0};
    if ((top & 7) == 7) {
        struct native_desc nd;
        if (!appine_simd_dp_decode(insn, &nd))
            return 0;
        for (unsigned i = 0; i < nd.n; i++) {
            add_operand(&o, nd.gpr[i].pos, false);
            if (nd.gpr[i].store) {
                unsigned r = (insn >> nd.gpr[i].pos) & 31;
                if (r < 31 && (r == rn || r == rm))
                    return 0;
            }
        }
        return uses_t2(x, insn, &o) ? 2 : 1;
    }
    if (top == 0x8 || top == 0x9 || top == 0x5 || top == 0xd) {
        if (FIELD(insn, 28, 24) == 0x10) {
            unsigned rd = insn & 31;
            return (rd == 31 || (rd != rn && rd != rm)) ? 1 : 0;
        }
        if (!dbt_dp_operands(insn, &o))
            return 0;
        uint32_t op = insn & 0xff800000;
        unsigned rd = insn & 31;
        if ((op == 0x91000000 || op == 0xd1000000) && FIELD(insn, 9, 5) == rd) {
            int64_t imm = (int64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0);
            if (op == 0xd1000000)
                imm = -imm;
            if (rd == rn && rn != rm) {
                if (rn == 31 && (imm & 15))
                    return 0;
                *delta += imm;
                return uses_t2(x, insn, &o) ? 2 : 1;
            }
            if (rd == rm && rm != 31 && rn != rm && (option == 3 || option == 7)) {
                *delta += (int64_t)((uint64_t)imm << shift);
                return uses_t2(x, insn, &o) ? 2 : 1;
            }
        }
        if (o.writes_rd) {
            if (rn == 31 ? (rd == 31 && o.sp[0]) : rd == rn)
                return 0;
            if (rm < 31 && rd == rm)
                return 0;
        }
        return uses_t2(x, insn, &o) ? 2 : 1;
    }
    return (insn & 0xff000010) == 0x54000000 || /* B.cond */
           (insn & 0x7e000000) == 0x34000000 || /* CBZ/CBNZ */
           (insn & 0x7e000000) == 0x36000000 || /* TBZ/TBNZ */
           (insn & 0xfffff01f) == 0xd503201f || /* HINT */
           (insn & 0xfffff01f) == 0xd503301f;   /* barriers, CLREX */
}

/* When access `m` executes, the base is `delta` more than before the leader executed: the start
 * of the access range (relative to the base before the leader) */
static int64_t member_start(const struct memop *m, int64_t delta)
{
    return delta + (m->mode == M_POST || m->mode == M_REG ? 0 : m->imm);
}

/* Starting from access `lead` (instruction x->idx of the block), look ahead for members with the
 * same (or affine-aliased) base, or matching M_REG (rn, rm, option, shift); if there is at least
 * one member, fill in this group in a free slot and return the slot's index, otherwise return -1 */
int dbt_plan_group(struct xlate *x, const struct memop *lead)
{
    uint8_t free_slots = (uint8_t)~x->active_groups;
    if (!free_slots)
        return -1;
    int slot = __builtin_ctz(free_slots);
    struct group *g = &x->groups[slot];
    unsigned rn = lead->rn;
    uint64_t pc0 = x->pc + 4ull * x->idx;
    g->n = g->next = 0;
    g->spill = false;
    if (lead->mode == M_LITERAL || nogroup(x->d, pc0))
        return -1;
    int64_t lo = member_start(lead, 0), hi = lo + memop_bytes(lead);
    bool write = !lead->load;
    if (!member_fits(x, lead, lo))
        return -1;
    g->idx[0] = x->idx;
    g->off[0] = (int32_t)lo;
    g->reload[0] = false;
    g->n = 1;
    bool clobbered = false; /* an instruction used T2 after the previous member */

    if (lead->mode == M_REG) {
        unsigned rm = lead->rm, opt = lead->option, sh = lead->shift;
        int64_t delta = 0;
        bool overwritten = lead->load && !lead->simd &&
                           ((rn < 31 && lead->rt == rn) || (rm < 31 && lead->rt == rm));
        for (unsigned j = x->idx + 1; !overwritten && j < x->limit && g->n < GROUP_MAX; j++) {
            uint32_t insn = fetch_guest(x, j);
            unsigned top = FIELD(insn, 28, 25);
            if (top != 0x4 && top != 0x6 && top != 0xc && top != 0xe) {
                int keep = keeps_group_reg(x, insn, rn, rm, opt, sh, &delta);
                if (!keep)
                    break;
                clobbered |= keep == 2;
                continue;
            }
            struct memop m;
            uint64_t pc = x->pc + 4ull * j;
            if (dbt_is_atomic(insn) || !(BIT(insn, 26) ? dbt_decode_simd_memop(insn, pc, &m) : dbt_decode_memop(insn, pc, &m)))
                break;
            if (m.prefetch)
                continue;
            if (is_grouped_idx(x, j) || m.mode != M_REG || m.rn != rn || m.rm != rm ||
                m.option != opt || m.shift != sh) {
                if (m.load && !m.simd &&
                    ((rn < 31 && (m.rt == rn || (m.pair && m.rt2 == rn))) ||
                     (rm < 31 && (m.rt == rm || (m.pair && m.rt2 == rm)))))
                    break;
                if ((m.mode == M_PRE || m.mode == M_POST) && (m.rn == rn || (rm < 31 && m.rn == rm)))
                    break;
                clobbered = true;
                continue;
            }
            int64_t start = delta, end = start + memop_bytes(&m);
            int64_t nlo = start < lo ? start : lo, nhi = end > hi ? end : hi;
            if (nhi - nlo > GROUP_SPAN || start <= -(1 << 23) || start >= (1 << 23) ||
                nlo <= -(1 << 23) || nlo >= (1 << 23) || !member_fits(x, &m, start))
                break;
            lo = nlo;
            hi = nhi;
            write |= !m.load;
            g->idx[g->n] = j;
            g->off[g->n] = (int32_t)start;
            g->reload[g->n] = clobbered;
            g->spill |= clobbered;
            clobbered = false;
            g->n++;
            overwritten = m.load && !m.simd && ((rn < 31 && m.rt == rn) || (rm < 31 && m.rt == rm));
        }
    } else {
        uint32_t alias_mask = 1u << rn;
        int64_t alias_off[32];
        alias_off[rn] = 0;
        /* Seed with any block-local affine aliases already established before the leader */
        if (x->affine_valid) {
            unsigned root = ((x->affine_valid >> rn) & 1) ? x->affine_base[rn] : rn;
            int64_t lead_off = ((x->affine_valid >> rn) & 1) ? x->affine_off[rn] : 0;
            if (root != rn) {
                alias_mask |= 1u << root;
                alias_off[root] = -lead_off;
            }
            for (uint32_t bits = x->affine_valid; bits; bits &= bits - 1) {
                unsigned r = (unsigned)__builtin_ctz(bits);
                if (r != rn && x->affine_base[r] == root) {
                    alias_mask |= 1u << r;
                    alias_off[r] = x->affine_off[r] - lead_off;
                }
            }
        }
        if (lead->mode == M_PRE || lead->mode == M_POST) {
            if (lead->wb_reg)
                alias_mask &= ~(1u << rn);
            else
                alias_off[rn] += lead->imm;
        }
        if (lead->load && !lead->simd) {
            if (lead->rt < 31)
                alias_mask &= ~(1u << lead->rt);
            if (lead->pair && lead->rt2 < 31)
                alias_mask &= ~(1u << lead->rt2);
        }
        for (unsigned j = x->idx + 1; alias_mask && j < x->limit && g->n < GROUP_MAX; j++) {
            uint32_t insn = fetch_guest(x, j);
            unsigned top = FIELD(insn, 28, 25);
            if (top != 0x4 && top != 0x6 && top != 0xc && top != 0xe) {
                int keep = keeps_group_step(x, insn, &alias_mask, alias_off);
                if (!keep)
                    break;
                clobbered |= keep == 2;
                continue;
            }
            struct memop m;
            uint64_t pc = x->pc + 4ull * j;
            if (dbt_is_atomic(insn) || !(BIT(insn, 26) ? dbt_decode_simd_memop(insn, pc, &m) : dbt_decode_memop(insn, pc, &m)))
                break;
            if (m.prefetch) /* generates no code */
                continue;
            bool can_join = !is_grouped_idx(x, j) && m.mode != M_LITERAL && m.mode != M_REG &&
                            ((alias_mask >> m.rn) & 1) &&
                            (m.rn != 31 || (rn == 31 && (alias_off[31] & 15) == 0));
            if (!can_join) {
                if (m.load && !m.simd) {
                    if (m.rt < 31)
                        alias_mask &= ~(1u << m.rt);
                    if (m.pair && m.rt2 < 31)
                        alias_mask &= ~(1u << m.rt2);
                }
                if (m.mode == M_PRE || m.mode == M_POST) {
                    if (m.wb_reg)
                        alias_mask &= ~(1u << m.rn);
                    else if ((alias_mask >> m.rn) & 1)
                        alias_off[m.rn] += m.imm;
                }
                if (!alias_mask)
                    break;
                clobbered = true;
                continue;
            }
            int64_t start = member_start(&m, alias_off[m.rn]), end = start + memop_bytes(&m);
            int64_t nlo = start < lo ? start : lo, nhi = end > hi ? end : hi;
            if (nhi - nlo > GROUP_SPAN || start <= -(1 << 23) || start >= (1 << 23) ||
                nlo <= -(1 << 23) || nlo >= (1 << 23) || !member_fits(x, &m, start))
                break;
            lo = nlo;
            hi = nhi;
            write |= !m.load;
            g->idx[g->n] = j;
            g->off[g->n] = (int32_t)start;
            g->reload[g->n] = clobbered;
            g->spill |= clobbered;
            clobbered = false;
            g->n++;
            if (m.mode == M_PRE || m.mode == M_POST) {
                if (m.wb_reg)
                    alias_mask &= ~(1u << m.rn);
                else
                    alias_off[m.rn] += m.imm;
            }
            if (m.load && !m.simd) {
                if (m.rt < 31)
                    alias_mask &= ~(1u << m.rt);
                if (m.pair && m.rt2 < 31)
                    alias_mask &= ~(1u << m.rt2);
            }
        }
    }
    if (g->n < 2) {
        g->n = 0;
        return -1;
    }
    g->next = g->n; /* starts only after the leader's check is emitted */
    g->lo = (int32_t)lo;
    g->bytes = (unsigned)(hi - lo);
    g->write = write;
    for (unsigned k = 1; k < g->n; k++)
        x->grouped_bits[g->idx[k] >> 6] |= UINT64_C(1) << (g->idx[k] & 63);
    return slot;
}

/* A member's (including the leader's) access: host address = T2 + off, then base writeback */
void dbt_emit_member(struct xlate *x, const struct memop *m, int64_t off)
{
    unsigned rn = m->rn == 31 ? REG_SP : m->rn, addr = T2;
    bool s1 = !m->simd && is_stolen(m->rt), s2 = m->pair && !m->simd && is_stolen(m->rt2);
    uint32_t insn = 0;
    if (!member_insn(m, off, &insn)) {
        addr = member_scratch(x, m);
        emit_add_const(x, addr, T2, off);
        member_insn(m, 0, &insn);
    }
    if (m->structure) {
        emit(x, insn | addr << 5);
    } else if (!m->pair) {
        unsigned rt = s1 ? T1 : m->rt;
        if (s1 && !m->load)
            emit_load_guest(x, T1, m->rt);
        emit(x, insn | addr << 5 | rt);
        if (s1 && m->load)
            emit_store_guest(x, T1, m->rt);
    } else {
        unsigned h1 = s1 ? T0 : m->rt, h2 = s2 ? T1 : m->rt2;
        if (!m->load) {
            if (s1)
                emit_load_guest(x, T0, m->rt);
            if (s2)
                emit_load_guest(x, T1, m->rt2);
        }
        emit(x, insn | h2 << 10 | addr << 5 | h1);
        if (m->load) {
            if (s1)
                emit_store_guest(x, T0, m->rt);
            if (s2)
                emit_store_guest(x, T1, m->rt2);
        }
    }
    if (m->mode == M_PRE || m->mode == M_POST) {
        unsigned dst = rn == REG_SP ? SP_HOST : is_stolen(rn) ? T0 : rn;
        if (m->wb_reg) {
            unsigned inc = m->rm;
            if (is_stolen(inc)) {
                emit_load_guest(x, T1, inc);
                inc = T1;
            }
            if (dst == T0)
                emit_load_guest(x, T0, rn);
            emit(x, enc_add_lsl(dst, dst, inc, 0));
        } else {
            if (dst == T0)
                emit_load_guest(x, T0, rn);
            emit_add_const(x, dst, dst, m->imm);
        }
        if (dst == T0)
            emit_store_guest(x, T0, rn);
        if (rn == REG_SP)
            dbt_sp_moved(x, m->wb_reg ? 1 : m->imm);
    }
    x->st->insns_memory++;
}

/* The leader: check the range the whole group covers, T2 = the base's host address (stored in
 * the slot when some member reloads it), then do the leader's own access */
void dbt_emit_group(struct xlate *x, const struct memop *lead, uint64_t pc, int slot)
{
    struct group *g = &x->groups[slot];
    unsigned rn = lead->rn == 31 ? REG_SP : lead->rn;
    if (rn == REG_SP)
        dbt_emit_sp_check(x, pc);
    bool base_in_t0 = false;
    unsigned base = rn == REG_SP ? SP_HOST : rn;
    if (rn != REG_SP && is_stolen(rn)) {
        emit_load_guest(x, T0, rn);
        base = T0;
        base_in_t0 = true;
    }
    if (lead->mode == M_REG) {
        unsigned idx = lead->rm;
        if (idx != 31 && is_stolen(idx)) {
            emit_load_guest(x, T1, idx);
            idx = T1;
        }
        emit(x, enc_add_ext(T0, base, idx, lead->option, lead->shift));
        base = T0;
        base_in_t0 = true;
    }
    bool in_granule = rn == REG_SP && lead->mode != M_REG && (g->lo & 15) + g->bytes <= 16;
    uint64_t addr;
    if (lead->mode != M_REG && dbt_known_address(x, rn, g->lo, g->bytes, &addr)) {
        emit_add_const(x, T0, base, g->lo);
        dbt_emit_tlb_check_known(x, pc, addr, g->bytes, g->write, R_UNGROUP);
    } else {
        bool last_ready = dbt_emit_address_imm(x, base, g->lo, g->bytes, in_granule);
        dbt_emit_tlb_check(x, pc, g->bytes, g->write, in_granule, last_ready, R_UNGROUP);
    }
    if (base_in_t0) {
        /* T0 now holds base + g->lo (preserved across refill), so subtract g->lo to recover
         * host(base) for members. */
        emit(x, enc_add_lsl(T2, T2, T0, 0));
        emit_add_const(x, T2, T2, -g->lo);
    } else {
        emit(x, enc_add_lsl(T2, T2, base, 0));
    }
    if (g->spill)
        emit(x, enc_str_x(T2, CTX, offsetof(struct appine_cpu, dbt_groups) + 8 * (size_t)slot));
    x->t2_group = slot;
    x->active_groups |= (uint8_t)(1u << slot);
    g->next = 1;
    dbt_emit_member(x, lead, g->off[0]);
}


#endif /* DBT_SUPPORTED */
