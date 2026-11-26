/*
 * Tier 1 strip-mined fast loops: recognize canonical single-block (and 1-boundary cross-page)
 * constant-stride or register-stride self-loops and emit a guarded native fast loop ahead of the
 * standard checked body.
 */
#define _GNU_SOURCE
#include "dbt_internal.h"

#ifdef DBT_SUPPORTED

/* Same as fetch_guest, allowing analyze_fast_loop to peek across at most one 4 KiB guest page
 * boundary when the next page is mapped executable and shares the block's code-group status. */
static inline bool fetch_guest_fast(struct xlate *x, unsigned idx, uint32_t *out)
{
    if (LIKELY(idx < x->limit)) {
        *out = fetch_guest(x, idx);
        return true;
    }
    if (idx >= MAX_BLOCK_INSNS)
        return false;
    if (!x->tried_src1) {
        x->tried_src1 = true;
        uint64_t next_page = (x->pc & ~PAGE_MASK) + APPINE_PAGE_SIZE;
        if (next_page > x->pc && next_page < (UINT64_C(1) << APPINE_VA_BITS) &&
            (!x->shared || !__atomic_load_n(&x->d->shared, __ATOMIC_ACQUIRE) ||
             in_shared(x->d, next_page)))
            x->src1 = appine_mmu_translate(x->mmu, next_page, APPINE_PROT_EXEC);
    }
    if (!x->src1)
        return false;
    if (x->copied < x->limit) {
        memcpy(x->words + x->copied, x->src + x->copied, (x->limit - x->copied) * 4);
        x->copied = x->limit;
    }
    if (idx >= x->copied) {
        unsigned want = x->copied + 64;
        if (want > MAX_BLOCK_INSNS)
            want = MAX_BLOCK_INSNS;
        memcpy(x->words + x->copied, x->src1 + (x->copied - x->limit), (want - x->copied) * 4);
        x->copied = want;
    }
    *out = x->words[idx];
    return true;
}

/* ---- Strip-mined in-page fast loops ---- */

/*
 * Recognize canonical single-block constant-stride self-loops (prefix 0..back_idx with back-edge
 * targeting x->pc) and emit a guarded native fast loop ahead of the normal translated body:
 *   1. Verify cpu->nwatch == 0 (never bypass hardware watchpoints).
 *   2. Compute a conservative lower bound `rem_backedges` on how many iterations are guaranteed to
 *      take the back-edge before the loop exits, clamped to `1 << kick_log2` so kicks stay prompt.
 *   3. For each induction pointer (up to 7, saving addends in dbt_groups[0..6] and safe_iters in
 *      dbt_groups[7]), verify its accessed range stays within one 4 KiB page and hits the data
 *      TLB, shrinking safe_iters to the number of whole iterations that fit in that page.
 *   4. If safe_iters >= 2, add each pointer's TLB addend to its register (converting guest pointers
 *      to host pointers), execute the loop body natively with zero TLB or kick checks for
 *      safe_iters iterations (counted in T2, which fast-body instructions never touch), then
 *      subtract each addend from the root pointer and any live end-of-iteration affine aliases and
 *      fall through into the standard checked loop for page crossings, tail iterations, and kicks.
 *
 * All inserted prologue/counter/epilogue code is strictly NZCV-free (D6) and leaves X18 untouched.
 * Because safe_iters <= rem_backedges, at least one full iteration always runs in the standard
 * loop afterward, producing exact exit NZCV and precise faults on any page boundary or mismatch.
 */
#define FAST_LOOP_MAX_PTRS 7
#define FAST_LOOP_MAX_STREAMS 16
#define FAST_LOOP_MAX_WORDS 1500
_Static_assert(FAST_LOOP_MAX_PTRS < GROUP_SLOTS, "dbt_groups[7] holds safe_iters during prologue");

enum fast_loop_kind { FL_COUNTDOWN, FL_CMP_INC };
enum fast_cmp_kind { FL_NE, FL_SLT, FL_SLE, FL_ULT, FL_ULE };

struct fast_ptr {
    uint8_t reg;         /* 0..30 = guest Xr; 31 = guest SP (SP_HOST) */
    uint32_t alias_mask; /* regs (a != reg) holding reg + const at end of iteration */
};

struct fast_stream {
    uint8_t ptr_idx;    /* index into fast_loop::ptrs */
    uint8_t idx_reg;    /* 31 = none (plain offset); 0..30 = M_REG index register */
    uint8_t idx_reg2;   /* 31 = none; 0..30 = second 64-bit index reg added before idx_shift */
    uint8_t idx_opt;    /* M_REG option (2, 3, 6, 7) */
    uint8_t idx_shift;  /* M_REG / derived left shift (0..4) */
    uint8_t stride_reg; /* 31 = constant stride; 0..30 = loop-invariant register stride */
    bool write;
    bool first_for_ptr; /* true saves addend in dbt_groups[ptr_idx]; false checks equality */
    int32_t lo, hi;
    uint32_t stride;    /* constant byte stride per iteration when stride_reg == 31 */
};

struct fast_loop {
    unsigned back_idx;
    enum fast_loop_kind kind;
    unsigned ctrl_idx; /* cnt_idx for FL_COUNTDOWN, cmp_idx for FL_CMP_INC */
    unsigned cnt_reg;
    unsigned bound_reg;
    uint32_t bound_imm;
    bool bound_is_imm;
    bool is_64;
    bool uses_sp;
    uint32_t step;
    int64_t cmp_off; /* for FL_CMP_INC: iter-0 compared value is cnt_reg + cmp_off */
    enum fast_cmp_kind cmp;
    unsigned cd_cond; /* B.cond code for FL_COUNTDOWN */
    unsigned kick_log2;
    unsigned nptrs;
    unsigned nstreams;
    unsigned npin;
    uint8_t pin_reg[6];
    uint8_t pin_host[6];
    bool pin_written[6];
    struct fast_ptr ptrs[FAST_LOOP_MAX_PTRS];
    struct fast_stream streams[FAST_LOOP_MAX_STREAMS];
};

static bool simd_reads_nzcv(uint32_t insn)
{
    if ((FIELD(insn, 31, 28) & 0x5) != 0x1 || BIT(insn, 24) || !BIT(insn, 21))
        return false;
    if (FIELD(insn, 15, 10) == 0)
        return false;
    unsigned op = FIELD(insn, 11, 10);
    return op == 1 || op == 3; /* FCCMP/FCCMPE, FCSEL */
}

static bool simd_writes_nzcv(uint32_t insn)
{
    if ((FIELD(insn, 31, 28) & 0x5) != 0x1 || BIT(insn, 24) || !BIT(insn, 21))
        return false;
    if (FIELD(insn, 15, 10) == 0) /* FJCVTZS */
        return !BIT(insn, 31) && FIELD(insn, 23, 22) == 1 && FIELD(insn, 20, 19) == 3 &&
               FIELD(insn, 18, 16) == 6;
    unsigned op = FIELD(insn, 11, 10);
    return op == 1 || (op == 0 && !BIT(insn, 12) && BIT(insn, 13)); /* FCCMP/E, FCMP/E */
}

static bool dp_is_flagm(uint32_t insn)
{
    return FIELD(insn, 28, 26) != 4 && BIT(insn, 28) && FIELD(insn, 24, 21) == 0 &&
           FIELD(insn, 15, 10) != 0;
}

static bool dp_reads_nzcv(uint32_t insn)
{
    if (FIELD(insn, 28, 26) == 4 || !BIT(insn, 28))
        return false;
    unsigned op2 = FIELD(insn, 24, 21);
    return op2 == 0 || op2 == 2 || op2 == 4; /* ADC/SBC/FlagM, CCMP/CCMN, CSEL */
}

static bool dp_writes_nzcv(uint32_t insn)
{
    if (FIELD(insn, 28, 26) == 4) {
        unsigned g = FIELD(insn, 25, 23);
        return (g == 2 && BIT(insn, 29)) || (g == 4 && FIELD(insn, 30, 29) == 3);
    }
    if (!BIT(insn, 28))
        return BIT(insn, 24) ? BIT(insn, 29) : FIELD(insn, 30, 29) == 3;
    unsigned op2 = FIELD(insn, 24, 21);
    if (op2 == 2) /* CCMP/CCMN */
        return true;
    if (op2 == 0) /* ADCS/SBCS or FlagM */
        return BIT(insn, 29) || FIELD(insn, 15, 10) != 0;
    return false;
}

static bool dp_reads_rd(uint32_t insn)
{
    if (FIELD(insn, 28, 26) != 4)
        return false;
    unsigned g = FIELD(insn, 25, 23), opc = FIELD(insn, 30, 29);
    return (g == 5 && opc == 3) || (g == 6 && opc == 1); /* MOVK, BFM */
}

static unsigned count_distinct_stolen(const struct xlate *x, uint32_t insn, const struct operands *o)
{
    unsigned seen[3], n = 0;
    for (unsigned i = 0; i < o->n; i++) {
        unsigned r = (insn >> o->pos[i]) & 31;
        if ((r == 31 && o->sp[i]) || !is_stolen(r))
            continue;
        unsigned k;
        for (k = 0; k < n && seen[k] != r; k++)
            ;
        if (k == n) {
            if (n == 3)
                return 4;
            seen[n++] = r;
        }
    }
    return n;
}

/* Record that guest register r (0..30) was read by a non-pointer-preserving operation */
static void fl_mark_read(unsigned r, const int8_t sym_root[31], uint32_t written, uint32_t *rbw,
                         uint32_t *nonptr)
{
    if (r >= 31)
        return;
    if (!(written & (1u << r)))
        *rbw |= 1u << r;
    if (sym_root[r] >= 0)
        *nonptr |= 1u << (unsigned)sym_root[r];
}

static bool analyze_fast_loop(struct xlate *x, struct fast_loop *fl)
{
    if (x->limit == 0)
        return false;

    int8_t sym_root[31], sym_sreg[31];
    int64_t sym_off[31];
    /* Block-local derived 64-bit index expressions: (reg0 + reg1 + off) << shift (reg1 == -1 if single). */
    struct sym_idx {
        int8_t reg0, reg1;
        int64_t off;
        uint8_t shift;
    } sym_idx[31];
    struct raw_stream {
        uint8_t root, idx_reg, idx_reg2, idx_opt, idx_shift;
        bool write;
        int32_t lo, hi;
    } raw[FAST_LOOP_MAX_STREAMS];
    unsigned nraw = 0;
    uint32_t used_as_ptr = 0, used_as_nonptr = 0;
    uint32_t written = 0, read_before_write = 0;
    uint32_t w32_valid = (1u << 31) - 1;
    uint32_t w32_step[31] = {0};
    unsigned write_count[31] = {0};
    unsigned last_write_idx[31] = {0};
    unsigned flag_writers = 0, last_flag_idx = 0;
    bool nzcv_written = false, nzcv_read_after_last_write = false;
    bool has_deferred_cmp = false;
    unsigned deferred_cmp_idx = 0;
    int8_t deferred_cmp_root0 = -1, deferred_cmp_root1 = -1;
    unsigned body_words = 0;

    for (unsigned r = 0; r < 31; r++) {
        sym_root[r] = (int8_t)r;
        sym_sreg[r] = -1;
        sym_off[r] = 0;
        sym_idx[r] = (struct sym_idx){.reg0 = (int8_t)r, .reg1 = -1, .off = 0, .shift = 0};
    }

    unsigned back_idx = 0;
    uint32_t back_insn = 0;
    bool found_back = false;

    for (unsigned i = 0; i < MAX_BLOCK_INSNS; i++) {
        uint32_t insn;
        if (!fetch_guest_fast(x, i, &insn))
            return false;
        uint64_t va = x->pc + 4ull * i;
        unsigned top = FIELD(insn, 28, 25);

        /* Check for closing conditional back-edge targeting x->pc */
        if ((insn & 0xff000010) == 0x54000000 || (insn & 0x7e000000) == 0x34000000) {
            uint64_t target = va + (uint64_t)(sext(FIELD(insn, 23, 5), 19) * 4);
            if (target == x->pc && i > 0) {
                if (!dbt_tier0_defined(x->probe, x->defined, insn, va))
                    return false;
                back_idx = i;
                back_insn = insn;
                found_back = true;
                break;
            }
            return false;
        }
        if (insn == 0xd503201f) /* NOP */
            continue;

        if ((top & 7) == 7) { /* SIMD&FP data processing */
            struct native_desc nd;
            if (!appine_has(APPINE_HWCAP_FP | APPINE_HWCAP_ASIMD) || !appine_native_available() ||
                !appine_simd_dp_decode(insn, &nd))
                return false;
            bool reads_flags = simd_reads_nzcv(insn);
            bool writes_flags = simd_writes_nzcv(insn);
            if (reads_flags) {
                if (!nzcv_written)
                    return false;
                nzcv_read_after_last_write = true;
            }
            if (writes_flags) {
                nzcv_written = true;
                flag_writers++;
                last_flag_idx = i;
                nzcv_read_after_last_write = false;
            }
            struct operands o = {.n = 0, .writes_rd = false};
            for (unsigned k = 0; k < nd.n; k++) {
                add_operand(&o, nd.gpr[k].pos, false);
                unsigned r = (insn >> nd.gpr[k].pos) & 31;
                if (nd.gpr[k].load)
                    fl_mark_read(r, sym_root, written, &read_before_write, &used_as_nonptr);
            }
            unsigned ns = count_distinct_stolen(x, insn, &o);
            if (ns > 2)
                return false;
            body_words += 1 + ns * 2;
            for (unsigned k = 0; k < nd.n; k++) {
                if (nd.gpr[k].store) {
                    unsigned r = (insn >> nd.gpr[k].pos) & 31;
                    if (r < 31) {
                        sym_root[r] = -1;
                        sym_sreg[r] = -1;
                        sym_idx[r].reg0 = -1;
                        w32_valid &= ~(1u << r);
                        written |= 1u << r;
                        write_count[r]++;
                        last_write_idx[r] = i;
                    }
                }
            }
            continue;
        }

        if (!dbt_tier0_defined(x->probe, x->defined, insn, va))
            return false;

        if (top == 0x4 || top == 0x6 || top == 0xc || top == 0xe) { /* Memory access */
            struct memop m;
            if (dbt_is_atomic(insn) ||
                !(BIT(insn, 26) ? dbt_decode_simd_memop(insn, va, &m) : dbt_decode_memop(insn, va, &m)))
                return false;
            if (m.prefetch)
                continue;
            if (m.mode == M_LITERAL || m.wb_reg || (m.rn == 31 && m.mode != M_OFFSET))
                return false;
            if ((m.mode == M_PRE || m.mode == M_POST) && !m.simd &&
                (m.rt == m.rn || (m.pair && m.rt2 == m.rn)))
                return false;
            if (m.pair && !m.simd && m.load && m.rt == m.rt2)
                return false;
            if (m.rn < 31 && (sym_root[m.rn] < 0 || sym_sreg[m.rn] >= 0))
                return false;

            unsigned idx_reg = 31, idx_reg2 = 31, idx_opt = 0, idx_shift = 0;
            int64_t idx_cur_off = 0;
            if (m.mode == M_REG && m.rm < 31) {
                if (sym_root[m.rm] == (int8_t)m.rm && sym_sreg[m.rm] < 0) {
                    if (sym_off[m.rm] != 0 && m.option != 3 && m.option != 7)
                        return false;
                    idx_reg = m.rm;
                    idx_opt = m.option;
                    idx_shift = m.shift;
                    idx_cur_off = sym_off[m.rm] * (int64_t)(1u << m.shift);
                    fl_mark_read(m.rm, sym_root, written, &read_before_write, &used_as_nonptr);
                } else if ((m.option == 3 || m.option == 7) && sym_idx[m.rm].reg0 >= 0 &&
                           sym_idx[m.rm].shift + m.shift <= 4) {
                    unsigned tot_shift = sym_idx[m.rm].shift + m.shift;
                    idx_reg = (unsigned)sym_idx[m.rm].reg0;
                    idx_reg2 = sym_idx[m.rm].reg1 >= 0 ? (unsigned)sym_idx[m.rm].reg1 : 31;
                    if (idx_reg2 < 31 && idx_reg > idx_reg2) {
                        unsigned tmp = idx_reg;
                        idx_reg = idx_reg2;
                        idx_reg2 = tmp;
                    }
                    idx_opt = m.option;
                    idx_shift = tot_shift;
                    idx_cur_off = sym_idx[m.rm].off * (int64_t)(1u << tot_shift);
                    fl_mark_read(m.rm, sym_root, written, &read_before_write, &used_as_nonptr);
                    used_as_nonptr |= 1u << idx_reg;
                    if (idx_reg2 < 31)
                        used_as_nonptr |= 1u << idx_reg2;
                } else {
                    return false;
                }
            }

            unsigned seen[2], ns = 0;
            if (m.rn < 31 && is_stolen(m.rn))
                seen[ns++] = m.rn;
            if (m.mode == M_REG && m.rm < 31 && is_stolen(m.rm) && (ns == 0 || seen[0] != m.rm)) {
                if (ns == 2)
                    return false;
                seen[ns++] = m.rm;
            }
            if (!m.simd) {
                if (m.rt < 31 && is_stolen(m.rt)) {
                    unsigned k;
                    for (k = 0; k < ns && seen[k] != m.rt; k++)
                        ;
                    if (k == ns) {
                        if (ns == 2)
                            return false;
                        seen[ns++] = m.rt;
                    }
                }
                if (m.pair && m.rt2 < 31 && is_stolen(m.rt2)) {
                    unsigned k;
                    for (k = 0; k < ns && seen[k] != m.rt2; k++)
                        ;
                    if (k == ns) {
                        if (ns == 2)
                            return false;
                        seen[ns++] = m.rt2;
                    }
                }
            }
            body_words +=
                1 + ns * 2 + ((m.mode == M_PRE || m.mode == M_POST) && m.rn < 31 && is_stolen(m.rn) ? 1 : 0);

            if (m.rn < 31 && !(written & (1u << m.rn)))
                read_before_write |= 1u << m.rn;
            unsigned root = m.rn == 31 ? 31 : (unsigned)sym_root[m.rn];
            int64_t base_off = m.rn == 31 ? 0 : sym_off[m.rn];
            int64_t start = base_off + idx_cur_off +
                            (m.mode == M_POST || m.mode == M_REG ? 0 : m.imm);
            int64_t end = start + (int64_t)memop_bytes(&m);
            if (start < -4095 || start > 4095 || end < -4095 || end > 8192)
                return false;
            used_as_ptr |= 1u << root;
            unsigned si;
            for (si = 0; si < nraw; si++) {
                if (raw[si].root == root && raw[si].idx_reg == idx_reg && raw[si].idx_reg2 == idx_reg2 &&
                    raw[si].idx_opt == idx_opt && raw[si].idx_shift == idx_shift)
                    break;
            }
            if (si == nraw) {
                if (nraw >= FAST_LOOP_MAX_STREAMS)
                    return false;
                raw[nraw++] = (struct raw_stream){
                    .root = (uint8_t)root,
                    .idx_reg = (uint8_t)idx_reg,
                    .idx_reg2 = (uint8_t)idx_reg2,
                    .idx_opt = (uint8_t)idx_opt,
                    .idx_shift = (uint8_t)idx_shift,
                    .write = !m.load,
                    .lo = (int32_t)start,
                    .hi = (int32_t)end,
                };
            } else {
                if (start < raw[si].lo)
                    raw[si].lo = (int32_t)start;
                if (end > raw[si].hi)
                    raw[si].hi = (int32_t)end;
                if (!m.load)
                    raw[si].write = true;
            }
            if (!m.load && !m.simd) {
                fl_mark_read(m.rt, sym_root, written, &read_before_write, &used_as_nonptr);
                if (m.pair)
                    fl_mark_read(m.rt2, sym_root, written, &read_before_write, &used_as_nonptr);
            }
            if (m.mode == M_PRE || m.mode == M_POST) {
                sym_off[m.rn] += m.imm;
                if (sym_idx[m.rn].reg0 >= 0 && sym_idx[m.rn].shift == 0)
                    sym_idx[m.rn].off += m.imm;
                else
                    sym_idx[m.rn].reg0 = -1;
                w32_valid &= ~(1u << m.rn);
                written |= 1u << m.rn;
                write_count[m.rn]++;
                last_write_idx[m.rn] = i;
            }
            if (m.load && !m.simd) {
                if (m.rt < 31) {
                    sym_root[m.rt] = -1;
                    sym_sreg[m.rt] = -1;
                    sym_idx[m.rt].reg0 = -1;
                    w32_valid &= ~(1u << m.rt);
                    written |= 1u << m.rt;
                    write_count[m.rt]++;
                    last_write_idx[m.rt] = i;
                }
                if (m.pair && m.rt2 < 31) {
                    sym_root[m.rt2] = -1;
                    sym_sreg[m.rt2] = -1;
                    sym_idx[m.rt2].reg0 = -1;
                    w32_valid &= ~(1u << m.rt2);
                    written |= 1u << m.rt2;
                    write_count[m.rt2]++;
                    last_write_idx[m.rt2] = i;
                }
            }
            continue;
        }

        if (top == 0x8 || top == 0x9 || top == 0x5 || top == 0xd) { /* Integer DP */
            if (FIELD(insn, 28, 24) == 0x10 || dp_is_flagm(insn)) /* ADR/ADRP, FlagM */
                return false;
            struct operands o;
            if (!dbt_dp_operands(insn, &o))
                return false;
            bool reads_flags = dp_reads_nzcv(insn);
            bool writes_flags = dp_writes_nzcv(insn);
            if (reads_flags) {
                if (!nzcv_written)
                    return false;
                nzcv_read_after_last_write = true;
            }
            for (unsigned k = 0; k < o.n; k++) {
                if (((insn >> o.pos[k]) & 31) == 31 && o.sp[k])
                    return false; /* do not touch SP */
            }
            unsigned ns = count_distinct_stolen(x, insn, &o);
            if (ns > 2)
                return false;
            body_words += 1 + ns * 2;

            if (writes_flags) {
                nzcv_written = true;
                flag_writers++;
                last_flag_idx = i;
                nzcv_read_after_last_write = false;
            }

            uint32_t op = insn & 0xff800000;
            unsigned rd = insn & 31, rn = FIELD(insn, 9, 5);
            /* 64-bit ADD/SUB immediate (non-flag-setting): preserves pointer affine relation */
            if (op == 0x91000000 || op == 0xd1000000) {
                if (!(written & (1u << rn)))
                    read_before_write |= 1u << rn;
                int64_t imm = (int64_t)FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0);
                if (op == 0xd1000000)
                    imm = -imm;
                struct sym_idx idx_in = sym_idx[rn];
                if (sym_root[rn] >= 0) {
                    sym_root[rd] = sym_root[rn];
                    sym_sreg[rd] = sym_sreg[rn];
                    sym_off[rd] = sym_off[rn] + imm;
                } else {
                    sym_root[rd] = -1;
                    sym_sreg[rd] = -1;
                }
                if (idx_in.reg0 >= 0 && idx_in.shift == 0) {
                    idx_in.off += imm;
                    sym_idx[rd] = idx_in;
                } else {
                    sym_idx[rd].reg0 = -1;
                }
                w32_valid &= ~(1u << rd);
                written |= 1u << rd;
                write_count[rd]++;
                last_write_idx[rd] = i;
                continue;
            }
            /* 64-bit MOV Xd, Xm (ORR Xd, XZR, Xm): preserves pointer affine relation */
            if ((insn & 0xffe0ffe0) == 0xaa0003e0) {
                unsigned rm = FIELD(insn, 20, 16);
                if (rm < 31 && !(written & (1u << rm)))
                    read_before_write |= 1u << rm;
                if (rd < 31) {
                    struct sym_idx idx_in = rm < 31 ? sym_idx[rm] : (struct sym_idx){.reg0 = -1};
                    if (rm < 31 && sym_root[rm] >= 0) {
                        sym_root[rd] = sym_root[rm];
                        sym_sreg[rd] = sym_sreg[rm];
                        sym_off[rd] = sym_off[rm];
                    } else {
                        sym_root[rd] = -1;
                        sym_sreg[rd] = -1;
                    }
                    sym_idx[rd] = idx_in;
                    w32_valid &= ~(1u << rd);
                    written |= 1u << rd;
                    write_count[rd]++;
                    last_write_idx[rd] = i;
                }
                continue;
            }
            /* 64-bit ADD Xd, Xn, Xm (unshifted): tracks register stride (in-place) or derived sum index */
            if ((insn & 0xffe0fc00) == 0x8b000000) {
                unsigned rm = FIELD(insn, 20, 16);
                unsigned sreg = (rd == rn) ? rm : (rd == rm ? rn : 31);
                if (rd < 31 && sreg < 31 && sreg != rd && sym_root[rd] == (int8_t)rd &&
                    sym_sreg[rd] == -1) {
                    if (!(written & (1u << rd)))
                        read_before_write |= 1u << rd;
                    fl_mark_read(sreg, sym_root, written, &read_before_write, &used_as_nonptr);
                    sym_sreg[rd] = (int8_t)sreg;
                    sym_idx[rd].reg0 = -1;
                    w32_valid &= ~(1u << rd);
                    written |= 1u << rd;
                    write_count[rd]++;
                    last_write_idx[rd] = i;
                    continue;
                }
                if (rd < 31 && rn < 31 && rm < 31 && sym_root[rn] >= 0 && sym_sreg[rn] < 0 &&
                    sym_root[rm] >= 0 && sym_sreg[rm] < 0) {
                    struct sym_idx s = {
                        .reg0 = sym_root[rn],
                        .reg1 = sym_root[rm],
                        .off = sym_off[rn] + sym_off[rm],
                        .shift = 0,
                    };
                    fl_mark_read(rn, sym_root, written, &read_before_write, &used_as_nonptr);
                    fl_mark_read(rm, sym_root, written, &read_before_write, &used_as_nonptr);
                    sym_root[rd] = -1;
                    sym_sreg[rd] = -1;
                    sym_idx[rd] = s;
                    w32_valid &= ~(1u << rd);
                    written |= 1u << rd;
                    write_count[rd]++;
                    last_write_idx[rd] = i;
                    continue;
                }
            }
            /* 64-bit LSL Xd, Xn, #sh (UBFM Xd, Xn, #64-sh, #63-sh, 1 <= sh <= 4): shifts derived index */
            if ((insn & 0xffc00000) == 0xd3400000 && rd < 31 && rn < 31) {
                unsigned immr = FIELD(insn, 21, 16), imms = FIELD(insn, 15, 10);
                if (imms != 63 && immr == imms + 1) {
                    unsigned sh = 64 - immr;
                    if (sh >= 1 && sh <= 4 && sym_idx[rn].reg0 >= 0 && sym_idx[rn].shift + sh <= 4) {
                        struct sym_idx s = sym_idx[rn];
                        s.shift += (uint8_t)sh;
                        fl_mark_read(rn, sym_root, written, &read_before_write, &used_as_nonptr);
                        sym_root[rd] = -1;
                        sym_sreg[rd] = -1;
                        sym_idx[rd] = s;
                        w32_valid &= ~(1u << rd);
                        written |= 1u << rd;
                        write_count[rd]++;
                        last_write_idx[rd] = i;
                        continue;
                    }
                }
            }
            /* 32-bit ADD Wd, Wd, #imm (non-flag-setting): tracks 32-bit loop counter step */
            if (op == 0x11000000 && rd == rn && rd < 31) {
                uint32_t imm = FIELD(insn, 21, 10) << (BIT(insn, 22) ? 12 : 0);
                fl_mark_read(rn, sym_root, written, &read_before_write, &used_as_nonptr);
                sym_root[rd] = -1;
                sym_sreg[rd] = -1;
                sym_idx[rd].reg0 = -1;
                if (imm > 0 && w32_step[rd] + imm <= 4096)
                    w32_step[rd] += imm;
                else
                    w32_valid &= ~(1u << rd);
                written |= 1u << rd;
                write_count[rd]++;
                last_write_idx[rd] = i;
                continue;
            }
            /* CMP Xn, Xm / CMP Wn, Wm / CMP Xn, #imm / CMP Wn, #imm: omitted in fast loop when
             * it is the loop-closing CMP, so defer non-pointer tainting until control matching. */
            bool is_cmp = (insn & 0x7fe0fc1f) == 0x6b00001f || (insn & 0x7f80001f) == 0x7100001f;
            if (is_cmp && writes_flags) {
                if (has_deferred_cmp) {
                    if (deferred_cmp_root0 >= 0)
                        used_as_nonptr |= 1u << (unsigned)deferred_cmp_root0;
                    if (deferred_cmp_root1 >= 0)
                        used_as_nonptr |= 1u << (unsigned)deferred_cmp_root1;
                }
                has_deferred_cmp = true;
                deferred_cmp_idx = i;
                deferred_cmp_root0 = rn < 31 ? sym_root[rn] : -1;
                deferred_cmp_root1 = -1;
                if (rn < 31 && !(written & (1u << rn)))
                    read_before_write |= 1u << rn;
                if ((insn & 0x7fe0fc1f) == 0x6b00001f) {
                    unsigned rm = FIELD(insn, 20, 16);
                    if (rm < 31) {
                        deferred_cmp_root1 = sym_root[rm];
                        if (!(written & (1u << rm)))
                            read_before_write |= 1u << rm;
                    }
                }
                continue;
            }

            /* General DP instruction: reading any register taints its root as non-pointer */
            bool reads_rd = dp_reads_rd(insn);
            for (unsigned k = 0; k < o.n; k++) {
                if (o.pos[k] == 0 && o.writes_rd && !reads_rd)
                    continue;
                fl_mark_read((insn >> o.pos[k]) & 31, sym_root, written, &read_before_write,
                             &used_as_nonptr);
            }
            if (o.writes_rd && rd < 31) {
                sym_root[rd] = -1;
                sym_sreg[rd] = -1;
                sym_idx[rd].reg0 = -1;
                w32_valid &= ~(1u << rd);
                written |= 1u << rd;
                write_count[rd]++;
                last_write_idx[rd] = i;
            }
            continue;
        }

        return false;
    }

    if (!found_back || !used_as_ptr)
        return false;

    /* Match the loop-closing counter and condition */
    *fl = (struct fast_loop){.back_idx = back_idx};
    bool matched_ctrl = false;

    if ((back_insn & 0x7f000000) == 0x35000000) {
        /* CBNZ Xc/Wc: require SUB Xc/Wc, Xc/Wc, #imm with no other writes to c */
        unsigned c = back_insn & 31;
        bool is64 = BIT(back_insn, 31);
        if (c < 31 && write_count[c] == 1 && !(used_as_ptr & (1u << c))) {
            unsigned ci = last_write_idx[c];
            uint32_t ci_insn = x->words[ci];
            uint32_t expect = is64 ? 0xd1000000u : 0x51000000u;
            if ((ci_insn & 0xff800000) == expect && (ci_insn & 31) == c && FIELD(ci_insn, 9, 5) == c) {
                uint32_t imm = FIELD(ci_insn, 21, 10) << (BIT(ci_insn, 22) ? 12 : 0);
                if (imm >= 1 && imm <= 4096) {
                    fl->kind = FL_COUNTDOWN;
                    fl->ctrl_idx = ci;
                    fl->cnt_reg = c;
                    fl->is_64 = is64;
                    fl->step = imm;
                    fl->cd_cond = 1; /* NE */
                    matched_ctrl = true;
                }
            }
        }
    } else if ((back_insn & 0xff000010) == 0x54000000 && flag_writers >= 1 &&
               !nzcv_read_after_last_write) {
        unsigned cond = back_insn & 15;
        unsigned flag_idx = last_flag_idx;
        uint32_t fi_insn = x->words[flag_idx];
        /* Pattern 1: SUBS Xc/Wc, Xc/Wc, #imm + B.NE/HI/GT/GE/PL */
        if (((fi_insn & 0x7f800000) == 0x71000000) && (fi_insn & 31) < 31 &&
            (fi_insn & 31) == FIELD(fi_insn, 9, 5) &&
            (cond == 1 || cond == 5 || cond == 8 || cond == 10 || cond == 12)) {
            unsigned c = fi_insn & 31;
            uint32_t imm = FIELD(fi_insn, 21, 10) << (BIT(fi_insn, 22) ? 12 : 0);
            if (write_count[c] == 1 && !(used_as_ptr & (1u << c)) && imm >= 1 && imm <= 4096) {
                fl->kind = FL_COUNTDOWN;
                fl->ctrl_idx = flag_idx;
                fl->cnt_reg = c;
                fl->is_64 = BIT(fi_insn, 31);
                fl->step = imm;
                fl->cd_cond = cond;
                matched_ctrl = true;
            }
        }
        /* Pattern 2: CMP reg, reg or CMP reg, #imm + B.cond (direct or affine-derived operand) */
        if (!matched_ctrl &&
            ((fi_insn & 0x7fe0fc1f) == 0x6b00001f || (fi_insn & 0x7f80001f) == 0x7100001f)) {
            bool is64 = BIT(fi_insn, 31);
            bool is_imm = (fi_insn & 0x7f80001f) == 0x7100001f;
            unsigned rn = FIELD(fi_insn, 9, 5);
            unsigned rm = is_imm ? 31 : FIELD(fi_insn, 20, 16);
            /* Try both orientations for register compare: (B=rn, D=rm) vs (D=rn, B=rm).
             * Immediate compare always has (D=rn, B=imm). */
            for (unsigned side = 0; side < (is_imm ? 1u : 2u) && !matched_ctrl; side++) {
                bool cnt_first = is_imm || side == 1;
                unsigned d = cnt_first ? rn : rm;
                unsigned b = cnt_first ? rm : rn;
                if (d >= 31)
                    continue;
                if (!is_imm && (b >= 31 || b == d || (written & (1u << b)) || (used_as_ptr & (1u << b))))
                    continue;
                /* Compared register must be written strictly before flag_idx and not afterward */
                if (!(written & (1u << d)) || last_write_idx[d] >= flag_idx)
                    continue;
                unsigned c = d;
                uint32_t step = 0;
                int64_t cmp_off = 0;
                if (is64) {
                    if (sym_root[d] < 0 || sym_sreg[d] >= 0)
                        continue;
                    c = (unsigned)sym_root[d];
                    if ((!is_imm && c == b) || sym_root[c] != (int8_t)c || sym_sreg[c] >= 0 ||
                        sym_off[c] <= 0 || sym_off[c] > 4096)
                        continue;
                    if (d != c && ((used_as_ptr & (1u << c)) || (used_as_ptr & (1u << d)) ||
                                   sym_off[d] < -4095 || sym_off[d] > 4095))
                        continue;
                    step = (uint32_t)sym_off[c];
                    cmp_off = sym_off[d];
                } else {
                    if (used_as_ptr & (1u << d))
                        continue;
                    if (((w32_valid >> d) & 1) && w32_step[d] > 0)
                        step = w32_step[d];
                    else if (sym_root[d] == (int8_t)d && sym_sreg[d] < 0 && sym_off[d] > 0 &&
                             sym_off[d] <= 4096)
                        step = (uint32_t)sym_off[d];
                    else
                        continue;
                    cmp_off = (int64_t)step;
                }
                enum fast_cmp_kind ck;
                bool cond_ok = true;
                if (cond == 1) {
                    ck = FL_NE;
                } else if (!cnt_first) { /* CMP B, D */
                    if (cond == 12)
                        ck = FL_SLT;
                    else if (cond == 10)
                        ck = FL_SLE;
                    else if (cond == 8)
                        ck = FL_ULT;
                    else if (cond == 2)
                        ck = FL_ULE;
                    else
                        cond_ok = false;
                } else { /* CMP D, B */
                    if (cond == 11)
                        ck = FL_SLT;
                    else if (cond == 13)
                        ck = FL_SLE;
                    else if (cond == 3)
                        ck = FL_ULT;
                    else if (cond == 9)
                        ck = FL_ULE;
                    else
                        cond_ok = false;
                }
                if (!cond_ok)
                    continue;
                fl->kind = FL_CMP_INC;
                fl->ctrl_idx = flag_idx;
                fl->cnt_reg = c;
                fl->bound_reg = b;
                fl->bound_is_imm = is_imm;
                fl->bound_imm = is_imm ? (FIELD(fi_insn, 21, 10) << (BIT(fi_insn, 22) ? 12 : 0)) : 0;
                fl->is_64 = is64;
                fl->step = step;
                fl->cmp_off = cmp_off;
                fl->cmp = ck;
                matched_ctrl = true;
            }
        }
    }

    if (!matched_ctrl)
        return false;

    /* Any CMP that did NOT become the omitted loop-closing CMP executes in the body and reads its
     * operands as non-pointers. */
    if (has_deferred_cmp && !(fl->kind == FL_CMP_INC && fl->ctrl_idx == deferred_cmp_idx)) {
        if (deferred_cmp_root0 >= 0)
            used_as_nonptr |= 1u << (unsigned)deferred_cmp_root0;
        if (deferred_cmp_root1 >= 0)
            used_as_nonptr |= 1u << (unsigned)deferred_cmp_root1;
    }

    /* Validate every root base pointer (0..30 or 31 = SP) and collect live end-of-iteration aliases */
    int8_t ptr_map[32];
    for (unsigned r = 0; r < 32; r++)
        ptr_map[r] = -1;
    for (uint32_t bits = used_as_ptr; bits; bits &= bits - 1) {
        unsigned r = (unsigned)__builtin_ctz(bits);
        if (fl->nptrs >= FAST_LOOP_MAX_PTRS)
            return false;
        if (r == 31) {
            fl->uses_sp = true;
            ptr_map[31] = (int8_t)fl->nptrs;
            fl->ptrs[fl->nptrs++] = (struct fast_ptr){.reg = 31, .alias_mask = 0};
            continue;
        }
        if (used_as_nonptr & (1u << r))
            return false;
        if (sym_root[r] != (int8_t)r)
            return false;
        if (sym_sreg[r] >= 0) {
            unsigned sr = (unsigned)sym_sreg[r];
            if (sym_off[r] != 0 || (written & (1u << sr)) || (used_as_ptr & (1u << sr)))
                return false;
        } else if (sym_off[r] < 0) {
            return false;
        }
        uint32_t alias_mask = 0;
        for (unsigned a = 0; a < 31; a++) {
            if (a != r && sym_root[a] == (int8_t)r) {
                /* An alias carrying addend_r at iteration end must not have been read before its
                 * first write (otherwise iteration 2 would observe the shifted pointer value). */
                if (read_before_write & (1u << a))
                    return false;
                alias_mask |= 1u << a;
            }
        }
        ptr_map[r] = (int8_t)fl->nptrs;
        fl->ptrs[fl->nptrs++] = (struct fast_ptr){
            .reg = (uint8_t)r,
            .alias_mask = alias_mask,
        };
    }

    /* Validate every access stream and resolve its per-iteration byte stride */
    bool has_positive_stride = false;
    uint32_t ptr_seen = 0;
    for (unsigned s = 0; s < nraw; s++) {
        unsigned r = raw[s].root;
        unsigned pi = (unsigned)ptr_map[r];
        uint32_t span = (uint32_t)(raw[s].hi - raw[s].lo);
        if (span == 0 || span > APPINE_PAGE_SIZE)
            return false;
        uint8_t sreg = (r < 31 && sym_sreg[r] >= 0) ? (uint8_t)sym_sreg[r] : 31;
        uint64_t cstride = (r == 31 || sreg < 31) ? 0 : (uint64_t)sym_off[r];
        unsigned idx_regs[2] = {raw[s].idx_reg, raw[s].idx_reg2};
        for (unsigned k = 0; k < 2; k++) {
            unsigned ir = idx_regs[k];
            if (ir < 31 && (written & (1u << ir))) {
                /* Induction index: must be 64-bit LSL/SXTX with positive constant step */
                if (sreg < 31 || (raw[s].idx_opt != 3 && raw[s].idx_opt != 7))
                    return false;
                if (sym_root[ir] != (int8_t)ir || sym_sreg[ir] >= 0 || sym_off[ir] <= 0 ||
                    sym_off[ir] > 4096)
                    return false;
                cstride += (uint64_t)sym_off[ir] << raw[s].idx_shift;
            }
        }
        if (sreg < 31) {
            if (span >= APPINE_PAGE_SIZE)
                return false;
            has_positive_stride = true;
        } else if (cstride > 0) {
            if (cstride + span > APPINE_PAGE_SIZE)
                return false; /* fewer than 2 iterations could ever fit in one page */
            has_positive_stride = true;
        }
        bool first = !(ptr_seen & (1u << pi));
        ptr_seen |= 1u << pi;
        fl->streams[fl->nstreams++] = (struct fast_stream){
            .ptr_idx = (uint8_t)pi,
            .idx_reg = raw[s].idx_reg,
            .idx_reg2 = raw[s].idx_reg2,
            .idx_opt = raw[s].idx_opt,
            .idx_shift = raw[s].idx_shift,
            .stride_reg = sreg,
            .write = raw[s].write,
            .first_for_ptr = first,
            .lo = raw[s].lo,
            .hi = raw[s].hi,
            .stride = (uint32_t)cstride,
        };
    }

    if (!has_positive_stride)
        return false;

    /* Pick a power-of-2 KICK_BUDGET in [32, 256] so kick latency stays within a few microseconds */
    unsigned budget_log2 = 8; /* 256 */
    while (budget_log2 > 5 && ((1u << budget_log2) * back_idx > 12288))
        budget_log2--;
    fl->kick_log2 = budget_log2;

    /* Pin all stolen GPRs touched in the fast body so the native inner body has zero CTX traffic:
     * the first 2 use T0/T1 directly, and any additional stolen GPRs borrow unused non-stolen
     * guest registers (saved/restored across the fast loop in their dead cpu->x[] slots). */
    uint32_t body_stolen = 0, body_used = 0;
    for (unsigned i = 0; i < back_idx; i++) {
        uint32_t insn = x->words[i];
        if (insn == 0xd503201f)
            continue;
        bool omitted_cmp = fl->kind == FL_CMP_INC && i == fl->ctrl_idx;
        unsigned top = FIELD(insn, 28, 25);
        if ((top & 7) == 7) {
            struct native_desc nd;
            appine_simd_dp_decode(insn, &nd);
            for (unsigned k = 0; k < nd.n; k++) {
                unsigned r = (insn >> nd.gpr[k].pos) & 31;
                if (r < 31) {
                    body_used |= 1u << r;
                    if (!omitted_cmp && is_stolen(r))
                        body_stolen |= 1u << r;
                }
            }
        } else if (top == 0x4 || top == 0x6 || top == 0xc || top == 0xe) {
            struct memop m;
            uint64_t va = x->pc + 4ull * i;
            if (BIT(insn, 26))
                dbt_decode_simd_memop(insn, va, &m);
            else
                dbt_decode_memop(insn, va, &m);
            if (m.prefetch)
                continue;
            if (m.rn < 31) {
                body_used |= 1u << m.rn;
                if (is_stolen(m.rn))
                    body_stolen |= 1u << m.rn;
            }
            if (m.mode == M_REG && m.rm < 31) {
                body_used |= 1u << m.rm;
                if (is_stolen(m.rm))
                    body_stolen |= 1u << m.rm;
            }
            if (!m.simd) {
                if (m.rt < 31) {
                    body_used |= 1u << m.rt;
                    if (is_stolen(m.rt))
                        body_stolen |= 1u << m.rt;
                }
                if (m.pair && m.rt2 < 31) {
                    body_used |= 1u << m.rt2;
                    if (is_stolen(m.rt2))
                        body_stolen |= 1u << m.rt2;
                }
            }
        } else {
            struct operands o;
            dbt_dp_operands(insn, &o);
            for (unsigned k = 0; k < o.n; k++) {
                unsigned r = (insn >> o.pos[k]) & 31;
                if (r < 31) {
                    body_used |= 1u << r;
                    if (!omitted_cmp && is_stolen(r))
                        body_stolen |= 1u << r;
                }
            }
        }
    }
    if (body_stolen) {
        if (fl->cnt_reg < 31)
            body_used |= 1u << fl->cnt_reg;
        if (fl->kind == FL_CMP_INC && !fl->bound_is_imm && fl->bound_reg < 31)
            body_used |= 1u << fl->bound_reg;
        for (unsigned i = 0; i < fl->nptrs; i++) {
            if (fl->ptrs[i].reg < 31)
                body_used |= 1u << fl->ptrs[i].reg;
            body_used |= fl->ptrs[i].alias_mask;
        }
        unsigned n = 0;
        uint8_t preg[6], phost[6];
        bool pwr[6];
        bool ok = true;
        const unsigned base_pool[2] = {T0, T1};
        uint32_t avail = ((1u << 31) - 1) & ~body_used;
        for (uint32_t bits = body_stolen; bits; bits &= bits - 1) {
            unsigned r = (unsigned)__builtin_ctz(bits);
            unsigned hr = 31;
            if (n < 2) {
                hr = base_pool[n];
            } else {
                for (uint32_t cand = avail; cand; cand &= cand - 1) {
                    unsigned c = (unsigned)__builtin_ctz(cand);
                    if (!is_stolen(c)) {
                        hr = c;
                        avail &= ~(1u << c);
                        break;
                    }
                }
            }
            if (hr >= 31 || n >= 6) {
                ok = false;
                break;
            }
            preg[n] = (uint8_t)r;
            phost[n] = (uint8_t)hr;
            pwr[n] = ((written >> r) & 1) != 0;
            n++;
        }
        if (ok) {
            fl->npin = n;
            for (unsigned k = 0; k < n; k++) {
                fl->pin_reg[k] = preg[k];
                fl->pin_host[k] = phost[k];
                fl->pin_written[k] = pwr[k];
            }
            body_words = back_idx;
        }
    }

    /* Worst-case host words for prologue + fast body + epilogue must leave ample room for slow_loop */
    unsigned est_words = 36 + fl->nstreams * 48 + fl->nptrs * 10 + fl->npin * 6 + body_words + 64;
    if (est_words > FAST_LOOP_MAX_WORDS)
        return false;

    return true;
}

static bool fast_is_pinned(const struct fast_loop *fl, unsigned r)
{
    for (unsigned k = 0; k < fl->npin; k++) {
        if (fl->pin_reg[k] == r)
            return true;
    }
    return false;
}

static unsigned fast_pin_host(const struct fast_loop *fl, unsigned r)
{
    for (unsigned k = 0; k < fl->npin; k++) {
        if (fl->pin_reg[k] == r)
            return fl->pin_host[k];
    }
    return r;
}

static int fast_ptr_index(const struct fast_loop *fl, unsigned r)
{
    for (unsigned i = 0; i < fl->nptrs; i++) {
        if (fl->ptrs[i].reg == r)
            return (int)i;
    }
    return -1;
}

static int fast_ptr_or_alias_index(const struct fast_loop *fl, unsigned r)
{
    for (unsigned i = 0; i < fl->nptrs; i++) {
        if (fl->ptrs[i].reg == r || ((fl->ptrs[i].alias_mask >> r) & 1))
            return (int)i;
    }
    return -1;
}

/* Emit a data-processing / SIMD-DP instruction inside fast_loop_body using only T0 and T1 (T2 holds
 * the strip-mine trip counter) */
static void emit_fast_operands(struct xlate *x, uint32_t insn, const struct operands *o, bool reads_rd)
{
    const unsigned pool[2] = {T0, T1};
    unsigned guest[2], nmap = 0, rd_host = 0, rd_guest = 0;
    bool need_load[2] = {false, false};
    bool rd_stolen = false;
    uint32_t out = insn;
    for (unsigned i = 0; i < o->n; i++) {
        unsigned r = (insn >> o->pos[i]) & 31;
        if (!is_stolen(r))
            continue;
        unsigned k;
        for (k = 0; k < nmap && guest[k] != r; k++)
            ;
        if (k == nmap) {
            if (nmap == 2)
                appine_guard_fail();
            guest[nmap++] = r;
        }
        out = (out & ~(31u << o->pos[i])) | pool[k] << o->pos[i];
        if (o->pos[i] == 0 && o->writes_rd) {
            rd_stolen = true;
            rd_host = pool[k];
            rd_guest = r;
            if (reads_rd)
                need_load[k] = true;
        } else {
            need_load[k] = true;
        }
    }
    for (unsigned k = 0; k < nmap; k++) {
        if (need_load[k])
            emit_load_guest(x, pool[k], guest[k]);
    }
    emit(x, out);
    if (rd_stolen)
        emit_store_guest(x, rd_host, rd_guest);
}

/* Emit a direct host memory access inside fast_loop_body (Rn already holds a host address in its
 * register / SP_HOST, or is stolen in cpu->x[Rn]); uses only T0 and T1 so T2 stays intact */
static void emit_fast_memop(struct xlate *x, uint32_t insn, const struct memop *m)
{
    bool rn_sp = m->rn == 31;
    bool rn_s = !rn_sp && is_stolen(m->rn);
    bool rm_s = m->mode == M_REG && m->rm < 31 && is_stolen(m->rm);
    bool rt_s = !m->simd && m->rt < 31 && is_stolen(m->rt);
    bool rt2_s = m->pair && !m->simd && m->rt2 < 31 && is_stolen(m->rt2);
    if (!rn_sp && !rn_s && !rm_s && !rt_s && !rt2_s) {
        emit(x, insn);
        return;
    }
    if (m->mode == M_REG) {
        const unsigned pool[2] = {T0, T1};
        unsigned guest[2], nmap = 0;
        unsigned hrn = m->rn, hrm = m->rm, hrt = m->rt;
        if (rn_s) {
            guest[nmap++] = m->rn;
            hrn = pool[0];
            emit_load_guest(x, hrn, m->rn);
        }
        if (rm_s) {
            unsigned k;
            for (k = 0; k < nmap && guest[k] != m->rm; k++)
                ;
            if (k == nmap) {
                if (nmap == 2)
                    appine_guard_fail();
                guest[nmap++] = m->rm;
                emit_load_guest(x, pool[k], m->rm);
            }
            hrm = pool[k];
        }
        if (rt_s) {
            unsigned k;
            for (k = 0; k < nmap && guest[k] != m->rt; k++)
                ;
            if (k == nmap) {
                if (nmap == 2)
                    appine_guard_fail();
                guest[nmap++] = m->rt;
                if (!m->load)
                    emit_load_guest(x, pool[k], m->rt);
            }
            hrt = pool[k];
        }
        uint32_t out = (insn & ~(31u << 16 | 31u << 5)) | (hrm << 16) | (hrn << 5);
        if (!m->simd)
            out = (out & ~31u) | hrt;
        emit(x, out);
        if (rt_s && m->load)
            emit_store_guest(x, hrt, m->rt);
        return;
    }
    if (m->simd) {
        unsigned hrn = rn_sp ? SP_HOST : T0;
        if (rn_s)
            emit_load_guest(x, T0, m->rn);
        emit(x, (insn & ~(31u << 5)) | (hrn << 5));
        if (rn_s && (m->mode == M_PRE || m->mode == M_POST))
            emit_store_guest(x, T0, m->rn);
        return;
    }
    if (!m->pair) {
        unsigned hrn = rn_sp ? SP_HOST : rn_s ? T0 : m->rn;
        unsigned hrt = rt_s ? T1 : m->rt;
        if (rn_s)
            emit_load_guest(x, T0, m->rn);
        if (rt_s && !m->load)
            emit_load_guest(x, T1, m->rt);
        emit(x, (insn & ~(31u << 5 | 31u)) | (hrn << 5) | hrt);
        if (rn_s && (m->mode == M_PRE || m->mode == M_POST))
            emit_store_guest(x, T0, m->rn);
        if (rt_s && m->load)
            emit_store_guest(x, T1, m->rt);
        return;
    }
    /* Integer LDP/STP/LDPSW with <= 2 distinct stolen GPRs */
    unsigned hrn = rn_sp ? SP_HOST : rn_s ? T0 : m->rn;
    unsigned hrt = m->rt, hrt2 = m->rt2;
    if (rn_s) {
        emit_load_guest(x, T0, m->rn);
        if (rt_s)
            hrt = T1;
        if (rt2_s)
            hrt2 = T1;
    } else {
        if (rt_s)
            hrt = T0;
        if (rt2_s)
            hrt2 = (rt_s && m->rt2 == m->rt) ? T0 : (rt_s ? T1 : T0);
    }
    if (!m->load) {
        if (rt_s)
            emit_load_guest(x, hrt, m->rt);
        if (rt2_s && (!rt_s || m->rt2 != m->rt))
            emit_load_guest(x, hrt2, m->rt2);
    }
    emit(x, (insn & ~(31u << 10 | 31u << 5 | 31u)) | (hrt2 << 10) | (hrn << 5) | hrt);
    if (rn_s && (m->mode == M_PRE || m->mode == M_POST))
        emit_store_guest(x, T0, m->rn);
    if (m->load) {
        if (rt_s)
            emit_store_guest(x, hrt, m->rt);
        if (rt2_s)
            emit_store_guest(x, hrt2, m->rt2);
    }
}

/* Add or subtract T0 to/from guest register r (0..30 or 31 = SP) */
static void emit_adjust_reg(struct xlate *x, unsigned r, bool sub)
{
    if (r == 31) {
        emit(x, sub ? enc_sub_reg(SP_HOST, SP_HOST, T0) : enc_add_lsl(SP_HOST, SP_HOST, T0, 0));
    } else if (!is_stolen(r)) {
        emit(x, sub ? enc_sub_reg(r, r, T0) : enc_add_lsl(r, r, T0, 0));
    } else {
        emit_load_guest(x, T1, r);
        emit(x, sub ? enc_sub_reg(T1, T1, T0) : enc_add_lsl(T1, T1, T0, 0));
        emit_store_guest(x, T1, r);
    }
}

static void emit_fast_loop(struct xlate *x, const struct fast_loop *fl)
{
    uint32_t *bails[128];
    unsigned nbails = 0;
    size_t grp_off = offsetof(struct appine_cpu, dbt_groups);
    size_t iters_off = grp_off + 8 * 7;

    /* 1. Never bypass active hardware watchpoints; if SP is accessed, require 16-byte alignment */
    size_t nwatch = offsetof(struct appine_cpu, nwatch);
    emit_add_const(x, T0, CTX, (int64_t)(nwatch & ~(size_t)0xfff));
    emit(x, enc_ldr_w(T0, T0, nwatch & 0xfff));
    bails[nbails++] = here(x);
    emit(x, enc_cbnz_x(T0));
    if (fl->uses_sp) {
        emit(x, enc_and_low(T0, SP_HOST, 4));
        bails[nbails++] = here(x);
        emit(x, enc_cbnz_x(T0));
    }

    /* 2. Compute rem_backedges into T2 (NZCV-free), clamp to KICK_BUDGET, require >= 2 */
    if (fl->kind == FL_COUNTDOWN) {
        unsigned src = fl->cnt_reg;
        if (is_stolen(src)) {
            emit_load_guest(x, T2, src);
            src = T2;
        }
        bool is_signed = fl->cd_cond == 5 || fl->cd_cond == 10 || fl->cd_cond == 12;
        if (!fl->is_64)
            emit(x, is_signed ? enc_sbfx(T2, src, 0, 32) : enc_ubfx(T2, src, 0, 32));
        else if (src != T2)
            emit(x, enc_mov(T2, src));
        if (is_signed) {
            bails[nbails++] = here(x);
            emit(x, enc_tbnz(T2, 63));
        }
        if (fl->cd_cond == 1 || fl->cd_cond == 8 || fl->cd_cond == 12) { /* NE/HI/GT */
            bails[nbails++] = here(x);
            emit(x, enc_cbz_x(T2));
            emit(x, enc_sub_imm(T2, T2, 1, 0));
        }
        if (fl->step > 1) {
            if ((fl->step & (fl->step - 1)) == 0) {
                unsigned sh = (unsigned)__builtin_ctz(fl->step);
                emit(x, enc_ubfx(T2, T2, sh, 64 - sh));
            } else {
                emit_mov_const(x, T0, fl->step);
                emit(x, enc_udiv(T2, T2, T0));
            }
        }
        /* Clamp T2 to KICK_BUDGET = 1 << fl->kick_log2 */
        emit(x, enc_ubfx(T0, T2, fl->kick_log2, 64 - fl->kick_log2));
        uint32_t *no_clamp = here(x);
        emit(x, enc_cbz_x(T0));
        emit(x, enc_movz(T2, 1u << fl->kick_log2, 0));
        patch_local(x, no_clamp, here(x));
        /* Bail if safe_iters < 2 */
        emit(x, enc_ubfx(T0, T2, 1, 63));
        bails[nbails++] = here(x);
        emit(x, enc_cbz_x(T0));
    } else { /* FL_CMP_INC: iter j compares v_j = cnt_reg + cmp_off + j * step against bound */
        bool is_signed = fl->cmp == FL_SLT || fl->cmp == FL_SLE;
        /* Load bound into T0 and v_0 = cnt_reg + cmp_off into T1 */
        if (fl->bound_is_imm) {
            emit_mov_const(x, T0, fl->bound_imm);
        } else {
            unsigned b = fl->bound_reg;
            if (is_stolen(b)) {
                emit_load_guest(x, T0, b);
                b = T0;
            }
            if (!fl->is_64)
                emit(x, is_signed ? enc_sbfx(T0, b, 0, 32) : enc_ubfx(T0, b, 0, 32));
            else if (b != T0)
                emit(x, enc_mov(T0, b));
        }
        unsigned c = fl->cnt_reg;
        if (is_stolen(c)) {
            emit_load_guest(x, T1, c);
            c = T1;
        }
        emit_add_const(x, T1, c, fl->cmp_off);
        if (!fl->is_64)
            emit(x, is_signed ? enc_sbfx(T1, T1, 0, 32) : enc_ubfx(T1, T1, 0, 32));

        emit(x, enc_sub_reg(T2, T0, T1)); /* diff = B - v_0 */
        if (!fl->is_64) {
            if (fl->cmp == FL_NE) {
                emit(x, enc_ubfx(T2, T2, 0, 32));
                bails[nbails++] = here(x);
                emit(x, enc_cbz_x(T2));
            } else {
                bails[nbails++] = here(x);
                emit(x, enc_tbnz(T2, 63));
                bails[nbails++] = here(x);
                emit(x, enc_cbz_x(T2));
            }
        } else {
            bails[nbails++] = here(x);
            emit(x, enc_cbz_x(T2));
            if (fl->cmp == FL_ULT || fl->cmp == FL_ULE) {
                /* unsigned borrow = d ^ ((a ^ b) & (b ^ d)) */
                emit(x, enc_eor_lsr(T0, T0, T1, 0));
                emit(x, enc_eor_lsr(T1, T1, T2, 0));
                emit(x, enc_and_reg(T0, T0, T1));
                emit(x, enc_eor_lsr(T0, T0, T2, 0));
                bails[nbails++] = here(x);
                emit(x, enc_tbnz(T0, 63));
            } else if (fl->cmp == FL_SLT || fl->cmp == FL_SLE) {
                /* signed_lt = d ^ ((a ^ b) & (a ^ d)) */
                emit(x, enc_eor_lsr(T1, T0, T1, 0));
                emit(x, enc_eor_lsr(T0, T0, T2, 0));
                emit(x, enc_and_reg(T0, T0, T1));
                emit(x, enc_eor_lsr(T0, T0, T2, 0));
                bails[nbails++] = here(x);
                emit(x, enc_tbnz(T0, 63));
            }
        }
        if (fl->cmp == FL_NE || fl->cmp == FL_SLT || fl->cmp == FL_ULT)
            emit(x, enc_sub_imm(T2, T2, 1, 0));
        if (fl->step > 1) {
            if ((fl->step & (fl->step - 1)) == 0) {
                unsigned sh = (unsigned)__builtin_ctz(fl->step);
                emit(x, enc_ubfx(T2, T2, sh, 64 - sh));
            } else {
                emit_mov_const(x, T0, fl->step);
                emit(x, enc_udiv(T2, T2, T0));
            }
        }
        /* Now T2 = q = rem_backedges - 1. Bail if q == 0 (rem_backedges < 2), clamp q to
         * (1 << kick_log2) - 1, then add 1 so safe_iters is in [2, 1 << kick_log2]. */
        bails[nbails++] = here(x);
        emit(x, enc_cbz_x(T2));
        emit(x, enc_ubfx(T0, T2, fl->kick_log2, 64 - fl->kick_log2));
        uint32_t *no_clamp = here(x);
        emit(x, enc_cbz_x(T0));
        emit(x, enc_movz(T2, (1u << fl->kick_log2) - 1, 0));
        patch_local(x, no_clamp, here(x));
        emit(x, enc_add_imm(T2, T2, 1, 0));
    }
    emit(x, enc_str_x(T2, CTX, iters_off));

    /* 3. For each access stream: verify TLB/STLB hits, shared addends for multi-stream bases, and
     *    span bounds (shrinking safe_iters for positive-stride streams; dual-endpoint 4 KiB TLB
     *    check for zero-stride streams so cross-4 KiB stack frames never bail). */
    for (unsigned i = 0; i < fl->nstreams; i++) {
        const struct fast_stream *s = &fl->streams[i];
        unsigned base = fl->ptrs[s->ptr_idx].reg;
        if (s->idx_reg2 < 31) {
            unsigned ir1 = s->idx_reg, ir2 = s->idx_reg2;
            if (is_stolen(ir1)) {
                emit_load_guest(x, T1, ir1);
                ir1 = T1;
            }
            if (is_stolen(ir2)) {
                emit_load_guest(x, T2, ir2);
                ir2 = T2;
            }
            emit(x, enc_add_lsl(T1, ir1, ir2, 0));
            if (base == 31) {
                base = SP_HOST;
            } else if (is_stolen(base)) {
                emit_load_guest(x, T0, base);
                base = T0;
            }
            emit(x, enc_add_lsl(T0, base, T1, s->idx_shift));
            emit_add_const(x, T0, T0, s->lo);
        } else {
            if (base == 31) {
                base = SP_HOST;
            } else if (is_stolen(base)) {
                emit_load_guest(x, T0, base);
                base = T0;
            }
            if (s->idx_reg < 31) {
                unsigned idx = s->idx_reg;
                if (is_stolen(idx)) {
                    emit_load_guest(x, T1, idx);
                    idx = T1;
                }
                emit(x, enc_add_ext(T0, base, idx, s->idx_opt, s->idx_shift));
                base = T0;
            }
            emit_add_const(x, T0, base, s->lo); /* T0 = first = G_eff + lo */
        }
        uint32_t span = (uint32_t)(s->hi - s->lo);

        if (s->stride_reg == 31 && s->stride == 0) {
            /* Zero-stride stream (span <= 4 KiB): check first byte and last byte in 4 KiB TLB and
             * require identical addends so even cross-page stack frames run natively. */
            emit(x, enc_ubfx(T1, T0, APPINE_PAGE_SHIFT, TLB_BITS));
            emit(x, enc_add_lsl(T1, CTX, T1, 5));
            emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF + (s->write ? 16 : 0)));
            emit(x, enc_eon_lsr(T1, T1, T0, APPINE_PAGE_SHIFT));
            bails[nbails++] = here(x);
            emit(x, enc_cbnz_x(T1));
            if (s->first_for_ptr) {
                emit(x, enc_str_x(T2, CTX, grp_off + 8 * (size_t)s->ptr_idx));
            } else {
                emit(x, enc_ldr_x(T1, CTX, grp_off + 8 * (size_t)s->ptr_idx));
                emit(x, enc_eor_lsr(T1, T1, T2, 0));
                bails[nbails++] = here(x);
                emit(x, enc_cbnz_x(T1));
            }
            if (span > 1) {
                emit_add_const(x, T0, T0, (int64_t)(span - 1));
                emit(x, enc_ubfx(T1, T0, APPINE_PAGE_SHIFT, TLB_BITS));
                emit(x, enc_add_lsl(T1, CTX, T1, 5));
                emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF + (s->write ? 16 : 0)));
                emit(x, enc_eon_lsr(T1, T1, T0, APPINE_PAGE_SHIFT));
                bails[nbails++] = here(x);
                emit(x, enc_cbnz_x(T1));
                emit(x, enc_ldr_x(T0, CTX, grp_off + 8 * (size_t)s->ptr_idx));
                emit(x, enc_eor_lsr(T0, T0, T2, 0));
                bails[nbails++] = here(x);
                emit(x, enc_cbnz_x(T0));
            }
            continue;
        }

        /* Fast path: 2 MiB superpage TLB (cpu->stlb) */
        emit(x, enc_add_imm(T1, CTX, (uint32_t)(STLB_OFF >> 12), 1));
        emit(x, enc_ubfx(T2, T0, MMU_SUPER_SHIFT, STLB_BITS));
        emit(x, enc_add_lsl(T1, T1, T2, 5));
        emit(x, enc_ldp_x(T1, T2, T1, s->write ? 16 : 0));
        emit(x, enc_eon_lsr(T1, T1, T0, MMU_SUPER_SHIFT));
        uint32_t *try_4k = here(x);
        emit(x, enc_cbnz_x(T1));
        emit(x, enc_and_low(T1, T0, MMU_SUPER_SHIFT));
        emit_mov_const(x, T0, MMU_SUPER_SIZE - span);
        emit(x, enc_sub_reg(T1, T0, T1)); /* avail = (2 MiB - span) - super_off */
        uint32_t *got_super = here(x);
        emit(x, enc_b(0));

        /* Fallback: 4 KiB data TLB (cpu->tlb) */
        patch_local(x, try_4k, here(x));
        emit(x, enc_ubfx(T1, T0, APPINE_PAGE_SHIFT, TLB_BITS));
        emit(x, enc_add_lsl(T1, CTX, T1, 5));
        emit(x, enc_ldp_x(T1, T2, T1, (int)TLB_OFF + (s->write ? 16 : 0)));
        emit(x, enc_eon_lsr(T1, T1, T0, APPINE_PAGE_SHIFT));
        bails[nbails++] = here(x);
        emit(x, enc_cbnz_x(T1));
        emit(x, enc_and_low(T1, T0, APPINE_PAGE_SHIFT));
        emit(x, enc_movz(T0, (uint32_t)(APPINE_PAGE_SIZE - span), 0));
        emit(x, enc_sub_reg(T1, T0, T1)); /* avail = (4 KiB - span) - page_off */

        patch_local(x, got_super, here(x));
        bails[nbails++] = here(x);
        emit(x, enc_tbnz(T1, 63));
        if (s->first_for_ptr) {
            emit(x, enc_str_x(T2, CTX, grp_off + 8 * (size_t)s->ptr_idx));
        } else {
            emit(x, enc_ldr_x(T0, CTX, grp_off + 8 * (size_t)s->ptr_idx));
            emit(x, enc_eor_lsr(T0, T0, T2, 0));
            bails[nbails++] = here(x);
            emit(x, enc_cbnz_x(T0));
        }

        if (s->stride_reg < 31) {
            /* Runtime register stride: reject negative or >= 2 MiB strides, then check if all
             * safe_iters fit via MUL (avoiding UDIV on the common 2 MiB superpage fast path).
             * Only on a boundary crossing fall through to UDIV to shrink safe_iters. */
            unsigned sr = s->stride_reg;
            if (is_stolen(sr)) {
                emit_load_guest(x, T0, sr);
                sr = T0;
            }
            emit(x, enc_ubfx(T2, sr, MMU_SUPER_SHIFT, 64 - MMU_SUPER_SHIFT));
            bails[nbails++] = here(x);
            emit(x, enc_cbnz_x(T2));
            emit(x, enc_ldr_x(T2, CTX, iters_off));
            emit(x, enc_sub_imm(T2, T2, 1, 0));
            emit(x, enc_mul(T2, T2, sr));
            emit(x, enc_sub_reg(T2, T1, T2)); /* avail - (safe_iters - 1) * sr */
            uint32_t *fits_all = here(x);
            emit(x, enc_tbz(T2, 63));
            emit(x, enc_udiv(T1, T1, sr));
            bails[nbails++] = here(x);
            emit(x, enc_cbz_x(T1));
            emit(x, enc_add_imm(T1, T1, 1, 0));
            emit(x, enc_str_x(T1, CTX, iters_off));
            patch_local(x, fits_all, here(x));
        } else {
            if ((s->stride & (s->stride - 1)) == 0) {
                unsigned sh = (unsigned)__builtin_ctz(s->stride);
                emit(x, enc_ubfx(T1, T1, sh, 64 - sh));
            } else {
                /* Exact floor(avail / stride) for 0 <= avail < 2 MiB, 1 <= stride <= 4095 */
                uint64_t mul = ((UINT64_C(1) << 34) + s->stride - 1) / s->stride;
                emit_mov_const(x, T2, mul);
                emit(x, enc_mul(T1, T1, T2));
                emit(x, enc_ubfx(T1, T1, 34, 30));
            }
            /* page_iters = avail / stride + 1; if avail / stride == 0 then page_iters == 1 < 2 */
            bails[nbails++] = here(x);
            emit(x, enc_cbz_x(T1));
            emit(x, enc_add_imm(T1, T1, 1, 0));
            emit(x, enc_ldr_x(T2, CTX, iters_off));
            emit(x, enc_sub_reg(T2, T1, T2));
            uint32_t *keep = here(x);
            emit(x, enc_tbz(T2, 63));
            emit(x, enc_str_x(T1, CTX, iters_off));
            patch_local(x, keep, here(x));
        }
    }
    if (nbails > sizeof(bails) / sizeof(bails[0]))
        appine_guard_fail();

    /* 4. Commit: convert induction pointers to host pointers, save any borrowed non-stolen host
     *    registers, load loop-wide pinned stolen registers into pin_host[], and load safe_iters into T2 */
    for (unsigned i = 0; i < fl->nptrs; i++) {
        if (fl->ptrs[i].reg < 31 && fast_is_pinned(fl, fl->ptrs[i].reg))
            continue;
        emit(x, enc_ldr_x(T0, CTX, grp_off + 8 * (size_t)i));
        emit_adjust_reg(x, fl->ptrs[i].reg, false);
    }
    for (unsigned k = 2; k < fl->npin; k++)
        emit_store_guest(x, fl->pin_host[k], fl->pin_host[k]);
    for (unsigned k = 0; k < fl->npin; k++) {
        unsigned gr = fl->pin_reg[k], hr = fl->pin_host[k];
        emit_load_guest(x, hr, gr);
        int pi = fast_ptr_index(fl, gr);
        if (pi >= 0) {
            emit(x, enc_ldr_x(T2, CTX, grp_off + 8 * (size_t)pi));
            emit(x, enc_add_lsl(hr, hr, T2, 0));
        }
    }
    emit(x, enc_ldr_x(T2, CTX, iters_off));

    /* 5. Native inner loop body (zero TLB checks, zero kick checks) */
    uint32_t *loop_head = here(x);
    for (unsigned i = 0; i < fl->back_idx; i++) {
        uint32_t insn = x->words[i];
        if (insn == 0xd503201f)
            continue;
        if (fl->kind == FL_CMP_INC && i == fl->ctrl_idx)
            continue; /* loop-closing CMP omitted in body, re-emitted once in epilogue */
        unsigned top = FIELD(insn, 28, 25);
        if ((top & 7) == 7) {
            struct native_desc nd;
            appine_simd_dp_decode(insn, &nd);
            struct operands o = {.n = 0, .writes_rd = false};
            bool reads_rd = false;
            for (unsigned k = 0; k < nd.n; k++) {
                add_operand(&o, nd.gpr[k].pos, false);
                if (nd.gpr[k].pos == 0 && nd.gpr[k].store) {
                    o.writes_rd = true;
                    if (nd.gpr[k].load)
                        reads_rd = true;
                }
            }
            if (fl->npin) {
                uint32_t out = insn;
                for (unsigned k = 0; k < o.n; k++) {
                    unsigned r = (insn >> o.pos[k]) & 31;
                    out = (out & ~(31u << o.pos[k])) | (fast_pin_host(fl, r) << o.pos[k]);
                }
                emit(x, out);
            } else {
                emit_fast_operands(x, insn, &o, reads_rd);
            }
        } else if (top == 0x4 || top == 0x6 || top == 0xc || top == 0xe) {
            struct memop m;
            uint64_t va = x->pc + 4ull * i;
            if (BIT(insn, 26))
                dbt_decode_simd_memop(insn, va, &m);
            else
                dbt_decode_memop(insn, va, &m);
            if (!m.prefetch) {
                if (fl->npin) {
                    unsigned hrn = m.rn == 31 ? SP_HOST : fast_pin_host(fl, m.rn);
                    uint32_t out = (insn & ~(31u << 5)) | (hrn << 5);
                    if (m.mode == M_REG && m.rm < 31)
                        out = (out & ~(31u << 16)) | (fast_pin_host(fl, m.rm) << 16);
                    if (!m.simd) {
                        if (m.rt < 31)
                            out = (out & ~31u) | fast_pin_host(fl, m.rt);
                        if (m.pair && m.rt2 < 31)
                            out = (out & ~(31u << 10)) | (fast_pin_host(fl, m.rt2) << 10);
                    }
                    emit(x, out);
                } else {
                    emit_fast_memop(x, insn, &m);
                }
            }
        } else {
            struct operands o;
            dbt_dp_operands(insn, &o);
            if (fl->npin) {
                uint32_t out = insn;
                for (unsigned k = 0; k < o.n; k++) {
                    unsigned r = (insn >> o.pos[k]) & 31;
                    out = (out & ~(31u << o.pos[k])) | (fast_pin_host(fl, r) << o.pos[k]);
                }
                emit(x, out);
            } else {
                emit_fast_operands(x, insn, &o, dp_reads_rd(insn));
            }
        }
    }
    emit(x, enc_sub_imm(T2, T2, 1, 0));
    uint32_t *back = here(x);
    emit(x, enc_cbnz_x(T2));
    patch_local(x, back, loop_head);

    /* 6. Epilogue: flush written pinned registers (restoring guest VA if shifted), restore any
     *    borrowed non-stolen host registers, restore non-pinned root pointers and live
     *    end-of-iteration affine aliases to guest VAs, and restore exact iteration-end NZCV for
     *    omitted FL_CMP_INC compares. */
    for (unsigned k = 0; k < fl->npin; k++) {
        if (!fl->pin_written[k])
            continue;
        unsigned gr = fl->pin_reg[k], hr = fl->pin_host[k];
        int pi = fast_ptr_or_alias_index(fl, gr);
        if (pi >= 0) {
            emit(x, enc_ldr_x(T2, CTX, grp_off + 8 * (size_t)pi));
            emit(x, enc_sub_reg(hr, hr, T2));
        }
        emit_store_guest(x, hr, gr);
    }
    for (unsigned k = 2; k < fl->npin; k++)
        emit_load_guest(x, fl->pin_host[k], fl->pin_host[k]);
    for (unsigned i = 0; i < fl->nptrs; i++) {
        const struct fast_ptr *p = &fl->ptrs[i];
        bool load_needed = p->reg == 31 || !fast_is_pinned(fl, p->reg);
        uint32_t nonpin_aliases = 0;
        for (uint32_t aliases = p->alias_mask; aliases; aliases &= aliases - 1) {
            unsigned a = (unsigned)__builtin_ctz(aliases);
            if (!fast_is_pinned(fl, a))
                nonpin_aliases |= 1u << a;
        }
        if (!load_needed && !nonpin_aliases)
            continue;
        emit(x, enc_ldr_x(T0, CTX, grp_off + 8 * (size_t)i));
        if (load_needed)
            emit_adjust_reg(x, p->reg, true);
        for (uint32_t aliases = nonpin_aliases; aliases; aliases &= aliases - 1)
            emit_adjust_reg(x, (unsigned)__builtin_ctz(aliases), true);
    }
    if (fl->kind == FL_CMP_INC) {
        uint32_t cmp_insn = x->words[fl->ctrl_idx];
        struct operands o;
        dbt_dp_operands(cmp_insn, &o);
        emit_fast_operands(x, cmp_insn, &o, false);
    }

    uint32_t *slow = here(x);
    for (unsigned i = 0; i < nbails; i++)
        patch_local(x, bails[i], slow);
    x->st->fast_loops++;
}

uint32_t dbt_try_fast_loop(struct xlate *x)
{
    struct fast_loop fl;
    if (!analyze_fast_loop(x, &fl))
        return 0;
    emit_fast_loop(x, &fl);
    return fl.back_idx >= x->limit ? fl.back_idx + 1 : 0;
}

#endif /* DBT_SUPPORTED */
