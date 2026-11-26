//! Tier 1 keeping translations after the address space changes and checking guest instruction
//! words block by block (instances taken from the pool), function return prediction (the shadow
//! return stack), cross-page accesses, and hardware watchpoints. When the host is not aarch64
//! Linux there is no Tier 1 and the tests pass trivially.

use std::ptr::NonNull;
use std::sync::{Mutex, MutexGuard};

use appine_engine::{
    Access, Cpu, Dbt, DbtMemop, DbtRegs, DbtSource, DbtSpace, Exit, FaultKind, MEMOP_MEMCHR,
    MEMOP_MEMCMP, MEMOP_MEMCPY, MEMOP_MEMMOVE, MEMOP_MEMSET, MEMOP_STRNCMP, Mmu, PAGE_SIZE,
    WATCH_LOAD, WATCH_STORE, prot,
};

/// Serializes tests that rely on keyed [`DbtSpace`] instances staying in the process-wide pool
/// across `drop` / `DbtSpace::new`, expect template hits, or trim or churn the pool.
static POOL_LOCK: Mutex<()> = Mutex::new(());

fn lock_pool() -> MutexGuard<'static, ()> {
    POOL_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn keyed_dbt(key: u64) -> Option<Dbt> {
    Dbt::attach(&DbtSpace::new(key, DbtRegs::Default)?, 0)
}

#[repr(C, align(4096))]
struct Page([u8; 4096]);

/// Two pages of code, `CODE` and the page right after it; below `STACK` is one page of stack.
const CODE: u64 = 0x40_0000;
const STACK: u64 = 0x80_0000;
/// The data pages mapped by [`Guest::with_data`] start here; see the description there.
const DATA: u64 = 0x100_0000;

const SVC: u32 = 0xd400_0001;
const RET: u32 = 0xd65f_03c0;
const STP_FP_LR_PRE: u32 = 0xa9bf_7bfd; // stp x29, x30, [sp, #-16]!
const LDP_FP_LR_POST: u32 = 0xa8c1_7bfd; // ldp x29, x30, [sp], #16
const SUB_X0_1: u32 = 0xd100_0400; // sub x0, x0, #1
const ADD_X1_1: u32 = 0x9100_0421; // add x1, x1, #1
const LDR_X0_X2: u32 = 0xf940_0040; // ldr x0, [x2]
const STR_X3_X4: u32 = 0xf900_0083; // str x3, [x4]
const LDP_X5_X6_X7: u32 = 0xa940_18e5; // ldp x5, x6, [x7]

struct Guest {
    // Drop order: cpu → mmu → pages
    cpu: Cpu,
    mmu: Mmu,
    pages: Box<[Page]>,
}

impl Guest {
    fn new() -> Self {
        Self::with_pages(3)
    }

    /// Maps 6 data pages in addition to [`Guest::new`]; every byte of page i is `i * 16` plus the
    /// low 4 bits of its offset in the page:
    /// the host pages of `DATA` and `DATA + 1 page` are adjacent; those of `+ 2 pages` and
    /// `+ 3 pages` are in reverse order;
    /// `+ 4 pages` is read-write, `+ 5 pages` read-only, and `+ 6 pages` unmapped.
    fn with_data() -> Self {
        let mut g = Self::with_pages(9);
        for (i, page) in g.pages[3..].iter_mut().enumerate() {
            for (j, byte) in page.0.iter_mut().enumerate() {
                *byte = (i * 16 + j % 16) as u8;
            }
        }
        let base = NonNull::new(g.pages.as_mut_ptr().cast::<u8>()).unwrap();
        let rw = prot::READ | prot::WRITE;
        let layout = [
            (0, 3, rw),
            (1, 4, rw),
            (2, 6, rw),
            (3, 5, rw),
            (4, 7, rw),
            (5, 8, prot::READ),
        ];
        for (page, host, p) in layout {
            unsafe {
                g.mmu
                    .map(DATA + page * PAGE_SIZE, base.add(host * 4096), PAGE_SIZE, p)
                    .unwrap();
            }
        }
        g
    }

    fn with_pages(n: usize) -> Self {
        let mut pages: Box<[Page]> = (0..n).map(|_| Page([0; 4096])).collect();
        let mut mmu = Mmu::new();
        let base = NonNull::new(pages.as_mut_ptr().cast::<u8>()).unwrap();
        unsafe {
            mmu.map(CODE, base, 2 * PAGE_SIZE, prot::READ | prot::EXEC)
                .unwrap();
            mmu.map(
                STACK - PAGE_SIZE,
                base.add(2 * 4096),
                PAGE_SIZE,
                prot::READ | prot::WRITE,
            )
            .unwrap();
        }
        let mut cpu = unsafe { Cpu::new(&mmu) };
        cpu.state_mut().sp = STACK;
        Guest { cpu, mmu, pages }
    }

    /// Writes instructions to `addr` (only the two pages this test maps are supported).
    fn code(&mut self, addr: u64, insns: &[u32]) {
        let off = (addr - CODE) as usize;
        for (i, insn) in insns.iter().enumerate() {
            let at = off + 4 * i;
            self.pages[at / 4096].0[at % 4096..at % 4096 + 4].copy_from_slice(&insn.to_le_bytes());
        }
    }

    /// Runs from `CODE` to an svc and returns x0.
    fn run(&mut self, dbt: &mut Dbt) -> u64 {
        self.run_at(dbt, CODE)
    }

    /// Runs from `pc` to an svc and returns x0.
    fn run_at(&mut self, dbt: &mut Dbt, pc: u64) -> u64 {
        let _ = &self.mmu;
        self.cpu.state_mut().pc = pc;
        assert!(matches!(dbt.run(&mut self.cpu), Exit::Svc { imm: 0 }));
        self.cpu.state().x[0]
    }

    /// The 8 bytes at offset `off` of data page `page` (not crossing pages).
    fn data(&self, page: usize, off: usize) -> u64 {
        let host = [3, 4, 6, 5, 7, 8][page];
        u64::from_le_bytes(self.pages[host].0[off..off + 8].try_into().unwrap())
    }
}

#[test]
fn recheck_after_exec_runs_the_new_code() {
    let _pool = lock_pool();
    const KEY: u64 = 0x5eed_0002;
    let Some(mut dbt) = keyed_dbt(KEY) else {
        return;
    };
    let mut g = Guest::new();
    g.code(CODE, &[movz_x0(1), SVC]);
    assert_eq!(g.run(&mut dbt), 1);
    drop(dbt);
    // The same address now holds another program (exec); after pool recheck, the new code runs
    g.code(CODE, &[movz_x0(2), SVC]);
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 2);
    drop(dbt);
    // When the code has not changed it is still usable after the check, without retranslation
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 2);
    assert_eq!(dbt.stats().blocks, 0);
}

#[test]
fn pooled_instances_are_checked_before_use() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    g.code(CODE, &[movz_x0(3), SVC]);
    assert_eq!(g.run(&mut dbt), 3);
    // The instance goes back to the pool; when the next thread takes it, this holds different
    // code
    drop(dbt);
    g.code(CODE, &[movz_x0(4), SVC]);
    let mut dbt = Dbt::new().unwrap();
    assert_eq!(g.run(&mut dbt), 4);
}

#[test]
fn pooled_instances_keep_translations_of_the_same_program() {
    let _pool = lock_pool();
    // No other test uses this key; a pooled instance with the same key is only given back to it
    const KEY: u64 = 0x5eed_0001;
    let Some(mut dbt) = keyed_dbt(KEY) else {
        return;
    };
    let mut g = Guest::new();
    g.code(CODE, &[movz_x0(7), SVC]);
    assert_eq!(g.run(&mut dbt), 7);
    drop(dbt);
    // The same program runs again: it takes back the translations left behind and, after the
    // check, uses them directly without translating again
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 7);
    assert_eq!(dbt.stats().blocks, 0);
    drop(dbt);
    // The code changed in the meantime: invalidated by the check and translated again
    g.code(CODE, &[movz_x0(8), SVC]);
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 8);
    assert_eq!(dbt.stats().blocks, 1);
    drop(dbt);
    // Memory pressure evicts both the keyed instance and its translation templates.
    appine_engine::trim_dbt_pool();
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 8);
    assert_eq!(dbt.stats().blocks, 1);
    assert_eq!(dbt.stats().blocks_shared, 0);
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
#[test]
fn trim_reclaims_template_high_water_after_arena_rollover() {
    // RssAnon and the template arena belong to the whole process. Keep other tests' allocations
    // out of both samples, including tests which never take the pool lock.
    if std::env::var_os("APPINE_TEST_TEMPLATE_RSS").is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "trim_reclaims_template_high_water_after_arena_rollover",
            ])
            .env("APPINE_TEST_TEMPLATE_RSS", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let _pool = lock_pool();
    let rss_anon_kb = || -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix("RssAnon:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    let mut dbt = Dbt::new().unwrap();
    let mut g = Guest::new();
    let mut words = [0x9100_0400; 256]; // add x0, x0, #1
    words[255] = SVC;
    g.code(CODE, &words);
    let page = NonNull::from(&mut g.pages[0]).cast();
    // Each distinct PC needs over 2 KiB for guest and host words. Cross the 32 MiB arena
    // boundary, leaving the bump cursor near the start while the first generation stays resident.
    for i in 0..16384 {
        let pc = 0x1_0000_0000 + i * PAGE_SIZE;
        // SAFETY: the guest owns this executable page for the lifetime of its MMU.
        unsafe {
            g.mmu
                .map(pc, page, PAGE_SIZE, prot::READ | prot::EXEC)
                .unwrap();
        }
        g.cpu.state_mut().x[0] = i;
        assert_eq!(g.run_at(&mut dbt, pc), i + 255);
    }
    let before = rss_anon_kb();
    appine_engine::trim_dbt_pool();
    let after = rss_anon_kb();
    assert!(
        before >= after + 24 * 1024,
        "RssAnon {before} -> {after} KiB"
    );
    // The live instance and its thread stayed attached throughout the measurement.
    g.cpu.state_mut().x[0] = 10;
    assert_eq!(g.run_at(&mut dbt, 0x1_0000_0000), 265);
}

#[test]
fn trim_discards_templates_and_new_translations_are_shareable() {
    let _pool = lock_pool();
    let Some(mut first) = Dbt::new() else { return };
    let mut g = Guest::new();
    let blocks = [(CODE + 0x648, 0x3a00), (CODE + 0x12d8, 0x3a01)];
    for (pc, value) in blocks {
        g.code(pc, &[movz_x0(value), SVC]);
    }
    let mut run = |dbt: &mut Dbt| {
        for (pc, value) in blocks {
            assert_eq!(g.run_at(dbt, pc), u64::from(value));
        }
        assert_eq!(dbt.stats().blocks, 2);
    };
    run(&mut first);
    let mut second = Dbt::new().unwrap();
    run(&mut second);
    assert_eq!(second.stats().blocks_shared, 2);
    appine_engine::trim_dbt_pool();
    let mut cold = Dbt::new().unwrap();
    run(&mut cold);
    assert_eq!(cold.stats().blocks_shared, 0);
    let mut warm = Dbt::new().unwrap();
    run(&mut warm);
    assert_eq!(warm.stats().blocks_shared, 2);
}

// BL pushes a shadow return, BR goes through the jump cache, and the subroutine round-trips
// the input through the inline store/load paths before returning to the caller's SVC.
fn exercise_attachment(g: &mut Guest, dbt: &mut Dbt, pc: u64, input: u64) {
    g.code(
        pc,
        &[bl(pc, pc + 8), SVC, 0xd61f_00a0, STR_X3_X4, LDR_X0_X2, RET],
    );
    let x = &mut g.cpu.state_mut().x;
    x[2] = STACK - 8;
    x[3] = input;
    x[4] = STACK - 8;
    x[5] = pc + 12;
    assert_eq!(g.run_at(dbt, pc), input);
    assert_eq!(g.cpu.state().x[30], pc + 4);
    assert_eq!(dbt.stats().exits_interp, 0);
}

#[test]
fn attachments_run_on_live_and_new_spaces_after_trim() {
    let _pool = lock_pool();
    let Some(live) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let mut g = Guest::new();
    let mut threads: Vec<_> = (0..8).map(|_| Dbt::attach(&live, 0).unwrap()).collect();
    for (i, dbt) in threads.iter_mut().enumerate() {
        exercise_attachment(&mut g, dbt, CODE, 100 + i as u64);
    }
    drop(threads);
    appine_engine::trim_dbt_pool();
    for space in [
        live,
        DbtSpace::new(0, DbtRegs::Default).unwrap(),
        DbtSpace::new(0, DbtRegs::Go).unwrap(),
    ] {
        let mut dbt = Dbt::attach(&space, 0).unwrap();
        exercise_attachment(&mut g, &mut dbt, CODE, 200);
        exercise_attachment(&mut g, &mut dbt, CODE, 201);
    }
}

#[test]
fn concurrent_trim_preserves_running_translations() {
    let _pool = lock_pool();
    let Some(live) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let start = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for worker in 0..4 {
            let (live, start) = (&live, &start);
            workers.push(scope.spawn(move || {
                let mut g = Guest::new();
                start.wait();
                for round in 0..64 {
                    let pc = CODE + 32 * round;
                    let mut shared = Dbt::attach(live, 0).unwrap();
                    exercise_attachment(&mut g, &mut shared, pc, worker + round);
                    let mut private = Dbt::with_regs(DbtRegs::Go).unwrap();
                    exercise_attachment(&mut g, &mut private, pc, worker * 100 + round);
                }
            }));
        }
        start.wait();
        loop {
            appine_engine::trim_dbt_pool();
            appine_engine::unmap_written_code();
            if workers.iter().all(|worker| worker.is_finished()) {
                break;
            }
            std::thread::yield_now();
        }
    });
}

#[test]
fn fpcr_reads_use_the_guest_state_inside_translated_code() {
    let mut g = Guest::new();
    g.code(CODE, &[0xd53b_4410, 0xd53b_4415, 0xd53b_441f, SVC]); // mrs x16/x21/xzr, fpcr
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        // Translated `mrs fpcr` reads `CpuState::fpcr` directly, even for bits host FPCR ignores.
        let fpcr = 0x0040_8000;
        let s = g.cpu.state_mut();
        s.fpcr = fpcr;
        s.x[16] = 0;
        s.x[21] = 0;
        g.run(&mut dbt);
        assert_eq!((g.cpu.state().x[16], g.cpu.state().x[21]), (fpcr, fpcr));
        assert_eq!(dbt.stats().exits_interp, 0);
    }
}

#[test]
fn unchanged_fpcr_writes_stay_in_the_block() {
    let mut g = Guest::new();
    let fz16 = if appine_engine::guest_hwcap() & appine_engine::hwcap::FPHP != 0 {
        1 << 19
    } else {
        0
    };
    let mode = (1 << 22) | fz16;
    g.code(
        CODE,
        &[
            0xd51b_4410, // msr fpcr, x16
            0xd51b_4415, // msr fpcr, x21
            0xd53b_4400, // mrs x0, fpcr
            0xd51b_441f, // msr fpcr, xzr
            SVC,
        ],
    );
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        for (initial, exits) in [(mode, 1), (mode | 1, 2)] {
            let s = g.cpu.state_mut();
            s.fpcr = initial;
            s.nzcv = 0xa000_0000;
            s.x[16] = mode | 1 | (1 << 19);
            s.x[21] = mode;
            let before = dbt.stats().exits_interp;
            assert_eq!(g.run(&mut dbt), mode);
            assert_eq!(g.cpu.state().fpcr, 0);
            assert_eq!(g.cpu.state().nzcv, 0xa000_0000);
            assert_eq!(dbt.stats().exits_interp - before, exits);
        }
    }
}

#[test]
fn fpsr_reads_observe_exceptions_raised_inside_translated_code() {
    const IOC: u64 = 1 << 0; // Invalid operation
    const IXC: u64 = 1 << 4; // Inexact result
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::new();
        g.cpu.state_mut().fpsr = IXC;
        g.code(
            CODE,
            &[
                0x1e60_1800, // fdiv d0, d0, d0: 0 / 0 sets IOC
                0xd53b_4430, // mrs x16, fpsr (stolen in the default set)
                0xd53b_4435, // mrs x21, fpsr (stolen in the Go set)
                0xd53b_443f, // mrs xzr, fpsr
                SVC,
            ],
        );
        g.run(&mut dbt);
        let s = g.cpu.state();
        assert_eq!([s.x[16], s.x[21], s.fpsr], [IXC | IOC; 3]);
        assert_eq!(dbt.stats().exits_interp, 0);
    }
}

#[test]
fn both_register_sets_run_the_same_code() {
    if Dbt::new().is_none() {
        return;
    }
    let mut g = Guest::new();
    // x0 = x1 + … + x30, then change two registers each set takes, and copy x25 to x26 through
    // the stack
    let mut code: Vec<u32> = (1..=30).map(|n| 0x8b00_0000 | n << 16).collect(); // add x0, x0, xn
    code.extend([
        0x9100_0610, // add x16, x16, #1
        0x9100_06b5, // add x21, x21, #1
        0xf81f_0ff9, // str x25, [sp, #-16]!
        0xf841_07fa, // ldr x26, [sp], #16
        SVC,
    ]);
    g.code(CODE, &code);
    let sum: u64 = (1..=30).map(|n| n * 0x101).sum();
    // The two sets alternate: translation templates for the same pc are told apart by register
    // assignment, and an empty pooled instance regenerates its routines when the set changes
    for regs in [DbtRegs::Default, DbtRegs::Go, DbtRegs::Default, DbtRegs::Go] {
        let mut dbt = Dbt::with_regs(regs).unwrap();
        let s = g.cpu.state_mut();
        s.x[0] = 0;
        for n in 1..=30 {
            s.x[n] = n as u64 * 0x101;
        }
        assert_eq!(g.run(&mut dbt), sum, "{regs:?}");
        let s = g.cpu.state();
        assert_eq!(
            (s.x[16], s.x[21], s.x[26]),
            (16 * 0x101 + 1, 21 * 0x101 + 1, 25 * 0x101),
            "{regs:?}"
        );
        assert_eq!(s.sp, STACK);
    }
    // x16 and x26–x28, which Go programs use heavily, need no rewriting with the Go set, while
    // x21–x25 do
    let other = CODE + 0x200;
    g.code(
        other,
        &[
            0x8b10_0000, // add x0, x0, x16
            0x8b1a_0000, // add x0, x0, x26
            0x8b1b_0000, // add x0, x0, x27
            0x8b1c_0000, // add x0, x0, x28
            0x8b15_0000, // add x0, x0, x21
            SVC,
        ],
    );
    for (regs, remapped) in [(DbtRegs::Default, 4), (DbtRegs::Go, 1)] {
        let mut dbt = Dbt::with_regs(regs).unwrap();
        g.run_at(&mut dbt, other);
        let st = dbt.stats();
        assert_eq!(
            (st.insns_remapped, st.insns_copied),
            (remapped, 5 - remapped),
            "{regs:?}"
        );
    }
}

#[test]
fn branches_to_unaligned_addresses_fault() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    // Page 0 holds a block that, once invalidated, leaves a tombstone in the translation table
    // (its pc field is the unaligned 1), placed exactly where a lookup of 1 starts searching;
    // page 1 holds the three kinds of indirect branch
    let mut pages: Box<[Page]> = (0..2).map(|_| Page([0; 4096])).collect();
    let mut mmu = Mmu::new();
    let base = NonNull::new(pages.as_mut_ptr().cast::<u8>()).unwrap();
    unsafe { mmu.map(0, base, 2 * PAGE_SIZE, prot::READ | prot::EXEC) }.unwrap();
    let mut cpu = unsafe { Cpu::new(&mmu) };
    let code = |page: &mut Page, off: usize, insns: &[u32]| {
        for (i, w) in insns.iter().enumerate() {
            page.0[off + 4 * i..off + 4 * i + 4].copy_from_slice(&w.to_le_bytes());
        }
    };
    code(&mut pages[0], 0, &[movz_x0(7), SVC]);
    code(&mut pages[1], 0, &[0xd61f_0020, 0xd63f_0020, RET]); // br x1, blr x1, ret
    cpu.state_mut().pc = 0;
    assert_eq!(dbt.run(&mut cpu), Exit::Svc { imm: 0 });
    code(&mut pages[0], 0, &[movz_x0(8)]);
    dbt.invalidate(&cpu, 0, PAGE_SIZE);
    for target in [1, 2, 3, PAGE_SIZE + 1] {
        for at in [PAGE_SIZE, PAGE_SIZE + 4, PAGE_SIZE + 8] {
            let s = cpu.state_mut();
            s.x[1] = target;
            s.x[30] = target;
            s.pc = at;
            // As on Linux, the alignment fault is reported after the branch, at instruction
            // fetch, with pc being the target; previously a branch to 1 entered the jump cache's
            // empty entry (code is NULL) or the invalidated block of that tombstone
            let fault = Exit::Fault {
                addr: target,
                access: Access::Exec,
                kind: FaultKind::Alignment,
            };
            assert_eq!(dbt.run(&mut cpu), fault, "{at:#x} → {target:#x}");
            assert_eq!(cpu.state().pc, target);
        }
    }
    drop((dbt, cpu, mmu));
}

#[test]
fn members_share_file_code_and_keep_jit_code_apart() {
    // Two address spaces share one instance: the first page is a registered file (shared), and
    // the second page is each one's own JIT code. A shared block calls the second page directly:
    // after the first member links it, the second member must still reach its own code
    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let file = DbtSource {
        start: CODE,
        len: PAGE_SIZE,
        id: [1, 2, 0, 3, 4],
    };
    space.share(&[file]);
    let jit = CODE + PAGE_SIZE;
    let tags = [space.new_tag().unwrap(), space.new_tag().unwrap()];
    let mut members: Vec<(Guest, Dbt)> = (0..2)
        .map(|i| {
            let mut g = Guest::new();
            g.code(CODE, &[bl(CODE, jit), SVC]);
            g.code(jit, &[movz_x0(i as u16 + 1), RET]);
            (g, Dbt::attach(&space, tags[i]).unwrap())
        })
        .collect();
    for round in 0..3 {
        for (n, (g, dbt)) in members.iter_mut().enumerate() {
            assert_eq!(g.run(dbt), n as u64 + 1, "round {round}");
        }
    }
    // The second member translated only its own JIT code; the two blocks of the first page are
    // the ones the first member translated
    assert_eq!(members[1].1.stats().blocks, 1);
    // A pc beyond 48 bits never finds a tagged block: the second member branches to "the first
    // member's tag | the JIT code's address"
    let (g, dbt) = &mut members[1];
    let forged = jit | u64::from(tags[0]) << 48;
    g.code(CODE + 8, &[0xd61f_0020]); // br x1
    g.cpu.state_mut().x[1] = forged;
    g.cpu.state_mut().pc = CODE + 8;
    assert!(
        matches!(dbt.run(&mut g.cpu), Exit::Fault { addr, access: Access::Exec, .. } if addr == forged)
    );
}

#[test]
fn barriers_resume_in_rewritten_code() {
    for barrier in [0xd503_3b9f, 0xd503_3fdf] {
        // dsb ish, isb
        let Some(mut dbt) = Dbt::new() else {
            return;
        };
        let mut g = Guest::new();
        let next = CODE + 8;
        g.code(CODE, &[0xd50b_7521, barrier, movz_x0(1), SVC]); // ic ivau, x1
        assert_eq!(g.run_at(&mut dbt, next), 1);
        g.code(next, &[movz_x0(2)]);
        g.cpu.state_mut().x[1] = (0xab << 56) | CODE;
        assert_eq!(g.run(&mut dbt), 2);
        assert_eq!(g.cpu.state().ivau_page, 0);
        assert_eq!(dbt.stats().exits_interp, 0);
        assert!(dbt.stats().invalidated > 0);
    }
}

#[test]
fn ic_ivau_invalidates_page_zero() {
    let Some(mut dbt) = Dbt::new() else { return };
    let mut g = Guest::with_pages(4);
    let page = &mut g.pages[3].0;
    page[..4].copy_from_slice(&movz_x0(1).to_le_bytes());
    page[4..8].copy_from_slice(&SVC.to_le_bytes());
    unsafe {
        g.mmu
            .map(
                0,
                NonNull::new(page.as_mut_ptr()).unwrap(),
                PAGE_SIZE,
                prot::READ | prot::EXEC,
            )
            .unwrap();
    }
    g.code(CODE, &[0xd50b_7521, 0xd503_3b9f, 0xd61f_0040]); // ic ivau, x1; dsb ish; br x2
    assert_eq!(g.run_at(&mut dbt, 0), 1);
    for (tag, value) in [(0xab << 56, 2), (0, 3)] {
        g.pages[3].0[..4].copy_from_slice(&movz_x0(value).to_le_bytes());
        g.cpu.state_mut().x[1] = tag;
        assert_eq!(g.run(&mut dbt), u64::from(value));
    }
}

#[test]
fn invalidation_keeps_blocks_whose_code_did_not_change() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    let other = CODE + 0x100;
    g.code(CODE, &[movz_x0(7), SVC]);
    g.code(other, &[movz_x0(8), SVC]);
    assert_eq!(g.run(&mut dbt), 7);
    assert_eq!(g.run_at(&mut dbt, other), 8);
    // The JIT changed only one place in the same page, with a per-page ic ivau: only the changed
    // block is invalidated and translated again
    g.code(other, &[movz_x0(9), SVC]);
    let before = dbt.stats();
    dbt.invalidate(&g.cpu, CODE, PAGE_SIZE);
    assert_eq!(g.run(&mut dbt), 7);
    assert_eq!(g.run_at(&mut dbt, other), 9);
    let after = dbt.stats();
    assert_eq!(after.invalidated - before.invalidated, 1);
    assert_eq!(after.blocks - before.blocks, 1);
    // The retired record for `other` is between the new block and the live block at CODE.
    g.code(CODE, &[movz_x0(10), SVC]);
    dbt.invalidate(&g.cpu, CODE, PAGE_SIZE);
    assert_eq!(g.run(&mut dbt), 10);
    assert_eq!(g.run_at(&mut dbt, other), 9);
    assert_eq!(dbt.stats().invalidated - after.invalidated, 1);
}

#[test]
fn recheck_retires_only_blocks_that_changed() {
    let _pool = lock_pool();
    const KEY: u64 = 0x5eed_0003;
    let Some(mut dbt) = keyed_dbt(KEY) else {
        return;
    };
    let mut g = Guest::new();
    let second = CODE + PAGE_SIZE;
    g.code(CODE, &[b(CODE, second)]);
    g.code(second, &[movz_x0(5), SVC]);
    assert_eq!(g.run(&mut dbt), 5);
    drop(dbt);
    // Change only the second page: the first page's block and its link to the second page are
    // kept, and the second page's block is invalidated and translated again
    g.code(second, &[movz_x0(6), SVC]);
    let mut dbt = keyed_dbt(KEY).unwrap();
    assert_eq!(g.run(&mut dbt), 6);
    let after = dbt.stats();
    assert_eq!(after.invalidated, 1);
    assert_eq!(after.blocks, 1);
}

#[test]
fn parking_and_flushing_over_and_over_keeps_free_slots() {
    let _pool = lock_pool();
    const KEY: u64 = 0x5eed_0004;
    if Dbt::new().is_none() {
        return;
    }
    // With no empty slot in the table an insertion keeps searching forever: run it in another
    // thread, and a timeout counts as failure
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut dbt = keyed_dbt(KEY).unwrap();
        let mut g = Guest::new();
        let second = CODE + PAGE_SIZE;
        g.code(CODE, &[movz_x0(1), SVC]);
        g.code(second, &[movz_x0(2), SVC]);
        let source = DbtSource {
            start: CODE,
            len: 2 * PAGE_SIZE,
            id: [1, 0, 0, 0, 0],
        };
        let host = NonNull::new(g.pages[1].0.as_mut_ptr()).unwrap();
        // The smallest table has 4096 entries: leaking one tombstone per round would fill it in a
        // few thousand rounds
        for _ in 0..5000 {
            assert_eq!(g.run(&mut dbt), 1);
            assert_eq!(g.run_at(&mut dbt, second), 2);
            // The address space changed (exec of the same program) and the second page is not
            // mapped yet: returning to the pool marks it stale so the blocks there are parked
            dbt.space().set_sources(&[source]);
            drop(dbt);
            dbt = keyed_dbt(KEY).unwrap();
            dbt.space().trust(&[]);
            g.mmu.unmap(second, PAGE_SIZE).unwrap();
            g.cpu.tlb_flush();
            assert_eq!(g.run(&mut dbt), 1);
            // Mapped back: restored the first time it is executed, without retranslation
            unsafe {
                g.mmu
                    .map(second, host, PAGE_SIZE, prot::READ | prot::EXEC)
                    .unwrap();
            }
            let blocks = dbt.stats().blocks;
            assert_eq!(g.run_at(&mut dbt, second), 2);
            assert_eq!(dbt.stats().blocks, blocks);
            dbt.flush();
        }
        done.send(()).unwrap();
    });
    let result = finished.recv_timeout(std::time::Duration::from_secs(60));
    assert!(
        result.is_ok(),
        "translation table full: an insertion found no empty slot"
    );
}

#[test]
fn flushing_waits_for_threads_running_and_entering_the_same_space() {
    if Dbt::new().is_none() {
        return;
    }
    // A full flush has to wait until every other thread has stopped (parked) or left translated
    // code: half the threads keep spinning in a loop and stop only when kicked; half enter and
    // leave frequently. Never getting there (hanging) counts as failure. After the flush, the
    // thread that requested it first translates a few other pieces of code, overwriting the old
    // translations at the start of the code cache: if a thread were still running old
    // translations during the flush, it would run into them and compute wrong results or crash.
    // All threads run the same code (shared translations), with the loop count in x0
    const OTHER: u64 = CODE + 0x100;
    let program = |g: &mut Guest| {
        g.code(CODE, &[SUB_X0_1, cbnz_x0(CODE + 4, CODE), movz_x0(7), SVC]);
        for i in 0..16u16 {
            let at = OTHER + 0x10 * u64::from(i);
            g.code(at, &[movz_x0(100 + i), ADD_X1_1, SVC]);
        }
    };
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut dbt = Dbt::new().unwrap();
        let space = dbt.space().clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let workers: Vec<_> = (0..4)
            .map(|i| {
                let (space, stop) = (space.clone(), stop.clone());
                std::thread::spawn(move || {
                    let mut dbt = Dbt::attach(&space, 0).unwrap();
                    let mut g = Guest::new();
                    program(&mut g);
                    let mut runs = 0u64;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        g.cpu.state_mut().pc = CODE;
                        g.cpu.state_mut().x[0] = if i % 2 == 0 { 200_000 } else { 1 };
                        run_to_svc(&mut dbt, &mut g.cpu);
                        assert_eq!(g.cpu.state().x[0], 7);
                        runs += 1;
                    }
                    (runs, dbt.stats().flushes)
                })
            })
            .collect();
        let mut g = Guest::new();
        program(&mut g);
        for _ in 0..200 {
            dbt.flush();
            for i in 0..16u16 {
                g.cpu.state_mut().pc = OTHER + 0x10 * u64::from(i);
                run_to_svc(&mut dbt, &mut g.cpu);
                assert_eq!(g.cpu.state().x[0], u64::from(100 + i));
            }
            g.cpu.state_mut().pc = CODE;
            g.cpu.state_mut().x[0] = 1;
            run_to_svc(&mut dbt, &mut g.cpu);
            assert_eq!(g.cpu.state().x[0], 7);
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let mut flushes = dbt.stats().flushes;
        for w in workers {
            let (runs, n) = w.join().unwrap();
            assert!(runs > 0);
            flushes += n;
        }
        done.send(flushes).unwrap();
    });
    let flushes = finished
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("a full flush kept waiting for the other threads to stop, or a thread failed");
    // Every flush request results in exactly one flush (done by the thread that sees it first)
    assert_eq!(flushes, 200);
}

fn cbnz_x0(from: u64, to: u64) -> u32 {
    0xb500_0000 | ((((to as i64 - from as i64) / 4) as u32 & 0x7_ffff) << 5)
}

/// Runs to an svc, continuing when interrupted (a full flush needs the other threads to stop).
fn run_to_svc(dbt: &mut Dbt, cpu: &mut Cpu) {
    loop {
        match dbt.run(cpu) {
            Exit::Svc { imm: 0 } => return,
            Exit::Kick => {}
            e => panic!("unexpected exit {e:?}"),
        }
    }
}

#[test]
fn returns_follow_x30_even_when_the_prediction_is_wrong() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    let f = CODE + 0x100;
    let other = CODE + 0x200;
    g.code(CODE, &[bl(CODE, f), movz_x0(7), SVC]);
    // An ordinary call and return: returns to just after the call
    g.code(f, &[RET]);
    assert_eq!(g.run(&mut dbt), 7);
    assert_eq!(g.run(&mut dbt), 7);
    // The callee changed x30 (as longjmp does): the shadow stack top does not match, so return by
    // x30
    g.code(f, &[adr_x30(f, other), RET]);
    g.code(other, &[movz_x0(9), SVC]);
    dbt.invalidate(&g.cpu, f, 4);
    assert_eq!(g.run(&mut dbt), 9);
}

fn adr_x30(from: u64, to: u64) -> u32 {
    let off = (to as i64 - from as i64) as u32;
    0x1000_001e | (off & 3) << 29 | ((off >> 2) & 0x7_ffff) << 5
}

#[test]
fn returning_to_the_empty_entry_marker_is_still_checked() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    // An empty shadow-stack entry records guest address 1: when x30 equals it, return still goes
    // by x30, giving a pc alignment fault
    g.code(CODE, &[0xd280_003e, RET]); // movz x30, #1; ret
    g.cpu.state_mut().pc = CODE;
    assert!(matches!(
        dbt.run(&mut g.cpu),
        Exit::Fault {
            addr: 1,
            kind: FaultKind::Alignment,
            ..
        }
    ));
}

#[test]
fn deep_recursion_wraps_the_shadow_stack() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    let f = CODE + 0x100;
    // main: x0 = 200; bl f; svc. f recurses x0 levels deep, and x1 is incremented on each return:
    // past the shadow stack's 64 entries the bottom entries are overwritten and deeper returns
    // can only be looked up by x30, with the same result
    g.code(CODE, &[movz_x0(200), bl(CODE + 4, f), SVC]);
    let done = f + 6 * 4;
    g.code(
        f,
        &[
            cbz_x0(f, done),
            STP_FP_LR_PRE,
            SUB_X0_1,
            bl(f + 12, f),
            LDP_FP_LR_POST,
            ADD_X1_1,
            RET,
        ],
    );
    for _ in 0..2 {
        g.cpu.state_mut().x[1] = 0;
        assert_eq!(g.run(&mut dbt), 0);
        assert_eq!(g.cpu.state().x[1], 200);
        assert_eq!(g.cpu.state().sp, STACK);
    }
}

#[test]
fn cross_page_accesses_stay_in_translated_code() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    g.code(CODE, &[LDR_X0_X2, STR_X3_X4, LDP_X5_X6_X7, SVC]);
    // Each new top byte refills both pages. Repeating it exercises the cached pair.
    for (round, top_byte) in [0, 0, 0xab, 0xab, 0xff].into_iter().enumerate() {
        let tag = top_byte << 56;
        let value = 0x1122_3344_5566_7788 + round as u64;
        let s = g.cpu.state_mut();
        s.x[2] = tag | before_page(1, 4);
        s.x[3] = value;
        s.x[4] = tag | before_page(1, 2);
        s.x[7] = tag | before_page(1, 12);
        let expect = crossing(&g, 1, 4);
        g.run(&mut dbt);
        let s = g.cpu.state();
        assert_eq!(s.x[0], expect);
        assert_eq!(g.data(0, 4096 - 8) >> 48, value & 0xffff);
        assert_eq!(g.data(1, 0) & 0xffff_ffff_ffff, value >> 16);
        assert_eq!(s.x[6], crossing(&g, 1, 4));
        assert_eq!(s.x[5], g.data(0, 4096 - 12));
    }
    assert_eq!(dbt.stats().exits_interp, 0);
}

#[test]
fn tagged_group_writeback_and_exclusive_aliases() {
    let Some(mut dbt) = Dbt::new() else { return };
    let mut g = Guest::with_data();
    let f = CODE + 0x900;
    g.code(
        f,
        &[
            LDR_X0_X2,
            0xf800_8443, // str x3, [x2], #8
            0xc85f_7c85, // ldxr x5, [x4]
            0xc806_7ce3, // stxr w6, x3, [x7]
            SVC,
        ],
    );
    let s = g.cpu.state_mut();
    s.x[2] = (0xab << 56) | DATA;
    s.x[3] = 12345;
    s.x[4] = (0xcd << 56) | (DATA + 8);
    s.x[7] = DATA + 8;
    let pair = (g.data(0, 0), g.data(0, 8));
    g.run_at(&mut dbt, f);
    let s = g.cpu.state();
    assert_eq!((s.x[0], s.x[5]), pair);
    assert_eq!(s.x[2], (0xab << 56) | (DATA + 8));
    assert_eq!(s.x[6], 0);
    assert_eq!((g.data(0, 0), g.data(0, 8)), (12345, 12345));
    assert!(dbt.stats().insns_grouped > 0);
    assert_eq!(dbt.stats().exits_interp, 0);
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
fn exceptions_clear_translated_exclusive_reservations() {
    use std::sync::atomic::{AtomicU32, Ordering};

    const LDAXR: u32 = 0xc85f_fc20; // ldaxr x0, [x1]
    const STLXR: u32 = 0xc802_fc23; // stlxr w2, x3, [x1]
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let mut dbt = Dbt::with_regs(regs).expect("tier 1");
        let mut g = Guest::with_data();
        let original = g.data(0, 0);
        g.cpu.state_mut().x[1] = DATA;
        g.cpu.state_mut().x[3] = 99;
        let retry = CODE + 0x100;
        g.code(retry, &[STLXR, SVC]);
        for (i, (insn, expected)) in [
            (
                STLXR,
                Exit::Fault {
                    addr: DATA,
                    access: Access::Write,
                    kind: FaultKind::Page,
                },
            ),
            (0, Exit::Undefined { insn: 0 }),
            (0xd420_0020, Exit::Breakpoint { imm: 1 }),
            (SVC, Exit::Svc { imm: 0 }),
        ]
        .into_iter()
        .enumerate()
        {
            if insn == STLXR {
                g.mmu.protect(DATA, PAGE_SIZE, prot::READ).unwrap();
                g.cpu.tlb_flush();
            }
            let pc = CODE + 16 * i as u64;
            g.code(pc, &[LDAXR, insn]);
            assert_eq!(go(&mut g, &mut dbt, pc), expected, "{regs:?}");
            assert_eq!(g.cpu.state().x[0], original);
            if insn == STLXR {
                g.mmu
                    .protect(DATA, PAGE_SIZE, prot::READ | prot::WRITE)
                    .unwrap();
                g.cpu.tlb_flush();
            }
            g.run_at(&mut dbt, retry);
            assert_eq!(
                (g.cpu.state().x[2], g.data(0, 0)),
                (1, original),
                "{regs:?} {expected:?}"
            );
        }

        // Publish readiness after LDAXR, then spin at a block entry until the host kicks.
        let pc = CODE + 0x200;
        g.code(pc, &[LDAXR, 0x889f_fc83, 0x1400_0000]); // stlr w3, [x4]; b .
        g.cpu.state_mut().x[4] = STACK - PAGE_SIZE;
        g.cpu.state_mut().pc = pc;
        let kicker = g.cpu.kicker();
        // The guest publishes to this aligned word with STLR.
        let ready = unsafe { AtomicU32::from_ptr(g.pages[2].0.as_mut_ptr().cast()) };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while ready.load(Ordering::Acquire) == 0 {
                    std::thread::yield_now();
                }
                unsafe { kicker.kick() };
            });
            let exit = dbt.run(&mut g.cpu);
            ready.store(1, Ordering::Release); // release the helper on an unexpected early exit
            assert_eq!(exit, Exit::Kick, "{regs:?}");
        });
        assert_eq!(g.cpu.state().pc, pc + 8);
        assert_eq!(g.cpu.state().x[0], original);
        g.run_at(&mut dbt, retry);
        assert_eq!(
            (g.cpu.state().x[2], g.data(0, 0)),
            (1, original),
            "{regs:?}"
        );

        // DSB drains this IC IVAU through R_CODE between the exclusive instructions.
        let pc = CODE + 0x300;
        g.code(pc, &[LDAXR, 0xd50b_7521, 0xd503_3f9f, STLXR, SVC]);
        g.run_at(&mut dbt, pc);
        assert_eq!((g.cpu.state().x[2], g.data(0, 0)), (0, 99), "{regs:?}");
    }
}

#[test]
fn a_write_only_mapping_cannot_authorize_a_grouped_read() {
    let Some(mut dbt) = Dbt::new() else { return };
    let mut g = Guest::with_data();
    // The raw MMU can represent write-only pages even though Linux adds read permission.
    g.mmu.protect(DATA, PAGE_SIZE, prot::WRITE).unwrap();
    let f = CODE + 0xb00;
    g.code(CODE, &[STR_X3_X4, SVC]);
    g.code(f, &[LDR_X0_X2, 0xf900_0443, SVC]); // ldr x0, [x2]; str x3, [x2, #8]
    for tag in [0xab << 56, 0] {
        let s = g.cpu.state_mut();
        s.x[2] = tag | DATA;
        s.x[4] = s.x[2];
        s.x[3] = 99;
        g.run(&mut dbt);
        assert_eq!(g.data(0, 0), 99);
        let before = g.data(0, 8);
        assert_eq!(
            go(&mut g, &mut dbt, f),
            Exit::Fault {
                addr: DATA,
                access: Access::Read,
                kind: FaultKind::Page
            }
        );
        assert_eq!(g.cpu.state().pc, f);
        assert_eq!(g.data(0, 8), before);
    }
}

#[test]
fn cross_page_accesses_to_scattered_host_pages_use_tier0() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    g.code(CODE, &[LDR_X0_X2, SVC]);
    g.cpu.state_mut().x[2] = before_page(3, 4);
    // On the host, page 2 is followed by the page before page 3, so each page must be accessed
    // through the page table separately
    assert_eq!(g.run(&mut dbt), crossing(&g, 3, 4));
    assert_eq!(dbt.stats().exits_interp, 1);
}

#[test]
fn cross_page_faults_are_precise() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    // A write crossing into a read-only page, a read crossing into an unmapped page: reported at
    // the second page, and the first page must not be written
    let cases = [
        (STR_X3_X4, 4, before_page(5, 4), DATA + 5 * PAGE_SIZE),
        (LDR_X0_X2, 2, before_page(6, 4), DATA + 6 * PAGE_SIZE),
        (LDR_X0_X2, 2, u64::MAX - 3, 0),
        (LDR_X0_X2, 2, (0xab01u64 << 48) | DATA, (1 << 48) | DATA),
        (
            STR_X3_X4,
            4,
            (0xab << 56) | before_page(5, 4),
            DATA + 5 * PAGE_SIZE,
        ),
    ];
    for (insn, reg, addr, fault) in cases {
        g.code(CODE, &[insn, SVC]);
        dbt.invalidate(&g.cpu, CODE, 8);
        let before = g.data(4, 4096 - 8);
        g.cpu.state_mut().x[reg] = addr;
        g.cpu.state_mut().pc = CODE;
        match dbt.run(&mut g.cpu) {
            Exit::Fault { addr, .. } if fault != 0 => assert_eq!(addr, fault),
            Exit::Fault { .. } => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(g.cpu.state().pc, CODE);
        assert_eq!(g.data(4, 4096 - 8), before);
    }
}

const LDR_X1_X2_8: u32 = 0xf940_0441; // ldr x1, [x2, #8]

// The following tests check whether accesses are grouped. An instance may come from the pool,
// carrying "no more grouping here" marks (by pc) recorded by other tests, so each test puts its
// code at its own address.

#[test]
fn exits_beyond_48_bits_keep_the_whole_pc() {
    // An exit stub keeps the guest pc and the exit reason in one data word (low 48 bits, high 16
    // bits); when the computed branch target is beyond 48 bits a different stub is used. Code in
    // the last page of the address space runs to the end of the page and falls to 2^48: the
    // instruction fetch fault reports the full address, which must not be truncated to 0
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_pages(4);
    const LAST: u64 = (1 << 48) - PAGE_SIZE;
    let page = &mut g.pages[3].0;
    page[..4].copy_from_slice(&b(LAST, LAST + 4092).to_le_bytes());
    page[4092..].copy_from_slice(&movz_x0(5).to_le_bytes());
    let host = NonNull::new(g.pages[3].0.as_mut_ptr()).unwrap();
    unsafe {
        g.mmu
            .map(LAST, host, PAGE_SIZE, prot::READ | prot::EXEC)
            .unwrap()
    };
    g.cpu.state_mut().pc = LAST;
    match dbt.run(&mut g.cpu) {
        Exit::Fault { addr, .. } => assert_eq!(addr, 1 << 48),
        other => panic!("{other:?}"),
    }
    assert_eq!(g.cpu.state().pc, 1 << 48);
    assert_eq!(g.cpu.state().x[0], 5);
}

#[test]
fn accesses_with_the_same_base_share_one_check() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::new();
    // A function prologue and epilogue around instructions that rewrite stolen registers: 6
    // memory accesses in all, checked only once
    let f = CODE + 0x100;
    g.code(
        f,
        &[
            0xa9bd_7bfd, // stp x29, x30, [sp, #-48]!
            0xa901_47f0, // stp x16, x17, [sp, #16]
            0xf900_17fb, // str x27, [sp, #40]
            0xd280_0010, // movz x16, #0
            0xd280_0011, // movz x17, #0
            0xd280_001b, // movz x27, #0
            0xa941_47f0, // ldp x16, x17, [sp, #16]
            0xf940_17fb, // ldr x27, [sp, #40]
            0xa8c3_7bfd, // ldp x29, x30, [sp], #48
            SVC,
        ],
    );
    let regs = [16, 17, 27, 29, 30];
    for (i, &r) in regs.iter().enumerate() {
        g.cpu.state_mut().x[r] = 0x1111 * (i as u64 + 1);
    }
    g.run_at(&mut dbt, f);
    for (i, &r) in regs.iter().enumerate() {
        assert_eq!(g.cpu.state().x[r], 0x1111 * (i as u64 + 1));
    }
    assert_eq!(g.cpu.state().sp, STACK);
    let s = dbt.stats();
    assert_eq!(s.insns_grouped, 5);
    assert_eq!(s.exits_interp, 0);
}

#[test]
fn shared_checks_across_scattered_host_pages_are_undone() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    let f = CODE + 0x200;
    g.code(f, &[LDR_X0_X2, LDR_X1_X2_8, SVC]);
    // Each of the two accesses stays within a page, but together they cross into the next page,
    // which is not adjacent on the host: falls back to Tier 0, and from the second time on this
    // block is no longer grouped
    for (ungrouped, interp) in [(0, 1), (1, 2), (1, 2)] {
        g.cpu.state_mut().x[2] = before_page(3, 8);
        g.run_at(&mut dbt, f);
        assert_eq!(g.cpu.state().x[0], g.data(2, 4096 - 8));
        assert_eq!(g.cpu.state().x[1], g.data(3, 0));
        let s = dbt.stats();
        assert_eq!((s.ungrouped, s.exits_interp), (ungrouped, interp));
    }
    // The same code elsewhere, accessing two pages that are adjacent on the host, still shares
    // one check
    let f = CODE + 0x300;
    g.code(f, &[LDR_X0_X2, LDR_X1_X2_8, SVC]);
    g.cpu.state_mut().x[2] = before_page(1, 8);
    g.run_at(&mut dbt, f);
    assert_eq!(g.cpu.state().x[1], g.data(1, 0));
    let s = dbt.stats();
    assert_eq!((s.ungrouped, s.insns_grouped), (1, 2));
}

#[test]
fn shared_checks_cover_accesses_behind_branches() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    // The second load comes after a conditional branch, and the next page it accesses is not
    // mapped; when x0 is 0 it does not execute
    let f = CODE + 0x400;
    g.code(f, &[LDR_X0_X2, cbz_x0(f + 4, f + 12), LDR_X1_X2_8, SVC]);
    g.pages[8].0[4096 - 8..].fill(0);
    g.cpu.state_mut().x[1] = 7;
    for ungrouped in [0, 1, 1] {
        g.cpu.state_mut().x[2] = before_page(6, 8);
        g.run_at(&mut dbt, f);
        assert_eq!(g.cpu.state().x[0], 0);
        assert_eq!(g.cpu.state().x[1], 7);
        assert_eq!(dbt.stats().ungrouped, ungrouped);
    }
}

#[test]
fn alternating_group_leaders_in_same_slot_are_both_ungrouped() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    // Three leaders spaced by 64 * 4 = 256 bytes: all three mapped to the same direct-mapped
    // strikes[64] slot previously, so alternating failures evicted each other forever.
    let leaders = [CODE + 0x200, CODE + 0x300, CODE + 0x400];
    for &f in &leaders {
        g.code(f, &[LDR_X0_X2, LDR_X1_X2_8, SVC]);
    }
    // Round 1 records first strikes; round 2 ungroups all three; round 3 stays ungrouped.
    for (ungrouped, interp) in [(0, 3), (3, 6), (3, 6)] {
        for &f in &leaders {
            g.cpu.state_mut().x[2] = before_page(3, 8);
            g.run_at(&mut dbt, f);
            assert_eq!(g.cpu.state().x[0], g.data(2, 4096 - 8));
            assert_eq!(g.cpu.state().x[1], g.data(3, 0));
        }
        assert_eq!(
            (dbt.stats().ungrouped, dbt.stats().exits_interp),
            (ungrouped, interp)
        );
    }
}

#[test]
fn watchpoints_send_only_watched_pages_to_tier0() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    let f = CODE + 0x500;
    g.code(f, &[LDR_X0_X2, STR_X3_X4, SVC]);
    let page = DATA + 4 * PAGE_SIZE;
    let watched = page + 0x100;
    g.cpu
        .state_mut()
        .set_hw_debug(&[], &[(watched, watched + 8, WATCH_STORE)]);
    let interp = |dbt: &Dbt| dbt.stats().exits_interp;
    // Read the write-watched page and write another page: the first time misses the TLB and is
    // executed by Tier 0, which fills the table; after that everything stays in translated code
    let s = g.cpu.state_mut();
    (s.x[2], s.x[3], s.x[4]) = (page + 0x108, 5, DATA + 0x10);
    for _ in 0..2 {
        assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
    }
    let before = interp(&dbt);
    assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
    assert_eq!(interp(&dbt), before);
    assert_eq!(g.cpu.state().x[0], g.data(4, 0x108));
    // Writing bytes of the watched page that are not watched: executed by Tier 0 every time
    g.cpu.state_mut().x[4] = page + 0x108;
    for i in 1..=2 {
        assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
        assert_eq!(interp(&dbt), before + i);
    }
    assert_eq!(g.data(4, 0x108), 5);
    // Writing the watched bytes: stops at this instruction without writing; the preceding read
    // has already executed
    let old = g.data(4, 0x100);
    let s = g.cpu.state_mut();
    (s.x[0], s.x[4]) = (0, (0xab << 56) | (watched + 4));
    let hit = Exit::Fault {
        addr: watched + 4,
        access: Access::Write,
        kind: FaultKind::Watchpoint,
    };
    assert_eq!(go(&mut g, &mut dbt, f), hit);
    assert_eq!(g.cpu.state().pc, f + 4);
    assert_eq!(g.cpu.state().x[0], g.data(4, 0x108));
    assert_eq!(g.data(4, 0x100), old);
    // Read watchpoint: the read half does not enter the TLB either
    g.cpu
        .state_mut()
        .set_hw_debug(&[], &[(watched, watched + 8, WATCH_LOAD)]);
    let s = g.cpu.state_mut();
    (s.x[2], s.x[4]) = (watched, DATA + 0x10);
    let hit = Exit::Fault {
        addr: watched,
        access: Access::Read,
        kind: FaultKind::Watchpoint,
    };
    assert_eq!(go(&mut g, &mut dbt, f), hit);
    assert_eq!(g.cpu.state().pc, f);
    // After removing it, the whole page is in translated code again
    g.cpu.state_mut().set_hw_debug(&[], &[]);
    g.cpu.state_mut().x[4] = page + 0x100;
    assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
    let before = interp(&dbt);
    assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
    assert_eq!(interp(&dbt), before);
    assert_eq!(g.data(4, 0x100), 5);
}

#[test]
fn watchpoints_stop_inside_shared_checks_and_atomics() {
    let Some(mut dbt) = Dbt::new() else {
        return;
    };
    let mut g = Guest::with_data();
    // Several stack writes in a function prologue sharing one check: stops at the instruction
    // writing the watched slot, with the earlier ones already executed
    let f = CODE + 0x600;
    g.code(
        f,
        &[
            0xa9bd_7bfd, // stp x29, x30, [sp, #-48]!
            0xa901_47f0, // stp x16, x17, [sp, #16]
            0xf900_17fb, // str x27, [sp, #40]
            0x9100_c3ff, // add sp, sp, #48
            SVC,
        ],
    );
    let slot = STACK - 8;
    g.cpu
        .state_mut()
        .set_hw_debug(&[], &[(slot, slot + 8, WATCH_STORE)]);
    g.cpu.state_mut().x[29] = 0x2929;
    let hit = Exit::Fault {
        addr: slot,
        access: Access::Write,
        kind: FaultKind::Watchpoint,
    };
    assert_eq!(go(&mut g, &mut dbt, f), hit);
    assert_eq!(g.cpu.state().pc, f + 8);
    assert_eq!(g.cpu.state().sp, STACK - 48);
    let stack = &g.pages[2].0;
    assert_eq!(
        u64::from_le_bytes(stack[4096 - 48..4096 - 40].try_into().unwrap()),
        0x2929
    );
    // Not a case of the group being unable to share a check: "no more grouping here" is not
    // recorded
    assert_eq!(dbt.stats().ungrouped, 0);
    g.cpu.state_mut().set_hw_debug(&[], &[]);
    assert_eq!(dbt.run(&mut g.cpu), Exit::Svc { imm: 0 });
    assert_eq!(g.cpu.state().sp, STACK);

    // An atomic read-modify-write counts as a read: a read watchpoint must stop it too
    let f = CODE + 0x700;
    g.code(f, &[0xf825_00e6, SVC]); // ldadd x5, x6, [x7]
    let at = DATA + 4 * PAGE_SIZE + 0x200;
    g.cpu.state_mut().x[7] = at;
    g.cpu.state_mut().x[5] = 1;
    assert_eq!(go(&mut g, &mut dbt, f), Exit::Svc { imm: 0 });
    let after = g.data(4, 0x200);
    g.cpu
        .state_mut()
        .set_hw_debug(&[], &[(at, at + 8, WATCH_LOAD)]);
    let exit = go(&mut g, &mut dbt, f);
    assert!(
        matches!(exit, Exit::Fault { kind: FaultKind::Watchpoint, addr, .. } if addr == at),
        "{exit:?}"
    );
    assert_eq!(g.cpu.state().pc, f);
    assert_eq!(g.data(4, 0x200), after);
}

#[test]
fn memops_accelerate_large_and_preserve_small_and_fallbacks() {
    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let mut dbt = Dbt::attach(&space, 0).unwrap();
    let mut g = Guest::with_data();

    // Stub functions at distinct entry PCs: if guest code runs (small n < 128 or fallback), they
    // return sentinel 0x7777; if exec_memop runs, it completes the operation and returns via x30.
    let f_memset = CODE + 0x100;
    let f_memcpy = CODE + 0x120;
    let f_memmove = CODE + 0x140;
    let f_memcmp = CODE + 0x160;
    let f_memchr = CODE + 0x180;
    let f_strncmp = CODE + 0x1a0;
    for pc in [f_memset, f_memcpy, f_memmove, f_memcmp, f_memchr, f_strncmp] {
        g.code(pc, &[movz_x0(0x7777), RET]);
    }
    space.set_memops(&[
        DbtMemop {
            pc: f_memset,
            kind: MEMOP_MEMSET,
            reserved: 0,
        },
        DbtMemop {
            pc: f_memcpy,
            kind: MEMOP_MEMCPY,
            reserved: 0,
        },
        DbtMemop {
            pc: f_memmove,
            kind: MEMOP_MEMMOVE,
            reserved: 0,
        },
        DbtMemop {
            pc: f_memcmp,
            kind: MEMOP_MEMCMP,
            reserved: 0,
        },
        DbtMemop {
            pc: f_memchr,
            kind: MEMOP_MEMCHR,
            reserved: 0,
        },
        DbtMemop {
            pc: f_strncmp,
            kind: MEMOP_STRNCMP,
            reserved: 0,
        },
    ]);

    let caller = CODE + 0x40;
    g.code(caller, &[0xd63f_0120, SVC]); // blr x9; svc #0
    let call = |g: &mut Guest, dbt: &mut Dbt, target: u64, x0: u64, x1: u64, x2: u64| -> u64 {
        let s = g.cpu.state_mut();
        s.x[9] = target;
        s.x[0] = x0;
        s.x[1] = x1;
        s.x[2] = x2;
        g.run_at(dbt, caller)
    };

    // Small operations (n < 128) stay inline in Tier 1 and execute the guest stub.
    assert_eq!(call(&mut g, &mut dbt, f_memset, DATA, 0x5a, 127), 0x7777);
    assert_eq!(
        call(&mut g, &mut dbt, f_memcpy, DATA, DATA + 0x100, 64),
        0x7777
    );

    // Cross-page memset across scattered host pages (DATA + 2*4096 and DATA + 3*4096 are reversed
    // in host memory).
    let p2_end = before_page(3, 64);
    assert_eq!(call(&mut g, &mut dbt, f_memset, p2_end, 0xa5, 256), p2_end);
    assert!(g.pages[6].0[4096 - 64..].iter().all(|&b| b == 0xa5));
    assert!(g.pages[5].0[..192].iter().all(|&b| b == 0xa5));

    // Cross-page memcpy from DATA + 0 (pages 3, 4) into DATA + 2*4096 (scattered pages 6, 5).
    for (i, b) in g.pages[3].0[4096 - 100..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    for (i, b) in g.pages[4].0[..200].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(5).wrapping_add(7);
    }
    let src = before_page(1, 100);
    let dst = before_page(3, 100);
    assert_eq!(call(&mut g, &mut dbt, f_memcpy, dst, src, 300), dst);
    assert_eq!(&g.pages[6].0[4096 - 100..], &g.pages[3].0[4096 - 100..]);
    assert_eq!(&g.pages[5].0[..200], &g.pages[4].0[..200]);

    // Overlapping memmove in both directions across a scattered page boundary.
    let expected: Vec<u8> = g.pages[6].0[4096 - 100..]
        .iter()
        .chain(&g.pages[5].0[..156])
        .copied()
        .collect();
    // Backward copy: dst > src, overlapping across page 2 -> page 3.
    let dst_fwd = dst + 32;
    assert_eq!(
        call(&mut g, &mut dbt, f_memmove, dst_fwd, dst, 256),
        dst_fwd
    );
    let moved_fwd: Vec<u8> = g.pages[6].0[4096 - 68..]
        .iter()
        .chain(&g.pages[5].0[..188])
        .copied()
        .collect();
    assert_eq!(moved_fwd, expected);
    // Forward copy: dst < src, moving back to dst.
    assert_eq!(call(&mut g, &mut dbt, f_memmove, dst, dst_fwd, 256), dst);
    let moved_back: Vec<u8> = g.pages[6].0[4096 - 100..]
        .iter()
        .chain(&g.pages[5].0[..156])
        .copied()
        .collect();
    assert_eq!(moved_back, expected);

    // memcmp equal and differing across pages.
    assert_eq!(call(&mut g, &mut dbt, f_memcmp, src, dst, 256), 0);
    g.pages[5].0[10] = g.pages[4].0[10].wrapping_add(1);
    let cmp = call(&mut g, &mut dbt, f_memcmp, src, dst, 256) as i64;
    assert!(cmp < 0, "expected negative memcmp result, got {cmp}");

    // memchr across pages, preserving a TBI top-byte tag on the returned pointer.
    g.pages[6].0[4096 - 100..].fill(b'x');
    g.pages[5].0[..200].fill(b'x');
    g.pages[5].0[42] = b'Z';
    let tagged_dst = dst | (0xab_u64 << 56);
    assert_eq!(
        call(&mut g, &mut dbt, f_memchr, tagged_dst, b'Z' as u64, 300),
        tagged_dst + 142
    );
    assert_eq!(
        call(&mut g, &mut dbt, f_memchr, tagged_dst, b'Q' as u64, 300),
        0
    );

    // strncmp stops at NUL before n and distinguishes differing bytes.
    g.pages[3].0[4096 - 100..].fill(b'a');
    g.pages[4].0[..200].fill(b'a');
    g.pages[6].0[4096 - 100..].fill(b'a');
    g.pages[5].0[..200].fill(b'a');
    g.pages[4].0[50] = 0;
    g.pages[5].0[50] = 0;
    g.pages[4].0[51] = b'1';
    g.pages[5].0[51] = b'2';
    assert_eq!(call(&mut g, &mut dbt, f_strncmp, src, dst, 256), 0);
    g.pages[4].0[49] = b'b';
    assert!((call(&mut g, &mut dbt, f_strncmp, src, dst, 256) as i64) > 0);

    // Watchpoint active: exec_memop must decline and fall back to guest code.
    let watched = DATA + 4 * PAGE_SIZE;
    g.cpu
        .state_mut()
        .set_hw_debug(&[], &[(watched, watched + 8, WATCH_STORE)]);
    assert_eq!(call(&mut g, &mut dbt, f_memset, watched, 0x33, 256), 0x7777);
    g.cpu.state_mut().set_hw_debug(&[], &[]);

    // Precise fault pre-validation: a memset crossing from writable page 4 into read-only page 5
    // must leave page 4 untouched and fall back to guest code.
    g.pages[7].0[4096 - 64..].fill(0x11);
    let ro_cross = before_page(5, 64);
    assert_eq!(
        call(&mut g, &mut dbt, f_memset, ro_cross, 0xee, 256),
        0x7777
    );
    assert!(g.pages[7].0[4096 - 64..].iter().all(|&b| b == 0x11));

    // Shadow return stack stays aligned across a nested caller -> memop call -> caller ret.
    let outer = CODE + 0x200;
    let inner = CODE + 0x220;
    g.code(outer, &[bl(outer, inner), SVC]);
    g.code(
        inner,
        &[STP_FP_LR_PRE, bl(inner + 4, f_memset), LDP_FP_LR_POST, RET],
    );
    let s = g.cpu.state_mut();
    s.x[0] = DATA + 4 * PAGE_SIZE;
    s.x[1] = 0x42;
    s.x[2] = 256;
    assert_eq!(g.run_at(&mut dbt, outer), DATA + 4 * PAGE_SIZE);
    assert!(g.pages[7].0[..256].iter().all(|&b| b == 0x42));
}

#[test]
fn memops_bypass_templates_retire_on_update_and_clear_on_pool_reuse() {
    let _pool = lock_pool();
    let Some(space_a) = DbtSpace::new(0xfeed_cafe, DbtRegs::Default) else {
        return;
    };
    let mut g = Guest::with_data();
    let f = CODE + 0x300;
    let caller = CODE + 0x340;
    g.code(f, &[movz_x0(0x5555), RET]);
    g.code(caller, &[bl(caller, f), SVC]);

    // 1. Populate the global template arena from an instance WITHOUT memops first.
    {
        let space_plain = DbtSpace::new(0, DbtRegs::Default).unwrap();
        let mut dbt_plain = Dbt::attach(&space_plain, 0).unwrap();
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x99;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_plain, caller), 0x5555);
    }

    // 2. Register memop on space_a: must NOT reuse the plain template from above, and must retire
    //    existing translations on live updates.
    {
        let mut dbt_a = Dbt::attach(&space_a, 0).unwrap();
        // Translate f before registering memop.
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x99;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_a, caller), 0x5555);

        // Register memop dynamically: existing block at f must be retired.
        space_a.set_memops(&[DbtMemop {
            pc: f,
            kind: MEMOP_MEMSET,
            reserved: 0,
        }]);
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x99;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_a, caller), DATA);
        assert!(g.pages[3].0[..256].iter().all(|&b| b == 0x99));

        // Remove memop dynamically: must immediately revert to guest code.
        space_a.set_memops(&[]);
        g.pages[3].0[..256].fill(0);
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x88;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_a, caller), 0x5555);
        assert!(g.pages[3].0[..256].iter().all(|&b| b == 0));

        // Re-register before returning space_a to the pool.
        space_a.set_memops(&[DbtMemop {
            pc: f,
            kind: MEMOP_MEMSET,
            reserved: 0,
        }]);
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x77;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_a, caller), DATA);
    }

    // 3. Another fresh space without memops must NOT be polluted by space_a's memop translation.
    {
        let space_other = DbtSpace::new(0, DbtRegs::Default).unwrap();
        let mut dbt_other = Dbt::attach(&space_other, 0).unwrap();
        let s = g.cpu.state_mut();
        s.x[0] = DATA;
        s.x[1] = 0x66;
        s.x[2] = 256;
        assert_eq!(g.run_at(&mut dbt_other, caller), 0x5555);
    }

    // 4. Pool reuse: dropping space_a returns it to the pool under key 0xfeed_cafe; the next
    //    instance taking it without calling set_memops must NOT inherit space_a's memops.
    drop(space_a);
    let space_reused = DbtSpace::new(0xfeed_cafe, DbtRegs::Default).unwrap();
    let mut dbt_reused = Dbt::attach(&space_reused, 0).unwrap();
    g.pages[3].0[..256].fill(0);
    let s = g.cpu.state_mut();
    s.x[0] = DATA;
    s.x[1] = 0x55;
    s.x[2] = 256;
    assert_eq!(g.run_at(&mut dbt_reused, caller), 0x5555);
    assert!(g.pages[3].0[..256].iter().all(|&b| b == 0));
}

#[test]
fn memops_in_code_group_ignore_private_mappings() {
    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let mut g = Guest::with_data();
    let f = CODE + 0x400;
    let caller = CODE + 0x440;
    g.code(f, &[movz_x0(0x4444), RET]);
    g.code(caller, &[bl(caller, f), SVC]);

    let tag = space.new_tag().unwrap();
    // Register a shared range that does NOT cover f, and register f as a memop.
    space.share(&[DbtSource {
        start: CODE + PAGE_SIZE,
        len: PAGE_SIZE,
        id: [1, 2, 0, 3, 4],
    }]);
    space.set_memops(&[DbtMemop {
        pc: f,
        kind: MEMOP_MEMSET,
        reserved: 0,
    }]);

    let mut dbt = Dbt::attach(&space, tag).unwrap();
    let s = g.cpu.state_mut();
    s.x[0] = DATA;
    s.x[1] = 0x22;
    s.x[2] = 256;
    // f is outside shared ranges (private to this tag), so it must not use the shared memop.
    assert_eq!(g.run_at(&mut dbt, caller), 0x4444);
}

#[test]
fn memops_concurrent_set_memops_keeps_translations_consistent() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    const N: usize = 16;
    let ops: Vec<DbtMemop> = (0..N)
        .map(|i| DbtMemop {
            pc: CODE + 0x10 * i as u64,
            kind: MEMOP_MEMSET,
            reserved: 0,
        })
        .collect();
    let setup = |g: &mut Guest| {
        for i in 0..N {
            let f = CODE + 0x10 * i as u64;
            let caller = CODE + 0x200 + 0x10 * i as u64;
            g.code(f, &[movz_x0(0x5555), RET]);
            g.code(caller, &[bl(caller, f), SVC]);
        }
    };

    let mut dbt = Dbt::attach(&space, 0).unwrap();
    let mut g = Guest::with_data();
    setup(&mut g);

    for final_enabled in [true, false] {
        space.set_memops(if final_enabled { &[] } else { &ops });
        dbt.flush();

        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let (space, stop, done) = (space.clone(), stop.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut dbt = Dbt::attach(&space, 0).unwrap();
                    let mut g = Guest::with_data();
                    setup(&mut g);
                    let mut i = 0usize;
                    while !stop.load(Ordering::Relaxed) {
                        let caller = CODE + 0x200 + 0x10 * (i % N) as u64;
                        g.pages[3].0[..256].fill(0);
                        let s = g.cpu.state_mut();
                        s.pc = caller;
                        s.x[0] = DATA;
                        s.x[1] = 0x7a;
                        s.x[2] = 256;
                        run_to_svc(&mut dbt, &mut g.cpu);
                        let ret = g.cpu.state().x[0];
                        if ret == DATA {
                            assert!(g.pages[3].0[..256].iter().all(|&b| b == 0x7a));
                        } else {
                            assert_eq!(ret, 0x5555);
                            assert!(g.pages[3].0[..256].iter().all(|&b| b == 0));
                        }
                        i += 1;
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for round in 0..32 {
            space.set_memops(if final_enabled { &[] } else { &ops });
            if round % 4 == 0 {
                dbt.flush();
            }
            space.set_memops(if final_enabled { &ops } else { &[] });
        }
        // Let workers finish any in-flight translations racing the final update.
        let target = done.load(Ordering::Relaxed) + 64;
        while done.load(Ordering::Relaxed) < target {
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
        for w in workers {
            w.join().unwrap();
        }

        // Verify directly without calling set_memops again so any stale block installed across
        // the final registration change is caught.
        for i in 0..N {
            let caller = CODE + 0x200 + 0x10 * i as u64;
            g.pages[3].0[..256].fill(0);
            let s = g.cpu.state_mut();
            s.pc = caller;
            s.x[0] = DATA;
            s.x[1] = 0x7a;
            s.x[2] = 256;
            run_to_svc(&mut dbt, &mut g.cpu);
            if final_enabled {
                assert_eq!(g.cpu.state().x[0], DATA);
                assert!(g.pages[3].0[..256].iter().all(|&b| b == 0x7a));
            } else {
                assert_eq!(g.cpu.state().x[0], 0x5555);
                assert!(g.pages[3].0[..256].iter().all(|&b| b == 0));
            }
        }
    }
}

#[test]
fn memops_in_cache_same_page_fast_path_and_sizemax() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(space) = DbtSpace::new(0, regs) else {
            return;
        };
        let mut dbt = Dbt::attach(&space, 0).unwrap();
        let mut g = Guest::with_data();

        // Warm data pages 0, 1, 2 (host pages 3, 4, 6) and read-only page 5 (host page 8) in the
        // data TLB by executing one load/store per page in translated code.
        let warm = CODE + 0x20;
        g.code(
            warm,
            &[
                0xf900_0001, // str x1, [x0]
                0xf940_0043, // ldr x3, [x2]
                SVC,
            ],
        );
        let warm_rw = |g: &mut Guest, dbt: &mut Dbt, addr: u64| {
            let s = g.cpu.state_mut();
            s.x[0] = addr;
            s.x[1] = 0;
            s.x[2] = addr;
            g.run_at(dbt, warm);
        };
        warm_rw(&mut g, &mut dbt, DATA);
        warm_rw(&mut g, &mut dbt, DATA + PAGE_SIZE);
        warm_rw(&mut g, &mut dbt, DATA + 2 * PAGE_SIZE);

        let f_memset = CODE + 0x100;
        let f_memcpy = CODE + 0x120;
        let f_memmove = CODE + 0x140;
        let f_memcmp = CODE + 0x160;
        let f_memchr = CODE + 0x180;
        let f_strncmp = CODE + 0x1a0;
        for pc in [f_memset, f_memcpy, f_memmove, f_memcmp, f_memchr, f_strncmp] {
            g.code(pc, &[movz_x0(0x7777), RET]);
        }
        space.set_memops(&[
            DbtMemop {
                pc: f_memset,
                kind: MEMOP_MEMSET,
                reserved: 0,
            },
            DbtMemop {
                pc: f_memcpy,
                kind: MEMOP_MEMCPY,
                reserved: 0,
            },
            DbtMemop {
                pc: f_memmove,
                kind: MEMOP_MEMMOVE,
                reserved: 0,
            },
            DbtMemop {
                pc: f_memcmp,
                kind: MEMOP_MEMCMP,
                reserved: 0,
            },
            DbtMemop {
                pc: f_memchr,
                kind: MEMOP_MEMCHR,
                reserved: 0,
            },
            DbtMemop {
                pc: f_strncmp,
                kind: MEMOP_STRNCMP,
                reserved: 0,
            },
        ]);

        // Caller preserves X3..X29 and NZCV; test checks they survive every fast-path call.
        let caller = CODE + 0x40;
        g.code(caller, &[0xd63f_0120, SVC]); // blr x9; svc #0
        let call_checked =
            |g: &mut Guest, dbt: &mut Dbt, target: u64, x0: u64, x1: u64, x2: u64| -> (u64, u64) {
                let before_interp = dbt.stats().exits_interp;
                let s = g.cpu.state_mut();
                s.x[9] = target;
                s.x[0] = x0;
                s.x[1] = x1;
                s.x[2] = x2;
                for r in 3..29 {
                    if r != 9 {
                        s.x[r] = 0x1111_0000_0000_0000 + r as u64;
                    }
                }
                s.nzcv = 0xa000_0000; // N=1, Z=0, C=1, V=0
                let ret = g.run_at(dbt, caller);
                let s = g.cpu.state();
                assert_eq!(s.x[1], x1, "x1 clobbered for {regs:?}");
                assert_eq!(s.x[2], x2, "x2 clobbered for {regs:?}");
                for r in 3..29 {
                    if r != 9 {
                        assert_eq!(
                            s.x[r],
                            0x1111_0000_0000_0000 + r as u64,
                            "x{r} clobbered for {regs:?}"
                        );
                    }
                }
                assert_eq!(s.nzcv, 0xa000_0000, "NZCV clobbered for {regs:?}");
                (ret, dbt.stats().exits_interp - before_interp)
            };

        // Below fast-path threshold: must stay in guest stub (sentinel 0x7777).
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memset, DATA, 0xaa, 31).0,
            0x7777
        );
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memcpy, DATA, DATA + 64, 31).0,
            0x7777
        );
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memmove, DATA, DATA + 64, 31).0,
            0x7777
        );
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memcmp, DATA, DATA + 64, 7).0,
            0x7777
        );
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memchr, DATA, 0xaa, 0).0,
            0x7777
        );

        // In-cache same-page memset across every boundary length (32..=4096) with guard bytes.
        for &len in &[32usize, 33, 47, 63, 64, 65, 95, 96, 97, 127, 128, 513, 4096] {
            let off = if len == 4096 { 0 } else { 7 };
            g.pages[3].0.fill(0x55);
            let (ret, interps) = call_checked(
                &mut g,
                &mut dbt,
                f_memset,
                DATA + off as u64,
                0x1ab,
                len as u64,
            );
            assert_eq!(ret, DATA + off as u64);
            assert_eq!(interps, 0, "memset({len}) should stay in-cache");
            assert!(g.pages[3].0[..off].iter().all(|&b| b == 0x55));
            assert!(g.pages[3].0[off..off + len].iter().all(|&b| b == 0xab));
            assert!(g.pages[3].0[off + len..].iter().all(|&b| b == 0x55));
        }

        // In-cache same-page memcpy & overlapping memmove (forward, backward, and dst == src).
        let pattern: Vec<u8> = (0..4096).map(|i| ((i * 73 + 19) & 0xff) as u8).collect();
        for &len in &[32usize, 33, 47, 48, 63, 64, 65, 95, 127, 255, 4096] {
            let off = if len == 4096 { 0 } else { 5 };
            g.pages[4].0.copy_from_slice(&pattern);
            g.pages[3].0.fill(0xee);
            let dst = DATA + off as u64;
            let src = DATA + PAGE_SIZE + off as u64;
            let (ret, interps) = call_checked(&mut g, &mut dbt, f_memcpy, dst, src, len as u64);
            assert_eq!(ret, dst);
            assert_eq!(interps, 0, "memcpy({len}) should stay in-cache");
            assert!(g.pages[3].0[..off].iter().all(|&b| b == 0xee));
            assert_eq!(&g.pages[3].0[off..off + len], &pattern[off..off + len]);
            assert!(g.pages[3].0[off + len..].iter().all(|&b| b == 0xee));
        }
        for &shift in &[1usize, 7, 17, 31, 33, 64] {
            for &len in &[32usize, 33, 63, 64, 95, 129] {
                // Backward overlap: dst > src
                g.pages[3].0.copy_from_slice(&pattern);
                let mut expected = pattern.clone();
                expected.copy_within(100..100 + len, 100 + shift);
                let (ret, interps) = call_checked(
                    &mut g,
                    &mut dbt,
                    f_memmove,
                    DATA + (100 + shift) as u64,
                    DATA + 100,
                    len as u64,
                );
                assert_eq!(ret, DATA + (100 + shift) as u64);
                assert_eq!(interps, 0);
                assert_eq!(
                    &g.pages[3].0[..],
                    &expected[..],
                    "bwd shift={shift} len={len}"
                );

                // Forward overlap: dst < src
                g.pages[3].0.copy_from_slice(&pattern);
                let mut expected = pattern.clone();
                expected.copy_within(100 + shift..100 + shift + len, 100);
                let (ret, interps) = call_checked(
                    &mut g,
                    &mut dbt,
                    f_memmove,
                    DATA + 100,
                    DATA + (100 + shift) as u64,
                    len as u64,
                );
                assert_eq!(ret, DATA + 100);
                assert_eq!(interps, 0);
                assert_eq!(
                    &g.pages[3].0[..],
                    &expected[..],
                    "fwd shift={shift} len={len}"
                );
            }
        }
        // dst == src no-op
        g.pages[3].0.copy_from_slice(&pattern);
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memmove, DATA + 64, DATA + 64, 128),
            (DATA + 64, 0)
        );
        assert_eq!(&g.pages[3].0[..], &pattern[..]);

        // In-cache same-page memcmp: equal, self, and differing at head/middle/tail with unsigned bytes.
        for &len in &[8usize, 9, 15, 16, 17, 31, 32, 63, 127, 256, 4096] {
            let off = if len == 4096 { 0 } else { 3 };
            g.pages[3].0.copy_from_slice(&pattern);
            g.pages[4].0.copy_from_slice(&pattern);
            let a = DATA + off as u64;
            let b = DATA + PAGE_SIZE + off as u64;
            assert_eq!(
                call_checked(&mut g, &mut dbt, f_memcmp, a, b, len as u64),
                (0, 0)
            );
            assert_eq!(
                call_checked(&mut g, &mut dbt, f_memcmp, a, a, len as u64),
                (0, 0)
            );
            for &pos in &[0usize, 1, 7, len / 2, len - 1] {
                g.pages[3].0[off + pos] = 0xff;
                g.pages[4].0[off + pos] = 0x00;
                let (res, interps) = call_checked(&mut g, &mut dbt, f_memcmp, a, b, len as u64);
                assert_eq!(interps, 0);
                assert_eq!(res as i64, 255, "memcmp +diff len={len} pos={pos}");
                let (res, interps) = call_checked(&mut g, &mut dbt, f_memcmp, b, a, len as u64);
                assert_eq!(interps, 0);
                assert_eq!(res as i64, -255, "memcmp -diff len={len} pos={pos}");
                g.pages[3].0[off + pos] = pattern[off + pos];
                g.pages[4].0[off + pos] = pattern[off + pos];
            }
        }

        // In-cache first-page memchr (including n = SIZE_MAX) + cross-page SIZE_MAX fallback.
        g.pages[3].0.fill(b'a');
        g.pages[4].0.fill(b'a');
        for &pos in &[0usize, 1, 7, 8, 9, 15, 16, 31, 63, 100] {
            g.pages[3].0[5 + pos] = b'Q';
            let (res, interps) =
                call_checked(&mut g, &mut dbt, f_memchr, DATA + 5, b'Q' as u64, 200);
            assert_eq!(res, DATA + 5 + pos as u64);
            assert_eq!(interps, 0, "memchr hit pos={pos} should stay in-cache");
            // Same call with n = SIZE_MAX (as musl strnlen does) must also finish in-cache!
            let (res, interps) =
                call_checked(&mut g, &mut dbt, f_memchr, DATA + 5, b'Q' as u64, u64::MAX);
            assert_eq!(res, DATA + 5 + pos as u64);
            assert_eq!(
                interps, 0,
                "memchr(SIZE_MAX) same-page hit should stay in-cache"
            );
            g.pages[3].0[5 + pos] = b'a';
        }
        // Same-page miss returns NULL in-cache.
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memchr, DATA + 5, b'Q' as u64, 200),
            (0, 0)
        );
        // Cross-page memchr with n = SIZE_MAX and a TBI top-byte tag: falls back cleanly to
        // exec_memop and finds the match on page 1 without failing on MEMOP_MAX_BYTES.
        g.pages[4].0[77] = b'Z';
        let tagged_start = before_page(1, 32) | (0x5a_u64 << 56);
        assert_eq!(
            call_checked(
                &mut g,
                &mut dbt,
                f_memchr,
                tagged_start,
                b'Z' as u64,
                u64::MAX
            ),
            (tagged_start + 32 + 77, 0)
        );
        // Cross-page strncmp with n = SIZE_MAX stops at NUL without failing on MEMOP_MAX_BYTES.
        g.pages[3].0[4096 - 32..].fill(b'm');
        g.pages[4].0[..100].fill(b'm');
        g.pages[6].0[4096 - 32..].fill(b'm');
        g.pages[5].0[..100].fill(b'm');
        g.pages[4].0[40] = 0;
        g.pages[5].0[40] = 0;
        assert_eq!(
            call_checked(
                &mut g,
                &mut dbt,
                f_strncmp,
                before_page(1, 32),
                before_page(3, 32),
                u64::MAX
            ),
            (0, 0)
        );

        // Read-only page 5: warm read TLB, ensure memset declines in-cache fast path (no write TLB)
        // and falls back to guest code with zero writes.
        let ro_page = DATA + 5 * PAGE_SIZE;
        g.pages[8].0[..64].fill(0x3c);
        let read_only = CODE + 0x30;
        g.code(read_only, &[0xf940_0003, SVC]); // ldr x3, [x0]; svc #0
        g.cpu.state_mut().x[0] = ro_page;
        g.run_at(&mut dbt, read_only);
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memset, ro_page, 0xee, 64).0,
            0x7777
        );
        assert!(g.pages[8].0[..64].iter().all(|&b| b == 0x3c));

        // Watchpoint on a previously warm page (after TLB flush): must decline fast path and fall
        // back to guest code for both 32..127 B and >= 128 B.
        g.cpu
            .state_mut()
            .set_hw_debug(&[], &[(DATA, DATA + 8, WATCH_STORE)]);
        g.cpu.tlb_flush();
        g.pages[3].0[..256].fill(0x22);
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memset, DATA, 0x99, 64).0,
            0x7777
        );
        assert_eq!(
            call_checked(&mut g, &mut dbt, f_memset, DATA, 0x99, 256).0,
            0x7777
        );
        assert!(g.pages[3].0[..256].iter().all(|&b| b == 0x22));
        g.cpu.state_mut().set_hw_debug(&[], &[]);
    }
}

#[test]
fn yield_is_emitted_verbatim_and_preserves_state() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::new();
        let f = CODE + 0x100;
        g.code(
            f,
            &[
                0xd503_201f, // nop (emits nothing)
                0xd503_203f, // yield (copied verbatim)
                SVC,
            ],
        );
        g.cpu.state_mut().x[0] = 0x1234_5678;
        g.cpu.state_mut().nzcv = 0x9000_0000;
        assert_eq!(g.run_at(&mut dbt, f), 0x1234_5678);
        assert_eq!(g.cpu.state().nzcv, 0x9000_0000);
        let st = dbt.stats();
        assert_eq!(st.insns_copied, 1, "{regs:?}");
        assert_eq!(st.exits_interp, 0, "{regs:?}");
    }
}

#[test]
fn long_blocks_run_past_64_insns_and_stop_on_host_budget() {
    let _pool = lock_pool();
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // 1. A 256-instruction block (255 ALU instructions + SVC) fits in a single block and
        //    reuses cleanly via the template cache in a second instance. Use the second code page
        //    so nogroup marks recorded by other tests in page CODE do not split the template key.
        let long_pc = CODE + PAGE_SIZE;
        let mut long_code = vec![0x9100_0400u32; 255]; // add x0, x0, #1
        long_code.push(SVC);
        g.code(long_pc, &long_code);
        g.cpu.state_mut().x[0] = 10;
        assert_eq!(g.run_at(&mut dbt, long_pc), 265, "{regs:?}");
        assert_eq!(dbt.stats().blocks, 1, "{regs:?}");
        assert_eq!(dbt.stats().insns, 256, "{regs:?}");

        // Second fresh instance hits the >64-insn template cleanly (testing lazy word snapshot).
        let mut dbt2 = Dbt::with_regs(regs).unwrap();
        g.cpu.state_mut().x[0] = 100;
        assert_eq!(g.run_at(&mut dbt2, long_pc), 355, "{regs:?}");
        assert_eq!(dbt2.stats().blocks, 1, "{regs:?}");
        assert_eq!(dbt2.stats().blocks_shared, 1, "{regs:?}");

        // 2. 256 heavy ungrouped exclusive instructions exceed MAX_BLOCK_WORDS / MAX_STUBS if not
        //    split by the host budget; must split cleanly without triggering a guard failure.
        let heavy_pc = CODE + PAGE_SIZE + 0x800;
        let mut heavy_code = Vec::with_capacity(256);
        for _ in 0..127 {
            heavy_code.push(0xc85f_7c41); // ldxr x1, [x2]
            heavy_code.push(0xc803_7c41); // stxr w3, x1, [x2]
        }
        heavy_code.push(0x9100_0400); // add x0, x0, #1
        heavy_code.push(SVC);
        g.code(heavy_pc, &heavy_code);
        g.cpu.state_mut().x[0] = 41;
        g.cpu.state_mut().x[2] = DATA;
        let before_blocks = dbt.stats().blocks;
        assert_eq!(g.run_at(&mut dbt, heavy_pc), 42, "{regs:?}");
        assert!(
            dbt.stats().blocks - before_blocks >= 2,
            "heavy block should split on host budget ({regs:?})"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");
    }
}

#[test]
fn eight_interleaved_groups_share_checks() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();
        let f = CODE + 0x100;
        // 8 distinct base registers (x1..x8), each accessed twice in interleaved order:
        // round 0: ldr x10, [xi, #0]; add x0, x0, x10
        // round 1: ldr x10, [xi, #8]; add x0, x0, x10
        let mut code = Vec::new();
        for off_idx in [0u32, 1u32] {
            for base in 1u32..=8 {
                code.push(0xf940_000a | (off_idx << 10) | (base << 5)); // ldr x10, [x{base}, #{off}]
                code.push(0x8b0a_0000); // add x0, x0, x10
            }
        }
        code.push(SVC);
        g.code(f, &code);

        let mut expected = 0u64;
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            for i in 0..8usize {
                s.x[i + 1] = DATA + (i * 16) as u64;
            }
        }
        for i in 0..8usize {
            expected = expected
                .wrapping_add(g.data(0, i * 16))
                .wrapping_add(g.data(0, i * 16 + 8));
        }
        assert_eq!(g.run_at(&mut dbt, f), expected, "{regs:?}");
        let st = dbt.stats();
        assert_eq!(st.insns_grouped, 8, "{regs:?}");
        assert_eq!(st.exits_interp, 0, "{regs:?}");
    }
}

#[test]
fn affine_aliases_group_before_and_after_leader() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // 1. Pre-leader SUB #8 from a stolen base (x28 in Default, x25 in Go):
        //    sub x20, xBase, #8; ldr x0, [x20]; ldr x1, [xBase, #0]; ldr x2, [xBase, #16]
        let base_reg: u32 = match regs {
            DbtRegs::Default => 28,
            DbtRegs::Go => 25,
        };
        let f1 = CODE + 0x200;
        g.code(
            f1,
            &[
                0xd100_2014 | (base_reg << 5), // sub x20, xBase, #8
                0xf940_0280,                   // ldr x0, [x20]
                0xf940_0001 | (base_reg << 5), // ldr x1, [xBase, #0]
                0xf940_0802 | (base_reg << 5), // ldr x2, [xBase, #16]
                SVC,
            ],
        );
        g.cpu.state_mut().x[base_reg as usize] = DATA + 0x40;
        let before = dbt.stats();
        g.run_at(&mut dbt, f1);
        let s = g.cpu.state();
        assert_eq!(s.x[0], g.data(0, 0x38), "{regs:?}");
        assert_eq!(s.x[1], g.data(0, 0x40), "{regs:?}");
        assert_eq!(s.x[2], g.data(0, 0x50), "{regs:?}");
        assert_eq!(
            dbt.stats().insns_grouped - before.insns_grouped,
            2,
            "{regs:?}"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");

        // 2. Pre-leader MOV X5, X2 + post-index LD1 on X5 + offset load on X2
        //    (matching ggml_gemv_q8_0_4x4_q8_0):
        let f2 = CODE + 0x280;
        g.code(
            f2,
            &[
                0xaa02_03e5, // mov x5, x2
                0x4cdf_70a0, // ld1 {v0.16b}, [x5], #16
                0x4c40_70a1, // ld1 {v1.16b}, [x5]
                0xf85f_8040, // ldur x0, [x2, #-8]
                SVC,
            ],
        );
        g.cpu.state_mut().x[2] = DATA + 0x80;
        let before = dbt.stats();
        g.run_at(&mut dbt, f2);
        let s = g.cpu.state();
        assert_eq!(s.x[0], g.data(0, 0x78), "{regs:?}");
        assert_eq!(s.x[2], DATA + 0x80, "{regs:?}");
        assert_eq!(s.x[5], DATA + 0x90, "{regs:?}");
        assert_eq!(s.v[0], [g.data(0, 0x80), g.data(0, 0x88)], "{regs:?}");
        assert_eq!(s.v[1], [g.data(0, 0x90), g.data(0, 0x98)], "{regs:?}");
        assert_eq!(
            dbt.stats().insns_grouped - before.insns_grouped,
            2,
            "{regs:?}"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");

        // 3. Mid-group MOV X5, X2 + ADD X6, X5, #16:
        let f3 = CODE + 0x300;
        g.code(
            f3,
            &[
                0xf85f_8040, // ldur x0, [x2, #-8]
                0xaa02_03e5, // mov x5, x2
                0x9100_40a6, // add x6, x5, #16
                0xf940_00a1, // ldr x1, [x5]
                0xf940_00c3, // ldr x3, [x6]
                SVC,
            ],
        );
        g.cpu.state_mut().x[2] = DATA + 0x100;
        let before = dbt.stats();
        g.run_at(&mut dbt, f3);
        let s = g.cpu.state();
        assert_eq!(s.x[0], g.data(0, 0xf8), "{regs:?}");
        assert_eq!(s.x[1], g.data(0, 0x100), "{regs:?}");
        assert_eq!(s.x[3], g.data(0, 0x110), "{regs:?}");
        assert_eq!(
            dbt.stats().insns_grouped - before.insns_grouped,
            2,
            "{regs:?}"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");

        // 4. Non-SP leader derived from misaligned SP must NOT suppress SP alignment fault on a
        //    later [sp] access.
        let f4 = CODE + 0x380;
        g.code(
            f4,
            &[
                0x9100_23e9, // add x9, sp, #8
                0xf940_0120, // ldr x0, [x9]
                0xf940_0521, // ldr x1, [x9, #8]
                0xf940_03e2, // ldr x2, [sp]
                SVC,
            ],
        );
        g.cpu.state_mut().sp = STACK - 24; // misaligned (mod 16 == 8)
        assert_eq!(
            go(&mut g, &mut dbt, f4),
            Exit::Fault {
                addr: STACK - 24,
                access: Access::Read,
                kind: FaultKind::StackAlignment,
            },
            "{regs:?}"
        );
        assert_eq!(g.cpu.state().pc, f4 + 12, "{regs:?}");
        g.cpu.state_mut().sp = STACK;

        // 5. Overlapping out-of-span alias (`add x3, x2, #1024`) must not collide across groups.
        let f5 = CODE + 0x400;
        g.code(
            f5,
            &[
                0xf940_0040, // ldr x0, [x2]
                0x9110_0043, // add x3, x2, #1024
                0xf940_0061, // ldr x1, [x3]
                0xf940_0464, // ldr x4, [x3, #8]
                0xf940_0445, // ldr x5, [x2, #8]
                SVC,
            ],
        );
        g.cpu.state_mut().x[2] = DATA + 0x20;
        g.run_at(&mut dbt, f5);
        let s = g.cpu.state();
        assert_eq!(s.x[0], g.data(0, 0x20), "{regs:?}");
        assert_eq!(s.x[1], g.data(0, 0x420), "{regs:?}");
        assert_eq!(s.x[4], g.data(0, 0x428), "{regs:?}");
        assert_eq!(s.x[5], g.data(0, 0x28), "{regs:?}");
    }
}

#[test]
fn stolen_base_and_mreg_accesses_group_correctly() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();
        let (stolen_a, stolen_b): (u32, u32) = match regs {
            DbtRegs::Default => (28, 16),
            DbtRegs::Go => (25, 21),
        };

        // 1. Stolen base with negative g->lo, post-index writeback, and TBI tag.
        let f1 = CODE + 0x500;
        g.code(
            f1,
            &[
                0xf85f_8000 | (stolen_a << 5), // ldur x0, [xStolen, #-8]
                0xf841_0401 | (stolen_a << 5), // ldr x1, [xStolen], #16
                0xf940_0002 | (stolen_a << 5), // ldr x2, [xStolen]
                SVC,
            ],
        );
        let tagged = (0xab_u64 << 56) | (DATA + 0x60);
        g.cpu.state_mut().x[stolen_a as usize] = tagged;
        let before = dbt.stats();
        g.run_at(&mut dbt, f1);
        let s = g.cpu.state();
        assert_eq!(s.x[0], g.data(0, 0x58), "{regs:?}");
        assert_eq!(s.x[1], g.data(0, 0x60), "{regs:?}");
        assert_eq!(s.x[2], g.data(0, 0x70), "{regs:?}");
        assert_eq!(s.x[stolen_a as usize], tagged + 16, "{regs:?}");
        assert_eq!(
            dbt.stats().insns_grouped - before.insns_grouped,
            2,
            "{regs:?}"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");

        // 2. M_REG grouping with stolen base + stolen index advancing via ADD #imm (LSL #3),
        //    plus a store back through the same M_REG address.
        let f2 = CODE + 0x580;
        g.code(
            f2,
            &[
                // ldr x0, [xStolenA, xStolenB, lsl #3]
                0xf860_7800 | (stolen_b << 16) | (stolen_a << 5),
                // add xStolenB, xStolenB, #1
                0x9100_0400 | (stolen_b << 5) | stolen_b,
                // ldr x1, [xStolenA, xStolenB, lsl #3]
                0xf860_7801 | (stolen_b << 16) | (stolen_a << 5),
                // str x3, [xStolenA, xStolenB, lsl #3]
                0xf820_7803 | (stolen_b << 16) | (stolen_a << 5),
                SVC,
            ],
        );
        let s = g.cpu.state_mut();
        s.x[stolen_a as usize] = DATA + 0x100;
        s.x[stolen_b as usize] = 2;
        s.x[3] = 0xdead_beef_cafe_babe;
        let expect0 = g.data(0, 0x110);
        let expect1 = g.data(0, 0x118);
        let before = dbt.stats();
        g.run_at(&mut dbt, f2);
        let s = g.cpu.state();
        assert_eq!(s.x[0], expect0, "{regs:?}");
        assert_eq!(s.x[1], expect1, "{regs:?}");
        assert_eq!(s.x[stolen_b as usize], 3, "{regs:?}");
        assert_eq!(g.data(0, 0x118), 0xdead_beef_cafe_babe, "{regs:?}");
        assert_eq!(
            dbt.stats().insns_grouped - before.insns_grouped,
            2,
            "{regs:?}"
        );
        assert_eq!(dbt.stats().exits_interp, 0, "{regs:?}");

        // 3. M_REG with UXTW (option=2) must NOT treat `add xIndex, xIndex, #1` as +8 across a
        //    32-bit wrap: start at x3 = 0xffff_ffff with base chosen so the first load hits
        //    DATA + 0x200, and after add x3, #1 the wrapped w3 == 0 loads from unmapped base_uxtw.
        let f3 = CODE + 0x600;
        g.code(
            f3,
            &[
                0xf863_5840, // ldr x0, [x2, w3, uxtw #3]
                0x9100_0463, // add x3, x3, #1
                0xf863_5841, // ldr x1, [x2, w3, uxtw #3]
                SVC,
            ],
        );
        let s = g.cpu.state_mut();
        let base_uxtw = (DATA + 0x200).wrapping_sub(0xffff_ffffu64 << 3);
        s.x[2] = base_uxtw;
        s.x[3] = 0xffff_ffff;
        assert!(matches!(
            go(&mut g, &mut dbt, f3),
            Exit::Fault {
                access: Access::Read,
                kind: FaultKind::Page,
                ..
            }
        ));
        assert_eq!(g.cpu.state().pc, f3 + 8, "{regs:?}");
        assert_eq!(g.cpu.state().x[0], g.data(0, 0x200), "{regs:?}");
    }
}

#[test]
fn fast_loop_accelerates_canonical_strided_loops() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // 1. Loop 1 shape (ggml_vec_dot_f16): 2 pointers += 64, cmp x6, x2; b.ne across two
        //    adjacent pages (DATA + 0x40 .. DATA + 0x1840 = 96 iterations, crossing page 0 -> 1).
        let f1 = CODE + 0x700;
        g.code(
            f1,
            &[
                0xad40_5854,            // ldp q20, q22, [x2]
                0xad40_5c95,            // ldp q21, q23, [x4]
                0xad41_6858,            // ldp q24, q26, [x2, #32]
                0x9101_0042,            // add x2, x2, #0x40
                0xad41_6c99,            // ldp q25, q27, [x4, #32]
                0x9101_0084,            // add x4, x4, #0x40
                0x4ef5_87bd,            // add v29.2d, v29.2d, v21.2d
                0x4ef4_87bd,            // add v29.2d, v29.2d, v20.2d
                0x4ef8_87bd,            // add v29.2d, v29.2d, v24.2d
                0x4ef9_87bd,            // add v29.2d, v29.2d, v25.2d
                0xeb02_00df,            // cmp x6, x2
                b_cond(f1 + 44, f1, 1), // b.ne f1
                SVC,
            ],
        );
        let n1 = 96usize;
        let off1 = 0x40usize;
        {
            let s = g.cpu.state_mut();
            s.x[2] = DATA + off1 as u64;
            s.x[4] = DATA + off1 as u64;
            s.x[6] = DATA + (off1 + n1 * 64) as u64;
            s.v[29] = [0, 0];
            s.nzcv = 0x8000_0000;
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f1);
        let mut exp_v29 = [0u64; 2];
        for iter in 0..n1 {
            let base = off1 + iter * 64;
            for delta in [0usize, 32] {
                let addr = base + delta;
                let lo = g.data(addr / 4096, addr % 4096);
                let hi = g.data((addr + 8) / 4096, (addr + 8) % 4096);
                exp_v29[0] = exp_v29[0].wrapping_add(lo).wrapping_add(lo);
                exp_v29[1] = exp_v29[1].wrapping_add(hi).wrapping_add(hi);
            }
        }
        let s = g.cpu.state();
        assert_eq!(s.v[29], exp_v29, "{regs:?}");
        assert_eq!(s.x[2], DATA + (off1 + n1 * 64) as u64, "{regs:?}");
        assert_eq!(s.x[4], DATA + (off1 + n1 * 64) as u64, "{regs:?}");
        assert_eq!(s.nzcv, 0x6000_0000, "{regs:?}"); // cmp equal: Z=1, C=1
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        assert_eq!(dbt.stats().exits_interp, before.exits_interp, "{regs:?}");

        // 2. Loop 2 shape (ggml_gemv_q4_0): non-pow2 post-index strides (+34, +72), 32-bit signed
        //    counter starting negative (w5 = -5 -> w6 = 95, 100 iters across pages 0 -> 1).
        let f2 = CODE + 0x760;
        g.code(
            f2,
            &[
                0x3cc0_2057,             // ldur q23, [x2, #2]
                0x1100_04a5,             // add w5, w5, #1
                0x3cc1_2056,             // ldur q22, [x2, #18]
                0x7c42_2459,             // ldr h25, [x2], #34
                0x3cc0_801c,             // ldur q28, [x0, #8]
                0xfc44_8418,             // ldr d24, [x0], #72
                0x4ef7_879d,             // add v29.2d, v28.2d, v23.2d
                0x4ef6_87bd,             // add v29.2d, v29.2d, v22.2d
                0x4efd_87de,             // add v30.2d, v30.2d, v29.2d
                0x6b05_00df,             // cmp w6, w5
                b_cond(f2 + 40, f2, 12), // b.gt f2
                SVC,
            ],
        );
        let n2 = 100usize;
        {
            let s = g.cpu.state_mut();
            s.x[0] = DATA + 16;
            s.x[2] = DATA + 32;
            s.x[5] = (-5i32) as u32 as u64;
            s.x[6] = 95;
            s.v[30] = [0, 0];
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f2);
        let read_u64 = |off: usize| -> u64 {
            let mut b = [0u8; 8];
            for k in 0..8 {
                let p = (off + k) / 4096;
                let host = [3, 4, 6, 5, 7, 8][p];
                b[k] = g.pages[host].0[(off + k) % 4096];
            }
            u64::from_le_bytes(b)
        };
        let mut exp_v30 = [0u64; 2];
        for iter in 0..n2 {
            let p0 = 16 + iter * 72;
            let p2 = 32 + iter * 34;
            for (lane, acc) in exp_v30.iter_mut().enumerate() {
                let a = read_u64(p0 + 8 + lane * 8);
                let b = read_u64(p2 + 2 + lane * 8);
                let c = read_u64(p2 + 18 + lane * 8);
                *acc = acc.wrapping_add(a).wrapping_add(b).wrapping_add(c);
            }
        }
        let s = g.cpu.state();
        assert_eq!(s.v[30], exp_v30, "{regs:?}");
        assert_eq!(s.x[0], DATA + 16 + (n2 * 72) as u64, "{regs:?}");
        assert_eq!(s.x[2], DATA + 32 + (n2 * 34) as u64, "{regs:?}");
        assert_eq!(s.x[5], 95, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        assert_eq!(dbt.stats().exits_interp, before.exits_interp, "{regs:?}");

        // 3. Loop 3 shape (ggml_gemv_q8_0): negative offsets [-2]/[-8], derived alias mov x5, x2
        //    with post-index ld1 [x5], #64 and ld1 [x5], verifying exact restored guest x5!
        let f3 = CODE + 0x7c0;
        g.code(
            f3,
            &[
                0x7c5f_e000,             // ldur h0, [x0, #-2]
                0xaa02_03e5,             // mov x5, x2
                0xfc5f_8053,             // ldur d19, [x2, #-8]
                0x1100_04c6,             // add w6, w6, #1
                0x9102_2042,             // add x2, x2, #0x88
                0x4cdf_20bc,             // ld1 {v28.16b-v31.16b}, [x5], #64
                0x4c40_a016,             // ld1 {v22.16b-v23.16b}, [x0]
                0x9100_8800,             // add x0, x0, #0x22
                0x4c40_20b8,             // ld1 {v24.16b-v27.16b}, [x5]
                0x4efc_86d4,             // add v20.2d, v22.2d, v28.2d
                0x4ef8_8694,             // add v20.2d, v20.2d, v24.2d
                0x4ef4_86b5,             // add v21.2d, v21.2d, v20.2d
                0x6b06_00ff,             // cmp w7, w6
                b_cond(f3 + 52, f3, 12), // b.gt f3
                SVC,
            ],
        );
        let n3 = 50usize;
        {
            let s = g.cpu.state_mut();
            s.x[0] = DATA + 16;
            s.x[2] = DATA + 16;
            s.x[5] = 0;
            s.x[6] = 0;
            s.x[7] = n3 as u64;
            s.v[21] = [0, 0];
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f3);
        let s = g.cpu.state();
        assert_eq!(s.x[0], DATA + 16 + (n3 * 0x22) as u64, "{regs:?}");
        assert_eq!(s.x[2], DATA + 16 + (n3 * 0x88) as u64, "{regs:?}");
        assert_eq!(
            s.x[5],
            DATA + 16 + ((n3 - 1) * 0x88 + 64) as u64,
            "{regs:?}"
        );
        assert_eq!(s.x[6], n3 as u64, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        assert_eq!(dbt.stats().exits_interp, before.exits_interp, "{regs:?}");

        // 4. Loop 4 shape (ggml_gemm_q4_0): 5 pointers including stolen base (x28 in Default, x25
        //    in Go), derived alias sub x20, xBase, #8, mid-body subs x24, x24, #1 + b.gt.
        let base_s: u32 = match regs {
            DbtRegs::Default => 28,
            DbtRegs::Go => 25,
        };
        let f4 = CODE + 0x820;
        g.code(
            f4,
            &[
                0x3dc0_0003 | (base_s << 5),          // ldr q3, [xBase]
                0x3dc0_029f,                          // ldr q31, [x20] -- wait: set x20 first below
                0xd100_2014 | (base_s << 5),          // sub x20, xBase, #8
                0xfd40_0291,                          // ldr d17, [x20]
                0xf100_0718,                          // subs x24, x24, #1
                0x9101_2000 | (base_s << 5) | base_s, // add xBase, xBase, #0x48
                0x3dc0_02a4,                          // ldr q4, [x21]
                0x9102_22b5,                          // add x21, x21, #0x88
                0x3dc0_02c5,                          // ldr q5, [x22]
                0x9102_22d6,                          // add x22, x22, #0x88
                0x3dc0_02e6,                          // ldr q6, [x23]
                0x9102_22f7,                          // add x23, x23, #0x88
                0x3dc0_0127,                          // ldr q7, [x9]
                0x9102_2129,                          // add x9, x9, #0x88
                0x4ee3_8484,                          // add v4.2d, v4.2d, v3.2d
                0x4ee5_8484,                          // add v4.2d, v4.2d, v5.2d
                0x4ee6_8484,                          // add v4.2d, v4.2d, v6.2d
                0x4ee7_8484,                          // add v4.2d, v4.2d, v7.2d
                0x4ee4_8508,                          // add v8.2d, v8.2d, v4.2d
                b_cond(f4 + 76, f4, 12),              // b.gt f4
                SVC,
            ],
        );
        // Replace slot 1 with NOP (0xd503201f) so x20 is written before read!
        g.code(f4 + 4, &[0xd503_201f]);
        let n4 = 40usize;
        {
            let s = g.cpu.state_mut();
            s.x[base_s as usize] = DATA + 16;
            s.x[21] = DATA + 32;
            s.x[22] = DATA + 48;
            s.x[23] = DATA + 64;
            s.x[9] = DATA + 80;
            s.x[24] = n4 as u64;
            s.v[8] = [0, 0];
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f4);
        let s = g.cpu.state();
        assert_eq!(
            s.x[base_s as usize],
            DATA + 16 + (n4 * 0x48) as u64,
            "{regs:?}"
        );
        assert_eq!(
            s.x[20],
            DATA + 16 + ((n4 - 1) * 0x48) as u64 - 8,
            "{regs:?}"
        );
        assert_eq!(s.x[21], DATA + 32 + (n4 * 0x88) as u64, "{regs:?}");
        assert_eq!(s.x[24], 0, "{regs:?}");
        assert_eq!(s.nzcv, 0x6000_0000, "{regs:?}"); // subs 1 - 1 -> Z=1, C=1
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        assert_eq!(dbt.stats().exits_interp, before.exits_interp, "{regs:?}");

        // 5. Write loop with overlapping src/dst on the same page + CBNZ countdown.
        let f5 = CODE + 0x8a0;
        g.code(
            f5,
            &[
                0xf840_842a,            // ldr x10, [x1], #8
                0x9100_054a,            // add x10, x10, #1
                0xf800_844a,            // str x10, [x2], #8
                0xd100_0463,            // sub x3, x3, #1
                cbnz_x(f5 + 16, f5, 3), // cbnz x3, f5
                SVC,
            ],
        );
        // Copy 32 u64s from DATA+0x100 to DATA+0x108 (overlapping forward shift by 8 bytes:
        // every element propagates the first word + iter!).
        let init_word = g.data(0, 0x100);
        {
            let s = g.cpu.state_mut();
            s.x[1] = DATA + 0x100;
            s.x[2] = DATA + 0x108;
            s.x[3] = 32;
            s.nzcv = 0x9000_0000;
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f5);
        for k in 1..=32usize {
            assert_eq!(
                g.data(0, 0x100 + k * 8),
                init_word.wrapping_add(k as u64),
                "overlap iter {k} ({regs:?})"
            );
        }
        // CBNZ loop does not touch NZCV at all.
        assert_eq!(g.cpu.state().nzcv, 0x9000_0000, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // 6. Immediate compare (cmp x4, #60; b.lo) with non-power-of-2 counter step (+3).
        let f6 = CODE + 0x8e0;
        g.code(
            f6,
            &[
                0xf840_842a,            // ldr x10, [x1], #8
                0x8b0a_0000,            // add x0, x0, x10
                0x9100_0c84,            // add x4, x4, #3
                0xf100_f09f,            // cmp x4, #60
                b_cond(f6 + 16, f6, 3), // b.lo f6
                SVC,
            ],
        );
        let mut exp6 = 0u64;
        for k in 0..20usize {
            exp6 = exp6.wrapping_add(g.data(0, 0x400 + k * 8));
        }
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA + 0x400;
            s.x[4] = 0;
        }
        let before = dbt.stats();
        assert_eq!(g.run_at(&mut dbt, f6), exp6, "{regs:?}");
        assert_eq!(g.cpu.state().x[4], 60, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
    }
}

#[test]
fn fast_loop_preserves_exact_faults_tbi_watchpoints_and_kicks() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // 1. Precise fault when a fast-loop write crosses from RW page 4 into RO page 5, with a
        //    derived alias x5 that must hold the exact guest address at the faulting PC!
        let f1 = CODE + 0x920;
        g.code(
            f1,
            &[
                0xaa02_03e5,            // mov x5, x2
                0xf840_842a,            // ldr x10, [x1], #8
                0xf900_00aa,            // str x10, [x5]
                0x9100_2042,            // add x2, x2, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f1 + 20, f1, 1), // b.ne f1
                SVC,
            ],
        );
        // Start 10 u64s before end of RW page 4, try to write 16 u64s -> 10 succeed, 11th faults
        // on RO page 5 at `str x10, [x5]` (f1 + 8).
        let start_dst = DATA + 5 * PAGE_SIZE - 80;
        {
            let s = g.cpu.state_mut();
            s.x[1] = DATA + 0x100;
            s.x[2] = start_dst;
            s.x[3] = 16;
            s.x[5] = 0;
        }
        let before = dbt.stats();
        assert_eq!(
            go(&mut g, &mut dbt, f1),
            Exit::Fault {
                addr: DATA + 5 * PAGE_SIZE,
                access: Access::Write,
                kind: FaultKind::Page,
            },
            "{regs:?}"
        );
        let s = g.cpu.state();
        assert_eq!(s.pc, f1 + 8, "{regs:?}");
        assert_eq!(s.x[2], DATA + 5 * PAGE_SIZE, "{regs:?}");
        assert_eq!(
            s.x[5],
            DATA + 5 * PAGE_SIZE,
            "alias must be guest VA ({regs:?})"
        );
        assert_eq!(s.x[3], 6, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // 2. Scattered host pages (DATA + 2*PAGE_SIZE -> DATA + 3*PAGE_SIZE are mapped in reverse
        //    host order!) + TBI tag (0xab << 56) + negative offset [-8].
        let f2 = CODE + 0x960;
        g.code(
            f2,
            &[
                0xaa02_03e5,            // mov x5, x2
                0xf85f_804a,            // ldur x10, [x2, #-8]
                0xf940_00ab,            // ldr x11, [x5]
                0x8b0a_0000,            // add x0, x0, x10
                0x8b0b_0000,            // add x0, x0, x11
                0x9100_2042,            // add x2, x2, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f2 + 28, f2, 1), // b.ne f2
                SVC,
            ],
        );
        let tag = 0xab_u64 << 56;
        let base_va = DATA + 3 * PAGE_SIZE - 64; // 8 u64s in page 2, then 8 u64s in page 3
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = tag | base_va;
            s.x[3] = 16;
            s.x[5] = 0;
        }
        let mut exp2 = 0u64;
        for k in 0..16usize {
            let a1 = (base_va + (k * 8) as u64 - 8) - DATA;
            let a2 = (base_va + (k * 8) as u64) - DATA;
            exp2 = exp2
                .wrapping_add(g.data((a1 / 4096) as usize, (a1 % 4096) as usize))
                .wrapping_add(g.data((a2 / 4096) as usize, (a2 % 4096) as usize));
        }
        assert_eq!(g.run_at(&mut dbt, f2), exp2, "{regs:?}");
        assert_eq!(g.cpu.state().x[2], tag | (base_va + 128), "{regs:?}");
        assert_eq!(g.cpu.state().x[5], tag | (base_va + 120), "{regs:?}");

        // 3. Hardware watchpoint inside a warmed page must NOT be bypassed by the fast loop.
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = DATA + 0x200;
            s.x[3] = 20;
        }
        g.run_at(&mut dbt, f2); // warm TLB for page 0
        g.cpu.tlb_flush();
        g.cpu
            .state_mut()
            .set_hw_debug(&[], &[(DATA + 0x240, DATA + 0x248, WATCH_LOAD)]);
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = DATA + 0x200;
            s.x[3] = 20;
        }
        assert_eq!(
            go(&mut g, &mut dbt, f2),
            Exit::Fault {
                addr: DATA + 0x240,
                access: Access::Read,
                kind: FaultKind::Watchpoint,
            },
            "{regs:?}"
        );
        g.cpu.state_mut().set_hw_debug(&[], &[]);
        g.cpu.tlb_flush();

        // 4. Boundary counter edge cases (cnt = 1, signed/unsigned B <= C, non-multiple B.NE,
        //    and NZCV preservation when fast loop bails).
        let f4 = CODE + 0x9c0;
        g.code(
            f4,
            &[
                0xf840_842a,            // ldr x10, [x1], #8
                0x8b0a_0000,            // add x0, x0, x10
                0xeb01_00df,            // cmp x6, x1
                b_cond(f4 + 12, f4, 1), // b.ne f4
                SVC,
            ],
        );
        // Single iteration (diff == 8 -> rem_backedges == 0 -> bails cleanly to slow loop).
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA + 0x100;
            s.x[6] = DATA + 0x108;
        }
        assert_eq!(g.run_at(&mut dbt, f4), g.data(0, 0x100), "{regs:?}");

        // 64-bit signed compare with INT64_MIN / negative counters (`cmp x6, x4; b.gt`).
        let f5 = CODE + 0x9e0;
        g.code(
            f5,
            &[
                0xf840_842a,             // ldr x10, [x1], #8
                0x8b0a_0000,             // add x0, x0, x10
                0x9100_0484,             // add x4, x4, #1
                0xeb04_00df,             // cmp x6, x4
                b_cond(f5 + 16, f5, 12), // b.gt f5
                SVC,
            ],
        );
        // x4 = 10, x6 = -1 (signed B < C -> 1 iteration only, must not enter fast loop).
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA + 0x100;
            s.x[4] = 10;
            s.x[6] = u64::MAX;
        }
        assert_eq!(g.run_at(&mut dbt, f5), g.data(0, 0x100), "{regs:?}");
        assert_eq!(g.cpu.state().x[4], 11, "{regs:?}");
        // x4 = -3, x6 = 5 (signed B > C crossing 0 -> 8 iterations).
        let mut exp5 = 0u64;
        for k in 0..8usize {
            exp5 = exp5.wrapping_add(g.data(0, 0x100 + k * 8));
        }
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA + 0x100;
            s.x[4] = (-3i64) as u64;
            s.x[6] = 5;
        }
        assert_eq!(g.run_at(&mut dbt, f5), exp5, "{regs:?}");
        assert_eq!(g.cpu.state().x[4], 5, "{regs:?}");

        // 5. Kick responsiveness: a long-running fast loop exits with Exit::Kick promptly.
        let f6 = CODE + 0xa20;
        g.code(
            f6,
            &[
                0xf940_002a, // ldr x10, [x1]   (stride 0)
                0xf840_844b, // ldr x11, [x2], #8 (would cross if unbounded, reset via sub)
                0xd100_2042, // sub x2, x2, #8  -- net stride 0
                SVC,
            ],
        );
        // Use a real strided loop over page 0 (500 iters) with kick set before entry & from thread.
        let _ = f6;
        let f_kick = CODE + 0xa40;
        g.code(
            f_kick,
            &[
                0xf940_002a,                    // ldr x10, [x1]
                0xf940_004b,                    // ldr x11, [x2]
                0x9100_0442,                    // add x2, x2, #1
                0xf100_0463,                    // subs x3, x3, #1
                b_cond(f_kick + 16, f_kick, 1), // b.ne f_kick
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[1] = DATA;
            s.x[2] = DATA;
            s.x[3] = 3000;
        }
        let kicker = g.cpu.kicker();
        unsafe { kicker.kick() };
        assert_eq!(go(&mut g, &mut dbt, f_kick), Exit::Kick, "{regs:?}");
    }
}

#[test]
fn fast_loop_rejects_unsafe_patterns() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // 1. Pointer opacity violation: storing an induction pointer's numeric value to memory.
        let f1 = CODE + 0xa80;
        g.code(
            f1,
            &[
                0xf940_004a,            // ldr x10, [x2]  (x2 is an induction pointer)
                0xf900_0082,            // str x2, [x4]   (stores x2's address value!)
                0x9100_2042,            // add x2, x2, #8
                0x9100_2084,            // add x4, x4, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f1 + 20, f1, 1), // b.ne f1
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[2] = DATA + 0x100;
            s.x[4] = DATA + 0x200;
            s.x[3] = 8;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f1);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "pointer store must not fast-loop ({regs:?})"
        );
        assert_eq!(g.data(0, 0x200), DATA + 0x100, "{regs:?}");
        assert_eq!(g.data(0, 0x208), DATA + 0x108, "{regs:?}");

        // 2. Read-before-write cross-iteration alias: `add x0, x0, x5` before `mov x5, x2`.
        let f2 = CODE + 0xac0;
        g.code(
            f2,
            &[
                0x8b05_0000,            // add x0, x0, x5
                0xaa02_03e5,            // mov x5, x2
                0xf940_00aa,            // ldr x10, [x5]
                0x9100_2042,            // add x2, x2, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f2 + 20, f2, 1), // b.ne f2
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = DATA + 0x100;
            s.x[5] = 7;
            s.x[3] = 4;
        }
        let before = dbt.stats().fast_loops;
        let expected = 7 + (DATA + 0x100) + (DATA + 0x108) + (DATA + 0x110);
        assert_eq!(g.run_at(&mut dbt, f2), expected, "{regs:?}");
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "RBW alias must not fast-loop ({regs:?})"
        );

        // 3. Atomic load inside loop must be rejected.
        let f3 = CODE + 0xb00;
        g.code(
            f3,
            &[
                0xc8df_fc4a,            // ldar x10, [x2]
                0x9100_2042,            // add x2, x2, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f3 + 12, f3, 1), // b.ne f3
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[2] = DATA + 0x100;
            s.x[3] = 4;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f3);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "atomic loop must not fast-loop ({regs:?})"
        );

        // 4. SP-based loop must be rejected.
        let f4 = CODE + 0xb40;
        g.code(
            f4,
            &[
                0xf841_07ea,            // ldr x10, [sp], #16
                0x8b0a_0000,            // add x0, x0, x10
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f4 + 12, f4, 1), // b.ne f4
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.sp = STACK - 128;
            s.x[3] = 4;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f4);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "SP loop must not fast-loop ({regs:?})"
        );
        g.cpu.state_mut().sp = STACK;

        // 5. M_REG with UXTW (option=2) and advancing index must be rejected (32-bit wrap hazard).
        let f5 = CODE + 0xb80;
        g.code(
            f5,
            &[
                0xf866_582a,            // ldr x10, [x1, w6, uxtw #3]
                0x8b0a_0000,            // add x0, x0, x10
                0x9100_04c6,            // add x6, x6, #1
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f5 + 16, f5, 1), // b.ne f5
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[6] = 0;
            s.x[3] = 8;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f5);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "UXTW induction index must be rejected ({regs:?})"
        );

        // 6. M_REG with 32-bit index update (add w6, w6, #1) must be rejected (clears upper 32 bits).
        let f6 = CODE + 0xbc0;
        g.code(
            f6,
            &[
                0xf866_782a,            // ldr x10, [x1, x6, lsl #3]
                0x8b0a_0000,            // add x0, x0, x10
                0x1100_04c6,            // add w6, w6, #1
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f6 + 16, f6, 1), // b.ne f6
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[6] = 0;
            s.x[3] = 8;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f6);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "32-bit index add must be rejected ({regs:?})"
        );

        // 7. M_REG with rn == rm must be rejected (shifting rn would double-shift the address).
        let f7 = CODE + 0xc00;
        g.code(
            f7,
            &[
                0xf862_684a,            // ldr x10, [x2, x2]
                0x9100_2042,            // add x2, x2, #8
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f7 + 12, f7, 1), // b.ne f7
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[2] = DATA / 2;
            s.x[3] = 4;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f7);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "rn==rm M_REG must be rejected ({regs:?})"
        );

        // 8. Loop-local NZCV read-before-write (cset before any flag writer) must be rejected.
        let f8 = CODE + 0xc40;
        g.code(
            f8,
            &[
                0xf840_842a,            // ldr x10, [x1], #8
                0x1a9f_47e7,            // cset w7, pl  (reads pre-loop/prev-iter NZCV!)
                0x8b07_0000,            // add x0, x0, x7
                0xeb04_003f,            // cmp x1, x4
                b_cond(f8 + 16, f8, 1), // b.ne f8
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[4] = DATA + 64;
            s.nzcv = 0x8000_0000; // N=1 (pl is false on iter 0, then true after cmp x1, x4!)
        }
        let before = dbt.stats().fast_loops;
        let res8 = g.run_at(&mut dbt, f8);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "RBW NZCV must be rejected ({regs:?})"
        );
        assert_eq!(res8, 0, "{regs:?}"); // N=1 before loop and N=1 on every cmp x1 < x4

        // 9. Inner CMP comparing a shifted pointer must be rejected (pointer opacity).
        let f9 = CODE + 0xc80;
        g.code(
            f9,
            &[
                0xf840_842a,            // ldr x10, [x1], #8
                0xeb05_003f,            // cmp x1, x5  (reads shifted x1!)
                0x1a9f_17e7,            // cset w7, eq
                0x8b07_0000,            // add x0, x0, x7
                0xf100_0463,            // subs x3, x3, #1
                b_cond(f9 + 20, f9, 1), // b.ne f9
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[5] = DATA + 32;
            s.x[3] = 8;
        }
        let before = dbt.stats().fast_loops;
        assert_eq!(g.run_at(&mut dbt, f9), 1, "{regs:?}");
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "inner CMP on shifted ptr must be rejected ({regs:?})"
        );

        // 10. Register-stride pointer with non-invariant stride register must be rejected.
        let f10 = CODE + 0xcc0;
        g.code(
            f10,
            &[
                0xf940_008a,              // ldr x10, [x4]
                0x8b09_0084,              // add x4, x4, x9
                0x9100_2129,              // add x9, x9, #8 (mutates stride reg!)
                0x8b0a_0000,              // add x0, x0, x10
                0xf100_0463,              // subs x3, x3, #1
                b_cond(f10 + 20, f10, 1), // b.ne f10
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[4] = DATA;
            s.x[9] = 8;
            s.x[3] = 6;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f10);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "non-invariant stride reg must be rejected ({regs:?})"
        );

        // 11. Register-stride pointer accessed AFTER `add x4, x4, x9` must be rejected.
        let f11 = CODE + 0xd00;
        g.code(
            f11,
            &[
                0x8b09_0084,              // add x4, x4, x9
                0xf940_008a,              // ldr x10, [x4]
                0x8b0a_0000,              // add x0, x0, x10
                0xf100_0463,              // subs x3, x3, #1
                b_cond(f11 + 16, f11, 1), // b.ne f11
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[4] = DATA;
            s.x[9] = 8;
            s.x[3] = 6;
        }
        let before = dbt.stats().fast_loops;
        g.run_at(&mut dbt, f11);
        assert_eq!(
            dbt.stats().fast_loops,
            before,
            "access after reg-stride add must be rejected ({regs:?})"
        );
    }
}

#[test]
fn fast_loop_flash_attn_mreg_regstride_and_nzcv() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // Populate data pages 0..4 with finite floats (1.0 + idx * 0.25) and page 0..1 with
        // small f16 values for exact float/NZCV verification.
        for p in 0..5usize {
            let host = [3, 4, 6, 5, 7][p];
            for k in 0..1024usize {
                let f = ((p * 1024 + k) % 64) as f32 * 0.25 - 4.0;
                g.pages[host].0[k * 4..k * 4 + 4].copy_from_slice(&f.to_le_bytes());
            }
        }
        let read_f32 = |g: &Guest, addr: u64| -> f32 {
            let off = (addr - DATA) as usize;
            let host = [3, 4, 6, 5, 7, 8][off / 4096];
            let p = off % 4096;
            f32::from_le_bytes(g.pages[host].0[p..p + 4].try_into().unwrap())
        };

        // 1. Loop 0x6f260 shape: induction base x2 with both plain [x2] and M_REG [x2, x28, lsl #2]
        //    (x28 is stolen in Default!), plus stolen post-index ldp [x17], #256.
        let f1 = CODE + 0xd60;
        g.code(
            f1,
            &[
                0xacc8_7e3c,            // ldp q28, q31, [x17], #256
                0xbc7c_7857,            // ldr s23, [x2, x28, lsl #2]
                0x4d40_c85d,            // ld1r {v29.4s}, [x2]
                0x9100_1042,            // add x2, x2, #4
                0x4f97_139b,            // fmla v27.4s, v28.4s, v23.s[0]
                0x4e3d_cf99,            // fmla v25.4s, v28.4s, v29.4s
                0x4e3d_cff8,            // fmla v24.4s, v31.4s, v29.4s
                0x4f97_13fa,            // fmla v26.4s, v31.4s, v23.s[0]
                0xeb03_005f,            // cmp x2, x3
                b_cond(f1 + 36, f1, 1), // b.ne f1
                SVC,
            ],
        );
        // 1a. Contiguous host pages (page 0 + page 1 share addend): x28 = 1024 floats (4096 B) ->
        //     [x2] is on page 0 and [x2, x28, lsl #2] is on page 1 with the SAME addend!
        let run_f1 =
            |g: &mut Guest, dbt: &mut Dbt, x2_start: u64, x28_floats: u64, n: usize| -> [f32; 4] {
                let s = g.cpu.state_mut();
                s.x[17] = DATA;
                s.x[2] = x2_start;
                s.x[3] = x2_start + (n * 4) as u64;
                s.x[28] = x28_floats;
                for v in [24usize, 25, 26, 27] {
                    s.v[v] = [0, 0];
                }
                g.run_at(dbt, f1);
                let s = g.cpu.state();
                assert_eq!(s.x[2], x2_start + (n * 4) as u64);
                assert_eq!(s.x[17], DATA + (n * 256) as u64);
                assert_eq!(s.nzcv, 0x6000_0000);
                let lo = s.v[27][0].to_le_bytes();
                let hi = s.v[27][1].to_le_bytes();
                [
                    f32::from_le_bytes(lo[0..4].try_into().unwrap()),
                    f32::from_le_bytes(lo[4..8].try_into().unwrap()),
                    f32::from_le_bytes(hi[0..4].try_into().unwrap()),
                    f32::from_le_bytes(hi[4..8].try_into().unwrap()),
                ]
            };
        let exp_f1 = |g: &Guest, x2_start: u64, x28_floats: u64, n: usize| -> [f32; 4] {
            let mut acc = [0.0f32; 4];
            for k in 0..n {
                let s23 = read_f32(g, x2_start + (k * 4) as u64 + x28_floats * 4);
                for (lane, slot) in acc.iter_mut().enumerate() {
                    let v28 = read_f32(g, DATA + (k * 256 + lane * 4) as u64);
                    *slot = v28.mul_add(s23, *slot);
                }
            }
            acc
        };
        let before = dbt.stats();
        let got_same = run_f1(&mut g, &mut dbt, DATA + 0x100, 1024, 24);
        assert_eq!(
            got_same,
            exp_f1(&g, DATA + 0x100, 1024, 24),
            "same-addend M_REG ({regs:?})"
        );
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        assert_eq!(dbt.stats().exits_interp, before.exits_interp, "{regs:?}");

        // 1b. Scattered non-contiguous host pages (page 2 -> page 3 have DIFFERENT host addends!):
        //     prologue addend-equality check must bail cleanly and produce the exact same result!
        let got_diff = run_f1(&mut g, &mut dbt, DATA + 2 * PAGE_SIZE + 0x100, 1024, 24);
        assert_eq!(
            got_diff,
            exp_f1(&g, DATA + 2 * PAGE_SIZE + 0x100, 1024, 24),
            "mismatched-addend M_REG must bail cleanly ({regs:?})"
        );

        // 2. Loop 0x6f5a0 shape: loop-invariant register stride `add x4, x4, x26` (stolen in Default!).
        let f2 = CODE + 0xda0;
        g.code(
            f2,
            &[
                0xad40_7c9c,            // ldp q28, q31, [x4]
                0x8b1a_0084,            // add x4, x4, x26
                0xbd41_0037,            // ldr s23, [x1, #256]
                0x4d40_c83d,            // ld1r {v29.4s}, [x1]
                0x9100_1021,            // add x1, x1, #4
                0x4f97_139b,            // fmla v27.4s, v28.4s, v23.s[0]
                0x4e3d_cf99,            // fmla v25.4s, v28.4s, v29.4s
                0x4e3d_cff8,            // fmla v24.4s, v31.4s, v29.4s
                0x4f97_13fa,            // fmla v26.4s, v31.4s, v23.s[0]
                0xeb14_003f,            // cmp x1, x20
                b_cond(f2 + 40, f2, 1), // b.ne f2
                SVC,
            ],
        );
        let run_f2 = |g: &mut Guest, dbt: &mut Dbt, x4_start: u64, stride: u64, n: usize| -> f32 {
            let s = g.cpu.state_mut();
            s.x[4] = x4_start;
            s.x[26] = stride;
            s.x[1] = DATA;
            s.x[20] = DATA + (n * 4) as u64;
            for v in [24usize, 25, 26, 27] {
                s.v[v] = [0, 0];
            }
            g.run_at(dbt, f2);
            let s = g.cpu.state();
            assert_eq!(s.x[1], DATA + (n * 4) as u64);
            assert_eq!(s.x[4], x4_start.wrapping_add(stride.wrapping_mul(n as u64)));
            f32::from_le_bytes(s.v[27][0].to_le_bytes()[0..4].try_into().unwrap())
        };
        let exp_f2 = |g: &Guest, x4_start: u64, stride: u64, n: usize| -> f32 {
            let mut acc = 0.0f32;
            for k in 0..n {
                let s23 = read_f32(g, DATA + 256 + (k * 4) as u64);
                let v28 = read_f32(g, x4_start.wrapping_add(stride.wrapping_mul(k as u64)));
                acc = v28.mul_add(s23, acc);
            }
            acc
        };
        let before = dbt.stats();
        // 2a. Normal positive stride (256 B) crossing page 0 -> page 1 (24 iters).
        assert_eq!(
            run_f2(&mut g, &mut dbt, DATA + 0x200, 256, 24),
            exp_f2(&g, DATA + 0x200, 256, 24),
            "{regs:?}"
        );
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
        // 2b. Zero stride (bails cleanly via udiv -> 0).
        assert_eq!(
            run_f2(&mut g, &mut dbt, DATA + 0x200, 0, 10),
            exp_f2(&g, DATA + 0x200, 0, 10),
            "{regs:?}"
        );
        // 2c. Negative stride (-32 B, bails cleanly via udiv -> 0).
        let neg32 = (-32i64) as u64;
        assert_eq!(
            run_f2(&mut g, &mut dbt, DATA + 0x800, neg32, 10),
            exp_f2(&g, DATA + 0x800, neg32, 10),
            "{regs:?}"
        );
        // 2d. Stride >= 4096 (bails cleanly via udiv -> 0).
        assert_eq!(
            run_f2(&mut g, &mut dbt, DATA, 4096, 4),
            exp_f2(&g, DATA, 4096, 4),
            "{regs:?}"
        );

        // 3. Loop 0x6ed64 shape: M_REG with loop-invariant bases x1/x2 + 64-bit induction index x6
        //    + 32-bit compare `cmp w10, w6; b.gt` + loop-local write-before-read NZCV (`fcmp`+`cset`).
        //    Store half-precision 0x3c00 (+1.0) and 0xbc00 (-1.0) in page 0..1.
        for k in 0..128usize {
            let h: u16 = if k == 99 { 0xbc00 } else { 0x3c00 }; // -1.0 at k=99, +1.0 elsewhere
            g.pages[3].0[k * 2..k * 2 + 2].copy_from_slice(&h.to_le_bytes());
        }
        let f3 = CODE + 0xde0;
        g.code(
            f3,
            &[
                0x7c66_783f,             // ldr h31, [x1, x6, lsl #1]
                0x1ee2_43ff,             // fcvt s31, h31
                0x1e28_0bff,             // fmul s31, s31, s8
                0x1e2e_23e0,             // fcmp s31, s14
                0xbc26_785f,             // str s31, [x2, x6, lsl #2]
                0x9100_04c6,             // add x6, x6, #1
                0x1a9f_47e7,             // cset w7, pl
                0x5200_00e7,             // eor w7, w7, #1
                0x0a07_0000,             // and w0, w0, w7
                0x6b06_015f,             // cmp w10, w6
                b_cond(f3 + 40, f3, 12), // b.gt f3
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 1;
            s.x[1] = DATA;
            s.x[2] = DATA + PAGE_SIZE; // RW page 1
            s.x[6] = 0;
            s.x[10] = 100;
            s.v[8] = [2.0f32.to_bits() as u64, 0]; // s8 = 2.0
            s.v[14] = [3.0f32.to_bits() as u64, 0]; // s14 = 3.0 -> +2.0 < 3.0 (MI -> pl=0 -> eor=1)
        }
        let before = dbt.stats();
        assert_eq!(g.run_at(&mut dbt, f3), 1, "all 100 elems < 3.0 ({regs:?})");
        let s = g.cpu.state();
        assert_eq!(s.x[1], DATA, "{regs:?}");
        assert_eq!(s.x[2], DATA + PAGE_SIZE, "{regs:?}");
        assert_eq!(s.x[6], 100, "{regs:?}");
        assert_eq!(s.nzcv, 0x6000_0000, "{regs:?}");
        assert_eq!(read_f32(&g, DATA + PAGE_SIZE + 98 * 4), 2.0, "{regs:?}");
        assert_eq!(read_f32(&g, DATA + PAGE_SIZE + 99 * 4), -2.0, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // 3b. Hostile fault check on 0x6ed64: place output near end of RW page 4 so iteration 8
        //     faults at `str s31, [x2, x6, lsl #2]` on RO page 5, and place input near end of page 5
        //     so iteration 8 faults at `ldr h31, [x1, x6, lsl #1]` (BEFORE `fcmp`!) on unmapped
        //     page 6 — verify exact guest x1, x2, x6 AND exact NZCV from `cmp w10, w6` of iter 7!
        for k in 0..8usize {
            let off = 4096 - 16 + k * 2;
            g.pages[8].0[off..off + 2].copy_from_slice(&0x3c00u16.to_le_bytes()); // +1.0 in page 5
        }
        {
            let s = g.cpu.state_mut();
            s.x[0] = 1;
            s.x[1] = DATA + 6 * PAGE_SIZE - 16; // 8 f16s in page 5, 9th faults on unmapped page 6!
            s.x[2] = DATA + 4 * PAGE_SIZE; // RW page 4
            s.x[6] = 0;
            s.x[10] = 20;
            s.v[8] = [2.0f32.to_bits() as u64, 0];
            s.v[14] = [0.0f32.to_bits() as u64, 0]; // +2.0 > 0.0 -> fcmp sets C=1,N=0,Z=0,V=0 (0x2000_0000)
        }
        // `cmp w10=20, w6=8` sets C=1 (20 >= 8), N=0, Z=0, V=0 (0x2000_0000). To distinguish fcmp
        // from cmp, use s14 = +5.0 (+2.0 < +5.0 -> fcmp sets N=1, C=0 = 0x8000_0000, whereas
        // `cmp w10=20, w6=8` sets N=0, C=1 = 0x2000_0000!).
        g.cpu.state_mut().v[14] = [5.0f32.to_bits() as u64, 0];
        assert_eq!(
            go(&mut g, &mut dbt, f3),
            Exit::Fault {
                addr: DATA + 6 * PAGE_SIZE,
                access: Access::Read,
                kind: FaultKind::Page,
            },
            "{regs:?}"
        );
        let s = g.cpu.state();
        assert_eq!(s.pc, f3, "fault must land on ldr h31 ({regs:?})");
        assert_eq!(s.x[1], DATA + 6 * PAGE_SIZE - 16, "x1 restored ({regs:?})");
        assert_eq!(s.x[2], DATA + 4 * PAGE_SIZE, "x2 restored ({regs:?})");
        assert_eq!(s.x[6], 8, "8 iterations completed before fault ({regs:?})");
        assert_eq!(
            s.nzcv, 0x2000_0000,
            "NZCV at pre-fcmp fault must match cmp w10, w6 from iter 7, not fcmp ({regs:?})"
        );

        // 4. Loop 0x6f3a0 (fcmpe + fcsel max-reduce) and 0x6f804 (M_REG read+write on same base).
        let f4 = CODE + 0xe20;
        g.code(
            f4,
            &[
                0xbc40_441e,            // ldr s30, [x0], #4
                0x1e3f_23d0,            // fcmpe s30, s31
                0x1e3e_4fff,            // fcsel s31, s31, s30, mi
                0xeb18_001f,            // cmp x0, x24
                b_cond(f4 + 16, f4, 1), // b.ne f4
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = DATA;
            s.x[24] = DATA + 64 * 4;
            s.v[31] = [(-1000.0f32).to_bits() as u64, 0];
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f4);
        let max_got = f32::from_le_bytes(
            g.cpu.state().v[31][0].to_le_bytes()[0..4]
                .try_into()
                .unwrap(),
        );
        let max_exp = (0..64)
            .map(|k| read_f32(&g, DATA + k * 4))
            .fold(-1000.0f32, f32::max);
        assert_eq!(max_got, max_exp, "fcmpe+fcsel max ({regs:?})");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        let f5 = CODE + 0xe40;
        g.code(
            f5,
            &[
                0x3ce0_685f,            // ldr q31, [x2, x0]
                0x3ce0_69dd,            // ldr q29, [x14, x0]
                0x4e3d_d7ff,            // fadd v31.4s, v31.4s, v29.4s
                0x3ca0_69df,            // str q31, [x14, x0]
                0x9100_4000,            // add x0, x0, #16
                0xeb01_001f,            // cmp x0, x1
                b_cond(f5 + 24, f5, 1), // b.ne f5
                SVC,
            ],
        );
        let dst_base = DATA + 4 * PAGE_SIZE;
        let expected_first = read_f32(&g, DATA) + read_f32(&g, dst_base);
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = 32 * 16;
            s.x[2] = DATA;
            s.x[14] = dst_base;
        }
        let before = dbt.stats();
        g.run_at(&mut dbt, f5);
        assert_eq!(
            read_f32(&g, dst_base),
            expected_first,
            "M_REG rw stream ({regs:?})"
        );
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // 5. Loop-wide stolen-register pinning edge cases:
        //    5a. Unwritten stolen base [xS0, x6, lsl #3] + written stolen counter xS1 (npin == 2).
        //    5b. Written stolen alias mov xS0, x2 + written stolen counter xS1 (npin == 2).
        //    5c. 3 distinct stolen registers across separate instructions (npin == 0 fallback path).
        let (s0, s1, s2): (u32, u32, u32) = match regs {
            DbtRegs::Default => (16, 17, 28),
            DbtRegs::Go => (21, 22, 23),
        };
        let f6 = CODE + 0xe80;
        g.code(
            f6,
            &[
                0xf866_780a | (s0 << 5), // ldr x10, [xS0, x6, lsl #3] (xS0 unwritten base)
                0x8b0a_0000,             // add x0, x0, x10
                0x9100_04c6,             // add x6, x6, #1
                0xf100_0400 | (s1 << 5) | s1, // subs xS1, xS1, #1 (xS1 written non-ptr)
                b_cond(f6 + 16, f6, 1),  // b.ne f6
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[s0 as usize] = DATA + 0x100;
            s.x[6] = 0;
            s.x[s1 as usize] = 24;
        }
        let mut exp6 = 0u64;
        for k in 0..24usize {
            exp6 = exp6.wrapping_add(g.data(0, 0x100 + k * 8));
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f6),
            exp6,
            "pinned unwritten stolen base ({regs:?})"
        );
        assert_eq!(
            g.cpu.state().x[s0 as usize],
            DATA + 0x100,
            "xS0 must stay guest VA ({regs:?})"
        );
        assert_eq!(g.cpu.state().x[s1 as usize], 0, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        let f7 = CODE + 0xec0;
        g.code(
            f7,
            &[
                0xaa02_03e0 | s0,             // mov xS0, x2 (written stolen alias of x2!)
                0xf940_000a | (s0 << 5),      // ldr x10, [xS0]
                0x8b0a_0000,                  // add x0, x0, x10
                0x9100_2042,                  // add x2, x2, #8
                0xf100_0400 | (s1 << 5) | s1, // subs xS1, xS1, #1
                b_cond(f7 + 20, f7, 1),       // b.ne f7
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = DATA + 0x100;
            s.x[s0 as usize] = 0;
            s.x[s1 as usize] = 24;
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f7),
            exp6,
            "pinned written stolen alias ({regs:?})"
        );
        assert_eq!(g.cpu.state().x[2], DATA + 0x100 + 24 * 8, "{regs:?}");
        assert_eq!(
            g.cpu.state().x[s0 as usize],
            DATA + 0x100 + 23 * 8,
            "pinned stolen alias must be restored to guest VA ({regs:?})"
        );
        assert_eq!(g.cpu.state().x[s1 as usize], 0, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        let f8 = CODE + 0xf00;
        g.code(
            f8,
            &[
                0xf860_780a | (s1 << 16) | (s0 << 5), // ldr x10, [xS0, xS1, lsl #3] (2 stolen)
                0x8b0a_0000,                          // add x0, x0, x10
                0x9100_2000 | (s0 << 5) | s0,         // add xS0, xS0, #8
                0xf100_0400 | (s2 << 5) | s2,         // subs xS2, xS2, #1 (3rd stolen -> npin=0)
                b_cond(f8 + 16, f8, 1),               // b.ne f8
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[s0 as usize] = DATA + 0x80;
            s.x[s1 as usize] = 16; // +128 bytes -> starts at DATA + 0x100
            s.x[s2 as usize] = 24;
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f8),
            exp6,
            "3-stolen fallback M_REG ({regs:?})"
        );
        assert_eq!(
            g.cpu.state().x[s0 as usize],
            DATA + 0x80 + 24 * 8,
            "{regs:?}"
        );
        assert_eq!(g.cpu.state().x[s1 as usize], 16, "{regs:?}");
        assert_eq!(g.cpu.state().x[s2 as usize], 0, "{regs:?}");
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");
    }
}

#[test]
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "android")
))]
fn superpage_refill_prefill_fast_loops_demotion_and_memops() {
    const SUPER: u64 = PAGE_SIZE << 9; // 2 MiB
    const RW: u32 = prot::READ | prot::WRITE;
    // Map two contiguous 2 MiB superpages at a 2 MiB-aligned guest VA backed by a non-2 MiB-aligned
    // (4 KiB-aligned) host allocation, plus one extra page for CoW demotion testing.
    let mut backing = vec![0u8; (2 * SUPER + 2 * PAGE_SIZE) as usize + 4096];
    let align_off = (4096 - (backing.as_ptr() as usize & 4095)) & 4095;
    let base_ptr = unsafe { backing.as_mut_ptr().add(align_off) };
    // Start at +4 KiB so the host pointer is guaranteed 4 KiB-aligned and not 2 MiB-aligned when
    // the allocator returned a 2 MiB-aligned buffer.
    let super_host = unsafe { NonNull::new_unchecked(base_ptr.add(PAGE_SIZE as usize)) };
    let alt_host = unsafe { NonNull::new_unchecked(base_ptr) };
    let buf_va = 0x2000_0000u64; // 2 MiB-aligned, 4 MiB total

    // Fill backing memory with deterministic u64 values (8-byte word index + 1).
    let words = unsafe {
        std::slice::from_raw_parts_mut(super_host.as_ptr().cast::<u64>(), (2 * SUPER / 8) as usize)
    };
    for (i, w) in words.iter_mut().enumerate() {
        *w = (i as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(1);
    }

    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let mut g = Guest::new();
        let mut dbt = Dbt::with_regs(regs).expect("tier 1");
        unsafe {
            g.mmu.map(buf_va, super_host, 2 * SUPER, RW).unwrap();
        }
        let s0: u32 = match regs {
            DbtRegs::Default => 16,
            DbtRegs::Go => 21,
        };

        // 1. Sequential scan across 80 pages (320 KiB, crossing a 256 KiB tlb_used word boundary
        //    and a 2 MiB superpage boundary) via plain non-fast-loop code: exercises superpage
        //    emit_fill + sequential batch prefill (8 slots at a time) + cross-superpage refill.
        //    Use SP-relative/branchy block or simple strided scan with a conditional branch so it
        //    goes through normal inline TLB + emit_refill (not fast loop).
        let f_seq = CODE + 0x100;
        let start_off = SUPER - 20 * PAGE_SIZE; // crosses 2 MiB boundary after 20 pages
        g.code(
            f_seq,
            &[
                0xf940_0043,                  // ldr x3, [x2]
                0x8b03_0000,                  // add x0, x0, x3
                0x9140_0442,                  // add x2, x2, #4096
                0xb400_0024,                  // cbz x4, +4 (prevents fast-loop match)
                0xf100_0484,                  // subs x4, x4, #1
                b_cond(f_seq + 20, f_seq, 1), // b.ne f_seq
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + start_off;
            s.x[4] = 80;
        }
        let mut exp_seq = 0u64;
        for k in 0..80u64 {
            exp_seq = exp_seq.wrapping_add(words[((start_off + k * PAGE_SIZE) / 8) as usize]);
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f_seq),
            exp_seq,
            "superpage sequential prefill ({regs:?})"
        );
        assert_eq!(
            dbt.stats().exits_interp,
            before.exits_interp,
            "no tier0 exits ({regs:?})"
        );

        // 2. Constant-stride fast loops spanning multiple 4 KiB pages inside a 2 MiB superpage:
        //    (a) 256 B stride x 80 iters = 20 KiB (5x 4 KiB pages, like flash_attn 0x6f260)
        //    (b) 136 B non-pow2 stride x 120 iters = 16,320 B (like ggml_gemm_q4_0_4x4_q8_0),
        //        also run crossing the 2 MiB boundary!
        let f_256 = CODE + 0x200;
        g.code(
            f_256,
            &[
                0xf940_0043,                  // ldr x3, [x2]
                0x8b03_0000,                  // add x0, x0, x3
                0x9104_0042,                  // add x2, x2, #256
                0xf100_0484,                  // subs x4, x4, #1
                b_cond(f_256 + 16, f_256, 1), // b.ne f_256
                SVC,
            ],
        );
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + 0x300;
            s.x[4] = 80;
        }
        let mut exp_256 = 0u64;
        for k in 0..80u64 {
            exp_256 = exp_256.wrapping_add(words[((0x300 + k * 256) / 8) as usize]);
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f_256),
            exp_256,
            "2 MiB 256B fast loop ({regs:?})"
        );
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // TBI top-byte tag on 2 MiB superpage fast loop
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = (0xab_u64 << 56) | (buf_va + 0x300);
            s.x[4] = 80;
        }
        assert_eq!(
            g.run_at(&mut dbt, f_256),
            exp_256,
            "TBI 2 MiB fast loop ({regs:?})"
        );
        assert_eq!(
            g.cpu.state().x[2],
            (0xab_u64 << 56) | (buf_va + 0x300 + 80 * 256)
        );

        // Non-pow2 136 B stride crossing the 2 MiB superpage boundary
        let f_136 = CODE + 0x240;
        g.code(
            f_136,
            &[
                0xf940_0043,                  // ldr x3, [x2]
                0x8b03_0000,                  // add x0, x0, x3
                0x9102_2042,                  // add x2, x2, #136
                0xf100_0484,                  // subs x4, x4, #1
                b_cond(f_136 + 16, f_136, 1), // b.ne f_136
                SVC,
            ],
        );
        let off_136 = SUPER - 1000;
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + off_136;
            s.x[4] = 120;
        }
        let mut exp_136 = 0u64;
        for k in 0..120u64 {
            exp_136 = exp_136.wrapping_add(words[((off_136 + k * 136) / 8) as usize]);
        }
        let before = dbt.stats();
        assert_eq!(
            g.run_at(&mut dbt, f_136),
            exp_136,
            "2 MiB 136B boundary-crossing ({regs:?})"
        );
        assert!(dbt.stats().fast_loops > before.fast_loops, "{regs:?}");

        // 3. Register-stride fast loop (like flash_attn 0x6f5a0):
        //    (a) stride_reg = 256 (fits in 2 MiB via MUL without UDIV)
        //    (b) stride_reg = 4096 (>= 4 KiB, still runs in 2 MiB superpage!)
        //    (c) stride_reg = 256 crossing 2 MiB boundary (exercises UDIV shrink path)
        //    (d) stride_reg = 0 (repeats same address safely)
        //    (e) stride_reg = -256 (negative, bails cleanly to slow loop)
        let f_rstr = CODE + 0x280;
        g.code(
            f_rstr,
            &[
                0xf940_0043,                    // ldr x3, [x2]
                0x8b03_0000,                    // add x0, x0, x3
                0x8b00_0042 | (s0 << 16),       // add x2, x2, xS0 (stolen stride reg)
                0xf100_0484,                    // subs x4, x4, #1
                b_cond(f_rstr + 16, f_rstr, 1), // b.ne f_rstr
                SVC,
            ],
        );
        for (start, stride, iters, label) in [
            (0x1000u64, 256i64, 64u64, "regstride 256 in 2M"),
            (0x1000u64, 4096i64, 32u64, "regstride 4096 in 2M"),
            (SUPER - 1024, 256i64, 64u64, "regstride 256 crossing 2M"),
            (0x1000u64, 0i64, 16u64, "regstride 0"),
            (0x8000u64, -256i64, 32u64, "regstride -256"),
        ] {
            let mut exp = 0u64;
            for k in 0..iters {
                let off = (start as i64 + (k as i64) * stride) as u64;
                exp = exp.wrapping_add(words[(off / 8) as usize]);
            }
            {
                let s = g.cpu.state_mut();
                s.x[0] = 0;
                s.x[2] = buf_va + start;
                s.x[s0 as usize] = stride as u64;
                s.x[4] = iters;
            }
            assert_eq!(g.run_at(&mut dbt, f_rstr), exp, "{label} ({regs:?})");
        }

        // 4. Watchpoint inside a 2 MiB superpage must stop precisely at the watched address
        //    even after cpu->stlb was populated by previous runs.
        let watch_va = buf_va + 0x300 + 40 * 256;
        g.cpu
            .state_mut()
            .set_hw_debug(&[], &[(watch_va, watch_va + 8, WATCH_LOAD)]);
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + 0x300;
            s.x[4] = 80;
            s.pc = f_256;
        }
        assert_eq!(
            dbt.run(&mut g.cpu),
            Exit::Fault {
                addr: watch_va,
                access: Access::Read,
                kind: FaultKind::Watchpoint,
            },
            "watchpoint inside 2 MiB superpage ({regs:?})"
        );
        g.cpu.state_mut().set_hw_debug(&[], &[]);

        // 5. Demotion + tlb_flush must invalidate cpu->stlb so a replaced/unmapped/RO page inside
        //    the former 2 MiB superpage is observed immediately.
        //    First warm stlb again on buf_va, then replace page 10 with alt_host (different data),
        //    flush TLB, and verify the loop reads alt_host's value.
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + 0x300;
            s.x[4] = 80;
        }
        assert_eq!(g.run_at(&mut dbt, f_256), exp_256);

        let alt_val = 0xdead_beef_cafe_babe_u64;
        unsafe {
            alt_host
                .as_ptr()
                .cast::<u64>()
                .add(0x300 / 8)
                .write(alt_val);
            g.mmu
                .map_shared(buf_va + 10 * PAGE_SIZE, alt_host, PAGE_SIZE, prot::READ)
                .unwrap();
        }
        g.cpu.tlb_flush();
        let mut exp_200 = 0u64;
        for k in 0..200u64 {
            let off = 0x300 + k * 256;
            if (10 * PAGE_SIZE..11 * PAGE_SIZE).contains(&off) {
                let in_page = (off - 10 * PAGE_SIZE) as usize;
                let v = unsafe { alt_host.as_ptr().add(in_page).cast::<u64>().read() };
                exp_200 = exp_200.wrapping_add(v);
            } else {
                exp_200 = exp_200.wrapping_add(words[(off / 8) as usize]);
            }
        }
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + 0x300;
            s.x[4] = 200;
        }
        assert_eq!(
            g.run_at(&mut dbt, f_256),
            exp_200,
            "demoted page observed after flush ({regs:?})"
        );

        // Unmap page 11 and confirm exact fault at buf_va + 11 * PAGE_SIZE + 0x000
        g.mmu.unmap(buf_va + 11 * PAGE_SIZE, PAGE_SIZE).unwrap();
        g.cpu.tlb_flush();
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[2] = buf_va + 0x300;
            s.x[4] = 200;
            s.pc = f_256;
        }
        assert_eq!(
            dbt.run(&mut g.cpu),
            Exit::Fault {
                addr: buf_va + 11 * PAGE_SIZE,
                access: Access::Read,
                kind: FaultKind::Page,
            },
            "exact fault on unmapped demoted page ({regs:?})"
        );
    }

    // 6. exec_memop bulk span paths across > 2 MiB superpages (memset, memcpy/memmove forward &
    //    backward overlap, memcmp, memchr, strncmp).
    let mut g = Guest::new();
    let space = DbtSpace::new(0, DbtRegs::Default).unwrap();
    let mut dbt = Dbt::attach(&space, 0).unwrap();
    unsafe {
        g.mmu.map(buf_va, super_host, 2 * SUPER, RW).unwrap();
    }
    let fn_memset = CODE + 0x400;
    let fn_memmove = CODE + 0x410;
    let fn_memcmp = CODE + 0x420;
    let fn_memchr = CODE + 0x430;
    let fn_strncmp = CODE + 0x440;
    for pc in [fn_memset, fn_memmove, fn_memcmp, fn_memchr, fn_strncmp] {
        g.code(pc, &[0xd65f_03c0]); // ret (never reached on memop hit)
    }
    space.set_memops(&[
        DbtMemop {
            pc: fn_memset,
            kind: MEMOP_MEMSET,
            reserved: 0,
        },
        DbtMemop {
            pc: fn_memmove,
            kind: MEMOP_MEMMOVE,
            reserved: 0,
        },
        DbtMemop {
            pc: fn_memcmp,
            kind: MEMOP_MEMCMP,
            reserved: 0,
        },
        DbtMemop {
            pc: fn_memchr,
            kind: MEMOP_MEMCHR,
            reserved: 0,
        },
        DbtMemop {
            pc: fn_strncmp,
            kind: MEMOP_STRNCMP,
            reserved: 0,
        },
    ]);
    let ret_svc = CODE + 0x480;
    g.code(ret_svc, &[SVC]);

    let bytes =
        unsafe { std::slice::from_raw_parts_mut(super_host.as_ptr(), (2 * SUPER) as usize) };
    let len = (SUPER + 0x12345) as usize; // > 2 MiB, crosses superpage boundary

    // memset > 2 MiB
    {
        let s = g.cpu.state_mut();
        s.x[0] = buf_va + 0x100;
        s.x[1] = 0x5a;
        s.x[2] = len as u64;
        s.x[30] = ret_svc;
    }
    assert_eq!(g.run_at(&mut dbt, fn_memset), buf_va + 0x100);
    assert!(bytes[0x100..0x100 + len].iter().all(|&b| b == 0x5a));

    // Seed pattern and test backward overlapping memmove across 2 MiB boundary
    for (i, b) in bytes[0x100..0x100 + len].iter_mut().enumerate() {
        *b = ((i * 7 + 3) & 0xff) as u8;
    }
    let shift = 0x500usize;
    let expected_copy: Vec<u8> = bytes[0x100..0x100 + len].to_vec();
    {
        let s = g.cpu.state_mut();
        s.x[0] = buf_va + (0x100 + shift) as u64;
        s.x[1] = buf_va + 0x100;
        s.x[2] = len as u64;
        s.x[30] = ret_svc;
    }
    assert_eq!(
        g.run_at(&mut dbt, fn_memmove),
        buf_va + (0x100 + shift) as u64
    );
    assert_eq!(
        &bytes[0x100 + shift..0x100 + shift + len],
        &expected_copy[..]
    );

    // memcmp equal across > 2 MiB (using two non-overlapping superpage ranges)
    let dst2 = (SUPER + 0x2000) as usize;
    let cmp_len = (SUPER - 0x4000) as usize;
    bytes.copy_within(0x100..0x100 + cmp_len, dst2);
    {
        let s = g.cpu.state_mut();
        s.x[0] = buf_va + 0x100;
        s.x[1] = buf_va + dst2 as u64;
        s.x[2] = cmp_len as u64;
        s.x[30] = ret_svc;
    }
    assert_eq!(g.run_at(&mut dbt, fn_memcmp), 0);

    // memchr finding a byte past the 2 MiB superpage boundary
    bytes[0..0x220000].fill(b'A');
    bytes[0x215432] = b'Z';
    {
        let s = g.cpu.state_mut();
        s.x[0] = buf_va + 0x10;
        s.x[1] = b'Z' as u64;
        s.x[2] = 0x220000;
        s.x[30] = ret_svc;
    }
    assert_eq!(g.run_at(&mut dbt, fn_memchr), buf_va + 0x215432);

    // strncmp crossing the 2 MiB superpage boundary
    bytes[0..0x201000].fill(b'x');
    bytes[0x200500] = 0;
    {
        let s = g.cpu.state_mut();
        s.x[0] = buf_va;
        s.x[1] = buf_va;
        s.x[2] = 0x201000;
        s.x[30] = ret_svc;
    }
    assert_eq!(g.run_at(&mut dbt, fn_strncmp), 0);
}

#[test]
fn fast_loop_gemm_bloc_derived_index_sp_and_cross_page() {
    let _pool = lock_pool();
    let add_x = |rd: u32, rn: u32, rm: u32| 0x8b00_0000u32 | (rm << 16) | (rn << 5) | rd;
    let lsl1 = |rd: u32, rn: u32| 0xd37f_f800u32 | (rn << 5) | rd;
    let ldr_q_reg = |rt: u32, rn: u32, rm: u32| 0x3ce0_6800u32 | (rm << 16) | (rn << 5) | rt;
    let stp_q_sp = |rt1: u32, rt2: u32, off: u32| {
        0xad00_03e0u32 | (((off / 16) & 0x7f) << 15) | (rt2 << 10) | rt1
    };
    let fmla_8h = |rd: u32, rn: u32, rm: u32| 0x4e40_0c00u32 | (rm << 16) | (rn << 5) | rd;

    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::with_data();

        // Populate data pages 0..4 with exact IEEE-754 f16 values (+1.0 = 0x3c00, +0.5 = 0x3800)
        // so fmla v.8h accumulates exact integers with zero rounding ambiguity.
        for p in 0..5usize {
            let host = [3, 4, 6, 5, 7][p];
            for k in 0..2048usize {
                let h: u16 = if (p + k) & 1 == 0 { 0x3c00 } else { 0x3800 };
                g.pages[host].0[k * 2..k * 2 + 2].copy_from_slice(&h.to_le_bytes());
            }
        }
        let read_u64 = |g: &Guest, addr: u64| -> u64 {
            let off = (addr - DATA) as usize;
            let host = [3, 4, 6, 5, 7, 8][off / 4096];
            let p = off % 4096;
            u64::from_le_bytes(g.pages[host].0[p..p + 8].try_into().unwrap())
        };

        // 1. Single-page tinyBLAS::gemm_bloc<4,5>-shaped kernel:
        //    - Derived shifted indices `add tmp, row_off, x0; lsl tmp, tmp, #1`
        //    - > 2 stolen GPRs in Default (x16/x17 read-only + x27/x28 written scratch!)
        //    - Zero-stride SP stores `stp q0..q3, [sp, #0..352]`
        //    - Derived compare `add x3, x0, #15; add x0, x0, #8; cmp x11, x3; b.gt`
        let f_single = CODE + 0x100;
        let single_insns = [
            add_x(7, 10, 0),                         // add x7, x10, x0
            add_x(6, 17, 0),                         // add x6, x17, x0 (stolen x17 read)
            add_x(28, 16, 0),    // add x28, x16, x0 (2 stolen: x16 read, x28 write)
            add_x(27, 15, 0),    // add x27, x15, x0 (stolen x27 write)
            lsl1(7, 7),          // lsl x7, x7, #1
            lsl1(6, 6),          // lsl x6, x6, #1
            lsl1(5, 28),         // lsl x5, x28, #1 (stolen x28 read)
            lsl1(4, 27),         // lsl x4, x27, #1 (stolen x27 read)
            ldr_q_reg(15, 2, 7), // ldr q15, [x2, x7]
            ldr_q_reg(11, 1, 6), // ldr q11, [x1, x6]
            fmla_8h(0, 11, 15),  // fmla v0.8h, v11.8h, v15.8h
            ldr_q_reg(11, 1, 5), // ldr q11, [x1, x5]
            fmla_8h(1, 11, 15),  // fmla v1.8h, v11.8h, v15.8h
            ldr_q_reg(11, 1, 4), // ldr q11, [x1, x4]
            fmla_8h(2, 11, 15),  // fmla v2.8h, v11.8h, v15.8h
            0x9100_3c03,         // add x3, x0, #15
            0x9100_2000,         // add x0, x0, #8
            stp_q_sp(0, 1, 0),   // stp q0, q1, [sp, #0]
            stp_q_sp(2, 3, 352), // stp q2, q3, [sp, #352] (384 B stack span)
            0xeb03_017f,         // cmp x11, x3
            b_cond(f_single + 20 * 4, f_single, 12), // b.gt f_single
            SVC,
        ];
        g.code(f_single, &single_insns);

        let run_gemm =
            |g: &mut Guest, dbt: &mut Dbt, pc: u64, sp: u64, n: i64| -> (u64, u64, u64, u64) {
                let s = g.cpu.state_mut();
                s.x[0] = 0;
                s.x[1] = DATA;
                s.x[2] = DATA;
                s.x[10] = 0;
                s.x[11] = n as u64;
                s.x[15] = 256;
                s.x[16] = 512;
                s.x[17] = 768;
                s.x[18] = 1024;
                s.x[9] = 128;
                s.x[12] = 256;
                s.x[13] = 384;
                for r in 19..=25usize {
                    s.x[r] = 0xfeed_0000_0000_0000u64 + r as u64;
                }
                s.sp = sp;
                for v in 0..4usize {
                    s.v[v] = [0, 0];
                }
                g.run_at(dbt, pc);
                let s = g.cpu.state();
                assert_eq!(s.sp, sp, "SP restored exactly ({regs:?})");
                assert_eq!(s.x[1], DATA, "x1 restored ({regs:?})");
                assert_eq!(s.x[2], DATA, "x2 restored ({regs:?})");
                for r in 19..=25usize {
                    assert_eq!(
                        s.x[r],
                        0xfeed_0000_0000_0000u64 + r as u64,
                        "borrowed non-stolen x{r} must be preserved ({regs:?})"
                    );
                }
                (s.x[0], s.x[3], s.v[0][0], s.nzcv)
            };

        // 1a. SP inside a single page + derived-compare boundary counts (0, 1, 2, 16 iters).
        let before = dbt.stats();
        let (x0_15, x3_15, _, _) = run_gemm(&mut g, &mut dbt, f_single, STACK - 512, 15);
        assert_eq!(
            (x0_15, x3_15),
            (8, 15),
            "N=15 -> 1 iter, 0 back-edges ({regs:?})"
        );
        assert!(
            dbt.stats().fast_loops > before.fast_loops,
            "gemm_bloc<4,5> matched ({regs:?})"
        );

        let (x0_16, x3_16, _, _) = run_gemm(&mut g, &mut dbt, f_single, STACK - 512, 16);
        assert_eq!(
            (x0_16, x3_16),
            (16, 23),
            "N=16 -> 2 iters, 1 back-edge ({regs:?})"
        );

        let (x0_23, x3_23, _, _) = run_gemm(&mut g, &mut dbt, f_single, STACK - 512, 23);
        assert_eq!(
            (x0_23, x3_23),
            (16, 23),
            "N=23 -> 2 iters, 1 back-edge ({regs:?})"
        );

        let (x0_24, x3_24, v0_24, _) = run_gemm(&mut g, &mut dbt, f_single, STACK - 512, 24);
        assert_eq!(
            (x0_24, x3_24),
            (24, 31),
            "N=24 -> 3 iters, 2 back-edges ({regs:?})"
        );

        // Compare N=128 against Tier 0 (interpreter) for exact v0..v2, x27, x28, nzcv, and stack!
        let sp_in = DATA + 4 * PAGE_SIZE + 0x200;
        let (x0_128, x3_128, v0_128, nzcv_128) = run_gemm(&mut g, &mut dbt, f_single, sp_in, 128);
        assert_eq!((x0_128, x3_128), (128, 135), "{regs:?}");
        assert_eq!(
            g.cpu.state().x[28],
            512 + 120,
            "x28 scratch preserved ({regs:?})"
        );
        assert_eq!(
            g.cpu.state().x[27],
            256 + 120,
            "x27 scratch preserved ({regs:?})"
        );
        assert_eq!(
            read_u64(&g, sp_in),
            v0_128,
            "spilled q0 matches v0 ({regs:?})"
        );
        assert_eq!(
            read_u64(&g, sp_in + 352),
            g.cpu.state().v[2][0],
            "spilled q2 matches v2 ({regs:?})"
        );
        assert_ne!(v0_128, v0_24);
        assert_eq!(nzcv_128, 0x8000_0000, "cmp 128, 135 sets N=1 ({regs:?})");

        // 1b. SP straddling a 4 KiB boundary across CONTIGUOUS host pages (page 0 -> page 1):
        //     must run in fast loop with zero Tier 0 exits and write exact values across the seam!
        let sp_cross = DATA + PAGE_SIZE - 128;
        let before_interp = dbt.stats().exits_interp;
        let (x0_c, _, v0_c, _) = run_gemm(&mut g, &mut dbt, f_single, sp_cross, 128);
        assert_eq!(
            (x0_c, v0_c),
            (128, v0_128),
            "cross-page contiguous SP ({regs:?})"
        );
        assert_eq!(read_u64(&g, sp_cross), v0_128);
        assert_eq!(read_u64(&g, sp_cross + 352), g.cpu.state().v[2][0]);
        assert_eq!(
            dbt.stats().exits_interp,
            before_interp,
            "no tier0 exits on contiguous cross-page SP ({regs:?})"
        );

        // 1c. SP straddling NON-CONTIGUOUS host pages (page 2 -> page 3 have swapped host pages!):
        //     prologue must detect addend mismatch and bail cleanly to slow loop!
        let sp_scat = DATA + 3 * PAGE_SIZE - 128;
        let (x0_s, _, v0_s, _) = run_gemm(&mut g, &mut dbt, f_single, sp_scat, 128);
        assert_eq!(
            (x0_s, v0_s),
            (128, v0_128),
            "scattered cross-page SP bails cleanly ({regs:?})"
        );
        assert_eq!(read_u64(&g, sp_scat), v0_128);
        assert_eq!(read_u64(&g, sp_scat + 352), g.cpu.state().v[2][0]);

        // 1d. Hostile misaligned SP -> prologue bails, exact FaultKind::Align!
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[2] = DATA;
            s.x[10] = 0;
            s.x[11] = 128;
            s.x[15] = 256;
            s.x[16] = 512;
            s.x[17] = 768;
            s.sp = sp_in + 8; // misaligned!
        }
        assert_eq!(
            go(&mut g, &mut dbt, f_single),
            Exit::Fault {
                addr: sp_in + 8,
                access: Access::Write,
                kind: FaultKind::StackAlignment,
            },
            "misaligned SP must fault precisely ({regs:?})"
        );

        // 1e. Hostile read-only SP page (page 5 is RO) -> exact write page fault!
        let sp_ro = DATA + 5 * PAGE_SIZE + 0x100;
        {
            let s = g.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[2] = DATA;
            s.x[10] = 0;
            s.x[11] = 128;
            s.x[15] = 256;
            s.x[16] = 512;
            s.x[17] = 768;
            s.sp = sp_ro;
        }
        assert_eq!(
            go(&mut g, &mut dbt, f_single),
            Exit::Fault {
                addr: sp_ro,
                access: Access::Write,
                kind: FaultKind::Page,
            },
            "read-only SP must fault on write ({regs:?})"
        );

        // 2. Cross-4 KiB-code-page tinyBLAS::gemm_bloc<4,6>-shaped loop:
        //    4 instructions at end of page 0 (CODE + 0xff0..0x1000) and body + back-edge in page 1
        //    (CODE + 0x1000..), mapped from NON-CONTIGUOUS host pages so any contiguous-code bug fails.
        let mut g2 = Guest::with_pages(10);
        // Remap CODE + PAGE_SIZE to host page 9 (far from host page 0) so page 0 and page 1 are
        // non-contiguous in host memory!
        let base2 = NonNull::new(g2.pages.as_mut_ptr().cast::<u8>()).unwrap();
        let rw = prot::READ | prot::WRITE;
        unsafe {
            g2.mmu.unmap(CODE + PAGE_SIZE, PAGE_SIZE).unwrap();
            g2.mmu
                .map(
                    CODE + PAGE_SIZE,
                    base2.add(9 * 4096),
                    PAGE_SIZE,
                    prot::READ | prot::EXEC,
                )
                .unwrap();
            for (p, host, perm) in [
                (0, 3, rw),
                (1, 4, rw),
                (2, 6, rw),
                (3, 5, rw),
                (4, 7, rw),
                (5, 8, prot::READ),
            ] {
                g2.mmu
                    .map(
                        DATA + p * PAGE_SIZE,
                        base2.add(host * 4096),
                        PAGE_SIZE,
                        perm,
                    )
                    .unwrap();
            }
        }
        for p in 0..5usize {
            let host = [3, 4, 6, 5, 7][p];
            for k in 0..2048usize {
                let h: u16 = if (p + k) & 1 == 0 { 0x3c00 } else { 0x3800 };
                g2.pages[host].0[k * 2..k * 2 + 2].copy_from_slice(&h.to_le_bytes());
            }
        }
        let f_cross = CODE + 0xff0; // 4 instructions on page 0, rest on page 1!
        let cross_insns = [
            // Page 0 (0xff0..0x1000)
            add_x(3, 10, 0), // 0xff0: add x3, x10, x0
            add_x(7, 18, 0), // 0xff4: add x7, x18, x0 (stolen x18)
            add_x(6, 9, 0),  // 0xff8: add x6, x9, x0
            add_x(5, 12, 0), // 0xffc: add x5, x12, x0
            // Page 1 (0x1000..)
            lsl1(3, 3),                            // 0x1000: lsl x3, x3, #1
            lsl1(7, 7),                            // 0x1004: lsl x7, x7, #1
            lsl1(6, 6),                            // 0x1008: lsl x6, x6, #1
            lsl1(5, 5),                            // 0x100c: lsl x5, x5, #1
            ldr_q_reg(15, 2, 3),                   // 0x1010: ldr q15, [x2, x3]
            add_x(3, 17, 0),                       // 0x1014: add x3, x17, x0 (stolen x17)
            ldr_q_reg(14, 2, 6),                   // 0x1018: ldr q14, [x2, x6]
            lsl1(3, 3),                            // 0x101c: lsl x3, x3, #1
            ldr_q_reg(13, 2, 5),                   // 0x1020: ldr q13, [x2, x5]
            ldr_q_reg(11, 1, 7),                   // 0x1024: ldr q11, [x1, x7]
            add_x(7, 16, 0),                       // 0x1028: add x7, x16, x0 (stolen x16)
            lsl1(7, 7),                            // 0x102c: lsl x7, x7, #1
            fmla_8h(0, 11, 15),                    // 0x1030: fmla v0.8h, v11.8h, v15.8h
            ldr_q_reg(11, 1, 3),                   // 0x1034: ldr q11, [x1, x3]
            0x9100_3c03,                           // 0x1038: add x3, x0, #15
            0x9100_2000,                           // 0x103c: add x0, x0, #8
            fmla_8h(1, 11, 14),                    // 0x1040: fmla v1.8h, v11.8h, v14.8h
            ldr_q_reg(11, 1, 7),                   // 0x1044: ldr q11, [x1, x7]
            fmla_8h(2, 11, 13),                    // 0x1048: fmla v2.8h, v11.8h, v13.8h
            stp_q_sp(0, 1, 0),                     // 0x104c: stp q0, q1, [sp, #0]
            stp_q_sp(2, 3, 352),                   // 0x1050: stp q2, q3, [sp, #352]
            0xeb03_017f,                           // 0x1054: cmp x11, x3
            b_cond(f_cross + 26 * 4, f_cross, 12), // 0x1058: b.gt f_cross
            SVC,
        ];
        // Write first 4 insns to host page 0 (0xff0..0x1000) and remaining to host page 9 (0x0..)!
        for (i, insn) in cross_insns.iter().enumerate() {
            let bytes = insn.to_le_bytes();
            if i < 4 {
                let off = 0xff0 + i * 4;
                g2.pages[0].0[off..off + 4].copy_from_slice(&bytes);
            } else {
                let off = (i - 4) * 4;
                g2.pages[9].0[off..off + 4].copy_from_slice(&bytes);
            }
        }

        let mut dbt2 = Dbt::with_regs(regs).unwrap();
        let before2 = dbt2.stats();
        let (x0_x, x3_x, v0_x, nzcv_x) = run_gemm(
            &mut g2,
            &mut dbt2,
            f_cross,
            DATA + 4 * PAGE_SIZE + 0x100,
            128,
        );
        assert_eq!(
            (x0_x, x3_x, nzcv_x),
            (128, 135, 0x8000_0000),
            "cross-page fast loop ({regs:?})"
        );
        assert!(
            dbt2.stats().fast_loops > before2.fast_loops,
            "cross-page fast loop matched ({regs:?})"
        );
        assert_eq!(
            v0_x, v0_128,
            "cross-page fast loop value matches ({regs:?})"
        );

        // 2b. Template reuse across instances for the cross-page fast loop
        let mut dbt3 = Dbt::with_regs(regs).unwrap();
        let (x0_t, _, v0_t, _) = run_gemm(
            &mut g2,
            &mut dbt3,
            f_cross,
            DATA + 4 * PAGE_SIZE + 0x100,
            128,
        );
        assert_eq!(
            (x0_t, v0_t),
            (128, v0_128),
            "cross-page template reuse ({regs:?})"
        );
        assert!(
            dbt3.stats().blocks_shared > 0,
            "cross-page template hit ({regs:?})"
        );
        assert!(
            dbt3.stats().fast_loops > 0,
            "cross-page template preserved fast_loops stat ({regs:?})"
        );

        // 2c. Exact data fault inside page 1 of cross-page fast loop (at 0x1010: ldr q15, [x2, x3]):
        //     place x2 so iter 4 (x0 = 32 -> offset 64 B) hits unmapped DATA + 6 * PAGE_SIZE.
        {
            let s = g2.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[2] = DATA + 6 * PAGE_SIZE - 64; // 4 iters (64 B) in page 5, iter 4 faults on page 6!
            s.x[10] = 0;
            s.x[11] = 128;
            s.x[9] = 0;
            s.x[12] = 0;
            s.x[16] = 0;
            s.x[17] = 0;
            s.x[18] = 0;
            s.sp = DATA + 4 * PAGE_SIZE + 0x100;
        }
        assert_eq!(
            go(&mut g2, &mut dbt2, f_cross),
            Exit::Fault {
                addr: DATA + 6 * PAGE_SIZE,
                access: Access::Read,
                kind: FaultKind::Page,
            },
            "cross-page data fault ({regs:?})"
        );
        assert_eq!(
            g2.cpu.state().pc,
            CODE + 0x1010,
            "exact fault PC in page 1 ({regs:?})"
        );
        assert_eq!(
            g2.cpu.state().x[0],
            32,
            "4 iters completed before fault ({regs:?})"
        );
        assert_eq!(
            g2.cpu.state().x[2],
            DATA + 6 * PAGE_SIZE - 64,
            "x2 restored ({regs:?})"
        );
        assert_eq!(
            g2.cpu.state().sp,
            DATA + 4 * PAGE_SIZE + 0x100,
            "SP restored ({regs:?})"
        );

        // 2d. Hostile page-1 code modification + invalidate(CODE + PAGE_SIZE, PAGE_SIZE) ONLY:
        //     change `add x0, x0, #8` (at page 1 offset 0x3c) to `add x0, x0, #16` (`0x9100_4000`)
        //     and verify the cross-page block starting in page 0 IS invalidated!
        g2.pages[9].0[0x3c..0x40].copy_from_slice(&0x9100_4000u32.to_le_bytes());
        dbt2.invalidate(&g2.cpu, CODE + PAGE_SIZE, PAGE_SIZE);
        let (x0_mod, _, _, _) = run_gemm(
            &mut g2,
            &mut dbt2,
            f_cross,
            DATA + 4 * PAGE_SIZE + 0x100,
            128,
        );
        assert_eq!(
            x0_mod, 144,
            "modified page-1 step=16 runs 9 iters (0..=128 -> 144) ({regs:?})"
        );
        assert_eq!(
            g2.cpu.state().x[3],
            128 + 15,
            "iter 8 saw x0=128 -> x3=143, then x0=144 ({regs:?})"
        );
        // Verify it truly ran 9 iters (not 16): v0_x had 16 iters of +1.0*+1.0, new has 9 iters!
        assert_ne!(
            g2.cpu.state().v[0][0],
            v0_x,
            "page-1 rewrite observed by page-0 block ({regs:?})"
        );

        // 2e. Hostile page-1 unmap + invalidate(CODE + PAGE_SIZE, PAGE_SIZE):
        //     re-running from f_cross must execute page 0 and fault cleanly at CODE + PAGE_SIZE!
        g2.mmu.unmap(CODE + PAGE_SIZE, PAGE_SIZE).unwrap();
        g2.cpu.tlb_flush();
        dbt2.invalidate(&g2.cpu, CODE + PAGE_SIZE, PAGE_SIZE);
        {
            let s = g2.cpu.state_mut();
            s.x[0] = 0;
            s.x[1] = DATA;
            s.x[2] = DATA;
            s.x[10] = 0;
            s.x[11] = 128;
            s.sp = DATA + 4 * PAGE_SIZE + 0x100;
        }
        assert_eq!(
            go(&mut g2, &mut dbt2, f_cross),
            Exit::Fault {
                addr: CODE + PAGE_SIZE,
                access: Access::Exec,
                kind: FaultKind::Page,
            },
            "unmapped page 1 must invalidate cross-page block and fault at page 1 ({regs:?})"
        );
    }
}

fn b_cond(from: u64, to: u64, cond: u32) -> u32 {
    0x5400_0000 | ((((to as i64 - from as i64) / 4) as u32 & 0x7_ffff) << 5) | (cond & 15)
}

fn cbnz_x(from: u64, to: u64, rt: u32) -> u32 {
    0xb500_0000 | ((((to as i64 - from as i64) / 4) as u32 & 0x7_ffff) << 5) | (rt & 31)
}

fn bl(from: u64, to: u64) -> u32 {
    0x9400_0000 | (((to as i64 - from as i64) / 4) as u32 & 0x3ff_ffff)
}

fn cbz_x0(from: u64, to: u64) -> u32 {
    0xb400_0000 | ((((to as i64 - from as i64) / 4) as u32 & 0x7_ffff) << 5)
}

fn movz_x0(imm: u16) -> u32 {
    0xd280_0000 | (imm as u32) << 5
}

fn b(from: u64, to: u64) -> u32 {
    0x1400_0000 | (((to as i64 - from as i64) / 4) as u32 & 0x3ff_ffff)
}

/// The address of the first byte of data page `page` minus `before`: an access starting here
/// crosses into page `page`.
fn before_page(page: u64, before: u64) -> u64 {
    DATA + page * PAGE_SIZE - before
}

/// The expected value of a cross-page access: the last `before` bytes of page `page - 1` followed
/// by the first bytes of page `page`.
fn crossing(g: &Guest, page: usize, before: usize) -> u64 {
    let lo = g.data(page - 1, 4096 - 8) >> (8 * (8 - before));
    let hi = g.data(page, 0) << (8 * before);
    lo | hi
}

/// Runs from `pc` to an svc or a fault.
fn go(g: &mut Guest, dbt: &mut Dbt, pc: u64) -> Exit {
    g.cpu.state_mut().pc = pc;
    dbt.run(&mut g.cpu)
}

#[test]
fn memop_self_copy_validates_pages_before_returning() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(space) = DbtSpace::new(0, regs) else {
            return;
        };
        let mut dbt = Dbt::attach(&space, 0).unwrap();
        let mut g = Guest::with_data();

        let f_memcpy = CODE + 0x100;
        let f_memmove = CODE + 0x120;
        let caller = CODE + 0x40;
        g.code(f_memcpy, &[movz_x0(0x7777), RET]);
        g.code(f_memmove, &[movz_x0(0x7777), RET]);
        g.code(caller, &[0xd63f_0120, SVC]); // blr x9; svc #0
        space.set_memops(&[
            DbtMemop {
                pc: f_memcpy,
                kind: MEMOP_MEMCPY,
                reserved: 0,
            },
            DbtMemop {
                pc: f_memmove,
                kind: MEMOP_MEMMOVE,
                reserved: 0,
            },
        ]);

        let ro_page = DATA + 5 * PAGE_SIZE;
        let unmapped = DATA + 6 * PAGE_SIZE;

        for target in [f_memcpy, f_memmove] {
            for len in [256u64, 5000] {
                // Unmapped dst == src with n >= 128 must decline exec_memop and run guest code.
                {
                    let s = g.cpu.state_mut();
                    s.x[9] = target;
                    s.x[0] = unmapped;
                    s.x[1] = unmapped;
                    s.x[2] = len;
                }
                assert_eq!(g.run_at(&mut dbt, caller), 0x7777, "{regs:?} len={len}");

                // Read-only dst == src with n >= 128 must also decline exec_memop.
                {
                    let s = g.cpu.state_mut();
                    s.x[9] = target;
                    s.x[0] = ro_page;
                    s.x[1] = ro_page;
                    s.x[2] = len;
                }
                assert_eq!(g.run_at(&mut dbt, caller), 0x7777, "{regs:?} len={len}");

                // Writable+readable dst == src (including cross-page > 4 KiB through exec_memop)
                // succeeds without running guest stub.
                let before0 = g.pages[3].0;
                let before1 = g.pages[4].0;
                {
                    let s = g.cpu.state_mut();
                    s.x[9] = target;
                    s.x[0] = DATA;
                    s.x[1] = DATA;
                    s.x[2] = len;
                }
                assert_eq!(g.run_at(&mut dbt, caller), DATA, "{regs:?} len={len}");
                assert_eq!(g.pages[3].0, before0, "{regs:?} len={len}");
                assert_eq!(g.pages[4].0, before1, "{regs:?} len={len}");
            }

            // Zero-length copy stays below the length gate and runs guest code directly.
            {
                let s = g.cpu.state_mut();
                s.x[9] = target;
                s.x[0] = unmapped;
                s.x[1] = unmapped;
                s.x[2] = 0;
            }
            assert_eq!(g.run_at(&mut dbt, caller), 0x7777, "{regs:?}");
        }
    }
}

#[test]
fn revive_does_not_insert_duplicate_key_after_early_stop() {
    let _pool = lock_pool();
    const KEY: u64 = 0x5eed_0005;
    let Some(mut dbt) = keyed_dbt(KEY) else {
        return;
    };
    // 2 initial code pages (CODE, CODE+PAGE_SIZE) + 1 stack page + 6 extra code pages.
    let mut g = Guest::with_pages(9);
    let base = NonNull::new(g.pages.as_mut_ptr().cast::<u8>()).unwrap();
    let park_page = CODE + PAGE_SIZE;
    let park_host = unsafe { base.add(4096) };
    let extra_base = CODE + 2 * PAGE_SIZE;
    unsafe {
        g.mmu
            .map(
                extra_base,
                base.add(3 * 4096),
                6 * PAGE_SIZE,
                prot::READ | prot::EXEC,
            )
            .unwrap();
    }

    // Install pc_a before pc_b on park_page so page_head visits pc_b first during dbt_revive.
    let pc_a = park_page;
    let pc_b = park_page + 0x10;
    let pc_c = park_page + 0x20;
    g.code(pc_a, &[movz_x0(11), SVC]);
    g.code(pc_b, &[movz_x0(22), SVC]);
    g.code(pc_c, &[movz_x0(33), SVC]);
    assert_eq!(g.run_at(&mut dbt, pc_a), 11);
    assert_eq!(g.run_at(&mut dbt, pc_b), 22);

    // Fill the initial 4096-slot table to 3071 occupied slots (3/4 load is 3072):
    // 2 blocks on park_page + 3069 distinct blocks across the 6 extra code pages.
    for i in 0..3069usize {
        let page_idx = 3 + i / 512;
        let off = (i % 512) * 8;
        let insns = [movz_x0(1), SVC];
        g.pages[page_idx].0[off..off + 4].copy_from_slice(&insns[0].to_le_bytes());
        g.pages[page_idx].0[off + 4..off + 8].copy_from_slice(&insns[1].to_le_bytes());
        let pc = extra_base + (i as u64) * 8;
        assert_eq!(g.run_at(&mut dbt, pc), 1);
    }

    // Park park_page while keeping the 3069 extra blocks live (table_occupied stays 3071).
    let source = DbtSource {
        start: park_page,
        len: PAGE_SIZE,
        id: [1, 2, 0, 0, PAGE_SIZE],
    };
    dbt.space().set_sources(&[source]);
    drop(dbt);
    let mut dbt = keyed_dbt(KEY).unwrap();
    dbt.space().trust(&[]);
    g.mmu.unmap(park_page, PAGE_SIZE).unwrap();
    g.cpu.tlb_flush();
    assert_eq!(g.run_at(&mut dbt, extra_base), 1);

    // Remap park_page and run pc_a: dbt_revive revives pc_b (n=1), hits 3071+1 == 3072 and
    // stops before pc_a; dbt_run then translates and installs a fresh pc_a (growing the table).
    unsafe {
        g.mmu
            .map(park_page, park_host, PAGE_SIZE, prot::READ | prot::EXEC)
            .unwrap();
    }
    assert_eq!(g.run_at(&mut dbt, pc_a), 11);

    // Run a third PC on park_page to trigger dbt_revive again if any parked block remained.
    assert_eq!(g.run_at(&mut dbt, pc_c), 33);

    // Rewrite pc_a and invalidate: exactly one live block for pc_a must exist (no duplicate key).
    g.code(pc_a, &[movz_x0(99), SVC]);
    let inv_before = dbt.stats().invalidated;
    dbt.invalidate(&g.cpu, pc_a, 4);
    assert_eq!(dbt.stats().invalidated - inv_before, 1);
    assert_eq!(g.run_at(&mut dbt, pc_a), 99);
}

#[test]
fn concurrent_attach_during_conditional_branch_linking() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    const PAIRS: usize = 32;
    let setup = |g: &mut Guest| {
        for i in 0..PAIRS {
            let src = CODE + (i as u64) * 0x20;
            let dst = CODE + 0x800 + (i as u64) * 0x10;
            // src: cbz x0, dst; movz x0, #1; svc #0
            // dst: movz x0, #2; svc #0
            g.code(src, &[cbz_x0(src, dst), movz_x0(1), SVC]);
            g.code(dst, &[movz_x0(2), SVC]);
        }
    };

    let stop = Arc::new(AtomicBool::new(false));
    let space2 = space.clone();
    let stop2 = stop.clone();
    let attacher = std::thread::spawn(move || {
        let mut g = Guest::new();
        setup(&mut g);
        while !stop2.load(Ordering::Relaxed) {
            let mut dbt = Dbt::attach(&space2, 0).unwrap();
            for i in 0..PAIRS {
                let src = CODE + (i as u64) * 0x20;
                g.cpu.state_mut().x[0] = 0;
                g.cpu.state_mut().pc = src;
                run_to_svc(&mut dbt, &mut g.cpu);
                assert_eq!(g.cpu.state().x[0], 2);
            }
        }
    });

    let mut dbt = Dbt::attach(&space, 0).unwrap();
    let mut g = Guest::new();
    setup(&mut g);
    for _ in 0..32 {
        dbt.flush();
        // Translate src (not taken), then dst directly, then take src -> dst so the link hits
        // the already-translated path with patch_branch_site != NULL while attacher races attach.
        for i in 0..PAIRS {
            let src = CODE + (i as u64) * 0x20;
            let dst = CODE + 0x800 + (i as u64) * 0x10;
            g.cpu.state_mut().x[0] = 1;
            g.cpu.state_mut().pc = src;
            run_to_svc(&mut dbt, &mut g.cpu);
            assert_eq!(g.cpu.state().x[0], 1);

            g.cpu.state_mut().pc = dst;
            run_to_svc(&mut dbt, &mut g.cpu);
            assert_eq!(g.cpu.state().x[0], 2);

            g.cpu.state_mut().x[0] = 0;
            g.cpu.state_mut().pc = src;
            run_to_svc(&mut dbt, &mut g.cpu);
            assert_eq!(g.cpu.state().x[0], 2);
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacher.join().unwrap();
}

#[test]
fn concurrent_instances_update_spare_stats_independently() {
    let _pool = lock_pool();
    if DbtSpace::new(0, DbtRegs::Default).is_none() {
        return;
    }
    let workers: Vec<_> = (0..4)
        .map(|id| {
            std::thread::spawn(move || {
                let mut g = Guest::new();
                g.code(CODE, &[movz_x0(7), SVC]);
                let ops = [DbtMemop {
                    pc: CODE,
                    kind: MEMOP_MEMSET,
                    reserved: 0,
                }];
                for r in 0..24u64 {
                    let space = DbtSpace::new(0x1000 + id * 100 + r, DbtRegs::Default).unwrap();
                    let mut dbt = Dbt::attach(&space, 0).unwrap();
                    assert_eq!(g.run(&mut dbt), 7);
                    space.set_memops(&ops);
                    space.set_memops(&[]);
                    space.retire_outside(&[]);
                    drop(dbt);
                    drop(space);
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
}

#[test]
fn unallocated_id_registers_fault_in_tier1() {
    for regs in [DbtRegs::Default, DbtRegs::Go] {
        let Some(mut dbt) = Dbt::with_regs(regs) else {
            return;
        };
        let mut g = Guest::new();
        // REVIDR_EL1 (CRm=0, op2=6) reads 0 and proceeds to SVC.
        g.cpu.state_mut().x[0] = 0xbeef;
        g.code(CODE, &[0xd538_00c0, SVC]);
        assert_eq!(g.run(&mut dbt), 0, "{regs:?}");

        // Unallocated CRm=0 (op2=1) and CRm=1 (op2=0) must exit Undefined in Tier 1.
        for insn in [0xd538_0020u32, 0xd538_0100u32] {
            let mut g = Guest::new();
            g.code(CODE, &[insn, SVC]);
            g.cpu.state_mut().pc = CODE;
            let exit = dbt.run(&mut g.cpu);
            assert_eq!(exit, Exit::Undefined { insn }, "{regs:?} {insn:#x}");
            assert_eq!(g.cpu.state().pc, CODE, "{regs:?} {insn:#x}");
        }
    }
}

#[test]
fn code_group_private_conditional_branch_relinks_across_members() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let Some(space) = DbtSpace::new(0, DbtRegs::Default) else {
        return;
    };
    let tag1 = space.new_tag().unwrap();
    let tag2 = space.new_tag().unwrap();
    const SHARED_CODE: u64 = CODE;
    const PRIV_CODE: u64 = CODE + PAGE_SIZE;
    space.share(&[DbtSource {
        start: SHARED_CODE,
        len: PAGE_SIZE,
        id: [1, 2, 3, 4, 5],
    }]);

    let setup_member = |g: &mut Guest, shared_val: u16, priv_val: u16| {
        // Shared conditional branch pair on page 0 (identical code across both members).
        let s_src = SHARED_CODE;
        let s_dst = SHARED_CODE + 0x40;
        g.code(s_src, &[cbz_x0(s_src, s_dst), movz_x0(1), SVC]);
        g.code(s_dst, &[movz_x0(shared_val), SVC]);

        // Private conditional branch pairs on page 1 (member-specific results in private JIT page).
        for i in 0..16u64 {
            let p_src = PRIV_CODE + i * 0x20;
            let p_dst = PRIV_CODE + 0x800 + i * 0x10;
            g.code(p_src, &[cbz_x0(p_src, p_dst), movz_x0(1), SVC]);
            g.code(p_dst, &[movz_x0(priv_val + i as u16), SVC]);
        }
    };

    let run_pc = |dbt: &mut Dbt, g: &mut Guest, pc: u64, x0: u64| -> u64 {
        let s = g.cpu.state_mut();
        s.x[0] = x0;
        s.pc = pc;
        run_to_svc(dbt, &mut g.cpu);
        g.cpu.state().x[0]
    };

    // Keep member 2 actively running shared + private code while member 1 translates and relinks
    // its own private conditional branches (and also races a same-tag helper thread).
    let stop = Arc::new(AtomicBool::new(false));
    let space_m2 = space.clone();
    let stop_m2 = stop.clone();
    let member2 = std::thread::spawn(move || {
        let mut g = Guest::new();
        setup_member(&mut g, 20, 200);
        let mut dbt = Dbt::attach(&space_m2, tag2).unwrap();
        while !stop_m2.load(Ordering::Relaxed) {
            assert_eq!(run_pc(&mut dbt, &mut g, SHARED_CODE, 0), 20);
            for i in 0..16u64 {
                assert_eq!(run_pc(&mut dbt, &mut g, PRIV_CODE + i * 0x20, 0), 200 + i);
            }
        }
    });

    let exercise_relinks = |dbt: &mut Dbt, g: &mut Guest| {
        for _ in 0..16 {
            dbt.flush();
            for i in 0..16u64 {
                let (p_src, p_dst) = (PRIV_CODE + i * 0x20, PRIV_CODE + 0x800 + i * 0x10);
                assert_eq!(run_pc(dbt, g, p_src, 1), 1);
                assert_eq!(run_pc(dbt, g, p_dst, 0), 100 + i);
                // Already-translated private conditional branch relinks directly when solo on tag1.
                assert_eq!(run_pc(dbt, g, p_src, 0), 100 + i);
            }
            assert_eq!(run_pc(dbt, g, SHARED_CODE, 0), 20);
        }
    };

    // Member 1 runs solo for its tag while member 2 is attached on tag2: private conditional
    // branches must execute cleanly and relink on both install and already-translated paths.
    let mut g1 = Guest::new();
    setup_member(&mut g1, 20, 100);
    let mut dbt1 = Dbt::attach(&space, tag1).unwrap();
    exercise_relinks(&mut dbt1, &mut g1);

    // Also stress concurrent attach/detach on the SAME tag1 while member 1 relinks.
    let space_same = space.clone();
    let stop_same = Arc::new(AtomicBool::new(false));
    let stop_same2 = stop_same.clone();
    let peer_same_tag = std::thread::spawn(move || {
        let mut g = Guest::new();
        setup_member(&mut g, 20, 100);
        while !stop_same2.load(Ordering::Relaxed) {
            let mut dbt = Dbt::attach(&space_same, tag1).unwrap();
            for i in 0..16u64 {
                assert_eq!(run_pc(&mut dbt, &mut g, PRIV_CODE + i * 0x20, 0), 100 + i);
            }
        }
    });

    exercise_relinks(&mut dbt1, &mut g1);

    stop_same.store(true, Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);
    peer_same_tag.join().unwrap();
    member2.join().unwrap();
}
