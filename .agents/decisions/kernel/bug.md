# Bug containment, kill reports and BKL watchdog (kernel/bug) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/bug"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/bug made before it was split from kernel/process keep their `kernel/process` tags and live in `.agents/decisions/kernel/process.md`: D29, D38, D56, and the bug-containment, watchdog and test-hook parts of D14, D18 and D53.

## Active

### D1: Bug containment, kill reports, test hooks and the BKL watchdog have a dedicated module

- **What**: kernel/bug owns `bug.rs`, `watchdog.rs`, `Hold`/`HoldSample`/`Entry`/`Doing`/`doing`/`done` in `kernel.rs`, `Machine::take_kills`/`stall` in `machine.rs` and `TEST_SYSCALL` (`0xa991`) in `syscall/mod.rs`.
- **Why**: Panic containment, kill-report queuing, debug test hooks and the lock-free BKL watchdog needed a focused map separate from general task and scheduling internals.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/process.md`, and watchdog start/stop stays in `kernel/boot`.
- **Watch out**: Changes to BKL acquisition cache-line layout or exit-stage panic salvage require consulting both `kernel/process` and `kernel/bug`.
- **Source**: e4d7bbe5
