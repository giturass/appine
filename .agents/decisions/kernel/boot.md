# Machine lifecycle and virtual init (kernel/boot) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/boot"`
>
> Last distilled: 2026-11-21 (HEAD = 125f3d00)
>
> Decisions made before kernel/boot was split from kernel/process retain their `kernel/process` tags in `.agents/decisions/kernel/process.md`: D9, D35, D53, the host-stop part of D30 and the host-spawn part of D43; D16 retains the process-reaping contract.

## Active

### D1: Boot owns machine startup, host spawn and virtual init

- **What**: kernel/boot owns machine lifecycle types and methods, inittab, INIT and reboot.
- **Why**: Startup, host-launched programs and PID 1 policy have a lifecycle separate from general task execution.
- **Tradeoffs**: Shared kernel state, general reaping, waits, statistics and console behavior stay with their existing owners; host CLI launch integration belongs to harness/cli.
- **Watch out**: Keep spawn registration and worker teardown ordered, and retain the inherited Android poweroff question.
- **Source**: 8a17e4a9; d053be24; 60790c14; 39e55b4b

### D2: Startup installs an optional GPU renderer per machine

- **What**: `Machine` accepts an optional GPU renderer at startup and installs it only after the host probe and mapper succeed.
- **Why**: Guest startup must still succeed on hosts without a usable GPU.
- **Tradeoffs**: Hardware probing adds startup work when GPU mode is enabled.
- **Watch out**: Probe stalls or failures can disable GPU acceleration for that boot.
- **Source**: 87c7d9db
