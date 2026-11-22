# Raw ICMP sockets (kernel/rawicmp) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/rawicmp"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/rawicmp made before it was split from kernel/net keep their `kernel/net` tags and live in `.agents/decisions/kernel/net.md`: D2, D22 and the raw-ICMP parts of D9, D12, D18 and D19.

## Active

### D1: Raw ICMP ping-socket emulation has a dedicated module

- **What**: kernel/rawicmp owns `core/kernel/src/rawicmp.rs` plus `raw_recv` and `take_errors` in `core/kernel/src/syscall/net.rs`, while socket-syscall dispatch and `InetSocket` fields remain in `kernel/net` and periodic tap polling in `kernel/time`.
- **Why**: The 1,353-line raw ICMP ping-socket emulation layer needed a focused map independent of general internet socket passthrough.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/net.md`.
- **Watch out**: Changes touching `InetSocket` raw-ICMP fields, UDP TTL tapping, socket dispatch or timer-thread tap polling require reading `kernel/rawicmp` together with `kernel/net` or `kernel/time`.
- **Source**: e0719858
