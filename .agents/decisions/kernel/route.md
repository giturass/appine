# Synthesized routing tables and FIB rules (kernel/route) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/route"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/route made before it was split from kernel/net keep their `kernel/net` tags and live in `.agents/decisions/kernel/net.md`: D4 and the routing parts of D3, D9 and D12.

## Active

### D1: Synthesized routing tables and FIB rules have a dedicated module

- **What**: kernel/route owns `core/kernel/src/route.rs` (documenting `Machine::set_routes` as its host feed), while `Machine` storage stays in `kernel/process`, netlink transport in `kernel/netlink` and `SIOCADDRT`/`SIOCDELRT` in `kernel/net`.
- **Why**: The 1,105-line routing-table and FIB-rule synthesizer needed a dedicated map separate from socket I/O.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/net.md`.
- **Watch out**: Changes to `RTM_GETROUTE`/`RTM_GETRULE` replies, virtual-device route merging or Android `LinkProperties` route updates require reading `kernel/route` together with `kernel/netlink`, `kernel/netns` or `kernel/net`.
- **Source**: e0719858
