# /proc/sys sysctls (kernel/sysctl) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/sysctl"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on kernel/sysctl made before it was split from kernel/procfs keep their `kernel/procfs` tags and live in `.agents/decisions/kernel/procfs.md`: D16, D22 and the sysctl parts of D8, D9, D15, D21, D25, D28 and D31.

## Active

### D1: /proc/sys sysctls have a dedicated module

- **What**: kernel/sysctl owns the `sys/*` portion of `STATIC`, `RECORDED`, `recorded`, `recorded_value`, `NET_CONF4`, `NET_CONF6`, `PseudoNode::{Static(b"sys/..."), NetConf, NetSysctl}`, `sysctl_kind`, `is_net_sysctl` and the `/proc/sys` dispatch arms in `core/kernel/src/pseudo.rs`.
- **Why**: `/proc/sys` sysctl tables, permission rules, namespace scoping and recorded sysctls needed a boundary separate from general procfs views.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/kernel/procfs.md`, and section/variant ownership inside `pseudo.rs` lives in `.agents/MODULES.md`.
- **Watch out**: Changes touching `open_pseudo`, namespace-scoped regeneration, `netconf::SYSCTLS` or `RECORDED` keys require reading `kernel/sysctl` together with `kernel/procfs`, `kernel/files`, `kernel/netns` or the backing subsystem map.
- **Source**: e0719858
