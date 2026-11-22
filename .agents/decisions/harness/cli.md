# Host CLI and integration (harness/cli) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: harness/cli"`
>
> Last distilled: 2026-11-21 (HEAD = 125f3d00)
>
> Decisions on harness/cli made before it was split from harness keep their `harness` tags and live in `.agents/decisions/harness.md`: D5, D6, D9, D11, D15, D20, D21, D25, D28, D32, D35 and the guest-test portions of D36, D40 and D41.

## Active

### D1: CLI and cargo integration are separate from shared tooling

- **What**: harness/cli owns the host CLI and cargo integration checks, while shared development tooling remains in harness.
- **Why**: The extracted subsystem needs a focused architecture reference with explicit integration boundaries.
- **Tradeoffs**: Pre-split decisions remain in the parent snapshot and related changes may require several maps.
- **Watch out**: The split preserves inherited verification and open issues; it is not a fresh full audit.
- **Source**: 60790c14; 39e55b4b

### D2: Interactive Android CLI shells preload DNS on a joined background thread

- **What**: On Android, `appine-run` starts a background DNS preload thread for recognized interactive shells when `options.terminal.is_some()` (covering forced `--pty`), provides an opt-out, and joins the preload `JoinHandle` after restoring the terminal before `main()` returns.
- **Why**: Interactive shells can overlap `libandroid.so` DNS setup with startup and user input, while joining prevents a detached `dlopen` from racing `libc::exit()` on fast exits and relying on `options.terminal` avoids skipping forced `--pty`.
- **Tradeoffs**: Interactive shells may load `libandroid.so` without querying DNS, and fast failures or very short shells wait for an in-flight `dlopen` before exiting.
- **Watch out**: Unrecognized shell launch forms fall back to on-demand loading, and an unexpected hang inside Android's `dlopen` would delay CLI exit.
- **Source**: 86d7523c, 73394ffd

## Superseded

- ~~Detached Android DNS preload thread and host `on_tty` shell check in 86d7523c~~ → replaced by **D2** in 73394ffd (2026-11-21, implicit refinement).
