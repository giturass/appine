# Host CLI and integration (harness/cli) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: harness/cli"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)
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

### D3: `appine-run --stats` reports compiled strip-mined fast loops

- **What**: `print_stats` in `hosts/cli/src/main.rs` prints the `fast loops` counter from `DbtStats::fast_loops`.
- **Why**: Profiling and benchmarking runs need visibility into how many strip-mined fast loops Tier 1 compiled.
- **Tradeoffs**: Adds one line to `--stats` stderr output.
- **Watch out**: Scripts that strictly check `--stats` line counts will see one additional line.
- **Source**: 49585f4e

### D4: End-to-end kernel regression suites run as static C binaries in per-test empty rootfs stores

- **What**: `hosts/cli/tests/guest_programs.rs` runs standalone static C regression suites (`stability`, `isolation`, `fs_mm`, `ipc_poll_unix`, `fs_io_regressions`, `sig_ptrace_tty`) across Tier 0 and Tier 1 in per-test empty stores via `run_guest_in_empty_rootfs` (alongside host-driven `doomed_elf_fails_to_spawn` and `sig_ptrace_tty_console_write_after_end`), with `isolation.c` calling `mount()` before `pthread_create()` for its FUSE daemon.
- **Why**: Syscall, mount, VFS, FUSE, memory, signal, ptrace, tty, IPC, and Tier 0/Tier 1 boundaries need end-to-end guest verification beyond Rust unit tests, and starting `isolation.c`'s FUSE thread before `mount()` caused intermittent pre-mount `POLLERR` hangs.
- **Tradeoffs**: Each suite invokes `tar` to build a tiny temporary store and adds roughly 0.4–1 s per suite across both tiers plus dedicated guest C test code.
- **Watch out**: Suites depend on `/dev/fuse` and `/sys/fs/cgroup` at boot, clean `/tmp` at startup so both tiers reuse the empty store safely, and should synchronize via pipes, `waitpid`, or kernel state rather than short fixed sleeps (such as 30–40 ms waits) that can flake on loaded CI hosts.
- **Source**: 849bf98a, b51818cf, 0e02d7cd, 15347732, ab694aab, 13dd5ae4

### D5: Networking guest regressions are self-contained without rootfs or Linux UAPI headers

- **What**: `tests/guest/net_regressions.c` (wired as `guest_programs::net_regressions`) exercises networking fixes across Tier 0 and Tier 1 without a rootfs or external network, embedding self-contained Linux UAPI structs so `musl-gcc` compiles cleanly.
- **Why**: Networking fixes across `kernel/net`, `netns`, `netlink`, `rawicmp`, and `nft` need end-to-end Tier 0 and Tier 1 regression coverage without depending on the Alpine rootfs tarball or external connectivity.
- **Tradeoffs**: Duplicating Linux UAPI constants and structs inside `tests/guest/net_regressions.c` adds local boilerplate in exchange for header-free `musl-gcc` builds.
- **Watch out**: The dual-stack `AF_INET6` DNAT test skips gracefully when the host lacks a non-loopback IPv4 interface, whereas `scripts/dev` and CI containers provide `eth0` and run the full path.
- **Source**: a1fd0beb

### D6: C guest regression suites share `run_c_guest` and focused C setup and assertion helpers

- **What**: `hosts/cli/tests/guest_programs.rs` shares `run_c_guest` for rootfs-free C suites (`threads`, `net`, `net_regressions`), while the new C regression suites share focused assertion and protocol/setup helpers (`CHECK_ERR`, overlay/FUSE/netlink/nft/ptrace builders) and pass thread fd arguments by value.
- **Why**: Repeated build/run checks in `guest_programs.rs`, verbose syscall-error and protocol boilerplate, and stack-lifetime thread arguments obscured test intent and risked lifetime bugs.
- **Tradeoffs**: Individual test cases read through small shared helper wrappers instead of raw inline syscalls.
- **Watch out**: Helper failure macros must continue reporting line numbers and `errno` clearly so regressions stay easy to diagnose.
- **Source**: 3a90a0ef

## Superseded

- ~~Detached Android DNS preload thread and host `on_tty` shell check in 86d7523c~~ → replaced by **D2** in 73394ffd (2026-11-21, implicit refinement).
