# Program execution (kernel/exec) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/exec"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)
>
> Decisions on execve and the ELF loader made before kernel/exec was split from kernel/process keep their `kernel/process` tags and live in `.agents/decisions/kernel/process.md`: D7, D17, D31, D41, D43, D46 and D51.

## Active

### D1: kernel/exec is split out of kernel/process
- **What**: kernel/exec owns `loader.rs` and the execve section of `syscall/proc.rs`: arguments, targets, `#!` scripts, `ETXTBSY`, the effects of set-id bits and file capabilities, the ELF loader with doomed images, the point of no return, `exe_file`, the executable cache and the names of the program's mappings.
- **Why**: execve and the ELF loader are a self-contained path (6.1's `fs/exec.c` and `binfmt_elf.c`) changed often on their own, and the process map could no longer be read in one Read.
- **Tradeoffs**: Execution spans task teardown in kernel/process, host spawn in kernel/boot and timer clearing in kernel/time, alongside credentials, namespaces, memory, signals and file-related modules; tracing implementation and vDSO construction belong to kernel/ptrace and kernel/vdso.
- **Watch out**: A step added to the point of no return without updating its ordered list in the map.
- **Source**: b320f8e; 8a17e4a9; d053be24; 60790c14; 39e55b4b

### D2: Automatic Tier 1 memop discovery is restricted to SHA-256-verified bundled Alpine musl

- **What**: `loader.rs` verifies the bundled Alpine 3.24.3 musl image by SHA-256 (caching `Option<Arc<BundledLibc>>` by `(dev, ino, ctime, size)` up to 256 entries) and discovers `(file_off, kind)` entries via `parse_elf_memops`, validating ELF64 headers/sections/executable `PT_LOAD` containment and matching `STB_GLOBAL`/`STB_WEAK` standard C memop names only.
- **Why**: ELF symbol names alone cannot guarantee implementation semantics against guest-defined or `LD_PRELOAD`-interposed functions, and earlier raw `st_value` scanning broke when `p_vaddr != p_offset`.
- **Tradeoffs**: Static executables, glibc and other libc builds run normal Tier 1 guest code, and cache overflow at 256 entries causes a one-time re-scan.
- **Watch out**: Refresh the SHA-256 fingerprint and size whenever the bundled Alpine musl changes, and future glibc support will need internal IFUNC symbol matching re-added if desired.
- **Source**: f2690b02, dc43dc57, fd91c633, 9b3b6860, 6b59a1b4, c8f01dbf

### D3: Bundled musl verification uses an inline pure-Rust SHA-256 helper

- **What**: `core/kernel/src/loader.rs` implements a self-contained FIPS 180-4 `sha256` function with standard test-vector coverage instead of depending on the `sha2` crate.
- **Why**: Adding `sha2` pulled seven transitive runtime crates into `appine-android`, requiring matching license notices and dependency maintenance for a single one-time file hash.
- **Tradeoffs**: Software SHA-256 is slower than hardware-accelerated `sha2`, though it runs at most once per host process on the 723 KB bundled musl image.
- **Watch out**: Keep this helper scoped to fixed-size file verification in `loader.rs`, not general high-throughput or constant-time cryptographic use.
- **Source**: 6b59a1b4, c8f01dbf, 189c6c98

### D4: `execve` clears `TaskState::restart` at the point of no return

- **What**: `execve` clears `cx.t.restart = None` alongside `altstack` and `saved_sigmask` at the point of no return in `syscall/proc.rs`, paired with clearing it on `EINTR` conversion in `signal::deliver`.
- **Why**: Leaving `TaskState::restart` populated across `execve` allowed a subsequent `restart_syscall` in the new image to resume a stale sleep or futex.
- **Tradeoffs**: None.
- **Watch out**: Keep `execve`'s point-of-no-return state reset synchronized if future per-syscall restart state is added to `TaskState`.
- **Source**: 849bf98a

### D5: `execve` enforces `ETXTBSY` on scripts and `PT_INTERP`, pins mounts, and skips ptrace exec stops on doomed images

- **What**: `execve` checks `open_for_write` on the initial target, every `#!` hop and `PT_INTERP`, propagates `image.doomed` to `exec_done` so doomed images flush hardware debug slots, skip `ptrace::exec`/`ptrace::syscall_exit` and deliver the forced `SIGSEGV` immediately, and pins executable/interpreter mounts on segment VMAs (`label_image`/`interp_label`) and `ExeFile`.
- **Why**: `execve` missed `ETXTBSY` on nested `#!` scripts and `PT_INTERP`, reported ptrace exec/syscall-exit stops for doomed images, and left executable/interpreter mounts unpinned for `umount2`.
- **Tradeoffs**: `execve`/`execveat` return `Result<bool, Errno>` instead of `Result<(), Errno>`, and `exec` runs `evict_unlinked_tmpfs` after `close_on_exec`.
- **Watch out**: `LoadError::Interpreter` passes `Errno::ETXTBSY` straight through `load_error`, so future loader error wrapping must keep `ETXTBSY` intact.
- **Source**: 0e02d7cd

### D6: Secure `execve` computes `Args::arg_limit` before clamping the 8 MB stack limit

- **What**: `loader::Args` carries an explicit `arg_limit` computed via `loader::arg_limit(stack_limit)` in `syscall/proc.rs::exec` before clamping `stack_limit` to `STACK_SIZE` (8 MB) for secure execs, and `loader::build_stack` enforces `args.arg_limit`.
- **Why**: Clamping `RLIMIT_STACK` to 8 MB before computing the argument limit capped secure-exec arguments at 2 MB instead of Linux 6.1's up-to-6 MB pre-clamp limit.
- **Tradeoffs**: Adds an explicit `arg_limit` field to `loader::Args` (initialized in `machine.rs` and loader tests) to decouple stack sizing from argument-limit sizing.
- **Watch out**: `Machine::spawn` passes `arg_limit(STACK_SIZE)` directly because host-spawned processes start with the default 8 MB stack limit.
- **Source**: 2609ab43

### D7: Non-leader `execve` takeover clears stale `leader_serial` and `leader_tracer`

- **What**: `kill_other_threads` clears `g.leader_serial = None` and `g.leader_tracer = None` alongside `g.leader_exit = None` when a non-leader thread takes over `tgid` during `execve`.
- **Why**: Replacing the thread-group leader in a non-leader `execve` otherwise left stale `leader_serial` and `leader_tracer` fields on `ThreadGroup`.
- **Tradeoffs**: Adds two reset lines in `syscall/proc.rs` to keep `ThreadGroup` leader-exit invariants self-consistent across exec handover.
- **Watch out**: Keep `kill_other_threads` updated if additional leader-exit fields are added to `ThreadGroup`.
- **Source**: 13dd5ae4

## Superseded

- ~~`(st_dev, st_ino)` `st_value` symbol cache and duplicated ELF scanners in f2690b02, dc43dc57 and fd91c633~~ → replaced by **D2** in 9b3b6860 (2026-11-21).
- ~~Scanning arbitrary executables/shared libraries and matching glibc internal IFUNC memop names in f2690b02, dc43dc57 and 9b3b6860~~ → narrowed by **D2** in 6b59a1b4 and c8f01dbf (2026-11-21, implicit refinement).
- ~~Adding the `sha2` crate dependency for bundled musl verification in 6b59a1b4 and c8f01dbf~~ → replaced by **D3** in 189c6c98 (2026-11-21).
