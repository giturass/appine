# Program execution (kernel/exec) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/exec"`
>
> Last distilled: 2026-11-21 (HEAD = 125f3d00)
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

## Superseded

- ~~`(st_dev, st_ino)` `st_value` symbol cache and duplicated ELF scanners in f2690b02, dc43dc57 and fd91c633~~ → replaced by **D2** in 9b3b6860 (2026-11-21).
- ~~Scanning arbitrary executables/shared libraries and matching glibc internal IFUNC memop names in f2690b02, dc43dc57 and 9b3b6860~~ → narrowed by **D2** in 6b59a1b4 and c8f01dbf (2026-11-21, implicit refinement).
- ~~Adding the `sha2` crate dependency for bundled musl verification in 6b59a1b4 and c8f01dbf~~ → replaced by **D3** in 189c6c98 (2026-11-21).
