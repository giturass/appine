# Android instrumentation (android/tests) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: android/tests"`
>
> Last distilled: 2026-11-21 (HEAD = 125f3d00)
>
> Decisions on android/tests made before it was split from android/native keep their `android/native` tags and live in `.agents/decisions/android/native.md`: D5, D8, the test portions of D9, D12–D14, D16, D19 and D23–D32.

## Active

### D1: Android instrumentation has its own maintenance boundary

- **What**: android/tests owns instrumentation source and verification entry points, while runtime behavior and build configuration retain their existing owners.
- **Why**: The extracted subsystem needs a focused architecture reference with explicit integration boundaries.
- **Tradeoffs**: Pre-split decisions remain in the parent snapshot and related changes may require several maps.
- **Watch out**: The split preserves inherited verification and open issues; it is not a fresh full audit.
- **Source**: 60790c14; 39e55b4b

### D2: GPU instrumentation exercises packaged drivers, discovery and worker teardown end to end

- **What**: `GpuTest` exercises packaged Alpine and Debian drivers for compute, mapping lifetime, default Venus-plus-llvmpipe discovery versus Venus-only `appine-gpu`, concurrent clients, allocator and retirement worker exit on peer death, restart and unsupported startup.
- **Why**: Host probes and compute outputs alone cannot establish driver discovery, guest integration or context resource cleanup across exits.
- **Tradeoffs**: Positive cases require capable hardware and fixtures, perform an extra compute run for discovery, and poll thread state while asynchronous cleanup finishes.
- **Watch out**: Fixtures must keep the software driver for discovery checks, thread exit cannot account for vendor-driver allocations, and device coverage depends on tested drivers and page sizes.
- **Source**: 87c7d9db, 9cafc90b, e94c49df

### D3: Alpine OpenRC first-login and upgrade migration have offline instrumentation coverage

- **What**: `MachineTest` and `LicenseTest` test offline failure/retry, starting `osclock` via `rc-service`, cache cleanup, persistent user removal, dependency-only upgrade migrations, interrupted setup with a repair login, isolated one-boot kernels and Alpine license-catalog coverage.
- **Why**: Package presence alone does not prove first-login service startup or upgrade preservation of ownership, configuration and user removal across restarts.
- **Tradeoffs**: Automated checks run offline with `osclock` and synthetic upgrade fixtures rather than live network packages.
- **Watch out**: Docker interoperability needs separate end-to-end verification when Alpine packages change, and custom user package sets can hit different `apk` dependency conflicts.
- **Source**: d0ff9a31, 7e85e8dc

### D4: Unrelated tests disable GPU probing while `GpuTest` verifies the default-off Settings toggle

- **What**: Non-GPU instrumentation tests pass `gpu = false` to `Native.start`, GPU tests pass `gpu = true` with `Native.hasGpu` checks, and `GpuTest.disabledByDefault` and `GpuTest.toggleRestartsKernel` verify Settings dialogs, cancellation, restart, render-node presence/absence and cleanup.
- **Why**: Instrumentation must verify the default-off contract and end-to-end Settings restart flow without paying `:venus` probe overhead in unrelated suites.
- **Tradeoffs**: `toggleRestartsKernel` drives `SettingsActivity` against the real app store and service and requires an unlocked device screen.
- **Watch out**: Coverage ran on Galaxy S23 (API 36), and the unavailable-device summary path was exercised only on probe failure rather than permanently unsupported hardware.
- **Source**: b605a0a3

### D5: Alpine bash startup seeding is tested across new imports and existing regular accounts

- **What**: `MachineTest` verifies `.bashrc` loading, `adduser -D` `/etc/skel` ownership and non-interactive `bash -lc` on new Alpine imports, and tests existing Alpine stores for regular `/bin/bash` accounts (`alice`), homeless accounts (`carol`), symlinked `.profile` (`dave`), `/bin/sh` accounts (`erin`), custom `.bashrc` preservation and deletion persistence.
- **Why**: Both fresh Alpine imports and upgraded stores with pre-existing accounts and dotfiles need on-device regression coverage for ownership, loading and non-shadowing rules.
- **Tradeoffs**: Tests run against isolated temporary stores with bundled bash installed up front rather than driving `TerminalService` across an app upgrade, adding slight runtime.
- **Watch out**: Verified on a 4 KB-page API 36 device (SM-S9110) only; 16 KB-page devices and live `TerminalService` upgrade cold starts remain uncovered.
- **Source**: 9f3e93ed, 125f3d00
