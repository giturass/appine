# Android build and packaging (android/build) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: android/build"`
>
> Last distilled: 2026-11-21 (HEAD = 125f3d00)
>
> Decisions on android/build made before it was split from android/native keep their `android/native` tags and live in `.agents/decisions/android/native.md`: D2–D7, D10, D12–D14, D20–D22, D24–D26, D28 and the dependency portion of D32.

## Active

### D1: Android packaging is separate from runtime JNI

- **What**: android/build owns build configuration, dependencies, packaged assets and release sources, while runtime JNI remains in android/native.
- **Why**: The extracted subsystem needs a focused architecture reference with explicit integration boundaries.
- **Tradeoffs**: Pre-split decisions remain in the parent snapshot and related changes may require several maps.
- **Watch out**: The split preserves inherited verification and open issues; it is not a fresh full audit.
- **Source**: 60790c14; 39e55b4b

### D2: The manifest explicitly exposes supported app languages

- **What**: The application references locale_config for en, zh-CN, zh-Hant, ko and ja, enabling the Android 13+ picker while Android 11–12 follow the system language.
- **Why**: System language choices must match the translations the app ships.
- **Tradeoffs**: The explicit list and build map require manual synchronization, with UnusedAttribute suppressed for the application declaration.
- **Watch out**: Vendor picker behavior remains unverified and the application-level suppression also covers later unused attributes on that element.
- **Source**: e406fc21, 5bd37526; 39e55b4b

### D3: The exemption request starts with a user tap

- **What**: Declare REQUEST_IGNORE_BATTERY_OPTIMIZATIONS for the package-specific system confirmation opened from the terminal banner.
- **Why**: Android requires the permission declaration for this direct request.
- **Tradeoffs**: The APK carries an additional permission for an optional prompt.
- **Watch out**: The effect on long-running commands still needs physical-device measurement.
- **Source**: 7a931d97

### D4: Both Gradle native build paths resolve the same Zig executable

- **What**: Browser and Cargo tasks use the nonblank local.properties zig.path first, then ZIG, then zig on PATH, through a shared provider.
- **Why**: An IDE Gradle daemon can lack the shell environment that locates Zig.
- **Tradeoffs**: Developers maintain a machine-local override, and direct Cargo invocations still use ZIG or PATH.
- **Watch out**: An invalid nonblank local path must fail without silently selecting a different compiler.
- **Source**: 757b91c8

### D5: Release APKs shrink Java, resources and native code

- **What**: Use R8 and resource shrinking with JNI method and VtSession.on* keep rules, build native release code with full LTO and one codegen unit in android-release, and build debug APKs with release plus test-hooks and borrow-check.
- **Why**: The measured arm64 APK shrank from 27.54 to 16.01 MiB while debug rebuilds kept their faster profile.
- **Tradeoffs**: On the recorded M2 Pro a warm-cache JNI edit took 31.12 s with android-release versus 1.29 s with release.
- **Watch out**: Keep new native callbacks explicitly when they fall outside the pattern, and archive the matching R8 mapping.
- **Source**: 7b3e57c5; f674e98c

### D6: Cargo and Android use the same release version

- **What**: Keep the shared Cargo version and lockfile package entries synchronized with Android's release version (bumped to 1.0.1 and `versionCode 2`), and ignore local `android/app/release` exports.
- **Why**: Native version labels should identify the same Appine release as the APK while keeping local exports out of Git.
- **Tradeoffs**: Cargo and Gradle still declare versions separately and require manual synchronization.
- **Watch out**: Check both declarations and the lockfile when preparing a release.
- **Source**: 295fbe95, 3a7019eb

### D7: The pinned virglrenderer Venus decoder is verified, patched separately and built with CMake

- **What**: `scripts/fetch-virglrenderer` verifies the pinned virglrenderer 1.3.0 archive and re-extracts after clearing stale directories whenever `src/venus/vkr_renderer.c` is missing, CMake applies `android-blob.patch` and `venus-teardown.patch` as separate ordered inputs for debug and release APKs, and static notices and release sources include it.
- **Why**: Debug and release APKs need reproducible Venus builds, independent patch tracking for blob allocation versus teardown, and recovery from partial trees left by `rust-cache` target cleaning.
- **Tradeoffs**: Adds build prerequisites, tracks two separate patches tied to virglrenderer 1.3.0, and relies on `src/venus/vkr_renderer.c` rather than verifying every extracted file.
- **Watch out**: Upgrading virglrenderer requires checking patch compatibility, attribution and the `vkr_renderer.c` layout check, and a partially corrupted tree containing that file will not trigger re-extraction.
- **Source**: 87c7d9db, e94c49df, 87f1094f

### D8: New Alpine installs package pinned offline OpenRC packages

- **What**: Pin four Alpine OpenRC packages, share the staged `libcap2` package with bubblewrap, and include their licenses and source origins in the Alpine notice.
- **Why**: First launch must set up OpenRC offline with verifiable packages and matching distribution attribution.
- **Tradeoffs**: The four package downloads add 460,050 bytes to the bundled assets.
- **Watch out**: Package revisions removed from Alpine mirrors require refreshed pins and updated notices.
- **Source**: d0ff9a31

### D9: The Venus renderer target optimizes independently for size

- **What**: Set `-Oz` and `-flto=full` as private compile options on `appine_venus` in `hosts/android/gpu/CMakeLists.txt`.
- **Why**: The Venus decoder can shrink independently of the CPU engine and kernel without penalizing their build flags.
- **Tradeoffs**: Full LTO shifts GPU code generation into the final link.
- **Watch out**: Device performance with the size-optimized renderer has not been measured.
- **Source**: b37ad74a

### D10: Debug APKs coexist with release via a `.debug` ID and soft yellow icon outline

- **What**: Set `applicationIdSuffix = ".debug"` in `buildTypes.debug` (keeping `namespace` at `io.github.mthli.appine`, provider authorities on `${applicationId}` and the shared `Appine` label) and override `ic_foreground_stroke_color` to `#F5DF4D` in debug resources.
- **Why**: Debug builds need a separate package ID and a harmonious visual cue so they can be installed alongside release builds.
- **Tradeoffs**: The softer yellow has slightly less contrast against the white icon body, and Android themed/monochrome icons render without the colored stroke while sharing the `Appine` label.
- **Watch out**: Side-by-side device installation, instrumentation under `io.github.mthli.appine.debug` and launcher icon rendering remain unverified on device.
- **Source**: 1afcffbc, 8ab3b92b

## Superseded

- ~~One --release Cargo profile for every APK in android/native D2~~ → replaced by **D5** in 7b3e57c5 (2026-11-17).
- ~~Material Yellow A700 (`#FFD600`) debug icon stroke in 1afcffbc~~ → replaced by **D10** in 8ab3b92b (2026-11-21).
