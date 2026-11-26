# android/native Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/native.md` for the paired decision history, including pre-split decisions for android/build and android/tests.
>
> Verified: 2026-11-10 (full mapping: 3 research concerns; 16 claims checked by 2 independent verifiers — 14 confirmed and 2 partial, corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's browse JNI errno-to-exception mapping alongside the retained four-argument start contract with pre-registration shared-storage mounting)

## Responsibilities

`android/native` connects the Kotlin app to the Rust kernel: the kernel handle table, JNI
entry points, error and panic handling, stderr to logcat, the guest browser client and the Venus renderer.

Root: `hosts/android/src/lib.rs`, `hosts/android/open-url.c`,
`hosts/android/src/gpu.rs`, the native sources, Android buffer patch and Venus teardown patch in `hosts/android/gpu/`, and the Kotlin
files `Native.kt`, `GpuService.kt` and `MainApplication.kt`.

The build, manifests, assets and release packaging are `android/build`; instrumentation is
`android/tests`. `Machine` lifecycle belongs to `kernel/boot`, process API to `kernel/process`
and store calls to `kernel/store`. Terminal shim/JNI ownership remains `android/vtcore`,
with view, gesture and rendering portions in `android/vtview`, `android/vtgestures` and
`android/vtrender`.

## Key types

- `MACHINES` — a mutex-protected map from handle (`jlong`, from `NEXT_HANDLE`, counting up from 1
  and never reused in a process) to `RegisteredMachine` (`Arc<Machine>` plus `has_gpu: bool`); a poisoned lock is recovered. `vt.rs` looks
  kernels up in the same table through `machine(handle)`.
- `Native` — `internal object` with 41 `@JvmStatic external` functions, 19 of them
  `@Throws(IOException::class)`; its initialiser loads the library and calls the private
  `init(BuildConfig.DEBUG)`.
- `guarded!` — the macro every JNI body runs in: `(name, fallback, body)`, or
  `(name, throws env, fallback, body)` for the functions Kotlin declares `@Throws`.

## Public entry points

- Init: `init(verbose)` (private; stderr redirect, debug log).
- Store: `importRootfs`, `syncRootfs`, `writeFile`, `readFile` (null on `ENOENT`).
- Browse: `browseStat`, `browseList`, `browseOpen`, `browseSniff`, `browseSearch`, `browseGenerations` (read);
  `browseImport`, `browseCreate`, `browseRemove`, `browseRename`, `browseMove`, `browseOpenWrite`, `browseWritten`
  (through the store's change path; `browseWritten` is not `@Throws` and ignores every error).
- Kernel: `start(store, tier, gpu, sharedStorage)` (GPU probing defaults to false; the nullable
  fourth argument defaults to `Environment.getExternalStorageDirectory().absolutePath`,
  and null disables mounting for isolated callers; 1 = Tier 1, else Tier 0; `gpu = true`
  probes `:venus` and attaches its renderer when supported; false avoids binding; the kernel starts with
  `debug.exception-trace` at 1, so guest crashes reach the kernel log and with it the bug reports;
  0 and an `IOException("cannot start: …")` on failure), `hasGpu(machine)` (whether the registered handle has a host GPU renderer; false if stopped or panicked; does not take the BKL), `boot`, `setRoutes`, `takeListens`,
  `takeKills`, `bklStall` (the latest too-long hold of the BKL as
  `<id>\t<seconds>\t<report>\t<end record or empty>`, tabs and line breaks in the last two turned
  into spaces, or null; it does not take the BKL), `takePower`, `processes`, `guestCpuTime`
  (live-plus-exited guest CPU nanoseconds under the BKL; −1 for a stopped handle or caught panic), `loginRuleInputs` (inode, size, mtime and ctime of the five rule inputs under one BKL hold; four zeros for a missing path), `takeChangedDirs`,
  `trimMemory`, `shutdown`, `stop`.
- Consoles and processes: `openConsole`, `spawn` (negative console = the app's stdio), `read`,
  `write` (until all bytes are written), `resize`, `closeConsole`, `waitFor`, `consoleCwd`. The app
  itself no longer calls `read` or `resize` (the terminal's pump and resizes go through `vt.rs`);
  `MachineTest` does.

## Data flow / lifecycle

### Handles

- When `Native.start` receives `gpu = true`, the nonexported `:venus` service probes the hardware under the app UID. `GpuService.connect` binds with `BIND_AUTO_CREATE | BIND_IMPORTANT`, transfers the socket descriptor at most once via an `AtomicReference`, awaits up to 3 s for `onServiceConnected` when OEM schedulers (such as Samsung `FreecessController` during activity switches) return false from `bindService` while delivering the binding asynchronously, and calls `close()` (including `unbindService`) on failure. On success
  `Native.start` supplies an Android renderer to the machine and records `has_gpu = true`; when `gpu = false`, `:venus` is not bound and `has_gpu` is false. Each DRM context uses a seqpacket
  connection to a service thread. The application normally imports coherent Android Hardware Buffers on its
  mapping device. If that probe fails, a second two-device copy tests CPU export. On success the machine
  process maps the original coherent allocation and sends its AHB to the service on a per-context allocation
  socket. The decoder exposes the probed GPU with the CPU mapping flags at the GPU import index.
  Pending exports are keyed by Venus memory ID until DRM blob creation takes the mapping, Vulkan frees it,
  or the context disconnects. A retirement thread holds submitted buffers through their fence and handles
  memory release and Binder unbinding. Context teardown waits for the GPU in the service process.

- `start` parses the nullable shared-storage path inside `guarded!`, builds `MachineOptions`
  (tier, exception trace), starts a renderer-aware `Machine`, mounts the supplied path at `/storage/emulated/0`
  and `/sdcard`, then registers it. A mount configuration error throws `IOException` and returns
  0 before registration; missing host access is deferred to guest operations. GPU probing defaults to false; calls without an explicit
  shared-storage path use the default path; the native descriptor is `(Ljava/lang/String;IZLjava/lang/String;)J`.
  Every call clones the `Arc` under the table lock and releases the lock before working, so a
  blocked call keeps its kernel alive across a concurrent `stop`.
- `stop` removes the handle and then kills everything; `shutdown` runs the inittab shutdown
  (poweroff, 30 s) while the handle is still registered and then removes it. Both drop the removed
  `Arc` only after the table lock is released, since the last reference's drop (`kill_all`, sync,
  joining the timer thread, stopping the watchdog) can take long. Whichever thread finishes the
  last call on a removed kernel runs that drop.
- After the kernel is gone: `read` and `write` return −1, `waitFor` −9, `openConsole` and `spawn`
  throw "the machine is stopped", `takeListens`, `takeKills` and `takeChangedDirs` return empty
  arrays, `bklStall`, `loginRuleInputs` and `consoleCwd` null, `takePower` and `processes` 0, `guestCpuTime` −1, and the rest
  (`boot`, `setRoutes`, `resize`, `closeConsole`, `trimMemory`, `shutdown`, `stop`) do nothing.
- `browseImport` calls an `IntConsumer` synchronously with a borrowed staging fd, returns the
  encoded name after publication, and propagates any exception thrown by the writer. All throwing
  browse calls (`browseStat`, `browseGenerations`, `browseList`, `browseOpen`, `browseSniff`,
  `browseSearch`, `browseImport`, `browseCreate`, `browseRemove`, `browseRename`, `browseMove`,
  `browseOpenWrite`) map store/browse errnos via `browse_error`: `ENOENT`/`ENOTDIR` to
  `FileNotFoundException`, `EEXIST` to `FileAlreadyExistsException`, `EACCES` to
  `AccessDeniedException`, and all other errnos (`ENOSPC`, `EISDIR`, `EINVAL`, `ENAMETOOLONG`,
  `ELOOP`, `EIO`, etc.) to `IOException`. Other runtime calls use `IOException` or sentinel values.
  `openConsole` and `resize` clamp rows and columns to 1–65535.
- `setRoutes` parses lines of `<hex destination>/<prefix> <hex gateway or -> <interface>` (later
  fields ignored); hex fields must be ASCII and even, the destination 4 or 16 bytes and the gateway
  the same length; the metric is 0 for IPv4, and for IPv6 1024 for a default route, else 256.
  Malformed lines are dropped silently.

### Callers

- GPU context setup attaches its caller to the JVM to bind the service. The retirement thread attaches
  to release the binding. Other runtime JNI callers include the main thread (`bklStall`, and `openConsole`/`spawn` from a tab's
  start), `appine-start` (`start`, OpenRC setup's `spawn`/`waitFor` and `boot` when setup installs it), the service's worker (the poll's calls, `setRoutes`,
  `consoleCwd`, `trimMemory`, `stop`, `shutdown`, the rules refresh's `spawn`), `appine-login-rules` (the refresh's `waitFor`), `appine-boot`
  (`spawn`, `waitFor`, `boot` only when setup did not already boot), each tab's `vt-writer` (`write`) and `vt-waiter` (`waitFor`),
  the provider's binder threads (browse functions, `readFile`), and each tab's `vt-pump`, which reads
  the console through `Machine::read_console_run_timeout` in `vt.rs` and calls back into Java from inside
  `pump`.

### stderr and panics

- `init` redirects stderr once: creates a pipe, spawns the `stderr-log` thread first (writing each
  line to logcat with tag `appine`, priority INFO; lines containing NUL are dropped), and only then
  redirects fd 2 via `dup2` (closing `write_end` if `write_end != 2`). A failing `pipe` or thread
  spawn closes any open pipe ends without touching fd 2; a failing `dup2` closes `write_end` so the
  reader exits cleanly while fd 2 stays as it was. `verbose` sets `APPINE_LOG=1`.
- Panics are contained at two layers. The kernel wraps most `Machine` methods in `host_call`,
  which turns a panic into an error of the call when containment is on (`APPINE_ON_BUG=kill`, or
  by default whenever debug assertions are off, which is always on Android) and aborts the process
  otherwise. Everything else is caught by `guarded!`: `Machine::wait`, `processes`, `cpu_time_ns`, `take_power`,
  `stall`, `sync_store`, the Tier 1 pool trim, the wait loops of console reads and writes, the
  unwrapped parts of `boot`, `shutdown`, `kill_all` and `Machine`'s drop (their wait loops, flags,
  inittab plan parsing and thread joins; their signals, inittab reads, spawns and syncs run in
  `host_call`), and the JNI code itself, `vt.rs` included. `guarded!` runs the body in
  `catch_unwind`: the panic message reaches logcat through the panic hook's stderr, a
  line names the function, and the call returns its fallback (−1 for console reads and writes,
  `openConsole`, `spawn`, `browseOpen` and `browseOpenWrite`; 0 for `start`, `takePower` and
  `processes`; −9 from `waitFor`; null for objects; nothing for unit). The `@Throws` functions
  also throw `IOException("internal error in …")` unless an exception is already pending. Kernel
  state a panic left half changed (a poisoned lock, a held BKL) is not repaired, so later calls
  may fail or wait.

### Application startup

- `MainApplication.onCreate` skips app-wide setup in `:venus`. The main process registers the GPU
  application context and installs `Privacy` (`android/privacy`) and `Diagnostics`
  (`android/reports`). Manifest registration and provider configuration are in `android/build`.

### Guest browser client

- `android/build` packages `hosts/android/open-url.c` as the static `appine-open-url` asset
  for either distro; no guest package is needed.
- The client rereads `/etc/appine/browser`, connects to IPv4 loopback, sends token and URL lines
  and waits up to 5 s total for an `OK` reply. Invalid arguments/configuration, connection failures,
  refusal or a missing reply print an error and exit 1; URLs and tokens are never logged.
  Only HTTP(S) URLs up to 8192 bytes are accepted; the service performs strict UTF-8/URI checks.
  A timeout means no acknowledgment: it cannot prove no launch occurred or cancel buffered TCP requests.

## Dependencies (inbound / outbound)

### Inbound

- `TerminalService`, `VtSession`, `ConsolePty`, `Rootfs`, `Documents` and `android/tests`
  call `Native`; `vt.rs` uses `guarded!`, `machine`, `string`, `throw` and the handle table.
- `android/build` compiles and packages this bridge and the guest browser client.

### Outbound

- `appine_kernel` (`Machine`, `MachineOptions`, routes, store and browse functions), `jni` 0.21,
  `libc` and Android `liblog`; terminal JNI also uses `libjnigraphics`.
- `MainApplication` installs `android/privacy` and `android/reports` diagnostic capture.
- `android/service` receives the guest browser client's requests; `android/build` supplies its asset.

## Invariants and gotchas

- JNI symbol names hard-code `io.github.mthli.appine.Native` (and `VtNative` for the libghostty-vt
  terminal's functions); each `external fun` has exactly one `Java_…` function.
- `Native.start`'s default path and JNI GPU and storage parameters must stay in sync; Settings owns Android's
  all-files grant flow, while the kernel performs host access under the app's credentials.
- The crate is `#![cfg(target_os = "android")]`, so it is empty on other hosts, where `build.rs`
  only prints its rerun lines.
- Every JNI function's body goes in `guarded!` (with `throws env` exactly when Kotlin declares
  `@Throws`); the macro is defined before `mod vt` so `vt.rs` can use it, and its closure moves the
  parameters, so a `return` inside returns from the body only.

## Confirmed bugs / technical debt

- A failed string conversion with no pending exception makes void calls return silently
  (unreachable from the non-null Kotlin signatures).

## Open questions

- Successful hardware-backed 16 KiB-page operation still awaits a device test. Both tested AHB paths use one physical device.

## To verify

- Real-device shared-storage grant/revoke behavior and vendor restrictions; source-level JNI and
  Kotlin signature checks and both-tier host tests do not establish Android permission UI behavior.
- The static browser launcher on Debian and a 16 KB-page device; current bridge tests use Alpine on API 34.
