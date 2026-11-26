# android/vt Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/vt.md` for the paired decision history (it still holds the pre-split decisions for `android/vtcore`; earlier decisions remain D2, D5, D6, D8, D16, D17, D32, D33, D35–D39 and D42–D49 in `.agents/decisions/android/terminal.md`).
>
> Verified: 2026-11-23 (full mapping: 3 research concerns; 9 claims checked by 2 independent verifiers — 9 confirmed; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: OSC 52 read capture, preview dismissal and writer invalidation across user resets and program RIS)

## Responsibilities

`android/vt` owns the Kotlin session of each terminal tab and its kernel console wrapper:

- opening the console and spawning `login.sh` lazily on the first known grid, creating or restoring
  the native terminal, starting the `vt-writer`, `vt-pump` and `vt-waiter` threads, resizing,
  waiting for exit and closing the console exactly once;
- bridging native `vt-pump` callbacks onto the main thread (`Events`), queuing asynchronous OSC 52
  clipboard reads, and managing OSC 9;4 progress and OSC 7501 program-status records;
- staging restored snapshots/transcripts/notices, serving capped primary-screen transcripts and
  three-way native snapshots for persistence, and executing session-side message, cursor, clear
  and reset actions.

Root: `VtSession.kt`, `ClipboardReads.kt` and `ConsolePty.kt` in
`android/app/src/main/java/io/github/mthli/appine/`.

Outside the module: `VtNative`, JNI, the pump implementation, terminal ownership and locks,
protocol parsing, command timing, snapshots, reset semantics and compression (`android/vtcore`);
view lifecycle, input and search (`android/vtview`); gestures, selection and scrolling
(`android/vtgestures`); frame encoding and drawing (`android/vtrender`); the surrounding screen
(`android/terminal`); session ownership, notifications and persistence policy (`android/service`,
`android/reports`); the kernel console (`kernel/tty`); kernel JNI (`android/native`); and the
login script and prompt-mark producers (`android/setup`).

## Key types

- `VtSession` — per-tab session owned by `TerminalService`: holds `id`, `ConsolePty`, `machine`,
  `Events`, `@Volatile tab` (`0L` until created; never reset on `release`), `@Volatile view` (read
  on `vt-pump`), `console` (`pty.console`), `consoleOpen` (`pty.console >= 0 && !hungUp`),
  `isRunning` (`exit == null`, true before start as well), `busy` (`isRunning && tab != 0L &&
  VtNative.busy(tab)`), restore staging (`restoredSnapshot`, `restoredText`, `pending`),
  `lastTranscript` (capped to `Tabs.MAX_TRANSCRIPT` = 256 K chars), worker-only `@Volatile` save
  metadata (`resolvedLogin`, `savedSnapshot`), cursor defaults (`cursorStyle`, `cursorBlink`),
  grid cache, main-thread `progress` (`Progress?`, 15 s `dropProgress` timer) and `status`
  (`Status?` selected from `LinkedHashMap<String, Status> records`, LRU-ordered, max 64),
  synchronized `reports` handoff buffer from `vt-pump`, `clipboardReads` (`ClipboardReads`), `AtomicBoolean
  hungUp`, and single-thread `vt-writer` executor.
- `ClipboardReads` — main-thread OSC 52 read queue per session (max 64 targets, 60 s wait timer
  and active preview). Each reply carries a `Token` with the local queue generation and the
  native generation applied to that batch. The latest observed native generation is atomic.
- `VtSession.Events` — main-thread callback interface implemented by `TerminalService`:
  `onTitleChanged`, `onBell`, `onClipboard`, `onNotification`, `onClipboardRead`,
  `onStatusChanged`, `onCommandFinished`, `onTmuxDetached`, `onFinished`.
- `VtSession.Progress(state, percent)` & `VtSession.Status(id, state, kind, percent, title,
  message)` — value types for OSC 9;4 progress and OSC 7501 status; companion defines protocol
  constants (`PROGRESS_*`, `STATUS_*`, `KIND_*`) and localized `describe(context, status)`.
- `ConsolePty` — per-tab kernel PTY handle and login-shell launcher (`machine`, `script`, `login`,
  `cwd`, optional `ConsoleTracker`, `@Volatile console` starting at `-1` and retained after
  `close`, `@Volatile openedEpoch`, `@Volatile closedEpoch`, `pid`). Companion holds `LOGIN_AUTO`,
  `LOGIN_ROOT`, cached `script(context)` (`login.sh`), `argv(script, login, cwd)` and `ENVIRONMENT`.

## Public entry points

- Lifecycle: `VtSession.start`, `resize`, `write`, `finishIfRunning`, `release`, `ownedConsoleAt`;
  `ConsolePty.start`, `waitFor`, `close`, `script`, `argv`, `ENVIRONMENT`, `LOGIN_AUTO`,
  `LOGIN_ROOT`.
- State and saving: `id`, `login`, `resolvedLogin`, `savedSnapshot`, `tab`, `view`, `console`,
  `consoleOpen`, `title`, `isRunning`, `busy`, `cwd`, `setRestored`, `transcriptText`,
  `takeSnapshot`, `showMessage`, `setCursor`, `clear`, `reset`.
- Program reports and native pump callbacks: `progress`, `status`, `statusSeen`, `describe`,
  `answerClipboardRead`, `Events`; JNI callbacks invoked on `vt-pump`: `onOutput`, `onTitle`,
  `onBell`, `onClipboard`, `onNotification`, `onClipboardReset`, `onClipboardRead`, `onProgress`, `onStatus`,
  `onForeground`, `onCommandFinished`, `onTmuxDetached`.

## Data flow / lifecycle

### Start, execution and teardown

- `TerminalService.createSession` builds `ConsolePty` and `VtSession` and calls `setCursor`;
  restored tabs also call `setRestored(text, snapshotLoader, notice)`. While unstarted (`tab == 0L`),
  `isRunning` is true, `busy` is false, `console` is `-1`, `transcriptText` returns `null` (so
  `saveTabs` preserves the original unshown tab record), and `showMessage` appends yellow ANSI
  lines to `pending`.
- `VtSession.start(cols, rows, cellWidth, cellHeight)` runs once on the main thread when a view
  first reports its grid (`Host.onGrid`):
  1. Calls `ConsolePty.start(cols, rows)` -> `Native.openConsole(machine, rows, cols)` and
     `Native.spawn(machine, console, "/bin/sh", argv, ENVIRONMENT)` (passing `HOME=/root`, `PATH`,
     `TERM=xterm-256color`, `LANG=C.UTF-8`, `SHELL=/bin/sh`, `USER=root`, `LOGNAME=root`,
     `BROWSER=/usr/local/bin/xdg-open`, `NMAP_UNPRIVILEGED=1`), catching `IOException` into `error`.
  2. `createTerminal` invokes and clears `restoredSnapshot` and `restoredText`: tries
     `VtNative.restore` if a snapshot exists (logging and falling back on `0L`), else calls
     `VtNative.create` and prints `restoredText` if present; JNI `IOException` yields `0L`.
  3. **Terminal-creation failure (`t == 0L`)**: calls `hangUp()` and `exited(127)` (silent — no
     completion line, no `view?.onStarted()`, no threads, and later `showMessage` returns `false`).
  4. **Terminal initialized (`t != 0L`)**: sets `tab = t`, applies `VtNative.setCursor` before
     printing and clearing `pending`, and caches grid dimensions.
  5. **Console/spawn failure (`error != null`)**: prints `"\r\n[$error]\r\n"`, calls `hangUp()`,
     sets `exit = 127` directly (no `"[Process completed ...]"` line, no `writer`), calls
     `view?.onStarted()` and `events.onFinished(this)`, and returns without starting threads.
  6. **Normal start**: starts `vt-writer` (single-thread `ExecutorService`), non-daemon `vt-pump`
     (`VtNative.pump(t, this)`), and non-daemon `vt-waiter` (`pty.waitFor()`, `pump.join(500)`,
     then posts `exited(code)` on `main`), and calls `view?.onStarted()`.
- `exited(code)` (main thread, idempotent on `exit != null`): sets `exit = code`, calls `hangUp()`
  (cancelling queued `vt-writer` tasks via `shutdownNow()` before closing the console), calls
  `writer?.shutdownNow()`, cancels `dropProgress`, returns early if `released`, else calls
  `clearStatus()` (cancelling `dropProgress`, clearing buffered `reports`/`records`, zeroing
  `progress`/`status`, and firing `onStatusChanged` if any existed), prints
  `"[Process completed (code N | signal N) - press Enter]"` (omitting reason for exit 0),
  invalidates `view`, and fires `events.onFinished(this)`.
- `release()` (idempotent on `released`): sets `released = true`, calls `finishIfRunning()` ->
  `hangUp()` (`AtomicBoolean.compareAndSet(false, true)` cancelling queued writes with
  `writer?.shutdownNow()` before `pty.close()` so a closed console number reused by the kernel
  can never be closed twice or receive drained writes), calls `writer?.shutdownNow()`, cancels
  `dropProgress`, and calls `VtNative.destroy(tab)` (removing the handle from native `TABS` while
  any running `vt-pump` retains its `Arc<Tab>` until return).

### Pump callbacks, clipboard, progress and status

- `onOutput()` runs directly on `vt-pump` without checking `released` and calls
  `view?.postInvalidateOnAnimation()`. All other native callbacks post to `main`: `onProgress` and
  `applyReports` guard `!released && isRunning`; `onTitle`, `onBell`, `onClipboard`,
  `onNotification`, `onCommandFinished` and `onTmuxDetached` guard `!released`.
  `onForeground` uses the progress and status queues.
- `ClipboardReads` retains up to 64 OSC 52 targets per session. The first read starts a 60 s
  main-handler timeout and notifies the service. Further reads share the first deadline and
  question. Excess requests receive empty replies immediately. The activity claims a batch
  before reading the clipboard and cancels the timer. An open preview has no timeout.
- An answer formats one ST-terminated OSC 52 reply per queued target with unwrapped base64
  text. Denial, timeout and an empty clipboard send empty payloads. Reset, shell exit and
  release cancel the timer, clear the batch and dismiss any preview without a reply.
- `onClipboardReset(generation)` publishes the generation on the pump thread before posting
  `resetTo` to main. `onClipboardRead(kind, count, generation)` rejects stale reads on the pump
  and checks again on main, where the session must still be running and unreleased. A newer
  read generation clears the old batch. An equal or older reset leaves the current batch alone.
- Progress (`OSC 9;4`): `onProgress` maps `PROGRESS_REMOVE` to `null`, else `Progress(state,
  percent)`. `setProgress` cancels and re-posts the 15 s `dropProgress` timer (`PROGRESS_TIMEOUT_MS`)
  before checking `p == progress`, so identical heartbeats extend the timeout without firing
  `onStatusChanged`.
- Status (`OSC 7501`): `onStatus` strips Unicode direction controls (`U+202A..202E`,
  `U+2066..2069`, `U+200E`, `U+200F`, `U+061C`) from `title` and `message` (not `id`) on `vt-pump`,
  appends to `synchronized(reports)`, and posts `::applyReports` when `reports.size == 1`.
  `applyReports` drains `reports` on `main`: `STATUS_CLEAR` clears all records when `id` is empty
  or removes `id` and any `id + "/..."` descendants; other states replace `id` at the tail of
  `records` (`LinkedHashMap`), evicting the oldest entry past `MAX_STATUS_RECORDS` (64).
  `updateStatus` selects the most urgent record (`blocked > error > done > working > idle`, ties to
  most recently updated) and fires `events.onStatusChanged` on value change.
- A command end or primary prompt expires earlier progress and transient status records. A later
  report in the same read survives. A foreground process-group change observed on a read without
  reports sends the same progress removal and ordered status expiry through `onForeground`.
  Done and error records remain until `statusSeen()` when the tab is in front. Shell exit clears all.
- `onCommandFinished(hasExit, exit, millis)` converts `exit.takeIf { hasExit }` and forwards to
  `Events`; `onTmuxDetached` forwards to `Events` (where `TerminalService` displays a notice).

### Saving, messages, actions and shell integration

- `transcriptText` (main thread): returns `null` when `tab == 0L`. Otherwise calls
  `VtNative.transcript(tab)`: a non-null result (primary screen changed) is truncated to its last
  `Tabs.MAX_TRANSCRIPT` (256 K) characters, cached in `lastTranscript` and returned; a `null`
  result (unchanged, alternate screen, or error) returns `lastTranscript.orEmpty()`.
- `takeSnapshot()` (service worker): returns `null` if `tab == 0L`, else forwards
  `VtNative.snapshot(t)`'s three-way result (`null` = unchanged -> keep `savedSnapshot`; empty
  `ByteArray` = failed / >16 MiB -> clear `savedSnapshot`; non-empty bytes -> write new snapshot).
  `resolvedLogin` caches `Rootfs.loginAccount(LOGIN_AUTO)` on the service worker on first save.
- `showMessage(text)` queues yellow ANSI lines in `pending` before `start()`, returns `false` if
  `started && tab == 0L`, or calls `VtNative.message` + `view?.invalidate()` (refused on alternate
  screen). `setCursor` updates defaults and applies via `VtNative.setCursor` + `view?.invalidate()`
  if started.
- `resize(cols, rows, cellWidth, cellHeight)` skips unchanged dimensions or `tab == 0L`, calls
  `VtNative.resize` (reflow + console `SIGWINCH`), and immediately passes any non-empty replies
  (e.g. mode 2048 size reports) to `write(replies)`. `write(data)` queues `Native.write` on
  `vt-writer` while `writer != null && isRunning && !hungUp.get() && pty.console >= 0`, rechecking
  `!hungUp.get()` inside the write runnable before calling `Native.write` (swallowing
  `RejectedExecutionException`).
- `clear()` calls `VtNative.clear(tab)`: `-1` (alt screen / gone) is a no-op; `0` invalidates
  `view`; `1` (at prompt) writes `^L` (`0x0c`) and invalidates. `reset()` clears clipboard work
  immediately, then returns early if `tab == 0L || released`. It applies the magnitude of a
  nonzero `VtNative.reset` result and writes `^L` for a positive result (at prompt). It calls `clearStatus()`
  (cancelling `dropProgress`, clearing buffered `reports`/`records`, zeroing `progress`/`status`,
  and firing `onStatusChanged` when any existed), invalidates `view`, and emits
  `events.onTitleChanged(this)`.
- `busy` is `isRunning && tab != 0L && VtNative.busy(tab)` (OSC 133 prompt state first, falling
  back to foreground-process detection for unmarked shells and busybox ash whose `PS1` lost its
  marks). `cwd()` calls `Native.consoleCwd(machine, pty.console)` only when `isRunning &&
  consoleOpen` (taking the kernel BKL on the caller's thread).

## Dependencies (inbound / outbound)

### Inbound

- `android/service` (`TerminalService`, `Notifications`): constructs/restores/saves/releases
  sessions (passing `ConsoleTracker` to `ConsolePty`), implements `Events`, reads
  `isRunning`/`transcriptText`/`console`/`consoleOpen`/`tab`/`id`/`title`/`progress`/`status`,
  calls `ownedConsoleAt`, mutates `resolvedLogin`/`savedSnapshot`, calls `setCursor`,
  `setRestored`, `showMessage`, `takeSnapshot`, `answerClipboardRead`, `statusSeen` and `describe`.
- `android/terminal` (`MainActivity`): calls `start`, `cwd`, `clear`, `reset`, `write`,
  `answerClipboardRead`; reads `id`, `tab`, `busy`, `isRunning`, `progress`, `status`.
- `android/tabbar` (`TabBarView`, `TabListView`, `TabMarks`, `ProgressLine`): reads `id`, `title`,
  `isRunning`, `progress`, `status`, `describe` and protocol constants.
- `android/vtview` (`VtView`): sets `view`, reads `tab`, calls `resize`.
- `android/vtcore` (`vt.rs`): invokes the session callbacks on `vt-pump`.
- `android/setup` / `android/settings` (`Rootfs`, `Settings`, `SettingsActivity`): reuse
  `ConsolePty.LOGIN_AUTO`, `LOGIN_ROOT`, `script`, `argv` and `ENVIRONMENT`.

### Outbound

- `android/vtcore` (`VtNative`): `create`, `restore`, `setCursor`, `print`, `pump`, `destroy`,
  `title`, `atPrompt`, `busy`, `transcript`, `snapshot`, `message`, `resize`, `clear`, `reset`.
- `android/native` (`Native`): `openConsole`, `spawn`, `write`, `closeConsole`, `waitFor`,
  `consoleCwd`.
- `android/service`: `VtSession.Events` and `Tabs.MAX_TRANSCRIPT`.
- `android/vtview`: `VtView` (`onStarted`, `invalidate`, `postInvalidateOnAnimation`).
- `android/setup`: `assets/login.sh`; Android framework (`Handler`, `Base64`, `R.string.status_*`).

## Invariants and gotchas

- `ConsolePty.start(columns, rows)` swaps argument order to `Native.openConsole(machine, rows,
  columns)`.
- `ConsolePty.console` retains its integer after `close()` (for kill-report routing to ended tabs
  via disjoint `[openedEpoch, closedEpoch]` lifetimes recorded through `ConsoleTracker` and checked
  by `ownedConsoleAt`); active-ownership checks must use `consoleOpen` (`pty.console >= 0 &&
  !hungUp.get()`), and `hangUp()`'s `AtomicBoolean` cancels queued writes (`shutdownNow()`) before
  closing the console at most once so a reused console number is never closed or written by another
  tab.
- `VtSession.tab` is never zeroed on `release()`; subsequent `VtNative.*` calls rely on `vt.rs`'s
  `TABS` lookup returning `None`.
- `openConsole`, `spawn`, `closeConsole`, `VtNative.resize` and `VtSession.cwd()` take the kernel
  BKL on the caller's thread (main thread unless called on the service worker); per-tab `vt-writer`
  isolates blocked PTY writes.
- `ConsolePty.ENVIRONMENT` sets `BROWSER=/usr/local/bin/xdg-open` without VT transport state.
- `VtNative.create` and `VtNative.restore` omit `@Throws(IOException::class)` in Kotlin though JNI
  throws `IOException` when the machine is stopped, caught by `VtSession.start`.
- If `openConsole` throws, `pty.console` remains `-1` and is passed to `createTerminal` (cast to
  `u32::MAX` in `vt.rs`), which is harmless only because `error != null` prevents `vt-pump` from
  starting and `pty.close()` guards `console >= 0`.
- Re-entrant `statusSeen()`: when a `STATUS_DONE`/`STATUS_ERROR` report arrives for the foreground
  tab, `updateStatus()` -> `onStatusChanged` -> `Notifications.status` calls `statusSeen()`
  synchronously and re-enters `updateStatus()` (terminating on the second pass).
- Both a program's RIS (via libghostty-vt callbacks) and `VtSession.reset()` clear `progress`,
  `dropProgress`, buffered `reports`, `records` and `status`.
- Same-read OSC 52 `?` requests collapse to the last clipboard target's `kind` in `vt.c`; separate
  reads preserve individual targets in `clipboardReads`. Clipboard replies go through the
  session's `vt-writer` after native terminal locks are released.
- Native `AppineVt` owns the clipboard generation for both `VtSession.reset()` and a program's RIS.
  Reads retain the generation captured under the terminal lock. The writer checks both token
  generations before calling `Native.write`. Once a write passes this final check, it can
  complete across reset, including when it is already inside the native console call.
- Release sessions and close consoles before stopping the kernel so `vt-pump` can return; native
  pumps must not hold a session-long `Arc<Machine>`.

## Confirmed bugs / technical debt

- **Shell mark coverage limits inherited from `android/vtcore`:** local unmarked shells (dash,
  mksh, tcsh, elvish, ash with overwritten `PS1`) now have foreground-process fallback for `busy`,
  command titles and exit-code-less completion timing, and Alpine `doas -s` preserves ash marks;
  remote shells over ssh without OSC 133 marks (where the local foreground process is `ssh`) and
  in-shell builtins in unmarked shells still stay busy without prompt marks, and prompt
  jumping/output selection/prompt taps still require OSC 133 marks.

## Open questions

- Should a status notification name the record's `app` when it has no title rather than the tab's
  title?

## To verify

- Session behavior on physical and 16 KB-page devices: progress/status from real programs (`cargo`,
  `systemd`, AI coding CLIs), clipboard copy toast on Android 12 and earlier, and end-to-end
  restore with Kitty images, bash prompt marks, alternate-screen saves, or across a libghostty-vt
  version change.
