# android/service Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/service.md` for the paired decision history (it still holds the decisions on notifications, fault reports and diagnostics made before they were split out into `android/reports`).
>
> Verified: 2026-11-15 (full mapping: 3 research concerns; 15 claims checked by 3 independent verifiers — 14 confirmed and 1 partial, scoped below; tab-index hash collision recorded)
>
> Maintained: 2026-11-22 (targeted verification only since the full mapping; latest change: list android/vtgestures alongside android/vtview and android/vtrender)

## Responsibilities

`android/service` is the app's foreground service, `TerminalService`, which owns everything that
outlives an Activity:

- the kernel handle (`machine`), starting, booting (inittab), shutting down, rebooting and
  replacing the kernel and its store;
- all terminal sessions (`VtSession`s, `android/vt`), and restoring tabs after the process
  was killed (`Tabs`);
- the ongoing foreground notification (id 1) and its actions, the wake lock, memory trimming;
- a 2 s poll that fetches kernel events (listens, kills, power requests, process count, changed
  directories, too-long holds of the BKL) and decides whether they become in-tab messages,
  lifecycle actions or notifications delegated to `android/reports`, and the routing of what
  programs ask of the app (bells, notifications, program statuses, clipboard writes and reads,
  browser URL opens via `BrowserBridge`) and of commands the shells' prompt marks see finish;
- the settings state that activities only display and forward (tier and Vulkan GPU in all builds,
  screen-off running policy, login account, file access, CJK characters filling two cells, the
  cursor's shape and blinking, whether the volume keys switch tabs, tab-list button visibility,
  distro switch), the preferences kept in `Settings`.

Root: `android/app/src/main/java/io/github/mthli/appine/TerminalService.kt`, `Settings.kt`,
`Tabs.kt`, `BrowserBridge.kt`.

Outside the module: non-ongoing notifications, channels, copyable fault reports and diagnostic
retention/export (`android/reports`); rootfs import, downloads, mirrors and `login.sh`
(`android/setup`); the Settings screen (`android/settings`); the terminal screen
(`android/terminal`) and its tab bar (`android/tabbar`); the view (`android/vtview`), gestures
and selection (`android/vtgestures`) and rendering (`android/vtrender`); sessions' internals and the console adapter (`android/vt`), native terminals
and compression (`android/vtcore`); the Files app provider (`android/documents`); JNI and the
kernel API (`android/native`, `kernel/boot`, `kernel/process`, `kernel/bug`).

## Key types

- `TerminalService` — a same-process service; `onBind` returns a `LocalBinder` whose `service` is
  the service itself.
- `Listener` — UI callbacks with no-op defaults, always on the main thread: `onProgress`,
  `onMachineReady(error)`, `onSessionsChanged`, `onBell` (haptics for a bell or program notification
  in the tab in front), `onClipboardRead`
  (a program in the tab in front, the current one, asks to read the clipboard), `onTabStatus` (a
  tab's progress or program status changed), `onSettingsChanged`,
  `onOpenUrl` (guest browser request; true acknowledges Android accepted it), `onNotice`, `onRestarting`, `onExitAll` (sessions redraw their view themselves). Activities
  register in `onServiceConnected` and leave in `onStop`; "UI visible" means at least one listener
  (the Settings fragment included).
- `worker` — a single-thread executor (`appine-worker`) for the calls that take a kernel handle
  and the BKL in the background (the poll's fetches, `setRoutes`, `consoleCwd`, `trimMemory` with
  the tabs' scrollback compression after it, `shutdown`, `stop`), together with what must stay
  ordered with them: saving tabs (their terminals' snapshots included), resolving an `auto` login, changed directories,
  and a replacement's mirror join and store reset.
- Session state (internal): `sessions` (every tab, ended ones included), `unshown` (restored tabs
  whose terminal does not exist yet, with their saved copy), `restore` (saved tabs from a killed
  run, kept until a start restores them), `ended` (why that run ended), `focus` (set only by the
  restore), `current` (written only by `MainActivity`; setting it takes the tab's notification and
  bell throttle away and, with the terminal Activity listening, marks the tab's statuses seen),
  `nextSessionId` (counting up from the clock, never wrapped); `sessionEvents` (title changed,
  bell, clipboard write, notification, clipboard read, progress or status changed, a command
  finished, tmux's control mode detached, the shell finished).
- Lifecycle state (internal): `exiting`, `starting` (a start thread is running), `transitioning`
  (restart or replace, between letting go of the old kernel and starting the new one),
  `booting` (boot work is outstanding), `destroyed` (late completions cannot restart the service),
  `pendingReplace` (a distro download that finished during a start or restart), `startError`,
  `progress`, `mirrorThread`.
- `GuestActivity` — the last guest CPU sample and activity timestamp used by
  the BUSY running policy; `RunPolicy` in `Settings` defines SLEEP, BUSY and ALWAYS.
- `BrowserBridge` — per-kernel random-port IPv4 loopback listener with a UUID capability that
  relays guest HTTP(S) open requests to the focused UI.
- `Settings` — the `settings` preferences: getters and plain setters taking a `Context` for the
  tier (default 1 in all builds), Vulkan GPU (`gpu`, default off), login, running policy and its remembered non-always choice,
  privacy mode (`privacy_mode`, default off), file access (`file_access`, default off and refused during privacy; old `system_documents` ignored), wide cells, the
  cursor's shape (stored as Ghostty's names) and blinking, and whether the volume keys switch tabs
  (on by default), and tab-list button visibility (`show_tab_list`, on by default);
  `clearLogin` for a replaced store.
- `Switch` — a distro download in progress (volatile `done`, `total`, `cancelled`): `switching` is
  the active one, `downloader` the one whose thread has not ended yet.
- `Tabs` — the `files/tabs/` store: `running` marker (the pid of the run that left it),
  `index.json` (recording the libghostty-vt version, `VtNative.version`, its snapshots were written
  with), transcripts named by content (`t-<128-bit SHA-256 prefix>.txt`; earlier versions wrote
  `t<i>.txt`, still read), terminal snapshots named by content and deflated
  (`s-<128-bit SHA-256 prefix of the snapshot>.snap`); `Tab(login, cwd, transcript, snapshot)`
  (the snapshot's file name, null for none), `Saved(tabs, current, time)`, `Killed(pid, saved)`;
  transcripts capped at 256 K chars, snapshots read back at most 16 MiB.
- Constants: poll 2 s, trim delay 60 s, periodic save 60 s, save-soon 2 s, commands notifying from
  10 s.

## Public entry points

- Lifecycle: `onCreate`, `onStartCommand` (EXIT_ALL, CANCEL_SWITCH, TOGGLE_KEEP_AWAKE, legacy
  COPY_REPORT forwarded to `Notifications.copyReport`; `START_NOT_STICKY`), `onBind`,
  `onTrimMemory`, `onConfigurationChanged`, `onDestroy`.
- Called by activities: `addListener`/`removeListener`, `createSession(account = login setting,
  cwd = null)`/`removeSession`, the `current` setter, `exitAll`, `setTier`, `setGpu`,
  `setRunPolicy`, `switchTo`/`cancelSwitch`/`canSwitch`,
  `setLogin`, `setFileAccess`, `setFillWide`, `setCursorStyle`, `setCursorBlink`,
  `setVolumeKeysSwitchTabs`, `setShowTabList`, `takeNotice`; state read by them: `machine`, `gpuAvailable`, `startError`,
  `progress`, `switching`, `sessions`, `focus`, the settings.
- Settings read without the service: `Settings.login` and `fileAccess` by `Documents`,
  `Settings.fillWide` and `Settings.showTabList` by `MainActivity` (in `onStart` and `onSettingsChanged`) and
  `Settings.volumeKeysSwitchTabs` by it at each volume key press; the service's getters read
  `Settings` too, and its setters write it and act on the change (`setVolumeKeysSwitchTabs` and `setShowTabList` only
  tell the listeners).
- `setFileAccess` saves the gate, revokes all provider URI grants when disabling via
  `Documents.revokeAccess`, refreshes roots and tells listeners. Settings confirms before enabling.

## Data flow / lifecycle

### Start and boot

- `onCreate` creates the four channels via `Notifications`, starts foreground (type `specialUse` on
  API 34+) and takes a killed run (`Tabs.takeKilled`; with no marker it deletes `files/tabs/` and
  there is none): its saved tabs, and how its process ended, looked up by the marker's pid in
  Android's exit records (`ApplicationExitInfo`); a crash or ANR of Appine posts a notification
  through `Notifications` at once. Then it calls `start(Rootfs.importing())` when no rootfs is
  ready (Alpine on the first run, else the distro an import was last started for), else
  `start(null)`.
- `start` clears `startError`, sets `starting` (the wake lock follows) and runs on an
  `appine-start` thread: import when a distro is given (`Rootfs.prepare`, with progress to the
  notification and listeners, then an `appine-mirrors` thread choosing a mirror once, android/setup),
  `ensureNetworkConfig`, `ensureContainersConfig`, `ensureLoginTools`, `ensureBashStartup`,
  `ensureGpuCommand` (only when `gpu` is enabled), `ensureBrowser`, `updateProfile`, then
  `Native.start(store, tier, gpu)` under `Rootfs.access`'s write lock (`tier` is the saved setting in
  all builds, defaulting to 1; `gpu` defaults to false) and `Native.hasGpu(handle)` recorded as `gpuAvailable`. On Alpine, `Rootfs.ensureOpenRc` checks the store and installs a missing OpenRC
  before publishing the kernel handle. If it installs or resumes, it runs inittab on this thread.
  A setup I/O failure during import stops the private kernel. On an existing store the service
  presents the error and allows a terminal for repairs. The boot thread runs inittab only if
  setup has not already run it, including when runlevel verification failed.
- Back on the main thread it clears `starting`; if "exit all" came meanwhile it finishes the exit
  with the new kernel (shutdown if setup booted it, stop if still unbooted). On success: set `machine`, clear `progress`,
  refresh Files roots; a `pendingReplace` replaces the store at once; otherwise update the wake
  lock, write the running marker, restore the killed run's tabs (once), schedule periodic saves,
  start the boot thread, register a default-network callback (routes), post the poll, update the
  notification, `onMachineReady(null)`.
- On failure: a failed import of a downloaded distro (not Alpine, store not ready) falls back to
  Alpine with a notice; with a `pendingReplace` the store is replaced; any other failure records
  the exception in `Diagnostics`, sets `startError`, updates the wake lock and notification
  ("Cannot start" with the error in its body, unless privacy mode hides it), reports it to the
  listeners, and stops the service as soon as no UI is left and no distro switch is downloading
  (there is no kernel, so no poll would end it; opening the app tries again).
- Which start: when no store is ready (`startOrImport`, at creation and when an exit finishes with
  a UI back) the distro the last import was started for is imported first, otherwise the store
  starts as it is.
- Boot (`appine-boot` thread): unless the start thread already booted the kernel, run the osclock script without a console (exceptions logged, exit status ignored),
  `Native.boot` (blocks until inittab's boot entries finish), then notify OpenRC services that
  failed to start through `Notifications`, if the kernel is still the same.

### Poll (every 2 s)

- On the main thread, while a kernel runs: first `bklStall` (it takes no BKL, and the worker
  would wait behind a hold that does not end) reports a too-long hold of the BKL to
  `Notifications`; then the worker fetches `takeListens`, `takeKills`, `takePower`, `processes`
  and `takeChangedDirs`, then `guestCpuTime`; the poll reschedules itself at once, whether or not
  the fetch has run.
- Changed directories are handled on the worker straight away: `Documents.dirsChanged`, then
  `Rootfs.dirsChanged` (a change in `/etc` rewrites the login's NOPASSWD rules, android/setup).
- The rest is applied on the main thread only if the kernel is still the same: listens (to
  `Notifications`), kills (in-tab `[appine]` message into the tab whose console with that number
  is open, else the newest tab that had it, in yellow above the cursor line and skipped on the
  alternate screen; then `Notifications` unless shown in the tab in front, and always for an Appine
  bug), then power. Reboot → `restart()`; halt/poweroff → `exitAll()`; no running sessions (tabs
  whose shell ended do not count; restored tabs not shown yet do), no listeners and no guest
  processes (init and zombies excluded) → `exitAll()`.

### Stopping, restarting, replacing

- `exitAll` (once): mark exiting, cancel a switch and a `pendingReplace`, `onExitAll`, clear
  listeners immediately, `detach`, show "Stopping services…". While `starting` or `transitioning`
  it stops there and the start or restart finishes the exit once its kernel is up or has failed;
  otherwise `finishExit`: `Native.shutdown` on the worker (inittab shutdown, 30 s; `Native.stop`
  for a kernel that was never booted), then clear `exiting`, release the wake lock and clear saved
  tabs unless tabs of a killed run are still waiting to be restored; start the kernel again
  (importing when no store is ready, as after a failed import the exit came during) if a listener
  came back meanwhile, else `stopSelf`.
- `detach`: unregister the network callback, clear `machine` (before sessions end, so the UI does
  not treat it as the last tab closing), update the wake lock, cancel the poll and saves, release
  (hang up and free) every session and take its notification away, clear `sessions` and
  `unshown`; it runs before the kernel is shut down or stopped.
- `setTier` and `setGpu` ignore unchanged values; otherwise they save the choice and call `restart` in all
  builds. `restart` (guest reboot, tier or GPU change; nothing without a kernel):
  `transitioning`, `detach` (which also clears `gpuAvailable`), `onRestarting`, shutdown on the worker, then `start(null)` (or, after
  "exit all" meanwhile, finish the exit); the UI opens a new tab when the new kernel is ready and
  no sessions exist.
- Distro switch/reset (`switchTo`, allowed while no switch or download is under way and either a
  kernel runs or the start failed): download on an `appine-download` thread (progress in Settings
  and the notification, both cancellable; a failure other than a cancel shows a notice); when it
  finishes, `replace` if a kernel runs or the start failed, else record it in `pendingReplace`
  while a start or restart is under way (in any other state it is dropped). After a failed start
  the switch keeps the service running without a UI; its failure or cancel then stops it as a
  failed start does. `replace`: reset the login setting, `transitioning`,
  `detach`, then on the worker `Native.stop` (kill all, no inittab shutdown), join the mirror
  thread and delete the store, then `start(distro)` — also after "exit all" meanwhile, so the
  chosen distro is imported (and then stopped) rather than the next start importing Alpine.
- `onDestroy` marks the service destroyed (from then on nothing posts the ongoing notification,
  which a thread outliving it, the download's, would otherwise post again),
  cancels a distro switch still downloading, removes the pending callbacks, clears saved tabs
  unless tabs of a killed run are still waiting to be restored, unregisters the network callback,
  releases the sessions, shuts a remaining kernel down on the worker (best effort), shuts the
  worker down and releases the wake lock. A start completing after destruction closes its browser
  bridge and shuts its returned kernel handle down on a separate `appine-stop` thread.

### Wake lock and ongoing notification

- `RunPolicy`: SLEEP (default) allows sleep; ALWAYS holds `PARTIAL_WAKE_LOCK` throughout start,
  import, boot, running, restart, replacement and shutdown; BUSY protects those transitions and
  distro downloads, but releases during normal running after 30 s without observed guest CPU activity.
  Locks are not reference-counted. Legacy `keep_awake` false/true reads as SLEEP/ALWAYS until a
  policy write saves `run_policy` and removes it; non-ALWAYS writes also save `idle_policy`.
- `GuestActivity` compares live-plus-exited guest CPU samples from the worker's 2 s poll, excluding
  host UI and timer CPU. Changed or failed samples renew grace; pre-reset samples are ignored,
  delivery delayed by 2 s renews grace, and a new kernel, completed boot or policy change resets it.
  Release/reacquisition happens on a completed poll; polling cannot wake a suspended device.
  CPU inactivity can include network waits and scheduled work, which need ALWAYS for continuity.
- The ongoing notification (id 1) title shows, by precedence: "Stopping services…" while exiting; the
  import or download progress while no kernel runs; "Cannot start" after a failed start;
  "Running in the background" while a kernel runs and no tab does; else the count of running
  sessions ("0 sessions running" while a start is under way, except that a start after an exit,
  because a listener came back, keeps "Stopping services…" until it ends under SLEEP,
  as nothing refreshes the notification). A switch adds its progress, subtext
  and a cancel action. The body shows the error reason when the title is "Cannot start", otherwise
  the selected policy without the instantaneous wake-lock state; expanded body text wraps.
  Privacy mode uses "Privacy mode" as the title and the selected policy in the body, hiding
  both the state and error details, including in the expanded body.
  The single toggle names its target: ALWAYS from either non-always policy,
  otherwise the saved `idle_policy` (SLEEP until chosen). Settings and notification stay in sync.
  The toggle is hidden while exiting, and "Exit all" is always there.
- Exit all, cancel download and running-policy actions always target `TerminalService`, including
  while locked. The `Privacy` mode-change listener clears old non-ongoing notifications via
  `Notifications` and refreshes the ongoing notification and UI listeners. `Privacy` owns
  authenticated mode changes without requiring a service binding: enabling clears file access,
  revokes grants and refreshes roots; disabling restores neither access nor grants. The service
  also refuses enabling file access while privacy is on.

### Memory

- The last listener leaving saves tabs at once and starts a 60 s timer that trims memory (on the
  worker: `Native.trimMemory`, the kernel's rebuildable caches, then `VtNative.compressAll`, every
  tab's cold scrollback at once, android/vtcore); a returning listener cancels it. `onTrimMemory` at
  `RUNNING_LOW` and above (except `UI_HIDDEN`) trims and saves immediately, and also cuts the Kitty
  images of every started tab but `current` down to 4 MiB a screen, deleting the oldest
  (`VtNative.dropImages`, android/vtcore); since Android 14 those levels are no longer sent, so this
  happens only on Android 11–13. Tabs also compress their own scrollback within seconds of their
  output, so the trim mostly finds what the last few seconds left.

### Sessions, saving and restore

- `createSession` builds a `ConsolePty` and a `VtSession` with the next id and gives it the
  cursor settings (`VtSession.setCursor`: the shape, a `GhosttyCursorStyle`, recorded as Ghostty's
  `cursor-style` name, and blinking); changing either in Settings gives every tab, restored ones
  not shown yet included, the new values at once. The shell starts when a view first knows its
  size. A title change only calls the listeners' `onSessionsChanged`; a
  shell's end, and opening or closing a tab, go through `sessionsChanged` (the notification's
  count, the listeners, a save 2 s later while a kernel runs). `removeSession` releases the session
  and takes its notification away, as `detach` and `onDestroy` do for every tab.
- Saving (`saveTabs`, while a kernel runs): for running tabs only, the login setting and the
  transcript (plain text, last 256 K chars; `VtSession.transcriptText`) on the main thread, and on
  the worker the foreground group's cwd (`consoleCwd` of the tab's console, when it has one; null
  once the shell has ended) and, for a tab whose shell started, its terminal's snapshot
  (`VtSession.takeSnapshot`: written with `Tabs.writeSnapshot` when it changed since the last save,
  else the file saved last, `VtSession.savedSnapshot`; none when none can be taken), with an `auto`
  login saved as the account it resolves to
  (`Rootfs.loginAccount`, kept in `VtSession.resolvedLogin` from the tab's first save) so a
  restored tab logs in as the same user. Restored tabs not shown yet keep their saved transcript,
  snapshot and cwd; the saved current tab is an index among the running tabs (0 when none is current).
- `Tabs.save` writes temp-then-rename, as `writeSnapshot` did before it; a transcript's or
  snapshot's name is its content digest, so unchanged ones are not rewritten; the index (with the time) is skipped when its tabs and current tab hash the
  same as the last one this process wrote, so the saved time is that of the last save that found a
  change or was its process's first; transcripts and snapshots no index names any more (and their
  leftover temporary files) are deleted only after the index step (a kill at any point leaves a
  consistent set). A
  `name` key in an index from versions that could rename tabs is ignored. Triggers: every 60 s, 2 s
  after a tab opens, closes or its shell ends, when the last listener leaves, on memory trim.
- The `running` marker, holding the process's pid, is written after each successful start and
  removed (with saved tabs) on a normal exit; `takeKilled` loads the tabs when it is present at
  service creation and leaves the marker and files alone, so a second kill (or a failed start)
  before the kernel is up keeps them, and the marker still names the run they belong to. A marker
  from an earlier version is empty (pid 0).
- Restore, at the first successful start without a pending replacement (a failed start or a
  replacement keeps `restore` for the next one): each saved tab reopens with its saved login
  setting and cwd, below its terminal as saved (its snapshot, read and inflated when the tab is
  first shown, when the index's version is this build's and it decodes; else its transcript) and a
  yellow `[appine]` notice saying why the run ended and when the tabs were saved; the saved current tab becomes `focus`. Seven reasons are told
  apart: low memory, too many resources in the background, force-stopped (user requested or
  stopped), the app updated (from Android 14), a crash (Java or native) and an ANR of Appine;
  anything else, no record or no pid gives "Android stopped the app".

### What programs ask of the app

- With privacy mode enabled, `Privacy.locked` excludes the current tab from `inFront` and drops
  clipboard writes while locked or with no resumed page; clipboard reads then receive an empty
  answer. With privacy mode off this gate does not restrict delivery. The terminal independently
  guards browser requests and input. Guest programs continue running.
- `BrowserBridge` owns a random-port IPv4 loopback listener and per-kernel UUID capability.
  Start creates it before `ensureBrowser` writes the guest configuration; failed/abandoned starts,
  detach and service destruction close it. Closed endpoints cannot dispatch queued UI work.
  Initial-netns guest AF_INET reaches Android loopback; isolated netns remap it and cannot reach
  this endpoint. Guest AF_UNIX stays emulated (kernel/netns, kernel/unix).
- Its single daemon worker reads two UTF-8 lines (token, URL), bounded to 64/8192 bytes and a
  2 s total read deadline. Only authenticated HTTP(S) URLs with a host and no controls or spaces
  reach the main thread. The callback has a 2 s wait; expired queued work is cancelled, but a
  callback already executing is not interrupted.
  `onOpenUrl` succeeds only with a live kernel and a listener accepting it; MainActivity requires
  window focus and reports Android intent acceptance. The reply is `OK` or an ASCII `ERROR`.
  This is kernel-wide, with no originating-tab identity: any guest process may ask while the
  terminal is focused, including detached multiplexers. Background-app requests fail, not queue.
- A bell in the tab in front (`inFront`: it is `current` and `MainActivity` is a listener, so not
  another tab and not Settings in front) goes to the listeners' `onBell`; elsewhere it becomes the
  tab's notification via `Notifications` (`android/reports`). An OSC 9 or OSC 777 notification
  uses the same `onBell` haptic feedback in the tab in front, sharing the view's 100 ms bell
  throttle and system touch-feedback setting; elsewhere it becomes the tab's notification. A
  change of a tab's progress or program status goes to the listeners' `onTabStatus`; a program
  status that is blocked, done or failed (`Notifications.status`) becomes the tab's notification,
  once per status (the same record again posts nothing), unless the tab is in front, where done
  and error count as seen at once (`VtSession.statusSeen`). A status that goes without the user
  (the program was killed or stopped waiting) takes its notification away, unless a bell or a
  program's notification has replaced it since. A clipboard write sets the clipboard from any tab
  (labelled Appine), or clears it; before Android 13, which shows copies itself, a toast says a
  program copied text. A clipboard read (OSC 52) from the tab in front goes to the listeners'
  `onClipboardRead`, where the terminal Activity asks the user; from any other tab it is answered
  at once with an empty clipboard (`VtSession.answerClipboardRead(null)`): Android lets an app
  read the clipboard only while it has the focus, and the program would otherwise wait for a
  timeout.
- tmux's control mode (tmux -CC), which the terminal detaches as it starts (android/vtcore),
  ending (`onTmuxDetached`) is told in that tab as a yellow `[appine]` line
  (`VtSession.showMessage`): it cannot be shown, its session goes on, and `tmux attach` brings it
  back.
- A command the shell's prompt marks (OSC 133) saw finish (`onCommandFinished`, timed by the
  terminal, android/vtcore) after at least 10 s, in a tab not in front (another tab shown, or
  the terminal Activity not listening), becomes the tab's notification via `Notifications`, as
  Ghostty's `notify-on-command-finish = unfocused` (Ghostty's default is `never` and its threshold
  5 s); shorter ones and those in the tab in front post nothing.

## Dependencies (inbound / outbound)

### Inbound

- `MainActivity` (`android/terminal`), `SettingsFragment` (`android/settings`: start and bind,
  listeners, setters, state); `VtSession` (`android/vt`: `Events`); ongoing notification
  `PendingIntent`s; `ConnectivityManager`; system trim callbacks; `Documents` (`android/documents`),
  `MainActivity`, `Notifications` and `Diagnostics` (`android/reports`), and `Privacy`
  (`android/privacy`) reading `Settings`.

### Outbound

- `Notifications` and `Diagnostics` (`android/reports`: channels, non-ongoing notifications,
  copy-report forwarding, fault retention).
- `Native` (`android/native`: start, boot, spawn, waitFor, shutdown, stop, trim, the poll's calls,
  `bklStall`, routes, `consoleCwd`); `VtNative.compressAll` and `dropImages`, and `VtNative.version`
  through `Tabs` (`android/vtcore`); `Rootfs` (`android/setup`: readiness, importing, prepare,
  download, mirrors, ensure-files, profile, access lock, store, reset, failed services, rules
  refresh, login accounts); `Tabs`; `VtSession` and `ConsolePty` (`android/vt`); `Documents`
  (`android/documents`: `rootsChanged`, `dirsChanged`, `revokeAccess`); `Privacy`
  (`android/privacy`).
- Android: `ActivityManager` (exit records), `PowerManager`, `NotificationManager`,
  `ConnectivityManager`, `ClipboardManager`, the `settings` preferences, `BuildConfig`.

## Invariants and gotchas

- Debug and release builds share the saved tier preference; a Tier 0 choice from an earlier
  debug install is also honoured by a release build when that preference is retained.
- Normal background kernel work goes through the single worker, so polls and saves are
  ordered before stop and shutdown; `Native.start` runs on `appine-start`, the boot for OpenRC installation on
  that same thread and ordinary boots on `appine-boot`, a tab's console opening on the main thread. If destruction races a start,
  its abandoned handle is shut down on `appine-stop`. A stale kernel handle is harmless
  (the JNI table no longer finds it). A call that must answer while the BKL is stuck (`bklStall`)
  must not take it and runs on the main thread.
- Results of a poll other than changed directories are dropped if the kernel changed meanwhile
  (reports fetched just before a restart are lost). While a hold of the BKL lasts, the poll keeps
  queueing fetches behind it on the worker, which run back to back once it ends.
- Android names low-memory kills only where `isLowMemoryKillReportSupported`; elsewhere they are
  plain signals, as is a `SIGKILL` from anyone, and get the general notice. Exit records are kept
  for a limited number of processes per app, so a run killed long ago may have none.
- `exitAll` clears listeners at once so that a quick shutdown is not mistaken for the user
  returning.
- An `exitAll` during a start, restart or replace leaves the rest of the exit to them: every path
  that ends `starting` or `transitioning` must check `exiting` (a replacement does so through the
  start it ends with), or the service stops with a kernel still running (or never stops).
- A thread that outlives the service (a download; the mirror probe posts nothing) posts to the
  main thread after `onDestroy`: it reaches notification 1 only through `updateNotification`, which does nothing once
  destroyed, so a new way of posting it must go through that too. Ongoing notification id 1 must
  not collide with `android/reports`'s notification id ranges.
- The marker is rewritten at a start before the first save replaces the old run's index, so a kill
  in between restores the old tabs again; tabs of a killed run kept through a replacement are
  restored into the new distro, where their directories may not exist.

## Confirmed bugs / technical debt

- **A layout hash collision can skip a tab-index update:** `Tabs.writtenLayout` compares only a
  32-bit string hash, so different metadata with the same hash can retain the old index and save
  time. Changing only cwd from `/Aa` to `/BB` with unchanged other fields is one such collision;
  restore then uses the stale cwd. Artifact cleanup still follows the skipped index update.
- **A kill report of a shell can reach a new tab:** when a tab's shell itself is killed and a tab
  opened within the next poll (2 s) gets the freed console number, the report goes to the new tab,
  whose console is open, rather than the ended one.

## Open questions

None.

## To verify

- The ongoing notification's state title, error or running-policy body and expanded text have not
  been checked on a device, including long startup errors and privacy mode.
- Foreground program-notification haptics on physical devices, including touch feedback disabled.
- Screen-off power consumption and reacquisition on physical devices; busy/idle lock transitions
  and notification toggling were exercised on an API 34 emulator, not across real device suspend.
