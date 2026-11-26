# android/vtcore Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/vtcore.md` for the paired decision history (pre-split decisions D1, D3, D4 and the parsing side of D5–D7 stay in `.agents/decisions/android/vt.md`; earlier terminal implementation decisions D2, D5, D6, D8, D16, D17, D32, D33, D35–D39 and D42–D49 stay in `.agents/decisions/android/terminal.md`).
>
> Verified: 2026-11-14 (split out of android/vt, whose facts descend from the android/terminal full mapping of 2026-11-11; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: clipboard generations in reset results, pump effects and JNI callbacks)

## Responsibilities

`android/vtcore` owns each tab's native libghostty-vt terminal and its Kotlin JNI facade:

- terminal handles, locking, creation and destruction, and the console-output pump;
- terminal options, PNG decoding, protocol effects, prompt parsing and command timing,
  tmux control-mode detachment, messages, transcripts and clear/reset semantics;
- scrollback compression, image trimming, snapshots and settling a restored terminal;
- all `VtNative` JNI functions, including the locked calls into the interaction and rendering
  sections owned by other modules.

Root: `VtNative.kt` in `android/app/src/main/java/io/github/mthli/appine/`,
`hosts/android/src/vt.rs`, and `hosts/android/src/vt.c` except its frame-format specification
and Frames section (`android/vtrender`), its Input, Paste, `appine_vt_focus` (in Mouse and focus)
and Search sections (`android/vtview`), and `appine_vt_mouse` (in Mouse and focus) plus its
Selection, Links and Taps on the prompt sections (`android/vtgestures`).

Outside the module: Kotlin sessions and console/login lifecycle (`android/vt`); session ownership,
save files, notifications and memory policy (`android/service`); the screen (`android/terminal`);
view lifecycle, input and search (`android/vtview`); touch/mouse gestures, scrolling, selection,
links and prompt taps (`android/vtgestures`); frame encoding and drawing (`android/vtrender`);
the host console (`kernel/tty`); `guarded!` and the kernel handle table (`android/native`), build/linking (`android/build`); the shell hooks producing prompt marks (`android/setup`).

## Key types

- `VtNative` — 49 `@JvmStatic external` functions on the native library, plus raw libghostty-vt
  cursor style (`CURSOR_*`), selection gesture (`GESTURE_*`) and adjustment (`ADJUST_*`) constants
  that must match libghostty-vt's headers.
- In `vt.rs`: `Tab` (handle, kernel handle, console number, mutex-guarded `Term`, separately
  mutex-guarded `Render`, `dirty` flag) in monotonically keyed `TABS` (handles from 1, never
  reused); `TermGuard` (releases the tab's terminal lock and schedules compression when work
  remains); `Term` (owns `AppineVt` and optional foreground-process `fallback_title`, freed on
  drop); `Render` (owns `AppineVtRender`, freed on drop); `RawEffects` (C-ABI mirror of
  `AppineVtEffects`) decoded into `Effects` (`StatusReport` queue, optional clipboard reset and
  reads tagged with the captured generation, last finished command, `tmux_detached`);
  `COMPRESS` (`Due` per tab) served by `vt-compress` (`compressor`).
- In `vt.c`: `AppineVt` — per-terminal native state holding the libghostty-vt terminal,
  key/mouse encoders, grid/cell geometry, shared reply/text buffers, resize settle and
  synchronized-output (`held_state`, `held`, `held_since`)/password flags, selection-gesture and
  search scratch, clipboard generation and pending reset flag, queued effects, OSC/DCS prefix
  scanners and `tmux_control` state, command-timing, `prompt_click` and `lf_resumed` state, and compression/transcript/snapshot dirty
  flags. `AppineVtRender` — per-tab render state guarded by `Tab.render`, holding the
  `GhosttyRenderState`, row/cell/image iterators, frame/extras/grapheme buffers, viewport search
  marks (`marks`/`marks_sent`), Kitty `Placement` list with generation/validity, and the
  `FrameSnap` captured under `Tab.term` in `appine_vt_frame_begin`. Process-wide (`install_sys`,
  installed with the first terminal): the Wuffs PNG decoder and `on_log` (sharing a 20 lines/s
  rate limit with `on_unknown_sequence`, `log_allowed`).

## Public entry points

- `VtNative`: `create`, `restore`, `setCursor`, `print`, `pump`, `title`, `atPrompt`, `busy`, `frame`,
  `image`, `passwordInput`, `resize`, `key`, `paste`, `mouse`, `focus`, `scroll`, `jumpPrompt`,
  `gesturePress`, `gestureDrag`, `gestureEnd`, `mousePress`, `mouseDrag`, `mouseRelease`,
  `selectContext`, `selectGrab`, `selectTo`, `selectAdjust`, `selectRectangle`, `selectAll`,
  `outputAt`, `selectOutput`, `selectClear`, `copy`, `link`, `promptClick`, `search`,
  `searchSelect`, `searchRows`, `searchEnd`, `clear`, `reset`, `message`, `transcript`, `snapshot`,
  `version`, `compressAll`, `dropImages`, `destroy`; `pump` runs on `vt-pump` and calls
  `VtSession.onOutput`, `onTitle`, `onBell`, `onClipboard`, `onNotification`, `onProgress`,
  `onStatus`, `onClipboardReset`, `onClipboardRead`, `onCommandFinished`, `onTmuxDetached` and `onForeground` back;
  `snapshot`, `compressAll` and `dropImages` run on the service's worker, `version` wherever `Tabs`
  needs it, the rest on the main thread.

## Data flow / lifecycle

### Terminal creation and ownership

- `create` and `restore` check the kernel handle, create or decode an `AppineVt`, then register
  a `Tab` in `TABS`. Kotlin holds the monotonically allocated handle; a call clones the tab's
  `Arc`. `destroy` removes the handle, while a running pump keeps its terminal until it returns.
- New and restored terminals use the same options: scrollback limited to
  10,000 lines or 10 MiB, whichever is reached first: the lines up to about 120 columns, the bytes
  beyond; default colours white on black and no default cursor colour, so the cursor follows the
  foreground as in Ghostty; the cursor's default from Settings, a blinking block unless changed
  (`wrap` only turns blinking on over libghostty-vt's steady block, and the session sets the user's
  choice right after, `VtNative.setCursor`, before the pending text; android/vtrender's Frames and
  drawing); grapheme clustering, mode 2027, on by default as in Ghostty; the render state asks for
  one overscan row below the viewport; the OSC 133 callback for command timing and report expiry;
  unimplemented OSC and APC strings reported with 16 bytes kept, of which only an OSC's leading number or an APC's
  first letter is logged (a malformed string may start with the program's data); Kitty graphics on,
  with 32 MiB of decoded images per screen (Ghostty's default is 320 MB) and only data sent in the
  escape sequences (the file, temporary file and shared memory media, which would name the host's
  files and objects, answer `EINVAL: unsupported medium`, so programs fall back to sending the
  data); the Glyph Protocol off, so it is not advertised and programs that probe fall back to text;
  the terminfo name `xterm-256color`, the `TERM` the console's login gets, which XTGETTCAP's `TN`
  reports; continuation tracking of up to 64 KiB, so a snapshot can be taken while output stops
  inside a sequence.
- android/vt chooses snapshot versus transcript fallback, applies the user's cursor settings,
  prints pending text and starts the threads. The native terminal owns the emulated screens,
  not the login shell or the session's progress/status records.

### Console output and effects

- A grid-size change sets `resize_pending` and resets its output timestamp. Each nonempty feed
  while pending records `resize_output_at`; a frame clears pending only after 32 ms without more
  bytes, at parser ground (no partial UTF-8/control sequence), with no synchronized-output hold.
  android/vtrender exposes pending OR the hold in frame flags bit 7. android/vtview uses it only
  during a bounded height-shrink preview. This delays neither resize nor SIGWINCH; a quiet gap
  is a heuristic, not proof that the program finished redrawing.
- The pump reads the console into a 64 KB buffer, asks the kernel whether the console now reads a
  password (`Machine::console_password_input`: lines without echo, which programs set before
  printing their prompt) and notes it in vt.c, feeds the terminal under the tab's lock (in parts
  that end at the start or end of an OSC or DCS string, `ghostty_terminal_vt_write_until`, where
  vt.c keeps an OSC's first 64 bytes to find clipboard reads and prompt starts and a DCS's first 5,
  its header, to find tmux's control mode; no slower than one write), writes
  the terminal's replies (DA, DSR, XTVERSION, size reports, pastes' bytes, the line that detaches
  tmux's control mode) back to the console
  before reading again, calls `VtSession.onOutput` only when it sets `dirty` (so a burst asks for
  one frame, and nothing is asked while no view takes frames) and `onTitle` after OSC 0/2. It runs
  whether or not a view shows the tab, and ends when the kernel is gone, the console reads end or
  fail, a reply cannot be written, a call into Java throws, or it panics.
- What programs ask of the app is taken after each read (`appine_vt_take_effects`) and handed to
  the session, which posts it to the service unless released: the bell (any number of BELs in a
  read counts once); a clipboard write (OSC 52, OSC 1337, OSC 5522, to any location, as Ghostty's
  `clipboard-write = allow`): its first `text/plain…` representation up to 256 KiB (larger is
  denied, other types unsupported; those replies reach only OSC 5522 programs), or a request to
  clear (an OSC 5522 write of more than 1 MiB in all its representations fails with EFBIG inside
  libghostty-vt, which buffers a write whole before handing it over); a notification (OSC 9's
  body, OSC 777's title and body, up to 4 KiB each; only the last of a read); a progress report
  (OSC 9;4, only the last of a read); program status reports (OSC 7501, every one in order, which
  libghostty-vt has already checked against the specification and whose title and message it has
  decoded; with the callback set it also answers the protocol's `?` query); clipboard reads
  (OSC 52 with `?` for data: an OSC string of `52;`, the clipboards named (`c`, `p`, `q`, `s`,
  `0`–`7`, maybe none) and `;?`, ended and not cancelled, however the reads split it), counted
  with the first clipboard the last one named (`p` or `s`, else `c`), which every read of the
  batch is answered for; the last command the prompt marks saw finish (Shell integration); the end
  of tmux's control mode, which vt.c detached (below), delivered last (`onTmuxDetached`).
  `appine_vt_take_effects` captures the clipboard generation under `Tab.term` and consumes the
  reset flag and read count. After unlocking, the pump delivers `onClipboardReset(generation)`
  before `onClipboardRead(kind, count, generation)` when both occur in one batch.
  libghostty-vt's clipboard-read
  callback is left unset: it must answer before returning, under the tab's lock, which rules out
  asking the user; so OSC 5522 reads are refused and Kitty paste events never sent. What the app
  prints itself (`VtNative.print`) asks nothing: its replies and effects are dropped. A RIS in
  those bytes still advances the generation captured with the next clipboard read. Where effects go
  is android/service's choice; the bell of the tab in front comes back as `VtView.bell`.
- tmux's control mode (`tmux -CC`), which libghostty-vt built for apps does not parse (Confirmed
  bugs / technical debt), would leave the tab showing nothing while keys reach tmux as commands.
  vt.c finds a DCS whose header is literally `1000p`, however the reads split it, and, as Enter
  would, puts a carriage return among the replies the pump writes before reading again: tmux takes
  the empty line as a detach, leaving its session running, and ends the string with ST. That end
  is reported (only an ESC ending it, which libghostty-vt reports at ST's first byte; 0x9C is
  payload once the header is complete, and a string a program cancels with CAN or SUB, or the app's
  own CAN cuts, reports nothing), and the service shows a yellow `[appine]` line in the tab saying
  so and that `tmux attach` brings the session back (android/service; nothing on the alternate
  screen). Other DCS strings (DECRQSS, XTGETTCAP, tmux passthrough) only cost two extra stops each. Nothing
  retries when tmux does not detach.
- At an OSC 133 command end or primary prompt start after a report, the progress slot records
  removal and the ordered status queue records expiry of transient records. Later reports in the
  same read take effect in order. This also works when no command was timed. The pump also samples
  the foreground group after a report (`Machine::console_foreground`). If it recorded a group
  and a later report-free read sees a different one or none, `onForeground` expires progress and
  working, blocked and idle records. This covers shells without marks. The service's `statusSeen`
  drops done and error records when the user sees the tab. Shell exit clears all records.
- Kill reports go through `VtNative.message` (a yellow line inserted above the cursor line: a CAN
  first when the parser is not at ground (`VT_GROUND`, which includes the UTF-8 decoder), so a
  program that died inside an OSC, DCS or APC string does not swallow it; then as many line feeds
  as the text needs rows, up again, save the cursor, insert lines, write, restore and move down,
  dropping any replies; skipped on the alternate screen) or are queued until the terminal exists.

### Scrollback compression

- libghostty-vt compresses the primary screen's cold pages (wholly in the scrollback and outside
  the viewport; the alternate screen keeps no scrollback) to about a fifth of their 400 KiB, and
  restores a page when something reads it: drawing a viewport scrolled back over it, the formatter
  (transcripts, copies), select all (which reads the oldest and newest pages), a mouse's
  Ctrl+triple-click that selected a command's output and a tapped link's line; searching restores
  nothing. The scrollback limits count pages uncompressed, so the same
  history is kept in less memory.
- A pass is scheduled when a call into vt.c left work for one, which vt.c tells as the
  `TermGuard` is released: libghostty-vt's activity token changed (rows moving into the
  scrollback, a resize, scrolling), or one of the reads above restored pages, which vt.c marks
  itself since the token does not change for them. The `vt-compress` thread looks at the tab
  250 ms later and, while the terminal keeps changing, waits another 250 ms each time, but not
  beyond 5 s from scheduling, so output that never pauses is compressed too. It then runs
  libghostty-vt's incremental steps 1 ms apart, each under the tab's lock, until a pass finds
  nothing left; the last step frees vt.c's text buffer if a transcript or copy grew it past
  64 KiB.
- Memory trimming (`VtNative.compressAll`, from android/service) compresses every tab's cold pages
  at once, idle or not, one tab's lock at a time.
- When trimming background tabs (after 60 s with the UI hidden, after 60 s unseen or beyond 2
  recently left background tabs while switching, on periodic saves for already-trimmed unseen tabs,
  or under system memory pressure), the service also cuts the images of tabs not shown
  (`VtNative.dropImages`): vt.c lowers the tab's Kitty storage limit to 4 MiB and puts it back to
  32 MiB, the only way libghostty-vt gives image memory back. On each screen it deletes whole
  images with their placements, those no placement shows first, then the oldest sent, until the
  rest fit, so images in the scrollback or on the screen go too. The last snapshot is left as it
  was, images included: taking a new one would decompress every page of the scrollback.
- Saving does not format a transcript again while nothing changed the screen, since formatting
  restores every compressed page; a tab whose text changed is formatted at each save and
  compressed again afterwards. A snapshot, which reads every page, marks the terminal touched too.

### Snapshots and restoring

- A snapshot (`VtSession.takeSnapshot`, `VtNative.snapshot`, on the service's worker) is
  libghostty-vt's binary record of the whole terminal: both screens, the scrollback, images,
  colours, modes, the title and the unfinished sequence the parser is in. One is encoded only
  after the terminal changed since the last (output, a message, a resize, clearing or resetting;
  null otherwise, and the service keeps the last file); none can be taken (empty) when encoding
  fails, output having stopped inside a sequence longer than the 64 KiB tracked, or the snapshot
  is larger than 16 MiB (mostly images), and none is tried again until the terminal changes. A full
  scrollback of coloured output takes about 1.5 MB, encoded in about 1 ms and decoded in about
  3 ms on a Mac; the service stores it deflated (android/service).
- Restoring (`VtNative.restore`) decodes a snapshot into a new terminal, compressing its
  scrollback as it comes and keeping its images within the 32 MiB per screen. Before any callback
  is installed (nothing is reported, replies go nowhere), vt.c undoes what the programs that ran
  in it set up for themselves: an unfinished sequence is cancelled (CAN), the alternate screen
  left for the primary one, a soft reset (DECSTR) brings back the cursor, margins, attributes,
  cursor and keypad modes, the palette and the cursor style, reverse video, mouse tracking and its
  formats, focus events, bracketed paste, synchronized output, colour scheme and in-band size
  reports and Kitty paste events are reset, alternate scroll set, the Kitty keyboard flags popped,
  an open hyperlink closed, the title cleared and the mouse pointer's shape (OSC 22, which the
  snapshot carries and a full reset keeps) back to text; what follows is marked as output
  (OSC 133;C), so
  the prompt the snapshot was taken at is not cleared by a resize as a live one is, the cursor
  starts a line of its own when it is not at its start, and the rest of the screen below it is
  erased; the selection goes and the viewport returns to the bottom. The terminal then gets the
  options a new one gets and is resized to the grid. A snapshot that does not decode leaves the
  tab to its transcript (logged).

### Clearing and resetting

- ⋮'s Clear screen (`VtSession.clear`, `VtNative.clear`) is Ghostty's clear_screen, and does
  nothing on the alternate screen (the item is disabled there): the selection goes and the
  scrollback is erased (ED 3). At the shell's prompt (prompt marks) the whole screen goes too (ED 2,
  which libghostty-vt turns into a move into the scrollback when the last non-blank row is a
  prompt, hence the ED 3 after it) and the shell gets a form feed (^L) to draw its prompt again;
  elsewhere (a command running, or a shell without marks) the rows above the cursor's are deleted
  from the top (DL), so the cursor's row moves up to it with the rows below, and the screen's
  Kitty placements are deleted with the images no other one shows. The viewport returns to the
  bottom.
- Reset terminal (`VtSession.reset`, `VtNative.reset`) is Ghostty's reset: libghostty-vt's full
  reset (RIS) of both screens, the scrollback, modes, the palette, the title and images, keeping
  the app's options and the colours set with OSC 10, 11 and 12; the selection, a
  synchronized-output hold and the prompt's way of moving its cursor end, a shell that was at its
  prompt gets a form feed (^L) to redraw, and the tab bar hears that the title went. The session
  clears progress and status directly. A program's RIS clears them through stream callbacks.
- `on_reset` advances the native clipboard generation on each program RIS, drops earlier reads
  in the feed and sets the reset flag. Later reads use the new generation. `appine_vt_reset`
  advances the same counter, clears buffered reads and the pending reset flag, and returns the
  generation to JNI through an output parameter. `VtNative.reset` returns zero for a missing tab,
  the positive generation at a prompt, or its negative otherwise.
- Clearing writes its sequences as the app's own (`write_own`, as kill reports do): after a CAN
  when the parser is inside a sequence a program left unfinished, keeping the console's replies
  as they were. Resetting uses the same cancellation before libghostty-vt resets the screens.
  Both paths clear `osc_open`, `dcs_open` and `tmux_control`.

### Shell integration

- The guest's login and interactive shells mark their prompts with OSC 133 (android/setup's
  profile and rc hooks: bash marks the prompt, multi-line continuation rows, typed command and
  output start on both distros including nested shells; zsh does likewise including on Debian via
  `/etc/appine/zsh/.zshenv` and in nested shells via `/etc/zsh/zshrc`, wrapping `RPROMPT`/`RPS2`
  so right prompts are not counted as input; busybox ash marks the prompt, continuation rows and
  typed command, asking with `appine_lf=output` for its line feeds to be read, below; fish 4 and
  nushell send their own, all four marks, fish's prompt start with `click_events=1` and nushell's
  with no way for taps to move the cursor). libghostty-vt keeps the marks in the rows and cells it
  writes (prompt, input, output) and the cursor's place among them, which closing, jumping, Select
  output and taps on the input read through vt.c's shell integration functions; a mouse's
  Ctrl+triple-click selects a command's output through libghostty-vt's selection gesture, and a
  right-click looks for one for the menu's Select output. A shell without the marks (dash, mksh,
  tcsh, elvish, an ash started through `doas -s`, a remote shell over ssh that sends none) leaves
  every cell output: it is never at a prompt, there is nothing to jump to and no output to select,
  and no command is timed.
- A prompt start or prompt mark (OSC 133;A or P, on the primary screen) with `appine_lf=output`
  has `appine_vt_feed` read the shell's line feeds from there on, outside OSC and DCS strings,
  until one ends the input: a line feed after two carriage returns is ash breaking a long command
  (it writes CR LF, and the console's ONLCR adds a CR; counted across feeds), so the input goes on
  and libghostty-vt marks the next row as the prompt's continuation; any other line feed with the
  cursor at the prompt (the typed command's end, but also the start of a completion list or
  Ctrl-C's echo) gets an output start (OSC 133;C) fed after it, which also
  takes the continuation mark off the new row. Bytes the console's foreground process group did
  not write are not read so: the pump reads output in runs by writer
  (`Machine::read_console_run`, kernel/tty) and feeds each with whether another group wrote it,
  so a line from a job left in the background ends no input. At the prompt vt.c marks such bytes
  as output itself: an output start before them, and after them, when the output moved to a new
  row, a continuation prompt with no text and an input start (OSC 133;P;k=s and B) plus a tracked
  `lf_resumed` reference on that row (or only OSC 133;B when it stayed on the same row), unless
  an OSC or DCS string is open. So the cursor stays at the prompt, what is typed after them is
  input again, they are selected as one output, and `appine_vt_prompt_click` rejects taps above
  `lf_resumed` and never treats `lf_resumed` as an ash-broken row. A primary prompt without the
  option, a program's full reset and the app's Reset terminal end the reading and clear
  `lf_resumed`. So a command of several rows is all input: the cursor stays at the prompt while it
  is typed, and its rows are not selected as output.
- Foreground-process fallback (`vt.rs` + `vt.c`'s `prompt_mode` (`NONE`/`FULL`/`ASH`) and
  `is_alternate`, querying `Machine::console_foreground_process` and bounded 15/35/75 ms
  `read_console_run_timeout` probes only after a foreground newline while the shell still holds the
  foreground, zero idle wakeups):
  - For busybox ash (`APPINE_PROMPT_ASH`, which has no preexec hook) and unmarked shells
    (`APPINE_PROMPT_NONE`), while a non-shell foreground process runs and has not emitted OSC 0/2
    during that command, `Term`'s fallback title holds its sanitized command line (falling back to
    `comm`, skipping Appine's `login.sh` wrapper) and notifies `onTitle`; any explicit OSC 0/2
    title wins immediately, and returning to the prompt clears the fallback title.
  - `VtNative.busy` checks `appine_vt_at_prompt` first, treats alternate screens and full OSC 133
    shells (`bash`/`zsh`/`fish`/`nushell`) as busy when `!at_prompt`, and otherwise marks the tab
    idle when `console_foreground_process` reports an interactive shell (requiring `!canonical_input`
    for `APPINE_PROMPT_ASH` so ash canonical builtins like `read` stay busy while an overwritten
    `PS1` in raw-mode `read_line_input` recovers idle).
  - For unmarked shells (`APPINE_PROMPT_NONE`) and ash that lost its `PS1` marks (`!canonical_input`
    with no OSC 133 `D`), transitioning from a tracked non-shell foreground command back to an
    interactive shell delivers `onCommandFinished(hasExit = false, 0, millis)` without double-firing
    when OSC 133 already reported the command.
- Commands are timed through libghostty-vt's OSC 133 callback (`on_semantic_prompt`): a command
  starts at the output's mark (bash's PS0 and zsh's preexec hook, `C`) or, as busybox ash marks
  none, when a feed ends with the cursor no longer at the prompt where the one before left it there
  (the line feed that ends the typed input; the
  output start vt.c feeds for ash starts no timing itself, as a completion list or Ctrl-C at the
  prompt also gets one; a background job's output at the prompt does not move the cursor off
  it); it
  finishes at the command end (`D` with the exit code) the next prompt sends, and a primary prompt's
  start without one forgets it. A command end with nothing timed (a prompt drawn again after a
  resize, Ctrl-C at the prompt) reports nothing. The pump hands the last finished command of a read
  to `VtSession.onCommandFinished`, and the service notifies for one that ran at least 10 s in a tab
  not in front (android/service).
- At the prompt (`VtNative.atPrompt`, libghostty-vt's cursor-at-prompt: the cursor in a prompt or
  the input after it, on the primary screen): `VtSession.busy` is false and closing asks nothing.
  A command typed and entered ends the input at its line feed, so a running command, even a silent
  one, counts as busy until the next prompt; jobs left in the background do not.

## Dependencies (inbound / outbound)

### Inbound

- android/vt: `VtSession` creates/restores/destroys the terminal, runs `pump` on `vt-pump`,
  reads title and at-prompt state, requests transcript/snapshot, sets cursor defaults and calls
  resize, messages and clear/reset. The session closes the console to end a pump read.
- android/service: `VtNative.compressAll` and `dropImages` on its worker; `Tabs` reads
  `VtNative.version` for snapshot compatibility.
- android/vtview: `VtNative` frame, password, key/paste/focus, prompt-jump and search functions
  using the attached session's handle; android/vtgestures: `VtNative` mouse, scroll, selection,
  output, copy, link and prompt-tap functions. The JNI calls take the terminal lock before entering
  vt.c's interaction sections.
- android/vtrender: `VtImages` uses `VtNative.image`; frame and image calls enter its native
  Frames section through this module's JNI under the tab lock.

### Outbound

- android/vt through `VtSession.on*` callbacks on the pump thread; the session marshals events
  to the main thread and owns clipboard responses and progress/status lifetime. android/setup
  provides the prompt marks whose parsing is described here.
- android/vtview, android/vtgestures and android/vtrender own the excluded vt.c sections; their
  implementations share `AppineVt` and obey this module's lock, buffer and compression contracts.
- libghostty-vt 1.0.0 and its bundled Wuffs PNG decoder linked into `libappine.so` (`android/build`),
  providing terminal state, render state with one overscan row, input/selection/search/formatter
  APIs, OSC 133 semantic prompts, progress/status callbacks, scrollback compression, snapshots with
  continuation tracking and Kitty graphics; `libjnigraphics` (used by android/vtrender);
  `Machine::{read_console_run_timeout, write_console, resize_console, console_foreground_process,
  console_password_input}` (`kernel/tty`); `android/native`'s `guarded!`, handle table and string
  helpers.
- Deliberately unused libghostty-vt C surfaces: standalone parsers/encoders superseded by terminal
  handling, WASM/JSON helpers, X11 colour names, stepped snapshot decoding, macOS Option-as-Alt,
  hollow cursor style, manual title/directory setters, and OSC 7 directory hooks (local shells use
  the kernel's foreground cwd). Defaults kept unset: resize pulling scrollback rows, APC limits and
  `getrandom`.

## Invariants and gotchas

- A kill report opens room with line feeds after CAN-resetting to `VT_GROUND` (leaving U+FFFD if a
  program died mid-UTF-8) and overwrites any program-saved cursor.
- A tab looks up its kernel by handle per call (dropping `Arc<Machine>` before Java callbacks) so
  stale tabs cannot keep an old store open across reboot, tier change or distro switch; the service
  releases tabs before kernel shutdown.
- The pump stays in native code for the tab's whole life, so JNI local references created per event
  must be deleted immediately.
- `AppineVtEffects` (vt.c) and `RawEffects` (vt.rs) share one layout and must change together, as
  the frame format does.
- Restoring creates a fresh terminal: callbacks, Kitty storage/media limits, Glyph Protocol,
  continuation limit, terminfo name and clipboard/unknown-sequence limits are not in the snapshot
  and must be re-applied after `settle` (before `VtNative.setCursor`); `settle`'s DECSTR resets the
  cursor to its defaults.
- libghostty-vt is not thread-safe: every terminal `vt.c` call holds `Tab.term` (recovered if
  poisoned), while `VtNative.frame` holds `Tab.render` around `appine_vt_frame_begin` (which
  takes `Tab.term` only for `ghostty_render_state_begin_update`, images/search and metadata) and
  `appine_vt_frame_end` (which runs `ghostty_render_state_end_update` and row encoding with
  `Tab.term` released). `on_render_hold` captures mode-2026 holds into `vt->held_state` under
  `Tab.term` alone and hands it off to `AppineVtRender` under both locks. Callbacks must never
  block on the main thread (hence async OSC 52 reads and refused OSC 5522 reads). `frame` writes
  the frame buffer only on the main thread; the shared text buffer (title, copy, link,
  transcript) is copied to a Java string under `Tab.term`.
- Compression schedules only when `TermGuard` drops, so mutating calls must lock via `Tab::term`,
  while `compressor`/`compressAll` lock the mutex directly to avoid self-rescheduling. Lock order:
  `Tab.render` before `Tab.term` before `COMPRESS`, never reversed.
- Because libghostty-vt's activity token ignores read-triggered decompression, any `vt.c` path
  reading beyond the viewport must set `compress_touched`; any path mutating terminal state must
  clear `transcribed`.
- `vt.c`'s OSC/DCS tracking (`osc_open`, `dcs_open`, `tmux_control`) follows only `appine_vt_feed`:
  `write_own` clears it after CAN (cutting a tmux control string without reporting detach), and any
  other direct terminal write must do the same. `VtNative.print` drops replies so it cannot detach
  tmux; a tmux `1000p` string that opens and closes in one read still sends its CR to the console
  (detach relies on tmux 3.5a/3.7c treating a lone CR as an empty line).
- Continuation tracking caps unfinished sequences at 64 KiB; saving mid-sequence beyond that fails
  until the terminal changes.
- Compression uses `MADV_DONTNEED` at 4 KiB alignment (rounded up on 16 KB kernels), safe only
  because Zig's page allocator gives every terminal page its own mapping.
- `GHOSTTY_TERMINAL_OPT_USERDATA` takes the pointer itself (not `&ptr`), and `get`/`set` take
  untyped `void *` values, so libghostty-vt upgrades must re-check every key's documented C type.
- `vt.c` answers DA1 (132 cols, selective erase, ANSI colour, clipboard 52), DA2 (VT220), DA3,
  XTVERSION (`"appine"`) and dark colour scheme so probing tools (vim, tmux) do not time out;
  XTGETTCAP answers `TN` with `xterm-256color` and all other capabilities from libghostty-vt's
  built-in Ghostty entry.
- `was_at_prompt` updates only in `appine_vt_feed` (clear/reset/message/resize leave it); edited
  profiles using older ash OSC 133;I marks without `appine_lf=output` can start timing on
  background-job output at the prompt. ReleaseFast logs warnings/errors via `on_log`, installed
  after the first terminal is created/restored, so first-restore decode/settle logs are dropped.
- Default foreground/background colours must be set or OSC 10/11 queries go unanswered, DECSCNM
  swaps nothing and OSC 10/11 overrides miss render state; with them, OSC 12 falls back to
  foreground, and RIS resets the palette while keeping OSC 10/11/12 colours.
- `vt.c` explicitly disables the Glyph Protocol and restricts Kitty media to direct escape data at
  create (both persist across RIS and copy to the alternate screen) so library defaults cannot
  expose host files; Wuffs PNG decoding must be installed via `ghostty_sys_set` or `f=100` fails
  with `EINVAL`. ED 0 leaves images; ED 2/3 delete them.
- Mode 2027 (grapheme clustering) can disagree with `wcwidth`-only programs on emoji unless disabled;
  libghostty-vt's C terminal starts at a 10,000-byte scrollback default (raised to active pages + 1),
  so both the 10,000-line and 10 MiB limits must be set (pruning whole 400 KiB pages: ~1,000 rows
  at 45 cols, ~580 at 80, ~190 at 250).
- Prompt marks make every resize at a prompt clear the prompt rows (bash's `redraw=last` clears
  only the last row) expecting the shell to redraw on SIGWINCH; shells that do not redraw lose
  visible input until the next prompt.
- `VtNative.print` does not consume `title_changed` (reported on the next pump read); 4 KiB
  notification truncation can split UTF-8 (decoded lossily in `vt.rs`).
- `android/vt` applies cursor defaults, sends clear/reset form feeds and releases sessions before
  shutdown; `android/service`'s `Tabs` version-gates snapshots and retains the last file on null.

## Confirmed bugs / technical debt

- **Shell integration is partial**: the profile, rc hooks and Alpine `doas.d` `setenv` rules mark
  prompts for bash, busybox ash (including `doas -s`) and zsh (fish and nushell mark their own);
  local unmarked shells (dash, mksh, tcsh, elvish, and ash after `PS1` is overwritten past `ENV`)
  get foreground-process fallback for `busy`, command titles and exit-code-less completion timing,
  while prompt jumping, Select output, prompt taps, and remote shells over ssh without OSC 133
  marks still require OSC 133 marks.
- **libghostty-vt features not wired**: ENQ, the title report (CSI 21 t),
  XTCHECKSUM and window resizing (CSI 8 t) are left unanswered, as Ghostty's defaults leave them
  (`enquiry-response` empty, `title-report`, `vt-xt-checksum-report` and
  `vt-window-resize-allowed` false); OSC 5522 clipboard reads are refused and Kitty
  paste events never sent, since only the read callback, which cannot wait for the user, serves
  them (wiring it would also need the IME's multi-line commits, pasted as
  `GHOSTTY_PASTE_SOURCE_CLIPBOARD`, marked `GHOSTTY_PASTE_SOURCE_TEXT`, or they would become paste
  events).
- **More of libghostty-vt left unused**:
  - VT/HTML formatting with colours and OSC 8 links (transcripts are plain text); memory usage and
    the VT processing-error flag; OSC 133 command line and error text; KAM (mode 2).
  - Out of reach in the C API: terminal visibility (mode 2033 reports every tab visible), native
    password-input flag, Kitty drag-and-drop (OSC 72), OSC 66/99/hierarchical contexts, and tmux
    control-mode parsing (built without Oniguruma; `vt.c` detaches `tmux -CC` instead of providing
    iTerm2-style windows/tabs).

## Open questions

(None currently.)

## To verify

- Native checks include a Pixel 4a API 34 emulator (4 KB pages), prompt expiry on an API 37
  emulator (16 KB pages) and vt.c harnesses on macOS, the source of the scrollback measurements.
  Unverified on physical devices and in these cases:
  - shell integration: zsh's marks in the app, bash's on Debian (on Alpine only closing a tab at
    its prompt was tried), and those fish 4.6 and nushell 0.104 send themselves (all seen only in
    containers); the console's password state at sudo, passwd, ssh or
    doas prompts;
  - output: tmux -CC with versions other than 3.5a and 3.7c; how programs that
    probe for the Glyph Protocol fall back;
  - memory: scrollback compression on 16 KB-page devices and its battery cost; snapshots with
    images, bash's marks, a program on the alternate screen at saving, or across a library version
    change.
