# android/vtview Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/vtview.md` for the paired decision history (decisions from before the split are D5, D7, D9, D16, D17, D25, D30–D32, D34, D36, D37, D40, D41, D43 and D46–D48 in `.agents/decisions/android/terminal.md`; this snapshot also keeps the decisions on rendering and gestures/selection/scrolling made before `android/vtrender` and `android/vtgestures` were split out).
>
> Verified: 2026-11-23 (full mapping: 4 research concerns; 12 claims checked by 2 independent verifiers — 9 confirmed and 3 partial, all corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's remapped text and mode 1004 focus delivery on tab switches, with the retained `Host.onBackgroundColor` and same-draw background clearing re-recorded from the merged source)

## Responsibilities

`android/vtview` is the terminal view's lifecycle, frame orchestration, keyboard/IME/clipboard
input and search: `VtView` attaches a tab, manages font/grid sizing, requests frames and applies
their state (including height-shrink previews), schedules redraws and cursor/password/animation
timers, handles hardware/extra-key encoding, the IME, pastes, focus events, scrollback search and
prompt jumps. `VtKeys` maps Android key codes to libghostty-vt's key numbers.

Root: `VtKeys.kt` and `VtView.kt` (except its `Selection`, `Touch`, `A mouse or touchpad` and
`Scrolling` sections) in `android/app/src/main/java/io/github/mthli/appine/`, and the `Input`,
`Paste`, `appine_vt_focus` (in `Mouse and focus`) and `Search` sections of `hosts/android/src/vt.c`.

Outside the module: touch/mouse gestures, pixel scrolling/flings, selection handles/menu, links
and prompt-output/prompt-tap actions (`android/vtgestures`); the frame format, `Frames` section of
vt.c, screen mirror, rendering classes and font (`android/vtrender`); the sessions (`android/vt`);
terminal handles and locks, JNI functions (`VtNative`, `vt.rs`) and the rest of vt.c
(`android/vtcore`); the surrounding screen, search bar and opening links (`android/terminal`).

## Key types

- `VtView` — the terminal `View`: holds the attached `VtSession` (`session`, `tab`); its
  `VtScreen`, `VtImages` and `VtRenderer` (`android/vtrender`, whose cell metrics it reads); the
  font size (`fontPx`, default 12 dp, clamped to 6–32 dp) and `fillWide` setting (default true);
  the last frame's modes (`altScreen`, `mouseTracking`, `altScroll`), scroll bounds (`scrollTotal`,
  `scrollOffset`, `scrollLen`, `atBottom`) and selection bounds/shape; frame and height-shrink
  preview state (`full`, `hasFrame`, `resizePreview`, `resizePreviewUntil`); search state,
  reported counts, cached scroll-bar match rows (`matchRows`, `matchSelectedRow`,
  `matchMarkHeight`) and `stepFrom`; timers (`blinkTick`, `passwordCheck`, `animationTick`,
  `imePassword`, `lastBell`); the IME connection (`Connection`, `preedit`, `monitorCursor`); plus
  the gesture/selection/scrolling state owned by `android/vtgestures`.
- `VtView.Host` — the activity's callback interface: `onGrid`, `onInput`, `onFocus` (delivers mode
  1004 focus bytes to a specific `VtSession`, defaulting to `onInput`), `onZoom`, extra-key
  modifiers (`ctrl`, `alt`, `shift`, `modifiersUsed`), `onLink` (invoked by `android/vtgestures`),
  `onSearchCount` and optional `onBackgroundColor` (the default background of a frame accepted
  for display, reported only when it changes).
- `VtKeys` — stateless mapper from Android `KeyEvent.KEYCODE_*` to libghostty-vt `GhosttyKey`
  numbers (`of`, returning 0 when unknown), action constants (`ACTION_RELEASE`/`PRESS`/`REPEAT`),
  modifier bits (`MOD_SHIFT`/`CTRL`/`ALT`/`SUPER`; no lock bits), `isModifier` (8 modifiers and 3
  lock keys) and `mods`.

## Public entry points

- `VtView(context, host)`, built by `TerminalLayout` and driven by `MainActivity`: `session`,
  `altScreen`, `attach`, `onStarted`, `setFontSize`, `setFillWide`, `press`, `type`, `search`,
  `searchStep`, `endSearch`, `jumpToPrompt`, `bell`; `View` overrides `onSizeChanged`, `onDraw`,
  `computeVerticalScrollRange`/`Offset`/`Extent`, `onKeyDown`, `onKeyUp`, `onWindowFocusChanged`,
  `onFocusChanged`, `onDetachedFromWindow`, `onWindowVisibilityChanged`, `onCheckIsTextEditor`,
  `onCreateInputConnection`.
- From `android/vt` (`VtSession.view`): `onStarted` (shell started or spawn failed: request full
  frame and invalidate), `postInvalidateOnAnimation` (from pump thread on output) and `invalidate`.
- Native C entry points (`hosts/android/src/vt.c`, bound through `vt.rs`/`VtNative`):
  `appine_vt_key`, `appine_vt_paste`, `appine_vt_focus`, `appine_vt_search`,
  `appine_vt_search_select`, `appine_vt_search_rows`, `appine_vt_search_end`.

## Data flow / lifecycle

### Lifecycle, sizing and frame integration

- `VtView` initialization enables focus (`isFocusable`, `isFocusableInTouchMode`), disables the
  default focus highlight (`defaultFocusHighlightEnabled = false`), enables a fading vertical
  scroll bar using the theme's `scrollbarThumbVertical`, and configures `VtRenderer`'s font.
- `attach(s)` ignores an unchanged session. When switching or detaching, it clears any resize
  preview, ends search, detaches `session.view`, finishes the floating action menu and any active
  native selection gesture (`VtNative.gestureEnd`), cancels autoscroll and flings, stops
  `passwordCheck`, resets `imePassword`, clears `preedit` (`setPreedit("")`), calls `restartInput()`
  synchronously when switching/detaching tabs or when `imePassword`/`preedit` was active, clears
  hover/selection/scroll state, and drops `VtImages` bitmaps and `animationTick`. For the new
  session it clears `hasFrame`, binds `s.view = this`, calls `s.resize` and `host.onGrid` when the
  grid is already known (starting an unstarted shell), calls `updateBlink()` (stopping `blinkTick`
  whenever `tab == 0L`), sets `full = true` and invalidates.
- `setFontSize` clamps to 6–32 dp, clears any resize preview, updates `VtRenderer` and regrids;
  `zoom` (called from `android/vtgestures`'s scale detector) steps by density and notifies
  `host.onZoom`. `setFillWide` clears any resize preview, updates `VtRenderer`, sets `full = true`
  and invalidates without regridding.
- `regrid` computes `cols = max(1, width / cellWidth)` and `rows = max(1, height / cellHeight)`.
  Only when `VtRenderer.resize` changes the grid does it clear `hasFrame`, reset `scrollPx = 0`,
  set `full = true`, call `session?.resize` and `host.onGrid`, and invalidate. `VtSession.resize`
  reflows the terminal via `VtNative.resize` (which sets native `resize_pending`, preserves any
  selected search match, and resizes the kernel console) and immediately writes any returned
  terminal replies (such as mode 2048 in-band size reports) through the tab's writer rather than
  waiting for the pump's next read.
- `onDraw` fills `screen.defaultBg` and returns early if `!renderer.hasGrid`; otherwise it expires
  any past-deadline resize preview, (when `tab != 0L`) captures `VtNative.frame(tab, full)` on the
  main thread (restoring `full` if `frame` returns null), passes it to `apply(VtFrame)` and only
  then fills the canvas with `screen.defaultBg`, so the margins beside and below the grid take a
  changed default background on the same draw as the grid.
- `apply(frame)` rejects frames whose dimensions do not match `(cols, rows)` (re-setting
  `full = true` and scheduling `postInvalidateOnAnimation()`), applies the height-shrink preview
  gate (below), copies cursor/mode/viewport/selection/scrollbar/pointer fields, resets `scrollPx`
  when `!frame.overscan` or `scrollWay() != WAY_VIEWPORT`, awakens the scroll bar if `stepFrom`
  changed `scrollOffset`, updates search progress/counts/marks, updates cursor anchor and blink
  timers, requests another full frame on default foreground/background color changes (calling
  `host.onBackgroundColor` when the background changed) or late `VtImages.take` pixels, reschedules `animationTick` for animated Kitty images, calls
  `VtRenderer.takeRows(frame)`, and sets `hasFrame = true`.
- After `apply`, `onDraw` either paints the active resize preview (scheduling
  `postInvalidateOnAnimation()` and returning early) or paints `drawContent` (grid, cursor if not
  blinked off, preedit), then `drawMatchMarks`, then `android/vtgestures`'s `drawHandles`, and
  finally shows or repositions the floating `ActionMode` menu.
- `onWindowVisibilityChanged` drops `VtImages` bitmaps, cancels `animationTick`, stops
  `passwordCheck` and clears any resize preview when hidden; becoming visible invalidates so images
  and password checks resume. `onDetachedFromWindow` clears the resize preview, stops
  `passwordCheck`, and clears blink state directly (since `isAttachedToWindow` is still true).
- Cursor blinking runs on a 500 ms half-period (`BLINK_MS`) only while `tab != 0L`, requested by
  the frame, cursor is shown, and the view is attached with view and window focus; cursor movement
  or sent input restarts the visible phase. Native frames force `cursorBlinking = false` on the
  lock cursor.
- Password mode: when a frame shows `VtNative.CURSOR_LOCK`, `apply` starts a 200 ms poll
  (`passwordCheck` -> `VtNative.passwordInput`) while the window is visible until echo returns, and
  posts `restartInput()` whenever `imePassword` changes so the IME switches input connection types
  outside `onDraw`.
- `bell` vibrates via `performHapticFeedback(REJECT)` at most once per 100 ms (`BELL_MS`).

### Height-shrink preview

- In `onSizeChanged` (before `regrid`), when width is unchanged and height shrinks (`h > 0 && h < oldh`)
  with a live terminal, `atBottom`, no selection, no active search and a grid allocated, if
  `h / cellHeight < rows && resizePreview == null && hasFrame`, the view snapshots
  `screen.defaultBg` plus `drawContent` (grid, cursor, preedit) into a temporary `w × h`
  `ARGB_8888` bitmap (clipped to the new smaller bounds) and sets `resizePreviewUntil` to
  `uptimeMillis() + 200 ms` (`RESIZE_PREVIEW_MS`).
- While `resizePreview != null`, `apply` rejects frames whose `outputPending` flag is set
  (native `resize_pending || held`, where `resize_pending` clears once post-resize output has been
  quiet for 32 ms at VT parser ground with no mode 2026 synchronized-output hold), re-setting
  `full = true` because `appine_vt_frame` already cleaned native dirty rows. `onDraw` draws the
  snapshot and calls `postInvalidateOnAnimation()` so both the 32 ms quiet timer and the 200 ms
  deadline advance even without further PTY output.
- Subsequent shrink steps (including sub-row shrinks) keep the existing bitmap and original 200 ms
  deadline without reallocating. The preview is cleared and recycled on settlement
  (`!frame.outputPending`), deadline expiry, any non-shrinking or ineligible `onSizeChanged` (width
  change, growth, scrolled back, selected, searching), `setFontSize`/`zoom`, `setFillWide`,
  `attach`, any `onTouchEvent` (plus `invalidate()`), any non-empty `send(...)`, window hide, or
  detach.

### Input, IME, paste and focus

- Hardware keys: `MainActivity.dispatchKeyEvent` filters locked privacy state, tab-list Esc and
  app-level shortcuts before `VtView` sees keys. `VtView` passes system keys (Back, Home, volume,
  media) through to the system, exempting `KEYCODE_MENU` (mapped to `GhosttyKey` 55, legacy
  `CSI 29 ~`). Mapped keys go through `VtNative.key` -> `appine_vt_key`, which syncs the encoder
  from the terminal (`ghostty_key_encoder_set_from_terminal`: cursor/keypad modes, NumLock 1035,
  Alt ESC 1036, backarrow 67, modifyOtherKeys, Kitty keyboard protocol), rejects unknown key or
  action values before encoding so stale reused-event fields are never emitted, and encodes into a
  128-byte buffer. Lone modifier presses (`VtKeys.isModifier`) ignore extra-key modifiers and send
  only when the encoder produces bytes (preserving selection). Unmapped keys with printable text
  go as UTF-8 text without Ctrl/Alt (consuming extra modifiers), or through `VtNative.key` with
  `key = 0` when Ctrl or Alt is held; unmapped keys with no text return false. A null encoder
  result swallows the key and leaves extra-key modifiers armed.
- Key releases (`onKeyUp`) encode `ACTION_RELEASE` with `event.metaState` only (never extra-key
  modifiers, never consuming them) and call `send` directly (preserving selection) if non-empty.
- Extra keys (`press`, `type`): CTRL, ALT and SHIFT from `Host` are merged into `KeyEvent` meta
  state on `press` and on single-codepoint `type` characters found in
  `KeyCharacterMap.VIRTUAL_KEYBOARD` (selecting the first non-Shift `ACTION_DOWN`). Multi-codepoint
  strings, characters absent from the virtual keymap (such as CJK or emoji), and `type` with no
  extra modifiers go straight to `input` as UTF-8 (replacing `\n` with `\r`) and leave extra
  modifiers armed. Extra keys are press-only and emit no releases.
- Shortcuts before encoding (`shortcut`): `KEYCODE_PASTE` / `Ctrl+Shift+V` pastes; `KEYCODE_COPY`
  / `Ctrl+Shift+C` copies when a selection exists (always consumed, even without a selection); with
  a selection and Shift-only + arrow / Page Up / Page Down / Home / End, `VtNative.selectAdjust`
  adjusts the selection end, stops flings, zeroes `scrollPx` and awakens scroll bars. Matched
  shortcuts consume active extra-key modifiers.
- Output dispatch: `input(data)` clears any active selection and calls `send(data)`. `send(data,
  scrolling)` discards any resize preview, stops flings unless `scrolling == true` (wheel /
  alt-scroll arrows), restarts cursor blink, scrolls the viewport back to bottom (`VtNative.scroll(tab,
  0)`, `scrollPx = 0`) if `!atBottom`, and passes bytes to `host.onInput` (which re-checks
  `Privacy.locked` before writing to `vt-writer` or closing an exited tab on Enter).
- IME (`Connection : BaseInputConnection`): `onCreateInputConnection` configures
  `TYPE_TEXT_FLAG_NO_SUGGESTIONS` normally, or `TYPE_TEXT_VARIATION_PASSWORD` with
  `IME_FLAG_NO_PERSONALIZED_LEARNING` when `imePassword` is true (always disabling extract/fullscreen
  UI). `commitText` clears the editable and `preedit`, routing lone `"\n"` to `press(KEYCODE_ENTER)`,
  any other string containing `\n`, `\r` or `\u001b` through `paste`, and everything else through
  `type`. Android 14+ `replaceText` and `finishComposingText` delegate to `commitText` after
  clearing the editable so IME clipboard pastes cannot bypass paste safety or replay later;
  replacement offsets cover only the local preedit. `performContextMenuAction` routes `paste` and
  `pasteAsPlainText` to `pasteClipboard()`. `performEditorAction` sends Enter; `setComposingText`
  updates `preedit` drawn at the cursor; `deleteSurroundingText` and
  `deleteSurroundingTextInCodePoints` send DEL `beforeLength` times when the editable is empty
  (ignoring `afterLength`) and delegate to `super` while composing before calling `setPreedit` with
  the updated editable text. `requestCursorUpdates` tracks `monitorCursor` and pushes `CursorAnchorInfo`
  (offset by `-scrollPx`) immediately and on subsequent cursor or preedit moves (not on scroll-only
  changes).
- Paste (`pasteClipboard`, `paste`, `appine_vt_paste`): `copySelection`, `pasteClipboard` and
  `paste` guard against `Privacy.locked`. `VtNative.paste(tab, text, allowUnsafe = false)` invokes
  `ghostty_terminal_paste` (bracketed under mode 2004, otherwise newlines to CR and unsafe control
  bytes scrubbed) and drains `vt->replies`. When `VtNative.paste` returns null (primarily
  `GHOSTTY_REJECTED`: line breaks without mode 2004, or a bracketed-paste terminator), the view
  shows a Material 3 confirmation dialog via `showPrivate()` (`FLAG_SECURE`) with a 300-character
  monospace preview (`Context.monospaceMessage` in `Ui.kt`, preserving `TypefaceSpan` through `^1`),
  "Paste as is" and Cancel. A neutral "Drop trailing newlines" action appears only when
  `text.trimEnd('\r', '\n')` is shorter, non-empty, and passes a probe `VtNative.paste(..., false)`;
  choosing it re-calls `paste(trimmed)` to recheck the terminal modes. Both actions require the
  original dialog, the requesting session, a live terminal and an unlocked page. Changing or
  detaching the session dismisses the dialog and invalidates queued clicks.
- Focus: `VtView` tracks window focus (`windowFocused: Boolean?`) and the session holding terminal
  focus (`focusedSession`), delivering non-empty `VtNative.focus(session.tab, gained)` bytes
  (encoded via `ghostty_focus_encode` into a 16-byte buffer only when mode 1004 is enabled, queried
  directly by `appine_vt_focus` via `mode_on`, while `FLAG_FOCUS_EVENTS` in the frame header goes
  unread by `VtFrame`) through `host.onFocus(session, bytes)` (checked against `Privacy.locked` in
  `MainActivity.Host` and written directly to `session.write` without calling `send(...)`,
  preserving `settle()` and scrolled-back viewports). `onWindowFocusChanged` finishes flings and
  calls `settle()` if `scrollPx != 0` on focus loss, deduplicates repeated states, updates cursor
  blinking and invalidates. Switching tabs (`attach`) while `windowFocused == true` sends focus-out
  to the outgoing session and focus-in to an already-started incoming session; tab switches while
  unfocused, repeated attaches, and detaches after focus loss emit no duplicate or spurious events.
  `onAttachedToWindow` syncs an already-focused window; `onDetachedFromWindow` clears focus state
  (sending focus-out if still focused). `onFocusChanged` only updates blink.

### Search and prompt jumps

- `search(needle)` sets `searching = true`, calls `VtNative.search` (`appine_vt_search`, which skips
  allocating `GhosttySearch` if `vt->search == NULL` and `needle` is empty, else sets
  `GHOSTTY_SEARCH_OPT_NEEDLE`), resets `searchTotal = -1` and `matchRowsTotal = -1` (forcing count
  and scroll-bar mark notifications on the next frame, including "0/0"), and invalidates.
  libghostty-vt matches UTF-8 bytes with ASCII case-insensitivity across the active screen and
  scrollback, preserving primary-screen results while on the alternate screen. Frame capture
  (`android/vtrender`) advances search up to 4 ms per frame and reports `searchPending`, total and
  1-based selected index; `apply` schedules animation redraws while pending and notifies
  `host.onSearchCount` on changes.
- `searchStep(older)` calls `VtNative.searchSelect` (`ghostty_search_select_next` for older /
  `prev` for newer, wrapping round and scrolling if needed), stops flings, zeroes `scrollPx`,
  records `stepFrom = scrollOffset` (so the next `apply` awakens scroll bars if the viewport
  moved) and invalidates. `endSearch` clears Kotlin search state and frees `vt->search` and its
  scratch buffers via `VtNative.searchEnd` (`appine_vt_search_end`).
- Scroll-bar search marks: while `searching`, `apply` refreshes `VtNative.searchRows`
  (`appine_vt_search_rows`) when total or selected match changes, when `scrollTotal` shrinks, or at
  most every 500 ms (`MATCH_ROWS_MS`) when dirty frames arrive (catching steady-state top eviction).
  `appine_vt_search_rows` resolves the selected match directly via `screen_point` and all other
  matches newest-first via each page's first row (`x = 0, y = 0`), deduplicating adjacent rows
  without decompressing cold scrollback pages.
  `drawMatchMarks` draws non-fading marks (`verticalScrollbarWidth` wide, `2 dp` tall, min 1 px)
  along the right scrollbar track beneath the fading thumb whenever `scrollTotal > scrollLen`
  (yellow `SEARCH_MATCH` merged per vertical pixel, then orange `SEARCH_SELECTED` on top).
- Resize search preservation: in `appine_vt_resize` (`android/vtcore`), if a search match was
  selected before reflow, `search_reselect` runs `ghostty_search_run` synchronously to completion
  and steps back to that 0-based index from newest (suppressing scroll until the final step).
- `jumpToPrompt(delta)` returns `false` if `tab == 0L || altScreen` (letting `Ctrl+Shift+↑/↓`
  fall through on the alternate screen); otherwise stops flings, zeroes `scrollPx`, records
  `stepFrom`, calls `VtNative.jumpPrompt` (`appine_vt_jump_prompt`, which sets
  `compress_touched = true` because prompt scanning may decompress cold scrollback pages, and
  scrolls via `GHOSTTY_TERMINAL_SCROLL_VIEWPORT_DELTA_PROMPT`), invalidates and returns `true`.

## Dependencies (inbound / outbound)

### Inbound

- `android/terminal`: `TerminalLayout` builds `VtView` and sets font size/visibility; `MainActivity`
  implements `VtView.Host` and calls `attach`, `bell`, `setFillWide`, `altScreen`, `search`,
  `searchStep`, `endSearch`, `jumpToPrompt`, `press` and `type`.
- `android/vt`: `VtSession.view` calls `onStarted`, `postInvalidateOnAnimation` (from pump thread)
  and `invalidate`.
- `android/vtgestures`: co-located sections on `VtView` call `zoom`, `clearResizePreview`, `send`,
  `copySelection` and `pasteClipboard`, use `VtKeys` (`of`, `mods`, `ACTION_PRESS`), `inputMethod`,
  `clipboard`, `host` and `screen`, and read frame-applied modes, scroll bounds and selection bounds.
- `android/vtcore`: `vt.rs` locks (`TermGuard`) and invokes `appine_vt_key`, `appine_vt_paste`,
  `appine_vt_focus` and `appine_vt_search*`; `vt.c`'s `appine_vt_free` frees search buffers and
  `appine_vt_resize` preserves selected search matches.
- `android/vtrender`: `vt.c`'s `appine_vt_frame` advances `vt->search` and diffs viewport cell marks.

### Outbound

- `android/vtgestures`: `VtView` calls `drawHandles`, `showMenu`, `scrollWay`, `updatePointer`,
  `settle`, `hoverModifiers` and `clearSelection`, and resets gesture/scroller/menu/hover state on
  `attach` and `onWindowFocusChanged`.
- `android/vtrender`: owns `VtScreen`, `VtImages` and `VtRenderer`, decodes `VtFrame`, updates
  screen cursor/default colors, drives `VtRenderer.takeRows`/drawing/metrics and `VtImages.take`/
  `drop`, and reads `VtRenderer.SEARCH_MATCH`/`SEARCH_SELECTED`.
- `android/vt`: attached `VtSession` (`tab`, `view`, `resize`).
- `android/vtcore`: `VtNative` (`frame`, `passwordInput`, `CURSOR_LOCK`, `key`, `paste`, `focus`,
  `copy`, `selectAdjust`, `ADJUST_*`, `scroll`, `gestureEnd`, `search`, `searchSelect`,
  `searchRows`, `searchEnd`, `jumpPrompt`); in `vt.c`, `mode_on`, `screen_point`, `on_write_pty`
  and `vt->replies`.
- `android/terminal`: `VtView.Host` callbacks, `Ui.kt` (`themeDrawable`, `monospaceMessage`,
  `showPrivate`) and paste dialog string resources.
- `android/privacy`: `Privacy.locked` guards on copy/paste (and `FLAG_SECURE` via `showPrivate`).
- `libghostty-vt`: key encoder, paste encoder, focus encoder, search API and prompt viewport scroll.
- Android framework: `InputMethodManager`, `ClipboardManager`, Material 3 `AlertDialog`, haptics.

## Invariants and gotchas

- `hasFrame` is independent of `full`: requesting a full frame (`full = true`) does not clear
  `hasFrame`, so a queued repaint does not suppress height-shrink preview capture. Null frame
  captures restore `full`, and frames rejected for dimension mismatch or `outputPending` re-set
  `full = true` because `appine_vt_frame` already cleaned native dirty rows.
- Output settlement is heuristic, not a `SIGWINCH` acknowledgement: a 32 ms quiet gap at parser
  ground may still precede a later redraw, while a partial escape sequence or UTF-8 byte never
  settles early (bounded by the 200 ms deadline). `onGenericMotionEvent` viewport scrolling and
  `setPreedit` do not discard an active preview immediately; empty `send()` calls do not either.
- `VtFrame`'s backing direct `ByteBuffer` is valid only until the next `VtNative.frame` call on the
  main thread and must be consumed synchronously in `onDraw`.
- `BaseInputConnection.replaceText` (Android 14+) and `finishComposingText` must clear the editable
  and funnel through `commitText` so IME clipboard pastes cannot bypass unsafe-paste confirmation
  or replay later; `performContextMenuAction` must override Paste/Paste as plain text explicitly.
- Reused `GhosttyKeyEvent` safety: `appine_vt_key` validates `action` and `key` setter return codes
  before encoding so invalid values never re-encode the previous event.
- `appine_vt_paste` relies on `vt->replies` being empty before `ghostty_terminal_paste` because
  `vt.rs` drains the whole buffer (maintained by `feed`, `resize` and `promptClick` draining before
  unlocking).
- When mode 1004 is active, focus events (`onWindowFocusChanged`, `attach`, `onAttachedToWindow`,
  `onDetachedFromWindow`) go directly to `host.onFocus(session, bytes)` rather than `send(...)`,
  preserving `settle()` and any scrolled-back viewport position and targeting each session even
  after `MainActivity.show` updates `current`.
- With IME shown, a hardware Esc press is consumed by the IME (e.g. Gboard hides itself), so a
  Kitty-protocol program receives only the `ACTION_UP` release.
- Scroll bar metrics (`computeVerticalScroll*`) return pixels with `scrollPx` added to offset so
  the thumb follows pixel scrolling; a programmatic `View` needs `verticalScrollbarThumbDrawable`
  and `isScrollbarFadingEnabled = true` explicitly. `defaultFocusHighlightEnabled = false` prevents
  a translucent grey overlay after hardware keys.
- `onDetachedFromWindow` stops blinking directly rather than via `updateBlink()` because
  `isAttachedToWindow` is still true during the callback, and does not call `dropImages()` (images
  are dropped in `onWindowVisibilityChanged` and `attach`).
- `appine_vt_search_rows` resolves matches via page metadata without decompressing cold scrollback
  pages, whereas `appine_vt_jump_prompt` decompresses cold pages and must set `compress_touched =
  true`. `search_reselect` runs `ghostty_search_run` synchronously on the main thread during resize
  and re-selects by 0-based match index from newest (which can pick a different match if reflow
  changed match count).
- `VtView.search("")` sets `searching = true` without allocating `vt->search`, suppressing
  height-shrink previews until `endSearch()`. `jumpToPrompt` checks cached `altScreen` from the
  last frame.
- `VtView` with `tab == 0L` keeps drawing the last painted grid bitmap in `onDraw`.
- Frames `apply` rejects (an old grid size, or `outputPending` during a resize preview) return
  before the default colours are read, so they change neither the canvas fill nor the host's
  chrome (`onBackgroundColor`).

## Confirmed bugs / technical debt

None.

## Open questions

None.

## To verify

- Height-shrink preview on physical devices (IME animation interruptions, vendor keyboards, touch/tab
  cleanup) and real-device behavior of Gboard recommendation strip/clipboard history, CJK composing
  and floating candidates (`CursorAnchorInfo`), IMEs sending Enter as text, non-Gboard password
  modes, hardware keyboards, paste confirmation dialog under vendor fonts/accessibility scales, and
  bell with haptics off.
- Two `TerminalResizeTest` cases cover OSC 11 same-frame margin repaint and withholding
  background callbacks for pending resize frames. They compile against API 37.0 with warnings
  as errors but have not executed on a device.
