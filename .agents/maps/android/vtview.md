# android/vtview Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/vtview.md` for the paired decision history (decisions from before the split are D5, D7, D9, D16, D17, D25, D30–D32, D34, D36, D37, D40, D41, D43 and D46–D48 in `.agents/decisions/android/terminal.md`; this snapshot also keeps the decisions on rendering and gestures/selection/scrolling made before `android/vtrender` and `android/vtgestures` were split out).
>
> Verified: 2026-11-22 (full project-source mapping: 5 concerns, 20 claims checked by 2 independent verifiers; 12 confirmed and 8 partial, narrowed below; external and device residuals retained)

## Responsibilities

`android/vtview` is the terminal view's lifecycle, frame orchestration, keyboard/IME/clipboard
input and search: `VtView` attaches a tab, manages grid sizing, requests frames and applies their
state (including height-shrink previews), schedules redraws and cursor/password timers, handles
hardware/extra-key encoding, the IME, pastes, focus events, scrollback search and prompt jumps.
`VtKeys` maps Android key codes to libghostty-vt's key numbers.

Root: `VtKeys.kt` and `VtView.kt` (except its `Selection`, `Touch`, `A mouse or touchpad` and
`Scrolling` sections) in `android/app/src/main/java/io/github/mthli/appine/`, and the `Input`,
`Paste`, `appine_vt_focus` (in `Mouse and focus`) and `Search` sections of `hosts/android/src/vt.c`.

Outside the module: touch/mouse gestures, pixel scrolling/flings, selection handles/menu, links
and prompt-output/prompt-tap actions (`android/vtgestures`); the frame format, `Frames` section of
vt.c, screen mirror, rendering classes and font (`android/vtrender`); the sessions (`android/vt`);
terminal handles and locks, JNI functions (`VtNative`, `vt.rs`) and the rest of vt.c
(`android/vtcore`); the surrounding screen, search bar and opening links (`android/terminal`).

## Key types

- `VtView` — the view: the attached `VtSession`; its `VtScreen`, `VtImages` and `VtRenderer`
  (`android/vtrender`, whose cell metrics it reads); the font size and the wide-cell setting; the
  last frame's modes (`altScreen`, `mouseTracking`, `altScroll`), scroll range/offset/length
  (`atBottom`) and selection bounds/shape; the height-shrink preview (`resizePreview`,
  `resizePreviewUntil`, `hasFrame`, `full`); the search state, count and match rows along the
  scroll bar; the animation redraw; the IME connection (`Connection`, `preedit`, `monitorCursor`);
  the cursor blink timer; the password check (`passwordCheck`, `imePassword`); the bell's last
  vibration; plus the gesture/selection/scrolling state owned by `android/vtgestures`. `Host`
  (the activity): `onGrid`, `onInput`, `onZoom`, the extra keys' `ctrl`, `alt`, `shift` and
  `modifiersUsed`, `onLink`, `onSearchCount` and optional `onBackgroundColor`.
- `VtKeys` — Android key codes to libghostty-vt's `GhosttyKey` numbers (`of`, 0 when unknown),
  modifier bits (Shift, Ctrl, Alt, Meta as Super; no lock bits), actions, `isModifier`.

## Public entry points

- `VtView(context, host)`, built by `MainActivity`: `attach` (show a tab, or none), `setFontSize`,
  `setFillWide`, `press` and `type` (the extra keys), `search`, `searchStep` and `endSearch`,
  `jumpToPrompt`, `bell`, `altScreen`; the framework's drawing (`onDraw`), sizing
  (`onSizeChanged`), scroll-bar (`computeVerticalScroll*`), key (`onKeyDown`/`Up`),
  focus/visibility and IME (`onCreateInputConnection`) callbacks. `Host` is the activity's side; optional
  `onBackgroundColor` reports changes only after a frame is accepted for display.
- From the session (`android/vt`): `onStarted` (the shell started: take the whole screen) and an
  invalidate on animation after output.

## Data flow / lifecycle

### Attachment and sizing

- Once started, a session owns its terminal and pump independently of view visibility; output
  invalidates only its current view. Attaching the same session does nothing. A different
  attachment ends prior search and interactions, drops image copies, resets scroll metrics,
  the view's selected flag and `hasFrame`, switches session backpointers, applies an already-known
  grid and requests a full frame. It does not reset every frame-derived mode or selection coordinate.
- With nonzero bounds, regrid computes at least one column and row from the view and cell sizes.
  When the renderer's grid or bitmap dimensions change, it immediately resizes the attached
  session and calls `Host.onGrid`; the host starts the current session only once. The renderer
  includes one overscan row. Font size is clamped to 6–32 dp.
- Hiding the window clears the preview, password polling and image animation/copies. Detach
  also explicitly stops cursor blinking. Window-focus changes update blinking and forward
  requested mode-1004 events; tab attachment sends no focus pair.

### Frame integration

- `onOutput` invalidates the attached view; `onDraw` takes `VtNative.frame` on the main thread,
  reads it through `android/vtrender`'s `VtFrame`, and applies the header to interaction state and
  `VtScreen`. `VtImages.take` copies image pixels and `VtRenderer.takeRows` updates the grid
  bitmap; the renderer draws the grid, cursor and preedit, then the view draws scroll-bar search
  marks and `android/vtgestures`'s selection handles.
- The whole canvas is cleared after frame application, using the accepted default background so
  subrow margins change on the same draw. A changed background also notifies the host for chrome;
  stale-grid frames and held resize-preview frames leave both colours and host state unchanged.
- The view owns regridding, full-frame requests, animation redraws and applying mode, selection,
  scroll, pointer and search-count fields. It rejects frames at an old grid size and requests a
  full frame after attaching, shell start, regridding, default-colour or wide-cell changes, or
  late image pixels; the rendering contract and image lifetimes are in `android/vtrender`.
- When a positive height shrinks at the same width with `height / cellHeight` below the previous
  row count (as the IME opens), at the bottom with a live terminal and no
  selection or search and a painted grid, it captures the old grid, cursor and preedit in a bitmap
  clipped to the new bounds. Regridding runs immediately; an actual grid or cell-metric change
  resizes the terminal and console in that callback. The preview stays until a frame reports
  settled output after resize (a nonempty post-resize feed followed by 32 ms quiet at parser ground,
  with no synchronized-output hold), or the next draw after 200 ms. Frames rejected while waiting
  require another full frame, since native capture consumes dirty rows. Draws continue on
  animation frames even without output. Another shrink, even within the same grid row, keeps the
  original deadline; a growing or width-changing layout, font/wide-cell change, tab change, touch,
  encoded input, hidden window or detach discards the preview. Scrolled-back, selected and
  searched content, width changes and growing grids use the normal immediate path. `hasFrame`
  tracks whether the current bitmap is painted independently of `full`: asking for every row again
  does not make the already-painted content unavailable for a preview.
- A resize (`VtSession.resize`, from an attachment with a known grid or a changed regrid) takes the replies the terminal
  made for it, the in-band size report of a program using mode 2048, and writes them through the
  tab's writer at once, rather than leaving them for the pump's next read. Native search
  reselection attempts to keep the previous relative selected index through a resize.
- The frame's lock cursor switches the IME's password mode (Input); while visible the view polls
  the console every 200 ms until that state ends. Cursor blinking runs every 500 ms only while
  requested by a shown cursor, the view is attached and the view/window have focus; input or cursor movement restarts it.
  Cursor appearance, default-style semantics and drawing are in `android/vtrender`.
- The bell of the tab shown vibrates once through `performHapticFeedback(REJECT)` (a double click,
  subject to the system's touch feedback setting), at most once per 100 ms.

### Input

- Keys: mapped keys go through `VtNative.key`; the native adapter refreshes the encoder from the
  terminal before each event (`set_from_terminal`). Encoding and mode semantics are delegated to
  libghostty-vt, including releases from `onKeyUp` and
  lone modifiers, which are sent only when the encoder emits something. An unmapped key that
  types a character goes as text without Ctrl or Alt, and to the encoder as an unidentified key
  with that text with them; one that types nothing goes to the system. System keys (Back, Home,
  volume, media) go to the system, except the menu key, a hardware keyboard's context menu key,
  which goes to the encoder (`CSI 29 ~` in the legacy encoding). A key the encoder cannot encode
  is swallowed and leaves the modifiers on.
- CTRL, ALT and SHIFT on the extra keys (SHIFT only with the first page shown) apply to the next
  key or one typed character (turned back into a key event through the virtual keyboard's key
  map), or to every one while locked: they are added to the key event's meta state, so with SHIFT
  a key types its shifted character in that map (`a` → `A`, `-` → `_`, `/` → `?`) and Tab is sent
  as back-tab. A character the key map lacks (CJK) or a commit of several characters goes as text
  and leaves them on; so does any character typed with no modifier on. The extra keys send presses
  only (a held key repeats as new presses), never releases, and a key's release never carries
  their modifiers.
- Ctrl+Shift+C and V (held, or from the extra keys, also with a character the IME types) and the
  dedicated copy and paste keys copy and paste; copying without a selection does nothing, and the
  release still reaches the program.
- With a selection, Shift with an arrow, Page Up or Down, Home or End (a hardware keyboard, or the
  extra keys' SHIFT with their arrows, HOME and END) moves its end as Ghostty's adjust_selection
  keys do (`VtNative.selectAdjust`): to the previous or next non-blank cell (going round rows), a
  row or a page up or down at its column, the screen's top left cell, or the end of its last
  non-blank row; the anchor of a drag is dropped and the viewport scrolls to show the end (at its
  top when above, at its bottom when below). Without a selection the keys reach the program.
- Nonempty typed and pasted bytes end a selection; all input that encodes to bytes (focus events and hover
  motion included) first scrolls the viewport back to the bottom (the grid on a whole row) and,
  but for scrolling's own wheel events and arrow keys, stops a fling or settling, then goes
  through the host to the tab's `vt-writer` thread (`Native.write`).
- IME: committed text is sent at once (a lone `\n` as Enter; other text containing LF, CR or ESC
  through paste encoding and its safety check). Android 14's `replaceText` and finishing a
  composition use the same commit path and clear the editable before delivery or confirmation, so
  later `finishComposingText` calls cannot replay it. Replacement offsets address only the local
  preedit; already-sent terminal input cannot be replaced. IME context-menu Paste and Paste as
  plain text use the same clipboard path as the view's menu. The editor action is Enter; composing
  text is only drawn at the cursor; the editable is kept empty so Backspace with nothing composed
  arrives as `deleteSurroundingText` and becomes as many DELs (text after the cursor is ignored).
  `requestCursorUpdates` is answered with the cursor and composing text's position
  (`CursorAnchorInfo`, less `scrollPx`), again whenever the cursor or composing text moves while
  the IME monitors it (not when only `scrollPx` changes).
- The editor is text without suggestions (`TYPE_TEXT_FLAG_NO_SUGGESTIONS`), and a password
  (`TYPE_TEXT_VARIATION_PASSWORD` with `IME_FLAG_NO_PERSONALIZED_LEARNING`) while the frames give
  the cursor as a lock: when a frame changes that, the view posts an input restart (outside
  drawing); attaching another tab during one turns it off and restarts the input at once; the IME
  then takes a new connection of the other kind. Gboard then shows its password layout (a number
  row, no toolbar or suggestions) and is asked to learn nothing typed; restarting the input ends a
  composition, which password layouts do not make.
- Paste (`VtNative.paste`, through `ghostty_terminal_paste`): bracketed with mode 2004, else line
  breaks become carriage returns; unsafe control bytes become spaces. Text that could run commands
  (line breaks without bracketed paste, or the bracketed terminator) is refused, and the view asks
  in a Material 3 dialog with a monospace preview (300 UTF-16 code units plus an optional ellipsis), Paste as is and Cancel.
  `Ui.monospaceMessage` preserves the preview's TypefaceSpan through localized `^1` substitution;
  the explanation keeps the dialog's normal font. A neutral Drop trailing newlines action appears
  only when removing the final run of CR/LF leaves nonempty text that the paste encoder accepts; it
  preserves all other whitespace. Checking eligibility encodes without sending input; choosing the
  action rechecks privacy and encodes against the current terminal modes rather than sending the
  earlier result.
- Copy, clipboard reads and paste entry points refuse access while `Privacy.locked`; paste
  previews use `showPrivate` so their separate windows follow `FLAG_SECURE`. The activity also
  guards the final input sink against queued IME/paste callbacks after locking.
- Focus: window focus changes are sent as focus events when the program asked (mode 1004); showing
  another tab sends none.

### Search and prompt jumps

- `VtView.search` (`VtNative.search`) submits the search bar's text (`android/terminal`) to one
  native search per terminal. Empty text skips creating a search or clears an existing needle.
  Query changes invalidate row/count sentinels rather than immediately clearing the row cache.
  Matching, direction, wrap and alternate-screen retention follow libghostty-vt. `searchStep`
  delegates selection; on success it stops a fling and puts the grid on a whole row, with the
  scroll bar shown after a frame reports viewport movement. The count, reported to the activity when it changes and once after every `search`
  (so a needle that is not found reads "0/0"), grows as a long scrollback is searched over several
  frames (`android/vtrender` drives the search from frame capture, checking a 4 ms progress budget
  between library calls; pending accepted frames schedule another draw). `endSearch`
  (`VtNative.searchEnd`) clears view marks and frees native search/all-match/row state.
- Matches are drawn as Ghostty draws them: black text on yellow, the selected match on orange, the
  second cell of a wide character with its first. Along the scroll bar, as browsers mark found
  text, a 2 dp mark as wide as the scroll bar in the same yellow (the selected match's in orange)
  stands for each row a match starts on, at that row's place among the scrollable rows (where the
  thumb's top is when the row is the viewport's first, unless the thumb is held at its least
  length), rows closer than a pixel sharing one; the marks stay while the search runs and there is
  a scrollback, under the thumb, which fades as before. The view takes the rows
  (`VtNative.searchRows`) when the count or the selected match changes, when the scrollable rows
  shrink (rows left the scrollback at its limit, or it was cleared) and at most every 500 ms while
  frames bring changes, since rows that leave the scrollback move every match's row. JNI returns
  the selected row first, then vt.c's rows in library match order with adjacent duplicates removed.
  vt.c reuses a page's first-row lookup while its node remains unchanged, adding the match's row
  within that page; global uniqueness/order and compressed-page avoidance depend on the library.
- Jumping between prompts (`VtView.jumpToPrompt`, `VtNative.jumpPrompt`) refuses an absent
  terminal or alternate screen and passes the signed delta to the native prompt-scroll adapter.
  A fling stops, the grid goes back to a whole row (`scrollPx` 0), and the next accepted frame
  shows the scroll bar only if the viewport moved. (Selecting a command's output and tapping to move the prompt's cursor belong to
  `android/vtgestures`; prompt-mark parsing belongs to `android/vtcore`.)

## Dependencies (inbound / outbound)

### Inbound

- `MainActivity` (`android/terminal`): the entry points above; it also passes the service's bell
  for the tab in front (`bell`) and the wide-cell setting.
- `android/vt`: `VtSession.view`, through which the session invalidates the view and reports its
  shell's start.
- `android/vtgestures`: calls `send`/`input`, `copySelection`/`pasteClipboard`, `zoom`,
  `clearResizePreview`, and reads frame-applied modes, scroll bounds and selection bounds.

### Outbound

- `android/vtgestures`: `drawHandles`, `clearSelection`, `updatePointer`, `hoverModifiers`,
  `settle` and `VtView.pointerType` (plus `VtNative.selectAdjust` in `vt.c`'s `Selection`
  section).
- `android/vtrender`: `VtFrame`, `VtScreen`, `VtImages` and `VtRenderer`; the view supplies grid
  and font settings, applies headers, requests full frames and draws search marks. Frame capture
  advances the search and encodes its cell marks; this module owns query changes, match selection
  and the marks along the scroll bar.
- `android/vt`: the attached `VtSession` (`tab`, the terminal handle, and `resize`).
- `android/vtcore`: `VtNative`'s functions for frames, password state, key/paste/focus encoding,
  prompt jumps and search, which hold the tab's lock.
- `android/terminal`'s `MainActivity` through `Host` (`onGrid`, `onInput`, `onZoom`, the extra
  keys' `ctrl`, `alt`, `shift` and `modifiersUsed`, `onLink`, `onSearchCount`, `onBackgroundColor`); input reaches the
  tab's writer that way.
- `android/privacy`: `Privacy.locked` checks on copy/paste and `showPrivate` on paste confirmation
  dialogs.
- libghostty-vt through `vt.c`: key encoder, paste, focus encoding, prompt scrolling and search.
- The clipboard, Material Components' dialog for paste confirmation and haptics.

## Invariants and gotchas

- Output readiness is not an acknowledgement of SIGWINCH: even a quiet gap at parser ground may
  precede a later redraw. A partial control sequence or UTF-8 character never releases the preview
  through readiness; the 200 ms deadline still bounds it. The preview is bounded rather than
  waiting indefinitely for a program that ignores the size change; it adds one temporary bitmap of
  the smaller view. Null frame captures preserve the full-frame request.
- `BaseInputConnection.replaceText` (Android 14+) edits its buffer without calling the view's
  `commitText`; inheriting it silently buffers IME clipboard text. A later finish can then send
  that text unexpectedly. All committed IME entry points must use the same paste safety checks;
  `performContextMenuAction` also needs an override because the base implementation does nothing.
- With IME shown, a hardware Esc press is taken by the IME (Gboard hides itself), so a program
  using the Kitty protocol's release events sees only the release.
- The scroll bar is `View`'s own (`computeVerticalScrollRange`, `Offset` and `Extent` return the
  last frame's rows in pixels, the offset with `scrollPx`, so it follows pixel scrolling), shown
  with `awakenScrollBars` wherever the viewport moves. A view built in code has no scroll bar
  until it is given a thumb (`verticalScrollbarThumbDrawable`, the theme's
  `scrollbarThumbVertical`) and fading is turned on explicitly; `View` also flashes it each time
  the window becomes visible again.
- `VtView` turns off the default focus highlight: focused outside touch mode (after hardware or
  injected keys) the system would cover the whole view with a translucent grey.
- Without a terminal (`tab` 0) `onDraw` draws the bitmap as it was last painted.
- Numeric key/action tables must match the pinned libghostty-vt ABI. vt.c encodes nothing when
  an event setter fails; the dependency headers require a separate source check.
- Resize reselection tracks an available relative index rather than match identity. It attempts
  to run and reselect with intermediate scrolling suppressed, returns when search progress fails
  and does not check every setter/final-selection result. Changed results can select different text.
- Search's 4 ms progress budget is checked between library calls, so a single call can exceed it.
- A frame is valid only until the next capture. Keep `android/vtrender`'s full-frame invalidation,
  image-drop and overscan contracts and `android/vtgestures`'s selection/scrolling contracts when
  changing view lifecycle or frame handling.

## Open questions

- Should showing another tab send focus-out and focus-in (mode 1004) to the two tabs?

## To verify

- Pinned libghostty-vt 1.0.0 source is unavailable locally: key ABI tables, search case folding,
  wrap/index ordering, alternate-screen retention, resize reselection and prompt-scroll semantics,
  and whether page-coordinate lookup avoids decompression need dependency-source verification.
- Height-shrink preview on physical devices: whether the corrected edge cases explain the
  occasional old-text report at IME opening, plus actual IME animation interruptions and touch/tab
  cleanup.
- Real Gboard taps on the recommendation strip and clipboard history, CJK IMEs' composing text and
  floating candidates (`CursorAnchorInfo`), which IMEs deliver Enter as text, other IMEs' password
  mode, hardware keyboards, and Android 11–13 / real or 16 KB-page devices.
- Paste confirmation dialog with vendor fonts and larger accessibility font scales.
- The bell with haptics off.

- Two `TerminalResizeTest` cases cover OSC 11 same-frame margin repaint and withholding
  background callbacks for pending resize frames. They compile against API 37.0 with warnings
  as errors but have not executed on a device.
