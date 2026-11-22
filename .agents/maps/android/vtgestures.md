# android/vtgestures Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/vtgestures.md` for the paired decision history (not yet created; decisions from before the split are D6, D11 and the gesture/selection/scrolling parts of D1 and D5 in `.agents/decisions/android/vtview.md`, and D25, D30, D31, D34, D40 and the gesture/selection/mouse/prompt-tap/scrolling parts of D7, D16, D17, D43, D46 and D48 in `.agents/decisions/android/terminal.md`).
>
> Verified: 2026-11-22 (split out of android/vtview, inherited from the android/terminal full mapping of 2026-11-11 and its later maintenance; the boundary was checked against the source at the split)

## Responsibilities

`android/vtgestures` owns touch and pointer interaction, pixel scrolling, selection, links and
prompt-tap actions on `VtView`:

- touch taps, double/triple taps, long presses, pinch zoom and finger drags;
- mouse and touchpad button routing, desktop-style pointer selection, hover motion, context menus
  and OSC 22 pointer icons;
- viewport pixel scrolling (`scrollPx`), flings (`OverScroller`), whole-row settling,
  mouse-wheel/alternate-scroll translation and scroll-bar awakening;
- selection handles, floating `TYPE_FLOATING` action mode, rectangular/linear toggles, Select
  output and libghostty-vt selection gestures;
- OSC 8 and plain-text URL detection and prompt-mark cursor-click-to-move.

Root: in `android/app/src/main/java/io/github/mthli/appine/VtView.kt`, the `Selection`, `Touch`,
`A mouse or touchpad` and `Scrolling` sections; and in `hosts/android/src/vt.c`, `appine_vt_mouse`
in `Mouse and focus` plus the `Selection`, `Links` and `Taps on the prompt` sections.

Outside the module: `VtView` lifecycle, grid metrics, frame integration and height-shrink preview,
cursor/password timers, keyboard/IME/paste input, focus events, search and `jumpToPrompt`, plus
`VtKeys` (`android/vtview`); frame encoding/decoding and grid/cursor/preedit drawing
(`android/vtrender`); sessions (`android/vt`); terminal handles, locks, JNI (`VtNative`, `vt.rs`)
and prompt-mark parsing (`android/vtcore`); link opening and activity host callbacks
(`android/terminal`).

## Key types

- `VtView` interaction state (owned on `VtView` alongside `android/vtview`'s frame/input fields):
  `scrollPx` and sub-pixel drag remainder; `OverScroller` of flings and whole-row settling
  (`settling`, `stoppedFling`); gesture and drag state (taps in a row, `pointerButton`,
  `lastPointerPress`, `pointerRectangle`, `pointerSelection`); mouse pointer state (`pointerShape`,
  `hoverCell`, `hoverLink`, `hoverCtrl`, `pointerSet`); selection bounds, shape, autoscroll timer,
  handles (`handleStart`, `handleEnd`, `handleExclusion`) and floating `ActionMode` (`menu`,
  `menuPending`, `menuLink`, `menuOutput`).

## Public entry points

- Android `View` callbacks on `VtView`: `onTouchEvent`, `onGenericMotionEvent`,
  `onResolvePointerIcon`, `computeScroll`.
- Internal `VtView` hooks called by `android/vtview`: `drawHandles` (from `onDraw`),
  `clearSelection` (from input/attach), `updatePointer` and `hoverModifiers` (from frame apply and
  key events), `settle` (from window focus loss), and `VtView.pointerType`.
- Native helpers called by `android/vtrender`'s `Frames` section: `viewport_ref` and `screen_point`
  in `vt.c`'s `Selection` section.

## Data flow / lifecycle

### Touch, mouse and selection

- A finger's (or a stylus's) tap ends a selection or its menu; a mouse's or touchpad's press takes
  the pointer paths below. Otherwise, when the program does not track the mouse and the tap is on
  a link, it opens the link instead of the IME. When the program tracks the mouse, it sends a left
  click (press and release at the tap's pixel position, in the program's format) and opens the IME
  only if the tap is not on a link accepted by `linkAt`; opening the link stays with the program
  or the long-press menu. Otherwise it opens the IME and moves the shell's cursor when it is on
  the input at the prompt (Links and prompt taps below). A tap that stopped a fling does nothing
  else (one during settling on a whole row is no fling stop and acts). Taps act at once: `VtView`
  counts taps in a row itself (each within the system's double-tap timeout and slop of the last
  tap's lift). With mouse tracking every tap is a click, for the program's own double and triple
  clicks. Without it, the press of the second tap selects the word under it and that of the third
  the line, before the gesture detector sees it (`tapPress`), and the view keeps that touch: moved
  on past the touch slop, it drags the selection by whole words or lines (Ghostty's double- and
  triple-click drags, through libghostty-vt's selection gesture, below); lifted, the menu comes
  up, and a press that did not drag counts as a tap (one that dragged ends the row of taps). A
  fourth tap counts as a first, and so does a tap after one that opened a link. The line is
  Ghostty's triple-click line: the soft-wrapped line with blanks at its ends left out, cut where
  an OSC 133 prompt mark starts or ends a part of it. A second or third tap on blanks selects
  nothing and goes on as a single tap.
- Word and line selections and the drags after them go through libghostty-vt's selection gesture
  (`VtNative.gesturePress`, `gestureDrag`, `gestureEnd`; vt.c keeps one gesture per terminal): the
  press selects the word or line at its cell, which the gesture tracks through output, and a drag
  takes the selection from the pressed cell's word or line to the one under the finger
  (`selectWordBetween` both ways for words), so over blanks and punctuation a word drag stays on
  the last word reached, while a line drag takes in blank rows too (libghostty-vt 1.0's fix;
  before, the selection stayed as it was); any drag once the pressed cell's screen has changed
  (the alternate screen) leaves the selection as it was. The view counts a finger's taps itself,
  since a finger press may become a scroll, so each finger press goes to the gesture untimed (a
  first click in libghostty-vt's count) with the behaviour the view asks for as a first click's; a
  mouse's left presses go to the same gesture timed (below). Lifting a finger ends the gesture
  (its tracking goes, the selection stays); so does clearing the selection, a right-click selecting
  a word, or attaching another tab during a drag, a mouse's included.
- A long press (ignored during a pinch, with a long-press haptic) selects the word under it as a
  gesture's press (`GESTURE_WORD`), notes whether the cell is in a command's output (Links and
  prompt taps below), and moving on extends the selection by whole words as a double tap's drag
  does. On blank cells it selects nothing and shows a menu with Paste (with a clipboard), Select
  all and, on a link, Open link. When the program tracks the mouse, the long press selects the
  same way, but what it becomes waits for the finger: lifted, it keeps the word (or the point
  menu); moved on past the touch slop, the selection and the output found are dropped and the
  program gets a left-button drag instead (press at the long-pressed point, motion while moving,
  release where the finger lifts).
- A mouse or touchpad (not a finger) pressed while the program tracks the mouse, Shift not held at
  the press, goes to it as it is: the first button pressed (left, right or middle; a touchpad tap
  is left) with modifiers, motion while it is held and its release, bypassing the gestures (it
  clears a selection and takes focus without opening the IME). Without tracking, or with Shift
  held (always: the C API does not expose a program's XTSHIFTESCAPE, so this is Ghostty's
  `mouse-shift-capture = never`, not its default), it selects as in a desktop terminal (below). A
  touchpad's two-finger swipe or pinch (classified from Android 14 on) takes the finger gestures
  instead; earlier, and for other multi-finger swipes, delivered as mouse touches it would select.
  Hover (no button) is sent as motion while the program tracks the mouse. Which of these the
  program gets is the encoder's choice by its mode (1000 none of the motion, 1002 motion with a
  button held, 1003 all), and vt.c skips motion within the cell of the last event it encoded,
  press or release included (except in SGR-Pixels format).
- Selecting with a mouse (`pointer`, as Ghostty does on Linux; the first button pressed owns the
  rest of its stream, and every press takes the focus):
  - The left button (a touchpad's tap) goes to libghostty-vt's selection gesture with its press
    timed (`VtNative.mousePress`, `mouseDrag`, `mouseRelease`), so libghostty-vt counts the
    clicks: a press within the double-tap timeout of the last press and a cell's width of the
    series' first is the next click, up to three. A first click clears the selection, and dragging
    from it selects by cells, a cell counting once the drag passes its point 60% of the way across
    (libghostty-vt's threshold), a rectangle while Ctrl (or Meta) and Alt are held (checked at
    each move); a second click selects the word and a third the line (with Ctrl or Meta, the
    command's output), each dragging on by its unit; a second or third on empty cells leaves the
    selection as it was. Held past the grid's edges, the drag scrolls as below.
  - Shift+press, with a selection and later than the double-tap timeout after the last left press,
    extends the selection from that press by its unit instead (Ghostty's), when the gesture still
    has it; otherwise it is a plain press.
  - A release keeps the click count for the next press; only a first click that did not drag (it
    stayed in its cell and selected nothing) acts: with Ctrl or Meta on a link it opens the link,
    otherwise it moves the shell's cursor there at the prompt and brings the keyboard up, as a tap
    does. A press that stopped a fling still acts.
  - The right button, as Ghostty's before its context menu: a selection holding the cell stays,
    otherwise the word there is selected (on a written space the run of spaces; on empty cells the
    selection stays as it was), and the menu comes up pinned at the click once the frame has the
    selection, with Open link for a link under it (no Ctrl needed) and Select output in a
    command's output.
  - The middle button only takes the focus.
  - No menu comes up after the left button, and a selection made or right-clicked with a mouse
    shows no handles (`pointerSelection`) until the next press that reaches the touch path (a
    finger, a stylus, a touchpad's swipe or pinch), which itself cannot grab one; Ctrl+Shift+C or
    the right-click menu copies it.
  - Unlike Ghostty, a double click on a URL or a right-click on a link selects the word, not the
    link, and Ctrl or Meta count with other modifiers held too.
- The mouse pointer over the terminal (`updatePointer`) is the shape the program asked for with
  OSC 22 (an I-beam by default, as in Ghostty; libghostty-vt's names are CSS's cursors), shown as
  the closest of Android's system pointers (progress as waiting, move as all-scroll, not-allowed
  as no-drop, edge resizes by their axis), or a hand over a link while Ctrl or Meta is held and
  the program does not track the mouse (a Ctrl+click opens it then), looked up again when a
  hovering mouse reaches another cell or a hardware Ctrl or Meta that reaches the view is pressed
  or let go (the extra keys' CTRL counts for neither). It is set on the view, so a program
  changing it while the mouse rests shows at once; Ghostty's I-beam and crosshair for its Shift
  override and Ctrl+Alt rectangle have no counterpart.
- The two handles (shown for a selection not made with a mouse; start below the first cell, end
  below the last, when in the viewport; a rectangle's top left and bottom right corners) drag the
  selection's ends; the other end is the anchor, kept as tracked grid references so output does
  not move it, a handle drag extends by cells, and a rectangle stays one with the anchor and the
  finger's cell at opposite corners. A handle that would stick out of the view at the left edge
  (start) or right edge (end) is drawn with the other handle's drawable, on the other side of the
  same point, so both stay on the screen, and the handles' areas (with an 8 dp margin) are
  excluded from the system's back gesture while they are shown, so a drag from the edge moves the
  handle. The finger keeps its offset from the dragged cell; held above or below the grid (a
  handle's drag or a gesture's: a long press's, a double or triple tap's, a mouse's left-button
  drag), the viewport scrolls one row every 50 ms (the grid on a whole row) and the selection
  follows (a gesture's to the edge row's word or line, by the view's own timer, not
  libghostty-vt's autoscroll tick).
- A floating action mode (`TYPE_FLOATING`) appears once the next frame is drawn after a selection
  drag, a long press's word or a double or triple tap's press ends (the finger lifted), Select
  all, or a right-click (pinned at the click), and at once, pinned at the press point, after a
  long press on blanks or a mouse-mode long press that selected nothing; never after a mouse's
  left button. It offers Open link (when the long press that began the selection, or the
  right-click, was on a link, also in mouse mode), Copy (with a selection), Paste (with a
  clipboard), Select output (when that long press or right-click was in a command's output),
  Select all (scrollback included), and with a selection Rectangle, or Lines for a rectangle, with
  the system's own labels but Open link's, Select output's and the last two, placed over the
  selected rows and moved with them on every draw; a frame without a selection closes it. Open
  link ends the selection and opens the link. Select output selects the whole output and the menu
  comes back for it, without the item, which a double or triple tap, Select all, clearing, a
  mouse-mode drag or a mouse press to select also drop; when the output has left the scrollback
  the menu comes back without the item and the selection as it was. Rectangle makes the
  selection's first and last cells opposite corners of a rectangle; Lines makes it linear again from
  the rectangle's top left to its bottom right corner; the menu comes back with the other item.
  Copy takes the selection as plain text with soft wraps joined (not in a rectangle, whose rows
  are lines of their own) and trailing blanks trimmed (as Ghostty copies), puts it on the
  clipboard and ends the selection.
- Pinch zoom changes the font by 1 dp beyond a 0.9–1.1 scale band, within 6–32 dp, which regrids
  and resizes the terminal and then the console (`SIGWINCH`) via `android/vtview`'s `zoom`; the
  activity saves the new size.

### Scrolling and flings

- A vertical drag, or a mouse wheel or touchpad scroll (3 rows per scroll event, whatever its
  size), scrolls: wheel events when the program tracks the mouse and arrow keys on the alternate
  screen with alternate scroll (1007, on by default), by whole rows; else the viewport, which a
  drag moves by pixels (`scrollPixels`): within a row by drawing the grid up to a row higher
  (`scrollPx`, with the overscan row after the viewport showing below), across rows by scrolling
  libghostty-vt's viewport, as far as either end (by the last frame's scroll total and length,
  with the rows moved since), where the grid rests on a whole row. A wheel moves it by whole rows
  and keeps the pixels.
- With mouse tracking a mouse's or touchpad's sideways scroll goes to the program as wheel buttons
  6 (left) and 7 (right), one per scroll event, as Ghostty sends them; without it nothing scrolls
  sideways.
- A fling goes on scrolling that way, slowing down as a ScrollView does (Android's fling physics,
  in pixels for the viewport and taken as whole rows otherwise): the viewport until it cannot
  move, wheel events and arrow keys for at most a screen of rows. It stops when the way to scroll
  changes (mouse tracking, the alternate screen, alternate scroll), when the tab has no terminal,
  at a touch, at any other input to the program (not scrolling's own), when the window loses focus
  and when another tab is shown.
- The viewport comes to rest on the nearest whole row (`settle`, 150 ms through the same scroller)
  when a fling stops between rows, when a touch ends there without a fling (a touch that
  interrupts settling settles again when it lifts), and when the window loses focus (unless the
  program asked for focus events, whose report, like any input, returns the viewport to the
  bottom); prompt jumps, search steps, a selection's keyboard adjustment, its autoscroll and input
  returning to the bottom put the grid on a whole row at once, and so do a regrid, attaching a tab
  and a frame without the overscan row or with scrolling going another way. Touches are taken to
  cells with the shift (`cellY`; a touch on the part of the overscan row shown counts as the last
  row), and the handles, the menu's place and a drag's offset subtract it.
- The viewport scrolling (a drag, wheel, fling, a selection's autoscroll, input returning it to
  the bottom) shows the theme's scroll bar at the right edge, faded out after a moment as a
  ScrollView's; output alone does not show it, and with no scrollback (the alternate screen) it is
  never drawn.

### Links and prompt taps

- A link is a cell's OSC 8 hyperlink, else an `http://` or `https://` URL written in the text
  (`VtNative.link`): vt.c joins the cell's soft-wrapped line (up to 64 rows above and below),
  takes the run's first scheme at or before the cell and runs on over ASCII URL characters
  (letters, digits and RFC 3986 punctuation but the single quote) while brackets balance, then drops
  a trailing `.,;:!?`; any other character, CJK included, ends it. Only `http`, `https`, `mailto`
  and `file` links open (an OSC 8 link can name any scheme, other apps' deep links among them);
  the view hands them to the activity (`Host.onLink`), which opens them (`android/terminal`).
- Output (`VtNative.outputAt`, `selectOutput`): a cell is in a command's output when
  libghostty-vt can derive an output selection from it (the cell is output, after a prompt, or
  above the first prompt); vt.c then tracks the cell, and selecting it later takes the whole
  output as it is then (a command still running may have added to it), trailing blanks left out,
  anchored by cells (no drag of the view uses that anchor: a handle anchors anew).
- Taps on the input (`VtNative.promptClick`), as Ghostty's cursor-click-to-move: a prompt start
  (OSC 133;A) on the primary screen that declares how the shell moves its cursor is noted by vt.c
  from the OSC string (the C API does not expose the value libghostty-vt keeps) and holds until
  another declares a way or a full reset: Kitty's `click_events=1` or `2` (fish's) first, else
  `cl=` (`line`, or `m`, `v` and `w`, which Ghostty treats as line too; the profile sends
  `cl=line` from bash, ash and zsh); an option with a value it does not know is ignored like a
  missing one, so the way the last prompt declared stays, and only OSC strings of at most 64
  bytes, not cancelled, are read. A tap without mouse tracking that is not on a link, or a mouse's
  left click (without tracking, or with Shift) that did not drag and is no Ctrl+click on a link,
  with the cursor at the prompt and the tapped row not above the prompt's first one (found going
  up from the cursor, at most 64 rows) moves the cursor there: with `cl`, left or right arrows (in
  the cursor key mode's form), one for each input cell between the cursor and the tapped cell over
  the soft-wrapped rows of the cursor's line and, for a shell whose line feeds are read (busybox
  ash, `android/vtcore`), the rows it broke the line into itself: continuation rows that do not
  start with a secondary prompt (rows after it must continue the prompt), a tap on the prompt
  going to the input's start and one past it or below to its end (one more arrow when the cursor
  is on input); unlike Ghostty, which counts both halves, a wide character takes one arrow and its
  second half stands for it; with `click_events`, a left button press in SGR without a release,
  its row counted from the screen's top (`1`) or from the prompt's first row (`2`). The bytes go
  out as typing does and the keyboard comes up as for any tap, or such a click; a tap that is no
  prompt's sends nothing.

## Dependencies (inbound / outbound)

### Inbound

- `android/vtview`: `onDraw` calls `drawHandles`; `apply` updates selection/scroll/pointer state
  and calls `updatePointer`; input/attach call `clearSelection`; key events call `hoverModifiers`
  and `VtNative.selectAdjust`; window focus loss calls `settle`.
- `android/vtrender`: frame capture uses the `Selection` section's `viewport_ref` and
  `screen_point` helpers for viewport coordinates and search highlights.

### Outbound

- `android/vtview`: `send`/`input` (mouse/scroll/prompt-click bytes), `copySelection`/
  `pasteClipboard`, `zoom`, `clearResizePreview`, scroll-bar range/offset/extent hooks, and
  frame-header fields (`altScreen`, `mouseTracking`, `altScroll`, `scrollTotal`/`scrollOffset`/
  `scrollLen`, `atBottom`, selection bounds).
- `android/vtcore`: `VtNative` calls for `mouse`, `scroll`, `gesturePress`/`Drag`/`End`,
  `mousePress`/`Drag`/`Release`, `selectContext`/`Grab`/`To`/`Adjust`/`Rectangle`/`All`/`Output`/
  `Clear`, `outputAt`, `copy`, `link`, `promptClick`, which hold the tab lock.
- `android/terminal`: `Host.onLink`, `Host.onZoom` (via `zoom`), and `MainActivity`'s pinned night
  configuration for the system `TYPE_FLOATING` menu.
- libghostty-vt through `vt.c`: mouse encoder, selection gestures, word selection and containment,
  output derivation and keyboard adjustment, plain-text copy formatting.
- Android `GestureDetector`, `ScaleGestureDetector`, `OverScroller`, `ActionMode`, system pointers
  and haptics.

## Invariants and gotchas

- The inspected S23 Android 16 / One UI 8.5 ordinary floating toolbar loads its background from
  `materialColorSurfaceContainerHighest` and text from `materialColorOnSurface`, both selected by
  configuration night mode, while its ripple follows the theme. A fixed dark theme with a light
  configuration mixed a light surface with a white ripple. `MainActivity` (`android/terminal`)
  pins its night configuration before creating the window; retain the system `TYPE_FLOATING` menu.
- libghostty-vt's mouse encoder deduplicates motion only when asked (off by default) and forgets
  its last cell whenever `set_from_terminal` or the size option is set, which `appine_vt_mouse`
  does for every event; so vt.c keeps the last cell itself, updated only when an event was
  encoded.
- `GestureDetector` with a double-tap listener (any `SimpleOnGestureListener`) gives the second
  tap of a double tap to that listener: `onSingleTapUp` never sees it and a drag starting there
  does not scroll. `VtView` therefore uses a plain `OnGestureListener`, and takes the press of a
  double or triple tap that selected before the detector (or the pinch detector) sees any of that
  touch: the view then counts the tap itself when the finger lifts without dragging, and a quick
  tap followed by a drag selects rather than scrolls.
- A fling runs in `computeScroll`, before each draw takes its frame, so the viewport's ends are
  those of the frame before, kept up by `scrollPixels` with the rows it moved: `VtNative.scroll`
  is relative, and output that changes the scroll total meanwhile can make the two disagree until
  the next frame. A viewport fling ends at the first step that cannot move.
- `scrollPx` is nonzero only while scrolling moves the viewport and there is a row after it; a
  frame without the overscan row puts it back to 0, which keeps the view from showing the mirror's
  stale extra row. Mouse positions sent to programs ignore it, which is safe because mouse
  tracking (another way to scroll) puts it to 0.
- A pointer set on the view while the mouse rests is resolved again by the system with an event
  whose source is no mouse, and `View.onResolvePointerIcon` returns the view's pointer only for
  mouse events (seen on API 34), which shows the default arrow; `VtView` returns its own pointer
  for such events (a stylus keeps the system's). A pointer set while the view handles a hover
  event shows only at the next one.
- The selection gesture is one per terminal, shared by touch and mouse: a mouse's click count
  survives its releases, but vt.c's own clearing (`appine_vt_select_clear`: the view's
  `clearSelection`, typing, Clear screen, Reset terminal), a finger's word or line press and the
  finger lifting from its drag, a right-click that selects a word, a failed mouse press and
  attaching another tab during a drag reset it; selecting all, a rectangle, an output or a
  handle's grab do not, so a later Shift+press after the timeout replaces those with an extension
  from the last left press. A cell press yields no selection (vt.c clears it on a first click, and
  a cell drag not yet past its threshold leaves none, neither resetting the gesture), and a repeat
  keeps the first click's cell, so a release on another cell counts as a drag.
- Grid references from libghostty-vt are valid only until the terminal changes, so every selection
  call takes fresh ones; the anchor of a handle's drag and the gesture's pressed cell are tracked,
  and the gesture's selections are installed at once. A changed selection makes the next frame a
  full one (the render state redraws everything when the screen's selection changes), as does
  scrolling the viewport.
- The C API's `select_line` defaults to ignoring prompt marks (`semantic_prompt_boundary` off);
  the selection gesture's line is Ghostty's own, with them on, so a triple tap or triple click
  stops at a prompt mark. vt.c no longer calls `select_line`; a direct call would need the option
  set.
- vt.c's tracked cell of an output frees its tracking only after the output's selection is
  installed: untracking may change the page list the references taken from it point into.
- Keep `android/vtrender`'s overscan contract when changing pixel scrolling or selection overlays.

## Confirmed bugs / technical debt

- **libghostty-vt's selection features left unused**: the gesture's click counting for a finger,
  its autoscroll ticks and data (the view scrolls on its own timer), deep presses, behaviour data
  and word-boundary characters.

## Open questions

- Should a mouse wheel or touchpad scrolling the viewport go by pixels and by the event's size
  (high-resolution wheels, touchpads) rather than 3 rows a scroll event?
- Should a mouse's middle button paste the clipboard (Ghostty's `middle-click-action`; Android has
  no primary selection), and should a left-button selection copy on release (Ghostty's
  `copy-on-select`) or bring up the menu?
- Should a double click on a URL, or a right-click on a link, select the whole link, as Ghostty
  does, and should the extra keys' CTRL make Ctrl+click and the hand pointer work?

## To verify

- S23 system-menu colours and press contrast after MainActivity's night override, including
  opening a new menu after an in-place system dark-mode change.
- Link taps with mouse tracking: end-to-end keyboard visibility and browser handoff on device.
- Real fingers, styluses, mice and touchpads (swipe/pinch classification, Android 11–13,
  DeX/ChromeOS/desktop windowing), sideways scrolling and wheel events to mouse-tracking programs,
  selection-drag autoscroll past grid edges, and prompt taps with fish or ash wide characters /
  multi-row commands on real or 16 KB-page devices.
