# android/tabbar Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/tabbar.md` for the paired decision history (pre-split decisions D4, D18–D24, D27, the drawing half of D39, D51 and D54 stay in `.agents/decisions/android/terminal.md`).
>
> Verified: 2026-11-15 (split out of the android/terminal full mapping of 2026-11-14; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's labelled import stop action was left out with the retired import button; the transparent new-session icon and terminal-background contrast updates are unchanged)

## Responsibilities

`android/tabbar` owns tab-bar/list presentation, number animations and progress/status drawing.
Root: `TabBarView.kt`, `TabListView.kt`, `TabNumber.kt`, `TabMarks.kt` and `ProgressLine.kt` in
`android/app/src/main/java/io/github/mthli/appine/`.

All MainActivity target adapters, session selection/closing, menu policy, focus/Back coordination
and layout placement remain `android/terminal`; session state is `android/vt`. Shared indicator
helpers in `ExtraKeysView` belong to `android/keys`, and `Ui.kt`, strings/themes to `android/terminal`.

## Key types

- `TabBarView` — the tab bar: optional session-list icon at the start, scrolling numbered tabs,
  then close, new-session and overflow icons over the end. `render` shows the supplied sessions
  and current selection; `Target` receives `show`, `closeCurrent`, `newTab`, `menu` and `listTabs`.
  `setListOpen` highlights the list button; `setListVisible` changes its visibility and the row's start margin;
  it draws the other tabs' progress and status marks and redraws them
  on `refreshStatus`; `Tab` (one per session: its number in the row, which slides, rolls to a new
  number and fades out when closed); `TabNumber` (in its own file: the number, a `TextView`
  drawing its digits itself so they can roll).
- `TabMarks` — shared progress/status drawing and accessible status text for the bar and list;
  draws over a direct child number, following its translation and opacity, and reports whether
  a sweep needs another frame. Each container owns the redraw scheduling.
- `TabListView` — a full-width overlay above the notification banner, terminal and extra keys,
  flush below the bar. Its RecyclerView shows session numbers, single-line ellipsized titles and independent close buttons;
  immutable row snapshots (including progress and status) and stable session IDs keep updates
  and callbacks tied to sessions. `refreshStatus` diffs new reports only while open.
  `open` renders and reveals the current row without moving input focus; `render` updates an open
  list; `close` hides it and clears retained rows. The activity coordinates Back and accessibility.
- `ProgressLine` — a 1 dp view over the top of the terminal showing the current tab's progress
  report; `Colors` (primary, error, muted by progress state); its companion draws progress into any
  rectangle (`draw`, a fill or a sweep) and gives a report's fraction (`fractionOf`).

## Public entry points

- `TabBarView.render`, `refreshStatus`, `setListOpen`, `setListVisible`, `setTerminalBackgroundColor`.
- `TabListView.open`, `render`, `refreshStatus`, `close`; `ProgressLine.show`.
- `TabBarView.Target` and `TabListView.Target` send user actions to MainActivity.

## Data flow / lifecycle

### The tab bar

- One 48 dp row in any window, with square 48 dp tab/control bounds. The optional session-list icon,
  shown by default and controlled by Settings' Terminal switch, occupies the first 48 dp;
  scrolling tabs start to its right. Close (hidden without a current tab), new-session and
  overflow controls reserve 144 dp at the end. New-session shows only a plus icon with a
  transparent idle background and opens a session while the kernel runs, in the current tab's
  directory: its console's foreground group's, read from the kernel on the main thread as a spawn is; the home directory
  without a current tab or once its shell ended. The overflow menu offers:
  "Find", disabled with no current tab, "Clear screen", disabled without a current tab whose
  terminal exists or while it shows the alternate screen, "Reset terminal", disabled without such a
  tab, "Close other tabs", disabled when there is no other, "Close all tabs", disabled with no tabs,
  "Keep screen on" (a checkbox), and Settings; Clear screen and Reset terminal are android/vt's;
  Find is enabled for a current tab whose terminal does not exist yet, where searching does
  nothing. The tabs pass under the buttons, which hide them, and end padding as wide as the
  buttons lets the last tab scroll out from under them. While more tabs lie beyond, the row
  fades out over 32 dp ending 12 dp inside the close control, at its icon padding
  (the scroll view's right fading edge; the left edge does not fade).
- The bar and fixed group's retained drawable follow the displayed terminal background, initially
  black. `setTerminalBackgroundColor` updates inactive labels and ordinary icon tints, including
  new-session, for contrast.
  Ui.kt's `terminalControlColor` retains on-surface-variant at 4.5:1 or chooses black/white;
  selected text/indicators use on-primary-container.
  `terminalControlBackground` supplies inset rounded containers and ripples; selected tabs and
  the open-list button have filled primary containers. Extra keys share the filled-control palette;
  progress/status marks retain their theme-role mapping and animation logic.
- A tab shows its number (from 1, by position): the current one in a rounded filled primary
  container above the indicator, the others muted, an ended one faded (38% opacity, its indicator too). The current
  tab is scrolled into view after each change, clear of the fade, or to the row's end when less
  than a fade's width of tabs would be left beyond the padding; scrolled away from it, the row
  brings it back the same way 3 s after coming to rest: a finger on the row holds that off, and
  each later move without one (a fling, TalkBack's scrolling) starts the wait again. With gesture
  navigation, the bar but for its buttons is excluded from the system's back gesture.
- The indicator is a rounded bar 16 dp wide and 1 dp high in the selected colour, centred under the
  label with its top 4 dp below the baseline, in whole pixels rounded down; the row draws it over
  its tabs. Number labels are 16 dp and list titles 14 dp, so the system font scale leaves
  them as they are (dialogs, menus and toasts follow it). Fixed controls use 24 dp vector icons.
- The other tabs, while their shell runs, show what their programs report (`VtSession.progress`
  and `status`; the current tab has the terminal's progress line instead): progress in the
  indicator's place, its track the progress colour at 30% opacity, filled from the left to the
  percentage or with a quarter of it sweeping across and back, in the progress line's colours (a
  progress report; else a working status, or a blocked one with a percentage, in the primary
  colour); and a dot of 1.5 dp radius 2 dp right of the number's ink, centred on the top of its
  digits, for a status: blocked in the primary colour, failed in the error colour, done in the muted
  one. The row draws them over its tabs, following a sliding tab and fading with its number, and
  redraws every frame while a sweep is drawn.
- Closing tabs is animated (150–300 ms a step, under the system's animator duration scale): a
  closed tab shrinks and fades out where it was; the tabs after it slide into the places left,
  still showing their old numbers, then roll to the new ones (300 ms, like SwiftUI's numeric
  text): each digit that changes moves down and out, fading and blurring, as the new one comes in
  from above and sharpens (from below for a higher number); digits that stay the same stay still,
  and a number of another length rolls whole. The indicator keeps to the current tab's place on
  screen; a row at its end scrolls back as it shortens, the tabs before slide right instead, and
  the indicator slides on to the new current tab. Showing another tab (a tap, Ctrl+Tab, a new tab)
  slides the indicator there the same way (200 ms) from where it is drawn; only the row's first
  layout puts it in place at once. The numbers' colours change at once, and so do TalkBack's
  descriptions.
- Clicking a tab or a fixed bar button requests `KEYBOARD_TAP` feedback before its action,
  matching the extra keys' tap haptic. Feedback stays in the view's click listener, so Ctrl+Tab
  and programmatic tab changes do not request it.
- Tapping a tab shows it; a long press shows its title in a native Android tooltip: the program's
  title (`sh` when it set none), with "(ended)" once the shell ended. `Tab.update` refreshes the
  tooltip text when sessions or titles change; title display stays in the view without an activity callback.
  TalkBack reads "Tab N: title", followed for a running program that reported something by what
  it reported in parentheses (`VtSession.describe`'s words: "Waiting for your approval", "Waiting
  for your answer", "Waiting for credentials", "Waiting for you", "Done", "Failed", "Working", or
  "Paused" for a paused progress, with the percentage when there is one; an idle status alone says
  nothing; for the
  current tab too, though only the other tabs draw marks), and fixed controls by their localized
  names (overflow as "More options").
- The four fixed controls use vector icons and native Android tooltips matching their localized
  accessibility descriptions. Long presses show the name without running the click action,
  as for numbered tabs' title tooltips.
- The list button reserves 48 dp at the start only while shown. Hiding it uses `GONE` and
  removes the row's start margin; changing visibility
  reveals the current tab after layout, and layout updates gesture exclusion to the new row bounds.
  `MainActivity` reads `Settings.showTabList` on start and on live settings changes, closing an open
  list before hiding its button, including while both activities are visible in split screen.
- The tab list overlays the notification banner, terminal and extra keys in the same activity
  window without regridding it. A surface-container panel sits flush below the toolbar, with
  20 dp bottom corners, 8 dp side padding/elevation and a dim scrim over the remaining content.
  Rows are 56 dp with 48 dp number/close widths, 16 dp numbers, 14 dp titles and vector close
  controls. The current selectable row and number have filled primary containers and paired text;
  ended titles are faded and marked. At most ten rows fit (`ROW_DP`, `MAX_VISIBLE_ROWS`), further
  limited by content height below the toolbar, including visible permission banners.
  The list scrolls and opens with the current tab visible. Its themed vertical scrollbar appears
  while scrolling and fades afterward; no thumb is drawn when all rows fit. Titles use the bar’s `sh` fallback.
  Every running row, including the current tab, draws the shared progress bar and status dot
  around its number; ended rows show no marks.
  `MainActivity.onTabStatus` refreshes the open list's report snapshots and accessible descriptions
  alongside the bar and progress line, without resetting scroll. Only rows drawing a sweep request
  another frame; closing the list detaches and clears its rows.
- Tapping a list title selects the session and closes the list. Its close button uses the existing
  busy confirmation and leaves the list open, including when the current tab’s successor is shown.
  Both click listeners request `KEYBOARD_TAP` feedback before their action, as the bar does.
  Session/title changes update visible rows and positional numbers without resetting scroll.
  RecyclerView's `DefaultItemAnimator` retains its default settings. Content changes carry a
  non-empty payload so it reuses the row without cross-fading; additions, removals and moves
  retain their animations. Partial binding compares the last bound snapshot with the latest entry,
  skipping unchanged labels and styling while refreshing marks and accessible descriptions.
  Empty payloads perform a full bind, including for recycled rows whose payloads were dropped.
  The list button toggles it; a tap outside its rows over the terminal or extra keys dismisses
  and consumes that tap. Back, Escape,
  explicit tab switching, search, the other bar actions, extra-key input, pause and restart dismiss
  it too. Touch opening and scrolling preserve terminal input focus and its IME connection;
  the notification banner, terminal and extra keys are hidden from accessibility while the list
  is open. Closing restores terminal focus only if a list control had it; close confirmations
  return focus to the terminal.
  It lives under the activity’s privacy shield and secure-window policy, rather than in a separate popup.

### The progress line

- The current tab's progress report is drawn by `ProgressLine`, as high as the tab bar's
  indicator (`LINE_DP`, 1 dp and at least a pixel; Ghostty's is 2 points) over the top of the terminal's first
  row, otherwise as Ghostty draws it: filled from the left to the percentage in the primary
  colour, the error colour for an error, the muted colour while paused (all of it for a pause
  without a percentage); without a percentage, or indeterminate, a quarter of its width sweeps
  across and back (1.2 s each way, ease-in-out, timed by the clock) over a track at 30% opacity,
  redrawn every frame. It fades in and out in 150 ms and slides to a new percentage in 200 ms;
  showing another tab puts that tab's progress there at once (a tab without one still lets the
  old one fade out). It takes no touches and is hidden from accessibility.

## Dependencies (inbound / outbound)

### Inbound

- `android/terminal` constructs views after dynamic colours, renders session lists, updates status
  and sets visibility. It owns the focus/Back/accessibility policy around the list.

### Outbound

- Target callbacks reach `android/terminal` for session, list and menu actions.
- `android/vt` supplies session identity, title, progress/status and accessible descriptions.
- `android/keys` provides indicator geometry/paint helpers and fade size; `android/terminal`
  provides dp/theme helpers and shared resources. `TabListView` uses RecyclerView 1.2.1.

## Invariants and gotchas

- The end-control group is clickable and opaque except where the fade reaches into Close.
  A hidden (`INVISIBLE`) close control takes no touches; the group prevents a tap reaching a
  tab underneath. Its surface is an `InsetDrawable`, whose inset also sets padding, so the group
  clears that padding, as the extra keys' fixed group does. TalkBack reads each button alone.
- The row brings the current tab into view after a change with a plain post of its own, not the
  delayed return's `Runnable`: the scroll that laying out a shorter row makes restarts the return's
  wait, which would remove that post and leave the tab out of view for 3 s.
- The tab row keeps its tabs across changes and relies on sessions being added only at the end.
  It animates a change from the on-screen places taken at the first change before the next
  layout (closing the current tab renders the row twice), in a pre-draw listener once laid out.
  Closed tabs are drawn in the row's overlay, past its end once it shortens, so its scroll view
  does not clip its children; a roll under way goes on there. The indicator goes by the label's
  layout place, not its translation (the row's own slide comes as `drawIndicator`'s `dx`), and
  takes the label's opacity, so a number rolls inside the label, which keeps its opacity and place.
- `TabNumber` draws its digits one by one, centred between its paddings, rolling or not, never
  through `TextView`'s layout, whose centring rounds differently: a digit that stays would shift
  by a fraction of a pixel as a roll starts or ends. The blur is a `BlurMaskFilter` on the
  `TextView`'s own paint, made in the roll's update listener (`onDraw` must not allocate) and
  cleared after each draw.
- Fixed controls use vector drawables; numbered tabs retain their custom rolling-number rendering.
- The programmatically built tab list must assign `verticalScrollbarThumbDrawable` from the
  theme, as the terminal view does; enabling the scrollbar alone does not initialize its drawable.
- The tab row and the extra keys' grid draw into their end padding (`clipToPadding` off).
  `HorizontalScrollView` leaves the padding out of its scroll range and fade strength, and `View`
  draws the fading edge at the padding; a right padding offset (`isPaddingOffsetRequired`,
  `getRightPaddingOffset`) carries the edge into `×` or the last column without changing either.
  `canScrollHorizontally` counts the end padding as shown (from 315 dp on the keys would find
  nothing to scroll), so the extra keys compare the grid's width with the room between the
  paddings. The bar's 12 dp fade inset aligns with its vector-icon padding; the extra keys'
  6 dp inset fits the blank before the 12 dp SHIFT label in Roboto. Another label size or font
  can put the keys' fade over their text.
- The indicators are drawn by the containers (the tab row, each page's grid, the fixed column) in
  `dispatchDraw`, over their labels, so a change of state must invalidate the container, not the
  label: `refresh` invalidates the shown grid and the fixed column (turning pages refreshes the
  newly attached grid), and `TabBarView.render` the tab
  row. The label's place is the sum of `left` and `top` up to the container:
  `offsetDescendantRectToMyCoords` subtracts each view's scroll, and a single-line `TextView` (the
  extra keys' labels) scrolls far sideways to centre its text, which also draws a foreground
  drawable it is given off the label.
- Shared indicator changes must be checked against `android/keys`; containers own invalidation.
- Session callbacks carry identity, never an index; MainActivity validates existence and privacy
  before applying actions. These adapters remain `android/terminal`'s responsibility.

## Open questions

- Should a background tab's progress take another colour than the primary one?

## To verify

- New-session's transparent idle background, press ripple and contrast after dark/light terminal
  background changes still need device verification.

- The 48 dp bar height and square controls passed source/layout review, CI debug/release
  assembly/lint and signed-APK verification for source
  `daf981e18859524310cd0f59632bc83ec30a3a0c`
  ([Release](https://github.com/giturass/appine/actions/runs/44607898415),
  [Android](https://github.com/giturass/appine/actions/runs/44607893291)).
  Runtime selection, touch targets, scrolling/focus, ended-tab fading,
  wallpaper palettes and TalkBack need fresh device verification. Earlier build/device checks
  below used the prior control geometry; progress/status colour-role mappings and animation
  logic are unchanged.

- Fixed-button and numbered-tab tooltips pass debug assembly and lint. Device checks remain for
  long-title wrapping and edge placement, long-press release without switching tabs or clicking,
  and coexistence with the keyboard, tab list and privacy transitions.

- Notification-banner coverage passed API 34 visual and touch checks with the banner visible
  and absent: the list starts directly below the bar, covered-banner taps select a row without
  requesting permission, and dismissal restores the banner. The covered banner is excluded
  from important accessibility nodes; TalkBack speech remains unverified. Debug assembly and lint passed.

- After moving the list above the extra keys, debug assembly and lint passed, and the three
  existing TabListTest cases passed on API 34 and S23 API 36. API 34 checks confirmed rows cover
  and receive taps over the keys in a short viewport, outside taps on the keys only dismiss,
  and the terminal input connection survives opening the list and hiding the IME. TalkBack
  traversal and frame-by-frame IME animation clipping remain unverified.

- The tab-list visibility switch, saved choice across launches, reclaimed row space and live
  split-screen dismissal still need device checks; debug assembly and lint cover compilation/resources.

- Tab-list item animations and payload binding compile and pass lint. Device checks remain for
  content updates, removal and movement,
  especially bottom-row removal while the short list's viewport shrinks, rapid closes and dismissal
  during an animation.

- Tab-list identity after removal, the bounded 50-tab layout and preserving editor focus passed
  three API 34 instrumentation cases; the focus case failed against the former requestFocus path. API 34 UI checks covered flush placement with the IME, live titles, busy/current and idle/
  background closes, switching, Back, Escape and outside dismissal. Opening/dismissing with the IME
  visible or hidden retains the same terminal input connection and visibility. Physical touch targets, TalkBack
  traversal and vendor glyph rendering remain unverified. A 14-tab API 34 check reproduced the
  missing scrollbar before assigning its theme drawable, then confirmed it appears during scrolling
  and fades afterward; debug assembly and lint passed.
- Shared bar/list marks pass debug assembly and lint. API 34 checks covered live progress changes
  and clearing while the list stayed open, the current row's indeterminate sweep, and background
  blocked/error/done dots with matching accessible descriptions. TalkBack speech and real-device
  rendering remain unverified.

- Real fingers on the resized targets, rolling-number blur on Android 11/real GPUs, progress marks
  from real programs (cargo, systemd, AI coding CLIs), TalkBack speech and physical haptic feel
  under device touch-feedback settings remain unverified.
