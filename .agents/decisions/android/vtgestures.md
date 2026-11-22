# Terminal gestures, scrolling, selection and links (android/vtgestures) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: android/vtgestures"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on android/vtgestures made before it was split from android/vtview keep their `android/vtview` tags and live in `.agents/decisions/android/vtview.md`: D6, D11 and the gesture/selection/scrolling parts of D1 and D5; earlier `android/terminal` decisions remain in `.agents/decisions/android/terminal.md`: D25, D30, D31, D34, D40 and the gesture/selection/mouse/prompt-tap/scrolling parts of D7, D16, D17, D43, D46 and D48.

## Active

### D1: Touch/mouse gestures, scrolling, selection, links and prompt taps have a dedicated module

- **What**: android/vtgestures owns the `Selection`, `Touch`, `A mouse or touchpad` and `Scrolling` sections of `VtView.kt` plus `appine_vt_mouse` (in `Mouse and focus`) and the `Selection`, `Links` and `Taps on the prompt` sections of `hosts/android/src/vt.c`.
- **Why**: Touch/mouse gestures, pixel scrolling/flings, selection handles/menu, link detection and prompt-tap cursor movement (~980 lines in `VtView.kt` plus ~910 lines in `vt.c`) needed a focused map of their own.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/android/vtview.md` and `.agents/decisions/android/terminal.md`, and `VtView.kt` and `vt.c` are shared with sibling terminal modules.
- **Watch out**: Changes to `scrollPx`/overscan, selection highlights, `Host.onLink`/`onZoom` or `VtNative` selection/mouse calls require reading `android/vtgestures` together with `android/vtview`, `android/vtrender`, `android/vtcore` or `android/terminal`.
- **Source**: 02dfe2ec
