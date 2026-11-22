# Settings screen (android/settings) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: android/settings"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on android/settings made before it was split from android/setup keep their `android/setup` tags and live in `.agents/decisions/android/setup.md`: D10–D12, D21–D23, D25, D26, D28, D31–D33, D35, D36, D38, D41, and the Settings halves of D1, D3, D9, D14 and D15.

## Active

### D1: The Settings screen has a dedicated module

- **What**: android/settings owns `SettingsActivity.kt` (`SettingsActivity`, `SettingsFragment`, `ChoiceDialog` and `PendingLogSave`), while preference storage stays in `android/service`, rootfs/account queries in `android/setup` and archive export in `android/reports`.
- **Why**: The 728-line Settings UI needed a focused map independent of rootfs import and guest shell integration.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/android/setup.md`.
- **Watch out**: Changes touching service setters, diagnostic export or login-account lists require reading `android/settings` together with `android/service`, `android/reports` or `android/setup`.
- **Source**: e4d7bbe5
