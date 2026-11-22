# Notifications, fault reports and diagnostics (android/reports) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: android/reports"`
>
> Last distilled: 2026-11-22 (HEAD = e0719858)
>
> Decisions on android/reports made before it was split from android/service keep their `android/service` tags and live in `.agents/decisions/android/service.md`: D6, D24, D29, and the notification, report and diagnostic parts of D10, D14, D15, D18, D19, D21, D23, D28 and D32.

## Active

### D1: Non-ongoing notifications, fault reports and diagnostics have a dedicated module

- **What**: android/reports owns `Notifications.kt` and `Diagnostics.kt` (`Notifications`, `ReportReceiver`, `Diagnostics`, `DiagnosticFiles` and `DiagnosticProvider`), while ongoing notification id 1 and event-routing decisions stay in `android/service`.
- **Why**: Non-ongoing notifications, copyable fault reports and service-independent diagnostic retention/export needed a focused module map.
- **Tradeoffs**: Pre-split decisions remain in `.agents/decisions/android/service.md`, and notification-routing decisions remain in `android/service`.
- **Watch out**: Adding notification channels, notification IDs or privacy redaction rules requires checking both `android/service` and `android/reports`.
- **Source**: e4d7bbe5
