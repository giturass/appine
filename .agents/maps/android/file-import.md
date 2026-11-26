# android/file-import Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/file-import.md` for the paired decision history (pre-split decisions D4 and D62 stay in `.agents/decisions/android/terminal.md`).
>
> Verified: 2026-11-15 (split out of the android/terminal full mapping of 2026-11-14; the boundary was checked against the source at the split)
>
> Maintained: 2026-11-26 (targeted verification only since the full mapping; latest change: upstream's cancellable, generation-checked import was left out of the upstream merge; the module stays retired)

## Responsibilities

`android/file-import` is retired. The terminal file-selection, copy-worker and result-presentation
implementation has been removed, with no active replacement.

## Key types

None.

## Public entry points

None.

## Data flow / lifecycle

None.

## Dependencies (inbound / outbound)

### Inbound

None.

### Outbound

None.

## Invariants and gotchas

- Upstream still develops this module (`TerminalFiles.kt`, `TerminalFilesTest.kt`, MainActivity's
  picker and result block, `TabBarView.setImportState` and the import strings). Merges from
  upstream drop those parts again; the rest of each upstream change is kept.
- `Native.browseImport` and its JNI and store implementation come from upstream and stay
  compiled (`android/native`, `kernel/store`), but no Kotlin code calls them here.

## Open questions

None.
