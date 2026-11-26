# android/documents Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/documents.md` for the paired decision history.
>
> Verified: 2026-11-23 (full mapping: 3 research concerns; 9 claims checked by 2 independent verifiers — 8 confirmed and 1 partial, corrected below; bugs and debts recorded)
>
> Maintained: 2026-11-25 (targeted verification only since the full mapping; latest change: translate native browse `AccessDeniedException` to `SecurityException` and other non-`FileNotFoundException` `IOException`s to `IllegalStateException` in `DocumentsProvider` callbacks)

## Responsibilities

`android/documents` is the exported `DocumentsProvider` (`${applicationId}.documents`) that exposes
the guest rootfs store to Android's Storage Access Framework (Files app and pickers) and resolves
terminal `file:` links:

- up to two roots, both gated behind default-off `Settings.fileAccess` (overridden by privacy
  mode): the login account's home (writable) and the whole system (read-only outside home);
- generation-checked guest-path document IDs, `%XX` encoding/decoding matching native `browse`, columns,
  literal-path flags, containment/path queries (`isChildDocument`, `findDocumentPath`), and MIME
  detection with batched UTF-8 content sniffing;
- direct store reads, home-confined writes/creates/deletes/renames/moves and breadth-first search
  via `Native.browse*` under `Rootfs.access.read`, without starting a kernel;
- URI grant revocation (`revokeAccess`, `revokeTree`/`grantedUnder`) and bidirectional change
  notifications (provider -> running kernel inotify, kernel/lifecycle -> Files app);
- resolving terminal OSC 8 `file:` hyperlinks (`Documents.fileLink`).

Root: `android/app/src/main/java/io/github/mthli/appine/Documents.kt` (and its `<provider>` entry
in `android/app/src/main/AndroidManifest.xml`).

Outside the module: the store-side browse implementation, real-path confinement, collision
numbering and ownership (`kernel/store`); the 2 s poll that delivers guest directory changes
(`android/service`); account resolution and the store lock (`android/setup`); JNI wrappers
(`android/native`); `TerminalLinks` UI dispatch (`android/terminal`); privacy mode orchestration
(`android/privacy`). Upstream's terminal file import (`android/file-import`) is retired here.

## Key types

- `Documents : DocumentsProvider` — exported SAF provider (`MANAGE_DOCUMENTS`,
  `grantUriPermissions="true"`, `DOCUMENTS_PROVIDER` intent filter); roots `home` and `system`,
  `SEARCH_LIMIT = 200`, `CACHE_MS = 5_000L`, lazy `closer: Handler` on
  `HandlerThread("documents-close")`, and companion `@Volatile cache: HomeCache?` guarded by
  `cacheGeneration: AtomicLong`.
- `Documents.Home(account, uid, gid, path)` — resolved login account and non-`/` canonical home
  document ID, cached 5 s per `(cacheGeneration, Settings.login)` value (`HomeCache`).
- `Documents.AutoRootsWatcher(machine)` — per-kernel watcher polled on `TerminalService`'s worker
  that samples `/etc/passwd` metadata via `Native.loginRuleInputs` (elements 4..7) and checks the
  auto account's home parent in `changedDirs`, calling `rootsChanged` only when `fileAccess` is on,
  `login` is `"auto"`, and the resolved `Home` actually changes.
- `Documents.FileLink` — sealed interface returned by `fileLink`: `Found(uri, mime)`,
  `Remote(host)`, `Hidden`, `Missing`.

## Public entry points

- Framework overrides: `onCreate`, `queryRoots`, `queryDocument`, `queryChildDocuments`,
  `querySearchDocuments`, `isChildDocument`, `findDocumentPath`, `openDocument`, `createDocument`,
  `deleteDocument`, `renameDocument`, `moveDocument`. (`getDocumentType`, `copyDocument`,
  `removeDocument`, `queryRecentDocuments` and `openDocumentThumbnail` are not overridden;
  `getType` delegates to `queryDocument`.)
- Companion APIs: `authority`, `rootsChanged`, `revokeAccess`, `dirsChanged`, `fileLink`,
  `grantedUnder`, `documentId`, `canonical`, `child`, `parent`, `within`, `fileName`,
  `displayName`, `mimeType`, `guessType`.

## Data flow / lifecycle

### Roots, IDs, flags and MIME detection

- **Access gate**: `Settings.fileAccess` (`!privacyMode && file_access`, default false; old
  `system_documents` ignored) gates every operation. When disabled (or privacy mode is on),
  `queryRoots` returns an empty cursor, `isChildDocument` returns `false`, and all other provider
  methods throw `FileNotFoundException`. Enabling privacy clears `file_access` and revokes grants;
  disabling privacy restores neither.
- **Home resolution and roots**: `home(context)` returns `null` when `!Rootfs.isReady(context)`
  (`meta.db` absent); otherwise checks the 5 s companion cache keyed by `(cacheGeneration,
  Settings.login)` (caching `null` too, invalidated by `rootsChanged`). On miss, under
  `Rootfs.access.read`, it calls `Rootfs.loginAccount` (reading `/etc/passwd` from the store;
  falling back to `root`/`/root`), encodes the raw guest path via `documentId(account.home)`,
  rejects `/` (so the whole system cannot become writable) and non-canonical paths, and confirms
  the target exists and is a directory (`meta.startsWith("d\t")`) via `Native.browseStat` (a
  symlink to `/` still relies on native `top_of` to refuse writes). `queryRoots`
  adds `home` (`"account · distro"`, flags local-only, is-child, search, create) when `home`
  resolves, and always adds `system` (`"/"`, same flags without create) with free space from
  `StorageManager.getAllocatableBytes`, setting the roots notification URI (early empty returns
  when disabled or unready skip `setNotificationUri`).
- **Document IDs**: the canonical absolute guest path optionally prefixed by its decimal generation. The path format is unchanged (`"/"` or leading `"/"`, no trailing `"/"`, no
  empty, `"."` or `".."` segments, no NUL bytes, and exact round-trip equality with
  `documentId(percentDecode(path))`, rejecting encoded `/` or `.` such as `%2F`/`%2E` and
  non-canonical escapes). `documentId` + `utf8Length` mirror native `browse::encode_path`:
  valid UTF-8 passes literally except `%` and ISO control characters (`U+0000..001F`,
  `U+007F..009F`), which along with invalid UTF-8 bytes become uppercase `%XX`. `displayName`
  decodes the last segment via `percentDecode` (invalid UTF-8 -> `U+FFFD`).
- **Columns and flags**: ID, display name, MIME type, size (`null` for dirs), last-modified ms,
  and literal-path flags (`home == null` -> 0; `path == home` -> `FLAG_DIR_SUPPORTS_CREATE` only;
  strict child of `home` -> delete, rename, move, plus create for dirs or write for files;
  elsewhere 0). `queryChildDocuments` ignores `sortOrder` (SQLite `ORDER BY d.name`) and sets the
  child-documents notification URI.
- **MIME detection**: directories are `MIME_TYPE_DIR`; files check `MimeTypeMap` by lowercased
  extension after the last `.` (dotfiles like `.bashrc` usually miss). Unknown-extension files are
  batched in one `Native.browseSniff` call (first 1000 files only; reads up to 4 KB following
  symlinks; no NUL and valid UTF-8 -> `text/plain`, else `application/octet-stream`).
- **Ancestry and paths**: with file access enabled, `isChildDocument` checks both IDs against their
  current store generations, then tests whether the child's path is strictly below the parent's.
  `findDocumentPath` returns the ancestor ID list from
  a supplied `parentDocumentId`, else from `home` if `within(home, child)`, else from `system`
  (`"/"`), throwing `FileNotFoundException` if `child` is not under `top`.

### Operations, locking and grant revocation

- **Locking and errors**: provider callbacks serialize ID validation with namespace mutations. Every `Native.browse*` call runs inside `Rootfs.access.read` (including `providerIds`/`providerId`/`providerPath` generation checks) and opens a
  fresh `Store` connection per JNI call (forcing a running kernel to flush deferred commits, then
  closing immediately). Native `ENOENT`/`ENOTDIR` (`FileNotFoundException`) propagates as
  `FileNotFoundException`; `EACCES` (`AccessDeniedException`) maps to `SecurityException`; other
  `IOException`s (`FileAlreadyExistsException`, `ENOSPC`, `EISDIR`, `EINVAL`, `EIO`, etc.) map to
  `IllegalStateException` (all Binder-parcelable under `DocumentsProvider`'s contract); writes
  outside `home` (or targeting `home` itself when `top = false`) throw
  `UnsupportedOperationException`. During `Rootfs.reset`, `Rootfs.access.write` blocks provider
  calls until the store is removed.
- **`openDocument`**: read-only (`MODE_READ_ONLY`) checks visibility and adopts the host object fd
  from `Native.browseOpen` (follows symlinks without home confinement; regular files only). Any
  non-read-only mode requires a strict child of `home`, passes `truncate` (`MODE_TRUNCATE`) and
  `append` (`MODE_APPEND`) to `Native.browseOpenWrite` (`MODE_CREATE` ignored; real path confined
  strictly inside `home`, unshares held objects, clears guest file capabilities, records `HOST_WRITERS`, replays `Change::Opened`),
  and wraps the adopted fd with `ParcelFileDescriptor.wrap(..., closer)` on `documents-close` so
  closing invokes `Native.browseWritten` (clears `HOST_WRITERS` and replays `Change::Written` ->
  `IN_MODIFY` + `IN_CLOSE_WRITE`). If `wrap` throws `IOException`, the already-detached fd is
  re-adopted by number without close notifications (leaving `HOST_WRITERS` set for that object).
- **Mutations and search**:
  - `createDocument`: allowed under `home` (`top = true`); `fileName` replaces `/` and NUL with `_`,
    maps empty/`.``/..` to `_`, and appends a `MimeTypeMap` extension for non-octet-stream files
    when the name's MIME differs; native `browse::create` creates 0644/0755 owned by `(uid, gid)`
    with collision numbering up to 100 (`name (1).ext`).
  - `deleteDocument`: strict child of `home`; native `browse::remove` confines parent by real path,
    does not follow a final symlink, and removes trees recursively.
  - `renameDocument`: strict child of `home`; `fileName(displayName, "", true)` adds no extension;
    native `browse::rename` never overwrites (`noreplace = true`).
  - `moveDocument`: strict child of `home` into `home` (`top = true`, validating the source-parent ID); native `browse::move_to` refuses overwrites and moving a directory
    into itself.
  - `querySearchDocuments`: breadth-first case-insensitive substring search under `home` or
    `system` (`SEARCH_LIMIT = 200`, native `SEARCH_BUDGET = 50,000` entries; does not descend into
    symlinked dirs; batch-sniffs unknown extensions).
- **Grant revocation**:
  - `revokeAccess(context)` calls `revokeUriPermission` on `content://<authority>` for read+write
    (revoking persisted and transient document/tree grants provider-wide; called by
    `TerminalService.setFileAccess(false)`, `TerminalService.replace` and `Privacy.changeMode(true)`).
    Already-open fds and copied data survive; re-enabling does not restore revoked grants.
  - `deleteDocument`, `renameDocument` (when path changed) and `moveDocument` call `revokeTree`:
    revokes the source ID directly and enumerates `outgoingPersistedUriPermissions` through
    `grantedUnder` (checking `getTreeDocumentId` for tree URIs and `getDocumentId` for document
    URIs) to revoke persisted grants on descendants, because SAF document IDs occupy a single URI
    path segment. The store records the source parent inode and name in the same SQLite transaction
    as removal, rename or move. An ID takes the newest generation traversed during resolution,
    including symlinks and their targets. Reusing the path invalidates old direct and descendant
    URIs, including aliases. Siblings, rolled-back operations and no-op renames keep their IDs.

### Terminal `file:` links

- `Documents.fileLink(context, link)` (called off the main thread by `TerminalLinks` on
  `"appine-link"`):
  1. Checks `link.host`: empty or `"localhost"` (any case) passes; otherwise reads `/etc/hostname`
     from the store under `Rootfs.access.read` and matches case-insensitively, else returns
     `FileLink.Remote(host)` (before checking `fileAccess`).
  2. Decodes `link.encodedPath` (must start with `'/'`) via `percentDecode` -> `documentId`, drops
     empty and `"."` segments, rejects `".."` (`Missing`), and validates via `canonical`.
  3. Queries `contentResolver.getType(uri)` (which runs `queryDocument` + `sniff`, applying
     `fileAccess` and visibility): non-null -> `FileLink.Found(uri, mime)`; null -> falls back to
     direct `Native.browseStat` under `Rootfs.access.read`: exists -> `FileLink.Hidden`, else
     `FileLink.Missing`.

### Bidirectional notifications

- **Provider -> kernel**: mutating `Native.browse*` calls run inside `appine_kernel::browse_changing`,
  which replays collected `Change` records into every live kernel sharing that store path under its
  BKL (`machine::store_changed` -> `inotify::host_change`, updating open-file renames/unshares and
  emitting inotify events).
- **Provider -> Files app**: `createDocument`, `deleteDocument`, `renameDocument` and
  `moveDocument` call `childrenChanged` on affected parent directory URI(s).
- **Kernel/lifecycle -> Files app**: `TerminalService`'s 2 s poll drains `Native.takeChangedDirs`
  (lazy recording, capped at 256 dirs per window) and passes encoded IDs to `Documents.dirsChanged`,
  which issues one batched `contentResolver.notifyChange(uris, null, 0)` call, and polls
  `Documents.AutoRootsWatcher` to call `rootsChanged` when `login` is `"auto"`, `fileAccess` is on,
  and `/etc/passwd` (or the auto account's home parent directory) changes the resolved `Home`.
  `rootsChanged` is also called on kernel start, login change, file-access toggle and privacy-mode
  toggle.

## Dependencies (inbound / outbound)

### Inbound

- Android SAF / Files app (manifest `<provider>`, `MANAGE_DOCUMENTS`, `DOCUMENTS_PROVIDER`).
- `android/service` (`TerminalService`: `dirsChanged`, `rootsChanged`, `revokeAccess`).
- `android/privacy` (`Privacy.changeMode`: `revokeAccess`, `rootsChanged`).
- `android/terminal` (`TerminalLinks`: `fileLink`, `FileLink`, read-only `ACTION_VIEW` grant).
- `android/tests` (`MachineTest`).

### Outbound

- `android/native` -> `kernel/store`: `Native.browse*`, `Native.readFile`.
- `android/setup`: `Rootfs` (`isReady`, `installed`, `store`, `access`, `loginAccount`).
- `android/service`: `Settings` (`fileAccess`, `login`).
- `android/terminal`: shared string/icon resources (`app_name`, `documents_home`,
  `documents_system`, `ic_launcher`).

## Invariants and gotchas

- Read-only `openDocument` follows symlinks without home confinement (accepted limitation: no guest
  permission checks apply), whereas all writes/mutations enforce real-path home confinement in
  native `browse.rs` (Kotlin `flags`/`writable` check literal paths only).
- `Documents.documentId` + `utf8Length` match native `browse::encode_path` and must change
  together; both Kotlin `percentDecode` and native `browse::decode_path` require two ASCII hex
  digits after `%`, and `canonical` enforces `documentId(percentDecode(path)) == path` with no NUL
  bytes so `%2F`, `%2E` and non-canonical escapes are rejected everywhere.
- `fileLink` checks `/etc/hostname` in the store (not the running UTS hostname) before checking
  `fileAccess`, and infers `Hidden` whenever `getType` returns null while direct `browseStat`
  succeeds (including when privacy mode forces `fileAccess` false).
- `ParcelFileDescriptor.wrap` detaches `fd` before creating its socket pair; on `IOException`,
  re-adopting `fd` keeps the write working but skips `browseWritten` (no `IN_MODIFY`/`IN_CLOSE_WRITE`
  and `HOST_WRITERS` stays marked until exit).
- `queryRoots` returns early before `setNotificationUri` when `fileAccess` is off or rootfs is not
  ready.

## Confirmed bugs / technical debt

None recorded.

## Open questions

None.

## To verify

- Persisted and picker-issued grant revocation, `fileLink`, `findDocumentPath`, and empty
  `queryRoots` without `setNotificationUri` across real devices, OEM file managers and Android
  versions (exercised on a Pixel 4a API 34 emulator with Google Files, HTML Viewer and Chrome).
