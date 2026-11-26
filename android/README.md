# Appine Android app

The Gradle project for the Android shell (design doc §3 and the `android/*` maps; terminals in the `kernel/tty` map):

- `app/`: the Kotlin app. `TerminalService` is a `specialUse` foreground service that
  owns the guest kernel and the terminal sessions; `MainActivity` shows them with tabs
  and a row of extra keys. The terminal emulator is libghostty-vt from Ghostty, linked into
  `libappine.so` (`hosts/android/src/vt.c`, `vt.rs`), and drawn by `VtView` with the bundled
  JetBrains Mono font. `Rootfs` imports Alpine from the APK assets on first launch
  and can replace it with Debian (downloaded and checked against a pinned sha256 digest).
  During import it selects the fastest package mirror measured by the time local setup finishes,
  falling back to the official mirror if no result is available. From the tab bar's menu,
  `SettingsActivity` lets users switch distributions, reset the rootfs, and choose the login
  account and execution mode (Tier 1 by default; Tier 0 for troubleshooting in both debug
  and release builds).
  On the first launch of a new or upgraded Alpine system, Appine checks for OpenRC.
  If it is missing, Appine installs it offline and boots it before opening a tab. An existing
  installation keeps its configuration. After setup, users can remove OpenRC with `apk del`.
  If setup fails on an upgrade, the terminal opens for repairs and the next start retries.
  Each tab runs `assets/login.sh` as root: it picks the
  login account (the first regular user by default), gives a regular user doas or sudo the
  first time it logs in (the doas package from `scripts/fetch-rootfs` is in the assets),
  installs the bundled bash, procps-ng and bubblewrap packages offline on a new Alpine system,
  and switches to it with `su` (`--session-command` where su is util-linux's, so that the
  shell keeps its controlling terminal and job control). `Native` is the JNI interface to
  `libappine.so`, which is built from `hosts/android` with cargo-ndk.

## Building

Requirements: the Android SDK with NDK 29.0.14206865 and CMake 3.22.1, Python 3, patch, JDK 17 or later,
`rustup target add aarch64-linux-android`, `cargo install cargo-ndk`, Zig 0.17.0 on `PATH`
(or in `ZIG`), the rootfs tarball (`scripts/fetch-rootfs`) and the libghostty-vt source release
with its Zig packages (`scripts/fetch-ghostty`), and the pinned Venus decoder (`scripts/fetch-virglrenderer`). Run the fetch scripts from the repository root. The Zig
build then runs offline. Zig also builds the static Linux browser launcher from
`hosts/android/open-url.c`; its musl libc notice is included in the APK.

Gradle resolves Zig from `zig.path` in `android/local.properties` first, then the `ZIG`
environment variable, then `zig` on `PATH`. A missing or blank local value falls back to
the environment. Both the browser launcher and Rust native build use this setting.
For Android Studio on a Mac with Homebrew, add this to the ignored `local.properties`:

```properties
zig.path=/opt/homebrew/bin/zig
```

```sh
./gradlew installDebug                 # build and install on a connected arm64 device
./gradlew connectedDebugAndroidTest    # instrumentation tests on a device or emulator
```

Both APKs build `libappine.so` for `arm64-v8a`. Debug uses Cargo's `release` profile to keep
the interpreter fast, appends `.debug` to the application ID (`io.github.mthli.appine.debug`),
and uses a lemon yellow launcher icon outline (`#F5DF4D`) to distinguish it from release.
Release uses `android-release` for cross-crate LTO and a smaller library.

The release APK uses R8 and resource shrinking. Gradle's release output is an intermediate
signed with the debug key; GitHub Actions produces the signed APK for distribution.
`app/proguard-rules.pro` preserves JNI methods and the `VtSession.on*` callbacks Rust looks up
by name. Archive `app/build/outputs/mapping/release/mapping.txt` with its APK to decode stack traces.

Run the instrumentation tests on both a 4K-page
and a 16K-page system image. `downloadedDistributionsRun` and
`debianImportsBothSourcesWithTheSelectedMirror` each import the Debian tarball (about 50 MB).
These tests and the browser bridge test that installs tmux/screen require
`-Pandroid.testInstrumentationRunnerArguments.network=true`. An emulator started
with `-http-proxy` sends connections to 127.0.0.1 to the proxy too, which breaks
`downloadsResumeWhereTheyBrokeOff`. Setting the system proxy instead
(`adb shell settings put global http_proxy 10.0.2.2:<port>`) only affects the app's own
HTTP downloads and leaves 127.0.0.1 alone; clear it afterwards with
`adb shell settings put global http_proxy :0`. Deleting the setting instead leaves
`global_http_proxy_host` and `global_http_proxy_port` behind, and the proxy stays in effect
(with an empty exclusion list, so 127.0.0.1 goes to the proxy too) until the next reboot.

## Release APKs in GitHub Actions

The manual `release.yml` workflow builds and lints an exact Appine revision, aligns the APK
for 16 KB pages, and signs it with the established Appine PKCS12 key after Gradle finishes.
Signing passwords stay out of Gradle, and the release build disables its configuration cache.
The ordinary `android.yml` workflow keeps building debug APKs on matching pushes and pull requests.

Select the workflow branch and optionally set `source_sha` to a full lowercase, 40-character
commit SHA available on GitHub. An empty value builds the selected branch's tip. For example,
after the requested commit and workflow are on `master`:

```sh
gh workflow run release.yml --ref master -f source_sha="$(git rev-parse HEAD)"
```

Release signing uses these repository secrets:

| Secret | Value |
| --- | --- |
| `APPINE_RELEASE_KEYSTORE_BASE64` | Base64 of the established PKCS12 keystore |
| `APPINE_RELEASE_STORE_PASSWORD` | Keystore password |
| `APPINE_RELEASE_KEY_ALIAS` | Signing key alias |
| `APPINE_RELEASE_KEY_PASSWORD` | Signing key password |

Keep the established key and credentials outside the checkout, with a private backup.
Supply secrets through private files or stdin rather than plaintext command-line arguments.
The workflow decodes the key into the runner's temporary directory and removes it when finished.

The `appine-release-<full SHA>` artifact contains `appine-1.1.0-<short SHA>-release.apk`,
its SHA-256 checksum, `SOURCE_SHA`, the matching R8 `mapping.txt`, and `verification.json`.
Verification pins Appine's signing certificate and checks the APK manifest, assets, JNI,
shared-storage `Native.start` signature and ELF/ZIP alignment. It does not install the APK
or exercise Android's all-files access grant. The workflow does not publish a GitHub release.

## Open source licenses

The notices under Settings → Open source licenses are checked-in resources in
`app/src/main/assets/notices/`; Gradle does not generate them. `index.json` records each
entry's stable ID, project name, version, short license label and HTML file. The optional
`packageCount` produces the localized Alpine summary, and `kind: "license"` identifies a
standalone license text, hidden from the main list but reachable through component detail
links. Each HTML document links to the shared `style.css`. The reader
supplies `/theme/colors.css` from the current Material theme, opens external web links in
Custom Tabs and needs no network connection to read a notice.

Keep notices in the same change as dependency updates:

- Appine's notice includes the repository's `LICENSE`, copyright, warranty and source link.
- Fuchsia, libghostty-vt and its linked components, and JetBrains Mono retain their original
  notices; `licenses/` keeps the upstream source copies for comparison.
- Rust entries cover the normal dependencies reachable from `appine-android` on
  `aarch64-linux-android`, excluding workspace members, build dependencies and proc-macros.
  Record the chosen MIT license when offered as an alternative, and retain the upstream
  expression and any additional notices in the detail page. Keep separate entries for
  simultaneously linked versions, such as jni-sys 0.3 and 0.4.
- `android.html` lists the resolved Android runtime libraries, including transitive ones;
  check both debug and release runtime classpaths when changing the version catalog.
- `alpine.html` records the bundled rootfs and doas/bash/procps/bubblewrap/OpenRC packages, with versions,
  license expressions and aports commits. Compare with the artifacts Gradle selects in
  `target/rootfs`, and count shared packages only once.
- Preserve license wording, copyright notices and all required component notices when
  editing HTML. Use paragraphs and headings for reflow; do not shrink fixed-width text.
  Keep IDs stable across upgrades, and update the separate source bundles as before
  (`scripts/release-sources`).

`LicenseTest` checks coverage and offline rendering/scroll restoration without starting the
kernel or changing its store. It does not detect every dependency upgrade; reviewing the
resolved dependencies and bundled package metadata remains part of updating the static files.

```sh
./gradlew assembleDebug lintDebug
./gradlew connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=io.github.mthli.appine.LicenseTest
```
