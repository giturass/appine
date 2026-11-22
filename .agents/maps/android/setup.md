# android/setup Map

> Static understanding snapshot, not a decision history.
> See `.agents/decisions/android/setup.md` for the paired decision history (it still holds the decisions on the Settings screen made before it was split out into `android/settings`).
>
> Verified: 2026-11-15 (full mapping: 4 research concerns; 12 claims checked by an independent verifier — 8 confirmed and 4 qualified below)
>
> Maintained: 2026-11-22 (targeted verification only since the full mapping; latest change: bash startup-file seeding and extracted settings ownership while preserving offline OpenRC setup)

## Responsibilities

`android/setup` provides the guest system and its account setup:

- the distributions (Alpine from the APK, Debian downloaded), downloading and verifying tarballs,
  importing them into a new store, and writing first-boot configuration, which on Alpine makes
  bash the login shell;
- files refreshed before every kernel start (network interfaces, rootless podman's network, the
  bundled doas package, the profile script and the files of ash's, bash's and zsh's prompt marks for the
  terminal's shell integration), one-time OpenRC setup on Alpine, the osclock script run before boot and the boot log's failed services;
- package mirrors: built-in lists, one speed probe after an import, writing the fastest into
  sources nobody has changed;
- resolving the login account and the per-tab login script (`login.sh`), including the first-login
  admin setup, installing the bundled bash, procps-ng and bubblewrap, and the NOPASSWD rules;
- the store lock shared by the kernel start, store deletion and the Files provider.

Root: `android/app/src/main/java/io/github/mthli/appine/Rootfs.kt`,
`android/app/src/main/assets/login.sh`, `android/app/src/main/assets/install-openrc.sh`, `android/app/src/main/assets/profile.sh`,
`android/app/src/main/assets/ashrc.sh`, `android/app/src/main/assets/bashrc.sh`,
`android/app/src/main/assets/zshrc.sh`, `android/app/src/main/assets/xdg-open.sh`, `android/app/src/main/assets/appine-gpu.sh`, `scripts/fetch-rootfs`.

Outside the module: the settings screen (`android/settings`); when imports, switches, restarts and
logins happen, and the `settings` preferences (`android/service`); the import and
`write_file`/`read_file` implementations (`kernel/store`, `kernel/vfs`); bundling the assets
(`android/build`); what the terminal does with the prompt marks (`android/vtcore`, `android/vtview`,
`android/vtgestures`) and the Kotlin session consuming their state and events (`android/vt`).

## Key types

- `Rootfs` — object: `Distro` (`ALPINE`, `DEBIAN`: label, download, mirrors, probe path),
  `Download` (urls, sha256, size), `Cancelled` and the private `Oversize` (both `IOException`s),
  `Account` (name, uid, gid, home from `/etc/passwd`), `access` (a `ReentrantReadWriteLock`).
  - `ALPINE`: labelled with the branch the APK bundles (`BuildConfig.ALPINE_BRANCH`); no download;
    mirrors are URLs ending in `/alpine` (dl-cdn, Tsinghua, USTC, Aliyun), probed at the branch's
    `main/aarch64/APKINDEX.tar.gz`.
  - `DEBIAN`: "Debian 13"; one pinned GitHub URL (debuerreotype's `debian:trixie`) with fixed
    length and sha256; mirrors are host names (deb.debian.org, Tsinghua, USTC, Aliyun), probed at
    `debian/dists/trixie/InRelease` over https.
  - The first mirror of each list is the official one: the import writes it, and probing falls
    back to it.
- Preferences: file `rootfs`, owned here (`distro`); the `settings` file is `android/service`'s
  `Settings`, displayed and edited through `android/settings`.
- `login.sh` — `sh -c <script> appine-login <login> <cwd>`, run as root on each tab's console, or
  without a console with `--refresh-rules`.
- `profile.sh` — copied verbatim, comments included, into the guest as
  `/etc/profile.d/appine.sh`; `Rootfs` keeps the texts of the versions without prompt marks
  (`OLD_PROFILE`, `UNMARKED_PROFILE`) and the sha256s of the later ones (`REPLACED_PROFILES`) to
  recognise them.
- `ashrc.sh` — copied verbatim into the guest as `/etc/profile.d/appine.ashrc` (not `.sh`, so
  `/etc/profile` does not read it): ash's prompt marks, read through `ENV`.
- `bashrc.sh` — copied verbatim into the guest as `/etc/profile.d/appine.bashrc`: bash's prompt
  marks, read by the profile and, on Alpine, by `/etc/bash/appine.sh` (`BASH_HOOK`, a line sourcing
  it).
- `zshrc.sh` — copied verbatim into the guest as `/etc/profile.d/appine.zshrc`, read by the
  profile only in zsh. Its anonymous function registers the hooks in local zsh emulation,
  preserving the caller's options. `Rootfs.writeProfile(context, store, distro)` writes all three
  companion files and then the profile.
- Guest-side state: `/var/lib/appine/admins` (recorded admins), `/var/lib/appine/doas-installed`,
  `sudo-installed` and `bash-startup-done` (markers), `/etc/doas.d/20-wheel.conf`, the NOPASSWD rules
  (`/etc/doas.d/30-appine.conf` or `/etc/sudoers.d/appine`), `/var/cache/appine/doas.apk`,
  `/var/cache/appine/{bash,procps,bubblewrap,openrc}/` (packages until installed), and `/run/appine-install.lock`.

## Public entry points

- `Rootfs.prepare(distro)` (with an optional store, used by the instrumentation tests), `download`,
  `fetch`, `isReady`, `installed`, `importing`, `store`, `reset`, `access`.
- Before every start: `ensureNetworkConfig`, `ensureContainersConfig`, `ensureLoginTools`,
  `ensureBashStartup`, `ensureGpuCommand`, `ensureBrowser`, `updateProfile`; around boot:
  `ensureOpenRc`, `boot`, `PREFER_OSCLOCK`, `failedServices`.
- Mirrors: `chooseMirror`, `useMirror`.
- Accounts: `loginAccount`, `regularAccounts`, `dirsChanged` (with `REFRESH_RULES`).
- `scripts/fetch-rootfs [outdir]` (build-time download of the Alpine minirootfs and the bundled
  packages into `target/rootfs` by default; prints each package's path, then the tarball's last).
- `login.sh` arguments: login setting (`auto`, `root` or an account name) and an optional start
  directory; or `--refresh-rules`.

## Data flow / lifecycle

### Tarballs

- Alpine: `scripts/fetch-rootfs` downloads the bundled packages from the branch's `main`
  repository (doas, and bash with readline, libncursesw and ncurses-terminfo-base, each checked by
  its pinned sha256 only; also procps-ng, libproc2, libintl, utmps-libs and skalibs-libs, sharing
  the ncurses dependencies; also bubblewrap and libcap2, openrc, openrc-user, ifupdown-ng and bridge; apk checks signatures at install) and, unless a copy with the
  pinned sha256 is already there, the minirootfs: its GPG signature is
  checked when both gpg and gpgv are installed (a failed signature download counts as bad; without
  gpg a warning), then its pinned sha256. Gradle bundles the newest fetched files by version
  (`BuildConfig.ALPINE_BRANCH` is taken from the name, `edge` without one) as `rootfs.tgz`,
  `doas.apk`, `{bash,procps,bubblewrap,openrc}/<file name>` without checking them again, and fails without them; `prepare`
  copies the tarball asset to the cache.
- Debian (`download`): a cached `cacheDir/<distro>.tar.gz` with the pinned length and sha256 is
  reused; else `fetch` tries the sources in order (probed by speed when there are several; Debian
  has one), checking for cancellation before each, moving to the next on any error but a cancel,
  and throwing the last error.
- One source: 30 s timeouts; written to `.part` while hashing (64 KiB reads, cancellation checked
  before each, progress every 0.5%); an attempt that failed after getting data is resumed with
  `Range` up to 5 times, and one that got none ends the source. A resume answered 206 continues,
  one answered 200 starts again from zero, and any other status ends the source like an attempt
  that got no data. An attempt that broke off with the whole pinned length received is not resumed
  but verified at once (a `Range` from the end would be answered 416). More than the pinned length
  stops the source at once (no resume). Length and sha256
  are checked and `.part` is renamed into place; any other exit deletes `.part` (a kill can leave
  it), and every call starts from zero, truncating it, so nothing resumes across calls or kills. A
  206 reply's range is not checked; the final hash catches a wrong one.
- A switch's download can be cancelled (between reads; a blocked connect or read waits for its
  timeout); a download inside `prepare` cannot.

### Import

- `prepare` (does nothing for a ready store, one whose `meta.db` exists):
  1. for the app's store, commit the distro it imports (`distro`), the only record;
  2. delete `<store>.tmp`;
  3. get the tarball into the cache: Alpine's asset copied over it, unchecked; others through
     `download`;
  4. import into `<store>.tmp` (`Native.importRootfs`) and `configure` it;
  5. sync the store (`syncfs`), rename it to the real store, fsync `files/` (a failure only
     logged) and only then delete the tarball.
- `installed` is the recorded distro of a ready store (Alpine when there is no record); while
  there is no store, `importing` names the distro an import was last started for (Alpine when
  there is none), which the service imports at the next launch. `reset` deletes `rootfs.tmp` and
  the store under the write lock and leaves the preferences and the cache alone.
- `configure` writes, with mode 0644 for new files (an overwritten file keeps its mode, and an
  existing entry that is not a regular file fails the import):
  - always: package sources from the first mirror (apk `main` and `community`; Debian deb822 over
    http for trixie, -updates, -security), `hostname` (`localhost`), `motd`, and
    `/etc/profile.d/appine.ashrc`, `/etc/profile.d/appine.bashrc`, `/etc/profile.d/appine.zshrc`, on Alpine
    `/etc/bash/appine.sh`, and then `/etc/profile.d/appine.sh` (the assets' `ashrc.sh`,
    `bashrc.sh`, `zshrc.sh` and `profile.sh`: motd, `TERM`, `LANG`, `NMAP_UNPRIVILEGED`, the browser default below,
    `ENV` naming the ash file unless one is set or the file is unreadable, and for bash, busybox ash and zsh only a
    coloured prompt with prompt marks, below; other shells keep the distro's prompt);
  - Alpine: `hosts` only when absent (the minirootfs ships one, so nothing is written), and no
    `resolv.conf` (the kernel writes one pointing at the DNS stub at every start when it is
    missing); bash as the login shell (`useBash`): the bundled packages from the assets' `bash/`
    into `/var/cache/appine/bash/`, and, when there were any, root's `/etc/passwd` shell changed
    from `/bin/sh` to `/bin/bash` (any other shell is kept) and `ensureBashStartup` run so
    `/etc/skel` and `/root` receive `.bash_profile` (sourcing `~/.bashrc`) and `.bashrc` (an
    interactive guard leaving `PS1` and history unchanged) and `/var/lib/appine/bash-startup-done`
    is recorded. Systems imported before keep busybox ash; accounts busybox's `adduser` makes
    later take the shell of `$SHELL` or of the account running it (so from a root tab they get
    bash too) and copy `/etc/skel`; procps-ng and its six dependencies are
    staged in `/var/cache/appine/procps/` by `cachePackages`, also used for bash and bubblewrap
    with libcap2 (`/var/cache/appine/bubblewrap/`). Existing stores do not receive these import-time files;
  - Debian: `hosts` and `resolv.conf` (the DNS stub) always.

### Before every start and boot

- `ensureGpuCommand` installs `/usr/local/bin/appine-gpu` (0755) when missing, called before
  kernel start only when Vulkan GPU is enabled. The launcher
  finds the packaged Alpine or Debian Venus manifest and execs the supplied command with
  `VK_DRIVER_FILES` set for that invocation.
- `ensureBrowser` installs `xdg-open.sh` as `/usr/local/bin/xdg-open` (0755) on either distro.
  It preserves custom launchers, replacing only the known previous Appine OSC helper by SHA-256.
  Before every kernel start it refreshes the static `/usr/local/libexec/appine-open-url` (0755)
  and `/etc/appine/browser` (0644: current loopback port and capability, shared by guest users).
  The shim execs that client; `ConsolePty` sets `BROWSER` to the shim (android/vt).
  The login profile also exports that default when `BROWSER` is unset or empty and the shim is
  executable, restoring browser discovery after `su -` clears the inherited environment.
  Nonempty custom values are preserved. This requires a shell that reads `/etc/profile`;
  shells such as fish and Debian's zsh need their own login configuration.
  Each invocation rereads the configuration and sends one HTTP(S) URL without using a TTY or
  inherited tab token; success acknowledges Android intent acceptance, not page loading or login.
- On the start thread, after an import and the start of its mirror probe when there is one, in
  this order, before the kernel starts under the write lock: a loopback-only `/etc/network/interfaces` when absent;
  `/etc/containers/containers.rootless.conf.d/appine.conf` setting `netns = "host"` when absent
  (rootless podman's pasta and slirp4netns need a TUN device Appine lacks; only rootless podman
  reads that directory, and a user's own `containers.conf` overrides it); on Alpine the bundled
  `doas.apk` into `/var/cache/appine/`, rewritten at every start; on Alpine, `ensureBashStartup`
  once per store (gated by `/var/lib/appine/bash-startup-done`): writes `/etc/skel/.bash_profile`
  and `/etc/skel/.bashrc` when missing and, for root and pre-existing regular accounts (UID
  1000–65533) whose `/etc/passwd` shell is `/bin/bash` and whose non-root home directory already
  exists, writes `.bash_profile` only if none of `.bash_profile`, `.bash_login` or `.profile`
  (including symlinks) exists and writes `.bashrc` when missing, owned by each account (`uid:gid`,
  0644), then writes the marker so later user deletions persist (missing or symlinked homes are
  skipped without creating directories); a profile left exactly as an
  earlier version wrote it (with `cd "$HOME"`, without prompt marks, or with marks that do not
  declare `cl=line`, or with ash's, bash's or zsh's marks in itself) replaced by the current one, with
  the mark files written before it (`/etc/bash/appine.sh` on Alpine stores, bash installed or
  not); an edited one is kept and a missing one not recreated, and then the mark files are not
  written either. The first two apply to every distro. A failed write in any of them fails the start.
- Storage is left to the packages: podman's overlay driver and docker's (containerd's) overlayfs
  snapshotter run on the kernel's overlayfs, rootful and rootless. A `storage.conf` choosing vfs or
  a `daemon.json` choosing native that an earlier build wrote stays until the user removes it.
- On Alpine, `ensureOpenRc` checks the per-store marker `/var/lib/appine/openrc-setup-done`.
  On an unmarked store it checks apk offline. If OpenRC is already installed, it writes only the
  marker and leaves boot asynchronous. A staged `/var/cache/appine/install-openrc.sh` (including
  one left by an older app) resumes an incomplete installation even if the package is present.
- For a missing or pending install, setup rebuilds its private package cache from the APK's
  OpenRC bundle and libcap2 from its bubblewrap assets. The installer uses a temporary virtual
  package for missing dependencies, records openrc by name in world and removes the virtual package.
  Setup runs inittab before tabs open, verifies the lock directory and default runlevel, removes the
  cache and installer and writes the marker. Later removal persists. A failed migration on an
  existing store reports the error and allows a login for repairs. The next start retries.
- Both first and subsequent boots run `PREFER_OSCLOCK` without a console. It adds osclock to the boot runlevel when
  `rc-update` and the osclock service exist and no runlevel has hwclock, osclock or swclock (a
  dangling link counts); the thread waits for it, ignores its exit status and only logs an
  exception. On subsequent boots tabs can log in while inittab runs. After boot, `failedServices` lists the services `/var/log/boot.log` says failed to
  start, for the service's notification.

### Prompt marks

- Integrated bash, ash and zsh set OSC 2 to the full current `$PWD` at each primary prompt, with
  control characters replaced by `?`. Before execution, bash and zsh set OSC 2 to the submitted
  command line, also sanitized, once for the whole pipeline or compound command. This is input
  text, not tracking of the foreground executable or its children. Programs can replace it with
  OSC 0/2 between prompts; the next primary prompt restores the directory.
  Bash sends the directory from `__appine_prompt`, zsh from precmd,
  and ash after the visible PS1 and B mark. Secondary prompts do not replace the title.
  Bash appends `$(__appine_preexec)` to PS0 once and snapshots `HISTCMD` at each prompt. The
  preexec function reads `history 1` with no timestamp only when history is enabled and its
  counter advanced; otherwise it reports `bash`, including ignored duplicate/space-prefixed
  commands, HISTIGNORE matches and disabled history. It does not install a DEBUG trap or
  change history settings. Zsh uses preexec's command argument, independent of history storage.
  The tab bar still shows numbers; these titles are available through long presses and TalkBack.
  Existing shells retain their loaded hooks until a new shell starts or the full profile is
  reloaded. Sourcing ashrc alone into an already-marked old PS1 skips its existing-mark guard.
- For the terminal's shell integration (android/vtcore) the profile has login shells mark their
  prompts with OSC 133:
  - bash: the profile sets the coloured PS1 and reads `appine.bashrc`, whose `__appine_prompt`
    function, put first in `PROMPT_COMMAND` (once, however often the file is read), prints, before
    each prompt, the last command's end with its status (D) and the prompt's start on a fresh line
    (A, `redraw=last;cl=line`), and wraps PS1 (P with `k=i` … B, the input starting) and PS2
    (`k=s`), and appends the output's start (C) to PS0, each again whenever it is missing, so a PS1
    that `~/.bashrc` or anything later sets is wrapped from the next prompt on; a later plain
    assignment to `PROMPT_COMMAND` drops the function and with it every mark. On Alpine,
    `/etc/bash/bashrc` reads `/etc/bash/appine.sh`, hence `appine.bashrc`, in every interactive
    bash (a login one first, through `/etc/profile.d/00-bashrc.sh`), so a nested bash (`bash`, `su`
    without `-l`) marks its own prompt, Alpine's `\h:\w\$ `;
  - busybox ash, which has no hook before a command or a prompt (1.37 has no `PROMPT_COMMAND`):
    PS1 itself carries D with `$?` (expanded at each prompt and redraw), A with `cl=line`, and
    after the prompt B (the input starts); PS2 is P with `k=s` and B. ash marks no output start
    and breaks a command longer than the screen's width into rows itself, so A and P also carry
    `appine_lf=output`, the app's own option, asking the terminal to read ash's line feeds
    (android/vtcore): one ash breaks a line with continues the input, any other ends it. `appine.ashrc`
    wraps whatever PS1 and PS2 are when they have no marks, and only in busybox ash: the profile
    sources it after setting its coloured PS1, and every interactive ash reads it again through
    `ENV`, a login shell after `/etc/profile` and `~/.profile`, so a PS1 that `~/.profile` sets is
    marked; one set later (typed, or by a file the user's own `ENV` names) goes without.
  - zsh: the profile sets the coloured PS1 and reads `appine.zshrc`. Its `__appine_precmd`,
    appended to `precmd_functions`, prints D with the status before each
    prompt, wraps PS1 (A with `cl=line` … B) and PS2 (P with `k=s` … B) in `%{ %}` whenever the
    marks are missing, and moves itself last in `precmd_functions`, so a PS1 that `~/.zshrc` or a
    theme's own hook sets is wrapped (a theme setting PS1 before each prompt gets its first prompt
    unmarked); `__appine_preexec`, appended to `preexec_functions`, prints the output's start (C)
    and the command title. Reloading the profile or companion file deduplicates both hook
    registrations while preserving other hooks, including when sourced in sh emulation.
    A and B are in PS1, so every redraw by zle sends them again; D is sent once per prompt.
  - `cl=line` tells the terminal that the three line editors move the cursor with the left and
    right arrows, so a tap on the typed command moves the cursor there.
- Every login shell of a tab reads it (root's shell `-l`, and `su <account> -c … exec "$SHELL" -l`
  for others) when the shell reads `/etc/profile`: zsh does only where its `/etc/zsh/zprofile`
  sources it (Alpine's does, in sh emulation; Debian trixie's does not, so zsh there has no marks
  unless the user's `~/.zprofile` sources `/etc/profile.d/appine.sh`). `ENV` is exported from every
  shell that reads the profile, so a nested interactive ash that inherits it (`ash`, `sh` on
  Alpine, `su` without `-l`, also under bash or zsh) marks its own prompt, the distro's; one
  started through `doas -s`, which resets the environment, does not. Other nested non-login shells
  (but bash on Alpine, above; a nested bash on Debian has none) and
  other shells get no marks from it (fish and nushell send their own, android/vtcore), and shells that
  do not read it still have `TERM`, `LANG` and `NMAP_UNPRIVILEGED` from the console's fixed login
  environment (android/vt), but show no motd.
- The shared profile contains no zsh array syntax; only zsh sources `appine.zshrc`. The companion
  uses an anonymous function with `emulate -L zsh` for registration, so Alpine's sh emulation
  does not change array filtering or indexing and the caller's options are restored afterwards.
  Both hooks also use local zsh emulation when invoked.

### Mirrors

- Each distro has built-in mirrors (official, Tsinghua, USTC, Aliyun). After every import, and
  only then, on the `appine-mirrors` thread, `chooseMirror` probes every mirror at once (one
  thread each, checking 512 KiB and 5 s thresholds between reads, waiting at most 10 s for each result) and takes the
  highest throughput (ties to the earlier mirror); if every probe failed it does nothing. A read
  can overshoot either probe threshold; these are not hard byte or elapsed-time caps.
- Writing (`useMirror`): only while the distro's sources file (`/etc/apk/repositories` or
  `debian.sources`) is byte for byte what the import wrote, with the official mirror, it is
  written again from the same template with the winner (nothing is written when the official
  mirror won). A file that differs in any way (already switched, edited by the user) or is
  missing is left alone, so the mirror is switched at most once per import and the sources are
  the user's from then on. It does not take the store lock; a failed write is only logged.
- Nothing records the mirror in use and nothing in the app shows or changes it later: the user
  edits the sources in the guest.

### Accounts and login

- `loginAccount`: `auto` is the regular account (UID 1000–65533, a shell other than empty,
  `nologin` or `false`) with the lowest UID, else root; `root`; or a named passwd entry, falling
  back to root. `regularAccounts` lists the same accounts for `android/settings`. `login.sh` picks
  the account by the same rules, except that it does not require a numeric GID or all seven fields.
- `login.sh` traps SIGINT, so Ctrl-C does not end the login but still interrupts the command
  running (normally apk or apt, skipping the install until the next login), chooses wheel, doas and
  `/etc/doas.d/30-appine.conf` on Alpine (`/etc/alpine-release`), else sudo, sudo and
  `/etc/sudoers.d/appine`, picks the account, and:
  - every login, root's included: rewrite the NOPASSWD rules for recorded admins still in the
    group that have no password: a shadow field that, after any leading `!`s, is empty or `*`
    (`adduser -D` writes `!`); `passwd -l`'s `!` before a hash still counts as a password, and so
    do a missing shadow entry and an unreadable `/etc/shadow`. The file is written beside it,
    made 0440 and renamed into place; with nobody qualifying, or without the rules' directory
    (on Debian, until sudo is installed), it is deleted;
  - `--refresh-rules` as the first argument only rewrites the rules: `Rootfs.dirsChanged` runs
    it as root, without a console and without waiting, when the service's poll finds `/etc`
    itself among the directories the guest changed (`passwd`, `chpasswd` and `adduser` replace
    `/etc/shadow`; group changes replace `/etc/group`), so a password set in a running session
    makes escalating ask for it within about one poll (2 s);
  - before choosing the account: install procps-ng, then bubblewrap offline when their cache directories
    exist, under the install lock, testing `apk info -e <package>` (BusyBox already provides ps/top/free),
    re-add each by name for upgrades, and delete its cache under the lock only on success. Failure
    leaves the cache for the next login and still opens a shell; later user removal is respected.
    This works with any login shell; `--refresh-rules` returns before installing;
  - every login whose account's passwd shell is `/bin/bash` while bash is missing and
    `/var/cache/appine/bash` exists: install those packages offline, then add `bash` once more by
    name (so world records it and `apk upgrade` upgrades it), under the install lock (below), and
    delete the directory once bash is there, so bash removed later is not installed again; if it
    is still missing (Ctrl-C while the install waited, below), say so and use `/bin/sh` this time,
    and the next login tries again;
  - root: `cd` to the directory (else root's home, else `/`) and `exec` root's passwd shell (or
    `/bin/sh` when it is not executable) as a login shell;
  - a regular account not yet in `/var/lib/appine/admins` (matched literally): add it to wheel
    (Alpine, with `permit persist :wheel` in `20-wheel.conf`) or sudo (Debian) and record it once
    it really is in the group (otherwise say so and retry at the next login);
  - a regular account, while the tool's marker is missing and the tool is not on PATH (whether or
    not the account was just made an admin): install doas from the bundled package and re-add it
    by name under the install lock, or sudo from the network showing apt's progress (Ctrl-C skips
    until the next login; no install lock is taken: `apt_update` retries `apt-get update` every 2 s
    while another apt holds the package lists' lock, saying so once and showing apt's other errors
    and warnings after it ends, and `apt-get install` waits up to an hour for dpkg's lock through
    `DPkg::Lock::Timeout`, which apt shows on the terminal), and touch the marker once the tool is
    there;
  - the install lock: a `flock` on `/run/appine-install.lock` held around each install of a bundled
    package (`locked`), so concurrent logins install bash, doas, procps-ng and bubblewrap one after another, each first
    checking whether an earlier holder installed it already; each `apk add` (`apk_add`) that fails
    on apk's own lock, held by an apk the user runs, prints that another apk is running and is
    retried with `--wait 3600`, so the login waits until that apk ends; Ctrl-C stops the wait and
    skips the install until the next login;
  - switch with `su <account> -c '<cd dir or home>; exec "$SHELL" -l'` (`--session-command` when
    util-linux su offers it), adding `-s /bin/sh` when the account's shell is not executable (su
    would otherwise fail and the tab close); package commands read from `/dev/null` so early typing
    reaches the shell.

## Dependencies (inbound / outbound)

### Inbound

- `TerminalService` (`android/service`: start, import, switch, reset, the mirror probe, per-start
  files, boot, the poll's `dirsChanged`, login accounts), `SettingsFragment` (`android/settings`:
  `Distro`, `installed`, `regularAccounts`, `loginAccount`), `Documents` (`android/documents`:
  `loginAccount`, `installed`, `isReady`, `access`), `ConsolePty` (`android/vt`: runs `login.sh`),
  the instrumentation tests (`fetch`, `prepare` into another store, `useMirror`, `updateProfile`,
  `PREFER_OSCLOCK`).

### Outbound

- `Native.importRootfs`, `syncRootfs`, `writeFile` (creates parent directories, does not follow
  symlinks), `readFile` (null when missing), `spawn` and `waitFor` (`android/native`);
  `HttpURLConnection` (system proxy); `BuildConfig` (Alpine branch); the bundled assets
  (`android/build`).

## Invariants and gotchas

- `Rootfs.access`: provider calls hold the read lock; starting the kernel and deleting the store
  hold the write lock, so the kernel's exclusive boot open never overlaps a provider open. The
  mirror write, the import (on `rootfs.tmp`) and the per-start files run without it.
- The probe starts as the import ends, so it can write the sources while the kernel opens the
  store (a distro switch's `replace` joins the mirror thread before deleting the store). The write
  opens its own store connection: at worst the kernel then skips one boot
  cleanup (the store's leftovers under `/dev/shm` and `/run`, hidden by the tmpfs mounts, and
  orphaned objects reclaimed later), with no corruption.
- A store becomes ready only when the synced import is renamed into place, so a half-imported
  `rootfs.tmp` never counts and is deleted by the next `prepare` or `reset`.
- An import interrupted by a kill (a first run, a distro switch, a reset) is redone with the same
  distro on the next launch, from the verified tarball still in the cache or by downloading it
  again with the usual progress; if that fails, the service falls back to Alpine with its notice.
- The distro record is committed before the import starts, so an existing store always has it;
  only the app's own store writes it, but an import into another store (only the
  instrumentation tests make one) still overwrites (Alpine) and deletes the shared cached tarball.
- `writeFile` while the kernel runs is seen at once (the store's commit counter invalidates kernel
  caches).
- `updateProfile` replaces only the versions it knows, compared whole (`OLD_PROFILE` and
  `UNMARKED_PROFILE` by text, later ones by sha256 in `REPLACED_PROFILES`): changing `profile.sh`
  must add the sha256 of the text it replaces (the committed asset, byte for byte), or stores keep
  the version they have; `ashrc.sh`, `bashrc.sh` and `zshrc.sh` are written only with the profile,
  so a change to any companion alone reaches no existing store (change `profile.sh` with it); and
  the motd is written only at import, so it is never updated.
- apk takes its database lock without waiting unless given `--wait` (which apk 3 accepts though
  its help does not list it): hence the install lock and the retry with `--wait`; a tab whose login
  waits for an apk the user runs shows only that line until the apk ends or Ctrl-C. apt 3's
  `DPkg::Lock::Timeout` covers dpkg's frontend lock but not the package lists' lock, which
  `apt-get update` takes, hence the retries there; apt shows its own wait only on a terminal. The
  branch's mirrors keep only each package's latest build, so a rebuild of a pinned package makes a
  fresh `scripts/fetch-rootfs` fail until it is pinned anew.
- The marks rely on the shell redrawing its prompt on SIGWINCH (the terminal clears the prompt's
  rows on a resize; `android/vtcore`): bash, busybox ash and zsh do.
- The rules refresh writes in `/etc/doas.d` or `/etc/sudoers.d`, not `/etc` itself, so it does not
  trigger itself; the first login's group change and `mkdir /etc/doas.d` cause one more refresh.
- `login.sh` runs without job control, so its children share its process group: a Ctrl-C that
  lands during another command than an install (the passwd lookup, the group check, the shadow
  read, the `su --help` probe) can log a named account in as root, leave an admin out of the
  NOPASSWD rules until the next refresh, or make Debian fall back to `su -c`. The window is short.

## Confirmed bugs / technical debt

- Mirror template comparison and replacement are separate operations: a guest edit between
  them can be overwritten.
- `locked` runs the install command even when `flock 9` fails. The unchecked return is confirmed;
  consequences under lock errors or interruption have not been reproduced.
- Busybox ash can emit literal path controls through the visible prompt's `\w`. The directory
  title is sanitized and restored after that prompt, but other terminal effects in visible
  prompt text are not sanitized.
- Automatic command titles cover bash and zsh only. Busybox ash has no preexec hook; it still
  needs terminal-side or foreground-process detection to report commands that set no title.
- **The rules miss changes that rename nothing in `/etc`.** A shadow or group file edited in place
  (an append, a text editor writing the file itself) changes no entry of `/etc`, a burst of more
  than 256 changed directories between two polls stops recording the rest, and changes before the
  service's first poll are not recorded, so such a change waits for the next login; while the app
  is not running there is nothing to refresh.

## Open questions

- Should a failed optional per-start write (the network, containers, doas package or profile file,
  for example through a directory the user replaced with a symlink, which `writeFile` refuses) fail
  the whole start rather than be logged?
- Should a Debian tarball left in the cache after its import failed and fell back to Alpine be
  deleted?

## To verify

- Alpine `.bash_profile`/`.bashrc` seeding on 16 KB-page devices and live `TerminalService`
  upgrade cold starts (4 KB-page API 36 instrumentation tests passed).
- Android device execution and end-to-end migration of the extracted `zshrc.sh` companion (host
  zsh native/sh-emulation and ash/dash profile checks passed).
- Browser defaults and Codex authorization flow on Android (host container PTY checks passed;
  existing stores receive the profile update at restart only when unmodified).
- Shell command titles with custom prompt frameworks, history changes in later `PROMPT_COMMAND`
  entries and live upgrades of already-running shells.
- That Alpine's doas reads `/etc/doas.d/*.conf` in lexical order (the NOPASSWD file relies on coming
  after `20-wheel.conf`), and that doas reads only `*.conf` and sudo skips names with a dot (the
  temporary rules files rely on it).
- The profile's bash marks in the app on Debian (tried only in a container with Ubuntu 26.04's
  bash 5.3) and with a `PROMPT_COMMAND` array or a prompt tool that rewrites PS1 after it each time.
- The profile's zsh marks in the app (tried only in a container with Alpine's zsh 5.9) and with a
  right prompt (its cells follow B, so they count as input), a multiline PS1 (rows after the first
  are not marked as continuation rows), `prompt_percent` unset or a prompt framework (oh-my-zsh,
  powerlevel10k).
