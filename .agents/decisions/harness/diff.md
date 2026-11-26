# Differential and upstream suites (harness/diff) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: harness/diff"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)
>
> Decisions on harness/diff made before it was split from harness keep their `harness` tags and live in `.agents/decisions/harness.md`: D1–D3, D5, D9, D11–D14, D17–D20, D23, D27, D29, D31, D33, D34 and D36–D41.

## Active

### D1: Differential suites own runners, cases and recorded deviations

- **What**: harness/diff owns differential and upstream runners, case inputs and recorded test deviations, while implementation policy remains in the kernel maps.
- **Why**: The extracted subsystem needs a focused architecture reference with explicit integration boundaries.
- **Tradeoffs**: Pre-split decisions remain in the parent snapshot and related changes may require several maps.
- **Watch out**: The split preserves inherited verification and open issues; it is not a fresh full audit.
- **Source**: 60790c14; 39e55b4b

### D2: Cgroup watch tests avoid registering an event-file reader

- **What**: Test inherited freeze with separate file and directory watches, then retain a directory watch across pids enable and re-enable and require IN_MODIFY after each denied fork.
- **Why**: Opening an event file for reading could mask a broken watch lifetime or missing controller registration.
- **Tradeoffs**: The directory cases use O_PATH to pin the child dentry for comparison with native Linux.
- **Watch out**: A never-looked-up dentry can behave differently on Linux 6.8, and a notification delayed beyond two seconds fails the pids case.
- **Source**: 0f5c5132, b65799c8

### D3: The gtest runner dumps `gtest.out` diagnostics on unexpected `exit 0` or `exit 1`

- **What**: `tests/diff/gtest/run.sh` prints `out: file=<bytes>B cap=<len>B` and the first 30 lines of `gtest.out` (mapping NUL bytes to `?`) when a test produces `exit 0` or `exit 1` without a gtest result line.
- **Why**: Discarding `gtest.out` hid whether intermittent `exit 0`/`exit 1` CI failures came from an empty or truncated file versus command-substitution read loss.
- **Tradeoffs**: Assumes legitimate crashes exit via signal codes rather than `0` or `1`, and truncates long outputs to 30 lines.
- **Watch out**: If a future gtest legitimately exits `0` or `1` without a standard gtest status line on both sides, differing diagnostic output could cause a mismatch.
- **Source**: 45495baf

### D4: Difftest store creation retries initial `apk add` up to three times

- **What**: `scripts/difftest` wraps its initial `apk add -q` in a 3-attempt loop with a 5-second pause between retries before failing.
- **Why**: A single transient DNS failure against `dl-cdn.alpinelinux.org` aborted an entire `Full tests` shard before any test ran.
- **Tradeoffs**: Adds up to 10 seconds before failing when offline while keeping the existing partial-store check on final failure.
- **Watch out**: Mirror outages longer than the retry window still fail store creation and leave a partial store that must be removed on local reruns.
- **Source**: 166dd6ee

### D5: Legacy Starnix and gVisor skip filters narrow only after verifying individual gtest outcomes

- **What**: Legacy Starnix and gVisor case scripts narrow broad skip filters by restoring verified passing tests, listing remaining multicast exclusions individually, and running `uio_test` in `starnix-mm`.
- **Why**: Overly broad skip filters masked regressions in kernel behaviors that Appine now implements.
- **Tradeoffs**: Named exclusions add more filter entries and admit newly added multicast tests into the suite by default.
- **Watch out**: Group-level output matching can hide identical failures on both sides, so verify individual gtest outcomes whenever revisiting other skips.
- **Source**: b5673c4c

### D6: Legacy gVisor coverage adds `gvisor-mm` and `gvisor-io` after native and Appine trials

- **What**: Legacy gVisor coverage adds `gvisor-mm` (seven memory and cross-process transfer programs with two exact exclusions) and `gvisor-io` (three file I/O programs without exclusions) after native and Appine trials.
- **Why**: These previously omitted gVisor programs exercise partial transfers, memory mappings, and file I/O behaviors beyond the existing differential suites.
- **Tradeoffs**: Regular comparisons build ten additional gVisor programs and add roughly 1.5 s locally for the initial `gvisor-mm` pair.
- **Watch out**: The CI runner executes against a different native Linux kernel than the local trial environment.
- **Source**: 54ce6b50, 48f1c17e

### D7: Selected gVisor filter groups enforce expected pass counts and refresh stale lane clones

- **What**: `scripts/build-gvisor-tests` builds from both legacy scripts and `tests/diff/gtest/gvisor.filters`, `tests/diff/gtest/selected.sh` and `run.sh` require each selected row to reach its expected `exit 0` pass count before comparing outputs, and `scripts/difftest` refreshes lane clones when their image ID changes.
- **Why**: Plain output comparison alone could treat identical failures, skips, teardown errors, or empty selections on native Linux and Appine as passing runs.
- **Tradeoffs**: Updating upstream gVisor requires re-checking both the filter rows and their expected pass counts.
- **Watch out**: Native kernel-version differences and socket timing can shift native test outcomes across environments.
- **Source**: 231480cb
