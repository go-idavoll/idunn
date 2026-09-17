# IDN-39 — Probation: a new version confirms it is healthy, or is rolled back (§6.1, §6.2, §14.3, §14.5)

**Priority:** P1 — blocks a trustworthy release

Today an update is final once its transaction commits. `txn.Rollback` undoes a
completed swap, but only for a caller that is still inside `Apply` and has decided the
update is bad (`updater.md` §6). A release that commits and then crashes on every start,
hangs, or fails its own data migration stays live, although the previous version is
still under `versions/` (`stage.MinRetain`). The launcher cannot see it either: on POSIX
it `exec`s into the application and is gone, and on Windows it only passes the exit code
through, with `launch.RelaunchExitCode` as the one code it acts on (IDN-29).

"No non-zero exit within n seconds" is not the answer: an application that hangs or
shows an empty window passes, one that fails at n+1 seconds does not, the reason is
reduced to an exit code, and it needs a supervising parent the launcher does not have
on POSIX. The application knows when it is healthy, so it says so.

Wanted:

- **A committed update starts in probation.** The install state records the new
  version as `PROBATION` with an attempt counter and the version it replaced. Opt-in:
  without a probation setting, a commit is confirmed at once, so an application that
  never calls the API is never rolled back.
- **The publisher sets `K` per release, signed.** `pack.yaml` takes
  `probation: { attempts: K }`; each release carries its own value, so a release whose
  migration needs several starts raises it, and the next one lowers it again. The value
  that governs a probation is the one of the release *in* probation, read from signed
  metadata and copied into the install state at commit — the launcher never fetches
  anything to decide. **Not a descriptor field:** `release.ParseDescriptor` refuses
  unknown fields and schema versions, so either would make every deployed client
  refuse every new release. It travels like release notes (IDN-38): a TUF target
  discovered by name, e.g. `policy/v<major>/<version>.json`, with a strict parser; a
  client that knows nothing about probation never asks for it. The client clamps `K`
  to a ceiling, so a typo cannot turn probation into "never roll back". A host policy
  may override it locally (lower for a fleet canary, off for a kiosk), the same
  precedence as other policy.
- **The launcher counts starts, not seconds.** Before it starts a version in probation
  it increments the counter, durably, the way a boot counter works (A/B updates on
  Android and ChromeOS, GRUB `boot_counter`). No timer, no waiting process, the same
  on every platform. The code stays in `core/launch` and `core/txn`; `cmd/launcher`
  gains a call, not logic.
- **The application reports, through `core/launch`:**
  - `MarkHealthy(ctx)` — atomic write, idempotent, cheap enough to call on every start;
    ends probation. The application calls it once it is actually ready, after its own
    migrations, not at `main`.
  - `MarkUnhealthy(ctx, reason)` — records a bounded, sanitized reason; the application
    then exits. The next launcher start rolls back without spending further attempts.
- **Rollback on the next start** when the version is reported unhealthy, or when the
  counter exceeds `K` without a confirmation. It runs `txn.Rollback` with
  `Migrator.Rollback`, under the app lock, journaled and crash-safe like every other
  rollback, and then starts the previous version. The packer default for `K` is at
  least 2–3: users close an application before it confirms, and machines lose power.
- **A restart the application asks for is not a failed attempt.** A migration that
  needs several starts goes through `launch.Relaunch` (IDN-29). Before the application
  leaves, `Relaunch` atomically increments `requested_restarts` in the probation state;
  the launcher consumes the marker on its next start and does not count that start as
  an attempt. The three paths `Relaunch` has today:
  - **POSIX:** the application `execve`s the launcher. The launcher saw nothing of the
    run, so the marker is the only way it can know; the process id a service manager
    watches does not change.
  - **Windows, under the launcher:** the launcher never exits while the application
    runs — it is the parent for the application's lifetime (`exec_windows.go`), keeps
    the process id its starter sees and sees exit code `RelaunchExitCode` itself. The
    marker is redundant here and written anyway, so the launcher has one rule instead
    of a per-platform one.
  - **Windows, started without the launcher:** `Relaunch` starts a new launcher with
    `--after-pid` and the application exits. The process id does change on this path,
    as it already does for IDN-29; the marker covers it like the others.

  `requested_restarts` has its own ceiling, reset by `MarkHealthy`, so a loop of
  requested restarts ends in a rollback too — on POSIX, where no supervising launcher
  enforces the IDN-29 relaunch limits, this ceiling is the bound. An application that
  just exits and relies on being started again spends attempts, and its publisher
  sizes `K` for that.
- **No fork-and-hand-over supervisor on POSIX.** A launcher that starts the application
  as a child and exits once it is healthy changes the process id (systemd kills the
  control group, launchd with `KeepAlive` starts a second instance), returns a shell
  prompt while a CLI application still owns the terminal (`SIGTTIN`), loses the exit
  code, and must forward signals until it leaves. It would be neither the Windows
  model (a parent for the whole lifetime) nor the POSIX one (`exec`, same process id),
  and would carry the costs of both. Counting starts needs none of that.
- **The rolled-back version is blocked** in the install state until the channel offers
  a newer one; otherwise the next update check installs it again and the loop repeats.
  This is a local decision about an already verified target, not a TUF downgrade, and
  the security concept (§11) says so.
- **The reason is reported, not only stored:** a hook event (§7) and telemetry (§14.5)
  carry version, attempts and reason, so a publisher learns *why* a release failed, and
  a UI sidecar (IDN-19) can tell the user. The same record is what a later crash
  reporter reads; a reporter itself stays out of the launcher.

## As built — the mechanism, with a host policy

The allowance comes from the host for now (`updater.Policy.Probation`); the signed
per-release value is the second half of this item. Documented in `updater.md`
(*Probation*).

- **A record outside the journal.** `.updater/probation.json` (`internal/layout`,
  strict parser, bounded, schema-versioned): version, previous, status, attempts and
  restarts with their allowances, reason, and the blocked version. Not new journal
  states, deliberately: a rollback puts the previous version back, and its copy of
  `core/txn` would refuse a journal holding a state it does not know — that version
  could never update again. The journal keeps saying COMMITTED, which is true.
- **Armed before `BEGIN`** by `Apply` when `Policy.Probation.Attempts` is set, and
  acted on only while `current` names its version: a rolled-back transaction leaves a
  record nobody reads, a deferred one is on probation from the start that applies it,
  and there is no crash window between commit and record. A first install gets none.
  An unfinished rollback's record is never replaced (`ErrStale`); the blocked version
  carries over into every new record.
- **Counted in `launch.Start`**, after recovery and a deferred update and before the
  launcher swap and the OS integrations, so those follow the version that runs
  afterwards. `launch.Result.Probation` reports the attempt or the rollback;
  `cmd/launcher` prints a rollback even with `-quiet`.
- **`launch.MarkHealthy(fs, root, version)` / `MarkUnhealthy(fs, root, version,
  reason)`** take the version, so an instance of another version cannot confirm or
  condemn the one on probation. Both are no-ops without an active record for that
  version. The reason is sanitized (`layout.SanitizeReason`: valid UTF-8, no control
  characters, 512 bytes).
- **The restart marker** is written by `launch.Relaunch` before it hands back 42,
  starts the launcher or `exec`s it, into the root it relaunches (`Root`, else the
  launcher's directory), and only while the running version is the one on probation.
  Best-effort: an application that cannot write it relaunches anyway and spends an
  attempt. `Restarts` defaults to 3; one past it rolls back.
- **The rollback** takes the application lock (and waits for a start that gets it),
  records `reverting`, moves `current`, runs `Migrator.Rollback`, writes the install
  state, records `reverted` with the version blocked, and removes the version
  directory last, best-effort. Every step repeats; a start that finds `reverting`
  finishes it before anything else. A version whose predecessor is gone is `kept`, with
  the reason saying so.
- **Blocked in the updater:** `CheckForUpdate` answers "no update" for it, and `Apply`
  refuses it with `ErrPolicy`/`ErrBlocked`. A blocked version installed again by an
  updater that predates probation is rolled back again at the next start.
- **Refused for elevated roots** by `New` (`ErrConfig`): nobody unprivileged could
  write the record.
- **Tests:** `internal/layout` (round trip, every refusal, sanitizing), `core/launch`
  (counting, confirmation, unhealthy, restart marker and its ceiling, stale records,
  deferred updates and the lock, a rollback that waits for a running instance, one that
  is interrupted in the host's hook and finished by the next start, kept, blocked
  version installed again, unreadable record), `core/updater` (policy bounds, arming,
  the whole cycle through `launch.Start`, the block, an unfinished rollback), and
  end to end (`test/e2e/local/probation_test.go`): an unconfirmed update rolled back
  on the third start and not offered again while the next release is and stays once
  confirmed, and an unhealthy one rolled back with the application's own reason.

## As built — the release's own allowance

- **A policy target beside the descriptor:** `releases/<os>-<arch>/<version>_policy.json`
  (`release.PolicyPath`, `release.Policy`, `release.ParsePolicy` — strict, key-checked,
  fuzzed). Not the `policy/v<major>/…` path sketched above: under the existing
  `releases/*/<major>.*.json` pattern it needs no delegation change and no re-sign of
  `targets`. The underscore keeps it from ever parsing as a descriptor path — with a
  dot, `1.3.0-rc.1.policy.json` would be the descriptor of `1.3.0-rc.1.policy` to
  every deployed client that lists releases, and to retention.
- **Packer:** `probation: { attempts, restarts }` in `pack.yaml`, `attempts` required
  (0 publishes "not on probation"), bounds checked, the emitted policy re-parsed by
  the client's parser; retention retires a policy with its descriptor.
- **Trust:** `trust.Client.ReleasePolicy` resolves the descriptor first, which loads the
  owning role, and treats a policy path absent from the signed target lists as "none";
  a listed policy that cannot be fetched, parsed or matched to its path is an error.
- **Updater:** `ProbationPolicy.FollowRelease`. A release's signed allowance applies
  only to a host that opts in — the host knows whether its application confirms; the
  host's `Attempts`/`Restarts` are the fallback. A published policy that cannot be
  resolved fails the update before `BEGIN`. `New` refuses `FollowRelease` without a
  `PolicyResolver`.
- **Tests:** parser and path round trips including pre-release and build metadata,
  fuzzing; the trust client against a signed repository (none, resolved, malformed,
  mismatched, out of bounds, unpublished release, `Versions` unaffected); packer config,
  a published policy resolved by the real client, retention with policies (mutation
  checked); updater precedence table and failure; e2e `TestReleasePolicyDecidesTheProbation`
  — a release published with `attempts: 1` rolled back after one start where the host
  would have given two, and one published with `attempts: 0` not put on probation.

## As built — telemetry for a failed probation

- **The launcher leaves an outcome, the updater reports it.** The launcher has no
  Reporter and no network. When it decides a rollback — right after the `reverting`
  record — or keeps a version, it writes `.updater/probation-outcomes/<version>_<result>_<class>.json`
  (`internal/layout`, strict, bounded to 16 pending files). The next
  `CheckForUpdate` of the version that runs hands each to the host's `Reporter` and
  removes it; one the Reporter refuses stays for the next check, one that does not
  parse is dropped. An elevated updater leaves them alone.
- **What is reported** is a `hook.Outcome` like any other: versions, platform,
  `Result` `rolled_back` (so a publisher's rolled_back rate includes it) or `kept`,
  `FailedPhase` `probation` (new phase), and `ErrorClass` from a closed vocabulary —
  `unconfirmed`, `unhealthy`, `restarts`, `reinstalled`. The application's reason is
  free text and never leaves the machine (§14.5). `At` comes from
  `launch.Options.Now`.
- **Once.** The file is named after version, result and class, and written only by
  the start that decides the rollback, so a rollback finished by a later start is not
  reported again. A separate directory rather than a field in `probation.json`: a
  version rolled back to that predates this change would refuse a record with a field
  it does not know.
- **Never in the way.** An outcome that cannot be written is an Observer event; the
  rollback goes on.
- **Tests:** `internal/layout` (round trip, one file for the same outcome, the
  ceiling, refusals including free text as a class), `core/launch` (each class, no
  second report for a finished rollback, kept, a rollback that goes on at the ceiling),
  `core/updater` (reported once through `launch.Start` and `CheckForUpdate`, offered
  again after a refusal, waiting without a Reporter, unreadable dropped), and end to
  end: the rollback in `TestUnconfirmedUpdateIsRolledBackAndNotOfferedAgain` is
  reported exactly once by the application's own updater.

## Still open

- **A host ceiling on the release's allowance** (a lower limit for a canary fleet)
  beyond turning `FollowRelease` off.
- **The launcher a reverted release staged** stays swapped in; whether a rollback
  should restore the previous launcher too is undecided.
- How a `Migrator.Rollback` that runs days after `Migrate` handles data the new
  version has written since — whether probation should forbid irreversible migrations,
  or `Migrate` runs on confirmation rather than before the swap.
- Whether services and headless hosts count attempts per launcher start or need a
  supervisor's restart count (systemd `Restart=`, the Windows service recovery actions).
- System-wide installs (IDN-23): refused today.
- Whether GC must pin the previous version while probation lasts: with `MinRetain` it
  survives the commit, but a second update during probation moves the window.
- Whether the policy target carries more than `K` later (a probation deadline in
  wall-clock time, subject to the time floor of IDN-09).
