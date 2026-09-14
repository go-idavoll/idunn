# Local end-to-end scenarios

`test/e2e/run.sh` proves that a release published on GitHub installs and updates
(minor, major, floor gap, elevated). This suite covers what that run does not
drive: the failure and edge paths of the lifecycle. Every step is a real process,
and nothing leaves the machine. `cmd/packer` publishes into a throwaway
repository, an `httptest` server on 127.0.0.1 serves it, and `cmd/installer`,
`cmd/launcher` and the `cmd/hostapp` fixture consume it.

```
go test -tags=e2e ./test/e2e/local/...
```

It sits behind the `e2e` build tag because it compiles binaries and runs them, so
`go test ./...` stays fast. One run takes about a minute with a warm build cache
and about two and a half minutes cold.

## Scenarios

| Test | What it asserts |
|---|---|
| `TestBusyAppDefersAndLauncherFinishes` | A second process holds the application lock, so `--on-busy defer` exits 4. `current` has not moved, the verified 1.1.0 tree is on disk and the journal rests in `DEFERRED`. The holder then releases the lock, and `cmd/launcher` finishes the update, starts 1.1.0 and commits. A second start writes nothing (§14.3). |
| `TestKilledInsideTransactionRecovers` | The app stops inside a phase and is killed from outside (SIGKILL / TerminateProcess). The test first checks that the journal is open at the expected record (`BEGIN`, `MIGRATED`, `SWAPPED`). Then the launcher's recovery must reach one exact whole version: rolled back to 1.0.0, rolled back to 1.0.0, or committed at 1.1.0. Pointer, recorded state, version directories, staging and the binary that actually starts must all agree (§6.2, T10). |
| `TestFailedMigrationRollsBack` | The host migration changes host state and then fails. The app exits 1 with `migration failed`. The tree is unwound (`ROLLED_BACK`, 1.1.0 removed). The host's `Rollback` hook ran and restored its state, which the hook's own log shows. Retrying the same update on that base then succeeds (§7, T11). |
| `TestInstallerRefusesDowngrade` | `installer --version 1.0.0` over 2.0.0 exits 3 with the preflight's own message. The journal is not written and no payload is downloaded. `--allow-downgrade` does install 1.0.0, and retention keeps the newer 2.0.0 tree (§14.6, T19). |
| `TestTamperedPayloadIsRefused` | One byte of a payload is flipped, keeping its length. The installer exits 1 and nothing is installed. The reason is pinned too (see below). A control step then restores the byte, and the same client with the same cache installs. |
| `TestRetentionCollectsOldVersions` | Four self-updates with `--retain 3` and then `--retain 2`. After each commit, exactly the configured window of version directories remains. The retained rollback target still runs (§14.1). |

Scenarios that `run.sh` already attests are left out on purpose: install, minor
and major self-update, sequential updates and the migration floor.

## How it is built

- **Keys.** Each scenario runs `test/e2e/cmd/e2etool init-repo`, the same
  ceremony `run.sh` uses. The suite accepts only the three publishing-key
  variables it prints and gives them to the packer. As soon as `1.root.json` is
  signed, the root key file is deleted. Child processes never inherit a role key
  variable from the parent environment.
- **Anchor.** The client's trust anchor is a copy of `1.root.json`, taken before
  anything is published. The client never reads it back out of the served
  repository, because that would let the server decide whom to trust.
- **The host application.** `cmd/hostapp` is rebuilt from source for each version
  (`-X main.version=…`). Unlike `e2eapp`, it takes the anchor and the URLs as
  flags, because many repositories run side by side. It also adds the seams these
  scenarios need: `--hold-lock`, `--data`/`--fail-migrate` and `--hang-at`.
- **The clock is real.** The binaries under test take no injected clock. The
  packer's reproducibility is pinned by `internal/packer`'s golden test.

## Where it runs binaries

Every binary is built under one work directory and executed from there, and so
is every installed application. This includes the app in `versions/<v>/`, which
the launcher starts. The work directory is, in this order:

1. `IDUNN_E2E_WORK`, if set;
2. `GOTMPDIR` (from the environment or `go env`);
3. the system temp directory.

On Windows, endpoint protection (Defender ASR, for example) often refuses to
start a program that was just written below `%TEMP%`, which is where
`t.TempDir()` would put it. On such a host, point `GOTMPDIR` or `IDUNN_E2E_WORK`
at a directory that is allowed to run programs.

Scenario directories are deleted after a pass. They are kept on failure, and
always when `IDUNN_E2E_KEEP` is set; the test log prints their path.

## The rule for the tamper scenario

A 404, a truncated file or a dead server also make the installer exit non-zero. A
test that accepted any of them would keep passing after the hash check was
removed. So the scenario asserts two things:

1. The server delivered the tampered file **whole**: status 200, with every byte
   of its signed length.
2. The installer refused it with go-tuf's hash verdict
   (`hash verification failed - mismatch for algorithm sha256`), naming the
   payload target.

go-tuf checks the hash before the length, so (2) on its own would also match a
truncated file. (1) rules that out. This was checked by temporarily breaking
things; none of these changes is committed:

- **Truncated file:** fails (1).
- **Deleted file (404):** fails (1).
- **Verification skipped in `core/trust`:** the installer exits 0, so the test fails.

If this scenario ever passes for the wrong reason, treat it as the
highest-priority bug class in the project (AGENTS.md §7).

## Not in CI (yet)

This suite has only been run on Windows so far. A job in `ci.yml` would be cheap:
one `go test -tags=e2e ./test/e2e/local/...` step on each of the three runners,
one to three minutes each. It would not overlap `e2e-update.yml`, which needs
GitHub releases and a token. It is proposed rather than added until it has
passed on Linux and macOS.
