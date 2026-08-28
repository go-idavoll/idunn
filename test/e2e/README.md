# End-to-end tests

This tree is the only place where idunn is tested with **no seam in it**. Every
other suite injects a filesystem, a clock, or a trust client; here the real
`cmd/packer` publishes a real TUF repository, a real HTTP server hands it out,
and the real `cmd/installer`, `cmd/launcher` and a host application consume it as
**separate processes**.

```
make e2e          # or: go test -tags=e2e ./test/e2e/...
```

It is behind the `e2e` build tag because it builds binaries and talks over a
socket — `go test ./...` stays fast and hermetic.

## What it covers

| Scenario | The property |
|---|---|
| `TestInstallThenLaunch` | publish → install → launch, with the payload on disk |
| `TestSelfUpdateKeepsARollbackTarget` | a running app replaces itself; the predecessor survives (§6.1) |
| `TestDeferredUpdateAppliedByLauncher` | a busy app defers, the launcher finishes it at the next start (§14.3, IDN-06) |
| `TestCrashDuringApplyLeavesAWholeInstall` | a process that stops existing mid-transaction leaves old **or** new (§6.2, T10) |
| `TestFailedMigrationRollsBack` | a failing host migration unwinds (§7, T11) |
| `TestDowngradeRefusedUnlessAllowed` | the installer's downgrade preflight (§14.6, T19) |
| `TestTamperedPayloadIsRefused` | the backstop: a flipped byte is refused, with nothing installed (AGENTS.md §7) |
| `TestUnchangedPayloadsAreNotRefetched` | delta stage 1: unchanged bytes cross the wire once (§6.4) |
| `TestGarbageCollectionKeepsTheRollbackTarget` | retention drops the old and keeps the rollback target (§14.1) |
| `TestTheLauncherReplacesItself` | the shim above `versions/` is carried forward by the start after the update (§13, IDN-17) |
| `TestAChangedFileArrivesAsAPatch` | delta stage 2: a changed binary crosses the wire as the difference (§6.4) |

## How it is built

- **Keys.** One throwaway ed25519 key per role, generated per test and never
  written outside the test's temp dir (AGENTS.md §5, §7). The three publishing
  keys are handed to the packer as PKCS#8 PEM files through the documented
  environment variables; **the root key never is** — a tool that runs on every
  release must not be able to sign the trust anchor.
- **Root ceremony.** `repo.ceremony` is the offline ceremony of `docs/packer.md`
  §4 reduced to what a test needs. The packer never writes a root, so the suite
  has to.
- **Anchor.** The client is seeded with a *copy* of `1.root.json` taken before
  anything is published. Reading it out of the served repository would mean
  trusting the server to say whom to trust.
- **The host application.** `fixtures/app` is both the payload of every release
  and the host that wires `core/updater` together. It is rebuilt from source per
  version, so the suite proves that *today's* core survives the round trip.
- **The clock is real.** The binaries under test take no injected clock, so
  publishes are stamped with the real time. Reproducibility of packer output is
  pinned by `internal/packer`'s golden test, not here.

## The rule

A scenario here asserts the *reason* as well as the outcome. A 404, a truncated
file or a broken server also produce a non-zero exit, and a test that accepted
any of those would keep passing after the check it exists for was removed. If
`TestTamperedPayloadIsRefused` ever goes green for the wrong reason, that is the
highest-priority bug class in the project (AGENTS.md §7).
