# IDN-06 — `BusyDeferToRestart` actually defers (§14.3) — **done**

**Priority:** P1 — blocks a trustworthy release

The staged tree stays and the journal moves to `DEFERRED`, a resting state recovery
neither undoes nor finishes — and one it does not sweep the staged version or the hook
scratch space up behind, which is what would otherwise turn a deferred update into a
lost one. The launcher completes it at the next start. Applying the same version again
while it waits is a no-op rather than a re-download; a *different* version supersedes
it, so a machine that never restarts cannot wedge the updater.
