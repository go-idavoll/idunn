# IDN-28 — macOS: install on quit and relaunch (§14.3)

**Priority:** P1 — blocks a trustworthy release

There is no launcher on macOS — the bundle is what starts — so `DEFERRED` cannot be
completed "at the next start" without starting the application twice. The macOS
shape is Sparkle's: a helper shipped in `Contents/Helpers/`, signed with the same
Team ID (macOS 13's App Management lets a process modify only bundles of its own
team without a prompt), started when the application wants the update applied; it
waits for the application's process to exit (optionally asking it to quit with an
Apple event), resumes the deferred transaction, swaps (IDN-26) and relaunches through
Launch Services — only on success, and only if the application was running.

The helper takes the same three scalars as the elevated `apply` verb and no path from
its caller; for a system-wide install it is the thing IDN-08 elevates.
