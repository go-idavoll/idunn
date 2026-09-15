# IDN-21 — Reconcile the `OnBusy` default with the design (§6.3, §14.3) — **done**

**Priority:** P2 — hardening and reach

Decided the second way: the design text drops the claim, `New` promotes nothing, and
`BusyAbort` stays the zero value. No API or behaviour change.

Promoting an unset `OnBusy` to `BusyDeferToRestart` was the other option and is the
worse one. Go cannot distinguish "left unset" from "deliberately chosen", so the
promotion would turn a forgotten line of host configuration into a change of behaviour
in the apply path — an update that quietly stays staged and lands at the next start, on
a host that never asked for one. Deferral remains what §14.3 recommends to a host whose
running application updates itself; a host that wants it says so.
`TestUnsetOnBusyAbortsRatherThanDefers` (`core/updater`) pins the zero value.
