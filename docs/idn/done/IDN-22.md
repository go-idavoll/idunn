# IDN-22 — The elevated helper vets the install root it is asked to write (§14.2, T16) — **done**

**Priority:** P2 — hardening and reach

The root is one of the three scalars, and the caller chooses it. A helper running as
administrator that writes into a directory a non-administrator can modify can be
redirected by a junction planted between two of its operations. `elevate.AcceptRequest`
is what a helper calls first: the request grammar, then `CheckPrivilegedRoot`, which
refuses — before anything is written — a root that is a network path or on anything
but a fixed local disk (a SUBST drive included); any path component that is a
reparse point; an owner other than SYSTEM, Administrators or TrustedInstaller on the
root, its ancestors, or what a helper writes in an existing root; an ancestor that
grants anyone else delete, `FILE_DELETE_CHILD`, `WRITE_DAC` or `WRITE_OWNER`; and a
root (or the directory it will be created in) that grants anyone else a right to
create, delete or re-permission — including rights they would only inherit. Callers
run the same check before the prompt. POSIX judges owner and mode bits the same way;
POSIX ACLs are not read.

A group other than those three — a domain group of operators — is refused too; the
check cannot tell a trusted group from another. Contents of version directories below
their top level are not examined: the helper never writes into an existing one and
verifies every byte it reuses.
