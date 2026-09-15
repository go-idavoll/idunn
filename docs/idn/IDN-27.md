# IDN-27 — macOS: Apple code signing as a gate before the swap (§13, §14.2)

**Priority:** P1 — blocks a trustworthy release

TUF decides what is authentic; this is the platform's own check that the result will
run, as an additional refusal that can never accept something TUF refused.

Decided: AGENTS.md §1.2 carries an explicit carve-out for it. It answers a different
question — not "are these the publisher's bytes" but "will macOS launch them" — which
a release signed in TUF but broken for Gatekeeper (a missing notarization, a nested
binary signed with the wrong identity) otherwise fails only after the swap. It runs
after TUF accepted every byte and can only narrow the funnel, never widen it.

`SecStaticCodeCheckValidity` on the staged bundle with
`kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode` against
a requirement built into the binary — `anchor apple generic and certificate
leaf[subject.OU] = "<TEAMID>" and identifier "<bid>"` — not against the installed
bundle's designated requirement as Sparkle does, so a tampered installed bundle
cannot lower the bar.

Open: how to reach Security.framework. The calls needed are plain C with pointer and
integer arguments — `CFURLCreateFromFileSystemRepresentation`,
`SecStaticCodeCreateWithPath`, `SecRequirementCreateWithString`,
`SecStaticCodeCheckValidityWithErrors`, `CFErrorCopyDescription`, `CFRelease`; no
structs by value, no callbacks, no variadics.
- `/usr/bin/codesign --verify --strict --deep -R=<req> <bundle>`: no dependency, no
  cgo; the verdict is the exit status, so no output is parsed. Absolute path (SIP
  protects it), empty environment. Costs one process per apply. **Unverified:**
  whether `/usr/bin/codesign` exists on a macOS without the Command Line Tools —
  sources disagree; signing needs `codesign_allocate` from the CLT, verifying may
  not. Check on a clean install before choosing this; if it is absent, only the
  framework routes remain.
- Pure-Go FFI without cgo — `github.com/go-webgpu/goffi` (MIT, v0.6.x) or
  `github.com/ebitengine/purego` (Apache-2.0, beta, Tier 1 on darwin, more
  deployments). Both replace the cgo runtime with a fake one under
  `CGO_ENABLED=0`, which changes process startup for the whole binary — including
  the helper that runs as root — and is a new `core` dependency (AGENTS.md §3).
  goffi's advantages (zero-alloc calls, full struct ABI) buy nothing for six calls
  per apply.
- cgo: exact and dependency-free, but ends cross-compiling darwin from another OS.

Leaning: `codesign` first; FFI only if the process spawn proves a problem. A build
without a Team ID follows the proposal in IDN-31: no requirement compiled in, no gate.
On Apple Silicon the linker's ad-hoc signature is still needed for anything to run;
that is the build's concern, not the gate's.
