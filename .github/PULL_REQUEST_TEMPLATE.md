<!-- CONTRIBUTING.md: describe the security impact explicitly, even if it is "none". -->

## What & why

<!-- What changes, and why. Reference the issue you are addressing. -->

Closes #

## Security impact

<!-- Required. "None" is a valid answer — saying it tells reviewers you considered it. -->

- Threat(s) affected (docs/design.md §11, T1–T23):
- Negative test proving the prevented attack still fails:
- Touches trust / verification / path handling / elevation / journal? yes / no
  <!-- If yes: human maintainer sign-off is required and this does not auto-merge. -->

## Checklist

- [ ] Fail closed: no new "best effort" path in trust or apply.
- [ ] No parallel trust path; verification stays inside go-tuf.
- [ ] No mechanism that fetches and executes remote code.
- [ ] No secrets, keys, or key access added.
- [ ] No check weakened, skipped, or fast-pathed to make CI pass.
- [ ] Tests added; security-relevant changes ship a negative test.
- [ ] New attacks landed as permanent cases in `test/redteam/corpus/`.
- [ ] `go test ./...`, `make redteam`, `gofmt`, and `go vet` are green locally.
- [ ] New third-party dependency in `core` justified above (every dep is attack surface).
