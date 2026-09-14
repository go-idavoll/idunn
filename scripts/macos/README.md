# macOS: bundle, sign, notarize and verify the privileged helper

These scripts take a helper built from `cmd/helper` (the contract is
[`docs/helper.md`](../../docs/helper.md)) and turn it into something macOS will run
as root: a LaunchDaemon inside the publisher's signed, notarized application
bundle, registered through `SMAppService` (design §14.2, IDN-08).

They run on macOS only, need the Xcode command line tools (`codesign`,
`xcrun notarytool`, `xcrun stapler`, `plutil`, `ditto`, `spctl`), and are written
for the bash 3.2 macOS ships. Every script takes `--help`.

**Minimum macOS: 13 (Ventura).** `SMAppService` does not exist before 13; this is
a maintainer decision, not a limitation of the scripts. Set
`LSMinimumSystemVersion` to `13.0` in the application's `Info.plist` so an older
system refuses to launch the app instead of failing at registration.

Nothing here reads an identity or a credential from the tree. The signing identity
is an argument or `IDUNN_SIGN_IDENTITY`, its private key stays in the keychain, and
notarization credentials exist only as a `notarytool` keychain profile.

## The flow

```sh
# 1. Build the helper with the publisher's compiled-in anchor (docs/helper.md §5).
cp ceremony/1.root.json    cmd/helper/anchor/root.json
cp release/repository.json cmd/helper/anchor/
cp release/helper.json     cmd/helper/anchor/           # label com.acme.app.helper
go build -trimpath -ldflags "-X main.version=1.3.0" -o dist/com.acme.app.helper ./cmd/helper

# 2. Put the helper and its LaunchDaemon plist into the app bundle.
scripts/macos/bundle-helper.sh --app dist/Acme.app \
  --helper dist/com.acme.app.helper --label com.acme.app.helper

# 3. Sign inside out: nested code, the helper (identifier = label), the bundle.
scripts/macos/sign.sh --app dist/Acme.app \
  --identity "Developer ID Application: Acme Inc (TEAMID1234)"

# 4. Notarize and staple.
scripts/macos/notarize.sh --app dist/Acme.app --keychain-profile acme-notary

# 5. Verify what will ship, including that the helper admits this app.
scripts/macos/verify.sh --app dist/Acme.app --label com.acme.app.helper \
  --requirement 'anchor apple generic and identifier "com.acme.app" and certificate leaf[subject.OU] = "TEAMID1234"'

# 6. Ship dist/Acme.app (in a DMG or zip, or as the content of an idunn release).
```

| Script | Does | Refuses |
|---|---|---|
| `bundle-helper.sh --app A --helper H --label L [--force]` | copies `H` to `Contents/Library/HelperTools/L` (0755); writes `Contents/Library/LaunchDaemons/L.plist` from `H plist` | a label outside docs/helper.md §2 (reverse-DNS, `[A-Za-z0-9.-]`, ≤ 62 bytes); a plist that does not lint, has any key `elevate.DaemonPlist` does not write, a `Label`/`BundleProgram`/`ProgramArguments[0]` not naming this helper, or `AssociatedBundleIdentifiers` without the app's `CFBundleIdentifier`; symlinks on the way; a second helper; a signed bundle without `--force` |
| `sign.sh --app A --identity I [--entitlements-helper F] [--entitlements-app F]` | `codesign --force --options runtime --timestamp` on nested code, then the helper with `--identifier L`, then the bundle; never `--deep` (see the script for why) | an empty identity; anything but `Developer ID Application: …` or a SHA-1; `-` without `--adhoc-for-ci`; helper entitlements that weaken a root process (`get-task-allow`, `cs.allow-dyld-environment-variables`, `cs.disable-library-validation`, JIT/unsigned memory, `cs.debugger`); an inconsistent bundle |
| `notarize.sh --app A --keychain-profile P` | `ditto -c -k --keepParent`, `notarytool submit --wait`, prints the log on anything but `Accepted`, `stapler staple` and `validate` | Apple ID, password, team ID or API key on the command line; an ad-hoc or broken signature |
| `verify.sh --app A --label L [--requirement R] [--adhoc]` | bundle consistency as above; `codesign --verify --strict --deep` on the app; `--strict` on the helper; helper identifier = label; hardened runtime and equal Team ID; `-R=R` on the app and its main executable; `spctl --assess --type execute`; `stapler validate`; runs `L version` and `L check` | — (every check is fatal except `L check`, which is informational: it needs `/Library/Application Support/<label>/` and `callers.json`, which a build machine does not have) |

`--adhoc-for-ci` / `--adhoc` exist so CI can run the whole flow without a
certificate. An ad-hoc bundle has no Team ID and no timestamp, cannot be
notarized, and Gatekeeper refuses it. It is never shippable.

### Why `--requirement` matters

The helper compiles `peer_requirement` from `helper.json` in and refuses any
caller whose code signature does not satisfy it. A requirement with a typo, the
wrong Team ID or the wrong bundle identifier builds and signs fine and then
refuses the real application at runtime. `verify.sh --requirement` checks the
same string against the bundle that will call, before it ships.

## Keychain and notarytool setup (once per machine)

1. **Developer ID Application certificate.** Create it in the Apple Developer
   account (Certificates → Developer ID Application) and import it with its
   private key into the login keychain. Check:
   `security find-identity -v -p codesigning` lists
   `Developer ID Application: <Name> (<TEAMID>)`. `sign.sh` refuses an identity
   that is not in that list.
2. **Notarization credentials** as a keychain profile, with either an
   app-specific password (the password is prompted for, never typed as an
   argument):

   ```sh
   xcrun notarytool store-credentials acme-notary --apple-id dev@acme.example --team-id TEAMID1234
   ```

   or an App Store Connect API key (preferred for CI; team key with the
   Developer role):

   ```sh
   xcrun notarytool store-credentials acme-notary --key AuthKey_ABC123.p8 --key-id ABC123 --issuer <issuer-uuid>
   ```

   Delete the `.p8` afterwards; the profile keeps what notarytool needs.
3. **On a CI runner**, create a temporary keychain for the job
   (`security create-keychain`, `security import … -T /usr/bin/codesign`,
   `security set-key-partition-list -S apple-tool:,apple:`, add it to the search
   list), store the notary profile into it with
   `notarytool store-credentials --keychain <that keychain>`, and delete the
   keychain at the end of the job. The certificate, its password and the API key
   come from the CI secret store — never from this repository (AGENTS.md §5).
   Signing and notarizing belong in a release job with a protected environment,
   not in a pull-request job.

## What the application must do at runtime

The helper does nothing until the application registers it and the user approves
it. From the application bundle (a bare executable has no bundle for
`SMAppService` to look in), in a cgo build on macOS 13+:

```go
const plist = "com.acme.app.helper.plist" // <label>.plist

state, err := elevate.DaemonStatus(plist)
if err != nil {
	return err // fail closed: an unknown state is not "enabled"
}
switch state {
case elevate.DaemonNotRegistered:
	if err := elevate.RegisterDaemon(plist); err != nil {
		return err
	}
	if state, err = elevate.DaemonStatus(plist); err != nil {
		return err
	}
case elevate.DaemonNotFound:
	// The bundle carries no such plist, or this process is not that bundle.
	return errors.New("helper plist not found in this bundle")
}
if state == elevate.DaemonRequiresApproval {
	// Explain what the helper is for, then take the user to
	// System Settings → General → Login Items & Extensions.
	_ = elevate.OpenLoginItemsSettings()
}
```

Registration is not approval. Until the user switches the item on under
**System Settings → General → Login Items** ("Allow in the Background"), the
daemon is `DaemonRequiresApproval` and launchd does not run it. Nothing may click
that switch for the user.

After approval an administrator admits the local accounts that may ask the
helper for updates (docs/helper.md §2):

```sh
sudo "/Applications/Acme.app/Contents/Library/HelperTools/com.acme.app.helper" allow --uid 501
```

The application then connects to `elevate.DefaultHelperEndpoint(label)`.

## Updating the helper itself

The helper lives inside the application bundle, so a new helper arrives with a new
application version. What is certain:

- The new bundle must be signed and notarized again as a whole (steps 2–5). A
  changed helper inside an old signature is a broken bundle, and launchd will not
  run it.
- **Keep the label, the bundle identifier and the Team ID.** Background Task
  Management attributes the approval to the app's identity; a different Team ID
  or bundle identifier is a different item and needs approval again. A different
  label is a different daemon: unregister the old one first, or it stays behind.
- The plist is generated by the helper build. If a new version changes it
  (arguments, keys), the registration must be refreshed — see below.
- The running daemon keeps running the old code until launchd starts it again.
  `KeepAlive` is `{SuccessfulExit: false}`: a helper that exits non-zero is
  restarted, one that exits 0 stays stopped until the next boot or registration.

What is **not verified** here and needs confirmation on a real macOS 13, 14 and
15 system before a release depends on it:

- *Does launchd pick up a replaced `BundleProgram` binary on its next spawn
  without re-registration?* It resolves the path inside the registered bundle at
  spawn time, so it is expected to; not tested.
- *Does `SMAppService` re-read a changed plist on its own* (for example when
  `CFBundleVersion` changes), or only after `unregister` + `register`? Reports
  differ between macOS versions. The conservative procedure is: after an update,
  the application compares the helper's version (over IPC, or `helper version`)
  with the one it expects; on a mismatch it calls `UnregisterDaemon` and then
  `RegisterDaemon`, and checks `DaemonStatus` again, handling
  `DaemonRequiresApproval` as on first install.
- *Does unregister + register of the same label, bundle identifier and Team ID
  keep the user's approval?* Expected yes; not verified.
- *Who restarts the helper after it applied an update to its own bundle?* A
  helper that replaces the bundle it runs from and then exits cleanly is not
  restarted by `KeepAlive`. Either the application re-registers as above, or the
  helper must exit non-zero to be restarted — a decision for `cmd/helper`, open.
- *Bumping `CFBundleVersion`* on every release is required anyway for a sane
  update story and costs nothing; do it.

## CI

`.github/workflows/helper-macos.yml` runs on changes to `cmd/helper/**`,
`scripts/macos/**` and `core/elevate/**`. It builds `cmd/helper` with a throwaway
anchor generated in the job (the keys are deleted immediately; only `1.root.json`
is used), creates a minimal `.app`, and runs `bundle-helper.sh`,
`sign.sh --identity - --adhoc-for-ci` and `verify.sh --adhoc --requirement …`, plus
negative cases: a bad label, an ad-hoc identity without the CI flag, re-bundling a
signed app without `--force`, a wrong requirement, a tampered helper and a plist
with an extra key must all be refused. A separate job runs `shellcheck`.

It proves the scripts agree with each other, with `helper plist`, and with
`codesign`'s view of the result. It cannot prove anything about a Developer ID
signature, notarization, Gatekeeper, stapling, `SMAppService` registration or
user approval: those need a certificate, Apple's service and a person.
