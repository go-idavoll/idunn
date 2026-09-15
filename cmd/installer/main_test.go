// Copyright 2026 The idunn Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/installer"
)

// The command line is the contract with whatever runs this — a shell script, an
// MDM, a CI job — so every refusal has to land on the code that describes it.
func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitUsage},
		{"help", []string{"help"}, exitOK},
		{"long help", []string{"--help"}, exitOK},
		{"unknown verb", []string{"uninstall"}, exitUsage},
		{"no root", []string{"install"}, exitUsage},
		{"unknown flag", []string{"install", "--root", "x", "--force"}, exitUsage},
		{"stray argument", []string{"install", "--root", "x", "extra"}, exitUsage},
		{"version is not semver", []string{"install", "--root", "x", "--version", "latest"}, exitUsage},
		{"missing anchor file", []string{"install", "--root", "x", "--root-metadata", "does-not-exist.json"}, exitUsage},
		{"root and scope", []string{"install", "--root", "x", "--scope", "user"}, exitUsage},
		{"unknown scope", []string{"install", "--scope", "system"}, exitUsage},
		{"empty scope", []string{"install", "--scope", ""}, exitUsage},
		{"scope without an application", []string{"install", "--scope", "machine"}, exitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.want {
				t.Errorf("run(%v) = %d, want %d\n%s%s", tt.args, got, tt.want, &stdout, &stderr)
			}
		})
	}
}

// A build with no embedded anchor cannot install anything: it has no trust
// decision to make with. It says so instead of resolving one from a flag it was
// not given.
func TestInstallWithoutAnyAnchorIsRefused(t *testing.T) {
	var out bytes.Buffer
	code := run([]string{"install", "--root", filepath.Join(t.TempDir(), "app")}, &out, &out)
	if code != exitUsage {
		t.Fatalf("run = %d, want %d\n%s", code, exitUsage, &out)
	}
	if !strings.Contains(out.String(), "--root-metadata") {
		t.Errorf("the error does not name the flag that would fix it: %q", out.String())
	}
}

// The privileged verb takes exactly three scalars. Everything else it needs it
// takes from what it was built with — a caller-supplied URL or anchor would move
// the trust decision to the unprivileged side that asked for the elevation
// (docs/design.md §14.2, T16).
func TestApplyAcceptsOnlyTheRequestGrammar(t *testing.T) {
	rejected := [][]string{
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--metadata-url", "https://evil/"},
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--targets-url", "https://evil/"},
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--root-metadata", "/tmp/root.json"},
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--cache", "/tmp/cache"},
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--allow-downgrade"},
		{"apply", "--root", "/opt/app", "--channel", "stable", "--version", "1.2.0", "--scope", "machine"},
	}
	for _, args := range rejected {
		t.Run(args[len(args)-1], func(t *testing.T) {
			var out bytes.Buffer
			if code := run(args, &out, &out); code != exitUsage {
				t.Fatalf("run(%v) = %d, want %d\n%s", args, code, exitUsage, &out)
			}
		})
	}
}

// Each of the three is required: the helper is answering a specific request, not
// guessing at one.
func TestApplyRequiresAllThreeScalars(t *testing.T) {
	incomplete := [][]string{
		{"apply"},
		{"apply", "--root", "/opt/app"},
		{"apply", "--root", "/opt/app", "--channel", "stable"},
		{"apply", "--channel", "stable", "--version", "1.2.0"},
	}
	for i, args := range incomplete {
		var out bytes.Buffer
		if code := run(args, &out, &out); code != exitUsage {
			t.Errorf("case %d: run(%v) = %d, want %d\n%s", i, args, code, exitUsage, &out)
		}
	}
}

// The helper validates what it receives by the grammar the sender enforces. A
// relative root would otherwise be resolved against whatever working directory
// the elevated process got, and a channel or version outside the grammar is not
// a request, whoever sent it. Refused as usage before the anchor is even looked
// at — the build under test embeds none, which would be exitError.
func TestApplyRefusesAMalformedRequest(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "app")
	malformed := [][]string{
		{"apply", "--root", "app", "--channel", "stable", "--version", "1.2.0"},
		{"apply", "--root", abs + string(filepath.Separator) + ".." + string(filepath.Separator) + "x", "--channel", "stable", "--version", "1.2.0"},
		{"apply", "--root", abs, "--channel", "stable&calc", "--version", "1.2.0"},
		{"apply", "--root", abs, "--channel", "stable", "--version", "1.2"},
	}
	for i, args := range malformed {
		var out bytes.Buffer
		if code := run(args, &out, &out); code != exitUsage {
			t.Errorf("case %d: run(%v) = %d, want %d\n%s", i, args, code, exitUsage, &out)
		}
	}
}

// adminOnlyRoot is a root that does not exist, in a directory only administrators
// control on a stock system, so the helper's root check lets it through to
// whatever the test is about.
func adminOnlyRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		pf := os.Getenv("ProgramFiles")
		if pf == "" {
			t.Skip("no %ProgramFiles%")
		}
		return filepath.Join(pf, "idunn-test-does-not-exist", "app")
	}
	return "/idunn-test-does-not-exist/app"
}

// A build that embeds nothing cannot serve as its own privileged helper, and
// says so rather than starting an elevated process that would fail after the
// prompt.
func TestApplyNeedsAnEmbeddedAnchor(t *testing.T) {
	var out bytes.Buffer
	args := []string{"apply", "--root", adminOnlyRoot(t), "--channel", "stable", "--version", "1.2.0"}
	if code := run(args, &out, &out); code != exitError {
		t.Fatalf("run = %d, want %d\n%s", code, exitError, &out)
	}
	if !strings.Contains(out.String(), "embeds") {
		t.Errorf("err = %q", out.String())
	}
}

// The usage text has to name the exit codes: they are the only thing a script
// can branch on, and a refusal that reads as a failure defeats the reason they
// are distinct.
func TestUsageDocumentsExitCodes(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, want := range []string{"refused", "declined", "privileges", "--root-metadata", "apply"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage does not mention %q", want)
		}
	}
}

// The install root is resolved to an absolute path before anything else looks at
// it: an install must not depend on the working directory of whatever launched
// it, and the path is handed to an elevated helper further down.
func TestRootIsMadeAbsolute(t *testing.T) {
	var errOut bytes.Buffer
	cfg, code := buildConfig(config{
		root:           "relative/app",
		anchorFromFlag: []byte("{}"),
		metadataURL:    "https://updates.example.com/metadata/",
	}, nil, &errOut)
	if code != exitOK {
		t.Fatalf("buildConfig = %d: %s", code, &errOut)
	}
	if !filepath.IsAbs(cfg.root) {
		t.Errorf("root = %q, want an absolute path", cfg.root)
	}
}

// The helper refuses a root that someone other than an administrator controls,
// before it reads its anchor or touches anything (IDN-22). A user who can start
// the helper elevated — or talk an administrator into accepting the prompt —
// must not get a privileged write into a directory they can redirect.
func TestApplyRefusesARootAUserControls(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("as root, a temporary directory is root-owned")
	}
	var out bytes.Buffer
	args := []string{"apply", "--root", filepath.Join(t.TempDir(), "app"), "--channel", "stable", "--version", "1.2.0"}
	if code := run(args, &out, &out); code != exitUnsafeRoot {
		t.Fatalf("run = %d, want %d\n%s", code, exitUnsafeRoot, &out)
	}
	if !strings.Contains(out.String(), "administrators-only") {
		t.Errorf("err = %q", out.String())
	}
}

// withApp sets the build-time application identity for one test.
func withApp(t *testing.T, name, id string) {
	t.Helper()
	oldName, oldID := appName, bundleID
	appName, bundleID = name, id
	t.Cleanup(func() { appName, bundleID = oldName, oldID })
}

// Without --root, a build that names its application installs where the
// platform puts it: the user's location by default, the machine's on request
// (IDN-24). The derivation itself is core/installer's and tested there; this is
// the wiring.
func TestRootDefaultsToTheScope(t *testing.T) {
	withApp(t, "Acme Editor", "com.acme.editor")
	tests := []struct {
		name     string
		scope    string
		scopeSet bool
		want     installer.Scope
	}{
		{"no scope", "", false, installer.ScopeUser},
		{"user", "user", true, installer.ScopeUser},
		{"machine", "machine", true, installer.ScopeMachine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := installer.DefaultRoot(tt.want, installer.App{Name: appName, BundleID: bundleID})
			if err != nil {
				t.Fatalf("DefaultRoot: %v", err)
			}
			var errOut bytes.Buffer
			got, code := resolveRoot("", tt.scope, tt.scopeSet, &errOut)
			if code != exitOK || got != want {
				t.Errorf("resolveRoot = %q, %d; want %q, %d\n%s", got, code, want, exitOK, &errOut)
			}
		})
	}
}

// --root wins over the build's identity, and does so without deriving anything.
func TestExplicitRootIsTakenAsGiven(t *testing.T) {
	withApp(t, "../bad", "")
	var errOut bytes.Buffer
	if got, code := resolveRoot("some/dir", "", false, &errOut); code != exitOK || got != "some/dir" {
		t.Errorf("resolveRoot = %q, %d\n%s", got, code, &errOut)
	}
}

// --root and --scope say two things about where the install goes, and which one
// wins decides whether it is elevated. Neither does: the command line is refused,
// even when the two happen to agree.
func TestRootAndScopeAreMutuallyExclusive(t *testing.T) {
	withApp(t, "Acme Editor", "com.acme.editor")
	user, err := installer.DefaultRoot(installer.ScopeUser, installer.App{Name: appName, BundleID: bundleID})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"user", "machine", ""} {
		var errOut bytes.Buffer
		if got, code := resolveRoot(user, scope, true, &errOut); code != exitUsage {
			t.Errorf("--root %q --scope %q: resolveRoot = %q, %d; want %d", user, scope, got, code, exitUsage)
		}
		if !strings.Contains(errOut.String(), "mutually exclusive") {
			t.Errorf("err = %q", errOut.String())
		}
	}
}

// An identity the build carries but no root can be derived from is the build's
// defect, not the operator's typo, and is reported as a failure — with --root as
// the way out.
func TestUnusableBuildIdentityIsAnError(t *testing.T) {
	withApp(t, "../etc", "not reverse dns")
	var errOut bytes.Buffer
	if got, code := resolveRoot("", "", false, &errOut); code != exitError {
		t.Fatalf("resolveRoot = %q, %d; want %d\n%s", got, code, exitError, &errOut)
	}
	if !strings.Contains(errOut.String(), "--root") {
		t.Errorf("the error does not name the flag that would fix it: %q", errOut.String())
	}
}

// A build without an identity keeps today's contract: --root is required, and
// the error says why.
func TestNoIdentityRequiresRoot(t *testing.T) {
	withApp(t, "", "")
	var errOut bytes.Buffer
	if _, code := resolveRoot("", "", false, &errOut); code != exitUsage {
		t.Fatalf("resolveRoot = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "--root is required") {
		t.Errorf("err = %q", errOut.String())
	}
}

// End to end through the command line: a derived root gets as far as the trust
// anchor, which this tree does not embed — past the point where a missing --root
// would have stopped it, and before anything is written.
func TestInstallWithoutRootReachesTheAnchor(t *testing.T) {
	withApp(t, "Acme Editor", "com.acme.editor")
	var out bytes.Buffer
	if code := run([]string{"install"}, &out, &out); code != exitUsage {
		t.Fatalf("run = %d, want %d\n%s", code, exitUsage, &out)
	}
	if !strings.Contains(out.String(), "--root-metadata") {
		t.Errorf("did not reach the anchor: %q", out.String())
	}
}
