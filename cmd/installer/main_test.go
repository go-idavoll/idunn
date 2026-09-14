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
