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

package packer

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigAcceptsTheDesignExample(t *testing.T) {
	// The example from docs/design.md §9, verbatim in shape.
	cfg, err := LoadConfig(writeConfigFile(t, `name: acme-app
version: 1.3.0
channel: stable
requirements:
  min_from_version: 1.0.0
  min_client_version: 1.2.0
rollout: 0.1
targets:
  - os: windows
    arch: amd64
    files:
      - { src: build/win-amd64/app.exe,    dst: app.exe,        kind: exe }
      - { src: build/win-amd64/plugin.dll, dst: lib/plugin.dll, kind: lib }
  - os: linux
    arch: amd64
    files:
      - { src: build/linux-amd64/app,    dst: app,          kind: exe }
      - { src: build/linux-amd64/libx.so, dst: lib/libx.so, kind: lib }
`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Name != "acme-app" || cfg.Version != "1.3.0" || cfg.Rollout != 0.1 {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(cfg.Targets) != 2 {
		t.Fatalf("%d platforms", len(cfg.Targets))
	}
	if got, err := cfg.Targets[0].Files[0].mode(); err != nil || got != 0o755 {
		t.Errorf("exe mode = %#o (%v), want 0755", got, err)
	}
	if got, err := cfg.Targets[0].Files[1].mode(); err != nil || got != 0o644 {
		t.Errorf("lib mode = %#o (%v), want 0644", got, err)
	}
}

// Every rejection here is a defect that would otherwise be published and then
// fail on every client instead of at publish time.
func TestLoadConfigRejects(t *testing.T) {
	const good = `name: demo
version: 1.2.0
channel: stable
targets:
  - os: linux
    arch: amd64
    files:
      - { src: app, dst: bin/app, kind: exe }
`
	tests := []struct {
		name string
		body string
		want string
	}{
		{"unknown key", strings.Replace(good, "channel: stable", "channels: stable", 1), "field channels"},
		{"unknown nested key", strings.Replace(good, "kind: exe", "kind: exe, sudo: true", 1), "field sudo"},
		{"no name", strings.Replace(good, "name: demo\n", "", 1), "name \"\""},
		{"not semver", strings.Replace(good, "1.2.0", "1.2", 1), "not SemVer"},
		{"leading zero major", strings.Replace(good, "1.2.0", "01.2.0", 1), "leading zero"},
		{"leading zero patch", strings.Replace(good, "1.2.0", "1.2.03", 1), "leading zero"},
		{"bad requirement", good + "requirements:\n  min_from_version: latest\n", "not SemVer"},
		{"empty channel", strings.Replace(good, "channel: stable", `channel: ""`, 1), "channel \"\""},
		{"glob channel", strings.Replace(good, "channel: stable", `channel: "*"`, 1), "channel \"*\""},
		{"channel with slash", strings.Replace(good, "channel: stable", "channel: a/b", 1), "channel \"a/b\""},
		{"release-line channel", strings.Replace(good, "channel: stable", "channel: v1", 1), "collides"},
		{"rollout above one", good + "rollout: 1.5\n", "outside [0,1]"},
		{"no targets", "name: demo\nversion: 1.2.0\nchannel: stable\ntargets: []\n", "no targets"},
		{"no files", strings.Replace(good, "    files:\n      - { src: app, dst: bin/app, kind: exe }\n", "    files: []\n", 1), "no files"},
		{"bad os", strings.Replace(good, "os: linux", "os: Linux", 1), "os \"Linux\""},
		{"bad arch", strings.Replace(good, "arch: amd64", "arch: x86_64!", 1), "arch"},
		{"empty src", strings.Replace(good, "src: app", `src: ""`, 1), "empty src"},
		{"traversal dst", strings.Replace(good, "dst: bin/app", "dst: ../../etc/passwd", 1), "escapes the install root"},
		{"absolute dst", strings.Replace(good, "dst: bin/app", "dst: /etc/passwd", 1), "absolute"},
		{"windows device dst", strings.Replace(good, "dst: bin/app", "dst: NUL", 1), "reserved device name"},
		{"unclean dst", strings.Replace(good, "dst: bin/app", "dst: bin//app", 1), "not in clean form"},
		{"unknown kind", strings.Replace(good, "kind: exe", "kind: script", 1), "kind \"script\""},
		{"setuid mode", strings.Replace(good, "kind: exe", `kind: exe, mode: "4755"`, 1), "outside 0777"},
		{"non-octal mode", strings.Replace(good, "kind: exe", `kind: exe, mode: "999"`, 1), "octal digits"},
		{
			name: "duplicate dst",
			body: strings.Replace(good, "      - { src: app, dst: bin/app, kind: exe }\n",
				"      - { src: app, dst: bin/app, kind: exe }\n      - { src: app2, dst: bin/app, kind: data }\n", 1),
			want: "duplicate dst",
		},
		{
			name: "duplicate platform",
			body: good + "  - os: linux\n    arch: amd64\n    files:\n      - { src: app, dst: x, kind: data }\n",
			want: "duplicate platform",
		},
		{
			name: "two documents",
			body: good + "---\nname: other\n",
			want: "more than one YAML document",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadConfig(writeConfigFile(t, tt.body))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("err = %v, want ErrConfig", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "absent.yaml"))
	if !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}

func TestLoadConfigTooLarge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pack.yaml")
	if err := os.WriteFile(path, make([]byte, MaxConfigLen+1), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(path)
	if !errors.Is(err, ErrConfig) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
}

// Build metadata may carry leading zeros; the version core may not.
func TestLeadingZerosOnlyMatterInTheVersionCore(t *testing.T) {
	body := `name: demo
version: 1.2.0+build.007
channel: stable
targets:
  - os: linux
    arch: amd64
    files:
      - { src: app, dst: bin/app, kind: exe }
`
	if _, err := LoadConfig(writeConfigFile(t, body)); err != nil {
		t.Fatalf("build metadata with a leading zero was refused: %v", err)
	}
}

// An explicit mode overrides the default for the kind, within the bounds the
// client accepts.
func TestExplicitMode(t *testing.T) {
	cfg, err := LoadConfig(writeConfigFile(t, `name: demo
version: 1.2.0
channel: stable
targets:
  - os: linux
    arch: amd64
    files:
      - { src: app, dst: bin/app, kind: exe, mode: "0700" }
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.Targets[0].Files[0].mode()
	if err != nil || got != 0o700 {
		t.Fatalf("mode = %#o (%v), want 0700", got, err)
	}
}

// Every kind the descriptor accepts has a default mode; a missing entry would
// silently install files with mode 0.
func TestEveryKindHasADefaultMode(t *testing.T) {
	for _, kind := range []release.FileKind{release.KindExe, release.KindLib, release.KindData} {
		if defaultModes[kind] == 0 {
			t.Errorf("kind %q has no default mode", kind)
		}
	}
}

// src is resolved against pack.yaml, not the working directory.
func TestSrcPathResolution(t *testing.T) {
	cfg := &Config{dir: filepath.Join("build", "release")}
	got := cfg.srcPath(&File{Src: "win-amd64/app.exe"})
	if want := filepath.Join("build", "release", "win-amd64", "app.exe"); got != want {
		t.Errorf("srcPath = %q, want %q", got, want)
	}
	abs := filepath.Join(string(filepath.Separator), "tmp", "app")
	if got := cfg.srcPath(&File{Src: abs}); got != abs {
		t.Errorf("srcPath(%q) = %q", abs, got)
	}
}
