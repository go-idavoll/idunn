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

package installer

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeDirs is a machine whose answers the test chooses. Every call is counted so
// a test can tell a fixed machine root from one that asked the environment.
type fakeDirs struct {
	homeDir, userPF, pf string
	env                 map[string]string
	homeErr, pfErr      error
	calls               []string
}

func (f *fakeDirs) home() (string, error) {
	f.calls = append(f.calls, "home")
	return f.homeDir, f.homeErr
}

func (f *fakeDirs) getenv(k string) string {
	f.calls = append(f.calls, "env:"+k)
	return f.env[k]
}

func (f *fakeDirs) userProgramFiles() (string, error) {
	f.calls = append(f.calls, "userProgramFiles")
	return f.userPF, f.pfErr
}

func (f *fakeDirs) programFiles() (string, error) {
	f.calls = append(f.calls, "programFiles")
	return f.pf, f.pfErr
}

func machine() *fakeDirs {
	return &fakeDirs{
		homeDir: "/home/alice",
		userPF:  `C:\Users\alice\AppData\Local\Programs`,
		pf:      `C:\Program Files`,
		env:     map[string]string{},
	}
}

var acme = App{Name: "Acme Editor", BundleID: "com.acme.editor"}

// The table IDN-24 asks for, row by row.
func TestDefaultRootFollowsThePlatformConventions(t *testing.T) {
	tests := []struct {
		goos  string
		scope Scope
		env   map[string]string
		want  string
	}{
		{"windows", ScopeUser, nil, `C:\Users\alice\AppData\Local\Programs\Acme Editor`},
		{"windows", ScopeMachine, nil, `C:\Program Files\Acme Editor`},
		{"linux", ScopeUser, nil, "/home/alice/.local/share/Acme Editor"},
		{"linux", ScopeUser, map[string]string{"XDG_DATA_HOME": "/data/alice/"}, "/data/alice/Acme Editor"},
		{"linux", ScopeMachine, nil, "/opt/Acme Editor"},
		{"darwin", ScopeUser, nil, "/home/alice/Library/Application Support/com.acme.editor"},
		{"darwin", ScopeMachine, nil, "/Library/Application Support/com.acme.editor"},
	}
	for _, tt := range tests {
		t.Run(tt.goos+"/"+tt.scope.String(), func(t *testing.T) {
			d := machine()
			for k, v := range tt.env {
				d.env[k] = v
			}
			got, err := defaultRoot(tt.goos, tt.scope, acme, d)
			if err != nil {
				t.Fatalf("defaultRoot: %v", err)
			}
			if got != tt.want {
				t.Errorf("defaultRoot = %q, want %q", got, tt.want)
			}
		})
	}
}

// A machine root is what the elevated helper is asked to write, so nothing the
// calling process's environment says may move it: no $HOME, no $XDG_*, no
// %ProgramFiles%. On Windows it comes from the shell's known folder; elsewhere it
// is a constant.
func TestMachineRootIgnoresTheEnvironment(t *testing.T) {
	for _, goos := range []string{"windows", "linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			d := machine()
			d.homeDir = "/tmp/attacker"
			d.env = map[string]string{"XDG_DATA_HOME": "/tmp/attacker", "ProgramFiles": `C:\Users\Public`}
			if _, err := defaultRoot(goos, ScopeMachine, acme, d); err != nil {
				t.Fatalf("defaultRoot: %v", err)
			}
			for _, c := range d.calls {
				if c != "programFiles" {
					t.Errorf("the machine root consulted %s", c)
				}
			}
		})
	}
}

// The spec says a relative $XDG_DATA_HOME is invalid and must be ignored; using
// it would put the root below whatever the working directory is.
func TestRelativeXDGDataHomeIsIgnored(t *testing.T) {
	for _, xdg := range []string{"", "data", "./share", "~/share"} {
		d := machine()
		d.env["XDG_DATA_HOME"] = xdg
		got, err := defaultRoot("linux", ScopeUser, acme, d)
		if err != nil {
			t.Fatalf("XDG_DATA_HOME=%q: %v", xdg, err)
		}
		if want := "/home/alice/.local/share/Acme Editor"; got != want {
			t.Errorf("XDG_DATA_HOME=%q: defaultRoot = %q, want %q", xdg, got, want)
		}
	}
}

// A base that is not absolute would make the root relative, and a relative root
// resolves against a working directory nobody chose.
func TestRelativeBaseIsRefused(t *testing.T) {
	tests := []struct {
		goos  string
		scope Scope
		set   func(*fakeDirs)
	}{
		{"linux", ScopeUser, func(d *fakeDirs) { d.homeDir = "alice" }},
		{"darwin", ScopeUser, func(d *fakeDirs) { d.homeDir = "" }},
		{"windows", ScopeUser, func(d *fakeDirs) { d.userPF = `Programs` }},
		{"windows", ScopeUser, func(d *fakeDirs) { d.userPF = `\Programs` }},
		{"windows", ScopeMachine, func(d *fakeDirs) { d.pf = `C:Program Files` }},
		{"windows", ScopeMachine, func(d *fakeDirs) { d.pf = `\\server\share` }},
	}
	for i, tt := range tests {
		d := machine()
		tt.set(d)
		if got, err := defaultRoot(tt.goos, tt.scope, acme, d); !errors.Is(err, ErrApp) {
			t.Errorf("case %d (%s): defaultRoot = %q, %v; want ErrApp", i, tt.goos, got, err)
		}
	}
}

func TestPlatformLookupFailuresAreReported(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		goos  string
		scope Scope
		set   func(*fakeDirs)
	}{
		{"windows", ScopeUser, func(d *fakeDirs) { d.pfErr = boom }},
		{"windows", ScopeMachine, func(d *fakeDirs) { d.pfErr = boom }},
		{"linux", ScopeUser, func(d *fakeDirs) { d.homeErr = boom }},
		{"darwin", ScopeUser, func(d *fakeDirs) { d.homeErr = boom }},
	}
	for i, tt := range tests {
		d := machine()
		tt.set(d)
		if got, err := defaultRoot(tt.goos, tt.scope, acme, d); !errors.Is(err, boom) {
			t.Errorf("case %d (%s/%v): defaultRoot = %q, %v; want the lookup error", i, tt.goos, tt.scope, got, err)
		}
	}
}

// An application name is one path component. Anything that could make the root
// something else — a separator, a climb, a device, a trailing dot Windows strips
// — is refused, not escaped.
func TestApplicationNameIsOnePlainComponent(t *testing.T) {
	bad := []string{
		"", ".", "..", "../etc", "acme/editor", `acme\editor`, "C:acme", "acme:stream",
		" acme", "acme ", ".acme", "acme.", "acme\x00", "acme\n", "acme*", "acme?", `acme"`,
		"äcme", "CON", "con", "nul.txt", "COM1", "lpt9", "CONOUT$",
		strings.Repeat("a", maxAppNameLen+1),
	}
	for _, name := range bad {
		for _, goos := range []string{"windows", "linux"} {
			for _, scope := range []Scope{ScopeUser, ScopeMachine} {
				if got, err := defaultRoot(goos, scope, App{Name: name}, machine()); !errors.Is(err, ErrApp) {
					t.Errorf("%s/%v name %q: defaultRoot = %q, %v; want ErrApp", goos, scope, name, got, err)
				}
			}
		}
	}
	good := []string{"acme", "Acme Editor", "acme-editor_2.0", "COM", "CONSOLE", "com10", strings.Repeat("a", maxAppNameLen)}
	for _, name := range good {
		if err := checkAppName(name); err != nil {
			t.Errorf("name %q: %v", name, err)
		}
	}
}

func TestBundleIdentifierIsReverseDNS(t *testing.T) {
	bad := []string{
		"", "acme", ".com.acme", "com.acme.", "com..acme", "com.-acme", "com.acme-",
		"com/acme", "com.acme/../x", "com.acme editor", "com.äcme", "com.acme_editor",
		"com." + strings.Repeat("a", maxAppNameLen),
	}
	for _, id := range bad {
		for _, scope := range []Scope{ScopeUser, ScopeMachine} {
			if got, err := defaultRoot("darwin", scope, App{Name: "acme", BundleID: id}, machine()); !errors.Is(err, ErrApp) {
				t.Errorf("%v bundle id %q: defaultRoot = %q, %v; want ErrApp", scope, id, got, err)
			}
		}
	}
	for _, id := range []string{"com.acme", "com.acme.editor", "io.x-y.Z9"} {
		if err := checkBundleID(id); err != nil {
			t.Errorf("bundle id %q: %v", id, err)
		}
	}
}

// Each platform reads the identity it names roots by, and only that one.
func TestEachPlatformRequiresItsOwnIdentity(t *testing.T) {
	if _, err := defaultRoot("darwin", ScopeUser, App{BundleID: "com.acme"}, machine()); err != nil {
		t.Errorf("darwin without a name: %v", err)
	}
	if _, err := defaultRoot("darwin", ScopeUser, App{Name: "acme"}, machine()); !errors.Is(err, ErrApp) {
		t.Errorf("darwin without a bundle id: %v, want ErrApp", err)
	}
	for _, goos := range []string{"windows", "linux"} {
		if _, err := defaultRoot(goos, ScopeUser, App{Name: "acme"}, machine()); err != nil {
			t.Errorf("%s without a bundle id: %v", goos, err)
		}
		if _, err := defaultRoot(goos, ScopeUser, App{BundleID: "com.acme"}, machine()); !errors.Is(err, ErrApp) {
			t.Errorf("%s without a name: %v, want ErrApp", goos, err)
		}
	}
}

func TestUnknownPlatformAndScopeAreRefused(t *testing.T) {
	if _, err := defaultRoot("plan9", ScopeUser, acme, machine()); !errors.Is(err, ErrApp) {
		t.Errorf("plan9: %v, want ErrApp", err)
	}
	for _, s := range []Scope{-1, 2} {
		d := machine()
		if _, err := defaultRoot("linux", s, acme, d); !errors.Is(err, ErrApp) {
			t.Errorf("scope %v: %v, want ErrApp", s, err)
		}
		if len(d.calls) != 0 {
			t.Errorf("scope %v consulted the machine: %v", s, d.calls)
		}
	}
}

func TestParseScope(t *testing.T) {
	for _, s := range []Scope{ScopeUser, ScopeMachine} {
		got, err := ParseScope(s.String())
		if err != nil || got != s {
			t.Errorf("ParseScope(%q) = %v, %v", s.String(), got, err)
		}
	}
	for _, raw := range []string{"", "User", "MACHINE", "system", "user "} {
		if _, err := ParseScope(raw); !errors.Is(err, ErrApp) {
			t.Errorf("ParseScope(%q) = %v, want ErrApp", raw, err)
		}
	}
	if got := Scope(7).String(); got != "Scope(7)" {
		t.Errorf("Scope(7).String() = %q", got)
	}
	if ScopeUser != 0 {
		t.Error("ScopeUser is not the zero value")
	}
}

// Against the real machine: the root is absolute, named after the application,
// and on Windows, where the known folder exists on every installation, below
// what the shell reports.
func TestDefaultRootOnThisMachine(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("no default root on %s", runtime.GOOS)
	}
	for _, scope := range []Scope{ScopeUser, ScopeMachine} {
		got, err := DefaultRoot(scope, acme)
		if err != nil {
			t.Fatalf("DefaultRoot(%v): %v", scope, err)
		}
		if !filepath.IsAbs(got) {
			t.Errorf("DefaultRoot(%v) = %q, not absolute", scope, got)
		}
		want := acme.Name
		if runtime.GOOS == "darwin" {
			want = acme.BundleID
		}
		if filepath.Base(got) != want {
			t.Errorf("DefaultRoot(%v) = %q, not named %q", scope, got, want)
		}
	}
}
