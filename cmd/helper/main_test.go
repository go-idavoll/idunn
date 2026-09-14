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
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/go-idavoll/idunn/core/elevate"
)

// absRoot is an absolute path on the platform running the test.
func absRoot(name string) string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\` + name
	}
	return "/opt/" + name
}

func helperJSON(t *testing.T, extra string) string {
	t.Helper()
	root := strings.ReplaceAll(absRoot("acme"), `\`, `\\`)
	return `{"label":"com.acme.app.helper","allowed_roots":["` + root + `"]` + extra + `}`
}

// withBuild swaps the embedded configuration for the length of a test.
func withBuild(t *testing.T, files map[string]string) {
	t.Helper()
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys["anchor/"+name] = &fstest.MapFile{Data: []byte(body)}
	}
	saved := buildFS
	buildFS = fsys
	t.Cleanup(func() { buildFS = saved })
}

func completeBuild(t *testing.T, helper string) map[string]string {
	t.Helper()
	return map[string]string{
		"root.json":       `{"signed":{"_type":"root"}}`,
		"repository.json": `{"metadata_url":"https://updates.example.com/metadata/","channel":"beta"}`,
		"helper.json":     helper,
	}
}

// This tree embeds nothing, and a helper built from it must refuse every verb
// that would act on a configuration — there is no default trust anchor and no
// default install root to fall back to.
func TestThisTreeBuildsAHelperThatRefusesToServe(t *testing.T) {
	for _, verb := range [][]string{{"check"}, {"plist"}, {"serve"}} {
		var out bytes.Buffer
		if code := run(verb, &out, &out); code != exitRefuse {
			t.Errorf("helper %v = %d, want %d\n%s", verb, code, exitRefuse, &out)
		}
	}
}

func TestUsageAndVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run(nil, &out, &out); code != exitUsage {
		t.Fatalf("no arguments = %d", code)
	}
	if code := run([]string{"uninstall"}, &out, &out); code != exitUsage {
		t.Fatalf("unknown verb = %d", code)
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &out); code != exitOK || strings.TrimSpace(out.String()) == "" {
		t.Fatalf("version = %d %q", code, out.String())
	}
	// Verbs that take no arguments refuse any, so nothing can be smuggled in.
	for _, verb := range []string{"serve", "check", "plist"} {
		if code := run([]string{verb, "--root", "/tmp"}, &out, &out); code != exitUsage {
			t.Errorf("helper %s --root = %d, want %d", verb, code, exitUsage)
		}
	}
}

func TestLoadBuild(t *testing.T) {
	withBuild(t, completeBuild(t, helperJSON(t, "")))
	b, err := loadBuild(buildFS)
	if err != nil {
		t.Fatalf("loadBuild(complete) = %v", err)
	}
	if b.helper.Label != "com.acme.app.helper" || channelOf(b) != "beta" {
		t.Fatalf("loadBuild = %+v", b.helper)
	}

	for name, files := range map[string]map[string]string{
		"no helper.json": {"root.json": "{}", "repository.json": `{"metadata_url":"https://u/m/"}`},
		"no root.json":   {"repository.json": `{"metadata_url":"https://u/m/"}`, "helper.json": helperJSON(t, "")},
		"no repository":  {"root.json": "{}", "helper.json": helperJSON(t, "")},
	} {
		withBuild(t, files)
		if _, err := loadBuild(buildFS); err == nil {
			t.Errorf("loadBuild(%s) succeeded", name)
		}
	}
}

func TestDecodeHelperConfigRefuses(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":        helperJSON(t, `,"allowed_uids":[0]`),
		"bad label":          `{"label":"acme","allowed_roots":["` + strings.ReplaceAll(absRoot("a"), `\`, `\\`) + `"]}`,
		"no roots":           `{"label":"com.acme.app.helper","allowed_roots":[]}`,
		"relative root":      `{"label":"com.acme.app.helper","allowed_roots":["acme"]}`,
		"unclean root":       `{"label":"com.acme.app.helper","allowed_roots":["` + strings.ReplaceAll(absRoot("a/../b"), `\`, `\\`) + `"]}`,
		"negative interval":  helperJSON(t, `,"min_interval_seconds":-1`),
		"too long interval":  helperJSON(t, `,"min_interval_seconds":86400`),
		"trailing data":      helperJSON(t, "") + ` {}`,
		"not json":           `label=com.acme.app.helper`,
		"root of other kind": `{"label":"com.acme.app.helper","allowed_roots":["` + foreignRoot() + `"]}`,
	} {
		if _, err := decodeHelperConfig([]byte(body)); !errors.Is(err, ErrConfig) {
			t.Errorf("decodeHelperConfig(%s) = %v, want ErrConfig", name, err)
		}
	}
}

// foreignRoot is an absolute path on the other platform family, which is not an
// absolute path here.
func foreignRoot() string {
	if runtime.GOOS == "windows" {
		return "/opt/acme"
	}
	return `C:\\Program Files\\acme`
}

func TestCallersRoundTripAndRefusals(t *testing.T) {
	c := callers{UIDs: []uint32{501, 502}, SIDs: []string{"S-1-5-21-1-2-3-1001"}}
	back, err := decodeCallers(c.encode())
	if err != nil || len(back.UIDs) != 2 || back.SIDs[0] != c.SIDs[0] {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
	if !bytes.Equal(c.encode(), back.encode()) {
		t.Fatal("encoding is not deterministic")
	}
	if got := string((callers{}).encode()); got != "{}\n" {
		t.Fatalf("empty list encodes as %q", got)
	}

	for name, body := range map[string]string{
		"unknown key":   `{"uids":[1],"gids":[0]}`,
		"negative uid":  `{"uids":[-1]}`,
		"huge uid":      `{"uids":[4294967296]}`,
		"sid is a name": `{"sids":["BUILTIN\\Users"]}`,
		"sid sddl":      `{"sids":["S-1-5-21-1)(A;;GA;;;WD"]}`,
		"trailing":      `{"uids":[1]} {"uids":[0]}`,
	} {
		if _, err := decodeCallers([]byte(body)); !errors.Is(err, ErrConfig) {
			t.Errorf("decodeCallers(%s) = %v, want ErrConfig", name, err)
		}
	}
}

func TestReadAndWriteCallers(t *testing.T) {
	dir := t.TempDir()
	if _, exists, err := readCallers(dir); err != nil || exists {
		t.Fatalf("readCallers(empty dir) = %v, %v; want absent", exists, err)
	}
	want := callers{UIDs: []uint32{1000}}
	if err := writeCallers(dir, want); err != nil {
		t.Fatal(err)
	}
	got, exists, err := readCallers(dir)
	if err != nil || !exists || len(got.UIDs) != 1 || got.UIDs[0] != 1000 {
		t.Fatalf("readCallers = %+v, %v, %v", got, exists, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("writeCallers left %d entries behind, want only %s", len(entries), callersName)
	}

	if err := os.WriteFile(filepath.Join(dir, callersName), bytes.Repeat([]byte(" "), maxCallersBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCallers(dir); !errors.Is(err, ErrConfig) {
		t.Fatalf("readCallers(oversized) = %v, want ErrConfig", err)
	}

	sub := t.TempDir()
	if err := os.Mkdir(filepath.Join(sub, callersName), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCallers(sub); !errors.Is(err, ErrConfig) {
		t.Fatalf("readCallers(a directory) = %v, want ErrConfig", err)
	}
}

func TestEditCallers(t *testing.T) {
	c, err := edit(callers{}, "1001", "", true)
	if err == nil {
		c, err = edit(c, "501", "", true)
	}
	if err == nil {
		c, err = edit(c, "1001", "", true) // a duplicate is not added twice.
	}
	if err != nil || len(c.UIDs) != 2 || c.UIDs[0] != 501 || c.UIDs[1] != 1001 {
		t.Fatalf("edit = %+v, %v; want sorted [501 1001]", c, err)
	}
	c, _ = edit(c, "501", "", false)
	if len(c.UIDs) != 1 || c.UIDs[0] != 1001 {
		t.Fatalf("deny = %+v", c)
	}
	c, err = edit(c, "", "S-1-5-21-9-8-7-1002", true)
	if err != nil || len(c.SIDs) != 1 {
		t.Fatalf("edit(sid) = %+v, %v", c, err)
	}
	for _, bad := range [][2]string{{"-1", ""}, {"abc", ""}, {"4294967296", ""}, {"", "Administrators"}, {"", "S-1-5-32-544;"}} {
		if _, err := edit(callers{}, bad[0], bad[1], true); !errors.Is(err, ErrConfig) {
			t.Errorf("edit(%q, %q) = %v, want ErrConfig", bad[0], bad[1], err)
		}
	}
}

func TestAllowNeedsExactlyOneCallerAndAdministratorRights(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"allow"}, {"allow", "--uid", "1", "--sid", "S-1-5-18"}, {"deny", "extra"}} {
		if code := run(args, &out, &out); code != exitUsage {
			t.Errorf("helper %v = %d, want %d", args, code, exitUsage)
		}
	}
	if requireAdministrator() == nil {
		t.Skip("running with administrator rights; the refusal cannot be observed")
	}
	withBuild(t, completeBuild(t, helperJSON(t, "")))
	out.Reset()
	if code := run([]string{"allow", "--uid", "1000"}, &out, &out); code != exitRefuse ||
		!strings.Contains(out.String(), "administrator") {
		t.Fatalf("unprivileged allow = %d %q, want a refusal naming administrator rights", code, out.String())
	}
}

// A state directory an ordinary user controls is refused by check and serve,
// whatever it contains: the caller list in it could have been written by anyone.
func TestAStateDirectoryAUserControlsIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("as root, a temporary directory is root-owned")
	}
	withBuild(t, completeBuild(t, helperJSON(t, "")))
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeCallers(state, callers{UIDs: []uint32{0}, SIDs: []string{"S-1-5-18"}}); err != nil {
		t.Fatal(err)
	}
	saved := pathsFor
	pathsFor = func(string) (elevate.HelperPaths, error) {
		return elevate.HelperPaths{StateDir: state, Endpoint: filepath.Join(state, "helper.sock")}, nil
	}
	t.Cleanup(func() { pathsFor = saved })

	var out bytes.Buffer
	if code := run([]string{"check"}, &out, &out); code != exitRefuse || !strings.Contains(out.String(), "state:") {
		t.Fatalf("check = %d\n%s", code, &out)
	}
	out.Reset()
	if code := run([]string{"serve"}, &out, &out); code != exitRefuse || !strings.Contains(out.String(), "state directory") {
		t.Fatalf("serve = %d\n%s", code, &out)
	}
}

func TestPlist(t *testing.T) {
	withBuild(t, completeBuild(t, helperJSON(t, "")))
	var out bytes.Buffer
	if code := run([]string{"plist"}, &out, &out); code != exitRefuse || !strings.Contains(out.String(), "macos_bundle_identifier") {
		t.Fatalf("plist without a bundle identifier = %d %q", code, out.String())
	}

	withBuild(t, completeBuild(t, helperJSON(t, `,"macos_bundle_identifier":"com.acme.app"`)))
	out.Reset()
	var errw bytes.Buffer
	if code := run([]string{"plist"}, &out, &errw); code != exitOK {
		t.Fatalf("plist = %d %s", code, &errw)
	}
	for _, want := range []string{
		"<string>com.acme.app.helper</string>",
		"<string>Contents/Library/HelperTools/com.acme.app.helper</string>",
		"<string>com.acme.app</string>",
		"<string>serve</string>",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plist lacks %s:\n%s", want, &out)
		}
	}
}

func TestParseBuildTime(t *testing.T) {
	if ts, err := parseBuildTime(""); err != nil || !ts.IsZero() {
		t.Fatalf("empty = %v, %v", ts, err)
	}
	if ts, err := parseBuildTime("1789372852"); err != nil || ts.Unix() != 1789372852 {
		t.Fatalf("unix = %v, %v", ts, err)
	}
	if _, err := parseBuildTime("2026-09-14T12:00:00Z"); err != nil {
		t.Fatalf("rfc3339 = %v", err)
	}
	if _, err := parseBuildTime("yesterday"); !errors.Is(err, ErrConfig) {
		t.Fatalf("garbage = %v, want ErrConfig", err)
	}
}
