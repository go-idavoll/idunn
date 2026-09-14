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

//go:build e2e

package e2elocal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/packer"
)

// Exit codes of the binaries under test, restated rather than imported: they are
// the contract with whatever runs these programs, and a test that imported the
// constants would not notice the contract changing.
const (
	exitOK      = 0
	exitError   = 1
	exitRefused = 3 // cmd/installer: an install exists that it must not touch.
	appNoUpdate = 3 // hostapp: already up to date.
	appDeferred = 4 // hostapp: staged, waiting for the next start.
)

// ---------------------------------------------------------------------------
// 1. A busy application defers, and the launcher finishes the update at the
//    next start (§14.3).
// ---------------------------------------------------------------------------

func TestBusyAppDefersAndLauncherFinishes(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")
	r.publish("1.1.0")

	// A running instance of 1.0.0 holds the application lock.
	holder := startProc(t, in.appPath(), "--hold-lock", "--lock", in.lock)
	holder.waitFor("holding")

	code, out := in.selfUpdate("--lock", in.lock, "--on-busy", "defer", "--quiesce", "1s")
	if code != appDeferred {
		t.Fatalf("self-update against a held lock = %d, want %d\n%s", code, appDeferred, out)
	}
	if !strings.Contains(out, "deferred 1.1.0") {
		t.Fatalf("the application did not report the deferral: %q", out)
	}
	s := in.observe()
	// Deferred means: nothing live changed, the verified tree stays on disk, and
	// the journal rests in DEFERRED so recovery leaves it alone.
	if s.installed != "1.0.0" || !equal(s.versions, []string{"1.0.0", "1.1.0"}) ||
		s.journal.State != txn.StateDeferred || s.journal.ToVersion != "1.1.0" {
		t.Fatalf("after deferring: %s", s)
	}

	// The instance exits and releases its lock.
	if code := holder.closeStdin(); code != exitOK {
		t.Fatalf("the lock holder exited %d:\n%s", code, holder.output())
	}
	if _, err := os.Stat(in.lock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the lock file survived its holder: %v", err)
	}

	code, out = in.runLauncher()
	if code != exitOK {
		t.Fatalf("launcher = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "applying the deferred update 1.1.0") {
		t.Errorf("the launcher did not say it finished the deferred update: %q", out)
	}
	if !strings.Contains(out, "app 1.1.0") {
		t.Errorf("the launcher started %q, want app 1.1.0", out)
	}
	in.observe().settled(t, "1.1.0", "1.0.0", "1.1.0")

	// A second start has nothing left to do and must not apply anything again.
	s = in.observe()
	code, out = in.runLauncher()
	if code != exitOK || strings.Contains(out, "applying the deferred update") || !strings.Contains(out, "app 1.1.0") {
		t.Fatalf("second start = %d: %q", code, out)
	}
	if after := in.observe(); after.records != s.records {
		t.Errorf("a start with nothing deferred wrote the journal: %d records, then %d", s.records, after.records)
	}
}

// ---------------------------------------------------------------------------
// 2. A process killed inside the transaction leaves old or new, never half, and
//    the launcher's recovery settles it (§6.2, T10).
// ---------------------------------------------------------------------------

func TestKilledInsideTransactionRecovers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		phase   string
		journal txn.State // the last record when the process dies
		settles string    // the version recovery must arrive at
		result  txn.State
		dirs    []string
	}{
		// BEGIN is written, nothing is staged yet: undone.
		{phase: "download", journal: txn.StateBegin, settles: "1.0.0", result: txn.StateRolledBack, dirs: []string{"1.0.0"}},
		// Staged and past the migration step, the pointer has not moved: undone.
		{phase: "apply", journal: txn.StateMigrated, settles: "1.0.0", result: txn.StateRolledBack, dirs: []string{"1.0.0"}},
		// The pointer moved, the commit record was never written: finished.
		{phase: "verify", journal: txn.StateSwapped, settles: "1.1.0", result: txn.StateCommitted, dirs: []string{"1.0.0", "1.1.0"}},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			t.Parallel()
			r := newRepo(t)
			r.publish("1.0.0")
			in := newInstall(t, r)
			in.mustInstall("1.0.0")
			r.publish("1.1.0")

			p := startProc(t, in.appPath(), in.selfUpdateArgs("--hang-at", tc.phase)...)
			p.waitFor("hanging in " + tc.phase)
			p.kill()

			// Before recovery: the journal shows the transaction open where the
			// process died. Without this, a scenario that died somewhere else
			// would pass on whatever state it happened to leave.
			j, err := txn.Open(fsx.OS(), in.root)
			if err != nil {
				t.Fatal(err)
			}
			if last, _ := j.Last(); last.State != tc.journal || last.ToVersion != "1.1.0" {
				t.Fatalf("killed in %s, the journal reads %s->%s %s; want %s", tc.phase,
					last.FromVersion, last.ToVersion, last.State, tc.journal)
			}

			code, out := in.runLauncher()
			if code != exitOK {
				t.Fatalf("launcher after the kill = %d, want %d\n%s", code, exitOK, out)
			}
			// The pointer, the recorded state and the binary that actually runs
			// agree — that agreement is what "not half" means.
			if !strings.Contains(out, "app "+tc.settles) {
				t.Errorf("the launcher started %q, want app %s", out, tc.settles)
			}
			s := in.observe()
			if s.installed != tc.settles || !equal(s.versions, tc.dirs) || s.staging != 0 ||
				s.journal.State != tc.result {
				t.Fatalf("after recovery: %s; want %s installed, versions %v, journal %s",
					s, tc.settles, tc.dirs, tc.result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. A failing host migration unwinds the transaction, and the host is asked to
//    undo its own change (§7, T11).
// ---------------------------------------------------------------------------

func TestFailedMigrationRollsBack(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")
	if err := os.MkdirAll(in.data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.data, "schema"), []byte("1.0.0"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.publish("1.1.0")

	code, out := in.selfUpdate("--data", in.data, "--fail-migrate")
	if code != exitError {
		t.Fatalf("self-update with a failing migration = %d, want %d\n%s", code, exitError, out)
	}
	if !strings.Contains(out, "migration failed") || !strings.Contains(out, "the migration was told to fail") {
		t.Fatalf("the update failed, but not in the migration: %q", out)
	}
	s := in.observe()
	if s.installed != "1.0.0" || !equal(s.versions, []string{"1.0.0"}) || s.staging != 0 ||
		s.journal.State != txn.StateRolledBack || s.journal.ToVersion != "1.1.0" {
		t.Fatalf("after the failed migration: %s", s)
	}
	if got, want := readFile(t, filepath.Join(in.data, "migrations.log")), "migrate 1.0.0->1.1.0\nrollback 1.0.0->1.1.0\n"; got != want {
		t.Errorf("host migration calls:\n%s\nwant:\n%s", got, want)
	}
	if schema := readFile(t, filepath.Join(in.data, "schema")); schema != "1.0.0" {
		t.Errorf("host schema after the rollback is %q, want 1.0.0", schema)
	}
	if code, out := in.runLauncher(); code != exitOK || !strings.Contains(out, "app 1.0.0") {
		t.Errorf("after the rollback the launcher = %d: %q", code, out)
	}

	// The unwound install is a valid base: the same update, with a migration
	// that works, applies on top of it.
	code, out = in.selfUpdate("--data", in.data)
	if code != exitOK {
		t.Fatalf("retrying the update = %d\n%s", code, out)
	}
	in.observe().settled(t, "1.1.0", "1.0.0", "1.1.0")
	if schema := readFile(t, filepath.Join(in.data, "schema")); schema != "1.1.0" {
		t.Errorf("host schema after the retry is %q, want 1.1.0", schema)
	}
}

// ---------------------------------------------------------------------------
// 4. The installer's downgrade preflight, against a repository the packer
//    published (§14.6, T19).
// ---------------------------------------------------------------------------

func TestInstallerRefusesDowngrade(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0")
	r.publish("2.0.0")
	in := newInstall(t, r)
	in.mustInstall("2.0.0")
	before := in.observe()
	fetched := r.srv.payloads.Load()

	code, out := in.runInstaller("--version", "1.0.0")
	if code != exitRefused {
		t.Fatalf("installing 1.0.0 over 2.0.0 = %d, want %d\n%s", code, exitRefused, out)
	}
	if !strings.Contains(out, "installer refused") || !strings.Contains(out, "2.0.0 is already installed and 1.0.0 is not newer") {
		t.Fatalf("refused, but not by the downgrade preflight: %q", out)
	}
	after := in.observe()
	after.settled(t, "2.0.0", "2.0.0")
	if after.records != before.records {
		t.Errorf("the refusal wrote the journal: %d records, then %d", before.records, after.records)
	}
	if n := r.srv.payloads.Load() - fetched; n != 0 {
		t.Errorf("the refused install downloaded %d payloads; the preflight runs before any", n)
	}

	// An operator may overrule it with the flag; the descriptor cannot ask for it.
	code, out = in.runInstaller("--version", "1.0.0", "--allow-downgrade")
	if code != exitOK {
		t.Fatalf("allowed downgrade = %d, want %d\n%s", code, exitOK, out)
	}
	// Retention keeps the newer tree: it is not this transaction's leftover.
	in.observe().settled(t, "1.0.0", "1.0.0", "2.0.0")
	if code, out := in.runLauncher(); code != exitOK || !strings.Contains(out, "app 1.0.0") {
		t.Errorf("after the downgrade the launcher = %d: %q", code, out)
	}
}

// ---------------------------------------------------------------------------
// 5. The backstop (AGENTS.md §7): a payload with one flipped byte is refused by
//    the real installer, for a hash mismatch, with nothing installed.
// ---------------------------------------------------------------------------

func TestTamperedPayloadIsRefused(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)

	// Same length, one byte different: the signed metadata still states what
	// the bytes must hash to, so this is the wrong-hash attack and nothing else.
	victim := payloadFile(t, r, dataContent("1.0.0"))
	orig, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), orig...)
	tampered[0] ^= 0xff
	if err := os.WriteFile(victim, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	code, out := in.runInstaller()
	if code != exitError {
		t.Fatalf("installing from a tampered repository = %d, want %d\n%s", code, exitError, out)
	}
	// The reason matters as much as the refusal. A 404, a truncated file or a
	// dead server also exit non-zero, and a test that accepted any of them would
	// keep passing after the hash check was removed. So two things are pinned:
	//
	//  1. The server delivered the victim whole — status 200, every byte of its
	//     signed length. A 404, a short body or a dropped connection fail here.
	//  2. The client refused those bytes with go-tuf's hash verdict
	//     (metadata.ErrLengthOrHashMismatch), naming the target it refused.
	//
	// go-tuf checks the hash before the length, so (2) alone would also match a
	// truncated file; (1) is what rules that out. If go-tuf rewords the verdict,
	// pin the new wording — never drop the assertion.
	rel, err := filepath.Rel(filepath.Join(r.tuf, packer.TargetsDir), victim)
	if err != nil {
		t.Fatal(err)
	}
	urlPath := "/targets/" + filepath.ToSlash(rel)
	whole := false
	for _, resp := range r.srv.responses(urlPath) {
		if resp.status == 200 && resp.bytes == int64(len(orig)) {
			whole = true
		}
	}
	if !whole {
		t.Fatalf("the tampered payload %s was never served whole (responses %+v), so the refusal "+
			"cannot have been the hash check:\n%s", urlPath, r.srv.responses(urlPath), out)
	}
	sum := sha256.Sum256(dataContent("1.0.0"))
	target := release.PayloadPath("1", sum[:])
	if !strings.Contains(out, "length/hash verification error: hash verification failed - mismatch for algorithm sha256") ||
		!strings.Contains(out, `"`+target+`"`) {
		t.Fatalf("the install was refused, but not for a hash mismatch of %s:\n%s", target, out)
	}
	s := in.observe()
	if s.installed != "" || len(s.versions) != 0 || s.staging != 0 ||
		(s.hasJournal && s.journal.State == txn.StateCommitted) {
		t.Fatalf("a tampered repository left state behind: %s", s)
	}

	// Control: with the byte restored, the same client and the same cache
	// install. So the refusal was the flipped byte, and the rejected bytes did
	// not stick in the cache either.
	if err := os.WriteFile(victim, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	in.mustInstall("1.0.0")
	if got := readFile(t, filepath.Join(in.root, layout.VersionsName, "1.0.0", "share", "version.txt")); got != string(dataContent("1.0.0")) {
		t.Errorf("the installed data file reads %q", got)
	}
}

// payloadFile finds the published payload holding content. Payload targets are
// content-addressed, so its file name carries the SHA-256 of the bytes.
func payloadFile(t *testing.T, r *repo, content []byte) string {
	t.Helper()
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])
	var found []string
	root := filepath.Join(r.tuf, packer.TargetsDir, "payloads")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.Contains(d.Name(), hexSum) {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the published payloads: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one payload file for sha256 %s, found %v", hexSum, found)
	}
	return found[0]
}

// ---------------------------------------------------------------------------
// 6. Retention: the configured window is kept, the live version and its
//    rollback target always survive, older trees are collected (§14.1).
// ---------------------------------------------------------------------------

func TestRetentionCollectsOldVersions(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0")
	in := newInstall(t, r)
	in.mustInstall("1.0.0")

	for _, step := range []struct {
		version string
		retain  string
		kept    []string
	}{
		{"1.1.0", "3", []string{"1.0.0", "1.1.0"}},
		{"1.2.0", "3", []string{"1.0.0", "1.1.0", "1.2.0"}},
		// The window is full: the oldest goes, the two newest predecessors stay.
		{"1.3.0", "3", []string{"1.1.0", "1.2.0", "1.3.0"}},
		// Narrowing the window collects everything beyond the rollback target.
		{"1.4.0", "2", []string{"1.3.0", "1.4.0"}},
	} {
		r.publish(step.version)
		code, out := in.selfUpdate("--retain", step.retain)
		if code != exitOK {
			t.Fatalf("self-update to %s = %d\n%s", step.version, code, out)
		}
		in.observe().settled(t, step.version, step.kept...)
	}

	if code, out := in.runLauncher(); code != exitOK || !strings.Contains(out, "app 1.4.0") {
		t.Errorf("the launcher = %d: %q", code, out)
	}
	// The rollback target is not just a directory name: it is a whole,
	// runnable tree.
	prev := filepath.Join(in.root, layout.VersionsName, "1.3.0", filepath.FromSlash(appDst))
	if code, out := runProc(t, prev); code != exitOK || !strings.Contains(out, "app 1.3.0") {
		t.Errorf("the retained 1.3.0 does not run: %d %q", code, out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// 7. Install and restart (IDN-29): a running application defers an update it
//    cannot apply to itself, asks to be relaunched, and the launcher finishes
//    the update and starts the new version.
// ---------------------------------------------------------------------------

func TestInstallAndRestart(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// underLauncher runs the application through cmd/launcher, as a user
		// starting it would; otherwise it is started directly.
		underLauncher bool
	}{
		{"under the launcher", true},
		{"started directly", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := newRepo(t)
			r.publish("1.0.0")
			in := newInstall(t, r)
			in.mustInstall("1.0.0")
			r.publish("1.1.0")

			appArgs := in.selfUpdateArgs("--lock", in.lock, "--on-busy", "defer", "--quiesce", "1s",
				"--hold-own-lock", "--relaunch-via", suite.launcher)
			var code int
			var out string
			if tc.underLauncher {
				code, out = in.runLauncher(append([]string{"--"}, appArgs...)...)
			} else {
				code, out = runProc(t, in.appPath(), appArgs...)
			}

			for _, want := range []string{
				"deferred 1.1.0",                     // the running 1.0.0 could not apply it to itself,
				"relaunching",                        // asked to be started again,
				"applying the deferred update 1.1.0", // the launcher finished it with 1.0.0 gone,
				"up to date at 1.1.0",                // and the new run is 1.1.0.
			} {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
			// The code the test sees is the last run's where a process carries on
			// to the end (POSIX exec, the Windows launcher's loop), and the first
			// instance's where it handed over to a new launcher and left (Windows,
			// started directly).
			want := appNoUpdate
			if runtime.GOOS == "windows" && !tc.underLauncher {
				want = exitOK
			}
			if code != want {
				t.Errorf("exit = %d, want %d\n%s", code, want, out)
			}
			in.observe().settled(t, "1.1.0", "1.0.0", "1.1.0")
			if _, err := os.Stat(in.lock); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the application lock survived the relaunch: %v", err)
			}
		})
	}
}
