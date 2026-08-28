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

package e2e

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/installer"
)

// Exit codes of the binaries under test. They are duplicated here on purpose:
// they are the contract with whatever runs these programs, and a test that
// imported the constant would not notice if the contract changed.
const (
	exitOK         = 0
	exitError      = 1
	exitRefused    = 3 // installer: an install exists that it must not touch.
	exitAppNoUpd   = 3 // app: the channel head is already installed.
	exitAppDefer   = 4 // app: staged, waiting for the next start.
	exitAppCrashed = 137
)

// install is one install root plus everything needed to drive it.
type install struct {
	t    *testing.T
	repo *repo
	root string

	// cache is the client-side TUF cache. It survives across processes, which
	// is what makes "unchanged files are not fetched twice" observable at all.
	cache string
}

func newInstall(t *testing.T, r *repo) *install {
	t.Helper()
	base := t.TempDir()
	return &install{
		t:     t,
		repo:  r,
		root:  filepath.Join(base, "app"),
		cache: filepath.Join(base, "cache"),
	}
}

// runInstaller runs the real installer binary against the served repository.
func (in *install) runInstaller(extra ...string) (int, string) {
	in.t.Helper()
	args := append([]string{
		"install",
		"--root", in.root,
		"--root-metadata", in.repo.anchor,
		"--metadata-url", in.repo.srv.metadataURL(),
		"--targets-url", in.repo.srv.targetsURL(),
		"--cache", in.cache,
	}, extra...)
	return runProc(in.t, bin.installer, args...)
}

// runLauncher starts the installed application through the launcher shim, which
// is what settles an interrupted transaction and finishes a deferred update.
func (in *install) runLauncher(extra ...string) (int, string) {
	in.t.Helper()
	args := append([]string{"-root", in.root, "-quiet"}, extra...)
	return runProc(in.t, bin.launcher, args...)
}

// appPath is the installed application of the version `current` points at.
//
// It is resolved through the pointer rather than through current/ itself,
// because current/ is a symlink on POSIX and a pointer *file* on Windows — the
// launcher is the component that knows the difference, and a test that assumed
// one of the two would only run on half the matrix.
func (in *install) appPath() string {
	in.t.Helper()
	v := in.version()
	if v == "" {
		in.t.Fatalf("%s holds no installation", in.root)
	}
	return filepath.Join(in.root, "versions", v, filepath.FromSlash(appDst()))
}

// version is what the install root says is installed, or "" for nothing.
func (in *install) version() string {
	in.t.Helper()
	v, err := installer.InstalledVersion(in.root)
	if err != nil {
		in.t.Fatalf("InstalledVersion: %v", err)
	}
	return v
}

// selfUpdate runs the *installed* application and has it update itself, which is
// the shape a host actually ships: the binary being replaced is the one running.
func (in *install) selfUpdate(extra ...string) (int, string) {
	in.t.Helper()
	args := append([]string{
		"--self-update",
		"--root", in.root,
		"--metadata-url", in.repo.srv.metadataURL(),
		"--targets-url", in.repo.srv.targetsURL(),
		"--root-metadata", in.repo.anchor,
		"--cache", in.cache,
	}, extra...)
	return runProc(in.t, in.appPath(), args...)
}

// procTimeout bounds one process under test. It is generous: what it exists to
// catch is a hang, and a hang that is reported against a named binary is worth
// far more than the whole suite timing out anonymously.
const procTimeout = 5 * time.Minute

// runProc runs one process to completion and returns its exit code and its
// combined output.
func runProc(t *testing.T, name string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), procTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("running %s: %v", filepath.Base(name), err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// oneFile is the payload set most scenarios use beside the application binary.
func oneFile(content string) release {
	return release{data: map[string]string{"share/readme.txt": content}}
}

// ---------------------------------------------------------------------------
// 1. The whole point of the project, in one test.
// ---------------------------------------------------------------------------

func TestInstallThenLaunch(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("hello from 1.0.0"))
	in := newInstall(t, r)

	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d, want %d\n%s", code, exitOK, out)
	}
	if v := in.version(); v != "1.0.0" {
		t.Fatalf("installed %q, want 1.0.0", v)
	}
	data, err := os.ReadFile(filepath.Join(in.root, "versions", "1.0.0", "share", "readme.txt"))
	if err != nil {
		t.Fatalf("reading the installed payload: %v", err)
	}
	if got, want := string(data), "hello from 1.0.0"; got != want {
		t.Errorf("payload = %q, want %q", got, want)
	}

	code, out := in.runLauncher()
	if code != exitOK {
		t.Fatalf("launcher = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "app 1.0.0") {
		t.Errorf("the launcher did not start the installed application: %q", out)
	}
}

// ---------------------------------------------------------------------------
// 2. A running application replaces itself, and the old tree survives as the
//    rollback target.
// ---------------------------------------------------------------------------

func TestSelfUpdateKeepsARollbackTarget(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}

	r.publish("2.0.0", oneFile("two"))
	code, out := in.selfUpdate()
	if code != exitOK {
		t.Fatalf("self-update = %d, want %d\n%s", code, exitOK, out)
	}
	if !strings.Contains(out, "applied 2.0.0") {
		t.Errorf("self-update did not report what it applied: %q", out)
	}
	if v := in.version(); v != "2.0.0" {
		t.Fatalf("installed %q, want 2.0.0", v)
	}
	// Instant rollback needs the predecessor to still be on disk (§6.1).
	if _, err := os.Stat(filepath.Join(in.root, "versions", "1.0.0")); err != nil {
		t.Errorf("the rollback target is gone: %v", err)
	}
	if _, out := in.runLauncher(); !strings.Contains(out, "app 2.0.0") {
		t.Errorf("the launcher started %q, want the new version", out)
	}
}

// ---------------------------------------------------------------------------
// 3. A busy application defers, and the launcher finishes the job at the next
//    start (IDN-06, §14.3) — across three processes, for the first time.
// ---------------------------------------------------------------------------

func TestDeferredUpdateAppliedByLauncher(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}
	r.publish("2.0.0", oneFile("two"))

	lock := filepath.Join(t.TempDir(), "app.lock")
	holder := holdLock(t, in.appPath(), lock)

	code, out := in.selfUpdate("--lock", lock, "--on-busy", "defer")
	if code != exitAppDefer {
		t.Fatalf("self-update against a held lock = %d, want %d\n%s", code, exitAppDefer, out)
	}
	if v := in.version(); v != "1.0.0" {
		t.Fatalf("a deferred update changed the live version to %q", v)
	}
	// The staged tree must survive the deferral; losing it is what turns a
	// deferred update into a lost one.
	if _, err := os.Stat(filepath.Join(in.root, "versions", "2.0.0")); err != nil {
		t.Fatalf("the staged version was swept up: %v", err)
	}

	holder.stop()

	code, out = in.runLauncher()
	if code != exitOK {
		t.Fatalf("launcher = %d, want %d\n%s", code, exitOK, out)
	}
	if v := in.version(); v != "2.0.0" {
		t.Fatalf("after the restart the installed version is %q, want 2.0.0", v)
	}
	if !strings.Contains(out, "app 2.0.0") {
		t.Errorf("the launcher started %q, want the deferred version", out)
	}
}

// lockHolder is a second process holding the exclusive application lock.
type lockHolder struct {
	t   *testing.T
	cmd *exec.Cmd
}

// holdLock starts the application in lock-holding mode and waits until it says
// it has the lock, so the test never races the update it is about to run.
func holdLock(t *testing.T, app, lock string) *lockHolder {
	t.Helper()
	// The context is the test's own: when the test ends, the holder is killed,
	// so no scenario can leak a process that owns a lock.
	cmd := exec.CommandContext(t.Context(), app, "--lock", lock, "--hold-lock", "5m")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &lockHolder{t: t, cmd: cmd}
	t.Cleanup(h.stop)

	done := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "holding" {
				done <- "holding"
				return
			}
		}
		done <- ""
	}()
	select {
	case line := <-done:
		if line == "" {
			t.Fatal("the lock holder exited without taking the lock")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the lock holder")
	}
	return h
}

func (h *lockHolder) stop() {
	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	_ = h.cmd.Process.Kill()
	_, _ = h.cmd.Process.Wait()
	h.cmd = nil
}

// ---------------------------------------------------------------------------
// 4. A process that stops existing mid-transaction leaves old or new, never
//    half (§6.2, T10).
// ---------------------------------------------------------------------------

func TestCrashDuringApplyLeavesAWholeInstall(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}
	r.publish("2.0.0", oneFile("two"))

	// Die the moment the apply phase is entered: the journal has been written
	// and the swap has not happened, which is the window recovery exists for.
	code, out := in.selfUpdate("--die-at", "apply")
	if code != exitAppCrashed {
		t.Fatalf("the fixture did not die where it was told: %d\n%s", code, out)
	}

	code, out = in.runLauncher()
	if code != exitOK {
		t.Fatalf("launcher after the crash = %d, want %d\n%s", code, exitOK, out)
	}
	v := in.version()
	if v != "1.0.0" && v != "2.0.0" {
		t.Fatalf("after recovery the installed version is %q, want a whole 1.0.0 or 2.0.0", v)
	}
	// Whatever it settled on, the pointer, the install state and the binary on
	// disk must agree — that agreement is what "not half" means.
	if !strings.Contains(out, "app "+v) {
		t.Errorf("the pointer says %s but the launcher started %q", v, out)
	}
}

// ---------------------------------------------------------------------------
// 5. A failing host migration unwinds the transaction (§7, T11).
// ---------------------------------------------------------------------------

func TestFailedMigrationRollsBack(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}
	r.publish("2.0.0", oneFile("two"))

	code, out := in.selfUpdate("--fail-migrate")
	if code != exitError {
		t.Fatalf("self-update with a failing migration = %d, want %d\n%s", code, exitError, out)
	}
	if v := in.version(); v != "1.0.0" {
		t.Fatalf("a failed migration left %q installed, want 1.0.0", v)
	}
	if _, out := in.runLauncher(); !strings.Contains(out, "app 1.0.0") {
		t.Errorf("after the rollback the launcher started %q", out)
	}
}

// ---------------------------------------------------------------------------
// 6. The downgrade preflight, against a repository the packer published
//    (§14.6, T19).
// ---------------------------------------------------------------------------

func TestDowngradeRefusedUnlessAllowed(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	r.publish("2.0.0", oneFile("two"))
	in := newInstall(t, r)

	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}
	if v := in.version(); v != "2.0.0" {
		t.Fatalf("the channel head installed as %q, want 2.0.0", v)
	}

	code, out := in.runInstaller("--version", "1.0.0")
	if code != exitRefused {
		t.Fatalf("installing 1.0.0 over 2.0.0 = %d, want %d\n%s", code, exitRefused, out)
	}
	if v := in.version(); v != "2.0.0" {
		t.Fatalf("the refusal changed the install to %q", v)
	}

	// An operator may overrule it, and only an operator: the flag exists, the
	// descriptor cannot ask for it.
	if code, out := in.runInstaller("--version", "1.0.0", "--allow-downgrade"); code != exitOK {
		t.Fatalf("allowed downgrade = %d, want %d\n%s", code, exitOK, out)
	}
	if v := in.version(); v != "1.0.0" {
		t.Fatalf("after the allowed downgrade the install is %q, want 1.0.0", v)
	}
}

// ---------------------------------------------------------------------------
// 7. The backstop (AGENTS.md §7): a tampered payload must be refused by the
//    real binaries, with nothing installed.
// ---------------------------------------------------------------------------

func TestTamperedPayloadIsRefused(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("hello"))
	in := newInstall(t, r)

	// Flip one byte of one published payload. The signed metadata still says
	// what the bytes should hash to, so this is the wrong-hash attack — served
	// by the real server to the real installer.
	tamperOnePayload(t, r)

	code, out := in.runInstaller()
	if code != exitError {
		t.Fatalf("installing from a tampered repository = %d, want %d\n%s", code, exitError, out)
	}
	// The *reason* matters as much as the refusal. A 404, a truncated file or a
	// broken server would also produce a non-zero exit, and a test that accepted
	// any of those would keep passing after the hash check was removed — which is
	// exactly the reward-hacking failure AGENTS.md §6 asks reviewers to look for.
	// If go-tuf rewords this, re-read the new wording and pin that; never drop
	// the assertion.
	if !strings.Contains(out, "hash") {
		t.Fatalf("the repository was refused, but not for a hash mismatch: %q", out)
	}
	if v := in.version(); v != "" {
		t.Fatalf("a tampered repository installed %q", v)
	}
	if entries, err := os.ReadDir(filepath.Join(in.root, "versions")); err == nil && len(entries) != 0 {
		t.Errorf("the refused install left %d version directories behind", len(entries))
	}
}

// tamperOnePayload rewrites the first payload file it finds in the served
// repository.
func tamperOnePayload(t *testing.T, r *repo) {
	t.Helper()
	dir := filepath.Join(r.dir, "targets", "payloads")
	var victim string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && victim == "" {
			victim = path
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the published payloads: %v", err)
	}
	if victim == "" {
		t.Fatal("the publish produced no payload target to tamper with")
	}
	raw, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatalf("%s is empty", victim)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(victim, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// 8. Delta stage 1: an unchanged file does not cross the wire twice (§6.4).
// ---------------------------------------------------------------------------

func TestUnchangedPayloadsAreNotRefetched(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	stable := "this file never changes"
	r.publish("1.0.0", release{data: map[string]string{
		"share/stable.txt":   stable,
		"share/changing.txt": "first",
	}})
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}

	// 2.0.0 changes one of the two data files. The application binary carries a
	// different version stamp, so it changes too: two of three payloads are new.
	//
	// The major bump is the point. A payload target's path carries its release
	// line (payloads/v<major>/<sha256>), and the go-tuf cache is keyed by path,
	// so the cache alone cannot recognise identical bytes republished under a
	// new major — it fetched all three before IDN-10. What closes it is reuse
	// driven by the content already installed, and this is where that shows.
	r.publish("2.0.0", release{data: map[string]string{
		"share/stable.txt":   stable,
		"share/changing.txt": "second",
	}})

	r.srv.resetCounts()
	if code, out := in.selfUpdate(); code != exitOK {
		t.Fatalf("self-update = %d: %s", code, out)
	}
	if got := r.srv.payloadRequests(); got != 2 {
		t.Errorf("the update fetched %d payload targets, want 2 (the binary and the changed file); "+
			"3 means the unchanged file was not recognised in the installed version", got)
	}
	// And the file that was not fetched is nonetheless present and correct in
	// the new version — a complete, self-contained tree is what blue/green
	// needs (§6.1).
	got, err := os.ReadFile(filepath.Join(in.root, "versions", "2.0.0", "share", "stable.txt"))
	if err != nil {
		t.Fatalf("the reused file is missing from the new version: %v", err)
	}
	if string(got) != stable {
		t.Errorf("the reused file reads %q, want %q", got, stable)
	}
}

// ---------------------------------------------------------------------------
// 9. Garbage collection keeps the rollback target and drops what is older
//    (§14.1).
// ---------------------------------------------------------------------------

func TestGarbageCollectionKeepsTheRollbackTarget(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", oneFile("one"))
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}
	r.publish("2.0.0", oneFile("two"))
	if code, out := in.selfUpdate("--retain", "2"); code != exitOK {
		t.Fatalf("self-update to 2.0.0 = %d: %s", code, out)
	}
	r.publish("3.0.0", oneFile("three"))
	if code, out := in.selfUpdate("--retain", "2"); code != exitOK {
		t.Fatalf("self-update to 3.0.0 = %d: %s", code, out)
	}

	if v := in.version(); v != "3.0.0" {
		t.Fatalf("installed %q, want 3.0.0", v)
	}
	for _, keep := range []string{"3.0.0", "2.0.0"} {
		if _, err := os.Stat(filepath.Join(in.root, "versions", keep)); err != nil {
			t.Errorf("retention dropped %s, which must survive: %v", keep, err)
		}
	}
	if _, err := os.Stat(filepath.Join(in.root, "versions", "1.0.0")); err == nil {
		t.Error("1.0.0 is beyond the retention window and should have been collected")
	}
}

// ---------------------------------------------------------------------------
// 10. The launcher replaces itself (§13, IDN-17).
// ---------------------------------------------------------------------------

// The shim lives at the top of the install root and a release's files land
// inside a version directory, so the blue/green swap never touches it. This is
// the step that carries a new launcher the last few centimetres — and the reason
// it needs a mechanism of its own on Windows, where the running executable
// cannot be replaced but can be renamed.
func TestTheLauncherReplacesItself(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", release{data: map[string]string{"share/readme.txt": "one"},
		launcher: "1.0.0"})
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}

	// The shim is what a user clicks, so it sits in the install root — put it
	// there the way an installer would, from the version that was just
	// installed.
	shim := filepath.Join(in.root, exeName("launcher"))
	installShim(t, in, shim)
	if got := launcherVersionOf(t, shim); got != "1.0.0" {
		t.Fatalf("the shim reports %q before any update", got)
	}

	// A release that ships a different launcher.
	r.publish("2.0.0", release{data: map[string]string{"share/readme.txt": "two"},
		launcher: "2.0.0"})
	if code, out := in.selfUpdate(); code != exitOK {
		t.Fatalf("self-update = %d: %s", code, out)
	}
	// The update moved versions/ forward; the shim is still the old one,
	// because nothing has started it since.
	if got := launcherVersionOf(t, shim); got != "1.0.0" {
		t.Errorf("the shim changed without a start: %q", got)
	}

	// This start is the moment it may replace itself.
	if code, out := runProc(t, shim, "-root", in.root, "-quiet"); code != exitOK {
		t.Fatalf("launcher = %d: %s", code, out)
	}
	if got := launcherVersionOf(t, shim); got != "2.0.0" {
		t.Errorf("the shim reports %q after the start that should have refreshed it", got)
	}
	// And it still launches the application it is there to launch.
	if _, out := runProc(t, shim, "-root", in.root, "-quiet"); !strings.Contains(out, "app 2.0.0") {
		t.Errorf("the replaced launcher started %q", out)
	}
}

// installShim copies the launcher out of the installed version into the install
// root, which is what an installer does with it.
func installShim(t *testing.T, in *install, dst string) {
	t.Helper()
	src := filepath.Join(in.root, "versions", in.version(), filepath.FromSlash(launcherDst()))
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("the release did not ship a launcher: %v", err)
	}
	if err := os.WriteFile(dst, raw, 0o755); err != nil { //nolint:gosec // it is a launcher.
		t.Fatal(err)
	}
}

// launcherVersionOf asks a shim which launcher it is.
func launcherVersionOf(t *testing.T, shim string) string {
	t.Helper()
	code, out := runProc(t, shim, "-version")
	if code != exitOK {
		t.Fatalf("%s -version = %d: %s", shim, code, out)
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "idunn launcher"))
}

// ---------------------------------------------------------------------------
// 11. Delta stage 2: a changed file arrives as a patch (§6.4, IDN-14).
// ---------------------------------------------------------------------------

// Stage 1 keeps *unchanged* files off the wire. This is the other half: a file
// that did change, and is nonetheless mostly what is already installed, arrives
// as the difference rather than as itself.
//
// Nothing in the descriptor points at the patch. The client names it from the
// hash it has and the hash it wants, asks for it, and is simply told there is no
// such target when the publisher made none — which is what makes this an
// optimisation a repository can start and stop offering without any client
// caring.
func TestAChangedFileArrivesAsAPatch(t *testing.T) {
	t.Parallel()
	r := newRepo(t)
	r.publish("1.0.0", release{data: map[string]string{"share/readme.txt": "one"}})
	in := newInstall(t, r)
	if code, out := in.runInstaller(); code != exitOK {
		t.Fatalf("installer = %d: %s", code, out)
	}

	// The application binary of 1.1.0 differs from 1.0.0 only in the version
	// stamped into it — the shape a rebuilt binary usually has.
	r.publish("1.1.0", release{
		data:         map[string]string{"share/readme.txt": "one"},
		patchAgainst: 1,
	})

	r.srv.resetCounts()
	if code, out := in.selfUpdate(); code != exitOK {
		t.Fatalf("self-update = %d: %s", code, out)
	}

	if got := r.srv.patchRequests(); got == 0 {
		t.Error("no patch was fetched; the update took the full payload")
	}
	if got := r.srv.payloadRequests(); got != 0 {
		t.Errorf("%d payloads were fetched; the changed binary should have arrived as a patch", got)
	}
	// And the result is the real thing, not an approximation of it: the
	// application that was reconstructed runs and says which version it is.
	if code, out := runProc(t, in.appPath()); code != exitOK || !strings.Contains(out, "app 1.1.0") {
		t.Errorf("the patched application reports %q (%d)", out, code)
	}
}
