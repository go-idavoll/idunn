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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/internal/layout"
)

// The accounts of the service scenario. Numeric on purpose: the kernel decides
// on uids, not on names, and neither needs an entry in /etc/passwd.
const (
	appUID   = 65534 // nobody: the account the application runs as, allowed by the administrator
	appGID   = 65534
	otherUID = 1 // daemon: a local account nobody allowed
	otherGID = 1
)

// hostapp's exit codes for an elevated apply (cmd/hostapp).
const (
	appDenied = 5 // elevate.ErrDenied
	appHelper = 6 // elevate.ErrHelper: the helper refused or failed the apply
)

// helperInterval is the helper's min_interval_seconds in this build: short, so
// the scenario does not wait five seconds between requests, and still enforced.
const helperInterval = 1 * time.Second

// ---------------------------------------------------------------------------
// 7. Service mode: a system-wide root owned by root, maintained only by the
//    reference helper, for an application running as an ordinary user
//    (docs/helper.md, §14.2, §14.8).
// ---------------------------------------------------------------------------

func TestServiceModeInstallsAndUpdatesThroughTheHelper(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("service mode needs root: cmd/helper serves as root and the application runs as uid 65534 " +
			"(CI runs this scenario with sudo; see test/e2e/local/README.md)")
	}
	// Not parallel: it creates system-wide paths under /etc, /run and /usr/local.

	label := fmt.Sprintf("io.idunn-e2e.h%d", os.Getpid())
	paths, err := elevate.DefaultHelperPaths(label)
	if err != nil {
		t.Fatal(err)
	}
	// Below /usr/local, which is root:root 0755. Not /opt: GitHub's Ubuntu
	// runners have it world-writable, and CheckPrivilegedRoot rightly refuses
	// every root below it.
	base := fmt.Sprintf("/usr/local/idunn-e2e-%d", os.Getpid())
	root := filepath.Join(base, "app")
	system := []string{paths.StateDir, filepath.Dir(paths.Endpoint), base}
	for _, p := range system {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s already exists (%v); this run neither runs over nor removes what it did not create", p, err)
		}
	}
	// Registered first, so it runs last: after the helper has stopped, and
	// whether or not the scenario passed. These paths are the machine's, not the
	// scenario directory's, so they are never kept.
	t.Cleanup(func() {
		for _, p := range system {
			if err := os.RemoveAll(p); err != nil {
				t.Errorf("removing %s: %v", p, err)
			}
		}
	})

	r := newRepo(t)
	r.publish("1.0.0")

	// --- The unprivileged side's files: a directory other users can reach, ---
	// --- outside the run directory, which is root's and 0700.              ---
	world := worldDir(t)
	app := filepath.Join(world, "bin", "hostapp")
	copyFile(t, appBinary(t, "1.0.0"), app, 0o755)
	anchor := filepath.Join(world, "root.json")
	copyFile(t, r.anchor, anchor, 0o644)
	appCache := ownedDir(t, filepath.Join(world, "cache-app"), appUID, appGID)
	otherCache := ownedDir(t, filepath.Join(world, "cache-other"), otherUID, otherGID)
	if code, out := runAs(t, appUID, appGID, world, "/bin/sh", "-c", `test -x "$1"`, "sh", app); code != 0 {
		t.Fatalf("uid %d cannot reach %s (%d: %s); run from a work directory other users can traverse (IDUNN_E2E_WORK)",
			appUID, app, code, out)
	}

	// --- The helper, built with an anchor for this repository. ---
	helper := buildHelper(t, r, label, root)

	code, out := runProc(t, helper, "check")
	t.Logf("helper check before allow = %d:\n%s", code, out)
	if code != exitOK || !strings.Contains(out, "callers:   none") {
		t.Fatalf("helper check before allow = %d, want %d and no callers\n%s", code, exitOK, out)
	}
	if code, out := runProc(t, helper, "allow", "--uid", fmt.Sprint(appUID)); code != exitOK {
		t.Fatalf("helper allow --uid %d = %d\n%s", appUID, code, out)
	}
	code, out = runProc(t, helper, "check")
	t.Logf("helper check after allow = %d:\n%s", code, out)
	if code != exitOK || !strings.Contains(out, fmt.Sprintf("callers:   uids [%d]", appUID)) {
		t.Fatalf("helper check after allow = %d, want %d naming uid %d\n%s", code, exitOK, appUID, out)
	}
	assertRootOnly(t, paths.StateDir)

	hp := startHelper(t, helper, paths.Endpoint)

	serviceArgs := func(cache string) []string {
		return []string{
			"--self-update",
			"--service", paths.Endpoint,
			"--root", root,
			"--metadata-url", r.srv.metadataURL(),
			"--targets-url", r.srv.targetsURL(),
			"--root-metadata", anchor,
			"--cache", cache,
		}
	}
	in := &install{t: t, repo: r, root: root}

	// --- Before anything: the application cannot create the root itself. ---
	if code, out := runAs(t, appUID, appGID, world, "/bin/sh", "-c", `mkdir -p "$1"`, "sh", root); code == 0 {
		t.Fatalf("uid %d created %s itself; the scenario proves nothing on this machine\n%s", appUID, root, out)
	}

	// --- A local account nobody allowed is denied, and nothing is written. ---
	code, out = runAs(t, otherUID, otherGID, world, app, serviceArgs(otherCache)...)
	if code != appDenied || !strings.Contains(out, "denied") {
		t.Fatalf("install as uid %d, which is not a caller = %d, want %d (elevate.ErrDenied)\n%s", otherUID, code, appDenied, out)
	}
	hp.waitLog(t, fmt.Sprintf("uid %d may not ask this helper", otherUID))
	if _, err := os.Lstat(base); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a denied request left %s behind (%v)", base, err)
	}

	// --- Install 1.0.0 through the helper. ---
	code, out = runAs(t, appUID, appGID, world, app, serviceArgs(appCache)...)
	if !strings.Contains(out, fmt.Sprintf("euid %d", appUID)) {
		t.Errorf("the application did not run as uid %d:\n%s", appUID, out)
	}
	if code != exitOK || !strings.Contains(out, "updated  -> 1.0.0") {
		// Not fatal yet: what the helper did to the root is checked next, and
		// the two answers together say which side went wrong.
		t.Errorf("install through the helper = %d, want %d reporting 1.0.0\n%s", code, exitOK, out)
	}
	in.observe().settled(t, "1.0.0", "1.0.0")
	hp.waitLog(t, fmt.Sprintf("applied 1.0.0 for uid %d", appUID))
	last := time.Now()
	assertServiceInstall(t, in, world, appCache, "1.0.0")

	// --- Update to 1.1.0 through the helper. ---
	r.publish("1.1.0")
	waitInterval(last)
	code, out = runAs(t, appUID, appGID, world, app, serviceArgs(appCache)...)
	if code != exitOK || !strings.Contains(out, "updated 1.0.0 -> 1.1.0") {
		t.Errorf("update through the helper = %d, want %d reporting 1.0.0 -> 1.1.0\n%s", code, exitOK, out)
	}
	in.observe().settled(t, "1.1.0", "1.0.0", "1.1.0")
	hp.waitLog(t, fmt.Sprintf("applied 1.1.0 for uid %d", appUID))
	last = time.Now()
	assertServiceInstall(t, in, world, appCache, "1.1.0")

	// --- A request for a release that is not the channel head is refused. ---
	// 1.2.0 is newer than what is installed and signed like any other release;
	// what makes it wrong is that the publisher's channel names 1.3.0, and which
	// release a machine gets is not the caller's choice.
	r.publish("1.2.0")
	r.publish("1.3.0")
	before := in.observe()
	pointer := fileDigest(t, layout.Current(root))
	waitInterval(last)
	code, out = runAs(t, appUID, appGID, world, app,
		"--service", paths.Endpoint, "--root", root, "--channel", r.channel, "--request-version", "1.2.0")
	if code != appHelper || !strings.Contains(out, "the privileged apply failed") {
		t.Fatalf("a request for 1.2.0 behind the channel head = %d, want %d (the helper answers error apply)\n%s",
			code, appHelper, out)
	}
	hp.waitLog(t, "apply failed: release no longer applies to this install: 1.2.0 was requested")
	after := in.observe()
	if after.String() != before.String() || fileDigest(t, layout.Current(root)) != pointer {
		t.Fatalf("a refused request changed the install:\nbefore %s\nafter  %s", before, after)
	}
	if strings.Contains(hp.log(), "applied 1.2.0") {
		t.Fatalf("the helper logged applying 1.2.0:\n%s", hp.log())
	}

	if code := hp.stop(t); code != exitOK || !strings.HasSuffix(hp.log(), " stopped\n") {
		t.Errorf("helper serve after SIGTERM = %d, want %d and a stopped line", code, exitOK)
	}
	t.Logf("helper log:\n%s", hp.log())
}

// assertServiceInstall checks what a system-wide install maintained by the
// helper must look like after an apply: everything under the root is root's;
// the helper's TUF cache is inside the root and the application's cache holds
// nothing of root's; the application's user can neither write the root nor any
// file in it, and can run the installed application.
func assertServiceInstall(t *testing.T, in *install, world, appCache, version string) {
	t.Helper()
	root := in.root

	var foreign []string
	err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if uid := ownerOf(t, p); uid != 0 {
			foreign = append(foreign, fmt.Sprintf("%s (uid %d)", p, uid))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(foreign) > 0 {
		t.Errorf("entries under the root not owned by root: %v", foreign)
	}

	// §14.8, T23: the privileged side verifies with its own metadata, kept where
	// only it can write.
	cache := elevate.PrivilegedCacheDir(root)
	if want := filepath.Join(root, layout.MetaName, layout.TrustCacheName); cache != want {
		t.Fatalf("PrivilegedCacheDir = %s, want %s", cache, want)
	}
	for _, name := range []string{"root.json", "timestamp.json"} {
		if _, err := os.Stat(filepath.Join(cache, "metadata", name)); err != nil {
			t.Errorf("the helper's TUF cache has no %s: %v", name, err)
		}
	}
	var appFiles int
	err = filepath.WalkDir(appCache, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		appFiles++
		if uid := ownerOf(t, p); uid != appUID {
			t.Errorf("%s in the application's cache is owned by uid %d: the helper wrote where the caller can", p, uid)
		}
		return nil
	})
	if err != nil || appFiles < 2 {
		t.Errorf("the application's own cache %s holds %d entries (%v); it refreshes with its own client", appCache, appFiles, err)
	}

	// The application's user writes nothing: not a new entry in the root, not
	// the pointer, not an installed file, not the journal's directory, not the
	// helper's metadata.
	app := filepath.Join(root, layout.VersionsName, version, filepath.FromSlash(appDst))
	probes := []struct{ script, path string }{
		{`printf x > "$1"`, filepath.Join(root, "probe")},
		{`printf x >> "$1"`, layout.Current(root)},
		{`rm -f "$1"`, layout.Current(root)},
		{`printf x >> "$1"`, app},
		{`mkdir "$1"`, filepath.Join(root, layout.VersionsName, "9.9.9")},
		{`printf x > "$1"`, filepath.Join(layout.Meta(root), "probe")},
		{`printf x >> "$1"`, filepath.Join(cache, "metadata", "root.json")},
	}
	digests := map[string]string{}
	for _, p := range probes {
		if _, err := os.Lstat(p.path); err == nil {
			digests[p.path] = fileDigest(t, p.path)
		}
	}
	for _, p := range probes {
		if code, out := runAs(t, appUID, appGID, world, "/bin/sh", "-c", p.script, "sh", p.path); code == 0 {
			t.Errorf("uid %d could run %q on %s\n%s", appUID, p.script, p.path, out)
		}
	}
	for _, p := range probes {
		want, existed := digests[p.path]
		switch _, err := os.Lstat(p.path); {
		case !existed && err == nil:
			t.Errorf("uid %d created %s", appUID, p.path)
		case existed && err != nil:
			t.Errorf("uid %d removed %s: %v", appUID, p.path, err)
		case existed && fileDigest(t, p.path) != want:
			t.Errorf("uid %d changed %s", appUID, p.path)
		}
	}

	// A system-wide install exists to be run by the machine's users.
	if code, out := runAs(t, appUID, appGID, world, app); code != exitOK || !strings.Contains(out, "app "+version) {
		t.Errorf("uid %d running the installed %s = %d %q, want app %s; modes along the way: %s",
			appUID, app, code, out, version, modesAlong(root, app))
	}
}

// buildHelper builds cmd/helper with an anchor for r, a label and one allowed
// root. The three build-time files are generated into the scenario directory and
// laid over cmd/helper/anchor/ with -overlay, so the tree's own anchor directory
// is never written — it is where a publisher's files would be.
func buildHelper(t *testing.T, r *repo, label, root string) string {
	t.Helper()
	rootJSON, err := os.ReadFile(r.anchor)
	if err != nil {
		t.Fatal(err)
	}
	repoJSON, err := json.Marshal(map[string]string{
		"metadata_url": r.srv.metadataURL(),
		"targets_url":  r.srv.targetsURL(),
		"channel":      r.channel,
	})
	if err != nil {
		t.Fatal(err)
	}
	helperJSON, err := json.Marshal(map[string]any{
		"label":                label,
		"allowed_roots":        []string{root},
		"min_interval_seconds": int(helperInterval / time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(r.dir, "helper")
	src := filepath.Join(dir, "anchor")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	anchorDir := filepath.Join(suite.repoRoot, "cmd", "helper", "anchor")
	replace := map[string]string{}
	for name, body := range map[string][]byte{"root.json": rootJSON, "repository.json": repoJSON, "helper.json": helperJSON} {
		p := filepath.Join(src, name)
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(anchorDir, name)] = p
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}

	beforeTree := dirNames(t, anchorDir)
	out := filepath.Join(dir, label)
	if err := goBuild(out, "./cmd/helper", "-X main.version=1.0.0", "-overlay", overlayPath); err != nil {
		t.Fatal(err)
	}
	if afterTree := dirNames(t, anchorDir); !slices.Equal(beforeTree, afterTree) {
		t.Fatalf("building the helper changed %s: %v, then %v", anchorDir, beforeTree, afterTree)
	}
	if code, out := runProc(t, out, "version"); code != exitOK || strings.TrimSpace(out) != "1.0.0" {
		t.Fatalf("helper version = %d %q", code, out)
	}
	return out
}

// helperProc is `helper serve`, running as root for the length of the scenario.
type helperProc struct {
	cmd  *exec.Cmd
	out  *lockedBuffer
	done chan struct{}
}

func startHelper(t *testing.T, bin, endpoint string) *helperProc {
	t.Helper()
	h := &helperProc{out: &lockedBuffer{}, done: make(chan struct{})}
	// Not the test's context: that ends before the cleanups run and would kill
	// the helper; it is stopped with SIGTERM, as systemd stops it, or killed by
	// the cleanup below.
	h.cmd = exec.CommandContext(context.Background(), bin, "serve")
	h.cmd.Env = childEnv()
	h.cmd.Stdout = h.out
	h.cmd.Stderr = h.out
	if err := h.cmd.Start(); err != nil {
		t.Fatalf("starting helper serve: %v", err)
	}
	go func() {
		_ = h.cmd.Wait()
		close(h.done)
	}()
	t.Cleanup(func() {
		select {
		case <-h.done:
		default:
			_ = h.cmd.Process.Kill()
			<-h.done
		}
		// The helper's reasons never reach the caller, only its log: without it
		// a failed scenario says "denied" and nothing about why.
		if t.Failed() {
			t.Logf("helper log:\n%s", h.log())
		}
	})

	deadline := time.After(lineTimeout)
	for {
		if st, err := os.Lstat(endpoint); err == nil && st.Mode()&fs.ModeSocket != 0 {
			return h
		}
		select {
		case <-h.done:
			t.Fatalf("helper serve exited before listening (%d):\n%s", h.cmd.ProcessState.ExitCode(), h.log())
		case <-deadline:
			t.Fatalf("helper serve did not create %s:\n%s", endpoint, h.log())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (h *helperProc) log() string { return h.out.String() }

// waitLog waits until the helper's log contains every one of lines. The helper
// logs a decision before it answers, but its output reaches this process through
// a pipe, a moment later.
func (h *helperProc) waitLog(t *testing.T, lines ...string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		log := h.log()
		missing := ""
		for _, l := range lines {
			if !strings.Contains(log, l) {
				missing = l
				break
			}
		}
		if missing == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the helper log has no %q:\n%s", missing, log)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop sends SIGTERM and returns the helper's exit code.
func (h *helperProc) stop(t *testing.T) int {
	t.Helper()
	if err := h.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stopping the helper: %v", err)
	}
	select {
	case <-h.done:
	case <-time.After(lineTimeout):
		t.Fatalf("the helper did not stop after SIGTERM:\n%s", h.log())
	}
	return h.cmd.ProcessState.ExitCode()
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runAs runs a process as uid:gid with no supplementary groups, in dir. The
// credentials are dropped by the kernel between fork and exec; the child never
// runs a line of its own code as root.
func runAs(t *testing.T, uid, gid uint32, dir, name string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), procTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = childEnv("HOME=" + dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}},
	}
	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("running %s as uid %d: %v", filepath.Base(name), uid, err)
	}
	return cmd.ProcessState.ExitCode(), string(out)
}

// worldDir is a directory other users can traverse, next to the run directory:
// the run directory itself is 0700 and root's, and the application's user must
// reach its binary, its anchor and its cache.
func worldDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(filepath.Dir(suite.runDir), "idunn-e2e-service-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() || os.Getenv(envKeep) != "" {
			t.Logf("service directory kept: %s", dir)
			return
		}
		_ = os.RemoveAll(dir)
	})
	//nolint:gosec // G302: other users must traverse it; nothing in it is secret.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// ownedDir creates a 0700 directory belonging to uid:gid.
func ownedDir(t *testing.T, dir string, uid, gid int) string {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		t.Fatal(err)
	}
	return dir
}

func copyFile(t *testing.T, src, dst string, mode fs.FileMode) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G301: other users must reach the file.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, raw, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the umask.
	if err := os.Chmod(dst, mode); err != nil {
		t.Fatal(err)
	}
}

func ownerOf(t *testing.T, p string) uint32 {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no owner for %s", p)
	}
	return sys.Uid
}

// assertRootOnly requires a directory owned by root that nobody else can write.
func assertRootOnly(t *testing.T, dir string) {
	t.Helper()
	st, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !st.IsDir() || ownerOf(t, dir) != 0 || st.Mode().Perm()&0o022 != 0 {
		t.Fatalf("%s is %s owned by uid %d, want a root-owned directory nobody else can write", dir, st.Mode(), ownerOf(t, dir))
	}
}

// fileDigest identifies what is at p: a file's contents, or, for a symlink such as
// the `current` pointer, where it points.
func fileDigest(t *testing.T, p string) string {
	t.Helper()
	st, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if st.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Readlink(p)
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte("symlink:" + target)
	} else if raw, err = os.ReadFile(p); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// modesAlong describes the owner and mode of every directory from root down to
// target, for a failure message.
func modesAlong(root, target string) string {
	var parts []string
	for p := target; ; p = filepath.Dir(p) {
		if st, err := os.Lstat(p); err == nil {
			uid := uint32(0)
			if sys, ok := st.Sys().(*syscall.Stat_t); ok {
				uid = sys.Uid
			}
			parts = append(parts, fmt.Sprintf("%s %s uid %d", p, st.Mode(), uid))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %v", p, err))
		}
		if p == root || filepath.Dir(p) == p {
			break
		}
	}
	slices.Reverse(parts)
	return strings.Join(parts, "; ")
}

// waitInterval lets the helper's rate limit pass since the last accepted
// request, so a refusal below is the one the scenario provoked.
func waitInterval(last time.Time) {
	if d := helperInterval + 500*time.Millisecond - time.Since(last); d > 0 {
		time.Sleep(d)
	}
}
