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

// Package e2elocal drives the parts of the update lifecycle the GitHub
// end-to-end test (test/e2e/run.sh) does not: a deferred update the launcher
// finishes, a process killed inside the transaction, a failing migration, the
// installer's downgrade preflight, a tampered payload and retention. Everything
// runs as separate processes — cmd/packer, cmd/installer, cmd/launcher and the
// hostapp fixture — against a repository served from 127.0.0.1, so it needs no
// network, no token and no GitHub.
//
// TEST KEYS ONLY. Role keys are generated per scenario by e2etool init-repo and
// thrown away with the scenario's directory (AGENTS.md §5, §7).
package e2elocal

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/packer"
)

// envWork names the directory the suite builds its binaries and keeps its
// install roots under. Every binary under test is executed from there, so it
// must be a place the host lets freshly built programs run. Unset, the suite
// uses `go env GOTMPDIR`, and then the system temp directory.
const envWork = "IDUNN_E2E_WORK"

// envKeep leaves every scenario's directory in place after the run.
const envKeep = "IDUNN_E2E_KEEP"

// Timeouts. They exist to turn a hang into a failure with a name attached.
const (
	buildTimeout = 5 * time.Minute
	procTimeout  = 3 * time.Minute
	lineTimeout  = time.Minute
)

// suite holds what TestMain prepares once per run.
var suite struct {
	repoRoot string // module root
	runDir   string // this run's scratch directory
	binDir   string

	packer    string
	e2etool   string
	installer string
	launcher  string

	mu   sync.Mutex
	apps map[string]*appBuild
}

type appBuild struct {
	once sync.Once
	path string
	err  error
}

func TestMain(m *testing.M) {
	code, err := setup()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "e2elocal: %v\n", err)
		code = 1
	}
	if code == 0 {
		code = m.Run()
	}
	if suite.runDir != "" && os.Getenv(envKeep) == "" && code == 0 {
		_ = os.RemoveAll(suite.runDir)
	} else if suite.runDir != "" {
		_, _ = fmt.Fprintf(os.Stderr, "e2elocal: work directory kept: %s\n", suite.runDir)
	}
	os.Exit(code)
}

func setup() (int, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return 1, errors.New("cannot locate the test source")
	}
	suite.repoRoot = filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	suite.apps = map[string]*appBuild{}

	base, err := workBase()
	if err != nil {
		return 1, err
	}
	if base != "" {
		if err := os.MkdirAll(base, 0o755); err != nil {
			return 1, err
		}
	}
	suite.runDir, err = os.MkdirTemp(base, "idunn-e2elocal-")
	if err != nil {
		return 1, err
	}
	suite.binDir = filepath.Join(suite.runDir, "bin")

	for _, b := range []struct {
		pkg     string
		out     *string
		ldflags string
	}{
		{"./cmd/packer", &suite.packer, ""},
		{"./test/e2e/cmd/e2etool", &suite.e2etool, ""},
		{"./cmd/installer", &suite.installer, ""},
		// The launcher bakes in what it starts; the application lives at the
		// same install-relative path in every release.
		{"./cmd/launcher", &suite.launcher, "-X main.appBinary=" + appDst},
	} {
		out := filepath.Join(suite.binDir, exe(filepath.Base(b.pkg)))
		if err := goBuild(out, b.pkg, b.ldflags); err != nil {
			return 1, err
		}
		*b.out = out
	}
	return 0, nil
}

// workBase picks where binaries are built and run. On Windows, endpoint
// protection commonly refuses to start a program that was just written below
// %TEMP%, which is where t.TempDir() and os.MkdirTemp("") put it.
func workBase() (string, error) {
	if dir := os.Getenv(envWork); dir != "" {
		return filepath.Abs(dir)
	}
	if dir := os.Getenv("GOTMPDIR"); dir != "" {
		return dir, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, "go", "env", "GOTMPDIR").Output()
	if err != nil {
		return "", fmt.Errorf("go env GOTMPDIR: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// goBuild builds pkg into out. extra goes before the package, for flags such as
// -overlay.
func goBuild(out, pkg, ldflags string, extra ...string) error {
	args := []string{"build", "-o", out}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, extra...)
	args = append(args, pkg)
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = suite.repoRoot
	if combined, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, combined)
	}
	return nil
}

// appBinary builds the hostapp fixture stamped with version, once per version.
func appBinary(t *testing.T, version string) string {
	t.Helper()
	suite.mu.Lock()
	b, ok := suite.apps[version]
	if !ok {
		b = &appBuild{}
		suite.apps[version] = b
	}
	suite.mu.Unlock()
	b.once.Do(func() {
		b.path = filepath.Join(suite.binDir, exe("hostapp-"+version))
		b.err = goBuild(b.path, "./test/e2e/local/cmd/hostapp", "-X main.version="+version)
	})
	if b.err != nil {
		t.Fatal(b.err)
	}
	return b.path
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// appDst is the install-relative path of the application in every release.
var appDst = "bin/" + exe("app")

// scenarioDir is a fresh directory for one test below the run directory, kept
// when the test fails so the install root can be inspected.
func scenarioDir(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "_", "\\", "_", " ", "_").Replace(t.Name())
	dir, err := os.MkdirTemp(suite.runDir, name+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() || os.Getenv(envKeep) != "" {
			t.Logf("scenario directory kept: %s", dir)
			return
		}
		_ = os.RemoveAll(dir)
	})
	return dir
}

// childEnv is the environment of every process under test: this one's, minus
// any role key variable it may have inherited, plus extra.
func childEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(name) {
		case packer.EnvTargetsKey, packer.EnvSnapshotKey, packer.EnvTimestampKey:
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

// repo is one throwaway TUF repository and the server that hands it out.
type repo struct {
	t       *testing.T
	dir     string // scenario directory
	tuf     string // the published repository: metadata/ and targets/
	anchor  string // the client's trust anchor, copied before any publish
	keyEnv  []string
	srv     *server
	channel string
}

// newRepo runs the throwaway root ceremony through e2etool init-repo, secures the
// anchor, and starts serving.
func newRepo(t *testing.T) *repo {
	t.Helper()
	dir := scenarioDir(t)
	r := &repo{t: t, dir: dir, tuf: filepath.Join(dir, "repo"), channel: "stable"}
	keys := filepath.Join(dir, "keys")

	code, out := runProc(t, suite.e2etool, "init-repo", "--repo", r.tuf, "--keys", keys)
	if code != 0 {
		t.Fatalf("e2etool init-repo = %d\n%s", code, out)
	}
	// The packer gets the three publishing keys and nothing else. init-repo
	// prints exactly those; anything more would be a key this suite must not
	// hand to a tool that runs on every release.
	want := map[string]bool{packer.EnvTargetsKey: true, packer.EnvSnapshotKey: true, packer.EnvTimestampKey: true}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		name, _, ok := strings.Cut(line, "=")
		if !ok || !want[name] {
			t.Fatalf("e2etool init-repo printed %q, which is not a publishing key variable", line)
		}
		delete(want, name)
		r.keyEnv = append(r.keyEnv, line)
	}
	if len(want) != 0 {
		t.Fatalf("e2etool init-repo did not name every publishing key: missing %v", want)
	}
	// The root key has signed 1.root.json and has no further business here.
	// Removing it means nothing later in the scenario can sign a trust anchor.
	if err := os.Remove(filepath.Join(keys, "root.pem")); err != nil {
		t.Fatalf("removing the root key after the ceremony: %v", err)
	}

	// The anchor the client ships with is a copy taken before anything is
	// published. A client that read it out of the served repository would be
	// trusting the server to tell it whom to trust.
	raw, err := os.ReadFile(filepath.Join(r.tuf, packer.MetadataDir, "1.root.json"))
	if err != nil {
		t.Fatal(err)
	}
	r.anchor = filepath.Join(dir, "anchor", "root.json")
	if err := os.MkdirAll(filepath.Dir(r.anchor), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.anchor, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r.srv = serve(t, r.tuf)
	return r
}

// dataContent is what the data file of a release says; the tamper scenario
// locates the payload by the hash of these bytes.
func dataContent(version string) []byte { return []byte("release " + version + "\n") }

// publish builds hostapp at version and runs the real packer over it and one
// data file.
func (r *repo) publish(version string) {
	r.t.Helper()
	src := filepath.Join(r.dir, "build", version)
	if err := os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		r.t.Fatal(err)
	}
	raw, err := os.ReadFile(appBinary(r.t, version))
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, filepath.FromSlash(appDst)), raw, 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "version.txt"), dataContent(version), 0o644); err != nil {
		r.t.Fatal(err)
	}
	cfg := fmt.Sprintf(`name: hostapp
version: %s
channel: %s
targets:
  - os: %s
    arch: %s
    files:
      - { src: %s, dst: %s, kind: exe, mode: "0755" }
      - { src: version.txt, dst: share/version.txt, kind: data }
`, version, r.channel, runtime.GOOS, runtime.GOARCH, appDst, appDst)
	cfgPath := filepath.Join(src, "pack.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		r.t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(r.t.Context(), procTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, suite.packer, "publish",
		"--config", cfgPath,
		"--repo", r.tuf,
		// The binaries under test judge expiry against the real clock, so the
		// metadata is stamped with it. Reproducibility of packer output is
		// pinned by internal/packer's golden test, not here.
		"--now", time.Now().UTC().Format(time.RFC3339),
	)
	cmd.Env = childEnv(r.keyEnv...)
	if out, err := cmd.CombinedOutput(); err != nil {
		r.t.Fatalf("packer publish %s: %v\n%s", version, err, out)
	}
}

// server serves a published repository and records what it answered.
type server struct {
	*httptest.Server
	payloads atomic.Int64

	mu     sync.Mutex
	served map[string][]response // by URL path
}

// response is one answer the server gave: its status and how many body bytes
// actually went out.
type response struct {
	status int
	bytes  int64
}

func serve(t *testing.T, dir string) *server {
	t.Helper()
	s := &server{served: map[string][]response{}}
	mux := http.NewServeMux()
	mux.Handle("/metadata/", http.StripPrefix("/metadata/",
		http.FileServer(http.Dir(filepath.Join(dir, packer.MetadataDir)))))
	mux.Handle("/targets/", http.StripPrefix("/targets/",
		http.FileServer(http.Dir(filepath.Join(dir, packer.TargetsDir)))))
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/targets/payloads/") {
			s.payloads.Add(1)
		}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(rec, req)
		s.mu.Lock()
		s.served[req.URL.Path] = append(s.served[req.URL.Path], response{status: rec.status, bytes: rec.bytes})
		s.mu.Unlock()
	}))
	t.Cleanup(s.Close)
	return s
}

// responses returns what the server answered for one URL path.
func (s *server) responses(path string) []response {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]response(nil), s.served[path]...)
}

type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (s *server) metadataURL() string { return s.URL + "/metadata/" }
func (s *server) targetsURL() string  { return s.URL + "/targets/" }

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

// install is one install root and the client-side state around it.
type install struct {
	t     *testing.T
	repo  *repo
	root  string
	cache string // the client's TUF cache, shared by installer and app
	data  string // host state outside the root, for the migration hook
	lock  string // the application lock file
}

func newInstall(t *testing.T, r *repo) *install {
	t.Helper()
	return &install{
		t:     t,
		repo:  r,
		root:  filepath.Join(r.dir, "install"),
		cache: filepath.Join(r.dir, "cache"),
		data:  filepath.Join(r.dir, "hostdata"),
		lock:  filepath.Join(r.dir, "app.lock"),
	}
}

// runInstaller runs cmd/installer against the served repository.
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
	return runProc(in.t, suite.installer, args...)
}

// mustInstall installs the channel head and checks it arrived.
func (in *install) mustInstall(version string) {
	in.t.Helper()
	if code, out := in.runInstaller(); code != 0 {
		in.t.Fatalf("installer = %d, want 0\n%s", code, out)
	}
	in.observe().settled(in.t, version, version)
}

// runLauncher starts the installed application through cmd/launcher.
func (in *install) runLauncher(extra ...string) (int, string) {
	in.t.Helper()
	return runProc(in.t, suite.launcher, append([]string{"-root", in.root}, extra...)...)
}

// appPath is the installed application of the version the pointer names.
func (in *install) appPath() string {
	in.t.Helper()
	v, err := installer.InstalledVersion(in.root)
	if err != nil || v == "" {
		in.t.Fatalf("no installed application under %s (%q, %v)", in.root, v, err)
	}
	return filepath.Join(in.root, layout.VersionsName, v, filepath.FromSlash(appDst))
}

// selfUpdateArgs is the command line of the installed application updating
// itself.
func (in *install) selfUpdateArgs(extra ...string) []string {
	return append([]string{
		"--self-update",
		"--root", in.root,
		"--metadata-url", in.repo.srv.metadataURL(),
		"--targets-url", in.repo.srv.targetsURL(),
		"--root-metadata", in.repo.anchor,
		"--cache", in.cache,
	}, extra...)
}

// selfUpdate runs the installed application and has it update itself: the
// binary being replaced is the one running.
func (in *install) selfUpdate(extra ...string) (int, string) {
	in.t.Helper()
	return runProc(in.t, in.appPath(), in.selfUpdateArgs(extra...)...)
}

// state is what an install root says about itself, read without the network.
type state struct {
	installed  string // pointer and recorded state agreeing; "" for none
	versions   []string
	staging    int
	journal    txn.Record
	hasJournal bool
	records    int
}

func (in *install) observe() state {
	in.t.Helper()
	var s state
	var err error
	if s.installed, err = installer.InstalledVersion(in.root); err != nil {
		in.t.Fatalf("install state: %v", err)
	}
	s.versions = dirNames(in.t, filepath.Join(in.root, layout.VersionsName))
	s.staging = len(dirNames(in.t, layout.Staging(in.root)))
	j, err := txn.Open(fsx.OS(), in.root)
	if err != nil {
		in.t.Fatalf("journal: %v", err)
	}
	s.journal, s.hasJournal = j.Last()
	s.records = len(j.Records())
	return s
}

func (s state) String() string {
	return fmt.Sprintf("installed=%q versions=%v staging=%d journal=%s:%s->%s (%d records)",
		s.installed, s.versions, s.staging, s.journal.State, s.journal.FromVersion, s.journal.ToVersion, s.records)
}

// settled asserts the state a committed transaction leaves behind.
func (s state) settled(t *testing.T, version string, versions ...string) {
	t.Helper()
	if s.installed != version || !equal(s.versions, versions) || s.staging != 0 ||
		s.journal.State != txn.StateCommitted || s.journal.ToVersion != version {
		t.Fatalf("want %s committed with versions %v and empty staging; got %s", version, versions, s)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

// runProc runs one process to completion and returns its exit code and combined
// output.
func runProc(t *testing.T, name string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), procTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = childEnv()
	out, err := cmd.CombinedOutput()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("running %s: %v", filepath.Base(name), err)
	}
	return cmd.ProcessState.ExitCode(), strings.ReplaceAll(string(out), "\r\n", "\n")
}

// proc is a process the scenario keeps running while it does something else.
type proc struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string
	out   bytes.Buffer // everything read so far
	mu    sync.Mutex
	done  chan struct{}
}

// startProc starts a process with its stdin and stdout connected to the test.
// It is killed when the test ends, whatever happened.
func startProc(t *testing.T, name string, args ...string) *proc {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...)
	cmd.Env = childEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", filepath.Base(name), err)
	}
	p := &proc{t: t, cmd: cmd, stdin: stdin, lines: make(chan string, 256), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			p.mu.Lock()
			p.out.WriteString(line + "\n")
			p.mu.Unlock()
			select {
			case p.lines <- line:
			default:
			}
		}
	}()
	t.Cleanup(func() {
		_ = p.cmd.Process.Kill()
		<-p.done
		_ = p.cmd.Wait()
	})
	return p
}

// waitFor blocks until the process prints line.
func (p *proc) waitFor(line string) {
	p.t.Helper()
	timeout := time.After(lineTimeout)
	for {
		select {
		case got := <-p.lines:
			if strings.TrimSpace(got) == line {
				return
			}
		case <-p.done:
			p.t.Fatalf("the process exited before printing %q:\n%s", line, p.output())
		case <-timeout:
			p.t.Fatalf("timed out waiting for %q:\n%s", line, p.output())
		}
	}
}

func (p *proc) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// closeStdin asks the process to finish and waits for its exit code.
func (p *proc) closeStdin() int {
	p.t.Helper()
	_ = p.stdin.Close()
	select {
	case <-p.done:
	case <-time.After(lineTimeout):
		p.t.Fatalf("the process did not exit after stdin closed:\n%s", p.output())
	}
	_ = p.cmd.Wait()
	return p.cmd.ProcessState.ExitCode()
}

// kill ends the process abruptly — SIGKILL, TerminateProcess — and waits for it.
func (p *proc) kill() {
	p.t.Helper()
	if err := p.cmd.Process.Kill(); err != nil {
		p.t.Fatalf("killing the process: %v", err)
	}
	<-p.done
	_ = p.cmd.Wait()
}
