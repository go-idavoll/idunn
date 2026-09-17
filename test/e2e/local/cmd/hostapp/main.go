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

// Command hostapp is the host application the local end-to-end suite
// (test/e2e/local) publishes, installs, launches and updates. It is a fixture,
// not a product.
//
// Unlike test/e2e/cmd/e2eapp it embeds nothing: the suite runs many throwaway
// repositories side by side, so the trust anchor and the repository URLs are
// flags. What it adds are the seams the local scenarios need and the GitHub run
// cannot drive: a lock a second process holds, a host migration that records
// what it did and can be told to fail, and a phase to stop in so the suite can
// kill the process there.
//
//	hostapp                         print "app <version>" and exit
//	hostapp --hold-lock --lock L    take the lock, print "holding", keep it
//	                                until stdin closes
//	hostapp --self-update ...       check the channel and apply what it names
//	  --hold-own-lock               hold --lock itself while updating, as a running
//	                                application does, so the update defers
//	  --relaunch-via <launcher>     afterwards, launch.Relaunch through that
//	                                launcher and exit with its code (IDN-29)
//	hostapp --self-update --service E ...
//	                                the same, but the install root belongs to a
//	                                privileged helper listening on E, which
//	                                applies the update (updater.ElevationService)
//	hostapp --service E --root R --request-version V
//	                                send the helper a bare request for V, with no
//	                                trust client and no resolution on this side:
//	                                a caller asking for what the channel does not
//	                                offer
//	hostapp --linger --state D --name N
//	                                run until a console control event or a
//	                                termination request arrives, then take
//	                                --work to shut down cleanly (IDN-40)
//	  --spawn M                     first start a lingering child named M
//	  --console-window              record the console window handle, for a
//	                                scenario that closes it
//	  --exit-after D                exit 0 on its own after D, leaving the
//	                                --spawn child running
//
// Exit codes: 0 ok, 1 error, 2 usage, 3 already up to date, 4 deferred to the
// next start, 5 denied by the helper (elevate.ErrDenied), 6 the helper refused
// or failed the apply (elevate.ErrHelper), 7 shut down cleanly after a console
// control event or termination request (--linger).
//
// Build-time configuration:
//
//	-X main.version=1.0.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
)

// version is the release this binary belongs to. The suite tells trees apart by
// it, so it is the one thing that must differ between two builds.
var version = "0.0.0"

const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNoUpdate = 3
	exitDeferred = 4
	exitDenied   = 5
	exitHelper   = 6
	exitSignaled = 7
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

type config struct {
	root, channel, metadataURL, targetsURL, anchor, cache string

	lockFile    string
	onBusy      string
	quiesce     time.Duration
	retain      int
	data        string
	failMigrate bool
	hangAt      string

	holdOwnLock    bool
	relaunchVia    string
	args           []string // this run's own arguments, for the relaunch
	service        string
	requestVersion string

	state         string
	name          string
	spawn         string
	work          time.Duration
	consoleWindow bool
	exitAfter     time.Duration
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hostapp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	selfUpdate := fs.Bool("self-update", false, "check the channel and apply what it names")
	holdLock := fs.Bool("hold-lock", false, "take --lock and hold it until stdin closes")
	fs.StringVar(&c.root, "root", "", "install root")
	fs.StringVar(&c.channel, "channel", "stable", "channel to follow")
	fs.StringVar(&c.metadataURL, "metadata-url", "", "TUF metadata URL")
	fs.StringVar(&c.targetsURL, "targets-url", "", "TUF targets URL")
	fs.StringVar(&c.anchor, "root-metadata", "", "trust anchor file")
	fs.StringVar(&c.cache, "cache", "", "TUF metadata and target cache")
	fs.StringVar(&c.lockFile, "lock", "", "path of the exclusive application lock")
	fs.StringVar(&c.onBusy, "on-busy", "abort", "abort|defer")
	fs.DurationVar(&c.quiesce, "quiesce", time.Second, "how long to wait for the lock")
	fs.IntVar(&c.retain, "retain", 2, "version directories to keep after a commit")
	fs.StringVar(&c.data, "data", "", "host state directory the migration hook works on")
	fs.BoolVar(&c.failMigrate, "fail-migrate", false, "make the migration fail after it changed host state")
	fs.StringVar(&c.hangAt, "hang-at", "", "stop and wait to be killed the moment this phase is entered")
	fs.BoolVar(&c.holdOwnLock, "hold-own-lock", false, "hold --lock while updating, as a running instance does")
	fs.StringVar(&c.relaunchVia, "relaunch-via", "", "after the update, relaunch through this launcher")
	fs.StringVar(&c.service, "service", "", "endpoint of the privileged helper that owns --root")
	fs.StringVar(&c.requestVersion, "request-version", "", "with --service: ask the helper for this version, resolving nothing here")
	lingerMode := fs.Bool("linger", false, "run until a console control event or termination request arrives")
	fs.StringVar(&c.state, "state", "", "with --linger: directory the process reports into")
	fs.StringVar(&c.name, "name", "app", "with --linger: the name its files in --state carry")
	fs.StringVar(&c.spawn, "spawn", "", "with --linger: first start a lingering child of this name")
	fs.DurationVar(&c.work, "work", time.Second, "with --linger: how long a clean shutdown takes")
	fs.BoolVar(&c.consoleWindow, "console-window", false, "with --linger: record the console window handle")
	fs.DurationVar(&c.exitAfter, "exit-after", 0, "with --linger: exit 0 on its own after this long, leaving --spawn running")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	c.args = args

	switch {
	case *lingerMode:
		return linger(c, stderr)
	case *holdLock:
		return hold(c.lockFile, stdin, stdout, stderr)
	case c.requestVersion != "":
		return request(c, stdout, stderr)
	case *selfUpdate:
		return doSelfUpdate(c, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stdout, "app %s\n", version)
		return exitOK
	}
}

// linger is an application that runs until it is told to stop and then needs
// time to stop cleanly: the application a launcher must neither leave behind
// nor cut short (IDN-40). It reports into --state, one file per fact, rather
// than on stdout: a pipe held by a process that outlives its parent is exactly
// what the scenarios provoke, and a reader waiting for its EOF would hang.
//
//	<name>.hwnd    the console window handle (--console-window)
//	<name>.pid     written last during start-up: the handler is installed and,
//	               with --spawn, the child started
//	<name>.signal  what arrived
//	<name>.done    the clean shutdown finished; the process exits 7 right after
//
// os.Interrupt is Ctrl+C and Ctrl+Break. On Windows syscall.SIGTERM is a close,
// logoff or shutdown event, and Go keeps the process alive while it is being
// handled, so the --work that follows runs inside the grace period Windows
// gives.
func linger(c config, stderr io.Writer) int {
	if c.state == "" {
		_, _ = fmt.Fprintln(stderr, "hostapp: --linger needs --state")
		return exitUsage
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if c.spawn != "" {
		self, err := os.Executable()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
			return exitError
		}
		//nolint:gosec // G204: the fixture starts itself.
		child := exec.CommandContext(context.Background(), self,
			"--linger", "--state", c.state, "--name", c.spawn, "--work", c.work.String())
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintf(stderr, "hostapp: --spawn: %v\n", err)
			return exitError
		}
		// Not waited for: what becomes of it is what the scenario looks at.
		_ = child.Process.Release()
	}
	if c.consoleWindow {
		if err := report(c, "hwnd", strconv.FormatUint(uint64(consoleWindow()), 10)); err != nil {
			_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
			return exitError
		}
	}
	if err := report(c, "pid", strconv.Itoa(os.Getpid())); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}

	var timeout <-chan time.Time
	if c.exitAfter > 0 {
		timeout = time.After(c.exitAfter)
	}
	var got os.Signal
	select {
	case got = <-sig:
	case <-timeout:
		return exitOK
	}
	_ = report(c, "signal", got.String())
	time.Sleep(c.work)
	if err := report(c, "done", got.String()); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}
	return exitSignaled
}

// report writes one fact into --state atomically, so a reader polling for the
// file never sees half of it.
func report(c config, kind, value string) error {
	final := filepath.Join(c.state, c.name+"."+kind)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, []byte(value), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// hold takes the application lock and keeps it until stdin reaches EOF, which is
// how a scenario models "an instance is still running" to another process — and
// releases it cleanly, so no stale lock survives the scenario.
func hold(path string, stdin io.Reader, stdout, stderr io.Writer) int {
	if path == "" {
		_, _ = fmt.Fprintln(stderr, "hostapp: --hold-lock needs --lock")
		return exitUsage
	}
	l := &fileLock{path: path}
	ok, err := l.TryLock(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: taking the lock: %v\n", err)
		return exitError
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "hostapp: the lock is already held")
		return exitError
	}
	// Announce only once the lock is held: the scenario waits for this line
	// before it starts the update it expects to be deferred.
	_, _ = fmt.Fprintln(stdout, "holding")
	_, _ = io.Copy(io.Discard, stdin)
	if err := l.Unlock(); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: releasing the lock: %v\n", err)
		return exitError
	}
	return exitOK
}

func doSelfUpdate(c config, stdout, stderr io.Writer) int {
	if c.root == "" || c.metadataURL == "" || c.anchor == "" || c.cache == "" {
		_, _ = fmt.Fprintln(stderr, "hostapp: --self-update needs --root, --metadata-url, --root-metadata and --cache")
		return exitUsage
	}
	var busy updater.BusyPolicy
	switch c.onBusy {
	case "abort":
		busy = updater.BusyAbort
	case "defer":
		busy = updater.BusyDeferToRestart
	default:
		_, _ = fmt.Fprintf(stderr, "hostapp: --on-busy: unknown policy %q\n", c.onBusy)
		return exitUsage
	}
	anchor, err := os.ReadFile(c.anchor)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: --root-metadata: %v\n", err)
		return exitUsage
	}
	f, err := fetch.New(fetch.Options{UserAgent: "idunn-e2e-hostapp/" + version})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}
	tc, err := trust.New(trust.Options{
		Root:        anchor,
		MetadataURL: c.metadataURL,
		TargetsURL:  c.targetsURL,
		LocalDir:    c.cache,
		Fetcher:     f,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}

	o := updater.Options{
		Trust:         tc,
		Fetcher:       f,
		FS:            fsx.OS(),
		Root:          c.root,
		Channel:       c.channel,
		ClientVersion: version,
		Observe:       &progress{w: stdout, hangAt: hook.Phase(c.hangAt)},
		Policy: updater.Policy{
			RetainVersions:   c.retain,
			VerifyAfterApply: true,
			QuiesceTimeout:   c.quiesce,
			OnBusy:           busy,
		},
	}
	if c.lockFile != "" {
		o.Lock = &fileLock{path: c.lockFile}
	}
	if c.data != "" {
		o.Migrate = &migrator{dir: c.data, fail: c.failMigrate}
	}
	if c.service != "" {
		el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: c.service})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "hostapp: --service: %v\n", err)
			return exitUsage
		}
		o.Elevator = el
		o.Policy.Elevation = updater.ElevationService
		// The helper decides on the user that connects; printing it ties this
		// process to the helper's log line.
		_, _ = fmt.Fprintf(stdout, "euid %d\n", os.Geteuid())
	}

	// A running application holds its own lock while it works, which is exactly
	// why an update it applies to itself has to wait for a moment it is gone.
	own := &fileLock{path: c.lockFile}
	if c.holdOwnLock {
		if held, err := own.TryLock(context.Background()); err != nil || !held {
			_, _ = fmt.Fprintf(stderr, "hostapp: --hold-own-lock: held=%v err=%v\n", held, err)
			return exitError
		}
	}

	u, err := updater.New(o)
	if err != nil {
		_ = own.Unlock()
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}
	code := applyOnce(u, stdout, stderr)
	// The instance is about to be gone: its lock goes first, so the launcher can
	// prove nobody is writing before it finishes the update.
	if err := own.Unlock(); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: unlock: %v\n", err)
		return exitError
	}
	if c.relaunchVia == "" || (code != exitOK && code != exitDeferred) {
		return code
	}
	_, _ = fmt.Fprintln(stdout, "relaunching")
	// The same arguments again: a restart, not a different program. The new run
	// checks the channel once more and finds itself up to date.
	relaunchCode, err := launch.Relaunch(launch.RelaunchOptions{Launcher: c.relaunchVia, Root: c.root, Args: c.args})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: relaunch: %v\n", err)
		return exitError
	}
	return relaunchCode
}

// applyOnce checks the channel and applies what it names, returning the exit code.
func applyOnce(u *updater.Updater, stdout, stderr io.Writer) int {
	ctx := context.Background()
	rel, err := u.CheckForUpdate(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: check: %v\n", err)
		return exitError
	}
	if rel == nil {
		_, _ = fmt.Fprintf(stdout, "up to date at %s\n", version)
		return exitNoUpdate
	}
	if err := u.Apply(ctx, rel); err != nil {
		if errors.Is(err, updater.ErrDeferred) {
			_, _ = fmt.Fprintf(stdout, "deferred %s\n", rel.Descriptor.Version)
			return exitDeferred
		}
		_, _ = fmt.Fprintf(stderr, "hostapp: apply: %v\n", err)
		return elevationExit(err)
	}
	_, _ = fmt.Fprintf(stdout, "updated %s -> %s\n", rel.FromVersion, rel.Descriptor.Version)
	return exitOK
}

// request sends the helper a request for one version and nothing else: no
// refresh, no resolution, no policy on this side. It is the caller the helper
// must not take at its word.
func request(c config, stdout, stderr io.Writer) int {
	if c.service == "" || c.root == "" {
		_, _ = fmt.Fprintln(stderr, "hostapp: --request-version needs --service and --root")
		return exitUsage
	}
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: c.service})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: --service: %v\n", err)
		return exitUsage
	}
	_, _ = fmt.Fprintf(stdout, "euid %d\n", os.Geteuid())
	d := &release.Descriptor{Channel: c.channel, Version: c.requestVersion}
	if err := el.Apply(context.Background(), c.root, d); err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: request: %v\n", err)
		return elevationExit(err)
	}
	_, _ = fmt.Fprintf(stdout, "requested %s\n", c.requestVersion)
	return exitOK
}

// elevationExit classifies a failed apply by what the helper answered.
func elevationExit(err error) int {
	switch {
	case errors.Is(err, elevate.ErrDenied):
		return exitDenied
	case errors.Is(err, elevate.ErrHelper):
		return exitHelper
	default:
		return exitError
	}
}

// progress prints one line per event and, when asked, stops in a named phase.
type progress struct {
	w      io.Writer
	hangAt hook.Phase
}

// OnEvent reports the phase and, for --hang-at, blocks inside it.
//
// Blocking rather than exiting is deliberate: the suite kills the process from
// outside once it has read the line, so what it tests is a process that stops
// existing — no deferred function, no flush, no cleanup — at a point it chose.
func (p *progress) OnEvent(e hook.Event) {
	_, _ = fmt.Fprintf(p.w, "phase %s: %s\n", e.Phase, e.Message)
	if p.hangAt != "" && e.Phase == p.hangAt {
		_, _ = fmt.Fprintf(p.w, "hanging in %s\n", e.Phase)
		// A sleep, not an empty select: with no other goroutine alive the
		// runtime would call that a deadlock and exit on its own.
		for {
			time.Sleep(time.Hour)
		}
	}
}

// migrator is a host migration over state outside the install root: a schema
// file holding the version the state is migrated to, and a log of every call.
// The log is how the suite tells "the tree was unwound" from "the host was
// asked to undo its own change too".
type migrator struct {
	dir  string
	fail bool
}

func (m *migrator) Migrate(hc hook.Context) error {
	if err := m.record("migrate", hc); err != nil {
		return err
	}
	// The state is changed before the failure, so a rollback that did not run
	// would be visible in the schema file.
	if err := m.writeSchema(hc.ToVersion); err != nil {
		return err
	}
	if m.fail {
		return errors.New("hostapp: the migration was told to fail")
	}
	return nil
}

func (m *migrator) Rollback(hc hook.Context) error {
	if err := m.record("rollback", hc); err != nil {
		return err
	}
	return m.writeSchema(hc.FromVersion)
}

func (m *migrator) record(verb string, hc hook.Context) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(m.dir, "migrations.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s %s->%s\n", verb, hc.FromVersion, hc.ToVersion); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (m *migrator) writeSchema(v string) error {
	return os.WriteFile(filepath.Join(m.dir, "schema"), []byte(v), 0o600)
}

// fileLock is an exclusive lock two processes can contend for: the create is
// O_EXCL, so exactly one of them wins, on every platform the suite runs on.
type fileLock struct {
	path string
	held bool
}

func (l *fileLock) TryLock(context.Context) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return false, err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	l.held = true
	return true, nil
}

func (l *fileLock) Unlock() error {
	if !l.held {
		return nil
	}
	l.held = false
	return os.Remove(l.path)
}
