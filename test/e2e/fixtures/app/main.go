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

// Command app is the host application the end-to-end suite installs, launches
// and updates. It is a fixture, not a product.
//
// It exists because every other test in this tree drives core as a library. The
// one thing none of them covers is the shape a real host has: a binary that is
// itself the payload of a release, that wires core/updater together the way
// docs/design.md §6.3 sketches, and that is running while it updates itself. The
// flags below are the seams the scenarios need — a lock a second process can
// hold, a migration that fails on demand, a phase to die in — and nothing more.
//
// It is deliberately built from source by the test rather than shipped as a
// fixture binary: what the suite must prove is that *today's* core survives the
// round trip, not that a recorded one did.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
)

// version is the release this binary belongs to, stamped at build time:
//
//	go build -ldflags "-X main.version=1.0.0" ./test/e2e/fixtures/app
//
// The suite asserts on it to tell which tree `current` actually points at, so it
// is the one thing that must differ between two builds of this file.
var version = "0.0.0"

// Exit codes. `deferred` is its own answer rather than a failure: an update that
// waits for the next start is the outcome BusyDeferToRestart promises, and a
// test that could not tell it from a crash would be asserting on nothing.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitNoUpdate = 3 // --self-update found the channel head already installed.
	exitDeferred = 4 // the update was staged and left for the next start.
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("app", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		selfUpdate  = fs.Bool("self-update", false, "check the channel and apply what it names")
		root        = fs.String("root", "", "install root")
		channel     = fs.String("channel", "stable", "channel to follow")
		metadataURL = fs.String("metadata-url", "", "TUF metadata URL")
		targetsURL  = fs.String("targets-url", "", "TUF targets URL")
		anchor      = fs.String("root-metadata", "", "trust anchor file")
		cache       = fs.String("cache", "", "TUF metadata and target cache")
		lockFile    = fs.String("lock", "", "path of the exclusive application lock")
		holdLock    = fs.Duration("hold-lock", 0, "take the lock, hold it this long, exit")
		onBusy      = fs.String("on-busy", "abort", "abort|defer|force")
		retain      = fs.Int("retain", 0, "version directories to keep after a commit")
		failMigrate = fs.Bool("fail-migrate", false, "make the migration hook fail, forcing a rollback")
		dieAt       = fs.String("die-at", "", "exit(137) the moment this phase is entered")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	switch {
	case *holdLock > 0:
		return hold(*lockFile, *holdLock, stdout, stderr)
	case !*selfUpdate:
		_, _ = fmt.Fprintf(stdout, "app %s\n", version)
		return exitOK
	}
	return doSelfUpdate(selfUpdateArgs{
		root:        *root,
		channel:     *channel,
		metadataURL: *metadataURL,
		targetsURL:  *targetsURL,
		anchor:      *anchor,
		cache:       *cache,
		lockFile:    *lockFile,
		onBusy:      *onBusy,
		retain:      *retain,
		failMigrate: *failMigrate,
		dieAt:       *dieAt,
	}, stdout, stderr)
}

// hold takes the application lock and keeps it, which is how a scenario models
// "an instance is still running" to a second process.
func hold(path string, d time.Duration, stdout, stderr io.Writer) int {
	if path == "" {
		_, _ = fmt.Fprintln(stderr, "app: --hold-lock needs --lock")
		return exitUsage
	}
	l := &fileLock{path: path}
	ok, err := l.TryLock(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: taking the lock: %v\n", err)
		return exitError
	}
	if !ok {
		_, _ = fmt.Fprintln(stderr, "app: the lock is already held")
		return exitError
	}
	defer func() { _ = l.Unlock() }()
	// Announce only once the lock is actually held: the scenario waits for this
	// line before it starts the update it expects to be deferred.
	_, _ = fmt.Fprintln(stdout, "holding")
	if f, ok := stdout.(*os.File); ok {
		_ = f.Sync()
	}
	time.Sleep(d)
	return exitOK
}

type selfUpdateArgs struct {
	root        string
	channel     string
	metadataURL string
	targetsURL  string
	anchor      string
	cache       string
	lockFile    string
	onBusy      string
	retain      int
	failMigrate bool
	dieAt       string
}

func doSelfUpdate(a selfUpdateArgs, stdout, stderr io.Writer) int {
	if a.root == "" || a.metadataURL == "" || a.anchor == "" || a.cache == "" {
		_, _ = fmt.Fprintln(stderr, "app: --self-update needs --root, --metadata-url, --root-metadata and --cache")
		return exitUsage
	}
	busy, err := busyPolicy(a.onBusy)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: %v\n", err)
		return exitUsage
	}
	anchorBytes, err := os.ReadFile(a.anchor)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: --root-metadata: %v\n", err)
		return exitUsage
	}
	f, err := fetch.New(fetch.Options{UserAgent: "idunn-e2e-app"})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: %v\n", err)
		return exitError
	}
	tc, err := trust.New(trust.Options{
		Root:        anchorBytes,
		MetadataURL: a.metadataURL,
		TargetsURL:  a.targetsURL,
		LocalDir:    a.cache,
		Fetcher:     f,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: %v\n", err)
		return exitError
	}

	o := updater.Options{
		Trust:   tc,
		Fetcher: f,
		FS:      fsx.OS(),
		Root:    a.root,
		Channel: a.channel,
		Observe: &progress{w: stdout, dieAt: hook.Phase(a.dieAt)},
		Policy: updater.Policy{
			RetainVersions:   a.retain,
			VerifyAfterApply: true,
			QuiesceTimeout:   2 * time.Second,
			OnBusy:           busy,
		},
	}
	if a.lockFile != "" {
		o.Lock = &fileLock{path: a.lockFile}
	}
	if a.failMigrate {
		o.Migrate = failingMigrator{}
	}

	u, err := updater.New(o)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: %v\n", err)
		return exitError
	}
	ctx := context.Background()
	rel, err := u.CheckForUpdate(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "app: check: %v\n", err)
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
		_, _ = fmt.Fprintf(stderr, "app: apply: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "applied %s\n", rel.Descriptor.Version)
	return exitOK
}

func busyPolicy(name string) (updater.BusyPolicy, error) {
	switch name {
	case "abort":
		return updater.BusyAbort, nil
	case "defer":
		return updater.BusyDeferToRestart, nil
	case "force":
		return updater.BusyForce, nil
	default:
		return 0, fmt.Errorf("--on-busy: unknown policy %q", name)
	}
}

// progress prints one line per event, and optionally dies in a named phase.
type progress struct {
	w     io.Writer
	dieAt hook.Phase
}

// OnEvent reports the phase and, when asked, kills this process inside it.
//
// The hard exit is what makes crash recovery testable end to end: a transaction
// interrupted between the journal record and the swap is exactly the state
// core/txn's recovery exists for, and no in-process test seam can produce it as
// honestly as a process that stops existing.
func (p *progress) OnEvent(e hook.Event) {
	_, _ = fmt.Fprintf(p.w, "phase %s: %s\n", e.Phase, e.Message)
	if f, ok := p.w.(*os.File); ok {
		_ = f.Sync()
	}
	if p.dieAt != "" && e.Phase == p.dieAt {
		os.Exit(137)
	}
}

// failingMigrator is a host migration that always fails, so the transaction has
// to unwind. Rollback succeeds: what is under test is the updater's unwinding,
// not a host that cannot clean up after itself.
type failingMigrator struct{}

func (failingMigrator) Migrate(hook.Context) error {
	return errors.New("fixture: the migration was told to fail")
}

func (failingMigrator) Rollback(hook.Context) error { return nil }

// fileLock is an exclusive lock two processes can contend for: the create is
// O_EXCL, so exactly one of them wins, on every platform the suite runs on.
//
// A real host would use whatever its data store already offers. This one is
// enough for the property the scenarios need — a lock a *different* process
// holds — and has no unlock-on-crash story on purpose: a stale lock is a state
// the tests want to be able to produce.
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
		if os.IsExist(err) {
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
