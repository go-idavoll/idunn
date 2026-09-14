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
//
// Exit codes: 0 ok, 1 error, 2 usage, 3 already up to date, 4 deferred to the
// next start.
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
	"path/filepath"
	"time"

	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
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
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	switch {
	case *holdLock:
		return hold(c.lockFile, stdin, stdout, stderr)
	case *selfUpdate:
		return doSelfUpdate(c, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stdout, "app %s\n", version)
		return exitOK
	}
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

	u, err := updater.New(o)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "hostapp: %v\n", err)
		return exitError
	}
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
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "updated %s -> %s\n", rel.FromVersion, rel.Descriptor.Version)
	return exitOK
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
