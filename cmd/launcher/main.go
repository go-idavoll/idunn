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

// Command launcher is the small stable binary the install layout starts with
// (docs/design.md §6.1). It settles whatever the last run left behind, applies an
// update that was deferred because the application would not stop writing, and
// then hands over to the application itself.
//
// It is deliberately the least interesting program in this repository. It has no
// network, no keys, no TUF client and no update logic: everything it touches was
// verified when it was staged. This code runs on every single start of the
// application, so the worst thing it could be is clever.
//
// The layout it expects is the one core/stage maintains:
//
//	<root>/current            -> versions/<version>   (symlink or pointer file)
//	<root>/versions/<version>/<app>
//	<root>/.updater/          journal, install state, known-good clock
//
// A host that wants its own launcher can have one: everything here beyond flag
// parsing and the hand-over lives in core/launch.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// Exit codes. The application's own exit code is passed through where the
// platform makes that necessary, so these are only about failing before it ever
// starts.
const (
	exitOK    = 0 // the launcher answered a question and did not start anything.
	exitError = 1 // there is nothing to launch, or it could not be started.
	exitUsage = 2 // the command line was wrong.
)

// appBinary is the install-relative path of the application to start, set at
// build time:
//
//	go build -ldflags "-X main.appBinary=bin/acme" ./cmd/launcher
//
// A host bakes it in rather than passing it at runtime, because the launcher is
// what a user clicks: it should need no arguments to do its job.
var appBinary = "app"

// launcherSource is the install-relative path, inside a version directory, at
// which a release ships this launcher — set at build time alongside appBinary:
//
//	go build -ldflags "-X main.appBinary=bin/acme -X main.launcherSource=bin/acme-launcher" ./cmd/launcher
//
// Empty (the default) means releases do not carry the launcher, and the shim in
// the install root is never touched. A host that does ship it gets the shim
// refreshed at the start after the update that brought it, which is the only
// moment a program may replace the file it is executing from (docs/design.md
// §13, IDN-17).
//
// It is a linker variable rather than a flag for the same reason appBinary is:
// the launcher is what a user clicks, and it should need no arguments to do its
// job — and because a flag here would let whoever writes the command line choose
// which file becomes the thing everyone clicks next.
var launcherSource = ""

// launcherVersion is this shim's own version, set at build time:
//
//	go build -ldflags "-X main.launcherVersion=1.3.0" ./cmd/launcher
//
// It answers a question that otherwise has no answer once self-replacement
// exists (IDN-17): the shim in the install root is no longer necessarily the one
// that was installed originally, and `--version` is how an operator finds out
// which one is actually sitting there. A build that leaves it unset says so.
var launcherVersion = ""

// execFn hands control to the application. It is a variable so the tests can
// exercise everything up to the hand-over on every platform — the real
// implementations replace the process (POSIX) or run it as a child and pass on
// its exit code (Windows).
type execFn func(path string, args []string) (int, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, execApp))
}

func run(args []string, stdout, stderr io.Writer, exec execFn) int {
	fs := flag.NewFlagSet("launcher", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		root   = fs.String("root", "", "install root (default: the directory this binary is in)")
		app    = fs.String("app", appBinary, "install-relative path of the application to start")
		retain = fs.Int("retain", 0, "version directories to keep after applying a deferred update")
		quiet  = fs.Bool("quiet", false, "suppress progress output")
		show   = fs.Bool("version", false, "print this launcher's own version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *show {
		v := launcherVersion
		if v == "" {
			v = "unknown (this build stamped no version)"
		}
		_, _ = fmt.Fprintf(stdout, "idunn launcher %s\n", v)
		return exitOK
	}

	installRoot, err := resolveRoot(*root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: %v\n", err)
		return exitError
	}
	rel, err := safepath.Clean(*app)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: --app: %v\n", err)
		return exitUsage
	}

	o := launch.Options{
		FS:             fsx.OS(),
		Root:           installRoot,
		RetainVersions: *retain,
		SelfSource:     launcherSource,
	}
	if launcherSource != "" {
		// The file to replace is the one this process was started from, not a
		// name derived from the root: a host may install the shim under any
		// name, and the only authority on which it chose is the running image.
		self, err := os.Executable()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "idunn launcher: cannot locate this executable, so it will not be refreshed: %v\n", err)
		} else {
			o.SelfPath = fsx.Slash(self)
		}
	}
	if !*quiet {
		o.Observe = &progress{w: stdout}
	}

	// A start that could not finish a deferred update is not a start that
	// fails: the installation that is live is complete and runnable, and
	// refusing to launch an application because an update it did not ask for
	// could not be applied would be the worse outcome by far.
	if _, err := launch.Start(context.Background(), o); err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: the pending update was not applied: %v\n", err)
	}

	bin, err := appPath(o.FS, installRoot, rel)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: %v\n", err)
		return exitError
	}
	code, err := exec(bin, fs.Args())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: starting the application: %v\n", err)
		return exitError
	}
	return code
}

// resolveRoot picks the install root: the flag, or the directory this binary
// lives in.
//
// The default is what makes the launcher need no arguments — the layout puts it
// at the top of the install root, next to current/ and versions/ — and it is why
// a host can ship it as the thing a user clicks.
func resolveRoot(fromFlag string) (string, error) {
	if fromFlag != "" {
		return filepath.Abs(fromFlag)
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate the install root: %w; pass --root", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", fmt.Errorf("cannot locate the install root: %w; pass --root", err)
	}
	return filepath.Dir(self), nil
}

// appPath resolves the application binary through the install pointer.
//
// It goes through the pointer's target rather than through `current` itself,
// because `current` is a symlink on POSIX and a pointer file on Windows
// (docs/design.md §13). Resolving the version first is the one form that means
// the same thing on both.
func appPath(f fsx.FS, root, rel string) (string, error) {
	version, err := layout.PointerTarget(f, root)
	if err != nil {
		return "", err
	}
	if version == "" {
		return "", fmt.Errorf("%s holds no installation", root)
	}
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		return "", err
	}
	path := fsx.Join(dir, rel)
	if _, err := f.Stat(path); err != nil {
		return "", fmt.Errorf("%s is not in the installed version %s: %w", rel, version, err)
	}
	return path, nil
}

// progress renders lifecycle events as lines.
type progress struct{ w io.Writer }

func (p *progress) OnEvent(e hook.Event) {
	if e.Err != nil {
		_, _ = fmt.Fprintf(p.w, "%-8s %s: %v\n", e.Phase, e.Message, e.Err)
		return
	}
	_, _ = fmt.Fprintf(p.w, "%-8s %s\n", e.Phase, e.Message)
}

// errNotStarted reports that the application never ran, so a caller can tell a
// failed hand-over from an application that exited non-zero.
var errNotStarted = errors.New("the application was not started")
