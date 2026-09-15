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
//	<root>/.updater/          journal, install state, known-good clock,
//	                          and launcher.next/<name>, a launcher to swap in
//
// It is also the uninstaller: `launcher --uninstall` removes the installation it
// belongs to, and then itself (core/uninstall, IDN-35). One binary fewer to build,
// sign and ship, and it is the one file that stays on disk above versions/.
//
// A host that wants its own launcher can have one: everything here beyond flag
// parsing and the hand-over lives in core/launch and core/uninstall.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/launch"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/uninstall"
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

	// --uninstall only. The same numbers cmd/installer gives the same
	// situations, so a script or an MDM reads both alike.
	exitRefused    = 3 // not an installation of this application, or the application refused.
	exitIncomplete = 4 // the application is running, or something is still in use; run again.
	exitPrivileges = 5 // the install root needs administrator rights.
	exitUnsafeRoot = 6 // administrator rights, but the root is not administrators-only.
)

// appBinary is the install-relative path of the application to start, set at
// build time:
//
//	go build -ldflags "-X main.appBinary=bin/acme" ./cmd/launcher
//
// A host bakes it in rather than passing it at runtime, because the launcher is
// what a user clicks: it should need no arguments to do its job.
var appBinary = "app"

// launcherVersion is this launcher's own version, set at build time:
//
//	go build -ldflags "-X main.launcherVersion=1.3.0" ./cmd/launcher
//
// Once the launcher can replace itself, the one in the install root is no longer
// necessarily the one that was installed, and `--version` is how an operator
// finds out which one is actually there. A build that leaves it unset says so.
var launcherVersion = ""

// releaseName is the name the application's releases are published under — the
// `name` of its pack.yaml, which the install state records — set at build time:
//
//	go build -ldflags "-X main.releaseName=acme-app" ./cmd/launcher
//
// `--uninstall` refuses a root that holds another application when it is set. A
// build that leaves it unset still refuses a root that holds no installation at
// all, and removes only the root this launcher sits in.
var releaseName = ""

// execFn hands control to the application. It is a variable so the tests can
// exercise everything up to the hand-over on every platform — the real
// implementations replace the process (POSIX) or run it as a child and pass on
// its exit code (Windows).
type execFn func(path string, args []string) (int, error)

// supervises is whether this launcher stays the application's parent — on
// Windows, where execApp runs the application as a child — and so can act on
// launch.RelaunchExitCode. On POSIX the launcher is gone once the application
// runs, and an application relaunches through launch.Relaunch instead.
var supervises = runtime.GOOS == "windows"

// Relaunch limits (IDN-29). An application that exits with RelaunchExitCode is
// started again; one that does so again and again without running for a while is
// not, so a relaunch that cannot make progress ends instead of spinning.
const (
	maxQuickRelaunches = 3
	quickRun           = 30 * time.Second

	// afterPIDTimeout bounds how long a relaunched launcher waits for the
	// instance that relaunched it to exit.
	afterPIDTimeout = 60 * time.Second
)

// now is the clock the relaunch limit is measured on, and afterPIDTimeoutFor the
// wait for a previous instance; both are variables for the tests.
var (
	now                = time.Now
	afterPIDTimeoutFor = func() time.Duration { return afterPIDTimeout }
)

func main() {
	// The copy an uninstall starts to remove this launcher (Windows). It is
	// dispatched before anything else is parsed: it is not a start.
	if len(os.Args) > 1 && os.Args[1] == uninstall.FinishArg {
		os.Exit(finishUninstall(os.Args[2:]))
	}
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
		after  = fs.Int("after-pid", 0, "wait for this process to exit first (set by launch.Relaunch)")
		show   = fs.Bool("version", false, "print this launcher's own version and exit")
		remove = fs.Bool("uninstall", false, "remove this installation and this launcher instead of starting the application")
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
	}
	// The file a staged launcher replaces is the one this process was started
	// from, not a name derived from the root or the command line: a host may
	// install the launcher under any name, and the only authority on which it
	// chose is the running image. core/launch swaps in only what a committed
	// update staged for exactly that name, and only if it sits directly in the
	// root served (docs/design.md §13, IDN-17). No flag can point it elsewhere.
	if self, err := selfPath(); err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: cannot locate this executable, so it will not be replaced: %v\n", err)
	} else {
		o.SelfPath = self
	}
	if !*quiet {
		o.Observe = &progress{w: stdout}
	}
	if *remove && fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: --uninstall starts nothing, so it takes no arguments for the application (%q)\n", fs.Arg(0))
		return exitUsage
	}

	// Started by launch.Relaunch beside the instance that asked for it: nothing
	// is applied, and nothing is started, while that instance is still up. A
	// migration running under a live application is the thing deferring exists
	// to prevent, and a second instance is not what anyone asked for.
	if *after != 0 {
		if err := launch.WaitForExit(context.Background(), *after, afterPIDTimeoutFor()); err != nil {
			_, _ = fmt.Fprintf(stderr, "idunn launcher: %v\n", err)
			return exitError
		}
	}

	if *remove {
		return uninstallRoot(installRoot, o.SelfPath, o.Observe, stderr)
	}

	quick := 0
	for {
		code, err := startOnce(o, installRoot, rel, fs.Args(), stderr, exec)
		if err != nil || !supervises || code != launch.RelaunchExitCode {
			return code
		}
		// The application asked to be started again (IDN-29). A run long enough
		// to have done something resets the count; a run that did not is a
		// relaunch that cannot make progress, and that ends here.
		if now().Sub(lastStart) >= quickRun {
			quick = 0
		}
		quick++
		if quick > maxQuickRelaunches {
			_, _ = fmt.Fprintf(stderr, "idunn launcher: the application asked to be relaunched %d times within %s each; not again\n",
				maxQuickRelaunches, quickRun)
			return exitError
		}
		if !*quiet {
			_, _ = fmt.Fprintln(stdout, "launch   relaunching the application")
		}
	}
}

// finishUninstall runs the copy that removes the launcher an uninstall left
// behind (Windows only; uninstall.Finish refuses it elsewhere).
func finishUninstall(args []string) int {
	if err := uninstall.Finish(args); err != nil { //nolint:staticcheck // SA4023: Finish returns nil only on Windows; this dispatch is Windows-only in practice.
		return exitError
	}
	return exitOK
}

// lastStart is when startOnce last handed over to the application.
var lastStart time.Time

// startOnce settles the install root and runs the application once, returning
// its exit code. An error means the application was not started, and the code
// is the launcher's own.
func startOnce(o launch.Options, installRoot, rel string, args []string, stderr io.Writer, exec execFn) (int, error) {
	// A start that could not finish a deferred update is not a start that
	// fails: the installation that is live is complete and runnable, and
	// refusing to launch an application because an update it did not ask for
	// could not be applied would be the worse outcome by far.
	res, err := launch.Start(context.Background(), o)
	if errors.Is(err, txn.ErrUninstalling) {
		// The one failure a start does not go past: an uninstall began, and the
		// tree it has partly removed is not an installation to run.
		_, _ = fmt.Fprintln(stderr, "idunn launcher: an uninstall of this installation was interrupted; "+
			"run the launcher with --uninstall to finish it")
		return exitError, err
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: the pending update was not applied: %v\n", err)
	}
	// Likewise a launcher that could not replace itself: it is reported on every
	// start until it is fixed, and the application starts regardless. In a
	// system-wide install this is the expected outcome for an unprivileged user
	// (ErrSelfNotWritable, IDN-23).
	if res.SelfErr != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: this launcher was not replaced: %v\n", res.SelfErr)
	}

	// Resolved again on every start: after a relaunch, `current` may name a
	// newer version than the one that asked for it.
	bin, err := appPath(o.FS, installRoot, rel)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: %v\n", err)
		return exitError, err
	}
	lastStart = now()
	code, err := exec(bin, args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: starting the application: %v\n", err)
		return exitError, err
	}
	return code, nil
}

// uninstallRoot removes the installation this launcher belongs to (IDN-35).
//
// It takes no path from its caller: the root is the one this launcher sits in,
// the same judgement a launcher makes before it swaps a staged launcher over
// itself. A --root that names another directory is refused rather than removed,
// so a launcher cannot be talked into deleting an installation it is not part of.
func uninstallRoot(root, self string, observe hook.Observer, stderr io.Writer) int {
	if self == "" {
		_, _ = fmt.Fprintln(stderr, "idunn launcher: --uninstall needs to know where this launcher is, and it could not be located")
		return exitError
	}
	if fsx.Dir(self) != fsx.Clean(fsx.Slash(root)) {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: --uninstall removes only the installation this launcher is in; %s is not in %s\n",
			self, root)
		return exitUsage
	}

	o := uninstall.Options{
		FS:       fsx.OS(),
		Root:     fsx.Slash(root),
		Name:     releaseName,
		SelfPath: self,
		Observe:  observe,
	}
	// The installer's TUF cache for this root goes with it. A different
	// spelling of the root names a different cache, which then stays behind:
	// it holds public metadata and nothing else.
	if cache, err := os.UserCacheDir(); err == nil {
		o.Caches = []string{fsx.Slash(layout.InstallerCache(cache, root))}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := uninstall.Run(ctx, o)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: %v\n", err)
		switch {
		case errors.Is(err, uninstall.ErrNotInstalled), errors.Is(err, uninstall.ErrRefused):
			return exitRefused
		case errors.Is(err, uninstall.ErrBusy), errors.Is(err, uninstall.ErrIncomplete):
			return exitIncomplete
		case errors.Is(err, uninstall.ErrNotWritable):
			return exitPrivileges
		case errors.Is(err, uninstall.ErrUnsafeRoot):
			return exitUnsafeRoot
		default:
			return exitError
		}
	}
	if len(res.Kept) > 0 {
		_, _ = fmt.Fprintf(stderr, "idunn launcher: %s was kept, because it holds files idunn did not install\n", root)
	}
	return exitOK
}

// selfPath is the running executable with symlinks resolved, in the form
// core/launch works with. It is a variable so the tests can stand a file in for
// the test binary, which they must not replace.
var selfPath = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", err
	}
	return fsx.Slash(self), nil
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
