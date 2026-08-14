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

// Command installer is the thin first-install binary: it carries the embedded TUF
// root, resolves the channel, and hands the work to core/installer. It contains no
// trust logic of its own. See docs/design.md §5.
//
// It has two verbs. `install` is what a user runs. `apply` is the privileged
// helper contract from docs/design.md §14.2: when the install root needs
// privileges the current process does not have, core/elevate re-launches this
// same binary elevated as `apply --root R --channel C --version V`, and that
// process resolves and verifies everything again from the embedded anchor. Three
// scalars cross the privilege boundary and nothing else — no URL, no descriptor,
// no staged path — which is why `apply` accepts no other flag.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
)

// Exit codes. They are the contract with whatever runs this — a shell script, an
// MDM, a CI job — and they exist so that "did not install" can be told from
// "refused to install", which is not a failure at all (docs/design.md §14.6).
const (
	exitOK         = 0 // installed, or already at the requested version.
	exitError      = 1 // something went wrong.
	exitUsage      = 2 // the command line was wrong.
	exitRefused    = 3 // an install exists that this installer must not touch.
	exitDeclined   = 4 // the user dismissed the elevation prompt.
	exitPrivileges = 5 // the install root needs privileges this process cannot get.
)

// defaultChannel is what an install follows when neither the build nor the flags
// name one.
const defaultChannel = "stable"

// clientVersion is this installer's own version, set at build time:
//
//	go build -ldflags "-X main.clientVersion=1.3.0" ./cmd/installer
//
// It is what a descriptor's min_client_version floor is checked against (§11.3
// T14), and it is deliberately not a flag: an operator who could claim any
// version could talk an installer past the floor that exists to stop it from
// mishandling a layout it does not implement. A build that leaves it unset
// refuses any release that demands a minimum.
var clientVersion = ""

// buildTime is when this binary was built, as RFC3339 or as a Unix timestamp,
// set at build time alongside clientVersion:
//
//	go build -ldflags "-X main.clientVersion=1.3.0 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/installer
//
// It is the first floor under the system clock: a binary cannot have been built
// after the moment it runs, so a clock below it is wrong before anything else is
// known (§14.7, T22). A build that leaves it unset simply has no floor until the
// first successful refresh records one — it is a defence in depth, not a
// precondition. Like clientVersion it is a linker variable rather than a flag:
// an operator who could set it could also lower it.
var buildTime = ""

// userAgent identifies this client to proxies and servers.
const userAgent = "idunn-installer"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch {
	case args[0] == "apply":
		return applyHelper(args[1:], stdout, stderr)
	case args[0] == "install":
		return installVerb(args[1:], stdout, stderr)
	case args[0] == "-h", args[0] == "--help", args[0] == "help":
		usage(stdout)
		return exitOK
	case strings.HasPrefix(args[0], "-"):
		// Installing is what this binary is for; the verb is optional.
		return installVerb(args, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "idunn installer: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `idunn installer — first-time install of a TUF-published release.

Usage:
  installer [install] --root <dir> [--channel %s] [--version <semver>]
  installer apply --root <dir> --channel <name> --version <semver>

The trust anchor is compiled in (cmd/installer/anchor/root.json). A build that
carries one cannot be pointed at another; a build without one requires
--root-metadata.

Exit codes:
  %d  installed, or already at the requested version
  %d  failed
  %d  usage
  %d  refused: an install exists that this installer must not touch
  %d  the elevation prompt was declined
  %d  the install root needs privileges this process cannot obtain

`, defaultChannel, exitOK, exitError, exitUsage, exitRefused, exitDeclined, exitPrivileges)
}

// installVerb is the ordinary, unprivileged entry point.
func installVerb(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		root         = fs.String("root", "", "install root (required)")
		channel      = fs.String("channel", "", "channel to follow (default "+defaultChannel+")")
		version      = fs.String("version", "", "install this exact version instead of the channel head")
		allowDown    = fs.Bool("allow-downgrade", false, "permit installing over a newer existing install")
		metadataURL  = fs.String("metadata-url", "", "TUF metadata URL (overrides the embedded one)")
		targetsURL   = fs.String("targets-url", "", "TUF targets URL (default: the targets/ sibling of --metadata-url)")
		rootMetadata = fs.String(strings.TrimPrefix(anchorFlag, "--"), "", "trust anchor file; only for a build that embeds none")
		cache        = fs.String("cache", "", "directory for trusted TUF metadata and the target cache")
		quiet        = fs.Bool("quiet", false, "suppress progress output")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "idunn installer: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	var anchorFromFlag []byte
	if *rootMetadata != "" {
		raw, err := os.ReadFile(*rootMetadata)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "idunn installer: --root-metadata: %v\n", err)
			return exitUsage
		}
		anchorFromFlag = raw
	}

	cfg, code := buildConfig(config{
		root:           *root,
		channel:        *channel,
		version:        *version,
		allowDowngrade: *allowDown,
		metadataURL:    *metadataURL,
		targetsURL:     *targetsURL,
		anchorFromFlag: anchorFromFlag,
		cache:          *cache,
		quiet:          *quiet,
		elevate:        true,
	}, stdout, stderr)
	if code != exitOK {
		return code
	}
	return doInstall(cfg, stdout, stderr)
}

// applyHelper is the privileged half of interactive elevation (§14.2).
//
// It accepts exactly the three scalars core/elevate puts on the command line.
// Everything else it needs — the trust anchor, the repository URL — it takes
// from what it was built with, never from its caller: this process may be
// running as administrator or root, and a caller-supplied URL or anchor would
// move the trust decision to the unprivileged side that asked for the elevation.
// The flag set refuses any other flag by construction.
func applyHelper(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		root    = fs.String("root", "", "install root (required)")
		channel = fs.String("channel", "", "channel (required)")
		version = fs.String("version", "", "exact version to arrive at (required)")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "idunn installer: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	for _, f := range []struct{ name, val string }{
		{"--root", *root}, {"--channel", *channel}, {"--version", *version},
	} {
		if f.val == "" {
			_, _ = fmt.Fprintf(stderr, "idunn installer: apply requires %s\n", f.name)
			return exitUsage
		}
	}

	cfg, code := buildConfig(config{
		root:    *root,
		channel: *channel,
		version: *version,
		quiet:   true,
		// Already privileged: elevating again would be a loop, and there is
		// nothing left to ask for.
		elevate: false,
		// No anchor, URL or cache from the caller. See the doc comment.
		requireEmbedded: true,
	}, stdout, stderr)
	if code != exitOK {
		return code
	}
	return doInstall(cfg, stdout, stderr)
}

// config is one resolved run, after flags and the embedded anchor have been
// reconciled.
type config struct {
	root           string
	channel        string
	version        string
	allowDowngrade bool
	metadataURL    string
	targetsURL     string
	anchorFromFlag []byte
	cache          string
	quiet          bool

	// elevate wires the interactive elevator when the root needs privileges.
	elevate bool

	// requireEmbedded refuses to run unless the build carries its own anchor and
	// repository description. It is what makes the privileged verb independent
	// of its caller.
	requireEmbedded bool

	// anchorRoot is the resolved trust anchor.
	anchorRoot []byte
}

// buildConfig validates the flags against what the build embeds. It returns an
// exit code rather than an error so every refusal keeps its own classification.
func buildConfig(c config, _, stderr io.Writer) (config, int) {
	if c.root == "" {
		_, _ = fmt.Fprintln(stderr, "idunn installer: --root is required")
		return c, exitUsage
	}
	abs, err := filepath.Abs(c.root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: --root: %v\n", err)
		return c, exitUsage
	}
	c.root = abs
	if c.version != "" && !release.ValidVersion(c.version) {
		_, _ = fmt.Fprintf(stderr, "idunn installer: --version %q is not SemVer\n", c.version)
		return c, exitUsage
	}

	a, err := loadAnchor()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return c, exitError
	}
	if c.requireEmbedded && (!a.hasRoot() || a.repo.MetadataURL == "") {
		_, _ = fmt.Fprintln(stderr, "idunn installer: the privileged apply verb needs a build that embeds "+
			"its own trust anchor and repository; this build carries none")
		return c, exitError
	}

	c.anchorRoot, err = a.trustAnchor(c.anchorFromFlag)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return c, exitUsage
	}
	c.metadataURL, c.targetsURL, err = a.urls(c.metadataURL, c.targetsURL)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return c, exitUsage
	}
	c.channel = a.channel(c.channel)

	if c.cache == "" {
		c.cache, err = defaultCacheDir(c.root)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
			return c, exitError
		}
	}
	return c, exitOK
}

// doInstall wires core and runs the install, then maps the outcome onto an exit
// code.
func doInstall(c config, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	o, code := options(c, stdout, stderr)
	if code != exitOK {
		return code
	}

	err := installer.Install(ctx, o)
	switch {
	case err == nil:
		installed, verr := installer.InstalledVersion(c.root)
		if verr != nil {
			_, _ = fmt.Fprintf(stderr, "idunn installer: installed, but the install state is unreadable: %v\n", verr)
			return exitError
		}
		if !c.quiet {
			_, _ = fmt.Fprintf(stdout, "%s is installed at %s\n", installed, c.root)
		}
		return exitOK
	case errors.Is(err, installer.ErrRefused):
		// Not a failure: an installer that finds a newer install has done its
		// job by refusing, and the answer is the application's own updater.
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return exitRefused
	case errors.Is(err, elevate.ErrDeclined):
		_, _ = fmt.Fprintln(stderr, "idunn installer: the elevation prompt was declined; nothing was installed")
		return exitDeclined
	case errors.Is(err, elevate.ErrNotImplemented):
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v; re-run with the privileges %s requires\n", err, c.root)
		return exitPrivileges
	case errors.Is(err, context.Canceled):
		_, _ = fmt.Fprintln(stderr, "idunn installer: interrupted; nothing was installed")
		return exitError
	default:
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return exitError
	}
}

// options assembles the core configuration: transport, trust client, policy and
// the elevation decision.
func options(c config, stdout, stderr io.Writer) (installer.Options, int) {
	fetcher, err := fetch.New(fetch.Options{UserAgent: userAgent})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return installer.Options{}, exitError
	}
	tc, err := trust.New(trust.Options{
		Root:        c.anchorRoot,
		MetadataURL: c.metadataURL,
		TargetsURL:  c.targetsURL,
		LocalDir:    c.cache,
		Fetcher:     fetcher,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return installer.Options{}, exitError
	}

	stamp, err := parseBuildTime(buildTime)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: this build carries an unusable build time: %v\n", err)
		return installer.Options{}, exitError
	}

	o := installer.Options{
		Updater: updater.Options{
			Trust:         tc,
			Fetcher:       fetcher,
			FS:            fsx.OS(),
			Root:          c.root,
			Channel:       c.channel,
			ClientVersion: clientVersion,
			BuildTime:     stamp,
			Policy: updater.Policy{
				// A first install has nothing to roll back to, but the tree it
				// leaves behind is the one the updater will roll back into.
				RetainVersions: 2,
				// Cheap here — an install writes every file anyway — and it is
				// the check that catches what happened to the bytes between
				// staging and the swap (§11.3 T9).
				VerifyAfterApply: true,
			},
		},
		Version:        c.version,
		AllowDowngrade: c.allowDowngrade,
	}
	if !c.quiet {
		o.Updater.Observe = &progress{w: stdout}
	}

	code, err := wireElevation(&o, c)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn installer: %v\n", err)
		return installer.Options{}, code
	}
	return o, exitOK
}

// wireElevation decides whether this install needs privileges, and arranges for
// them if it does.
//
// The probe errs towards "needs elevation" (core/elevate), and so does this: an
// install root we cannot write and cannot elevate for is refused before the
// network is touched, rather than halfway through a swap.
func wireElevation(o *installer.Options, c config) (int, error) {
	if !c.elevate {
		return exitOK, nil
	}
	needs, err := elevate.NeedsElevation(c.root)
	if err != nil {
		return exitError, fmt.Errorf("cannot tell whether %s needs privileges: %w", c.root, err)
	}
	if !needs {
		return exitOK, nil
	}
	// The elevated half of this is `apply`, which takes its anchor and URL from
	// the build. A binary without them cannot serve as its own helper, and
	// saying so beats a privileged process that fails after the prompt.
	a, err := loadAnchor()
	if err != nil {
		return exitError, err
	}
	if !a.hasRoot() || a.repo.MetadataURL == "" {
		return exitPrivileges, fmt.Errorf("%s needs privileges, and this build embeds no trust anchor to "+
			"re-verify with once elevated; re-run with those privileges instead", c.root)
	}
	el, err := elevate.NewInteractive(elevate.InteractiveOptions{})
	if err != nil {
		if errors.Is(err, elevate.ErrNotImplemented) {
			return exitPrivileges, fmt.Errorf("%s needs privileges and this platform has no prompt yet (%w); "+
				"re-run with those privileges", c.root, err)
		}
		return exitError, err
	}
	o.Updater.Elevator = el
	o.Updater.Policy.Elevation = updater.ElevationInteractive
	return exitOK, nil
}

// parseBuildTime reads the linker-set stamp. Both spellings are accepted because
// both are what a build system has to hand: RFC3339 from `date -u`, and a Unix
// timestamp from SOURCE_DATE_EPOCH.
//
// An unparsable stamp is an error rather than a silent zero: a build that meant
// to carry a floor and does not would look identical to one that never had one.
func parseBuildTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is neither RFC3339 nor a Unix timestamp", raw)
	}
	return time.Unix(secs, 0).UTC(), nil
}

// defaultCacheDir is where trusted TUF metadata and the target cache live.
//
// It is keyed by install root so two installs never share trusted metadata
// state, and it lives in the user's cache directory rather than in the install
// root: the root may not exist yet, and it may be one this process cannot write
// — which is precisely the case where elevation is about to happen.
func defaultCacheDir(root string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("no cache directory (%w); pass --cache", err)
	}
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(base, "idunn", "installer", hex.EncodeToString(sum[:8])), nil
}

// progress renders lifecycle events as lines. It is the smallest possible
// Observer, and it exists as much to keep that hook surface exercised by
// something other than a test as to inform the user.
type progress struct{ w io.Writer }

func (p *progress) OnEvent(e hook.Event) {
	switch {
	case e.Err != nil:
		_, _ = fmt.Fprintf(p.w, "%-8s %s: %v\n", e.Phase, e.Message, e.Err)
	case e.Progress >= 0:
		_, _ = fmt.Fprintf(p.w, "%-8s %s (%.0f%%)\n", e.Phase, e.Message, e.Progress*100)
	default:
		_, _ = fmt.Fprintf(p.w, "%-8s %s\n", e.Phase, e.Message)
	}
}
