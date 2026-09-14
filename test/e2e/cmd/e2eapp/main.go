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

// Command e2eapp is the application the GitHub end-to-end test publishes,
// installs and updates (test/e2e/run.sh). It is a host application the way a
// real one would be written: the trust anchor is embedded, the repository is a
// GitHub release, and it updates itself headlessly through core/updater.
//
//	e2eapp version                 print the version this binary was built as
//	e2eapp install --root <dir>    first install from the release
//	e2eapp update  --root <dir>    check and apply an update, no prompts
//	e2eapp status  --root <dir>    print the install state the test attests
//	e2eapp apply   --root <dir> --channel <c> --version <v>
//	                               the privileged helper; started elevated by
//	                               install and update, never by hand
//
// An install root this process cannot write (C:\Program Files, or any directory
// only administrators may change) is installed and updated through
// core/elevate: the check runs here, unprivileged, and the transaction runs in
// this same binary started elevated with the `apply` verb, which refreshes and
// resolves everything again on its own.
//
// Exit codes: 0 ok, 1 error, 2 usage, 3 refused by update policy (a downgrade,
// a migration floor, a client too old), 4 the elevation prompt was declined,
// 5 the install root is not administrators-only and is not elevated for.
// A refusal is kept apart from an error so a test that expects one cannot pass
// on a network failure.
//
// Build-time configuration, all through the linker:
//
//	-X main.version=1.0.0
//	-X main.buildTime=2026-09-14T12:00:00Z
//	-X main.releaseURL=https://github.com/<owner>/<repo>/releases/download/<tag>
//
// and anchor/root.json, which run.sh writes before building.
package main

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/test/e2e/ghfetch"
)

var (
	version    = "0.0.0-dev"
	buildTime  = ""
	releaseURL = ""
)

const channel = "stable"

// The trust anchor, generated per run. A tree without it builds, and every
// verb that needs it refuses.
//
//go:embed anchor
var anchorFS embed.FS

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: e2eapp version|install|update|status|apply [--root dir]")
		return 2
	}
	var err error
	switch args[0] {
	case "version":
		_, err = fmt.Fprintln(stdout, version)
	case "install":
		err = withRoot(args[1:], stdout, doInstall)
	case "update":
		err = withRoot(args[1:], stdout, doUpdate)
	case "status":
		err = status(args[1:], stdout)
	case "apply":
		err = applyVerb(args[1:], stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "e2eapp: unknown command %q\n", args[0])
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "e2eapp: %v\n", err)
		switch {
		case errors.Is(err, updater.ErrPolicy):
			return 3
		case errors.Is(err, elevate.ErrDeclined):
			return 4
		case errors.Is(err, elevate.ErrUnsafeRoot):
			return 5
		}
		return 1
	}
	return 0
}

// rootFlag parses the one flag every stateful verb takes.
func rootFlag(args []string) (string, error) {
	fl := flag.NewFlagSet("e2eapp", flag.ContinueOnError)
	root := fl.String("root", "", "install root (required)")
	if err := fl.Parse(args); err != nil {
		return "", err
	}
	if *root == "" {
		return "", errors.New("--root is required")
	}
	return filepath.Abs(*root)
}

func withRoot(args []string, stdout io.Writer, verb func(context.Context, updater.Options, io.Writer) error) error {
	abs, err := rootFlag(args)
	if err != nil {
		return err
	}
	needs, err := elevate.NeedsElevation(abs)
	if err != nil {
		return fmt.Errorf("cannot tell whether %s needs privileges: %w", abs, err)
	}
	if !needs {
		// Next to the install root rather than in it, so the layout sees only
		// what idunn put there, and a fresh root never meets stale metadata.
		o, err := options(abs, abs+".tuf", stdout)
		if err != nil {
			return err
		}
		return verb(context.Background(), o, stdout)
	}

	// Next to the root is inside a directory this process cannot write either,
	// so the unprivileged check keeps its cache with the user. Nothing privileged
	// ever reads it: the helper has a cache of its own (elevate.PrivilegedCacheDir).
	base, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(abs))
	o, err := options(abs, filepath.Join(base, "idunn-e2eapp", hex.EncodeToString(sum[:8])), stdout)
	if err != nil {
		return err
	}
	// The helper refuses such a root; asking for consent first would be a
	// prompt for nothing.
	if err := elevate.CheckPrivilegedRoot(abs); err != nil {
		return err
	}
	// Where no prompt is built, NewInteractive always fails, so staticcheck is
	// right that the comparison is constant on that platform — and wrong about
	// Windows, where this is the path that elevates. See cmd/installer.
	//
	//nolint:staticcheck // SA4023: true per platform, not per program.
	el, err := elevate.NewInteractive(elevate.InteractiveOptions{})
	//nolint:staticcheck // SA4023: as above.
	if err != nil {
		return err
	}
	o.Elevator = el
	o.Policy.Elevation = updater.ElevationInteractive
	_, _ = fmt.Fprintf(stdout, "  %s needs privileges; the apply will ask for them\n", abs)
	return verb(context.Background(), o, stdout)
}

// applyVerb is the privileged helper. It takes the three scalars core/elevate
// sends and nothing else, validates them by the same grammar, refuses a root
// anyone but an administrator controls, and answers with
// an update of its own: its own refresh, its own resolution of the channel head,
// its own cache inside the root. The requested version only has to agree.
func applyVerb(args []string, stdout io.Writer) error {
	fl := flag.NewFlagSet("apply", flag.ContinueOnError)
	root := fl.String("root", "", "install root")
	ch := fl.String("channel", "", "channel")
	ver := fl.String("version", "", "version")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", fl.Arg(0))
	}
	req, err := elevate.AcceptRequest(*root, *ch, *ver)
	if err != nil {
		return err
	}
	// The channel is this application's own; a request for another one is not
	// a request this build answers.
	if req.Channel != channel {
		return fmt.Errorf("%w: channel %q, this application follows %q", elevate.ErrRequest, req.Channel, channel)
	}
	o, err := options(req.Root, elevate.PrivilegedCacheDir(req.Root), stdout)
	if err != nil {
		return err
	}
	u, err := updater.New(o)
	if err != nil {
		return err
	}
	return u.ApplyRequested(context.Background(), req.Version)
}

// options wires the client exactly as a host would, with one difference: the
// transport maps TUF paths onto flat release asset names.
func options(root, cache string, stdout io.Writer) (updater.Options, error) {
	anchor, err := anchorFS.ReadFile("anchor/root.json")
	if err != nil {
		return updater.Options{}, fmt.Errorf("this build embeds no trust anchor: %w", err)
	}
	if releaseURL == "" {
		return updater.Options{}, errors.New("this build carries no release URL")
	}
	var stamp time.Time
	if buildTime != "" {
		if stamp, err = time.Parse(time.RFC3339, buildTime); err != nil {
			return updater.Options{}, fmt.Errorf("build time: %w", err)
		}
	}

	base, err := fetch.New(fetch.Options{UserAgent: "idunn-e2eapp/" + version})
	if err != nil {
		return updater.Options{}, err
	}
	fetcher, err := ghfetch.New(base, releaseURL)
	if err != nil {
		return updater.Options{}, err
	}
	tc, err := trust.New(trust.Options{
		Root:        anchor,
		MetadataURL: releaseURL + "/metadata/",
		TargetsURL:  releaseURL + "/targets/",
		LocalDir:    cache,
		Fetcher:     fetcher,
	})
	if err != nil {
		return updater.Options{}, err
	}
	return updater.Options{
		Trust:         tc,
		Fetcher:       fetcher,
		FS:            fsx.OS(),
		Root:          root,
		Channel:       channel,
		ClientVersion: version,
		BuildTime:     stamp,
		Observe:       &progress{w: stdout},
		Policy: updater.Policy{
			RetainVersions:   2,
			VerifyAfterApply: true,
		},
	}, nil
}

func doInstall(ctx context.Context, o updater.Options, stdout io.Writer) error {
	if err := installer.Install(ctx, installer.Options{Updater: o}); err != nil {
		return err
	}
	v, err := installer.InstalledVersion(o.Root)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "installed %s\n", v)
	return err
}

func doUpdate(ctx context.Context, o updater.Options, stdout io.Writer) error {
	u, err := updater.New(o)
	if err != nil {
		return err
	}
	rel, err := u.CheckForUpdate(ctx)
	if err != nil {
		return err
	}
	if rel == nil {
		_, err = fmt.Fprintf(stdout, "up to date at %s\n", version)
		return err
	}
	if err := u.Apply(ctx, rel); err != nil {
		return err
	}
	v, err := installer.InstalledVersion(o.Root)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "updated %s -> %s\n", rel.FromVersion, v)
	return err
}

// progress writes lifecycle events, so a failed CI run shows how far it got.
type progress struct{ w io.Writer }

func (p *progress) OnEvent(e hook.Event) {
	if e.Err != nil {
		_, _ = fmt.Fprintf(p.w, "  %-8s %s: %v\n", e.Phase, e.Message, e.Err)
		return
	}
	_, _ = fmt.Fprintf(p.w, "  %-8s %s\n", e.Phase, e.Message)
}

// status prints the install state as key=value lines, without touching the
// network: the version the pointer and the recorded state agree on, the version
// directories that exist, whether a transaction is still open, and how much is
// left in staging. It is what the test attests after every step.
func status(args []string, stdout io.Writer) error {
	root, err := rootFlag(args)
	if err != nil {
		return err
	}
	installed, err := installer.InstalledVersion(root)
	if err != nil {
		return err
	}
	versions, err := dirNames(filepath.Join(root, layout.VersionsName))
	if err != nil {
		return err
	}
	staging, err := dirNames(filepath.Join(root, layout.MetaName, layout.StagingName))
	if err != nil {
		return err
	}
	// The journal keeps its history after a commit, so what matters is the
	// last record: COMMITTED means no transaction is left open.
	j, err := txn.Open(fsx.OS(), root)
	if err != nil {
		return err
	}
	journal := "none"
	if last, ok := j.Last(); ok {
		journal = fmt.Sprintf("%s:%s->%s", last.State, last.FromVersion, last.ToVersion)
	}
	_, err = fmt.Fprintf(stdout, "installed=%s\nversions=%s\njournal=%s\nstaging=%d\n",
		installed, strings.Join(versions, ","), journal, len(staging))
	return err
}

// dirNames lists a directory sorted by name; a missing directory is empty.
func dirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
