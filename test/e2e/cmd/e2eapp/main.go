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
	"embed"
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
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
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
		_, _ = fmt.Fprintln(stderr, "usage: e2eapp version|install|update [--root dir]")
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
	default:
		_, _ = fmt.Fprintf(stderr, "e2eapp: unknown command %q\n", args[0])
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "e2eapp: %v\n", err)
		return 1
	}
	return 0
}

func withRoot(args []string, stdout io.Writer, verb func(context.Context, updater.Options, io.Writer) error) error {
	fl := flag.NewFlagSet("e2eapp", flag.ContinueOnError)
	root := fl.String("root", "", "install root (required)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *root == "" {
		return errors.New("--root is required")
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	o, err := options(abs, stdout)
	if err != nil {
		return err
	}
	return verb(context.Background(), o, stdout)
}

// options wires the client exactly as a host would, with one difference: the
// transport maps TUF paths onto flat release asset names.
func options(root string, stdout io.Writer) (updater.Options, error) {
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
		// Next to the install root rather than in it, so the layout sees only
		// what idunn put there, and a fresh root never meets stale metadata.
		LocalDir: root + ".tuf",
		Fetcher:  fetcher,
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
