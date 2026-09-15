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

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/anchor"
)

// serveVerb runs the helper until it is told to stop. Under the Windows service
// control manager it speaks the service protocol (platform_windows.go); anywhere
// else it runs in the foreground and stops on SIGINT or SIGTERM, which is what
// launchd and systemd send.
func serveVerb(args []string, stderr io.Writer) int {
	if !noArgs("serve", args, stderr) {
		return exitUsage
	}
	return runService(func(ctx context.Context, logw io.Writer) int {
		return serve(ctx, logw)
	}, stderr)
}

// serve builds the helper from the embedded configuration and this machine's
// caller list, and answers requests until ctx is done.
func serve(ctx context.Context, logw io.Writer) int {
	logger := log.New(logw, "helper: ", log.LstdFlags|log.LUTC)

	b, err := loadBuild(buildFS)
	if err != nil {
		logger.Print(err)
		return exitRefuse
	}
	paths, err := pathsFor(b.helper.Label)
	if err != nil {
		logger.Print(err)
		return exitRefuse
	}
	// The caller list is only as trustworthy as the directory it lives in.
	if err := elevate.CheckPrivilegedRoot(paths.StateDir); err != nil {
		logger.Printf("state directory: %v", err)
		return exitRefuse
	}
	c, _, err := readCallers(paths.StateDir)
	if err != nil {
		logger.Print(err)
		return exitRefuse
	}
	if err := prepareEndpoint(paths.Endpoint); err != nil {
		logger.Print(err)
		return exitRefuse
	}

	opts := elevate.HelperOptions{
		Endpoint: paths.Endpoint,
		Applier: updater.RequestApplier{
			Channel: channelOf(b),
			Options: func(root, cacheDir string) (updater.Options, error) {
				return updaterOptions(b, root, cacheDir)
			},
		},
		AllowedRoots:    b.helper.AllowedRoots,
		PeerRequirement: b.helper.PeerRequirement,
		MinInterval:     b.helper.minInterval(),
		OnEvent:         func(msg string) { logger.Print(msg) },
	}
	if runtime.GOOS == "windows" {
		opts.AllowedSIDs = c.SIDs
	} else {
		opts.AllowedUIDs = c.UIDs
	}
	if (runtime.GOOS == "windows" && len(c.UIDs) > 0) || (runtime.GOOS != "windows" && len(c.SIDs) > 0) {
		logger.Printf("%s lists callers for another platform; they are not used here", callersName)
	}

	h, err := elevate.NewHelper(opts)
	if err != nil {
		logger.Print(err)
		return exitRefuse
	}
	defer func() { _ = h.Close() }()
	logger.Printf("serving %s (version %s, %d roots) on %s", b.helper.Label, versionString(), len(opts.AllowedRoots), paths.Endpoint)
	if err := h.Serve(ctx); err != nil {
		logger.Print(err)
		return exitError
	}
	logger.Print("stopped")
	return exitOK
}

// prepareEndpoint creates the directory a Unix socket lives in, as root with
// mode 0755, when it does not exist yet. Whether that directory and everything
// above it is fit to hold the socket is then judged by elevate.NewHelper. On
// Windows the endpoint is a pipe and there is nothing to create.
func prepareEndpoint(endpoint string) error {
	if strings.HasPrefix(endpoint, `\\.\pipe\`) {
		return nil
	}
	dir := filepath.Dir(endpoint)
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	// 0755 and no narrower: callers must be able to reach the socket inside, and
	// nobody but root may create names next to it (elevate's checkSocketDir).
	//
	//nolint:gosec // G301: see above.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	// MkdirAll is subject to the umask; the directory must be exactly 0755.
	//
	//nolint:gosec // G302: see above.
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	return nil
}

// updaterOptions builds the privileged side's updater for one install root: its
// own trust client from the embedded anchor, with its metadata and targets in the
// root's privileged cache, never anywhere a caller can write (§14.8, T23).
func updaterOptions(b *build, root, cacheDir string) (updater.Options, error) {
	fetcher, err := fetch.New(fetch.Options{UserAgent: "idunn-helper/" + versionString()})
	if err != nil {
		return updater.Options{}, err
	}
	targetsURL, err := anchor.TargetsURL(b.anchor.Repo.MetadataURL, b.anchor.Repo.TargetsURL)
	if err != nil {
		return updater.Options{}, err
	}
	tc, err := trust.New(trust.Options{
		Root:        b.anchor.Root,
		MetadataURL: b.anchor.Repo.MetadataURL,
		TargetsURL:  targetsURL,
		LocalDir:    cacheDir,
		Fetcher:     fetcher,
	})
	if err != nil {
		return updater.Options{}, err
	}
	stamp, err := parseBuildTime(buildTime)
	if err != nil {
		return updater.Options{}, err
	}
	return updater.Options{
		Trust:         tc,
		Fetcher:       fetcher,
		FS:            fsx.OS(),
		Root:          root,
		ClientVersion: version,
		BuildTime:     stamp,
		// A system-wide installation's "Installed apps" entry is in
		// HKEY_LOCAL_MACHINE; the helper that applies the update is the
		// process that can bring it up to date (IDN-36).
		Registry: integrate.OSRegistry(),
		Policy: updater.Policy{
			RetainVersions:   2,
			VerifyAfterApply: true,
		},
	}, nil
}

// parseBuildTime reads the linker-set stamp: RFC3339 or Unix seconds, empty for
// none. An unparsable stamp is an error, not a silent zero.
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
		return time.Time{}, fmt.Errorf("%w: build time %q is neither RFC3339 nor Unix seconds", ErrConfig, raw)
	}
	return time.Unix(secs, 0).UTC(), nil
}
