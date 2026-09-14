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

package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// Result is the outcome of running the client under test against one repository.
type Result struct {
	Descriptor *release.Descriptor
	Err        error
	// Class is the taxonomy bucket Err falls into, or "" if there was no error.
	Class ErrorClass
	// InstallRoot is the directory that must be untouched after a rejection.
	InstallRoot string
}

// Run points a fresh client at srv and attempts a full resolve: TUF refresh, then
// channel pointer to descriptor. It returns whether that succeeded and, on
// failure, which layer refused.
//
// Everything the client persists goes under workDir; the install root stays empty,
// because a rejection must never produce an on-disk change.
func Run(srv *Server, rootBytes []byte, workDir string, refTime time.Time, opts BuildOptions) Result {
	installRoot := filepath.Join(workDir, "install")
	res := Result{InstallRoot: installRoot}

	c, err := trust.New(trust.Options{
		Root:        rootBytes,
		MetadataURL: srv.MetadataURL(),
		TargetsURL:  srv.TargetsURL(),
		LocalDir:    filepath.Join(workDir, "cache"),
		Now:         func() time.Time { return refTime },
	})
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	// Expiry is judged against the case's reference time, never the wall clock,
	// so an expired-metadata case cannot pass or fail by accident of when CI runs.
	c.UnsafeSetRefTime(refTime)

	if err := c.Refresh(); err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	d, err := c.LatestRelease(opts.Channel, opts.OS, opts.Arch)
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}

	// Resolving is not enough: an accepted release must also materialize, which
	// is where a target whose bytes do not match its signed hash is caught.
	for _, f := range d.Files {
		dst := filepath.Join(workDir, "staged", filepath.FromSlash(f.Dst))
		if err := c.MaterializeTarget(f.Target, dst); err != nil {
			res.Err, res.Class = err, classify(err)
			return res
		}
	}

	res.Descriptor = d
	return res
}

// RunInstall drives the real first-install path — core/installer, and through it
// the updater, the time floor and the apply transaction — against srv at the
// given local time.
//
// Run points a bare trust client at a repository, which is the right instrument
// for an attack on the bytes. It is the wrong one for an attack on the clock: the
// known-good floor lives with the installation, so only a run that owns an
// install root can have one at all.
//
// Everything the client persists stays under workDir, and calling it twice with
// the same workDir is the point — that is one machine, running twice.
func RunInstall(srv *Server, rootBytes []byte, workDir string, at time.Time, opts BuildOptions) Result {
	installRoot := filepath.Join(workDir, "install")
	res := Result{InstallRoot: installRoot}

	c, err := machineClient(srv, rootBytes, workDir, at)
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}

	err = installer.Install(context.Background(), installer.Options{
		Updater: machineUpdater(c, workDir, at, opts),
	})
	res.Err, res.Class = err, classify(err)
	return res
}

// UpdateResult is the outcome of running the updater of a machine that already
// has an installation: the delta story, or a downgrade offered to it.
type UpdateResult struct {
	Result

	// Version is what is installed when the dust settles.
	Version string
}

// machineClient is the trust client of one run of the client on the machine at
// workDir. Two runs share the local cache, as two runs on one machine do, but
// never a client: a go-tuf workflow runs once per process.
func machineClient(srv *Server, rootBytes []byte, workDir string, at time.Time) (*trust.Client, error) {
	c, err := trust.New(trust.Options{
		Root:        rootBytes,
		MetadataURL: srv.MetadataURL(),
		TargetsURL:  srv.TargetsURL(),
		LocalDir:    filepath.Join(workDir, "cache"),
		Now:         func() time.Time { return at },
	})
	if err != nil {
		return nil, err
	}
	c.UnsafeSetRefTime(at)
	return c, nil
}

// machineUpdater is the updater configuration of the machine at workDir.
func machineUpdater(c *trust.Client, workDir string, at time.Time, opts BuildOptions) updater.Options {
	return updater.Options{
		Trust:   c,
		FS:      fsx.OS(),
		Root:    filepath.Join(workDir, "install"),
		Channel: opts.Channel,
		OS:      opts.OS,
		Arch:    opts.Arch,
		Now:     func() time.Time { return at },
	}
}

// RunUpdate runs the updater of the machine at workDir once, the way an
// installed application does: check the channel, and apply what it offers.
//
// It is the driver for attacks that need an installation to be attacking at
// all. A channel that offers nothing is reported as an error rather than as
// success: every caller asks it for an update it expects to arrive or to be
// refused, and a run that did neither has not exercised anything.
func RunUpdate(srv *Server, rootBytes []byte, workDir string, at time.Time, opts BuildOptions) UpdateResult {
	installRoot := filepath.Join(workDir, "install")
	res := UpdateResult{Result: Result{InstallRoot: installRoot}}

	c, err := machineClient(srv, rootBytes, workDir, at)
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	u, err := updater.New(machineUpdater(c, workDir, at, opts))
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	rel, err := u.CheckForUpdate(context.Background())
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	if rel == nil {
		res.Err = errors.New("the channel head was not offered as an update")
		return res
	}
	if err := u.Apply(context.Background(), rel); err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}

	res.Version, err = installer.InstalledVersion(installRoot)
	if err != nil {
		res.Err, res.Class = err, classify(err)
	}
	return res
}

// RunPatchedUpdate installs the previous release of a delta build and then
// updates to the head, driving the real path: core/installer, core/updater, the
// route through the releases in between, and core/stage applying whatever
// patches the repository offers.
//
// It is the only driver that can exercise a patch at all, because a patch needs
// a base — an installation that already exists. What it proves is not that a bad
// patch is refused: a patch is not trusted in the first place, so the client is
// free to try it and throw the result away. What it proves is that the bytes
// that end up installed are the signed ones either way.
func RunPatchedUpdate(srv *Server, rootBytes []byte, workDir string, at time.Time, opts BuildOptions) UpdateResult {
	// The machine starts out on the older release. Everything the attack is
	// about happens on top of this.
	c, err := machineClient(srv, rootBytes, workDir, at)
	if err != nil {
		return UpdateResult{Result: Result{InstallRoot: filepath.Join(workDir, "install"), Err: err, Class: classify(err)}}
	}
	if err := installer.Install(context.Background(), installer.Options{
		Updater: machineUpdater(c, workDir, at, opts),
		Version: opts.Previous,
	}); err != nil {
		return UpdateResult{Result: Result{
			InstallRoot: filepath.Join(workDir, "install"),
			Err:         fmt.Errorf("installing %s: %w", opts.Previous, err),
			Class:       classify(err),
		}}
	}

	return RunUpdate(srv, rootBytes, workDir, at, opts)
}

// InstalledBytes reads a file out of the running installation.
//
// It follows the install pointer rather than reading through `current`: on
// POSIX that is a symlink the path can traverse, but on Windows it is a pointer
// file, and `current/<dst>` does not exist there at all.
func InstalledBytes(installRoot, dst string) ([]byte, error) {
	version, err := layout.PointerTarget(fsx.OS(), installRoot)
	if err != nil {
		return nil, err
	}
	if version == "" {
		return nil, fmt.Errorf("%s holds no installation", installRoot)
	}
	dir, err := layout.VersionDir(installRoot, version)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(dst)))
}

// NoTraceOf reports whether marker appears in any file under root.
//
// It is the assertion a delta case turns on. "The update succeeded" is not the
// interesting part — what matters is that nothing the attacker chose is anywhere
// on the machine afterwards, in the installation, in a retained version, or in
// a staging tree somebody forgot to clean up.
func NoTraceOf(root string, marker []byte) error {
	return filepath.WalkDir(root, func(name string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return err
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, marker) {
			return fmt.Errorf("the attacker's bytes are on disk at %s", name)
		}
		return nil
	})
}

// InstalledVersion reports what RunInstall left installed, or "" for nothing.
func InstalledVersion(installRoot string) (string, error) {
	return installer.InstalledVersion(installRoot)
}

// classify buckets an error for the corpus check. It deliberately distinguishes
// only the two layers a case can be refused by; finer classification belongs to
// the Reporter taxonomy, not here.
func classify(err error) ErrorClass {
	// Order matters: trust wraps the errors it forwards, so the most specific
	// classification has to be tested first.
	if errors.Is(err, timefloor.ErrClockRollback) {
		return ClassClock
	}
	if errors.Is(err, release.ErrInvalid) {
		return ClassDescriptor
	}
	if errors.Is(err, updater.ErrPolicy) {
		return ClassPolicy
	}
	if errors.Is(err, trust.ErrResolve) {
		return ClassResolve
	}
	if errors.Is(err, trust.ErrTrust) {
		return ClassVerify
	}
	return ErrorClass(fmt.Sprintf("unclassified(%v)", err))
}

// NoOnDiskChange reports whether the install root is still absent or empty. A
// rejected update must leave nothing behind (AGENTS.md §1.1).
func NoOnDiskChange(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("install root %s is not empty: %d entries", root, len(entries))
	}
	return nil
}
