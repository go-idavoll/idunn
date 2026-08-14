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

	c, err := trust.New(trust.Options{
		Root:        rootBytes,
		MetadataURL: srv.MetadataURL(),
		TargetsURL:  srv.TargetsURL(),
		LocalDir:    filepath.Join(workDir, "cache"),
		Now:         func() time.Time { return at },
	})
	if err != nil {
		res.Err, res.Class = err, classify(err)
		return res
	}
	c.UnsafeSetRefTime(at)

	err = installer.Install(context.Background(), installer.Options{
		Updater: updater.Options{
			Trust:   c,
			FS:      fsx.OS(),
			Root:    installRoot,
			Channel: opts.Channel,
			OS:      opts.OS,
			Arch:    opts.Arch,
			Now:     func() time.Time { return at },
		},
	})
	res.Err, res.Class = err, classify(err)
	return res
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
