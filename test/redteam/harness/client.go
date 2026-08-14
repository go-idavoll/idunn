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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/trust"
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

// classify buckets an error for the corpus check. It deliberately distinguishes
// only the two layers a case can be refused by; finer classification belongs to
// the Reporter taxonomy, not here.
func classify(err error) ErrorClass {
	// Order matters: trust wraps the errors it forwards, so the most specific
	// classification has to be tested first.
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
