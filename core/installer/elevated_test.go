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

package installer_test

import (
	"context"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/installer"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// readOnlyRoot is an install root the installing process may read but not write.
type readOnlyRoot struct {
	*fsx.Mem
	attempts []string
}

func (r *readOnlyRoot) deny(op, name string) error {
	if name == root || strings.HasPrefix(name, root+"/") {
		r.attempts = append(r.attempts, op+" "+name)
		return &fs.PathError{Op: op, Path: name, Err: fs.ErrPermission}
	}
	return nil
}

func (r *readOnlyRoot) Create(name string, mode fs.FileMode) (io.WriteCloser, error) {
	if err := r.deny("create", name); err != nil {
		return nil, err
	}
	return r.Mem.Create(name, mode)
}

func (r *readOnlyRoot) MkdirAll(name string, mode fs.FileMode) error {
	if err := r.deny("mkdir", name); err != nil {
		return err
	}
	return r.Mem.MkdirAll(name, mode)
}

func (r *readOnlyRoot) Rename(oldname, newname string) error {
	if err := r.deny("rename", newname); err != nil {
		return err
	}
	return r.Mem.Rename(oldname, newname)
}

func (r *readOnlyRoot) Remove(name string) error {
	if err := r.deny("remove", name); err != nil {
		return err
	}
	return r.Mem.Remove(name)
}

func (r *readOnlyRoot) RemoveAll(name string) error {
	if err := r.deny("removeall", name); err != nil {
		return err
	}
	return r.Mem.RemoveAll(name)
}

// installHelper is the privileged `apply` verb of cmd/installer, in-process: an
// install of its own, pinned to the requested version, on a filesystem it may
// write.
type installHelper struct {
	opts installer.Options
	err  error
}

func (h *installHelper) Apply(ctx context.Context, r string, d *release.Descriptor) error {
	o := h.opts
	o.Updater.Root = r
	o.Updater.Channel = d.Channel
	o.Version = d.Version
	h.err = installer.Install(ctx, o)
	return h.err
}

func TestElevatedInstallWritesNothingUnprivileged(t *testing.T) {
	f := newFixture(t, "1.3.0")
	now := time.Unix(1_700_000_000, 0).UTC()
	f.opts.Updater.Now = func() time.Time { return now }

	helper := &installHelper{opts: f.opts}
	// A minute later than the helper's clock, so a floor record on this side
	// would be a real write rather than a no-op on a floor that is already
	// there.
	f.opts.Updater.Now = func() time.Time { return now.Add(time.Minute) }
	ro := &readOnlyRoot{Mem: f.fs}
	f.opts.Updater.FS = ro
	f.opts.Updater.Elevator = helper
	f.opts.Updater.Policy.Elevation = updater.ElevationInteractive

	if err := installer.Install(context.Background(), f.opts); err != nil {
		t.Fatalf("elevated Install = %v (helper: %v)", err, helper.err)
	}
	if len(ro.attempts) != 0 {
		t.Fatalf("the unprivileged installer tried to write the root: %q", ro.attempts)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	// The floor is still recorded — by the side that can write it.
	if _, err := f.fs.Stat(layout.Clock(root)); err != nil {
		t.Fatalf("the helper recorded no time floor: %v", err)
	}
}
