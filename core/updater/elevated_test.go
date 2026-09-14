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

package updater_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// readOnlyRoot is the view an unprivileged process has of a system-wide install
// (C:\Program Files, /opt): everything under the root reads, nothing under it
// writes. Every attempt is counted, so a test can prove that the unprivileged
// side did not merely fail to write but never tried.
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

func (r *readOnlyRoot) Rename(oldname, newname string) error {
	if err := r.deny("rename", newname); err != nil {
		return err
	}
	if err := r.deny("rename", oldname); err != nil {
		return err
	}
	return r.Mem.Rename(oldname, newname)
}

func (r *readOnlyRoot) Symlink(target, linkname string) error {
	if err := r.deny("symlink", linkname); err != nil {
		return err
	}
	return r.Mem.Symlink(target, linkname)
}

// helperElevator plays the elevated helper in-process: it receives exactly what
// crosses the boundary — root, channel, version — and answers it the way a host's
// `apply` verb does, with an Updater of its own that can write the root.
type helperElevator struct {
	helper updater.Options // the privileged side's own configuration.
	calls  int
	root   string
	seen   *release.Descriptor
	err    error // what the helper returned.
}

func (e *helperElevator) Apply(ctx context.Context, r string, d *release.Descriptor) error {
	e.calls++
	e.root = r
	e.seen = d
	o := e.helper
	o.Root = r
	o.Channel = d.Channel
	u, err := updater.New(o)
	if err != nil {
		e.err = err
		return err
	}
	e.err = u.ApplyRequested(ctx, d.Version)
	if e.err != nil {
		// A real helper reports only an exit status across the boundary.
		return elevate.ErrHelper
	}
	return nil
}

// elevated rewires the fixture as a system-wide install: the unprivileged updater
// sees a root it cannot write and elevates through an in-process helper that can.
func (f *fixture) elevated() (*readOnlyRoot, *helperElevator) {
	ro := &readOnlyRoot{Mem: f.fs}
	helper := f.opts
	helper.FS = f.fs
	// The helper has its own hooks in a real host; sharing the recorder here
	// would count its events and outcomes as the unprivileged side's.
	helper.Observe, helper.Report = nil, nil
	el := &helperElevator{helper: helper}

	f.opts.FS = ro
	f.opts.Elevator = el
	f.opts.Policy.Elevation = updater.ElevationInteractive
	return ro, el
}

func (f *fixture) journalExists() bool {
	f.t.Helper()
	_, err := f.fs.Stat(layout.Journal(root))
	return err == nil
}

func TestElevatedUpdateWritesNothingUnprivileged(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	ro, el := f.elevated()

	if err := f.run(); err != nil {
		t.Fatalf("elevated update = %v (helper: %v)", err, el.err)
	}
	if len(ro.attempts) != 0 {
		t.Fatalf("the unprivileged side tried to write the root: %q", ro.attempts)
	}
	if el.calls != 1 || el.root != root || el.seen.Version != "1.3.0" || el.seen.Channel != channel {
		t.Fatalf("the helper was asked %d times for %q %+v", el.calls, el.root, el.seen)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	if got := f.stateVersion(); got != "1.3.0" {
		t.Fatalf("state = %q, want 1.3.0", got)
	}
	// Once for the unprivileged check, once for the helper's own: the helper
	// never acts on metadata it did not refresh itself.
	if f.trust.refreshes != 2 {
		t.Fatalf("refreshes = %d, want 2", f.trust.refreshes)
	}
	if n := len(f.hooks.outcomes); n != 1 || f.hooks.outcomes[0].Result != "committed" {
		t.Fatalf("outcomes = %+v, want one committed", f.hooks.outcomes)
	}
}

// Without the elevated path the same read-only root fails at the first journal
// record. This is the failure the elevated path exists to avoid, pinned so the
// test above cannot pass for a reason other than elevation.
func TestAnUnprivilegedUpdateCannotWriteASystemRoot(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.opts.FS = &readOnlyRoot{Mem: f.fs}

	if err := f.run(); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("unprivileged update of a read-only root = %v, want a permission error", err)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
}

// A helper that exits zero has not thereby installed anything. Recording its
// word as the outcome would report an update that never happened.
func TestElevatedUpdateDoesNotTakeTheHelpersWordForIt(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	f.elevated()
	el := &fakeElevator{} // exits zero, installs nothing.
	f.opts.Elevator = el

	err := f.run()
	if !errors.Is(err, elevate.ErrHelper) {
		t.Fatalf("Apply() = %v, want ErrHelper", err)
	}
	if el.calls != 1 {
		t.Fatalf("the elevator was called %d times, want once", el.calls)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current = %q, want 1.2.0", got)
	}
	o := f.hooks.outcomes[0]
	if o.Result != "aborted" || o.ErrorClass != "elevation" {
		t.Fatalf("outcome = %+v, want aborted/elevation", o)
	}
}

func TestElevatedUpdateDeclinedAtThePrompt(t *testing.T) {
	f := newFixture(t, "1.2.0", "1.3.0")
	ro, _ := f.elevated()
	f.opts.Elevator = &fakeElevator{err: elevate.ErrDeclined}

	err := f.run()
	if !errors.Is(err, elevate.ErrDeclined) {
		t.Fatalf("Apply() = %v, want elevate.ErrDeclined", err)
	}
	if len(ro.attempts) != 0 || f.journalExists() {
		t.Fatalf("a declined prompt left traces: attempts %q, journal %v", ro.attempts, f.journalExists())
	}
	if o := f.hooks.outcomes[0]; o.Result != "aborted" || o.ErrorClass != "declined" {
		t.Fatalf("outcome = %+v, want aborted/declined", o)
	}
}

// Everything that can be refused without privileges is refused before the prompt
// is raised. A consent dialog for an update that is certain to be refused
// teaches users to click it away.
func TestElevatedUpdateRefusesBeforeThePrompt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture) *updater.Release
		want  error
	}{
		{"host check refuses", func(f *fixture) *updater.Release {
			f.hooks.checkErr = errors.New("disk full")
			f.opts.Check = f.hooks
			return nil
		}, updater.ErrCheck},
		{"user declines", func(f *fixture) *updater.Release {
			f.hooks.confirm = false
			f.opts.Prompt = f.hooks
			return nil
		}, updater.ErrDeclined},
		{"stale release", func(*fixture) *updater.Release {
			return &updater.Release{Descriptor: descriptor("1.3.0"), FromVersion: "1.1.0"}
		}, updater.ErrStale},
		{"already installed", func(*fixture) *updater.Release {
			return &updater.Release{Descriptor: descriptor("1.2.0"), FromVersion: "1.2.0"}
		}, updater.ErrStale},
		{"downgrade", func(*fixture) *updater.Release {
			return &updater.Release{Descriptor: descriptor("1.0.0"), FromVersion: "1.2.0"}
		}, updater.ErrPolicy},
		{"other channel", func(*fixture) *updater.Release {
			d := descriptor("1.3.0")
			d.Channel = "beta"
			return &updater.Release{Descriptor: d, FromVersion: "1.2.0"}
		}, updater.ErrPolicy},
		{"clock below the build time", func(f *fixture) *updater.Release {
			f.opts.BuildTime = f.opts.Now().AddDate(0, 1, 0)
			return &updater.Release{Descriptor: descriptor("1.3.0"), FromVersion: "1.2.0"}
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			ro, el := f.elevated()
			rel := tc.setup(f)
			u := f.updater()
			var err error
			if rel == nil {
				if rel, err = u.CheckForUpdate(context.Background()); err != nil || rel == nil {
					t.Fatalf("CheckForUpdate = %v, %v", rel, err)
				}
			}
			err = u.Apply(context.Background(), rel)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Apply() = %v, want %v", err, tc.want)
			}
			if el.calls != 0 {
				t.Fatal("the elevator was asked anyway")
			}
			if len(ro.attempts) != 0 || f.journalExists() {
				t.Fatalf("a refusal left traces: attempts %q, journal %v", ro.attempts, f.journalExists())
			}
			if got := f.pointer(); got != "1.2.0" {
				t.Fatalf("current = %q, want 1.2.0", got)
			}
		})
	}
}

// A release behind a migration floor the repository bridges is walked by the
// helper, and elevating must not be stricter about it than updating in place.
func TestElevatedUpdateWalksAMigrationFloorInTheHelper(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.3.0")
	f.trust.descriptor.Requirements.MinFromVersion = "1.2.0"
	step := descriptor("1.2.0", ref("targets/app-1.2.0", "app"))
	f.trust.publish(step, map[string][]byte{"targets/app-1.2.0": []byte("binary 1.2.0")})
	_, el := f.elevated()

	if err := f.run(); err != nil {
		t.Fatalf("elevated walk = %v (helper: %v)", err, el.err)
	}
	if el.calls != 1 {
		t.Fatalf("the helper was asked %d times, want once for the whole walk", el.calls)
	}
	if got := f.pointer(); got != "1.3.0" {
		t.Fatalf("current = %q, want 1.3.0", got)
	}
	if got := f.hooks.migrateMarks; len(got) != 2 {
		t.Fatalf("migrations = %q, want one per step of the walk", got)
	}
}

// --- the privileged side ------------------------------------------------------
//
// ApplyRequested is where a hostile unprivileged caller meets the privileges.
// Every case below is a request it must refuse without writing anything.

func TestApplyRequestedInstallsOnlyTheChannelHead(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		setup   func(f *fixture)
		want    error
	}{
		{"an older release that is still an upgrade", "1.2.5", func(f *fixture) {
			f.trust.publish(descriptor("1.2.5", ref("targets/app-1.2.5", "app")),
				map[string][]byte{"targets/app-1.2.5": []byte("binary 1.2.5")})
		}, updater.ErrStale},
		{"a version the repository does not publish", "9.9.9", nil, updater.ErrStale},
		{"the installed version while the head is newer", "1.2.0", nil, updater.ErrStale},
		{"an empty version", "", nil, updater.ErrConfig},
		{"a head that is a downgrade", "1.0.0", func(f *fixture) {
			f.trust.descriptor = descriptor("1.0.0", ref("targets/app", "app"))
		}, updater.ErrPolicy},
		{"a head for another channel", "1.3.0", func(f *fixture) {
			f.trust.descriptor.Channel = "beta"
		}, updater.ErrPolicy},
		{"metadata that does not refresh", "1.3.0", func(f *fixture) {
			f.trust.refreshErr = errors.New("expired timestamp")
		}, nil},
		{"a helper configured to elevate again", "1.3.0", func(f *fixture) {
			f.opts.Elevator = &fakeElevator{}
			f.opts.Policy.Elevation = updater.ElevationInteractive
		}, updater.ErrConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "1.2.0", "1.3.0")
			if tc.setup != nil {
				tc.setup(f)
			}
			err := f.updater().ApplyRequested(context.Background(), tc.version)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("ApplyRequested(%q) = %v, want %v", tc.version, err, tc.want)
			}
			if f.journalExists() {
				t.Fatal("a refused request opened a transaction")
			}
			if got := f.pointer(); got != "1.2.0" {
				t.Fatalf("current = %q, want 1.2.0", got)
			}
			if el, ok := f.opts.Elevator.(*fakeElevator); ok && el.calls != 0 {
				t.Fatal("the helper elevated again")
			}
		})
	}
}

func TestApplyRequestedIsIdempotent(t *testing.T) {
	f := newFixture(t, "1.3.0", "1.3.0")
	if err := f.updater().ApplyRequested(context.Background(), "1.3.0"); err != nil {
		t.Fatalf("ApplyRequested(installed head) = %v, want nil", err)
	}
	if f.journalExists() {
		t.Fatal("a request for the installed version opened a transaction")
	}
	if f.trust.refreshes != 1 {
		t.Fatalf("refreshes = %d, want 1: even a no-op is decided on fresh metadata", f.trust.refreshes)
	}
}
