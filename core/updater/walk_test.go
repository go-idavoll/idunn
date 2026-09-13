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
	"slices"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/updater"
)

// stepping adds a release the walk can pass through: its own payloads, and the
// floor it demands of whatever is installed before it.
func stepping(f *fixture, version, floor, ch string) *release.Descriptor {
	d := descriptor(version, ref("targets/app-"+version, "app"), ref("targets/plugin-"+version, "lib/plugin.so"))
	d.Requirements.MinFromVersion = floor
	if ch != "" {
		d.Channel = ch
	}
	f.trust.publish(d, map[string][]byte{
		"targets/app-" + version:    []byte("binary " + version),
		"targets/plugin-" + version: []byte("library " + version),
	})
	return d
}

// A release that will not migrate from what is installed is not the end of the
// road if the repository published the releases in between: they are installed
// in order, each with its own migration, and the install arrives where it was
// going.
func TestApplyWalksTheReleasesAMigrationFloorDemands(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	stepping(f, "1.1.0", "1.0.0", "")
	head := stepping(f, "1.2.0", "1.1.0", "")
	f.trust.descriptor = head

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := f.stateVersion(); got != "1.2.0" {
		t.Fatalf("installed %q, want 1.2.0", got)
	}
	if got := f.pointer(); got != "1.2.0" {
		t.Fatalf("current points at %q, want 1.2.0", got)
	}
	// Each release migrated in its turn: that is the whole reason for walking
	// rather than jumping.
	if want := []string{"1.1.0", "1.2.0"}; !slices.Equal(f.hooks.migrateMarks, want) {
		t.Fatalf("migrations ran for %v, want %v", f.hooks.migrateMarks, want)
	}
	if got := f.hostState(); got != "1.2.0" {
		t.Fatalf("host state is %q, want 1.2.0", got)
	}

	var installed []string
	for _, e := range f.hooks.events {
		if strings.HasPrefix(e.Message, "installed ") {
			installed = append(installed, strings.TrimPrefix(e.Message, "installed "))
		}
	}
	if want := []string{"1.1.0", "1.2.0"}; !slices.Equal(installed, want) {
		t.Fatalf("installed %v, want %v", installed, want)
	}
	// Every step is a complete update, so every step reports its own outcome.
	if len(f.hooks.outcomes) != 2 {
		t.Fatalf("%d outcomes reported, want one per release", len(f.hooks.outcomes))
	}
}

// The walk is the shortest one the floors allow: a release that may be
// installed directly is not reached through the ones before it.
func TestApplyTakesTheFewestStepsTheFloorsAllow(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.3.0")
	stepping(f, "1.1.0", "1.0.0", "")
	stepping(f, "1.2.0", "1.0.0", "")
	head := stepping(f, "1.3.0", "1.2.0", "")
	f.trust.descriptor = head

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []string{"1.2.0", "1.3.0"}; !slices.Equal(f.hooks.migrateMarks, want) {
		t.Fatalf("migrations ran for %v, want %v", f.hooks.migrateMarks, want)
	}
}

// Nothing is walked when nothing has to be: a release that may be installed
// straight away is, even with releases published in between.
func TestApplyStillJumpsWhenTheFloorAllowsIt(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	stepping(f, "1.1.0", "1.0.0", "")
	head := stepping(f, "1.2.0", "1.0.0", "")
	f.trust.descriptor = head

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []string{"1.2.0"}; !slices.Equal(f.hooks.migrateMarks, want) {
		t.Fatalf("migrations ran for %v, want %v", f.hooks.migrateMarks, want)
	}
}

// A stable install does not pass through a beta to get anywhere. The releases
// of another channel are published, orderable, and none of this install's
// business.
func TestApplyDoesNotStepThroughAnotherChannel(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	stepping(f, "1.1.0", "1.0.0", "beta")
	head := stepping(f, "1.2.0", "1.1.0", "")
	f.trust.descriptor = head

	err := f.run()
	if !errors.Is(err, updater.ErrMigrationFloor) {
		t.Fatalf("err = %v, want the migration floor to stand", err)
	}
	if got := f.stateVersion(); got != "1.0.0" {
		t.Fatalf("installed %q; nothing should have been installed", got)
	}
}

// Without a bridge the floor stands, and it stands as the same refusal it
// always was — an update that cannot be taken, not a broken one.
func TestApplyRefusesWhenNothingBridgesTheGap(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	head := stepping(f, "1.2.0", "1.1.0", "")
	f.trust.descriptor = head

	err := f.run()
	if !errors.Is(err, updater.ErrPolicy) || !errors.Is(err, updater.ErrMigrationFloor) {
		t.Fatalf("err = %v, want ErrPolicy and ErrMigrationFloor", err)
	}
	if got := f.stateVersion(); got != "1.0.0" {
		t.Fatalf("installed %q; nothing should have been installed", got)
	}
}

// A refusal a path cannot answer is not turned into one: a client too old for
// the release is too old for every release on the way to it.
func TestApplyDoesNotWalkAroundOtherRefusals(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	stepping(f, "1.1.0", "1.0.0", "")
	head := stepping(f, "1.2.0", "1.0.0", "")
	head.Requirements.MinClientVersion = "9.0.0"
	f.opts.ClientVersion = "1.0.0"
	f.trust.descriptor = head

	err := f.run()
	if !errors.Is(err, updater.ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
	if errors.Is(err, updater.ErrMigrationFloor) {
		t.Fatalf("err = %v; this is not a floor to walk around", err)
	}
	if f.hooks.migrated != 0 {
		t.Fatalf("%d migrations ran for a release this client may not have", f.hooks.migrated)
	}
}

// Apply plans the walk itself rather than trusting the Release it was handed:
// the check may be minutes old, and a release that cannot be reached must be
// refused where it would otherwise be installed.
func TestApplyRefusesAReleaseNoPathReaches(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	head := stepping(f, "1.2.0", "1.1.0", "")
	f.trust.descriptor = head

	err := f.updater().Apply(context.Background(), &updater.Release{Descriptor: head, FromVersion: "1.0.0"})
	if !errors.Is(err, updater.ErrMigrationFloor) {
		t.Fatalf("err = %v, want the migration floor", err)
	}
	if got := f.stateVersion(); got != "1.0.0" {
		t.Fatalf("installed %q; nothing should have been installed", got)
	}
}

// Each step is a real installation, so a step that fails leaves the install on
// the last release that committed — a published release, not a half-state — and
// the error says where it stopped.
func TestApplyStopsOnAPublishedReleaseWhenAStepFails(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.2.0")
	stepping(f, "1.1.0", "1.0.0", "")
	head := stepping(f, "1.2.0", "1.1.0", "")
	f.trust.descriptor = head
	f.trust.targetErr["targets/app-1.2.0"] = errors.New("the payload is not there")

	err := f.run()
	if err == nil {
		t.Fatal("Apply succeeded although a step could not be staged")
	}
	if !strings.Contains(err.Error(), "1.1.0") {
		t.Errorf("err = %v; it should say where the walk stopped", err)
	}
	if got := f.stateVersion(); got != "1.1.0" {
		t.Fatalf("installed %q, want the last release that committed", got)
	}
	if got := f.pointer(); got != "1.1.0" {
		t.Fatalf("current points at %q, want 1.1.0", got)
	}
	if got := f.hostState(); got != "1.1.0" {
		t.Fatalf("host state is %q, want 1.1.0", got)
	}
}
