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

package updater

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

// walkFixture is a repository of releases where each one refuses to migrate
// from anything below the one before it — the shape that forces a walk.
func walkFixture(t *testing.T, versions ...string) (*Updater, *history) {
	t.Helper()
	releases := map[string]map[string]string{}
	h := newHistory(releases)
	for i, v := range versions {
		releases[v] = map[string]string{"app": "payloads/v1/a" + v}
		if i > 0 {
			h.floors[v] = versions[i-1]
		}
	}
	// The platform and channel are the updater's own; applicable() judges every
	// release against them, and the planner uses applicable() so that it cannot
	// pick a step the apply would then refuse.
	return &Updater{trust: h, channel: "stable", goos: "linux", goarch: "amd64"}, h
}

// The head of the walk, as CheckForUpdate would hand it over.
func headOf(h *history, version string) *release.Descriptor {
	d := descriptorOf("linux", "amd64", version, h.releases[version])
	d.Requirements.MinFromVersion = h.floors[version]
	if ch := h.channels[version]; ch != "" {
		d.Channel = ch
	}
	return d
}

// A floor a path can answer is answered by the path; everything else about the
// walk is checked by the same applicable() the apply enforces, so a planner and
// an enforcer cannot disagree.
func TestStepsPlansTheWalk(t *testing.T) {
	u, h := walkFixture(t, "1.0.0", "1.1.0", "1.2.0")

	walk, err := u.steps(headOf(h, "1.2.0"), "1.0.0")
	if err != nil {
		t.Fatalf("steps: %v", err)
	}
	if len(walk) != 2 || walk[0].Version != "1.1.0" || walk[1].Version != "1.2.0" {
		t.Fatalf("walk = %v", versionsOf(walk))
	}
}

// Without a client that can look releases up there is no walk to plan, and the
// floor stands exactly as it did before paths existed.
func TestStepsNeedsAClientThatKnowsTheReleases(t *testing.T) {
	_, h := walkFixture(t, "1.0.0", "1.1.0", "1.2.0")
	u := &Updater{trust: plainResolver{}, channel: "stable", goos: "linux", goarch: "amd64"}

	_, err := u.steps(headOf(h, "1.2.0"), "1.0.0")
	if !errors.Is(err, ErrMigrationFloor) {
		t.Fatalf("err = %v, want the floor to stand", err)
	}
}

// A repository that publishes two releases of the same precedence gives no
// order to walk, so the floor stands rather than being resolved by a tie-break
// nobody could predict.
func TestStepsRefusesAnAmbiguousRepository(t *testing.T) {
	u, h := walkFixture(t, "1.0.0", "1.1.0+a", "1.2.0")
	h.releases["1.1.0+b"] = map[string]string{"app": "payloads/v1/ab"}
	h.floors["1.2.0"] = "1.1.0+a"

	_, err := u.steps(headOf(h, "1.2.0"), "1.0.0")
	if !errors.Is(err, ErrMigrationFloor) {
		t.Fatalf("err = %v, want the floor to stand", err)
	}
}

// A walk of dozens of releases is not one to take: each step is a full
// installation with its own migration, and an install this far behind is better
// served by being told so.
func TestStepsRefusesAnEndlessWalk(t *testing.T) {
	versions := make([]string, 0, maxWalk+2)
	for i := range maxWalk + 2 {
		versions = append(versions, fmt.Sprintf("1.%d.0", i))
	}
	u, h := walkFixture(t, versions...)

	last := versions[len(versions)-1]
	_, err := u.steps(headOf(h, last), "1.0.0")
	if !errors.Is(err, ErrMigrationFloor) {
		t.Fatalf("err = %v, want the floor to stand", err)
	}
	if !strings.Contains(err.Error(), "longer than") {
		t.Fatalf("err = %v; it should say the path is too long", err)
	}
}

// A release in the middle that will not resolve is not a stepping stone. If
// nothing else bridges the gap, the floor stands.
func TestStepsRefusesWhenAStoneIsMissing(t *testing.T) {
	u, h := walkFixture(t, "1.0.0", "1.1.0", "1.2.0")
	h.failing["1.1.0"] = true

	_, err := u.steps(headOf(h, "1.2.0"), "1.0.0")
	if !errors.Is(err, ErrMigrationFloor) {
		t.Fatalf("err = %v, want the floor to stand", err)
	}
	if !strings.Contains(err.Error(), "bridges the gap") {
		t.Fatalf("err = %v; it should say nothing bridges the gap", err)
	}
}

func versionsOf(walk []*release.Descriptor) []string {
	out := make([]string, 0, len(walk))
	for _, d := range walk {
		out = append(out, d.Version)
	}
	return out
}
