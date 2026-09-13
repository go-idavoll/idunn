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
	"slices"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

// history is a trust client that can look releases up by version, which is what
// turns a walk into a route. The releases are described the short way: a version
// and, per destination, the payload it shipped there.
type history struct {
	releases map[string]map[string]string

	// floors and channels are what a migration walk is planned against: the
	// version each release refuses to migrate from below, and the channel it
	// belongs to.
	floors   map[string]string
	channels map[string]string

	failing map[string]bool
	asked   []string
}

func newHistory(releases map[string]map[string]string) *history {
	return &history{
		releases: releases,
		floors:   map[string]string{},
		channels: map[string]string{},
		failing:  map[string]bool{},
	}
}

func (h *history) Refresh() error { return nil }

func (h *history) LatestRelease(string, string, string) (*release.Descriptor, error) {
	return nil, errors.New("not used here")
}

func (h *history) Target(string) ([]byte, error)      { return nil, errors.New("not used here") }
func (h *history) TargetLength(string) (int64, error) { return 0, errors.New("not used here") }
func (h *history) VerifyTarget(string, []byte) error  { return errors.New("not used here") }
func (h *history) Versions(_, _ string) []string {
	var out []string
	for v := range h.releases {
		out = append(out, v)
	}
	// Deliberately unsorted-ish: the ordering is release.Chain's job, and this
	// is where a route that depended on map order would show up.
	slices.Sort(out)
	slices.Reverse(out)
	return out
}

func (h *history) ReleaseVersion(goos, goarch, version string) (*release.Descriptor, error) {
	h.asked = append(h.asked, version)
	if h.failing[version] {
		return nil, errors.New("no such release")
	}
	files, ok := h.releases[version]
	if !ok {
		return nil, errors.New("no such release")
	}
	d := descriptorOf(goos, goarch, version, files)
	d.Requirements.MinFromVersion = h.floors[version]
	if ch := h.channels[version]; ch != "" {
		d.Channel = ch
	}
	return d, nil
}

func descriptorOf(goos, goarch, version string, files map[string]string) *release.Descriptor {
	d := &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme-app",
		Version:       version,
		Channel:       "stable",
		OS:            goos,
		Arch:          goarch,
	}
	for _, dst := range slices.Sorted(maps(files)) {
		d.Files = append(d.Files, release.FileRef{
			Target: files[dst], Dst: dst, Kind: release.KindData, Mode: 0o644,
		})
	}
	return d
}

func maps(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// The route is the byte-level history of the releases being walked: for each
// destination, what it was at each release, oldest first, ending at what this
// release installs.
func TestRouteCollectsTheWalk(t *testing.T) {
	h := newHistory(map[string]map[string]string{
		"1.0.0": {"app": "payloads/v1/a0", "lib/x.so": "payloads/v1/x0"},
		"1.1.0": {"app": "payloads/v1/a1", "lib/x.so": "payloads/v1/x0"},
		"1.2.0": {"app": "payloads/v1/a2", "lib/x.so": "payloads/v1/x1", "new": "payloads/v1/n0"},
	})
	u := &Updater{trust: h}

	got := u.route(descriptorOf("linux", "amd64", "1.2.0", h.releases["1.2.0"]), "1.0.0")

	want := map[string][]string{
		"app":      {"payloads/v1/a0", "payloads/v1/a1", "payloads/v1/a2"},
		"lib/x.so": {"payloads/v1/x0", "payloads/v1/x0", "payloads/v1/x1"},
		"new":      {"payloads/v1/n0"},
	}
	if len(got) != len(want) {
		t.Fatalf("route = %v, want %v", got, want)
	}
	for dst, lineage := range want {
		if !slices.Equal(got[dst], lineage) {
			t.Errorf("route[%q] = %v, want %v", dst, got[dst], lineage)
		}
	}

	// The release being applied is already resolved; asking the repository for
	// it again would be a fetch for something the caller is holding.
	if slices.Contains(h.asked, "1.2.0") {
		t.Errorf("re-resolved the release being applied: %v", h.asked)
	}
}

// Every way of not knowing the history ends in no route, and no route is not an
// error anywhere: the update then fetches full targets, exactly as it did
// before patches existed.
func TestRouteIsAbsentWhenTheWalkIsUnknown(t *testing.T) {
	releases := map[string]map[string]string{
		"1.0.0": {"app": "payloads/v1/a0"},
		"1.1.0": {"app": "payloads/v1/a1"},
	}
	head := descriptorOf("linux", "amd64", "1.1.0", releases["1.1.0"])

	for name, u := range map[string]*Updater{
		"a trust client that cannot look releases up": {trust: &plainResolver{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := u.route(head, "1.0.0"); got != nil {
				t.Fatalf("route = %v, want none", got)
			}
		})
	}

	for name, tc := range map[string]struct {
		installed string
		setup     func(*history)
	}{
		"nothing is installed yet": {
			installed: "",
		},
		"the installed release is no longer published": {
			installed: "0.9.0",
		},
		"the installed release will not resolve": {
			installed: "1.0.0",
			setup:     func(h *history) { h.failing["1.0.0"] = true },
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHistory(releases)
			if tc.setup != nil {
				tc.setup(h)
			}
			u := &Updater{trust: h}
			if got := u.route(head, tc.installed); got != nil {
				t.Fatalf("route = %v, want none", got)
			}
		})
	}
}

// A release in the middle of the walk that will not resolve leaves a hole, and
// a route with a hole in it is not a route: the lineage either describes every
// step or it describes nothing.
func TestRouteIsAbsentWhenAStepIsMissing(t *testing.T) {
	h := newHistory(map[string]map[string]string{
		"1.0.0": {"app": "payloads/v1/a0"},
		"1.1.0": {"app": "payloads/v1/a1"},
		"1.2.0": {"app": "payloads/v1/a2"},
	})
	h.failing["1.1.0"] = true
	u := &Updater{trust: h}

	head := descriptorOf("linux", "amd64", "1.2.0", h.releases["1.2.0"])
	if got := u.route(head, "1.0.0"); got != nil {
		t.Fatalf("route = %v, want none", got)
	}
}

// A client far enough behind is better served by downloading the release it is
// going to. The bound is on cost, not on trust — every hop would be verified —
// so it is deliberately generous and deliberately there.
func TestRouteStopsAtAVeryLongWalk(t *testing.T) {
	releases := map[string]map[string]string{}
	for i := range maxWalk + 1 {
		releases[fmt.Sprintf("1.%d.0", i)] = map[string]string{"app": fmt.Sprintf("payloads/v1/a%d", i)}
	}
	h := newHistory(releases)
	u := &Updater{trust: h}

	last := fmt.Sprintf("1.%d.0", maxWalk)
	head := descriptorOf("linux", "amd64", last, releases[last])
	if got := u.route(head, "1.0.0"); got != nil {
		t.Fatalf("route over %d releases = %v, want none", maxWalk+1, got)
	}

	// One release closer, and the walk is inside the bound again.
	shorter := fmt.Sprintf("1.%d.0", maxWalk-1)
	head = descriptorOf("linux", "amd64", shorter, releases[shorter])
	if got := u.route(head, "1.0.0"); got == nil {
		t.Fatal("a walk inside the bound produced no route")
	}
}

// plainResolver is a trust client with no history: the capability is optional,
// and a client without it updates the way it always did.
type plainResolver struct{}

func (plainResolver) Refresh() error { return nil }
func (plainResolver) LatestRelease(string, string, string) (*release.Descriptor, error) {
	return nil, errors.New("not used here")
}
func (plainResolver) Target(string) ([]byte, error)      { return nil, errors.New("not used here") }
func (plainResolver) TargetLength(string) (int64, error) { return 0, errors.New("not used here") }
func (plainResolver) VerifyTarget(string, []byte) error  { return errors.New("not used here") }
