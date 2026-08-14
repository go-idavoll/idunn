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

package packer

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// roleFor asks go-tuf itself which of the delegations claim a target path. Using
// the client's own matcher is the point: a hand-rolled reimplementation could
// agree with the packer and disagree with the thing that actually resolves.
func rolesFor(t *testing.T, roles []metadata.DelegatedRole, target string) []string {
	t.Helper()
	var out []string
	for _, r := range roles {
		ok, err := r.IsDelegatedPath(target)
		if err != nil {
			t.Fatalf("matching %s against %s: %v", target, r.Name, err)
		}
		if ok {
			out = append(out, r.Name)
		}
	}
	return out
}

// delegationSet builds the delegations a repository with these channels and
// release lines would carry.
func delegationSet(channels []string, majors []string) []metadata.DelegatedRole {
	var out []metadata.DelegatedRole
	for _, c := range channels {
		out = append(out, metadata.DelegatedRole{Name: channelRole(c), Paths: channelPaths(c), Terminating: true})
	}
	for _, m := range majors {
		out = append(out, metadata.DelegatedRole{Name: lineRole(m), Paths: linePaths(m), Terminating: true})
	}
	return out
}

// Every target a publish can emit is claimed by exactly one delegated role.
//
// This is the property the whole scheme rests on. Overlapping patterns would
// make a client fetch delegated metadata it has no use for — the cost
// delegations exist to remove — and would leave "which role may provide this
// target" to traversal order rather than to the path.
func TestEveryTargetHasExactlyOneRole(t *testing.T) {
	channels := []string{"stable", "beta", "nightly"}
	majors := []string{"0", "1", "2", "10", "11"}
	roles := delegationSet(channels, majors)

	platforms := [][2]string{{"linux", "amd64"}, {"windows", "amd64"}, {"darwin", "arm64"}}
	versions := map[string]string{
		"0":  "0.9.0",
		"1":  "1.2.3",
		"2":  "2.0.0-rc.1",
		"10": "10.0.0+build.7",
		"11": "11.4.0",
	}

	var targets []string
	for _, c := range channels {
		for _, p := range platforms {
			targets = append(targets, release.PointerPath(c, p[0], p[1]))
		}
	}
	for major, version := range versions {
		for _, p := range platforms {
			targets = append(targets, release.DescriptorPath(p[0], p[1], version))
		}
		targets = append(targets, payloadTarget(major, sha256.Sum256([]byte(version))))
	}

	for _, target := range targets {
		got := rolesFor(t, roles, target)
		if len(got) != 1 {
			t.Errorf("%s is claimed by %v, want exactly one role", target, got)
		}
	}
}

// The role that owns a path is the one the packer puts the target in. A pattern
// that matched the right count but the wrong role would still publish targets a
// client cannot find.
func TestTargetsLandInTheExpectedRole(t *testing.T) {
	roles := delegationSet([]string{"stable", "beta"}, []string{"1", "2"})
	tests := []struct{ target, want string }{
		{release.PointerPath("stable", "linux", "amd64"), "stable"},
		{release.PointerPath("beta", "windows", "amd64"), "beta"},
		{release.DescriptorPath("linux", "amd64", "1.2.0"), "v1"},
		{release.DescriptorPath("linux", "amd64", "2.0.0-rc.1"), "v2"},
		{payloadTarget("1", sha256.Sum256([]byte("x"))), "v1"},
		{payloadTarget("2", sha256.Sum256([]byte("x"))), "v2"},
	}
	for _, tt := range tests {
		got := rolesFor(t, roles, tt.target)
		if len(got) != 1 || got[0] != tt.want {
			t.Errorf("%s -> %v, want [%s]", tt.target, got, tt.want)
		}
	}
}

// A delegated role must not be reachable by a path outside its own namespace. A
// crafted target path is attacker-influenced input the moment a compromised
// delegation key tries to widen its own reach.
func TestNoRoleClaimsForeignPaths(t *testing.T) {
	roles := delegationSet([]string{"stable"}, []string{"1"})
	foreign := []string{
		"channels/stable/linux-amd64/../../evil.json",
		"channels/stable/linux-amd64/latest.json/extra",
		"channels/stableX/linux-amd64/latest.json",
		"releases/linux-amd64/12.0.0.json",
		"releases/linux-amd64/nested/1.2.0.json",
		"payloads/v1/deep/aa",
		"payloads/v12/aa",
		"root.json",
		"",
	}
	for _, target := range foreign {
		if got := rolesFor(t, roles, target); len(got) != 0 {
			t.Errorf("%q is claimed by %v, want no role", target, got)
		}
	}
}

// Target paths the packer emits must be the same clean, relative form the client
// demands of them. A path the sanitizer refuses could never be resolved.
func TestEmittedTargetPathsAreClean(t *testing.T) {
	targets := []string{
		release.PointerPath("stable", "linux", "amd64"),
		release.DescriptorPath("linux", "amd64", "1.2.0"),
		payloadTarget("1", sha256.Sum256([]byte("payload"))),
	}
	for _, target := range targets {
		clean, err := safepath.CleanTarget(target)
		if err != nil {
			t.Errorf("%s: %v", target, err)
			continue
		}
		if clean != target {
			t.Errorf("%s is not in clean form (%s)", target, clean)
		}
	}
}

// The two role namespaces must not collide: a channel that could name itself
// "v2" would be delegated the v2 release line's paths as well as its own.
func TestChannelCannotCollideWithAReleaseLine(t *testing.T) {
	cfg := Config{
		Name:    "demo",
		Version: "2.0.0",
		Channel: "v2",
		Targets: []Platform{{OS: "linux", Arch: "amd64", Files: []File{{Src: "app", Dst: "app", Kind: "exe"}}}},
	}
	err := cfg.validate()
	if err == nil {
		t.Fatal("a channel named v2 was accepted")
	}
	if !strings.Contains(err.Error(), "collides") {
		t.Errorf("err = %v", err)
	}
}

// hashPrefixedPath is the on-disk naming rule under consistent snapshots. It is
// the same rule go-tuf builds its request URL from; the end-to-end resolve tests
// prove they agree, this one pins the shape.
func TestHashPrefixedPath(t *testing.T) {
	sum := sha256.Sum256([]byte("payload"))
	hex := "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	tests := []struct{ target, want string }{
		{"payloads/v1/abc", "payloads/v1/" + hex + ".abc"},
		{"channels/stable/linux-amd64/latest.json", "channels/stable/linux-amd64/" + hex + ".latest.json"},
		{"latest.json", hex + ".latest.json"},
	}
	for _, tt := range tests {
		if got := hashPrefixedPath(tt.target, sum); got != tt.want {
			t.Errorf("hashPrefixedPath(%q) = %q, want %q", tt.target, got, tt.want)
		}
	}
}

// roleLess only has to be a total, stable order: the emitted delegation list has
// to be identical across runs.
func TestRoleOrderIsStable(t *testing.T) {
	roles := []string{"v2", "beta", "v10", "stable", "v1"}
	want := []string{"beta", "stable", "v10", "v2", "v1"}
	got := append([]string(nil), roles...)
	sortStable(got)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func sortStable(roles []string) {
	for i := 1; i < len(roles); i++ {
		for j := i; j > 0 && roleLess(roles[j], roles[j-1]); j-- {
			roles[j], roles[j-1] = roles[j-1], roles[j]
		}
	}
}
