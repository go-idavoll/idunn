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
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
)

// withProbation adds a probation block to a pack.yaml body.
func withProbation(body, block string) string {
	return strings.Replace(body, "targets:", block+"targets:", 1)
}

func TestLoadConfigReadsProbation(t *testing.T) {
	cfg, err := LoadConfig(writeConfigFile(t, withProbation(retainConfig("1.2.0", "stable", nil),
		"probation:\n  attempts: 4\n  restarts: 2\n")))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Probation == nil || *cfg.Probation.Attempts != 4 || cfg.Probation.Restarts != 2 {
		t.Fatalf("probation = %+v", cfg.Probation)
	}
	if cfg, err := LoadConfig(writeConfigFile(t, withProbation(retainConfig("1.2.0", "stable", nil),
		"probation:\n  attempts: 0\n"))); err != nil || *cfg.Probation.Attempts != 0 {
		t.Fatalf("a release that turns probation off = %+v, %v", cfg, err)
	}
}

func TestLoadConfigRefusesABadProbation(t *testing.T) {
	for name, block := range map[string]string{
		"attempts missing":  "probation:\n  restarts: 2\n",
		"negative attempts": "probation:\n  attempts: -1\n",
		"too many attempts": "probation:\n  attempts: 21\n",
		"negative restarts": "probation:\n  attempts: 3\n  restarts: -1\n",
		"too many restarts": "probation:\n  attempts: 3\n  restarts: 21\n",
		"unknown key":       "probation:\n  attempts: 3\n  seconds: 30\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfigFile(t, withProbation(retainConfig("1.2.0", "stable", nil), block)))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("LoadConfig = %v, want ErrConfig", err)
			}
		})
	}
}

// What the packer publishes is what the real client resolves: the policy is
// found by name, verified, and reads back as configured — while a release
// without a probation block publishes none.
func TestPublishedPolicyResolvesThroughTheClient(t *testing.T) {
	f := newFixture(t)
	f.writeSource("linux-amd64/app", appBytes("1.0.0"))
	f.writeSource("linux-amd64/lib.so", libBytes(1))
	f.writeConfig(retainConfig("1.0.0", "stable", nil))
	f.mustPublish(refTime)

	f.writeSource("linux-amd64/app", appBytes("1.1.0"))
	f.writeConfig(withProbation(retainConfig("1.1.0", "stable", nil), "probation:\n  attempts: 4\n  restarts: 2\n"))
	f.mustPublish(refTime.Add(time.Hour))

	c, _, err := f.client(refTime.Add(2 * time.Hour))
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := c.LatestRelease("stable", "linux", "amd64"); err != nil {
		t.Fatalf("LatestRelease: %v", err)
	}
	p, err := c.ReleasePolicy("linux", "amd64", "1.1.0")
	if err != nil {
		t.Fatalf("ReleasePolicy: %v", err)
	}
	if p == nil || p.Name != "demo" || p.Probation == nil || p.Probation.Attempts != 4 || p.Probation.Restarts != 2 {
		t.Fatalf("policy = %+v", p)
	}
	if p, err := c.ReleasePolicy("linux", "amd64", "1.0.0"); p != nil || err != nil {
		t.Fatalf("policy of a release published without one = %+v, %v", p, err)
	}
	// The policy is not a release of its own.
	if got := c.Versions("linux", "amd64"); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Fatalf("Versions = %v", got)
	}
}

// A policy goes with its release, and a release-line role holding policies is
// still one retention can classify.
func TestRetentionRetiresAPolicyWithItsRelease(t *testing.T) {
	f := newFixture(t)
	lib := libBytes(1)
	block := "probation:\n  attempts: 3\n"
	for i, v := range []string{"1.0.0", "1.1.0", "1.2.0"} {
		f.writeSource("linux-amd64/app", appBytes(v))
		f.writeSource("linux-amd64/lib.so", lib)
		f.writeConfig(withProbation(retainConfig(v, "stable", keepOf(2)), block))
		if _, err := f.publish(refTime.Add(time.Duration(i) * time.Hour)); err != nil {
			t.Fatalf("publishing %s: %v", v, err)
		}
	}
	after := lineTargets(t, f, "v1")
	if _, ok := after[release.PolicyPath("linux", "amd64", "1.0.0")]; ok {
		t.Error("the policy of the retired 1.0.0 is still published")
	}
	for _, v := range []string{"1.1.0", "1.2.0"} {
		if _, ok := after[release.PolicyPath("linux", "amd64", v)]; !ok {
			t.Errorf("the policy of the retained %s is gone", v)
		}
	}
}
