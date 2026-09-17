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

package release_test

import (
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

const validPolicy = `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":3,"restarts":2}}`

func TestParsePolicyAcceptsAValidPolicy(t *testing.T) {
	p, err := release.ParsePolicy([]byte(validPolicy))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	if p.Version != "1.2.0" || p.Probation == nil || p.Probation.Attempts != 3 || p.Probation.Restarts != 2 {
		t.Fatalf("policy = %+v", p)
	}

	p, err = release.ParsePolicy([]byte(`{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64"}`))
	if err != nil || p.Probation != nil {
		t.Fatalf("a policy that says nothing about probation = %+v, %v", p, err)
	}
	p, err = release.ParsePolicy([]byte(`{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":0}}`))
	if err != nil || p.Probation == nil || p.Probation.Attempts != 0 {
		t.Fatalf("a release that turns probation off = %+v, %v", p, err)
	}
}

func TestParsePolicyRefusesWhatItDoesNotUnderstand(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":             ``,
		"malformed":         `{`,
		"trailing":          validPolicy + `{}`,
		"unknown field":     `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","deadline":"1h"}`,
		"unknown nested":    `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":3,"seconds":9}}`,
		"miscased field":    `{"Schema_Version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64"}`,
		"miscased nested":   `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"Attempts":3}}`,
		"unknown schema":    `{"schema_version":2,"name":"app","version":"1.2.0","os":"linux","arch":"amd64"}`,
		"no name":           `{"schema_version":1,"version":"1.2.0","os":"linux","arch":"amd64"}`,
		"no os":             `{"schema_version":1,"name":"app","version":"1.2.0","arch":"amd64"}`,
		"bad version":       `{"schema_version":1,"name":"app","version":"1.2","os":"linux","arch":"amd64"}`,
		"negative attempts": `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":-1}}`,
		"too many attempts": `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":21}}`,
		"too many restarts": `{"schema_version":1,"name":"app","version":"1.2.0","os":"linux","arch":"amd64","probation":{"attempts":3,"restarts":21}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if p, err := release.ParsePolicy([]byte(raw)); p != nil || !errors.Is(err, release.ErrInvalid) {
				t.Fatalf("ParsePolicy = %+v, %v; want ErrInvalid", p, err)
			}
		})
	}
}

// A policy path is never a descriptor path, for any version — including
// pre-releases and build metadata, whose characters would otherwise let the
// policy suffix pass as part of a version.
func TestPolicyPathsAreNeverDescriptorPaths(t *testing.T) {
	for _, v := range []string{"1.2.0", "1.2.0-rc.1", "1.2.0+build.7", "1.2.0-rc.1+b.2"} {
		p := release.PolicyPath("linux", "amd64", v)
		if got, ok := release.VersionOfDescriptorPath(p, "linux", "amd64"); ok {
			t.Errorf("VersionOfDescriptorPath(%q) = %q, a policy read as a release", p, got)
		}
		goos, goarch, version, ok := release.VersionOfPolicyPath(p)
		if !ok || goos != "linux" || goarch != "amd64" || version != v {
			t.Errorf("VersionOfPolicyPath(%q) = %s %s %s %v", p, goos, goarch, version, ok)
		}
		if _, _, _, ok := release.VersionOfPolicyPath(release.DescriptorPath("linux", "amd64", v)); ok {
			t.Errorf("a descriptor path of %s reads as a policy", v)
		}
	}
	for _, p := range []string{
		"releases/linux-amd64/1.2_policy.json",
		"releases/linuxamd64/1.2.0_policy.json",
		"releases/linux-amd64/x/1.2.0_policy.json",
		"payloads/linux-amd64/1.2.0_policy.json",
		"releases/-amd64/1.2.0_policy.json",
	} {
		if _, _, _, ok := release.VersionOfPolicyPath(p); ok {
			t.Errorf("VersionOfPolicyPath(%q) accepted a path PolicyPath cannot produce", p)
		}
	}
}

func FuzzPolicy(f *testing.F) {
	f.Add(validPolicy)
	f.Add(`{"schema_version":1}`)
	f.Add(`{"schema_version":1,"name":"a","version":"1.0.0","os":"l","arch":"a","probation":null}`)
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := release.ParsePolicy([]byte(raw))
		if err != nil {
			return
		}
		if p.SchemaVersion != release.SchemaVersion || !release.ValidVersion(p.Version) {
			t.Fatalf("accepted %+v", p)
		}
		if pp := p.Probation; pp != nil &&
			(pp.Attempts < 0 || pp.Attempts > release.MaxProbationAttempts || pp.Restarts < 0 || pp.Restarts > release.MaxProbationRestarts) {
			t.Fatalf("accepted out-of-bounds probation %+v", pp)
		}
	})
}
