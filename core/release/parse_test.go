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
	"encoding/json"
	"errors"
	"path"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/release"
)

func validDescriptor() release.Descriptor {
	return release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "demo",
		Version:       "1.2.0",
		Channel:       "stable",
		OS:            "linux",
		Arch:          "amd64",
		Files: []release.FileRef{
			{Target: "payloads/1.2.0/app", Dst: "bin/app", Mode: 0o755, Kind: release.KindExe},
			{Target: "payloads/1.2.0/lib.so", Dst: "lib/lib.so", Mode: 0o644, Kind: release.KindLib},
		},
	}
}

func encode(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return raw
}

func TestParseDescriptorAcceptsValid(t *testing.T) {
	d, err := release.ParseDescriptor(encode(t, validDescriptor()))
	if err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	if d.Version != "1.2.0" || len(d.Files) != 2 {
		t.Fatalf("parsed descriptor is wrong: %+v", d)
	}
}

// Each case is an attack the parser must refuse. These are the negative tests
// AGENTS.md §1.6 requires for the ingest path.
func TestParseDescriptorRejects(t *testing.T) {
	tests := map[string]func(d *release.Descriptor){
		"schema from the future": func(d *release.Descriptor) { d.SchemaVersion = release.SchemaVersion + 1 },
		"schema missing":         func(d *release.Descriptor) { d.SchemaVersion = 0 },
		"layout from the future": func(d *release.Descriptor) { d.LayoutSchema = release.LayoutSchema + 1 },
		"empty name":             func(d *release.Descriptor) { d.Name = "" },
		"empty channel":          func(d *release.Descriptor) { d.Channel = "" },
		"non-semver version":     func(d *release.Descriptor) { d.Version = "v1.2" },
		"no files":               func(d *release.Descriptor) { d.Files = nil },
		"rollout above one":      func(d *release.Descriptor) { d.Rollout = 1.5 },
		"rollout negative":       func(d *release.Descriptor) { d.Rollout = -0.1 },
		"dst escapes root":       func(d *release.Descriptor) { d.Files[0].Dst = "../evil" },
		"dst deep escape":        func(d *release.Descriptor) { d.Files[0].Dst = "bin/../../evil" },
		"dst absolute":           func(d *release.Descriptor) { d.Files[0].Dst = "/etc/passwd" },
		"dst drive relative":     func(d *release.Descriptor) { d.Files[0].Dst = "C:evil" },
		"dst backslash":          func(d *release.Descriptor) { d.Files[0].Dst = `bin\evil` },
		"dst device name":        func(d *release.Descriptor) { d.Files[0].Dst = "bin/NUL" },
		"dst unclean":            func(d *release.Descriptor) { d.Files[0].Dst = "bin//app" },
		"dst empty":              func(d *release.Descriptor) { d.Files[0].Dst = "" },
		"target escapes":         func(d *release.Descriptor) { d.Files[0].Target = "../../secrets" },
		"target empty":           func(d *release.Descriptor) { d.Files[0].Target = "" },
		"unknown kind":           func(d *release.Descriptor) { d.Files[0].Kind = "script" },
		"setuid mode":            func(d *release.Descriptor) { d.Files[0].Mode = 0o4755 },
		"duplicate dst":          func(d *release.Descriptor) { d.Files[1].Dst = d.Files[0].Dst },
		"duplicate target":       func(d *release.Descriptor) { d.Files[1].Target = d.Files[0].Target },
		"bad min from version":   func(d *release.Descriptor) { d.Requirements.MinFromVersion = "oldest" },
		"bad min client version": func(d *release.Descriptor) { d.Requirements.MinClientVersion = "latest" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			d := validDescriptor()
			mutate(&d)
			got, err := release.ParseDescriptor(encode(t, d))
			if err == nil {
				t.Fatalf("accepted: %+v", got)
			}
			if !errors.Is(err, release.ErrInvalid) {
				t.Fatalf("error is not classified as ErrInvalid: %v", err)
			}
		})
	}
}

func TestParseDescriptorRejectsRawInput(t *testing.T) {
	tests := map[string]string{
		"empty":         "",
		"not json":      "not json at all",
		"truncated":     `{"schema_version": 1,`,
		"array":         `[]`,
		"null":          `null`,
		"unknown field": `{"schema_version":1,"layout_schema":1,"name":"a","version":"1.0.0","channel":"c","os":"linux","arch":"amd64","files":[],"backdoor":true}`,
		"trailing data": `{"schema_version":1} {"schema_version":1}`,
		// encoding/json matches field names case-insensitively; a signed document
		// must have exactly one spelling, so these are refused.
		"case-variant key":      `{"sChemA_version":1,"lAYout_sChemA":1,"nAme":"a","version":"1.0.0","ChAnnel":"c","os":"linux","ArCh":"amd64","files":[{"tArget":"t","dst":"a","mode":420,"kind":"data"}]}`,
		"case-variant file key": `{"schema_version":1,"layout_schema":1,"name":"a","version":"1.0.0","channel":"c","os":"linux","arch":"amd64","files":[{"Target":"t","dst":"a","mode":420,"kind":"data"}]}`,
		"unknown key in file":   `{"schema_version":1,"layout_schema":1,"name":"a","version":"1.0.0","channel":"c","os":"linux","arch":"amd64","files":[{"target":"t","dst":"a","mode":420,"kind":"data","exec":true}]}`,
		"unknown requirement":   `{"schema_version":1,"layout_schema":1,"name":"a","version":"1.0.0","channel":"c","os":"linux","arch":"amd64","requirements":{"min_root_version":"1.0.0"},"files":[{"target":"t","dst":"a","mode":420,"kind":"data"}]}`,
		"oversized":             "{" + strings.Repeat(" ", release.MaxJSONLen) + "}",
		"nul in the dst":        "{\"schema_version\":1,\"layout_schema\":1,\"name\":\"a\",\"version\":\"1.0.0\",\"channel\":\"c\",\"os\":\"linux\",\"arch\":\"amd64\",\"files\":[{\"target\":\"a\",\"dst\":\"a\\u0000b\",\"mode\":420,\"kind\":\"data\"}]}",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := release.ParseDescriptor([]byte(raw)); err == nil {
				t.Fatalf("accepted: %+v", got)
			}
		})
	}
}

func validPointer() release.Pointer {
	return release.Pointer{
		SchemaVersion: release.SchemaVersion,
		Channel:       "stable",
		OS:            "linux",
		Arch:          "amd64",
		Version:       "1.2.0",
		Descriptor:    release.DescriptorPath("linux", "amd64", "1.2.0"),
	}
}

func TestParsePointer(t *testing.T) {
	if _, err := release.ParsePointer(encode(t, validPointer())); err != nil {
		t.Fatalf("valid pointer rejected: %v", err)
	}

	tests := map[string]func(p *release.Pointer){
		"schema from the future": func(p *release.Pointer) { p.SchemaVersion = release.SchemaVersion + 1 },
		"empty channel":          func(p *release.Pointer) { p.Channel = "" },
		"empty os":               func(p *release.Pointer) { p.OS = "" },
		"non-semver version":     func(p *release.Pointer) { p.Version = "latest" },
		"descriptor escapes":     func(p *release.Pointer) { p.Descriptor = "../../etc/passwd" },
		"descriptor absolute":    func(p *release.Pointer) { p.Descriptor = "/releases/x.json" },
		"descriptor empty":       func(p *release.Pointer) { p.Descriptor = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := validPointer()
			mutate(&p)
			if got, err := release.ParsePointer(encode(t, p)); err == nil {
				t.Fatalf("accepted: %+v", got)
			}
		})
	}
}

// FuzzDescriptor drives arbitrary bytes through the ingest path. The property is
// total-ness, not acceptance: the parser may reject anything, but it must never
// panic, and anything it accepts must hold the invariants we rely on downstream.
func FuzzDescriptor(f *testing.F) {
	f.Add(string(encode(f, validDescriptor())))
	f.Add(`{"schema_version":1}`)
	f.Add(`{"schema_version":1,"layout_schema":1,"name":"a","version":"1.0.0","channel":"c","os":"linux","arch":"amd64","files":[{"target":"t","dst":"../x","mode":420,"kind":"data"}]}`)
	f.Add("")
	f.Add("{")

	f.Fuzz(func(t *testing.T, raw string) {
		d, err := release.ParseDescriptor([]byte(raw))
		if err != nil {
			return
		}
		if d.SchemaVersion != release.SchemaVersion || d.LayoutSchema != release.LayoutSchema {
			t.Fatalf("accepted unsupported schema: %+v", d)
		}
		if len(d.Files) == 0 {
			t.Fatal("accepted a descriptor with no files")
		}
		for _, file := range d.Files {
			// Check path *elements*, not substrings: "..0" is a perfectly ordinary
			// filename, while a bare ".." element is an escape.
			if file.Dst != path.Clean(file.Dst) || path.IsAbs(file.Dst) {
				t.Fatalf("accepted non-canonical or absolute dst %q", file.Dst)
			}
			for _, elem := range strings.Split(file.Dst, "/") {
				if elem == "" || elem == "." || elem == ".." {
					t.Fatalf("accepted dst %q with element %q", file.Dst, elem)
				}
			}
			if file.Mode&^uint32(0o777) != 0 {
				t.Fatalf("accepted mode %#o", file.Mode)
			}
		}
	})
}
