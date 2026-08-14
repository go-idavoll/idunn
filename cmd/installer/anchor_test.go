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

package main

import (
	"errors"
	"strings"
	"testing"
)

// idunn's own tree must ship no trust anchor. A placeholder root.json is the one
// file that must never become shippable by accident, and the only thing standing
// between "someone dropped their build config in for a moment" and a released
// binary pinned to the wrong publisher is this test.
func TestThisTreeEmbedsNoAnchor(t *testing.T) {
	a, err := loadAnchor()
	if err != nil {
		t.Fatalf("loadAnchor: %v", err)
	}
	if a.hasRoot() {
		t.Error("cmd/installer/anchor/root.json is committed; it must not be")
	}
	if a.repo.MetadataURL != "" {
		t.Errorf("cmd/installer/anchor/repository.json is committed (metadata_url %q)", a.repo.MetadataURL)
	}
}

// A build that carries an anchor is pinned to it. A flag that could replace the
// pin would make every shipped installer a generic installer for anyone's
// repository.
func TestTrustAnchorCannotBeDisplaced(t *testing.T) {
	embedded := &anchor{root: []byte(`{"embedded":true}`)}

	got, err := embedded.trustAnchor(nil)
	if err != nil || string(got) != `{"embedded":true}` {
		t.Fatalf("embedded anchor = %q, %v", got, err)
	}

	_, err = embedded.trustAnchor([]byte(`{"other":true}`))
	if !errors.Is(err, ErrAnchor) {
		t.Fatalf("err = %v, want ErrAnchor", err)
	}
	if !strings.Contains(err.Error(), "cannot replace it") {
		t.Errorf("err = %v", err)
	}
}

// A build without an anchor is a tool, not a product: it must be told which
// anchor to trust, and it refuses to guess.
func TestTrustAnchorRequiresOneWhenNothingIsEmbedded(t *testing.T) {
	bare := &anchor{}

	_, err := bare.trustAnchor(nil)
	if !errors.Is(err, ErrAnchor) {
		t.Fatalf("err = %v, want ErrAnchor", err)
	}
	if !strings.Contains(err.Error(), "--root-metadata") {
		t.Errorf("the error does not name the flag that would fix it: %v", err)
	}

	got, err := bare.trustAnchor([]byte(`{"flag":true}`))
	if err != nil || string(got) != `{"flag":true}` {
		t.Fatalf("anchor from flag = %q, %v", got, err)
	}
}

func TestURLResolution(t *testing.T) {
	tests := []struct {
		name                   string
		a                      anchor
		metaFlag, targetsFlag  string
		wantMetadata, wantTgts string
		wantErr                bool
	}{
		{
			name:         "sibling targets by default",
			metaFlag:     "https://updates.example.com/metadata/",
			wantMetadata: "https://updates.example.com/metadata/",
			wantTgts:     "https://updates.example.com/targets/",
		},
		{
			name:         "sibling at the root of the host",
			metaFlag:     "https://updates.example.com/",
			wantMetadata: "https://updates.example.com/",
			wantTgts:     "https://updates.example.com/targets/",
		},
		{
			name:         "embedded is used when no flag is given",
			a:            anchor{repo: repository{MetadataURL: "https://a/metadata/", TargetsURL: "https://a/t/"}},
			wantMetadata: "https://a/metadata/",
			wantTgts:     "https://a/t/",
		},
		{
			name:         "flags override the embedded URLs",
			a:            anchor{repo: repository{MetadataURL: "https://a/metadata/", TargetsURL: "https://a/t/"}},
			metaFlag:     "https://mirror/metadata/",
			targetsFlag:  "https://mirror/targets/",
			wantMetadata: "https://mirror/metadata/",
			wantTgts:     "https://mirror/targets/",
		},
		{name: "nothing anywhere", wantErr: true},
		{name: "not a URL", metaFlag: "://nope", wantErr: true},
		{name: "unsupported scheme", metaFlag: "file:///srv/repo/metadata/", wantErr: true},
		{name: "no host", metaFlag: "https:///metadata/", wantErr: true},
		{name: "bad targets flag", metaFlag: "https://a/metadata/", targetsFlag: "ftp://a/t/", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, targets, err := tt.a.urls(tt.metaFlag, tt.targetsFlag)
			if tt.wantErr {
				if !errors.Is(err, ErrAnchor) {
					t.Fatalf("err = %v, want ErrAnchor", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("urls: %v", err)
			}
			if meta != tt.wantMetadata || targets != tt.wantTgts {
				t.Errorf("urls = %q, %q; want %q, %q", meta, targets, tt.wantMetadata, tt.wantTgts)
			}
		})
	}
}

func TestChannelPrecedence(t *testing.T) {
	embedded := &anchor{repo: repository{Channel: "beta"}}
	if got := embedded.channel(""); got != "beta" {
		t.Errorf("embedded channel = %q, want beta", got)
	}
	if got := embedded.channel("nightly"); got != "nightly" {
		t.Errorf("flag channel = %q, want nightly", got)
	}
	if got := (&anchor{}).channel(""); got != defaultChannel {
		t.Errorf("default channel = %q, want %q", got, defaultChannel)
	}
}

// The embedded repository description is parsed strictly: an unknown key means
// the build embedded a configuration this binary does not understand, and
// proceeding with defaults would silently install from somewhere else than the
// build intended.
func TestDecodeRepository(t *testing.T) {
	var repo repository
	err := decodeRepository([]byte(`{"metadata_url":"https://a/metadata/","channel":"beta"}`), &repo)
	if err != nil {
		t.Fatalf("decodeRepository: %v", err)
	}
	if repo.MetadataURL != "https://a/metadata/" || repo.Channel != "beta" {
		t.Errorf("repo = %+v", repo)
	}

	bad := []struct{ name, body string }{
		{"unknown key", `{"metadata_url":"https://a/","insecure":true}`},
		{"no metadata url", `{"channel":"stable"}`},
		{"bad metadata url", `{"metadata_url":"ftp://a/"}`},
		{"bad targets url", `{"metadata_url":"https://a/","targets_url":"nonsense"}`},
		{"trailing data", `{"metadata_url":"https://a/"}{}`},
		{"not json", `nope`},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			var out repository
			if err := decodeRepository([]byte(tt.body), &out); !errors.Is(err, ErrAnchor) {
				t.Fatalf("err = %v, want ErrAnchor", err)
			}
		})
	}
}
