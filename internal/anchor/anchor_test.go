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

package anchor_test

import (
	"errors"
	"testing"
	"testing/fstest"

	"github.com/go-idavoll/idunn/internal/anchor"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	e, err := anchor.Load(fstest.MapFS{}, "anchor")
	if err != nil || e.Root != nil || e.Repo != nil || e.Complete() {
		t.Fatalf("Load(empty) = %+v, %v; want nothing embedded", e, err)
	}

	full := fstest.MapFS{
		"anchor/root.json":       {Data: []byte(`{"signed":{}}`)},
		"anchor/repository.json": {Data: []byte(`{"metadata_url":"https://u/metadata/"}`)},
	}
	e, err = anchor.Load(full, "anchor")
	if err != nil || !e.Complete() {
		t.Fatalf("Load(full) = %+v, %v; want complete", e, err)
	}

	onlyRoot := fstest.MapFS{"anchor/root.json": {Data: []byte(`{}`)}}
	if e, err := anchor.Load(onlyRoot, "anchor"); err != nil || e.Complete() {
		t.Fatalf("Load(root only) = %+v, %v; want incomplete", e, err)
	}

	for name, fsys := range map[string]fstest.MapFS{
		"empty root":    {"anchor/root.json": {Data: []byte(" \n")}},
		"bad repo json": {"anchor/repository.json": {Data: []byte(`{`)}},
	} {
		if _, err := anchor.Load(fsys, "anchor"); !errors.Is(err, anchor.ErrAnchor) {
			t.Errorf("Load(%s) = %v, want ErrAnchor", name, err)
		}
	}
}

func TestDecodeRepositoryRefuses(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"unknown key":     `{"metadata_url":"https://u/m/","mirror":"x"}`,
		"no metadata url": `{"channel":"stable"}`,
		"file scheme":     `{"metadata_url":"file:///etc/"}`,
		"no host":         `{"metadata_url":"https:///m/"}`,
		"bad targets":     `{"metadata_url":"https://u/m/","targets_url":"ftp://u/t/"}`,
		"trailing data":   `{"metadata_url":"https://u/m/"} {}`,
	} {
		if _, err := anchor.DecodeRepository([]byte(body)); !errors.Is(err, anchor.ErrAnchor) {
			t.Errorf("DecodeRepository(%s) = %v, want ErrAnchor", name, err)
		}
	}
}

func TestTargetsURLDefaultsToTheSibling(t *testing.T) {
	t.Parallel()

	got, err := anchor.TargetsURL("https://u/repo/metadata/", "")
	if err != nil || got != "https://u/repo/targets/" {
		t.Fatalf("TargetsURL = %q, %v", got, err)
	}
	if got, _ := anchor.TargetsURL("https://u/m/", "https://cdn/t/"); got != "https://cdn/t/" {
		t.Fatalf("an explicit targets URL was replaced: %q", got)
	}
}
