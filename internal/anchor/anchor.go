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

// Package anchor reads the build-time trust anchor and repository description a
// shipped binary embeds.
//
// Both cmd/installer and cmd/helper compile a publisher's root.json and
// repository.json in with go:embed. The trust anchor is the trust decision itself
// (docs/design.md §4); the repository description is configuration. Reading them
// is kept in one place so the two binaries cannot come to disagree about what a
// valid embedded configuration is.
package anchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
)

// The file names inside an embedded anchor directory.
const (
	RootName = "root.json"
	RepoName = "repository.json"
)

// ErrAnchor is the class of every rejection of an embedded configuration.
var ErrAnchor = errors.New("trust anchor")

// Repository is the embedded description of where the repository lives. It
// carries no trust: root.json does.
type Repository struct {
	MetadataURL string `json:"metadata_url"`
	TargetsURL  string `json:"targets_url"`
	Channel     string `json:"channel"`
}

// Embedded is what a build was compiled with.
type Embedded struct {
	Root []byte      // the trust anchor, nil if the build carries none.
	Repo *Repository // nil if the build carries no repository description.
}

// Load reads dir/root.json and dir/repository.json from fsys. Both are optional;
// a present but unusable file is an error.
func Load(fsys fs.FS, dir string) (*Embedded, error) {
	e := &Embedded{}

	raw, err := fs.ReadFile(fsys, path.Join(dir, RootName))
	switch {
	case err == nil:
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, fmt.Errorf("%w: the embedded %s is empty", ErrAnchor, RootName)
		}
		e.Root = raw
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("%w: %w", ErrAnchor, err)
	}

	raw, err = fs.ReadFile(fsys, path.Join(dir, RepoName))
	switch {
	case err == nil:
		repo, err := DecodeRepository(raw)
		if err != nil {
			return nil, err
		}
		e.Repo = &repo
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("%w: %w", ErrAnchor, err)
	}
	return e, nil
}

// Complete reports whether the build carries both a trust anchor and a
// repository to use it with — what a binary that may run privileged requires.
func (e *Embedded) Complete() bool {
	return len(e.Root) > 0 && e.Repo != nil && e.Repo.MetadataURL != ""
}

// DecodeRepository parses repository.json strictly. An unknown key means the
// build embedded a configuration this binary does not understand, which is not
// something to proceed on with defaults.
func DecodeRepository(raw []byte) (Repository, error) {
	var out Repository
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return Repository{}, fmt.Errorf("%w: %s: %w", ErrAnchor, RepoName, err)
	}
	if dec.More() {
		return Repository{}, fmt.Errorf("%w: %s: trailing data", ErrAnchor, RepoName)
	}
	if out.MetadataURL == "" {
		return Repository{}, fmt.Errorf("%w: %s names no metadata_url", ErrAnchor, RepoName)
	}
	if err := CheckURL("metadata_url", out.MetadataURL); err != nil {
		return Repository{}, err
	}
	if out.TargetsURL != "" {
		if err := CheckURL("targets_url", out.TargetsURL); err != nil {
			return Repository{}, err
		}
	}
	return out, nil
}

// CheckURL rejects a repository URL a client could not fetch from.
//
// It does not demand https. TLS is transport hardening here, not the basis of
// trust — the embedded root.json is (docs/design.md §4) — and an air-gapped
// mirror served over plain http is a legitimate deployment, not a downgrade.
func CheckURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %s is not a URL: %w", ErrAnchor, field, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return fmt.Errorf("%w: %s has scheme %q; only http and https are supported", ErrAnchor, field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%w: %s names no host", ErrAnchor, field)
	}
	return nil
}

// TargetsURL returns the repository's targets URL, defaulting to the targets/
// sibling of the metadata URL — the layout the packer publishes (docs/packer.md
// §6), not go-tuf's default, which nests targets underneath the metadata URL.
func TargetsURL(metadataURL, targetsURL string) (string, error) {
	if targetsURL != "" {
		return targetsURL, nil
	}
	base, err := url.Parse(metadataURL)
	if err != nil {
		return "", fmt.Errorf("%w: metadata URL: %w", ErrAnchor, err)
	}
	return base.JoinPath("..", "targets/").String(), nil
}
