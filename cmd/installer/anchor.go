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
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path"
)

// The build-time trust anchor.
//
// A host project drops its own `root.json` and `repository.json` into
// cmd/installer/anchor/ before building; see the README there. idunn's own tree
// carries neither, because this repository has no repository to point at and a
// placeholder trust anchor is the one file that must never be shippable by
// accident.
//
// The anchor is embedded rather than passed in because it is the trust decision
// itself (docs/design.md §4): everything else — URLs, channel, version — is
// configuration, and a wrong value there fails verification. A wrong root.json
// would not fail; it would succeed against the wrong publisher.
//
//go:embed anchor
var anchorFS embed.FS

const (
	anchorDir      = "anchor"
	anchorRootName = "root.json"
	anchorRepoName = "repository.json"

	// anchorFlag is the only way to name a trust anchor at runtime, and only a
	// build that embeds none accepts it.
	anchorFlag = "--root-metadata"
)

// ErrAnchor is the class of every rejection of the embedded configuration or of
// a flag that tries to displace it.
var ErrAnchor = errors.New("installer: trust anchor")

// repository is the embedded description of where the repository lives. It
// carries no trust: root.json does.
type repository struct {
	MetadataURL string `json:"metadata_url"`
	TargetsURL  string `json:"targets_url"`
	Channel     string `json:"channel"`
}

// anchor is what this build was compiled with.
type anchor struct {
	root []byte     // the trust anchor, nil if this build carries none.
	repo repository // zero if this build carries no repository description.
}

// loadAnchor reads the embedded files. Both are optional: a build without them
// is the tool as it lives in idunn's own tree, usable only with the flags that
// name a trust anchor explicitly.
func loadAnchor() (*anchor, error) {
	a := &anchor{}

	raw, err := anchorFS.ReadFile(path.Join(anchorDir, anchorRootName))
	switch {
	case err == nil:
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil, fmt.Errorf("%w: the embedded %s is empty", ErrAnchor, anchorRootName)
		}
		a.root = raw
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("%w: %w", ErrAnchor, err)
	}

	raw, err = anchorFS.ReadFile(path.Join(anchorDir, anchorRepoName))
	switch {
	case err == nil:
		if err := decodeRepository(raw, &a.repo); err != nil {
			return nil, err
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, fmt.Errorf("%w: %w", ErrAnchor, err)
	}
	return a, nil
}

// decodeRepository parses repository.json strictly. An unknown key means the
// build embedded a configuration this binary does not understand, which is not
// something to proceed on with defaults.
func decodeRepository(raw []byte, out *repository) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrAnchor, anchorRepoName, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: %s: trailing data", ErrAnchor, anchorRepoName)
	}
	if out.MetadataURL == "" {
		return fmt.Errorf("%w: %s names no metadata_url", ErrAnchor, anchorRepoName)
	}
	if err := checkURL("metadata_url", out.MetadataURL); err != nil {
		return err
	}
	if out.TargetsURL != "" {
		if err := checkURL("targets_url", out.TargetsURL); err != nil {
			return err
		}
	}
	return nil
}

// checkURL rejects a repository URL this binary could not fetch from.
//
// It does not demand https. TLS is transport hardening here, not the basis of
// trust — the embedded root.json is (docs/design.md §4) — and an air-gapped
// mirror served over plain http is a legitimate deployment, not a downgrade.
func checkURL(field, raw string) error {
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

// hasRoot reports whether this build carries a trust anchor.
func (a *anchor) hasRoot() bool { return len(a.root) > 0 }

// trustAnchor returns the root metadata to seed the trust client with.
//
// A build that carries an anchor cannot be redirected to another one. That is
// the whole point of embedding it: an installer a user downloaded is pinned to
// the publisher it was built for, and a flag that could replace the pin would
// make every such binary a generic installer for anyone's repository. A build
// without an anchor is a tool rather than a product, and there the flag is the
// only way to name one.
func (a *anchor) trustAnchor(fromFlag []byte) ([]byte, error) {
	if a.hasRoot() {
		if len(fromFlag) > 0 {
			return nil, fmt.Errorf("%w: this build carries an embedded %s; %s cannot replace it",
				ErrAnchor, anchorRootName, anchorFlag)
		}
		return a.root, nil
	}
	if len(fromFlag) == 0 {
		return nil, fmt.Errorf("%w: this build carries no embedded %s; pass %s (see cmd/installer/anchor/README.md)",
			ErrAnchor, anchorRootName, anchorFlag)
	}
	return fromFlag, nil
}

// urls resolves where to fetch from: the flags if given, else what the build
// embedded.
//
// Unlike the trust anchor, a URL may be overridden. A wrong one cannot make this
// binary trust anything new — it fails verification or finds nothing — and being
// able to point a shipped installer at a mirror or a staging repository is worth
// more than the illusion of protection a locked URL would give.
func (a *anchor) urls(metadataFlag, targetsFlag string) (metadataURL, targetsURL string, err error) {
	metadataURL = firstNonEmpty(metadataFlag, a.repo.MetadataURL)
	if metadataURL == "" {
		return "", "", fmt.Errorf("%w: no metadata URL: this build embeds none, so --metadata-url is required", ErrAnchor)
	}
	if err := checkURL("--metadata-url", metadataURL); err != nil {
		return "", "", err
	}

	targetsURL = firstNonEmpty(targetsFlag, a.repo.TargetsURL)
	if targetsURL == "" {
		// The published layout puts /metadata/ and /targets/ side by side
		// (docs/packer.md §6), so the sibling is the right default — not
		// go-tuf's, which nests targets underneath the metadata URL.
		base, perr := url.Parse(metadataURL)
		if perr != nil {
			return "", "", fmt.Errorf("%w: metadata URL: %w", ErrAnchor, perr)
		}
		targetsURL = base.JoinPath("..", "targets/").String()
	}
	if err := checkURL("--targets-url", targetsURL); err != nil {
		return "", "", err
	}
	return metadataURL, targetsURL, nil
}

// channel picks the channel: the flag, then the embedded default, then stable.
func (a *anchor) channel(fromFlag string) string {
	return firstNonEmpty(fromFlag, a.repo.Channel, defaultChannel)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
