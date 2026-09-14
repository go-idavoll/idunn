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
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/internal/anchor"
)

// The build-time configuration: a publisher's root.json, repository.json and
// helper.json, compiled in (docs/helper.md §2). idunn's own tree carries none of
// them; see anchor/README.md.
//
//go:embed anchor
var anchorFS embed.FS

// buildFS is where the build configuration is read from: the embedded files, or
// a test's stand-in.
var buildFS fs.FS = anchorFS

const (
	anchorDir  = "anchor"
	helperName = "helper.json"

	callersName = "callers.json"

	// maxCallersBytes bounds callers.json. It is a short list of numbers; the
	// ceiling exists so a damaged file cannot make a root process read forever.
	maxCallersBytes = 64 << 10
	// maxCallers bounds the list itself.
	maxCallers = 1024
	// maxMinInterval bounds min_interval_seconds: an hour between applies is
	// already more than any real deployment wants.
	maxMinInterval = 3600
)

// ErrConfig classifies every refusal of the embedded or per-machine
// configuration.
var ErrConfig = errors.New("helper: configuration")

// helperConfig is helper.json.
type helperConfig struct {
	Label                 string   `json:"label"`
	AllowedRoots          []string `json:"allowed_roots"`
	PeerRequirement       string   `json:"peer_requirement"`
	MinIntervalSeconds    int      `json:"min_interval_seconds"`
	MacOSBundleIdentifier string   `json:"macos_bundle_identifier"`
}

// build is everything this binary was compiled with.
type build struct {
	anchor *anchor.Embedded
	helper helperConfig
}

// loadBuild reads and validates the embedded configuration. A helper runs as
// root or SYSTEM, so an incomplete build is refused outright rather than started
// with defaults: there is no default trust anchor and no default install root.
func loadBuild(fsys fs.FS) (*build, error) {
	a, err := anchor.Load(fsys, anchorDir)
	if err != nil {
		return nil, err
	}
	if !a.Complete() {
		return nil, fmt.Errorf("%w: this build embeds no complete trust anchor (%s and %s in cmd/helper/anchor/)",
			ErrConfig, anchor.RootName, anchor.RepoName)
	}
	raw, err := fs.ReadFile(fsys, path.Join(anchorDir, helperName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: this build embeds no %s", ErrConfig, helperName)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	cfg, err := decodeHelperConfig(raw)
	if err != nil {
		return nil, err
	}
	return &build{anchor: a, helper: cfg}, nil
}

// decodeHelperConfig parses helper.json strictly and checks what can be checked
// without the machine: the label, that roots are absolute here, and the bounds.
// Whether a root is safe to write as root is judged by elevate.NewHelper on the
// machine, at start and per request.
func decodeHelperConfig(raw []byte) (helperConfig, error) {
	var cfg helperConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return helperConfig{}, fmt.Errorf("%w: %s: %w", ErrConfig, helperName, err)
	}
	if dec.More() {
		return helperConfig{}, fmt.Errorf("%w: %s: trailing data", ErrConfig, helperName)
	}
	if err := elevate.CheckHelperLabel(cfg.Label); err != nil {
		return helperConfig{}, fmt.Errorf("%w: %s: %w", ErrConfig, helperName, err)
	}
	if len(cfg.AllowedRoots) == 0 {
		return helperConfig{}, fmt.Errorf("%w: %s names no allowed_roots", ErrConfig, helperName)
	}
	for _, root := range cfg.AllowedRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return helperConfig{}, fmt.Errorf("%w: %s: allowed root %q is not a clean absolute path on this platform",
				ErrConfig, helperName, root)
		}
	}
	if cfg.MinIntervalSeconds < 0 || cfg.MinIntervalSeconds > maxMinInterval {
		return helperConfig{}, fmt.Errorf("%w: %s: min_interval_seconds must be 0 to %d", ErrConfig, helperName, maxMinInterval)
	}
	return cfg, nil
}

func (c helperConfig) minInterval() time.Duration {
	return time.Duration(c.MinIntervalSeconds) * time.Second
}

// callers is callers.json: who may ask, on this machine.
type callers struct {
	UIDs []uint32 `json:"uids,omitempty"`
	SIDs []string `json:"sids,omitempty"`
}

// sidPattern is the shape of a SID string. It is a syntax check for the file;
// which SIDs are acceptable as callers (accounts, not groups) is decided by
// elevate.NewHelper.
var sidPattern = regexp.MustCompile(`^S-1-[0-9]{1,13}(-[0-9]{1,10}){1,14}$`)

// readCallers reads callers.json from dir. A missing file is an empty list — the
// helper then answers only root or SYSTEM, which is elevate's fail-closed
// default — and anything else unusable is an error.
func readCallers(dir string) (callers, bool, error) {
	p := filepath.Join(dir, callersName)
	st, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return callers{}, false, nil
	}
	if err != nil {
		return callers{}, false, fmt.Errorf("%w: %s: %w", ErrConfig, p, err)
	}
	if !st.Mode().IsRegular() {
		return callers{}, false, fmt.Errorf("%w: %s is not a regular file", ErrConfig, p)
	}
	f, err := os.Open(p)
	if err != nil {
		return callers{}, false, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxCallersBytes+1))
	if err != nil {
		return callers{}, false, fmt.Errorf("%w: %s: %w", ErrConfig, p, err)
	}
	if len(raw) > maxCallersBytes {
		return callers{}, false, fmt.Errorf("%w: %s is larger than %d bytes", ErrConfig, p, maxCallersBytes)
	}
	c, err := decodeCallers(raw)
	if err != nil {
		return callers{}, false, fmt.Errorf("%s: %w", p, err)
	}
	return c, true, nil
}

func decodeCallers(raw []byte) (callers, error) {
	var c callers
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return callers{}, fmt.Errorf("%w: %s: %w", ErrConfig, callersName, err)
	}
	if dec.More() {
		return callers{}, fmt.Errorf("%w: %s: trailing data", ErrConfig, callersName)
	}
	if len(c.UIDs)+len(c.SIDs) > maxCallers {
		return callers{}, fmt.Errorf("%w: %s lists more than %d callers", ErrConfig, callersName, maxCallers)
	}
	for _, sid := range c.SIDs {
		if !sidPattern.MatchString(sid) {
			return callers{}, fmt.Errorf("%w: %s: %q is not a SID", ErrConfig, callersName, sid)
		}
	}
	return c, nil
}

// encode renders the list deterministically, so rewriting an unchanged list
// leaves the same bytes.
func (c callers) encode() []byte {
	var b bytes.Buffer
	b.WriteString("{")
	sep := ""
	if len(c.UIDs) > 0 {
		b.WriteString(`"uids":[`)
		for i, u := range c.UIDs {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(strconv.FormatUint(uint64(u), 10))
		}
		b.WriteString("]")
		sep = ","
	}
	if len(c.SIDs) > 0 {
		b.WriteString(sep + `"sids":[`)
		for i, s := range c.SIDs {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(strconv.Quote(s))
		}
		b.WriteString("]")
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// writeCallers replaces callers.json atomically: a temporary file in the same
// directory, flushed, then renamed over the old one.
func writeCallers(dir string, c callers) error {
	tmp, err := os.CreateTemp(dir, ".callers-*.json")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(c.encode()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	// Readable by everyone on purpose: `helper check` runs unprivileged, and who
	// may ask is not a secret — who may write it is what the state directory's
	// check protects.
	//
	//nolint:gosec // G302: see above.
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if err := os.Rename(name, filepath.Join(dir, callersName)); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return nil
}
