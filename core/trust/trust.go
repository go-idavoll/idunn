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

// Package trust wraps go-tuf v2 and is the only place in idunn that decides which
// bytes may be trusted.
//
// It answers "which bytes may I trust and fetch?"; everything else in core answers
// "how do I apply them safely?". There is deliberately no second verification path
// beside go-tuf (AGENTS.md §1.2): signatures, key rotation, freshness, and
// freeze/rollback/mix-and-match defense are go-tuf's job and are not re-implemented
// here. What this package adds is the app-level layer TUF does not model —
// resolving a channel pointer to a descriptor and checking that the two agree.
// See docs/design.md §3, §4.
package trust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	tufupdater "github.com/theupdateframework/go-tuf/v2/metadata/updater"

	"github.com/go-idavoll/idunn/core/fetch"
	"github.com/go-idavoll/idunn/core/release"
)

// ErrTrust is the class of every rejection originating in the TUF trust layer:
// signatures, thresholds, expiry, freshness, and target verification. It maps to
// the "verify" class of the Reporter taxonomy.
var ErrTrust = errors.New("trust")

// ErrResolve is the class of app-level resolution failures: a channel pointer and
// a descriptor that are each properly signed but do not agree with each other, or
// with the platform and version they were requested for. TUF cannot catch these —
// both documents are authentic, just not the pair we asked for.
var ErrResolve = errors.New("resolve")

// IsExpiry reports whether err is go-tuf's rejection of expired metadata.
//
// It exists so the updater can tell an operator "your system clock looks wrong"
// instead of "update failed" (docs/design.md §14.7). The distinction is for
// diagnosis only: expired metadata is refused either way, and nothing here or
// above may weaken that check — a clock the client cannot trust is the reason
// the freeze defence works.
func IsExpiry(err error) bool {
	var expired *metadata.ErrExpiredMetadata
	return errors.As(err, &expired)
}

// Options configures the trust client.
type Options struct {
	// Root is the trust anchor: the embedded, shipped root.json. It is compiled
	// into the binary, never downloaded on first use.
	Root []byte

	// MetadataURL and TargetsURL locate the TUF repository.
	MetadataURL string
	TargetsURL  string

	// LocalDir holds the trusted local metadata and the target cache.
	LocalDir string

	// Fetcher performs the transport. Injected so core does no direct network I/O.
	// Nil selects go-tuf's default fetcher.
	Fetcher fetch.Fetcher

	// Now is the injected clock. Tests drive expiry and clock-skew cases through
	// UnsafeSetRefTime rather than the real clock (AGENTS.md §4).
	Now func() time.Time
}

// Client is the narrow trust surface the rest of core sees. It exposes only
// Refresh, LatestRelease and MaterializeTarget so no TUF detail leaks outward.
type Client struct {
	up  *tufupdater.Updater
	cfg *tufconfig.UpdaterConfig
	now func() time.Time
}

// New creates a Client from the embedded root metadata. It does not touch the
// network; call Refresh for that.
func New(o Options) (*Client, error) {
	if len(o.Root) == 0 {
		return nil, fmt.Errorf("%w: no embedded root metadata", ErrTrust)
	}
	if o.MetadataURL == "" {
		return nil, fmt.Errorf("%w: no metadata URL", ErrTrust)
	}
	if o.LocalDir == "" {
		return nil, fmt.Errorf("%w: no local directory", ErrTrust)
	}

	cfg, err := tufconfig.New(o.MetadataURL, o.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTrust, err)
	}
	cfg.LocalMetadataDir = filepath.Join(o.LocalDir, "metadata")
	cfg.LocalTargetsDir = filepath.Join(o.LocalDir, "targets")
	if o.TargetsURL != "" {
		cfg.RemoteTargetsURL = o.TargetsURL
	}
	if o.Fetcher != nil {
		cfg.Fetcher = o.Fetcher
	}
	if err := cfg.EnsurePathsExist(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTrust, err)
	}

	up, err := tufupdater.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTrust, err)
	}

	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Client{up: up, cfg: cfg, now: now}, nil
}

// Now returns the current time from the injected clock. Callers use this instead
// of time.Now so expiry decisions stay deterministic under test.
func (c *Client) Now() time.Time { return c.now() }

// Refresh runs the TUF client workflow (root -> timestamp -> snapshot -> targets).
// Any expired, rolled-back, frozen, or inconsistent metadata aborts here with no
// on-disk change to the install root.
func (c *Client) Refresh() error {
	if err := c.up.Refresh(); err != nil {
		return fmt.Errorf("%w: refresh: %w", ErrTrust, err)
	}
	return nil
}

// LatestRelease resolves the channel pointer for the given channel and platform
// and returns the verified descriptor it names.
//
// A missing or unresolvable pointer is an error, not "no update": we cannot
// distinguish an empty channel from a server withholding it, so we fail closed.
func (c *Client) LatestRelease(channel, goos, goarch string) (*release.Descriptor, error) {
	raw, err := c.target(release.PointerPath(channel, goos, goarch))
	if err != nil {
		return nil, err
	}
	ptr, err := release.ParsePointer(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: channel pointer: %w", ErrTrust, err)
	}
	if ptr.Channel != channel || ptr.OS != goos || ptr.Arch != goarch {
		return nil, fmt.Errorf("%w: channel pointer is for %s/%s-%s, wanted %s/%s-%s",
			ErrResolve, ptr.Channel, ptr.OS, ptr.Arch, channel, goos, goarch)
	}
	// The descriptor path is derivable from the version the pointer claims, so a
	// pointer that names some other path is fetching a release it is not
	// entitled to name. Check before fetching: never request what is already
	// known to be wrong.
	if want := release.DescriptorPath(goos, goarch, ptr.Version); ptr.Descriptor != want {
		return nil, fmt.Errorf("%w: pointer names descriptor %q, expected %q", ErrResolve, ptr.Descriptor, want)
	}

	raw, err = c.target(ptr.Descriptor)
	if err != nil {
		return nil, err
	}
	d, err := release.ParseDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: descriptor: %w", ErrTrust, err)
	}

	// The pointer and the descriptor are separately signed targets. If they
	// disagree, one of them was substituted for another valid-but-wrong target,
	// so we refuse rather than pick a winner.
	if d.Version != ptr.Version || d.Channel != channel || d.OS != goos || d.Arch != goarch {
		return nil, fmt.Errorf("%w: descriptor %s/%s-%s@%s does not match pointer %s/%s-%s@%s",
			ErrResolve, d.Channel, d.OS, d.Arch, d.Version, channel, goos, goarch, ptr.Version)
	}

	return d, nil
}

// Target returns the verified bytes of one TUF target.
//
// It is what core/stage consumes: the trust layer hands over bytes go-tuf has
// checked against the signed hash and length, and the staging code does every
// write itself, through fsx, with the destination path already sanitized. The
// alternative — letting the trust layer write to a caller-supplied path — would
// put file placement inside the package that is supposed to answer only "which
// bytes may I trust?".
//
// TODO(stage): large payload targets are held whole in memory here, because
// go-tuf's DownloadTarget returns a byte slice. Streaming needs a fetcher that
// exposes the response body; the verification story is unchanged either way.
func (c *Client) Target(targetPath string) ([]byte, error) {
	return c.target(targetPath)
}

// MaterializeTarget places the verified bytes of a TUF target at dst, reusing the
// local cache only when the cached bytes match the signed hash and length. A
// cached file is never trusted on name alone (AGENTS.md §1.5).
func (c *Client) MaterializeTarget(targetPath, dst string) error {
	raw, err := c.target(targetPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	// Write via a temp file in the destination directory so an interrupted
	// materialization can never leave a half-written file where a complete one
	// is expected.
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".idunn-*")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("%w: %w", ErrTrust, err)
	}
	return nil
}

// target returns the verified bytes of one TUF target, preferring the local cache.
// go-tuf checks the signed hash and length in both paths; nothing here decides
// whether bytes are acceptable.
func (c *Client) target(targetPath string) ([]byte, error) {
	info, err := c.up.GetTargetInfo(targetPath)
	if err != nil {
		return nil, fmt.Errorf("%w: target %q: %w", ErrTrust, targetPath, err)
	}
	if _, raw, err := c.up.FindCachedTarget(info, ""); err == nil && raw != nil {
		return raw, nil
	}
	_, raw, err := c.up.DownloadTarget(info, "", "")
	if err != nil {
		return nil, fmt.Errorf("%w: download %q: %w", ErrTrust, targetPath, err)
	}
	return raw, nil
}

// UnsafeSetRefTime pins the reference time used for expiry checks. TEST ONLY —
// it exists so expiry, freeze and clock-rollback cases are deterministic, and must
// never be reachable from a production code path.
func (c *Client) UnsafeSetRefTime(t time.Time) {
	c.up.UnsafeSetRefTime(t)
}
