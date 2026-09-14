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
	"sort"
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

	// MaxTargetBytes is the largest signed length this client accepts for any
	// one target. Zero selects DefaultMaxTargetBytes; a negative value is
	// refused by New rather than guessed at.
	//
	// It exists because go-tuf hands a target over as one []byte (see Target),
	// so the signed length is also the allocation this process is about to
	// make — and the same length sizes the reads that reuse and patching do
	// beside it. A repository is untrusted input even when it is correctly
	// signed: a compromised publisher, or a mistake in a build pipeline, can put
	// a length in targets metadata that no client can hold. Refusing it with a
	// typed error is the fail-closed answer to what would otherwise be an OOM
	// kill with no diagnosis (AGENTS.md §1.1).
	//
	// The ceiling can only refuse. Whatever it lets through is still verified by
	// go-tuf exactly as before; it adds no check of its own on the bytes.
	MaxTargetBytes int64
}

// DefaultMaxTargetBytes is the ceiling on one target when Options leaves
// MaxTargetBytes unset. It is generous on purpose — a guard against the absurd,
// not a policy about release size — and a host that ships larger payloads
// raises it deliberately.
const DefaultMaxTargetBytes = 2 << 30 // 2 GiB

// Client is the narrow trust surface the rest of core sees. It exposes only
// Refresh, LatestRelease and MaterializeTarget so no TUF detail leaks outward.
type Client struct {
	up        *tufupdater.Updater
	cfg       *tufconfig.UpdaterConfig
	now       func() time.Time
	maxTarget int64
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
	maxTarget := o.MaxTargetBytes
	switch {
	case maxTarget < 0:
		return nil, fmt.Errorf("%w: MaxTargetBytes %d is negative", ErrTrust, maxTarget)
	case maxTarget == 0:
		maxTarget = DefaultMaxTargetBytes
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
	return &Client{up: up, cfg: cfg, now: now, maxTarget: maxTarget}, nil
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
// A target is held whole in memory, and at go-tuf v2.4.2 that is structural
// rather than a shortcut taken here: fetcher.Fetcher is
//
//	DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error)
//
// and Updater.DownloadTarget verifies with VerifyLengthHashes over the complete
// slice. Streaming would need that contract to expose the response body, and
// building a second download-and-verify path beside go-tuf to get it is exactly
// what AGENTS.md §1.2 forbids. What is in this package's hands is the ceiling:
// a target above Options.MaxTargetBytes is refused before it is requested. See
// backlog IDN-12.
func (c *Client) Target(targetPath string) ([]byte, error) {
	return c.target(targetPath)
}

// TargetLength returns the signed length of a target without fetching it.
//
// It is a pre-filter, never a verdict: staging uses it to dismiss a local reuse
// candidate whose size cannot possibly match before it reads the file at all —
// which for a several-hundred-megabyte payload is the difference between one
// stat and one full read. A length is not an authentication; whatever survives
// this still goes through VerifyTarget.
//
// It is also the size every read beside go-tuf is bounded by — a reuse
// candidate, a patch base, a patch's output — so a length above the ceiling is
// refused here too, not handed out for someone to allocate.
func (c *Client) TargetLength(targetPath string) (int64, error) {
	info, err := c.targetInfo(targetPath)
	if err != nil {
		return 0, err
	}
	return info.Length, nil
}

// VerifyTarget reports whether data are exactly the bytes signed for targetPath.
//
// It exists so bytes that did not come out of go-tuf's own download path — a
// file reused from an already-installed version, later the result of a delta
// patch — are admitted by the *same* check that guards a download, performed by
// the same code go-tuf uses on a cached target (AGENTS.md §1.2, §1.5). Callers
// get one verdict and no material to assemble a check of their own: nothing
// outside this package ever sees a signed hash, so nothing outside it can
// compare against one leniently.
func (c *Client) VerifyTarget(targetPath string, data []byte) error {
	info, err := c.targetInfo(targetPath)
	if err != nil {
		return err
	}
	if err := info.VerifyLengthHashes(data); err != nil {
		return fmt.Errorf("%w: target %q: %w", ErrTrust, targetPath, err)
	}
	return nil
}

// ReleaseVersion resolves one explicitly named version, bypassing the channel
// pointer.
//
// It exists for the installer's `--version` and for pinned deployments. The
// descriptor is still a signed TUF target and is verified exactly as the channel
// head would be; what is bypassed is only the publisher's statement about which
// version is current. TUF's metadata rollback protection is untouched — an
// operator naming an old version is choosing it, not being served it — and the
// installer's own downgrade preflight still applies on top (docs/design.md
// §14.6).
func (c *Client) ReleaseVersion(goos, goarch, version string) (*release.Descriptor, error) {
	if !release.ValidVersion(version) {
		return nil, fmt.Errorf("%w: version %q is not SemVer", ErrResolve, version)
	}
	raw, err := c.target(release.DescriptorPath(goos, goarch, version))
	if err != nil {
		return nil, err
	}
	d, err := release.ParseDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: descriptor: %w", ErrTrust, err)
	}
	// The path a descriptor lives at states what it describes. A document that
	// disagrees with its own location is a valid target substituted for another
	// one, so we refuse rather than believe the contents over the path.
	if d.Version != version || d.OS != goos || d.Arch != goarch {
		return nil, fmt.Errorf("%w: descriptor for %s-%s@%s describes %s-%s@%s",
			ErrResolve, goos, goarch, version, d.OS, d.Arch, d.Version)
	}
	return d, nil
}

// Versions lists the releases the repository publishes for a platform, oldest
// first, as the signed targets metadata already knows them.
//
// A patch turns one exact set of bytes into another, so a client that skipped
// releases has to walk the ones it missed (release.Chain). Walking needs to know
// which releases exist — and that is not a new thing to publish and sign: every
// descriptor is a target, the targets metadata lists the path of every target in
// a role, and the path of a descriptor states the version it describes. This
// reads that list. It adds no trust decision: what a version here entitles
// anyone to is still decided when its descriptor is resolved and its bytes are
// verified.
//
// It reports what the client currently has metadata for. Delegated roles are
// loaded lazily — resolving a release of a line is what pulls that line's role
// in — so a caller that wants the full picture resolves the two ends it knows
// (the channel head, its own installed version) before asking. A line whose role
// was never loaded is silently absent, which costs a chain and never invents
// one.
func (c *Client) Versions(goos, goarch string) []string {
	seen := map[string]bool{}
	var out []string
	for _, role := range c.up.GetTrustedMetadataSet().Targets {
		if role == nil {
			continue
		}
		for targetPath := range role.Signed.Targets {
			v, ok := release.VersionOfDescriptorPath(targetPath, goos, goarch)
			if !ok || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}

	// Map iteration is unordered and this feeds a walk, so the order is
	// established here rather than left to whoever consumes it.
	sort.SliceStable(out, func(i, j int) bool {
		cmp, err := release.Compare(out[i], out[j])
		if err != nil {
			// Unreachable: every entry passed ValidVersion above. Ordering
			// equal keeps the sort total instead of panicking on a version
			// that cannot be compared.
			return false
		}
		return cmp < 0
	})
	return out
}

// OpenLine makes the descriptors of one release line visible to Versions.
//
// A TUF client loads delegated roles lazily: a role is pulled in, verified and
// kept when a target it owns is resolved. That is the right behaviour for
// fetching — a client following one release line never downloads another line's
// metadata — and the wrong one for planning a walk, which needs the list of
// releases *before* it resolves any of them. A client that has just resolved a
// 2.0.0 head knows the 2.x line and nothing else, and would conclude that the
// 1.x releases it has to walk through do not exist.
//
// So this asks for a target in the line and throws the answer away: what
// matters is the role that gets loaded and verified on the way, not whether
// that particular path exists. Nothing is trusted differently for having been
// loaded this way — it is the same role, verified by the same delegation, and
// every target in it is still checked when it is used.
//
// A line the repository does not publish loads nothing, which is not an error:
// a walk through it simply finds no releases.
func (c *Client) OpenLine(goos, goarch, major string) {
	_, _ = c.up.GetTargetInfo(release.DescriptorPath(goos, goarch, major+".0.0"))
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
	info, err := c.targetInfo(targetPath)
	if err != nil {
		return nil, err
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

// targetInfo returns the signed description of one target, refusing a target
// whose signed length is above the ceiling.
//
// Every way a target's bytes come into this process starts here — a download or
// a cache read in target, and the reads that reuse and patching size by
// TargetLength — so the ceiling is checked once, before any of them has
// requested or read a byte. Refusing here costs a request that would have failed
// anyway; refusing later costs the memory. The check narrows what go-tuf may be
// asked for and nothing else: it never admits bytes, it only declines to fetch
// them.
func (c *Client) targetInfo(targetPath string) (*metadata.TargetFiles, error) {
	info, err := c.up.GetTargetInfo(targetPath)
	if err != nil {
		return nil, fmt.Errorf("%w: target %q: %w", ErrTrust, targetPath, err)
	}
	if info.Length > c.maxTarget {
		return nil, fmt.Errorf("%w: target %q is %d bytes, above the %d-byte ceiling (raise Options.MaxTargetBytes)",
			ErrTrust, targetPath, info.Length, c.maxTarget)
	}
	return info, nil
}

// UnsafeSetRefTime pins the reference time used for expiry checks. TEST ONLY —
// it exists so expiry, freeze and clock-rollback cases are deterministic, and must
// never be reachable from a production code path.
func (c *Client) UnsafeSetRefTime(t time.Time) {
	c.up.UnsafeSetRefTime(t)
}
