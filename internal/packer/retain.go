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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/theupdateframework/go-tuf/v2/metadata"

	"github.com/go-idavoll/idunn/core/release"
)

// Retention (docs/packer.md §4 step 4, docs/design.md §4.1).
//
// Content addressing turns "which old files may go?" into reference counting
// rather than path guessing. A release is a descriptor; a descriptor names
// payload targets by content; a patch names the two payloads it connects by
// content. So once the set of retained descriptors is fixed, every other target
// in the release line is either named by one of them — directly, or as an end of
// a patch — or it is not, and only the second kind is removed. Two releases
// sharing a file share one target, and that target stays for as long as either
// release does.
//
// The rules, each of them a way retention could otherwise hurt the clients it
// exists to serve:
//
//   - The window is the newest Keep releases per platform of the release line
//     being published. Nothing in another line is touched: retiring a major is an
//     end-of-life decision, and it would need a key this publish was not given.
//   - A release a channel pointer names is never dropped — and a window that
//     would drop one is refused, not quietly widened. A publisher retiring its
//     own channel head would be running the freeze attack on its own clients,
//     and a window that means something other than what it says is not one to
//     delete files on.
//   - A payload stays while any retained descriptor, in any role, names it.
//   - A patch stays while the payload it starts from or the payload it produces
//     is named by a retained descriptor. Every patch a client can use on a walk
//     between retained releases (release.Chain, stage.Route) connects two
//     retained payloads, so that set is contained in what survives.
//   - Anything in the line role that is none of the three is a refusal: a target
//     retention cannot classify is one it cannot tell the users of.
//
// Metadata is re-signed through the normal flow over the reduced target set, and
// files are deleted only after the timestamp naming that metadata is written.

// retirement is what one retention pass removes.
type retirement struct {
	// targets are the target paths that leave the release-line role, sorted.
	targets []string

	// files are the repository-relative paths under targets/ that back them,
	// sorted. They are deleted last, after the metadata that no longer names
	// them is the metadata being served.
	files []string
}

// retire applies the retention window to the release-line role in roleTargets,
// in place, and reports what it removed. It returns nil when retention is off.
//
// roleTargets is the merged view: the repository as it was plus this publish,
// so the release being published is part of what the window is counted over.
func retire(cfg *Config, st *state, blobs []blob, roleTargets map[string]map[string]*metadata.TargetFiles, lineRole string) (*retirement, error) {
	if cfg.Retention.Keep == nil {
		return nil, nil
	}
	keep := *cfg.Retention.Keep
	if keep < MinRetain {
		// validate refuses this already; a caller that built a Config by hand
		// gets the same answer.
		return nil, fmt.Errorf("%w: retention.keep %d is below the minimum of %d", ErrConfig, keep, MinRetain)
	}
	line := roleTargets[lineRole]
	if line == nil {
		return nil, nil
	}
	major, ok := majorNum(lineRole)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a release-line role", ErrRepo, lineRole)
	}
	lineMajor := fmt.Sprint(major)

	// Classify every target of the line before deciding anything.
	byPlatform := map[string][]string{} // "os-arch" -> versions
	var payloads, patches []string
	for _, target := range sortedKeys(line) {
		if goos, goarch, version, ok := parseDescriptorTarget(target); ok {
			if majorOf(version) != lineMajor {
				return nil, fmt.Errorf("%w: %s holds %s, which belongs to another release line", ErrRepo, lineRole, target)
			}
			byPlatform[goos+"-"+goarch] = append(byPlatform[goos+"-"+goarch], version)
			continue
		}
		if _, ok := payloadHash(target); ok {
			payloads = append(payloads, target)
			continue
		}
		if _, _, ok := patchHashes(target); ok {
			patches = append(patches, target)
			continue
		}
		return nil, fmt.Errorf("%w: %s holds %s, which is neither a descriptor, a payload nor a patch; retention cannot tell what still needs it",
			ErrRepo, lineRole, target)
	}

	dropped, err := window(byPlatform, keep)
	if err != nil {
		return nil, err
	}

	read := newTargetReader(st, blobs, roleTargets)
	if err := checkHeads(cfg, roleTargets, read, dropped, keep); err != nil {
		return nil, err
	}

	// The reference count: every file target a retained descriptor names, in
	// any role, and the content hash of each.
	refTargets := map[string]bool{}
	refHashes := map[string]bool{}
	for _, role := range sortedKeys(roleTargets) {
		for _, target := range sortedKeys(roleTargets[role]) {
			goos, goarch, version, ok := parseDescriptorTarget(target)
			if !ok || dropped[target] {
				continue
			}
			d, err := readDescriptorTarget(read, target)
			if err != nil {
				return nil, err
			}
			if d.OS != goos || d.Arch != goarch || d.Version != version {
				return nil, fmt.Errorf("%w: %s describes %s %s-%s; retention cannot tell what it protects",
					ErrRepo, target, d.Version, d.OS, d.Arch)
			}
			for i := range d.Files {
				sum, ok := payloadHash(d.Files[i].Target)
				if !ok {
					return nil, fmt.Errorf("%w: %s names %s, which is not a content-addressed payload",
						ErrRepo, target, d.Files[i].Target)
				}
				refTargets[d.Files[i].Target] = true
				refHashes[sum] = true
			}
		}
	}

	for _, target := range payloads {
		if !refTargets[target] {
			dropped[target] = true
		}
	}
	for _, target := range patches {
		from, to, _ := patchHashes(target)
		if !refHashes[from] && !refHashes[to] {
			dropped[target] = true
		}
	}
	if len(dropped) == 0 {
		return nil, nil
	}

	// The invariant everything above exists for, checked on its own rather
	// than trusted to follow from the construction: nothing removed is named
	// by a retained descriptor or emitted by this very publish.
	emitted := make(map[string]bool, len(blobs))
	for i := range blobs {
		emitted[blobs[i].target] = true
	}
	r := &retirement{}
	for _, target := range sortedKeys(dropped) {
		if refTargets[target] || emitted[target] {
			return nil, fmt.Errorf("%w: retention would remove %s, which a retained release still needs", ErrRepo, target)
		}
		sum, ok := sumOf(line[target].Hashes["sha256"])
		if !ok {
			return nil, fmt.Errorf("%w: %s carries no sha256 hash", ErrRepo, target)
		}
		r.targets = append(r.targets, target)
		r.files = append(r.files, hashPrefixedPath(target, sum))
		delete(line, target)
	}
	sort.Strings(r.files)
	return r, nil
}

// window picks, per platform, the descriptors beyond the newest keep releases.
func window(byPlatform map[string][]string, keep int) (map[string]bool, error) {
	dropped := map[string]bool{}
	for _, platform := range sortedKeys(byPlatform) {
		versions := byPlatform[platform]
		var cmpErr error
		sort.SliceStable(versions, func(i, j int) bool {
			c, err := release.Compare(versions[i], versions[j])
			if err != nil && cmpErr == nil {
				cmpErr = err
			}
			return c > 0 // newest first
		})
		if cmpErr != nil {
			return nil, fmt.Errorf("%w: ordering the releases of %s: %w", ErrRepo, platform, cmpErr)
		}
		// Two spellings of one precedence ("1.0.0+a", "1.0.0+b") leave "the
		// newest N" undefined, and which of them survives would be a tie-break
		// nobody chose. release.Chain refuses the same ambiguity.
		for i := 1; i < len(versions); i++ {
			if c, _ := release.Compare(versions[i-1], versions[i]); c == 0 {
				return nil, fmt.Errorf("%w: %s publishes %s and %s with the same precedence; retention has no order to count",
					ErrRepo, platform, versions[i-1], versions[i])
			}
		}
		goos, goarch, _ := strings.Cut(platform, "-")
		for i := keep; i < len(versions); i++ {
			dropped[release.DescriptorPath(goos, goarch, versions[i])] = true
		}
	}
	return dropped, nil
}

// checkHeads refuses a window that would drop a release a channel pointer names,
// the one being published included.
//
// Pointers are parsed with the client's own parser rather than inferred from a
// path: what a pointer names is a property of its content.
func checkHeads(cfg *Config, roleTargets map[string]map[string]*metadata.TargetFiles, read targetReader, dropped map[string]bool, keep int) error {
	for i := range cfg.Targets {
		p := &cfg.Targets[i]
		if target := release.DescriptorPath(p.OS, p.Arch, cfg.Version); dropped[target] {
			return fmt.Errorf("%w: retention.keep %d would drop %s, the release this publish makes the head of %s",
				ErrConfig, keep, target, cfg.Channel)
		}
	}
	for _, role := range sortedKeys(roleTargets) {
		if _, isLine := majorNum(role); isLine {
			continue
		}
		for _, target := range sortedKeys(roleTargets[role]) {
			if !strings.HasPrefix(target, "channels/") {
				continue
			}
			raw, err := read(target)
			if err != nil {
				return err
			}
			ptr, err := release.ParsePointer(raw)
			if err != nil {
				return fmt.Errorf("%w: channel pointer %s cannot be parsed, so retention cannot tell what it protects: %w",
					ErrRepo, target, err)
			}
			head := release.DescriptorPath(ptr.OS, ptr.Arch, ptr.Version)
			if dropped[head] || dropped[ptr.Descriptor] {
				return fmt.Errorf("%w: retention.keep %d would drop %s, the head channel %s points at; widen the window or move that channel first",
					ErrConfig, keep, head, ptr.Channel)
			}
		}
	}
	return nil
}

// readDescriptorTarget reads and parses one published descriptor. A descriptor
// that cannot be read is a refusal: retention cannot count references it cannot
// see, and guessing would delete what it protects.
func readDescriptorTarget(read targetReader, target string) (*release.Descriptor, error) {
	raw, err := read(target)
	if err != nil {
		return nil, err
	}
	d, err := release.ParseDescriptor(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be parsed, so retention cannot tell what it still needs: %w", ErrRepo, target, err)
	}
	return d, nil
}

// targetReader returns the published bytes of one target.
type targetReader func(target string) ([]byte, error)

// newTargetReader reads a target from this publish when it is part of it, and
// from the repository otherwise.
//
// What this publish emits is not on disk yet — targets are written after the
// metadata is built — so its in-memory blob is the copy that counts, and it
// replaces what the repository held (a channel pointer moves). Everything else
// is read back contained by os.Root and checked against the length and hashes
// the role signs for it, with go-tuf's own check.
func newTargetReader(st *state, blobs []blob, roleTargets map[string]map[string]*metadata.TargetFiles) targetReader {
	pending := make(map[string][]byte, len(blobs))
	for i := range blobs {
		pending[blobs[i].target] = blobs[i].data
	}
	// The delegation patterns are disjoint, so one flat view cannot hide two
	// different targets behind one path.
	flat := map[string]*metadata.TargetFiles{}
	for _, role := range sortedKeys(roleTargets) {
		for target, info := range roleTargets[role] {
			flat[target] = info
		}
	}
	return func(target string) ([]byte, error) {
		if raw, ok := pending[target]; ok {
			return raw, nil
		}
		info, ok := flat[target]
		if !ok {
			return nil, fmt.Errorf("%w: %s is not a published target", ErrRepo, target)
		}
		sum, ok := sumOf(info.Hashes["sha256"])
		if !ok {
			return nil, fmt.Errorf("%w: %s carries no sha256 hash", ErrRepo, target)
		}
		raw, err := readContainedTarget(st.targetsDir, hashPrefixedPath(target, sum))
		if err != nil {
			return nil, fmt.Errorf("%w: reading published target %s: %w", ErrRepo, target, err)
		}
		if err := info.VerifyLengthHashes(raw); err != nil {
			return nil, fmt.Errorf("%w: published target %s does not match what its role signs for: %w", ErrRepo, target, err)
		}
		return raw, nil
	}
}

// readContainedTarget reads one metadata-sized target file under dir. Only
// descriptors and pointers are read this way, so the metadata ceiling applies.
func readContainedTarget(dir, rel string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.FromSlash(rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxMetadataLen+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxMetadataLen {
		return nil, fmt.Errorf("larger than %d bytes", MaxMetadataLen)
	}
	return raw, nil
}

// removeRetired deletes the files behind retired targets.
//
// It runs after timestamp.json is written. A file already gone is not an error —
// the outcome asked for is its absence — but any other failure is reported: the
// repository metadata is complete and consistent at that point, and what is left
// is an orphaned file the operator should know about.
func removeRetired(st *state, r *retirement) error {
	if r == nil || len(r.files) == 0 {
		return nil
	}
	root, err := os.OpenRoot(st.targetsDir)
	if err != nil {
		return fmt.Errorf("%w: opening %s: %w", ErrRepo, st.targetsDir, err)
	}
	defer func() { _ = root.Close() }()
	for _, rel := range r.files {
		if err := root.Remove(filepath.FromSlash(rel)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w: the metadata no longer names %s, but removing it failed: %w", ErrRepo, rel, err)
		}
	}
	return nil
}

// parseDescriptorTarget is the inverse of release.DescriptorPath, reporting false
// for anything that is not a descriptor target.
func parseDescriptorTarget(target string) (goos, goarch, version string, ok bool) {
	rest, found := strings.CutPrefix(target, "releases/")
	if !found {
		return "", "", "", false
	}
	platform, file, found := strings.Cut(rest, "/")
	if !found {
		return "", "", "", false
	}
	goos, goarch, found = strings.Cut(platform, "-")
	if !found || !platformRe.MatchString(goos) || !platformRe.MatchString(goarch) {
		return "", "", "", false
	}
	version, found = strings.CutSuffix(file, ".json")
	if !found || !release.ValidVersion(version) {
		return "", "", "", false
	}
	// A round trip refuses anything that only looks like a descriptor path.
	if release.DescriptorPath(goos, goarch, version) != target {
		return "", "", "", false
	}
	return goos, goarch, version, true
}

// hexSumRe is a lowercase hex SHA-256.
var hexSumRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// majorDigitsRe is a major version as the packer writes it into a path: digits,
// no leading zero (validate refuses one in pack.yaml for the same reason).
var majorDigitsRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// payloadHash returns the content hash a payload target path is named after,
// reporting false for anything release.PayloadPath could not have produced.
func payloadHash(target string) (string, bool) {
	rest, ok := strings.CutPrefix(target, "payloads/v")
	if !ok {
		return "", false
	}
	major, sum, ok := strings.Cut(rest, "/")
	if !ok || !majorDigitsRe.MatchString(major) || !hexSumRe.MatchString(sum) {
		return "", false
	}
	raw, err := hex.DecodeString(sum)
	if err != nil || len(raw) != sha256.Size || release.PayloadPath(major, raw) != target {
		return "", false
	}
	return sum, true
}

// patchHashes returns the two content hashes a patch target path is named after,
// reporting false for anything release.PatchPath could not have produced.
func patchHashes(target string) (from, to string, ok bool) {
	rest, found := strings.CutPrefix(target, "patches/v")
	if !found {
		return "", "", false
	}
	major, name, found := strings.Cut(rest, "/")
	if !found || !majorDigitsRe.MatchString(major) {
		return "", "", false
	}
	from, to, found = strings.Cut(name, "-")
	if !found || !hexSumRe.MatchString(from) || !hexSumRe.MatchString(to) {
		return "", "", false
	}
	fromRaw, _ := hex.DecodeString(from)
	toRaw, _ := hex.DecodeString(to)
	// The line of the base is not part of the name, so any line reconstructs it.
	want, found := release.PatchPath(release.PayloadPath(major, fromRaw), release.PayloadPath(major, toRaw))
	if !found || want != target || path.Base(target) != name {
		return "", "", false
	}
	return from, to, true
}
