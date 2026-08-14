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

package elevate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/go-idavoll/idunn/core/release"
)

// The helper command line. This is the contract between the unprivileged updater
// and the privileged apply helper, and it is deliberately tiny: a verb and three
// scalars, no file list, no hashes, no staged path, no URL.
//
// Everything the helper needs beyond this it must obtain and verify itself
// (docs/design.md §14.2, threat T16). Widening this contract with anything the
// helper would then *act on* moves trust to the unprivileged side and defeats the
// whole boundary.
const (
	helperVerb        = "apply"
	helperFlagRoot    = "--root"
	helperFlagChannel = "--channel"
	helperFlagVersion = "--version"
)

// maxPathLen bounds a root or helper path. It is far above any real install
// layout and below every platform limit, so an absurd path is rejected before it
// reaches the filesystem or a command line.
const maxPathLen = 1024

// maxFieldLen bounds a channel or version string taken from a descriptor.
const maxFieldLen = 64

// Request is what actually crosses the privilege boundary.
//
// Each field is validated by newRequest before it is ever put on a command line.
// Quoting alone would be enough to make the launch unambiguous — the point of the
// character rules is stronger: a value that cannot be expressed in the request
// grammar is refused rather than transported.
type Request struct {
	Root    string // absolute install root the helper must write.
	Channel string // update channel to resolve, e.g. "stable".
	Version string // target version the helper must arrive at.
}

// newRequest validates the untrusted inputs and reduces them to the three scalars
// the helper accepts.
func newRequest(root string, d *release.Descriptor) (Request, error) {
	if d == nil {
		return Request{}, fmt.Errorf("%w: no descriptor", ErrRequest)
	}
	if err := checkInstallRoot(root); err != nil {
		return Request{}, err
	}
	if err := checkChannel(d.Channel); err != nil {
		return Request{}, err
	}
	if err := checkVersion(d.Version); err != nil {
		return Request{}, err
	}
	return Request{Root: root, Channel: d.Channel, Version: d.Version}, nil
}

// args renders the request as an argument vector, one element per value. The
// platform layer quotes these; it never concatenates them by hand.
func (r Request) args() []string {
	return []string{
		helperVerb,
		helperFlagRoot, r.Root,
		helperFlagChannel, r.Channel,
		helperFlagVersion, r.Version,
	}
}

// checkChannel accepts a short, lowercase channel name.
//
// The set is narrower than what a TUF target path can carry on purpose: this
// value ends up as a command-line argument to a process running as
// administrator, so it is restricted to what a channel name plausibly is.
func checkChannel(c string) error {
	if c == "" {
		return fmt.Errorf("%w: empty channel", ErrRequest)
	}
	if len(c) > maxFieldLen {
		return fmt.Errorf("%w: channel longer than %d bytes", ErrRequest, maxFieldLen)
	}
	if !isAlnum(rune(c[0])) {
		return fmt.Errorf("%w: channel %q does not start with a letter or digit", ErrRequest, c)
	}
	for _, r := range c {
		if isAlnum(r) || r == '.' || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("%w: channel %q contains %q", ErrRequest, c, r)
	}
	return nil
}

// checkVersion accepts a version the release package can parse.
//
// The parse is delegated to core/release rather than re-derived here: a second
// semver implementation that disagrees with the first is exactly the kind of
// split-brain the project bans (AGENTS.md §1.2 in spirit — one implementation per
// judgement). The character check in front of it keeps anything the parser might
// tolerate but a command line should not carry out of the argument vector.
func checkVersion(v string) error {
	if v == "" {
		return fmt.Errorf("%w: empty version", ErrRequest)
	}
	if len(v) > maxFieldLen {
		return fmt.Errorf("%w: version longer than %d bytes", ErrRequest, maxFieldLen)
	}
	for _, r := range v {
		if isAlnum(r) || r == '.' || r == '-' || r == '+' {
			continue
		}
		return fmt.Errorf("%w: version %q contains %q", ErrRequest, v, r)
	}
	if !release.ValidVersion(v) {
		return fmt.Errorf("%w: version %q is not SemVer", ErrRequest, v)
	}
	return nil
}

// checkInstallRoot accepts an absolute, clean, unambiguous install root.
//
// The rules are applied identically on every OS. A root is not descriptor data —
// it comes from the host application — but it is still the string that tells a
// privileged process where to write, and a relative or dot-laden one would be
// resolved against whatever working directory the elevated process happens to
// get. That directory is not ours to choose, so the ambiguity is refused here.
func checkInstallRoot(root string) error {
	if root == "" {
		return fmt.Errorf("%w: empty install root", ErrRequest)
	}
	if len(root) > maxPathLen {
		return fmt.Errorf("%w: install root longer than %d bytes", ErrRequest, maxPathLen)
	}
	if err := checkPathChars(root); err != nil {
		return fmt.Errorf("%w: install root: %w", ErrRequest, err)
	}
	rest, ok := splitAbsPrefix(root)
	if !ok {
		return fmt.Errorf("%w: install root %q is not absolute", ErrRequest, root)
	}
	if err := checkPathElements(rest); err != nil {
		return fmt.Errorf("%w: install root %q: %w", ErrRequest, root, err)
	}
	return nil
}

// checkHelperPath accepts an absolute, local path to an existing regular file.
//
// It is the cheap half of the helper guarantee; the expensive half — that only
// administrators can write that file and every directory above it — is an
// install-time property and cannot be established here without a TOCTOU of its
// own (see InteractiveOptions.HelperPath).
//
// A UNC path is refused outright: a binary fetched from a file server and run as
// administrator hands whoever controls that server, or the path to it, the local
// machine. On a domain-joined host that is a realistic reach, not a theoretical
// one.
func checkHelperPath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty helper path", ErrRequest)
	}
	if len(p) > maxPathLen {
		return fmt.Errorf("%w: helper path longer than %d bytes", ErrRequest, maxPathLen)
	}
	if err := checkPathChars(p); err != nil {
		return fmt.Errorf("%w: helper path: %w", ErrRequest, err)
	}
	if isUNC(p) {
		return fmt.Errorf("%w: helper path %q is a network path", ErrRequest, p)
	}
	rest, ok := splitAbsPrefix(p)
	if !ok {
		return fmt.Errorf("%w: helper path %q is not absolute", ErrRequest, p)
	}
	if err := checkPathElements(rest); err != nil {
		return fmt.Errorf("%w: helper path %q: %w", ErrRequest, p, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%w: helper %q does not exist", ErrRequest, p)
		}
		return fmt.Errorf("%w: helper %q: %w", ErrRequest, p, err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: helper %q is not a regular file", ErrRequest, p)
	}
	return nil
}

// checkPathChars rejects bytes that have no place in an install path and that a
// command line, a console, or the Win32 path parser would each read differently.
func checkPathChars(p string) error {
	for _, r := range p {
		switch {
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("contains a control character %q", r)
		case strings.ContainsRune(`"<>|*?`, r):
			return fmt.Errorf("contains %q", r)
		}
	}
	return nil
}

// splitAbsPrefix strips a POSIX root, a drive root, or a UNC prefix and reports
// whether the path had one. The remainder is what checkPathElements judges.
//
// Both separators count on every OS: this validates data that is written on one
// platform and may be read on another, so "\" is never an ordinary character.
func splitAbsPrefix(p string) (rest string, ok bool) {
	switch {
	case isUNC(p):
		return p[2:], true
	case len(p) >= 3 && isDriveLetter(rune(p[0])) && p[1] == ':' && isSep(rune(p[2])):
		return p[3:], true
	case isSep(rune(p[0])):
		return p[1:], true
	default:
		return "", false
	}
}

// checkPathElements rejects dot elements, empty elements, and a trailing
// separator. What remains is a path whose text cannot mean two things.
func checkPathElements(rest string) error {
	if rest == "" {
		return nil // a bare root: "/" or "C:\".
	}
	if isSep(rune(rest[len(rest)-1])) {
		return errors.New("ends in a path separator")
	}
	for _, e := range strings.FieldsFunc(rest, isSep) {
		if e == "." || e == ".." {
			return fmt.Errorf("contains a %q element", e)
		}
	}
	// FieldsFunc drops empty fields, so a doubled separator has to be found
	// directly. It is not merely redundant: "C:\\a\\\\b" and "\\\\a\\b" are read
	// differently by the Win32 path parser depending on where they appear.
	if strings.Contains(rest, `\\`) || strings.Contains(rest, "//") ||
		strings.Contains(rest, `\/`) || strings.Contains(rest, `/\`) {
		return errors.New("contains an empty path element")
	}
	return nil
}

func isUNC(p string) bool {
	return len(p) > 2 && isSep(rune(p[0])) && isSep(rune(p[1])) && !isSep(rune(p[2]))
}

func isSep(r rune) bool { return r == '/' || r == '\\' }

func isDriveLetter(r rune) bool { return (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') }

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
