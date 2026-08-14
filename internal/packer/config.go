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
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/internal/safepath"
)

// MaxConfigLen bounds pack.yaml. It is far above any real release description
// and keeps a pathological document from being parsed at all.
const MaxConfigLen = 1 << 20 // 1 MiB

// nameRe bounds the app name. The descriptor only demands "not empty", but the
// name ends up in operator-facing output and in no path, so a conservative
// character set costs nothing here.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// channelRe bounds a channel name. A channel becomes both a target path element
// and a delegated role name with a glob path pattern, so anything that could act
// as a wildcard, a path separator, or a role-name collision is refused here —
// before it can widen what a delegated role is trusted to provide.
var channelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// platformRe bounds GOOS/GOARCH. Both appear in target paths.
var platformRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)

// leadingZeroRe matches a leading zero in one of the three numeric identifiers of
// a version core. It is applied to the core only: leading zeros are legal inside
// build metadata ("1.2.0+build.007").
var leadingZeroRe = regexp.MustCompile(`^0[0-9]|\.0[0-9]`)

// modeRe bounds an explicit file mode: three or four octal digits.
var modeRe = regexp.MustCompile(`^[0-7]{3,4}$`)

// Config is pack.yaml: the description of one release. It contains no secrets and
// no key references — role keys come from the environment or an HSM, always.
type Config struct {
	Name         string       `yaml:"name"`
	Version      string       `yaml:"version"`
	Channel      string       `yaml:"channel"`
	Requirements Requirements `yaml:"requirements"`

	// Rollout in [0,1] drives staged rollout on the client. Optional.
	Rollout float64 `yaml:"rollout"`

	// Targets lists one block per platform. The field is named after the TUF
	// concept it produces, matching docs/design.md §9.
	Targets []Platform `yaml:"targets"`

	// dir is the directory pack.yaml was read from. Relative src paths resolve
	// against it, so a publish does not depend on the working directory.
	dir string
}

// Requirements are the app-level floors written into the descriptor.
type Requirements struct {
	MinFromVersion   string `yaml:"min_from_version"`
	MinClientVersion string `yaml:"min_client_version"`
}

// Platform is one os/arch block and the payload files it installs.
type Platform struct {
	OS    string `yaml:"os"`
	Arch  string `yaml:"arch"`
	Files []File `yaml:"files"`
}

// File maps one built artifact to its install-relative destination.
type File struct {
	// Src is the file to publish, relative to pack.yaml unless absolute.
	Src string `yaml:"src"`

	// Dst is the install-relative destination. It is validated with the same
	// sanitizer the client runs on ingest, so a path that would be refused at
	// install time is refused at publish time instead of shipping.
	Dst string `yaml:"dst"`

	// Kind is one of exe, lib, data.
	Kind string `yaml:"kind"`

	// Mode is an optional explicit POSIX mode in octal ("0644"). Empty means
	// the default for Kind. It is a string because YAML's own integer rules
	// make a leading zero mean different things in different parsers, and a
	// permission bit is not a place for that ambiguity.
	Mode string `yaml:"mode"`
}

// LoadConfig reads and validates pack.yaml.
//
// Validation is strict and total: unknown keys, an unorderable version, a
// destination the client would refuse, or two files claiming one destination are
// all rejected here. The packer is the last place these can be caught cheaply —
// after publication the same defect fails on every client instead.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: reading %s: %w", ErrConfig, path, err)
	}
	if len(raw) > MaxConfigLen {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrConfig, path, MaxConfigLen)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// Unknown keys mean unknown semantics. A typo'd "requirement:" that is
	// silently dropped would publish a release without the floor the operator
	// believed they set.
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: parsing %s: %w", ErrConfig, path, err)
	}
	// A second document would make "the config" ambiguous.
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%w: %s contains more than one YAML document", ErrConfig, path)
	}

	cfg.dir = filepath.Dir(path)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if !nameRe.MatchString(c.Name) {
		return fmt.Errorf("%w: name %q must match %s", ErrConfig, c.Name, nameRe)
	}
	if !release.ValidVersion(c.Version) {
		return fmt.Errorf("%w: version %q is not SemVer", ErrConfig, c.Version)
	}
	// SemVer forbids leading zeros in the numeric identifiers, and here they
	// would do real damage: "01.2.0" and "1.3.0" are the same release line to a
	// human and two different delegated roles ("v01", "v1") to the repository.
	// The client's version regex is more permissive; the publisher does not have
	// to be.
	if leadingZeroRe.MatchString(versionCore(c.Version)) {
		return fmt.Errorf("%w: version %q has a leading zero; SemVer forbids it and it would split the release line", ErrConfig, c.Version)
	}
	if !channelRe.MatchString(c.Channel) {
		return fmt.Errorf("%w: channel %q must match %s", ErrConfig, c.Channel, channelRe)
	}
	// A channel named "v2" would collide with the delegated role that owns the
	// v2 release line, and one role cannot be trusted for two disjoint path
	// sets without giving each the other's reach.
	if majorRoleRe.MatchString(c.Channel) {
		return fmt.Errorf("%w: channel %q collides with a release-line role name", ErrConfig, c.Channel)
	}
	if c.Rollout < 0 || c.Rollout > 1 {
		return fmt.Errorf("%w: rollout %v outside [0,1]", ErrConfig, c.Rollout)
	}
	for _, r := range []struct{ name, val string }{
		{"requirements.min_from_version", c.Requirements.MinFromVersion},
		{"requirements.min_client_version", c.Requirements.MinClientVersion},
	} {
		if r.val != "" && !release.ValidVersion(r.val) {
			return fmt.Errorf("%w: %s %q is not SemVer", ErrConfig, r.name, r.val)
		}
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("%w: no targets", ErrConfig)
	}

	seenPlatform := make(map[string]bool, len(c.Targets))
	for i := range c.Targets {
		p := &c.Targets[i]
		if !platformRe.MatchString(p.OS) {
			return fmt.Errorf("%w: targets[%d].os %q must match %s", ErrConfig, i, p.OS, platformRe)
		}
		if !platformRe.MatchString(p.Arch) {
			return fmt.Errorf("%w: targets[%d].arch %q must match %s", ErrConfig, i, p.Arch, platformRe)
		}
		key := p.OS + "-" + p.Arch
		if seenPlatform[key] {
			return fmt.Errorf("%w: targets[%d]: duplicate platform %s", ErrConfig, i, key)
		}
		seenPlatform[key] = true

		if len(p.Files) == 0 {
			return fmt.Errorf("%w: targets[%d] (%s): no files", ErrConfig, i, key)
		}
		seenDst := make(map[string]bool, len(p.Files))
		for j := range p.Files {
			if err := validateFile(&p.Files[j], i, j, key); err != nil {
				return err
			}
			if seenDst[p.Files[j].Dst] {
				return fmt.Errorf("%w: targets[%d].files[%d]: duplicate dst %q", ErrConfig, i, j, p.Files[j].Dst)
			}
			seenDst[p.Files[j].Dst] = true
		}
	}
	return nil
}

func validateFile(f *File, pi, fi int, platform string) error {
	where := fmt.Sprintf("targets[%d].files[%d] (%s)", pi, fi, platform)
	if f.Src == "" {
		return fmt.Errorf("%w: %s: empty src", ErrConfig, where)
	}
	dst, err := safepath.Clean(f.Dst)
	if err != nil {
		return fmt.Errorf("%w: %s.dst: %w", ErrConfig, where, err)
	}
	if dst != f.Dst {
		return fmt.Errorf("%w: %s.dst %q is not in clean form (want %q)", ErrConfig, where, f.Dst, dst)
	}
	switch release.FileKind(f.Kind) {
	case release.KindExe, release.KindLib, release.KindData:
	default:
		return fmt.Errorf("%w: %s.kind %q is unknown", ErrConfig, where, f.Kind)
	}
	if f.Mode != "" && !modeRe.MatchString(f.Mode) {
		return fmt.Errorf("%w: %s.mode %q is not three or four octal digits", ErrConfig, where, f.Mode)
	}
	if _, err := f.mode(); err != nil {
		return fmt.Errorf("%w: %s.mode: %w", ErrConfig, where, err)
	}
	return nil
}

// defaultModes are the permissions a kind gets when pack.yaml does not say. An
// executable is the only thing that needs the exec bit; nothing is ever group- or
// world-writable, and setuid/setgid cannot be expressed at all.
var defaultModes = map[release.FileKind]uint32{
	release.KindExe:  0o755,
	release.KindLib:  0o644,
	release.KindData: 0o644,
}

// mode returns the POSIX mode this file installs with.
func (f *File) mode() (uint32, error) {
	if f.Mode == "" {
		return defaultModes[release.FileKind(f.Kind)], nil
	}
	m, err := strconv.ParseUint(f.Mode, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("%q is not octal", f.Mode)
	}
	// The client refuses anything outside 0777 on ingest, because setuid,
	// setgid and type bits would let a descriptor request a privileged file.
	// Refusing it here means that descriptor is never published.
	if m&^uint64(0o777) != 0 {
		return 0, fmt.Errorf("%#o has bits outside 0777", m)
	}
	return uint32(m), nil
}

// versionCore is the "major.minor.patch" part of a SemVer string, without any
// prerelease or build metadata.
func versionCore(version string) string {
	core, _, _ := strings.Cut(version, "-")
	core, _, _ = strings.Cut(core, "+")
	return core
}

// srcPath resolves a file's src against the directory pack.yaml was read from.
func (c *Config) srcPath(f *File) string {
	if filepath.IsAbs(f.Src) {
		return f.Src
	}
	return filepath.Join(c.dir, filepath.FromSlash(f.Src))
}
