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

package release

import (
	"fmt"
	"strconv"
	"strings"
)

// Version ordering is security-relevant, not cosmetic. It answers "is this an
// upgrade?" — the question the downgrade protection in Policy.AllowDowngrade and
// Requirements.MinFromVersion is built on — and "which version directories may
// the GC delete?". A wrong answer in the first case installs an old, vulnerable
// build; in the second it deletes the rollback target.
//
// This is SemVer 2.0.0 precedence, no more: build metadata is ignored, as the
// specification requires, and anything that is not a version this project
// accepts is refused rather than ordered by some fallback rule. TUF's own
// rollback protection sits underneath all of this; the ordering here is the
// app-level floor on top of it, never a replacement.

// Compare orders two versions by SemVer precedence. It returns -1 if a sorts
// before b, +1 if after, and 0 if they have equal precedence.
//
// Comparing anything that is not an accepted version is an error: a version we
// cannot order is a version we cannot make a trust decision about, so callers
// must not be able to get a silent answer.
func Compare(a, b string) (int, error) {
	if !ValidVersion(a) {
		return 0, fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, a)
	}
	if !ValidVersion(b) {
		return 0, fmt.Errorf("%w: version %q is not SemVer", ErrInvalid, b)
	}
	return compareParsed(parseVersion(a), parseVersion(b)), nil
}

// Newer reports whether a has strictly higher precedence than b.
func Newer(a, b string) (bool, error) {
	c, err := Compare(a, b)
	if err != nil {
		return false, err
	}
	return c > 0, nil
}

// parsedVersion is a version split into the parts precedence is decided on.
// Build metadata is dropped here: SemVer says it does not participate.
type parsedVersion struct {
	nums [3]uint64
	pre  []string
}

func parseVersion(v string) parsedVersion {
	// ValidVersion has already accepted the shape, so the splits below cannot
	// fail to produce the three numeric fields.
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	var pre []string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	var p parsedVersion
	for i, field := range strings.SplitN(v, ".", 3) {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			// Only reachable for a numeric field beyond uint64. Treating it as
			// the largest representable value keeps the ordering total instead
			// of silently collapsing it to zero, and ValidVersion is what keeps
			// such a version out in the first place.
			n = ^uint64(0)
		}
		p.nums[i] = n
	}
	p.pre = pre
	return p
}

func compareParsed(a, b parsedVersion) int {
	for i := range a.nums {
		if a.nums[i] != b.nums[i] {
			return sign(a.nums[i], b.nums[i])
		}
	}

	// A release outranks any pre-release of the same numbers: 1.3.0 is newer
	// than 1.3.0-rc.1.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}

	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		if c := comparePreField(a.pre[i], b.pre[i]); c != 0 {
			return c
		}
	}
	// All shared fields equal: the longer identifier list has higher precedence.
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	default:
		return 0
	}
}

// comparePreField orders one pre-release identifier. Numeric identifiers compare
// numerically and always rank below alphanumeric ones (SemVer 2.0.0 §11.4).
func comparePreField(a, b string) int {
	an, aNum := numericIdent(a)
	bn, bNum := numericIdent(b)
	switch {
	case aNum && bNum:
		if an != bn {
			return sign(an, bn)
		}
		return 0
	case aNum:
		return -1
	case bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// numericIdent reports whether s is a numeric identifier and returns its value.
// A leading zero makes it alphanumeric, because SemVer forbids numeric
// identifiers with leading zeros and we must not read "01" as 1.
func numericIdent(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func sign(a, b uint64) int {
	if a < b {
		return -1
	}
	return 1
}
