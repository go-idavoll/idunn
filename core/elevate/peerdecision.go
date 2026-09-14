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
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// maxPeerRequirementLen bounds a code-signing requirement's source text. Real
// ones are a line or two; the bound only keeps configuration from becoming a
// workload.
const maxPeerRequirementLen = 4096

// admitPeer is the whole authorization decision about a connected peer, kept
// free of system calls so it is tested on every platform.
//
// Both halves must say yes. The uid comes first and is judged alone: a peer
// whose user may not ask is refused without its code ever being examined, so a
// correctly signed application run by the wrong user gets nowhere. The
// code-signing requirement, when one is configured, is an additional refusal
// and never a substitute — an unlisted uid is not rescued by a valid signature,
// and a listed uid is not enough when the requirement is not met.
//
// checkCode examines the peer's code against the requirement; nil with a
// requirement configured is a helper that cannot judge what it was told to,
// and is denied.
func admitPeer(uid uint32, allowed []uint32, requirement string, checkCode func() error) error {
	if !uidPermitted(uid, allowed) {
		return fmt.Errorf("%w: uid %d may not ask this helper", ErrDenied, uid)
	}
	if requirement == "" {
		return nil
	}
	if checkCode == nil {
		return fmt.Errorf("%w: a peer requirement is configured and nothing can check it", ErrDenied)
	}
	if err := checkCode(); err != nil {
		return fmt.Errorf("%w: the peer does not satisfy the code-signing requirement: %w", ErrDenied, err)
	}
	return nil
}

// uidPermitted reports whether this uid may ask at all.
//
// An empty list reads as "the superuser and nobody else". "Not configured" must
// never read as "everyone": a helper deployed without its allowlist filled in is
// a mistake, and the shape of that mistake should be a helper that answers no one
// rather than one that answers anyone.
func uidPermitted(uid uint32, allowed []uint32) bool {
	if len(allowed) == 0 {
		return uid == 0
	}
	return slices.Contains(allowed, uid)
}

// checkRequirementText refuses requirement source text that could not be what
// its author meant: empty after trimming, longer than maxPeerRequirementLen,
// invalid UTF-8, or carrying a NUL or another control character that C would
// truncate at or a reviewer would not see.
func checkRequirementText(req string) error {
	if strings.TrimSpace(req) == "" {
		return fmt.Errorf("%w: peer requirement is blank", ErrRequest)
	}
	if len(req) > maxPeerRequirementLen {
		return fmt.Errorf("%w: peer requirement is longer than %d bytes", ErrRequest, maxPeerRequirementLen)
	}
	if !utf8.ValidString(req) {
		return fmt.Errorf("%w: peer requirement is not valid UTF-8", ErrRequest)
	}
	for _, r := range req {
		if r < 0x20 && r != '\t' && r != '\n' || r == 0x7f {
			return fmt.Errorf("%w: peer requirement contains control character %U", ErrRequest, r)
		}
	}
	return nil
}
