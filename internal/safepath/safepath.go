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

// Package safepath validates untrusted, install-relative destination paths.
//
// It is the single implementation behind stage.SanitizeDst and the descriptor
// ingest check in core/release, so a path can never be accepted by one and
// rejected by the other. Everything here is pure and total: it takes arbitrary
// attacker-controlled bytes and must never panic (it is reached from
// FuzzDstSanitize and FuzzDescriptor).
//
// It answers exactly one question — "is this a clean, relative path that cannot
// leave the install root by its own text?". Escapes that need the filesystem to
// judge (an existing symlink pointing outside the root) are checked at apply time
// in core/stage, not here.
package safepath

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// MaxLen bounds a destination path. It is far above any legitimate install layout
// and below every platform limit, so an absurd path is rejected before it reaches
// the filesystem.
const MaxLen = 1024

// ErrUnsafe is the class of every rejection here. Callers classify errors by this
// sentinel rather than by string matching (the Reporter taxonomy depends on it).
var ErrUnsafe = errors.New("unsafe path")

// reservedWindows are device names Windows resolves specially in any directory.
// A file called "NUL" or "COM1.txt" is not a file, so we refuse to install one
// regardless of the host we are currently running on: descriptors are
// cross-platform data and must be judged identically everywhere.
var reservedWindows = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// Clean validates dst and returns its cleaned, slash-separated form.
//
// Accepted: a non-empty, relative, slash-separated path whose cleaned form has no
// "." or ".." element. Rejected: absolute paths, drive-relative and UNC paths,
// backslashes, NUL bytes, traversal, and Windows device names.
func Clean(dst string) (string, error) {
	if dst == "" {
		return "", fmt.Errorf("%w: empty", ErrUnsafe)
	}
	if len(dst) > MaxLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrUnsafe, MaxLen)
	}
	if strings.ContainsRune(dst, 0) {
		return "", fmt.Errorf("%w: contains NUL byte", ErrUnsafe)
	}
	// Backslash is a separator on Windows and a legal filename character on
	// POSIX. Rather than resolve that ambiguity per host, we refuse it: a
	// descriptor must mean the same thing on every platform.
	if strings.ContainsRune(dst, '\\') {
		return "", fmt.Errorf("%w: contains a backslash", ErrUnsafe)
	}
	if strings.HasPrefix(dst, "/") {
		return "", fmt.Errorf("%w: absolute", ErrUnsafe)
	}
	// "C:foo" is drive-relative on Windows and would escape the install root.
	if strings.ContainsRune(dst, ':') {
		return "", fmt.Errorf("%w: contains a colon", ErrUnsafe)
	}

	cleaned := path.Clean(dst)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: escapes the install root", ErrUnsafe)
	}
	if path.IsAbs(cleaned) {
		return "", fmt.Errorf("%w: absolute after cleaning", ErrUnsafe)
	}

	for _, elem := range strings.Split(cleaned, "/") {
		if elem == "" {
			return "", fmt.Errorf("%w: empty path element", ErrUnsafe)
		}
		if elem == "." || elem == ".." {
			return "", fmt.Errorf("%w: traversal element %q", ErrUnsafe, elem)
		}
		// Trailing dots and spaces are silently stripped by Windows, so
		// "evil.exe " and "evil.exe" would collide after installation.
		if strings.HasSuffix(elem, " ") || strings.HasSuffix(elem, ".") {
			return "", fmt.Errorf("%w: element %q ends in a space or dot", ErrUnsafe, elem)
		}
		base, _, _ := strings.Cut(elem, ".")
		if reservedWindows[strings.ToUpper(base)] {
			return "", fmt.Errorf("%w: reserved device name %q", ErrUnsafe, elem)
		}
	}

	return cleaned, nil
}

// CleanTarget validates a TUF target path from a descriptor or channel pointer.
// Target paths are repository-relative and follow the same rules as destinations:
// nothing in idunn may turn one into a filesystem path that leaves its root.
func CleanTarget(target string) (string, error) {
	return Clean(target)
}
