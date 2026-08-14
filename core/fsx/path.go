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

package fsx

import (
	"path"
	"path/filepath"
	"strings"
)

// The helpers below are the one path vocabulary core uses. They work in slash
// space: an OS-native name is converted on the way in, and the OS filesystem
// converts back on the way out. Keeping one spelling inside core means a path
// compares equal to itself no matter which platform produced it — the version
// directories in `versions/` are compared by name, and "1.3.0" must not depend on
// whether the caller wrote a slash or a backslash.

// Slash returns name in slash-separated form.
func Slash(name string) string { return filepath.ToSlash(name) }

// Join joins path elements in slash space, cleaning the result.
func Join(elem ...string) string {
	parts := make([]string, 0, len(elem))
	for _, e := range elem {
		if e != "" {
			parts = append(parts, Slash(e))
		}
	}
	return path.Join(parts...)
}

// Dir returns the directory part of name. Unlike path.Dir it keeps a root of "/"
// and returns "." for a bare name, which is what MkdirAll and SyncDir expect.
func Dir(name string) string { return path.Dir(Slash(name)) }

// Base returns the final element of name.
func Base(name string) string { return path.Base(Slash(name)) }

// Clean returns the shortest equivalent spelling of name in slash space.
func Clean(name string) string { return path.Clean(Slash(name)) }

// IsAbs reports whether name is rooted.
//
// It judges Windows spellings on every host, not just on Windows: filepath.IsAbs
// on Linux calls `C:\Program Files\app` relative, and a check that changes its
// answer with the host is a check an attacker picks the host for. The rule here
// is the same everywhere — leading separator, drive root, or UNC root.
func IsAbs(name string) bool {
	s := Slash(name)
	switch {
	case strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`):
		return true // POSIX root, or a Windows root/UNC path.
	case len(s) >= 3 && isDriveLetter(s[0]) && s[1] == ':' && (s[2] == '/' || s[2] == '\\'):
		return true // C:/... or C:\...
	default:
		return filepath.IsAbs(name)
	}
}

func isDriveLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}
