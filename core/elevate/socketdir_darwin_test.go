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
	"path/filepath"
	"testing"
)

// Where a launchd daemon's socket can live on a stock macOS, judged by the
// same ancestor rule checkSocketDir applies at start, with euid 0 because the
// daemon runs as root. The socket's own directory is the daemon's to create
// (root, 0755) and is not part of this; what is tested is everything above it.
//
// The recommended parent must pass. The conventional /var/run is only
// recorded: it is expected to fail (root:daemon, group-writable), and the rule
// is not changed to suit it.
func TestDaemonSocketLocations(t *testing.T) {
	recommended := "/Library/Application Support"
	real, err := filepath.EvalSymlinks(recommended)
	if err != nil {
		t.Fatalf("%s: %v", recommended, err)
	}
	if err := checkSocketAncestors(real, 0); err != nil {
		t.Fatalf("the recommended socket parent fails the ancestor rule: %v", err)
	}

	for _, dir := range []string{"/var/run", "/var/db"} {
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			t.Logf("%s: %v", dir, err)
			continue
		}
		t.Logf("%s (%s) as a socket parent: %v", dir, real, checkSocketAncestors(real, 0))
	}
}
