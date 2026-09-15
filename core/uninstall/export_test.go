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

package uninstall

import (
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
)

// SetCheckRoot replaces the platform's root check for one test. The in-memory
// filesystem has no owners and no probe to run.
func SetCheckRoot(t *testing.T, fn func(root string) error) {
	t.Helper()
	old := checkRoot
	checkRoot = fn
	t.Cleanup(func() { checkRoot = old })
}

// SetRemoveSelf replaces the platform's launcher removal for one test.
func SetRemoveSelf(t *testing.T, fn func(f fsx.FS, self, root string, removeRoot bool) (bool, error)) {
	t.Helper()
	old := removeSelf
	removeSelf = fn
	t.Cleanup(func() { removeSelf = old })
}

// CheckRootOS is the platform's root check.
var CheckRootOS = checkRootOS

// Privileged reports whether this process runs with administrator rights.
var Privileged = privileged
