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

//go:build windows

package uninstall_test

import (
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/uninstall"
)

// The copy's argument grammar is closed: every handle and an absolute launcher
// path, nothing else. The launcher being removed is tested end to end, as real
// processes (test/e2e/local TestUninstall).
func TestFinishRefusesAnIncompleteCommandLine(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--process", "1", "--copy", "2"},
		{"--process", "1", "--launcher", `C:\app\launcher.exe`},
		{"--copy", "2", "--launcher", `C:\app\launcher.exe`},
		{"--process", "1", "--copy", "2", "--launcher", `launcher.exe`},
		{"--process", "1", "--copy", "2", "--launcher", `C:\app\launcher.exe`, "extra"},
		{"--process", "1", "--copy", "2", "--launcher", `C:\app\launcher.exe`, "--unknown"},
	} {
		if err := uninstall.Finish(args); !errors.Is(err, uninstall.ErrUninstall) {
			t.Errorf("Finish(%q) = %v, want a refusal", args, err)
		}
	}
}
