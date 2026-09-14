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

//go:build e2e && !linux

package e2elocal

import (
	"runtime"
	"testing"
)

// TestServiceModeInstallsAndUpdatesThroughTheHelper is service_linux_test.go's
// scenario. It needs a helper run as root, an application run as another user
// and the Linux helper paths; here it only says why it did not run.
func TestServiceModeInstallsAndUpdatesThroughTheHelper(t *testing.T) {
	t.Skipf("the service-mode scenario runs on Linux as root only (this is %s)", runtime.GOOS)
}
