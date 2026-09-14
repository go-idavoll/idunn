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

//go:build unix

package elevate_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-idavoll/idunn/core/elevate"
)

// A Windows caller allow-list on POSIX is refused, not ignored: whoever wrote it
// believed it restricted who may ask, and a helper that started anyway would
// answer callers nobody chose. It is refused before a socket exists.
func TestAllowedSIDsAreRefusedOnPOSIX(t *testing.T) {
	endpoint := filepath.Join(socketDir(t), "helper.sock")
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      &recorder{},
		AllowedRoots: []string{"/usr/idunn-test-acme"},
		AllowedSIDs:  []string{"S-1-5-18"},
	})
	if !errors.Is(err, elevate.ErrRequest) || !strings.Contains(err.Error(), "AllowedSIDs") {
		t.Fatalf("err = %v, want a refusal naming AllowedSIDs", err)
	}
	if _, statErr := os.Lstat(endpoint); statErr == nil {
		t.Error("a refused helper still created its socket")
	}
}
