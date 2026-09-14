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

package elevate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/go-idavoll/idunn/core/elevate"
)

type nopApplier struct{}

func (nopApplier) Apply(context.Context, elevate.Request) error { return nil }

// Until the named-pipe transport exists, neither side of the service may pretend
// to work here: an updater configured for it must fail at construction, and a
// helper must not start.
func TestTheServiceFailsClosedOnWindows(t *testing.T) {
	t.Parallel()

	if el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: `\.\pipe\idunn`}); !errors.Is(err, elevate.ErrNotImplemented) || el != nil {
		t.Fatalf("NewService = %v, %v; want ErrNotImplemented", el, err)
	}
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     `\.\pipe\idunn`,
		Applier:      nopApplier{},
		AllowedRoots: []string{`C:\Program Files\idunn-test-does-not-exist`},
	})
	if !errors.Is(err, elevate.ErrNotImplemented) {
		t.Fatalf("NewHelper = %v, want ErrNotImplemented", err)
	}
}
