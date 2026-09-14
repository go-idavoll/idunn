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

package elevate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/release"
)

type countingApplier struct {
	calls atomic.Int32
	delay time.Duration
}

func (c *countingApplier) Apply(context.Context, Request) error {
	c.calls.Add(1)
	time.Sleep(c.delay)
	return nil
}

func startHelper(t *testing.T, a Applier, checkRoot func(string) error, adjust ...func(*Helper)) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "idn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	endpoint := filepath.Join(dir, "helper.sock")

	h, err := newHelper(HelperOptions{
		Endpoint:     endpoint,
		Applier:      a,
		AllowedRoots: []string{"/usr/idunn-test-acme"},
		AllowedUIDs:  []uint32{uint32(os.Getuid())}, //nolint:gosec // a uid fits.
		MinInterval:  time.Nanosecond,
	}, checkRoot)
	if err != nil {
		t.Fatalf("newHelper: %v", err)
	}
	for _, f := range adjust {
		f(h)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = h.Close()
		<-done
	})
	return endpoint
}

func stableDescriptor(version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme",
		Version:       version,
		Channel:       "stable",
		OS:            "linux",
		Arch:          "amd64",
	}
}

// The root is judged again for every request, not only at start: its
// directories and permissions can change while the helper runs, and a root that
// became writable by someone else must stop being written as root at once.
func TestARootThatBecameUnsafeAfterStartIsDenied(t *testing.T) {
	var unsafe atomic.Bool
	check := func(string) error {
		if unsafe.Load() {
			return ErrUnsafeRoot
		}
		return nil
	}
	a := &countingApplier{}
	endpoint := startHelper(t, a, check)
	el, err := NewService(ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	if err := el.Apply(t.Context(), "/usr/idunn-test-acme", stableDescriptor("1.3.0")); err != nil {
		t.Fatalf("the control apply: %v", err)
	}
	unsafe.Store(true)
	err = el.Apply(t.Context(), "/usr/idunn-test-acme", stableDescriptor("1.4.0"))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("VULNERABILITY: the applier ran %d times, want only the control", n)
	}
}

// The exchange deadline bounds reading a request and writing an answer, never
// the apply between them. A release that takes longer to install than the
// deadline must not be reported as failed while it goes on to commit.
func TestAnApplyLongerThanTheExchangeTimeoutStillAnswers(t *testing.T) {
	saved := exchangeTimeout
	exchangeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { exchangeTimeout = saved })

	a := &countingApplier{delay: time.Second}
	endpoint := startHelper(t, a, func(string) error { return nil })
	el, err := NewService(ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	if err := el.Apply(t.Context(), "/usr/idunn-test-acme", stableDescriptor("1.3.0")); err != nil {
		t.Fatalf("Apply = %v, want the answer after the long apply", err)
	}
}
