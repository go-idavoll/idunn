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

package updater_test

import (
	"testing"

	"github.com/go-idavoll/idunn/core/hook"
)

// staging is where all the time of an update goes, and until it reported bytes a
// UI had to invent a number or show a spinner for the whole operation (IDN-19).
// An Observer now sees the release advance, file by file and byte by byte.
func TestObserverSeesByteProgress(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.1.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	var staging []hook.Event
	for _, e := range f.hooks.events {
		if e.BytesTotal != 0 || e.File != "" {
			staging = append(staging, e)
		}
	}
	if len(staging) == 0 {
		t.Fatal("no event carried byte progress")
	}

	want := int64(len("binary 1.1.0") + len("library 1.1.0"))
	for i, e := range staging {
		if e.Phase != hook.PhaseDownload {
			t.Errorf("event %d: phase = %q, want %q", i, e.Phase, hook.PhaseDownload)
		}
		if e.BytesTotal != want {
			t.Errorf("event %d: BytesTotal = %d, want %d", i, e.BytesTotal, want)
		}
		if e.BytesDone < 0 || e.BytesDone > e.BytesTotal {
			t.Errorf("event %d: BytesDone = %d outside [0, %d]", i, e.BytesDone, e.BytesTotal)
		}
		if e.Progress < 0 || e.Progress > 1 {
			t.Errorf("event %d: Progress = %v is not a fraction", i, e.Progress)
		}
		if e.FileCount != 2 {
			t.Errorf("event %d: FileCount = %d, want 2", i, e.FileCount)
		}
		if e.FileIndex < 1 || e.FileIndex > e.FileCount {
			t.Errorf("event %d: FileIndex = %d outside [1, %d]", i, e.FileIndex, e.FileCount)
		}
		if e.Source == "" {
			t.Errorf("event %d: no Source; a UI cannot tell the network from the local disk", i)
		}
		if e.Message == "" {
			t.Errorf("event %d: no message", i)
		}
	}

	last := staging[len(staging)-1]
	if last.BytesDone != want || last.Progress != 1 {
		t.Errorf("the release finished at %d of %d bytes (progress %v)", last.BytesDone, want, last.Progress)
	}
	if last.File != "lib/plugin.so" {
		t.Errorf("the last file reported is %q, want lib/plugin.so", last.File)
	}
}

// A release whose files are all reused says so, so a UI does not claim to be
// downloading while it copies from the version already on disk.
func TestObserverIsToldWhenNothingIsDownloaded(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.1.0")
	// The new release is byte-identical to the installed one, so every file is
	// found on disk and nothing crosses the wire.
	f.trust.targets["targets/app"] = []byte("1.0.0")
	f.trust.descriptor.Files = f.trust.descriptor.Files[:1]

	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	var sources []hook.Source
	for _, e := range f.hooks.events {
		if e.Source != "" && (len(sources) == 0 || sources[len(sources)-1] != e.Source) {
			sources = append(sources, e.Source)
		}
	}
	if len(sources) != 1 || sources[0] != hook.SourceReuse {
		t.Errorf("sources = %v, want only %v", sources, hook.SourceReuse)
	}
}

// Everything outside staging keeps the indeterminate progress it always had: a
// quiesce or a migration has no byte count, and inventing one would be worse
// than admitting there is none.
func TestNonStagingEventsCarryNoBytes(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.1.0")
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i, e := range f.hooks.events {
		if e.File != "" || e.BytesTotal != 0 {
			continue
		}
		if e.Progress != -1 {
			t.Errorf("event %d (%s): Progress = %v, want -1 for an event with no byte count", i, e.Phase, e.Progress)
		}
		if e.BytesDone != 0 || e.FileIndex != 0 || e.FileCount != 0 || e.Source != "" {
			t.Errorf("event %d (%s): carries staging fields outside staging: %+v", i, e.Phase, e)
		}
	}
}

// A headless updater registers no Observer, and then nothing is called at all —
// the progress callback is not even installed, so streaming costs nothing extra.
func TestHeadlessUpdateReportsNothing(t *testing.T) {
	f := newFixture(t, "1.0.0", "1.1.0")
	f.opts.Observe = nil
	if err := f.run(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(f.hooks.events) != 0 {
		t.Errorf("%d events although no Observer was registered", len(f.hooks.events))
	}
}
