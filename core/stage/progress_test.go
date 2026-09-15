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

package stage_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/stage"
	"github.com/go-idavoll/idunn/internal/layout"
)

// recorder collects every Report a Stage produced, which is what a UI would see.
type recorder struct{ reports []stage.Report }

func (r *recorder) on(rep stage.Report) { r.reports = append(r.reports, rep) }

// last returns the final Report for each destination, in the order the
// destinations were first reported.
func (r *recorder) last() []stage.Report {
	var order []string
	final := map[string]stage.Report{}
	for _, rep := range r.reports {
		if _, seen := final[rep.Dst]; !seen {
			order = append(order, rep.Dst)
		}
		final[rep.Dst] = rep
	}
	out := make([]stage.Report, 0, len(order))
	for _, dst := range order {
		out = append(out, final[dst])
	}
	return out
}

// A release reports its size before it starts and reaches exactly that size when
// it is done. The total comes from the signed lengths, so it is known up front
// and is never revised — a bar built on it cannot jump when a file turns out to
// be reused rather than downloaded.
func TestStageReportsByteProgress(t *testing.T) {
	m := newRoot(t)
	files := map[string][]byte{
		"targets/app":       bytes.Repeat([]byte("a"), 3000),
		"targets/plugin.so": bytes.Repeat([]byte("p"), 5000),
	}
	tr := newTargets(files)
	var rec recorder
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Progress: rec.on}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "bin/app", release.KindExe, 0o755),
		ref("targets/plugin.so", "lib/plugin.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if len(rec.reports) == 0 {
		t.Fatal("staging reported nothing")
	}
	total := int64(8000)
	for i, rep := range rec.reports {
		if rep.Total != total {
			t.Fatalf("report %d: Total = %d, want %d — the total must not be revised", i, rep.Total, total)
		}
		if rep.Files != 2 {
			t.Errorf("report %d: Files = %d, want 2", i, rep.Files)
		}
		if rep.Done < 0 || rep.Done > rep.Total {
			t.Errorf("report %d: Done = %d is outside [0, %d]", i, rep.Done, rep.Total)
		}
		if rep.FileDone > rep.FileSize {
			t.Errorf("report %d: FileDone = %d is past FileSize %d", i, rep.FileDone, rep.FileSize)
		}
	}

	final := rec.last()
	if len(final) != 2 {
		t.Fatalf("%d destinations reported, want 2", len(final))
	}
	for i, want := range []struct {
		dst   string
		size  int64
		index int
	}{{"bin/app", 3000, 1}, {"lib/plugin.so", 5000, 2}} {
		if final[i].Dst != want.dst || final[i].FileSize != want.size || final[i].Index != want.index {
			t.Errorf("file %d: %+v, want %s of %d bytes at index %d",
				i, final[i], want.dst, want.size, want.index)
		}
		if final[i].FileDone != want.size {
			t.Errorf("%s: FileDone = %d, want the whole %d", want.dst, final[i].FileDone, want.size)
		}
		if final[i].Source != stage.SourceDownload {
			t.Errorf("%s: Source = %q, want %q", want.dst, final[i].Source, stage.SourceDownload)
		}
	}
	if got := final[len(final)-1].Done; got != total {
		t.Errorf("the release finished at %d of %d bytes", got, total)
	}
}

// Where the bytes come from is reported, not inferred. A UI that says
// "downloading" while a gigabyte is copied off the local disk is telling the
// user the wrong thing about how long this will take.
func TestStageReportsWhereTheBytesCameFrom(t *testing.T) {
	m := newRoot(t)
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the runtime"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}

	tr := offline(t, map[string][]byte{"targets/libcef.so": []byte("the runtime")})
	var rec recorder
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Progress: rec.on}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	final := rec.last()
	if len(final) != 1 || final[0].Source != stage.SourceReuse {
		t.Fatalf("reports = %+v, want one reuse", final)
	}
}

// A reuse candidate of the right length whose content is wrong is written into a
// scratch file before it is refused — the verification and the copy are one
// pass, which is what makes "the bytes that were checked are the bytes that
// landed" true. Its contribution must then be taken back: a release whose
// progress counted a discarded attempt would report more than it has, and after
// two of them, more than its total.
func TestStageRewindsProgressWhenACandidateIsRefused(t *testing.T) {
	m := newRoot(t)
	// Same length, different content: the cheap size filter lets it through, so
	// the copy really does happen and really is discarded.
	install(t, m, "1.2.0", map[string]string{"lib/libcef.so": "the IMPOSTOR"})
	if err := layout.SetPointer(m, root, "1.2.0"); err != nil {
		t.Fatalf("SetPointer: %v", err)
	}
	signed := []byte("the runtime!")
	if len("the IMPOSTOR") != len(signed) {
		t.Fatal("the fixture must use two payloads of the same length")
	}

	tr := newTargets(map[string][]byte{"targets/libcef.so": signed})
	var rec recorder
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Progress: rec.on}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/libcef.so", "lib/libcef.so", release.KindLib, 0o644),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}

	if got := read(t, m, "/opt/app/versions/1.3.0/lib/libcef.so"); got != string(signed) {
		t.Fatalf("staged %q, want the signed bytes — the impostor was installed", got)
	}
	for i, rep := range rec.reports {
		if rep.Done > rep.Total {
			t.Fatalf("report %d: Done = %d is past the total %d; a discarded attempt was left counted",
				i, rep.Done, rep.Total)
		}
	}
	final := rec.last()
	if len(final) != 1 {
		t.Fatalf("%d destinations reported, want 1", len(final))
	}
	if final[0].Source != stage.SourceDownload {
		t.Errorf("Source = %q, want the fallback %q", final[0].Source, stage.SourceDownload)
	}
	if final[0].Done != final[0].Total {
		t.Errorf("finished at %d of %d bytes", final[0].Done, final[0].Total)
	}

	// The restart has to be announced before the retry runs, so a UI is told the
	// file is starting over — and told which source is starting — rather than
	// watching the number move under it.
	var sources []stage.Source
	for _, rep := range rec.reports {
		if rep.FileDone != 0 {
			continue
		}
		if len(sources) == 0 || sources[len(sources)-1] != rep.Source {
			sources = append(sources, rep.Source)
		}
	}
	want := []stage.Source{stage.SourceReuse, stage.SourceDownload}
	if len(sources) != len(want) || sources[0] != want[0] || sources[1] != want[1] {
		t.Errorf("the file was announced as %v, want %v — the restart was not reported", sources, want)
	}
}

// Staging without an observer is the headless default and must behave exactly
// the same. A nil Progress is never called, so the streaming path costs nothing
// extra when nobody is watching.
func TestStageWithoutAProgressCallback(t *testing.T) {
	m := newRoot(t)
	tr := newTargets(map[string][]byte{"targets/app": []byte("the binary")})
	s := &stage.Stager{FS: m, Trust: tr, Root: root}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "bin/app", release.KindExe, 0o755),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if got := read(t, m, "/opt/app/versions/1.3.0/bin/app"); got != "the binary" {
		t.Errorf("staged %q", got)
	}
}

// A payload far larger than any buffer has to arrive whole and in order. It is
// the cheapest check that the windowed copy does not drop or duplicate a chunk
// at a boundary — the failure mode a streaming rewrite actually has.
func TestStageStreamsAPayloadLargerThanTheCopyWindow(t *testing.T) {
	m := newRoot(t)
	// Past the progress interval as well as the copy window, so the intermediate
	// reports are produced too rather than only the ones bracketing the file.
	payload := make([]byte, 5*fsx.CopyBufferSize+1237)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	tr := newTargets(map[string][]byte{"targets/app": payload})
	var rec recorder
	s := &stage.Stager{FS: m, Trust: tr, Root: root, Progress: rec.on}

	if _, err := s.Stage(context.Background(), descriptor(
		ref("targets/app", "bin/app", release.KindExe, 0o755),
	), nil); err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if len(rec.reports) < 3 {
		t.Errorf("%d reports for a payload of %d bytes; a long file must move the bar while it is written",
			len(rec.reports), len(payload))
	}
	got, err := fsx.ReadFile(m, "/opt/app/versions/1.3.0/bin/app", int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("the staged payload differs from the signed one (%d of %d bytes)", len(got), len(payload))
	}
}
