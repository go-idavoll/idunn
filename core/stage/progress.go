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

package stage

import "io"

// Source names where the bytes of one staged file came from.
//
// It is reported rather than inferred because the three differ by orders of
// magnitude in what they cost, and a UI that says "downloading" while a
// gigabyte is being copied off the local disk is telling the user the wrong
// thing about how long this will take.
type Source string

// The ways a staged file is produced, cheapest first (docs/design.md §6.4).
const (
	// SourceReuse: an installed version already held exactly these signed bytes.
	SourceReuse Source = "reuse"
	// SourcePatch: reconstructed from a local base plus delta patches.
	SourcePatch Source = "patch"
	// SourceDownload: fetched whole through the trust layer.
	SourceDownload Source = "download"
)

// Report is one progress observation from staging.
//
// Bytes counts what has been written into the staging tree, which is the only
// number that is true for all three sources: a reused file moves bytes without
// touching the network, and a patched one writes far more than it fetched.
// A caller that wants "downloaded" rather than "produced" has Source to filter
// on.
//
// Total is the sum of the signed lengths of every file in the release, so it is
// known before the first byte moves and never revised.
type Report struct {
	// Dst is the install-relative destination being staged, in the clean form
	// the descriptor carries. It is a path, so it belongs in an Observer and
	// never in a Reporter outcome (§14.5).
	Dst string

	// Index is the 1-based position of this file, Files the count of them.
	Index int
	Files int

	// Source is where this file's bytes are coming from.
	Source Source

	// FileDone and FileSize are this file's progress and its signed length.
	FileDone int64
	FileSize int64

	// Done and Total are the release's progress and the sum of signed lengths.
	Done  int64
	Total int64
}

// Progress receives Reports while Stage runs.
//
// It is called synchronously from the goroutine running Stage, between writes,
// so an implementation that blocks stalls the update. A UI sidecar records the
// latest Report and repaints on its own schedule rather than painting here.
//
// A nil Progress is the headless default and costs nothing.
type Progress func(Report)

// progressInterval is how much has to be written before the next Report. It
// bounds the callback rate by the one quantity that matters — bytes — so a
// release of ten thousand small files does not produce ten thousand repaints,
// and a single multi-gigabyte payload still moves the bar.
const progressInterval = 1 << 20

// counter is the io.Writer that turns a copy into Reports. It wraps the writer
// the staged bytes are going to, so what it counts is what landed, not what was
// offered.
//
// One counter lives for the whole of one file, across the attempts staging makes
// at producing it, because that is the only scope in which "how far along is
// this file" has a single answer.
type counter struct {
	w      io.Writer
	report Report
	on     Progress
	next   int64 // FileDone at which the next Report is due
}

// newCounter starts counting one file. r carries everything already known about
// it — its destination, its position in the release, its signed length, and the
// release total so far.
//
// The per-file counter is zeroed rather than taken from r: r is the report the
// previous file ended on, and carrying its FileDone into this one would make the
// first begin rewind the release by the length of a file that is already staged.
func newCounter(on Progress, r Report) *counter {
	r.FileDone = 0
	return &counter{w: io.Discard, report: r, on: on}
}

// begin points the counter at the scratch writer of one attempt and says which
// source that attempt is taking its bytes from.
//
// It rewinds this file's contribution first. A source that turned out not to
// verify had its scratch file discarded, and the bytes it wrote were never
// staged; leaving them counted would let a release report more progress than it
// has — and after two failed candidates, more than its total. Announcing the
// rewind before the retry is also what a progress bar that may not run backwards
// needs: it is told the file restarts, rather than watching the number drop.
func (c *counter) begin(w io.Writer, source Source) {
	c.w = w
	c.report.Done -= c.report.FileDone
	c.report.FileDone = 0
	c.report.Source = source
	c.next = progressInterval
	c.emit()
}

// done is the Report that closes one file: what the release stands at once this
// file has been promoted into the staging tree.
func (c *counter) done() Report {
	c.emit()
	return c.report
}

func (c *counter) emit() {
	if c.on != nil {
		c.on(c.report)
	}
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.report.FileDone += int64(n)
	c.report.Done += int64(n)
	if c.report.FileDone >= c.next {
		c.next = c.report.FileDone + progressInterval
		c.emit()
	}
	return n, err
}
