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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests drive the pkexec elevator's decisions against a fake system: a
// filesystem of owners and modes, and a start function that records what it
// was asked to run. They run on every OS; interactive_linux_test.go runs the
// real launcher against a stand-in pkexec on Linux, and IDUNN_TEST_PKEXEC=1
// runs the real prompt.

// fakeSys is a filesystem of owners and modes plus a recording launcher.
type fakeSys struct {
	mu       sync.Mutex
	files    map[string]posixStat
	links    map[string]string // resolved targets; absent means the path itself
	lstats   []string
	started  [][]string
	dirs     []string
	code     int
	waitErr  error
	startErr error
	release  chan struct{} // if non-nil, the process runs until it is closed
	reaped   chan struct{} // closed once wait has returned
}

const (
	rootDir  = fs.ModeDir | 0o755
	rootExe  = fs.FileMode(0o755)
	suidExe  = fs.ModeSetuid | 0o755
	userUID  = 1000
	staffGID = 50
)

// stockSystem is a machine with a root-owned setuid /usr/bin/pkexec and a
// root-owned helper at /opt/acme/bin/acme.
func stockSystem() *fakeSys {
	return &fakeSys{
		files: map[string]posixStat{
			"/":                  {mode: rootDir},
			"/usr":               {mode: rootDir},
			"/usr/bin":           {mode: rootDir},
			"/usr/bin/pkexec":    {mode: suidExe},
			"/opt":               {mode: rootDir},
			"/opt/acme":          {mode: rootDir},
			"/opt/acme/bin":      {mode: rootDir},
			"/opt/acme/bin/acme": {mode: rootExe},
		},
		links: map[string]string{},
	}
}

func (s *fakeSys) system() pkexecSystem {
	return pkexecSystem{lstat: s.lstat, resolve: s.resolve, start: s.start}
}

func (s *fakeSys) lstat(name string) (posixStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lstats = append(s.lstats, name)
	if _, ok := s.links[name]; ok {
		return posixStat{mode: fs.ModeSymlink | 0o777}, nil
	}
	st, ok := s.files[name]
	if !ok {
		return posixStat{}, fmt.Errorf("lstat %s: %w", name, fs.ErrNotExist)
	}
	return st, nil
}

func (s *fakeSys) resolve(name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 8 {
		target, ok := s.links[name]
		if !ok {
			break
		}
		name = target
	}
	if _, ok := s.files[name]; !ok {
		return "", fmt.Errorf("resolve %s: %w", name, fs.ErrNotExist)
	}
	return name, nil
}

func (s *fakeSys) start(argv []string, dir string) (func() (int, error), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.startErr != nil {
		return nil, s.startErr
	}
	s.started = append(s.started, slices.Clone(argv))
	s.dirs = append(s.dirs, dir)
	return func() (int, error) {
		if s.release != nil {
			<-s.release
		}
		if s.reaped != nil {
			defer close(s.reaped)
		}
		return s.code, s.waitErr
	}, nil
}

func (s *fakeSys) startCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.started)
}

func newStock(t *testing.T, s *fakeSys) *pkexecElevator {
	t.Helper()
	e, err := newPkexec("/opt/acme/bin/acme", s.system())
	if err != nil {
		t.Fatalf("newPkexec on a stock system = %v", err)
	}
	return e
}

func TestNewPkexecAcceptsAStockSystem(t *testing.T) {
	t.Parallel()

	e := newStock(t, stockSystem())
	if e.pkexec != pkexecUsrBin || e.helper != "/opt/acme/bin/acme" {
		t.Fatalf("pkexec, helper = %q, %q", e.pkexec, e.helper)
	}
}

// pkexec is never looked up through PATH, the working directory, or anywhere
// but the two fixed system paths. Without one there, elevation is not
// available — it is not found somewhere else.
func TestFindPkexecLooksOnlyAtFixedPaths(t *testing.T) {
	t.Setenv("PATH", "/home/mallory/bin")

	s := stockSystem()
	delete(s.files, "/usr/bin/pkexec")
	s.files["/home"] = posixStat{mode: rootDir}
	s.files["/home/mallory"] = posixStat{mode: rootDir, uid: userUID}
	s.files["/home/mallory/bin"] = posixStat{mode: rootDir, uid: userUID}
	s.files["/home/mallory/bin/pkexec"] = posixStat{mode: suidExe}

	_, err := newPkexec("/opt/acme/bin/acme", s.system())
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("newPkexec without a system pkexec = %v, want ErrNotImplemented", err)
	}
	for _, p := range s.lstats {
		if strings.HasSuffix(p, "pkexec") && p != pkexecUsrBin && p != pkexecBin {
			t.Fatalf("VULNERABILITY: pkexec was looked for at %q", p)
		}
	}
	if s.startCount() != 0 {
		t.Fatal("something was started")
	}
}

// /bin/pkexec is the second candidate; on a merged /usr it is a link, and what
// runs is the file it resolves to.
func TestFindPkexecFallsBackToBinAndResolvesIt(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	delete(s.files, "/usr/bin/pkexec")
	s.files["/usr/lib"] = posixStat{mode: rootDir}
	s.files["/usr/lib/polkit-pkexec"] = posixStat{mode: suidExe}
	s.links["/bin"] = "/usr/lib"
	s.links["/bin/pkexec"] = "/usr/lib/polkit-pkexec"

	e, err := newPkexec("/opt/acme/bin/acme", s.system())
	if err != nil {
		t.Fatal(err)
	}
	if e.pkexec != "/usr/lib/polkit-pkexec" {
		t.Fatalf("pkexec = %q, want the resolved file", e.pkexec)
	}
}

// A pkexec that anyone but root could have replaced is refused, and the search
// stops there rather than trying the next candidate.
func TestFindPkexecRefusesAnUntrustworthyBinary(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		mut  func(s *fakeSys)
	}{
		{"owned by a user", func(s *fakeSys) { s.files["/usr/bin/pkexec"] = posixStat{mode: suidExe, uid: userUID} }},
		{"world-writable", func(s *fakeSys) { s.files["/usr/bin/pkexec"] = posixStat{mode: suidExe | 0o002} }},
		{"not setuid", func(s *fakeSys) { s.files["/usr/bin/pkexec"] = posixStat{mode: rootExe} }},
		{"a directory", func(s *fakeSys) { s.files["/usr/bin/pkexec"] = posixStat{mode: rootDir} }},
		{"group-writable /usr/bin", func(s *fakeSys) { s.files["/usr/bin"] = posixStat{mode: rootDir | 0o020, gid: staffGID} }},
		{"dangling link", func(s *fakeSys) {
			delete(s.files, "/usr/bin/pkexec")
			s.links["/usr/bin/pkexec"] = "/nowhere"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := stockSystem()
			tc.mut(s)
			// A perfectly good second candidate must not rescue the first.
			s.files["/bin"] = posixStat{mode: rootDir}
			s.files["/bin/pkexec"] = posixStat{mode: suidExe}
			_, err := newPkexec("/opt/acme/bin/acme", s.system())
			if !errors.Is(err, ErrHelper) {
				t.Fatalf("newPkexec = %v, want ErrHelper", err)
			}
		})
	}
}

// The helper runs as root. Anything that lets someone other than root decide
// what that binary is — owning it, writing it, writing a directory above it, or
// pointing a link at a file that is theirs — is refused before a prompt exists.
func TestNewPkexecRefusesAHelperOthersControl(t *testing.T) {
	t.Parallel()

	const h = "/opt/acme/bin/acme"
	for _, tc := range []struct {
		name   string
		helper string
		mut    func(s *fakeSys)
	}{
		{"empty", "", nil},
		{"relative", "acme", nil},
		{"a drive path", `C:\acme\acme`, nil},
		{"a UNC path", `\\server\share\acme`, nil},
		{"a backslash", `/opt/acme\bin/acme`, nil},
		{"a dot element", "/opt/acme/../acme/bin/acme", nil},
		{"does not exist", "/opt/acme/bin/missing", nil},
		{"a directory", "/opt/acme/bin", nil},
		{"owned by a user", h, func(s *fakeSys) { s.files[h] = posixStat{mode: rootExe, uid: userUID} }},
		{"group-writable by a non-root group", h, func(s *fakeSys) { s.files[h] = posixStat{mode: rootExe | 0o020, gid: staffGID} }},
		{"world-writable", h, func(s *fakeSys) { s.files[h] = posixStat{mode: rootExe | 0o002} }},
		{"parent owned by a user", h, func(s *fakeSys) { s.files["/opt/acme/bin"] = posixStat{mode: rootDir, uid: userUID} }},
		{"grandparent group-writable", h, func(s *fakeSys) { s.files["/opt/acme"] = posixStat{mode: rootDir | 0o020, gid: staffGID} }},
		{"under a sticky world-writable directory", "/tmp/acme", func(s *fakeSys) {
			s.files["/tmp"] = posixStat{mode: fs.ModeDir | fs.ModeSticky | 0o777}
			s.files["/tmp/acme"] = posixStat{mode: rootExe}
		}},
		{"/opt writable by others", h, func(s *fakeSys) { s.files["/opt"] = posixStat{mode: rootDir | 0o002} }},
		{"a link to a user's file", "/usr/bin/acme", func(s *fakeSys) {
			s.files["/home"] = posixStat{mode: rootDir}
			s.files["/home/alice"] = posixStat{mode: rootDir, uid: userUID}
			s.files["/home/alice/acme"] = posixStat{mode: rootExe, uid: userUID}
			s.links["/usr/bin/acme"] = "/home/alice/acme"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := stockSystem()
			if tc.mut != nil {
				tc.mut(s)
			}
			e, err := newPkexec(tc.helper, s.system())
			if !errors.Is(err, ErrRequest) {
				t.Fatalf("newPkexec(%q) = %v, want ErrRequest", tc.helper, err)
			}
			if e != nil {
				t.Fatal("an elevator was returned alongside the refusal")
			}
			if s.startCount() != 0 {
				t.Fatal("something was started")
			}
		})
	}
}

// Root's own group may write, as for an install root; and a helper reached
// through a root-owned link runs as the file it resolves to — which is what was
// checked.
func TestNewPkexecAcceptsRootGroupAndResolvesLinks(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	s.files["/opt/acme/bin/acme"] = posixStat{mode: rootExe | 0o020}
	s.links["/usr/bin/acme"] = "/opt/acme/bin/acme"
	e, err := newPkexec("/usr/bin/acme", s.system())
	if err != nil {
		t.Fatal(err)
	}
	if e.helper != "/opt/acme/bin/acme" {
		t.Fatalf("helper = %q, want the resolved path", e.helper)
	}
}

// What reaches pkexec is an argument vector — pkexec, the helper, the verb and
// the three scalars, one element each — started in the helper's directory.
func TestPkexecApplyArgumentVector(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	e := newStock(t, s)
	if err := e.Apply(context.Background(), "/opt/acme app", descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	want := []string{pkexecUsrBin, "/opt/acme/bin/acme", "apply", "--root", "/opt/acme app", "--channel", "stable", "--version", "1.3.0"}
	if len(s.started) != 1 || !slices.Equal(s.started[0], want) {
		t.Fatalf("started %q, want %q", s.started, want)
	}
	if s.dirs[0] != "/opt/acme/bin" {
		t.Fatalf("working directory = %q, want the helper's", s.dirs[0])
	}
}

func TestPkexecApplyMapsExitStatus(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		code    int
		waitErr error
		want    error
		not     error
		text    string
	}{
		{name: "success", code: 0},
		{name: "dialog dismissed", code: 126, want: ErrDeclined},
		{name: "no agent, failed or refused authentication", code: 127, want: ErrHelper, not: ErrDeclined, text: "authentication agent"},
		{name: "helper failed", code: 3, want: ErrHelper, not: ErrDeclined, text: "status 3"},
		{name: "killed by a signal", code: -1, want: ErrHelper, not: ErrDeclined},
		{name: "wait failed", code: 0, waitErr: errors.New("wait: no child"), want: ErrHelper},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := stockSystem()
			s.code, s.waitErr = tc.code, tc.waitErr
			err := newStock(t, s).Apply(context.Background(), "/opt/acme", descriptor("stable", "1.3.0"))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Apply = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Apply = %v, want %v", err, tc.want)
			}
			if tc.not != nil && errors.Is(err, tc.not) {
				t.Fatalf("Apply = %v, must not be %v", err, tc.not)
			}
			if !strings.Contains(fmt.Sprint(err), tc.text) {
				t.Fatalf("Apply = %v, want it to mention %q", err, tc.text)
			}
		})
	}
}

func TestPkexecApplyReportsAFailedStart(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	e := newStock(t, s)
	s.startErr = errors.New("fork: resource temporarily unavailable")
	if err := e.Apply(context.Background(), "/opt/acme", descriptor("stable", "1.3.0")); !errors.Is(err, ErrHelper) {
		t.Fatalf("Apply = %v, want ErrHelper", err)
	}
}

// A request outside the grammar never becomes a process: this is where an
// unvalidated value would land on a root process's command line.
func TestPkexecApplyRefusesABadRequestWithoutStarting(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, root, channel, version string
	}{
		{"relative root", "opt/acme", "stable", "1.3.0"},
		{"drive root", `C:\acme`, "stable", "1.3.0"},
		{"backslash root", `/opt\acme`, "stable", "1.3.0"},
		{"dot root", "/opt/../etc", "stable", "1.3.0"},
		{"injected flag", "/opt/acme", "stable", "1.3.0 --root /etc"},
		{"shell channel", "/opt/acme", "stable;id", "1.3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := stockSystem()
			err := newStock(t, s).Apply(context.Background(), tc.root, descriptor(tc.channel, tc.version))
			if !errors.Is(err, ErrRequest) {
				t.Fatalf("Apply = %v, want ErrRequest", err)
			}
			if s.startCount() != 0 {
				t.Fatal("VULNERABILITY: a refused request started pkexec")
			}
		})
	}
	s := stockSystem()
	if err := newStock(t, s).Apply(context.Background(), "/opt/acme", nil); !errors.Is(err, ErrRequest) || s.startCount() != 0 {
		t.Fatalf("Apply(nil descriptor) = %v, started %d", err, s.startCount())
	}
}

func TestPkexecApplyStartsNothingForACancelledContext(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newStock(t, s).Apply(ctx, "/opt/acme", descriptor("stable", "1.3.0")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply = %v, want context.Canceled", err)
	}
	if s.startCount() != 0 {
		t.Fatal("pkexec was started for a cancelled context")
	}
}

// Cancelling stops the wait. The process is left to finish and is still
// reaped: pkexecSystem has no kill, and nothing here asks for one.
func TestPkexecApplyAbandonsTheWaitNotTheHelper(t *testing.T) {
	t.Parallel()

	s := stockSystem()
	s.release = make(chan struct{})
	s.reaped = make(chan struct{})
	e := newStock(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- e.Apply(ctx, "/opt/acme", descriptor("stable", "1.3.0")) }()
	for s.startCount() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	err := <-errc
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "keeps running") {
		t.Fatalf("Apply = %v, want context.Canceled saying the apply keeps running", err)
	}
	select {
	case <-s.reaped:
		t.Fatal("the helper was finished before it was released")
	default:
	}
	close(s.release)
	select {
	case <-s.reaped:
	case <-time.After(10 * time.Second):
		t.Fatal("the abandoned helper was never waited for")
	}
}
