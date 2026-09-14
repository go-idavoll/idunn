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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/release"
)

// The hostile-caller corpus, on a named pipe.
//
// These are the POSIX cases of service_unix_test.go against the Windows
// transport, plus the attacks only a pipe has: a squatter holding the name
// first, a DACL that grants more than it should, a remote client over SMB, and a
// client that refuses to be identified. Every refusal also asserts that the
// applier was never reached.

type recorder struct {
	mu       sync.Mutex
	requests []elevate.Request
	err      error
}

func (r *recorder) Apply(_ context.Context, req elevate.Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
	return r.err
}

func (r *recorder) calls() []elevate.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]elevate.Request(nil), r.requests...)
}

// Well-known SIDs the tests judge a DACL against.
const (
	sidEveryone      = "S-1-1-0"
	sidNetwork       = "S-1-5-2"
	sidInteractive   = "S-1-5-4"
	sidAnonymous     = "S-1-5-7"
	sidAuthenticated = "S-1-5-11"
	sidSystem        = "S-1-5-18"
	sidAdmins        = "S-1-5-32-544"
	sidUsers         = "S-1-5-32-545"
	sidGuests        = "S-1-5-32-546"

	// sidStranger is a well-formed account SID that is nobody on this machine.
	sidStranger = "S-1-5-21-1111111111-2222222222-3333333333-1001"
)

// selfSID is the account running the test.
func selfSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// pipeName is a pipe endpoint no other test, and no other run, uses.
func pipeName(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return `\\.\pipe\idunn-test-` + hex.EncodeToString(b[:])
}

// allowedRoot is a root CheckPrivilegedRoot accepts on a stock Windows: a
// directory that does not exist, under %ProgramFiles%.
func allowedRoot(t *testing.T) string {
	t.Helper()
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		t.Skip("no %ProgramFiles%")
	}
	return filepath.Join(pf, "idunn-test-does-not-exist", "acme")
}

// helper starts a privileged-side listener that the running user may ask. In
// production the helper runs as SYSTEM and the caller is someone else; the
// property under test — the kernel says who is calling, and the helper
// decides — is the same either way.
func helper(t *testing.T, adjust func(*elevate.HelperOptions)) (*recorder, string, string) {
	t.Helper()
	rec := &recorder{}
	endpoint := pipeName(t)
	root := allowedRoot(t)
	o := elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      rec,
		AllowedRoots: []string{root},
		AllowedSIDs:  []string{selfSID(t)},
		MinInterval:  time.Nanosecond,
		Now:          steadyClock(),
	}
	if adjust != nil {
		adjust(&o)
	}
	h, err := elevate.NewHelper(o)
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
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
	return rec, endpoint, root
}

// steadyClock is the wall clock, moved on by a millisecond at every reading.
//
// Go's clock on Windows can advance in steps of a millisecond or more, so two
// requests in quick succession may read the same instant — and a same-instant
// second request is inside any MinInterval, however small. A test that means
// "no rate limit" must not be refused by one; the step keeps each reading later
// than the last while the exchange deadlines stay close to real time.
func steadyClock() func() time.Time {
	var n atomic.Int64
	return func() time.Time { return time.Now().Add(time.Duration(n.Add(1)) * time.Millisecond) }
}

func descriptor(channel, version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme",
		Version:       version,
		Channel:       channel,
		OS:            "windows",
		Arch:          "amd64",
	}
}

func service(t *testing.T, endpoint string) elevate.Elevator {
	t.Helper()
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	return el
}

// The control. Without it, a helper that denied everything would look like a
// perfect one.
func TestPipeHelperAppliesAPermittedRequest(t *testing.T) {
	rec, endpoint, root := helper(t, nil)

	if err := service(t, endpoint).Apply(t.Context(), root, descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("the applier ran %d times, want 1", len(calls))
	}
	if got := calls[0]; got.Root != root || got.Channel != "stable" || got.Version != "1.3.0" {
		t.Errorf("the applier was asked for %+v", got)
	}
}

// A signed release written to a root of the caller's choosing, as SYSTEM, is a
// local privilege escalation with a valid signature on it (T16).
func TestPipeARootTheHelperDoesNotMaintainIsDenied(t *testing.T) {
	rec, endpoint, root := helper(t, nil)

	other := filepath.Join(filepath.Dir(root), "other")
	err := service(t, endpoint).Apply(t.Context(), other, descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for a root outside the allowed set")
	}
}

// A caller whose token user is not in AllowedSIDs is refused, although the pipe
// let it connect: the DACL is the first gate, the token is the decision.
func TestPipeAnUnpermittedSIDIsDenied(t *testing.T) {
	var events []string
	var mu sync.Mutex
	rec, endpoint, root := helper(t, func(o *elevate.HelperOptions) {
		o.AllowedSIDs = []string{sidStranger}
		o.OnEvent = func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	})

	err := service(t, endpoint).Apply(t.Context(), root, descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for a caller that is not permitted")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 || !strings.Contains(events[0], selfSID(t)) || !strings.Contains(events[0], "pid ") {
		t.Errorf("the refusal was not logged with the caller's SID and pid: %q", events)
	}
}

// An unconfigured allow-list means SYSTEM and nobody else — not the helper's own
// account, not Administrators.
func TestPipeAnEmptySIDListMeansSystemOnly(t *testing.T) {
	if selfSID(t) == sidSystem {
		t.Skip("this test needs to run as an account other than SYSTEM")
	}
	rec, endpoint, root := helper(t, func(o *elevate.HelperOptions) { o.AllowedSIDs = nil })

	err := service(t, endpoint).Apply(t.Context(), root, descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: an unconfigured helper answered a non-SYSTEM caller: %v", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for an unconfigured helper")
	}
}

// A client that opens the pipe at anonymous impersonation level cannot be
// identified, and a client that cannot be identified is not answered — even
// when its account is the one allowed.
func TestPipeAnAnonymousClientIsDenied(t *testing.T) {
	rec, endpoint, root := helper(t, nil)

	answer := speakAt(t, endpoint, winio.PipeImpLevelAnonymous,
		"idunn-apply/1\nroot="+root+"\nchannel=stable\nversion=1.3.0\n\n")
	if answer != "error denied" {
		t.Fatalf("VULNERABILITY: an unidentifiable client got %q, want %q", answer, "error denied")
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for an anonymous client")
	}
}

func TestPipeAVersionOutsideTheGrammarNeverLeavesTheCaller(t *testing.T) {
	rec, endpoint, root := helper(t, nil)
	el := service(t, endpoint)

	for _, version := range []string{"1.3.0; del /q C:\\", "1.3.0\nroot=C:\\Windows", `..\..\Windows`, ""} {
		if err := el.Apply(t.Context(), root, descriptor("stable", version)); !errors.Is(err, elevate.ErrRequest) {
			t.Errorf("version %q: err = %v, want ErrRequest", version, err)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: a value outside the request grammar reached the privileged side")
	}
}

func TestPipeARootOutsideTheGrammarNeverLeavesTheCaller(t *testing.T) {
	rec, endpoint, root := helper(t, nil)
	el := service(t, endpoint)

	for _, bad := range []string{`Program Files\acme`, root + `\..\..\Windows`, root + `\`, "", `\\server\share\acme`} {
		err := el.Apply(t.Context(), bad, descriptor("stable", "1.3.0"))
		if !errors.Is(err, elevate.ErrRequest) && !errors.Is(err, elevate.ErrDenied) {
			t.Errorf("root %q: err = %v, want a refusal", bad, err)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: an install root outside the request grammar reached the privileged side")
	}
}

func TestPipeRawGarbageIsRefused(t *testing.T) {
	rec, endpoint, root := helper(t, nil)

	for _, payload := range []string{
		"",
		"GET / HTTP/1.1\r\n\r\n",
		"idunn-apply/2\nroot=" + root + "\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nchannel=stable\nroot=" + root + "\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=" + root + "\nchannel=stable\nversion=1.3.0\nextra=1\n\n",
		"idunn-apply/1\nroot=" + root + "\nroot=C:\\Windows\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\r\nroot=" + root + "\r\nchannel=stable\r\nversion=1.3.0\r\n\r\n",
		"idunn-apply/1\nroot=" + root + "\nchannel=stable\nversion=1.3.0\n" + strings.Repeat("A", 8192),
	} {
		if answer := speak(t, endpoint, payload); answer == "ok" {
			t.Errorf("payload %q was ACCEPTED", payload)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: a request outside the grammar reached the privileged side")
	}
}

func TestPipeASecondRequestInsideTheIntervalIsDenied(t *testing.T) {
	rec, endpoint, root := helper(t, func(o *elevate.HelperOptions) { o.MinInterval = time.Hour })
	el := service(t, endpoint)

	if err := el.Apply(t.Context(), root, descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("the first apply: %v", err)
	}
	if err := el.Apply(t.Context(), root, descriptor("stable", "1.4.0")); !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if n := len(rec.calls()); n != 1 {
		t.Errorf("the applier ran %d times, want 1", n)
	}
}

// What crosses back is exactly the class (§11.3 T20).
func TestPipeAFailedApplyPutsNothingButTheClassOnTheWire(t *testing.T) {
	rec, endpoint, root := helper(t, nil)
	rec.err = errors.New(`open C:\Program Files\acme\.updater\journal: Access is denied.`)

	answer := speak(t, endpoint, "idunn-apply/1\nroot="+root+"\nchannel=stable\nversion=1.3.0\n\n")
	if answer != "error apply" {
		t.Fatalf("the helper answered %q, want exactly %q", answer, "error apply")
	}
	if len(rec.calls()) != 1 {
		t.Fatalf("the applier ran %d times, want 1", len(rec.calls()))
	}

	err := service(t, endpoint).Apply(t.Context(), root, descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrHelper) || strings.Contains(err.Error(), "journal") {
		t.Fatalf("err = %v, want ErrHelper without the helper's detail", err)
	}
}

type blocker struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (b *blocker) Apply(context.Context, elevate.Request) error {
	close(b.started)
	<-b.release
	close(b.finished)
	return nil
}

// Cancelling the caller stops its wait, not the privileged apply.
func TestPipeCancellingTheCallerDoesNotStopTheApply(t *testing.T) {
	b := &blocker{started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	_, endpoint, root := helper(t, func(o *elevate.HelperOptions) { o.Applier = b })

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	el := service(t, endpoint)
	go func() { done <- el.Apply(ctx, root, descriptor("stable", "1.3.0")) }()

	select {
	case <-b.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the apply never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled caller kept waiting")
	}

	close(b.release)
	select {
	case <-b.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("the apply did not run to completion after the caller left")
	}
}

// The attack a first-instance check exists for. A process that creates the
// pipe name before the helper does would otherwise have the helper join *its*
// pipe as one more instance, and every updater that connected could reach the
// squatter instead: it would read their requests, answer "ok" for applies that
// never happened, and learn who they are.
func TestPipeASquatterOnTheNameStopsTheHelperFromStarting(t *testing.T) {
	endpoint := pipeName(t)
	name, err := windows.UTF16PtrFromString(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	squat, err := windows.CreateNamedPipe(name,
		windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatalf("the squatter could not create its pipe: %v", err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(squat) })

	h, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      &recorder{},
		AllowedRoots: []string{allowedRoot(t)},
		AllowedSIDs:  []string{selfSID(t)},
	})
	if err == nil {
		_ = h.Close()
		t.Fatal("VULNERABILITY: the helper started on a pipe name another process already held")
	}
	if !errors.Is(err, elevate.ErrHelper) {
		t.Errorf("err = %v, want ErrHelper", err)
	}
}

// A second helper on the same name is the same squatter from the other side.
func TestPipeASecondHelperOnTheSameNameIsRefused(t *testing.T) {
	_, endpoint, root := helper(t, nil)
	h, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      &recorder{},
		AllowedRoots: []string{root},
		AllowedSIDs:  []string{selfSID(t)},
	})
	if err == nil {
		_ = h.Close()
		t.Fatal("VULNERABILITY: a second helper joined a pipe that already had one")
	}
}

// The pipe's security descriptor, read back from the kernel and judged: owner,
// protection, and every ACE. Anything granted to a principal not named here —
// Everyone, Users, Authenticated Users, Anonymous, NETWORK — or any right beyond
// the client mask for an allowed caller, is a failure.
func TestPipeTheDACLGrantsExactlyWhatIsIntended(t *testing.T) {
	self := selfSID(t)
	if self == sidSystem {
		t.Skip("as SYSTEM the helper's own account is SYSTEM")
	}
	const (
		fullAccess   = 0x001F01FF // FILE_ALL_ACCESS.
		clientAccess = 0x00100083 // FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE.

		fileCreatePipeInstance = 0x00000004
		writeDAC               = 0x00040000
		writeOwner             = 0x00080000
		genericMask            = 0xF0000000
	)

	for _, tc := range []struct {
		name    string
		allowed []string
	}{
		{"with an allowed caller", []string{sidStranger}},
		{"with an empty allow-list", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, endpoint, _ := helper(t, func(o *elevate.HelperOptions) { o.AllowedSIDs = tc.allowed })
			owner, protected, aces := readPipeSecurity(t, endpoint)

			if owner != sidSystem && owner != sidAdmins && owner != self {
				t.Errorf("VULNERABILITY: the pipe is owned by %s", owner)
			}
			if !protected {
				t.Error("the DACL is not protected")
			}
			want := map[string]uint32{sidSystem: fullAccess, sidAdmins: fullAccess, self: fullAccess}
			for _, sid := range tc.allowed {
				want[sid] = clientAccess
			}
			seen := map[string]bool{}
			for _, a := range aces {
				switch a.sid {
				case sidEveryone, sidUsers, sidAuthenticated, sidAnonymous, sidNetwork, sidInteractive, sidGuests:
					t.Errorf("VULNERABILITY: the DACL names %s (mask %#x)", a.sid, a.mask)
					continue
				}
				if a.typ != 0 {
					t.Errorf("ACE for %s has type %d, want ACCESS_ALLOWED", a.sid, a.typ)
				}
				if a.flags != 0 {
					t.Errorf("ACE for %s has flags %#x, want none", a.sid, a.flags)
				}
				w, ok := want[a.sid]
				if !ok {
					t.Errorf("VULNERABILITY: the DACL grants %#x to %s, who is not meant to be in it", a.mask, a.sid)
					continue
				}
				if a.mask != w {
					t.Errorf("VULNERABILITY: %s is granted %#x, want %#x", a.sid, a.mask, w)
				}
				if w == clientAccess && a.mask&(fileCreatePipeInstance|writeDAC|writeOwner|genericMask) != 0 {
					t.Errorf("VULNERABILITY: caller %s may create pipe instances or rewrite the DACL (%#x)", a.sid, a.mask)
				}
				seen[a.sid] = true
			}
			for sid := range want {
				if !seen[sid] {
					t.Errorf("the DACL has no ACE for %s", sid)
				}
			}
		})
	}
}

type ace struct {
	sid   string
	typ   uint8
	flags uint8
	mask  uint32
}

// readPipeSecurity opens the pipe for READ_CONTROL only, at anonymous level so
// the helper learns nothing from it, and reads its owner and DACL.
func readPipeSecurity(t *testing.T, endpoint string) (string, bool, []ace) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	var h windows.Handle
	deadline := time.Now().Add(10 * time.Second)
	for {
		h, err = windows.CreateFile(name, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING,
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS, 0)
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("opening the pipe for READ_CONTROL: %v", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("VULNERABILITY: no DACL (%v): a NULL DACL grants everyone everything", err)
	}
	var out []ace
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &a); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		out = append(out, ace{sid: sid.String(), typ: a.Header.AceType, flags: a.Header.AceFlags, mask: uint32(a.Mask)})
	}
	return owner.String(), control&windows.SE_DACL_PROTECTED != 0, out
}

// An SMB client is a remote client, even from this machine: opening the pipe
// through \\localhost goes through the server service and arrives with a
// network logon. The pipe must refuse it at open, before any of the helper's
// code runs.
func TestPipeARemoteClientCannotOpenThePipe(t *testing.T) {
	_, endpoint, _ := helper(t, nil)

	// The control: a pipe without the remote-client rejection, opened the same
	// way. If this does not open, this machine cannot produce a remote client
	// and the case below would prove nothing.
	control := pipeName(t)
	cname, err := windows.UTF16PtrFromString(control)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := windows.CreateNamedPipe(cname, windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, windows.PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(cp) })
	remote := func(local string) error {
		p, err := windows.UTF16PtrFromString(`\\localhost\pipe\` + strings.TrimPrefix(local, `\\.\pipe\`))
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err == nil {
			_ = windows.CloseHandle(h)
		}
		return err
	}
	if err := remote(control); err != nil {
		t.Skipf("no SMB loopback on this machine (%v); a remote client cannot be produced", err)
	}

	if err := remote(endpoint); err == nil {
		t.Fatal("VULNERABILITY: a network client opened the helper's pipe")
	}
}

func TestPipeAllowedUIDsAreRefusedOnWindows(t *testing.T) {
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     pipeName(t),
		Applier:      &recorder{},
		AllowedRoots: []string{allowedRoot(t)},
		AllowedUIDs:  []uint32{1000},
	})
	if !errors.Is(err, elevate.ErrRequest) || !strings.Contains(err.Error(), "AllowedUIDs") {
		t.Fatalf("err = %v, want a refusal naming AllowedUIDs", err)
	}
}

// A group, an alias or a non-canonical spelling in AllowedSIDs is refused: the
// decision is on the token's user SID, and a group would put an ACE for all of
// its members on the pipe while permitting none of them.
func TestPipeAllowedSIDsMustBeCanonicalAccounts(t *testing.T) {
	for _, sid := range []string{
		sidEveryone, sidNetwork, sidInteractive, sidAnonymous, sidAuthenticated,
		sidAdmins, sidUsers, sidGuests, "S-1-5-80-0", "S-1-3-0",
		"SY", "BA", "s-1-5-18", "S-1-5-018", "not a sid", "", sidSystem + ")(A;;FA;;;WD",
		// An account SID's shape, in a spelling that is not the canonical one.
		"S-1-5-21-01111111111-2222222222-3333333333-1001",
	} {
		_, err := elevate.NewHelper(elevate.HelperOptions{
			Endpoint:     pipeName(t),
			Applier:      &recorder{},
			AllowedRoots: []string{allowedRoot(t)},
			AllowedSIDs:  []string{sid},
		})
		if !errors.Is(err, elevate.ErrRequest) {
			t.Errorf("AllowedSIDs %q: err = %v, want ErrRequest", sid, err)
		}
	}
}

// The endpoint grammar, on both sides. A dial to `\\host\pipe\x` would send this
// user's credentials to whatever answers there; a name the path normalizer
// rewrites is a second spelling of another pipe.
func TestPipeMalformedEndpointsAreRefused(t *testing.T) {
	for _, endpoint := range []string{
		"",
		`\\.\pipe\`,
		`\\.\pipe\a\b`,
		`\\.\pipe\a/b`,
		`\\.\pipe\x.`,
		`\\.\pipe\.x`,
		`\\.\pipe\..`,
		`\\.\pipe\-x`,
		`\\.\pipe\x y`,
		`\\.\pipe\x` + "\x00",
		`\\.\PIPE\x`,
		`\\?\pipe\x`,
		`//./pipe/x`,
		`\\localhost\pipe\x`,
		`\\server\pipe\x`,
		`C:\x`,
		`\\.\pipe\` + strings.Repeat("a", 129),
	} {
		_, err := elevate.NewHelper(elevate.HelperOptions{
			Endpoint:     endpoint,
			Applier:      &recorder{},
			AllowedRoots: []string{allowedRoot(t)},
			AllowedSIDs:  []string{selfSID(t)},
		})
		if !errors.Is(err, elevate.ErrRequest) {
			t.Errorf("NewHelper(%q) = %v, want ErrRequest", endpoint, err)
		}
		if el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint}); !errors.Is(err, elevate.ErrRequest) || el != nil {
			t.Errorf("NewService(%q) = %v, %v, want ErrRequest", endpoint, el, err)
		}
	}
	// And the longest name the grammar allows is a name.
	for _, endpoint := range []string{`\\.\pipe\` + strings.Repeat("a", 128), `\\.\pipe\a`, `\\.\pipe\Acme.Updater_1-0`} {
		if _, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint}); err != nil {
			t.Errorf("NewService(%q) = %v, want nil", endpoint, err)
		}
	}
}

// Nobody listening is a failure to reach the helper, not a hang.
func TestPipeNoHelperIsAnErrorNotAHang(t *testing.T) {
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: pipeName(t), DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := el.Apply(t.Context(), allowedRoot(t), descriptor("stable", "1.3.0")); !errors.Is(err, elevate.ErrHelper) {
		t.Fatalf("err = %v, want ErrHelper", err)
	}
}

// speak sends raw bytes as an identifiable client and returns the answer line.
func speak(t *testing.T, endpoint, payload string) string {
	t.Helper()
	return speakAt(t, endpoint, winio.PipeImpLevelIdentification, payload)
}

func speakAt(t *testing.T, endpoint string, level winio.PipeImpLevel, payload string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const access = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
	conn, err := winio.DialPipeAccessImpLevel(ctx, endpoint, access, level)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// A write error is not a failure: the helper may refuse and close before
	// reading everything, and what it answered is still there to be read.
	_, _ = io.WriteString(conn, payload)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	answer, _ := io.ReadAll(io.LimitReader(conn, 256))
	return strings.TrimSpace(string(answer))
}
