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
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/release"
)

// The hostile-caller corpus.
//
// These are the cases AGENTS.md §7 asks to be kept forever, and they live here
// rather than in test/redteam/corpus because that corpus is built out of
// tampered *repositories*: its fixture is a signed TUF tree and its mutators
// change bytes the server hands out. The attacks below change none of that. The
// repository is honest; the attacker is the process on the other end of the
// helper's socket, and the only place that exists is here.
//
// Each of them must be refused, and refused for its own reason. A case that
// passed because the applier happened to fail would be proving nothing, so every
// case also asserts that the applier was never reached.

// recorder is an Applier that records what it was asked to do — and, by never
// being called, records that a refusal happened before any privileged work.
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

// helper starts a privileged-side listener in a directory only this test owns,
// with the running user allowed to ask. In production the helper runs as root
// and the caller is someone else; the property under test — the kernel says who
// is calling, and the helper decides — is the same either way.
func helper(t *testing.T, adjust func(*elevate.HelperOptions)) (*recorder, string) {
	t.Helper()
	rec := &recorder{}
	dir := t.TempDir()
	endpoint := filepath.Join(dir, "helper.sock")

	o := elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      rec,
		AllowedRoots: []string{"/opt/acme"},
		AllowedUIDs:  []uint32{uint32(os.Getuid())}, //nolint:gosec // a uid fits.
		MinInterval:  time.Nanosecond,
	}
	if adjust != nil {
		adjust(&o)
	}
	h, err := elevate.NewHelper(o)
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
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
	return rec, endpoint
}

func descriptor(channel, version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme",
		Version:       version,
		Channel:       channel,
		OS:            "linux",
		Arch:          "amd64",
	}
}

// The control. Without it, a helper that denied everything would look like a
// perfect one.
func TestTheHelperAppliesAPermittedRequest(t *testing.T) {
	rec, endpoint := helper(t, nil)
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	if err := el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("the applier ran %d times, want 1", len(calls))
	}
	if got := calls[0]; got.Root != "/opt/acme" || got.Channel != "stable" || got.Version != "1.3.0" {
		t.Errorf("the applier was asked for %+v", got)
	}
}

// The attack the allowed-roots list exists for. The bytes a helper installs are
// signed, so a caller cannot choose them — but a caller who could choose *where*
// they land would be writing publisher-signed content to a path of their
// choosing, as root. That is a local privilege escalation with a valid signature
// on it (T16).
func TestARootTheHelperDoesNotMaintainIsDenied(t *testing.T) {
	rec, endpoint := helper(t, nil)
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	err = el.Apply(t.Context(), "/etc/cron.d", descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for a root outside the allowed set")
	}
}

// A helper configured with no roots at all would be that same primitive with the
// list left empty, so the configuration is refused rather than defaulted.
func TestAHelperWithNoAllowedRootsRefusesToStart(t *testing.T) {
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint: filepath.Join(t.TempDir(), "helper.sock"),
		Applier:  &recorder{},
	})
	if err == nil {
		t.Fatal("a helper that would write anywhere was allowed to start")
	}
	if !strings.Contains(err.Error(), "root exploit") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// A caller the helper does not answer gets nothing, and gets it before the
// parser sees a byte.
func TestAnUnpermittedUIDIsDenied(t *testing.T) {
	// Nobody is allowed except a uid this test cannot be running as: uid 0 is
	// excluded by the check itself when the list is non-empty, and 65534
	// (nobody) is not who runs `go test`.
	if os.Getuid() == 65534 {
		t.Skip("this test cannot run as nobody")
	}
	rec, endpoint := helper(t, func(o *elevate.HelperOptions) {
		o.AllowedUIDs = []uint32{65534}
	})
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	err = el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for a caller that is not permitted")
	}
}

// An unconfigured allowlist means the superuser and nobody else. "Not
// configured" must read as "answer no one", never as "answer everyone".
func TestAnEmptyUIDListMeansSuperuserOnly(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("this test needs to run as an unprivileged user")
	}
	rec, endpoint := helper(t, func(o *elevate.HelperOptions) { o.AllowedUIDs = nil })
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	err = el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("VULNERABILITY: an unconfigured helper answered a non-root caller: %v", err)
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: the privileged applier ran for an unconfigured helper")
	}
}

// A version the request grammar does not describe never becomes a request, so it
// never reaches the wire and never reaches the privileged side.
func TestAVersionOutsideTheGrammarNeverLeavesTheCaller(t *testing.T) {
	rec, endpoint := helper(t, nil)
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{
		"1.3.0; rm -rf /",
		"1.3.0\nroot=/etc",
		"../../../etc",
		"",
	} {
		err := el.Apply(t.Context(), "/opt/acme", descriptor("stable", version))
		if !errors.Is(err, elevate.ErrRequest) {
			t.Errorf("version %q: err = %v, want ErrRequest", version, err)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: a value outside the request grammar reached the privileged side")
	}
}

// The same for the install root: a relative or dot-laden one would be resolved
// against a working directory the privileged process happens to have.
func TestARootOutsideTheGrammarNeverLeavesTheCaller(t *testing.T) {
	rec, endpoint := helper(t, nil)
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{"opt/acme", "/opt/../etc", "/opt/acme/", "", "//server/share"} {
		err := el.Apply(t.Context(), root, descriptor("stable", "1.3.0"))
		if !errors.Is(err, elevate.ErrRequest) && !errors.Is(err, elevate.ErrDenied) {
			t.Errorf("root %q: err = %v, want a refusal", root, err)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: an install root outside the request grammar reached the privileged side")
	}
}

// A caller that speaks something other than the protocol is refused by the
// parser, not accommodated by it.
func TestRawGarbageIsRefused(t *testing.T) {
	rec, endpoint := helper(t, nil)

	for _, payload := range []string{
		"",
		"GET / HTTP/1.1\r\n\r\n",
		"idunn-apply/2\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nchannel=stable\nroot=/opt/acme\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\nextra=1\n\n",
		"idunn-apply/1\nroot=/opt/acme\nroot=/etc\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\r\nroot=/opt/acme\r\nchannel=stable\r\nversion=1.3.0\r\n\r\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n" + strings.Repeat("A", 8192),
	} {
		// A caller that oversteps the protocol may not get to read the answer:
		// the helper writes its refusal and closes, and a socket still holding
		// unread bytes resets. That is a refusal too — what must never happen
		// is an "ok".
		answer := speak(t, endpoint, payload)
		if answer == "ok" {
			t.Errorf("payload %q was ACCEPTED", payload)
		}
	}
	if len(rec.calls()) != 0 {
		t.Fatal("VULNERABILITY: a request outside the grammar reached the privileged side")
	}
}

// Rate limiting is not about load: a caller that can ask in a loop can keep a
// machine reinstalling for as long as it likes.
func TestASecondRequestInsideTheIntervalIsDenied(t *testing.T) {
	rec, endpoint := helper(t, func(o *elevate.HelperOptions) { o.MinInterval = time.Hour })
	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	if err := el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.3.0")); err != nil {
		t.Fatalf("the first apply: %v", err)
	}
	err = el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.4.0"))
	if !errors.Is(err, elevate.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if n := len(rec.calls()); n != 1 {
		t.Errorf("the applier ran %d times, want 1", n)
	}
}

// The helper's answer says a class and nothing else. It crosses back to a less
// privileged process, and what it says must not describe a filesystem that
// process may not be able to read (§11.3 T20).
func TestAFailedApplyReportsAClassAndNoDetail(t *testing.T) {
	rec, endpoint := helper(t, nil)
	rec.err = errors.New("open /opt/acme/.updater/journal: permission denied")

	el, err := elevate.NewService(elevate.ServiceOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	err = el.Apply(t.Context(), "/opt/acme", descriptor("stable", "1.3.0"))
	if !errors.Is(err, elevate.ErrHelper) {
		t.Fatalf("err = %v, want ErrHelper", err)
	}
	if strings.Contains(err.Error(), "/opt/acme") || strings.Contains(err.Error(), "permission denied") {
		t.Errorf("the helper described its own filesystem to the caller: %v", err)
	}
}

// A socket directory another local user can write is a directory in which
// somebody else can be the helper.
func TestAWorldWritableSocketDirectoryIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     filepath.Join(dir, "helper.sock"),
		Applier:      &recorder{},
		AllowedRoots: []string{"/opt/acme"},
	})
	if err == nil {
		t.Fatal("a helper bound a socket in a directory any local user can write")
	}
	if !strings.Contains(err.Error(), "writable by group or other") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// Starting the helper must not become a way to have a privileged process delete
// an arbitrary file.
func TestAnEndpointThatIsNotASocketIsRefused(t *testing.T) {
	dir := t.TempDir()
	endpoint := filepath.Join(dir, "important")
	if err := os.WriteFile(endpoint, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:     endpoint,
		Applier:      &recorder{},
		AllowedRoots: []string{"/opt/acme"},
	})
	if err == nil {
		t.Fatal("the helper took over a path that was not its socket")
	}
	if _, statErr := os.Stat(endpoint); statErr != nil {
		t.Errorf("the refused start deleted the file that was in the way: %v", statErr)
	}
}

// speak sends raw bytes to the helper and returns its answer line. It exists so
// a case can be a *caller*, not a well-behaved client: the protocol is what the
// privileged side parses, and the tests that matter most are the ones that do
// not speak it.
func speak(t *testing.T, endpoint, payload string) string {
	t.Helper()
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "unix", endpoint)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		// Close our half so a helper waiting for the terminator sees EOF rather
		// than the deadline; a caller that simply stops talking is one of the
		// shapes under test.
		_ = uc.CloseWrite()
	}
	// A read error is not a test failure. The helper writes its refusal and
	// closes; a connection still holding bytes the helper did not read resets,
	// and the caller sees that instead of the answer. Either way it was refused.
	answer, _ := io.ReadAll(io.LimitReader(conn, 256))
	return strings.TrimSpace(string(answer))
}

// A setting meant for the other platform is refused, not ignored. An operator
// who wrote SecurityDescriptor into a POSIX deployment believed they were
// deciding who may ask; silently dropping it would leave them believing it.
func TestAWindowsOnlySettingIsRefusedOnPosix(t *testing.T) {
	_, err := elevate.NewHelper(elevate.HelperOptions{
		Endpoint:           filepath.Join(t.TempDir(), "helper.sock"),
		Applier:            &recorder{},
		AllowedRoots:       []string{"/opt/acme"},
		SecurityDescriptor: "D:P(A;;GA;;;BA)",
	})
	if err == nil {
		t.Fatal("a Windows-only access setting was accepted on POSIX")
	}
	if !strings.Contains(err.Error(), "AllowedUIDs") {
		t.Errorf("the refusal does not say what to use instead: %v", err)
	}
}
