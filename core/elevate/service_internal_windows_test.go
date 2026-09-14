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

package elevate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

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

// A root in the grammar; the tests below inject the root judgement, so it need
// not exist or be protected on this machine.
const testRoot = `C:\Program Files\idunn-test-does-not-exist\acme`

func startPipeHelper(t *testing.T, a Applier, checkRoot func(string) error) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	endpoint := `\\.\pipe\idunn-test-` + hex.EncodeToString(b[:])
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	var tick atomic.Int64
	h, err := newHelper(HelperOptions{
		Endpoint:     endpoint,
		Applier:      a,
		AllowedRoots: []string{testRoot},
		AllowedSIDs:  []string{u.User.Sid.String()},
		MinInterval:  time.Nanosecond,
		// Go's clock on Windows can read the same instant for two quick
		// requests, which any MinInterval refuses; each reading is moved on.
		Now: func() time.Time { return time.Now().Add(time.Duration(tick.Add(1)) * time.Millisecond) },
	}, checkRoot)
	if err != nil {
		t.Fatalf("newHelper: %v", err)
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

func windowsDescriptor(version string) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          "acme",
		Version:       version,
		Channel:       "stable",
		OS:            "windows",
		Arch:          "amd64",
	}
}

// The root is judged again for every request: an ACL can change while the
// helper runs, and a root that became writable by someone else must stop being
// written as SYSTEM at once.
func TestPipeARootThatBecameUnsafeAfterStartIsDenied(t *testing.T) {
	var unsafe atomic.Bool
	check := func(string) error {
		if unsafe.Load() {
			return ErrUnsafeRoot
		}
		return nil
	}
	a := &countingApplier{}
	el, err := NewService(ServiceOptions{Endpoint: startPipeHelper(t, a, check)})
	if err != nil {
		t.Fatal(err)
	}

	if err := el.Apply(t.Context(), testRoot, windowsDescriptor("1.3.0")); err != nil {
		t.Fatalf("the control apply: %v", err)
	}
	unsafe.Store(true)
	if err := el.Apply(t.Context(), testRoot, windowsDescriptor("1.4.0")); !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("VULNERABILITY: the applier ran %d times, want only the control", n)
	}
}

// The exchange deadline bounds reading and answering, never the apply.
func TestPipeAnApplyLongerThanTheExchangeTimeoutStillAnswers(t *testing.T) {
	saved := exchangeTimeout
	exchangeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { exchangeTimeout = saved })

	a := &countingApplier{delay: time.Second}
	el, err := NewService(ServiceOptions{Endpoint: startPipeHelper(t, a, func(string) error { return nil })})
	if err != nil {
		t.Fatal(err)
	}
	if err := el.Apply(t.Context(), testRoot, windowsDescriptor("1.3.0")); err != nil {
		t.Fatalf("Apply = %v, want the answer after the long apply", err)
	}
}

// The decision, apart from the token it is fed. The live tests can only ever be
// this machine's own account; these are the identities they cannot produce.
func TestPermitsClient(t *testing.T) {
	const (
		alice  = "S-1-5-21-1111111111-2222222222-3333333333-1001"
		bob    = "S-1-5-21-1111111111-2222222222-3333333333-1002"
		system = "S-1-5-18"
	)
	listed := &Helper{sids: []string{alice}}
	empty := &Helper{}

	for _, tc := range []struct {
		name string
		h    *Helper
		c    pipeClient
		want bool
	}{
		{"a listed account", listed, pipeClient{user: alice}, true},
		{"an unlisted account", listed, pipeClient{user: bob}, false},
		{"SYSTEM when not listed", listed, pipeClient{user: system}, false},
		{"a listed account over the network", listed, pipeClient{user: alice, remote: "WORKSTATION7"}, false},
		{"SYSTEM with an empty list", empty, pipeClient{user: system}, true},
		{"SYSTEM over the network with an empty list", empty, pipeClient{user: system, remote: "[::1]"}, false},
		{"an account with an empty list", empty, pipeClient{user: alice}, false},
		{"Administrators with an empty list", empty, pipeClient{user: "S-1-5-32-544"}, false},
		{"no identity", empty, pipeClient{}, false},
		{"no identity with a list", listed, pipeClient{}, false},
	} {
		if got := tc.h.permitsClient(tc.c); got != tc.want {
			t.Errorf("%s: permitsClient = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsAccountSID(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-5-18": true,
		"S-1-5-19": true,
		"S-1-5-20": true,
		"S-1-5-21-1111111111-2222222222-3333333333-1001":                 true,
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": true,
		"S-1-12-1-1111111111-2222222222-3333333333-4444444444":           true,

		"S-1-1-0":          false, // Everyone
		"S-1-5-2":          false, // NETWORK
		"S-1-5-4":          false, // INTERACTIVE
		"S-1-5-7":          false, // ANONYMOUS LOGON
		"S-1-5-11":         false, // Authenticated Users
		"S-1-5-32-544":     false, // Administrators
		"S-1-5-32-545":     false, // Users
		"S-1-5-80-0":       false, // ALL SERVICES
		"S-1-5-21-1-2":     false,
		"S-1-5-18-1":       false,
		"S-1-3-0":          false, // CREATOR OWNER
		"S-1-15-2-1":       false, // ALL APPLICATION PACKAGES
		"S-1-12-2-1-2-3-4": false,
		"S-2-5-18":         false,
		"X-1-5-18":         false,
		"S-1-5":            false,
		"":                 false,
	} {
		if got := isAccountSID(sid); got != want {
			t.Errorf("isAccountSID(%s) = %v, want %v", sid, got, want)
		}
	}
}

// handleConn hands authorizeConn a pipe handle this test created itself.
type handleConn struct {
	net.Conn
	h windows.Handle
}

func (c handleConn) Fd() uintptr { return uintptr(c.h) }

// The helper's own refusal of a network client, apart from the pipe flag that
// normally stops one earlier. The server end here is a plain pipe *without*
// FILE_PIPE_REJECT_REMOTE_CLIENTS, so an SMB client reaches authorizeConn — as it
// would if that flag were ever lost — and must be refused there. The client is
// this machine through \\localhost, which is exactly the case a token check alone
// would miss: its token is the user's local one.
func TestAuthorizeConnRefusesANetworkClient(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self := u.User.Sid.String()
	h := &Helper{sids: []string{self}}

	connect := func(t *testing.T, client string) (string, error) {
		t.Helper()
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		name := "idunn-test-" + hex.EncodeToString(b[:])
		sp, err := windows.UTF16PtrFromString(`\\.\pipe\` + name)
		if err != nil {
			t.Fatal(err)
		}
		server, err := windows.CreateNamedPipe(sp, windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = windows.CloseHandle(server) }()
		cp, err := windows.UTF16PtrFromString(client + name)
		if err != nil {
			t.Fatal(err)
		}
		c, err := windows.CreateFile(cp, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
		if err != nil {
			t.Skipf("cannot open the pipe as %s (%v)", client, err)
		}
		defer func() { _ = windows.CloseHandle(c) }()
		if err := windows.ConnectNamedPipe(server, nil); err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			t.Fatal(err)
		}
		return authorizeConn(h, handleConn{h: server})
	}

	t.Run("the local control", func(t *testing.T) {
		caller, err := connect(t, `\\.\pipe\`)
		if err != nil || !strings.Contains(caller, self) {
			t.Fatalf("a local client of a listed account: %q, %v", caller, err)
		}
	})
	t.Run("through SMB", func(t *testing.T) {
		_, err := connect(t, `\\localhost\pipe\`)
		if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), "network") {
			t.Fatalf("VULNERABILITY: a network client of a listed account: err = %v, want a network refusal", err)
		}
	})
}

// A connection that is not a pipe cannot be identified, and is not answered.
func TestAuthorizeConnRefusesWhatIsNotAPipe(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if _, err := authorizeConn(&Helper{}, a); !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}
