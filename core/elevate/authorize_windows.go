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
	"errors"
	"fmt"
	"net"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the pipe's DACL is the first gate, and it is not the decision. It
// is evaluated when a client opens the pipe, which keeps anyone it does not
// name away from this process entirely; but a DACL grants to groups as readily
// as to accounts, may carry what a later edit put there, and says nothing this
// helper can log. So the helper asks the kernel who is on the other end of this
// connection, and decides against AllowedSIDs itself, as the POSIX side decides
// on SO_PEERCRED.

// Neither call is in golang.org/x/sys. Both DLLs are loaded from the system
// directory only.
var (
	procImpersonateNamedPipeClient      = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	procGetNamedPipeClientComputerNameW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientComputerNameW")
)

// checkPrincipals validates the Windows caller allow-list and returns it in
// canonical form.
//
// AllowedUIDs is refused rather than ignored: it is a POSIX setting, and an
// operator who wrote it believed it restricted something.
//
// Each SID must be written canonically — "S-1-5-18", not "SY" or "s-1-5-18" —
// because the canonical string is what the client's token is compared with and
// what goes into the pipe's SDDL; accepting a second spelling would be a second
// parser. And it must name an account: the decision is on the token's user SID,
// which is never a group, so a group here would permit nobody while its ACE let
// every member open the pipe.
func checkPrincipals(o HelperOptions) ([]string, error) {
	if len(o.AllowedUIDs) != 0 {
		return nil, fmt.Errorf("%w: AllowedUIDs is a POSIX setting; on Windows the helper decides on AllowedSIDs", ErrRequest)
	}
	out := make([]string, 0, len(o.AllowedSIDs))
	for _, s := range o.AllowedSIDs {
		sid, err := windows.StringToSid(s)
		if err != nil {
			return nil, fmt.Errorf("%w: AllowedSIDs: %q is not a SID: %w", ErrRequest, s, err)
		}
		if sid.String() != s {
			return nil, fmt.Errorf("%w: AllowedSIDs: %q is not in canonical form (%s)", ErrRequest, s, sid)
		}
		if !isAccountSID(s) {
			return nil, fmt.Errorf("%w: AllowedSIDs: %s is not an account SID; groups and well-known principals cannot be callers", ErrRequest, s)
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// isAccountSID reports whether sid can be the user SID of a token: SYSTEM,
// LocalService, NetworkService (S-1-5-18/19/20), a local or domain account
// (S-1-5-21-a-b-c-rid), a service account (S-1-5-80- and five sub-authorities;
// S-1-5-80-0 is the group of all services), or an Entra ID user
// (S-1-12-1-a-b-c-d).
//
// Domain groups share the S-1-5-21 shape and cannot be told apart without a
// lookup this check will not make; such a SID never equals a token's user SID,
// so its only effect is an ACE letting the group open the pipe to be refused.
//
// It reads the canonical string, which checkPrincipals has established by
// round-tripping it through the system's own parser, rather than the binary
// SID: x/sys's SID accessors return pointers the race detector's pointer
// checks reject on a Go-allocated SID.
func isAccountSID(canonical string) bool {
	parts := strings.Split(canonical, "-")
	if len(parts) < 4 || parts[0] != "S" || parts[1] != "1" {
		return false
	}
	auth, subs := parts[2], parts[3:]
	switch auth {
	case "5": // SECURITY_NT_AUTHORITY
		switch {
		case len(subs) == 1 && (subs[0] == "18" || subs[0] == "19" || subs[0] == "20"):
			return true
		case len(subs) == 5 && subs[0] == "21":
			return true
		case len(subs) == 6 && subs[0] == "80":
			return true
		}
	case "12": // Entra ID
		return len(subs) == 5 && subs[0] == "1"
	}
	return false
}

// pipeClient is who the kernel says opened this connection, and from where.
type pipeClient struct {
	user   string // the token's user SID, canonical.
	remote string // the client computer the pipe reports; "" for a local client.
}

// authorizeConn identifies the client through the pipe and decides.
//
// The client's process ID is read as well, for the log and nothing else: a pid
// names whichever process holds that number *now*, a client that exits can hand
// its number to another, and for a client arriving over SMB it is not a local
// process at all. The token does not have those problems — it is the security
// context the kernel captured when this client opened this pipe.
func authorizeConn(h *Helper, conn net.Conn) (string, error) {
	f, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return "", fmt.Errorf("%w: not a named pipe connection", ErrDenied)
	}
	pipe := windows.Handle(f.Fd())

	var pid uint32                                      // stays 0 when unknown.
	_ = windows.GetNamedPipeClientProcessId(pipe, &pid) // for the log only.

	remote, err := clientComputer(pipe)
	if err != nil {
		return "", fmt.Errorf("%w: cannot tell whether the pipe client (pid %d) is local: %w", ErrDenied, pid, err)
	}
	user, err := clientUser(pipe)
	if err != nil {
		return "", fmt.Errorf("%w: cannot identify the pipe client (pid %d): %w", ErrDenied, pid, err)
	}
	c := pipeClient{user: user, remote: remote}
	if !h.permitsClient(c) {
		if c.remote != "" {
			return "", fmt.Errorf("%w: %s connected from %q, over the network", ErrDenied, c.user, c.remote)
		}
		return "", fmt.Errorf("%w: %s (pid %d) may not ask this helper", ErrDenied, c.user, pid)
	}
	return fmt.Sprintf("%s (pid %d)", c.user, pid), nil
}

// permitsClient is the decision.
//
// A client that came over the network is refused whatever its account. The pipe
// is created to reject remote clients already (go-winio sets
// FILE_PIPE_REJECT_REMOTE_CLIENTS); this is the same rule applied where the
// identity is decided, so it does not rest on one flag inside a dependency.
//
// An empty list reads as SYSTEM and nobody else — see HelperOptions.AllowedSIDs.
func (h *Helper) permitsClient(c pipeClient) bool {
	if c.remote != "" || c.user == "" {
		return false
	}
	if len(h.sids) == 0 {
		return c.user == sidSystem.String()
	}
	return slices.Contains(h.sids, c.user)
}

// clientComputer returns the computer a remote pipe client connected from, or ""
// for a local one.
//
// The name is a pipe attribute the SMB server sets in the kernel when it opens a
// pipe on a network client's behalf — including a client on this machine that
// went through \\localhost, whose token is otherwise indistinguishable from a
// local one. A local open has no such attribute, and the call fails with
// ERROR_PIPE_LOCAL. Any other failure is not "local": it is unknown, and
// refused.
func clientComputer(pipe windows.Handle) (string, error) {
	if err := procGetNamedPipeClientComputerNameW.Find(); err != nil {
		return "", err
	}
	var buf [256]uint16
	r, _, callErr := procGetNamedPipeClientComputerNameW.Call(uintptr(pipe),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2)) //nolint:gosec // G103: a UTF-16 buffer and its size in bytes.
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_PIPE_LOCAL) {
			return "", nil
		}
		return "", fmt.Errorf("GetNamedPipeClientComputerName: %w", callErr)
	}
	name := windows.UTF16ToString(buf[:])
	if name == "" {
		// A remote client with an empty name must not read as local.
		name = "an unnamed computer"
	}
	return name, nil
}

// errStillImpersonating marks the one failure after which the thread must not
// be reused.
var errStillImpersonating = errors.New("RevertToSelf failed")

// clientUser reads the user SID of the pipe client's token.
//
// The token is obtained the only way the pipe offers it: by impersonating the
// client on this thread, opening the thread's token, and reverting. Nothing is
// done while impersonating except OpenThreadToken, which is opened as the
// helper itself (OpenAsSelf) so that an identification-level token — all a
// well-behaved client grants — is enough. The token is read after RevertToSelf.
//
// Impersonation is per OS thread, and Go moves goroutines between threads, so
// it runs on a goroutine locked to its thread. If RevertToSelf fails, that
// goroutine returns without unlocking, and the runtime destroys the thread
// rather than hand an impersonating thread to other code.
//
// A client that connected at anonymous level cannot be identified: opening the
// token fails, and so does this.
func clientUser(pipe windows.Handle) (string, error) {
	type result struct {
		user string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		tok, err := impersonatedToken(pipe)
		if errors.Is(err, errStillImpersonating) {
			ch <- result{err: err}
			return // still locked: the thread dies with the goroutine.
		}
		runtime.UnlockOSThread()
		if err != nil {
			ch <- result{err: err}
			return
		}
		defer func() { _ = tok.Close() }()
		u, err := tok.GetTokenUser()
		if err != nil {
			ch <- result{err: fmt.Errorf("the client's user: %w", err)}
			return
		}
		ch <- result{user: u.User.Sid.String()}
	}()
	r := <-ch
	return r.user, r.err
}

// impersonatedToken must run on a locked thread. It returns with the thread
// reverted, or with errStillImpersonating.
func impersonatedToken(pipe windows.Handle) (windows.Token, error) {
	if err := procImpersonateNamedPipeClient.Find(); err != nil {
		return 0, err
	}
	var tok windows.Token
	r, _, callErr := procImpersonateNamedPipeClient.Call(uintptr(pipe))
	var openErr error
	if r != 0 {
		thread := windows.CurrentThread() // a pseudo-handle.
		openErr = windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &tok)
	}
	// Reverted unconditionally: harmless if the impersonation never took, and
	// the only safe state to leave this function in if it did.
	if err := windows.RevertToSelf(); err != nil {
		if r != 0 && openErr == nil {
			_ = tok.Close()
		}
		return 0, fmt.Errorf("%w: %w", errStillImpersonating, err)
	}
	if r == 0 {
		return 0, fmt.Errorf("ImpersonateNamedPipeClient: %w", callErr)
	}
	if openErr != nil {
		return 0, fmt.Errorf("the client's token: %w", openErr)
	}
	return tok, nil
}
