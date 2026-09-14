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
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The Windows transport is a named pipe, created through go-winio.
//
// go-winio is used for two calls and nothing else: ListenPipe and
// DialPipeAccessImpLevel, which give a net.Listener and a net.Conn over
// overlapped pipe I/O. golang.org/x/sys has the raw CreateNamedPipe but no pipe
// server — no accept loop, no deadlines, no cancellable I/O — and writing that
// by hand at a privilege boundary is the larger risk. What go-winio does *not*
// decide here: the security descriptor (built below from SIDs, never taken as
// SDDL from a caller) and who the client is (authorize_windows.go asks the
// kernel through the pipe handle).
//
// Two properties this file depends on are go-winio's, and both are pinned by
// tests rather than trusted: the first instance is created with FILE_CREATE, so
// a pipe name somebody else already holds makes ListenPipe fail instead of
// joining their pipe; and every instance carries FILE_PIPE_REJECT_REMOTE_CLIENTS,
// so an SMB client never gets a connection.

// pipePrefix is the only namespace an endpoint may live in. It is compared
// exactly: `\\?\pipe\`, `//./pipe/` and `\\localhost\pipe\` name the same or
// another machine's pipes by a second spelling, and a dial to `\\host\pipe\x`
// would hand this user's credentials to whatever answers there.
const pipePrefix = `\\.\pipe\`

// maxPipeName bounds the part after the prefix. The kernel accepts 256
// characters; nothing here needs half of that.
const maxPipeName = 128

// checkPipeEndpoint enforces the endpoint grammar: the prefix, then a name of
// letters, digits, '.', '_' and '-' that begins and ends with a letter or digit.
//
// The outer characters are constrained because the path goes through Win32
// path normalization on its way to the kernel, which drops trailing dots and
// resolves "..": `foo.` would be the pipe `foo` under another spelling, and `..`
// would not be a pipe at all.
func checkPipeEndpoint(endpoint string) error {
	name, ok := strings.CutPrefix(endpoint, pipePrefix)
	if !ok {
		return fmt.Errorf(`%w: %q is not a local named pipe (it must start with \\.\pipe\)`, ErrRequest, endpoint)
	}
	if name == "" || len(name) > maxPipeName {
		return fmt.Errorf("%w: the pipe name must be 1 to %d characters", ErrRequest, maxPipeName)
	}
	for i := range len(name) {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		inner := c == '.' || c == '_' || c == '-'
		if !alnum && (!inner || i == 0 || i == len(name)-1) {
			return fmt.Errorf("%w: pipe name %q: character %d is not allowed there", ErrRequest, name, i)
		}
	}
	return nil
}

// Access masks in the pipe's DACL.
const (
	// pipeFullAccess is FILE_ALL_ACCESS: for SYSTEM, Administrators and the
	// helper's own account, which needs FILE_CREATE_PIPE_INSTANCE to create
	// the instance each Accept waits on.
	pipeFullAccess = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

	// pipeClientAccess is what an allowed caller gets, and exactly what
	// dialLocal asks for: read and write the byte stream, read the pipe's
	// attributes (go-winio's dial queries the pipe type), and wait on the
	// handle. It deliberately leaves out FILE_APPEND_DATA — on a pipe that is
	// FILE_CREATE_PIPE_INSTANCE, which would let a caller add its own server
	// instance to this pipe and answer the next client — and WRITE_DAC,
	// WRITE_OWNER, DELETE, FILE_WRITE_ATTRIBUTES and the extended-attribute
	// rights. Also left out is every generic right: GENERIC_WRITE maps to
	// FILE_APPEND_DATA.
	pipeClientAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA |
		windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE
)

// pipeSecurity builds the pipe's security descriptor, in SDDL because that is
// the form go-winio accepts.
//
// It is assembled from SIDs, never passed through: every SID in it is either a
// fixed well-known one, read from this process's own token, or one of allowed —
// which checkPrincipals has already parsed and required to be in canonical
// form, so the string cannot carry an ACE of its own.
//
//   - Owner: this process's default owner (TokenOwner). For a helper running as
//     LocalSystem, or elevated, that is SYSTEM or Administrators.
//   - DACL, protected: FILE_ALL_ACCESS for SYSTEM, for Administrators, and for
//     the helper's own account if it is neither; pipeClientAccess for each
//     allowed SID. Nothing for Everyone, Users, Authenticated Users, Anonymous
//     or NETWORK, and no inheritable ACEs.
//
// An empty allow-list gives no caller ACE at all. Administrators can still open
// the pipe — they could stop the helper anyway — and are then refused by
// authorizeConn, which for an empty list answers SYSTEM only.
func pipeSecurity(allowed []string) (string, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("%w: the helper's own account: %w", ErrHelper, err)
	}
	owner, err := tokenOwner(tok)
	if err != nil {
		return "", fmt.Errorf("%w: the helper's default owner: %w", ErrHelper, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "O:%sD:P", owner)
	full := []string{sidSystem.String(), sidAdministrators.String()}
	if self := user.User.Sid.String(); self != full[0] && self != full[1] {
		full = append(full, self)
	}
	for _, sid := range full {
		fmt.Fprintf(&b, "(A;;0x%x;;;%s)", pipeFullAccess, sid)
	}
	for _, sid := range allowed {
		fmt.Fprintf(&b, "(A;;0x%x;;;%s)", pipeClientAccess, sid)
	}
	return b.String(), nil
}

// tokenOwner reads TokenOwner, the owner the kernel would assign to an object
// this process creates without saying.
func tokenOwner(tok windows.Token) (string, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenOwner, nil, 0, &n)
	if n == 0 {
		return "", fmt.Errorf("no TokenOwner size")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenOwner, &buf[0], n, &n); err != nil {
		return "", err
	}
	// TOKEN_OWNER is a single PSID pointing into the same buffer.
	sid := *(**windows.SID)(unsafe.Pointer(&buf[0])) //nolint:gosec // G103: TOKEN_OWNER layout.
	if sid == nil || !sid.IsValid() {
		return "", fmt.Errorf("an invalid TokenOwner")
	}
	return sid.String(), nil
}

// listenLocal creates the helper's named pipe.
//
// The pipe is created with its final security descriptor in the same call that
// creates it, so there is no moment in which it exists with a DACL nobody chose.
// If the name is taken — by an earlier helper still running, or by a process
// that got there first to impersonate the helper — creation fails and so does
// NewHelper: a helper that joined an existing pipe would share its clients with
// whoever made it.
func listenLocal(endpoint string, allowed []string) (net.Listener, error) {
	if err := checkPipeEndpoint(endpoint); err != nil {
		return nil, err
	}
	sddl, err := pipeSecurity(allowed)
	if err != nil {
		return nil, err
	}
	ln, err := winio.ListenPipe(endpoint, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		// Message mode gives the stream a half-close: a zero-length message is
		// end of input on the other side, as shutdown(SHUT_WR) is on a Unix
		// socket. It is still read as a byte stream.
		MessageMode:      true,
		InputBufferSize:  maxRequestBytes,
		OutputBufferSize: maxRequestBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: creating the pipe %s (is the name already in use?): %w", ErrHelper, endpoint, err)
	}
	return ln, nil
}

// dialLocal opens the helper's pipe.
//
// It asks for pipeClientAccess and nothing more, so an ACL granting exactly that
// is enough, and it offers the helper an identification-level token: the helper
// may learn who this is — that is what it decides on — but cannot act as this
// user. An anonymous-level client is one the helper cannot identify, and it
// refuses those.
func dialLocal(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	if err := checkPipeEndpoint(endpoint); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, endpoint, pipeClientAccess, winio.PipeImpLevelIdentification)
}

// checkServiceEndpoint refuses, at construction, an endpoint that is not a local
// pipe in the grammar — before anything could dial it.
func checkServiceEndpoint(endpoint string) error {
	return checkPipeEndpoint(endpoint)
}
