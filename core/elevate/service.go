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
	"net"
	"slices"
	"sync"
	"time"

	"github.com/go-idavoll/idunn/core/release"
)

// ErrDenied reports that the helper refused the caller or the target: the peer
// is not one it answers, it asked too often, or the install root is not one it
// maintains or not one only administrators control. It is its own class because
// it is neither a malformed request nor a failed apply — it is the authorization
// boundary saying no (§14.2, T16).
var ErrDenied = errors.New("elevate: denied by the privileged helper")

// Applier is the privileged half of an apply: it resolves and verifies the named
// release *itself* and installs it into root.
//
// It takes a Request and nothing else. That is the boundary: the helper is told
// which release to arrive at, never which bytes to install, which file list to
// trust, or which staged directory to swap in. Everything it acts on it obtains
// through its own TUF client, with its own trust anchor, inside the privileged
// context (AGENTS.md §1.4, docs/design.md §14.2).
//
// core/updater provides one (updater.RequestApplier) around
// Updater.ApplyRequested. core/elevate deliberately does not: a package that
// could construct one would have to know a repository URL, and then the
// privileged side's trust anchor would be a parameter rather than a build-time
// fact of the host.
type Applier interface {
	Apply(ctx context.Context, req Request) error
}

// DefaultMinInterval is the shortest gap between two accepted requests when
// HelperOptions leaves MinInterval unset.
//
// Rate limiting is not about load. An unprivileged caller that can ask for an
// apply in a loop can keep a machine's install root churning and its disk busy
// for as long as it likes; one apply per interval turns that into a nuisance.
const DefaultMinInterval = 5 * time.Second

// HelperOptions configures the privileged side.
type HelperOptions struct {
	// Endpoint is the local address to listen on.
	//
	// On POSIX it is a Unix socket path. Its directory must belong to the
	// helper's own user and be writable by nobody else, and so must every
	// directory above it (see listenLocal).
	//
	// For a launchd daemon on macOS, give the socket a directory of its own that
	// the daemon creates as root with mode 0755, below a root-owned tree nobody
	// else can write — for example
	// "/Library/Application Support/<label>/helper.sock". /var/run is the
	// conventional place, but /private/var/run is usually root:daemon 0775 on
	// macOS, which fails the ancestor rule; the rule is not relaxed for it (the
	// darwin tests record what the CI runner actually has). The path must fit in
	// 103 bytes.
	//
	// On Windows it is a named pipe, `\\.\pipe\<name>`, where name is 1 to 128
	// letters, digits, '.', '_' or '-', beginning and ending with a letter or
	// digit. The helper creates the pipe with a security descriptor it builds
	// itself from AllowedSIDs, and refuses to start if the name already exists.
	Endpoint string

	// Applier performs the verified install. Required.
	Applier Applier

	// AllowedRoots are the install roots this helper maintains. It must name at
	// least one, and a request for anything else is denied.
	//
	// This is the difference between a helper and a local root exploit. The
	// bytes a helper installs are signed, so a caller cannot choose them — but
	// without this list a caller could choose *where* they land, and a signed
	// binary written to a path of the attacker's choosing, as root, is a local
	// privilege escalation with the publisher's signature on it (T16).
	//
	// Being listed is necessary, not sufficient. Every root must also pass
	// CheckPrivilegedRoot when the helper starts and again for every request: a
	// root an ordinary user can change is refused however it got into this list
	// (IDN-22).
	AllowedRoots []string

	// AllowedUIDs are the local users permitted to ask. Empty means only the
	// superuser, which is the fail-closed reading of "not configured": a helper
	// that answered everyone by default would be a helper nobody meant to deploy
	// that way.
	//
	// POSIX only. On Windows a non-empty AllowedUIDs is refused, not ignored: an
	// operator who wrote it believed it restricted something.
	AllowedUIDs []uint32

	// AllowedSIDs are the Windows accounts permitted to ask, as canonical SID
	// strings ("S-1-5-21-…-1001"). Each is compared with the user SID of the
	// client's token, which the helper obtains through the pipe itself; group
	// membership is never consulted, so naming a group would permit nobody, and
	// is refused. Accepted are account SIDs only: SYSTEM, LocalService,
	// NetworkService, local and domain accounts (S-1-5-21-…), service accounts
	// (S-1-5-80-…) and Entra ID users (S-1-12-1-…). Everyone, Users,
	// Authenticated Users, NETWORK, Anonymous and every other well-known group are
	// refused.
	//
	// Empty means SYSTEM only, for the same fail-closed reason as AllowedUIDs —
	// not even members of Administrators, whose token user is their own account.
	//
	// Windows only. On POSIX a non-empty AllowedSIDs is refused.
	AllowedSIDs []string

	// PeerRequirement, if set, is a code-signing requirement in Apple's
	// requirement language that the connecting process must also satisfy, for
	// example
	//
	//	anchor apple generic and identifier "com.acme.app" and certificate leaf[subject.OU] = "TEAMID"
	//
	// It is checked after the uid and in addition to it — never instead: a peer
	// must be an allowed user AND running code that meets the requirement. The
	// process is identified by its audit token (LOCAL_PEERTOKEN), not by pid, and
	// judged with SecCodeCopyGuestWithAttributes and SecCodeCheckValidity.
	//
	// Empty means the uid check alone. It needs macOS and a build with cgo; in any
	// other build a non-empty requirement makes NewHelper fail with
	// ErrNotImplemented rather than start a helper weaker than configured. A
	// requirement that does not compile is refused at start, too.
	PeerRequirement string

	// MinInterval is the shortest gap between two accepted requests. Zero
	// selects DefaultMinInterval.
	MinInterval time.Duration

	// Now is the injected clock the rate limit and the exchange deadlines are
	// measured on.
	Now func() time.Time

	// OnEvent, if set, receives one line per decision. It never receives an
	// apply's error text verbatim from the caller's side of the wire — the log is
	// the privileged side's own — and it is read by whoever can read the system
	// journal, so hosts should treat it as such.
	OnEvent func(string)
}

// Helper is the privileged listener.
type Helper struct {
	ln      net.Listener
	applier Applier

	roots     []string
	uids      []uint32
	sids      []string
	interval  time.Duration
	now       func() time.Time
	onEvent   func(string)
	checkRoot func(string) error

	peerRequirement string
	checkPeerCode   func(conn net.Conn, requirement string) error

	mu   sync.Mutex
	last time.Time
}

// NewHelper validates the configuration and starts listening.
//
// Every refusal here is a deployment that would have been worse than no helper
// at all: no applier, no roots, a root someone else controls, or an endpoint a
// local user could replace. The listener is created last, so a rejected
// configuration never has a socket anyone could connect to.
func NewHelper(o HelperOptions) (*Helper, error) {
	return newHelper(o, CheckPrivilegedRoot)
}

// newHelper is NewHelper with the root judgement injectable, so tests can put a
// root that passes on this machine through the refusal that only a root that
// changed after start would trigger.
func newHelper(o HelperOptions, checkRoot func(string) error) (*Helper, error) {
	if o.Applier == nil {
		return nil, fmt.Errorf("%w: no applier", ErrRequest)
	}
	if o.Endpoint == "" {
		return nil, fmt.Errorf("%w: no endpoint", ErrRequest)
	}
	// The principals come before the roots: a helper configured with another
	// platform's notion of a caller is wrong however good its roots are.
	sids, err := checkPrincipals(o)
	if err != nil {
		return nil, err
	}
	// Judged before the roots, so a helper told to check code signatures where
	// it cannot is refused for exactly that.
	if o.PeerRequirement != "" {
		// Fails always without Security.framework (peercode_other.go), which
		// staticcheck can prove per build and not per program.
		//
		//nolint:staticcheck // SA4023: true per platform, not per program.
		if err := checkPeerRequirement(o.PeerRequirement); err != nil {
			return nil, err
		}
	}
	if len(o.AllowedRoots) == 0 {
		return nil, fmt.Errorf("%w: no allowed install roots; a helper that would write anywhere is a local root exploit", ErrRequest)
	}
	roots := make([]string, 0, len(o.AllowedRoots))
	for _, root := range o.AllowedRoots {
		if err := checkRoot(root); err != nil {
			return nil, fmt.Errorf("allowed root: %w", err)
		}
		roots = append(roots, root)
	}

	h := &Helper{
		applier:   o.Applier,
		roots:     roots,
		uids:      slices.Clone(o.AllowedUIDs),
		sids:      sids,
		interval:  o.MinInterval,
		now:       o.Now,
		onEvent:   o.OnEvent,
		checkRoot: checkRoot,

		peerRequirement: o.PeerRequirement,
		checkPeerCode:   peerCodeCheck,
	}
	if h.interval <= 0 {
		h.interval = DefaultMinInterval
	}
	if h.now == nil {
		h.now = time.Now
	}

	ln, err := listenLocal(o.Endpoint, sids)
	if err != nil {
		return nil, err
	}
	h.ln = ln
	return h, nil
}

// Addr is the address the helper is listening on.
func (h *Helper) Addr() net.Addr { return h.ln.Addr() }

// Close stops the listener.
func (h *Helper) Close() error { return h.ln.Close() }

// Serve answers requests until ctx is cancelled or the listener is closed.
//
// Connections are handled one at a time and on purpose. The work behind a
// request is a TUF refresh and an install into a single root; two of them at
// once would contend for the same journal and the same pointer, and a privileged
// process is the last place to discover that by racing.
//
// Cancelling ctx stops accepting. It is also the context an apply in progress
// runs under, so a host that cancels it is asking for that apply to stop at its
// next cancellation point — which the transaction survives, as it survives a
// crash (§6.2).
func (h *Helper) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = h.ln.Close() })
	defer stop()
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			// A closed listener during shutdown is the shutdown, not a failure.
			//
			//nolint:nilerr // the accept error IS the cancellation arriving.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%w: accept: %w", ErrHelper, err)
		}
		h.handle(ctx, conn)
	}
}

// exchangeTimeout bounds each half of an exchange that is not the apply itself:
// reading the request, and writing the answer. A peer that connects and says
// nothing cannot hold the single-threaded helper; a peer that stops reading
// cannot hold it after the work is done.
//
// It deliberately does not bound the apply. A release can take minutes to
// download and stage, and a deadline that fired in the middle would leave the
// caller told "failed" about an update that then commits.
var exchangeTimeout = 30 * time.Second

func (h *Helper) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(h.now().Add(exchangeTimeout))

	class := h.serve(ctx, conn)
	if class != "" {
		h.emit("refused: " + class)
	}
	_ = conn.SetWriteDeadline(h.now().Add(exchangeTimeout))
	_ = encodeResponse(conn, class)
}

// serve is one exchange, returning the error class to answer with.
//
// The order is deliberate: who is asking, then how often, then what is being
// asked, then where it would land, and only then the work. Authentication before
// parsing means a peer that may not ask at all never reaches the parser; the rate
// limit before the request means a permitted peer cannot use the parser as a
// workload; the root is judged last and immediately before the apply, so the
// answer is as fresh as it can be.
func (h *Helper) serve(ctx context.Context, conn net.Conn) string {
	caller, err := authorizeConn(h, conn)
	if err != nil {
		h.emit("denied: " + err.Error())
		return classDenied
	}
	if !h.takeToken() {
		h.emit("rate limited: " + caller)
		return classDenied
	}

	req, err := decodeRequest(conn)
	if err != nil {
		return classRequest
	}
	// The request is read. Nothing further is read from this connection, so the
	// read deadline cannot cut the work that follows short; the answer gets a
	// write deadline of its own in handle.

	if !slices.Contains(h.roots, req.Root) {
		// Naming a root this helper does not maintain is the request that would
		// turn it into an arbitrary-write primitive, so it is denied rather than
		// reported as malformed: it is well-formed, and not permitted.
		h.emit("install root is not one this helper maintains")
		return classDenied
	}
	// Judged again although it passed at start: the root's directories and
	// ACLs can have changed since, and the check is only as good as its age.
	if err := h.checkRoot(req.Root); err != nil {
		h.emit("install root refused: " + err.Error())
		return classDenied
	}

	if err := h.applier.Apply(ctx, req); err != nil {
		// The reason stays on this side. It names paths on a filesystem the
		// caller may not be able to read, and a privileged process does not
		// describe itself to an unprivileged one (§11.3 T20).
		h.emit("apply failed: " + err.Error())
		return classApply
	}
	h.emit("applied " + req.Version + " for " + caller)
	return ""
}

// takeToken enforces the minimum gap between two accepted requests.
func (h *Helper) takeToken() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if !h.last.IsZero() && now.Sub(h.last) < h.interval {
		return false
	}
	h.last = now
	return true
}

func (h *Helper) emit(msg string) {
	if h.onEvent != nil {
		h.onEvent(msg)
	}
}

// ServiceOptions configures the unprivileged side.
type ServiceOptions struct {
	// Endpoint is where the privileged helper listens: its Unix socket path on
	// POSIX, its `\\.\pipe\<name>` on Windows, where NewService refuses anything
	// outside the pipe-name grammar before it could dial it.
	Endpoint string

	// DialTimeout bounds reaching the helper. Zero selects DefaultDialTimeout.
	DialTimeout time.Duration
}

// DefaultDialTimeout bounds connecting to the helper.
const DefaultDialTimeout = 10 * time.Second

// NewService returns an Elevator that hands the apply to an already privileged
// helper over local IPC.
//
// It transports a request and nothing else. The descriptor it is given is
// reduced to three validated scalars before anything is sent, and the file list,
// the hashes and the staged paths stay on this side — the helper re-resolves and
// re-verifies the release itself. That is why this side needs no trust anchor
// and why compromising it does not compromise what gets installed.
func NewService(o ServiceOptions) (Elevator, error) {
	if o.Endpoint == "" {
		return nil, fmt.Errorf("%w: no helper endpoint", ErrRequest)
	}
	if err := checkServiceEndpoint(o.Endpoint); err != nil {
		return nil, err
	}
	timeout := o.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	return &serviceElevator{endpoint: o.Endpoint, timeout: timeout}, nil
}

type serviceElevator struct {
	endpoint string
	timeout  time.Duration
}

// Apply sends the request and waits for the helper's answer.
//
// Cancelling ctx stops the wait, not the apply: the helper owns it from the
// moment it has read the request, exactly as the interactive elevator's helper
// does once it is running.
func (s *serviceElevator) Apply(ctx context.Context, root string, d *release.Descriptor) error {
	req, err := newRequest(root, d)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := dialLocal(ctx, s.endpoint, s.timeout)
	if err != nil {
		return fmt.Errorf("%w: cannot reach the privileged helper: %w", ErrHelper, err)
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_ = conn.SetWriteDeadline(time.Now().Add(exchangeTimeout))
	// A write failure is not necessarily the end of the exchange. The helper
	// decides who may ask *before* it reads anything — that ordering is what
	// keeps an unpermitted peer away from the parser — so a refusal can arrive
	// while this side is still writing, and the close behind it turns the rest
	// of the write into a broken pipe. Reading the answer first means the caller
	// learns "denied" instead of "the pipe broke", which is the difference
	// between a diagnosis and a shrug.
	writeErr := encodeRequest(conn, req)

	// No read deadline: the answer comes after the apply, and the apply may take
	// as long as a release takes. Only ctx ends this wait.
	respErr := decodeResponse(conn)
	if ctx.Err() != nil {
		return fmt.Errorf("%w (the privileged apply may keep running)", ctx.Err())
	}
	if respErr != nil || writeErr == nil {
		return respErr
	}
	return fmt.Errorf("%w: %w", ErrHelper, writeErr)
}
