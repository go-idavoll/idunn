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
// is not one it answers, or the install root is not one it maintains. It is its
// own class because it is neither a malformed request nor a failed apply — it is
// the authorization boundary saying no (§14.2, T16).
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
// A host implements it around core/installer with the anchor its build embeds.
// core/elevate deliberately does not: a package that could construct one would
// have to know a repository URL, and then the privileged side's trust anchor
// would be a parameter rather than a build-time fact.
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
	// Endpoint is the local address to listen on: a Unix socket path on POSIX,
	// a named pipe on Windows.
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
	AllowedRoots []string

	// AllowedUIDs are the local users permitted to ask. Empty means only the
	// superuser, which is the fail-closed reading of "not configured": a helper
	// that answered everyone by default would be a helper nobody meant to
	// deploy that way.
	AllowedUIDs []uint32

	// MinInterval is the shortest gap between two accepted requests. Zero
	// selects DefaultMinInterval.
	MinInterval time.Duration

	// Now is the injected clock the rate limit is measured on.
	Now func() time.Time

	// OnEvent, if set, receives one line per decision. It never receives the
	// request's fields: this runs privileged, and its log is read by whoever
	// can read the system journal.
	OnEvent func(string)
}

// Helper is the privileged listener.
type Helper struct {
	ln      net.Listener
	applier Applier

	roots    []string
	uids     []uint32
	interval time.Duration
	now      func() time.Time
	onEvent  func(string)

	mu   sync.Mutex
	last time.Time
}

// NewHelper validates the configuration and starts listening.
//
// Every refusal here is a deployment that would have been worse than no helper
// at all: no applier, no roots, or an endpoint a local user could replace. The
// listener is created last, so a rejected configuration never has a socket
// anyone could connect to.
func NewHelper(o HelperOptions) (*Helper, error) {
	if o.Applier == nil {
		return nil, fmt.Errorf("%w: no applier", ErrRequest)
	}
	if o.Endpoint == "" {
		return nil, fmt.Errorf("%w: no endpoint", ErrRequest)
	}
	if len(o.AllowedRoots) == 0 {
		return nil, fmt.Errorf("%w: no allowed install roots; a helper that would write anywhere is a local root exploit", ErrRequest)
	}
	roots := make([]string, 0, len(o.AllowedRoots))
	for _, root := range o.AllowedRoots {
		if err := checkInstallRoot(root); err != nil {
			return nil, fmt.Errorf("%w: allowed root: %w", ErrRequest, err)
		}
		roots = append(roots, root)
	}

	h := &Helper{
		applier:  o.Applier,
		roots:    roots,
		uids:     slices.Clone(o.AllowedUIDs),
		interval: o.MinInterval,
		now:      o.Now,
		onEvent:  o.OnEvent,
	}
	if h.interval <= 0 {
		h.interval = DefaultMinInterval
	}
	if h.now == nil {
		h.now = time.Now
	}

	ln, err := listenLocal(o.Endpoint)
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
func (h *Helper) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = h.ln.Close()
	}()
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

// connTimeout bounds one exchange, so a peer that connects and says nothing
// cannot hold the single-threaded helper.
const connTimeout = 30 * time.Second

func (h *Helper) handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(h.now().Add(connTimeout))

	class := h.serve(ctx, conn)
	if class != "" {
		h.emit("refused: " + class)
	}
	_ = encodeResponse(conn, class)
}

// serve is one exchange, returning the error class to answer with.
//
// The order is deliberate: who is asking, then how often, then what is being
// asked, and only then the work. Authentication before parsing means a peer that
// may not ask at all never reaches the parser; the rate limit before the request
// means a permitted peer cannot use the parser as a workload.
func (h *Helper) serve(ctx context.Context, conn net.Conn) string {
	p, err := peerOf(conn)
	if err != nil {
		h.emit("peer credentials unavailable")
		return classDenied
	}
	if !h.permits(p) {
		h.emit(fmt.Sprintf("uid %d is not permitted", p.uid))
		return classDenied
	}
	if !h.takeToken() {
		h.emit("rate limited")
		return classDenied
	}

	req, err := decodeRequest(conn)
	if err != nil {
		return classRequest
	}
	if !slices.Contains(h.roots, req.Root) {
		// Naming a root this helper does not maintain is the request that would
		// turn it into an arbitrary-write primitive, so it is denied rather than
		// reported as malformed: it is well-formed, and not permitted.
		h.emit("install root is not one this helper maintains")
		return classDenied
	}

	if err := h.applier.Apply(ctx, req); err != nil {
		// The reason stays on this side. It names paths on a filesystem the
		// caller may not be able to read, and a privileged process does not
		// describe itself to an unprivileged one (§11.3 T20).
		h.emit("apply failed: " + err.Error())
		return classApply
	}
	h.emit("applied " + req.Version)
	return ""
}

// permits reports whether this peer may ask at all.
func (h *Helper) permits(p peer) bool {
	if len(h.uids) == 0 {
		return p.uid == 0
	}
	return slices.Contains(h.uids, p.uid)
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
	// Endpoint is where the privileged helper listens.
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

func (s *serviceElevator) Apply(ctx context.Context, root string, d *release.Descriptor) error {
	req, err := newRequest(root, d)
	if err != nil {
		return err
	}
	conn, err := dialLocal(ctx, s.endpoint, s.timeout)
	if err != nil {
		return fmt.Errorf("%w: cannot reach the privileged helper: %w", ErrHelper, err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(connTimeout)
	}
	_ = conn.SetDeadline(deadline)

	if err := encodeRequest(conn, req); err != nil {
		return fmt.Errorf("%w: %w", ErrHelper, err)
	}
	return decodeResponse(conn)
}
