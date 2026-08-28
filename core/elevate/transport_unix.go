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

package elevate

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// listenLocal binds the helper's Unix socket, after checking that nobody else
// could have put one there.
//
// The socket's own mode lets any local user connect — it has to, because the
// whole point is that an unprivileged updater asks a privileged helper — so the
// authentication is the peer's credentials, not the file mode. What the mode of
// the *directory* decides is something else entirely: if another user can write
// it, they can unlink this socket and bind their own, and every updater on the
// machine then talks to whoever got there first. That is not a privilege
// escalation, but it is a silent denial of every future update, and it is
// cheaply excluded here.
func listenLocal(o HelperOptions) (net.Listener, error) {
	endpoint := o.Endpoint
	dir := filepath.Dir(endpoint)
	if err := checkSocketDir(dir); err != nil {
		return nil, err
	}

	// A socket left behind by a previous run of this helper is removed; any
	// other kind of file is not. Unlinking whatever happens to sit at the path
	// would make "the helper starts" into "the helper deletes an arbitrary
	// file", which is the sort of favour a privileged process must not do.
	if st, err := os.Lstat(endpoint); err == nil {
		if st.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: %s exists and is not a socket", ErrRequest, endpoint)
		}
		if err := os.Remove(endpoint); err != nil {
			return nil, fmt.Errorf("%w: removing the stale socket: %w", ErrHelper, err)
		}
	}

	// Binding is not cancellable work, so the context is a formality here; the
	// ListenConfig form is used because it is the one API surface this project
	// reaches the network through.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: listening on %s: %w", ErrHelper, endpoint, err)
	}
	// Connectable by anyone; who may actually ask is decided by SO_PEERCRED.
	//
	//nolint:gosec // G302: a helper only its owner could reach would answer nobody.
	if err := os.Chmod(endpoint, 0o666); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("%w: %w", ErrHelper, err)
	}
	return ln, nil
}

// checkSocketDir refuses a directory another local user could write.
//
// The rule is the one that holds both in production and under test: the
// directory belongs to whoever is running this helper, and nobody else may
// create names in it. In production that is root and /run; in a test it is the
// test's own temporary directory. A sticky directory (/tmp) is refused rather
// than special-cased — the sticky bit stops other users deleting *this* socket,
// but not from being there first.
func checkSocketDir(dir string) error {
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: the helper's socket directory: %w", ErrRequest, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrRequest, dir)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot determine the owner of %s", ErrRequest, dir)
	}
	// Widened to int64 on both sides rather than converted into each other: a
	// uid is unsigned and Geteuid is signed, and the comparison must not depend
	// on which way the narrowing went.
	if int64(sys.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: %s is owned by uid %d, not by the helper's own uid %d",
			ErrRequest, dir, sys.Uid, os.Geteuid())
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or other (mode %o); another user could replace the socket",
			ErrRequest, dir, st.Mode().Perm())
	}
	return nil
}

// dialLocal reaches the helper's socket.
func dialLocal(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "unix", endpoint)
}
