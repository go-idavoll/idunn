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

package updater

import (
	"context"
	"fmt"

	"github.com/go-idavoll/idunn/core/elevate"
	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/internal/layout"
)

// applyElevated is Apply for an install root this process cannot write.
//
// Everything a transaction does happens under the root: the journal, the staging
// tree, the version directory, the pointer, the time floor. A process that may
// not write there cannot run any part of it — not even the first journal record
// — so this side does none of it. What it does is decide whether to ask at all,
// using only reads, and then ask: the elevated helper answers the request with
// its own refresh, its own resolution and the ordinary transaction (see
// ApplyRequested). Asking for a prompt the helper is certain to refuse would be
// a consent dialog for nothing.
//
// The one thing this side still has to establish is the outcome. A helper that
// exits zero has not thereby installed anything, and an update recorded as done
// on its word alone is the false success the journal exists to rule out. The
// pointer is read back, and anything but the version asked for is a failure.
func (u *Updater) applyElevated(ctx context.Context, r *Release) error {
	d := r.Descriptor

	fail := func(phase hook.Phase, err error) error {
		u.emit(phase, "failed", err)
		u.reportOutcome(ctx, r, "aborted", classify(err), phase)
		return err
	}

	if err := ctx.Err(); err != nil {
		return fail(hook.PhaseCheck, err)
	}
	if err := u.floor.Check(u.now()); err != nil {
		return fail(hook.PhaseCheck, err)
	}
	installed, err := u.installedVersion()
	if err != nil {
		return fail(hook.PhaseCheck, err)
	}
	if installed != r.FromVersion {
		return fail(hook.PhaseCheck, fmt.Errorf("%w: it was resolved against %q but %q is installed",
			ErrStale, r.FromVersion, installed))
	}
	if installed == d.Version {
		return fail(hook.PhaseCheck, fmt.Errorf("%w: %s is already installed", ErrStale, d.Version))
	}
	// steps rather than applicable: a release behind a migration floor that the
	// repository bridges is one the helper will walk to, and refusing it here
	// would make an elevated install stricter than an unprivileged one.
	if _, err := u.steps(d, installed); err != nil {
		return fail(hook.PhaseCheck, err)
	}

	hc := hook.Context{
		Ctx:         ctx,
		FromVersion: installed,
		ToVersion:   d.Version,
		Root:        u.root,
		StageDir:    fsx.Join(layout.Staging(u.root), d.Version),
	}
	if u.check != nil {
		u.emit(hook.PhaseCheck, "running pre-flight checks", nil)
		if err := u.check.Check(hc); err != nil {
			return fail(hook.PhaseCheck, fmt.Errorf("%w: %w", ErrCheck, err))
		}
	}
	if u.prompt != nil {
		ok, err := u.prompt.Confirm(ctx, fmt.Sprintf("Install %s %s now?", d.Name, d.Version))
		if err != nil {
			return fail(hook.PhaseCheck, err)
		}
		if !ok {
			return fail(hook.PhaseCheck, ErrDeclined)
		}
	}

	u.emit(hook.PhaseApply, "requesting privileges to install "+d.Version, nil)
	// The descriptor is a request, not a verdict: only channel and version
	// cross the boundary, and the helper resolves both again (AGENTS.md §1.4).
	if err := u.elevator.Apply(ctx, u.root, d); err != nil {
		return fail(hook.PhaseApply, err)
	}

	after, err := u.installedVersion()
	if err != nil {
		return fail(hook.PhaseVerify, err)
	}
	if after != d.Version {
		return fail(hook.PhaseVerify, fmt.Errorf("%w: the helper exited successfully, but %q is installed, not %s",
			elevate.ErrHelper, after, d.Version))
	}
	u.emit(hook.PhaseCommit, "installed "+d.Version, nil)
	u.reportOutcome(ctx, r, "committed", classNone, "")
	return nil
}

// ApplyRequested is the privileged side of an elevated update: the helper's
// answer to "install version V of this channel into this root".
//
// The request is untrusted input from a less privileged process, and it is
// treated as one. Nothing about it is taken on faith: the metadata is refreshed
// here, the channel head is resolved here, and every policy check runs here
// against what this process resolved. The requested version only has to *agree*
// with that — it names what the caller expects to happen, and the helper refuses
// to do anything else. In particular a caller cannot pick an older release than
// the channel head, even one still newer than what is installed: that choice is
// the publisher's, made in signed metadata, and not the caller's.
//
// A request for the version that is already installed succeeds without doing
// anything, so a helper that is started twice for the same update — a retried
// prompt, a second instance — is harmless.
//
// The Updater must be configured for ElevationNone. A helper that elevates again
// would ask for privileges it already holds, in a loop.
func (u *Updater) ApplyRequested(ctx context.Context, version string) error {
	if u.policy.Elevation != ElevationNone {
		return fmt.Errorf("%w: the privileged side of an elevated update must not elevate again", ErrConfig)
	}
	if version == "" {
		return fmt.Errorf("%w: no requested version", ErrConfig)
	}
	// Repaired here as well as in Apply: a request for the version that is
	// already installed never reaches Apply, and a helper is exactly the process
	// that can write a root whose launcher an interrupted swap left missing.
	u.repairLauncher()

	rel, err := u.CheckForUpdate(ctx)
	if err != nil {
		return err
	}
	if rel == nil {
		installed, err := u.installedVersion()
		if err != nil {
			return err
		}
		if installed == version {
			return nil
		}
		return fmt.Errorf("%w: %s was requested, and channel %q offers no update to this install (%q installed)",
			ErrStale, version, u.channel, installed)
	}
	if rel.Descriptor.Version != version {
		return fmt.Errorf("%w: %s was requested, but channel %q resolves to %s",
			ErrStale, version, u.channel, rel.Descriptor.Version)
	}
	return u.Apply(ctx, rel)
}

// RequestApplier answers the privileged helper service's requests
// (elevate.Applier) with ApplyRequested, so a host's helper daemon does not have
// to assemble that path itself.
//
// Everything that decides what gets installed stays on the privileged side:
// Options builds this side's own trust client, with the anchor the host's build
// embeds, for the one root the request names; the channel is the helper's, not
// the caller's; and ApplyRequested resolves the channel head itself and refuses
// any other version (AGENTS.md §1.4).
type RequestApplier struct {
	// Channel is the only channel this helper installs. A request for another
	// one is refused before any options are built: which stream of releases a
	// machine follows is the host's configuration, not a choice the unprivileged
	// caller gets to make for root.
	Channel string

	// Options returns the updater options for one install root. cacheDir is
	// elevate.PrivilegedCacheDir(root): the trust client built here must keep
	// its metadata and targets there, never in a directory the caller can write
	// (§14.8, T23). Root and Channel are set from the request and from Channel
	// afterwards; an elevation mode or Elevator in the result is a
	// misconfiguration, not something to strip silently.
	Options func(root, cacheDir string) (Options, error)
}

var _ elevate.Applier = RequestApplier{}

// Apply installs the requested version into the requested root, or refuses.
func (a RequestApplier) Apply(ctx context.Context, req elevate.Request) error {
	if a.Options == nil || a.Channel == "" {
		return fmt.Errorf("%w: a RequestApplier needs a Channel and an Options function", ErrConfig)
	}
	if req.Channel != a.Channel {
		return fmt.Errorf("%w: channel %q was requested, this helper installs %q", ErrPolicy, req.Channel, a.Channel)
	}
	o, err := a.Options(req.Root, elevate.PrivilegedCacheDir(req.Root))
	if err != nil {
		return err
	}
	if o.Policy.Elevation != ElevationNone || o.Elevator != nil {
		return fmt.Errorf("%w: the privileged side of an elevated update must not elevate again", ErrConfig)
	}
	o.Root = req.Root
	o.Channel = a.Channel
	u, err := New(o)
	if err != nil {
		return err
	}
	return u.ApplyRequested(ctx, req.Version)
}
