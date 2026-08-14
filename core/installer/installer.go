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

// Package installer performs the first-time install bootstrap.
//
// A fresh install is the same transaction as an update with an empty FromVersion,
// plus a downgrade preflight: installing over an existing newer install is refused
// unless explicitly allowed. See docs/design.md §5, §14.6.
package installer

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/timefloor"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

// ErrRefused is the preflight's rejection: an installation already exists that
// this installer must not touch.
//
// It is its own class because it is not a failure. An installer binary that
// finds a newer installation has done its job by refusing, and the caller's
// answer is to run the updater, not to retry (§14.6).
var ErrRefused = errors.New("installer refused")

// VersionResolver is the optional capability of resolving one explicitly named
// version instead of the channel head. *trust.Client provides it.
//
// It is separate from updater.Resolver because it is not part of the normal
// update path: naming a version bypasses the publisher's statement about which
// release is current. The descriptor is verified either way — what changes is
// who chose it.
type VersionResolver interface {
	ReleaseVersion(goos, goarch, version string) (*release.Descriptor, error)
}

// Options configures a first-time install.
type Options struct {
	// Updater carries the already-configured trust client, filesystem and hooks.
	Updater updater.Options

	// Version selects an explicit version instead of the channel head. Empty
	// means "whatever the channel currently points at".
	Version string

	// AllowDowngrade permits installing over a newer existing install. Default
	// false: the preflight refuses and leaves the existing install untouched.
	AllowDowngrade bool
}

// Install performs the first-time install into Options.Updater.Root. It runs the
// downgrade preflight, then the ordinary verified transaction, so a failed install
// leaves no partial tree behind.
func Install(ctx context.Context, o Options) error {
	if o.Updater.FS == nil {
		return fmt.Errorf("%w: no filesystem", updater.ErrConfig)
	}
	if o.Version != "" && !release.ValidVersion(o.Version) {
		return fmt.Errorf("%w: requested version %q is not SemVer", updater.ErrConfig, o.Version)
	}

	// The clock is an input to metadata expiry, so a clock below the known-good
	// floor is refused before anything that depends on it — including the
	// network. A first install usually has no persisted floor yet, and then the
	// build time is the whole of it (§14.7, T22).
	floor := timefloor.Floor{FS: o.Updater.FS, Root: o.Updater.Root, BuildTime: o.Updater.BuildTime}
	if err := floor.Check(now(o)); err != nil {
		return err
	}

	// The preflight runs before anything else, including the network. An
	// installer that discovers only after downloading that it must not proceed
	// has already spent the user's bandwidth on a decision it could have made
	// first.
	existing, err := preflightState(o)
	if err != nil {
		return err
	}

	// A downgrade the operator asked for has to be permitted in the transaction
	// too, or the preflight would allow what Apply then refuses.
	o.Updater.Policy.AllowDowngrade = o.Updater.Policy.AllowDowngrade || o.AllowDowngrade

	r, err := resolve(ctx, o)
	if err != nil {
		return err
	}
	if r == nil {
		// The channel offers exactly what is installed. For an installer that is
		// success: the requested state is the state on disk.
		return recordKnownGood(floor, now(o))
	}
	if err := preflightVersion(existing, r.Descriptor.Version, o.AllowDowngrade); err != nil {
		return err
	}

	u, err := updater.New(o.Updater)
	if err != nil {
		return err
	}
	if err := u.Apply(ctx, r); err != nil {
		return err
	}
	return recordKnownGood(floor, now(o))
}

// recordKnownGood raises the time floor once an install has succeeded.
//
// It runs here rather than right after the refresh so that a failed install
// leaves the root exactly as it found it — an installer that refuses or fails
// must write nothing, and a floor file is still a write. The evidence is the
// same either way: this machine has been at this local time with a repository it
// trusts answering.
//
// A failure to record it is reported rather than swallowed, and says what
// happened: the install is done, and re-running the installer is a safe way to
// retry the record.
func recordKnownGood(floor timefloor.Floor, at time.Time) error {
	if err := floor.Observe(at); err != nil {
		return fmt.Errorf("the install completed but the known-good time could not be recorded: %w", err)
	}
	return nil
}

// resolve picks the release to install: the channel head, or the explicitly
// named version.
//
// It goes to the trust client directly rather than through Updater.CheckForUpdate
// so that the installer's own refusal is the one the caller sees. Both would
// refuse an install over a newer version, but only this package can say "use the
// application's own updater" — which is the whole point of the check, and useless
// advice buried under a generic policy error (§14.6).
func resolve(ctx context.Context, o Options) (*updater.Release, error) {
	if o.Updater.Trust == nil {
		return nil, fmt.Errorf("%w: no trust client", updater.ErrConfig)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The refresh is not optional, and not even when the version is named:
	// expiry, rollback and freeze are checked in it, and a pinned version
	// resolved from stale metadata is exactly the freeze attack (§11.3 T5).
	if err := o.Updater.Trust.Refresh(); err != nil {
		return nil, err
	}

	var (
		d   *release.Descriptor
		err error
	)
	if o.Version == "" {
		d, err = o.Updater.Trust.LatestRelease(o.Updater.Channel, goosOf(o), goarchOf(o))
	} else {
		vr, ok := o.Updater.Trust.(VersionResolver)
		if !ok {
			return nil, fmt.Errorf("%w: this trust client cannot resolve an explicit version", updater.ErrConfig)
		}
		d, err = vr.ReleaseVersion(goosOf(o), goarchOf(o), o.Version)
	}
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, fmt.Errorf("%w: the channel resolved to no release", updater.ErrConfig)
	}

	installed, err := layout.PointerTarget(o.Updater.FS, o.Updater.Root)
	if err != nil {
		return nil, err
	}
	if installed == d.Version {
		return nil, nil
	}
	return &updater.Release{Descriptor: d, FromVersion: installed}, nil
}

// preflightState reads the recorded install state and refuses what this
// installer must not touch.
//
// An unreadable state is a refusal, not an empty answer: the whole point of the
// check is to find out whether something is already installed, and "I could not
// tell" is not permission to overwrite it (§14.6).
func preflightState(o Options) (*layout.Install, error) {
	in, err := layout.ReadInstall(o.Updater.FS, o.Updater.Root)
	if err != nil {
		return nil, fmt.Errorf("%w: the existing install state could not be read (%w); "+
			"resolve this by hand rather than installing over it", ErrRefused, err)
	}
	if in == nil {
		return nil, nil
	}
	if in.LayoutSchema > release.LayoutSchema {
		return nil, fmt.Errorf("%w: the installation uses layout schema %d and this installer implements %d; "+
			"use the application's own updater", ErrRefused, in.LayoutSchema, release.LayoutSchema)
	}
	return in, nil
}

// preflightVersion refuses to install over an installation that is already at
// the target version or newer.
//
// This is the check that stops an old but still validly signed installer binary
// from walking over a newer install and its versions/ layout. It defends against
// stale binaries and operator mistakes; a local attacker who can already write
// the install root can also rewrite the state it reads, and that residual risk is
// documented rather than papered over (§11.5).
func preflightVersion(existing *layout.Install, target string, allowDowngrade bool) error {
	if existing == nil || allowDowngrade {
		return nil
	}
	c, err := release.Compare(existing.Version, target)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if c >= 0 {
		return fmt.Errorf("%w: %s is already installed and %s is not newer; "+
			"use the application's own updater", ErrRefused, existing.Version, target)
	}
	return nil
}

// InstalledVersion reports the version currently installed under root, or "" if
// there is no install. An unreadable or inconsistent install is an error, not "".
//
// It reads the real filesystem, because it is what an installer binary calls
// before it has built anything. The pointer is the authority — it decides which
// code actually runs — and the recorded state has to agree with it. A
// disagreement means a transaction was interrupted and recovery has not run yet;
// reporting either version as the truth would be a guess.
func InstalledVersion(root string) (string, error) {
	fs := fsx.OS()

	live, err := layout.PointerTarget(fs, root)
	if err != nil {
		return "", err
	}
	in, err := layout.ReadInstall(fs, root)
	if err != nil {
		return "", err
	}

	switch {
	case live == "" && in == nil:
		return "", nil
	case live == "" || in == nil:
		return "", fmt.Errorf("%w: the install pointer and the recorded state disagree "+
			"(pointer %q, state present: %v); run recovery first",
			layout.ErrLayout, live, in != nil)
	case live != in.Version:
		return "", fmt.Errorf("%w: current points at %s but the recorded state says %s; "+
			"run recovery first", layout.ErrLayout, live, in.Version)
	default:
		return live, nil
	}
}

// The running platform, named once so the defaulting below reads as the mirror
// of the updater's that it is.
const (
	runtimeGOOS   = runtime.GOOS
	runtimeGOARCH = runtime.GOARCH
)

// now reads the injected clock, mirroring the updater's defaulting so the
// installer and the updater it builds judge time the same way.
func now(o Options) time.Time {
	if o.Updater.Now != nil {
		return o.Updater.Now()
	}
	return time.Now()
}

// goosOf and goarchOf mirror the updater's defaulting, so an installer and the
// updater it builds resolve the same platform.
func goosOf(o Options) string {
	if o.Updater.OS != "" {
		return o.Updater.OS
	}
	return runtimeGOOS
}

func goarchOf(o Options) string {
	if o.Updater.Arch != "" {
		return o.Updater.Arch
	}
	return runtimeGOARCH
}
