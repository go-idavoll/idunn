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

// Package integrate registers an installation with the operating system outside
// its install root — today the Windows "Installed apps" entry — and removes
// exactly what it registered (docs/design.md §5, §13, backlog IDN-36).
//
// Everything an installation puts outside its root is recorded in a manifest,
// <root>/.updater/integrations.json, the way Windows Installer records what an
// MSI wrote. The record is written before the registration it describes takes
// effect, so a crash between the two leaves a record of something that may not
// exist — which Unregister handles — and never a registration nobody knows
// about. Unregister reads the record and reverses it; it guesses nothing.
//
// Three rules shape the rest.
//
// What an integration shows is derived state, never a source of truth. The
// version an entry displays is read from the install pointer every time it is
// written, and Refresh rewrites it whenever the two disagree. A registry value
// that could not be written is reported and nothing else: the swap is the
// transaction, and the registry is not part of it.
//
// Nothing is removed that idunn did not write for this root. Every entry carries
// the root it belongs to, and an entry that names another root, or none, is left
// alone by Unregister and refused by Register.
//
// Nothing here is a trust decision, and nothing needs the network. The operating
// system is reached only through an injected interface (Registry), so every path
// is testable on every platform.
package integrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/internal/layout"
)

// The errors of this package. Every one of them is an ErrIntegrate.
var (
	// ErrIntegrate is the class of every error here.
	ErrIntegrate = errors.New("integrate")

	// ErrNotSupported reports an integration this platform, or this
	// configuration, has no way to register or remove — a Windows entry with
	// no registry to write it to.
	ErrNotSupported = fmt.Errorf("%w: not supported here", ErrIntegrate)

	// ErrConflict refuses to register over an entry that belongs to something
	// else: another installation of the same application, or software that is
	// not idunn's. Nothing was changed.
	ErrConflict = fmt.Errorf("%w: the entry belongs to something else", ErrIntegrate)

	// ErrMissing reports a recorded entry that is no longer registered —
	// removed by hand or by a cleanup tool. Refresh cannot bring it back, as
	// the values it was registered with are the host's, not the record's;
	// registering it again can.
	ErrMissing = fmt.Errorf("%w: a recorded entry is no longer registered", ErrIntegrate)

	// ErrNotInstalled refuses to register an integration for a root with no
	// live installation: there is nothing for it to describe.
	ErrNotInstalled = fmt.Errorf("%w: the root holds no installation", ErrIntegrate)

	// ErrManifest reports a manifest that cannot be read or does not validate.
	// It is never taken for "nothing registered": the answer is acted on by
	// deleting.
	ErrManifest = fmt.Errorf("%w: integrations manifest", ErrIntegrate)
)

// Scope is whose integration it is: the current user's, or every user's.
type Scope string

// The scopes. They follow the install root's: a per-user installation registers
// with the user, a system-wide one with the machine, which needs administrator
// rights.
const (
	ScopeUser    Scope = "user"
	ScopeMachine Scope = "machine"
)

func (s Scope) valid() bool { return s == ScopeUser || s == ScopeMachine }

// Options configures an Integrator.
type Options struct {
	// FS is the filesystem the install root is read and the manifest written
	// through. It must be able to Lstat (fsx.LstatFS): sizing an installation
	// never follows a link out of it.
	FS fsx.FS

	// Root is the install root.
	Root string

	// Registry is the Windows registry, OSRegistry() in a real program. Nil
	// on a platform without one; an operation that needs it then fails with
	// ErrNotSupported, and one that finds nothing recorded succeeds.
	Registry Registry

	// Now is the clock an entry's install date is taken from. Nil means
	// time.Now.
	Now func() time.Time

	// Observe receives what is worth telling a user and is not an error — an
	// entry left alone because it was not idunn's. Optional.
	Observe hook.Observer
}

// Integrator registers, refreshes and removes the OS integrations of one
// installation. It is immutable after New.
type Integrator struct {
	fs       fsx.FS
	root     string
	registry Registry
	now      func() time.Time
	observe  hook.Observer
}

// New validates o and returns an Integrator.
func New(o Options) (*Integrator, error) {
	if o.FS == nil {
		return nil, fmt.Errorf("%w: no filesystem", ErrIntegrate)
	}
	if _, ok := o.FS.(fsx.LstatFS); !ok {
		return nil, fmt.Errorf("%w: the filesystem cannot tell a link from its target: %w", ErrIntegrate, fsx.ErrNotSupported)
	}
	if o.Root == "" || !fsx.IsAbs(o.Root) {
		return nil, fmt.Errorf("%w: the install root %q is not absolute", ErrIntegrate, o.Root)
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Integrator{fs: o.FS, root: fsx.Clean(o.Root), registry: o.Registry, now: now, observe: o.Observe}, nil
}

// Recorded reports whether root records any integration. It reads the manifest
// and nothing else, so a caller about to remove the root can refuse before it
// changes anything when it would have no way to unregister what is recorded. An
// unreadable manifest is an error, never false.
func Recorded(f fsx.FS, root string) (bool, error) {
	m, err := readManifest(f, fsx.Clean(root))
	if err != nil {
		return false, err
	}
	return len(m.Entries) > 0, nil
}

// Registered returns the recorded integrations of the root, in the order they
// were registered.
func (i *Integrator) Registered() ([]Record, error) {
	m, err := readManifest(i.fs, i.root)
	if err != nil {
		return nil, err
	}
	return m.Entries, nil
}

// RegisterUninstallEntry registers e as the installation's Windows "Installed
// apps" entry, or updates the one already registered under e.ID for this root.
//
// It is also how a UI sidecar sets what Modify and Repair do: it registers the
// entry again with ModifyPath and Repair set. A later registration that leaves
// them empty — the installer run again — resets them to hidden.
//
// The version, install location, size and uninstall commands are derived from
// the root, never taken from e. An entry registered under e.ID for another root
// that still holds an installation, or by software other than idunn, is refused
// with ErrConflict before anything is written.
func (i *Integrator) RegisterUninstallEntry(ctx context.Context, e UninstallEntry) error {
	if err := e.validate(); err != nil {
		return err
	}
	if i.registry == nil {
		return fmt.Errorf("%w: the Installed apps entry needs the Windows registry", ErrNotSupported)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	version, err := layout.PointerTarget(i.fs, i.root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrate, err)
	}
	if version == "" {
		return fmt.Errorf("%w: %s", ErrNotInstalled, i.root)
	}

	rec := e.record()
	existing, err := i.registry.ReadKey(rec.hive(), rec.keyPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		existing = nil
	case err != nil:
		return fmt.Errorf("%w: reading %s: %w", ErrIntegrate, rec, err)
	}
	fresh, err := i.claim(rec, existing)
	if err != nil {
		return err
	}

	set, err := i.derived(rec, version)
	if err != nil {
		return err
	}
	for name, v := range e.values(i.root) {
		set[name] = v
	}
	if fresh || existing[valueInstallDate].S == "" {
		set[valueInstallDate] = String(i.now().Format("20060102"))
	}
	var remove []string
	if e.ModifyPath == "" {
		remove = append(remove, valueModifyPath)
	}
	if e.Publisher == "" {
		remove = append(remove, valuePublisher)
	}

	// The record first. A crash after it and before the key leaves a record of
	// an entry that does not exist, which Unregister passes over; the other
	// order could leave an entry nothing knows to remove.
	if err := i.record(rec); err != nil {
		return err
	}
	if err := i.registry.WriteKey(rec.hive(), rec.keyPath(), set, remove); err != nil {
		return fmt.Errorf("%w: writing %s: %w", ErrIntegrate, rec, err)
	}
	return nil
}

// Refresh brings the derived values of every recorded integration in line with
// the version the install pointer names: an update that committed, or a
// recovery that finished one, changes what the entry has to say.
//
// It writes only what differs, so a start that finds everything current costs a
// read and changes nothing — and in a system-wide installation, whose entry an
// unprivileged process cannot write, succeeds. A root with nothing recorded, or
// with no live version (an uninstall under way), has nothing to refresh.
//
// A caller reports an error and carries on. The update it follows has
// committed, and an entry that says the wrong version is not a reason to undo
// it.
func (i *Integrator) Refresh(ctx context.Context) error {
	m, err := readManifest(i.fs, i.root)
	if err != nil || len(m.Entries) == 0 {
		return err
	}
	if i.registry == nil {
		return fmt.Errorf("%w: %d recorded integrations need the Windows registry", ErrNotSupported, len(m.Entries))
	}
	version, err := layout.PointerTarget(i.fs, i.root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrate, err)
	}
	if version == "" {
		return nil
	}

	var failed []error
	for _, rec := range m.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := i.refresh(rec, version); err != nil {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

func (i *Integrator) refresh(rec Record, version string) error {
	existing, err := i.registry.ReadKey(rec.hive(), rec.keyPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: %s", ErrMissing, rec)
	case err != nil:
		return fmt.Errorf("%w: reading %s: %w", ErrIntegrate, rec, err)
	}
	if !i.owns(existing) {
		return fmt.Errorf("%w: %s is registered for %q, not for this installation", ErrConflict, rec, existing[valueOwner].S)
	}
	icon, err := rec.icon(i.root, version)
	if err != nil {
		return err
	}
	if existing[valueDisplayVersion] == String(version) && existing[valueDisplayIcon] == String(icon) {
		return nil
	}
	set, err := i.derived(rec, version)
	if err != nil {
		return err
	}
	if err := i.registry.WriteKey(rec.hive(), rec.keyPath(), set, nil); err != nil {
		return fmt.Errorf("%w: writing %s: %w", ErrIntegrate, rec, err)
	}
	return nil
}

// Unregister removes every recorded integration, newest first, and the manifest
// with them.
//
// Each record is dropped from the manifest once what it describes is gone, so an
// interrupted run leaves exactly what is still registered on record, and running
// it again continues. An entry that no longer exists is simply dropped; one that
// belongs to another root or to other software is left where it is — it is not
// this installation's to remove — and dropped from the record too.
func (i *Integrator) Unregister(ctx context.Context) error {
	m, err := readManifest(i.fs, i.root)
	if err != nil {
		return err
	}
	if len(m.Entries) > 0 && i.registry == nil {
		return fmt.Errorf("%w: %d recorded integrations need the Windows registry to be removed", ErrNotSupported, len(m.Entries))
	}
	for len(m.Entries) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		last := len(m.Entries) - 1
		if err := i.unregister(m.Entries[last]); err != nil {
			return err
		}
		m.Entries = m.Entries[:last]
		if len(m.Entries) > 0 {
			if err := writeManifest(i.fs, i.root, m); err != nil {
				return err
			}
		}
	}
	if err := i.fs.Remove(layout.Integrations(i.root)); err != nil && !fsx.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	return nil
}

func (i *Integrator) unregister(rec Record) error {
	existing, err := i.registry.ReadKey(rec.hive(), rec.keyPath())
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("%w: reading %s: %w", ErrIntegrate, rec, err)
	}
	if !i.owns(existing) {
		i.emit(hook.PhaseUninstall, fmt.Sprintf("%s belongs to %q, not to this installation, and was left alone", rec, existing[valueOwner].S))
		return nil
	}
	if err := i.registry.DeleteKey(rec.hive(), rec.keyPath()); err != nil {
		return fmt.Errorf("%w: removing %s: %w", ErrIntegrate, rec, err)
	}
	return nil
}

// claim decides whether an existing entry may be written for this root. It
// reports fresh when the entry is new to this root: absent, or taken over from
// an installation whose root is gone.
func (i *Integrator) claim(rec Record, existing map[string]Value) (fresh bool, err error) {
	switch owner := existing[valueOwner].S; {
	case existing == nil:
		return true, nil
	case i.owns(existing):
		return false, nil
	case owner == "":
		return false, fmt.Errorf("%w: %s was not registered by idunn", ErrConflict, rec)
	case i.abandoned(owner):
		// The root that entry was registered for holds no installation any
		// more — deleted by hand, without the uninstall. Its entry points at
		// nothing, and the installation that is here is the application's.
		i.emit(hook.PhaseCommit, fmt.Sprintf("%s pointed at %s, which holds no installation; it now describes this one", rec, owner))
		return true, nil
	default:
		return false, fmt.Errorf("%w: %s is registered for the installation at %s", ErrConflict, rec, owner)
	}
}

// owns reports whether an entry was registered for this root.
func (i *Integrator) owns(existing map[string]Value) bool {
	return existing != nil && sameRoot(existing[valueOwner].S, windowsPath(i.root))
}

// abandoned reports whether the root an entry names holds no idunn state at all.
// Only a definite "does not exist" counts: a root that cannot be inspected is
// not abandoned.
func (i *Integrator) abandoned(owner string) bool {
	other := fsx.Clean(strings.ReplaceAll(owner, `\`, "/"))
	if !fsx.IsAbs(other) {
		return false
	}
	_, err := fsx.Lstat(i.fs, layout.Meta(other))
	return fsx.IsNotExist(err)
}

// record adds rec to the manifest, or replaces the record with the same
// identity. It writes nothing when the record is already there as it is.
func (i *Integrator) record(rec Record) error {
	m, err := readManifest(i.fs, i.root)
	if err != nil {
		return err
	}
	for n, have := range m.Entries {
		if have.sameEntry(rec) {
			if have == rec {
				return nil
			}
			m.Entries[n] = rec
			return writeManifest(i.fs, i.root, m)
		}
	}
	if len(m.Entries) >= maxEntries {
		return fmt.Errorf("%w: more than %d integrations", ErrManifest, maxEntries)
	}
	m.Entries = append(m.Entries, rec)
	return writeManifest(i.fs, i.root, m)
}

func (i *Integrator) emit(phase hook.Phase, msg string) {
	if i.observe == nil {
		return
	}
	i.observe.OnEvent(hook.Event{Phase: phase, Message: msg, Progress: -1})
}
