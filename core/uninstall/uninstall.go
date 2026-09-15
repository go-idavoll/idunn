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

// Package uninstall removes an idunn installation: the pointer, the version
// directories, idunn's own state, the launcher, and — when the user asks — the
// application's data (docs/design.md §5, backlog IDN-35).
//
// It is the launcher's `--uninstall`, and it lives here rather than in
// cmd/launcher so a host that writes its own launcher removes an installation
// the same way.
//
// Three properties shape it.
//
// It needs nothing from the network. No TUF client, no fetch, no trust
// decision: an application has to be removable when its update server is gone
// and its metadata has long expired.
//
// It removes only what idunn put there. The root must hold an installation — a
// valid install state or journal, naming this application when the host says
// which one that is — and only the layout's own names are removed. Anything else
// in the root is left where it is, and so is the root. Nothing is ever followed
// through a symlink, a junction or any other reparse point: a link below the root
// is removed as a link, and what it points at is not touched.
//
// It survives a crash. An UNINSTALLING record goes into the journal before
// anything is removed, and the journal is the last file to go, so an interrupted
// uninstall leaves a tree that neither the launcher nor the updater will run or
// update (txn.ErrUninstalling), and that running the uninstall again finishes.
package uninstall

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/integrate"
	"github.com/go-idavoll/idunn/core/txn"
	"github.com/go-idavoll/idunn/internal/launcherfile"
	"github.com/go-idavoll/idunn/internal/layout"
)

// The refusals and outcomes of an uninstall. Every one of them is an ErrUninstall.
var (
	// ErrUninstall is the class of every error here.
	ErrUninstall = errors.New("uninstall")

	// ErrNotInstalled refuses a root that holds no installation, or an
	// installation of a different application. Nothing was changed.
	ErrNotInstalled = fmt.Errorf("%w: not an installation of this application", ErrUninstall)

	// ErrRefused reports that the host's BeforeUninstall declined. Nothing was
	// changed.
	ErrRefused = fmt.Errorf("%w: refused by the application", ErrUninstall)

	// ErrBusy reports that the application lock is held: an instance is
	// running. Nothing was changed.
	ErrBusy = fmt.Errorf("%w: the application is running", ErrUninstall)

	// ErrNotWritable reports a root this process may not change — a
	// system-wide installation, for a process without administrator rights.
	// Nothing was changed.
	ErrNotWritable = fmt.Errorf("%w: the install root needs administrator rights", ErrUninstall)

	// ErrUnsafeRoot refuses to uninstall with administrator rights from a root
	// that someone other than an administrator can change. A privileged delete
	// in such a tree can be redirected by a link planted between two of its
	// operations (the junction attack of design §14.8, T23). Nothing was
	// changed.
	ErrUnsafeRoot = fmt.Errorf("%w: the install root is not administrators-only, so it is not removed with administrator rights", ErrUninstall)

	// ErrIncomplete reports an uninstall that started and could not remove
	// everything — typically a file still in use. The installation stays
	// marked as being uninstalled, and running the uninstall again continues
	// where this one stopped.
	ErrIncomplete = fmt.Errorf("%w: not everything could be removed; close the application and run the uninstall again", ErrUninstall)
)

// AppLock is the host's exclusive application lock, the same shape as
// launch.AppLock and updater.AppLock.
type AppLock interface {
	TryLock(ctx context.Context) (bool, error)
	Unlock() error
}

// Options configures one uninstall.
type Options struct {
	// FS is the filesystem to work through. It must be able to Lstat
	// (fsx.LstatFS): telling a link from what it points at is the whole of
	// removing a tree safely.
	FS fsx.FS

	// Root is the install root.
	Root string

	// Name is the application this uninstall is for, as its install state
	// records it (the name a release is published under). When set, a root
	// that holds another application is refused. Empty skips the comparison,
	// not the check that the root holds an installation at all.
	Name string

	// Lock proves no instance is running. Optional; without it an uninstall
	// under a running application stops at the first file in use and reports
	// ErrIncomplete.
	Lock AppLock

	// Migrate is the host's migration hook. An interrupted update transaction
	// is recovered before the uninstall begins, exactly as at a start, and a
	// migration that ran has to be rolled back by the host's own code.
	Migrate hook.Migrator

	// Hooks lets the host refuse the uninstall and remove its own data.
	// Optional.
	Hooks hook.Uninstaller

	// Purge asks Hooks.PurgeData to remove the application's data.
	Purge bool

	// Caches are directories outside the root that belong to this
	// installation and go with it, such as the TUF cache the installer kept
	// (layout.InstallerCache). Each is removed like the root: never through a
	// link. A missing one is not an error.
	Caches []string

	// SelfPath is the launcher running this uninstall. It must sit directly in
	// Root. It is removed last, and on Windows — where a running executable
	// cannot be deleted — by a copy of itself once this process has exited
	// (see Finish). Empty leaves any launcher in the root as a file idunn did
	// not put there.
	SelfPath string

	// Registry is where the installation's recorded OS integrations — the
	// Windows "Installed apps" entry — are removed from (core/integrate,
	// IDN-36): integrate.OSRegistry() in a real program. An installation that
	// records integrations is refused without one, before anything is changed:
	// removing the root would lose the only record of what to unregister.
	Registry integrate.Registry

	// Observe receives progress events. Optional.
	Observe hook.Observer
}

// Result reports what an uninstall did.
type Result struct {
	// Name and Version identify what was uninstalled. Both are empty when an
	// uninstall found only the launcher left and finished that.
	Name    string
	Version string

	// Resumed is true when this run finished an uninstall that an earlier one
	// started.
	Resumed bool

	// Kept lists the entries of the root that were left because idunn did not
	// create them. The root itself is kept when this is not empty.
	Kept []string

	// RootRemoved is true when the root directory itself is gone. It is false
	// when something was kept, and on Windows while the launcher's removal is
	// still pending (SelfScheduled).
	RootRemoved bool

	// SelfScheduled is true when the launcher could not be removed by this
	// process — Windows, where it is executing — and a copy was started to
	// remove it, and the root, once this process has exited.
	SelfScheduled bool
}

// Run uninstalls the installation at o.Root.
func Run(ctx context.Context, o Options) (Result, error) {
	if err := o.check(); err != nil {
		return Result{}, err
	}
	root := fsx.Clean(o.Root)

	info, err := fsx.Lstat(o.FS, root)
	switch {
	case fsx.IsNotExist(err):
		return Result{}, fmt.Errorf("%w: %s does not exist", ErrNotInstalled, root)
	case err != nil:
		return Result{}, fmt.Errorf("%w: %w", ErrUninstall, err)
	case !isPlainDir(info):
		return Result{}, fmt.Errorf("%w: %s is a link or not a directory", ErrNotInstalled, root)
	}
	if err := checkRoot(root); err != nil {
		return Result{}, err
	}

	id, err := o.identify(root)
	if err != nil {
		return Result{}, err
	}
	res := Result{Name: id.name, Version: id.version, Resumed: id.resumed}

	// What was registered outside the root is removed from the record inside
	// it, so an installation whose record could not be acted on is not begun.
	recorded, err := integrate.Recorded(o.FS, root)
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	var integrations *integrate.Integrator
	if recorded {
		if o.Registry == nil {
			return res, fmt.Errorf("%w: the installation registered OS integrations and this uninstall has no way to remove them", ErrUninstall)
		}
		integrations, err = integrate.New(integrate.Options{FS: o.FS, Root: root, Registry: o.Registry, Observe: o.Observe})
		if err != nil {
			return res, fmt.Errorf("%w: %w", ErrUninstall, err)
		}
	}

	if o.Lock != nil {
		held, err := o.Lock.TryLock(ctx)
		if err != nil {
			return res, fmt.Errorf("%w: consulting the application lock: %w", ErrUninstall, err)
		}
		if !held {
			return res, ErrBusy
		}
		defer func() {
			if err := o.Lock.Unlock(); err != nil {
				o.emit("the application lock could not be released", err)
			}
		}()
	}

	hc := hook.Context{Ctx: ctx, FromVersion: id.version, Root: root}
	if !id.resumed {
		if o.Hooks != nil {
			if err := o.Hooks.BeforeUninstall(hc); err != nil {
				return res, fmt.Errorf("%w: %w", ErrRefused, err)
			}
		}
		if err := o.begin(ctx, root, id); err != nil {
			return res, err
		}
		o.emit("uninstalling "+describe(id), nil)
	} else {
		o.emit("finishing the uninstall of "+describe(id), nil)
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}

	// From here on the journal says UNINSTALLING. Every failure below leaves it
	// that way, and the next run picks up where this one stopped.
	//
	// The integrations go first: an "Installed apps" entry that outlives the
	// installation it lists is the one leftover a user sees, and its record is
	// in the directory removed last.
	if integrations != nil {
		if err := integrations.Unregister(ctx); err != nil {
			return res, fmt.Errorf("%w: %w", ErrIncomplete, err)
		}
	}
	if err := layout.RemovePointer(o.FS, root); err != nil {
		return res, fmt.Errorf("%w: %w", ErrIncomplete, err)
	}
	var failed []error
	if err := removeTree(o.FS, layout.Versions(root)); err != nil {
		failed = append(failed, err)
	}
	if o.Purge && o.Hooks != nil {
		if err := o.Hooks.PurgeData(hc); err != nil {
			failed = append(failed, fmt.Errorf("purging the application's data: %w", err))
		}
	}
	for _, dir := range o.Caches {
		if err := removeTree(o.FS, fsx.Clean(dir)); err != nil {
			failed = append(failed, err)
		}
	}
	if len(failed) > 0 {
		return res, fmt.Errorf("%w: %w", ErrIncomplete, errors.Join(failed...))
	}
	if err := removeMeta(o.FS, root); err != nil {
		return res, fmt.Errorf("%w: %w", ErrIncomplete, err)
	}

	// The installation is gone. What is left is the root and whatever sits in
	// it beside the layout.
	self := ""
	if o.SelfPath != "" {
		self = fsx.Base(fsx.Clean(o.SelfPath))
	}
	kept, err := sweepRoot(o.FS, root, self)
	if err != nil {
		return res, fmt.Errorf("%w: %w", ErrIncomplete, err)
	}
	res.Kept = kept
	if len(kept) > 0 {
		o.emit("kept what idunn did not install: "+strings.Join(kept, ", "), nil)
	}

	if self != "" {
		scheduled, err := removeSelf(o.FS, fsx.Join(root, self), root, len(kept) == 0)
		if err != nil {
			return res, fmt.Errorf("%w: removing the launcher: %w", ErrIncomplete, err)
		}
		if scheduled {
			res.SelfScheduled = true
			o.emit("uninstalled; the launcher is removed once it has exited", nil)
			return res, nil
		}
	}
	if len(kept) == 0 {
		if err := o.FS.Remove(root); err != nil && !fsx.IsNotExist(err) {
			// Everything idunn installed is gone; a root its parent will not
			// let go of is reported, not failed.
			o.emit("uninstalled, but the install directory itself could not be removed", err)
			return res, nil
		}
		res.RootRemoved = true
	}
	o.emit("uninstalled", nil)
	return res, nil
}

// identity is what an uninstall found in the root.
type identity struct {
	name    string
	version string

	// resumed: an earlier uninstall already began; the journal says so, or it
	// got as far as removing the journal and only the launcher is left.
	resumed bool

	// journal is the last record, when there is a journal.
	journal    txn.Record
	hasJournal bool
}

// identify decides whether root holds an installation this uninstall may remove.
//
// The journal and the install state are the evidence, in that order: an
// uninstall that was interrupted after it removed the state still has its
// journal, and an installation whose journal is gone still has its state. Either
// one that cannot be read is an error, never "not installed" — the answer is
// acted on by deleting.
func (o Options) identify(root string) (identity, error) {
	j, err := txn.Open(o.FS, root)
	if err != nil {
		return identity{}, fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	var id identity
	id.journal, id.hasJournal = j.Last()

	in, err := layout.ReadInstall(o.FS, root)
	if err != nil {
		return identity{}, fmt.Errorf("%w: %w", ErrUninstall, err)
	}

	switch {
	case id.hasJournal && id.journal.State == txn.StateUninstalling:
		id.name, id.version, id.resumed = id.journal.Name, id.journal.ToVersion, true
	case in != nil:
		id.name, id.version = in.Name, in.Version
	case id.hasJournal:
		// A first install that never committed: a journal, no state.
		id.name, id.version = id.journal.Name, id.journal.ToVersion
	case o.onlyLeftovers(root):
		// Journal and state are gone, the pointer and versions with them:
		// an earlier uninstall got as far as its last steps.
		id.resumed = true
		return id, nil
	default:
		return identity{}, fmt.Errorf("%w: %s holds no install state and no journal", ErrNotInstalled, root)
	}

	if o.Name != "" && id.name != o.Name {
		return identity{}, fmt.Errorf("%w: %s holds %q", ErrNotInstalled, root, id.name)
	}
	return id, nil
}

// onlyLeftovers reports whether root holds nothing but what the last steps of an
// uninstall leave behind: this launcher and its old images, idunn's scratch
// files, and an idunn state directory that no longer holds a journal or state.
// Only then is an uninstall resumed without either record, and only with a
// launcher to finish: without SelfPath there is nothing to say the directory is
// this launcher's.
func (o Options) onlyLeftovers(root string) bool {
	if o.SelfPath == "" {
		return false
	}
	self := fsx.Base(fsx.Clean(o.SelfPath))
	entries, err := o.FS.ReadDir(root)
	if err != nil {
		return false
	}
	sawSelf := false
	for _, e := range entries {
		switch name := e.Name(); {
		case name == self:
			sawSelf = true
		case name == layout.MetaName, isScratch(name), isLauncherLeftover(name, self):
		default:
			return false
		}
	}
	return sawSelf
}

// begin settles whatever the last run left behind and records the uninstall.
func (o Options) begin(ctx context.Context, root string, id identity) error {
	// An interrupted update is finished or undone first, exactly as a start
	// would, so the record below follows a resting state. A deferred update
	// is simply dropped with the installation it was waiting to change.
	if id.hasJournal {
		if _, err := txn.RecoverResult(ctx, o.FS, root, o.Migrate); err != nil {
			return fmt.Errorf("%w: settling the last update first: %w", ErrUninstall, err)
		}
	}
	j, err := txn.Open(o.FS, root)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	rec := txn.Record{State: txn.StateUninstalling, Name: id.name, ToVersion: id.version, Phase: hook.PhaseUninstall}
	if last, ok := j.Last(); ok {
		// The record carries the identity of the transaction it ends; the
		// journal refuses one that changes it.
		rec.Name, rec.FromVersion, rec.ToVersion = last.Name, last.FromVersion, last.ToVersion
	}
	if err := j.Append(rec); err != nil {
		return fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	return nil
}

// removeMeta removes idunn's state directory, the journal last.
func removeMeta(f fsx.FS, root string) error {
	meta := layout.Meta(root)
	entries, err := f.ReadDir(meta)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil
		}
		return err
	}
	var failed []error
	for _, e := range entries {
		if e.Name() == layout.JournalName {
			continue
		}
		if err := removeTree(f, fsx.Join(meta, e.Name())); err != nil {
			failed = append(failed, err)
		}
	}
	if len(failed) > 0 {
		return errors.Join(failed...)
	}
	if err := f.Remove(layout.Journal(root)); err != nil && !fsx.IsNotExist(err) {
		return err
	}
	return removeTree(f, meta)
}

// sweepRoot removes what idunn leaves directly in the root besides the layout —
// its scratch files and old launcher images — and returns the names it left
// alone. self, the launcher, is neither removed nor reported.
func sweepRoot(f fsx.FS, root, self string) ([]string, error) {
	entries, err := f.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var kept []string
	var failed []error
	for _, e := range entries {
		name := e.Name()
		switch {
		case self != "" && name == self:
		case isScratch(name), self != "" && isLauncherLeftover(name, self):
			if err := removeTree(f, fsx.Join(root, name)); err != nil {
				failed = append(failed, err)
			}
		default:
			kept = append(kept, name)
		}
	}
	return kept, errors.Join(failed...)
}

// isScratch matches the scratch files of fsx.WriteFileAtomic and
// layout.SetPointer, the same pattern recovery sweeps.
func isScratch(name string) bool {
	return strings.Contains(name, ".idunn-") && strings.HasSuffix(name, ".tmp")
}

// isLauncherLeftover matches an old launcher image moved aside by a replacement
// (launcherfile.AsideSuffix and a counter) or its scratch file.
func isLauncherLeftover(name, self string) bool {
	if name == self+launcherfile.NewSuffix {
		return true
	}
	n, ok := strings.CutPrefix(name, self+launcherfile.AsideSuffix)
	if !ok {
		return false
	}
	i, err := strconv.Atoi(n)
	return err == nil && i >= 1 && strconv.Itoa(i) == n
}

// removeTree removes name and everything below it without following a link.
//
// A symlink, a junction or any other entry that is not a plain directory is
// removed as itself: on Windows a junction reports as irregular rather than as a
// directory, and os.Remove deletes the junction, not its target. A plain
// directory is emptied first. A failure does not stop the walk — as much is
// removed as can be, so a second run has less to do — and every failure is
// returned. A name that does not exist is not an error.
func removeTree(f fsx.FS, name string) error {
	info, err := fsx.Lstat(f, name)
	if err != nil {
		if fsx.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !isPlainDir(info) {
		if err := f.Remove(name); err != nil && !fsx.IsNotExist(err) {
			return err
		}
		return nil
	}
	entries, err := f.ReadDir(name)
	if err != nil {
		return err
	}
	var failed []error
	for _, e := range entries {
		if err := removeTree(f, fsx.Join(name, e.Name())); err != nil {
			failed = append(failed, err)
		}
	}
	if len(failed) > 0 {
		return errors.Join(failed...)
	}
	if err := f.Remove(name); err != nil && !fsx.IsNotExist(err) {
		return err
	}
	return nil
}

// isPlainDir is a directory that is not also a link or reparse point.
func isPlainDir(info fs.FileInfo) bool {
	return info.IsDir() && info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0
}

func describe(id identity) string {
	switch {
	case id.name == "":
		return "the launcher"
	case id.version == "":
		return id.name
	default:
		return id.name + " " + id.version
	}
}

func (o Options) check() error {
	if o.FS == nil {
		return fmt.Errorf("%w: no filesystem", ErrUninstall)
	}
	if _, ok := o.FS.(fsx.LstatFS); !ok {
		return fmt.Errorf("%w: the filesystem cannot tell a link from its target: %w", ErrUninstall, fsx.ErrNotSupported)
	}
	if o.Root == "" {
		return fmt.Errorf("%w: no install root", ErrUninstall)
	}
	if o.SelfPath != "" && fsx.Dir(fsx.Clean(o.SelfPath)) != fsx.Clean(o.Root) {
		return fmt.Errorf("%w: the launcher %s is not directly in the root %s", ErrUninstall, o.SelfPath, o.Root)
	}
	if o.Purge && o.Hooks == nil {
		return fmt.Errorf("%w: a purge was asked for, but the application provides no way to remove its data", ErrUninstall)
	}
	root := fsx.Clean(o.Root)
	for _, c := range o.Caches {
		// Absolute and at least two directories deep: a cache is never a
		// volume or a top-level directory, and never overlaps the root.
		c = fsx.Clean(c)
		if !fsx.IsAbs(c) || len(fsx.Split(c)) < 3 || isWithin(root, c) || isWithin(c, root) {
			return fmt.Errorf("%w: cache %q is not an absolute directory of its own apart from the install root", ErrUninstall, c)
		}
	}
	return nil
}

// isWithin reports whether path is dir or below it.
func isWithin(dir, path string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// emit notifies the Observer if the host registered one.
func (o Options) emit(msg string, err error) {
	if o.Observe == nil {
		return
	}
	o.Observe.OnEvent(hook.Event{Phase: hook.PhaseUninstall, Message: msg, Progress: -1, Err: err})
}
