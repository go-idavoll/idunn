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

package updater_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/hook"
	"github.com/go-idavoll/idunn/core/release"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
)

const (
	root    = "/opt/app"
	channel = "stable"
	appName = "acme-app"
)

// fakeTrust stands in for the go-tuf client. Everything it returns is treated as
// already verified, which is the boundary the design draws: by the time the
// updater sees a descriptor or a target, whether to trust it has been settled.
type fakeTrust struct {
	refreshErr error
	refreshes  int

	descriptor *release.Descriptor
	latestErr  error
	asked      []string

	targets   map[string][]byte
	targetErr map[string]error

	// fetched records every target whose bytes were actually handed over. It is
	// how a test tells "verified" from "downloaded again".
	fetched []string
}

func (f *fakeTrust) Refresh() error {
	f.refreshes++
	return f.refreshErr
}

func (f *fakeTrust) LatestRelease(ch, goos, goarch string) (*release.Descriptor, error) {
	f.asked = append(f.asked, ch+"/"+goos+"-"+goarch)
	if f.latestErr != nil {
		return nil, f.latestErr
	}
	return f.descriptor, nil
}

func (f *fakeTrust) Target(path string) ([]byte, error) {
	if err := f.targetErr[path]; err != nil {
		return nil, err
	}
	data, ok := f.targets[path]
	if !ok {
		return nil, errors.New("no such target: " + path)
	}
	f.fetched = append(f.fetched, path)
	return data, nil
}

// SignedLength and Accepts are the trust layer's half of delta stage 1: how long
// a target is, and whether bytes obtained some other way are it. Both answer
// from the same map Target serves.
func (f *fakeTrust) SignedLength(path string) (int64, error) {
	data, ok := f.targets[path]
	if !ok {
		return 0, errors.New("no such target: " + path)
	}
	return int64(len(data)), nil
}

func (f *fakeTrust) Accepts(path string, data []byte) error {
	want, ok := f.targets[path]
	if !ok {
		return errors.New("no such target: " + path)
	}
	if !bytes.Equal(want, data) {
		return errors.New("bytes are not target " + path)
	}
	return nil
}

// hooks records every call the host would see, so a test can assert what ran and
// in which order rather than only what ended up on disk.
type hooks struct {
	fs *fsx.Mem

	checkErr  error
	checked   int
	migrated  int
	rolled    int
	migrateEr error
	rollbackE error

	confirm    bool
	confirmErr error
	prompted   []string

	shutdowns    int
	shutdownErr  error
	events       []hook.Event
	outcomes     []hook.Outcome
	reportErr    error
	lastHookCtx  hook.Context
	migrateMarks []string

	// beforeMigrate runs at the top of Migrate, which is the moment the staged
	// tree is complete and the swap has not happened. It is how a test reaches
	// in between the two.
	beforeMigrate func()
}

func (h *hooks) Check(c hook.Context) error {
	h.checked++
	h.lastHookCtx = c
	return h.checkErr
}

func (h *hooks) Migrate(c hook.Context) error {
	if h.beforeMigrate != nil {
		h.beforeMigrate()
	}
	h.migrated++
	h.lastHookCtx = c
	if h.migrateEr != nil {
		return h.migrateEr
	}
	h.migrateMarks = append(h.migrateMarks, c.ToVersion)
	return fsx.WriteFileAtomic(h.fs, "/appdata/schema", []byte(c.ToVersion), 0o644)
}

func (h *hooks) Rollback(c hook.Context) error {
	h.rolled++
	h.lastHookCtx = c
	if h.rollbackE != nil {
		return h.rollbackE
	}
	if c.FromVersion == "" {
		return h.fs.RemoveAll("/appdata/schema")
	}
	return fsx.WriteFileAtomic(h.fs, "/appdata/schema", []byte(c.FromVersion), 0o644)
}

func (h *hooks) Confirm(_ context.Context, question string) (bool, error) {
	h.prompted = append(h.prompted, question)
	return h.confirm, h.confirmErr
}

func (h *hooks) RequestShutdown(hook.Context) error {
	h.shutdowns++
	return h.shutdownErr
}

func (h *hooks) OnEvent(e hook.Event) { h.events = append(h.events, e) }

func (h *hooks) Report(_ context.Context, o hook.Outcome) error {
	h.outcomes = append(h.outcomes, o)
	return h.reportErr
}

func (h *hooks) phases() []hook.Phase {
	var out []hook.Phase
	for _, e := range h.events {
		out = append(out, e.Phase)
	}
	return out
}

// fakeLock is the host's exclusive application lock.
type fakeLock struct {
	// heldBySomeoneElse counts how many TryLock calls report the lock as taken
	// before it becomes available. -1 means it never becomes available.
	heldBySomeoneElse int
	err               error
	attempts          int
	unlocked          int
	unlockErr         error
}

func (l *fakeLock) TryLock(context.Context) (bool, error) {
	l.attempts++
	if l.err != nil {
		return false, l.err
	}
	if l.heldBySomeoneElse < 0 {
		return false, nil
	}
	if l.attempts <= l.heldBySomeoneElse {
		return false, nil
	}
	return true, nil
}

func (l *fakeLock) Unlock() error {
	l.unlocked++
	return l.unlockErr
}

// fakeElevator records the privileged apply the updater would have delegated.
type fakeElevator struct {
	calls int
	err   error
	seen  string
}

func (e *fakeElevator) Apply(_ context.Context, root string, d *release.Descriptor) error {
	e.calls++
	e.seen = root + "@" + d.Version
	return e.err
}

// fixture is one install root plus everything wired around it.
type fixture struct {
	t     *testing.T
	fs    *fsx.Mem
	trust *fakeTrust
	hooks *hooks
	opts  updater.Options
}

func descriptor(version string, files ...release.FileRef) *release.Descriptor {
	return &release.Descriptor{
		SchemaVersion: release.SchemaVersion,
		LayoutSchema:  release.LayoutSchema,
		Name:          appName,
		Version:       version,
		Channel:       channel,
		OS:            "linux",
		Arch:          "amd64",
		Files:         files,
	}
}

func ref(target, dst string) release.FileRef {
	return release.FileRef{Target: target, Dst: dst, Kind: release.KindExe, Mode: 0o755}
}

// newFixture prepares an install root with the given version already installed
// ("" for a machine with nothing on it) and a channel offering `offers`.
func newFixture(t *testing.T, installedVersion, offers string) *fixture {
	t.Helper()

	m := fsx.NewMem()
	if err := m.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := m.MkdirAll("/appdata", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if installedVersion != "" {
		dir, err := layout.VersionDir(root, installedVersion)
		if err != nil {
			t.Fatalf("VersionDir: %v", err)
		}
		if err := m.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := fsx.WriteFileAtomic(m, fsx.Join(dir, "app"), []byte(installedVersion), 0o755); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := layout.SetPointer(m, root, installedVersion); err != nil {
			t.Fatalf("SetPointer: %v", err)
		}
		if err := layout.WriteInstall(m, root, layout.Install{
			Name: appName, Version: installedVersion, LayoutSchema: release.LayoutSchema,
		}); err != nil {
			t.Fatalf("WriteInstall: %v", err)
		}
		if err := fsx.WriteFileAtomic(m, "/appdata/schema", []byte(installedVersion), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	tr := &fakeTrust{
		descriptor: descriptor(offers, ref("targets/app", "app"), ref("targets/plugin.so", "lib/plugin.so")),
		targets: map[string][]byte{
			"targets/app":       []byte("binary " + offers),
			"targets/plugin.so": []byte("library " + offers),
		},
		targetErr: map[string]error{},
	}
	h := &hooks{fs: m, confirm: true}

	return &fixture{
		t:     t,
		fs:    m,
		trust: tr,
		hooks: h,
		opts: updater.Options{
			Trust:   tr,
			FS:      m,
			Root:    root,
			Channel: channel,
			OS:      "linux",
			Arch:    "amd64",
			Now:     func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
			Migrate: h,
			Observe: h,
			Report:  h,
		},
	}
}

func (f *fixture) updater() *updater.Updater {
	f.t.Helper()
	u, err := updater.New(f.opts)
	if err != nil {
		f.t.Fatalf("New: %v", err)
	}
	return u
}

// run does a full check-then-apply cycle and returns Apply's error.
func (f *fixture) run() error {
	f.t.Helper()
	u := f.updater()
	r, err := u.CheckForUpdate(context.Background())
	if err != nil {
		return err
	}
	if r == nil {
		f.t.Fatal("CheckForUpdate found no update to apply")
	}
	return u.Apply(context.Background(), r)
}

func (f *fixture) pointer() string {
	f.t.Helper()
	v, err := layout.PointerTarget(f.fs, root)
	if err != nil {
		f.t.Fatalf("PointerTarget: %v", err)
	}
	return v
}

func (f *fixture) stateVersion() string {
	f.t.Helper()
	in, err := layout.ReadInstall(f.fs, root)
	if err != nil {
		f.t.Fatalf("ReadInstall: %v", err)
	}
	if in == nil {
		return ""
	}
	return in.Version
}

func (f *fixture) hostState() string {
	f.t.Helper()
	b, err := fsx.ReadFile(f.fs, "/appdata/schema", 64)
	if err != nil {
		if fsx.IsNotExist(err) {
			return ""
		}
		f.t.Fatalf("read host state: %v", err)
	}
	return string(b)
}

func (f *fixture) exists(name string) bool {
	f.t.Helper()
	_, err := f.fs.Stat(name)
	if err != nil && !fsx.IsNotExist(err) {
		f.t.Fatalf("Stat(%s): %v", name, err)
	}
	return err == nil
}

func (f *fakeTrust) SignedSHA256(path string) (string, error) {
	data, ok := f.targets[path]
	if !ok {
		return "", errors.New("no such target: " + path)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
