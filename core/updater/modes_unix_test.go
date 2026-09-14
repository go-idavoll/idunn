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

package updater_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/core/trust"
	"github.com/go-idavoll/idunn/core/updater"
	"github.com/go-idavoll/idunn/internal/layout"
	"github.com/go-idavoll/idunn/test/redteam/harness"
)

// An install tree written by one account must be usable by another: a
// system-wide install is written by root through the helper and run, checked and
// updated by ordinary users. Every directory the updater creates must therefore be
// enterable and listable by others, and every metadata file readable — and none of
// them writable by anyone but the owner.
//
// This runs a real install through a real trust client, whose privileged cache
// lives inside the root, so the parents go-tuf would otherwise create are covered
// too.
func TestAnInstallTreeIsReadableByOthersAndWritableByNone(t *testing.T) {
	keys, err := harness.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	opts := harness.DefaultBuildOptions(keys)
	dir := t.TempDir()
	build, err := harness.BuildRepo(filepath.Join(dir, "repo"), opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := harness.Serve(filepath.Join(dir, "repo"))
	t.Cleanup(srv.Close)

	root := filepath.Join(dir, "machine", "app") // does not exist yet.
	at := opts.Now.Add(time.Hour)
	c, err := trust.New(trust.Options{
		Root:        build.RootBytes,
		MetadataURL: srv.MetadataURL(),
		TargetsURL:  srv.TargetsURL(),
		LocalDir:    filepath.Join(root, layout.MetaName, layout.TrustCacheName),
		Now:         func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	c.UnsafeSetRefTime(at)
	u, err := updater.New(updater.Options{
		Trust: c, FS: fsx.OS(), Root: root, Channel: opts.Channel, OS: opts.OS, Arch: opts.Arch,
		Now: func() time.Time { return at },
	})
	if err != nil {
		t.Fatal(err)
	}
	rel, err := u.CheckForUpdate(context.Background())
	if err != nil || rel == nil {
		t.Fatalf("CheckForUpdate = %v, %v", rel, err)
	}
	if err := u.Apply(context.Background(), rel); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	mustReadable := func(p string, dir bool) {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		perm := st.Mode().Perm()
		want := fs.FileMode(0o044)
		if dir {
			want = 0o055
		}
		if perm&want != want {
			t.Errorf("%s has mode %v; others cannot read it", p, perm)
		}
		if perm&0o022 != 0 {
			t.Errorf("%s has mode %v; others can write it", p, perm)
		}
	}
	version, err := layout.VersionDir(root, opts.Version)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{root, layout.Meta(root), layout.Versions(root), version} {
		mustReadable(filepath.FromSlash(d), true)
	}
	for _, f := range []string{layout.Journal(root), layout.State(root), layout.Clock(root)} {
		mustReadable(filepath.FromSlash(f), false)
	}
	// Every directory inside the installed version, e.g. bin/.
	_ = filepath.WalkDir(filepath.FromSlash(version), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			mustReadable(p, true)
		}
		return nil
	})
}
