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

// Command genrepo builds the known-good baseline TUF repository that every
// adversarial mutation derives from, so a corpus case differs from a valid
// repository in exactly one way.
//
// The build is deterministic: all expiries derive from a fixed reference time, not
// from the wall clock (AGENTS.md §1.7).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-idavoll/idunn/test/redteam/harness"
)

func main() {
	keysDir := flag.String("keys", "test/redteam/fixtures/keys", "directory holding the TEST-ONLY role keys")
	out := flag.String("out", "test/redteam/fixtures/valid-repo", "directory to write the baseline repository to")
	flag.Parse()

	if err := run(*keysDir, *out); err != nil {
		fmt.Fprintln(os.Stderr, "genrepo:", err)
		os.Exit(1)
	}
}

func run(keysDir, out string) error {
	keys, err := harness.LoadKeys(keysDir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(out); err != nil {
		return fmt.Errorf("clearing %s: %w", out, err)
	}

	opts := harness.DefaultBuildOptions(keys)
	build, err := harness.BuildRepo(out, opts)
	if err != nil {
		return err
	}

	// The trust anchor a client is seeded with. Mutated repositories are always
	// judged against this root, never against one they ship themselves.
	rootPath := filepath.Join(out, "root.json")
	if err := os.WriteFile(rootPath, build.RootBytes, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", rootPath, err)
	}

	fmt.Printf("genrepo: baseline %s %s/%s@%s written to %s\n",
		opts.Channel, opts.OS, opts.Arch, opts.Version, out)
	return nil
}
