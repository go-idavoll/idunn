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

// Command genkeys generates the TEST-ONLY TUF role keys the adversarial corpus
// signs with.
//
// These are throwaway keys for a disposable repository. They are not, and must
// never become, production keys: the output directory is git-ignored and nothing
// here reads a real key store, an HSM, or CI secrets (AGENTS.md §5, §7).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/go-idavoll/idunn/test/redteam/harness"
)

func main() {
	out := flag.String("out", "test/redteam/fixtures/keys", "directory to write the test keys to")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "genkeys:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	// Regenerating is cheap and keeps every run self-contained: a stale key set
	// that no longer matches the baseline repo would produce confusing failures.
	keys, err := harness.GenerateKeys()
	if err != nil {
		return err
	}
	if err := keys.Save(out); err != nil {
		return err
	}
	fmt.Printf("genkeys: wrote TEST-ONLY keys for %v (+%s) to %s\n", harness.Roles, harness.AttackerRole, out)
	return nil
}
