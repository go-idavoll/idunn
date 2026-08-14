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

// Package harness builds TUF repositories for the adversarial corpus: one
// known-good baseline and, from it, deliberately tampered variants that the client
// under test must reject.
//
// Everything here is TEST ONLY. The keys it generates are throwaway keys written
// in the clear under test/redteam/fixtures/keys (git-ignored). No production key,
// secret, or signing service is ever touched (AGENTS.md §5, §7).
package harness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Roles are the top-level TUF roles the baseline repository uses.
var Roles = []string{"root", "targets", "snapshot", "timestamp"}

// AttackerRole is an extra key pair that is never listed in root. Mutators sign
// with it to model "role signed by a key the client does not trust".
const AttackerRole = "attacker"

// KeySet holds the throwaway signing keys of one test repository.
type KeySet struct {
	Private map[string]ed25519.PrivateKey
}

type storedKey struct {
	Role string `json:"role"`
	// Seed is the 32-byte ed25519 seed, base64-encoded. TEST KEY ONLY: writing
	// private key material to disk in the clear is acceptable here and nowhere
	// else in this project.
	Seed string `json:"seed"`
}

// GenerateKeys creates one key per top-level role plus the untrusted attacker key.
func GenerateKeys() (*KeySet, error) {
	ks := &KeySet{Private: make(map[string]ed25519.PrivateKey, len(Roles)+1)}
	for _, role := range append(append([]string{}, Roles...), AttackerRole) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("harness: generating %s key: %w", role, err)
		}
		ks.Private[role] = priv
	}
	return ks, nil
}

// Save writes the key set to dir as one JSON file per role.
func (k *KeySet) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("harness: %w", err)
	}
	names := make([]string, 0, len(k.Private))
	for name := range k.Private {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := json.MarshalIndent(storedKey{
			Role: name,
			Seed: base64.StdEncoding.EncodeToString(k.Private[name].Seed()),
		}, "", "  ")
		if err != nil {
			return fmt.Errorf("harness: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0o600); err != nil {
			return fmt.Errorf("harness: %w", err)
		}
	}
	return nil
}

// LoadKeys reads a key set previously written by Save.
func LoadKeys(dir string) (*KeySet, error) {
	ks := &KeySet{Private: map[string]ed25519.PrivateKey{}}
	for _, name := range append(append([]string{}, Roles...), AttackerRole) {
		raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			return nil, fmt.Errorf("harness: reading %s key (run `make test-keys`): %w", name, err)
		}
		var sk storedKey
		if err := json.Unmarshal(raw, &sk); err != nil {
			return nil, fmt.Errorf("harness: parsing %s key: %w", name, err)
		}
		seed, err := base64.StdEncoding.DecodeString(sk.Seed)
		if err != nil {
			return nil, fmt.Errorf("harness: decoding %s key: %w", name, err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("harness: %s key seed is %d bytes, want %d", name, len(seed), ed25519.SeedSize)
		}
		ks.Private[name] = ed25519.NewKeyFromSeed(seed)
	}
	return ks, nil
}
