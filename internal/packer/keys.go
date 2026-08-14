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

package packer

import (
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Key hygiene (AGENTS.md §5, docs/packer.md §5).
//
// Keys never live in the repository and never travel through this process as
// values. The environment carries a *reference* — a file path today, a KMS/HSM
// URI later — and nothing here reads, writes, logs or prints key material. The
// error paths below name the role, the variable and the reason, never the bytes.

// Role key environment variables. The names are part of the operator contract
// and are quoted verbatim in docs/design.md §9.
const (
	EnvTargetsKey   = "TUF_TARGETS_KEY"   // offline / HSM
	EnvSnapshotKey  = "TUF_SNAPSHOT_KEY"  // CI
	EnvTimestampKey = "TUF_TIMESTAMP_KEY" // CI, short-lived
)

// EnvDelegationKeyPrefix builds the optional per-delegation override:
// TUF_DELEGATION_KEY_STABLE, TUF_DELEGATION_KEY_V2. A delegated role falls back
// to TUF_TARGETS_KEY, which keeps the common single-offline-key setup simple
// while leaving room to give one channel or one release line its own key.
const EnvDelegationKeyPrefix = "TUF_DELEGATION_KEY_"

// envSuffix maps a role name onto the tail of its override variable.
var envSuffix = regexp.MustCompile(`[^A-Z0-9]`)

// delegationKeyEnv is the override variable name for a delegated role.
func delegationKeyEnv(role string) string {
	return EnvDelegationKeyPrefix + envSuffix.ReplaceAllString(strings.ToUpper(role), "_")
}

// schemeRe matches a URI scheme. Two characters minimum, so a Windows drive
// letter ("C:\keys\targets.pem") stays a path instead of becoming an unknown
// scheme.
var schemeRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]+):`)

// roleKey is one resolved signing key: the signer, and the public half in the
// form TUF records it. The private key is held by the signer and is never
// exported from this type.
type roleKey struct {
	role   string
	signer signature.Signer
	public *metadata.Key
	id     string
}

// lookupEnv is the environment accessor, injected so tests never depend on (or
// mutate) the real process environment.
type lookupEnv func(string) (string, bool)

// resolveKey loads the signing key for one role from the environment.
//
// A missing variable is a hard failure by design: this runs before anything is
// written, so a repository can never end up half-signed because a key was absent
// (T13).
func resolveKey(role, envVar string, env lookupEnv) (*roleKey, error) {
	ref, ok := env(envVar)
	if !ok || strings.TrimSpace(ref) == "" {
		return nil, fmt.Errorf("%w: %s is not set; refusing to publish without the %s key",
			ErrKey, envVar, role)
	}
	return loadKeyRef(role, envVar, strings.TrimSpace(ref))
}

// loadKeyRef turns a key reference into a signer.
func loadKeyRef(role, envVar, ref string) (*roleKey, error) {
	// A variable holding the key itself is refused rather than used. Key
	// material in an environment variable leaks into process listings, crash
	// dumps and CI logs, and this tool must never be the reason it does.
	if strings.Contains(ref, "-----BEGIN") {
		return nil, fmt.Errorf("%w: %s looks like key material; it must hold a file path or a KMS/HSM URI",
			ErrKey, envVar)
	}
	path := ref
	if m := schemeRe.FindStringSubmatch(ref); m != nil {
		if !strings.EqualFold(m[1], "file") {
			return nil, fmt.Errorf("%w: %s uses the %q scheme; only file: is implemented (KMS/HSM is future work)",
				ErrKey, envVar, m[1])
		}
		path = strings.TrimPrefix(ref[len(m[1])+1:], "//")
	}
	if path == "" {
		return nil, fmt.Errorf("%w: %s names no file", ErrKey, envVar)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: reading the %s key: %w", ErrKey, envVar, role, err)
	}
	priv, err := parsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s key: %w", ErrKey, envVar, role, err)
	}

	pub, err := metadata.KeyFromPublicKey(priv.Public())
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s key: %w", ErrKey, envVar, role, err)
	}
	id, err := pub.ID()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s key: %w", ErrKey, envVar, role, err)
	}
	signer, err := signature.LoadSigner(priv, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %s key: %w", ErrKey, envVar, role, err)
	}
	return &roleKey{role: role, signer: signer, public: pub, id: id}, nil
}

// parsePrivateKey decodes an unencrypted PKCS#8 Ed25519 private key.
//
// Ed25519 is the signature algorithm of this design (§4). Anything else — an
// encrypted key, another algorithm, a bare seed — is refused rather than coerced:
// the failure mode of guessing here is a repository signed with a key nobody
// meant to use. The error never quotes the input.
func parsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("not PEM; expected an unencrypted PKCS#8 %q block", "PRIVATE KEY")
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("the key is encrypted; decrypt it into the signing environment or use an HSM")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block is %q; expected %q", block.Type, "PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#8 private key")
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T; idunn signs with Ed25519", parsed)
	}
	return priv, nil
}

// keyring holds every key one publish needs. It is complete before the first
// byte is written, or the publish never starts.
type keyring struct {
	targets   *roleKey
	snapshot  *roleKey
	timestamp *roleKey

	// delegated maps a delegated role name to the key that signs it.
	delegated map[string]*roleKey
}

// resolveKeys loads every key the publish will need: the three top-level roles
// this tool signs, plus one per delegated role it will touch.
//
// It never resolves a root key. Root signatures are a separate offline ceremony;
// a command that runs on every release must not be able to sign the trust anchor
// (docs/packer.md §4).
func resolveKeys(env lookupEnv, delegatedRoles []string) (*keyring, error) {
	kr := &keyring{delegated: map[string]*roleKey{}}
	var err error
	if kr.targets, err = resolveKey(metadata.TARGETS, EnvTargetsKey, env); err != nil {
		return nil, err
	}
	if kr.snapshot, err = resolveKey(metadata.SNAPSHOT, EnvSnapshotKey, env); err != nil {
		return nil, err
	}
	if kr.timestamp, err = resolveKey(metadata.TIMESTAMP, EnvTimestampKey, env); err != nil {
		return nil, err
	}
	for _, role := range delegatedRoles {
		envVar := delegationKeyEnv(role)
		if ref, ok := env(envVar); ok && strings.TrimSpace(ref) != "" {
			key, err := loadKeyRef(role, envVar, strings.TrimSpace(ref))
			if err != nil {
				return nil, err
			}
			kr.delegated[role] = key
			continue
		}
		// No override: the delegation is signed with the offline targets key,
		// the same key root already trusts for the top-level role.
		kr.delegated[role] = &roleKey{
			role:   role,
			signer: kr.targets.signer,
			public: kr.targets.public,
			id:     kr.targets.id,
		}
	}
	return kr, nil
}
