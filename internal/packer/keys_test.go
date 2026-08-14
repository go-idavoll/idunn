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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func env(pairs map[string]string) lookupEnv {
	return func(name string) (string, bool) {
		v, ok := pairs[name]
		return v, ok
	}
}

func TestResolveKeyAcceptsAPathAndAFileURI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.pem")
	der, err := x509.MarshalPKCS8PrivateKey(testKey("resolve"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, ref := range []string{path, "file:" + path, "file://" + path} {
		key, err := resolveKey(metadata.TARGETS, EnvTargetsKey, env(map[string]string{EnvTargetsKey: ref}))
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if key.id == "" || key.public == nil || key.signer == nil {
			t.Errorf("%s: incomplete key", ref)
		}
	}
}

// The environment carries a reference to a key, never a key. Refusing material
// outright is what keeps it out of process listings, crash dumps and CI logs —
// and the refusal itself must not echo it.
func TestKeyMaterialInTheEnvironmentIsRefused(t *testing.T) {
	const secret = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHVERYSECRET\n-----END PRIVATE KEY-----"
	_, err := resolveKey(metadata.TARGETS, EnvTargetsKey, env(map[string]string{EnvTargetsKey: secret}))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("err = %v, want ErrKey", err)
	}
	if strings.Contains(err.Error(), "VERYSECRET") || strings.Contains(err.Error(), "BEGIN") {
		t.Fatalf("the error quotes the key material: %v", err)
	}
}

func TestResolveKeyRejects(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	rsaDER, err := x509.MarshalPKCS8PrivateKey(&rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: big.NewInt(3233), E: 17},
		D:         big.NewInt(2753),
		Primes:    []*big.Int{big.NewInt(61), big.NewInt(53)},
	})
	if err != nil {
		t.Skipf("cannot marshal an RSA key on this platform: %v", err)
	}

	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"unset", "", "is not set"},
		{"blank", "   ", "is not set"},
		{"unsupported scheme", "awskms:///alias/targets", "only file: is implemented"},
		{"empty file uri", "file:", "names no file"},
		{"missing file", filepath.Join(dir, "absent.pem"), "reading the targets key"},
		{"not pem", write("plain.bin", []byte("not a key")), "not PEM"},
		{"encrypted", write("enc.pem", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})), "encrypted"},
		{"wrong block", write("pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})), "PEM block is"},
		{"not pkcs8", write("junk.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}})), "not a PKCS#8"},
		{"not ed25519", write("rsa.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaDER})), "idunn signs with Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := map[string]string{}
			if tt.name != "unset" {
				vars[EnvTargetsKey] = tt.ref
			}
			_, err := resolveKey(metadata.TARGETS, EnvTargetsKey, env(vars))
			if !errors.Is(err, ErrKey) {
				t.Fatalf("err = %v, want ErrKey", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

// A Windows path is a path, not a URI with a one-letter scheme.
func TestWindowsDrivePathIsNotAScheme(t *testing.T) {
	_, err := resolveKey(metadata.TARGETS, EnvTargetsKey, env(map[string]string{EnvTargetsKey: `C:\keys\targets.pem`}))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("err = %v, want ErrKey", err)
	}
	if strings.Contains(err.Error(), "scheme") {
		t.Errorf("a drive letter was treated as a URI scheme: %v", err)
	}
}

func TestDelegationKeyEnvNames(t *testing.T) {
	tests := map[string]string{
		"stable":      "TUF_DELEGATION_KEY_STABLE",
		"v2":          "TUF_DELEGATION_KEY_V2",
		"long-term":   "TUF_DELEGATION_KEY_LONG_TERM",
		"beta.canary": "TUF_DELEGATION_KEY_BETA_CANARY",
	}
	for role, want := range tests {
		if got := delegationKeyEnv(role); got != want {
			t.Errorf("delegationKeyEnv(%q) = %q, want %q", role, got, want)
		}
	}
}

// Without an override a delegation is signed with the offline targets key, which
// root already trusts for the top-level role.
func TestDelegationsFallBackToTheTargetsKey(t *testing.T) {
	f := newFixture(t)
	kr, err := resolveKeys(f.lookupEnv, []string{"stable", "v1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"stable", "v1"} {
		if kr.delegated[role].id != kr.targets.id {
			t.Errorf("delegation %s does not fall back to the targets key", role)
		}
	}
}

// A delegation can be given its own key, which is the point of splitting the
// roles: one channel or one release line can be signed by a different offline
// key without touching the others.
func TestDelegationKeyOverrideIsUsed(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()

	own := testKey("stable-delegation")
	f.priv["stable"] = own
	f.writeKey("stable", own)
	f.env[delegationKeyEnv("stable")] = f.keyPath("stable")

	f.mustPublish(refTime)

	pub, err := metadata.KeyFromPublicKey(own.Public())
	if err != nil {
		t.Fatal(err)
	}
	wantID, err := pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	top := f.readTargets(t, metadata.TARGETS, 1)
	for _, d := range top.Signed.Delegations.Roles {
		if d.Name != "stable" {
			continue
		}
		if len(d.KeyIDs) != 1 || d.KeyIDs[0] != wantID {
			t.Errorf("stable delegation names %v, want [%s]", d.KeyIDs, wantID)
		}
	}
	// And it still resolves: the client verifies the delegation against the key
	// targets.json names for it.
	if _, err := f.resolve("stable", "linux", "amd64", refTime); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}

// A publish never resolves a root key. Rotation is a separate ceremony, and a
// command that runs on every release must not be able to sign the trust anchor.
func TestNoRootKeyIsEverResolved(t *testing.T) {
	f := newFixture(t)
	f.seedRelease()
	var asked []string
	f.env["TUF_ROOT_KEY"] = f.keyPath(metadata.ROOT)
	o := f.options(refTime)
	o.LookupEnv = func(name string) (string, bool) {
		asked = append(asked, name)
		return f.lookupEnv(name)
	}
	if _, err := Publish(o); err != nil {
		t.Fatal(err)
	}
	for _, name := range asked {
		if strings.Contains(strings.ToUpper(name), "ROOT") {
			t.Errorf("the publish asked for %s", name)
		}
	}
}

// parsePrivateKey is reached from every key path; it must not panic on hostile
// input and must never accept anything but an unencrypted Ed25519 PKCS#8 key.
func TestParsePrivateKeyIsTotal(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		[]byte("-----BEGIN PRIVATE KEY-----"),
		[]byte("-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----\n"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY"}),
	}
	for _, in := range inputs {
		if _, err := parsePrivateKey(in); err == nil {
			t.Errorf("parsePrivateKey(%q) accepted the input", in)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(testKey("total"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		t.Errorf("a valid key was refused: %v", err)
	}
}
