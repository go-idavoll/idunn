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

package elevate

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type nopApplier struct{}

func (nopApplier) Apply(context.Context, Request) error { return nil }

const someRequirement = `anchor apple generic and identifier "com.acme.app" and certificate leaf[subject.OU] = "TEAMID"`

// codeCheck records whether it was consulted and answers with err.
type codeCheck struct {
	called bool
	err    error
}

func (c *codeCheck) fn() error {
	c.called = true
	return c.err
}

// The uid is judged alone and first. A caller running exactly the right,
// correctly signed application as a user the helper does not answer is refused,
// and its code is never even examined.
func TestAdmitPeerDeniesAnUnlistedUIDWhateverItsSignature(t *testing.T) {
	for name, allowed := range map[string][]uint32{
		"not in the list":           {501, 502},
		"empty list, not superuser": nil,
	} {
		t.Run(name, func(t *testing.T) {
			cc := &codeCheck{} // would say yes
			err := admitPeer(503, allowed, someRequirement, cc.fn)
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
			}
			if cc.called {
				t.Fatal("the code of a peer whose uid was refused was examined")
			}
		})
	}
}

// A listed uid is not enough once a requirement is configured.
func TestAdmitPeerDeniesAListedUIDThatFailsTheRequirement(t *testing.T) {
	cc := &codeCheck{err: errors.New("checking the peer's code: OSStatus -67050")}
	err := admitPeer(501, []uint32{501}, someRequirement, cc.fn)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
	if !cc.called {
		t.Fatal("the requirement was never checked")
	}
	if !strings.Contains(err.Error(), "-67050") {
		t.Fatalf("the reason did not reach the helper's log: %v", err)
	}
}

func TestAdmitPeerDeniesARequirementNothingCanCheck(t *testing.T) {
	if err := admitPeer(501, []uint32{501}, someRequirement, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: err = %v, want ErrDenied", err)
	}
}

func TestAdmitPeerAdmitsWhenBothHalvesAgree(t *testing.T) {
	cc := &codeCheck{}
	if err := admitPeer(501, []uint32{501}, someRequirement, cc.fn); err != nil {
		t.Fatalf("err = %v", err)
	}
	if !cc.called {
		t.Fatal("admitted without checking the requirement")
	}
}

// No requirement is today's behaviour: the uid alone, and no code check.
func TestAdmitPeerWithoutARequirementIsTheUIDCheck(t *testing.T) {
	cc := &codeCheck{err: errors.New("must not be asked")}
	if err := admitPeer(501, []uint32{501}, "", cc.fn); err != nil {
		t.Fatalf("err = %v", err)
	}
	if err := admitPeer(0, nil, "", cc.fn); err != nil {
		t.Fatalf("superuser with an empty list: err = %v", err)
	}
	if err := admitPeer(501, nil, "", cc.fn); !errors.Is(err, ErrDenied) {
		t.Fatalf("VULNERABILITY: empty list admitted a non-superuser: %v", err)
	}
	if cc.called {
		t.Fatal("a code check ran with no requirement configured")
	}
}

func TestCheckRequirementText(t *testing.T) {
	if err := checkRequirementText(someRequirement); err != nil {
		t.Fatalf("a real requirement was refused: %v", err)
	}
	if err := checkRequirementText("anchor apple generic\n\tand identifier \"com.acme.app\""); err != nil {
		t.Fatalf("a multi-line requirement was refused: %v", err)
	}
	bad := map[string]string{
		"blank":             " \t\n",
		"NUL truncation":    "anchor apple\x00 and identifier \"com.evil\"",
		"carriage return":   "anchor apple\r",
		"escape":            "anchor \x1b[2Kapple",
		"DEL":               "anchor apple\x7f",
		"invalid UTF-8":     "anchor \xff apple",
		"longer than bound": "anchor apple or " + strings.Repeat("x", maxPeerRequirementLen),
	}
	for name, req := range bad {
		if err := checkRequirementText(req); !errors.Is(err, ErrRequest) {
			t.Errorf("%s: err = %v, want ErrRequest", name, err)
		}
	}
}
