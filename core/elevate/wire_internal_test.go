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
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The wire parser is what the privileged side runs on bytes from an unprivileged
// process. These cases run on every OS: the grammar is text, and a request
// refused on Linux must be refused identically wherever a transport exists.

func TestWireRoundTrip(t *testing.T) {
	t.Parallel()

	for _, want := range []Request{
		{Root: "/opt/acme", Channel: "stable", Version: "1.3.0"},
		{Root: `C:\Program Files\Acme App`, Channel: "beta.2", Version: "2.0.0-rc.1+build.7"},
	} {
		var buf bytes.Buffer
		if err := encodeRequest(&buf, want); err != nil {
			t.Fatalf("encodeRequest(%+v): %v", want, err)
		}
		got, err := decodeRequest(&buf)
		if err != nil || got != want {
			t.Fatalf("decodeRequest = %+v, %v; want %+v", got, err, want)
		}
	}
}

func TestWireRefusesWhatIsNotExactlyARequest(t *testing.T) {
	t.Parallel()

	for _, payload := range []string{
		"",
		"GET / HTTP/1.1\r\n\r\n",
		"idunn-apply/2\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nchannel=stable\nroot=/opt/acme\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\nextra=1\n\n",
		"idunn-apply/1\nroot=/opt/acme\nroot=/etc\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\r\nroot=/opt/acme\r\nchannel=stable\r\nversion=1.3.0\r\n\r\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n",
		"idunn-apply/1\nroot=opt/acme\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/../etc\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable beta\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3\n\n",
		"idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n\nidunn-apply/1\n",
		"idunn-apply/1\nroot=/" + strings.Repeat("a", maxLineBytes) + "\nchannel=stable\nversion=1.3.0\n\n",
		"idunn-apply/1\nroot=/opt/acme\x00\nchannel=stable\nversion=1.3.0\n\n",
	} {
		if req, err := decodeRequest(strings.NewReader(payload)); !errors.Is(err, ErrRequest) {
			t.Errorf("decodeRequest(%q) = %+v, %v; want ErrRequest", payload, req, err)
		}
	}
}

func TestWireResponses(t *testing.T) {
	t.Parallel()

	for class, want := range map[string]error{
		"":           nil,
		classRequest: ErrRequest,
		classDenied:  ErrDenied,
		classApply:   ErrHelper,
	} {
		var buf bytes.Buffer
		if err := encodeResponse(&buf, class); err != nil {
			t.Fatal(err)
		}
		if err := decodeResponse(&buf); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("class %q decoded as %v, want %v", class, err, want)
		}
	}
	for _, answer := range []string{"", "ok ", "OK\n", "error\n", "error surprise\n", "error apply /opt/acme\n", "okay\n"} {
		if err := decodeResponse(strings.NewReader(answer)); err == nil {
			t.Errorf("answer %q was taken for success", answer)
		}
	}
}

// Fuzzing the privileged side's parser (AGENTS.md §4). Whatever it accepts must
// be a request the grammar accepts, and must encode back to exactly the bytes it
// was read from — a second spelling of an accepted request is a second parser.
func FuzzDecodeRequest(f *testing.F) {
	f.Add("idunn-apply/1\nroot=/opt/acme\nchannel=stable\nversion=1.3.0\n\n")
	f.Add("idunn-apply/1\nroot=C:\\Program Files\\Acme\nchannel=beta\nversion=2.0.0-rc.1\n\n")
	f.Add("idunn-apply/1\r\nroot=/opt/acme\r\n\r\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, payload string) {
		req, err := decodeRequest(strings.NewReader(payload))
		if err != nil {
			if !errors.Is(err, ErrRequest) {
				t.Fatalf("refusal outside the ErrRequest class: %v", err)
			}
			return
		}
		if _, err := ParseRequest(req.Root, req.Channel, req.Version); err != nil {
			t.Fatalf("accepted a request the grammar refuses: %+v: %v", req, err)
		}
		var buf bytes.Buffer
		if err := encodeRequest(&buf, req); err != nil {
			t.Fatalf("an accepted request does not encode: %v", err)
		}
		// Accepted bytes are exactly one request's spelling. Anything after it
		// can only be data a stream had not delivered yet when the parser
		// stopped reading, which it never acts on.
		if !strings.HasPrefix(payload, buf.String()) {
			t.Fatalf("accepted %q, which re-encodes as %q", payload, buf.String())
		}
	})
}
