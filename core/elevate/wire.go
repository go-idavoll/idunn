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
	"bufio"
	"fmt"
	"io"
	"strings"
)

// The wire format between the unprivileged updater and the privileged helper.
//
// It carries exactly what the command-line contract carries — a verb and three
// scalars — and it is a line format rather than a serialization because the
// request grammar already forbids every byte that would need escaping: a control
// character cannot appear in a root, a channel or a version (see checkPathChars,
// checkChannel, checkVersion), so "one field per line" is injective without a
// quoting rule anyone could get wrong.
//
// The privileged side is the one parsing untrusted bytes here, so the parser is
// the smallest thing that can do the job: fixed keys, fixed order, hard length
// bounds, and no vocabulary beyond it. Nothing is skipped, defaulted or
// tolerated — an unexpected byte is a refusal (AGENTS.md §1.1).
const (
	wireBanner = "idunn-apply/1"

	wireKeyRoot    = "root"
	wireKeyChannel = "channel"
	wireKeyVersion = "version"

	// wireOK and wireError are the entire response vocabulary. An error carries
	// a class and never a path, a version or an error string: the response
	// crosses back to a less privileged process, and what it says must not
	// describe the privileged side's filesystem (§11.3 T20).
	wireOK    = "ok"
	wireError = "error"
)

// maxRequestBytes bounds one request. Four short lines and a terminator; the
// ceiling exists so a peer cannot make the privileged side read forever.
const maxRequestBytes = 4096

// maxLineBytes bounds one line, above the longest field the grammar allows.
const maxLineBytes = maxPathLen + 64

// The error classes a helper reports back. They are a closed vocabulary so the
// caller can act on the answer without matching on prose.
const (
	classRequest = "request" // the request was malformed or out of grammar.
	classDenied  = "denied"  // the caller or the target is not permitted.
	classApply   = "apply"   // the privileged apply itself failed.
)

// encodeRequest writes r in the wire format.
//
// It re-validates before writing. The caller has validated already; doing it
// again here costs nothing and means no path into this function can put an
// unchecked value on the wire.
func encodeRequest(w io.Writer, r Request) error {
	if err := checkInstallRoot(r.Root); err != nil {
		return err
	}
	if err := checkChannel(r.Channel); err != nil {
		return err
	}
	if err := checkVersion(r.Version); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "%s\n%s=%s\n%s=%s\n%s=%s\n\n",
		wireBanner,
		wireKeyRoot, r.Root,
		wireKeyChannel, r.Channel,
		wireKeyVersion, r.Version)
	return err
}

// decodeRequest reads one request and validates every field with the same rules
// the command-line path uses.
//
// A caller cannot reach the applier with anything this function would not also
// have produced. That is the whole point of it being one grammar: the privileged
// side has exactly one description of what a request may be.
func decodeRequest(r io.Reader) (Request, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, maxRequestBytes), maxLineBytes)

	banner, err := readLine(br)
	if err != nil {
		return Request{}, err
	}
	if banner != wireBanner {
		return Request{}, fmt.Errorf("%w: not an idunn apply request", ErrRequest)
	}

	var req Request
	for _, want := range []struct {
		key   string
		field *string
	}{
		{wireKeyRoot, &req.Root},
		{wireKeyChannel, &req.Channel},
		{wireKeyVersion, &req.Version},
	} {
		line, err := readLine(br)
		if err != nil {
			return Request{}, err
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != want.key {
			// The order is fixed rather than free. A parser that accepted the
			// fields in any order would have to carry state about which it had
			// seen, and "which of the two roots wins" is not a question this
			// side should ever be able to be asked.
			return Request{}, fmt.Errorf("%w: expected %q", ErrRequest, want.key)
		}
		*want.field = value
	}

	end, err := readLine(br)
	if err != nil {
		return Request{}, err
	}
	if end != "" {
		return Request{}, fmt.Errorf("%w: trailing data after the request", ErrRequest)
	}

	if err := checkInstallRoot(req.Root); err != nil {
		return Request{}, err
	}
	if err := checkChannel(req.Channel); err != nil {
		return Request{}, err
	}
	if err := checkVersion(req.Version); err != nil {
		return Request{}, err
	}
	return req, nil
}

// readLine reads one newline-terminated line without its terminator, refusing a
// line longer than the bound and a carriage return.
//
// "\r\n" is not accepted as an alternative terminator: two spellings of the same
// message are two parsers, and the difference between them is where a smuggled
// field would live.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("%w: truncated request", ErrRequest)
	}
	line = strings.TrimSuffix(line, "\n")
	if strings.ContainsRune(line, '\r') {
		return "", fmt.Errorf("%w: carriage return in the request", ErrRequest)
	}
	return line, nil
}

// encodeResponse writes the helper's answer. A nil class is success.
func encodeResponse(w io.Writer, class string) error {
	if class == "" {
		_, err := fmt.Fprintf(w, "%s\n", wireOK)
		return err
	}
	_, err := fmt.Fprintf(w, "%s %s\n", wireError, class)
	return err
}

// decodeResponse reads the helper's answer and turns a refusal back into a typed
// error on the caller's side.
func decodeResponse(r io.Reader) error {
	br := bufio.NewReaderSize(io.LimitReader(r, maxLineBytes), maxLineBytes)
	line, err := readLine(br)
	if err != nil {
		return fmt.Errorf("%w: no answer from the helper", ErrHelper)
	}
	if line == wireOK {
		return nil
	}
	verb, class, ok := strings.Cut(line, " ")
	if !ok || verb != wireError {
		return fmt.Errorf("%w: unintelligible answer from the helper", ErrHelper)
	}
	switch class {
	case classRequest:
		return fmt.Errorf("%w: the helper refused the request", ErrRequest)
	case classDenied:
		return fmt.Errorf("%w: the helper denied this caller", ErrDenied)
	case classApply:
		return fmt.Errorf("%w: the privileged apply failed", ErrHelper)
	default:
		return fmt.Errorf("%w: unknown refusal from the helper", ErrHelper)
	}
}
