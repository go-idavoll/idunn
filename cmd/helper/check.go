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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/go-idavoll/idunn/core/elevate"
)

// checkSchema is the version of the `helper check --json` document. Install
// scripts parse it; a change that removes or renames a field raises it.
const checkSchema = 1

// checkReport is what `helper check` found. It is printed as text for people and,
// with --json, as a stable document for install scripts (docs/helper.md §4).
type checkReport struct {
	Schema      int           `json:"schema"`
	OK          bool          `json:"ok"`
	Error       string        `json:"error,omitempty"`
	Version     string        `json:"version,omitempty"`
	Label       string        `json:"label,omitempty"`
	Channel     string        `json:"channel,omitempty"`
	MetadataURL string        `json:"metadata_url,omitempty"`
	StateDir    string        `json:"state_dir,omitempty"`
	Endpoint    string        `json:"endpoint,omitempty"`
	Roots       []checkResult `json:"roots"`
	State       *checkResult  `json:"state,omitempty"`
	Callers     *checkCallers `json:"callers,omitempty"`
}

type checkResult struct {
	Path  string `json:"path"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type checkCallers struct {
	Present bool     `json:"present"`
	UIDs    []uint32 `json:"uids"`
	SIDs    []string `json:"sids"`
	Error   string   `json:"error,omitempty"`
}

// checkVerb validates the build and this machine and reports what serve would
// use. It needs no privileges: every file it reads is readable by anyone. The
// exit code is 0 only if serve would start.
func checkVerb(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("check", flag.ContinueOnError)
	fl.SetOutput(stderr)
	asJSON := fl.Bool("json", false, "print a machine-readable report (schema 1)")
	if err := fl.Parse(args); err != nil {
		return exitUsage
	}
	if fl.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "helper check: unexpected argument %q\n", fl.Arg(0))
		return exitUsage
	}

	r := runCheck()
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return exitError
		}
	} else {
		printCheck(r, stdout, stderr)
	}
	if !r.OK {
		return exitRefuse
	}
	return exitOK
}

func runCheck() checkReport {
	r := checkReport{Schema: checkSchema, Version: versionString(), Roots: []checkResult{}}
	b, err := loadBuild(buildFS)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	paths, err := pathsFor(b.helper.Label)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Label, r.Channel, r.MetadataURL = b.helper.Label, channelOf(b), b.anchor.Repo.MetadataURL
	r.StateDir, r.Endpoint = paths.StateDir, paths.Endpoint

	ok := true
	for _, root := range b.helper.AllowedRoots {
		res := checkResult{Path: root, OK: true}
		if err := elevate.CheckPrivilegedRoot(root); err != nil {
			res.OK, res.Error, ok = false, err.Error(), false
		}
		r.Roots = append(r.Roots, res)
	}

	state := checkResult{Path: paths.StateDir, OK: true}
	if err := elevate.CheckPrivilegedRoot(paths.StateDir); err != nil {
		state.OK, state.Error = false, err.Error()
		r.State = &state
		return r
	}
	r.State = &state

	c, exists, err := readCallers(paths.StateDir)
	callers := &checkCallers{Present: exists, UIDs: nonNil(c.UIDs), SIDs: nonNilS(c.SIDs)}
	if err != nil {
		callers.Error = err.Error()
		r.Callers = callers
		return r
	}
	r.Callers = callers
	r.OK = ok
	return r
}

func printCheck(r checkReport, stdout, stderr io.Writer) {
	if r.Error != "" {
		_, _ = fmt.Fprintf(stderr, "helper check: %s\n", r.Error)
		return
	}
	_, _ = fmt.Fprintf(stdout, "version:   %s\nlabel:     %s\nchannel:   %s\nmetadata:  %s\nstate dir: %s\nendpoint:  %s\n",
		r.Version, r.Label, r.Channel, r.MetadataURL, r.StateDir, r.Endpoint)
	for _, root := range r.Roots {
		verdict := "ok"
		if !root.OK {
			verdict = root.Error
		}
		_, _ = fmt.Fprintf(stdout, "root:      %s — %s\n", root.Path, verdict)
	}
	if r.State != nil && !r.State.OK {
		_, _ = fmt.Fprintf(stdout, "state:     %s\n", r.State.Error)
		return
	}
	switch c := r.Callers; {
	case c == nil:
	case c.Error != "":
		_, _ = fmt.Fprintf(stdout, "callers:   %s\n", c.Error)
	case !c.Present:
		_, _ = fmt.Fprintln(stdout, "callers:   none (only root / SYSTEM may ask; add one with `helper allow`)")
	default:
		_, _ = fmt.Fprintf(stdout, "callers:   uids %v sids %v\n", c.UIDs, c.SIDs)
	}
}

func nonNil(v []uint32) []uint32 {
	if v == nil {
		return []uint32{}
	}
	return v
}

func nonNilS(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
