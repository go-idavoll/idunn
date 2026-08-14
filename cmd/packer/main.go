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

// Command packer builds release artifacts and maintains the TUF repository from a
// pack.yaml. It is a maintainer tool run via go:generate, never shipped to clients.
//
// Role keys are supplied via env/HSM and are never read from, written to, or
// printed by this tool (AGENTS.md §5). Its output must be reproducible: no
// wall-clock, randomness, or environment leakage into artifacts (§1.7). See
// docs/design.md §9 and docs/packer.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/go-idavoll/idunn/internal/packer"
)

// Exit codes. They are part of the contract with CI: a configuration or key
// mistake is the operator's to fix, and is worth telling apart from a usage
// error at a glance.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

// envSourceDateEpoch is the cross-ecosystem convention for "the reference time
// of this build". Honouring it means a reproducible-build harness that already
// sets it does not need to know about idunn's own flag.
const envSourceDateEpoch = "SOURCE_DATE_EPOCH"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "publish":
		return publish(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "idunn packer: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `idunn packer — publishes a TUF repository.

Usage:
  packer publish --config pack.yaml --repo ./tuf-repo [--now <RFC3339>]

Role keys are read from the environment as file paths (KMS/HSM URIs later),
never from pack.yaml and never as key material:

  `+packer.EnvTargetsKey+`     offline/HSM key of the targets role and its delegations
  `+packer.EnvSnapshotKey+`    CI key of the snapshot role
  `+packer.EnvTimestampKey+`   CI key of the timestamp role
  `+packer.EnvDelegationKeyPrefix+`<ROLE>   optional per-delegation override

The reference time (--now, or `+envSourceDateEpoch+`) is an input, not the wall
clock: two runs over the same inputs must produce a byte-identical repository.

root is never signed, written, or created here. Key rotation is a separate,
offline, m-of-n ceremony.
`)
}

func publish(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		config    = fs.String("config", "pack.yaml", "release description to publish")
		repo      = fs.String("repo", "", "TUF repository directory to publish into")
		now       = fs.String("now", "", "reference time for every expiry (RFC3339); defaults to "+envSourceDateEpoch)
		targets   = fs.Duration("targets-expiry", packer.DefaultTargetsExpiry, "validity of the targets roles")
		snapshot  = fs.Duration("snapshot-expiry", packer.DefaultSnapshotExpiry, "validity of the snapshot role")
		timestamp = fs.Duration("timestamp-expiry", packer.DefaultTimestampExpiry, "validity of the timestamp role")
	)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "idunn packer: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *repo == "" {
		_, _ = fmt.Fprintln(stderr, "idunn packer: --repo is required")
		return exitUsage
	}
	ref, err := referenceTime(*now, os.LookupEnv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn packer: %v\n", err)
		return exitUsage
	}

	res, err := packer.Publish(packer.Options{
		ConfigPath:      *config,
		RepoDir:         *repo,
		Now:             ref,
		TargetsExpiry:   *targets,
		SnapshotExpiry:  *snapshot,
		TimestampExpiry: *timestamp,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "idunn packer: %v\n", err)
		return exitError
	}
	report(stdout, res)
	return exitOK
}

// referenceTime resolves the reference time from --now or SOURCE_DATE_EPOCH.
//
// There is deliberately no fallback to the wall clock. Silently stamping "when
// this ran" into signed metadata would make the output unreproducible without
// anyone noticing, which is the one failure mode a supply-chain tool cannot have
// (AGENTS.md §1.7).
func referenceTime(flagValue string, env func(string) (string, bool)) (time.Time, error) {
	if flagValue != "" {
		t, err := time.Parse(time.RFC3339, flagValue)
		if err != nil {
			return time.Time{}, fmt.Errorf("--now %q is not RFC3339: %w", flagValue, err)
		}
		return t.UTC(), nil
	}
	if raw, ok := env(envSourceDateEpoch); ok && raw != "" {
		secs, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s %q is not a Unix timestamp: %w", envSourceDateEpoch, raw, err)
		}
		return time.Unix(secs, 0).UTC(), nil
	}
	return time.Time{}, errors.New("no reference time: pass --now <RFC3339> or set " + envSourceDateEpoch +
		" (publish output must be reproducible)")
}

// report prints what the publish did. It names roles, versions and target paths
// — never a key, a key reference, or anything read from one.
func report(w io.Writer, res *packer.Result) {
	_, _ = fmt.Fprintf(w, "published %s %s on channel %s\n", res.Name, res.Version, res.Channel)
	for _, role := range sortedKeys(res.Roles) {
		_, _ = fmt.Fprintf(w, "  role %-12s -> version %d\n", role, res.Roles[role])
	}
	for _, role := range sortedKeys(res.Delegations) {
		_, _ = fmt.Fprintf(w, "  delegation %-6s holds %d targets\n", role, res.Delegations[role])
	}
	_, _ = fmt.Fprintf(w, "  %d new targets\n", len(res.AddedTargets))
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
