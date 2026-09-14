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

// Command helper is the reference privileged helper for ElevationService: a
// daemon (launchd, systemd) or Windows service that owns a publisher's install
// roots and applies the updates the unprivileged application asks for.
//
// Every publisher builds their own: the trust anchor, the repository and the
// install roots are compiled in from cmd/helper/anchor/, and the binary is
// signed with the publisher's identity (docs/helper.md). Nothing a caller could
// choose — an anchor, a URL, a root, a code requirement — is accepted on the
// command line.
//
//	helper serve                     run the helper (as root / SYSTEM)
//	helper allow --uid N | --sid S   let a local account ask (administrator)
//	helper deny  --uid N | --sid S   stop letting it ask (administrator)
//	helper check [--json]            validate the build and this machine
//	helper plist                     print the macOS LaunchDaemon plist
//	helper version                   print the version
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/go-idavoll/idunn/core/elevate"
)

// Exit codes.
const (
	exitOK     = 0
	exitError  = 1
	exitUsage  = 2
	exitRefuse = 3 // the build or this machine is not fit to run the helper.
)

// version is this helper's own version, set at build time with
// -ldflags "-X main.version=1.3.0". It is the client version a release's
// min_client_version is checked against.
var version = ""

// buildTime is when this helper was built (RFC3339 or Unix seconds), set with
// -ldflags "-X main.buildTime=...". It is the first floor under the clock
// (§14.7).
var buildTime = ""

// pathsFor locates the state directory and endpoint for a label. A variable so
// tests can point it at a directory they own.
var pathsFor = elevate.DefaultHelperPaths

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "serve":
		return serveVerb(args[1:], stderr)
	case "allow":
		return callersVerb(args[1:], true, stdout, stderr)
	case "deny":
		return callersVerb(args[1:], false, stdout, stderr)
	case "check":
		return checkVerb(args[1:], stdout, stderr)
	case "plist":
		return plistVerb(args[1:], stdout, stderr)
	case "version":
		_, _ = fmt.Fprintln(stdout, versionString())
		return exitOK
	case "-h", "--help", "help":
		usage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "helper: unknown command %q\n\n", args[0])
		usage(stderr)
		return exitUsage
	}
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `helper — the privileged update helper (docs/helper.md)

Usage:
  helper serve
  helper allow --uid <uid> | --sid <sid>
  helper deny  --uid <uid> | --sid <sid>
  helper check [--json]
  helper plist
  helper version

Exit codes: 0 ok, 1 error, 2 usage, 3 the build or this machine is not fit to serve.
`)
}

func versionString() string {
	if version == "" {
		return "(unversioned build)"
	}
	return version
}

// noArgs parses a verb that takes no flags.
func noArgs(name string, args []string, stderr io.Writer) bool {
	fl := flag.NewFlagSet(name, flag.ContinueOnError)
	fl.SetOutput(stderr)
	if err := fl.Parse(args); err != nil {
		return false
	}
	if fl.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "helper %s: unexpected argument %q\n", name, fl.Arg(0))
		return false
	}
	return true
}

// callersVerb adds or removes one caller. It must run with administrator
// rights, because the file it writes decides who may ask a root process for an
// install; and it refuses a state directory anyone else could change, before
// and after it creates it.
func callersVerb(args []string, add bool, stdout, stderr io.Writer) int {
	name := "deny"
	if add {
		name = "allow"
	}
	fl := flag.NewFlagSet(name, flag.ContinueOnError)
	fl.SetOutput(stderr)
	uidFlag := fl.String("uid", "", "numeric uid (POSIX)")
	sidFlag := fl.String("sid", "", "account SID (Windows)")
	if err := fl.Parse(args); err != nil {
		return exitUsage
	}
	if fl.NArg() != 0 || (*uidFlag == "") == (*sidFlag == "") {
		_, _ = fmt.Fprintf(stderr, "helper %s: exactly one of --uid or --sid is required\n", name)
		return exitUsage
	}
	if err := requireAdministrator(); err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitRefuse
	}
	b, err := loadBuild(buildFS)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitRefuse
	}
	paths, err := pathsFor(b.helper.Label)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitRefuse
	}
	if err := ensureStateDir(paths.StateDir); err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitRefuse
	}
	c, _, err := readCallers(paths.StateDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitRefuse
	}
	c, err = edit(c, *uidFlag, *sidFlag, add)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitUsage
	}
	if err := writeCallers(paths.StateDir, c); err != nil {
		_, _ = fmt.Fprintf(stderr, "helper %s: %v\n", name, err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "callers: uids %v sids %v (restart the helper to apply)\n", c.UIDs, c.SIDs)
	return exitOK
}

// edit adds or removes one caller, keeping the list sorted and free of
// duplicates.
func edit(c callers, uid, sid string, add bool) (callers, error) {
	if uid != "" {
		n, err := strconv.ParseUint(uid, 10, 32)
		if err != nil {
			return c, fmt.Errorf("%w: --uid %q is not a uid", ErrConfig, uid)
		}
		u := uint32(n)
		c.UIDs = slices.DeleteFunc(c.UIDs, func(x uint32) bool { return x == u })
		if add {
			c.UIDs = append(c.UIDs, u)
			slices.Sort(c.UIDs)
		}
		return c, nil
	}
	if !sidPattern.MatchString(sid) {
		return c, fmt.Errorf("%w: --sid %q is not a SID", ErrConfig, sid)
	}
	c.SIDs = slices.DeleteFunc(c.SIDs, func(x string) bool { return x == sid })
	if add {
		c.SIDs = append(c.SIDs, sid)
		slices.Sort(c.SIDs)
	}
	return c, nil
}

// ensureStateDir creates the state directory if needed, and requires it to be
// one only administrators control — the same judgement as an install root.
func ensureStateDir(dir string) error {
	if err := elevate.CheckPrivilegedRoot(dir); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	// 0755: on macOS the state directory is also the socket's directory, and a
	// caller has to be able to reach the socket in it.
	//
	//nolint:gosec // G301: see above.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	if err := elevate.CheckPrivilegedRoot(dir); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	return nil
}

// plistVerb prints the LaunchDaemon plist for this build. It runs anywhere, for
// the bundle step on a build machine.
func plistVerb(args []string, stdout, stderr io.Writer) int {
	if !noArgs("plist", args, stderr) {
		return exitUsage
	}
	b, err := loadBuild(buildFS)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper plist: %v\n", err)
		return exitRefuse
	}
	if b.helper.MacOSBundleIdentifier == "" {
		_, _ = fmt.Fprintf(stderr, "helper plist: %s names no macos_bundle_identifier\n", helperName)
		return exitRefuse
	}
	raw, err := elevate.DaemonPlist(elevate.DaemonConfig{
		Label:                       b.helper.Label,
		BundleProgram:               "Contents/Library/HelperTools/" + b.helper.Label,
		AssociatedBundleIdentifiers: []string{b.helper.MacOSBundleIdentifier},
		Arguments:                   []string{"serve"},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper plist: %v\n", err)
		return exitRefuse
	}
	_, _ = stdout.Write(raw)
	return exitOK
}

func channelOf(b *build) string {
	if b.anchor.Repo.Channel != "" {
		return b.anchor.Repo.Channel
	}
	return "stable"
}

// errNotAdministrator is returned by requireAdministrator.
var errNotAdministrator = errors.New("helper: this command needs administrator rights (root, or an elevated administrator on Windows)")
