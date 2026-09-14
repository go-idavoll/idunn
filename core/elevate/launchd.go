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
	"fmt"
	"strings"
)

// This file is the part of the macOS helper daemon that is data, not a system
// call: the names SMAppService is given and the launchd property list it reads.
// It is plain Go and tested on every platform; only the registration itself
// (framework_darwin.go) needs macOS.
//
// The plist is the most privileged configuration the host ships: launchd runs
// whatever it names, as root, at boot. It is therefore generated from a closed
// set of validated fields rather than written by hand or templated from strings,
// and anything that cannot be expressed in that set — an environment, a working
// directory, a user name, a program outside the bundle — cannot be expressed at
// all.

// Limits on what DaemonPlist accepts. They are generous for any real helper and
// small enough that nothing unreviewable fits.
const (
	maxLabelLen   = 200
	maxArgs       = 16
	maxArgLen     = 256
	maxProgramLen = 256
)

// DaemonConfig describes the LaunchDaemon plist of a privileged helper
// registered through SMAppService (docs/design.md §14.2).
//
// The plist file belongs in the application bundle at
// Contents/Library/LaunchDaemons/<Label>.plist; RegisterDaemon is then called
// with "<Label>.plist".
type DaemonConfig struct {
	// Label is launchd's name for the job, in reverse-DNS form
	// ("com.acme.app.helper").
	Label string

	// BundleProgram is the helper executable's path relative to the bundle root,
	// under Contents/ ("Contents/MacOS/acme-helper"). launchd resolves it inside
	// the bundle the daemon was registered from, so the program cannot be
	// anything but a file the bundle's signature covers.
	BundleProgram string

	// AssociatedBundleIdentifiers are the bundle identifiers macOS shows as the
	// daemon's owner under Login Items. At least one is required: an
	// unattributed background item is what users are taught to distrust.
	AssociatedBundleIdentifiers []string

	// Arguments follow the program name in the helper's argv, for example
	// {"serve", "--endpoint", "/Library/Application Support/com.acme.app.helper/helper.sock"}.
	// Each is a single argv element — launchd passes them to the program
	// directly, no shell ever sees them — and each must stay inside a narrow
	// charset (see checkDaemonArg).
	Arguments []string
}

// DaemonPlist renders cfg as a launchd property list.
//
// The output is deterministic — fixed key order, fixed indentation, no
// timestamps — so a bundle built twice carries the same bytes (AGENTS.md §1.7),
// and it has exactly these keys: Label, BundleProgram, ProgramArguments,
// AssociatedBundleIdentifiers, RunAtLoad and KeepAlive.
//
// RunAtLoad and KeepAlive are not defaults picked for convenience. The helper
// binds its own socket (so that checkSocketDir judges the directory it lives
// in); launchd therefore has no socket to activate it on demand, and without
// RunAtLoad nothing would be listening. KeepAlive is {SuccessfulExit: false}:
// a helper that crashed is restarted (launchd throttles the restarts), and a
// helper that exited cleanly — it was told to stop — stays stopped.
//
// Deliberately absent: EnvironmentVariables (DYLD_* and friends would be code
// injection into a root process), UserName/GroupName (the daemon runs as root,
// which CheckPrivilegedRoot assumes), WorkingDirectory, Program (only
// BundleProgram, which cannot leave the bundle), MachServices and Sockets (the
// transport is the helper's own Unix socket).
func DaemonPlist(cfg DaemonConfig) ([]byte, error) {
	if err := checkLabel(cfg.Label); err != nil {
		return nil, err
	}
	if err := checkBundleProgram(cfg.BundleProgram); err != nil {
		return nil, err
	}
	if len(cfg.AssociatedBundleIdentifiers) == 0 {
		return nil, fmt.Errorf("%w: a daemon needs at least one associated bundle identifier", ErrRequest)
	}
	for _, id := range cfg.AssociatedBundleIdentifiers {
		if err := checkReverseDNS("associated bundle identifier", id); err != nil {
			return nil, err
		}
	}
	if len(cfg.Arguments) > maxArgs {
		return nil, fmt.Errorf("%w: %d daemon arguments, at most %d", ErrRequest, len(cfg.Arguments), maxArgs)
	}
	for _, a := range cfg.Arguments {
		if err := checkDaemonArg(a); err != nil {
			return nil, err
		}
	}

	// argv[0] is the program's own name, as a shell would pass it. launchd
	// takes ProgramArguments as the whole argv when BundleProgram names the
	// executable.
	argv := append([]string{cfg.BundleProgram[strings.LastIndexByte(cfg.BundleProgram, '/')+1:]}, cfg.Arguments...)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")
	plistString(&b, "Label", cfg.Label)
	plistString(&b, "BundleProgram", cfg.BundleProgram)
	plistArray(&b, "ProgramArguments", argv)
	plistArray(&b, "AssociatedBundleIdentifiers", cfg.AssociatedBundleIdentifiers)
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

// Every value reaching these writers has passed a charset check that excludes
// the XML metacharacters, so escaping is a second line and not the only one.
func plistString(b *bytes.Buffer, key, value string) {
	fmt.Fprintf(b, "\t<key>%s</key>\n\t<string>%s</string>\n", key, xmlEscape(value))
}

func plistArray(b *bytes.Buffer, key string, values []string) {
	fmt.Fprintf(b, "\t<key>%s</key>\n\t<array>\n", key)
	for _, v := range values {
		fmt.Fprintf(b, "\t\t<string>%s</string>\n", xmlEscape(v))
	}
	b.WriteString("\t</array>\n")
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")

func xmlEscape(s string) string { return xmlEscaper.Replace(s) }

// checkPlistName validates the name SMAppService is asked about: a file name,
// never a path, of the form <reverse-DNS label>.plist.
//
// daemonServiceWithPlistName: looks the name up in the bundle's
// Contents/Library/LaunchDaemons. A separator or a dot-dot in it would be a
// question about some other file, and a question this API was not designed to
// answer safely; so it is refused rather than normalised.
func checkPlistName(name string) error {
	label, ok := strings.CutSuffix(name, ".plist")
	if !ok {
		return fmt.Errorf("%w: plist name %q does not end in .plist", ErrRequest, name)
	}
	return checkReverseDNS("plist name", label)
}

func checkLabel(label string) error { return checkReverseDNS("launchd label", label) }

// checkReverseDNS accepts at least two dot-separated components of ASCII
// letters, digits and hyphens, none empty and none starting or ending with a
// hyphen. That covers every bundle identifier and launchd label worth shipping,
// and excludes separators, whitespace, XML and anything Unicode could make look
// like something else.
func checkReverseDNS(what, s string) error {
	if s == "" || len(s) > maxLabelLen {
		return fmt.Errorf("%w: %s %q is empty or longer than %d bytes", ErrRequest, what, s, maxLabelLen)
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return fmt.Errorf("%w: %s %q is not reverse-DNS", ErrRequest, what, s)
	}
	for _, p := range parts {
		if p == "" || p[0] == '-' || p[len(p)-1] == '-' {
			return fmt.Errorf("%w: %s %q has an empty or hyphen-edged component", ErrRequest, what, s)
		}
		for i := 0; i < len(p); i++ {
			if !isAlnum(rune(p[i])) && p[i] != '-' {
				return fmt.Errorf("%w: %s %q contains %q", ErrRequest, what, s, p[i])
			}
		}
	}
	return nil
}

// checkBundleProgram accepts a relative path below Contents/ whose components
// are plain names: no absolute path, no "." or "..", no empty or hidden
// component, no backslash, nothing outside [A-Za-z0-9._-].
func checkBundleProgram(p string) error {
	if len(p) > maxProgramLen {
		return fmt.Errorf("%w: bundle program is longer than %d bytes", ErrRequest, maxProgramLen)
	}
	rest, ok := strings.CutPrefix(p, "Contents/")
	if !ok || rest == "" {
		return fmt.Errorf("%w: bundle program %q is not a path below Contents/", ErrRequest, p)
	}
	for _, c := range strings.Split(rest, "/") {
		if c == "" || c[0] == '.' {
			return fmt.Errorf("%w: bundle program %q has an empty, dot or hidden component", ErrRequest, p)
		}
		for i := 0; i < len(c); i++ {
			if !isAlnum(rune(c[i])) && c[i] != '.' && c[i] != '_' && c[i] != '-' {
				return fmt.Errorf("%w: bundle program %q contains %q", ErrRequest, p, c[i])
			}
		}
	}
	return nil
}

// checkDaemonArg accepts one argv element: 1..maxArgLen bytes of
// [A-Za-z0-9 ._/=:@+,-], not starting or ending with a space, and with no ".."
// path component.
//
// No shell interprets launchd's ProgramArguments, so this is not quoting
// hygiene. It keeps the plist reviewable at a glance, keeps XML metacharacters
// out by construction, and keeps a path argument from walking out of the
// directory a reviewer thinks it names.
func checkDaemonArg(a string) error {
	if a == "" || len(a) > maxArgLen {
		return fmt.Errorf("%w: daemon argument is empty or longer than %d bytes", ErrRequest, maxArgLen)
	}
	if a[0] == ' ' || a[len(a)-1] == ' ' {
		return fmt.Errorf("%w: daemon argument %q starts or ends with a space", ErrRequest, a)
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if !isAlnum(rune(c)) && !strings.ContainsRune(" ._/=:@+,-", rune(c)) {
			return fmt.Errorf("%w: daemon argument %q contains %q", ErrRequest, a, c)
		}
	}
	for _, seg := range strings.Split(a, "/") {
		if seg == ".." {
			return fmt.Errorf("%w: daemon argument %q contains a .. path component", ErrRequest, a)
		}
	}
	return nil
}
