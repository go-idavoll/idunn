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
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func goodDaemon() DaemonConfig {
	return DaemonConfig{
		Label:                       "com.acme.app.helper",
		BundleProgram:               "Contents/MacOS/acme-helper",
		AssociatedBundleIdentifiers: []string{"com.acme.app"},
		Arguments: []string{
			"serve", "--endpoint", "/Library/Application Support/com.acme.app.helper/helper.sock",
		},
	}
}

// The golden bytes. A change here is a change to what launchd runs as root on
// every machine with the helper installed, and must be read as one.
const goldenDaemonPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.acme.app.helper</string>
	<key>BundleProgram</key>
	<string>Contents/MacOS/acme-helper</string>
	<key>ProgramArguments</key>
	<array>
		<string>acme-helper</string>
		<string>serve</string>
		<string>--endpoint</string>
		<string>/Library/Application Support/com.acme.app.helper/helper.sock</string>
	</array>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>com.acme.app</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
</dict>
</plist>
`

func TestDaemonPlistMatchesTheGolden(t *testing.T) {
	got, err := DaemonPlist(goodDaemon())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenDaemonPlist {
		t.Fatalf("plist changed:\n%s", got)
	}
	again, err := DaemonPlist(goodDaemon())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, again) {
		t.Fatal("two renderings of the same config differ")
	}
}

// topLevelKeys parses the plist as XML and returns the keys of its outermost
// dict, so the key set is asserted on structure and not on substrings.
func topLevelKeys(t *testing.T, doc []byte) []string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(doc))
	dec.Strict = true
	var keys []string
	depth := 0 // dict nesting depth
	inKey := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return keys
		}
		if err != nil {
			t.Fatalf("the plist is not well-formed XML: %v", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if el.Name.Local == "dict" {
				depth++
			}
			inKey = el.Name.Local == "key" && depth == 1
		case xml.EndElement:
			if el.Name.Local == "dict" {
				depth--
			}
			inKey = false
		case xml.CharData:
			if inKey {
				keys = append(keys, string(el))
			}
		}
	}
}

func TestDaemonPlistHasExactlyTheIntendedKeys(t *testing.T) {
	got, err := DaemonPlist(goodDaemon())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"Label", "BundleProgram", "ProgramArguments", "AssociatedBundleIdentifiers", "RunAtLoad", "KeepAlive"}
	if keys := topLevelKeys(t, got); !slices.Equal(keys, want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

// Injection. Every field is a place someone could try to smuggle a second key
// — EnvironmentVariables with a DYLD_INSERT_LIBRARIES, a UserName, a Program
// outside the bundle — into the plist of a root daemon. Each must be refused,
// not escaped into something launchd would read as data and a reviewer would
// read as nothing.
func TestDaemonPlistRefusesInjection(t *testing.T) {
	inject := "</string><key>EnvironmentVariables</key><dict><key>DYLD_INSERT_LIBRARIES</key><string>/tmp/x.dylib</string></dict><string>"
	cases := map[string]func(*DaemonConfig){
		"label closes the string":     func(c *DaemonConfig) { c.Label = "com.acme" + inject },
		"label with an ampersand":     func(c *DaemonConfig) { c.Label = "com.acme&amp;.x" },
		"program closes the string":   func(c *DaemonConfig) { c.BundleProgram = "Contents/MacOS/x" + inject },
		"argument closes the string":  func(c *DaemonConfig) { c.Arguments = []string{"serve" + inject} },
		"argument with a quote":       func(c *DaemonConfig) { c.Arguments = []string{`--endpoint="x"`} },
		"argument with an apostrophe": func(c *DaemonConfig) { c.Arguments = []string{"it's"} },
		"argument with a CDATA":       func(c *DaemonConfig) { c.Arguments = []string{"<![CDATA[x]]>"} },
		"argument with an entity":     func(c *DaemonConfig) { c.Arguments = []string{"&lt;key&gt;"} },
		"argument with a newline":     func(c *DaemonConfig) { c.Arguments = []string{"serve\n<key>UserName</key>"} },
		"argument with a NUL":         func(c *DaemonConfig) { c.Arguments = []string{"serve\x00x"} },
		"associated id injection":     func(c *DaemonConfig) { c.AssociatedBundleIdentifiers = []string{"com.acme" + inject} },
		"environment through a shell": func(c *DaemonConfig) { c.Arguments = []string{"DYLD_INSERT_LIBRARIES=$(id)"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := goodDaemon()
			mutate(&cfg)
			out, err := DaemonPlist(cfg)
			if !errors.Is(err, ErrRequest) {
				t.Fatalf("VULNERABILITY: err = %v, want ErrRequest; plist:\n%s", err, out)
			}
			if out != nil {
				t.Fatal("a refused config still produced bytes")
			}
		})
	}
}

func TestXMLEscapeIsASecondLine(t *testing.T) {
	// Unreachable through DaemonPlist, whose checks keep these characters out;
	// asserted so that relaxing a charset one day does not also mean raw XML.
	if got := xmlEscape(`<&>"'`); got != "&lt;&amp;&gt;&quot;&apos;" {
		t.Fatalf("xmlEscape = %q", got)
	}
}

func TestDaemonPlistRefusesBadFields(t *testing.T) {
	long := strings.Repeat("a", maxArgLen+1)
	cases := map[string]func(*DaemonConfig){
		"empty label":               func(c *DaemonConfig) { c.Label = "" },
		"single-component label":    func(c *DaemonConfig) { c.Label = "helper" },
		"label with a slash":        func(c *DaemonConfig) { c.Label = "com.acme/helper" },
		"label with a space":        func(c *DaemonConfig) { c.Label = "com.acme helper" },
		"label with an empty part":  func(c *DaemonConfig) { c.Label = "com..acme" },
		"label hyphen-edged":        func(c *DaemonConfig) { c.Label = "com.-acme" },
		"label with unicode":        func(c *DaemonConfig) { c.Label = "com.acmé.helper" },
		"label too long":            func(c *DaemonConfig) { c.Label = "com." + strings.Repeat("a", maxLabelLen) },
		"absolute program":          func(c *DaemonConfig) { c.BundleProgram = "/usr/bin/true" },
		"program outside Contents":  func(c *DaemonConfig) { c.BundleProgram = "MacOS/acme-helper" },
		"program is Contents":       func(c *DaemonConfig) { c.BundleProgram = "Contents/" },
		"program traversal":         func(c *DaemonConfig) { c.BundleProgram = "Contents/../../../../usr/bin/true" },
		"program dot component":     func(c *DaemonConfig) { c.BundleProgram = "Contents/./MacOS/x" },
		"program hidden component":  func(c *DaemonConfig) { c.BundleProgram = "Contents/MacOS/.x" },
		"program empty component":   func(c *DaemonConfig) { c.BundleProgram = "Contents//x" },
		"program backslash":         func(c *DaemonConfig) { c.BundleProgram = `Contents\MacOS\x` },
		"program trailing slash":    func(c *DaemonConfig) { c.BundleProgram = "Contents/MacOS/" },
		"program with a space":      func(c *DaemonConfig) { c.BundleProgram = "Contents/MacOS/a b" },
		"program too long":          func(c *DaemonConfig) { c.BundleProgram = "Contents/" + strings.Repeat("a", maxProgramLen) },
		"no associated ids":         func(c *DaemonConfig) { c.AssociatedBundleIdentifiers = nil },
		"bad associated id":         func(c *DaemonConfig) { c.AssociatedBundleIdentifiers = []string{"acme"} },
		"one good one bad id":       func(c *DaemonConfig) { c.AssociatedBundleIdentifiers = []string{"com.acme.app", "x/y"} },
		"empty argument":            func(c *DaemonConfig) { c.Arguments = []string{""} },
		"argument too long":         func(c *DaemonConfig) { c.Arguments = []string{long} },
		"argument leading space":    func(c *DaemonConfig) { c.Arguments = []string{" serve"} },
		"argument trailing space":   func(c *DaemonConfig) { c.Arguments = []string{"serve "} },
		"argument tab":              func(c *DaemonConfig) { c.Arguments = []string{"a\tb"} },
		"argument traversal":        func(c *DaemonConfig) { c.Arguments = []string{"/Library/../private/tmp/x.sock"} },
		"argument bare dotdot":      func(c *DaemonConfig) { c.Arguments = []string{".."} },
		"argument semicolon":        func(c *DaemonConfig) { c.Arguments = []string{"serve;id"} },
		"argument backtick":         func(c *DaemonConfig) { c.Arguments = []string{"`id`"} },
		"argument non-ascii":        func(c *DaemonConfig) { c.Arguments = []string{"sérve"} },
		"too many arguments":        func(c *DaemonConfig) { c.Arguments = slices.Repeat([]string{"x"}, maxArgs+1) },
		"argument backslash escape": func(c *DaemonConfig) { c.Arguments = []string{`a\"b`} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := goodDaemon()
			mutate(&cfg)
			if _, err := DaemonPlist(cfg); !errors.Is(err, ErrRequest) {
				t.Fatalf("err = %v, want ErrRequest", err)
			}
		})
	}
}

func TestDaemonPlistAcceptsTheEdges(t *testing.T) {
	cfg := goodDaemon()
	cfg.Label = "a.b"
	cfg.BundleProgram = "Contents/Library/LaunchServices/com.acme.app_helper-2.bin"
	cfg.AssociatedBundleIdentifiers = []string{"com.acme.app", "com.acme.app-beta"}
	cfg.Arguments = append(slices.Repeat([]string{"x"}, maxArgs-1), strings.Repeat("a", maxArgLen))
	if _, err := DaemonPlist(cfg); err != nil {
		t.Fatalf("a config at the limits was refused: %v", err)
	}
	cfg.Arguments = nil
	out, err := DaemonPlist(cfg)
	if err != nil {
		t.Fatalf("no arguments was refused: %v", err)
	}
	if !bytes.Contains(out, []byte("<string>com.acme.app_helper-2.bin</string>")) {
		t.Fatalf("argv[0] is not the program's base name:\n%s", out)
	}
	for _, a := range []string{"--endpoint=/var/run/x.sock", "user@host:1,2+3", "a..b", "..x"} {
		if err := checkDaemonArg(a); err != nil {
			t.Errorf("checkDaemonArg(%q) = %v", a, err)
		}
	}
}

func TestCheckPlistName(t *testing.T) {
	for _, ok := range []string{"com.acme.app.helper.plist", "a.b.plist"} {
		if err := checkPlistName(ok); err != nil {
			t.Errorf("checkPlistName(%q) = %v", ok, err)
		}
	}
	bad := []string{
		"",
		".plist",
		"helper.plist",
		"com.acme.helper",
		"com.acme.helper.PLIST",
		"com.acme.helper.plist.plist.x",
		"../com.acme.helper.plist",
		"LaunchDaemons/com.acme.helper.plist",
		"/Library/LaunchDaemons/com.acme.helper.plist",
		`..\com.acme.helper.plist`,
		"com.acme..plist",
		"com.acme helper.plist",
		"com.acme.helper\x00.plist",
		"com.acme.hélper.plist",
		"com.acme." + strings.Repeat("a", maxLabelLen) + ".plist",
	}
	for _, name := range bad {
		if err := checkPlistName(name); !errors.Is(err, ErrRequest) {
			t.Errorf("VULNERABILITY: checkPlistName(%q) = %v, want ErrRequest", name, err)
		}
	}
}
