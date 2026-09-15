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

package integrate

import (
	"fmt"
	"io/fs"
	"math"
	"strings"
	"unicode"

	"github.com/go-idavoll/idunn/core/fsx"
	"github.com/go-idavoll/idunn/internal/layout"
)

// UninstallKey is the registry key, below HKEY_CURRENT_USER or the 64-bit view of
// HKEY_LOCAL_MACHINE, that holds one subkey per "Installed apps" entry.
const UninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

// The values of an entry. The names are Windows'; OwnerValue is idunn's own.
const (
	valueDisplayName          = "DisplayName"
	valuePublisher            = "Publisher"
	valueDisplayIcon          = "DisplayIcon"
	valueDisplayVersion       = "DisplayVersion"
	valueInstallLocation      = "InstallLocation"
	valueInstallDate          = "InstallDate"
	valueEstimatedSize        = "EstimatedSize"
	valueUninstallString      = "UninstallString"
	valueQuietUninstallString = "QuietUninstallString"
	valueModifyPath           = "ModifyPath"
	valueNoModify             = "NoModify"
	valueNoRepair             = "NoRepair"
	valueOwner                = OwnerValue
)

// OwnerValue is the value in which an entry records the install root it was
// registered for. Windows ignores it; it is what tells an entry of this
// installation from one of another root, or of other software, so that nothing
// is removed or overwritten that is not this installation's.
const OwnerValue = "IdunnInstallRoot"

// UninstallEntry is what a host says about its Windows "Installed apps" entry.
// Everything that follows from the installation itself — the version, the
// location, the size, the commands that uninstall it — is derived by the
// Integrator and not configurable here.
//
// When an MSI installed the application (IDN-34), Windows Installer owns the
// entry and a host registers none of its own.
type UninstallEntry struct {
	// Scope is whose entry it is. A machine entry is written to
	// HKEY_LOCAL_MACHINE and needs administrator rights.
	Scope Scope

	// ID is the entry's key name, stable for the life of the application —
	// Windows and management tools (winget, Intune) know the application by
	// it. Letters, digits, '.', '_', '-', '{' and '}'.
	ID string

	// DisplayName is the application's name as the list shows it. Required.
	DisplayName string

	// Publisher is who the list says published it. Optional.
	Publisher string

	// Launcher is the launcher's file name directly in the root. The uninstall
	// commands are this launcher's --uninstall verb (IDN-35). Required.
	Launcher string

	// Icon is the install-relative path, inside the version directory, of a
	// file to take the entry's icon from — the application's executable,
	// typically. It follows the version the pointer names. Empty uses the
	// launcher.
	Icon string

	// ModifyPath is the command line Settings runs for "Modify". Core
	// registers none: without a UI there is nothing for it to open, so the
	// default hides the button. A UI sidecar registers its own entry point
	// here and presents the dialog (update now, repair, uninstall).
	ModifyPath string

	// Repair shows the "Repair" button, which runs ModifyPath. Default hidden.
	Repair bool
}

func (e UninstallEntry) validate() error {
	if !e.Scope.valid() {
		return fmt.Errorf("%w: unknown scope %q", ErrIntegrate, e.Scope)
	}
	if err := validateID(e.ID); err != nil {
		return err
	}
	if strings.TrimSpace(e.DisplayName) == "" {
		return fmt.Errorf("%w: the entry has no display name", ErrIntegrate)
	}
	for _, f := range []struct{ name, val string }{
		{"display name", e.DisplayName}, {"publisher", e.Publisher}, {"modify path", e.ModifyPath},
	} {
		if strings.IndexFunc(f.val, unicode.IsControl) >= 0 {
			return fmt.Errorf("%w: the entry's %s contains a control character", ErrIntegrate, f.name)
		}
	}
	if e.Repair && e.ModifyPath == "" {
		return fmt.Errorf("%w: a Repair button needs a ModifyPath to run", ErrIntegrate)
	}
	return e.record().validate()
}

func (e UninstallEntry) record() Record {
	return Record{Kind: KindWindowsUninstall, Scope: e.Scope, ID: e.ID, Launcher: e.Launcher, Icon: e.Icon}
}

// values are the entry's values that follow from the host's configuration and
// the root, and do not change with the version.
func (e UninstallEntry) values(root string) map[string]Value {
	launcher := `"` + windowsPath(fsx.Join(root, e.Launcher)) + `"`
	v := map[string]Value{
		valueDisplayName:          String(e.DisplayName),
		valueInstallLocation:      String(windowsPath(root)),
		valueUninstallString:      String(launcher + " --uninstall"),
		valueQuietUninstallString: String(launcher + " --uninstall --quiet"),
		valueNoModify:             DWord(boolDWord(e.ModifyPath == "")),
		valueNoRepair:             DWord(boolDWord(!e.Repair)),
		valueOwner:                String(windowsPath(root)),
	}
	if e.Publisher != "" {
		v[valuePublisher] = String(e.Publisher)
	}
	if e.ModifyPath != "" {
		v[valueModifyPath] = String(e.ModifyPath)
	}
	return v
}

// derived are the values that follow from the version the pointer names.
func (i *Integrator) derived(rec Record, version string) (map[string]Value, error) {
	icon, err := rec.icon(i.root, version)
	if err != nil {
		return nil, err
	}
	size, err := i.estimatedSize(rec, version)
	if err != nil {
		return nil, err
	}
	return map[string]Value{
		valueDisplayVersion: String(version),
		valueDisplayIcon:    String(icon),
		valueEstimatedSize:  DWord(size),
	}, nil
}

// icon is the file the entry takes its icon from, for version.
func (r Record) icon(root, version string) (string, error) {
	if r.Icon == "" {
		return windowsPath(fsx.Join(root, r.Launcher)), nil
	}
	dir, err := layout.VersionDir(root, version)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrIntegrate, err)
	}
	return windowsPath(fsx.Join(dir, r.Icon)), nil
}

// estimatedSize is the size of the live version directory and the launcher, in
// KiB, as Windows expects it. Links are not followed and count as nothing: a
// size that could be steered outside the root would be a way to make this walk
// anything.
func (i *Integrator) estimatedSize(rec Record, version string) (uint32, error) {
	dir, err := layout.VersionDir(i.root, version)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrIntegrate, err)
	}
	total, err := i.treeSize(dir)
	if err != nil {
		return 0, fmt.Errorf("%w: sizing %s: %w", ErrIntegrate, dir, err)
	}
	if info, err := fsx.Lstat(i.fs, fsx.Join(i.root, rec.Launcher)); err == nil && info.Mode().IsRegular() {
		total += info.Size()
	}
	kib := (total + 1023) / 1024
	if kib > math.MaxUint32 {
		return math.MaxUint32, nil
	}
	return uint32(kib), nil //nolint:gosec // G115: bounded by the check above.
}

func (i *Integrator) treeSize(name string) (int64, error) {
	info, err := fsx.Lstat(i.fs, name)
	if err != nil {
		return 0, err
	}
	switch {
	case info.Mode().IsRegular():
		return info.Size(), nil
	case !info.IsDir() || info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
		return 0, nil
	}
	entries, err := i.fs.ReadDir(name)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		n, err := i.treeSize(fsx.Join(name, e.Name()))
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

// hive is where a record's key lives.
func (r Record) hive() Hive {
	if r.Scope == ScopeMachine {
		return HiveMachine
	}
	return HiveUser
}

// keyPath is a record's key below its hive. The ID was validated to be one key
// name, so this cannot address any other key.
func (r Record) keyPath() string { return UninstallKey + `\` + r.ID }

// windowsPath spells a slash-space path the way the registry stores one.
func windowsPath(p string) string { return strings.ReplaceAll(p, "/", `\`) }

// sameRoot compares two roots as Windows does: without regard to case or to a
// trailing separator.
func sameRoot(a, b string) bool {
	return a != "" && strings.EqualFold(strings.TrimRight(a, `\`), strings.TrimRight(b, `\`))
}

func boolDWord(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
