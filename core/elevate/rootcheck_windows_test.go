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

//go:build windows

package elevate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The security descriptors below are written in SDDL and judged without touching
// a disk, so every case is exact and none depends on the machine running it. The
// real descriptors of C:\, C:\Program Files and C:\ProgramData on a stock
// Windows 11 are among them, because those are the directories an install root
// is actually created in.
const (
	sddlDriveRoot    = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	sddlProgramFiles = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)"
	sddlProgramData  = "O:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)"
	// An install directory as a helper leaves it: inherited from Program Files.
	sddlInstalled = "O:BAD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICIIOID;GA;;;CO)(A;OICIIOID;GA;;;SY)(A;ID;0x1301bf;;;SY)(A;OICIIOID;GA;;;BA)(A;ID;0x1301bf;;;BA)(A;OICIIOID;GXGR;;;BU)(A;ID;0x1200a9;;;BU)"
)

func sd(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	d, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", sddl, err)
	}
	return d
}

func TestJudgeAcceptsWhatOnlyAdministratorsControl(t *testing.T) {
	for _, tc := range []struct {
		name string
		sddl string
		role role
	}{
		{"Program Files as the parent of a new root", sddlProgramFiles, roleParentOfNewRoot},
		{"Program Files as an ancestor", sddlProgramFiles, roleAncestor},
		{"the drive root as an ancestor: users may add folders, not move this one", sddlDriveRoot, roleAncestor},
		{"ProgramData as an ancestor", sddlProgramData, roleAncestor},
		{"an installed directory", sddlInstalled, roleContainer},
		{"owned by SYSTEM", "O:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", roleContainer},
		{"owned by TrustedInstaller", "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:(A;;FA;;;BA)", roleContainer},
		{"a deny ACE for users only takes away", "O:BAD:(D;OICI;FA;;;BU)(A;OICI;FA;;;BA)", roleContainer},
		{"OWNER RIGHTS applies to an administrator owner", "O:BAD:(A;;FA;;;OW)", roleContainer},
		{"an object-inherit ACE that does not propagate stays out of a new directory", "O:BAD:(A;OINPIO;FA;;;BU)", roleParentOfNewRoot},
		{"read and execute for everyone", "O:BAD:(A;OICI;0x1200a9;;;WD)", roleContainer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := judge(`C:\x`, 0, sd(t, tc.sddl), tc.role); err != nil {
				t.Fatalf("judge = %v, want nil", err)
			}
		})
	}
}

// Each case is a way a non-administrator keeps a hand on the root: owning it,
// being granted a right on it, inheriting one into what the helper creates, or
// replacing it with a link.
func TestJudgeRefusesWhatSomeoneElseControls(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sddl  string
		role  role
		attrs uint32
	}{
		{"the drive root as the parent of a new root", sddlDriveRoot, roleParentOfNewRoot, 0},
		{"ProgramData as the parent of a new root", sddlProgramData, roleParentOfNewRoot, 0},
		{"a junction in place of a directory", sddlInstalled, roleContainer, fileAttributeReparsePoint},
		{"a junction as an ancestor", sddlProgramFiles, roleAncestor, fileAttributeReparsePoint},
		{"owned by users", "O:BUD:(A;OICI;FA;;;BA)", roleContainer, 0},
		{"owned by a user", "O:S-1-5-21-1-2-3-1001D:(A;OICI;FA;;;BA)", roleAncestor, 0},
		{"a NULL DACL", "O:BAD:NO_ACCESS_CONTROL", roleAncestor, 0},
		{"users may create files", "O:BAD:(A;;0x2;;;BU)", roleContainer, 0},
		{"users may create folders", "O:BAD:(A;;0x4;;;BU)", roleContainer, 0},
		{"authenticated users may delete", "O:BAD:(A;;SD;;;AU)", roleAncestor, 0},
		{"users may delete children", "O:BAD:(A;;0x40;;;BU)", roleAncestor, 0},
		{"users may change the DACL", "O:BAD:(A;;WD;;;BU)", roleAncestor, 0},
		{"users may take ownership", "O:BAD:(A;;WO;;;BU)", roleAncestor, 0},
		{"everyone has generic all", "O:BAD:(A;;GA;;;WD)", roleAncestor, 0},
		{"users inherit write into what is created", "O:BAD:(A;OICIIO;GW;;;BU)", roleContainer, 0},
		{"users inherit modify into a new root", "O:BAD:(A;CIIO;0x1301bf;;;BU)", roleParentOfNewRoot, 0},
		{"a non-propagating container ACE still reaches the new root", "O:BAD:(A;CINP;FA;;;BU)", roleParentOfNewRoot, 0},
		{"a domain group of operators", "O:BAD:(A;OICI;FA;;;S-1-5-21-1-2-3-1105)", roleContainer, 0},
		{"a conditional allow ACE", "O:BAD:(XA;;FA;;;BU;(WIN://SYSAPPID Contains \"x\"))", roleContainer, 0},
		{"an object ACE this check does not read", "O:BAD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BA)", roleContainer, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := judge(`C:\x`, tc.attrs, sd(t, tc.sddl), tc.role); !errors.Is(err, ErrUnsafeRoot) {
				t.Fatalf("judge = %v, want ErrUnsafeRoot", err)
			}
		})
	}
}

func TestCheckPrivilegedRootOnThisMachine(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		t.Skip("no %ProgramFiles%")
	}
	if err := CheckPrivilegedRoot(filepath.Join(programFiles, "idunn-test-does-not-exist", "app")); err != nil {
		t.Fatalf("a new root under %s = %v, want nil", programFiles, err)
	}

	for _, root := range []string{
		filepath.Join(t.TempDir(), "app"), // under the user's profile.
		`\\localhost\c$\Program Files\app`,
		filepath.Join(programFiles, "..", "app"),
		"relative",
	} {
		err := CheckPrivilegedRoot(root)
		if !errors.Is(err, ErrUnsafeRoot) && !errors.Is(err, ErrRequest) {
			t.Errorf("CheckPrivilegedRoot(%q) = %v, want a refusal", root, err)
		}
	}
}

// A junction is judged as itself, not as what it points to: pointing one at a
// perfectly protected directory must not lend it that directory's ACL.
func TestCheckObjectDoesNotFollowAJunction(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		t.Skip("no %ProgramFiles%")
	}
	link := filepath.Join(t.TempDir(), "link")
	out, err := exec.CommandContext(t.Context(), "cmd", "/c", "mklink", "/J", link, programFiles).CombinedOutput()
	if err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
	err = checkObject(link, roleAncestor)
	if !errors.Is(err, ErrUnsafeRoot) || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("checkObject(junction to %s) = %v, want a reparse point refusal", programFiles, err)
	}
	if err := checkObject(programFiles, roleAncestor); err != nil {
		t.Fatalf("checkObject(%s) = %v, want nil: the refusal above is the junction's", programFiles, err)
	}
}

// freeDriveLetter returns a drive letter nothing is mounted on.
func freeDriveLetter(t *testing.T) string {
	t.Helper()
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	for i := 25; i >= 3; i-- { // from Z: down, away from the usual disks.
		if mask&(1<<uint(i)) == 0 {
			return string(rune('A'+i)) + ":"
		}
	}
	t.Skip("no free drive letter")
	return ""
}

// Only a local fixed disk is acceptable: what is not a disk of this machine has
// its permissions decided somewhere else.
func TestCheckVolumeRefusesWhatIsNotAFixedDisk(t *testing.T) {
	if err := checkVolume(freeDriveLetter(t) + `\app`); !errors.Is(err, ErrUnsafeRoot) {
		t.Fatalf("checkVolume(unmounted drive) = %v, want ErrUnsafeRoot", err)
	}
}

func TestJudgeVolume(t *testing.T) {
	if err := judgeVolume("C:", windows.DRIVE_FIXED, `\Device\HarddiskVolume3`); err != nil {
		t.Fatalf("judgeVolume(fixed disk) = %v, want nil", err)
	}
	for _, tc := range []struct {
		name      string
		driveType uint32
		device    string
	}{
		{"a mapped network drive", windows.DRIVE_REMOTE, `\Device\LanmanRedirector\;Z:0000000000012345\server\share`},
		{"a removable disk", windows.DRIVE_REMOVABLE, `\Device\HarddiskVolume9`},
		{"a RAM disk", windows.DRIVE_RAMDISK, `\Device\RamDisk`},
		{"an optical drive", windows.DRIVE_CDROM, `\Device\CdRom0`},
		{"no such drive", windows.DRIVE_NO_ROOT_DIR, ``},
		{"a SUBST drive", windows.DRIVE_FIXED, `\??\C:\Users\someone\evil`},
	} {
		if err := judgeVolume("Z:", tc.driveType, tc.device); !errors.Is(err, ErrUnsafeRoot) {
			t.Errorf("judgeVolume(%s) = %v, want ErrUnsafeRoot", tc.name, err)
		}
	}
}

// A SUBST drive is a fixed disk by type and a directory in truth. Mapped onto
// Program Files, it would pass every ACL check while its real ancestors are
// never looked at — and a user can point one at a directory they own.
func TestCheckPrivilegedRootRefusesASubstDrive(t *testing.T) {
	programFiles := os.Getenv("ProgramFiles")
	if programFiles == "" {
		t.Skip("no %ProgramFiles%")
	}
	drive := freeDriveLetter(t)
	if out, err := exec.CommandContext(t.Context(), "subst", drive, programFiles).CombinedOutput(); err != nil {
		t.Skipf("subst: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.CommandContext(context.Background(), "subst", drive, "/d").Run() })

	err := CheckPrivilegedRoot(drive + `\idunn-test-does-not-exist\app`)
	if !errors.Is(err, ErrUnsafeRoot) || !strings.Contains(err.Error(), "substituted") {
		t.Fatalf("CheckPrivilegedRoot(subst of %s) = %v, want a substituted-drive refusal", programFiles, err)
	}
}
