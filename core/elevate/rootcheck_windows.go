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
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Access rights, as they appear in a file or directory ACE.
const (
	fileAddFile      = 0x00000002 // FILE_WRITE_DATA on a file.
	fileAddSubdir    = 0x00000004 // FILE_APPEND_DATA on a file.
	fileDeleteChild  = 0x00000040
	rightDelete      = 0x00010000
	rightWriteDAC    = 0x00040000
	rightWriteOwner  = 0x00080000
	rightGenericAll  = 0x10000000
	rightGenericWrit = 0x40000000

	// moveRights let a holder delete, rename or re-permission an object — or,
	// through FILE_DELETE_CHILD, the entries of a directory.
	moveRights = rightDelete | rightWriteDAC | rightWriteOwner | fileDeleteChild | rightGenericAll

	// changeRights additionally let a holder create in a directory or write a
	// file. Writing extended attributes or basic attributes is left out: neither
	// redirects a write or replaces content.
	changeRights = moveRights | fileAddFile | fileAddSubdir | rightGenericWrit
)

// ACE types a DACL may hold. Only the allow types grant anything; a deny ACE can
// only take rights away, so ignoring it errs towards refusing.
const (
	aceAllowed         = 0x0
	aceDenied          = 0x1
	aceAllowedCallback = 0x9
	aceDeniedCallback  = 0xA
)

const fileAttributeReparsePoint = 0x400

// The principals a privileged install may be owned by and writable for.
var (
	sidSystem           = mustSID("S-1-5-18")
	sidAdministrators   = mustSID("S-1-5-32-544")
	sidTrustedInstaller = mustSID("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	// CREATOR OWNER and CREATOR GROUP in an inheritable ACE stand for whoever
	// creates the child — here, the privileged helper itself.
	sidCreatorOwner = mustSID("S-1-3-0")
	sidCreatorGroup = mustSID("S-1-3-1")
	// OWNER RIGHTS grants to the owner, who is checked separately.
	sidOwnerRights = mustSID("S-1-3-4")
)

func mustSID(s string) *windows.SID {
	sid, err := windows.StringToSid(s)
	if err != nil {
		panic(fmt.Sprintf("elevate: well-known SID %s: %v", s, err))
	}
	return sid
}

func isAdminPrincipal(sid *windows.SID) bool {
	return sid.Equals(sidSystem) || sid.Equals(sidAdministrators) || sid.Equals(sidTrustedInstaller)
}

// checkVolume refuses a root on anything but a local fixed disk. A removable
// disk can be rewritten elsewhere, a network drive's ACL is enforced by a server
// this machine does not control, and a SUBST drive is a path in disguise whose
// real ancestors this check would never see.
func checkVolume(dir string) error {
	vol := filepath.VolumeName(dir)
	if len(vol) != 2 || vol[1] != ':' {
		return fmt.Errorf("%w: %q is not on a drive letter", ErrUnsafeRoot, dir)
	}
	rootPath, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeRoot, err)
	}
	driveType := windows.GetDriveType(rootPath)
	name, err := windows.UTF16PtrFromString(vol)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeRoot, err)
	}
	const bufLen = windows.MAX_PATH
	buf := make([]uint16, bufLen)
	if _, err := windows.QueryDosDevice(name, &buf[0], uint32(bufLen)); err != nil {
		return fmt.Errorf("%w: cannot resolve %s: %w", ErrUnsafeRoot, vol, err)
	}
	return judgeVolume(vol, driveType, windows.UTF16ToString(buf))
}

// judgeVolume is checkVolume's decision, apart from the calls that feed it: the
// drive type, and the device the letter is defined as.
func judgeVolume(vol string, driveType uint32, device string) error {
	if driveType != windows.DRIVE_FIXED {
		return fmt.Errorf("%w: %s is not a fixed local disk (drive type %d)", ErrUnsafeRoot, vol, driveType)
	}
	if strings.HasPrefix(device, `\??\`) {
		return fmt.Errorf("%w: %s is a substituted drive for %s", ErrUnsafeRoot, vol, device)
	}
	return nil
}

// checkPointer judges the install's `current` entry. On Windows it is a file
// (internal/layout), judged like every other entry: a reparse point there is
// refused.
func checkPointer(path string) error { return checkObject(path, roleContainer) }

// checkObject reads one object's attributes, owner and DACL — without following
// a reparse point, so a junction is judged as itself — and judges them.
func checkObject(path string, r role) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeRoot, err)
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("%w: cannot inspect %q: %w", ErrUnsafeRoot, path, err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("%w: cannot inspect %q: %w", ErrUnsafeRoot, path, err)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: cannot read the security of %q: %w", ErrUnsafeRoot, path, err)
	}
	return judge(path, info.FileAttributes, sd, r)
}

// judge is the decision, apart from the system calls that feed it.
func judge(path string, attrs uint32, sd *windows.SECURITY_DESCRIPTOR, r role) error {
	if attrs&fileAttributeReparsePoint != 0 {
		return fmt.Errorf("%w: %q is a junction, symbolic link or other reparse point", ErrUnsafeRoot, path)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: %q has no readable owner", ErrUnsafeRoot, path)
	}
	if !isAdminPrincipal(owner) {
		// An owner may always rewrite the DACL, whatever it says today.
		return fmt.Errorf("%w: %q is owned by %s", ErrUnsafeRoot, path, owner)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%w: %q has no readable DACL: %w", ErrUnsafeRoot, path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%w: %q has a NULL DACL, which grants everyone everything", ErrUnsafeRoot, path)
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("%w: %q: ACE %d: %w", ErrUnsafeRoot, path, i, err)
		}
		switch ace.Header.AceType {
		case aceDenied, aceDeniedCallback:
			continue
		case aceAllowed, aceAllowedCallback:
		default:
			// Object ACEs and anything newer carry the SID elsewhere; not being
			// able to read what it grants is not a reason to assume nothing.
			return fmt.Errorf("%w: %q holds an ACE of type %#x this check does not read",
				ErrUnsafeRoot, path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: SidStart is the first byte of the SID in the ACE, per the Win32 ACE layout.
		if isAdminPrincipal(sid) || sid.Equals(sidOwnerRights) {
			continue
		}
		if denied := forbidden(ace.Header.AceFlags, uint32(ace.Mask), sid, r); denied != 0 {
			return fmt.Errorf("%w: %q grants %s access %#x", ErrUnsafeRoot, path, sid, denied)
		}
	}
	return nil
}

// forbidden returns the rights an ACE for a non-administrator grants that the
// role does not allow, or 0.
func forbidden(flags uint8, mask uint32, sid *windows.SID, r role) uint32 {
	inheritOnly := flags&windows.INHERIT_ONLY_ACE != 0
	inherits := flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
	// An object-inherit ACE that does not propagate reaches only the files
	// directly in this directory, not a directory created in it.
	reachesNewDir := flags&windows.CONTAINER_INHERIT_ACE != 0 ||
		(flags&windows.OBJECT_INHERIT_ACE != 0 && flags&windows.NO_PROPAGATE_INHERIT_ACE == 0)
	creator := sid.Equals(sidCreatorOwner) || sid.Equals(sidCreatorGroup)

	var bad uint32
	if !inheritOnly && !creator {
		switch r {
		case roleAncestor, roleParentOfNewRoot:
			bad |= mask & moveRights
		case roleContainer:
			bad |= mask & changeRights
		}
	}
	if !creator {
		switch {
		case r == roleContainer && inherits:
			bad |= mask & changeRights
		case r == roleParentOfNewRoot && reachesNewDir:
			bad |= mask & changeRights
		}
	}
	return bad
}
