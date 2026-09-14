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

//go:build darwin && cgo

package elevate

// This file is idunn's entire cgo surface: two Apple frameworks, reached for
// two jobs, with no callbacks, no structs crossing into Go, and no network.
//
//   - ServiceManagement (SMAppService, macOS 13+): register, unregister and query
//     the privileged helper daemon, and open Login Items for the user's approval.
//   - Security (SecCode, SecRequirement): judge the code of the process on the
//     other end of a helper connection, identified by its audit token.
//
// Everything that is a decision rather than a call lives in plain Go next door
// (launchd.go, smappservice.go, peerdecision.go) and is tested on every OS.

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework ServiceManagement -framework Security -framework CoreFoundation

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mach/message.h>
#import <Foundation/Foundation.h>
#import <ServiceManagement/ServiceManagement.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// Return codes of the idunn_sm_* bridges.
#define IDUNN_SM_OK          0
#define IDUNN_SM_UNAVAILABLE 1  // macOS older than 13: no SMAppService
#define IDUNN_SM_BADNAME     2  // not representable as an NSString
#define IDUNN_SM_FAILED      3  // the framework returned NO with an NSError

static char *idunn_error_text(NSError *err) {
	if (err == nil) {
		return strdup("no error object");
	}
	NSString *s = [NSString stringWithFormat:@"%@ (%@ %ld)",
		err.localizedDescription, err.domain, (long)err.code];
	const char *u = s.UTF8String;
	return strdup(u != NULL ? u : "unprintable error");
}

static int idunn_sm_status(const char *name, long *status) {
	if (@available(macOS 13.0, *)) {
		@autoreleasepool {
			NSString *n = [NSString stringWithUTF8String:name];
			if (n == nil) {
				return IDUNN_SM_BADNAME;
			}
			SMAppService *svc = [SMAppService daemonServiceWithPlistName:n];
			*status = (long)svc.status;
			return IDUNN_SM_OK;
		}
	}
	return IDUNN_SM_UNAVAILABLE;
}

// op: 1 = registerAndReturnError:, 2 = unregisterAndReturnError:.
static int idunn_sm_change(const char *name, int op, char **errText) {
	if (@available(macOS 13.0, *)) {
		@autoreleasepool {
			NSString *n = [NSString stringWithUTF8String:name];
			if (n == nil) {
				return IDUNN_SM_BADNAME;
			}
			SMAppService *svc = [SMAppService daemonServiceWithPlistName:n];
			NSError *err = nil;
			BOOL ok = op == 1 ? [svc registerAndReturnError:&err]
			                  : [svc unregisterAndReturnError:&err];
			if (!ok) {
				*errText = idunn_error_text(err);
				return IDUNN_SM_FAILED;
			}
			return IDUNN_SM_OK;
		}
	}
	return IDUNN_SM_UNAVAILABLE;
}

static int idunn_sm_open_login_items(void) {
	if (@available(macOS 13.0, *)) {
		[SMAppService openSystemSettingsLoginItems];
		return IDUNN_SM_OK;
	}
	return IDUNN_SM_UNAVAILABLE;
}

static OSStatus idunn_requirement_compiles(const char *text) {
	CFStringRef s = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
	if (s == NULL) {
		return errSecParam;
	}
	SecRequirementRef req = NULL;
	OSStatus st = SecRequirementCreateWithString(s, kSecCSDefaultFlags, &req);
	CFRelease(s);
	if (req != NULL) {
		CFRelease(req);
	}
	return st;
}

// Stages at which idunn_check_peer can fail, for the helper's log.
#define IDUNN_PEER_TOKEN       1  // getsockopt(LOCAL_PEERTOKEN)
#define IDUNN_PEER_ALLOC       2  // CoreFoundation allocation
#define IDUNN_PEER_GUEST       3  // SecCodeCopyGuestWithAttributes
#define IDUNN_PEER_REQUIREMENT 4  // SecRequirementCreateWithString
#define IDUNN_PEER_VALIDITY    5  // SecCodeCheckValidity

// idunn_check_peer judges the process on the other end of fd against the
// requirement. It returns errSecSuccess only when that process's code is valid
// and satisfies it; otherwise *stage says which step refused.
//
// The audit token is the kernel's record of the connecting process, taken at
// connect time. It carries the pid *version*, so the SecCode it resolves to is
// that process and not a later one that inherited its pid.
static OSStatus idunn_check_peer(int fd, const char *text, int *stage) {
	audit_token_t token;
	socklen_t len = sizeof(token);
	memset(&token, 0, sizeof(token));
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0 || len != sizeof(token)) {
		*stage = IDUNN_PEER_TOKEN;
		return errSecParam;
	}

	CFDataRef tokenData = CFDataCreate(NULL, (const UInt8 *)&token, sizeof(token));
	if (tokenData == NULL) {
		*stage = IDUNN_PEER_ALLOC;
		return errSecAllocate;
	}
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *values[] = { tokenData };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, values, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(tokenData);
	if (attrs == NULL) {
		*stage = IDUNN_PEER_ALLOC;
		return errSecAllocate;
	}

	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	if (st != errSecSuccess || code == NULL) {
		if (code != NULL) {
			CFRelease(code);
		}
		*stage = IDUNN_PEER_GUEST;
		return st != errSecSuccess ? st : errSecCSNoSuchCode;
	}

	CFStringRef s = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
	if (s == NULL) {
		CFRelease(code);
		*stage = IDUNN_PEER_ALLOC;
		return errSecAllocate;
	}
	SecRequirementRef req = NULL;
	st = SecRequirementCreateWithString(s, kSecCSDefaultFlags, &req);
	CFRelease(s);
	if (st != errSecSuccess || req == NULL) {
		if (req != NULL) {
			CFRelease(req);
		}
		CFRelease(code);
		*stage = IDUNN_PEER_REQUIREMENT;
		return st != errSecSuccess ? st : errSecParam;
	}

	st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	CFRelease(req);
	CFRelease(code);
	if (st != errSecSuccess) {
		*stage = IDUNN_PEER_VALIDITY;
	}
	return st;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"unsafe"
)

func smError(rc C.int, what string, text *C.char) error {
	switch rc {
	case C.IDUNN_SM_UNAVAILABLE:
		return fmt.Errorf("%w: SMAppService needs macOS 13 or later (IDN-08)", ErrNotImplemented)
	case C.IDUNN_SM_BADNAME:
		return fmt.Errorf("%w: plist name is not representable", ErrRequest)
	case C.IDUNN_SM_FAILED:
		msg := "unknown"
		if text != nil {
			msg = C.GoString(text)
		}
		return fmt.Errorf("%w: SMAppService %s: %s", ErrHelper, what, msg)
	default:
		return fmt.Errorf("%w: SMAppService %s: unexpected bridge result %d", ErrHelper, what, int(rc))
	}
}

func smDaemonStatus(name string) (int64, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var status C.long
	if rc := C.idunn_sm_status(cname, &status); rc != C.IDUNN_SM_OK {
		return 0, smError(rc, "status", nil)
	}
	return int64(status), nil
}

func smChange(name string, op C.int, what string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var text *C.char
	rc := C.idunn_sm_change(cname, op, &text)
	if text != nil {
		defer C.free(unsafe.Pointer(text))
	}
	if rc != C.IDUNN_SM_OK {
		return smError(rc, what, text)
	}
	return nil
}

func smRegisterDaemon(name string) error { return smChange(name, 1, "register") }

func smUnregisterDaemon(name string) error { return smChange(name, 2, "unregister") }

func smOpenLoginItemsSettings() error {
	if rc := C.idunn_sm_open_login_items(); rc != C.IDUNN_SM_OK {
		return smError(rc, "open Login Items", nil)
	}
	return nil
}

// checkPeerRequirement validates the text and has Security.framework compile
// it, so a typo stops the helper at start rather than denying every caller
// later with a reason nobody reads.
func checkPeerRequirement(req string) error {
	if err := checkRequirementText(req); err != nil {
		return err
	}
	ctext := C.CString(req)
	defer C.free(unsafe.Pointer(ctext))
	if st := C.idunn_requirement_compiles(ctext); st != C.errSecSuccess {
		return fmt.Errorf("%w: peer requirement does not compile (OSStatus %d)", ErrRequest, int32(st))
	}
	return nil
}

var peerStages = map[C.int]string{
	C.IDUNN_PEER_TOKEN:       "reading the audit token",
	C.IDUNN_PEER_ALLOC:       "allocating",
	C.IDUNN_PEER_GUEST:       "resolving the peer's code",
	C.IDUNN_PEER_REQUIREMENT: "compiling the requirement",
	C.IDUNN_PEER_VALIDITY:    "checking the peer's code",
}

// peerCodeCheck judges the connected process's code signature against req.
func peerCodeCheck(conn net.Conn, req string) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	ctext := C.CString(req)
	defer C.free(unsafe.Pointer(ctext))

	var st C.OSStatus
	var stage C.int
	if err := raw.Control(func(fd uintptr) {
		st = C.idunn_check_peer(C.int(fd), ctext, &stage)
	}); err != nil {
		return err
	}
	if st != C.errSecSuccess {
		return fmt.Errorf("%s: OSStatus %d", peerStages[stage], int32(st))
	}
	return nil
}
