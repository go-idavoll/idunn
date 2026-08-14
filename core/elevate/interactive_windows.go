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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/go-idavoll/idunn/core/release"
)

// Interactive elevation on Windows is ShellExecuteEx with the verb "runas": the
// shell asks the Application Information service to start the target with the
// user's full token, which is what raises the UAC consent dialog. It is the only
// documented way to obtain that dialog; CreateProcess cannot elevate, and a token
// obtained by other means is not the same thing (docs/design.md §14.2).
//
// Two properties of the launch matter beyond "it starts a process":
//
//   - The elevated process is the trust boundary, not a delegate of ours. We hand
//     it a request (see Request), it verifies everything itself, and once it is
//     running we cannot and must not stop it mid-swap. Cancelling the context
//     therefore stops *waiting*; it does not stop the apply.
//   - The consent dialog is the user's decision. Declining it is ErrDeclined —
//     an ordinary, expected outcome that must not be logged or retried as a
//     failure of the update system.
const (
	// SEE_MASK_NOCLOSEPROCESS keeps hProcess valid after the call returns, which
	// is the only way to learn whether the elevated apply succeeded.
	seeMaskNoCloseProcess = 0x00000040
	// SEE_MASK_NOASYNC makes the call safe to issue from a process that may exit
	// or block right after: the shell finishes the DDE/COM work before returning.
	seeMaskNoAsync = 0x00000100
	// SEE_MASK_FLAG_NO_UI suppresses the shell's own error popups. An update that
	// runs unattended must return an error, not park a modal dialog on a desktop
	// nobody is watching. The UAC prompt itself is not affected by this.
	seeMaskFlagNoUI = 0x00000400

	swHide       = 0
	swShowNormal = 1

	// runasVerb triggers the elevation prompt. It is a field on the elevator
	// rather than a constant in the call so tests can exercise the whole Win32
	// path — quoting, handle, wait, exit code — with a verb that does not need
	// an administrator sitting at the machine.
	runasVerb = "runas"

	// waitSliceMs is how long each wait blocks before the context is re-checked.
	// Short enough that a cancelled update returns promptly, long enough that
	// waiting on a multi-minute apply costs nothing measurable.
	waitSliceMs = 200
)

// shellExecuteInfo mirrors SHELLEXECUTEINFOW. The field order and types are the
// ABI; do not reorder them. Go's alignment rules reproduce the C padding on both
// 386 and amd64 (the int32 nShow followed by a pointer-sized hInstApp, and the
// uint32 dwHotKey followed by the pointer-sized union member).
type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.HWND
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIconMonitor windows.Handle // union: hIcon / hMonitor.
	hProcess     windows.Handle
}

// shell32 is loaded from the system directory. NewLazySystemDLL pins the load to
// %SystemRoot%\System32, so a shell32.dll planted next to the application — or in
// any other directory on the search path — is not what we end up calling. For a
// package whose whole job is to start a process with administrator rights, the
// ordinary search order is not acceptable.
var (
	shell32             = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

// interactive is the Windows on-demand elevator.
type interactive struct {
	helper string // absolute path to the privileged apply helper.
	dir    string // working directory handed to the helper.
	show   int32  // SW_* window state for the helper's own window.
	verb   string // "runas" in production; overridden in tests.
}

var _ Elevator = (*interactive)(nil)

// newInteractive validates the helper and returns the elevator that will run it.
//
// The validation happens here, at construction, so a misconfigured updater fails
// when it is built rather than in the middle of an apply — the same rule the
// updater applies to its own options.
func newInteractive(opts InteractiveOptions) (Elevator, error) {
	helper := opts.HelperPath
	if helper == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("%w: cannot locate the running executable: %w", ErrRequest, err)
		}
		helper = exe
	}
	if err := checkHelperPath(helper); err != nil {
		return nil, err
	}
	show := int32(swHide)
	if opts.ShowWindow {
		show = swShowNormal
	}
	return &interactive{
		helper: helper,
		// The elevated process inherits a working directory. Ours is whatever the
		// host application happened to set, and on Windows the working directory
		// still participates in module resolution for a process started this way.
		// Pinning it to the helper's own directory keeps that surface inside the
		// administrator-owned tree the helper already has to live in.
		dir:  filepath.Dir(helper),
		show: show,
		verb: runasVerb,
	}, nil
}

// Apply requests the elevated apply and waits for the helper to finish.
func (e *interactive) Apply(ctx context.Context, root string, d *release.Descriptor) error {
	req, err := newRequest(root, d)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h, err := e.start(req)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	return waitForHelper(ctx, h)
}

// start launches the helper elevated and returns its process handle.
func (e *interactive) start(req Request) (windows.Handle, error) {
	verb, err := windows.UTF16PtrFromString(e.verb)
	if err != nil {
		return 0, fmt.Errorf("%w: verb: %w", ErrRequest, err)
	}
	file, err := windows.UTF16PtrFromString(e.helper)
	if err != nil {
		return 0, fmt.Errorf("%w: helper path: %w", ErrRequest, err)
	}
	dir, err := windows.UTF16PtrFromString(e.dir)
	if err != nil {
		return 0, fmt.Errorf("%w: helper directory: %w", ErrRequest, err)
	}
	params, err := windows.UTF16PtrFromString(commandLine(req.args()))
	if err != nil {
		return 0, fmt.Errorf("%w: helper arguments: %w", ErrRequest, err)
	}

	sei := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        e.show,
	}
	sei.cbSize = uint32(unsafe.Sizeof(sei))

	//nolint:gosec // G103: SHELLEXECUTEINFOW is passed by pointer — that is the
	// Win32 ABI, and there is no ShellExecuteEx binding in x/sys/windows to hide
	// it behind. The struct is stack-allocated here, filled entirely above, and
	// read back only through its own fields.
	ret, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	// The struct holds the only references the call reads through; keep the
	// strings alive until it has returned.
	runtime.KeepAlive(verb)
	runtime.KeepAlive(file)
	runtime.KeepAlive(dir)
	runtime.KeepAlive(params)

	if ret == 0 {
		// callErr carries GetLastError and is only meaningful on failure.
		if errors.Is(callErr, windows.ERROR_CANCELLED) {
			return 0, fmt.Errorf("%w: the elevation prompt was dismissed", ErrDeclined)
		}
		return 0, fmt.Errorf("%w: ShellExecuteEx(%q, %q): %w", ErrHelper, e.verb, e.helper, callErr)
	}
	if sei.hProcess == 0 {
		// SEE_MASK_NOCLOSEPROCESS was set, so a success without a handle means we
		// cannot observe the outcome. Reporting success we did not witness would
		// let a failed apply be recorded as an installed version.
		return 0, fmt.Errorf("%w: no process handle for %q", ErrHelper, e.helper)
	}
	return sei.hProcess, nil
}

// waitForHelper blocks until the helper exits, the wait fails, or ctx is done.
//
// Cancelling ctx abandons the wait; it does not terminate the elevated process.
// Killing a helper that may be mid-swap is precisely the half-written install the
// journal and this whole package exist to prevent (AGENTS.md §1.1), and an
// unprivileged process could not do it reliably anyway.
func waitForHelper(ctx context.Context, h windows.Handle) error {
	for {
		event, err := windows.WaitForSingleObject(h, waitSliceMs)
		switch event {
		case windows.WAIT_OBJECT_0:
			return helperExitStatus(h)
		case uint32(windows.WAIT_TIMEOUT):
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("%w (the elevated apply keeps running)", err)
			}
		default:
			return fmt.Errorf("%w: waiting for the helper: %w", ErrHelper, err)
		}
	}
}

// helperExitStatus turns the helper's exit code into this package's error taxonomy.
func helperExitStatus(h windows.Handle) error {
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return fmt.Errorf("%w: cannot read the helper exit code: %w", ErrHelper, err)
	}
	switch code {
	case 0:
		return nil
	case uint32(windows.ERROR_CANCELLED):
		// A helper that reports "cancelled" is relaying a user decision, not a
		// defect. Classifying it as a failure would turn "not now" into a retry
		// loop with a consent dialog on every pass.
		return fmt.Errorf("%w: the helper reported a cancelled apply", ErrDeclined)
	default:
		return fmt.Errorf("%w: helper exited with status %d", ErrHelper, code)
	}
}

// commandLine renders an argument vector as the single parameter string
// ShellExecuteEx takes.
//
// ShellExecuteEx has no argv form: the helper's own CommandLineToArgvW splits
// this string back apart, so the quoting has to be the exact inverse of that
// split. EscapeArg implements it; hand-rolled quoting here would be a second,
// subtly different parser on the privileged side of the boundary. The values are
// validated in newRequest as well — quoting is the mechanism, not the defence.
func commandLine(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	return strings.Join(quoted, " ")
}
