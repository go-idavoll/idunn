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

package uninstall

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/go-idavoll/idunn/core/fsx"
)

// Windows will not delete a file a process is executing from, and the launcher
// running the uninstall is exactly that file. So the launcher's last act is to
// hand its own removal to a copy of itself, the way rustup and uv remove
// themselves (mitsuhiko/self-replace):
//
//  1. The launcher copies itself beside the install root — not into %TEMP%, where
//     endpoint protection commonly refuses to start a program — and opens the
//     copy with FILE_FLAG_DELETE_ON_CLOSE through an inheritable handle.
//  2. It starts the copy with that handle and an inheritable handle to its own
//     process, and exits.
//  3. The copy (Finish) waits on the process handle, deletes the launcher and
//     the empty root, and starts `cmd.exe /d /c exit` with the copy's handle.
//  4. The copy exits. Its image is unmapped; cmd.exe still holds the handle.
//     When cmd.exe exits the last handle closes, and Windows deletes the copy.
//
// Step 3's cmd.exe exists only to hold the handle past the copy's own exit: a
// file cannot be deleted while it is mapped as an image, and a process's
// handles are closed before its image is gone. It runs nothing.
//
// Waiting on a process handle rather than a pid means a pid reused after the
// launcher exits cannot make the copy wait for the wrong process. No
// administrator rights are involved at any step.

// finishWait bounds how long the copy waits for the launcher to exit. The
// launcher exits as soon as it has started the copy, so this is only what turns
// a hang into an exit.
const finishWait = 5 * time.Minute

// removeRetries and removeRetryDelay give the file a moment to become deletable
// after the process object is signalled.
const (
	removeRetries    = 50
	removeRetryDelay = 100 * time.Millisecond
)

// privileged is running with an elevated token.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }

// removeSelfOS deletes the launcher when it can, which is when this process is
// not executing from it, and otherwise starts the copy that will.
func removeSelfOS(f fsx.FS, self, root string, removeRoot bool) (bool, error) {
	err := f.Remove(self)
	if err == nil || fsx.IsNotExist(err) {
		return false, nil
	}
	if serr := scheduleFinish(filepath.FromSlash(self), filepath.FromSlash(root), removeRoot); serr != nil {
		return false, fmt.Errorf("%w; and no copy could be started to remove it: %w", err, serr)
	}
	return true, nil
}

// scheduleFinish starts the copy that removes self (steps 1 and 2 above).
func scheduleFinish(self, root string, removeRoot bool) error {
	stem := strings.TrimSuffix(filepath.Base(self), filepath.Ext(self))
	copyPath := filepath.Join(filepath.Dir(root), fmt.Sprintf(".%s.idunn-uninstall-%d.exe", stem, os.Getpid()))
	if err := copyFile(self, copyPath); err != nil {
		return err
	}

	name, err := windows.UTF16PtrFromString(copyPath)
	if err != nil {
		_ = os.Remove(copyPath)
		return err
	}
	sa := &windows.SecurityAttributes{InheritHandle: 1}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	file, err := windows.CreateFile(name, windows.GENERIC_READ|windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, sa, windows.OPEN_EXISTING,
		windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
	if err != nil {
		_ = os.Remove(copyPath)
		return fmt.Errorf("opening %s: %w", copyPath, err)
	}
	// Closing this handle is safe once the copy has started: it holds its own,
	// inherited one. If it never starts, this close deletes the copy.
	defer func() { _ = windows.CloseHandle(file) }()

	cur := windows.CurrentProcess()
	var proc windows.Handle
	if err := windows.DuplicateHandle(cur, cur, cur, &proc, windows.SYNCHRONIZE, true, 0); err != nil {
		return fmt.Errorf("duplicating the process handle: %w", err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()

	args := []string{FinishArg,
		"--process", strconv.FormatUint(uint64(proc), 10),
		"--copy", strconv.FormatUint(uint64(file), 10),
		"--launcher", self,
	}
	if removeRoot {
		args = append(args, "--remove-root")
	}
	cmd := exec.CommandContext(context.Background(), copyPath, args...) //nolint:gosec // G204: copyPath is our own copy of this launcher; args are handles and our own path.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:                 true,
		CreationFlags:              windows.CREATE_NO_WINDOW,
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(proc), syscall.Handle(file)},
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", copyPath, err)
	}
	_ = cmd.Process.Release()
	return nil
}

// copyFile copies the launcher to dst, which must not exist yet.
func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755) //nolint:gosec // G302: a launcher is an executable; it must be runnable.
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	_, err = io.Copy(out, in)
	return err
}

// Finish is the copy's side (steps 3 and 4 above). A launcher started with
// FinishArg calls it with the remaining arguments and exits with its result;
// nothing is shown, since the copy runs without a console.
//
// It removes only the launcher it is told about, its old images, and the root
// when that is empty — whatever else an uninstall kept stays. It does nothing
// before the process it was handed has exited.
func Finish(args []string) error {
	fs := flag.NewFlagSet(FinishArg, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		process    = fs.Uint64("process", 0, "")
		copyHandle = fs.Uint64("copy", 0, "")
		launcher   = fs.String("launcher", "", "")
		removeRoot = fs.Bool("remove-root", false, "")
	)
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", ErrUninstall, err)
	}
	if fs.NArg() != 0 || *process == 0 || *copyHandle == 0 || *launcher == "" || !filepath.IsAbs(*launcher) {
		return fmt.Errorf("%w: %s needs --process, --copy and an absolute --launcher", ErrUninstall, FinishArg)
	}
	file := windows.Handle(*copyHandle)
	// Whatever happens below, the handle to this copy has to outlive this
	// process, or the copy stays on disk.
	defer holdPastExit(file)

	proc := windows.Handle(*process)
	event, err := windows.WaitForSingleObject(proc, uint32(finishWait/time.Millisecond))
	_ = windows.CloseHandle(proc)
	if event != windows.WAIT_OBJECT_0 {
		if err == nil {
			err = fmt.Errorf("still running after %s", finishWait)
		}
		return fmt.Errorf("%w: waiting for the launcher to exit: %w", ErrUninstall, err)
	}

	info, err := os.Lstat(*launcher)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("%w: %w", ErrUninstall, err)
	case !info.Mode().IsRegular():
		return fmt.Errorf("%w: %s is not a regular file", ErrUninstall, *launcher)
	default:
		if err := removeWithRetry(*launcher); err != nil {
			return fmt.Errorf("%w: %w", ErrUninstall, err)
		}
	}
	root := filepath.Dir(*launcher)
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if isLauncherLeftover(e.Name(), filepath.Base(*launcher)) {
				_ = os.Remove(filepath.Join(root, e.Name()))
			}
		}
	}
	if *removeRoot {
		// Refuses a directory that is not empty, which is the only root this
		// may remove.
		_ = os.Remove(root)
	}
	return nil
}

// removeWithRetry deletes name, retrying while the image of the process that
// just exited is still being released.
func removeWithRetry(name string) error {
	var err error
	for range removeRetries {
		if err = os.Remove(name); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		time.Sleep(removeRetryDelay)
	}
	return err
}

// holdPastExit starts a process that inherits handle and exits at once (step 4
// above), so the handle is still open when this process's image is unmapped.
func holdPastExit(handle windows.Handle) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return
	}
	cmd := exec.CommandContext(context.Background(), filepath.Join(system, "cmd.exe"), "/d", "/c", "exit") //nolint:gosec // G204: GetSystemDirectory + a constant command; no input.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:                 true,
		CreationFlags:              windows.CREATE_NO_WINDOW,
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(handle)},
	}
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}
