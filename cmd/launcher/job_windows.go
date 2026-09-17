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

package main

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// lifetimeJob ties the application's lifetime to the launcher's (IDN-40).
//
// The launcher puts itself into a job object that kills every process in it
// when its last handle closes, and holds the only handle. Every process the
// launcher starts from then on — the application, and whatever the application
// starts — is in the job too, so a launcher that dies for any reason, including
// TerminateProcess, takes them along instead of leaving them behind as orphans
// nobody passes an exit code for.
//
// The launcher joins the job itself rather than assigning the application to it:
// a child assigned after it was created would run unassigned for a moment, and
// closing that gap needs a suspended start whose main thread os/exec does not
// expose. Nested jobs (Windows 8 and later) make joining work when the launcher
// already runs inside one, as it does under a CI runner, a terminal or a service
// host.
type lifetimeJob struct {
	once sync.Once
	h    windows.Handle
	err  error
}

var job lifetimeJob

// join creates the job and moves this process into it, once.
func (j *lifetimeJob) join() error {
	j.once.Do(func() {
		h, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			j.err = fmt.Errorf("creating the job object: %w", err)
			return
		}
		if err := setJobLimits(h, windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK); err != nil {
			_ = windows.CloseHandle(h)
			j.err = err
			return
		}
		if err := windows.AssignProcessToJobObject(h, windows.CurrentProcess()); err != nil {
			_ = windows.CloseHandle(h)
			j.err = fmt.Errorf("joining the job object: %w", err)
			return
		}
		// The handle is never closed on purpose: closing it is what ends the
		// job, and the launcher's exit does that.
		j.h = h
	})
	return j.err
}

// release lets whatever the application left running outlive the launcher.
//
// Called once the application has exited on its own: from then on the job's
// purpose is served, and a process the application started and meant to keep —
// a browser it opened, a detached helper — must not die because the launcher
// that stood in front of it exits. Only a launcher that dies while the
// application still runs takes the tree along.
func (j *lifetimeJob) release() error {
	if j.h == 0 {
		return nil
	}
	return setJobLimits(j.h, windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
}

// rearm restores kill-on-close before the application is started again, after
// a relaunch (IDN-29).
func (j *lifetimeJob) rearm() error {
	if j.h == 0 {
		return nil
	}
	return setJobLimits(j.h, windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
}

// setJobLimits sets the job's limit flags and nothing else.
//
// JOB_OBJECT_LIMIT_BREAKAWAY_OK lets a process the application starts with
// CREATE_BREAKAWAY_FROM_JOB leave the job deliberately; without that flag nothing
// leaves it.
func setJobLimits(h windows.Handle, flags uint32) error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = flags
	//nolint:gosec // G103: JOBOBJECT_EXTENDED_LIMIT_INFORMATION is passed by pointer with its size, per the Win32 API.
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("setting the job object's limits: %w", err)
	}
	return nil
}
