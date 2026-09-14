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
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// logName is the helper's log file in its state directory when it runs as a
// service, where there is no console to write to. The state directory is one
// only administrators control, so the log is as private as the caller list.
const logName = "helper.log"

// runService runs body under the service control manager when started by it,
// and in the foreground (stopped by Ctrl+C) otherwise.
func runService(body func(context.Context, io.Writer) int, stderr io.Writer) int {
	isService, err := svc.IsWindowsService()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper: cannot tell whether this is a service: %v\n", err)
		return exitError
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return body(ctx, stderr)
	}

	b, err := loadBuild(buildFS)
	if err != nil {
		return exitRefuse
	}
	paths, err := pathsFor(b.helper.Label)
	if err != nil {
		return exitRefuse
	}
	logw := io.Discard
	if f, err := openServiceLog(paths.StateDir); err == nil {
		defer func() { _ = f.Close() }()
		logw = f
	}
	h := &serviceHandler{body: body, logw: logw}
	if err := svc.Run(b.helper.Label, h); err != nil {
		_, _ = fmt.Fprintf(logw, "helper: service: %v\n", err)
		return exitError
	}
	return h.code
}

// openServiceLog appends to the log in the state directory, creating the
// directory only if it is missing; serve judges the directory before trusting
// anything in it.
func openServiceLog(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(stateDir, logName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

type serviceHandler struct {
	body func(context.Context, io.Writer) int
	logw io.Writer
	code int
}

// Execute is the service main loop: report running, run the helper, and turn
// Stop and Shutdown into a cancelled context.
func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() { done <- h.body(ctx, h.logw) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case h.code = <-done:
			status <- svc.Status{State: svc.StopPending}
			// A non-zero exit is reported as a service-specific error, so the
			// recovery actions configured for the service apply.
			if h.code != exitOK {
				return true, uint32(h.code) //nolint:gosec // G115: exit codes are small and non-negative.
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}

func requireAdministrator() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errNotAdministrator
	}
	return nil
}
