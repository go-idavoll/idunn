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

//go:build !windows

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// runService runs body in the foreground until SIGINT or SIGTERM — the signals
// launchd and systemd stop a daemon with. Logs go to stderr, which both collect.
func runService(body func(context.Context, io.Writer) int, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return body(ctx, stderr)
}

func requireAdministrator() error {
	if os.Geteuid() != 0 {
		return errNotAdministrator
	}
	return nil
}
