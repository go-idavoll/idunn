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

// Package installer performs the first-time install bootstrap.
//
// A fresh install is the same transaction as an update with an empty FromVersion,
// plus a downgrade preflight: installing over an existing newer install is refused
// unless explicitly allowed. See docs/design.md §5, §14.6.
package installer

import (
	"context"

	"github.com/go-idavoll/idunn/core/updater"
)

// Options configures a first-time install.
type Options struct {
	// Updater carries the already-configured trust client, filesystem and hooks.
	Updater updater.Options

	// Version selects an explicit version instead of the channel head. Empty
	// means "whatever the channel currently points at".
	Version string

	// AllowDowngrade permits installing over a newer existing install. Default
	// false: the preflight refuses and leaves the existing install untouched.
	AllowDowngrade bool
}

// Install performs the first-time install into Options.Updater.Root. It runs the
// downgrade preflight, then the ordinary verified transaction, so a failed install
// leaves no partial tree behind.
func Install(ctx context.Context, o Options) error {
	panic("not implemented")
}

// InstalledVersion reports the version currently installed under root, or "" if
// there is no install. An unreadable or inconsistent install is an error, not "".
func InstalledVersion(root string) (string, error) {
	panic("not implemented")
}
