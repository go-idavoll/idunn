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

//go:build !darwin || !cgo

package elevate

import "fmt"

// SMAppService is a macOS framework reached through Objective-C, so it exists
// only in a darwin build with cgo. A darwin build without cgo — which is how
// the reproducible release commands are built (scripts/repro.sh) — fails closed
// here just as Linux and Windows do.

var errNoSMAppService = fmt.Errorf("%w: SMAppService needs macOS and a build with cgo (IDN-08)", ErrNotImplemented)

func smDaemonStatus(string) (int64, error) { return 0, errNoSMAppService }

func smRegisterDaemon(string) error { return errNoSMAppService }

func smUnregisterDaemon(string) error { return errNoSMAppService }

func smOpenLoginItemsSettings() error { return errNoSMAppService }
