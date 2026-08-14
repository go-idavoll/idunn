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

package fsx

// SyncDir is a no-op on Windows.
//
// A directory handle there cannot be flushed the way a POSIX directory fd can,
// and NTFS makes the rename itself durable in its own metadata log. Reporting an
// error for an operation the platform does not offer would turn every successful
// commit into a spurious rollback, so the platform guarantee is what we rely on.
func (osFS) SyncDir(string) error { return nil }
