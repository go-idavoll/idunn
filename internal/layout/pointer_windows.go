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

package layout

// activePointer selects the pointer-file form.
//
// The symlink form cannot work here, for two independent reasons. A symlink to a
// version directory is itself a directory, and MoveFileEx with
// MOVEFILE_REPLACE_EXISTING — which is what os.Rename compiles to — refuses to
// replace an existing directory: the swap fails with "Access is denied". And
// creating a symlink at all needs administrator rights or Developer Mode, which
// a per-user install does not have.
//
// Replacing a regular file by rename IS atomic here, so the pointer is a file
// naming versions/<v>, and the launcher reads it rather than walking through it
// (docs/design.md §13). Nothing in core reads through `current`, so this costs
// the update path nothing.
func activePointer() pointerForm { return filePointer{} }
