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

// Command installer is the thin first-install binary: it carries the embedded TUF
// root, resolves the channel, and hands the work to core/installer. It contains no
// trust logic of its own. See docs/design.md §5.
package main

import "fmt"

func main() {
	fmt.Println("idunn installer: not implemented")
}
