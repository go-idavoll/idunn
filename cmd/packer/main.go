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

// Command packer builds release artifacts and maintains the TUF repository from a
// pack.yaml. It is a maintainer tool run via go:generate, never shipped to clients.
//
// Role keys are supplied via env/HSM and are never read from, written to, or
// printed by this tool (AGENTS.md §5). Its output must be reproducible: no
// wall-clock, randomness, or environment leakage into artifacts (§1.7). See
// docs/design.md §9.
package main

import "fmt"

func main() {
	fmt.Println("idunn packer: not implemented")
}
