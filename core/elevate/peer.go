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

package elevate

// peer is who is on the other end of a helper connection.
//
// It is the operating system's answer, not the caller's claim: every
// implementation below reads it from the kernel through the connection itself,
// so a caller cannot state a uid and cannot be impersonated by another process
// that merely knows the endpoint. That is the entire basis on which the helper
// decides whether to act (§14.2, T16).
//
// pid is carried for the log and for nothing else. It is inherently racy — the
// process behind it may be gone or replaced by the time anything reads it — so
// no decision may be taken on it.
type peer struct {
	uid uint32
	pid int
}
