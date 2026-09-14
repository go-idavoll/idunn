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

package fetch

import "time"

// NewWithSleep is New with the pause between resume attempts replaced, so a test
// can count the pauses instead of waiting them out.
func NewWithSleep(o Options, sleep func(time.Duration)) (Fetcher, error) {
	return newFetcher(o, sleep)
}

// ResumeBackoff exposes the backoff schedule to tests.
var ResumeBackoff = resumeBackoff
