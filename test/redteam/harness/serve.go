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

package harness

import (
	"net/http"
	"net/http/httptest"
)

// Server is a (possibly mutated) repository exposed over HTTP, standing in for the
// malicious update server the threat model assumes.
type Server struct {
	*httptest.Server
}

// Serve serves dir: metadata under /metadata/ and target files under /targets/.
// The caller closes it.
func Serve(dir string) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metadata/", http.StripPrefix("/metadata/", http.FileServer(http.Dir(dir+"/"+MetadataDir))))
	mux.Handle("/targets/", http.StripPrefix("/targets/", http.FileServer(http.Dir(dir+"/"+TargetsDir))))
	return &Server{httptest.NewServer(mux)}
}

// MetadataURL is where the client fetches role metadata.
func (s *Server) MetadataURL() string { return s.URL + "/metadata/" }

// TargetsURL is where the client fetches target files.
func (s *Server) TargetsURL() string { return s.URL + "/targets/" }
