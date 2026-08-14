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

package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// maxSymlinkHops bounds link resolution. A cycle must end in an error, not in a
// hung update.
const maxSymlinkHops = 40

// errTooManyLinks ends a symlink cycle.
var errTooManyLinks = errors.New("too many levels of symbolic links")

// Mem is an in-memory filesystem: the test double that lets every branch of the
// apply path run without touching a disk.
//
// It models the parts of POSIX semantics the transaction actually depends on —
// atomic rename over an existing name, symlinks that are followed on lookup but
// not on rename or remove, and directories that must be empty to be removed. It
// is deliberately not a complete filesystem; ".." is resolved lexically, and it
// has no permission enforcement, because no idunn code path decides anything on
// those.
//
// The zero value is not usable; call NewMem.
type Mem struct {
	mu    sync.Mutex
	nodes map[string]*memNode

	// Fail, if non-nil, is consulted before every mutating operation and can
	// return an error to make it fail. This is how the property tests inject a
	// crash at an exact transaction boundary and assert that what remains on
	// disk is still either the old state or the new one (AGENTS.md §4).
	//
	// It is called with the operation name ("create", "rename", "remove",
	// "removeall", "mkdirall", "symlink", "write", "sync") and the affected
	// name, already in canonical slash form.
	Fail func(op, name string) error
}

// memNode is one file, directory or symlink.
type memNode struct {
	mode fs.FileMode // ModeDir / ModeSymlink plus permission bits.
	data []byte
	link string
}

func (n *memNode) isDir() bool     { return n.mode&fs.ModeDir != 0 }
func (n *memNode) isSymlink() bool { return n.mode&fs.ModeSymlink != 0 }

// NewMem returns an empty in-memory filesystem containing only the roots "/"
// and ".", so both an absolute install root and a relative one work.
func NewMem() *Mem {
	return &Mem{nodes: map[string]*memNode{
		"/": {mode: fs.ModeDir | 0o755},
		".": {mode: fs.ModeDir | 0o755},
	}}
}

// Compile-time proof that the in-memory filesystem offers everything the real one
// does. If the two ever diverge, the tests stop proving anything about production.
var (
	_ FS        = (*Mem)(nil)
	_ LstatFS   = (*Mem)(nil)
	_ SyncDirFS = (*Mem)(nil)
)

// canon returns the canonical map key for name.
func canon(name string) string { return path.Clean(Slash(name)) }

// splitElems returns the meaningful path elements of a canonical path.
func splitElems(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." {
		return nil
	}
	parts := strings.Split(p, "/")
	out := make([]string, 0, len(parts))
	for _, e := range parts {
		if e != "" && e != "." {
			out = append(out, e)
		}
	}
	return out
}

func joinPath(dir, elem string) string {
	switch dir {
	case "/":
		return "/" + elem
	case ".":
		if elem == ".." {
			return ".."
		}
		return elem
	default:
		return path.Join(dir, elem)
	}
}

func pathErr(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

// resolve expands symlinks in name and returns the canonical path they lead to.
//
// followLast decides whether a symlink in the final position is expanded. Lookup
// operations (Stat, Open) expand it; operations that act on the link itself
// (Lstat, Readlink, Remove, Rename) do not — that difference is what lets the
// apply path swap `current` instead of writing through it.
//
// Components that do not exist are not an error here: Create and MkdirAll need
// the canonical name of something that is about to be made.
func (m *Mem) resolve(name string, followLast bool) (string, error) {
	p := canon(name)
	cur := "."
	if strings.HasPrefix(p, "/") {
		cur = "/"
	}
	elems := splitElems(p)
	hops := 0

	for i := 0; i < len(elems); {
		next := joinPath(cur, elems[i])
		n := m.nodes[next]
		last := i == len(elems)-1

		if n != nil && n.isSymlink() && (followLast || !last) {
			hops++
			if hops > maxSymlinkHops {
				return "", pathErr("resolve", name, errTooManyLinks)
			}
			target := canon(n.link)
			rest := elems[i+1:]
			expanded := splitElems(target)
			joined := make([]string, 0, len(expanded)+len(rest))
			joined = append(joined, expanded...)
			joined = append(joined, rest...)
			if strings.HasPrefix(target, "/") {
				cur = "/"
			}
			// cur otherwise stays the directory that contained the link, so a
			// relative target resolves against it, as POSIX does.
			elems = joined
			i = 0
			continue
		}
		cur = next
		i++
	}
	return cur, nil
}

// node returns the resolved path and the node at name.
func (m *Mem) node(name string, followLast bool) (string, *memNode, error) {
	if name == "" {
		return "", nil, pathErr("open", name, fs.ErrInvalid)
	}
	p, err := m.resolve(name, followLast)
	if err != nil {
		return "", nil, err
	}
	n, ok := m.nodes[p]
	if !ok {
		return p, nil, pathErr("open", name, fs.ErrNotExist)
	}
	return p, n, nil
}

// requireDir checks that the parent of p exists and is a directory, so a file can
// never appear under a path whose parent is a regular file.
func (m *Mem) requireDir(p, op, name string) error {
	dir := path.Dir(p)
	n, ok := m.nodes[dir]
	if !ok {
		return pathErr(op, name, fs.ErrNotExist)
	}
	if !n.isDir() {
		return pathErr(op, name, errors.New("parent is not a directory"))
	}
	return nil
}

// fail consults the injected failure hook.
//
// It is called WITHOUT the filesystem lock held, so a hook may mutate the
// filesystem itself — planting a symlink between a check and the write that
// follows it, for instance. Simulating that race is much of what the hook is
// for, and a hook that deadlocked the moment it touched the filesystem would be
// useless for it. Set Fail before the filesystem is shared between goroutines.
func (m *Mem) fail(op, name string) error {
	if m.Fail == nil {
		return nil
	}
	if err := m.Fail(op, name); err != nil {
		return pathErr(op, name, err)
	}
	return nil
}

// Open returns the file at name, following a final symlink.
func (m *Mem) Open(name string) (fs.File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, n, err := m.node(name, true)
	if err != nil {
		return nil, err
	}
	if n.isDir() {
		return &memFile{name: path.Base(p), node: n}, nil
	}
	return &memFile{name: path.Base(p), node: n, r: strings.NewReader(string(n.data))}, nil
}

// Stat follows a final symlink; Lstat does not.
func (m *Mem) Stat(name string) (fs.FileInfo, error) { return m.stat(name, true) }

// Lstat reports on the link itself, so a caller can tell a symlink from the file
// it points at.
func (m *Mem) Lstat(name string) (fs.FileInfo, error) { return m.stat(name, false) }

func (m *Mem) stat(name string, follow bool) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, n, err := m.node(name, follow)
	if err != nil {
		return nil, err
	}
	return &memInfo{name: path.Base(p), node: n}, nil
}

// ReadDir lists name in name order, so every walk over an install root is
// deterministic and two runs of the packer or the GC see the same sequence.
func (m *Mem) ReadDir(name string) ([]fs.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, n, err := m.node(name, true)
	if err != nil {
		return nil, err
	}
	if !n.isDir() {
		return nil, pathErr("readdir", name, errors.New("not a directory"))
	}

	prefix := p + "/"
	if p == "/" {
		prefix = "/"
	}
	var out []fs.DirEntry
	for key, child := range m.nodes {
		if key == p || !strings.HasPrefix(key, prefix) {
			continue
		}
		if strings.Contains(strings.TrimPrefix(key, prefix), "/") {
			continue
		}
		out = append(out, &memInfo{name: path.Base(key), node: child})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// Create truncates or creates name. A final symlink is followed, as an open with
// O_CREAT does: that is exactly why core/stage checks with Lstat before writing
// rather than trusting the write itself to stay inside the root.
func (m *Mem) Create(name string, mode fs.FileMode) (io.WriteCloser, error) {
	if name == "" {
		return nil, pathErr("create", name, fs.ErrInvalid)
	}
	if err := m.fail("create", canon(name)); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	p, err := m.resolve(name, true)
	if err != nil {
		return nil, err
	}
	if n, ok := m.nodes[p]; ok && n.isDir() {
		return nil, pathErr("create", name, errors.New("is a directory"))
	}
	if err := m.requireDir(p, "create", name); err != nil {
		return nil, err
	}
	n := &memNode{mode: mode.Perm()}
	m.nodes[p] = n
	return &memWriter{fs: m, path: p, node: n}, nil
}

// MkdirAll creates name and every missing parent.
func (m *Mem) MkdirAll(name string, mode fs.FileMode) error {
	if name == "" {
		return pathErr("mkdirall", name, fs.ErrInvalid)
	}
	if err := m.fail("mkdirall", canon(name)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	p, err := m.resolve(name, true)
	if err != nil {
		return err
	}

	cur := "."
	if strings.HasPrefix(p, "/") {
		cur = "/"
	}
	for _, e := range splitElems(p) {
		cur = joinPath(cur, e)
		if n, ok := m.nodes[cur]; ok {
			if !n.isDir() {
				return pathErr("mkdirall", cur, errors.New("not a directory"))
			}
			continue
		}
		m.nodes[cur] = &memNode{mode: fs.ModeDir | mode.Perm()}
	}
	return nil
}

// Remove deletes name. It never follows a final symlink — removing a link must
// remove the link, not what it points at — and refuses a non-empty directory.
func (m *Mem) Remove(name string) error {
	if err := m.fail("remove", canon(name)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	p, _, err := m.node(name, false)
	if err != nil {
		return err
	}
	if len(m.childrenOf(p)) > 0 {
		return pathErr("remove", name, errors.New("directory not empty"))
	}
	delete(m.nodes, p)
	return nil
}

// RemoveAll deletes name and everything under it. A missing name is not an error,
// which is what makes abort and recovery paths idempotent.
func (m *Mem) RemoveAll(name string) error {
	if name == "" {
		return pathErr("removeall", name, fs.ErrInvalid)
	}
	if err := m.fail("removeall", canon(name)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	p, err := m.resolve(name, false)
	if err != nil {
		return err
	}
	if _, ok := m.nodes[p]; !ok {
		return nil
	}
	for _, key := range m.childrenOf(p) {
		delete(m.nodes, key)
	}
	delete(m.nodes, p)
	return nil
}

// Rename atomically moves oldname onto newname, replacing an existing newname.
//
// This is the operation the whole design rests on: the commit of an update is one
// rename of `current` (docs/design.md §6.1). Neither name follows a final
// symlink, so repointing `current` replaces the link rather than writing through
// it into the old version directory.
func (m *Mem) Rename(oldname, newname string) error {
	if newname == "" {
		return pathErr("rename", newname, fs.ErrInvalid)
	}
	if err := m.fail("rename", canon(newname)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	from, n, err := m.node(oldname, false)
	if err != nil {
		return err
	}
	to, err := m.resolve(newname, false)
	if err != nil {
		return err
	}
	if err := m.requireDir(to, "rename", newname); err != nil {
		return err
	}
	if from == to {
		return nil
	}
	if strings.HasPrefix(to+"/", from+"/") {
		return pathErr("rename", newname, errors.New("cannot move a directory into itself"))
	}

	if existing, ok := m.nodes[to]; ok {
		if existing.isDir() != n.isDir() {
			return pathErr("rename", newname, errors.New("cannot replace a directory with a file or vice versa"))
		}
		if existing.isDir() && len(m.childrenOf(to)) > 0 {
			return pathErr("rename", newname, errors.New("destination directory not empty"))
		}
		delete(m.nodes, to)
	}

	// Move the node and, for a directory, its whole subtree in one step: a
	// reader either sees the old tree or the new one.
	children := m.childrenOf(from)
	delete(m.nodes, from)
	m.nodes[to] = n
	for _, key := range children {
		child := m.nodes[key]
		delete(m.nodes, key)
		m.nodes[to+strings.TrimPrefix(key, from)] = child
	}
	return nil
}

// Symlink creates a link at linkname pointing to target. The target is stored
// verbatim and is not required to exist: `current` is written before the version
// directory is fully populated in some recovery paths, and a dangling link is a
// state the recovery must be able to observe rather than be prevented from
// creating.
func (m *Mem) Symlink(target, linkname string) error {
	if linkname == "" || target == "" {
		return pathErr("symlink", linkname, fs.ErrInvalid)
	}
	if err := m.fail("symlink", canon(linkname)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	p, err := m.resolve(linkname, false)
	if err != nil {
		return err
	}
	if _, ok := m.nodes[p]; ok {
		return pathErr("symlink", linkname, fs.ErrExist)
	}
	if err := m.requireDir(p, "symlink", linkname); err != nil {
		return err
	}
	m.nodes[p] = &memNode{mode: fs.ModeSymlink | 0o777, link: Slash(target)}
	return nil
}

// Readlink returns the stored target of the link at name.
func (m *Mem) Readlink(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, n, err := m.node(name, false)
	if err != nil {
		return "", err
	}
	if !n.isSymlink() {
		return "", pathErr("readlink", name, errors.New("not a symlink"))
	}
	return n.link, nil
}

// SyncDir succeeds: there is no dirty directory entry to flush, and the rename
// that preceded it was already as durable as this medium gets.
func (m *Mem) SyncDir(name string) error {
	if err := m.fail("sync", canon(name)); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	_, _, err := m.node(name, true)
	return err
}

// childrenOf returns every key strictly below p. The caller holds the lock.
func (m *Mem) childrenOf(p string) []string {
	prefix := p + "/"
	if p == "/" {
		prefix = "/"
	}
	var out []string
	for key := range m.nodes {
		if key != p && strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// memWriter is the io.WriteCloser Create returns.
type memWriter struct {
	fs     *Mem
	path   string
	node   *memNode
	closed bool
}

func (w *memWriter) Write(p []byte) (int, error) {
	if err := w.fs.fail("write", w.path); err != nil {
		return 0, err
	}

	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()

	if w.closed {
		return 0, pathErr("write", w.path, fs.ErrClosed)
	}
	w.node.data = append(w.node.data, p...)
	return len(p), nil
}

// Sync satisfies Syncer so WriteFileAtomic exercises the same code path here as
// it does against a real disk.
func (w *memWriter) Sync() error {
	if err := w.fs.fail("sync", w.path); err != nil {
		return err
	}

	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()

	if w.closed {
		return pathErr("sync", w.path, fs.ErrClosed)
	}
	return nil
}

func (w *memWriter) Close() error {
	w.fs.mu.Lock()
	defer w.fs.mu.Unlock()

	if w.closed {
		return pathErr("close", w.path, fs.ErrClosed)
	}
	w.closed = true
	return nil
}

// memFile is the fs.File Open returns.
type memFile struct {
	name string
	node *memNode
	r    *strings.Reader
}

func (f *memFile) Stat() (fs.FileInfo, error) { return &memInfo{name: f.name, node: f.node}, nil }

func (f *memFile) Read(p []byte) (int, error) {
	if f.r == nil {
		return 0, pathErr("read", f.name, errors.New("is a directory"))
	}
	return f.r.Read(p)
}

func (f *memFile) Close() error { return nil }

// memInfo is both the fs.FileInfo and the fs.DirEntry view of a node.
type memInfo struct {
	name string
	node *memNode
}

func (i *memInfo) Name() string { return i.name }

func (i *memInfo) Size() int64 { return int64(len(i.node.data)) }

func (i *memInfo) Mode() fs.FileMode { return i.node.mode }

// ModTime is a fixed instant. Nothing in idunn decides anything on a
// modification time, and a real clock here would make tests depend on it
// (AGENTS.md §1.7).
func (i *memInfo) ModTime() time.Time { return time.Unix(0, 0).UTC() }

func (i *memInfo) IsDir() bool { return i.node.isDir() }

func (i *memInfo) Sys() any { return nil }

func (i *memInfo) Type() fs.FileMode { return i.node.mode.Type() }

func (i *memInfo) Info() (fs.FileInfo, error) { return i, nil }

// String renders the node for test failure messages.
func (i *memInfo) String() string {
	return fmt.Sprintf("%s (%s)", i.name, i.node.mode)
}
