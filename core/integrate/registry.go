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

package integrate

import (
	"fmt"
	"io/fs"
	"strings"
	"sync"
)

// Hive is the registry root a key lives below.
type Hive int

// The hives integrations are registered in.
const (
	// HiveUser is HKEY_CURRENT_USER.
	HiveUser Hive = iota + 1

	// HiveMachine is the 64-bit view of HKEY_LOCAL_MACHINE: the view Windows
	// reads the "Installed apps" list of 64-bit software from, whatever the
	// bitness of the process writing it.
	HiveMachine
)

func (h Hive) String() string {
	switch h {
	case HiveUser:
		return "HKEY_CURRENT_USER"
	case HiveMachine:
		return "HKEY_LOCAL_MACHINE"
	default:
		return fmt.Sprintf("Hive(%d)", int(h))
	}
}

// ValueKind is the type of a registry value this package reads and writes.
type ValueKind int

// The value types. Anything else a key holds is not read.
const (
	KindString ValueKind = iota + 1 // REG_SZ; REG_EXPAND_SZ is read as one.
	KindDWord                       // REG_DWORD.
)

// Value is one registry value.
type Value struct {
	Kind ValueKind
	S    string
	D    uint32
}

// String is a REG_SZ value.
func String(s string) Value { return Value{Kind: KindString, S: s} }

// DWord is a REG_DWORD value.
func DWord(d uint32) Value { return Value{Kind: KindDWord, D: d} }

// Registry is the narrow surface of the Windows registry this package needs. It
// is an interface so every path runs in a test on every platform; OSRegistry is
// the real one on Windows.
//
// Key paths are below the hive, backslash-separated, and case-insensitive, as in
// the registry.
type Registry interface {
	// ReadKey returns the string and DWORD values of a key. A key that does
	// not exist is an error wrapping fs.ErrNotExist.
	ReadKey(h Hive, path string) (map[string]Value, error)

	// WriteKey creates the key if needed, sets the values in set and deletes
	// those named in remove. A value named in remove that does not exist is
	// not an error.
	WriteKey(h Hive, path string, set map[string]Value, remove []string) error

	// DeleteKey deletes a key that has no subkeys. A key that does not exist
	// is not an error.
	DeleteKey(h Hive, path string) error
}

// MemRegistry is an in-memory Registry for tests, here rather than in a test file
// so the packages that wire an Integrator test with it too. The zero value is
// ready to use.
type MemRegistry struct {
	mu   sync.Mutex
	keys map[string]map[string]memValue

	// Fail, when set, is consulted before every operation, named "read",
	// "write" or "delete"; a non-nil error fails it with nothing changed.
	Fail func(op string, h Hive, path string) error
}

type memValue struct {
	name  string
	value Value
}

func memKey(h Hive, path string) string {
	return fmt.Sprintf("%d\\%s", h, strings.ToLower(path))
}

// ReadKey implements Registry.
func (m *MemRegistry) ReadKey(h Hive, path string) (map[string]Value, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("read", h, path); err != nil {
		return nil, err
	}
	k, ok := m.keys[memKey(h, path)]
	if !ok {
		return nil, fmt.Errorf("%s\\%s: %w", h, path, fs.ErrNotExist)
	}
	out := make(map[string]Value, len(k))
	for _, v := range k {
		out[v.name] = v.value
	}
	return out, nil
}

// WriteKey implements Registry.
func (m *MemRegistry) WriteKey(h Hive, path string, set map[string]Value, remove []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("write", h, path); err != nil {
		return err
	}
	if m.keys == nil {
		m.keys = map[string]map[string]memValue{}
	}
	k, ok := m.keys[memKey(h, path)]
	if !ok {
		k = map[string]memValue{}
		m.keys[memKey(h, path)] = k
	}
	for name, v := range set {
		k[strings.ToLower(name)] = memValue{name: name, value: v}
	}
	for _, name := range remove {
		delete(k, strings.ToLower(name))
	}
	return nil
}

// DeleteKey implements Registry.
func (m *MemRegistry) DeleteKey(h Hive, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("delete", h, path); err != nil {
		return err
	}
	delete(m.keys, memKey(h, path))
	return nil
}

// Keys returns how many keys the registry holds.
func (m *MemRegistry) Keys() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}

func (m *MemRegistry) fail(op string, h Hive, path string) error {
	if m.Fail == nil {
		return nil
	}
	return m.Fail(op, h, path)
}
