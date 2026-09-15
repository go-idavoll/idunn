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
	"errors"
	"fmt"
	"io/fs"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// OSRegistry is the Windows registry.
func OSRegistry() Registry { return osRegistry{} }

type osRegistry struct{}

// base is the predefined key of a hive.
func (osRegistry) base(h Hive) (registry.Key, error) {
	switch h {
	case HiveUser:
		return registry.CURRENT_USER, nil
	case HiveMachine:
		return registry.LOCAL_MACHINE, nil
	default:
		return 0, fmt.Errorf("%w: unknown hive %s", ErrIntegrate, h)
	}
}

// ReadKey implements Registry. Every key is opened in the 64-bit view, so a
// 32-bit build reads and writes the same entries a 64-bit one does.
func (r osRegistry) ReadKey(h Hive, path string) (map[string]Value, error) {
	base, err := r.base(h)
	if err != nil {
		return nil, err
	}
	k, err := registry.OpenKey(base, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil, fmt.Errorf("%s\\%s: %w", h, path, fs.ErrNotExist)
		}
		return nil, err
	}
	defer func() { _ = k.Close() }()

	names, err := k.ReadValueNames(0)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Value, len(names))
	for _, name := range names {
		_, kind, err := k.GetValue(name, nil)
		if err != nil {
			return nil, err
		}
		switch kind {
		case registry.SZ, registry.EXPAND_SZ:
			s, _, err := k.GetStringValue(name)
			if err != nil {
				return nil, err
			}
			out[name] = String(s)
		case registry.DWORD:
			d, _, err := k.GetIntegerValue(name)
			if err != nil {
				return nil, err
			}
			out[name] = DWord(uint32(d)) //nolint:gosec // G115: GetIntegerValue widens a REG_DWORD, which is 32 bits.
		}
	}
	return out, nil
}

// WriteKey implements Registry.
func (r osRegistry) WriteKey(h Hive, path string, set map[string]Value, remove []string) error {
	base, err := r.base(h)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(base, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()

	for name, v := range set {
		switch v.Kind {
		case KindString:
			err = k.SetStringValue(name, v.S)
		case KindDWord:
			err = k.SetDWordValue(name, v.D)
		default:
			err = fmt.Errorf("%w: value %s has no kind", ErrIntegrate, name)
		}
		if err != nil {
			return err
		}
	}
	for _, name := range remove {
		if err := k.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}

var procRegDeleteKeyExW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegDeleteKeyExW")

// DeleteKey implements Registry. It calls RegDeleteKeyExW rather than the
// registry package's DeleteKey, which cannot name the 64-bit view.
func (r osRegistry) DeleteKey(h Hive, path string) error {
	base, err := r.base(h)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	ret, _, _ := procRegDeleteKeyExW.Call(uintptr(base), uintptr(unsafe.Pointer(p)), uintptr(registry.WOW64_64KEY), 0) //nolint:gosec // G103: a NUL-terminated UTF-16 key name, per RegDeleteKeyExW.
	if errno := windows.Errno(ret); errno != 0 && !errors.Is(errno, registry.ErrNotExist) {
		return fmt.Errorf("delete %s\\%s: %w", h, path, errno)
	}
	return nil
}
