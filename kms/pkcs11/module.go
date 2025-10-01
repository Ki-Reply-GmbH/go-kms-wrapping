// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// NOTE: This file holds critical concurrency flow and manual memory management,
// please review carefully :)

// module is a [pkcs11.Ctx] plus information to track its lifecycle.
type module struct {
	*pkcs11.Ctx
	path string // The path that the above context was loaded from.

	slots map[uint]struct{} // This tracks occupied slots that have been acquired via [open].
	lock  sync.Mutex        // This guards the above map.
}

// slot is a [module] plus slot/token information.
// Semantically, slot implies exclusive access to the backing slot on the
// PKCS#11 device.
type slot struct {
	*module

	id   uint              // The resolved slot ID.
	info *pkcs11.TokenInfo // This holds information that is useful later, such as MaxRwSessionCount.
}

var (
	// modules is a global cache of loaded and initialized modules by resolved
	// module path.
	modules = make(map[string]*module)

	// modulesLock guards [modules].
	modulesLock = sync.Mutex{}
)

// open loads a PKCS#11 library (or reuses an already loaded one from the cache)
// and acquires exclusive access to a slot.
func open(path string, id *uint, label string) (*slot, error) {
	var err error

	path, err = resolveModulePath(path)
	if err != nil {
		return nil, err
	}

	modulesLock.Lock()
	m, ok := modules[path]

	// Load the module if it's not cached yet.
	if !ok {
		ctx := pkcs11.New(path)
		if ctx == nil {
			modulesLock.Unlock()
			return nil, errors.New("failed to load pkcs#11 module")
		}

		if err := ctx.Initialize(); err != nil {
			ctx.Destroy()
			modulesLock.Unlock()
			return nil, pkcs11Error("Initialize", err)
		}

		m = &module{
			Ctx:   ctx,
			path:  path,
			slots: make(map[uint]struct{}),
		}

		modules[path] = m
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	// Release global lock, we have the per-module lock now.
	modulesLock.Unlock()

	resolvedId, info, err := resolveTokenInfo(m.Ctx, id, label)
	if err != nil {
		return nil, errors.Join(err, m.finalize())
	}

	// Use of a slot is exclusive. This ensures that PKCS#11 login state (which
	// is global per slot) is never shared between tenants.
	if _, ok := m.slots[resolvedId]; ok {
		return nil, fmt.Errorf("pkcs#11 slot %d is already in use", resolvedId)
	}

	m.slots[resolvedId] = struct{}{}

	return &slot{
		module: m,
		id:     resolvedId,
		info:   info,
	}, nil
}

// finalize calls C_Finalize and unloads the module's underlying shared library
// context if the caller is the only remaining user.
// NOTE: finalize assumes that the caller holds the module's lock.
func (m *module) finalize() error {
	// Someone else is still using a slot on the module, keep it.
	if len(m.slots) != 0 {
		return nil
	}

	modulesLock.Lock()
	defer modulesLock.Unlock()

	delete(modules, m.path)

	err := pkcs11Error("Finalize", m.Finalize())

	// Destroy even if Finalize failed; it is best-effort.
	m.Destroy()

	return err
}

// close releases exclusive slot access and calls [module.finalize].
func (s *slot) close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if _, taken := s.slots[s.id]; !taken {
		return errors.New("tried to release slot that was never acquired")
	}

	delete(s.slots, s.id)
	return s.finalize()
}

// resolveModulePath validates and cleans a PKCS#11 dynamic library file path.
func resolveModulePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("module path must be set")
	}

	// Don't allow dynamic library loading via search paths. This makes it
	// hard for us to track which file is ultimately opened by dlopen. For more
	// context, see the dlopen(3).
	if !strings.Contains(path, "/") {
		return "", errors.New("module loading via search paths is not allowed")
	}

	// Best-effort path deduplication.
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute module path: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("failed to eval symlinks in module path: %w", err)
	}

	return path, nil
}

// resolveTokenInfo resolves token information from slot ID + token label.
func resolveTokenInfo(ctx *pkcs11.Ctx, id *uint, label string) (uint, *pkcs11.TokenInfo, error) {
	if id == nil && label == "" {
		return 0, nil, errors.New("at least one of slot, token label must be set")
	}

	ids, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, nil, pkcs11Error("GetSlotList", err)
	}

	for _, i := range ids {
		info, err := ctx.GetTokenInfo(i)
		if err != nil {
			return 0, nil, pkcs11Error("GetTokenInfo", err)
		}

		// We choose the first one that matches either slot number or label,
		// while prioritizing a match on the explicit slot number.
		if (id != nil && *id == i) || info.Label == label {
			return i, &info, err
		}
	}

	return 0, nil, errors.New("no matching token slot found")
}
