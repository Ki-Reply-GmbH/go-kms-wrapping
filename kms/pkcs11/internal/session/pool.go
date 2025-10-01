// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package session provides pooled PKCS#11 session management.
package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/softhsm"
	"github.com/stretchr/testify/require"
)

// pool creates sessions for a token slot. pool assumes that sessions are cheap
// (i.e., only exist on the client side) and skips the complexity of storing
// and reusing sessions. A single persistent session is created and logged in to
// maintain login state across all temporary sessions.
type pool struct {
	mod   *module.Ref
	token *module.Token

	refs uint // Count of shared users. A value of zero implies a closed pool.

	persistent pkcs11.SessionHandle // Persistent, logged-in session.

	pinHash []byte // SHA256 of pin that was used to log in.

	max  uint // Maximum pool size.
	size uint // Current pool size.

	cond *sync.Cond // Concurrency control.
}

// key is used to uniquely identify a pool in the global cache.
type key struct {
	// path is the module path.
	path string
	// slot is the token slot ID.
	slot uint
}

var (
	// cache globally tracks pools.
	cache = make(map[key]*pool)

	// cacheLock guards cache.
	cacheLock sync.Mutex
)

type PoolRef struct {
	*pool

	_       noCopy
	dropped atomic.Bool
}

type noCopy struct{}

func (noCopy) Lock()   {}
func (noCopy) Unlock() {}

// Login creates a new session pool and logs it in, or attempts to reuse an
// existing pool from a global cache.
func Login(mod *module.Ref, token *module.Token, pin string) (*PoolRef, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(pin)); err != nil {
		return nil, fmt.Errorf("failed to hash pin: %w", err)
	}

	cacheLock.Lock()

	k := key{mod.Path(), token.ID}

	for {
		p, ok := cache[k]
		if !ok {
			// Cache miss, keep the lock and create a new pool.
			break
		}

		// Ensure these locks never intersect.
		cacheLock.Unlock()
		p.cond.L.Lock()

		if p.refs == 0 {
			// Rare condition: We've found a pool that is currently shutting
			// down, i.e., has no remaining references. We must wait until the
			// current pool has fully drained, logged out and removed itself
			// from the cache.
			p.cond.L.Unlock()
			cacheLock.Lock()
			continue
		}

		if subtle.ConstantTimeCompare(h.Sum(nil), p.pinHash) == 0 {
			p.cond.L.Unlock()
			return nil, errors.New("inconsistent pin values")
		}

		// If pin hashes match, reuse the pool and increment its refcount.
		p.refs++
		p.cond.L.Unlock()

		return &PoolRef{pool: p}, nil
	}

	defer cacheLock.Unlock()

	var maxSessions uint
	switch token.Info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
		maxSessions = math.MaxUint
	default:
		maxSessions = token.Info.MaxRwSessionCount
	}

	if maxSessions < 2 {
		return nil, fmt.Errorf("need to create at least 2 sessions, but max session count is %d", maxSessions)
	}

	// Create our persistent session to keep the the application logged in.
	session, err := mod.OpenSession(token.ID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, mapErr(err, "OpenSession")
	}

	if err := mod.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, errors.Join(
			mapErr(err, "Login"),
			mapErr(mod.CloseSession(session), "CloseSession"),
		)
	}

	var lock sync.Mutex
	p := &pool{
		mod:        mod,
		token:      token,
		refs:       1,
		persistent: session,
		pinHash:    h.Sum(nil),
		max:        maxSessions - 1, // Minus the persistent session.
		cond:       sync.NewCond(&lock),
	}

	cache[k] = p
	return &PoolRef{pool: p}, nil
}

// Get a new session, waiting for available capacity if needed. Note that this
// method supports context cancellation such that requests can time out on
// highly constrained pool sizes.
func (p *pool) Get(ctx context.Context) (*Handle, error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.refs == 0 {
		return nil, errors.New("session pool is closed")
	}

	// Wait for available capacity.
	for p.size == p.max {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			p.cond.Wait()
		}
		// Since we called Wait(), the pool might have closed.
		if p.refs == 0 {
			return nil, errors.New("session pool is closed")
		}
	}

	// Open a new session and grow the pool.
	session, err := p.mod.OpenSession(p.token.ID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, mapErr(err, "OpenSession")
	}

	p.size += 1

	return &Handle{pool: p, session: session}, nil
}

// free releases one unit of capacity from the pool.
// This is called after a session handle was closed.
func (p *pool) free() {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	p.size--
	p.cond.Signal()
}

// Scope calls f with a session handle that is valid only within f's scope.
func (p *pool) Scope(ctx context.Context, f func(s *Handle) (err error)) error {
	s, err := p.Get(ctx)
	if err != nil {
		return err
	}

	// Don't break the pool's integrity even if the callback panics.
	defer func() {
		err = errors.Join(err, s.Close())
	}()

	err = f(s)
	return err
}

// Scope wraps pool.Scope to add a generic return value for extra convenience.
func Scope[T any](ctx context.Context, p *PoolRef, f func(s *Handle) (T, error)) (T, error) {
	var ret T
	err := p.Scope(ctx, func(s *Handle) (err error) {
		ret, err = f(s)
		return err
	})
	return ret, err
}

// Drop decrements the pool's reference count. If the pool has no other
// remaining references, it will permanently close, log out the persistent
// session and remove itself from the global cache. Dropping a reference
// multiple times will not compromise the pool's reference count, however, any
// continued usage of the dropped reference is undefined behavior.
func (p *PoolRef) Drop() error {
	if !p.dropped.CompareAndSwap(false, true) {
		return errors.New("reference was already dropped")
	}

	p.cond.L.Lock()

	p.refs--
	if p.refs != 0 {
		// Drop the reference only.
		p.cond.L.Unlock()
		return nil
	}

	// Drain the pool:
	for p.size != 0 {
		p.cond.Wait()
	}

	p.cond.L.Unlock()

	err := errors.Join(
		mapErr(p.mod.Logout(p.persistent), "Logout"),
		mapErr(p.mod.CloseAllSessions(p.token.ID), "CloseAllSessions"),
	)

	cacheLock.Lock()
	defer cacheLock.Unlock()

	delete(cache, key{p.mod.Path(), p.token.ID})

	return err
}

// mapErr adds the respective PKCS#11 operation to an error if it is non-nil.
func mapErr(err error, op string) error {
	if err == nil {
		return nil
	} else {
		return fmt.Errorf("failed to pkcs#11 %s: %w", op, err)
	}
}

// TestLogin is a test helper that logs into a pool and automatically drops it
// on test completion, handling all errors.
func TestLogin(t *testing.T, mod *module.Ref, token *module.Token, pin string) *PoolRef {
	t.Helper()

	pool, err := Login(mod, token, pin)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, pool.Drop())
	})

	return pool
}

// TestPool is a test helper that creates a SoftHSM test & token, loads a module
// and logs a pool into the token. This is a convenient shortcuts for tests that
// don't concern themselves with multi-slot testing.
func TestPool(t *testing.T) *PoolRef {
	t.Helper()

	softhsm := softhsm.New(t)
	label, pin := softhsm.InitToken()

	mod := module.TestOpen(t, softhsm.Path)
	token, err := mod.GetToken(module.SelectLabel(label))
	require.NoError(t, err)

	return TestLogin(t, mod, token, pin)
}

// TestSession calls TestPool and returns a session that is automatically closed
// on test completion.
func TestSession(t *testing.T) (*Handle, *PoolRef) {
	t.Helper()

	p := TestPool(t)
	s, err := p.Get(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, s.Close())
	})

	return s, p
}
