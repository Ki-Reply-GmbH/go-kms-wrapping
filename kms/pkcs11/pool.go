// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/miekg/pkcs11"
)

// NOTE: This file holds critical concurrency flow, please review carefully :)

// pool creates PKCS#11 sessions for a slot. pool assumes that sessions are
// cheap (i.e., only exist on the client side) and skips the complexity storing
// and reusing sessions. However, a single persistent session is kept to
// maintain login state across all temporary sessions.
type pool struct {
	slot       *slot                // The underlying slot.
	persistent pkcs11.SessionHandle // Persistent, logged-in session.

	max uint // Maximum pool size.

	closeContext context.Context // to stop and drain
	closeFunc    context.CancelFunc

	sessionChan chan interface{} // control the distribution of sessions in the pool

	wg sync.WaitGroup // tracks number of active sessions
}

// errPoolClosed is returned when a caller attempts to acquire a new session,
// but the pool has already been closed.
var errPoolClosed = errors.New("session pool is closed")

// newPool creates a new session pool for a slot, creating the initial
// persistent session and logging it in.
func newPool(s *slot, pin string) (*pool, error) {
	var maxSessions uint
	switch s.info.MaxSessionCount {
	case pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_EFFECTIVELY_INFINITE:
		maxSessions = math.MaxUint
	default:
		maxSessions = s.info.MaxSessionCount
	}

	if maxSessions < 2 {
		return nil, fmt.Errorf("need to create at least 2 sessions, but max session count is %d", maxSessions)
	}

	// Create our persistent session to keep the the application logged in.
	session, err := s.OpenSession(s.id, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, pkcs11Error("OpenSession", err)
	}

	if err := s.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, errors.Join(
			pkcs11Error("Login", err),
			pkcs11Error("CloseSession", s.CloseSession(session)),
		)
	}

	closeContext, closeFunc := context.WithCancel(context.Background())

	p := &pool{
		slot:         s,
		persistent:   session,
		max:          maxSessions - 1, // Minus the persistent session.
		closeContext: closeContext,
		closeFunc:    closeFunc,
		sessionChan:  make(chan interface{}, maxSessions-1),
		wg:           sync.WaitGroup{},
	}

	// Fill the channel with empty values, these are just tokens
	// representing the channels left in the pool
	for i := uint(0); i < p.max; i++ {
		p.sessionChan <- struct{}{}
	}

	return p, nil
}

// get a new session, waiting for available capacity if needed. Note that this
// supports context cancellation such that requests can time out on highly
// constrained pool sizes.
func (p *pool) get(ctx context.Context) (pkcs11.SessionHandle, error) {
	p.wg.Add(1)
	select {
	case <-p.closeContext.Done():
		p.wg.Done()
		return 0, errPoolClosed
	case <-ctx.Done():
		p.wg.Done()
		return 0, ctx.Err()
	case <-p.sessionChan:
		// Open a new session
		session, err := p.slot.OpenSession(p.slot.id, pkcs11.CKF_SERIAL_SESSION)
		if err != nil {
			// Note: I'm pretty sure this can be handled better (less indentation, more err return correctness etc...)
			// Return the token since OpenSessino fails
			select {
			case p.sessionChan <- struct{}{}:
			case <-p.closeContext.Done(): // don't block if the pool is closed
			case <-ctx.Done(): // or if ctx is done
			}
			p.wg.Done()
			return 0, pkcs11Error("OpenSession", err)
		}
		return session, nil
	}
}

// put closes the session, freeing pool capacity. The caller must ensure that
// this function is only called once per session.
// Note: this would fail if put is called twice for the same session, maybe
// we need to track session handles, thus a lock anw?
func (p *pool) put(session pkcs11.SessionHandle) error {
	// The best we can do if CloseSession fails is assume that it is closed
	// regardless.
	defer func() {
		select {
		// refill the session channel or stop if pool is closed
		case p.sessionChan <- struct{}{}:
		case <-p.closeContext.Done():
		}
		p.wg.Done()
	}()
	return pkcs11Error("CloseSession", p.slot.CloseSession(session))
}

// close marks the pool as closed and waits for all sessions to be returned via
// [pool.put], then closes the underlying slot.
func (p *pool) close() error {
	// Signal to close the pool:
	p.closeFunc()

	// Then wait for all sessions to finish
	p.wg.Wait()

	return errors.Join(
		pkcs11Error("Logout", p.slot.Logout(p.persistent)),
		pkcs11Error("CloseAllSessions", p.slot.CloseAllSessions(p.slot.id)),
		p.slot.close(),
	)
}

// do is a convenience wrapper around [pool.get] and [pool.put], calling the
// passed callback function with a valid session and discarding it afterwards.
func (p *pool) do(ctx context.Context, callback func(*pkcs11.Ctx, pkcs11.SessionHandle) error) error {
	session, err := p.get(ctx)
	if err != nil {
		return err
	}

	// Don't break the pool's integrity even if the callback panics.
	defer func() {
		err = errors.Join(p.put(session))
	}()

	err = callback(p.slot.Ctx, session)
	return err
}
