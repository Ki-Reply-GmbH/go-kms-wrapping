// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/softhsm"
	"github.com/stretchr/testify/require"
)

func Test(t *testing.T) {
	t.Run("Login+Drop", func(t *testing.T) {
		hsm := softhsm.New(t)

		label1, pin1 := hsm.InitToken()
		label2, pin2 := hsm.InitToken()

		mod := module.TestOpen(t, hsm.Path)

		token1, err := mod.GetToken(module.SelectLabel(label1))
		require.NoError(t, err)

		token2, err := mod.GetToken(module.SelectLabel(label2))
		require.NoError(t, err)

		t.Run("Sharing", func(t *testing.T) {
			pool1, err := Login(mod, token1, pin2)
			require.Nil(t, pool1, "should not return a pool")
			require.Error(t, err, "wrong pin should not work")

			require.Len(t, cache, 0, "cache should be empty")

			pool1, err = Login(mod, token1, pin1)
			require.NotNil(t, pool1, "should return a pool")
			require.NoError(t, err, "correct pin should work")

			require.Len(t, cache, 1, "cache should have one entry")
			require.Equal(t, pool1.refs, uint(1), "pool should have one reference")

			pool2, err := Login(mod, token1, pin2)
			require.Nil(t, pool2, "should not return a pool")
			require.ErrorContains(t, err, "inconsistent pin values", "existing pool should reject inconsistent pin")

			require.Equal(t, pool1.refs, uint(1), "pool should have one reference")

			pool2, err = Login(mod, token1, pin1)
			require.NotNil(t, pool1, "should return a pool")
			require.NoError(t, err, "correct pin should yield shared pool")

			require.Len(t, cache, 1, "cache should have one entry")
			require.Equal(t, pool1.refs, uint(2), "pool should have two references")

			require.NoError(t, pool1.Drop(), "pool should drop")

			require.Len(t, cache, 1, "cache should have one entry")
			require.Equal(t, pool1.refs, uint(1), "pool should have one reference")

			require.NoError(t, pool2.Drop(), "pool should drop")

			require.Len(t, cache, 0, "cache should have one entry")
			require.Equal(t, pool1.refs, uint(0), "pool should have one reference")
		})

		t.Run("MultiToken", func(t *testing.T) {
			pool1, err := Login(mod, token1, pin1)
			require.NotNil(t, pool1, "should return a pool")
			require.NoError(t, err, "correct pin should work")

			pool2, err := Login(mod, token2, pin2)
			require.NotNil(t, pool2, "should return a pool")
			require.NoError(t, err, "correct pin should work")

			require.Len(t, cache, 2, "cache should have two entries")

			require.NoError(t, pool1.Drop(), "pool should drop")
			require.NoError(t, pool2.Drop(), "pool should drop")

			require.Len(t, cache, 0, "cache should have no entries")
		})
	})

	t.Run("Get+Close", func(t *testing.T) {
		hsm := softhsm.New(t)
		label, pin := hsm.InitToken()

		mod := module.TestOpen(t, hsm.Path)
		token, err := mod.GetToken(module.SelectLabel(label))
		require.NoError(t, err)

		pool := TestLogin(t, mod, token, pin)

		require.Equal(t, pool.size, uint(0), "pool should have no active session")

		s, err := pool.Get(t.Context())
		require.NoError(t, err, "pool should have available sessions")

		require.Equal(t, pool.size, uint(1), "pool should have one active session")

		s2, err := pool.Get(t.Context())
		require.NoError(t, err, "pool should have available sessions")

		require.Equal(t, pool.size, uint(2), "pool should have two active sessions")

		require.NoError(t, s2.Close(), "session should close")
		require.Equal(t, pool.size, uint(1), "pool should have one active session")

		_, err = s.GenerateRandom(1)
		require.NoError(t, err, "session should work")

		require.NoError(t, s.Close(), "first close should not error")
		require.Error(t, s.Close(), "double close should error")

		require.Equal(t, pool.size, uint(0), "pool should have no active sessions")

		_, err = s.GenerateRandom(1)
		require.Error(t, err, "session should not work after closing")

		t.Run("Scope", func(t *testing.T) {
			var escaped *Handle

			pool.Scope(t.Context(), func(s *Handle) error {
				escaped = s

				_, err := s.GenerateRandom(1)
				require.NoError(t, err, "session should work inside scope")

				return nil
			})

			_, err = escaped.GenerateRandom(1)
			require.Error(t, err, "session should not work outside of scope")

			defer func() {
				if r := recover(); r != nil {
					// The session should have closed even on panic.
					_, err = escaped.GenerateRandom(1)
					require.Error(t, err, "session was not closed by panic")
				} else {
					require.FailNow(t, "expected panic")
				}
			}()

			pool.Scope(t.Context(), func(s *Handle) error {
				escaped = s
				panic("catch me")
			})
		})
	})
}
