// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"strconv"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/softhsm"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	t.Run("NewKeyStore", func(t *testing.T) {
		hsm := softhsm.New(t)
		label, _ := hsm.InitToken()

		// Open the module separately to find the token slot ID.
		mod := module.TestOpen(t, hsm.Path)
		token, err := mod.GetToken(module.SelectLabel(label))
		require.NoError(t, err)

		tests := map[string]struct {
			err    bool
			params map[string]any
		}{
			"slot as uint": {
				params: map[string]any{
					KeyStoreParamLib:  hsm.Path,
					KeyStoreParamSlot: token.ID}},
			"slot as string": {
				params: map[string]any{
					KeyStoreParamLib:  hsm.Path,
					KeyStoreParamSlot: strconv.FormatUint(uint64(token.ID), 10)}},
			"slot as hex string": {
				params: map[string]any{
					KeyStoreParamLib:  hsm.Path,
					KeyStoreParamSlot: "0x" + strconv.FormatUint(uint64(token.ID), 16)}},
			"label as string": {
				params: map[string]any{
					KeyStoreParamLib:   hsm.Path,
					KeyStoreParamLabel: label}},
			"label as []byte": {
				params: map[string]any{
					KeyStoreParamLib:   hsm.Path,
					KeyStoreParamLabel: []byte(label)}},
			"no lib": {
				err: true,
				params: map[string]any{
					KeyStoreParamLabel: label,
					KeyStoreParamSlot:  token.ID}},
			"no slot or label": {
				err: true,
				params: map[string]any{
					KeyStoreParamLib: hsm.Path}},
			"bogus": {
				err: true,
				params: map[string]any{
					KeyStoreParamLib:   hsm.Path,
					KeyStoreParamLabel: "foo"}},
		}

		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				store, err := NewKeyStore(tt.params)
				if tt.err {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					// Ensure the module is removed from cache, else this will
					// conflict with other tests.
					require.NoError(t, store.Close(t.Context()))
				}
			})
		}
	})

	t.Run("Login+Close", func(t *testing.T) {
		hsm := softhsm.New(t)
		label, pin := hsm.InitToken()

		store, err := NewKeyStore(map[string]any{
			KeyStoreParamLib: hsm.Path, KeyStoreParamLabel: label,
		})
		require.NoError(t, err)

		err = store.Login(t.Context(), &kms.Credentials{Password: "foo"})
		require.Error(t, err, "should error on login with bogus pin")

		err = store.Login(t.Context(), &kms.Credentials{Password: pin})
		require.NoError(t, err, "should login with correct pin")

		err = store.Login(t.Context(), &kms.Credentials{Password: pin})
		require.Error(t, err, "login should error when already logged in")

		err = store.Close(t.Context())
		require.NoError(t, err, "store should close")
	})

	t.Run("ListKeys", func(t *testing.T) {
		hsm := softhsm.New(t)
		label, pin := hsm.InitToken()

		// Store setup:
		params := map[string]any{
			KeyStoreParamLib: hsm.Path, KeyStoreParamLabel: label}
		store, err := NewKeyStore(params)
		require.NoError(t, err)
		err = store.Login(t.Context(), &kms.Credentials{Password: pin})
		require.NoError(t, err)
		defer func() { require.NoError(t, store.Close(t.Context())) }()

		// Manually open another session for key generation:
		mod := module.TestOpen(t, hsm.Path)
		token, err := mod.GetToken(module.SelectLabel(label))
		require.NoError(t, err)
		p := session.TestLogin(t, mod, token, pin)
		s, err := p.Get(t.Context())
		require.NoError(t, err)
		defer func() { require.NoError(t, s.Close()) }()

		t.Run("no keys", func(t *testing.T) {
			keys, err := store.ListKeys(t.Context())
			require.NoError(t, err)
			require.Len(t, keys, 0)
		})

		_, err = keybuilder.AES(32).Generate(s)
		require.NoError(t, err)

		t.Run("one key", func(t *testing.T) {
			keys, err := store.ListKeys(t.Context())
			require.NoError(t, err)
			require.Len(t, keys, 1)
			require.Equal(t, kms.KeyType_AES, keys[0].GetType())
		})

		for range 9 {
			_, err = keybuilder.AES(32).Generate(s)
			require.NoError(t, err)
		}

		for range 5 {
			_, _, err = keybuilder.RSA(2048).Generate(s)
			require.NoError(t, err)
		}

		for range 5 {
			_, _, err = keybuilder.EC(kms.Curve_P256).Generate(s)
			require.NoError(t, err)
		}

		// We should have 10 AES keys + 5 RSA public keys + 5 RSA private keys +
		// 5 EC public keys + 5 EC private keys now, so 30 total.

		t.Run("many keys", func(t *testing.T) {
			keys, err := store.ListKeys(t.Context())
			require.NoError(t, err)
			require.Len(t, keys, 30)

			var aesSecret, rsaPublic, rsaPrivate, ecPublic, ecPrivate int
			for _, k := range keys {
				switch k.GetType() {
				case kms.KeyType_AES:
					aesSecret++
				case kms.KeyType_RSA_Public:
					rsaPublic++
				case kms.KeyType_RSA_Private:
					rsaPrivate++
				case kms.KeyType_EC_Public:
					ecPublic++
				case kms.KeyType_EC_Private:
					ecPrivate++
				}
			}

			require.Equal(t, aesSecret, 10)
			require.Equal(t, rsaPublic, 5)
			require.Equal(t, rsaPrivate, 5)
			require.Equal(t, ecPublic, 5)
			require.Equal(t, ecPrivate, 5)
		})
	})

	t.Run("GetKey", func(t *testing.T) {
		hsm := softhsm.New(t)
		label, pin := hsm.InitToken()

		// Store setup:
		params := map[string]any{
			KeyStoreParamLib: hsm.Path, KeyStoreParamLabel: label}
		store, err := NewKeyStore(params)
		require.NoError(t, err)
		err = store.Login(t.Context(), &kms.Credentials{Password: pin})
		require.NoError(t, err)
		defer func() { require.NoError(t, store.Close(t.Context())) }()

		// Manually open another session for key generation:
		mod := module.TestOpen(t, hsm.Path)
		token, err := mod.GetToken(module.SelectLabel(label))
		require.NoError(t, err)
		p := session.TestLogin(t, mod, token, pin)
		s, err := p.Get(t.Context())
		require.NoError(t, err)
		defer func() { require.NoError(t, s.Close()) }()

		_, err = keybuilder.AES(32).Label("my-aes-key").Generate(s)
		require.NoError(t, err)

		k, err := store.GetKeyByName(t.Context(), "my-aes-key")
		require.NoError(t, err)
		require.Equal(t, kms.KeyType_AES, k.GetType())

		// An imposter appears!!!
		_, _, err = keybuilder.RSA(2048).Label("my-aes-key").Generate(s)
		require.NoError(t, err)

		k, err = store.GetKeyByName(t.Context(), "my-aes-key")
		require.Error(t, err, "should error as label is not unique anymore")

		_, _, err = keybuilder.RSA(4096).
			ID("my-rsa-key-pair").
			// Label public and private keys differently! Scary!
			PublicAttribute(pkcs11.CKA_LABEL, "my-rsa-public-key").
			PrivateAttribute(pkcs11.CKA_LABEL, "my-rsa-private-key").
			Generate(s)
		require.NoError(t, err)

		k, err = store.GetKeyById(t.Context(), "my-rsa-key-pair")
		require.NoError(t, err)
		require.Equal(t, kms.KeyType_RSA_Private, k.GetType())
		require.IsType(t, &pair{}, k)

		k, err = store.GetKeyByName(t.Context(), "my-rsa-public-key")
		require.NoError(t, err)
		require.Equal(t, kms.KeyType_RSA_Public, k.GetType())
		require.IsType(t, &public{}, k)

		k, err = store.GetKeyByName(t.Context(), "my-rsa-private-key")
		require.NoError(t, err)
		require.Equal(t, kms.KeyType_RSA_Private, k.GetType())
		require.IsType(t, &private{}, k)

		// Two EC key pairs with the same label, but different IDs!
		_, _, err = keybuilder.EC(kms.Curve_P256).
			ID("my-ec-key-pair").Label("ec").Generate(s)
		require.NoError(t, err)
		_, _, err = keybuilder.EC(kms.Curve_P256).
			ID("my-other-ec-key-pair").Label("ec").Generate(s)
		require.NoError(t, err)

		k, err = store.GetKeyByName(t.Context(), "ec")
		require.Error(t, err, "should error as label is not unique anymore")

		attrs := map[string]any{IdAttr: "my-ec-key-pair", LabelAttr: "ec"}
		k, err = store.GetKeyByAttrs(t.Context(), attrs)
		require.NoError(t, err)
		require.Equal(t, kms.KeyType_EC_Private, k.GetType())
		require.IsType(t, &pair{}, k)
	})
}
