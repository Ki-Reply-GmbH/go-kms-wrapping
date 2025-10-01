// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestCipher(t *testing.T) {
	s, p := session.TestSession(t)
	plaintext := []byte("Hello, World!")

	t.Run("RSA", func(t *testing.T) {
		o1, o2, err := keybuilder.RSA(4096).Generate(s)
		require.NoError(t, err)

		kp, err := pairFromHandles(s, p, o1, o2)
		require.NoError(t, err)

		factory, ok := kp.(kms.CipherFactory)
		require.True(t, ok)

		t.Run("OAEP/SHA-1", func(t *testing.T) {
			// SoftHSM only supports OAEP via SHA1.
			// https://github.com/softhsm/SoftHSMv2/issues/474

			ctx := t.Context()

			// Create the encrypting cipher.
			params := &kms.CipherParameters{Algorithm: CipherMode_RSA_OAEP_SHA1}
			encryptor, err := factory.NewCipher(ctx, kms.CipherOp_Encrypt, params)
			require.NoError(t, err)

			// Perform the encryption, always single-part.
			ciphertext, err := encryptor.Close(ctx, plaintext)
			require.NoError(t, err)
			require.NotEmpty(t, ciphertext)

			// Ensure the cipher cannot be used anymore once closed.
			_, err = encryptor.Update(ctx, plaintext)
			require.Error(t, err)
			_, err = encryptor.Close(ctx, plaintext)
			require.Error(t, err)

			// Create the decrypting cipher.
			decryptor, err := factory.NewCipher(ctx, kms.CipherOp_Decrypt, params)
			require.NoError(t, err)

			// Perform the decryption, again always single-part.
			plaintext, err := decryptor.Close(ctx, ciphertext)
			require.NoError(t, err)

			// Then compare to the original plaintext.
			require.Equal(t, plaintext, plaintext)
		})
	})

	t.Run("AES", func(t *testing.T) {
		obj, err := keybuilder.AES(32).Generate(s)
		require.NoError(t, err)

		sec, err := fromHandle(s, p, obj)
		require.NoError(t, err)

		factory, ok := sec.(kms.CipherFactory)
		require.True(t, ok)

		feed := func(t *testing.T, cipher kms.Cipher, input []byte, multipart bool) []byte {
			if !multipart {
				output, err := cipher.Close(t.Context(), input)
				require.NoError(t, err)
				return output
			}

			var output []byte
			for _, c := range input {
				part, err := cipher.Update(t.Context(), []byte{c})
				require.NoError(t, err)
				output = append(output, part...)
			}

			final, err := cipher.Close(t.Context(), nil)
			require.NoError(t, err)

			return append(output, final...)
		}

		t.Run("GCM", func(t *testing.T) {
			tests := map[string]struct {
				aad       []byte
				multipart bool
			}{
				"Oneshot":       {},
				"Oneshot+AAD":   {aad: []byte("Wow!")},
				"Multipart":     {multipart: true},
				"Multipart+AAD": {aad: []byte("Wow!"), multipart: true},
			}

			for name, tt := range tests {
				t.Run(name, func(t *testing.T) {
					ctx := t.Context()

					gcmParams := &kms.AESGCMCipherParameters{AAD: tt.aad}

					params := &kms.CipherParameters{
						Algorithm:  kms.CipherMode_AES_GCM96,
						Parameters: gcmParams,
					}

					// Create the encrypting cipher.
					encryptor, err := factory.NewCipher(ctx, kms.CipherOp_Encrypt, params)
					require.NoError(t, err)

					encrypted := feed(t, encryptor, plaintext, tt.multipart)

					require.NotEmpty(t, encrypted)
					require.NotEmpty(t, gcmParams.Nonce)

					// Closed cipher returns errors.
					_, err = encryptor.Update(ctx, plaintext)
					require.Error(t, err)
					_, err = encryptor.Close(ctx, plaintext)
					require.Error(t, err)

					// Create the decrypting cipher.
					decryptor, err := factory.NewCipher(ctx, kms.CipherOp_Decrypt, params)
					require.NoError(t, err)

					decrypted := feed(t, decryptor, encrypted, tt.multipart)

					// Closed cipher returns errors.
					_, err = decryptor.Update(ctx, encrypted)
					require.Error(t, err)
					_, err = decryptor.Close(ctx, encrypted)
					require.Error(t, err)

					require.Equal(t, plaintext, decrypted)
				})
			}
		})
	})
}
