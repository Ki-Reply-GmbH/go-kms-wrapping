// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	s, p := session.TestSession(t)

	t.Run("Secret", func(t *testing.T) {
		t.Run("AES", func(t *testing.T) {
			obj, err := keybuilder.AES(32).Generate(s)
			require.NoError(t, err)

			sec, err := fromHandle(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &secret{}, sec)
			require.Implements(t, (*kms.Key)(nil), sec)
			require.Implements(t, (*kms.CipherFactory)(nil), sec)
			require.NotImplements(t, (*kms.AsymmetricKey)(nil), sec)
			require.NotImplements(t, (*kms.SignerFactory)(nil), sec)
			require.NotImplements(t, (*kms.VerifierFactory)(nil), sec)

			a := sec.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_AES)

			require.True(t, a.CanDecrypt)
			require.True(t, a.CanEncrypt)

			require.False(t, a.CanSign)
			require.False(t, a.CanVerify)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(32*8))
			require.Equal(t, a.Curve, kms.Curve_None)
		})
	})

	t.Run("Pair", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			o1, o2, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			kp, err := pairFromHandles(s, p, o1, o2)
			require.NoError(t, err)

			require.IsType(t, &pair{}, kp)
			require.Implements(t, (*kms.Key)(nil), kp)
			require.Implements(t, (*kms.AsymmetricKey)(nil), kp)
			require.Implements(t, (*kms.CipherFactory)(nil), kp)
			require.Implements(t, (*kms.SignerFactory)(nil), kp)
			require.Implements(t, (*kms.VerifierFactory)(nil), kp)

			a := kp.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Private)

			// SoftHSM defaults all these to true.
			require.True(t, a.CanSign)
			require.True(t, a.CanVerify)
			require.True(t, a.CanDecrypt)
			require.True(t, a.CanEncrypt)

			require.False(t, a.IsSensitive)
			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			for _, curve := range []kms.Curve{
				kms.Curve_P256, kms.Curve_P384, kms.Curve_P521,
			} {
				t.Run(strings.ToUpper(curve.String()), func(t *testing.T) {
					o1, o2, err := keybuilder.EC(curve).Generate(s)
					require.NoError(t, err)

					kp, err := pairFromHandles(s, p, o1, o2)
					require.NoError(t, err)

					require.IsType(t, &pair{}, kp)
					require.Implements(t, (*kms.Key)(nil), kp)
					require.Implements(t, (*kms.AsymmetricKey)(nil), kp)
					require.Implements(t, (*kms.SignerFactory)(nil), kp)
					require.Implements(t, (*kms.VerifierFactory)(nil), kp)

					a := kp.GetKeyAttributes()

					require.Equal(t, a.KeyType, kms.KeyType_EC_Private)

					// SoftHSM defaults all these to true, even on EC keys.
					require.True(t, a.CanSign)
					require.True(t, a.CanVerify)
					require.True(t, a.CanDecrypt)
					require.True(t, a.CanEncrypt)

					require.False(t, a.IsSensitive)
					require.False(t, a.IsExportable)
					require.False(t, a.IsPersistent)

					require.Equal(t, a.Curve, curve)
					require.Equal(t, a.BitKeyLen, curve.Len())
				})
			}
		})
	})

	t.Run("Public", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			obj, _, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			pub, err := fromHandle(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &public{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			require.Implements(t, (*kms.CipherFactory)(nil), pub)
			require.Implements(t, (*kms.VerifierFactory)(nil), pub)
			require.NotImplements(t, (*kms.SignerFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Public)

			require.True(t, a.CanVerify)
			require.True(t, a.CanEncrypt)
			require.True(t, a.IsExportable)

			require.False(t, a.CanSign)
			require.False(t, a.CanDecrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			obj, _, err := keybuilder.EC(kms.Curve_P256).Generate(s)
			require.NoError(t, err)

			pub, err := fromHandle(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &public{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			require.Implements(t, (*kms.CipherFactory)(nil), pub)
			require.Implements(t, (*kms.VerifierFactory)(nil), pub)
			require.NotImplements(t, (*kms.SignerFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_EC_Public)

			require.True(t, a.CanVerify)
			require.True(t, a.CanEncrypt)
			require.True(t, a.IsExportable)

			require.False(t, a.CanSign)
			require.False(t, a.CanDecrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.Curve, kms.Curve_P256)
			require.Equal(t, a.BitKeyLen, kms.Curve_P256.Len())
		})
	})

	t.Run("Private", func(t *testing.T) {
		t.Run("RSA", func(t *testing.T) {
			_, obj, err := keybuilder.RSA(4096).Generate(s)
			require.NoError(t, err)

			pub, err := fromHandle(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &private{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.Implements(t, (*kms.AsymmetricKey)(nil), pub)
			require.Implements(t, (*kms.CipherFactory)(nil), pub)
			require.Implements(t, (*kms.SignerFactory)(nil), pub)
			require.NotImplements(t, (*kms.VerifierFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_RSA_Private)

			require.True(t, a.CanSign)
			require.True(t, a.CanDecrypt)

			require.False(t, a.CanVerify)
			require.False(t, a.CanEncrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.BitKeyLen, uint32(4096))
			require.Equal(t, a.Curve, kms.Curve_None)
		})

		t.Run("EC", func(t *testing.T) {
			_, obj, err := keybuilder.EC(kms.Curve_P256).Generate(s)
			require.NoError(t, err)

			pub, err := fromHandle(s, p, obj)
			require.NoError(t, err)

			require.IsType(t, &private{}, pub)
			require.Implements(t, (*kms.Key)(nil), pub)
			require.Implements(t, (*kms.CipherFactory)(nil), pub)
			require.Implements(t, (*kms.SignerFactory)(nil), pub)
			require.NotImplements(t, (*kms.VerifierFactory)(nil), pub)

			a := pub.GetKeyAttributes()

			require.Equal(t, a.KeyType, kms.KeyType_EC_Private)

			require.True(t, a.CanSign)
			require.True(t, a.CanDecrypt)

			require.False(t, a.CanVerify)
			require.False(t, a.CanEncrypt)
			require.False(t, a.IsSensitive)
			require.False(t, a.IsExportable)
			require.False(t, a.IsPersistent)

			require.Equal(t, a.Curve, kms.Curve_P256)
			require.Equal(t, a.BitKeyLen, kms.Curve_P256.Len())
		})
	})
}

func TestAsymmetricKey(t *testing.T) {
	s, p := session.TestSession(t)

	// NOTE: This test effectively builds a matrix of (Key types...) x (Pair,
	// Public, Private) and then runs all kms.AsymmetricKey methods against each
	// variant.

	type handles struct{ pub, prv pkcs11.ObjectHandle }
	collect := func(pub, prv pkcs11.ObjectHandle, err error) handles {
		require.NoError(t, err)
		return handles{pub, prv}
	}

	// Keys need to be labeled (or, alternatively, have IDs) such that
	// GetPublic() has a chance at finding the other half.
	keys := map[string]handles{
		"RSA":     collect(keybuilder.RSA(4096).Label("RSA").Generate(s)),
		"EC-P256": collect(keybuilder.EC(kms.Curve_P256).Label("EC-P256").Generate(s)),
		"EC-P384": collect(keybuilder.EC(kms.Curve_P384).Label("EC-P384").Generate(s)),
		"EC-P521": collect(keybuilder.EC(kms.Curve_P521).Label("EC-P521").Generate(s)),
	}

	tests := map[string]func(*testing.T, handles) kms.AsymmetricKey{
		"Pair": func(t *testing.T, h handles) kms.AsymmetricKey {
			kp, err := pairFromHandles(s, p, h.pub, h.prv)
			require.NoError(t, err)

			asym, ok := kp.(kms.AsymmetricKey)
			require.True(t, ok)

			return asym
		},
		"Public": func(t *testing.T, h handles) kms.AsymmetricKey {
			pub, err := fromHandle(s, p, h.pub)
			require.NoError(t, err)

			asym, ok := pub.(kms.AsymmetricKey)
			require.True(t, ok)

			return asym
		},
		"Private": func(t *testing.T, h handles) kms.AsymmetricKey {
			prv, err := fromHandle(s, p, h.prv)
			require.NoError(t, err)

			asym, ok := prv.(kms.AsymmetricKey)
			require.True(t, ok)

			return asym
		},
	}

	for name, builder := range keys {
		t.Run(name, func(t *testing.T) {
			for name, factory := range tests {
				t.Run(name, func(t *testing.T) {
					asym := factory(t, builder)

					t.Run("GetPublic", func(t *testing.T) {
						pub, err := asym.GetPublic(t.Context())
						require.NoError(t, err)
						require.NotNil(t, pub)

						switch pub.(type) {
						case *public, *pair:
						default:
							require.FailNow(t, fmt.Sprintf("expected *public or *private, got %T", pub))
						}
					})

					t.Run("ExportPublic", func(t *testing.T) {
						b, err := asym.ExportPublic(t.Context())
						require.NoError(t, err)
						require.NotEmpty(t, b)
					})

					t.Run("ExportComponentPublic", func(t *testing.T) {
						pub, err := asym.ExportComponentPublic(t.Context())
						require.NoError(t, err)
						require.NotEmpty(t, pub)

						switch ty := asym.(kms.Key).GetType(); ty {
						case kms.KeyType_RSA_Private, kms.KeyType_RSA_Public:
							require.IsType(t, &rsa.PublicKey{}, pub)
						case kms.KeyType_EC_Private, kms.KeyType_EC_Public:
							require.IsType(t, &ecdsa.PublicKey{}, pub)
						default:
							require.FailNow(t, fmt.Sprintf("unexpected key type %s", ty))
						}
					})
				})
			}
		})
	}
}
