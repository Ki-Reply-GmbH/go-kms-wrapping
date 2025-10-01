// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/keybuilder"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	s, p := session.TestSession(t)

	tests := map[string]*keybuilder.PairBuilder{
		"RSA":     keybuilder.RSA(4096),
		"EC-P256": keybuilder.EC(kms.Curve_P256),
		"EC-P384": keybuilder.EC(kms.Curve_P384),
		"EC-P521": keybuilder.EC(kms.Curve_P521),
	}

	for name, builder := range tests {
		t.Run(name, func(t *testing.T) {
			o1, o2, err := builder.Generate(s)
			require.NoError(t, err)

			key, err := pairFromHandles(s, p, o1, o2)
			require.NoError(t, err)

			testSigner(t, key)
		})
	}
}

func testSigner(t *testing.T, key kms.Key) {
	ctx := t.Context()

	signerFactory, ok := key.(kms.SignerFactory)
	require.True(t, ok)

	verifierFactory, ok := key.(kms.VerifierFactory)
	require.True(t, ok)

	var tests map[string]kms.SignAlgorithm

	switch keytype := key.GetType(); keytype {
	case kms.KeyType_EC_Private:
		var algo kms.SignAlgorithm
		switch key.GetKeyAttributes().Curve {
		case kms.Curve_P256:
			algo = kms.SignAlgo_EC_P256
		case kms.Curve_P384:
			algo = kms.SignAlgo_EC_P384
		case kms.Curve_P521:
			algo = kms.SignAlgo_EC_P521
		}
		tests = map[string]kms.SignAlgorithm{"ECDSA": algo}

	case kms.KeyType_RSA_Private:
		tests = map[string]kms.SignAlgorithm{
			"PSS-SHA256": kms.SignAlgo_RSA_PKCS1_PSS_SHA_256,
			"PSS-SHA384": kms.SignAlgo_RSA_PKCS1_PSS_SHA_384,
			"PSS-SHA512": kms.SignAlgo_RSA_PKCS1_PSS_SHA_512,
		}

	default:
		t.Fatalf("incompatible key type: %s", keytype)
	}

	message := []byte("Hello, World!")

	for name, algo := range tests {
		t.Run(name, func(t *testing.T) {
			signerParams := &kms.SignerParameters{Algorithm: algo}

			h := algo.Hash().New()
			_, err := h.Write(message)
			require.NoError(t, err)
			digest := h.Sum(nil)

			var signature []byte

			signature, err = signerFactory.Sign(ctx, signerParams, digest)
			require.NoError(t, err)
			require.NotEmpty(t, signature)

			verifierParams := &kms.VerifierParameters{
				Algorithm: algo,
				Signature: signature,
			}

			// Verify the signature using PKCS#11.
			err = verifierFactory.Verify(ctx, verifierParams, digest)
			require.NoError(t, err)

			// Verify the signature using the standard library.
			asym, ok := key.(kms.AsymmetricKey)
			require.True(t, ok)
			pub, err := asym.ExportComponentPublic(ctx)
			require.NoError(t, err)

			switch pub := pub.(type) {
			case *ecdsa.PublicKey:
				require.True(t, ecdsa.VerifyASN1(pub, digest, signature))
			case *rsa.PublicKey:
				hash := map[kms.SignAlgorithm]crypto.Hash{
					kms.SignAlgo_RSA_PKCS1_PSS_SHA_256: crypto.SHA256,
					kms.SignAlgo_RSA_PKCS1_PSS_SHA_384: crypto.SHA384,
					kms.SignAlgo_RSA_PKCS1_PSS_SHA_512: crypto.SHA512,
				}[algo]
				err := rsa.VerifyPSS(pub, hash, digest, signature, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
				})
				require.NoError(t, err)
			}
		})
	}

	t.Run("x509", func(t *testing.T) {
		// This is very minimal and could be expanded, but ensures basic
		// functionality with kms.NewCryptoSigner and x509.CreateCertificate.
		template := &x509.Certificate{
			BasicConstraintsValid: true, IsCA: true,
		}

		if key.GetType() == kms.KeyType_RSA_Private {
			// Override the PKCS#1v1.5 default.
			template.SignatureAlgorithm = x509.SHA256WithRSAPSS
		}

		signer, err := kms.NewCryptoSigner(ctx, key)
		require.NoError(t, err)

		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)

		err = cert.CheckSignatureFrom(cert)
		require.NoError(t, err)
	})
}
