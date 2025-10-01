// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var keyTypeBySignAlgo = map[kms.SignAlgorithm]kms.KeyType{
	kms.SignAlgo_EC_P256:               kms.KeyType_EC_Private,
	kms.SignAlgo_EC_P384:               kms.KeyType_EC_Private,
	kms.SignAlgo_EC_P521:               kms.KeyType_EC_Private,
	kms.SignAlgo_RSA_PKCS1_PSS_SHA_256: kms.KeyType_RSA_Private,
	kms.SignAlgo_RSA_PKCS1_PSS_SHA_384: kms.KeyType_RSA_Private,
	kms.SignAlgo_RSA_PKCS1_PSS_SHA_512: kms.KeyType_RSA_Private,
}

var curveBySignAlgo = map[kms.SignAlgorithm]kms.Curve{
	kms.SignAlgo_EC_P256: kms.Curve_P256,
	kms.SignAlgo_EC_P384: kms.Curve_P384,
	kms.SignAlgo_EC_P521: kms.Curve_P521,
}

var signatureEncodingLength = map[kms.SignAlgorithm]int{
	kms.SignAlgo_EC_P256: 32,
	kms.SignAlgo_EC_P384: 48,
	kms.SignAlgo_EC_P521: 66,
}

// signVerifyMechanism is code shared between Signer and Verifier
// implementations to map common parameters to the respective PKCS#11 mechanism.
func signVerifyMechanism(attrs *kms.KeyAttributes, algo kms.SignAlgorithm, digest []byte) (*pkcs11.Mechanism, error) {
	if attrs.KeyType != keyTypeBySignAlgo[algo] {
		return nil, fmt.Errorf("key type and signing algorithm do not match: %s with %s", attrs.KeyType, algo)
	}

	if attrs.Curve != curveBySignAlgo[algo] {
		return nil, fmt.Errorf("curve and signing algorithm do not match: %s with %s", attrs.Curve, algo)
	}

	hash := algo.Hash()
	if hash.Size() != len(digest) {
		return nil, fmt.Errorf("digest size does not match expected size from hash function: %d vs %d",
			len(digest), hash.Size())
	}

	var mech *pkcs11.Mechanism

	switch algo {
	case kms.SignAlgo_EC_P256, kms.SignAlgo_EC_P384, kms.SignAlgo_EC_P521:
		mech = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	case kms.SignAlgo_RSA_PKCS1_PSS_SHA_256:
		pssParams := pkcs11.NewPSSParams(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, uint(hash.Size()))
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams)
	case kms.SignAlgo_RSA_PKCS1_PSS_SHA_384:
		pssParams := pkcs11.NewPSSParams(pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, uint(hash.Size()))
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams)
	case kms.SignAlgo_RSA_PKCS1_PSS_SHA_512:
		pssParams := pkcs11.NewPSSParams(pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, uint(hash.Size()))
		mech = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, pssParams)

	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algo)
	}

	return mech, nil
}

func (pk *private) Sign(ctx context.Context, params *kms.SignerParameters, digest []byte) ([]byte, error) {
	mech, err := signVerifyMechanism(&pk.attributes, params.Algorithm, digest)
	if err != nil {
		return nil, err
	}

	sig, err := session.Scope(ctx, pk.pool, func(s *session.Handle) ([]byte, error) {
		init := s.SignInit(mech, pk.obj)
		sig, err := s.Sign(digest)
		return sig, errors.Join(init, err)
	})

	if err != nil {
		return nil, err
	}

	if mech.Mechanism == pkcs11.CKM_ECDSA {
		if len(sig) == 0 || len(sig)%2 != 0 {
			return nil, fmt.Errorf("ECDSA signature length invalid: %d", len(sig))
		}
		mid := len(sig) / 2
		return asn1.Marshal(struct{ R, S *big.Int }{
			R: new(big.Int).SetBytes(sig[:mid]),
			S: new(big.Int).SetBytes(sig[mid:]),
		})
	}

	return sig, nil
}

func (pk *public) Verify(ctx context.Context, params *kms.VerifierParameters, digest []byte) error {
	mech, err := signVerifyMechanism(&pk.attributes, params.Algorithm, digest)
	if err != nil {
		return err
	}

	signature := params.Signature
	if mech.Mechanism == pkcs11.CKM_ECDSA {
		// Transcode ASN.1 into PKCS#11's EC signature format.
		var rs struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &rs)
		switch {
		case err != nil:
			return err
		case len(rest) != 0:
			return errors.New("unexpected data remaining after asn1 unmarshal")
		}

		signature = nil
		rbytes, sbytes := rs.R.Bytes(), rs.S.Bytes()

		target := signatureEncodingLength[params.Algorithm]

		// Pad each value with leading zeroes up to target.
		if diff := target - len(rbytes); diff > 0 {
			rbytes = append(make([]byte, diff), rbytes...)
		}
		if diff := target - len(sbytes); diff > 0 {
			sbytes = append(make([]byte, diff), sbytes...)
		}

		signature = append(rbytes, sbytes...)
	}

	return pk.pool.Scope(ctx, func(s *session.Handle) error {
		return errors.Join(
			s.VerifyInit(mech, pk.obj),
			s.Verify(digest, signature))
	})
}

func (kp *pair) Sign(ctx context.Context, params *kms.SignerParameters, digest []byte) ([]byte, error) {
	return (&private{key: kp.key, obj: kp.prv}).Sign(ctx, params, digest)
}

func (kp *pair) Verify(ctx context.Context, params *kms.VerifierParameters, digest []byte) error {
	return (&public{key: kp.key, obj: kp.pub}).Verify(ctx, params, digest)
}
