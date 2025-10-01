// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// TODO(satoqz): Use provider-specific constant offset:
	// https://github.com/openbao/go-kms-wrapping/pull/48

	// CipherMode_RSA_OAEP_SHA1 behaves like other kms.CipherMode_RSA_OAEP_SHA*
	// variants. It is included for compatibility with SoftHSM and historical
	// PKCS#11 Wrapper implementations.
	CipherMode_RSA_OAEP_SHA1 kms.CipherAlgorithmMode = iota + 1337

	// CipherMode_RSA_OAEP_SHA224 behaves like other
	// kms.CipherMode_RSA_OAEP_SHA* variants. It is included for compatibility
	// with historical PKCS#11 Wrapper implementations.
	CipherMode_RSA_OAEP_SHA224
)

// modestr wraps CipherAlgorithmMode.String to support the above custom modes.
func modestr(mode kms.CipherAlgorithmMode) string {
	switch mode {
	case CipherMode_RSA_OAEP_SHA1:
		return "rsa-oaep-sha1"
	case CipherMode_RSA_OAEP_SHA224:
		return "rsa-oaep-sha224"
	default:
		return mode.String()
	}
}

func (sec *secret) NewCipher(ctx context.Context, op kms.CipherOperation, params *kms.CipherParameters) (kms.Cipher, error) {
	switch params.Algorithm {
	case kms.CipherMode_AES_GCM96:
	default:
		return nil, fmt.Errorf("key does not support cipher mode %q", modestr(params.Algorithm))
	}

	switch op {
	case kms.CipherOp_Encrypt:
		return newEncrypt(ctx, sec.pool, sec.obj, params)
	case kms.CipherOp_Decrypt:
		return newDecrypt(ctx, sec.pool, sec.obj, params)
	}

	return nil, fmt.Errorf("key does not support cipher operation %q", op)
}

func (pk *public) NewCipher(ctx context.Context, op kms.CipherOperation, params *kms.CipherParameters) (kms.Cipher, error) {
	switch {
	case isOAEP(params.Algorithm):
	default:
		return nil, fmt.Errorf("does not support cipher mode %q", modestr(params.Algorithm))
	}

	switch op {
	case kms.CipherOp_Encrypt:
		return newEncrypt(ctx, pk.pool, pk.obj, params)
	default:
		return nil, fmt.Errorf("key does not support cipher operation %q", op)
	}
}

func (pk *private) NewCipher(ctx context.Context, op kms.CipherOperation, params *kms.CipherParameters) (kms.Cipher, error) {
	switch {
	case isOAEP(params.Algorithm):
	default:
		return nil, fmt.Errorf("key does not support cipher mode %q", modestr(params.Algorithm))
	}

	switch op {
	case kms.CipherOp_Decrypt:
		return newDecrypt(ctx, pk.pool, pk.obj, params)
	default:
		return nil, fmt.Errorf("key does not support cipher operation %q", op)
	}
}

func (kp *pair) NewCipher(ctx context.Context, op kms.CipherOperation, params *kms.CipherParameters) (kms.Cipher, error) {
	switch {
	case isOAEP(params.Algorithm):
	default:
		return nil, fmt.Errorf("key does not support cipher mode %q", modestr(params.Algorithm))
	}

	switch op {
	case kms.CipherOp_Encrypt:
		return newEncrypt(ctx, kp.pool, kp.pub, params)
	case kms.CipherOp_Decrypt:
		return newDecrypt(ctx, kp.pool, kp.prv, params)
	default:
		return nil, fmt.Errorf("key pair does not support cipher operation %q", op)
	}
}

// encrypt is an encrypting kms.Cipher.
type encrypt struct {
	session   *session.Handle // The session that we called EncryptInit with.
	multipart bool            // multipart is true if Update was called at least once.

	kmsGCMParams    *kms.AESGCMCipherParameters // The final nonce and tag must be written here.
	pkcs11GCMParams *pkcs11.GCMParams           // AES-GCM nonce memory (must be manually freed).
}

// decrypt is a decrypting kms.Cipher.
type decrypt struct {
	session   *session.Handle // session that we called EncryptInit with.
	multipart bool            // multipart is true if Update was called at least once.

	kmsGCMParams    *kms.AESGCMCipherParameters // Holds the tag that must be appended in the final call.
	pkcs11GCMParams *pkcs11.GCMParams           // AES-GCM nonce memory (must be manually freed).
}

// isOAEP returns true if mode is an RSA-OAEP mode.
func isOAEP(mode kms.CipherAlgorithmMode) bool {
	switch mode {
	case kms.CipherMode_RSA_OAEP_SHA256, kms.CipherMode_RSA_OAEP_SHA384, kms.CipherMode_RSA_OAEP_SHA512,
		CipherMode_RSA_OAEP_SHA1, CipherMode_RSA_OAEP_SHA224:
		return true
	default:
		return false
	}
}

// makeOAEPMechanism creates the RSA-OAEP mechanism for a given OAEP mode.
func makeOAEPMechanism(mode kms.CipherAlgorithmMode) *pkcs11.Mechanism {
	var hash, mgf uint

	switch mode {
	case kms.CipherMode_RSA_OAEP_SHA256:
		hash, mgf = pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256
	case kms.CipherMode_RSA_OAEP_SHA384:
		hash, mgf = pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384
	case kms.CipherMode_RSA_OAEP_SHA512:
		hash, mgf = pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512
	case CipherMode_RSA_OAEP_SHA1:
		hash, mgf = pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1
	case CipherMode_RSA_OAEP_SHA224:
		hash, mgf = pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224
	}

	params := pkcs11.NewOAEPParams(hash, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil)
	return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, params)
}

func newEncrypt(ctx context.Context, pool *session.PoolRef, obj pkcs11.ObjectHandle, params *kms.CipherParameters) (kms.Cipher, error) {
	// We need a session upfront to generate nonce values.
	s, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}

	var ret encrypt
	ret.session = s

	var mech *pkcs11.Mechanism

	switch params.Algorithm {
	case kms.CipherMode_AES_GCM96:
		nonce, err := s.GenerateRandom(12)
		if err != nil {
			return nil, errors.Join(err, s.Close())
		}

		kmsGCMParams, ok := params.Parameters.(*kms.AESGCMCipherParameters)
		if !ok {
			return nil, errors.Join(
				fmt.Errorf("expected *kms.AESGCMCipherParameters, got %T", kmsGCMParams),
				s.Close(),
			)
		}

		ret.kmsGCMParams = kmsGCMParams
		ret.pkcs11GCMParams = pkcs11.NewGCMParams(nonce, kmsGCMParams.AAD, 128)
		mech = pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, ret.pkcs11GCMParams)

	default:
		mech = makeOAEPMechanism(params.Algorithm)
	}

	if err := s.EncryptInit(mech, obj); err != nil {
		return nil, errors.Join(err, s.Close())
	}

	return &ret, nil
}

func newDecrypt(ctx context.Context, pool *session.PoolRef, obj pkcs11.ObjectHandle, params *kms.CipherParameters) (kms.Cipher, error) {
	var ret decrypt
	var mech *pkcs11.Mechanism

	switch params.Algorithm {
	case kms.CipherMode_AES_GCM96:
		kmsGCMParams, ok := params.Parameters.(*kms.AESGCMCipherParameters)
		if !ok {
			return nil, fmt.Errorf("expected *kms.AESGCMCipherParameters, got %T", kmsGCMParams)
		}

		ret.kmsGCMParams = kmsGCMParams
		ret.pkcs11GCMParams = pkcs11.NewGCMParams(kmsGCMParams.Nonce, kmsGCMParams.AAD, 128)
		mech = pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, ret.pkcs11GCMParams)

	default:
		mech = makeOAEPMechanism(params.Algorithm)
	}

	s, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}

	ret.session = s

	if err := s.DecryptInit(mech, obj); err != nil {
		return nil, errors.Join(err, s.Close())
	}

	return &ret, nil
}

func (enc *encrypt) Update(ctx context.Context, input []byte) (output []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Close the session if we've panicked.
			err = errors.Join(err, enc.session.Close())
			panic(r)
		} else if err != nil {
			// ...or if we're returning an error.
			err = errors.Join(err, enc.session.Close())
		}
	}()

	enc.multipart = true
	output, err = enc.session.EncryptUpdate(input)

	return output, err
}

func (dec *decrypt) Update(ctx context.Context, input []byte) (output []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			// Close the session if we've panicked.
			err = errors.Join(err, dec.session.Close())
			panic(r)
		} else if err != nil {
			// ...or if we're returning an error.
			err = errors.Join(err, dec.session.Close())
		}
	}()

	dec.multipart = true
	output, err = dec.session.DecryptUpdate(input)

	return output, err
}

func (enc *encrypt) Close(ctx context.Context, input []byte) (output []byte, err error) {
	defer func() {
		// Always close the session when closing the cipher.
		err = errors.Join(err, enc.session.Close())

		// Always free the GCMParams and store the IV.
		if enc.pkcs11GCMParams != nil {
			enc.kmsGCMParams.Nonce = enc.pkcs11GCMParams.IV()
			enc.pkcs11GCMParams.Free()
			enc.pkcs11GCMParams = nil
		}
	}()

	if !enc.multipart {
		output, err = enc.session.Encrypt(input)
		return output, err
	}

	if input != nil {
		output, err = enc.session.EncryptUpdate(input)
		if err != nil {
			return nil, err
		}
	}

	final, err := enc.session.EncryptFinal()
	return append(output, final...), err
}

func (dec *decrypt) Close(ctx context.Context, input []byte) (output []byte, err error) {
	defer func() {
		// Always close the session when closing the cipher.
		err = errors.Join(err, dec.session.Close())

		// Always free the GCMParams.
		if dec.pkcs11GCMParams != nil {
			dec.pkcs11GCMParams.Free()
			dec.pkcs11GCMParams = nil
		}
	}()

	if !dec.multipart {
		output, err = dec.session.Decrypt(input)
		return output, err
	}

	if input != nil {
		output, err = dec.session.DecryptUpdate(input)
		if err != nil {
			return nil, err
		}
	}

	final, err := dec.session.DecryptFinal()
	return append(output, final...), err
}
