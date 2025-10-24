// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
	kms11 "github.com/openbao/go-kms-wrapping/kms/pkcs11/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type Wrapper struct {
	store kms.KeyStore   // store is the PKCS#11 key store.
	attrs map[string]any // attrs are used to perform the key lookup.

	// mode may be unset (zero value) and automatically determined based on the key.
	mode kms.CipherAlgorithmMode

	// oaepHash is the RSA-OAEP hash to use (if mode is set to an RSA-OAEP
	// variant, these must match).
	oaepMode kms.CipherAlgorithmMode

	// id is returned by KeyId().
	id string

	// soft is true if software encryption should be used for asymmetric
	// ciphers. This is the default.
	soft bool
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

// NewWrapper creates a new PKCS#11 Wrapper.
func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (w *Wrapper) Init(ctx context.Context, opt ...wrapping.Option) error {
	return nil
}

func (w *Wrapper) Finalize(ctx context.Context, opt ...wrapping.Option) error {
	if w.store == nil {
		return nil
	}
	return w.store.Close(ctx)
}

func (w *Wrapper) SetConfig(ctx context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse wrapper options: %w", err)
	}

	if !opts.WithDisallowEnvVars {
		mergeOptionsWithEnv(opts)
	}

	params := make(map[string]any)
	w.attrs = make(map[string]any)

	{
		set := func(m map[string]any, key string, val string) {
			if val != "" {
				m[key] = val
			}
		}

		set(params, kms11.KeyStoreParamLib, opts.withLib)
		set(params, kms11.KeyStoreParamSlot, opts.withSlot)
		set(params, kms11.KeyStoreParamLabel, opts.withTokenLabel)

		set(w.attrs, kms11.IdAttr, opts.withKeyId)
		set(w.attrs, kms11.LabelAttr, opts.withKeyLabel)

		w.id = opts.withKeyLabel + ":" + opts.withKeyId
	}

	if w.oaepMode, err = oaepModeFromHashString(opts.withRsaOaepHash); err != nil {
		return nil, fmt.Errorf("failed to parse RSA-OAEP hash: %w", err)
	}

	if w.mode, err = modeFromString(opts.withMechanism); err != nil {
		return nil, fmt.Errorf(": %w", err)
	}

	if opts.withDisableSoftwareEncryption != "" {
		disable, err := strconv.ParseBool(opts.withDisableSoftwareEncryption)
		if err != nil {
			return nil, err
		}
		w.soft = !disable
	} else {
		w.soft = true
	}

	store, err := kms11.NewKeyStore(params)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key store: %w", err)
	}

	creds := &kms.Credentials{Password: opts.withPin}
	if err := store.Login(ctx, creds); err != nil {
		return nil, fmt.Errorf("failed to log into key store: %w", err)
	}

	w.store = store

	// We can just extend the base metadata available on the key store.
	metadata := store.GetInfo()

	{
		set := func(m map[string]string, key string, val string) {
			if val != "" {
				m[key] = val
			}
		}

		set(metadata, "key_id", opts.withKeyId)
		set(metadata, "key_label", opts.withKeyLabel)
		set(metadata, "mechanism", opts.withMechanism)
		set(metadata, "rsa_oaep_hash", opts.withRsaOaepHash)
	}

	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

func (w *Wrapper) Type(ctx context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	return w.id, nil
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	key, err := w.store.GetKeyByAttrs(ctx, w.attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	defer func() {
		err = errors.Join(err, key.Close(ctx))
	}()

	mode, soft := w.mode, false
	switch mode {
	// Mark modes eligible for software encryption:
	case kms.CipherMode_RSA_OAEP_SHA256:
		mode, soft = w.oaepMode, w.soft
	// Choose the best-available/default mode if unset:
	case kms.CipherAlgorithmMode(0):
		switch t := key.GetType(); t {
		case kms.KeyType_AES:
			mode = kms.CipherMode_AES_GCM96
		case kms.KeyType_RSA_Private, kms.KeyType_RSA_Public:
			mode, soft = w.oaepMode, w.soft
		default:
			return nil, fmt.Errorf("unsupported key type: %s", t)
		}
	}

	if soft {
		asymmetricKey, ok := key.(kms.AsymmetricKey)
		if !ok {
			return nil, errors.New("key is not a kms.AsymmetricKey")
		}

		pub, err := asymmetricKey.ExportComponentPublic(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to export public key: %w", err)
		}

		switch pub := pub.(type) {
		case *rsa.PublicKey:
			var h hash.Hash
			switch mode {
			case kms.CipherMode_RSA_OAEP_SHA256:
				h = sha256.New()
			case kms.CipherMode_RSA_OAEP_SHA384:
				h = sha512.New384()
			case kms.CipherMode_RSA_OAEP_SHA512:
				h = sha512.New()
			case kms11.CipherMode_RSA_OAEP_SHA1:
				h = sha1.New()
			case kms11.CipherMode_RSA_OAEP_SHA224:
				h = sha256.New224()
			default:
				return nil, fmt.Errorf("cipher mode %s is incompatible with public key of type %T", mode, pub)
			}
			ciphertext, err := rsa.EncryptOAEP(h, rand.Reader, pub, plaintext, nil)
			if err != nil {
				return nil, err
			}
			return &wrapping.BlobInfo{Ciphertext: ciphertext}, nil
		default:
			return nil, fmt.Errorf("unsupported public key type %T", pub)
		}
	}

	if !key.GetKeyAttributes().CanEncrypt {
		return nil, errors.New("key cannot encrypt")
	}

	factory, ok := key.(kms.CipherFactory)
	if !ok {
		return nil, errors.New("key is not a kms.CipherFactory")
	}

	params := &kms.CipherParameters{Algorithm: mode}
	var gcmParams *kms.AESGCMCipherParameters

	if mode == kms.CipherMode_AES_GCM96 {
		// Ensure we insert an AESGCMCipherParameters so we can query the nonce
		// and tag later.
		gcmParams = &kms.AESGCMCipherParameters{}
		params.Parameters = gcmParams
	}

	cipher, err := factory.NewCipher(ctx, kms.CipherOp_Encrypt, params)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cipher: %w", err)
	}

	ciphertext, err := cipher.Close(ctx, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to close cipher: %w", err)
	}

	blob := &wrapping.BlobInfo{Ciphertext: ciphertext}
	if gcmParams != nil {
		blob.Iv = gcmParams.Nonce
	}

	return blob, nil
}

func (w *Wrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	key, err := w.store.GetKeyByAttrs(ctx, w.attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	defer func() {
		err = errors.Join(err, key.Close(ctx))
	}()

	mode := w.mode
	switch mode {
	case kms.CipherMode_AES_GCM96:
	case kms.CipherMode_RSA_OAEP_SHA256:
		mode = w.oaepMode
	case kms.CipherAlgorithmMode(0):
		switch t := key.GetType(); t {
		case kms.KeyType_AES:
			mode = kms.CipherMode_AES_GCM96
		case kms.KeyType_RSA_Private, kms.KeyType_RSA_Public:
			mode = w.oaepMode
		default:
			return nil, fmt.Errorf("unsupported key type: %s", t)
		}
	}

	if !key.GetKeyAttributes().CanDecrypt {
		return nil, errors.New("key cannot decrypt")
	}

	factory, ok := key.(kms.CipherFactory)
	if !ok {
		return nil, errors.New("key is not a kms.CipherFactory")
	}

	ciphertext := in.Ciphertext
	params := &kms.CipherParameters{Algorithm: mode}

	if mode == kms.CipherMode_AES_GCM96 {
		params.Parameters = &kms.AESGCMCipherParameters{Nonce: in.Iv}
	}

	cipher, err := factory.NewCipher(ctx, kms.CipherOp_Decrypt, params)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate cipher: %w", err)
	}

	return cipher.Close(ctx, ciphertext)
}

func modeFromString(mech string) (kms.CipherAlgorithmMode, error) {
	switch mech {
	case "":
		return 0, nil
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return kms.CipherMode_RSA_OAEP_SHA256, nil
	case "CKM_AES_GCM", "AES_GCM":
		return kms.CipherMode_AES_GCM96, nil
	case "CKM_RSA_PKCS", "RSA_PKCS", "CKM_AES_CBC_PAD", "AES_CBC_PAD":
		return 0, fmt.Errorf("deprecated mechanism: %s", mech)
	}

	var num uint64
	var err error

	if strings.HasPrefix(mech, "0x") {
		num, err = strconv.ParseUint(mech[2:], 16, 32)
	} else {
		num, err = strconv.ParseUint(mech, 10, 32)
	}

	if err != nil {
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}

	switch num {
	case pkcs11.CKM_AES_GCM:
		return kms.CipherMode_AES_GCM96, nil
	case pkcs11.CKM_RSA_PKCS_OAEP:
		return kms.CipherMode_RSA_OAEP_SHA256, nil
	case pkcs11.CKM_RSA_PKCS, pkcs11.CKM_AES_CBC_PAD:
		return 0, fmt.Errorf("deprecated mechanism: %s", mech)
	}

	return 0, fmt.Errorf("unsupported mechanism: %s", mech)
}

func oaepModeFromHashString(hash string) (kms.CipherAlgorithmMode, error) {
	hash = strings.ToLower(hash)
	switch hash {
	case "", "sha256":
		return kms.CipherMode_RSA_OAEP_SHA256, nil
	case "sha384":
		return kms.CipherMode_RSA_OAEP_SHA384, nil
	case "sha512":
		return kms.CipherMode_RSA_OAEP_SHA512, nil
	case "sha1":
		return kms11.CipherMode_RSA_OAEP_SHA1, nil
	case "sha224":
		return kms11.CipherMode_RSA_OAEP_SHA1, nil // TODO
	default:
		return 0, fmt.Errorf("unsupported hash mechanism: %s", hash)
	}
}
