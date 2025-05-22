// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"strconv"

	"github.com/ThalesGroup/crypto11"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

type Wrapper struct {
	ctx *crypto11.Context

	key Key

	mechanism   Mechanism
	rsaOaepHash crypto.Hash
}

var (
	_ wrapping.Wrapper       = (*Wrapper)(nil)
	_ wrapping.InitFinalizer = (*Wrapper)(nil)
)

func NewWrapper() *Wrapper {
	return &Wrapper{}
}

func (k *Wrapper) Init(_ context.Context, _ ...wrapping.Option) error {
	return nil
}

func (k *Wrapper) Finalize(_ context.Context, _ ...wrapping.Option) error {
	if k.ctx != nil {
		return k.ctx.Close()
	}
	return nil
}

func (k *Wrapper) SetConfig(_ context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(options...)
	if err != nil {
		return nil, err
	}

	metadata := make(map[string]string)

	key := NewKey(opts.withKeyId, opts.withKeyLabel)
	if key.id == "" && key.label == "" {
		return nil, fmt.Errorf("one of key id, key label is required")
	}
	k.key = key
	metadata["key_id"] = key.id
	metadata["key_label"] = key.label

	if opts.withMechanism != "" {
		mechanism, err := MechanismFromString(opts.withMechanism)
		if err != nil {
			return nil, err
		}
		k.mechanism = mechanism
		metadata["mechanism"] = k.mechanism.String()
	} else {
		k.mechanism = MechanismUnspecified
	}

	if k.mechanism == MechanismRsaOaep {
		if opts.withRsaOaepHash != "" {
			rsaOaepHash, err := RsaOaepHashMechanismFromString(opts.withRsaOaepHash)
			if err != nil {
				return nil, err
			}
			k.rsaOaepHash = rsaOaepHash
		} else {
			k.rsaOaepHash = DefaultRsaOaepHashMechanism
		}
		metadata["rsa_oaep_hash"] = k.rsaOaepHash.String()
	}

	var slot *int
	if opts.withSlot != "" {
		parsed, err := numberAutoParse(opts.withSlot, 32)
		if err != nil {
			return nil, err
		}
		// crypto11 converts back to uint again later...
		asInt := int(parsed)
		slot = &asInt
		metadata["slot"] = strconv.FormatUint(parsed, 10)
	}

	if opts.withTokenLabel != "" {
		metadata["token_label"] = opts.withTokenLabel
	} else if slot == nil {
		return nil, fmt.Errorf("one of slot, token label is required")
	}

	if opts.withLib == "" {
		return nil, fmt.Errorf("lib is required")
	}
	metadata["lib"] = opts.withLib

	config := &crypto11.Config{
		SlotNumber: slot,
		TokenLabel: opts.withTokenLabel,
		Pin:        opts.withPin,
		Path:       opts.withLib,
	}
	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, err
	}
	k.ctx = ctx

	return &wrapping.WrapperConfig{Metadata: metadata}, nil
}

func (k *Wrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperTypePkcs11, nil
}

func (k *Wrapper) KeyId(_ context.Context) (string, error) {
	return k.key.String(), nil
}

func (k *Wrapper) Encrypt(_ context.Context, plaintext []byte, _ ...wrapping.Option) (*wrapping.BlobInfo, error) {
	id, label := k.key.Bytes()

	if k.mechanism == MechanismAesGcm || k.mechanism == MechanismUnspecified {
		key, err := k.ctx.FindKey(id, label)
		if err != nil {
			return nil, err
		}
		if key != nil {
			return k.encryptAesGcm(key, plaintext, nil)
		}
	}

	if k.mechanism == MechanismRsaOaep || k.mechanism == MechanismUnspecified {
		keypair, err := k.ctx.FindRSAKeyPair(id, label)
		if err != nil {
			return nil, err
		}
		if keypair != nil {
			return k.encryptRsa(keypair, plaintext)
		}
	}

	return nil, fmt.Errorf("no key matching mechanism and key id/label found")
}

func (k *Wrapper) encryptAesGcm(key *crypto11.SecretKey, plaintext, additionalData []byte) (*wrapping.BlobInfo, error) {
	cipher, err := key.NewGCM()
	if err != nil {
		return nil, err
	}

	rand, err := k.ctx.NewRandomReader()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, cipher.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, err
	}

	ciphertext := cipher.Seal(nil, nonce, plaintext, additionalData)

	// Some HSMs (CloudHSM) do not read the nonce/IV and generate their own.
	// Since it's appended, we need to extract it.
	if len(ciphertext) == crypto11.DefaultGCMIVLength+len(plaintext)+cipher.Overhead() {
		nonce = ciphertext[len(ciphertext)-cipher.NonceSize():]
		ciphertext = ciphertext[:len(ciphertext)-cipher.NonceSize()]
	}

	return &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		Iv:         nonce,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: k.key.String(),
		},
	}, nil
}

func (k *Wrapper) encryptRsa(keypair crypto11.RSAKeyPair, plaintext []byte) (*wrapping.BlobInfo, error) {
	ciphertext, err := keypair.EncryptOAEP(k.rsaOaepHash, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return &wrapping.BlobInfo{
		Ciphertext: ciphertext,
		KeyInfo: &wrapping.KeyInfo{
			KeyId: k.key.String(),
		},
	}, nil
}

func (k *Wrapper) Decrypt(_ context.Context, in *wrapping.BlobInfo, _ ...wrapping.Option) ([]byte, error) {
	id, label := k.key.Bytes()

	if k.mechanism == MechanismAesGcm || k.mechanism == MechanismUnspecified {
		key, err := k.ctx.FindKey(id, label)
		if err != nil {
			return nil, err
		}
		if key != nil {
			return k.decryptAesGcm(key, in.Iv, in.Ciphertext, nil)
		}
	}

	if k.mechanism == MechanismRsaOaep || k.mechanism == MechanismUnspecified {
		keypair, err := k.ctx.FindRSAKeyPair(id, label)
		if err != nil {
			return nil, err
		}
		if keypair != nil {
			return k.decryptRsa(keypair, in.Ciphertext)
		}
	}

	return nil, fmt.Errorf("no key matching mechanism and key id/label found")
}

func (k *Wrapper) decryptAesGcm(key *crypto11.SecretKey, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	cipher, err := key.NewGCM()
	if err != nil {
		return nil, err
	}

	return cipher.Open(nil, nonce, ciphertext, additionalData)
}

func (k *Wrapper) decryptRsa(keypair crypto11.RSAKeyPair, ciphertext []byte) ([]byte, error) {
	return keypair.Decrypt(nil, ciphertext, &rsa.OAEPOptions{Hash: crypto.SHA1})
}

func (k *Wrapper) GetClient() *crypto11.Context {
	return k.ctx
}
