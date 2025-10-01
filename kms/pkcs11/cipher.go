// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type cipher struct{}

var (
	_ kms.Cipher        = (*cipher)(nil)
	_ kms.CipherFactory = (*keyStore)(nil)
)

func (c *cipher) Update(ctx context.Context, input []byte) (output []byte, err error) {
	return nil, nil
}

func (c *cipher) Close(ctx context.Context, input []byte) (output []byte, err error) {
	return nil, nil
}

func (k *keyStore) NewCipher(ctx context.Context, operation kms.CipherOperation, key kms.Key, cipherParams *kms.CipherParameters) (kms.Cipher, error) {
	return nil, nil
}
