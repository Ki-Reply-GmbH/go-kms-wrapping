// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type signer struct{}

var (
	_ kms.Signer        = (*signer)(nil)
	_ kms.SignerFactory = (*keyStore)(nil)
)

func (c *signer) Update(ctx context.Context, data []byte) error {
	return nil
}

func (c *signer) Close(ctx context.Context, data []byte) (signature []byte, err error) {
	return nil, nil
}

func (k *keyStore) DigestSign(ctx context.Context, privateKey kms.Key, signerParams *kms.SignerParameters, digest []byte) ([]byte, error) {
	return nil, nil
}

func (k *keyStore) NewSigner(ctx context.Context, privateKey kms.Key, signerParams *kms.SignerParameters) (kms.Signer, error) {
	return nil, nil
}
