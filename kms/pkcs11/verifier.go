// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type verifier struct{}

var (
	_ kms.Verifier        = (*verifier)(nil)
	_ kms.VerifierFactory = (*keyStore)(nil)
)

func (c *verifier) Update(ctx context.Context, data []byte) error {
	return nil
}

func (c *verifier) Close(ctx context.Context, data, signature []byte) error {
	return nil
}

func (k *keyStore) DigestVerify(ctx context.Context, publicKey kms.Key, verifierParams *kms.VerifierParameters, digest []byte) error {
	return nil
}

func (k *keyStore) NewVerifier(ctx context.Context, publicKey kms.Key, verifierParams *kms.VerifierParameters) (kms.Verifier, error) {
	return nil, nil
}
