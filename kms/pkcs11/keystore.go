// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type keyStore struct{}

var (
	_ kms.KeyStore    = (*keyStore)(nil)
	_ kms.NewKeyStore = NewKeyStore
)

func NewKeyStore(params map[string]any) (kms.KeyStore, error) {
	return &keyStore{}, nil
}

func (k *keyStore) Close(ctx context.Context) error {
	return nil
}

func (k *keyStore) Login(ctx context.Context, credentials *kms.Credentials) error {
	return nil
}

func (k *keyStore) ListKeys(ctx context.Context) ([]kms.Key, error) {
	return nil, nil
}

func (k *keyStore) GetKeyById(ctx context.Context, keyId string) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) GetKeyByName(ctx context.Context, keyId string) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) GetKeyByAttrs(ctx context.Context, attrs map[string]any) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) AssumeKeyById(keyId string) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) AssumeKeyByName(keyId string) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) AssumeKeyByAttrs(attrs map[string]any) (kms.Key, error) {
	return nil, nil
}

func (k *keyStore) GetInfo() map[string]string {
	return nil
}
