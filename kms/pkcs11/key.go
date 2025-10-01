// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type key struct{}

type asymmetricKey struct{}

var (
	_ kms.Key           = (*key)(nil)
	_ kms.AsymmetricKey = (*asymmetricKey)(nil)
)

func (k *key) Resolved() bool {
	return false
}

func (k *key) Resolve(ctx context.Context) error {
	return nil
}

func (k *key) Close(ctx context.Context) error {
	return nil
}

func (k *key) Login(ctx context.Context, credentials *kms.Credentials) error {
	return nil
}

func (k *key) GetType() kms.KeyType {
	return 0
}

func (k *key) GetId() string {
	return ""
}

func (k *key) GetName() string {
	return ""
}

func (k *key) GetGroupId() string {
	return ""
}

func (k *key) IsPersistent() bool {
	return false
}

func (k *key) IsSensitive() bool {
	return false
}

func (k *key) IsAsymmetric() bool {
	return false
}

func (k *key) GetLength() uint32 {
	return 0
}

func (k *key) GetKeyAttributes() *kms.KeyAttributes {
	return nil
}

func (k *key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	return nil
}

func (k *asymmetricKey) GetPublic(ctx context.Context) (kms.Key, error) {
	return nil, nil
}

func (k *asymmetricKey) ExportPublic(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (k *asymmetricKey) ExportComponentPublic(ctx context.Context) (any, error) {
	return nil, nil
}
