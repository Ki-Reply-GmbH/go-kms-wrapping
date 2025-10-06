// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// LibKeyStoreParam sets the path to the PKCS#11 library.
	LibKeyStoreParam = "lib"

	// PinKeyStoreParam sets the user pin for the PKCS#11 slot.
	PinKeyStoreParam = "pin"

	// SlotKeyStoreParam sets the PKCS#11 slot ID.
	SlotKeyStoreParam = "slot"

	// TokenLabelKeyStoreParam sets the PKCS#11 token label.
	TokenLabelKeyStoreParam = "token_label"

	// DisableSoftwareEncryptionKeyStoreParam disables local public key
	// encryption in software and performs it on-device instead.
	DisableSoftwareEncryptionKeyStoreParam = "disable_software_encryption"

	// DisableSoftwareVerificationKeyStoreParam disables local public key
	// verification in software and performs it on-device instead.
	DisableSoftwareVerificationKeyStoreParam = "disable_software_verification"
)

var ErrKeyAssumptionNotSupported = errors.New("key assumption is not supported")

type keyStore struct {
	// These are initialized in [NewKeyStore].
	slot                                     *uint
	lib, pin, label                          string
	softwareEncryption, softwareVerification bool

	pool *pool // This is initialized in [keyStore.Login].
}

var (
	_ kms.KeyStore    = (*keyStore)(nil)
	_ kms.NewKeyStore = NewKeyStore
)

// NewKeyStore creates a new [kms.KeyStore] for a PKCS#11 token slot.
func NewKeyStore(params map[string]any) (kms.KeyStore, error) {
	var err error

	k := &keyStore{
		// Special case, these default to true rather than their zero value.
		softwareEncryption:   true,
		softwareVerification: true,
	}

	if v, ok := params[LibKeyStoreParam]; !ok {
		return nil, fmt.Errorf("missing required key store parameter %q", LibKeyStoreParam)
	} else {
		k.lib, err = parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}
	}

	// We can sensibly default to an empty string if the parameter is not given;
	// some PKCS#11 modules (e.g., GCP KMS) ignore the pin value and bring their
	// own authentication elsewhere.
	if v, ok := params[PinKeyStoreParam]; ok {
		k.pin, err = parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := params[TokenLabelKeyStoreParam]; ok {
		k.label, err = parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}
	}

	if v, ok := params[SlotKeyStoreParam]; ok {
		// Bit cursed, we first reinterpret as a string and then perform custom
		// uint parsing that understands both hex and decimal.
		tmp, err := parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}

		var slot64 uint64
		tmp = strings.ToLower(tmp)

		if strings.HasPrefix(tmp, "0x") {
			slot64, err = strconv.ParseUint(tmp[2:], 16, 32)
		} else {
			slot64, err = strconv.ParseUint(tmp, 10, 32)
		}

		if err != nil {
			return nil, err
		}

		slot := uint(slot64) // Safe because we call ParseUint w/ 32 bits.
		k.slot = &slot
	}

	if k.slot == nil && k.label == "" {
		return nil, fmt.Errorf("at least one of %q, %q is required", SlotKeyStoreParam, TokenLabelKeyStoreParam)
	}

	if v, ok := params[DisableSoftwareEncryptionKeyStoreParam]; ok {
		tmp, err := parseutil.ParseBool(v)
		k.softwareEncryption = !tmp
		if err != nil {
			return nil, err
		}
	}

	if v, ok := params[DisableSoftwareVerificationKeyStoreParam]; ok {
		tmp, err := parseutil.ParseBool(v)
		k.softwareVerification = !tmp
		if err != nil {
			return nil, err
		}
	}

	return k, nil
}

func (k *keyStore) Login(ctx context.Context, _ *kms.Credentials) error {
	slot, err := open(k.lib, k.slot, k.label)
	if err != nil {
		return err
	}

	// Update the optionally user-provided initial slot ID with the slot
	// ID resolved by slot acquisition. This is mainly a nice to have for
	// [KeyStore.GetInfo].
	k.slot = &slot.id

	// The slot will be fully owned and managed by the session pool.
	k.pool, err = newPool(slot, k.pin)
	return err
}

func (k *keyStore) Close(ctx context.Context) error {
	return k.pool.close()
}

func (k *keyStore) ListKeys(ctx context.Context) (keys []kms.Key, err error) {
	err = k.pool.do(ctx, func(c *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		keys, err = findKeys(c, sh, nil, 0)
		return err
	})
	return keys, err
}

func (k *keyStore) GetKeyById(ctx context.Context, id string) (key kms.Key, err error) {
	tmp := []byte(id)
	if strings.HasPrefix(id, "0x") {
		var err error
		tmp, err = hex.DecodeString(id)
		if err != nil {
			return nil, err
		}
	}

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, tmp)}

	err = k.pool.do(ctx, func(c *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		key, err = findOneKey(c, sh, template)
		return err
	})

	return key, err
}

func (k *keyStore) GetKeyByName(ctx context.Context, name string) (key kms.Key, err error) {
	// Up for debate: What should "Name" map to in PKCS#11? I've chosen
	// CKA_LABEL for now, but there's also a reasonable argument not to support
	// "Name" at all, since there's no clear mapping.
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(name))}

	err = k.pool.do(ctx, func(c *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		key, err = findOneKey(c, sh, template)
		return err
	})

	return key, err
}

func (k *keyStore) GetKeyByAttrs(ctx context.Context, attrs map[string]any) (key kms.Key, err error) {
	var template []*pkcs11.Attribute

	if v, ok := attrs[kms.NameAttr]; ok {
		name, err := parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}

		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(name)))
	}

	if v, ok := attrs[kms.IdAttr]; ok {
		tmp, err := parseutil.ParseString(v)
		if err != nil {
			return nil, err
		}

		id := []byte(tmp)
		if strings.HasPrefix(tmp, "0x") {
			id, err = hex.DecodeString(tmp)
			if err != nil {
				return nil, err
			}
		}

		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}

	err = k.pool.do(ctx, func(c *pkcs11.Ctx, sh pkcs11.SessionHandle) error {
		key, err = findOneKey(c, sh, template)
		return err
	})

	return key, err
}

func (k *keyStore) AssumeKeyById(id string) (kms.Key, error) {
	return nil, ErrKeyAssumptionNotSupported
}

func (k *keyStore) AssumeKeyByName(name string) (kms.Key, error) {
	return nil, ErrKeyAssumptionNotSupported
}

func (k *keyStore) AssumeKeyByAttrs(attrs map[string]any) (kms.Key, error) {
	return nil, ErrKeyAssumptionNotSupported
}

func (k *keyStore) GetInfo() map[string]string {
	info := make(map[string]string)

	info[LibKeyStoreParam] = k.lib

	if k.label != "" {
		info[TokenLabelKeyStoreParam] = k.label
	}

	if k.slot != nil {
		info[SlotKeyStoreParam] = fmt.Sprintf("0x%x", k.slot)
	}

	return info
}
