// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// KeyAttributeClass maps to CKA_CLASS. Expected to be of type uint.
	KeyAttributeClass = "pkcs11_class"
	// KeyAttributeType maps to CKA_KEY_TYPE. Expected to be of type uint.
	KeyAttributeType = "pkcs11_key_type"
)

var (
	ErrKeyNotFound  = errors.New("key not found")
	ErrKeyNotUnique = errors.New("key cannot be uniquely identified")
)

type key struct {
	*kms.KeyAttributes
}

var _ kms.Key = (*key)(nil)

func (k *key) Resolved() bool                    { return true }
func (k *key) Resolve(ctx context.Context) error { return nil }

func (k *key) GetId() string        { return k.KeyId }
func (k *key) GetName() string      { return k.Name }
func (k *key) GetGroupId() string   { return k.GroupId }
func (k *key) GetType() kms.KeyType { return k.KeyType }
func (k *key) GetLength() uint32    { return k.BitKeyLen }

func (k *key) GetKeyAttributes() *kms.KeyAttributes { return k.KeyAttributes }
func (k *key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	return &kms.ProtectedKeyAttributes{}
}

func (k *key) IsPersistent() bool {
	// Assume that keys in PKCS#11 are always persistent.
	return true
}

func (k *key) IsSensitive() bool {
	return true
}

func (k *key) IsAsymmetric() bool {
	// This is overridden by more specialized implementations.
	return false
}

func (k *key) Close(ctx context.Context) error {
	return nil
}

func (k *key) Login(ctx context.Context, _ *kms.Credentials) error {
	// We can try to support CKA_ALWAYS_AUTHENTICATE in the future if someone
	// deems it necessary. The spec is very unclear on how this flag affects
	// global session state (and the locking we need to do as a result), so I
	// won't open this can of worms for now.
	return errors.New("not supported")
}

type secretKey struct {
	key
	obj pkcs11.ObjectHandle
}

type publicKey struct {
	key
	obj pkcs11.ObjectHandle
}

type privateKey struct {
	key
	obj pkcs11.ObjectHandle
}

type publicPrivateKeyPair struct {
	key
	pub, prv pkcs11.ObjectHandle
}

var (
	_ kms.AsymmetricKey = (*publicKey)(nil)
	_ kms.AsymmetricKey = (*privateKey)(nil)
	_ kms.AsymmetricKey = (*publicPrivateKeyPair)(nil)
)

func (k *publicKey) IsAsymmetric() bool            { return true }
func (k *privateKey) IsAsymmetric() bool           { return true }
func (k *publicPrivateKeyPair) IsAsymmetric() bool { return true }

func (k *publicKey) GetPublic(ctx context.Context) (kms.Key, error) {
	return k, nil
}

func (k *publicKey) ExportPublic(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (k *publicKey) ExportComponentPublic(ctx context.Context) (any, error) {
	return nil, nil
}

func (k *privateKey) GetPublic(ctx context.Context) (kms.Key, error) {
	return k, nil
}

func (k *privateKey) ExportPublic(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (k *privateKey) ExportComponentPublic(ctx context.Context) (any, error) {
	return nil, nil
}

func (k *publicPrivateKeyPair) GetPublic(ctx context.Context) (kms.Key, error) {
	return k, nil
}

func (k *publicPrivateKeyPair) ExportPublic(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (k *publicPrivateKeyPair) ExportComponentPublic(ctx context.Context) (any, error) {
	return nil, nil
}

// findObjects is a helper to perform the PKCS#11
//
//	FindObjectsInit -> FindObjects -> FindObjectsFinal
//
// flow.
//
// A limit of zero equals no limit.
func findObjects(c *pkcs11.Ctx, sh pkcs11.SessionHandle, template []*pkcs11.Attribute, limit int) ([]pkcs11.ObjectHandle, error) {
	if err := c.FindObjectsInit(sh, template); err != nil {
		return nil, pkcs11Error("FindObjectsInit", err)
	}

	const batchSize = 128
	var objs []pkcs11.ObjectHandle

	if limit == 0 {
		for {
			batch, _, err := c.FindObjects(sh, batchSize)
			if err != nil {
				return nil, pkcs11Error("FindObjects", err)
			}
			if len(batch) == 0 {
				break
			}
			objs = append(objs, batch...)
		}
	} else {
		for remaining := limit; remaining > 0; remaining -= batchSize {
			batch, _, err := c.FindObjects(sh, min(remaining, batchSize))
			if err != nil {
				return nil, pkcs11Error("FindObjects", err)
			}
			if len(batch) == 0 {
				break
			}
			objs = append(objs, batch...)
		}
	}

	if err := c.FindObjectsFinal(sh); err != nil {
		return nil, pkcs11Error("FindObjectsFinal", err)
	}

	return objs, nil
}

// getKeyAttributes resolves most of [kms.KeyAttributes] from a key object.
func getKeyAttributes(c *pkcs11.Ctx, sh pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (*kms.KeyAttributes, error) {
	// First, resolve generic attributes that apply to all possible key types.
	// Then, use that information to query specific attributes down the line.
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}

	attrs, err := c.GetAttributeValue(sh, obj, template)
	if err != nil {
		return nil, pkcs11Error("GetAttributeValue", err)
	}

	var ret kms.KeyAttributes

	class, keytype := pkcs11.CK_UNAVAILABLE_INFORMATION, pkcs11.CK_UNAVAILABLE_INFORMATION

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_ID:
			ret.KeyId = string(attr.Value)
			ret.GroupId = string(attr.Value)
		case pkcs11.CKA_LABEL:
			ret.Name = string(attr.Value)
		case pkcs11.CKA_CLASS:
			class, err = bytesToUint(attr.Value)
		case pkcs11.CKA_KEY_TYPE:
			keytype, err = bytesToUint(attr.Value)
		default:
			err = fmt.Errorf("unexpected field in GetAttributeValue response: %d", attr.Type)
		}

		if err != nil {
			return nil, err
		}
	}

	ret.KeyType, err = classAndKeytypeToKms(class, keytype)
	if err != nil {
		return nil, err
	}

	// These are quite useful to keep around (internally) as they provide much
	// simpler control flow than the condensed kms.KeyType.
	ret.ProviderSpecific = map[string]any{
		KeyAttributeClass: class,
		KeyAttributeType:  keytype,
	}

	template = nil

	// Query for key usage.
	//
	// NOTE: We cannot just query any key class for any attribute. This is not a
	// performance optimization, some PKCS#11 implementations will hard error if
	// a query includes a nonsensical attribute (e.g., querying CKA_DECRYPT for
	// CKO_PUBLIC_KEY).
	switch class {
	case pkcs11.CKO_SECRET_KEY:
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
		)
	case pkcs11.CKO_PRIVATE_KEY:
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, 0),
		)
	case pkcs11.CKO_PUBLIC_KEY:
		template = append(template,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, 0),
		)
	}

	// Query for some additional boolean flags no matter the key type, it's
	// easier to handle them here than in the first query.
	template = append(template,
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, 0),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, 0),
	)

	attrs, err = c.GetAttributeValue(sh, obj, template)
	if err != nil {
		return nil, pkcs11Error("GetAttributeValue", err)
	}

	for _, attr := range attrs {
		val, err := bytesToUint(attr.Value)
		if err != nil {
			return nil, err
		}

		if val != pkcs11.CK_TRUE {
			continue
		}

		switch attr.Type {
		case pkcs11.CKA_ENCRYPT:
			ret.CanEncrypt = true
		case pkcs11.CKA_DECRYPT:
			ret.CanDecrypt = true
		case pkcs11.CKA_SIGN:
			ret.CanSign = true
		case pkcs11.CKA_VERIFY:
			ret.CanVerify = true
		case pkcs11.CKA_SENSITIVE:
			ret.IsSensitive = true
		case pkcs11.CKA_EXTRACTABLE:
			ret.IsExportable = true
		}
	}

	template = nil

	// ...and a final very specific query for key sizes.
	switch class {
	case pkcs11.CKO_SECRET_KEY:
		template = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 0)}
	case pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY:
		switch keytype {
		case pkcs11.CKK_EC:
			template = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, 0)}
		case pkcs11.CKK_RSA:
			template = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_MODULUS, 0)}
		}
	}

	attrs, err = c.GetAttributeValue(sh, obj, template)
	if err != nil {
		return nil, pkcs11Error("GetAttributeValue", err)
	}

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_VALUE_LEN:
			val, err := bytesToUint(attr.Value)
			if err != nil {
				return nil, err
			}
			if val == pkcs11.CK_UNAVAILABLE_INFORMATION {
				continue
			}
			// CKA_VALUE_LEN is byte length, at least according to Thales.
			ret.BitKeyLen = uint32(val) * 8

		case pkcs11.CKA_EC_PARAMS:
			ret.Curve, err = curveFromOID(attr.Value)
			if err != nil {
				return nil, err
			}
			if ret.Curve == kms.Curve_None {
				// Give this one more try by interpreting the value as a string.
				ret.Curve = curveFromLiteral(attrs[0].Value)
			}
			ret.BitKeyLen = ret.Curve.Len()

		case pkcs11.CKA_MODULUS:
			ret.BitKeyLen = uint32(new(big.Int).SetBytes(attr.Value).BitLen())
		}
	}

	return &ret, nil
}

// mergeIntoKeys finds public/private key pairs in a list of keys and either
// merges them or returns an error if keys cannot be meaningfully combined
// (e.g., when there are two private keys with the same ID).
func mergeIntoKeys(attrs []*kms.KeyAttributes, objs []pkcs11.ObjectHandle) ([]kms.Key, error) {
	type group struct {
		// Prefer matching public/private keys by ID, as the spec recommends.
		// Alternatively, also allow matching them by label.
		id, label string
		// Even if key ID or label match, we can still tell them apart via key
		// type as a last resort.
		keytype uint
	}

	var ret []kms.Key

	appendStandalone := func(a *kms.KeyAttributes, obj pkcs11.ObjectHandle, class uint) {
		k := key{KeyAttributes: a}
		switch class {
		case pkcs11.CKO_SECRET_KEY:
			ret = append(ret, &secretKey{
				key: k, obj: obj,
			})
		case pkcs11.CKO_PRIVATE_KEY:
			ret = append(ret, &privateKey{
				key: k, obj: obj,
			})
		case pkcs11.CKO_PUBLIC_KEY:
			ret = append(ret, &publicKey{
				key: k, obj: obj,
			})
		}
	}

	groups := make(map[group][]int)

	for i, a := range attrs {
		class, keytype :=
			a.ProviderSpecific[KeyAttributeClass].(uint),
			a.ProviderSpecific[KeyAttributeType].(uint)

		if class == pkcs11.CKO_SECRET_KEY {
			// Fast path for symmetric keys.
			appendStandalone(a, objs[i], class)
			continue
		}

		switch {
		case a.GroupId != "":
			g := group{
				label:   a.GroupId,
				keytype: keytype,
			}
			arr := groups[g]
			groups[g] = append(arr, i)

		case a.Name != "":
			g := group{
				label:   a.Name,
				keytype: keytype,
			}
			arr := groups[g]
			groups[g] = append(arr, i)

		default:
			// If neither was set, skip right to considering this a standalone
			// key; there's no way we can match it to another one.
			appendStandalone(a, objs[i], class)
		}
	}

	for _, indices := range groups {
		switch len(indices) {
		case 2:
			// Try finding a public/private key pair match.
			attrs1, obj1 := attrs[indices[0]], objs[indices[0]]
			class1 := attrs1.ProviderSpecific[KeyAttributeClass].(uint)

			attrs2, obj2 := attrs[indices[1]], objs[indices[1]]
			class2 := attrs2.ProviderSpecific[KeyAttributeClass].(uint)

			switch {
			case class1 == pkcs11.CKO_PRIVATE_KEY && class2 == pkcs11.CKO_PUBLIC_KEY:
				ret = append(ret, &publicPrivateKeyPair{
					key: key{KeyAttributes: mergeUsage(attrs1, attrs2)},
					prv: obj1, pub: obj2,
				})
			case class2 == pkcs11.CKO_PRIVATE_KEY && class1 == pkcs11.CKO_PUBLIC_KEY:
				ret = append(ret, &publicPrivateKeyPair{
					key: key{KeyAttributes: mergeUsage(attrs2, attrs1)},
					prv: obj2, pub: obj1,
				})
			default:
				appendStandalone(attrs1, obj1, class1)
				appendStandalone(attrs2, obj2, class2)
			}
		default:
			// Treat each key as standalone.
			for _, i := range indices {
				appendStandalone(attrs[i], objs[i], attrs[i].ProviderSpecific[KeyAttributeClass].(uint))
			}
		}
	}

	return ret, nil
}

// mergeUsage merges public key usage attributes with private key usage
// attributes for compound public/private keys.
func mergeUsage(prv, pub *kms.KeyAttributes) *kms.KeyAttributes {
	prv.CanEncrypt = prv.CanEncrypt || pub.CanEncrypt
	prv.CanDecrypt = prv.CanDecrypt || pub.CanDecrypt

	prv.CanSign = prv.CanSign || pub.CanSign
	prv.CanVerify = prv.CanVerify || pub.CanVerify

	prv.CanWrap = prv.CanWrap || pub.CanWrap
	prv.CanUnwrap = prv.CanUnwrap || pub.CanUnwrap

	prv.CanDerive = prv.CanDerive || pub.CanDerive

	return prv
}

// findKeys performs the common
//
//	[findObjects] -> [getKeyAttributes] -> [mergeIntoKeys]
//
// flow used by high-level key store operations.
func findKeys(c *pkcs11.Ctx, sh pkcs11.SessionHandle, template []*pkcs11.Attribute, limit int) ([]kms.Key, error) {
	objs, err := findObjects(c, sh, nil, 0)
	if err != nil {
		return nil, err
	}

	var attrs []*kms.KeyAttributes
	for _, obj := range objs {
		a, err := getKeyAttributes(c, sh, obj)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, a)
	}

	return mergeIntoKeys(attrs, objs)
}

// findOneKey finds exactly one key matching a template.
// It errors if no keys were found, or if more than one key was found.
func findOneKey(c *pkcs11.Ctx, sh pkcs11.SessionHandle, template []*pkcs11.Attribute) (kms.Key, error) {
	// A limit of 3 objects leaves room to merge public/private key pairs
	// together. If the HSM holds a key pair with equal identifiers, we'd
	// preferably return the private key or full key pair here, not just the
	// public key (which may be the 1st object we find).
	keys, err := findKeys(c, sh, template, 3)

	if len(keys) < 1 {
		return nil, ErrKeyNotFound
	}

	// Potential key pairs are already merge here, unless they were
	// ambiguous (more than 2 key halves for the same identifiers).
	if len(keys) > 1 {
		return nil, ErrKeyNotUnique
	}

	return keys[0], err
}

// classAndKeytypeToKms maps the CKA_CLASS and CKA_KEY_TYPE of a key object to
// the corresponding [kms.KeyType].
func classAndKeytypeToKms(class, keytype uint) (kms.KeyType, error) {
	switch class {
	case pkcs11.CKO_SECRET_KEY:
		switch keytype {
		case pkcs11.CKK_AES:
			return kms.KeyType_AES, nil
		default:
			return 0, fmt.Errorf("unsupported key type: %d", keytype)
		}

	case pkcs11.CKO_PRIVATE_KEY:
		switch keytype {
		case pkcs11.CKK_RSA:
			return kms.KeyType_RSA_Private, nil
		case pkcs11.CKK_EC:
			return kms.KeyType_EC_Private, nil
		default:
			return 0, fmt.Errorf("unsupported key type: %d", keytype)
		}

	case pkcs11.CKO_PUBLIC_KEY:
		switch keytype {
		case pkcs11.CKK_RSA:
			return kms.KeyType_RSA_Public, nil
		case pkcs11.CKK_EC:
			return kms.KeyType_EC_Public, nil
		default:
			return 0, fmt.Errorf("unsupported key type: %d", keytype)
		}

	default:
		return 0, fmt.Errorf("unsupported object class: %d", class)
	}
}

// curveFromOID determines a [kms.Curve] by interpreting bytes as an ASN-1
// encoded OID.
func curveFromOID(val []byte) (kms.Curve, error) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(val, &oid)
	switch {
	case err != nil:
		return kms.Curve_None, err
	case len(rest) != 0:
		return kms.Curve_None, errors.New("unexpected data remaining after asn1 unmarshal")
	}

	for _, curve := range []kms.Curve{kms.Curve_P256, kms.Curve_P384, kms.Curve_P521} {
		if oid.Equal(curve.OID()) {
			return curve, nil
		}
	}

	return kms.Curve_None, nil
}

// curveFromLiteral determines a [kms.Curve] by interpreting bytes as a string.
// Some vendors (e.g. Utimaco, CryptoServer 5) store ASCII strings rather than
// OIDs in EC_PARAMS. Not part of the standard, but not hard to support.
func curveFromLiteral(val []byte) kms.Curve {
	switch {
	case bytes.Equal(val, []byte("secp256r1")):
		return kms.Curve_P256
	case bytes.Equal(val, []byte("secp384r1")):
		return kms.Curve_P384
	case bytes.Equal(val, []byte("secp521r1")):
		return kms.Curve_P521
	default:
		return kms.Curve_None
	}
}

// bytesToUint converts a byte slice to uint.
func bytesToUint(value []byte) (uint, error) {
	switch len(value) {
	case 1:
		return uint(value[0]), nil
	case 2:
		return uint(binary.NativeEndian.Uint16(value)), nil
	case 4:
		return uint(binary.NativeEndian.Uint32(value)), nil
	case 8:
		u64 := binary.NativeEndian.Uint64(value)
		if u64 > math.MaxUint {
			return 0, errors.New("value exceeds max uint")
		}
		return uint(u64), nil
	default:
		return 0, fmt.Errorf("cannot convert byte slice of length %d to uint", len(value))
	}
}
