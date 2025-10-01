// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// IdAttr is CKA_ID. This attribute may be passed to GetKeyByAttrs as
	// []byte or string. It is always present as []byte in ProviderSpecific key
	// attributes.
	IdAttr = "id"

	// LabelAttr is CKA_LABEL. This attribute may be passed to GetKeyByAttrs as
	// []byte or string. String values that start with "0x" are decoded as Hex.
	// It is always present as []byte in ProviderSpecific key attributes.
	LabelAttr = "label"

	// ClassAttr is CKA_CLASS. This attribute always available as uint in
	// ProviderSpecific attributes.
	ClassAttr = "class"

	// TypeAttr is CKA_KEY_TYPE. This attribute is always available as uint in
	// ProviderSpecific attributes.
	TypeAttr = "type"
)

type key struct {
	pool *session.PoolRef

	CKA_ID, CKA_LABEL       []byte
	CKA_KEY_TYPE, CKA_CLASS uint

	attributes kms.KeyAttributes
}

func (k *key) Resolved() bool                               { return true }
func (k *key) Resolve(ctx context.Context) (kms.Key, error) { return k, nil }

func (k *key) GetId() string      { return k.attributes.KeyId }
func (k *key) GetName() string    { return k.attributes.Name }
func (k *key) GetGroupId() string { return k.attributes.GroupId }

func (k *key) GetLength() uint32    { return k.attributes.BitKeyLen }
func (k *key) GetType() kms.KeyType { return k.attributes.KeyType }

func (k *key) IsSensitive() bool  { return k.attributes.IsSensitive }
func (k *key) IsPersistent() bool { return k.attributes.IsPersistent }

func (k key) GetKeyAttributes() *kms.KeyAttributes {
	// No pointer receiver such that the returned attributes cannot be used to
	// mutate the key's internal attributes.

	k.attributes.ProviderSpecific = map[string]any{
		IdAttr:    k.CKA_ID,
		LabelAttr: k.CKA_LABEL,
		ClassAttr: k.CKA_CLASS,
		TypeAttr:  k.CKA_KEY_TYPE,
	}

	return &k.attributes
}

func (k *key) GetProtectedKeyAttributes() *kms.ProtectedKeyAttributes {
	return &kms.ProtectedKeyAttributes{}
}

func (k *key) IsAsymmetric() bool {
	// This is overridden by specialized implementations.
	return false
}

func (k *key) Close(ctx context.Context) error {
	return nil
}

func (k *key) Login(ctx context.Context, creds *kms.Credentials) error {
	// This would likely map to CKA_ALWAYS_AUTHENTICATE. This is a niche feature
	// that is difficult to implement in terms of session handling, so it is
	// omitted for the time being.
	return errors.New("unimplemented")
}

// secret is a secret key (Supported types: AES).
type secret struct {
	*key
	obj pkcs11.ObjectHandle
}

// public is a public key (Supported types: RSA, EC)
type public struct {
	*key
	obj pkcs11.ObjectHandle

	components crypto.PublicKey
}

// private is a private key (Supported types: RSA, EC).
type private struct {
	*key
	obj pkcs11.ObjectHandle

	components crypto.PublicKey
}

// pair is a key pair (Supported types: RSA, EC).
type pair struct {
	*key
	pub, prv pkcs11.ObjectHandle

	components crypto.PublicKey
}

// errUnknownObject is returned by fromHandle if a non-key object is found or a
// particular key type is not supported yet.
var errUnknownObject = errors.New("unknown object")

// fromHandle constructs a key from an object handle.
// Editor's note: long and boring function that just queries ALL the attributes.
func fromHandle(s *session.Handle, p *session.PoolRef, obj pkcs11.ObjectHandle) (kms.Key, error) {
	// These are generic attributes that can always be queried. Specialized
	// attributes are retrieved in follow-up queries below.
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, 0),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, 0),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, 0),
	}

	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	var k key
	k.pool = p

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_ID:
			k.CKA_ID = attr.Value
		case pkcs11.CKA_LABEL:
			k.CKA_LABEL = attr.Value
		case pkcs11.CKA_CLASS:
			k.CKA_CLASS, err = bytesToUint(attr.Value)
		}

		if err != nil {
			return nil, err
		}
	}

	// Next, query boolean flags based on key class.
	temp = []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_TOKEN, 0)}

	switch k.CKA_CLASS {
	case pkcs11.CKO_SECRET_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
		)
	case pkcs11.CKO_PRIVATE_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, 0),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, 0),
		)
	case pkcs11.CKO_PUBLIC_KEY:
		temp = append(temp,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, 0),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, 0),
		)
		// Public keys objects cannot be queried for CKA_EXTRACTABLE, assume true.
		k.attributes.IsExportable = true
	default:
		return nil, errUnknownObject
	}

	attrs, err = s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		var val uint
		val, err = bytesToUint(attr.Value)
		if err != nil {
			return nil, err
		}

		if val != 1 {
			continue
		}

		switch attr.Type {
		case pkcs11.CKA_TOKEN:
			k.attributes.IsPersistent = true
		case pkcs11.CKA_SENSITIVE:
			k.attributes.IsSensitive = true
		case pkcs11.CKA_EXTRACTABLE:
			k.attributes.IsExportable = true
		case pkcs11.CKA_ENCRYPT:
			k.attributes.CanEncrypt = true
		case pkcs11.CKA_DECRYPT:
			k.attributes.CanDecrypt = true
		case pkcs11.CKA_SIGN:
			k.attributes.CanSign = true
		case pkcs11.CKA_VERIFY:
			k.attributes.CanVerify = true
		}
	}

	// Next, query the key type. This cannot be part of the initial query
	// alongside CKA_CLASS as non-key objects (e.g., certificates) do not
	// support this attribute.
	temp = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}

	attrs, err = s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	for _, attr := range attrs {
		switch attr.Type {
		case pkcs11.CKA_KEY_TYPE:
			k.CKA_KEY_TYPE, err = bytesToUint(attr.Value)
		}
	}

	if err != nil {
		return nil, err
	}

	var ret kms.Key
	switch k.CKA_KEY_TYPE {
	case pkcs11.CKK_AES:
		ret, err = newAES(s, &k, obj)
	case pkcs11.CKK_RSA:
		ret, err = newRSA(s, &k, obj)
	case pkcs11.CKK_EC:
		ret, err = newEC(s, &k, obj)
	default:
		err = errUnknownObject
	}

	return ret, err
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

// newAES constructs an AES kms.Key.
func newAES(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, nil)}

	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	if len(attrs) != len(temp) {
		return nil, fmt.Errorf("expected %d attributes, got %d", len(temp), len(attrs))
	}

	val, err := bytesToUint(attrs[0].Value)
	if err != nil {
		return nil, err
	}

	if val != pkcs11.CK_UNAVAILABLE_INFORMATION {
		// CKA_VALUE_LEN is byte size, not bit size.
		base.attributes.BitKeyLen = uint32(val) * 8
	}

	switch base.CKA_CLASS {
	case pkcs11.CKO_SECRET_KEY:
		base.attributes.KeyType = kms.KeyType_AES
		return &secret{key: base, obj: obj}, nil
	default:
		return nil, fmt.Errorf("class %d cannot represent an AES key", base.CKA_CLASS)
	}
}

// newRSA constructs an RSA kms.Key.
func newRSA(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
	}

	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	if len(attrs) != len(temp) {
		return nil, fmt.Errorf("expected %d attributes, got %d", len(temp), len(attrs))
	}

	n := new(big.Int).SetBytes(attrs[0].Value)
	e := new(big.Int).SetBytes(attrs[1].Value)

	// Sanity checks
	switch {
	case n.Cmp(big.NewInt(1)) != 1:
		err = errors.New("modulus is less than one")
	case e.Cmp(big.NewInt(1)) != 1:
		err = errors.New("exponent is less than one")
	case n.Cmp(e) != 1:
		err = errors.New("modulus is not greater than exponent")
	case e.BitLen() > 32:
		err = errors.New("exponent is longer than 32 bits")
	case n.BitLen() < 2048:
		err = errors.New("modulus is shorter than 2048 bits")
	}

	if err != nil {
		return nil, fmt.Errorf("malformed rsa public key: %w", err)
	}

	components := &rsa.PublicKey{N: n, E: int(e.Int64())}
	base.attributes.BitKeyLen = uint32(n.BitLen())

	switch base.CKA_CLASS {
	case pkcs11.CKO_PUBLIC_KEY:
		base.attributes.KeyType = kms.KeyType_RSA_Public
		return &public{key: base, obj: obj, components: components}, nil
	case pkcs11.CKO_PRIVATE_KEY:
		base.attributes.KeyType = kms.KeyType_RSA_Private
		return &private{key: base, obj: obj, components: components}, nil
	default:
		return nil, fmt.Errorf("class %d cannot represent an RSA key", base.CKA_CLASS)
	}
}

// newEC constructs an EC kms.Key.
func newEC(s *session.Handle, base *key, obj pkcs11.ObjectHandle) (kms.Key, error) {
	temp := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil)}
	if base.CKA_CLASS == pkcs11.CKO_PUBLIC_KEY {
		// CKA_EC_POINT is not available on private key objects. This is depressing.
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil))
	}

	attrs, err := s.GetAttributeValue(obj, temp)
	if err != nil {
		return nil, err
	}

	if len(attrs) != len(temp) {
		return nil, fmt.Errorf("expected %d attributes, got %d", len(temp), len(attrs))
	}

	curve, err := curveFromOID(attrs[0].Value)
	if err != nil {
		// Give this one more try as a string.
		curve = curveFromLiteral(attrs[0].Value)
		if curve == kms.Curve_None {
			return nil, err
		}
	}

	base.attributes.Curve = curve
	base.attributes.BitKeyLen = curve.Len()

	switch base.CKA_CLASS {
	case pkcs11.CKO_PUBLIC_KEY:
		// Continue and export the public key.
		base.attributes.KeyType = kms.KeyType_EC_Public
	case pkcs11.CKO_PRIVATE_KEY:
		base.attributes.KeyType = kms.KeyType_EC_Private
		// We cannot export the public key yet as CKA_EC_POINT is unavailable.
		return &private{key: base, obj: obj}, nil
	default:
		return nil, fmt.Errorf("class %d cannot represent an EC key", base.CKA_CLASS)
	}

	var stdCurve elliptic.Curve
	switch curve {
	case kms.Curve_P256:
		stdCurve = elliptic.P256()
	case kms.Curve_P384:
		stdCurve = elliptic.P384()
	case kms.Curve_P521:
		stdCurve = elliptic.P521()
	default:
		panic("unreachable")
	}

	var point []byte
	rest, err := asn1.Unmarshal(attrs[1].Value, &point)
	switch {
	case err != nil:
		return nil, err
	case len(rest) != 0:
		return nil, errors.New("unexpected data remaining after asn1 unmarshal")
	}

	components, err := ecdsa.ParseUncompressedPublicKey(stdCurve, point)
	if err != nil {
		return nil, err
	}

	return &public{key: base, obj: obj, components: components}, nil
}

// curveFromOID determines a kms.Curve by interpreting bytes as an ASN.1 encoded OID.
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

	return kms.Curve_None, errors.New("unsupported/unknown curve")
}

// curveFromLiteral determines a kms.Curve by interpreting bytes as a string.
// Some vendors store named curves as ASCII strings instead of OIDs.
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

// pairFromHandles creates a key pair from two object handles. This is primarily
// useful in tests that generate the key pair itself and want the respective
// combined key representation.
func pairFromHandles(s *session.Handle, p *session.PoolRef, pubobj, prvobj pkcs11.ObjectHandle) (kms.Key, error) {
	k, err := fromHandle(s, p, pubobj)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*public)
	if !ok {
		return nil, errors.New("not a public key")
	}

	k, err = fromHandle(s, p, prvobj)
	if err != nil {
		return nil, err
	}
	prv, ok := k.(*private)
	if !ok {
		return nil, errors.New("not a private key")
	}

	return toPair(pub, prv)
}

// halvesMatch returns true if a public and private key match.
func halvesMatch(pub *public, prv *private) bool {
	if prv.CKA_KEY_TYPE == pkcs11.CKK_EC {
		// Special case: We can only compare the curve as
		// EC private keys do not carry CKA_EC_POINT.
		return prv.attributes.Curve == pub.attributes.Curve
	}

	type equaler interface{ Equal(x crypto.PublicKey) bool }
	return pub.components.(equaler).Equal(prv.components)
}

// toPair merges key halves into one key pair.
func toPair(pub *public, prv *private) (*pair, error) {
	if !halvesMatch(pub, prv) {
		return nil, errors.New("key halves to not match")
	}

	prv.attributes.CanVerify = pub.attributes.CanVerify
	prv.attributes.CanEncrypt = pub.attributes.CanEncrypt

	return &pair{
		key: prv.key,
		pub: pub.obj, prv: prv.obj,
		components: pub.components, // pub.components is guaranteed to be set.
	}, nil
}

func (kp *pair) IsAsymmetric() bool    { return true }
func (pk *public) IsAsymmetric() bool  { return true }
func (pk *private) IsAsymmetric() bool { return true }

func (kp *pair) GetPublic(ctx context.Context) (kms.Key, error) {
	return kp, nil
}

func (pk *public) GetPublic(ctx context.Context) (kms.Key, error) {
	return pk, nil
}

func (pk *private) GetPublic(ctx context.Context) (kms.Key, error) {
	temp := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pk.CKA_KEY_TYPE),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	if len(pk.CKA_ID) > 0 {
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_ID, pk.CKA_ID))
	}
	if len(pk.CKA_LABEL) > 0 {
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_LABEL, pk.CKA_LABEL))
	}

	pub, err := session.Scope(ctx, pk.pool, func(s *session.Handle) (kms.Key, error) {
		return findUniqueKey(s, pk.pool, temp)
	})

	if err != nil {
		return nil, err
	}

	return pub, nil
}

func (kp *pair) ExportPublic(ctx context.Context) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(kp.components)
}

func (pk *public) ExportPublic(ctx context.Context) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pk.components)
}

func (pk *private) ExportPublic(ctx context.Context) ([]byte, error) {
	// EC private key special case:
	components, err := pk.ExportComponentPublic(ctx)
	if err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(components)
}

func (kp *pair) ExportComponentPublic(ctx context.Context) (crypto.PublicKey, error) {
	return kp.components, nil
}

func (pk *public) ExportComponentPublic(ctx context.Context) (ret crypto.PublicKey, err error) {
	return pk.components, nil
}

func (pk *private) ExportComponentPublic(ctx context.Context) (crypto.PublicKey, error) {
	// EC private key special case:
	if pk.attributes.KeyType == kms.KeyType_EC_Private {
		pub, err := pk.GetPublic(ctx)
		if err != nil {
			return nil, err
		}
		asym, ok := pub.(kms.AsymmetricKey)
		if !ok {
			return nil, errors.New("public key is not a kms.AsymmetricKey")
		}
		return asym.ExportComponentPublic(ctx)
	}

	return pk.components, nil
}
