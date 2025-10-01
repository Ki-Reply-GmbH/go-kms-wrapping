// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package keybuilder provides helpers for test key material generation.
package keybuilder

import (
	"encoding/asn1"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// SecretBuilder is a builder for secret keys.
type SecretBuilder struct {
	mech *pkcs11.Mechanism
	temp map[uint]any
}

// PairBuilder is a builder for key pairs.
type PairBuilder struct {
	mech     *pkcs11.Mechanism
	pub, prv map[uint]any
}

// Secret initializes a SecretBuilder.
func Secret(mech uint) *SecretBuilder {
	return &SecretBuilder{
		mech: pkcs11.NewMechanism(mech, nil),
		temp: make(map[uint]any),
	}
}

// Pair initializes a PairBuilder.
func Pair(mech uint) *PairBuilder {
	return &PairBuilder{
		mech: pkcs11.NewMechanism(mech, nil),
		pub:  make(map[uint]any),
		prv:  make(map[uint]any),
	}
}

// Attribute adds an attribute.
func (b *SecretBuilder) Attribute(typ uint, x any) *SecretBuilder {
	b.temp[typ] = x
	return b
}

// PublicAttribute adds an attribute to the public key half.
func (b *PairBuilder) PublicAttribute(typ uint, x any) *PairBuilder {
	b.pub[typ] = x
	return b
}

// PrivateAttribute adds an attribute to the private key half.
func (b *PairBuilder) PrivateAttribute(typ uint, x any) *PairBuilder {
	b.prv[typ] = x
	return b
}

// ID sets CKA_ID.
func (b *SecretBuilder) ID(id string) *SecretBuilder {
	b.temp[pkcs11.CKA_ID] = id
	return b
}

// Label sets CKA_LABEL.
func (b *SecretBuilder) Label(label string) *SecretBuilder {
	b.temp[pkcs11.CKA_LABEL] = label
	return b
}

// ID sets CKA_ID on both key parts.
func (b *PairBuilder) ID(id string) *PairBuilder {
	b.pub[pkcs11.CKA_ID] = id
	b.prv[pkcs11.CKA_ID] = id
	return b
}

// Label sets CKA_LABEL on both key parts.
func (b *PairBuilder) Label(label string) *PairBuilder {
	b.pub[pkcs11.CKA_LABEL] = label
	b.prv[pkcs11.CKA_LABEL] = label
	return b
}

// AES initializes a SecretBuilder with AES key defaults.
func AES(size int) *SecretBuilder {
	return Secret(pkcs11.CKM_AES_KEY_GEN).
		Attribute(pkcs11.CKA_VALUE_LEN, size)
}

// RSA initializes a PairBuilder with RSA key pair defaults.
func RSA(bits int) *PairBuilder {
	return Pair(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN).
		PublicAttribute(pkcs11.CKA_MODULUS_BITS, bits)
}

// EC initializes a PairBuilder with EC key pair defaults.
func EC(curve kms.Curve) *PairBuilder {
	b, err := asn1.Marshal(curve.OID())
	if err != nil {
		panic(fmt.Errorf("OID should marshal: %w", err))
	}

	return Pair(pkcs11.CKM_EC_KEY_PAIR_GEN).
		PublicAttribute(pkcs11.CKA_EC_PARAMS, b)
}

// Generate generates the key and returns its object handle.
func (b *SecretBuilder) Generate(s *session.Handle) (pkcs11.ObjectHandle, error) {
	var temp []*pkcs11.Attribute
	for typ, x := range b.temp {
		temp = append(temp, pkcs11.NewAttribute(typ, x))
	}

	return s.GenerateKey(b.mech, temp)
}

// Generate generates the key and returns the (public, private) object handles.
func (b *PairBuilder) Generate(s *session.Handle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	var pub, prv []*pkcs11.Attribute
	for typ, x := range b.pub {
		pub = append(pub, pkcs11.NewAttribute(typ, x))
	}
	for typ, x := range b.prv {
		prv = append(prv, pkcs11.NewAttribute(typ, x))
	}

	return s.GenerateKeyPair(b.mech, pub, prv)
}
