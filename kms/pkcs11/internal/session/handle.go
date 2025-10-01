// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package session

import (
	"errors"
	"sync/atomic"

	"github.com/miekg/pkcs11"
)

// Handle wraps a PKCS#11 session handle. It provides convenience methods to
// perform operations using the underlying handle.
type Handle struct {
	pool    *pool
	session pkcs11.SessionHandle

	_      noCopy
	closed atomic.Bool
}

// Close calls CloseSession and frees pool capacity.
func (h *Handle) Close() error {
	if !h.closed.CompareAndSwap(false, true) {
		return errors.New("session is already closed")
	}

	err := mapErr(h.pool.mod.CloseSession(h.session), "CloseSession")

	// Free capacity no matter what, there's little reason to hold this up in
	// the event of CloseSession failing.
	h.pool.free()

	return err
}

// Below methods are somewhat spammy, but they prove their worth higher up the
// stack by simplifying error handling & context management.

// GenerateRandom wraps C_GenerateRandom.
func (h *Handle) GenerateRandom(length int) ([]byte, error) {
	output, err := h.pool.mod.GenerateRandom(h.session, length)
	return output, mapErr(err, "GenerateRandom")
}

// GetAttributeValue wraps C_GetAttributeValue.
func (h *Handle) GetAttributeValue(o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	attrs, err := h.pool.mod.GetAttributeValue(h.session, o, a)
	return attrs, mapErr(err, "GetAttributeValue")
}

// FindObjectsInit wraps C_FindObjectsInit.
func (h *Handle) FindObjectsInit(temp []*pkcs11.Attribute) error {
	return mapErr(h.pool.mod.FindObjectsInit(h.session, temp), "FindObjectsInit")
}

// FindObjects wraps C_FindObjects.
func (h *Handle) FindObjects(max int) ([]pkcs11.ObjectHandle, error) {
	objs, _, err := h.pool.mod.FindObjects(h.session, max)
	return objs, mapErr(err, "FindObjects")
}

// FindObjectsFinal wraps C_FindObjectsFinal.
func (h *Handle) FindObjectsFinal() error {
	return mapErr(h.pool.mod.FindObjectsFinal(h.session), "FindObjectsFinal")
}

// EncryptInit wraps C_EncryptInit.
func (h *Handle) EncryptInit(m *pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mapErr(h.pool.mod.EncryptInit(h.session, []*pkcs11.Mechanism{m}, o), "EncryptInit")
}

// Encrypt wraps C_Encrypt.
func (h *Handle) Encrypt(data []byte) ([]byte, error) {
	output, err := h.pool.mod.Encrypt(h.session, data)
	return output, mapErr(err, "Encrypt")
}

// EncryptUpdate wraps C_EncryptUpdate.
func (h *Handle) EncryptUpdate(data []byte) ([]byte, error) {
	output, err := h.pool.mod.EncryptUpdate(h.session, data)
	return output, mapErr(err, "EncryptUpdate")
}

// EncryptFinal wraps C_EncryptFinal.
func (h *Handle) EncryptFinal() ([]byte, error) {
	output, err := h.pool.mod.EncryptFinal(h.session)
	return output, mapErr(err, "EncryptFinal")
}

// DecryptInit wraps C_DecryptInit.
func (h *Handle) DecryptInit(m *pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mapErr(h.pool.mod.DecryptInit(h.session, []*pkcs11.Mechanism{m}, o), "DecryptInit")
}

// Decrypt wraps C_Decrypt.
func (h *Handle) Decrypt(data []byte) ([]byte, error) {
	output, err := h.pool.mod.Decrypt(h.session, data)
	return output, mapErr(err, "Decrypt")
}

// DecryptUpdate wraps C_DecryptUpdate.
func (h *Handle) DecryptUpdate(data []byte) ([]byte, error) {
	output, err := h.pool.mod.DecryptUpdate(h.session, data)
	return output, mapErr(err, "DecryptUpdate")
}

// DecryptFinal wraps C_DecryptFinal.
func (h *Handle) DecryptFinal() ([]byte, error) {
	output, err := h.pool.mod.DecryptFinal(h.session)
	return output, mapErr(err, "DecryptFinal")
}

// SignInit wraps C_SignInit.
func (h *Handle) SignInit(m *pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mapErr(h.pool.mod.SignInit(h.session, []*pkcs11.Mechanism{m}, o), "SignInit")
}

// Sign wraps C_Sign.
func (h *Handle) Sign(data []byte) ([]byte, error) {
	signature, err := h.pool.mod.Sign(h.session, data)
	return signature, mapErr(err, "Sign")
}

// VerifyInit wraps C_VerifyInit.
func (h *Handle) VerifyInit(m *pkcs11.Mechanism, o pkcs11.ObjectHandle) error {
	return mapErr(h.pool.mod.VerifyInit(h.session, []*pkcs11.Mechanism{m}, o), "VerifyInit")
}

// Verify wraps C_Verify.
func (h *Handle) Verify(data, signature []byte) error {
	return mapErr(h.pool.mod.Verify(h.session, data, signature), "Verify")
}

// GenerateKey wraps C_GenerateKey.
func (h *Handle) GenerateKey(m *pkcs11.Mechanism, temp []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	o, err := h.pool.mod.GenerateKey(h.session, []*pkcs11.Mechanism{m}, temp)
	return o, mapErr(err, "GenerateKey")
}

// GenerateKeyPair wraps C_GenerateKeyPair.
func (h *Handle) GenerateKeyPair(m *pkcs11.Mechanism, public, private []*pkcs11.Attribute) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	opub, oprv, err := h.pool.mod.GenerateKeyPair(h.session, []*pkcs11.Mechanism{m}, public, private)
	return opub, oprv, mapErr(err, "GenerateKeyPair")
}
