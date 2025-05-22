// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"crypto"
	"fmt"
	"strconv"
	"strings"
)

type Mechanism int

const (
	MechanismUnspecified Mechanism = iota
	MechanismAesGcm
	MechanismRsaOaep
)

const (
	DefaultRsaOaepHashMechanism = crypto.SHA256
)

type Key struct {
	id    string
	label string
}

func NewKey(id, label string) Key {
	// Remove the 0x prefix.
	if strings.HasPrefix(id, "0x") {
		id = id[2:]
	}

	return Key{id: id, label: label}
}

func (k Key) String() string {
	return fmt.Sprintf("%s:%s", k.label, k.id)
}

func (k Key) Bytes() ([]byte, []byte) {
	// Ensure that empty strings convert to nil, not a zero-length byte slice.
	var idBytes, labelBytes []byte
	if k.id != "" {
		idBytes = []byte(k.id)
	}
	if k.label != "" {
		labelBytes = []byte(k.label)
	}
	return idBytes, labelBytes
}

func MechanismFromString(mech string) (Mechanism, error) {
	switch mech {
	case "":
		return MechanismUnspecified, nil
	case "CKM_AES_GCM", "AES_GCM":
		return MechanismAesGcm, nil
	case "CKM_RSA_PKCS_OAEP", "RSA_PKCS_OAEP":
		return MechanismRsaOaep, nil
	// Deprecated mechanisms
	case "CKM_RSA_PKCS", "RSA_PKCS", "CKM_AES_CBC_PAD", "AES_CBC_PAD":
		return 0, fmt.Errorf("deprecated mechanism: %s", mech)
	default:
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

func (m Mechanism) String() string {
	switch m {
	case MechanismUnspecified:
		return "unspecified"
	case MechanismAesGcm:
		return "CKM_AES_GCM"
	case MechanismRsaOaep:
		return "CKM_RSA_PKCS_OAEP"
	default:
		// Unreachable, we either construct m via MechanismFromString _or_
		// it is the default value (zero), which yields MechanismUnspecified.
		panic(fmt.Errorf("internal error: invalid mechanism %d", m))
	}
}

func RsaOaepHashMechanismFromString(mech string) (crypto.Hash, error) {
	mech = strings.ToLower(mech)
	switch mech {
	case "sha1":
		return crypto.SHA1, nil
	case "sha224":
		return crypto.SHA224, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported mechanism: %s", mech)
	}
}

func numberAutoParse(value string, bitSize int) (uint64, error) {
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "0x") {
		return strconv.ParseUint(value[2:], 16, bitSize)
	} else {
		return strconv.ParseUint(value, 10, bitSize)
	}
}
