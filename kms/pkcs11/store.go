// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/pkcs11"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/module"
	"github.com/openbao/go-kms-wrapping/kms/pkcs11/v2/internal/session"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

const (
	// KeyStoreParamLib sets the path to the PKCS#11 library. It is always
	// passed as type string.
	KeyStoreParamLib = "lib"

	// KeyStoreParamSlot sets the PKCS#11 token slot ID. It can be passed as
	// type uint, uint32 or string. String values that start with "0x" are
	// decoded as Hex.
	KeyStoreParamSlot = "slot"

	// KeyStoreParamLabel sets the PKCS#11 token label. It can be passed as
	// string or []byte.
	KeyStoreParamLabel = "token_label"
)

type store struct {
	// These are set in NewKeyStore(...)
	mod   *module.Ref
	token *module.Token

	// This is set in Login(...)
	pool *session.PoolRef
}

// NewKeyStore returns a kms.KeyStore backed by PKCS#11.
func NewKeyStore(params map[string]any) (kms.KeyStore, error) {
	var lib string
	switch v := params[KeyStoreParamLib].(type) {
	case string:
		lib = v
	case nil:
		return nil, fmt.Errorf("param %q is required", KeyStoreParamLib)
	default:
		return nil, fmt.Errorf("param %q cannot be passed as %T", KeyStoreParamLib, v)
	}

	var selectors []module.TokenSelector

	switch v := params[KeyStoreParamSlot].(type) {
	case nil: // This parameter is optional.
	case string:
		var tmp uint64
		var err error
		if strings.HasPrefix(v, "0x") {
			tmp, err = strconv.ParseUint(v[2:], 16, 32)
		} else {
			tmp, err = strconv.ParseUint(v, 10, 32)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q value: %w", KeyStoreParamSlot, err)
		}
		selectors = append(selectors, module.SelectID(uint(tmp)))
	case uint32:
		selectors = append(selectors, module.SelectID(uint(v)))
	case uint:
		selectors = append(selectors, module.SelectID(v))
	default:
		return nil, fmt.Errorf("param %q cannot be passed as %T", KeyStoreParamSlot, v)
	}

	switch v := params[KeyStoreParamLabel].(type) {
	case nil: // This parameter is optional.
	case string:
		selectors = append(selectors, module.SelectLabel(v))
	case []byte:
		selectors = append(selectors, module.SelectLabel(string(v)))
	default:
		return nil, fmt.Errorf("param %q cannot be passed as %T", KeyStoreParamLabel, v)
	}

	if len(selectors) == 0 {
		return nil, fmt.Errorf("at least one of %q, %q is required",
			KeyStoreParamSlot, KeyStoreParamLabel)
	}

	mod, err := module.Open(lib)
	if err != nil {
		return nil, err
	}

	token, err := mod.GetToken(selectors...)
	if err != nil {
		return nil, errors.Join(err, mod.Drop())
	}

	return &store{
		mod: mod, token: token,
	}, nil
}

func (s *store) Login(ctx context.Context, credentials *kms.Credentials) error {
	if s.pool != nil {
		return errors.New("already logged in")
	}

	// An empty PIN is okay: Some PKCS#11 modules never expect a meaningful PIN value.
	var pin string
	if credentials != nil {
		pin = credentials.Password
	}

	switch pool, err := session.Login(s.mod, s.token, pin); err {
	case nil:
		s.pool = pool
	default:
		return err
	}

	return nil
}

func (s *store) Close(ctx context.Context) error {
	if s.pool != nil {
		if err := s.pool.Drop(); err != nil {
			return err
		}
		// Erase the pool for good measure.
		s.pool = nil
	}

	if s.mod != nil {
		if err := s.mod.Drop(); err != nil {
			return err
		}
		// Erase the module and token for good measure. This means one cannot
		// call Login() several times, a new key store must be constructed
		// instead -- probably okay?
		s.mod, s.token = nil, nil
	}

	return nil
}

func (s *store) GetInfo() map[string]string {
	info := make(map[string]string)

	if s.mod != nil {
		info[KeyStoreParamLib] = s.mod.Path()
	}

	if s.token != nil {
		// Popular tools such as pkcs11-tool display the slot as Hex, so this
		// might be more user-friendly:
		info["slot"] = fmt.Sprintf("0x%x", s.token.ID)
		info["token_label"] = s.token.Info.Label

		// These seem useful as additional information:
		info["model"] = s.token.Info.Model
		info["manufacturer"] = s.token.Info.ManufacturerID
		info["firmware_version"] = fmt.Sprintf("%d.%d",
			s.token.Info.FirmwareVersion.Major, s.token.Info.FirmwareVersion.Minor)
		info["hardware_version"] = fmt.Sprintf("%d.%d",
			s.token.Info.HardwareVersion.Major, s.token.Info.HardwareVersion.Minor)
	}

	return info
}

// NOTE: ListKeys will not group key pairs into unified kms.Key instances.
func (s *store) ListKeys(ctx context.Context) (keys []kms.Key, err error) {
	return session.Scope(ctx, s.pool, func(sh *session.Handle) ([]kms.Key, error) {
		return findAllKeys(sh, s.pool, nil)
	})
}

func (s *store) GetKeyById(ctx context.Context, id string) (kms.Key, error) {
	return s.GetKeyByAttrs(ctx, map[string]any{
		IdAttr: id,
	})
}

func (s *store) GetKeyByName(ctx context.Context, name string) (kms.Key, error) {
	return s.GetKeyByAttrs(ctx, map[string]any{
		LabelAttr: name,
	})
}

func (s *store) GetKeyByAttrs(ctx context.Context, attrs map[string]any) (kms.Key, error) {
	var temp []*pkcs11.Attribute

	switch v := cmp.Or(attrs[IdAttr], attrs[kms.IdAttr]).(type) {
	case nil: // Optional
	case string:
		var b []byte
		var err error
		if strings.HasPrefix(v, "0x") {
			b, err = hex.DecodeString(v[2:])
		} else {
			b = []byte(v)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q value: %w", IdAttr, err)
		}
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_ID, b))
	case []byte:
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_ID, v))
	default:
		return nil, fmt.Errorf("attr %q cannot be passed as %T", IdAttr, v)
	}

	switch v := cmp.Or(attrs[LabelAttr], attrs[kms.NameAttr]).(type) {
	case nil: // Optional
	case string, []byte:
		temp = append(temp, pkcs11.NewAttribute(pkcs11.CKA_LABEL, v))
	default:
		return nil, fmt.Errorf("attr %q cannot be passed as %T", LabelAttr, v)
	}

	if len(temp) == 0 {
		return nil, fmt.Errorf("must pass at least one of %q, %q", IdAttr, LabelAttr)
	}

	return session.Scope(ctx, s.pool, func(sh *session.Handle) (kms.Key, error) {
		return findUniqueKey(sh, s.pool, temp)
	})
}

// findAllKeys finds all keys that match temp by continuously calling C_FindObjects.
func findAllKeys(s *session.Handle, p *session.PoolRef, temp []*pkcs11.Attribute) ([]kms.Key, error) {
	if err := s.FindObjectsInit(temp); err != nil {
		return nil, err
	}

	var err error
	var batch, total []pkcs11.ObjectHandle

	for {
		// The batch size here is arbitrary, really.
		batch, err = s.FindObjects(128)
		if err != nil || len(batch) == 0 {
			break
		}
		total = append(total, batch...)
	}

	if err := errors.Join(err, s.FindObjectsFinal()); err != nil {
		return nil, err
	}

	var keys []kms.Key
	for _, obj := range total {
		k, err := fromHandle(s, p, obj)
		switch {
		case errors.Is(err, errUnknownObject):
			continue
		case err != nil:
			return nil, err
		default:
			keys = append(keys, k)
		}
	}

	return keys, nil
}

// findUniqueKey finds a single unique key, grouping public and private key
// instances into one key pair instance if they match. An error is returned
// when multiple, not groupable objects are found.
func findUniqueKey(s *session.Handle, p *session.PoolRef, temp []*pkcs11.Attribute) (kms.Key, error) {
	keys, err := findAllKeys(s, p, temp)
	if err != nil {
		return nil, err
	}

	// Get trivial cases out of the way:
	switch len(keys) {
	case 0:
		return nil, errors.New("key not found")
	case 1:
		return keys[0], nil
	}

	// More than two is always ambiguous:
	if len(keys) > 2 {
		return nil, fmt.Errorf("expected at most 2 key objects, got %d", len(keys))
	}

	complain := func() error {
		return fmt.Errorf("got two key objects that do not make a pair, have %T and %T", keys[0], keys[1])
	}

	switch a := keys[0].(type) {
	case *secret:
		// This can never work.
		return nil, complain()
	case *public:
		switch b := keys[1].(type) {
		// Look for a matching private key.
		case *private:
			return toPair(a, b)
		default:
			return nil, complain()
		}
	case *private:
		switch b := keys[1].(type) {
		// Look for a matching public key.
		case *public:
			return toPair(b, a)
		default:
			return nil, complain()
		}
	default:
		panic("unreachable")
	}
}
