// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/api/v2"
)

const (
	EnvLib                = "BAO_HSM_LIB"
	EnvSlot               = "BAO_HSM_SLOT"
	EnvTokenLabel         = "BAO_HSM_TOKEN_LABEL"
	EnvPin                = "BAO_HSM_PIN"
	EnvMaxParallel        = "BAO_HSM_MAX_PARALLEL"
	EnvKeyId              = "BAO_HSM_KEY_ID"
	EnvKeyLabel           = "BAO_HSM_KEY_LABEL"
	EnvMechanism          = "BAO_HSM_MECHANISM"
	EnvRsaOaepHash        = "BAO_HSM_RSA_OAEP_HASH"
	EnvSoftwareEncryption = "BAO_HSM_SOFTWARE_ENCRYPTION"
)

func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global.
	var wrappingOptions []wrapping.Option
	var localOptions []OptionFunc

	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case wrapping.OptionFunc:
			wrappingOptions = append(wrappingOptions, o)
		case OptionFunc:
			localOptions = append(localOptions, to)
		}
	}

	var opts options

	// Parse the global options.
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options.
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field (for
	// over the plugin barrier or embedding) or via local option functions (for
	// embedding). First pull from the config map.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "lib":
				opts.withLib = v
			case "pin":
				opts.withPin = v
			case "slot":
				opts.withSlot = v
			case "token_label":
				opts.withTokenLabel = v
			case "key_id":
				opts.withKeyId = v
			case "key_label":
				opts.withKeyLabel = v
			case "mechanism":
				opts.withMechanism = v
			case "rsa_oaep_hash":
				opts.withRsaOaepHash = v
			case "disable_software_encryption":
				opts.withDisableSoftwareEncryption = v
			}
		}
	}

	// Now run the local options functions. This may overwrite options set by
	// the options above.
	for _, o := range localOptions {
		if o != nil {
			if err := o(&opts); err != nil {
				return nil, err
			}
		}
	}

	if err := wrapping.ParsePaths(&opts.withPin); err != nil {
		return nil, err
	}

	return &opts, nil
}

func mergeOptionsWithEnv(opts *options) {
	if env := api.ReadBaoVariable(EnvLib); env != "" {
		opts.withLib = env
	}
	if env := api.ReadBaoVariable(EnvPin); env != "" {
		opts.withPin = env
	}
	if env := api.ReadBaoVariable(EnvSlot); env != "" {
		opts.withSlot = env
	}
	if env := api.ReadBaoVariable(EnvTokenLabel); env != "" {
		opts.withTokenLabel = env
	}
	if env := api.ReadBaoVariable(EnvKeyId); env != "" {
		opts.withKeyId = env
	}
	if env := api.ReadBaoVariable(EnvKeyLabel); env != "" {
		opts.withKeyLabel = env
	}
	if env := api.ReadBaoVariable(EnvMechanism); env != "" {
		opts.withMechanism = env
	}
	if env := api.ReadBaoVariable(EnvRsaOaepHash); env != "" {
		opts.withRsaOaepHash = env
	}
	if env := api.ReadBaoVariable(EnvSoftwareEncryption); env != "" {
		opts.withDisableSoftwareEncryption = env
	}
}

// OptionFunc holds a function  local options.
type OptionFunc func(*options) error

// options are local options.
type options struct {
	*wrapping.Options

	// Provider-specific:
	withLib        string
	withPin        string
	withSlot       string
	withTokenLabel string

	// Key-specific:
	withKeyId    string
	withKeyLabel string

	// Mechanism-specific:
	withMechanism                 string
	withRsaOaepHash               string
	withDisableSoftwareEncryption string
}

// WithSlot sets the token slot number.
func WithSlot(slot string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withSlot = slot
			return nil
		})
	}
}

// WithSlot sets the token label.
func WithTokenLabel(slot string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withTokenLabel = slot
			return nil
		})
	}
}

// WithPin sets the pin.
func WithPin(pin string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withPin = pin
			return nil
		})
	}
}

// WithLib sets the dynamic library path.
func WithLib(lib string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withLib = lib
			return nil
		})
	}
}

// WithLabel sets the key ID (CKA_ID).
func WithKeyId(keyId string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withKeyId = keyId
			return nil
		})
	}
}

// WithLabel sets the key label (CKA_LABEL).
func WithKeyLabel(label string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withKeyLabel = label
			return nil
		})
	}
}

// WithMechanism sets the mechanism (CKM_X).
func WithMechanism(mechanism string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withMechanism = mechanism
			return nil
		})
	}
}

// WithRsaOaepHash sets the RSA-OAEP hash mechanism.
func WithRsaOaepHash(hashMechanisme string) wrapping.Option {
	return func() any {
		return OptionFunc(func(o *options) error {
			o.withRsaOaepHash = hashMechanisme
			return nil
		})
	}
}
