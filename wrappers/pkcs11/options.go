// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/api/v2"
)

const (
	EnvHsmWrapperLib         = "BAO_HSM_LIB"
	EnvHsmWrapperSlot        = "BAO_HSM_SLOT"
	EnvHsmWrapperTokenLabel  = "BAO_HSM_TOKEN_LABEL"
	EnvHsmWrapperPin         = "BAO_HSM_PIN"
	EnvHsmWrapperKeyLabel    = "BAO_HSM_KEY_LABEL"
	EnvHsmWrapperKeyId       = "BAO_HSM_KEY_ID"
	EnvHsmWrapperMechanism   = "BAO_HSM_MECHANISM"
	EnvHsmWrapperRsaOaepHash = "BAO_HSM_RSA_OAEP_HASH"
)

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...wrapping.Option) (*options, error) {
	// First, separate out options into local and global
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

	// Parse the global options
	var opts options
	var err error
	opts.Options, err = wrapping.GetOpts(wrappingOptions...)
	if err != nil {
		return nil, err
	}

	// Don't ever return blank options
	if opts.Options == nil {
		opts.Options = new(wrapping.Options)
	}

	// Local options can be provided either via the WithConfigMap field
	// (for over the plugin barrier or embedding) or via local option functions
	// (for embedding). First pull from the option.
	if opts.WithConfigMap != nil {
		for k, v := range opts.WithConfigMap {
			switch k {
			case "key_id":
				opts.withKeyId = v
			case "slot":
				opts.withSlot = v
			case "pin":
				opts.withPin = v
			case "lib", "module":
				opts.withLib = v
			case "token", "token_label":
				opts.withTokenLabel = v
			case "label", "key_label":
				opts.withKeyLabel = v
			case "mechanism":
				opts.withMechanism = v
			case "rsa_oaep_hash":
				opts.withRsaOaepHash = v
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

	if !opts.WithDisallowEnvVars {
		mergeWithEnv(&opts)
	}

	return &opts, nil
}

func mergeWithEnv(opts *options) {
	if env := api.ReadBaoVariable(EnvHsmWrapperLib); env != "" {
		opts.withLib = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperSlot); env != "" {
		opts.withSlot = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperTokenLabel); env != "" {
		opts.withTokenLabel = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperPin); env != "" {
		opts.withPin = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperKeyLabel); env != "" {
		opts.withKeyLabel = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperKeyId); env != "" {
		opts.WithKeyId = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperMechanism); env != "" {
		opts.withMechanism = env
	}
	if env := api.ReadBaoVariable(EnvHsmWrapperRsaOaepHash); env != "" {
		opts.withRsaOaepHash = env
	}
}

// OptionFunc holds a function with local options
type OptionFunc func(*options) error

// options = how options are represented
type options struct {
	*wrapping.Options

	withSlot        string
	withPin         string
	withLib         string
	withKeyId       string
	withKeyLabel    string
	withTokenLabel  string
	withMechanism   string
	withRsaOaepHash string
}

// WithSlot sets the slot
func WithSlot(slot string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withSlot = slot
			return nil
		})
	}
}

// WithTokenLabel sets the token label
func WithTokenLabel(slot string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withTokenLabel = slot
			return nil
		})
	}
}

// WithPin sets the pin
func WithPin(pin string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withPin = pin
			return nil
		})
	}
}

// WithLib sets the module (dynamic library)
func WithLib(lib string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withLib = lib
			return nil
		})
	}
}

// WithKeyId sets the key id
func WithKeyId(keyId string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyId = keyId
			return nil
		})
	}
}

// WithKeyLabel sets the key label
func WithKeyLabel(label string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withKeyLabel = label
			return nil
		})
	}
}

// WithMechanism sets the mechanism
func WithMechanism(mechanism string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withMechanism = mechanism
			return nil
		})
	}
}

// WithRsaOaepHash sets the RSA OAEP Hash mechanism
func WithRsaOaepHash(hashMechanisme string) wrapping.Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.withRsaOaepHash = hashMechanisme
			return nil
		})
	}
}
