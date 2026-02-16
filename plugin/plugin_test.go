// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/aead"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// client is a test helper that spawns a plugin server by re-executing the
// test binary into one of the TestServer_* tests below and returns a client
// connected to it.
func client(t *testing.T, test string) plugin.ClientProtocol {
	cmd := exec.Command(os.Args[0], fmt.Sprintf("--test.run=TestServer_%s", test))
	cmd.Env = append(cmd.Env, "OPENBAO_TEST_SERVER=1")

	plug := plugin.NewClient(&plugin.ClientConfig{
		Cmd:              cmd,
		VersionedPlugins: PluginSets,
		HandshakeConfig:  HandshakeConfig,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
	})

	t.Cleanup(func() {
		plug.Kill()
	})

	client, err := plug.Client()
	require.NoError(t, err)

	return client
}

func TestServer_TestWrapper(t *testing.T) {
	if _, ok := os.LookupEnv("OPENBAO_TEST_SERVER"); !ok {
		t.Skip()
	}
	Serve(&ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return wrapping.NewTestInitFinalizer([]byte("test"))
		},
	})
}

func TestServer_AeadWrapper(t *testing.T) {
	if _, ok := os.LookupEnv("OPENBAO_TEST_SERVER"); !ok {
		t.Skip()
	}
	Serve(&ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper {
			return aead.NewWrapper()
		},
	})
}

func TestWrapper(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	tests := []struct {
		server string // See client().
		opts   *wrapping.Options
	}{
		{
			server: "TestWrapper",
			opts: &wrapping.Options{
				WithKeyId: "test",
			},
		},
		{
			server: "AeadWrapper",
			opts: &wrapping.Options{
				WithKeyId: "root",
				WithConfigMap: map[string]string{
					"key": base64.StdEncoding.EncodeToString(key),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.server, func(t *testing.T) {
			raw, err := client(t, tt.server).Dispense("wrapper")
			require.NoError(t, err)

			wrapper, ok := raw.(interface {
				wrapping.Wrapper
				wrapping.InitFinalizer
			})
			require.True(t, ok)

			// We don't test multiplexing in this test, just use a static ID.
			ctx := metadata.NewOutgoingContext(t.Context(), metadata.MD{
				pluginutil.MultiplexingCtxKey: {"test"},
			})

			_, err = wrapper.SetConfig(
				ctx,
				wrapping.WithKeyId(tt.opts.WithKeyId),
				wrapping.WithConfigMap(tt.opts.WithConfigMap),
			)
			require.NoError(t, err)

			require.NoError(t, wrapper.Init(ctx))

			t.Run("Encrypt+Decrypt", func(t *testing.T) {
				input := "foobar"
				blob, err := wrapper.Encrypt(ctx, []byte(input))
				require.NoError(t, err)

				plaintext, err := wrapper.Decrypt(ctx, blob)
				require.NoError(t, err)
				require.Equal(t, input, string(plaintext))
			})

			t.Run("KeyId", func(t *testing.T) {
				id, err := wrapper.KeyId(ctx)
				require.NoError(t, err)
				require.Equal(t, tt.opts.WithKeyId, id)
			})

			require.NoError(t, wrapper.Finalize(ctx))
		})
	}
}

func TestWrapperMultiplex(t *testing.T) {
	raw, err := client(t, "AeadWrapper").Dispense("wrapper")
	require.NoError(t, err)

	wrapper, ok := raw.(interface {
		wrapping.Wrapper
		wrapping.InitFinalizer
	})
	require.True(t, ok)

	ctx := t.Context()

	_, err = wrapper.SetConfig(ctx)
	require.ErrorContains(t, err, pluginutil.ErrNoMultiplexingIDFound.Error())

	// Create two wrappers with separate key material:
	a := metadata.NewOutgoingContext(ctx, metadata.MD{pluginutil.MultiplexingCtxKey: {"a"}})
	b := metadata.NewOutgoingContext(ctx, metadata.MD{pluginutil.MultiplexingCtxKey: {"b"}})

	akey := make([]byte, 32)
	_, _ = rand.Read(akey)
	bkey := make([]byte, 32)
	_, _ = rand.Read(bkey)

	_, err = wrapper.SetConfig(a, wrapping.WithConfigMap(map[string]string{
		"key": base64.StdEncoding.EncodeToString(akey),
	}))
	require.NoError(t, err)
	_, err = wrapper.SetConfig(b, wrapping.WithConfigMap(map[string]string{
		"key": base64.StdEncoding.EncodeToString(bkey),
	}))
	require.NoError(t, err)

	// Now ensure that wrappers do indeed use separate key material:
	blob, err := wrapper.Encrypt(a, []byte("foo"))
	require.NoError(t, err)

	// This should fail since we're using the wrong key:
	_, err = wrapper.Decrypt(b, blob)
	require.Error(t, err)

	// But the correct key should work:
	_, err = wrapper.Decrypt(a, blob)
	require.NoError(t, err)

	// Finalizing once should remove the instance:
	require.NoError(t, wrapper.Finalize(a))
	_, err = wrapper.Encrypt(a, []byte("foo"))
	require.Error(t, err)

	// But this one's still live:
	_, err = wrapper.Encrypt(b, []byte("foo"))
	require.NoError(t, err)
}
