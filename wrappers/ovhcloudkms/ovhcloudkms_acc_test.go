// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package ovhcloudkms

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

// This test executes real calls. The calls themselves should be free,
// but the OKMS key used is generally not free.
//
// To run this test, the following env variables need to be set or provided
// with `withConfigMap` wrapper option:
//   - OVHCLOUDKMS_KEY_ID / withConfigMap["key_id"]
//   - OVHCLOUDKMS_ENDPOINT / withConfigMap["endpoint"]
//   - OVHCLOUDKMS_ID / withConfigMap["kms_id"]
//
// You can choose the auth type by setting corresponding env variables
// or providing them with `withConfigMap` wrapper option.
// token:
//   - OVHCLOUDKMS_TOKEN / withConfigMap["token"]
//
// or mTLS:
//   - OVHCLOUDKMS_CLIENT_CERT / withConfigMap["client_cert_bytes"]
//   - OVHCLOUDKMS_CLIENT_KEY / withConfigMap["client_key_bytes"]
//
// optionally:
//   - OVHCLOUDKMS_CA_CERT / withConfigMap["ca_cert_bytes"]
func TestAccWrapper(t *testing.T) {
	roundtrip := func(t *testing.T, ow *Wrapper) {
		t.Helper()

		input := []byte("foobar")
		ciphertext0, err := ow.Encrypt(t.Context(), input)
		require.NoError(t, err)
		require.NotEqual(t, ciphertext0, input)

		ciphertext1, err := ow.Encrypt(t.Context(), input)
		require.NoError(t, err)
		require.NotEqual(t, ciphertext1, input)
		require.NotEqual(t, ciphertext1, ciphertext0)

		plaintext0, err := ow.Decrypt(t.Context(), ciphertext0)
		require.NoError(t, err)
		require.Equal(t, input, plaintext0)

		plaintext1, err := ow.Decrypt(t.Context(), ciphertext1)
		require.NoError(t, err)
		require.Equal(t, input, plaintext1)

		corruptedCipher := &wrapping.BlobInfo{
			Ciphertext: bytes.Clone(ciphertext0.Ciphertext),
			Iv:         ciphertext0.Iv,
			KeyInfo:    ciphertext0.KeyInfo,
		}
		corruptedCipher.Ciphertext[0] ^= 0xff
		_, err = ow.Decrypt(t.Context(), corruptedCipher)
		require.Error(t, err)
	}

	if os.Getenv("VAULT_ACC") == "" && os.Getenv("KMS_ACC_TESTS") == "" {
		t.SkipNow()
	}

	keyId := os.Getenv("OVHCLOUDKMS_KEY_ID")
	if keyId == "" {
		t.SkipNow()
	}

	t.Run("Certificate authorization with env vars", func(t *testing.T) {
		tempDir := t.TempDir()

		clientCertFile, err := os.CreateTemp(tempDir, "client-cert.pem")
		require.NoError(t, err)

		clientCert := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT")
		_, err = clientCertFile.Write([]byte(clientCert))
		clientCertFile.Close()
		t.Setenv(EnvOkmsClientCert, clientCertFile.Name())

		clientKeyFile, err := os.CreateTemp(tempDir, "client-key.pem")
		require.NoError(t, err)
		clientKey := os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY")
		_, err = clientKeyFile.Write([]byte(clientKey))
		t.Setenv(EnvOkmsClientKey, clientKeyFile.Name())

		ow := NewWrapper()
		_, err = ow.SetConfig(t.Context())
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Certificate authorization with disallow env vars", func(t *testing.T) {
		configMap := map[string]string{
			"key_id":            keyId,
			"endpoint":          os.Getenv("OVHCLOUDKMS_ENDPOINT"),
			"kms_id":            os.Getenv("OVHCLOUDKMS_ID"),
			"client_cert_bytes": os.Getenv("OVHCLOUDKMS_CERT_CLIENT_CERT"),
			"client_key_bytes":  os.Getenv("OVHCLOUDKMS_CERT_CLIENT_KEY"),
		}
		ow := NewWrapper()
		_, err := ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Credentials authorization with env vars", func(t *testing.T) {
		token, err := getOVHServiceAccountToken(t)
		require.NoError(t, err)

		t.Setenv(EnvOkmsToken, token.AccessToken)
		ow := NewWrapper()
		_, err = ow.SetConfig(t.Context())
		require.NoError(t, err)
		roundtrip(t, ow)
	})

	t.Run("Credentials authorization with disallow env vars", func(t *testing.T) {
		token, err := getOVHServiceAccountToken(t)
		require.NoError(t, err)

		configMap := map[string]string{
			"key_id":   keyId,
			"endpoint": os.Getenv("OVHCLOUDKMS_ENDPOINT"),
			"kms_id":   os.Getenv("OVHCLOUDKMS_ID"),
			"token":    token.AccessToken,
		}
		ow := NewWrapper()
		_, err = ow.SetConfig(t.Context(), wrapping.WithConfigMap(configMap), wrapping.WithDisallowEnvVars(true))
		require.NoError(t, err)
		roundtrip(t, ow)
	})
}

type OVHTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func getOVHServiceAccountToken(t *testing.T) (*OVHTokenResponse, error) {
	accName := os.Getenv("OVHCLOUDKMS_SERVICE_ACCOUNT_NAME")
	accPassword := os.Getenv("OVHCLOUDKMS_SERVICE_ACCOUNT_PASSWORD")

	if accName == "" {
		return nil, fmt.Errorf("OVHCLOUDKMS_SERVICE_ACCOUNT_NAME is not set")
	}
	if accPassword == "" {
		return nil, fmt.Errorf("OVHCLOUDKMS_SERVICE_ACCOUNT_PASSWORD is not set")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", accName)
	form.Set("client_secret", accPassword)
	form.Set("scope", "all")

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://www.ovh.ca/auth/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OVH token request failed with status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var token OVHTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	if token.AccessToken == "" {
		return nil, errors.New("OVH token response did not contain access_token")
	}

	return &token, nil
}
