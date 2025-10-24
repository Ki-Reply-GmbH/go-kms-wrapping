// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test executes real calls. The calls themselves should be free,
// but the KMS key used is generally not free.
//
// To run this test, the following env variables need to be set:
//   - BAO_HSM_LIB
//   - BAO_HSM_PIN
//   - BAO_HSM_SLOT and/or BAO_HSM_TOKEN_LABEL
//   - BAO_HSM_KEY_ID and/or BAO_HSM_KEY_LABEL
//
// Additionally, the following variables can optionally be set:
//   - BAO_HSM_MECHANISM
//   - BAO_HSM_DISABLE_SOFTWARE_ENCRYPTION
func TestLifecycle(t *testing.T) {
	if yes, err := strconv.ParseBool(os.Getenv("KMS_ACC_TESTS")); err != nil || !yes {
		t.Skip("Skipping acceptance test, set KMS_ACC_TESTS=1 to run")
	}

	ctx := t.Context()
	wrapper := NewWrapper()

	_, err := wrapper.SetConfig(ctx)
	require.NoError(t, err)

	input := []byte("foo")

	blob, err := wrapper.Encrypt(ctx, input)
	require.NoError(t, err)

	plaintext, err := wrapper.Decrypt(ctx, blob)
	require.NoError(t, err)

	require.Equal(t, input, plaintext)
}
