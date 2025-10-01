// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package pkcs11

import "fmt"

func pkcs11Error(op string, inner error) error {
	if inner == nil {
		return nil
	} else {
		return fmt.Errorf("failed to pkcs#11 %s: %w", op, inner)
	}
}
