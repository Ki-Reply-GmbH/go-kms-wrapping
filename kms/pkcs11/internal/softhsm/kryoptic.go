// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package softhsm

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type Kryoptic struct {
	Path string // Path is the dynamic library path to use.

	maxSlots    int // Slot count allocated in the configuration file.
	currentSlot int // Incremented with each call to InitToken().

	t *testing.T
}

func New(t *testing.T) *Kryoptic {
	return NewKryoptic(t, 3)
}

func NewKryoptic(t *testing.T, slots int) *Kryoptic {
	t.Helper()

	dir := t.TempDir()

	var config []string
	for i := range slots {
		config = append(config, strings.Join([]string{
			"[[slots]]",
			fmt.Sprintf("slot = %d", i),
			fmt.Sprintf("dbtype = %q", "sqlite"),
			fmt.Sprintf("dbargs = %q", path.Join(dir, fmt.Sprintf("token-%d.sql", i))),
		}, "\n"))
	}

	configPath := path.Join(dir, "token.conf")
	t.Setenv("KRYOPTIC_CONF", configPath)
	require.NoError(t, os.WriteFile(configPath, []byte(strings.Join(config, "\n")), 0o644))

	path := "/usr/lib/kryoptic/libkryoptic_pkcs11.so"
	if env := os.Getenv("KRYOPTIC_LIBRARY_PATH"); env != "" {
		path = env
	}

	return &Kryoptic{
		Path:     path,
		maxSlots: slots,
		t:        t,
	}
}

func (k *Kryoptic) InitToken() (label, pin string) {
	if k.currentSlot >= k.maxSlots {
		require.FailNow(k.t, "maximum slot count reached")
	}

	label, pin = rand.Text(), rand.Text()

	// Initialize the token & SO PIN.
	cmd := exec.Command(
		"pkcs11-tool", "--module", k.Path, "--init-token",
		"--slot", strconv.Itoa(k.currentSlot), "--label", label,
		"--so-pin", pin,
	)

	cmd.Stderr = os.Stderr
	require.NoError(k.t, cmd.Run())

	// Set the user PIN.
	cmd = exec.Command(
		"pkcs11-tool", "--module", k.Path, "--init-pin",
		"--slot", strconv.Itoa(k.currentSlot), "--login", "--login-type", "so",
		"--so-pin", pin, "--pin", pin,
	)

	cmd.Stderr = os.Stderr
	require.NoError(k.t, cmd.Run())

	k.currentSlot++

	return label, pin
}
