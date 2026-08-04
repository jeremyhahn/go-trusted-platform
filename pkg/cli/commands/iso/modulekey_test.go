// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package iso

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

func TestModuleSigningKeyCommand_Creation(t *testing.T) {
	cmd := newModuleSigningKeyCommand(getTestFlags)
	require.NotNil(t, cmd, "newModuleSigningKeyCommand returned nil")
	assert.Equal(t, "module-signing-key", cmd.Use)
	assert.Contains(t, cmd.Long, "CONFIG_MODULE_SIG_KEY")
}

func TestModuleSigningKeyCommand_FlagsExist(t *testing.T) {
	cmd := newModuleSigningKeyCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	for _, flagName := range []string{"out", "key-bits", "common-name", "organization", "country", "valid-years", "force"} {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}

	assert.Equal(t, "4096", cmd.Flags().Lookup("key-bits").DefValue)
	assert.Equal(t, "false", cmd.Flags().Lookup("force").DefValue)
}

func TestModuleSigningKeyCommand_GeneratesKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "module-signing-key.pem")

	cmd := newModuleSigningKeyCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	// 2048 keeps the unit test fast; production default is 4096.
	cmd.SetArgs([]string{"--out", out, "--key-bits", "2048"})

	require.NoError(t, cmd.Execute())

	msk, err := secureboot.LoadModuleSigningKey(out)
	require.NoError(t, err, "generated bundle must load back")
	assert.False(t, msk.Certificate.IsCA)
	assert.NotEmpty(t, msk.Certificate.SubjectKeyId)
}

func TestModuleSigningKeyCommand_RefusesOverwrite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "module-signing-key.pem")

	first := newModuleSigningKeyCommand(getTestFlags)
	first.SetOut(new(bytes.Buffer))
	first.SetErr(new(bytes.Buffer))
	first.SetArgs([]string{"--out", out, "--key-bits", "2048"})
	require.NoError(t, first.Execute())

	second := newModuleSigningKeyCommand(getTestFlags)
	second.SetOut(new(bytes.Buffer))
	second.SetErr(new(bytes.Buffer))
	second.SetArgs([]string{"--out", out, "--key-bits", "2048"})

	err := second.Execute()
	var exists secureboot.ErrModuleKeyExists
	require.True(t, errors.As(err, &exists), "expected ErrModuleKeyExists, got %v", err)
}

func TestModuleSigningKeyCommand_RejectsWeakKey(t *testing.T) {
	cmd := newModuleSigningKeyCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"--out", filepath.Join(t.TempDir(), "k.pem"), "--key-bits", "1024"})

	err := cmd.Execute()
	require.True(t, errors.Is(err, secureboot.ErrInvalidConfig), "expected ErrInvalidConfig, got %v", err)
}
