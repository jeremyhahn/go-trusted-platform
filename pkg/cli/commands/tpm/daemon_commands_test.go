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

package tpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Daemon-Required Command Run Function Tests
// =============================================================================

func TestInstallCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newInstallCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "install", dcErr.Operation)
}

func TestDestroyCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newDestroyCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "destroy", dcErr.Operation)
}

func TestPolicyCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPolicyCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "policy", dcErr.Operation)
}

func TestExtendCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newExtendCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "extend", dcErr.Operation)
}

func TestXKMSCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newXKMSCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "xkms", dcErr.Operation)
}

func TestEnrollCommand_ReturnsDaemonConnectionRequired(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newEnrollCommand(getFlags)
	err := cmd.RunE(cmd, nil)
	require.NotNil(t, err)

	var dcErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &dcErr)
	assert.Equal(t, "enroll", dcErr.Operation)
}

// =============================================================================
// Clear Command Without Confirm Tests
// =============================================================================

func TestClearCommand_WithoutConfirm(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newClearCommand(getFlags)
	// When confirm is false, it should just print a warning and return nil
	err := cmd.RunE(cmd, nil)
	assert.NoError(t, err)
}
