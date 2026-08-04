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

package provision

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// NewCommand Tests
// =============================================================================

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "provision", cmd.Use)
	assert.Equal(t, "Device provisioning operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage device provisioning during ISO boot")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 3)

	expectedCommands := map[string]bool{
		"fetch-config": false,
		"interactive":  false,
		"session":      false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

func TestNewCommand_NilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "provision", cmd.Use)
}
