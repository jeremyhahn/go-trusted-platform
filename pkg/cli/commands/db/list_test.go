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

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewListCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List QuicBaaS entity types and counts", cmd.Short)
	assert.Contains(t, cmd.Long, "entity types")
	assert.Contains(t, cmd.Long, "entity counts")
}

func TestNewListCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Check config-dir flag
	configDirFlag := cmd.Flags().Lookup("config-dir")
	require.NotNil(t, configDirFlag)
	assert.Equal(t, "", configDirFlag.DefValue)
}

func TestNewListCommand_HelpText(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	// Verify help text contains known entity types
	assert.Contains(t, cmd.Long, "Organization")
	assert.Contains(t, cmd.Long, "User")
	assert.Contains(t, cmd.Long, "Zone")
	assert.Contains(t, cmd.Long, "Device")
}

// Note: runList requires a running platformd server to test properly.
// Integration tests for the full command execution are in the integration test suite.
