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

// TestNewCommand tests the db command creation
func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd, "NewCommand should not return nil")
	assert.Equal(t, "db", cmd.Use, "command Use should be 'db'")
	assert.Equal(t, "Database operations", cmd.Short)
	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
}

func TestNewCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
	assert.Contains(t, cmd.Long, "QuicBaaS")
	assert.Contains(t, cmd.Long, "Examples:")
}

func TestNewCommand_HasSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	subcommands := cmd.Commands()
	require.NotEmpty(t, subcommands, "db command should have subcommands")

	// Check for dump subcommand
	found := false
	for _, subcmd := range subcommands {
		if subcmd.Name() == "dump" {
			found = true
			break
		}
	}
	assert.True(t, found, "dump subcommand should exist")
}

func TestNewCommand_DumpSubcommandStructure(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	for _, subcmd := range cmd.Commands() {
		if subcmd.Name() == "dump" {
			assert.Equal(t, "dump", subcmd.Use)
			assert.Equal(t, "Export QuicBaaS data to files", subcmd.Short)
			assert.NotNil(t, subcmd.RunE, "dump command should have RunE set")
			return
		}
	}
	t.Error("dump subcommand not found")
}
