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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "iso", cmd.Use)
	assert.Equal(t, "ISO image management operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage ISO images for Trusted Platform deployment")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 7) // create, download, extract, customize, build, profile, test

	// Verify key subcommands exist
	expectedCommands := map[string]bool{
		"create":    false,
		"download":  false,
		"extract":   false,
		"customize": false,
		"build":     false,
		"profile":   false,
		"test":      false,
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

func TestNewCommand_SubcommandUseFields(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	// Verify each subcommand has proper Use field
	for _, sub := range subcommands {
		assert.NotEmpty(t, sub.Use, "subcommand Use field should not be empty")
		assert.NotEmpty(t, sub.Short, "subcommand Short field should not be empty")
	}
}

func TestNewCommand_SubcommandRunFunctions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	// Verify each subcommand has a RunE function (or has subcommands of its own)
	for _, sub := range subcommands {
		hasRun := sub.RunE != nil || sub.Run != nil
		hasSubcommands := len(sub.Commands()) > 0
		assert.True(t, hasRun || hasSubcommands, "subcommand %s should have a run function or subcommands", sub.Use)
	}
}

func TestNewCommand_NilGetFlags(t *testing.T) {
	// Test that passing nil getFlags doesn't panic during command creation
	// The panic would happen at runtime when RunE is called
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewCommand panicked with nil getFlags: %v", r)
		}
	}()

	// This should not panic - the command creation doesn't call getFlags
	cmd := NewCommand(nil)
	require.NotNil(t, cmd)
}
