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
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfileCommand_Creation(t *testing.T) {
	cmd := newProfileCommand(getTestFlags)
	require.NotNil(t, cmd, "newProfileCommand returned nil")
	assert.Equal(t, "profile", cmd.Use)
	assert.Equal(t, "Manage installation profiles", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage installation configuration profiles")
}

func TestProfileCommand_HasSubcommands(t *testing.T) {
	cmd := newProfileCommand(getTestFlags)

	subcommands := cmd.Commands()
	assert.Equal(t, 4, len(subcommands), "expected 4 subcommands")

	// Verify subcommand names - profile subcommands might have uses like "show <profile-name>"
	expectedNames := map[string]bool{
		"list":     false,
		"generate": false,
	}

	for _, sub := range subcommands {
		// Handle use strings that include arguments like "show <profile-name>"
		use := sub.Use
		if len(use) > 0 {
			// Extract first word (command name)
			for i, c := range use {
				if c == ' ' {
					use = use[:i]
					break
				}
			}
		}
		if _, ok := expectedNames[use]; ok {
			expectedNames[use] = true
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "subcommand %s should exist", name)
	}
}

func TestProfileListCommand_Creation(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileListCommand(getTestFlags, pFlags)
	require.NotNil(t, cmd, "newProfileListCommand returned nil")
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List available installation profiles", cmd.Short)

	// Verify alias
	require.Greater(t, len(cmd.Aliases), 0, "expected aliases")
	assert.Equal(t, "ls", cmd.Aliases[0])
}

func TestProfileShowCommand_Creation(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileShowCommand(getTestFlags, pFlags)
	require.NotNil(t, cmd, "newProfileShowCommand returned nil")
	assert.Equal(t, "show <profile-name>", cmd.Use)
	assert.Equal(t, "Show installation profile configuration", cmd.Short)
}

func TestProfileValidateCommand_Creation(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileValidateCommand(getTestFlags, pFlags)
	require.NotNil(t, cmd, "newProfileValidateCommand returned nil")
	assert.Equal(t, "validate <config-file>", cmd.Use)
	assert.Contains(t, cmd.Short, "Validate")
}

func TestProfileGenerateCommand_Creation(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)
	require.NotNil(t, cmd, "newProfileGenerateCommand returned nil")
	assert.Equal(t, "generate", cmd.Use)
	assert.Contains(t, cmd.Short, "Generate")
}

func TestProfileGenerateCommand_FlagsExist(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify flags exist
	expectedFlags := []string{"profile", "output", "device", "interactive"}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestProfileGenerateCommand_RequiresProfile(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)

	found := false
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "profile" {
			found = true
		}
	})

	assert.True(t, found, "expected 'profile' flag to be defined")
}

func TestProfileGenerateCommand_DefaultValues(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)

	profileFlag := cmd.Flags().Lookup("profile")
	// Profile default is empty (required flag)
	assert.Equal(t, "", profileFlag.DefValue)

	interactiveFlag := cmd.Flags().Lookup("interactive")
	assert.Equal(t, "false", interactiveFlag.DefValue)

	outputFlag := cmd.Flags().Lookup("output")
	assert.Equal(t, "", outputFlag.DefValue)

	deviceFlag := cmd.Flags().Lookup("device")
	assert.Equal(t, "", deviceFlag.DefValue)
}

func TestRunProfileList_ReturnsError(t *testing.T) {
	pFlags := &profileFlags{noColor: true}

	err := runProfileList(getTestFlags(), pFlags)
	require.Error(t, err, "expected error from runProfileList (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestRunProfileShow_ReturnsError(t *testing.T) {
	pFlags := &profileFlags{noColor: true}

	err := runProfileShow(getTestFlags(), pFlags, "dev")
	require.Error(t, err, "expected error from runProfileShow (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestRunProfileValidate_ReturnsError(t *testing.T) {
	pFlags := &profileFlags{noColor: true}

	err := runProfileValidate(getTestFlags(), pFlags, "/tmp/config.yaml")
	require.Error(t, err, "expected error from runProfileValidate (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestRunProfileGenerate_ReturnsError(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	gFlags := &generateProfileFlags{
		profileName:    "dev",
		outputFile:     "/tmp/output.yaml",
		overrideDevice: "/dev/sda",
	}

	err := runProfileGenerate(getTestFlags(), pFlags, gFlags)
	require.Error(t, err, "expected error from runProfileGenerate (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestProfileFlags_StructFields(t *testing.T) {
	flags := &profileFlags{noColor: true}
	assert.True(t, flags.noColor)

	flags.noColor = false
	assert.False(t, flags.noColor)
}

func TestGenerateProfileFlags_StructFields(t *testing.T) {
	flags := &generateProfileFlags{
		profileName:    "production",
		outputFile:     "/etc/installer.yaml",
		overrideDevice: "/dev/nvme0n1",
		interactive:    true,
	}

	assert.Equal(t, "production", flags.profileName)
	assert.Equal(t, "/etc/installer.yaml", flags.outputFile)
	assert.Equal(t, "/dev/nvme0n1", flags.overrideDevice)
	assert.True(t, flags.interactive)
}

func TestProfileCommand_LongDescription(t *testing.T) {
	cmd := newProfileCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "Profiles")
	assert.Contains(t, cmd.Long, "configuration")
}

func TestProfileListCommand_HasRunE(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileListCommand(getTestFlags, pFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestProfileShowCommand_HasRunE(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileShowCommand(getTestFlags, pFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestProfileValidateCommand_HasRunE(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileValidateCommand(getTestFlags, pFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestProfileGenerateCommand_HasRunE(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestProfileListCommand_LongDescription(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileListCommand(getTestFlags, pFlags)
	assert.Contains(t, cmd.Long, "dev")
	assert.Contains(t, cmd.Long, "production")
	assert.Contains(t, cmd.Long, "fips")
}

func TestProfileShowCommand_LongDescription(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileShowCommand(getTestFlags, pFlags)
	assert.Contains(t, cmd.Long, "YAML")
	assert.Contains(t, cmd.Long, "configuration")
}

func TestProfileValidateCommand_LongDescription(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileValidateCommand(getTestFlags, pFlags)
	assert.Contains(t, cmd.Long, "validator")
	assert.Contains(t, cmd.Long, "Required fields")
}

func TestProfileGenerateCommand_LongDescription(t *testing.T) {
	pFlags := &profileFlags{noColor: true}
	cmd := newProfileGenerateCommand(getTestFlags, pFlags)
	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl iso profile generate")
}
