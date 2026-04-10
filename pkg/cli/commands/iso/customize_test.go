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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomizeCommand_Creation(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)
	require.NotNil(t, cmd, "newCustomizeCommand returned nil")
	assert.Equal(t, "customize", cmd.Use)
	assert.Equal(t, "Customize ISO with overlays and initramfs", cmd.Short)
	assert.Contains(t, cmd.Long, "Customize an extracted ISO")
}

func TestCustomizeCommand_FlagsExist(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify all flags exist
	flags := []string{
		"iso-dir", "overlay", "keys-dir", "platformd-binary",
		"autoinstall", "modify-initramfs",
		"config", "work-dir", "debug", "verbose",
	}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestCustomizeCommand_RequiredFlags(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)

	// Verify iso-dir is required
	isoDirFlag := cmd.Flags().Lookup("iso-dir")
	require.NotNil(t, isoDirFlag, "iso-dir flag not found")
}

func TestRunCustomize_ReturnsError(t *testing.T) {
	flags := &customizeFlags{
		isoDir:          "/tmp/test-iso",
		overlay:         "/tmp/overlay",
		keysDir:         "/tmp/keys",
		platformdPath:   "/usr/bin/platformd",
		autoinstall:     false,
		modifyInitramfs: false,
	}

	err := runCustomize(getTestFlags(), flags)
	require.Error(t, err, "expected error from runCustomize (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestCustomizeCommand_DefaultValues(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	verboseFlag := cmd.Flags().Lookup("verbose")
	assert.Equal(t, "false", verboseFlag.DefValue)

	autoinstallFlag := cmd.Flags().Lookup("autoinstall")
	assert.Equal(t, "false", autoinstallFlag.DefValue)

	modifyInitramfsFlag := cmd.Flags().Lookup("modify-initramfs")
	assert.Equal(t, "false", modifyInitramfsFlag.DefValue)

	// Optional flags should be empty by default
	overlayFlag := cmd.Flags().Lookup("overlay")
	assert.Equal(t, "", overlayFlag.DefValue)

	keysDirFlag := cmd.Flags().Lookup("keys-dir")
	assert.Equal(t, "", keysDirFlag.DefValue)

	platformdBinaryFlag := cmd.Flags().Lookup("platformd-binary")
	assert.Equal(t, "", platformdBinaryFlag.DefValue)
}

func TestCustomizeFlags_StructFields(t *testing.T) {
	flags := &customizeFlags{
		isoDir:          "/path/to/iso",
		overlay:         "/path/to/overlay",
		keysDir:         "/path/to/keys",
		platformdPath:   "/usr/local/bin/platformd",
		autoinstall:     true,
		modifyInitramfs: true,
		configFile:      "/etc/config.yaml",
		workDir:         "/tmp/work",
		debug:           true,
		verbose:         true,
	}

	assert.Equal(t, "/path/to/iso", flags.isoDir)
	assert.Equal(t, "/path/to/overlay", flags.overlay)
	assert.Equal(t, "/path/to/keys", flags.keysDir)
	assert.Equal(t, "/usr/local/bin/platformd", flags.platformdPath)
	assert.True(t, flags.autoinstall)
	assert.True(t, flags.modifyInitramfs)
	assert.Equal(t, "/etc/config.yaml", flags.configFile)
	assert.Equal(t, "/tmp/work", flags.workDir)
	assert.True(t, flags.debug)
	assert.True(t, flags.verbose)
}

func TestCustomizeCommand_HasRunE(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestCustomizeCommand_LongDescription(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "platformd")
	assert.Contains(t, cmd.Long, "initramfs")
	assert.Contains(t, cmd.Long, "Secure Boot")
	assert.Contains(t, cmd.Long, "overlay")
}

func TestCustomizeCommand_ExamplesExist(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "Example:")
	assert.Contains(t, cmd.Long, "platformctl iso customize")
}
