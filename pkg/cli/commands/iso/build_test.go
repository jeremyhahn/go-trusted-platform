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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// getTestFlags returns a CommonFlags instance for testing
func getTestFlags() *cli.CommonFlags {
	return &cli.CommonFlags{
		ConfigPath:   "",
		ContextName:  "test",
		OutputFormat: cli.OutputFormatTable,
		Verbose:      false,
		NoColor:      true,
	}
}

func TestBuildCommand_Creation(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)
	require.NotNil(t, cmd, "newBuildCommand returned nil")
	assert.Equal(t, "build", cmd.Use)
	assert.Equal(t, "Build final bootable ISO image", cmd.Short)
	assert.Contains(t, cmd.Long, "Builds a bootable ISO image")
}

func TestBuildCommand_FlagsExist(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify required flags exist
	flags := []string{"iso-dir", "output", "label", "checksum", "config", "work-dir", "debug", "verbose"}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestBuildCommand_RequiredFlags(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)

	// Verify iso-dir is required
	isoDirFlag := cmd.Flags().Lookup("iso-dir")
	require.NotNil(t, isoDirFlag, "iso-dir flag not found")

	// Verify output is required
	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag, "output flag not found")
}

func TestBuildCommand_DefaultValues(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)

	labelFlag := cmd.Flags().Lookup("label")
	assert.Equal(t, "TRUSTED_PLATFORM", labelFlag.DefValue)

	checksumFlag := cmd.Flags().Lookup("checksum")
	assert.Equal(t, "true", checksumFlag.DefValue)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	verboseFlag := cmd.Flags().Lookup("verbose")
	assert.Equal(t, "false", verboseFlag.DefValue)
}

func TestRunBuild_ReturnsError(t *testing.T) {
	flags := &buildFlags{
		sourceDir:   "/tmp/test-iso",
		output:      "/tmp/output.iso",
		volumeID:    "TEST",
		generateSum: true,
	}

	err := runBuild(getTestFlags(), flags)
	require.Error(t, err, "expected error from runBuild (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestBuildFlags_StructFields(t *testing.T) {
	flags := &buildFlags{
		sourceDir:   "/tmp/iso-dir",
		output:      "/tmp/output.iso",
		volumeID:    "MY_VOLUME",
		generateSum: true,
		configFile:  "/etc/config.yaml",
		workDir:     "/tmp/work",
		debug:       true,
		verbose:     true,
	}

	assert.Equal(t, "/tmp/iso-dir", flags.sourceDir)
	assert.Equal(t, "/tmp/output.iso", flags.output)
	assert.Equal(t, "MY_VOLUME", flags.volumeID)
	assert.True(t, flags.generateSum)
	assert.Equal(t, "/etc/config.yaml", flags.configFile)
	assert.Equal(t, "/tmp/work", flags.workDir)
	assert.True(t, flags.debug)
	assert.True(t, flags.verbose)
}

func TestBuildCommand_HasRunE(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestBuildCommand_LongDescription(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "xorriso")
	assert.Contains(t, cmd.Long, "BIOS")
	assert.Contains(t, cmd.Long, "UEFI")
	assert.Contains(t, cmd.Long, "USB")
}

func TestBuildCommand_ExamplesExist(t *testing.T) {
	cmd := newBuildCommand(getTestFlags)
	// Examples are in the Long description
	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl iso build")
}
