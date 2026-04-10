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

func TestExtractCommand_Creation(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)
	require.NotNil(t, cmd, "newExtractCommand returned nil")
	assert.Equal(t, "extract", cmd.Use)
	assert.Equal(t, "Extract ISO contents for customization", cmd.Short)
	assert.Contains(t, cmd.Long, "Extracts the contents of an ISO file")
}

func TestExtractCommand_FlagsExist(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify all flags exist
	flags := []string{"iso", "output-dir", "force", "config", "work-dir", "debug", "verbose"}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestExtractCommand_RequiredFlags(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)

	// Verify the 'iso' flag exists (marked as required)
	isoFlag := cmd.Flags().Lookup("iso")
	require.NotNil(t, isoFlag, "iso flag not found")
}

func TestExtractCommand_DefaultValues(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	forceFlag := cmd.Flags().Lookup("force")
	assert.Equal(t, "false", forceFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	verboseFlag := cmd.Flags().Lookup("verbose")
	assert.Equal(t, "false", verboseFlag.DefValue)

	// output-dir should be empty by default (uses work-dir/iso)
	outputDirFlag := cmd.Flags().Lookup("output-dir")
	assert.Equal(t, "", outputDirFlag.DefValue)
}

func TestRunExtract_ReturnsError(t *testing.T) {
	flags := &extractFlags{
		iso:       "/tmp/test.iso",
		outputDir: "/tmp/extracted",
		force:     false,
		workDir:   "work",
	}

	err := runExtract(getTestFlags(), flags)
	require.Error(t, err, "expected error from runExtract (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestExtractFlags_StructFields(t *testing.T) {
	flags := &extractFlags{
		iso:        "/path/to/alpine.iso",
		outputDir:  "/path/to/output",
		force:      true,
		configFile: "/etc/config.yaml",
		workDir:    "/tmp/work",
		debug:      true,
		verbose:    true,
	}

	assert.Equal(t, "/path/to/alpine.iso", flags.iso)
	assert.Equal(t, "/path/to/output", flags.outputDir)
	assert.True(t, flags.force)
	assert.Equal(t, "/etc/config.yaml", flags.configFile)
	assert.Equal(t, "/tmp/work", flags.workDir)
	assert.True(t, flags.debug)
	assert.True(t, flags.verbose)
}

func TestExtractCommand_HasRunE(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestExtractCommand_LongDescription(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "7z")
	assert.Contains(t, cmd.Long, "bsdtar")
	assert.Contains(t, cmd.Long, "xorriso")
	assert.Contains(t, cmd.Long, "writable")
}

func TestExtractCommand_ExamplesExist(t *testing.T) {
	cmd := newExtractCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl iso extract")
}
