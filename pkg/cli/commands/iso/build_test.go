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
	"context"
	"os"
	"path/filepath"
	"strings"
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

// getJSONTestFlags returns the common flags with -o json, so a verb's printed
// result can be decoded by the test.
func getJSONTestFlags() *cli.CommonFlags {
	flags := getTestFlags()
	flags.OutputFormat = cli.OutputFormatJSON
	return flags
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
	flags := []string{"iso-dir", "output", "label", "checksum", "debug"}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}

	// The verb runs locally; it takes no ISO build config or work directory.
	for _, removed := range []string{"config", "work-dir", "verbose"} {
		assert.Nil(t, cmd.Flags().Lookup(removed), "flag '%s' should not be defined", removed)
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

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)
}

func TestRunBuild_MissingSourceDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	flags := &buildFlags{
		sourceDir:   missing,
		output:      filepath.Join(t.TempDir(), "output.iso"),
		volumeID:    "TEST",
		generateSum: true,
	}

	out := new(bytes.Buffer)
	err := runBuild(context.Background(), getTestFlags(), flags, out)
	require.Error(t, err)

	var notFound ErrDirectoryNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, missing, notFound.Path)
	assert.Empty(t, out.String(), "a failed build prints no result")
}

func TestRunBuild_SourceIsAFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	err := runBuild(context.Background(), getTestFlags(), &buildFlags{sourceDir: file, output: file + ".iso"}, new(bytes.Buffer))

	var notFound ErrDirectoryNotFound
	require.ErrorAs(t, err, &notFound)
}

func TestRunBuild_LabelTooLong(t *testing.T) {
	flags := &buildFlags{
		sourceDir: t.TempDir(),
		output:    filepath.Join(t.TempDir(), "output.iso"),
		volumeID:  strings.Repeat("L", maxVolumeLabelLength+1),
	}

	err := runBuild(context.Background(), getTestFlags(), flags, new(bytes.Buffer))

	var tooLong ErrVolumeLabelTooLong
	require.ErrorAs(t, err, &tooLong)
	assert.Equal(t, maxVolumeLabelLength, tooLong.MaxLength)
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
