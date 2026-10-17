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
	flags := []string{"iso", "output-dir", "force", "work-dir", "debug"}
	for _, removed := range []string{"config", "verbose"} {
		assert.Nil(t, cmd.Flags().Lookup(removed), "flag '%s' should not be defined", removed)
	}

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

	// output-dir should be empty by default (uses work-dir/iso)
	outputDirFlag := cmd.Flags().Lookup("output-dir")
	assert.Equal(t, "", outputDirFlag.DefValue)
}

func TestRunExtract_MissingISO(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.iso")
	flags := &extractFlags{
		iso:       missing,
		outputDir: t.TempDir(),
		workDir:   "work",
	}

	out := new(bytes.Buffer)
	err := runExtract(context.Background(), getTestFlags(), flags, out)

	var notFound ErrISONotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, missing, notFound.Path)
	assert.Empty(t, out.String(), "a failed extract prints no result")
}

func TestRunExtract_RefusesNonEmptyOutputWithoutForce(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "test.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("iso"), 0o600))
	outputDir := t.TempDir()
	keep := filepath.Join(outputDir, "keep")
	require.NoError(t, os.WriteFile(keep, []byte("existing"), 0o600))

	err := runExtract(context.Background(), getTestFlags(), &extractFlags{iso: isoPath, outputDir: outputDir}, new(bytes.Buffer))

	var exists ErrDirectoryAlreadyExists
	require.ErrorAs(t, err, &exists)
	assert.Equal(t, outputDir, exists.Path)
	assert.FileExists(t, keep, "the existing tree is left alone")
}

func TestRunExtract_DefaultOutputDirIsUnderWorkDir(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "test.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("iso"), 0o600))
	workDir := t.TempDir()
	defaultDir := filepath.Join(workDir, "iso")
	require.NoError(t, os.MkdirAll(defaultDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(defaultDir, "keep"), []byte("x"), 0o600))

	err := runExtract(context.Background(), getTestFlags(), &extractFlags{iso: isoPath, workDir: workDir}, new(bytes.Buffer))

	var exists ErrDirectoryAlreadyExists
	require.ErrorAs(t, err, &exists)
	assert.Equal(t, defaultDir, exists.Path)
}

func TestDirectoryHasEntries(t *testing.T) {
	empty := t.TempDir()
	assert.False(t, directoryHasEntries(empty))
	assert.False(t, directoryHasEntries(filepath.Join(empty, "absent")))

	require.NoError(t, os.WriteFile(filepath.Join(empty, "f"), nil, 0o600))
	assert.True(t, directoryHasEntries(empty))
}

func TestCountFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "boot", "grub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "boot", "b"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "boot", "grub", "c"), nil, 0o600))

	count, err := countFiles(root)
	require.NoError(t, err)
	assert.Equal(t, 3, count, "directories are not counted")

	_, err = countFiles(filepath.Join(root, "absent"))
	assert.Error(t, err)
}

func TestExtractFlags_StructFields(t *testing.T) {
	flags := &extractFlags{
		iso:       "/path/to/alpine.iso",
		outputDir: "/path/to/output",
		force:     true,
		workDir:   "/tmp/work",
		debug:     true,
	}

	assert.Equal(t, "/path/to/alpine.iso", flags.iso)
	assert.Equal(t, "/path/to/output", flags.outputDir)
	assert.True(t, flags.force)
	assert.Equal(t, "/tmp/work", flags.workDir)
	assert.True(t, flags.debug)
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
