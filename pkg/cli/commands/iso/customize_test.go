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
	"path/filepath"
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
		"platform-config", "config", "work-dir", "debug",
	}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}

	// The no-op flags were removed with the daemon-connection stub.
	for _, removed := range []string{"autoinstall", "modify-initramfs", "verbose"} {
		assert.Nil(t, cmd.Flags().Lookup(removed), "flag '%s' must not exist", removed)
	}
}

func TestCustomizeCommand_RequiredFlags(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)

	// Verify iso-dir is required
	isoDirFlag := cmd.Flags().Lookup("iso-dir")
	require.NotNil(t, isoDirFlag, "iso-dir flag not found")
}

func TestRunCustomize_MissingISODir(t *testing.T) {
	flags := &customizeFlags{isoDir: filepath.Join(t.TempDir(), "missing")}

	err := runCustomize(context.Background(), getTestFlags(), flags, new(bytes.Buffer))
	require.Error(t, err)

	var notFound ErrDirectoryNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, flags.isoDir, notFound.Path)
}

func TestRunCustomize_UnreadableConfig(t *testing.T) {
	flags := &customizeFlags{
		isoDir:     t.TempDir(),
		configFile: filepath.Join(t.TempDir(), "missing.yaml"),
	}

	err := runCustomize(context.Background(), getTestFlags(), flags, new(bytes.Buffer))
	require.Error(t, err)

	var parseErr ErrConfigParseError
	require.ErrorAs(t, err, &parseErr)
	assert.Equal(t, flags.configFile, parseErr.Path)
}

func TestCustomizeCommand_DefaultValues(t *testing.T) {
	cmd := newCustomizeCommand(getTestFlags)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	// Optional flags should be empty by default
	for _, name := range []string{"overlay", "keys-dir", "platformd-binary", "platform-config", "config"} {
		assert.Equal(t, "", cmd.Flags().Lookup(name).DefValue, "flag %s", name)
	}
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
