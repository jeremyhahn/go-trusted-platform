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

func TestDownloadCommand_Creation(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	require.NotNil(t, cmd, "newDownloadCommand returned nil")
	assert.Equal(t, "download", cmd.Use)
	assert.Equal(t, "Download Alpine Linux base ISO", cmd.Short)
	assert.Contains(t, cmd.Long, "Downloads Alpine Linux ISO")
}

func TestDownloadCommand_FlagsExist(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify all flags exist
	flags := []string{
		"url", "version", "mirror", "arch", "force", "verify", "resume",
		"config", "work-dir", "debug", "verbose",
	}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}
}

func TestDownloadCommand_DefaultValues(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)

	// Verify default flag values
	versionFlag := cmd.Flags().Lookup("version")
	assert.Equal(t, "3.22.2", versionFlag.DefValue)

	archFlag := cmd.Flags().Lookup("arch")
	assert.Equal(t, "x86_64", archFlag.DefValue)

	verifyFlag := cmd.Flags().Lookup("verify")
	assert.Equal(t, "true", verifyFlag.DefValue)

	resumeFlag := cmd.Flags().Lookup("resume")
	assert.Equal(t, "true", resumeFlag.DefValue)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	forceFlag := cmd.Flags().Lookup("force")
	assert.Equal(t, "false", forceFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)

	verboseFlag := cmd.Flags().Lookup("verbose")
	assert.Equal(t, "false", verboseFlag.DefValue)
}

func TestRunDownload_ReturnsError(t *testing.T) {
	flags := &downloadFlags{
		url:          "",
		version:      "3.22.2",
		mirror:       "http://mirror.example.com/alpine",
		arch:         "x86_64",
		force:        false,
		verify:       true,
		resumeEnable: true,
	}

	err := runDownload(getTestFlags(), flags)
	require.Error(t, err, "expected error from runDownload (daemon connection required)")

	// Verify it's the expected error type
	_, ok := err.(ErrDaemonConnectionRequired)
	assert.True(t, ok, "expected ErrDaemonConnectionRequired, got %T", err)
}

func TestDownloadFlags_StructFields(t *testing.T) {
	flags := &downloadFlags{
		url:          "https://example.com/alpine.iso",
		version:      "3.21.0",
		mirror:       "https://dl-cdn.alpinelinux.org/alpine",
		arch:         "aarch64",
		force:        true,
		verify:       false,
		resumeEnable: false,
		configFile:   "/etc/config.yaml",
		workDir:      "/tmp/work",
		debug:        true,
		verbose:      true,
	}

	assert.Equal(t, "https://example.com/alpine.iso", flags.url)
	assert.Equal(t, "3.21.0", flags.version)
	assert.Equal(t, "https://dl-cdn.alpinelinux.org/alpine", flags.mirror)
	assert.Equal(t, "aarch64", flags.arch)
	assert.True(t, flags.force)
	assert.False(t, flags.verify)
	assert.False(t, flags.resumeEnable)
	assert.Equal(t, "/etc/config.yaml", flags.configFile)
	assert.Equal(t, "/tmp/work", flags.workDir)
	assert.True(t, flags.debug)
	assert.True(t, flags.verbose)
}

func TestDownloadCommand_HasRunE(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestDownloadCommand_LongDescription(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "SHA256")
	assert.Contains(t, cmd.Long, "checksum")
	assert.Contains(t, cmd.Long, "resuming")
}

func TestDownloadCommand_ExamplesExist(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl iso download")
}
