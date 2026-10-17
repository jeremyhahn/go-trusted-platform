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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
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
	cmd := newProfileListCommand(getTestFlags)
	require.NotNil(t, cmd, "newProfileListCommand returned nil")
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List available installation profiles", cmd.Short)
	assert.Contains(t, cmd.Aliases, "ls")
	assert.Contains(t, cmd.Long, "production")
	assert.Contains(t, cmd.Long, "fips")
}

func TestProfileShowCommand_Creation(t *testing.T) {
	cmd := newProfileShowCommand(getTestFlags)
	require.NotNil(t, cmd, "newProfileShowCommand returned nil")
	assert.Equal(t, "show <profile-name>", cmd.Use)
	assert.Equal(t, "Show installation profile configuration", cmd.Short)
}

func TestProfileValidateCommand_Creation(t *testing.T) {
	cmd := newProfileValidateCommand(getTestFlags)
	require.NotNil(t, cmd, "newProfileValidateCommand returned nil")
	assert.Equal(t, "validate <config-file>", cmd.Use)
	assert.Contains(t, cmd.Short, "Validate")
}

func TestProfileGenerateCommand_Flags(t *testing.T) {
	cmd := newProfileGenerateCommand(getTestFlags)
	require.NotNil(t, cmd, "newProfileGenerateCommand returned nil")
	assert.Equal(t, "generate", cmd.Use)

	for _, name := range []string{"profile", "output", "device"} {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "expected flag '%s' to be defined", name)
		assert.Equal(t, "", flag.DefValue, "flag %s", name)
	}
	assert.Equal(t, "p", cmd.Flags().Lookup("profile").Shorthand)
	assert.Equal(t, "o", cmd.Flags().Lookup("output").Shorthand)

	// The "(future)" interactive mode was a no-op and is gone.
	assert.Nil(t, cmd.Flags().Lookup("interactive"))
}

func TestRunProfileList_ReportsEveryProfilePosture(t *testing.T) {
	out := new(bytes.Buffer)
	require.NoError(t, runProfileList(getJSONTestFlags(), out))

	var result profileListResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	assert.True(t, result.Success)

	byName := map[string]profileSummary{}
	for _, summary := range result.Profiles {
		byName[summary.Name] = summary
	}
	require.Len(t, byName, 4)
	for _, name := range []string{"dev", "production", "fips", "production-hs"} {
		require.Contains(t, byName, name)
		assert.NotEmpty(t, byName[name].Description, "profile %s", name)
	}

	assert.False(t, byName["dev"].FIPS)
	assert.Equal(t, "none", byName["dev"].Lockdown)
	assert.True(t, byName["production"].TPMUnseal)
	assert.True(t, byName["production"].LUKS)
	assert.Equal(t, "integrity", byName["production"].Lockdown)
	assert.True(t, byName["fips"].FIPS)
	assert.True(t, byName["production-hs"].FIPS)
	assert.Equal(t, "confidentiality", byName["production-hs"].Lockdown)
}

func TestRunProfileShow_RendersInstallConfig(t *testing.T) {
	out := new(bytes.Buffer)
	require.NoError(t, runProfileShow(getJSONTestFlags(), "production", out))

	var result profileShowResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	assert.True(t, result.Success)
	assert.Equal(t, "production", result.Profile.Name)
	assert.True(t, result.Profile.LUKS)

	// The rendered YAML is an install configuration the installer accepts.
	path := filepath.Join(t.TempDir(), "production.yaml")
	require.NoError(t, os.WriteFile(path, []byte(result.YAML), 0o600))
	require.NoError(t, runProfileValidate(getJSONTestFlags(), path, new(bytes.Buffer)))
}

func TestRunProfileShow_UnknownProfile(t *testing.T) {
	err := runProfileShow(getJSONTestFlags(), "nonexistent", new(bytes.Buffer))
	require.Error(t, err)

	var notFound ErrProfileNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "nonexistent", notFound.ProfileName)
}

func TestRunProfileGenerate_WritesConfigWithDeviceOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prod.yaml")
	flags := &generateProfileFlags{
		profileName:    "production",
		outputFile:     path,
		overrideDevice: "/dev/nvme0n1",
	}

	out := new(bytes.Buffer)
	require.NoError(t, runProfileGenerate(getJSONTestFlags(), flags, out))

	var result profileGenerateResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	assert.True(t, result.Success)
	assert.Equal(t, path, result.OutputFile)
	assert.Contains(t, result.YAML, "/dev/nvme0n1")

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, result.YAML, string(written))

	validateOut := new(bytes.Buffer)
	require.NoError(t, runProfileValidate(getJSONTestFlags(), path, validateOut))
	var validation profileValidateResult
	require.NoError(t, json.Unmarshal(validateOut.Bytes(), &validation), validateOut.String())
	assert.True(t, validation.Valid)
	assert.Empty(t, validation.Errors)
}

func TestRunProfileGenerate_StdoutOnly(t *testing.T) {
	flags := &generateProfileFlags{profileName: "dev"}

	out := new(bytes.Buffer)
	require.NoError(t, runProfileGenerate(getJSONTestFlags(), flags, out))

	var result profileGenerateResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	assert.Empty(t, result.OutputFile)
	assert.NotEmpty(t, result.YAML)
}

func TestRunProfileGenerate_UnknownProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.yaml")
	flags := &generateProfileFlags{profileName: "nonexistent", outputFile: path}

	err := runProfileGenerate(getJSONTestFlags(), flags, new(bytes.Buffer))
	require.Error(t, err)

	var notFound ErrProfileNotFound
	require.ErrorAs(t, err, &notFound)
	assert.NoFileExists(t, path)
}

func TestRunProfileGenerate_UnwritableOutput(t *testing.T) {
	flags := &generateProfileFlags{
		profileName: "dev",
		outputFile:  filepath.Join(t.TempDir(), "missing-dir", "out.yaml"),
	}

	err := runProfileGenerate(getJSONTestFlags(), flags, new(bytes.Buffer))
	require.Error(t, err)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
}

func TestRunProfileValidate_InvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte("disk: [not, a, mapping\n"), 0o600))

	out := new(bytes.Buffer)
	err := runProfileValidate(getJSONTestFlags(), path, out)
	require.Error(t, err)

	var failed ErrConfigValidationFailed
	require.ErrorAs(t, err, &failed)

	var result profileValidateResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	assert.True(t, result.Success)
	assert.False(t, result.Valid)
	require.Len(t, result.Errors, 1)
	assert.Equal(t, failed.Reason, result.Errors[0])
}

func TestRunProfileValidate_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")

	out := new(bytes.Buffer)
	err := runProfileValidate(getJSONTestFlags(), path, out)
	require.Error(t, err)

	var parseErr ErrConfigParseError
	require.ErrorAs(t, err, &parseErr)
	assert.Equal(t, path, parseErr.Path)
	assert.Empty(t, out.String(), "nothing is printed for a file that cannot be read")
}

func TestSummarizeProfile_EmptyConfig(t *testing.T) {
	summary := summarizeProfile("bare", "no sections", &installer.Config{})
	assert.Equal(t, profileSummary{Name: "bare", Description: "no sections", Lockdown: "none"}, summary)
}
