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

package tpm

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
	assert.Equal(t, "tpm", cmd.Use)
	assert.Equal(t, "TPM device identity operations", cmd.Short)

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 21) // all TPM subcommands

	// Verify key subcommands exist
	expectedCommands := map[string]bool{
		"idevid":    false,
		"iak":       false,
		"flush":     false,
		"device":    false,
		"info":      false,
		"status":    false,
		"provision": false,
		"clear":     false,
		"install":   false,
		"destroy":   false,
		"policy":    false,
		"extend":    false,
		"xkms":      false,
		"ek":        false,
		"srk":       false,
		"seal":      false,
		"unseal":    false,
		"eventlog":  false,
		"nvram":     false,
		"enroll":    false,
		"certify":   false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmd, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmd)
	}
}

func TestNewIDevIDCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewIDevIDCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "idevid", cmd.Use)
	assert.Equal(t, "Manage IDevID (Initial Device Identifier) keys", cmd.Short)

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 7) // generate, info, delete, csr, install, cert, ldevid

	// Find all commands
	var hasGenerate, hasInfo, hasDelete, hasCSR, hasInstall, hasCert bool
	for _, sub := range subcommands {
		switch sub.Use {
		case "generate":
			hasGenerate = true
			// Verify flags
			algFlag := sub.Flag("algorithm")
			require.NotNil(t, algFlag)
			assert.Equal(t, "ECDSA-P256", algFlag.DefValue)

			overwriteFlag := sub.Flag("overwrite")
			require.NotNil(t, overwriteFlag)
			assert.Equal(t, "false", overwriteFlag.DefValue)
		case "info":
			hasInfo = true
		case "delete":
			hasDelete = true
		case "csr":
			hasCSR = true
			// Verify CSR flags
			cnFlag := sub.Flag("common-name")
			require.NotNil(t, cnFlag)
			orgFlag := sub.Flag("organization")
			require.NotNil(t, orgFlag)
			countryFlag := sub.Flag("country")
			require.NotNil(t, countryFlag)
			stateFlag := sub.Flag("state")
			require.NotNil(t, stateFlag)
			localityFlag := sub.Flag("locality")
			require.NotNil(t, localityFlag)
			orgUnitFlag := sub.Flag("organizational-unit")
			require.NotNil(t, orgUnitFlag)
		case "install":
			hasInstall = true
			// Verify install flags
			certFileFlag := sub.Flag("cert-file")
			require.NotNil(t, certFileFlag)
		case "certificate":
			hasCert = true
		}
	}

	assert.True(t, hasGenerate, "generate subcommand should exist")
	assert.True(t, hasInfo, "info subcommand should exist")
	assert.True(t, hasDelete, "delete subcommand should exist")
	assert.True(t, hasCSR, "csr subcommand should exist")
	assert.True(t, hasInstall, "install subcommand should exist")
	assert.True(t, hasCert, "certificate subcommand should exist")
}

func TestNewIAKCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewIAKCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "iak", cmd.Use)
	assert.Equal(t, "Manage IAK (Initial Attestation Key) keys", cmd.Short)

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 6) // generate, info, delete, csr, install, cert

	// Find all commands
	var hasGenerate, hasInfo, hasDelete, hasCSR, hasInstall, hasCert bool
	for _, sub := range subcommands {
		switch sub.Use {
		case "generate":
			hasGenerate = true
			// Verify flags
			algFlag := sub.Flag("algorithm")
			require.NotNil(t, algFlag)
			assert.Equal(t, "ECDSA-P256", algFlag.DefValue)

			overwriteFlag := sub.Flag("overwrite")
			require.NotNil(t, overwriteFlag)
			assert.Equal(t, "false", overwriteFlag.DefValue)
		case "info":
			hasInfo = true
		case "delete":
			hasDelete = true
		case "csr":
			hasCSR = true
			// Verify CSR flags
			cnFlag := sub.Flag("common-name")
			require.NotNil(t, cnFlag)
			orgFlag := sub.Flag("organization")
			require.NotNil(t, orgFlag)
			countryFlag := sub.Flag("country")
			require.NotNil(t, countryFlag)
			stateFlag := sub.Flag("state")
			require.NotNil(t, stateFlag)
			localityFlag := sub.Flag("locality")
			require.NotNil(t, localityFlag)
			orgUnitFlag := sub.Flag("organizational-unit")
			require.NotNil(t, orgUnitFlag)
		case "install":
			hasInstall = true
			// Verify install flags
			certFileFlag := sub.Flag("cert-file")
			require.NotNil(t, certFileFlag)
		case "certificate":
			hasCert = true
		}
	}

	assert.True(t, hasGenerate, "generate subcommand should exist")
	assert.True(t, hasInfo, "info subcommand should exist")
	assert.True(t, hasDelete, "delete subcommand should exist")
	assert.True(t, hasCSR, "csr subcommand should exist")
	assert.True(t, hasInstall, "install subcommand should exist")
	assert.True(t, hasCert, "certificate subcommand should exist")
}
