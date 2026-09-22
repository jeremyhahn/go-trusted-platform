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

// =============================================================================
// Command Creation Tests
// =============================================================================

func TestNewFlushCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newFlushCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "flush", cmd.Use)
	assert.Equal(t, "Flush transient TPM contexts", cmd.Short)
	assert.Contains(t, cmd.Long, "Flush all transient TPM contexts")
}

func TestNewDeviceCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newDeviceCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "device", cmd.Use)
	assert.Equal(t, "TPM device information", cmd.Short)

	// Verify subcommands
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 1) // attributes
	assert.Equal(t, "attributes", subcommands[0].Use)
}

func TestNewDeviceAttributesCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newDeviceAttributesCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "attributes", cmd.Use)
	assert.Equal(t, "Get TPM device attributes", cmd.Short)
}

func TestNewInfoCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newInfoCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "info", cmd.Use)
	assert.Equal(t, "Get TPM device information", cmd.Short)
	assert.Contains(t, cmd.Long, "TPM 2.0 device information")
}

func TestNewProvisionCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newProvisionCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "provision", cmd.Use)
	assert.Equal(t, "Provision the TPM with required keys", cmd.Short)

	// Verify flags
	createEKFlag := cmd.Flag("create-ek")
	require.NotNil(t, createEKFlag)
	assert.Equal(t, "true", createEKFlag.DefValue)

	createSRKFlag := cmd.Flag("create-srk")
	require.NotNil(t, createSRKFlag)
	assert.Equal(t, "true", createSRKFlag.DefValue)

	createAKFlag := cmd.Flag("create-ak")
	require.NotNil(t, createAKFlag)
	assert.Equal(t, "true", createAKFlag.DefValue)

	ownerPasswordFlag := cmd.Flag("owner-password")
	require.NotNil(t, ownerPasswordFlag)
	assert.Equal(t, "", ownerPasswordFlag.DefValue)

	endorsementPasswordFlag := cmd.Flag("endorsement-password")
	require.NotNil(t, endorsementPasswordFlag)
	assert.Equal(t, "", endorsementPasswordFlag.DefValue)
}

func TestNewClearCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newClearCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "clear", cmd.Use)
	assert.Equal(t, "Clear the TPM", cmd.Short)
	assert.Contains(t, cmd.Long, "destructive")

	// Verify flags
	ownerPasswordFlag := cmd.Flag("owner-password")
	require.NotNil(t, ownerPasswordFlag)

	confirmFlag := cmd.Flag("confirm")
	require.NotNil(t, confirmFlag)
	assert.Equal(t, "false", confirmFlag.DefValue)
}

func TestNewInstallCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newInstallCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "install", cmd.Use)
	assert.Equal(t, "Safely provision the platform", cmd.Short)
	assert.Contains(t, cmd.Long, "modified version of the TCG")
}

func TestNewDestroyCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newDestroyCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "destroy", cmd.Use)
	assert.Equal(t, "Destroy the platform and clear TPM", cmd.Short)
	assert.Contains(t, cmd.Long, "destructive")
}

func TestNewPolicyCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newPolicyCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "policy", cmd.Use)
	assert.Equal(t, "Platform PCR policy operations", cmd.Short)
}

func TestNewExtendCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newExtendCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "extend", cmd.Use)
	assert.Equal(t, "Extend platform PCR with golden measurement", cmd.Short)
}

func TestNewXKMSCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newXKMSCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "xkms", cmd.Use)
	assert.Equal(t, "TPM XKMS operations", cmd.Short)
}

func TestNewEnrollCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEnrollCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "enroll", cmd.Use)
	assert.Equal(t, "Enroll device using ACME enroll-01 challenge", cmd.Short)
	assert.Contains(t, cmd.Long, "ACME enroll-01 challenge")
}

// =============================================================================
// EK Command Tests
// =============================================================================

func TestNewEKCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEKCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "ek", cmd.Use)
	assert.Equal(t, "Endorsement Key operations", cmd.Short)

	// Verify subcommands
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4) // create, info, certificate, delete

	expectedCommands := map[string]bool{
		"create":      false,
		"info":        false,
		"certificate": false,
		"delete":      false,
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

func TestNewEKCreateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEKCreateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Equal(t, "Create a new Endorsement Key", cmd.Short)

	// Verify flags
	algFlag := cmd.Flag("algorithm")
	require.NotNil(t, algFlag)
	assert.Equal(t, "RSA-2048", algFlag.DefValue)

	persistentFlag := cmd.Flag("persistent")
	require.NotNil(t, persistentFlag)
	assert.Equal(t, "true", persistentFlag.DefValue)
}

func TestNewEKInfoCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEKInfoCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "info", cmd.Use)
	assert.Equal(t, "Get Endorsement Key information", cmd.Short)

	// Verify flags
	handleFlag := cmd.Flag("handle")
	require.NotNil(t, handleFlag)
	assert.Equal(t, "2164326401", handleFlag.DefValue) // 0x81010001
}

func TestNewEKCertificateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEKCertificateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "certificate", cmd.Use)
	assert.Equal(t, "Get Endorsement Key certificate", cmd.Short)
}

func TestNewEKDeleteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEKDeleteCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "delete", cmd.Use)
	assert.Equal(t, "Delete the Endorsement Key", cmd.Short)

	// Verify flags
	handleFlag := cmd.Flag("handle")
	require.NotNil(t, handleFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)
	assert.Equal(t, "", passwordFlag.DefValue)
}

// =============================================================================
// SRK Command Tests
// =============================================================================

func TestNewSRKCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSRKCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "srk", cmd.Use)
	assert.Equal(t, "Storage Root Key operations", cmd.Short)

	// Verify subcommands
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 3) // create, info, delete

	expectedCommands := map[string]bool{
		"create": false,
		"info":   false,
		"delete": false,
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

func TestNewSRKCreateCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSRKCreateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Equal(t, "Create a new Storage Root Key", cmd.Short)

	// Verify flags
	algFlag := cmd.Flag("algorithm")
	require.NotNil(t, algFlag)
	assert.Equal(t, "RSA-2048", algFlag.DefValue)

	persistentFlag := cmd.Flag("persistent")
	require.NotNil(t, persistentFlag)
	assert.Equal(t, "true", persistentFlag.DefValue)

	parentFlag := cmd.Flag("parent")
	require.NotNil(t, parentFlag)

	parentPasswordFlag := cmd.Flag("parent-password")
	require.NotNil(t, parentPasswordFlag)
}

func TestNewSRKInfoCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSRKInfoCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "info", cmd.Use)
	assert.Equal(t, "Get Storage Root Key information", cmd.Short)

	// Verify flags
	handleFlag := cmd.Flag("handle")
	require.NotNil(t, handleFlag)
}

func TestNewSRKDeleteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSRKDeleteCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "delete", cmd.Use)
	assert.Equal(t, "Delete the Storage Root Key", cmd.Short)

	// Verify flags
	handleFlag := cmd.Flag("handle")
	require.NotNil(t, handleFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)
}

// =============================================================================
// Seal/Unseal Command Tests
// =============================================================================

func TestNewSealCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newSealCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "seal", cmd.Use)
	assert.Equal(t, "Seal data to the TPM", cmd.Short)

	// Verify flags
	cnFlag := cmd.Flag("cn")
	require.NotNil(t, cnFlag)

	dataFlag := cmd.Flag("data")
	require.NotNil(t, dataFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)

	parentFlag := cmd.Flag("parent")
	require.NotNil(t, parentFlag)

	pcrsFlag := cmd.Flag("pcrs")
	require.NotNil(t, pcrsFlag)

	pcrBankFlag := cmd.Flag("pcr-bank")
	require.NotNil(t, pcrBankFlag)
	assert.Equal(t, "sha256", pcrBankFlag.DefValue)

	overwriteFlag := cmd.Flag("overwrite")
	require.NotNil(t, overwriteFlag)
	assert.Equal(t, "false", overwriteFlag.DefValue)

	// --policy was accepted and ignored (no request carried it); it is gone
	// rather than wired, PCR binding being --pcrs (#681).
	assert.Nil(t, cmd.Flag("policy"), "the dead --policy flag must not come back")
}

func TestNewUnsealCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newUnsealCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "unseal", cmd.Use)
	assert.Equal(t, "Unseal data from the TPM", cmd.Short)

	// Verify flags
	cnFlag := cmd.Flag("cn")
	require.NotNil(t, cnFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)

	parentFlag := cmd.Flag("parent")
	require.NotNil(t, parentFlag)

	pcrsFlag := cmd.Flag("pcrs")
	require.NotNil(t, pcrsFlag)

	pcrBankFlag := cmd.Flag("pcr-bank")
	require.NotNil(t, pcrBankFlag)
	assert.Equal(t, "sha256", pcrBankFlag.DefValue)
}

// =============================================================================
// Eventlog Command Tests
// =============================================================================

func TestNewEventlogCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newEventlogCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "eventlog", cmd.Use)
	assert.Equal(t, "Get TPM event log", cmd.Short)

	// Verify flags
	formatFlag := cmd.Flag("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "text", formatFlag.DefValue)
}

// =============================================================================
// NVRAM Command Tests
// =============================================================================

func TestNewNVRAMCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newNVRAMCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "nvram", cmd.Use)
	assert.Equal(t, "NVRAM operations", cmd.Short)

	// Verify subcommands
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4) // define, write, read, delete

	expectedCommands := map[string]bool{
		"define": false,
		"write":  false,
		"read":   false,
		"delete": false,
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

func TestNewNVRAMDefineCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newNVRAMDefineCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "define", cmd.Use)
	assert.Equal(t, "Define a new NV index", cmd.Short)

	// Verify flags
	indexFlag := cmd.Flag("index")
	require.NotNil(t, indexFlag)

	sizeFlag := cmd.Flag("size")
	require.NotNil(t, sizeFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)

	attributesFlag := cmd.Flag("attributes")
	require.NotNil(t, attributesFlag)
}

func TestNewNVRAMWriteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newNVRAMWriteCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "write", cmd.Use)
	assert.Equal(t, "Write data to an NV index", cmd.Short)

	// Verify flags
	indexFlag := cmd.Flag("index")
	require.NotNil(t, indexFlag)

	dataFlag := cmd.Flag("data")
	require.NotNil(t, dataFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)

	offsetFlag := cmd.Flag("offset")
	require.NotNil(t, offsetFlag)
	assert.Equal(t, "0", offsetFlag.DefValue)
}

func TestNewNVRAMReadCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newNVRAMReadCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "read", cmd.Use)
	assert.Equal(t, "Read data from an NV index", cmd.Short)

	// Verify flags
	indexFlag := cmd.Flag("index")
	require.NotNil(t, indexFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)

	offsetFlag := cmd.Flag("offset")
	require.NotNil(t, offsetFlag)
	assert.Equal(t, "0", offsetFlag.DefValue)

	sizeFlag := cmd.Flag("size")
	require.NotNil(t, sizeFlag)
	assert.Equal(t, "0", sizeFlag.DefValue)

	hexFlag := cmd.Flag("hex")
	require.NotNil(t, hexFlag)
	assert.Equal(t, "false", hexFlag.DefValue)
}

func TestNewNVRAMDeleteCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newNVRAMDeleteCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "delete", cmd.Use)
	assert.Equal(t, "Delete (undefine) an NV index", cmd.Short)

	// Verify flags
	indexFlag := cmd.Flag("index")
	require.NotNil(t, indexFlag)

	passwordFlag := cmd.Flag("password")
	require.NotNil(t, passwordFlag)
}
