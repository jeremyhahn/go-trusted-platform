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

package bmc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// NewCommand Tests
// =============================================================================

func TestNewCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "bmc", cmd.Use)
	assert.Equal(t, "Baseboard Management Controller operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage Baseboard Management Controller")

	// Verify all subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 17)

	expectedCommands := map[string]bool{
		"power-on":        false,
		"power-off":       false,
		"power-reset":     false,
		"power-cycle":     false,
		"power-status":    false,
		"set-boot-device": false,
		"get-boot-device": false,
		"mount-iso":       false,
		"unmount-iso":     false,
		"media-status":    false,
		"sensors":         false,
		"system-info":     false,
		"provision":       false,
		"console":         false,
		"cert":            false,
		"enroll":          false,
		"user":            false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

func TestNewCommand_NilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "bmc", cmd.Use)
}

// =============================================================================
// ValidateBMCFlags Tests
// =============================================================================

func TestValidateBMCFlags(t *testing.T) {
	flags := &bmcFlags{
		serverURL: "https://platform:8443",
		profileID: "server-01",
	}

	err := validateBMCFlags(flags)
	assert.NoError(t, err)
}

func TestValidateBMCFlags_MissingServerURL(t *testing.T) {
	flags := &bmcFlags{
		profileID: "server-01",
	}

	err := validateBMCFlags(flags)
	require.Error(t, err)

	var urlErr ErrServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestValidateBMCFlags_MissingProfileID(t *testing.T) {
	flags := &bmcFlags{
		serverURL: "https://platform:8443",
	}

	err := validateBMCFlags(flags)
	require.Error(t, err)

	var pidErr ErrProfileIDRequired
	require.ErrorAs(t, err, &pidErr)
}

// =============================================================================
// BuildURL Tests
// =============================================================================

func TestBuildURL(t *testing.T) {
	url := buildURL("https://platform:8443", "server-01", "power")
	assert.Equal(t, "https://platform:8443/api/v1/bmc/server-01/power", url)
}

func TestBuildURL_TrailingSlash(t *testing.T) {
	url := buildURL("https://platform:8443/", "server-01", "boot")
	assert.Equal(t, "https://platform:8443/api/v1/bmc/server-01/boot", url)
}

func TestBuildURL_MultipleSegments(t *testing.T) {
	url := buildURL("https://platform:8443", "server-01", "media", "status")
	assert.Equal(t, "https://platform:8443/api/v1/bmc/server-01/media/status", url)
}

func TestBuildURL_NoSegments(t *testing.T) {
	url := buildURL("https://platform:8443", "server-01")
	assert.Equal(t, "https://platform:8443/api/v1/bmc/server-01", url)
}

// =============================================================================
// Subcommand Flag Tests
// =============================================================================

func TestPowerOnCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPowerOnCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "power-on", cmd.Use)

	for _, flagName := range []string{"server-url", "profile-id"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestPowerOffCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPowerOffCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "power-off", cmd.Use)
}

func TestPowerResetCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPowerResetCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "power-reset", cmd.Use)
}

func TestPowerCycleCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPowerCycleCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "power-cycle", cmd.Use)
}

func TestPowerStatusCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newPowerStatusCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "power-status", cmd.Use)
}

func TestSetBootDeviceCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSetBootDeviceCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "set-boot-device", cmd.Use)

	for _, flagName := range []string{"server-url", "profile-id", "device", "persistent"} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestGetBootDeviceCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newGetBootDeviceCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "get-boot-device", cmd.Use)
}

func TestMountISOCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newMountISOCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "mount-iso", cmd.Use)

	flag := cmd.Flag("iso-url")
	require.NotNil(t, flag)
}

func TestUnmountISOCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newUnmountISOCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "unmount-iso", cmd.Use)
}

func TestMediaStatusCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newMediaStatusCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "media-status", cmd.Use)
}

func TestSensorsCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSensorsCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "sensors", cmd.Use)
}

func TestSystemInfoCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newSystemInfoCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "system-info", cmd.Use)
}

func TestProvisionCommand_Flags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := newProvisionCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "provision", cmd.Use)

	flag := cmd.Flag("iso-url")
	require.NotNil(t, flag)
}
