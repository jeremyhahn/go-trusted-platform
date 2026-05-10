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

package switchcmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewCommand_HasExpectedSubcommands(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
	assert.Equal(t, "switch", cmd.Use)

	subcommands := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		subcommands[sub.Use] = true
	}

	assert.True(t, subcommands["list-ports"], "should have list-ports subcommand")
	assert.True(t, subcommands["port-status"], "should have port-status subcommand")
	assert.True(t, subcommands["set-vlan"], "should have set-vlan subcommand")
	assert.True(t, subcommands["enable-port"], "should have enable-port subcommand")
	assert.True(t, subcommands["disable-port"], "should have disable-port subcommand")
}

func TestNewSwitchClient_MissingServerURL(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "",
		switchName: "core-01",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	_, err := newSwitchClient(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrServerURLRequired{}, err)
}

func TestNewSwitchClient_Success(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	client, err := newSwitchClient(flags, getFlags)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestRunListPorts_MissingSwitchName(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runListPorts(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrSwitchNameRequired{}, err)
}

func TestRunPortStatus_MissingSwitchName(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "",
		port:       "Eth1/3",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runPortStatus(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrSwitchNameRequired{}, err)
}

func TestRunPortStatus_MissingPort(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runPortStatus(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrPortNameRequired{}, err)
}

func TestRunSetVLAN_MissingSwitch(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "",
		port:       "Eth1/3",
		vlan:       100,
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runSetVLAN(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrSwitchNameRequired{}, err)
}

func TestRunSetVLAN_MissingPort(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "",
		vlan:       100,
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runSetVLAN(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrPortNameRequired{}, err)
}

func TestRunSetVLAN_MissingVLAN(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "Eth1/3",
		vlan:       0,
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runSetVLAN(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrVLANIDRequired{}, err)
}

func TestRunSetVLAN_InvalidVLAN(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "Eth1/3",
		vlan:       5000,
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runSetVLAN(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrInvalidVLANID{}, err)
}

func TestRunEnablePort_MissingSwitch(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "",
		port:       "Eth1/3",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runEnablePort(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrSwitchNameRequired{}, err)
}

func TestRunEnablePort_MissingPort(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runEnablePort(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrPortNameRequired{}, err)
}

func TestRunDisablePort_MissingSwitch(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "",
		port:       "Eth1/3",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runDisablePort(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrSwitchNameRequired{}, err)
}

func TestRunDisablePort_MissingPort(t *testing.T) {
	flags := &switchFlags{
		serverURL:  "https://example.com",
		switchName: "core-01",
		port:       "",
	}
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	err := runDisablePort(flags, getFlags)
	assert.Error(t, err)
	assert.IsType(t, ErrPortNameRequired{}, err)
}

func TestBuildHTTPClient_NilFlags(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	client, err := buildHTTPClient(getFlags)
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestBuildHTTPClient_NoRemoteContext(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	client, err := buildHTTPClient(getFlags)
	require.NoError(t, err)
	assert.NotNil(t, client)
}
