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

package entities

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestBMCConfig_Validate(t *testing.T) {
	tests := []struct {
		name   string
		config *BMCConfig
	}{
		{
			name: "valid IPMI config with explicit port",
			config: &BMCConfig{
				Address:  "192.168.1.100",
				Port:     623,
				Username: "admin",
				Password: "secret",
				Protocol: BMCProtocolIPMI,
			},
		},
		{
			name: "valid Redfish config with explicit port",
			config: &BMCConfig{
				Address:  "bmc.example.com",
				Port:     443,
				Username: "root",
				Password: "changeme",
				Protocol: BMCProtocolRedfish,
			},
		},
		{
			name: "valid config with zero port uses default",
			config: &BMCConfig{
				Address:  "10.0.0.50",
				Port:     0,
				Username: "admin",
				Password: "secret",
				Protocol: BMCProtocolIPMI,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestBMCConfig_Validate_MissingAddress(t *testing.T) {
	config := &BMCConfig{
		Address:  "",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: BMCProtocolIPMI,
	}
	err := config.Validate()
	require.Error(t, err)
	var target ErrBMCAddressRequired
	assert.ErrorAs(t, err, &target)
}

func TestBMCConfig_Validate_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{
			name: "negative port",
			port: -1,
		},
		{
			name: "port above max",
			port: 65536,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &BMCConfig{
				Address:  "192.168.1.100",
				Port:     tt.port,
				Username: "admin",
				Password: "secret",
				Protocol: BMCProtocolIPMI,
			}
			err := config.Validate()
			require.Error(t, err)
			var target ErrBMCInvalidPort
			assert.ErrorAs(t, err, &target)
			assert.Equal(t, tt.port, target.Port)
		})
	}
}

func TestBMCConfig_Validate_UnknownProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol BMCProtocol
	}{
		{
			name:     "empty protocol",
			protocol: "",
		},
		{
			name:     "unsupported protocol",
			protocol: "snmp",
		},
		{
			name:     "case sensitive mismatch",
			protocol: "IPMI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &BMCConfig{
				Address:  "192.168.1.100",
				Port:     623,
				Username: "admin",
				Password: "secret",
				Protocol: tt.protocol,
			}
			err := config.Validate()
			require.Error(t, err)
			var target ErrBMCUnknownProtocol
			assert.ErrorAs(t, err, &target)
			assert.Equal(t, string(tt.protocol), target.Protocol)
		})
	}
}

func TestBMCConfig_Validate_MissingUsername(t *testing.T) {
	config := &BMCConfig{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "",
		Password: "secret",
		Protocol: BMCProtocolIPMI,
	}
	err := config.Validate()
	require.Error(t, err)
	var target ErrBMCUsernameRequired
	assert.ErrorAs(t, err, &target)
}

func TestBMCConfig_Validate_MissingPassword(t *testing.T) {
	config := &BMCConfig{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "",
		Protocol: BMCProtocolIPMI,
	}
	err := config.Validate()
	require.Error(t, err)
	var target ErrBMCPasswordRequired
	assert.ErrorAs(t, err, &target)
}

func TestBMCConfig_EffectivePort(t *testing.T) {
	tests := []struct {
		name     string
		config   *BMCConfig
		expected int
	}{
		{
			name: "explicit port returned as-is",
			config: &BMCConfig{
				Port:     8080,
				Protocol: BMCProtocolIPMI,
			},
			expected: 8080,
		},
		{
			name: "zero port returns IPMI default",
			config: &BMCConfig{
				Port:     0,
				Protocol: BMCProtocolIPMI,
			},
			expected: DefaultBMCIPMIPort,
		},
		{
			name: "zero port returns Redfish default",
			config: &BMCConfig{
				Port:     0,
				Protocol: BMCProtocolRedfish,
			},
			expected: DefaultBMCRedfishPort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.EffectivePort())
		})
	}
}

func TestBMCProtocol_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		protocol BMCProtocol
		expected bool
	}{
		{name: "ipmi is valid", protocol: BMCProtocolIPMI, expected: true},
		{name: "redfish is valid", protocol: BMCProtocolRedfish, expected: true},
		{name: "empty is invalid", protocol: "", expected: false},
		{name: "unknown is invalid", protocol: "snmp", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.protocol.IsValid())
		})
	}
}

func TestBMCProtocol_String(t *testing.T) {
	assert.Equal(t, "ipmi", BMCProtocolIPMI.String())
	assert.Equal(t, "redfish", BMCProtocolRedfish.String())
}

func TestBMCProtocol_DefaultPort(t *testing.T) {
	tests := []struct {
		name     string
		protocol BMCProtocol
		expected int
	}{
		{name: "IPMI default port", protocol: BMCProtocolIPMI, expected: 623},
		{name: "Redfish default port", protocol: BMCProtocolRedfish, expected: 443},
		{name: "unknown protocol returns zero", protocol: "snmp", expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.protocol.DefaultPort())
		})
	}
}

func TestBMCConfig_JSONRoundTrip(t *testing.T) {
	original := &BMCConfig{
		Address:  "192.168.1.100",
		Port:     623,
		Username: "admin",
		Password: "secret",
		Protocol: BMCProtocolIPMI,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded BMCConfig
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Address, decoded.Address)
	assert.Equal(t, original.Port, decoded.Port)
	assert.Equal(t, original.Username, decoded.Username)
	assert.Equal(t, original.Password, decoded.Password)
	assert.Equal(t, original.Protocol, decoded.Protocol)
}

func TestBMCConfig_YAMLRoundTrip(t *testing.T) {
	original := &BMCConfig{
		Address:  "bmc.example.com",
		Port:     443,
		Username: "root",
		Password: "changeme",
		Protocol: BMCProtocolRedfish,
	}

	data, err := yaml.Marshal(original)
	require.NoError(t, err)

	var decoded BMCConfig
	err = yaml.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Address, decoded.Address)
	assert.Equal(t, original.Port, decoded.Port)
	assert.Equal(t, original.Username, decoded.Username)
	assert.Equal(t, original.Password, decoded.Password)
	assert.Equal(t, original.Protocol, decoded.Protocol)
}

func TestBMCConfig_ErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{
			name:     "address required",
			err:      ErrBMCAddressRequired{},
			contains: "address is required",
		},
		{
			name:     "invalid port",
			err:      ErrBMCInvalidPort{Port: -1},
			contains: "invalid port -1",
		},
		{
			name:     "unknown protocol",
			err:      ErrBMCUnknownProtocol{Protocol: "snmp"},
			contains: `unknown protocol "snmp"`,
		},
		{
			name:     "username required",
			err:      ErrBMCUsernameRequired{},
			contains: "username is required",
		},
		{
			name:     "password required",
			err:      ErrBMCPasswordRequired{},
			contains: "password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Contains(t, tt.err.Error(), tt.contains)
		})
	}
}

func TestDeviceProfile_BMCField(t *testing.T) {
	profile := &DeviceProfile{
		ID:   1,
		Name: "bare-metal-server",
		BMC: &BMCConfig{
			Address:  "192.168.1.100",
			Port:     623,
			Username: "admin",
			Password: "secret",
			Protocol: BMCProtocolIPMI,
		},
	}

	require.NotNil(t, profile.BMC)
	assert.Equal(t, "192.168.1.100", profile.BMC.Address)
	assert.Equal(t, 623, profile.BMC.Port)
	assert.NoError(t, profile.BMC.Validate())
}

func TestDeviceTemplate_BMCField(t *testing.T) {
	tmpl := &DeviceTemplate{
		ID:   1,
		Name: "bare-metal-template",
		BMC: &BMCConfig{
			Address:  "10.0.0.50",
			Port:     443,
			Username: "root",
			Password: "changeme",
			Protocol: BMCProtocolRedfish,
		},
	}

	require.NotNil(t, tmpl.BMC)
	assert.Equal(t, "10.0.0.50", tmpl.BMC.Address)
	assert.Equal(t, BMCProtocolRedfish, tmpl.BMC.Protocol)
	assert.NoError(t, tmpl.BMC.Validate())
}
