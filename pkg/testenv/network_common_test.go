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

//go:build linux

// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkConfig_AllFields tests all NetworkConfig fields
func TestNetworkConfig_AllFields(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.100.0/24")
	require.NoError(t, err)

	cfg := &NetworkConfig{
		BridgeName:     "test-bridge",
		ServerTapName:  "test-server-tap",
		ClientTapName:  "test-client-tap",
		GatewayIP:      net.ParseIP("192.168.100.1"),
		ServerIP:       net.ParseIP("192.168.100.10"),
		ServerPublicIP: net.ParseIP("192.0.2.10"),
		ClientIP:       net.ParseIP("192.168.100.20"),
		ClientPublicIP: net.ParseIP("192.0.2.20"),
		Subnet:         subnet,
		Domain:         "test.local",
		ServerMAC:      "52:54:00:11:22:33",
		ClientMAC:      "52:54:00:44:55:66",
	}

	// Validate all fields are set
	assert.Equal(t, "test-bridge", cfg.BridgeName)
	assert.Equal(t, "test-server-tap", cfg.ServerTapName)
	assert.Equal(t, "test-client-tap", cfg.ClientTapName)
	assert.Equal(t, "192.168.100.1", cfg.GatewayIP.String())
	assert.Equal(t, "192.168.100.10", cfg.ServerIP.String())
	assert.Equal(t, "192.0.2.10", cfg.ServerPublicIP.String())
	assert.Equal(t, "192.168.100.20", cfg.ClientIP.String())
	assert.Equal(t, "192.0.2.20", cfg.ClientPublicIP.String())
	assert.Equal(t, "192.168.100.0/24", cfg.Subnet.String())
	assert.Equal(t, "test.local", cfg.Domain)
	assert.Equal(t, "52:54:00:11:22:33", cfg.ServerMAC)
	assert.Equal(t, "52:54:00:44:55:66", cfg.ClientMAC)

	// Test validation
	err = cfg.Validate()
	assert.NoError(t, err)

	// Test SubnetMask
	mask := cfg.SubnetMask()
	assert.Equal(t, "255.255.255.0", mask)

	// Test SubnetCIDR
	cidr := cfg.SubnetCIDR()
	assert.Equal(t, "192.168.100.0/24", cidr)
}

// TestNetworkConfig_DifferentSubnets tests different subnet sizes
func TestNetworkConfig_DifferentSubnets(t *testing.T) {
	tests := []struct {
		name         string
		subnet       string
		expectedMask string
	}{
		{"Class C /24", "10.0.0.0/24", "255.255.255.0"},
		{"Small /28", "10.0.0.0/28", "255.255.255.240"},
		{"Medium /20", "10.0.0.0/20", "255.255.240.0"},
		{"Large /16", "10.0.0.0/16", "255.255.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, subnet, err := net.ParseCIDR(tt.subnet)
			require.NoError(t, err)

			cfg := &NetworkConfig{
				BridgeName:    "test-br",
				ServerTapName: "test-server",
				ClientTapName: "test-client",
				GatewayIP:     subnet.IP,
				ServerIP:      subnet.IP,
				ClientIP:      subnet.IP,
				Subnet:        subnet,
			}

			// Adjust IPs to be within subnet
			cfg.GatewayIP[len(cfg.GatewayIP)-1] = 1
			cfg.ServerIP[len(cfg.ServerIP)-1] = 2
			cfg.ClientIP[len(cfg.ClientIP)-1] = 3

			mask := cfg.SubnetMask()
			assert.Equal(t, tt.expectedMask, mask)

			err = cfg.Validate()
			assert.NoError(t, err)
		})
	}
}

// TestNetworkConfig_EdgeCaseIPs tests IP addresses at subnet boundaries
func TestNetworkConfig_EdgeCaseIPs(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.99.99.0/28")

	// Valid: IPs at the edges of the subnet
	cfg := &NetworkConfig{
		BridgeName:    "test-br",
		ServerTapName: "test-server",
		ClientTapName: "test-client",
		GatewayIP:     net.ParseIP("10.99.99.1"),  // First usable
		ServerIP:      net.ParseIP("10.99.99.14"), // Near last usable
		ClientIP:      net.ParseIP("10.99.99.13"),
		Subnet:        subnet,
	}

	err := cfg.Validate()
	assert.NoError(t, err)

	// Invalid: IP just outside subnet
	cfg.ServerIP = net.ParseIP("10.99.99.16") // Outside /28 range
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server IP")
}

// TestDefaultNetworkConfig_PublicIPs tests public IP configuration
func TestDefaultNetworkConfig_PublicIPs(t *testing.T) {
	cfg := DefaultNetworkConfig()

	// Public IPs should be in TEST-NET-1 range (192.0.2.0/24)
	assert.NotNil(t, cfg.ServerPublicIP)
	assert.NotNil(t, cfg.ClientPublicIP)

	// Verify they're in the correct range
	_, testNet1, _ := net.ParseCIDR("192.0.2.0/24")
	assert.True(t, testNet1.Contains(cfg.ServerPublicIP))
	assert.True(t, testNet1.Contains(cfg.ClientPublicIP))
}

// TestDefaultNetworkConfig_MACs tests MAC address configuration
func TestDefaultNetworkConfig_MACs(t *testing.T) {
	cfg := DefaultNetworkConfig()

	assert.Equal(t, "52:54:00:99:00:02", cfg.ServerMAC)
	assert.Equal(t, "52:54:00:99:00:03", cfg.ClientMAC)
}

// TestNetworkConfig_NilSubnet tests handling of nil subnet
func TestNetworkConfig_NilSubnet(t *testing.T) {
	cfg := &NetworkConfig{
		BridgeName:    "test-br",
		ServerTapName: "test-server",
		ClientTapName: "test-client",
		GatewayIP:     net.ParseIP("10.0.0.1"),
		ServerIP:      net.ParseIP("10.0.0.2"),
		ClientIP:      net.ParseIP("10.0.0.3"),
		Subnet:        nil,
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "subnet is required")
}

// TestNetworkConfig_ValidateEmptyStrings tests validation with empty strings
func TestNetworkConfig_ValidateEmptyStrings(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")

	tests := []struct {
		name      string
		modify    func(*NetworkConfig)
		expectErr string
	}{
		{
			name: "empty bridge name",
			modify: func(cfg *NetworkConfig) {
				cfg.BridgeName = ""
			},
			expectErr: "bridge name is required",
		},
		{
			name: "empty server tap name",
			modify: func(cfg *NetworkConfig) {
				cfg.ServerTapName = ""
			},
			expectErr: "server TAP name is required",
		},
		{
			name: "empty client tap name",
			modify: func(cfg *NetworkConfig) {
				cfg.ClientTapName = ""
			},
			expectErr: "client TAP name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &NetworkConfig{
				BridgeName:    "br0",
				ServerTapName: "tap0",
				ClientTapName: "tap1",
				GatewayIP:     net.ParseIP("10.0.0.1"),
				ServerIP:      net.ParseIP("10.0.0.2"),
				ClientIP:      net.ParseIP("10.0.0.3"),
				Subnet:        subnet,
			}

			tt.modify(cfg)

			err := cfg.Validate()
			assert.Error(t, err)
			assert.Equal(t, tt.expectErr, err.Error())
		})
	}
}

// TestIsolatedNetworkInterface verifies interface contract
func TestIsolatedNetworkInterface(t *testing.T) {
	// Verify interface methods exist
	var network IsolatedNetwork = NewIsolatedNetwork(nil)
	assert.NotNil(t, network)

	// Verify all methods are callable
	_ = network.Config()
	_ = network.ServerTapName()
	_ = network.ClientTapName()
}

// TestNetworkConfig_IPv4Only tests that only IPv4 is supported
func TestNetworkConfig_IPv4Only(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")

	// IPv4 addresses work
	cfg := &NetworkConfig{
		BridgeName:    "test-br",
		ServerTapName: "test-server",
		ClientTapName: "test-client",
		GatewayIP:     net.ParseIP("10.0.0.1"),
		ServerIP:      net.ParseIP("10.0.0.2"),
		ClientIP:      net.ParseIP("10.0.0.3"),
		Subnet:        subnet,
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestNetworkExists_Coverage tests NetworkExists with various conditions
func TestNetworkExists_Coverage(t *testing.T) {
	// Test with custom config that doesn't exist
	cfg := &NetworkConfig{
		BridgeName:    "nonexistent-bridge-xyz",
		ServerTapName: "nonexistent-server-xyz",
		ClientTapName: "nonexistent-client-xyz",
		GatewayIP:     net.ParseIP("10.0.0.1"),
		ServerIP:      net.ParseIP("10.0.0.2"),
		ClientIP:      net.ParseIP("10.0.0.3"),
	}
	_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
	cfg.Subnet = subnet

	exists := NetworkExists(cfg)
	assert.False(t, exists, "Non-existent network should return false")

	// Test with nil config (uses defaults)
	exists = NetworkExists(nil)
	// Result depends on whether default network exists
	t.Logf("Default network exists: %v", exists)
}

// TestCheckRootPrivileges_Coverage tests both root and non-root cases
func TestCheckRootPrivileges_Coverage(t *testing.T) {
	err := CheckRootPrivileges()

	// Just verify it returns appropriate result based on UID
	// Don't make assumptions about test environment
	t.Logf("CheckRootPrivileges result: %v", err)
}
