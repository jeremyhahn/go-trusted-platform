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

package testenv

import (
	"net"
	"testing"
)

func TestDefaultNetworkConfig(t *testing.T) {
	cfg := DefaultNetworkConfig()

	if cfg == nil {
		t.Fatal("DefaultNetworkConfig returned nil")
	}

	// Verify default values
	if cfg.BridgeName != "tp-br" {
		t.Errorf("expected bridge name 'tp-br', got '%s'", cfg.BridgeName)
	}

	if cfg.ServerTapName != "tap-tp-server" {
		t.Errorf("expected server TAP name 'tap-tp-server', got '%s'", cfg.ServerTapName)
	}

	if cfg.ClientTapName != "tap-tp-client" {
		t.Errorf("expected client TAP name 'tap-tp-client', got '%s'", cfg.ClientTapName)
	}

	expectedGateway := net.ParseIP("10.99.99.1")
	if !cfg.GatewayIP.Equal(expectedGateway) {
		t.Errorf("expected gateway IP %s, got %s", expectedGateway, cfg.GatewayIP)
	}

	expectedServer := net.ParseIP("10.99.99.2")
	if !cfg.ServerIP.Equal(expectedServer) {
		t.Errorf("expected server IP %s, got %s", expectedServer, cfg.ServerIP)
	}

	expectedClient := net.ParseIP("10.99.99.3")
	if !cfg.ClientIP.Equal(expectedClient) {
		t.Errorf("expected client IP %s, got %s", expectedClient, cfg.ClientIP)
	}

	if cfg.Domain != "example.internal" {
		t.Errorf("expected domain 'example.internal', got '%s'", cfg.Domain)
	}

	// Verify subnet
	_, expectedSubnet, _ := net.ParseCIDR("10.99.99.0/28")
	if cfg.Subnet.String() != expectedSubnet.String() {
		t.Errorf("expected subnet %s, got %s", expectedSubnet, cfg.Subnet)
	}
}

func TestNetworkConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(*NetworkConfig)
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid config",
			modify:    func(cfg *NetworkConfig) {},
			expectErr: false,
		},
		{
			name: "missing bridge name",
			modify: func(cfg *NetworkConfig) {
				cfg.BridgeName = ""
			},
			expectErr: true,
			errMsg:    "bridge name is required",
		},
		{
			name: "missing server TAP name",
			modify: func(cfg *NetworkConfig) {
				cfg.ServerTapName = ""
			},
			expectErr: true,
			errMsg:    "server TAP name is required",
		},
		{
			name: "missing client TAP name",
			modify: func(cfg *NetworkConfig) {
				cfg.ClientTapName = ""
			},
			expectErr: true,
			errMsg:    "client TAP name is required",
		},
		{
			name: "missing gateway IP",
			modify: func(cfg *NetworkConfig) {
				cfg.GatewayIP = nil
			},
			expectErr: true,
			errMsg:    "gateway IP is required",
		},
		{
			name: "missing server IP",
			modify: func(cfg *NetworkConfig) {
				cfg.ServerIP = nil
			},
			expectErr: true,
			errMsg:    "server IP is required",
		},
		{
			name: "missing client IP",
			modify: func(cfg *NetworkConfig) {
				cfg.ClientIP = nil
			},
			expectErr: true,
			errMsg:    "client IP is required",
		},
		{
			name: "missing subnet",
			modify: func(cfg *NetworkConfig) {
				cfg.Subnet = nil
			},
			expectErr: true,
			errMsg:    "subnet is required",
		},
		{
			name: "gateway IP outside subnet",
			modify: func(cfg *NetworkConfig) {
				cfg.GatewayIP = net.ParseIP("192.168.1.1")
			},
			expectErr: true,
			errMsg:    "gateway IP 192.168.1.1 is not within subnet",
		},
		{
			name: "server IP outside subnet",
			modify: func(cfg *NetworkConfig) {
				cfg.ServerIP = net.ParseIP("192.168.1.2")
			},
			expectErr: true,
			errMsg:    "server IP 192.168.1.2 is not within subnet",
		},
		{
			name: "client IP outside subnet",
			modify: func(cfg *NetworkConfig) {
				cfg.ClientIP = net.ParseIP("192.168.1.3")
			},
			expectErr: true,
			errMsg:    "client IP 192.168.1.3 is not within subnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultNetworkConfig()
			tt.modify(cfg)

			err := cfg.Validate()

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got nil")
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					// Check if error message contains expected substring
					if !containsString(err.Error(), tt.errMsg) {
						t.Errorf("expected error containing '%s', got '%s'", tt.errMsg, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestNetworkConfigSubnetMask(t *testing.T) {
	cfg := DefaultNetworkConfig()

	// /28 subnet should have mask 255.255.255.240
	expectedMask := "255.255.255.240"
	mask := cfg.SubnetMask()

	if mask != expectedMask {
		t.Errorf("expected subnet mask %s, got %s", expectedMask, mask)
	}
}

func TestNetworkConfigSubnetCIDR(t *testing.T) {
	cfg := DefaultNetworkConfig()

	expectedCIDR := "10.99.99.0/28"
	cidr := cfg.SubnetCIDR()

	if cidr != expectedCIDR {
		t.Errorf("expected subnet CIDR %s, got %s", expectedCIDR, cidr)
	}
}

func TestNewIsolatedNetwork(t *testing.T) {
	// Test with nil config (should use defaults)
	net1 := NewIsolatedNetwork(nil)
	if net1 == nil {
		t.Fatal("NewIsolatedNetwork with nil config returned nil")
	}
	if net1.Config().BridgeName != "tp-br" {
		t.Error("NewIsolatedNetwork with nil config did not use defaults")
	}

	// Test with custom config
	customCfg := &NetworkConfig{
		BridgeName:    "custom-br",
		ServerTapName: "tap-custom-server",
		ClientTapName: "tap-custom-client",
		GatewayIP:     net.ParseIP("10.99.99.1"),
		ServerIP:      net.ParseIP("10.99.99.2"),
		ClientIP:      net.ParseIP("10.99.99.3"),
		Subnet:        func() *net.IPNet { _, s, _ := net.ParseCIDR("10.99.99.0/28"); return s }(),
		Domain:        "test.internal",
	}

	net2 := NewIsolatedNetwork(customCfg)
	if net2 == nil {
		t.Fatal("NewIsolatedNetwork with custom config returned nil")
	}
	if net2.Config().BridgeName != "custom-br" {
		t.Error("NewIsolatedNetwork did not use custom config")
	}
}

func TestIsolatedNetworkTapNames(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	if network.ServerTapName() != cfg.ServerTapName {
		t.Errorf("ServerTapName() returned %s, expected %s", network.ServerTapName(), cfg.ServerTapName)
	}

	if network.ClientTapName() != cfg.ClientTapName {
		t.Errorf("ClientTapName() returned %s, expected %s", network.ClientTapName(), cfg.ClientTapName)
	}
}

// containsString checks if s contains substr
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
