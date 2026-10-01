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
	"testing"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

func TestErrInvalidNetworkPhase_Error(t *testing.T) {
	err := &ErrInvalidNetworkPhase{
		Phase:  "provisioning",
		Reason: "missing DHCP pool",
	}
	expected := "invalid network phase provisioning: missing DHCP pool"
	if err.Error() != expected {
		t.Errorf("ErrInvalidNetworkPhase.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestErrMissingNetworkConfig_Error(t *testing.T) {
	err := &ErrMissingNetworkConfig{
		Phase: "admitted",
	}
	expected := "missing network configuration for phase: admitted"
	if err.Error() != expected {
		t.Errorf("ErrMissingNetworkConfig.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestErrInvalidIPAddress_Error(t *testing.T) {
	err := &ErrInvalidIPAddress{
		Address: "192.168.1.999",
		Reason:  "invalid octet",
	}
	expected := "invalid IP address 192.168.1.999: invalid octet"
	if err.Error() != expected {
		t.Errorf("ErrInvalidIPAddress.Error() = %v, want %v", err.Error(), expected)
	}
}

func TestNewProfileNetworkBuilder(t *testing.T) {
	tests := []struct {
		name       string
		baseConfig *NetworkConfig
	}{
		{
			name:       "with nil base config",
			baseConfig: nil,
		},
		{
			name:       "with default base config",
			baseConfig: DefaultNetworkConfig(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewProfileNetworkBuilder(tt.baseConfig)
			if builder == nil {
				t.Fatal("NewProfileNetworkBuilder() returned nil")
			}
			if builder.baseConfig != tt.baseConfig {
				t.Errorf("NewProfileNetworkBuilder() baseConfig = %v, want %v", builder.baseConfig, tt.baseConfig)
			}
		})
	}
}

func TestProfileNetworkBuilder_WithServerProfile(t *testing.T) {
	builder := NewProfileNetworkBuilder(nil)
	profile := &deviceentities.DeviceProfile{
		Name: "test-server",
		Role: deviceentities.DeviceRoleServer,
	}

	result := builder.WithServerProfile(profile)
	if result == nil {
		t.Fatal("WithServerProfile() returned nil")
	}
	if result.serverProfile != profile {
		t.Errorf("WithServerProfile() serverProfile = %v, want %v", result.serverProfile, profile)
	}
	if result != builder {
		t.Errorf("WithServerProfile() should return the same builder instance")
	}
}

func TestProfileNetworkBuilder_WithClientProfile(t *testing.T) {
	builder := NewProfileNetworkBuilder(nil)
	profile := &deviceentities.DeviceProfile{
		Name: "test-client",
		Role: deviceentities.DeviceRoleClient,
	}

	result := builder.WithClientProfile(profile)
	if result == nil {
		t.Fatal("WithClientProfile() returned nil")
	}
	if result.clientProfile != profile {
		t.Errorf("WithClientProfile() clientProfile = %v, want %v", result.clientProfile, profile)
	}
	if result != builder {
		t.Errorf("WithClientProfile() should return the same builder instance")
	}
}

func TestProfileNetworkBuilder_Build_Success(t *testing.T) {
	tests := []struct {
		name          string
		serverProfile *deviceentities.DeviceProfile
		clientProfile *deviceentities.DeviceProfile
		baseConfig    *NetworkConfig
		validate      func(t *testing.T, cfg *NetworkConfig)
	}{
		{
			name: "full profiles with static IPs",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Role: deviceentities.DeviceRoleServer,
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						VLAN:     100,
						StaticIP: "10.0.0.2",
						Gateway:  "10.0.0.1",
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network: "10.0.0.0/24",
						},
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Role: deviceentities.DeviceRoleClient,
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						VLAN:     10,
						StaticIP: "10.0.0.3",
					},
				},
			},
			baseConfig: DefaultNetworkConfig(),
			validate: func(t *testing.T, cfg *NetworkConfig) {
				if cfg.ServerIP.String() != "10.0.0.2" {
					t.Errorf("ServerIP = %v, want 10.0.0.2", cfg.ServerIP)
				}
				if cfg.ClientIP.String() != "10.0.0.3" {
					t.Errorf("ClientIP = %v, want 10.0.0.3", cfg.ClientIP)
				}
				if cfg.GatewayIP.String() != "10.0.0.1" {
					t.Errorf("GatewayIP = %v, want 10.0.0.1", cfg.GatewayIP)
				}
				if cfg.Subnet.String() != "10.0.0.0/24" {
					t.Errorf("Subnet = %v, want 10.0.0.0/24", cfg.Subnet)
				}
			},
		},
		{
			name: "profiles with DHCP pool",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network:    "192.168.1.0/24",
							RangeStart: "192.168.1.10",
							RangeEnd:   "192.168.1.100",
						},
						Gateway: "192.168.1.1",
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network:    "192.168.1.0/24",
							RangeStart: "192.168.1.20",
						},
					},
				},
			},
			baseConfig: DefaultNetworkConfig(),
			validate: func(t *testing.T, cfg *NetworkConfig) {
				if cfg.ServerIP.String() != "192.168.1.10" {
					t.Errorf("ServerIP = %v, want 192.168.1.10", cfg.ServerIP)
				}
				if cfg.ClientIP.String() != "192.168.1.20" {
					t.Errorf("ClientIP = %v, want 192.168.1.20", cfg.ClientIP)
				}
			},
		},
		{
			name: "legacy subnet field",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						Subnet:  "172.16.0.0/16",
						Gateway: "172.16.0.1",
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						Subnet: "172.16.0.0/16",
					},
				},
			},
			baseConfig: DefaultNetworkConfig(),
			validate: func(t *testing.T, cfg *NetworkConfig) {
				// IP should be network address + 1
				if cfg.ServerIP.String() != "172.16.0.1" {
					t.Errorf("ServerIP = %v, want 172.16.0.1", cfg.ServerIP)
				}
				if cfg.Subnet.String() != "172.16.0.0/16" {
					t.Errorf("Subnet = %v, want 172.16.0.0/16", cfg.Subnet)
				}
			},
		},
		{
			name: "client only (no server profile)",
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						StaticIP: "10.1.1.3",
						Gateway:  "10.1.1.1",
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network: "10.1.1.0/24",
						},
					},
				},
			},
			baseConfig: DefaultNetworkConfig(),
			validate: func(t *testing.T, cfg *NetworkConfig) {
				if cfg.ClientIP.String() != "10.1.1.3" {
					t.Errorf("ClientIP = %v, want 10.1.1.3", cfg.ClientIP)
				}
				if cfg.GatewayIP.String() != "10.1.1.1" {
					t.Errorf("GatewayIP = %v, want 10.1.1.1", cfg.GatewayIP)
				}
				if cfg.Subnet.String() != "10.1.1.0/24" {
					t.Errorf("Subnet = %v, want 10.1.1.0/24", cfg.Subnet)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewProfileNetworkBuilder(tt.baseConfig)
			if tt.serverProfile != nil {
				builder.WithServerProfile(tt.serverProfile)
			}
			if tt.clientProfile != nil {
				builder.WithClientProfile(tt.clientProfile)
			}

			cfg, err := builder.Build()
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if cfg == nil {
				t.Fatal("Build() returned nil config")
			}

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

func TestProfileNetworkBuilder_Build_Errors(t *testing.T) {
	tests := []struct {
		name          string
		serverProfile *deviceentities.DeviceProfile
		clientProfile *deviceentities.DeviceProfile
		baseConfig    *NetworkConfig
		expectedError string
	}{
		{
			name: "missing server admitted network",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						StaticIP: "10.0.0.3",
					},
				},
			},
			baseConfig:    DefaultNetworkConfig(),
			expectedError: "missing network configuration for phase: admitted (server)",
		},
		{
			name: "missing client provisioning network",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						StaticIP: "10.0.0.2",
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network: "10.0.0.0/24",
						},
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
			},
			baseConfig:    DefaultNetworkConfig(),
			expectedError: "missing network configuration for phase: provisioning (client)",
		},
		{
			name: "invalid server static IP",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						StaticIP: "999.999.999.999",
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						StaticIP: "10.0.0.3",
					},
				},
			},
			baseConfig:    DefaultNetworkConfig(),
			expectedError: "invalid IP address",
		},
		{
			name: "invalid gateway IP",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {
						StaticIP: "10.0.0.2",
						Gateway:  "invalid-ip",
						DHCPPool: &deviceentities.DHCPPoolConfig{
							Network: "10.0.0.0/24",
						},
					},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {
						StaticIP: "10.0.0.3",
					},
				},
			},
			baseConfig:    DefaultNetworkConfig(),
			expectedError: "invalid gateway address",
		},
		{
			name: "no IP configuration",
			serverProfile: &deviceentities.DeviceProfile{
				Name: "server",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultPostEnrollmentNetwork: {},
				},
			},
			clientProfile: &deviceentities.DeviceProfile{
				Name: "client",
				Networks: map[string]*deviceentities.NetworkPhaseConfig{
					deviceentities.DefaultEnrollmentNetwork: {},
				},
			},
			baseConfig:    DefaultNetworkConfig(),
			expectedError: "no static IP, DHCP pool, or subnet configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewProfileNetworkBuilder(tt.baseConfig)
			if tt.serverProfile != nil {
				builder.WithServerProfile(tt.serverProfile)
			}
			if tt.clientProfile != nil {
				builder.WithClientProfile(tt.clientProfile)
			}

			cfg, err := builder.Build()
			if err == nil {
				t.Fatalf("Build() expected error containing %q, got nil (config: %+v)", tt.expectedError, cfg)
			}
			if tt.expectedError != "" {
				errStr := err.Error()
				if !contains(errStr, tt.expectedError) {
					t.Errorf("Build() error = %v, want error containing %q", err, tt.expectedError)
				}
			}
		})
	}
}

func TestProfileNetworkBuilder_extractIPFromNetworkPhase(t *testing.T) {
	builder := NewProfileNetworkBuilder(nil)

	tests := []struct {
		name        string
		phase       *deviceentities.NetworkPhaseConfig
		expectedIP  string
		expectError bool
	}{
		{
			name: "static IP configured",
			phase: &deviceentities.NetworkPhaseConfig{
				StaticIP: "192.168.1.10",
			},
			expectedIP:  "192.168.1.10",
			expectError: false,
		},
		{
			name: "DHCP pool configured",
			phase: &deviceentities.NetworkPhaseConfig{
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network:    "10.0.0.0/24",
					RangeStart: "10.0.0.100",
				},
			},
			expectedIP:  "10.0.0.100",
			expectError: false,
		},
		{
			name: "legacy subnet field",
			phase: &deviceentities.NetworkPhaseConfig{
				Subnet: "172.16.0.0/24",
			},
			expectedIP:  "172.16.0.1",
			expectError: false,
		},
		{
			name:        "nil phase",
			phase:       nil,
			expectError: true,
		},
		{
			name:        "no configuration",
			phase:       &deviceentities.NetworkPhaseConfig{},
			expectError: true,
		},
		{
			name: "invalid static IP",
			phase: &deviceentities.NetworkPhaseConfig{
				StaticIP: "not-an-ip",
			},
			expectError: true,
		},
		{
			name: "invalid DHCP range start",
			phase: &deviceentities.NetworkPhaseConfig{
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network:    "10.0.0.0/24",
					RangeStart: "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "invalid subnet CIDR",
			phase: &deviceentities.NetworkPhaseConfig{
				Subnet: "not-a-cidr",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := builder.extractIPFromNetworkPhase(tt.phase)

			if tt.expectError {
				if err == nil {
					t.Errorf("extractIPFromNetworkPhase() expected error, got nil (IP: %v)", ip)
				}
			} else {
				if err != nil {
					t.Errorf("extractIPFromNetworkPhase() unexpected error: %v", err)
				}
				if ip.String() != tt.expectedIP {
					t.Errorf("extractIPFromNetworkPhase() IP = %v, want %v", ip, tt.expectedIP)
				}
			}
		})
	}
}

func TestProfileNetworkBuilder_extractSubnetFromNetworkPhase(t *testing.T) {
	builder := NewProfileNetworkBuilder(nil)

	tests := []struct {
		name           string
		phase          *deviceentities.NetworkPhaseConfig
		expectedSubnet string
		expectError    bool
	}{
		{
			name: "DHCP pool network",
			phase: &deviceentities.NetworkPhaseConfig{
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network: "10.0.0.0/24",
				},
			},
			expectedSubnet: "10.0.0.0/24",
			expectError:    false,
		},
		{
			name: "legacy subnet field",
			phase: &deviceentities.NetworkPhaseConfig{
				Subnet: "172.16.0.0/16",
			},
			expectedSubnet: "172.16.0.0/16",
			expectError:    false,
		},
		{
			name: "inferred from static IP (IPv4)",
			phase: &deviceentities.NetworkPhaseConfig{
				StaticIP: "192.168.1.10",
			},
			expectedSubnet: "192.168.1.0/24",
			expectError:    false,
		},
		{
			name: "inferred from static IP (IPv6)",
			phase: &deviceentities.NetworkPhaseConfig{
				StaticIP: "2001:db8::1",
			},
			expectedSubnet: "2001:db8::/64",
			expectError:    false,
		},
		{
			name:        "nil phase",
			phase:       nil,
			expectError: true,
		},
		{
			name:        "no configuration",
			phase:       &deviceentities.NetworkPhaseConfig{},
			expectError: true,
		},
		{
			name: "invalid DHCP pool network",
			phase: &deviceentities.NetworkPhaseConfig{
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network: "not-a-cidr",
				},
			},
			expectError: true,
		},
		{
			name: "invalid legacy subnet",
			phase: &deviceentities.NetworkPhaseConfig{
				Subnet: "invalid-cidr",
			},
			expectError: true,
		},
		{
			name: "invalid static IP for inference",
			phase: &deviceentities.NetworkPhaseConfig{
				StaticIP: "not-an-ip",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet, err := builder.extractSubnetFromNetworkPhase(tt.phase)

			if tt.expectError {
				if err == nil {
					t.Errorf("extractSubnetFromNetworkPhase() expected error, got nil (subnet: %v)", subnet)
				}
			} else {
				if err != nil {
					t.Errorf("extractSubnetFromNetworkPhase() unexpected error: %v", err)
				}
				if subnet.String() != tt.expectedSubnet {
					t.Errorf("extractSubnetFromNetworkPhase() subnet = %v, want %v", subnet, tt.expectedSubnet)
				}
			}
		})
	}
}

func TestProfileNetworkBuilder_Build_WithNilBaseConfig(t *testing.T) {
	// Test that builder creates default config when base is nil
	builder := NewProfileNetworkBuilder(nil)
	builder.WithServerProfile(&deviceentities.DeviceProfile{
		Name: "server",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultPostEnrollmentNetwork: {
				StaticIP: "10.0.0.2",
				Gateway:  "10.0.0.1",
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network: "10.0.0.0/24",
				},
			},
		},
	})
	builder.WithClientProfile(&deviceentities.DeviceProfile{
		Name: "client",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {
				StaticIP: "10.0.0.3",
			},
		},
	})

	cfg, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	// Should have default values from DefaultNetworkConfig()
	defaultCfg := DefaultNetworkConfig()
	if cfg.BridgeName != defaultCfg.BridgeName {
		t.Errorf("BridgeName = %v, want %v", cfg.BridgeName, defaultCfg.BridgeName)
	}
	if cfg.Domain != defaultCfg.Domain {
		t.Errorf("Domain = %v, want %v", cfg.Domain, defaultCfg.Domain)
	}

	// But IPs should be from profiles
	if cfg.ServerIP.String() != "10.0.0.2" {
		t.Errorf("ServerIP = %v, want 10.0.0.2", cfg.ServerIP)
	}
	if cfg.ClientIP.String() != "10.0.0.3" {
		t.Errorf("ClientIP = %v, want 10.0.0.3", cfg.ClientIP)
	}
}

func TestProfileNetworkBuilder_IPv6Support(t *testing.T) {
	builder := NewProfileNetworkBuilder(nil)
	builder.WithServerProfile(&deviceentities.DeviceProfile{
		Name: "server",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultPostEnrollmentNetwork: {
				StaticIP: "2001:db8::2",
				Gateway:  "2001:db8::1",
				DHCPPool: &deviceentities.DHCPPoolConfig{
					Network: "2001:db8::/64",
				},
			},
		},
	})
	builder.WithClientProfile(&deviceentities.DeviceProfile{
		Name: "client",
		Networks: map[string]*deviceentities.NetworkPhaseConfig{
			deviceentities.DefaultEnrollmentNetwork: {
				StaticIP: "2001:db8::3",
			},
		},
	})

	cfg, err := builder.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if cfg.ServerIP.String() != "2001:db8::2" {
		t.Errorf("ServerIP = %v, want 2001:db8::2", cfg.ServerIP)
	}
	if cfg.ClientIP.String() != "2001:db8::3" {
		t.Errorf("ClientIP = %v, want 2001:db8::3", cfg.ClientIP)
	}
	if cfg.GatewayIP.String() != "2001:db8::1" {
		t.Errorf("GatewayIP = %v, want 2001:db8::1", cfg.GatewayIP)
	}
	if cfg.Subnet.String() != "2001:db8::/64" {
		t.Errorf("Subnet = %v, want 2001:db8::/64", cfg.Subnet)
	}
}

// contains checks if a string contains a substring (helper function)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
