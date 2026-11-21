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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLinuxIsolatedNetwork_EnableIPForwarding_PermissionHandling tests IP forwarding control
// This test verifies proper error handling based on privilege level
func TestLinuxIsolatedNetwork_EnableIPForwarding_PermissionHandling(t *testing.T) {
	cfg := DefaultNetworkConfig()
	linuxNet := NewIsolatedNetwork(cfg)

	err := linuxNet.enableIPForwarding()

	if os.Geteuid() == 0 {
		// Running as root - should succeed
		assert.NoError(t, err, "enableIPForwarding should succeed with root")
	} else {
		// Not running as root - should fail with permission error
		assert.Error(t, err, "enableIPForwarding should fail without root")
	}
}

// TestLinuxIsolatedNetwork_Setup_ValidationError tests setup with invalid config
func TestLinuxIsolatedNetwork_Setup_ValidationError(t *testing.T) {
	// Create config with missing required fields
	cfg := &NetworkConfig{}

	network := NewIsolatedNetwork(cfg)

	err := network.Setup()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network config")
}

// TestLinuxIsolatedNetwork_Setup_CreateBridgeError tests bridge creation failure
func TestLinuxIsolatedNetwork_Setup_CreateBridgeError(t *testing.T) {
	cfg := DefaultNetworkConfig()
	// Use unique name to avoid conflicts
	cfg.BridgeName = "test-br-fail"

	network := NewIsolatedNetwork(cfg)

	err := network.Setup()
	// Will fail - either due to permissions (non-root) or other reasons
	// The key assertion is that the error is handled properly
	if os.Geteuid() != 0 {
		assert.Error(t, err)
	}
}

// TestLinuxIsolatedNetwork_Cleanup_Idempotent tests cleanup can be called multiple times
func TestLinuxIsolatedNetwork_Cleanup_Idempotent(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.BridgeName = "test-cleanup-idempotent"
	cfg.ServerTapName = "test-cleanup-server"
	cfg.ClientTapName = "test-cleanup-client"

	network := NewIsolatedNetwork(cfg)

	// First cleanup
	err := network.Cleanup()
	// May return error if resources don't exist
	t.Logf("First cleanup: %v", err)

	// Second cleanup - should not panic
	err = network.Cleanup()
	t.Logf("Second cleanup: %v", err)

	// Third cleanup - should still not panic
	err = network.Cleanup()
	t.Logf("Third cleanup: %v", err)
}

// TestLinuxIsolatedNetwork_NetworkExistsCoverage tests different network states
func TestLinuxIsolatedNetwork_NetworkExistsCoverage(t *testing.T) {
	tests := []struct {
		name   string
		config func() *NetworkConfig
	}{
		{
			name:   "default config",
			config: DefaultNetworkConfig,
		},
		{
			name: "custom config",
			config: func() *NetworkConfig {
				cfg := DefaultNetworkConfig()
				cfg.BridgeName = "custom-test-br"
				cfg.ServerTapName = "custom-test-server"
				cfg.ClientTapName = "custom-test-client"
				return cfg
			},
		},
		{
			name: "nil config",
			config: func() *NetworkConfig {
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config()
			exists := NetworkExists(cfg)
			// Just verify it doesn't panic and returns a bool
			t.Logf("Network exists: %v", exists)
			assert.IsType(t, false, exists)
		})
	}
}

// TestCleanupStaleResources_Idempotent tests cleanup can be called multiple times
func TestCleanupStaleResources_Idempotent(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.BridgeName = "test-stale-cleanup"
	cfg.ServerTapName = "test-stale-server"
	cfg.ClientTapName = "test-stale-client"

	// First cleanup
	CleanupStaleResources(cfg)

	// Second cleanup - should not panic
	CleanupStaleResources(cfg)

	// Cleanup with nil config
	CleanupStaleResources(nil)
}

// TestLinuxIsolatedNetwork_EnsureRules_Coverage tests EnsureRules error paths
func TestLinuxIsolatedNetwork_EnsureRules_Coverage(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	// Call without setup - will fail but shouldn't panic
	err := network.EnsureRules()
	t.Logf("EnsureRules without setup: %v", err)

	// Should return error due to missing permissions or setup
	if os.Geteuid() != 0 {
		assert.Error(t, err)
	}
}

// TestLinuxIsolatedNetwork_Config_Mutability tests config reference
func TestLinuxIsolatedNetwork_Config_Mutability(t *testing.T) {
	cfg := DefaultNetworkConfig()
	originalBridge := cfg.BridgeName

	network := NewIsolatedNetwork(cfg)

	// Get config
	gotCfg := network.Config()
	assert.Equal(t, originalBridge, gotCfg.BridgeName)

	// Modify returned config
	gotCfg.BridgeName = "modified"

	// Original should be modified (no deep copy)
	assert.Equal(t, "modified", network.Config().BridgeName)
}

// TestLinuxIsolatedNetwork_TapNames_Consistency tests tap names are consistent
func TestLinuxIsolatedNetwork_TapNames_Consistency(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.ServerTapName = "consistent-server"
	cfg.ClientTapName = "consistent-client"

	network := NewIsolatedNetwork(cfg)

	// Call multiple times - should return same values
	for i := 0; i < 5; i++ {
		assert.Equal(t, "consistent-server", network.ServerTapName())
		assert.Equal(t, "consistent-client", network.ClientTapName())
	}
}

// TestCheckRootPrivileges_ErrorMessage tests the error message
func TestCheckRootPrivileges_ErrorMessage(t *testing.T) {
	err := CheckRootPrivileges()

	if os.Geteuid() == 0 {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "root privileges required")
		assert.Contains(t, err.Error(), "run with sudo")
	}
}

// TestLinuxIsolatedNetwork_CustomConfig tests with various custom configs
func TestLinuxIsolatedNetwork_CustomConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *NetworkConfig
	}{
		{
			name:   "nil config uses defaults",
			config: nil,
		},
		{
			name: "custom names",
			config: func() *NetworkConfig {
				cfg := DefaultNetworkConfig()
				cfg.BridgeName = "my-bridge"
				cfg.ServerTapName = "my-server"
				cfg.ClientTapName = "my-client"
				return cfg
			}(),
		},
		{
			name: "custom domain",
			config: func() *NetworkConfig {
				cfg := DefaultNetworkConfig()
				cfg.Domain = "custom.local"
				return cfg
			}(),
		},
		{
			name: "custom MACs",
			config: func() *NetworkConfig {
				cfg := DefaultNetworkConfig()
				cfg.ServerMAC = "AA:BB:CC:DD:EE:01"
				cfg.ClientMAC = "AA:BB:CC:DD:EE:02"
				return cfg
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := NewIsolatedNetwork(tt.config)
			assert.NotNil(t, network)

			cfg := network.Config()
			assert.NotNil(t, cfg)

			// Verify config is accessible
			assert.NotEmpty(t, cfg.BridgeName)
			assert.NotEmpty(t, cfg.ServerTapName)
			assert.NotEmpty(t, cfg.ClientTapName)
		})
	}
}

// TestNetworkExists_PartialNetwork tests when some but not all resources exist
func TestNetworkExists_PartialNetwork(t *testing.T) {
	// Create a config for resources that definitely don't exist
	cfg := &NetworkConfig{
		BridgeName:    "absolutely-nonexistent-bridge-xyz123",
		ServerTapName: "absolutely-nonexistent-server-xyz123",
		ClientTapName: "absolutely-nonexistent-client-xyz123",
	}

	exists := NetworkExists(cfg)
	assert.False(t, exists, "Network with non-existent resources should return false")
}

// TestIptablesCommand_PrefersLegacyOnlyWhenItWorks checks that the test
// network picks iptables-legacy only when it is on PATH and its tables load,
// and otherwise falls back to iptables (#2150).
func TestIptablesCommand_PrefersLegacyOnlyWhenItWorks(t *testing.T) {
	tests := []struct {
		name         string
		legacyOnPath bool
		usable       bool
		want         string
		wantProbed   bool
	}{
		{name: "legacy on PATH and usable", legacyOnPath: true, usable: true, want: "iptables-legacy", wantProbed: true},
		{name: "legacy on PATH but tables do not load", legacyOnPath: true, usable: false, want: "iptables", wantProbed: true},
		{name: "legacy not on PATH", legacyOnPath: false, usable: true, want: "iptables", wantProbed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookPath := func(file string) (string, error) {
				if file == "iptables-legacy" && tt.legacyOnPath {
					return "/usr/sbin/iptables-legacy", nil
				}
				return "", os.ErrNotExist
			}
			probed := false
			usable := func(cmd string) bool {
				probed = true
				assert.Equal(t, "iptables-legacy", cmd)
				return tt.usable
			}
			assert.Equal(t, tt.want, iptablesCommand(lookPath, usable))
			assert.Equal(t, tt.wantProbed, probed)
		})
	}
}
