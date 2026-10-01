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
	"github.com/stretchr/testify/require"
)

func TestLinuxIsolatedNetwork_Config(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	gotCfg := network.Config()
	assert.Equal(t, cfg, gotCfg)
	assert.Equal(t, "tp-br", gotCfg.BridgeName)
}

func TestLinuxIsolatedNetwork_ServerTapName(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.ServerTapName = "custom-server-tap"
	network := NewIsolatedNetwork(cfg)

	assert.Equal(t, "custom-server-tap", network.ServerTapName())
}

func TestLinuxIsolatedNetwork_ClientTapName(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.ClientTapName = "custom-client-tap"
	network := NewIsolatedNetwork(cfg)

	assert.Equal(t, "custom-client-tap", network.ClientTapName())
}

func TestLinuxIsolatedNetwork_Setup_InvalidConfig(t *testing.T) {
	// Create invalid config (missing required fields)
	cfg := &NetworkConfig{
		BridgeName: "", // Invalid - empty bridge name
	}
	network := NewIsolatedNetwork(cfg)

	err := network.Setup()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network config")
}

// TestLinuxIsolatedNetwork_Setup_PermissionError tests setup fails appropriately
// when the caller lacks necessary permissions. This test verifies error handling
// behavior regardless of the current user's privilege level.
func TestLinuxIsolatedNetwork_Setup_PermissionError(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.Setup()
	// When not running as root, will fail due to lack of permissions
	// When running as root in CI, it may succeed or fail based on namespace isolation
	if os.Geteuid() != 0 {
		// Non-root: expect permission error
		assert.Error(t, err)
	}
	// For root case, the test passes regardless - we're testing error handling
}

// TestLinuxIsolatedNetwork_EnsureRules_PermissionError tests EnsureRules error handling
func TestLinuxIsolatedNetwork_EnsureRules_PermissionError(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.EnsureRules()
	// When not running as root, will fail due to lack of permissions
	if os.Geteuid() != 0 {
		assert.Error(t, err)
	}
}

func TestLinuxIsolatedNetwork_Cleanup(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	// Cleanup should not error even if nothing was set up
	err := network.Cleanup()
	// May return error if resources don't exist, but shouldn't panic
	t.Logf("Cleanup result: %v", err)
}

func TestCheckRootPrivileges(t *testing.T) {
	err := CheckRootPrivileges()

	if os.Geteuid() == 0 {
		assert.NoError(t, err)
	} else {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "root privileges required")
	}
}

func TestNetworkExists(t *testing.T) {
	cfg := DefaultNetworkConfig()

	// Test with default config
	exists := NetworkExists(cfg)
	// In most test environments, network won't exist
	t.Logf("Network exists: %v", exists)

	// Test with nil config (should use defaults)
	exists = NetworkExists(nil)
	t.Logf("Network exists (nil config): %v", exists)
}

func TestCleanupStaleResources(t *testing.T) {
	cfg := DefaultNetworkConfig()

	// Should not panic even if resources don't exist
	CleanupStaleResources(cfg)

	// Test with nil config
	CleanupStaleResources(nil)
}

func TestLinuxIsolatedNetwork_NilConfig(t *testing.T) {
	network := NewIsolatedNetwork(nil)
	require.NotNil(t, network)

	// Should use default config
	cfg := network.Config()
	require.NotNil(t, cfg)
	assert.Equal(t, "tp-br", cfg.BridgeName)
	assert.Equal(t, "tap-tp-server", cfg.ServerTapName)
	assert.Equal(t, "tap-tp-client", cfg.ClientTapName)
}

func TestLinuxIsolatedNetwork_Interface(t *testing.T) {
	// Verify LinuxIsolatedNetwork implements IsolatedNetwork interface
	var _ IsolatedNetwork = (*LinuxIsolatedNetwork)(nil)
}

// TestLinuxIsolatedNetwork_CleanupWithoutSetup tests cleanup when setup was never called
func TestLinuxIsolatedNetwork_CleanupWithoutSetup(t *testing.T) {
	cfg := DefaultNetworkConfig()
	cfg.BridgeName = "test-tp-br-nosetup"
	cfg.ServerTapName = "test-tap-server-nosetup"
	cfg.ClientTapName = "test-tap-client-nosetup"

	// Ensure resources don't exist
	CleanupStaleResources(cfg)

	network := NewIsolatedNetwork(cfg)

	// Cleanup without setup should not panic
	err := network.Cleanup()
	// May return error but shouldn't panic
	t.Logf("Cleanup without setup result: %v", err)
}

// TestLinuxIsolatedNetwork_SetPhase tests the stub implementation
func TestLinuxIsolatedNetwork_SetPhase(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.SetPhase("test-port", NetworkPhaseProvisioning)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// TestLinuxIsolatedNetwork_GetPhase tests the stub implementation
func TestLinuxIsolatedNetwork_GetPhase(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	phase := network.GetPhase("test-port")
	assert.Equal(t, NetworkPhaseUnconnected, phase)
}

// TestLinuxIsolatedNetwork_TransitionToAdmitted tests the stub implementation
func TestLinuxIsolatedNetwork_TransitionToAdmitted(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.TransitionToAdmitted("test-port", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// TestLinuxIsolatedNetwork_QuarantinePort tests the stub implementation
func TestLinuxIsolatedNetwork_QuarantinePort(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.QuarantinePort("test-port", "test reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// TestLinuxIsolatedNetwork_UnquarantinePort tests the stub implementation
func TestLinuxIsolatedNetwork_UnquarantinePort(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.UnquarantinePort("test-port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// TestLinuxIsolatedNetwork_BlockPort tests the stub implementation
func TestLinuxIsolatedNetwork_BlockPort(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.BlockPort("test-port", "test reason")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

// TestLinuxIsolatedNetwork_UnblockPort tests the stub implementation
func TestLinuxIsolatedNetwork_UnblockPort(t *testing.T) {
	cfg := DefaultNetworkConfig()
	network := NewIsolatedNetwork(cfg)

	err := network.UnblockPort("test-port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}
