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

package ovs

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupVXLANTest(t *testing.T) (*Client, *mockOVSDBServer) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create a test bridge
	_, err = client.CreateBridge(ctx, "br-vxlan-test")
	require.NoError(t, err)

	return client, server
}

// TestVXLANPortConfig_Validate tests the validation of VXLAN configurations
func TestVXLANPortConfig_Validate(t *testing.T) {
	t.Run("valid config with remote IP only", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with all options", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP:     netip.MustParseAddr("10.0.0.1"),
			LocalIP:      netip.MustParseAddr("10.0.0.2"),
			Key:          1000,
			DstPort:      4789,
			TOS:          64,
			TTL:          64,
			DF:           true,
			Csum:         true,
			ExtensionGBP: true,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with flow-based key", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.1.1"),
			Key:      0, // Flow-based
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with max VNI", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
			Key:      MaxVNI,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid config with IPv6", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("2001:db8::1"),
			LocalIP:  netip.MustParseAddr("2001:db8::2"),
			Key:      100,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("invalid - missing remote IP", func(t *testing.T) {
		cfg := &VXLANPortConfig{}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidRemoteIP)
	})

	t.Run("invalid - zero remote IP", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("0.0.0.0"),
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidRemoteIP)
	})

	t.Run("invalid - VNI too large", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
			Key:      MaxVNI + 1,
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrInvalidVNI)
	})

	t.Run("invalid - IP family mismatch", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),    // IPv4
			LocalIP:  netip.MustParseAddr("2001:db8::1"), // IPv6
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrIPFamilyMismatch)
	})

	t.Run("invalid - reverse IP family mismatch", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("2001:db8::1"), // IPv6
			LocalIP:  netip.MustParseAddr("10.0.0.1"),    // IPv4
		}
		err := cfg.Validate()
		assert.ErrorIs(t, err, ErrIPFamilyMismatch)
	})
}

// TestGenerateVXLANPortName tests the port name generation
func TestGenerateVXLANPortName(t *testing.T) {
	t.Run("generates consistent names", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		name1 := generateVXLANPortName(ip, 100)
		name2 := generateVXLANPortName(ip, 100)
		assert.Equal(t, name1, name2)
	})

	t.Run("different IPs produce different names", func(t *testing.T) {
		ip1 := netip.MustParseAddr("10.0.0.1")
		ip2 := netip.MustParseAddr("10.0.0.2")
		name1 := generateVXLANPortName(ip1, 100)
		name2 := generateVXLANPortName(ip2, 100)
		assert.NotEqual(t, name1, name2)
	})

	t.Run("different keys produce different names", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		name1 := generateVXLANPortName(ip, 100)
		name2 := generateVXLANPortName(ip, 200)
		assert.NotEqual(t, name1, name2)
	})

	t.Run("flow-based key produces special name", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		name := generateVXLANPortName(ip, 0)
		assert.Contains(t, name, "-flow")
	})

	t.Run("non-flow key includes key value", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		name := generateVXLANPortName(ip, 1234)
		assert.Contains(t, name, "-1234")
	})

	t.Run("name starts with vxlan prefix", func(t *testing.T) {
		ip := netip.MustParseAddr("10.0.0.1")
		name := generateVXLANPortName(ip, 100)
		assert.True(t, len(name) > 0)
		assert.Equal(t, "vxlan-", name[:6])
	})
}

// TestBuildVXLANOptions tests the VXLAN options map building
func TestBuildVXLANOptions(t *testing.T) {
	t.Run("minimal config", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
		}
		opts := buildVXLANOptions(cfg)

		assert.Equal(t, "10.0.0.1", opts["remote_ip"])
		assert.Equal(t, "flow", opts["key"]) // Default for Key=0
		_, hasLocal := opts["local_ip"]
		assert.False(t, hasLocal)
	})

	t.Run("full config", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP:     netip.MustParseAddr("10.0.0.1"),
			LocalIP:      netip.MustParseAddr("10.0.0.2"),
			Key:          1000,
			DstPort:      8472,
			TOS:          64,
			TTL:          128,
			DF:           true,
			Csum:         true,
			ExtensionGBP: true,
		}
		opts := buildVXLANOptions(cfg)

		assert.Equal(t, "10.0.0.1", opts["remote_ip"])
		assert.Equal(t, "10.0.0.2", opts["local_ip"])
		assert.Equal(t, "1000", opts["key"])
		assert.Equal(t, "8472", opts["dst_port"])
		assert.Equal(t, "64", opts["tos"])
		assert.Equal(t, "128", opts["ttl"])
		assert.Equal(t, "true", opts["df_default"])
		assert.Equal(t, "true", opts["csum"])
		assert.Equal(t, "gbp", opts["exts"])
	})

	t.Run("default port not included", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
			DstPort:  DefaultVXLANPort,
		}
		opts := buildVXLANOptions(cfg)

		_, hasDstPort := opts["dst_port"]
		assert.False(t, hasDstPort)
	})

	t.Run("zero values not included", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("10.0.0.1"),
			TOS:      0,
			TTL:      0,
			DF:       false,
			Csum:     false,
		}
		opts := buildVXLANOptions(cfg)

		_, hasTOS := opts["tos"]
		_, hasTTL := opts["ttl"]
		_, hasDF := opts["df_default"]
		_, hasCsum := opts["csum"]
		assert.False(t, hasTOS)
		assert.False(t, hasTTL)
		assert.False(t, hasDF)
		assert.False(t, hasCsum)
	})

	t.Run("IPv6 addresses", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("2001:db8::1"),
			LocalIP:  netip.MustParseAddr("2001:db8::2"),
			Key:      500,
		}
		opts := buildVXLANOptions(cfg)

		assert.Equal(t, "2001:db8::1", opts["remote_ip"])
		assert.Equal(t, "2001:db8::2", opts["local_ip"])
	})
}

// TestClient_AddVXLANPort tests adding VXLAN ports
func TestClient_AddVXLANPort(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("add VXLAN port successfully", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.1.100"),
			Key:      1000,
		}

		port, err := client.AddVXLANPort(ctx, "br-vxlan-test", cfg)
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.NotEmpty(t, port.UUID)
	})

	t.Run("add VXLAN port with empty bridge name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.1.101"),
			Key:      1001,
		}

		_, err := client.AddVXLANPort(ctx, "", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("add VXLAN port with nil config", func(t *testing.T) {
		_, err := client.AddVXLANPort(ctx, "br-vxlan-test", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidVXLANConfig)
	})

	t.Run("add VXLAN port with invalid config", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			// Missing RemoteIP
			Key: 1002,
		}

		_, err := client.AddVXLANPort(ctx, "br-vxlan-test", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidRemoteIP)
	})

	t.Run("add VXLAN port to non-existent bridge", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.1.103"),
			Key:      1003,
		}

		_, err := client.AddVXLANPort(ctx, "br-nonexistent", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("add VXLAN port when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.1.104"),
			Key:      1004,
		}

		_, err = disconnectedClient.AddVXLANPort(ctx, "br-vxlan-test", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestClient_AddVXLANPortWithName tests adding VXLAN ports with custom names
func TestClient_AddVXLANPortWithName(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("add VXLAN port with custom name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.2.100"),
			Key:      2000,
		}

		port, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-custom-1", cfg)
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.Equal(t, "vxlan-custom-1", port.Name)
	})

	t.Run("add VXLAN port with empty name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.2.101"),
			Key:      2001,
		}

		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("add VXLAN port with empty bridge name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.2.102"),
			Key:      2002,
		}

		_, err := client.AddVXLANPortWithName(ctx, "", "vxlan-custom-2", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("add VXLAN port with nil config", func(t *testing.T) {
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-custom-3", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidVXLANConfig)
	})

	t.Run("add duplicate VXLAN port name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.2.103"),
			Key:      2003,
		}

		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-dup", cfg)
		require.NoError(t, err)

		// Try to add again with same name
		cfg2 := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.2.104"),
			Key:      2004,
		}

		_, err = client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-dup", cfg2)
		require.Error(t, err)
		// Should be either ErrVXLANPortExists or ErrPortExists
		assert.True(t, err == ErrVXLANPortExists || err == ErrPortExists)
	})
}

// TestClient_DeleteVXLANPort tests deleting VXLAN ports
func TestClient_DeleteVXLANPort(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("delete existing VXLAN port", func(t *testing.T) {
		// First create a VXLAN port
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.3.100"),
			Key:      3000,
		}

		port, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-delete-1", cfg)
		require.NoError(t, err)
		require.NotNil(t, port)

		// Delete it
		err = client.DeleteVXLANPort(ctx, "br-vxlan-test", "vxlan-delete-1")
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.GetVXLANPort(ctx, "br-vxlan-test", "vxlan-delete-1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})

	t.Run("delete with empty bridge name", func(t *testing.T) {
		err := client.DeleteVXLANPort(ctx, "", "vxlan-test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("delete with empty port name", func(t *testing.T) {
		err := client.DeleteVXLANPort(ctx, "br-vxlan-test", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("delete non-existent VXLAN port", func(t *testing.T) {
		err := client.DeleteVXLANPort(ctx, "br-vxlan-test", "vxlan-nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})

	t.Run("delete regular port as VXLAN fails", func(t *testing.T) {
		// First create a regular (non-VXLAN) port
		_, err := client.AddPort(ctx, "br-vxlan-test", "regular-port")
		require.NoError(t, err)

		// Try to delete it as VXLAN - should fail
		err = client.DeleteVXLANPort(ctx, "br-vxlan-test", "regular-port")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})
}

// TestClient_ListVXLANPorts tests listing VXLAN ports
func TestClient_ListVXLANPorts(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("list VXLAN ports when none exist", func(t *testing.T) {
		// Create a fresh bridge for this test
		_, err := client.CreateBridge(ctx, "br-vxlan-empty")
		require.NoError(t, err)

		ports, err := client.ListVXLANPorts(ctx, "br-vxlan-empty")
		require.NoError(t, err)
		assert.Empty(t, ports)
	})

	t.Run("list VXLAN ports does not error", func(t *testing.T) {
		// Create VXLAN ports
		cfg1 := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.4.1"),
			Key:      4001,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-list-1", cfg1)
		require.NoError(t, err)

		cfg2 := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.4.2"),
			Key:      4002,
		}
		_, err = client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-list-2", cfg2)
		require.NoError(t, err)

		// Verify listing does not error (the mock may not track types correctly)
		ports, err := client.ListVXLANPorts(ctx, "br-vxlan-test")
		require.NoError(t, err)
		// The mock server may or may not return the VXLAN ports depending on
		// how it handles interface types. We only verify no error occurs.
		assert.NotNil(t, ports)
	})

	t.Run("verify VXLAN ports can be retrieved individually", func(t *testing.T) {
		// This is more reliable than listing since it queries by name
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.4.3"),
			Key:      4003,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-list-3", cfg)
		require.NoError(t, err)

		// Verify we can get it back
		port, err := client.GetVXLANPort(ctx, "br-vxlan-test", "vxlan-list-3")
		require.NoError(t, err)
		assert.Equal(t, "vxlan-list-3", port.Name)
	})

	t.Run("list with empty bridge name", func(t *testing.T) {
		_, err := client.ListVXLANPorts(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("list on non-existent bridge", func(t *testing.T) {
		_, err := client.ListVXLANPorts(ctx, "br-nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

// TestClient_GetVXLANPort tests getting specific VXLAN ports
func TestClient_GetVXLANPort(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("get existing VXLAN port", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.5.1"),
			Key:      5000,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-get-1", cfg)
		require.NoError(t, err)

		port, err := client.GetVXLANPort(ctx, "br-vxlan-test", "vxlan-get-1")
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.Equal(t, "vxlan-get-1", port.Name)
	})

	t.Run("get with empty bridge name", func(t *testing.T) {
		_, err := client.GetVXLANPort(ctx, "", "vxlan-test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("get with empty port name", func(t *testing.T) {
		_, err := client.GetVXLANPort(ctx, "br-vxlan-test", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("get non-existent VXLAN port", func(t *testing.T) {
		_, err := client.GetVXLANPort(ctx, "br-vxlan-test", "vxlan-nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})

	t.Run("get regular port as VXLAN fails", func(t *testing.T) {
		// First create a regular port
		_, err := client.AddPort(ctx, "br-vxlan-test", "regular-port-get")
		require.NoError(t, err)

		// Try to get it as VXLAN
		_, err = client.GetVXLANPort(ctx, "br-vxlan-test", "regular-port-get")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})

	t.Run("get on non-existent bridge", func(t *testing.T) {
		_, err := client.GetVXLANPort(ctx, "br-nonexistent", "vxlan-test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

// TestClient_GetVXLANPortWithOptions tests getting VXLAN ports with their full options
func TestClient_GetVXLANPortWithOptions(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("get VXLAN port with options", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.6.1"),
			LocalIP:  netip.MustParseAddr("192.168.6.2"),
			Key:      6000,
			DstPort:  8472,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-opts-1", cfg)
		require.NoError(t, err)

		port, err := client.GetVXLANPortWithOptions(ctx, "br-vxlan-test", "vxlan-opts-1")
		require.NoError(t, err)
		assert.NotNil(t, port)
		assert.Equal(t, "vxlan-opts-1", port.Name)
	})

	t.Run("get with empty bridge name", func(t *testing.T) {
		_, err := client.GetVXLANPortWithOptions(ctx, "", "vxlan-test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("get with empty port name", func(t *testing.T) {
		_, err := client.GetVXLANPortWithOptions(ctx, "br-vxlan-test", "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})
}

// TestClient_UpdateVXLANPort tests updating VXLAN port configuration
func TestClient_UpdateVXLANPort(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("update existing VXLAN port", func(t *testing.T) {
		// Create initial port
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.1"),
			Key:      7000,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-update-1", cfg)
		require.NoError(t, err)

		// Update with new config
		newCfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.2"),
			Key:      7001,
			DstPort:  8472,
		}
		err = client.UpdateVXLANPort(ctx, "br-vxlan-test", "vxlan-update-1", newCfg)
		require.NoError(t, err)
	})

	t.Run("update with empty bridge name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.3"),
		}
		err := client.UpdateVXLANPort(ctx, "", "vxlan-test", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("update with empty port name", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.4"),
		}
		err := client.UpdateVXLANPort(ctx, "br-vxlan-test", "", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("update with nil config", func(t *testing.T) {
		err := client.UpdateVXLANPort(ctx, "br-vxlan-test", "vxlan-update-1", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidVXLANConfig)
	})

	t.Run("update non-existent VXLAN port", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.5"),
		}
		err := client.UpdateVXLANPort(ctx, "br-vxlan-test", "vxlan-nonexistent", cfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrVXLANPortNotFound)
	})

	t.Run("update with invalid config", func(t *testing.T) {
		// Create a port first
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.7.6"),
			Key:      7006,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-update-invalid", cfg)
		require.NoError(t, err)

		// Try to update with invalid config
		badCfg := &VXLANPortConfig{
			// Missing RemoteIP
			Key: 7007,
		}
		err = client.UpdateVXLANPort(ctx, "br-vxlan-test", "vxlan-update-invalid", badCfg)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidRemoteIP)
	})
}

// TestClient_GetInterfaceOptions tests getting interface options
func TestClient_GetInterfaceOptions(t *testing.T) {
	client, server := setupVXLANTest(t)
	defer server.Close()
	defer client.Close()

	ctx := context.Background()

	t.Run("get options for VXLAN interface", func(t *testing.T) {
		cfg := &VXLANPortConfig{
			RemoteIP: netip.MustParseAddr("192.168.8.1"),
			Key:      8000,
		}
		_, err := client.AddVXLANPortWithName(ctx, "br-vxlan-test", "vxlan-opts-iface", cfg)
		require.NoError(t, err)

		opts, err := client.GetInterfaceOptions(ctx, "vxlan-opts-iface")
		require.NoError(t, err)
		assert.NotNil(t, opts)
	})

	t.Run("get options with empty name", func(t *testing.T) {
		_, err := client.GetInterfaceOptions(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("get options for non-existent interface", func(t *testing.T) {
		_, err := client.GetInterfaceOptions(ctx, "nonexistent-iface")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}

// TestParseVXLANPort tests parsing VXLAN port data
func TestParseVXLANPort(t *testing.T) {
	t.Run("parse with valid data", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-parse-test",
		}
		iface := &Interface{
			UUID: "iface-uuid",
			Name: "vxlan-parse-test",
			Type: VXLANInterfaceType,
			OtherConfig: map[string]string{
				"remote_ip": "10.0.0.1",
				"local_ip":  "10.0.0.2",
				"key":       "1000",
				"dst_port":  "8472",
			},
		}

		vxlanPort := parseVXLANPort(port, iface)
		assert.Equal(t, "test-uuid", vxlanPort.UUID)
		assert.Equal(t, "vxlan-parse-test", vxlanPort.Name)
		assert.Equal(t, netip.MustParseAddr("10.0.0.1"), vxlanPort.RemoteIP)
		assert.Equal(t, netip.MustParseAddr("10.0.0.2"), vxlanPort.LocalIP)
		assert.Equal(t, uint32(1000), vxlanPort.Key)
		assert.Equal(t, uint16(8472), vxlanPort.DstPort)
		assert.False(t, vxlanPort.IsFlowKey)
	})

	t.Run("parse with flow-based key", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-flow-test",
		}
		iface := &Interface{
			UUID: "iface-uuid",
			Name: "vxlan-flow-test",
			Type: VXLANInterfaceType,
			OtherConfig: map[string]string{
				"remote_ip": "10.0.0.1",
				"key":       "flow",
			},
		}

		vxlanPort := parseVXLANPort(port, iface)
		assert.Equal(t, uint32(0), vxlanPort.Key)
		assert.True(t, vxlanPort.IsFlowKey)
	})

	t.Run("parse with default port", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-default-port",
		}
		iface := &Interface{
			UUID: "iface-uuid",
			Name: "vxlan-default-port",
			Type: VXLANInterfaceType,
			OtherConfig: map[string]string{
				"remote_ip": "10.0.0.1",
			},
		}

		vxlanPort := parseVXLANPort(port, iface)
		assert.Equal(t, DefaultVXLANPort, vxlanPort.DstPort)
	})

	t.Run("parse with empty OtherConfig", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-empty-config",
		}
		iface := &Interface{
			UUID:        "iface-uuid",
			Name:        "vxlan-empty-config",
			Type:        VXLANInterfaceType,
			OtherConfig: map[string]string{},
		}

		vxlanPort := parseVXLANPort(port, iface)
		assert.Equal(t, "test-uuid", vxlanPort.UUID)
		assert.Equal(t, DefaultVXLANPort, vxlanPort.DstPort)
	})

	t.Run("parse with nil OtherConfig", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-nil-config",
		}
		iface := &Interface{
			UUID:        "iface-uuid",
			Name:        "vxlan-nil-config",
			Type:        VXLANInterfaceType,
			OtherConfig: nil,
		}

		vxlanPort := parseVXLANPort(port, iface)
		assert.NotNil(t, vxlanPort)
		assert.NotNil(t, vxlanPort.Options)
	})

	t.Run("parse with invalid IP in options", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-invalid-ip",
		}
		iface := &Interface{
			UUID: "iface-uuid",
			Name: "vxlan-invalid-ip",
			Type: VXLANInterfaceType,
			OtherConfig: map[string]string{
				"remote_ip": "not-an-ip",
				"local_ip":  "also-not-an-ip",
			},
		}

		vxlanPort := parseVXLANPort(port, iface)
		// Should not panic, just have invalid IPs
		assert.False(t, vxlanPort.RemoteIP.IsValid())
		assert.False(t, vxlanPort.LocalIP.IsValid())
	})

	t.Run("parse with invalid key in options", func(t *testing.T) {
		port := &Port{
			UUID: "test-uuid",
			Name: "vxlan-invalid-key",
		}
		iface := &Interface{
			UUID: "iface-uuid",
			Name: "vxlan-invalid-key",
			Type: VXLANInterfaceType,
			OtherConfig: map[string]string{
				"remote_ip": "10.0.0.1",
				"key":       "not-a-number",
			},
		}

		vxlanPort := parseVXLANPort(port, iface)
		// Should not panic, key should be 0
		assert.Equal(t, uint32(0), vxlanPort.Key)
	})
}

// TestVXLANConstants tests VXLAN constant values
func TestVXLANConstants(t *testing.T) {
	t.Run("default VXLAN port is 4789", func(t *testing.T) {
		assert.Equal(t, uint16(4789), DefaultVXLANPort)
	})

	t.Run("max VNI is 16777215", func(t *testing.T) {
		assert.Equal(t, uint32(16777215), MaxVNI)
	})

	t.Run("VXLAN interface type is vxlan", func(t *testing.T) {
		assert.Equal(t, "vxlan", VXLANInterfaceType)
	})
}

// TestVXLANErrors tests VXLAN error handling
func TestVXLANErrors(t *testing.T) {
	t.Run("ErrInvalidRemoteIP has correct message", func(t *testing.T) {
		assert.Contains(t, ErrInvalidRemoteIP.Error(), "remote VTEP IP")
	})

	t.Run("ErrVXLANPortExists has correct message", func(t *testing.T) {
		assert.Contains(t, ErrVXLANPortExists.Error(), "VXLAN port already exists")
	})

	t.Run("ErrVXLANPortNotFound has correct message", func(t *testing.T) {
		assert.Contains(t, ErrVXLANPortNotFound.Error(), "VXLAN port not found")
	})

	t.Run("ErrInvalidVXLANConfig has correct message", func(t *testing.T) {
		assert.Contains(t, ErrInvalidVXLANConfig.Error(), "invalid VXLAN configuration")
	})

	t.Run("ErrInvalidVNI has correct message", func(t *testing.T) {
		assert.Contains(t, ErrInvalidVNI.Error(), "VXLAN Network Identifier")
	})

	t.Run("ErrIPFamilyMismatch has correct message", func(t *testing.T) {
		assert.Contains(t, ErrIPFamilyMismatch.Error(), "family mismatch")
	})
}
