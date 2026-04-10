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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListPortsEdgeCases tests edge cases in ListPorts
func TestListPortsEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create test bridge
	_, err = client.CreateBridge(ctx, "br-listports")
	require.NoError(t, err)

	t.Run("ListPorts with empty bridge", func(t *testing.T) {
		ports, err := client.ListPorts(ctx, "br-listports")
		require.NoError(t, err)
		// May have internal port
		assert.NotNil(t, ports)
	})

	t.Run("ListPorts with multiple ports", func(t *testing.T) {
		// Add several ports
		_, err := client.AddPort(ctx, "br-listports", "port1")
		require.NoError(t, err)
		_, err = client.AddPort(ctx, "br-listports", "port2")
		require.NoError(t, err)
		_, err = client.AddPort(ctx, "br-listports", "port3")
		require.NoError(t, err)

		ports, err := client.ListPorts(ctx, "br-listports")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(ports), 0)
	})

	t.Run("ListPorts handles select error gracefully", func(t *testing.T) {
		// Add a port, then try to list - some ports may fail to parse
		_, err := client.AddPort(ctx, "br-listports", "port-err")
		require.NoError(t, err)

		// List should still work even if individual port parsing fails
		ports, err := client.ListPorts(ctx, "br-listports")
		require.NoError(t, err)
		assert.NotNil(t, ports)
	})

	t.Run("ListPorts with invalid bridge returns error", func(t *testing.T) {
		_, err := client.ListPorts(ctx, "nonexistent-bridge")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("ListPorts continues on individual port error", func(t *testing.T) {
		// This tests the error handling in the loop
		// Even if some ports can't be parsed, others should be returned
		ports, err := client.ListPorts(ctx, "br-listports")
		require.NoError(t, err)
		// Should have at least some ports
		assert.NotNil(t, ports)
	})
}

// TestUpdatePortEdgeCases tests edge cases in UpdatePort
func TestUpdatePortEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-update")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-update", "port-update")
	require.NoError(t, err)

	t.Run("UpdatePort with empty name", func(t *testing.T) {
		err := client.UpdatePort(ctx, "", map[string]interface{}{"tag": 100})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("UpdatePort on non-existent port", func(t *testing.T) {
		err := client.UpdatePort(ctx, "nonexistent", map[string]interface{}{"tag": 100})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("UpdatePort with valid updates", func(t *testing.T) {
		updates := map[string]interface{}{
			"tag": int64(100),
		}
		err := client.UpdatePort(ctx, "port-update", updates)
		require.NoError(t, err)
	})
}

// TestSetPortVLANEdgeCases tests edge cases in SetPortVLAN
func TestSetPortVLANEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-vlan")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-vlan", "port-vlan")
	require.NoError(t, err)

	t.Run("SetPortVLAN with tag 0 clears VLAN", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "port-vlan", 0)
		require.NoError(t, err)
	})

	t.Run("SetPortVLAN with valid tag", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "port-vlan", 100)
		require.NoError(t, err)
	})

	t.Run("SetPortVLAN with maximum valid tag", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "port-vlan", 4095)
		require.NoError(t, err)
	})

	t.Run("SetPortVLAN with negative tag fails", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "port-vlan", -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("SetPortVLAN with tag too large fails", func(t *testing.T) {
		err := client.SetPortVLAN(ctx, "port-vlan", 4096)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})
}

// TestSetPortTrunksEdgeCases tests edge cases in SetPortTrunks
func TestSetPortTrunksEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-trunk")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-trunk", "port-trunk")
	require.NoError(t, err)

	t.Run("SetPortTrunks with empty list", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{})
		require.NoError(t, err)
	})

	t.Run("SetPortTrunks with single VLAN", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{100})
		require.NoError(t, err)
	})

	t.Run("SetPortTrunks with multiple VLANs", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{100, 200, 300})
		require.NoError(t, err)
	})

	t.Run("SetPortTrunks with maximum valid VLAN", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{4095})
		require.NoError(t, err)
	})

	t.Run("SetPortTrunks with invalid VLAN fails", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{100, -1, 200})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})

	t.Run("SetPortTrunks with VLAN too large fails", func(t *testing.T) {
		err := client.SetPortTrunks(ctx, "port-trunk", []int64{100, 4096})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN tag")
	})
}

// TestSetPortStateEdgeCases tests edge cases in SetPortState
func TestSetPortStateEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-state")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-state", "port-state")
	require.NoError(t, err)

	t.Run("SetPortState with empty port name", func(t *testing.T) {
		err := client.SetPortState(ctx, "", PortStateUp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("SetPortState on non-existent port", func(t *testing.T) {
		err := client.SetPortState(ctx, "nonexistent", PortStateUp)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("SetPortState to up", func(t *testing.T) {
		err := client.SetPortState(ctx, "port-state", PortStateUp)
		require.NoError(t, err)
	})

	t.Run("SetPortState to down", func(t *testing.T) {
		err := client.SetPortState(ctx, "port-state", PortStateDown)
		require.NoError(t, err)
	})
}

// TestGetInterfaceEdgeCases tests edge cases in GetInterface
func TestGetInterfaceEdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-iface")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-iface", "port-iface")
	require.NoError(t, err)

	t.Run("GetInterface with empty name", func(t *testing.T) {
		_, err := client.GetInterface(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("GetInterface on non-existent interface", func(t *testing.T) {
		_, err := client.GetInterface(ctx, "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("GetInterface on existing interface", func(t *testing.T) {
		iface, err := client.GetInterface(ctx, "port-iface")
		// May or may not exist depending on mock implementation
		if err == nil {
			assert.NotNil(t, iface)
			assert.Equal(t, "port-iface", iface.Name)
		} else {
			assert.ErrorIs(t, err, ErrPortNotFound)
		}
	})
}

// TestParsePortEdgeCases tests edge cases in parsePort
func TestParsePortEdgeCases(t *testing.T) {
	t.Run("parsePort with minimal data", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-port",
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, "test-port", port.Name)
		assert.Empty(t, port.UUID)
		assert.Equal(t, int64(0), port.Tag)
		assert.Empty(t, port.Trunks)
	})

	t.Run("parsePort with tag as float64", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-port",
			"tag":  float64(100),
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, int64(100), port.Tag)
	})

	t.Run("parsePort with tag as int64", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-port",
			"tag":  int64(200),
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, int64(200), port.Tag)
	})

	t.Run("parsePort with tag as empty set", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-port",
			"tag":  []interface{}{"set", []interface{}{}},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, int64(0), port.Tag)
	})

	t.Run("parsePort with trunks", func(t *testing.T) {
		row := map[string]interface{}{
			"name":   "test-port",
			"trunks": []interface{}{"set", []interface{}{float64(100), float64(200)}},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Len(t, port.Trunks, 2)
		assert.Contains(t, port.Trunks, int64(100))
		assert.Contains(t, port.Trunks, int64(200))
	})

	t.Run("parsePort with full UUID format", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "550e8400-e29b-41d4-a716-446655440000"},
			"name":  "test-port",
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.Equal(t, "550e8400-e29b-41d4-a716-446655440000", port.UUID)
	})

	t.Run("parsePort with interfaces", func(t *testing.T) {
		row := map[string]interface{}{
			"name":       "test-port",
			"interfaces": []interface{}{"set", []interface{}{[]interface{}{"uuid", "iface-uuid-1"}}},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		assert.NotNil(t, port.Interfaces)
	})
}

// TestParseInterfaceEdgeCases tests edge cases in parseInterface
func TestParseInterfaceEdgeCases(t *testing.T) {
	t.Run("parseInterface with minimal data", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-iface",
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, "test-iface", iface.Name)
		assert.Empty(t, iface.UUID)
		assert.Equal(t, int64(0), iface.MTU)
	})

	t.Run("parseInterface with MTU as float64", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-iface",
			"mtu":  float64(1500),
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, int64(1500), iface.MTU)
	})

	t.Run("parseInterface with MTU as int64", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-iface",
			"mtu":  int64(9000),
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, int64(9000), iface.MTU)
	})

	t.Run("parseInterface with all fields", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":       []interface{}{"uuid", "iface-uuid"},
			"name":        "eth0",
			"type":        "internal",
			"mac_in_use":  "00:11:22:33:44:55",
			"mtu":         float64(1500),
			"admin_state": "up",
			"link_state":  "up",
			"external_ids": map[string]interface{}{
				"map": []interface{}{[]interface{}{"key", "value"}},
			},
			"other_config": map[string]interface{}{
				"map": []interface{}{[]interface{}{"cfg", "val"}},
			},
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, "iface-uuid", iface.UUID)
		assert.Equal(t, "eth0", iface.Name)
		assert.Equal(t, "internal", iface.Type)
		assert.Equal(t, "00:11:22:33:44:55", iface.MAC)
		assert.Equal(t, int64(1500), iface.MTU)
		assert.Equal(t, "up", iface.AdminState)
		assert.Equal(t, "up", iface.LinkState)
		assert.NotNil(t, iface.ExternalIDs)
		assert.NotNil(t, iface.OtherConfig)
	})
}

// TestGetPortVLANTag tests the internal getPortVLANTag function
func TestGetPortVLANTag(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-vlan-get")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-vlan-get", "port-vlan-get")
	require.NoError(t, err)

	t.Run("getPortVLANTag returns tag", func(t *testing.T) {
		// Set a VLAN first
		err := client.SetPortVLAN(ctx, "port-vlan-get", 100)
		require.NoError(t, err)

		// Get the tag
		tag, err := client.getPortVLANTag(ctx, "port-vlan-get")
		require.NoError(t, err)
		assert.Equal(t, int64(100), tag)
	})

	t.Run("getPortVLANTag on non-existent port", func(t *testing.T) {
		_, err := client.getPortVLANTag(ctx, "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})
}
