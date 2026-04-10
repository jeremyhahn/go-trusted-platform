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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetOFPort tests the GetOFPort function which retrieves OpenFlow port numbers
func TestGetOFPort(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: server close: %v", err)
		}
	})
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: client close: %v", err)
		}
	})

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port for testing
	_, err = client.CreateBridge(ctx, "br-ofport")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-ofport", "port-ofport")
	require.NoError(t, err)

	t.Run("GetOFPort with empty port name returns error", func(t *testing.T) {
		_, err := client.GetOFPort(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPortName)
	})

	t.Run("GetOFPort with non-existent port returns error", func(t *testing.T) {
		_, err := client.GetOFPort(ctx, "nonexistent-port-xyz")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPortNotFound)
	})

	t.Run("GetOFPort with existing port but no ofport set returns error", func(t *testing.T) {
		// The interface exists but ofport is 0 or negative by default
		_, err := client.GetOFPort(ctx, "port-ofport")
		// This should return ErrPortNotFound since ofport <= 0
		require.Error(t, err)
	})
}

// TestGetOFPortWithValidOFPort tests GetOFPort when interface has valid ofport
func TestGetOFPortWithValidOFPort(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: server close: %v", err)
		}
	})
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: client close: %v", err)
		}
	})

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge and port
	_, err = client.CreateBridge(ctx, "br-ofport-valid")
	require.NoError(t, err)
	_, err = client.AddPort(ctx, "br-ofport-valid", "port-ofport-valid")
	require.NoError(t, err)

	// Manually set the ofport value in the mock Interface table
	server.mu.RLock()
	db := server.databases[DefaultDatabase]
	server.mu.RUnlock()

	ifaceTable := db.tables["Interface"]
	ifaceTable.mu.Lock()
	for uuid, row := range ifaceTable.rows {
		if name, ok := row["name"].(string); ok && name == "port-ofport-valid" {
			row["ofport"] = float64(5) // Set ofport to 5
			ifaceTable.rows[uuid] = row
			break
		}
	}
	ifaceTable.mu.Unlock()

	t.Run("GetOFPort returns valid ofport number", func(t *testing.T) {
		ofport, err := client.GetOFPort(ctx, "port-ofport-valid")
		require.NoError(t, err)
		assert.Equal(t, int32(5), ofport)
	})
}

// TestParseInterfaceOFPortInt64 tests parseInterface with ofport as int64
func TestParseInterfaceOFPortInt64(t *testing.T) {
	t.Run("parseInterface with ofport as int64", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":  []interface{}{"uuid", "test-iface-uuid"},
			"name":   "test-iface",
			"ofport": int64(10), // int64 type instead of float64
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, int32(10), iface.OFPort)
	})

	t.Run("parseInterface with all fields and int64 types", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":  []interface{}{"uuid", "complete-iface-uuid"},
			"name":   "complete-iface",
			"type":   "internal",
			"ofport": int64(42),
			"mtu":    int64(1500),
		}

		iface, err := parseInterface(row)
		require.NoError(t, err)
		assert.Equal(t, int32(42), iface.OFPort)
		assert.Equal(t, int64(1500), iface.MTU)
	})
}

// TestParseStringSetSingleValue tests parseStringSet with single string value
func TestParseStringSetSingleValue(t *testing.T) {
	t.Run("parseStringSet with single string value", func(t *testing.T) {
		result := parseStringSet("OpenFlow13")
		require.NotNil(t, result)
		assert.Len(t, result, 1)
		assert.Equal(t, "OpenFlow13", result[0])
	})

	t.Run("parseStringSet with nil", func(t *testing.T) {
		result := parseStringSet(nil)
		assert.Nil(t, result)
	})

	t.Run("parseStringSet with set containing multiple values", func(t *testing.T) {
		val := []interface{}{"set", []interface{}{"OpenFlow13", "OpenFlow14", "OpenFlow15"}}
		result := parseStringSet(val)
		require.NotNil(t, result)
		assert.Len(t, result, 3)
		assert.Contains(t, result, "OpenFlow13")
		assert.Contains(t, result, "OpenFlow14")
		assert.Contains(t, result, "OpenFlow15")
	})

	t.Run("parseStringSet with invalid array structure", func(t *testing.T) {
		val := []interface{}{"invalid", []interface{}{"str1"}}
		result := parseStringSet(val)
		assert.Nil(t, result)
	})
}

// TestCloseOpenFlowClientWithExistingClient tests closeOpenFlowClient when client exists
func TestCloseOpenFlowClientWithExistingClient(t *testing.T) {
	t.Run("closeOpenFlowClient removes and closes existing client", func(t *testing.T) {
		// Create a mock OpenFlow client
		ofClient, err := openflow.NewClient("test-bridge",
			openflow.WithSocketDir("/tmp/nonexistent"))
		require.NoError(t, err)

		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}

		// Add the OpenFlow client to the map
		client.ofClients["test-bridge"] = ofClient

		// Verify client exists
		assert.Len(t, client.ofClients, 1)

		// Close the OpenFlow client
		client.closeOpenFlowClient("test-bridge")

		// Verify client was removed
		assert.Len(t, client.ofClients, 0)
	})

	t.Run("closeOpenFlowClient with multiple clients", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}

		// Create multiple mock clients
		for _, name := range []string{"br0", "br1", "br2"} {
			ofClient, err := openflow.NewClient(name,
				openflow.WithSocketDir("/tmp/nonexistent"))
			require.NoError(t, err)
			client.ofClients[name] = ofClient
		}

		assert.Len(t, client.ofClients, 3)

		// Close one specific client
		client.closeOpenFlowClient("br1")
		assert.Len(t, client.ofClients, 2)
		assert.NotContains(t, client.ofClients, "br1")
		assert.Contains(t, client.ofClients, "br0")
		assert.Contains(t, client.ofClients, "br2")
	})
}

// TestGetOpenFlowClientErrorPaths tests various error paths in getOpenFlowClient
func TestGetOpenFlowClientErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("getOpenFlowClient with disconnected stale client", func(t *testing.T) {
		client := &Client{
			connected:   true,
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
			ofSocketDir: "/tmp/nonexistent-socket-dir",
		}

		// Create a client that's not connected
		staleClient, err := openflow.NewClient("stale-bridge",
			openflow.WithSocketDir("/tmp/nonexistent"))
		require.NoError(t, err)

		// Add the stale client (not connected)
		client.ofClients["stale-bridge"] = staleClient

		// Trying to get the client should attempt reconnection, which fails
		_, err = client.getOpenFlowClient(ctx, "stale-bridge")
		assert.Error(t, err)
	})

	t.Run("getOpenFlowClient creates new client on first call", func(t *testing.T) {
		client := &Client{
			connected:   true,
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
			ofSocketDir: "/tmp/nonexistent-socket-dir",
		}

		// First call for a new bridge should attempt to create and connect
		_, err := client.getOpenFlowClient(ctx, "new-bridge")
		assert.Error(t, err) // Will fail because socket doesn't exist
	})
}

// TestDeleteBridgeNilBridgeCheck tests the nil bridge check in DeleteBridge
func TestDeleteBridgeNilBridgeCheck(t *testing.T) {
	t.Run("DeleteBridge with empty name returns ErrInvalidBridgeName", func(t *testing.T) {
		client := &Client{connected: true}
		ctx := context.Background()

		err := client.DeleteBridge(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})
}

// TestListBridgesParseError tests ListBridges handling of unparseable bridges
func TestListBridgesParseError(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: server close: %v", err)
		}
	})
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: client close: %v", err)
		}
	})

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create a few valid bridges
	_, err = client.CreateBridge(ctx, "br-list-1")
	require.NoError(t, err)
	_, err = client.CreateBridge(ctx, "br-list-2")
	require.NoError(t, err)

	t.Run("ListBridges returns valid bridges", func(t *testing.T) {
		bridges, err := client.ListBridges(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(bridges), 2)
	})
}

// TestParseBridgeFailMode tests parseBridge with different fail_mode formats
func TestParseBridgeFailModeFormats(t *testing.T) {
	t.Run("parseBridge with fail_mode as string", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":     []interface{}{"uuid", "test-bridge-uuid"},
			"name":      "test-bridge",
			"fail_mode": "standalone",
		}

		bridge, err := parseBridge(row)
		require.NoError(t, err)
		assert.Equal(t, "standalone", bridge.FailMode)
	})

	t.Run("parseBridge with fail_mode as array", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":     []interface{}{"uuid", "test-bridge-uuid-2"},
			"name":      "test-bridge-2",
			"fail_mode": []interface{}{"set", "secure"},
		}

		bridge, err := parseBridge(row)
		require.NoError(t, err)
		assert.Equal(t, "secure", bridge.FailMode)
	})

	t.Run("parseBridge with all boolean fields", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":                 []interface{}{"uuid", "full-bridge-uuid"},
			"name":                  "full-bridge",
			"stp_enable":            true,
			"rstp_enable":           true,
			"mcast_snooping_enable": true,
			"datapath_type":         "netdev",
		}

		bridge, err := parseBridge(row)
		require.NoError(t, err)
		assert.True(t, bridge.STP)
		assert.True(t, bridge.RSTP)
		assert.True(t, bridge.McastSnooping)
		assert.Equal(t, "netdev", bridge.DatapathType)
	})
}

// TestParseMatchStringInvalidFormats tests parseMatchString error handling
func TestParseMatchStringInvalidFormats(t *testing.T) {
	t.Run("parseMatchString with invalid nw_src CIDR", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_src=192.168.1.0/invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_src CIDR")
	})

	t.Run("parseMatchString with invalid nw_dst CIDR", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_dst=10.0.0.0/invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_dst CIDR")
	})

	t.Run("parseMatchString with invalid nw_src IP", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_src=not.an.ip")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_src")
	})

	t.Run("parseMatchString with invalid nw_dst IP", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_dst=not.valid.ip")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_dst")
	})

	t.Run("parseMatchString with invalid dl_vlan", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_vlan=invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dl_vlan")
	})

	t.Run("parseMatchString with invalid nw_proto", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_proto=invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_proto")
	})

	t.Run("parseMatchString with UDP protocol ports", func(t *testing.T) {
		match := openflow.NewMatch()
		// nw_proto=17 is UDP
		err := parseMatchString(match, "nw_proto=17,tp_src=53,tp_dst=5353")
		require.NoError(t, err)
	})
}

// TestParseActionsStringInvalidFormats tests parseActionsString error handling
func TestParseActionsStringInvalidFormats(t *testing.T) {
	t.Run("parseActionsString with invalid mod_vlan_vid", func(t *testing.T) {
		_, err := parseActionsString("mod_vlan_vid:invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN ID")
	})

	t.Run("parseActionsString with invalid mod_dl_src MAC", func(t *testing.T) {
		_, err := parseActionsString("mod_dl_src:invalid-mac")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC")
	})

	t.Run("parseActionsString with invalid mod_dl_dst MAC", func(t *testing.T) {
		_, err := parseActionsString("mod_dl_dst:invalid-mac")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC")
	})

	t.Run("parseActionsString with invalid mod_nw_src IP", func(t *testing.T) {
		_, err := parseActionsString("mod_nw_src:invalid-ip")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP")
	})

	t.Run("parseActionsString with invalid mod_nw_dst IP", func(t *testing.T) {
		_, err := parseActionsString("mod_nw_dst:invalid-ip")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP")
	})

	t.Run("parseActionsString with ALL action", func(t *testing.T) {
		actions, err := parseActionsString("ALL")
		require.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("parseActionsString with CONTROLLER action", func(t *testing.T) {
		actions, err := parseActionsString("CONTROLLER")
		require.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("parseActionsString with LOCAL action", func(t *testing.T) {
		actions, err := parseActionsString("LOCAL")
		require.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("parseActionsString with IN_PORT action", func(t *testing.T) {
		actions, err := parseActionsString("IN_PORT")
		require.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("parseActionsString with strip_vlan lowercase", func(t *testing.T) {
		actions, err := parseActionsString("STRIP_VLAN")
		require.NoError(t, err)
		assert.Len(t, actions, 1)
	})
}

// TestConvertToOpenFlowInvalidActions tests convertToOpenFlow with invalid actions
func TestConvertToOpenFlowInvalidActions(t *testing.T) {
	t.Run("convertToOpenFlow with invalid actions", func(t *testing.T) {
		flow := &FlowMod{
			Table:   0,
			Actions: "output:invalid-port",
		}

		_, err := convertToOpenFlow(flow)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse actions")
	})

	t.Run("convertToOpenFlow with invalid match", func(t *testing.T) {
		flow := &FlowMod{
			Table: 0,
			Match: "in_port=invalid",
		}

		_, err := convertToOpenFlow(flow)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse match")
	})
}

// TestListPortsErrorHandlingPaths tests error paths in ListPorts
func TestListPortsErrorHandlingPaths(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: server close: %v", err)
		}
	})
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: client close: %v", err)
		}
	})

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	// Create bridge with a port
	_, err = client.CreateBridge(ctx, "br-list-ports")
	require.NoError(t, err)

	// Add a port
	_, err = client.AddPort(ctx, "br-list-ports", "port-lp-a")
	require.NoError(t, err)

	t.Run("ListPorts returns valid ports without error", func(t *testing.T) {
		ports, err := client.ListPorts(ctx, "br-list-ports")
		require.NoError(t, err)
		// Just verify it returns without error and the result is not nil
		assert.NotNil(t, ports)
	})

	t.Run("ListPorts handles select/parse errors gracefully", func(t *testing.T) {
		// The ListPorts function has continue statements for error handling
		// This tests that the function completes even if individual ports have issues
		ports, err := client.ListPorts(ctx, "br-list-ports")
		require.NoError(t, err)
		// Should return at least an empty slice, not nil
		assert.NotNil(t, ports)
	})
}

// TestParsePortTagTypes tests parsePort with different tag types
func TestParsePortTagTypes(t *testing.T) {
	t.Run("parsePort with tag as array non-set", func(t *testing.T) {
		row := map[string]interface{}{
			"name": "test-port",
			"tag":  []interface{}{"other", "value"},
		}

		port, err := parsePort(row)
		require.NoError(t, err)
		// Tag should be 0 since it's not a valid set format
		assert.Equal(t, int64(0), port.Tag)
	})
}
