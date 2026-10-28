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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetFlowStatsEmptyMatch tests GetFlowStats with empty match string
func TestGetFlowStatsEmptyMatch(t *testing.T) {
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

	t.Run("GetFlowStats with empty match string", func(t *testing.T) {
		// This tests the empty match path in GetFlowStats
		// Will fail because native OpenFlow client can't connect (no .mgmt socket)
		_, err := client.GetFlowStats(ctx, "br0", "")
		assert.Error(t, err)
	})

	t.Run("GetFlowStats with invalid bridge name", func(t *testing.T) {
		_, err := client.GetFlowStats(ctx, "", "in_port=1")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})

	t.Run("GetFlowStats not connected", func(t *testing.T) {
		// Use a client with a nonexistent socket so lazy connect fails
		deadClient, err := NewClient(filepath.Join(tmpDir, "nonexistent.sock"))
		require.NoError(t, err)
		defer deadClient.Close()

		_, err = deadClient.GetFlowStats(ctx, "br0", "in_port=1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestDispatcherNetworkErrors tests dispatcher error handling on connection close
func TestDispatcherNetworkErrors(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	t.Run("dispatcher handles connection close", func(t *testing.T) {
		client, err := NewClient(socketPath)
		require.NoError(t, err)

		ctx := context.Background()
		err = client.Connect(ctx)
		require.NoError(t, err)

		// Verify connected
		assert.True(t, client.IsConnected())

		// Close the server connection to simulate network error
		server.mu.Lock()
		if server.conn != nil {
			if err := server.conn.Close(); err != nil {
				t.Logf("cleanup: server conn close: %v", err)
			}
		}
		server.mu.Unlock()

		// Attempt an operation -- the dispatcher will detect the broken
		// connection when it tries to read the response
		shortCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, _ = client.ListDatabases(shortCtx)

		// Closing should always work, regardless of connection state
		err = client.Close()
		assert.NoError(t, err)
	})
}

// TestCallContextCancellation tests call with context cancellation
func TestCallContextCancellation(t *testing.T) {
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

	t.Run("call with cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.call(ctx, "test_method", nil)
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	})
}

// TestCloseOpenFlowClient tests closeOpenFlowClient functionality
func TestCloseOpenFlowClient(t *testing.T) {
	client := &Client{
		ofClients: make(map[string]*openflow.Client),
	}

	t.Run("closeOpenFlowClient with non-existent bridge", func(t *testing.T) {
		// Should not panic when closing non-existent client
		client.closeOpenFlowClient("nonexistent")
		assert.Len(t, client.ofClients, 0)
	})
}

// TestListPortsWithContinueOnError tests ListPorts error handling
func TestListPortsWithContinueOnError(t *testing.T) {
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

	t.Run("ListPorts continues on individual port errors", func(t *testing.T) {
		// First create a bridge
		_, err := client.CreateBridge(ctx, "br-test")
		require.NoError(t, err)

		// Get the bridge to verify it exists
		br, err := client.GetBridge(ctx, "br-test")
		require.NoError(t, err)
		assert.NotNil(t, br)

		// ListPorts should handle gracefully even if some ports have issues
		ports, err := client.ListPorts(ctx, "br-test")
		assert.NoError(t, err)
		assert.NotNil(t, ports)
	})

	t.Run("ListPorts with empty bridge name", func(t *testing.T) {
		_, err := client.ListPorts(ctx, "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})
}

// TestGetInterfaceWithEmptyName tests GetInterface with empty name
func TestGetInterfaceWithEmptyName(t *testing.T) {
	client := &Client{}
	client.connected.Store(true)

	t.Run("GetInterface with empty name", func(t *testing.T) {
		_, err := client.GetInterface(context.Background(), "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidPortName, err)
	})
}

// TestGetInterfaceNotFound tests GetInterface when interface doesn't exist
func TestGetInterfaceNotFound(t *testing.T) {
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

	t.Run("GetInterface not found", func(t *testing.T) {
		_, err := client.GetInterface(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Equal(t, ErrPortNotFound, err)
	})
}

// TestDisconnectWithOpenFlowClients tests Disconnect cleanup of OpenFlow clients
func TestDisconnectWithOpenFlowClients(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "db.sock")

	server, err := newMockOVSDBServer(t, socketPath)
	require.NoError(t, err)
	defer server.Close()
	server.Start()

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	ctx := context.Background()
	err = client.Connect(ctx)
	require.NoError(t, err)

	t.Run("Disconnect cleans up OpenFlow clients map", func(t *testing.T) {
		err := client.Disconnect()
		assert.NoError(t, err)
		assert.Len(t, client.ofClients, 0)
	})
}

// TestCallNotConnected tests call when not connected
func TestCallNotConnected(t *testing.T) {
	client := &Client{}

	t.Run("call when not connected", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.call(ctx, "test", nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestGetOpenVSwitchUUIDNoRows tests getOpenVSwitchUUID with no rows
func TestGetOpenVSwitchUUIDNoRows(t *testing.T) {
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

	t.Run("getOpenVSwitchUUID handles no rows error", func(t *testing.T) {
		// Clear the Open_vSwitch table to simulate no rows
		server.databases[DefaultDatabase].tables["Open_vSwitch"].mu.Lock()
		server.databases[DefaultDatabase].tables["Open_vSwitch"].rows = make(map[string]map[string]interface{})
		server.databases[DefaultDatabase].tables["Open_vSwitch"].mu.Unlock()

		_, err := client.getOpenVSwitchUUID(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no Open_vSwitch row found")
	})
}

// TestListFlowsNotConnected tests ListFlows when not connected
func TestListFlowsNotConnected(t *testing.T) {
	client := &Client{}

	t.Run("ListFlows when not connected", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.ListFlows(ctx, "br0")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("ListFlows with empty bridge name", func(t *testing.T) {
		ctx := context.Background()
		_, err := client.ListFlows(ctx, "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})
}

// TestDeleteFlowNotConnected tests DeleteFlow when not connected
func TestDeleteFlowNotConnected(t *testing.T) {
	client := &Client{}

	t.Run("DeleteFlow when not connected", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteFlow(ctx, "br0", "in_port=1")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("DeleteFlow with empty bridge name", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteFlow(ctx, "", "in_port=1")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})

	t.Run("DeleteFlow with empty match", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteFlow(ctx, "br0", "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidFlow, err)
	})
}

// TestAddFlowNotConnected tests AddFlow when not connected
func TestAddFlowNotConnected(t *testing.T) {
	client := &Client{}

	flow := &FlowMod{
		Table:    0,
		Priority: 100,
		Match:    "in_port=1",
		Actions:  "output:2",
	}

	t.Run("AddFlow when not connected", func(t *testing.T) {
		ctx := context.Background()
		err := client.AddFlow(ctx, "br0", flow)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("AddFlow with empty bridge name", func(t *testing.T) {
		ctx := context.Background()
		err := client.AddFlow(ctx, "", flow)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})

	t.Run("AddFlow with nil flow", func(t *testing.T) {
		ctx := context.Background()
		err := client.AddFlow(ctx, "br0", nil)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidFlow, err)
	})
}

// TestModifyFlowNotConnected tests ModifyFlow when not connected
func TestModifyFlowNotConnected(t *testing.T) {
	client := &Client{}

	flow := &FlowMod{
		Table:    0,
		Priority: 100,
		Match:    "in_port=1",
		Actions:  "output:2",
	}

	t.Run("ModifyFlow when not connected", func(t *testing.T) {
		ctx := context.Background()
		err := client.ModifyFlow(ctx, "br0", flow)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("ModifyFlow with empty bridge name", func(t *testing.T) {
		ctx := context.Background()
		err := client.ModifyFlow(ctx, "", flow)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})

	t.Run("ModifyFlow with nil flow", func(t *testing.T) {
		ctx := context.Background()
		err := client.ModifyFlow(ctx, "br0", nil)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidFlow, err)
	})
}

// TestDeleteAllFlowsNotConnected tests DeleteAllFlows when not connected
func TestDeleteAllFlowsNotConnected(t *testing.T) {
	client := &Client{}

	t.Run("DeleteAllFlows when not connected", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteAllFlows(ctx, "br0")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("DeleteAllFlows with empty bridge name", func(t *testing.T) {
		ctx := context.Background()
		err := client.DeleteAllFlows(ctx, "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidBridgeName, err)
	})
}
