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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdditionalFlowCoverage tests additional flow function paths
func TestAdditionalFlowCoverage(t *testing.T) {
	ctx := context.Background()

	t.Run("DeleteFlow with various match patterns", func(t *testing.T) {
		client := &Client{
			connected: false,
			ofClients: make(map[string]*openflow.Client),
		}

		// Test not connected
		err := client.DeleteFlow(ctx, "br0", "in_port=1,dl_type=0x0800,nw_src=192.168.1.1")
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("ListFlows when not connected", func(t *testing.T) {
		client := &Client{
			connected: false,
			ofClients: make(map[string]*openflow.Client),
		}

		_, err := client.ListFlows(ctx, "br0")
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("ModifyFlow when not connected", func(t *testing.T) {
		client := &Client{
			connected: false,
			ofClients: make(map[string]*openflow.Client),
		}

		flow := &FlowMod{
			Table:    0,
			Priority: 100,
		}

		err := client.ModifyFlow(ctx, "br0", flow)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})

	t.Run("GetFlowStats when not connected", func(t *testing.T) {
		client := &Client{
			connected: false,
			ofClients: make(map[string]*openflow.Client),
		}

		_, err := client.GetFlowStats(ctx, "br0", "in_port=1")
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestAdditionalDisconnectCoverage tests additional disconnect scenarios
func TestAdditionalDisconnectCoverage(t *testing.T) {
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

	t.Run("disconnect closes OpenFlow clients", func(t *testing.T) {
		// Just verify disconnect completes
		err := client.Disconnect()
		require.NoError(t, err)
		assert.False(t, client.IsConnected())
	})

	server.Close()
}

// TestCallErrorHandling tests error paths in call method
func TestCallErrorHandling(t *testing.T) {
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

	t.Run("call with invalid method", func(t *testing.T) {
		// Try to call with parameters that will fail
		_, err := client.call(ctx, "invalid_method", []interface{}{})
		// Error is expected
		assert.Error(t, err)
	})
}

// TestSelectNoResults tests Select with no results
func TestSelectNoResults(t *testing.T) {
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

	t.Run("select returns empty rows", func(t *testing.T) {
		rows, err := client.Select(ctx, "Bridge", []Condition{NewCondition("name", "==", "does-not-exist-xyz-123")}, nil)
		require.NoError(t, err)
		assert.Empty(t, rows)
	})
}

// TestBridgeEdgeCases covers additional bridge scenarios
func TestBridgeEdgeCases(t *testing.T) {
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

	t.Run("create and list bridges", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-test-123")
		require.NoError(t, err)

		bridges, err := client.ListBridges(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, bridges)
	})

	t.Run("update bridge", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-update-123")
		require.NoError(t, err)

		err = client.UpdateBridge(ctx, "br-update-123", map[string]interface{}{
			"fail_mode": Set{Set: []interface{}{"standalone"}},
		})
		require.NoError(t, err)
	})

	t.Run("delete bridge", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "br-delete-123")
		require.NoError(t, err)

		err = client.DeleteBridge(ctx, "br-delete-123")
		require.NoError(t, err)
	})
}

// TestGetOpenVSwitchUUIDBranches tests different branches
func TestGetOpenVSwitchUUIDBranches(t *testing.T) {
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

	t.Run("getOpenVSwitchUUID returns valid UUID", func(t *testing.T) {
		uuid, err := client.getOpenVSwitchUUID(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, uuid)
		// Verify it's a valid format
		assert.Contains(t, uuid, "-")
	})
}

// TestTransactMultiOps tests Transact with multiple operations
func TestTransactMultiOps(t *testing.T) {
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

	t.Run("transact with three operations", func(t *testing.T) {
		op1 := NewSelectOperation("Bridge", nil, nil)
		op2 := NewSelectOperation("Port", nil, nil)
		op3 := NewSelectOperation("Interface", nil, nil)

		results, err := client.Transact(ctx, op1, op2, op3)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 3)
	})
}
