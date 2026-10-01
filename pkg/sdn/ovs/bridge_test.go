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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupBridgeTest(t *testing.T) (*Client, *mockOVSDBServer) {
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

	return client, server
}

func TestClient_CreateBridge(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("create bridge successfully", func(t *testing.T) {
		bridge, err := client.CreateBridge(ctx, "br0")
		require.NoError(t, err)
		assert.NotNil(t, bridge)
		assert.Equal(t, "br0", bridge.Name)
		assert.NotEmpty(t, bridge.UUID)
	})

	t.Run("create bridge with empty name", func(t *testing.T) {
		_, err := client.CreateBridge(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("create duplicate bridge", func(t *testing.T) {
		// Create first bridge
		_, err := client.CreateBridge(ctx, "br-dup")
		require.NoError(t, err)

		// Try to create duplicate
		_, err = client.CreateBridge(ctx, "br-dup")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeExists)
	})

	t.Run("create bridge when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.CreateBridge(ctx, "br-fail")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_DeleteBridge(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("delete existing bridge", func(t *testing.T) {
		// Create bridge first
		_, err := client.CreateBridge(ctx, "br-del")
		require.NoError(t, err)

		// Delete it
		err = client.DeleteBridge(ctx, "br-del")
		require.NoError(t, err)

		// Verify it's gone
		_, err = client.GetBridge(ctx, "br-del")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("delete bridge with empty name", func(t *testing.T) {
		err := client.DeleteBridge(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("delete non-existent bridge", func(t *testing.T) {
		err := client.DeleteBridge(ctx, "br-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("delete bridge when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		err = disconnectedClient.DeleteBridge(ctx, "br-fail")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_GetBridge(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	// Add test bridge to mock database
	server.AddBridge("br-test", "test-bridge-uuid")

	t.Run("get existing bridge", func(t *testing.T) {
		bridge, err := client.GetBridge(ctx, "br-test")
		require.NoError(t, err)
		assert.NotNil(t, bridge)
		assert.Equal(t, "br-test", bridge.Name)
		assert.Equal(t, "test-bridge-uuid", bridge.UUID)
	})

	t.Run("get bridge with empty name", func(t *testing.T) {
		_, err := client.GetBridge(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("get non-existent bridge", func(t *testing.T) {
		_, err := client.GetBridge(ctx, "br-nonexist")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("get bridge when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.GetBridge(ctx, "br-test")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_ListBridges(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("list bridges when none exist", func(t *testing.T) {
		bridges, err := client.ListBridges(ctx)
		require.NoError(t, err)
		assert.Empty(t, bridges)
	})

	t.Run("list multiple bridges", func(t *testing.T) {
		// Create bridges
		_, err := client.CreateBridge(ctx, "br1")
		require.NoError(t, err)
		_, err = client.CreateBridge(ctx, "br2")
		require.NoError(t, err)

		// List them
		bridges, err := client.ListBridges(ctx)
		require.NoError(t, err)
		assert.Len(t, bridges, 2)

		names := make([]string, len(bridges))
		for i, br := range bridges {
			names[i] = br.Name
		}
		assert.Contains(t, names, "br1")
		assert.Contains(t, names, "br2")
	})

	t.Run("list bridges when not connected", func(t *testing.T) {
		disconnectedClient, err := NewClient(filepath.Join(t.TempDir(), "disconnected.sock"))
		require.NoError(t, err)

		_, err = disconnectedClient.ListBridges(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

func TestClient_UpdateBridge(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("update existing bridge", func(t *testing.T) {
		// Create bridge
		_, err := client.CreateBridge(ctx, "br-update")
		require.NoError(t, err)

		// Update it
		updates := map[string]interface{}{
			"datapath_type": "netdev",
		}
		err = client.UpdateBridge(ctx, "br-update", updates)
		require.NoError(t, err)
	})

	t.Run("update bridge with empty name", func(t *testing.T) {
		err := client.UpdateBridge(ctx, "", map[string]interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("update non-existent bridge", func(t *testing.T) {
		err := client.UpdateBridge(ctx, "br-nonexist", map[string]interface{}{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestClient_SetBridgeFailMode(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	// Create test bridge
	_, err := client.CreateBridge(ctx, "br-failmode")
	require.NoError(t, err)

	t.Run("set standalone fail mode", func(t *testing.T) {
		err := client.SetBridgeFailMode(ctx, "br-failmode", "standalone")
		require.NoError(t, err)
	})

	t.Run("set secure fail mode", func(t *testing.T) {
		err := client.SetBridgeFailMode(ctx, "br-failmode", "secure")
		require.NoError(t, err)
	})

	t.Run("clear fail mode", func(t *testing.T) {
		err := client.SetBridgeFailMode(ctx, "br-failmode", "")
		require.NoError(t, err)
	})

	t.Run("set invalid fail mode", func(t *testing.T) {
		err := client.SetBridgeFailMode(ctx, "br-failmode", "invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid fail mode")
	})

	t.Run("set fail mode on non-existent bridge", func(t *testing.T) {
		err := client.SetBridgeFailMode(ctx, "br-nonexist", "standalone")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		assert.ErrorIs(t, client.SetBridgeFailMode(ctx, "", "secure"), ErrInvalidBridgeName)
	})
}

// TestClient_SetBridgeFailMode_WaitsForVswitchd: the change bumps next_cfg
// in the same transaction and returns only once cur_cfg has caught up,
// because vswitchd flushes the bridge's flows when it applies a fail-mode
// change, after the commit (#614).
func TestClient_SetBridgeFailMode_WaitsForVswitchd(t *testing.T) {
	client, server := setupBridgeTest(t)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	ctx := context.Background()
	_, err := client.CreateBridge(ctx, "br-wait")
	require.NoError(t, err)

	require.NoError(t, client.SetBridgeFailMode(ctx, "br-wait", "secure"))
	rows, err := client.Select(ctx, ovsTable, nil, []string{"next_cfg", "cur_cfg"})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	// One bump for the bridge's creation, one for the fail-mode change.
	assert.Equal(t, float64(2), rows[0]["next_cfg"], "the change bumps next_cfg")
	assert.Equal(t, float64(2), rows[0]["cur_cfg"])

	bridge, err := client.GetBridge(ctx, "br-wait")
	require.NoError(t, err)
	assert.Equal(t, "secure", bridge.FailMode)
}

func TestClient_SetBridgeFailMode_ReportsAConfigurationNeverApplied(t *testing.T) {
	client, server := setupBridgeTest(t)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	_, err := client.CreateBridge(context.Background(), "br-stuck")
	require.NoError(t, err)
	server.holdCurCfg.Store(true)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err = client.SetBridgeFailMode(ctx, "br-stuck", "secure")
	var notApplied *ErrConfigNotApplied
	require.ErrorAs(t, err, &notApplied)
	assert.Equal(t, int64(2), notApplied.Target)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Contains(t, err.Error(), "did not apply configuration 2")
}

// TestClient_CreateBridge_WaitsForVswitchd: until vswitchd applies the new
// bridge it has no OpenFlow management socket, so CreateBridge returns only
// once cur_cfg reaches the transaction's next_cfg.
func TestClient_CreateBridge_WaitsForVswitchd(t *testing.T) {
	client, server := setupBridgeTest(t)
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	_, err := client.CreateBridge(context.Background(), "br-applied")
	require.NoError(t, err)
	rows, err := client.Select(context.Background(), ovsTable, nil, []string{"cur_cfg"})
	require.NoError(t, err)
	assert.Equal(t, float64(1), rows[0]["cur_cfg"])

	server.holdCurCfg.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = client.CreateBridge(ctx, "br-unapplied")
	var notApplied *ErrConfigNotApplied
	require.ErrorAs(t, err, &notApplied)
	assert.Equal(t, int64(2), notApplied.Target)
}

func TestCfgSequence_RefusesWhatIsNotOneNumber(t *testing.T) {
	_, ok := cfgSequence(nil, "cur_cfg")
	assert.False(t, ok)
	_, ok = cfgSequence([]map[string]interface{}{{"cur_cfg": "x"}}, "cur_cfg")
	assert.False(t, ok)
	_, ok = cfgSequence([]map[string]interface{}{{"cur_cfg": float64(1)}, {"cur_cfg": float64(2)}}, "cur_cfg")
	assert.False(t, ok)
	v, ok := cfgSequence([]map[string]interface{}{{"cur_cfg": float64(7)}}, "cur_cfg")
	assert.True(t, ok)
	assert.Equal(t, int64(7), v)
}

func TestClient_SetBridgeProtocols(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	// Create test bridge
	_, err := client.CreateBridge(ctx, "br-proto")
	require.NoError(t, err)

	t.Run("set valid protocols", func(t *testing.T) {
		protocols := []string{"OpenFlow13", "OpenFlow14"}
		err := client.SetBridgeProtocols(ctx, "br-proto", protocols)
		require.NoError(t, err)
	})

	t.Run("set single protocol", func(t *testing.T) {
		protocols := []string{"OpenFlow13"}
		err := client.SetBridgeProtocols(ctx, "br-proto", protocols)
		require.NoError(t, err)
	})

	t.Run("set empty protocols", func(t *testing.T) {
		protocols := []string{}
		err := client.SetBridgeProtocols(ctx, "br-proto", protocols)
		require.NoError(t, err)
	})

	t.Run("set invalid protocol", func(t *testing.T) {
		protocols := []string{"InvalidProtocol"}
		err := client.SetBridgeProtocols(ctx, "br-proto", protocols)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidProtocol)
	})

	t.Run("set protocols on non-existent bridge", func(t *testing.T) {
		err := client.SetBridgeProtocols(ctx, "br-nonexist", []string{"OpenFlow13"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeNotFound)
	})
}

func TestParseBridge(t *testing.T) {
	t.Run("parse complete bridge row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid":                 []interface{}{"uuid", "test-uuid"},
			"name":                  "br0",
			"datapath_type":         "system",
			"fail_mode":             "standalone",
			"ports":                 []interface{}{"set", []interface{}{[]interface{}{"uuid", "port1"}}},
			"protocols":             []interface{}{"set", []interface{}{"OpenFlow13"}},
			"stp_enable":            true,
			"rstp_enable":           false,
			"mcast_snooping_enable": true,
			"external_ids":          []interface{}{"map", []interface{}{[]interface{}{"key", "value"}}},
			"other_config":          []interface{}{"map", []interface{}{}},
			"status":                []interface{}{"map", []interface{}{}},
		}

		bridge, err := parseBridge(row)
		require.NoError(t, err)
		assert.Equal(t, "test-uuid", bridge.UUID)
		assert.Equal(t, "br0", bridge.Name)
		assert.Equal(t, "system", bridge.DatapathType)
		assert.Equal(t, "standalone", bridge.FailMode)
		assert.Contains(t, bridge.Ports, "port1")
		assert.Contains(t, bridge.FlowProtocols, "OpenFlow13")
		assert.True(t, bridge.STP)
		assert.False(t, bridge.RSTP)
		assert.True(t, bridge.McastSnooping)
		assert.Equal(t, "value", bridge.ExternalIDs["key"])
	})

	t.Run("parse minimal bridge row", func(t *testing.T) {
		row := map[string]interface{}{
			"_uuid": []interface{}{"uuid", "minimal-uuid"},
			"name":  "br-minimal",
		}

		bridge, err := parseBridge(row)
		require.NoError(t, err)
		assert.Equal(t, "minimal-uuid", bridge.UUID)
		assert.Equal(t, "br-minimal", bridge.Name)
		assert.Empty(t, bridge.DatapathType)
		assert.Empty(t, bridge.FailMode)
		assert.Empty(t, bridge.Ports)
	})
}

func TestParseUUIDSet(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: nil,
		},
		{
			name:     "single UUID",
			input:    []interface{}{"uuid", "test-uuid"},
			expected: []string{"test-uuid"},
		},
		{
			name: "set of UUIDs",
			input: []interface{}{"set", []interface{}{
				[]interface{}{"uuid", "uuid1"},
				[]interface{}{"uuid", "uuid2"},
			}},
			expected: []string{"uuid1", "uuid2"},
		},
		{
			name:     "empty set",
			input:    []interface{}{"set", []interface{}{}},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUUIDSet(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseStringSet(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: nil,
		},
		{
			name:     "single string",
			input:    "value1",
			expected: []string{"value1"},
		},
		{
			name:     "set of strings",
			input:    []interface{}{"set", []interface{}{"value1", "value2"}},
			expected: []string{"value1", "value2"},
		},
		{
			name:     "empty set",
			input:    []interface{}{"set", []interface{}{}},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseStringSet(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMap(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected map[string]string
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name: "valid map",
			input: []interface{}{"map", []interface{}{
				[]interface{}{"key1", "value1"},
				[]interface{}{"key2", "value2"},
			}},
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "empty map",
			input:    []interface{}{"map", []interface{}{}},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		expected bool
	}{
		{"OpenFlow10", "OpenFlow10", true},
		{"OpenFlow11", "OpenFlow11", true},
		{"OpenFlow12", "OpenFlow12", true},
		{"OpenFlow13", "OpenFlow13", true},
		{"OpenFlow14", "OpenFlow14", true},
		{"OpenFlow15", "OpenFlow15", true},
		{"lowercase", "openflow13", true},
		{"mixed case", "OpenFLOW13", true},
		{"invalid", "OpenFlow99", false},
		{"empty", "", false},
		{"random", "InvalidProtocol", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidProtocol(tt.protocol)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_CreateBridgeWithOptions(t *testing.T) {
	client, server := setupBridgeTest(t)
	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("create with full options", func(t *testing.T) {
		bridge, err := client.CreateBridgeWithOptions(ctx, "br-opts", &BridgeOptions{
			DatapathType: "netdev",
			FailMode:     "secure",
			Protocols:    []string{"OpenFlow13", "OpenFlow15"},
		})
		require.NoError(t, err)
		require.NotNil(t, bridge)
		assert.Equal(t, "br-opts", bridge.Name)
		assert.Equal(t, "netdev", bridge.DatapathType)
		assert.Equal(t, "secure", bridge.FailMode)
		assert.ElementsMatch(t, []string{"OpenFlow13", "OpenFlow15"}, bridge.FlowProtocols)

		// Wire-level: the Bridge insert row must carry the optional columns.
		var insertRow map[string]interface{}
		for _, op := range server.TransactOps() {
			if op.Op == "insert" && op.Table == "Bridge" {
				if name, ok := op.Row["name"].(string); ok && name == "br-opts" {
					insertRow = op.Row
				}
			}
		}
		require.NotNil(t, insertRow, "Bridge insert operation not recorded")
		assert.Equal(t, "netdev", insertRow["datapath_type"])
		assert.Equal(t, "secure", insertRow["fail_mode"])
	})

	t.Run("nil options matches CreateBridge defaults", func(t *testing.T) {
		bridge, err := client.CreateBridgeWithOptions(ctx, "br-nil-opts", nil)
		require.NoError(t, err)
		require.NotNil(t, bridge)
		assert.Equal(t, "", bridge.DatapathType)
		assert.Empty(t, bridge.FailMode)
		assert.Empty(t, bridge.FlowProtocols)

		var insertRow map[string]interface{}
		for _, op := range server.TransactOps() {
			if op.Op == "insert" && op.Table == "Bridge" {
				if name, ok := op.Row["name"].(string); ok && name == "br-nil-opts" {
					insertRow = op.Row
				}
			}
		}
		require.NotNil(t, insertRow, "Bridge insert operation not recorded")
		assert.Equal(t, "", insertRow["datapath_type"])
		_, hasFailMode := insertRow["fail_mode"]
		assert.False(t, hasFailMode, "fail_mode must be omitted when unset")
		_, hasProtocols := insertRow["protocols"]
		assert.False(t, hasProtocols, "protocols must be omitted when unset")
	})

	t.Run("empty options struct matches defaults", func(t *testing.T) {
		bridge, err := client.CreateBridgeWithOptions(ctx, "br-zero-opts", &BridgeOptions{})
		require.NoError(t, err)
		require.NotNil(t, bridge)
		assert.Equal(t, "", bridge.DatapathType)
	})

	t.Run("empty name", func(t *testing.T) {
		_, err := client.CreateBridgeWithOptions(ctx, "", &BridgeOptions{DatapathType: "netdev"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("invalid fail mode", func(t *testing.T) {
		_, err := client.CreateBridgeWithOptions(ctx, "br-badfm", &BridgeOptions{FailMode: "bogus"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid fail mode")
	})

	t.Run("invalid protocol", func(t *testing.T) {
		_, err := client.CreateBridgeWithOptions(ctx, "br-badproto", &BridgeOptions{Protocols: []string{"OpenFlow99"}})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidProtocol)
	})

	t.Run("duplicate bridge", func(t *testing.T) {
		_, err := client.CreateBridgeWithOptions(ctx, "br-opts", &BridgeOptions{DatapathType: "netdev"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBridgeExists)
	})
}
