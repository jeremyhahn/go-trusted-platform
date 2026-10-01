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
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockOpenFlowClient implements the OpenFlow client interface for testing
type mockOpenFlowClient struct {
	mu              sync.Mutex
	connected       bool
	addFlowErr      error
	deleteFlowErr   error
	modifyFlowErr   error
	getStatsErr     error
	deleteAllErr    error
	flowStats       []openflow.FlowStats
	addedFlows      []*openflow.FlowMod
	deletedFlows    []*openflow.FlowMod
	modifiedFlows   []*openflow.FlowMod
	deleteAllCalled bool
}

func newMockOpenFlowClient() *mockOpenFlowClient {
	return &mockOpenFlowClient{
		connected:  true,
		flowStats:  []openflow.FlowStats{},
		addedFlows: []*openflow.FlowMod{},
	}
}

func (m *mockOpenFlowClient) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

func (m *mockOpenFlowClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *mockOpenFlowClient) AddFlow(ctx context.Context, flow *openflow.FlowMod) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	m.addedFlows = append(m.addedFlows, flow)
	return nil
}

func (m *mockOpenFlowClient) DeleteFlow(ctx context.Context, flow *openflow.FlowMod) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	m.deletedFlows = append(m.deletedFlows, flow)
	return nil
}

func (m *mockOpenFlowClient) DeleteAllFlows(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteAllErr != nil {
		return m.deleteAllErr
	}
	m.deleteAllCalled = true
	return nil
}

func (m *mockOpenFlowClient) ModifyFlow(ctx context.Context, flow *openflow.FlowMod) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.modifyFlowErr != nil {
		return m.modifyFlowErr
	}
	m.modifiedFlows = append(m.modifiedFlows, flow)
	return nil
}

func (m *mockOpenFlowClient) GetFlowStats(ctx context.Context, match *openflow.Match) ([]openflow.FlowStats, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getStatsErr != nil {
		return nil, m.getStatsErr
	}
	return m.flowStats, nil
}

// setupTestClient creates a test client with a mock OpenFlow client
func setupTestClient(t *testing.T) (*Client, *mockOpenFlowClient) {
	client := &Client{
		connected:   true,
		ofClients:   make(map[string]*openflow.Client),
		ofClientsMu: sync.RWMutex{},
	}
	mockClient := newMockOpenFlowClient()
	return client, mockClient
}

// TestAddFlow tests the AddFlow function
func TestAddFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("success with convertToOpenFlow", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		// Test convertToOpenFlow directly
		flow := &FlowMod{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
			Cookie:   "0x1234",
		}

		ofFlow, err := convertToOpenFlow(flow)
		require.NoError(t, err)
		assert.NotNil(t, ofFlow)
		assert.Equal(t, uint8(0), ofFlow.TableID)
		assert.Equal(t, uint16(100), ofFlow.Priority)
		assert.Equal(t, uint64(0x1234), ofFlow.Cookie)

		// Test that mock handles AddFlow
		err = mockOF.AddFlow(ctx, ofFlow)
		assert.NoError(t, err)
		assert.Len(t, mockOF.addedFlows, 1)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flow := &FlowMod{Priority: 100}

		err := client.AddFlow(ctx, "", flow)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("nil flow", func(t *testing.T) {
		client, _ := setupTestClient(t)

		err := client.AddFlow(ctx, "br0", nil)
		assert.ErrorIs(t, err, ErrInvalidFlow)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false
		flow := &FlowMod{Priority: 100}

		err := client.AddFlow(ctx, "br0", flow)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestDeleteFlow tests the DeleteFlow function
func TestDeleteFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("success with parseMatchString", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		// Test parseMatchString independently
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port=1")
		assert.NoError(t, err)

		// Test that mock handles delete
		ofFlow := openflow.NewFlowMod(0)
		err = mockOF.DeleteFlow(ctx, ofFlow)
		assert.NoError(t, err)
		assert.Len(t, mockOF.deletedFlows, 1)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)

		err := client.DeleteFlow(ctx, "", "in_port=1")
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("empty match", func(t *testing.T) {
		client, _ := setupTestClient(t)

		err := client.DeleteFlow(ctx, "br0", "")
		assert.ErrorIs(t, err, ErrInvalidFlow)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false

		err := client.DeleteFlow(ctx, "br0", "in_port=1")
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestListFlows tests the ListFlows function
func TestListFlows(t *testing.T) {
	ctx := context.Background()

	t.Run("success conversion", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		mockOF.flowStats = []openflow.FlowStats{
			{
				TableID:     0,
				Priority:    100,
				DurationSec: 60,
				IdleTimeout: 30,
				HardTimeout: 300,
				Cookie:      0x1234,
				PacketCount: 1000,
				ByteCount:   65000,
			},
		}

		// Test the conversion logic used in ListFlows
		flows := make([]*Flow, 0, len(mockOF.flowStats))
		for _, stat := range mockOF.flowStats {
			flow := &Flow{
				Table:       int(stat.TableID),
				Priority:    int(stat.Priority),
				Duration:    int(stat.DurationSec),
				IdleAge:     int(stat.IdleTimeout),
				HardAge:     int(stat.HardTimeout),
				Cookie:      fmt.Sprintf("0x%x", stat.Cookie),
				PacketCount: int64(stat.PacketCount),
				ByteCount:   int64(stat.ByteCount),
			}
			flows = append(flows, flow)
		}

		require.Len(t, flows, 1)
		assert.Equal(t, 0, flows[0].Table)
		assert.Equal(t, 100, flows[0].Priority)
		assert.Equal(t, "0x1234", flows[0].Cookie)
		assert.Equal(t, int64(1000), flows[0].PacketCount)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)

		flows, err := client.ListFlows(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
		assert.Nil(t, flows)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false

		flows, err := client.ListFlows(ctx, "br0")
		assert.ErrorIs(t, err, ErrConnectionFailed)
		assert.Nil(t, flows)
	})
}

// TestDeleteAllFlows tests the DeleteAllFlows function
func TestDeleteAllFlows(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		err := mockOF.DeleteAllFlows(ctx)
		assert.NoError(t, err)
		assert.True(t, mockOF.deleteAllCalled)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)

		err := client.DeleteAllFlows(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false

		err := client.DeleteAllFlows(ctx, "br0")
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestModifyFlow tests the ModifyFlow function
func TestModifyFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		flow := &FlowMod{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}

		ofFlow, err := convertToOpenFlow(flow)
		require.NoError(t, err)

		err = mockOF.ModifyFlow(ctx, ofFlow)
		assert.NoError(t, err)
		assert.Len(t, mockOF.modifiedFlows, 1)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)
		flow := &FlowMod{Priority: 100}

		err := client.ModifyFlow(ctx, "", flow)
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
	})

	t.Run("nil flow", func(t *testing.T) {
		client, _ := setupTestClient(t)

		err := client.ModifyFlow(ctx, "br0", nil)
		assert.ErrorIs(t, err, ErrInvalidFlow)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false
		flow := &FlowMod{Priority: 100}

		err := client.ModifyFlow(ctx, "br0", flow)
		assert.ErrorIs(t, err, ErrConnectionFailed)
	})
}

// TestGetFlowStats tests the GetFlowStats function
func TestGetFlowStats(t *testing.T) {
	ctx := context.Background()

	t.Run("success with match", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		mockOF.flowStats = []openflow.FlowStats{
			{
				TableID:     0,
				Priority:    100,
				Cookie:      0xabcd,
				PacketCount: 500,
				ByteCount:   32000,
			},
		}

		// Test the match string parsing
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port=1,dl_type=0x0800")
		assert.NoError(t, err)

		stats, err := mockOF.GetFlowStats(ctx, match)
		assert.NoError(t, err)
		assert.Len(t, stats, 1)
	})

	t.Run("success without match", func(t *testing.T) {
		_, mockOF := setupTestClient(t)

		mockOF.flowStats = []openflow.FlowStats{
			{TableID: 0, Priority: 100},
			{TableID: 1, Priority: 200},
		}

		stats, err := mockOF.GetFlowStats(ctx, nil)
		assert.NoError(t, err)
		assert.Len(t, stats, 2)
	})

	t.Run("empty bridge name", func(t *testing.T) {
		client, _ := setupTestClient(t)

		flows, err := client.GetFlowStats(ctx, "", "in_port=1")
		assert.ErrorIs(t, err, ErrInvalidBridgeName)
		assert.Nil(t, flows)
	})

	t.Run("not connected", func(t *testing.T) {
		client, _ := setupTestClient(t)
		client.connected = false

		flows, err := client.GetFlowStats(ctx, "br0", "")
		assert.ErrorIs(t, err, ErrConnectionFailed)
		assert.Nil(t, flows)
	})
}

// TestConvertToOpenFlow tests the convertToOpenFlow function
func TestConvertToOpenFlow(t *testing.T) {
	t.Run("basic flow", func(t *testing.T) {
		flow := &FlowMod{
			Table:    1,
			Priority: 200,
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Equal(t, uint8(1), ofFlow.TableID)
		assert.Equal(t, uint16(200), ofFlow.Priority)
	})

	t.Run("with cookie hex", func(t *testing.T) {
		flow := &FlowMod{
			Cookie: "0xdeadbeef",
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xdeadbeef), ofFlow.Cookie)
	})

	t.Run("with cookie decimal", func(t *testing.T) {
		flow := &FlowMod{
			Cookie: "12345",
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Equal(t, uint64(12345), ofFlow.Cookie)
	})

	t.Run("with timeouts", func(t *testing.T) {
		flow := &FlowMod{
			IdleTimeout: 30,
			HardTimeout: 300,
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Equal(t, uint16(30), ofFlow.IdleTimeout)
		assert.Equal(t, uint16(300), ofFlow.HardTimeout)
	})

	t.Run("with match string", func(t *testing.T) {
		flow := &FlowMod{
			Match: "in_port=1,dl_dst=aa:bb:cc:dd:ee:ff",
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.NotNil(t, ofFlow.Match)
	})

	t.Run("with actions string", func(t *testing.T) {
		flow := &FlowMod{
			Actions: "output:2,NORMAL",
		}

		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.NotEmpty(t, ofFlow.Instructions)
	})

	t.Run("invalid match", func(t *testing.T) {
		flow := &FlowMod{
			Match: "in_port=invalid",
		}

		_, err := convertToOpenFlow(flow)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse match")
	})

	t.Run("invalid actions", func(t *testing.T) {
		flow := &FlowMod{
			Actions: "output:invalid",
		}

		_, err := convertToOpenFlow(flow)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse actions")
	})

	t.Run("invalid cookie", func(t *testing.T) {
		flow := &FlowMod{
			Cookie: "0xGGGG", // Invalid hex
		}

		_, err := convertToOpenFlow(flow)
		var invalid *ErrInvalidCookie
		assert.ErrorAs(t, err, &invalid, "a flow its owner cannot delete by cookie must not be installed")
	})
}

// TestParseMatchString tests the parseMatchString function
func TestParseMatchString(t *testing.T) {
	t.Run("in_port", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port=1")
		assert.NoError(t, err)
	})

	t.Run("dl_src MAC address", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_src=00:11:22:33:44:55")
		assert.NoError(t, err)
	})

	t.Run("dl_dst MAC address", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_dst=aa:bb:cc:dd:ee:ff")
		assert.NoError(t, err)
	})

	t.Run("dl_type hex", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_type=0x0800")
		assert.NoError(t, err)
	})

	t.Run("dl_type decimal", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_type=2048")
		assert.NoError(t, err)
	})

	t.Run("dl_vlan", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_vlan=100")
		assert.NoError(t, err)
	})

	t.Run("nw_src IPv4", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_src=192.168.1.1")
		assert.NoError(t, err)
	})

	t.Run("nw_dst IPv4", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_dst=10.0.0.1")
		assert.NoError(t, err)
	})

	t.Run("nw_proto", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_proto=6")
		assert.NoError(t, err)
	})

	t.Run("tp_src", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "tp_src=80")
		assert.NoError(t, err)
	})

	t.Run("tp_dst", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "tp_dst=443")
		assert.NoError(t, err)
	})

	t.Run("multiple fields", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port=1,dl_type=0x0800,nw_src=192.168.1.1,tp_dst=80")
		assert.NoError(t, err)
	})

	t.Run("empty string", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "")
		assert.NoError(t, err)
	})

	t.Run("whitespace handling", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, " in_port = 1 , dl_type = 0x0800 ")
		assert.NoError(t, err)
	})

	t.Run("invalid in_port", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port=invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid in_port")
	})

	t.Run("invalid dl_src", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_src=not-a-mac")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dl_src")
	})

	t.Run("invalid dl_dst", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_dst=invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dl_dst")
	})

	t.Run("invalid dl_type", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_type=0xGGGG")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dl_type")
	})

	t.Run("invalid dl_vlan", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "dl_vlan=invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dl_vlan")
	})

	t.Run("invalid nw_src", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_src=not.an.ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_src")
	})

	t.Run("invalid nw_dst", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_dst=bad-ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_dst")
	})

	t.Run("invalid nw_proto", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "nw_proto=invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nw_proto")
	})

	t.Run("invalid tp_src", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "tp_src=invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tp_src")
	})

	t.Run("invalid tp_dst", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "tp_dst=bad")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tp_dst")
	})

	t.Run("unknown field refused", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "unknown_field=value,in_port=1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported match field: unknown_field")
	})

	t.Run("malformed key-value refused", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "no_equals,in_port=1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported match field: no_equals")
	})
}

// TestParseActionsString tests the parseActionsString function
func TestParseActionsString(t *testing.T) {
	t.Run("drop", func(t *testing.T) {
		actions, err := parseActionsString("drop")
		assert.NoError(t, err)
		assert.Empty(t, actions)
	})

	t.Run("NORMAL", func(t *testing.T) {
		actions, err := parseActionsString("NORMAL")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("FLOOD", func(t *testing.T) {
		actions, err := parseActionsString("FLOOD")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("ALL", func(t *testing.T) {
		actions, err := parseActionsString("ALL")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("CONTROLLER", func(t *testing.T) {
		actions, err := parseActionsString("CONTROLLER")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("LOCAL", func(t *testing.T) {
		actions, err := parseActionsString("LOCAL")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("IN_PORT", func(t *testing.T) {
		actions, err := parseActionsString("IN_PORT")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("output port", func(t *testing.T) {
		actions, err := parseActionsString("output:2")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("mod_vlan_vid", func(t *testing.T) {
		actions, err := parseActionsString("mod_vlan_vid:100")
		assert.NoError(t, err)
		assert.Len(t, actions, 2) // Push VLAN + Set field
	})

	t.Run("strip_vlan", func(t *testing.T) {
		actions, err := parseActionsString("strip_vlan")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("mod_dl_src", func(t *testing.T) {
		actions, err := parseActionsString("mod_dl_src:aa:bb:cc:dd:ee:ff")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("mod_dl_dst", func(t *testing.T) {
		actions, err := parseActionsString("mod_dl_dst:11:22:33:44:55:66")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("mod_nw_src", func(t *testing.T) {
		actions, err := parseActionsString("mod_nw_src:192.168.1.1")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("mod_nw_dst", func(t *testing.T) {
		actions, err := parseActionsString("mod_nw_dst:10.0.0.1")
		assert.NoError(t, err)
		assert.Len(t, actions, 1)
	})

	t.Run("multiple actions", func(t *testing.T) {
		actions, err := parseActionsString("output:1,output:2,NORMAL")
		assert.NoError(t, err)
		assert.Len(t, actions, 3)
	})

	t.Run("empty string", func(t *testing.T) {
		actions, err := parseActionsString("")
		assert.NoError(t, err)
		assert.Empty(t, actions)
	})

	t.Run("whitespace handling", func(t *testing.T) {
		actions, err := parseActionsString(" output:1 , NORMAL ")
		assert.NoError(t, err)
		assert.Len(t, actions, 2)
	})

	t.Run("invalid output port", func(t *testing.T) {
		_, err := parseActionsString("output:invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid output port")
	})

	t.Run("invalid VLAN ID", func(t *testing.T) {
		_, err := parseActionsString("mod_vlan_vid:invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid VLAN ID")
	})

	t.Run("invalid MAC in mod_dl_src", func(t *testing.T) {
		_, err := parseActionsString("mod_dl_src:invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC")
	})

	t.Run("invalid MAC in mod_dl_dst", func(t *testing.T) {
		_, err := parseActionsString("mod_dl_dst:not-a-mac")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid MAC")
	})

	t.Run("invalid IP in mod_nw_src", func(t *testing.T) {
		_, err := parseActionsString("mod_nw_src:not.an.ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP")
	})

	t.Run("invalid IP in mod_nw_dst", func(t *testing.T) {
		_, err := parseActionsString("mod_nw_dst:bad-ip")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP")
	})

	t.Run("drop returns early", func(t *testing.T) {
		actions, err := parseActionsString("drop,output:1")
		assert.NoError(t, err)
		assert.Empty(t, actions) // drop returns immediately
	})
}

// TestParseCookie tests the parseCookie function
func TestParseCookie(t *testing.T) {
	t.Run("hex with 0x prefix", func(t *testing.T) {
		cookie, err := parseCookie("0xdeadbeef")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xdeadbeef), cookie)
	})

	t.Run("hex with 0X prefix", func(t *testing.T) {
		cookie, err := parseCookie("0Xabcd")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xabcd), cookie)
	})

	t.Run("decimal", func(t *testing.T) {
		cookie, err := parseCookie("12345")
		assert.NoError(t, err)
		assert.Equal(t, uint64(12345), cookie)
	})

	t.Run("whitespace", func(t *testing.T) {
		cookie, err := parseCookie("  0x1234  ")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0x1234), cookie)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := parseCookie("0xGGGG")
		assert.Error(t, err)
	})

	t.Run("invalid decimal", func(t *testing.T) {
		_, err := parseCookie("not-a-number")
		assert.Error(t, err)
	})
}

// TestParseHexOrDecimal tests the parseHexOrDecimal function
func TestParseHexOrDecimal(t *testing.T) {
	t.Run("hex lowercase prefix", func(t *testing.T) {
		val, err := parseHexOrDecimal("0x100")
		assert.NoError(t, err)
		assert.Equal(t, uint64(256), val)
	})

	t.Run("hex uppercase prefix", func(t *testing.T) {
		val, err := parseHexOrDecimal("0X200")
		assert.NoError(t, err)
		assert.Equal(t, uint64(512), val)
	})

	t.Run("decimal", func(t *testing.T) {
		val, err := parseHexOrDecimal("1024")
		assert.NoError(t, err)
		assert.Equal(t, uint64(1024), val)
	})

	t.Run("zero", func(t *testing.T) {
		val, err := parseHexOrDecimal("0")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), val)
	})

	t.Run("hex zero", func(t *testing.T) {
		val, err := parseHexOrDecimal("0x0")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), val)
	})

	t.Run("max uint64 hex", func(t *testing.T) {
		val, err := parseHexOrDecimal("0xFFFFFFFFFFFFFFFF")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), val)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := parseHexOrDecimal("0xZZZ")
		assert.Error(t, err)
	})

	t.Run("invalid decimal", func(t *testing.T) {
		_, err := parseHexOrDecimal("abc")
		assert.Error(t, err)
	})

	t.Run("overflow", func(t *testing.T) {
		_, err := parseHexOrDecimal("18446744073709551616") // uint64 max + 1
		assert.Error(t, err)
	})

	t.Run("negative not allowed", func(t *testing.T) {
		_, err := parseHexOrDecimal("-100")
		assert.Error(t, err)
	})
}

// TestFlowMatchBuilder tests the FlowMatchBuilder
func TestFlowMatchBuilder(t *testing.T) {
	t.Run("empty builder", func(t *testing.T) {
		builder := NewFlowMatchBuilder()
		assert.Equal(t, "", builder.Build())
	})

	t.Run("single match", func(t *testing.T) {
		builder := NewFlowMatchBuilder().InPort("1")
		assert.Equal(t, "in_port=1", builder.Build())
	})

	t.Run("all match types", func(t *testing.T) {
		builder := NewFlowMatchBuilder().
			InPort("1").
			DLSrc("aa:bb:cc:dd:ee:ff").
			DLDst("11:22:33:44:55:66").
			DLType("0x0800").
			NWSrc("192.168.1.1").
			NWDst("10.0.0.1").
			NWProto(6).
			TPSrc(80).
			TPDst(443).
			VLANTag(100)

		result := builder.Build()
		assert.Contains(t, result, "in_port=1")
		assert.Contains(t, result, "dl_src=aa:bb:cc:dd:ee:ff")
		assert.Contains(t, result, "dl_dst=11:22:33:44:55:66")
		assert.Contains(t, result, "dl_type=0x0800")
		assert.Contains(t, result, "nw_src=192.168.1.1")
		assert.Contains(t, result, "nw_dst=10.0.0.1")
		assert.Contains(t, result, "nw_proto=6")
		assert.Contains(t, result, "tp_src=80")
		assert.Contains(t, result, "tp_dst=443")
		assert.Contains(t, result, "dl_vlan=100")
	})

	t.Run("chaining", func(t *testing.T) {
		builder := NewFlowMatchBuilder()
		result := builder.InPort("1").DLType("0x0800").NWSrc("192.168.1.1")
		assert.NotNil(t, result)
		assert.Contains(t, builder.Build(), "in_port=1")
		assert.Contains(t, builder.Build(), "dl_type=0x0800")
		assert.Contains(t, builder.Build(), "nw_src=192.168.1.1")
	})

	t.Run("multiple builds", func(t *testing.T) {
		builder := NewFlowMatchBuilder().InPort("1").DLType("0x0800")
		result1 := builder.Build()
		result2 := builder.Build()
		assert.Equal(t, result1, result2)
	})

	t.Run("zero values", func(t *testing.T) {
		builder := NewFlowMatchBuilder().
			NWProto(0).
			TPSrc(0).
			TPDst(0).
			VLANTag(0)

		result := builder.Build()
		assert.Contains(t, result, "nw_proto=0")
		assert.Contains(t, result, "tp_src=0")
		assert.Contains(t, result, "tp_dst=0")
		assert.Contains(t, result, "dl_vlan=0")
	})
}

// TestFlowActionBuilder tests the FlowActionBuilder
func TestFlowActionBuilder(t *testing.T) {
	t.Run("empty builder", func(t *testing.T) {
		builder := NewFlowActionBuilder()
		assert.Equal(t, "", builder.Build())
	})

	t.Run("output", func(t *testing.T) {
		builder := NewFlowActionBuilder().Output("2")
		assert.Equal(t, "output:2", builder.Build())
	})

	t.Run("drop", func(t *testing.T) {
		builder := NewFlowActionBuilder().Drop()
		assert.Equal(t, "drop", builder.Build())
	})

	t.Run("NORMAL", func(t *testing.T) {
		builder := NewFlowActionBuilder().Normal()
		assert.Equal(t, "NORMAL", builder.Build())
	})

	t.Run("FLOOD", func(t *testing.T) {
		builder := NewFlowActionBuilder().Flood()
		assert.Equal(t, "FLOOD", builder.Build())
	})

	t.Run("mod VLAN", func(t *testing.T) {
		builder := NewFlowActionBuilder().ModVLAN(100)
		assert.Equal(t, "mod_vlan_vid:100", builder.Build())
	})

	t.Run("strip VLAN", func(t *testing.T) {
		builder := NewFlowActionBuilder().StripVLAN()
		assert.Equal(t, "strip_vlan", builder.Build())
	})

	t.Run("set DL src", func(t *testing.T) {
		builder := NewFlowActionBuilder().SetDLSrc("aa:bb:cc:dd:ee:ff")
		assert.Equal(t, "mod_dl_src:aa:bb:cc:dd:ee:ff", builder.Build())
	})

	t.Run("set DL dst", func(t *testing.T) {
		builder := NewFlowActionBuilder().SetDLDst("11:22:33:44:55:66")
		assert.Equal(t, "mod_dl_dst:11:22:33:44:55:66", builder.Build())
	})

	t.Run("set NW src", func(t *testing.T) {
		builder := NewFlowActionBuilder().SetNWSrc("192.168.1.1")
		assert.Equal(t, "mod_nw_src:192.168.1.1", builder.Build())
	})

	t.Run("set NW dst", func(t *testing.T) {
		builder := NewFlowActionBuilder().SetNWDst("10.0.0.1")
		assert.Equal(t, "mod_nw_dst:10.0.0.1", builder.Build())
	})

	t.Run("resubmit", func(t *testing.T) {
		builder := NewFlowActionBuilder().Resubmit(10)
		assert.Equal(t, "resubmit(,10)", builder.Build())
	})

	t.Run("all actions", func(t *testing.T) {
		builder := NewFlowActionBuilder().
			Output("1").
			ModVLAN(100).
			SetDLSrc("aa:bb:cc:dd:ee:ff").
			SetNWSrc("192.168.1.1").
			Output("2")

		result := builder.Build()
		assert.Contains(t, result, "output:1")
		assert.Contains(t, result, "mod_vlan_vid:100")
		assert.Contains(t, result, "mod_dl_src:aa:bb:cc:dd:ee:ff")
		assert.Contains(t, result, "mod_nw_src:192.168.1.1")
		assert.Contains(t, result, "output:2")
	})

	t.Run("chaining", func(t *testing.T) {
		builder := NewFlowActionBuilder()
		result := builder.Output("1").Normal().Output("2")
		assert.NotNil(t, result)
		assert.Contains(t, builder.Build(), "output:1")
		assert.Contains(t, builder.Build(), "NORMAL")
		assert.Contains(t, builder.Build(), "output:2")
	})

	t.Run("multiple builds", func(t *testing.T) {
		builder := NewFlowActionBuilder().Output("1").Normal()
		result1 := builder.Build()
		result2 := builder.Build()
		assert.Equal(t, result1, result2)
	})

	t.Run("zero VLAN", func(t *testing.T) {
		builder := NewFlowActionBuilder().ModVLAN(0)
		assert.Equal(t, "mod_vlan_vid:0", builder.Build())
	})

	t.Run("zero table resubmit", func(t *testing.T) {
		builder := NewFlowActionBuilder().Resubmit(0)
		assert.Equal(t, "resubmit(,0)", builder.Build())
	})
}

// TestConvertToOpenFlowComplex tests complex flow conversion
func TestConvertToOpenFlowComplex(t *testing.T) {
	flow := &FlowMod{
		Table:       10,
		Priority:    1000,
		Match:       "in_port=1,dl_type=0x0800,nw_src=192.168.1.0,nw_dst=10.0.0.0,nw_proto=6,tp_dst=80",
		Actions:     "mod_vlan_vid:100,mod_dl_src:aa:bb:cc:dd:ee:ff,output:2",
		Cookie:      "0xdeadbeefcafe",
		IdleTimeout: 60,
		HardTimeout: 600,
	}

	ofFlow, err := convertToOpenFlow(flow)
	require.NoError(t, err)
	assert.Equal(t, uint8(10), ofFlow.TableID)
	assert.Equal(t, uint16(1000), ofFlow.Priority)
	assert.Equal(t, uint64(0xdeadbeefcafe), ofFlow.Cookie)
	assert.Equal(t, uint16(60), ofFlow.IdleTimeout)
	assert.Equal(t, uint16(600), ofFlow.HardTimeout)
	assert.NotNil(t, ofFlow.Match)
	assert.NotEmpty(t, ofFlow.Instructions)
}

// TestConcurrentFlowOperations tests thread safety
func TestConcurrentFlowOperations(t *testing.T) {
	t.Run("concurrent match parsing", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				match := openflow.NewMatch()
				_ = parseMatchString(match, "in_port=1,dl_type=0x0800")
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent actions parsing", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = parseActionsString("output:1,NORMAL")
			}()
		}

		wg.Wait()
	})

	t.Run("concurrent builder usage", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				builder := NewFlowMatchBuilder().InPort(fmt.Sprintf("%d", port))
				_ = builder.Build()
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent conversion", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 100

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				flow := &FlowMod{
					Table:    i % 10,
					Priority: 100 + i,
					Match:    fmt.Sprintf("in_port=%d", i),
					Actions:  fmt.Sprintf("output:%d", i+1),
				}
				_, _ = convertToOpenFlow(flow)
			}(i)
		}

		wg.Wait()
	})
}

// TestSplitStatsFilter verifies extraction of the "table=N" and
// "cookie=V[/M]" stats scope keys from ovs-ofctl style dump filters.
func TestSplitStatsFilter(t *testing.T) {
	tests := []struct {
		name       string
		match      string
		wantRest   string
		wantTable  uint8
		wantCookie uint64
		wantMask   uint64
		wantErr    bool
	}{
		{"empty", "", "", openflow.OFPTTAll, 0, 0, false},
		{"table only", "table=21", "", 21, 0, 0, false},
		{"table with fields", "table=21,ct_state=+inv+trk,dl_vlan=100", "ct_state=+inv+trk,dl_vlan=100", 21, 0, 0, false},
		{"fields only", "dl_type=0x0800,nw_dst=10.0.0.0/24", "dl_type=0x0800,nw_dst=10.0.0.0/24", openflow.OFPTTAll, 0, 0, false},
		{"table zero", "table=0", "", 0, 0, 0, false},
		{"masked cookie", "cookie=0xf1be000300000000/0xffffffff00000000,table=26", "", 26, 0xf1be000300000000, 0xffffffff00000000, false},
		{"exact cookie", "cookie=0x5", "", openflow.OFPTTAll, 5, ^uint64(0), false},
		{"invalid table", "table=abc", "", 0, 0, 0, true},
		{"table out of range", "table=300", "", 0, 0, 0, true},
		{"invalid cookie", "cookie=xyz", "", 0, 0, 0, true},
		{"invalid cookie mask", "cookie=1/xyz", "", 0, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest, filter, err := splitStatsFilter(tt.match)
			if tt.wantErr {
				var msgErr *MessageError
				require.ErrorAs(t, err, &msgErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantRest, rest)
			assert.Equal(t, tt.wantTable, filter.TableID)
			assert.Equal(t, tt.wantCookie, filter.Cookie)
			assert.Equal(t, tt.wantMask, filter.CookieMask)
		})
	}
}

// TestFormatCTState verifies masked ct_state rendering in ovs-ofctl grammar.
func TestFormatCTState(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		mask  uint32
		want  string
	}{
		{"inv trk set", openflow.CTStateInv | openflow.CTStateTrk, openflow.CTStateInv | openflow.CTStateTrk, "+inv+trk"},
		{"new set est clear", openflow.CTStateNew, openflow.CTStateNew | openflow.CTStateEst, "+new-est"},
		{"empty mask", openflow.CTStateNew, 0, ""},
		{"all bits", 0xff, 0xff, "+new+est+rel+rpl+inv+trk+snat+dnat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCTState(tt.value, tt.mask); got != tt.want {
				t.Errorf("formatCTState = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFormatMatchString verifies OXM match fields render back to the
// ovs-ofctl grammar accepted by parseMatchString.
func TestFormatMatchString(t *testing.T) {
	t.Run("nil match", func(t *testing.T) {
		if got := formatMatchString(nil); got != "" {
			t.Errorf("formatMatchString(nil) = %q, want empty", got)
		}
	})

	t.Run("ct firewall verdict rule", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddCTState(openflow.CTStateInv|openflow.CTStateTrk, openflow.CTStateInv|openflow.CTStateTrk)
		match.AddVLANVid(100)
		want := "ct_state=+inv+trk,dl_vlan=100"
		if got := formatMatchString(match); got != want {
			t.Errorf("formatMatchString = %q, want %q", got, want)
		}
	})

	t.Run("l3 l4 fields", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddInPort(3)
		match.AddEthSrc(net.HardwareAddr{0x0e, 0x1b, 0x00, 0x00, 0x00, 0x01})
		match.AddEthDst(net.HardwareAddr{0x0e, 0x1b, 0x00, 0x00, 0x00, 0x02})
		match.AddEthType(0x0800)
		match.AddIPv4SrcMasked(net.ParseIP("10.230.1.0"), net.CIDRMask(24, 32))
		match.AddIPv4Dst(net.ParseIP("10.230.2.5"))
		match.AddIPProto(6)
		match.AddTCPDst(9090)
		want := "in_port=3,dl_src=0e:1b:00:00:00:01,dl_dst=0e:1b:00:00:00:02," +
			"dl_type=0x0800,nw_src=10.230.1.0/24,nw_dst=10.230.2.5,nw_proto=6,tp_dst=9090"
		if got := formatMatchString(match); got != want {
			t.Errorf("formatMatchString = %q, want %q", got, want)
		}
	})

	t.Run("conntrack zone and mark", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddCTZone(40040)
		match.AddCTMark(0x10, 0xff)
		want := "ct_zone=40040,ct_mark=0x10/0xff"
		if got := formatMatchString(match); got != want {
			t.Errorf("formatMatchString = %q, want %q", got, want)
		}
	})

	t.Run("udp ports", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddIPProto(17)
		match.AddUDPSrc(68)
		match.AddUDPDst(67)
		want := "nw_proto=17,tp_src=68,tp_dst=67"
		if got := formatMatchString(match); got != want {
			t.Errorf("formatMatchString = %q, want %q", got, want)
		}
	})

	t.Run("unknown fields omitted", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBMplsLabel, []byte{0x00, 0x00, 0x00, 0x01}, nil)
		match.AddVLANVid(101)
		want := "dl_vlan=101"
		if got := formatMatchString(match); got != want {
			t.Errorf("formatMatchString = %q, want %q", got, want)
		}
	})

	t.Run("round trip through parseMatchString", func(t *testing.T) {
		match := openflow.NewMatch()
		match.AddCTState(openflow.CTStateInv|openflow.CTStateTrk, openflow.CTStateInv|openflow.CTStateTrk)
		match.AddVLANVid(100)

		rendered := formatMatchString(match)
		reparsed := openflow.NewMatch()
		if err := parseMatchString(reparsed, rendered); err != nil {
			t.Fatalf("parseMatchString(%q) failed: %v", rendered, err)
		}
		if formatMatchString(reparsed) != rendered {
			t.Errorf("round trip = %q, want %q", formatMatchString(reparsed), rendered)
		}
	})
}

// TestParseMatchString_AnyTaggedFrame: vlan_vid=0x1000/0x1000 is how a flow
// says "any tagged frame", which dl_vlan has no spelling for; the NAT64
// hand-off strips the tag of exactly those frames (#614).
func TestParseMatchString_AnyTaggedFrame(t *testing.T) {
	m := openflow.NewMatch()
	require.NoError(t, parseMatchString(m, "dl_type=0x86dd,vlan_vid=0x1000/0x1000"))
	var found bool
	for _, f := range m.Fields {
		if f.Class == openflow.OFPXMCOpenflowBasic && f.Field == openflow.OFPXMTOFBVlanVid {
			found = true
			assert.Equal(t, []byte{0x10, 0x00}, f.Value)
			assert.Equal(t, []byte{0x10, 0x00}, f.Mask)
		}
	}
	require.True(t, found, "no VLAN_VID field: %+v", m.Fields)
	assert.Equal(t, "dl_type=0x86dd,vlan_vid=0x1000/0x1000", formatMatchString(m))

	exact := openflow.NewMatch()
	require.NoError(t, parseMatchString(exact, "vlan_vid=0x1064"))
	assert.Equal(t, "dl_vlan=100", formatMatchString(exact), "an unmasked VID reads back as the VLAN")

	assert.Error(t, parseMatchString(openflow.NewMatch(), "vlan_vid=0x2000"))
	assert.Error(t, parseMatchString(openflow.NewMatch(), "vlan_vid=0x1000/zz"))
}
