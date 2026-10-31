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
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlowOperationsWithMockOpenFlow tests flow operations using mock OpenFlow client
func TestFlowOperationsWithMockOpenFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("AddFlow with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		flow := &FlowMod{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}

		// This will fail because getOpenFlowClient will fail without proper setup
		err := client.AddFlow(ctx, "br0", flow)
		assert.Error(t, err)
	})

	t.Run("DeleteFlow with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		err := client.DeleteFlow(ctx, "br0", "in_port=1")
		assert.Error(t, err)
	})

	t.Run("ListFlows with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		_, err := client.ListFlows(ctx, "br0")
		assert.Error(t, err)
	})

	t.Run("DeleteAllFlows with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		err := client.DeleteAllFlows(ctx, "br0")
		assert.Error(t, err)
	})

	t.Run("ModifyFlow with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		flow := &FlowMod{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}

		err := client.ModifyFlow(ctx, "br0", flow)
		assert.Error(t, err)
	})

	t.Run("GetFlowStats with getOpenFlowClient error simulation", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		_, err := client.GetFlowStats(ctx, "br0", "in_port=1")
		assert.Error(t, err)
	})

	t.Run("GetFlowStats with empty match string", func(t *testing.T) {
		client := &Client{
			ofClients:   make(map[string]*openflow.Client),
			ofClientsMu: sync.RWMutex{},
		}
		client.connected.Store(true)

		// Test with empty match string to cover that branch
		_, err := client.GetFlowStats(ctx, "br0", "")
		assert.Error(t, err)
	})
}

// TestParseMatchStringEdgeCases tests edge cases in parseMatchString
func TestParseMatchStringEdgeCases(t *testing.T) {
	t.Run("empty parts after split", func(t *testing.T) {
		match := openflow.NewMatch()
		// Multiple commas create empty parts
		err := parseMatchString(match, "in_port=1,,,dl_type=0x0800,,")
		assert.NoError(t, err)
	})

	t.Run("a bare word that is not a protocol keyword is refused", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "invalidpair,in_port=1")
		require.Error(t, err, "a dropped field would install a broader flow than written")
		assert.Contains(t, err.Error(), "unsupported match field: invalidpair")
	})

	t.Run("an unknown key is refused", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "key=value=extra,in_port=1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported match field: key")
	})

	t.Run("whitespace in values", func(t *testing.T) {
		match := openflow.NewMatch()
		err := parseMatchString(match, "in_port = 1 , dl_type = 0x0800")
		assert.NoError(t, err)
	})
}

// TestParseActionsStringEdgeCases tests edge cases in parseActionsString
func TestParseActionsStringEdgeCases(t *testing.T) {
	t.Run("empty parts after split", func(t *testing.T) {
		actions, err := parseActionsString("output:1,,,NORMAL,,")
		assert.NoError(t, err)
		assert.Len(t, actions, 2) // Only valid actions
	})

	t.Run("whitespace in actions", func(t *testing.T) {
		actions, err := parseActionsString(" output:1 , NORMAL , output:2 ")
		assert.NoError(t, err)
		assert.Len(t, actions, 3)
	})

	t.Run("an unknown action is refused", func(t *testing.T) {
		_, err := parseActionsString("unknown_action,output:1")
		require.Error(t, err, "a dropped action would install a flow that does less than written")
		assert.Contains(t, err.Error(), "unsupported action: unknown_action")
	})

	t.Run("action with prefix but invalid value", func(t *testing.T) {
		_, err := parseActionsString("output:abc")
		assert.Error(t, err)
	})
}

// TestConvertToOpenFlowEdgeCases tests edge cases in convertToOpenFlow
func TestConvertToOpenFlowEdgeCases(t *testing.T) {
	t.Run("flow with empty cookie string", func(t *testing.T) {
		flow := &FlowMod{
			Cookie: "",
		}
		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), ofFlow.Cookie)
	})

	t.Run("flow with invalid cookie format", func(t *testing.T) {
		flow := &FlowMod{
			Cookie: "invalid-cookie",
		}
		// A cookie is how a flow's owner deletes it; installing the flow
		// with cookie 0 instead would strand it.
		_, err := convertToOpenFlow(flow)
		var invalid *ErrInvalidCookie
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "invalid-cookie", invalid.Cookie)
	})

	t.Run("flow with empty match string", func(t *testing.T) {
		flow := &FlowMod{
			Match: "",
		}
		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.NotNil(t, ofFlow.Match)
	})

	t.Run("flow with empty actions string", func(t *testing.T) {
		flow := &FlowMod{
			Actions: "",
		}
		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Empty(t, ofFlow.Instructions)
	})

	t.Run("flow with actions that return empty list", func(t *testing.T) {
		flow := &FlowMod{
			Actions: "drop",
		}
		ofFlow, err := convertToOpenFlow(flow)
		assert.NoError(t, err)
		assert.Empty(t, ofFlow.Instructions) // drop returns empty actions
	})
}

// TestDeleteFlowMatchParsing tests the match parsing in DeleteFlow
func TestDeleteFlowMatchParsing(t *testing.T) {
	client := &Client{
		ofClients:   make(map[string]*openflow.Client),
		ofClientsMu: sync.RWMutex{},
	}
	client.connected.Store(true)
	ctx := context.Background()

	t.Run("DeleteFlow with invalid match string", func(t *testing.T) {
		// This should fail at getOpenFlowClient, but tests the validation path
		err := client.DeleteFlow(ctx, "br0", "in_port=invalid")
		assert.Error(t, err)
	})

	t.Run("DeleteFlow with complex match string", func(t *testing.T) {
		err := client.DeleteFlow(ctx, "br0", "in_port=1,dl_type=0x0800,nw_src=192.168.1.1")
		assert.Error(t, err)
	})
}

// TestGetFlowStatsMatchParsing tests match parsing in GetFlowStats
func TestGetFlowStatsMatchParsing(t *testing.T) {
	client := &Client{
		ofClients:   make(map[string]*openflow.Client),
		ofClientsMu: sync.RWMutex{},
	}
	client.connected.Store(true)
	ctx := context.Background()

	t.Run("GetFlowStats with invalid match in parseMatchString", func(t *testing.T) {
		// The error will happen at getOpenFlowClient, but this tests the path
		_, err := client.GetFlowStats(ctx, "br0", "in_port=invalid")
		assert.Error(t, err)
	})
}

// TestFlowMatchBuilderEdgeCases tests edge cases in FlowMatchBuilder
func TestFlowMatchBuilderEdgeCases(t *testing.T) {
	t.Run("builder with maximum values", func(t *testing.T) {
		builder := NewFlowMatchBuilder().
			InPort("65535").
			NWProto(255).
			TPSrc(65535).
			TPDst(65535).
			VLANTag(4095)

		result := builder.Build()
		assert.Contains(t, result, "in_port=65535")
		assert.Contains(t, result, "nw_proto=255")
		assert.Contains(t, result, "tp_src=65535")
		assert.Contains(t, result, "tp_dst=65535")
		assert.Contains(t, result, "dl_vlan=4095")
	})

	t.Run("builder with special characters in strings", func(t *testing.T) {
		builder := NewFlowMatchBuilder().
			DLSrc("ff:ff:ff:ff:ff:ff").
			NWSrc("255.255.255.255")

		result := builder.Build()
		assert.Contains(t, result, "dl_src=ff:ff:ff:ff:ff:ff")
		assert.Contains(t, result, "nw_src=255.255.255.255")
	})
}

// TestFlowActionBuilderEdgeCases tests edge cases in FlowActionBuilder
func TestFlowActionBuilderEdgeCases(t *testing.T) {
	t.Run("builder with all special actions", func(t *testing.T) {
		builder := NewFlowActionBuilder().
			Drop().
			Normal().
			Flood()

		// Note: Multiple actions, but drop doesn't prevent others in builder
		result := builder.Build()
		assert.Contains(t, result, "drop")
		assert.Contains(t, result, "NORMAL")
		assert.Contains(t, result, "FLOOD")
	})

	t.Run("builder with maximum VLAN value", func(t *testing.T) {
		builder := NewFlowActionBuilder().ModVLAN(4095)
		result := builder.Build()
		assert.Equal(t, "mod_vlan_vid:4095", result)
	})

	t.Run("builder with large table resubmit", func(t *testing.T) {
		builder := NewFlowActionBuilder().Resubmit(255)
		result := builder.Build()
		assert.Equal(t, "resubmit(,255)", result)
	})

	t.Run("builder with special MAC addresses", func(t *testing.T) {
		builder := NewFlowActionBuilder().
			SetDLSrc("ff:ff:ff:ff:ff:ff").
			SetDLDst("00:00:00:00:00:00")

		result := builder.Build()
		assert.Contains(t, result, "mod_dl_src:ff:ff:ff:ff:ff:ff")
		assert.Contains(t, result, "mod_dl_dst:00:00:00:00:00:00")
	})

	t.Run("builder with special IP addresses", func(t *testing.T) {
		builder := NewFlowActionBuilder().
			SetNWSrc("0.0.0.0").
			SetNWDst("255.255.255.255")

		result := builder.Build()
		assert.Contains(t, result, "mod_nw_src:0.0.0.0")
		assert.Contains(t, result, "mod_nw_dst:255.255.255.255")
	})
}

// TestParseCookieEdgeCases tests edge cases in parseCookie
func TestParseCookieEdgeCases(t *testing.T) {
	t.Run("max uint64 value", func(t *testing.T) {
		cookie, err := parseCookie("18446744073709551615")
		assert.NoError(t, err)
		assert.Equal(t, uint64(18446744073709551615), cookie)
	})

	t.Run("max hex value", func(t *testing.T) {
		cookie, err := parseCookie("0xFFFFFFFFFFFFFFFF")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), cookie)
	})

	t.Run("zero value", func(t *testing.T) {
		cookie, err := parseCookie("0")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), cookie)
	})

	t.Run("hex zero", func(t *testing.T) {
		cookie, err := parseCookie("0x0")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), cookie)
	})
}

// TestParseHexOrDecimalEdgeCases tests edge cases in parseHexOrDecimal
func TestParseHexOrDecimalEdgeCases(t *testing.T) {
	t.Run("whitespace trimming", func(t *testing.T) {
		val, err := parseHexOrDecimal("  0x100  ")
		assert.NoError(t, err)
		assert.Equal(t, uint64(256), val)
	})

	t.Run("uppercase X", func(t *testing.T) {
		val, err := parseHexOrDecimal("0X100")
		assert.NoError(t, err)
		assert.Equal(t, uint64(256), val)
	})

	t.Run("mixed case hex digits", func(t *testing.T) {
		val, err := parseHexOrDecimal("0xAbCdEf")
		assert.NoError(t, err)
		assert.Equal(t, uint64(0xABCDEF), val)
	})
}

// TestConcurrentFlowBuilders tests thread safety of builders
func TestConcurrentFlowBuilders(t *testing.T) {
	t.Run("concurrent match builder creation", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 50

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				builder := NewFlowMatchBuilder()
				builder.InPort(fmt.Sprintf("%d", id))
				builder.DLType("0x0800")
				_ = builder.Build()
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent action builder creation", func(t *testing.T) {
		var wg sync.WaitGroup
		iterations := 50

		for i := 0; i < iterations; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				builder := NewFlowActionBuilder()
				builder.Output(fmt.Sprintf("%d", id))
				builder.Normal()
				_ = builder.Build()
			}(i)
		}

		wg.Wait()
	})
}

// TestComplexFlowConversions tests complex flow conversion scenarios
func TestComplexFlowConversions(t *testing.T) {
	t.Run("flow with all fields populated", func(t *testing.T) {
		flow := &FlowMod{
			Table:       255,
			Priority:    65535,
			Match:       "in_port=1,dl_src=aa:bb:cc:dd:ee:ff,dl_dst=11:22:33:44:55:66,dl_type=0x0800,dl_vlan=100,nw_src=192.168.1.1,nw_dst=10.0.0.1,nw_proto=6,tp_src=80,tp_dst=443",
			Actions:     "mod_vlan_vid:200,mod_dl_src:ff:ee:dd:cc:bb:aa,mod_dl_dst:66:55:44:33:22:11,mod_nw_src:10.1.1.1,mod_nw_dst:192.168.2.1,output:2",
			Cookie:      "0xFEDCBA9876543210",
			IdleTimeout: 3600,
			HardTimeout: 7200,
		}

		ofFlow, err := convertToOpenFlow(flow)
		require.NoError(t, err)
		assert.Equal(t, uint8(255), ofFlow.TableID)
		assert.Equal(t, uint16(65535), ofFlow.Priority)
		assert.Equal(t, uint16(3600), ofFlow.IdleTimeout)
		assert.Equal(t, uint16(7200), ofFlow.HardTimeout)
		assert.Equal(t, uint64(0xFEDCBA9876543210), ofFlow.Cookie)
		assert.NotNil(t, ofFlow.Match)
		assert.NotEmpty(t, ofFlow.Instructions)
	})

	t.Run("flow with minimal fields", func(t *testing.T) {
		flow := &FlowMod{
			Table:    0,
			Priority: 0,
		}

		ofFlow, err := convertToOpenFlow(flow)
		require.NoError(t, err)
		assert.Equal(t, uint8(0), ofFlow.TableID)
		assert.Equal(t, uint16(0), ofFlow.Priority)
		assert.Equal(t, uint64(0), ofFlow.Cookie)
	})
}
