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

package daemon

import (
	"context"
	"encoding/json"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// SDNGetPortState Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNGetPortState_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNGetPortState(ctx, "br0", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNGetPortState_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortState(ctx, "", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNGetPortState_WithEmptyPortName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortState(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListBridges Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNListBridges_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListFlows Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNListFlows_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNListFlows_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNListFlows(ctx, "")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListVLANs Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNListVLANs_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNListVLANs_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNListVLANs(ctx, "")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNAuthenticatePort Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNAuthenticatePort_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		"format":      "PEM",
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAuthenticatePort_WithEmptyFormatDefaultsToPEM(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		// format is empty, should default to PEM
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	// The error path is still ErrServiceNotAvailable since we check nil service first
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAuthenticatePort_WithEmptyCredentials(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", map[string]string{})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAuthenticatePort_WithDERFormat(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "binary-der-data",
		"format":      "DER",
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNGetPortStats Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNGetPortStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNGetPortStats(ctx, "br0", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNGetPortStats_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortStats(ctx, "", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNGetPortStats_WithEmptyPortName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetPortStats(ctx, "br0", "")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNGetFlowStats Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNGetFlowStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	result, err := provider.SDNGetFlowStats(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if result != nil {
		t.Error("expected nil result")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNGetFlowStats_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	_, err := provider.SDNGetFlowStats(ctx, "")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNAddFlow Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNAddFlow_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"priority": 100,
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithEmptyBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"priority": 100,
	}

	err := provider.SDNAddFlow(ctx, "", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithEmptyFlow(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNAddFlow(ctx, "br0", map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithPriorityOnly(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"priority": 100,
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithTableOnly(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"table": "FLOW_TABLE_CLASSIFICATION",
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithTimeoutsOnly(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"idle_timeout": 300,
		"hard_timeout": 600,
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithMatchCriteria(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"match": map[string]interface{}{
			"in_port":  "eth0",
			"vlan_id":  100,
			"eth_src":  "00:11:22:33:44:55",
			"eth_dst":  "66:77:88:99:aa:bb",
			"eth_type": 0x0800,
			"ip_src":   "192.168.1.1",
			"ip_dst":   "192.168.1.2",
			"ip_proto": 6,
			"tcp_src":  80,
			"tcp_dst":  443,
			"udp_src":  53,
			"udp_dst":  5353,
			"metadata": map[string]string{"key": "value"},
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithActionsOnly(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"actions": []interface{}{
			map[string]interface{}{
				"type":     "FLOW_ACTION_OUTPUT",
				"port":     "eth1",
				"vlan_id":  200,
				"field":    "dst_ip",
				"value":    "10.0.0.1",
				"table_id": 5,
			},
			map[string]interface{}{
				"type": "FLOW_ACTION_DROP",
			},
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithCompleteConfig(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"priority":     100,
		"table":        "FLOW_TABLE_CLASSIFICATION",
		"idle_timeout": 300,
		"hard_timeout": 600,
		"match": map[string]interface{}{
			"in_port":  "eth0",
			"vlan_id":  100,
			"eth_src":  "00:11:22:33:44:55",
			"eth_dst":  "66:77:88:99:aa:bb",
			"eth_type": 0x0800,
			"ip_src":   "192.168.1.1",
			"ip_dst":   "192.168.1.2",
			"ip_proto": 6,
			"tcp_src":  80,
			"tcp_dst":  443,
			"udp_src":  53,
			"udp_dst":  5353,
			"metadata": map[string]string{"tag": "test"},
		},
		"actions": []interface{}{
			map[string]interface{}{
				"type":     "FLOW_ACTION_OUTPUT",
				"port":     "eth1",
				"vlan_id":  200,
				"field":    "dst_ip",
				"value":    "10.0.0.1",
				"table_id": 5,
			},
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddFlow_WithInvalidActionNotMap(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	flow := map[string]interface{}{
		"actions": []interface{}{
			"invalid_action_not_a_map",
		},
	}

	err := provider.SDNAddFlow(ctx, "br0", flow)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// buildFlowMatch Helper Function Tests
// =============================================================================

func TestServiceProvider_BuildFlowMatch_WithAllFields(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port":  "eth0",
		"vlan_id":  100,
		"eth_src":  "00:11:22:33:44:55",
		"eth_dst":  "66:77:88:99:aa:bb",
		"eth_type": 0x0800,
		"ip_src":   "192.168.1.1",
		"ip_dst":   "192.168.1.2",
		"ip_proto": 6,
		"tcp_src":  80,
		"tcp_dst":  443,
		"udp_src":  53,
		"udp_dst":  5353,
		"metadata": map[string]string{"key": "value"},
	}

	match := buildFlowMatch(matchMap)
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.InPort != "eth0" {
		t.Errorf("expected in_port=eth0, got %s", match.InPort)
	}
	if match.VlanId != 100 {
		t.Errorf("expected vlan_id=100, got %d", match.VlanId)
	}
	if match.EthSrc != "00:11:22:33:44:55" {
		t.Errorf("expected eth_src=00:11:22:33:44:55, got %s", match.EthSrc)
	}
	if match.EthDst != "66:77:88:99:aa:bb" {
		t.Errorf("expected eth_dst=66:77:88:99:aa:bb, got %s", match.EthDst)
	}
	if match.EthType != 0x0800 {
		t.Errorf("expected eth_type=0x0800, got %d", match.EthType)
	}
	if match.IpSrc != "192.168.1.1" {
		t.Errorf("expected ip_src=192.168.1.1, got %s", match.IpSrc)
	}
	if match.IpDst != "192.168.1.2" {
		t.Errorf("expected ip_dst=192.168.1.2, got %s", match.IpDst)
	}
	if match.IpProto != 6 {
		t.Errorf("expected ip_proto=6, got %d", match.IpProto)
	}
	if match.TcpSrc != 80 {
		t.Errorf("expected tcp_src=80, got %d", match.TcpSrc)
	}
	if match.TcpDst != 443 {
		t.Errorf("expected tcp_dst=443, got %d", match.TcpDst)
	}
	if match.UdpSrc != 53 {
		t.Errorf("expected udp_src=53, got %d", match.UdpSrc)
	}
	if match.UdpDst != 5353 {
		t.Errorf("expected udp_dst=5353, got %d", match.UdpDst)
	}
	if match.Metadata == nil || match.Metadata["key"] != "value" {
		t.Errorf("expected metadata with key=value, got %v", match.Metadata)
	}
}

func TestServiceProvider_BuildFlowMatch_WithEmptyMap(t *testing.T) {
	match := buildFlowMatch(map[string]interface{}{})
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.InPort != "" {
		t.Errorf("expected empty in_port, got %s", match.InPort)
	}
}

func TestServiceProvider_BuildFlowMatch_WithPartialFields(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port": "eth0",
		"vlan_id": 100,
	}

	match := buildFlowMatch(matchMap)
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.InPort != "eth0" {
		t.Errorf("expected in_port=eth0, got %s", match.InPort)
	}
	if match.VlanId != 100 {
		t.Errorf("expected vlan_id=100, got %d", match.VlanId)
	}
	if match.EthSrc != "" {
		t.Errorf("expected empty eth_src, got %s", match.EthSrc)
	}
}

func TestServiceProvider_BuildFlowMatch_WithWrongTypes(t *testing.T) {
	matchMap := map[string]interface{}{
		"in_port": 123,            // wrong type, should be string
		"vlan_id": "not-a-number", // wrong type, should be int
		"eth_src": 456,            // wrong type
	}

	match := buildFlowMatch(matchMap)
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	// Should be empty since types don't match
	if match.InPort != "" {
		t.Errorf("expected empty in_port for wrong type, got %s", match.InPort)
	}
	if match.VlanId != 0 {
		t.Errorf("expected 0 vlan_id for wrong type, got %d", match.VlanId)
	}
}

// =============================================================================
// buildFlowActions Helper Function Tests
// =============================================================================

func TestServiceProvider_BuildFlowActions_WithAllFields(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type":     "FLOW_ACTION_OUTPUT",
			"port":     "eth1",
			"vlan_id":  200,
			"field":    "dst_ip",
			"value":    "10.0.0.1",
			"table_id": 5,
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	action := actions[0]
	if action.Type != platformv1.FlowActionType_FLOW_ACTION_OUTPUT {
		t.Errorf("expected FLOW_ACTION_OUTPUT, got %v", action.Type)
	}
	if action.Port != "eth1" {
		t.Errorf("expected port=eth1, got %s", action.Port)
	}
	if action.VlanId != 200 {
		t.Errorf("expected vlan_id=200, got %d", action.VlanId)
	}
	if action.Field != "dst_ip" {
		t.Errorf("expected field=dst_ip, got %s", action.Field)
	}
	if action.Value != "10.0.0.1" {
		t.Errorf("expected value=10.0.0.1, got %s", action.Value)
	}
	if action.TableId != 5 {
		t.Errorf("expected table_id=5, got %d", action.TableId)
	}
}

func TestServiceProvider_BuildFlowActions_WithEmptySlice(t *testing.T) {
	actions := buildFlowActions([]interface{}{})
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(actions))
	}
}

func TestServiceProvider_BuildFlowActions_WithMultipleActions(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type": "FLOW_ACTION_OUTPUT",
			"port": "eth1",
		},
		map[string]interface{}{
			"type": "FLOW_ACTION_DROP",
		},
		map[string]interface{}{
			"type":    "FLOW_ACTION_SET_VLAN",
			"vlan_id": 100,
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 3 {
		t.Fatalf("expected 3 actions, got %d", len(actions))
	}
}

func TestServiceProvider_BuildFlowActions_WithInvalidNotMapItems(t *testing.T) {
	actionsSlice := []interface{}{
		"not-a-map",
		123,
		nil,
	}

	actions := buildFlowActions(actionsSlice)
	// Invalid items should be skipped
	if len(actions) != 0 {
		t.Fatalf("expected 0 actions for invalid items, got %d", len(actions))
	}
}

func TestServiceProvider_BuildFlowActions_WithPartialFields(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type": "FLOW_ACTION_OUTPUT",
			"port": "eth1",
			// no vlan_id, field, value, table_id
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	action := actions[0]
	if action.Port != "eth1" {
		t.Errorf("expected port=eth1, got %s", action.Port)
	}
	if action.VlanId != 0 {
		t.Errorf("expected vlan_id=0, got %d", action.VlanId)
	}
}

func TestServiceProvider_BuildFlowActions_WithInvalidActionType(t *testing.T) {
	actionsSlice := []interface{}{
		map[string]interface{}{
			"type": "INVALID_ACTION_TYPE",
			"port": "eth1",
		},
	}

	actions := buildFlowActions(actionsSlice)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	// Invalid type should result in unspecified (0)
	if actions[0].Type != platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED {
		t.Errorf("expected FLOW_ACTION_UNSPECIFIED for invalid type, got %v", actions[0].Type)
	}
}

// =============================================================================
// Additional SDN Nil Service Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNCreateBridge_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNCreateBridge(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNDeleteBridge_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNDeleteBridge(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAddPort_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNAddPort(ctx, "br0", "eth0", "access")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNDeletePort_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNDeletePort(ctx, "br0", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNPolicies_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	calls := map[string]func() error{
		"apply": func() error {
			_, err := provider.SDNApplyPolicy(ctx, json.RawMessage(`{"name":"p1","type":"acl"}`))
			return err
		},
		"get": func() error {
			_, err := provider.SDNGetPolicy(ctx, "p1")
			return err
		},
		"list": func() error {
			_, err := provider.SDNListPolicies(ctx, "", "")
			return err
		},
		"delete": func() error {
			return provider.SDNDeletePolicy(ctx, "p1")
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			if _, ok := call().(ErrServiceNotAvailable); !ok {
				t.Errorf("expected ErrServiceNotAvailable")
			}
		})
	}
}

func TestServiceProvider_SDNDeleteFlow_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNDeleteFlow(ctx, "br0", "flow-1")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNFlushFlows_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNFlushFlows(ctx, "br0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNCreateVLAN_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNCreateVLAN(ctx, "br0", 100, "guest")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNDeleteVLAN_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNDeleteVLAN(ctx, "br0", 100)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNRevokePortAuth_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	err := provider.SDNRevokePortAuth(ctx, "br0", "eth0")
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// Table-Driven SDN Tests - Service Provider
// =============================================================================

func TestServiceProvider_SDNOperations_NilServiceTableDriven(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name     string
		testFunc func() error
	}{
		{
			name: "SDNCreateBridge",
			testFunc: func() error {
				return provider.SDNCreateBridge(ctx, "br0")
			},
		},
		{
			name: "SDNDeleteBridge",
			testFunc: func() error {
				return provider.SDNDeleteBridge(ctx, "br0")
			},
		},
		{
			name: "SDNAddPort",
			testFunc: func() error {
				return provider.SDNAddPort(ctx, "br0", "eth0", "internal")
			},
		},
		{
			name: "SDNDeletePort",
			testFunc: func() error {
				return provider.SDNDeletePort(ctx, "br0", "eth0")
			},
		},
		{
			name: "SDNDeleteFlow",
			testFunc: func() error {
				return provider.SDNDeleteFlow(ctx, "br0", "flow-1")
			},
		},
		{
			name: "SDNFlushFlows",
			testFunc: func() error {
				return provider.SDNFlushFlows(ctx, "br0")
			},
		},
		{
			name: "SDNCreateVLAN",
			testFunc: func() error {
				return provider.SDNCreateVLAN(ctx, "br0", 100, "test")
			},
		},
		{
			name: "SDNDeleteVLAN",
			testFunc: func() error {
				return provider.SDNDeleteVLAN(ctx, "br0", 100)
			},
		},
		{
			name: "SDNRevokePortAuth",
			testFunc: func() error {
				return provider.SDNRevokePortAuth(ctx, "br0", "eth0")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.testFunc()
			if err == nil {
				t.Fatalf("%s: expected error for nil SDN service", tc.name)
			}
			if _, ok := err.(ErrServiceNotAvailable); !ok {
				t.Errorf("%s: expected ErrServiceNotAvailable, got %T: %v", tc.name, err, err)
			}
		})
	}
}

func TestServiceProvider_SDNQueryOperations_NilServiceTableDriven(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	tests := []struct {
		name     string
		testFunc func() (interface{}, error)
	}{
		{
			name: "SDNGetPortState",
			testFunc: func() (interface{}, error) {
				return provider.SDNGetPortState(ctx, "br0", "eth0")
			},
		},
		{
			name: "SDNListBridges",
			testFunc: func() (interface{}, error) {
				return provider.SDNListBridges(ctx)
			},
		},
		{
			name: "SDNListFlows",
			testFunc: func() (interface{}, error) {
				return provider.SDNListFlows(ctx, "br0")
			},
		},
		{
			name: "SDNListVLANs",
			testFunc: func() (interface{}, error) {
				return provider.SDNListVLANs(ctx, "br0")
			},
		},
		{
			name: "SDNGetPortStats",
			testFunc: func() (interface{}, error) {
				return provider.SDNGetPortStats(ctx, "br0", "eth0")
			},
		},
		{
			name: "SDNGetFlowStats",
			testFunc: func() (interface{}, error) {
				return provider.SDNGetFlowStats(ctx, "br0")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.testFunc()
			if err == nil {
				t.Fatalf("%s: expected error for nil SDN service", tc.name)
			}
			// Note: Not checking for nil result because in Go, when a function
			// returns ([]interface{}, error) with nil slice, and this is wrapped
			// in an interface{} return type, the nil slice becomes non-nil interface
			if _, ok := err.(ErrServiceNotAvailable); !ok {
				t.Errorf("%s: expected ErrServiceNotAvailable, got %T: %v", tc.name, err, err)
			}
		})
	}
}

// =============================================================================
// SDNAddFlow Tests with Authentication Credential Variations
// =============================================================================

func TestServiceProvider_SDNAuthenticatePort_WithValidPEMCert(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALHf...test\n-----END CERTIFICATE-----",
		"format":      "PEM",
	}

	err := provider.SDNAuthenticatePort(ctx, "br0", "eth0", creds)
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

func TestServiceProvider_SDNAuthenticatePort_WithMultipleBridgePort(t *testing.T) {
	ctx := context.Background()
	provider := NewPlatformServiceProvider(&PlatformServiceProviderConfig{})

	creds := map[string]string{
		"certificate": "cert-data",
	}

	testCases := []struct {
		bridge string
		port   string
	}{
		{"br0", "eth0"},
		{"br1", "eth1"},
		{"ovs-br", "tap0"},
		{"docker0", "veth123"},
	}

	for _, tc := range testCases {
		err := provider.SDNAuthenticatePort(ctx, tc.bridge, tc.port, creds)
		if err == nil {
			t.Fatalf("expected error for bridge=%s, port=%s", tc.bridge, tc.port)
		}
		if _, ok := err.(ErrServiceNotAvailable); !ok {
			t.Errorf("expected ErrServiceNotAvailable for bridge=%s, port=%s, got %T", tc.bridge, tc.port, err)
		}
	}
}
