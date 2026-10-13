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

//go:build codec_msgpack

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleSDNOperation_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	// All SDN operations should return unavailable when sdnClient is nil
	opcodes := []byte{
		quicwire.OpSDNCreateBridge,
		quicwire.OpSDNDeleteBridge,
		quicwire.OpSDNGetBridge,
		quicwire.OpSDNListBridges,
		quicwire.OpSDNCreatePort,
		quicwire.OpSDNDeletePort,
		quicwire.OpSDNGetPort,
		quicwire.OpSDNListPorts,
		quicwire.OpSDNGetPortState,
		quicwire.OpSDNSetPortState,
		quicwire.OpSDNSetVLAN,
		quicwire.OpSDNGetVLAN,
		quicwire.OpSDNAddFlow,
		quicwire.OpSDNDeleteFlow,
		quicwire.OpSDNGetFlow,
		quicwire.OpSDNListFlows,
		quicwire.OpSDNGetMetrics,
	}

	for _, opcode := range opcodes {
		t.Run(quicwire.OpcodeToString(opcode), func(t *testing.T) {
			req := &quicwire.Request{
				Opcode:  opcode,
				Payload: []byte{},
			}
			resp := handler.handleSDNOperation(ctx, req)
			assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
		})
	}
}

func TestHandleSDNOperation_UnknownOpcode(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	// We need to set a mock SDN client to pass the nil check
	// but we don't have a mock, so we'll test this a different way
	ctx := context.Background()

	// Create a minimal mock by using WithQUICSDNService - but we can't really
	// set a mock client easily. Instead, let's test the unknown opcode path
	// by checking the handler directly returns not implemented for unknown opcodes

	// Since we can't mock the client easily, let's verify the routing behavior
	// by ensuring the HandleRequest method routes SDN operations correctly
	req := &quicwire.Request{
		Opcode:  0x53, // Not a valid SDN opcode; reserved
		Payload: []byte{},
	}
	resp := handler.HandleRequest(ctx, req)
	// 0x53 is still unallocated (0x50 is the NTP category, 0x51 the IAM
	// category, 0x52 the VPN category), so the authorization guard refuses it as unclassified before dispatch.
	assert.Equal(t, quicwire.StatusPermissionDenied, resp.Status)
}

// =============================================================================
// Handler Policy Engine Tests (nil policy engine path)
// =============================================================================

func TestHandleSDNApplyPolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	// Create a minimal mock for sdnClient would be needed
	// For now, test the policy engine nil check path

	ctx := context.Background()

	// The handlers check for policy engine first, then sdnClient
	// handleSDNApplyPolicy checks policyEngine first
	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNApplyPolicy,
		Payload: []byte{},
	}

	// Without SDN client, should return unavailable
	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestHandleSDNDeletePolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNDeletePolicy,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestHandleSDNGetPolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNGetPolicy,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestHandleSDNListPolicies_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  quicwire.OpSDNListPolicies,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// =============================================================================
// Request/Response Encoding Tests
// =============================================================================

func TestSDNGetPortStateRequest_Encoding(t *testing.T) {
	original := &SDNGetPortStateRequest{
		PortName: "eth0",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPortStateRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
}

func TestSDNGetPortStateResponse_Encoding(t *testing.T) {
	original := &SDNGetPortStateResponse{
		PortName:  "eth0",
		State:     "authorized",
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPortStateResponse
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
	assert.Equal(t, original.State, decoded.State)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNSetVLANRequest_Encoding(t *testing.T) {
	original := &SDNSetVLANRequest{
		PortName: "eth0",
		VLAN:     100,
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNSetVLANRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
	assert.Equal(t, original.VLAN, decoded.VLAN)
}

func TestSDNSetVLANResponse_Encoding(t *testing.T) {
	original := &SDNSetVLANResponse{
		PortName:  "eth0",
		VLAN:      100,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNSetVLANResponse
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
	assert.Equal(t, original.VLAN, decoded.VLAN)
	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNGetVLANRequest_Encoding(t *testing.T) {
	original := &SDNGetVLANRequest{
		PortName: "eth0",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetVLANRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
}

func TestSDNGetVLANResponse_Encoding(t *testing.T) {
	original := &SDNGetVLANResponse{
		PortName:  "eth0",
		VLAN:      200,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetVLANResponse
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
	assert.Equal(t, original.VLAN, decoded.VLAN)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNGetFlowRequest_Encoding(t *testing.T) {
	original := &SDNGetFlowRequest{
		BridgeName: "br0",
		Match:      "in_port=1",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetFlowRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BridgeName, decoded.BridgeName)
	assert.Equal(t, original.Match, decoded.Match)
}

func TestSDNGetFlowResponse_Encoding(t *testing.T) {
	original := &SDNGetFlowResponse{
		Flows: []*SDNFlow{
			{
				Table:       0,
				Priority:    100,
				Match:       "in_port=1",
				Actions:     "output:2",
				Cookie:      "0x1234",
				Duration:    60,
				IdleAge:     10,
				HardAge:     20,
				PacketCount: 1000,
				ByteCount:   100000,
			},
		},
		Total:     1,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetFlowResponse
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Flows, 1)
	assert.Equal(t, original.Total, decoded.Total)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)

	flow := decoded.Flows[0]
	assert.Equal(t, 0, flow.Table)
	assert.Equal(t, 100, flow.Priority)
	assert.Equal(t, "in_port=1", flow.Match)
	assert.Equal(t, "output:2", flow.Actions)
}

func TestSDNDeletePolicyRequest_Encoding(t *testing.T) {
	original := &SDNDeletePolicyRequest{
		PolicyID: "policy1",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNDeletePolicyRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PolicyID, decoded.PolicyID)
}

func TestSDNGetPolicyRequest_Encoding(t *testing.T) {
	original := &SDNGetPolicyRequest{
		PolicyID: "policy1",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPolicyRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PolicyID, decoded.PolicyID)
}

func TestSDNListPoliciesRequest_Encoding(t *testing.T) {
	original := &SDNListPoliciesRequest{}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNListPoliciesRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)
}

func TestSDNGetMetricsRequest_Encoding(t *testing.T) {
	original := &SDNGetMetricsRequest{
		BridgeName: "br0",
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetMetricsRequest
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BridgeName, decoded.BridgeName)
}

func TestSDNGetMetricsResponse_Encoding(t *testing.T) {
	original := &SDNGetMetricsResponse{
		Metrics: &SDNMetrics{
			BridgeCount:     5,
			PortCount:       20,
			FlowCount:       100,
			PolicyCount:     10,
			TotalPackets:    1000000,
			TotalBytes:      500000000,
			ActivePorts:     15,
			BlockedPorts:    3,
			AuthorizedPorts: 12,
			Timestamp:       time.Now().Unix(),
		},
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetMetricsResponse
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Metrics)
	assert.Equal(t, original.Metrics.BridgeCount, decoded.Metrics.BridgeCount)
	assert.Equal(t, original.Metrics.PortCount, decoded.Metrics.PortCount)
	assert.Equal(t, original.Metrics.FlowCount, decoded.Metrics.FlowCount)
	assert.Equal(t, original.Metrics.PolicyCount, decoded.Metrics.PolicyCount)
	assert.Equal(t, original.Metrics.TotalPackets, decoded.Metrics.TotalPackets)
	assert.Equal(t, original.Metrics.TotalBytes, decoded.Metrics.TotalBytes)
	assert.Equal(t, original.Metrics.ActivePorts, decoded.Metrics.ActivePorts)
	assert.Equal(t, original.Metrics.BlockedPorts, decoded.Metrics.BlockedPorts)
	assert.Equal(t, original.Metrics.AuthorizedPorts, decoded.Metrics.AuthorizedPorts)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

// =============================================================================
// SDNBridge, SDNPort, SDNFlow Type Tests
// =============================================================================

func TestSDNFlow_Encoding(t *testing.T) {
	original := &SDNFlow{
		Table:       1,
		Priority:    100,
		Match:       "in_port=1,dl_src=00:11:22:33:44:55",
		Actions:     "output:2,set_vlan_vid:100",
		Cookie:      "0xabcdef",
		Duration:    3600,
		IdleAge:     60,
		HardAge:     120,
		PacketCount: 10000,
		ByteCount:   1500000,
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNFlow
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Table, decoded.Table)
	assert.Equal(t, original.Priority, decoded.Priority)
	assert.Equal(t, original.Match, decoded.Match)
	assert.Equal(t, original.Actions, decoded.Actions)
	assert.Equal(t, original.Cookie, decoded.Cookie)
	assert.Equal(t, original.Duration, decoded.Duration)
	assert.Equal(t, original.IdleAge, decoded.IdleAge)
	assert.Equal(t, original.HardAge, decoded.HardAge)
	assert.Equal(t, original.PacketCount, decoded.PacketCount)
	assert.Equal(t, original.ByteCount, decoded.ByteCount)
}

func TestSDNMetrics_Encoding(t *testing.T) {
	original := &SDNMetrics{
		BridgeCount:     5,
		PortCount:       25,
		FlowCount:       150,
		PolicyCount:     20,
		TotalPackets:    5000000,
		TotalBytes:      2500000000,
		ActivePorts:     20,
		BlockedPorts:    3,
		AuthorizedPorts: 17,
		Timestamp:       time.Now().Unix(),
	}

	encoded, err := quicwire.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNMetrics
	err = quicwire.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.BridgeCount, decoded.BridgeCount)
	assert.Equal(t, original.PortCount, decoded.PortCount)
	assert.Equal(t, original.FlowCount, decoded.FlowCount)
	assert.Equal(t, original.PolicyCount, decoded.PolicyCount)
	assert.Equal(t, original.TotalPackets, decoded.TotalPackets)
	assert.Equal(t, original.TotalBytes, decoded.TotalBytes)
	assert.Equal(t, original.ActivePorts, decoded.ActivePorts)
	assert.Equal(t, original.BlockedPorts, decoded.BlockedPorts)
	assert.Equal(t, original.AuthorizedPorts, decoded.AuthorizedPorts)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

// =============================================================================
// handleSDNOperation Routing Tests
// =============================================================================

func TestHandleSDNOperation_RoutingAllOpcodes(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)
	ctx := context.Background()

	// Define all SDN opcodes and expected service unavailable response
	// (since we don't have a mock SDN client configured)
	sdnOpcodes := map[byte]string{
		quicwire.OpSDNCreateBridge: "SDNCreateBridge",
		quicwire.OpSDNDeleteBridge: "SDNDeleteBridge",
		quicwire.OpSDNGetBridge:    "SDNGetBridge",
		quicwire.OpSDNListBridges:  "SDNListBridges",
		quicwire.OpSDNCreatePort:   "SDNCreatePort",
		quicwire.OpSDNDeletePort:   "SDNDeletePort",
		quicwire.OpSDNGetPort:      "SDNGetPort",
		quicwire.OpSDNListPorts:    "SDNListPorts",
		quicwire.OpSDNGetPortState: "SDNGetPortState",
		quicwire.OpSDNSetPortState: "SDNSetPortState",
		quicwire.OpSDNSetVLAN:      "SDNSetVLAN",
		quicwire.OpSDNGetVLAN:      "SDNGetVLAN",
		quicwire.OpSDNAddFlow:      "SDNAddFlow",
		quicwire.OpSDNDeleteFlow:   "SDNDeleteFlow",
		quicwire.OpSDNGetFlow:      "SDNGetFlow",
		quicwire.OpSDNListFlows:    "SDNListFlows",
		quicwire.OpSDNApplyPolicy:  "SDNApplyPolicy",
		quicwire.OpSDNDeletePolicy: "SDNDeletePolicy",
		quicwire.OpSDNGetPolicy:    "SDNGetPolicy",
		quicwire.OpSDNListPolicies: "SDNListPolicies",
		quicwire.OpSDNGetMetrics:   "SDNGetMetrics",
	}

	for opcode, name := range sdnOpcodes {
		t.Run(name, func(t *testing.T) {
			req := &quicwire.Request{
				Opcode:  opcode,
				Payload: []byte{},
			}

			resp := handler.handleSDNOperation(ctx, req)
			// All should return unavailable since sdnClient is nil
			assert.Equal(t, quicwire.StatusUnavailable, resp.Status, "opcode %s should return unavailable", name)
		})
	}
}
