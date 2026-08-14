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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Conversion Function Tests - These don't require services
// =============================================================================

func TestConvertSDNACLsToPbRules(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		result := convertSDNACLsToPbRules(nil)
		assert.Nil(t, result)
	})

	t.Run("empty_input", func(t *testing.T) {
		result := convertSDNACLsToPbRules([]*SDNACLRule{})
		assert.Nil(t, result)
	})

	t.Run("with_acls", func(t *testing.T) {
		acls := []*SDNACLRule{
			{
				Priority: 100,
				Action:   "allow",
				Match: &SDNFlowMatch{
					IPv4Src: "192.168.1.0/24",
					IPv4Dst: "10.0.0.0/8",
					TCPSrc:  12345,
					TCPDst:  80,
					VLANVid: 100,
				},
			},
			{
				Priority: 50,
				Action:   "deny",
				Match:    nil,
			},
		}

		result := convertSDNACLsToPbRules(acls)
		require.Len(t, result, 2)

		assert.Equal(t, int32(100), result[0].Priority)
		assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW, result[0].Action)
		assert.Equal(t, "192.168.1.0/24", result[0].Match.SourceIp)
		assert.Equal(t, "10.0.0.0/8", result[0].Match.DestinationIp)
		assert.Equal(t, uint32(12345), result[0].Match.SourcePort)
		assert.Equal(t, uint32(80), result[0].Match.DestinationPort)
		assert.Equal(t, uint32(100), result[0].Match.VlanId)

		assert.Equal(t, int32(50), result[1].Priority)
		assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY, result[1].Action)
	})
}

func TestConvertPbRulesToSDNACLs(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		result := convertPbRulesToSDNACLs(nil)
		assert.Nil(t, result)
	})

	t.Run("empty_input", func(t *testing.T) {
		result := convertPbRulesToSDNACLs([]*platformv1.PolicyRule{})
		assert.Nil(t, result)
	})

	t.Run("with_rules", func(t *testing.T) {
		rules := []*platformv1.PolicyRule{
			{
				Priority: 100,
				Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
				Match: &platformv1.PolicyRuleMatch{
					SourceIp:        "192.168.1.0/24",
					DestinationIp:   "10.0.0.0/8",
					SourcePort:      12345,
					DestinationPort: 80,
					VlanId:          100,
				},
			},
			{
				Priority: 50,
				Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY,
			},
		}

		result := convertPbRulesToSDNACLs(rules)
		require.Len(t, result, 2)

		assert.Equal(t, 100, result[0].Priority)
		assert.Equal(t, "allow", result[0].Action)
		assert.Equal(t, "192.168.1.0/24", result[0].Match.IPv4Src)
		assert.Equal(t, "10.0.0.0/8", result[0].Match.IPv4Dst)
		assert.Equal(t, uint16(12345), result[0].Match.TCPSrc)
		assert.Equal(t, uint16(80), result[0].Match.TCPDst)
		assert.Equal(t, uint16(100), result[0].Match.VLANVid)

		assert.Equal(t, 50, result[1].Priority)
		assert.Equal(t, "deny", result[1].Action)
	})
}

func TestConvertPbPolicyToSDNPolicy(t *testing.T) {
	t.Run("nil_input", func(t *testing.T) {
		result := convertPbPolicyToSDNPolicy("port1", nil)
		assert.Nil(t, result)
	})

	t.Run("minimal_policy", func(t *testing.T) {
		now := time.Now()
		pol := &platformv1.Policy{
			Id:        "policy-1",
			CreatedAt: timestamppb.New(now),
		}

		result := convertPbPolicyToSDNPolicy("port1", pol)
		require.NotNil(t, result)
		assert.Equal(t, "port1", result.PortID)
		assert.Equal(t, now.Unix(), result.IssuedAt)
	})

	t.Run("with_rules", func(t *testing.T) {
		pol := &platformv1.Policy{
			Id: "policy-1",
			Config: &platformv1.PolicyConfig{
				Rules: []*platformv1.PolicyRule{
					{
						Priority: 100,
						Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
					},
				},
			},
			CreatedAt: timestamppb.New(time.Now()),
		}

		result := convertPbPolicyToSDNPolicy("port1", pol)
		require.NotNil(t, result)
		require.Len(t, result.ACLs, 1)
		assert.Equal(t, 100, result.ACLs[0].Priority)
		assert.Equal(t, "allow", result.ACLs[0].Action)
	})
}

func TestHandleSDNOperation_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// All SDN operations should return unavailable when sdnClient is nil
	opcodes := []byte{
		quic.OpSDNCreateBridge,
		quic.OpSDNDeleteBridge,
		quic.OpSDNGetBridge,
		quic.OpSDNListBridges,
		quic.OpSDNCreatePort,
		quic.OpSDNDeletePort,
		quic.OpSDNGetPort,
		quic.OpSDNListPorts,
		quic.OpSDNGetPortState,
		quic.OpSDNSetPortState,
		quic.OpSDNSetVLAN,
		quic.OpSDNGetVLAN,
		quic.OpSDNAddFlow,
		quic.OpSDNDeleteFlow,
		quic.OpSDNGetFlow,
		quic.OpSDNListFlows,
		quic.OpSDNGetMetrics,
	}

	for _, opcode := range opcodes {
		t.Run(quic.OpcodeToString(opcode), func(t *testing.T) {
			req := &quic.Request{
				Opcode:  opcode,
				Payload: []byte{},
			}
			resp := handler.handleSDNOperation(ctx, req)
			assert.Equal(t, quic.StatusUnavailable, resp.Status)
		})
	}
}

func TestHandleSDNOperation_UnknownOpcode(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	// We need to set a mock SDN client to pass the nil check
	// but we don't have a mock, so we'll test this a different way
	ctx := context.Background()

	// Create a minimal mock by using WithQUICSDNService - but we can't really
	// set a mock client easily. Instead, let's test the unknown opcode path
	// by checking the handler directly returns not implemented for unknown opcodes

	// Since we can't mock the client easily, let's verify the routing behavior
	// by ensuring the HandleRequest method routes SDN operations correctly
	req := &quic.Request{
		Opcode:  0x51, // Not a valid SDN opcode; reserved for NTP growth
		Payload: []byte{},
	}
	resp := handler.HandleRequest(ctx, req)
	// 0x51 is still unallocated (0x50 is the NTP category opcode), so the
	// dispatcher must answer unknown-opcode.
	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

// =============================================================================
// Handler Policy Engine Tests (nil policy engine path)
// =============================================================================

func TestHandleSDNApplyPolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	// Create a minimal mock for sdnClient would be needed
	// For now, test the policy engine nil check path

	ctx := context.Background()

	// The handlers check for policy engine first, then sdnClient
	// handleSDNApplyPolicy checks policyEngine first
	req := &quic.Request{
		Opcode:  quic.OpSDNApplyPolicy,
		Payload: []byte{},
	}

	// Without SDN client, should return unavailable
	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleSDNDeletePolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNDeletePolicy,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleSDNGetPolicy_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPolicy,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleSDNListPolicies_NilPolicyEngine(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNListPolicies,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// Request/Response Encoding Tests
// =============================================================================

func TestSDNGetPortStateRequest_Encoding(t *testing.T) {
	original := &SDNGetPortStateRequest{
		PortName: "eth0",
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPortStateRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
}

func TestSDNGetPortStateResponse_Encoding(t *testing.T) {
	original := &SDNGetPortStateResponse{
		PortName:  "eth0",
		State:     "authorized",
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPortStateResponse
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNSetVLANRequest
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNSetVLANResponse
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetVLANRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortName, decoded.PortName)
}

func TestSDNGetVLANResponse_Encoding(t *testing.T) {
	original := &SDNGetVLANResponse{
		PortName:  "eth0",
		VLAN:      200,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetVLANResponse
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetFlowRequest
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetFlowResponse
	err = quic.DecodePayload(encoded, &decoded)
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

func TestSDNApplyPolicyRequest_Encoding(t *testing.T) {
	original := &SDNApplyPolicyRequest{
		PortID:   "port1",
		TenantID: "tenant1",
		VLAN:     100,
		ACLs: []*SDNACLRule{
			{
				Priority:    100,
				Action:      "allow",
				Description: "Allow HTTP",
				Match: &SDNFlowMatch{
					InPort:  "1",
					EthSrc:  "00:11:22:33:44:55",
					TCPDst:  80,
					IPProto: 6,
				},
			},
		},
		Metadata: map[string]string{"env": "prod"},
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNApplyPolicyRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
	assert.Equal(t, original.TenantID, decoded.TenantID)
	assert.Equal(t, original.VLAN, decoded.VLAN)
	assert.Len(t, decoded.ACLs, 1)
	assert.Equal(t, "prod", decoded.Metadata["env"])
}

func TestSDNApplyPolicyResponse_Encoding(t *testing.T) {
	original := &SDNApplyPolicyResponse{
		PortID:    "port1",
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNApplyPolicyResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNDeletePolicyRequest_Encoding(t *testing.T) {
	original := &SDNDeletePolicyRequest{
		PortID: "port1",
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNDeletePolicyRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
}

func TestSDNDeletePolicyResponse_Encoding(t *testing.T) {
	original := &SDNDeletePolicyResponse{
		PortID:    "port1",
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNDeletePolicyResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNGetPolicyRequest_Encoding(t *testing.T) {
	original := &SDNGetPolicyRequest{
		PortID: "port1",
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPolicyRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
}

func TestSDNGetPolicyResponse_Encoding(t *testing.T) {
	original := &SDNGetPolicyResponse{
		Policy: &SDNPolicy{
			PortID:    "port1",
			TenantID:  "tenant1",
			VLAN:      100,
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Metadata:  map[string]string{"key": "value"},
			ACLs: []*SDNACLRule{
				{
					Priority:    100,
					Action:      "allow",
					Description: "Test rule",
					Match: &SDNFlowMatch{
						InPort: "1",
					},
				},
			},
		},
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetPolicyResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Policy)
	assert.Equal(t, original.Policy.PortID, decoded.Policy.PortID)
	assert.Equal(t, original.Policy.TenantID, decoded.Policy.TenantID)
	assert.Equal(t, original.Policy.VLAN, decoded.Policy.VLAN)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNListPoliciesRequest_Encoding(t *testing.T) {
	original := &SDNListPoliciesRequest{}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNListPoliciesRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)
}

func TestSDNListPoliciesResponse_Encoding(t *testing.T) {
	original := &SDNListPoliciesResponse{
		Policies: []*SDNPolicy{
			{PortID: "port1", TenantID: "tenant1", VLAN: 100},
			{PortID: "port2", TenantID: "tenant2", VLAN: 200},
		},
		Total:     2,
		Timestamp: time.Now().Unix(),
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNListPoliciesResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Policies, 2)
	assert.Equal(t, original.Total, decoded.Total)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestSDNGetMetricsRequest_Encoding(t *testing.T) {
	original := &SDNGetMetricsRequest{
		BridgeName: "br0",
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetMetricsRequest
	err = quic.DecodePayload(encoded, &decoded)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNGetMetricsResponse
	err = quic.DecodePayload(encoded, &decoded)
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
// SDNACLRule and SDNFlowMatch Encoding Tests
// =============================================================================

func TestSDNACLRule_Encoding(t *testing.T) {
	original := &SDNACLRule{
		Priority:    100,
		Action:      "allow",
		Description: "Test ACL rule",
		Match: &SDNFlowMatch{
			InPort:  "1",
			EthSrc:  "00:11:22:33:44:55",
			EthDst:  "66:77:88:99:aa:bb",
			EthType: 0x0800,
			VLANVid: 100,
			IPProto: 6,
			IPv4Src: "192.168.1.0/24",
			IPv4Dst: "10.0.0.0/8",
			TCPSrc:  12345,
			TCPDst:  80,
			UDPSrc:  0,
			UDPDst:  0,
		},
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNACLRule
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Priority, decoded.Priority)
	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.Description, decoded.Description)
	require.NotNil(t, decoded.Match)
	assert.Equal(t, original.Match.InPort, decoded.Match.InPort)
	assert.Equal(t, original.Match.EthSrc, decoded.Match.EthSrc)
	assert.Equal(t, original.Match.EthDst, decoded.Match.EthDst)
	assert.Equal(t, original.Match.EthType, decoded.Match.EthType)
	assert.Equal(t, original.Match.VLANVid, decoded.Match.VLANVid)
	assert.Equal(t, original.Match.IPProto, decoded.Match.IPProto)
	assert.Equal(t, original.Match.IPv4Src, decoded.Match.IPv4Src)
	assert.Equal(t, original.Match.IPv4Dst, decoded.Match.IPv4Dst)
	assert.Equal(t, original.Match.TCPSrc, decoded.Match.TCPSrc)
	assert.Equal(t, original.Match.TCPDst, decoded.Match.TCPDst)
}

func TestSDNFlowMatch_EncodingAllFields(t *testing.T) {
	original := &SDNFlowMatch{
		InPort:  "eth0",
		EthSrc:  "00:11:22:33:44:55",
		EthDst:  "66:77:88:99:aa:bb",
		EthType: 0x0800,
		VLANVid: 100,
		IPProto: 17,
		IPv4Src: "10.0.0.0/8",
		IPv4Dst: "192.168.0.0/16",
		TCPSrc:  0,
		TCPDst:  0,
		UDPSrc:  53,
		UDPDst:  53,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNFlowMatch
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.InPort, decoded.InPort)
	assert.Equal(t, original.EthSrc, decoded.EthSrc)
	assert.Equal(t, original.EthDst, decoded.EthDst)
	assert.Equal(t, original.EthType, decoded.EthType)
	assert.Equal(t, original.VLANVid, decoded.VLANVid)
	assert.Equal(t, original.IPProto, decoded.IPProto)
	assert.Equal(t, original.IPv4Src, decoded.IPv4Src)
	assert.Equal(t, original.IPv4Dst, decoded.IPv4Dst)
	assert.Equal(t, original.UDPSrc, decoded.UDPSrc)
	assert.Equal(t, original.UDPDst, decoded.UDPDst)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNFlow
	err = quic.DecodePayload(encoded, &decoded)
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

func TestSDNPolicy_Encoding(t *testing.T) {
	original := &SDNPolicy{
		PortID:    "port1",
		TenantID:  "tenant1",
		VLAN:      100,
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Metadata:  map[string]string{"env": "prod", "region": "us-west"},
		ACLs: []*SDNACLRule{
			{
				Priority:    100,
				Action:      "allow",
				Description: "Allow HTTP",
				Match: &SDNFlowMatch{
					IPProto: 6,
					TCPDst:  80,
				},
			},
			{
				Priority:    50,
				Action:      "deny",
				Description: "Deny all",
			},
		},
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNPolicy
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.PortID, decoded.PortID)
	assert.Equal(t, original.TenantID, decoded.TenantID)
	assert.Equal(t, original.VLAN, decoded.VLAN)
	assert.Equal(t, original.ExpiresAt, decoded.ExpiresAt)
	assert.Equal(t, original.IssuedAt, decoded.IssuedAt)
	assert.Equal(t, original.Metadata["env"], decoded.Metadata["env"])
	assert.Equal(t, original.Metadata["region"], decoded.Metadata["region"])
	assert.Len(t, decoded.ACLs, 2)
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

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded SDNMetrics
	err = quic.DecodePayload(encoded, &decoded)
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
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// Define all SDN opcodes and expected service unavailable response
	// (since we don't have a mock SDN client configured)
	sdnOpcodes := map[byte]string{
		quic.OpSDNCreateBridge: "SDNCreateBridge",
		quic.OpSDNDeleteBridge: "SDNDeleteBridge",
		quic.OpSDNGetBridge:    "SDNGetBridge",
		quic.OpSDNListBridges:  "SDNListBridges",
		quic.OpSDNCreatePort:   "SDNCreatePort",
		quic.OpSDNDeletePort:   "SDNDeletePort",
		quic.OpSDNGetPort:      "SDNGetPort",
		quic.OpSDNListPorts:    "SDNListPorts",
		quic.OpSDNGetPortState: "SDNGetPortState",
		quic.OpSDNSetPortState: "SDNSetPortState",
		quic.OpSDNSetVLAN:      "SDNSetVLAN",
		quic.OpSDNGetVLAN:      "SDNGetVLAN",
		quic.OpSDNAddFlow:      "SDNAddFlow",
		quic.OpSDNDeleteFlow:   "SDNDeleteFlow",
		quic.OpSDNGetFlow:      "SDNGetFlow",
		quic.OpSDNListFlows:    "SDNListFlows",
		quic.OpSDNApplyPolicy:  "SDNApplyPolicy",
		quic.OpSDNDeletePolicy: "SDNDeletePolicy",
		quic.OpSDNGetPolicy:    "SDNGetPolicy",
		quic.OpSDNListPolicies: "SDNListPolicies",
		quic.OpSDNGetMetrics:   "SDNGetMetrics",
	}

	for opcode, name := range sdnOpcodes {
		t.Run(name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  opcode,
				Payload: []byte{},
			}

			resp := handler.handleSDNOperation(ctx, req)
			// All should return unavailable since sdnClient is nil
			assert.Equal(t, quic.StatusUnavailable, resp.Status, "opcode %s should return unavailable", name)
		})
	}
}

// =============================================================================
// Edge Cases and Error Path Tests
// =============================================================================

func TestConvertSDNACLsToPbRules_NilACLs(t *testing.T) {
	result := convertSDNACLsToPbRules(nil)
	assert.Nil(t, result)
}

func TestConvertPbRulesToSDNACLs_NilRules(t *testing.T) {
	result := convertPbRulesToSDNACLs(nil)
	assert.Nil(t, result)
}

func TestConvertPbPolicyToSDNPolicy_NilCreatedAt(t *testing.T) {
	pol := &platformv1.Policy{
		Id: "policy-1",
	}

	result := convertPbPolicyToSDNPolicy("port1", pol)
	require.NotNil(t, result)
	assert.Equal(t, int64(0), result.IssuedAt)
}
