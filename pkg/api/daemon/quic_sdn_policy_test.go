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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// newQUICPolicyHandler is a QUIC handler on a fresh SDN service.
func newQUICPolicyHandler() (*SDNService, *QUICServiceHandler) {
	svc := newPolicySDNService()
	return svc, newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICSDNService(svc))
}

// webPolicyRequest is webPolicyBody as a QUIC apply payload.
func webPolicyRequest(t *testing.T) rest.CreatePolicyRequest {
	t.Helper()
	var req rest.CreatePolicyRequest
	require.NoError(t, json.Unmarshal([]byte(webPolicyBody), &req))
	return req
}

// callQUICPolicy sends req as the payload of a QUIC SDN operation through the
// dispatch the QUIC server uses.
func callQUICPolicy(t *testing.T, handler *QUICServiceHandler, opcode byte, req interface{}) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(req)
	require.NoError(t, err)
	return handler.handleSDNOperation(context.Background(), &quicwire.Request{Opcode: opcode, Payload: payload})
}

// decodeQUICPolicy decodes a successful QUIC policy response into v.
func decodeQUICPolicy(t *testing.T, resp *quicwire.Response, v interface{}) {
	t.Helper()
	require.Equal(t, quicwire.StatusOK, resp.Status, string(resp.Payload))
	require.NoError(t, quicwire.DecodePayload(resp.Payload, v))
}

// inUTC returns policy with its timestamps in UTC. The QUIC codec decodes
// times in the local zone; JSON and protobuf decode them in UTC.
func inUTC(policy rest.PolicyResponse) rest.PolicyResponse {
	policy.CreatedAt = policy.CreatedAt.UTC()
	policy.UpdatedAt = policy.UpdatedAt.UTC()
	return policy
}

func TestQUICSDNApplyPolicy(t *testing.T) {
	svc, handler := newQUICPolicyHandler()
	req := webPolicyRequest(t)
	req.Rules = []rest.PolicyRule{{Priority: 10, Action: "allow", Protocol: "tcp", DestinationPort: 443}}

	var applied rest.PolicyResponse
	decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, req), &applied)

	assert.NotEmpty(t, applied.ID)
	assert.Equal(t, "web", applied.Name)
	assert.Equal(t, "firewall", applied.Type)
	assert.Equal(t, int32(200), applied.Priority)
	assert.True(t, applied.Enabled)
	assert.Equal(t, []rest.PolicyTarget{{Type: "bridge", ID: "br0"}}, applied.Targets)
	require.Len(t, applied.Rules, 1)
	assert.Equal(t, "allow", applied.Rules[0].Action)
	assert.Equal(t, uint32(443), applied.Rules[0].DestinationPort)

	stored, err := svc.GetPolicy(context.Background(), &platformv1.GetPolicyRequest{PolicyId: applied.ID})
	require.NoError(t, err)
	assert.Equal(t, rest.PolicyToResponse(stored.GetPolicy()), inUTC(applied))
}

func TestQUICSDNApplyPolicyRefusals(t *testing.T) {
	_, handler := newQUICPolicyHandler()

	t.Run("unknown type", func(t *testing.T) {
		req := webPolicyRequest(t)
		req.Type = "sideways"
		resp := callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "sideways")
	})

	t.Run("missing name", func(t *testing.T) {
		req := webPolicyRequest(t)
		req.Name = ""
		resp := callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, req)
		assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status, string(resp.Payload))
	})

	t.Run("duplicate name", func(t *testing.T) {
		decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, webPolicyRequest(t)), &rest.PolicyResponse{})
		resp := callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, webPolicyRequest(t))
		assert.Equal(t, quicwire.StatusAlreadyExists, resp.Status, string(resp.Payload))
	})

	t.Run("undecodable payload", func(t *testing.T) {
		resp := handler.handleSDNOperation(context.Background(),
			&quicwire.Request{Opcode: quicwire.OpSDNApplyPolicy, Payload: []byte{0xFF, 0xFE}})
		assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)
	})
}

func TestQUICSDNGetPolicy(t *testing.T) {
	_, handler := newQUICPolicyHandler()
	var applied rest.PolicyResponse
	decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, webPolicyRequest(t)), &applied)

	for _, key := range []string{applied.ID, "web"} {
		var got rest.PolicyResponse
		decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNGetPolicy, SDNGetPolicyRequest{PolicyID: key}), &got)
		assert.Equal(t, applied, got, "policy fetched by %q", key)
	}
}

func TestQUICSDNListPolicies(t *testing.T) {
	svc, handler := newQUICPolicyHandler()
	decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, webPolicyRequest(t)), &rest.PolicyResponse{})
	_, err := svc.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{
		Name: "grpc-qos",
		Type: platformv1.PolicyType_POLICY_TYPE_QOS,
	}})
	require.NoError(t, err)

	names := func(req SDNListPoliciesRequest) []string {
		var list rest.SDNPolicyListResponse
		decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNListPolicies, req), &list)
		require.Equal(t, len(list.Policies), list.Count)
		got := make([]string, 0, len(list.Policies))
		for _, policy := range list.Policies {
			got = append(got, policy.Name)
		}
		return got
	}

	assert.ElementsMatch(t, []string{"web", "grpc-qos"}, names(SDNListPoliciesRequest{}))
	assert.Equal(t, []string{"grpc-qos"}, names(SDNListPoliciesRequest{Type: "qos"}))
	assert.Equal(t, []string{"web"}, names(SDNListPoliciesRequest{TargetID: "br0"}))
	assert.Empty(t, names(SDNListPoliciesRequest{TargetID: "br9"}))
}

func TestQUICSDNListPoliciesRefusals(t *testing.T) {
	_, handler := newQUICPolicyHandler()
	resp := handler.handleSDNOperation(context.Background(),
		&quicwire.Request{Opcode: quicwire.OpSDNListPolicies, Payload: []byte{0xFF, 0xFE}})
	assert.Equal(t, quicwire.StatusInvalidRequest, resp.Status)

	resp = newTestQUICServiceHandler(logging.DefaultLogger()).handleSDNOperation(context.Background(),
		&quicwire.Request{Opcode: quicwire.OpSDNListPolicies})
	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

func TestQUICSDNDeletePolicy(t *testing.T) {
	svc, handler := newQUICPolicyHandler()
	decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNApplyPolicy, webPolicyRequest(t)), &rest.PolicyResponse{})

	var deleted rest.SDNActionResponse
	decodeQUICPolicy(t, callQUICPolicy(t, handler, quicwire.OpSDNDeletePolicy, SDNDeletePolicyRequest{PolicyID: "web"}), &deleted)
	assert.Equal(t, rest.SDNActionResponse{ResourceID: "web", ResourceType: "policy", Action: "delete", Success: true,
		Message: "policy deleted successfully"}, deleted)

	_, err := svc.GetPolicy(context.Background(), &platformv1.GetPolicyRequest{PolicyId: "web"})
	assert.Error(t, err, "the policy is still there")

	resp := callQUICPolicy(t, handler, quicwire.OpSDNDeletePolicy, SDNDeletePolicyRequest{PolicyID: "web"})
	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
	assert.Contains(t, string(resp.Payload), "web")
}
