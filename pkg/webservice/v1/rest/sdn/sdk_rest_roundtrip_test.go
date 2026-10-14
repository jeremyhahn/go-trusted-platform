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

package sdn

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// connectSDNSDK serves the SDN router over TLS in-process and returns an SDK
// SDN client connected to it through the REST adapter.
func connectSDNSDK(t *testing.T, server platformv1.SDNServiceServer) platformv1.SDNServiceClient {
	t.Helper()

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	NewSDNRouter(logging.NewLogger(slog.LevelError, io.Discard), server, &mockResponseWriter{}).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	httpServer := httptest.NewTLSServer(root)
	t.Cleanup(httpServer.Close)

	tlsConfig := httpServer.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(),
		platform.NewOptions(platform.WithRESTAddr(httpServer.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, adapter.Close()) })

	return platformv1.NewSDNServiceClient(adapter.Connection())
}

func TestSDKREST_ApplyPolicy(t *testing.T) {
	var got *platformv1.ApplyPolicyRequest
	server := &mockSDNService{
		applyPolicyFunc: func(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
			got = req
			return &platformv1.ApplyPolicyResponse{Policy: &platformv1.Policy{
				Id:       req.GetPolicyId(),
				Config:   req.GetConfig(),
				Status:   platformv1.PolicyStatus_POLICY_STATUS_ACTIVE,
				HitCount: 3,
			}}, nil
		},
	}
	client := connectSDNSDK(t, server)

	resp, err := client.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{
		PolicyId: "p1",
		Config: &platformv1.PolicyConfig{
			Name: "web", Type: platformv1.PolicyType_POLICY_TYPE_QOS, Priority: 5, Enabled: true,
			Rules: []*platformv1.PolicyRule{{
				RuleId: "r1",
				Match:  &platformv1.PolicyRuleMatch{SourceIp: "10.0.0.0/8", VlanId: 20},
				Action: platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, ActionValue: "1mbit",
			}},
			Targets: []*platformv1.PolicyTarget{{Type: platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, Id: "eth1"}},
		},
	})
	require.NoError(t, err)

	require.NotNil(t, got, "the SDK claim did not reach ApplyPolicy")
	config := got.GetConfig()
	assert.Equal(t, "p1", got.GetPolicyId())
	assert.Equal(t, "web", config.GetName())
	assert.Equal(t, platformv1.PolicyType_POLICY_TYPE_QOS, config.GetType())
	assert.Equal(t, int32(5), config.GetPriority())
	assert.True(t, config.GetEnabled())
	require.Len(t, config.GetRules(), 1)
	assert.Equal(t, "10.0.0.0/8", config.GetRules()[0].GetMatch().GetSourceIp())
	assert.Equal(t, uint32(20), config.GetRules()[0].GetMatch().GetVlanId())
	assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, config.GetRules()[0].GetAction())
	require.Len(t, config.GetTargets(), 1)
	assert.Equal(t, platformv1.PolicyTargetType_POLICY_TARGET_TYPE_PORT, config.GetTargets()[0].GetType())

	assert.True(t, resp.GetStatus().GetSuccess())
	policy := resp.GetPolicy()
	assert.Equal(t, "p1", policy.GetId())
	assert.Equal(t, platformv1.PolicyStatus_POLICY_STATUS_ACTIVE, policy.GetStatus())
	assert.Equal(t, uint64(3), policy.GetHitCount())
	assert.Equal(t, platformv1.PolicyType_POLICY_TYPE_QOS, policy.GetConfig().GetType())
	assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, policy.GetConfig().GetRules()[0].GetAction())
}

func TestSDKREST_ApplyPolicy_ServiceRefusalIsInvalidArgument(t *testing.T) {
	server := &mockSDNService{
		applyPolicyFunc: func(context.Context, *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "policy name is required")
		},
	}
	client := connectSDNSDK(t, server)

	_, err := client.ApplyPolicy(context.Background(), &platformv1.ApplyPolicyRequest{Config: &platformv1.PolicyConfig{}})

	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}
