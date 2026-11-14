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

//go:build opa

// VPN tests over gRPC, MCP and QUIC that store a posture policy, which needs
// the OPA engine to compile it. The !opa build refuses every policy as
// Unavailable (vpn_posture_noopa_test.go).

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestVPNGRPCService_PosturePolicyLifecycle(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	set, err := server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: vpnTestPolicy},
	})
	require.NoError(t, err)
	assert.NotZero(t, set.GetPolicy().GetUpdatedAtUnix())

	got, err := server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	require.NoError(t, err)
	assert.Equal(t, vpnTestPolicy, got.GetPolicy().GetModule())

	listed, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
	require.NoError(t, err)
	assert.Len(t, listed.GetPolicies(), 1)

	_, err = server.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	require.NoError(t, err)

	_, err = server.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestVPNGRPCService_RefusesInvalidRequests(t *testing.T) {
	server, _ := newVPNTestServer(t)
	ctx := context.Background()

	_, err := server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing peer")

	_, err = server.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme"}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing device id")

	_, err = server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a missing policy")

	_, err = server.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package other\n"},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a module outside package vpn.posture")

	listed, err := server.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{})
	require.NoError(t, err)
	assert.Empty(t, listed.GetPolicies(), "a refused policy must not be stored")
}

func TestMCPProvidersRunTheVPNOperationsOnTheSharedServer(t *testing.T) {
	server, _ := newVPNTestServer(t)

	for name, provider := range vpnProviders(server) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			enrolled, err := provider.VPNEnrolPeer(ctx, "acme", "laptop-1", []string{"management"})
			require.NoError(t, err)
			enrolResp, ok := enrolled.(*platformv1.EnrolVPNPeerResponse)
			require.True(t, ok, "VPNEnrolPeer() = %T, want the pb response", enrolled)
			assert.Equal(t, []string{"management"}, enrolResp.GetPeer().GetZones())

			peers, err := provider.VPNListPeers(ctx, "acme")
			require.NoError(t, err)
			assert.Len(t, peers.(*platformv1.ListVPNPeersResponse).GetPeers(), 1)

			_, err = provider.VPNRevokePeer(ctx, "acme", "laptop-1")
			require.NoError(t, err)

			statusResult, err := provider.VPNStatus(ctx, "gw-1")
			require.NoError(t, err)
			assert.Len(t, statusResult.(*platformv1.GetVPNStatusResponse).GetGateways(), 1)

			_, err = provider.VPNPosturePolicySet(ctx, "acme", "corp", vpnTestPolicy)
			require.NoError(t, err)

			got, err := provider.VPNPosturePolicyGet(ctx, "acme", "corp")
			require.NoError(t, err)
			assert.Equal(t, "corp", got.(*platformv1.GetVPNPosturePolicyResponse).GetPolicy().GetName())

			policies, err := provider.VPNPosturePolicyList(ctx, "")
			require.NoError(t, err)
			assert.Len(t, policies.(*platformv1.ListVPNPosturePoliciesResponse).GetPolicies(), 1)

			_, err = provider.VPNPosturePolicyDelete(ctx, "acme", "corp")
			require.NoError(t, err)
		})
	}
}

func TestMCPProvidersReturnTheServiceRefusals(t *testing.T) {
	server, _ := newVPNTestServer(t)

	for name, provider := range vpnProviders(server) {
		t.Run(name, func(t *testing.T) {
			_, err := provider.VPNRevokePeer(context.Background(), "acme", "never-enrolled")
			assert.Equal(t, codes.NotFound, status.Code(err))

			_, err = provider.VPNPosturePolicySet(context.Background(), "acme", "corp", "package other\n")
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
}

func TestQUICVPNCategoryServesEverySubOperation(t *testing.T) {
	handler, _ := newVPNQUICHandler(t)
	ctx := context.Background()

	var enrolled platformv1.EnrolVPNPeerResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubEnrolPeer,
		&platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}}})), &enrolled)
	assert.Equal(t, "laptop-1", enrolled.GetPeer().GetDeviceId())

	var peers platformv1.ListVPNPeersResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubListPeers,
		&platformv1.ListVPNPeersRequest{TenantId: "acme"})), &peers)
	require.Len(t, peers.GetPeers(), 1)
	assert.Equal(t, []string{"management"}, peers.GetPeers()[0].GetZones())

	var gateways platformv1.GetVPNStatusResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubGetStatus,
		&platformv1.GetVPNStatusRequest{GatewayId: "gw-1"})), &gateways)
	require.Len(t, gateways.GetGateways(), 1)
	assert.Equal(t, "lease-1", gateways.GetGateways()[0].GetLeases()[0].GetId())

	var set platformv1.SetVPNPosturePolicyResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubSetPosturePolicy,
		&platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: vpnTestPolicy}})), &set)
	assert.Equal(t, "corp", set.GetPolicy().GetName())

	var got platformv1.GetVPNPosturePolicyResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubGetPosturePolicy,
		&platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})), &got)
	assert.Equal(t, vpnTestPolicy, got.GetPolicy().GetModule())

	var policies platformv1.ListVPNPosturePoliciesResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubListPosturePolicies,
		&platformv1.ListVPNPosturePoliciesRequest{TenantId: "acme"})), &policies)
	assert.Len(t, policies.GetPolicies(), 1)

	var deleted platformv1.DeleteVPNPosturePolicyResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubDeletePosturePolicy,
		&platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"})), &deleted)

	var revoked platformv1.RevokeVPNPeerResponse
	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubRevokePeer,
		&platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"})), &revoked)

	requireVPNQUICOK(t, handler.HandleRequest(ctx, vpnCategoryRequest(t, quicwire.VPNSubListPeers,
		&platformv1.ListVPNPeersRequest{TenantId: "acme"})), &peers)
	assert.Empty(t, peers.GetPeers(), "the revoked peer must be gone")
}
