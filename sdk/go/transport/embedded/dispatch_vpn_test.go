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

package embedded

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingVPNServer answers each VPN RPC with a response carrying a field of
// the request it received, so a test can tell the call reached the right
// method with the caller's request.
type recordingVPNServer struct {
	platformv1.UnimplementedVPNServiceServer
}

func (recordingVPNServer) EnrolPeer(_ context.Context, req *platformv1.EnrolVPNPeerRequest) (*platformv1.EnrolVPNPeerResponse, error) {
	return &platformv1.EnrolVPNPeerResponse{Peer: req.GetPeer()}, nil
}

func (recordingVPNServer) ListPeers(_ context.Context, req *platformv1.ListVPNPeersRequest) (*platformv1.ListVPNPeersResponse, error) {
	return &platformv1.ListVPNPeersResponse{Peers: []*platformv1.VPNPeer{{TenantId: req.GetTenantId(), DeviceId: "dev-1"}}}, nil
}

func (recordingVPNServer) RevokePeer(_ context.Context, req *platformv1.RevokeVPNPeerRequest) (*platformv1.RevokeVPNPeerResponse, error) {
	if req.GetDeviceId() == "wrong" {
		return nil, status.Error(codes.PermissionDenied, "wrong device")
	}
	return &platformv1.RevokeVPNPeerResponse{}, nil
}

func (recordingVPNServer) GetStatus(_ context.Context, req *platformv1.GetVPNStatusRequest) (*platformv1.GetVPNStatusResponse, error) {
	return &platformv1.GetVPNStatusResponse{Gateways: []*platformv1.VPNGatewayStatus{{GatewayId: req.GetGatewayId(), Running: true}}}, nil
}

func (recordingVPNServer) GetPosturePolicy(_ context.Context, req *platformv1.GetVPNPosturePolicyRequest) (*platformv1.GetVPNPosturePolicyResponse, error) {
	return &platformv1.GetVPNPosturePolicyResponse{Policy: &platformv1.VPNPosturePolicy{TenantId: req.GetTenantId(), Name: req.GetName()}}, nil
}

func (recordingVPNServer) SetPosturePolicy(_ context.Context, req *platformv1.SetVPNPosturePolicyRequest) (*platformv1.SetVPNPosturePolicyResponse, error) {
	return &platformv1.SetVPNPosturePolicyResponse{Policy: req.GetPolicy()}, nil
}

func (recordingVPNServer) DeletePosturePolicy(_ context.Context, req *platformv1.DeleteVPNPosturePolicyRequest) (*platformv1.DeleteVPNPosturePolicyResponse, error) {
	if req.GetName() == "missing" {
		return nil, status.Error(codes.NotFound, "no such policy")
	}
	return &platformv1.DeleteVPNPosturePolicyResponse{}, nil
}

func (recordingVPNServer) ListPosturePolicies(_ context.Context, req *platformv1.ListVPNPosturePoliciesRequest) (*platformv1.ListVPNPosturePoliciesResponse, error) {
	return &platformv1.ListVPNPosturePoliciesResponse{Policies: []*platformv1.VPNPosturePolicy{{TenantId: req.GetTenantId(), Name: "baseline"}}}, nil
}

// TestDispatch_VPN drives the eight VPNService RPCs through the embedded
// connection to the registered server, and checks that a registry without a
// VPN service registers none of them.
func TestDispatch_VPN(t *testing.T) {
	a, err := New(&ServiceRegistry{VPN: recordingVPNServer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client := platformv1.NewVPNServiceClient(a.Connection())
	ctx := context.Background()

	t.Run("EnrolPeer", func(t *testing.T) {
		resp, err := client.EnrolPeer(ctx, &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "t1", DeviceId: "dev-1"}})
		if err != nil {
			t.Fatalf("EnrolPeer: %v", err)
		}
		if resp.GetPeer().GetTenantId() != "t1" || resp.GetPeer().GetDeviceId() != "dev-1" {
			t.Errorf("EnrolPeer = %v, want the enrolled peer t1/dev-1", resp)
		}
	})
	t.Run("ListPeers", func(t *testing.T) {
		resp, err := client.ListPeers(ctx, &platformv1.ListVPNPeersRequest{TenantId: "t1"})
		if err != nil {
			t.Fatalf("ListPeers: %v", err)
		}
		if len(resp.GetPeers()) != 1 || resp.GetPeers()[0].GetTenantId() != "t1" {
			t.Errorf("ListPeers = %v, want one peer of tenant t1", resp)
		}
	})
	t.Run("RevokePeer", func(t *testing.T) {
		if _, err := client.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: "t1", DeviceId: "dev-1"}); err != nil {
			t.Fatalf("RevokePeer: %v", err)
		}
		_, err := client.RevokePeer(ctx, &platformv1.RevokeVPNPeerRequest{TenantId: "t1", DeviceId: "wrong"})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("RevokePeer(wrong) err = %v, want the server's PermissionDenied", err)
		}
	})
	t.Run("GetStatus", func(t *testing.T) {
		resp, err := client.GetStatus(ctx, &platformv1.GetVPNStatusRequest{GatewayId: "gw-1"})
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if len(resp.GetGateways()) != 1 || resp.GetGateways()[0].GetGatewayId() != "gw-1" || !resp.GetGateways()[0].GetRunning() {
			t.Errorf("GetStatus = %v, want running gateway gw-1", resp)
		}
	})
	t.Run("GetPosturePolicy", func(t *testing.T) {
		resp, err := client.GetPosturePolicy(ctx, &platformv1.GetVPNPosturePolicyRequest{TenantId: "t1", Name: "baseline"})
		if err != nil {
			t.Fatalf("GetPosturePolicy: %v", err)
		}
		if resp.GetPolicy().GetTenantId() != "t1" || resp.GetPolicy().GetName() != "baseline" {
			t.Errorf("GetPosturePolicy = %v, want policy t1/baseline", resp)
		}
	})
	t.Run("SetPosturePolicy", func(t *testing.T) {
		resp, err := client.SetPosturePolicy(ctx, &platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "t1", Name: "strict", Module: "package vpn"}})
		if err != nil {
			t.Fatalf("SetPosturePolicy: %v", err)
		}
		if resp.GetPolicy().GetName() != "strict" || resp.GetPolicy().GetModule() != "package vpn" {
			t.Errorf("SetPosturePolicy = %v, want the stored policy strict", resp)
		}
	})
	t.Run("DeletePosturePolicy", func(t *testing.T) {
		if _, err := client.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "t1", Name: "strict"}); err != nil {
			t.Fatalf("DeletePosturePolicy: %v", err)
		}
		_, err := client.DeletePosturePolicy(ctx, &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "t1", Name: "missing"})
		if status.Code(err) != codes.NotFound {
			t.Errorf("DeletePosturePolicy(missing) err = %v, want the server's NotFound", err)
		}
	})
	t.Run("ListPosturePolicies", func(t *testing.T) {
		resp, err := client.ListPosturePolicies(ctx, &platformv1.ListVPNPosturePoliciesRequest{TenantId: "t1"})
		if err != nil {
			t.Fatalf("ListPosturePolicies: %v", err)
		}
		if len(resp.GetPolicies()) != 1 || resp.GetPolicies()[0].GetTenantId() != "t1" {
			t.Errorf("ListPosturePolicies = %v, want one policy of tenant t1", resp)
		}
	})

	t.Run("nil service registers nothing", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{})
		for _, md := range platformv1.VPNService_ServiceDesc.Methods {
			full := "/" + platformv1.VPNService_ServiceDesc.ServiceName + "/" + md.MethodName
			if _, ok := m[full]; ok {
				t.Errorf("%s registered without a service", full)
			}
		}
	})

	t.Run("every method is registered", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{VPN: recordingVPNServer{}})
		for _, md := range platformv1.VPNService_ServiceDesc.Methods {
			full := "/" + platformv1.VPNService_ServiceDesc.ServiceName + "/" + md.MethodName
			if _, ok := m[full]; !ok {
				t.Errorf("%s is not registered", full)
			}
		}
	})
}
