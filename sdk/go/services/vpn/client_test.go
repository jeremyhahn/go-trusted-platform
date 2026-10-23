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

package vpn

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// stubGRPC is a scripted VPNServiceClient: it records each request and
// answers with the scripted peer, policy and gateway, or with err.
type stubGRPC struct {
	peer    *platformv1.VPNPeer
	policy  *platformv1.VPNPosturePolicy
	gateway *platformv1.VPNGatewayStatus
	err     error
	last    proto.Message
}

func (s *stubGRPC) EnrolPeer(_ context.Context, in *platformv1.EnrolVPNPeerRequest, _ ...grpc.CallOption) (*platformv1.EnrolVPNPeerResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.EnrolVPNPeerResponse{Peer: s.peer}, nil
}

func (s *stubGRPC) ListPeers(_ context.Context, in *platformv1.ListVPNPeersRequest, _ ...grpc.CallOption) (*platformv1.ListVPNPeersResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListVPNPeersResponse{Peers: []*platformv1.VPNPeer{s.peer}}, nil
}

func (s *stubGRPC) RevokePeer(_ context.Context, in *platformv1.RevokeVPNPeerRequest, _ ...grpc.CallOption) (*platformv1.RevokeVPNPeerResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.RevokeVPNPeerResponse{}, nil
}

func (s *stubGRPC) GetStatus(_ context.Context, in *platformv1.GetVPNStatusRequest, _ ...grpc.CallOption) (*platformv1.GetVPNStatusResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetVPNStatusResponse{Gateways: []*platformv1.VPNGatewayStatus{s.gateway}}, nil
}

func (s *stubGRPC) GetPosturePolicy(_ context.Context, in *platformv1.GetVPNPosturePolicyRequest, _ ...grpc.CallOption) (*platformv1.GetVPNPosturePolicyResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetVPNPosturePolicyResponse{Policy: s.policy}, nil
}

func (s *stubGRPC) SetPosturePolicy(_ context.Context, in *platformv1.SetVPNPosturePolicyRequest, _ ...grpc.CallOption) (*platformv1.SetVPNPosturePolicyResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.SetVPNPosturePolicyResponse{Policy: s.policy}, nil
}

func (s *stubGRPC) DeletePosturePolicy(_ context.Context, in *platformv1.DeleteVPNPosturePolicyRequest, _ ...grpc.CallOption) (*platformv1.DeleteVPNPosturePolicyResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.DeleteVPNPosturePolicyResponse{}, nil
}

func (s *stubGRPC) ListPosturePolicies(_ context.Context, in *platformv1.ListVPNPosturePoliciesRequest, _ ...grpc.CallOption) (*platformv1.ListVPNPosturePoliciesResponse, error) {
	s.last = in
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListVPNPosturePoliciesResponse{Policies: []*platformv1.VPNPosturePolicy{s.policy}}, nil
}

// clientCall is one Client method, the request it must send, and the
// operation its failure must name.
type clientCall struct {
	op   Op
	call func(context.Context, *Client) error
	want proto.Message
}

var clientCalls = []clientCall{
	{
		op: OpEnrolPeer,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.EnrolPeer(ctx, "acme", "laptop-1", []string{"management"})
			return err
		},
		want: &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}}},
	},
	{
		op: OpListPeers,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.ListPeers(ctx, "acme")
			return err
		},
		want: &platformv1.ListVPNPeersRequest{TenantId: "acme"},
	},
	{
		op:   OpRevokePeer,
		call: func(ctx context.Context, c *Client) error { return c.RevokePeer(ctx, "acme", "laptop-1") },
		want: &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"},
	},
	{
		op: OpStatus,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.Status(ctx, "gw-1")
			return err
		},
		want: &platformv1.GetVPNStatusRequest{GatewayId: "gw-1"},
	},
	{
		op: OpGetPosturePolicy,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.GetPosturePolicy(ctx, "acme", "corp")
			return err
		},
		want: &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
	},
	{
		op: OpSetPosturePolicy,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.SetPosturePolicy(ctx, "acme", "corp", "package vpn.posture")
			return err
		},
		want: &platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package vpn.posture"}},
	},
	{
		op:   OpDeletePosturePolicy,
		call: func(ctx context.Context, c *Client) error { return c.DeletePosturePolicy(ctx, "acme", "corp") },
		want: &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
	},
	{
		op: OpListPosturePolicies,
		call: func(ctx context.Context, c *Client) error {
			_, err := c.ListPosturePolicies(ctx, "acme")
			return err
		},
		want: &platformv1.ListVPNPosturePoliciesRequest{TenantId: "acme"},
	},
}

func TestClientSendsEveryRequest(t *testing.T) {
	if len(platformv1.VPNService_ServiceDesc.Methods) != len(clientCalls) {
		t.Fatalf("VPNService has %d methods, the test calls %d", len(platformv1.VPNService_ServiceDesc.Methods), len(clientCalls))
	}
	for _, tc := range clientCalls {
		stub := &stubGRPC{}
		if err := tc.call(context.Background(), NewClientFromGRPC(stub)); err != nil {
			t.Errorf("%s: error = %v", tc.op, err)
			continue
		}
		if !proto.Equal(stub.last, tc.want) {
			t.Errorf("%s: sent %v, want %v", tc.op, stub.last, tc.want)
		}
	}
}

func TestClientUnwrapsTheResponseEnvelopes(t *testing.T) {
	stub := &stubGRPC{
		peer:    &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1"},
		policy:  &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp"},
		gateway: &platformv1.VPNGatewayStatus{GatewayId: "gw-1", Reporting: true},
	}
	client := NewClientFromGRPC(stub)
	ctx := context.Background()

	peer, err := client.EnrolPeer(ctx, "acme", "laptop-1", nil)
	if err != nil || peer.GetDeviceId() != "laptop-1" {
		t.Fatalf("EnrolPeer() = %v, %v", peer, err)
	}
	peers, err := client.ListPeers(ctx, "")
	if err != nil || len(peers) != 1 {
		t.Fatalf("ListPeers() = %v, %v", peers, err)
	}
	gateways, err := client.Status(ctx, "")
	if err != nil || len(gateways) != 1 || !gateways[0].GetReporting() {
		t.Fatalf("Status() = %v, %v", gateways, err)
	}
	policy, err := client.GetPosturePolicy(ctx, "acme", "corp")
	if err != nil || policy.GetName() != "corp" {
		t.Fatalf("GetPosturePolicy() = %v, %v", policy, err)
	}
	set, err := client.SetPosturePolicy(ctx, "acme", "corp", "package vpn.posture")
	if err != nil || set.GetName() != "corp" {
		t.Fatalf("SetPosturePolicy() = %v, %v", set, err)
	}
	policies, err := client.ListPosturePolicies(ctx, "")
	if err != nil || len(policies) != 1 {
		t.Fatalf("ListPosturePolicies() = %v, %v", policies, err)
	}
}

func TestClientWrapsTransportFailuresWithTypedErrors(t *testing.T) {
	cause := errors.New("connection closed")
	client := NewClientFromGRPC(&stubGRPC{err: cause})
	for _, tc := range clientCalls {
		err := tc.call(context.Background(), client)
		var callErr *ErrCallFailed
		if !errors.As(err, &callErr) || callErr.Op != tc.op || !errors.Is(err, cause) {
			t.Errorf("%s: error = %v, want ErrCallFailed{%s} wrapping the cause", tc.op, err, tc.op)
		}
	}
}

func TestNewClientRejectsANilTransport(t *testing.T) {
	if _, err := NewClient(nil); !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("NewClient(nil) error = %v, want ErrNilConnection", err)
	}
}

// fakeAdapter is a transport.Adapter whose Connection may be nil, covering
// both branches of NewClient's validation.
type fakeAdapter struct{ conn grpc.ClientConnInterface }

// Connection returns the configured connection.
func (f *fakeAdapter) Connection() grpc.ClientConnInterface { return f.conn }

// Close is a no-op.
func (f *fakeAdapter) Close() error { return nil }

// IsConnected always reports true.
func (f *fakeAdapter) IsConnected() bool { return true }

// Target reports a fixed test target.
func (f *fakeAdapter) Target() string { return "test" }

// errNotConnected is what the test connection answers every call with.
type errNotConnected struct{}

func (errNotConnected) Error() string { return "not connected" }

// nopConn satisfies grpc.ClientConnInterface without doing any I/O.
type nopConn struct{}

// Invoke reports that the test connection carries no RPCs.
func (nopConn) Invoke(context.Context, string, any, any, ...grpc.CallOption) error {
	return errNotConnected{}
}

// NewStream reports that the test connection carries no streams.
func (nopConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errNotConnected{}
}

func TestNewClientBuildsFromATransportAdapter(t *testing.T) {
	client, err := NewClient(&fakeAdapter{conn: nopConn{}})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.ListPeers(context.Background(), ""); !errors.Is(err, errNotConnected{}) {
		t.Fatalf("ListPeers() over the adapter error = %v, want the connection's error", err)
	}

	if _, err := NewClient(&fakeAdapter{}); !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("NewClient(adapter with nil connection) error = %v, want ErrNilConnection", err)
	}
}

func TestErrCallFailedNamesTheOperation(t *testing.T) {
	err := &ErrCallFailed{Op: OpRevokePeer, Cause: errNotConnected{}}
	if got, want := err.Error(), "vpn: revoke peer failed: not connected"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
