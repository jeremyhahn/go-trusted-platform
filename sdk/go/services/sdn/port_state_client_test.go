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
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakePortStateClient records the SetPortState request it receives.
type fakePortStateClient struct {
	platformv1.SDNServiceClient
	err  error
	last *platformv1.SetPortStateRequest
}

func (f *fakePortStateClient) SetPortState(_ context.Context, in *platformv1.SetPortStateRequest, _ ...grpc.CallOption) (*platformv1.SetPortStateResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.last = in
	return &platformv1.SetPortStateResponse{Port: &platformv1.Port{Id: in.GetPortId(), BridgeId: in.GetBridgeId()}}, nil
}

func TestClient_SetPortState_SendsStateAndPolicing(t *testing.T) {
	fake := &fakePortStateClient{}
	c := NewClientFromGRPC(fake)

	port, err := c.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br0", PortId: "eth0", AdminState: "down",
		IngressRate: 10_000_000, IngressBurst: 1_000_000,
	})
	if err != nil {
		t.Fatalf("SetPortState: %v", err)
	}
	if port.GetId() != "eth0" || port.GetBridgeId() != "br0" {
		t.Fatalf("port = %v", port)
	}
	if fake.last.GetAdminState() != "down" || fake.last.GetIngressRate() != 10_000_000 || fake.last.GetIngressBurst() != 1_000_000 {
		t.Fatalf("request = %v", fake.last)
	}
}

func TestClient_SetPortState_WrapsError(t *testing.T) {
	boom := errors.New("boom")
	c := NewClientFromGRPC(&fakePortStateClient{err: boom})

	_, err := c.SetPortState(context.Background(), &platformv1.SetPortStateRequest{BridgeId: "br0", PortId: "eth0"})

	var setErr *ErrSetPortStateFailed
	if !errors.As(err, &setErr) || !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if setErr.BridgeID != "br0" || setErr.PortID != "eth0" || setErr.Error() == "" {
		t.Fatalf("err fields = %+v", setErr)
	}
}
