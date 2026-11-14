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

// recordingBarrierServer answers each barrier RPC with a status naming the
// RPC and the request field it received, so a test can tell the call reached
// the right method with the caller's request.
type recordingBarrierServer struct {
	platformv1.UnimplementedBarrierServiceServer
}

func (recordingBarrierServer) Init(_ context.Context, req *platformv1.BarrierInitRequest) (*platformv1.BarrierInitResponse, error) {
	return &platformv1.BarrierInitResponse{
		Status:    &platformv1.Status{Success: true, Message: "init"},
		Strategy:  platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR,
		Threshold: req.GetThreshold(),
	}, nil
}

func (recordingBarrierServer) GetStatus(context.Context, *platformv1.BarrierStatusRequest) (*platformv1.BarrierStatusResponse, error) {
	return &platformv1.BarrierStatusResponse{Sealed: true, Initialized: true}, nil
}

func (recordingBarrierServer) Unseal(_ context.Context, req *platformv1.BarrierUnsealRequest) (*platformv1.BarrierUnsealResponse, error) {
	if req.GetSecret() != "share-1" {
		return nil, status.Error(codes.PermissionDenied, "wrong secret")
	}
	return &platformv1.BarrierUnsealResponse{Status: &platformv1.Status{Success: true, Message: "unseal"}}, nil
}

func (recordingBarrierServer) Seal(context.Context, *platformv1.BarrierSealRequest) (*platformv1.BarrierSealResponse, error) {
	return &platformv1.BarrierSealResponse{Status: &platformv1.Status{Success: true, Message: "seal"}}, nil
}

func (recordingBarrierServer) Rekey(_ context.Context, req *platformv1.BarrierRekeyRequest) (*platformv1.BarrierRekeyResponse, error) {
	return &platformv1.BarrierRekeyResponse{
		Status:    &platformv1.Status{Success: true, Message: "rekey"},
		Threshold: req.GetThreshold(),
	}, nil
}

// TestDispatch_Barrier drives the five BarrierService RPCs through the
// embedded connection to the registered server, and checks that a registry
// without a Barrier service registers none of them.
func TestDispatch_Barrier(t *testing.T) {
	a, err := New(&ServiceRegistry{Barrier: recordingBarrierServer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client := platformv1.NewBarrierServiceClient(a.Connection())
	ctx := context.Background()

	t.Run("Init", func(t *testing.T) {
		resp, err := client.Init(ctx, &platformv1.BarrierInitRequest{Threshold: 3, Shares: 5})
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if resp.GetStatus().GetMessage() != "init" || resp.GetThreshold() != 3 {
			t.Errorf("Init = %v, want the server's init answer with threshold 3", resp)
		}
	})
	t.Run("GetStatus", func(t *testing.T) {
		resp, err := client.GetStatus(ctx, &platformv1.BarrierStatusRequest{})
		if err != nil {
			t.Fatalf("GetStatus: %v", err)
		}
		if !resp.GetSealed() || !resp.GetInitialized() {
			t.Errorf("GetStatus = %v, want sealed and initialized", resp)
		}
	})
	t.Run("Unseal", func(t *testing.T) {
		resp, err := client.Unseal(ctx, &platformv1.BarrierUnsealRequest{Secret: "share-1"})
		if err != nil {
			t.Fatalf("Unseal: %v", err)
		}
		if resp.GetStatus().GetMessage() != "unseal" {
			t.Errorf("Unseal = %v, want the server's unseal answer", resp)
		}
		_, err = client.Unseal(ctx, &platformv1.BarrierUnsealRequest{Secret: "wrong"})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("Unseal(wrong) err = %v, want the server's PermissionDenied", err)
		}
	})
	t.Run("Seal", func(t *testing.T) {
		resp, err := client.Seal(ctx, &platformv1.BarrierSealRequest{})
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		if resp.GetStatus().GetMessage() != "seal" {
			t.Errorf("Seal = %v, want the server's seal answer", resp)
		}
	})
	t.Run("Rekey", func(t *testing.T) {
		resp, err := client.Rekey(ctx, &platformv1.BarrierRekeyRequest{Threshold: 2, Shares: 3})
		if err != nil {
			t.Fatalf("Rekey: %v", err)
		}
		if resp.GetStatus().GetMessage() != "rekey" || resp.GetThreshold() != 2 {
			t.Errorf("Rekey = %v, want the server's rekey answer with threshold 2", resp)
		}
	})

	t.Run("nil service registers nothing", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{})
		for _, md := range platformv1.BarrierService_ServiceDesc.Methods {
			full := "/" + platformv1.BarrierService_ServiceDesc.ServiceName + "/" + md.MethodName
			if _, ok := m[full]; ok {
				t.Errorf("%s registered without a service", full)
			}
		}
	})

	t.Run("every method is registered", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{Barrier: recordingBarrierServer{}})
		for _, md := range platformv1.BarrierService_ServiceDesc.Methods {
			full := "/" + platformv1.BarrierService_ServiceDesc.ServiceName + "/" + md.MethodName
			if _, ok := m[full]; !ok {
				t.Errorf("%s is not registered", full)
			}
		}
	})
}
