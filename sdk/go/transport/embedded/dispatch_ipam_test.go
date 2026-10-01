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

// testIPAMGatewayServer answers CreateIPAMPool, echoing the allocation
// window, so the dispatcher round-trip carries the new pool fields.
type testIPAMGatewayServer struct {
	platformv1.UnimplementedGatewayServiceServer
}

func (s *testIPAMGatewayServer) CreateIPAMPool(_ context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
	return &platformv1.CreateIPAMPoolResponse{Pool: &platformv1.IPAMPool{
		Id:         req.GetId(),
		Reserved:   req.GetReserved(),
		RangeStart: req.GetRangeStart(),
		RangeEnd:   req.GetRangeEnd(),
	}}, nil
}

// ipamPoolMethodNames lists the IPAM pool CRUD methods the embedded
// dispatcher must register beside the list method.
var ipamPoolMethodNames = []string{
	platformv1.GatewayService_ListIPAMPools_FullMethodName,
	platformv1.GatewayService_CreateIPAMPool_FullMethodName,
	platformv1.GatewayService_GetIPAMPool_FullMethodName,
	platformv1.GatewayService_UpdateIPAMPool_FullMethodName,
	platformv1.GatewayService_DeleteIPAMPool_FullMethodName,
}

// TestBuildHandlerMap_IPAMPoolCRUDRegistered verifies the embedded transport
// carries every IPAM pool RPC the other transports carry.
func TestBuildHandlerMap_IPAMPoolCRUDRegistered(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{Gateway: &testIPAMGatewayServer{}})
	for _, method := range ipamPoolMethodNames {
		if _, ok := m[method]; !ok {
			t.Errorf("handler for %s not registered", method)
		}
	}
}

// TestDispatch_CreateIPAMPoolCarriesWindow round-trips the allocation window
// through the dispatcher.
func TestDispatch_CreateIPAMPoolCarriesWindow(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{Gateway: &testIPAMGatewayServer{}})
	resp, err := m[platformv1.GatewayService_CreateIPAMPool_FullMethodName](context.Background(), &platformv1.CreateIPAMPoolRequest{
		Id:         "provisioning",
		Reserved:   []string{"192.0.2.1/32"},
		RangeStart: "192.0.2.50",
		RangeEnd:   "192.0.2.254",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	pool := resp.(*platformv1.CreateIPAMPoolResponse).GetPool()
	if pool.GetRangeStart() != "192.0.2.50" || pool.GetRangeEnd() != "192.0.2.254" || len(pool.GetReserved()) != 1 {
		t.Fatalf("window not carried: %+v", pool)
	}
}

// TestDispatch_IPAMPoolUnimplemented verifies a server error flows back
// through the dispatcher unchanged.
func TestDispatch_IPAMPoolUnimplemented(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{Gateway: &testIPAMGatewayServer{}})
	_, err := m[platformv1.GatewayService_DeleteIPAMPool_FullMethodName](context.Background(), &platformv1.DeleteIPAMPoolRequest{Id: "x"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("want Unimplemented, got %v", err)
	}
}
