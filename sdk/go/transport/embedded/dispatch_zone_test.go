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

// testZoneSDNServer answers CreateNetworkZone, echoing the zone config, and
// leaves the other zone RPCs unimplemented.
type testZoneSDNServer struct {
	platformv1.UnimplementedSDNServiceServer
}

func (s *testZoneSDNServer) CreateNetworkZone(_ context.Context, req *platformv1.CreateNetworkZoneRequest) (*platformv1.CreateNetworkZoneResponse, error) {
	return &platformv1.CreateNetworkZoneResponse{Zone: &platformv1.NetworkZone{Config: req.GetConfig(), RestartRequired: true}}, nil
}

// TestBuildHandlerMap_ZoneOpsRegistered verifies the embedded transport
// carries every zone RPC the other transports carry.
func TestBuildHandlerMap_ZoneOpsRegistered(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{SDN: &testZoneSDNServer{}})
	for _, method := range []string{
		platformv1.SDNService_CreateNetworkZone_FullMethodName,
		platformv1.SDNService_UpdateNetworkZone_FullMethodName,
		platformv1.SDNService_DeleteNetworkZone_FullMethodName,
		platformv1.SDNService_ListNetworkZones_FullMethodName,
	} {
		if _, ok := m[method]; !ok {
			t.Errorf("handler for %s not registered", method)
		}
	}
}

// TestDispatch_CreateNetworkZoneCarriesSchema round-trips the new zone
// fields through the dispatcher.
func TestDispatch_CreateNetworkZoneCarriesSchema(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{SDN: &testZoneSDNServer{}})
	resp, err := m[platformv1.SDNService_CreateNetworkZone_FullMethodName](context.Background(), &platformv1.CreateNetworkZoneRequest{
		Config: &platformv1.NetworkZoneConfig{
			Name: "lab", Offset: 9, PortClasses: []string{"hypervisor"},
			PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{Reason: "r", ApprovedBy: "owner"},
		},
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	z := resp.(*platformv1.CreateNetworkZoneResponse).GetZone()
	if z.GetConfig().GetOffset() != 9 || z.GetConfig().GetPrivilegedAccess().GetApprovedBy() != "owner" || !z.GetRestartRequired() {
		t.Fatalf("zone not carried: %+v", z)
	}
}

// TestDispatch_ZoneOpsPropagateErrors verifies server errors flow back
// through the dispatcher unchanged for every other zone RPC.
func TestDispatch_ZoneOpsPropagateErrors(t *testing.T) {
	m := buildHandlerMap(&ServiceRegistry{SDN: &testZoneSDNServer{}})
	ctx := context.Background()
	calls := map[string]interface{}{
		platformv1.SDNService_UpdateNetworkZone_FullMethodName: &platformv1.UpdateNetworkZoneRequest{Name: "storage"},
		platformv1.SDNService_DeleteNetworkZone_FullMethodName: &platformv1.DeleteNetworkZoneRequest{Name: "lab"},
		platformv1.SDNService_ListNetworkZones_FullMethodName:  &platformv1.ListNetworkZonesRequest{},
	}
	for method, req := range calls {
		if _, err := m[method](ctx, req); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: want Unimplemented, got %v", method, err)
		}
	}
}
