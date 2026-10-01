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

// fakeZoneClient answers the zone RPCs of SDNServiceClient; every other RPC
// is left to the embedded nil interface and is never called.
type fakeZoneClient struct {
	platformv1.SDNServiceClient
	err      error
	lastName string
}

func (f *fakeZoneClient) CreateNetworkZone(_ context.Context, in *platformv1.CreateNetworkZoneRequest, _ ...grpc.CallOption) (*platformv1.CreateNetworkZoneResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.CreateNetworkZoneResponse{Zone: &platformv1.NetworkZone{Config: in.GetConfig(), RestartRequired: true}}, nil
}

func (f *fakeZoneClient) UpdateNetworkZone(_ context.Context, in *platformv1.UpdateNetworkZoneRequest, _ ...grpc.CallOption) (*platformv1.UpdateNetworkZoneResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastName = in.GetName()
	return &platformv1.UpdateNetworkZoneResponse{Zone: &platformv1.NetworkZone{Config: in.GetConfig()}}, nil
}

func (f *fakeZoneClient) DeleteNetworkZone(_ context.Context, in *platformv1.DeleteNetworkZoneRequest, _ ...grpc.CallOption) (*platformv1.DeleteNetworkZoneResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastName = in.GetName()
	return &platformv1.DeleteNetworkZoneResponse{RestartRequired: true}, nil
}

func (f *fakeZoneClient) ListNetworkZones(_ context.Context, in *platformv1.ListNetworkZonesRequest, _ ...grpc.CallOption) (*platformv1.ListNetworkZonesResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.ListNetworkZonesResponse{Zones: []*platformv1.NetworkZone{{
		Config:    &platformv1.NetworkZoneConfig{Name: "provisioning", Offset: 5, LifecycleRole: in.GetLifecycleRole()},
		Numbering: &platformv1.NetworkZoneNumbering{Vlan: 405, Subnet4: "192.0.2.0/24", Gateway: "192.0.2.1"},
	}}}, nil
}

// TestZoneClient_Success covers every zone method against a fake server.
func TestZoneClient_Success(t *testing.T) {
	fake := &fakeZoneClient{}
	c := NewClientFromGRPC(fake)
	ctx := context.Background()

	z, err := c.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{Config: &platformv1.NetworkZoneConfig{
		Name: "lab", Offset: 9, PortClasses: []string{"hypervisor"},
		PrivilegedAccess: &platformv1.NetworkZonePrivilegedAccess{Reason: "r", ApprovedBy: "owner"},
	}})
	if err != nil || z.GetConfig().GetOffset() != 9 || !z.GetRestartRequired() ||
		z.GetConfig().GetPrivilegedAccess().GetApprovedBy() != "owner" {
		t.Fatalf("create = %+v, %v", z, err)
	}

	if _, err := c.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: "storage"}); err != nil || fake.lastName != "storage" {
		t.Fatalf("update: %v (name %q)", err, fake.lastName)
	}

	restart, err := c.DeleteNetworkZone(ctx, "lab")
	if err != nil || !restart || fake.lastName != "lab" {
		t.Fatalf("delete = %v, %v (name %q)", restart, err, fake.lastName)
	}

	zones, err := c.ListNetworkZones(ctx, "provisioning")
	if err != nil || len(zones) != 1 || zones[0].GetNumbering().GetVlan() != 405 {
		t.Fatalf("list = %+v, %v", zones, err)
	}
}

// TestZoneClient_Errors wraps every server failure in its typed error.
func TestZoneClient_Errors(t *testing.T) {
	boom := errors.New("boom")
	c := NewClientFromGRPC(&fakeZoneClient{err: boom})
	ctx := context.Background()

	_, err := c.CreateNetworkZone(ctx, &platformv1.CreateNetworkZoneRequest{})
	var createErr *ErrCreateNetworkZoneFailed
	if !errors.As(err, &createErr) || !errors.Is(err, boom) {
		t.Fatalf("create err = %v", err)
	}
	_, err = c.UpdateNetworkZone(ctx, &platformv1.UpdateNetworkZoneRequest{Name: "storage"})
	var updateErr *ErrUpdateNetworkZoneFailed
	if !errors.As(err, &updateErr) || updateErr.Name != "storage" {
		t.Fatalf("update err = %v", err)
	}
	_, err = c.DeleteNetworkZone(ctx, "lab")
	var deleteErr *ErrDeleteNetworkZoneFailed
	if !errors.As(err, &deleteErr) || deleteErr.Name != "lab" {
		t.Fatalf("delete err = %v", err)
	}
	_, err = c.ListNetworkZones(ctx, "")
	var listErr *ErrListNetworkZonesFailed
	if !errors.As(err, &listErr) {
		t.Fatalf("list err = %v", err)
	}
	for _, e := range []error{createErr, updateErr, deleteErr, listErr} {
		if e.Error() == "" {
			t.Fatalf("%T has an empty message", e)
		}
	}
}
