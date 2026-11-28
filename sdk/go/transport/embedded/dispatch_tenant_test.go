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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingInitialAdminTenantServer answers CreateInitialAdminInvitation with
// the tenant and email it received.
type recordingInitialAdminTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
}

func (recordingInitialAdminTenantServer) CreateInitialAdminInvitation(
	_ context.Context,
	req *platformv1.CreateInitialAdminInvitationRequest,
) (*platformv1.CreateInitialAdminInvitationResponse, error) {
	return &platformv1.CreateInitialAdminInvitationResponse{
		Invitation: &platformv1.Invitation{TenantId: req.GetTenantId(), Email: req.GetEmail()},
	}, nil
}

// TestDispatch_Tenant checks every TenantService method is registered and
// that CreateInitialAdminInvitation reaches the registered server.
func TestDispatch_Tenant(t *testing.T) {
	t.Run("every method is registered", func(t *testing.T) {
		m := buildHandlerMap(&ServiceRegistry{Tenant: recordingInitialAdminTenantServer{}})
		for _, md := range platformv1.TenantService_ServiceDesc.Methods {
			full := "/" + platformv1.TenantService_ServiceDesc.ServiceName + "/" + md.MethodName
			if _, ok := m[full]; !ok {
				t.Errorf("%s is not registered", full)
			}
		}
	})

	t.Run("CreateInitialAdminInvitation", func(t *testing.T) {
		a, err := New(&ServiceRegistry{Tenant: recordingInitialAdminTenantServer{}})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		client := platformv1.NewTenantServiceClient(a.Connection())
		resp, err := client.CreateInitialAdminInvitation(context.Background(),
			&platformv1.CreateInitialAdminInvitationRequest{TenantId: "t1", Email: "owner@example.com"})
		if err != nil {
			t.Fatalf("CreateInitialAdminInvitation: %v", err)
		}
		if resp.GetInvitation().GetTenantId() != "t1" || resp.GetInvitation().GetEmail() != "owner@example.com" {
			t.Errorf("CreateInitialAdminInvitation = %v, want the server's answer for t1", resp)
		}
	})
}
