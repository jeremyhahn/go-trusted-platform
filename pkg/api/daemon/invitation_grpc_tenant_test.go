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

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestInvitationGRPCService_RevokeDeleteInvitation_CallerTenantEnforced pins
// the own-tenant rule (#2056): a caller bound to another tenant cannot revoke
// or delete the invitation, while an own-tenant or unbound caller can.
func TestInvitationGRPCService_RevokeDeleteInvitation_CallerTenantEnforced(t *testing.T) {
	t.Run("other tenant is refused", func(t *testing.T) {
		fake := &fakeInvitationServicer{getByIDResult: newTestInvitation()}
		svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)
		ctx := tokenCallerContext("tenant-a")

		revokeResp, err := svc.RevokeInvitation(ctx, &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 7})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RevokeInvitation code = %v (err %v), want PermissionDenied", status.Code(err), err)
		}
		if revokeResp != nil {
			t.Fatalf("RevokeInvitation response = %v, want nil", revokeResp)
		}

		deleteResp, err := svc.DeleteInvitation(ctx, &platformv1.DeleteInvitationRequest{InvitationId: 42})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("DeleteInvitation code = %v (err %v), want PermissionDenied", status.Code(err), err)
		}
		if deleteResp != nil {
			t.Fatalf("DeleteInvitation response = %v, want nil", deleteResp)
		}

		calls := fake.calls()
		if calls.revokeCalls != 0 {
			t.Fatalf("revokeCalls = %d, want 0", calls.revokeCalls)
		}
		if calls.deleteCalls != 0 {
			t.Fatalf("deleteCalls = %d, want 0", calls.deleteCalls)
		}
	})

	allowed := map[string]context.Context{
		"own tenant":     tokenCallerContext("tenant-1"),
		"unbound caller": context.Background(),
	}
	for name, ctx := range allowed {
		t.Run(name+" is allowed", func(t *testing.T) {
			fake := &fakeInvitationServicer{getByIDResult: newTestInvitation()}
			svc := NewInvitationGRPCService(logging.DefaultLogger(), fake)

			if _, err := svc.RevokeInvitation(ctx, &platformv1.RevokeInvitationRequest{InvitationId: 42, RevokerId: 7}); err != nil {
				t.Fatalf("RevokeInvitation: %v", err)
			}
			if _, err := svc.DeleteInvitation(ctx, &platformv1.DeleteInvitationRequest{InvitationId: 42}); err != nil {
				t.Fatalf("DeleteInvitation: %v", err)
			}

			calls := fake.calls()
			if calls.revokeCalls != 1 {
				t.Fatalf("revokeCalls = %d, want 1", calls.revokeCalls)
			}
			if calls.deleteCalls != 1 {
				t.Fatalf("deleteCalls = %d, want 1", calls.deleteCalls)
			}
		})
	}
}
