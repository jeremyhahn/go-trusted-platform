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

package invitation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// tenantBInvitationServer serves every invitation as tenant-b's and records
// whether the handler reached RevokeInvitation or DeleteInvitation.
type tenantBInvitationServer struct {
	fakeInvitationServer
	revoked bool
	deleted bool
}

func (f *tenantBInvitationServer) GetInvitation(_ context.Context, r *platformv1.GetInvitationRequest) (*platformv1.GetInvitationResponse, error) {
	return &platformv1.GetInvitationResponse{
		Invitation: &platformv1.Invitation{Id: r.GetInvitationId(), TenantId: "tenant-b"},
	}, nil
}

func (f *tenantBInvitationServer) RevokeInvitation(ctx context.Context, r *platformv1.RevokeInvitationRequest) (*platformv1.RevokeInvitationResponse, error) {
	f.revoked = true
	return f.fakeInvitationServer.RevokeInvitation(ctx, r)
}

func (f *tenantBInvitationServer) DeleteInvitation(ctx context.Context, r *platformv1.DeleteInvitationRequest) (*platformv1.DeleteInvitationResponse, error) {
	f.deleted = true
	return f.fakeInvitationServer.DeleteInvitation(ctx, r)
}

func TestRevokeDeleteInvitation_RefusesAnotherTenantsInvitation(t *testing.T) {
	deleteReq := func() *http.Request {
		return httptest.NewRequest(http.MethodDelete, "/api/v1/invitations/42", nil)
	}
	revokeReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "/api/v1/invitations/42/revoke", strings.NewReader(`{}`))
	}

	t.Run("another tenant", func(t *testing.T) {
		srv := &tenantBInvitationServer{}
		rec := serve(srv, withSession(deleteReq(), "tenant-a", "42"))
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.False(t, srv.deleted, "DeleteInvitation must not reach the service")

		rec = serve(srv, withSession(revokeReq(), "tenant-a", "42"))
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		assert.False(t, srv.revoked, "RevokeInvitation must not reach the service")
	})

	t.Run("own tenant", func(t *testing.T) {
		srv := &tenantBInvitationServer{}
		rec := serve(srv, withSession(deleteReq(), "tenant-b", "42"))
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, srv.deleted)

		rec = serve(srv, withSession(revokeReq(), "tenant-b", "42"))
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, srv.revoked)
	})

	t.Run("no session", func(t *testing.T) {
		srv := &tenantBInvitationServer{}
		rec := serve(srv, deleteReq())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, srv.deleted)

		rec = serve(srv, revokeReq())
		assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.True(t, srv.revoked)
	})
}
