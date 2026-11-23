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

package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// initialAdminTenantServer records the CreateInitialAdminInvitation requests
// that reach it and answers an invitation for the requested owner.
type initialAdminTenantServer struct {
	platformv1.UnimplementedTenantServiceServer
	calls []*platformv1.CreateInitialAdminInvitationRequest
}

func (s *initialAdminTenantServer) CreateInitialAdminInvitation(
	_ context.Context, req *platformv1.CreateInitialAdminInvitationRequest) (*platformv1.CreateInitialAdminInvitationResponse, error) {

	s.calls = append(s.calls, req)
	return &platformv1.CreateInitialAdminInvitationResponse{
		Invitation: &platformv1.Invitation{Email: "owner@example.com"},
	}, nil
}

// mintOwnerInvitation sends POST /api/v1/tenants/{target}/initial-admin-invitation
// as an admin of callerTenant through the full v1 router: the session
// middleware, the admin gate and the system-only guard, as the daemon mounts
// them.
func mintOwnerInvitation(t *testing.T, callerTenant, target string) (*httptest.ResponseRecorder, *initialAdminTenantServer) {
	t.Helper()
	fake := &initialAdminTenantServer{}
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:  &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: callerTenant},
		tenantService: fake,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+target+"/initial-admin-invitation",
		strings.NewReader(`{"email":"owner@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	return rec, fake
}

// TestTenantRoutes_InitialAdminInvitationRefusesATenantAdminForItsOwnTenant:
// a tenant admin cannot mint the owner invitation of its own tenant; only the
// system tenant mints a new tenant's first owner.
func TestTenantRoutes_InitialAdminInvitationRefusesATenantAdminForItsOwnTenant(t *testing.T) {
	rec, fake := mintOwnerInvitation(t, "t1", "t1")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, fake.calls, "the service must not be reached")
}

// TestTenantRoutes_InitialAdminInvitationRefusesATenantAdminForAnotherTenant:
// a tenant admin cannot mint the owner invitation of another tenant.
func TestTenantRoutes_InitialAdminInvitationRefusesATenantAdminForAnotherTenant(t *testing.T) {
	rec, fake := mintOwnerInvitation(t, "t1", "t2")
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Empty(t, fake.calls, "the service must not be reached")
}

// TestTenantRoutes_InitialAdminInvitationReachesTheServiceForTheSystemTenant:
// the system tenant's admin reaches the service, with the tenant id taken
// from the path and the email from the body.
func TestTenantRoutes_InitialAdminInvitationReachesTheServiceForTheSystemTenant(t *testing.T) {
	rec, fake := mintOwnerInvitation(t, "system", "t2")
	assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.Len(t, fake.calls, 1)
	assert.Equal(t, "t2", fake.calls[0].GetTenantId())
	assert.Equal(t, "owner@example.com", fake.calls[0].GetEmail())
	assert.Contains(t, rec.Body.String(), "owner@example.com")
}
