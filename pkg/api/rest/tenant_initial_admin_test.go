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

package rest

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeInitialAdminServer records the owner invitation the REST route sends.
type fakeInitialAdminServer struct {
	calls  int
	caller *platformtoken.AuthorizedContext
	got    *platformv1.CreateInitialAdminInvitationRequest
}

func (f *fakeInitialAdminServer) CreateInitialAdminInvitation(_ context.Context, caller *platformtoken.AuthorizedContext, req *platformv1.CreateInitialAdminInvitationRequest) (*platformv1.CreateInitialAdminInvitationResponse, error) {
	f.calls++
	f.caller = caller
	f.got = req
	return &platformv1.CreateInitialAdminInvitationResponse{}, nil
}

func initialAdminRouter(server InitialAdminInvitationServer) *mux.Router {
	mgr := newMockTenantManager()
	mgr.tenants[tenantSystemID] = createTestTenantEntity(tenantSystemID, "system")
	mgr.tenants[tenantAID] = createTestTenantEntity(tenantAID, tenantAName)
	opts := []TenantHandlersOption{
		WithTenantManager(mgr),
		WithTenantLogger(slog.Default()),
		WithTenantGuard(tenantTestGuard()),
		WithTenantSystemTenant(tenantSystemID),
	}
	if server != nil {
		opts = append(opts, WithTenantInitialAdmin(server))
	}
	router := mux.NewRouter()
	NewTenantHandlers(opts...).RegisterRoutes(router)
	return router
}

// TestTenantRoutes_InitialAdminInvitation: the daemon serves the owner
// invitation the SDK REST adapter targets, to the system tenant only, with
// the path tenant winning over any body tenant and the verified caller passed
// on as the inviter.
func TestTenantRoutes_InitialAdminInvitation(t *testing.T) {
	const path = "/api/v1/tenants/" + tenantAID + "/initial-admin-invitation"
	body := map[string]string{"email": "owner@example.com", "tenantId": tenantBID}

	t.Run("system tenant", func(t *testing.T) {
		fake := &fakeInitialAdminServer{}
		rr := serveTenant(t, initialAdminRouter(fake), tenantSystemToken, http.MethodPost, path, body)
		require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
		require.Equal(t, 1, fake.calls)
		assert.Equal(t, tenantAID, fake.got.GetTenantId())
		assert.Equal(t, "owner@example.com", fake.got.GetEmail())
		require.NotNil(t, fake.caller)
		assert.Equal(t, "system-operator", fake.caller.Subject)
		var resp platformv1.CreateInitialAdminInvitationResponse
		require.NoError(t, protojson.Unmarshal(rr.Body.Bytes(), &resp), rr.Body.String())
	})

	t.Run("another tenant is refused", func(t *testing.T) {
		fake := &fakeInitialAdminServer{}
		rr := serveTenant(t, initialAdminRouter(fake), tenantAToken, http.MethodPost, path, body)
		require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
		assert.Zero(t, fake.calls)
	})

	t.Run("no server wired", func(t *testing.T) {
		rr := serveTenant(t, initialAdminRouter(nil), tenantSystemToken, http.MethodPost, path, body)
		assert.Equal(t, http.StatusServiceUnavailable, rr.Code, rr.Body.String())
	})
}
