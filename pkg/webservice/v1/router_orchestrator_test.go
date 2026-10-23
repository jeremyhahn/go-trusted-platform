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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// countingOrchestratorServer answers ListAgents and CancelJob and counts
// the calls that reached it.
type countingOrchestratorServer struct {
	platformv1.UnimplementedOrchestratorServiceServer
	calls int
}

func (s *countingOrchestratorServer) ListAgents(context.Context, *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	s.calls++
	return &platformv1.ListOrchestratorAgentsResponse{}, nil
}

func (s *countingOrchestratorServer) CancelJob(context.Context, *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	s.calls++
	return &platformv1.CancelOrchestratorJobResponse{}, nil
}

const (
	orchestratorSystemTenant = "system"
	tenantAAgents            = "/api/v1/orchestrator/tenants/tenant-a/agents"
	tenantAJobCancel         = "/api/v1/orchestrator/tenants/tenant-a/jobs/7/cancel"
)

// serveOrchestrator sends one request through the webservice v1 router,
// authenticated by auth, and reports the status and whether the request
// reached the orchestrator server.
func serveOrchestrator(t *testing.T, auth jwt.TokenHandler, method, target string) (int, bool) {
	t.Helper()
	server := &countingOrchestratorServer{}
	router := newGatedTestRouter(t, &testHandlerRegistry{
		tokenHandler:        auth,
		orchestratorService: server,
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, target, nil))
	return recorder.Code, server.calls > 0
}

// orchestratorAdmin is an admin session of tenantID holding scopes.
func orchestratorAdmin(tenantID string, scopes ...string) *scopedSessionAuth {
	return &scopedSessionAuth{
		sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: tenantID},
		scopes:      scopes,
	}
}

// TestOrchestratorRoutes_SessionCallerDecidesTheTenant drives the
// orchestrator routes through the v1 router with a real session, so the
// tenant rule sees the caller sessionCaller builds from that session
// (docs/orchestrator/api-reference-rest.md, docs/tenant/api.md).
func TestOrchestratorRoutes_SessionCallerDecidesTheTenant(t *testing.T) {
	t.Run("an admin of the named tenant is served", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin("tenant-a", "orchestrator:read"), http.MethodGet, tenantAAgents)
		assert.Equal(t, http.StatusOK, code)
		assert.True(t, reached)
	})

	t.Run("an admin of another tenant is refused", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin("tenant-b", "orchestrator:read"), http.MethodGet, tenantAAgents)
		assert.Equal(t, http.StatusForbidden, code)
		assert.False(t, reached, "a refused request must not reach the orchestrator")
	})

	t.Run("an admin of the system tenant is served for any tenant", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin(orchestratorSystemTenant, "orchestrator:read"), http.MethodGet, tenantAAgents)
		assert.Equal(t, http.StatusOK, code)
		assert.True(t, reached)
	})
}

func TestOrchestratorRoutes_RefuseWithoutASession(t *testing.T) {
	code, reached := serveOrchestrator(t, &anonymousAuth{}, http.MethodGet, tenantAAgents)
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.False(t, reached)
}

func TestOrchestratorRoutes_RefuseACallerWithoutTheScope(t *testing.T) {
	t.Run("no orchestrator scope", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin("tenant-a"), http.MethodGet, tenantAAgents)
		assert.Equal(t, http.StatusForbidden, code)
		assert.False(t, reached)
	})

	t.Run("orchestrator:read does not grant a write route", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin("tenant-a", "orchestrator:read"), http.MethodPost, tenantAJobCancel)
		assert.Equal(t, http.StatusForbidden, code)
		assert.False(t, reached)
	})

	t.Run("orchestrator:write grants the write route", func(t *testing.T) {
		code, reached := serveOrchestrator(t, orchestratorAdmin("tenant-a", "orchestrator:write"), http.MethodPost, tenantAJobCancel)
		assert.Equal(t, http.StatusOK, code)
		assert.True(t, reached)
	})
}

func TestOrchestratorRoutes_RefuseAnAuthenticatedNonAdmin(t *testing.T) {
	user := &scopedSessionAuth{
		sessionAuth: sessionAuth{roles: []string{"user"}, tenantID: "tenant-a"},
		scopes:      []string{"orchestrator:read"},
	}
	code, reached := serveOrchestrator(t, user, http.MethodGet, tenantAAgents)
	assert.Equal(t, http.StatusForbidden, code)
	assert.False(t, reached)
}
