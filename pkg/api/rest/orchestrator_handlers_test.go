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
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// orchestratorTestServer records the ListJobs request it receives and
// answers CancelJob with a fixed error, so the tests can see both what the
// route bound and how an RPC error reaches the client.
type orchestratorTestServer struct {
	platformv1.UnimplementedOrchestratorServiceServer

	listJobs  *platformv1.ListOrchestratorJobsRequest
	cancelErr error
}

func (s *orchestratorTestServer) ListJobs(_ context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	s.listJobs = req
	return &platformv1.ListOrchestratorJobsResponse{
		Jobs: []*platformv1.OrchestratorJob{{JobId: "j1", State: "running"}},
		Page: &platformv1.OrchestratorPageInfo{Total: 1, Limit: req.GetPage().GetLimit()},
	}, nil
}

func (s *orchestratorTestServer) CancelJob(_ context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	if s.cancelErr != nil {
		return nil, s.cancelErr
	}
	return &platformv1.CancelOrchestratorJobResponse{JobId: req.GetJobId(), Cancelled: true}, nil
}

func orchestratorRouter(server platformv1.OrchestratorServiceServer) *mux.Router {
	router := mux.NewRouter()
	guard := NewScopeGuard(tenantOperatorAuthorizer{tenantID: "acme"}, nil, nil)
	NewOrchestratorHandlers(server, guard, "system", nil).RegisterRoutes(router)
	return router
}

// tenantOperatorAuthorizer admits operatorToken with every scope, as a
// member of tenantID.
type tenantOperatorAuthorizer struct{ tenantID string }

func (a tenantOperatorAuthorizer) AuthorizeToken(_ context.Context, token, _, _, _, _ string) (*platformtoken.AuthorizedContext, error) {
	if token != operatorToken {
		return nil, ErrOrchestratorServiceNotAvailable{}
	}
	return &platformtoken.AuthorizedContext{Subject: token, TenantID: a.tenantID, Scopes: []string{"*:*"}}, nil
}

func TestOrchestratorTenantRoutesRefuseAnotherTenant(t *testing.T) {
	rec := serveOrchestrator(orchestratorRouter(&orchestratorTestServer{}), http.MethodGet,
		"/api/v1/orchestrator/tenants/other/jobs")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d (%s), want 403", rec.Code, rec.Body)
	}
}

// TestOrchestratorQueryCannotOverridePathTenant: a query key naming a
// path-bound field, under its proto or its JSON name, never reaches the
// service with another tenant. The loop runs each request many times so
// map iteration order cannot hide an override.
func TestOrchestratorQueryCannotOverridePathTenant(t *testing.T) {
	for _, query := range []string{"tenantId=globex", "tenant_id=globex", "agentId=other", "agent_id=other"} {
		t.Run(query, func(t *testing.T) {
			for range 20 {
				srv := &orchestratorRecordingServer{}
				rec := serveOrchestrator(orchestratorRouter(srv), http.MethodPost,
					"/api/v1/orchestrator/tenants/acme/agents/x/disable?"+query)
				if srv.got != nil {
					req, ok := srv.got.(*platformv1.DisableOrchestratorAgentRequest)
					if !ok || req.GetTenantId() != "acme" || req.GetAgentId() != "x" {
						t.Fatalf("service reached with %v, want tenant acme and agent x only", srv.got)
					}
				}
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body)
				}
			}
		})
	}
}

// TestOrchestratorSessionRoutesServeOnlyTheSystemTenant: the session RPCs
// carry no tenant, and the embedded orchestrator lists every tenant's
// sessions for a caller it cannot place in a tenant, so a tenant caller
// holding the orchestrator scopes is refused before the service.
func TestOrchestratorSessionRoutesServeOnlyTheSystemTenant(t *testing.T) {
	for _, call := range orchestratorRouteCalls {
		if !strings.Contains(call.target, "/sessions") {
			continue
		}
		t.Run(call.method+" "+call.target, func(t *testing.T) {
			acme := &orchestratorRecordingServer{}
			rec := serveOrchestrator(orchestratorRouter(acme), call.method, call.target)
			if rec.Code != http.StatusForbidden || acme.got != nil {
				t.Fatalf("tenant caller: status = %d, RPC called = %v; want 403 before the RPC", rec.Code, acme.got != nil)
			}

			system := &orchestratorRecordingServer{}
			if rec := serveOrchestrator(systemOrchestratorRouter(system), call.method, call.target); rec.Code != http.StatusOK || system.got == nil {
				t.Fatalf("system tenant: status = %d (%s), RPC called = %v; want 200 from the RPC", rec.Code, rec.Body, system.got != nil)
			}
		})
	}
}

// systemOrchestratorRouter mounts the orchestrator routes for a caller in
// the system tenant.
func systemOrchestratorRouter(server platformv1.OrchestratorServiceServer) *mux.Router {
	router := mux.NewRouter()
	guard := NewScopeGuard(tenantOperatorAuthorizer{tenantID: "system"}, nil, nil)
	NewOrchestratorHandlers(server, guard, "system", nil).RegisterRoutes(router)
	return router
}

func serveOrchestrator(router http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, operatorRequest(method, target, http.NoBody))
	return rec
}

func TestOrchestratorListJobsBindsPathQueryAndPage(t *testing.T) {
	server := &orchestratorTestServer{}
	rec := serveOrchestrator(orchestratorRouter(server), http.MethodGet,
		"/api/v1/orchestrator/tenants/acme/jobs?statuses=running&statuses=queued&page.limit=20&page.offset=40")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}

	got := server.listJobs
	if got.GetTenantId() != "acme" || !slices.Equal(got.GetStatuses(), []string{"running", "queued"}) ||
		got.GetPage().GetLimit() != 20 || got.GetPage().GetOffset() != 40 {
		t.Fatalf("ListJobs bound %v", got)
	}
	resp := &platformv1.ListOrchestratorJobsResponse{}
	if err := protojson.Unmarshal(rec.Body.Bytes(), resp); err != nil {
		t.Fatalf("response %s: %v", rec.Body, err)
	}
	if len(resp.GetJobs()) != 1 || resp.GetJobs()[0].GetJobId() != "j1" || resp.GetPage().GetLimit() != 20 {
		t.Fatalf("response = %v", resp)
	}
}

func TestOrchestratorCancelJob(t *testing.T) {
	rec := serveOrchestrator(orchestratorRouter(&orchestratorTestServer{}), http.MethodPost,
		"/api/v1/orchestrator/tenants/acme/jobs/j1/cancel")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	resp := &platformv1.CancelOrchestratorJobResponse{}
	if err := protojson.Unmarshal(rec.Body.Bytes(), resp); err != nil {
		t.Fatalf("response %s: %v", rec.Body, err)
	}
	if resp.GetJobId() != "j1" || !resp.GetCancelled() {
		t.Fatalf("response = %v, want j1 cancelled", resp)
	}
}

func TestOrchestratorHandlerErrors(t *testing.T) {
	tests := []struct {
		name   string
		server platformv1.OrchestratorServiceServer
		method string
		target string
		want   int
	}{
		{"no server is 503", nil, http.MethodGet, "/api/v1/orchestrator/health", http.StatusServiceUnavailable},
		{"a job in the wrong state is 409",
			&orchestratorTestServer{cancelErr: status.Error(codes.FailedPrecondition, "job already finished")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusConflict},
		{"an unknown job is 404",
			&orchestratorTestServer{cancelErr: status.Error(codes.NotFound, "no job j1")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusNotFound},
		{"an unauthenticated caller of the orchestrator is 401",
			&orchestratorTestServer{cancelErr: status.Error(codes.Unauthenticated, "orchestrator token expired")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusUnauthorized},
		{"a forbidden cancel is 403",
			&orchestratorTestServer{cancelErr: status.Error(codes.PermissionDenied, "not your job")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusForbidden},
		{"an invalid request is 400",
			&orchestratorTestServer{cancelErr: status.Error(codes.InvalidArgument, "orchestrator: job_id is required")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusBadRequest},
		{"an unavailable orchestrator is 503",
			&orchestratorTestServer{cancelErr: status.Error(codes.Unavailable, "fleet unreachable")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusServiceUnavailable},
		{"an internal failure is 500",
			&orchestratorTestServer{cancelErr: status.Error(codes.Internal, "boom")},
			http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", http.StatusInternalServerError},
		{"a page limit that is not an int32 is 400", &orchestratorTestServer{},
			http.MethodGet, "/api/v1/orchestrator/tenants/acme/jobs?page.limit=4294967296", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serveOrchestrator(orchestratorRouter(tt.server), tt.method, tt.target)
			if rec.Code != tt.want {
				t.Fatalf("status = %d (%s), want %d", rec.Code, rec.Body, tt.want)
			}
		})
	}
}

// orchestratorRecordingServer serves every orchestrator RPC: it records the
// request it was given and answers an empty response, or err.
type orchestratorRecordingServer struct {
	platformv1.UnimplementedOrchestratorServiceServer

	got proto.Message
	err error
}

func orchestratorAnswer[T proto.Message](s *orchestratorRecordingServer, req proto.Message, resp T) (T, error) {
	s.got = req
	if s.err != nil {
		var none T
		return none, s.err
	}
	return resp, nil
}

func (s *orchestratorRecordingServer) Health(_ context.Context, req *platformv1.OrchestratorHealthRequest) (*platformv1.OrchestratorHealthResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.OrchestratorHealthResponse{})
}

func (s *orchestratorRecordingServer) ListAgents(_ context.Context, req *platformv1.ListOrchestratorAgentsRequest) (*platformv1.ListOrchestratorAgentsResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.ListOrchestratorAgentsResponse{})
}

func (s *orchestratorRecordingServer) GetAgent(_ context.Context, req *platformv1.GetOrchestratorAgentRequest) (*platformv1.GetOrchestratorAgentResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.GetOrchestratorAgentResponse{})
}

func (s *orchestratorRecordingServer) DisableAgent(_ context.Context, req *platformv1.DisableOrchestratorAgentRequest) (*platformv1.DisableOrchestratorAgentResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.DisableOrchestratorAgentResponse{})
}

func (s *orchestratorRecordingServer) EnableAgent(_ context.Context, req *platformv1.EnableOrchestratorAgentRequest) (*platformv1.EnableOrchestratorAgentResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.EnableOrchestratorAgentResponse{})
}

func (s *orchestratorRecordingServer) ListSessions(_ context.Context, req *platformv1.ListOrchestratorSessionsRequest) (*platformv1.ListOrchestratorSessionsResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.ListOrchestratorSessionsResponse{})
}

func (s *orchestratorRecordingServer) CloseSession(_ context.Context, req *platformv1.CloseOrchestratorSessionRequest) (*platformv1.CloseOrchestratorSessionResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.CloseOrchestratorSessionResponse{})
}

func (s *orchestratorRecordingServer) ListJobs(_ context.Context, req *platformv1.ListOrchestratorJobsRequest) (*platformv1.ListOrchestratorJobsResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.ListOrchestratorJobsResponse{})
}

func (s *orchestratorRecordingServer) GetJob(_ context.Context, req *platformv1.GetOrchestratorJobRequest) (*platformv1.GetOrchestratorJobResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.GetOrchestratorJobResponse{})
}

func (s *orchestratorRecordingServer) CancelJob(_ context.Context, req *platformv1.CancelOrchestratorJobRequest) (*platformv1.CancelOrchestratorJobResponse, error) {
	return orchestratorAnswer(s, req, &platformv1.CancelOrchestratorJobResponse{})
}

// orchestratorRouteCalls is every orchestrator route, called by a\n// system-tenant caller for tenant acme, with the RPC request it must bind from the path.
var orchestratorRouteCalls = []struct {
	method string
	target string
	want   proto.Message
}{
	{http.MethodGet, "/api/v1/orchestrator/health", &platformv1.OrchestratorHealthRequest{}},
	{http.MethodGet, "/api/v1/orchestrator/tenants/acme/agents", &platformv1.ListOrchestratorAgentsRequest{TenantId: "acme"}},
	{http.MethodGet, "/api/v1/orchestrator/tenants/acme/agents/a1", &platformv1.GetOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}},
	{http.MethodPost, "/api/v1/orchestrator/tenants/acme/agents/a1/disable", &platformv1.DisableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}},
	{http.MethodPost, "/api/v1/orchestrator/tenants/acme/agents/a1/enable", &platformv1.EnableOrchestratorAgentRequest{TenantId: "acme", AgentId: "a1"}},
	{http.MethodGet, "/api/v1/orchestrator/sessions", &platformv1.ListOrchestratorSessionsRequest{}},
	{http.MethodDelete, "/api/v1/orchestrator/sessions/s1", &platformv1.CloseOrchestratorSessionRequest{SessionId: "s1"}},
	{http.MethodGet, "/api/v1/orchestrator/tenants/acme/jobs", &platformv1.ListOrchestratorJobsRequest{TenantId: "acme"}},
	{http.MethodGet, "/api/v1/orchestrator/tenants/acme/jobs/j1", &platformv1.GetOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}},
	{http.MethodPost, "/api/v1/orchestrator/tenants/acme/jobs/j1/cancel", &platformv1.CancelOrchestratorJobRequest{TenantId: "acme", JobId: "j1"}},
}

func TestOrchestratorEveryRouteServesItsRPC(t *testing.T) {
	for _, call := range orchestratorRouteCalls {
		t.Run(call.method+" "+call.target, func(t *testing.T) {
			server := &orchestratorRecordingServer{}
			rec := serveOrchestrator(systemOrchestratorRouter(server), call.method, call.target)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body)
			}
			if !proto.Equal(server.got, call.want) {
				t.Fatalf("RPC request = %v, want %v", server.got, call.want)
			}
		})
	}
}

func TestOrchestratorEveryRouteMapsTheServiceError(t *testing.T) {
	for _, call := range orchestratorRouteCalls {
		t.Run(call.method+" "+call.target, func(t *testing.T) {
			server := &orchestratorRecordingServer{err: status.Error(codes.NotFound, "no such orchestrator object")}
			rec := serveOrchestrator(systemOrchestratorRouter(server), call.method, call.target)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d (%s), want 404", rec.Code, rec.Body)
			}
		})
	}
}

func TestOrchestratorTenantRoutesOwnTenantOrSystem(t *testing.T) {
	for _, call := range orchestratorRouteCalls {
		if !strings.Contains(call.target, "/tenants/acme/") {
			continue
		}
		t.Run(call.method+" "+call.target, func(t *testing.T) {
			other := &orchestratorRecordingServer{}
			rec := serveOrchestrator(orchestratorRouter(other), call.method,
				strings.Replace(call.target, "/tenants/acme/", "/tenants/globex/", 1))
			if rec.Code != http.StatusForbidden || other.got != nil {
				t.Fatalf("another tenant: status = %d, RPC called = %v; want 403 before the RPC", rec.Code, other.got != nil)
			}

			system := &orchestratorRecordingServer{}
			router := mux.NewRouter()
			guard := NewScopeGuard(tenantOperatorAuthorizer{tenantID: "system"}, nil, nil)
			NewOrchestratorHandlers(system, guard, "system", nil).RegisterRoutes(router)
			if rec := serveOrchestrator(router, call.method, call.target); rec.Code != http.StatusOK {
				t.Fatalf("system tenant: status = %d (%s), want 200", rec.Code, rec.Body)
			}
		})
	}
}
