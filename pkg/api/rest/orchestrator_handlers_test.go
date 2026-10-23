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
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

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
