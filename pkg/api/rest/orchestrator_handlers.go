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

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// orchestratorBasePath is the REST prefix of the go-quicbaas agent-fleet
// routes (docs/orchestrator/api-reference-rest.md).
const orchestratorBasePath = "/api/v1/orchestrator"

// Orchestrator route scopes; they match the OrchestratorService entries in
// the gRPC method catalog (pkg/api/grpc/method_permissions.go).
const (
	scopeOrchestratorRead  = "orchestrator:read"
	scopeOrchestratorWrite = "orchestrator:write"
)

// ErrOrchestratorServiceNotAvailable is returned when the REST server has
// no OrchestratorService to delegate to.
type ErrOrchestratorServiceNotAvailable struct{}

// Error implements the error interface.
func (ErrOrchestratorServiceNotAvailable) Error() string {
	return "orchestrator service is not available"
}

// OrchestratorHandlers binds the agent-fleet REST routes to the in-process
// OrchestratorServiceServer that also backs gRPC, QUIC, MCP and the Unix
// socket.
type OrchestratorHandlers struct {
	protoResponder
	orchestrator platformv1.OrchestratorServiceServer
	guard        *ScopeGuard
}

// NewOrchestratorHandlers creates the orchestrator REST handlers. A nil
// guard refuses every route with 403; a nil server answers every authorized
// route with 503. A job or agent in the wrong state for the request
// (FailedPrecondition) answers 409.
func NewOrchestratorHandlers(orchestrator platformv1.OrchestratorServiceServer, guard *ScopeGuard, logger *slog.Logger) *OrchestratorHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &OrchestratorHandlers{
		protoResponder: protoResponder{
			logger:   logger,
			statuses: map[codes.Code]int{codes.FailedPrecondition: http.StatusConflict},
		},
		orchestrator: orchestrator,
		guard:        guard,
	}
}

// orchestratorRoute is one row of the orchestrator route table.
type orchestratorRoute struct {
	method  string
	path    string
	scope   string
	handler http.HandlerFunc
}

// RegisterRoutes mounts every orchestrator route behind the scope it
// requires.
func (h *OrchestratorHandlers) RegisterRoutes(router *mux.Router) {
	for _, route := range h.routes() {
		router.HandleFunc(orchestratorBasePath+route.path, h.guard.Require(route.scope, route.handler)).Methods(route.method)
	}
	h.logger.Info("Orchestrator REST routes registered")
}

// routes is the orchestrator route table. Path variables are named after
// the request field they set; list filters and paging travel in the query
// (?status=, ?statuses=a&statuses=b, ?page.limit=, ?page.offset=).
func (h *OrchestratorHandlers) routes() []orchestratorRoute {
	const agents = "/tenants/{tenant_id}/agents"
	const jobs = "/tenants/{tenant_id}/jobs"
	return []orchestratorRoute{
		{http.MethodGet, "/health", scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.Health)},
		{http.MethodGet, agents, scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListAgents)},
		{http.MethodGet, agents + "/{agent_id}", scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.GetAgent)},
		{http.MethodPost, agents + "/{agent_id}/disable", scopeOrchestratorWrite, orchestratorRPC(h, platformv1.OrchestratorServiceServer.DisableAgent)},
		{http.MethodPost, agents + "/{agent_id}/enable", scopeOrchestratorWrite, orchestratorRPC(h, platformv1.OrchestratorServiceServer.EnableAgent)},
		{http.MethodGet, "/sessions", scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListSessions)},
		{http.MethodDelete, "/sessions/{session_id}", scopeOrchestratorWrite, orchestratorRPC(h, platformv1.OrchestratorServiceServer.CloseSession)},
		{http.MethodGet, jobs, scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListJobs)},
		{http.MethodGet, jobs + "/{job_id}", scopeOrchestratorRead, orchestratorRPC(h, platformv1.OrchestratorServiceServer.GetJob)},
		{http.MethodPost, jobs + "/{job_id}/cancel", scopeOrchestratorWrite, orchestratorRPC(h, platformv1.OrchestratorServiceServer.CancelJob)},
	}
}

// orchestratorRPC adapts one OrchestratorService method to a route.
func orchestratorRPC[Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](h *OrchestratorHandlers, rpc func(platformv1.OrchestratorServiceServer, context.Context, PReq) (Resp, error)) http.HandlerFunc {
	return protoRPC(h.protoResponder, h.orchestratorService, rpc)
}

// orchestratorService returns the orchestrator service, or
// ErrOrchestratorServiceNotAvailable when none is configured.
func (h *OrchestratorHandlers) orchestratorService() (platformv1.OrchestratorServiceServer, error) {
	if h.orchestrator == nil {
		return nil, ErrOrchestratorServiceNotAvailable{}
	}
	return h.orchestrator, nil
}
