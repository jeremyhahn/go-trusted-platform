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
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// orchestratorPath is the agent-fleet route prefix below the versioned API
// root; the routes are /api/v1/orchestrator/...
// (docs/orchestrator/api-reference-rest.md).
const orchestratorPath = "/orchestrator"

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

// CallerRouteGuard is a RouteGuard that can also hand a route the caller it
// authenticated, for a route whose decision depends on who is calling.
// *ScopeGuard is one; the webservice listener supplies its own.
type CallerRouteGuard interface {
	RouteGuard
	RequireCaller(scope string, next CallerHandlerFunc) http.HandlerFunc
}

// OrchestratorHandlers binds the agent-fleet REST routes to the in-process
// OrchestratorServiceServer that also backs gRPC, QUIC, MCP and the Unix
// socket. Both REST listeners mount the same handlers: the daemon REST
// server and the webservice.
type OrchestratorHandlers struct {
	protoResponder
	orchestrator   platformv1.OrchestratorServiceServer
	guard          CallerRouteGuard
	systemTenantID string
}

// NewOrchestratorHandlers creates the orchestrator REST handlers. A nil
// guard refuses every route with 403; a nil server answers every authorized
// route with 503. A job or agent in the wrong state for the request
// (FailedPrecondition) answers 409. A route naming a tenant serves only
// that tenant's callers and the system tenant, systemTenantID; any other
// caller is refused with 403.
func NewOrchestratorHandlers(orchestrator platformv1.OrchestratorServiceServer, guard CallerRouteGuard, systemTenantID string, logger *slog.Logger) *OrchestratorHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	if guard == nil {
		guard = (*ScopeGuard)(nil)
	}
	return &OrchestratorHandlers{
		protoResponder: protoResponder{
			logger:   logger,
			statuses: map[codes.Code]int{codes.FailedPrecondition: http.StatusConflict},
		},
		orchestrator:   orchestrator,
		guard:          guard,
		systemTenantID: systemTenantID,
	}
}

// orchestratorRoute is one row of the orchestrator route table. A route
// whose path names {tenant_id} is tenantScoped.
type orchestratorRoute struct {
	method       string
	path         string
	scope        string
	tenantScoped bool
	handler      http.HandlerFunc
}

// RegisterRoutes mounts every orchestrator route on a root router, under
// /api/v1, behind the scope it requires.
func (h *OrchestratorHandlers) RegisterRoutes(router *mux.Router) {
	h.registerUnder(router, appAPIRoot)
}

// RegisterVersionedRoutes mounts the same routes on a router already rooted
// at /api/v1, as the webservice listener's is.
func (h *OrchestratorHandlers) RegisterVersionedRoutes(router *mux.Router) {
	h.registerUnder(router, "")
}

func (h *OrchestratorHandlers) registerUnder(router *mux.Router, prefix string) {
	for _, route := range h.routes() {
		handler := h.guard.Require(route.scope, route.handler)
		if route.tenantScoped {
			handler = h.guard.RequireCaller(route.scope, h.ownTenantOrSystem(route.handler))
		}
		router.HandleFunc(prefix+orchestratorPath+route.path, handler).Methods(route.method)
	}
	h.logger.Info("Orchestrator REST routes registered")
}

// ownTenantOrSystem serves next only when the caller belongs to the tenant
// the path names, or is the system tenant (tenant.AuthorizeTenantAccess);
// any other caller, and one carrying no tenant, is refused with 403. The
// tenant the request reaches the service with is the path's: the body
// cannot override a path variable (decodeProtoParams binds it last).
func (h *OrchestratorHandlers) ownTenantOrSystem(next http.HandlerFunc) CallerHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		var callerTenant string
		if caller != nil {
			callerTenant = caller.TenantID
		}
		isSystem := tenant.IsSystemTenant(h.systemTenantID, callerTenant)
		if err := tenant.AuthorizeTenantAccess(callerTenant, isSystem, mux.Vars(r)["tenant_id"]); err != nil {
			h.writeError(w, http.StatusForbidden, err)
			return
		}
		next(w, r)
	}
}

// routes is the orchestrator route table. Path variables are named after
// the request field they set; list filters and paging travel in the query
// (?status=, ?statuses=a&statuses=b, ?page.limit=, ?page.offset=).
func (h *OrchestratorHandlers) routes() []orchestratorRoute {
	const agents = "/tenants/{tenant_id}/agents"
	const jobs = "/tenants/{tenant_id}/jobs"
	return []orchestratorRoute{
		{http.MethodGet, "/health", scopeOrchestratorRead, false, orchestratorRPC(h, platformv1.OrchestratorServiceServer.Health)},
		{http.MethodGet, agents, scopeOrchestratorRead, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListAgents)},
		{http.MethodGet, agents + "/{agent_id}", scopeOrchestratorRead, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.GetAgent)},
		{http.MethodPost, agents + "/{agent_id}/disable", scopeOrchestratorWrite, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.DisableAgent)},
		{http.MethodPost, agents + "/{agent_id}/enable", scopeOrchestratorWrite, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.EnableAgent)},
		{http.MethodGet, "/sessions", scopeOrchestratorRead, false, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListSessions)},
		{http.MethodDelete, "/sessions/{session_id}", scopeOrchestratorWrite, false, orchestratorRPC(h, platformv1.OrchestratorServiceServer.CloseSession)},
		{http.MethodGet, jobs, scopeOrchestratorRead, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.ListJobs)},
		{http.MethodGet, jobs + "/{job_id}", scopeOrchestratorRead, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.GetJob)},
		{http.MethodPost, jobs + "/{job_id}/cancel", scopeOrchestratorWrite, true, orchestratorRPC(h, platformv1.OrchestratorServiceServer.CancelJob)},
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
