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

// Package tenant implements REST endpoints under /api/v1/tenants. Handlers
// delegate to the in-process platformv1.TenantServiceServer.
package tenant

import (
	"net/http"

	"github.com/gorilla/mux"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/tenants"

// TenantRouter wires REST endpoints onto a TenantServiceServer.
type TenantRouter struct {
	handlers *Handlers
	authz    Authorization
	server   platformv1.TenantServiceServer
	// dark and record mount an operation whose backend the daemon did not
	// configure: dark answers it, record lists its routes as not
	// configured. Both nil mounts every route live.
	dark   func(name string) http.Handler
	record func(name string, routes ...*mux.Route)
	// scopeAuthorizer, when set, makes every route take its TenantService
	// RPC's catalog scope; nil leaves the role gate alone (legacy JWT).
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// Capability names for the tenant operations that need a backend beyond
// IAM. A route mounted dark lists as "not-configured: <name>".
const (
	FeatureTenantBarrier = "tenant-barrier"
	FeatureTenantDEK     = "tenant-dek"
)

// Features is implemented by a tenant server that can say which backends
// the daemon wired into it. A server without it keeps every route live.
type Features interface {
	BarrierConfigured() bool
	DEKConfigured() bool
}

// SetUnavailable gives the router the handler that answers an operation
// whose backend is not configured, and the hook that records its routes
// for the capability listing. Call it before RegisterRoutes.
func (r *TenantRouter) SetUnavailable(
	dark func(name string) http.Handler,
	record func(name string, routes ...*mux.Route),
) {
	r.dark = dark
	r.record = record
}

// configured reports whether the server says the named backend is wired.
// Without Features or without the unavailable hooks every route is live.
func (r *TenantRouter) configured(name string) bool {
	features, ok := r.server.(Features)
	if !ok || r.dark == nil {
		return true
	}
	switch name {
	case FeatureTenantBarrier:
		return features.BarrierConfigured()
	case FeatureTenantDEK:
		return features.DEKConfigured()
	}
	return true
}

// tenantServicePrefix is the gRPC full-method prefix the REST routes look
// their scope up under.
const tenantServicePrefix = "/platform.v1.TenantService/"

// scopedTenantRoute is one REST route: its TenantService RPC (whose catalog scope
// it takes), the tenant guard, the handler, and the backend feature it needs
// beyond IAM ("" for none).
type scopedTenantRoute struct {
	method  string
	path    string
	rpc     string
	guard   func(http.HandlerFunc) http.Handler
	handler http.HandlerFunc
	feature string
}

// SetScopeAuthorizer makes every route take its RPC's catalog scope before
// dispatch, as gRPC does. Without one the admin role gate alone applies.
func (r *TenantRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps h in the scope check for rpc. An rpc with no catalog
// scope fails closed.
func (r *TenantRouter) requireScope(rpc string, h http.Handler) http.Handler {
	if r.scopeAuthorizer == nil {
		return h
	}
	scope := grpcapi.ScopeForMethod(tenantServicePrefix + rpc)
	if scope == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}
	return r.scopeAuthorizer.RequireScope(scope)(h)
}

// mountFeature mounts routes live when the named backend is configured,
// otherwise behind the dark handler, recording them as not configured.
func (r *TenantRouter) mountFeature(sr *mux.Router, name string, routes []scopedTenantRoute) {
	if r.configured(name) {
		for _, fr := range routes {
			sr.Handle(fr.path, r.requireScope(fr.rpc, fr.guard(fr.handler))).Methods(fr.method)
		}
		return
	}
	dark := r.dark(name)
	mounted := make([]*mux.Route, 0, len(routes))
	for _, fr := range routes {
		mounted = append(mounted,
			sr.Handle(fr.path, r.requireScope(fr.rpc, fr.guard(dark.ServeHTTP))).Methods(fr.method))
	}
	if r.record != nil {
		r.record(name, mounted...)
	}
}

// Authorization carries the two guards this router mounts, neither of which
// the admin role can express (#234).
//
// Every route under /{id} takes its target tenant from the URL, so the
// "admin" gate #165 put in front of this router says only that the CALLER is
// an administrator — not that they administer the tenant they named.
type Authorization struct {
	// RequireOwnTenantOrSystem gates every route whose target tenant comes
	// from the {id} path variable: admitted for the caller's own tenant, or
	// for the system tenant acting as the control plane.
	//
	// Neither existing guard expresses that disjunction, and each is wrong
	// alone: RequireOwnTenant would deny the system admin that platformctl
	// drives this surface as, and RequireTenant(system) would deny a tenant
	// reading itself, which docs/auth/architecture.md §6c says this surface
	// is for.
	RequireOwnTenantOrSystem func(http.Handler) http.Handler

	// RequireSystemTenant gates the routes that are inherently cross-tenant —
	// listing every tenant, creating one, and syncing. A tenant
	// administrator holds "admin" inside their own tenant and must not
	// enumerate or create tenants with it, exactly as #159 decided for
	// /api/v1/iam/tenants.
	RequireSystemTenant func(http.Handler) http.Handler

	// RequireOwnTenantNameOrSystem gates the lookup by name: admitted for
	// the caller's own tenant's name, or for the system tenant resolving
	// any. It applies tenant.AuthorizeNameLookup, the rule gRPC, QUIC, MCP
	// and Unix apply, to the session's tenant claim (#304).
	RequireOwnTenantNameOrSystem func(http.Handler) http.Handler
}

// NewTenantRouter constructs a tenant REST router.
// It fails closed: without a complete Authorization the router is not built,
// and the caller must then leave the routes unregistered. An unreachable
// tenancy surface is a fault; one where any administrator can act on any
// tenant by changing a path segment is a breach (#234).
func NewTenantRouter(
	logger *logging.Logger,
	server platformv1.TenantServiceServer,
	respWriter response.HttpWriter,
	authz Authorization,
) (*TenantRouter, error) {

	if authz.RequireOwnTenantOrSystem == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireOwnTenantOrSystem"}
	}
	if authz.RequireSystemTenant == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireSystemTenant"}
	}
	if authz.RequireOwnTenantNameOrSystem == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireOwnTenantNameOrSystem"}
	}
	return &TenantRouter{
		handlers: NewHandlers(logger, server, respWriter),
		authz:    authz,
		server:   server,
	}, nil
}

// NameResolver returns the resolver RequireOwnTenantNameOrSystem needs: the
// id of the tenant the request's {name} names, or "" when the lookup fails.
// A failed lookup is not an error the caller sees here — the guard refuses
// it exactly like another tenant's name, so only the system tenant learns
// that a name does not exist.
func NameResolver(server platformv1.TenantServiceServer) func(*http.Request) string {
	return func(r *http.Request) string {
		resp, err := server.GetTenantByName(r.Context(),
			&platformv1.GetTenantByNameRequest{Name: mux.Vars(r)["name"]})
		if err != nil {
			return ""
		}
		return resp.GetTenant().GetId()
	}
}

// tenantScoped wraps a handler whose target tenant comes from {id}.
func (r *TenantRouter) tenantScoped(h http.HandlerFunc) http.Handler {
	return r.authz.RequireOwnTenantOrSystem(h)
}

// systemOnly wraps a handler that acts across tenants.
func (r *TenantRouter) systemOnly(h http.HandlerFunc) http.Handler {
	return r.authz.RequireSystemTenant(h)
}

// ownNameOrSystem wraps a handler whose target tenant comes from {name}.
func (r *TenantRouter) ownNameOrSystem(h http.HandlerFunc) http.Handler {
	return r.authz.RequireOwnTenantNameOrSystem(h)
}

// RegisterRoutes mounts tenant routes on the parent router.
//
//	GET    /api/v1/tenants                          - ListTenants
//	POST   /api/v1/tenants                          - CreateTenant
//	GET    /api/v1/tenants/{id}                     - GetTenant
//	PUT    /api/v1/tenants/{id}                     - UpdateTenant
//	DELETE /api/v1/tenants/{id}                     - DeleteTenant
//	GET    /api/v1/tenants/by-name/{name}           - GetTenantByName
//	POST   /api/v1/tenants/{id}/suspend             - SuspendTenant
//	POST   /api/v1/tenants/{id}/resume              - ResumeTenant
//	GET    /api/v1/tenants/{id}/quotas              - GetQuotas
//	PUT    /api/v1/tenants/{id}/quotas              - UpdateQuotas
//	GET    /api/v1/tenants/{id}/usage               - GetUsage
//	POST   /api/v1/tenants/{id}/quota-check         - CheckQuota
//	POST   /api/v1/tenants/sync                     - Sync
//	POST   /api/v1/tenants/{id}/dek/rotate          - RotateTenantDEK
//	GET    /api/v1/tenants/{id}/dek                 - GetTenantDEKStatus
//	POST   /api/v1/tenants/{id}/barrier/init        - InitTenantBarrier
//	POST   /api/v1/tenants/{id}/barrier/unseal      - UnsealTenantBarrier
//	POST   /api/v1/tenants/{id}/barrier/seal        - SealTenantBarrier
//	GET    /api/v1/tenants/{id}/barrier             - GetTenantBarrierStatus
func (r *TenantRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	features := map[string][]scopedTenantRoute{}
	var order []string
	for _, route := range r.routeTable() {
		if route.feature == "" {
			sr.Handle(route.path, r.requireScope(route.rpc, route.guard(route.handler))).Methods(route.method)
			continue
		}
		if _, seen := features[route.feature]; !seen {
			order = append(order, route.feature)
		}
		features[route.feature] = append(features[route.feature], route)
	}
	for _, name := range order {
		r.mountFeature(sr, name, features[name])
	}
}

// routeTable is every tenant route in mount order, each with the
// TenantService RPC whose scope it takes.
func (r *TenantRouter) routeTable() []scopedTenantRoute {
	h := r.handlers
	return []scopedTenantRoute{
		// Cross-tenant control-plane operations.
		{"GET", "", "ListTenants", r.systemOnly, h.ListTenants, ""},
		{"POST", "", "CreateTenant", r.systemOnly, h.CreateTenant, ""},
		{"POST", "/sync", "Sync", r.systemOnly, h.Sync, ""},
		// by-name cannot take the {id} guard: tenant ids are UUIDs
		// (pkg/tenant/manager.go generates uuid.New()), so the NAME in the path
		// never equals the session's tenant id. Its guard resolves the name and
		// applies tenant.AuthorizeNameLookup to the session's tenant claim: a
		// tenant resolves its own name, the system tenant any, and a foreign
		// name is refused exactly like an unknown one.
		{"GET", "/by-name/{name}", "GetTenantByName", r.ownNameOrSystem, h.GetTenantByName, ""},
		{"GET", "/{id}", "GetTenant", r.tenantScoped, h.GetTenant, ""},
		{"PUT", "/{id}", "UpdateTenant", r.tenantScoped, h.UpdateTenant, ""},
		{"DELETE", "/{id}", "DeleteTenant", r.tenantScoped, h.DeleteTenant, ""},
		{"POST", "/{id}/suspend", "SuspendTenant", r.tenantScoped, h.SuspendTenant, ""},
		{"POST", "/{id}/resume", "ResumeTenant", r.tenantScoped, h.ResumeTenant, ""},
		{"GET", "/{id}/quotas", "GetQuotas", r.tenantScoped, h.GetQuotas, ""},
		{"PUT", "/{id}/quotas", "UpdateQuotas", r.tenantScoped, h.UpdateQuotas, ""},
		{"GET", "/{id}/usage", "GetUsage", r.tenantScoped, h.GetUsage, ""},
		{"POST", "/{id}/quota-check", "CheckQuota", r.tenantScoped, h.CheckQuota, ""},
		// The DEK and barrier operations need backends the IAM-only tenant
		// manager may not have; without one they answer not configured, and
		// the capability listing says so, rather than failing every call.
		{"POST", "/{id}/dek/rotate", "RotateTenantDEK", r.tenantScoped, h.RotateTenantDEK, FeatureTenantDEK},
		{"GET", "/{id}/dek", "GetTenantDEKStatus", r.tenantScoped, h.GetTenantDEKStatus, FeatureTenantDEK},
		{"POST", "/{id}/barrier/init", "InitTenantBarrier", r.tenantScoped, h.InitBarrier, FeatureTenantBarrier},
		{"POST", "/{id}/barrier/unseal", "UnsealTenantBarrier", r.tenantScoped, h.UnsealBarrier, FeatureTenantBarrier},
		{"POST", "/{id}/barrier/seal", "SealTenantBarrier", r.tenantScoped, h.SealBarrier, FeatureTenantBarrier},
		{"GET", "/{id}/barrier", "GetTenantBarrierStatus", r.tenantScoped, h.GetBarrierStatus, FeatureTenantBarrier},
	}
}
