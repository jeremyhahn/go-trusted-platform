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
	"github.com/gorilla/mux"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/tenants"

// TenantRouter wires REST endpoints onto a TenantServiceServer.
type TenantRouter struct {
	handlers *Handlers
	authz    Authorization
	router.WebServiceRouter
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
	// listing every tenant, creating one, syncing, and looking one up by
	// name. A tenant administrator holds "admin" inside their own tenant and
	// must not enumerate or create tenants with it, exactly as #159 decided
	// for /api/v1/iam/tenants.
	RequireSystemTenant func(http.Handler) http.Handler
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
	return &TenantRouter{
		handlers: NewHandlers(logger, server, respWriter),
		authz:    authz,
	}, nil
}

// tenantScoped wraps a handler whose target tenant comes from {id}.
func (r *TenantRouter) tenantScoped(h http.HandlerFunc) http.Handler {
	return r.authz.RequireOwnTenantOrSystem(h)
}

// systemOnly wraps a handler that acts across tenants.
func (r *TenantRouter) systemOnly(h http.HandlerFunc) http.Handler {
	return r.authz.RequireSystemTenant(h)
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
//	POST   /api/v1/tenants/{id}/vlan/validate       - ValidateVLAN
//	GET    /api/v1/tenants/{id}/bridge              - GetBridgeName
//	POST   /api/v1/tenants/sync                     - Sync
//	POST   /api/v1/tenants/{id}/dek/rotate          - RotateTenantDEK
//	GET    /api/v1/tenants/{id}/dek                 - GetTenantDEKStatus
//	POST   /api/v1/tenants/{id}/barrier/init        - InitTenantBarrier
//	POST   /api/v1/tenants/{id}/barrier/unseal      - UnsealTenantBarrier
//	POST   /api/v1/tenants/{id}/barrier/seal        - SealTenantBarrier
//	GET    /api/v1/tenants/{id}/barrier             - GetTenantBarrierStatus
func (r *TenantRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	// Cross-tenant control-plane operations.
	sr.Handle("", r.systemOnly(r.handlers.ListTenants)).Methods("GET")
	sr.Handle("", r.systemOnly(r.handlers.CreateTenant)).Methods("POST")
	sr.Handle("/sync", r.systemOnly(r.handlers.Sync)).Methods("POST")
	// by-name is a DISCOVERY lookup across tenants, and it could not take the
	// {id} guard even in principle: tenant ids are UUIDs
	// (pkg/tenant/manager.go generates uuid.New()), so comparing the NAME in
	// the path against the session's tenant id would deny every caller,
	// including a tenant looking up its own.
	sr.Handle("/by-name/{name}", r.systemOnly(r.handlers.GetTenantByName)).Methods("GET")
	sr.Handle("/{id}", r.tenantScoped(r.handlers.GetTenant)).Methods("GET")
	sr.Handle("/{id}", r.tenantScoped(r.handlers.UpdateTenant)).Methods("PUT")
	sr.Handle("/{id}", r.tenantScoped(r.handlers.DeleteTenant)).Methods("DELETE")
	sr.Handle("/{id}/suspend", r.tenantScoped(r.handlers.SuspendTenant)).Methods("POST")
	sr.Handle("/{id}/resume", r.tenantScoped(r.handlers.ResumeTenant)).Methods("POST")
	sr.Handle("/{id}/quotas", r.tenantScoped(r.handlers.GetQuotas)).Methods("GET")
	sr.Handle("/{id}/quotas", r.tenantScoped(r.handlers.UpdateQuotas)).Methods("PUT")
	sr.Handle("/{id}/usage", r.tenantScoped(r.handlers.GetUsage)).Methods("GET")
	sr.Handle("/{id}/quota-check", r.tenantScoped(r.handlers.CheckQuota)).Methods("POST")
	sr.Handle("/{id}/vlan/validate", r.tenantScoped(r.handlers.ValidateVLAN)).Methods("POST")
	sr.Handle("/{id}/bridge", r.tenantScoped(r.handlers.GetBridgeName)).Methods("GET")
	sr.Handle("/{id}/dek/rotate", r.tenantScoped(r.handlers.RotateTenantDEK)).Methods("POST")
	sr.Handle("/{id}/dek", r.tenantScoped(r.handlers.GetTenantDEKStatus)).Methods("GET")
	sr.Handle("/{id}/barrier/init", r.tenantScoped(r.handlers.InitBarrier)).Methods("POST")
	sr.Handle("/{id}/barrier/unseal", r.tenantScoped(r.handlers.UnsealBarrier)).Methods("POST")
	sr.Handle("/{id}/barrier/seal", r.tenantScoped(r.handlers.SealBarrier)).Methods("POST")
	sr.Handle("/{id}/barrier", r.tenantScoped(r.handlers.GetBarrierStatus)).Methods("GET")
}
