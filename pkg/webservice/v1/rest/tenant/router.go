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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/tenants"

// TenantRouter wires REST endpoints onto a TenantServiceServer.
type TenantRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewTenantRouter constructs a tenant REST router.
func NewTenantRouter(
	logger *logging.Logger,
	server platformv1.TenantServiceServer,
	respWriter response.HttpWriter,
) *TenantRouter {
	return &TenantRouter{handlers: NewHandlers(logger, server, respWriter)}
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
	sr.HandleFunc("", r.handlers.ListTenants).Methods("GET")
	sr.HandleFunc("", r.handlers.CreateTenant).Methods("POST")
	sr.HandleFunc("/sync", r.handlers.Sync).Methods("POST")
	sr.HandleFunc("/by-name/{name}", r.handlers.GetTenantByName).Methods("GET")
	sr.HandleFunc("/{id}", r.handlers.GetTenant).Methods("GET")
	sr.HandleFunc("/{id}", r.handlers.UpdateTenant).Methods("PUT")
	sr.HandleFunc("/{id}", r.handlers.DeleteTenant).Methods("DELETE")
	sr.HandleFunc("/{id}/suspend", r.handlers.SuspendTenant).Methods("POST")
	sr.HandleFunc("/{id}/resume", r.handlers.ResumeTenant).Methods("POST")
	sr.HandleFunc("/{id}/quotas", r.handlers.GetQuotas).Methods("GET")
	sr.HandleFunc("/{id}/quotas", r.handlers.UpdateQuotas).Methods("PUT")
	sr.HandleFunc("/{id}/usage", r.handlers.GetUsage).Methods("GET")
	sr.HandleFunc("/{id}/quota-check", r.handlers.CheckQuota).Methods("POST")
	sr.HandleFunc("/{id}/vlan/validate", r.handlers.ValidateVLAN).Methods("POST")
	sr.HandleFunc("/{id}/bridge", r.handlers.GetBridgeName).Methods("GET")
	sr.HandleFunc("/{id}/dek/rotate", r.handlers.RotateTenantDEK).Methods("POST")
	sr.HandleFunc("/{id}/dek", r.handlers.GetTenantDEKStatus).Methods("GET")
	sr.HandleFunc("/{id}/barrier/init", r.handlers.InitBarrier).Methods("POST")
	sr.HandleFunc("/{id}/barrier/unseal", r.handlers.UnsealBarrier).Methods("POST")
	sr.HandleFunc("/{id}/barrier/seal", r.handlers.SealBarrier).Methods("POST")
	sr.HandleFunc("/{id}/barrier", r.handlers.GetBarrierStatus).Methods("GET")
}
