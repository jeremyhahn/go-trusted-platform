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

package sdn

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

const (
	basePath = "/sdn"
)

// SDNRouter provides REST routing for SDN operations
type SDNRouter struct {
	handlers *SDNHandlers
	// scopeAuthorizer is the per-route scope check the delete routes take
	// on top of the admin gate; nil leaves them on the gate.
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// SetScopeAuthorizer supplies the scope check the policy and VLAN delete
// routes take on top of the admin gate. Nil leaves them on the role gate.
func (r *SDNRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps handler in the scope check of the gRPC method when an
// authorizer is set. A method with no scope fails closed.
func (r *SDNRouter) requireScope(rpc string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	scope := grpcapi.ScopeForMethod(rpc)
	if scope == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// NewSDNRouter creates a new SDNRouter instance
func NewSDNRouter(
	logger *logging.Logger,
	sdnService platformv1.SDNServiceServer,
	respWriter response.HttpWriter,
) *SDNRouter {
	return &SDNRouter{
		handlers: NewSDNHandlers(logger, sdnService, respWriter),
	}
}

// RegisterRoutes registers all SDN REST routes on the provided router
func (r *SDNRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for SDN endpoints
	sdnRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerBridgeRoutes(sdnRouter)
	r.registerPortRoutes(sdnRouter)
	r.registerFlowRoutes(sdnRouter)
	r.registerPolicyRoutes(sdnRouter)
	r.registerVLANRoutes(sdnRouter)
	r.registerZoneRoutes(sdnRouter)
}

// registerBridgeRoutes registers bridge management endpoints
// POST   /api/v1/sdn/bridges           - Create bridge
// GET    /api/v1/sdn/bridges           - List bridges
// GET    /api/v1/sdn/bridges/{name}    - Get bridge
// DELETE /api/v1/sdn/bridges/{name}    - Delete bridge
func (r *SDNRouter) registerBridgeRoutes(router *mux.Router) {
	// Bridge collection routes
	router.HandleFunc("/bridges", r.handlers.CreateBridge).Methods("POST")
	router.HandleFunc("/bridges", r.handlers.ListBridges).Methods("GET")

	// Bridge instance routes
	router.HandleFunc("/bridges/{name}", r.handlers.GetBridge).Methods("GET")
	router.HandleFunc("/bridges/{name}", r.handlers.DeleteBridge).Methods("DELETE")
}

// registerPortRoutes registers port management endpoints
// POST   /api/v1/sdn/bridges/{name}/ports                    - Add port
// DELETE /api/v1/sdn/bridges/{name}/ports/{port}             - Delete port
// GET    /api/v1/sdn/bridges/{name}/ports/{port}/state       - Get port state
// PUT    /api/v1/sdn/bridges/{name}/ports/{port}/state       - Set port state
// GET    /api/v1/sdn/bridges/{name}/ports/{port}/stats       - Get port statistics
// POST   /api/v1/sdn/bridges/{name}/ports/{port}/auth        - Authenticate port
// DELETE /api/v1/sdn/bridges/{name}/ports/{port}/auth        - Revoke port authentication
func (r *SDNRouter) registerPortRoutes(router *mux.Router) {
	// Port management routes
	router.HandleFunc("/bridges/{name}/ports", r.handlers.AddPort).Methods("POST")
	router.HandleFunc("/bridges/{name}/ports", r.handlers.ListPorts).Methods("GET")
	router.HandleFunc("/bridges/{name}/ports/{port}", r.handlers.DeletePort).Methods("DELETE")

	// Port state routes
	router.HandleFunc("/bridges/{name}/ports/{port}/state", r.handlers.GetPortState).Methods("GET")
	router.HandleFunc("/bridges/{name}/ports/{port}/state", r.handlers.SetPortState).Methods("PUT")

	// Port statistics routes
	router.HandleFunc("/bridges/{name}/ports/{port}/stats", r.handlers.GetPortStats).Methods("GET")

	// Port authentication routes
	router.HandleFunc("/bridges/{name}/ports/{port}/auth", r.handlers.AuthenticatePort).Methods("POST")
	router.HandleFunc("/bridges/{name}/ports/{port}/auth", r.handlers.RevokePortAuth).Methods("DELETE")
}

// registerFlowRoutes registers flow management endpoints
// POST   /api/v1/sdn/flows             - Add flow
// DELETE /api/v1/sdn/flows             - Delete flow
// GET    /api/v1/sdn/flows             - List flows (query param: bridge_id)
func (r *SDNRouter) registerFlowRoutes(router *mux.Router) {
	router.HandleFunc("/flows", r.handlers.AddFlow).Methods("POST")
	router.HandleFunc("/flows", r.handlers.DeleteFlow).Methods("DELETE")
	router.HandleFunc("/flows", r.handlers.ListFlows).Methods("GET")
	// Nested aliases so the SDK can use a bridge-scoped URL.
	router.HandleFunc("/bridges/{name}/flows", r.handlers.AddFlow).Methods("POST")
	router.HandleFunc("/bridges/{name}/flows", r.handlers.ListFlows).Methods("GET")
}

// registerPolicyRoutes registers policy management endpoints
// POST   /api/v1/sdn/policies          - Apply policy
// GET    /api/v1/sdn/policies          - List policies
// GET    /api/v1/sdn/policies/{id}     - Get policy
// DELETE /api/v1/sdn/policies/{id}     - Delete policy
func (r *SDNRouter) registerPolicyRoutes(router *mux.Router) {
	router.HandleFunc("/policies", r.handlers.ApplyPolicy).Methods("POST")
	router.HandleFunc("/policies", r.handlers.ListPolicies).Methods("GET")
	router.HandleFunc("/policies/{id}", r.handlers.GetPolicy).Methods("GET")
	router.Handle("/policies/{id}", r.requireScope("/platform.v1.SDNService/DeletePolicy", r.handlers.DeletePolicy)).Methods("DELETE")
}

// registerVLANRoutes registers VLAN management endpoints.
//
// Both flat (?bridge_id=…) and nested (/bridges/{bridge_id}/vlans)
// shapes are supported so the SDK and direct callers can use whichever
// is more ergonomic.
//
//	POST   /api/v1/sdn/vlans                              - Create VLAN
//	GET    /api/v1/sdn/vlans?bridge_id=…                  - List VLANs
//	DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id=…        - Delete VLAN
//	POST   /api/v1/sdn/bridges/{bridge_id}/vlans          - Create VLAN
//	GET    /api/v1/sdn/bridges/{bridge_id}/vlans          - List VLANs
//	GET    /api/v1/sdn/bridges/{bridge_id}/vlans/{vlan_id} - Get VLAN
func (r *SDNRouter) registerVLANRoutes(router *mux.Router) {
	router.HandleFunc("/vlans", r.handlers.CreateVLAN).Methods("POST")
	router.HandleFunc("/vlans", r.handlers.ListVLANs).Methods("GET")
	router.Handle("/vlans/{vlan_id}", r.requireScope("/platform.v1.SDNService/DeleteVLAN", r.handlers.DeleteVLAN)).Methods("DELETE")
	router.HandleFunc("/bridges/{bridge_id}/vlans", r.handlers.CreateVLAN).Methods("POST")
	router.HandleFunc("/bridges/{bridge_id}/vlans", r.handlers.ListVLANs).Methods("GET")
}
