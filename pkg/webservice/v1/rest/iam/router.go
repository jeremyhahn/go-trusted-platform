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

package iam

import (
	"github.com/gorilla/mux"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const (
	basePath = "/api/v1/iam"
)

// IAMRouter provides REST routing for IAM operations
type IAMRouter struct {
	handlers *IAMHandlers
	router.WebServiceRouter
}

// NewIAMRouter creates a new IAMRouter instance
func NewIAMRouter(
	logger *logging.Logger,
	iamClient iampb.IAMServiceClient,
	pepClient iampb.PEPServiceClient,
	respWriter response.HttpWriter,
) *IAMRouter {
	return &IAMRouter{
		handlers: NewIAMHandlers(logger, iamClient, pepClient, respWriter),
	}
}

// RegisterRoutes registers all IAM REST routes on the provided router
func (r *IAMRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for IAM endpoints
	iamRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerTenantRoutes(iamRouter)
	r.registerUserRoutes(iamRouter)
	r.registerGroupRoutes(iamRouter)
	r.registerRoleRoutes(iamRouter)
	r.registerPolicyRoutes(iamRouter)
	r.registerAppRoutes(iamRouter)
}

// registerTenantRoutes registers tenant management endpoints
// POST   /api/v1/iam/tenants                - Create tenant
// GET    /api/v1/iam/tenants                - List tenants
// GET    /api/v1/iam/tenants/{tenant}       - Get tenant
// PUT    /api/v1/iam/tenants/{tenant}       - Update tenant
// DELETE /api/v1/iam/tenants/{tenant}       - Delete tenant
func (r *IAMRouter) registerTenantRoutes(router *mux.Router) {
	// Tenant collection routes
	router.HandleFunc("/tenants", r.handlers.CreateTenant).Methods("POST")
	router.HandleFunc("/tenants", r.handlers.ListTenants).Methods("GET")

	// Tenant instance routes
	router.HandleFunc("/tenants/{tenant}", r.handlers.GetTenant).Methods("GET")
	router.HandleFunc("/tenants/{tenant}", r.handlers.UpdateTenant).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}", r.handlers.DeleteTenant).Methods("DELETE")
}

// registerUserRoutes registers user management endpoints
// POST   /api/v1/iam/tenants/{tenant}/users                    - Create user
// GET    /api/v1/iam/tenants/{tenant}/users                    - List users
// GET    /api/v1/iam/tenants/{tenant}/users/{id}               - Get user
// PUT    /api/v1/iam/tenants/{tenant}/users/{id}               - Update user
// DELETE /api/v1/iam/tenants/{tenant}/users/{id}               - Delete user
// POST   /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}  - Assign role
// DELETE /api/v1/iam/tenants/{tenant}/users/{id}/roles/{role}  - Remove role
func (r *IAMRouter) registerUserRoutes(router *mux.Router) {
	// User collection routes
	router.HandleFunc("/tenants/{tenant}/users", r.handlers.CreateUser).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/users", r.handlers.ListUsers).Methods("GET")

	// User instance routes
	router.HandleFunc("/tenants/{tenant}/users/{id}", r.handlers.GetUser).Methods("GET")
	router.HandleFunc("/tenants/{tenant}/users/{id}", r.handlers.UpdateUser).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}/users/{id}", r.handlers.DeleteUser).Methods("DELETE")

	// User role management routes
	router.HandleFunc("/tenants/{tenant}/users/{id}/roles/{role}", r.handlers.AssignUserRole).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/users/{id}/roles/{role}", r.handlers.RevokeUserRole).Methods("DELETE")
}

// registerGroupRoutes registers group management endpoints
// POST   /api/v1/iam/tenants/{tenant}/groups                        - Create group
// GET    /api/v1/iam/tenants/{tenant}/groups                        - List groups
// GET    /api/v1/iam/tenants/{tenant}/groups/{id}                   - Get group
// PUT    /api/v1/iam/tenants/{tenant}/groups/{id}                   - Update group
// DELETE /api/v1/iam/tenants/{tenant}/groups/{id}                   - Delete group
// POST   /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}    - Add member
// DELETE /api/v1/iam/tenants/{tenant}/groups/{id}/members/{user}    - Remove member
func (r *IAMRouter) registerGroupRoutes(router *mux.Router) {
	// Group collection routes
	router.HandleFunc("/tenants/{tenant}/groups", r.handlers.CreateGroup).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/groups", r.handlers.ListGroups).Methods("GET")

	// Group instance routes
	router.HandleFunc("/tenants/{tenant}/groups/{id}", r.handlers.GetGroup).Methods("GET")
	router.HandleFunc("/tenants/{tenant}/groups/{id}", r.handlers.UpdateGroup).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}/groups/{id}", r.handlers.DeleteGroup).Methods("DELETE")

	// Group membership management routes
	router.HandleFunc("/tenants/{tenant}/groups/{id}/members/{user}", r.handlers.AddGroupMember).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/groups/{id}/members/{user}", r.handlers.RemoveGroupMember).Methods("DELETE")
}

// registerRoleRoutes registers role management endpoints
// POST   /api/v1/iam/tenants/{tenant}/roles           - Create role
// GET    /api/v1/iam/tenants/{tenant}/roles           - List roles
// GET    /api/v1/iam/tenants/{tenant}/roles/{id}      - Get role
// PUT    /api/v1/iam/tenants/{tenant}/roles/{id}      - Update role
// DELETE /api/v1/iam/tenants/{tenant}/roles/{id}      - Delete role
func (r *IAMRouter) registerRoleRoutes(router *mux.Router) {
	// Role collection routes
	router.HandleFunc("/tenants/{tenant}/roles", r.handlers.CreateRole).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/roles", r.handlers.ListRoles).Methods("GET")

	// Role instance routes
	router.HandleFunc("/tenants/{tenant}/roles/{id}", r.handlers.GetRole).Methods("GET")
	router.HandleFunc("/tenants/{tenant}/roles/{id}", r.handlers.UpdateRole).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}/roles/{id}", r.handlers.DeleteRole).Methods("DELETE")
}

// registerPolicyRoutes registers policy management endpoints
// POST   /api/v1/iam/tenants/{tenant}/policies              - Create policy
// GET    /api/v1/iam/tenants/{tenant}/policies              - List policies
// GET    /api/v1/iam/tenants/{tenant}/policies/{id}         - Get policy
// PUT    /api/v1/iam/tenants/{tenant}/policies/{id}         - Update policy
// DELETE /api/v1/iam/tenants/{tenant}/policies/{id}         - Delete policy
// POST   /api/v1/iam/tenants/{tenant}/policies/validate     - Validate policy
// POST   /api/v1/iam/tenants/{tenant}/policies/test         - Test policy
func (r *IAMRouter) registerPolicyRoutes(router *mux.Router) {
	// Policy special action routes (must be before {id} routes to avoid conflicts)
	router.HandleFunc("/tenants/{tenant}/policies/validate", r.handlers.ValidatePolicy).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/policies/test", r.handlers.TestPolicy).Methods("POST")

	// Policy collection routes
	router.HandleFunc("/tenants/{tenant}/policies", r.handlers.CreatePolicy).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/policies", r.handlers.ListPolicies).Methods("GET")

	// Policy instance routes
	router.HandleFunc("/tenants/{tenant}/policies/{id}", r.handlers.GetPolicy).Methods("GET")
	router.HandleFunc("/tenants/{tenant}/policies/{id}", r.handlers.UpdatePolicy).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}/policies/{id}", r.handlers.DeletePolicy).Methods("DELETE")
}

// registerAppRoutes registers application (OAuth client) management endpoints
// POST   /api/v1/iam/tenants/{tenant}/apps                  - Register app
// GET    /api/v1/iam/tenants/{tenant}/apps                  - List apps
// GET    /api/v1/iam/tenants/{tenant}/apps/{id}             - Get app
// PUT    /api/v1/iam/tenants/{tenant}/apps/{id}             - Update app
// DELETE /api/v1/iam/tenants/{tenant}/apps/{id}             - Delete app
// POST   /api/v1/iam/tenants/{tenant}/apps/{id}/rotate      - Rotate secret
func (r *IAMRouter) registerAppRoutes(router *mux.Router) {
	// App collection routes
	router.HandleFunc("/tenants/{tenant}/apps", r.handlers.RegisterApp).Methods("POST")
	router.HandleFunc("/tenants/{tenant}/apps", r.handlers.ListApps).Methods("GET")

	// App instance routes
	router.HandleFunc("/tenants/{tenant}/apps/{id}", r.handlers.GetApp).Methods("GET")
	router.HandleFunc("/tenants/{tenant}/apps/{id}", r.handlers.UpdateApp).Methods("PUT")
	router.HandleFunc("/tenants/{tenant}/apps/{id}", r.handlers.DeleteApp).Methods("DELETE")

	// App secret rotation route
	router.HandleFunc("/tenants/{tenant}/apps/{id}/rotate", r.handlers.RotateAppSecret).Methods("POST")
}
