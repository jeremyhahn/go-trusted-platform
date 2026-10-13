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
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const (
	basePath = "/iam"

	// tenantQueryParam is the query parameter a request on a flat route
	// uses to name its tenant, mirroring the tenant_id field the gRPC
	// request messages carry.
	tenantQueryParam = "tenant_id"
)

// RequestedTenant returns the tenant a request names: the URL's {tenant}
// variable on the tenant-scoped routes, otherwise the tenant_id query
// parameter. It is empty when the request names no tenant.
//
// It is the extractor the daemon hands to RequireOwnTenant, so a request
// naming a tenant other than the caller's is refused with 403 on either
// route form — exactly as gRPC refuses a foreign tenant_id with
// PermissionDenied — instead of being answered from the session's tenant.
func RequestedTenant(r *http.Request) string {
	if tenant := mux.Vars(r)["tenant"]; tenant != "" {
		return tenant
	}
	return r.URL.Query().Get(tenantQueryParam)
}

// Authorization carries the server-side guards the IAM router mounts. IAM
// is the platform's administration surface: every route under it reads or
// writes identity, role, policy or tenant state, so the whole subtree is
// gated rather than a hand-picked subset of verbs.
//
//   - Authenticate publishes the verified session. Mounted first on every
//     IAM route.
//   - RequireAdmin gates the whole subtree on the "admin" role.
//   - RequireSystemTenant additionally gates tenant provisioning, which
//     only the system tenant may drive (docs/08-bootstrap-auth-contract.md
//     §"Control plane vs data plane"): a tenant-scoped admin holds the same
//     "admin" role inside their own tenant and must not create or delete
//     tenants with it.
//   - RequireOwnTenant gates every route a request can name a tenant on:
//     the /tenants/{tenant}/... routes and the flat routes' tenant_id query
//     parameter (see RequestedTenant). The handlers give the path's
//     {tenant} precedence over the session's, so the admin role alone
//     would otherwise let a tenant administrator reach any other tenant's
//     users, groups, roles, policies or applications by naming it in the
//     path; on a flat route a foreign tenant_id would otherwise be answered
//     from the session's tenant.
//
// All four are required. NewIAMRouter refuses to build with any of them
// missing, and the caller must then leave the IAM routes unregistered —
// an unreachable admin surface is a fault, an ungated one is a breach.
type Authorization struct {
	Authenticate        func(http.Handler) http.Handler
	RequireAdmin        func(http.Handler) http.Handler
	RequireSystemTenant func(http.Handler) http.Handler
	RequireOwnTenant    func(http.Handler) http.Handler
}

// IAMRouter provides REST routing for IAM operations
type IAMRouter struct {
	handlers *IAMHandlers
	authz    Authorization
	router.WebServiceRouter
}

// NewIAMRouter creates a new IAMRouter instance. It fails closed: without
// a complete Authorization the router is not built at all, so no caller
// can accidentally publish the IAM surface unguarded.
func NewIAMRouter(
	logger *logging.Logger,
	iamClient IAMClient,
	pepClient PEPClient,
	respWriter response.HttpWriter,
	authz Authorization,
) (*IAMRouter, error) {

	if authz.Authenticate == nil {
		return nil, ErrAuthorizationRequired{Guard: "Authenticate"}
	}
	if authz.RequireAdmin == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireAdmin"}
	}
	if authz.RequireSystemTenant == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireSystemTenant"}
	}
	if authz.RequireOwnTenant == nil {
		return nil, ErrAuthorizationRequired{Guard: "RequireOwnTenant"}
	}
	return &IAMRouter{
		handlers: NewIAMHandlers(logger, iamClient, pepClient, respWriter),
		authz:    authz,
	}, nil
}

// RegisterRoutes registers all IAM REST routes on the provided router
func (r *IAMRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for IAM endpoints. Authentication and the admin
	// role gate the entire subtree — reading the tenant's users, roles,
	// policies or OAuth applications is administrative disclosure, so the
	// guards are not limited to the mutating verbs.
	iamRouter := router.PathPrefix(basePath).Subrouter()
	iamRouter.Use(r.authz.Authenticate, r.authz.RequireAdmin)

	// Register all route groups
	r.registerTenantRoutes(iamRouter)
	r.registerUserRoutes(iamRouter)
	r.registerGroupRoutes(iamRouter)
	r.registerRoleRoutes(iamRouter)
	r.registerPolicyRoutes(iamRouter)
	r.registerAppRoutes(iamRouter)

	// Flat (tenant-implicit) routes — convenience aliases that the
	// WebUI hits without carrying the tenant in the URL. The
	// handlers' `getTenantID` falls back to the session's tenant
	// when the URL doesn't contain {tenant}, so the same handler
	// body backs both forms; a tenant_id query naming another
	// tenant is refused by the own-tenant guard, and a request
	// body naming one by the handler (decodeTenantBody).
	r.registerFlatRoutes(iamRouter)
}

// registerFlatRoutes registers tenant-implicit aliases for the IAM
// collections. Used by the WebUI which sources the active tenant
// from the JWT rather than encoding it in every URL.
func (r *IAMRouter) registerFlatRoutes(router *mux.Router) {
	// Users
	router.Handle("/users", r.tenantScoped(r.handlers.CreateUser)).Methods("POST")
	router.Handle("/users", r.tenantScoped(r.handlers.ListUsers)).Methods("GET")
	router.Handle("/users/{id}", r.tenantScoped(r.handlers.GetUser)).Methods("GET")
	router.Handle("/users/{id}", r.tenantScoped(r.handlers.UpdateUser)).Methods("PUT")
	router.Handle("/users/{id}", r.tenantScoped(r.handlers.DeleteUser)).Methods("DELETE")
	router.Handle("/users/{id}/roles/{role}", r.tenantScoped(r.handlers.AssignUserRole)).Methods("POST")
	router.Handle("/users/{id}/roles/{role}", r.tenantScoped(r.handlers.RevokeUserRole)).Methods("DELETE")

	// Groups
	router.Handle("/groups", r.tenantScoped(r.handlers.CreateGroup)).Methods("POST")
	router.Handle("/groups", r.tenantScoped(r.handlers.ListGroups)).Methods("GET")
	router.Handle("/groups/{id}", r.tenantScoped(r.handlers.GetGroup)).Methods("GET")
	router.Handle("/groups/{id}", r.tenantScoped(r.handlers.UpdateGroup)).Methods("PUT")
	router.Handle("/groups/{id}", r.tenantScoped(r.handlers.DeleteGroup)).Methods("DELETE")
	router.Handle("/groups/{id}/members/{user}", r.tenantScoped(r.handlers.AddGroupMember)).Methods("POST")
	router.Handle("/groups/{id}/members/{user}", r.tenantScoped(r.handlers.RemoveGroupMember)).Methods("DELETE")

	// Roles
	router.Handle("/roles", r.tenantScoped(r.handlers.CreateRole)).Methods("POST")
	router.Handle("/roles", r.tenantScoped(r.handlers.ListRoles)).Methods("GET")
	router.Handle("/roles/{id}", r.tenantScoped(r.handlers.GetRole)).Methods("GET")
	router.Handle("/roles/{id}", r.tenantScoped(r.handlers.UpdateRole)).Methods("PUT")
	router.Handle("/roles/{id}", r.tenantScoped(r.handlers.DeleteRole)).Methods("DELETE")

	// Policies (special action routes registered before {id} to
	// avoid conflicts).
	router.Handle("/policies/validate", r.tenantScoped(r.handlers.ValidatePolicy)).Methods("POST")
	router.Handle("/policies/test", r.tenantScoped(r.handlers.TestPolicy)).Methods("POST")
	router.Handle("/policies", r.tenantScoped(r.handlers.CreatePolicy)).Methods("POST")
	router.Handle("/policies", r.tenantScoped(r.handlers.ListPolicies)).Methods("GET")
	router.Handle("/policies/{id}", r.tenantScoped(r.handlers.GetPolicy)).Methods("GET")
	router.Handle("/policies/{id}", r.tenantScoped(r.handlers.UpdatePolicy)).Methods("PUT")
	router.Handle("/policies/{id}", r.tenantScoped(r.handlers.DeletePolicy)).Methods("DELETE")

	// Applications
	router.Handle("/apps", r.tenantScoped(r.handlers.RegisterApp)).Methods("POST")
	router.Handle("/apps", r.tenantScoped(r.handlers.ListApps)).Methods("GET")
	router.Handle("/apps/{id}", r.tenantScoped(r.handlers.GetApp)).Methods("GET")
	router.Handle("/apps/{id}", r.tenantScoped(r.handlers.UpdateApp)).Methods("PUT")
	router.Handle("/apps/{id}", r.tenantScoped(r.handlers.DeleteApp)).Methods("DELETE")
	router.Handle("/apps/{id}/rotate", r.tenantScoped(r.handlers.RotateAppSecret)).Methods("POST")
}

// tenantScoped wraps a handler on which a request can name a tenant,
// requiring the named tenant to be the caller's own. Every
// /tenants/{tenant}/<collection> route needs it: the handlers give the
// path's tenant precedence over the session's, so the admin role alone
// would let a tenant administrator reach any other tenant by naming it.
// Every flat route needs it too: there a request names its tenant with the
// tenant_id query parameter, and a foreign one must be refused rather than
// silently answered from the session's tenant (#401).
//
// It is applied per route rather than on the subtree because the tenant
// RECORD routes (/tenants/{tenant}) share the same variable but are a
// control-plane surface the system tenant drives across tenants — they
// carry systemOnly instead. TestRegisterRoutes_EveryTenantScopedRouteIsGuarded
// keeps a newly added route from missing this.
func (r *IAMRouter) tenantScoped(h http.HandlerFunc) http.Handler {
	return r.authz.RequireOwnTenant(h)
}

// systemOnly wraps a handler in the system-tenant guard. It is applied per
// route rather than on a "/tenants" subrouter because the tenant-scoped
// user, group, role, policy and app routes share that same path prefix; a
// prefix subrouter would swallow them and answer 404.
func (r *IAMRouter) systemOnly(h http.HandlerFunc) http.Handler {
	return r.authz.RequireSystemTenant(h)
}

// registerTenantRoutes registers tenant management endpoints. The whole
// group is system-tenant-only: the control plane owns tenant records, and
// a tenant-scoped admin (who holds the same "admin" role inside their own
// tenant) must not be able to enumerate, create or delete tenants. A
// tenant admin reads their own tenant through /api/v1/tenants instead.
//
// POST   /api/v1/iam/tenants                - Create tenant
// GET    /api/v1/iam/tenants                - List tenants
// GET    /api/v1/iam/tenants/{tenant}       - Get tenant
// PUT    /api/v1/iam/tenants/{tenant}       - Update tenant
// DELETE /api/v1/iam/tenants/{tenant}       - Delete tenant
func (r *IAMRouter) registerTenantRoutes(router *mux.Router) {
	// Tenant collection routes
	router.Handle("/tenants", r.systemOnly(r.handlers.CreateTenant)).Methods("POST")
	router.Handle("/tenants", r.systemOnly(r.handlers.ListTenants)).Methods("GET")

	// Tenant instance routes
	router.Handle("/tenants/{tenant}", r.systemOnly(r.handlers.GetTenant)).Methods("GET")
	router.Handle("/tenants/{tenant}", r.systemOnly(r.handlers.UpdateTenant)).Methods("PUT")
	router.Handle("/tenants/{tenant}", r.systemOnly(r.handlers.DeleteTenant)).Methods("DELETE")
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
	router.Handle("/tenants/{tenant}/users", r.tenantScoped(r.handlers.CreateUser)).Methods("POST")
	router.Handle("/tenants/{tenant}/users", r.tenantScoped(r.handlers.ListUsers)).Methods("GET")

	// User instance routes
	router.Handle("/tenants/{tenant}/users/{id}", r.tenantScoped(r.handlers.GetUser)).Methods("GET")
	router.Handle("/tenants/{tenant}/users/{id}", r.tenantScoped(r.handlers.UpdateUser)).Methods("PUT")
	router.Handle("/tenants/{tenant}/users/{id}", r.tenantScoped(r.handlers.DeleteUser)).Methods("DELETE")

	// User role management routes
	router.Handle("/tenants/{tenant}/users/{id}/roles/{role}", r.tenantScoped(r.handlers.AssignUserRole)).Methods("POST")
	router.Handle("/tenants/{tenant}/users/{id}/roles/{role}", r.tenantScoped(r.handlers.RevokeUserRole)).Methods("DELETE")
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
	router.Handle("/tenants/{tenant}/groups", r.tenantScoped(r.handlers.CreateGroup)).Methods("POST")
	router.Handle("/tenants/{tenant}/groups", r.tenantScoped(r.handlers.ListGroups)).Methods("GET")

	// Group instance routes
	router.Handle("/tenants/{tenant}/groups/{id}", r.tenantScoped(r.handlers.GetGroup)).Methods("GET")
	router.Handle("/tenants/{tenant}/groups/{id}", r.tenantScoped(r.handlers.UpdateGroup)).Methods("PUT")
	router.Handle("/tenants/{tenant}/groups/{id}", r.tenantScoped(r.handlers.DeleteGroup)).Methods("DELETE")

	// Group membership management routes
	router.Handle("/tenants/{tenant}/groups/{id}/members/{user}", r.tenantScoped(r.handlers.AddGroupMember)).Methods("POST")
	router.Handle("/tenants/{tenant}/groups/{id}/members/{user}", r.tenantScoped(r.handlers.RemoveGroupMember)).Methods("DELETE")
}

// registerRoleRoutes registers role management endpoints
// POST   /api/v1/iam/tenants/{tenant}/roles           - Create role
// GET    /api/v1/iam/tenants/{tenant}/roles           - List roles
// GET    /api/v1/iam/tenants/{tenant}/roles/{id}      - Get role
// PUT    /api/v1/iam/tenants/{tenant}/roles/{id}      - Update role
// DELETE /api/v1/iam/tenants/{tenant}/roles/{id}      - Delete role
func (r *IAMRouter) registerRoleRoutes(router *mux.Router) {
	// Role collection routes
	router.Handle("/tenants/{tenant}/roles", r.tenantScoped(r.handlers.CreateRole)).Methods("POST")
	router.Handle("/tenants/{tenant}/roles", r.tenantScoped(r.handlers.ListRoles)).Methods("GET")

	// Role instance routes
	router.Handle("/tenants/{tenant}/roles/{id}", r.tenantScoped(r.handlers.GetRole)).Methods("GET")
	router.Handle("/tenants/{tenant}/roles/{id}", r.tenantScoped(r.handlers.UpdateRole)).Methods("PUT")
	router.Handle("/tenants/{tenant}/roles/{id}", r.tenantScoped(r.handlers.DeleteRole)).Methods("DELETE")
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
	router.Handle("/tenants/{tenant}/policies/validate", r.tenantScoped(r.handlers.ValidatePolicy)).Methods("POST")
	router.Handle("/tenants/{tenant}/policies/test", r.tenantScoped(r.handlers.TestPolicy)).Methods("POST")

	// Policy collection routes
	router.Handle("/tenants/{tenant}/policies", r.tenantScoped(r.handlers.CreatePolicy)).Methods("POST")
	router.Handle("/tenants/{tenant}/policies", r.tenantScoped(r.handlers.ListPolicies)).Methods("GET")

	// Policy instance routes
	router.Handle("/tenants/{tenant}/policies/{id}", r.tenantScoped(r.handlers.GetPolicy)).Methods("GET")
	router.Handle("/tenants/{tenant}/policies/{id}", r.tenantScoped(r.handlers.UpdatePolicy)).Methods("PUT")
	router.Handle("/tenants/{tenant}/policies/{id}", r.tenantScoped(r.handlers.DeletePolicy)).Methods("DELETE")
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
	router.Handle("/tenants/{tenant}/apps", r.tenantScoped(r.handlers.RegisterApp)).Methods("POST")
	router.Handle("/tenants/{tenant}/apps", r.tenantScoped(r.handlers.ListApps)).Methods("GET")

	// App instance routes
	router.Handle("/tenants/{tenant}/apps/{id}", r.tenantScoped(r.handlers.GetApp)).Methods("GET")
	router.Handle("/tenants/{tenant}/apps/{id}", r.tenantScoped(r.handlers.UpdateApp)).Methods("PUT")
	router.Handle("/tenants/{tenant}/apps/{id}", r.tenantScoped(r.handlers.DeleteApp)).Methods("DELETE")

	// App secret rotation route
	router.Handle("/tenants/{tenant}/apps/{id}/rotate", r.tenantScoped(r.handlers.RotateAppSecret)).Methods("POST")
}
