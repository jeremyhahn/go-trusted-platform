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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// SessionGuard turns the verified IAMSession an authenticating middleware
// published into the request context into route-level authorization
// decisions. It performs no authentication of its own: every guard fails
// closed with 401 when no session is present, so mounting a guard without
// an authenticator ahead of it denies the route rather than opening it.
//
// The guard is deliberately separate from AuthMiddleware. Authentication
// has several implementations (the platform JWT handler, the QuicBaaS
// broker platform token, mTLS), but the authorization decision they all
// feed is one piece of code — AuthMiddleware embeds this type so its
// RequireRoles/RequireAllRoles surface and a directly mounted guard are
// literally the same implementation.
type SessionGuard struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
}

// NewSessionGuard constructs a SessionGuard, failing closed when either
// dependency is missing — a guard that cannot write a 403 cannot deny.
func NewSessionGuard(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
) (*SessionGuard, error) {

	if logger == nil {
		return nil, ErrInvalidConfig{Field: "logger", Reason: "logger is required"}
	}
	if responseWriter == nil {
		return nil, ErrInvalidConfig{Field: "responseWriter", Reason: "response writer is required"}
	}
	return &SessionGuard{logger: logger, responseWriter: responseWriter}, nil
}

// session resolves the request's authenticated session, writing 401 and
// reporting false when the authenticating middleware published none.
func (g *SessionGuard) session(w http.ResponseWriter, r *http.Request) (IAMSession, bool) {
	session, ok := GetSessionFromContext(r.Context())
	if !ok || session == nil {
		g.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "session required"})
		return nil, false
	}
	return session, true
}

// RequireRoles returns a middleware that requires ANY of the roles.
func (g *SessionGuard) RequireRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			if !session.HasAnyRole(roles...) {
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "required role not present",
				}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllRoles returns a middleware that requires ALL of the roles.
func (g *SessionGuard) RequireAllRoles(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			if !session.HasAllRoles(roles...) {
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "all required roles not present",
				}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenant returns a middleware that requires the session's tenant to
// be exactly tenantID. It is how a control-plane surface that only the
// system tenant may drive — tenant provisioning, per
// docs/08-bootstrap-auth-contract.md §"Control plane vs data plane" — is
// kept out of reach of a tenant-scoped admin who legitimately holds the
// same "admin" role inside their own tenant.
//
// An empty tenantID denies every request: a guard configured with no
// tenant cannot distinguish the system tenant from any other, and opening
// the route would be the opposite of what the caller asked for.
func (g *SessionGuard) RequireTenant(tenantID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tenantID == "" {
				g.logger.Error(ErrForbidden{Reason: "tenant guard is unconfigured"},
					"iam/guard: RequireTenant mounted without a tenant; denying")
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "tenant guard is unconfigured",
				}, nil)
				return
			}
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			if session.TenantID() != tenantID {
				g.logger.Debugf("iam/guard: tenant %q denied, %q required",
					session.TenantID(), tenantID)
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "caller is not a member of the required tenant",
				}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnTenantOrSystem returns a middleware that admits a request naming
// a tenant when EITHER the caller's own tenant is the one named, OR the
// caller is the system tenant.
//
// It exists because /api/v1/tenants/{id} is neither of the two shapes
// RequireTenant and RequireOwnTenant were written for, and using either alone
// is wrong in a different direction (#234):
//
//   - RequireOwnTenant alone would deny the SYSTEM tenant acting on any other
//     tenant — which is how the platform operates today. `platformctl` drives
//     /api/v1/tenants/{id}/barrier/* through the SDK as a system admin naming
//     a tenant, so that guard would break the only caller this surface has.
//   - RequireTenant(system) alone would deny a tenant administrator reading
//     their own tenant, which docs/auth/architecture.md §6c says is what this
//     surface is for: "A tenant admin reads their own tenant through
//     /api/v1/tenants".
//
// The disjunction is therefore the documented model rather than a new one:
// the control plane holds tenant records and may act across tenants, and a
// tenant is visible to itself. What it removes is the third case, which is
// the defect: a tenant administrator naming SOMEBODY ELSE'S tenant in the
// path and being served because they hold the "admin" role in their own.
//
// systemTenantID empty denies every non-matching caller, on the same
// reasoning as RequireTenant: a guard that cannot identify the system tenant
// must not fall back to admitting one.
//
// A request that names no tenant is admitted; the handler then resolves it
// from the verified session, which is not caller-controlled.
func (g *SessionGuard) RequireOwnTenantOrSystem(
	systemTenantID string,
	target func(*http.Request) string) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if target == nil {
				g.logger.Error(ErrForbidden{Reason: "tenant extractor is unconfigured"},
					"iam/guard: RequireOwnTenantOrSystem mounted without an extractor; denying")
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "tenant guard is unconfigured",
				}, nil)
				return
			}
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			named := target(r)
			if named == "" {
				next.ServeHTTP(w, r)
				return
			}
			if named == session.TenantID() {
				next.ServeHTTP(w, r)
				return
			}
			if systemTenantID != "" && session.TenantID() == systemTenantID {
				next.ServeHTTP(w, r)
				return
			}
			g.logger.Debugf("iam/guard: tenant %q may not act on tenant %q",
				session.TenantID(), named)
			g.responseWriter.Error403(w, r, ErrForbidden{
				Reason: "caller may not act on another tenant",
			}, nil)
		})
	}
}

// RequireOwnTenantNameOrSystem returns a middleware for a route that names a
// tenant by NAME rather than by id: GET /api/v1/tenants/by-name/{name}.
// RequireOwnTenantOrSystem cannot guard it, because a tenant name never
// equals the session's tenant id.
//
// resolve maps the request's name to a tenant id, returning "" when the name
// resolves to nothing. The decision is tenant.AuthorizeNameLookup, the rule
// TenantGRPCServer applies on gRPC, QUIC, MCP and Unix, fed the session's
// tenant claim — never a request field. The system tenant is admitted
// without a lookup. Any other caller is admitted for its own tenant's name
// only; another tenant's name and an unknown one get the same 403 carrying
// tenant.ErrNameLookupDenied.
//
// systemTenantID empty admits no caller as the system tenant, on the same
// fail-closed reasoning as RequireTenant. A nil resolve denies every request.
func (g *SessionGuard) RequireOwnTenantNameOrSystem(
	systemTenantID string,
	resolve func(*http.Request) string) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if resolve == nil {
				g.logger.Error(ErrForbidden{Reason: "tenant name resolver is unconfigured"},
					"iam/guard: RequireOwnTenantNameOrSystem mounted without a resolver; denying")
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "tenant guard is unconfigured",
				}, nil)
				return
			}
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			caller := session.TenantID()
			isSystem := systemTenantID != "" && caller == systemTenantID
			resolvedID := ""
			if !isSystem {
				resolvedID = resolve(r)
			}
			if err := tenant.AuthorizeNameLookup(caller, isSystem, resolvedID); err != nil {
				g.logger.Debugf("iam/guard: tenant %q may not resolve that tenant name", caller)
				g.responseWriter.Error403(w, r, err, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOwnTenant returns a middleware that requires the tenant a request
// NAMES to be the session's own tenant. The caller supplies target, which
// extracts the named tenant from the request — typically a path variable.
//
// This is the guard for a handler that takes its target tenant from the
// URL. Without it, holding an administrative role inside one tenant would
// be enough to administer any other tenant simply by naming it in the
// path: the role check passes, and the handler then trusts the URL.
//
// It applies to the system tenant too, deliberately. Per
// docs/08-bootstrap-auth-contract.md §"Control plane vs data plane" the
// control plane holds tenant records and tenant-admin identities while
// tenant users belong to the tenant's own data plane, and the upstream
// narrowing in go-quicbaas#357 denies system-tenant impersonation of
// tenant users outright. Carving out an exception here would build on
// behaviour that is being removed.
//
// A request that names no tenant is admitted: the handler then resolves
// the tenant from the verified session instead, which is not a
// caller-controlled input. A request that names one while the session
// carries none is denied.
func (g *SessionGuard) RequireOwnTenant(
	target func(*http.Request) string) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if target == nil {
				g.logger.Error(ErrForbidden{Reason: "tenant extractor is unconfigured"},
					"iam/guard: RequireOwnTenant mounted without an extractor; denying")
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "tenant guard is unconfigured",
				}, nil)
				return
			}
			session, ok := g.session(w, r)
			if !ok {
				return
			}
			named := target(r)
			if named == "" {
				next.ServeHTTP(w, r)
				return
			}
			if named != session.TenantID() {
				g.logger.Debugf("iam/guard: request names tenant %q, session holds %q",
					named, session.TenantID())
				g.responseWriter.Error403(w, r, ErrForbidden{
					Reason: "caller may not act on another tenant",
				}, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
