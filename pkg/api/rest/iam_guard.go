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
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// IAM scopes, the ones the gRPC method catalog
// (pkg/api/grpc/method_permissions.go) requires for the PlatformIAMService
// RPC behind each route.
const (
	scopeIAMRead  = "iam:read"
	scopeIAMWrite = "iam:write"
)

// iamReadPosts are the IAM POST routes that only read: the RPCs behind them
// (CheckPermission, ValidatePolicy, TestPolicy) are iam:read on gRPC.
var iamReadPosts = []string{"/permissions/check", "/policies/validate", "/policies/test"}

// iamCallerKey carries the authenticated caller from IAMRouteGuards.Authenticate
// to the guards mounted after it.
type iamCallerKey struct{}

// IAMRouteGuards adapts a ScopeGuard to the four guards the IAM route table
// (pkg/webservice/v1/rest/iam, Authorization) mounts, so the daemon REST
// listener serves the same IAM handlers as the webservice under the daemon's
// own credentials: a bearer platform token, else the mTLS client certificate.
type IAMRouteGuards struct {
	guard           *ScopeGuard
	systemTenantID  string
	requestedTenant func(*http.Request) string
}

// NewIAMRouteGuards builds the guards. systemTenantID is the platform's
// system tenant; requestedTenant extracts the tenant a request names (the IAM
// router's RequestedTenant). A nil guard refuses every request with 403.
func NewIAMRouteGuards(guard *ScopeGuard, systemTenantID string, requestedTenant func(*http.Request) string) *IAMRouteGuards {
	return &IAMRouteGuards{
		guard:           guard,
		systemTenantID:  systemTenantID,
		requestedTenant: requestedTenant,
	}
}

// Authenticate verifies the caller's credential, answering 401 when it is
// missing or invalid, and hands the caller to the guards that follow.
func (g *IAMRouteGuards) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.guard == nil {
			writeGuardError(w, g.guard.loggerOrDefault(), http.StatusForbidden,
				ErrRouteForbidden{Scope: iamRouteScope(r), Reason: "no authorization is configured for this route"})
			return
		}
		caller, err := g.guard.authenticate(r)
		if err != nil {
			writeGuardError(w, g.guard.loggerOrDefault(), http.StatusUnauthorized, err)
			return
		}
		if caller == nil {
			writeGuardError(w, g.guard.loggerOrDefault(), http.StatusUnauthorized,
				ErrRouteUnauthenticated{Reason: "the credential authorized no caller"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), iamCallerKey{}, caller)))
	})
}

// RequireAdmin requires the IAM scope the gRPC catalog requires for the same
// operation: iam:read for a read, iam:write for anything that changes state.
func (g *IAMRouteGuards) RequireAdmin(next http.Handler) http.Handler {
	return g.withCaller(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		scope := iamRouteScope(r)
		if err := caller.RequireScope(scope); err != nil {
			g.refuse(w, ErrRouteForbidden{Scope: scope, Reason: err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSystemTenant admits only the system tenant: the IAM tenant-record
// routes act across tenants, as CreateTenant and ListTenants do on gRPC.
func (g *IAMRouteGuards) RequireSystemTenant(next http.Handler) http.Handler {
	return g.withCaller(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		isSystem := tenant.IsSystemTenant(g.systemTenantID, caller.TenantID)
		if err := tenant.AuthorizeCrossTenant(isSystem, r.Method+" "+r.URL.Path); err != nil {
			g.refuse(w, ErrRouteForbidden{Scope: iamRouteScope(r), Reason: err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireOwnTenant serves a tenant-bound caller from its own tenant only, the
// system tenant included, the binding authorizeIAMTenant applies on gRPC,
// QUIC and MCP (docs/iam/api.md §8). A request that names no tenant passes.
func (g *IAMRouteGuards) RequireOwnTenant(next http.Handler) http.Handler {
	return g.withCaller(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		if g.requestedTenant == nil {
			g.refuse(w, ErrRouteForbidden{Scope: iamRouteScope(r), Reason: "tenant guard is unconfigured"})
			return
		}
		named := g.requestedTenant(r)
		if named == "" {
			next.ServeHTTP(w, r)
			return
		}
		if err := tenant.AuthorizeTenantAccess(caller.TenantID, false, named); err != nil {
			g.refuse(w, ErrRouteForbidden{Scope: iamRouteScope(r), Reason: err.Error()})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withCaller runs next with the caller Authenticate stored, refusing with 401
// when a guard is mounted without Authenticate in front of it.
func (g *IAMRouteGuards) withCaller(next CallerHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		caller, ok := r.Context().Value(iamCallerKey{}).(*platformtoken.AuthorizedContext)
		if !ok || caller == nil {
			writeGuardError(w, g.guard.loggerOrDefault(), http.StatusUnauthorized,
				ErrRouteUnauthenticated{Reason: "no authenticated caller"})
			return
		}
		next(w, r, caller)
	})
}

func (g *IAMRouteGuards) refuse(w http.ResponseWriter, err error) {
	writeGuardError(w, g.guard.loggerOrDefault(), http.StatusForbidden, err)
}

// iamRouteScope is the scope an IAM route requires: iam:read for GET and for
// the read-only POSTs, iam:write for everything else.
func iamRouteScope(r *http.Request) string {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return scopeIAMRead
	}
	if r.Method == http.MethodPost {
		for _, suffix := range iamReadPosts {
			if strings.HasSuffix(r.URL.Path, suffix) {
				return scopeIAMRead
			}
		}
	}
	return scopeIAMWrite
}
