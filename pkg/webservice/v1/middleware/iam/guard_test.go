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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func guardLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newGuard(t *testing.T) *SessionGuard {
	t.Helper()
	guard, err := NewSessionGuard(guardLogger(), response.NewResponseWriter(guardLogger(), nil))
	require.NoError(t, err)
	return guard
}

// run drives a guarded handler and reports the status plus whether the
// protected handler was reached.
func run(t *testing.T, guard func(http.Handler) http.Handler, session IAMSession) (int, bool) {
	t.Helper()
	reached := false
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if session != nil {
		req = req.WithContext(SetSessionInContext(req.Context(), session))
	}
	rec := httptest.NewRecorder()
	guard(protected).ServeHTTP(rec, req)
	return rec.Code, reached
}

func session(tenantID string, roles ...string) IAMSession {
	return NewIAMSession(&iamsdk.User{ID: "u1", TenantID: tenantID, Roles: roles})
}

func TestNewSessionGuard_RejectsMissingDependencies(t *testing.T) {
	writer := response.NewResponseWriter(guardLogger(), nil)

	guard, err := NewSessionGuard(nil, writer)
	assert.Nil(t, guard)
	require.ErrorAs(t, err, &ErrInvalidConfig{})

	guard, err = NewSessionGuard(guardLogger(), nil)
	assert.Nil(t, guard)
	require.ErrorAs(t, err, &ErrInvalidConfig{})
}

// TestSessionGuard_FailsClosedWithoutSession is the property that makes a
// guard safe to mount: with no authenticator ahead of it, it denies.
func TestSessionGuard_FailsClosedWithoutSession(t *testing.T) {
	guard := newGuard(t)
	guards := map[string]func(http.Handler) http.Handler{
		"RequireRoles":    guard.RequireRoles("admin"),
		"RequireAllRoles": guard.RequireAllRoles("admin"),
		"RequireTenant":   guard.RequireTenant("system"),
	}
	for name, g := range guards {
		t.Run(name, func(t *testing.T) {
			status, reached := run(t, g, nil)
			assert.Equal(t, http.StatusUnauthorized, status)
			assert.False(t, reached)
		})
	}
}

func TestRequireRoles(t *testing.T) {
	guard := newGuard(t)
	tests := []struct {
		name    string
		roles   []string
		session IAMSession
		status  int
	}{
		{"holds the role", []string{"admin"}, session("system", "admin"), http.StatusOK},
		{"holds one of several", []string{"admin", "so"}, session("t1", "so"), http.StatusOK},
		{"holds none", []string{"admin"}, session("t1", "user"), http.StatusForbidden},
		{"holds no roles at all", []string{"admin"}, session("t1"), http.StatusForbidden},
		{"role match is exact", []string{"admin"}, session("t1", "administrator"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := run(t, guard.RequireRoles(tt.roles...), tt.session)
			assert.Equal(t, tt.status, status)
			assert.Equal(t, tt.status == http.StatusOK, reached)
		})
	}
}

func TestRequireAllRoles(t *testing.T) {
	guard := newGuard(t)
	tests := []struct {
		name    string
		roles   []string
		session IAMSession
		status  int
	}{
		{"holds both", []string{"admin", "so"}, session("t1", "admin", "so"), http.StatusOK},
		{"holds only one", []string{"admin", "so"}, session("t1", "admin"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := run(t, guard.RequireAllRoles(tt.roles...), tt.session)
			assert.Equal(t, tt.status, status)
		})
	}
}

// TestRequireTenant covers the control-plane boundary: a tenant-scoped
// admin holds the same "admin" role inside their own tenant and must not
// reach the system-tenant surfaces with it.
func TestRequireTenant(t *testing.T) {
	guard := newGuard(t)
	tests := []struct {
		name     string
		required string
		session  IAMSession
		status   int
	}{
		{"system admin", "system", session("system", "admin"), http.StatusOK},
		{"tenant admin is refused", "system", session("acme", "admin"), http.StatusForbidden},
		{"no tenant on the session", "system", session("", "admin"), http.StatusForbidden},
		{"unconfigured guard denies everyone", "", session("system", "admin"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := run(t, guard.RequireTenant(tt.required), tt.session)
			assert.Equal(t, tt.status, status)
			assert.Equal(t, tt.status == http.StatusOK, reached)
		})
	}
}

// TestAuthMiddlewarePromotesGuard proves AuthMiddleware's RBAC surface is
// the guard's implementation, not a second copy of it.
func TestAuthMiddlewarePromotesGuard(t *testing.T) {
	mw, err := NewAuthMiddleware(guardLogger(),
		response.NewResponseWriter(guardLogger(), nil),
		AuthConfig{}, newMockIAMServiceClient(), nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, mw.SessionGuard)

	status, _ := run(t, mw.RequireRoles("admin"), session("system", "admin"))
	assert.Equal(t, http.StatusOK, status)

	status, _ = run(t, mw.RequireTenant("system"), session("acme", "admin"))
	assert.Equal(t, http.StatusForbidden, status)
}

// TestRequireOwnTenant covers the cross-tenant hole a role check alone
// leaves open: handlers that take their target tenant from the URL would
// otherwise let an administrator of one tenant act on any other by naming
// it in the path.
func TestRequireOwnTenant(t *testing.T) {
	guard := newGuard(t)
	named := func(value string) func(*http.Request) string {
		return func(*http.Request) string { return value }
	}

	tests := []struct {
		name    string
		target  func(*http.Request) string
		session IAMSession
		status  int
	}{
		{"acts on its own tenant", named("acme"), session("acme", "admin"), http.StatusOK},
		{"names another tenant", named("other"), session("acme", "admin"), http.StatusForbidden},
		{"the system tenant gets no exception", named("acme"), session("system", "admin"), http.StatusForbidden},
		{"names no tenant, resolved from the session instead", named(""), session("acme", "admin"), http.StatusOK},
		{"names a tenant while holding none", named("acme"), session("", "admin"), http.StatusForbidden},
		{"no session at all", named("acme"), nil, http.StatusUnauthorized},
		{"unconfigured extractor denies everyone", nil, session("acme", "admin"), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reached := run(t, guard.RequireOwnTenant(tt.target), tt.session)
			assert.Equal(t, tt.status, status)
			assert.Equal(t, tt.status == http.StatusOK, reached)
		})
	}
}

// =============================================================================
// RequireOwnTenantOrSystem (#234)
// =============================================================================

func ownOrSystemGuard(t *testing.T, systemID string) (*SessionGuard, *httptest.ResponseRecorder) {
	t.Helper()
	logger := logging.DefaultLogger()
	rec := httptest.NewRecorder()
	g, err := NewSessionGuard(logger, response.NewResponseWriter(logger, nil))
	require.NoError(t, err)
	return g, rec
}

// serveOwnOrSystem runs one request through the guard and reports whether the
// handler was reached, plus the status written when it was not.
func serveOwnOrSystem(
	t *testing.T, systemID, sessionTenant, namedTenant string) (reached bool, status int) {
	t.Helper()

	g, rec := ownOrSystemGuard(t, systemID)
	mw := g.RequireOwnTenantOrSystem(systemID, func(*http.Request) string { return namedTenant })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/x", nil)
	if sessionTenant != "" {
		req = req.WithContext(SetSessionInContext(req.Context(),
			NewIAMSession(&iamsdk.User{ID: "u1", TenantID: sessionTenant})))
	}

	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).
		ServeHTTP(rec, req)
	return reached, rec.Code
}

// TestRequireOwnTenantOrSystem_AdmitsTheCallersOwnTenant — a tenant reading
// itself is the case docs/auth/architecture.md §6c says this surface exists
// for.
func TestRequireOwnTenantOrSystem_AdmitsTheCallersOwnTenant(t *testing.T) {
	reached, _ := serveOwnOrSystem(t, "system", "tenant-a", "tenant-a")
	assert.True(t, reached)
}

// TestRequireOwnTenantOrSystem_AdmitsTheSystemTenant — the control plane acts
// across tenants, and platformctl drives this surface as a system admin
// naming a tenant. Denying it would break the only caller the surface has.
func TestRequireOwnTenantOrSystem_AdmitsTheSystemTenant(t *testing.T) {
	reached, _ := serveOwnOrSystem(t, "system", "system", "tenant-b")
	assert.True(t, reached)
}

// TestRequireOwnTenantOrSystem_DeniesAnotherTenant is #234 itself: an
// administrator of tenant A naming tenant B in the path. The admin role alone
// admitted this, because the role says the caller is an administrator and not
// which tenant they administer.
func TestRequireOwnTenantOrSystem_DeniesAnotherTenant(t *testing.T) {
	reached, status := serveOwnOrSystem(t, "system", "tenant-a", "tenant-b")
	assert.False(t, reached, "tenant-a reached tenant-b")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestRequireOwnTenantOrSystem_DeniesWithoutASession — a guard mounted without
// an authenticator ahead of it must deny, never open.
func TestRequireOwnTenantOrSystem_DeniesWithoutASession(t *testing.T) {
	reached, status := serveOwnOrSystem(t, "system", "", "tenant-b")
	assert.False(t, reached)
	assert.Equal(t, http.StatusUnauthorized, status)
}

// TestRequireOwnTenantOrSystem_AdmitsWhenNoTenantIsNamed — the collection
// routes name no tenant; the handler then resolves it from the verified
// session, which is not caller-controlled.
func TestRequireOwnTenantOrSystem_AdmitsWhenNoTenantIsNamed(t *testing.T) {
	reached, _ := serveOwnOrSystem(t, "system", "tenant-a", "")
	assert.True(t, reached)
}

// TestRequireOwnTenantOrSystem_AnEmptySystemIDDoesNotAdmit is the fail-closed
// case that matters most. A guard that cannot identify the system tenant must
// not treat "no system tenant configured" as "everyone is the system tenant" —
// the same reasoning RequireTenant carries for an empty tenantID.
func TestRequireOwnTenantOrSystem_AnEmptySystemIDDoesNotAdmit(t *testing.T) {
	reached, status := serveOwnOrSystem(t, "", "tenant-a", "tenant-b")
	assert.False(t, reached, "an unconfigured system tenant admitted a cross-tenant request")
	assert.Equal(t, http.StatusForbidden, status)
}

// TestRequireOwnTenantOrSystem_DeniesWithoutAnExtractor — a guard that cannot
// read the named tenant cannot compare it, so it refuses rather than passing
// the request through unchecked.
func TestRequireOwnTenantOrSystem_DeniesWithoutAnExtractor(t *testing.T) {
	logger := logging.DefaultLogger()
	g, err := NewSessionGuard(logger, response.NewResponseWriter(logger, nil))
	require.NoError(t, err)

	reached := false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/x", nil)
	req = req.WithContext(SetSessionInContext(req.Context(),
		NewIAMSession(&iamsdk.User{ID: "u1", TenantID: "system"})))

	g.RequireOwnTenantOrSystem("system", nil)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })).
		ServeHTTP(rec, req)

	assert.False(t, reached)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}
