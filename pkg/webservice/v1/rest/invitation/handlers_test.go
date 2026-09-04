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

package invitation

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
)

// forgedToken builds something shaped exactly like a JWT — three
// dot-separated segments with a base64url payload — carrying whatever claims
// the caller names, and signed by nobody. Before #171 this was enough to
// choose the tenant an invitation landed in and the user id it was
// attributed to, because the handlers base64-decoded the payload and never
// checked a signature.
func forgedToken(claims map[string]any) string {
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	return "eyJhbGciOiJIUzI1NiJ9." +
		base64.RawURLEncoding.EncodeToString(payload) +
		".not-a-signature"
}

// withForgedCarriers attaches the forged token by every carrier the deleted
// decoders honoured: a raw (non-Bearer) Authorization header, a `jwt` cookie
// and a `token` cookie.
func withForgedCarriers(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", token)
	r.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	r.AddCookie(&http.Cookie{Name: "token", Value: token})
	return r
}

func withSession(r *http.Request, tenantID, userID string) *http.Request {
	session := iammw.NewIAMSession(&iamsdk.User{
		ID:       userID,
		TenantID: tenantID,
		Email:    "admin@example.test",
	})
	return r.WithContext(iammw.SetSessionInContext(r.Context(), session))
}

// TestResolveTenantID_ComesFromTheVerifiedSession is the #171 regression in
// its stated shape: a forged cookie and a raw non-Bearer header must not move
// the resolved tenant.
func TestResolveTenantID_ComesFromTheVerifiedSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	req = withForgedCarriers(req, forgedToken(map[string]any{"tenant_id": "victim-tenant"}))
	req = withSession(req, "caller-tenant", "42")

	assert.Equal(t, "caller-tenant", resolveTenantID(req),
		"the forged carriers moved the tenant; the verified session must win")
}

// TestResolveTenantID_IsEmptyWithoutASession proves the forged carriers are
// not merely outranked but ignored. Empty fails closed at the service, which
// is the correct outcome for a request that authenticated nobody.
func TestResolveTenantID_IsEmptyWithoutASession(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	req = withForgedCarriers(req, forgedToken(map[string]any{"tenant_id": "victim-tenant"}))

	assert.Empty(t, resolveTenantID(req),
		"a request with no verified session resolved a tenant from a forged token")
}

// TestResolveUserID_ComesFromTheVerifiedSession covers the second decoder,
// which #171 did not name. Its value is recorded as WHO ISSUED the
// invitation, so a forged one makes the audit trail attacker-authored rather
// than merely attacker-triggered.
func TestResolveUserID_ComesFromTheVerifiedSession(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", nil)
	req = withForgedCarriers(req, forgedToken(map[string]any{
		"uid": 9999, "user_id": "9999", "sub": "9999",
	}))
	req = withSession(req, "caller-tenant", "42")

	assert.Equal(t, uint64(42), resolveUserID(req),
		"the forged carriers moved the inviter identity; the verified session must win")
}

// TestResolveUserID_IsZeroWithoutASession — unattributed honestly beats
// attributed falsely. Every claim shape the deleted decoder understood is
// present and must be ignored.
func TestResolveUserID_IsZeroWithoutASession(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", nil)
	req = withForgedCarriers(req, forgedToken(map[string]any{
		"uid": 9999, "user_id": "9999", "sub": "9999",
	}))

	assert.Zero(t, resolveUserID(req),
		"a request with no verified session attributed an invitation to a forged user id")
}

// TestResolveUserID_IsZeroForANonNumericSessionID covers the error path:
// IAMSession.UserID() is a string and the service wants a uint64, so a
// session whose id is not numeric must yield unattributed rather than a
// parse artifact.
func TestResolveUserID_IsZeroForANonNumericSessionID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/invitations", nil)
	req = withSession(req, "caller-tenant", "not-a-number")

	assert.Zero(t, resolveUserID(req))
}

// TestResolveTenantID_PrefersTheTenantMiddlewareContext pins the ordering
// that survives: the tenant middleware's value is populated from the same
// verified identity and is what a tenant-scoped mount supplies, so it is
// consulted first.
func TestResolveTenantID_PrefersTheTenantMiddlewareContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	req = withSession(req, "session-tenant", "42")
	req = req.WithContext(
		tenant.SetTenantContext(req.Context(), "middleware-tenant", 7, false))

	assert.Equal(t, "middleware-tenant", resolveTenantID(req))
}
