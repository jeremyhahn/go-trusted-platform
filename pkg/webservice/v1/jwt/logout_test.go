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

package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// #215: logout only deleted the browser cookie, so the session token kept
// working server-side until it expired. These tests pin that a signed-out
// token is refused by every path that verifies one.

func issueBackboneBearer(t *testing.T, handler *RestHandler) string {
	t.Helper()
	bearer, _, err := handler.jwtService.IssueSession(&quicbaas.Identity{
		Subject: backboneSubject, TenantID: "tenant-a",
	})
	require.NoError(t, err)
	return bearer
}

func bearerRequest(method, target, bearer string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return req
}

// verifyThrough runs the protected-route middleware and reports the status
// and whether the protected handler ran.
func verifyThrough(handler *RestHandler, bearer string) (int, bool) {
	reached := false
	rec := httptest.NewRecorder()
	handler.Verify(rec, bearerRequest(http.MethodGet, "/api/v1/protected", bearer),
		func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
	return rec.Code, reached
}

func logout(handler *RestHandler, bearer string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.Logout(rec, bearerRequest(http.MethodPost, "/logout", bearer))
	return rec
}

func TestLogout_ProtectedRoutesRefuseTheTokenAfterward(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	bearer := issueBackboneBearer(t, handler)

	code, reached := verifyThrough(handler, bearer)
	require.True(t, reached, "the session must work before logout")
	require.Equal(t, http.StatusOK, code)

	require.Equal(t, http.StatusOK, logout(handler, bearer).Code)

	code, reached = verifyThrough(handler, bearer)
	assert.False(t, reached, "a signed-out token must not reach a protected handler")
	assert.Equal(t, http.StatusUnauthorized, code)
}

func TestLogout_ExpiresTheSessionCookies(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)

	rec := logout(handler, issueBackboneBearer(t, handler))

	require.Equal(t, http.StatusOK, rec.Code)
	expired := map[string]bool{}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 && cookie.Value == "" && cookie.Path == "/" {
			expired[cookie.Name] = true
		}
		// The expiring Set-Cookie is itself held to the session cookie's
		// attributes (gosec G124): no script may read it, it never rides
		// plain HTTP, and no cross-site request carries it.
		assert.True(t, cookie.Secure, "cookie %q must be Secure", cookie.Name)
		assert.True(t, cookie.HttpOnly, "cookie %q must be HttpOnly", cookie.Name)
		assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "cookie %q must be SameSite=Strict", cookie.Name)
	}
	assert.True(t, expired["jwt"], "the jwt cookie must be expired")
	assert.True(t, expired["token"], "the token cookie must be expired")
}

func TestLogout_ASignedOutSessionCannotBeRefreshed(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	bearer := issueBackboneBearer(t, handler)
	require.Equal(t, http.StatusOK, logout(handler, bearer).Code)

	rec := httptest.NewRecorder()
	handler.RefreshToken(rec, bearerRequest(http.MethodPost, "/login/refresh", bearer))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	handler.userService.(*MockUserService).AssertNotCalled(t, "GetByEmail", mock.Anything, mock.Anything)
}

func TestLogout_TransportsRefuseTheTokenAfterward(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	bearer := issueBackboneBearer(t, handler)
	_, err := handler.jwtService.VerifyTokenClaims(bearer)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, logout(handler, bearer).Code)

	_, err = handler.jwtService.VerifyTokenClaims(bearer)
	assert.ErrorIs(t, err, ErrTokenRevoked)
}

func TestLogout_LeavesTheUsersOtherSessionsValid(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	first := issueBackboneBearer(t, handler)
	second := issueBackboneBearer(t, handler)
	require.NotEqual(t, first, second, "each session must be a distinct token")

	require.Equal(t, http.StatusOK, logout(handler, first).Code)

	_, reached := verifyThrough(handler, second)
	assert.True(t, reached, "signing one session out must not sign out another")
}

func TestLogout_SigningOutTwiceSucceeds(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	bearer := issueBackboneBearer(t, handler)

	require.Equal(t, http.StatusOK, logout(handler, bearer).Code)
	assert.Equal(t, http.StatusOK, logout(handler, bearer).Code)
}

func TestLogout_RefusesARequestWithoutAToken(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	rec := httptest.NewRecorder()

	handler.Logout(rec, httptest.NewRequest(http.MethodPost, "/logout", nil))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, handler.jwtService.revocations.entries)
}

func TestLogout_RefusesAForgedToken(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	other := newHandlerForLoginTest(t)

	rec := logout(handler, issueBackboneBearer(t, other))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, handler.jwtService.revocations.entries)
}

func TestRevocationList_ForgetsExpiredEntries(t *testing.T) {
	t.Parallel()
	handler := newHandlerForLoginTest(t)
	token, err := handler.jwtService.ParseTokenString(issueBackboneBearer(t, handler))
	require.NoError(t, err)
	claims := token.Claims.(*TokenClaims)

	var list revocationList
	list.revoke(token, claims.IssuedAt.Time)
	require.True(t, list.revoked(token))

	other, err := handler.jwtService.ParseTokenString(issueBackboneBearer(t, handler))
	require.NoError(t, err)
	list.revoke(other, claims.ExpiresAt.Add(1))

	assert.False(t, list.revoked(token), "an entry outlives its token's expiry")
	assert.True(t, list.revoked(other))
}
