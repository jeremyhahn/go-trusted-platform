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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// newRouter mounts BOTH halves of the invitation surface, the way
// v1Router.invitationRoutes does, so the existing behavioural tests keep
// exercising every route they were written for. Which half production hands
// to the gated router is asserted by the two split tests below rather than
// by this helper.
func newRouter() (*InvitationRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewInvitationRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	sub := parent.PathPrefix("/api/v1").Subrouter()
	r.RegisterInviteeRoutes(sub)
	r.RegisterRoutes(sub)
	return r, parent
}

// registeredInvitationPaths returns the "METHOD /path" set one registration
// method installs, so the split is asserted by its effect on the route table
// rather than by reading the source.
func registeredInvitationPaths(register func(*mux.Router)) map[string]bool {
	router := mux.NewRouter()
	register(router.PathPrefix("/api/v1").Subrouter())

	out := map[string]bool{}
	_ = router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			out[m+" "+path] = true
		}
		return nil
	})
	return out
}

// TestRegisterRoutes_GatedHalfIsExactlyTheTenantAdminRoutes pins which routes
// take the caller's role gate. These are the five that resolve a tenant and
// an inviter from the session (#171); one drifting out of this set becomes
// reachable by an anonymous caller who then chooses both.
func TestRegisterRoutes_GatedHalfIsExactlyTheTenantAdminRoutes(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewInvitationRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)

	assert.Equal(t, map[string]bool{
		"GET /api/v1/invitations":                     true,
		"POST /api/v1/invitations":                    true,
		"GET /api/v1/invitations/{id:[0-9]+}":         true,
		"DELETE /api/v1/invitations/{id:[0-9]+}":      true,
		"POST /api/v1/invitations/{id:[0-9]+}/revoke": true,
	}, registeredInvitationPaths(r.RegisterRoutes))
}

// TestRegisterInviteeRoutes_IsExactlyTheTokenBearingPair pins the other half.
// An admin route drifting in here would be published to anyone; a route
// drifting OUT of here would demand a session from an invitee who has none,
// which makes invitations unacceptable rather than merely denied.
func TestRegisterInviteeRoutes_IsExactlyTheTokenBearingPair(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewInvitationRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)

	assert.Equal(t, map[string]bool{
		"POST /api/v1/invitations/accept":       true,
		"GET /api/v1/invitations/token/{token}": true,
	}, registeredInvitationPaths(r.RegisterInviteeRoutes))
}

// TestInvitationHalvesAreDisjointAndCoverTheSurface proves the split lost
// nothing: together the two methods register every route the router had
// before it was divided, and no route appears in both.
func TestInvitationHalvesAreDisjointAndCoverTheSurface(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewInvitationRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)

	admin := registeredInvitationPaths(r.RegisterRoutes)
	invitee := registeredInvitationPaths(r.RegisterInviteeRoutes)

	for route := range admin {
		assert.False(t, invitee[route], "route is in both halves: %s", route)
	}
	assert.Len(t, admin, 5)
	assert.Len(t, invitee, 2)
}

func TestInvitationRouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/invitations"},
		{http.MethodPost, "/api/v1/invitations"},
		{http.MethodPost, "/api/v1/invitations/accept"},
		{http.MethodGet, "/api/v1/invitations/token/abc-token"},
		{http.MethodGet, "/api/v1/invitations/123"},
		{http.MethodDelete, "/api/v1/invitations/123"},
		{http.MethodPost, "/api/v1/invitations/123/revoke"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestInvitationRouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "invitation service is not available")
}

func TestInvitationRouter_InvalidIDIs400(t *testing.T) {
	// /invitations/{id:[0-9]+} regex prevents non-numeric, so this should
	// fall through to 404 from the parent router.
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/invitations/abc", nil)
	var match mux.RouteMatch
	assert.False(t, parent.Match(req, &match), "non-numeric id should not match")
}
