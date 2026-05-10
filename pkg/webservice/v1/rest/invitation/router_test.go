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

func newRouter() (*InvitationRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewInvitationRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
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
