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

package idevid

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

func newRouter() (*IDevIDRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewIDevIDRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

func TestIDevIDRouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/idevid"},
		{http.MethodPost, "/api/v1/idevid/generate"},
		{http.MethodGet, "/api/v1/idevid/exists"},
		{http.MethodDelete, "/api/v1/idevid"},
		{http.MethodPost, "/api/v1/idevid/csr"},
		{http.MethodGet, "/api/v1/idevid/certificate"},
		{http.MethodPost, "/api/v1/idevid/certificate"},
		{http.MethodDelete, "/api/v1/idevid/certificate"},
		{http.MethodPost, "/api/v1/idevid/ldevid"},
		{http.MethodGet, "/api/v1/idevid/iak"},
		{http.MethodPost, "/api/v1/idevid/iak/generate"},
		{http.MethodGet, "/api/v1/idevid/iak/exists"},
		{http.MethodDelete, "/api/v1/idevid/iak"},
		{http.MethodPost, "/api/v1/idevid/iak/csr"},
		{http.MethodGet, "/api/v1/idevid/iak/certificate"},
		{http.MethodPost, "/api/v1/idevid/iak/certificate"},
		{http.MethodDelete, "/api/v1/idevid/iak/certificate"},
		{http.MethodGet, "/api/v1/idevid/attributes"},
		{http.MethodPost, "/api/v1/idevid/flush"},
		{http.MethodPost, "/api/v1/idevid/activate-credential"},
		{http.MethodDelete, "/api/v1/tpm/idevid"},
		{http.MethodDelete, "/api/v1/tpm/iak"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestIDevIDRouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/idevid", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "idevid service is not available")
}
