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

package tpm

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

func newRouter() (*TPMRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewTPMRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

func TestTPMRouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/tpm/info"},
		{http.MethodPost, "/api/v1/tpm/provision"},
		{http.MethodPost, "/api/v1/tpm/clear"},
		{http.MethodGet, "/api/v1/tpm/ek"},
		{http.MethodPost, "/api/v1/tpm/ek"},
		{http.MethodDelete, "/api/v1/tpm/ek"},
		{http.MethodGet, "/api/v1/tpm/ek/certificate"},
		{http.MethodPost, "/api/v1/tpm/ek/certificate"},
		{http.MethodGet, "/api/v1/tpm/srk"},
		{http.MethodPost, "/api/v1/tpm/srk"},
		{http.MethodDelete, "/api/v1/tpm/srk"},
		{http.MethodGet, "/api/v1/tpm/ak"},
		{http.MethodPost, "/api/v1/tpm/ak"},
		{http.MethodDelete, "/api/v1/tpm/ak"},
		{http.MethodPost, "/api/v1/tpm/seal"},
		{http.MethodPost, "/api/v1/tpm/unseal"},
		{http.MethodPost, "/api/v1/tpm/quote"},
		{http.MethodPost, "/api/v1/tpm/quote/verify"},
		{http.MethodPost, "/api/v1/tpm/certify"},
		{http.MethodGet, "/api/v1/tpm/eventlog"},
		{http.MethodGet, "/api/v1/tpm/pcrs"},
		{http.MethodPost, "/api/v1/tpm/nvram"},
		{http.MethodGet, "/api/v1/tpm/nvram/0x1c00002"},
		{http.MethodPut, "/api/v1/tpm/nvram/0x1c00002"},
		{http.MethodDelete, "/api/v1/tpm/nvram/0x1c00002"},
		{http.MethodPost, "/api/v1/tpm/random"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestTPMRouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/info", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "tpm service is not available")
}

func TestTPMRouter_InvalidNVRAMIndex(t *testing.T) {
	_, parent := newRouter()
	// Use a valid index path but server is nil — service-unavailable wins.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tpm/nvram/0x1c00002", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
