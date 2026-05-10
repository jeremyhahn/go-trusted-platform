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

package attestation

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

func newServerRouter() (*AttestationServerRouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewAttestationServerRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w)
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

func TestAttestationServerRouter_RoutesRegistered(t *testing.T) {
	_, parent := newServerRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/attestation/manifests"},
		{http.MethodGet, "/api/v1/attestation/manifests/abc"},
		{http.MethodPost, "/api/v1/attestation/manifests/build"},
		{http.MethodPost, "/api/v1/attestation/manifests/verify"},
		{http.MethodDelete, "/api/v1/attestation/manifests/abc"},
		{http.MethodPost, "/api/v1/attestation/quote"},
		{http.MethodPost, "/api/v1/attestation/quote/verify"},
		{http.MethodPost, "/api/v1/attestation/host"},
		{http.MethodPost, "/api/v1/attestation/vm/v1"},
		{http.MethodPost, "/api/v1/attestation/container/c1"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestAttestationServerRouter_NilServer(t *testing.T) {
	_, parent := newServerRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/manifests", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "attestation service is not available")
}
