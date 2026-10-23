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

package compute

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func newTestWriter() response.HttpWriter {
	return response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
}

func newTestRouter() (*ComputeRouter, *mux.Router) {
	r := NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, newTestWriter())
	parent := mux.NewRouter()
	r.RegisterRoutes(parent.PathPrefix("/api/v1").Subrouter())
	return r, parent
}

func TestComputeRouter_ConstructorOK(t *testing.T) {
	r := NewComputeRouter(logging.NewLogger(slog.LevelError, io.Discard), nil, newTestWriter())
	require.NotNil(t, r)
	require.NotNil(t, r.handlers)
}

func TestComputeRouter_RoutesRegistered(t *testing.T) {
	_, parent := newTestRouter()
	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/compute/vms"},
		{http.MethodGet, "/api/v1/compute/vms"},
		{http.MethodGet, "/api/v1/compute/vms/abc"},
		{http.MethodDelete, "/api/v1/compute/vms/abc"},
		{http.MethodPost, "/api/v1/compute/vms/abc/start"},
		{http.MethodPost, "/api/v1/compute/vms/abc/stop"},
		{http.MethodPost, "/api/v1/compute/vms/abc/reboot"},
		{http.MethodPost, "/api/v1/compute/vms/abc/suspend"},
		{http.MethodPost, "/api/v1/compute/vms/abc/resume"},
		{http.MethodGet, "/api/v1/compute/vms/abc/metrics"},
		{http.MethodPost, "/api/v1/compute/vms/abc/migrate"},
		{http.MethodPost, "/api/v1/compute/migrations/prepare"},
		{http.MethodPost, "/api/v1/compute/migrations/abc/finalize"},
		{http.MethodPost, "/api/v1/compute/vms/abc/disks"},
		{http.MethodDelete, "/api/v1/compute/vms/abc/disks/d1"},
		{http.MethodPatch, "/api/v1/compute/vms/abc/disks/d1"},
		{http.MethodPost, "/api/v1/compute/vms/abc/snapshots"},
		{http.MethodGet, "/api/v1/compute/vms/abc/snapshots"},
		{http.MethodGet, "/api/v1/compute/vms/abc/snapshots/s1"},
		{http.MethodDelete, "/api/v1/compute/vms/abc/snapshots/s1"},
		{http.MethodPost, "/api/v1/compute/vms/abc/snapshots/s1/restore"},
		{http.MethodPost, "/api/v1/compute/vms/abc/attest"},
		{http.MethodPost, "/api/v1/compute/vms/abc/attest/verify"},
		{http.MethodPost, "/api/v1/compute/containers"},
		{http.MethodGet, "/api/v1/compute/containers"},
		{http.MethodGet, "/api/v1/compute/containers/c1"},
		{http.MethodDelete, "/api/v1/compute/containers/c1"},
		{http.MethodPost, "/api/v1/compute/containers/c1/start"},
		{http.MethodPost, "/api/v1/compute/containers/c1/stop"},
		{http.MethodPost, "/api/v1/compute/containers/c1/exec"},
		{http.MethodGet, "/api/v1/compute/containers/c1/metrics"},
		{http.MethodPost, "/api/v1/compute/containers/c1/attest"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			ok := parent.Match(req, &match)
			assert.True(t, ok, "route should match")
		})
	}
}

func TestComputeRouter_NilServerReturnsServiceUnavailable(t *testing.T) {
	_, parent := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compute/vms", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	// nil server triggers 500 envelope with "service is not available"
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "compute service is not available")
}
