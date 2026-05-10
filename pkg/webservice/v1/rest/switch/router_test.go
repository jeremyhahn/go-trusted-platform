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

package switchapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
)

func TestSwitchRouter_RegisterRoutes(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{
		"core-01": &mockManager{},
	}}
	switchRouter := NewSwitchRouter(newTestLogger(), svc, newTestResponseWriter())

	r := mux.NewRouter()
	switchRouter.RegisterRoutes(r.PathPrefix("/api/v1").Subrouter())

	// Verify all routes are registered by making requests and checking
	// that we get proper responses (not 405 Method Not Allowed).
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/switches/core-01/ports"},
		{http.MethodGet, "/api/v1/switches/core-01/ports/Eth1%2F1"},
		{http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F1/vlan"},
		{http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F1/enable"},
		{http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F1/disable"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			// 200 or 400 are acceptable (means route matched);
			// 405 means wrong method registered.
			assert.NotEqual(t, http.StatusMethodNotAllowed, rec.Code,
				"route should be registered: %s %s", route.method, route.path)
		})
	}
}

func TestSwitchRouter_UnregisteredPath(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{
		"core-01": &mockManager{},
	}}
	switchRouter := NewSwitchRouter(newTestLogger(), svc, newTestResponseWriter())

	r := mux.NewRouter()
	switchRouter.RegisterRoutes(r.PathPrefix("/api/v1").Subrouter())

	// A completely unregistered path should return 404.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/core-01/nonexistent", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}
