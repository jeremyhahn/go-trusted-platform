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

package sdn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func TestNewSDNRouter(t *testing.T) {
	logger := newTestLogger()
	router := NewSDNRouter(logger, &scriptedSDNServer{}, response.NewResponseWriter(logger, nil))

	require.NotNil(t, router)
	require.NotNil(t, router.handlers)
}

// TestRegisterRoutes: every SDN route, zones included, is mounted.
func TestRegisterRoutes(t *testing.T) {
	router := newTestRouter(&scriptedSDNServer{})
	routes := append([]struct{ method, target string }{
		{http.MethodPost, "/api/v1/sdn/zones"},
		{http.MethodGet, "/api/v1/sdn/zones"},
		{http.MethodPut, "/api/v1/sdn/zones/lab"},
		{http.MethodDelete, "/api/v1/sdn/zones/lab"},
	}, everyRoute...)

	for _, route := range routes {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			var match mux.RouteMatch
			assert.True(t, router.Match(httptest.NewRequest(route.method, route.target, nil), &match))
		})
	}
}
