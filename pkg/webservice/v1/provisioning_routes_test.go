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

package v1

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const configRoute = "GET /api/v1/devices/config"

// TestRegisterRoutes_ConfigRouteIsNotMounted: the full route table — every
// general listener's API — does not carry the unauthenticated boot-time
// config fetch, so the request falls to the listener's unknown-route 404
// (#177).
func TestRegisterRoutes_ConfigRouteIsNotMounted(t *testing.T) {
	router := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})

	assert.NotContains(t, testutil.WalkRoutes(t, router), configRoute)

	var match mux.RouteMatch
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/config?mac=52:54:00:aa:bb:cc", nil)
	assert.False(t, router.Match(req, &match), "a general listener must not route GET /api/v1/devices/config")
}

// TestRegisterProvisioningRoutes_MountsOnlyTheConfigRoute: the provisioning
// listener's API is the config route and nothing else.
func TestRegisterProvisioningRoutes_MountsOnlyTheConfigRoute(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{responseWriter: respWriter, deviceProfileService: &stubDeviceProfileService{}}

	root := mux.NewRouter()
	assert.True(t, NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter).RegisterProvisioningRoutes(root, "/api/v1"))

	for _, route := range testutil.WalkRoutes(t, root) {
		assert.Contains(t, []string{configRoute, "GET /api/v1"}, route, "provisioning routes mounted %q", route)
	}
	assert.Contains(t, testutil.WalkRoutes(t, root), configRoute)

	var match mux.RouteMatch
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/templates", nil)
	assert.False(t, root.Match(req, &match), "the seeder's template routes stay off the provisioning listener")
}

func TestRegisterProvisioningRoutes_NoProfileServiceMountsNothing(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{responseWriter: respWriter}

	root := mux.NewRouter()
	assert.False(t, NewRouter(logger, &stubCA{}, nil, nil, registry, respWriter).RegisterProvisioningRoutes(root, "/api/v1"))
	assert.Empty(t, testutil.WalkRoutes(t, root))
}
