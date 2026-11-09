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

package device

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// TestRouterRegistration verifies that RegisterRoutes registers the expected
// endpoints under /devices.
func TestRouterRegistration(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	profSvc := &mockProfileService{}
	router := NewDeviceRouter(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	r := mux.NewRouter()
	router.RegisterRoutes(r)

	// Verify POST /devices/templates is routed.
	req := httptest.NewRequest(http.MethodPost, "/devices/templates", nil)
	var match mux.RouteMatch
	assert.True(t, r.Match(req, &match), "POST /devices/templates should match a route")

	// Verify POST /devices/templates/{id}/create-profile is routed.
	req = httptest.NewRequest(http.MethodPost, "/devices/templates/12345/create-profile", nil)
	assert.True(t, r.Match(req, &match), "POST /devices/templates/{id}/create-profile should match a route")

	// Verify GET /devices/templates is NOT routed (only POST is registered).
	req = httptest.NewRequest(http.MethodGet, "/devices/templates", nil)
	assert.False(t, r.Match(req, &match), "GET /devices/templates should not match")

	// GET /devices/config belongs to the provisioning surface alone (#177):
	// the seeder routes must not carry it.
	req = httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	assert.False(t, r.Match(req, &match), "GET /devices/config must not ride the seeder routes")
}

// TestRegisterConfigRoute mounts GET /devices/config and nothing else: not
// another method on it, and none of the seeder's template routes.
func TestRegisterConfigRoute(t *testing.T) {
	router := NewDeviceRouter(testLogger(), testResponseWriter(), nil, &mockProfileService{})

	r := mux.NewRouter()
	router.RegisterConfigRoute(r)

	var match mux.RouteMatch
	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	assert.True(t, r.Match(req, &match), "GET /devices/config should match")

	req = httptest.NewRequest(http.MethodPost, "/devices/config", nil)
	assert.False(t, r.Match(req, &match), "POST /devices/config should not match")

	req = httptest.NewRequest(http.MethodPost, "/devices/templates", nil)
	assert.False(t, r.Match(req, &match), "the config route must not bring the seeder routes")
}

// TestRouterEndToEnd_UploadTemplate verifies the full request flow through the
// router for template upload.
func TestRouterEndToEnd_UploadTemplate(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	profSvc := &mockProfileService{}
	deviceRouter := NewDeviceRouter(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	r := mux.NewRouter()
	deviceRouter.RegisterRoutes(r)

	body := templateRequest{
		Role:     "server",
		Template: json.RawMessage(`{"platform":"config"}`),
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp restwire.WebServiceResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

// TestRouterEndToEnd_CreateProfile verifies the full request flow through
// the router for profile creation from a template.
func TestRouterEndToEnd_CreateProfile(t *testing.T) {
	templateID := util.NewID([]byte("server"))
	profile := &entities.DeviceProfile{
		ID:   util.NewID([]byte("web-01")),
		Name: "web-01",
		Role: entities.DeviceRoleServer,
	}
	tmplSvc := &mockTemplateService{profile: profile}
	profSvc := &mockProfileService{}
	deviceRouter := NewDeviceRouter(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	r := mux.NewRouter()
	deviceRouter.RegisterRoutes(r)

	body := profileRequest{
		MAC:      "00:11:22:33:44:55",
		Hostname: "web-01",
		Role:     "server",
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	url := "/devices/templates/" + strconv.FormatUint(templateID, 10) + "/create-profile"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, profSvc.saved)
	assert.Equal(t, "web-01", profSvc.saved.Name)
}

// TestRouterEndToEnd_GetConfig verifies the full request flow through the
// router for config retrieval by MAC address.
func TestRouterEndToEnd_GetConfig(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:     99,
		Name:   "edge-01",
		Config: map[string]interface{}{"hostname": "edge-01"},
	}
	profSvc := &mockProfileService{findByMAC: profile}
	deviceRouter := NewDeviceRouter(testLogger(), testResponseWriter(), nil, profSvc)

	r := mux.NewRouter()
	deviceRouter.RegisterConfigRoute(r)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/x-yaml", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "hostname: edge-01")
}
