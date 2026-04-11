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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// TestRouterRegistration verifies that RegisterRoutes registers the expected
// POST endpoints under /devices/templates.
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

	var resp response.WebServiceResponse
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
