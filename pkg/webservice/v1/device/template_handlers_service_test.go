// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// newServiceTemplateHandler builds a TemplateHandler over the real template
// and profile services on in-memory storage, through the public constructor.
func newServiceTemplateHandler(t *testing.T) (*TemplateHandler, *devicepkg.TemplateService, *devicepkg.ProfileService) {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	ds := devicepkg.NewDatastore(storage, logging.DefaultLogger())
	templates, err := devicepkg.NewTemplateService(ds)
	require.NoError(t, err)
	profiles, err := devicepkg.NewProfileService(ds)
	require.NoError(t, err)
	handler := NewTemplateHandler(logging.DefaultLogger(), &mockResponseWriter{}, templates, profiles, nil)
	return handler.(*TemplateHandler), templates, profiles
}

// serveTemplateRoute routes one request through a router holding the single
// route under test, so path variables arrive the way they do in production.
func serveTemplateRoute(handler http.HandlerFunc, method, pattern, target, body string) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	router.HandleFunc(pattern, handler).Methods(method)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec
}

func decodeTemplate(t *testing.T, rec *httptest.ResponseRecorder) TemplateResponse {
	t.Helper()
	var resp TemplateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	return resp
}

// TestTemplateHandler_TemplateLifecycle drives create, read, rename, find,
// list and delete through the handlers against the real template service.
func TestTemplateHandler_TemplateLifecycle(t *testing.T) {
	h, _, _ := newServiceTemplateHandler(t)

	rec := serveTemplateRoute(h.CreateTemplate, http.MethodPost, "/device/templates", "/device/templates",
		`{"id":7001,"name":"workers","role":"worker","description":"d","match_rules":{"mac_prefix":"52:54:00","serial_prefix":"LAB-"}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	rec = serveTemplateRoute(h.GetTemplate, http.MethodGet, "/device/templates/{id}", "/device/templates/7001", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	got := decodeTemplate(t, rec)
	assert.Equal(t, uint64(7001), got.ID.Uint64())
	assert.Equal(t, "workers", got.Name)
	assert.Equal(t, "worker", got.Role)
	require.NotNil(t, got.MatchRules, "stored match rules reach the response")
	assert.Equal(t, "52:54:00", got.MatchRules.MACPrefix)
	assert.Equal(t, "LAB-", got.MatchRules.SerialPrefix)

	rec = serveTemplateRoute(h.UpdateTemplate, http.MethodPut, "/device/templates/{id}", "/device/templates/7001",
		`{"name":"workers-v2","role":"worker"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, uint64(7001), decodeTemplate(t, rec).ID.Uint64(), "the path id wins over the body")

	rec = serveTemplateRoute(h.FindTemplateByName, http.MethodGet, "/device/templates/name/{name}", "/device/templates/name/workers-v2", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, uint64(7001), decodeTemplate(t, rec).ID.Uint64())

	rec = serveTemplateRoute(h.CreateTemplate, http.MethodPost, "/device/templates", "/device/templates",
		`{"id":7002,"name":"gateways","role":"gateway"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	rec = serveTemplateRoute(h.ListTemplates, http.MethodGet, "/device/templates", "/device/templates?page=1&page_size=1", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var list TemplateListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Len(t, list.Templates, 1)
	assert.Equal(t, 2, list.Pagination.Total)
	assert.Equal(t, 2, list.Pagination.TotalPages)
	assert.True(t, list.Pagination.HasMore)

	rec = serveTemplateRoute(h.DeleteTemplate, http.MethodDelete, "/device/templates/{id}", "/device/templates/7001", "")
	require.Equal(t, http.StatusNoContent, rec.Code, rec.Body.String())
	rec = serveTemplateRoute(h.GetTemplate, http.MethodGet, "/device/templates/{id}", "/device/templates/7001", "")
	assert.Equal(t, http.StatusNotFound, rec.Code, "a deleted template is gone")
}

// TestTemplateHandler_TemplateRequestErrors covers the boundary failures of
// the template routes: a malformed id or body is the caller's fault, an
// unknown template is not found, and nothing answers 200.
func TestTemplateHandler_TemplateRequestErrors(t *testing.T) {
	h, _, _ := newServiceTemplateHandler(t)
	cases := []struct {
		name                  string
		handler               http.HandlerFunc
		method, pattern, path string
		body                  string
		want                  int
	}{
		{"get bad id", h.GetTemplate, http.MethodGet, "/t/{id}", "/t/x", "", http.StatusBadRequest},
		{"get unknown", h.GetTemplate, http.MethodGet, "/t/{id}", "/t/404", "", http.StatusNotFound},
		{"update bad id", h.UpdateTemplate, http.MethodPut, "/t/{id}", "/t/x", `{"role":"worker"}`, http.StatusBadRequest},
		{"update bad body", h.UpdateTemplate, http.MethodPut, "/t/{id}", "/t/1", `{`, http.StatusBadRequest},
		{"delete bad id", h.DeleteTemplate, http.MethodDelete, "/t/{id}", "/t/x", "", http.StatusBadRequest},
		{"delete unknown", h.DeleteTemplate, http.MethodDelete, "/t/{id}", "/t/404", "", http.StatusNotFound},
		{"create bad body", h.CreateTemplate, http.MethodPost, "/t", "/t", `{`, http.StatusBadRequest},
		{"find no name", h.FindTemplateByName, http.MethodGet, "/t/name", "/t/name", "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveTemplateRoute(tc.handler, tc.method, tc.pattern, tc.path, tc.body)
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}

	t.Run("find unknown name", func(t *testing.T) {
		rec := serveTemplateRoute(h.FindTemplateByName, http.MethodGet, "/t/name/{name}", "/t/name/absent", "")
		assert.NotEqual(t, http.StatusOK, rec.Code, rec.Body.String())
	})
	t.Run("update unknown", func(t *testing.T) {
		rec := serveTemplateRoute(h.UpdateTemplate, http.MethodPut, "/t/{id}", "/t/404", `{"name":"n","role":"worker"}`)
		assert.NotEqual(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}

// TestTemplateHandler_UnwiredServicesAnswer500 pins that a route whose
// service is not wired fails as a server fault, never as an empty success.
func TestTemplateHandler_UnwiredServicesAnswer500(t *testing.T) {
	noTemplates := &TemplateHandler{logger: logging.DefaultLogger(), responseWriter: &mockResponseWriter{}}
	noProfiles := &TemplateHandler{logger: logging.DefaultLogger(), responseWriter: &mockResponseWriter{},
		templateService: &captureTemplateService{}}
	cases := map[string]http.HandlerFunc{
		"create template":            noTemplates.CreateTemplate,
		"get template":               noTemplates.GetTemplate,
		"update template":            noTemplates.UpdateTemplate,
		"delete template":            noTemplates.DeleteTemplate,
		"list templates":             noTemplates.ListTemplates,
		"find template by name":      noTemplates.FindTemplateByName,
		"profile from template":      noTemplates.CreateProfileFromTemplate,
		"profile, no profiles":       noProfiles.CreateProfileFromTemplate,
		"find config, no profiles":   noProfiles.FindConfigForDevice,
		"unassign, no profiles":      noProfiles.UnassignProfileFromDevice,
		"assign, no profiles at all": noProfiles.AssignProfileToDevice,
	}
	for name, handler := range cases {
		t.Run(name, func(t *testing.T) {
			rec := serveTemplateRoute(handler, http.MethodPost, "/t/{id}", "/t/1", `{"ek_serial":"EK-1"}`)
			assert.Equal(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		})
	}
}

// TestTemplateHandler_CreateProfileFromTemplate_RealService saves the profile
// the real template service derives, and refuses an unknown template.
func TestTemplateHandler_CreateProfileFromTemplate_RealService(t *testing.T) {
	h, templates, profiles := newServiceTemplateHandler(t)
	require.NoError(t, templates.Save(context.Background(), &entities.DeviceTemplate{
		ID: 7100, Name: "edge", Role: entities.DeviceRoleWorker,
	}))

	rec := serveTemplateRoute(h.CreateProfileFromTemplate, http.MethodPost, "/t/{id}/create-profile", "/t/7100/create-profile",
		`{"overrides":{"name":"edge-01"}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created ProfileFullResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	stored, err := profiles.Get(context.Background(), created.ID.Uint64())
	require.NoError(t, err, "the derived profile is saved")
	assert.Equal(t, "edge-01", stored.Name)

	rec = serveTemplateRoute(h.CreateProfileFromTemplate, http.MethodPost, "/t/{id}/create-profile", "/t/x/create-profile", `{}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = serveTemplateRoute(h.CreateProfileFromTemplate, http.MethodPost, "/t/{id}/create-profile", "/t/404/create-profile", `{}`)
	assert.NotEqual(t, http.StatusCreated, rec.Code, rec.Body.String())
}

// TestTemplateHandler_FindConfigForDevice resolves an assigned profile by
// either identity, and refuses a request that names neither or an unknown one.
func TestTemplateHandler_FindConfigForDevice(t *testing.T) {
	h, _, profiles := newServiceTemplateHandler(t)
	ctx := context.Background()
	require.NoError(t, profiles.Save(ctx, &entities.DeviceProfile{ID: 7200, Name: "node-07", Role: entities.DeviceRoleWorker}))
	require.NoError(t, profiles.AssignToDevice(ctx, 7200, "EK-7200", "52:54:00:00:72:00"))

	find := func(query string) *httptest.ResponseRecorder {
		return serveTemplateRoute(h.FindConfigForDevice, http.MethodGet, "/find-config", "/find-config"+query, "")
	}
	for _, query := range []string{"?ek_serial=EK-7200", "?mac=52:54:00:00:72:00"} {
		rec := find(query)
		require.Equal(t, http.StatusOK, rec.Code, query+": "+rec.Body.String())
		var resp ProfileFullResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "node-07", resp.Name, query)
	}

	assert.Equal(t, http.StatusBadRequest, find("").Code, "no identity")
	unknown := find("?ek_serial=EK-UNKNOWN")
	assert.Equal(t, http.StatusNotFound, unknown.Code, unknown.Body.String())
	assert.NotContains(t, unknown.Body.String(), "node-07", "an unknown identity is handed no profile")

	// A profile service that cannot resolve config by identity is a wiring
	// fault, not an absent profile.
	mocked, _ := newTestTemplateHandler()
	rec := serveTemplateRoute(mocked.FindConfigForDevice, http.MethodGet, "/find-config", "/find-config?mac=aa", "")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestCalculatePages(t *testing.T) {
	cases := []struct{ total, pageSize, want int }{
		{0, 10, 0},
		{10, 10, 1},
		{11, 10, 2},
		{5, 0, 0},
		{5, -1, 0},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, calculatePages(tc.total, tc.pageSize), "total=%d pageSize=%d", tc.total, tc.pageSize)
	}
}
