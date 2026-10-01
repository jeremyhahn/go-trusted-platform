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

package rest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// zoneRouter returns a router with the zone routes backed by a real zone
// service in environment 4.
func zoneRouter(t *testing.T) *mux.Router {
	t.Helper()
	svc, err := gateway.NewZoneService(nil, &netplan.Environment{ID: 4})
	require.NoError(t, err)
	h := NewSDNHandlers(nil, slog.Default())
	h.SetZoneService(svc)
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	return r
}

func zoneCall(t *testing.T, r *mux.Router, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, &buf))
	return w
}

// TestZoneHandlers_Lifecycle creates an owner zone, lists it with its
// derived numbering, tunes a built-in, and deletes the owner zone.
func TestZoneHandlers_Lifecycle(t *testing.T) {
	r := zoneRouter(t)

	w := zoneCall(t, r, http.MethodPost, "/api/v1/sdn/zones", NetworkZoneCreateRequest{
		Name: "lab", Offset: 9, PortClasses: []string{"hypervisor"}, Isolate: true,
	})
	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	var created NetworkZoneResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	assert.Equal(t, "lab", created.Name)
	assert.True(t, created.RestartRequired)
	require.NotNil(t, created.Numbering)
	assert.Equal(t, uint16(409), created.Numbering.VLAN)
	assert.Equal(t, "10.4.9.0/24", created.Numbering.Subnet4)

	w = zoneCall(t, r, http.MethodGet, "/api/v1/sdn/zones?lifecycle_role=provisioning", nil)
	require.Equal(t, http.StatusOK, w.Code)
	var list NetworkZoneListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &list))
	require.Len(t, list.Zones, 1)
	assert.Equal(t, "provisioning", list.Zones[0].Name)

	w = zoneCall(t, r, http.MethodPut, "/api/v1/sdn/zones/storage", NetworkZoneUpdateRequest{
		Isolate: true, Services: []string{"nvme-tcp"},
	})
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var updated NetworkZoneResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &updated))
	assert.Equal(t, uint8(7), updated.Offset, "a built-in keeps its offset")
	assert.Equal(t, []string{"nvme-tcp"}, updated.Services)

	w = zoneCall(t, r, http.MethodDelete, "/api/v1/sdn/zones/lab", nil)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

// TestZoneHandlers_Errors maps every zone service failure to its status.
func TestZoneHandlers_Errors(t *testing.T) {
	r := zoneRouter(t)

	tests := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"create without name", http.MethodPost, "/api/v1/sdn/zones", NetworkZoneCreateRequest{}, http.StatusBadRequest},
		{"create a built-in", http.MethodPost, "/api/v1/sdn/zones", NetworkZoneCreateRequest{Name: "fabric"}, http.StatusConflict},
		{"reserved name", http.MethodPost, "/api/v1/sdn/zones", NetworkZoneCreateRequest{Name: "public", Offset: 9, PortClasses: []string{"gateway"}}, http.StatusBadRequest},
		{"unaudited path to control-plane", http.MethodPost, "/api/v1/sdn/zones", NetworkZoneCreateRequest{
			Name: "lab", Offset: 9, PortClasses: []string{"gateway"},
			AllowTo: []gateway.ZonePathSpec{{Zone: "control-plane"}},
		}, http.StatusBadRequest},
		{"renumber a built-in", http.MethodPut, "/api/v1/sdn/zones/storage", NetworkZoneUpdateRequest{Offset: 30}, http.StatusBadRequest},
		{"update unknown", http.MethodPut, "/api/v1/sdn/zones/nowhere", NetworkZoneUpdateRequest{}, http.StatusNotFound},
		{"delete a required built-in", http.MethodDelete, "/api/v1/sdn/zones/fabric", nil, http.StatusBadRequest},
		{"delete unknown", http.MethodDelete, "/api/v1/sdn/zones/nowhere", nil, http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := zoneCall(t, r, tc.method, tc.path, tc.body)
			assert.Equal(t, tc.want, w.Code, w.Body.String())
		})
	}

	for path, method := range map[string]string{
		"/api/v1/sdn/zones":         http.MethodPost,
		"/api/v1/sdn/zones/storage": http.MethodPut,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewBufferString("{")))
		assert.Equal(t, http.StatusBadRequest, w.Code, "%s %s with a malformed body", method, path)
	}
}

// TestZoneHandlers_NoZoneService answers 503 on every zone route.
func TestZoneHandlers_NoZoneService(t *testing.T) {
	h := NewSDNHandlers(nil, slog.Default())
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/sdn/zones"},
		{http.MethodPost, "/api/v1/sdn/zones"},
		{http.MethodPut, "/api/v1/sdn/zones/storage"},
		{http.MethodDelete, "/api/v1/sdn/zones/storage"},
	} {
		w := zoneCall(t, r, c.method, c.path, nil)
		assert.Equal(t, http.StatusServiceUnavailable, w.Code, "%s %s", c.method, c.path)
	}
	w := zoneCall(t, r, http.MethodPut, "/api/v1/sdn/networks/data/zone", map[string]string{"zone": "storage"})
	assert.Equal(t, http.StatusNotFound, w.Code, "assigning a network to a zone is gone: networks are zones")
}
