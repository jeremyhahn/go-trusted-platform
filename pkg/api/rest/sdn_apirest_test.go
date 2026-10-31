package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdnErrorMessage decodes the SDNErrorResponse an SDN handler wrote.
func sdnErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp SDNErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, rec.Code, resp.Code, "the body carries the status it was sent with")
	return resp.Error
}

// sdnServe sends one request through a router built on the SDN handlers.
func sdnServe(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

// zoneStoreFault is a zone store whose every call fails with a fault that is
// neither a not-found, a conflict nor a validation error.
type zoneStoreFault struct {
	gateway.ZoneService
	err error
}

func (z zoneStoreFault) Create(context.Context, zone.ZoneConfig) (*gateway.ZoneRecord, bool, error) {
	return nil, false, z.err
}

func (z zoneStoreFault) Update(context.Context, zone.Zone, zone.ZoneConfig) (*gateway.ZoneRecord, bool, error) {
	return nil, false, z.err
}

func (z zoneStoreFault) Delete(context.Context, zone.Zone) (bool, error) {
	return false, z.err
}

func (z zoneStoreFault) List(context.Context, zone.LifecycleRole) ([]*gateway.ZoneRecord, error) {
	return nil, z.err
}

type zoneStoreFaultError struct{}

func (zoneStoreFaultError) Error() string { return "zone store unavailable" }

// The router never yields an empty path variable; the zone handlers still
// refuse one when called directly, so a mis-registered route cannot reach the
// zone store with an empty name.
func TestSDNAPIRest_EmptyZoneName(t *testing.T) {
	t.Parallel()
	h := NewSDNHandlers(nil, slog.Default())
	h.SetZoneService(zoneStoreFault{err: zoneStoreFaultError{}})
	want := (&MessageError{Msg: "zone name is required"}).Error()

	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"update zone", h.handleUpdateNetworkZone},
		{"delete zone", h.handleDeleteNetworkZone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), map[string]string{"name": ""})
			rec := httptest.NewRecorder()

			tc.handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, want, sdnErrorMessage(t, rec))
		})
	}
}

func TestSDNAPIRest_ZoneStoreFault(t *testing.T) {
	t.Parallel()
	h := NewSDNHandlers(nil, slog.Default())
	h.SetZoneService(zoneStoreFault{err: zoneStoreFaultError{}})
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"create", http.MethodPost, "/api/v1/sdn/zones", `{"name":"lab"}`},
		{"list", http.MethodGet, "/api/v1/sdn/zones?lifecycle_role=tenant", ""},
		{"update", http.MethodPut, "/api/v1/sdn/zones/lab", `{}`},
		{"delete", http.MethodDelete, "/api/v1/sdn/zones/lab", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec := sdnServe(router, tc.method, tc.path, tc.body)

			assert.Equal(t, http.StatusInternalServerError, rec.Code, "a store fault is the server's, not the caller's")
			assert.Equal(t, zoneStoreFaultError{}.Error(), sdnErrorMessage(t, rec))
		})
	}
}

func TestSDNAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	t.Parallel()
	h := NewSDNHandlers(nil, slog.Default())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
