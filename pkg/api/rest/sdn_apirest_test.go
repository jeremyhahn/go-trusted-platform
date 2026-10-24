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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
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

// The router never yields an empty path variable; the handlers still refuse
// one when called directly, so a mis-registered route cannot reach OVS with
// an empty bridge, port or flow.
func TestSDNAPIRest_EmptyPathVariables(t *testing.T) {
	t.Parallel()
	svc := newMockSDNService()
	h, _ := setupSDNTestHandler(svc)
	h.SetZoneService(zoneStoreFault{err: zoneStoreFaultError{}})

	bridgeOrPort := ErrMissingRequiredField{Field: "bridge_id or port_id"}.Error()
	zoneName := (&MessageError{Msg: "zone name is required"}).Error()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		vars    map[string]string
		want    string
	}{
		{"get bridge", h.handleGetBridge, map[string]string{"id": ""}, ErrInvalidBridgeID{}.Error()},
		{"delete bridge", h.handleDeleteBridge, map[string]string{"id": ""}, ErrInvalidBridgeID{}.Error()},
		{"add port", h.handleAddPort, map[string]string{"id": ""}, ErrInvalidBridgeID{}.Error()},
		{"list ports", h.handleListPorts, map[string]string{"id": ""}, ErrInvalidBridgeID{}.Error()},
		{"remove port without bridge", h.handleRemovePort, map[string]string{"id": "", "port": "p"}, ErrInvalidBridgeID{}.Error()},
		{"remove port without port", h.handleRemovePort, map[string]string{"id": "br0", "port": ""}, ErrInvalidPortID{}.Error()},
		{"delete flow", h.handleDeleteFlow, map[string]string{"id": ""}, ErrInvalidFlowID{}.Error()},
		{"get port state", h.handleGetPortState, map[string]string{"id": "br0", "port": ""}, bridgeOrPort},
		{"set port state", h.handleSetPortState, map[string]string{"id": "", "port": "p"}, bridgeOrPort},
		{"get port stats", h.handleGetPortStats, map[string]string{"id": "br0", "port": ""}, bridgeOrPort},
		{"add bridge flow", h.handleAddFlowForBridge, map[string]string{"id": ""}, ErrMissingRequiredField{Field: "bridge_id"}.Error()},
		{"list bridge flows", h.handleListFlowsForBridge, map[string]string{"id": ""}, ErrMissingRequiredField{Field: "bridge_id"}.Error()},
		{"delete bridge flow", h.handleDeleteFlowForBridge, map[string]string{"id": "br0", "flow_id": ""}, ErrMissingRequiredField{Field: "bridge_id or flow_id"}.Error()},
		{"update zone", h.handleUpdateNetworkZone, map[string]string{"name": ""}, zoneName},
		{"delete zone", h.handleDeleteNetworkZone, map[string]string{"name": ""}, zoneName},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")), tc.vars)
			rec := httptest.NewRecorder()

			tc.handler(rec, req)

			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want, sdnErrorMessage(t, rec))
		})
	}
	assert.Empty(t, svc.deletedCookies, "no refused request reaches OVS")
	assert.Empty(t, svc.portStates, "no refused request reaches OVS")
}

func TestSDNAPIRest_MalformedFlowIDs(t *testing.T) {
	t.Parallel()
	svc := newMockSDNService()
	_, router := setupSDNTestHandler(svc)

	t.Run("delete flow", func(t *testing.T) {
		_, want := ovs.ParseFlowID("bogus")
		require.Error(t, want)

		rec := sdnServe(router, http.MethodDelete, "/api/v1/sdn/flows/bogus?bridge_id=br0", "")

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, want.Error(), sdnErrorMessage(t, rec))
	})

	t.Run("add bridge flow with a bad cookie", func(t *testing.T) {
		_, want := ovs.ParseFlowID(ovs.FlowIDPrefix + "zz")
		require.Error(t, want)
		body, err := json.Marshal(AddFlowRequest{Cookie: "zz", Match: "in_port=1", Actions: "drop"})
		require.NoError(t, err)

		rec := sdnServe(router, http.MethodPost, "/api/v1/sdn/bridges/br0/flows", string(body))

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, want.Error(), sdnErrorMessage(t, rec))
	})

	assert.Empty(t, svc.deletedCookies, "a malformed flow ID never deletes a flow")
	assert.Empty(t, svc.flows["br0"], "a malformed cookie never adds a flow")
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
	h, _ := setupSDNTestHandler(newMockSDNService())
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusCreated, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusCreated, rec.Code, "the status is already sent when encoding fails")
	assert.Empty(t, rec.Body.String(), "nothing of the unencodable value is written")
}
