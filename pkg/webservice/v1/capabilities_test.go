// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// decodeCapabilities reads the platform envelope and indexes the
// capability entries by op.
func decodeCapabilities(t *testing.T, rec *httptest.ResponseRecorder) map[string]Capability {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var envelope struct {
		Payload CapabilitiesResponse `json:"payload"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&envelope))
	require.NotEmpty(t, envelope.Payload.Capabilities, "an empty listing proves nothing")
	out := make(map[string]Capability, len(envelope.Payload.Capabilities))
	for _, c := range envelope.Payload.Capabilities {
		_, dup := out[c.Op]
		require.Falsef(t, dup, "op %q listed twice", c.Op)
		out[c.Op] = c
	}
	return out
}

// capabilitiesFixture builds a v1 table the way RegisterRoutes does: a
// configured service, a service whose backend is nil (turned off in the
// config) and a stub route, then the capabilities listing over it.
func capabilitiesFixture(t *testing.T) *mux.Router {
	t.Helper()
	logger := testLogger()
	writer := response.NewResponseWriter(logger, nil)
	services := NewServiceRegistry(logger, writer)

	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

	services.requireService(api, "ntp", "/ntp", struct{}{}, func() {
		api.HandleFunc("/ntp/status", ok).Methods(http.MethodGet)
		api.HandleFunc("/ntp/servers", ok).Methods(http.MethodPost, http.MethodDelete)
	})
	services.requireService(api, "dns", "/dns", nil, func() {
		t.Fatal("a nil dns backend must not register its routes")
	})

	stubs := recordNewRoutes(api, func() {
		api.HandleFunc("/quicbaas/kv", ok).Methods(http.MethodGet)
	})

	registerCapabilitiesEndpoint(api, services, stubs, writer, nil)
	return root
}

func getCapabilities(t *testing.T, router http.Handler) map[string]Capability {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	return decodeCapabilities(t, rec)
}

func TestCapabilities_ReturnsJSONListing(t *testing.T) {
	caps := getCapabilities(t, capabilitiesFixture(t))
	for op, c := range caps {
		require.NotEmpty(t, c.Kind, "op %q has no kind", op)
		if c.Enabled {
			require.Emptyf(t, c.Reason, "enabled op %q carries a reason", op)
		} else {
			require.NotEmptyf(t, c.Reason, "disabled op %q carries no reason", op)
		}
	}
}

func TestCapabilities_RegisteredRouteIsEnabled(t *testing.T) {
	caps := getCapabilities(t, capabilitiesFixture(t))

	for _, op := range []string{
		"GET /api/v1/ntp/status",
		"POST /api/v1/ntp/servers",
		"DELETE /api/v1/ntp/servers",
	} {
		c, found := caps[op]
		require.Truef(t, found, "registered route %q is missing from the listing", op)
		require.Truef(t, c.Enabled, "registered route %q is listed disabled: %s", op, c.Reason)
		require.Equal(t, CapabilityKindRoute, c.Kind)
		require.Equal(t, "ntp", c.Service)
	}

	svc, found := caps["ntp"]
	require.True(t, found, "the configured ntp service is missing")
	require.Equal(t, CapabilityKindService, svc.Kind)
	require.True(t, svc.Enabled)
}

func TestCapabilities_ServiceOffInConfigIsDisabled(t *testing.T) {
	caps := getCapabilities(t, capabilitiesFixture(t))

	svc, found := caps["dns"]
	require.True(t, found, "a service turned off in the config must still be listed")
	require.Equal(t, CapabilityKindService, svc.Kind)
	require.False(t, svc.Enabled)
	require.Equal(t, "not-configured: dns", svc.Reason)

	// The 503 catch-alls requireService mounts for the dark service are
	// listed under it, disabled with the same reason.
	darkRoutes := 0
	for op, c := range caps {
		if c.Kind != CapabilityKindRoute || c.Service != "dns" {
			continue
		}
		darkRoutes++
		require.Falsef(t, c.Enabled, "dark dns route %q listed enabled", op)
		require.Equal(t, "not-configured: dns", c.Reason)
	}
	require.NotZero(t, darkRoutes, "the dark dns surface lists no routes")
}

func TestCapabilities_StubRoutesAreBlockedOnIntegration(t *testing.T) {
	caps := getCapabilities(t, capabilitiesFixture(t))

	c, found := caps["GET /api/v1/quicbaas/kv"]
	require.True(t, found)
	require.False(t, c.Enabled)
	require.Equal(t, CapabilityReasonBlockedIntegration, c.Reason)
}

// The real table: the endpoint is mounted by RegisterRoutes, refuses an
// anonymous caller and lists the platform for an authenticated one.
func TestCapabilities_RegisterRoutesRequiresAnAuthenticatedCaller(t *testing.T) {
	anonymous := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &anonymousAuth{}})
	require.Equal(t, http.StatusUnauthorized,
		probe(anonymous, http.MethodGet, "/api/v1/capabilities"))

	authed := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: &sessionAuth{}})
	caps := getCapabilities(t, authed)

	self, found := caps["GET /api/v1/capabilities"]
	require.True(t, found, "the listing omits its own route")
	require.True(t, self.Enabled)

	stub, found := caps["GET /api/v1/quicbaas/kv"]
	require.True(t, found, "the quicbaas stub routes are missing")
	require.False(t, stub.Enabled)
	require.Equal(t, CapabilityReasonBlockedIntegration, stub.Reason)
}
