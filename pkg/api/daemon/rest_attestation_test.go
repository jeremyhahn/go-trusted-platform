package daemon

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

func attestationRESTServer(t *testing.T, server *AttestationServiceServer, guard *restapi.ScopeGuard) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := NewRESTServer(cfg, svc, quiet)
	require.NoError(t, err)
	s.SetAttestationHandlers(server, nil, nil, guard)
	return s
}

func serveAttestation(s *RESTServer, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	return rec
}

// The daemon listener serves /api/v1/attestation/* (#949): without it a
// platformd with no webservices section answered every attestation REST
// call with a bare 404.
func TestDaemonRESTAttestation_ServesTheRoutesBehindTheirScopes(t *testing.T) {
	tokens := tokenScopes{
		"reader":  {attestationReadScope},
		"writer":  {attestationWriteScope},
		"deleter": {attestationDeleteScope},
	}
	server := NewAttestationServiceServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := attestationRESTServer(t, server, restapi.NewScopeGuard(tokens, nil, nil))

	cases := []struct {
		name   string
		method string
		path   string
		token  string
		want   int
	}{
		{"read token lists manifests", http.MethodGet, "/api/v1/attestation/manifests", "reader", http.StatusOK},
		{"no token is unauthenticated", http.MethodGet, "/api/v1/attestation/manifests", "", http.StatusUnauthorized},
		{"read token cannot build", http.MethodPost, "/api/v1/attestation/manifests/build", "reader", http.StatusForbidden},
		{"write token cannot delete", http.MethodDelete, "/api/v1/attestation/manifests/m1", "writer", http.StatusForbidden},
		{"read token cannot collect a VM", http.MethodPost, "/api/v1/attestation/vm/vm-1", "reader", http.StatusForbidden},
		{"read token cannot quote", http.MethodPost, "/api/v1/attestation/quote", "reader", http.StatusForbidden},
		{"write token cannot read reports", http.MethodGet, "/api/v1/attestation/reports", "writer", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveAttestation(s, tc.method, tc.path, tc.token)
			assert.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}

	// A permitted call reaches the servicer: the route answers with the
	// servicer's verdict, never the router's 404.
	for _, call := range []struct{ method, path, token string }{
		{http.MethodPost, "/api/v1/attestation/manifests/build", "writer"},
		{http.MethodPost, "/api/v1/attestation/vm/vm-1", "writer"},
		{http.MethodDelete, "/api/v1/attestation/manifests/m1", "deleter"},
		{http.MethodGet, "/api/v1/attestation/callers", "reader"},
		{http.MethodGet, "/api/v1/attestation/reports", "reader"},
		{http.MethodGet, "/api/v1/attestation/events", "reader"},
	} {
		rec := serveAttestation(s, call.method, call.path, call.token)
		assert.NotContains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusUnauthorized, http.StatusForbidden},
			rec.Code, "%s %s: %s", call.method, call.path, rec.Body.String())
	}
}

func TestDaemonRESTAttestation_NilServerRegistersNoRoute(t *testing.T) {
	s := attestationRESTServer(t, nil, restapi.NewScopeGuard(tokenScopes{"reader": {attestationReadScope}}, nil, nil))
	rec := serveAttestation(s, http.MethodGet, "/api/v1/attestation/manifests", "reader")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDaemonRESTAttestation_NilGuardRefusesEveryCaller(t *testing.T) {
	server := NewAttestationServiceServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := attestationRESTServer(t, server, nil)
	rec := serveAttestation(s, http.MethodGet, "/api/v1/attestation/manifests", "reader")
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// Every route the attestation routers mount on the daemon has a scope; a
// route without one would be refused to every caller.
func TestDaemonRESTAttestation_EveryMountedRouteIsClassified(t *testing.T) {
	server := NewAttestationServiceServer(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := attestationRESTServer(t, server, nil)

	mounted := map[string]bool{}
	err := s.Router().Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/api/v1/attestation/") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			mounted[m+" "+template] = true
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, mounted)
	for route := range mounted {
		assert.Contains(t, attestationRouteScopes, route, "mounted but unclassified")
	}
	for route := range attestationRouteScopes {
		assert.True(t, mounted[route], "classified but not mounted: %s", route)
	}
}

func TestAttestationScopeGuard_RefusesAnUnclassifiedRoute(t *testing.T) {
	var written error
	writeError := func(w http.ResponseWriter, status int, err error) {
		written = err
		w.WriteHeader(status)
	}
	router := mux.NewRouter()
	router.Use(attestationScopeGuard(restapi.NewScopeGuard(tokenScopes{"all": {"*:*"}}, nil, nil), writeError))
	router.HandleFunc("/api/v1/attestation/unlisted", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attestation/unlisted", nil)
	req.Header.Set("Authorization", "Bearer all")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	var unclassified ErrAttestationRouteUnclassified
	require.True(t, errors.As(written, &unclassified))
	assert.Equal(t, "GET /api/v1/attestation/unlisted", unclassified.Route)
}
