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

package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newTestRESTServerForPhase35 builds a bare REST server suitable for route
// registration tests. It avoids the full daemon lifecycle so the test stays
// fast and hermetic.
func newTestRESTServerForPhase35(t *testing.T) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	s, err := NewRESTServer(cfg, svc, slog.Default())
	if err != nil {
		t.Fatalf("NewRESTServer: %v", err)
	}
	return s
}

// doJSON performs a synthetic HTTP request against the server's router.
// Returns the status code and response body for assertion.
func doJSON(t *testing.T, s *RESTServer, method, path string, body interface{}) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

// =============================================================================
// Ceremony REST routes
// =============================================================================

func TestRESTServer_CeremonyRoutesNotMountedWithoutService(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/ceremony/status", nil)
	if code != http.StatusNotFound {
		t.Errorf("without SetCeremonyService: want 404, got %d", code)
	}
}

func TestRESTServer_CeremonyRoutesMounted(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	svc := NewCeremonyService(logging.DefaultLogger(), &fakeCeremonyBackend{})
	s.SetCeremonyService(svc)

	code, body := doJSON(t, s, http.MethodGet, "/api/v1/ceremony/status", nil)
	if code != http.StatusOK {
		t.Errorf("GET /ceremony/status: want 200, got %d (body=%s)", code, body)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if _, ok := resp["state"]; !ok {
		t.Errorf("expected state field in response, got %v", resp)
	}

	// POST /ceremony/init routes to Init on the service backend.
	code, body = doJSON(t, s, http.MethodPost, "/api/v1/ceremony/init", map[string]interface{}{
		"so_pin": "1234", "threshold": "2-of-3",
	})
	if code != http.StatusOK {
		t.Errorf("POST /ceremony/init: want 200, got %d (body=%s)", code, body)
	}
}

func TestRESTServer_CeremonyRoutes_BackendNotConfigured(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	// Wire a service with a nil backend. The service layer returns
	// ErrCeremonyNotConfigured which the handler maps to 503.
	svc := NewCeremonyService(logging.DefaultLogger(), nil)
	s.SetCeremonyService(svc)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/ceremony/status", nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("want 503 from unconfigured backend, got %d", code)
	}
}

func TestRESTServer_SetCeremonyService_Nil(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	// Passing nil should be a no-op.
	s.SetCeremonyService(nil)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/ceremony/status", nil)
	if code != http.StatusNotFound {
		t.Errorf("want 404 after nil SetCeremonyService, got %d", code)
	}
}

// =============================================================================
// PIV REST routes
// =============================================================================

func TestRESTServer_PIVRoutesMounted(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	svc := NewPIVService(logging.DefaultLogger(), &fakePIVBackend{
		devices: []PIVDevice{{ID: "yk5", Name: "YubiKey"}},
	})
	s.SetPIVService(svc)

	code, body := doJSON(t, s, http.MethodGet, "/api/v1/piv/devices", nil)
	if code != http.StatusOK {
		t.Errorf("GET /piv/devices: want 200, got %d (body=%s)", code, body)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if _, ok := resp["devices"]; !ok {
		t.Errorf("expected devices field in response, got %v", resp)
	}
}

func TestRESTServer_PIVRoutes_NotMountedWithoutService(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/piv/devices", nil)
	if code != http.StatusNotFound {
		t.Errorf("without SetPIVService: want 404, got %d", code)
	}
}

func TestRESTServer_SetPIVService_Nil(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetPIVService(nil)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/piv/devices", nil)
	if code != http.StatusNotFound {
		t.Errorf("want 404 after nil SetPIVService, got %d", code)
	}
}

// =============================================================================
// LUKS REST routes
// =============================================================================

func TestRESTServer_LUKSRoutesMounted(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	svc := NewLUKSService(logging.DefaultLogger(), &fakeLUKSBackend{},
		RootCheckerFunc(func() bool { return true }))
	s.SetLUKSService(svc)

	code, body := doJSON(t, s, http.MethodGet, "/api/v1/luks/status?device=/dev/x", nil)
	if code != http.StatusOK {
		t.Errorf("GET /luks/status: want 200, got %d (body=%s)", code, body)
	}
}

func TestRESTServer_LUKSRoutes_NotMountedWithoutService(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/luks/status?device=/dev/x", nil)
	if code != http.StatusNotFound {
		t.Errorf("without SetLUKSService: want 404, got %d", code)
	}
}

func TestRESTServer_SetLUKSService_Nil(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetLUKSService(nil)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/luks/status?device=/dev/x", nil)
	if code != http.StatusNotFound {
		t.Errorf("want 404 after nil SetLUKSService, got %d", code)
	}
}

// =============================================================================
// FIDO2 REST routes
// =============================================================================

func TestRESTServer_FIDO2RoutesMounted(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	svc := NewFIDO2Service(logging.DefaultLogger(), &fakeFIDO2Backend{})
	s.SetFIDO2Service(svc)

	code, body := doJSON(t, s, http.MethodGet, "/api/v1/fido2/devices", nil)
	if code != http.StatusOK {
		t.Errorf("GET /fido2/devices: want 200, got %d (body=%s)", code, body)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if _, ok := resp["devices"]; !ok {
		t.Errorf("expected devices field in response, got %v", resp)
	}
}

func TestRESTServer_FIDO2Routes_NotMountedWithoutService(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/fido2/devices", nil)
	if code != http.StatusNotFound {
		t.Errorf("without SetFIDO2Service: want 404, got %d", code)
	}
}

func TestRESTServer_SetFIDO2Service_Nil(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetFIDO2Service(nil)
	code, _ := doJSON(t, s, http.MethodGet, "/api/v1/fido2/devices", nil)
	if code != http.StatusNotFound {
		t.Errorf("want 404 after nil SetFIDO2Service, got %d", code)
	}
}

// =============================================================================
// Error-translation covers Phase 3.5 not-configured → 503
// =============================================================================

func TestRESTServer_Phase35Errors_MapTo503(t *testing.T) {
	cases := []struct {
		name   string
		wireup func(s *RESTServer)
		path   string
	}{
		{
			name: "piv",
			wireup: func(s *RESTServer) {
				s.SetPIVService(NewPIVService(logging.DefaultLogger(), nil))
			},
			path: "/api/v1/piv/devices",
		},
		{
			name: "luks",
			wireup: func(s *RESTServer) {
				s.SetLUKSService(NewLUKSService(logging.DefaultLogger(), nil,
					RootCheckerFunc(func() bool { return true })))
			},
			path: "/api/v1/luks/status?device=/dev/x",
		},
		{
			name: "fido2",
			wireup: func(s *RESTServer) {
				s.SetFIDO2Service(NewFIDO2Service(logging.DefaultLogger(), nil))
			},
			path: "/api/v1/fido2/devices",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newTestRESTServerForPhase35(t)
			c.wireup(s)
			code, _ := doJSON(t, s, http.MethodGet, c.path, nil)
			if code != http.StatusServiceUnavailable {
				t.Errorf("%s: want 503, got %d", c.name, code)
			}
		})
	}
}
