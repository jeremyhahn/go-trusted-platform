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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func TestServiceRegistry_RecordsConfiguredService(t *testing.T) {
	r := newRegistry(t)
	mr := mux.NewRouter()

	called := false
	r.requireService(mr, "vtpm", "/vtpm", &fakeService{}, func() { called = true })

	if !called {
		t.Fatal("register callback was not invoked for non-nil service")
	}
	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(snap))
	}
	if !snap[0].Configured {
		t.Fatalf("entry should be Configured: %+v", snap[0])
	}
	if snap[0].Reason != "" {
		t.Fatalf("Configured entry should have empty Reason, got %q", snap[0].Reason)
	}
}

func TestServiceRegistry_NilServiceTriggers503Stub(t *testing.T) {
	r := newRegistry(t)
	mr := mux.NewRouter()

	called := false
	// Literal nil: the original silent-skip path.
	r.requireService(mr, "vtpm", "/vtpm", nil, func() { called = true })

	if called {
		t.Fatal("register callback ran despite nil service")
	}
	snap := r.Snapshot()
	if len(snap) != 1 || snap[0].Configured {
		t.Fatalf("expected one unconfigured entry, got %+v", snap)
	}
	if snap[0].Reason == "" {
		t.Fatal("Unconfigured entry should carry a Reason for operators")
	}

	// GET /vtpm and /vtpm/templates both hit the catch-all 503.
	for _, path := range []string{"/vtpm", "/vtpm/templates", "/vtpm/templates/xyz"} {
		rec := httptest.NewRecorder()
		mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503", path, rec.Code)
		}
		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("%s: decode 503 body: %v", path, err)
		}
		if got, _ := body["service"].(string); got != "vtpm" {
			t.Fatalf("%s: service in body = %q, want %q", path, got, "vtpm")
		}
	}
}

func TestServiceRegistry_StubDoesNotShadowUnrelatedRoutes(t *testing.T) {
	r := newRegistry(t)
	mr := mux.NewRouter()
	r.requireService(mr, "vtpm", "/vtpm", nil, func() {})

	// /vtpm-extras is not /vtpm/... — must not be captured by the stub.
	mr.HandleFunc("/vtpm-extras", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vtpm-extras", nil))
	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("/vtpm-extras: status=%d body=%s; the 503 stub leaked beyond its prefix", rec.Code, string(body))
	}
}

func TestServiceRegistry_StatusEndpoint(t *testing.T) {
	r := newRegistry(t)
	mr := mux.NewRouter()

	r.requireService(mr, "vtpm", "/vtpm", nil, func() {})
	r.requireService(mr, "dns", "/dns", &fakeService{}, func() {})
	r.RegisterStatusEndpoint(mr)

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/platform/service-registry", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	// The platform response envelope wraps the body in {code, error,
	// success, payload}. Decode loosely and check the payload.
	var envelope map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	payload, ok := envelope["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload in envelope: %+v", envelope)
	}
	if got, _ := payload["total"].(float64); int(got) != 2 {
		t.Fatalf("total = %v, want 2", payload["total"])
	}
	if got, _ := payload["configured"].(float64); int(got) != 1 {
		t.Fatalf("configured = %v, want 1", payload["configured"])
	}
	if got, _ := payload["dark"].(float64); int(got) != 1 {
		t.Fatalf("dark = %v, want 1", payload["dark"])
	}
}

func TestServiceRegistry_TypedNilTreatedAsUnconfigured(t *testing.T) {
	r := newRegistry(t)
	mr := mux.NewRouter()

	var typedNil *fakeService // typed-nil — interface carries (*fakeService, nil)
	called := false
	r.requireService(mr, "typednil", "/typednil", typedNil, func() { called = true })

	if called {
		t.Fatal("register callback ran for a typed-nil service (classic Go gotcha)")
	}
	snap := r.Snapshot()
	if len(snap) != 1 || snap[0].Configured {
		t.Fatalf("typed nil should be Unconfigured, got %+v", snap)
	}
}

// --- test helpers ---

type fakeService struct{}

func (f *fakeService) doNothing() {}

func newRegistry(t *testing.T) *ServiceRegistry {
	t.Helper()
	// Discard logger so test output stays clean; the registry only logs
	// Warn lines we don't want to assert on at this level.
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	writer := response.NewResponseWriter(logger, nil)
	return NewServiceRegistry(logger, writer)
}
