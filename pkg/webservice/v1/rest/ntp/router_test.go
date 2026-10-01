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

package ntp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// scriptedServer is a scripted platformv1.NTPServiceServer. The router is a
// thin binding, so the tests drive it directly instead of a real chronyd.
type scriptedServer struct {
	platformv1.UnimplementedNTPServiceServer

	status    *platformv1.NTPStatus
	sources   []*platformv1.NTPSource
	err       error
	stepCalls int
}

// GetStatus returns the scripted status.
func (s *scriptedServer) GetStatus(_ context.Context, _ *platformv1.GetNTPStatusRequest) (*platformv1.GetNTPStatusResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetNTPStatusResponse{Status: s.status}, nil
}

// ListSources returns the scripted sources.
func (s *scriptedServer) ListSources(_ context.Context, _ *platformv1.ListNTPSourcesRequest) (*platformv1.ListNTPSourcesResponse, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListNTPSourcesResponse{Sources: s.sources}, nil
}

// Step records the call and returns the scripted result.
func (s *scriptedServer) Step(_ context.Context, _ *platformv1.StepNTPClockRequest) (*platformv1.StepNTPClockResponse, error) {
	s.stepCalls++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.StepNTPClockResponse{Status: s.status}, nil
}

// newTestLogger builds a quiet logger for the router.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

// mountRouter mounts the NTP routes under /api/v1.
func mountRouter(server platformv1.NTPServiceServer) *mux.Router {
	router := mux.NewRouter()
	NewNTPRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

// envelope is the standard webservice response wrapper.
type envelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

func TestNTPRouterServesEveryOperation(t *testing.T) {
	server := &scriptedServer{
		status: &platformv1.NTPStatus{
			Synced:  true,
			Stratum: 3,
			Mode:    "both",
		},
		sources: []*platformv1.NTPSource{
			{Address: "10.4.200.1", State: "selected", Reachable: true},
		},
	}
	router := mountRouter(server)

	probes := []struct {
		name string
		verb string
		path string
	}{
		{"status", http.MethodGet, "/api/v1/ntp/status"},
		{"sources", http.MethodGet, "/api/v1/ntp/sources"},
		{"step", http.MethodPost, "/api/v1/ntp/step"},
	}

	for _, probe := range probes {
		t.Run(probe.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(probe.verb, probe.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if !body.Success || len(body.Payload) == 0 {
				t.Fatalf("envelope = %+v", body)
			}
		})
	}

	if server.stepCalls != 1 {
		t.Fatalf("step calls = %d, want 1", server.stepCalls)
	}
}

func TestNTPRouterReturns409WhenNoSourceIsReachable(t *testing.T) {
	router := mountRouter(&scriptedServer{
		err: status.Error(codes.Aborted, "ntp: no reachable time source (2 configured)"),
	})

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ntp/step", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409 (body %s)", rec.Code, rec.Body)
	}
}

func TestNTPRouterReturns503WithoutABackend(t *testing.T) {
	router := mountRouter(nil)

	for _, probe := range []struct {
		verb string
		path string
	}{
		{http.MethodGet, "/api/v1/ntp/status"},
		{http.MethodGet, "/api/v1/ntp/sources"},
		{http.MethodPost, "/api/v1/ntp/step"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(probe.verb, probe.path, nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s code = %d, want 503 (body %s)", probe.verb, probe.path, rec.Code, rec.Body)
		}
	}
}

func TestNTPRouterRejectsWrongMethods(t *testing.T) {
	router := mountRouter(&scriptedServer{status: &platformv1.NTPStatus{}})

	// Step is a mutation: it must not be reachable with GET.
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ntp/step", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /step code = %d, want 405", rec.Code)
	}
}

func TestNTPRouterSurfacesReadFailures(t *testing.T) {
	// The read paths must propagate a backend failure rather than
	// returning an empty 200, which would let a caller mistake a broken
	// control socket for a healthy clock.
	router := mountRouter(&scriptedServer{
		err: status.Error(codes.Unavailable, "ntp: chrony control command failed"),
	})

	for _, path := range []string{"/api/v1/ntp/status", "/api/v1/ntp/sources"} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("code = %d, want 503 (body %s)", rec.Code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if body.Success || body.Error == "" {
				t.Fatalf("envelope = %+v, want a failure with a message", body)
			}
		})
	}
}
