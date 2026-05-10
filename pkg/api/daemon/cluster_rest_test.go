// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestRESTServer_ClusterRoutesMounted_NoBackend verifies that
// SetClusterService(nil) still mounts the routes so the dashboard sees
// 503 (not 404). 503 lets the WebUI render an actionable empty state.
func TestRESTServer_ClusterRoutesMounted_NoBackend(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	s.SetClusterService(nil)

	code, body := doJSON(t, s, http.MethodGet, "/api/v1/cluster/status", nil)
	if code != http.StatusServiceUnavailable {
		t.Errorf("GET /cluster/status: want 503, got %d (body=%s)", code, body)
	}
	var resp map[string]string
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if resp["error"] == "" {
		t.Errorf("expected error message, got %v", resp)
	}
}

// TestRESTServer_ClusterRoutesMounted_StubBackend verifies the routes
// hand off to the gRPC stub which returns codes.Unimplemented (mapped
// to 503 by clusterErrorToHTTP).
func TestRESTServer_ClusterRoutesMounted_StubBackend(t *testing.T) {
	s := newTestRESTServerForPhase35(t)
	stub := NewClusterGRPCService(logging.DefaultLogger())
	s.SetClusterService(stub)

	tests := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodGet, "/api/v1/cluster/status", nil},
		{http.MethodGet, "/api/v1/cluster/nodes", nil},
		{http.MethodPost, "/api/v1/cluster/bootstrap", map[string]string{}},
		{http.MethodPost, "/api/v1/cluster/join", map[string]string{}},
		{http.MethodPost, "/api/v1/cluster/leave", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			code, body := doJSON(t, s, tt.method, tt.path, tt.body)
			// gRPC stub returns codes.Unimplemented -> HTTP 503
			if code != http.StatusServiceUnavailable {
				t.Errorf("want 503, got %d (body=%s)", code, body)
			}
		})
	}
}
