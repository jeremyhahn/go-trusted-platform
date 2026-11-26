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

package platform

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// serveProbe registers the platform routes under /api/v1, optionally with a
// health registry, and serves one GET of path through the root router. It
// returns the recorder and the decoded envelope payload.
func serveProbe(t *testing.T, registry health.Registry, path string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	platformRouter := NewPlatformRouter(logger, respWriter)
	if registry != nil {
		platformRouter.SetHealthRegistry(registry)
	}
	root, apiRouter := newTestRouter()
	platformRouter.RegisterRoutes(apiRouter)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: expected status %d, got %d (body %q)", path, http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp restwire.WebServiceResponse
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success to be true")
	}
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("expected payload to be a map, got %T", resp.Payload)
	}
	return rec, payload
}

func assertProbeTimestamp(t *testing.T, payload map[string]interface{}) {
	t.Helper()
	ts, _ := payload["timestamp"].(string)
	if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("timestamp %q does not parse as RFC3339Nano: %v", ts, err)
	}
}

func TestPlatformProbes_LivenessAlive(t *testing.T) {
	_, payload := serveProbe(t, nil, "/api/v1/platform/liveness")

	if alive, ok := payload["alive"].(bool); !ok || !alive {
		t.Errorf("expected alive true, got %v", payload["alive"])
	}
	if status, _ := payload["status"].(string); status != "healthy" {
		t.Errorf("expected status 'healthy', got %v", payload["status"])
	}
	assertProbeTimestamp(t, payload)
}

func TestPlatformProbes_ReadinessWithoutRegistry(t *testing.T) {
	_, payload := serveProbe(t, nil, "/api/v1/platform/readiness")

	if ready, ok := payload["ready"].(bool); !ok || !ready {
		t.Errorf("expected ready true, got %v", payload["ready"])
	}
	if status, _ := payload["status"].(string); status != "healthy" {
		t.Errorf("expected status 'healthy', got %v", payload["status"])
	}
	assertProbeTimestamp(t, payload)
}

func TestPlatformProbes_ReadinessUnhealthy(t *testing.T) {
	registry := health.NewRegistry()
	registry.Register(&mockHealthChecker{name: "db", status: health.StatusUnhealthy})

	rec, payload := serveProbe(t, registry, "/api/v1/platform/readiness")

	if ready, ok := payload["ready"].(bool); !ok || ready {
		t.Errorf("expected ready false, got %v", payload["ready"])
	}
	if status, _ := payload["status"].(string); status != "unhealthy" {
		t.Errorf("expected status 'unhealthy', got %v", payload["status"])
	}
	if strings.Contains(rec.Body.String(), "db") {
		t.Errorf("readiness body names a component: %q", rec.Body.String())
	}
	assertProbeTimestamp(t, payload)
}

func TestPlatformProbes_ReadinessDegradedIsReady(t *testing.T) {
	registry := health.NewRegistry()
	registry.Register(&mockHealthChecker{name: "cache", status: health.StatusDegraded})

	_, payload := serveProbe(t, registry, "/api/v1/platform/readiness")

	if ready, ok := payload["ready"].(bool); !ok || !ready {
		t.Errorf("expected ready true, got %v", payload["ready"])
	}
	if status, _ := payload["status"].(string); status != "degraded" {
		t.Errorf("expected status 'degraded', got %v", payload["status"])
	}
}
