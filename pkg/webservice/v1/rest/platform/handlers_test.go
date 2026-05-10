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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

func TestGetHealth_WithoutRegistry(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/health", nil)
	rec := httptest.NewRecorder()

	handlers.GetHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}
	healthBlock, ok := payload["health"].(map[string]interface{})
	if !ok {
		t.Fatal("expected payload.health to be a map")
	}
	if healthy, _ := healthBlock["healthy"].(bool); !healthy {
		t.Error("expected health.healthy to be true when no registry is configured")
	}
}

func TestGetHealth_WithRegistry(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	registry := health.NewRegistry()
	handlers.SetHealthRegistry(registry)

	registry.Register(&mockHealthChecker{
		name:   "test-component",
		status: health.StatusHealthy,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/health", nil)
	rec := httptest.NewRecorder()

	handlers.GetHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}
	healthBlock, ok := payload["health"].(map[string]interface{})
	if !ok {
		t.Fatal("expected payload.health to be a map")
	}

	if status, _ := healthBlock["status"].(string); status != "healthy" {
		t.Errorf("expected health.status 'healthy', got '%v'", healthBlock["status"])
	}
	if healthy, _ := healthBlock["healthy"].(bool); !healthy {
		t.Error("expected health.healthy to be true")
	}
	services, ok := healthBlock["services"].([]interface{})
	if !ok || len(services) != 1 {
		t.Fatalf("expected one service in health.services, got %v", healthBlock["services"])
	}
	svc, _ := services[0].(map[string]interface{})
	if name, _ := svc["name"].(string); name != "test-component" {
		t.Errorf("expected service name 'test-component', got %v", svc["name"])
	}
}

func TestGetStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/status", nil)
	rec := httptest.NewRecorder()

	handlers.GetStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}

	// Verify payload structure
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}

	// Check required fields
	if _, ok := payload["status"]; !ok {
		t.Error("expected payload to contain 'status'")
	}
	if _, ok := payload["version"]; !ok {
		t.Error("expected payload to contain 'version'")
	}
	if _, ok := payload["go_version"]; !ok {
		t.Error("expected payload to contain 'go_version'")
	}
	if _, ok := payload["system"]; !ok {
		t.Error("expected payload to contain 'system'")
	}
}

func TestGetVersion(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/version", nil)
	rec := httptest.NewRecorder()

	handlers.GetVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success to be true")
	}

	// Verify payload structure
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}

	// Check required fields
	if _, ok := payload["version"]; !ok {
		t.Error("expected payload to contain 'version'")
	}
	if _, ok := payload["go_version"]; !ok {
		t.Error("expected payload to contain 'go_version'")
	}
}

func TestGetMetrics_DashboardShape(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	registry := health.NewRegistry()
	handlers.SetHealthRegistry(registry)
	registry.Register(&mockHealthChecker{
		name:   "tpm",
		status: health.StatusHealthy,
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/metrics", nil)
	rec := httptest.NewRecorder()
	handlers.GetMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp response.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if !resp.Success {
		t.Error("expected success")
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload map")
	}
	metrics, ok := payload["metrics"].(map[string]interface{})
	if !ok {
		t.Fatal("expected payload.metrics map")
	}
	if _, ok := metrics["cpuUsagePercent"]; !ok {
		t.Error("expected metrics.cpuUsagePercent field")
	}
	if _, ok := metrics["memoryUsagePercent"]; !ok {
		t.Error("expected metrics.memoryUsagePercent field")
	}
	if _, ok := metrics["diskUsagePercent"]; !ok {
		t.Error("expected metrics.diskUsagePercent field")
	}
	if _, ok := metrics["timestamp"].(string); !ok {
		t.Error("expected metrics.timestamp string")
	}
	services, ok := metrics["services"].([]interface{})
	if !ok || len(services) != 1 {
		t.Fatalf("expected one entry in metrics.services, got %v", metrics["services"])
	}
}

// mockHealthChecker is a simple mock for testing
type mockHealthChecker struct {
	name   string
	status health.HealthStatus
}

func (m *mockHealthChecker) Name() string {
	return m.name
}

func (m *mockHealthChecker) Check(ctx context.Context) health.ComponentHealth {
	return health.ComponentHealth{
		Name:        m.name,
		Status:      m.status,
		Message:     "test component healthy",
		LastChecked: time.Now(),
	}
}
