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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

func TestGetStatus_WithVersionInfo(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	handlers.SetVersionInfo(&VersionInfo{
		Version:   "1.2.3",
		BuildDate: "2026-01-01T00:00:00Z",
		GitHash:   "abc123def",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/status", nil)
	rec := httptest.NewRecorder()

	handlers.GetStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp restwire.WebServiceResponse
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

	if v, ok := payload["version"].(string); !ok || v != "1.2.3" {
		t.Errorf("expected version '1.2.3', got '%v'", payload["version"])
	}

	if v, ok := payload["build_time"].(string); !ok || v != "2026-01-01T00:00:00Z" {
		t.Errorf("expected build_time '2026-01-01T00:00:00Z', got '%v'", payload["build_time"])
	}

	if v, ok := payload["git_commit"].(string); !ok || v != "abc123def" {
		t.Errorf("expected git_commit 'abc123def', got '%v'", payload["git_commit"])
	}
}

func TestGetVersion_WithVersionInfo(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	handlers.SetVersionInfo(&VersionInfo{
		Version:   "2.0.0-beta",
		BuildDate: "2026-03-15T12:00:00Z",
		GitHash:   "deadbeef",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/version", nil)
	rec := httptest.NewRecorder()

	handlers.GetVersion(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp restwire.WebServiceResponse
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

	if v, ok := payload["version"].(string); !ok || v != "2.0.0-beta" {
		t.Errorf("expected version '2.0.0-beta', got '%v'", payload["version"])
	}
}

func TestGetProtocols_WithRESTServerStopped(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	config := &ProtocolConfig{
		EnableREST:     true,
		RESTListenAddr: "0.0.0.0:8443",
		SocketPath:     "/run/platformd.sock",
	}
	handlers.SetProtocolConfig(config)
	handlers.SetRESTServerRunningFunc(func() bool {
		return false
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/protocols", nil)
	rec := httptest.NewRecorder()

	handlers.GetProtocols(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}

	protocols, ok := payload["protocols"].([]interface{})
	if !ok {
		t.Fatal("expected protocols to be an array")
	}

	for _, p := range protocols {
		proto, _ := p.(map[string]interface{})
		if proto["name"] == "REST" {
			status, _ := proto["status"].(string)
			if status != "stopped" {
				t.Errorf("expected REST status 'stopped', got '%s'", status)
			}
		}
	}
}

func TestServiceTypeFromName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"tpm", "SERVICE_TYPE_TPM"},
		{"sdn", "SERVICE_TYPE_SDN"},
		{"compute", "SERVICE_TYPE_COMPUTE"},
		{"dns", "SERVICE_TYPE_DNS"},
		{"acme", "SERVICE_TYPE_ACME"},
		{"webservice", "SERVICE_TYPE_WEBSERVICE"},
		{"attestation", "SERVICE_TYPE_ATTESTATION"},
		{"unknown", "SERVICE_TYPE_UNSPECIFIED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := serviceTypeFromName(tt.name)
			if result.String() != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result.String())
			}
		})
	}
}

func TestServiceStatusToString_AllValues(t *testing.T) {
	tests := []struct {
		name     string
		status   platformv1.ServiceStatus
		expected string
	}{
		{"stopped", platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, "stopped"},
		{"starting", platformv1.ServiceStatus_SERVICE_STATUS_STARTING, "starting"},
		{"running", platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, "running"},
		{"stopping", platformv1.ServiceStatus_SERVICE_STATUS_STOPPING, "stopping"},
		{"error", platformv1.ServiceStatus_SERVICE_STATUS_ERROR, "error"},
		{"unknown", platformv1.ServiceStatus(99), "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := serviceStatusToString(tc.status)
			if result != tc.expected {
				t.Errorf("expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestNewPlatformHandlers(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	if handlers == nil {
		t.Fatal("expected handlers to be created")
	}
	if handlers.logger == nil {
		t.Error("expected logger to be set")
	}
	if handlers.respWriter == nil {
		t.Error("expected response writer to be set")
	}
}

func TestSetters(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	t.Run("SetProtocolConfig", func(t *testing.T) {
		config := &ProtocolConfig{EnableREST: true}
		handlers.SetProtocolConfig(config)
		if handlers.protocolConfig == nil {
			t.Error("expected protocol config to be set")
		}
	})

	t.Run("SetVersionInfo", func(t *testing.T) {
		info := &VersionInfo{Version: "1.0.0"}
		handlers.SetVersionInfo(info)
		if handlers.versionInfo == nil {
			t.Error("expected version info to be set")
		}
	})

	t.Run("SetRESTServerRunningFunc", func(t *testing.T) {
		handlers.SetRESTServerRunningFunc(func() bool { return true })
		if handlers.restServerRunFn == nil {
			t.Error("expected REST server run func to be set")
		}
	})
}
