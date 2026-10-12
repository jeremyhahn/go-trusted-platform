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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

func TestGetProtocols_WithoutConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/platform/protocols", nil)
	rec := httptest.NewRecorder()

	handlers.GetProtocols(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}

	var resp restwire.WebServiceResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Error("expected success to be false")
	}
}

func TestGetProtocols_WithConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	// Set protocol config
	config := &ProtocolConfig{
		EnableREST:     true,
		RESTListenAddr: "0.0.0.0:8443",
		RESTTLSEnabled: true,
		EnableGRPCTCP:  true,
		GRPCListenAddr: "0.0.0.0:10443",
		GRPCTLSEnabled: false,
		SocketPath:     "/run/platformd.sock",
		EnableQUIC:     true,
		QUICListenAddr: "0.0.0.0:9444",
		EnableMCP:      true,
		MCPHTTPAddr:    "127.0.0.1:9445",
	}
	handlers.SetProtocolConfig(config)

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

	if !resp.Success {
		t.Error("expected success to be true")
	}

	// Verify payload structure
	payload, ok := resp.Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected payload to be a map")
	}

	protocols, ok := payload["protocols"].([]interface{})
	if !ok {
		t.Fatal("expected protocols to be an array")
	}

	// Should have 5 protocols: REST, gRPC, Unix Socket, QUIC, MCP
	if len(protocols) != 5 {
		t.Errorf("expected 5 protocols, got %d", len(protocols))
	}
}

func TestGetProtocols_WithRESTServerRunningFunc(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	handlers := NewPlatformHandlers(logger, respWriter)

	config := &ProtocolConfig{
		EnableREST:     true,
		RESTListenAddr: "0.0.0.0:8443",
		RESTTLSEnabled: true,
		EnableGRPCTCP:  true,
		GRPCListenAddr: "0.0.0.0:10443",
		GRPCTLSEnabled: false,
		SocketPath:     "/run/platformd.sock",
		EnableQUIC:     true,
		QUICListenAddr: "0.0.0.0:9444",
		EnableMCP:      true,
		MCPHTTPAddr:    "127.0.0.1:9445",
	}
	handlers.SetProtocolConfig(config)

	// Set REST server running function
	handlers.SetRESTServerRunningFunc(func() bool {
		return true
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

	if !resp.Success {
		t.Error("expected success to be true")
	}

	// Verify REST protocol status is "running"
	payload, _ := resp.Payload.(map[string]interface{})
	protocols, _ := payload["protocols"].([]interface{})

	for _, p := range protocols {
		proto, _ := p.(map[string]interface{})
		if proto["name"] == "REST" {
			status, _ := proto["status"].(string)
			if status != "running" {
				t.Errorf("expected REST status 'running', got '%s'", status)
			}
		}
	}
}

func TestExtractPort(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected int
	}{
		{
			name:     "standard IPv4 address with port",
			addr:     "0.0.0.0:8443",
			expected: 8443,
		},
		{
			name:     "localhost with port",
			addr:     "127.0.0.1:9443",
			expected: 9443,
		},
		{
			name:     "IPv6 with port",
			addr:     "[::1]:8080",
			expected: 8080,
		},
		{
			name:     "no port",
			addr:     "localhost",
			expected: 0,
		},
		{
			name:     "empty string",
			addr:     "",
			expected: 0,
		},
		{
			name:     "invalid port",
			addr:     "localhost:abc",
			expected: 0,
		},
		{
			name:     "port with path",
			addr:     "localhost:8080/path",
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractPort(tc.addr)
			if result != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, result)
			}
		})
	}
}

func TestBoolToStatus(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		expected string
	}{
		{
			name:     "enabled",
			enabled:  true,
			expected: "running",
		},
		{
			name:     "disabled",
			enabled:  false,
			expected: "stopped",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := boolToStatus(tc.enabled)
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}
