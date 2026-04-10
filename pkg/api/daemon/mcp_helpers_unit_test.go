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
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestMCPSystemStatusString verifies system status string conversion.
func TestMCPSystemStatusString(t *testing.T) {
	tests := []struct {
		input    platformv1.SystemStatus
		expected string
	}{
		{platformv1.SystemStatus_SYSTEM_STATUS_READY, "ready"},
		{platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING, "initializing"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := mcpSystemStatusString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestMCPServiceStatusString verifies service status string conversion.
func TestMCPServiceStatusString(t *testing.T) {
	tests := []struct {
		input    platformv1.ServiceStatus
		expected string
	}{
		{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, "running"},
		{platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, "stopped"},
		{platformv1.ServiceStatus_SERVICE_STATUS_ERROR, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := mcpServiceStatusString(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestMCPStatusResponseMap verifies the status response map builder.
func TestMCPStatusResponseMap(t *testing.T) {
	now := time.Now()
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info: &platformv1.PlatformInfo{
			Version:   "1.0.0",
			BuildTime: "2025-01-01",
			GitCommit: "abc123",
			SystemInfo: &platformv1.SystemInfo{
				Os:                "linux",
				Arch:              "amd64",
				NumCpus:           8,
				TotalMemoryMb:     32768,
				AvailableMemoryMb: 16384,
				UptimeSeconds:     3661,
			},
		},
		Timestamp: timestamppb.New(now),
	}

	result := mcpStatusResponseMap(resp)

	if result["status"] != "ready" {
		t.Errorf("expected status=ready, got %v", result["status"])
	}
	if result["version"] != "1.0.0" {
		t.Errorf("expected version=1.0.0, got %v", result["version"])
	}
	system, ok := result["system"].(map[string]interface{})
	if !ok {
		t.Fatal("expected system map")
	}
	if system["os"] != "linux" {
		t.Errorf("expected os=linux, got %v", system["os"])
	}
}

// TestMCPVersionResponseMap verifies the version response map builder.
func TestMCPVersionResponseMap(t *testing.T) {
	resp := &platformv1.GetVersionResponse{
		Version:   "2.0.0",
		BuildTime: "2025-06-01",
		GitCommit: "def456",
		GoVersion: "go1.26",
	}

	result := mcpVersionResponseMap(resp)

	if result["version"] != "2.0.0" {
		t.Errorf("expected version=2.0.0, got %v", result["version"])
	}
	if result["goVersion"] != "go1.26" {
		t.Errorf("expected goVersion=go1.26, got %v", result["goVersion"])
	}
}

// TestMCPServiceInfoMap verifies the service info map builder.
func TestMCPServiceInfoMap(t *testing.T) {
	now := time.Now()
	info := &platformv1.ServiceInfo{
		Name:          "ca",
		Status:        platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		StartedAt:     timestamppb.New(now),
		UptimeSeconds: 3600,
		Metadata: map[string]string{
			"start_count": "5",
			"stop_count":  "3",
			"last_error":  "connection reset",
		},
	}

	result := mcpServiceInfoMap(info)

	if result["name"] != "ca" {
		t.Errorf("expected name=ca, got %v", result["name"])
	}
	if result["status"] != "running" {
		t.Errorf("expected status=running, got %v", result["status"])
	}
	if result["startCount"] != uint64(5) {
		t.Errorf("expected startCount=5, got %v", result["startCount"])
	}
	if result["lastError"] != "connection reset" {
		t.Errorf("expected lastError, got %v", result["lastError"])
	}
}

// TestMCPListServicesResponseMap verifies the services list map builder.
func TestMCPListServicesResponseMap(t *testing.T) {
	resp := &platformv1.ListServicesResponse{
		Services: []*platformv1.ServiceInfo{
			{Name: "ca", Status: platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, Metadata: map[string]string{}},
			{Name: "dns", Status: platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, Metadata: map[string]string{}},
		},
	}

	result := mcpListServicesResponseMap(resp)

	if result["count"] != 2 {
		t.Errorf("expected count=2, got %v", result["count"])
	}
	services, ok := result["services"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected services slice")
	}
	if len(services) != 2 {
		t.Errorf("expected 2 services, got %d", len(services))
	}
}

// TestMCPServiceActionMap verifies the service action map builder.
func TestMCPServiceActionMap(t *testing.T) {
	result := mcpServiceActionMap("ca", "start", true, "service started")

	if result["service"] != "ca" {
		t.Errorf("expected service=ca, got %v", result["service"])
	}
	if result["action"] != "start" {
		t.Errorf("expected action=start, got %v", result["action"])
	}
	if result["success"] != true {
		t.Errorf("expected success=true, got %v", result["success"])
	}
	if result["message"] != "service started" {
		t.Errorf("expected message, got %v", result["message"])
	}
}

// TestMCPListProtocolsMap verifies the protocol list map builder.
func TestMCPListProtocolsMap(t *testing.T) {
	config := &Config{
		EnableREST:      true,
		RESTListenAddr:  ":8443",
		RESTTLSCertFile: "/path/to/cert",
		EnableGRPCTCP:   true,
		GRPCListenAddr:  ":10443",
		GRPCTLSCertFile: "/path/to/cert",
		EnableQUIC:      true,
		QUICListenAddr:  ":9444",
		EnableMCP:       true,
		MCPConfig:       &MCPConfig{HTTPAddr: ":9445"},
		EnableGRPCUDS:   true,
		GRPCSocketPath:  "/run/platformd.sock",
	}

	result := mcpListProtocolsMap(config)

	protocols, ok := result["protocols"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected protocols slice")
	}
	if len(protocols) != 5 {
		t.Errorf("expected 5 protocols, got %d", len(protocols))
	}
}

// TestMCPListProtocolsMap_AllDisabled verifies empty protocol list.
func TestMCPListProtocolsMap_AllDisabled(t *testing.T) {
	config := &Config{}
	result := mcpListProtocolsMap(config)

	protocols, ok := result["protocols"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected protocols slice")
	}
	if len(protocols) != 0 {
		t.Errorf("expected 0 protocols, got %d", len(protocols))
	}
}

// TestFormatUptimeDuration verifies the uptime formatting helper.
func TestFormatUptimeDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{0, "0s"},
		{30 * time.Second, "30s"},
		{5*time.Minute + 30*time.Second, "5m30s"},
		{2*time.Hour + 15*time.Minute + 45*time.Second, "2h15m45s"},
		{1 * time.Hour, "1h0m0s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatUptimeDuration(tt.duration)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestParseUint64FromMetadata verifies the metadata parsing helper.
func TestParseUint64FromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata map[string]string
		key      string
		expected uint64
	}{
		{"valid number", map[string]string{"count": "42"}, "count", 42},
		{"zero", map[string]string{"count": "0"}, "count", 0},
		{"missing key", map[string]string{}, "count", 0},
		{"non-numeric", map[string]string{"count": "abc"}, "count", 0},
		{"mixed content", map[string]string{"count": "12x"}, "count", 0},
		{"nil metadata", nil, "count", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUint64FromMetadata(tt.metadata, tt.key)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}
