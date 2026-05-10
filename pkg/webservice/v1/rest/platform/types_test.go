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
	"testing"
	"time"
)

func TestHealthResponse_JSON(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	resp := HealthResponse{
		Health: PlatformHealth{
			Healthy:   true,
			Status:    "healthy",
			Timestamp: now,
			Services: []ServiceHealth{
				{
					Name:      "test-component",
					Healthy:   true,
					Status:    "healthy",
					Message:   "all good",
					LastCheck: now,
				},
			},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal HealthResponse: %v", err)
	}

	var unmarshaled HealthResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal HealthResponse: %v", err)
	}

	if unmarshaled.Health.Status != resp.Health.Status {
		t.Errorf("expected status %s, got %s", resp.Health.Status, unmarshaled.Health.Status)
	}
	if len(unmarshaled.Health.Services) != len(resp.Health.Services) {
		t.Errorf("expected %d services, got %d", len(resp.Health.Services), len(unmarshaled.Health.Services))
	}
}

func TestMetricsResponse_JSON(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	resp := MetricsResponse{
		Metrics: PlatformMetrics{
			CPUUsagePercent:    12.5,
			MemoryUsagePercent: 47.0,
			DiskUsagePercent:   31.2,
			OverallStatus:      "healthy",
			Services:           []ServiceMetricResponse{},
			Timestamp:          now,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal MetricsResponse: %v", err)
	}

	var unmarshaled MetricsResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal MetricsResponse: %v", err)
	}
	if unmarshaled.Metrics.CPUUsagePercent != resp.Metrics.CPUUsagePercent {
		t.Errorf("CPU mismatch")
	}
	if unmarshaled.Metrics.MemoryUsagePercent != resp.Metrics.MemoryUsagePercent {
		t.Errorf("memory mismatch")
	}
	if unmarshaled.Metrics.DiskUsagePercent != resp.Metrics.DiskUsagePercent {
		t.Errorf("disk mismatch")
	}
}

func TestStatusResponse_JSON(t *testing.T) {
	resp := StatusResponse{
		Status:    "ready",
		Version:   "1.0.0",
		BuildTime: "2025-01-01T00:00:00Z",
		GitCommit: "abc123",
		GoVersion: "go1.21",
		System: SystemInfoResponse{
			OS:                "linux",
			Arch:              "amd64",
			NumCPUs:           8,
			TotalMemoryMB:     16384,
			AvailableMemoryMB: 8192,
			Uptime:            "1h30m",
		},
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal StatusResponse: %v", err)
	}

	var unmarshaled StatusResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal StatusResponse: %v", err)
	}

	if unmarshaled.Status != resp.Status {
		t.Errorf("expected status %s, got %s", resp.Status, unmarshaled.Status)
	}

	if unmarshaled.System.NumCPUs != resp.System.NumCPUs {
		t.Errorf("expected %d CPUs, got %d", resp.System.NumCPUs, unmarshaled.System.NumCPUs)
	}
}

func TestVersionResponse_JSON(t *testing.T) {
	resp := VersionResponse{
		Version:   "1.0.0",
		BuildTime: "2025-01-01T00:00:00Z",
		GitCommit: "abc123",
		GoVersion: "go1.21",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal VersionResponse: %v", err)
	}

	var unmarshaled VersionResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal VersionResponse: %v", err)
	}

	if unmarshaled.Version != resp.Version {
		t.Errorf("expected version %s, got %s", resp.Version, unmarshaled.Version)
	}
}

func TestServiceInfoResponse_JSON(t *testing.T) {
	startedAt := time.Now()
	resp := ServiceInfoResponse{
		Name:       "tpm",
		Status:     "running",
		StartedAt:  startedAt,
		Uptime:     "1h",
		StartCount: 5,
		StopCount:  4,
		LastError:  "",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ServiceInfoResponse: %v", err)
	}

	var unmarshaled ServiceInfoResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ServiceInfoResponse: %v", err)
	}

	if unmarshaled.Name != resp.Name {
		t.Errorf("expected name %s, got %s", resp.Name, unmarshaled.Name)
	}

	if unmarshaled.StartCount != resp.StartCount {
		t.Errorf("expected start count %d, got %d", resp.StartCount, unmarshaled.StartCount)
	}
}

func TestServicesListResponse_JSON(t *testing.T) {
	resp := ServicesListResponse{
		Services: []ServiceInfoResponse{
			{
				Name:   "tpm",
				Status: "running",
			},
			{
				Name:   "dns",
				Status: "stopped",
			},
		},
		Count:     2,
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ServicesListResponse: %v", err)
	}

	var unmarshaled ServicesListResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ServicesListResponse: %v", err)
	}

	if unmarshaled.Count != resp.Count {
		t.Errorf("expected count %d, got %d", resp.Count, unmarshaled.Count)
	}

	if len(unmarshaled.Services) != len(resp.Services) {
		t.Errorf("expected %d services, got %d", len(resp.Services), len(unmarshaled.Services))
	}
}

func TestServiceActionResponse_JSON(t *testing.T) {
	resp := ServiceActionResponse{
		Service: "tpm",
		Action:  "start",
		Success: true,
		Message: "service started successfully",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ServiceActionResponse: %v", err)
	}

	var unmarshaled ServiceActionResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ServiceActionResponse: %v", err)
	}

	if unmarshaled.Service != resp.Service {
		t.Errorf("expected service %s, got %s", resp.Service, unmarshaled.Service)
	}

	if unmarshaled.Success != resp.Success {
		t.Errorf("expected success %v, got %v", resp.Success, unmarshaled.Success)
	}
}

func TestProtocolStatusResponse_JSON(t *testing.T) {
	resp := ProtocolStatusResponse{
		Name:    "REST",
		Enabled: true,
		Address: "0.0.0.0:8443",
		Port:    8443,
		Status:  "running",
		TLS:     true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ProtocolStatusResponse: %v", err)
	}

	var unmarshaled ProtocolStatusResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ProtocolStatusResponse: %v", err)
	}

	if unmarshaled.Name != resp.Name {
		t.Errorf("expected name %s, got %s", resp.Name, unmarshaled.Name)
	}

	if unmarshaled.Port != resp.Port {
		t.Errorf("expected port %d, got %d", resp.Port, unmarshaled.Port)
	}
}

func TestProtocolsResponse_JSON(t *testing.T) {
	resp := ProtocolsResponse{
		Protocols: []ProtocolStatusResponse{
			{
				Name:    "REST",
				Enabled: true,
				Address: "0.0.0.0:8443",
				Port:    8443,
				Status:  "running",
				TLS:     true,
			},
			{
				Name:    "gRPC",
				Enabled: true,
				Address: "0.0.0.0:10443",
				Port:    10443,
				Status:  "running",
				TLS:     false,
			},
		},
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal ProtocolsResponse: %v", err)
	}

	var unmarshaled ProtocolsResponse
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ProtocolsResponse: %v", err)
	}

	if len(unmarshaled.Protocols) != len(resp.Protocols) {
		t.Errorf("expected %d protocols, got %d", len(resp.Protocols), len(unmarshaled.Protocols))
	}
}
