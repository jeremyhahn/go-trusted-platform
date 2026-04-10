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

package commands

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewStatusCommand(t *testing.T) {
	cmd := NewStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	})

	if cmd == nil {
		t.Fatal("NewStatusCommand returned nil")
	}

	if cmd.Use != "status" {
		t.Errorf("expected Use to be 'status', got %s", cmd.Use)
	}

	if cmd.Short != "Show platform status" {
		t.Errorf("unexpected Short description: %s", cmd.Short)
	}

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestFormatSystemStatus(t *testing.T) {
	tests := []struct {
		status   platformv1.SystemStatus
		expected string
	}{
		{platformv1.SystemStatus_SYSTEM_STATUS_READY, "READY"},
		{platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING, "INITIALIZING"},
		{platformv1.SystemStatus_SYSTEM_STATUS_DEGRADED, "DEGRADED"},
		{platformv1.SystemStatus_SYSTEM_STATUS_UNAVAILABLE, "UNAVAILABLE"},
		{platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN, "SHUTTING_DOWN"},
		{platformv1.SystemStatus_SYSTEM_STATUS_UNSPECIFIED, "UNKNOWN"},
		{platformv1.SystemStatus(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		result := formatSystemStatus(tt.status)
		if result != tt.expected {
			t.Errorf("formatSystemStatus(%v): expected %s, got %s",
				tt.status, tt.expected, result)
		}
	}
}

func TestFormatServiceType(t *testing.T) {
	tests := []struct {
		serviceType platformv1.ServiceType
		expected    string
	}{
		{platformv1.ServiceType_SERVICE_TYPE_TPM, "TPM"},
		{platformv1.ServiceType_SERVICE_TYPE_SDN, "SDN"},
		{platformv1.ServiceType_SERVICE_TYPE_COMPUTE, "Compute"},
		{platformv1.ServiceType_SERVICE_TYPE_DNS, "DNS"},
		{platformv1.ServiceType_SERVICE_TYPE_ACME, "ACME"},
		{platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, "WebService"},
		{platformv1.ServiceType_SERVICE_TYPE_ATTESTATION, "Attestation"},
		{platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, "Unknown"},
		{platformv1.ServiceType(999), "Unknown"},
	}

	for _, tt := range tests {
		result := formatServiceType(tt.serviceType)
		if result != tt.expected {
			t.Errorf("formatServiceType(%v): expected %s, got %s",
				tt.serviceType, tt.expected, result)
		}
	}
}

func TestFormatServiceStatus(t *testing.T) {
	tests := []struct {
		status   platformv1.ServiceStatus
		expected string
	}{
		{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, "RUNNING"},
		{platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, "STOPPED"},
		{platformv1.ServiceStatus_SERVICE_STATUS_STARTING, "STARTING"},
		{platformv1.ServiceStatus_SERVICE_STATUS_STOPPING, "STOPPING"},
		{platformv1.ServiceStatus_SERVICE_STATUS_ERROR, "ERROR"},
		{platformv1.ServiceStatus_SERVICE_STATUS_UNSPECIFIED, "UNKNOWN"},
		{platformv1.ServiceStatus(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		result := formatServiceStatus(tt.status)
		if result != tt.expected {
			t.Errorf("formatServiceStatus(%v): expected %s, got %s",
				tt.status, tt.expected, result)
		}
	}
}

func TestFormatHealthStatus(t *testing.T) {
	tests := []struct {
		status   platformv1.HealthStatus
		expected string
	}{
		{platformv1.HealthStatus_HEALTH_STATUS_HEALTHY, "HEALTHY"},
		{platformv1.HealthStatus_HEALTH_STATUS_DEGRADED, "DEGRADED"},
		{platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY, "UNHEALTHY"},
		{platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED, "UNKNOWN"},
		{platformv1.HealthStatus(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		result := formatHealthStatus(tt.status)
		if result != tt.expected {
			t.Errorf("formatHealthStatus(%v): expected %s, got %s",
				tt.status, tt.expected, result)
		}
	}
}

func TestFormatTPMVersion(t *testing.T) {
	tests := []struct {
		version  platformv1.TPMVersion
		expected string
	}{
		{platformv1.TPMVersion_TPM_VERSION_2_0, "2.0"},
		{platformv1.TPMVersion_TPM_VERSION_1_2, "1.2"},
		{platformv1.TPMVersion_TPM_VERSION_UNSPECIFIED, "Unknown"},
		{platformv1.TPMVersion(999), "Unknown"},
	}

	for _, tt := range tests {
		result := formatTPMVersion(tt.version)
		if result != tt.expected {
			t.Errorf("formatTPMVersion(%v): expected %s, got %s",
				tt.version, tt.expected, result)
		}
	}
}

func TestPrintStatusTable(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info: &platformv1.PlatformInfo{
			Hostname:   "test-host",
			PlatformId: "platform-123",
			Version:    "1.4.0",
			BuildTime:  "2025-01-01T00:00:00Z",
			GitCommit:  "abc123",
			FipsMode:   true,
			SystemInfo: &platformv1.SystemInfo{
				Os:                "Linux",
				Arch:              "amd64",
				KernelVersion:     "6.14.0",
				NumCpus:           8,
				TotalMemoryMb:     16384,
				AvailableMemoryMb: 8192,
				UptimeSeconds:     86400,
			},
			TpmInfo: &platformv1.TPMInfo{
				Version:         platformv1.TPMVersion_TPM_VERSION_2_0,
				Manufacturer:    "Intel",
				FirmwareVersion: "1.0",
				IsSimulator:     false,
				FipsMode:        true,
			},
		},
		Services: []*platformv1.ServiceInfo{
			{
				Name:          "tpm-service",
				Type:          platformv1.ServiceType_SERVICE_TYPE_TPM,
				Status:        platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
				Health:        platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
				UptimeSeconds: 3600,
			},
		},
	}

	err := printStatusTable(printer, resp)
	if err != nil {
		t.Errorf("printStatusTable failed: %v", err)
	}
}

func TestPrintStatusTableNilInfo(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info:   nil,
	}

	err := printStatusTable(printer, resp)
	if err != nil {
		t.Errorf("printStatusTable with nil info failed: %v", err)
	}
}

func TestPrintStatusTableNilSystemInfo(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info: &platformv1.PlatformInfo{
			Hostname:   "test-host",
			PlatformId: "platform-123",
			Version:    "1.4.0",
			SystemInfo: nil,
			TpmInfo:    nil,
		},
	}

	err := printStatusTable(printer, resp)
	if err != nil {
		t.Errorf("printStatusTable with nil system info failed: %v", err)
	}
}

func TestPrintStatusTableNoServices(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info: &platformv1.PlatformInfo{
			Hostname:   "test-host",
			PlatformId: "platform-123",
			Version:    "1.4.0",
		},
		Services: nil,
	}

	err := printStatusTable(printer, resp)
	if err != nil {
		t.Errorf("printStatusTable with no services failed: %v", err)
	}
}

func TestPrintStatusTableEmptyServices(t *testing.T) {
	printer := cli.NewPrinter(cli.OutputFormatTable, false)
	resp := &platformv1.GetStatusResponse{
		Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
		Info: &platformv1.PlatformInfo{
			Hostname: "test-host",
		},
		Services: []*platformv1.ServiceInfo{},
	}

	err := printStatusTable(printer, resp)
	if err != nil {
		t.Errorf("printStatusTable with empty services failed: %v", err)
	}
}

func TestStatusCommandStructure(t *testing.T) {
	cmd := NewStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestStatusRunEWithNoConnection(t *testing.T) {
	cmd := NewStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{
			GetContext: func() (*cli.Context, error) {
				return nil, cli.ErrContextNotFound{Context: "test"}
			},
		}
	})

	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Error("expected error when connection fails")
	}
}

func TestStatusCommandLongDescription(t *testing.T) {
	cmd := NewStatusCommand(func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	})

	expectedLong := "Display the current status of the Trusted Platform and its services"
	if cmd.Long != expectedLong {
		t.Errorf("unexpected Long description: got %s, want %s", cmd.Long, expectedLong)
	}
}
