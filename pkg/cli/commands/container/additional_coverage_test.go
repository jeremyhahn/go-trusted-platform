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

package container

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Tests for printContainerList edge cases
func TestPrintContainerList_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListContainersResult{
		Containers: []*computesvc.Container{},
	}

	err := printContainerList(printer, resp)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintContainerList_ContainersWithNilConfig(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListContainersResult{
		Containers: []*computesvc.Container{
			{
				ID:        "container-1",
				State:     computesvc.ContainerStateRunning,
				Config:    nil, // No config
				CreatedAt: time.Now(),
			},
		},
	}

	err := printContainerList(printer, resp)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintContainerList_MultipleContainersWithPorts(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	resp := &computesvc.ListContainersResult{
		Containers: []*computesvc.Container{
			{
				ID:    "container-1",
				State: computesvc.ContainerStateRunning,
				Config: &computesvc.ContainerConfig{
					Name:  "web-app",
					Image: "nginx:latest",
					Ports: []*computesvc.PortMapping{
						{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
						{HostPort: 443, ContainerPort: 443, Protocol: "tcp", HostIP: "0.0.0.0"},
					},
				},
				CreatedAt: time.Now(),
			},
			{
				ID:    "container-2",
				State: computesvc.ContainerStateStopped,
				Config: &computesvc.ContainerConfig{
					Name:  "db",
					Image: "postgres:14",
				},
				CreatedAt: time.Now(),
			},
		},
	}

	err := printContainerList(printer, resp)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Additional tests for parseFilters edge cases
func TestParseFilters_MultipleStates(t *testing.T) {
	filters := []string{"state=running", "state=stopped"}

	_, states, err := parseFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(states) != 2 {
		t.Errorf("expected 2 states, got %d", len(states))
	}
}

func TestParseFilters_MixedFilters(t *testing.T) {
	filters := []string{
		"state=running",
		"label=env=production",
		"name=my-container",
		"image=nginx",
	}

	selector, states, err := parseFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(states) != 1 {
		t.Errorf("expected 1 state, got %d", len(states))
	}

	if selector == nil {
		t.Fatal("expected selector, got nil")
	}

	// Should have label, name, and image in MatchLabels
	if len(selector) != 3 {
		t.Errorf("expected 3 labels, got %d", len(selector))
	}
}

// Tests for printFullContainerDetails edge cases
func TestPrintFullContainerDetails_ContainerWithNoMetrics(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:    "container-1",
		State: computesvc.ContainerStateRunning,
		Config: &computesvc.ContainerConfig{
			Name:  "app",
			Image: "myimage:latest",
		},
		Metrics: nil, // No metrics
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_ContainerWithEmptyResources(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:    "container-1",
		State: computesvc.ContainerStateRunning,
		Config: &computesvc.ContainerConfig{
			Name:      "app",
			Image:     "myimage:latest",
			Resources: &computesvc.ResourceLimits{}, // Empty resources
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_ContainerWithMetricsAndNoLimit(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:    "container-1",
		State: computesvc.ContainerStateRunning,
		Config: &computesvc.ContainerConfig{
			Name:  "app",
			Image: "myimage:latest",
		},
		Metrics: &computesvc.ContainerMetrics{
			CPUUsagePercent: 10.5,
			MemoryUsedMB:   256,
			MemoryLimitMB:  0, // No limit
			DiskReadBytes:  1024,
			DiskWriteBytes: 2048,
			NetworkRxBytes: 4096,
			NetworkTxBytes: 8192,
			UptimeSeconds:  0, // No uptime
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintFullContainerDetails_ContainerWithReadonlyVolume(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:    "container-1",
		State: computesvc.ContainerStateRunning,
		Config: &computesvc.ContainerConfig{
			Name:  "app",
			Image: "myimage:latest",
			Volumes: []*computesvc.VolumeMount{
				{Source: "/data", Destination: "/mnt/data", Readonly: false},
				{Source: "/config", Destination: "/etc/config", Readonly: true},
			},
		},
	}

	err := printFullContainerDetails(printer, container)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Tests for printContainerDetails edge cases
func TestPrintContainerDetails_WithEmptyCommand(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:    "container-1",
		State: computesvc.ContainerStateCreated,
		Config: &computesvc.ContainerConfig{
			Name:       "app",
			Image:      "myimage:latest",
			WorkingDir: "",
			Command:    []string{}, // Empty command
			Privileged: false,
			TpmAccess:  false,
			Network:    "", // No network mode
		},
	}

	printContainerDetails(printer, container)
}

func TestPrintContainerDetails_WithNoHostID(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	container := &computesvc.Container{
		ID:     "container-1",
		State:  computesvc.ContainerStateRunning,
		HostID: "", // No host ID
		Config: &computesvc.ContainerConfig{
			Name:  "app",
			Image: "myimage:latest",
		},
	}

	printContainerDetails(printer, container)
}

// Tests for formatPorts edge cases
func TestFormatPorts_WithEmptySlice(t *testing.T) {
	result := formatPorts([]*computesvc.PortMapping{})
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

func TestFormatPorts_WithMixedHostIPs(t *testing.T) {
	ports := []*computesvc.PortMapping{
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		{HostPort: 8443, ContainerPort: 443, Protocol: "tcp", HostIP: "192.168.1.1"},
		{HostPort: 53, ContainerPort: 53, Protocol: "udp", HostIP: ""},
	}

	result := formatPorts(ports)
	if result == "" {
		t.Error("expected non-empty result")
	}
}

// Tests for additional helper functions
func TestFormatBytes_EdgeCases(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.00 KB"},
		{1025, "1.00 KB"},
		{1536, "1.50 KB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestFormatDuration_EdgeCases(t *testing.T) {
	tests := []struct {
		seconds  uint32
		expected string
	}{
		{0, "0s"},
		{1, "1s"},
		{59, "59s"},
		{60, "1m0s"},
		{61, "1m1s"},
		{3599, "59m59s"},
		{3600, "1h0m"},
		{3601, "1h0m"},
		{7199, "1h59m"},
	}

	for _, tt := range tests {
		result := formatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, result, tt.expected)
		}
	}
}

func TestTruncateID_EdgeCases(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "a"},
		{"ab", "ab"},
		{"abc", "abc"},
		{"abcdefghijk", "abcdefghijk"},
		{"abcdefghijkl", "abcdefghijkl"},
		{"abcdefghijklm", "abcdefghijkl"},
		{"abcdefghijklmnopqrstuvwxyz", "abcdefghijkl"},
	}

	for _, tt := range tests {
		result := truncateID(tt.input)
		if result != tt.expected {
			t.Errorf("truncateID(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// Tests for parseCPUCount edge cases
func TestParseCPUCount_EdgeCases(t *testing.T) {
	tests := []struct {
		input       string
		expected    uint32
		expectError bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1", 1, false},
		{"10", 10, false},
		{"100", 100, false},
		{"2.5", 2, false},
		{"-1", 0, true},
		{"abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseCPUCount(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("parseCPUCount(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// Tests for printAttestResponse edge case - attestation result with image digest
func TestPrintAttestResponse_WithImageDigest(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	result := &containerAttestationResult{
		ContainerID:   "container-123",
		ContainerName: "myapp",
		ImageID:       "nginx:latest",
		ImageDigest:   "sha256:abc123def456",
		State:         "RUNNING",
		Nonce:         "testnonce123",
		PCRIndices:    []uint32{0, 1, 7, 14},
	}

	err := printAttestResponse(printer, cli.OutputFormatTable, result, "container-123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPrintAttestResponse_WithoutImageDigest(t *testing.T) {
	var buf bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &buf)

	result := &containerAttestationResult{
		ContainerID:   "container-123",
		ContainerName: "myapp",
		ImageID:       "nginx:latest",
		ImageDigest:   "", // Empty digest
		State:         "RUNNING",
		Nonce:         "testnonce123",
		PCRIndices:    nil, // No PCR indices
	}

	err := printAttestResponse(printer, cli.OutputFormatTable, result, "container-123")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// Test for printLogEntry with nil timestamp flag set but actual timestamp present
func TestPrintLogEntry_WithTimestamp(t *testing.T) {
	entry := &platformv1.LogEntry{
		Message:   "Test log message with timestamp",
		Timestamp: timestamppb.Now(),
	}

	// Should not panic and print with timestamp
	printLogEntry(entry, true)
}

func TestPrintLogEntry_WithTimestampFlagFalse(t *testing.T) {
	entry := &platformv1.LogEntry{
		Message:   "Test log message without timestamp display",
		Timestamp: timestamppb.Now(),
	}

	// Should not panic and print without timestamp
	printLogEntry(entry, false)
}
