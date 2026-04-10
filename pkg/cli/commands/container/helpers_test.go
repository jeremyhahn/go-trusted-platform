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
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

func TestFormatContainerState(t *testing.T) {
	tests := []struct {
		state    platformv1.ContainerState
		expected string
	}{
		{platformv1.ContainerState_CONTAINER_STATE_CREATED, "CREATED"},
		{platformv1.ContainerState_CONTAINER_STATE_STARTING, "STARTING"},
		{platformv1.ContainerState_CONTAINER_STATE_RUNNING, "RUNNING"},
		{platformv1.ContainerState_CONTAINER_STATE_PAUSED, "PAUSED"},
		{platformv1.ContainerState_CONTAINER_STATE_STOPPING, "STOPPING"},
		{platformv1.ContainerState_CONTAINER_STATE_STOPPED, "STOPPED"},
		{platformv1.ContainerState_CONTAINER_STATE_EXITED, "EXITED"},
		{platformv1.ContainerState_CONTAINER_STATE_ERROR, "ERROR"},
		{platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED, "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatContainerState(tt.state)
			if result != tt.expected {
				t.Errorf("formatContainerState(%v) = %q, want %q", tt.state, result, tt.expected)
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	t.Run("nil timestamp", func(t *testing.T) {
		result := formatTimestamp(nil)
		if result != "N/A" {
			t.Errorf("formatTimestamp(nil) = %q, want %q", result, "N/A")
		}
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC))
		result := formatTimestamp(ts)
		expected := "2025-01-10T12:00:00Z"
		if result != expected {
			t.Errorf("formatTimestamp() = %q, want %q", result, expected)
		}
	})
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  uint32
		expected string
	}{
		{30, "30s"},
		{90, "1m30s"},
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatDuration(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatDuration(%d) = %q, want %q", tt.seconds, result, tt.expected)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
		{1099511627776, "1.00 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestFormatBool(t *testing.T) {
	if formatBool(true) != "Yes" {
		t.Errorf("formatBool(true) = %q, want %q", formatBool(true), "Yes")
	}

	if formatBool(false) != "No" {
		t.Errorf("formatBool(false) = %q, want %q", formatBool(false), "No")
	}
}

func TestParseEnvVar(t *testing.T) {
	t.Run("valid env var", func(t *testing.T) {
		result, err := parseEnvVar("KEY=value")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "KEY" || result.Value != "value" {
			t.Errorf("parseEnvVar() = {%q, %q}, want {%q, %q}", result.Name, result.Value, "KEY", "value")
		}
	})

	t.Run("value with equals", func(t *testing.T) {
		result, err := parseEnvVar("KEY=value=with=equals")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Name != "KEY" || result.Value != "value=with=equals" {
			t.Errorf("parseEnvVar() = {%q, %q}, want {%q, %q}", result.Name, result.Value, "KEY", "value=with=equals")
		}
	})

	t.Run("invalid env var", func(t *testing.T) {
		_, err := parseEnvVar("INVALID")
		if err == nil {
			t.Error("expected error for invalid env var")
		}
	})
}

func TestParseEnvVars(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result, err := parseEnvVars(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("multiple env vars", func(t *testing.T) {
		result, err := parseEnvVars([]string{"KEY1=value1", "KEY2=value2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 env vars, got %d", len(result))
		}
	})

	t.Run("invalid env var in list", func(t *testing.T) {
		_, err := parseEnvVars([]string{"KEY1=value1", "INVALID"})
		if err == nil {
			t.Error("expected error for invalid env var in list")
		}
	})
}

func TestParseLabel(t *testing.T) {
	t.Run("valid label", func(t *testing.T) {
		key, value, err := parseLabel("app=myapp")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "app" || value != "myapp" {
			t.Errorf("parseLabel() = {%q, %q}, want {%q, %q}", key, value, "app", "myapp")
		}
	})

	t.Run("invalid label", func(t *testing.T) {
		_, _, err := parseLabel("invalid")
		if err == nil {
			t.Error("expected error for invalid label")
		}
	})
}

func TestParseLabels(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result, err := parseLabels(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("multiple labels", func(t *testing.T) {
		result, err := parseLabels([]string{"app=myapp", "env=prod"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 labels, got %d", len(result))
		}
		if result["app"] != "myapp" {
			t.Errorf("expected app=myapp, got app=%s", result["app"])
		}
	})

	t.Run("invalid label in list", func(t *testing.T) {
		_, err := parseLabels([]string{"app=myapp", "invalid"})
		if err == nil {
			t.Error("expected error for invalid label in list")
		}
	})
}

func TestParsePortMapping(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedHost  uint32
		expectedCont  uint32
		expectedProto string
		expectError   bool
	}{
		{"tcp port", "8080:80", 8080, 80, "tcp", false},
		{"udp port", "53:53/udp", 53, 53, "udp", false},
		{"tcp explicit", "443:443/tcp", 443, 443, "tcp", false},
		{"invalid format", "8080", 0, 0, "", true},
		{"invalid host port", "abc:80", 0, 0, "", true},
		{"invalid container port", "8080:abc", 0, 0, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePortMapping(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.HostPort != tt.expectedHost {
				t.Errorf("HostPort = %d, want %d", result.HostPort, tt.expectedHost)
			}
			if result.ContainerPort != tt.expectedCont {
				t.Errorf("ContainerPort = %d, want %d", result.ContainerPort, tt.expectedCont)
			}
			if result.Protocol != tt.expectedProto {
				t.Errorf("Protocol = %q, want %q", result.Protocol, tt.expectedProto)
			}
		})
	}
}

func TestParsePortMappings(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result, err := parsePortMappings(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("multiple ports", func(t *testing.T) {
		result, err := parsePortMappings([]string{"8080:80", "443:443/tcp"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 port mappings, got %d", len(result))
		}
	})

	t.Run("invalid port in list", func(t *testing.T) {
		_, err := parsePortMappings([]string{"8080:80", "invalid"})
		if err == nil {
			t.Error("expected error for invalid port in list")
		}
	})
}

func TestParseMountSpec(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedSrc string
		expectedDst string
		expectedRO  bool
		expectError bool
	}{
		{"basic mount", "/host:/container", "/host", "/container", false, false},
		{"readonly mount", "/host:/container:ro", "/host", "/container", true, false},
		{"readonly explicit", "/host:/container:readonly", "/host", "/container", true, false},
		{"invalid mount", "/host", "", "", false, true},
		{"too many parts", "/a:/b:/c:/d", "", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseMountSpec(tt.input)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Source != tt.expectedSrc {
				t.Errorf("Source = %q, want %q", result.Source, tt.expectedSrc)
			}
			if result.Destination != tt.expectedDst {
				t.Errorf("Destination = %q, want %q", result.Destination, tt.expectedDst)
			}
			if result.Readonly != tt.expectedRO {
				t.Errorf("Readonly = %v, want %v", result.Readonly, tt.expectedRO)
			}
		})
	}
}

func TestParseMountSpecs(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result, err := parseMountSpecs(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("multiple mounts", func(t *testing.T) {
		result, err := parseMountSpecs([]string{"/a:/b", "/c:/d:ro"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) != 2 {
			t.Errorf("expected 2 mounts, got %d", len(result))
		}
	})

	t.Run("invalid mount in list", func(t *testing.T) {
		_, err := parseMountSpecs([]string{"/a:/b", "/invalid"})
		if err == nil {
			t.Error("expected error for invalid mount in list")
		}
	})
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		input       string
		expected    uint64
		expectError bool
	}{
		{"", 0, false},
		{"512m", 512, false},
		{"1g", 1024, false},
		{"2G", 2048, false},
		{"1024k", 1, false},
		{"1t", 1024 * 1024, false},
		{"1024b", 0, false},
		{"invalid", 0, true},
		{"abc", 0, true},
		{"m", 0, true},
		{"512x", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseMemory(tt.input)
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
				t.Errorf("parseMemory(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseCPU(t *testing.T) {
	tests := []struct {
		input       string
		expected    float64
		expectError bool
	}{
		{"", 0, false},
		{"0.5", 0.5, false},
		{"1", 1, false},
		{"2.5", 2.5, false},
		{"-1", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseCPU(tt.input)
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
				t.Errorf("parseCPU(%q) = %f, want %f", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseContainerState(t *testing.T) {
	tests := []struct {
		input    string
		expected platformv1.ContainerState
		ok       bool
	}{
		{"CREATED", platformv1.ContainerState_CONTAINER_STATE_CREATED, true},
		{"created", platformv1.ContainerState_CONTAINER_STATE_CREATED, true},
		{"STARTING", platformv1.ContainerState_CONTAINER_STATE_STARTING, true},
		{"starting", platformv1.ContainerState_CONTAINER_STATE_STARTING, true},
		{"RUNNING", platformv1.ContainerState_CONTAINER_STATE_RUNNING, true},
		{"running", platformv1.ContainerState_CONTAINER_STATE_RUNNING, true},
		{"PAUSED", platformv1.ContainerState_CONTAINER_STATE_PAUSED, true},
		{"paused", platformv1.ContainerState_CONTAINER_STATE_PAUSED, true},
		{"STOPPING", platformv1.ContainerState_CONTAINER_STATE_STOPPING, true},
		{"stopping", platformv1.ContainerState_CONTAINER_STATE_STOPPING, true},
		{"STOPPED", platformv1.ContainerState_CONTAINER_STATE_STOPPED, true},
		{"stopped", platformv1.ContainerState_CONTAINER_STATE_STOPPED, true},
		{"EXITED", platformv1.ContainerState_CONTAINER_STATE_EXITED, true},
		{"exited", platformv1.ContainerState_CONTAINER_STATE_EXITED, true},
		{"ERROR", platformv1.ContainerState_CONTAINER_STATE_ERROR, true},
		{"error", platformv1.ContainerState_CONTAINER_STATE_ERROR, true},
		{"invalid", platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED, false},
		{"unknown", platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED, false},
		{"", platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED, false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, ok := parseContainerState(tt.input)
			if ok != tt.ok {
				t.Errorf("parseContainerState(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			}
			if ok && result != tt.expected {
				t.Errorf("parseContainerState(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestTruncateID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"abc", "abc"},
		{"123456789012", "123456789012"},
		{"1234567890123", "123456789012"},
		{"abcdefghijklmnop", "abcdefghijkl"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := truncateID(tt.input)
			if result != tt.expected {
				t.Errorf("truncateID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPrintLogEntry(t *testing.T) {
	t.Run("without timestamp", func(t *testing.T) {
		entry := &platformv1.LogEntry{
			Message: "Test log message",
		}
		// This function prints to stdout, so we just verify it doesn't panic
		printLogEntry(entry, false)
	})

	t.Run("with timestamp", func(t *testing.T) {
		entry := &platformv1.LogEntry{
			Message:   "Test log message",
			Timestamp: timestamppb.New(time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)),
		}
		// This function prints to stdout, so we just verify it doesn't panic
		printLogEntry(entry, true)
	})

	t.Run("with timestamp flag but nil timestamp", func(t *testing.T) {
		entry := &platformv1.LogEntry{
			Message:   "Test log message",
			Timestamp: nil,
		}
		// Should still work when timestamp is nil but flag is true
		printLogEntry(entry, true)
	})
}
