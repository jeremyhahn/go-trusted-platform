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

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

func TestFormatContainerState(t *testing.T) {
	tests := []struct {
		state    computesvc.ContainerState
		expected string
	}{
		{computesvc.ContainerStateCreated, "CREATED"},
		{computesvc.ContainerStateStarting, "STARTING"},
		{computesvc.ContainerStateRunning, "RUNNING"},
		{computesvc.ContainerStatePaused, "PAUSED"},
		{computesvc.ContainerStateStopping, "STOPPING"},
		{computesvc.ContainerStateStopped, "STOPPED"},
		{computesvc.ContainerStateExited, "EXITED"},
		{computesvc.ContainerStateError, "ERROR"},
		{computesvc.ContainerStateUnspecified, "UNSPECIFIED"},
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
	t.Run("zero time", func(t *testing.T) {
		result := formatTimestamp(time.Time{})
		if result != "N/A" {
			t.Errorf("formatTimestamp(zero) = %q, want %q", result, "N/A")
		}
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := time.Date(2025, 1, 10, 12, 0, 0, 0, time.UTC)
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
		t.Error("formatBool(true) should return Yes")
	}
	if formatBool(false) != "No" {
		t.Error("formatBool(false) should return No")
	}
}
