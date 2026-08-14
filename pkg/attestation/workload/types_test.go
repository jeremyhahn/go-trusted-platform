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

package workload

import (
	"testing"
	"time"
)

func TestWorkloadType_String(t *testing.T) {
	tests := []struct {
		wt       WorkloadType
		expected string
	}{
		{WorkloadTypeVM, "vm"},
		{WorkloadTypeContainer, "container"},
		{WorkloadType("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.wt.String(); got != tt.expected {
				t.Errorf("String() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestWorkloadType_IsValid(t *testing.T) {
	tests := []struct {
		wt       WorkloadType
		expected bool
	}{
		{WorkloadTypeVM, true},
		{WorkloadTypeContainer, true},
		{WorkloadType("invalid"), false},
		{WorkloadType(""), false},
		{WorkloadType("VM"), false},        // case sensitive
		{WorkloadType("Container"), false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(string(tt.wt), func(t *testing.T) {
			if got := tt.wt.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_String(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected string
	}{
		{HashAlgorithmSHA1, "sha1"},
		{HashAlgorithmSHA256, "sha256"},
		{HashAlgorithmSHA384, "sha384"},
		{HashAlgorithmSHA512, "sha512"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.alg.String(); got != tt.expected {
				t.Errorf("String() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected bool
	}{
		{HashAlgorithmSHA1, true},
		{HashAlgorithmSHA256, true},
		{HashAlgorithmSHA384, true},
		{HashAlgorithmSHA512, true},
		{HashAlgorithm("md5"), false},
		{HashAlgorithm(""), false},
		{HashAlgorithm("SHA256"), false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.IsValid(); got != tt.expected {
				t.Errorf("IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHashAlgorithm_DigestSize(t *testing.T) {
	tests := []struct {
		alg      HashAlgorithm
		expected int
	}{
		{HashAlgorithmSHA1, 20},
		{HashAlgorithmSHA256, 32},
		{HashAlgorithmSHA384, 48},
		{HashAlgorithmSHA512, 64},
		{HashAlgorithm("invalid"), 0},
		{HashAlgorithm(""), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			if got := tt.alg.DigestSize(); got != tt.expected {
				t.Errorf("DigestSize() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestWorkloadMeasurement_Validate(t *testing.T) {
	tests := []struct {
		name        string
		measurement WorkloadMeasurement
		expectErr   bool
		errType     string
	}{
		{
			name: "valid container measurement",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadTypeContainer,
				WorkloadID:   "abc123",
				ImageDigest:  "sha256:abcdef",
			},
			expectErr: false,
		},
		{
			name: "valid VM measurement",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadTypeVM,
				WorkloadID:   "vm-uuid-123",
				ImageDigest:  "sha256:fedcba",
			},
			expectErr: false,
		},
		{
			name: "valid measurement without image digest",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadTypeContainer,
				WorkloadID:   "abc123",
				ImageDigest:  "",
			},
			expectErr: false,
		},
		{
			name: "invalid workload type",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadType("invalid"),
				WorkloadID:   "abc123",
				ImageDigest:  "sha256:abcdef",
			},
			expectErr: true,
			errType:   "ErrInvalidWorkloadType",
		},
		{
			name: "empty workload type",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadType(""),
				WorkloadID:   "abc123",
				ImageDigest:  "sha256:abcdef",
			},
			expectErr: true,
			errType:   "ErrInvalidWorkloadType",
		},
		{
			name: "empty workload ID",
			measurement: WorkloadMeasurement{
				WorkloadType: WorkloadTypeContainer,
				WorkloadID:   "",
				ImageDigest:  "sha256:abcdef",
			},
			expectErr: true,
			errType:   "ErrInvalidWorkloadID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.measurement.Validate()
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				switch tt.errType {
				case "ErrInvalidWorkloadType":
					if _, ok := err.(ErrInvalidWorkloadType); !ok {
						t.Errorf("expected ErrInvalidWorkloadType, got %T", err)
					}
				case "ErrInvalidWorkloadID":
					if _, ok := err.(ErrInvalidWorkloadID); !ok {
						t.Errorf("expected ErrInvalidWorkloadID, got %T", err)
					}
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestChainEntry_Fields(t *testing.T) {
	now := time.Now().UTC()
	entry := &ChainEntry{
		Timestamp:    now,
		WorkloadType: WorkloadTypeContainer,
		WorkloadID:   "container-123",
		ImageDigest:  "sha256:abc123",
		Digest:       []byte{0x01, 0x02, 0x03},
		PCRValue:     []byte{0x04, 0x05, 0x06},
	}

	if entry.Timestamp != now {
		t.Errorf("Timestamp = %v, want %v", entry.Timestamp, now)
	}
	if entry.WorkloadType != WorkloadTypeContainer {
		t.Errorf("WorkloadType = %s, want %s", entry.WorkloadType, WorkloadTypeContainer)
	}
	if entry.WorkloadID != "container-123" {
		t.Errorf("WorkloadID = %s, want container-123", entry.WorkloadID)
	}
	if entry.ImageDigest != "sha256:abc123" {
		t.Errorf("ImageDigest = %s, want sha256:abc123", entry.ImageDigest)
	}
	if len(entry.Digest) != 3 {
		t.Errorf("Digest length = %d, want 3", len(entry.Digest))
	}
	if len(entry.PCRValue) != 3 {
		t.Errorf("PCRValue length = %d, want 3", len(entry.PCRValue))
	}
}

func TestChainStatistics_Fields(t *testing.T) {
	now := time.Now().UTC()
	stats := &ChainStatistics{
		TotalEntries:    10,
		VMCount:         3,
		ContainerCount:  7,
		FirstEntryTime:  now.Add(-time.Hour),
		LastEntryTime:   now,
		CurrentPCRValue: []byte{0x01, 0x02, 0x03},
	}

	if stats.TotalEntries != 10 {
		t.Errorf("TotalEntries = %d, want 10", stats.TotalEntries)
	}
	if stats.VMCount != 3 {
		t.Errorf("VMCount = %d, want 3", stats.VMCount)
	}
	if stats.ContainerCount != 7 {
		t.Errorf("ContainerCount = %d, want 7", stats.ContainerCount)
	}
	if stats.FirstEntryTime.After(stats.LastEntryTime) {
		t.Error("FirstEntryTime should be before LastEntryTime")
	}
	if len(stats.CurrentPCRValue) != 3 {
		t.Errorf("CurrentPCRValue length = %d, want 3", len(stats.CurrentPCRValue))
	}
}

func TestChainStatistics_EmptyChain(t *testing.T) {
	stats := &ChainStatistics{}

	if stats.TotalEntries != 0 {
		t.Errorf("TotalEntries = %d, want 0", stats.TotalEntries)
	}
	if stats.VMCount != 0 {
		t.Errorf("VMCount = %d, want 0", stats.VMCount)
	}
	if stats.ContainerCount != 0 {
		t.Errorf("ContainerCount = %d, want 0", stats.ContainerCount)
	}
	if stats.CurrentPCRValue != nil {
		t.Errorf("CurrentPCRValue = %v, want nil", stats.CurrentPCRValue)
	}
}

func TestWorkloadMeasurement_Fields(t *testing.T) {
	m := &WorkloadMeasurement{
		WorkloadType: WorkloadTypeVM,
		WorkloadID:   "vm-uuid-456",
		ImageDigest:  "sha256:xyz789",
	}

	if m.WorkloadType != WorkloadTypeVM {
		t.Errorf("WorkloadType = %s, want %s", m.WorkloadType, WorkloadTypeVM)
	}
	if m.WorkloadID != "vm-uuid-456" {
		t.Errorf("WorkloadID = %s, want vm-uuid-456", m.WorkloadID)
	}
	if m.ImageDigest != "sha256:xyz789" {
		t.Errorf("ImageDigest = %s, want sha256:xyz789", m.ImageDigest)
	}
}
