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
