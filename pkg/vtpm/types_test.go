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

package vtpm

import (
	"errors"
	"testing"
)

func TestBundleMode_String(t *testing.T) {
	tests := []struct {
		mode     BundleMode
		expected string
	}{
		{BundleModeTemplate, "template"},
		{BundleModePreAssigned, "pre-assigned"},
		{BundleMode("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.expected {
				t.Errorf("BundleMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBundleMode_IsValid(t *testing.T) {
	tests := []struct {
		mode     BundleMode
		expected bool
	}{
		{BundleModeTemplate, true},
		{BundleModePreAssigned, true},
		{BundleMode("invalid"), false},
		{BundleMode(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.expected {
				t.Errorf("BundleMode.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEKAlgorithm_String(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected string
	}{
		{EKAlgorithmRSA, "RSA"},
		{EKAlgorithmECC, "ECC"},
		{EKAlgorithm("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.algo.String(); got != tt.expected {
				t.Errorf("EKAlgorithm.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEKAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected bool
	}{
		{EKAlgorithmRSA, true},
		{EKAlgorithmECC, true},
		{EKAlgorithm("DSA"), false},
		{EKAlgorithm(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := tt.algo.IsValid(); got != tt.expected {
				t.Errorf("EKAlgorithm.IsValid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseEKAlgorithm(t *testing.T) {
	tests := []struct {
		input string
		want  EKAlgorithm
	}{
		{"RSA", EKAlgorithmRSA},
		{"ECC", EKAlgorithmECC},
		{"ecc", EKAlgorithmECC},
		{" Rsa ", EKAlgorithmRSA},
		{"", ""},
		{"   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseEKAlgorithm(tt.input)
			if err != nil {
				t.Fatalf("ParseEKAlgorithm(%q) err = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ParseEKAlgorithm(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseEKAlgorithm_RejectsUndocumentedValues guards the coercion bug:
// every value other than RSA or ECC was silently treated as RSA.
func TestParseEKAlgorithm_RejectsUndocumentedValues(t *testing.T) {
	for _, input := range []string{"ECDSA", "DSA", "RSA-2048", "P256", "rsa ecc"} {
		t.Run(input, func(t *testing.T) {
			got, err := ParseEKAlgorithm(input)
			var invalid ErrInvalidEKAlgorithm
			if !errors.As(err, &invalid) {
				t.Fatalf("ParseEKAlgorithm(%q) err = %v, want ErrInvalidEKAlgorithm", input, err)
			}
			if invalid.Algorithm != input {
				t.Errorf("ErrInvalidEKAlgorithm.Algorithm = %q, want %q", invalid.Algorithm, input)
			}
			if got != "" {
				t.Errorf("ParseEKAlgorithm(%q) = %q on error, want empty", input, got)
			}
		})
	}
}

func TestEKAlgorithm_NVIndex(t *testing.T) {
	tests := []struct {
		algo     EKAlgorithm
		expected uint32
	}{
		{EKAlgorithmRSA, 0x01C00002},
		{EKAlgorithmECC, 0x01C0000A},
		{EKAlgorithm("unknown"), 0x01C00002}, // Default to RSA index
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			if got := tt.algo.NVIndex(); got != tt.expected {
				t.Errorf("EKAlgorithm.NVIndex() = 0x%08X, want 0x%08X", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Manifest Tests
// =============================================================================

func TestManifest_VersionConstant(t *testing.T) {
	if ManifestVersion != "1.0" {
		t.Errorf("ManifestVersion = %v, want 1.0", ManifestVersion)
	}
}

// =============================================================================
// Constants Tests
// =============================================================================
