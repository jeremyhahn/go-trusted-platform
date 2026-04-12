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

package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"

	kmssvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
)

// =============================================================================
// KeyAlgorithm string() Tests
// =============================================================================

func TestCoverageKeyAlgorithm_All(t *testing.T) {
	tests := []struct {
		alg      kmssvc.KeyAlgorithm
		expected string
	}{
		{kmssvc.KeyAlgorithmAES128, "AES-128"},
		{kmssvc.KeyAlgorithmAES192, "AES-192"},
		{kmssvc.KeyAlgorithmAES256, "AES-256"},
		{kmssvc.KeyAlgorithmChaCha20Poly, "ChaCha20-Poly1305"},
		{kmssvc.KeyAlgorithmRSA2048, "RSA-2048"},
		{kmssvc.KeyAlgorithmRSA3072, "RSA-3072"},
		{kmssvc.KeyAlgorithmRSA4096, "RSA-4096"},
		{kmssvc.KeyAlgorithmECDSAP256, "ECDSA-P256"},
		{kmssvc.KeyAlgorithmECDSAP384, "ECDSA-P384"},
		{kmssvc.KeyAlgorithmECDSAP521, "ECDSA-P521"},
		{kmssvc.KeyAlgorithmED25519, "Ed25519"},
		{kmssvc.KeyAlgorithmDilithium2, "Dilithium2"},
		{kmssvc.KeyAlgorithmDilithium3, "Dilithium3"},
		{kmssvc.KeyAlgorithmDilithium5, "Dilithium5"},
		{kmssvc.KeyAlgorithmHMACSHA256, "HMAC-SHA256"},
		{kmssvc.KeyAlgorithmHMACSHA384, "HMAC-SHA384"},
		{kmssvc.KeyAlgorithmHMACSHA512, "HMAC-SHA512"},
		{kmssvc.KeyAlgorithmUnspecified, "UNSPECIFIED"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, string(tc.alg))
	}
}

// =============================================================================
// KeyStatus string() Tests
// =============================================================================

func TestCoverageKeyStatus_All(t *testing.T) {
	tests := []struct {
		status   kmssvc.KeyStatus
		expected string
	}{
		{kmssvc.KeyStatusEnabled, "ENABLED"},
		{kmssvc.KeyStatusDisabled, "DISABLED"},
		{kmssvc.KeyStatusPendingDeletion, "PENDING DELETION"},
		{kmssvc.KeyStatusDestroyed, "DESTROYED"},
		{kmssvc.KeyStatusPendingImport, "PENDING IMPORT"},
		{kmssvc.KeyStatusUnspecified, "UNKNOWN"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, string(tc.status))
	}
}

// =============================================================================
// KeyUsage string() Tests
// =============================================================================

func TestCoverageKeyUsage_All(t *testing.T) {
	tests := []struct {
		usage    kmssvc.KeyUsage
		expected string
	}{
		{kmssvc.KeyUsageEncrypt, "encrypt"},
		{kmssvc.KeyUsageDecrypt, "decrypt"},
		{kmssvc.KeyUsageSign, "sign"},
		{kmssvc.KeyUsageVerify, "verify"},
		{kmssvc.KeyUsageWrap, "wrap"},
		{kmssvc.KeyUsageUnwrap, "unwrap"},
		{kmssvc.KeyUsageDerive, "derive"},
		{kmssvc.KeyUsageHMAC, "hmac"},
		{kmssvc.KeyUsageUnspecified, "unspecified"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, string(tc.usage))
	}
}

func TestCoverageFormatDomainKeyUsages_Multiple(t *testing.T) {
	usages := []kmssvc.KeyUsage{kmssvc.KeyUsageEncrypt, kmssvc.KeyUsageDecrypt}
	result := formatDomainKeyUsages(usages)
	assert.Equal(t, "encrypt, decrypt", result)
}

func TestCoverageFormatDomainKeyUsages_Empty(t *testing.T) {
	assert.Equal(t, "none", formatDomainKeyUsages(nil))
}

// =============================================================================
// formatKeyTimestamp Tests (not yet covered)
// =============================================================================

func TestCoverageFormatKeyTimestamp_Valid(t *testing.T) {
	result := formatKeyTimestamp(1700000000)
	assert.Contains(t, result, "2023")
}

func TestCoverageFormatKeyTimestamp_Zero(t *testing.T) {
	assert.Equal(t, "-", formatKeyTimestamp(0))
}

// =============================================================================
// DEK formatTimestamp Tests (not yet covered)
// =============================================================================

func TestCoverageDEKFormatTimestamp_Valid(t *testing.T) {
	assert.Equal(t, "1700000000", formatTimestamp(1700000000))
}

func TestCoverageDEKFormatTimestamp_Zero(t *testing.T) {
	assert.Equal(t, "-", formatTimestamp(0))
}
