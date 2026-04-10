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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// =============================================================================
// formatKMSKeyAlgorithm Tests (not yet covered)
// =============================================================================

func TestCoverageFormatKMSKeyAlgorithm_All(t *testing.T) {
	tests := []struct {
		alg      platformv1.KMSKeyAlgorithm
		expected string
	}{
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, "AES-128"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192, "AES-192"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, "AES-256"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305, "ChaCha20-Poly1305"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048, "RSA-2048"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072, "RSA-3072"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096, "RSA-4096"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256, "ECDSA-P256"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384, "ECDSA-P384"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521, "ECDSA-P521"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519, "Ed25519"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2, "Dilithium2"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM3, "Dilithium3"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM5, "Dilithium5"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256, "HMAC-SHA256"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384, "HMAC-SHA384"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512, "HMAC-SHA512"},
		{platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, "UNKNOWN"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, formatKMSKeyAlgorithm(tc.alg))
	}
}

// =============================================================================
// formatKeyStatus Tests (not yet covered)
// =============================================================================

func TestCoverageFormatKeyStatus_All(t *testing.T) {
	tests := []struct {
		status   platformv1.KeyStatus
		expected string
	}{
		{platformv1.KeyStatus_KEY_STATUS_ENABLED, "ENABLED"},
		{platformv1.KeyStatus_KEY_STATUS_DISABLED, "DISABLED"},
		{platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION, "PENDING DELETION"},
		{platformv1.KeyStatus_KEY_STATUS_DESTROYED, "DESTROYED"},
		{platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT, "PENDING IMPORT"},
		{platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED, "UNKNOWN"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, formatKeyStatus(tc.status))
	}
}

// =============================================================================
// formatKeyUsage / formatKeyUsages Tests (not yet covered)
// =============================================================================

func TestCoverageFormatKeyUsage_All(t *testing.T) {
	tests := []struct {
		usage    platformv1.KeyUsage
		expected string
	}{
		{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, "encrypt"},
		{platformv1.KeyUsage_KEY_USAGE_DECRYPT, "decrypt"},
		{platformv1.KeyUsage_KEY_USAGE_SIGN, "sign"},
		{platformv1.KeyUsage_KEY_USAGE_VERIFY, "verify"},
		{platformv1.KeyUsage_KEY_USAGE_WRAP, "wrap"},
		{platformv1.KeyUsage_KEY_USAGE_UNWRAP, "unwrap"},
		{platformv1.KeyUsage_KEY_USAGE_DERIVE, "derive"},
		{platformv1.KeyUsage_KEY_USAGE_HMAC, "hmac"},
		{platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED, "unknown"},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.expected, formatKeyUsage(tc.usage))
	}
}

func TestCoverageFormatKeyUsages_Multiple(t *testing.T) {
	usages := []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, platformv1.KeyUsage_KEY_USAGE_DECRYPT}
	result := formatKeyUsages(usages)
	assert.Equal(t, "encrypt, decrypt", result)
}

func TestCoverageFormatKeyUsages_Empty(t *testing.T) {
	assert.Equal(t, "none", formatKeyUsages(nil))
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
