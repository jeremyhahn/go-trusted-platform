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

//go:build integration

package kms

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestQUICKeyAlgorithm(t *testing.T) {
	tests := map[string]platformv1.KMSKeyAlgorithm{
		"":                  platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
		"AES-256-GCM":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		"aes-256-gcm":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
		"ECDSA-P256":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
		"RSA-2048":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
		"ChaCha20-Poly1305": platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	}
	for name, want := range tests {
		got, err := quicKeyAlgorithm(name)
		require.NoError(t, err, name)
		assert.Equal(t, int32(want), got, name)
	}
}

func TestQUICKeyAlgorithm_Unsupported(t *testing.T) {
	// AES-128 has a platform.v1 number but the QUIC KMS server rejects it.
	for _, name := range []string{"AES-128-GCM", "HMAC-SHA256", "bogus"} {
		_, err := quicKeyAlgorithm(name)
		var unsupported ErrQUICUnsupportedValue
		require.True(t, errors.As(err, &unsupported), name)
		assert.Equal(t, "key algorithm", unsupported.Kind)
		assert.Equal(t, name, unsupported.Value)
		assert.Contains(t, err.Error(), name)
	}
}

func TestQUICUsages(t *testing.T) {
	ecdsa := int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256)
	aes := int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256)
	tests := []struct {
		purpose string
		alg     int32
		want    []int32
	}{
		{"", ecdsa, quicSignUsages},
		{"", aes, quicEncryptUsages},
		{"Sign_Verify", aes, quicSignUsages},
		{"encrypt", ecdsa, quicEncryptUsages},
		{"wrap", aes, quicWrapUsages},
	}
	for _, tt := range tests {
		got, err := quicUsages(tt.purpose, tt.alg)
		require.NoError(t, err, tt.purpose)
		assert.Equal(t, tt.want, got, tt.purpose)
	}
}

func TestQUICUsages_UnknownPurpose(t *testing.T) {
	_, err := quicUsages("bogus", int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256))
	var unsupported ErrQUICUnsupportedValue
	require.True(t, errors.As(err, &unsupported))
	assert.Equal(t, "key purpose", unsupported.Kind)
	assert.Equal(t, "bogus", unsupported.Value)
}

func TestQUICHashAlgorithm(t *testing.T) {
	tests := map[string]platformv1.HashAlgorithm{
		"":        platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		"SHA256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
		"sha-384": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
		"SHA512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	}
	for name, want := range tests {
		got, err := quicHashAlgorithm(name)
		require.NoError(t, err, name)
		assert.Equal(t, int32(want), got, name)
	}
}

func TestQUICHashAlgorithm_Unsupported(t *testing.T) {
	for _, name := range []string{"SHA1", "SHA3-256", "MD5"} {
		_, err := quicHashAlgorithm(name)
		var unsupported ErrQUICUnsupportedValue
		require.True(t, errors.As(err, &unsupported), name)
		assert.Equal(t, "hash algorithm", unsupported.Kind)
	}
}

func TestQUICExpiresAt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	never, err := quicExpiresAt("", now)
	require.NoError(t, err)
	assert.Zero(t, never, "an empty duration must mean no expiry")

	day, err := quicExpiresAt("24h", now)
	require.NoError(t, err)
	assert.Equal(t, now.Add(24*time.Hour).Unix(), day)
}

func TestQUICExpiresAt_Invalid(t *testing.T) {
	for _, in := range []string{"soon", "-1h", "0s"} {
		_, err := quicExpiresAt(in, time.Now())
		var unsupported ErrQUICUnsupportedValue
		require.True(t, errors.As(err, &unsupported), in)
		assert.Equal(t, in, unsupported.Value)
	}
}

func TestQUICEnumNames(t *testing.T) {
	assert.Equal(t, "AES_256", quicAlgorithmName(int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256)))
	assert.Equal(t, "DISABLED", quicStatusName(int32(platformv1.KeyStatus_KEY_STATUS_DISABLED)))
	assert.Equal(t, "ENABLED", quicStatusName(int32(platformv1.KeyStatus_KEY_STATUS_ENABLED)))
	assert.Equal(t, "SHA256", quicHashName(int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256)))
	assert.Equal(t, []string{"ENCRYPT", "SIGN"}, quicUsageNames([]int32{
		int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
		int32(platformv1.KeyUsage_KEY_USAGE_SIGN),
	}))
	assert.Empty(t, quicUsageNames(nil))
}

func TestQUICEnumNames_UnknownNumber(t *testing.T) {
	// A number the enum does not define keeps its digits rather than
	// borrowing a neighbouring name.
	assert.Equal(t, "99", quicStatusName(99))
	assert.Equal(t, "99", quicHashName(99))
	assert.Equal(t, "99", quicAlgorithmName(99))
}

func TestErrQUICMissingInResponse(t *testing.T) {
	err := error(ErrQUICMissingInResponse{Operation: "KeyGet", Field: "key"})
	assert.Equal(t, "QUIC KeyGet response carries no key", err.Error())

	var missing ErrQUICMissingInResponse
	require.True(t, errors.As(err, &missing))
	assert.Equal(t, "key", missing.Field)
}
