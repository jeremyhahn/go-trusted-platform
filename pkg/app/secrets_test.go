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

package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretsConfig_Default(t *testing.T) {
	cfg := DefaultSecretsConfig()

	assert.NotNil(t, cfg)
	assert.False(t, cfg.Enabled, "default should have Enabled=false for backward compatibility")
	assert.True(t, cfg.AutoGenerate, "default should enable AutoGenerate")
	assert.True(t, cfg.LocalKMS, "default should enable LocalKMS")
	assert.False(t, cfg.RemoteKMS, "default should disable RemoteKMS")
	assert.True(t, cfg.Encrypted, "default should enable Encrypted")
	assert.True(t, cfg.MigrateToKMS, "default should enable MigrateToKMS")
	assert.False(t, cfg.UpdateConfigFile, "default should disable UpdateConfigFile")
}

func TestAutoGenResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)

	assert.Equal(t, bootstrap.SchemeAutoGen, resolver.Scheme())
}

func TestAutoGenResolver_CanResolve(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "valid autogen URI",
			uri:      "autogen://32/base64",
			expected: true,
		},
		{
			name:     "valid autogen URI uppercase",
			uri:      "AUTOGEN://32/hex",
			expected: true,
		},
		{
			name:     "valid autogen URI mixed case",
			uri:      "AutoGen://16",
			expected: true,
		},
		{
			name:     "kms URI should not resolve",
			uri:      "kms://path/to/secret",
			expected: false,
		},
		{
			name:     "encrypted URI should not resolve",
			uri:      "encrypted://base64ciphertext",
			expected: false,
		},
		{
			name:     "plain text should not resolve",
			uri:      "mysecretpassword",
			expected: false,
		},
		{
			name:     "empty string should not resolve",
			uri:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.CanResolve(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAutoGenResolver_Resolve_Base64(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://32/base64")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Decode to verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(string(result))
	require.NoError(t, err)
	assert.Len(t, decoded, 32, "decoded bytes should be 32 bytes")
}

func TestAutoGenResolver_Resolve_Hex(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://16/hex")

	require.NoError(t, err)
	require.NotNil(t, result)

	// Decode to verify it's valid hex
	decoded, err := hex.DecodeString(string(result))
	require.NoError(t, err)
	assert.Len(t, decoded, 16, "decoded bytes should be 16 bytes")
}

func TestAutoGenResolver_Resolve_Raw(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://64/raw")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 64, "raw bytes should be 64 bytes")
}

func TestAutoGenResolver_Resolve_DefaultEncoding(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://48")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 48, "default encoding should return raw bytes")
}

func TestAutoGenResolver_Resolve_InvalidLength(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "autogen://invalid/base64")

	require.Error(t, err)
	var invalidURIErr ErrInvalidAutoGenURI
	assert.ErrorAs(t, err, &invalidURIErr)
	assert.Contains(t, err.Error(), "invalid length")
}

func TestAutoGenResolver_Resolve_NegativeLength(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "autogen://-5/base64")

	require.Error(t, err)
	var invalidURIErr ErrInvalidAutoGenURI
	assert.ErrorAs(t, err, &invalidURIErr)
}

func TestAutoGenResolver_Resolve_ZeroLength(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "autogen://0/base64")

	require.Error(t, err)
	var invalidURIErr ErrInvalidAutoGenURI
	assert.ErrorAs(t, err, &invalidURIErr)
}

func TestAutoGenResolver_Resolve_UnsupportedEncoding(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "autogen://32/unsupported")

	require.Error(t, err)
	var invalidURIErr ErrInvalidAutoGenURI
	assert.ErrorAs(t, err, &invalidURIErr)
	assert.Contains(t, err.Error(), "unsupported encoding")
}

func TestAutoGenResolver_Resolve_InvalidScheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "kms://path/to/secret")

	require.Error(t, err)
	var invalidURIErr ErrInvalidAutoGenURI
	assert.ErrorAs(t, err, &invalidURIErr)
	assert.Contains(t, err.Error(), "invalid scheme")
}

func TestAutoGenResolver_Resolve_CanceledContext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.Resolve(ctx, "autogen://32/base64")

	require.Error(t, err)
	var cancelErr ErrContextCanceled
	assert.ErrorAs(t, err, &cancelErr)
}

func TestAutoGenResolver_Resolve_Uniqueness(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	// Generate multiple secrets and verify they're unique
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result, err := resolver.Resolve(ctx, "autogen://32/hex")
		require.NoError(t, err)

		key := string(result)
		assert.False(t, secrets[key], "generated secret should be unique")
		secrets[key] = true
	}
}

func TestLocalSecretsResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)

	assert.Equal(t, bootstrap.SchemeKMS, resolver.Scheme())
}

func TestLocalSecretsResolver_CanResolve(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "valid kms URI",
			uri:      "kms://path/to/secret",
			expected: true,
		},
		{
			name:     "valid kms URI uppercase",
			uri:      "KMS://config/password",
			expected: true,
		},
		{
			name:     "autogen URI should not resolve",
			uri:      "autogen://32/base64",
			expected: false,
		},
		{
			name:     "encrypted URI should not resolve",
			uri:      "encrypted://ciphertext",
			expected: false,
		},
		{
			name:     "plain text should not resolve",
			uri:      "password123",
			expected: false,
		},
		{
			name:     "empty string should not resolve",
			uri:      "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.CanResolve(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocalSecretsResolver_Resolve_NilSecretsService(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "kms://path/to/secret")

	require.Error(t, err)
	var secretsErr ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &secretsErr)
}

func TestLocalSecretsResolver_Resolve_InvalidScheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "autogen://32/base64")

	require.Error(t, err)
	var invalidErr ErrInvalidKMSURI
	assert.ErrorAs(t, err, &invalidErr)
}

func TestLocalSecretsResolver_Resolve_EmptyPath(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)
	ctx := context.Background()

	_, err := resolver.Resolve(ctx, "kms://")

	require.Error(t, err)
	var invalidErr ErrInvalidKMSURI
	assert.ErrorAs(t, err, &invalidErr)
	assert.Contains(t, err.Error(), "empty path")
}

func TestLocalSecretsResolver_Resolve_CanceledContext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.Resolve(ctx, "kms://path/to/secret")

	require.Error(t, err)
	var cancelErr ErrContextCanceled
	assert.ErrorAs(t, err, &cancelErr)
}

func TestSecretsServiceClient_StoreSecret_NilSecretsService(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	client := NewSecretsServiceClient(nil, logger)
	ctx := context.Background()

	err := client.StoreSecret(ctx, "path/to/secret", []byte("secret"), nil)

	require.Error(t, err)
	var secretsErr ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &secretsErr)
}

func TestSecretsServiceClient_GetSecret_NilSecretsService(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	client := NewSecretsServiceClient(nil, logger)
	ctx := context.Background()

	_, err := client.GetSecret(ctx, "path/to/secret")

	require.Error(t, err)
	var secretsErr ErrSecretsServiceNotAvailable
	assert.ErrorAs(t, err, &secretsErr)
}

func TestNoOpSecretsClient_StoreSecret(t *testing.T) {
	client := &noOpSecretsClient{}
	ctx := context.Background()

	err := client.StoreSecret(ctx, "path", []byte("data"), nil)

	assert.NoError(t, err)
}

func TestNoOpSecretsClient_GetSecret(t *testing.T) {
	client := &noOpSecretsClient{}
	ctx := context.Background()

	_, err := client.GetSecret(ctx, "path")

	require.Error(t, err)
	var notFoundErr bootstrap.ErrSecretNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestEncryptedResolverAdapter_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	adapter := NewEncryptedResolverAdapter(nil, logger)

	assert.Equal(t, bootstrap.SchemeEncrypted, adapter.Scheme())
}

// Error type tests

func TestErrNilSecretsConfig_Error(t *testing.T) {
	err := ErrNilSecretsConfig{}
	assert.Contains(t, err.Error(), "secrets config cannot be nil")
}

func TestErrSetupSecretResolvers_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrSetupSecretResolvers{Cause: cause}

	assert.Contains(t, err.Error(), "failed to setup secret resolvers")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrSetupSecretResolvers_Error_NilCause(t *testing.T) {
	err := ErrSetupSecretResolvers{}

	assert.Contains(t, err.Error(), "failed to setup secret resolvers")
	assert.Nil(t, err.Unwrap())
}

func TestErrCreateSecretManager_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrCreateSecretManager{Cause: cause}

	assert.Contains(t, err.Error(), "failed to create secret manager")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrProcessSecrets_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrProcessSecrets{Cause: cause}

	assert.Contains(t, err.Error(), "failed to process secrets")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrUpdateConfigFile_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrUpdateConfigFile{Cause: cause}

	assert.Contains(t, err.Error(), "failed to update config file")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrTPMNotAvailable_Error(t *testing.T) {
	err := ErrTPMNotAvailable{}
	assert.Contains(t, err.Error(), "TPM is not available")
}

func TestErrIDevIDNotConfigured_Error(t *testing.T) {
	err := ErrIDevIDNotConfigured{}
	assert.Contains(t, err.Error(), "IDevID is not configured")
}

func TestErrPlatformKSNotAvailable_Error(t *testing.T) {
	err := ErrPlatformKSNotAvailable{}
	assert.Contains(t, err.Error(), "platform keystore is not available")
}

func TestErrGetIDevIDAttrs_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrGetIDevIDAttrs{Cause: cause}

	assert.Contains(t, err.Error(), "failed to get IDevID attributes")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrGetDecrypter_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrGetDecrypter{Cause: cause}

	assert.Contains(t, err.Error(), "failed to get decrypter")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrContextCanceled_Error(t *testing.T) {
	cause := context.Canceled
	err := ErrContextCanceled{Cause: cause}

	assert.Contains(t, err.Error(), "context canceled")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrInvalidAutoGenURI_Error(t *testing.T) {
	err := ErrInvalidAutoGenURI{URI: "bad://uri", Reason: "test reason"}

	assert.Contains(t, err.Error(), "invalid autogen URI")
	assert.Contains(t, err.Error(), "bad://uri")
	assert.Contains(t, err.Error(), "test reason")
}

func TestErrInvalidAutoGenURI_Error_NoReason(t *testing.T) {
	err := ErrInvalidAutoGenURI{URI: "bad://uri"}

	assert.Contains(t, err.Error(), "invalid autogen URI")
	assert.Contains(t, err.Error(), "bad://uri")
}

func TestErrAutoGenFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrAutoGenFailed{URI: "autogen://32", Cause: cause}

	assert.Contains(t, err.Error(), "failed to auto-generate secret")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrKMSNotAvailable_Error(t *testing.T) {
	err := ErrKMSNotAvailable{}
	assert.Contains(t, err.Error(), "KMS service is not available")
}

func TestErrInvalidKMSURI_Error(t *testing.T) {
	err := ErrInvalidKMSURI{URI: "bad://uri", Reason: "empty path"}

	assert.Contains(t, err.Error(), "invalid KMS URI")
	assert.Contains(t, err.Error(), "bad://uri")
	assert.Contains(t, err.Error(), "empty path")
}

func TestErrKMSGetFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrKMSGetFailed{Path: "config/secret", Cause: cause}

	assert.Contains(t, err.Error(), "failed to get secret from KMS")
	assert.Contains(t, err.Error(), "config/secret")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrKMSStoreFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrKMSStoreFailed{Path: "config/secret", Cause: cause}

	assert.Contains(t, err.Error(), "failed to store secret in KMS")
	assert.Contains(t, err.Error(), "config/secret")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrSecretsServiceNotAvailable_Error(t *testing.T) {
	err := ErrSecretsServiceNotAvailable{}
	assert.Contains(t, err.Error(), "secrets service is not available")
}

func TestErrSecretsGetFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrSecretsGetFailed{Path: "config/secret", Cause: cause}

	assert.Contains(t, err.Error(), "failed to get secret at")
	assert.Contains(t, err.Error(), "config/secret")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrSecretsStoreFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrSecretsStoreFailed{Path: "config/secret", Cause: cause}

	assert.Contains(t, err.Error(), "failed to store secret at")
	assert.Contains(t, err.Error(), "config/secret")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestAutoGenResolver_NilLogger(t *testing.T) {
	resolver := NewAutoGenResolver(nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, bootstrap.SchemeAutoGen, resolver.Scheme())
}

func TestLocalSecretsResolver_NilLogger(t *testing.T) {
	resolver := NewLocalSecretsResolver(nil, nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, bootstrap.SchemeKMS, resolver.Scheme())
}

func TestSecretsServiceClient_NilLogger(t *testing.T) {
	client := NewSecretsServiceClient(nil, nil)
	assert.NotNil(t, client)
}

func TestEncryptedResolverAdapter_NilLogger(t *testing.T) {
	adapter := NewEncryptedResolverAdapter(nil, nil)
	assert.NotNil(t, adapter)
	assert.Equal(t, bootstrap.SchemeEncrypted, adapter.Scheme())
}

func TestAutoGenResolver_Resolve_LargeLength(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	// Test with a large length
	result, err := resolver.Resolve(ctx, "autogen://1024/raw")

	require.NoError(t, err)
	assert.Len(t, result, 1024)
}

func TestAutoGenResolver_Resolve_Base64URLEncoding(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	// base64 is standard base64 which may contain + and /
	result, err := resolver.Resolve(ctx, "autogen://32/base64")

	require.NoError(t, err)
	// Result should be valid base64
	decoded, err := base64.StdEncoding.DecodeString(string(result))
	require.NoError(t, err)
	assert.Len(t, decoded, 32)
}

func TestAutoGenResolver_Resolve_Numeric(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://6/numeric")

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result, 6, "numeric PIN should be exactly 6 characters")

	// Verify all characters are digits
	for i, b := range result {
		assert.True(t, b >= '0' && b <= '9',
			"character at index %d should be a digit, got %c", i, b)
	}
}

func TestAutoGenResolver_Resolve_Numeric_LargeLength(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	result, err := resolver.Resolve(ctx, "autogen://128/numeric")

	require.NoError(t, err)
	assert.Len(t, result, 128)

	for _, b := range result {
		assert.True(t, b >= '0' && b <= '9',
			"all characters should be digits, got %c", b)
	}
}

func TestAutoGenResolver_Resolve_Numeric_Uniqueness(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)
	ctx := context.Background()

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		result, err := resolver.Resolve(ctx, "autogen://8/numeric")
		require.NoError(t, err)
		seen[string(result)] = true
	}
	assert.Greater(t, len(seen), 1,
		"100 random 8-digit PINs should produce more than 1 unique value")
}

func TestAutoGenResolver_Resolve_Numeric_CanceledContext(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewAutoGenResolver(logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := resolver.Resolve(ctx, "autogen://6/numeric")

	require.Error(t, err)
	var cancelErr ErrContextCanceled
	assert.ErrorAs(t, err, &cancelErr)
}

func TestEncryptedResolverAdapter_CanResolve_NilResolver(t *testing.T) {
	adapter := NewEncryptedResolverAdapter(nil, nil)

	// Should handle nil resolver gracefully - will panic if called
	// This test just verifies the adapter can be created with nil
	assert.NotNil(t, adapter)
}

func TestErrCreateSecretManager_NilCause(t *testing.T) {
	err := ErrCreateSecretManager{}
	assert.Contains(t, err.Error(), "failed to create secret manager")
	assert.Nil(t, err.Unwrap())
}

func TestErrProcessSecrets_NilCause(t *testing.T) {
	err := ErrProcessSecrets{}
	assert.Contains(t, err.Error(), "failed to process secrets")
	assert.Nil(t, err.Unwrap())
}

func TestErrUpdateConfigFile_NilCause(t *testing.T) {
	err := ErrUpdateConfigFile{}
	assert.Contains(t, err.Error(), "failed to update config file")
	assert.Nil(t, err.Unwrap())
}

func TestErrGetIDevIDAttrs_NilCause(t *testing.T) {
	err := ErrGetIDevIDAttrs{}
	assert.Contains(t, err.Error(), "failed to get IDevID attributes")
	assert.Nil(t, err.Unwrap())
}

func TestErrGetDecrypter_NilCause(t *testing.T) {
	err := ErrGetDecrypter{}
	assert.Contains(t, err.Error(), "failed to get decrypter")
	assert.Nil(t, err.Unwrap())
}

func TestErrContextCanceled_NilCause(t *testing.T) {
	err := ErrContextCanceled{}
	assert.Contains(t, err.Error(), "context canceled")
	assert.Nil(t, err.Unwrap())
}

func TestErrAutoGenFailed_NilCause(t *testing.T) {
	err := ErrAutoGenFailed{URI: "autogen://32"}
	assert.Contains(t, err.Error(), "autogen://32")
	assert.Nil(t, err.Unwrap())
}

func TestErrKMSGetFailed_NilCause(t *testing.T) {
	err := ErrKMSGetFailed{Path: "config/secret"}
	assert.Contains(t, err.Error(), "config/secret")
	assert.Nil(t, err.Unwrap())
}

func TestErrKMSStoreFailed_NilCause(t *testing.T) {
	err := ErrKMSStoreFailed{Path: "config/secret"}
	assert.Contains(t, err.Error(), "config/secret")
	assert.Nil(t, err.Unwrap())
}

func TestErrSecretsGetFailed_NilCause(t *testing.T) {
	err := ErrSecretsGetFailed{Path: "config/secret"}
	assert.Contains(t, err.Error(), "config/secret")
	assert.Nil(t, err.Unwrap())
}

func TestErrSecretsStoreFailed_NilCause(t *testing.T) {
	err := ErrSecretsStoreFailed{Path: "config/secret"}
	assert.Contains(t, err.Error(), "config/secret")
	assert.Nil(t, err.Unwrap())
}

func TestErrInvalidKMSURI_NoReason(t *testing.T) {
	err := ErrInvalidKMSURI{URI: "bad://uri"}
	assert.Contains(t, err.Error(), "invalid KMS URI")
	assert.Contains(t, err.Error(), "bad://uri")
}
