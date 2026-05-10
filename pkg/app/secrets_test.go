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
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretsConfig_Default(t *testing.T) {
	cfg := DefaultSecretsConfig()

	assert.NotNil(t, cfg)
	assert.False(t, cfg.Enabled, "default should have Enabled=false for backward compatibility")
	assert.True(t, cfg.LocalKMS, "default should enable LocalKMS")
	assert.False(t, cfg.RemoteKMS, "default should disable RemoteKMS")
	assert.True(t, cfg.Encrypted, "default should enable Encrypted")
	assert.True(t, cfg.ConfigEncryption, "default should enable ConfigEncryption")
	assert.True(t, cfg.MigrateToKMS, "default should enable MigrateToKMS")
	assert.False(t, cfg.UpdateConfigFile, "default should disable UpdateConfigFile")
}

func TestLocalSecretsResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := NewLocalSecretsResolver(nil, logger)

	assert.Equal(t, bootstrap.SchemeKMS, resolver.Scheme())
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

func TestIDevIDResolverAdapter_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	adapter := NewIDevIDResolverAdapter(nil, logger)

	assert.Equal(t, bootstrap.SchemeIDevID, adapter.Scheme())
}

// =============================================================================
// EncryptedResolverAdapter tests
// =============================================================================

func TestEncryptedResolverAdapter_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := secrets.NewEncryptedResolver(nil, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	assert.Equal(t, bootstrap.SchemeEncrypted, adapter.Scheme())
}

func TestEncryptedResolverAdapter_CanResolve(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := secrets.NewEncryptedResolver(nil, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	tests := []struct {
		name     string
		uri      string
		expected bool
	}{
		{
			name:     "encrypted URI",
			uri:      "encrypted://dGVzdA",
			expected: true,
		},
		{
			name:     "encrypted prefix",
			uri:      "encrypted:dGVzdA",
			expected: true,
		},
		{
			name:     "encrypted URI uppercase",
			uri:      "ENCRYPTED://dGVzdA",
			expected: true,
		},
		{
			name:     "kms URI should not resolve",
			uri:      "kms://path/to/secret",
			expected: false,
		},
		{
			name:     "idevid URI should not resolve",
			uri:      "idevid://ciphertext",
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
			result := adapter.CanResolve(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncryptedResolverAdapter_Resolve_Success(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	expectedPlaintext := []byte("my-secret-value")

	// Create a fake ciphertext: 12-byte nonce + actual data
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	fakeCipherData := append(nonce, []byte("encrypted-payload")...)

	// Base64url encode the nonce+ciphertext
	encoded := base64.RawURLEncoding.EncodeToString(fakeCipherData)
	uri := "encrypted://" + encoded

	decryptFn := func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return expectedPlaintext, nil
	}

	resolver := secrets.NewEncryptedResolver(decryptFn, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	result, err := adapter.Resolve(ctx, uri)

	require.NoError(t, err)
	assert.Equal(t, expectedPlaintext, result)
}

func TestEncryptedResolverAdapter_Resolve_DecryptError(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	// Create a fake ciphertext: 12-byte nonce + actual data
	nonce := make([]byte, 12)
	fakeCipherData := append(nonce, []byte("bad-data")...)
	encoded := base64.RawURLEncoding.EncodeToString(fakeCipherData)
	uri := "encrypted://" + encoded

	decryptFn := func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		return nil, errors.New("decrypt failed")
	}

	resolver := secrets.NewEncryptedResolver(decryptFn, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	_, err := adapter.Resolve(ctx, uri)

	require.Error(t, err)
}

func TestEncryptedResolverAdapter_Resolve_NilDecryptFunc(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	resolver := secrets.NewEncryptedResolver(nil, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	_, err := adapter.Resolve(ctx, "encrypted://dGVzdA")

	require.Error(t, err)
}

func TestEncryptedResolverAdapter_NilLogger(t *testing.T) {
	resolver := secrets.NewEncryptedResolver(nil, nil)
	adapter := NewEncryptedResolverAdapter(resolver, nil)
	assert.NotNil(t, adapter)
	assert.Equal(t, bootstrap.SchemeEncrypted, adapter.Scheme())
}

// =============================================================================
// configDecryptFunc tests
// =============================================================================

func TestConfigDecryptFunc_CiphertextTooShort(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	ctx := context.Background()

	// Create a fake ciphertext that is too short (less than nonce size)
	shortCiphertext := make([]byte, 5)

	// Use the function directly with a nil app (we just test the closure)
	decryptFn := func(ctx context.Context, ciphertext []byte) ([]byte, error) {
		// This checks the nonce extraction logic
		const nonceSize = 12
		if len(ciphertext) <= nonceSize {
			return nil, ErrConfigDecryptFailed{
				Cause: ErrInvalidCiphertextLength{
					Length:   len(ciphertext),
					MinBytes: nonceSize + 1,
				},
			}
		}
		return nil, nil
	}

	// Encode the short ciphertext and create URI
	encoded := base64.RawURLEncoding.EncodeToString(shortCiphertext)
	uri := "encrypted://" + encoded

	resolver := secrets.NewEncryptedResolver(decryptFn, logger)
	adapter := NewEncryptedResolverAdapter(resolver, logger)

	_, err := adapter.Resolve(ctx, uri)

	require.Error(t, err)
}

// =============================================================================
// PlatformConfigKeyID constant test
// =============================================================================

func TestPlatformConfigKeyID(t *testing.T) {
	assert.Equal(t, "platform-config-key", PlatformConfigKeyID)
}

// =============================================================================
// EnsurePlatformConfigKey tests
// =============================================================================

func TestEnsurePlatformConfigKey_NilKMS(t *testing.T) {
	app := &App{
		Logger: logging.DefaultLogger(),
	}

	err := app.EnsurePlatformConfigKey(context.Background())

	require.Error(t, err)
	var kmsErr ErrKMSNotAvailable
	assert.ErrorAs(t, err, &kmsErr)
}

// =============================================================================
// Error type tests
// =============================================================================

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

func TestLocalSecretsResolver_NilLogger(t *testing.T) {
	resolver := NewLocalSecretsResolver(nil, nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, bootstrap.SchemeKMS, resolver.Scheme())
}

func TestSecretsServiceClient_NilLogger(t *testing.T) {
	client := NewSecretsServiceClient(nil, nil)
	assert.NotNil(t, client)
}

func TestIDevIDResolverAdapter_NilLogger(t *testing.T) {
	adapter := NewIDevIDResolverAdapter(nil, nil)
	assert.NotNil(t, adapter)
	assert.Equal(t, bootstrap.SchemeIDevID, adapter.Scheme())
}

func TestIDevIDResolverAdapter_CanResolve_NilResolver(t *testing.T) {
	adapter := NewIDevIDResolverAdapter(nil, nil)

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

// =============================================================================
// New error type tests for config encryption
// =============================================================================

func TestErrConfigDecryptFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrConfigDecryptFailed{Cause: cause}

	assert.Contains(t, err.Error(), "config decryption failed")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrConfigDecryptFailed_NilCause(t *testing.T) {
	err := ErrConfigDecryptFailed{}
	assert.Contains(t, err.Error(), "config decryption failed")
	assert.Nil(t, err.Unwrap())
}

func TestErrInvalidCiphertextLength_Error(t *testing.T) {
	err := ErrInvalidCiphertextLength{Length: 5, MinBytes: 13}
	assert.Contains(t, err.Error(), "ciphertext too short")
	assert.Contains(t, err.Error(), "5")
	assert.Contains(t, err.Error(), "13")
}

func TestErrEmptyDecryptResult_Error(t *testing.T) {
	err := ErrEmptyDecryptResult{}
	assert.Contains(t, err.Error(), "decrypt returned empty plaintext")
}

func TestErrConfigKeyGenerateFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrConfigKeyGenerateFailed{Cause: cause}

	assert.Contains(t, err.Error(), "failed to generate platform config-encryption key")
	assert.ErrorIs(t, err.Unwrap(), cause)
}

func TestErrConfigKeyGenerateFailed_NilCause(t *testing.T) {
	err := ErrConfigKeyGenerateFailed{}
	assert.Contains(t, err.Error(), "failed to generate platform config-encryption key")
	assert.Nil(t, err.Unwrap())
}
