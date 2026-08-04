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
	"log/slog"
	"testing"

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
	assert.True(t, cfg.Encrypted, "default should enable Encrypted (idevid)")
	assert.False(t, cfg.File, "default should disable the file:// escape hatch")
}

// =============================================================================
// kmsNotAvailableResolver tests (standalone mode fail-closed guard)
// =============================================================================

func TestKMSNotAvailableResolver_Scheme(t *testing.T) {
	r := &kmsNotAvailableResolver{}
	assert.Equal(t, "kms", r.Scheme())
}

func TestKMSNotAvailableResolver_CanResolve(t *testing.T) {
	r := &kmsNotAvailableResolver{}
	tests := []struct {
		uri      string
		expected bool
	}{
		{"kms://path/to/secret", true},
		{"KMS://uppercase", true},
		{"kms://", true},
		{"dynamic://role", false},
		{"xkms://backend/key", false},
		{"literal-value", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			assert.Equal(t, tt.expected, r.CanResolve(tt.uri))
		})
	}
}

func TestKMSNotAvailableResolver_Resolve_AlwaysErrors(t *testing.T) {
	r := &kmsNotAvailableResolver{}
	ctx := context.Background()

	_, err := r.Resolve(ctx, "kms://path/to/secret")

	require.Error(t, err)
	var kmsErr ErrSecretsServiceNotAvailableButKMSRequired
	require.ErrorAs(t, err, &kmsErr)
	assert.Equal(t, 1, kmsErr.URICount)
}

func TestErrSecretsServiceNotAvailableButKMSRequired_Error(t *testing.T) {
	err := ErrSecretsServiceNotAvailableButKMSRequired{URICount: 3}
	assert.Contains(t, err.Error(), "SecretsService not available")
	assert.Contains(t, err.Error(), "3")
}

// =============================================================================
// IDevIDResolver tests (via pkg/app, verifying quicbaassecret.SecretResolver contract)
// =============================================================================

func TestIDevIDResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := secrets.NewIDevIDResolver(nil, logger)

	assert.Equal(t, secrets.SchemeIDevID, resolver.Scheme())
}

// =============================================================================
// FileResolver tests (via pkg/app, verifying quicbaassecret.SecretResolver contract)
// =============================================================================

func TestFileResolver_Scheme(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	resolver := secrets.NewFileResolver(logger)

	assert.Equal(t, secrets.SchemeFile, resolver.Scheme())
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

func TestErrProcessSecrets_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrProcessSecrets{Cause: cause}

	assert.Contains(t, err.Error(), "failed to process secrets")
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

func TestIDevIDResolver_NilLogger(t *testing.T) {
	resolver := secrets.NewIDevIDResolver(nil, nil)
	assert.NotNil(t, resolver)
	assert.Equal(t, secrets.SchemeIDevID, resolver.Scheme())
}

func TestIDevIDResolver_NilDecrypter(t *testing.T) {
	resolver := secrets.NewIDevIDResolver(nil, nil)
	// Verifies construction with nil decrypter does not panic.
	assert.NotNil(t, resolver)
}

func TestErrProcessSecrets_NilCause(t *testing.T) {
	err := ErrProcessSecrets{}
	assert.Contains(t, err.Error(), "failed to process secrets")
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
// CryptoService tests (nil-factory path)
// =============================================================================

// TestApp_CryptoService_NilFactory verifies CryptoService returns nil when no
// QuicBaaS factory is wired (the default unit-test condition).
func TestApp_CryptoService_NilFactory(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	assert.Nil(t, app.CryptoService())
}
