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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SetTPM2Service Additional Coverage Tests
// =============================================================================

func TestMCPSetTPM2Service_WithValidService(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Initially nil
	assert.Nil(t, provider.tpm2Service)

	// Set the service
	provider.SetTPM2Service(mockTPM)

	// Should now be set
	assert.NotNil(t, provider.tpm2Service)
	assert.Equal(t, mockTPM, provider.tpm2Service)
}

func TestMCPSetTPM2Service_OverwriteExisting(t *testing.T) {
	mockTPM1 := &mockTPM2MCPService{}
	mockTPM2 := &mockTPM2MCPService{}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Set first service
	provider.SetTPM2Service(mockTPM1)
	assert.Equal(t, mockTPM1, provider.tpm2Service)

	// Overwrite with second service
	provider.SetTPM2Service(mockTPM2)
	assert.Equal(t, mockTPM2, provider.tpm2Service)
}

// =============================================================================
// KMSService Additional Coverage Tests
// =============================================================================

func TestKMSService_StartStopCoverage(t *testing.T) {
	service := &KMSService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	err := service.Start(ctx)
	require.NoError(t, err)
	assert.True(t, service.IsRunning())

	// Start again should be no-op
	err = service.Start(ctx)
	require.NoError(t, err)

	// Stop
	err = service.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, service.IsRunning())

	// Stop again should be no-op
	err = service.Stop(ctx)
	require.NoError(t, err)
}

func TestKMSService_Servers_NotInitializedCoverage(t *testing.T) {
	service := &KMSService{}

	// All server getters should return nil before initialization
	assert.Nil(t, service.KMSServer())
	assert.Nil(t, service.SecretsServer())
	assert.Nil(t, service.CryptoServer())
	assert.Nil(t, service.DEKServer())
}

// =============================================================================
// IAMService Additional Coverage Tests
// =============================================================================

func TestIAMService_StartStopCoverage(t *testing.T) {
	service := &IAMService{
		logger: slog.Default(),
	}

	ctx := context.Background()
	err := service.Start(ctx)
	require.NoError(t, err)
	assert.True(t, service.IsRunning())

	// Start again should be no-op
	err = service.Start(ctx)
	require.NoError(t, err)

	// Stop
	err = service.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, service.IsRunning())

	// Stop again should be no-op
	err = service.Stop(ctx)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Coverage Tests
// =============================================================================

func TestErrTPM2ServiceNotAvailable_ErrorCoverage(t *testing.T) {
	err := ErrTPM2ServiceNotAvailable{}
	assert.Equal(t, "TPM2 service not available", err.Error())
}

func TestErrTPM2OperationFailed_ErrorCoverage(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrTPM2OperationFailed{Operation: "test op", Cause: cause}
	assert.Contains(t, err.Error(), "test op")
	assert.Contains(t, err.Error(), "underlying error")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrIDevIDCertificateNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIDevIDCertificateNotFound{}
	assert.Equal(t, "IDevID certificate not installed", err.Error())
}

func TestErrIAKCertificateNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIAKCertificateNotFound{}
	assert.Equal(t, "IAK certificate not installed", err.Error())
}

func TestErrInvalidCertificatePEM_ErrorCoverage(t *testing.T) {
	err := ErrInvalidCertificatePEM{}
	assert.Equal(t, "invalid PEM-encoded certificate", err.Error())
}

func TestErrIDevIDNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIDevIDNotFound{}
	assert.Equal(t, "IDevID not found in TPM", err.Error())
}

func TestErrIAKNotFound_ErrorCoverage(t *testing.T) {
	err := ErrIAKNotFound{}
	assert.Equal(t, "IAK not found in TPM", err.Error())
}

// =============================================================================
// MCPServiceProvider Constructor Coverage Tests
// =============================================================================

func TestNewMCPServiceProvider_WithAllServices(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}

	config := &MCPServiceProviderConfig{
		Logger:      slog.Default(),
		TPM2Service: mockTPM,
	}

	provider := NewMCPServiceProvider(config)

	require.NotNil(t, provider)
	assert.NotNil(t, provider.logger)
	assert.Equal(t, mockTPM, provider.tpm2Service)
}

func TestNewMCPServiceProvider_NilLogger(t *testing.T) {
	config := &MCPServiceProviderConfig{
		Logger: nil,
	}

	provider := NewMCPServiceProvider(config)

	require.NotNil(t, provider)
	assert.NotNil(t, provider.logger) // Should use slog.Default()
}

// =============================================================================
// Daemon SetTPM2Service Coverage Tests
// =============================================================================

func TestDaemon_SetTPM2Service_NilService(t *testing.T) {
	d := &Daemon{
		logger: logging.NewLogger(slog.LevelDebug, nil),
	}

	// Setting nil should return early
	d.SetTPM2Service(nil)

	assert.Nil(t, d.tpm2Service)
}

func TestDaemon_SetTPM2Service_WithService(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	mockProvider := &MCPServiceProvider{
		logger: logging.NewLogger(slog.LevelDebug, nil).Slog(),
	}

	d := &Daemon{
		logger:      logging.NewLogger(slog.LevelDebug, nil),
		mcpProvider: mockProvider,
	}

	d.SetTPM2Service(mockTPM)

	assert.Equal(t, mockTPM, d.tpm2Service)
	assert.Equal(t, mockTPM, mockProvider.tpm2Service)
}

func TestDaemon_TPM2Service_Getter(t *testing.T) {
	mockTPM := &mockTPM2MCPService{}
	d := &Daemon{
		tpm2Service: mockTPM,
	}

	result := d.TPM2Service()
	assert.Equal(t, mockTPM, result)
}
