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

package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/internal/ca"
	"github.com/jeremyhahn/go-trusted-platform/internal/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/internal/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// writeTestCACert writes a self-signed CA certificate to a temp file and
// returns its path. Used to satisfy the remote-transport TLS validators
// without disabling certificate verification.
func writeTestCACert(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// =============================================================================
// NewRegistry Tests
// =============================================================================

func TestNewRegistry_NilConfig(t *testing.T) {
	registry, err := NewRegistry(nil)
	assert.Nil(t, registry)
	assert.Equal(t, ErrNilConfig, err)
}

func TestNewRegistry_NilLogger(t *testing.T) {
	cfg := &RegistryConfig{}
	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	assert.Equal(t, ErrNilLogger, err)
}

func TestNewRegistry_MinimalConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// Should not be started or closed
	assert.False(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())

	// SDK adapters should be nil (not configured)
	assert.Nil(t, registry.QuicBaaS())
	assert.Nil(t, registry.CA())
	assert.Nil(t, registry.XKMS())

	// Native services should be nil (not passed in)
	assert.Nil(t, registry.DeviceService())
	assert.Nil(t, registry.DNSService())
}

func TestNewRegistry_WithQuicBaaSConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// QuicBaaS adapter should be created but not started
	assert.NotNil(t, registry.QuicBaaS())
	assert.False(t, registry.QuicBaaS().IsStarted())
}

func TestNewRegistry_WithCAConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// CA adapter should be created but not started
	assert.NotNil(t, registry.CA())
	assert.False(t, registry.CA().IsStarted())
}

func TestNewRegistry_WithXKMSConfig(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// XKMS adapter should be created but not started
	assert.NotNil(t, registry.XKMS())
	assert.False(t, registry.XKMS().IsStarted())
}

func TestNewRegistry_WithAllAdapters(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// All adapters should be created but not started
	assert.NotNil(t, registry.QuicBaaS())
	assert.NotNil(t, registry.CA())
	assert.NotNil(t, registry.XKMS())

	assert.False(t, registry.QuicBaaS().IsStarted())
	assert.False(t, registry.CA().IsStarted())
	assert.False(t, registry.XKMS().IsStarted())
}

func TestNewRegistry_WithNativeServices(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Create mock native services (they can be nil pointers for testing)
	var deviceSvc *device.Service
	var dnsSvc *dns.Service

	cfg := &RegistryConfig{
		Logger:        logger,
		DeviceService: deviceSvc,
		DNSService:    dnsSvc,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// Native services should be nil (we passed nil)
	assert.Nil(t, registry.DeviceService())
	assert.Nil(t, registry.DNSService())
}

func TestNewRegistry_QuicBaaSConfigValidationError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Unix transport requires a socket path
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport:  quicbaas.TransportUnix,
			UnixSocket: "", // Missing required socket
		},
	}

	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.IsType(t, ErrAdapterCreationFailed{}, err)
	assert.Contains(t, err.Error(), "QuicBaaS")
}

func TestNewRegistry_CAConfigValidationError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Unix transport requires a socket path
	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport:  ca.TransportUnix,
			UnixSocket: "", // Missing required socket
		},
	}

	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.IsType(t, ErrAdapterCreationFailed{}, err)
	assert.Contains(t, err.Error(), "CA")
}

func TestNewRegistry_XKMSConfigValidationError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Unix transport requires a socket path
	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport:  xkms.TransportUnix,
			UnixSocket: "", // Missing required socket
		},
	}

	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.IsType(t, ErrAdapterCreationFailed{}, err)
	assert.Contains(t, err.Error(), "XKMS")
}

// =============================================================================
// Registry State Tests
// =============================================================================

func TestRegistry_InitialState(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// Initial state checks
	assert.False(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())
}

// =============================================================================
// Start/Stop Lifecycle Tests
// =============================================================================

func TestRegistry_Start_NilParams(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// Start with nil params should work (no adapters configured)
	ctx := t.Context()
	err = registry.Start(ctx, nil)
	require.NoError(t, err)

	assert.True(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())
}

func TestRegistry_Start_EmptyParams(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()
	err = registry.Start(ctx, &StartParams{})
	require.NoError(t, err)

	assert.True(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())
}

func TestRegistry_Start_AlreadyStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// First start
	err = registry.Start(ctx, nil)
	require.NoError(t, err)
	assert.True(t, registry.IsStarted())

	// Second start should be idempotent (no error)
	err = registry.Start(ctx, nil)
	require.NoError(t, err)
	assert.True(t, registry.IsStarted())
}

func TestRegistry_Start_WhenClosed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// Start then stop
	err = registry.Start(ctx, nil)
	require.NoError(t, err)
	err = registry.Stop(ctx)
	require.NoError(t, err)

	// Start after close should fail
	err = registry.Start(ctx, nil)
	require.Error(t, err)
	assert.IsType(t, ErrRegistryClosed{}, err)
}

func TestRegistry_Stop_NotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// Stop before start should be idempotent (no error)
	err = registry.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, registry.IsStarted())
	assert.True(t, registry.IsClosed())
}

func TestRegistry_Stop_AlreadyClosed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// Start the registry
	err = registry.Start(ctx, nil)
	require.NoError(t, err)

	// First stop
	err = registry.Stop(ctx)
	require.NoError(t, err)
	assert.True(t, registry.IsClosed())

	// Second stop should be idempotent (no error)
	err = registry.Stop(ctx)
	require.NoError(t, err)
	assert.True(t, registry.IsClosed())
}

func TestRegistry_FullLifecycle(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// Initial state
	assert.False(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())

	// Start
	err = registry.Start(ctx, &StartParams{})
	require.NoError(t, err)
	assert.True(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())

	// Stop
	err = registry.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, registry.IsStarted())
	assert.True(t, registry.IsClosed())
}

// =============================================================================
// Adapter Start Failure Tests (Tests adapter start error paths)
// =============================================================================

func TestRegistry_Start_QuicBaaSAdapterFailure(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure QuicBaaS in embedded mode
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Start without providing embedded service - should fail
	// because embedded mode requires the QuicBaaSService to be provided
	err = registry.Start(ctx, nil)
	require.Error(t, err)

	// Should be ErrAdapterStartFailed wrapping the embedded service required error
	var adapterErr ErrAdapterStartFailed
	assert.True(t, errors.As(err, &adapterErr))
	assert.Equal(t, "QuicBaaS", adapterErr.Adapter)

	// Registry should not be started
	assert.False(t, registry.IsStarted())
}

func TestRegistry_Start_CAAdapterFailure_WithQuicBaaSCleanup(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure CA in embedded mode (QuicBaaS not configured, so it won't start)
	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Start without providing embedded CA service - should fail
	err = registry.Start(ctx, nil)
	require.Error(t, err)

	// Should be ErrAdapterStartFailed for CA
	var adapterErr ErrAdapterStartFailed
	assert.True(t, errors.As(err, &adapterErr))
	assert.Equal(t, "CA", adapterErr.Adapter)

	// Registry should not be started
	assert.False(t, registry.IsStarted())
}

func TestRegistry_Start_XKMSAdapterFailure(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure XKMS in embedded mode
	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Start without providing embedded XKMS service - should fail
	err = registry.Start(ctx, nil)
	require.Error(t, err)

	// Should be ErrAdapterStartFailed for XKMS
	var adapterErr ErrAdapterStartFailed
	assert.True(t, errors.As(err, &adapterErr))
	assert.Equal(t, "XKMS", adapterErr.Adapter)

	// Registry should not be started
	assert.False(t, registry.IsStarted())
}

func TestRegistry_Start_AllAdaptersConfigured_QuicBaaSFails(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure all adapters in embedded mode
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Start without any embedded services - QuicBaaS should fail first
	err = registry.Start(ctx, nil)
	require.Error(t, err)

	var adapterErr ErrAdapterStartFailed
	assert.True(t, errors.As(err, &adapterErr))
	// QuicBaaS is started first, so it should fail first
	assert.Equal(t, "QuicBaaS", adapterErr.Adapter)

	assert.False(t, registry.IsStarted())
}

// =============================================================================
// Adapter Stop Tests (Tests adapter stop paths with configured adapters)
// =============================================================================

func TestRegistry_Stop_WithQuicBaaSAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure QuicBaaS adapter
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Call Stop directly (adapter is not started)
	// This exercises the adapter stop path even though adapter was never started
	err = registry.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, registry.IsClosed())
}

func TestRegistry_Stop_WithCAAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure CA adapter
	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Call Stop directly
	err = registry.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, registry.IsClosed())
}

func TestRegistry_Stop_WithXKMSAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure XKMS adapter
	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Call Stop directly
	err = registry.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, registry.IsClosed())
}

func TestRegistry_Stop_WithAllAdapters(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Configure all adapters
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	ctx := t.Context()

	// Call Stop directly - exercises all three adapter stop paths
	err = registry.Stop(ctx)
	require.NoError(t, err)

	assert.True(t, registry.IsClosed())
}

// =============================================================================
// SDK Service Accessor Tests (When Not Configured)
// =============================================================================

func TestRegistry_SDKServiceAccessors_NotConfigured(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// All SDK service accessors should return nil when not configured
	assert.Nil(t, registry.KV())
	assert.Nil(t, registry.KMS())
	assert.Nil(t, registry.Secrets())
	assert.Nil(t, registry.IAM())
	assert.Nil(t, registry.Crypto())
	assert.Nil(t, registry.Vector())
	assert.Nil(t, registry.TimeSeries())
	assert.Nil(t, registry.Scheduler())
	assert.Nil(t, registry.Messaging())
}

func TestRegistry_QuicBaaSAccessors_AdapterNotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// Adapter created but not started - all accessors return nil
	assert.NotNil(t, registry.QuicBaaS())
	assert.Nil(t, registry.KV())
	assert.Nil(t, registry.KMS())
	assert.Nil(t, registry.Secrets())
	assert.Nil(t, registry.IAM())
	assert.Nil(t, registry.Crypto())
	assert.Nil(t, registry.Vector())
	assert.Nil(t, registry.TimeSeries())
	assert.Nil(t, registry.Scheduler())
	assert.Nil(t, registry.Messaging())
}

// =============================================================================
// Native Service Tests
// =============================================================================

func TestRegistry_SetNativeServices(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// Initially nil
	assert.Nil(t, registry.DeviceService())
	assert.Nil(t, registry.DNSService())

	// Set services (using nil for simplicity, in real use these would be actual services)
	registry.SetDeviceService(nil)
	registry.SetDNSService(nil)

	// Still nil since we set nil values
	assert.Nil(t, registry.DeviceService())
	assert.Nil(t, registry.DNSService())
}

func TestRegistry_SetDeviceService_WithValue(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// We cannot create an actual device.Service without complex setup,
	// but we can verify the setter and getter work with the pointer type
	assert.Nil(t, registry.DeviceService())

	// The setter accepts *device.Service
	registry.SetDeviceService(nil)
	assert.Nil(t, registry.DeviceService())
}

func TestRegistry_SetDNSService_WithValue(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	// We cannot create an actual dns.Service without complex setup,
	// but we can verify the setter and getter work with the pointer type
	assert.Nil(t, registry.DNSService())

	// The setter accepts *dns.Service
	registry.SetDNSService(nil)
	assert.Nil(t, registry.DNSService())
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrRegistryClosed_Error(t *testing.T) {
	err := ErrRegistryClosed{}
	assert.Equal(t, "platform registry: registry is closed", err.Error())
}

func TestErrRegistryNotStarted_Error(t *testing.T) {
	err := ErrRegistryNotStarted{}
	assert.Equal(t, "platform registry: registry is not started", err.Error())
}

func TestErrAdapterCreationFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrAdapterCreationFailed{Adapter: "QuicBaaS", Cause: cause}
	assert.Contains(t, err.Error(), "platform registry: failed to create QuicBaaS adapter")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrAdapterStartFailed_Error(t *testing.T) {
	cause := assert.AnError
	err := ErrAdapterStartFailed{Adapter: "CA", Cause: cause}
	assert.Contains(t, err.Error(), "platform registry: failed to start CA adapter")
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrAdapterNotConfigured_AllAdapters(t *testing.T) {
	testCases := []struct {
		adapter  string
		expected string
	}{
		{"QuicBaaS", "platform registry: QuicBaaS adapter is not configured"},
		{"CA", "platform registry: CA adapter is not configured"},
		{"XKMS", "platform registry: XKMS adapter is not configured"},
	}

	for _, tc := range testCases {
		t.Run(tc.adapter, func(t *testing.T) {
			err := ErrAdapterNotConfigured{Adapter: tc.adapter}
			assert.Equal(t, tc.expected, err.Error())
		})
	}
}

func TestErrServiceUnavailable_Error(t *testing.T) {
	t.Run("without_reason", func(t *testing.T) {
		err := ErrServiceUnavailable{Service: "KMS"}
		assert.Equal(t, "platform registry: service KMS is unavailable", err.Error())
	})

	t.Run("with_reason", func(t *testing.T) {
		err := ErrServiceUnavailable{Service: "KMS", Reason: "not started"}
		assert.Equal(t, "platform registry: service KMS is unavailable: not started", err.Error())
	})

	t.Run("with_empty_reason", func(t *testing.T) {
		err := ErrServiceUnavailable{Service: "Secrets", Reason: ""}
		assert.Equal(t, "platform registry: service Secrets is unavailable", err.Error())
	})
}

// =============================================================================
// Remote Mode Configuration Tests
// =============================================================================

func TestRegistry_QuicBaaSConfig_RemoteMode(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	caPath := writeTestCACert(t)

	// Test with gRPC transport (remote mode). Remote transports require
	// a CA certificate path so TLS verification can be enforced.
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportGRPC,
			Address:   "localhost:10443",
			TLS:       &quicbaas.TLSConfig{CACert: caPath},
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// QuicBaaS adapter should be created but not started
	assert.NotNil(t, registry.QuicBaaS())
	assert.False(t, registry.QuicBaaS().IsStarted())
	assert.False(t, registry.QuicBaaS().IsEmbedded())
	assert.Equal(t, quicbaas.TransportGRPC, registry.QuicBaaS().Transport())
}

func TestRegistry_CAConfig_RemoteMode(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	caPath := writeTestCACert(t)

	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport: ca.TransportGRPC,
			Address:   "localhost:10444",
			TLS:       &ca.TLSConfig{CACert: caPath},
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	assert.NotNil(t, registry.CA())
	assert.False(t, registry.CA().IsStarted())
	assert.False(t, registry.CA().IsEmbedded())
	assert.Equal(t, ca.TransportGRPC, registry.CA().Transport())
}

func TestRegistry_XKMSConfig_RemoteMode(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	caPath := writeTestCACert(t)

	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportGRPC,
			Address:   "localhost:10445",
			TLS:       &xkms.TLSConfig{CACert: caPath},
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	assert.NotNil(t, registry.XKMS())
	assert.False(t, registry.XKMS().IsStarted())
	assert.False(t, registry.XKMS().IsEmbedded())
	assert.Equal(t, xkms.TransportGRPC, registry.XKMS().Transport())
}

func TestRegistry_QuicBaaSConfig_AllTransports(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	testCases := []struct {
		name      string
		transport quicbaas.Transport
		address   string
		socket    string
		embedded  bool
	}{
		{"embedded", quicbaas.TransportEmbedded, "", "", true},
		{"grpc", quicbaas.TransportGRPC, "localhost:10443", "", false},
		{"rest", quicbaas.TransportREST, "https://localhost:8443", "", false},
		{"quic", quicbaas.TransportQUIC, "localhost:9444", "", false},
		{"unix", quicbaas.TransportUnix, "", "/tmp/test.sock", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			qbCfg := &quicbaas.Config{
				Transport:  tc.transport,
				Address:    tc.address,
				UnixSocket: tc.socket,
			}
			// Remote transports enforce TLS verification; embedded mode
			// does not require a CA certificate.
			if !tc.embedded {
				qbCfg.TLS = &quicbaas.TLSConfig{CACert: writeTestCACert(t)}
			}
			cfg := &RegistryConfig{
				Logger:         logger,
				QuicBaaSConfig: qbCfg,
			}

			registry, err := NewRegistry(cfg)
			require.NoError(t, err)
			require.NotNil(t, registry)

			adapter := registry.QuicBaaS()
			assert.NotNil(t, adapter)
			assert.Equal(t, tc.transport, adapter.Transport())
			assert.Equal(t, tc.embedded, adapter.IsEmbedded())
		})
	}
}

// =============================================================================
// Concurrent Access Tests (Thread Safety)
// =============================================================================

func TestRegistry_ConcurrentAccess_Accessors(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads of all accessors
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.QuicBaaS()
			_ = registry.CA()
			_ = registry.XKMS()
			_ = registry.DeviceService()
			_ = registry.DNSService()
			_ = registry.KV()
			_ = registry.KMS()
			_ = registry.Secrets()
			_ = registry.IAM()
			_ = registry.Crypto()
			_ = registry.Vector()
			_ = registry.TimeSeries()
			_ = registry.Scheduler()
			_ = registry.Messaging()
			_ = registry.IsStarted()
			_ = registry.IsClosed()
		}()
	}

	wg.Wait()
}

func TestRegistry_ConcurrentAccess_SettersAndGetters(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads and writes
	for i := 0; i < iterations; i++ {
		wg.Add(2)

		// Reader goroutine
		go func() {
			defer wg.Done()
			_ = registry.DeviceService()
			_ = registry.DNSService()
		}()

		// Writer goroutine
		go func() {
			defer wg.Done()
			registry.SetDeviceService(nil)
			registry.SetDNSService(nil)
		}()
	}

	wg.Wait()
}

func TestRegistry_ConcurrentAccess_StartStop(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	var wg sync.WaitGroup
	iterations := 50

	// Start the registry first
	err = registry.Start(ctx, nil)
	require.NoError(t, err)

	// Concurrent state checks while running
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = registry.IsStarted()
			_ = registry.IsClosed()
		}()
	}

	wg.Wait()

	// Stop the registry
	err = registry.Stop(ctx)
	require.NoError(t, err)
}

func TestRegistry_ConcurrentAccess_MultipleStarts(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	var wg sync.WaitGroup
	goroutines := 10

	// Multiple goroutines trying to start concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Multiple starts should be idempotent
			_ = registry.Start(ctx, nil)
		}()
	}

	wg.Wait()

	// Should end up started
	assert.True(t, registry.IsStarted())

	// Clean up
	err = registry.Stop(ctx)
	require.NoError(t, err)
}

func TestRegistry_ConcurrentAccess_MultipleStops(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// Start the registry
	err = registry.Start(ctx, nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	goroutines := 10

	// Multiple goroutines trying to stop concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Multiple stops should be idempotent
			_ = registry.Stop(ctx)
		}()
	}

	wg.Wait()

	// Should end up closed
	assert.True(t, registry.IsClosed())
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

func TestRegistry_MultipleAdapterFailures_FirstFails(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// QuicBaaS config is invalid (Unix needs socket)
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportUnix,
			// Missing UnixSocket
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	// Should fail on first adapter (QuicBaaS)
	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "QuicBaaS")
}

func TestRegistry_MultipleAdapterFailures_SecondFails(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// QuicBaaS config is valid, CA config is invalid
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportUnix,
			// Missing UnixSocket
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	// Should fail on second adapter (CA)
	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA")
}

func TestRegistry_MultipleAdapterFailures_ThirdFails(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// QuicBaaS and CA configs are valid, XKMS config is invalid
	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportUnix,
			// Missing UnixSocket
		},
	}

	// Should fail on third adapter (XKMS)
	registry, err := NewRegistry(cfg)
	assert.Nil(t, registry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "XKMS")
}

func TestRegistry_StartParams_NilFields(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// StartParams with all nil fields should work when no adapters are configured
	params := &StartParams{
		QuicBaaSService: nil,
		CAService:       nil,
		XKMSService:     nil,
	}

	err = registry.Start(ctx, params)
	require.NoError(t, err)
	assert.True(t, registry.IsStarted())

	err = registry.Stop(ctx)
	require.NoError(t, err)
}

func TestRegistry_StateTransitions(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	ctx := t.Context()

	// State: not started, not closed
	assert.False(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())

	// Transition: start
	err = registry.Start(ctx, nil)
	require.NoError(t, err)

	// State: started, not closed
	assert.True(t, registry.IsStarted())
	assert.False(t, registry.IsClosed())

	// Transition: stop
	err = registry.Stop(ctx)
	require.NoError(t, err)

	// State: not started, closed
	assert.False(t, registry.IsStarted())
	assert.True(t, registry.IsClosed())

	// Transition: try to start again (should fail)
	err = registry.Start(ctx, nil)
	assert.Error(t, err)

	// State: still not started, still closed
	assert.False(t, registry.IsStarted())
	assert.True(t, registry.IsClosed())
}

// =============================================================================
// Error Chaining Tests
// =============================================================================

func TestErrAdapterCreationFailed_ErrorChain(t *testing.T) {
	rootCause := errors.New("root cause")
	wrapped := ErrAdapterCreationFailed{Adapter: "QuicBaaS", Cause: rootCause}

	// Should be able to unwrap to root cause
	assert.True(t, errors.Is(wrapped, rootCause))

	// Error message should contain adapter name and cause
	assert.Contains(t, wrapped.Error(), "QuicBaaS")
	assert.Contains(t, wrapped.Error(), "root cause")
}

func TestErrAdapterStartFailed_ErrorChain(t *testing.T) {
	rootCause := errors.New("connection refused")
	wrapped := ErrAdapterStartFailed{Adapter: "CA", Cause: rootCause}

	// Should be able to unwrap to root cause
	assert.True(t, errors.Is(wrapped, rootCause))

	// Error message should contain adapter name and cause
	assert.Contains(t, wrapped.Error(), "CA")
	assert.Contains(t, wrapped.Error(), "connection refused")
}

// =============================================================================
// Accessor Synchronization Tests
// =============================================================================

func TestRegistry_QuicBaaS_ReturnsAdapterConcurrently(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		QuicBaaSConfig: &quicbaas.Config{
			Transport: quicbaas.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			adapter := registry.QuicBaaS()
			assert.NotNil(t, adapter)
		}()
	}

	wg.Wait()
}

func TestRegistry_CA_ReturnsAdapterConcurrently(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		CAConfig: &ca.Config{
			Transport: ca.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			adapter := registry.CA()
			assert.NotNil(t, adapter)
		}()
	}

	wg.Wait()
}

func TestRegistry_XKMS_ReturnsAdapterConcurrently(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger: logger,
		XKMSConfig: &xkms.Config{
			Transport: xkms.TransportEmbedded,
		},
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)

	var wg sync.WaitGroup
	iterations := 100

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			adapter := registry.XKMS()
			assert.NotNil(t, adapter)
		}()
	}

	wg.Wait()
}

// =============================================================================
// RegistryConfig Tests
// =============================================================================

func TestRegistryConfig_AllFieldsNil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &RegistryConfig{
		Logger:         logger,
		QuicBaaSConfig: nil,
		CAConfig:       nil,
		XKMSConfig:     nil,
		DeviceService:  nil,
		DNSService:     nil,
	}

	registry, err := NewRegistry(cfg)
	require.NoError(t, err)
	require.NotNil(t, registry)

	// All should be nil
	assert.Nil(t, registry.QuicBaaS())
	assert.Nil(t, registry.CA())
	assert.Nil(t, registry.XKMS())
	assert.Nil(t, registry.DeviceService())
	assert.Nil(t, registry.DNSService())
}

// =============================================================================
// StartParams Tests
// =============================================================================

func TestStartParams_AllFieldsNil(t *testing.T) {
	params := &StartParams{
		QuicBaaSService: nil,
		CAService:       nil,
		XKMSService:     nil,
	}

	// Just verifying struct can be created with all nil fields
	assert.Nil(t, params.QuicBaaSService)
	assert.Nil(t, params.CAService)
	assert.Nil(t, params.XKMSService)
}
