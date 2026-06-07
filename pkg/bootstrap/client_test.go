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

package bootstrap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClientTestLogger creates a silent logger for unit tests.
func newClientTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, io.Discard)
}

// validDANEConfig returns a minimal valid ClientConfig for the DANE strategy.
func validDANEConfig() *ClientConfig {
	return &ClientConfig{
		Strategy:         StrategyDANE,
		ServerURL:        "https://example.com",
		DNSServer:        "8.8.8.8:53",
		PerMethodTimeout: 5 * time.Second,
	}
}

// validEmbeddedConfig returns a minimal valid ClientConfig for the embedded strategy.
func validEmbeddedConfig() *ClientConfig {
	return &ClientConfig{
		Strategy:         StrategyEmbedded,
		PerMethodTimeout: 5 * time.Second,
	}
}

// validNoiseConfig returns a minimal valid ClientConfig for the noise strategy.
func validNoiseConfig() *ClientConfig {
	return &ClientConfig{
		Strategy:         StrategyNoise,
		PerMethodTimeout: 5 * time.Second,
		Noise: &ClientNoiseConfig{
			ServerAddr:      "localhost:9999",
			ServerStaticKey: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}

// validSPKIConfig returns a minimal valid ClientConfig for the SPKI strategy.
func validSPKIConfig() *ClientConfig {
	return &ClientConfig{
		Strategy:         StrategySPKI,
		ServerURL:        "https://example.com",
		PerMethodTimeout: 5 * time.Second,
		SPKI: &ClientSPKIConfig{
			Pin: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		},
	}
}

// --- NewClient tests ---

func TestNewClient_ValidDANEConfig(t *testing.T) {
	client, err := NewClient(validDANEConfig(), newClientTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_ValidEmbeddedConfig(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_ValidNoiseConfig(t *testing.T) {
	client, err := NewClient(validNoiseConfig(), newClientTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_ValidSPKIConfig(t *testing.T) {
	client, err := NewClient(validSPKIConfig(), newClientTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_ValidAutoConfig(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyAuto,
		PerMethodTimeout: 5 * time.Second,
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestNewClient_NilConfig(t *testing.T) {
	client, err := NewClient(nil, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "config", configErr.Field)
}

func TestNewClient_NilLogger(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), nil)
	require.Error(t, err)
	assert.Nil(t, client)

	var loggerErr ErrNilLogger
	assert.True(t, errors.As(err, &loggerErr))
}

func TestNewClient_InvalidStrategy(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         "bogus",
		PerMethodTimeout: 5 * time.Second,
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var stratErr *ErrStrategyNotSupported
	assert.True(t, errors.As(err, &stratErr))
	assert.Equal(t, "bogus", stratErr.Strategy)
}

func TestNewClient_EmptyStrategy(t *testing.T) {
	cfg := &ClientConfig{
		PerMethodTimeout: 5 * time.Second,
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "strategy", configErr.Field)
}

func TestNewClient_NegativeTimeout(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyEmbedded,
		PerMethodTimeout: -1 * time.Second,
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "per-method-timeout", configErr.Field)
}

func TestNewClient_DANEWithoutDNSServer(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyDANE,
		ServerURL:        "https://example.com",
		PerMethodTimeout: 5 * time.Second,
		// DNSServer intentionally omitted
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "dns-server", configErr.Field)
}

func TestNewClient_NoiseWithoutConfig(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyNoise,
		PerMethodTimeout: 5 * time.Second,
		// Noise intentionally nil
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "noise", configErr.Field)
}

func TestNewClient_NoiseWithoutStaticKey(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyNoise,
		PerMethodTimeout: 5 * time.Second,
		Noise: &ClientNoiseConfig{
			ServerAddr: "localhost:9999",
			// ServerStaticKey intentionally empty
		},
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "noise.server-static-key", configErr.Field)
}

func TestNewClient_NoiseWithoutServerAddr(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategyNoise,
		PerMethodTimeout: 5 * time.Second,
		Noise: &ClientNoiseConfig{
			ServerStaticKey: "0000000000000000000000000000000000000000000000000000000000000000",
			// ServerAddr intentionally empty
		},
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "noise.server-addr", configErr.Field)
}

func TestNewClient_SPKIWithoutConfig(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategySPKI,
		ServerURL:        "https://example.com",
		PerMethodTimeout: 5 * time.Second,
		// SPKI intentionally nil
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "spki", configErr.Field)
}

func TestNewClient_SPKIWithoutPin(t *testing.T) {
	cfg := &ClientConfig{
		Strategy:         StrategySPKI,
		ServerURL:        "https://example.com",
		PerMethodTimeout: 5 * time.Second,
		SPKI:             &ClientSPKIConfig{
			// Pin intentionally empty
		},
	}
	client, err := NewClient(cfg, newClientTestLogger())
	require.Error(t, err)
	assert.Nil(t, client)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "spki.pin", configErr.Field)
}

// --- strategy → mode mapping ---

func TestStrategyToMode_AllSupportedStrategies(t *testing.T) {
	cases := map[string]bool{
		StrategyDANE:  true,
		StrategyNoise: true,
		StrategySPKI:  true,
		StrategyAuto:  true,
		// StrategyEmbedded is intentionally NOT mapped — FetchCABundle
		// short-circuits before reaching the library.
		StrategyEmbedded: false,
	}
	for strategy, wantSupported := range cases {
		strategy, wantSupported := strategy, wantSupported
		t.Run(strategy, func(t *testing.T) {
			_, err := strategyToMode(strategy)
			if wantSupported {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// --- FetchCABundle tests ---

func TestFetchCABundle_EmbeddedStrategy_ReturnsNil(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	bundle, err := client.FetchCABundle(context.Background())
	require.NoError(t, err)
	assert.Nil(t, bundle)
}

func TestFetchCABundle_UnknownStrategy_ReturnsError(t *testing.T) {
	// Build a client with a valid strategy, then mutate the config to simulate
	// an unsupported strategy reaching the dispatch layer.
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	// Overwrite the strategy after construction to bypass Validate().
	client.config.Strategy = "quantum"

	bundle, err := client.FetchCABundle(context.Background())
	require.Error(t, err)
	assert.Nil(t, bundle)

	var stratErr *ErrStrategyNotSupported
	assert.True(t, errors.As(err, &stratErr))
	assert.Equal(t, "quantum", stratErr.Strategy)
}

func TestFetchCABundle_NoiseWithoutNoiseConfig_ReturnsError(t *testing.T) {
	// Config-validation errors are returned directly (not wrapped in
	// ErrBootstrapFetchFailed) because they happen before the
	// bootstrap library is invoked.
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	client.config.Strategy = StrategyNoise
	client.config.Noise = nil

	bundle, err := client.FetchCABundle(context.Background())
	require.Error(t, err)
	assert.Nil(t, bundle)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "noise", configErr.Field)
}

func TestFetchCABundle_SPKIWithoutSPKIConfig_ReturnsError(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	client.config.Strategy = StrategySPKI
	client.config.SPKI = nil

	bundle, err := client.FetchCABundle(context.Background())
	require.Error(t, err)
	assert.Nil(t, bundle)

	var configErr *ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "spki", configErr.Field)
}

// --- InstallToSystemTrust tests ---

func TestInstallToSystemTrust_Success(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-bundle.pem")
	bundlePEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n")

	err = client.InstallToSystemTrust(bundlePEM, certPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, bundlePEM, data)
}

func TestInstallToSystemTrust_EmptyBundle(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-bundle.pem")

	err = client.InstallToSystemTrust([]byte{}, certPath)
	require.Error(t, err)

	var emptyErr ErrCABundleEmpty
	assert.True(t, errors.As(err, &emptyErr))
}

func TestInstallToSystemTrust_NilBundle(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-bundle.pem")

	err = client.InstallToSystemTrust(nil, certPath)
	require.Error(t, err)

	var emptyErr ErrCABundleEmpty
	assert.True(t, errors.As(err, &emptyErr))
}

func TestInstallToSystemTrust_CreatesParentDirs(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "nested", "deep", "ca-bundle.pem")
	bundlePEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n")

	err = client.InstallToSystemTrust(bundlePEM, certPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, bundlePEM, data)

	// Verify intermediate directories were created.
	info, statErr := os.Stat(filepath.Join(tmpDir, "nested", "deep"))
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

func TestInstallToSystemTrust_InvalidPath(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	// /proc is a read-only filesystem on Linux; MkdirAll or WriteFile will fail.
	certPath := "/proc/nonexistent/subdir/ca-bundle.pem"
	bundlePEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n")

	err = client.InstallToSystemTrust(bundlePEM, certPath)
	require.Error(t, err)

	var writeErr *ErrWriteFailed
	assert.True(t, errors.As(err, &writeErr))
}

func TestInstallToSystemTrust_OverwritesExistingFile(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-bundle.pem")

	original := []byte("original content")
	require.NoError(t, os.WriteFile(certPath, original, 0644))

	newBundle := []byte("-----BEGIN CERTIFICATE-----\nnew-content\n-----END CERTIFICATE-----\n")
	err = client.InstallToSystemTrust(newBundle, certPath)
	require.NoError(t, err)

	data, readErr := os.ReadFile(certPath)
	require.NoError(t, readErr)
	assert.Equal(t, newBundle, data)
}

func TestInstallToSystemTrust_FilePermissions(t *testing.T) {
	client, err := NewClient(validEmbeddedConfig(), newClientTestLogger())
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca-bundle.pem")
	bundlePEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n")

	err = client.InstallToSystemTrust(bundlePEM, certPath)
	require.NoError(t, err)

	info, statErr := os.Stat(certPath)
	require.NoError(t, statErr)
	// File should be readable by all (0644).
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}
