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
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// NewTrustCommand Tests
// =============================================================================

func TestNewTrustCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := NewTrustCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "trust", cmd.Use)
	assert.Equal(t, "Bootstrap platform trust", cmd.Short)
	assert.Contains(t, cmd.Long, "Bootstrap trust with the platform")

	// Verify key flags exist
	for _, flagName := range []string{
		"server-url", "strategy", "dns-server", "hostname",
		"noise-key", "noise-addr", "spki-pin", "bundle-path",
		"install-to-system-trust", "cert-path", "per-method-timeout",
	} {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
	}
}

func TestNewTrustCommand_FlagDefaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := NewTrustCommand(getFlags)

	// Strategy should default to auto
	strategyFlag := cmd.Flag("strategy")
	require.NotNil(t, strategyFlag)
	assert.Equal(t, bootstrap.StrategyAuto, strategyFlag.DefValue)

	// Install-to-system-trust should default to false
	installFlag := cmd.Flag("install-to-system-trust")
	require.NotNil(t, installFlag)
	assert.Equal(t, "false", installFlag.DefValue)

	// Cert path should have Alpine default
	certFlag := cmd.Flag("cert-path")
	require.NotNil(t, certFlag)
	assert.Equal(t, defaultCertPath, certFlag.DefValue)
}

// =============================================================================
// BuildBootstrapConfig Tests
// =============================================================================

func TestBuildBootstrapConfig(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategyAuto,
		dnsServer:        "8.8.8.8",
		hostname:         "platform.example.com",
		bundlePath:       "/tmp/ca-bundle.pem",
		perMethodTimeout: 10 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)

	assert.Equal(t, "https://platform:8443", config.ServerURL)
	assert.Equal(t, bootstrap.StrategyAuto, config.Strategy)
	assert.Equal(t, "8.8.8.8", config.DNSServer)
	assert.Equal(t, "platform.example.com", config.Hostname)
	assert.Equal(t, "/tmp/ca-bundle.pem", config.BundlePath)
	assert.Equal(t, 10*time.Second, config.PerMethodTimeout)
	assert.Nil(t, config.Noise)
	assert.Nil(t, config.SPKI)
}

func TestBuildBootstrapConfig_MissingURL(t *testing.T) {
	flags := &trustFlags{
		strategy: bootstrap.StrategyAuto,
	}

	_, err := buildBootstrapConfig(flags)
	require.Error(t, err)

	var urlErr ErrTrustServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestBuildBootstrapConfig_WithNoise(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategyNoise,
		noiseKey:         "aabbccdd",
		noiseAddr:        "platform:9999",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)

	require.NotNil(t, config.Noise)
	assert.Equal(t, "aabbccdd", config.Noise.ServerStaticKey)
	assert.Equal(t, "platform:9999", config.Noise.ServerAddr)
	assert.Nil(t, config.SPKI)
}

func TestBuildBootstrapConfig_WithSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategySPKI,
		spkiPin:          "sha256/AAAA+BBBB+CCCC",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)

	require.NotNil(t, config.SPKI)
	assert.Equal(t, "sha256/AAAA+BBBB+CCCC", config.SPKI.Pin)
	assert.Nil(t, config.Noise)
}

func TestBuildBootstrapConfig_WithBothNoiseAndSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategyAuto,
		noiseKey:         "aabbccdd",
		noiseAddr:        "platform:9999",
		spkiPin:          "sha256/AAAA",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)

	require.NotNil(t, config.Noise)
	require.NotNil(t, config.SPKI)
}

func TestBuildBootstrapConfig_EmptyNoiseKeyDoesNotSetNoise(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategyAuto,
		noiseAddr:        "platform:9999",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)
	assert.Nil(t, config.Noise)
}

func TestBuildBootstrapConfig_EmptySPKIPinDoesNotSetSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         bootstrap.StrategyAuto,
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildBootstrapConfig(flags)
	require.NoError(t, err)
	assert.Nil(t, config.SPKI)
}

// =============================================================================
// LogLevelFromVerbose Tests
// =============================================================================

func TestLogLevelFromVerbose_True(t *testing.T) {
	level := logLevelFromVerbose(true)
	assert.Equal(t, slog.LevelDebug, level)
}

func TestLogLevelFromVerbose_False(t *testing.T) {
	level := logLevelFromVerbose(false)
	assert.Equal(t, slog.LevelInfo, level)
}

// =============================================================================
// Trust Bootstrap Error Tests
// =============================================================================

func TestErrTrustServerURLRequired(t *testing.T) {
	err := ErrTrustServerURLRequired{}
	assert.Equal(t, "bootstrap trust: --server-url is required", err.Error())
}

func TestErrTrustBootstrapFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrTrustBootstrapFailed{Cause: cause}
	assert.Contains(t, err.Error(), "bootstrap trust: failed")
	assert.ErrorIs(t, err, cause)
}

func TestErrTrustInstallFailed(t *testing.T) {
	cause := assert.AnError
	err := ErrTrustInstallFailed{Path: "/usr/local/share/ca-certificates/test.crt", Cause: cause}
	assert.Contains(t, err.Error(), "test.crt")
	assert.ErrorIs(t, err, cause)
}

// =============================================================================
// Trust Command Registration Tests
// =============================================================================

func TestBootstrapCommand_HasTrustSubcommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	var hasTrust bool
	for _, sub := range subcommands {
		if sub.Use == "trust" {
			hasTrust = true
		}
	}
	assert.True(t, hasTrust, "trust subcommand should be registered under bootstrap")
}
