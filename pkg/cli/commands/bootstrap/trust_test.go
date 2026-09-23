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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
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
	assert.Equal(t, strategyAuto, strategyFlag.DefValue)

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
// BuildTrustConfig Tests
// =============================================================================

func TestBuildTrustConfig(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         strategyAuto,
		dnsServer:        "8.8.8.8",
		hostname:         "platform.example.com",
		bundlePath:       "/api/v1/ca/bundle",
		perMethodTimeout: 10 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)
	require.NotNil(t, config.Bootstrap)

	scope := config.Bootstrap
	assert.Equal(t, "https://platform:8443", scope.ServerURL)
	assert.Equal(t,
		[]trust.Strategy{trust.StrategyDANE, trust.StrategyNoise, trust.StrategySPKI},
		scope.Strategies)
	// normalizeDNSServer auto-appends :53 for backward-compat with the
	// previous host-only flag form.
	require.NotNil(t, scope.DANE)
	assert.Equal(t, "8.8.8.8:53", scope.DANE.DNSServer)
	assert.Equal(t, "platform.example.com", scope.Hostname)
	assert.Equal(t, "/api/v1/ca/bundle", scope.BundlePath)
	assert.Equal(t, 10*time.Second, scope.PerMethodTimeout)
	assert.Nil(t, scope.Noise)
	assert.Nil(t, scope.SPKI)
}

func TestStrategiesFromFlag(t *testing.T) {
	autoChain := []trust.Strategy{trust.StrategyDANE, trust.StrategyNoise, trust.StrategySPKI}
	tests := []struct {
		in   string
		want []trust.Strategy
	}{
		{"", autoChain},
		{strategyAuto, autoChain},
		{"dane", []trust.Strategy{trust.StrategyDANE}},
		{"noise", []trust.Strategy{trust.StrategyNoise}},
		{"spki", []trust.Strategy{trust.StrategySPKI}},
		{"embedded", []trust.Strategy{trust.StrategyEmbedded}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			assert.Equal(t, tt.want, strategiesFromFlag(tt.in))
		})
	}
}

func TestNormalizeDNSServer(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"  ", ""},
		{"8.8.8.8", "8.8.8.8:53"},
		{"8.8.8.8:53", "8.8.8.8:53"},
		{"198.18.1.140", "198.18.1.140:53"},
		{"198.18.1.140:8053", "198.18.1.140:8053"},
		{"[::1]:53", "[::1]:53"},
		{"::1", "[::1]:53"},
		{"2001:db8::1", "[2001:db8::1]:53"},
		{"[2001:db8::1]:8053", "[2001:db8::1]:8053"},
		{"dns.example.com", "dns.example.com:53"},
		{"dns.example.com:8053", "dns.example.com:8053"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeDNSServer(tt.in)
			assert.Equal(t, tt.want, got, "normalizeDNSServer(%q)", tt.in)
		})
	}
}

func TestBuildTrustConfig_MissingURL(t *testing.T) {
	flags := &trustFlags{
		strategy: strategyAuto,
	}

	_, err := buildTrustConfig(flags)
	require.Error(t, err)

	var urlErr ErrTrustServerURLRequired
	require.ErrorAs(t, err, &urlErr)
}

func TestBuildTrustConfig_WithNoise(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         string(trust.StrategyNoise),
		noiseKey:         "aabbccdd",
		noiseAddr:        "platform:9999",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)

	scope := config.Bootstrap
	require.NotNil(t, scope.Noise)
	assert.Equal(t, "aabbccdd", scope.Noise.ServerStaticKey)
	assert.Equal(t, "platform:9999", scope.Noise.ServerAddr)
	assert.Nil(t, scope.SPKI)
}

func TestBuildTrustConfig_WithSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         string(trust.StrategySPKI),
		spkiPin:          "deadbeefcafe",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)

	scope := config.Bootstrap
	require.NotNil(t, scope.SPKI)
	assert.Equal(t, "deadbeefcafe", scope.SPKI.Pin)
	assert.Nil(t, scope.Noise)
}

func TestBuildTrustConfig_WithBothNoiseAndSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         strategyAuto,
		noiseKey:         "aabbccdd",
		noiseAddr:        "platform:9999",
		spkiPin:          "deadbeefcafe",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)

	scope := config.Bootstrap
	require.NotNil(t, scope.Noise)
	require.NotNil(t, scope.SPKI)
}

func TestBuildTrustConfig_EmptyNoiseKeyDoesNotSetNoise(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         strategyAuto,
		noiseAddr:        "platform:9999",
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)
	assert.Nil(t, config.Bootstrap.Noise)
}

func TestBuildTrustConfig_EmptySPKIPinDoesNotSetSPKI(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         strategyAuto,
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)
	assert.Nil(t, config.Bootstrap.SPKI)
}

func TestBuildTrustConfig_EmptyDNSServerDoesNotSetDANE(t *testing.T) {
	flags := &trustFlags{
		serverURL:        "https://platform:8443",
		strategy:         strategyAuto,
		perMethodTimeout: 5 * time.Second,
	}

	config, err := buildTrustConfig(flags)
	require.NoError(t, err)
	assert.Nil(t, config.Bootstrap.DANE)
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
