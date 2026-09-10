// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
)

// fakeSnapshotSource serves a fixed snapshot to the metrics collector.
type fakeSnapshotSource struct{ snap *gwstate.Snapshot }

func (f fakeSnapshotSource) Snapshot() *gwstate.Snapshot { return f.snap }

func metricsTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBuildMetricsServer_ServesTheSnapshot(t *testing.T) {
	source := fakeSnapshotSource{snap: &gwstate.Snapshot{
		GatewayID: "lab-node-1-gateway",
		Services:  []gwstate.ServiceState{{Name: "tunnels", Active: true, Healthy: true}},
	}}
	server, err := BuildMetricsServer(&MetricsConfig{Enabled: true, Listen: "127.0.0.1:0"}, source, metricsTestLogger())
	require.NoError(t, err)
	require.NotNil(t, server)
	defer func() { require.NoError(t, server.Shutdown()) }()

	done := make(chan error, 1)
	go func() { done <- server.Serve() }()

	resp, err := http.Get("http://" + server.Addr() + metricsPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), `gatewayd_service_active{gateway="lab-node-1-gateway",service="tunnels"} 1`)

	require.NoError(t, server.Shutdown())
	require.NoError(t, <-done, "a drained endpoint exits without error")
}

func TestBuildMetricsServer_DisabledOrRefused(t *testing.T) {
	logger := metricsTestLogger()
	source := fakeSnapshotSource{snap: &gwstate.Snapshot{GatewayID: "x"}}

	t.Run("absent section", func(t *testing.T) {
		server, err := BuildMetricsServer(nil, source, logger)
		require.NoError(t, err)
		assert.Nil(t, server, "no section, no endpoint")
	})

	t.Run("disabled section", func(t *testing.T) {
		server, err := BuildMetricsServer(&MetricsConfig{Enabled: false}, source, logger)
		require.NoError(t, err)
		assert.Nil(t, server)
	})

	t.Run("no gateway to collect from", func(t *testing.T) {
		_, err := BuildMetricsServer(&MetricsConfig{Enabled: true, Listen: "127.0.0.1:0"}, nil, logger)
		var listenErr *ErrMetricsListen
		require.True(t, errors.As(err, &listenErr), "got %v", err)
	})

	t.Run("an address that cannot be bound fails the boot", func(t *testing.T) {
		_, err := BuildMetricsServer(&MetricsConfig{Enabled: true, Listen: "203.0.113.99:9169"}, source, logger)
		var listenErr *ErrMetricsListen
		require.True(t, errors.As(err, &listenErr), "got %v", err)
		assert.Contains(t, listenErr.Error(), "203.0.113.99:9169")
	})
}

func TestMetricsConfig_DefaultsAndValidation(t *testing.T) {
	assert.Equal(t, DefaultMetricsListen, (&MetricsConfig{Enabled: true}).EffectiveListen())
	assert.Equal(t, "0.0.0.0:9100", (&MetricsConfig{Enabled: true, Listen: "0.0.0.0:9100"}).EffectiveListen())

	var absent *MetricsConfig
	assert.NoError(t, absent.Validate())
	assert.NoError(t, (&MetricsConfig{Enabled: false, Listen: "nonsense"}).Validate(), "a disabled section binds nothing")

	var listenErr *ErrMetricsListen
	err := (&MetricsConfig{Enabled: true, Listen: "nonsense"}).Validate()
	require.True(t, errors.As(err, &listenErr), "got %v", err)
}

func TestLoadServeConfig_MetricsSection(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(strings.NewReader("metrics:\n  enabled: true\n  listen: \"127.0.0.1:9169\"\n")))

	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Metrics)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, "127.0.0.1:9169", cfg.Metrics.EffectiveListen())

	t.Run("an unbindable address is refused at load", func(t *testing.T) {
		bad := viper.New()
		bad.SetConfigType("yaml")
		require.NoError(t, bad.ReadConfig(strings.NewReader("metrics:\n  enabled: true\n  listen: \"nonsense\"\n")))
		_, err := LoadServeConfig(bad)
		var section *ErrConfigSection
		require.True(t, errors.As(err, &section), "got %v", err)
		assert.Equal(t, "metrics", section.Section)
	})
}
