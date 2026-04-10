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

package quicbaas

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFactory_EmbeddedMode(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Should have embedded client but no SDK client yet (not started)
	assert.NotNil(t, factory.Client())
	assert.Nil(t, factory.SDK())
	assert.Nil(t, factory.SDKClient())

	// Should report as embedded
	assert.True(t, factory.IsEmbedded())
	assert.Equal(t, TransportEmbedded, factory.Transport())

	// Should not be started or closed
	assert.False(t, factory.IsStarted())
	assert.False(t, factory.IsClosed())
}

func TestNewFactory_RemoteModeGRPC(t *testing.T) {
	cfg := RemoteConfig(TransportGRPC, "localhost:10443")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Client is created for all modes (manages SDK connection)
	assert.NotNil(t, factory.Client())

	// Should NOT have embedded server for remote mode
	assert.Nil(t, factory.EmbeddedServer())

	// Should report as remote
	assert.False(t, factory.IsEmbedded())
	assert.Equal(t, TransportGRPC, factory.Transport())
}

func TestNewFactory_RemoteModeREST(t *testing.T) {
	cfg := RemoteConfig(TransportREST, "http://localhost:8443")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Client is created for all modes (manages SDK connection)
	assert.NotNil(t, factory.Client())

	// Should NOT have embedded server for remote mode
	assert.Nil(t, factory.EmbeddedServer())

	// Should report as remote
	assert.False(t, factory.IsEmbedded())
	assert.Equal(t, TransportREST, factory.Transport())
}

func TestNewFactory_RemoteModeQUIC(t *testing.T) {
	cfg := RemoteConfig(TransportQUIC, "localhost:9444")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Client is created for all modes (manages SDK connection)
	assert.NotNil(t, factory.Client())

	// Should NOT have embedded server for remote mode
	assert.Nil(t, factory.EmbeddedServer())

	// Should report as remote
	assert.False(t, factory.IsEmbedded())
	assert.Equal(t, TransportQUIC, factory.Transport())
}

func TestNewFactory_RemoteModeUnix(t *testing.T) {
	cfg := UnixSocketConfig("/var/run/quicbaas.sock")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Client is created for all modes (manages SDK connection)
	assert.NotNil(t, factory.Client())

	// Should NOT have embedded server for remote mode
	assert.Nil(t, factory.EmbeddedServer())

	// Should report as remote (Unix socket is still remote from embedded perspective)
	assert.False(t, factory.IsEmbedded())
	assert.Equal(t, TransportUnix, factory.Transport())
}

func TestNewFactory_InvalidEmbeddedConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportEmbedded,
		DataDir:        "", // Invalid - missing data dir
		RequestTimeout: 30 * time.Second,
	}
	logger := logging.DefaultLogger()

	_, err := NewFactory(cfg, logger, nil)
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
}

func TestNewFactory_InvalidGRPCConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "", // Invalid - missing address
		RequestTimeout: 30 * time.Second,
	}
	logger := logging.DefaultLogger()

	_, err := NewFactory(cfg, logger, nil)
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
}

func TestFactory_Config(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// Config getter should return the same config
	assert.Equal(t, cfg, factory.Config())
}

func TestFactory_DataDir_Embedded(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// DataDir should match config
	assert.Equal(t, cfg.DataDir, factory.DataDir())
}

func TestFactory_DataDir_Remote(t *testing.T) {
	cfg := RemoteConfig(TransportGRPC, "localhost:10443")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// DataDir should be empty for remote mode
	assert.Empty(t, factory.DataDir())
}

func TestFactory_QuicBaaSClient(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// QuicBaaSClient returns the client as interface
	client := factory.QuicBaaSClient()
	assert.NotNil(t, client)
}

func TestFactory_QuicBaaSClient_Remote(t *testing.T) {
	cfg := RemoteConfig(TransportGRPC, "localhost:10443")
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// QuicBaaSClient is created for all modes (manages SDK connection)
	client := factory.QuicBaaSClient()
	assert.NotNil(t, client)

	// But embedded server should be nil for remote mode
	assert.Nil(t, factory.EmbeddedServer())
}

func TestFactory_SDK_NotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// SDK should be nil before Start()
	assert.Nil(t, factory.SDK())
	assert.Nil(t, factory.SDKClient())
}

func TestFactory_IsStarted_BeforeStart(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	assert.False(t, factory.IsStarted())
}

func TestFactory_IsClosed_Initial(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	factory, err := NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	assert.False(t, factory.IsClosed())
}

func TestFactory_TransportTypes(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		transport Transport
	}{
		{
			name:      "embedded",
			config:    TestConfig(t),
			transport: TransportEmbedded,
		},
		{
			name:      "grpc",
			config:    RemoteConfig(TransportGRPC, "localhost:10443"),
			transport: TransportGRPC,
		},
		{
			name:      "rest",
			config:    RemoteConfig(TransportREST, "http://localhost:8443"),
			transport: TransportREST,
		},
		{
			name:      "quic",
			config:    RemoteConfig(TransportQUIC, "localhost:9444"),
			transport: TransportQUIC,
		},
		{
			name:      "unix",
			config:    UnixSocketConfig("/var/run/test.sock"),
			transport: TransportUnix,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			factory, err := NewFactory(tt.config, logger, nil)
			require.NoError(t, err)

			assert.Equal(t, tt.transport, factory.Transport())
		})
	}
}

func TestFactory_IsEmbedded_Values(t *testing.T) {
	tests := []struct {
		name       string
		transport  Transport
		isEmbedded bool
	}{
		{"embedded", TransportEmbedded, true},
		{"grpc", TransportGRPC, false},
		{"rest", TransportREST, false},
		{"quic", TransportQUIC, false},
		{"unix", TransportUnix, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *Config
			switch tt.transport {
			case TransportEmbedded:
				cfg = TestConfig(t)
			case TransportUnix:
				cfg = UnixSocketConfig("/var/run/test.sock")
			default:
				cfg = RemoteConfig(tt.transport, "localhost:10443")
			}

			logger := logging.DefaultLogger()
			factory, err := NewFactory(cfg, logger, nil)
			require.NoError(t, err)

			assert.Equal(t, tt.isEmbedded, factory.IsEmbedded())
		})
	}
}
