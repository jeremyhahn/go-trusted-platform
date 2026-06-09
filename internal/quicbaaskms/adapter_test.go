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

package quicbaaskms

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCACertPath is a placeholder CA certificate path for config-validation
// tests. Config.Validate only requires a non-empty TLS.CACert for remote
// transports (presence check, no file load), so a fixed path satisfies the
// mTLS security posture without an on-disk fixture.
const testCACertPath = "/path/to/ca.crt"

func TestNewAdapter(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("creates adapter with valid config", func(t *testing.T) {
		cfg := DefaultConfig()
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.NotNil(t, adapter)
		assert.Equal(t, cfg, adapter.Config())
		assert.False(t, adapter.IsStarted())
		assert.False(t, adapter.IsClosed())
		assert.True(t, adapter.IsEmbedded())
		assert.False(t, adapter.IsRemote())
	})

	t.Run("returns error with nil config", func(t *testing.T) {
		adapter, err := NewAdapter(nil, logger)

		require.Error(t, err)
		assert.Nil(t, adapter)
		assert.Equal(t, ErrNilConfig, err)
	})

	t.Run("returns error with nil logger", func(t *testing.T) {
		cfg := DefaultConfig()
		adapter, err := NewAdapter(cfg, nil)

		require.Error(t, err)
		assert.Nil(t, adapter)
		assert.Equal(t, ErrNilLogger, err)
	})

	t.Run("returns error with invalid config", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportUnix,
			// Missing required UnixSocket
		}
		adapter, err := NewAdapter(cfg, logger)

		require.Error(t, err)
		assert.Nil(t, adapter)
		assert.Equal(t, ErrMissingUnixSocket, err)
	})
}

func TestAdapter_StartStop_EmbeddedMode(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := DefaultConfig()

	adapter, err := NewAdapter(cfg, logger)
	require.NoError(t, err)

	t.Run("returns error when starting embedded without service", func(t *testing.T) {
		ctx := context.Background()
		err := adapter.Start(ctx, nil)

		require.Error(t, err)
		assert.Equal(t, ErrEmbeddedServiceRequired, err)
		assert.False(t, adapter.IsStarted())
	})

	t.Run("stop is idempotent when not started", func(t *testing.T) {
		ctx := context.Background()
		err := adapter.Stop(ctx)

		require.NoError(t, err)
	})
}

func TestAdapter_Client_NotStarted(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := DefaultConfig()

	adapter, err := NewAdapter(cfg, logger)
	require.NoError(t, err)

	t.Run("Client returns nil when not started", func(t *testing.T) {
		client := adapter.Client()
		assert.Nil(t, client)
	})

	t.Run("KMS returns nil when not started", func(t *testing.T) {
		kms := adapter.KMS()
		assert.Nil(t, kms)
	})

	t.Run("Crypto returns nil when not started", func(t *testing.T) {
		crypto := adapter.Crypto()
		assert.Nil(t, crypto)
	})

	t.Run("HealthClient returns nil when not started", func(t *testing.T) {
		health := adapter.HealthClient()
		assert.Nil(t, health)
	})
}

func TestAdapter_Operations_NotStarted(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := DefaultConfig()

	adapter, err := NewAdapter(cfg, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("Health returns error when not started", func(t *testing.T) {
		resp, err := adapter.Health(ctx)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("Ping returns error when not started", func(t *testing.T) {
		err := adapter.Ping(ctx)

		require.Error(t, err)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("GenerateKey returns error when not started", func(t *testing.T) {
		resp, err := adapter.GenerateKey(ctx, nil)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("GetKey returns error when not started", func(t *testing.T) {
		resp, err := adapter.GetKey(ctx, "test-key")

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("ListKeys returns error when not started", func(t *testing.T) {
		resp, err := adapter.ListKeys(ctx)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("RotateKey returns error when not started", func(t *testing.T) {
		resp, err := adapter.RotateKey(ctx, "test-key")

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("DeleteKey returns error when not started", func(t *testing.T) {
		err := adapter.DeleteKey(ctx, "test-key")

		require.Error(t, err)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("Sign returns error when not started", func(t *testing.T) {
		resp, err := adapter.Sign(ctx, nil)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("Verify returns error when not started", func(t *testing.T) {
		resp, err := adapter.Verify(ctx, nil)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("Encrypt returns error when not started", func(t *testing.T) {
		resp, err := adapter.Encrypt(ctx, nil)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})

	t.Run("Decrypt returns error when not started", func(t *testing.T) {
		resp, err := adapter.Decrypt(ctx, nil)

		require.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, ErrAdapterNotStarted, err)
	})
}

func TestAdapter_TransportType(t *testing.T) {
	t.Parallel()

	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("embedded transport", func(t *testing.T) {
		cfg := DefaultConfig()
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportEmbedded, adapter.Transport())
		assert.True(t, adapter.IsEmbedded())
		assert.False(t, adapter.IsRemote())
	})

	t.Run("unix transport", func(t *testing.T) {
		cfg := UnixConfig("/tmp/test.sock")
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportUnix, adapter.Transport())
		assert.False(t, adapter.IsEmbedded())
		assert.True(t, adapter.IsRemote())
	})

	t.Run("grpc transport", func(t *testing.T) {
		cfg := GRPCConfig("localhost:50051")
		cfg.TLS = &TLSConfig{CACert: testCACertPath}
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportGRPC, adapter.Transport())
		assert.False(t, adapter.IsEmbedded())
		assert.True(t, adapter.IsRemote())
	})

	t.Run("rest transport", func(t *testing.T) {
		cfg := RESTConfig("http://localhost:8080")
		cfg.TLS = &TLSConfig{CACert: testCACertPath}
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportREST, adapter.Transport())
		assert.False(t, adapter.IsEmbedded())
		assert.True(t, adapter.IsRemote())
	})

	t.Run("quic transport", func(t *testing.T) {
		cfg := QUICConfig("localhost:50051")
		cfg.TLS = &TLSConfig{CACert: testCACertPath}
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportQUIC, adapter.Transport())
		assert.False(t, adapter.IsEmbedded())
		assert.True(t, adapter.IsRemote())
	})

	t.Run("mcp transport", func(t *testing.T) {
		cfg := MCPConfig("localhost:9000")
		cfg.TLS = &TLSConfig{CACert: testCACertPath}
		adapter, err := NewAdapter(cfg, logger)

		require.NoError(t, err)
		assert.Equal(t, TransportMCP, adapter.Transport())
		assert.False(t, adapter.IsEmbedded())
		assert.True(t, adapter.IsRemote())
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("valid embedded config", func(t *testing.T) {
		cfg := DefaultConfig()
		err := cfg.Validate()

		require.NoError(t, err)
		assert.Equal(t, TransportEmbedded, cfg.Transport)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("valid unix config", func(t *testing.T) {
		cfg := UnixConfig("/tmp/test.sock")
		err := cfg.Validate()

		require.NoError(t, err)
		assert.Equal(t, TransportUnix, cfg.Transport)
		assert.Equal(t, "/tmp/test.sock", cfg.UnixSocket)
	})

	t.Run("unix config missing socket", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportUnix,
		}
		err := cfg.Validate()

		require.Error(t, err)
		assert.Equal(t, ErrMissingUnixSocket, err)
	})

	t.Run("valid grpc config", func(t *testing.T) {
		cfg := GRPCConfig("localhost:50051")
		cfg.TLS = &TLSConfig{CACert: testCACertPath}
		err := cfg.Validate()

		require.NoError(t, err)
		assert.Equal(t, TransportGRPC, cfg.Transport)
		assert.Equal(t, "localhost:50051", cfg.Address)
	})

	t.Run("grpc config missing address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
		}
		err := cfg.Validate()

		require.Error(t, err)
		assert.Equal(t, ErrMissingAddress, err)
	})

	t.Run("rest config missing address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
		}
		err := cfg.Validate()

		require.Error(t, err)
		assert.Equal(t, ErrMissingAddress, err)
	})

	t.Run("quic config missing address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
		}
		err := cfg.Validate()

		require.Error(t, err)
		assert.Equal(t, ErrMissingAddress, err)
	})

	t.Run("mcp config missing address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportMCP,
		}
		err := cfg.Validate()

		require.Error(t, err)
		assert.Equal(t, ErrMissingAddress, err)
	})

	t.Run("unsupported transport", func(t *testing.T) {
		cfg := &Config{
			Transport: Transport("invalid"),
		}
		err := cfg.Validate()

		require.Error(t, err)
		expectedErr := ErrUnsupportedTransport{Transport: Transport("invalid")}
		assert.Equal(t, expectedErr, err)
	})

	t.Run("infers grpc from backend", func(t *testing.T) {
		cfg := &Config{
			Backend: "remote-backend",
			Address: "localhost:50051",
			TLS: &TLSConfig{
				CACert: testCACertPath,
			},
		}
		err := cfg.Validate()

		require.NoError(t, err)
		assert.Equal(t, TransportGRPC, cfg.Transport)
	})

	t.Run("sets default timeout", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportEmbedded,
			RequestTimeout: 0,
		}
		err := cfg.Validate()

		require.NoError(t, err)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})
}

func TestConfig_IsEmbedded(t *testing.T) {
	t.Parallel()

	t.Run("embedded when no backend and embedded transport", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.True(t, cfg.IsEmbedded())
		assert.False(t, cfg.IsRemote())
	})

	t.Run("embedded when no backend and empty transport", func(t *testing.T) {
		cfg := &Config{}
		assert.True(t, cfg.IsEmbedded())
		assert.False(t, cfg.IsRemote())
	})

	t.Run("remote when backend specified", func(t *testing.T) {
		cfg := &Config{
			Backend: "remote",
			Address: "localhost:50051",
		}
		assert.False(t, cfg.IsEmbedded())
		assert.True(t, cfg.IsRemote())
	})

	t.Run("remote when using non-embedded transport", func(t *testing.T) {
		cfg := GRPCConfig("localhost:50051")
		assert.False(t, cfg.IsEmbedded())
		assert.True(t, cfg.IsRemote())
	})
}

func TestTransport_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		transport Transport
		expected  string
	}{
		{TransportEmbedded, "embedded"},
		{TransportUnix, "unix"},
		{TransportGRPC, "grpc"},
		{TransportREST, "rest"},
		{TransportQUIC, "quic"},
		{TransportMCP, "mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.transport.String())
		})
	}
}

func TestConfigConstructors(t *testing.T) {
	t.Parallel()

	t.Run("DefaultConfig", func(t *testing.T) {
		cfg := DefaultConfig()

		assert.Equal(t, TransportEmbedded, cfg.Transport)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
		assert.Empty(t, cfg.Address)
		assert.Empty(t, cfg.UnixSocket)
		assert.Empty(t, cfg.Backend)
	})

	t.Run("RemoteConfig", func(t *testing.T) {
		cfg := RemoteConfig("localhost:50051", TransportGRPC)

		assert.Equal(t, TransportGRPC, cfg.Transport)
		assert.Equal(t, "localhost:50051", cfg.Address)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("UnixConfig", func(t *testing.T) {
		cfg := UnixConfig("/var/run/quicbaas.sock")

		assert.Equal(t, TransportUnix, cfg.Transport)
		assert.Equal(t, "/var/run/quicbaas.sock", cfg.UnixSocket)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("GRPCConfig", func(t *testing.T) {
		cfg := GRPCConfig("localhost:10443")

		assert.Equal(t, TransportGRPC, cfg.Transport)
		assert.Equal(t, "localhost:10443", cfg.Address)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("RESTConfig", func(t *testing.T) {
		cfg := RESTConfig("https://localhost:8443")

		assert.Equal(t, TransportREST, cfg.Transport)
		assert.Equal(t, "https://localhost:8443", cfg.Address)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("QUICConfig", func(t *testing.T) {
		cfg := QUICConfig("localhost:9444")

		assert.Equal(t, TransportQUIC, cfg.Transport)
		assert.Equal(t, "localhost:9444", cfg.Address)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})

	t.Run("MCPConfig", func(t *testing.T) {
		cfg := MCPConfig("localhost:9445")

		assert.Equal(t, TransportMCP, cfg.Transport)
		assert.Equal(t, "localhost:9445", cfg.Address)
		assert.Equal(t, DefaultRequestTimeout, cfg.RequestTimeout)
	})
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()

	t.Run("config with TLS", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:50051",
			TLS: &TLSConfig{
				CACert:     "/path/to/ca.pem",
				ClientCert: "/path/to/client.pem",
				ClientKey:  "/path/to/client-key.pem",
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)

		assert.NotNil(t, cfg.TLS)
		assert.Equal(t, "/path/to/ca.pem", cfg.TLS.CACert)
		assert.Equal(t, "/path/to/client.pem", cfg.TLS.ClientCert)
		assert.Equal(t, "/path/to/client-key.pem", cfg.TLS.ClientKey)
	})

}

func TestPoolConfig(t *testing.T) {
	t.Parallel()

	t.Run("config with pool settings", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:50051",
			TLS: &TLSConfig{
				CACert: testCACertPath,
			},
			Pool: &PoolConfig{
				MinConnections: 5,
				MaxConnections: 50,
				MaxIdleTime:    time.Hour,
			},
		}

		err := cfg.Validate()
		require.NoError(t, err)

		assert.NotNil(t, cfg.Pool)
		assert.Equal(t, 5, cfg.Pool.MinConnections)
		assert.Equal(t, 50, cfg.Pool.MaxConnections)
		assert.Equal(t, time.Hour, cfg.Pool.MaxIdleTime)
	})
}
