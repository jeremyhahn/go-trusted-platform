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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSDKClient_EmbeddedWithoutService(t *testing.T) {
	cfg := TestConfig(t)

	// Embedded mode without service should fail
	_, err := NewSDKClient(cfg, nil)
	require.Error(t, err)

	var embeddedErr ErrEmbeddedServiceRequired
	assert.ErrorAs(t, err, &embeddedErr)
}

func TestNewSDKClient_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "", // Invalid - missing address
		RequestTimeout: 30 * time.Second,
	}

	_, err := NewSDKClient(cfg, nil)
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
}

func TestNewSDKClient_UnsupportedTransport(t *testing.T) {
	cfg := &Config{
		Transport:      Transport(99), // Invalid transport
		Address:        "localhost:10443",
		RequestTimeout: 30 * time.Second,
	}

	_, err := NewSDKClient(cfg, nil)
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
}

func TestSDKClient_Config(t *testing.T) {
	cfg := UnixSocketConfig("/var/run/test.sock")

	// We can't actually create the client without a real server,
	// but we can test the config getter if we had a mock
	assert.Equal(t, TransportUnix, cfg.Transport)
	assert.Equal(t, "/var/run/test.sock", cfg.UnixSocket)
}

func TestSDKClient_Transport(t *testing.T) {
	tests := []struct {
		transport Transport
		address   string
		socket    string
	}{
		{TransportGRPC, "localhost:10443", ""},
		{TransportREST, "http://localhost:8443", ""},
		{TransportQUIC, "localhost:9444", ""},
		{TransportUnix, "", "/var/run/quicbaas.sock"},
	}

	for _, tt := range tests {
		t.Run(tt.transport.String(), func(t *testing.T) {
			var cfg *Config
			if tt.transport == TransportUnix {
				cfg = UnixSocketConfig(tt.socket)
			} else {
				cfg = RemoteConfig(tt.transport, tt.address)
			}

			assert.Equal(t, tt.transport, cfg.Transport)
		})
	}
}

func TestSDKClient_IsEmbedded(t *testing.T) {
	tests := []struct {
		transport Transport
		expected  bool
	}{
		{TransportEmbedded, true},
		{TransportUnix, false},
		{TransportGRPC, false},
		{TransportREST, false},
		{TransportQUIC, false},
	}

	for _, tt := range tests {
		t.Run(tt.transport.String(), func(t *testing.T) {
			cfg := &Config{
				Transport:      tt.transport,
				RequestTimeout: 30 * time.Second,
			}
			assert.Equal(t, tt.expected, cfg.IsEmbedded())
		})
	}
}

// TestSDKClient_ServiceAccessors tests that service accessor methods
// handle nil client gracefully
func TestSDKClient_ServiceAccessorsReturnNilWhenClosed(t *testing.T) {
	// Create a minimal SDKClient with closed state
	sdkClient := &SDKClient{
		client: nil,
		config: &Config{Transport: TransportEmbedded},
		closed: true,
	}

	// All service accessors should return nil when closed
	assert.Nil(t, sdkClient.Client())
	assert.Nil(t, sdkClient.KV())
	assert.Nil(t, sdkClient.Batch())
	assert.Nil(t, sdkClient.Transaction())
	assert.Nil(t, sdkClient.Query())
	assert.Nil(t, sdkClient.Cluster())
	assert.Nil(t, sdkClient.Health())
	assert.Nil(t, sdkClient.Auth())
	assert.Nil(t, sdkClient.Seal())
	assert.Nil(t, sdkClient.KMS())
	assert.Nil(t, sdkClient.Secrets())
	assert.Nil(t, sdkClient.Crypto())
	assert.Nil(t, sdkClient.Vector())
	assert.Nil(t, sdkClient.TimeSeries())
	assert.Nil(t, sdkClient.Backup())
	assert.Nil(t, sdkClient.IAM())
	assert.Nil(t, sdkClient.Cache())
	assert.Nil(t, sdkClient.Operations())
	assert.Nil(t, sdkClient.RBAC())
	assert.Nil(t, sdkClient.DynamicSecrets())
	assert.Nil(t, sdkClient.Certificate())
	assert.Nil(t, sdkClient.DEK())
	assert.Nil(t, sdkClient.ObjectStorage())
	assert.Nil(t, sdkClient.ObjectStorageAdmin())
	assert.Nil(t, sdkClient.ObjectTransfer())
	assert.Nil(t, sdkClient.ParameterStore())
	assert.Nil(t, sdkClient.Scheduler())
	assert.Nil(t, sdkClient.Embedding())
	assert.Nil(t, sdkClient.Ollama())
}

func TestSDKClient_IsClosed(t *testing.T) {
	sdkClient := &SDKClient{
		client: nil,
		config: &Config{Transport: TransportEmbedded},
		closed: false,
	}

	assert.False(t, sdkClient.IsClosed())

	sdkClient.closed = true
	assert.True(t, sdkClient.IsClosed())
}

func TestSDKClient_Close_Idempotent(t *testing.T) {
	sdkClient := &SDKClient{
		client: nil,
		config: &Config{Transport: TransportEmbedded},
		closed: false,
	}

	// First close should succeed
	err := sdkClient.Close()
	require.NoError(t, err)
	assert.True(t, sdkClient.IsClosed())

	// Second close should also succeed (idempotent)
	err = sdkClient.Close()
	require.NoError(t, err)
}

func TestErrInvalidTransport_Error(t *testing.T) {
	err := ErrInvalidTransport{Value: "invalid"}
	expected := `invalid transport: "invalid" (valid values: embedded, unix, grpc, rest, quic)`
	assert.Equal(t, expected, err.Error())
}

func TestErrSDKClientClosed_Error(t *testing.T) {
	err := ErrSDKClientClosed{}
	assert.Equal(t, "quicbaas SDK client is closed", err.Error())
}

func TestErrSDKClientNotInitialized_Error(t *testing.T) {
	err := ErrSDKClientNotInitialized{}
	assert.Equal(t, "quicbaas SDK client is not initialized", err.Error())
}

func TestErrUnsupportedTransport_Error(t *testing.T) {
	err := ErrUnsupportedTransport{Transport: TransportGRPC}
	assert.Equal(t, "unsupported transport: grpc", err.Error())
}

func TestErrEmbeddedServiceRequired_Error(t *testing.T) {
	err := ErrEmbeddedServiceRequired{}
	assert.Equal(t, "embedded transport requires a QuicBaaS service instance", err.Error())
}
