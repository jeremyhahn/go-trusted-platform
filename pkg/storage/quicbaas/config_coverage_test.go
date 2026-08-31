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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateEmbeddedConfig_FileBackend_MissingDataDir tests file backend missing DataDir.
func TestValidateEmbeddedConfig_FileBackend_MissingDataDir(t *testing.T) {
	config := &Config{
		Transport:      TransportEmbedded,
		StorageBackend: quicbaas.StorageBackendFile,
		DataDir:        "",
		RequestTimeout: 5 * time.Second,
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DataDir")
}

// TestValidateEmbeddedConfig_PebbleBackend_MissingDataDir tests pebble backend missing DataDir.
func TestValidateEmbeddedConfig_PebbleBackend_MissingDataDir(t *testing.T) {
	config := &Config{
		StorageBackend: quicbaas.StorageBackendPebble,
		DataDir:        "",
		WALDir:         "/tmp/test-wal",
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DataDir")
}

// TestValidateEmbeddedConfig_PebbleBackend_MissingWALDir tests pebble backend missing WALDir.
func TestValidateEmbeddedConfig_PebbleBackend_MissingWALDir(t *testing.T) {
	config := &Config{
		StorageBackend: quicbaas.StorageBackendPebble,
		DataDir:        "/tmp/test-data",
		WALDir:         "",
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WALDir")
}

// TestValidateEmbeddedConfig_EmptyBackend_MissingDataDir tests empty backend string missing DataDir.
func TestValidateEmbeddedConfig_EmptyBackend_MissingDataDir(t *testing.T) {
	config := &Config{
		StorageBackend: "",
		DataDir:        "",
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DataDir")
}

// TestValidateEmbeddedConfig_EmptyBackend_MissingWALDir tests empty backend string missing WALDir.
func TestValidateEmbeddedConfig_EmptyBackend_MissingWALDir(t *testing.T) {
	config := &Config{
		StorageBackend: "",
		DataDir:        "/tmp/test-data",
		WALDir:         "",
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WALDir")
}

// TestValidateEmbeddedConfig_InvalidBackend tests invalid storage backend string.
func TestValidateEmbeddedConfig_InvalidBackend(t *testing.T) {
	config := &Config{
		StorageBackend: "invalid-backend",
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "StorageBackend")
}

// TestValidateEmbeddedConfig_NegativeCacheSize tests negative cache size.
func TestValidateEmbeddedConfig_NegativeCacheSize(t *testing.T) {
	config := &Config{
		StorageBackend: quicbaas.StorageBackendMemory,
		CacheSize:      -1,
	}
	err := config.validateEmbeddedConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CacheSize")
}

// TestValidateEmbeddedConfig_MemoryBackend_Success tests valid memory config.
func TestValidateEmbeddedConfig_MemoryBackend_Success(t *testing.T) {
	config := &Config{
		StorageBackend:    quicbaas.StorageBackendMemory,
		CacheSize:         0,
		SPIFFETrustDomain: "example.internal",
	}
	err := config.validateEmbeddedConfig()
	require.NoError(t, err)
}

// TestValidate_UnixTransport_MissingSocket tests unix transport missing socket.
func TestValidate_UnixTransport_MissingSocket(t *testing.T) {
	config := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "UnixSocket")
}

// TestValidate_GRPCTransport_MissingAddress tests gRPC transport missing address.
func TestValidate_GRPCTransport_MissingAddress(t *testing.T) {
	config := &Config{
		Transport:      TransportGRPC,
		Address:        "",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Address")
}

// TestValidate_QUICTransport_MissingAddress tests QUIC transport missing address.
func TestValidate_QUICTransport_MissingAddress(t *testing.T) {
	config := &Config{
		Transport:      TransportQUIC,
		Address:        "",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Address")
}

// TestValidate_RESTTransport_MissingAddress tests REST transport missing address.
func TestValidate_RESTTransport_MissingAddress(t *testing.T) {
	config := &Config{
		Transport:      TransportREST,
		Address:        "",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Address")
}

// TestValidate_UnsupportedTransport tests validation with unsupported transport.
func TestValidate_UnsupportedTransport(t *testing.T) {
	config := &Config{
		Transport:      Transport(99),
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

// TestValidate_GRPCTransport_Success tests valid gRPC config.
func TestValidate_GRPCTransport_Success(t *testing.T) {
	config := &Config{
		Transport:      TransportGRPC,
		Address:        "localhost:9000",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.NoError(t, err)
}

// TestValidate_RESTTransport_Success tests valid REST config.
func TestValidate_RESTTransport_Success(t *testing.T) {
	config := &Config{
		Transport:      TransportREST,
		Address:        "http://localhost:8080",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.NoError(t, err)
}

// TestValidate_UnixTransport_Success tests valid unix config.
func TestValidate_UnixTransport_Success(t *testing.T) {
	config := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "/tmp/test.sock",
		RequestTimeout: 5 * time.Second,
	}
	err := config.Validate()
	require.NoError(t, err)
}
