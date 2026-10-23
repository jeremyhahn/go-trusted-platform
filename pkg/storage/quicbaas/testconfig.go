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
	"net"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// This file holds the test-only configuration constructors. Production
// configuration comes from DefaultConfig and the file / env / flag layers;
// nothing here is reachable from a daemon.

// TestingT is a minimal interface for testing helpers.
// Satisfied by *testing.T and *testing.B.
type TestingT interface {
	TempDir() string
	Name() string
	Helper()
	Fatalf(format string, args ...any)
}

// TestConfig returns a configuration optimized for unit testing.
// Uses minimal resources and fast timeouts. Creates a temporary
// directory that will be cleaned up when the test completes.
// Uses PebbleDB backend for high-performance local storage without Raft.
// For faster unit tests that don't need persistence, use MemoryTestConfig instead.
func TestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // High-performance local storage, no Raft
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       FreeLoopbackAddress(t),
		NodeID:            1,
		CacheSize:         8 * 1024 * 1024, // 8MB
		LogLevel:          "error",         // Reduce log noise in tests
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "none",
		SyncWrites:        false,
		RequestTimeout:    30 * time.Second,
		// Serve every service the build carries: a WITH_VECTOR=1 build
		// (the integration build) runs the vector service.
		Vector: &VectorServiceConfig{Enabled: vectorCompiled},
	}
}

// MemoryTestConfig returns a configuration using in-memory storage.
// This is the fastest option for unit tests that don't need persistence.
// Data is lost when the server stops - ideal for isolated test cases.
func MemoryTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir() // Still needed for some internal operations
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendMemory,
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       "",              // Not needed for memory backend
		NodeID:            0,               // Not needed for memory backend
		CacheSize:         4 * 1024 * 1024, // 4MB - smaller for tests
		LogLevel:          "error",
		ConsistencyLevel:  ConsistencyEventual, // Memory is always consistent
		Compression:       "none",
		SyncWrites:        false,
		RequestTimeout:    10 * time.Second,
	}
}

// FileTestConfig returns a configuration using file-based storage.
// Each key-value pair is stored as a separate file, making it easy
// to inspect and debug data. Slower than Pebble but human-readable.
func FileTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendFile,
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       "",              // Not needed for file backend
		NodeID:            0,               // Not needed for file backend
		CacheSize:         4 * 1024 * 1024, // 4MB
		LogLevel:          "debug",         // Debug level for visibility
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "none", // No compression for readability
		SyncWrites:        true,   // Sync for debugging reliability
		RequestTimeout:    30 * time.Second,
	}
}

// RaftTestConfig returns a configuration suitable for Raft cluster testing.
// Uses PebbleDB storage with Raft-related settings configured.
// Note: Raft consensus is enabled via server mode, not storage backend.
// This config just ensures Raft address and NodeID are set for cluster tests.
func RaftTestConfig(t TestingT) *Config {
	t.Helper()
	dataDir := t.TempDir()
	return &Config{
		TransportStr:      "embedded",
		Transport:         TransportEmbedded,
		StorageBackend:    quicbaas.StorageBackendPebble, // Raft uses pebble for storage
		SPIFFETrustDomain: "example.internal",
		DataDir:           dataDir,
		WALDir:            dataDir + "/wal",
		RaftAddress:       FreeLoopbackAddress(t),
		NodeID:            1,
		CacheSize:         8 * 1024 * 1024, // 8MB
		LogLevel:          "error",
		ConsistencyLevel:  ConsistencyLinearizable,
		Compression:       "snappy",
		SyncWrites:        true,
		RequestTimeout:    30 * time.Second,
	}
}

// FreeLoopbackAddress returns a free "127.0.0.1:PORT" address for a test
// Raft transport, found by briefly binding port 0 on loopback. A host
// without loopback fails the test: there is no fallback port and no
// wildcard bind, so a test can never collide on a guessed port.
func FreeLoopbackAddress(t TestingT) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback Raft port: %v", err)
		return ""
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release the loopback Raft port %s: %v", addr, err)
		return ""
	}
	return addr
}
