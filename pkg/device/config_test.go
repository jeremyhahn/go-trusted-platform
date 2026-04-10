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

package device

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatastorePartition(t *testing.T) {
	assert.Equal(t, "devices", DatastorePartition)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig

	require.NotNil(t, config.QuicBaaS)
	assert.Equal(t, "pebble", config.QuicBaaS.StorageBackend)
	assert.Equal(t, "trusted-data/quicbaas", config.QuicBaaS.DataDir)
	assert.Equal(t, "trusted-data/quicbaas/wal", config.QuicBaaS.WALDir)
	assert.Equal(t, uint64(1), config.QuicBaaS.NodeID)
	assert.Equal(t, int64(64*1024*1024), config.QuicBaaS.CacheSize)
	assert.Equal(t, "warn", config.QuicBaaS.LogLevel)
	assert.Equal(t, quicbaas.ConsistencyLinearizable, config.QuicBaaS.ConsistencyLevel)

	// Verify new ShardID and Partition fields
	assert.Equal(t, uint64(0), config.ShardID)
	assert.Equal(t, "devices", config.Partition)
}

func TestConfig_QuicBaaS(t *testing.T) {
	config := &Config{
		QuicBaaS: &quicbaas.Config{
			StorageBackend:   "memory",
			DataDir:          "/custom/path",
			WALDir:           "/custom/path/wal",
			NodeID:           2,
			CacheSize:        128 * 1024 * 1024,
			LogLevel:         "debug",
			ConsistencyLevel: quicbaas.ConsistencyEventual,
		},
		ShardID:   1,
		Partition: "custom-partition",
	}

	require.NotNil(t, config.QuicBaaS)
	assert.Equal(t, "memory", config.QuicBaaS.StorageBackend)
	assert.Equal(t, "/custom/path", config.QuicBaaS.DataDir)
	assert.Equal(t, "/custom/path/wal", config.QuicBaaS.WALDir)
	assert.Equal(t, uint64(2), config.QuicBaaS.NodeID)
	assert.Equal(t, int64(128*1024*1024), config.QuicBaaS.CacheSize)
	assert.Equal(t, "debug", config.QuicBaaS.LogLevel)
	assert.Equal(t, quicbaas.ConsistencyEventual, config.QuicBaaS.ConsistencyLevel)
	assert.Equal(t, uint64(1), config.ShardID)
	assert.Equal(t, "custom-partition", config.Partition)
}

func TestConfig_EmptyQuicBaaS(t *testing.T) {
	config := &Config{
		QuicBaaS: nil,
	}

	assert.Nil(t, config.QuicBaaS)
}

func TestConfig_WithDefaultValues(t *testing.T) {
	config := &Config{
		QuicBaaS: &quicbaas.Config{},
	}

	require.NotNil(t, config.QuicBaaS)
	assert.Equal(t, "", config.QuicBaaS.StorageBackend)
	assert.Equal(t, "", config.QuicBaaS.DataDir)
	assert.Equal(t, "", config.QuicBaaS.WALDir)
	assert.Equal(t, uint64(0), config.QuicBaaS.NodeID)
	assert.Equal(t, int64(0), config.QuicBaaS.CacheSize)
	assert.Equal(t, "", config.QuicBaaS.LogLevel)
}

func TestConfiguration_GlobalVariable(t *testing.T) {
	// Test that the global Configuration variable can be set
	testConfig := &Config{
		QuicBaaS: &quicbaas.Config{
			StorageBackend:   "pebble",
			DataDir:          "test-dir",
			LogLevel:         "info",
			ConsistencyLevel: quicbaas.ConsistencyLinearizable,
		},
		ShardID:   3,
		Partition: "test-partition",
	}

	Configuration = testConfig
	assert.Equal(t, testConfig, Configuration)
	assert.Equal(t, "pebble", Configuration.QuicBaaS.StorageBackend)
	assert.Equal(t, uint64(3), Configuration.ShardID)
	assert.Equal(t, "test-partition", Configuration.Partition)

	// Reset to nil for other tests
	Configuration = nil
	assert.Nil(t, Configuration)
}

func TestConfig_StorageBackendVariations(t *testing.T) {
	tests := []struct {
		name    string
		backend string
	}{
		{
			name:    "pebble backend",
			backend: "pebble",
		},
		{
			name:    "memory backend",
			backend: "memory",
		},
		{
			name:    "file backend",
			backend: "file",
		},
		{
			name:    "raft backend",
			backend: "raft",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS: &quicbaas.Config{
					StorageBackend: tc.backend,
				},
			}

			assert.Equal(t, tc.backend, config.QuicBaaS.StorageBackend)
		})
	}
}

func TestConfig_ConsistencyLevelVariations(t *testing.T) {
	tests := []struct {
		name             string
		consistencyLevel quicbaas.ConsistencyLevel
	}{
		{
			name:             "linearizable consistency",
			consistencyLevel: quicbaas.ConsistencyLinearizable,
		},
		{
			name:             "strong consistency",
			consistencyLevel: quicbaas.ConsistencyStrong,
		},
		{
			name:             "eventual consistency",
			consistencyLevel: quicbaas.ConsistencyEventual,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS: &quicbaas.Config{
					ConsistencyLevel: tc.consistencyLevel,
				},
			}

			assert.Equal(t, tc.consistencyLevel, config.QuicBaaS.ConsistencyLevel)
		})
	}
}

func TestConfig_CacheSizeVariations(t *testing.T) {
	tests := []struct {
		name      string
		cacheSize int64
	}{
		{
			name:      "small cache",
			cacheSize: 16 * 1024 * 1024, // 16MB
		},
		{
			name:      "default cache",
			cacheSize: 64 * 1024 * 1024, // 64MB
		},
		{
			name:      "large cache",
			cacheSize: 512 * 1024 * 1024, // 512MB
		},
		{
			name:      "zero cache",
			cacheSize: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS: &quicbaas.Config{
					CacheSize: tc.cacheSize,
				},
			}

			assert.Equal(t, tc.cacheSize, config.QuicBaaS.CacheSize)
		})
	}
}

func TestConfig_DataDirVariations(t *testing.T) {
	tests := []struct {
		name    string
		dataDir string
	}{
		{
			name:    "relative path",
			dataDir: "trusted-data/quicbaas",
		},
		{
			name:    "absolute path",
			dataDir: "/var/lib/trusted-platform/quicbaas",
		},
		{
			name:    "empty path",
			dataDir: "",
		},
		{
			name:    "single directory",
			dataDir: "quicbaas",
		},
		{
			name:    "deep path",
			dataDir: "/opt/trusted/platform/data/store/devices",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS: &quicbaas.Config{
					DataDir: tc.dataDir,
				},
			}

			assert.Equal(t, tc.dataDir, config.QuicBaaS.DataDir)
		})
	}
}

func TestConfig_ShardIDVariations(t *testing.T) {
	tests := []struct {
		name    string
		shardID uint64
	}{
		{
			name:    "default shard",
			shardID: 0,
		},
		{
			name:    "shard 1",
			shardID: 1,
		},
		{
			name:    "high shard ID",
			shardID: 1000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS: &quicbaas.Config{},
				ShardID:  tc.shardID,
			}

			assert.Equal(t, tc.shardID, config.ShardID)
		})
	}
}

func TestConfig_PartitionVariations(t *testing.T) {
	tests := []struct {
		name      string
		partition string
	}{
		{
			name:      "devices partition",
			partition: "devices",
		},
		{
			name:      "profiles partition",
			partition: "device-profiles",
		},
		{
			name:      "custom partition",
			partition: "custom-data",
		},
		{
			name:      "empty partition",
			partition: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				QuicBaaS:  &quicbaas.Config{},
				Partition: tc.partition,
			}

			assert.Equal(t, tc.partition, config.Partition)
		})
	}
}

func TestConfig_CompleteConfiguration(t *testing.T) {
	config := &Config{
		QuicBaaS: &quicbaas.Config{
			StorageBackend:   "pebble",
			DataDir:          "/opt/trusted-platform/quicbaas",
			WALDir:           "/opt/trusted-platform/quicbaas/wal",
			RaftAddress:      "127.0.0.1:63000",
			NodeID:           1,
			CacheSize:        128 * 1024 * 1024,
			LogLevel:         "info",
			ConsistencyLevel: quicbaas.ConsistencyLinearizable,
		},
		ShardID:   2,
		Partition: "devices",
	}

	require.NotNil(t, config.QuicBaaS)
	assert.Equal(t, "pebble", config.QuicBaaS.StorageBackend)
	assert.Equal(t, "/opt/trusted-platform/quicbaas", config.QuicBaaS.DataDir)
	assert.Equal(t, "/opt/trusted-platform/quicbaas/wal", config.QuicBaaS.WALDir)
	assert.Equal(t, "127.0.0.1:63000", config.QuicBaaS.RaftAddress)
	assert.Equal(t, uint64(1), config.QuicBaaS.NodeID)
	assert.Equal(t, int64(128*1024*1024), config.QuicBaaS.CacheSize)
	assert.Equal(t, "info", config.QuicBaaS.LogLevel)
	assert.Equal(t, quicbaas.ConsistencyLinearizable, config.QuicBaaS.ConsistencyLevel)
	assert.Equal(t, uint64(2), config.ShardID)
	assert.Equal(t, "devices", config.Partition)
}
