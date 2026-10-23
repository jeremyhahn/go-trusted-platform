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

package cluster

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsistencyLevel_String(t *testing.T) {
	tests := []struct {
		name     string
		level    ConsistencyLevel
		expected string
	}{
		{
			name:     "linearizable",
			level:    ConsistencyLinearizable,
			expected: "linearizable",
		},
		{
			name:     "strong",
			level:    ConsistencyStrong,
			expected: "strong",
		},
		{
			name:     "eventual",
			level:    ConsistencyEventual,
			expected: "eventual",
		},
		{
			name:     "unknown",
			level:    ConsistencyLevel(99),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.level.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConflictResolutionStrategy_String(t *testing.T) {
	tests := []struct {
		name     string
		strategy ConflictResolutionStrategy
		expected string
	}{
		{
			name:     "last write wins",
			strategy: ConflictResolutionLastWriteWins,
			expected: "last-write-wins",
		},
		{
			name:     "highest version",
			strategy: ConflictResolutionHighestVersion,
			expected: "highest-version",
		},
		{
			name:     "lowest node id",
			strategy: ConflictResolutionLowestNodeID,
			expected: "lowest-node-id",
		},
		{
			name:     "manual",
			strategy: ConflictResolutionManual,
			expected: "manual",
		},
		{
			name:     "unknown",
			strategy: ConflictResolutionStrategy(99),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.strategy.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, uint64(1), cfg.NodeID)
	assert.Equal(t, "./data/sdn/quicbaas", cfg.QuicBaaSDataDir)
	assert.Equal(t, "./data/sdn/quicbaas/wal", cfg.QuicBaaSWALDir)
	assert.Equal(t, "127.0.0.1:63100", cfg.RaftAddress)
	assert.Empty(t, cfg.ClusterPeers)
	assert.Equal(t, ConsistencyLinearizable, cfg.ConsistencyLevel)
	assert.Equal(t, 30*time.Second, cfg.SyncInterval)
	assert.Equal(t, 10*time.Second, cfg.ReplicationTimeout)
	assert.Equal(t, 10*time.Second, cfg.LeaderElectionTimeout)
	assert.Equal(t, 1*time.Second, cfg.HeartbeatInterval)
	assert.True(t, cfg.EnableAutoSync)
	assert.True(t, cfg.EnableConflictResolution)
	assert.Equal(t, ConflictResolutionLastWriteWins, cfg.ConflictResolutionStrategy)
	assert.Equal(t, int64(128*1024*1024), cfg.CacheSize)
	assert.Equal(t, "snappy", cfg.Compression)
	assert.True(t, cfg.SyncWrites)
	assert.Equal(t, "info", cfg.LogLevel)
}

func TestTestConfig(t *testing.T) {
	cfg := TestConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, uint64(1), cfg.NodeID)
	assert.Equal(t, "/tmp/sdn-test", cfg.QuicBaaSDataDir)
	assert.Equal(t, "/tmp/sdn-test/wal", cfg.QuicBaaSWALDir)
	assert.Equal(t, "127.0.0.1:0", cfg.RaftAddress)
	assert.Empty(t, cfg.ClusterPeers)
	assert.Equal(t, ConsistencyLinearizable, cfg.ConsistencyLevel)
	assert.Equal(t, 5*time.Second, cfg.SyncInterval)
	assert.Equal(t, 5*time.Second, cfg.ReplicationTimeout)
	assert.Equal(t, 5*time.Second, cfg.LeaderElectionTimeout)
	assert.Equal(t, 1*time.Second, cfg.HeartbeatInterval)
	assert.False(t, cfg.EnableAutoSync)
	assert.True(t, cfg.EnableConflictResolution)
	assert.Equal(t, int64(8*1024*1024), cfg.CacheSize)
	assert.Equal(t, "none", cfg.Compression)
	assert.False(t, cfg.SyncWrites)
	assert.Equal(t, "error", cfg.LogLevel)
}

func TestConfig_Validate_Success(t *testing.T) {
	cfg := DefaultConfig()

	err := cfg.Validate()

	assert.NoError(t, err)
}

func TestConfig_Validate_InvalidNodeID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NodeID = 0

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "NodeID", invalidConfig.Field)
}

func TestConfig_Validate_EmptyDataDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QuicBaaSDataDir = ""

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "QuicBaaSDataDir", invalidConfig.Field)
}

func TestConfig_Validate_EmptyWALDir(t *testing.T) {
	cfg := DefaultConfig()
	cfg.QuicBaaSWALDir = ""

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "QuicBaaSWALDir", invalidConfig.Field)
}

func TestConfig_Validate_EmptyRaftAddress(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RaftAddress = ""

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "RaftAddress", invalidConfig.Field)
}

func TestConfig_Validate_ZeroSyncInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SyncInterval = 0

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "SyncInterval", invalidConfig.Field)
}

func TestConfig_Validate_NegativeSyncInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SyncInterval = -1 * time.Second

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "SyncInterval", invalidConfig.Field)
}

func TestConfig_Validate_ZeroReplicationTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReplicationTimeout = 0

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "ReplicationTimeout", invalidConfig.Field)
}

func TestConfig_Validate_ZeroLeaderElectionTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LeaderElectionTimeout = 0

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "LeaderElectionTimeout", invalidConfig.Field)
}

func TestConfig_Validate_ZeroHeartbeatInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HeartbeatInterval = 0

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "HeartbeatInterval", invalidConfig.Field)
}

func TestConfig_Validate_NegativeCacheSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CacheSize = -1

	err := cfg.Validate()

	require.Error(t, err)
	var invalidConfig ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidConfig)
	assert.Equal(t, "CacheSize", invalidConfig.Field)
}

func TestConfig_Validate_ZeroCacheSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CacheSize = 0

	err := cfg.Validate()

	// Zero cache size should be valid (means no caching)
	assert.NoError(t, err)
}
