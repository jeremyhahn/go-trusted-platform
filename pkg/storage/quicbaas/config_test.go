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
	"fmt"
	"net"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotEmpty(t, cfg.DataDir)
	assert.NotEmpty(t, cfg.WALDir)
	assert.Equal(t, uint64(1), cfg.NodeID)
	assert.Empty(t, cfg.RaftAddress, "no hard-coded Raft address (#93)")
	assert.Greater(t, cfg.CacheSize, int64(0))
	assert.Equal(t, ConsistencyLinearizable, cfg.ConsistencyLevel)
	assert.Greater(t, cfg.RequestTimeout, time.Duration(0))
}

func TestTestConfig(t *testing.T) {
	cfg := TestConfig(t)

	assert.Contains(t, cfg.DataDir, t.Name())
	assert.Contains(t, cfg.WALDir, t.Name())
	assert.Equal(t, uint64(1), cfg.NodeID)
	assert.Equal(t, "error", cfg.LogLevel)
	assert.Contains(t, cfg.RaftAddress, "127.0.0.1:")
}

func TestConfig_Validate_Success(t *testing.T) {
	cfg := TestConfig(t)
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestConfig_Validate_EmptyDataDir(t *testing.T) {
	cfg := TestConfig(t)
	cfg.DataDir = ""
	// Also clear WALDir since SetDefaults would derive it from DataDir
	cfg.WALDir = ""

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "DataDir", invalidCfgErr.Field)
}

func TestConfig_Validate_EmptyWALDir_AutoDefault(t *testing.T) {
	// Test that empty WALDir is automatically defaulted from DataDir
	cfg := TestConfig(t)
	cfg.WALDir = ""

	err := cfg.Validate()
	// Should NOT error - SetDefaults derives WALDir from DataDir
	require.NoError(t, err)
	// WALDir should now be set to DataDir/wal
	assert.Equal(t, cfg.DataDir+"/wal", cfg.WALDir)
}

func TestConfig_Validate_EmptyWALDir_NoDataDir(t *testing.T) {
	// Test that empty WALDir with empty DataDir fails for pebble backend
	cfg := TestConfig(t)
	cfg.DataDir = ""
	cfg.WALDir = ""

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	// DataDir validation should fail first
	assert.Equal(t, "DataDir", invalidCfgErr.Field)
}

// Note: NodeID and RaftAddress validation was removed - these are now
// controlled by QuicBaaS server mode, not storage backend. The Raft backend
// no longer exists; use pebble backend with cluster server mode for Raft.

func TestConfig_ToQuicBaaSConfig(t *testing.T) {
	cfg := TestConfig(t)
	dbCfg := cfg.ToQuicBaaSConfig()

	assert.NotNil(t, dbCfg)
	assert.Equal(t, cfg.DataDir, dbCfg.Storage.DataDir)
	assert.Equal(t, cfg.WALDir, dbCfg.Storage.WALDir)
	assert.Equal(t, cfg.NodeID, dbCfg.Raft.NodeID)
	assert.Equal(t, cfg.RaftAddress, dbCfg.Raft.RaftAddress)
	assert.Equal(t, cfg.CacheSize, dbCfg.Storage.CacheSize)
	assert.Equal(t, cfg.SyncWrites, dbCfg.Storage.SyncWrites)
	assert.Equal(t, cfg.Compression, dbCfg.Storage.CompressionType)
	assert.Equal(t, cfg.LogLevel, dbCfg.Logging.Level)
}

func TestConsistencyLevel_String(t *testing.T) {
	tests := []struct {
		level    ConsistencyLevel
		expected string
	}{
		{ConsistencyLinearizable, "linearizable"},
		{ConsistencyStrong, "strong"},
		{ConsistencyEventual, "eventual"},
		{ConsistencyLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.level.String())
		})
	}
}

func TestParseConsistencyLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected ConsistencyLevel
	}{
		{"strong", ConsistencyStrong},
		{"STRONG", ConsistencyStrong},
		{"Strong", ConsistencyStrong},
		{"eventual", ConsistencyEventual},
		{"EVENTUAL", ConsistencyEventual},
		{"linearizable", ConsistencyLinearizable},
		{"LINEARIZABLE", ConsistencyLinearizable},
		{"invalid", ConsistencyLinearizable},
		{"", ConsistencyLinearizable},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseConsistencyLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConsistencyLevel_UnmarshalText(t *testing.T) {
	tests := []struct {
		input    string
		expected ConsistencyLevel
	}{
		{"linearizable", ConsistencyLinearizable},
		{"strong", ConsistencyStrong},
		{"eventual", ConsistencyEventual},
		{"LINEARIZABLE", ConsistencyLinearizable},
		{"STRONG", ConsistencyStrong},
		{"EVENTUAL", ConsistencyEventual},
		{"invalid", ConsistencyLinearizable}, // defaults to linearizable
		{"", ConsistencyLinearizable},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var cl ConsistencyLevel
			err := cl.UnmarshalText([]byte(tt.input))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cl)
		})
	}
}

func TestConsistencyLevel_MarshalText(t *testing.T) {
	tests := []struct {
		level    ConsistencyLevel
		expected string
	}{
		{ConsistencyLinearizable, "linearizable"},
		{ConsistencyStrong, "strong"},
		{ConsistencyEventual, "eventual"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			data, err := tt.level.MarshalText()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestFreeLoopbackAddress(t *testing.T) {
	addr := FreeLoopbackAddress(t)

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", host)
	assert.NotEqual(t, "0", port)

	// The port was released: a Raft transport can bind it.
	listener, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, listener.Close())
}

// fatalT records Fatalf instead of stopping, so a test can observe a helper
// failing the test it was handed.
type fatalT struct {
	*testing.T
	fatal string
}

func (f *fatalT) Fatalf(format string, args ...any) {
	f.fatal = fmt.Sprintf(format, args...)
}

func TestFreeLoopbackAddress_DistinctWhileHeld(t *testing.T) {
	// Two probes never hand out the same live port, and neither fails the
	// test: the probe binds port 0, it never guesses a fallback port.
	ft := &fatalT{T: t}
	first := FreeLoopbackAddress(ft)
	held, err := net.Listen("tcp", first)
	require.NoError(t, err)
	defer func() { require.NoError(t, held.Close()) }()

	second := FreeLoopbackAddress(ft)
	assert.Empty(t, ft.fatal)
	assert.NotEqual(t, first, second)
}

func TestEffectiveRaftListenAddress(t *testing.T) {
	cfg := &Config{RaftAddress: "10.0.0.5:63000"}
	assert.Equal(t, "10.0.0.5:63000", cfg.EffectiveRaftListenAddress(), "empty listen address binds the advertised one")

	cfg.RaftListenAddress = "0.0.0.0:63000"
	assert.Equal(t, "0.0.0.0:63000", cfg.EffectiveRaftListenAddress())
}

func TestEffectiveRaftListenAddress_BothEmpty(t *testing.T) {
	cfg := &Config{}
	assert.Empty(t, cfg.EffectiveRaftListenAddress())
}

func TestIsRoutableRaftAddress(t *testing.T) {
	for _, addr := range []string{"10.0.0.5:63000", "[2001:db8::5]:63000", "node-1.cluster.internal:63000", "10.0.0.5"} {
		assert.True(t, IsRoutableRaftAddress(addr), addr)
	}
}

func TestIsRoutableRaftAddress_NotRoutable(t *testing.T) {
	for _, addr := range []string{"", "  ", "127.0.0.1:63000", "[::1]:63000", "0.0.0.0:63000", "[::]:63000", "localhost:63000", "LOCALHOST", ":63000"} {
		assert.False(t, IsRoutableRaftAddress(addr), addr)
	}
}

func TestConfig_Validate_JoinRequiresRoutableAdvertise(t *testing.T) {
	cfg := clusterMemberConfig(t, 1)
	assert.NoError(t, cfg.Validate())
}

func TestConfig_Validate_JoinWithLoopbackAdvertise(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1:63000", "0.0.0.0:63000"} {
		cfg := clusterMemberConfig(t, 1)
		cfg.RaftAddress = addr

		err := cfg.Validate()
		var advErr ErrRaftAdvertiseAddress
		require.ErrorAs(t, err, &advErr, addr)
		assert.Equal(t, addr, advErr.Address)
		assert.Contains(t, err.Error(), "quicbaas.raft-address")
		assert.Contains(t, err.Error(), "PLATFORMD_QUICBAAS_RAFT_ADDRESS")
		assert.Contains(t, err.Error(), "--raft-address")
	}
}

func TestConfig_ToQuicBaaSConfig_RaftListenAddress(t *testing.T) {
	cfg := TestConfig(t)
	cfg.RaftAddress = "10.0.0.5:63000"
	cfg.RaftListenAddress = "10.0.0.5:63001"

	qcfg := cfg.ToQuicBaaSConfig()
	assert.Equal(t, "10.0.0.5:63000", qcfg.Raft.RaftAddress)
	assert.Equal(t, "10.0.0.5:63001", qcfg.Raft.ListenAddress)
}

func TestConfig_ToQuicBaaSConfig_RaftListenDefaultsToAdvertise(t *testing.T) {
	cfg := TestConfig(t)
	cfg.RaftListenAddress = ""

	qcfg := cfg.ToQuicBaaSConfig()
	assert.Equal(t, cfg.RaftAddress, qcfg.Raft.ListenAddress)
}

func TestConfig_Validate_NegativeCacheSize_AutoDefault(t *testing.T) {
	// Test that negative CacheSize is automatically defaulted to 128MB
	cfg := TestConfig(t)
	cfg.CacheSize = -1

	err := cfg.Validate()
	// Should NOT error - SetDefaults fixes negative cache size
	require.NoError(t, err)
	// CacheSize should now be set to default (128MB)
	assert.Equal(t, int64(128*1024*1024), cfg.CacheSize)
}

func TestConfig_Validate_ZeroRequestTimeout_AutoDefault(t *testing.T) {
	// Test that zero RequestTimeout is automatically defaulted to 30s
	cfg := TestConfig(t)
	cfg.RequestTimeout = 0

	err := cfg.Validate()
	// Should NOT error - SetDefaults fixes zero timeout
	require.NoError(t, err)
	// RequestTimeout should now be set to default (30s)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
}

func TestConfig_ToQuicBaaSConfig_EmptyWALDir(t *testing.T) {
	cfg := TestConfig(t)
	cfg.WALDir = ""

	dbCfg := cfg.ToQuicBaaSConfig()

	// Should derive WALDir from DataDir
	assert.Equal(t, cfg.DataDir+"/wal", dbCfg.Storage.WALDir)
}

func TestMemoryTestConfig(t *testing.T) {
	cfg := MemoryTestConfig(t)

	assert.Equal(t, quicbaassdk.StorageBackendMemory, cfg.StorageBackend)
	assert.NotEmpty(t, cfg.DataDir) // Still set for internal ops
	assert.Empty(t, cfg.RaftAddress)
	assert.Equal(t, uint64(0), cfg.NodeID)
	assert.Equal(t, "error", cfg.LogLevel)
	assert.Greater(t, cfg.RequestTimeout, time.Duration(0))
}

func TestMemoryTestConfig_Validate(t *testing.T) {
	cfg := MemoryTestConfig(t)
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestMemoryTestConfig_ToQuicBaaSConfig(t *testing.T) {
	cfg := MemoryTestConfig(t)
	dbCfg := cfg.ToQuicBaaSConfig()

	assert.NotNil(t, dbCfg)
	assert.Equal(t, quicbaassdk.StorageBackendMemory, dbCfg.Storage.Backend)
}

func TestFileTestConfig(t *testing.T) {
	cfg := FileTestConfig(t)

	assert.Equal(t, quicbaassdk.StorageBackendFile, cfg.StorageBackend)
	assert.Contains(t, cfg.DataDir, t.Name())
	assert.Empty(t, cfg.RaftAddress)
	assert.Equal(t, uint64(0), cfg.NodeID)
	assert.Equal(t, "debug", cfg.LogLevel) // Debug for visibility
	assert.True(t, cfg.SyncWrites)         // Sync for reliability
}

func TestFileTestConfig_Validate(t *testing.T) {
	cfg := FileTestConfig(t)
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestFileTestConfig_ToQuicBaaSConfig(t *testing.T) {
	cfg := FileTestConfig(t)
	dbCfg := cfg.ToQuicBaaSConfig()

	assert.NotNil(t, dbCfg)
	assert.Equal(t, quicbaassdk.StorageBackendFile, dbCfg.Storage.Backend)
}

func TestRaftTestConfig(t *testing.T) {
	cfg := RaftTestConfig(t)

	// Note: RaftTestConfig now uses pebble backend - Raft is controlled via server mode
	assert.Equal(t, quicbaassdk.StorageBackendPebble, cfg.StorageBackend)
	assert.Contains(t, cfg.DataDir, t.Name())
	assert.Contains(t, cfg.RaftAddress, "127.0.0.1:")
	assert.Equal(t, uint64(1), cfg.NodeID)
	assert.True(t, cfg.SyncWrites)
}

func TestRaftTestConfig_Validate(t *testing.T) {
	cfg := RaftTestConfig(t)
	err := cfg.Validate()
	require.NoError(t, err)
}

func TestRaftTestConfig_ToQuicBaaSConfig(t *testing.T) {
	cfg := RaftTestConfig(t)
	dbCfg := cfg.ToQuicBaaSConfig()

	assert.NotNil(t, dbCfg)
	// Note: RaftTestConfig now uses pebble backend - Raft is controlled via server mode
	assert.Equal(t, quicbaassdk.StorageBackendPebble, dbCfg.Storage.Backend)
	assert.Equal(t, cfg.NodeID, dbCfg.Raft.NodeID)
	assert.Equal(t, cfg.RaftAddress, dbCfg.Raft.RaftAddress)
}

func TestConfig_Validate_InvalidStorageBackend(t *testing.T) {
	cfg := TestConfig(t)
	cfg.StorageBackend = "invalid"

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "StorageBackend", invalidCfgErr.Field)
}

func TestConfig_Validate_FileBackend_EmptyDataDir(t *testing.T) {
	cfg := FileTestConfig(t)
	cfg.DataDir = ""

	err := cfg.Validate()
	require.Error(t, err)

	var invalidCfgErr ErrInvalidConfig
	assert.ErrorAs(t, err, &invalidCfgErr)
	assert.Equal(t, "DataDir", invalidCfgErr.Field)
}

func TestConfig_Validate_PebbleBackend_AllRequirements(t *testing.T) {
	// Note: RaftAddress and NodeID validation was removed - these are now
	// controlled by QuicBaaS server mode, not storage backend
	// Note: Empty WALDir is auto-defaulted from DataDir, so we only test DataDir validation
	tests := []struct {
		name      string
		modify    func(*Config)
		wantField string
	}{
		{
			name: "empty_data_dir",
			modify: func(c *Config) {
				c.DataDir = ""
				c.WALDir = "" // Must also clear WALDir since it can't be derived
			},
			wantField: "DataDir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := RaftTestConfig(t) // Uses pebble backend
			tt.modify(cfg)

			err := cfg.Validate()
			require.Error(t, err)

			var invalidCfgErr ErrInvalidConfig
			assert.ErrorAs(t, err, &invalidCfgErr)
			assert.Equal(t, tt.wantField, invalidCfgErr.Field)
		})
	}
}

func TestConfig_SetDefaults(t *testing.T) {
	// Test that SetDefaults properly sets all default values
	t.Run("zero_values", func(t *testing.T) {
		cfg := &Config{
			StorageBackend: quicbaassdk.StorageBackendPebble,
			DataDir:        "/tmp/test",
		}
		cfg.SetDefaults()

		assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
		assert.Equal(t, int64(128*1024*1024), cfg.CacheSize)
		assert.Equal(t, "/tmp/test/wal", cfg.WALDir)
	})

	t.Run("negative_values", func(t *testing.T) {
		cfg := &Config{
			StorageBackend: quicbaassdk.StorageBackendPebble,
			DataDir:        "/tmp/test",
			RequestTimeout: -1,
			CacheSize:      -100,
		}
		cfg.SetDefaults()

		assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
		assert.Equal(t, int64(128*1024*1024), cfg.CacheSize)
	})

	t.Run("preserves_explicit_values", func(t *testing.T) {
		cfg := &Config{
			StorageBackend: quicbaassdk.StorageBackendPebble,
			DataDir:        "/tmp/test",
			WALDir:         "/tmp/custom-wal",
			RequestTimeout: 60 * time.Second,
			CacheSize:      256 * 1024 * 1024,
		}
		cfg.SetDefaults()

		// Explicit values should be preserved
		assert.Equal(t, 60*time.Second, cfg.RequestTimeout)
		assert.Equal(t, int64(256*1024*1024), cfg.CacheSize)
		assert.Equal(t, "/tmp/custom-wal", cfg.WALDir)
	})
}

func TestSelfServiceRegistrationConfig_Active(t *testing.T) {
	var nilCfg *SelfServiceRegistrationConfig
	assert.False(t, nilCfg.Active(), "absent section is the invite-only default")
	assert.False(t, (&SelfServiceRegistrationConfig{}).Active())
	assert.True(t, (&SelfServiceRegistrationConfig{Enabled: true}).Active())
}
