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
	"time"
)

// Config holds the configuration for cluster-aware SDN operations.
type Config struct {
	// NodeID is the unique identifier for this cluster node
	NodeID uint64

	// QuicBaaSDataDir is the directory where QuicBaaS stores its data
	QuicBaaSDataDir string

	// QuicBaaSWALDir is the directory for write-ahead log files
	QuicBaaSWALDir string

	// RaftAddress is the address for Raft consensus communication
	// Format: "host:port"
	RaftAddress string

	// ClusterPeers contains the addresses of other cluster nodes
	// Format: ["node1:port", "node2:port", ...]
	ClusterPeers []string

	// ConsistencyLevel sets the default consistency for read operations
	ConsistencyLevel ConsistencyLevel

	// SyncInterval is the interval for synchronizing state with OVS
	SyncInterval time.Duration

	// ReplicationTimeout is the timeout for replication operations
	ReplicationTimeout time.Duration

	// LeaderElectionTimeout is the timeout for leader election
	LeaderElectionTimeout time.Duration

	// HeartbeatInterval is the interval for sending heartbeats
	HeartbeatInterval time.Duration

	// EnableAutoSync enables automatic synchronization with OVS
	EnableAutoSync bool

	// EnableConflictResolution enables automatic conflict resolution
	EnableConflictResolution bool

	// ConflictResolutionStrategy specifies the strategy for resolving conflicts
	ConflictResolutionStrategy ConflictResolutionStrategy

	// CacheSize is the size of the in-memory cache in bytes
	CacheSize int64

	// Compression enables data compression
	Compression string

	// SyncWrites enables synchronous writes to disk
	SyncWrites bool

	// LogLevel controls the verbosity of logging
	LogLevel string
}

// ConsistencyLevel defines read consistency guarantees for cluster operations.
type ConsistencyLevel int

const (
	// ConsistencyLinearizable provides linearizable reads (recommended default).
	// Uses Raft ReadIndex optimization for low latency (1-5ms).
	ConsistencyLinearizable ConsistencyLevel = iota

	// ConsistencyStrong requires full Raft consensus on every read.
	// Strongest guarantee but highest latency (10-50ms).
	ConsistencyStrong

	// ConsistencyEventual allows reading from local node without coordination.
	// Fastest (<1ms) but may return stale data.
	ConsistencyEventual
)

// String returns the string representation of the consistency level.
func (c ConsistencyLevel) String() string {
	switch c {
	case ConsistencyLinearizable:
		return "linearizable"
	case ConsistencyStrong:
		return "strong"
	case ConsistencyEventual:
		return "eventual"
	default:
		return "unknown"
	}
}

// ConflictResolutionStrategy defines how to resolve state conflicts.
type ConflictResolutionStrategy int

const (
	// ConflictResolutionLastWriteWins uses timestamp to determine winner
	ConflictResolutionLastWriteWins ConflictResolutionStrategy = iota

	// ConflictResolutionHighestVersion uses version number to determine winner
	ConflictResolutionHighestVersion

	// ConflictResolutionLowestNodeID uses node ID to determine winner (deterministic)
	ConflictResolutionLowestNodeID

	// ConflictResolutionManual requires manual intervention
	ConflictResolutionManual
)

// String returns the string representation of the conflict resolution strategy.
func (s ConflictResolutionStrategy) String() string {
	switch s {
	case ConflictResolutionLastWriteWins:
		return "last-write-wins"
	case ConflictResolutionHighestVersion:
		return "highest-version"
	case ConflictResolutionLowestNodeID:
		return "lowest-node-id"
	case ConflictResolutionManual:
		return "manual"
	default:
		return "unknown"
	}
}

// DefaultConfig returns a configuration with sensible defaults for production use.
func DefaultConfig() *Config {
	return &Config{
		NodeID:                     1,
		QuicBaaSDataDir:            "./data/sdn/quicbaas",
		QuicBaaSWALDir:             "./data/sdn/quicbaas/wal",
		RaftAddress:                "127.0.0.1:63100",
		ClusterPeers:               []string{},
		ConsistencyLevel:           ConsistencyLinearizable,
		SyncInterval:               30 * time.Second,
		ReplicationTimeout:         10 * time.Second,
		LeaderElectionTimeout:      10 * time.Second,
		HeartbeatInterval:          1 * time.Second,
		EnableAutoSync:             true,
		EnableConflictResolution:   true,
		ConflictResolutionStrategy: ConflictResolutionLastWriteWins,
		CacheSize:                  128 * 1024 * 1024, // 128MB
		Compression:                "snappy",
		SyncWrites:                 true,
		LogLevel:                   "info",
	}
}

// TestConfig returns a configuration optimized for unit testing.
func TestConfig() *Config {
	return &Config{
		NodeID:                     1,
		QuicBaaSDataDir:            "/tmp/sdn-test",
		QuicBaaSWALDir:             "/tmp/sdn-test/wal",
		RaftAddress:                "127.0.0.1:0", // Auto-assign port
		ClusterPeers:               []string{},
		ConsistencyLevel:           ConsistencyLinearizable,
		SyncInterval:               5 * time.Second,
		ReplicationTimeout:         5 * time.Second,
		LeaderElectionTimeout:      5 * time.Second,
		HeartbeatInterval:          1 * time.Second,
		EnableAutoSync:             false,
		EnableConflictResolution:   true,
		ConflictResolutionStrategy: ConflictResolutionLastWriteWins,
		CacheSize:                  8 * 1024 * 1024, // 8MB
		Compression:                "none",
		SyncWrites:                 false,
		LogLevel:                   "error",
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.NodeID == 0 {
		return ErrInvalidConfig{Field: "NodeID", Reason: "node ID must be > 0"}
	}
	if c.QuicBaaSDataDir == "" {
		return ErrInvalidConfig{Field: "QuicBaaSDataDir", Reason: "data directory is required"}
	}
	if c.QuicBaaSWALDir == "" {
		return ErrInvalidConfig{Field: "QuicBaaSWALDir", Reason: "WAL directory is required"}
	}
	if c.RaftAddress == "" {
		return ErrInvalidConfig{Field: "RaftAddress", Reason: "raft address is required"}
	}
	if c.SyncInterval <= 0 {
		return ErrInvalidConfig{Field: "SyncInterval", Reason: "sync interval must be positive"}
	}
	if c.ReplicationTimeout <= 0 {
		return ErrInvalidConfig{Field: "ReplicationTimeout", Reason: "replication timeout must be positive"}
	}
	if c.LeaderElectionTimeout <= 0 {
		return ErrInvalidConfig{Field: "LeaderElectionTimeout", Reason: "leader election timeout must be positive"}
	}
	if c.HeartbeatInterval <= 0 {
		return ErrInvalidConfig{Field: "HeartbeatInterval", Reason: "heartbeat interval must be positive"}
	}
	if c.CacheSize < 0 {
		return ErrInvalidConfig{Field: "CacheSize", Reason: "cache size cannot be negative"}
	}
	return nil
}
