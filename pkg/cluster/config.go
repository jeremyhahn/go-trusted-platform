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

const (
	// DefaultHeartbeatInterval is the default interval between heartbeats.
	DefaultHeartbeatInterval = 100 * time.Millisecond

	// DefaultElectionTimeout is the default timeout for leader election.
	DefaultElectionTimeout = 1 * time.Second

	// DefaultSnapshotInterval is the default interval between snapshots.
	DefaultSnapshotInterval = 5 * time.Minute

	// DefaultSnapshotThreshold is the default number of log entries before snapshot.
	DefaultSnapshotThreshold = 10000

	// DefaultMaxConcurrentStreams is the default max concurrent streams per connection.
	DefaultMaxConcurrentStreams = 256
)

// Config holds the configuration for cluster operations.
type Config struct {
	// NodeID is the unique identifier for this node in the cluster.
	// Must be unique across all cluster nodes and greater than 0.
	NodeID uint64

	// ListenAddress is the address this node listens on for cluster communication.
	// Format: "host:port" (e.g., "0.0.0.0:7000")
	ListenAddress string

	// AdvertiseAddress is the address advertised to other nodes for communication.
	// Format: "host:port" (e.g., "192.168.1.10:7000")
	// If empty, ListenAddress is used.
	AdvertiseAddress string

	// JoinAddresses is the list of existing cluster node addresses to join.
	// Empty for bootstrap node, populated for nodes joining an existing cluster.
	JoinAddresses []string

	// DataDir is the directory where cluster state is persisted.
	DataDir string

	// HeartbeatInterval is the interval between heartbeat messages.
	// Lower values detect failures faster but increase network traffic.
	HeartbeatInterval time.Duration

	// ElectionTimeout is the timeout for leader election.
	// Should be significantly larger than HeartbeatInterval (typically 10x).
	ElectionTimeout time.Duration

	// SnapshotInterval is the interval between state snapshots.
	SnapshotInterval time.Duration

	// SnapshotThreshold is the number of log entries that triggers a snapshot.
	SnapshotThreshold uint64

	// MaxConcurrentStreams is the maximum number of concurrent streams
	// per gRPC connection for cluster communication.
	MaxConcurrentStreams int
}

// NewConfig returns a new Config with sensible defaults.
func NewConfig() *Config {
	return &Config{
		NodeID:               1,
		ListenAddress:        "0.0.0.0:7000",
		AdvertiseAddress:     "",
		JoinAddresses:        nil,
		DataDir:              "./data/cluster",
		HeartbeatInterval:    DefaultHeartbeatInterval,
		ElectionTimeout:      DefaultElectionTimeout,
		SnapshotInterval:     DefaultSnapshotInterval,
		SnapshotThreshold:    DefaultSnapshotThreshold,
		MaxConcurrentStreams: DefaultMaxConcurrentStreams,
	}
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.NodeID == 0 {
		return ErrInvalidConfig{
			Field:  "NodeID",
			Reason: "must be greater than 0",
		}
	}

	if c.ListenAddress == "" {
		return ErrInvalidConfig{
			Field:  "ListenAddress",
			Reason: "is required",
		}
	}

	if c.DataDir == "" {
		return ErrInvalidConfig{
			Field:  "DataDir",
			Reason: "is required",
		}
	}

	if c.HeartbeatInterval <= 0 {
		return ErrInvalidConfig{
			Field:  "HeartbeatInterval",
			Reason: "must be positive",
		}
	}

	if c.ElectionTimeout <= 0 {
		return ErrInvalidConfig{
			Field:  "ElectionTimeout",
			Reason: "must be positive",
		}
	}

	if c.ElectionTimeout < c.HeartbeatInterval*2 {
		return ErrInvalidConfig{
			Field:  "ElectionTimeout",
			Reason: "should be at least 2x HeartbeatInterval",
		}
	}

	if c.SnapshotInterval <= 0 {
		return ErrInvalidConfig{
			Field:  "SnapshotInterval",
			Reason: "must be positive",
		}
	}

	if c.SnapshotThreshold == 0 {
		return ErrInvalidConfig{
			Field:  "SnapshotThreshold",
			Reason: "must be greater than 0",
		}
	}

	if c.MaxConcurrentStreams <= 0 {
		return ErrInvalidConfig{
			Field:  "MaxConcurrentStreams",
			Reason: "must be positive",
		}
	}

	return nil
}

// Clone creates a deep copy of the configuration.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	clone := &Config{
		NodeID:               c.NodeID,
		ListenAddress:        c.ListenAddress,
		AdvertiseAddress:     c.AdvertiseAddress,
		DataDir:              c.DataDir,
		HeartbeatInterval:    c.HeartbeatInterval,
		ElectionTimeout:      c.ElectionTimeout,
		SnapshotInterval:     c.SnapshotInterval,
		SnapshotThreshold:    c.SnapshotThreshold,
		MaxConcurrentStreams: c.MaxConcurrentStreams,
	}

	if c.JoinAddresses != nil {
		clone.JoinAddresses = make([]string, len(c.JoinAddresses))
		copy(clone.JoinAddresses, c.JoinAddresses)
	}

	return clone
}

// WithNodeID returns a copy of the config with the specified NodeID.
func (c *Config) WithNodeID(nodeID uint64) *Config {
	clone := c.Clone()
	clone.NodeID = nodeID
	return clone
}

// WithListenAddress returns a copy of the config with the specified ListenAddress.
func (c *Config) WithListenAddress(address string) *Config {
	clone := c.Clone()
	clone.ListenAddress = address
	return clone
}

// WithAdvertiseAddress returns a copy of the config with the specified AdvertiseAddress.
func (c *Config) WithAdvertiseAddress(address string) *Config {
	clone := c.Clone()
	clone.AdvertiseAddress = address
	return clone
}

// WithJoinAddresses returns a copy of the config with the specified JoinAddresses.
func (c *Config) WithJoinAddresses(addresses []string) *Config {
	clone := c.Clone()
	if addresses != nil {
		clone.JoinAddresses = make([]string, len(addresses))
		copy(clone.JoinAddresses, addresses)
	} else {
		clone.JoinAddresses = nil
	}
	return clone
}

// WithDataDir returns a copy of the config with the specified DataDir.
func (c *Config) WithDataDir(dir string) *Config {
	clone := c.Clone()
	clone.DataDir = dir
	return clone
}

// WithHeartbeatInterval returns a copy of the config with the specified HeartbeatInterval.
func (c *Config) WithHeartbeatInterval(interval time.Duration) *Config {
	clone := c.Clone()
	clone.HeartbeatInterval = interval
	return clone
}

// WithElectionTimeout returns a copy of the config with the specified ElectionTimeout.
func (c *Config) WithElectionTimeout(timeout time.Duration) *Config {
	clone := c.Clone()
	clone.ElectionTimeout = timeout
	return clone
}

// WithSnapshotInterval returns a copy of the config with the specified SnapshotInterval.
func (c *Config) WithSnapshotInterval(interval time.Duration) *Config {
	clone := c.Clone()
	clone.SnapshotInterval = interval
	return clone
}

// WithSnapshotThreshold returns a copy of the config with the specified SnapshotThreshold.
func (c *Config) WithSnapshotThreshold(threshold uint64) *Config {
	clone := c.Clone()
	clone.SnapshotThreshold = threshold
	return clone
}

// WithMaxConcurrentStreams returns a copy of the config with the specified MaxConcurrentStreams.
func (c *Config) WithMaxConcurrentStreams(streams int) *Config {
	clone := c.Clone()
	clone.MaxConcurrentStreams = streams
	return clone
}

// GetAdvertiseAddress returns the advertise address, falling back to
// ListenAddress if AdvertiseAddress is not set.
func (c *Config) GetAdvertiseAddress() string {
	if c.AdvertiseAddress != "" {
		return c.AdvertiseAddress
	}
	return c.ListenAddress
}

// IsBootstrap returns true if this node should bootstrap a new cluster
// (i.e., no join addresses are configured).
func (c *Config) IsBootstrap() bool {
	return len(c.JoinAddresses) == 0
}
