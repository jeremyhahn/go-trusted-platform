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
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Default coordinator configuration values
const (
	DefaultCoordinatorHealthCheckInterval = 5 * time.Second
	DefaultCoordinatorLeaderWaitTimeout   = 30 * time.Second
	DefaultCoordinatorShutdownTimeout     = 10 * time.Second
)

// ClusterState represents the overall state of the cluster coordination.
type ClusterState string

const (
	// ClusterStateUninitialized indicates the cluster has not been initialized.
	ClusterStateUninitialized ClusterState = "uninitialized"

	// ClusterStateBootstrapping indicates the cluster is being bootstrapped.
	ClusterStateBootstrapping ClusterState = "bootstrapping"

	// ClusterStateJoining indicates the node is joining an existing cluster.
	ClusterStateJoining ClusterState = "joining"

	// ClusterStateRunning indicates the cluster is running normally.
	ClusterStateRunning ClusterState = "running"

	// ClusterStateDegraded indicates the cluster is running but degraded.
	ClusterStateDegraded ClusterState = "degraded"

	// ClusterStateLeaving indicates the node is leaving the cluster.
	ClusterStateLeaving ClusterState = "leaving"

	// ClusterStateStopped indicates the cluster coordinator has stopped.
	ClusterStateStopped ClusterState = "stopped"
)

// ClusterStatus represents the current status of the cluster.
type ClusterStatus struct {
	// State is the current cluster state.
	State ClusterState `json:"state" yaml:"state"`

	// NodeCount is the total number of nodes in the cluster.
	NodeCount int `json:"node_count" yaml:"node_count"`

	// HealthyCount is the number of healthy nodes in the cluster.
	HealthyCount int `json:"healthy_count" yaml:"healthy_count"`

	// LeaderID is the node ID of the current leader.
	LeaderID uint64 `json:"leader_id" yaml:"leader_id"`

	// Term is the current Raft term number.
	Term uint64 `json:"term" yaml:"term"`

	// HasQuorum indicates whether the cluster has quorum.
	HasQuorum bool `json:"has_quorum" yaml:"has_quorum"`

	// LastUpdated is when this status was last updated.
	LastUpdated time.Time `json:"last_updated" yaml:"last_updated"`

	// StartedAt is when the coordinator was started.
	StartedAt time.Time `json:"started_at" yaml:"started_at"`

	// ErrorMessage contains any current error message.
	ErrorMessage string `json:"error_message,omitempty" yaml:"error_message,omitempty"`
}

// Coordinator orchestrates cluster operations including membership management,
// health monitoring, and leadership tracking.
type Coordinator interface {
	// Lifecycle management

	// Start initializes the coordinator and begins health monitoring.
	Start(ctx context.Context) error

	// Stop gracefully stops the coordinator, leaving the cluster if joined.
	Stop(ctx context.Context) error

	// IsRunning returns true if the coordinator is currently running.
	IsRunning() bool

	// Cluster operations

	// Bootstrap initializes a new cluster with this node as the first member.
	Bootstrap(ctx context.Context) error

	// Join adds this node to an existing cluster.
	Join(ctx context.Context, addresses []string) error

	// Leave gracefully removes this node from the cluster.
	Leave(ctx context.Context) error

	// Status and node information

	// Status returns the current cluster status.
	Status(ctx context.Context) (*ClusterStatus, error)

	// Nodes returns all nodes in the cluster.
	Nodes(ctx context.Context) (NodeList, error)

	// Leadership

	// IsLeader returns true if this node is the current leader.
	IsLeader() bool

	// GetLeader returns the current cluster leader.
	GetLeader(ctx context.Context) (*Node, error)

	// WaitForLeader blocks until a leader is elected or context is cancelled.
	WaitForLeader(ctx context.Context) (*Node, error)

	// Health

	// IsHealthy returns true if the cluster is in a healthy state.
	IsHealthy() bool

	// HealthCheck performs a health check and returns any errors.
	HealthCheck(ctx context.Context) error

	// Configuration

	// Config returns the cluster configuration.
	Config() *Config

	// NodeID returns this node's ID.
	NodeID() uint64
}

// CoordinatorOption is a functional option for configuring the coordinator.
type CoordinatorOption func(*coordinator)

// WithCoordinatorHealthCheckInterval sets the health check interval.
func WithCoordinatorHealthCheckInterval(d time.Duration) CoordinatorOption {
	return func(c *coordinator) {
		c.healthCheckInterval = d
	}
}

// WithCoordinatorLeaderWaitTimeout sets the timeout for waiting for a leader.
func WithCoordinatorLeaderWaitTimeout(d time.Duration) CoordinatorOption {
	return func(c *coordinator) {
		c.leaderWaitTimeout = d
	}
}

// WithCoordinatorShutdownTimeout sets the graceful shutdown timeout.
func WithCoordinatorShutdownTimeout(d time.Duration) CoordinatorOption {
	return func(c *coordinator) {
		c.shutdownTimeout = d
	}
}

// coordinator implements the Coordinator interface.
type coordinator struct {
	config     *Config
	membership MembershipManager
	logger     *logging.Logger

	// Lifecycle state using atomic operations for lock-free access
	running atomic.Bool
	healthy atomic.Bool

	// Configuration
	healthCheckInterval time.Duration
	leaderWaitTimeout   time.Duration
	shutdownTimeout     time.Duration

	// Atomic status storage using atomic.Value for lock-free reads
	status atomic.Value // stores *ClusterStatus

	// Synchronization for status updates
	statusMu sync.Mutex

	// Goroutine coordination
	stopChan    chan struct{}
	stoppedChan chan struct{}
}

// NewCoordinator creates a new cluster coordinator with the given configuration,
// membership manager, and logger. Functional options can be used to customize
// the coordinator's behavior.
func NewCoordinator(config *Config, membership MembershipManager, logger *logging.Logger, opts ...CoordinatorOption) (Coordinator, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}

	if membership == nil {
		return nil, ErrNilMembership{}
	}

	if logger == nil {
		return nil, ErrNilLogger{}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	c := &coordinator{
		config:              config,
		membership:          membership,
		logger:              logger,
		healthCheckInterval: DefaultCoordinatorHealthCheckInterval,
		leaderWaitTimeout:   DefaultCoordinatorLeaderWaitTimeout,
		shutdownTimeout:     DefaultCoordinatorShutdownTimeout,
		stopChan:            make(chan struct{}),
		stoppedChan:         make(chan struct{}),
	}

	// Apply functional options
	for _, opt := range opts {
		opt(c)
	}

	// Initialize status
	initialStatus := &ClusterStatus{
		State:       ClusterStateUninitialized,
		LastUpdated: time.Now(),
	}
	c.status.Store(initialStatus)

	return c, nil
}

// Start initializes the coordinator and begins health monitoring.
func (c *coordinator) Start(ctx context.Context) error {
	if c.running.Swap(true) {
		return ErrCoordinatorAlreadyRunning{}
	}

	c.logger.Info("cluster coordinator starting", "node_id", c.config.NodeID)

	// Recreate channels for this run (they may have been closed by a previous Stop)
	c.stopChan = make(chan struct{})
	c.stoppedChan = make(chan struct{})

	// Update status
	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateRunning
		s.StartedAt = time.Now()
		s.LastUpdated = time.Now()
	})

	// Start health monitoring goroutine
	go c.healthMonitorLoop()

	c.healthy.Store(true)
	c.logger.Info("cluster coordinator started successfully", "node_id", c.config.NodeID)

	return nil
}

// Stop gracefully stops the coordinator.
func (c *coordinator) Stop(ctx context.Context) error {
	if !c.running.Load() {
		return ErrCoordinatorNotRunning{}
	}

	c.logger.Info("cluster coordinator stopping", "node_id", c.config.NodeID)

	// Update status to leaving
	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateLeaving
		s.LastUpdated = time.Now()
	})

	// Signal health monitor to stop
	close(c.stopChan)

	// Wait for health monitor to finish with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, c.shutdownTimeout)
	defer cancel()

	select {
	case <-c.stoppedChan:
		// Health monitor stopped cleanly
	case <-shutdownCtx.Done():
		c.logger.Warn("health monitor shutdown timed out", "timeout", c.shutdownTimeout)
	}

	// Leave the cluster if we're part of one
	leaveCtx, leaveCancel := context.WithTimeout(ctx, c.shutdownTimeout)
	defer leaveCancel()

	if err := c.membership.Leave(leaveCtx); err != nil {
		c.logger.Warn("failed to leave cluster gracefully", "error", err)
	}

	c.running.Store(false)
	c.healthy.Store(false)

	// Update final status
	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateStopped
		s.LastUpdated = time.Now()
	})

	c.logger.Info("cluster coordinator stopped", "node_id", c.config.NodeID)

	return nil
}

// IsRunning returns whether the coordinator is running.
func (c *coordinator) IsRunning() bool {
	return c.running.Load()
}

// Bootstrap initializes a new cluster with this node as the first member.
func (c *coordinator) Bootstrap(ctx context.Context) error {
	if !c.running.Load() {
		return ErrCoordinatorNotRunning{}
	}

	c.logger.Info("bootstrapping new cluster", "node_id", c.config.NodeID)

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateBootstrapping
		s.LastUpdated = time.Now()
	})

	if err := c.membership.Bootstrap(ctx); err != nil {
		c.updateStatus(func(s *ClusterStatus) {
			s.State = ClusterStateDegraded
			s.ErrorMessage = err.Error()
			s.LastUpdated = time.Now()
		})
		return ErrBootstrapFailed{Reason: "membership bootstrap failed", Cause: err}
	}

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateRunning
		s.ErrorMessage = ""
		s.LastUpdated = time.Now()
	})

	// Run initial health check to populate status with node count
	c.performHealthCheck()

	c.logger.Info("cluster bootstrapped successfully", "node_id", c.config.NodeID)

	return nil
}

// Join adds this node to an existing cluster.
func (c *coordinator) Join(ctx context.Context, addresses []string) error {
	if !c.running.Load() {
		return ErrCoordinatorNotRunning{}
	}

	if len(addresses) == 0 {
		return ErrNoJoinAddresses{}
	}

	c.logger.Info("joining cluster", "node_id", c.config.NodeID, "addresses", addresses)

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateJoining
		s.LastUpdated = time.Now()
	})

	if err := c.membership.Join(ctx, addresses); err != nil {
		c.updateStatus(func(s *ClusterStatus) {
			s.State = ClusterStateDegraded
			s.ErrorMessage = err.Error()
			s.LastUpdated = time.Now()
		})
		return ErrJoinFailed{
			NodeID:  c.config.NodeID,
			Address: c.config.GetAdvertiseAddress(),
			Reason:  "membership join failed",
			Cause:   err,
		}
	}

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateRunning
		s.ErrorMessage = ""
		s.LastUpdated = time.Now()
	})

	// Run initial health check to populate status with node count
	c.performHealthCheck()

	c.logger.Info("joined cluster successfully", "node_id", c.config.NodeID)

	return nil
}

// Leave gracefully removes this node from the cluster.
func (c *coordinator) Leave(ctx context.Context) error {
	if !c.running.Load() {
		return ErrCoordinatorNotRunning{}
	}

	c.logger.Info("leaving cluster", "node_id", c.config.NodeID)

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateLeaving
		s.LastUpdated = time.Now()
	})

	if err := c.membership.Leave(ctx); err != nil {
		c.updateStatus(func(s *ClusterStatus) {
			s.State = ClusterStateDegraded
			s.ErrorMessage = err.Error()
			s.LastUpdated = time.Now()
		})
		return ErrLeaveFailed{
			NodeID: c.config.NodeID,
			Reason: "membership leave failed",
			Cause:  err,
		}
	}

	c.updateStatus(func(s *ClusterStatus) {
		s.State = ClusterStateStopped
		s.ErrorMessage = ""
		s.LastUpdated = time.Now()
	})

	c.logger.Info("left cluster successfully", "node_id", c.config.NodeID)

	return nil
}

// Status returns the current cluster status.
func (c *coordinator) Status(ctx context.Context) (*ClusterStatus, error) {
	if !c.running.Load() {
		return nil, ErrCoordinatorNotRunning{}
	}

	// Refresh status with latest cluster state
	c.performHealthCheck()

	status := c.loadStatus()
	if status == nil {
		return nil, ErrStatusUnavailable{}
	}

	// Create a copy to prevent external modification
	statusCopy := *status
	return &statusCopy, nil
}

// Nodes returns all cluster nodes.
func (c *coordinator) Nodes(ctx context.Context) (NodeList, error) {
	if !c.running.Load() {
		return NodeList{}, ErrCoordinatorNotRunning{}
	}

	// Invalidate cache to ensure fresh data
	c.membership.InvalidateCache()

	return c.membership.GetNodes(ctx)
}

// IsLeader returns whether this node is the current leader.
func (c *coordinator) IsLeader() bool {
	if !c.running.Load() {
		return false
	}

	return c.membership.IsLeader()
}

// GetLeader returns the current cluster leader.
func (c *coordinator) GetLeader(ctx context.Context) (*Node, error) {
	if !c.running.Load() {
		return nil, ErrCoordinatorNotRunning{}
	}

	return c.membership.GetLeader(ctx)
}

// WaitForLeader waits until a leader is elected or context is cancelled.
func (c *coordinator) WaitForLeader(ctx context.Context) (*Node, error) {
	if !c.running.Load() {
		return nil, ErrCoordinatorNotRunning{}
	}

	return c.membership.WaitForLeader(ctx)
}

// IsHealthy returns whether the cluster is in a healthy state.
func (c *coordinator) IsHealthy() bool {
	return c.healthy.Load()
}

// HealthCheck verifies the cluster health.
func (c *coordinator) HealthCheck(ctx context.Context) error {
	if !c.running.Load() {
		return ErrCoordinatorNotRunning{}
	}

	// Get current nodes
	nodeList, err := c.membership.GetNodes(ctx)
	if err != nil {
		return ErrHealthCheckFailed{Reason: "failed to get nodes", Cause: err}
	}

	// Calculate quorum
	totalNodes := nodeList.Count()
	healthyNodes := nodeList.HealthyCount()
	quorumSize := (totalNodes / 2) + 1

	hasQuorum := healthyNodes >= quorumSize

	if !hasQuorum {
		return ErrQuorumLost{Required: quorumSize, Available: healthyNodes}
	}

	// Check for leader
	leader, err := c.membership.GetLeader(ctx)
	if err != nil || leader == nil {
		return ErrNoLeader{}
	}

	return nil
}

// Config returns the cluster configuration.
func (c *coordinator) Config() *Config {
	return c.config
}

// NodeID returns this node's ID.
func (c *coordinator) NodeID() uint64 {
	return c.config.NodeID
}

// healthMonitorLoop runs periodic health checks and updates status.
func (c *coordinator) healthMonitorLoop() {
	defer close(c.stoppedChan)

	ticker := time.NewTicker(c.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.performHealthCheck()
		}
	}
}

// performHealthCheck executes a health check and updates status.
func (c *coordinator) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), c.healthCheckInterval/2)
	defer cancel()

	// Invalidate cache to ensure fresh data
	c.membership.InvalidateCache()

	// Get nodes
	nodeList, err := c.membership.GetNodes(ctx)
	if err != nil {
		c.logger.Warn("health check failed to get nodes", "error", err)
		c.healthy.Store(false)
		c.updateStatus(func(s *ClusterStatus) {
			s.State = ClusterStateDegraded
			s.ErrorMessage = err.Error()
			s.LastUpdated = time.Now()
		})
		return
	}

	totalNodes := nodeList.Count()
	healthyNodes := nodeList.HealthyCount()
	quorumSize := (totalNodes / 2) + 1
	hasQuorum := healthyNodes >= quorumSize

	// Get leader info
	var leaderID uint64
	leader, err := c.membership.GetLeader(ctx)
	if err == nil && leader != nil {
		leaderID = leader.ID
	}

	// Determine cluster state
	state := ClusterStateRunning
	if !hasQuorum {
		state = ClusterStateDegraded
	}

	// Update status atomically
	c.updateStatus(func(s *ClusterStatus) {
		s.State = state
		s.NodeCount = totalNodes
		s.HealthyCount = healthyNodes
		s.LeaderID = leaderID
		s.HasQuorum = hasQuorum
		s.LastUpdated = time.Now()
		if hasQuorum {
			s.ErrorMessage = ""
		} else {
			s.ErrorMessage = fmt.Sprintf("insufficient healthy nodes: %d/%d required", healthyNodes, quorumSize)
		}
	})

	c.healthy.Store(hasQuorum)
}

// loadStatus returns the current status (thread-safe).
func (c *coordinator) loadStatus() *ClusterStatus {
	val := c.status.Load()
	if val == nil {
		return nil
	}
	return val.(*ClusterStatus)
}

// updateStatus atomically updates the coordinator status.
func (c *coordinator) updateStatus(fn func(*ClusterStatus)) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()

	// Load current status or create new one
	current := c.loadStatus()
	var newStatus ClusterStatus
	if current != nil {
		newStatus = *current
	}

	// Apply update function
	fn(&newStatus)

	// Store updated status
	c.status.Store(&newStatus)
}
