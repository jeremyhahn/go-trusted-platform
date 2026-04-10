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

// Package cluster provides cluster management and coordination for the
// Trusted Platform, including node discovery, leader election, and
// distributed state management.
package cluster

import (
	"fmt"
)

// ErrClusterNotInitialized is returned when cluster operations are attempted
// before the cluster has been initialized.
type ErrClusterNotInitialized struct{}

func (e ErrClusterNotInitialized) Error() string {
	return "cluster not initialized"
}

// ErrClusterAlreadyInitialized is returned when attempting to initialize
// a cluster that has already been initialized.
type ErrClusterAlreadyInitialized struct{}

func (e ErrClusterAlreadyInitialized) Error() string {
	return "cluster already initialized"
}

// ErrNodeNotFound is returned when a requested node cannot be found in the cluster.
type ErrNodeNotFound struct {
	NodeID uint64
}

func (e ErrNodeNotFound) Error() string {
	return fmt.Sprintf("node not found: id=%d", e.NodeID)
}

// ErrNodeAlreadyExists is returned when attempting to add a node that already
// exists in the cluster.
type ErrNodeAlreadyExists struct {
	NodeID uint64
}

func (e ErrNodeAlreadyExists) Error() string {
	return fmt.Sprintf("node already exists: id=%d", e.NodeID)
}

// ErrNodeNotLeader is returned when a leader-only operation is attempted
// on a non-leader node.
type ErrNodeNotLeader struct {
	NodeID   uint64
	LeaderID uint64
}

func (e ErrNodeNotLeader) Error() string {
	if e.LeaderID > 0 {
		return fmt.Sprintf("node %d is not the leader; current leader is %d", e.NodeID, e.LeaderID)
	}
	return fmt.Sprintf("node %d is not the leader; no leader currently elected", e.NodeID)
}

// ErrQuorumLost is returned when the cluster loses quorum and cannot
// process requests.
type ErrQuorumLost struct {
	Required  int
	Available int
}

func (e ErrQuorumLost) Error() string {
	return fmt.Sprintf("quorum lost: required=%d, available=%d", e.Required, e.Available)
}

// ErrBootstrapFailed is returned when cluster bootstrap fails.
type ErrBootstrapFailed struct {
	Reason string
	Cause  error
}

func (e ErrBootstrapFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("cluster bootstrap failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("cluster bootstrap failed: %s", e.Reason)
}

func (e ErrBootstrapFailed) Unwrap() error {
	return e.Cause
}

// ErrJoinFailed is returned when a node fails to join the cluster.
type ErrJoinFailed struct {
	NodeID  uint64
	Address string
	Reason  string
	Cause   error
}

func (e ErrJoinFailed) Error() string {
	msg := fmt.Sprintf("failed to join cluster: node=%d, address=%s", e.NodeID, e.Address)
	if e.Reason != "" {
		msg = fmt.Sprintf("%s, reason=%s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrJoinFailed) Unwrap() error {
	return e.Cause
}

// ErrLeaveFailed is returned when a node fails to leave the cluster gracefully.
type ErrLeaveFailed struct {
	NodeID uint64
	Reason string
	Cause  error
}

func (e ErrLeaveFailed) Error() string {
	msg := fmt.Sprintf("failed to leave cluster: node=%d", e.NodeID)
	if e.Reason != "" {
		msg = fmt.Sprintf("%s, reason=%s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrLeaveFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig is returned when cluster configuration validation fails.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid cluster configuration: %s: %s", e.Field, e.Reason)
}

// ErrTimeout is returned when a cluster operation times out.
type ErrTimeout struct {
	Operation string
}

func (e ErrTimeout) Error() string {
	return fmt.Sprintf("cluster operation timed out: %s", e.Operation)
}

// ErrConnectionFailed is returned when connection to a cluster node fails.
type ErrConnectionFailed struct {
	NodeID  uint64
	Address string
	Cause   error
}

func (e ErrConnectionFailed) Error() string {
	if e.NodeID > 0 {
		return fmt.Sprintf("connection failed to node %d at %s: %v", e.NodeID, e.Address, e.Cause)
	}
	return fmt.Sprintf("connection failed to %s: %v", e.Address, e.Cause)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrClusterUnavailable is returned when the cluster is unavailable
// for processing requests.
type ErrClusterUnavailable struct {
	Reason string
}

func (e ErrClusterUnavailable) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("cluster unavailable: %s", e.Reason)
	}
	return "cluster unavailable"
}

// ErrNoLeader is returned when no leader is available in the cluster.
type ErrNoLeader struct{}

func (e ErrNoLeader) Error() string {
	return "no leader available"
}

// ErrLeadershipTimeout is returned when waiting for leader election times out.
type ErrLeadershipTimeout struct{}

func (e ErrLeadershipTimeout) Error() string {
	return "leadership election timed out"
}

// ErrAlreadyJoined is returned when a node attempts to join a cluster
// it has already joined.
type ErrAlreadyJoined struct{}

func (e ErrAlreadyJoined) Error() string {
	return "node already joined to cluster"
}

// ErrNotJoined is returned when operations are attempted on a node
// that has not joined a cluster.
type ErrNotJoined struct{}

func (e ErrNotJoined) Error() string {
	return "node has not joined a cluster"
}

// ErrAddNodeFailed is returned when adding a node to the cluster fails.
type ErrAddNodeFailed struct {
	NodeID  uint64
	Address string
	Cause   error
}

func (e ErrAddNodeFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to add node %d at %s: %v", e.NodeID, e.Address, e.Cause)
	}
	return fmt.Sprintf("failed to add node %d at %s", e.NodeID, e.Address)
}

func (e ErrAddNodeFailed) Unwrap() error {
	return e.Cause
}

// ErrRemoveNodeFailed is returned when removing a node from the cluster fails.
type ErrRemoveNodeFailed struct {
	NodeID uint64
	Cause  error
}

func (e ErrRemoveNodeFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to remove node %d: %v", e.NodeID, e.Cause)
	}
	return fmt.Sprintf("failed to remove node %d", e.NodeID)
}

func (e ErrRemoveNodeFailed) Unwrap() error {
	return e.Cause
}

// ErrManagerClosed is returned when operations are attempted on a
// closed membership manager.
type ErrManagerClosed struct{}

func (e ErrManagerClosed) Error() string {
	return "membership manager is closed"
}

// ErrNoJoinAddresses is returned when no join addresses are provided
// for a join operation.
type ErrNoJoinAddresses struct{}

func (e ErrNoJoinAddresses) Error() string {
	return "no join addresses provided"
}

// ErrInvalidAddress is returned when an invalid address is provided.
type ErrInvalidAddress struct {
	Address string
	Reason  string
}

func (e ErrInvalidAddress) Error() string {
	return fmt.Sprintf("invalid address %s: %s", e.Address, e.Reason)
}

// ErrInvalidClusterState is returned when a cluster state value is invalid.
type ErrInvalidClusterState struct {
	State ClusterState
}

func (e ErrInvalidClusterState) Error() string {
	return fmt.Sprintf("invalid cluster state: %s", e.State)
}

// ErrInvalidStateTransition is returned when a state transition is not allowed.
type ErrInvalidStateTransition struct {
	From ClusterState
	To   ClusterState
}

func (e ErrInvalidStateTransition) Error() string {
	return fmt.Sprintf("invalid state transition: %s -> %s", e.From, e.To)
}

// ErrInvalidNodeState is returned when a node state value is invalid.
type ErrInvalidNodeState struct {
	State NodeState
}

func (e ErrInvalidNodeState) Error() string {
	return fmt.Sprintf("invalid node state: %s", e.State)
}

// ErrInvalidNodeID is returned when a node ID is invalid.
type ErrInvalidNodeID struct {
	ID uint64
}

func (e ErrInvalidNodeID) Error() string {
	return fmt.Sprintf("invalid node ID: %d", e.ID)
}

// ErrNilNode is returned when a nil node is provided.
type ErrNilNode struct{}

func (e ErrNilNode) Error() string {
	return "node cannot be nil"
}

// ErrContextCancelled is returned when an operation is cancelled via context.
type ErrContextCancelled struct {
	Err error
}

func (e ErrContextCancelled) Error() string {
	return fmt.Sprintf("operation cancelled: %v", e.Err)
}

func (e ErrContextCancelled) Unwrap() error {
	return e.Err
}

// ErrClusterNotReady is returned when the cluster is not ready for operations.
type ErrClusterNotReady struct {
	State ClusterState
}

func (e ErrClusterNotReady) Error() string {
	return fmt.Sprintf("cluster not ready: current state is %s", e.State)
}

// ErrLeadershipLost is returned when the node loses leadership during an operation.
type ErrLeadershipLost struct{}

func (e ErrLeadershipLost) Error() string {
	return "leadership lost during operation"
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "cluster configuration cannot be nil"
}

// ErrNilMembership is returned when a nil membership manager is provided.
type ErrNilMembership struct{}

func (e ErrNilMembership) Error() string {
	return "membership manager cannot be nil"
}

// ErrNilLogger is returned when a nil logger is provided.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "logger cannot be nil"
}

// ErrCoordinatorAlreadyRunning is returned when the coordinator is already running.
type ErrCoordinatorAlreadyRunning struct{}

func (e ErrCoordinatorAlreadyRunning) Error() string {
	return "cluster coordinator is already running"
}

// ErrCoordinatorNotRunning is returned when the coordinator is not running.
type ErrCoordinatorNotRunning struct{}

func (e ErrCoordinatorNotRunning) Error() string {
	return "cluster coordinator is not running"
}

// ErrStatusUnavailable is returned when cluster status is unavailable.
type ErrStatusUnavailable struct{}

func (e ErrStatusUnavailable) Error() string {
	return "cluster status is unavailable"
}

// ErrHealthCheckFailed is returned when a health check fails.
type ErrHealthCheckFailed struct {
	Reason string
	Cause  error
}

func (e ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("health check failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("health check failed: %s", e.Reason)
}

func (e ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}
