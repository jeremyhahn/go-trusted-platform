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

// Package cluster provides CLI commands for cluster management operations
// including bootstrap, join, leave, status, and node listing.
package cluster

import "fmt"

// ErrMissingNodeID is returned when node ID is required but not provided
type ErrMissingNodeID struct{}

func (e ErrMissingNodeID) Error() string {
	return "node ID is required"
}

// ErrMissingListenAddr is returned when listen address is required but not provided
type ErrMissingListenAddr struct{}

func (e ErrMissingListenAddr) Error() string {
	return "listen address is required"
}

// ErrMissingJoinAddrs is returned when join addresses are required but not provided
type ErrMissingJoinAddrs struct{}

func (e ErrMissingJoinAddrs) Error() string {
	return "join addresses are required (comma-separated list)"
}

// ErrInvalidListenAddr is returned when listen address format is invalid
type ErrInvalidListenAddr struct {
	Addr   string
	Reason string
}

func (e ErrInvalidListenAddr) Error() string {
	return fmt.Sprintf("invalid listen address %q: %s", e.Addr, e.Reason)
}

// ErrInvalidJoinAddr is returned when a join address format is invalid
type ErrInvalidJoinAddr struct {
	Addr   string
	Reason string
}

func (e ErrInvalidJoinAddr) Error() string {
	return fmt.Sprintf("invalid join address %q: %s", e.Addr, e.Reason)
}

// ErrClusterBootstrapFailed is returned when cluster bootstrap fails
type ErrClusterBootstrapFailed struct {
	Err error
}

func (e ErrClusterBootstrapFailed) Error() string {
	return fmt.Sprintf("failed to bootstrap cluster: %v", e.Err)
}

func (e ErrClusterBootstrapFailed) Unwrap() error {
	return e.Err
}

// ErrClusterJoinFailed is returned when joining cluster fails
type ErrClusterJoinFailed struct {
	Err error
}

func (e ErrClusterJoinFailed) Error() string {
	return fmt.Sprintf("failed to join cluster: %v", e.Err)
}

func (e ErrClusterJoinFailed) Unwrap() error {
	return e.Err
}

// ErrClusterLeaveFailed is returned when leaving cluster fails
type ErrClusterLeaveFailed struct {
	Err error
}

func (e ErrClusterLeaveFailed) Error() string {
	return fmt.Sprintf("failed to leave cluster: %v", e.Err)
}

func (e ErrClusterLeaveFailed) Unwrap() error {
	return e.Err
}

// ErrClusterStatusFailed is returned when getting cluster status fails
type ErrClusterStatusFailed struct {
	Err error
}

func (e ErrClusterStatusFailed) Error() string {
	return fmt.Sprintf("failed to get cluster status: %v", e.Err)
}

func (e ErrClusterStatusFailed) Unwrap() error {
	return e.Err
}

// ErrClusterNodesFailed is returned when listing cluster nodes fails
type ErrClusterNodesFailed struct {
	Err error
}

func (e ErrClusterNodesFailed) Error() string {
	return fmt.Sprintf("failed to list cluster nodes: %v", e.Err)
}

func (e ErrClusterNodesFailed) Unwrap() error {
	return e.Err
}

// ErrClusterNotBootstrapped is returned when cluster operations are attempted before bootstrap
type ErrClusterNotBootstrapped struct{}

func (e ErrClusterNotBootstrapped) Error() string {
	return "cluster is not bootstrapped"
}

// ErrNodeNotInCluster is returned when the node is not part of a cluster
type ErrNodeNotInCluster struct{}

func (e ErrNodeNotInCluster) Error() string {
	return "node is not part of a cluster"
}

// ErrNodeAlreadyInCluster is returned when trying to join a node that is already in a cluster
type ErrNodeAlreadyInCluster struct {
	NodeID string
}

func (e ErrNodeAlreadyInCluster) Error() string {
	return fmt.Sprintf("node %q is already part of a cluster", e.NodeID)
}

// ErrClusterClientNotInitialized is returned when cluster client is not initialized
type ErrClusterClientNotInitialized struct{}

func (e ErrClusterClientNotInitialized) Error() string {
	return "cluster client not initialized"
}

// ErrInvalidDataDir is returned when data directory is invalid
type ErrInvalidDataDir struct {
	Path   string
	Reason string
}

func (e ErrInvalidDataDir) Error() string {
	return fmt.Sprintf("invalid data directory %q: %s", e.Path, e.Reason)
}
