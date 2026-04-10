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

package grpc

import "context"

// ClusterService defines the interface for cluster management operations.
// This interface is implemented by cluster service providers and used by the gRPC service.
type ClusterService interface {
	// Bootstrap initializes a new cluster with this node as the initial leader.
	Bootstrap(ctx context.Context, req *ClusterBootstrapRequest) (*ClusterBootstrapResponse, error)

	// Join adds this node to an existing cluster.
	Join(ctx context.Context, req *ClusterJoinRequest) (*ClusterJoinResponse, error)

	// Leave gracefully removes this node from the cluster.
	Leave(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error)

	// GetStatus returns the current cluster status including leader and health.
	GetStatus(ctx context.Context, req *ClusterGetStatusRequest) (*ClusterGetStatusResponse, error)

	// ListNodes returns all nodes in the cluster with their status.
	ListNodes(ctx context.Context, req *ClusterListNodesRequest) (*ClusterListNodesResponse, error)
}

// =============================================================================
// Cluster State and Role Types
// =============================================================================

// ClusterStateType represents the state of the cluster.
type ClusterStateType int32

const (
	ClusterStateUnspecified  ClusterStateType = 0
	ClusterStateInitializing ClusterStateType = 1
	ClusterStateHealthy      ClusterStateType = 2
	ClusterStateDegraded     ClusterStateType = 3
	ClusterStateUnavailable  ClusterStateType = 4
	ClusterStatePartitioned  ClusterStateType = 5
)

// NodeRoleType represents the role of a node in the cluster.
type NodeRoleType int32

const (
	NodeRoleUnspecified NodeRoleType = 0
	NodeRoleLeader      NodeRoleType = 1
	NodeRoleFollower    NodeRoleType = 2
	NodeRoleCandidate   NodeRoleType = 3
	NodeRoleObserver    NodeRoleType = 4
)

// NodeStateType represents the state of a node in the cluster.
type NodeStateType int32

const (
	NodeStateUnspecified NodeStateType = 0
	NodeStateJoining     NodeStateType = 1
	NodeStateActive      NodeStateType = 2
	NodeStateLeaving     NodeStateType = 3
	NodeStateLeft        NodeStateType = 4
	NodeStateFailed      NodeStateType = 5
	NodeStateUnreachable NodeStateType = 6
)

// HealthStatusType represents the health status of a node.
type HealthStatusType int32

const (
	HealthStatusUnspecified HealthStatusType = 0
	HealthStatusHealthy     HealthStatusType = 1
	HealthStatusDegraded    HealthStatusType = 2
	HealthStatusUnhealthy   HealthStatusType = 3
)

// =============================================================================
// Cluster Node Types
// =============================================================================

// ClusterNodeInfo represents a node in the cluster.
type ClusterNodeInfo struct {
	ID            string
	Name          string
	Address       string
	Port          uint32
	Role          NodeRoleType
	State         NodeStateType
	Health        HealthStatusType
	Version       string
	JoinedAt      int64
	LastHeartbeat int64
	Labels        map[string]string
	Metadata      map[string]string
}

// ClusterInfoData contains comprehensive cluster information.
type ClusterInfoData struct {
	ID            string
	Name          string
	State         ClusterStateType
	LeaderID      string
	LeaderAddress string
	TotalNodes    uint32
	HealthyNodes  uint32
	Term          uint64
	CreatedAt     int64
	LastElection  int64
	Metadata      map[string]string
}

// =============================================================================
// Bootstrap Request/Response Types
// =============================================================================

// ClusterBootstrapRequest represents a cluster bootstrap request.
type ClusterBootstrapRequest struct {
	ClusterName      string
	NodeName         string
	BindAddress      string
	BindPort         uint32
	AdvertiseAddress string
	AdvertisePort    uint32
	Labels           map[string]string
	Metadata         map[string]string
}

// ClusterBootstrapResponse represents a cluster bootstrap response.
type ClusterBootstrapResponse struct {
	Cluster *ClusterInfoData
	Node    *ClusterNodeInfo
}

// =============================================================================
// Join Request/Response Types
// =============================================================================

// ClusterJoinRequest represents a cluster join request.
type ClusterJoinRequest struct {
	NodeName         string
	BindAddress      string
	BindPort         uint32
	AdvertiseAddress string
	AdvertisePort    uint32
	SeedAddresses    []string
	Labels           map[string]string
	Metadata         map[string]string
}

// ClusterJoinResponse represents a cluster join response.
type ClusterJoinResponse struct {
	Cluster *ClusterInfoData
	Node    *ClusterNodeInfo
}

// =============================================================================
// Leave Request/Response Types
// =============================================================================

// ClusterLeaveRequest represents a cluster leave request.
type ClusterLeaveRequest struct {
	NodeID         string
	Force          bool
	TimeoutSeconds uint32
}

// ClusterLeaveResponse represents a cluster leave response.
type ClusterLeaveResponse struct {
	Success bool
	Message string
}

// =============================================================================
// GetStatus Request/Response Types
// =============================================================================

// ClusterGetStatusRequest represents a cluster status request.
type ClusterGetStatusRequest struct {
	IncludeNodes bool
}

// ClusterGetStatusResponse represents a cluster status response.
type ClusterGetStatusResponse struct {
	Cluster   *ClusterInfoData
	LocalNode *ClusterNodeInfo
	Nodes     []*ClusterNodeInfo
	Timestamp int64
}

// =============================================================================
// ListNodes Request/Response Types
// =============================================================================

// ClusterListNodesRequest represents a list nodes request.
type ClusterListNodesRequest struct {
	Roles       []NodeRoleType
	States      []NodeStateType
	MatchLabels map[string]string
	Page        uint32
	PageSize    uint32
	SortBy      string
	Ascending   bool
}

// ClusterListNodesResponse represents a list nodes response.
type ClusterListNodesResponse struct {
	Nodes      []*ClusterNodeInfo
	Total      uint32
	Page       uint32
	PageSize   uint32
	TotalPages uint32
	TotalItems uint64
}

// =============================================================================
// Cluster Error Types
// =============================================================================

// ErrNilClusterService is returned when the cluster service is nil.
type ErrNilClusterService struct{}

func (e ErrNilClusterService) Error() string {
	return "cluster service is nil"
}

// ErrClusterNotInitialized is returned when the cluster is not initialized.
type ErrClusterNotInitialized struct{}

func (e ErrClusterNotInitialized) Error() string {
	return "cluster is not initialized"
}

// ErrClusterAlreadyInitialized is returned when attempting to bootstrap an already initialized cluster.
type ErrClusterAlreadyInitialized struct{}

func (e ErrClusterAlreadyInitialized) Error() string {
	return "cluster is already initialized"
}

// ErrNodeAlreadyInCluster is returned when a node is already a member of the cluster.
type ErrNodeAlreadyInCluster struct{}

func (e ErrNodeAlreadyInCluster) Error() string {
	return "node is already a member of the cluster"
}

// ErrNodeNotInCluster is returned when the node is not a member of the cluster.
type ErrNodeNotInCluster struct{}

func (e ErrNodeNotInCluster) Error() string {
	return "node is not a member of the cluster"
}

// ErrMissingClusterName is returned when a cluster name is required but not provided.
type ErrMissingClusterName struct{}

func (e ErrMissingClusterName) Error() string {
	return "cluster name is required"
}

// ErrMissingNodeName is returned when a node name is required but not provided.
type ErrMissingNodeName struct{}

func (e ErrMissingNodeName) Error() string {
	return "node name is required"
}

// ErrMissingSeedAddresses is returned when seed addresses are required but not provided.
type ErrMissingSeedAddresses struct{}

func (e ErrMissingSeedAddresses) Error() string {
	return "at least one seed address is required"
}

// ErrMissingNodeID is returned when a node ID is required but not provided.
type ErrMissingNodeID struct{}

func (e ErrMissingNodeID) Error() string {
	return "node ID is required"
}

// ErrClusterOperationFailed is returned when a cluster operation fails.
type ErrClusterOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrClusterOperationFailed) Error() string {
	return "cluster operation " + e.Operation + " failed: " + e.Reason
}

// ErrCannotLeaveAsLeader is returned when attempting to leave cluster as the leader.
type ErrCannotLeaveAsLeader struct{}

func (e ErrCannotLeaveAsLeader) Error() string {
	return "cannot leave cluster as leader without transferring leadership first"
}

// ErrNoSeedReachable is returned when none of the seed addresses are reachable.
type ErrNoSeedReachable struct{}

func (e ErrNoSeedReachable) Error() string {
	return "no seed addresses are reachable"
}

// ErrJoinTimeout is returned when the join operation times out.
type ErrJoinTimeout struct{}

func (e ErrJoinTimeout) Error() string {
	return "join operation timed out"
}

// ErrLeaveTimeout is returned when the leave operation times out.
type ErrLeaveTimeout struct{}

func (e ErrLeaveTimeout) Error() string {
	return "leave operation timed out"
}
