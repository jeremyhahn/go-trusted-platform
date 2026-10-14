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

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ClusterGRPCService implements the gRPC ClusterServiceServer interface.
// It wraps the ClusterService interface to provide gRPC access to cluster operations.
type ClusterGRPCService struct {
	platformv1.UnimplementedClusterServiceServer
	logger  *logging.Logger
	service ClusterService
}

// NewClusterGRPCService creates a new ClusterGRPCService instance.
// Kept with no caller: docs/cluster names it as the real service that replaces the registered daemon stub.
func NewClusterGRPCService(
	logger *logging.Logger,
	service ClusterService,
) *ClusterGRPCService {
	return &ClusterGRPCService{
		logger:  logger,
		service: service,
	}
}

// Bootstrap initializes a new cluster with this node as the initial leader.
func (s *ClusterGRPCService) Bootstrap(
	ctx context.Context,
	req *platformv1.BootstrapClusterRequest,
) (*platformv1.BootstrapClusterResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilClusterService{}.Error())
	}

	if req.GetClusterName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingClusterName{}.Error())
	}

	if req.GetNodeName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingNodeName{}.Error())
	}

	clusterReq := &ClusterBootstrapRequest{
		ClusterName:      req.GetClusterName(),
		NodeName:         req.GetNodeName(),
		BindAddress:      req.GetBindAddress(),
		BindPort:         req.GetBindPort(),
		AdvertiseAddress: req.GetAdvertiseAddress(),
		AdvertisePort:    req.GetAdvertisePort(),
		Labels:           req.GetLabels(),
		Metadata:         req.GetMetadata(),
	}

	resp, err := s.service.Bootstrap(ctx, clusterReq)
	if err != nil {
		return nil, s.mapError("Bootstrap", err)
	}

	return &platformv1.BootstrapClusterResponse{
		Status:  clusterSuccessStatus("cluster bootstrapped successfully"),
		Cluster: clusterInfoToProto(resp.Cluster),
		Node:    clusterNodeToProto(resp.Node),
	}, nil
}

// Join adds this node to an existing cluster.
func (s *ClusterGRPCService) Join(
	ctx context.Context,
	req *platformv1.JoinClusterRequest,
) (*platformv1.JoinClusterResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilClusterService{}.Error())
	}

	if req.GetNodeName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingNodeName{}.Error())
	}

	if len(req.GetSeedAddresses()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSeedAddresses{}.Error())
	}

	clusterReq := &ClusterJoinRequest{
		NodeName:         req.GetNodeName(),
		BindAddress:      req.GetBindAddress(),
		BindPort:         req.GetBindPort(),
		AdvertiseAddress: req.GetAdvertiseAddress(),
		AdvertisePort:    req.GetAdvertisePort(),
		SeedAddresses:    req.GetSeedAddresses(),
		Labels:           req.GetLabels(),
		Metadata:         req.GetMetadata(),
	}

	resp, err := s.service.Join(ctx, clusterReq)
	if err != nil {
		return nil, s.mapError("Join", err)
	}

	return &platformv1.JoinClusterResponse{
		Status:  clusterSuccessStatus("node joined cluster successfully"),
		Cluster: clusterInfoToProto(resp.Cluster),
		Node:    clusterNodeToProto(resp.Node),
	}, nil
}

// Leave gracefully removes this node from the cluster.
func (s *ClusterGRPCService) Leave(
	ctx context.Context,
	req *platformv1.LeaveClusterRequest,
) (*platformv1.LeaveClusterResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilClusterService{}.Error())
	}

	// NodeID can be empty to indicate local node
	clusterReq := &ClusterLeaveRequest{
		NodeID:         req.GetNodeId(),
		Force:          req.GetForce(),
		TimeoutSeconds: req.GetTimeoutSeconds(),
	}

	resp, err := s.service.Leave(ctx, clusterReq)
	if err != nil {
		return nil, s.mapError("Leave", err)
	}

	return &platformv1.LeaveClusterResponse{
		Status: &platformv1.Status{
			Success: resp.Success,
			Message: resp.Message,
		},
	}, nil
}

// GetStatus returns the current cluster status including leader and health.
func (s *ClusterGRPCService) GetStatus(
	ctx context.Context,
	req *platformv1.GetClusterStatusRequest,
) (*platformv1.GetClusterStatusResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilClusterService{}.Error())
	}

	clusterReq := &ClusterGetStatusRequest{
		IncludeNodes: req.GetIncludeNodes(),
	}

	resp, err := s.service.GetStatus(ctx, clusterReq)
	if err != nil {
		return nil, s.mapError("GetStatus", err)
	}

	nodes := make([]*platformv1.ClusterNode, 0, len(resp.Nodes))
	for _, n := range resp.Nodes {
		nodes = append(nodes, clusterNodeToProto(n))
	}

	return &platformv1.GetClusterStatusResponse{
		Cluster:   clusterInfoToProto(resp.Cluster),
		LocalNode: clusterNodeToProto(resp.LocalNode),
		Nodes:     nodes,
		Timestamp: timestamppb.New(time.Unix(resp.Timestamp, 0)),
	}, nil
}

// ListNodes returns all nodes in the cluster with their status.
func (s *ClusterGRPCService) ListNodes(
	ctx context.Context,
	req *platformv1.ListClusterNodesRequest,
) (*platformv1.ListClusterNodesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilClusterService{}.Error())
	}

	roles := make([]NodeRoleType, 0, len(req.GetRoles()))
	for _, r := range req.GetRoles() {
		roles = append(roles, NodeRoleType(r))
	}

	states := make([]NodeStateType, 0, len(req.GetStates()))
	for _, st := range req.GetStates() {
		states = append(states, NodeStateType(st))
	}

	var matchLabels map[string]string
	if req.GetSelector() != nil {
		matchLabels = req.GetSelector().GetMatchLabels()
	}

	var page, pageSize uint32
	var sortBy string
	var ascending bool
	if req.GetPagination() != nil {
		page = req.GetPagination().GetPage()
		pageSize = req.GetPagination().GetPageSize()
		sortBy = req.GetPagination().GetSortBy()
		ascending = req.GetPagination().GetAscending()
	}

	clusterReq := &ClusterListNodesRequest{
		Roles:       roles,
		States:      states,
		MatchLabels: matchLabels,
		Page:        page,
		PageSize:    pageSize,
		SortBy:      sortBy,
		Ascending:   ascending,
	}

	resp, err := s.service.ListNodes(ctx, clusterReq)
	if err != nil {
		return nil, s.mapError("ListNodes", err)
	}

	nodes := make([]*platformv1.ClusterNode, 0, len(resp.Nodes))
	for _, n := range resp.Nodes {
		nodes = append(nodes, clusterNodeToProto(n))
	}

	return &platformv1.ListClusterNodesResponse{
		Nodes: nodes,
		Total: resp.Total,
		Pagination: &platformv1.PaginationResponse{
			Page:       resp.Page,
			PageSize:   resp.PageSize,
			TotalPages: resp.TotalPages,
			TotalItems: resp.TotalItems,
		},
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func clusterSuccessStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func clusterInfoToProto(info *ClusterInfoData) *platformv1.ClusterInfo {
	if info == nil {
		return nil
	}
	return &platformv1.ClusterInfo{
		Id:            info.ID,
		Name:          info.Name,
		State:         platformv1.ClusterState(info.State),
		LeaderId:      info.LeaderID,
		LeaderAddress: info.LeaderAddress,
		TotalNodes:    info.TotalNodes,
		HealthyNodes:  info.HealthyNodes,
		Term:          info.Term,
		CreatedAt:     timestamppb.New(time.Unix(info.CreatedAt, 0)),
		LastElection:  timestamppb.New(time.Unix(info.LastElection, 0)),
		Metadata:      info.Metadata,
	}
}

func clusterNodeToProto(node *ClusterNodeInfo) *platformv1.ClusterNode {
	if node == nil {
		return nil
	}
	return &platformv1.ClusterNode{
		Id:            node.ID,
		Name:          node.Name,
		Address:       node.Address,
		Port:          node.Port,
		Role:          platformv1.NodeRole(node.Role),
		State:         platformv1.NodeState(node.State),
		Health:        platformv1.HealthStatus(node.Health),
		Version:       node.Version,
		JoinedAt:      timestamppb.New(time.Unix(node.JoinedAt, 0)),
		LastHeartbeat: timestamppb.New(time.Unix(node.LastHeartbeat, 0)),
		Labels:        node.Labels,
		Metadata:      node.Metadata,
	}
}

// mapError maps cluster errors to appropriate gRPC status codes.
func (s *ClusterGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "cluster operation failed", "operation", operation)

	// Check for specific cluster error types
	switch e := err.(type) {
	case ErrClusterServiceUnavailable:
		return status.Error(codes.Unavailable, e.Error())
	case ErrLeaveNodeNotLocal:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrUnsupportedNodeSortField:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrClusterNotInitialized:
		return status.Error(codes.FailedPrecondition, e.Error())
	case ErrClusterAlreadyInitialized:
		return status.Error(codes.AlreadyExists, e.Error())
	case ErrNodeAlreadyInCluster:
		return status.Error(codes.AlreadyExists, e.Error())
	case ErrNodeNotInCluster:
		return status.Error(codes.NotFound, e.Error())
	case ErrCannotLeaveAsLeader:
		return status.Error(codes.FailedPrecondition, e.Error())
	case ErrNoSeedReachable:
		return status.Error(codes.Unavailable, e.Error())
	case ErrJoinTimeout:
		return status.Error(codes.DeadlineExceeded, e.Error())
	case ErrLeaveTimeout:
		return status.Error(codes.DeadlineExceeded, e.Error())
	case ErrClusterOperationFailed:
		return status.Errorf(codes.Internal, "cluster operation %s failed: %s", e.Operation, e.Reason)
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// Ensure ClusterGRPCService implements the ClusterServiceServer interface.
var _ platformv1.ClusterServiceServer = (*ClusterGRPCService)(nil)
