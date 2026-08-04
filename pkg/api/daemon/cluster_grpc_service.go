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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ClusterGRPCService implements the Cluster gRPC service for cluster
// lifecycle operations including bootstrap, join, leave, status, and
// node listing. This stub returns Unimplemented for all methods until
// the full cluster coordinator is wired in.
type ClusterGRPCService struct {
	platformv1.UnimplementedClusterServiceServer

	logger *logging.Logger
}

// NewClusterGRPCService creates a new Cluster gRPC service instance.
func NewClusterGRPCService(logger *logging.Logger) *ClusterGRPCService {
	return &ClusterGRPCService{
		logger: logger,
	}
}

// clusterNotImplemented returns the standard error for unimplemented operations.
func (s *ClusterGRPCService) clusterNotImplemented(method string) error {
	return status.Errorf(codes.Unimplemented, "cluster: %s not implemented", method)
}

// Bootstrap initializes a new cluster with this node as the initial leader.
func (s *ClusterGRPCService) Bootstrap(
	ctx context.Context,
	req *platformv1.BootstrapClusterRequest,
) (*platformv1.BootstrapClusterResponse, error) {
	return nil, s.clusterNotImplemented("Bootstrap")
}

// Join adds this node to an existing cluster.
func (s *ClusterGRPCService) Join(
	ctx context.Context,
	req *platformv1.JoinClusterRequest,
) (*platformv1.JoinClusterResponse, error) {
	return nil, s.clusterNotImplemented("Join")
}

// Leave gracefully removes this node from the cluster.
func (s *ClusterGRPCService) Leave(
	ctx context.Context,
	req *platformv1.LeaveClusterRequest,
) (*platformv1.LeaveClusterResponse, error) {
	return nil, s.clusterNotImplemented("Leave")
}

// GetStatus returns the current cluster status including leader and health.
func (s *ClusterGRPCService) GetStatus(
	ctx context.Context,
	req *platformv1.GetClusterStatusRequest,
) (*platformv1.GetClusterStatusResponse, error) {
	return nil, s.clusterNotImplemented("GetStatus")
}

// ListNodes returns all nodes in the cluster with their status.
func (s *ClusterGRPCService) ListNodes(
	ctx context.Context,
	req *platformv1.ListClusterNodesRequest,
) (*platformv1.ListClusterNodesResponse, error) {
	return nil, s.clusterNotImplemented("ListNodes")
}
