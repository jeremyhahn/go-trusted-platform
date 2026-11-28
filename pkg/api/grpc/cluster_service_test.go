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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Cluster Service
// =============================================================================

// mockClusterService implements ClusterService for testing
type mockClusterService struct {
	bootstrapFunc func(ctx context.Context, req *ClusterBootstrapRequest) (*ClusterBootstrapResponse, error)
	joinFunc      func(ctx context.Context, req *ClusterJoinRequest) (*ClusterJoinResponse, error)
	leaveFunc     func(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error)
	getStatusFunc func(ctx context.Context, req *ClusterGetStatusRequest) (*ClusterGetStatusResponse, error)
	listNodesFunc func(ctx context.Context, req *ClusterListNodesRequest) (*ClusterListNodesResponse, error)
}

func (m *mockClusterService) Bootstrap(ctx context.Context, req *ClusterBootstrapRequest) (*ClusterBootstrapResponse, error) {
	if m.bootstrapFunc != nil {
		return m.bootstrapFunc(ctx, req)
	}
	return &ClusterBootstrapResponse{
		Cluster: &ClusterInfoData{
			ID:           "cluster-123",
			Name:         req.ClusterName,
			State:        ClusterStateHealthy,
			LeaderID:     "node-1",
			TotalNodes:   1,
			HealthyNodes: 1,
			CreatedAt:    time.Now().Unix(),
		},
		Node: &ClusterNodeInfo{
			ID:      "node-1",
			Name:    req.NodeName,
			Address: req.BindAddress,
			Port:    req.BindPort,
			Role:    NodeRoleLeader,
			State:   NodeStateActive,
			Health:  HealthStatusHealthy,
		},
	}, nil
}

func (m *mockClusterService) Join(ctx context.Context, req *ClusterJoinRequest) (*ClusterJoinResponse, error) {
	if m.joinFunc != nil {
		return m.joinFunc(ctx, req)
	}
	return &ClusterJoinResponse{
		Cluster: &ClusterInfoData{
			ID:           "cluster-123",
			Name:         "test-cluster",
			State:        ClusterStateHealthy,
			LeaderID:     "node-1",
			TotalNodes:   2,
			HealthyNodes: 2,
		},
		Node: &ClusterNodeInfo{
			ID:      "node-2",
			Name:    req.NodeName,
			Address: req.BindAddress,
			Port:    req.BindPort,
			Role:    NodeRoleFollower,
			State:   NodeStateActive,
			Health:  HealthStatusHealthy,
		},
	}, nil
}

func (m *mockClusterService) Leave(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error) {
	if m.leaveFunc != nil {
		return m.leaveFunc(ctx, req)
	}
	return &ClusterLeaveResponse{
		Success: true,
		Message: "node left cluster successfully",
	}, nil
}

func (m *mockClusterService) GetStatus(ctx context.Context, req *ClusterGetStatusRequest) (*ClusterGetStatusResponse, error) {
	if m.getStatusFunc != nil {
		return m.getStatusFunc(ctx, req)
	}
	nodes := []*ClusterNodeInfo{
		{
			ID:      "node-1",
			Name:    "leader-node",
			Address: "192.168.1.1",
			Port:    7946,
			Role:    NodeRoleLeader,
			State:   NodeStateActive,
			Health:  HealthStatusHealthy,
		},
	}
	if req.IncludeNodes {
		nodes = append(nodes, &ClusterNodeInfo{
			ID:      "node-2",
			Name:    "follower-node",
			Address: "192.168.1.2",
			Port:    7946,
			Role:    NodeRoleFollower,
			State:   NodeStateActive,
			Health:  HealthStatusHealthy,
		})
	}
	return &ClusterGetStatusResponse{
		Cluster: &ClusterInfoData{
			ID:           "cluster-123",
			Name:         "test-cluster",
			State:        ClusterStateHealthy,
			LeaderID:     "node-1",
			TotalNodes:   uint32(len(nodes)),
			HealthyNodes: uint32(len(nodes)),
		},
		LocalNode: nodes[0],
		Nodes:     nodes,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (m *mockClusterService) ListNodes(ctx context.Context, req *ClusterListNodesRequest) (*ClusterListNodesResponse, error) {
	if m.listNodesFunc != nil {
		return m.listNodesFunc(ctx, req)
	}
	return &ClusterListNodesResponse{
		Nodes: []*ClusterNodeInfo{
			{
				ID:      "node-1",
				Name:    "leader-node",
				Address: "192.168.1.1",
				Port:    7946,
				Role:    NodeRoleLeader,
				State:   NodeStateActive,
				Health:  HealthStatusHealthy,
			},
			{
				ID:      "node-2",
				Name:    "follower-node",
				Address: "192.168.1.2",
				Port:    7946,
				Role:    NodeRoleFollower,
				State:   NodeStateActive,
				Health:  HealthStatusHealthy,
			},
		},
		Total:      2,
		Page:       1,
		PageSize:   10,
		TotalPages: 1,
		TotalItems: 2,
	}, nil
}

// =============================================================================
// NewClusterGRPCService Tests
// =============================================================================

func TestNewClusterGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	mock := &mockClusterService{}

	svc := NewClusterGRPCService(logger, mock)

	require.NotNil(t, svc)
	assert.Equal(t, logger, svc.logger)
	assert.Equal(t, mock, svc.service)
}

// =============================================================================
// Bootstrap Tests
// =============================================================================

func TestClusterGRPCService_Bootstrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    ClusterService
		req        *platformv1.BootstrapClusterRequest
		wantCode   codes.Code
		wantErr    bool
		validateFn func(t *testing.T, resp *platformv1.BootstrapClusterResponse)
	}{
		{
			name:    "nil service returns FailedPrecondition",
			service: nil,
			req: &platformv1.BootstrapClusterRequest{
				ClusterName: "test-cluster",
				NodeName:    "node-1",
			},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name:    "missing cluster name returns InvalidArgument",
			service: &mockClusterService{},
			req: &platformv1.BootstrapClusterRequest{
				NodeName: "node-1",
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name:    "missing node name returns InvalidArgument",
			service: &mockClusterService{},
			req: &platformv1.BootstrapClusterRequest{
				ClusterName: "test-cluster",
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name:    "successful bootstrap",
			service: &mockClusterService{},
			req: &platformv1.BootstrapClusterRequest{
				ClusterName:      "test-cluster",
				NodeName:         "node-1",
				BindAddress:      "0.0.0.0",
				BindPort:         7946,
				AdvertiseAddress: "192.168.1.1",
				AdvertisePort:    7946,
				Labels:           map[string]string{"env": "test"},
				Metadata:         map[string]string{"region": "us-west"},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.BootstrapClusterResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Status)
				assert.True(t, resp.Status.Success)
				require.NotNil(t, resp.Cluster)
				assert.Equal(t, "test-cluster", resp.Cluster.Name)
				require.NotNil(t, resp.Node)
				assert.Equal(t, "node-1", resp.Node.Name)
			},
		},
		{
			name: "service error returns mapped error",
			service: &mockClusterService{
				bootstrapFunc: func(ctx context.Context, req *ClusterBootstrapRequest) (*ClusterBootstrapResponse, error) {
					return nil, ErrClusterAlreadyInitialized{}
				},
			},
			req: &platformv1.BootstrapClusterRequest{
				ClusterName: "test-cluster",
				NodeName:    "node-1",
			},
			wantCode: codes.AlreadyExists,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			svc := NewClusterGRPCService(logger, tt.service)

			resp, err := svc.Bootstrap(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateFn != nil {
					tt.validateFn(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// Join Tests
// =============================================================================

func TestClusterGRPCService_Join(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    ClusterService
		req        *platformv1.JoinClusterRequest
		wantCode   codes.Code
		wantErr    bool
		validateFn func(t *testing.T, resp *platformv1.JoinClusterResponse)
	}{
		{
			name:    "nil service returns FailedPrecondition",
			service: nil,
			req: &platformv1.JoinClusterRequest{
				NodeName:      "node-2",
				SeedAddresses: []string{"192.168.1.1:7946"},
			},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name:    "missing node name returns InvalidArgument",
			service: &mockClusterService{},
			req: &platformv1.JoinClusterRequest{
				SeedAddresses: []string{"192.168.1.1:7946"},
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name:    "missing seed addresses returns InvalidArgument",
			service: &mockClusterService{},
			req: &platformv1.JoinClusterRequest{
				NodeName: "node-2",
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name:    "empty seed addresses returns InvalidArgument",
			service: &mockClusterService{},
			req: &platformv1.JoinClusterRequest{
				NodeName:      "node-2",
				SeedAddresses: []string{},
			},
			wantCode: codes.InvalidArgument,
			wantErr:  true,
		},
		{
			name:    "successful join",
			service: &mockClusterService{},
			req: &platformv1.JoinClusterRequest{
				NodeName:         "node-2",
				BindAddress:      "0.0.0.0",
				BindPort:         7946,
				AdvertiseAddress: "192.168.1.2",
				AdvertisePort:    7946,
				SeedAddresses:    []string{"192.168.1.1:7946"},
				Labels:           map[string]string{"env": "test"},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.JoinClusterResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Status)
				assert.True(t, resp.Status.Success)
				require.NotNil(t, resp.Cluster)
				assert.Equal(t, uint32(2), resp.Cluster.TotalNodes)
				require.NotNil(t, resp.Node)
				assert.Equal(t, "node-2", resp.Node.Name)
			},
		},
		{
			name: "no seed reachable returns Unavailable",
			service: &mockClusterService{
				joinFunc: func(ctx context.Context, req *ClusterJoinRequest) (*ClusterJoinResponse, error) {
					return nil, ErrNoSeedReachable{}
				},
			},
			req: &platformv1.JoinClusterRequest{
				NodeName:      "node-2",
				SeedAddresses: []string{"192.168.1.1:7946"},
			},
			wantCode: codes.Unavailable,
			wantErr:  true,
		},
		{
			name: "join timeout returns DeadlineExceeded",
			service: &mockClusterService{
				joinFunc: func(ctx context.Context, req *ClusterJoinRequest) (*ClusterJoinResponse, error) {
					return nil, ErrJoinTimeout{}
				},
			},
			req: &platformv1.JoinClusterRequest{
				NodeName:      "node-2",
				SeedAddresses: []string{"192.168.1.1:7946"},
			},
			wantCode: codes.DeadlineExceeded,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			svc := NewClusterGRPCService(logger, tt.service)

			resp, err := svc.Join(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateFn != nil {
					tt.validateFn(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// Leave Tests
// =============================================================================

func TestClusterGRPCService_Leave(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    ClusterService
		req        *platformv1.LeaveClusterRequest
		wantCode   codes.Code
		wantErr    bool
		validateFn func(t *testing.T, resp *platformv1.LeaveClusterResponse)
	}{
		{
			name:     "nil service returns FailedPrecondition",
			service:  nil,
			req:      &platformv1.LeaveClusterRequest{},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name:    "successful leave with local node",
			service: &mockClusterService{},
			req: &platformv1.LeaveClusterRequest{
				Force: false,
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.LeaveClusterResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Status)
				assert.True(t, resp.Status.Success)
			},
		},
		{
			name:    "successful leave with specific node",
			service: &mockClusterService{},
			req: &platformv1.LeaveClusterRequest{
				NodeId:         "node-2",
				Force:          true,
				TimeoutSeconds: 30,
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.LeaveClusterResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Status)
				assert.True(t, resp.Status.Success)
			},
		},
		{
			name: "cannot leave as leader",
			service: &mockClusterService{
				leaveFunc: func(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error) {
					return nil, ErrCannotLeaveAsLeader{}
				},
			},
			req:      &platformv1.LeaveClusterRequest{},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name: "leave timeout returns DeadlineExceeded",
			service: &mockClusterService{
				leaveFunc: func(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error) {
					return nil, ErrLeaveTimeout{}
				},
			},
			req:      &platformv1.LeaveClusterRequest{},
			wantCode: codes.DeadlineExceeded,
			wantErr:  true,
		},
		{
			name: "node not in cluster returns NotFound",
			service: &mockClusterService{
				leaveFunc: func(ctx context.Context, req *ClusterLeaveRequest) (*ClusterLeaveResponse, error) {
					return nil, ErrNodeNotInCluster{}
				},
			},
			req: &platformv1.LeaveClusterRequest{
				NodeId: "nonexistent-node",
			},
			wantCode: codes.NotFound,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			svc := NewClusterGRPCService(logger, tt.service)

			resp, err := svc.Leave(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateFn != nil {
					tt.validateFn(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// GetStatus Tests
// =============================================================================

func TestClusterGRPCService_GetStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    ClusterService
		req        *platformv1.GetClusterStatusRequest
		wantCode   codes.Code
		wantErr    bool
		validateFn func(t *testing.T, resp *platformv1.GetClusterStatusResponse)
	}{
		{
			name:     "nil service returns FailedPrecondition",
			service:  nil,
			req:      &platformv1.GetClusterStatusRequest{},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name:    "successful get status without nodes",
			service: &mockClusterService{},
			req: &platformv1.GetClusterStatusRequest{
				IncludeNodes: false,
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.GetClusterStatusResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Cluster)
				assert.Equal(t, "cluster-123", resp.Cluster.Id)
				assert.Equal(t, "test-cluster", resp.Cluster.Name)
				require.NotNil(t, resp.LocalNode)
				require.NotNil(t, resp.Timestamp)
			},
		},
		{
			name:    "successful get status with nodes",
			service: &mockClusterService{},
			req: &platformv1.GetClusterStatusRequest{
				IncludeNodes: true,
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.GetClusterStatusResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Cluster)
				require.NotNil(t, resp.LocalNode)
				assert.GreaterOrEqual(t, len(resp.Nodes), 1)
			},
		},
		{
			name: "cluster not initialized returns FailedPrecondition",
			service: &mockClusterService{
				getStatusFunc: func(ctx context.Context, req *ClusterGetStatusRequest) (*ClusterGetStatusResponse, error) {
					return nil, ErrClusterNotInitialized{}
				},
			},
			req:      &platformv1.GetClusterStatusRequest{},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			svc := NewClusterGRPCService(logger, tt.service)

			resp, err := svc.GetStatus(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateFn != nil {
					tt.validateFn(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// ListNodes Tests
// =============================================================================

func TestClusterGRPCService_ListNodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		service    ClusterService
		req        *platformv1.ListClusterNodesRequest
		wantCode   codes.Code
		wantErr    bool
		validateFn func(t *testing.T, resp *platformv1.ListClusterNodesResponse)
	}{
		{
			name:     "nil service returns FailedPrecondition",
			service:  nil,
			req:      &platformv1.ListClusterNodesRequest{},
			wantCode: codes.FailedPrecondition,
			wantErr:  true,
		},
		{
			name:     "successful list nodes without filters",
			service:  &mockClusterService{},
			req:      &platformv1.ListClusterNodesRequest{},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.ListClusterNodesResponse) {
				require.NotNil(t, resp)
				assert.Equal(t, uint32(2), resp.Total)
				assert.Len(t, resp.Nodes, 2)
				require.NotNil(t, resp.Pagination)
			},
		},
		{
			name:    "list with role filter",
			service: &mockClusterService{},
			req: &platformv1.ListClusterNodesRequest{
				Roles: []platformv1.NodeRole{platformv1.NodeRole_NODE_ROLE_LEADER},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.ListClusterNodesResponse) {
				require.NotNil(t, resp)
				assert.NotNil(t, resp.Nodes)
			},
		},
		{
			name:    "list with state filter",
			service: &mockClusterService{},
			req: &platformv1.ListClusterNodesRequest{
				States: []platformv1.NodeState{platformv1.NodeState_NODE_STATE_ACTIVE},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.ListClusterNodesResponse) {
				require.NotNil(t, resp)
				assert.NotNil(t, resp.Nodes)
			},
		},
		{
			name:    "list with selector",
			service: &mockClusterService{},
			req: &platformv1.ListClusterNodesRequest{
				Selector: &platformv1.LabelSelector{
					MatchLabels: map[string]string{"env": "production"},
				},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.ListClusterNodesResponse) {
				require.NotNil(t, resp)
			},
		},
		{
			name:    "list with pagination",
			service: &mockClusterService{},
			req: &platformv1.ListClusterNodesRequest{
				Pagination: &platformv1.PaginationRequest{
					Page:      1,
					PageSize:  10,
					SortBy:    "name",
					Ascending: true,
				},
			},
			wantCode: codes.OK,
			wantErr:  false,
			validateFn: func(t *testing.T, resp *platformv1.ListClusterNodesResponse) {
				require.NotNil(t, resp)
				require.NotNil(t, resp.Pagination)
				assert.Equal(t, uint32(1), resp.Pagination.Page)
				assert.Equal(t, uint32(10), resp.Pagination.PageSize)
			},
		},
		{
			name: "service error returns Internal",
			service: &mockClusterService{
				listNodesFunc: func(ctx context.Context, req *ClusterListNodesRequest) (*ClusterListNodesResponse, error) {
					return nil, errors.New("internal error")
				},
			},
			req:      &platformv1.ListClusterNodesRequest{},
			wantCode: codes.Internal,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			svc := NewClusterGRPCService(logger, tt.service)

			resp, err := svc.ListNodes(context.Background(), tt.req)

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			} else {
				require.NoError(t, err)
				if tt.validateFn != nil {
					tt.validateFn(t, resp)
				}
			}
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestClusterInfoToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil info returns nil", func(t *testing.T) {
		result := clusterInfoToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid info converts correctly", func(t *testing.T) {
		now := time.Now().Unix()
		info := &ClusterInfoData{
			ID:            "cluster-123",
			Name:          "test-cluster",
			State:         ClusterStateHealthy,
			LeaderID:      "node-1",
			LeaderAddress: "192.168.1.1:7946",
			TotalNodes:    3,
			HealthyNodes:  3,
			Term:          5,
			CreatedAt:     now,
			LastElection:  now,
			Metadata:      map[string]string{"key": "value"},
		}

		result := clusterInfoToProto(info)

		require.NotNil(t, result)
		assert.Equal(t, "cluster-123", result.Id)
		assert.Equal(t, "test-cluster", result.Name)
		assert.Equal(t, platformv1.ClusterState(ClusterStateHealthy), result.State)
		assert.Equal(t, "node-1", result.LeaderId)
		assert.Equal(t, "192.168.1.1:7946", result.LeaderAddress)
		assert.Equal(t, uint32(3), result.TotalNodes)
		assert.Equal(t, uint32(3), result.HealthyNodes)
		assert.Equal(t, uint64(5), result.Term)
		assert.NotNil(t, result.CreatedAt)
		assert.NotNil(t, result.LastElection)
		assert.Equal(t, "value", result.Metadata["key"])
	})
}

func TestClusterNodeToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil node returns nil", func(t *testing.T) {
		result := clusterNodeToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("valid node converts correctly", func(t *testing.T) {
		now := time.Now().Unix()
		node := &ClusterNodeInfo{
			ID:            "node-1",
			Name:          "leader-node",
			Address:       "192.168.1.1",
			Port:          7946,
			Role:          NodeRoleLeader,
			State:         NodeStateActive,
			Health:        HealthStatusHealthy,
			Version:       "1.0.0",
			JoinedAt:      now,
			LastHeartbeat: now,
			Labels:        map[string]string{"env": "prod"},
			Metadata:      map[string]string{"zone": "us-west"},
		}

		result := clusterNodeToProto(node)

		require.NotNil(t, result)
		assert.Equal(t, "node-1", result.Id)
		assert.Equal(t, "leader-node", result.Name)
		assert.Equal(t, "192.168.1.1", result.Address)
		assert.Equal(t, uint32(7946), result.Port)
		assert.Equal(t, platformv1.NodeRole(NodeRoleLeader), result.Role)
		assert.Equal(t, platformv1.NodeState(NodeStateActive), result.State)
		assert.Equal(t, platformv1.HealthStatus(HealthStatusHealthy), result.Health)
		assert.Equal(t, "1.0.0", result.Version)
		assert.NotNil(t, result.JoinedAt)
		assert.NotNil(t, result.LastHeartbeat)
		assert.Equal(t, "prod", result.Labels["env"])
		assert.Equal(t, "us-west", result.Metadata["zone"])
	})
}

func TestClusterSuccessStatus(t *testing.T) {
	t.Parallel()

	msg := "operation completed"
	result := clusterSuccessStatus(msg)

	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Equal(t, msg, result.Message)
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestClusterGRPCService_MapError(t *testing.T) {
	t.Parallel()

	logger := logging.DefaultLogger()
	svc := NewClusterGRPCService(logger, &mockClusterService{})

	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "nil error returns nil",
			err:      nil,
			wantCode: codes.OK,
		},
		{
			name:     "ErrClusterServiceUnavailable returns Unavailable",
			err:      ErrClusterServiceUnavailable{},
			wantCode: codes.Unavailable,
		},
		{
			name:     "ErrLeaveNodeNotLocal returns InvalidArgument",
			err:      ErrLeaveNodeNotLocal{NodeID: "2", LocalNodeID: "1"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "ErrUnsupportedNodeSortField returns InvalidArgument",
			err:      ErrUnsupportedNodeSortField{Field: "uptime"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "ErrClusterNotInitialized returns FailedPrecondition",
			err:      ErrClusterNotInitialized{},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "ErrClusterAlreadyInitialized returns AlreadyExists",
			err:      ErrClusterAlreadyInitialized{},
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "ErrNodeAlreadyInCluster returns AlreadyExists",
			err:      ErrNodeAlreadyInCluster{},
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "ErrNodeNotInCluster returns NotFound",
			err:      ErrNodeNotInCluster{},
			wantCode: codes.NotFound,
		},
		{
			name:     "ErrCannotLeaveAsLeader returns FailedPrecondition",
			err:      ErrCannotLeaveAsLeader{},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "ErrNoSeedReachable returns Unavailable",
			err:      ErrNoSeedReachable{},
			wantCode: codes.Unavailable,
		},
		{
			name:     "ErrJoinTimeout returns DeadlineExceeded",
			err:      ErrJoinTimeout{},
			wantCode: codes.DeadlineExceeded,
		},
		{
			name:     "ErrLeaveTimeout returns DeadlineExceeded",
			err:      ErrLeaveTimeout{},
			wantCode: codes.DeadlineExceeded,
		},
		{
			name: "ErrClusterOperationFailed returns Internal",
			err: ErrClusterOperationFailed{
				Operation: "test-op",
				Reason:    "test reason",
			},
			wantCode: codes.Internal,
		},
		{
			name:     "generic error returns Internal",
			err:      errors.New("unknown error"),
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.mapError("test", tt.err)

			if tt.err == nil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				st, ok := status.FromError(result)
				require.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
			}
		})
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestClusterErrorTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ErrNilClusterService",
			err:  ErrNilClusterService{},
			want: "cluster service is nil",
		},
		{
			name: "ErrClusterNotInitialized",
			err:  ErrClusterNotInitialized{},
			want: "cluster is not initialized",
		},
		{
			name: "ErrClusterAlreadyInitialized",
			err:  ErrClusterAlreadyInitialized{},
			want: "cluster is already initialized",
		},
		{
			name: "ErrNodeAlreadyInCluster",
			err:  ErrNodeAlreadyInCluster{},
			want: "node is already a member of the cluster",
		},
		{
			name: "ErrNodeNotInCluster",
			err:  ErrNodeNotInCluster{},
			want: "node is not a member of the cluster",
		},
		{
			name: "ErrMissingClusterName",
			err:  ErrMissingClusterName{},
			want: "cluster name is required",
		},
		{
			name: "ErrMissingNodeName",
			err:  ErrMissingNodeName{},
			want: "node name is required",
		},
		{
			name: "ErrMissingSeedAddresses",
			err:  ErrMissingSeedAddresses{},
			want: "at least one seed address is required",
		},
		{
			name: "ErrMissingNodeID",
			err:  ErrMissingNodeID{},
			want: "node ID is required",
		},
		{
			name: "ErrClusterOperationFailed",
			err: ErrClusterOperationFailed{
				Operation: "bootstrap",
				Reason:    "network error",
			},
			want: "cluster operation bootstrap failed: network error",
		},
		{
			name: "ErrCannotLeaveAsLeader",
			err:  ErrCannotLeaveAsLeader{},
			want: "cannot leave cluster as leader without transferring leadership first",
		},
		{
			name: "ErrNoSeedReachable",
			err:  ErrNoSeedReachable{},
			want: "no seed addresses are reachable",
		},
		{
			name: "ErrJoinTimeout",
			err:  ErrJoinTimeout{},
			want: "join operation timed out",
		},
		{
			name: "ErrLeaveTimeout",
			err:  ErrLeaveTimeout{},
			want: "leave operation timed out",
		},
		{
			name: "ErrClusterServiceUnavailable",
			err:  ErrClusterServiceUnavailable{},
			want: "cluster service not configured",
		},
		{
			name: "ErrLeaveNodeNotLocal",
			err:  ErrLeaveNodeNotLocal{NodeID: "2", LocalNodeID: "1"},
			want: "leave removes the serving node 1, not node 2; send the leave request to node 2",
		},
		{
			name: "ErrUnsupportedNodeSortField",
			err:  ErrUnsupportedNodeSortField{Field: "uptime"},
			want: "unsupported node sort field: uptime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}
