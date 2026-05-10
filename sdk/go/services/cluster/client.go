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

// Package cluster provides a client for cluster service operations.
package cluster

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to cluster service operations.
type Client struct {
	grpc platformv1.ClusterServiceClient
}

// NewClient creates a new cluster service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewClusterServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new cluster service client from a gRPC client.
func NewClientFromGRPC(grpcClient platformv1.ClusterServiceClient) *Client {
	return &Client{grpc: grpcClient}
}

// GetStatusDomain retrieves cluster status and returns domain types.
func (c *Client) GetStatusDomain(ctx context.Context, includeNodes bool) (*StatusResponse, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetClusterStatusRequest{
		IncludeNodes: includeNodes,
	})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}

	status := &StatusResponse{}

	if resp.GetCluster() != nil {
		cluster := resp.GetCluster()
		status.ClusterID = cluster.GetId()
		status.LeaderID = cluster.GetLeaderId()
		status.LeaderAddr = cluster.GetLeaderAddress()
		status.Term = cluster.GetTerm()
		status.TotalNodes = cluster.GetTotalNodes()
		status.HealthyNodes = cluster.GetHealthyNodes()
		status.State = ClusterStateFromProto(cluster.GetState())
	}

	if resp.GetLocalNode() != nil {
		localNode := resp.GetLocalNode()
		status.LocalNodeID = localNode.GetId()
		status.LocalRole = NodeRoleFromProto(localNode.GetRole())
		if localNode.GetLastHeartbeat() != nil {
			t := localNode.GetLastHeartbeat().AsTime()
			status.LastHeartbeat = &t
		}
	}

	if resp.GetTimestamp() != nil {
		status.Timestamp = resp.GetTimestamp().AsTime()
	}

	return status, nil
}

// ListNodesDomain lists cluster nodes and returns domain types.
func (c *Client) ListNodesDomain(ctx context.Context) (*ListNodesResponse, error) {
	resp, err := c.grpc.ListNodes(ctx, &platformv1.ListClusterNodesRequest{})
	if err != nil {
		return nil, &ErrListNodesFailed{Cause: err}
	}

	result := &ListNodesResponse{Total: resp.GetTotal()}
	for _, node := range resp.GetNodes() {
		info := &NodeInfo{
			ID:      node.GetId(),
			Address: node.GetAddress(),
			Port:    node.GetPort(),
			Role:    NodeRoleFromProto(node.GetRole()),
			State:   NodeStateFromProto(node.GetState()),
		}
		if node.GetLastHeartbeat() != nil {
			t := node.GetLastHeartbeat().AsTime()
			info.LastHeartbeat = &t
		}
		if node.GetJoinedAt() != nil {
			t := node.GetJoinedAt().AsTime()
			info.JoinedAt = &t
		}
		result.Nodes = append(result.Nodes, info)
	}

	return result, nil
}

// BootstrapDomain bootstraps a new cluster and returns domain types.
func (c *Client) BootstrapDomain(ctx context.Context, clusterName, nodeName, bindAddr string, bindPort uint32, advAddr string, advPort uint32) (*BootstrapResponse, error) {
	resp, err := c.grpc.Bootstrap(ctx, &platformv1.BootstrapClusterRequest{
		ClusterName:      clusterName,
		NodeName:         nodeName,
		BindAddress:      bindAddr,
		BindPort:         bindPort,
		AdvertiseAddress: advAddr,
		AdvertisePort:    advPort,
	})
	if err != nil {
		return nil, &ErrBootstrapFailed{Cause: err}
	}

	result := &BootstrapResponse{}
	if resp.GetCluster() != nil {
		result.ClusterID = resp.GetCluster().GetId()
	}
	if resp.GetNode() != nil {
		result.NodeID = resp.GetNode().GetId()
	}
	if resp.GetStatus() != nil && resp.GetStatus().GetMessage() != "" {
		result.Message = resp.GetStatus().GetMessage()
	}
	return result, nil
}

// JoinDomain joins a cluster and returns domain types.
func (c *Client) JoinDomain(ctx context.Context, nodeName, bindAddr string, bindPort uint32, advAddr string, advPort uint32, seedAddrs []string) (*JoinResponse, error) {
	resp, err := c.grpc.Join(ctx, &platformv1.JoinClusterRequest{
		NodeName:         nodeName,
		BindAddress:      bindAddr,
		BindPort:         bindPort,
		AdvertiseAddress: advAddr,
		AdvertisePort:    advPort,
		SeedAddresses:    seedAddrs,
	})
	if err != nil {
		return nil, &ErrJoinFailed{Cause: err}
	}

	result := &JoinResponse{}
	if resp.GetCluster() != nil {
		result.ClusterID = resp.GetCluster().GetId()
		result.LeaderID = resp.GetCluster().GetLeaderId()
		result.LeaderAddr = resp.GetCluster().GetLeaderAddress()
	}
	if resp.GetNode() != nil {
		result.NodeID = resp.GetNode().GetId()
	}
	if resp.GetStatus() != nil && resp.GetStatus().GetMessage() != "" {
		result.Message = resp.GetStatus().GetMessage()
	}
	return result, nil
}

// LeaveDomain leaves the cluster and returns domain types.
func (c *Client) LeaveDomain(ctx context.Context, nodeID string, force bool, timeoutSeconds uint32) (*LeaveResponse, error) {
	resp, err := c.grpc.Leave(ctx, &platformv1.LeaveClusterRequest{
		NodeId:         nodeID,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return nil, &ErrLeaveFailed{Cause: err}
	}

	result := &LeaveResponse{}
	if resp.GetStatus() != nil && resp.GetStatus().GetMessage() != "" {
		result.Message = resp.GetStatus().GetMessage()
	}
	if result.Message == "" {
		if force {
			result.Message = "Force left cluster (immediate)"
		} else {
			result.Message = "Successfully left cluster"
		}
	}
	return result, nil
}

// IsLeader returns true if the given role is the leader role.
func IsLeader(role NodeRole) bool {
	return role == NodeRoleLeader
}

// IsVoter returns true if the given role participates in consensus.
func IsVoter(role NodeRole) bool {
	return role != NodeRoleObserver && role != NodeRoleUnknown
}

// FormatAddress formats a host and port into an address string.
func FormatAddress(host string, port uint32) string {
	return fmt.Sprintf("%s:%d", host, port)
}
