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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// ClusterBinding exposes cluster service methods to the Wails frontend.
type ClusterBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewClusterBinding creates a new ClusterBinding.
func NewClusterBinding(logger *slog.Logger, conn *ConnectionBinding) *ClusterBinding {
	return &ClusterBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *ClusterBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// Bootstrap initializes a new cluster with this node as the initial leader.
func (b *ClusterBinding) Bootstrap(clusterName string, nodeName string, bindAddress string, bindPort uint32, advertiseAddress string, advertisePort uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Cluster().Bootstrap(b.conn.ctx, &platformv1.BootstrapClusterRequest{
		ClusterName:      clusterName,
		NodeName:         nodeName,
		BindAddress:      bindAddress,
		BindPort:         bindPort,
		AdvertiseAddress: advertiseAddress,
		AdvertisePort:    advertisePort,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Join adds this node to an existing cluster.
func (b *ClusterBinding) Join(nodeName string, bindAddress string, bindPort uint32, advertiseAddress string, advertisePort uint32, seedAddresses []string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Cluster().Join(b.conn.ctx, &platformv1.JoinClusterRequest{
		NodeName:         nodeName,
		BindAddress:      bindAddress,
		BindPort:         bindPort,
		AdvertiseAddress: advertiseAddress,
		AdvertisePort:    advertisePort,
		SeedAddresses:    seedAddresses,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Leave gracefully removes this node from the cluster.
func (b *ClusterBinding) Leave(nodeID string, force bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Cluster().Leave(b.conn.ctx, &platformv1.LeaveClusterRequest{
		NodeId: nodeID,
		Force:  force,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetStatus returns the current cluster status including leader and health.
func (b *ClusterBinding) GetStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Cluster().GetStatus(b.conn.ctx, &platformv1.GetClusterStatusRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListNodes returns all nodes in the cluster with their status.
func (b *ClusterBinding) ListNodes() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.Cluster().ListNodes(b.conn.ctx, &platformv1.ListClusterNodesRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
