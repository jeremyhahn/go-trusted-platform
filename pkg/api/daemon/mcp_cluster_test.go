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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Test fakes
// =============================================================================

// fakeClusterServicer is a hand-rolled ClusterServicer that records calls
// and returns canned data. Hand-rolling beats a mocking framework here:
// the surface is tiny (7 methods) and tests stay readable.
type fakeClusterServicer struct {
	// mu guards clusterCalls: a transport's server goroutine records a call
	// while the test reads it, and a reply over a socket gives the race
	// detector no happens-before edge.
	mu sync.Mutex
	clusterCalls

	statusInfo *ClusterStatusInfo
	statusErr  error

	nodes    *ClusterNodesInfo
	nodesErr error

	bootstrapErr error
	joinErr      error
	leaveErr     error

	leader bool
	nodeID uint64
}

// clusterCalls is what fakeClusterServicer records of the calls it serves.
type clusterCalls struct {
	bootstrapCalled int
	joinCalled      int
	joinAddresses   []string
	leaveCalled     int
	statusCalls     int
	nodeCalls       int
}

// calls returns a copy of the recorded calls, taken under the lock.
func (f *fakeClusterServicer) calls() clusterCalls {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clusterCalls
}

// record runs one call's bookkeeping under the lock.
func (f *fakeClusterServicer) record(note func(*clusterCalls)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	note(&f.clusterCalls)
}

func (f *fakeClusterServicer) Bootstrap(ctx context.Context) error {
	f.record(func(c *clusterCalls) { c.bootstrapCalled++ })
	return f.bootstrapErr
}

func (f *fakeClusterServicer) Join(ctx context.Context, addresses []string) error {
	f.record(func(c *clusterCalls) {
		c.joinCalled++
		c.joinAddresses = append([]string(nil), addresses...)
	})
	return f.joinErr
}

func (f *fakeClusterServicer) Leave(ctx context.Context) error {
	f.record(func(c *clusterCalls) { c.leaveCalled++ })
	return f.leaveErr
}

func (f *fakeClusterServicer) Status(ctx context.Context) (*ClusterStatusInfo, error) {
	f.record(func(c *clusterCalls) { c.statusCalls++ })
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusInfo, nil
}

func (f *fakeClusterServicer) Nodes(ctx context.Context) (*ClusterNodesInfo, error) {
	f.record(func(c *clusterCalls) { c.nodeCalls++ })
	if f.nodesErr != nil {
		return nil, f.nodesErr
	}
	return f.nodes, nil
}

func (f *fakeClusterServicer) IsLeader() bool { return f.leader }
func (f *fakeClusterServicer) NodeID() uint64 { return f.nodeID }

// newProviderWithCluster wires a fake servicer into a fresh
// MCPServiceProvider the way the daemon does: behind the gRPC
// ClusterService servicer the platform_cluster_* tools call.
func newProviderWithCluster(svc ClusterServicer) *MCPServiceProvider {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	p.SetClusterServer(grpcapi.NewClusterGRPCService(logging.DefaultLogger(), newTestClusterBackend(svc)))
	return p
}

// stockStatus returns a canned ClusterStatusInfo for the happy path.
func stockStatus() *ClusterStatusInfo {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	return &ClusterStatusInfo{
		State:        "healthy",
		NodeCount:    3,
		HealthyCount: 3,
		LeaderID:     1,
		Term:         5,
		HasQuorum:    true,
		LastUpdated:  now,
		StartedAt:    now.Add(-time.Hour),
	}
}

// stockNodes returns a canned ClusterNodesInfo with a leader node.
func stockNodes() *ClusterNodesInfo {
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	leader := ClusterNodeInfo{
		ID:          1,
		Address:     "10.0.0.1:7001",
		RaftAddress: "10.0.0.1:7000",
		IsLeader:    true,
		State:       "healthy",
		LastSeen:    now,
		JoinTime:    now.Add(-time.Hour),
		Metadata:    map[string]string{"role": "leader"},
	}
	follower := ClusterNodeInfo{
		ID:       2,
		Address:  "10.0.0.2:7001",
		IsLeader: false,
		State:    "healthy",
		LastSeen: now,
		JoinTime: now.Add(-time.Hour),
	}
	return &ClusterNodesInfo{
		Nodes:  []ClusterNodeInfo{leader, follower},
		Leader: &leader,
		Term:   5,
	}
}

// =============================================================================
// Tests
// =============================================================================

func TestErrClusterNotConfigured_Error(t *testing.T) {
	err := ErrClusterNotConfigured{}
	assert.Equal(t, "cluster service not configured", err.Error())
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// The provider serves the servicer it was given, and nil until then.
func TestMCPServiceProvider_SetClusterServer(t *testing.T) {
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{})
	assert.Nil(t, p.ClusterServiceServer(), "an unwired provider serves a cluster servicer")

	server, _ := registerClusterGRPCService(logging.DefaultLogger())
	p.SetClusterServer(server)
	assert.Same(t, server, p.ClusterServiceServer())

	p.SetClusterServer(nil)
	assert.Nil(t, p.ClusterServiceServer())
}

// The daemon hands its MCP provider the gRPC ClusterService servicer it
// registers, so the tools answer as gRPC does: Unavailable until a cluster
// service is set, the service's answer after.
func TestCreateMCPServer_WiresTheClusterGRPCServicer(t *testing.T) {
	config := testConfig("/tmp/test-mcp-cluster.sock")
	config.EnableMCP = false
	d, err := New(config)
	require.NoError(t, err)
	d.config.MCPConfig = &MCPConfig{Transport: "stdio"}

	_, err = d.createMCPServer()
	require.NoError(t, err)
	server := d.mcpProvider.ClusterServiceServer()
	require.NotNil(t, server, "the MCP cluster tools have no servicer")

	ctx := context.Background()
	_, err = server.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	d.SetClusterService(&fakeClusterServicer{statusInfo: stockStatus()})
	resp, err := server.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), resp.GetCluster().GetTotalNodes())
}
