// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Registered service: what the daemon serves on gRPC and the Unix socket
// =============================================================================

// runningStatus is stockStatus in the coordinator's "running" state
// (pkg/cluster ClusterStateRunning), which the adapter reports verbatim.
func runningStatus() *ClusterStatusInfo {
	st := stockStatus()
	st.State = "running"
	return st
}

// serveRegisteredClusterGRPC registers the daemon's cluster service the way
// New does — on a TCP-listener server and a Unix-socket server — and returns
// a client per transport plus the backend Daemon.SetClusterService drives.
// The TCP server speaks TLS with the shared self-signed test certificate as
// the client's only root; the Unix server uses local credentials, which
// refuse a non-local peer. Neither half dials in plaintext.
func serveRegisteredClusterGRPC(t *testing.T) (map[string]platformv1.ClusterServiceClient, *clusterGRPCBackend) {
	t.Helper()
	cert := sharedTestTLSCertificate()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	tcpServer := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	udsServer := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	_, backend := registerClusterGRPCService(logging.DefaultLogger(), tcpServer, udsServer)

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	udsListener, err := net.Listen("unix", filepath.Join(t.TempDir(), "cluster.sock"))
	require.NoError(t, err)

	clients := map[string]platformv1.ClusterServiceClient{
		"gRPC": dialClusterGRPC(t, tcpServer, tcpListener, tcpListener.Addr().String(),
			credentials.NewTLS(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13})),
		"Unix": dialClusterGRPC(t, udsServer, udsListener, "unix://"+udsListener.Addr().String(),
			local.NewCredentials()),
	}
	return clients, backend
}

// dialClusterGRPC serves server on lis until the test ends and returns a
// cluster client dialled to target with creds.
func dialClusterGRPC(t *testing.T, server *grpc.Server, lis net.Listener, target string, creds credentials.TransportCredentials) platformv1.ClusterServiceClient {
	t.Helper()
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return platformv1.NewClusterServiceClient(conn)
}

// TestRegisteredClusterGRPCService_AnswersWithServicerResults is the
// regression test for #317: the service the daemon registers answers all
// five RPCs with the cluster servicer's result, not codes.Unimplemented.
func TestRegisteredClusterGRPCService_AnswersWithServicerResults(t *testing.T) {
	clients, backend := serveRegisteredClusterGRPC(t)
	fake := &fakeClusterServicer{statusInfo: runningStatus(), nodes: stockNodes(), nodeID: 1, leader: true}
	backend.set(fake)

	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()

			boot, err := client.Bootstrap(ctx, &platformv1.BootstrapClusterRequest{ClusterName: "alpha", NodeName: "node-1"})
			require.NoError(t, err)
			assert.Equal(t, "alpha", boot.GetCluster().GetName())
			assert.Equal(t, uint32(3), boot.GetCluster().GetTotalNodes())
			assert.Equal(t, "1", boot.GetNode().GetId())

			join, err := client.Join(ctx, &platformv1.JoinClusterRequest{NodeName: "node-1", SeedAddresses: []string{"10.0.0.2:7001"}})
			require.NoError(t, err)
			assert.Equal(t, "1", join.GetCluster().GetLeaderId())
			assert.Equal(t, []string{"10.0.0.2:7001"}, fake.joinAddresses)

			leave, err := client.Leave(ctx, &platformv1.LeaveClusterRequest{})
			require.NoError(t, err)
			assert.True(t, leave.GetStatus().GetSuccess())

			st, err := client.GetStatus(ctx, &platformv1.GetClusterStatusRequest{IncludeNodes: true})
			require.NoError(t, err)
			assert.Equal(t, platformv1.ClusterState_CLUSTER_STATE_HEALTHY, st.GetCluster().GetState())
			assert.Equal(t, "10.0.0.1:7001", st.GetCluster().GetLeaderAddress())
			assert.Len(t, st.GetNodes(), 2)

			list, err := client.ListNodes(ctx, &platformv1.ListClusterNodesRequest{})
			require.NoError(t, err)
			require.Len(t, list.GetNodes(), 2)
			assert.Equal(t, "1", list.GetNodes()[0].GetId())
			assert.Equal(t, uint32(7001), list.GetNodes()[0].GetPort())
		})
	}
	assert.Equal(t, 2, fake.bootstrapCalled)
	assert.Equal(t, 2, fake.joinCalled)
	assert.Equal(t, 2, fake.leaveCalled)
}

// TestRegisteredClusterGRPCService_UnavailableWithoutServicer verifies all
// five RPCs report Unavailable — never Unimplemented — before a servicer is
// set and after it is cleared.
func TestRegisteredClusterGRPCService_UnavailableWithoutServicer(t *testing.T) {
	clients, backend := serveRegisteredClusterGRPC(t)
	backend.set(&fakeClusterServicer{})
	backend.set(nil)

	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			calls := map[string]func() error{
				"Bootstrap": func() error {
					_, err := client.Bootstrap(ctx, &platformv1.BootstrapClusterRequest{ClusterName: "alpha", NodeName: "node-1"})
					return err
				},
				"Join": func() error {
					_, err := client.Join(ctx, &platformv1.JoinClusterRequest{NodeName: "node-1", SeedAddresses: []string{"10.0.0.2:7001"}})
					return err
				},
				"Leave": func() error {
					_, err := client.Leave(ctx, &platformv1.LeaveClusterRequest{})
					return err
				},
				"GetStatus": func() error {
					_, err := client.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
					return err
				},
				"ListNodes": func() error {
					_, err := client.ListNodes(ctx, &platformv1.ListClusterNodesRequest{})
					return err
				},
			}
			for method, call := range calls {
				assert.Equal(t, codes.Unavailable, status.Code(call()), method)
			}
		})
	}
}

func TestRegisterClusterGRPCService_SkipsNilServers(t *testing.T) {
	server := grpc.NewServer()
	service, backend := registerClusterGRPCService(logging.DefaultLogger(), nil, server)
	require.NotNil(t, service)
	require.NotNil(t, backend)
	assert.Contains(t, server.GetServiceInfo(), "platform.v1.ClusterService")
}

// TestDaemonSetClusterService_ReachesGRPCBackend verifies the daemon setter
// feeds the registered gRPC service, and that nil clears it again.
func TestDaemonSetClusterService_ReachesGRPCBackend(t *testing.T) {
	service, backend := registerClusterGRPCService(logging.DefaultLogger())
	d := &Daemon{clusterBackend: backend}
	ctx := context.Background()

	d.SetClusterService(&fakeClusterServicer{statusInfo: stockStatus()})
	resp, err := service.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), resp.GetCluster().GetTotalNodes())

	d.SetClusterService(nil)
	_, err = service.GetStatus(ctx, &platformv1.GetClusterStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// =============================================================================
// Backend methods
// =============================================================================

func newTestClusterBackend(svc ClusterServicer) *clusterGRPCBackend {
	b := newClusterGRPCBackend()
	b.now = func() time.Time { return time.Unix(1700000000, 0) }
	b.set(svc)
	return b
}

func TestClusterGRPCBackend_Bootstrap(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClusterServicer{statusInfo: runningStatus(), nodeID: 1, leader: true}

	resp, err := newTestClusterBackend(fake).Bootstrap(ctx, &grpcapi.ClusterBootstrapRequest{ClusterName: "alpha", NodeName: "node-1"})
	require.NoError(t, err)
	assert.Equal(t, 1, fake.bootstrapCalled)
	assert.Equal(t, "alpha", resp.Cluster.Name)
	assert.Equal(t, grpcapi.ClusterStateHealthy, resp.Cluster.State)
	assert.Equal(t, uint64(5), resp.Cluster.Term)
	assert.Equal(t, "node-1", resp.Node.Name)
	assert.Equal(t, grpcapi.NodeRoleLeader, resp.Node.Role)

	bootErr := errors.New("bootstrap refused")
	_, err = newTestClusterBackend(&fakeClusterServicer{bootstrapErr: bootErr}).Bootstrap(ctx, &grpcapi.ClusterBootstrapRequest{})
	assert.ErrorIs(t, err, bootErr)

	statusErr := errors.New("status unreadable")
	_, err = newTestClusterBackend(&fakeClusterServicer{statusErr: statusErr}).Bootstrap(ctx, &grpcapi.ClusterBootstrapRequest{})
	assert.ErrorIs(t, err, statusErr)

	_, err = newTestClusterBackend(nil).Bootstrap(ctx, &grpcapi.ClusterBootstrapRequest{})
	assert.ErrorAs(t, err, new(grpcapi.ErrClusterServiceUnavailable))
}

func TestClusterGRPCBackend_Join(t *testing.T) {
	ctx := context.Background()
	fake := &fakeClusterServicer{statusInfo: stockStatus(), nodeID: 2}

	resp, err := newTestClusterBackend(fake).Join(ctx, &grpcapi.ClusterJoinRequest{NodeName: "node-2", SeedAddresses: []string{"10.0.0.1:7001"}})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1:7001"}, fake.joinAddresses)
	assert.Equal(t, "2", resp.Node.ID)
	assert.Equal(t, grpcapi.NodeRoleFollower, resp.Node.Role)

	joinErr := errors.New("seed unreachable")
	_, err = newTestClusterBackend(&fakeClusterServicer{joinErr: joinErr}).Join(ctx, &grpcapi.ClusterJoinRequest{})
	assert.ErrorIs(t, err, joinErr)

	statusErr := errors.New("status unreadable")
	_, err = newTestClusterBackend(&fakeClusterServicer{statusErr: statusErr}).Join(ctx, &grpcapi.ClusterJoinRequest{})
	assert.ErrorIs(t, err, statusErr)

	_, err = newTestClusterBackend(nil).Join(ctx, &grpcapi.ClusterJoinRequest{})
	assert.ErrorAs(t, err, new(grpcapi.ErrClusterServiceUnavailable))
}

// deadlineLeaveServicer records the deadline Leave runs under and fails
// with the context error once the context is done.
type deadlineLeaveServicer struct {
	fakeClusterServicer
	deadline    time.Time
	hasDeadline bool
}

func (s *deadlineLeaveServicer) Leave(ctx context.Context) error {
	s.leaveCalled++
	s.deadline, s.hasDeadline = ctx.Deadline()
	return ctx.Err()
}

func TestClusterGRPCBackend_Leave(t *testing.T) {
	ctx := context.Background()

	t.Run("local node by empty and explicit id", func(t *testing.T) {
		fake := &fakeClusterServicer{nodeID: 7}
		b := newTestClusterBackend(fake)
		for _, id := range []string{"", "7"} {
			resp, err := b.Leave(ctx, &grpcapi.ClusterLeaveRequest{NodeID: id})
			require.NoError(t, err)
			assert.True(t, resp.Success)
			assert.Equal(t, "node 7 left the cluster", resp.Message)
		}
		assert.Equal(t, 2, fake.leaveCalled)
	})

	t.Run("another node is refused", func(t *testing.T) {
		fake := &fakeClusterServicer{nodeID: 7}
		_, err := newTestClusterBackend(fake).Leave(ctx, &grpcapi.ClusterLeaveRequest{NodeID: "8"})
		assert.Equal(t, grpcapi.ErrLeaveNodeNotLocal{NodeID: "8", LocalNodeID: "7"}, err)
		assert.Zero(t, fake.leaveCalled)
	})

	t.Run("timeout bounds the leave", func(t *testing.T) {
		svc := &deadlineLeaveServicer{}
		_, err := newTestClusterBackend(svc).Leave(ctx, &grpcapi.ClusterLeaveRequest{TimeoutSeconds: 30})
		require.NoError(t, err)
		require.True(t, svc.hasDeadline)
		assert.WithinDuration(t, time.Now().Add(30*time.Second), svc.deadline, 5*time.Second)
	})

	t.Run("expired deadline reports a leave timeout", func(t *testing.T) {
		expired, cancel := context.WithDeadline(ctx, time.Unix(0, 0))
		defer cancel()
		_, err := newTestClusterBackend(&deadlineLeaveServicer{}).Leave(expired, &grpcapi.ClusterLeaveRequest{})
		assert.Equal(t, grpcapi.ErrLeaveTimeout{}, err)
	})

	t.Run("servicer error passes through", func(t *testing.T) {
		leaveErr := errors.New("leave refused")
		_, err := newTestClusterBackend(&fakeClusterServicer{leaveErr: leaveErr}).Leave(ctx, &grpcapi.ClusterLeaveRequest{})
		assert.ErrorIs(t, err, leaveErr)
	})

	t.Run("no servicer", func(t *testing.T) {
		_, err := newTestClusterBackend(nil).Leave(ctx, &grpcapi.ClusterLeaveRequest{})
		assert.ErrorAs(t, err, new(grpcapi.ErrClusterServiceUnavailable))
	})
}

func TestClusterGRPCBackend_GetStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("without nodes", func(t *testing.T) {
		fake := &fakeClusterServicer{statusInfo: stockStatus(), nodes: stockNodes(), nodeID: 2}
		resp, err := newTestClusterBackend(fake).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{})
		require.NoError(t, err)
		assert.Zero(t, fake.nodeCalls)
		assert.Nil(t, resp.Nodes)
		assert.Equal(t, "2", resp.LocalNode.ID)
		assert.Equal(t, int64(1700000000), resp.Timestamp)
		assert.Equal(t, "1", resp.Cluster.LeaderID)
		assert.Empty(t, resp.Cluster.LeaderAddress)
	})

	t.Run("with nodes", func(t *testing.T) {
		fake := &fakeClusterServicer{statusInfo: stockStatus(), nodes: stockNodes(), nodeID: 2}
		resp, err := newTestClusterBackend(fake).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{IncludeNodes: true})
		require.NoError(t, err)
		require.Len(t, resp.Nodes, 2)
		assert.Equal(t, "10.0.0.2", resp.LocalNode.Address)
		assert.Equal(t, grpcapi.NodeStateActive, resp.LocalNode.State)
		assert.Equal(t, "10.0.0.1:7001", resp.Cluster.LeaderAddress)
	})

	t.Run("nil nodes", func(t *testing.T) {
		fake := &fakeClusterServicer{statusInfo: stockStatus()}
		resp, err := newTestClusterBackend(fake).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{IncludeNodes: true})
		require.NoError(t, err)
		assert.Empty(t, resp.Nodes)
	})

	t.Run("status error", func(t *testing.T) {
		statusErr := errors.New("status unreadable")
		_, err := newTestClusterBackend(&fakeClusterServicer{statusErr: statusErr}).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{})
		assert.ErrorIs(t, err, statusErr)
	})

	t.Run("nodes error", func(t *testing.T) {
		nodesErr := errors.New("membership unreadable")
		fake := &fakeClusterServicer{statusInfo: stockStatus(), nodesErr: nodesErr}
		_, err := newTestClusterBackend(fake).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{IncludeNodes: true})
		assert.ErrorIs(t, err, nodesErr)
	})

	t.Run("no servicer", func(t *testing.T) {
		_, err := newTestClusterBackend(nil).GetStatus(ctx, &grpcapi.ClusterGetStatusRequest{})
		assert.ErrorAs(t, err, new(grpcapi.ErrClusterServiceUnavailable))
	})
}

// threeNodes is a leader and two followers, one of them suspect.
func threeNodes() *ClusterNodesInfo {
	nodes := stockNodes()
	nodes.Nodes = append(nodes.Nodes, ClusterNodeInfo{
		ID:       3,
		Address:  "10.0.0.0:7001",
		State:    "suspect",
		Metadata: map[string]string{"zone": "b"},
	})
	nodes.Nodes[1].Metadata = map[string]string{"zone": "b"}
	return nodes
}

func nodeIDs(nodes []*grpcapi.ClusterNodeInfo) []string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	return ids
}

func TestClusterGRPCBackend_ListNodes(t *testing.T) {
	ctx := context.Background()
	b := newTestClusterBackend(&fakeClusterServicer{nodes: threeNodes()})

	tests := []struct {
		name    string
		req     *grpcapi.ClusterListNodesRequest
		wantIDs []string
	}{
		{"service order", &grpcapi.ClusterListNodesRequest{}, []string{"1", "2", "3"}},
		{"by id descending", &grpcapi.ClusterListNodesRequest{SortBy: "id"}, []string{"3", "2", "1"}},
		{"by address ascending", &grpcapi.ClusterListNodesRequest{SortBy: "address", Ascending: true}, []string{"3", "1", "2"}},
		{"followers", &grpcapi.ClusterListNodesRequest{Roles: []grpcapi.NodeRoleType{grpcapi.NodeRoleFollower}}, []string{"2", "3"}},
		{"unreachable", &grpcapi.ClusterListNodesRequest{States: []grpcapi.NodeStateType{grpcapi.NodeStateUnreachable}}, []string{"3"}},
		{"label zone=b", &grpcapi.ClusterListNodesRequest{MatchLabels: map[string]string{"zone": "b"}}, []string{"2", "3"}},
		{"second page of two", &grpcapi.ClusterListNodesRequest{Page: 2, PageSize: 2}, []string{"3"}},
		{"page past the end", &grpcapi.ClusterListNodesRequest{Page: 5, PageSize: 2}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := b.ListNodes(ctx, tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.wantIDs, nodeIDs(resp.Nodes))
		})
	}

	resp, err := b.ListNodes(ctx, &grpcapi.ClusterListNodesRequest{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, uint32(3), resp.Total)
	assert.Equal(t, uint32(2), resp.TotalPages)
	assert.Equal(t, uint64(3), resp.TotalItems)
}

func TestClusterGRPCBackend_ListNodes_Errors(t *testing.T) {
	ctx := context.Background()

	fake := &fakeClusterServicer{nodes: stockNodes()}
	_, err := newTestClusterBackend(fake).ListNodes(ctx, &grpcapi.ClusterListNodesRequest{SortBy: "uptime"})
	assert.Equal(t, grpcapi.ErrUnsupportedNodeSortField{Field: "uptime"}, err)
	assert.Zero(t, fake.nodeCalls)

	nodesErr := errors.New("membership unreadable")
	_, err = newTestClusterBackend(&fakeClusterServicer{nodesErr: nodesErr}).ListNodes(ctx, &grpcapi.ClusterListNodesRequest{})
	assert.ErrorIs(t, err, nodesErr)

	_, err = newTestClusterBackend(nil).ListNodes(ctx, &grpcapi.ClusterListNodesRequest{})
	assert.ErrorAs(t, err, new(grpcapi.ErrClusterServiceUnavailable))
}

func TestClusterGRPCBackend_ListNodes_Empty(t *testing.T) {
	resp, err := newTestClusterBackend(&fakeClusterServicer{}).ListNodes(context.Background(), &grpcapi.ClusterListNodesRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Nodes)
	assert.Zero(t, resp.Total)
	assert.Zero(t, resp.TotalPages)
	assert.Equal(t, uint32(1), resp.Page)
}

// =============================================================================
// Conversions
// =============================================================================

func TestClusterInfoToGRPC(t *testing.T) {
	st := stockStatus()
	st.State = "degraded"
	st.ErrorMessage = "insufficient healthy nodes"
	info := clusterInfoToGRPC("alpha", st, &ClusterNodeInfo{Address: "10.0.0.1:7001"})
	assert.Equal(t, grpcapi.ClusterStateDegraded, info.State)
	assert.Equal(t, "10.0.0.1:7001", info.LeaderAddress)
	assert.Equal(t, st.StartedAt.Unix(), info.CreatedAt)
	assert.Equal(t, map[string]string{"error_message": "insufficient healthy nodes"}, info.Metadata)

	empty := clusterInfoToGRPC("", nil, nil)
	assert.Equal(t, grpcapi.ClusterStateUnspecified, empty.State)
	assert.Empty(t, empty.LeaderID)
	assert.Zero(t, empty.CreatedAt)
	assert.Nil(t, empty.Metadata)

	assert.Equal(t, grpcapi.ClusterStateUnspecified, clusterInfoToGRPC("", &ClusterStatusInfo{State: "exploded"}, nil).State)
}

func TestClusterNodeToGRPC(t *testing.T) {
	node := clusterNodeToGRPC(stockNodes().Nodes[0])
	assert.Equal(t, "1", node.ID)
	assert.Equal(t, "10.0.0.1", node.Address)
	assert.Equal(t, uint32(7001), node.Port)
	assert.Equal(t, grpcapi.NodeRoleLeader, node.Role)
	assert.Equal(t, grpcapi.HealthStatusHealthy, node.Health)
	assert.NotZero(t, node.JoinedAt)

	unknown := clusterNodeToGRPC(ClusterNodeInfo{ID: 9, Address: "node-9", State: "exploded"})
	assert.Equal(t, "node-9", unknown.Address)
	assert.Zero(t, unknown.Port)
	assert.Equal(t, grpcapi.NodeStateUnspecified, unknown.State)
	assert.Equal(t, grpcapi.HealthStatusUnspecified, unknown.Health)
	assert.Zero(t, unknown.JoinedAt)
}

func TestSplitClusterAddress(t *testing.T) {
	tests := []struct {
		address  string
		wantHost string
		wantPort uint32
	}{
		{"10.0.0.1:7001", "10.0.0.1", 7001},
		{"[fd00::1]:7001", "fd00::1", 7001},
		{"10.0.0.1", "10.0.0.1", 0},
		{"10.0.0.1:http", "10.0.0.1:http", 0},
		{"10.0.0.1:70000", "10.0.0.1:70000", 0},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			host, port := splitClusterAddress(tt.address)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

func TestClusterCount(t *testing.T) {
	assert.Equal(t, uint32(3), clusterCount(3))
	assert.Zero(t, clusterCount(-1))
	assert.Equal(t, uint32(math.MaxUint32), clusterCount(math.MaxInt))
}
