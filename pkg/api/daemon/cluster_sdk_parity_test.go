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
	"path"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The ClusterService parity drivers below run every SDK transport against
// the daemon the same way: each transport file supplies only how it serves a
// ClusterService servicer and connects the SDK's adapter to it.

// clusterSDKConnect serves server through one daemon transport and connects
// the SDK's adapter for that transport as a caller holding scopes.
type clusterSDKConnect func(t *testing.T, server platformv1.ClusterServiceServer, scopes ...string) grpc.ClientConnInterface

// clusterSDKFixture is the daemon's ClusterService server over a fake
// cluster that answers every method and records what each call asked for.
type clusterSDKFixture struct {
	cluster *fakeClusterServicer
	server  platformv1.ClusterServiceServer
}

func newClusterSDKFixture() *clusterSDKFixture {
	fake := &fakeClusterServicer{
		statusInfo: runningStatus(),
		nodes:      threeNodes(),
		leader:     true,
		nodeID:     1,
	}
	return &clusterSDKFixture{
		cluster: fake,
		server:  grpcapi.NewClusterGRPCService(logging.DefaultLogger(), newTestClusterBackend(fake)),
	}
}

// recorded is everything the fake cluster recorded about the calls it served.
func (f *clusterSDKFixture) recorded() clusterCalls {
	return f.cluster.calls()
}

// invokeClusterServer calls method on server directly, through the generated
// service descriptor, as a gRPC caller reaches it once authorized.
func invokeClusterServer(server platformv1.ClusterServiceServer, method string, req proto.Message) (proto.Message, error) {
	for _, desc := range platformv1.ClusterService_ServiceDesc.Methods {
		if desc.MethodName != path.Base(method) {
			continue
		}
		decode := func(in interface{}) error {
			proto.Merge(in.(proto.Message), req)
			return nil
		}
		resp, err := desc.Handler(server, context.Background(), decode, nil)
		if err != nil {
			return nil, err
		}
		return resp.(proto.Message), nil
	}
	return nil, status.Errorf(codes.Unimplemented, "%s is not a ClusterService method", method)
}

// clusterSDKRequests holds one request for every ClusterService method.
func clusterSDKRequests() map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.ClusterService_Bootstrap_FullMethodName: &platformv1.BootstrapClusterRequest{
			ClusterName: "edge", NodeName: "node-1", BindAddress: "10.0.0.1", BindPort: 7000,
			Labels: map[string]string{"zone": "a"},
		},
		platformv1.ClusterService_Join_FullMethodName: &platformv1.JoinClusterRequest{
			NodeName: "node-2", SeedAddresses: []string{"10.0.0.1:7000", "10.0.0.3:7000"},
		},
		platformv1.ClusterService_Leave_FullMethodName:     &platformv1.LeaveClusterRequest{NodeId: "1", TimeoutSeconds: 30},
		platformv1.ClusterService_GetStatus_FullMethodName: &platformv1.GetClusterStatusRequest{IncludeNodes: true},
		platformv1.ClusterService_ListNodes_FullMethodName: &platformv1.ListClusterNodesRequest{},
	}
}

// testSDKClusterMethods drives every ClusterService method through connect,
// as a caller holding only the scope gRPC requires for it, and checks that
// the reply and the calls the cluster saw are the ones a direct gRPC call
// gives.
func testSDKClusterMethods(t *testing.T, transport string, connect clusterSDKConnect) {
	requests := clusterSDKRequests()
	require.Len(t, requests, len(platformv1.ClusterService_ServiceDesc.Methods))
	untouched := newClusterSDKFixture().recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newClusterSDKFixture()
			want, err := invokeClusterServer(direct.server, method, req)
			require.NoError(t, err)

			via := newClusterSDKFixture()
			got := want.ProtoReflect().New().Interface()
			scope := grpcapi.ScopeForMethod(method)
			require.NotEmpty(t, scope, "gRPC has no scope for %s", method)
			conn := connect(t, via.server, scope)
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			require.True(t, proto.Equal(want, got), "%s reply\n%v\nwant the gRPC reply\n%v", transport, got, want)
			require.NotEqual(t, untouched, via.recorded(), "the cluster saw no call")
			require.Equal(t, direct.recorded(), via.recorded())
		})
	}
}

// clusterScopeRefusals holds one method of each cluster permission class and
// the scopes of a caller who lacks that class.
var clusterScopeRefusals = []struct {
	class  string
	method string
	resp   proto.Message
	scopes []string
}{
	{
		class:  "cluster:read",
		method: platformv1.ClusterService_GetStatus_FullMethodName,
		resp:   &platformv1.GetClusterStatusResponse{},
		scopes: []string{"device:read"},
	},
	{
		class:  "cluster:write",
		method: platformv1.ClusterService_Bootstrap_FullMethodName,
		resp:   &platformv1.BootstrapClusterResponse{},
		scopes: []string{"cluster:read"},
	},
}

// testSDKClusterRefusesScope checks, for one method of each permission
// class, that a caller without the method's scope reaches the SDK caller as
// PermissionDenied, the code gRPC gives, and reaches no cluster.
func testSDKClusterRefusesScope(t *testing.T, transport string, connect clusterSDKConnect) {
	for _, tc := range clusterScopeRefusals {
		t.Run(tc.class+" without the scope", func(t *testing.T) {
			f := newClusterSDKFixture()
			before := f.recorded()
			conn := connect(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, clusterSDKRequests()[tc.method], tc.resp)

			require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", transport, err)
			require.Equal(t, before, f.recorded(), "a refused caller reached the cluster")
		})
	}
}

// clusterServiceRefusals holds a Bootstrap and a Join the cluster refuses,
// and the gRPC code each refusal carries.
var clusterServiceRefusals = []struct {
	name   string
	method string
	resp   proto.Message
	refuse func(f *clusterSDKFixture)
	code   codes.Code
}{
	{
		name:   "Bootstrap of an initialized cluster",
		method: platformv1.ClusterService_Bootstrap_FullMethodName,
		resp:   &platformv1.BootstrapClusterResponse{},
		refuse: func(f *clusterSDKFixture) { f.cluster.bootstrapErr = grpcapi.ErrClusterAlreadyInitialized{} },
		code:   codes.AlreadyExists,
	},
	{
		name:   "Join with no seed reachable",
		method: platformv1.ClusterService_Join_FullMethodName,
		resp:   &platformv1.JoinClusterResponse{},
		refuse: func(f *clusterSDKFixture) { f.cluster.joinErr = grpcapi.ErrNoSeedReachable{} },
		code:   codes.Unavailable,
	},
}

// testSDKClusterRefusesService checks that a Bootstrap or Join the cluster
// refuses reaches the SDK caller with the code gRPC gives.
func testSDKClusterRefusesService(t *testing.T, transport string, connect clusterSDKConnect) {
	for _, tc := range clusterServiceRefusals {
		req := clusterSDKRequests()[tc.method]

		t.Run(tc.name, func(t *testing.T) {
			direct := newClusterSDKFixture()
			tc.refuse(direct)
			_, err := invokeClusterServer(direct.server, tc.method, req)
			require.Equal(t, tc.code, status.Code(err), "gRPC: %v", err)

			via := newClusterSDKFixture()
			tc.refuse(via)
			conn := connect(t, via.server, "*:*")
			err = conn.Invoke(context.Background(), tc.method, req, tc.resp)
			require.Equal(t, tc.code, status.Code(err), "%s: %v", transport, err)
		})
	}
}
