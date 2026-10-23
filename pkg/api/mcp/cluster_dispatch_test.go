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

package mcp

import (
	"context"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// clusterTestProvider serves a ClusterService servicer to the cluster tools.
type clusterTestProvider struct {
	*mockServiceProvider
	server platformv1.ClusterServiceServer
}

func (p clusterTestProvider) ClusterServiceServer() platformv1.ClusterServiceServer {
	return p.server
}

// fakeMCPCluster answers GetStatus and records the request it was given; it
// refuses Join as unreachable seeds do, and every other method answers
// Unimplemented.
type fakeMCPCluster struct {
	platformv1.UnimplementedClusterServiceServer
	got *platformv1.GetClusterStatusRequest
}

func (f *fakeMCPCluster) GetStatus(_ context.Context, req *platformv1.GetClusterStatusRequest) (*platformv1.GetClusterStatusResponse, error) {
	f.got = req
	return &platformv1.GetClusterStatusResponse{
		Cluster: &platformv1.ClusterInfo{Name: "edge", State: platformv1.ClusterState_CLUSTER_STATE_HEALTHY},
	}, nil
}

func (f *fakeMCPCluster) Join(context.Context, *platformv1.JoinClusterRequest) (*platformv1.JoinClusterResponse, error) {
	return nil, status.Error(codes.Unavailable, "no seed addresses are reachable")
}

func newClusterTestRegistry(server platformv1.ClusterServiceServer) *ToolRegistry {
	provider := clusterTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// Every ClusterService method has one tool, and the tool requires the scope
// its gRPC method requires.
func TestClusterTools_CoverEveryMethodWithItsGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	byMethod := make(map[string]string, len(clusterTools))
	for name, tool := range clusterTools {
		byMethod[tool.method] = name
	}

	for _, desc := range platformv1.ClusterService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.ClusterService_ServiceDesc.ServiceName, desc.MethodName)
		name, ok := byMethod[method]
		require.True(t, ok, "%s has no tool", method)
		scope := grpcapi.ScopeForMethod(method)
		require.NotEmpty(t, scope, "%s has no gRPC scope", method)
		assert.Equal(t, scope, permissions[name], name)
	}
	assert.Len(t, clusterTools, len(platformv1.ClusterService_ServiceDesc.Methods))
}

// Every tool is advertised with a schema, and Bootstrap and Join require the
// fields gRPC refuses to go without.
func TestClusterTools_AreRegisteredWithTheirSchema(t *testing.T) {
	registered := make(map[string]map[string]interface{})
	for _, def := range newClusterTestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	for name := range clusterTools {
		_, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
	}
	assert.ElementsMatch(t, []string{"cluster_name", "node_name"}, registered["platform_cluster_bootstrap"]["required"])
	assert.ElementsMatch(t, []string{"node_name", "seed_addresses"}, registered["platform_cluster_join"]["required"])
}

// The tool decodes its arguments into the gRPC request and answers the gRPC
// response under the proto field names, enums by name.
func TestClusterTools_CallTheServicer(t *testing.T) {
	fake := &fakeMCPCluster{}
	registry := newClusterTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "platform_cluster_status",
		map[string]interface{}{"include_nodes": true})

	require.NoError(t, err)
	require.NotNil(t, fake.got)
	assert.True(t, fake.got.GetIncludeNodes())
	assert.Equal(t, map[string]interface{}{
		"cluster": map[string]interface{}{"name": "edge", "state": "CLUSTER_STATE_HEALTHY"},
	}, result)
}

// A servicer refusal reaches the caller with its gRPC status unchanged.
func TestClusterTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newClusterTestRegistry(&fakeMCPCluster{})

	_, err := registry.ExecuteTool(context.Background(), "platform_cluster_join",
		map[string]interface{}{"node_name": "node-2", "seed_addresses": []interface{}{"10.0.0.1:7000"}})
	assert.Equal(t, codes.Unavailable, status.Code(err), "err = %v", err)

	_, err = registry.ExecuteTool(context.Background(), "platform_cluster_leave", map[string]interface{}{})
	assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
}

// Without a ClusterService servicer every tool refuses with
// ErrClusterNotConfigured.
func TestClusterTools_RefuseWhenTheClusterServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		clusterTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range clusterTools {
			_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{})
			require.ErrorIs(t, err, ErrClusterNotConfigured, name)
		}
	}
}

// An argument the request does not declare is refused before the servicer
// runs.
func TestClusterTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPCluster{}
	registry := newClusterTestRegistry(fake)

	_, err := registry.ExecuteTool(context.Background(), "platform_cluster_status",
		map[string]interface{}{"include_nodes": true, "seed_addresses": []interface{}{"x:1"}})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, fake.got, "the servicer ran for a malformed call")
}

// The cluster dispatcher leaves a tool that is not platform_cluster_* to the
// next dispatcher.
func TestDispatchClusterTool_UnknownReturnsHandledFalse(t *testing.T) {
	registry := newClusterTestRegistry(&fakeMCPCluster{})

	result, handled, err := registry.dispatchClusterTool(context.Background(), "platform_bmc_power_on", map[string]interface{}{})

	assert.False(t, handled)
	assert.NoError(t, err)
	assert.Nil(t, result)
}
