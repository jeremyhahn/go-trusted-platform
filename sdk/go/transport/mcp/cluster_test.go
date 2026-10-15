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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Every ClusterService method has a tool, an argument builder and a reply
// decoder.
func TestClusterTools_CoverEveryMethod(t *testing.T) {
	desc := platformv1.ClusterService_ServiceDesc
	for _, m := range desc.Methods {
		method := "/" + desc.ServiceName + "/" + m.MethodName
		assert.NotEmpty(t, MethodTools()[method], "%s has no tool", method)
		assert.Contains(t, mcpArgBuilders, method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
	assert.Len(t, clusterToolMap, len(desc.Methods))
}

// A request travels under its proto field names, a repeated field as a list.
func TestClusterTools_BuildTheRequestArguments(t *testing.T) {
	build := mcpArgBuilders[platformv1.ClusterService_Join_FullMethodName]

	args, err := build(&platformv1.JoinClusterRequest{
		NodeName:      "node-2",
		BindPort:      7001,
		SeedAddresses: []string{"10.0.0.1:7001"},
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"node_name":      "node-2",
		"bind_port":      float64(7001),
		"seed_addresses": []interface{}{"10.0.0.1:7001"},
	}, args)
}

func TestClusterTools_RefuseAnArgumentOfAnotherType(t *testing.T) {
	build := mcpArgBuilders[platformv1.ClusterService_Join_FullMethodName]

	_, err := build("10.0.0.1:7001")

	var unexpected ErrUnexpectedArgsType
	require.True(t, errors.As(err, &unexpected), "error = %v", err)
	assert.Equal(t, platformv1.ClusterService_Join_FullMethodName, unexpected.Method)
}

// A tool result decodes into the gRPC response, enums by name.
func TestClusterTools_DecodeTheResult(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.ClusterService_ListNodes_FullMethodName]
	reply := &platformv1.ListClusterNodesResponse{}

	err := decode(map[string]interface{}{"total": 1, "nodes": []interface{}{map[string]interface{}{
		"id": "1", "address": "10.0.0.1", "role": "NODE_ROLE_LEADER", "state": "NODE_STATE_ACTIVE",
	}}}, reply)

	require.NoError(t, err)
	assert.Equal(t, uint32(1), reply.GetTotal())
	require.Len(t, reply.GetNodes(), 1)
	node := reply.GetNodes()[0]
	assert.Equal(t, "1", node.GetId())
	assert.Equal(t, "10.0.0.1", node.GetAddress())
	assert.Equal(t, platformv1.NodeRole_NODE_ROLE_LEADER, node.GetRole())
	assert.Equal(t, platformv1.NodeState_NODE_STATE_ACTIVE, node.GetState())
}

func TestClusterTools_RefuseAResultTheResponseCannotHold(t *testing.T) {
	decode := mcpReplyDecoders[platformv1.ClusterService_ListNodes_FullMethodName]

	err := decode(map[string]interface{}{"total": "many"}, &platformv1.ListClusterNodesResponse{})

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
