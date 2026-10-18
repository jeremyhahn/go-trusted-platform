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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// switchTestProvider serves a SwitchService servicer to the switch tools.
type switchTestProvider struct {
	*mockServiceProvider
	server platformv1.SwitchServiceServer
}

func (p switchTestProvider) SwitchServiceServer() platformv1.SwitchServiceServer { return p.server }

// fakeMCPSwitch answers SetPortVLAN and records the request it was given;
// every other method answers Unimplemented.
type fakeMCPSwitch struct {
	platformv1.UnimplementedSwitchServiceServer
	got *platformv1.SetSwitchPortVLANRequest
}

func (f *fakeMCPSwitch) SetPortVLAN(_ context.Context, req *platformv1.SetSwitchPortVLANRequest) (*platformv1.SetSwitchPortVLANResponse, error) {
	f.got = req
	return &platformv1.SetSwitchPortVLANResponse{Status: &platformv1.Status{Success: true, Message: "eth1 moved"}}, nil
}

func newSwitchTestRegistry(server platformv1.SwitchServiceServer) *ToolRegistry {
	provider := switchTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// Every SwitchService method has one tool, and the tool requires the scope
// its gRPC method requires: read-only for port reads, switch:write for VLAN
// and admin-state changes.
func TestSwitchTools_CoverEveryMethodWithItsGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	byMethod := make(map[string]string, len(switchTools))
	for name, tool := range switchTools {
		byMethod[tool.method] = name
	}

	for _, desc := range platformv1.SwitchService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.SwitchService_ServiceDesc.ServiceName, desc.MethodName)
		name, ok := byMethod[method]
		require.True(t, ok, "%s has no tool", method)
		scope := grpcapi.ScopeForMethod(method)
		require.NotEmpty(t, scope, "%s has no gRPC scope", method)
		assert.Equal(t, scope, permissions[name], name)
	}
	assert.Len(t, switchTools, len(platformv1.SwitchService_ServiceDesc.Methods))
}

// Every tool is advertised with a schema that requires switch_name.
func TestSwitchTools_AreRegisteredWithTheirSchema(t *testing.T) {
	registered := make(map[string]map[string]interface{})
	for _, def := range newSwitchTestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	for name := range switchTools {
		schema, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
		assert.Contains(t, schema["required"], "switch_name", name)
	}
	assert.Contains(t, registered["switch_set_vlan"]["required"], "vlan_id")
}

// The tool decodes its arguments into the gRPC request and answers the gRPC
// response under the proto field names.
func TestSwitchTools_CallTheServicer(t *testing.T) {
	fake := &fakeMCPSwitch{}
	registry := newSwitchTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "switch_set_vlan",
		map[string]interface{}{"switch_name": "core-1", "port_name": "eth1", "vlan_id": 20})

	require.NoError(t, err)
	require.NotNil(t, fake.got)
	assert.Equal(t, "core-1", fake.got.GetSwitchName())
	assert.Equal(t, "eth1", fake.got.GetPortName())
	assert.Equal(t, uint32(20), fake.got.GetVlanId())
	assert.Equal(t, map[string]interface{}{
		"status": map[string]interface{}{"success": true, "message": "eth1 moved"},
	}, result)
}

// A servicer refusal reaches the caller with its gRPC status unchanged.
func TestSwitchTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newSwitchTestRegistry(&fakeMCPSwitch{})

	_, err := registry.ExecuteTool(context.Background(), "switch_enable_port",
		map[string]interface{}{"switch_name": "core-1", "port_name": "eth1"})

	assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
}

// Without a SwitchService servicer every tool refuses with
// ErrSwitchNotConfigured, which MCP answers as Unavailable, the class every
// unconfigured service answers with.
func TestSwitchTools_RefuseWhenTheSwitchServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		switchTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range switchTools {
			_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{"switch_name": "core-1"})
			require.ErrorIs(t, err, ErrSwitchNotConfigured, name)
			assert.Equal(t, mcpwire.CodeForClass(codes.Unavailable), toolErrorCode(err), name)
		}
	}
}

// An argument the request does not declare is refused before the servicer
// runs.
func TestSwitchTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPSwitch{}
	registry := newSwitchTestRegistry(fake)

	_, err := registry.ExecuteTool(context.Background(), "switch_set_vlan",
		map[string]interface{}{"switch_name": "core-1", "port_name": "eth1", "vlan_id": 20, "trunk": true})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, fake.got, "the servicer ran for a malformed call")
}
