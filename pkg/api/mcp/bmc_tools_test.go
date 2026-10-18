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

// bmcTestProvider serves a BMCService servicer to the BMC tools.
type bmcTestProvider struct {
	*mockServiceProvider
	server platformv1.BMCServiceServer
}

func (p bmcTestProvider) BMCServiceServer() platformv1.BMCServiceServer { return p.server }

// fakeMCPBMC answers PowerStatus and records the request it was given; every
// other method answers Unimplemented.
type fakeMCPBMC struct {
	platformv1.UnimplementedBMCServiceServer
	got *platformv1.BMCPowerStatusRequest
}

func (f *fakeMCPBMC) PowerStatus(_ context.Context, req *platformv1.BMCPowerStatusRequest) (*platformv1.BMCPowerStatusResponse, error) {
	f.got = req
	return &platformv1.BMCPowerStatusResponse{State: platformv1.BMCPowerState_BMC_POWER_STATE_ON}, nil
}

func newBMCTestRegistry(server platformv1.BMCServiceServer) *ToolRegistry {
	provider := bmcTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// Every BMCService method has one tool, and the tool requires the scope its
// gRPC method requires.
func TestBMCTools_CoverEveryMethodWithItsGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	byMethod := make(map[string]string, len(bmcTools))
	for name, tool := range bmcTools {
		byMethod[tool.method] = name
	}

	for _, desc := range platformv1.BMCService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.BMCService_ServiceDesc.ServiceName, desc.MethodName)
		name, ok := byMethod[method]
		require.True(t, ok, "%s has no tool", method)
		scope := grpcapi.ScopeForMethod(method)
		require.NotEmpty(t, scope, "%s has no gRPC scope", method)
		assert.Equal(t, scope, permissions[name], name)
	}
	assert.Len(t, bmcTools, len(platformv1.BMCService_ServiceDesc.Methods))
}

// Every tool is advertised with a schema that requires profile_id.
func TestBMCTools_AreRegisteredWithTheirSchema(t *testing.T) {
	registered := make(map[string]map[string]interface{})
	for _, def := range newBMCTestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	for name := range bmcTools {
		schema, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
		assert.Contains(t, schema["required"], "profile_id", name)
	}
}

// The tool decodes its arguments into the gRPC request and answers the gRPC
// response under the proto field names, enums by name.
func TestBMCTools_CallTheServicer(t *testing.T) {
	fake := &fakeMCPBMC{}
	registry := newBMCTestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "platform_bmc_power_status",
		map[string]interface{}{"profile_id": "7"})

	require.NoError(t, err)
	require.NotNil(t, fake.got)
	assert.Equal(t, uint64(7), fake.got.GetProfileId())
	assert.Equal(t, map[string]interface{}{"state": "BMC_POWER_STATE_ON"}, result)
}

// A servicer refusal reaches the caller with its gRPC status unchanged.
func TestBMCTools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newBMCTestRegistry(&fakeMCPBMC{})

	_, err := registry.ExecuteTool(context.Background(), "platform_bmc_power_on",
		map[string]interface{}{"profile_id": 1})

	assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
}

// Without a BMCService servicer every tool refuses with ErrBMCNotConfigured.
func TestBMCTools_RefuseWhenTheBMCServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		bmcTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range bmcTools {
			_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{"profile_id": 1})
			require.ErrorIs(t, err, ErrBMCNotConfigured, name)
		}
	}
}

// An argument the request does not declare is refused before the servicer
// runs.
func TestBMCTools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPBMC{}
	registry := newBMCTestRegistry(fake)

	_, err := registry.ExecuteTool(context.Background(), "platform_bmc_power_status",
		map[string]interface{}{"profile_id": 1, "device": "pxe"})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, fake.got, "the servicer ran for a malformed call")
}
