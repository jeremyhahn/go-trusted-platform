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

// pxeTestProvider serves a PXEService servicer to the PXE tools.
type pxeTestProvider struct {
	*mockServiceProvider
	server platformv1.PXEServiceServer
}

func (p pxeTestProvider) PXEServiceServer() platformv1.PXEServiceServer { return p.server }

// fakeMCPPXE answers Authorize and records the request it was given; every
// other method answers Unimplemented.
type fakeMCPPXE struct {
	platformv1.UnimplementedPXEServiceServer
	got *platformv1.AuthorizePXEDeviceRequest
}

func (f *fakeMCPPXE) Authorize(_ context.Context, req *platformv1.AuthorizePXEDeviceRequest) (*platformv1.AuthorizePXEDeviceResponse, error) {
	f.got = req
	return &platformv1.AuthorizePXEDeviceResponse{Device: &platformv1.PXEDeviceInfo{
		Id:         req.GetDeviceId(),
		State:      platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED,
		TargetVlan: req.GetTargetVlan(),
	}}, nil
}

func newPXETestRegistry(server platformv1.PXEServiceServer) *ToolRegistry {
	provider := pxeTestProvider{mockServiceProvider: newMockServiceProvider(), server: server}
	return NewToolRegistry(provider, logging.DefaultLogger())
}

// Every PXEService method has one tool, and the tool requires the scope its
// gRPC method requires.
func TestPXETools_CoverEveryMethodWithItsGRPCScope(t *testing.T) {
	permissions := toolPermissionCatalog()
	byMethod := make(map[string]string, len(pxeTools))
	for name, tool := range pxeTools {
		byMethod[tool.method] = name
	}

	for _, desc := range platformv1.PXEService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.PXEService_ServiceDesc.ServiceName, desc.MethodName)
		name, ok := byMethod[method]
		require.True(t, ok, "%s has no tool", method)
		scope := grpcapi.ScopeForMethod(method)
		require.NotEmpty(t, scope, "%s has no gRPC scope", method)
		assert.Equal(t, scope, permissions[name], name)
	}
	assert.Len(t, pxeTools, len(platformv1.PXEService_ServiceDesc.Methods))
}

// Every tool is advertised with the schema of its gRPC request.
func TestPXETools_AreRegisteredWithTheirSchema(t *testing.T) {
	registered := make(map[string]map[string]interface{})
	for _, def := range newPXETestRegistry(nil).ListTools() {
		registered[def.Name] = def.InputSchema
	}

	for name := range pxeTools {
		_, ok := registered[name]
		require.True(t, ok, "%s is not registered", name)
	}
	assert.Equal(t, []string{"device_id", "target_vlan"}, registered["pxe_authorize_device"]["required"])
	properties, ok := registered["pxe_list_devices"]["properties"].(map[string]interface{})
	require.True(t, ok, "pxe_list_devices schema has no properties")
	assert.Contains(t, properties, "filter")
}

// The tool decodes its arguments into the gRPC request and answers the gRPC
// response under the proto field names, enums by name.
func TestPXETools_CallTheServicer(t *testing.T) {
	fake := &fakeMCPPXE{}
	registry := newPXETestRegistry(fake)

	result, err := registry.ExecuteTool(context.Background(), "pxe_authorize_device",
		map[string]interface{}{"device_id": "dev-1", "target_vlan": 300})

	require.NoError(t, err)
	require.NotNil(t, fake.got)
	assert.Equal(t, "dev-1", fake.got.GetDeviceId())
	assert.Equal(t, uint32(300), fake.got.GetTargetVlan())
	assert.Equal(t, map[string]interface{}{"device": map[string]interface{}{
		"id":          "dev-1",
		"state":       "PROVISIONING_STATE_AUTHORIZED",
		"target_vlan": float64(300),
	}}, result)
}

// A servicer refusal reaches the caller with its gRPC status unchanged.
func TestPXETools_PassTheServicerStatusThrough(t *testing.T) {
	registry := newPXETestRegistry(&fakeMCPPXE{})

	_, err := registry.ExecuteTool(context.Background(), "pxe_remove_device",
		map[string]interface{}{"device_id": "dev-1"})

	assert.Equal(t, codes.Unimplemented, status.Code(err), "err = %v", err)
}

// Without a PXEService servicer every tool refuses with ErrPXENotConfigured.
func TestPXETools_RefuseWhenThePXEServiceIsNotWired(t *testing.T) {
	for _, provider := range []ServiceProvider{
		newMockServiceProvider(),
		pxeTestProvider{mockServiceProvider: newMockServiceProvider()},
	} {
		registry := NewToolRegistry(provider, logging.DefaultLogger())
		for name := range pxeTools {
			_, err := registry.ExecuteTool(context.Background(), name, map[string]interface{}{"device_id": "dev-1"})
			require.ErrorIs(t, err, ErrPXENotConfigured, name)
		}
	}
}

// An argument the request does not declare is refused before the servicer
// runs.
func TestPXETools_RejectArgumentsTheRequestDoesNotHave(t *testing.T) {
	fake := &fakeMCPPXE{}
	registry := newPXETestRegistry(fake)

	_, err := registry.ExecuteTool(context.Background(), "pxe_authorize_device",
		map[string]interface{}{"device_id": "dev-1", "target_zone": "trusted"})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Nil(t, fake.got, "the servicer ran for a malformed call")
}
