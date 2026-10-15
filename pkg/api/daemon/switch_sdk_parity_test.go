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

// The SwitchService parity drivers below run every SDK transport against the
// daemon the same way: each transport file supplies only how it serves a
// SwitchService servicer and connects the SDK's adapter to it.

// switchSDKConnect serves server through one daemon transport and connects
// the SDK's adapter for that transport as a caller holding scopes.
type switchSDKConnect func(t *testing.T, server platformv1.SwitchServiceServer, scopes ...string) grpc.ClientConnInterface

// switchSDKFixture is the gRPC SwitchService servicer over a fake switch,
// core-1, that records every port operation it is asked for.
type switchSDKFixture struct {
	switches *fakeSwitchService
	server   *SwitchGRPCService
}

func newSwitchSDKFixture() *switchSDKFixture {
	switches := newFakeSwitchService()
	return &switchSDKFixture{switches: switches, server: NewSwitchGRPCService(logging.DefaultLogger(), switches)}
}

// recorded is everything the fake switch recorded about the calls it served:
// the switch lookups, the port operations, and the ports' resulting state.
func (f *switchSDKFixture) recorded() []interface{} {
	calls, ports := f.switches.managers["core-1"].snapshot()
	return []interface{}{f.switches.lookups(), calls, ports}
}

// invokeSwitchServer calls method on server directly, through the generated
// service descriptor, as a gRPC caller reaches it once authorized.
func invokeSwitchServer(server platformv1.SwitchServiceServer, method string, req proto.Message) (proto.Message, error) {
	for _, desc := range platformv1.SwitchService_ServiceDesc.Methods {
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
	return nil, status.Errorf(codes.Unimplemented, "%s is not a SwitchService method", method)
}

// switchSDKRequests holds one request for every SwitchService method, each
// naming switch core-1 and, where the method takes one, port.
func switchSDKRequests(port string) map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.SwitchService_ListPorts_FullMethodName:     &platformv1.ListSwitchPortsRequest{SwitchName: "core-1"},
		platformv1.SwitchService_GetPortStatus_FullMethodName: &platformv1.GetSwitchPortStatusRequest{SwitchName: "core-1", PortName: port},
		platformv1.SwitchService_SetPortVLAN_FullMethodName:   &platformv1.SetSwitchPortVLANRequest{SwitchName: "core-1", PortName: port, VlanId: 20},
		platformv1.SwitchService_EnablePort_FullMethodName:    &platformv1.EnableSwitchPortRequest{SwitchName: "core-1", PortName: port},
		platformv1.SwitchService_DisablePort_FullMethodName:   &platformv1.DisableSwitchPortRequest{SwitchName: "core-1", PortName: port},
	}
}

// switchSDKReplies holds an empty reply for every SwitchService method.
func switchSDKReplies() map[string]proto.Message {
	return map[string]proto.Message{
		platformv1.SwitchService_ListPorts_FullMethodName:     &platformv1.ListSwitchPortsResponse{},
		platformv1.SwitchService_GetPortStatus_FullMethodName: &platformv1.GetSwitchPortStatusResponse{},
		platformv1.SwitchService_SetPortVLAN_FullMethodName:   &platformv1.SetSwitchPortVLANResponse{},
		platformv1.SwitchService_EnablePort_FullMethodName:    &platformv1.EnableSwitchPortResponse{},
		platformv1.SwitchService_DisablePort_FullMethodName:   &platformv1.DisableSwitchPortResponse{},
	}
}

// testSDKSwitchMethods drives every SwitchService method through connect, as
// a caller holding only the scope gRPC requires for it, and checks that the
// reply and the calls the switch saw are the ones a direct gRPC call gives.
func testSDKSwitchMethods(t *testing.T, transport string, connect switchSDKConnect) {
	requests := switchSDKRequests("eth1")
	require.Len(t, requests, len(platformv1.SwitchService_ServiceDesc.Methods))
	untouched := newSwitchSDKFixture().recorded()

	for method, req := range requests {
		t.Run(path.Base(method), func(t *testing.T) {
			direct := newSwitchSDKFixture()
			want, err := invokeSwitchServer(direct.server, method, req)
			require.NoError(t, err)

			via := newSwitchSDKFixture()
			got := want.ProtoReflect().New().Interface()
			scope := grpcapi.ScopeForMethod(method)
			require.NotEmpty(t, scope, "gRPC has no scope for %s", method)
			conn := connect(t, via.server, scope)
			require.NoError(t, conn.Invoke(context.Background(), method, req, got))

			require.True(t, proto.Equal(want, got), "%s reply\n%v\nwant the gRPC reply\n%v", transport, got, want)
			require.NotEqual(t, untouched, via.recorded(), "the switch saw no call")
			require.Equal(t, direct.recorded(), via.recorded())
		})
	}
}

// switchRefusalCase is one method of a permission class and the scopes of a
// caller who lacks that class.
type switchRefusalCase struct {
	class  string
	method string
	scopes []string
}

// switchRefusalCases holds one read and one mutating method.
func switchRefusalCases() []switchRefusalCase {
	return []switchRefusalCase{
		{class: "switch:read", method: platformv1.SwitchService_ListPorts_FullMethodName, scopes: []string{"cluster:read"}},
		{class: "switch:write", method: platformv1.SwitchService_SetPortVLAN_FullMethodName, scopes: []string{"switch:read"}},
	}
}

// testSDKSwitchRefusesScope checks, for a read and a mutating method, that a
// caller without the method's scope reaches the SDK caller as
// PermissionDenied, the code gRPC gives, and reaches no switch.
func testSDKSwitchRefusesScope(t *testing.T, transport string, connect switchSDKConnect) {
	for _, tc := range switchRefusalCases() {
		t.Run(tc.class+" without the scope", func(t *testing.T) {
			f := newSwitchSDKFixture()
			before := f.recorded()
			conn := connect(t, f.server, tc.scopes...)

			err := conn.Invoke(context.Background(), tc.method, switchSDKRequests("eth1")[tc.method], switchSDKReplies()[tc.method])

			require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", transport, err)
			require.Equal(t, before, f.recorded(), "a refused caller reached the switch")
		})
	}
}

// testSDKSwitchRefusesNotFound checks that a port the switch does not have,
// and a switch the service does not know, reach the SDK caller with the code
// gRPC gives for every method.
func testSDKSwitchRefusesNotFound(t *testing.T, transport string, connect switchSDKConnect) {
	for method, req := range switchSDKRequests("eth9") {
		if method == platformv1.SwitchService_ListPorts_FullMethodName {
			// ListPorts names no port; it misses on the switch instead.
			req = &platformv1.ListSwitchPortsRequest{SwitchName: "core-9"}
		}
		t.Run(path.Base(method)+" of a port not found", func(t *testing.T) {
			_, want := invokeSwitchServer(newSwitchSDKFixture().server, method, req)
			require.Error(t, want, "gRPC served a missing port")

			conn := connect(t, newSwitchSDKFixture().server, "*:*")
			got := conn.Invoke(context.Background(), method, req, switchSDKReplies()[method])

			require.Equal(t, status.Code(want), status.Code(got), "%s: %v", transport, got)
		})
	}

	t.Run("GetPortStatus answers NotFound", func(t *testing.T) {
		conn := connect(t, newSwitchSDKFixture().server, "*:*")
		method := platformv1.SwitchService_GetPortStatus_FullMethodName
		err := conn.Invoke(context.Background(), method, switchSDKRequests("eth9")[method], switchSDKReplies()[method])
		require.Equal(t, codes.NotFound, status.Code(err), "%s: %v", transport, err)
	})
}
