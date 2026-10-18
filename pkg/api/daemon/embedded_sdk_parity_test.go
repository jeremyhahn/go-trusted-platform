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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// sdkCall is one RPC a parity test sends: the full method name, its
// request, and an empty reply of the method's response type.
type sdkCall struct {
	method string
	req    proto.Message
	resp   proto.Message
}

// invokeGRPCMethod calls method on server through the generated gRPC
// handler in desc, the path a direct gRPC call takes once the request is
// decoded.
func invokeGRPCMethod(desc *grpc.ServiceDesc, server any, method string, req proto.Message) (proto.Message, error) {
	for _, md := range desc.Methods {
		if "/"+desc.ServiceName+"/"+md.MethodName != method {
			continue
		}
		decode := func(in interface{}) error {
			proto.Merge(in.(proto.Message), req)
			return nil
		}
		resp, err := md.Handler(server, context.Background(), decode, nil)
		if err != nil {
			return nil, err
		}
		return resp.(proto.Message), nil
	}
	return nil, status.Errorf(codes.Unimplemented, "%s is not a %s method", method, desc.ServiceName)
}

// connectEmbeddedHost builds a daemon embedded host, lets wire place the
// servicers under test on its daemon, and connects the SDK's embedded
// adapter to the registry the host builds from them.
func connectEmbeddedHost(t *testing.T, wire func(d *Daemon)) grpc.ClientConnInterface {
	t.Helper()
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, host.Stop(context.Background())) })

	wire(host.daemon)

	adapter, err := embedded.New(host.daemon.embeddedServices())
	require.NoError(t, err)
	return adapter.Connection()
}

// requireSameRefusal checks a direct gRPC call failed with code want and
// the embedded call failed with the same status, code and message.
func requireSameRefusal(t *testing.T, want codes.Code, direct, via error) {
	t.Helper()
	require.Equal(t, want, status.Code(direct), "gRPC: %v", direct)
	require.Error(t, via)
	require.True(t, proto.Equal(status.Convert(direct).Proto(), status.Convert(via).Proto()),
		"embedded refused with %v, want the gRPC refusal %v", via, direct)
}
