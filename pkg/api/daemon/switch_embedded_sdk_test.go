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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
)

// serveSwitchEmbedded wires server as an embedded host's switch service and
// connects the SDK's embedded adapter to the registry the host builds.
func serveSwitchEmbedded(t *testing.T, server *SwitchGRPCService) grpc.ClientConnInterface {
	t.Helper()
	host, err := NewEmbeddedHost(testConfig(filepath.Join(t.TempDir(), "platformd.sock")))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, host.Stop(context.Background())) })

	host.daemon.switchGRPCService = server

	adapter, err := embedded.New(host.daemon.embeddedServices())
	require.NoError(t, err)
	return adapter.Connection()
}

// connectSwitchEmbedded serves server through the embedded host. The
// embedded transport runs no scope interceptor, so scopes are not used: the
// in-process caller is the daemon's own process.
func connectSwitchEmbedded(t *testing.T, server platformv1.SwitchServiceServer, _ ...string) grpc.ClientConnInterface {
	t.Helper()
	switchServer, ok := server.(*SwitchGRPCService)
	require.True(t, ok, "the daemon wires a *SwitchGRPCService, got %T", server)
	return serveSwitchEmbedded(t, switchServer)
}

// TestSDKEmbedded_SwitchMethods drives every SwitchService method through the
// SDK's embedded adapter and the registry the daemon's embedded host builds.
func TestSDKEmbedded_SwitchMethods(t *testing.T) {
	testSDKSwitchMethods(t, "embedded", connectSwitchEmbedded)
}

// TestSDKEmbedded_SwitchMethodsRefuse checks the embedded path refuses a
// missing port and a missing switch with the code gRPC gives.
func TestSDKEmbedded_SwitchMethodsRefuse(t *testing.T) {
	testSDKSwitchRefusesNotFound(t, "embedded", connectSwitchEmbedded)
}

// TestSwitchEmbeddedUnwiredAnswersUnimplemented checks that a daemon serving
// no SwitchService leaves the methods out of the embedded registry, so each
// answers Unimplemented and never dereferences a nil servicer.
func TestSwitchEmbeddedUnwiredAnswersUnimplemented(t *testing.T) {
	conn := serveSwitchEmbedded(t, nil)
	for method, req := range switchSDKRequests("eth1") {
		t.Run(path.Base(method), func(t *testing.T) {
			err := conn.Invoke(context.Background(), method, req, switchSDKReplies()[method])
			require.Equal(t, codes.Unimplemented, status.Code(err), "%v", err)
		})
	}
}
