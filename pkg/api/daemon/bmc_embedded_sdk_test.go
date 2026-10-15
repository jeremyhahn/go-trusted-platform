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
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectBMCEmbedded wires server as an embedded host's BMC service and
// connects the SDK's embedded adapter to the registry the host builds. The
// embedded transport runs no scope interceptor, so scopes are not used: the
// in-process caller is the daemon's own process.
func connectBMCEmbedded(t *testing.T, server platformv1.BMCServiceServer, _ ...string) grpc.ClientConnInterface {
	t.Helper()
	bmcServer, ok := server.(*BMCGRPCService)
	require.True(t, ok, "the daemon wires a *BMCGRPCService, got %T", server)
	return connectEmbeddedHost(t, func(d *Daemon) { d.bmcGRPCService = bmcServer })
}

// TestSDKEmbedded_BMCMethods drives every BMCService method through the
// SDK's embedded adapter and the registry the daemon's embedded host builds.
func TestSDKEmbedded_BMCMethods(t *testing.T) {
	testSDKBMCMethods(t, "embedded", connectBMCEmbedded)
}

// TestSDKEmbedded_BMCMethodsRefuse checks the embedded path refuses a
// missing profile with the code gRPC gives.
func TestSDKEmbedded_BMCMethodsRefuse(t *testing.T) {
	testSDKBMCRefusesNotFound(t, "embedded", connectBMCEmbedded)
}
