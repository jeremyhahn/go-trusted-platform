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

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectClusterQUIC serves server through the daemon's QUIC handler, which
// authorizes each sub-opcode with the scope its gRPC method requires, and
// connects the SDK's QUIC adapter as a caller holding scopes.
func connectClusterQUIC(t *testing.T, server platformv1.ClusterServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	validator := &quicScopeValidator{scopes: scopes}
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	if err != nil {
		t.Fatalf("NewQUICServiceHandler: %v", err)
	}
	handler.SetClusterServer(server)
	bundle := testutil.GenerateTestTLSBundle(t)
	return newPhase35QUICClient(t, handler, bundle, platform.WithBearerToken("operator-token")).Connection()
}

// TestSDKQUIC_ClusterMethods drives every ClusterService method through the
// SDK's QUIC adapter and the daemon's OpClusterCategory handler.
func TestSDKQUIC_ClusterMethods(t *testing.T) {
	testSDKClusterMethods(t, "QUIC", connectClusterQUIC)
}

// TestSDKQUIC_ClusterMethodsRefuse checks the QUIC path refuses a missing
// scope and a cluster refusal with the codes gRPC gives.
func TestSDKQUIC_ClusterMethodsRefuse(t *testing.T) {
	testSDKClusterRefusesScope(t, "QUIC", connectClusterQUIC)
	testSDKClusterRefusesService(t, "QUIC", connectClusterQUIC)
}
