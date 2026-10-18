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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// connectSwitchQUIC serves server through the daemon's QUIC handler and
// connects the SDK's QUIC adapter as a caller holding scopes. A nil server
// leaves the switch category unwired.
func connectSwitchQUIC(t *testing.T, server platformv1.SwitchServiceServer, scopes ...string) grpc.ClientConnInterface {
	t.Helper()
	validator := &quicScopeValidator{scopes: scopes}
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(),
		WithQUICAuthMiddleware(quic.NewAuthMiddleware(quic.WithQUICTokenValidator(validator))))
	if err != nil {
		t.Fatalf("NewQUICServiceHandler: %v", err)
	}
	if server != nil {
		handler.SetSwitchServer(server)
	}
	bundle := testutil.GenerateTestTLSBundle(t)
	return newPhase35QUICClient(t, handler, bundle, platform.WithBearerToken("operator-token")).Connection()
}

// TestSDKQUIC_SwitchMethods drives every SwitchService method through the
// SDK's QUIC adapter and the daemon's QUIC handler.
func TestSDKQUIC_SwitchMethods(t *testing.T) {
	testSDKSwitchMethods(t, "QUIC", connectSwitchQUIC)
}

// TestSDKQUIC_SwitchMethodsRefuse checks the QUIC path refuses a missing
// scope and a missing port with the codes gRPC gives.
func TestSDKQUIC_SwitchMethodsRefuse(t *testing.T) {
	testSDKSwitchRefusesScope(t, "QUIC", connectSwitchQUIC)
	testSDKSwitchRefusesNotFound(t, "QUIC", connectSwitchQUIC)
}

// TestSwitchQUICNotConfiguredAnswersUnavailable checks that the servicer
// with no switch backend answers every switch method over QUIC as not
// configured (Unavailable), the code gRPC gives.
func TestSwitchQUICNotConfiguredAnswersUnavailable(t *testing.T) {
	conn := connectSwitchQUIC(t, NewSwitchGRPCService(logging.DefaultLogger(), nil), "switch:read", "switch:write")
	for method, req := range switchSDKRequests("eth1") {
		t.Run(path.Base(method), func(t *testing.T) {
			err := conn.Invoke(context.Background(), method, req, switchSDKReplies()[method])
			require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}

// TestSwitchQUICUnwiredAnswersUnavailable checks that a QUIC handler with no
// SwitchService servicer answers every switch method Unavailable and never
// dereferences a nil servicer.
func TestSwitchQUICUnwiredAnswersUnavailable(t *testing.T) {
	conn := connectSwitchQUIC(t, nil, "switch:read", "switch:write")
	for method, req := range switchSDKRequests("eth1") {
		t.Run(path.Base(method), func(t *testing.T) {
			err := conn.Invoke(context.Background(), method, req, switchSDKReplies()[method])
			require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		})
	}
}
