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
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	sdkquic "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// reserveUDPPort binds an ephemeral loopback UDP port and releases it for the
// QUIC server, whose ListenAddr reports the configured address only.
func reserveUDPPort(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	addr := conn.LocalAddr().String()
	if err := conn.Close(); err != nil {
		t.Fatalf("release UDP port: %v", err)
	}
	return addr
}

// newPhase35QUICClient serves handler on a loopback QUIC listener and connects
// the SDK's QUIC adapter to it, so a call travels the client's opcodes and
// payloads through the daemon's category dispatch and back. The connection is
// mutual TLS: the client presents bundle's client certificate. opts add to
// the client's connection options.
func newPhase35QUICClient(t *testing.T, handler *QUICServiceHandler, bundle *testutil.TestTLSBundle, opts ...platform.Option) transport.Adapter {
	t.Helper()
	serverTLS := bundle.ServerTLSConfig()
	serverTLS.NextProtos = []string{quicwire.ALPNProtocol}
	addr := reserveUDPPort(t)

	server, err := quic.NewServer(&quic.ServerConfig{ListenAddr: addr, TLSConfig: serverTLS}, quic.WithHandler(handler))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})

	a, err := sdkquic.Connect(context.Background(), platform.NewOptions(append([]platform.Option{
		platform.WithQUICAddr(addr),
		platform.WithTLSConfig(bundle.ClientTLSConfig()),
		platform.WithTLSServerName("localhost"),
	}, opts...)...))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return a
}

// newMTLSQUICAuthMiddleware builds the auth middleware the daemon installs for
// QUIC under EnableMTLS, trusting bundle's CA: the client certificate becomes
// the request's principal.
func newMTLSQUICAuthMiddleware(t *testing.T, bundle *testutil.TestTLSBundle) *quic.AuthMiddleware {
	t.Helper()
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSOperatorTrustDomain = testOperatorTrustDomain
	mw, _, err := selectQUICAuth(config, nil, bundle.CAPool, nil, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("selectQUICAuth: %v", err)
	}
	return mw
}

func mtlsQUICAuth(t *testing.T, bundle *testutil.TestTLSBundle) QUICServiceHandlerOption {
	t.Helper()
	return WithQUICAuthMiddleware(newMTLSQUICAuthMiddleware(t, bundle))
}

// mtlsAuthenticatedQUICContext authenticates req as the QUIC listener does for
// a connection that presented bundle's client certificate, and returns the
// context the category handlers then run under.
func mtlsAuthenticatedQUICContext(t *testing.T, req *quicwire.Request) context.Context {
	t.Helper()
	bundle := operatorTLSBundle(t)
	state := &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{leafOf(t, bundle.ClientCert), bundle.CACert}},
	}
	ctx, resp := newMTLSQUICAuthMiddleware(t, bundle).AuthenticateRequest(
		quic.WithConnectionTLS(context.Background(), state), req)
	if resp != nil {
		t.Fatalf("AuthenticateRequest: status %d: %s", resp.Status, resp.Payload)
	}
	return ctx
}

// newPhase35QUICHandler builds a handler with the phase-3.5 services. Without
// an auth option it authenticates the transport peer but attaches no
// principal (see newTestQUICServiceHandler).
func newPhase35QUICHandler(opts ...QUICServiceHandlerOption) *QUICServiceHandler {
	h := newTestQUICServiceHandler(logging.DefaultLogger(), opts...)
	ceremony, piv, fido := phase35Services()
	h.SetCeremonyService(ceremony)
	h.SetPIVService(piv)
	h.SetFIDO2Service(fido)
	return h
}

// TestPhase35QUICClientAgainstDaemonHandler drives every ceremony, PIV and
// FIDO2 method of the SDK QUIC client through a real QUIC listener into the
// daemon's handler, authenticated by its client certificate as in production.
// A sub-opcode the daemon does not dispatch, a payload it cannot decode, or a
// reply the client cannot translate fails here.
func TestPhase35QUICClientAgainstDaemonHandler(t *testing.T) {
	bundle := operatorTLSBundle(t)
	h := newPhase35QUICHandler(mtlsQUICAuth(t, bundle))

	runPhase35SDKCases(t, newPhase35QUICClient(t, h, bundle).Connection())
}

// TestPhase35QUICClientAgainstDaemonHandler_AnonymousIsRefused proves the
// category operations fail closed: a handler that attaches no principal to
// the request refuses every one of them, even over a verified TLS connection.
func TestPhase35QUICClientAgainstDaemonHandler_AnonymousIsRefused(t *testing.T) {
	bundle := testutil.GenerateTestTLSBundle(t)
	conn := newPhase35QUICClient(t, newPhase35QUICHandler(), bundle).Connection()

	for _, tc := range phase35SDKCases() {
		t.Run(tc.method, func(t *testing.T) {
			err := conn.Invoke(context.Background(), tc.method, tc.req, tc.reply)
			if status.Code(err) != codes.PermissionDenied {
				t.Errorf("err = %v, want PermissionDenied for an anonymous caller", err)
			}
		})
	}
}

// TestPhase35QUICClientAgainstDaemonHandler_ServerErrorsSurface proves a
// daemon without the service answers the QUIC client with an error rather
// than an empty reply.
func TestPhase35QUICClientAgainstDaemonHandler_ServerErrorsSurface(t *testing.T) {
	bundle := operatorTLSBundle(t)
	a := newPhase35QUICClient(t, newTestQUICServiceHandler(logging.DefaultLogger(), mtlsQUICAuth(t, bundle)), bundle)

	err := a.Connection().Invoke(context.Background(), platformv1.PIVService_ListDevices_FullMethodName,
		&platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v, want Unavailable for a daemon without PIV", err)
	}
}
