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

//go:build codec_msgpack

package daemon

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	resttpm "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/tpm"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdktpm "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	sdkunix "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// tpmParityFixture is one TPM served by the daemon's TPM service on every
// transport, and the TLS material the network transports share.
type tpmParityFixture struct {
	tpm *certifyingTPM
	svc *TPMGRPCService
	tls *testutil.TestTLSBundle
}

func newTPMParityFixture(t *testing.T) *tpmParityFixture {
	t.Helper()
	tpm := newCertifyingTPM(t)
	svc := NewTPMGRPCService(logging.DefaultLogger())
	svc.SetTPM2Service(tpm)
	return &tpmParityFixture{tpm: tpm, svc: svc, tls: testutil.GenerateTestTLSBundle(t)}
}

// tpmTransport opens an SDK connection to the fixture's TPM over one
// transport.
type tpmTransport func(t *testing.T) grpc.ClientConnInterface

// boundTransports carry TLS, so the node binds a quote to the connection.
func (f *tpmParityFixture) boundTransports() map[string]tpmTransport {
	return map[string]tpmTransport{
		"gRPC":        f.grpcConn,
		"REST":        f.restConn,
		"daemon REST": f.daemonRESTConn("tpm:read"),
		"QUIC":        f.quicConn,
	}
}

// unboundTransports have no TLS connection to bind a quote to.
func (f *tpmParityFixture) unboundTransports() map[string]tpmTransport {
	return map[string]tpmTransport{"Unix": f.unixConn, "MCP": f.mcpConn, "Embedded": f.embeddedConn}
}

func (f *tpmParityFixture) client(t *testing.T, open tpmTransport) *sdktpm.Client {
	return sdktpm.NewClientFromGRPC(platformv1.NewTPMServiceClient(open(t)))
}

func (f *tpmParityFixture) registerTPM(srv grpc.ServiceRegistrar) {
	platformv1.RegisterTPMServiceServer(srv, f.svc)
}

func (f *tpmParityFixture) grpcConn(t *testing.T) grpc.ClientConnInterface {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.registerTPM, grpc.Creds(credentials.NewTLS(f.tls.ServerTLSConfig())))
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
	))
	return connection(t, adapter, err)
}

func (f *tpmParityFixture) unixConn(t *testing.T) grpc.ClientConnInterface {
	// A unix socket path must fit in 108 bytes; t.TempDir can exceed it.
	dir, err := os.MkdirTemp("", "tpm-parity")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.registerTPM)
	adapter, err := sdkunix.Connect(context.Background(), platform.NewOptions(platform.WithUnixSocket(socket)))
	return connection(t, adapter, err)
}

// restConn serves the /api/v1/tpm routes the web service mounts.
func (f *tpmParityFixture) restConn(t *testing.T) grpc.ClientConnInterface {
	logger := logging.DefaultLogger()
	router := mux.NewRouter()
	resttpm.NewTPMRouter(logger, f.svc, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	// The SDK's REST Connect probes GET /health.
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	srv := httptest.NewUnstartedServer(router)
	srv.TLS = f.tls.ServerTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(srv.URL),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
	))
	return connection(t, adapter, err)
}

// daemonRESTConn serves the /api/v1/tpm routes platformd mounts on its own
// REST listener, to a caller whose bearer token grants scopes.
func (f *tpmParityFixture) daemonRESTConn(scopes ...string) tpmTransport {
	return func(t *testing.T) grpc.ClientConnInterface {
		const token = "tpm-caller"
		router := mux.NewRouter()
		restapi.NewTPMHandlers(slog.Default()).
			WithTPMService(f.svc).
			WithScopeGuard(restapi.NewScopeGuard(tokenScopes{token: scopes}, nil, nil)).
			RegisterRoutes(router)
		router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}).Methods(http.MethodGet)
		srv := httptest.NewUnstartedServer(router)
		srv.TLS = f.tls.ServerTLSConfig()
		srv.StartTLS()
		t.Cleanup(srv.Close)
		adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
			platform.WithRESTAddr(srv.URL),
			platform.WithTLSConfig(f.tls.ClientTLSConfig()),
			platform.WithBearerToken(token),
		))
		return connection(t, adapter, err)
	}
}

// quicConn serves the 0x99 category to a caller holding only tpm:read, the
// scope Quote and VerifyQuote need.
func (f *tpmParityFixture) quicConn(t *testing.T) grpc.ClientConnInterface {
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"tpm:read"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth), WithQUICTPM2Service(f.tpm))
	require.NoError(t, err)
	return serveQUIC(t, f.tls, handler)
}

// mcpConn serves the quote tools the daemon's MCP provider builds on the TPM.
func (f *tpmParityFixture) mcpConn(t *testing.T) grpc.ClientConnInterface {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{TPM2Service: f.tpm, Logger: slog.Default()})
	srv := httptest.NewServer(mcpToolBridge(t, mcp.NewToolRegistry(provider, logging.DefaultLogger())))
	t.Cleanup(srv.Close)
	adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
	return connection(t, adapter, err)
}

func (f *tpmParityFixture) embeddedConn(t *testing.T) grpc.ClientConnInterface {
	adapter, err := embedded.New(&embedded.ServiceRegistry{TPM: f.svc})
	return connection(t, adapter, err)
}

// verifyRequest asks to verify q against akPublic under the scheme q declares.
func verifyRequest(q *platformv1.QuoteResponse, nonce, akPublic []byte) *platformv1.VerifyQuoteRequest {
	return &platformv1.VerifyQuoteRequest{
		Quote:              q.GetQuote(),
		Signature:          q.GetSignature(),
		Nonce:              nonce,
		ChannelBinding:     q.GetChannelBinding(),
		AkPublic:           akPublic,
		SignatureAlgorithm: q.GetSignatureAlgorithm(),
	}
}

func quoteOver(t *testing.T, client *sdktpm.Client, nonce []byte) (*platformv1.QuoteResponse, error) {
	t.Helper()
	return client.Quote(context.Background(), 0, "", []uint32{0, 7}, platformv1.PCRBank_PCR_BANK_SHA256, nonce)
}

// TestTPMQuoteParity_AQuoteVerifies: a quote produced through each TLS
// transport is bound to that connection and verifies through it, against
// the AK it names (#482).
func TestTPMQuoteParity_AQuoteVerifies(t *testing.T) {
	f := newTPMParityFixture(t)
	for name, open := range f.boundTransports() {
		t.Run(name, func(t *testing.T) {
			client := f.client(t, open)
			nonce := []byte("parity nonce " + name)

			q, err := quoteOver(t, client, nonce)
			require.NoError(t, err)
			assert.Equal(t, testutil.PSSQuoteScheme, q.GetSignatureAlgorithm())
			assert.NotEmpty(t, q.GetChannelBinding())

			v, err := client.VerifyQuote(context.Background(), verifyRequest(q, nonce, f.tpm.akPublic()))
			require.NoError(t, err)
			assert.True(t, v.GetVerified(), v.GetMessage())
		})
	}
}

// TestTPMQuoteParity_RefusesAWrongSchemeOrAK: every transport verifies one
// quote under the scheme it declares and the key that signed it, and
// refuses it under any other (#482).
func TestTPMQuoteParity_RefusesAWrongSchemeOrAK(t *testing.T) {
	f := newTPMParityFixture(t)
	nonce := []byte("parity refusal")
	q, err := quoteOver(t, f.client(t, f.grpcConn), nonce)
	require.NoError(t, err)
	akPublic := f.tpm.akPublic()
	_, otherAK := testutil.SignPSSQuote(t, []byte("another key"))

	refusals := map[string]func(*platformv1.VerifyQuoteRequest){
		"PKCS#1 v1.5 scheme": func(r *platformv1.VerifyQuoteRequest) { r.SignatureAlgorithm = x509.SHA256WithRSA.String() },
		"undeclared scheme":  func(r *platformv1.VerifyQuoteRequest) { r.SignatureAlgorithm = "" },
		"another AK":         func(r *platformv1.VerifyQuoteRequest) { r.AkPublic = otherAK },
	}
	transports := f.boundTransports()
	for name, open := range f.unboundTransports() {
		transports[name] = open
	}
	for name, open := range transports {
		t.Run(name, func(t *testing.T) {
			client := f.client(t, open)

			v, err := client.VerifyQuote(context.Background(), verifyRequest(q, nonce, akPublic))
			require.NoError(t, err)
			require.True(t, v.GetVerified(), "the quote as produced: %s", v.GetMessage())

			for label, mutate := range refusals {
				req := verifyRequest(q, nonce, akPublic)
				mutate(req)
				v, err := client.VerifyQuote(context.Background(), req)
				require.NoError(t, err, label)
				assert.False(t, v.GetVerified(), label)
				assert.Contains(t, v.GetMessage(), "signature_verification_failed", label)
			}
		})
	}
}

// TestTPMQuoteParity_UnboundTransportsRefuseAQuote: a transport with no TLS
// connection cannot bind a quote, so the SDK refuses it with the typed error
// and the TPM never quotes.
func TestTPMQuoteParity_UnboundTransportsRefuseAQuote(t *testing.T) {
	f := newTPMParityFixture(t)
	for name, open := range f.unboundTransports() {
		t.Run(name, func(t *testing.T) {
			_, err := quoteOver(t, f.client(t, open), []byte("unbound"))
			var failed *sdktpm.ErrQuoteFailed
			require.ErrorAs(t, err, &failed)
			var unavailable *transport.ErrChannelBindingUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Nil(t, f.tpm.akPublic(), "the TPM must not quote")
		})
	}
}

// TestTPMQuoteParity_DaemonRESTNeedsTPMRead: platformd's REST listener
// quotes and verifies only for a bearer token granting tpm:read, and the SDK
// reports the refusal as PermissionDenied (#482).
func TestTPMQuoteParity_DaemonRESTNeedsTPMRead(t *testing.T) {
	f := newTPMParityFixture(t)
	client := f.client(t, f.daemonRESTConn("tpm:write"))
	nonce := []byte("no tpm:read")

	_, err := quoteOver(t, client, nonce)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
	assert.Nil(t, f.tpm.akPublic(), "the TPM must not quote")

	_, err = client.VerifyQuote(context.Background(), &platformv1.VerifyQuoteRequest{Nonce: nonce})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), err)
}
