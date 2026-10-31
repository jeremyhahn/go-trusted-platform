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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	sdkquic "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	sdkunix "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// recordingCA issues one fixed certificate and records the request it was
// asked to issue, so each transport's request translation can be compared.
type recordingCA struct {
	configurableMockCA
	last atomic.Pointer[xkmsca.CACertificateRequest]
}

func (c *recordingCA) IssueCertificate(ctx context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	c.last.Store(req)
	return c.configurableMockCA.IssueCertificate(ctx, req)
}

// IssueCertificateWithProfile issues as IssueCertificate.
func (c *recordingCA) IssueCertificateWithProfile(ctx context.Context, req *xkmsca.CACertificateRequest, _ string) (*xkmsca.IssuedCertificate, error) {
	return c.IssueCertificate(ctx, req)
}

// caParityFixture is one CA served by the daemon's handler for every
// transport, and the TLS material the network transports share.
type caParityFixture struct {
	ca     *recordingCA
	svc    *CAGRPCService
	tls    *testutil.TestTLSBundle
	serial string
}

// newCAParityFixture builds a CA whose certificate sets every field the
// gRPC service reports: a full subject, all four SAN kinds, key usages,
// extended key usages and a path length.
func newCAParityFixture(t *testing.T) *caParityFixture {
	t.Helper()
	root, rootKey := parityCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Parity Root"},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	leaf, _ := parityCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(0x5a17e5),
		Subject: pkix.Name{
			CommonName:         "parity.example",
			Organization:       []string{"Parity Org"},
			OrganizationalUnit: []string{"Parity Unit"},
			Country:            []string{"US"},
			Province:           []string{"Ohio"},
			Locality:           []string{"Columbus"},
			StreetAddress:      []string{"1 Parity Way"},
			PostalCode:         []string{"43004"},
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		DNSNames:              []string{"parity.example"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.7")},
		EmailAddresses:        []string{"ops@parity.example"},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "parity", Path: "/leaf"}},
	}, root, rootKey)

	serial := hex.EncodeToString(leaf.SerialNumber.Bytes())
	ca := &recordingCA{configurableMockCA: configurableMockCA{
		trustedRoot: root,
		issuedCert:  leaf,
		certStore:   &mockCertStore{certs: map[string]*x509.Certificate{serial: leaf}},
	}}
	return &caParityFixture{
		ca:     ca,
		svc:    NewCAGRPCService(logging.DefaultLogger(), ca, nil),
		tls:    testutil.GenerateTestTLSBundle(t),
		serial: serial,
	}
}

// parityCertificate signs template with parentKey, or self-signs it when
// parent is nil, and returns the parsed certificate and its key.
func parityCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template.NotBefore = now.Add(-time.Hour)
	template.NotAfter = now.Add(24 * time.Hour)
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// connect wraps an SDK adapter as a CA client and closes it after the test.
func connect(t *testing.T, adapter transport.Adapter, err error) platformv1.CAServiceClient {
	t.Helper()
	return platformv1.NewCAServiceClient(connection(t, adapter, err))
}

// connection returns an SDK adapter's connection and closes the adapter
// after the test.
func connection(t *testing.T, adapter transport.Adapter, err error) grpc.ClientConnInterface {
	t.Helper()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return adapter.Connection()
}

// serveGRPC serves the CA service on lis until the test ends.
func serveGRPC(t *testing.T, svc *CAGRPCService, lis net.Listener, opts ...grpc.ServerOption) {
	t.Helper()
	serveGRPCServices(t, lis, func(srv grpc.ServiceRegistrar) { platformv1.RegisterCAServiceServer(srv, svc) }, opts...)
}

// serveGRPCServices serves the services register adds on lis until the test
// ends.
func serveGRPCServices(t *testing.T, lis net.Listener, register func(grpc.ServiceRegistrar), opts ...grpc.ServerOption) {
	t.Helper()
	srv := grpc.NewServer(opts...)
	register(srv)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		// Stop can win the race with Serve's start; Serve then returns ErrServerStopped, its other clean-shutdown result.
		if err := <-done; !errors.Is(err, grpc.ErrServerStopped) {
			assert.NoError(t, err)
		}
	})
}

func (f *caParityFixture) grpcClient(t *testing.T) platformv1.CAServiceClient {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPC(t, f.svc, lis, grpc.Creds(credentials.NewTLS(f.tls.ServerTLSConfig())))
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
	))
	return connect(t, adapter, err)
}

func (f *caParityFixture) unixClient(t *testing.T) platformv1.CAServiceClient {
	// A unix socket path must fit in 108 bytes; t.TempDir can exceed it.
	dir, err := os.MkdirTemp("", "ca-parity")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	serveGRPC(t, f.svc, lis)
	adapter, err := sdkunix.Connect(context.Background(), platform.NewOptions(platform.WithUnixSocket(socket)))
	return connect(t, adapter, err)
}

func (f *caParityFixture) restClient(t *testing.T) platformv1.CAServiceClient {
	router := mux.NewRouter()
	// Every daemon CA certificate route checks its scope; the client's token
	// holds the four the CA certificate routes take.
	const operatorToken = "ca-operator"
	guard := restapi.NewScopeGuard(tokenScopes{
		operatorToken: {"certs:generate", "certs:list", "certs:read", "certs:revoke"},
	}, nil, nil)
	restapi.NewCAHandlers(restapi.NewCAAuthorityAdapter(f.ca), nil, nil).WithScopeGuard(guard).RegisterRoutes(router)
	// The SDK's REST Connect probes GET /health, which the daemon serves on
	// every REST listener.
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
		platform.WithBearerToken(operatorToken),
	))
	return connect(t, adapter, err)
}

func (f *caParityFixture) quicClient(t *testing.T) platformv1.CAServiceClient {
	// The CA's certificates are go-qrdb's certs family; its metadata,
	// bundle and CRL are ca.
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"ca:*", "certs:*"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	handler.SetCAHandler(quic.NewCAHandler(logging.DefaultLogger(), f.ca, nil))
	return serveQUICCA(t, f.tls, handler)
}

// serveQUICCA serves handler on a daemon QUIC server until the test ends and
// returns an SDK QUIC client for it that presents the token "tok".
func serveQUICCA(t *testing.T, tlsBundle *testutil.TestTLSBundle, handler *QUICServiceHandler) platformv1.CAServiceClient {
	t.Helper()
	return platformv1.NewCAServiceClient(serveQUIC(t, tlsBundle, handler))
}

// serveQUIC serves handler on a daemon QUIC server until the test ends and
// returns an SDK QUIC connection to it that presents the token "tok".
func serveQUIC(t *testing.T, tlsBundle *testutil.TestTLSBundle, handler *QUICServiceHandler) grpc.ClientConnInterface {
	t.Helper()
	config := quic.DefaultServerConfig()
	config.ListenAddr = "127.0.0.1:0"
	config.TLSConfig = tlsBundle.ServerTLSConfig()
	config.TLSConfig.NextProtos = []string{"platform-quic"}
	srv, err := quic.NewServer(config, quic.WithHandler(handler))
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	adapter, err := sdkquic.Connect(context.Background(), platform.NewOptions(
		platform.WithQUICAddr(srv.ListenAddr()),
		platform.WithTLSConfig(tlsBundle.ClientTLSConfig()),
	))
	require.NoError(t, err)
	adapter.(*sdkquic.Adapter).SetToken("tok")
	return connection(t, adapter, err)
}

func (f *caParityFixture) mcpClient(t *testing.T) platformv1.CAServiceClient {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{CAService: f.svc})
	srv := httptest.NewServer(mcpToolBridge(t, mcp.NewToolRegistry(provider, logging.DefaultLogger())))
	t.Cleanup(srv.Close)
	adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
	return connect(t, adapter, err)
}

func (f *caParityFixture) embeddedClient(t *testing.T) platformv1.CAServiceClient {
	adapter, err := embedded.New(&embedded.ServiceRegistry{CA: f.svc})
	return connect(t, adapter, err)
}

// mcpToolBridge answers tools/call from the platform's tool registry, as the
// MCP server does once a call is authorized. The server refuses ca_issue and
// ca_get for every caller until they are classified (#304, docs/ca/api.md
// §4), so the bridge exercises the wire format each side speaks without
// reaching around that refusal in the server.
func mcpToolBridge(t *testing.T, registry *mcp.ToolRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpwire.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := &mcpwire.JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}
		if req.Method == "tools/call" {
			result, err := callTool(r.Context(), registry, req.Params)
			if err != nil {
				resp.Result = nil
				// Classified as the MCP server does, so a caller error stays one.
				resp.Error = &mcpwire.JSONRPCError{Code: mcpwire.CodeForClass(status.Code(err)), Message: err.Error()}
			} else {
				resp.Result = result
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("write MCP response: %v", err)
		}
	})
}

// errBridgeParams reports tools/call params the bridge cannot read.
type errBridgeParams struct{}

func (errBridgeParams) Error() string { return "tools/call params need a name and an arguments object" }

func callTool(ctx context.Context, registry *mcp.ToolRegistry, params interface{}) (interface{}, error) {
	p, ok := params.(map[string]interface{})
	if !ok {
		return nil, errBridgeParams{}
	}
	name, ok := p["name"].(string)
	if !ok {
		return nil, errBridgeParams{}
	}
	args, ok := p["arguments"].(map[string]interface{})
	if !ok {
		return nil, errBridgeParams{}
	}
	output, err := registry.ExecuteTool(ctx, name, args)
	if err != nil {
		return nil, err
	}
	// Answered as the MCP server answers tools/call: a CallToolResult.
	return mcpwire.NewCallToolResult(output)
}

// assertSameCertificate compares a transport's certificate with the gRPC
// service's.
func assertSameCertificate(t *testing.T, want, got *platformv1.Certificate) {
	t.Helper()
	assert.True(t, proto.Equal(want, got), "certificate differs from gRPC\nwant %s\ngot  %s",
		protojson.Format(want), protojson.Format(got))
}

// A certificate issued or read over any transport carries every field the
// gRPC service returns, and every transport asks the CA for the same
// certificate (#691).
func TestCACertificateParity(t *testing.T) {
	f := newCAParityFixture(t)
	ctx := context.Background()
	issueReq := &platformv1.IssueCertificateRequest{Request: &platformv1.CertificateRequest{
		Subject: &platformv1.Subject{
			CommonName:         "parity.example",
			Organization:       "Parity Org",
			OrganizationalUnit: "Parity Unit",
			Country:            "US",
			Province:           "Ohio",
			Locality:           "Columbus",
			Address:            "1 Parity Way",
			PostalCode:         "43004",
		},
		Sans: &platformv1.SubjectAlternativeNames{
			DnsNames:       []string{"parity.example"},
			IpAddresses:    []string{"192.0.2.7"},
			EmailAddresses: []string{"ops@parity.example"},
			Uris:           []string{"spiffe://parity/leaf"},
		},
		ValidDays:    90,
		KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P384,
		StoreType:    "software",
		KeyUsage:     []string{"DIGITAL_SIGNATURE", "CERT_SIGN"},
		ExtKeyUsage:  []string{"SERVER_AUTH", "CLIENT_AUTH"},
		IsCa:         true,
		MaxPathLen:   2,
	}}
	getReq := &platformv1.GetCertificateRequest{Serial: f.serial, IncludePem: true, IncludeDer: true}

	wantIssued, err := f.svc.IssueCertificate(ctx, issueReq)
	require.NoError(t, err)
	wantCARequest := f.ca.last.Load()
	wantGot, err := f.svc.GetCertificate(ctx, getReq)
	require.NoError(t, err)
	require.NotEmpty(t, wantGot.GetCertificate().GetDer())

	transports := []struct {
		name   string
		client func(*testing.T) platformv1.CAServiceClient
	}{
		{"gRPC", f.grpcClient},
		{"Unix", f.unixClient},
		{"REST", f.restClient},
		{"QUIC", f.quicClient},
		{"MCP", f.mcpClient},
		{"Embedded", f.embeddedClient},
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			client := tr.client(t)
			f.ca.last.Store(nil)

			issued, err := client.IssueCertificate(ctx, issueReq)
			require.NoError(t, err)
			assert.Equal(t, wantCARequest, f.ca.last.Load(), "the request the CA received")
			assert.True(t, proto.Equal(wantIssued.GetStatus(), issued.GetStatus()),
				"status = %v, want %v", issued.GetStatus(), wantIssued.GetStatus())
			assert.NotNil(t, issued.GetTimestamp())
			assertSameCertificate(t, wantIssued.GetCertificate(), issued.GetCertificate())

			got, err := client.GetCertificate(ctx, getReq)
			require.NoError(t, err)
			assert.NotNil(t, got.GetTimestamp())
			assertSameCertificate(t, wantGot.GetCertificate(), got.GetCertificate())
		})
	}
}

// A subordinate CA beneath a pathLen-0 issuer is refused on every transport
// as the same invalid request, carrying the refusal's message, and no
// transport asks the CA to sign it (docs/ca/api.md, path length).
func TestCAPathLenRefusalParity(t *testing.T) {
	f := newCAParityFixture(t)
	f.ca.caCertificate = pathLenZeroIssuer()
	ctx := context.Background()

	transports := []struct {
		name   string
		client func(*testing.T) platformv1.CAServiceClient
	}{
		{"gRPC", f.grpcClient},
		{"Unix", f.unixClient},
		{"REST", f.restClient},
		{"QUIC", f.quicClient},
		{"MCP", f.mcpClient},
		{"Embedded", f.embeddedClient},
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			client := tr.client(t)
			f.ca.last.Store(nil)

			_, err := client.IssueCertificate(ctx, subCARequest())
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "error = %v", err)
			assert.Contains(t, status.Convert(err).Message(), pathLenZeroRefusal())
			assert.Nil(t, f.ca.last.Load(), "the CA was asked to sign a refused subordinate CA")
		})
	}
}
