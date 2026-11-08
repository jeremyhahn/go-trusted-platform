// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build codec_msgpack

package daemon

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	sdnrest "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/sdn"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	sdkunix "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// sdnPortAuthParityFixture is one SDN service, holding the bridge and port
// the requests name, served by the daemon's handler on every transport.
type sdnPortAuthParityFixture struct {
	svc *SDNService
	tls *testutil.TestTLSBundle
}

func newSDNPortAuthParityFixture(t *testing.T) *sdnPortAuthParityFixture {
	t.Helper()
	svc := &SDNService{
		bridges: map[string]*bridgeResource{"br0": {id: "uuid-1", name: "br0"}},
		ports:   map[string]*portResource{"port0": {id: "uuid-2", name: "port0", bridgeID: "br0"}},
		taps:    make(map[string]*tapResource),
		vlans:   make(map[string]*vlanResource),
	}
	return &sdnPortAuthParityFixture{svc: svc, tls: testutil.GenerateTestTLSBundle(t)}
}

func (f *sdnPortAuthParityFixture) register(srv grpc.ServiceRegistrar) {
	platformv1.RegisterSDNServiceServer(srv, f.svc)
}

func (f *sdnPortAuthParityFixture) grpcClient(t *testing.T) platformv1.SDNServiceClient {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.register, grpc.Creds(credentials.NewTLS(f.tls.ServerTLSConfig())))
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
	))
	return platformv1.NewSDNServiceClient(connection(t, adapter, err))
}

func (f *sdnPortAuthParityFixture) unixClient(t *testing.T) platformv1.SDNServiceClient {
	// A unix socket path must fit in 108 bytes; t.TempDir can exceed it.
	dir, err := os.MkdirTemp("", "sdn-parity")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.register)
	adapter, err := sdkunix.Connect(context.Background(), platform.NewOptions(platform.WithUnixSocket(socket)))
	return platformv1.NewSDNServiceClient(connection(t, adapter, err))
}

func (f *sdnPortAuthParityFixture) restClient(t *testing.T) platformv1.SDNServiceClient {
	logger := logging.DefaultLogger()
	router := mux.NewRouter()
	sdnrest.NewSDNRouter(logger, f.svc, response.NewResponseWriter(logger, nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	// The SDK's REST Connect probes GET /health/live, which the daemon serves
	// on every REST listener.
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
	return platformv1.NewSDNServiceClient(connection(t, adapter, err))
}

func (f *sdnPortAuthParityFixture) quicClient(t *testing.T) platformv1.SDNServiceClient {
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"sdn:*"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	return platformv1.NewSDNServiceClient(serveQUIC(t, f.tls, handler))
}

func (f *sdnPortAuthParityFixture) mcpClient(t *testing.T) platformv1.SDNServiceClient {
	srv := httptest.NewServer(mcpToolBridge(t, f.toolRegistry()))
	t.Cleanup(srv.Close)
	adapter, err := sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
	return platformv1.NewSDNServiceClient(connection(t, adapter, err))
}

func (f *sdnPortAuthParityFixture) embeddedClient(t *testing.T) platformv1.SDNServiceClient {
	adapter, err := embedded.New(&embedded.ServiceRegistry{SDN: f.svc})
	return platformv1.NewSDNServiceClient(connection(t, adapter, err))
}

func (f *sdnPortAuthParityFixture) toolRegistry() *mcp.ToolRegistry {
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{SDNService: f.svc})
	return mcp.NewToolRegistry(provider, logging.DefaultLogger())
}

// No transport authenticates a port, or revokes its authentication, while
// the switch does not enforce port authentication: a self-signed certificate
// for a port that exists is refused everywhere (#304). Every transport that
// reaches the SDN service carries its FailedPrecondition refusal.
func TestSDNPortAuthParity(t *testing.T) {
	f := newSDNPortAuthParityFixture(t)
	ctx := context.Background()
	selfSigned := generateTestCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	authReq := &platformv1.AuthenticatePortRequest{
		BridgeId: "br0", PortId: "port0", Certificate: selfSigned, Format: "PEM",
	}
	revokeReq := &platformv1.RevokePortAuthRequest{BridgeId: "br0", PortId: "port0"}

	transports := []struct {
		name       string
		client     func(*testing.T) platformv1.SDNServiceClient
		wantAuth   codes.Code
		wantRevoke codes.Code
	}{
		{"gRPC", f.grpcClient, codes.FailedPrecondition, codes.FailedPrecondition},
		{"Unix", f.unixClient, codes.FailedPrecondition, codes.FailedPrecondition},
		{"Embedded", f.embeddedClient, codes.FailedPrecondition, codes.FailedPrecondition},
		// REST answers 409, the platform's status for FailedPrecondition
		// (#665). The SDK's REST transport reads a 409 as AlreadyExists,
		// except on a DELETE (RevokePortAuth), which it reads as
		// FailedPrecondition.
		{"REST", f.restClient, codes.AlreadyExists, codes.FailedPrecondition},
		// The SDK's QUIC and MCP transports map no port-auth call (QUIC has
		// no opcode for it), so they refuse before anything is sent.
		{"QUIC", f.quicClient, codes.Unimplemented, codes.Unimplemented},
		{"MCP", f.mcpClient, codes.Unimplemented, codes.Unimplemented},
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			client := tr.client(t)

			authResp, err := client.AuthenticatePort(ctx, authReq)
			assert.Nil(t, authResp)
			assert.Equal(t, tr.wantAuth, status.Code(err), "AuthenticatePort: %v", err)

			revokeResp, err := client.RevokePortAuth(ctx, revokeReq)
			assert.Nil(t, revokeResp)
			assert.Equal(t, tr.wantRevoke, status.Code(err), "RevokePortAuth: %v", err)
		})
	}

	// The MCP server answers a tools/call with the class of the tool's
	// error; the port-auth tools give the service's FailedPrecondition.
	t.Run("MCP tools", func(t *testing.T) {
		registry := f.toolRegistry()
		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "port0",
			"credentials": map[string]interface{}{"certificate": string(selfSigned)},
		}
		for _, tool := range []string{"sdn_authenticate_port", "sdn_revoke_port_auth"} {
			result, err := registry.ExecuteTool(ctx, tool, args)
			assert.Nil(t, result, tool)
			var refusal policy.ErrPortAuthNotEnforced
			require.ErrorAs(t, err, &refusal, tool)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), tool)
		}
	})
}
