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
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restdns "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/dns"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	sdkgrpc "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	sdkmcp "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	sdkunix "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// dnsParityFixture serves the DNS service a daemon built from one config
// exposes, over every transport. backend is the DNS service platformd starts
// (config.DNSService), or nil for a node without a dns: section; svc is the
// servicer the daemon registers on its gRPC and Unix servers.
type dnsParityFixture struct {
	backend dns.DNSService
	daemon  *Daemon
	svc     *DNSServiceServer
	tls     *testutil.TestTLSBundle
}

func newDNSParityFixture(t *testing.T, backend dns.DNSService) *dnsParityFixture {
	t.Helper()
	// A unix socket path must fit in 108 bytes; t.TempDir can exceed it.
	dir, err := os.MkdirTemp("", "dns-parity")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })

	config := testConfig(filepath.Join(dir, "platformd.sock"))
	if backend != nil {
		config.DNSService = backend
	}
	d, err := New(config)
	require.NoError(t, err)
	require.NotNil(t, d.DNSGRPCServiceServer())
	return &dnsParityFixture{
		backend: backend,
		daemon:  d,
		svc:     d.DNSGRPCServiceServer(),
		tls:     testutil.GenerateTestTLSBundle(t),
	}
}

// newDNSParityBackend is a real DNS service over in-memory storage.
func newDNSParityBackend(t *testing.T) *dns.Service {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	return newTenantDNSService(t, storage, "parity")
}

type dnsTransport struct {
	name string
	open func(*testing.T) grpc.ClientConnInterface
	// tools, when set, is the client the backend parity test drives instead
	// of the SDK route over open (MCP: see mcpZoneTools).
	tools func(*testing.T) dnsZoneClient
}

// zoneClient is the client the backend parity test drives on tr.
func (tr dnsTransport) zoneClient(t *testing.T) dnsZoneClient {
	if tr.tools != nil {
		return tr.tools(t)
	}
	return platformv1.NewDNSServiceClient(tr.open(t))
}

// transports are the transports platformd serves the DNS service on. REST is
// served by the webservice, which answers 503 SERVICE_NOT_CONFIGURED for a
// node without a backend before any DNS handler runs (requireService in
// pkg/webservice/v1/service_registry.go), so it joins only when a backend is
// present.
func (f *dnsParityFixture) transports(withREST bool) []dnsTransport {
	all := []dnsTransport{
		{name: "gRPC", open: f.grpcConn},
		{name: "Unix", open: f.unixConn},
		{name: "QUIC", open: f.quicConn},
		{name: "MCP", open: f.mcpConn, tools: f.mcpZoneTools},
		{name: "Embedded", open: f.embeddedConn},
	}
	if withREST {
		all = append(all, dnsTransport{name: "REST", open: f.restConn})
	}
	return all
}

func (f *dnsParityFixture) registerDNS(s grpc.ServiceRegistrar) {
	platformv1.RegisterDNSServiceServer(s, f.svc)
}

func (f *dnsParityFixture) grpcConn(t *testing.T) grpc.ClientConnInterface {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.registerDNS, grpc.Creds(credentials.NewTLS(f.tls.ServerTLSConfig())))
	adapter, err := sdkgrpc.Connect(context.Background(), platform.NewOptions(
		platform.WithGRPCAddr(lis.Addr().String()),
		platform.WithTLSConfig(f.tls.ClientTLSConfig()),
	))
	return connection(t, adapter, err)
}

func (f *dnsParityFixture) unixConn(t *testing.T) grpc.ClientConnInterface {
	dir, err := os.MkdirTemp("", "dns-parity")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	serveGRPCServices(t, lis, f.registerDNS)
	adapter, err := sdkunix.Connect(context.Background(), platform.NewOptions(platform.WithUnixSocket(socket)))
	return connection(t, adapter, err)
}

// quicConn wires the backend into the QUIC handler the way New does
// (SetDNSService(config.DNSService)).
func (f *dnsParityFixture) quicConn(t *testing.T) grpc.ClientConnInterface {
	auth := quic.NewAuthMiddleware(
		quic.WithQUICTokenValidator(scopedTokenValidator{scopes: []string{"dns:read", "dns:write"}}),
		quic.WithQUICRequireAuth(true),
	)
	handler, err := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICAuthMiddleware(auth))
	require.NoError(t, err)
	if f.backend != nil {
		handler.SetDNSService(f.backend)
	}
	return serveQUIC(t, f.tls, handler)
}

// mcpConn wires the backend into the MCP provider the way New does
// (MCPServiceProviderConfig.DNSService).
func (f *dnsParityFixture) mcpConn(t *testing.T) grpc.ClientConnInterface {
	adapter, err := f.mcpAdapter(t)
	return connection(t, adapter, err)
}

func (f *dnsParityFixture) mcpAdapter(t *testing.T) (transport.Adapter, error) {
	srv := httptest.NewServer(mcpToolBridge(t, newMCPDNSRegistry(f.backend)))
	t.Cleanup(srv.Close)
	return sdkmcp.Connect(context.Background(), platform.NewOptions(platform.WithMCPAddr(srv.URL)))
}

// mcpZoneTools drives the zone RPCs over the MCP wire through the tools bound
// to them, dns_zone_create and dns_zone_list (docs/dns/api.md §3). The SDK's
// MCP route for DNSService names the older tools instead, and dns_create_zone
// reads a "zone" argument where the request carries "name".
func (f *dnsParityFixture) mcpZoneTools(t *testing.T) dnsZoneClient {
	adapter, err := f.mcpAdapter(t)
	connection(t, adapter, err)
	mcpAdapter, ok := adapter.(*sdkmcp.Adapter)
	require.True(t, ok, "the MCP transport connected a %T", adapter)
	return mcpZoneTools{client: mcpAdapter.Client()}
}

// dnsZoneClient is the part of DNSService the backend parity test drives.
type dnsZoneClient interface {
	CreateZone(ctx context.Context, in *platformv1.CreateZoneRequest, opts ...grpc.CallOption) (*platformv1.CreateZoneResponse, error)
	ListZones(ctx context.Context, in *platformv1.ListZonesRequest, opts ...grpc.CallOption) (*platformv1.ListZonesResponse, error)
}

// mcpZoneTools sends each request as the bound tool's arguments, in the
// request message's JSON form, and reads the tool's result as the response.
type mcpZoneTools struct {
	client *mcpwire.Client
}

func (m mcpZoneTools) CreateZone(ctx context.Context, in *platformv1.CreateZoneRequest, _ ...grpc.CallOption) (*platformv1.CreateZoneResponse, error) {
	out := &platformv1.CreateZoneResponse{}
	return out, m.call(ctx, "dns_zone_create", in, out)
}

func (m mcpZoneTools) ListZones(ctx context.Context, in *platformv1.ListZonesRequest, _ ...grpc.CallOption) (*platformv1.ListZonesResponse, error) {
	out := &platformv1.ListZonesResponse{}
	return out, m.call(ctx, "dns_zone_list", in, out)
}

func (m mcpZoneTools) call(ctx context.Context, tool string, in, out proto.Message) error {
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(in)
	if err != nil {
		return err
	}
	args := map[string]interface{}{}
	if err := json.Unmarshal(data, &args); err != nil {
		return err
	}
	result, err := m.client.CallTool(ctx, tool, args)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(encoded, out)
}

// embeddedConn serves the registry the daemon hands the embedded transport.
func (f *dnsParityFixture) embeddedConn(t *testing.T) grpc.ClientConnInterface {
	adapter, err := embedded.New(&embedded.ServiceRegistry{DNS: f.daemon.embeddedServices().DNS})
	return connection(t, adapter, err)
}

func (f *dnsParityFixture) restConn(t *testing.T) grpc.ClientConnInterface {
	logger := logging.DefaultLogger()
	router := mux.NewRouter()
	restdns.NewDNSRouter(logger, f.backend, response.NewResponseWriter(logger, nil)).
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

// TestDNSTransportParity_EveryTransportReachesTheSameBackend: a zone created
// through any transport lands in the DNS service platformd starts, and a zone
// that service holds is listed through every transport. Before #704 the gRPC
// and Unix servicer had no backend at all.
func TestDNSTransportParity_EveryTransportReachesTheSameBackend(t *testing.T) {
	ctx := context.Background()
	backend := newDNSParityBackend(t)
	f := newDNSParityFixture(t, backend)
	seedParityZone(t, NewDNSServiceServer(backend, testLogger()))

	for _, tr := range f.transports(true) {
		t.Run(tr.name, func(t *testing.T) {
			client := tr.zoneClient(t)
			zoneName := strings.ToLower(tr.name) + ".parity.internal."

			_, err := client.CreateZone(ctx, &platformv1.CreateZoneRequest{Name: zoneName, Ttl: 3600, Internal: true})
			require.NoError(t, err)
			stored, err := backend.Zone(ctx, zoneName)
			require.NoError(t, err, "the zone %s created over %s is not in the backend", zoneName, tr.name)
			assert.Equal(t, zoneName, stored.Name)

			listed, err := client.ListZones(ctx, &platformv1.ListZonesRequest{})
			require.NoError(t, err)
			var names []string
			for _, zone := range listed.GetZones() {
				names = append(names, zone.GetName())
			}
			assert.Contains(t, names, parityZone, "the backend's seeded zone")
			assert.Contains(t, names, zoneName)
		})
	}
}

// TestDNSTransportParity_NoBackendAnswersNotConfigured: on a node without a
// DNS backend every transport answers Unavailable, and the transports that
// carry status details name the not-configured service. Before #704 gRPC and
// Unix dereferenced the nil backend.
func TestDNSTransportParity_NoBackendAnswersNotConfigured(t *testing.T) {
	ctx := context.Background()
	f := newDNSParityFixture(t, nil)
	carriesDetails := map[string]bool{"gRPC": true, "Unix": true, "Embedded": true}

	for _, tr := range f.transports(false) {
		t.Run(tr.name, func(t *testing.T) {
			client := platformv1.NewDNSServiceClient(tr.open(t))
			calls := map[string]func() error{
				"list zones": func() error {
					_, err := client.ListZones(ctx, &platformv1.ListZonesRequest{})
					return err
				},
				"create zone": func() error {
					_, err := client.CreateZone(ctx, &platformv1.CreateZoneRequest{Name: parityZone})
					return err
				},
			}
			for name, call := range calls {
				err := call()
				require.Error(t, err, name)
				st, ok := status.FromError(err)
				require.True(t, ok, "%s: %v is not a status", name, err)
				assert.Equal(t, codes.Unavailable, st.Code(), "%s: %v", name, err)
				if carriesDetails[tr.name] {
					assert.Equal(t, "dns", notConfiguredServiceName(t, st), name)
				}
			}
		})
	}
}

// TestDNSServiceServer_NoBackendAnswersNotConfiguredFirst: with no backend
// every handler answers the canonical not-configured status before any other
// work, so even a request its validation would refuse answers Unavailable,
// and none of them dereferences the nil backend.
func TestDNSServiceServer_NoBackendAnswersNotConfiguredFirst(t *testing.T) {
	record := map[string]interface{}{"type": "RECORD_TYPE_A", "a": map[string]interface{}{"name": "www", "value": "10.0.0.1"}}
	handlers := []struct {
		name  string
		call  dnsRPC
		valid map[string]interface{}
	}{
		{"CreateZone", dnsRPCOf((*DNSServiceServer).CreateZone), map[string]interface{}{"name": parityZone}},
		{"GetZone", dnsRPCOf((*DNSServiceServer).GetZone), map[string]interface{}{"name": parityZone}},
		{"UpdateZone", dnsRPCOf((*DNSServiceServer).UpdateZone), map[string]interface{}{"name": parityZone}},
		{"DeleteZone", dnsRPCOf((*DNSServiceServer).DeleteZone), map[string]interface{}{"name": parityZone}},
		{"ListZones", dnsRPCOf((*DNSServiceServer).ListZones), map[string]interface{}{}},
		{"AddRecord", dnsRPCOf((*DNSServiceServer).AddRecord), map[string]interface{}{"zone_name": parityZone, "record": record}},
		{"DeleteRecord", dnsRPCOf((*DNSServiceServer).DeleteRecord), map[string]interface{}{"zone_name": parityZone, "name": "www"}},
		{"UpdateRecord", dnsRPCOf((*DNSServiceServer).UpdateRecord), map[string]interface{}{"zone_name": parityZone, "old_record": record, "new_record": record}},
		{"ListRecords", dnsRPCOf((*DNSServiceServer).ListRecords), map[string]interface{}{"zone_name": parityZone}},
		{"SignZone", dnsRPCOf((*DNSServiceServer).SignZone), map[string]interface{}{"zone_name": parityZone}},
		{"GetDNSSECStatus", dnsRPCOf((*DNSServiceServer).GetDNSSECStatus), map[string]interface{}{"zone_name": parityZone}},
		{"Resolve", dnsRPCOf((*DNSServiceServer).Resolve), map[string]interface{}{"fqdn": "www." + parityZone}},
		{"Register", dnsRPCOf((*DNSServiceServer).Register), map[string]interface{}{"fqdn": "www." + parityZone, "ip": "10.0.0.1"}},
	}
	server := NewDNSServiceServer(nil, testLogger())

	for _, h := range handlers {
		t.Run(h.name, func(t *testing.T) {
			for input, args := range map[string]map[string]interface{}{"valid": h.valid, "empty": {}} {
				resp, err := h.call(t, server, args)
				require.Error(t, err, input)
				assert.Nil(t, resp, input)
				st, ok := status.FromError(err)
				require.True(t, ok, input)
				assert.Equal(t, codes.Unavailable, st.Code(), "%s: %v", input, err)
				assert.Equal(t, "dns", notConfiguredServiceName(t, st), input)
			}
		})
	}
}

// TestDNSServiceServer_WithBackendStillRefusesBadInput: the not-configured
// check does not mask validation: with a backend, a request the handler
// refuses still answers InvalidArgument.
func TestDNSServiceServer_WithBackendStillRefusesBadInput(t *testing.T) {
	server := NewDNSServiceServer(newDNSParityBackend(t), testLogger())
	handlers := map[string]dnsRPC{
		"CreateZone":      dnsRPCOf((*DNSServiceServer).CreateZone),
		"GetZone":         dnsRPCOf((*DNSServiceServer).GetZone),
		"UpdateZone":      dnsRPCOf((*DNSServiceServer).UpdateZone),
		"DeleteZone":      dnsRPCOf((*DNSServiceServer).DeleteZone),
		"AddRecord":       dnsRPCOf((*DNSServiceServer).AddRecord),
		"DeleteRecord":    dnsRPCOf((*DNSServiceServer).DeleteRecord),
		"UpdateRecord":    dnsRPCOf((*DNSServiceServer).UpdateRecord),
		"ListRecords":     dnsRPCOf((*DNSServiceServer).ListRecords),
		"SignZone":        dnsRPCOf((*DNSServiceServer).SignZone),
		"GetDNSSECStatus": dnsRPCOf((*DNSServiceServer).GetDNSSECStatus),
		"Resolve":         dnsRPCOf((*DNSServiceServer).Resolve),
		"Register":        dnsRPCOf((*DNSServiceServer).Register),
	}
	for name, call := range handlers {
		t.Run(name, func(t *testing.T) {
			_, err := call(t, server, map[string]interface{}{})
			assert.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
		})
	}

	// ListZones takes no required field; the backend answers it.
	listed, err := dnsRPCOf((*DNSServiceServer).ListZones)(t, server, map[string]interface{}{})
	require.NoError(t, err)
	assert.Empty(t, listed.(*platformv1.ListZonesResponse).GetZones())
}

// TestDaemon_DNSServicerIsTheOneEveryTransportShares: New hands
// config.DNSService to the servicer it registers on gRPC and Unix, and the
// embedded transport registers that same servicer.
func TestDaemon_DNSServicerIsTheOneEveryTransportShares(t *testing.T) {
	backend := newDNSParityBackend(t)
	f := newDNSParityFixture(t, backend)

	assert.Same(t, backend, f.svc.service, "the servicer's backend")
	assert.Same(t, f.svc, f.daemon.embeddedServices().DNS, "the embedded transport's DNS servicer")
}

// TestDaemon_NoDNSBackendListZonesAnswersNotConfigured is the regression for
// the nil dereference: a daemon built without a dns: section served a
// servicer whose ListZones called a nil backend.
func TestDaemon_NoDNSBackendListZonesAnswersNotConfigured(t *testing.T) {
	f := newDNSParityFixture(t, nil)

	assert.Nil(t, f.svc.service)
	resp, err := f.svc.ListZones(context.Background(), &platformv1.ListZonesRequest{})
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok, "%v", err)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, "dns", notConfiguredServiceName(t, st))
}

// TestErrDNSServiceNotAvailable_GRPCStatus: the typed error QUIC and the MCP
// provider answer with no backend carries the same class and discriminator as
// the servicer's not-configured answer, and keeps its message.
func TestErrDNSServiceNotAvailable_GRPCStatus(t *testing.T) {
	err := ErrDNSServiceNotAvailable{}

	st := err.GRPCStatus()
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, err.Error(), st.Message())
	assert.Equal(t, "dns", notConfiguredServiceName(t, st))
	assert.Equal(t, codes.Unavailable, status.Code(err), "status.Code honours GRPCStatus")
	assert.NotEqual(t, codes.Unavailable, status.Code(ErrUnsupportedRecordType{}), "other DNS errors keep their class")
}

// TestFullDNSService resolves the full DNS service behind the narrow config
// interface, and nothing for a nil or partial service.
func TestFullDNSService(t *testing.T) {
	backend := newDNSParityBackend(t)
	assert.Same(t, backend, fullDNSService(backend))
	assert.Nil(t, fullDNSService(nil))
	assert.Nil(t, fullDNSService(narrowDNSService{}))
}

// narrowDNSService implements only the daemon's narrow DNSService.
type narrowDNSService struct{ DNSService }
