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

package platform

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// mockAdapter implements transport.Adapter for testing.
type mockAdapter struct {
	connected  bool
	target     string
	closeErr   error
	closeCalls int
}

func (m *mockAdapter) Connection() grpc.ClientConnInterface {
	return nil
}

func (m *mockAdapter) Close() error {
	m.closeCalls++
	m.connected = false
	return m.closeErr
}

func (m *mockAdapter) IsConnected() bool {
	return m.connected
}

func (m *mockAdapter) Target() string {
	return m.target
}

// Ensure mockAdapter implements transport.Adapter.
var _ transport.Adapter = (*mockAdapter)(nil)

func TestConnect_NilOptions(t *testing.T) {
	originalConnectors := protocolConnectors
	t.Cleanup(func() {
		protocolConnectors = originalConnectors
	})

	// Every connector refuses, so the result does not depend on a daemon
	// listening on the host or on the user the test runs as.
	refused := errors.New("connection refused")
	protocolConnectors = make(map[Protocol]ConnectFunc)
	for _, proto := range []Protocol{ProtocolUnix, ProtocolGRPC, ProtocolREST, ProtocolQUIC, ProtocolMCP, ProtocolEmbedded} {
		protocolConnectors[proto] = func(context.Context, *Options) (transport.Adapter, error) {
			return nil, refused
		}
	}

	client, err := Connect(context.Background(), nil)
	if client != nil {
		t.Fatalf("Connect(nil) returned a client with every connector refusing")
	}

	var unavailableErr ErrDaemonUnavailable
	if !errors.As(err, &unavailableErr) {
		t.Fatalf("Connect(nil) error = %T: %v, want ErrDaemonUnavailable", err, err)
	}

	// Nil options fall back to NewOptions, which configures only the Unix
	// socket: no network protocol may be attempted.
	for _, proto := range unavailableErr.Attempted {
		if proto != ProtocolUnix {
			t.Errorf("Connect(nil) attempted %v, want only %v from the default options", proto, ProtocolUnix)
		}
	}
	if len(unavailableErr.Attempted) > 0 && !errors.Is(unavailableErr.LastErr, refused) {
		t.Errorf("LastErr = %v, want the connector's error", unavailableErr.LastErr)
	}
}

func TestConnect_InvalidOptions(t *testing.T) {
	ctx := context.Background()

	opts := NewOptions()
	opts.OnlyProtocol = Protocol(99) // Invalid protocol

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Error("expected error for invalid options")
	}

	var invalidErr ErrInvalidOptions
	if !errors.As(err, &invalidErr) {
		t.Errorf("expected ErrInvalidOptions, got %T: %v", err, err)
	}
}

func TestConnect_OnlyProtocolNotImplemented(t *testing.T) {
	ctx := context.Background()

	// Request a protocol that isn't registered
	opts := NewOptions(
		WithOnlyProtocol(ProtocolREST), // REST not implemented
	)

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Error("expected error for unimplemented protocol")
	}

	var notImplErr ErrProtocolNotImplemented
	if !errors.As(err, &notImplErr) {
		t.Errorf("expected ErrProtocolNotImplemented, got %T: %v", err, err)
	}
	if notImplErr.Protocol != ProtocolREST {
		t.Errorf("Protocol = %v, want %v", notImplErr.Protocol, ProtocolREST)
	}
}

func TestBuildProtocolOrder(t *testing.T) {
	t.Run("preferred protocol first", func(t *testing.T) {
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
			WithPreferredProtocol(ProtocolGRPC),
		)

		protocols := buildProtocolOrder(opts)
		if len(protocols) == 0 {
			t.Fatal("expected at least one protocol")
		}
		if protocols[0] != ProtocolGRPC {
			t.Errorf("first protocol = %v, want %v", protocols[0], ProtocolGRPC)
		}
	})

	t.Run("no duplicates when preferred matches configured", func(t *testing.T) {
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
			WithPreferredProtocol(ProtocolGRPC),
		)

		protocols := buildProtocolOrder(opts)

		// Count occurrences of gRPC
		count := 0
		for _, p := range protocols {
			if p == ProtocolGRPC {
				count++
			}
		}
		if count != 1 {
			t.Errorf("gRPC appeared %d times, want 1", count)
		}
	})

	t.Run("all configured protocols included", func(t *testing.T) {
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
			WithRESTAddr("localhost:8443"),
			WithQUICAddr("localhost:9444"),
			WithMCPAddr("localhost:9445"),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		hasGRPC := containsProtocol(protocols, ProtocolGRPC)
		hasREST := containsProtocol(protocols, ProtocolREST)
		hasQUIC := containsProtocol(protocols, ProtocolQUIC)
		hasMCP := containsProtocol(protocols, ProtocolMCP)

		if !hasGRPC {
			t.Error("protocols should include gRPC")
		}
		if !hasREST {
			t.Error("protocols should include REST")
		}
		if !hasQUIC {
			t.Error("protocols should include QUIC")
		}
		if !hasMCP {
			t.Error("protocols should include MCP")
		}
	})

	t.Run("empty when no protocols configured", func(t *testing.T) {
		opts := &Options{}

		protocols := buildProtocolOrder(opts)

		// When not root and no addresses configured, should be empty
		// (may include Unix if running as root)
		if isRootUser() {
			if len(protocols) != 1 || protocols[0] != ProtocolUnix {
				t.Error("root user should have Unix protocol as default")
			}
		} else {
			if len(protocols) != 0 {
				t.Errorf("non-root with no config should have no protocols, got %v", protocols)
			}
		}
	})

	t.Run("includes embedded when services configured", func(t *testing.T) {
		opts := NewOptions(
			WithEmbeddedServices(&struct{}{}),
		)
		opts.UnixSocket = "" // Disable Unix socket to simplify assertion

		protocols := buildProtocolOrder(opts)

		if !containsProtocol(protocols, ProtocolEmbedded) {
			t.Error("protocols should include embedded when EmbeddedServices is set")
		}
	})

	t.Run("excludes embedded when no services configured", func(t *testing.T) {
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		if containsProtocol(protocols, ProtocolEmbedded) {
			t.Error("protocols should not include embedded when EmbeddedServices is nil")
		}
	})

	t.Run("embedded not duplicated when preferred", func(t *testing.T) {
		opts := NewOptions(
			WithPreferredProtocol(ProtocolEmbedded),
			WithEmbeddedServices(&struct{}{}),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		count := 0
		for _, p := range protocols {
			if p == ProtocolEmbedded {
				count++
			}
		}
		if count != 1 {
			t.Errorf("embedded appeared %d times, want 1", count)
		}
	})

	t.Run("backward compatible without embedded", func(t *testing.T) {
		// Existing configs that don't set EmbeddedServices should work unchanged
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
			WithRESTAddr("localhost:8443"),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		if containsProtocol(protocols, ProtocolEmbedded) {
			t.Error("backward compatible config should not include embedded")
		}

		if !containsProtocol(protocols, ProtocolGRPC) {
			t.Error("backward compatible config should include gRPC")
		}
		if !containsProtocol(protocols, ProtocolREST) {
			t.Error("backward compatible config should include REST")
		}
	})

	t.Run("embedded added after other protocols", func(t *testing.T) {
		opts := NewOptions(
			WithGRPCAddr("localhost:10443"),
			WithRESTAddr("localhost:8443"),
			WithEmbeddedServices(&struct{}{}),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		// Embedded should be last (after gRPC, REST)
		if len(protocols) == 0 {
			t.Fatal("expected at least one protocol")
		}

		lastProto := protocols[len(protocols)-1]
		if lastProto != ProtocolEmbedded {
			t.Errorf("embedded should be last in order, got %v last", lastProto)
		}
	})

	t.Run("embedded first when preferred", func(t *testing.T) {
		opts := NewOptions(
			WithPreferredProtocol(ProtocolEmbedded),
			WithGRPCAddr("localhost:10443"),
			WithEmbeddedServices(&struct{}{}),
		)
		opts.UnixSocket = "" // Disable Unix socket

		protocols := buildProtocolOrder(opts)

		if len(protocols) == 0 {
			t.Fatal("expected at least one protocol")
		}
		if protocols[0] != ProtocolEmbedded {
			t.Errorf("first protocol = %v, want embedded", protocols[0])
		}
	})
}

func TestContainsProtocol(t *testing.T) {
	tests := []struct {
		name      string
		protocols []Protocol
		search    Protocol
		want      bool
	}{
		{
			name:      "found at start",
			protocols: []Protocol{ProtocolGRPC, ProtocolUnix, ProtocolREST},
			search:    ProtocolGRPC,
			want:      true,
		},
		{
			name:      "found at end",
			protocols: []Protocol{ProtocolGRPC, ProtocolUnix, ProtocolREST},
			search:    ProtocolREST,
			want:      true,
		},
		{
			name:      "found in middle",
			protocols: []Protocol{ProtocolGRPC, ProtocolUnix, ProtocolREST},
			search:    ProtocolUnix,
			want:      true,
		},
		{
			name:      "not found",
			protocols: []Protocol{ProtocolGRPC, ProtocolUnix},
			search:    ProtocolREST,
			want:      false,
		},
		{
			name:      "empty slice",
			protocols: []Protocol{},
			search:    ProtocolGRPC,
			want:      false,
		},
		{
			name:      "nil slice",
			protocols: nil,
			search:    ProtocolGRPC,
			want:      false,
		},
		{
			name:      "embedded found",
			protocols: []Protocol{ProtocolGRPC, ProtocolEmbedded},
			search:    ProtocolEmbedded,
			want:      true,
		},
		{
			name:      "embedded not found",
			protocols: []Protocol{ProtocolGRPC, ProtocolUnix},
			search:    ProtocolEmbedded,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsProtocol(tt.protocols, tt.search)
			if got != tt.want {
				t.Errorf("containsProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlatformClient_ServiceClients(t *testing.T) {
	// Create a client with nil adapter to test nil service handling
	c := &platformClient{
		adapter:  nil,
		services: nil,
		protocol: ProtocolGRPC,
	}

	// All service methods should return nil without panicking
	if c.Daemon() != nil {
		t.Error("Daemon() should return nil with nil services")
	}
	if c.TPM() != nil {
		t.Error("TPM() should return nil with nil services")
	}
	if c.CA() != nil {
		t.Error("CA() should return nil with nil services")
	}
	if c.Device() != nil {
		t.Error("Device() should return nil with nil services")
	}
	if c.VTPM() != nil {
		t.Error("VTPM() should return nil with nil services")
	}
	if c.IAM() != nil {
		t.Error("IAM() should return nil with nil services")
	}
	if c.KMS() != nil {
		t.Error("KMS() should return nil with nil services")
	}
	if c.SDN() != nil {
		t.Error("SDN() should return nil with nil services")
	}
	if c.Compute() != nil {
		t.Error("Compute() should return nil with nil services")
	}
	if c.IDevID() != nil {
		t.Error("IDevID() should return nil with nil services")
	}
	if c.Attestation() != nil {
		t.Error("Attestation() should return nil with nil services")
	}
	if c.Tenant() != nil {
		t.Error("Tenant() should return nil with nil services")
	}
	if c.PXE() != nil {
		t.Error("PXE() should return nil with nil services")
	}
	if c.DNS() != nil {
		t.Error("DNS() should return nil with nil services")
	}
	if c.Gateway() != nil {
		t.Error("Gateway() should return nil with nil services")
	}
	if c.Overlay() != nil {
		t.Error("Overlay() should return nil with nil services")
	}
	if c.PIV() != nil {
		t.Error("PIV() should return nil with nil services")
	}
	if c.FIDO2() != nil {
		t.Error("FIDO2() should return nil with nil services")
	}
	if c.Ceremony() != nil {
		t.Error("Ceremony() should return nil with nil services")
	}
	if c.LUKS() != nil {
		t.Error("LUKS() should return nil with nil services")
	}
	if c.Invitation() != nil {
		t.Error("Invitation() should return nil with nil services")
	}
	if c.EAB() != nil {
		t.Error("EAB() should return nil with nil services")
	}
	if c.Switch() != nil {
		t.Error("Switch() should return nil with nil services")
	}
	if c.ConfigDelivery() != nil {
		t.Error("ConfigDelivery() should return nil with nil services")
	}
	if c.Cache() != nil || c.Scheduler() != nil || c.Messaging() != nil || c.ObjectStorage() != nil {
		t.Error("the application service clients should be nil with nil services")
	}
}

// connAdapter is a mockAdapter with a live connection.
type connAdapter struct {
	mockAdapter
	conn grpc.ClientConnInterface
}

func (a *connAdapter) Connection() grpc.ClientConnInterface { return a.conn }

type fakeClientConn struct {
	grpc.ClientConnInterface
}

func TestPlatformClient_AppServiceClientsAreBuiltOnTheConnection(t *testing.T) {
	c := newClientFromAdapter(&connAdapter{conn: fakeClientConn{}}, ProtocolGRPC, nil)
	if c.Cache() == nil || c.Scheduler() == nil || c.Messaging() == nil || c.ObjectStorage() == nil {
		t.Fatalf("Cache, Scheduler, Messaging and ObjectStorage must be built on the adapter connection")
	}

	// Without a connection no service client is built.
	c = newClientFromAdapter(&connAdapter{}, ProtocolGRPC, nil)
	if c.Cache() != nil || c.Scheduler() != nil || c.Messaging() != nil || c.ObjectStorage() != nil {
		t.Error("the application service clients must be nil without a connection")
	}
}

type fakePIVClient struct {
	platformv1.PIVServiceClient
}

type fakeFIDO2Client struct {
	platformv1.FIDO2ServiceClient
}

type fakeCeremonyClient struct {
	platformv1.CeremonyServiceClient
}

type fakeLUKSClient struct {
	platformv1.LUKSServiceClient
}

func TestPlatformClient_PIVReturnsTheConfiguredServiceClient(t *testing.T) {
	want := &fakePIVClient{}
	c := &platformClient{services: &ServiceClients{PIV: want}}

	if got := c.PIV(); got != platformv1.PIVServiceClient(want) {
		t.Errorf("PIV() = %v, want the client held by ServiceClients", got)
	}
}

func TestPlatformClient_FIDO2ReturnsTheConfiguredServiceClient(t *testing.T) {
	want := &fakeFIDO2Client{}
	c := &platformClient{services: &ServiceClients{FIDO2: want}}

	if got := c.FIDO2(); got != platformv1.FIDO2ServiceClient(want) {
		t.Errorf("FIDO2() = %v, want the client held by ServiceClients", got)
	}
}

func TestPlatformClient_CeremonyReturnsTheConfiguredServiceClient(t *testing.T) {
	want := &fakeCeremonyClient{}
	c := &platformClient{services: &ServiceClients{Ceremony: want}}

	if got := c.Ceremony(); got != platformv1.CeremonyServiceClient(want) {
		t.Errorf("Ceremony() = %v, want the client held by ServiceClients", got)
	}
}

func TestPlatformClient_LUKSReturnsTheConfiguredServiceClient(t *testing.T) {
	want := &fakeLUKSClient{}
	c := &platformClient{services: &ServiceClients{LUKS: want}}

	if got := c.LUKS(); got != platformv1.LUKSServiceClient(want) {
		t.Errorf("LUKS() = %v, want the client held by ServiceClients", got)
	}
}

// recordingConn records the full method name of the last unary call.
type recordingConn struct {
	grpc.ClientConnInterface
	method string
}

func (r *recordingConn) Invoke(_ context.Context, method string, _, _ any, _ ...grpc.CallOption) error {
	r.method = method
	return nil
}

func TestPlatformClient_InvitationCallsTheInvitationService(t *testing.T) {
	conn := &recordingConn{}
	c := newClientFromAdapter(&connAdapter{conn: conn}, ProtocolGRPC, nil)

	if _, err := c.Invitation().GetInvitation(context.Background(), &platformv1.GetInvitationRequest{InvitationId: 1}); err != nil {
		t.Fatalf("GetInvitation: %v", err)
	}
	if conn.method != platformv1.InvitationService_GetInvitation_FullMethodName {
		t.Errorf("Invitation() called %q, want %q", conn.method, platformv1.InvitationService_GetInvitation_FullMethodName)
	}

	if c := newClientFromAdapter(&connAdapter{}, ProtocolGRPC, nil); c.Invitation() != nil {
		t.Error("Invitation() must be nil without a connection")
	}
}

func TestPlatformClient_OrchestratorCallsTheOrchestratorService(t *testing.T) {
	conn := &recordingConn{}
	c := newClientFromAdapter(&connAdapter{conn: conn}, ProtocolGRPC, nil)

	if _, err := c.Orchestrator().Health(context.Background(), &platformv1.OrchestratorHealthRequest{}); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if conn.method != platformv1.OrchestratorService_Health_FullMethodName {
		t.Errorf("Orchestrator() called %q, want %q", conn.method, platformv1.OrchestratorService_Health_FullMethodName)
	}

	if c := newClientFromAdapter(&connAdapter{}, ProtocolGRPC, nil); c.Orchestrator() != nil {
		t.Error("Orchestrator() must be nil without a connection")
	}
}

func TestPlatformClient_EABCallsTheEABService(t *testing.T) {
	conn := &recordingConn{}
	c := newClientFromAdapter(&connAdapter{conn: conn}, ProtocolGRPC, nil)

	if _, err := c.EAB().ListCredentials(context.Background(), &platformv1.ListEABCredentialsRequest{}); err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if conn.method != platformv1.EABService_ListCredentials_FullMethodName {
		t.Errorf("EAB() called %q, want %q", conn.method, platformv1.EABService_ListCredentials_FullMethodName)
	}

	if c := newClientFromAdapter(&connAdapter{}, ProtocolGRPC, nil); c.EAB() != nil {
		t.Error("EAB() must be nil without a connection")
	}
}

// methodRecordingConn records the method of every call and answers err.
type methodRecordingConn struct {
	grpc.ClientConnInterface
	methods []string
	err     error
}

func (c *methodRecordingConn) Invoke(_ context.Context, method string, _, _ interface{}, _ ...grpc.CallOption) error {
	c.methods = append(c.methods, method)
	return c.err
}

// Switch() is built on the adapter connection, so its calls reach the
// transport under the SwitchService method names; without a connection it
// is nil.
func TestPlatformClient_SwitchIsBuiltOnTheConnection(t *testing.T) {
	conn := &methodRecordingConn{}
	c := newClientFromAdapter(&connAdapter{conn: conn}, ProtocolMCP, nil)
	if c.Switch() == nil {
		t.Fatal("Switch() must be built on the adapter connection")
	}

	if _, err := c.Switch().ListPorts(context.Background(), &platformv1.ListSwitchPortsRequest{SwitchName: "tor-1"}); err != nil {
		t.Fatalf("ListPorts: %v", err)
	}
	if _, err := c.Switch().DisablePort(context.Background(), &platformv1.DisableSwitchPortRequest{SwitchName: "tor-1", PortName: "Eth1/3"}); err != nil {
		t.Fatalf("DisablePort: %v", err)
	}
	want := []string{platformv1.SwitchService_ListPorts_FullMethodName, platformv1.SwitchService_DisablePort_FullMethodName}
	if len(conn.methods) != len(want) || conn.methods[0] != want[0] || conn.methods[1] != want[1] {
		t.Errorf("calls reached the transport as %v, want %v", conn.methods, want)
	}

	if c := newClientFromAdapter(&connAdapter{}, ProtocolMCP, nil); c.Switch() != nil {
		t.Error("Switch() must be nil without a connection")
	}
}

// A transport failure reaches the Switch() caller unchanged.
func TestPlatformClient_SwitchReturnsTheTransportError(t *testing.T) {
	transportErr := errors.New("transport down")
	c := newClientFromAdapter(&connAdapter{conn: &methodRecordingConn{err: transportErr}}, ProtocolEmbedded, nil)

	_, err := c.Switch().EnablePort(context.Background(), &platformv1.EnableSwitchPortRequest{SwitchName: "tor-1", PortName: "Eth1/3"})
	if !errors.Is(err, transportErr) {
		t.Fatalf("EnablePort error = %v, want the transport error", err)
	}
}

func TestPlatformClient_Protocol(t *testing.T) {
	t.Run("returns gRPC protocol", func(t *testing.T) {
		c := &platformClient{
			protocol: ProtocolGRPC,
		}

		if c.Protocol() != ProtocolGRPC {
			t.Errorf("Protocol() = %v, want %v", c.Protocol(), ProtocolGRPC)
		}
	})

	t.Run("returns embedded protocol", func(t *testing.T) {
		c := &platformClient{
			protocol: ProtocolEmbedded,
		}

		if c.Protocol() != ProtocolEmbedded {
			t.Errorf("Protocol() = %v, want %v", c.Protocol(), ProtocolEmbedded)
		}
	})
}

func TestPlatformClient_IsConnected(t *testing.T) {
	t.Run("nil adapter", func(t *testing.T) {
		c := &platformClient{adapter: nil}
		if c.IsConnected() {
			t.Error("IsConnected() should return false with nil adapter")
		}
	})

	t.Run("connected adapter", func(t *testing.T) {
		c := &platformClient{
			adapter: &mockAdapter{connected: true},
		}
		if !c.IsConnected() {
			t.Error("IsConnected() should return true when adapter is connected")
		}
	})

	t.Run("disconnected adapter", func(t *testing.T) {
		c := &platformClient{
			adapter: &mockAdapter{connected: false},
		}
		if c.IsConnected() {
			t.Error("IsConnected() should return false when adapter is disconnected")
		}
	})
}

func TestPlatformClient_Close(t *testing.T) {
	t.Run("nil adapter", func(t *testing.T) {
		c := &platformClient{adapter: nil}
		err := c.Close()
		if err != nil {
			t.Errorf("Close() with nil adapter should not return error, got %v", err)
		}
	})

	t.Run("successful close", func(t *testing.T) {
		mock := &mockAdapter{connected: true}
		c := &platformClient{
			adapter:  mock,
			services: &ServiceClients{},
		}

		err := c.Close()
		if err != nil {
			t.Errorf("Close() returned error: %v", err)
		}
		if mock.closeCalls != 1 {
			t.Errorf("Close() was called %d times, want 1", mock.closeCalls)
		}
		if c.services != nil {
			t.Error("services should be nil after Close()")
		}
	})

	t.Run("close with error", func(t *testing.T) {
		closeErr := errors.New("close failed")
		mock := &mockAdapter{connected: true, closeErr: closeErr}
		c := &platformClient{adapter: mock}

		err := c.Close()
		if err == nil {
			t.Error("Close() should return error when adapter close fails")
		}
		if !errors.Is(err, closeErr) {
			t.Errorf("Close() error = %v, want %v", err, closeErr)
		}
	})

	t.Run("close with error wraps protocol", func(t *testing.T) {
		closeErr := errors.New("embedded close failed")
		mock := &mockAdapter{connected: true, closeErr: closeErr}
		c := &platformClient{
			adapter:  mock,
			protocol: ProtocolEmbedded,
		}

		err := c.Close()
		if err == nil {
			t.Error("Close() should return error when adapter close fails")
		}

		var closeFailed ErrCloseFailed
		if !errors.As(err, &closeFailed) {
			t.Errorf("expected ErrCloseFailed, got %T: %v", err, err)
		}
		if closeFailed.Protocol != ProtocolEmbedded {
			t.Errorf("ErrCloseFailed.Protocol = %v, want %v", closeFailed.Protocol, ProtocolEmbedded)
		}
	})
}

func TestPlatformClient_Ping(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		c := &platformClient{
			adapter: &mockAdapter{connected: false},
		}

		err := c.Ping(context.Background())
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("Ping() should return ErrNotConnected, got %v", err)
		}
	})

	t.Run("nil services", func(t *testing.T) {
		c := &platformClient{
			adapter:  &mockAdapter{connected: true},
			services: nil,
		}

		err := c.Ping(context.Background())
		if err == nil {
			t.Error("Ping() should return error with nil services")
		}

		var svcErr ErrServiceUnavailable
		if !errors.As(err, &svcErr) {
			t.Errorf("expected ErrServiceUnavailable, got %T: %v", err, err)
		}
	})

	t.Run("nil daemon service", func(t *testing.T) {
		c := &platformClient{
			adapter:  &mockAdapter{connected: true},
			services: &ServiceClients{Daemon: nil},
		}

		err := c.Ping(context.Background())
		if err == nil {
			t.Error("Ping() should return error with nil daemon service")
		}

		var svcErr ErrServiceUnavailable
		if !errors.As(err, &svcErr) {
			t.Errorf("expected ErrServiceUnavailable, got %T: %v", err, err)
		}
	})
}

func TestNewClientFromAdapter(t *testing.T) {
	t.Run("creates client with gRPC protocol", func(t *testing.T) {
		mock := &mockAdapter{
			connected: true,
			target:    "localhost:10443",
		}

		c := newClientFromAdapter(mock, ProtocolGRPC, nil)

		if c.adapter != mock {
			t.Error("adapter was not set correctly")
		}
		if c.protocol != ProtocolGRPC {
			t.Errorf("protocol = %v, want %v", c.protocol, ProtocolGRPC)
		}
	})

	t.Run("creates client with embedded protocol", func(t *testing.T) {
		mock := &mockAdapter{
			connected: true,
			target:    "embedded://in-process",
		}

		c := newClientFromAdapter(mock, ProtocolEmbedded, nil)

		if c.adapter != mock {
			t.Error("adapter was not set correctly")
		}
		if c.protocol != ProtocolEmbedded {
			t.Errorf("protocol = %v, want %v", c.protocol, ProtocolEmbedded)
		}
	})
}

func TestRegisterProtocol(t *testing.T) {
	// Save original state
	originalConnectors := make(map[Protocol]ConnectFunc)
	for k, v := range protocolConnectors {
		originalConnectors[k] = v
	}

	// Restore after test
	t.Cleanup(func() {
		protocolConnectors = originalConnectors
	})

	// Clear for test
	protocolConnectors = make(map[Protocol]ConnectFunc)

	t.Run("register and invoke gRPC connector", func(t *testing.T) {
		called := false
		testFn := func(ctx context.Context, opts *Options) (transport.Adapter, error) {
			called = true
			return nil, ErrNotConnected
		}

		RegisterProtocol(ProtocolGRPC, testFn)

		if _, ok := protocolConnectors[ProtocolGRPC]; !ok {
			t.Error("protocol was not registered")
		}

		_, err := protocolConnectors[ProtocolGRPC](context.Background(), nil)
		if !called {
			t.Error("registered function was not called")
		}
		if !errors.Is(err, ErrNotConnected) {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("register embedded connector", func(t *testing.T) {
		called := false
		testFn := func(ctx context.Context, opts *Options) (transport.Adapter, error) {
			called = true
			return &mockAdapter{connected: true, target: "embedded://in-process"}, nil
		}

		RegisterProtocol(ProtocolEmbedded, testFn)

		if _, ok := protocolConnectors[ProtocolEmbedded]; !ok {
			t.Error("embedded protocol was not registered")
		}

		adapter, err := protocolConnectors[ProtocolEmbedded](context.Background(), nil)
		if !called {
			t.Error("registered embedded function was not called")
		}
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if adapter == nil {
			t.Error("adapter should not be nil")
		}
	})
}

func TestConnectWithProtocol_EmbeddedNotRegistered(t *testing.T) {
	// Save original state
	originalConnectors := make(map[Protocol]ConnectFunc)
	for k, v := range protocolConnectors {
		originalConnectors[k] = v
	}
	t.Cleanup(func() {
		protocolConnectors = originalConnectors
	})

	// Clear connectors so embedded is not registered
	protocolConnectors = make(map[Protocol]ConnectFunc)

	ctx := context.Background()
	opts := NewOptions(WithOnlyProtocol(ProtocolEmbedded))

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Error("expected error for unregistered embedded protocol")
	}

	var notImplErr ErrProtocolNotImplemented
	if !errors.As(err, &notImplErr) {
		t.Errorf("expected ErrProtocolNotImplemented, got %T: %v", err, err)
	}
	if notImplErr.Protocol != ProtocolEmbedded {
		t.Errorf("Protocol = %v, want %v", notImplErr.Protocol, ProtocolEmbedded)
	}
}
