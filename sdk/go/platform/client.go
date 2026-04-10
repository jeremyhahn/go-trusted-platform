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
	"os"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client represents a connection to the platform daemon.
// It provides access to all service clients and manages the underlying connection.
//
// All services are exposed as platform services. Implementation details like
// the underlying data stores are abstracted away. Services are accessed through
// the platform's gRPC API.
type Client interface {
	// Core Platform Services
	Daemon() platformv1.PlatformDaemonClient
	TPM() platformv1.TPMServiceClient
	CA() platformv1.CAServiceClient
	Device() platformv1.DeviceServiceClient
	VTPM() platformv1.VTPMServiceClient
	SDN() platformv1.SDNServiceClient
	Compute() platformv1.ComputeServiceClient
	IDevID() platformv1.IDevIDServiceClient
	Attestation() platformv1.AttestationServiceClient
	Tenant() platformv1.TenantServiceClient
	PXE() platformv1.PXEServiceClient
	DNS() platformv1.DNSServiceClient
	Gateway() platformv1.GatewayServiceClient
	Overlay() platformv1.OverlayServiceClient
	Registry() platformv1.RegistryServiceClient
	Cluster() platformv1.ClusterServiceClient

	// Security Platform Services
	IAM() platformv1.PlatformIAMServiceClient
	KMS() platformv1.KeyManagementServiceClient
	Barrier() platformv1.BarrierServiceClient

	// Connection management
	Close() error
	IsConnected() bool
	Protocol() Protocol

	// Health check
	Ping(ctx context.Context) error
}

// ServiceClients holds all the gRPC service client interfaces.
// This is used internally by client implementations to initialize service clients.
type ServiceClients struct {
	Daemon      platformv1.PlatformDaemonClient
	TPM         platformv1.TPMServiceClient
	CA          platformv1.CAServiceClient
	Device      platformv1.DeviceServiceClient
	VTPM        platformv1.VTPMServiceClient
	IAM         platformv1.PlatformIAMServiceClient
	KMS         platformv1.KeyManagementServiceClient
	Barrier     platformv1.BarrierServiceClient
	SDN         platformv1.SDNServiceClient
	Compute     platformv1.ComputeServiceClient
	IDevID      platformv1.IDevIDServiceClient
	Attestation platformv1.AttestationServiceClient
	Tenant      platformv1.TenantServiceClient
	PXE         platformv1.PXEServiceClient
	DNS         platformv1.DNSServiceClient
	Gateway     platformv1.GatewayServiceClient
	Overlay     platformv1.OverlayServiceClient
	Registry    platformv1.RegistryServiceClient
	Cluster     platformv1.ClusterServiceClient
}

// ConnectFunc is a function type for protocol-specific connection establishment.
type ConnectFunc func(ctx context.Context, opts *Options) (transport.Adapter, error)

// protocolConnectors maps protocols to their connection functions for O(1) dispatch.
var protocolConnectors = map[Protocol]ConnectFunc{}

// RegisterProtocol registers a connection function for a protocol.
// This is called by transport packages during init to register their adapters.
func RegisterProtocol(proto Protocol, fn ConnectFunc) {
	protocolConnectors[proto] = fn
}

// NewClient creates a new client using the Connect function with the provided options.
func NewClient(ctx context.Context, opts ...Option) (Client, error) {
	options := NewOptions(opts...)
	return Connect(ctx, options)
}

// Connect attempts to connect to the daemon using available protocols.
// It tries protocols in priority order: Unix socket > gRPC > REST > QUIC > MCP.
// If OnlyProtocol is set, only that protocol is attempted.
// If PreferredProtocol is set, that protocol is tried first.
func Connect(ctx context.Context, opts *Options) (Client, error) {
	if opts == nil {
		opts = NewOptions()
	}

	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// If a specific protocol is required, only try that one
	if opts.OnlyProtocol != ProtocolUnknown {
		return connectWithProtocol(ctx, opts, opts.OnlyProtocol)
	}

	// Build the protocol order based on preferences
	protocols := buildProtocolOrder(opts)

	// Try each protocol in order
	var attempted []Protocol
	var lastErr error

	for _, proto := range protocols {
		attempted = append(attempted, proto)
		client, err := connectWithProtocol(ctx, opts, proto)
		if err == nil {
			return client, nil
		}
		lastErr = err
	}

	return nil, ErrDaemonUnavailable{
		Attempted: attempted,
		LastErr:   lastErr,
	}
}

// ConnectUnix connects to the daemon via Unix socket only.
func ConnectUnix(ctx context.Context, opts *Options) (Client, error) {
	if opts == nil {
		opts = NewOptions()
	}
	return connectWithProtocol(ctx, opts, ProtocolUnix)
}

// ConnectGRPC connects to the daemon via gRPC only.
func ConnectGRPC(ctx context.Context, opts *Options) (Client, error) {
	if opts == nil {
		opts = NewOptions()
	}
	return connectWithProtocol(ctx, opts, ProtocolGRPC)
}

// buildProtocolOrder builds the list of protocols to try based on options.
func buildProtocolOrder(opts *Options) []Protocol {
	// Default order: Unix (if root) > gRPC > REST > QUIC > MCP
	var protocols []Protocol

	// If preferred protocol is set, try it first
	if opts.PreferredProtocol != ProtocolUnknown {
		protocols = append(protocols, opts.PreferredProtocol)
	}

	// Add Unix socket if running as root and socket is configured
	if isRootUser() && opts.HasUnixSocket() {
		if !containsProtocol(protocols, ProtocolUnix) {
			protocols = append(protocols, ProtocolUnix)
		}
	}

	// Add gRPC if configured
	if opts.HasGRPCAddr() {
		if !containsProtocol(protocols, ProtocolGRPC) {
			protocols = append(protocols, ProtocolGRPC)
		}
	}

	// Add REST if configured
	if opts.HasRESTAddr() {
		if !containsProtocol(protocols, ProtocolREST) {
			protocols = append(protocols, ProtocolREST)
		}
	}

	// Add QUIC if configured
	if opts.HasQUICAddr() {
		if !containsProtocol(protocols, ProtocolQUIC) {
			protocols = append(protocols, ProtocolQUIC)
		}
	}

	// Add MCP if configured
	if opts.HasMCPAddr() {
		if !containsProtocol(protocols, ProtocolMCP) {
			protocols = append(protocols, ProtocolMCP)
		}
	}

	// Add embedded if services are configured
	if opts.HasEmbeddedServices() {
		if !containsProtocol(protocols, ProtocolEmbedded) {
			protocols = append(protocols, ProtocolEmbedded)
		}
	}

	// If no protocols are configured, try defaults
	if len(protocols) == 0 {
		if isRootUser() {
			protocols = append(protocols, ProtocolUnix)
		}
	}

	return protocols
}

// connectWithProtocol attempts to connect using a specific protocol.
// Uses map-based dispatch for O(1) lookup.
func connectWithProtocol(ctx context.Context, opts *Options, proto Protocol) (Client, error) {
	connector, ok := protocolConnectors[proto]
	if !ok {
		return nil, ErrProtocolNotImplemented{Protocol: proto}
	}

	adapter, err := connector(ctx, opts)
	if err != nil {
		return nil, err
	}

	return newClientFromAdapter(adapter, proto, opts), nil
}

// containsProtocol checks if a protocol is in the list.
func containsProtocol(protocols []Protocol, p Protocol) bool {
	for _, proto := range protocols {
		if proto == p {
			return true
		}
	}
	return false
}

// isRootUser checks if the current process is running as root.
func isRootUser() bool {
	return os.Geteuid() == 0
}

// platformClient is the concrete implementation of the Client interface.
type platformClient struct {
	adapter  transport.Adapter
	services *ServiceClients
	protocol Protocol
}

// newClientFromAdapter creates a new client from a transport adapter.
func newClientFromAdapter(adapter transport.Adapter, proto Protocol, _ *Options) *platformClient {
	c := &platformClient{
		adapter:  adapter,
		protocol: proto,
	}
	c.initServiceClients()
	return c
}

// initServiceClients initializes all service clients from the adapter's connection.
func (c *platformClient) initServiceClients() {
	conn := c.adapter.Connection()
	if conn == nil {
		return
	}

	c.services = &ServiceClients{
		Daemon:      platformv1.NewPlatformDaemonClient(conn),
		TPM:         platformv1.NewTPMServiceClient(conn),
		CA:          platformv1.NewCAServiceClient(conn),
		Device:      platformv1.NewDeviceServiceClient(conn),
		VTPM:        platformv1.NewVTPMServiceClient(conn),
		IAM:         platformv1.NewPlatformIAMServiceClient(conn),
		KMS:         platformv1.NewKeyManagementServiceClient(conn),
		Barrier:     platformv1.NewBarrierServiceClient(conn),
		SDN:         platformv1.NewSDNServiceClient(conn),
		Compute:     platformv1.NewComputeServiceClient(conn),
		IDevID:      platformv1.NewIDevIDServiceClient(conn),
		Attestation: platformv1.NewAttestationServiceClient(conn),
		Tenant:      platformv1.NewTenantServiceClient(conn),
		PXE:         platformv1.NewPXEServiceClient(conn),
		DNS:         platformv1.NewDNSServiceClient(conn),
		Gateway:     platformv1.NewGatewayServiceClient(conn),
		Overlay:     platformv1.NewOverlayServiceClient(conn),
		Registry:    platformv1.NewRegistryServiceClient(conn),
		Cluster:     platformv1.NewClusterServiceClient(conn),
	}
}

// Daemon returns the platform daemon service client.
func (c *platformClient) Daemon() platformv1.PlatformDaemonClient {
	if c.services == nil {
		return nil
	}
	return c.services.Daemon
}

// TPM returns the TPM service client.
func (c *platformClient) TPM() platformv1.TPMServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.TPM
}

// CA returns the CA service client.
func (c *platformClient) CA() platformv1.CAServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.CA
}

// Device returns the device service client.
func (c *platformClient) Device() platformv1.DeviceServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Device
}

// VTPM returns the virtual TPM service client.
func (c *platformClient) VTPM() platformv1.VTPMServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.VTPM
}

// IAM returns the IAM service client.
func (c *platformClient) IAM() platformv1.PlatformIAMServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.IAM
}

// KMS returns the KMS service client.
func (c *platformClient) KMS() platformv1.KeyManagementServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.KMS
}

// Barrier returns the barrier service client.
func (c *platformClient) Barrier() platformv1.BarrierServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Barrier
}

// SDN returns the SDN service client.
func (c *platformClient) SDN() platformv1.SDNServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.SDN
}

// Compute returns the compute service client.
func (c *platformClient) Compute() platformv1.ComputeServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Compute
}

// IDevID returns the IDevID service client.
func (c *platformClient) IDevID() platformv1.IDevIDServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.IDevID
}

// Attestation returns the attestation service client.
func (c *platformClient) Attestation() platformv1.AttestationServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Attestation
}

// Tenant returns the tenant service client.
func (c *platformClient) Tenant() platformv1.TenantServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Tenant
}

// PXE returns the PXE service client.
func (c *platformClient) PXE() platformv1.PXEServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.PXE
}

// DNS returns the DNS service client.
func (c *platformClient) DNS() platformv1.DNSServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.DNS
}

// Gateway returns the Gateway service client.
func (c *platformClient) Gateway() platformv1.GatewayServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Gateway
}

// Overlay returns the Overlay service client.
func (c *platformClient) Overlay() platformv1.OverlayServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Overlay
}

// Registry returns the Registry service client.
func (c *platformClient) Registry() platformv1.RegistryServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Registry
}

// Cluster returns the Cluster service client.
func (c *platformClient) Cluster() platformv1.ClusterServiceClient {
	if c.services == nil {
		return nil
	}
	return c.services.Cluster
}

// Close closes the client connection.
func (c *platformClient) Close() error {
	// Close platform adapter
	if c.adapter != nil {
		if err := c.adapter.Close(); err != nil {
			return ErrCloseFailed{Protocol: c.protocol, Err: err}
		}
	}
	c.services = nil
	return nil
}

// IsConnected returns true if the client is connected.
func (c *platformClient) IsConnected() bool {
	if c.adapter == nil {
		return false
	}
	return c.adapter.IsConnected()
}

// Protocol returns the protocol used by this client.
func (c *platformClient) Protocol() Protocol {
	return c.protocol
}

// Ping tests the connection to the daemon.
func (c *platformClient) Ping(ctx context.Context) error {
	if !c.IsConnected() {
		return ErrNotConnected
	}

	if c.services == nil || c.services.Daemon == nil {
		return ErrServiceUnavailable{Service: "daemon"}
	}

	// Use GetVersion as a simple ping
	_, err := c.services.Daemon.GetVersion(ctx, &platformv1.GetVersionRequest{})
	if err != nil {
		return ErrConnectionFailed{
			Protocol: c.protocol,
			Target:   c.adapter.Target(),
			Err:      err,
		}
	}

	return nil
}

// Ensure platformClient implements Client interface.
var _ Client = (*platformClient)(nil)
