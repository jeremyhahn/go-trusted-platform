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

// Package embedded provides an in-process transport adapter that routes
// gRPC method calls directly to service implementations without any
// network transport. It is used for desktop embedded mode where platformd
// services run in the same process as the client.
package embedded

import (
	"context"
	"sync/atomic"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"google.golang.org/grpc"
)

// ServiceRegistry holds references to gRPC server implementations
// for direct in-process invocation without network transport.
type ServiceRegistry struct {
	Daemon      platformv1.PlatformDaemonServer
	CA          platformv1.CAServiceServer
	TPM         platformv1.TPMServiceServer
	VTPM        platformv1.VTPMServiceServer
	Device      platformv1.DeviceServiceServer
	IAM         platformv1.PlatformIAMServiceServer
	KMS         platformv1.KeyManagementServiceServer
	SDN         platformv1.SDNServiceServer
	Compute     platformv1.ComputeServiceServer
	IDevID      platformv1.IDevIDServiceServer
	Attestation platformv1.AttestationServiceServer
	Tenant      platformv1.TenantServiceServer
	PXE         platformv1.PXEServiceServer
	DNS         platformv1.DNSServiceServer
	Gateway     platformv1.GatewayServiceServer
	Proxy       platformv1.ProxyServiceServer
	Overlay     platformv1.OverlayServiceServer
	Registry    platformv1.RegistryServiceServer
	Cluster     platformv1.ClusterServiceServer
	EAB         platformv1.EABServiceServer
	Invitation  platformv1.InvitationServiceServer

	// ConfigDelivery backs the pre-enrollment provisioning verbs
	// (nonce issuance, config fetch, remote Secure Boot digest signing,
	// provisioning session management).
	ConfigDelivery platformv1.ConfigDeliveryServiceServer
}

// Adapter implements the transport.Adapter interface for in-process
// service calls. It wraps a ServiceRegistry and dispatches gRPC method
// strings directly to service handler functions using O(1) map lookup.
type Adapter struct {
	conn      *embeddedClientConn
	connected atomic.Bool
}

func init() {
	platform.RegisterProtocol(platform.ProtocolEmbedded, Connect)
}

// Connect creates a new embedded transport adapter from the platform options.
// The options must contain an EmbeddedServices field holding a *ServiceRegistry.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, ErrNilRegistry{}
	}

	// Calls never leave the process, so a token or TLS setting would be
	// silently dropped. Refuse it instead.
	if names := opts.CredentialOptions(); len(names) > 0 {
		return nil, platform.ErrUnsupportedOption{
			Protocol: platform.ProtocolEmbedded,
			Option:   names[0],
			Reason:   "the embedded transport calls services in-process",
		}
	}

	registry, ok := opts.EmbeddedServices.(*ServiceRegistry)
	if !ok || registry == nil {
		return nil, ErrNilRegistry{}
	}

	return New(registry)
}

// New creates a new embedded transport adapter from a ServiceRegistry.
func New(registry *ServiceRegistry) (*Adapter, error) {
	if registry == nil {
		return nil, ErrNilRegistry{}
	}

	conn := newEmbeddedClientConn(registry)

	a := &Adapter{
		conn: conn,
	}
	a.connected.Store(true)

	return a, nil
}

// Connection returns the embedded client connection that implements
// grpc.ClientConnInterface for transparent gRPC service client usage.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return a.conn
}

// Close marks the adapter as disconnected and releases resources.
func (a *Adapter) Close() error {
	a.connected.Store(false)
	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	return a.connected.Load()
}

// Target returns the connection target identifier.
func (a *Adapter) Target() string {
	return "embedded://in-process"
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
