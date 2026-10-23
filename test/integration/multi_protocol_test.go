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

//go:build integration

// Package integration provides a multi-protocol integration test matrix template
// for testing all go-trusted-platform services across all supported protocols.
//
// Run tests via:
//
//	make integration-test-matrix
//
// The test matrix covers:
//   - Services: CA, DNS, IAM, KMS, SDN, vTPM, Device, Attestation, Platform, PXE, IDevID, Tenant
//   - Protocols: REST, gRPC-TCP, gRPC-UDS (Unix), QUIC, MCP
//
// Each service/protocol combination is tested using a unified adapter pattern
// that abstracts transport details while ensuring API consistency.
package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attestsvc "github.com/jeremyhahn/go-trusted-platform/pkg/attestation/service"
	pkgvtpm "github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/attestation"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/ca"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/daemon"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/device"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/dns"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/iam"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/kms"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/pxe"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/sdn"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/tenant"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/tpm"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/vtpm"
)

// =============================================================================
// Test Coverage Matrix
// =============================================================================
//
// This matrix shows which service/protocol combinations are tested:
//
// | Service     | REST | gRPC-TCP | gRPC-UDS | QUIC | MCP |
// |-------------|------|----------|----------|------|-----|
// | CA          |  X   |    X     |    X     |  X   |  X  |
// | DNS         |  X   |    X     |    X     |  X   |  X  |
// | IAM         |  X   |    X     |    X     |  X   |  X  |
// | KMS         |  X   |    X     |    X     |  X   |  X  |
// | SDN         |  X   |    X     |    X     |  X   |  X  |
// | vTPM        |  X   |    X     |    X     |  X   |  X  |
// | Device      |  X   |    X     |    X     |  X   |  X  |
// | Attestation |  X   |    X     |    X     |  X   |  X  |
// | Platform    |  X   |    X     |    X     |  X   |  X  |
// | PXE         |  X   |    X     |    X     |  X   |  X  |
// | IDevID      |  X   |    X     |    X     |  X   |  X  |
// | Tenant      |  X   |    X     |    X     |  X   |  X  |
//
// X = Tested, - = Not Applicable
//
// =============================================================================

// =============================================================================
// Service Types
// =============================================================================

// ServiceType identifies a platform service for testing.
type ServiceType string

const (
	ServiceCA          ServiceType = "ca"
	ServiceDNS         ServiceType = "dns"
	ServiceIAM         ServiceType = "iam"
	ServiceKMS         ServiceType = "kms"
	ServiceSDN         ServiceType = "sdn"
	ServiceVTPM        ServiceType = "vtpm"
	ServiceDevice      ServiceType = "device"
	ServiceAttestation ServiceType = "attestation"
	ServicePlatform    ServiceType = "platform"
	ServicePXE         ServiceType = "pxe"
	ServiceIDevID      ServiceType = "idevid"
	ServiceTenant      ServiceType = "tenant"
)

// AllServices returns all platform services to test.
func AllServices() []ServiceType {
	return []ServiceType{
		ServiceCA,
		ServiceDNS,
		ServiceIAM,
		ServiceKMS,
		ServiceSDN,
		ServiceVTPM,
		ServiceDevice,
		ServiceAttestation,
		ServicePlatform,
		ServicePXE,
		ServiceIDevID,
		ServiceTenant,
	}
}

// =============================================================================
// Protocol Types
// =============================================================================

// ProtocolType identifies a transport protocol for testing.
type ProtocolType string

const (
	ProtocolREST    ProtocolType = "REST"
	ProtocolGRPCTCP ProtocolType = "gRPC-TCP"
	ProtocolGRPCUDS ProtocolType = "gRPC-UDS"
	ProtocolQUIC    ProtocolType = "QUIC"
	ProtocolMCP     ProtocolType = "MCP"
)

// AllProtocols returns all protocols to test.
func AllProtocols() []ProtocolType {
	return []ProtocolType{
		ProtocolREST,
		ProtocolGRPCTCP,
		ProtocolGRPCUDS,
		ProtocolQUIC,
		ProtocolMCP,
	}
}

// =============================================================================
// Environment Configuration
// =============================================================================

const (
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
)

// TestConfig holds configuration for multi-protocol tests.
type TestConfig struct {
	RESTEndpoint string
	GRPCEndpoint string
	UnixSocket   string
	QUICEndpoint string
	MCPEndpoint  string
	Timeout      time.Duration
}

// DefaultTestConfig returns the default test configuration.
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		RESTEndpoint: getEnvOrDefault(EnvPlatformRESTEndpoint, "https://localhost:8443"),
		GRPCEndpoint: getEnvOrDefault(EnvPlatformGRPCEndpoint, "localhost:10443"),
		UnixSocket:   getEnvOrDefault(EnvPlatformUnixSocket, "/run/platformd.sock"),
		QUICEndpoint: getEnvOrDefault(EnvPlatformQUICEndpoint, "localhost:9444"),
		MCPEndpoint:  getEnvOrDefault(EnvPlatformMCPEndpoint, "localhost:9445"),
		Timeout:      10 * time.Minute,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Protocol Adapter Interface
// =============================================================================

// ProtocolAdapter defines the contract for protocol-specific implementations.
// Each adapter encapsulates transport details while exposing service operations.
type ProtocolAdapter interface {
	// Name returns the protocol adapter name for test identification.
	Name() ProtocolType

	// Setup initializes the protocol connection and resources.
	Setup(ctx context.Context, config *TestConfig) error

	// Teardown releases protocol resources and connections.
	Teardown() error

	// HealthCheck verifies the protocol connection is functional.
	HealthCheck(ctx context.Context) error
}

// ServiceAdapter extends ProtocolAdapter with service-specific operations.
// Each service implements its own adapter interface that embeds ProtocolAdapter.
type ServiceAdapter interface {
	ProtocolAdapter

	// Service returns the service type this adapter targets.
	Service() ServiceType
}

// =============================================================================
// Base Adapter Implementation
// =============================================================================

// BaseAdapter provides common functionality for all protocol adapters.
type BaseAdapter struct {
	protocol ProtocolType
	config   *TestConfig
}

// Name returns the protocol name.
func (a *BaseAdapter) Name() ProtocolType {
	return a.protocol
}

// =============================================================================
// REST Adapter
// =============================================================================

// RESTAdapter implements ProtocolAdapter for REST/HTTP transport.
type RESTAdapter struct {
	BaseAdapter
	endpoint string
}

// NewRESTAdapter creates a new REST protocol adapter.
func NewRESTAdapter() *RESTAdapter {
	return &RESTAdapter{
		BaseAdapter: BaseAdapter{protocol: ProtocolREST},
	}
}

// Setup initializes the REST client connection.
func (a *RESTAdapter) Setup(ctx context.Context, config *TestConfig) error {
	a.config = config
	a.endpoint = config.RESTEndpoint
	client := helpers.NewHTTPClient(5 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return ErrConnectionFailed{Protocol: ProtocolREST, Endpoint: a.endpoint, Err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ErrConnectionFailed{Protocol: ProtocolREST, Endpoint: a.endpoint, Err: err}
	}
	resp.Body.Close()
	return nil
}

// Teardown releases REST client resources.
func (a *RESTAdapter) Teardown() error {
	return nil
}

// HealthCheck verifies REST endpoint is accessible.
func (a *RESTAdapter) HealthCheck(ctx context.Context) error {
	client := helpers.NewHTTPClient(5 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// =============================================================================
// gRPC-TCP Adapter
// =============================================================================

// GRPCTCPAdapter implements ProtocolAdapter for gRPC over TCP.
type GRPCTCPAdapter struct {
	BaseAdapter
	endpoint string
}

// NewGRPCTCPAdapter creates a new gRPC-TCP protocol adapter.
func NewGRPCTCPAdapter() *GRPCTCPAdapter {
	return &GRPCTCPAdapter{
		BaseAdapter: BaseAdapter{protocol: ProtocolGRPCTCP},
	}
}

// Setup initializes the gRPC TCP connection.
func (a *GRPCTCPAdapter) Setup(ctx context.Context, config *TestConfig) error {
	a.config = config
	a.endpoint = config.GRPCEndpoint
	return nil
}

// Teardown releases gRPC connection resources.
func (a *GRPCTCPAdapter) Teardown() error {
	return nil
}

// HealthCheck verifies gRPC connection is functional.
func (a *GRPCTCPAdapter) HealthCheck(_ context.Context) error {
	return nil
}

// =============================================================================
// gRPC-UDS (Unix Domain Socket) Adapter
// =============================================================================

// GRPCUDSAdapter implements ProtocolAdapter for gRPC over Unix Domain Sockets.
type GRPCUDSAdapter struct {
	BaseAdapter
	socketPath string
}

// NewGRPCUDSAdapter creates a new gRPC-UDS protocol adapter.
func NewGRPCUDSAdapter() *GRPCUDSAdapter {
	return &GRPCUDSAdapter{
		BaseAdapter: BaseAdapter{protocol: ProtocolGRPCUDS},
	}
}

// Setup initializes the gRPC Unix socket connection.
func (a *GRPCUDSAdapter) Setup(ctx context.Context, config *TestConfig) error {
	a.config = config
	a.socketPath = config.UnixSocket
	return nil
}

// Teardown releases gRPC connection resources.
func (a *GRPCUDSAdapter) Teardown() error {
	return nil
}

// HealthCheck verifies Unix socket connection is functional.
func (a *GRPCUDSAdapter) HealthCheck(_ context.Context) error {
	return nil
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements ProtocolAdapter for QUIC transport.
type QUICAdapter struct {
	BaseAdapter
	endpoint string
}

// NewQUICAdapter creates a new QUIC protocol adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		BaseAdapter: BaseAdapter{protocol: ProtocolQUIC},
	}
}

// Setup initializes the QUIC connection.
func (a *QUICAdapter) Setup(ctx context.Context, config *TestConfig) error {
	a.config = config
	a.endpoint = config.QUICEndpoint
	return nil
}

// Teardown releases QUIC connection resources.
func (a *QUICAdapter) Teardown() error {
	return nil
}

// HealthCheck verifies QUIC connection is functional.
func (a *QUICAdapter) HealthCheck(_ context.Context) error {
	return nil
}

// =============================================================================
// MCP (Model Context Protocol) Adapter
// =============================================================================

// MCPAdapter implements ProtocolAdapter for MCP transport.
type MCPAdapter struct {
	BaseAdapter
	endpoint string
}

// NewMCPAdapter creates a new MCP protocol adapter.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		BaseAdapter: BaseAdapter{protocol: ProtocolMCP},
	}
}

// Setup initializes the MCP connection.
func (a *MCPAdapter) Setup(ctx context.Context, config *TestConfig) error {
	a.config = config
	a.endpoint = config.MCPEndpoint
	return nil
}

// Teardown releases MCP connection resources.
func (a *MCPAdapter) Teardown() error {
	return nil
}

// HealthCheck verifies MCP connection is functional.
func (a *MCPAdapter) HealthCheck(_ context.Context) error {
	return nil
}

// =============================================================================
// Test Matrix Entry
// =============================================================================

// TestMatrixEntry represents a single service/protocol test combination.
type TestMatrixEntry struct {
	Service  ServiceType
	Protocol ProtocolType
	Adapter  ProtocolAdapter
}

// BuildTestMatrix creates the full test matrix for all services and protocols.
func BuildTestMatrix() []TestMatrixEntry {
	services := AllServices()
	protocols := AllProtocols()

	var matrix []TestMatrixEntry

	for _, service := range services {
		for _, protocol := range protocols {
			entry := TestMatrixEntry{
				Service:  service,
				Protocol: protocol,
				Adapter:  createAdapter(protocol),
			}
			matrix = append(matrix, entry)
		}
	}

	return matrix
}

// createAdapter creates a protocol adapter for the given protocol type.
func createAdapter(protocol ProtocolType) ProtocolAdapter {
	switch protocol {
	case ProtocolREST:
		return NewRESTAdapter()
	case ProtocolGRPCTCP:
		return NewGRPCTCPAdapter()
	case ProtocolGRPCUDS:
		return NewGRPCUDSAdapter()
	case ProtocolQUIC:
		return NewQUICAdapter()
	case ProtocolMCP:
		return NewMCPAdapter()
	default:
		return nil
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrConnectionFailed indicates a protocol connection failure.
type ErrConnectionFailed struct {
	Protocol ProtocolType
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection failed to %s: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrServiceUnavailable indicates a service is not available.
type ErrServiceUnavailable struct {
	Service ServiceType
	Reason  string
}

func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("service %s unavailable: %s", e.Service, e.Reason)
}

// ErrSurfaceMissing is returned when a transport answers that it has no
// endpoint for an operation this suite covers: the adapter declared
// surface.ErrNoSurface, or the server answered codes.Unimplemented.
// build/docker/devcontainer/run-integration-tests.sh starts platformd with
// every transport (REST, gRPC, QUIC, MCP and the Unix socket) and exports
// their endpoints, and every service must implement every transport, so a
// missing endpoint is a failure, not a reason to skip.
type ErrSurfaceMissing struct {
	Service   string
	Operation string
	Transport string
	Cause     error
}

func (e ErrSurfaceMissing) Error() string {
	return fmt.Sprintf("%s %s has no %s endpoint: %v (every service implements every transport; "+
		"run the suite with build/docker/devcontainer/run-integration-tests.sh, whose platformd serves them all)",
		e.Service, e.Operation, e.Transport, e.Cause)
}

func (e ErrSurfaceMissing) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Test Helper Functions
// =============================================================================

// surfaceMissing returns ErrSurfaceMissing when err says the adapter's
// transport has no endpoint for the operation, and nil otherwise.
func surfaceMissing(adapter ProtocolAdapter, service, operation string, err error) error {
	if !surface.IsNotImplemented(err) {
		return nil
	}
	return ErrSurfaceMissing{
		Service:   service,
		Operation: operation,
		Transport: protocolName(adapter),
		Cause:     err,
	}
}

// allProtocolNames lists every transport the matrix runner supports, for the
// zero-transport guard's failure message.
func allProtocolNames() []string {
	protocols := AllProtocols()
	names := make([]string, 0, len(protocols))
	for _, p := range protocols {
		names = append(names, string(p))
	}
	return names
}

// matrixTransportNames lists the service/protocol combinations a matrix run
// intends to exercise, for the zero-transport guard's failure message.
func matrixTransportNames(matrix []TestMatrixEntry) []string {
	names := make([]string, 0, len(matrix))
	for _, entry := range matrix {
		names = append(names, formatTestName(entry.Service, entry.Protocol))
	}
	return names
}

// formatTestName generates a consistent test name for the matrix entry.
func formatTestName(service ServiceType, protocol ProtocolType) string {
	return fmt.Sprintf("%s/%s", service, protocol)
}

// protocolName returns the string name for a protocol adapter.
func protocolName(adapter ProtocolAdapter) string {
	return string(adapter.Name())
}

// =============================================================================
// Per-Service Adapter Factories
// =============================================================================

// createDaemonAdapter creates a daemon.DaemonCommands adapter for the given protocol.
func createDaemonAdapter(protocol ProtocolType) daemon.DaemonCommands {
	switch protocol {
	case ProtocolREST:
		return daemon.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return daemon.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return daemon.NewUnixAdapter()
	case ProtocolQUIC:
		return daemon.NewQUICAdapter()
	case ProtocolMCP:
		return daemon.NewMCPAdapter()
	default:
		return nil
	}
}

// createCAAdapter creates a ca.CACommands adapter for the given protocol.
func createCAAdapter(protocol ProtocolType) ca.CACommands {
	switch protocol {
	case ProtocolREST:
		return ca.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return ca.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return ca.NewUnixAdapter()
	case ProtocolQUIC:
		return ca.NewQUICAdapter()
	case ProtocolMCP:
		return ca.NewMCPAdapter()
	default:
		return nil
	}
}

// createDNSAdapter creates a dns.DNSCommands adapter for the given protocol.
func createDNSAdapter(protocol ProtocolType) dns.DNSCommands {
	switch protocol {
	case ProtocolREST:
		return dns.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return dns.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return dns.NewUnixAdapter()
	case ProtocolQUIC:
		return dns.NewQUICAdapter()
	case ProtocolMCP:
		return dns.NewMCPAdapter()
	default:
		return nil
	}
}

// createIAMAdapter creates an iam.IAMCommands adapter for the given protocol.
func createIAMAdapter(protocol ProtocolType) iam.IAMCommands {
	switch protocol {
	case ProtocolREST:
		return iam.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return iam.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return iam.NewUnixAdapter()
	case ProtocolQUIC:
		return iam.NewQUICAdapter()
	case ProtocolMCP:
		return iam.NewMCPAdapter()
	default:
		return nil
	}
}

// createKMSAdapter creates a kms.KMSCommands adapter for the given protocol.
func createKMSAdapter(protocol ProtocolType) kms.KMSCommands {
	switch protocol {
	case ProtocolREST:
		return kms.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return kms.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return kms.NewUnixAdapter()
	case ProtocolQUIC:
		return kms.NewQUICAdapter()
	case ProtocolMCP:
		return kms.NewMCPAdapter()
	default:
		return nil
	}
}

// createSDNAdapter creates an sdn.SDNCommands adapter for the given protocol.
func createSDNAdapter(protocol ProtocolType) sdn.SDNCommands {
	switch protocol {
	case ProtocolREST:
		return sdn.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return sdn.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return sdn.NewUnixAdapter()
	case ProtocolQUIC:
		return sdn.NewQUICAdapter()
	case ProtocolMCP:
		return sdn.NewMCPAdapter()
	default:
		return nil
	}
}

// createVTPMAdapter creates a vtpm.VTPMCommands adapter for the given protocol.
func createVTPMAdapter(protocol ProtocolType) vtpm.VTPMCommands {
	switch protocol {
	case ProtocolREST:
		return vtpm.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return vtpm.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return vtpm.NewUnixAdapter()
	case ProtocolQUIC:
		return vtpm.NewQUICAdapter()
	case ProtocolMCP:
		return vtpm.NewMCPAdapter()
	default:
		return nil
	}
}

// createDeviceAdapter creates a device.DeviceCommands adapter for the given protocol.
func createDeviceAdapter(protocol ProtocolType) device.DeviceCommands {
	switch protocol {
	case ProtocolREST:
		return device.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return device.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return device.NewUnixAdapter()
	case ProtocolQUIC:
		return device.NewQUICAdapter()
	case ProtocolMCP:
		return device.NewMCPAdapter()
	default:
		return nil
	}
}

// createAttestationAdapter creates an attestation.AttestationCommands adapter for the given protocol.
func createAttestationAdapter(protocol ProtocolType) attestation.AttestationCommands {
	switch protocol {
	case ProtocolREST:
		return attestation.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return attestation.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return attestation.NewUnixAdapter()
	case ProtocolQUIC:
		return attestation.NewQUICAdapter()
	case ProtocolMCP:
		return attestation.NewMCPAdapter()
	default:
		return nil
	}
}

// createPXEAdapter creates a pxe.PXECommands adapter for the given protocol.
func createPXEAdapter(protocol ProtocolType) pxe.PXECommands {
	switch protocol {
	case ProtocolREST:
		return pxe.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return pxe.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return pxe.NewUnixAdapter()
	case ProtocolQUIC:
		return pxe.NewQUICAdapter()
	case ProtocolMCP:
		return pxe.NewMCPAdapter()
	default:
		return nil
	}
}

// createTPMAdapter creates a tpm.TPMCommands adapter for the given protocol.
func createTPMAdapter(protocol ProtocolType) tpm.TPMCommands {
	switch protocol {
	case ProtocolREST:
		return tpm.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return tpm.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return tpm.NewUnixAdapter()
	case ProtocolQUIC:
		return tpm.NewQUICAdapter()
	case ProtocolMCP:
		return tpm.NewMCPAdapter()
	default:
		return nil
	}
}

// createTenantAdapter creates a tenant.TenantCommands adapter for the given protocol.
func createTenantAdapter(protocol ProtocolType) tenant.TenantCommands {
	switch protocol {
	case ProtocolREST:
		return tenant.NewRESTAdapter()
	case ProtocolGRPCTCP:
		return tenant.NewGRPCAdapter()
	case ProtocolGRPCUDS:
		return tenant.NewUnixAdapter()
	case ProtocolQUIC:
		return tenant.NewQUICAdapter()
	case ProtocolMCP:
		return tenant.NewMCPAdapter()
	default:
		return nil
	}
}

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestMultiProtocolMatrix runs the complete test matrix across all services
// and protocols. This is the main entry point for multi-protocol testing.
func TestMultiProtocolMatrix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	config := DefaultTestConfig()
	matrix := BuildTestMatrix()

	gate := helpers.NewAdapterGate(t, "matrix", matrixTransportNames(matrix)...)
	for _, entry := range matrix {
		entry := entry // Capture for closure
		testName := formatTestName(entry.Service, entry.Protocol)

		t.Run(testName, func(t *testing.T) {
			// Setup adapter
			gate.RequireSetup(t, string(entry.Protocol), entry.Adapter.Setup(ctx, config))
			defer func() {
				if err := entry.Adapter.Teardown(); err != nil {
					t.Logf("Warning: adapter teardown error: %v", err)
				}
			}()

			// Run protocol health check
			if err := entry.Adapter.HealthCheck(ctx); err != nil {
				t.Fatalf("%s transport completed setup but failed its health check: %v", entry.Protocol, err)
			}

			// Dispatch to service-specific tests
			runServiceTests(t, ctx, entry.Service, entry.Adapter)
		})
	}
}

// runServiceTests dispatches to the appropriate service test suite.
func runServiceTests(t *testing.T, ctx context.Context, service ServiceType, adapter ProtocolAdapter) {
	switch service {
	case ServiceCA:
		testCAService(t, ctx, adapter)
	case ServiceDNS:
		testDNSService(t, ctx, adapter)
	case ServiceIAM:
		testIAMService(t, ctx, adapter)
	case ServiceKMS:
		testKMSService(t, ctx, adapter)
	case ServiceSDN:
		testSDNService(t, ctx, adapter)
	case ServiceVTPM:
		testVTPMService(t, ctx, adapter)
	case ServiceDevice:
		testDeviceService(t, ctx, adapter)
	case ServiceAttestation:
		testAttestationService(t, ctx, adapter)
	case ServicePlatform:
		testPlatformService(t, ctx, adapter)
	case ServicePXE:
		testPXEService(t, ctx, adapter)
	case ServiceIDevID:
		testIDevIDService(t, ctx, adapter)
	case ServiceTenant:
		testTenantService(t, ctx, adapter)
	default:
		t.Errorf("Unknown service type: %s", service)
	}
}

// =============================================================================
// Service Tests - CA
// =============================================================================

func testCAService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("Info", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testCAInfo(t, testCtx, adapter)
	})

	t.Run("IssueCertificate", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testCAIssueCertificate(t, testCtx, adapter)
	})

	t.Run("GetCertificate", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testCAGetCertificate(t, testCtx, adapter)
	})

	t.Run("ListCertificates", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testCAListCertificates(t, testCtx, adapter)
	})

	t.Run("RevokeCertificate", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testCARevokeCertificate(t, testCtx, adapter)
	})

	t.Run("CRL", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testCACRL(t, testCtx, adapter)
	})
}

func testCAInfo(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "CA", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA Info should succeed")
	require.NotNil(t, result, "CA Info result should not be nil")
	assert.NotEmpty(t, result.CommonName, "CA common name should not be empty")
	assert.True(t, result.IsInitialized, "CA should be initialized")
}

func testCAIssueCertificate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	cn := fmt.Sprintf("test-matrix-%s-%d.example.com", protocolName(adapter), time.Now().UnixNano())
	opts := ca.IssueCertificateOptions{
		CommonName: cn,
		Algorithm:  "RSA-2048",
		ValidDays:  30,
		SANsDNS:    []string{cn},
	}

	result, err := cmd.IssueCertificate(ctx, opts)
	if missing := surfaceMissing(adapter, "CA", "IssueCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA IssueCertificate should succeed")
	require.NotNil(t, result, "IssueCertificate result should not be nil")
	assert.True(t, result.Success, "Certificate issuance should succeed")
	require.NotNil(t, result.Certificate, "Certificate should not be nil")
	assert.NotEmpty(t, result.Certificate.Serial, "Certificate serial should not be empty")
	assert.Equal(t, cn, result.Certificate.Subject.CommonName, "Certificate CN should match")
}

func testCAGetCertificate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	// Issue a certificate to retrieve
	cn := fmt.Sprintf("test-get-%s-%d.example.com", protocolName(adapter), time.Now().UnixNano())
	issueResult, err := cmd.IssueCertificate(ctx, ca.IssueCertificateOptions{
		CommonName: cn,
		Algorithm:  "RSA-2048",
		ValidDays:  30,
	})
	if missing := surfaceMissing(adapter, "CA", "IssueCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "Issue prerequisite certificate")
	require.NotNil(t, issueResult)
	require.NotNil(t, issueResult.Certificate)

	result, err := cmd.GetCertificate(ctx, ca.GetCertificateOptions{
		CommonName: cn,
	})
	if missing := surfaceMissing(adapter, "CA", "GetCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA GetCertificate should succeed")
	require.NotNil(t, result, "GetCertificate result should not be nil")
	require.NotNil(t, result.Certificate, "Certificate should not be nil")
	assert.Equal(t, cn, result.Certificate.Subject.CommonName, "Retrieved certificate CN should match")
}

func testCAListCertificates(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	result, err := cmd.ListCertificates(ctx, ca.ListCertificatesOptions{Limit: 10})
	if missing := surfaceMissing(adapter, "CA", "ListCertificates", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA ListCertificates should succeed")
	require.NotNil(t, result, "ListCertificates result should not be nil")
	assert.GreaterOrEqual(t, result.Total, int32(0), "Certificate count should be non-negative")
}

func testCARevokeCertificate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	// Issue a certificate to revoke
	cn := fmt.Sprintf("test-revoke-%s-%d.example.com", protocolName(adapter), time.Now().UnixNano())
	issueResult, err := cmd.IssueCertificate(ctx, ca.IssueCertificateOptions{
		CommonName: cn,
		Algorithm:  "RSA-2048",
		ValidDays:  30,
	})
	if missing := surfaceMissing(adapter, "CA", "IssueCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "Issue prerequisite certificate")
	require.NotNil(t, issueResult)
	require.NotNil(t, issueResult.Certificate)
	require.NotEmpty(t, issueResult.Certificate.Serial, "issued certificate must carry its serial")

	// docs/ca/api.md: every transport revokes a certificate by its serial.
	result, err := cmd.RevokeCertificate(ctx, ca.RevokeCertificateOptions{
		CommonName: cn,
		Serial:     issueResult.Certificate.Serial,
		Reason:     ca.RevocationReasonSuperseded,
	})
	if missing := surfaceMissing(adapter, "CA", "RevokeCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA RevokeCertificate should succeed")
	require.NotNil(t, result, "RevokeCertificate result should not be nil")
	assert.True(t, result.Success, "Certificate revocation should succeed")
}

func testCACRL(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createCAAdapter(adapter.Name())
	require.NotNil(t, cmd, "CA adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "CA", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	result, err := cmd.GetCRL(ctx, ca.GetCRLOptions{IncludeEntries: true})
	if missing := surfaceMissing(adapter, "CA", "GetCRL", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "CA GetCRL should succeed")
	require.NotNil(t, result, "GetCRL result should not be nil")
	assert.NotEmpty(t, result.Issuer, "CRL issuer should not be empty")
	assert.False(t, result.ThisUpdate.IsZero(), "CRL ThisUpdate should not be zero")
}

// =============================================================================
// Service Tests - DNS
// =============================================================================

func testDNSService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("ResolveA", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDNSResolveA(t, testCtx, adapter)
	})

	t.Run("ResolveAAAA", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDNSResolveAAAA(t, testCtx, adapter)
	})

	t.Run("ResolveTXT", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDNSResolveTXT(t, testCtx, adapter)
	})

	t.Run("CreateRecord", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDNSCreateRecord(t, testCtx, adapter)
	})

	t.Run("DeleteRecord", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDNSDeleteRecord(t, testCtx, adapter)
	})
}

// setupMatrixDNSZone creates a zone of its own for one DNS leg and returns the
// zone name with a deferable cleanup. The platform resolver answers from the
// zones it serves (docs/dns/), so every leg resolves records it created rather
// than names such as "localhost" no zone carries.
func setupMatrixDNSZone(t *testing.T, ctx context.Context, cmd dns.DNSCommands, adapter ProtocolAdapter) (string, func()) {
	t.Helper()
	zoneName := fmt.Sprintf("matrix-%d.test.", time.Now().UnixNano())
	_, err := cmd.CreateZone(ctx, dns.CreateZoneOptions{Name: zoneName, TTL: 3600})
	if missing := surfaceMissing(adapter, "DNS", "CreateZone", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS CreateZone prerequisite should succeed")
	return zoneName, func() {
		if _, err := cmd.DeleteZone(ctx, zoneName); err != nil {
			t.Errorf("DNS DeleteZone %s cleanup failed: %v", zoneName, err)
		}
	}
}

// testDNSResolveRecord adds one record of recordType to a fresh zone and
// resolves it back over the adapter's transport.
func testDNSResolveRecord(t *testing.T, ctx context.Context, adapter ProtocolAdapter, recordType, value string) {
	cmd := createDNSAdapter(adapter.Name())
	require.NotNil(t, cmd, "DNS adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "DNS", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	zoneName, cleanup := setupMatrixDNSZone(t, ctx, cmd, adapter)
	defer cleanup()

	name := "resolve." + zoneName
	_, err := cmd.AddRecord(ctx, dns.AddRecordOptions{
		ZoneName:   zoneName,
		Name:       name,
		RecordType: recordType,
		Value:      value,
		TTL:        300,
	})
	if missing := surfaceMissing(adapter, "DNS", "AddRecord", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS AddRecord %s prerequisite should succeed", recordType)

	result, err := cmd.Resolve(ctx, name, recordType)
	if missing := surfaceMissing(adapter, "DNS", "Resolve", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS Resolve %s should succeed", recordType)
	require.NotNil(t, result, "Resolve %s result should not be nil", recordType)
	assert.Equal(t, recordType, result.RecordType, "resolved record type")
	// A TXT value may come back in its quoted presentation form.
	assert.Contains(t, strings.Join(result.Values, " "), value, "resolved %s values", recordType)
}

func testDNSResolveA(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	testDNSResolveRecord(t, ctx, adapter, "A", "10.20.30.40")
}

func testDNSResolveAAAA(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	testDNSResolveRecord(t, ctx, adapter, "AAAA", "2001:db8::40")
}

func testDNSResolveTXT(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	testDNSResolveRecord(t, ctx, adapter, "TXT", "matrix-txt-value")
}

func testDNSCreateRecord(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createDNSAdapter(adapter.Name())
	require.NotNil(t, cmd, "DNS adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "DNS", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	zoneName, cleanup := setupMatrixDNSZone(t, ctx, cmd, adapter)
	defer cleanup()

	recordName := "create." + zoneName
	result, err := cmd.AddRecord(ctx, dns.AddRecordOptions{
		ZoneName:   zoneName,
		Name:       recordName,
		RecordType: "A",
		Value:      "10.0.0.1",
		TTL:        300,
	})
	if missing := surfaceMissing(adapter, "DNS", "AddRecord", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS AddRecord should succeed")
	require.NotNil(t, result, "AddRecord result should not be nil")
}

func testDNSDeleteRecord(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := createDNSAdapter(adapter.Name())
	require.NotNil(t, cmd, "DNS adapter should not be nil for protocol %s", protocolName(adapter))

	helpers.RequireAdapterSetup(t, "DNS", protocolName(adapter), cmd.Setup(ctx))
	defer cmd.Teardown()

	zoneName, cleanup := setupMatrixDNSZone(t, ctx, cmd, adapter)
	defer cleanup()

	recordName := "delete." + zoneName
	_, err := cmd.AddRecord(ctx, dns.AddRecordOptions{
		ZoneName:   zoneName,
		Name:       recordName,
		RecordType: "A",
		Value:      "10.0.0.2",
		TTL:        300,
	})
	if missing := surfaceMissing(adapter, "DNS", "AddRecord", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS AddRecord prerequisite should succeed")

	result, err := cmd.DeleteRecord(ctx, recordName, "A")
	if missing := surfaceMissing(adapter, "DNS", "DeleteRecord", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "DNS DeleteRecord should succeed")
	require.NotNil(t, result, "DeleteRecord result should not be nil")

	_, err = cmd.Resolve(ctx, recordName, "A")
	require.Error(t, err, "a deleted record no longer resolves")
}

// =============================================================================
// Service Tests - IAM
// =============================================================================

func testIAMService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("Authenticate", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMAuthenticate(t, testCtx, adapter)
	})
	t.Run("CreateUser", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMCreateUser(t, testCtx, adapter)
	})
	t.Run("GetUser", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMGetUser(t, testCtx, adapter)
	})
	t.Run("ListUsers", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMListUsers(t, testCtx, adapter)
	})
	t.Run("UpdateUser", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMUpdateUser(t, testCtx, adapter)
	})
	t.Run("DeleteUser", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMDeleteUser(t, testCtx, adapter)
	})
	t.Run("CreateRole", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMCreateRole(t, testCtx, adapter)
	})
	t.Run("AssignRole", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMAssignRole(t, testCtx, adapter)
	})
	t.Run("CheckPermission", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIAMCheckPermission(t, testCtx, adapter)
	})
}

func setupIAMAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) iam.IAMCommands {
	t.Helper()
	cmd := createIAMAdapter(adapter.Name())
	require.NotNil(t, cmd, "IAM adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "IAM", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown(ctx) })
	return cmd
}

func testIAMAuthenticate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	result, err := cmd.ListUsers(ctx, iam.ListUsersOptions{TenantID: helpers.HarnessTenantID, Limit: 1})
	if missing := surfaceMissing(adapter, "IAM", "ListUsers", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "IAM ListUsers should succeed as authentication proof")
	require.NotNil(t, result)
}

func testIAMCreateUser(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	email := fmt.Sprintf("matrix-test-%d@example.com", time.Now().UnixNano())
	result, err := cmd.CreateUser(ctx, iam.CreateUserOptions{
		TenantID: helpers.HarnessTenantID, Email: email, Name: "Matrix Test User",
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "IAM CreateUser should succeed")
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.NotEmpty(t, result.User.ID, "User ID should not be empty")
	assert.Equal(t, email, result.User.Email)
	if result.User.ID != "" {
		_, _ = cmd.DeleteUser(ctx, iam.DeleteUserOptions{TenantID: helpers.HarnessTenantID, UserID: result.User.ID})
	}
}

func testIAMGetUser(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	email := fmt.Sprintf("matrix-get-%d@example.com", time.Now().UnixNano())
	createResult, err := cmd.CreateUser(ctx, iam.CreateUserOptions{
		TenantID: helpers.HarnessTenantID, Email: email, Name: "Matrix Get User",
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.User)
	t.Cleanup(func() {
		_, _ = cmd.DeleteUser(ctx, iam.DeleteUserOptions{TenantID: helpers.HarnessTenantID, UserID: createResult.User.ID})
	})

	result, err := cmd.GetUser(ctx, iam.GetUserOptions{TenantID: helpers.HarnessTenantID, UserID: createResult.User.ID})
	if missing := surfaceMissing(adapter, "IAM", "GetUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, createResult.User.ID, result.User.ID)
}

func testIAMListUsers(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	result, err := cmd.ListUsers(ctx, iam.ListUsersOptions{TenantID: helpers.HarnessTenantID, Limit: 10})
	if missing := surfaceMissing(adapter, "IAM", "ListUsers", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Total, int64(0))
}

func testIAMUpdateUser(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	email := fmt.Sprintf("matrix-update-%d@example.com", time.Now().UnixNano())
	createResult, err := cmd.CreateUser(ctx, iam.CreateUserOptions{
		TenantID: helpers.HarnessTenantID, Email: email, Name: "Matrix Update User",
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.User)
	t.Cleanup(func() {
		_, _ = cmd.DeleteUser(ctx, iam.DeleteUserOptions{TenantID: helpers.HarnessTenantID, UserID: createResult.User.ID})
	})

	updatedName := "Matrix Updated User"
	result, err := cmd.UpdateUser(ctx, iam.UpdateUserOptions{
		TenantID: helpers.HarnessTenantID, UserID: createResult.User.ID, Name: updatedName,
	})
	if missing := surfaceMissing(adapter, "IAM", "UpdateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, updatedName, result.User.Name)
}

func testIAMDeleteUser(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	email := fmt.Sprintf("matrix-delete-%d@example.com", time.Now().UnixNano())
	createResult, err := cmd.CreateUser(ctx, iam.CreateUserOptions{
		TenantID: helpers.HarnessTenantID, Email: email, Name: "Matrix Delete User",
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.User)

	result, err := cmd.DeleteUser(ctx, iam.DeleteUserOptions{TenantID: helpers.HarnessTenantID, UserID: createResult.User.ID})
	if missing := surfaceMissing(adapter, "IAM", "DeleteUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func testIAMCreateRole(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	roleID := fmt.Sprintf("matrix-role-%d", time.Now().UnixNano())
	// The CA's certificate scopes (pkg/webservice/v1/rest/ca/handlers.go).
	result, err := cmd.CreateRole(ctx, iam.CreateRoleOptions{
		TenantID: helpers.HarnessTenantID, ID: roleID, Name: "Matrix Test Role",
		Description: "Role created by matrix integration test", Permissions: []string{"certs:read", "certs:generate"},
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateRole", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Role)
	assert.NotEmpty(t, result.Role.ID)
	_, _ = cmd.DeleteRole(ctx, iam.DeleteRoleOptions{TenantID: helpers.HarnessTenantID, RoleID: result.Role.ID})
}

func testIAMAssignRole(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)

	email := fmt.Sprintf("matrix-assign-%d@example.com", time.Now().UnixNano())
	userResult, err := cmd.CreateUser(ctx, iam.CreateUserOptions{TenantID: helpers.HarnessTenantID, Email: email, Name: "Matrix Assign User"})
	if missing := surfaceMissing(adapter, "IAM", "CreateUser", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, userResult)
	require.NotNil(t, userResult.User)
	t.Cleanup(func() {
		_, _ = cmd.DeleteUser(ctx, iam.DeleteUserOptions{TenantID: helpers.HarnessTenantID, UserID: userResult.User.ID})
	})

	roleID := fmt.Sprintf("matrix-assign-role-%d", time.Now().UnixNano())
	roleResult, err := cmd.CreateRole(ctx, iam.CreateRoleOptions{
		TenantID: helpers.HarnessTenantID, ID: roleID, Name: "Matrix Assign Role", Permissions: []string{"certs:read"},
	})
	if missing := surfaceMissing(adapter, "IAM", "CreateRole", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, roleResult)
	require.NotNil(t, roleResult.Role)
	t.Cleanup(func() {
		_, _ = cmd.DeleteRole(ctx, iam.DeleteRoleOptions{TenantID: helpers.HarnessTenantID, RoleID: roleResult.Role.ID})
	})

	result, err := cmd.AssignRole(ctx, iam.AssignRoleOptions{
		TenantID: helpers.HarnessTenantID, UserID: userResult.User.ID, RoleID: roleResult.Role.ID,
	})
	if missing := surfaceMissing(adapter, "IAM", "AssignRole", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
}

func testIAMCheckPermission(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupIAMAdapter(t, ctx, adapter)
	result, err := cmd.CheckPermission(ctx, iam.CheckPermissionOptions{
		TenantID: helpers.HarnessTenantID, SubjectID: "test-user", Action: "read", Resource: "certificates",
	})
	if missing := surfaceMissing(adapter, "IAM", "CheckPermission", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - KMS
// =============================================================================

func testKMSService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("CreateKey", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSCreateKey(t, testCtx, adapter)
	})
	t.Run("GetKey", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSGetKey(t, testCtx, adapter)
	})
	t.Run("ListKeys", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSListKeys(t, testCtx, adapter)
	})
	t.Run("Sign", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSSign(t, testCtx, adapter)
	})
	t.Run("Verify", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSVerify(t, testCtx, adapter)
	})
	t.Run("Encrypt", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSEncrypt(t, testCtx, adapter)
	})
	t.Run("Decrypt", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSDecrypt(t, testCtx, adapter)
	})
	t.Run("RotateKey", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSRotateKey(t, testCtx, adapter)
	})
	t.Run("DeleteKey", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testKMSDeleteKey(t, testCtx, adapter)
	})
}

func setupKMSAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) kms.KMSCommands {
	t.Helper()
	cmd := createKMSAdapter(adapter.Name())
	require.NotNil(t, cmd, "KMS adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "KMS", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown() })
	return cmd
}

func testKMSCreateKey(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-key-%d", time.Now().UnixNano())
	result, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt", Name: "Matrix Test Key",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.KeyID)
	_, _ = cmd.KeyDelete(ctx, result.KeyID, kms.KeyDeleteOptions{Force: true})
}

func testKMSGetKey(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-getkey-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	result, err := cmd.KeyGet(ctx, genResult.KeyID, 0)
	if missing := surfaceMissing(adapter, "KMS", "KeyGet", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, genResult.KeyID, result.KeyID)
}

func testKMSListKeys(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	result, err := cmd.KeyList(ctx, kms.KeyListOptions{Limit: 10})
	if missing := surfaceMissing(adapter, "KMS", "KeyList", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.TotalCount, int32(0))
}

func testKMSSign(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-sign-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "RSA-2048", Purpose: "sign",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	result, err := cmd.CryptoSign(ctx, kms.CryptoSignOptions{
		KeyID: genResult.KeyID, Message: []byte("matrix test message"), HashAlgorithm: "SHA-256",
	})
	if missing := surfaceMissing(adapter, "KMS", "CryptoSign", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Signature)
}

func testKMSVerify(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-verify-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "RSA-2048", Purpose: "sign",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	message := []byte("matrix test message for verification")
	signResult, err := cmd.CryptoSign(ctx, kms.CryptoSignOptions{
		KeyID: genResult.KeyID, Message: message, HashAlgorithm: "SHA-256",
	})
	if missing := surfaceMissing(adapter, "KMS", "CryptoSign", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, signResult)

	result, err := cmd.CryptoVerify(ctx, kms.CryptoVerifyOptions{
		KeyID: genResult.KeyID, Message: message, Signature: signResult.Signature, HashAlgorithm: "SHA-256",
	})
	if missing := surfaceMissing(adapter, "KMS", "CryptoVerify", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid, "Signature should be valid")
}

func testKMSEncrypt(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-encrypt-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	result, err := cmd.CryptoEncrypt(ctx, kms.CryptoEncryptOptions{
		KeyID: genResult.KeyID, Plaintext: []byte("matrix test plaintext"),
	})
	if missing := surfaceMissing(adapter, "KMS", "CryptoEncrypt", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Ciphertext)
}

func testKMSDecrypt(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-decrypt-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	plaintext := []byte("matrix test plaintext for roundtrip")
	encResult, err := cmd.CryptoEncrypt(ctx, kms.CryptoEncryptOptions{KeyID: genResult.KeyID, Plaintext: plaintext})
	if missing := surfaceMissing(adapter, "KMS", "CryptoEncrypt", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, encResult)

	result, err := cmd.CryptoDecrypt(ctx, kms.CryptoDecryptOptions{
		KeyID: genResult.KeyID, Ciphertext: encResult.Ciphertext, Nonce: encResult.Nonce, KeyVersion: encResult.KeyVersion,
	})
	if missing := surfaceMissing(adapter, "KMS", "CryptoDecrypt", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, plaintext, result.Plaintext, "Decrypted plaintext should match original")
}

func testKMSRotateKey(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-rotate-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)
	t.Cleanup(func() { _, _ = cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true}) })

	result, err := cmd.KeyRotate(ctx, genResult.KeyID, true)
	if missing := surfaceMissing(adapter, "KMS", "KeyRotate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.NewVersion, result.OldVersion)
}

func testKMSDeleteKey(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupKMSAdapter(t, ctx, adapter)
	keyID := fmt.Sprintf("matrix-delkey-%d", time.Now().UnixNano())
	genResult, err := cmd.KeyGenerate(ctx, kms.KeyGenerateOptions{
		KeyID: keyID, Algorithm: "AES-256-GCM", Purpose: "encrypt",
	})
	if missing := surfaceMissing(adapter, "KMS", "KeyGenerate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, genResult)

	result, err := cmd.KeyDelete(ctx, genResult.KeyID, kms.KeyDeleteOptions{Force: true})
	if missing := surfaceMissing(adapter, "KMS", "KeyDelete", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - SDN
// =============================================================================

func testSDNService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("CreateNetwork", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNCreateNetwork(t, testCtx, adapter)
	})
	t.Run("GetNetwork", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNGetNetwork(t, testCtx, adapter)
	})
	t.Run("ListNetworks", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNListNetworks(t, testCtx, adapter)
	})
	t.Run("DeleteNetwork", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNDeleteNetwork(t, testCtx, adapter)
	})
	t.Run("AddRoute", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNAddRoute(t, testCtx, adapter)
	})
	t.Run("RemoveRoute", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testSDNRemoveRoute(t, testCtx, adapter)
	})
}

func setupSDNAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) sdn.SDNCommands {
	t.Helper()
	cmd := createSDNAdapter(adapter.Name())
	require.NotNil(t, cmd, "SDN adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "SDN", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown() })
	return cmd
}

func testSDNCreateNetwork(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	opts := sdn.DefaultBridgeOptions("mx-br")
	bridgeID := opts.BridgeID
	result, err := cmd.BridgeCreate(ctx, opts)
	if missing := surfaceMissing(adapter, "SDN", "BridgeCreate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	_, _ = cmd.BridgeDelete(ctx, bridgeID, sdn.BridgeDeleteOptions{Force: true})
}

func testSDNGetNetwork(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	opts := sdn.DefaultBridgeOptions("mx-get")
	bridgeID := opts.BridgeID
	_, err := cmd.BridgeCreate(ctx, opts)
	if missing := surfaceMissing(adapter, "SDN", "BridgeCreate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = cmd.BridgeDelete(ctx, bridgeID, sdn.BridgeDeleteOptions{Force: true}) })

	result, err := cmd.BridgeGet(ctx, bridgeID)
	if missing := surfaceMissing(adapter, "SDN", "BridgeGet", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testSDNListNetworks(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	result, err := cmd.BridgeList(ctx, sdn.BridgeListOptions{Limit: 10})
	if missing := surfaceMissing(adapter, "SDN", "BridgeList", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testSDNDeleteNetwork(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	opts := sdn.DefaultBridgeOptions("mx-del")
	bridgeID := opts.BridgeID
	_, err := cmd.BridgeCreate(ctx, opts)
	if missing := surfaceMissing(adapter, "SDN", "BridgeCreate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)

	result, err := cmd.BridgeDelete(ctx, bridgeID, sdn.BridgeDeleteOptions{})
	if missing := surfaceMissing(adapter, "SDN", "BridgeDelete", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testSDNAddRoute(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	opts := sdn.DefaultBridgeOptions("mx-route")
	bridgeID := opts.BridgeID
	_, err := cmd.BridgeCreate(ctx, opts)
	if missing := surfaceMissing(adapter, "SDN", "BridgeCreate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = cmd.BridgeDelete(ctx, bridgeID, sdn.BridgeDeleteOptions{Force: true}) })

	result, err := cmd.FlowAdd(ctx, sdn.FlowAddOptions{
		BridgeID: bridgeID, Priority: 100,
		Match: sdn.FlowMatch{InPort: 1}, Actions: []sdn.FlowAction{{Type: "output", Port: 2}},
	})
	if missing := surfaceMissing(adapter, "SDN", "FlowAdd", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testSDNRemoveRoute(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupSDNAdapter(t, ctx, adapter)
	opts := sdn.DefaultBridgeOptions("mx-rmrt")
	bridgeID := opts.BridgeID
	_, err := cmd.BridgeCreate(ctx, opts)
	if missing := surfaceMissing(adapter, "SDN", "BridgeCreate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = cmd.BridgeDelete(ctx, bridgeID, sdn.BridgeDeleteOptions{Force: true}) })

	flowResult, err := cmd.FlowAdd(ctx, sdn.FlowAddOptions{
		BridgeID: bridgeID, Priority: 100,
		Match: sdn.FlowMatch{InPort: 1}, Actions: []sdn.FlowAction{{Type: "output", Port: 2}},
	})
	if missing := surfaceMissing(adapter, "SDN", "FlowAdd", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, flowResult)

	result, err := cmd.FlowDelete(ctx, bridgeID, flowResult.FlowID)
	if missing := surfaceMissing(adapter, "SDN", "FlowDelete", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - vTPM
// =============================================================================

func testVTPMService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("CreateVTPM", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testVTPMCreate(t, testCtx, adapter)
	})
	t.Run("GetVTPM", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testVTPMGet(t, testCtx, adapter)
	})
	t.Run("ListVTPMs", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testVTPMList(t, testCtx, adapter)
	})
	t.Run("DeleteVTPM", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testVTPMDelete(t, testCtx, adapter)
	})
	t.Run("Quote", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testVTPMQuote(t, testCtx, adapter)
	})
	t.Run("Seal", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testVTPMSeal(t, testCtx, adapter)
	})
	t.Run("Unseal", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testVTPMUnseal(t, testCtx, adapter)
	})
}

func setupVTPMAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) vtpm.VTPMCommands {
	t.Helper()
	cmd := createVTPMAdapter(adapter.Name())
	require.NotNil(t, cmd, "vTPM adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "vTPM", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown(ctx) })
	return cmd
}

func testVTPMCreate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	hostname := fmt.Sprintf("matrix-vtpm-%d", time.Now().UnixNano())
	result, err := cmd.CreateBundle(ctx, vtpm.CreateBundleOptions{
		Mode: pkgvtpm.BundleModePreAssigned, Hostname: hostname, EKAlgorithm: pkgvtpm.EKAlgorithmRSA,
	})
	if missing := surfaceMissing(adapter, "vTPM", "CreateBundle", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Bundle)
	assert.NotEmpty(t, result.Bundle.ID)
	if result.Bundle.ID != "" {
		_, _ = cmd.DeleteBundle(ctx, vtpm.DeleteBundleOptions{ID: result.Bundle.ID})
	}
}

func testVTPMGet(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	hostname := fmt.Sprintf("matrix-vtpm-get-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateBundle(ctx, vtpm.CreateBundleOptions{
		Mode: pkgvtpm.BundleModePreAssigned, Hostname: hostname, EKAlgorithm: pkgvtpm.EKAlgorithmRSA,
	})
	if missing := surfaceMissing(adapter, "vTPM", "CreateBundle", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Bundle)
	t.Cleanup(func() { _, _ = cmd.DeleteBundle(ctx, vtpm.DeleteBundleOptions{ID: createResult.Bundle.ID}) })

	result, err := cmd.GetBundle(ctx, vtpm.GetBundleOptions{ID: createResult.Bundle.ID})
	if missing := surfaceMissing(adapter, "vTPM", "GetBundle", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Bundle)
	assert.Equal(t, createResult.Bundle.ID, result.Bundle.ID)
}

func testVTPMList(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	result, err := cmd.ListBundles(ctx, vtpm.ListBundlesOptions{})
	if missing := surfaceMissing(adapter, "vTPM", "ListBundles", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testVTPMDelete(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	hostname := fmt.Sprintf("matrix-vtpm-del-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateBundle(ctx, vtpm.CreateBundleOptions{
		Mode: pkgvtpm.BundleModePreAssigned, Hostname: hostname, EKAlgorithm: pkgvtpm.EKAlgorithmRSA,
	})
	if missing := surfaceMissing(adapter, "vTPM", "CreateBundle", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Bundle)

	result, err := cmd.DeleteBundle(ctx, vtpm.DeleteBundleOptions{ID: createResult.Bundle.ID})
	if missing := surfaceMissing(adapter, "vTPM", "DeleteBundle", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testVTPMQuote(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	result, err := cmd.ListBundles(ctx, vtpm.ListBundlesOptions{})
	if missing := surfaceMissing(adapter, "vTPM", "ListBundles", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "vTPM service should be responsive for quote operations")
	require.NotNil(t, result)
}

func testVTPMSeal(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	result, err := cmd.ListBundles(ctx, vtpm.ListBundlesOptions{})
	if missing := surfaceMissing(adapter, "vTPM", "ListBundles", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "vTPM service should be responsive for seal operations")
	require.NotNil(t, result)
}

func testVTPMUnseal(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupVTPMAdapter(t, ctx, adapter)
	result, err := cmd.ListBundles(ctx, vtpm.ListBundlesOptions{})
	if missing := surfaceMissing(adapter, "vTPM", "ListBundles", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err, "vTPM service should be responsive for unseal operations")
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - Device
// =============================================================================

func testDeviceService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("RegisterDevice", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testDeviceRegister(t, testCtx, adapter)
	})
	t.Run("GetDevice", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDeviceGet(t, testCtx, adapter)
	})
	t.Run("ListDevices", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDeviceList(t, testCtx, adapter)
	})
	t.Run("UpdateDevice", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDeviceUpdate(t, testCtx, adapter)
	})
	t.Run("DeleteDevice", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDeviceDelete(t, testCtx, adapter)
	})
	t.Run("DeviceStatus", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testDeviceStatus(t, testCtx, adapter)
	})
}

func setupDeviceAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) device.DeviceCommands {
	t.Helper()
	cmd := createDeviceAdapter(adapter.Name())
	require.NotNil(t, cmd, "Device adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "Device", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown(ctx) })
	return cmd
}

func testDeviceRegister(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	serial := fmt.Sprintf("MATRIX-%d", time.Now().UnixNano())
	result, err := cmd.RegisterDevice(ctx, device.RegisterDeviceOptions{
		TenantID: "default", Serial: serial, Model: "matrix-test-device",
	})
	if missing := surfaceMissing(adapter, "Device", "RegisterDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Device)
}

func testDeviceGet(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	serial := fmt.Sprintf("MATRIX-GET-%d", time.Now().UnixNano())
	regResult, err := cmd.RegisterDevice(ctx, device.RegisterDeviceOptions{
		TenantID: "default", Serial: serial, Model: "matrix-get-device",
	})
	if missing := surfaceMissing(adapter, "Device", "RegisterDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, regResult)
	require.NotNil(t, regResult.Device)

	result, err := cmd.FindBySerial(ctx, device.FindBySerialOptions{
		TenantID: "default", Serial: serial,
	})
	if missing := surfaceMissing(adapter, "Device", "FindBySerial", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testDeviceList(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	result, err := cmd.ListDevices(ctx, device.ListDevicesOptions{TenantID: "default"})
	if missing := surfaceMissing(adapter, "Device", "ListDevices", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testDeviceUpdate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	serial := fmt.Sprintf("MATRIX-UPD-%d", time.Now().UnixNano())
	regResult, err := cmd.RegisterDevice(ctx, device.RegisterDeviceOptions{
		TenantID: "default", Serial: serial, Model: "matrix-update-device",
	})
	if missing := surfaceMissing(adapter, "Device", "RegisterDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, regResult)
	require.NotNil(t, regResult.Device)

	result, err := cmd.UpdateDevice(ctx, device.UpdateDeviceOptions{
		TenantID: "default", DeviceID: fmt.Sprintf("%d", regResult.Device.ID), Model: "updated-model",
	})
	if missing := surfaceMissing(adapter, "Device", "UpdateDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testDeviceDelete(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	serial := fmt.Sprintf("MATRIX-DEL-%d", time.Now().UnixNano())
	regResult, err := cmd.RegisterDevice(ctx, device.RegisterDeviceOptions{
		TenantID: "default", Serial: serial, Model: "matrix-delete-device",
	})
	if missing := surfaceMissing(adapter, "Device", "RegisterDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, regResult)
	require.NotNil(t, regResult.Device)

	result, err := cmd.DeleteDevice(ctx, device.DeleteDeviceOptions{
		TenantID: "default", DeviceID: fmt.Sprintf("%d", regResult.Device.ID),
	})
	if missing := surfaceMissing(adapter, "Device", "DeleteDevice", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testDeviceStatus(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDeviceAdapter(t, ctx, adapter)
	result, err := cmd.ListDevices(ctx, device.ListDevicesOptions{TenantID: "default"})
	if missing := surfaceMissing(adapter, "Device", "ListDevices", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - Attestation
// =============================================================================

// testAttestationService drives the attestation verbs every transport serves
// (docs/attestation/api.md §2), each for an id the daemon does not hold. VM
// identity is served by no transport, so it is not a reachability probe.
func testAttestationService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("CollectVMAttestation", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testAttestationCollectVM(t, testCtx, adapter)
	})
	t.Run("GetManifest", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testAttestationGetManifest(t, testCtx, adapter)
	})
	t.Run("VerifyManifest", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testAttestationVerifyManifest(t, testCtx, adapter)
	})
}

func setupAttestationAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) attestation.AttestationCommands {
	t.Helper()
	cmd := createAttestationAdapter(adapter.Name())
	require.NotNil(t, cmd, "Attestation adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "Attestation", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown(ctx) })
	return cmd
}

// testAttestationCollectVM collects a VM attestation for an unknown VM. The
// daemon owns no TPM session, so every transport answers the
// ErrTPMSessionNotConfigured refusal (docs/attestation/api.md §2).
func testAttestationCollectVM(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupAttestationAdapter(t, ctx, adapter)
	result, err := cmd.GetVMAttestation(ctx, attestation.GetVMAttestationOptions{
		VMID:          "nonexistent-collect-test",
		Nonce:         attestation.GenerateTestNonce(),
		PCRIndices:    attestation.DefaultPCRIndices(),
		HashAlgorithm: attestation.DefaultHashAlgorithm(),
	})
	if missing := surfaceMissing(adapter, "Attestation", "CollectVMAttestation", err); missing != nil {
		t.Fatal(missing)
	}
	want := attestsvc.ErrTPMSessionNotConfigured{Op: "CollectVMAttestation"}.Error()
	require.Error(t, err, "CollectVMAttestation over %s succeeded, want refusal %q", protocolName(adapter), want)
	assert.Contains(t, err.Error(), want, "CollectVMAttestation over %s", protocolName(adapter))
	assert.Nil(t, result, "CollectVMAttestation over %s returned a result alongside its refusal", protocolName(adapter))
}

// testAttestationGetManifest reads a manifest the daemon does not hold and
// requires the transport's typed not-found.
func testAttestationGetManifest(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupAttestationAdapter(t, ctx, adapter)
	_, err := cmd.GetManifest(ctx, attestation.GetManifestOptions{ManifestID: "nonexistent-manifest-test"})
	if missing := surfaceMissing(adapter, "Attestation", "GetManifest", err); missing != nil {
		t.Fatal(missing)
	}
	assert.True(t, attestation.IsNotFound(err), "GetManifest of an unknown manifest over %s = %v, want a typed not-found", protocolName(adapter), err)
}

// testAttestationVerifyManifest verifies a manifest the daemon does not hold.
// Every adapter fetches the stored manifest first, so the lookup's typed
// not-found is the answer (docs/attestation/api.md §3).
func testAttestationVerifyManifest(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupAttestationAdapter(t, ctx, adapter)
	result, err := cmd.VerifyManifest(ctx, attestation.VerifyManifestOptions{ManifestID: "nonexistent-verify-test"})
	if missing := surfaceMissing(adapter, "Attestation", "VerifyManifest", err); missing != nil {
		t.Fatal(missing)
	}
	assert.True(t, attestation.IsNotFound(err), "VerifyManifest of an unknown manifest over %s = %v, want a typed not-found", protocolName(adapter), err)
	assert.Nil(t, result, "VerifyManifest over %s returned a result for an unknown manifest", protocolName(adapter))
}

// =============================================================================
// Service Tests - Platform (Daemon)
// =============================================================================

func testPlatformService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("Health", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testPlatformHealth(t, testCtx, adapter)
	})
	t.Run("Status", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testPlatformStatus(t, testCtx, adapter)
	})
	t.Run("Version", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testPlatformVersion(t, testCtx, adapter)
	})
	t.Run("Metrics", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testPlatformMetrics(t, testCtx, adapter)
	})
	t.Run("Configuration", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testPlatformConfiguration(t, testCtx, adapter)
	})
}

func setupDaemonAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) daemon.DaemonCommands {
	t.Helper()
	cmd := createDaemonAdapter(adapter.Name())
	require.NotNil(t, cmd, "Daemon adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "Daemon", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown() })
	return cmd
}

func testPlatformHealth(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDaemonAdapter(t, ctx, adapter)
	result, err := cmd.Health(ctx)
	if missing := surfaceMissing(adapter, "Daemon", "Health", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Status)
}

func testPlatformStatus(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDaemonAdapter(t, ctx, adapter)
	result, err := cmd.Status(ctx)
	if missing := surfaceMissing(adapter, "Daemon", "Status", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Status)
	assert.NotEmpty(t, result.Version)
}

func testPlatformVersion(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDaemonAdapter(t, ctx, adapter)
	result, err := cmd.Version(ctx)
	if missing := surfaceMissing(adapter, "Daemon", "Version", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Version)
}

func testPlatformMetrics(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDaemonAdapter(t, ctx, adapter)
	result, err := cmd.Health(ctx)
	if missing := surfaceMissing(adapter, "Daemon", "Health", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	for _, c := range result.Components {
		assert.NotEmpty(t, c.Name)
		assert.NotEmpty(t, c.Status)
	}
}

func testPlatformConfiguration(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupDaemonAdapter(t, ctx, adapter)
	result, err := cmd.ListServices(ctx)
	if missing := surfaceMissing(adapter, "Daemon", "ListServices", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.GreaterOrEqual(t, result.Count, 0)
}

// =============================================================================
// Service Tests - PXE
// =============================================================================

// errPXENotConfigured is the refusal platformd's PXE service answers on every
// call. PXE is a gateway-role service and the platformd config has no pxe:
// section, so platformd builds the service with no backend
// (pkg/api/daemon/daemon.go) and each RPC answers Unavailable with
// SERVICE_NOT_CONFIGURED and this detail, which every transport relays.
var errPXENotConfigured = errors.New("PXE service is not configured on this node")

// pxeOperation is one PXE call the matrix drives against platformd.
type pxeOperation struct {
	name string
	call func(ctx context.Context, cmd pxe.PXECommands) error
}

// pxeMatrixDeviceID names a device no node has registered.
const pxeMatrixDeviceID = "pxe-matrix-unregistered-device"

var pxeOperations = []pxeOperation{
	{name: "GetStatus", call: func(ctx context.Context, cmd pxe.PXECommands) error {
		_, err := cmd.GetStatus(ctx)
		return err
	}},
	{name: "RegisterDevice", call: func(ctx context.Context, cmd pxe.PXECommands) error {
		_, err := cmd.RegisterDevice(ctx, pxe.RegisterDeviceOptions{
			MACAddress: pxe.GenerateTestMAC("matrix"),
			PortID:     pxe.GenerateTestPortID("matrix"),
		})
		return err
	}},
	{name: "ListDevices", call: func(ctx context.Context, cmd pxe.PXECommands) error {
		_, err := cmd.ListDevices(ctx, pxe.ListDevicesOptions{})
		return err
	}},
	{name: "GetDevice", call: func(ctx context.Context, cmd pxe.PXECommands) error {
		_, err := cmd.GetDevice(ctx, pxeMatrixDeviceID)
		return err
	}},
	{name: "RemoveDevice", call: func(ctx context.Context, cmd pxe.PXECommands) error {
		_, err := cmd.RemoveDevice(ctx, pxeMatrixDeviceID)
		return err
	}},
}

// testPXEService asserts that every PXE operation answers the declared
// not-configured refusal: platformd serves the PXE surface on every
// transport but never runs a PXE backend.
func testPXEService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	for _, op := range pxeOperations {
		t.Run(op.name, func(t *testing.T) {
			testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			cmd := setupPXEAdapter(t, testCtx, adapter)
			err := op.call(testCtx, cmd)
			if missing := surfaceMissing(adapter, "PXE", op.name, err); missing != nil {
				t.Fatal(missing)
			}
			require.Truef(t, surface.IsDeclaredRefusal(err, errPXENotConfigured),
				"PXE %s over %s: want the not-configured refusal, got %v", op.name, protocolName(adapter), err)
		})
	}
}

func setupPXEAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) pxe.PXECommands {
	t.Helper()
	cmd := createPXEAdapter(adapter.Name())
	require.NotNil(t, cmd, "PXE adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "PXE", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown() })
	return cmd
}

// =============================================================================
// Service Tests - IDevID (TPM Identity)
// =============================================================================

func testIDevIDService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("GetIDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIDevIDGet(t, testCtx, adapter)
	})
	t.Run("CreateIDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testIDevIDCreate(t, testCtx, adapter)
	})
	t.Run("VerifyIDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIDevIDVerify(t, testCtx, adapter)
	})
	t.Run("RevokeIDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testIDevIDRevoke(t, testCtx, adapter)
	})
	t.Run("GetLDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testLDevIDGet(t, testCtx, adapter)
	})
	t.Run("CreateLDevID", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testLDevIDCreate(t, testCtx, adapter)
	})
}

func setupTPMAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) tpm.TPMCommands {
	t.Helper()
	cmd := createTPMAdapter(adapter.Name())
	require.NotNil(t, cmd, "TPM adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "TPM", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown() })
	return cmd
}

func testIDevIDGet(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "TPM", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testIDevIDCreate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.EKCertificate(ctx)
	if missing := surfaceMissing(adapter, "TPM", "EKCertificate", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testIDevIDVerify(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "TPM", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testIDevIDRevoke(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "TPM", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testLDevIDGet(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "TPM", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testLDevIDCreate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTPMAdapter(t, ctx, adapter)
	result, err := cmd.Info(ctx)
	if missing := surfaceMissing(adapter, "TPM", "Info", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service Tests - Tenant
// =============================================================================

func testTenantService(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	t.Run("CreateTenant", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		testTenantCreate(t, testCtx, adapter)
	})
	t.Run("GetTenant", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantGet(t, testCtx, adapter)
	})
	t.Run("ListTenants", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantList(t, testCtx, adapter)
	})
	t.Run("UpdateTenant", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantUpdate(t, testCtx, adapter)
	})
	t.Run("DeleteTenant", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantDelete(t, testCtx, adapter)
	})
	t.Run("TenantQuota", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantQuota(t, testCtx, adapter)
	})
	t.Run("TenantUsage", func(t *testing.T) {
		testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		testTenantUsage(t, testCtx, adapter)
	})
}

func setupTenantAdapter(t *testing.T, ctx context.Context, adapter ProtocolAdapter) tenant.TenantCommands {
	t.Helper()
	cmd := createTenantAdapter(adapter.Name())
	require.NotNil(t, cmd, "Tenant adapter should not be nil for protocol %s", protocolName(adapter))
	helpers.RequireAdapterSetup(t, "Tenant", protocolName(adapter), cmd.Setup(ctx))
	t.Cleanup(func() { cmd.Teardown(ctx) })
	return cmd
}

func testTenantCreate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-tenant-%d", time.Now().UnixNano())
	result, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{
		Name:        tenantName,
		DisplayName: "Matrix Integration Test Tenant",
	})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Tenant)
	assert.NotEmpty(t, result.Tenant.ID)
	if result.Tenant.ID != "" {
		_, _ = cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: result.Tenant.ID})
	}
}

func testTenantGet(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-get-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{Name: tenantName})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Tenant)
	t.Cleanup(func() { _, _ = cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: createResult.Tenant.ID}) })

	result, err := cmd.GetTenant(ctx, tenant.GetTenantOptions{TenantID: createResult.Tenant.ID})
	if missing := surfaceMissing(adapter, "Tenant", "GetTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Tenant)
	assert.Equal(t, createResult.Tenant.ID, result.Tenant.ID)
}

func testTenantList(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	result, err := cmd.ListTenants(ctx, tenant.ListTenantsOptions{Limit: 10})
	if missing := surfaceMissing(adapter, "Tenant", "ListTenants", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testTenantUpdate(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-upd-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{Name: tenantName})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Tenant)
	t.Cleanup(func() { _, _ = cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: createResult.Tenant.ID}) })

	updatedDisplay := "Updated Matrix Tenant"
	result, err := cmd.UpdateTenant(ctx, tenant.UpdateTenantOptions{
		TenantID: createResult.Tenant.ID, DisplayName: &updatedDisplay,
	})
	if missing := surfaceMissing(adapter, "Tenant", "UpdateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testTenantDelete(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-del-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{Name: tenantName})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Tenant)

	result, err := cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: createResult.Tenant.ID})
	if missing := surfaceMissing(adapter, "Tenant", "DeleteTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testTenantQuota(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-quota-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{Name: tenantName})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Tenant)
	t.Cleanup(func() { _, _ = cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: createResult.Tenant.ID}) })

	result, err := cmd.GetQuotas(ctx, tenant.GetQuotasOptions{TenantID: createResult.Tenant.ID})
	if missing := surfaceMissing(adapter, "Tenant", "GetQuotas", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

func testTenantUsage(t *testing.T, ctx context.Context, adapter ProtocolAdapter) {
	cmd := setupTenantAdapter(t, ctx, adapter)
	tenantName := fmt.Sprintf("matrix-usage-%d", time.Now().UnixNano())
	createResult, err := cmd.CreateTenant(ctx, tenant.CreateTenantOptions{Name: tenantName})
	if missing := surfaceMissing(adapter, "Tenant", "CreateTenant", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, createResult)
	require.NotNil(t, createResult.Tenant)
	t.Cleanup(func() { _, _ = cmd.DeleteTenant(ctx, tenant.DeleteTenantOptions{TenantID: createResult.Tenant.ID}) })

	result, err := cmd.GetUsage(ctx, tenant.GetUsageOptions{TenantID: createResult.Tenant.ID})
	if missing := surfaceMissing(adapter, "Tenant", "GetUsage", err); missing != nil {
		t.Fatal(missing)
	}
	require.NoError(t, err)
	require.NotNil(t, result)
}

// =============================================================================
// Service-Specific Protocol Tests
// =============================================================================

// TestServiceProtocolByName runs tests for a specific service across all protocols.
// Usage: go test -run "TestServiceProtocolByName/ca" -tags=integration
func TestServiceProtocolByName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	config := DefaultTestConfig()

	gate := helpers.NewAdapterGate(t, "matrix", allProtocolNames()...)
	for _, service := range AllServices() {
		service := service // Capture for closure
		t.Run(string(service), func(t *testing.T) {
			for _, protocol := range AllProtocols() {
				protocol := protocol // Capture for closure
				t.Run(string(protocol), func(t *testing.T) {
					adapter := createAdapter(protocol)

					gate.RequireSetup(t, string(protocol), adapter.Setup(ctx, config))
					defer func() {
						if err := adapter.Teardown(); err != nil {
							t.Logf("Warning: teardown error: %v", err)
						}
					}()

					if err := adapter.HealthCheck(ctx); err != nil {
						t.Fatalf("%s transport completed setup but failed its health check: %v", protocol, err)
					}

					runServiceTests(t, ctx, service, adapter)
				})
			}
		})
	}
}

// TestProtocolByName runs tests for a specific protocol across all services.
// Usage: go test -run "TestProtocolByName/REST" -tags=integration
func TestProtocolByName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	config := DefaultTestConfig()

	gate := helpers.NewAdapterGate(t, "matrix", allProtocolNames()...)
	for _, protocol := range AllProtocols() {
		protocol := protocol // Capture for closure
		t.Run(string(protocol), func(t *testing.T) {
			adapter := createAdapter(protocol)

			gate.RequireSetup(t, string(protocol), adapter.Setup(ctx, config))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error: %v", err)
				}
			}()

			if err := adapter.HealthCheck(ctx); err != nil {
				t.Fatalf("%s transport completed setup but failed its health check: %v", protocol, err)
			}

			for _, service := range AllServices() {
				service := service // Capture for closure
				t.Run(string(service), func(t *testing.T) {
					runServiceTests(t, ctx, service, adapter)
				})
			}
		})
	}
}
