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

// Package mcp provides the MCP (Model Context Protocol) transport adapter for the platform SDK.
// It wraps the pkg/api/mcp client and provides a gRPC-compatible interface
// for service clients, using JSON-RPC 2.0 over HTTP.
package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolMCP, Connect)
}

// Adapter implements the transport.Adapter interface for MCP over HTTP.
type Adapter struct {
	client    *mcpapi.Client
	connected atomic.Bool
	closed    atomic.Bool
	address   string
}

// Connect establishes an MCP connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.MCPAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	// Ensure address has proper scheme - always use HTTPS
	address := opts.MCPAddr
	if !strings.HasPrefix(address, "http://") && !strings.HasPrefix(address, "https://") {
		address = "https://" + address
	}

	// Build MCP client configuration
	clientConfig := mcpapi.DefaultClientConfig(address)
	clientConfig.Timeout = opts.GetTimeout()

	// Create MCP client
	client, err := mcpapi.NewClient(clientConfig)
	if err != nil {
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolMCP,
			Target:   opts.MCPAddr,
			Err:      err,
		}
	}

	a := &Adapter{
		client:  client,
		address: opts.MCPAddr,
	}
	a.connected.Store(true)

	// Optionally initialize the MCP connection
	initCtx, cancel := context.WithTimeout(ctx, opts.GetTimeout())
	defer cancel()

	// Initialize the MCP connection. Initialization failure is non-fatal
	// because the MCP server might not require initialization.
	if _, initErr := client.Initialize(initCtx); initErr != nil {
		a.connected.Store(false)
	}

	return a, nil
}

// Connection returns a gRPC-compatible client connection interface.
// This wraps the MCP adapter to provide a unified interface for service clients.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return &mcpClientConn{adapter: a}
}

// Close closes the MCP client connection.
func (a *Adapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	a.connected.Store(false)

	if a.client != nil {
		err := a.client.Close()
		if err != nil {
			return platform.ErrCloseFailed{
				Protocol: platform.ProtocolMCP,
				Err:      err,
			}
		}
	}

	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	if a.client == nil {
		return false
	}
	return a.connected.Load() && !a.closed.Load() && a.client.IsConnected()
}

// Target returns the MCP server address.
func (a *Adapter) Target() string {
	return a.address
}

// Client returns the underlying MCP client for direct access.
func (a *Adapter) Client() *mcpapi.Client {
	return a.client
}

// SetToken sets the authentication token for MCP requests.
func (a *Adapter) SetToken(token string) {
	if a.client != nil {
		a.client.SetToken(token)
	}
}

// mcpClientConn implements grpc.ClientConnInterface for MCP transport.
// This allows using MCP as a drop-in replacement for gRPC connections.
type mcpClientConn struct {
	adapter *Adapter
}

// Invoke performs a unary RPC call by translating to MCP tool calls.
func (c *mcpClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	// Validate method mapping first (request validation before infrastructure check)
	toolName, ok := grpcMethodToMCPToolMap[method]
	if !ok {
		return status.Error(codes.Unimplemented, ErrMethodNotMapped{Method: method}.Error())
	}

	// Check connection state
	if c.adapter.closed.Load() {
		return status.Error(codes.Unavailable, "connection closed")
	}

	if c.adapter.client == nil {
		return status.Error(codes.Unavailable, "client not initialized")
	}

	// Convert args to map for MCP tool arguments
	arguments, err := structToMap(args)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Call MCP tool
	result, err := c.adapter.client.CallTool(ctx, toolName, arguments)
	if err != nil {
		return translateMCPErrorToGRPC(err)
	}

	// Convert result to reply
	if reply != nil && result != nil {
		if err := mapToStruct(result, reply); err != nil {
			return status.Error(codes.Internal, ErrUnmarshalFailed{Err: err}.Error())
		}
	}

	return nil
}

// NewStream creates a new stream (not supported for MCP).
func (c *mcpClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not supported over MCP transport")
}

// grpcMethodToMCPToolMap provides O(1) lookup for gRPC method to MCP tool mapping.
var grpcMethodToMCPToolMap = map[string]string{
	// Health Operations
	"/platformv1.PlatformDaemon/Health":    "platform.health",
	"/platformv1.PlatformDaemon/Liveness":  "platform.liveness",
	"/platformv1.PlatformDaemon/Readiness": "platform.readiness",
	"/platformv1.PlatformDaemon/GetStatus": "platform.status",

	// CA Service
	"/platformv1.CAService/GetInfo":   "ca.info",
	"/platformv1.CAService/Issue":     "ca.issue",
	"/platformv1.CAService/Get":       "ca.get",
	"/platformv1.CAService/List":      "ca.list",
	"/platformv1.CAService/Revoke":    "ca.revoke",
	"/platformv1.CAService/Renew":     "ca.renew",
	"/platformv1.CAService/Verify":    "ca.verify",
	"/platformv1.CAService/GetCRL":    "ca.crl",
	"/platformv1.CAService/GetBundle": "ca.bundle",

	// IAM User Operations
	"/platformv1.PlatformIAMService/CreateUser": "iam.user.create",
	"/platformv1.PlatformIAMService/DeleteUser": "iam.user.delete",
	"/platformv1.PlatformIAMService/GetUser":    "iam.user.get",
	"/platformv1.PlatformIAMService/ListUsers":  "iam.user.list",

	// IAM Role Operations
	"/platformv1.PlatformIAMService/CreateRole": "iam.role.create",
	"/platformv1.PlatformIAMService/DeleteRole": "iam.role.delete",
	"/platformv1.PlatformIAMService/GetRole":    "iam.role.get",
	"/platformv1.PlatformIAMService/ListRoles":  "iam.role.list",
	"/platformv1.PlatformIAMService/AssignRole": "iam.role.assign",
	"/platformv1.PlatformIAMService/RevokeRole": "iam.role.revoke",

	// IAM Group Operations
	"/platformv1.PlatformIAMService/CreateGroup":       "iam.group.create",
	"/platformv1.PlatformIAMService/DeleteGroup":       "iam.group.delete",
	"/platformv1.PlatformIAMService/GetGroup":          "iam.group.get",
	"/platformv1.PlatformIAMService/ListGroups":        "iam.group.list",
	"/platformv1.PlatformIAMService/AddGroupMember":    "iam.group.add_member",
	"/platformv1.PlatformIAMService/RemoveGroupMember": "iam.group.remove_member",

	// IAM Tenant Operations
	"/platformv1.PlatformIAMService/CreateTenant": "iam.tenant.create",
	"/platformv1.PlatformIAMService/DeleteTenant": "iam.tenant.delete",
	"/platformv1.PlatformIAMService/GetTenant":    "iam.tenant.get",
	"/platformv1.PlatformIAMService/ListTenants":  "iam.tenant.list",

	// IAM Auth Operations
	"/platformv1.PlatformIAMService/Authenticate":    "iam.authenticate",
	"/platformv1.PlatformIAMService/CheckPermission": "iam.check_permission",
	"/platformv1.PlatformIAMService/CreateToken":     "iam.token.create",
	"/platformv1.PlatformIAMService/RevokeToken":     "iam.token.revoke",
	"/platformv1.PlatformIAMService/VerifyToken":     "iam.token.verify",

	// KMS Key Management
	"/platformv1.KeyManagementService/CreateKey":              "kms.key.create",
	"/platformv1.KeyManagementService/DeleteKey":              "kms.key.delete",
	"/platformv1.KeyManagementService/GetKey":                 "kms.key.get",
	"/platformv1.KeyManagementService/ListKeys":               "kms.key.list",
	"/platformv1.KeyManagementService/RotateKey":              "kms.key.rotate",
	"/platformv1.KeyManagementService/Encrypt":                "kms.encrypt",
	"/platformv1.KeyManagementService/Decrypt":                "kms.decrypt",
	"/platformv1.KeyManagementService/Sign":                   "kms.sign",
	"/platformv1.KeyManagementService/Verify":                 "kms.verify",
	"/platformv1.KeyManagementService/GenerateRandom":         "kms.random",
	"/platformv1.KeyManagementService/GenerateDataKey":        "kms.datakey.generate",
	"/platformv1.KeyManagementService/GenerateWrappedDataKey": "kms.datakey.generate_wrapped",

	// VTPM Operations
	"/platformv1.VTPMService/Create":    "vtpm.create",
	"/platformv1.VTPMService/Delete":    "vtpm.delete",
	"/platformv1.VTPMService/Start":     "vtpm.start",
	"/platformv1.VTPMService/Stop":      "vtpm.stop",
	"/platformv1.VTPMService/List":      "vtpm.list",
	"/platformv1.VTPMService/GetState":  "vtpm.state",
	"/platformv1.VTPMService/Quote":     "vtpm.quote",
	"/platformv1.VTPMService/Seal":      "vtpm.seal",
	"/platformv1.VTPMService/Unseal":    "vtpm.unseal",
	"/platformv1.VTPMService/ExtendPCR": "vtpm.pcr.extend",
	"/platformv1.VTPMService/ReadPCR":   "vtpm.pcr.read",

	// Device Operations
	"/platformv1.DeviceService/Register": "device.register",
	"/platformv1.DeviceService/Delete":   "device.delete",
	"/platformv1.DeviceService/Get":      "device.get",
	"/platformv1.DeviceService/List":     "device.list",
	"/platformv1.DeviceService/Update":   "device.update",
	"/platformv1.DeviceService/Attest":   "device.attest",

	// SDN Operations
	"/platformv1.SDNService/CreateBridge":     "sdn.bridge.create",
	"/platformv1.SDNService/DeleteBridge":     "sdn.bridge.delete",
	"/platformv1.SDNService/ListBridges":      "sdn.bridge.list",
	"/platformv1.SDNService/GetPortState":     "sdn.port.get_state",
	"/platformv1.SDNService/SetPortState":     "sdn.port.set_state",
	"/platformv1.SDNService/AddPort":          "sdn.port.add",
	"/platformv1.SDNService/DeletePort":       "sdn.port.delete",
	"/platformv1.SDNService/AddFlow":          "sdn.flow.add",
	"/platformv1.SDNService/DeleteFlow":       "sdn.flow.delete",
	"/platformv1.SDNService/ListFlows":        "sdn.flow.list",
	"/platformv1.SDNService/ApplyPolicy":      "sdn.policy.apply",
	"/platformv1.SDNService/GetPolicy":        "sdn.policy.get",
	"/platformv1.SDNService/ListPolicies":     "sdn.policy.list",
	"/platformv1.SDNService/AuthenticatePort": "sdn.port.authenticate",

	// DNS Operations
	"/platformv1.DNSService/AddRecord":    "dns.record.add",
	"/platformv1.DNSService/DeleteRecord": "dns.record.delete",
	"/platformv1.DNSService/GetRecord":    "dns.record.get",
	"/platformv1.DNSService/ListRecords":  "dns.record.list",
	"/platformv1.DNSService/Resolve":      "dns.resolve",
	"/platformv1.DNSService/CreateZone":   "dns.zone.create",
	"/platformv1.DNSService/DeleteZone":   "dns.zone.delete",
	"/platformv1.DNSService/ListZones":    "dns.zone.list",

	// Attestation Operations
	"/platformv1.AttestationService/GetQuote":       "attestation.quote",
	"/platformv1.AttestationService/VerifyQuote":    "attestation.verify",
	"/platformv1.AttestationService/GetEK":          "attestation.ek",
	"/platformv1.AttestationService/GetAK":          "attestation.ak",
	"/platformv1.AttestationService/CreateAK":       "attestation.ak.create",
	"/platformv1.AttestationService/ChallengeAK":    "attestation.challenge",
	"/platformv1.AttestationService/VerifyChalleng": "attestation.challenge.verify",

	// IDevID Operations
	"/platformv1.IDevIDService/Generate":    "idevid.generate",
	"/platformv1.IDevIDService/GetInfo":     "idevid.info",
	"/platformv1.IDevIDService/Delete":      "idevid.delete",
	"/platformv1.IDevIDService/GetCSR":      "idevid.csr",
	"/platformv1.IDevIDService/InstallCert": "idevid.cert.install",
	"/platformv1.IDevIDService/GetCert":     "idevid.cert.get",
	"/platformv1.IDevIDService/Exists":      "idevid.exists",

	// IAK Operations
	"/platformv1.IAKService/Generate":    "iak.generate",
	"/platformv1.IAKService/GetInfo":     "iak.info",
	"/platformv1.IAKService/Delete":      "iak.delete",
	"/platformv1.IAKService/GetCSR":      "iak.csr",
	"/platformv1.IAKService/InstallCert": "iak.cert.install",
	"/platformv1.IAKService/GetCert":     "iak.cert.get",
	"/platformv1.IAKService/Exists":      "iak.exists",

	// Tenant Operations
	"/platformv1.TenantService/Create":       "tenant.create",
	"/platformv1.TenantService/Delete":       "tenant.delete",
	"/platformv1.TenantService/Get":          "tenant.get",
	"/platformv1.TenantService/List":         "tenant.list",
	"/platformv1.TenantService/Update":       "tenant.update",
	"/platformv1.TenantService/Suspend":      "tenant.suspend",
	"/platformv1.TenantService/Resume":       "tenant.resume",
	"/platformv1.TenantService/GetQuotas":    "tenant.quotas.get",
	"/platformv1.TenantService/UpdateQuotas": "tenant.quotas.update",

	// PXE Operations
	"/platformv1.PXEService/ListDevices":    "pxe.device.list",
	"/platformv1.PXEService/GetDevice":      "pxe.device.get",
	"/platformv1.PXEService/RegisterDevice": "pxe.device.register",
	"/platformv1.PXEService/UpdateState":    "pxe.device.update_state",
	"/platformv1.PXEService/Authorize":      "pxe.device.authorize",
	"/platformv1.PXEService/Quarantine":     "pxe.device.quarantine",
	"/platformv1.PXEService/GetStatus":      "pxe.status",

	// Compute/Container Operations
	"/platformv1.ComputeService/CreateContainer":  "container.create",
	"/platformv1.ComputeService/DeleteContainer":  "container.delete",
	"/platformv1.ComputeService/StartContainer":   "container.start",
	"/platformv1.ComputeService/StopContainer":    "container.stop",
	"/platformv1.ComputeService/ListContainers":   "container.list",
	"/platformv1.ComputeService/GetContainer":     "container.get",
	"/platformv1.ComputeService/AttestContainer":  "container.attest",
	"/platformv1.ComputeService/GetContainerLogs": "container.logs",
}

// mcpErrorCodeToGRPCMap provides O(1) lookup for MCP error codes to gRPC codes.
var mcpErrorCodeToGRPCMap = map[int]codes.Code{
	mcpapi.ParseError:             codes.InvalidArgument,
	mcpapi.InvalidRequest:         codes.InvalidArgument,
	mcpapi.MethodNotFound:         codes.Unimplemented,
	mcpapi.InvalidParams:          codes.InvalidArgument,
	mcpapi.InternalError:          codes.Internal,
	mcpapi.AuthenticationRequired: codes.Unauthenticated,
	mcpapi.InvalidToken:           codes.Unauthenticated,
	mcpapi.PermissionDenied:       codes.PermissionDenied,
	mcpapi.ServiceUnavailable:     codes.Unavailable,
}

// translateMCPErrorToGRPC translates MCP errors to gRPC status errors.
func translateMCPErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	// Check for MCP-specific errors
	if mcpErr, ok := err.(*mcpapi.MCPError); ok {
		code, found := mcpErrorCodeToGRPCMap[mcpErr.Code]
		if !found {
			code = codes.Unknown
		}
		return status.Error(code, mcpErr.Message)
	}

	// Default to unavailable for connection issues
	return status.Error(codes.Unavailable, err.Error())
}

// structToMap converts a struct to a map via JSON round-trip.
func structToMap(v interface{}) (map[string]interface{}, error) {
	if v == nil {
		return nil, nil
	}

	data, err := json.Marshal(v)
	if err != nil {
		return nil, ErrMarshalFailed{Err: err}
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}

	return result, nil
}

// mapToStruct converts a map to a struct via JSON round-trip.
func mapToStruct(src interface{}, dst interface{}) error {
	if src == nil || dst == nil {
		return nil
	}

	data, err := json.Marshal(src)
	if err != nil {
		return ErrMarshalFailed{Err: err}
	}

	if err := json.Unmarshal(data, dst); err != nil {
		return ErrUnmarshalFailed{Err: err}
	}

	return nil
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
