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
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
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

	// Convert args to map for MCP tool arguments. Methods with a custom
	// builder (e.g. provisioning fulfill-session, which must send its
	// uint64 profile_id as a decimal string) bypass the generic JSON
	// round-trip.
	var arguments map[string]interface{}
	var err error
	if build, hasBuilder := mcpArgBuilders[method]; hasBuilder {
		arguments, err = build(args)
	} else {
		arguments, err = structToMap(args)
	}
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	// Call MCP tool
	result, err := c.adapter.client.CallTool(ctx, toolName, arguments)
	if err != nil {
		return translateMCPErrorToGRPC(err)
	}

	// Convert result to reply. Methods with a custom decoder (domain JSON
	// shapes, flattened oneofs) bypass the generic JSON round-trip.
	if reply != nil && result != nil {
		if decode, hasDecoder := mcpReplyDecoders[method]; hasDecoder {
			if decErr := decode(result, reply); decErr != nil {
				return status.Error(codes.Internal, decErr.Error())
			}
			return nil
		}
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
// Method paths use the proto package "platform.v1" (with dot) and full RPC names
// matching the generated gRPC stubs. Tool names mirror those registered server-side
// by pkg/api/mcp/tools.go so adapter and server stay in lockstep.
var grpcMethodToMCPToolMap = map[string]string{
	// Daemon / Health — proto: pkg/api/grpc/proto/daemon.proto
	"/platform.v1.PlatformDaemon/GetHealth":        "platform_health",
	"/platform.v1.PlatformDaemon/GetStatus":        "platform_daemon_status",
	"/platform.v1.PlatformDaemon/GetVersion":       "platform_daemon_version",
	"/platform.v1.PlatformDaemon/ListServices":     "platform_daemon_list_services",
	"/platform.v1.PlatformDaemon/GetServiceStatus": "platform_daemon_get_service",
	"/platform.v1.PlatformDaemon/StartService":     "platform_daemon_start_service",
	"/platform.v1.PlatformDaemon/StopService":      "platform_daemon_stop_service",
	"/platform.v1.PlatformDaemon/RestartService":   "platform_daemon_restart_service",

	// CA Service — proto: pkg/api/grpc/proto/ca.proto
	"/platform.v1.CAService/GetCAInfo":         "ca_info",
	"/platform.v1.CAService/IssueCertificate":  "ca_issue",
	"/platform.v1.CAService/GetCertificate":    "ca_get",
	"/platform.v1.CAService/ListCertificates":  "ca_list",
	"/platform.v1.CAService/RevokeCertificate": "ca_revoke",
	"/platform.v1.CAService/RenewCertificate":  "ca_renew",
	"/platform.v1.CAService/VerifyCertificate": "ca_verify",
	"/platform.v1.CAService/GetCRL":            "ca_crl",
	"/platform.v1.CAService/GetCABundle":       "ca_bundle",

	// IAM User Operations — proto: pkg/api/grpc/proto/iam.proto
	"/platform.v1.PlatformIAMService/CreateUser": "iam_create_user",
	"/platform.v1.PlatformIAMService/DeleteUser": "iam_delete_user",
	"/platform.v1.PlatformIAMService/GetUser":    "iam_get_user",
	"/platform.v1.PlatformIAMService/ListUsers":  "iam_list_users",

	// IAM Role Operations
	"/platform.v1.PlatformIAMService/CreateRole": "iam_create_role",
	"/platform.v1.PlatformIAMService/DeleteRole": "iam_delete_role",
	"/platform.v1.PlatformIAMService/GetRole":    "iam_get_role",
	"/platform.v1.PlatformIAMService/ListRoles":  "iam_list_roles",
	"/platform.v1.PlatformIAMService/AssignRole": "iam_assign_role",
	"/platform.v1.PlatformIAMService/RevokeRole": "iam_revoke_role",

	// IAM Group Operations
	"/platform.v1.PlatformIAMService/CreateGroup":       "iam_create_group",
	"/platform.v1.PlatformIAMService/DeleteGroup":       "iam_delete_group",
	"/platform.v1.PlatformIAMService/GetGroup":          "iam_get_group",
	"/platform.v1.PlatformIAMService/ListGroups":        "iam_list_groups",
	"/platform.v1.PlatformIAMService/AddGroupMember":    "iam_add_group_member",
	"/platform.v1.PlatformIAMService/RemoveGroupMember": "iam_remove_group_member",

	// IAM Tenant Operations
	"/platform.v1.PlatformIAMService/CreateTenant": "iam_create_tenant",
	"/platform.v1.PlatformIAMService/DeleteTenant": "iam_delete_tenant",
	"/platform.v1.PlatformIAMService/GetTenant":    "iam_get_tenant",
	"/platform.v1.PlatformIAMService/ListTenants":  "iam_list_tenants",

	// IAM Token / Auth Operations
	"/platform.v1.PlatformIAMService/Authenticate":    "iam_authenticate",
	"/platform.v1.PlatformIAMService/CheckPermission": "iam_check_permission",
	"/platform.v1.PlatformIAMService/CreateToken":     "iam_create_token",
	"/platform.v1.PlatformIAMService/RevokeToken":     "iam_revoke_token",
	"/platform.v1.PlatformIAMService/VerifyToken":     "iam_verify_token",

	// KMS — proto: pkg/api/grpc/proto/kms.proto
	"/platform.v1.KeyManagementService/GenerateKey":            "kms_generate_key",
	"/platform.v1.KeyManagementService/DeleteKey":              "kms_delete_key",
	"/platform.v1.KeyManagementService/GetKey":                 "kms_get_key",
	"/platform.v1.KeyManagementService/ListKeys":               "kms_list_keys",
	"/platform.v1.KeyManagementService/RotateKey":              "kms_rotate_key",
	"/platform.v1.KeyManagementService/Encrypt":                "kms_encrypt",
	"/platform.v1.KeyManagementService/Decrypt":                "kms_decrypt",
	"/platform.v1.KeyManagementService/Sign":                   "kms_sign",
	"/platform.v1.KeyManagementService/Verify":                 "kms_verify",
	"/platform.v1.KeyManagementService/GenerateRandom":         "kms_random",
	"/platform.v1.KeyManagementService/GenerateDataKey":        "kms_generate_data_key",
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": "kms_generate_wrapped_data_key",

	// vTPM — proto: pkg/api/grpc/proto/vtpm.proto
	"/platform.v1.VTPMService/QuoteVTPM":     "vtpm_quote",
	"/platform.v1.VTPMService/SealVTPM":      "vtpm_seal",
	"/platform.v1.VTPMService/UnsealVTPM":    "vtpm_unseal",
	"/platform.v1.VTPMService/ExtendVTPMPCR": "vtpm_extend_pcr",
	"/platform.v1.VTPMService/ReadVTPMPCR":   "vtpm_read_pcr",

	// Device — proto: pkg/api/grpc/proto/device.proto
	"/platform.v1.DeviceService/CreateDevice": "device_register",
	"/platform.v1.DeviceService/DeleteDevice": "device_unregister",
	"/platform.v1.DeviceService/GetDevice":    "device_get",
	"/platform.v1.DeviceService/ListDevices":  "device_list",
	"/platform.v1.DeviceService/UpdateDevice": "device_update",

	// SDN — proto: pkg/api/grpc/proto/sdn.proto
	"/platform.v1.SDNService/CreateBridge": "sdn_create_bridge",
	"/platform.v1.SDNService/DeleteBridge": "sdn_delete_bridge",
	"/platform.v1.SDNService/ListBridges":  "sdn_list_bridges",
	"/platform.v1.SDNService/AddFlow":      "sdn_add_flow",
	"/platform.v1.SDNService/DeleteFlow":   "sdn_delete_flow",
	"/platform.v1.SDNService/ListFlows":    "sdn_list_flows",

	// DNS — proto: pkg/api/grpc/proto/platform_dns.proto
	"/platform.v1.DNSService/AddRecord":    "dns_add_record",
	"/platform.v1.DNSService/DeleteRecord": "dns_delete_record",
	"/platform.v1.DNSService/ListRecords":  "dns_list_records",
	"/platform.v1.DNSService/Resolve":      "dns_resolve",
	"/platform.v1.DNSService/CreateZone":   "dns_create_zone",
	"/platform.v1.DNSService/DeleteZone":   "dns_delete_zone",
	"/platform.v1.DNSService/ListZones":    "dns_list_zones",

	// Tenant — proto: pkg/api/grpc/proto/tenant.proto
	"/platform.v1.TenantService/CreateTenant":  "tenant_create",
	"/platform.v1.TenantService/DeleteTenant":  "tenant_delete",
	"/platform.v1.TenantService/GetTenant":     "tenant_get",
	"/platform.v1.TenantService/ListTenants":   "tenant_list",
	"/platform.v1.TenantService/UpdateTenant":  "tenant_update",
	"/platform.v1.TenantService/SuspendTenant": "tenant_suspend",
	"/platform.v1.TenantService/ResumeTenant":  "tenant_resume",

	// Compute / Container — proto: pkg/api/grpc/proto/compute.proto
	"/platform.v1.ComputeService/CreateContainer":  "container_create",
	"/platform.v1.ComputeService/DeleteContainer":  "container_delete",
	"/platform.v1.ComputeService/StartContainer":   "container_start",
	"/platform.v1.ComputeService/StopContainer":    "container_stop",
	"/platform.v1.ComputeService/ListContainers":   "container_list",
	"/platform.v1.ComputeService/GetContainer":     "container_get",
	"/platform.v1.ComputeService/GetContainerLogs": "container_logs",

	// Config Delivery (provisioning) — proto: pkg/api/grpc/proto/configdelivery.proto
	// Server registrations live in pkg/api/mcp/provision_tools.go.
	"/platform.v1.ConfigDeliveryService/GetNonce":       "provision_get_nonce",
	"/platform.v1.ConfigDeliveryService/FetchConfig":    "provision_fetch_config",
	"/platform.v1.ConfigDeliveryService/SignDigest":     "provision_sign_digest",
	"/platform.v1.ConfigDeliveryService/PollSession":    "provision_poll_session",
	"/platform.v1.ConfigDeliveryService/FulfillSession": "provision_fulfill_session",
	"/platform.v1.ConfigDeliveryService/ListSessions":   "provision_list_sessions",
	"/platform.v1.ConfigDeliveryService/GetSession":     "provision_get_session",
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
