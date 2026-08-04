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

// Package quic provides the QUIC transport adapter for the platform SDK.
// It wraps the pkg/api/quic client and provides a gRPC-compatible interface
// for service clients, using UDP transport with TLS 1.3.
package quic

import (
	"context"
	"crypto/tls"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolQUIC, Connect)
}

// Adapter implements the transport.Adapter interface for QUIC over UDP.
type Adapter struct {
	client    *quicapi.Client
	connected atomic.Bool
	closed    atomic.Bool
	address   string
}

// Connect establishes a QUIC connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.QUICAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	timeout := opts.GetTimeout()

	// Ensure TLS 1.3 minimum on any provided TLS config
	tlsConfig := opts.TLSConfig
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
		if tlsConfig.MinVersion < tls.VersionTLS13 {
			tlsConfig.MinVersion = tls.VersionTLS13
		}
	}
	if opts.TLSServerName != "" {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		tlsConfig.ServerName = opts.TLSServerName
	}

	// Build QUIC client configuration
	clientConfig := &quicapi.ClientConfig{
		ServerAddr:     opts.QUICAddr,
		TLSConfig:      tlsConfig,
		Timeout:        timeout,
		MaxIdleTimeout: timeout * 2,
		NextProtos:     []string{"platform-quic"},
	}

	// Create QUIC client
	client, err := quicapi.NewClient(clientConfig)
	if err != nil {
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolQUIC,
			Target:   opts.QUICAddr,
			Err:      err,
		}
	}

	a := &Adapter{
		client:  client,
		address: opts.QUICAddr,
	}
	a.connected.Store(true)

	return a, nil
}

// Connection returns a gRPC-compatible client connection interface.
// This wraps the QUIC adapter to provide a unified interface for service clients.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return &quicClientConn{adapter: a, sender: &realQUICSender{client: a.client}}
}

// Close closes the QUIC client connection.
func (a *Adapter) Close() error {
	if a.closed.Swap(true) {
		return nil
	}

	a.connected.Store(false)

	if a.client != nil {
		err := a.client.Close()
		if err != nil {
			return platform.ErrCloseFailed{
				Protocol: platform.ProtocolQUIC,
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

// Target returns the QUIC server address.
func (a *Adapter) Target() string {
	return a.address
}

// Client returns the underlying QUIC client for direct access.
func (a *Adapter) Client() *quicapi.Client {
	return a.client
}

// SetToken sets the authentication token for QUIC requests.
func (a *Adapter) SetToken(token string) {
	if a.client != nil {
		a.client.SetToken(token)
	}
}

// quicSender abstracts the QUIC client transport so tests can inject a
// recorder and assert on the exact bytes that hit the wire. The two
// methods mirror the two send modes used by Invoke: RPC-style for
// regular opcodes (encode args / decode reply) and raw-byte mode for
// category opcodes where the SDK must prepend a sub-opcode prefix.
type quicSender interface {
	Send(ctx context.Context, opcode byte, reqData, respData interface{}) error
	SendRequest(ctx context.Context, opcode byte, payload []byte) (*quicapi.Response, error)
}

// realQUICSender wraps the concrete *quicapi.Client to satisfy quicSender.
type realQUICSender struct {
	client *quicapi.Client
}

func (s *realQUICSender) Send(ctx context.Context, opcode byte, reqData, respData interface{}) error {
	return s.client.Send(ctx, opcode, reqData, respData)
}

func (s *realQUICSender) SendRequest(ctx context.Context, opcode byte, payload []byte) (*quicapi.Response, error) {
	return s.client.SendRequest(ctx, opcode, payload)
}

// quicClientConn implements grpc.ClientConnInterface for QUIC transport.
// This allows using QUIC as a drop-in replacement for gRPC connections.
type quicClientConn struct {
	adapter *Adapter
	sender  quicSender
}

// Invoke performs a unary RPC call by translating to QUIC opcode requests.
// Category opcodes (overlay, gateway, IPAM, switch, tenant barrier, etc.)
// multiplex multiple operations under one wire opcode by stuffing the
// sub-opcode into payload[0] and the marshalled request into payload[1:].
// The server-side dispatchers (e.g. handleSwitchCategory,
// handleTenantBarrierCategory) require this exact framing or they reject
// the request with ErrQUICMissingField{Field: "sub_opcode"}.
func (c *quicClientConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	// Validate method mapping first (request validation before infrastructure check)
	opcode, ok := grpcMethodToOpcodeMap[method]
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

	if c.sender == nil {
		c.sender = &realQUICSender{client: c.adapter.client}
	}

	// Category-opcode services require an explicit sub-opcode prefix on
	// the wire. For these methods we marshal the request ourselves,
	// prepend the sub-opcode byte, and use the raw-payload SendRequest
	// path so the prefix is preserved end-to-end.
	if isCategoryOpcode(opcode) {
		subOpcode, hasSubOpcode := categorySubOpcodeMap[method]
		if !hasSubOpcode {
			return status.Error(codes.Internal, ErrCategorySubOpcodeMissing{Method: method, Opcode: opcode}.Error())
		}

		// Empty-body sub-operations (e.g. provisioning get-nonce /
		// list-sessions) send only the sub-opcode byte on the wire even
		// though the generated gRPC client passes a non-nil empty request.
		payloadArgs := args
		if _, emptyBody := categoryEmptyBodyMethods[method]; emptyBody {
			payloadArgs = nil
		}

		payload, err := buildCategoryPayload(subOpcode, payloadArgs)
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}

		resp, err := c.sender.SendRequest(ctx, opcode, payload)
		if err != nil {
			return translateQUICErrorToGRPC(err)
		}

		if reply != nil && len(resp.Payload) > 0 {
			// Flattened-oneof responses (provisioning fetch-config /
			// poll-session) need a mirror-struct decode; everything else
			// decodes directly into the pb reply by Go field name.
			if decode, hasDecoder := categoryResponseDecoders[method]; hasDecoder {
				if decErr := decode(resp.Payload, reply); decErr != nil {
					return status.Error(codes.Internal, decErr.Error())
				}
				return nil
			}
			if decErr := quicapi.DecodePayload(resp.Payload, reply); decErr != nil {
				return status.Error(codes.Internal, ErrDecodingFailed{Err: decErr}.Error())
			}
		}
		return nil
	}

	// Standard non-category path. Methods whose reply shape differs from
	// the daemon wire response (Count* derived from List* pagination
	// totals) decode through a method-specific decoder; everything else
	// decodes directly into the pb reply by Go field name.
	if decode, hasDecoder := methodResponseDecoders[method]; hasDecoder {
		payload, encErr := quicapi.EncodePayload(args)
		if encErr != nil {
			return status.Error(codes.Internal, ErrEncodingFailed{Err: encErr}.Error())
		}
		resp, err := c.sender.SendRequest(ctx, opcode, payload)
		if err != nil {
			return translateQUICErrorToGRPC(err)
		}
		if reply != nil && len(resp.Payload) > 0 {
			if decErr := decode(resp.Payload, reply); decErr != nil {
				return status.Error(codes.Internal, decErr.Error())
			}
		}
		return nil
	}

	err := c.sender.Send(ctx, opcode, args, reply)
	if err != nil {
		return translateQUICErrorToGRPC(err)
	}

	return nil
}

// buildCategoryPayload marshals args via the protocol codec and prepends
// the sub-opcode byte expected by category-opcode dispatchers. Nil args
// are encoded as a one-byte payload containing only the sub-opcode,
// which mirrors the server-side decode path that treats payload[1:] as
// the optional sub-request body.
func buildCategoryPayload(subOpcode byte, args interface{}) ([]byte, error) {
	if args == nil {
		return []byte{subOpcode}, nil
	}

	encoded, err := quicapi.EncodePayload(args)
	if err != nil {
		return nil, ErrEncodingFailed{Err: err}
	}

	out := make([]byte, 0, 1+len(encoded))
	out = append(out, subOpcode)
	out = append(out, encoded...)
	return out, nil
}

// isCategoryOpcode reports whether opcode is one of the well-known
// category opcodes that multiplex sub-operations via payload[0].
func isCategoryOpcode(opcode byte) bool {
	_, ok := categoryOpcodes[opcode]
	return ok
}

// categoryOpcodes is the canonical set of QUIC category opcodes whose
// server-side handlers expect payload[0] to be the sub-opcode and
// payload[1:] to be the sub-request body. Any opcode added here MUST
// have a matching server-side dispatcher in pkg/api/daemon and every
// gRPC method routed to it MUST appear in categorySubOpcodeMap.
var categoryOpcodes = map[byte]struct{}{
	quicapi.OpOverlayCategory:       {},
	quicapi.OpGatewayCategory:       {},
	quicapi.OpIPAMCategory:          {},
	quicapi.OpTPM2Category:          {},
	quicapi.OpCeremonyCategory:      {},
	quicapi.OpPIVCategory:           {},
	quicapi.OpLUKSCategory:          {},
	quicapi.OpFIDO2Category:         {},
	quicapi.OpTenantBarrierCategory: {},
	quicapi.OpSwitchCategory:        {},
	quicapi.OpProvisioningCategory:  {},
}

// categorySubOpcodeMap routes gRPC method paths to the sub-opcode byte
// that the server-side category dispatcher expects in payload[0].
//
// Every entry in grpcMethodToOpcodeMap whose value appears in
// categoryOpcodes MUST have a corresponding entry here. The package
// init function asserts this invariant at startup so a missing mapping
// is caught at process start, not at first request.
var categorySubOpcodeMap = map[string]byte{
	// Switch Service — OpSwitchCategory (0xCC)
	// Server dispatcher: pkg/api/daemon/quic_switch.go::handleSwitchCategory
	"/platform.v1.SwitchService/ListPorts":     quicapi.SwitchSubListPorts,
	"/platform.v1.SwitchService/GetPortStatus": quicapi.SwitchSubGetPortStatus,
	"/platform.v1.SwitchService/SetPortVLAN":   quicapi.SwitchSubSetPortVLAN,
	"/platform.v1.SwitchService/EnablePort":    quicapi.SwitchSubEnablePort,
	"/platform.v1.SwitchService/DisablePort":   quicapi.SwitchSubDisablePort,

	// Tenant Service — OpTenantBarrierCategory (0x9E)
	// Server dispatcher: pkg/api/daemon/quic_tenant.go::handleTenantBarrierCategory
	"/platform.v1.TenantService/InitTenantBarrier":      quicapi.TenantBarrierSubInit,
	"/platform.v1.TenantService/UnsealTenantBarrier":    quicapi.TenantBarrierSubUnseal,
	"/platform.v1.TenantService/SealTenantBarrier":      quicapi.TenantBarrierSubSeal,
	"/platform.v1.TenantService/GetTenantBarrierStatus": quicapi.TenantBarrierSubStatus,

	// Config Delivery Service — OpProvisioningCategory (0xCF)
	// Server dispatcher: pkg/api/daemon/quic_configdelivery.go::handleProvisioningCategory
	"/platform.v1.ConfigDeliveryService/GetNonce":       quicapi.ProvisioningSubGetNonce,
	"/platform.v1.ConfigDeliveryService/FetchConfig":    quicapi.ProvisioningSubFetchConfig,
	"/platform.v1.ConfigDeliveryService/SignDigest":     quicapi.ProvisioningSubSignDigest,
	"/platform.v1.ConfigDeliveryService/PollSession":    quicapi.ProvisioningSubPollSession,
	"/platform.v1.ConfigDeliveryService/FulfillSession": quicapi.ProvisioningSubFulfillSession,
	"/platform.v1.ConfigDeliveryService/ListSessions":   quicapi.ProvisioningSubListSessions,
	"/platform.v1.ConfigDeliveryService/GetSession":     quicapi.ProvisioningSubGetSession,

	// EAB Service — multiplexed under OpProvisioningCategory (0xCF),
	// sub-range 0x10-0x1A (the single-byte opcode space is fully
	// allocated). Server dispatcher:
	// pkg/api/daemon/quic_eab.go::handleEABCategorySub
	"/platform.v1.EABService/CreateCredential":          quicapi.EABSubCreateCredential,
	"/platform.v1.EABService/GetCredential":             quicapi.EABSubGetCredential,
	"/platform.v1.EABService/GetCredentialByKeyID":      quicapi.EABSubGetCredentialByKeyID,
	"/platform.v1.EABService/ListCredentials":           quicapi.EABSubListCredentials,
	"/platform.v1.EABService/RevokeCredential":          quicapi.EABSubRevokeCredential,
	"/platform.v1.EABService/ValidateCredential":        quicapi.EABSubValidateCredential,
	"/platform.v1.EABService/DeleteCredential":          quicapi.EABSubDeleteCredential,
	"/platform.v1.EABService/GetCredentialQRCode":       quicapi.EABSubGetCredentialQRCode,
	"/platform.v1.EABService/GetEnrollmentURL":          quicapi.EABSubGetEnrollmentURL,
	"/platform.v1.EABService/MarkCredentialUsed":        quicapi.EABSubMarkCredentialUsed,
	"/platform.v1.EABService/CleanupExpiredCredentials": quicapi.EABSubCleanupExpiredCredentials,

	// Device profile assignment — multiplexed under
	// OpProvisioningCategory (0xCF), sub-range 0x20-0x2F. Server
	// dispatcher: pkg/api/daemon/quic_device_handlers.go::
	// handleDeviceProfileCategorySub
	"/platform.v1.DeviceService/AssignProfileToDevice":     quicapi.DeviceProfileSubAssign,
	"/platform.v1.DeviceService/UnassignProfileFromDevice": quicapi.DeviceProfileSubUnassign,
}

// init asserts the cross-table invariant: every gRPC method whose
// resolved opcode is a category opcode must have a sub-opcode mapping.
// A missing entry would silently send a zero-byte sub-opcode and trip
// the server's StatusNotImplemented branch on the first call.
func init() {
	for method, opcode := range grpcMethodToOpcodeMap {
		if _, isCat := categoryOpcodes[opcode]; !isCat {
			continue
		}
		if _, hasSub := categorySubOpcodeMap[method]; !hasSub {
			panic(ErrCategorySubOpcodeMissing{Method: method, Opcode: opcode}.Error())
		}
	}
}

// grpcMethodToOpcodeMap provides O(1) lookup for gRPC method to QUIC opcode mapping.
// Method paths use the proto package "platform.v1" (with dot) and full RPC
// names that exactly match the generated gRPC stubs in sdk/go/gen.
// The QUIC server side dispatches requests by opcode in pkg/api/daemon/quic_service.go.
var grpcMethodToOpcodeMap = map[string]byte{
	// CA Service — proto: pkg/api/grpc/proto/ca.proto
	"/platform.v1.CAService/GetCAInfo":         quicapi.OpCAInfo,
	"/platform.v1.CAService/IssueCertificate":  quicapi.OpCAIssue,
	"/platform.v1.CAService/GetCertificate":    quicapi.OpCAGet,
	"/platform.v1.CAService/ListCertificates":  quicapi.OpCAList,
	"/platform.v1.CAService/RevokeCertificate": quicapi.OpCARevoke,
	"/platform.v1.CAService/RenewCertificate":  quicapi.OpCARenew,
	"/platform.v1.CAService/VerifyCertificate": quicapi.OpCAVerify,
	"/platform.v1.CAService/GetCRL":            quicapi.OpCACRL,
	"/platform.v1.CAService/GetCABundle":       quicapi.OpCABundle,

	// IAM User Operations — proto: pkg/api/grpc/proto/iam.proto
	"/platform.v1.PlatformIAMService/CreateUser": quicapi.OpIAMUserCreate,
	"/platform.v1.PlatformIAMService/DeleteUser": quicapi.OpIAMUserDelete,
	"/platform.v1.PlatformIAMService/GetUser":    quicapi.OpIAMUserGet,
	"/platform.v1.PlatformIAMService/ListUsers":  quicapi.OpIAMUserList,
	"/platform.v1.PlatformIAMService/UpdateUser": quicapi.OpIAMUserUpdate,

	// IAM Role Operations
	"/platform.v1.PlatformIAMService/CreateRole": quicapi.OpIAMRoleCreate,
	"/platform.v1.PlatformIAMService/DeleteRole": quicapi.OpIAMRoleDelete,
	"/platform.v1.PlatformIAMService/GetRole":    quicapi.OpIAMRoleGet,
	"/platform.v1.PlatformIAMService/ListRoles":  quicapi.OpIAMRoleList,
	"/platform.v1.PlatformIAMService/AssignRole": quicapi.OpIAMRoleAssign,
	"/platform.v1.PlatformIAMService/RevokeRole": quicapi.OpIAMRoleRevoke,

	// IAM Group Operations
	"/platform.v1.PlatformIAMService/CreateGroup":       quicapi.OpIAMGroupCreate,
	"/platform.v1.PlatformIAMService/DeleteGroup":       quicapi.OpIAMGroupDelete,
	"/platform.v1.PlatformIAMService/GetGroup":          quicapi.OpIAMGroupGet,
	"/platform.v1.PlatformIAMService/ListGroups":        quicapi.OpIAMGroupList,
	"/platform.v1.PlatformIAMService/AddGroupMember":    quicapi.OpIAMGroupAddMember,
	"/platform.v1.PlatformIAMService/RemoveGroupMember": quicapi.OpIAMGroupRemoveMember,

	// IAM Tenant Operations (delegated through PlatformIAMService)
	"/platform.v1.PlatformIAMService/CreateTenant": quicapi.OpTenantCreate,
	"/platform.v1.PlatformIAMService/DeleteTenant": quicapi.OpTenantDelete,
	"/platform.v1.PlatformIAMService/GetTenant":    quicapi.OpTenantGet,
	"/platform.v1.PlatformIAMService/ListTenants":  quicapi.OpTenantList,

	// IAM Token / Auth Operations
	"/platform.v1.PlatformIAMService/CheckPermission": quicapi.OpIAMCheckPermission,
	"/platform.v1.PlatformIAMService/CreateToken":     quicapi.OpIAMTokenCreate,
	"/platform.v1.PlatformIAMService/RevokeToken":     quicapi.OpIAMTokenRevoke,
	"/platform.v1.PlatformIAMService/VerifyToken":     quicapi.OpIAMTokenVerify,

	// KMS Key Management — proto: pkg/api/grpc/proto/kms.proto
	"/platform.v1.KeyManagementService/GenerateKey":            quicapi.OpKMSGenerateKey,
	"/platform.v1.KeyManagementService/ImportKey":              quicapi.OpKMSImportKey,
	"/platform.v1.KeyManagementService/GetKey":                 quicapi.OpKMSGetKey,
	"/platform.v1.KeyManagementService/ListKeys":               quicapi.OpKMSListKeys,
	"/platform.v1.KeyManagementService/DeleteKey":              quicapi.OpKMSDeleteKey,
	"/platform.v1.KeyManagementService/RotateKey":              quicapi.OpKMSRotateKey,
	"/platform.v1.KeyManagementService/UpdateKeyStatus":        quicapi.OpKMSUpdateKeyStatus,
	"/platform.v1.KeyManagementService/ExportKey":              quicapi.OpKMSExportKey,
	"/platform.v1.KeyManagementService/GetKeyVersions":         quicapi.OpKMSGetKeyVersions,
	"/platform.v1.KeyManagementService/BackendStatus":          quicapi.OpKMSBackendStatus,
	"/platform.v1.KeyManagementService/Encrypt":                quicapi.OpKMSEncrypt,
	"/platform.v1.KeyManagementService/Decrypt":                quicapi.OpKMSDecrypt,
	"/platform.v1.KeyManagementService/BatchEncrypt":           quicapi.OpKMSBatchEncrypt,
	"/platform.v1.KeyManagementService/BatchDecrypt":           quicapi.OpKMSBatchDecrypt,
	"/platform.v1.KeyManagementService/Rewrap":                 quicapi.OpKMSRewrap,
	"/platform.v1.KeyManagementService/Sign":                   quicapi.OpKMSSign,
	"/platform.v1.KeyManagementService/Verify":                 quicapi.OpKMSVerify,
	"/platform.v1.KeyManagementService/GenerateRandom":         quicapi.OpKMSGenerateRandom,
	"/platform.v1.KeyManagementService/Hash":                   quicapi.OpKMSHash,
	"/platform.v1.KeyManagementService/HMAC":                   quicapi.OpKMSHMAC,
	"/platform.v1.KeyManagementService/VerifyHMAC":             quicapi.OpKMSVerifyHMAC,
	"/platform.v1.KeyManagementService/GenerateDataKey":        quicapi.OpKMSGenerateDataKey,
	"/platform.v1.KeyManagementService/GenerateWrappedDataKey": quicapi.OpKMSGenerateWrappedDataKey,

	// vTPM Service — proto: pkg/api/grpc/proto/vtpm.proto
	"/platform.v1.VTPMInstanceService/CreateInstance":    quicapi.OpVTPMCreate,
	"/platform.v1.VTPMInstanceService/DeleteInstance":    quicapi.OpVTPMDelete,
	"/platform.v1.VTPMInstanceService/StartInstance":     quicapi.OpVTPMStart,
	"/platform.v1.VTPMInstanceService/StopInstance":      quicapi.OpVTPMStop,
	"/platform.v1.VTPMInstanceService/ListInstances":     quicapi.OpVTPMList,
	"/platform.v1.VTPMInstanceService/GetInstance":       quicapi.OpVTPMGetState,
	"/platform.v1.VTPMInstanceService/GetInstanceStatus": quicapi.OpVTPMGetState,
	"/platform.v1.VTPMService/QuoteVTPM":                 quicapi.OpVTPMQuote,
	"/platform.v1.VTPMService/SealVTPM":                  quicapi.OpVTPMSeal,
	"/platform.v1.VTPMService/UnsealVTPM":                quicapi.OpVTPMUnseal,
	"/platform.v1.VTPMService/ExtendVTPMPCR":             quicapi.OpVTPMExtendPCR,
	"/platform.v1.VTPMService/ReadVTPMPCR":               quicapi.OpVTPMReadPCR,

	// Device Service — proto: pkg/api/grpc/proto/device.proto
	"/platform.v1.DeviceService/CreateDevice":       quicapi.OpDeviceRegister,
	"/platform.v1.DeviceService/DeleteDevice":       quicapi.OpDeviceUnregister,
	"/platform.v1.DeviceService/GetDevice":          quicapi.OpDeviceGet,
	"/platform.v1.DeviceService/ListDevices":        quicapi.OpDeviceList,
	"/platform.v1.DeviceService/UpdateDevice":       quicapi.OpDeviceUpdate,
	"/platform.v1.DeviceService/ActivateDevice":     quicapi.OpDeviceActivate,
	"/platform.v1.DeviceService/CountDevices":       quicapi.OpDeviceList,
	"/platform.v1.DeviceService/FindDeviceBySerial": quicapi.OpDeviceGet,
	"/platform.v1.DeviceService/CreateProfile":      quicapi.OpDeviceCreateProfile,
	"/platform.v1.DeviceService/GetProfile":         quicapi.OpDeviceGetProfile,
	"/platform.v1.DeviceService/ListProfiles":       quicapi.OpDeviceListProfiles,
	"/platform.v1.DeviceService/CountProfiles":      quicapi.OpDeviceListProfiles,
	"/platform.v1.DeviceService/UpdateProfile":      quicapi.OpDeviceSetProfile,
	"/platform.v1.DeviceService/DeleteProfile":      quicapi.OpDeviceDeleteProfile,
	// Profile assignment travels as sub-opcodes under
	// OpProvisioningCategory because the single-byte opcode space is
	// fully allocated. See categorySubOpcodeMap and
	// pkg/api/daemon/quic_device_handlers.go.
	"/platform.v1.DeviceService/AssignProfileToDevice":     quicapi.OpProvisioningCategory,
	"/platform.v1.DeviceService/UnassignProfileFromDevice": quicapi.OpProvisioningCategory,

	// SDN Service — proto: pkg/api/grpc/proto/sdn.proto
	"/platform.v1.SDNService/CreateBridge": quicapi.OpSDNCreateBridge,
	"/platform.v1.SDNService/DeleteBridge": quicapi.OpSDNDeleteBridge,
	"/platform.v1.SDNService/ListBridges":  quicapi.OpSDNListBridges,
	"/platform.v1.SDNService/GetBridge":    quicapi.OpSDNGetBridge,
	"/platform.v1.SDNService/GetPort":      quicapi.OpSDNGetPort,
	"/platform.v1.SDNService/SetPortState": quicapi.OpSDNSetPortState,
	"/platform.v1.SDNService/CreatePort":   quicapi.OpSDNCreatePort,
	"/platform.v1.SDNService/DeletePort":   quicapi.OpSDNDeletePort,
	"/platform.v1.SDNService/ListPorts":    quicapi.OpSDNListPorts,
	"/platform.v1.SDNService/AddFlow":      quicapi.OpSDNAddFlow,
	"/platform.v1.SDNService/DeleteFlow":   quicapi.OpSDNDeleteFlow,
	"/platform.v1.SDNService/ListFlows":    quicapi.OpSDNListFlows,

	// DNS Service — proto: pkg/api/grpc/proto/platform_dns.proto
	"/platform.v1.DNSService/AddRecord":    quicapi.OpDNSAddRecord,
	"/platform.v1.DNSService/DeleteRecord": quicapi.OpDNSDeleteRecord,
	"/platform.v1.DNSService/ListRecords":  quicapi.OpDNSListRecords,
	"/platform.v1.DNSService/Resolve":      quicapi.OpDNSResolve,
	"/platform.v1.DNSService/CreateZone":   quicapi.OpDNSAddZone,
	"/platform.v1.DNSService/DeleteZone":   quicapi.OpDNSDeleteZone,
	"/platform.v1.DNSService/ListZones":    quicapi.OpDNSListZones,

	// Attestation Service — proto: pkg/api/grpc/proto/attestation.proto
	"/platform.v1.AttestationService/GetAttestationQuote":    quicapi.OpAttestQuote,
	"/platform.v1.AttestationService/VerifyAttestationQuote": quicapi.OpAttestVerify,
	"/platform.v1.AttestationService/CollectHostAttestation": quicapi.OpAttestQuote,

	// IDevID Service — proto: pkg/api/grpc/proto/idevid.proto
	"/platform.v1.IDevIDService/GetIDevID":                quicapi.OpIDevIDInfo,
	"/platform.v1.IDevIDService/DeleteIDevID":             quicapi.OpIDevIDDelete,
	"/platform.v1.IDevIDService/CreateIDevIDCSR":          quicapi.OpIDevIDCSR,
	"/platform.v1.IDevIDService/InstallIDevIDCertificate": quicapi.OpIDevIDInstallCert,
	"/platform.v1.IDevIDService/GetIDevIDCertificate":     quicapi.OpIDevIDGetCert,

	// IAK (under IDevIDService)
	"/platform.v1.IDevIDService/GetIAK":                quicapi.OpIAKInfo,
	"/platform.v1.IDevIDService/DeleteIAK":             quicapi.OpIAKDelete,
	"/platform.v1.IDevIDService/CreateIAKCSR":          quicapi.OpIAKCSR,
	"/platform.v1.IDevIDService/InstallIAKCertificate": quicapi.OpIAKInstallCert,
	"/platform.v1.IDevIDService/GetIAKCertificate":     quicapi.OpIAKGetCert,

	// Tenant Service — proto: pkg/api/grpc/proto/tenant.proto
	"/platform.v1.TenantService/CreateTenant":    quicapi.OpTenantCreate,
	"/platform.v1.TenantService/DeleteTenant":    quicapi.OpTenantDelete,
	"/platform.v1.TenantService/GetTenant":       quicapi.OpTenantGet,
	"/platform.v1.TenantService/GetTenantByName": quicapi.OpTenantGetByName,
	"/platform.v1.TenantService/ListTenants":     quicapi.OpTenantList,
	"/platform.v1.TenantService/UpdateTenant":    quicapi.OpTenantUpdate,
	"/platform.v1.TenantService/SuspendTenant":   quicapi.OpTenantSuspend,
	"/platform.v1.TenantService/ResumeTenant":    quicapi.OpTenantResume,
	"/platform.v1.TenantService/GetQuotas":       quicapi.OpTenantGetQuotas,
	"/platform.v1.TenantService/UpdateQuotas":    quicapi.OpTenantUpdateQuotas,
	"/platform.v1.TenantService/GetUsage":        quicapi.OpTenantGetUsage,
	// Per-tenant barrier ops share OpTenantBarrierCategory and dispatch via
	// payload[0] on the server (pkg/api/daemon/quic_tenant.go::handleTenantBarrierCategory).
	// The SDK adapter prepends the sub-opcode automatically; see
	// categorySubOpcodeMap above.
	"/platform.v1.TenantService/InitTenantBarrier":      quicapi.OpTenantBarrierCategory,
	"/platform.v1.TenantService/UnsealTenantBarrier":    quicapi.OpTenantBarrierCategory,
	"/platform.v1.TenantService/SealTenantBarrier":      quicapi.OpTenantBarrierCategory,
	"/platform.v1.TenantService/GetTenantBarrierStatus": quicapi.OpTenantBarrierCategory,

	// Config Delivery Service — proto: pkg/api/grpc/proto/configdelivery.proto
	// All ConfigDeliveryService methods route to OpProvisioningCategory
	// (0xCF); the SDK adapter prepends the sub-opcode automatically. See
	// categorySubOpcodeMap and pkg/api/daemon/quic_configdelivery.go.
	"/platform.v1.ConfigDeliveryService/GetNonce":       quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/FetchConfig":    quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/SignDigest":     quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/PollSession":    quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/FulfillSession": quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/ListSessions":   quicapi.OpProvisioningCategory,
	"/platform.v1.ConfigDeliveryService/GetSession":     quicapi.OpProvisioningCategory,

	// EAB Service — proto: pkg/api/grpc/proto/eab.proto
	// All EABService methods route to OpProvisioningCategory (0xCF) via
	// the EAB sub-opcode range 0x10-0x1A; the SDK adapter prepends the
	// sub-opcode automatically. See categorySubOpcodeMap,
	// pkg/api/quic/eab_opcodes.go and pkg/api/daemon/quic_eab.go.
	"/platform.v1.EABService/CreateCredential":          quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredential":             quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredentialByKeyID":      quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/ListCredentials":           quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/RevokeCredential":          quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/ValidateCredential":        quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/DeleteCredential":          quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/GetCredentialQRCode":       quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/GetEnrollmentURL":          quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/MarkCredentialUsed":        quicapi.OpProvisioningCategory,
	"/platform.v1.EABService/CleanupExpiredCredentials": quicapi.OpProvisioningCategory,

	// Compute Service — proto: pkg/api/grpc/proto/compute.proto
	"/platform.v1.ComputeService/CreateContainer":  quicapi.OpContainerCreate,
	"/platform.v1.ComputeService/DeleteContainer":  quicapi.OpContainerRemove,
	"/platform.v1.ComputeService/StartContainer":   quicapi.OpContainerStart,
	"/platform.v1.ComputeService/StopContainer":    quicapi.OpContainerStop,
	"/platform.v1.ComputeService/ListContainers":   quicapi.OpContainerList,
	"/platform.v1.ComputeService/GetContainer":     quicapi.OpContainerGet,
	"/platform.v1.ComputeService/GetContainerLogs": quicapi.OpContainerLogs,

	// Switch Service — proto: pkg/api/grpc/proto/switch.proto
	// All SwitchService methods route to OpSwitchCategory (0xCC); the
	// SDK adapter prepends the sub-opcode automatically. See
	// categorySubOpcodeMap and pkg/api/daemon/quic_switch.go.
	"/platform.v1.SwitchService/ListPorts":     quicapi.OpSwitchCategory,
	"/platform.v1.SwitchService/GetPortStatus": quicapi.OpSwitchCategory,
	"/platform.v1.SwitchService/SetPortVLAN":   quicapi.OpSwitchCategory,
	"/platform.v1.SwitchService/EnablePort":    quicapi.OpSwitchCategory,
	"/platform.v1.SwitchService/DisablePort":   quicapi.OpSwitchCategory,

	// Daemon Service — proto: pkg/api/grpc/proto/daemon.proto
	"/platform.v1.PlatformDaemon/GetVersion":       quicapi.OpDaemonVersion,
	"/platform.v1.PlatformDaemon/GetStatus":        quicapi.OpDaemonStatus,
	"/platform.v1.PlatformDaemon/GetHealth":        quicapi.OpHealth,
	"/platform.v1.PlatformDaemon/ListServices":     quicapi.OpDaemonListServices,
	"/platform.v1.PlatformDaemon/GetServiceStatus": quicapi.OpDaemonGetService,
	"/platform.v1.PlatformDaemon/StartService":     quicapi.OpDaemonStartService,
	"/platform.v1.PlatformDaemon/StopService":      quicapi.OpDaemonStopService,
	"/platform.v1.PlatformDaemon/RestartService":   quicapi.OpDaemonRestartService,
}

// NewStream creates a new stream (not fully supported for QUIC in this adapter).
func (c *quicClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not supported over QUIC transport adapter")
}

// quicStatusToGRPCMap provides O(1) lookup for QUIC status to gRPC code mapping.
var quicStatusToGRPCMap = map[byte]codes.Code{
	quicapi.StatusOK:                codes.OK,
	quicapi.StatusInvalidRequest:    codes.InvalidArgument,
	quicapi.StatusNotFound:          codes.NotFound,
	quicapi.StatusUnauthorized:      codes.Unauthenticated,
	quicapi.StatusInternalError:     codes.Internal,
	quicapi.StatusTimeout:           codes.DeadlineExceeded,
	quicapi.StatusAlreadyExists:     codes.AlreadyExists,
	quicapi.StatusPermissionDenied:  codes.PermissionDenied,
	quicapi.StatusResourceExhausted: codes.ResourceExhausted,
	quicapi.StatusInvalidArgument:   codes.InvalidArgument,
	quicapi.StatusUnavailable:       codes.Unavailable,
	quicapi.StatusNotImplemented:    codes.Unimplemented,
}

// translateQUICErrorToGRPC translates QUIC errors to gRPC status errors.
func translateQUICErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}

	// Check for QUIC protocol errors
	if protoErr, ok := err.(*quicapi.ErrProtocol); ok {
		code, found := quicStatusToGRPCMap[protoErr.Status]
		if !found {
			code = codes.Unknown
		}
		return status.Error(code, protoErr.Message)
	}

	// Check for client closed error
	if err == quicapi.ErrClientClosed {
		return status.Error(codes.Unavailable, "QUIC client closed")
	}

	// Check for stream errors
	if err == quicapi.ErrStreamFailed {
		return status.Error(codes.Unavailable, "QUIC stream failed")
	}

	// Default to unavailable for connection issues
	return status.Error(codes.Unavailable, err.Error())
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
