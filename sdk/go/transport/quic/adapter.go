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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
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
	if tlsConfig != nil && tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.MinVersion = tls.VersionTLS13
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
	return &quicClientConn{adapter: a}
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

// quicClientConn implements grpc.ClientConnInterface for QUIC transport.
// This allows using QUIC as a drop-in replacement for gRPC connections.
type quicClientConn struct {
	adapter *Adapter
}

// Invoke performs a unary RPC call by translating to QUIC opcode requests.
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

	// Send request via QUIC client
	err := c.adapter.client.Send(ctx, opcode, args, reply)
	if err != nil {
		return translateQUICErrorToGRPC(err)
	}

	return nil
}

// NewStream creates a new stream (not fully supported for QUIC in this adapter).
func (c *quicClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streaming not supported over QUIC transport adapter")
}

// grpcMethodToOpcodeMap provides O(1) lookup for gRPC method to QUIC opcode mapping.
var grpcMethodToOpcodeMap = map[string]byte{
	// Health Operations
	"/platformv1.PlatformDaemon/Health":    quicapi.OpHealth,
	"/platformv1.PlatformDaemon/Liveness":  quicapi.OpLiveness,
	"/platformv1.PlatformDaemon/Readiness": quicapi.OpReadiness,

	// CA Service
	"/platformv1.CAService/GetInfo":   quicapi.OpCAInfo,
	"/platformv1.CAService/Issue":     quicapi.OpCAIssue,
	"/platformv1.CAService/Get":       quicapi.OpCAGet,
	"/platformv1.CAService/List":      quicapi.OpCAList,
	"/platformv1.CAService/Revoke":    quicapi.OpCARevoke,
	"/platformv1.CAService/Renew":     quicapi.OpCARenew,
	"/platformv1.CAService/Verify":    quicapi.OpCAVerify,
	"/platformv1.CAService/GetCRL":    quicapi.OpCACRL,
	"/platformv1.CAService/GetBundle": quicapi.OpCABundle,

	// IAM User Operations
	"/platformv1.PlatformIAMService/CreateUser": quicapi.OpIAMUserCreate,
	"/platformv1.PlatformIAMService/DeleteUser": quicapi.OpIAMUserDelete,
	"/platformv1.PlatformIAMService/GetUser":    quicapi.OpIAMUserGet,
	"/platformv1.PlatformIAMService/ListUsers":  quicapi.OpIAMUserList,

	// IAM Role Operations
	"/platformv1.PlatformIAMService/CreateRole": quicapi.OpIAMRoleCreate,
	"/platformv1.PlatformIAMService/DeleteRole": quicapi.OpIAMRoleDelete,
	"/platformv1.PlatformIAMService/GetRole":    quicapi.OpIAMRoleGet,
	"/platformv1.PlatformIAMService/ListRoles":  quicapi.OpIAMRoleList,
	"/platformv1.PlatformIAMService/AssignRole": quicapi.OpIAMRoleAssign,
	"/platformv1.PlatformIAMService/RevokeRole": quicapi.OpIAMRoleRevoke,

	// IAM Group Operations
	"/platformv1.PlatformIAMService/CreateGroup":       quicapi.OpIAMGroupCreate,
	"/platformv1.PlatformIAMService/DeleteGroup":       quicapi.OpIAMGroupDelete,
	"/platformv1.PlatformIAMService/GetGroup":          quicapi.OpIAMGroupGet,
	"/platformv1.PlatformIAMService/ListGroups":        quicapi.OpIAMGroupList,
	"/platformv1.PlatformIAMService/AddGroupMember":    quicapi.OpIAMGroupAddMember,
	"/platformv1.PlatformIAMService/RemoveGroupMember": quicapi.OpIAMGroupRemoveMember,

	// IAM Tenant Operations
	"/platformv1.PlatformIAMService/CreateTenant": quicapi.OpTenantCreate,
	"/platformv1.PlatformIAMService/DeleteTenant": quicapi.OpTenantDelete,
	"/platformv1.PlatformIAMService/GetTenant":    quicapi.OpTenantGet,
	"/platformv1.PlatformIAMService/ListTenants":  quicapi.OpTenantList,

	// IAM Auth Operations
	"/platformv1.PlatformIAMService/Authenticate":    quicapi.OpIAMAuthenticate,
	"/platformv1.PlatformIAMService/CheckPermission": quicapi.OpIAMCheckPermission,
	"/platformv1.PlatformIAMService/CreateToken":     quicapi.OpIAMTokenCreate,
	"/platformv1.PlatformIAMService/RevokeToken":     quicapi.OpIAMTokenRevoke,
	"/platformv1.PlatformIAMService/VerifyToken":     quicapi.OpIAMTokenVerify,

	// KMS Key Management
	"/platformv1.KeyManagementService/CreateKey":  quicapi.OpKMSGenerateKey,
	"/platformv1.KeyManagementService/ImportKey":  quicapi.OpKMSImportKey,
	"/platformv1.KeyManagementService/GetKey":     quicapi.OpKMSGetKey,
	"/platformv1.KeyManagementService/ListKeys":   quicapi.OpKMSListKeys,
	"/platformv1.KeyManagementService/DeleteKey":  quicapi.OpKMSDeleteKey,
	"/platformv1.KeyManagementService/RotateKey":  quicapi.OpKMSRotateKey,
	"/platformv1.KeyManagementService/ExportKey":  quicapi.OpKMSExportKey,
	"/platformv1.KeyManagementService/GetVersion": quicapi.OpKMSGetKeyVersions,

	// KMS Crypto Operations
	"/platformv1.KeyManagementService/Encrypt":                quicapi.OpKMSEncrypt,
	"/platformv1.KeyManagementService/Decrypt":                quicapi.OpKMSDecrypt,
	"/platformv1.KeyManagementService/Sign":                   quicapi.OpKMSSign,
	"/platformv1.KeyManagementService/Verify":                 quicapi.OpKMSVerify,
	"/platformv1.KeyManagementService/GenerateRandom":         quicapi.OpKMSGenerateRandom,
	"/platformv1.KeyManagementService/Hash":                   quicapi.OpKMSHash,
	"/platformv1.KeyManagementService/HMAC":                   quicapi.OpKMSHMAC,
	"/platformv1.KeyManagementService/GenerateDataKey":        quicapi.OpKMSGenerateDataKey,
	"/platformv1.KeyManagementService/GenerateWrappedDataKey": quicapi.OpKMSGenerateWrappedDataKey,

	// VTPM Operations
	"/platformv1.VTPMService/Create":    quicapi.OpVTPMCreate,
	"/platformv1.VTPMService/Delete":    quicapi.OpVTPMDelete,
	"/platformv1.VTPMService/Start":     quicapi.OpVTPMStart,
	"/platformv1.VTPMService/Stop":      quicapi.OpVTPMStop,
	"/platformv1.VTPMService/List":      quicapi.OpVTPMList,
	"/platformv1.VTPMService/GetState":  quicapi.OpVTPMGetState,
	"/platformv1.VTPMService/GetEK":     quicapi.OpVTPMGetEK,
	"/platformv1.VTPMService/GetAK":     quicapi.OpVTPMGetAK,
	"/platformv1.VTPMService/CreateAK":  quicapi.OpVTPMCreateAK,
	"/platformv1.VTPMService/Quote":     quicapi.OpVTPMQuote,
	"/platformv1.VTPMService/Seal":      quicapi.OpVTPMSeal,
	"/platformv1.VTPMService/Unseal":    quicapi.OpVTPMUnseal,
	"/platformv1.VTPMService/ExtendPCR": quicapi.OpVTPMExtendPCR,
	"/platformv1.VTPMService/ReadPCR":   quicapi.OpVTPMReadPCR,
	"/platformv1.VTPMService/GetRandom": quicapi.OpVTPMGetRandom,

	// Device Operations
	"/platformv1.DeviceService/Register": quicapi.OpDeviceRegister,
	"/platformv1.DeviceService/Delete":   quicapi.OpDeviceUnregister,
	"/platformv1.DeviceService/Get":      quicapi.OpDeviceGet,
	"/platformv1.DeviceService/List":     quicapi.OpDeviceList,
	"/platformv1.DeviceService/Update":   quicapi.OpDeviceUpdate,
	"/platformv1.DeviceService/Attest":   quicapi.OpDeviceAttest,
	"/platformv1.DeviceService/Activate": quicapi.OpDeviceActivate,

	// SDN Operations
	"/platformv1.SDNService/CreateBridge":     quicapi.OpSDNCreateBridge,
	"/platformv1.SDNService/DeleteBridge":     quicapi.OpSDNDeleteBridge,
	"/platformv1.SDNService/ListBridges":      quicapi.OpSDNListBridges,
	"/platformv1.SDNService/GetPortState":     quicapi.OpSDNGetPortState,
	"/platformv1.SDNService/SetPortState":     quicapi.OpSDNSetPortState,
	"/platformv1.SDNService/AddPort":          quicapi.OpSDNCreatePort,
	"/platformv1.SDNService/DeletePort":       quicapi.OpSDNDeletePort,
	"/platformv1.SDNService/AddFlow":          quicapi.OpSDNAddFlow,
	"/platformv1.SDNService/DeleteFlow":       quicapi.OpSDNDeleteFlow,
	"/platformv1.SDNService/ListFlows":        quicapi.OpSDNListFlows,
	"/platformv1.SDNService/ApplyPolicy":      quicapi.OpSDNApplyPolicy,
	"/platformv1.SDNService/GetPolicy":        quicapi.OpSDNGetPolicy,
	"/platformv1.SDNService/ListPolicies":     quicapi.OpSDNListPolicies,
	"/platformv1.SDNService/AuthenticatePort": quicapi.OpSDNSetPortState,
	"/platformv1.SDNService/GetVLAN":          quicapi.OpSDNGetVLAN,

	// DNS Operations
	"/platformv1.DNSService/AddRecord":    quicapi.OpDNSAddRecord,
	"/platformv1.DNSService/DeleteRecord": quicapi.OpDNSDeleteRecord,
	"/platformv1.DNSService/GetRecord":    quicapi.OpDNSGetRecord,
	"/platformv1.DNSService/ListRecords":  quicapi.OpDNSListRecords,
	"/platformv1.DNSService/Resolve":      quicapi.OpDNSResolve,
	"/platformv1.DNSService/CreateZone":   quicapi.OpDNSAddZone,
	"/platformv1.DNSService/DeleteZone":   quicapi.OpDNSDeleteZone,
	"/platformv1.DNSService/ListZones":    quicapi.OpDNSListZones,

	// Attestation Operations
	"/platformv1.AttestationService/GetQuote":       quicapi.OpAttestQuote,
	"/platformv1.AttestationService/VerifyQuote":    quicapi.OpAttestVerify,
	"/platformv1.AttestationService/GetEK":          quicapi.OpAttestGetEK,
	"/platformv1.AttestationService/GetAK":          quicapi.OpAttestGetAK,
	"/platformv1.AttestationService/ChallengeAK":    quicapi.OpAttestChallenge,
	"/platformv1.AttestationService/VerifyChalleng": quicapi.OpAttestResponse,
	"/platformv1.AttestationService/GetPCRs":        quicapi.OpAttestGetPCRs,

	// IDevID Operations
	"/platformv1.IDevIDService/Generate":    quicapi.OpIDevIDGenerate,
	"/platformv1.IDevIDService/GetInfo":     quicapi.OpIDevIDInfo,
	"/platformv1.IDevIDService/Delete":      quicapi.OpIDevIDDelete,
	"/platformv1.IDevIDService/GetCSR":      quicapi.OpIDevIDCSR,
	"/platformv1.IDevIDService/InstallCert": quicapi.OpIDevIDInstallCert,
	"/platformv1.IDevIDService/GetCert":     quicapi.OpIDevIDGetCert,
	"/platformv1.IDevIDService/Exists":      quicapi.OpHasIDevID,

	// IAK Operations
	"/platformv1.IAKService/Generate":    quicapi.OpIAKGenerate,
	"/platformv1.IAKService/GetInfo":     quicapi.OpIAKInfo,
	"/platformv1.IAKService/Delete":      quicapi.OpIAKDelete,
	"/platformv1.IAKService/GetCSR":      quicapi.OpIAKCSR,
	"/platformv1.IAKService/InstallCert": quicapi.OpIAKInstallCert,
	"/platformv1.IAKService/GetCert":     quicapi.OpIAKGetCert,
	"/platformv1.IAKService/Exists":      quicapi.OpHasIAK,

	// Tenant Operations
	"/platformv1.TenantService/Create":       quicapi.OpTenantCreate,
	"/platformv1.TenantService/Delete":       quicapi.OpTenantDelete,
	"/platformv1.TenantService/Get":          quicapi.OpTenantGet,
	"/platformv1.TenantService/GetByName":    quicapi.OpTenantGetByName,
	"/platformv1.TenantService/List":         quicapi.OpTenantList,
	"/platformv1.TenantService/Update":       quicapi.OpTenantUpdate,
	"/platformv1.TenantService/Suspend":      quicapi.OpTenantSuspend,
	"/platformv1.TenantService/Resume":       quicapi.OpTenantResume,
	"/platformv1.TenantService/GetQuotas":    quicapi.OpTenantGetQuotas,
	"/platformv1.TenantService/UpdateQuotas": quicapi.OpTenantUpdateQuotas,
	"/platformv1.TenantService/GetUsage":     quicapi.OpTenantGetUsage,

	// PXE Operations
	"/platformv1.PXEService/ListDevices":    quicapi.OpPXEListDevices,
	"/platformv1.PXEService/GetDevice":      quicapi.OpPXEGetDevice,
	"/platformv1.PXEService/RegisterDevice": quicapi.OpPXERegisterDevice,
	"/platformv1.PXEService/UpdateState":    quicapi.OpPXEUpdateState,
	"/platformv1.PXEService/Authorize":      quicapi.OpPXEAuthorize,
	"/platformv1.PXEService/Quarantine":     quicapi.OpPXEQuarantine,

	// Certificate Operations
	"/platformv1.CertificateService/Issue":    quicapi.OpCertIssue,
	"/platformv1.CertificateService/Revoke":   quicapi.OpCertRevoke,
	"/platformv1.CertificateService/Renew":    quicapi.OpCertRenew,
	"/platformv1.CertificateService/Get":      quicapi.OpCertGet,
	"/platformv1.CertificateService/List":     quicapi.OpCertList,
	"/platformv1.CertificateService/Verify":   quicapi.OpCertVerify,
	"/platformv1.CertificateService/GetChain": quicapi.OpCertGetChain,
	"/platformv1.CertificateService/GetCRL":   quicapi.OpCertGetCRL,

	// Provisioning Operations
	"/platformv1.ProvisioningService/FetchProfile": quicapi.OpProvFetchProfile,
	"/platformv1.ProvisioningService/Activate":     quicapi.OpProvActivate,
	"/platformv1.ProvisioningService/Deactivate":   quicapi.OpProvDeactivate,
	"/platformv1.ProvisioningService/GetState":     quicapi.OpProvGetState,
	"/platformv1.ProvisioningService/Enroll":       quicapi.OpProvEnroll,
	"/platformv1.ProvisioningService/Renew":        quicapi.OpProvRenew,

	// JWT/Auth Operations
	"/platformv1.AuthService/CreateJWT":  quicapi.OpJWTCreate,
	"/platformv1.AuthService/VerifyJWT":  quicapi.OpJWTVerify,
	"/platformv1.AuthService/RefreshJWT": quicapi.OpJWTRefresh,
	"/platformv1.AuthService/RevokeJWT":  quicapi.OpJWTRevoke,
	"/platformv1.AuthService/GetJWTKeys": quicapi.OpJWTGetKeys,
	"/platformv1.AuthService/Login":      quicapi.OpAuthLogin,
	"/platformv1.AuthService/Logout":     quicapi.OpAuthLogout,
	"/platformv1.AuthService/Check":      quicapi.OpAuthCheck,
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
