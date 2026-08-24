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

package daemon

import "fmt"

// ErrDaemonNotRunning is returned when attempting operations on a stopped daemon
type ErrDaemonNotRunning struct{}

func (e ErrDaemonNotRunning) Error() string {
	return "daemon is not running"
}

// ErrDaemonAlreadyRunning is returned when attempting to start an already running daemon
type ErrDaemonAlreadyRunning struct{}

func (e ErrDaemonAlreadyRunning) Error() string {
	return "daemon is already running"
}

// ErrServiceNotFound is returned when a requested service does not exist
type ErrServiceNotFound struct {
	ServiceName string
}

func (e ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceName)
}

// ErrServiceAlreadyRunning is returned when attempting to start an already running service
type ErrServiceAlreadyRunning struct {
	ServiceName string
}

func (e ErrServiceAlreadyRunning) Error() string {
	return fmt.Sprintf("service already running: %s", e.ServiceName)
}

// ErrServiceNotRunning is returned when attempting operations on a stopped service
type ErrServiceNotRunning struct {
	ServiceName string
}

func (e ErrServiceNotRunning) Error() string {
	return fmt.Sprintf("service is not running: %s", e.ServiceName)
}

// ErrServiceStartFailed is returned when a service fails to start
type ErrServiceStartFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStartFailed) Error() string {
	return fmt.Sprintf("service %s failed to start: %s", e.ServiceName, e.Reason)
}

// ErrServiceStopFailed is returned when a service fails to stop
type ErrServiceStopFailed struct {
	ServiceName string
	Reason      string
}

func (e ErrServiceStopFailed) Error() string {
	return fmt.Sprintf("service %s failed to stop: %s", e.ServiceName, e.Reason)
}

// ErrConfigNotFound is returned when requested configuration does not exist
type ErrConfigNotFound struct {
	ConfigKey string
}

func (e ErrConfigNotFound) Error() string {
	return fmt.Sprintf("configuration not found: %s", e.ConfigKey)
}

// ErrInvalidConfig is returned when configuration validation fails
type ErrInvalidConfig struct {
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s", e.Reason)
}

// ErrProvisionFailed is returned when platform provisioning fails
type ErrProvisionFailed struct {
	Reason string
}

func (e ErrProvisionFailed) Error() string {
	return fmt.Sprintf("provisioning failed: %s", e.Reason)
}

// ErrShutdownFailed is returned when graceful shutdown fails
type ErrShutdownFailed struct {
	Reason string
}

func (e ErrShutdownFailed) Error() string {
	return fmt.Sprintf("shutdown failed: %s", e.Reason)
}

// ErrInvalidServiceType is returned when an unknown service type is specified
type ErrInvalidServiceType struct {
	Type string
}

func (e ErrInvalidServiceType) Error() string {
	return fmt.Sprintf("invalid service type: %s", e.Type)
}

// ErrHealthRegistryNotConfigured is returned when health check operations
// are attempted but the health registry is not configured
type ErrHealthRegistryNotConfigured struct{}

func (e ErrHealthRegistryNotConfigured) Error() string {
	return "health registry not configured"
}

// ErrHealthCheckFailed is returned when a health check operation fails
type ErrHealthCheckFailed struct {
	Component string
	Reason    string
}

func (e ErrHealthCheckFailed) Error() string {
	return fmt.Sprintf("health check failed for %s: %s", e.Component, e.Reason)
}

// ErrDatabaseNotAvailable is returned when the database is not available for operations
type ErrDatabaseNotAvailable struct {
	Reason string
}

func (e ErrDatabaseNotAvailable) Error() string {
	return fmt.Sprintf("database not available: %s", e.Reason)
}

// ErrUnsupportedRecordType is returned when an unsupported DNS record type is specified
type ErrUnsupportedRecordType struct{}

func (e ErrUnsupportedRecordType) Error() string {
	return "unsupported DNS record type"
}

// ErrDNSServiceNotAvailable is returned when DNS service is not configured
type ErrDNSServiceNotAvailable struct{}

func (e ErrDNSServiceNotAvailable) Error() string {
	return "DNS service not available"
}

// ErrDNSInvalidParameter is returned when a DNS operation receives an invalid parameter
type ErrDNSInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrDNSInvalidParameter) Error() string {
	return fmt.Sprintf("invalid DNS parameter %s: %s", e.Parameter, e.Reason)
}

// ErrServiceNotAvailable is returned when a service is not configured or available
type ErrServiceNotAvailable struct {
	Service string
}

func (e ErrServiceNotAvailable) Error() string {
	return fmt.Sprintf("service not available: %s", e.Service)
}

// ErrServiceUnavailable is returned when a service is temporarily unavailable
// or not initialized yet. This is used by gRPC service adapters when the
// underlying SDK client is nil.
type ErrServiceUnavailable struct {
	Service string
}

func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("service unavailable: %s", e.Service)
}

// =============================================================================
// TLS Configuration Errors
// =============================================================================

// ErrTLSConfigFailed indicates a TLS configuration error during server setup.
type ErrTLSConfigFailed struct {
	Reason string
}

func (e ErrTLSConfigFailed) Error() string {
	return "tls config failed: " + e.Reason
}

// =============================================================================
// gRPC Server Errors
// =============================================================================

// ErrGRPCServerNotConfigured is returned when the gRPC server is not configured
type ErrGRPCServerNotConfigured struct{}

func (e ErrGRPCServerNotConfigured) Error() string {
	return "gRPC server not configured"
}

// =============================================================================
// REST Service Errors
// =============================================================================

// ErrRESTServerNotRunning is returned when attempting operations on a stopped REST server
type ErrRESTServerNotRunning struct{}

func (e ErrRESTServerNotRunning) Error() string {
	return "REST server is not running"
}

// ErrRESTServerAlreadyRunning is returned when attempting to start an already running REST server
type ErrRESTServerAlreadyRunning struct{}

func (e ErrRESTServerAlreadyRunning) Error() string {
	return "REST server is already running"
}

// ErrRESTServerStartFailed is returned when the REST server fails to start
type ErrRESTServerStartFailed struct {
	Reason string
}

func (e ErrRESTServerStartFailed) Error() string {
	return fmt.Sprintf("REST server failed to start: %s", e.Reason)
}

// ErrRESTServerStopFailed is returned when the REST server fails to stop gracefully
type ErrRESTServerStopFailed struct {
	Reason string
}

func (e ErrRESTServerStopFailed) Error() string {
	return fmt.Sprintf("REST server failed to stop: %s", e.Reason)
}

// ErrRESTInvalidRequest is returned when a REST request is invalid
type ErrRESTInvalidRequest struct {
	Reason string
}

func (e ErrRESTInvalidRequest) Error() string {
	return fmt.Sprintf("invalid REST request: %s", e.Reason)
}

// ErrRESTEncodingFailed is returned when JSON encoding fails
type ErrRESTEncodingFailed struct {
	Cause error
}

func (e ErrRESTEncodingFailed) Error() string {
	return fmt.Sprintf("REST response encoding failed: %v", e.Cause)
}

func (e ErrRESTEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrRESTDecodingFailed is returned when JSON decoding fails
type ErrRESTDecodingFailed struct {
	Cause error
}

func (e ErrRESTDecodingFailed) Error() string {
	return fmt.Sprintf("REST request decoding failed: %v", e.Cause)
}

func (e ErrRESTDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidRequestBody is returned when the request body is invalid or malformed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrMissingRequiredField is returned when a required field is missing from a request
type ErrMissingRequiredField struct {
	Field string
}

func (e ErrMissingRequiredField) Error() string {
	return fmt.Sprintf("missing required field: %s", e.Field)
}

// =============================================================================
// QUIC Service Errors
// =============================================================================

// ErrQUICNilRequest is returned when a nil request is passed to the QUIC handler
type ErrQUICNilRequest struct{}

func (e ErrQUICNilRequest) Error() string {
	return "QUIC request cannot be nil"
}

// ErrQUICHandlerPanic is returned when a handler sub-function panics.
// The recover() guard in QUICServiceHandler.HandleRequest catches the panic,
// logs a stack trace, and converts it to a StatusInternalError response so the
// QUIC stream is never closed without a valid response frame.
type ErrQUICHandlerPanic struct {
	Cause interface{}
}

func (e ErrQUICHandlerPanic) Error() string {
	return fmt.Sprintf("QUIC handler panic: %v", e.Cause)
}

// ErrQUICUnknownOpcode is returned when an unknown opcode is received
type ErrQUICUnknownOpcode struct {
	Opcode byte
}

func (e ErrQUICUnknownOpcode) Error() string {
	return fmt.Sprintf("unknown QUIC opcode: 0x%02X", e.Opcode)
}

// ErrQUICServiceUnavailable is returned when a required service is not available
type ErrQUICServiceUnavailable struct {
	Service string
}

func (e ErrQUICServiceUnavailable) Error() string {
	return fmt.Sprintf("QUIC service unavailable: %s", e.Service)
}

// ErrQUICDecodingFailed is returned when payload decoding fails
type ErrQUICDecodingFailed struct {
	Cause error
}

func (e ErrQUICDecodingFailed) Error() string {
	return fmt.Sprintf("QUIC payload decoding failed: %v", e.Cause)
}

func (e ErrQUICDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICEncodingFailed is returned when payload encoding fails
type ErrQUICEncodingFailed struct {
	Cause error
}

func (e ErrQUICEncodingFailed) Error() string {
	return fmt.Sprintf("QUIC payload encoding failed: %v", e.Cause)
}

func (e ErrQUICEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICMissingField is returned when a required field is missing
type ErrQUICMissingField struct {
	Field string
}

func (e ErrQUICMissingField) Error() string {
	return fmt.Sprintf("QUIC request missing required field: %s", e.Field)
}

// ErrQUICOperationFailed is returned when a QUIC operation fails
type ErrQUICOperationFailed struct {
	Op    string
	Cause error
}

func (e ErrQUICOperationFailed) Error() string {
	return fmt.Sprintf("QUIC operation %s failed: %v", e.Op, e.Cause)
}

func (e ErrQUICOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICServerNotConfigured is returned when QUIC server is not configured
type ErrQUICServerNotConfigured struct{}

func (e ErrQUICServerNotConfigured) Error() string {
	return "QUIC server not configured"
}

// ErrQUICServerStartFailed is returned when the QUIC server fails to start
type ErrQUICServerStartFailed struct {
	Cause error
}

func (e ErrQUICServerStartFailed) Error() string {
	return fmt.Sprintf("QUIC server failed to start: %v", e.Cause)
}

func (e ErrQUICServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrQUICServerStopFailed is returned when the QUIC server fails to stop gracefully
type ErrQUICServerStopFailed struct {
	Cause error
}

func (e ErrQUICServerStopFailed) Error() string {
	return fmt.Sprintf("QUIC server failed to stop: %v", e.Cause)
}

func (e ErrQUICServerStopFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// MCP Service Errors
// =============================================================================

// ErrMCPServerNotRunning is returned when attempting operations on a stopped MCP server
type ErrMCPServerNotRunning struct{}

func (e ErrMCPServerNotRunning) Error() string {
	return "MCP server is not running"
}

// ErrMCPServerAlreadyRunning is returned when attempting to start an already running MCP server
type ErrMCPServerAlreadyRunning struct{}

func (e ErrMCPServerAlreadyRunning) Error() string {
	return "MCP server is already running"
}

// ErrMCPServerStartFailed is returned when the MCP server fails to start
type ErrMCPServerStartFailed struct {
	Cause error
}

func (e ErrMCPServerStartFailed) Error() string {
	return fmt.Sprintf("MCP server failed to start: %v", e.Cause)
}

func (e ErrMCPServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrMCPServerStopFailed is returned when the MCP server fails to stop gracefully
type ErrMCPServerStopFailed struct {
	Cause error
}

func (e ErrMCPServerStopFailed) Error() string {
	return fmt.Sprintf("MCP server failed to stop: %v", e.Cause)
}

func (e ErrMCPServerStopFailed) Unwrap() error {
	return e.Cause
}

// ErrMCPServerNotConfigured is returned when MCP server is not configured
type ErrMCPServerNotConfigured struct{}

func (e ErrMCPServerNotConfigured) Error() string {
	return "MCP server not configured"
}

// =============================================================================
// vTPM Service Errors
// =============================================================================

// ErrVTPMOperationNotImplemented is returned when a vTPM operation is not yet implemented
type ErrVTPMOperationNotImplemented struct {
	Operation string
}

func (e ErrVTPMOperationNotImplemented) Error() string {
	return fmt.Sprintf("vTPM operation not implemented: %s", e.Operation)
}

// =============================================================================
// Device Service Errors
// =============================================================================

// ErrDeviceOperationNotImplemented is returned when a device operation is not yet implemented
type ErrDeviceOperationNotImplemented struct {
	Operation string
}

func (e ErrDeviceOperationNotImplemented) Error() string {
	return fmt.Sprintf("device operation not implemented: %s", e.Operation)
}

// ErrInvalidDeviceID is returned when a device ID is invalid
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrAttestationFailed is returned when device attestation fails
type ErrAttestationFailed struct {
	Reason string
}

func (e ErrAttestationFailed) Error() string {
	return fmt.Sprintf("attestation failed: %s", e.Reason)
}

// ErrDeviceNotFound is returned when a device is not found
type ErrDeviceNotFound struct {
	DeviceID string
}

func (e ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %s", e.DeviceID)
}

// ErrProvisioningFailed is returned when device provisioning fails
type ErrProvisioningFailed struct {
	Reason string
}

func (e ErrProvisioningFailed) Error() string {
	return fmt.Sprintf("device provisioning failed: %s", e.Reason)
}

// ErrProfileNotFound is returned when a device profile is not found
type ErrProfileNotFound struct {
	Profile string
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("device profile not found: %s", e.Profile)
}

// ErrInvalidAttestationEvidence is returned when attestation evidence is malformed
type ErrInvalidAttestationEvidence struct {
	Reason string
}

func (e ErrInvalidAttestationEvidence) Error() string {
	return fmt.Sprintf("invalid attestation evidence: %s", e.Reason)
}

// ErrDeviceOperationFailed is returned when a device operation fails
type ErrDeviceOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDeviceOperationFailed) Error() string {
	return fmt.Sprintf("device operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDeviceOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceProfileServiceNotAvailable is returned when the device profile service is not configured
type ErrDeviceProfileServiceNotAvailable struct{}

func (e ErrDeviceProfileServiceNotAvailable) Error() string {
	return "device: profile service not available"
}

// =============================================================================
// SDN Service Errors
// =============================================================================

// ErrSDNOperationNotImplemented is returned when an SDN operation is not yet implemented
type ErrSDNOperationNotImplemented struct {
	Operation string
}

func (e ErrSDNOperationNotImplemented) Error() string {
	return fmt.Sprintf("SDN operation not implemented: %s", e.Operation)
}

// ErrSDNPolicyEngineNotConfigured is returned when policy engine is not configured
type ErrSDNPolicyEngineNotConfigured struct{}

func (e ErrSDNPolicyEngineNotConfigured) Error() string {
	return "SDN policy engine not configured"
}

// ErrSDNInvalidPortState is returned when an invalid port state is specified
type ErrSDNInvalidPortState struct {
	State string
}

func (e ErrSDNInvalidPortState) Error() string {
	return fmt.Sprintf("invalid port state: %s", e.State)
}

// ErrSDNPolicyNotFound is returned when a policy is not found
type ErrSDNPolicyNotFound struct {
	PolicyID string
}

func (e ErrSDNPolicyNotFound) Error() string {
	return fmt.Sprintf("SDN policy not found: %s", e.PolicyID)
}

// ErrSDNInvalidPolicy is returned when a policy specification is invalid
type ErrSDNInvalidPolicy struct {
	Reason string
}

func (e ErrSDNInvalidPolicy) Error() string {
	return fmt.Sprintf("invalid SDN policy: %s", e.Reason)
}

// ErrSDNSetPortStateFailed is returned when setting port state fails
type ErrSDNSetPortStateFailed struct {
	PortID string
	Cause  error
}

func (e ErrSDNSetPortStateFailed) Error() string {
	return fmt.Sprintf("failed to set port state for %s: %v", e.PortID, e.Cause)
}

func (e ErrSDNSetPortStateFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNApplyPolicyFailed is returned when applying a policy fails
type ErrSDNApplyPolicyFailed struct {
	PolicyID string
	Cause    error
}

func (e ErrSDNApplyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to apply policy %s: %v", e.PolicyID, e.Cause)
}

func (e ErrSDNApplyPolicyFailed) Unwrap() error {
	return e.Cause
}

// ErrSDNBridgeNotFound is returned when a bridge is not found
type ErrSDNBridgeNotFound struct {
	BridgeName string
}

func (e ErrSDNBridgeNotFound) Error() string {
	return fmt.Sprintf("SDN bridge not found: %s", e.BridgeName)
}

// ErrSDNPortNotFound is returned when a port is not found
type ErrSDNPortNotFound struct {
	BridgeName string
	PortName   string
}

func (e ErrSDNPortNotFound) Error() string {
	return fmt.Sprintf("SDN port not found: %s on bridge %s", e.PortName, e.BridgeName)
}

// ErrSDNMissingParameter is returned when a required parameter is missing
type ErrSDNMissingParameter struct {
	Parameter string
}

func (e ErrSDNMissingParameter) Error() string {
	return fmt.Sprintf("missing required parameter: %s", e.Parameter)
}

// ErrOVSNotConfigured is returned when an OVS connection operation is attempted
// but no OVS client has been configured (e.g. when running in zone-only stub mode).
type ErrOVSNotConfigured struct{}

func (ErrOVSNotConfigured) Error() string {
	return "OVS client not configured"
}

// =============================================================================
// DNS Service Errors
// =============================================================================

// ErrDNSConfigUpdateNotSupported is returned when DNS configuration updates are not supported
type ErrDNSConfigUpdateNotSupported struct{}

func (e ErrDNSConfigUpdateNotSupported) Error() string {
	return "DNS configuration updates are not supported at runtime"
}

// ErrDNSCacheFlushNotSupported is returned when DNS cache flushing is not supported
type ErrDNSCacheFlushNotSupported struct{}

func (e ErrDNSCacheFlushNotSupported) Error() string {
	return "DNS cache flushing is not supported"
}

// ErrDNSZoneNotFound is returned when a DNS zone is not found
type ErrDNSZoneNotFound struct {
	Zone string
}

func (e ErrDNSZoneNotFound) Error() string {
	return fmt.Sprintf("DNS zone not found: %s", e.Zone)
}

// ErrDNSRecordNotFound is returned when a DNS record is not found
type ErrDNSRecordNotFound struct {
	Name       string
	RecordType string
}

func (e ErrDNSRecordNotFound) Error() string {
	return fmt.Sprintf("DNS record not found: %s %s", e.Name, e.RecordType)
}

// ErrDNSOperationFailed is returned when a DNS operation fails
type ErrDNSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDNSOperationFailed) Error() string {
	return fmt.Sprintf("DNS operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDNSOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// IAM Service Errors
// =============================================================================

// ErrIAMServiceNotAvailable is returned when IAM service is not configured
type ErrIAMServiceNotAvailable struct{}

func (e ErrIAMServiceNotAvailable) Error() string {
	return "IAM service not available"
}

// ErrIAMMissingParameter is returned when a required IAM parameter is missing
type ErrIAMMissingParameter struct {
	Parameter string
}

func (e ErrIAMMissingParameter) Error() string {
	return fmt.Sprintf("missing required IAM parameter: %s", e.Parameter)
}

// ErrIAMUserNotFound is returned when a user is not found
type ErrIAMUserNotFound struct {
	TenantID string
	UserID   string
}

func (e ErrIAMUserNotFound) Error() string {
	return fmt.Sprintf("IAM user not found: %s in tenant %s", e.UserID, e.TenantID)
}

// ErrIAMUserAlreadyExists is returned when attempting to create a user that already exists
type ErrIAMUserAlreadyExists struct {
	TenantID string
	Email    string
}

func (e ErrIAMUserAlreadyExists) Error() string {
	return fmt.Sprintf("IAM user already exists: %s in tenant %s", e.Email, e.TenantID)
}

// ErrIAMRoleNotFound is returned when a role is not found
type ErrIAMRoleNotFound struct {
	TenantID string
	RoleID   string
}

func (e ErrIAMRoleNotFound) Error() string {
	return fmt.Sprintf("IAM role not found: %s in tenant %s", e.RoleID, e.TenantID)
}

// ErrIAMRoleAlreadyExists is returned when attempting to create a role that already exists
type ErrIAMRoleAlreadyExists struct {
	TenantID string
	RoleID   string
}

func (e ErrIAMRoleAlreadyExists) Error() string {
	return fmt.Sprintf("IAM role already exists: %s in tenant %s", e.RoleID, e.TenantID)
}

// ErrIAMGroupNotFound is returned when a group is not found
type ErrIAMGroupNotFound struct {
	TenantID string
	GroupID  string
}

func (e ErrIAMGroupNotFound) Error() string {
	return fmt.Sprintf("IAM group not found: %s in tenant %s", e.GroupID, e.TenantID)
}

// ErrIAMGroupAlreadyExists is returned when attempting to create a group that already exists
type ErrIAMGroupAlreadyExists struct {
	TenantID string
	GroupID  string
}

func (e ErrIAMGroupAlreadyExists) Error() string {
	return fmt.Sprintf("IAM group already exists: %s in tenant %s", e.GroupID, e.TenantID)
}

// ErrIAMTenantNotFound is returned when a tenant is not found
type ErrIAMTenantNotFound struct {
	TenantID string
}

func (e ErrIAMTenantNotFound) Error() string {
	return fmt.Sprintf("IAM tenant not found: %s", e.TenantID)
}

// ErrIAMTenantAlreadyExists is returned when attempting to create a tenant that already exists
type ErrIAMTenantAlreadyExists struct {
	TenantID string
}

func (e ErrIAMTenantAlreadyExists) Error() string {
	return fmt.Sprintf("IAM tenant already exists: %s", e.TenantID)
}

// ErrIAMPolicyNotFound is returned when a policy is not found
type ErrIAMPolicyNotFound struct {
	TenantID   string
	PolicyName string
}

func (e ErrIAMPolicyNotFound) Error() string {
	return fmt.Sprintf("IAM policy not found: %s in tenant %s", e.PolicyName, e.TenantID)
}

// ErrIAMPolicyAlreadyExists is returned when attempting to create a policy that already exists
type ErrIAMPolicyAlreadyExists struct {
	TenantID   string
	PolicyName string
}

func (e ErrIAMPolicyAlreadyExists) Error() string {
	return fmt.Sprintf("IAM policy already exists: %s in tenant %s", e.PolicyName, e.TenantID)
}

// ErrIAMPolicyValidationFailed is returned when policy validation fails
type ErrIAMPolicyValidationFailed struct {
	Reason string
}

func (e ErrIAMPolicyValidationFailed) Error() string {
	return fmt.Sprintf("IAM policy validation failed: %s", e.Reason)
}

// ErrIAMAppNotFound is returned when an application is not found
type ErrIAMAppNotFound struct {
	TenantID string
	ClientID string
}

func (e ErrIAMAppNotFound) Error() string {
	return fmt.Sprintf("IAM application not found: %s in tenant %s", e.ClientID, e.TenantID)
}

// ErrIAMAppAlreadyExists is returned when attempting to create an application that already exists
type ErrIAMAppAlreadyExists struct {
	TenantID string
	Name     string
}

func (e ErrIAMAppAlreadyExists) Error() string {
	return fmt.Sprintf("IAM application already exists: %s in tenant %s", e.Name, e.TenantID)
}

// ErrIAMAuthenticationFailed is returned when authentication fails
type ErrIAMAuthenticationFailed struct {
	Reason string
}

func (e ErrIAMAuthenticationFailed) Error() string {
	return fmt.Sprintf("IAM authentication failed: %s", e.Reason)
}

// ErrIAMPermissionDenied is returned when a permission check fails
type ErrIAMPermissionDenied struct {
	Subject  string
	Resource string
	Action   string
}

func (e ErrIAMPermissionDenied) Error() string {
	return fmt.Sprintf("IAM permission denied: subject %s cannot perform %s on %s", e.Subject, e.Action, e.Resource)
}

// ErrIAMOperationFailed is returned when an IAM operation fails
type ErrIAMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrIAMOperationFailed) Error() string {
	return fmt.Sprintf("IAM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrIAMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrIAMInvalidCredentials is returned when credentials are invalid
type ErrIAMInvalidCredentials struct{}

func (e ErrIAMInvalidCredentials) Error() string {
	return "IAM invalid credentials"
}

// ErrIAMRoleAssignmentFailed is returned when role assignment fails
type ErrIAMRoleAssignmentFailed struct {
	UserID string
	RoleID string
	Reason string
}

func (e ErrIAMRoleAssignmentFailed) Error() string {
	return fmt.Sprintf("IAM failed to assign role %s to user %s: %s", e.RoleID, e.UserID, e.Reason)
}

// ErrIAMRoleRevocationFailed is returned when role revocation fails
type ErrIAMRoleRevocationFailed struct {
	UserID string
	RoleID string
	Reason string
}

func (e ErrIAMRoleRevocationFailed) Error() string {
	return fmt.Sprintf("IAM failed to revoke role %s from user %s: %s", e.RoleID, e.UserID, e.Reason)
}

// ErrIAMGroupMembershipFailed is returned when group membership operation fails
type ErrIAMGroupMembershipFailed struct {
	GroupID string
	UserID  string
	Reason  string
}

func (e ErrIAMGroupMembershipFailed) Error() string {
	return fmt.Sprintf("IAM group membership operation failed for user %s in group %s: %s", e.UserID, e.GroupID, e.Reason)
}

// ErrIAMTokenNotFound is returned when a token is not found
type ErrIAMTokenNotFound struct {
	TokenID string
}

func (e ErrIAMTokenNotFound) Error() string {
	return fmt.Sprintf("IAM token not found: %s", e.TokenID)
}

// ErrIAMTokenExpired is returned when a token has expired
type ErrIAMTokenExpired struct {
	TokenID string
}

func (e ErrIAMTokenExpired) Error() string {
	return fmt.Sprintf("IAM token expired: %s", e.TokenID)
}

// ErrIAMTokenRevoked is returned when a token has been revoked
type ErrIAMTokenRevoked struct {
	TokenID string
}

func (e ErrIAMTokenRevoked) Error() string {
	return fmt.Sprintf("IAM token revoked: %s", e.TokenID)
}

// ErrIAMTokenInvalid is returned when a token is invalid
type ErrIAMTokenInvalid struct {
	Reason string
}

func (e ErrIAMTokenInvalid) Error() string {
	return fmt.Sprintf("IAM token invalid: %s", e.Reason)
}

// =============================================================================
// KMS Service Errors
// =============================================================================

// ErrKMSKeyNotFound is returned when a key is not found in the KMS
type ErrKMSKeyNotFound struct {
	KeyID string
}

func (e ErrKMSKeyNotFound) Error() string {
	return fmt.Sprintf("KMS key not found: %s", e.KeyID)
}

// ErrKMSKeyAlreadyExists is returned when attempting to create a key that already exists
type ErrKMSKeyAlreadyExists struct {
	KeyID string
}

func (e ErrKMSKeyAlreadyExists) Error() string {
	return fmt.Sprintf("KMS key already exists: %s", e.KeyID)
}

// ErrKMSKeyDisabled is returned when attempting to use a disabled key
type ErrKMSKeyDisabled struct {
	KeyID string
}

func (e ErrKMSKeyDisabled) Error() string {
	return fmt.Sprintf("KMS key is disabled: %s", e.KeyID)
}

// ErrKMSInvalidParameter is returned when a KMS operation receives an invalid parameter
type ErrKMSInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrKMSInvalidParameter) Error() string {
	return fmt.Sprintf("invalid KMS parameter %s: %s", e.Parameter, e.Reason)
}

// ErrKMSInvalidAlgorithm is returned when an unsupported algorithm is specified
type ErrKMSInvalidAlgorithm struct {
	Algorithm string
}

func (e ErrKMSInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid KMS algorithm: %s", e.Algorithm)
}

// ErrKMSInvalidKeyUsage is returned when an invalid key usage is specified
type ErrKMSInvalidKeyUsage struct {
	Usage string
}

func (e ErrKMSInvalidKeyUsage) Error() string {
	return fmt.Sprintf("invalid KMS key usage: %s", e.Usage)
}

// ErrKMSOperationFailed is returned when a KMS operation fails
type ErrKMSOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrKMSOperationFailed) Error() string {
	return fmt.Sprintf("KMS operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrKMSOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSEncryptionFailed is returned when encryption fails
type ErrKMSEncryptionFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSEncryptionFailed) Error() string {
	return fmt.Sprintf("KMS encryption failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSEncryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSDecryptionFailed is returned when decryption fails
type ErrKMSDecryptionFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSDecryptionFailed) Error() string {
	return fmt.Sprintf("KMS decryption failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSDecryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSSigningFailed is returned when signing fails
type ErrKMSSigningFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSSigningFailed) Error() string {
	return fmt.Sprintf("KMS signing failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSSigningFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSVerificationFailed is returned when signature verification fails
type ErrKMSVerificationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSVerificationFailed) Error() string {
	return fmt.Sprintf("KMS signature verification failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSKeyRotationFailed is returned when key rotation fails
type ErrKMSKeyRotationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSKeyRotationFailed) Error() string {
	return fmt.Sprintf("KMS key rotation failed for key %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSKeyRotationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSRandomGenerationFailed is returned when random byte generation fails
type ErrKMSRandomGenerationFailed struct {
	Cause error
}

func (e ErrKMSRandomGenerationFailed) Error() string {
	return fmt.Sprintf("KMS random generation failed: %v", e.Cause)
}

func (e ErrKMSRandomGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSKeyDeletionProtected is returned when attempting to delete a protected key
type ErrKMSKeyDeletionProtected struct {
	KeyID string
}

func (e ErrKMSKeyDeletionProtected) Error() string {
	return fmt.Sprintf("KMS key %s has deletion protection enabled", e.KeyID)
}

// ErrKMSDataKeyGenerationFailed is returned when data key generation fails
type ErrKMSDataKeyGenerationFailed struct {
	KeyID string
	Cause error
}

func (e ErrKMSDataKeyGenerationFailed) Error() string {
	return fmt.Sprintf("KMS data key generation failed for KEK %s: %v", e.KeyID, e.Cause)
}

func (e ErrKMSDataKeyGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrKMSOperationNotImplemented is returned when a KMS operation is not yet
// implemented in the backend adapter. This allows partial KMS service wiring
// where implemented operations work while unimplemented ones return a clear error.
type ErrKMSOperationNotImplemented struct {
	Operation string
}

func (e ErrKMSOperationNotImplemented) Error() string {
	return fmt.Sprintf("KMS operation not implemented: %s", e.Operation)
}

// =============================================================================
// TPM2/IDevID Service Errors
// =============================================================================

// ErrInvalidCertificatePEM is returned when a PEM-encoded certificate is invalid
type ErrInvalidCertificatePEM struct{}

func (e ErrInvalidCertificatePEM) Error() string {
	return "invalid PEM-encoded certificate"
}

// ErrTPM2ServiceNotAvailable is returned when TPM2 service is not configured
type ErrTPM2ServiceNotAvailable struct{}

func (e ErrTPM2ServiceNotAvailable) Error() string {
	return "TPM2 service not available"
}

// ErrIDevIDNotFound is returned when IDevID is not found in TPM
type ErrIDevIDNotFound struct{}

func (e ErrIDevIDNotFound) Error() string {
	return "IDevID not found in TPM"
}

// ErrIAKNotFound is returned when IAK is not found in TPM
type ErrIAKNotFound struct{}

func (e ErrIAKNotFound) Error() string {
	return "IAK not found in TPM"
}

// ErrIDevIDCertificateNotFound is returned when IDevID certificate is not installed
type ErrIDevIDCertificateNotFound struct{}

func (e ErrIDevIDCertificateNotFound) Error() string {
	return "IDevID certificate not installed"
}

// ErrIAKCertificateNotFound is returned when IAK certificate is not installed
type ErrIAKCertificateNotFound struct{}

func (e ErrIAKCertificateNotFound) Error() string {
	return "IAK certificate not installed"
}

// ErrTPM2OperationFailed is returned when a TPM2 operation fails
type ErrTPM2OperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTPM2OperationFailed) Error() string {
	return fmt.Sprintf("TPM2 operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTPM2OperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Container Service Errors
// =============================================================================

// ErrContainerServiceNotAvailable is returned when container service is not configured
type ErrContainerServiceNotAvailable struct{}

func (e ErrContainerServiceNotAvailable) Error() string {
	return "container service not available"
}

// ErrContainerNotFound is returned when a container is not found
type ErrContainerNotFound struct {
	ContainerID string
}

func (e ErrContainerNotFound) Error() string {
	return fmt.Sprintf("container not found: %s", e.ContainerID)
}

// ErrContainerOperationFailed is returned when a container operation fails
type ErrContainerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrContainerOperationFailed) Error() string {
	return fmt.Sprintf("container operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrContainerOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerLogsNotSupported is returned when container log retrieval is not supported
type ErrContainerLogsNotSupported struct{}

func (e ErrContainerLogsNotSupported) Error() string {
	return "container logs not supported via orchestrator"
}

// ErrContainerAttestNotSupported is returned when container attestation is not supported
type ErrContainerAttestNotSupported struct{}

func (e ErrContainerAttestNotSupported) Error() string {
	return "container attestation not implemented"
}

// ErrContainerInvalidParameter is returned when a container operation receives an invalid parameter
type ErrContainerInvalidParameter struct {
	Parameter string
	Reason    string
}

func (e ErrContainerInvalidParameter) Error() string {
	return fmt.Sprintf("invalid container parameter %s: %s", e.Parameter, e.Reason)
}

// =============================================================================
// Authentication/Token Validation Errors
// =============================================================================

// ErrQuicBaaSServiceUnavailable is returned when QuicBaaS service is not available
// for authentication operations
type ErrQuicBaaSServiceUnavailable struct{}

func (e ErrQuicBaaSServiceUnavailable) Error() string {
	return "QuicBaaS service not available for authentication"
}

// ErrTokenValidationFailed is returned when token validation fails
type ErrTokenValidationFailed struct {
	Cause error
}

func (e ErrTokenValidationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("token validation failed: %v", e.Cause)
	}
	return "token validation failed"
}

func (e ErrTokenValidationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Overlay Network Service Errors
// =============================================================================

// ErrOverlayServiceNotAvailable is returned when the overlay network service is not configured
type ErrOverlayServiceNotAvailable struct{}

func (e ErrOverlayServiceNotAvailable) Error() string {
	return "overlay network service not available"
}

// ErrOverlayOperationNotImplemented is returned when an overlay operation is not yet implemented
type ErrOverlayOperationNotImplemented struct {
	Operation string
}

func (e ErrOverlayOperationNotImplemented) Error() string {
	return fmt.Sprintf("overlay operation not implemented: %s", e.Operation)
}

// =============================================================================
// Gateway Service Errors
// =============================================================================

// ErrGatewayServiceNotAvailable is returned when the gateway service is not configured
type ErrGatewayServiceNotAvailable struct{}

func (e ErrGatewayServiceNotAvailable) Error() string {
	return "gateway service not available"
}

// ErrGatewayOperationNotImplemented is returned when a gateway operation is not yet implemented
type ErrGatewayOperationNotImplemented struct {
	Operation string
}

func (e ErrGatewayOperationNotImplemented) Error() string {
	return fmt.Sprintf("gateway operation not implemented: %s", e.Operation)
}

// =============================================================================
// TPM Service Errors
// =============================================================================

// ErrTPMOperationNotImplemented is returned when a TPM operation is not yet implemented.
type ErrTPMOperationNotImplemented struct {
	Operation string
}

func (e ErrTPMOperationNotImplemented) Error() string {
	return fmt.Sprintf("TPM operation not implemented: %s", e.Operation)
}

// ErrTPMInvalidSize is returned when a requested size exceeds the maximum.
type ErrTPMInvalidSize struct {
	Max       int
	Requested int
}

func (e ErrTPMInvalidSize) Error() string {
	return fmt.Sprintf("requested size %d exceeds maximum %d bytes", e.Requested, e.Max)
}

// ErrTenantDEKProvision is returned when DEK provisioning fails during tenant creation.
type ErrTenantDEKProvision struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDEKProvision) Error() string {
	return fmt.Sprintf("daemon: failed to provision DEK for tenant %s: %v", e.TenantID, e.Cause)
}

func (e ErrTenantDEKProvision) Unwrap() error {
	return e.Cause
}

// ErrTenantDEKDeprovision is returned when DEK cleanup fails during tenant deletion.
type ErrTenantDEKDeprovision struct {
	TenantID string
	Cause    error
}

func (e ErrTenantDEKDeprovision) Error() string {
	return fmt.Sprintf("daemon: failed to deprovision DEK for tenant %s: %v", e.TenantID, e.Cause)
}

func (e ErrTenantDEKDeprovision) Unwrap() error {
	return e.Cause
}

// ErrConfigReloadFailed wraps a failure during runtime reload of the
// platformd configuration from disk. The cause exposes the underlying
// viper / unmarshal error for log analysis.
type ErrConfigReloadFailed struct {
	Cause error
}

func (e ErrConfigReloadFailed) Error() string {
	return fmt.Sprintf("daemon: config reload failed: %v", e.Cause)
}

func (e ErrConfigReloadFailed) Unwrap() error {
	return e.Cause
}

// ErrConfigInvalid is returned by validation paths when a YAML body
// fails to parse or fails schema checks.
type ErrConfigInvalid struct {
	Issues []string
}

func (e ErrConfigInvalid) Error() string {
	return fmt.Sprintf("daemon: invalid config: %v", e.Issues)
}

// ErrAttestationManifestIDRequired is returned by AttestationService
// operations that need a non-empty manifest ID.
type ErrAttestationManifestIDRequired struct{}

func (ErrAttestationManifestIDRequired) Error() string {
	return "daemon: attestation manifest id is required"
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// ErrConfigDeliveryServiceNotAvailable is returned when the pre-enrollment
// config delivery service is not configured on this daemon.
type ErrConfigDeliveryServiceNotAvailable struct{}

// Error implements the error interface.
func (e ErrConfigDeliveryServiceNotAvailable) Error() string {
	return "config delivery service is not available"
}

// ErrConfigSerializationFailed is returned when a resolved device
// configuration could not be serialized to JSON for wire delivery.
type ErrConfigSerializationFailed struct {
	Cause error
}

// Error implements the error interface.
func (e ErrConfigSerializationFailed) Error() string {
	return "config delivery: config serialization failed: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause.
func (e ErrConfigSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrEABUnsupportedSortField is returned when an EAB list request asks
// for a sort_by field the service does not support.
type ErrEABUnsupportedSortField struct {
	Field string
}

// Error implements the error interface.
func (e ErrEABUnsupportedSortField) Error() string {
	return "eab: unsupported sort field: " + e.Field
}

// ErrEABInvalidQRCodeSize is returned when an EAB QR code request asks
// for a negative pixel size.
type ErrEABInvalidQRCodeSize struct {
	Size int32
}

// Error implements the error interface.
func (e ErrEABInvalidQRCodeSize) Error() string {
	return fmt.Sprintf("eab: invalid QR code size: %d", e.Size)
}

// ErrProfileConfigInvalid is returned when a device profile create or
// update request carries config bytes that are not valid JSON, so the
// full platform config cannot be decoded onto the profile entity.
type ErrProfileConfigInvalid struct {
	Cause error
}

// Error implements the error interface.
func (e ErrProfileConfigInvalid) Error() string {
	return "device: profile config is not valid JSON: " + e.Cause.Error()
}

// Unwrap returns the wrapped cause.
func (e ErrProfileConfigInvalid) Unwrap() error {
	return e.Cause
}

// ErrDaemonRetryUnsafe is returned by Start when a prior failed startup had
// to stop a gRPC server that had already served. grpc.Server.Stop is
// permanent, so retrying on the same Daemon instance would report success
// with a dead gRPC transport; construct a new Daemon instead.
type ErrDaemonRetryUnsafe struct{}

func (ErrDaemonRetryUnsafe) Error() string {
	return "daemon startup previously failed after a gRPC server had served: retry on this instance is unsafe, construct a new Daemon"
}
