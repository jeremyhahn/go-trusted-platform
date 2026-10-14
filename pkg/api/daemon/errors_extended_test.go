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

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrServiceStartFailed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		serviceName string
		reason      string
		expected    string
	}{
		{
			name:        "with service and reason",
			serviceName: "dns",
			reason:      "port already in use",
			expected:    "service dns failed to start: port already in use",
		},
		{
			name:        "empty values",
			serviceName: "",
			reason:      "",
			expected:    "service  failed to start: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceStartFailed{ServiceName: tt.serviceName, Reason: tt.reason}
			if got := err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrServiceStopFailed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		serviceName string
		reason      string
		expected    string
	}{
		{
			name:        "with service and reason",
			serviceName: "web",
			reason:      "timeout waiting for connections",
			expected:    "service web failed to stop: timeout waiting for connections",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrServiceStopFailed{ServiceName: tt.serviceName, Reason: tt.reason}
			if got := err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrDNSInvalidParameter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		parameter string
		reason    string
		expected  string
	}{
		{
			name:      "invalid ttl",
			parameter: "ttl",
			reason:    "must be positive",
			expected:  "invalid DNS parameter ttl: must be positive",
		},
		{
			name:      "invalid record type",
			parameter: "recordType",
			reason:    "unknown type XYZ",
			expected:  "invalid DNS parameter recordType: unknown type XYZ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrDNSInvalidParameter{Parameter: tt.parameter, Reason: tt.reason}
			if got := err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// REST Service Error Tests

func TestErrRESTServerNotRunning(t *testing.T) {
	t.Parallel()
	err := ErrRESTServerNotRunning{}
	expected := "REST server is not running"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRESTServerAlreadyRunning(t *testing.T) {
	t.Parallel()
	err := ErrRESTServerAlreadyRunning{}
	expected := "REST server is already running"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRESTServerStartFailed(t *testing.T) {
	t.Parallel()
	err := ErrRESTServerStartFailed{Reason: "address already in use"}
	expected := "REST server failed to start: address already in use"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRESTServerStopFailed(t *testing.T) {
	t.Parallel()
	err := ErrRESTServerStopFailed{Reason: "shutdown timeout"}
	expected := "REST server failed to stop: shutdown timeout"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRESTInvalidRequest(t *testing.T) {
	t.Parallel()
	err := ErrRESTInvalidRequest{Reason: "missing required field"}
	expected := "invalid REST request: missing required field"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRESTEncodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("json marshal error")
	err := ErrRESTEncodingFailed{Cause: cause}

	expected := "REST response encoding failed: json marshal error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrRESTDecodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("json unmarshal error")
	err := ErrRESTDecodingFailed{Cause: cause}

	expected := "REST request decoding failed: json unmarshal error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

// QUIC Service Error Tests

func TestErrQUICNilRequest(t *testing.T) {
	t.Parallel()
	err := ErrQUICNilRequest{}
	expected := "QUIC request cannot be nil"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQUICUnknownOpcode(t *testing.T) {
	t.Parallel()
	err := ErrQUICUnknownOpcode{Opcode: 0xFF}
	expected := "unknown QUIC opcode: 0xFF"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQUICServiceUnavailable(t *testing.T) {
	t.Parallel()
	err := ErrQUICServiceUnavailable{Service: "dns"}
	expected := "QUIC service unavailable: dns"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQUICDecodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("invalid payload format")
	err := ErrQUICDecodingFailed{Cause: cause}

	expected := "QUIC payload decoding failed: invalid payload format"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrQUICEncodingFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("encoding failed")
	err := ErrQUICEncodingFailed{Cause: cause}

	expected := "QUIC payload encoding failed: encoding failed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrQUICMissingField(t *testing.T) {
	t.Parallel()
	err := ErrQUICMissingField{Field: "device_id"}
	expected := "QUIC request missing required field: device_id"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQUICOperationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("operation error")
	err := ErrQUICOperationFailed{Op: "create_device", Cause: cause}

	expected := "QUIC operation create_device failed: operation error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrQUICServerNotConfigured(t *testing.T) {
	t.Parallel()
	err := ErrQUICServerNotConfigured{}
	expected := "QUIC server not configured"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrQUICServerStartFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("TLS config error")
	err := ErrQUICServerStartFailed{Cause: cause}

	expected := "QUIC server failed to start: TLS config error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrQUICServerStopFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection still active")
	err := ErrQUICServerStopFailed{Cause: cause}

	expected := "QUIC server failed to stop: connection still active"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

// MCP Service Error Tests

func TestErrMCPServerNotRunning(t *testing.T) {
	t.Parallel()
	err := ErrMCPServerNotRunning{}
	expected := "MCP server is not running"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMCPServerAlreadyRunning(t *testing.T) {
	t.Parallel()
	err := ErrMCPServerAlreadyRunning{}
	expected := "MCP server is already running"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMCPServerStartFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("failed to bind port")
	err := ErrMCPServerStartFailed{Cause: cause}

	expected := "MCP server failed to start: failed to bind port"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrMCPServerStopFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("active connections")
	err := ErrMCPServerStopFailed{Cause: cause}

	expected := "MCP server failed to stop: active connections"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrMCPServerNotConfigured(t *testing.T) {
	t.Parallel()
	err := ErrMCPServerNotConfigured{}
	expected := "MCP server not configured"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// vTPM and Device Operation Errors

func TestErrVTPMOperationNotImplemented(t *testing.T) {
	t.Parallel()
	err := ErrVTPMOperationNotImplemented{Operation: "quote"}
	expected := "vTPM operation not implemented: quote"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSDNOperationNotImplemented(t *testing.T) {
	t.Parallel()
	err := ErrSDNOperationNotImplemented{Operation: "apply_policy"}
	expected := "SDN operation not implemented: apply_policy"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrInvalidDeviceID(t *testing.T) {
	t.Parallel()
	err := ErrInvalidDeviceID{ID: "not-a-number"}
	expected := "invalid device ID: not-a-number"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// Device Attestation and Provisioning Errors

func TestErrAttestationFailed(t *testing.T) {
	t.Parallel()
	err := ErrAttestationFailed{Reason: "invalid quote signature"}
	expected := "attestation failed: invalid quote signature"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDeviceNotFound(t *testing.T) {
	t.Parallel()
	err := ErrDeviceNotFound{DeviceID: "device-123"}
	expected := "device not found: device-123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrProvisioningFailed(t *testing.T) {
	t.Parallel()
	err := ErrProvisioningFailed{Reason: "profile mismatch"}
	expected := "device provisioning failed: profile mismatch"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrProfileNotFound(t *testing.T) {
	t.Parallel()
	err := ErrProfileNotFound{Profile: "default-profile"}
	expected := "device profile not found: default-profile"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrInvalidAttestationEvidence(t *testing.T) {
	t.Parallel()
	err := ErrInvalidAttestationEvidence{Reason: "malformed event log"}
	expected := "invalid attestation evidence: malformed event log"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// SDN Service Errors

func TestErrSDNPolicyNotFound(t *testing.T) {
	t.Parallel()
	err := ErrSDNPolicyNotFound{PolicyID: "policy-abc"}
	expected := "SDN policy not found: policy-abc"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSDNInvalidPolicy(t *testing.T) {
	t.Parallel()
	err := ErrSDNInvalidPolicy{Reason: "missing required field"}
	expected := "invalid SDN policy: missing required field"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSDNSetPortStateFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("OVS error")
	err := ErrSDNSetPortStateFailed{PortID: "eth0", Cause: cause}

	expected := "failed to set port state for eth0: OVS error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrSDNApplyPolicyFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("flow table full")
	err := ErrSDNApplyPolicyFailed{PolicyID: "policy-123", Cause: cause}

	expected := "failed to apply policy policy-123: flow table full"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrSDNBridgeNotFound(t *testing.T) {
	t.Parallel()
	err := ErrSDNBridgeNotFound{BridgeName: "br0"}
	expected := "SDN bridge not found: br0"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSDNPortNotFound(t *testing.T) {
	t.Parallel()
	err := ErrSDNPortNotFound{BridgeName: "br0", PortName: "eth0"}
	expected := "SDN port not found: eth0 on bridge br0"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrSDNMissingParameter(t *testing.T) {
	t.Parallel()
	err := ErrSDNMissingParameter{Parameter: "bridge_name"}
	expected := "missing required parameter: bridge_name"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// DNS QUIC Handler Errors

func TestErrDNSConfigUpdateNotSupported(t *testing.T) {
	t.Parallel()
	err := ErrDNSConfigUpdateNotSupported{}
	expected := "DNS configuration updates are not supported at runtime"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDNSCacheFlushNotSupported(t *testing.T) {
	t.Parallel()
	err := ErrDNSCacheFlushNotSupported{}
	expected := "DNS cache flushing is not supported"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDNSZoneNotFound(t *testing.T) {
	t.Parallel()
	err := ErrDNSZoneNotFound{Zone: "example.com"}
	expected := "DNS zone not found: example.com"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDNSRecordNotFound(t *testing.T) {
	t.Parallel()
	err := ErrDNSRecordNotFound{Name: "www.example.com", RecordType: "A"}
	expected := "DNS record not found: www.example.com A"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrDNSOperationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("zone file corrupt")
	err := ErrDNSOperationFailed{Operation: "add_record", Cause: cause}

	expected := "DNS operation add_record failed: zone file corrupt"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

// IAM Service Errors

func TestErrIAMServiceNotAvailable(t *testing.T) {
	t.Parallel()
	err := ErrIAMServiceNotAvailable{}
	expected := "IAM service not available"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMMissingParameter(t *testing.T) {
	t.Parallel()
	err := ErrIAMMissingParameter{Parameter: "tenant_id"}
	expected := "missing required IAM parameter: tenant_id"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMUserNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMUserNotFound{TenantID: "tenant-1", UserID: "user-123"}
	expected := "IAM user not found: user-123 in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMUserAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMUserAlreadyExists{TenantID: "tenant-1", Email: "user@example.com"}
	expected := "IAM user already exists: user@example.com in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMRoleNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleNotFound{TenantID: "tenant-1", RoleID: "admin"}
	expected := "IAM role not found: admin in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMRoleAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleAlreadyExists{TenantID: "tenant-1", RoleID: "admin"}
	expected := "IAM role already exists: admin in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTenantNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMTenantNotFound{TenantID: "tenant-xyz"}
	expected := "IAM tenant not found: tenant-xyz"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTenantAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMTenantAlreadyExists{TenantID: "tenant-xyz"}
	expected := "IAM tenant already exists: tenant-xyz"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMPolicyNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMPolicyNotFound{TenantID: "tenant-1", PolicyName: "default"}
	expected := "IAM policy not found: default in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMPolicyAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMPolicyAlreadyExists{TenantID: "tenant-1", PolicyName: "default"}
	expected := "IAM policy already exists: default in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMPolicyValidationFailed(t *testing.T) {
	t.Parallel()
	err := ErrIAMPolicyValidationFailed{Reason: "invalid action format"}
	expected := "IAM policy validation failed: invalid action format"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMAppNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMAppNotFound{TenantID: "tenant-1", ClientID: "client-abc"}
	expected := "IAM application not found: client-abc in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMAppAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrIAMAppAlreadyExists{TenantID: "tenant-1", Name: "my-app"}
	expected := "IAM application already exists: my-app in tenant tenant-1"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMAuthenticationViaOIDC(t *testing.T) {
	t.Parallel()
	err := ErrIAMAuthenticationViaOIDC{}
	expected := "iam authentication is handled via OIDC flows, not the IAM service"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
	if got := status.Code(err); got != codes.Unimplemented {
		t.Errorf("status.Code() = %v, want %v", got, codes.Unimplemented)
	}
}

func TestErrIAMServiceNotAvailable_GRPCStatus(t *testing.T) {
	t.Parallel()
	err := ErrIAMServiceNotAvailable{}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("status.Code() = %v, want %v", got, codes.FailedPrecondition)
	}
}

func TestErrIAMPermissionDenied(t *testing.T) {
	t.Parallel()
	err := ErrIAMPermissionDenied{Subject: "user-1", Resource: "document-123", Action: "delete"}
	expected := "IAM permission denied: subject user-1 cannot perform delete on document-123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMInvalidCredentials(t *testing.T) {
	t.Parallel()
	err := ErrIAMInvalidCredentials{}
	expected := "IAM invalid credentials"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMRoleAssignmentFailed(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleAssignmentFailed{UserID: "user-1", RoleID: "admin", Reason: "user not found"}
	expected := "IAM failed to assign role admin to user user-1: user not found"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMRoleRevocationFailed(t *testing.T) {
	t.Parallel()
	err := ErrIAMRoleRevocationFailed{UserID: "user-1", RoleID: "admin", Reason: "role not assigned"}
	expected := "IAM failed to revoke role admin from user user-1: role not assigned"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTokenNotFound(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenNotFound{TokenID: "token-xyz"}
	expected := "IAM token not found: token-xyz"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTokenExpired(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenExpired{TokenID: "token-xyz"}
	expected := "IAM token expired: token-xyz"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTokenRevoked(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenRevoked{TokenID: "token-xyz"}
	expected := "IAM token revoked: token-xyz"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrIAMTokenInvalid(t *testing.T) {
	t.Parallel()
	err := ErrIAMTokenInvalid{Reason: "signature mismatch"}
	expected := "IAM token invalid: signature mismatch"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

// KMS Service Errors

func TestErrKMSKeyNotFound(t *testing.T) {
	t.Parallel()
	err := ErrKMSKeyNotFound{KeyID: "key-123"}
	expected := "KMS key not found: key-123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSKeyAlreadyExists(t *testing.T) {
	t.Parallel()
	err := ErrKMSKeyAlreadyExists{KeyID: "key-123"}
	expected := "KMS key already exists: key-123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSKeyDisabled(t *testing.T) {
	t.Parallel()
	err := ErrKMSKeyDisabled{KeyID: "key-123"}
	expected := "KMS key is disabled: key-123"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSInvalidParameter(t *testing.T) {
	t.Parallel()
	err := ErrKMSInvalidParameter{Parameter: "key_size", Reason: "must be 256 bits"}
	expected := "invalid KMS parameter key_size: must be 256 bits"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSInvalidAlgorithm(t *testing.T) {
	t.Parallel()
	err := ErrKMSInvalidAlgorithm{Algorithm: "UNKNOWN_ALG"}
	expected := "invalid KMS algorithm: UNKNOWN_ALG"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSInvalidKeyUsage(t *testing.T) {
	t.Parallel()
	err := ErrKMSInvalidKeyUsage{Usage: "INVALID_USAGE"}
	expected := "invalid KMS key usage: INVALID_USAGE"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrKMSOperationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("HSM error")
	err := ErrKMSOperationFailed{Operation: "generate_key", Cause: cause}

	expected := "KMS operation generate_key failed: HSM error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSEncryptionFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("padding error")
	err := ErrKMSEncryptionFailed{KeyID: "key-123", Cause: cause}

	expected := "KMS encryption failed for key key-123: padding error"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSDecryptionFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("invalid ciphertext")
	err := ErrKMSDecryptionFailed{KeyID: "key-123", Cause: cause}

	expected := "KMS decryption failed for key key-123: invalid ciphertext"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSSigningFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("key not suitable for signing")
	err := ErrKMSSigningFailed{KeyID: "key-123", Cause: cause}

	expected := "KMS signing failed for key key-123: key not suitable for signing"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSVerificationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("signature mismatch")
	err := ErrKMSVerificationFailed{KeyID: "key-123", Cause: cause}

	expected := "KMS signature verification failed for key key-123: signature mismatch"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSKeyRotationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("rotation in progress")
	err := ErrKMSKeyRotationFailed{KeyID: "key-123", Cause: cause}

	expected := "KMS key rotation failed for key key-123: rotation in progress"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSRandomGenerationFailed(t *testing.T) {
	t.Parallel()
	cause := errors.New("entropy pool exhausted")
	err := ErrKMSRandomGenerationFailed{Cause: cause}

	expected := "KMS random generation failed: entropy pool exhausted"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}

	if unwrapped := err.Unwrap(); unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrKMSKeyDeletionProtected(t *testing.T) {
	t.Parallel()
	err := ErrKMSKeyDeletionProtected{KeyID: "master-key"}
	expected := "KMS key master-key has deletion protection enabled"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}
