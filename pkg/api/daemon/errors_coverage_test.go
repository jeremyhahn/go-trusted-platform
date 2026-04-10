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
	"strings"
	"testing"
)

func TestAllErrorTypes_ErrorMethod(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		contains string
	}{
		// Daemon errors
		{"ErrDaemonNotRunning", ErrDaemonNotRunning{}, "daemon is not running"},
		{"ErrDaemonAlreadyRunning", ErrDaemonAlreadyRunning{}, "daemon is already running"},

		// Service errors
		{"ErrServiceNotFound", ErrServiceNotFound{ServiceName: "test-service"}, "service not found: test-service"},
		{"ErrServiceAlreadyRunning", ErrServiceAlreadyRunning{ServiceName: "test-service"}, "service already running: test-service"},
		{"ErrServiceNotRunning", ErrServiceNotRunning{ServiceName: "test-service"}, "service is not running: test-service"},
		{"ErrServiceStartFailed", ErrServiceStartFailed{ServiceName: "test-service", Reason: "port in use"}, "service test-service failed to start: port in use"},
		{"ErrServiceStopFailed", ErrServiceStopFailed{ServiceName: "test-service", Reason: "timeout"}, "service test-service failed to stop: timeout"},
		{"ErrServiceNotAvailable", ErrServiceNotAvailable{Service: "kms"}, "service not available: kms"},

		// Config errors
		{"ErrConfigNotFound", ErrConfigNotFound{ConfigKey: "db.host"}, "configuration not found: db.host"},
		{"ErrInvalidConfig", ErrInvalidConfig{Reason: "missing required field"}, "invalid configuration: missing required field"},

		// Provisioning/Shutdown errors
		{"ErrProvisionFailed", ErrProvisionFailed{Reason: "TPM not available"}, "provisioning failed: TPM not available"},
		{"ErrShutdownFailed", ErrShutdownFailed{Reason: "service timeout"}, "shutdown failed: service timeout"},

		// Invalid service type
		{"ErrInvalidServiceType", ErrInvalidServiceType{Type: "unknown"}, "invalid service type: unknown"},

		// Health check errors
		{"ErrHealthRegistryNotConfigured", ErrHealthRegistryNotConfigured{}, "health registry not configured"},
		{"ErrHealthCheckFailed", ErrHealthCheckFailed{Component: "database", Reason: "connection refused"}, "health check failed for database: connection refused"},

		// Database errors
		{"ErrDatabaseNotAvailable", ErrDatabaseNotAvailable{Reason: "connection pool exhausted"}, "database not available: connection pool exhausted"},

		// DNS errors
		{"ErrUnsupportedRecordType", ErrUnsupportedRecordType{}, "unsupported DNS record type"},
		{"ErrDNSServiceNotAvailable", ErrDNSServiceNotAvailable{}, "DNS service not available"},
		{"ErrDNSInvalidParameter", ErrDNSInvalidParameter{Parameter: "ttl", Reason: "must be positive"}, "invalid DNS parameter ttl: must be positive"},
		{"ErrDNSConfigUpdateNotSupported", ErrDNSConfigUpdateNotSupported{}, "DNS configuration updates are not supported at runtime"},
		{"ErrDNSCacheFlushNotSupported", ErrDNSCacheFlushNotSupported{}, "DNS cache flushing is not supported"},
		{"ErrDNSZoneNotFound", ErrDNSZoneNotFound{Zone: "example.com"}, "DNS zone not found: example.com"},
		{"ErrDNSRecordNotFound", ErrDNSRecordNotFound{Name: "www.example.com", RecordType: "A"}, "DNS record not found: www.example.com A"},
		{"ErrDNSOperationFailed", ErrDNSOperationFailed{Operation: "add", Cause: errors.New("zone locked")}, "DNS operation add failed: zone locked"},

		// gRPC errors
		{"ErrGRPCServerNotConfigured", ErrGRPCServerNotConfigured{}, "gRPC server not configured"},

		// REST errors
		{"ErrRESTServerNotRunning", ErrRESTServerNotRunning{}, "REST server is not running"},
		{"ErrRESTServerAlreadyRunning", ErrRESTServerAlreadyRunning{}, "REST server is already running"},
		{"ErrRESTServerStartFailed", ErrRESTServerStartFailed{Reason: "address already in use"}, "REST server failed to start: address already in use"},
		{"ErrRESTServerStopFailed", ErrRESTServerStopFailed{Reason: "timeout"}, "REST server failed to stop: timeout"},
		{"ErrRESTInvalidRequest", ErrRESTInvalidRequest{Reason: "malformed JSON"}, "invalid REST request: malformed JSON"},
		{"ErrRESTEncodingFailed", ErrRESTEncodingFailed{Cause: errors.New("marshal error")}, "REST response encoding failed: marshal error"},
		{"ErrRESTDecodingFailed", ErrRESTDecodingFailed{Cause: errors.New("unmarshal error")}, "REST request decoding failed: unmarshal error"},
		{"ErrInvalidRequestBody", ErrInvalidRequestBody{Reason: "empty body"}, "invalid request body: empty body"},
		{"ErrMissingRequiredField", ErrMissingRequiredField{Field: "name"}, "missing required field: name"},

		// QUIC errors
		{"ErrQUICNilRequest", ErrQUICNilRequest{}, "QUIC request cannot be nil"},
		{"ErrQUICUnknownOpcode", ErrQUICUnknownOpcode{Opcode: 0xFF}, "unknown QUIC opcode: 0xFF"},
		{"ErrQUICServiceUnavailable", ErrQUICServiceUnavailable{Service: "kms"}, "QUIC service unavailable: kms"},
		{"ErrQUICDecodingFailed", ErrQUICDecodingFailed{Cause: errors.New("decode error")}, "QUIC payload decoding failed: decode error"},
		{"ErrQUICEncodingFailed", ErrQUICEncodingFailed{Cause: errors.New("encode error")}, "QUIC payload encoding failed: encode error"},
		{"ErrQUICMissingField", ErrQUICMissingField{Field: "payload"}, "QUIC request missing required field: payload"},
		{"ErrQUICOperationFailed", ErrQUICOperationFailed{Op: "encrypt", Cause: errors.New("key expired")}, "QUIC operation encrypt failed: key expired"},
		{"ErrQUICServerNotConfigured", ErrQUICServerNotConfigured{}, "QUIC server not configured"},
		{"ErrQUICServerStartFailed", ErrQUICServerStartFailed{Cause: errors.New("bind error")}, "QUIC server failed to start: bind error"},
		{"ErrQUICServerStopFailed", ErrQUICServerStopFailed{Cause: errors.New("timeout")}, "QUIC server failed to stop: timeout"},

		// MCP errors
		{"ErrMCPServerNotRunning", ErrMCPServerNotRunning{}, "MCP server is not running"},
		{"ErrMCPServerAlreadyRunning", ErrMCPServerAlreadyRunning{}, "MCP server is already running"},
		{"ErrMCPServerStartFailed", ErrMCPServerStartFailed{Cause: errors.New("port conflict")}, "MCP server failed to start: port conflict"},
		{"ErrMCPServerStopFailed", ErrMCPServerStopFailed{Cause: errors.New("shutdown timeout")}, "MCP server failed to stop: shutdown timeout"},
		{"ErrMCPServerNotConfigured", ErrMCPServerNotConfigured{}, "MCP server not configured"},

		// vTPM errors
		{"ErrVTPMOperationNotImplemented", ErrVTPMOperationNotImplemented{Operation: "seal"}, "vTPM operation not implemented: seal"},

		// Device errors
		{"ErrDeviceOperationNotImplemented", ErrDeviceOperationNotImplemented{Operation: "provision"}, "device operation not implemented: provision"},
		{"ErrInvalidDeviceID", ErrInvalidDeviceID{ID: "bad-id"}, "invalid device ID: bad-id"},
		{"ErrAttestationFailed", ErrAttestationFailed{Reason: "quote verification failed"}, "attestation failed: quote verification failed"},
		{"ErrDeviceNotFound", ErrDeviceNotFound{DeviceID: "device-123"}, "device not found: device-123"},
		{"ErrProvisioningFailed", ErrProvisioningFailed{Reason: "TPM error"}, "device provisioning failed: TPM error"},
		{"ErrProfileNotFound", ErrProfileNotFound{Profile: "edge-device"}, "device profile not found: edge-device"},
		{"ErrInvalidAttestationEvidence", ErrInvalidAttestationEvidence{Reason: "invalid signature"}, "invalid attestation evidence: invalid signature"},

		// SDN errors
		{"ErrSDNOperationNotImplemented", ErrSDNOperationNotImplemented{Operation: "create-vlan"}, "SDN operation not implemented: create-vlan"},
		{"ErrSDNPolicyEngineNotConfigured", ErrSDNPolicyEngineNotConfigured{}, "SDN policy engine not configured"},
		{"ErrSDNInvalidPortState", ErrSDNInvalidPortState{State: "invalid"}, "invalid port state: invalid"},
		{"ErrSDNPolicyNotFound", ErrSDNPolicyNotFound{PolicyID: "policy-1"}, "SDN policy not found: policy-1"},
		{"ErrSDNInvalidPolicy", ErrSDNInvalidPolicy{Reason: "missing action"}, "invalid SDN policy: missing action"},
		{"ErrSDNSetPortStateFailed", ErrSDNSetPortStateFailed{PortID: "eth0", Cause: errors.New("permission denied")}, "failed to set port state for eth0: permission denied"},
		{"ErrSDNApplyPolicyFailed", ErrSDNApplyPolicyFailed{PolicyID: "policy-1", Cause: errors.New("conflict")}, "failed to apply policy policy-1: conflict"},
		{"ErrSDNBridgeNotFound", ErrSDNBridgeNotFound{BridgeName: "br0"}, "SDN bridge not found: br0"},
		{"ErrSDNPortNotFound", ErrSDNPortNotFound{BridgeName: "br0", PortName: "eth1"}, "SDN port not found: eth1 on bridge br0"},
		{"ErrSDNMissingParameter", ErrSDNMissingParameter{Parameter: "bridge_name"}, "missing required parameter: bridge_name"},

		// IAM errors
		{"ErrIAMServiceNotAvailable", ErrIAMServiceNotAvailable{}, "IAM service not available"},
		{"ErrIAMMissingParameter", ErrIAMMissingParameter{Parameter: "tenant_id"}, "missing required IAM parameter: tenant_id"},
		{"ErrIAMUserNotFound", ErrIAMUserNotFound{TenantID: "tenant-1", UserID: "user-1"}, "IAM user not found: user-1 in tenant tenant-1"},
		{"ErrIAMUserAlreadyExists", ErrIAMUserAlreadyExists{TenantID: "tenant-1", Email: "user@example.com"}, "IAM user already exists: user@example.com in tenant tenant-1"},
		{"ErrIAMRoleNotFound", ErrIAMRoleNotFound{TenantID: "tenant-1", RoleID: "admin"}, "IAM role not found: admin in tenant tenant-1"},
		{"ErrIAMRoleAlreadyExists", ErrIAMRoleAlreadyExists{TenantID: "tenant-1", RoleID: "admin"}, "IAM role already exists: admin in tenant tenant-1"},
		{"ErrIAMGroupNotFound", ErrIAMGroupNotFound{TenantID: "tenant-1", GroupID: "developers"}, "IAM group not found: developers in tenant tenant-1"},
		{"ErrIAMGroupAlreadyExists", ErrIAMGroupAlreadyExists{TenantID: "tenant-1", GroupID: "developers"}, "IAM group already exists: developers in tenant tenant-1"},
		{"ErrIAMTenantNotFound", ErrIAMTenantNotFound{TenantID: "tenant-1"}, "IAM tenant not found: tenant-1"},
		{"ErrIAMTenantAlreadyExists", ErrIAMTenantAlreadyExists{TenantID: "tenant-1"}, "IAM tenant already exists: tenant-1"},
		{"ErrIAMPolicyNotFound", ErrIAMPolicyNotFound{TenantID: "tenant-1", PolicyName: "read-only"}, "IAM policy not found: read-only in tenant tenant-1"},
		{"ErrIAMPolicyAlreadyExists", ErrIAMPolicyAlreadyExists{TenantID: "tenant-1", PolicyName: "read-only"}, "IAM policy already exists: read-only in tenant tenant-1"},
		{"ErrIAMPolicyValidationFailed", ErrIAMPolicyValidationFailed{Reason: "invalid statement"}, "IAM policy validation failed: invalid statement"},
		{"ErrIAMAppNotFound", ErrIAMAppNotFound{TenantID: "tenant-1", ClientID: "client-123"}, "IAM application not found: client-123 in tenant tenant-1"},
		{"ErrIAMAppAlreadyExists", ErrIAMAppAlreadyExists{TenantID: "tenant-1", Name: "my-app"}, "IAM application already exists: my-app in tenant tenant-1"},
		{"ErrIAMAuthenticationFailed", ErrIAMAuthenticationFailed{Reason: "invalid password"}, "IAM authentication failed: invalid password"},
		{"ErrIAMPermissionDenied", ErrIAMPermissionDenied{Subject: "user-1", Resource: "bucket/data", Action: "write"}, "IAM permission denied: subject user-1 cannot perform write on bucket/data"},
		{"ErrIAMOperationFailed", ErrIAMOperationFailed{Operation: "create-user", Cause: errors.New("database error")}, "IAM operation create-user failed: database error"},
		{"ErrIAMInvalidCredentials", ErrIAMInvalidCredentials{}, "IAM invalid credentials"},
		{"ErrIAMRoleAssignmentFailed", ErrIAMRoleAssignmentFailed{UserID: "user-1", RoleID: "admin", Reason: "role limit exceeded"}, "IAM failed to assign role admin to user user-1: role limit exceeded"},
		{"ErrIAMRoleRevocationFailed", ErrIAMRoleRevocationFailed{UserID: "user-1", RoleID: "admin", Reason: "role not assigned"}, "IAM failed to revoke role admin from user user-1: role not assigned"},
		{"ErrIAMGroupMembershipFailed", ErrIAMGroupMembershipFailed{GroupID: "developers", UserID: "user-1", Reason: "group full"}, "IAM group membership operation failed for user user-1 in group developers: group full"},
		{"ErrIAMTokenNotFound", ErrIAMTokenNotFound{TokenID: "token-123"}, "IAM token not found: token-123"},
		{"ErrIAMTokenExpired", ErrIAMTokenExpired{TokenID: "token-123"}, "IAM token expired: token-123"},
		{"ErrIAMTokenRevoked", ErrIAMTokenRevoked{TokenID: "token-123"}, "IAM token revoked: token-123"},
		{"ErrIAMTokenInvalid", ErrIAMTokenInvalid{Reason: "signature mismatch"}, "IAM token invalid: signature mismatch"},

		// KMS errors
		{"ErrKMSKeyNotFound", ErrKMSKeyNotFound{KeyID: "key-123"}, "KMS key not found: key-123"},
		{"ErrKMSKeyAlreadyExists", ErrKMSKeyAlreadyExists{KeyID: "key-123"}, "KMS key already exists: key-123"},
		{"ErrKMSKeyDisabled", ErrKMSKeyDisabled{KeyID: "key-123"}, "KMS key is disabled: key-123"},
		{"ErrKMSInvalidParameter", ErrKMSInvalidParameter{Parameter: "key_size", Reason: "must be 256"}, "invalid KMS parameter key_size: must be 256"},
		{"ErrKMSInvalidAlgorithm", ErrKMSInvalidAlgorithm{Algorithm: "unknown"}, "invalid KMS algorithm: unknown"},
		{"ErrKMSInvalidKeyUsage", ErrKMSInvalidKeyUsage{Usage: "invalid"}, "invalid KMS key usage: invalid"},
		{"ErrKMSOperationFailed", ErrKMSOperationFailed{Operation: "wrap", Cause: errors.New("key expired")}, "KMS operation wrap failed: key expired"},
		{"ErrKMSEncryptionFailed", ErrKMSEncryptionFailed{KeyID: "key-123", Cause: errors.New("padding error")}, "KMS encryption failed for key key-123: padding error"},
		{"ErrKMSDecryptionFailed", ErrKMSDecryptionFailed{KeyID: "key-123", Cause: errors.New("authentication failed")}, "KMS decryption failed for key key-123: authentication failed"},
		{"ErrKMSSigningFailed", ErrKMSSigningFailed{KeyID: "key-123", Cause: errors.New("key not for signing")}, "KMS signing failed for key key-123: key not for signing"},
		{"ErrKMSVerificationFailed", ErrKMSVerificationFailed{KeyID: "key-123", Cause: errors.New("signature invalid")}, "KMS signature verification failed for key key-123: signature invalid"},
		{"ErrKMSKeyRotationFailed", ErrKMSKeyRotationFailed{KeyID: "key-123", Cause: errors.New("rotation in progress")}, "KMS key rotation failed for key key-123: rotation in progress"},
		{"ErrKMSRandomGenerationFailed", ErrKMSRandomGenerationFailed{Cause: errors.New("entropy exhausted")}, "KMS random generation failed: entropy exhausted"},
		{"ErrKMSKeyDeletionProtected", ErrKMSKeyDeletionProtected{KeyID: "key-123"}, "KMS key key-123 has deletion protection enabled"},
		{"ErrKMSDataKeyGenerationFailed", ErrKMSDataKeyGenerationFailed{KeyID: "kek-123", Cause: errors.New("wrap failed")}, "KMS data key generation failed for KEK kek-123: wrap failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			if !strings.Contains(errMsg, tt.contains) {
				t.Errorf("expected error to contain %q, got %q", tt.contains, errMsg)
			}
		})
	}
}

func TestErrorsWithUnwrap(t *testing.T) {
	causeErr := errors.New("underlying cause")

	tests := []struct {
		name string
		err  interface {
			error
			Unwrap() error
		}
		expectedCause error
	}{
		{"ErrRESTEncodingFailed", ErrRESTEncodingFailed{Cause: causeErr}, causeErr},
		{"ErrRESTDecodingFailed", ErrRESTDecodingFailed{Cause: causeErr}, causeErr},
		{"ErrQUICDecodingFailed", ErrQUICDecodingFailed{Cause: causeErr}, causeErr},
		{"ErrQUICEncodingFailed", ErrQUICEncodingFailed{Cause: causeErr}, causeErr},
		{"ErrQUICOperationFailed", ErrQUICOperationFailed{Op: "test", Cause: causeErr}, causeErr},
		{"ErrQUICServerStartFailed", ErrQUICServerStartFailed{Cause: causeErr}, causeErr},
		{"ErrQUICServerStopFailed", ErrQUICServerStopFailed{Cause: causeErr}, causeErr},
		{"ErrMCPServerStartFailed", ErrMCPServerStartFailed{Cause: causeErr}, causeErr},
		{"ErrMCPServerStopFailed", ErrMCPServerStopFailed{Cause: causeErr}, causeErr},
		{"ErrDNSOperationFailed", ErrDNSOperationFailed{Operation: "test", Cause: causeErr}, causeErr},
		{"ErrSDNSetPortStateFailed", ErrSDNSetPortStateFailed{PortID: "eth0", Cause: causeErr}, causeErr},
		{"ErrSDNApplyPolicyFailed", ErrSDNApplyPolicyFailed{PolicyID: "pol-1", Cause: causeErr}, causeErr},
		{"ErrIAMOperationFailed", ErrIAMOperationFailed{Operation: "test", Cause: causeErr}, causeErr},
		{"ErrKMSOperationFailed", ErrKMSOperationFailed{Operation: "test", Cause: causeErr}, causeErr},
		{"ErrKMSEncryptionFailed", ErrKMSEncryptionFailed{KeyID: "key-1", Cause: causeErr}, causeErr},
		{"ErrKMSDecryptionFailed", ErrKMSDecryptionFailed{KeyID: "key-1", Cause: causeErr}, causeErr},
		{"ErrKMSSigningFailed", ErrKMSSigningFailed{KeyID: "key-1", Cause: causeErr}, causeErr},
		{"ErrKMSVerificationFailed", ErrKMSVerificationFailed{KeyID: "key-1", Cause: causeErr}, causeErr},
		{"ErrKMSKeyRotationFailed", ErrKMSKeyRotationFailed{KeyID: "key-1", Cause: causeErr}, causeErr},
		{"ErrKMSRandomGenerationFailed", ErrKMSRandomGenerationFailed{Cause: causeErr}, causeErr},
		{"ErrKMSDataKeyGenerationFailed", ErrKMSDataKeyGenerationFailed{KeyID: "kek-1", Cause: causeErr}, causeErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unwrapped := tt.err.Unwrap()
			if unwrapped != tt.expectedCause {
				t.Errorf("Unwrap() = %v, want %v", unwrapped, tt.expectedCause)
			}

			// Also verify errors.Is works correctly
			if !errors.Is(tt.err, tt.expectedCause) {
				t.Errorf("errors.Is() failed to find cause %v in error %v", tt.expectedCause, tt.err)
			}
		})
	}
}

func TestErrorsWithNilCause(t *testing.T) {
	tests := []struct {
		name string
		err  interface {
			error
			Unwrap() error
		}
	}{
		{"ErrRESTEncodingFailed_NilCause", ErrRESTEncodingFailed{Cause: nil}},
		{"ErrRESTDecodingFailed_NilCause", ErrRESTDecodingFailed{Cause: nil}},
		{"ErrQUICDecodingFailed_NilCause", ErrQUICDecodingFailed{Cause: nil}},
		{"ErrQUICEncodingFailed_NilCause", ErrQUICEncodingFailed{Cause: nil}},
		{"ErrQUICOperationFailed_NilCause", ErrQUICOperationFailed{Op: "test", Cause: nil}},
		{"ErrQUICServerStartFailed_NilCause", ErrQUICServerStartFailed{Cause: nil}},
		{"ErrQUICServerStopFailed_NilCause", ErrQUICServerStopFailed{Cause: nil}},
		{"ErrMCPServerStartFailed_NilCause", ErrMCPServerStartFailed{Cause: nil}},
		{"ErrMCPServerStopFailed_NilCause", ErrMCPServerStopFailed{Cause: nil}},
		{"ErrDNSOperationFailed_NilCause", ErrDNSOperationFailed{Operation: "test", Cause: nil}},
		{"ErrSDNSetPortStateFailed_NilCause", ErrSDNSetPortStateFailed{PortID: "eth0", Cause: nil}},
		{"ErrSDNApplyPolicyFailed_NilCause", ErrSDNApplyPolicyFailed{PolicyID: "pol-1", Cause: nil}},
		{"ErrIAMOperationFailed_NilCause", ErrIAMOperationFailed{Operation: "test", Cause: nil}},
		{"ErrKMSOperationFailed_NilCause", ErrKMSOperationFailed{Operation: "test", Cause: nil}},
		{"ErrKMSEncryptionFailed_NilCause", ErrKMSEncryptionFailed{KeyID: "key-1", Cause: nil}},
		{"ErrKMSDecryptionFailed_NilCause", ErrKMSDecryptionFailed{KeyID: "key-1", Cause: nil}},
		{"ErrKMSSigningFailed_NilCause", ErrKMSSigningFailed{KeyID: "key-1", Cause: nil}},
		{"ErrKMSVerificationFailed_NilCause", ErrKMSVerificationFailed{KeyID: "key-1", Cause: nil}},
		{"ErrKMSKeyRotationFailed_NilCause", ErrKMSKeyRotationFailed{KeyID: "key-1", Cause: nil}},
		{"ErrKMSRandomGenerationFailed_NilCause", ErrKMSRandomGenerationFailed{Cause: nil}},
		{"ErrKMSDataKeyGenerationFailed_NilCause", ErrKMSDataKeyGenerationFailed{KeyID: "kek-1", Cause: nil}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Ensure Error() doesn't panic with nil cause
			errMsg := tt.err.Error()
			if errMsg == "" {
				t.Error("Error() returned empty string")
			}

			// Unwrap should return nil
			if unwrapped := tt.err.Unwrap(); unwrapped != nil {
				t.Errorf("Unwrap() = %v, want nil", unwrapped)
			}
		})
	}
}

func TestErrorsImplementErrorInterface(t *testing.T) {
	// Compile-time check that all error types implement the error interface
	var _ error = ErrDaemonNotRunning{}
	var _ error = ErrDaemonAlreadyRunning{}
	var _ error = ErrServiceNotFound{}
	var _ error = ErrServiceAlreadyRunning{}
	var _ error = ErrServiceNotRunning{}
	var _ error = ErrServiceStartFailed{}
	var _ error = ErrServiceStopFailed{}
	var _ error = ErrConfigNotFound{}
	var _ error = ErrInvalidConfig{}
	var _ error = ErrProvisionFailed{}
	var _ error = ErrShutdownFailed{}
	var _ error = ErrInvalidServiceType{}
	var _ error = ErrHealthRegistryNotConfigured{}
	var _ error = ErrHealthCheckFailed{}
	var _ error = ErrDatabaseNotAvailable{}
	var _ error = ErrUnsupportedRecordType{}
	var _ error = ErrDNSServiceNotAvailable{}
	var _ error = ErrDNSInvalidParameter{}
	var _ error = ErrServiceNotAvailable{}
	var _ error = ErrGRPCServerNotConfigured{}
	var _ error = ErrRESTServerNotRunning{}
	var _ error = ErrRESTServerAlreadyRunning{}
	var _ error = ErrRESTServerStartFailed{}
	var _ error = ErrRESTServerStopFailed{}
	var _ error = ErrRESTInvalidRequest{}
	var _ error = ErrRESTEncodingFailed{}
	var _ error = ErrRESTDecodingFailed{}
	var _ error = ErrInvalidRequestBody{}
	var _ error = ErrMissingRequiredField{}
	var _ error = ErrQUICNilRequest{}
	var _ error = ErrQUICUnknownOpcode{}
	var _ error = ErrQUICServiceUnavailable{}
	var _ error = ErrQUICDecodingFailed{}
	var _ error = ErrQUICEncodingFailed{}
	var _ error = ErrQUICMissingField{}
	var _ error = ErrQUICOperationFailed{}
	var _ error = ErrQUICServerNotConfigured{}
	var _ error = ErrQUICServerStartFailed{}
	var _ error = ErrQUICServerStopFailed{}
	var _ error = ErrMCPServerNotRunning{}
	var _ error = ErrMCPServerAlreadyRunning{}
	var _ error = ErrMCPServerStartFailed{}
	var _ error = ErrMCPServerStopFailed{}
	var _ error = ErrMCPServerNotConfigured{}
	var _ error = ErrVTPMOperationNotImplemented{}
	var _ error = ErrDeviceOperationNotImplemented{}
	var _ error = ErrInvalidDeviceID{}
	var _ error = ErrAttestationFailed{}
	var _ error = ErrDeviceNotFound{}
	var _ error = ErrProvisioningFailed{}
	var _ error = ErrProfileNotFound{}
	var _ error = ErrInvalidAttestationEvidence{}
	var _ error = ErrSDNOperationNotImplemented{}
	var _ error = ErrSDNPolicyEngineNotConfigured{}
	var _ error = ErrSDNInvalidPortState{}
	var _ error = ErrSDNPolicyNotFound{}
	var _ error = ErrSDNInvalidPolicy{}
	var _ error = ErrSDNSetPortStateFailed{}
	var _ error = ErrSDNApplyPolicyFailed{}
	var _ error = ErrSDNBridgeNotFound{}
	var _ error = ErrSDNPortNotFound{}
	var _ error = ErrSDNMissingParameter{}
	var _ error = ErrDNSConfigUpdateNotSupported{}
	var _ error = ErrDNSCacheFlushNotSupported{}
	var _ error = ErrDNSZoneNotFound{}
	var _ error = ErrDNSRecordNotFound{}
	var _ error = ErrDNSOperationFailed{}
	var _ error = ErrIAMServiceNotAvailable{}
	var _ error = ErrIAMMissingParameter{}
	var _ error = ErrIAMUserNotFound{}
	var _ error = ErrIAMUserAlreadyExists{}
	var _ error = ErrIAMRoleNotFound{}
	var _ error = ErrIAMRoleAlreadyExists{}
	var _ error = ErrIAMGroupNotFound{}
	var _ error = ErrIAMGroupAlreadyExists{}
	var _ error = ErrIAMTenantNotFound{}
	var _ error = ErrIAMTenantAlreadyExists{}
	var _ error = ErrIAMPolicyNotFound{}
	var _ error = ErrIAMPolicyAlreadyExists{}
	var _ error = ErrIAMPolicyValidationFailed{}
	var _ error = ErrIAMAppNotFound{}
	var _ error = ErrIAMAppAlreadyExists{}
	var _ error = ErrIAMAuthenticationFailed{}
	var _ error = ErrIAMPermissionDenied{}
	var _ error = ErrIAMOperationFailed{}
	var _ error = ErrIAMInvalidCredentials{}
	var _ error = ErrIAMRoleAssignmentFailed{}
	var _ error = ErrIAMRoleRevocationFailed{}
	var _ error = ErrIAMGroupMembershipFailed{}
	var _ error = ErrIAMTokenNotFound{}
	var _ error = ErrIAMTokenExpired{}
	var _ error = ErrIAMTokenRevoked{}
	var _ error = ErrIAMTokenInvalid{}
	var _ error = ErrKMSKeyNotFound{}
	var _ error = ErrKMSKeyAlreadyExists{}
	var _ error = ErrKMSKeyDisabled{}
	var _ error = ErrKMSInvalidParameter{}
	var _ error = ErrKMSInvalidAlgorithm{}
	var _ error = ErrKMSInvalidKeyUsage{}
	var _ error = ErrKMSOperationFailed{}
	var _ error = ErrKMSEncryptionFailed{}
	var _ error = ErrKMSDecryptionFailed{}
	var _ error = ErrKMSSigningFailed{}
	var _ error = ErrKMSVerificationFailed{}
	var _ error = ErrKMSKeyRotationFailed{}
	var _ error = ErrKMSRandomGenerationFailed{}
	var _ error = ErrKMSKeyDeletionProtected{}
	var _ error = ErrKMSDataKeyGenerationFailed{}

	// This test passes if it compiles
	t.Log("All error types implement the error interface")
}
