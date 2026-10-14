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

package mcp

import (
	"errors"
	"testing"
)

// =============================================================================
// Error Type Coverage Tests
// =============================================================================

func TestVMError_Error(t *testing.T) {
	err := &VMError{
		Code:    "TEST_ERROR",
		Message: "test message",
	}

	expected := "TEST_ERROR: test message"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestVMError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *VMError
		expected string
	}{
		{"ErrVMServiceUnavailable", ErrVMServiceUnavailable, "VM_SERVICE_UNAVAILABLE: VM service is not available"},
		{"ErrVMNameRequired", ErrVMNameRequired, "VM_NAME_REQUIRED: VM name is required"},
		{"ErrVMIDRequired", ErrVMIDRequired, "VM_ID_REQUIRED: VM ID is required"},
		{"ErrVMNotFound", ErrVMNotFound, "VM_NOT_FOUND: VM not found"},
		{"ErrSnapshotNameRequired", ErrSnapshotNameRequired, "SNAPSHOT_NAME_REQUIRED: snapshot name is required"},
		{"ErrSnapshotIDRequired", ErrSnapshotIDRequired, "SNAPSHOT_ID_REQUIRED: snapshot ID is required"},
		{"ErrSnapshotNotFound", ErrSnapshotNotFound, "SNAPSHOT_NOT_FOUND: snapshot not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestErrVMOperationFailedError(t *testing.T) {
	cause := errors.New("underlying error")
	err := &ErrVMOperationFailedError{
		Operation: "start",
		Cause:     cause,
	}

	expected := "VM operation start failed: underlying error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestContainerError_Error(t *testing.T) {
	err := &ContainerError{
		Code:    "CONTAINER_TEST",
		Message: "test container error",
	}

	expected := "CONTAINER_TEST: test container error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestContainerError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *ContainerError
		expected string
	}{
		{"ErrContainerServiceUnavailable", ErrContainerServiceUnavailable, "CONTAINER_SERVICE_UNAVAILABLE: container service is not available"},
		{"ErrContainerNameRequired", ErrContainerNameRequired, "CONTAINER_NAME_REQUIRED: container name is required"},
		{"ErrContainerImageRequired", ErrContainerImageRequired, "CONTAINER_IMAGE_REQUIRED: container image is required"},
		{"ErrContainerIDRequired", ErrContainerIDRequired, "CONTAINER_ID_REQUIRED: container ID is required"},
		{"ErrContainerNotFound", ErrContainerNotFound, "CONTAINER_NOT_FOUND: container not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestAttestationError_Error(t *testing.T) {
	err := &AttestationError{
		Code:    "ATTEST_TEST",
		Message: "test attestation error",
	}

	expected := "ATTEST_TEST: test attestation error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAttestationError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *AttestationError
		expected string
	}{
		{"ErrAttestationServiceUnavailable", ErrAttestationServiceUnavailable, "ATTESTATION_SERVICE_UNAVAILABLE: attestation service is not available"},
		{"ErrManifestIDRequired", ErrManifestIDRequired, "MANIFEST_ID_REQUIRED: manifest ID is required"},
		{"ErrReportIDRequired", ErrReportIDRequired, "REPORT_ID_REQUIRED: report ID is required"},
		{"ErrPolicyIDRequired", ErrPolicyIDRequired, "POLICY_ID_REQUIRED: policy ID is required"},
		{"ErrPolicyNameRequired", ErrPolicyNameRequired, "POLICY_NAME_REQUIRED: policy name is required"},
		{"ErrHostIDRequired", ErrHostIDRequired, "HOST_ID_REQUIRED: host ID is required"},
		{"ErrWorkloadIDRequired", ErrWorkloadIDRequired, "WORKLOAD_ID_REQUIRED: workload ID is required"},
		{"ErrWorkloadTypeRequired", ErrWorkloadTypeRequired, "WORKLOAD_TYPE_REQUIRED: workload type is required"},
		{"ErrEvidenceRequired", ErrEvidenceRequired, "EVIDENCE_REQUIRED: attestation evidence is required"},
		{"ErrAttestationDataRequired", ErrAttestationDataRequired, "ATTESTATION_DATA_REQUIRED: attestation data is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestDeviceError_Error(t *testing.T) {
	err := &DeviceError{
		Code:    "DEVICE_TEST",
		Message: "test device error",
	}

	expected := "DEVICE_TEST: test device error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestDeviceError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *DeviceError
		expected string
	}{
		{"ErrDeviceServiceUnavailable", ErrDeviceServiceUnavailable, "DEVICE_SERVICE_UNAVAILABLE: device service is not available"},
		{"ErrDeviceSerialRequired", ErrDeviceSerialRequired, "DEVICE_SERIAL_REQUIRED: device serial is required"},
		{"ErrDeviceIDRequired", ErrDeviceIDRequired, "DEVICE_ID_REQUIRED: device ID is required"},
		{"ErrDeviceNotFound", ErrDeviceNotFound, "DEVICE_NOT_FOUND: device not found"},
		{"ErrProfileNameRequired", ErrProfileNameRequired, "PROFILE_NAME_REQUIRED: profile name is required"},
		{"ErrProfileIDRequired", ErrProfileIDRequired, "PROFILE_ID_REQUIRED: profile ID is required"},
		{"ErrProfileNotFound", ErrProfileNotFound, "PROFILE_NOT_FOUND: profile not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestDNSError_Error(t *testing.T) {
	err := &DNSError{
		Code:    "DNS_TEST",
		Message: "test DNS error",
	}

	expected := "DNS_TEST: test DNS error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestIAMError_Error(t *testing.T) {
	err := &IAMError{
		Code:    "IAM_TEST",
		Message: "test IAM error",
	}

	expected := "IAM_TEST: test IAM error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestIAMError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *IAMError
		expected string
	}{
		{"ErrIAMServiceUnavailable", ErrIAMServiceUnavailable, "IAM_SERVICE_UNAVAILABLE: IAM service is not available"},
		{"ErrIAMTenantIDRequired", ErrIAMTenantIDRequired, "IAM_TENANT_ID_REQUIRED: tenant_id is required"},
		{"ErrIAMUserIDRequired", ErrIAMUserIDRequired, "IAM_USER_ID_REQUIRED: user_id is required"},
		{"ErrIAMRoleIDRequired", ErrIAMRoleIDRequired, "IAM_ROLE_ID_REQUIRED: role_id is required"},
		{"ErrIAMEmailRequired", ErrIAMEmailRequired, "IAM_EMAIL_REQUIRED: email is required"},
		{"ErrIAMPasswordRequired", ErrIAMPasswordRequired, "IAM_PASSWORD_REQUIRED: password is required"},
		{"ErrIAMResourceRequired", ErrIAMResourceRequired, "IAM_RESOURCE_REQUIRED: resource is required"},
		{"ErrIAMActionRequired", ErrIAMActionRequired, "IAM_ACTION_REQUIRED: action is required"},
		{"ErrIAMRoleRequired", ErrIAMRoleRequired, "IAM_ROLE_REQUIRED: role is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestIDevIDError_Error(t *testing.T) {
	err := &IDevIDError{
		Code:    "IDEVID_TEST",
		Message: "test IDevID error",
	}

	expected := "IDEVID_TEST: test IDevID error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestKMSError_Error(t *testing.T) {
	err := &KMSError{
		Code:    "KMS_TEST",
		Message: "test KMS error",
	}

	expected := "KMS_TEST: test KMS error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestKMSError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *KMSError
		expected string
	}{
		{"ErrKMSServiceUnavailable", ErrKMSServiceUnavailable, "KMS_SERVICE_UNAVAILABLE: KMS service is not available"},
		{"ErrKMSKeyIDRequired", ErrKMSKeyIDRequired, "KMS_KEY_ID_REQUIRED: key ID is required"},
		{"ErrKMSKeyNameRequired", ErrKMSKeyNameRequired, "KMS_KEY_NAME_REQUIRED: key name is required"},
		{"ErrKMSAlgorithmRequired", ErrKMSAlgorithmRequired, "KMS_ALGORITHM_REQUIRED: key algorithm is required"},
		{"ErrKMSMessageRequired", ErrKMSMessageRequired, "KMS_MESSAGE_REQUIRED: message is required"},
		{"ErrKMSSignatureRequired", ErrKMSSignatureRequired, "KMS_SIGNATURE_REQUIRED: signature is required"},
		{"ErrKMSPlaintextRequired", ErrKMSPlaintextRequired, "KMS_PLAINTEXT_REQUIRED: plaintext is required"},
		{"ErrKMSCiphertextRequired", ErrKMSCiphertextRequired, "KMS_CIPHERTEXT_REQUIRED: ciphertext is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestSDNError_Error(t *testing.T) {
	err := &SDNError{
		Code:    "SDN_TEST",
		Message: "test SDN error",
	}

	expected := "SDN_TEST: test SDN error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestSDNError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *SDNError
		expected string
	}{
		{"ErrSDNServiceUnavailable", ErrSDNServiceUnavailable, "SDN_SERVICE_UNAVAILABLE: SDN service is not available"},
		{"ErrSDNBridgeNameRequired", ErrSDNBridgeNameRequired, "SDN_BRIDGE_NAME_REQUIRED: bridge name is required"},
		{"ErrSDNPortNameRequired", ErrSDNPortNameRequired, "SDN_PORT_NAME_REQUIRED: port name is required"},
		{"ErrSDNFlowMatchRequired", ErrSDNFlowMatchRequired, "SDN_FLOW_MATCH_REQUIRED: flow match criteria is required"},
		{"ErrSDNFlowActionsRequired", ErrSDNFlowActionsRequired, "SDN_FLOW_ACTIONS_REQUIRED: flow actions are required"},
		{"ErrSDNFlowIDRequired", ErrSDNFlowIDRequired, "SDN_FLOW_ID_REQUIRED: flow ID is required"},
		{"ErrSDNPolicyNameRequired", ErrSDNPolicyNameRequired, "SDN_POLICY_NAME_REQUIRED: policy name is required"},
		{"ErrSDNPolicyIDRequired", ErrSDNPolicyIDRequired, "SDN_POLICY_ID_REQUIRED: policy ID is required"},
		{"ErrSDNPolicyRulesRequired", ErrSDNPolicyRulesRequired, "SDN_POLICY_RULES_REQUIRED: policy rules are required"},
		{"ErrSDNBridgeNotFound", ErrSDNBridgeNotFound, "SDN_BRIDGE_NOT_FOUND: bridge not found"},
		{"ErrSDNPortNotFound", ErrSDNPortNotFound, "SDN_PORT_NOT_FOUND: port not found"},
		{"ErrSDNFlowNotFound", ErrSDNFlowNotFound, "SDN_FLOW_NOT_FOUND: flow not found"},
		{"ErrSDNPolicyNotFound", ErrSDNPolicyNotFound, "SDN_POLICY_NOT_FOUND: policy not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestVTPMError_Error(t *testing.T) {
	err := &VTPMError{
		Code:    "VTPM_TEST",
		Message: "test VTPM error",
	}

	expected := "VTPM_TEST: test VTPM error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestVTPMError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *VTPMError
		expected string
	}{
		{"ErrVTPMServiceUnavailable", ErrVTPMServiceUnavailable, "VTPM_SERVICE_UNAVAILABLE: vTPM service is not available"},
		{"ErrVTPMBundleIDRequired", ErrVTPMBundleIDRequired, "VTPM_BUNDLE_ID_REQUIRED: bundle ID is required"},
		{"ErrVTPMTemplateIDRequired", ErrVTPMTemplateIDRequired, "VTPM_TEMPLATE_ID_REQUIRED: template ID is required"},
		{"ErrVTPMHostnameRequired", ErrVTPMHostnameRequired, "VTPM_HOSTNAME_REQUIRED: hostname is required"},
		{"ErrVTPMNonceRequired", ErrVTPMNonceRequired, "VTPM_NONCE_REQUIRED: nonce is required"},
		{"ErrVTPMInvalidNonce", ErrVTPMInvalidNonce, "VTPM_INVALID_NONCE: invalid nonce encoding"},
		{"ErrVTPMDataRequired", ErrVTPMDataRequired, "VTPM_DATA_REQUIRED: data is required"},
		{"ErrVTPMInvalidData", ErrVTPMInvalidData, "VTPM_INVALID_DATA: invalid data encoding"},
		{"ErrVTPMSealedDataRequired", ErrVTPMSealedDataRequired, "VTPM_SEALED_DATA_REQUIRED: sealed_data is required"},
		{"ErrVTPMInvalidSealedData", ErrVTPMInvalidSealedData, "VTPM_INVALID_SEALED_DATA: invalid sealed_data encoding"},
		{"ErrVTPMInvalidPCRIndex", ErrVTPMInvalidPCRIndex, "VTPM_INVALID_PCR_INDEX: invalid PCR index (must be 0-23)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestTenantError_Error(t *testing.T) {
	err := &TenantError{
		Code:    "TENANT_TEST",
		Message: "test tenant error",
	}

	expected := "TENANT_TEST: test tenant error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestTenantError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrTenantServiceUnavailable", ErrTenantServiceUnavailable, "TENANT_SERVICE_UNAVAILABLE: tenant management service is not available"},
		{"ErrTenantIDRequired", ErrTenantIDRequired, "TENANT_ID_REQUIRED: tenant ID is required"},
		{"ErrTenantNameRequired", ErrTenantNameRequired, "TENANT_NAME_REQUIRED: tenant name is required"},
		{"ErrTenantResourceTypeRequired", ErrTenantResourceTypeRequired, "TENANT_RESOURCE_TYPE_REQUIRED: resource type is required"},
		{"ErrTenantAmountRequired", ErrTenantAmountRequired, "TENANT_AMOUNT_REQUIRED: amount is required"},
		{"ErrTenantInvalidResourceType", ErrTenantInvalidResourceType, "TENANT_INVALID_RESOURCE_TYPE: invalid resource type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestPXEErrorCoverage(t *testing.T) {
	err := &PXEError{
		Code:    "PXE_TEST",
		Message: "test PXE error",
	}

	expected := "PXE_TEST: test PXE error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestPXEError_PredefinedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrPXEServiceUnavailable", ErrPXEServiceUnavailable, "PXE_SERVICE_UNAVAILABLE: PXE provisioning service is not available"},
		{"ErrPXEDeviceIDRequired", ErrPXEDeviceIDRequired, "PXE_DEVICE_ID_REQUIRED: device ID is required"},
		{"ErrPXEMACAddressRequired", ErrPXEMACAddressRequired, "PXE_MAC_ADDRESS_REQUIRED: MAC address is required"},
		{"ErrPXEPortIDRequired", ErrPXEPortIDRequired, "PXE_PORT_ID_REQUIRED: port ID is required"},
		{"ErrPXEStateRequired", ErrPXEStateRequired, "PXE_STATE_REQUIRED: state is required"},
		{"ErrPXEDeviceNotFound", ErrPXEDeviceNotFound, "PXE_DEVICE_NOT_FOUND: device not found"},
		{"ErrPXEInvalidState", ErrPXEInvalidState, "PXE_INVALID_STATE: invalid provisioning state"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}
