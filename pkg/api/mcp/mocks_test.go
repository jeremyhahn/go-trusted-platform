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
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// ErrMockServiceError is a standard mock service error for testing.
var ErrMockServiceError = errors.New("mock service error")

// mockServiceProvider implements ServiceProvider for testing.
type mockServiceProvider struct {
	// lastSRKHandle records the handle the last TPMGetSRK call carried.
	lastSRKHandle uint32

	// lastZoneCreate and lastZoneUpdate record the last zone requests.
	lastZoneCreate     *NetworkZoneCreateRequest
	lastZoneUpdate     *NetworkZoneUpdateRequest
	lastZoneUpdateName string

	// vTPM
	vtpmCreateFunc    func(ctx context.Context, name, algorithm string) (interface{}, error)
	vtpmDeleteFunc    func(ctx context.Context, name string) error
	vtpmListFunc      func(ctx context.Context) ([]interface{}, error)
	vtpmStartFunc     func(ctx context.Context, name string) error
	vtpmStopFunc      func(ctx context.Context, name string) error
	vtpmQuoteFunc     func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error)
	vtpmSealFunc      func(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error)
	vtpmUnsealFunc    func(ctx context.Context, name string, sealed []byte) ([]byte, error)
	vtpmExtendPCRFunc func(ctx context.Context, name string, pcr int, data []byte) error
	vtpmReadPCRFunc   func(ctx context.Context, name string, pcr int) ([]byte, error)

	// vTPM extended operations
	vtpmGetFunc              func(ctx context.Context, name string) (interface{}, error)
	vtpmValidateFunc         func(ctx context.Context, name string) (interface{}, error)
	vtpmExportFunc           func(ctx context.Context, name string) (interface{}, error)
	vtpmImportFunc           func(ctx context.Context, data []byte) (interface{}, error)
	vtpmCreateTemplateFunc   func(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error)
	vtpmGetTemplateFunc      func(ctx context.Context, id string) (interface{}, error)
	vtpmDeleteTemplateFunc   func(ctx context.Context, id string) error
	vtpmListTemplatesFunc    func(ctx context.Context) (interface{}, error)
	vtpmCloneTemplateFunc    func(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error)
	vtpmGetBundlePathFunc    func(ctx context.Context, name string) (interface{}, error)
	vtpmGetTPMSocketPathFunc func(ctx context.Context, name string) (interface{}, error)
	vtpmGetNVRAMPathFunc     func(ctx context.Context, name string) (interface{}, error)
	vtpmIsRunningFunc        func(ctx context.Context, name string) (interface{}, error)

	// DNS
	dnsAddRecordFunc    func(ctx context.Context, name, recordType, value string, ttl int) error
	dnsDeleteRecordFunc func(ctx context.Context, name, recordType string) error
	dnsGetRecordFunc    func(ctx context.Context, name, recordType string) (interface{}, error)
	dnsListRecordsFunc  func(ctx context.Context, zone string) ([]interface{}, error)
	dnsResolveFunc      func(ctx context.Context, name, recordType string) ([]string, error)
	dnsCreateZoneFunc   func(ctx context.Context, zone string) error
	dnsDeleteZoneFunc   func(ctx context.Context, zone string) error
	dnsListZonesFunc    func(ctx context.Context) ([]string, error)

	// Device
	deviceRegisterFunc         func(ctx context.Context, name, deviceType string, publicKey []byte) (interface{}, error)
	deviceGetFunc              func(ctx context.Context, deviceID string) (interface{}, error)
	deviceListFunc             func(ctx context.Context, filter map[string]string) ([]interface{}, error)
	deviceDeleteFunc           func(ctx context.Context, deviceID string) error
	deviceUpdateFunc           func(ctx context.Context, deviceID string, updates map[string]interface{}) error
	deviceAttestFunc           func(ctx context.Context, deviceID string, evidence []byte) (interface{}, error)
	deviceRecordAttestCertFunc func(ctx context.Context, deviceID string, reissue bool) (interface{}, error)
	deviceProvisionFunc        func(ctx context.Context, deviceID, profile string) error

	// SDN Bridge
	sdnGetPortStateFunc     func(ctx context.Context, bridgeName, portName string) (interface{}, error)
	sdnSetPortStateFunc     func(ctx context.Context, bridgeName, portName, state string) error
	sdnListBridgesFunc      func(ctx context.Context) ([]interface{}, error)
	sdnCreateBridgeFunc     func(ctx context.Context, bridgeName string) error
	sdnDeleteBridgeFunc     func(ctx context.Context, bridgeName string) error
	sdnAddPortFunc          func(ctx context.Context, bridgeName, portName, portType string) error
	sdnDeletePortFunc       func(ctx context.Context, bridgeName, portName string) error
	sdnApplyPolicyFunc      func(ctx context.Context, policyID, bridgeName string) error
	sdnGetPolicyFunc        func(ctx context.Context, policyID string) (interface{}, error)
	sdnListPoliciesFunc     func(ctx context.Context) ([]interface{}, error)
	sdnAddFlowFunc          func(ctx context.Context, bridgeName string, flow map[string]interface{}) error
	sdnDeleteFlowFunc       func(ctx context.Context, bridgeName, flowID string) error
	sdnListFlowsFunc        func(ctx context.Context, bridgeName string) ([]interface{}, error)
	sdnFlushFlowsFunc       func(ctx context.Context, bridgeName string) error
	sdnCreateVLANFunc       func(ctx context.Context, bridgeName string, vlanID int, name string) error
	sdnDeleteVLANFunc       func(ctx context.Context, bridgeName string, vlanID int) error
	sdnListVLANsFunc        func(ctx context.Context, bridgeName string) ([]interface{}, error)
	sdnAuthenticatePortFunc func(ctx context.Context, bridgeName, portName string, credentials map[string]string) error
	sdnRevokePortAuthFunc   func(ctx context.Context, bridgeName, portName string) error
	sdnGetPortStatsFunc     func(ctx context.Context, bridgeName, portName string) (interface{}, error)
	sdnGetFlowStatsFunc     func(ctx context.Context, bridgeName string) (interface{}, error)

	// Health
	healthFunc    func(ctx context.Context) (interface{}, error)
	livenessFunc  func(ctx context.Context) (interface{}, error)
	readinessFunc func(ctx context.Context) (interface{}, error)

	// Daemon management
	daemonStatusFunc         func(ctx context.Context) (interface{}, error)
	daemonVersionFunc        func(ctx context.Context) (interface{}, error)
	daemonListServicesFunc   func(ctx context.Context) (interface{}, error)
	daemonGetServiceFunc     func(ctx context.Context, name string) (interface{}, error)
	daemonStartServiceFunc   func(ctx context.Context, name string) (interface{}, error)
	daemonStopServiceFunc    func(ctx context.Context, name string) (interface{}, error)
	daemonRestartServiceFunc func(ctx context.Context, name string) (interface{}, error)
	daemonListProtocolsFunc  func(ctx context.Context) (interface{}, error)

	// CA
	caInfoFunc   func(ctx context.Context) (interface{}, error)
	caIssueFunc  func(ctx context.Context, req *CAIssueRequest) (interface{}, error)
	caGetFunc    func(ctx context.Context, serial string, includePEM bool) (interface{}, error)
	caListFunc   func(ctx context.Context, limit int, cursor string, status string) (interface{}, error)
	caRevokeFunc func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error)
	caRenewFunc  func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error)
	caVerifyFunc func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error)
	caCRLFunc    func(ctx context.Context) (interface{}, error)
	caBundleFunc func(ctx context.Context, storeType string, algorithm string) (interface{}, error)

	// IAM
	iamCreateUserFunc      func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error)
	iamDeleteUserFunc      func(ctx context.Context, tenantID, userID string) error
	iamGetUserFunc         func(ctx context.Context, tenantID, userID string) (interface{}, error)
	iamListUsersFunc       func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error)
	iamCreateRoleFunc      func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error)
	iamDeleteRoleFunc      func(ctx context.Context, tenantID, roleID string) error
	iamGetRoleFunc         func(ctx context.Context, tenantID, roleID string) (interface{}, error)
	iamListRolesFunc       func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error)
	iamAssignRoleFunc      func(ctx context.Context, tenantID, userID, role string) error
	iamRevokeRoleFunc      func(ctx context.Context, tenantID, userID, role string) error
	iamCheckPermissionFunc func(ctx context.Context, tenantID, userID, resource, action string) (bool, error)
	iamAuthenticateFunc    func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error)

	// KMS
	kmsCreateKeyFunc       func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error)
	kmsDeleteKeyFunc       func(ctx context.Context, keyID string) error
	kmsGetKeyFunc          func(ctx context.Context, keyID string, version uint64) (interface{}, error)
	kmsExportPublicKeyFunc func(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error)
	kmsListKeysFunc        func(ctx context.Context, limit, offset int) (interface{}, error)
	kmsRotateKeyFunc       func(ctx context.Context, keyID string) (interface{}, error)
	kmsEncryptFunc         func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error)
	kmsDecryptFunc         func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error)
	kmsSignFunc            func(ctx context.Context, req *KMSSignRequest) (interface{}, error)
	kmsVerifyFunc          func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error)
	kmsGenerateRandomFunc  func(ctx context.Context, numBytes int) ([]byte, error)

	// KMS lifecycle
	kmsRevokeKeyFunc              func(ctx context.Context, keyID, reason string) (interface{}, error)
	kmsGetKeyMetadataFunc         func(ctx context.Context, keyID string) (interface{}, error)
	kmsUpdateKeyMetadataFunc      func(ctx context.Context, req *KMSUpdateKeyMetadataRequest) (interface{}, error)
	kmsSetKeyPolicyFunc           func(ctx context.Context, req *KMSSetKeyPolicyRequest) (interface{}, error)
	kmsGetKeyPolicyFunc           func(ctx context.Context, keyID string) (interface{}, error)
	kmsGetSupportedAlgorithmsFunc func(ctx context.Context) ([]string, error)
	kmsBackendStatusFunc          func(ctx context.Context) (interface{}, error)

	// Secrets
	secretStoreFunc             func(ctx context.Context, req *SecretStoreRequest) (interface{}, error)
	secretGetFunc               func(ctx context.Context, secretID string, version uint64) (interface{}, error)
	secretListFunc              func(ctx context.Context, limit int) (interface{}, error)
	secretDeleteFunc            func(ctx context.Context, secretID string) error
	secretSetRotationPolicyFunc func(ctx context.Context, req *SecretSetRotationPolicyRequest) (interface{}, error)
	secretGetRotationPolicyFunc func(ctx context.Context, secretID string) (interface{}, error)

	// IDevID/IAK
	idevidGenerateFunc     func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error)
	idevidInfoFunc         func(ctx context.Context) (interface{}, error)
	idevidDeleteFunc       func(ctx context.Context) error
	idevidCSRFunc          func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error)
	idevidInstallCertFunc  func(ctx context.Context, certificatePEM string) (interface{}, error)
	idevidGetCertFunc      func(ctx context.Context, includePEM bool) (interface{}, error)
	idevidDeleteCertFunc   func(ctx context.Context) error
	idevidExistsFunc       func(ctx context.Context) (bool, error)
	iakGenerateFunc        func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error)
	iakInfoFunc            func(ctx context.Context) (interface{}, error)
	iakDeleteFunc          func(ctx context.Context) error
	iakCSRFunc             func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error)
	iakInstallCertFunc     func(ctx context.Context, certificatePEM string) (interface{}, error)
	iakGetCertFunc         func(ctx context.Context, includePEM bool) (interface{}, error)
	iakDeleteCertFunc      func(ctx context.Context) error
	iakExistsFunc          func(ctx context.Context) (bool, error)
	deviceAttributesFunc   func(ctx context.Context) (interface{}, error)
	activateCredentialFunc func(ctx context.Context, credentialBlob []byte, secret []byte) ([]byte, error)
	// IAM Group
	iamCreateGroupFunc       func(ctx context.Context, req *IAMCreateGroupRequest) (interface{}, error)
	iamDeleteGroupFunc       func(ctx context.Context, tenantID, groupID string) error
	iamGetGroupFunc          func(ctx context.Context, tenantID, groupID string) (interface{}, error)
	iamListGroupsFunc        func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error)
	iamAddGroupMemberFunc    func(ctx context.Context, tenantID, groupID, userID string) error
	iamRemoveGroupMemberFunc func(ctx context.Context, tenantID, groupID, userID string) error

	// IAM Tenant
	iamCreateTenantFunc func(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error)
	iamDeleteTenantFunc func(ctx context.Context, tenantID string) error
	iamGetTenantFunc    func(ctx context.Context, tenantID string) (interface{}, error)
	iamListTenantsFunc  func(ctx context.Context, limit, offset int) (interface{}, error)

	// IAM Token
	iamCreateTokenFunc func(ctx context.Context, req *IAMCreateTokenRequest) (interface{}, error)
	iamRevokeTokenFunc func(ctx context.Context, tokenID string) error
	iamVerifyTokenFunc func(ctx context.Context, token string) (interface{}, error)

	// Container
	containerCreateFunc func(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error)
	containerStartFunc  func(ctx context.Context, id string) error
	containerStopFunc   func(ctx context.Context, id string, timeout int) error
	containerRemoveFunc func(ctx context.Context, id string, force bool) error
	containerGetFunc    func(ctx context.Context, id string) (interface{}, error)
	containerListFunc   func(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error)
	containerLogsFunc   func(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error)
	containerAttestFunc func(ctx context.Context, id string) (interface{}, error)

	// KMS Data Key
	kmsGenerateDataKeyFunc        func(ctx context.Context, req *KMSGenerateDataKeyRequest) (interface{}, error)
	kmsGenerateWrappedDataKeyFunc func(ctx context.Context, req *KMSGenerateWrappedDataKeyRequest) (interface{}, error)

	// Gateway perf
	mu                 sync.Mutex
	perfErr            error
	ntpErr             error
	ntpStepCalls       int
	perfFlowsCalls     []perfFlowsCall
	perfConntrackZones []int
}

// perfFlowsCall records one GatewayPerfFlows invocation.
type perfFlowsCall struct {
	bridge string
	count  int
	batch  bool
}

// newMockServiceProvider creates a new mock service provider with default success responses.
func newMockServiceProvider() *mockServiceProvider {
	return &mockServiceProvider{
		// vTPM defaults
		vtpmCreateFunc: func(ctx context.Context, name, algorithm string) (interface{}, error) {
			return map[string]interface{}{"name": name, "algorithm": algorithm, "status": "created"}, nil
		},
		vtpmDeleteFunc: func(ctx context.Context, name string) error {
			return nil
		},
		vtpmListFunc: func(ctx context.Context) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"name": "vtpm-1", "status": "running"},
				map[string]interface{}{"name": "vtpm-2", "status": "stopped"},
			}, nil
		},
		vtpmStartFunc: func(ctx context.Context, name string) error {
			return nil
		},
		vtpmStopFunc: func(ctx context.Context, name string) error {
			return nil
		},
		vtpmQuoteFunc: func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
			return map[string]interface{}{"quote": "base64-quote-data", "signature": "base64-sig"}, nil
		},
		vtpmSealFunc: func(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error) {
			return []byte("sealed-data"), nil
		},
		vtpmUnsealFunc: func(ctx context.Context, name string, sealed []byte) ([]byte, error) {
			return []byte("unsealed-data"), nil
		},
		vtpmExtendPCRFunc: func(ctx context.Context, name string, pcr int, data []byte) error {
			return nil
		},
		vtpmReadPCRFunc: func(ctx context.Context, name string, pcr int) ([]byte, error) {
			return []byte("pcr-value"), nil
		},

		// vTPM extended defaults
		vtpmGetFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "hostname": name, "mode": "pre-assigned"}, nil
		},
		vtpmValidateFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "valid": true}, nil
		},
		vtpmExportFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "data": "dGVzdA==", "size": int64(4), "checksum": "abc123"}, nil
		},
		vtpmImportFunc: func(ctx context.Context, data []byte) (interface{}, error) {
			return map[string]interface{}{"id": "imported-bundle", "mode": "pre-assigned"}, nil
		},
		vtpmCreateTemplateFunc: func(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
			return map[string]interface{}{"id": id, "description": description, "ek_algorithm": algorithm}, nil
		},
		vtpmGetTemplateFunc: func(ctx context.Context, id string) (interface{}, error) {
			return map[string]interface{}{"id": id, "description": "test template"}, nil
		},
		vtpmDeleteTemplateFunc: func(ctx context.Context, id string) error {
			return nil
		},
		vtpmListTemplatesFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"templates": []interface{}{}, "total": 0}, nil
		},
		vtpmCloneTemplateFunc: func(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error) {
			return map[string]interface{}{"id": hostname, "cloned_from": templateID}, nil
		},
		vtpmGetBundlePathFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "path": "/vtpm/bundles/" + name}, nil
		},
		vtpmGetTPMSocketPathFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "path": "/vtpm/bundles/" + name + "/swtpm.sock"}, nil
		},
		vtpmGetNVRAMPathFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"id": name, "path": "/vtpm/bundles/" + name + "/OVMF_VARS.fd"}, nil
		},
		vtpmIsRunningFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"bundle_id": name, "running": false}, nil
		},

		// DNS defaults
		dnsAddRecordFunc: func(ctx context.Context, name, recordType, value string, ttl int) error {
			return nil
		},
		dnsDeleteRecordFunc: func(ctx context.Context, name, recordType string) error {
			return nil
		},
		dnsGetRecordFunc: func(ctx context.Context, name, recordType string) (interface{}, error) {
			return map[string]interface{}{"name": name, "type": recordType, "value": "192.168.1.1"}, nil
		},
		dnsListRecordsFunc: func(ctx context.Context, zone string) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"name": "host1", "type": "A", "value": "192.168.1.1"},
				map[string]interface{}{"name": "host2", "type": "A", "value": "192.168.1.2"},
			}, nil
		},
		dnsResolveFunc: func(ctx context.Context, name, recordType string) ([]string, error) {
			return []string{"192.168.1.1"}, nil
		},
		dnsCreateZoneFunc: func(ctx context.Context, zone string) error {
			return nil
		},
		dnsDeleteZoneFunc: func(ctx context.Context, zone string) error {
			return nil
		},
		dnsListZonesFunc: func(ctx context.Context) ([]string, error) {
			return []string{"example.com", "test.local"}, nil
		},

		// Device defaults
		deviceRegisterFunc: func(ctx context.Context, name, deviceType string, publicKey []byte) (interface{}, error) {
			return map[string]interface{}{"id": "device-123", "name": name, "type": deviceType}, nil
		},
		deviceGetFunc: func(ctx context.Context, deviceID string) (interface{}, error) {
			return map[string]interface{}{"id": deviceID, "name": "test-device", "status": "active"}, nil
		},
		deviceListFunc: func(ctx context.Context, filter map[string]string) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"id": "device-1", "name": "Device 1"},
				map[string]interface{}{"id": "device-2", "name": "Device 2"},
			}, nil
		},
		deviceDeleteFunc: func(ctx context.Context, deviceID string) error {
			return nil
		},
		deviceUpdateFunc: func(ctx context.Context, deviceID string, updates map[string]interface{}) error {
			return nil
		},
		deviceAttestFunc: func(ctx context.Context, deviceID string, evidence []byte) (interface{}, error) {
			return map[string]interface{}{"verified": true, "device_id": deviceID}, nil
		},
		deviceProvisionFunc: func(ctx context.Context, deviceID, profile string) error {
			return nil
		},

		// SDN defaults
		sdnGetPortStateFunc: func(ctx context.Context, bridgeName, portName string) (interface{}, error) {
			return map[string]interface{}{"bridge": bridgeName, "port": portName, "state": "up"}, nil
		},
		sdnSetPortStateFunc: func(ctx context.Context, bridgeName, portName, state string) error {
			return nil
		},
		sdnListBridgesFunc: func(ctx context.Context) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"name": "br0", "ports": 4},
				map[string]interface{}{"name": "br1", "ports": 2},
			}, nil
		},
		sdnCreateBridgeFunc: func(ctx context.Context, bridgeName string) error {
			return nil
		},
		sdnDeleteBridgeFunc: func(ctx context.Context, bridgeName string) error {
			return nil
		},
		sdnAddPortFunc: func(ctx context.Context, bridgeName, portName, portType string) error {
			return nil
		},
		sdnDeletePortFunc: func(ctx context.Context, bridgeName, portName string) error {
			return nil
		},
		sdnApplyPolicyFunc: func(ctx context.Context, policyID, bridgeName string) error {
			return nil
		},
		sdnGetPolicyFunc: func(ctx context.Context, policyID string) (interface{}, error) {
			return map[string]interface{}{"id": policyID, "name": "test-policy"}, nil
		},
		sdnListPoliciesFunc: func(ctx context.Context) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"id": "policy-1", "name": "Policy 1"},
			}, nil
		},
		sdnAddFlowFunc: func(ctx context.Context, bridgeName string, flow map[string]interface{}) error {
			return nil
		},
		sdnDeleteFlowFunc: func(ctx context.Context, bridgeName, flowID string) error {
			return nil
		},
		sdnListFlowsFunc: func(ctx context.Context, bridgeName string) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"id": "flow-1", "priority": 100},
			}, nil
		},
		sdnFlushFlowsFunc: func(ctx context.Context, bridgeName string) error {
			return nil
		},
		sdnCreateVLANFunc: func(ctx context.Context, bridgeName string, vlanID int, name string) error {
			return nil
		},
		sdnDeleteVLANFunc: func(ctx context.Context, bridgeName string, vlanID int) error {
			return nil
		},
		sdnListVLANsFunc: func(ctx context.Context, bridgeName string) ([]interface{}, error) {
			return []interface{}{
				map[string]interface{}{"id": 100, "name": "vlan-100"},
			}, nil
		},
		sdnAuthenticatePortFunc: func(ctx context.Context, bridgeName, portName string, credentials map[string]string) error {
			return nil
		},
		sdnRevokePortAuthFunc: func(ctx context.Context, bridgeName, portName string) error {
			return nil
		},
		sdnGetPortStatsFunc: func(ctx context.Context, bridgeName, portName string) (interface{}, error) {
			return map[string]interface{}{"rx_packets": 1000, "tx_packets": 500}, nil
		},
		sdnGetFlowStatsFunc: func(ctx context.Context, bridgeName string) (interface{}, error) {
			return map[string]interface{}{"flows": 10, "packets": 5000}, nil
		},

		// Health defaults
		healthFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"status": "healthy"}, nil
		},
		livenessFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"alive": true}, nil
		},
		readinessFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"ready": true}, nil
		},

		// Daemon management defaults
		daemonStatusFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"status": "ready", "version": "1.0.0"}, nil
		},
		daemonVersionFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"version": "1.0.0", "build_time": "2025-01-01T00:00:00Z"}, nil
		},
		daemonListServicesFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"services": []interface{}{}, "count": 0}, nil
		},
		daemonGetServiceFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"name": name, "status": "running"}, nil
		},
		daemonStartServiceFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"service": name, "action": "start", "success": true}, nil
		},
		daemonStopServiceFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"service": name, "action": "stop", "success": true}, nil
		},
		daemonRestartServiceFunc: func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"service": name, "action": "restart", "success": true}, nil
		},
		daemonListProtocolsFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{"protocols": []interface{}{}}, nil
		},

		// CA defaults
		caInfoFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"is_initialized":    true,
				"common_name":       "Test CA",
				"default_algorithm": "ECDSA",
				"default_validity":  365,
			}, nil
		},
		caIssueFunc: func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
			return map[string]interface{}{
				"serial":        "abc123",
				"common_name":   req.CommonName,
				"status":        "VALID",
				"not_before":    1704067200,
				"not_after":     1735689600,
				"key_algorithm": req.Algorithm,
			}, nil
		},
		caGetFunc: func(ctx context.Context, serial string, includePEM bool) (interface{}, error) {
			result := map[string]interface{}{
				"serial":        serial,
				"common_name":   "test.example.com",
				"status":        "VALID",
				"not_before":    1704067200,
				"not_after":     1735689600,
				"key_algorithm": "ECDSA",
			}
			if includePEM {
				result["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
			}
			return result, nil
		},
		caListFunc: func(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
			return map[string]interface{}{
				"certificates": []map[string]interface{}{
					{"serial": "abc123", "common_name": "test1.example.com", "status": "VALID"},
					{"serial": "def456", "common_name": "test2.example.com", "status": "VALID"},
				},
				"total_count": 2,
				"has_more":    false,
			}, nil
		},
		caRevokeFunc: func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
			return map[string]interface{}{
				"serial":     serial,
				"status":     "REVOKED",
				"revoked_at": 1704067200,
				"reason":     reason,
			}, nil
		},
		caRenewFunc: func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
			return map[string]interface{}{
				"old_serial":  serial,
				"serial":      "new123",
				"common_name": "test.example.com",
				"status":      "VALID",
				"not_before":  1704067200,
				"not_after":   1735689600,
			}, nil
		},
		caVerifyFunc: func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
			return map[string]interface{}{
				"valid":  true,
				"status": "VALID",
				"chain": []map[string]interface{}{
					{"serial": "abc123", "common_name": "test.example.com"},
					{"serial": "root123", "common_name": "Root CA"},
				},
			}, nil
		},
		caCRLFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"last_update":   1704067200,
				"next_update":   1704153600,
				"revoked_count": 1,
				"revoked_certs": []map[string]interface{}{
					{"serial": "revoked123", "revocation_time": 1704067200, "reason": 1},
				},
			}, nil
		},
		caBundleFunc: func(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
			return map[string]interface{}{
				"bundle": []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"),
				"certificates": []map[string]interface{}{
					{"serial": "root123", "common_name": "Root CA"},
					{"serial": "int123", "common_name": "Intermediate CA"},
				},
				"cert_count": 2,
			}, nil
		},

		// IAM defaults
		iamCreateUserFunc: func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
			return map[string]interface{}{
				"id":        "user-123",
				"tenant_id": req.TenantID,
				"email":     req.Email,
				"name":      req.Name,
				"roles":     req.Roles,
			}, nil
		},
		iamDeleteUserFunc: func(ctx context.Context, tenantID, userID string) error {
			return nil
		},
		iamGetUserFunc: func(ctx context.Context, tenantID, userID string) (interface{}, error) {
			return map[string]interface{}{
				"id":        userID,
				"tenant_id": tenantID,
				"email":     "user@example.com",
				"name":      "Test User",
			}, nil
		},
		iamListUsersFunc: func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
			return map[string]interface{}{
				"users": []map[string]interface{}{
					{"id": "user-1", "email": "user1@example.com"},
					{"id": "user-2", "email": "user2@example.com"},
				},
				"total":  2,
				"limit":  limit,
				"offset": offset,
			}, nil
		},
		iamCreateRoleFunc: func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
			return map[string]interface{}{
				"id":          req.ID,
				"tenant_id":   req.TenantID,
				"name":        req.Name,
				"description": req.Description,
				"permissions": req.Permissions,
			}, nil
		},
		iamDeleteRoleFunc: func(ctx context.Context, tenantID, roleID string) error {
			return nil
		},
		iamGetRoleFunc: func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
			return map[string]interface{}{
				"id":          roleID,
				"tenant_id":   tenantID,
				"name":        "Test Role",
				"description": "A test role",
				"permissions": []string{"read", "write"},
			}, nil
		},
		iamListRolesFunc: func(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
			return map[string]interface{}{
				"roles": []map[string]interface{}{
					{"id": "role-1", "name": "Admin"},
					{"id": "role-2", "name": "User"},
				},
				"total":  2,
				"limit":  limit,
				"offset": offset,
			}, nil
		},
		iamAssignRoleFunc: func(ctx context.Context, tenantID, userID, role string) error {
			return nil
		},
		iamRevokeRoleFunc: func(ctx context.Context, tenantID, userID, role string) error {
			return nil
		},
		iamCheckPermissionFunc: func(ctx context.Context, tenantID, userID, resource, action string) (bool, error) {
			return true, nil
		},
		iamAuthenticateFunc: func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
			return map[string]interface{}{
				"authenticated": true,
				"user": map[string]interface{}{
					"id":        "user-123",
					"tenant_id": req.TenantID,
					"email":     req.Email,
				},
				"tenant_id": req.TenantID,
			}, nil
		},

		// KMS defaults
		kmsCreateKeyFunc: func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
			return map[string]interface{}{
				"id":          "key-123",
				"name":        req.Name,
				"description": req.Description,
				"algorithm":   req.Algorithm,
				"key_usage":   req.KeyUsage,
				"status":      "active",
			}, nil
		},
		kmsDeleteKeyFunc: func(ctx context.Context, keyID string) error {
			return nil
		},
		kmsGetKeyFunc: func(ctx context.Context, keyID string, version uint64) (interface{}, error) {
			return map[string]interface{}{
				"id":        keyID,
				"name":      "test-key",
				"algorithm": "RSA-2048",
				"status":    "active",
			}, nil
		},
		kmsListKeysFunc: func(ctx context.Context, limit, offset int) (interface{}, error) {
			return map[string]interface{}{
				"keys": []map[string]interface{}{
					{"id": "key-1", "name": "Key 1", "algorithm": "RSA-2048"},
					{"id": "key-2", "name": "Key 2", "algorithm": "ECDSA-P256"},
				},
				"total":  2,
				"limit":  limit,
				"offset": offset,
			}, nil
		},
		kmsRotateKeyFunc: func(ctx context.Context, keyID string) (interface{}, error) {
			return map[string]interface{}{
				"id":          keyID,
				"new_version": 2,
				"status":      "rotated",
			}, nil
		},
		kmsEncryptFunc: func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
			return map[string]interface{}{
				"key_id":     req.KeyID,
				"ciphertext": []byte("encrypted-data"),
			}, nil
		},
		kmsDecryptFunc: func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
			return map[string]interface{}{
				"key_id":    req.KeyID,
				"plaintext": []byte("decrypted-data"),
			}, nil
		},
		kmsSignFunc: func(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
			return map[string]interface{}{
				"key_id":    req.KeyID,
				"signature": []byte("signature-data"),
			}, nil
		},
		kmsVerifyFunc: func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
			return map[string]interface{}{
				"key_id": req.KeyID,
				"valid":  true,
			}, nil
		},
		kmsGenerateRandomFunc: func(ctx context.Context, numBytes int) ([]byte, error) {
			result := make([]byte, numBytes)
			for i := range result {
				result[i] = byte(i % 256)
			}
			return result, nil
		},

		// IDevID/IAK defaults
		idevidGenerateFunc: func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			return map[string]interface{}{
				"handle":    "0x81010002",
				"algorithm": req.Algorithm,
				"status":    "created",
			}, nil
		},
		idevidInfoFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"handle":           "0x81010002",
				"algorithm":        "ECC",
				"has_certificate":  true,
				"certificate_hash": "sha256:abc123",
			}, nil
		},
		idevidDeleteFunc: func(ctx context.Context) error {
			return nil
		},
		idevidCSRFunc: func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			return map[string]interface{}{
				"csr_pem":     "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
				"common_name": req.CommonName,
			}, nil
		},
		idevidInstallCertFunc: func(ctx context.Context, certificatePEM string) (interface{}, error) {
			return map[string]interface{}{
				"installed":        true,
				"certificate_hash": "sha256:def456",
			}, nil
		},
		idevidGetCertFunc: func(ctx context.Context, includePEM bool) (interface{}, error) {
			result := map[string]interface{}{
				"serial":      "abc123",
				"common_name": "device.example.com",
				"not_before":  1704067200,
				"not_after":   1735689600,
			}
			if includePEM {
				result["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
			}
			return result, nil
		},
		idevidDeleteCertFunc: func(ctx context.Context) error {
			return nil
		},
		idevidExistsFunc: func(ctx context.Context) (bool, error) {
			return true, nil
		},
		iakGenerateFunc: func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			return map[string]interface{}{
				"handle":    "0x81010003",
				"algorithm": req.Algorithm,
				"status":    "created",
			}, nil
		},
		iakInfoFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"handle":           "0x81010003",
				"algorithm":        "ECC",
				"has_certificate":  true,
				"certificate_hash": "sha256:iak123",
			}, nil
		},
		iakDeleteFunc: func(ctx context.Context) error {
			return nil
		},
		iakCSRFunc: func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			return map[string]interface{}{
				"csr_pem":     "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
				"common_name": req.CommonName,
			}, nil
		},
		iakInstallCertFunc: func(ctx context.Context, certificatePEM string) (interface{}, error) {
			return map[string]interface{}{
				"installed":        true,
				"certificate_hash": "sha256:iak456",
			}, nil
		},
		iakGetCertFunc: func(ctx context.Context, includePEM bool) (interface{}, error) {
			result := map[string]interface{}{
				"serial":      "iak123",
				"common_name": "device-iak.example.com",
				"not_before":  1704067200,
				"not_after":   1735689600,
			}
			if includePEM {
				result["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
			}
			return result, nil
		},
		iakDeleteCertFunc: func(ctx context.Context) error {
			return nil
		},
		iakExistsFunc: func(ctx context.Context) (bool, error) {
			return true, nil
		},
		deviceAttributesFunc: func(ctx context.Context) (interface{}, error) {
			return map[string]interface{}{
				"manufacturer":       "Test TPM Manufacturer",
				"model":              "vTPM 2.0",
				"version":            "2.0",
				"firmware_version":   "1.2.3",
				"platform_serial":    "SERIAL123",
				"endorsement_key_id": "EK123",
			}, nil
		},
		activateCredentialFunc: func(ctx context.Context, credentialBlob []byte, secret []byte) ([]byte, error) {
			return []byte("decrypted-credential"), nil
		},
	}
}

// vTPM implementations
func (m *mockServiceProvider) VTPMCreate(ctx context.Context, name, algorithm string) (interface{}, error) {
	if m.vtpmCreateFunc != nil {
		return m.vtpmCreateFunc(ctx, name, algorithm)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMDelete(ctx context.Context, name string) error {
	if m.vtpmDeleteFunc != nil {
		return m.vtpmDeleteFunc(ctx, name)
	}
	return nil
}

func (m *mockServiceProvider) VTPMList(ctx context.Context) ([]interface{}, error) {
	if m.vtpmListFunc != nil {
		return m.vtpmListFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMStart(ctx context.Context, name string) error {
	if m.vtpmStartFunc != nil {
		return m.vtpmStartFunc(ctx, name)
	}
	return nil
}

func (m *mockServiceProvider) VTPMStop(ctx context.Context, name string) error {
	if m.vtpmStopFunc != nil {
		return m.vtpmStopFunc(ctx, name)
	}
	return nil
}

func (m *mockServiceProvider) VTPMQuote(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
	if m.vtpmQuoteFunc != nil {
		return m.vtpmQuoteFunc(ctx, name, nonce, pcrs)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMSeal(ctx context.Context, name string, data []byte, pcrs []int) ([]byte, error) {
	if m.vtpmSealFunc != nil {
		return m.vtpmSealFunc(ctx, name, data, pcrs)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMUnseal(ctx context.Context, name string, sealed []byte) ([]byte, error) {
	if m.vtpmUnsealFunc != nil {
		return m.vtpmUnsealFunc(ctx, name, sealed)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMExtendPCR(ctx context.Context, name string, pcr int, data []byte) error {
	if m.vtpmExtendPCRFunc != nil {
		return m.vtpmExtendPCRFunc(ctx, name, pcr, data)
	}
	return nil
}

func (m *mockServiceProvider) VTPMReadPCR(ctx context.Context, name string, pcr int) ([]byte, error) {
	if m.vtpmReadPCRFunc != nil {
		return m.vtpmReadPCRFunc(ctx, name, pcr)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMGet(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmGetFunc != nil {
		return m.vtpmGetFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMValidate(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmValidateFunc != nil {
		return m.vtpmValidateFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMExport(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmExportFunc != nil {
		return m.vtpmExportFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMImport(ctx context.Context, data []byte) (interface{}, error) {
	if m.vtpmImportFunc != nil {
		return m.vtpmImportFunc(ctx, data)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMCreateTemplate(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error) {
	if m.vtpmCreateTemplateFunc != nil {
		return m.vtpmCreateTemplateFunc(ctx, id, description, algorithm, secureBoot)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMGetTemplate(ctx context.Context, id string) (interface{}, error) {
	if m.vtpmGetTemplateFunc != nil {
		return m.vtpmGetTemplateFunc(ctx, id)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMDeleteTemplate(ctx context.Context, id string) error {
	if m.vtpmDeleteTemplateFunc != nil {
		return m.vtpmDeleteTemplateFunc(ctx, id)
	}
	return nil
}

func (m *mockServiceProvider) VTPMListTemplates(ctx context.Context) (interface{}, error) {
	if m.vtpmListTemplatesFunc != nil {
		return m.vtpmListTemplatesFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMCloneTemplate(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error) {
	if m.vtpmCloneTemplateFunc != nil {
		return m.vtpmCloneTemplateFunc(ctx, templateID, hostname, labels)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmGetBundlePathFunc != nil {
		return m.vtpmGetBundlePathFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMGetTPMSocketPath(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmGetTPMSocketPathFunc != nil {
		return m.vtpmGetTPMSocketPathFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMGetNVRAMPath(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmGetNVRAMPathFunc != nil {
		return m.vtpmGetNVRAMPathFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) VTPMIsRunning(ctx context.Context, name string) (interface{}, error) {
	if m.vtpmIsRunningFunc != nil {
		return m.vtpmIsRunningFunc(ctx, name)
	}
	return nil, nil
}

// DNS implementations
func (m *mockServiceProvider) DNSAddRecord(ctx context.Context, name, recordType, value string, ttl int) error {
	if m.dnsAddRecordFunc != nil {
		return m.dnsAddRecordFunc(ctx, name, recordType, value, ttl)
	}
	return nil
}

func (m *mockServiceProvider) DNSDeleteRecord(ctx context.Context, name, recordType string) error {
	if m.dnsDeleteRecordFunc != nil {
		return m.dnsDeleteRecordFunc(ctx, name, recordType)
	}
	return nil
}

func (m *mockServiceProvider) DNSGetRecord(ctx context.Context, name, recordType string) (interface{}, error) {
	if m.dnsGetRecordFunc != nil {
		return m.dnsGetRecordFunc(ctx, name, recordType)
	}
	return nil, nil
}

func (m *mockServiceProvider) DNSListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	if m.dnsListRecordsFunc != nil {
		return m.dnsListRecordsFunc(ctx, zone)
	}
	return nil, nil
}

func (m *mockServiceProvider) DNSResolve(ctx context.Context, name, recordType string) ([]string, error) {
	if m.dnsResolveFunc != nil {
		return m.dnsResolveFunc(ctx, name, recordType)
	}
	return nil, nil
}

func (m *mockServiceProvider) DNSCreateZone(ctx context.Context, zone string) error {
	if m.dnsCreateZoneFunc != nil {
		return m.dnsCreateZoneFunc(ctx, zone)
	}
	return nil
}

func (m *mockServiceProvider) DNSDeleteZone(ctx context.Context, zone string) error {
	if m.dnsDeleteZoneFunc != nil {
		return m.dnsDeleteZoneFunc(ctx, zone)
	}
	return nil
}

func (m *mockServiceProvider) DNSListZones(ctx context.Context) ([]string, error) {
	if m.dnsListZonesFunc != nil {
		return m.dnsListZonesFunc(ctx)
	}
	return nil, nil
}

// Device implementations
func (m *mockServiceProvider) DeviceRegister(ctx context.Context, name, deviceType string, publicKey []byte) (interface{}, error) {
	if m.deviceRegisterFunc != nil {
		return m.deviceRegisterFunc(ctx, name, deviceType, publicKey)
	}
	return nil, nil
}

func (m *mockServiceProvider) DeviceGet(ctx context.Context, deviceID string) (interface{}, error) {
	if m.deviceGetFunc != nil {
		return m.deviceGetFunc(ctx, deviceID)
	}
	return nil, nil
}

func (m *mockServiceProvider) DeviceList(ctx context.Context, filter map[string]string) ([]interface{}, error) {
	if m.deviceListFunc != nil {
		return m.deviceListFunc(ctx, filter)
	}
	return nil, nil
}

func (m *mockServiceProvider) DeviceDelete(ctx context.Context, deviceID string) error {
	if m.deviceDeleteFunc != nil {
		return m.deviceDeleteFunc(ctx, deviceID)
	}
	return nil
}

func (m *mockServiceProvider) DeviceUpdate(ctx context.Context, deviceID string, updates map[string]interface{}) error {
	if m.deviceUpdateFunc != nil {
		return m.deviceUpdateFunc(ctx, deviceID, updates)
	}
	return nil
}

func (m *mockServiceProvider) DeviceAttest(ctx context.Context, deviceID string, evidence []byte) (interface{}, error) {
	if m.deviceAttestFunc != nil {
		return m.deviceAttestFunc(ctx, deviceID, evidence)
	}
	return nil, nil
}

func (m *mockServiceProvider) DeviceRecordAttestCert(ctx context.Context, deviceID string, reissue bool) (interface{}, error) {
	if m.deviceRecordAttestCertFunc != nil {
		return m.deviceRecordAttestCertFunc(ctx, deviceID, reissue)
	}
	return nil, nil
}

func (m *mockServiceProvider) DeviceProvision(ctx context.Context, deviceID, profile string) error {
	if m.deviceProvisionFunc != nil {
		return m.deviceProvisionFunc(ctx, deviceID, profile)
	}
	return nil
}

// SDN implementations
func (m *mockServiceProvider) SDNGetPortState(ctx context.Context, bridgeName, portName string) (interface{}, error) {
	if m.sdnGetPortStateFunc != nil {
		return m.sdnGetPortStateFunc(ctx, bridgeName, portName)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNSetPortState(ctx context.Context, bridgeName, portName, state string) error {
	if m.sdnSetPortStateFunc != nil {
		return m.sdnSetPortStateFunc(ctx, bridgeName, portName, state)
	}
	return nil
}

func (m *mockServiceProvider) SDNListBridges(ctx context.Context) ([]interface{}, error) {
	if m.sdnListBridgesFunc != nil {
		return m.sdnListBridgesFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNCreateBridge(ctx context.Context, bridgeName string) error {
	if m.sdnCreateBridgeFunc != nil {
		return m.sdnCreateBridgeFunc(ctx, bridgeName)
	}
	return nil
}

func (m *mockServiceProvider) SDNDeleteBridge(ctx context.Context, bridgeName string) error {
	if m.sdnDeleteBridgeFunc != nil {
		return m.sdnDeleteBridgeFunc(ctx, bridgeName)
	}
	return nil
}

func (m *mockServiceProvider) SDNAddPort(ctx context.Context, bridgeName, portName, portType string) error {
	if m.sdnAddPortFunc != nil {
		return m.sdnAddPortFunc(ctx, bridgeName, portName, portType)
	}
	return nil
}

func (m *mockServiceProvider) SDNDeletePort(ctx context.Context, bridgeName, portName string) error {
	if m.sdnDeletePortFunc != nil {
		return m.sdnDeletePortFunc(ctx, bridgeName, portName)
	}
	return nil
}

func (m *mockServiceProvider) SDNApplyPolicy(ctx context.Context, policyID, bridgeName string) error {
	if m.sdnApplyPolicyFunc != nil {
		return m.sdnApplyPolicyFunc(ctx, policyID, bridgeName)
	}
	return nil
}

func (m *mockServiceProvider) SDNGetPolicy(ctx context.Context, policyID string) (interface{}, error) {
	if m.sdnGetPolicyFunc != nil {
		return m.sdnGetPolicyFunc(ctx, policyID)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNListPolicies(ctx context.Context) ([]interface{}, error) {
	if m.sdnListPoliciesFunc != nil {
		return m.sdnListPoliciesFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNAddFlow(ctx context.Context, bridgeName string, flow map[string]interface{}) error {
	if m.sdnAddFlowFunc != nil {
		return m.sdnAddFlowFunc(ctx, bridgeName, flow)
	}
	return nil
}

func (m *mockServiceProvider) SDNDeleteFlow(ctx context.Context, bridgeName, flowID string) error {
	if m.sdnDeleteFlowFunc != nil {
		return m.sdnDeleteFlowFunc(ctx, bridgeName, flowID)
	}
	return nil
}

func (m *mockServiceProvider) SDNListFlows(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if m.sdnListFlowsFunc != nil {
		return m.sdnListFlowsFunc(ctx, bridgeName)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNFlushFlows(ctx context.Context, bridgeName string) error {
	if m.sdnFlushFlowsFunc != nil {
		return m.sdnFlushFlowsFunc(ctx, bridgeName)
	}
	return nil
}

func (m *mockServiceProvider) SDNCreateVLAN(ctx context.Context, bridgeName string, vlanID int, name string) error {
	if m.sdnCreateVLANFunc != nil {
		return m.sdnCreateVLANFunc(ctx, bridgeName, vlanID, name)
	}
	return nil
}

func (m *mockServiceProvider) SDNDeleteVLAN(ctx context.Context, bridgeName string, vlanID int) error {
	if m.sdnDeleteVLANFunc != nil {
		return m.sdnDeleteVLANFunc(ctx, bridgeName, vlanID)
	}
	return nil
}

func (m *mockServiceProvider) SDNListVLANs(ctx context.Context, bridgeName string) ([]interface{}, error) {
	if m.sdnListVLANsFunc != nil {
		return m.sdnListVLANsFunc(ctx, bridgeName)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNAuthenticatePort(ctx context.Context, bridgeName, portName string, credentials map[string]string) error {
	if m.sdnAuthenticatePortFunc != nil {
		return m.sdnAuthenticatePortFunc(ctx, bridgeName, portName, credentials)
	}
	return nil
}

func (m *mockServiceProvider) SDNRevokePortAuth(ctx context.Context, bridgeName, portName string) error {
	if m.sdnRevokePortAuthFunc != nil {
		return m.sdnRevokePortAuthFunc(ctx, bridgeName, portName)
	}
	return nil
}

func (m *mockServiceProvider) SDNGetPortStats(ctx context.Context, bridgeName, portName string) (interface{}, error) {
	if m.sdnGetPortStatsFunc != nil {
		return m.sdnGetPortStatsFunc(ctx, bridgeName, portName)
	}
	return nil, nil
}

func (m *mockServiceProvider) SDNGetFlowStats(ctx context.Context, bridgeName string) (interface{}, error) {
	if m.sdnGetFlowStatsFunc != nil {
		return m.sdnGetFlowStatsFunc(ctx, bridgeName)
	}
	return nil, nil
}

// Health implementations
func (m *mockServiceProvider) Health(ctx context.Context) (interface{}, error) {
	if m.healthFunc != nil {
		return m.healthFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) Liveness(ctx context.Context) (interface{}, error) {
	if m.livenessFunc != nil {
		return m.livenessFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) Readiness(ctx context.Context) (interface{}, error) {
	if m.readinessFunc != nil {
		return m.readinessFunc(ctx)
	}
	return nil, nil
}

// Daemon management implementations
func (m *mockServiceProvider) DaemonStatus(ctx context.Context) (interface{}, error) {
	if m.daemonStatusFunc != nil {
		return m.daemonStatusFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonVersion(ctx context.Context) (interface{}, error) {
	if m.daemonVersionFunc != nil {
		return m.daemonVersionFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonListServices(ctx context.Context) (interface{}, error) {
	if m.daemonListServicesFunc != nil {
		return m.daemonListServicesFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonGetService(ctx context.Context, name string) (interface{}, error) {
	if m.daemonGetServiceFunc != nil {
		return m.daemonGetServiceFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonStartService(ctx context.Context, name string) (interface{}, error) {
	if m.daemonStartServiceFunc != nil {
		return m.daemonStartServiceFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonStopService(ctx context.Context, name string) (interface{}, error) {
	if m.daemonStopServiceFunc != nil {
		return m.daemonStopServiceFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonRestartService(ctx context.Context, name string) (interface{}, error) {
	if m.daemonRestartServiceFunc != nil {
		return m.daemonRestartServiceFunc(ctx, name)
	}
	return nil, nil
}

func (m *mockServiceProvider) DaemonListProtocols(ctx context.Context) (interface{}, error) {
	if m.daemonListProtocolsFunc != nil {
		return m.daemonListProtocolsFunc(ctx)
	}
	return nil, nil
}

// CA implementations
func (m *mockServiceProvider) CAInfo(ctx context.Context) (interface{}, error) {
	if m.caInfoFunc != nil {
		return m.caInfoFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) CAIssue(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
	if m.caIssueFunc != nil {
		return m.caIssueFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) CAGet(ctx context.Context, serial string, includePEM bool) (interface{}, error) {
	if m.caGetFunc != nil {
		return m.caGetFunc(ctx, serial, includePEM)
	}
	return nil, nil
}

func (m *mockServiceProvider) CAList(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
	if m.caListFunc != nil {
		return m.caListFunc(ctx, limit, cursor, status)
	}
	return nil, nil
}

func (m *mockServiceProvider) CARevoke(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
	if m.caRevokeFunc != nil {
		return m.caRevokeFunc(ctx, serial, reason, deleteKeys)
	}
	return nil, nil
}

func (m *mockServiceProvider) CARenew(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
	if m.caRenewFunc != nil {
		return m.caRenewFunc(ctx, serial, extendDays, preserveAttrs)
	}
	return nil, nil
}

func (m *mockServiceProvider) CAVerify(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
	if m.caVerifyFunc != nil {
		return m.caVerifyFunc(ctx, certificatePEM, certificateDER, checkRevoked)
	}
	return nil, nil
}

func (m *mockServiceProvider) CACRL(ctx context.Context) (interface{}, error) {
	if m.caCRLFunc != nil {
		return m.caCRLFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) CABundle(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
	if m.caBundleFunc != nil {
		return m.caBundleFunc(ctx, storeType, algorithm)
	}
	return nil, nil
}

// IAM implementations
func (m *mockServiceProvider) IAMCreateUser(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
	if m.iamCreateUserFunc != nil {
		return m.iamCreateUserFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMDeleteUser(ctx context.Context, tenantID, userID string) error {
	if m.iamDeleteUserFunc != nil {
		return m.iamDeleteUserFunc(ctx, tenantID, userID)
	}
	return nil
}

func (m *mockServiceProvider) IAMGetUser(ctx context.Context, tenantID, userID string) (interface{}, error) {
	if m.iamGetUserFunc != nil {
		return m.iamGetUserFunc(ctx, tenantID, userID)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMListUsers(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
	if m.iamListUsersFunc != nil {
		return m.iamListUsersFunc(ctx, tenantID, limit, offset)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMCreateRole(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
	if m.iamCreateRoleFunc != nil {
		return m.iamCreateRoleFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMDeleteRole(ctx context.Context, tenantID, roleID string) error {
	if m.iamDeleteRoleFunc != nil {
		return m.iamDeleteRoleFunc(ctx, tenantID, roleID)
	}
	return nil
}

func (m *mockServiceProvider) IAMGetRole(ctx context.Context, tenantID, roleID string) (interface{}, error) {
	if m.iamGetRoleFunc != nil {
		return m.iamGetRoleFunc(ctx, tenantID, roleID)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMListRoles(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
	if m.iamListRolesFunc != nil {
		return m.iamListRolesFunc(ctx, tenantID, limit, offset)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAMAssignRole(ctx context.Context, tenantID, userID, role string) error {
	if m.iamAssignRoleFunc != nil {
		return m.iamAssignRoleFunc(ctx, tenantID, userID, role)
	}
	return nil
}

func (m *mockServiceProvider) IAMRevokeRole(ctx context.Context, tenantID, userID, role string) error {
	if m.iamRevokeRoleFunc != nil {
		return m.iamRevokeRoleFunc(ctx, tenantID, userID, role)
	}
	return nil
}

func (m *mockServiceProvider) IAMCheckPermission(ctx context.Context, tenantID, userID, resource, action string) (bool, error) {
	if m.iamCheckPermissionFunc != nil {
		return m.iamCheckPermissionFunc(ctx, tenantID, userID, resource, action)
	}
	return false, nil
}

func (m *mockServiceProvider) IAMAuthenticate(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
	if m.iamAuthenticateFunc != nil {
		return m.iamAuthenticateFunc(ctx, req)
	}
	return nil, nil
}

// IAM Group implementations
func (m *mockServiceProvider) IAMCreateGroup(ctx context.Context, req *IAMCreateGroupRequest) (interface{}, error) {
	if m.iamCreateGroupFunc != nil {
		return m.iamCreateGroupFunc(ctx, req)
	}
	return map[string]interface{}{
		"id":          req.ID,
		"tenant_id":   req.TenantID,
		"name":        req.Name,
		"description": req.Description,
	}, nil
}

func (m *mockServiceProvider) IAMDeleteGroup(ctx context.Context, tenantID, groupID string) error {
	if m.iamDeleteGroupFunc != nil {
		return m.iamDeleteGroupFunc(ctx, tenantID, groupID)
	}
	return nil
}

func (m *mockServiceProvider) IAMGetGroup(ctx context.Context, tenantID, groupID string) (interface{}, error) {
	if m.iamGetGroupFunc != nil {
		return m.iamGetGroupFunc(ctx, tenantID, groupID)
	}
	return map[string]interface{}{
		"id":        groupID,
		"tenant_id": tenantID,
		"name":      "test-group",
	}, nil
}

func (m *mockServiceProvider) IAMListGroups(ctx context.Context, tenantID string, limit, offset int) (interface{}, error) {
	if m.iamListGroupsFunc != nil {
		return m.iamListGroupsFunc(ctx, tenantID, limit, offset)
	}
	return map[string]interface{}{
		"groups": []map[string]interface{}{
			{"id": "group-1", "tenant_id": tenantID, "name": "group-1"},
		},
		"total":  1,
		"limit":  limit,
		"offset": offset,
	}, nil
}

func (m *mockServiceProvider) IAMAddGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.iamAddGroupMemberFunc != nil {
		return m.iamAddGroupMemberFunc(ctx, tenantID, groupID, userID)
	}
	return nil
}

func (m *mockServiceProvider) IAMRemoveGroupMember(ctx context.Context, tenantID, groupID, userID string) error {
	if m.iamRemoveGroupMemberFunc != nil {
		return m.iamRemoveGroupMemberFunc(ctx, tenantID, groupID, userID)
	}
	return nil
}

// IAM Tenant implementations
func (m *mockServiceProvider) IAMCreateTenant(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error) {
	if m.iamCreateTenantFunc != nil {
		return m.iamCreateTenantFunc(ctx, req)
	}
	return map[string]interface{}{
		"id":   req.ID,
		"name": req.Name,
	}, nil
}

func (m *mockServiceProvider) IAMDeleteTenant(ctx context.Context, tenantID string) error {
	if m.iamDeleteTenantFunc != nil {
		return m.iamDeleteTenantFunc(ctx, tenantID)
	}
	return nil
}

func (m *mockServiceProvider) IAMGetTenant(ctx context.Context, tenantID string) (interface{}, error) {
	if m.iamGetTenantFunc != nil {
		return m.iamGetTenantFunc(ctx, tenantID)
	}
	return map[string]interface{}{
		"id":   tenantID,
		"name": "test-tenant",
	}, nil
}

func (m *mockServiceProvider) IAMListTenants(ctx context.Context, limit, offset int) (interface{}, error) {
	if m.iamListTenantsFunc != nil {
		return m.iamListTenantsFunc(ctx, limit, offset)
	}
	return map[string]interface{}{
		"tenants": []map[string]interface{}{
			{"id": "tenant-1", "name": "tenant-1"},
		},
		"total":  1,
		"limit":  limit,
		"offset": offset,
	}, nil
}

// IAM Token implementations
func (m *mockServiceProvider) IAMCreateToken(ctx context.Context, req *IAMCreateTokenRequest) (interface{}, error) {
	if m.iamCreateTokenFunc != nil {
		return m.iamCreateTokenFunc(ctx, req)
	}
	return map[string]interface{}{
		"token_id":   "test-token-id",
		"tenant_id":  req.TenantID,
		"user_id":    req.UserID,
		"expires_at": "2025-12-31T23:59:59Z",
	}, nil
}

func (m *mockServiceProvider) IAMRevokeToken(ctx context.Context, tokenID string) error {
	if m.iamRevokeTokenFunc != nil {
		return m.iamRevokeTokenFunc(ctx, tokenID)
	}
	return nil
}

func (m *mockServiceProvider) IAMVerifyToken(ctx context.Context, token string) (interface{}, error) {
	if m.iamVerifyTokenFunc != nil {
		return m.iamVerifyTokenFunc(ctx, token)
	}
	return map[string]interface{}{
		"valid":       true,
		"verified_at": "2025-01-05T12:00:00Z",
	}, nil
}

// KMS implementations
func (m *mockServiceProvider) KMSCreateKey(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
	if m.kmsCreateKeyFunc != nil {
		return m.kmsCreateKeyFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSDeleteKey(ctx context.Context, keyID string) error {
	if m.kmsDeleteKeyFunc != nil {
		return m.kmsDeleteKeyFunc(ctx, keyID)
	}
	return nil
}

func (m *mockServiceProvider) KMSGetKey(ctx context.Context, keyID string, version uint64) (interface{}, error) {
	if m.kmsGetKeyFunc != nil {
		return m.kmsGetKeyFunc(ctx, keyID, version)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSExportPublicKey(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error) {
	if m.kmsExportPublicKeyFunc != nil {
		return m.kmsExportPublicKeyFunc(ctx, req)
	}
	return map[string]interface{}{"key_id": req.KeyID, "public_key": "cHVibGljLWtleQ=="}, nil
}

func (m *mockServiceProvider) KMSListKeys(ctx context.Context, limit, offset int) (interface{}, error) {
	if m.kmsListKeysFunc != nil {
		return m.kmsListKeysFunc(ctx, limit, offset)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSRotateKey(ctx context.Context, keyID string) (interface{}, error) {
	if m.kmsRotateKeyFunc != nil {
		return m.kmsRotateKeyFunc(ctx, keyID)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSEncrypt(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
	if m.kmsEncryptFunc != nil {
		return m.kmsEncryptFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSDecrypt(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
	if m.kmsDecryptFunc != nil {
		return m.kmsDecryptFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSSign(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
	if m.kmsSignFunc != nil {
		return m.kmsSignFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSVerify(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
	if m.kmsVerifyFunc != nil {
		return m.kmsVerifyFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) KMSGenerateRandom(ctx context.Context, numBytes int) ([]byte, error) {
	if m.kmsGenerateRandomFunc != nil {
		return m.kmsGenerateRandomFunc(ctx, numBytes)
	}
	return nil, nil
}

// KMS lifecycle implementations
func (m *mockServiceProvider) KMSRevokeKey(ctx context.Context, keyID, reason string) (interface{}, error) {
	if m.kmsRevokeKeyFunc != nil {
		return m.kmsRevokeKeyFunc(ctx, keyID, reason)
	}
	return map[string]interface{}{"key_id": keyID, "status": "DISABLED"}, nil
}

func (m *mockServiceProvider) KMSGetKeyMetadata(ctx context.Context, keyID string) (interface{}, error) {
	if m.kmsGetKeyMetadataFunc != nil {
		return m.kmsGetKeyMetadataFunc(ctx, keyID)
	}
	return map[string]interface{}{"key_id": keyID, "name": "test-key"}, nil
}

func (m *mockServiceProvider) KMSUpdateKeyMetadata(ctx context.Context, req *KMSUpdateKeyMetadataRequest) (interface{}, error) {
	if m.kmsUpdateKeyMetadataFunc != nil {
		return m.kmsUpdateKeyMetadataFunc(ctx, req)
	}
	return map[string]interface{}{"key_id": req.KeyID, "name": req.Name}, nil
}

func (m *mockServiceProvider) KMSSetKeyPolicy(ctx context.Context, req *KMSSetKeyPolicyRequest) (interface{}, error) {
	if m.kmsSetKeyPolicyFunc != nil {
		return m.kmsSetKeyPolicyFunc(ctx, req)
	}
	return map[string]interface{}{"key_id": req.KeyID, "policy_version": 1}, nil
}

func (m *mockServiceProvider) KMSGetKeyPolicy(ctx context.Context, keyID string) (interface{}, error) {
	if m.kmsGetKeyPolicyFunc != nil {
		return m.kmsGetKeyPolicyFunc(ctx, keyID)
	}
	return map[string]interface{}{"key_id": keyID}, nil
}

func (m *mockServiceProvider) KMSGetSupportedAlgorithms(ctx context.Context) ([]string, error) {
	if m.kmsGetSupportedAlgorithmsFunc != nil {
		return m.kmsGetSupportedAlgorithmsFunc(ctx)
	}
	return []string{"AES-256-GCM"}, nil
}

func (m *mockServiceProvider) KMSBackendStatus(ctx context.Context) (interface{}, error) {
	if m.kmsBackendStatusFunc != nil {
		return m.kmsBackendStatusFunc(ctx)
	}
	return map[string]interface{}{"backend_type": "software", "status": "healthy"}, nil
}

// Secrets implementations
func (m *mockServiceProvider) SecretStore(ctx context.Context, req *SecretStoreRequest) (interface{}, error) {
	if m.secretStoreFunc != nil {
		return m.secretStoreFunc(ctx, req)
	}
	return map[string]interface{}{"secret_id": req.SecretID, "version": 1}, nil
}

func (m *mockServiceProvider) SecretGet(ctx context.Context, secretID string, version uint64) (interface{}, error) {
	if m.secretGetFunc != nil {
		return m.secretGetFunc(ctx, secretID, version)
	}
	return map[string]interface{}{"secret_id": secretID, "version": version}, nil
}

func (m *mockServiceProvider) SecretList(ctx context.Context, limit int) (interface{}, error) {
	if m.secretListFunc != nil {
		return m.secretListFunc(ctx, limit)
	}
	return map[string]interface{}{"secrets": []interface{}{}}, nil
}

func (m *mockServiceProvider) SecretDelete(ctx context.Context, secretID string) error {
	if m.secretDeleteFunc != nil {
		return m.secretDeleteFunc(ctx, secretID)
	}
	return nil
}

func (m *mockServiceProvider) SecretSetRotationPolicy(ctx context.Context, req *SecretSetRotationPolicyRequest) (interface{}, error) {
	if m.secretSetRotationPolicyFunc != nil {
		return m.secretSetRotationPolicyFunc(ctx, req)
	}
	return map[string]interface{}{"secret_id": req.SecretID}, nil
}

func (m *mockServiceProvider) SecretGetRotationPolicy(ctx context.Context, secretID string) (interface{}, error) {
	if m.secretGetRotationPolicyFunc != nil {
		return m.secretGetRotationPolicyFunc(ctx, secretID)
	}
	return map[string]interface{}{"secret_id": secretID}, nil
}

// newTestLogger creates a logger that discards output for testing.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// KMS Data Key implementations
func (m *mockServiceProvider) KMSGenerateDataKey(ctx context.Context, req *KMSGenerateDataKeyRequest) (interface{}, error) {
	if m.kmsGenerateDataKeyFunc != nil {
		return m.kmsGenerateDataKeyFunc(ctx, req)
	}
	return map[string]interface{}{
		"key_id":          req.KeyID,
		"plaintext":       []byte("plaintext-dek"),
		"ciphertext_blob": []byte("wrapped-dek"),
		"timestamp":       "2025-01-05T12:00:00Z",
	}, nil
}

func (m *mockServiceProvider) KMSGenerateWrappedDataKey(ctx context.Context, req *KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
	if m.kmsGenerateWrappedDataKeyFunc != nil {
		return m.kmsGenerateWrappedDataKeyFunc(ctx, req)
	}
	return map[string]interface{}{
		"key_id":          req.KeyID,
		"ciphertext_blob": []byte("wrapped-dek-only"),
		"timestamp":       "2025-01-05T12:00:00Z",
	}, nil
}

// Container implementations
func (m *mockServiceProvider) ContainerCreate(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
	if m.containerCreateFunc != nil {
		return m.containerCreateFunc(ctx, name, image, config)
	}
	return map[string]interface{}{
		"id":    "container-123",
		"name":  name,
		"image": image,
		"state": "created",
	}, nil
}

func (m *mockServiceProvider) ContainerStart(ctx context.Context, id string) error {
	if m.containerStartFunc != nil {
		return m.containerStartFunc(ctx, id)
	}
	return nil
}

func (m *mockServiceProvider) ContainerStop(ctx context.Context, id string, timeout int) error {
	if m.containerStopFunc != nil {
		return m.containerStopFunc(ctx, id, timeout)
	}
	return nil
}

func (m *mockServiceProvider) ContainerRemove(ctx context.Context, id string, force bool) error {
	if m.containerRemoveFunc != nil {
		return m.containerRemoveFunc(ctx, id, force)
	}
	return nil
}

func (m *mockServiceProvider) ContainerGet(ctx context.Context, id string) (interface{}, error) {
	if m.containerGetFunc != nil {
		return m.containerGetFunc(ctx, id)
	}
	return map[string]interface{}{
		"id":    id,
		"name":  "test-container",
		"image": "nginx:latest",
		"state": "running",
	}, nil
}

func (m *mockServiceProvider) ContainerList(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
	if m.containerListFunc != nil {
		return m.containerListFunc(ctx, all, filters, limit)
	}
	return []interface{}{
		map[string]interface{}{"id": "container-1", "name": "web", "state": "running"},
		map[string]interface{}{"id": "container-2", "name": "db", "state": "running"},
	}, nil
}

func (m *mockServiceProvider) ContainerLogs(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error) {
	if m.containerLogsFunc != nil {
		return m.containerLogsFunc(ctx, id, follow, stdout, stderr, tail, timestamps)
	}
	return "container log output line 1\ncontainer log output line 2\n", nil
}

func (m *mockServiceProvider) ContainerAttest(ctx context.Context, id string) (interface{}, error) {
	if m.containerAttestFunc != nil {
		return m.containerAttestFunc(ctx, id)
	}
	return map[string]interface{}{
		"container_id": id,
		"verified":     true,
		"timestamp":    "2025-01-05T12:00:00Z",
	}, nil
}

// IDevID implementations
func (m *mockServiceProvider) IDevIDGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
	if m.idevidGenerateFunc != nil {
		return m.idevidGenerateFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IDevIDInfo(ctx context.Context) (interface{}, error) {
	if m.idevidInfoFunc != nil {
		return m.idevidInfoFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) IDevIDDelete(ctx context.Context) error {
	if m.idevidDeleteFunc != nil {
		return m.idevidDeleteFunc(ctx)
	}
	return nil
}

func (m *mockServiceProvider) IDevIDCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
	if m.idevidCSRFunc != nil {
		return m.idevidCSRFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	if m.idevidInstallCertFunc != nil {
		return m.idevidInstallCertFunc(ctx, certificatePEM)
	}
	return nil, nil
}

func (m *mockServiceProvider) IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	if m.idevidGetCertFunc != nil {
		return m.idevidGetCertFunc(ctx, includePEM)
	}
	return nil, nil
}

func (m *mockServiceProvider) IDevIDDeleteCert(ctx context.Context) error {
	if m.idevidDeleteCertFunc != nil {
		return m.idevidDeleteCertFunc(ctx)
	}
	return nil
}

func (m *mockServiceProvider) IDevIDExists(ctx context.Context) (bool, error) {
	if m.idevidExistsFunc != nil {
		return m.idevidExistsFunc(ctx)
	}
	return false, nil
}

// IAK implementations
func (m *mockServiceProvider) IAKGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
	if m.iakGenerateFunc != nil {
		return m.iakGenerateFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAKInfo(ctx context.Context) (interface{}, error) {
	if m.iakInfoFunc != nil {
		return m.iakInfoFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAKDelete(ctx context.Context) error {
	if m.iakDeleteFunc != nil {
		return m.iakDeleteFunc(ctx)
	}
	return nil
}

func (m *mockServiceProvider) IAKCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
	if m.iakCSRFunc != nil {
		return m.iakCSRFunc(ctx, req)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error) {
	if m.iakInstallCertFunc != nil {
		return m.iakInstallCertFunc(ctx, certificatePEM)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error) {
	if m.iakGetCertFunc != nil {
		return m.iakGetCertFunc(ctx, includePEM)
	}
	return nil, nil
}

func (m *mockServiceProvider) IAKDeleteCert(ctx context.Context) error {
	if m.iakDeleteCertFunc != nil {
		return m.iakDeleteCertFunc(ctx)
	}
	return nil
}

func (m *mockServiceProvider) IAKExists(ctx context.Context) (bool, error) {
	if m.iakExistsFunc != nil {
		return m.iakExistsFunc(ctx)
	}
	return false, nil
}

// Device attribute and credential implementations
func (m *mockServiceProvider) DeviceAttributes(ctx context.Context) (interface{}, error) {
	if m.deviceAttributesFunc != nil {
		return m.deviceAttributesFunc(ctx)
	}
	return nil, nil
}

func (m *mockServiceProvider) ActivateCredential(ctx context.Context, credentialBlob []byte, secret []byte) ([]byte, error) {
	if m.activateCredentialFunc != nil {
		return m.activateCredentialFunc(ctx, credentialBlob, secret)
	}
	return nil, nil
}

// Overlay network operations
func (m *mockServiceProvider) OverlayStatus(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"status": "operational"}, nil
}

func (m *mockServiceProvider) OverlayVTEPList(ctx context.Context) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error) {
	return map[string]interface{}{"node_id": nodeID}, nil
}

func (m *mockServiceProvider) OverlayVNIList(ctx context.Context) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, name string) (interface{}, error) {
	return map[string]interface{}{"vni": vni, "vlan": vlan, "name": name}, nil
}

func (m *mockServiceProvider) OverlayVNIDelete(ctx context.Context, vni uint32) error {
	return nil
}

func (m *mockServiceProvider) OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) OverlayMACForget(ctx context.Context, mac string, vni uint32) error {
	return nil
}

// Gateway operations
func (m *mockServiceProvider) GatewayStatus(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"status": "operational"}, nil
}

func (m *mockServiceProvider) GatewaySnapshot(ctx context.Context, gatewayID string) (interface{}, error) {
	return map[string]interface{}{"gateway_id": gatewayID, "health": map[string]interface{}{"status": "healthy"}}, nil
}

func (m *mockServiceProvider) GatewaySnapshots(ctx context.Context) ([]interface{}, error) {
	return []interface{}{map[string]interface{}{"gateway_id": "lab-node-1-gateway"}}, nil
}

func (m *mockServiceProvider) GatewayModeSet(ctx context.Context, modes []string) (interface{}, error) {
	return map[string]interface{}{"modes": modes}, nil
}

// Gateway BGP operations
func (m *mockServiceProvider) GatewayBGPStatus(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"status": "operational"}, nil
}

func (m *mockServiceProvider) GatewayBGPPeers(ctx context.Context) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) GatewayBGPAnnounce(ctx context.Context, prefix string, nextHop string) error {
	return nil
}

func (m *mockServiceProvider) GatewayBGPWithdraw(ctx context.Context, prefix string) error {
	return nil
}

func (m *mockServiceProvider) GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error) {
	return []interface{}{}, nil
}

// Gateway load balancer operations
func (m *mockServiceProvider) GatewayLBVIPAdd(ctx context.Context, req *LBVIPAddRequest) (interface{}, error) {
	return map[string]interface{}{"address": req.Address, "port": req.Port, "protocol": req.Protocol}, nil
}

func (m *mockServiceProvider) GatewayLBVIPRemove(ctx context.Context, protocol, address string, port uint16) error {
	return nil
}

func (m *mockServiceProvider) GatewayLBVIPGet(ctx context.Context, protocol, address string, port uint16) (interface{}, error) {
	return map[string]interface{}{"address": address, "port": port, "protocol": protocol}, nil
}

func (m *mockServiceProvider) GatewayLBVIPList(ctx context.Context) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) GatewayLBVIPSetBackends(ctx context.Context, protocol, address string, port uint16, backends []*LBBackendRequest) (interface{}, error) {
	return map[string]interface{}{"address": address, "port": port, "backends": len(backends)}, nil
}

func (m *mockServiceProvider) GatewayLBStatus(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"active": true}, nil
}

// Gateway perf operations
func (m *mockServiceProvider) GatewayPerfFlows(ctx context.Context, bridge string, count int, batch bool) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.perfFlowsCalls = append(m.perfFlowsCalls, perfFlowsCall{bridge: bridge, count: count, batch: batch})
	if m.perfErr != nil {
		return nil, m.perfErr
	}
	return map[string]interface{}{"installed": count, "batched": batch, "bridge": bridge}, nil
}

func (m *mockServiceProvider) GatewayPerfDatapath(ctx context.Context, bridge string) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.perfErr != nil {
		return nil, m.perfErr
	}
	return map[string]interface{}{"hits": 1, "misses": 0, "lost": 0, "bridge": bridge}, nil
}

func (m *mockServiceProvider) GatewayPerfConntrack(ctx context.Context, zone int) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.perfConntrackZones = append(m.perfConntrackZones, zone)
	if m.perfErr != nil {
		return nil, m.perfErr
	}
	return map[string]interface{}{"total_entries": 0}, nil
}

// NTP (time synchronization) operations

func (m *mockServiceProvider) NTPStatus(ctx context.Context) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ntpErr != nil {
		return nil, m.ntpErr
	}
	return map[string]interface{}{"synced": true, "stratum": 3, "mode": "both"}, nil
}

func (m *mockServiceProvider) NTPSources(ctx context.Context) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ntpErr != nil {
		return nil, m.ntpErr
	}
	return map[string]interface{}{"sources": []interface{}{
		map[string]interface{}{"address": "198.18.0.1", "reachable": true},
	}}, nil
}

func (m *mockServiceProvider) NTPStep(ctx context.Context) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ntpStepCalls++
	if m.ntpErr != nil {
		return nil, m.ntpErr
	}
	return map[string]interface{}{"synced": true, "stratum": 3}, nil
}

// Gateway IPAM operations
func (m *mockServiceProvider) GatewayIPAMPools(ctx context.Context, zone string) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) GatewayIPAMPoolGet(ctx context.Context, poolID string) (interface{}, error) {
	return map[string]interface{}{"id": poolID, "name": "test-pool", "cidr": "10.0.0.0/24"}, nil
}

func (m *mockServiceProvider) GatewayIPAMAllocate(ctx context.Context, poolID string, deviceID string, hostname string) (interface{}, error) {
	return map[string]interface{}{"pool_id": poolID, "device_id": deviceID, "hostname": hostname}, nil
}

func (m *mockServiceProvider) GatewayIPAMRelease(ctx context.Context, ip string) error {
	return nil
}

func (m *mockServiceProvider) GatewayIPAMAllocations(ctx context.Context, poolID string) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) GatewayIPAMPoolCreate(ctx context.Context, req *IPAMPoolCreateRequest) (interface{}, error) {
	return map[string]interface{}{"id": "test-pool-id", "name": req.Name, "cidr": req.CIDR}, nil
}

func (m *mockServiceProvider) GatewayIPAMPoolUpdate(ctx context.Context, poolID string, req *IPAMPoolUpdateRequest) (interface{}, error) {
	return map[string]interface{}{"id": poolID, "name": req.Name}, nil
}

func (m *mockServiceProvider) GatewayIPAMPoolDelete(ctx context.Context, poolID string) error {
	return nil
}

func (m *mockServiceProvider) GatewayNetworkZoneList(ctx context.Context, lifecycleRole string) ([]interface{}, error) {
	return []interface{}{}, nil
}

func (m *mockServiceProvider) GatewayNetworkZoneCreate(ctx context.Context, req *NetworkZoneCreateRequest) (interface{}, error) {
	m.lastZoneCreate = req
	return map[string]interface{}{"zone": req, "restart_required": true}, nil
}

func (m *mockServiceProvider) GatewayNetworkZoneUpdate(ctx context.Context, name string, req *NetworkZoneUpdateRequest) (interface{}, error) {
	m.lastZoneUpdate = req
	m.lastZoneUpdateName = name
	return map[string]interface{}{"zone": req, "restart_required": true}, nil
}

func (m *mockServiceProvider) GatewayNetworkZoneDelete(ctx context.Context, name string) (bool, error) {
	return false, nil
}

func (m *mockServiceProvider) GatewayNetworkZoneVLAN(ctx context.Context, zoneName string) (uint16, error) {
	return 100, nil
}

// Physical TPM operations

func (m *mockServiceProvider) TPMInfo(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"info": "mock TPM"}, nil
}

func (m *mockServiceProvider) TPMProvision(ctx context.Context, ownerPassword string) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMClear(ctx context.Context, ownerPassword string) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMGetEK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"handle": uint32(0x81010001)}, nil
}

func (m *mockServiceProvider) TPMGetEKCert(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"certificate": "base64cert"}, nil
}

func (m *mockServiceProvider) TPMImportEKCert(ctx context.Context, certDER []byte) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMCreateEK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMDeleteEK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMGetSRK(ctx context.Context, handle uint32) (interface{}, error) {
	// Echo the handle back so a test can assert the tool passed the
	// caller's argument through rather than dropping it (#475).
	m.lastSRKHandle = handle
	if handle == 0x81000002 {
		return map[string]interface{}{"handle": uint32(0x81000002)}, nil
	}
	return map[string]interface{}{"handle": uint32(0x81000001)}, nil
}

func (m *mockServiceProvider) TPMCreateSRK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMDeleteSRK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMMakeCredential(ctx context.Context, akName, secret, ekCert, iakPub []byte) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMGetIAK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"handle": uint32(0x81010002)}, nil
}

func (m *mockServiceProvider) TPMCreateIAK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMDeleteIAK(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error) {
	return map[string]interface{}{"quote": "base64quote"}, nil
}

func (m *mockServiceProvider) TPMVerifyQuote(ctx context.Context, quote []byte, signature []byte, nonce []byte) (interface{}, error) {
	return map[string]interface{}{"valid": true}, nil
}

func (m *mockServiceProvider) TPMReadPCRs(ctx context.Context, indices []int) (interface{}, error) {
	return map[string]interface{}{"banks": []interface{}{}}, nil
}

func (m *mockServiceProvider) TPMExtendPCR(ctx context.Context, pcrIndex int, data []byte) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMEventLog(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"event_log": "base64log"}, nil
}

func (m *mockServiceProvider) TPMCapabilities(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"manufacturer": "mock"}, nil
}

func (m *mockServiceProvider) TPMRandom(ctx context.Context, numBytes int) ([]byte, error) {
	return make([]byte, numBytes), nil
}

func (m *mockServiceProvider) TPMSeal(ctx context.Context, data []byte, pcrs []int) ([]byte, error) {
	return []byte("sealed"), nil
}

func (m *mockServiceProvider) TPMUnseal(ctx context.Context, cn string) ([]byte, error) {
	return []byte("unsealed"), nil
}

func (m *mockServiceProvider) TPMCertify(ctx context.Context, keyHandle int) (interface{}, error) {
	return map[string]interface{}{"certify_info": "base64info"}, nil
}

func (m *mockServiceProvider) TPMNVList(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"indices": []interface{}{}}, nil
}

func (m *mockServiceProvider) TPMNVRead(ctx context.Context, index int, size int) ([]byte, error) {
	return []byte("nvdata"), nil
}

func (m *mockServiceProvider) TPMNVWrite(ctx context.Context, index int, data []byte) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMNVDelete(ctx context.Context, index int) (interface{}, error) {
	return map[string]interface{}{"success": true}, nil
}

func (m *mockServiceProvider) TPMPlatform(ctx context.Context) (interface{}, error) {
	return map[string]interface{}{"available": true}, nil
}
