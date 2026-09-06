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
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// =============================================================================
// Mock Policy Engine for coverage tests
// =============================================================================

type mcpCoverageMockPolicyEngine struct {
	portStates  map[string]policy.PortState
	policies    map[string]*policy.PortPolicy
	portInfos   map[string]*policy.PortInfo
	portVLANs   map[string]uint16
	ofPorts     map[string]int32
	shouldError bool
	errorMsg    string
}

func newMCPCoverageMockPolicyEngine() *mcpCoverageMockPolicyEngine {
	return &mcpCoverageMockPolicyEngine{
		portStates: make(map[string]policy.PortState),
		policies:   make(map[string]*policy.PortPolicy),
		portInfos:  make(map[string]*policy.PortInfo),
		portVLANs:  make(map[string]uint16),
		ofPorts:    make(map[string]int32),
	}
}

func (m *mcpCoverageMockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = state
	return nil
}

func (m *mcpCoverageMockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.shouldError {
		return policy.PortStateUnconnected, errors.New(m.errorMsg)
	}
	if state, ok := m.portStates[portID]; ok {
		return state, nil
	}
	return policy.PortStateUnconnected, nil
}

func (m *mcpCoverageMockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if info, ok := m.portInfos[portID]; ok {
		return info, nil
	}
	return &policy.PortInfo{
		PortID:          portID,
		State:           policy.PortStateUnconnected,
		LastStateChange: time.Now(),
	}, nil
}

func (m *mcpCoverageMockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.policies[portID] = pol
	return nil
}

func (m *mcpCoverageMockPolicyEngine) RemovePolicy(portID string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	delete(m.policies, portID)
	return nil
}

func (m *mcpCoverageMockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.shouldError {
		return nil, errors.New(m.errorMsg)
	}
	if pol, ok := m.policies[portID]; ok {
		return pol, nil
	}
	return nil, errors.New("policy not found")
}

func (m *mcpCoverageMockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portVLANs[portID] = vlan
	return nil
}

func (m *mcpCoverageMockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	if m.shouldError {
		return 0, errors.New(m.errorMsg)
	}
	if vlan, ok := m.portVLANs[portID]; ok {
		return vlan, nil
	}
	return 0, nil
}

func (m *mcpCoverageMockPolicyEngine) BlockPort(portID string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mcpCoverageMockPolicyEngine) UnblockPort(portID string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mcpCoverageMockPolicyEngine) GetOFPort(portID string) (int32, error) {
	if m.shouldError {
		return 0, errors.New(m.errorMsg)
	}
	if ofp, ok := m.ofPorts[portID]; ok {
		return ofp, nil
	}
	return 0, nil
}

func (m *mcpCoverageMockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = policy.PortStateAuthorized
	return nil
}

func (m *mcpCoverageMockPolicyEngine) OnCertificateExpired(portID string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = policy.PortStateUnauthorized
	return nil
}

func (m *mcpCoverageMockPolicyEngine) OnCertificateRevoked(portID string) error {
	if m.shouldError {
		return errors.New(m.errorMsg)
	}
	m.portStates[portID] = policy.PortStateBlocked
	return nil
}

func (m *mcpCoverageMockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// =============================================================================
// VTPMCreate Coverage Tests
// =============================================================================

func TestMCPServiceProvider_VTPMCreate_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMCreate(ctx, "test-vtpm", "RSA2048")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_VTPMCreate_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMCreate(ctx, "test", "RSA")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// VTPMList Coverage Tests
// =============================================================================

func TestMCPServiceProvider_VTPMList_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()

	// Create some bundles first using the mock service
	_, _ = mockSvc.CreateBundle(ctx, &vtpm.CreateBundleOptions{Hostname: "bundle1"})
	_, _ = mockSvc.CreateBundle(ctx, &vtpm.CreateBundleOptions{Hostname: "bundle2"})

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 bundles, got %d", len(result))
	}
}

func TestMCPServiceProvider_VTPMList_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.VTPMList(ctx)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_VTPMList_EmptyList(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockVTPMService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		VTPMService: mockSvc,
	})

	result, err := provider.VTPMList(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 bundles, got %d", len(result))
	}
}

// =============================================================================
// DNSAddRecord Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DNSAddRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSAddRecord_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSAddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)
	if err == nil {
		t.Error("expected error for nil service")
	}
	// DNS service uses ErrDNSServiceNotAvailable instead of ErrServiceNotAvailable
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSAddRecord_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	tests := []struct {
		name       string
		recordName string
		recordType string
		value      string
		ttl        int
		wantErr    bool
	}{
		{
			name:       "empty name",
			recordName: "",
			recordType: "A",
			value:      "192.168.1.1",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "empty type",
			recordName: "test.example.com",
			recordType: "",
			value:      "192.168.1.1",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "empty value",
			recordName: "test.example.com",
			recordType: "A",
			value:      "",
			ttl:        300,
			wantErr:    true,
		},
		{
			name:       "negative ttl",
			recordName: "test.example.com",
			recordType: "A",
			value:      "192.168.1.1",
			ttl:        -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.DNSAddRecord(ctx, tt.recordName, tt.recordType, tt.value, tt.ttl)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// DNSDeleteRecord Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DNSDeleteRecord_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	// Add a record first
	_ = mockSvc.AddRecord(ctx, "test.example.com", "A", "192.168.1.1", 300)

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPServiceProvider_DNSDeleteRecord_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.DNSDeleteRecord(ctx, "test.example.com", "A")
	if err == nil {
		t.Error("expected error for nil service")
	}
	// DNS service uses ErrDNSServiceNotAvailable instead of ErrServiceNotAvailable
	if _, ok := err.(ErrDNSServiceNotAvailable); !ok {
		t.Errorf("expected ErrDNSServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DNSDeleteRecord_ValidationErrors(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDNSService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DNSService: mockSvc,
	})

	tests := []struct {
		name       string
		recordName string
		recordType string
		wantErr    bool
	}{
		{
			name:       "empty name",
			recordName: "",
			recordType: "A",
			wantErr:    true,
		},
		{
			name:       "empty type",
			recordName: "test.example.com",
			recordType: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.DNSDeleteRecord(ctx, tt.recordName, tt.recordType)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// =============================================================================
// DeviceRegister Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DeviceRegister_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceRegister(ctx, "device1", "server", nil)
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceRegister_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	result, err := provider.DeviceRegister(ctx, "device1", "server", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// TestMCPServiceProvider_DeviceRegister_AssignsAnID is the #525
// regression on the MCP transport. The provider built a Device with no
// ID and called Save, which requires one, so the MCP create verb was
// refused exactly as gRPC, Unix and QUIC were. The assertion is on the
// assigned ID, not merely a nil-free result, because a result that
// carries a zero ID cannot be read back.
func TestMCPServiceProvider_DeviceRegister_AssignsAnID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	result, err := provider.DeviceRegister(ctx, "model-525", "SN-525", nil)
	if err != nil {
		t.Fatalf("DeviceRegister returned an error: %v", err)
	}
	dev, ok := result.(*deviceentities.Device)
	if !ok {
		t.Fatalf("expected a *entities.Device, got %T", result)
	}
	if dev.ID == 0 {
		t.Fatal("DeviceRegister returned a device with no ID; it cannot be read back")
	}

	// Readable afterwards under the assigned ID.
	got, err := provider.DeviceGet(ctx, itoa(dev.ID))
	if err != nil {
		t.Fatalf("DeviceGet on the created device failed: %v", err)
	}
	if got == nil {
		t.Fatal("DeviceGet returned no device")
	}
}

// TestMCPServiceProvider_DeviceRegister_SaveErrorSurfaces is the failure
// case: a storage refusal must reach the caller rather than being
// reported as a successful registration.
func TestMCPServiceProvider_DeviceRegister_SaveErrorSurfaces(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: &failingDeviceCreateService{mcpMockDeviceService: newMCPMockDeviceService()},
	})

	if _, err := provider.DeviceRegister(ctx, "model-525", "SN-525", nil); err == nil {
		t.Fatal("expected the storage failure to surface from DeviceRegister")
	}
}

// failingDeviceCreateService fails only the create verb so the error
// path is exercised without disturbing the other operations.
type failingDeviceCreateService struct {
	*mcpMockDeviceService
}

func (f *failingDeviceCreateService) Create(context.Context, *deviceentities.Device) error {
	return errors.New("storage write failed")
}

// =============================================================================
// DeviceGet Coverage Tests
// =============================================================================

func TestMCPServiceProvider_DeviceGet_Success(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	// Register a device first
	_, _ = provider.DeviceRegister(ctx, "device1", "server", nil)

	result, err := provider.DeviceGet(ctx, "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestMCPServiceProvider_DeviceGet_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.DeviceGet(ctx, "1")
	if err == nil {
		t.Error("expected error for nil service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_DeviceGet_InvalidID(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	_, err := provider.DeviceGet(ctx, "invalid")
	if err == nil {
		t.Error("expected error for invalid ID")
	}
}

func TestMCPServiceProvider_DeviceGet_NotFound(t *testing.T) {
	ctx := context.Background()
	mockSvc := newMCPMockDeviceService()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		DeviceService: mockSvc,
	})

	_, err := provider.DeviceGet(ctx, "999")
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

// =============================================================================
// SDNGetPolicy Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPolicy_NilPolicyEngine(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetPolicy(ctx, "port1")
	if err == nil {
		t.Error("expected error for nil policy engine")
	}
	if _, ok := err.(ErrSDNPolicyEngineNotConfigured); !ok {
		t.Errorf("expected ErrSDNPolicyEngineNotConfigured, got %T", err)
	}
}

func TestMCPServiceProvider_SDNGetPolicy_EmptyPolicyID(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	_, err := provider.SDNGetPolicy(ctx, "")
	if err == nil {
		t.Error("expected error for empty policy ID")
	}
	if _, ok := err.(ErrSDNMissingParameter); !ok {
		t.Errorf("expected ErrSDNMissingParameter, got %T", err)
	}
}

func TestMCPServiceProvider_SDNGetPolicy_PolicyNotFound(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	_, err := provider.SDNGetPolicy(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent policy")
	}
	if _, ok := err.(ErrSDNPolicyNotFound); !ok {
		t.Errorf("expected ErrSDNPolicyNotFound, got %T", err)
	}
}

func TestMCPServiceProvider_SDNGetPolicy_Success(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()

	// Add a policy
	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID:  "tenant1",
		VLAN:      100,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["tenant_id"] != "tenant1" {
		t.Errorf("expected tenant_id=tenant1, got %v", resultMap["tenant_id"])
	}
	if resultMap["vlan"] != uint16(100) {
		t.Errorf("expected vlan=100, got %v", resultMap["vlan"])
	}
}

func TestMCPServiceProvider_SDNGetPolicy_WithExpiration(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()

	expiry := time.Now().Add(24 * time.Hour)
	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID:  "tenant1",
		VLAN:      100,
		IssuedAt:  time.Now(),
		ExpiresAt: expiry,
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if _, exists := resultMap["expires_at"]; !exists {
		t.Error("expected expires_at field in response")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_WithMetadata(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()

	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		IssuedAt: time.Now(),
		Metadata: map[string]string{
			"department": "engineering",
			"owner":      "admin",
		},
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if _, exists := resultMap["metadata"]; !exists {
		t.Error("expected metadata field in response")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_WithACLs(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()

	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		IssuedAt: time.Now(),
		ACLs: []policy.ACLRule{
			{
				Priority:    100,
				Description: "Allow HTTP",
				Action:      policy.FlowAction{Type: policy.FlowActionAllow},
			},
		},
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["acl_count"] != 1 {
		t.Errorf("expected acl_count=1, got %v", resultMap["acl_count"])
	}
	if _, exists := resultMap["acls"]; !exists {
		t.Error("expected acls field in response")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_WithPortInfo(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()

	mockEngine.policies["port1"] = &policy.PortPolicy{
		TenantID: "tenant1",
		VLAN:     100,
		IssuedAt: time.Now(),
	}
	mockEngine.portInfos["port1"] = &policy.PortInfo{
		PortID:          "port1",
		State:           policy.PortStateAuthorized,
		LastStateChange: time.Now(),
		AuthAttempts:    3,
		ErrorCount:      1,
		LastError:       "previous timeout",
	}

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}
	if resultMap["state"] != "authorized" {
		t.Errorf("expected state=authorized, got %v", resultMap["state"])
	}
	if resultMap["auth_attempts"] != 3 {
		t.Errorf("expected auth_attempts=3, got %v", resultMap["auth_attempts"])
	}
	if resultMap["last_error"] != "previous timeout" {
		t.Errorf("expected last_error='previous timeout', got %v", resultMap["last_error"])
	}
}

// =============================================================================
// SDNListPolicies Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListPolicies_NilPolicyEngine(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListPolicies(ctx)
	if err == nil {
		t.Error("expected error for nil policy engine")
	}
	if _, ok := err.(ErrSDNPolicyEngineNotConfigured); !ok {
		t.Errorf("expected ErrSDNPolicyEngineNotConfigured, got %T", err)
	}
}

func TestMCPServiceProvider_SDNListPolicies_EmptyList(t *testing.T) {
	ctx := context.Background()
	mockEngine := newMCPCoverageMockPolicyEngine()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: mockEngine,
	})

	result, err := provider.SDNListPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The method returns an empty list, not nil
	if result == nil {
		t.Error("expected non-nil result")
	}
}

// =============================================================================
// SDNSetPortState Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNSetPortState_MissingBridgeName(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNSetPortState(ctx, "", "port1", "authorized")
	if err == nil {
		t.Error("expected error for missing bridge name")
	}
	if _, ok := err.(ErrSDNMissingParameter); !ok {
		t.Errorf("expected ErrSDNMissingParameter, got %T", err)
	}
}

func TestMCPServiceProvider_SDNSetPortState_MissingPortName(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNSetPortState(ctx, "br0", "", "authorized")
	if err == nil {
		t.Error("expected error for missing port name")
	}
	if _, ok := err.(ErrSDNMissingParameter); !ok {
		t.Errorf("expected ErrSDNMissingParameter, got %T", err)
	}
}

func TestMCPServiceProvider_SDNSetPortState_MissingState(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNSetPortState(ctx, "br0", "port1", "")
	if err == nil {
		t.Error("expected error for missing state")
	}
	if _, ok := err.(ErrSDNMissingParameter); !ok {
		t.Errorf("expected ErrSDNMissingParameter, got %T", err)
	}
}

func TestMCPServiceProvider_SDNSetPortState_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNSetPortState(ctx, "br0", "port1", "authorized")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNApplyPolicy Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNApplyPolicy_NilSDNService(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNApplyPolicy(ctx, "policy1", "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// Health, Liveness, Readiness Coverage Tests
// =============================================================================

func TestMCPServiceProvider_Health_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Health(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_Liveness_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Liveness(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

func TestMCPServiceProvider_Readiness_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.Readiness(ctx)
	if err == nil {
		t.Error("expected error for nil health service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListBridges Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListBridges_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListBridges(ctx)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListFlows Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListFlows_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListFlows(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNListVLANs Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNListVLANs_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNListVLANs(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNAuthenticatePort Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNAuthenticatePort_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", nil)
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetPortState Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortState_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetPortState(ctx, "br0", "port1")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetPortStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPortStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetPortStats(ctx, "br0", "port1")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}

// =============================================================================
// SDNGetFlowStats Coverage Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetFlowStats_NilServiceReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{})

	_, err := provider.SDNGetFlowStats(ctx, "br0")
	if err == nil {
		t.Error("expected error for nil SDN service")
	}
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Errorf("expected ErrServiceNotAvailable, got %T", err)
	}
}
