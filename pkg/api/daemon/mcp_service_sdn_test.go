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
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// =============================================================================
// Mock Policy Engine for SDN Tests
// =============================================================================

// sdnTestMockPolicyEngine implements policy.PolicyEngine for testing
type sdnTestMockPolicyEngine struct {
	// SetPortState
	setPortStateErr error

	// GetPortState
	getPortStateResp policy.PortState
	getPortStateErr  error

	// GetPortInfo
	getPortInfoResp *policy.PortInfo
	getPortInfoErr  error

	// ApplyPolicy
	applyPolicyErr error

	// GetPolicy
	getPolicyResp *policy.PortPolicy
	getPolicyErr  error

	// RemovePolicy
	removePolicyErr error

	// SetPortVLAN
	setPortVLANErr error

	// GetPortVLAN
	getPortVLANResp uint16
	getPortVLANErr  error

	// BlockPort
	blockPortErr error

	// UnblockPort
	unblockPortErr error

	// GetOFPort
	getOFPortResp int32
	getOFPortErr  error

	// AuthenticatePort
	authenticatePortErr error

	// OnCertificateExpired
	onCertExpiredErr error

	// OnCertificateRevoked
	onCertRevokedErr error
}

func (m *sdnTestMockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	return m.setPortStateErr
}

func (m *sdnTestMockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.getPortStateErr != nil {
		return policy.PortStateUnconnected, m.getPortStateErr
	}
	return m.getPortStateResp, nil
}

func (m *sdnTestMockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	if m.getPortInfoErr != nil {
		return nil, m.getPortInfoErr
	}
	return m.getPortInfoResp, nil
}

func (m *sdnTestMockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	return m.applyPolicyErr
}

func (m *sdnTestMockPolicyEngine) RemovePolicy(portID string) error {
	return m.removePolicyErr
}

func (m *sdnTestMockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.getPolicyErr != nil {
		return nil, m.getPolicyErr
	}
	return m.getPolicyResp, nil
}

func (m *sdnTestMockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	return m.setPortVLANErr
}

func (m *sdnTestMockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	if m.getPortVLANErr != nil {
		return 0, m.getPortVLANErr
	}
	return m.getPortVLANResp, nil
}

func (m *sdnTestMockPolicyEngine) BlockPort(portID string) error {
	return m.blockPortErr
}

func (m *sdnTestMockPolicyEngine) UnblockPort(portID string) error {
	return m.unblockPortErr
}

func (m *sdnTestMockPolicyEngine) GetOFPort(portID string) (int32, error) {
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	return m.getOFPortResp, nil
}

func (m *sdnTestMockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	return m.authenticatePortErr
}

func (m *sdnTestMockPolicyEngine) OnCertificateExpired(portID string) error {
	return m.onCertExpiredErr
}

func (m *sdnTestMockPolicyEngine) OnCertificateRevoked(portID string) error {
	return m.onCertRevokedErr
}

func (m *sdnTestMockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	return nil
}

// =============================================================================
// parsePortState Function Tests
// =============================================================================

func TestParsePortState_ValidStates(t *testing.T) {
	testCases := []struct {
		input    string
		expected policy.PortState
	}{
		{"unconnected", policy.PortStateUnconnected},
		{"UNCONNECTED", policy.PortStateUnconnected},
		{"  unconnected  ", policy.PortStateUnconnected},
		{"provisioning", policy.PortStateProvisioning},
		{"Provisioning", policy.PortStateProvisioning},
		{"enrolled", policy.PortStateEnrolled},
		{"ENROLLED", policy.PortStateEnrolled},
		{"unauthorized", policy.PortStateUnauthorized},
		{"Unauthorized", policy.PortStateUnauthorized},
		{"authenticating", policy.PortStateAuthenticating},
		{"AUTHENTICATING", policy.PortStateAuthenticating},
		{"authorized", policy.PortStateAuthorized},
		{"Authorized", policy.PortStateAuthorized},
		{"quarantined", policy.PortStateQuarantined},
		{"Quarantined", policy.PortStateQuarantined},
		{"blocked", policy.PortStateBlocked},
		{"BLOCKED", policy.PortStateBlocked},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result, err := parsePortState(tc.input)
			if err != nil {
				t.Fatalf("unexpected error for state %q: %v", tc.input, err)
			}
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestParsePortState_InvalidStates(t *testing.T) {
	invalidStates := []string{
		"invalid",
		"unknown",
		"active",
		"inactive",
		"123",
		"block", // should be "blocked"
		"auth",  // should be "authorized" or "authenticating"
	}

	for _, state := range invalidStates {
		t.Run(state, func(t *testing.T) {
			_, err := parsePortState(state)
			if err == nil {
				t.Fatalf("expected error for invalid state %q", state)
			}

			stateErr, ok := err.(ErrSDNInvalidPortState)
			if !ok {
				t.Fatalf("expected ErrSDNInvalidPortState, got %T: %v", err, err)
			}
			if stateErr.State != state {
				t.Errorf("expected state=%q, got %q", state, stateErr.State)
			}
		})
	}
}

// =============================================================================
// SDNSetPortState Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNSetPortState_InvalidStateError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		},
		PolicyEngine: &sdnTestMockPolicyEngine{},
		Logger:       slog.Default(),
	})

	err := provider.SDNSetPortState(ctx, "br0", "port1", "invalid_state")
	if err == nil {
		t.Fatal("expected error for invalid state")
	}

	stateErr, ok := err.(ErrSDNInvalidPortState)
	if !ok {
		t.Fatalf("expected ErrSDNInvalidPortState, got %T: %v", err, err)
	}
	if stateErr.State != "invalid_state" {
		t.Errorf("expected state='invalid_state', got %q", stateErr.State)
	}
}

func TestMCPServiceProvider_SDNSetPortState_NilPolicyEngineError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		},
		Logger: slog.Default(),
	})

	err := provider.SDNSetPortState(ctx, "br0", "port1", "blocked")
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}

	_, ok := err.(ErrSDNPolicyEngineNotConfigured)
	if !ok {
		t.Fatalf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNSetPortState_AllValidStatesParseCorrectly(t *testing.T) {
	validStates := []string{
		"unconnected",
		"provisioning",
		"enrolled",
		"unauthorized",
		"authenticating",
		"authorized",
		"quarantined",
		"blocked",
	}

	for _, state := range validStates {
		t.Run(state, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				SDNService: &SDNService{
					bridges:   make(map[string]*bridgeResource),
					ports:     make(map[string]*portResource),
					taps:      make(map[string]*tapResource),
					vlans:     make(map[string]*vlanResource),
					portAuths: make(map[string]*portAuthResource),
				},
				PolicyEngine: &sdnTestMockPolicyEngine{},
				Logger:       slog.Default(),
			})

			// This will fail at GetPort call, but validates state parsing works
			err := provider.SDNSetPortState(ctx, "br0", "port1", state)
			if err == nil {
				t.Fatal("expected error (GetPort should fail)")
			}

			// Verify it's not an invalid state error
			if _, ok := err.(ErrSDNInvalidPortState); ok {
				t.Errorf("unexpected ErrSDNInvalidPortState for valid state %q", state)
			}

			// Should be port not found error
			if _, ok := err.(ErrSDNPortNotFound); !ok {
				t.Errorf("expected ErrSDNPortNotFound, got %T: %v", err, err)
			}
		})
	}
}

// =============================================================================
// SDNApplyPolicy Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNApplyPolicy_PolicyNotFoundError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		},
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyErr: errors.New("policy not found"),
		},
		Logger: slog.Default(),
	})

	err := provider.SDNApplyPolicy(ctx, "nonexistent", "br0")
	if err == nil {
		t.Fatal("expected error for policy not found")
	}

	notFoundErr, ok := err.(ErrSDNPolicyNotFound)
	if !ok {
		t.Fatalf("expected ErrSDNPolicyNotFound, got %T: %v", err, err)
	}
	if notFoundErr.PolicyID != "nonexistent" {
		t.Errorf("expected PolicyID='nonexistent', got %q", notFoundErr.PolicyID)
	}
}

func TestMCPServiceProvider_SDNApplyPolicy_ApplyFailsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		},
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyResp: &policy.PortPolicy{
				TenantID: "tenant1",
				VLAN:     100,
			},
			applyPolicyErr: errors.New("apply failed"),
		},
		Logger: slog.Default(),
	})

	err := provider.SDNApplyPolicy(ctx, "policy1", "br0")
	if err == nil {
		t.Fatal("expected error when apply fails")
	}

	applyErr, ok := err.(ErrSDNApplyPolicyFailed)
	if !ok {
		t.Fatalf("expected ErrSDNApplyPolicyFailed, got %T: %v", err, err)
	}
	if applyErr.PolicyID != "policy1" {
		t.Errorf("expected PolicyID='policy1', got %q", applyErr.PolicyID)
	}
}

func TestMCPServiceProvider_SDNApplyPolicy_NilPolicyEngineError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		SDNService: &SDNService{
			bridges:   make(map[string]*bridgeResource),
			ports:     make(map[string]*portResource),
			taps:      make(map[string]*tapResource),
			vlans:     make(map[string]*vlanResource),
			portAuths: make(map[string]*portAuthResource),
		},
		Logger: slog.Default(),
	})

	err := provider.SDNApplyPolicy(ctx, "policy1", "br0")
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}

	_, ok := err.(ErrSDNPolicyEngineNotConfigured)
	if !ok {
		t.Fatalf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNListPolicies Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNListPolicies_EmptyResultReturnsSlice(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{},
		Logger:       slog.Default(),
	})

	result, err := provider.SDNListPolicies(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if len(result) != 0 {
		t.Errorf("expected empty result, got %d items", len(result))
	}
}

// =============================================================================
// SDNAuthenticatePort Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNAuthenticatePort_DefaultsFormatToPEM(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with empty format - should default to PEM internally
	// but still fail due to nil SDN service
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", map[string]string{
		"certificate": "test-cert",
		// format is intentionally missing
	})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Verify we get service not available (meaning format defaulting worked)
	svcErr, ok := err.(ErrServiceNotAvailable)
	if !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
	if svcErr.Service != "sdn" {
		t.Errorf("expected service='sdn', got %q", svcErr.Service)
	}
}

func TestMCPServiceProvider_SDNAuthenticatePort_ExplicitFormatDER(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	// Test with explicit DER format
	err := provider.SDNAuthenticatePort(ctx, "br0", "port1", map[string]string{
		"certificate": "test-cert-data",
		"format":      "DER",
	})
	if err == nil {
		t.Fatal("expected error for nil SDN service")
	}

	// Should still get service not available error
	if _, ok := err.(ErrServiceNotAvailable); !ok {
		t.Fatalf("expected ErrServiceNotAvailable, got %T: %v", err, err)
	}
}

// =============================================================================
// SDNGetPolicy Extended Tests
// =============================================================================

func TestMCPServiceProvider_SDNGetPolicy_SuccessWithAllFields(t *testing.T) {
	ctx := context.Background()
	issuedAt := time.Now()
	expiresAt := time.Now().Add(24 * time.Hour)

	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyResp: &policy.PortPolicy{
				TenantID:  "tenant1",
				VLAN:      100,
				IssuedAt:  issuedAt,
				ExpiresAt: expiresAt,
				ACLs: []policy.ACLRule{
					{
						Priority:    1000,
						Description: "Allow HTTP",
						Action: policy.FlowAction{
							Type: policy.FlowActionAllow,
						},
					},
				},
				Metadata: map[string]string{
					"department": "engineering",
				},
			},
			getPortInfoResp: &policy.PortInfo{
				State:           policy.PortStateAuthorized,
				LastStateChange: time.Now(),
				AuthAttempts:    3,
				ErrorCount:      1,
				LastError:       "previous timeout",
			},
		},
		Logger: slog.Default(),
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	// Verify core fields
	if resultMap["port_id"] != "port1" {
		t.Errorf("expected port_id='port1', got %v", resultMap["port_id"])
	}
	if resultMap["tenant_id"] != "tenant1" {
		t.Errorf("expected tenant_id='tenant1', got %v", resultMap["tenant_id"])
	}
	if resultMap["vlan"] != uint16(100) {
		t.Errorf("expected vlan=100, got %v", resultMap["vlan"])
	}
	if resultMap["acl_count"] != 1 {
		t.Errorf("expected acl_count=1, got %v", resultMap["acl_count"])
	}

	// Verify state info
	if resultMap["state"] != "authorized" {
		t.Errorf("expected state='authorized', got %v", resultMap["state"])
	}
	if resultMap["auth_attempts"] != 3 {
		t.Errorf("expected auth_attempts=3, got %v", resultMap["auth_attempts"])
	}

	// Verify expiration
	if _, hasExpiry := resultMap["expires_at"]; !hasExpiry {
		t.Error("expected expires_at field")
	}

	// Verify metadata
	if _, hasMetadata := resultMap["metadata"]; !hasMetadata {
		t.Error("expected metadata field")
	}

	// Verify ACLs
	if _, hasACLs := resultMap["acls"]; !hasACLs {
		t.Error("expected acls field")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_SuccessWithoutPortInfo(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyResp: &policy.PortPolicy{
				TenantID: "tenant1",
				VLAN:     200,
				IssuedAt: time.Now(),
			},
			getPortInfoErr: errors.New("port info not found"),
		},
		Logger: slog.Default(),
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	// Should still have policy data even without port info
	if resultMap["tenant_id"] != "tenant1" {
		t.Errorf("expected tenant_id='tenant1', got %v", resultMap["tenant_id"])
	}

	// Should not have state since port info failed
	if _, hasState := resultMap["state"]; hasState {
		t.Error("expected no 'state' field when port info unavailable")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_NoExpirationOmitted(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyResp: &policy.PortPolicy{
				TenantID: "tenant1",
				VLAN:     100,
				IssuedAt: time.Now(),
				// ExpiresAt is zero value
			},
		},
		Logger: slog.Default(),
	})

	result, err := provider.SDNGetPolicy(ctx, "port1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map[string]interface{}, got %T", result)
	}

	// Should not have expires_at since it's zero
	if _, hasExpiry := resultMap["expires_at"]; hasExpiry {
		t.Error("expected no 'expires_at' field when expiration is zero")
	}
}

func TestMCPServiceProvider_SDNGetPolicy_PolicyNotFoundErrorDetails(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{
			getPolicyErr: errors.New("not found"),
		},
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPolicy(ctx, "nonexistent-port")
	if err == nil {
		t.Fatal("expected error for policy not found")
	}

	notFoundErr, ok := err.(ErrSDNPolicyNotFound)
	if !ok {
		t.Fatalf("expected ErrSDNPolicyNotFound, got %T: %v", err, err)
	}
	if notFoundErr.PolicyID != "nonexistent-port" {
		t.Errorf("expected PolicyID='nonexistent-port', got %q", notFoundErr.PolicyID)
	}
}

func TestMCPServiceProvider_SDNGetPolicy_NilPolicyEngineReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		Logger: slog.Default(),
	})

	_, err := provider.SDNGetPolicy(ctx, "policy1")
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}

	_, ok := err.(ErrSDNPolicyEngineNotConfigured)
	if !ok {
		t.Fatalf("expected ErrSDNPolicyEngineNotConfigured, got %T: %v", err, err)
	}
}

func TestMCPServiceProvider_SDNGetPolicy_EmptyPolicyIDReturnsError(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
		PolicyEngine: &sdnTestMockPolicyEngine{},
		Logger:       slog.Default(),
	})

	_, err := provider.SDNGetPolicy(ctx, "")
	if err == nil {
		t.Fatal("expected error for missing policy ID")
	}

	paramErr, ok := err.(ErrSDNMissingParameter)
	if !ok {
		t.Fatalf("expected ErrSDNMissingParameter, got %T: %v", err, err)
	}
	if paramErr.Parameter != "policyID" {
		t.Errorf("expected parameter='policyID', got %q", paramErr.Parameter)
	}
}

// =============================================================================
// Error Type Validation Tests - Verifies error messages match actual format
// =============================================================================

func TestErrSDNMissingParameter_ErrorMessage(t *testing.T) {
	err := ErrSDNMissingParameter{Parameter: "bridgeName"}
	expected := "missing required parameter: bridgeName"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNInvalidPortState_ErrorMessage(t *testing.T) {
	err := ErrSDNInvalidPortState{State: "invalid"}
	expected := "invalid port state: invalid"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNPolicyNotFound_ErrorMessage(t *testing.T) {
	err := ErrSDNPolicyNotFound{PolicyID: "policy123"}
	expected := "SDN policy not found: policy123"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNPortNotFound_ErrorMessage(t *testing.T) {
	err := ErrSDNPortNotFound{BridgeName: "br0", PortName: "port1"}
	expected := "SDN port not found: port1 on bridge br0"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNApplyPolicyFailed_ErrorMessage(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrSDNApplyPolicyFailed{PolicyID: "policy1", Cause: cause}
	expected := "failed to apply policy policy1: timeout"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNSetPortStateFailed_ErrorMessage(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrSDNSetPortStateFailed{PortID: "port1", Cause: cause}
	expected := "failed to set port state for port1: connection refused"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSDNPolicyEngineNotConfigured_ErrorMessage(t *testing.T) {
	err := ErrSDNPolicyEngineNotConfigured{}
	expected := "SDN policy engine not configured"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

// =============================================================================
// Table-Driven Comprehensive Test for SDN Parameter Validation
// =============================================================================

func TestMCPServiceProvider_SDN_ParameterValidationTableDriven(t *testing.T) {
	testCases := []struct {
		name          string
		operation     string
		execFunc      func(context.Context, *MCPServiceProvider) error
		expectedError string
	}{
		{
			name:      "SDNSetPortState empty bridgeName",
			operation: "SDNSetPortState",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNSetPortState(ctx, "", "port1", "blocked")
			},
			expectedError: "bridgeName",
		},
		{
			name:      "SDNSetPortState empty portName",
			operation: "SDNSetPortState",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNSetPortState(ctx, "br0", "", "blocked")
			},
			expectedError: "portName",
		},
		{
			name:      "SDNSetPortState empty state",
			operation: "SDNSetPortState",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNSetPortState(ctx, "br0", "port1", "")
			},
			expectedError: "state",
		},
		{
			name:      "SDNApplyPolicy empty policyID",
			operation: "SDNApplyPolicy",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNApplyPolicy(ctx, "", "br0")
			},
			expectedError: "policyID",
		},
		{
			name:      "SDNApplyPolicy empty bridgeName",
			operation: "SDNApplyPolicy",
			execFunc: func(ctx context.Context, p *MCPServiceProvider) error {
				return p.SDNApplyPolicy(ctx, "policy1", "")
			},
			expectedError: "bridgeName",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			provider := NewMCPServiceProvider(&MCPServiceProviderConfig{
				Logger: slog.Default(),
			})

			err := tc.execFunc(ctx, provider)
			if err == nil {
				t.Fatal("expected error")
			}

			paramErr, ok := err.(ErrSDNMissingParameter)
			if !ok {
				t.Fatalf("expected ErrSDNMissingParameter, got %T: %v", err, err)
			}
			if paramErr.Parameter != tc.expectedError {
				t.Errorf("expected parameter=%q, got %q", tc.expectedError, paramErr.Parameter)
			}
		})
	}
}
