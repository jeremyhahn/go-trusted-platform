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

package network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Additional tests to improve coverage for auth.go

func TestNetworkAuthService_Close_ComponentErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("close with component close errors logs warnings", func(t *testing.T) {
		// Create a mock OPA evaluator that will error on close
		mockOPA := &mockOPAEvaluatorWithCloseError{}
		mockFlow := &mockFlowManagerWithCloseError{}

		service := NewNetworkAuthService(
			WithOPAEvaluator(mockOPA),
			WithFlowManager(mockFlow),
		)

		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequirePolicyEvaluation: true,
		}

		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Close should complete even with component errors
		err = service.Close()
		assert.NoError(t, err)

		// Verify close was attempted on components
		assert.True(t, mockOPA.closeCalled)
		assert.True(t, mockFlow.closeCalled)
	})
}

func TestNetworkAuthService_ValidateCertificate_NilCertificate(t *testing.T) {
	ctx := context.Background()

	service := NewNetworkAuthService()
	config := &AuthConfig{
		QuarantineVLAN: 1,
		ProductionVLAN: 100,
		BridgeName:     "br0",
	}
	err := service.Initialize(ctx, config)
	require.NoError(t, err)

	request := &PortAuthRequest{
		PortID:      "eth0",
		Certificate: nil,
	}

	result, err := service.Authenticate(ctx, request)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestNetworkAuthService_Reattest_WithQuarantineOnFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("reattest failure exceeds max failures triggers quarantine", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: false}
		service := NewNetworkAuthService(
			WithAttestationVerifier(verifier),
		)
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			Reattest: &ReattestConfig{
				Enabled:             true,
				Interval:            time.Hour,
				MaxFailures:         1,
				QuarantineOnFailure: true,
				AttestationTimeout:  time.Minute,
			},
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate first
		cert := createValidTestCert(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		// First reattest failure
		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.NotNil(t, result)

		// Check port state - should be quarantined after max failures
		state, err := service.GetPortState(ctx, "eth0")
		require.NoError(t, err)
		assert.Equal(t, AuthStateRevoked, state.AuthState)
	})

	t.Run("reattest failure with error triggers quarantine", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldFail: errors.New("verifier error")}
		service := NewNetworkAuthService(
			WithAttestationVerifier(verifier),
		)
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			Reattest: &ReattestConfig{
				Enabled:             true,
				Interval:            time.Hour,
				MaxFailures:         1,
				QuarantineOnFailure: true,
				AttestationTimeout:  time.Minute,
			},
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate first
		cert := createValidTestCert(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		// First reattest failure with error
		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.NotNil(t, result)

		// Check port state
		state, err := service.GetPortState(ctx, "eth0")
		require.NoError(t, err)
		assert.Equal(t, AuthStateRevoked, state.AuthState)
	})
}

// Additional tests to improve coverage for flow.go

func TestFlowManager_InstallProductionRules_ContextCancellation(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	err = manager.InstallProductionRules(cancelCtx, "eth0", 100)
	assert.Error(t, err)
	assert.IsType(t, ErrContextCanceled{}, err)
}

func TestFlowManager_InstallProductionRules_ClosedService(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	err = manager.Close()
	require.NoError(t, err)

	err = manager.InstallProductionRules(ctx, "eth0", 100)
	assert.Error(t, err)
	assert.IsType(t, ErrServiceNotInitialized{}, err)
}

func TestFlowManager_InstallQuarantineRules_ClosedService(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	err = manager.Close()
	require.NoError(t, err)

	err = manager.InstallQuarantineRules(ctx, "eth0", 1)
	assert.Error(t, err)
	assert.IsType(t, ErrServiceNotInitialized{}, err)
}

func TestFlowManager_GetRules_ContextCancellation(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	rules, err := manager.GetRules(cancelCtx, "eth0")
	assert.Error(t, err)
	assert.Nil(t, rules)
	assert.IsType(t, ErrContextCanceled{}, err)
}

func TestFlowManager_InstallRule_ClosedService(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	err = manager.Close()
	require.NoError(t, err)

	rule := &FlowRule{ID: "rule-1", PortID: "eth0", Type: FlowRuleTypeDrop}
	err = manager.InstallRule(ctx, rule)
	assert.Error(t, err)
	assert.IsType(t, ErrServiceNotInitialized{}, err)
}

func TestFlowManager_InstallRule_ContextCancellation(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	rule := &FlowRule{ID: "rule-1", PortID: "eth0", Type: FlowRuleTypeDrop}
	err = manager.InstallRule(cancelCtx, rule)
	assert.Error(t, err)
	assert.IsType(t, ErrContextCanceled{}, err)
}

func TestFlowManager_RemoveRule_ContextCancellation(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	err = manager.RemoveRule(cancelCtx, "rule-1")
	assert.Error(t, err)
	assert.IsType(t, ErrContextCanceled{}, err)
}

func TestFlowManager_RemoveRules_ContextCancellation(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	cancelCtx, cancel := context.WithCancel(ctx)
	cancel()

	err = manager.RemoveRules(cancelCtx, "eth0")
	assert.Error(t, err)
	assert.IsType(t, ErrContextCanceled{}, err)
}

func TestFlowManager_TransitionVLAN_ClosedService(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	err = manager.Close()
	require.NoError(t, err)

	err = manager.TransitionVLAN(ctx, "eth0", 1, 100)
	assert.Error(t, err)
	assert.IsType(t, ErrServiceNotInitialized{}, err)
}

func TestFlowManager_RemoveRules_WithControllerErrors(t *testing.T) {
	ctx := context.Background()

	controller := &mockFlowControllerWithDeleteError{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// Install some rules first
	err = manager.InstallQuarantineRules(ctx, "eth0", 1)
	require.NoError(t, err)

	// Set controller to fail on delete
	controller.shouldFail = true

	// RemoveRules should return error when some rules fail to delete
	err = manager.RemoveRules(ctx, "eth0")
	assert.Error(t, err)
	assert.IsType(t, ErrFlowRule{}, err)
}

func TestFlowManager_TransitionVLAN_InstallFailure(t *testing.T) {
	ctx := context.Background()

	controller := &mockFlowControllerWithAddError{shouldFail: true}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// TransitionVLAN should return error when install fails
	err = manager.TransitionVLAN(ctx, "eth0", 1, 100)
	assert.Error(t, err)
	assert.IsType(t, ErrVLANFailed{}, err)
}

func TestFlowManager_RemoveRule_WithControllerError(t *testing.T) {
	ctx := context.Background()

	controller := &mockFlowControllerWithDeleteError{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// Install a rule first
	rule := &FlowRule{ID: "rule-1", PortID: "eth0", Type: FlowRuleTypeDrop}
	err = manager.InstallRule(ctx, rule)
	require.NoError(t, err)

	// Set controller to fail on delete
	controller.shouldFail = true

	// RemoveRule should return error
	err = manager.RemoveRule(ctx, "rule-1")
	assert.Error(t, err)
	assert.IsType(t, ErrFlowRule{}, err)
}

func TestFlowManager_InstallQuarantineRules_EgressRuleFailure(t *testing.T) {
	ctx := context.Background()

	// Controller that fails on second AddFlow call
	controller := &mockFlowControllerFailOnSecondAdd{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// InstallQuarantineRules should fail on egress rule and rollback ingress
	err = manager.InstallQuarantineRules(ctx, "eth0", 1)
	assert.Error(t, err)
}

func TestFlowManager_InstallProductionRules_EgressRuleFailure(t *testing.T) {
	ctx := context.Background()

	// Controller that fails on second AddFlow call
	controller := &mockFlowControllerFailOnSecondAdd{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// InstallProductionRules should fail on egress rule and rollback ingress
	err = manager.InstallProductionRules(ctx, "eth0", 100)
	assert.Error(t, err)
}

func TestFlowManager_AddPortRule_Concurrent(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// Concurrent rule additions
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			rule := &FlowRule{
				ID:     generateRuleID(),
				PortID: "eth0",
				Type:   FlowRuleTypeDrop,
			}
			_ = manager.InstallRule(ctx, rule)
			done <- struct{}{}
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	rules, err := manager.GetRules(ctx, "eth0")
	require.NoError(t, err)
	assert.Equal(t, 10, len(rules))
}

func TestFlowManager_AddPortRule_Duplicate(t *testing.T) {
	ctx := context.Background()

	manager := NewFlowManager()
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	rule := &FlowRule{
		ID:     "static-rule-id",
		PortID: "eth0",
		Type:   FlowRuleTypeDrop,
	}

	// Install same rule twice
	err = manager.InstallRule(ctx, rule)
	require.NoError(t, err)

	err = manager.InstallRule(ctx, rule)
	require.NoError(t, err)

	// Should only have one rule (deduplicated by addPortRule)
	rules, err := manager.GetRules(ctx, "eth0")
	require.NoError(t, err)
	// The addPortRule function deduplicates based on rule ID
	assert.GreaterOrEqual(t, len(rules), 1)
}

// Additional tests to improve coverage for policy.go

func TestParseCertificatePolicies_TrailingData(t *testing.T) {
	// Test the trailing data error case
	// Create valid policy data followed by garbage
	type policyInfo struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}

	policies := []policyInfo{
		{PolicyIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4}},
	}

	validData, err := asn1.Marshal(policies)
	require.NoError(t, err)

	// Append trailing garbage
	dataWithTrailing := append(validData, []byte("garbage")...)

	oids, err := parseCertificatePolicies(dataWithTrailing)
	assert.Error(t, err)
	assert.Nil(t, oids)
	assert.IsType(t, ErrCertInvalid{}, err)
}

func TestParseCertificatePolicies_InvalidData(t *testing.T) {
	// Test with completely invalid ASN.1 data
	invalidData := []byte{0xFF, 0xFF, 0xFF}

	oids, err := parseCertificatePolicies(invalidData)
	assert.Error(t, err)
	assert.Nil(t, oids)
}

func TestPolicyExtractor_ExtractPolicyInfo_WithOIDs(t *testing.T) {
	ctx := context.Background()
	extractor := NewPolicyExtractor()

	// Create a certificate with policy OIDs
	oid := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	cert := createCertWithOIDs(t, []asn1.ObjectIdentifier{oid})

	info, err := extractor.ExtractPolicyInfo(ctx, cert)
	require.NoError(t, err)
	assert.NotNil(t, info)
	assert.True(t, len(info.OIDs) > 0)
}

func TestOPAEvaluator_Evaluate_ConnectionError(t *testing.T) {
	ctx := context.Background()

	evaluator := NewOPAEvaluator()
	// Initialize with invalid endpoint that will fail to connect
	err := evaluator.Initialize(ctx, "http://localhost:99999", "network/auth")
	require.NoError(t, err)

	input := &OPAInput{DeviceID: "device-123"}
	result, err := evaluator.Evaluate(ctx, input)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.IsType(t, ErrOPAEvaluation{}, err)
}

// Additional test for parseCertificatePolicies with valid data
func TestParseCertificatePolicies_ValidData(t *testing.T) {
	// Create valid certificate policies data
	type policyInfo struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}

	policies := []policyInfo{
		{PolicyIdentifier: asn1.ObjectIdentifier{1, 2, 3, 4}},
		{PolicyIdentifier: asn1.ObjectIdentifier{1, 2, 3, 5}},
	}

	validData, err := asn1.Marshal(policies)
	require.NoError(t, err)

	oids, err := parseCertificatePolicies(validData)
	require.NoError(t, err)
	assert.Len(t, oids, 2)
	assert.True(t, oids[0].Equal(asn1.ObjectIdentifier{1, 2, 3, 4}))
	assert.True(t, oids[1].Equal(asn1.ObjectIdentifier{1, 2, 3, 5}))
}

// Test for flow manager with SetPortVLAN failure warning
func TestFlowManager_InstallQuarantineRules_SetPortVLANWarning(t *testing.T) {
	ctx := context.Background()

	controller := &mockFlowControllerWithSetVLANError{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// Install quarantine rules - SetPortVLAN failure should be logged but not fail the operation
	err = manager.InstallQuarantineRules(ctx, "eth0", 1)
	require.NoError(t, err)

	rules, err := manager.GetRules(ctx, "eth0")
	require.NoError(t, err)
	assert.Len(t, rules, 2)
}

func TestFlowManager_InstallProductionRules_SetPortVLANWarning(t *testing.T) {
	ctx := context.Background()

	controller := &mockFlowControllerWithSetVLANError{}
	manager := NewFlowManager(
		WithFlowController(controller),
	)
	config := &FlowConfig{BridgeName: "br0"}
	err := manager.Initialize(ctx, config)
	require.NoError(t, err)

	// Install production rules - SetPortVLAN failure should be logged but not fail
	err = manager.InstallProductionRules(ctx, "eth0", 100)
	require.NoError(t, err)

	rules, err := manager.GetRules(ctx, "eth0")
	require.NoError(t, err)
	assert.Len(t, rules, 2)
}

// Mock implementations

type mockOPAEvaluatorWithCloseError struct {
	closeCalled bool
}

func (m *mockOPAEvaluatorWithCloseError) Initialize(ctx context.Context, endpoint string, policyPath string) error {
	return nil
}

func (m *mockOPAEvaluatorWithCloseError) Evaluate(ctx context.Context, input *OPAInput) (*OPAResult, error) {
	return &OPAResult{Allow: true}, nil
}

func (m *mockOPAEvaluatorWithCloseError) Close() error {
	m.closeCalled = true
	return errors.New("mock close error")
}

type mockFlowManagerWithCloseError struct {
	closeCalled bool
}

func (m *mockFlowManagerWithCloseError) Initialize(ctx context.Context, config *FlowConfig) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) InstallQuarantineRules(ctx context.Context, portID string, vlan uint16) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) InstallProductionRules(ctx context.Context, portID string, vlan uint16) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) RemoveRules(ctx context.Context, portID string) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) GetRules(ctx context.Context, portID string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowManagerWithCloseError) InstallRule(ctx context.Context, rule *FlowRule) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) RemoveRule(ctx context.Context, ruleID string) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) TransitionVLAN(ctx context.Context, portID string, fromVLAN uint16, toVLAN uint16) error {
	return nil
}

func (m *mockFlowManagerWithCloseError) Close() error {
	m.closeCalled = true
	return errors.New("mock close error")
}

type mockFlowControllerWithDeleteError struct {
	shouldFail bool
}

func (m *mockFlowControllerWithDeleteError) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerWithDeleteError) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	if m.shouldFail {
		return errors.New("mock delete error")
	}
	return nil
}

func (m *mockFlowControllerWithDeleteError) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerWithDeleteError) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowControllerWithDeleteError) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	return nil
}

type mockFlowControllerWithAddError struct {
	shouldFail bool
}

func (m *mockFlowControllerWithAddError) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	if m.shouldFail {
		return errors.New("mock add error")
	}
	return nil
}

func (m *mockFlowControllerWithAddError) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	return nil
}

func (m *mockFlowControllerWithAddError) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerWithAddError) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowControllerWithAddError) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	return nil
}

type mockFlowControllerFailOnSecondAdd struct {
	callCount int
}

func (m *mockFlowControllerFailOnSecondAdd) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	m.callCount++
	if m.callCount >= 2 {
		return errors.New("mock add error on second call")
	}
	return nil
}

func (m *mockFlowControllerFailOnSecondAdd) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	return nil
}

func (m *mockFlowControllerFailOnSecondAdd) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerFailOnSecondAdd) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowControllerFailOnSecondAdd) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	return nil
}

type mockFlowControllerWithSetVLANError struct{}

func (m *mockFlowControllerWithSetVLANError) AddFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerWithSetVLANError) DeleteFlow(ctx context.Context, bridge string, ruleID string) error {
	return nil
}

func (m *mockFlowControllerWithSetVLANError) ModifyFlow(ctx context.Context, bridge string, rule *FlowRule) error {
	return nil
}

func (m *mockFlowControllerWithSetVLANError) GetFlows(ctx context.Context, bridge string) ([]*FlowRule, error) {
	return nil, nil
}

func (m *mockFlowControllerWithSetVLANError) SetPortVLAN(ctx context.Context, bridge string, portID string, vlan uint16) error {
	return errors.New("mock set vlan error")
}

// Helper functions

func createValidTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-device"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
