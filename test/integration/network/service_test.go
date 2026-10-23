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

//go:build integration

// Package network provides integration tests for the network authentication service.
// These tests verify the NetworkAuthService works correctly with real OVS and OPA.
package network

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/network"
)

// TestNetworkAuthServiceIntegration tests the full authentication flow.
func TestNetworkAuthServiceIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create mock components for testing without full infrastructure
	mockOPA := newMockOPAEvaluator(true, 100) // Allow access, assign VLAN 100
	mockFlow := newMockFlowManager()
	mockAttest := newMockAttestationVerifier(true)

	service := network.NewNetworkAuthService(
		network.WithOPAEvaluator(mockOPA),
		network.WithFlowManager(mockFlow),
		network.WithAttestationVerifier(mockAttest),
	)

	config := &network.AuthConfig{
		QuarantineVLAN:          1,
		ProductionVLAN:          100,
		BridgeName:              "br-test",
		RequireAttestation:      true,
		RequirePolicyEvaluation: true,
		SessionTimeout:          time.Hour,
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	t.Run("full authentication flow", func(t *testing.T) {
		cert, _ := generateTestCert(t, "test-device-001")

		request := &network.PortAuthRequest{
			PortID:      "port-001",
			Certificate: cert,
			Nonce:       make([]byte, 32),
		}
		rand.Read(request.Nonce)

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, network.AuthStateAuthorized, result.State)
		assert.Equal(t, uint16(100), result.VLAN)
		assert.NotEmpty(t, result.SessionID)
		assert.True(t, result.AttestationVerified)
		assert.True(t, result.PolicyEvaluated)
		assert.True(t, result.PolicyDecision)
		assert.True(t, result.FlowRulesInstalled)
	})

	t.Run("get port state after authentication", func(t *testing.T) {
		state, err := service.GetPortState(ctx, "port-001")
		require.NoError(t, err)
		assert.Equal(t, network.AuthStateAuthorized, state.AuthState)
		assert.Equal(t, uint16(100), state.VLAN)
	})

	t.Run("get all ports", func(t *testing.T) {
		ports, err := service.GetAllPorts(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(ports), 1)
	})

	t.Run("re-attestation", func(t *testing.T) {
		nonce := make([]byte, 32)
		rand.Read(nonce)

		result, err := service.Reattest(ctx, "port-001", nonce)
		require.NoError(t, err)
		assert.True(t, result.AttestationVerified)
		assert.Equal(t, network.AuthStateAuthorized, result.State)
	})

	t.Run("revocation", func(t *testing.T) {
		err := service.Revoke(ctx, "port-001", "test revocation")
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "port-001")
		require.NoError(t, err)
		assert.Equal(t, network.AuthStateRevoked, state.AuthState)
		assert.Equal(t, uint16(1), state.VLAN) // Back to quarantine
	})
}

// TestNetworkAuthServicePolicyDenied tests authentication when policy denies access.
func TestNetworkAuthServicePolicyDenied(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Create OPA evaluator that denies access
	mockOPA := newMockOPAEvaluator(false, 0)
	mockFlow := newMockFlowManager()

	service := network.NewNetworkAuthService(
		network.WithOPAEvaluator(mockOPA),
		network.WithFlowManager(mockFlow),
	)

	config := &network.AuthConfig{
		QuarantineVLAN:          1,
		ProductionVLAN:          100,
		BridgeName:              "br-test",
		RequirePolicyEvaluation: true,
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	cert, _ := generateTestCert(t, "test-device-denied")

	request := &network.PortAuthRequest{
		PortID:      "port-denied",
		Certificate: cert,
		Nonce:       make([]byte, 32),
	}

	result, err := service.Authenticate(ctx, request)
	assert.Error(t, err)

	var policyErr network.ErrPolicyViolation
	assert.ErrorAs(t, err, &policyErr)
	assert.Equal(t, network.AuthStateQuarantine, result.State)
	assert.Equal(t, uint16(1), result.VLAN) // Stays in quarantine
}

// TestNetworkAuthServiceAttestationFailed tests authentication when attestation fails.
func TestNetworkAuthServiceAttestationFailed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Create attestation verifier that fails
	mockAttest := newMockAttestationVerifier(false)
	mockFlow := newMockFlowManager()

	service := network.NewNetworkAuthService(
		network.WithAttestationVerifier(mockAttest),
		network.WithFlowManager(mockFlow),
	)

	config := &network.AuthConfig{
		QuarantineVLAN:     1,
		ProductionVLAN:     100,
		BridgeName:         "br-test",
		RequireAttestation: true,
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	cert, _ := generateTestCert(t, "test-device-attest-fail")

	request := &network.PortAuthRequest{
		PortID:      "port-attest-fail",
		Certificate: cert,
		Nonce:       make([]byte, 32),
	}

	result, err := service.Authenticate(ctx, request)
	assert.Error(t, err)

	var attestErr network.ErrAttestFailed
	assert.ErrorAs(t, err, &attestErr)
	assert.Equal(t, network.AuthStateQuarantine, result.State)
}

// TestNetworkAuthServiceCertificateExpired tests authentication with expired certificate.
func TestNetworkAuthServiceCertificateExpired(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	mockFlow := newMockFlowManager()

	service := network.NewNetworkAuthService(
		network.WithFlowManager(mockFlow),
	)

	config := &network.AuthConfig{
		QuarantineVLAN: 1,
		ProductionVLAN: 100,
		BridgeName:     "br-test",
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	// Generate expired certificate
	cert := generateExpiredCert(t, "expired-device")

	request := &network.PortAuthRequest{
		PortID:      "port-expired",
		Certificate: cert,
	}

	result, err := service.Authenticate(ctx, request)
	assert.Error(t, err)

	var certErr network.ErrCertInvalid
	assert.ErrorAs(t, err, &certErr)
	assert.Equal(t, network.AuthStateQuarantine, result.State)
}

// TestNetworkAuthServiceConcurrentAuthentication tests concurrent authentication requests.
func TestNetworkAuthServiceConcurrentAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	mockOPA := newMockOPAEvaluator(true, 100)
	mockFlow := newMockFlowManager()
	mockAttest := newMockAttestationVerifier(true)

	service := network.NewNetworkAuthService(
		network.WithOPAEvaluator(mockOPA),
		network.WithFlowManager(mockFlow),
		network.WithAttestationVerifier(mockAttest),
	)

	config := &network.AuthConfig{
		QuarantineVLAN:          1,
		ProductionVLAN:          100,
		BridgeName:              "br-test",
		RequireAttestation:      true,
		RequirePolicyEvaluation: true,
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	const numConcurrent = 50
	results := make(chan error, numConcurrent)

	// Pre-generate certificates to avoid concurrent access to testing.T
	// and crypto/rand contention
	type authRequest struct {
		portID string
		cert   *x509.Certificate
		nonce  []byte
	}
	requests := make([]authRequest, numConcurrent)
	for i := 0; i < numConcurrent; i++ {
		cert, _ := generateTestCert(t, "concurrent-device")
		nonce := make([]byte, 32)
		rand.Read(nonce)
		requests[i] = authRequest{
			portID: GenerateUniquePortID("concurrent"),
			cert:   cert,
			nonce:  nonce,
		}
	}

	// Run authentications concurrently
	for i := 0; i < numConcurrent; i++ {
		go func(req authRequest) {
			request := &network.PortAuthRequest{
				PortID:      req.portID,
				Certificate: req.cert,
				Nonce:       req.nonce,
			}
			_, err := service.Authenticate(ctx, request)
			results <- err
		}(requests[i])
	}

	var successCount int
	for i := 0; i < numConcurrent; i++ {
		if err := <-results; err == nil {
			successCount++
		}
	}

	assert.Equal(t, numConcurrent, successCount, "All concurrent authentications should succeed")

	// Verify all ports were tracked
	ports, err := service.GetAllPorts(ctx)
	require.NoError(t, err)
	assert.Equal(t, numConcurrent, len(ports))
}

// TestNetworkAuthServiceVLANTransitions tests VLAN transitions through lifecycle.
func TestNetworkAuthServiceVLANTransitions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	mockOPA := newMockOPAEvaluator(true, 200) // Assign VLAN 200
	mockFlow := newMockFlowManager()

	service := network.NewNetworkAuthService(
		network.WithOPAEvaluator(mockOPA),
		network.WithFlowManager(mockFlow),
	)

	config := &network.AuthConfig{
		QuarantineVLAN:          1,
		ProductionVLAN:          100,
		BridgeName:              "br-test",
		RequirePolicyEvaluation: true,
	}

	err := service.Initialize(ctx, config)
	require.NoError(t, err)
	defer service.Close()

	cert, _ := generateTestCert(t, "vlan-test-device")

	// Initial authentication - should get VLAN 200 from policy
	request := &network.PortAuthRequest{
		PortID:      "port-vlan-test",
		Certificate: cert,
	}

	result, err := service.Authenticate(ctx, request)
	require.NoError(t, err)
	assert.Equal(t, uint16(200), result.VLAN, "Should use policy-assigned VLAN")

	// Verify flow manager received correct VLAN
	assert.Equal(t, uint16(200), mockFlow.lastProductionVLAN)

	// Revoke - should transition back to quarantine VLAN
	err = service.Revoke(ctx, "port-vlan-test", "vlan transition test")
	require.NoError(t, err)

	state, err := service.GetPortState(ctx, "port-vlan-test")
	require.NoError(t, err)
	assert.Equal(t, uint16(1), state.VLAN, "Should be back in quarantine VLAN")
}

// =============================================================================
// Mock Components
// =============================================================================

// mockOPAEvaluator implements network.OPAEvaluator for testing.
type mockOPAEvaluator struct {
	allow        bool
	assignedVLAN uint16
}

func newMockOPAEvaluator(allow bool, assignedVLAN uint16) *mockOPAEvaluator {
	return &mockOPAEvaluator{
		allow:        allow,
		assignedVLAN: assignedVLAN,
	}
}

func (m *mockOPAEvaluator) Initialize(ctx context.Context, endpoint, policyPath string) error {
	return nil
}

func (m *mockOPAEvaluator) Evaluate(ctx context.Context, input *network.OPAInput) (*network.OPAResult, error) {
	result := &network.OPAResult{
		Allow:        m.allow,
		AssignedVLAN: m.assignedVLAN,
	}
	if !m.allow {
		result.Reasons = []string{"policy denied access"}
	}
	return result, nil
}

func (m *mockOPAEvaluator) Close() error {
	return nil
}

// mockFlowManager implements network.FlowManager for testing.
type mockFlowManager struct {
	mu                 sync.Mutex
	productionRules    map[string]uint16
	quarantineRules    map[string]uint16
	customRules        map[string]*network.FlowRule
	lastProductionVLAN uint16
}

func newMockFlowManager() *mockFlowManager {
	return &mockFlowManager{
		productionRules: make(map[string]uint16),
		quarantineRules: make(map[string]uint16),
		customRules:     make(map[string]*network.FlowRule),
	}
}

func (m *mockFlowManager) Initialize(ctx context.Context, config *network.FlowConfig) error {
	return nil
}

func (m *mockFlowManager) InstallProductionRules(ctx context.Context, portID string, vlan uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.productionRules[portID] = vlan
	m.lastProductionVLAN = vlan
	delete(m.quarantineRules, portID)
	return nil
}

func (m *mockFlowManager) InstallQuarantineRules(ctx context.Context, portID string, vlan uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quarantineRules[portID] = vlan
	delete(m.productionRules, portID)
	return nil
}

func (m *mockFlowManager) RemoveRules(ctx context.Context, portID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.productionRules, portID)
	delete(m.quarantineRules, portID)
	// Also remove custom rules for this port
	for id, rule := range m.customRules {
		if rule.PortID == portID {
			delete(m.customRules, id)
		}
	}
	return nil
}

func (m *mockFlowManager) GetRules(ctx context.Context, portID string) ([]*network.FlowRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rules []*network.FlowRule
	for _, rule := range m.customRules {
		if rule.PortID == portID {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (m *mockFlowManager) InstallRule(ctx context.Context, rule *network.FlowRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customRules[rule.ID] = rule
	return nil
}

func (m *mockFlowManager) RemoveRule(ctx context.Context, ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.customRules, ruleID)
	return nil
}

func (m *mockFlowManager) TransitionVLAN(ctx context.Context, portID string, fromVLAN uint16, toVLAN uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Simulate VLAN transition by updating the production/quarantine rules
	if toVLAN == 1 {
		// Moving to quarantine
		m.quarantineRules[portID] = toVLAN
		delete(m.productionRules, portID)
	} else {
		// Moving to production
		m.productionRules[portID] = toVLAN
		m.lastProductionVLAN = toVLAN
		delete(m.quarantineRules, portID)
	}
	return nil
}

func (m *mockFlowManager) Close() error {
	return nil
}

// mockAttestationVerifier implements network.AttestationVerifier for testing.
type mockAttestationVerifier struct {
	shouldVerify bool
}

func newMockAttestationVerifier(shouldVerify bool) *mockAttestationVerifier {
	return &mockAttestationVerifier{shouldVerify: shouldVerify}
}

func (m *mockAttestationVerifier) Verify(ctx context.Context, deviceID string, nonce []byte, expectedPCRs map[int][]byte) (bool, error) {
	return m.shouldVerify, nil
}

// =============================================================================
// Certificate Generators
// =============================================================================

func generateTestCert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Add policy OID extension
	policyOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	policyValue, _ := asn1.Marshal("network-access-policy")
	template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
		Id:       policyOID,
		Critical: false,
		Value:    policyValue,
	})

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateExpiredCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
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
