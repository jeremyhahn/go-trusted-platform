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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthState_String(t *testing.T) {
	tests := []struct {
		name     string
		state    AuthState
		expected string
	}{
		{"quarantine", AuthStateQuarantine, "quarantine"},
		{"enrolling", AuthStateEnrolling, "enrolling"},
		{"authorized", AuthStateAuthorized, "authorized"},
		{"revoked", AuthStateRevoked, "revoked"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestAuthState_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		state    AuthState
		expected bool
	}{
		{"quarantine valid", AuthStateQuarantine, true},
		{"enrolling valid", AuthStateEnrolling, true},
		{"authorized valid", AuthStateAuthorized, true},
		{"revoked valid", AuthStateRevoked, true},
		{"invalid state", AuthState("invalid"), false},
		{"empty state", AuthState(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.IsValid())
		})
	}
}

func TestAuthState_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		state    AuthState
		expected bool
	}{
		{"quarantine not terminal", AuthStateQuarantine, false},
		{"enrolling not terminal", AuthStateEnrolling, false},
		{"authorized not terminal", AuthStateAuthorized, false},
		{"revoked is terminal", AuthStateRevoked, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.IsTerminal())
		})
	}
}

func TestAuthState_CanTransitionTo(t *testing.T) {
	tests := []struct {
		name  string
		from  AuthState
		to    AuthState
		canDo bool
	}{
		{"quarantine to enrolling", AuthStateQuarantine, AuthStateEnrolling, true},
		{"quarantine to authorized", AuthStateQuarantine, AuthStateAuthorized, true},
		{"quarantine to revoked", AuthStateQuarantine, AuthStateRevoked, true},
		{"enrolling to authorized", AuthStateEnrolling, AuthStateAuthorized, true},
		{"enrolling to quarantine", AuthStateEnrolling, AuthStateQuarantine, true},
		{"enrolling to revoked", AuthStateEnrolling, AuthStateRevoked, true},
		{"authorized to quarantine", AuthStateAuthorized, AuthStateQuarantine, true},
		{"authorized to revoked", AuthStateAuthorized, AuthStateRevoked, true},
		{"authorized to enrolling", AuthStateAuthorized, AuthStateEnrolling, false},
		{"revoked to quarantine", AuthStateRevoked, AuthStateQuarantine, true},
		{"revoked to authorized", AuthStateRevoked, AuthStateAuthorized, false},
		{"revoked to enrolling", AuthStateRevoked, AuthStateEnrolling, false},
		{"invalid from state", AuthState("invalid"), AuthStateAuthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.canDo, tt.from.CanTransitionTo(tt.to))
		})
	}
}

func TestVLANTransition(t *testing.T) {
	transition := VLANTransition{
		PortID:        "eth0",
		FromVLAN:      1,
		ToVLAN:        100,
		FromState:     AuthStateQuarantine,
		ToState:       AuthStateAuthorized,
		Reason:        "authentication successful",
		Timestamp:     time.Now(),
		TransactionID: "txn-123",
		Success:       true,
	}

	assert.Equal(t, "eth0", transition.PortID)
	assert.Equal(t, uint16(1), transition.FromVLAN)
	assert.Equal(t, uint16(100), transition.ToVLAN)
	assert.Equal(t, AuthStateQuarantine, transition.FromState)
	assert.Equal(t, AuthStateAuthorized, transition.ToState)
	assert.True(t, transition.Success)
}

func TestAuthResult_IsSuccessful(t *testing.T) {
	tests := []struct {
		name   string
		result AuthResult
		expect bool
	}{
		{
			name: "all conditions met",
			result: AuthResult{
				State:               AuthStateAuthorized,
				AttestationVerified: true,
				PolicyEvaluated:     true,
				PolicyDecision:      true,
				FlowRulesInstalled:  true,
			},
			expect: true,
		},
		{
			name: "wrong state",
			result: AuthResult{
				State:               AuthStateQuarantine,
				AttestationVerified: true,
				PolicyEvaluated:     true,
				PolicyDecision:      true,
				FlowRulesInstalled:  true,
			},
			expect: false,
		},
		{
			name: "attestation not verified",
			result: AuthResult{
				State:               AuthStateAuthorized,
				AttestationVerified: false,
				PolicyEvaluated:     true,
				PolicyDecision:      true,
				FlowRulesInstalled:  true,
			},
			expect: false,
		},
		{
			name: "policy denied",
			result: AuthResult{
				State:               AuthStateAuthorized,
				AttestationVerified: true,
				PolicyEvaluated:     true,
				PolicyDecision:      false,
				FlowRulesInstalled:  true,
			},
			expect: false,
		},
		{
			name: "flow rules not installed",
			result: AuthResult{
				State:               AuthStateAuthorized,
				AttestationVerified: true,
				PolicyEvaluated:     true,
				PolicyDecision:      true,
				FlowRulesInstalled:  false,
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, tt.result.IsSuccessful())
		})
	}
}

func TestAuthResult_Errors(t *testing.T) {
	result := &AuthResult{}

	assert.False(t, result.HasErrors())

	result.AddError("error 1")
	assert.True(t, result.HasErrors())
	assert.Len(t, result.Errors, 1)

	result.AddError("error 2")
	assert.Len(t, result.Errors, 2)
	assert.Equal(t, "error 1", result.Errors[0])
	assert.Equal(t, "error 2", result.Errors[1])
}

func TestPolicyInfo_HasOID(t *testing.T) {
	oid1 := asn1.ObjectIdentifier{1, 2, 3, 4}
	oid2 := asn1.ObjectIdentifier{1, 2, 3, 5}
	oid3 := asn1.ObjectIdentifier{1, 2, 3, 6}

	info := &PolicyInfo{
		OIDs: []asn1.ObjectIdentifier{oid1, oid2},
	}

	assert.True(t, info.HasOID(oid1))
	assert.True(t, info.HasOID(oid2))
	assert.False(t, info.HasOID(oid3))
}

func TestPolicyInfo_IsExpired(t *testing.T) {
	tests := []struct {
		name     string
		notAfter time.Time
		expired  bool
	}{
		{"not expired", time.Now().Add(time.Hour), false},
		{"expired", time.Now().Add(-time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &PolicyInfo{CertificateNotAfter: tt.notAfter}
			assert.Equal(t, tt.expired, info.IsExpired())
		})
	}
}

func TestPolicyInfo_IsNotYetValid(t *testing.T) {
	tests := []struct {
		name        string
		notBefore   time.Time
		notYetValid bool
	}{
		{"valid now", time.Now().Add(-time.Hour), false},
		{"not yet valid", time.Now().Add(time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &PolicyInfo{CertificateNotBefore: tt.notBefore}
			assert.Equal(t, tt.notYetValid, info.IsNotYetValid())
		})
	}
}

func TestReattestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ReattestConfig
		wantErr bool
	}{
		{
			name:    "disabled config valid",
			config:  ReattestConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: ReattestConfig{
				Enabled:            true,
				Interval:           time.Hour,
				GracePeriod:        time.Minute,
				MaxFailures:        3,
				AttestationTimeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "invalid interval",
			config: ReattestConfig{
				Enabled:            true,
				Interval:           0,
				AttestationTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative grace period",
			config: ReattestConfig{
				Enabled:            true,
				Interval:           time.Hour,
				GracePeriod:        -time.Minute,
				AttestationTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative max failures",
			config: ReattestConfig{
				Enabled:            true,
				Interval:           time.Hour,
				MaxFailures:        -1,
				AttestationTimeout: 30 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid attestation timeout",
			config: ReattestConfig{
				Enabled:            true,
				Interval:           time.Hour,
				AttestationTimeout: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  AuthConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 100,
				BridgeName:     "br0",
			},
			wantErr: false,
		},
		{
			name: "zero quarantine VLAN",
			config: AuthConfig{
				QuarantineVLAN: 0,
				ProductionVLAN: 100,
				BridgeName:     "br0",
			},
			wantErr: true,
		},
		{
			name: "zero production VLAN",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 0,
				BridgeName:     "br0",
			},
			wantErr: true,
		},
		{
			name: "same VLANs",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 1,
				BridgeName:     "br0",
			},
			wantErr: true,
		},
		{
			name: "empty bridge name",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 100,
				BridgeName:     "",
			},
			wantErr: true,
		},
		{
			name: "policy required without OPA endpoint",
			config: AuthConfig{
				QuarantineVLAN:          1,
				ProductionVLAN:          100,
				BridgeName:              "br0",
				RequirePolicyEvaluation: true,
				OPAEndpoint:             "",
			},
			wantErr: true,
		},
		{
			name: "negative session timeout",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 100,
				BridgeName:     "br0",
				SessionTimeout: -time.Hour,
			},
			wantErr: true,
		},
		{
			name: "valid with OPA",
			config: AuthConfig{
				QuarantineVLAN:          1,
				ProductionVLAN:          100,
				BridgeName:              "br0",
				RequirePolicyEvaluation: true,
				OPAEndpoint:             "http://localhost:8181",
				OPAPolicyPath:           "network/auth",
			},
			wantErr: false,
		},
		{
			name: "valid with reattest config",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 100,
				BridgeName:     "br0",
				Reattest: &ReattestConfig{
					Enabled:            true,
					Interval:           time.Hour,
					AttestationTimeout: 30 * time.Second,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid reattest config",
			config: AuthConfig{
				QuarantineVLAN: 1,
				ProductionVLAN: 100,
				BridgeName:     "br0",
				Reattest: &ReattestConfig{
					Enabled:  true,
					Interval: 0, // Invalid
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPortAuthRequest_Validate(t *testing.T) {
	cert := createTypesTestCertificate(t)

	tests := []struct {
		name    string
		request PortAuthRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: PortAuthRequest{
				PortID:      "eth0",
				Certificate: cert,
			},
			wantErr: false,
		},
		{
			name: "empty port ID",
			request: PortAuthRequest{
				PortID:      "",
				Certificate: cert,
			},
			wantErr: true,
		},
		{
			name: "nil certificate",
			request: PortAuthRequest{
				PortID:      "eth0",
				Certificate: nil,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPortState_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		state   PortState
		expired bool
	}{
		{
			name:    "zero expiration",
			state:   PortState{ExpiresAt: time.Time{}},
			expired: false,
		},
		{
			name:    "not expired",
			state:   PortState{ExpiresAt: time.Now().Add(time.Hour)},
			expired: false,
		},
		{
			name:    "expired",
			state:   PortState{ExpiresAt: time.Now().Add(-time.Hour)},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expired, tt.state.IsExpired())
		})
	}
}

func TestPortState_NeedsReattest(t *testing.T) {
	interval := time.Hour

	tests := []struct {
		name  string
		state PortState
		needs bool
	}{
		{
			name: "not authorized",
			state: PortState{
				AuthState:       AuthStateQuarantine,
				AuthenticatedAt: time.Now().Add(-2 * time.Hour),
			},
			needs: false,
		},
		{
			name: "recently authenticated",
			state: PortState{
				AuthState:       AuthStateAuthorized,
				AuthenticatedAt: time.Now().Add(-30 * time.Minute),
			},
			needs: false,
		},
		{
			name: "needs reattest based on auth time",
			state: PortState{
				AuthState:       AuthStateAuthorized,
				AuthenticatedAt: time.Now().Add(-2 * time.Hour),
			},
			needs: true,
		},
		{
			name: "recently reattested",
			state: PortState{
				AuthState:       AuthStateAuthorized,
				AuthenticatedAt: time.Now().Add(-2 * time.Hour),
				LastReattestAt:  time.Now().Add(-30 * time.Minute),
			},
			needs: false,
		},
		{
			name: "needs reattest based on last reattest",
			state: PortState{
				AuthState:       AuthStateAuthorized,
				AuthenticatedAt: time.Now().Add(-3 * time.Hour),
				LastReattestAt:  time.Now().Add(-2 * time.Hour),
			},
			needs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.needs, tt.state.NeedsReattest(interval))
		})
	}
}

// createTypesTestCertificate creates a test x509 certificate for types_test.go.
// This is a local helper to avoid conflicts with auth_test.go's helper.
func createTypesTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-device",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		PolicyIdentifiers:     []asn1.ObjectIdentifier{{1, 2, 3, 4}},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
