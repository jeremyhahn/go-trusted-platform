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
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAttestationVerifier implements AttestationVerifier for testing
type mockAttestationVerifier struct {
	shouldVerify bool
	shouldFail   error
}

func (m *mockAttestationVerifier) Verify(ctx context.Context, deviceID string, nonce []byte, expectedPCRs map[int][]byte) (bool, error) {
	if m.shouldFail != nil {
		return false, m.shouldFail
	}
	return m.shouldVerify, nil
}

func TestNetworkAuthService_Initialize(t *testing.T) {
	ctx := context.Background()

	t.Run("successful initialization", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}

		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Re-initialization should fail
		err = service.Initialize(ctx, config)
		assert.Error(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		service := NewNetworkAuthService()
		err := service.Initialize(ctx, nil)
		assert.Error(t, err)
	})

	t.Run("invalid config - zero quarantine VLAN", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 0, // Invalid
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "QuarantineVLAN", configErr.Field)
	})

	t.Run("invalid config - zero production VLAN", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 0, // Invalid
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "ProductionVLAN", configErr.Field)
	})

	t.Run("invalid config - same VLANs", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 100,
			ProductionVLAN: 100, // Same as quarantine
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "ProductionVLAN", configErr.Field)
	})

	t.Run("invalid config - empty bridge name", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "", // Invalid
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "BridgeName", configErr.Field)
	})

	t.Run("invalid config - policy required without OPA endpoint", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequirePolicyEvaluation: true,
			OPAEndpoint:             "", // Missing
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "OPAEndpoint", configErr.Field)
	})

	t.Run("invalid config - negative session timeout", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			SessionTimeout: -time.Hour, // Invalid
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
		var configErr ErrInvalidConfig
		assert.ErrorAs(t, err, &configErr)
		assert.Equal(t, "SessionTimeout", configErr.Field)
	})

	t.Run("invalid config - invalid reattest config", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			Reattest: &ReattestConfig{
				Enabled:  true,
				Interval: 0, // Invalid - must be positive when enabled
			},
		}
		err := service.Initialize(ctx, config)
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(cancelCtx, config)
		assert.Error(t, err)
		assert.IsType(t, ErrContextCanceled{}, err)
	})

	t.Run("with OPA evaluation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{Allow: true, AssignedVLAN: 100},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequirePolicyEvaluation: true,
			OPAEndpoint:             server.URL,
			OPAPolicyPath:           "network/auth",
		}

		err := service.Initialize(ctx, config)
		require.NoError(t, err)
	})

	t.Run("with session timeout", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			SessionTimeout: time.Hour,
		}

		err := service.Initialize(ctx, config)
		require.NoError(t, err)
	})

	t.Run("with trusted CAs", func(t *testing.T) {
		// Create CA
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(caCertDER)
		require.NoError(t, err)

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			TrustedCAs:     []*x509.Certificate{caCert},
		}

		err = service.Initialize(ctx, config)
		require.NoError(t, err)
	})
}

func TestNetworkAuthService_Authenticate(t *testing.T) {
	ctx := context.Background()

	createService := func(t *testing.T, attestVerifier AttestationVerifier, requireAttest bool, requirePolicy bool, opaServer *httptest.Server) NetworkAuthService {
		t.Helper()

		opts := []NetworkAuthServiceOption{}
		if attestVerifier != nil {
			opts = append(opts, WithAttestationVerifier(attestVerifier))
		}

		service := NewNetworkAuthService(opts...)

		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequireAttestation:      requireAttest,
			RequirePolicyEvaluation: requirePolicy,
		}

		if opaServer != nil && requirePolicy {
			config.OPAEndpoint = opaServer.URL
			config.OPAPolicyPath = "network/auth"
		}

		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		return service
	}

	t.Run("successful authentication without attestation/policy", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, AuthStateAuthorized, result.State)
		assert.Equal(t, uint16(100), result.VLAN)
		assert.True(t, result.IsSuccessful())
		assert.NotEmpty(t, result.SessionID)
	})

	t.Run("successful authentication with attestation", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := createService(t, verifier, true, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
			Nonce:       []byte("test-nonce"),
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
		assert.True(t, result.AttestationVerified)
	})

	t.Run("attestation failure", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: false}
		service := createService(t, verifier, true, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
		assert.NotNil(t, result)
		assert.NotEqual(t, AuthStateAuthorized, result.State)
	})

	t.Run("attestation required without verifier", func(t *testing.T) {
		service := createService(t, nil, true, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
		assert.NotNil(t, result)
	})

	t.Run("successful authentication with policy evaluation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{Allow: true, AssignedVLAN: 200},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		service := createService(t, nil, false, true, server)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
		assert.Equal(t, uint16(200), result.VLAN) // Should use OPA assigned VLAN
		assert.True(t, result.PolicyEvaluated)
		assert.True(t, result.PolicyDecision)
	})

	t.Run("policy evaluation denies access", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{
					Allow:   false,
					Reasons: []string{"missing required OID"},
				},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		service := createService(t, nil, false, true, server)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrPolicyViolation{}, err)
		assert.NotNil(t, result)
		assert.True(t, result.PolicyEvaluated)
		assert.False(t, result.PolicyDecision)
	})

	t.Run("nil request", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		result, err := service.Authenticate(ctx, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("invalid request", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		request := &PortAuthRequest{
			PortID:      "", // Invalid
			Certificate: createTestCertificate(t),
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("not initialized", func(t *testing.T) {
		service := NewNetworkAuthService()

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(cancelCtx, request)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("expired certificate", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cert := createExpiredCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrCertInvalid{}, err)
		assert.NotNil(t, result)
	})

	t.Run("future certificate", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cert := createFutureCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrCertInvalid{}, err)
		assert.NotNil(t, result)
	})

	t.Run("with required OIDs - present", func(t *testing.T) {
		requiredOID := asn1.ObjectIdentifier{1, 2, 3, 4}

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			RequiredOIDs:   []asn1.ObjectIdentifier{requiredOID},
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createCertWithOIDs(t, []asn1.ObjectIdentifier{requiredOID})
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
	})

	t.Run("with required OIDs - missing", func(t *testing.T) {
		requiredOID := asn1.ObjectIdentifier{1, 2, 3, 4}

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			RequiredOIDs:   []asn1.ObjectIdentifier{requiredOID},
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createCertWithOIDs(t, nil) // No OIDs
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrOIDMissing{}, err)
		assert.NotNil(t, result)
	})

	t.Run("with timeout", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
			Timeout:     10 * time.Second,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
	})

	t.Run("port state stored after authentication", func(t *testing.T) {
		service := createService(t, nil, false, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		_, err := service.Authenticate(ctx, request)
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "eth0")
		require.NoError(t, err)
		assert.Equal(t, "eth0", state.PortID)
		assert.Equal(t, AuthStateAuthorized, state.AuthState)
	})

	t.Run("attestation verifier returns error", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldFail: errors.New("attestation error")}
		service := createService(t, verifier, true, false, nil)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.NotNil(t, result)
	})

	t.Run("policy evaluation with no assigned VLAN uses production VLAN", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{Allow: true, AssignedVLAN: 0}, // No VLAN assigned
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		service := createService(t, nil, false, true, server)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, uint16(100), result.VLAN) // Should use production VLAN
	})

	t.Run("session expiration is set when session timeout configured", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			SessionTimeout: time.Hour,
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.False(t, result.ExpiresAt.IsZero())
		assert.True(t, result.ExpiresAt.After(time.Now()))
	})
}

func TestNetworkAuthService_Reattest(t *testing.T) {
	ctx := context.Background()

	setupAuthenticatedPort := func(t *testing.T, verifier AttestationVerifier) NetworkAuthService {
		t.Helper()

		service := NewNetworkAuthService(
			WithAttestationVerifier(verifier),
		)
		config := &AuthConfig{
			QuarantineVLAN:     1,
			ProductionVLAN:     100,
			BridgeName:         "br0",
			RequireAttestation: false, // Don't require for initial auth
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate a port first
		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		return service
	}

	t.Run("successful re-attestation", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := setupAuthenticatedPort(t, verifier)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		require.NoError(t, err)
		assert.True(t, result.AttestationVerified)
	})

	t.Run("re-attestation failure", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: false}
		service := setupAuthenticatedPort(t, verifier)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
		assert.False(t, result.AttestationVerified)
	})

	t.Run("port not found", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := setupAuthenticatedPort(t, verifier)

		result, err := service.Reattest(ctx, "eth1", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrPortNotFound{}, err)
		assert.Nil(t, result)
	})

	t.Run("not initialized", func(t *testing.T) {
		service := NewNetworkAuthService()

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
		assert.Nil(t, result)
	})

	t.Run("empty port ID", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := setupAuthenticatedPort(t, verifier)

		result, err := service.Reattest(ctx, "", []byte("nonce"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("context cancellation", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := setupAuthenticatedPort(t, verifier)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		result, err := service.Reattest(cancelCtx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("no attestation verifier configured", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate a port first
		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrAttestFailed{}, err)
		assert.Nil(t, result)
	})

	t.Run("verifier returns error", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldFail: errors.New("verifier error")}
		service := setupAuthenticatedPort(t, verifier)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.AttestationVerified)
	})

	t.Run("re-attestation on non-authorized port", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := setupAuthenticatedPort(t, verifier)

		// Revoke the port first
		err := service.Revoke(ctx, "eth0", "test")
		require.NoError(t, err)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrStateTransition{}, err)
		assert.Nil(t, result)
	})
}

func TestNetworkAuthService_Revoke(t *testing.T) {
	ctx := context.Background()

	setupAuthenticatedPort := func(t *testing.T) NetworkAuthService {
		t.Helper()

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		return service
	}

	t.Run("successful revocation", func(t *testing.T) {
		service := setupAuthenticatedPort(t)

		err := service.Revoke(ctx, "eth0", "manual revocation")
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "eth0")
		require.NoError(t, err)
		assert.Equal(t, AuthStateRevoked, state.AuthState)
		assert.Equal(t, uint16(1), state.VLAN) // Back to quarantine
	})

	t.Run("port not found", func(t *testing.T) {
		service := setupAuthenticatedPort(t)

		err := service.Revoke(ctx, "eth1", "test")
		assert.Error(t, err)
		assert.IsType(t, ErrPortNotFound{}, err)
	})

	t.Run("not initialized", func(t *testing.T) {
		service := NewNetworkAuthService()

		err := service.Revoke(ctx, "eth0", "test")
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
	})

	t.Run("empty port ID", func(t *testing.T) {
		service := setupAuthenticatedPort(t)

		err := service.Revoke(ctx, "", "test")
		assert.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		service := setupAuthenticatedPort(t)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		err := service.Revoke(cancelCtx, "eth0", "test")
		assert.Error(t, err)
	})
}

func TestNetworkAuthService_GetPortState(t *testing.T) {
	ctx := context.Background()

	t.Run("get existing port state", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "eth0")
		require.NoError(t, err)
		assert.Equal(t, "eth0", state.PortID)
		assert.Equal(t, AuthStateAuthorized, state.AuthState)
	})

	t.Run("port not found", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "eth0")
		assert.Error(t, err)
		assert.IsType(t, ErrPortNotFound{}, err)
		assert.Nil(t, state)
	})

	t.Run("not initialized", func(t *testing.T) {
		service := NewNetworkAuthService()

		state, err := service.GetPortState(ctx, "eth0")
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
		assert.Nil(t, state)
	})

	t.Run("empty port ID", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		state, err := service.GetPortState(ctx, "")
		assert.Error(t, err)
		assert.Nil(t, state)
	})

	t.Run("context cancellation", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		state, err := service.GetPortState(cancelCtx, "eth0")
		assert.Error(t, err)
		assert.Nil(t, state)
	})
}

func TestNetworkAuthService_GetAllPorts(t *testing.T) {
	ctx := context.Background()

	t.Run("get all ports", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate multiple ports
		for _, portID := range []string{"eth0", "eth1", "eth2"} {
			cert := createTestCertificate(t)
			request := &PortAuthRequest{
				PortID:      portID,
				Certificate: cert,
			}
			_, err = service.Authenticate(ctx, request)
			require.NoError(t, err)
		}

		ports, err := service.GetAllPorts(ctx)
		require.NoError(t, err)
		assert.Len(t, ports, 3)
	})

	t.Run("empty when no ports", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		ports, err := service.GetAllPorts(ctx)
		require.NoError(t, err)
		assert.Empty(t, ports)
	})

	t.Run("not initialized", func(t *testing.T) {
		service := NewNetworkAuthService()

		ports, err := service.GetAllPorts(ctx)
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
		assert.Nil(t, ports)
	})

	t.Run("context cancellation", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cancelCtx, cancel := context.WithCancel(ctx)
		cancel()

		ports, err := service.GetAllPorts(cancelCtx)
		assert.Error(t, err)
		assert.Nil(t, ports)
	})
}

func TestNetworkAuthService_Close(t *testing.T) {
	ctx := context.Background()

	t.Run("close initialized service", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		err = service.Close()
		assert.NoError(t, err)

		// Second close should be no-op
		err = service.Close()
		assert.NoError(t, err)
	})

	t.Run("close uninitialized service", func(t *testing.T) {
		service := NewNetworkAuthService()
		err := service.Close()
		assert.NoError(t, err)
	})

	t.Run("operations after close", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		err = service.Close()
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("close service with OPA evaluator", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{Allow: true, AssignedVLAN: 100},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequirePolicyEvaluation: true,
			OPAEndpoint:             server.URL,
			OPAPolicyPath:           "network/auth",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		err = service.Close()
		assert.NoError(t, err)
	})

	t.Run("revoke after close", func(t *testing.T) {
		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate a port first
		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		err = service.Close()
		require.NoError(t, err)

		err = service.Revoke(ctx, "eth0", "test")
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
	})

	t.Run("reattest after close", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := NewNetworkAuthService(WithAttestationVerifier(verifier))
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		// Authenticate a port first
		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}
		_, err = service.Authenticate(ctx, request)
		require.NoError(t, err)

		err = service.Close()
		require.NoError(t, err)

		result, err := service.Reattest(ctx, "eth0", []byte("nonce"))
		assert.Error(t, err)
		assert.IsType(t, ErrServiceNotInitialized{}, err)
		assert.Nil(t, result)
	})
}

func TestNetworkAuthService_WithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with custom logger", func(t *testing.T) {
		logger := slog.Default()
		service := NewNetworkAuthService(
			WithLogger(logger),
		)
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)
	})

	t.Run("with custom policy extractor", func(t *testing.T) {
		extractor := NewPolicyExtractor()
		service := NewNetworkAuthService(
			WithPolicyExtractor(extractor),
		)
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)
	})

	t.Run("with custom OPA evaluator", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := opaResponse{
				Result: &OPAResult{Allow: true, AssignedVLAN: 100},
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				return
			}
		}))
		defer server.Close()

		evaluator := NewOPAEvaluator()
		err := evaluator.Initialize(ctx, server.URL, "network/auth")
		require.NoError(t, err)

		service := NewNetworkAuthService(
			WithOPAEvaluator(evaluator),
		)
		config := &AuthConfig{
			QuarantineVLAN:          1,
			ProductionVLAN:          100,
			BridgeName:              "br0",
			RequirePolicyEvaluation: true,
		}
		err = service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
	})

	t.Run("with custom flow manager", func(t *testing.T) {
		manager := NewFlowManager()
		flowConfig := &FlowConfig{BridgeName: "br0"}
		err := manager.Initialize(ctx, flowConfig)
		require.NoError(t, err)

		service := NewNetworkAuthService(
			WithFlowManager(manager),
		)
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
		}
		err = service.Initialize(ctx, config)
		require.NoError(t, err)
	})

	t.Run("with attestation verifier", func(t *testing.T) {
		verifier := &mockAttestationVerifier{shouldVerify: true}
		service := NewNetworkAuthService(
			WithAttestationVerifier(verifier),
		)
		config := &AuthConfig{
			QuarantineVLAN:     1,
			ProductionVLAN:     100,
			BridgeName:         "br0",
			RequireAttestation: true,
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.True(t, result.AttestationVerified)
	})
}

func TestNetworkAuthService_CertificateValidation(t *testing.T) {
	ctx := context.Background()

	createServiceWithCA := func(t *testing.T, caCert *x509.Certificate) NetworkAuthService {
		t.Helper()

		service := NewNetworkAuthService()
		config := &AuthConfig{
			QuarantineVLAN: 1,
			ProductionVLAN: 100,
			BridgeName:     "br0",
			TrustedCAs:     []*x509.Certificate{caCert},
		}
		err := service.Initialize(ctx, config)
		require.NoError(t, err)

		return service
	}

	t.Run("valid certificate chain", func(t *testing.T) {
		// Create CA
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(caCertDER)
		require.NoError(t, err)

		// Create leaf certificate signed by CA
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		leafTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "test-device"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}

		leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
		require.NoError(t, err)
		leafCert, err := x509.ParseCertificate(leafCertDER)
		require.NoError(t, err)

		service := createServiceWithCA(t, caCert)

		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: leafCert,
		}

		result, err := service.Authenticate(ctx, request)
		require.NoError(t, err)
		assert.Equal(t, AuthStateAuthorized, result.State)
	})

	t.Run("invalid certificate chain", func(t *testing.T) {
		// Create CA
		caKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		caTemplate := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}

		caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
		require.NoError(t, err)
		caCert, err := x509.ParseCertificate(caCertDER)
		require.NoError(t, err)

		service := createServiceWithCA(t, caCert)

		// Use self-signed cert (not signed by CA)
		cert := createTestCertificate(t)
		request := &PortAuthRequest{
			PortID:      "eth0",
			Certificate: cert,
		}

		result, err := service.Authenticate(ctx, request)
		assert.Error(t, err)
		assert.IsType(t, ErrCertInvalid{}, err)
		assert.NotNil(t, result)
	})
}

func TestGenerateSessionID(t *testing.T) {
	t.Run("generates unique IDs", func(t *testing.T) {
		id1 := generateSessionID("eth0")
		id2 := generateSessionID("eth0")

		assert.NotEmpty(t, id1)
		assert.NotEmpty(t, id2)
		assert.Len(t, id1, 32) // 16 bytes hex encoded
	})

	t.Run("different ports produce different IDs", func(t *testing.T) {
		id1 := generateSessionID("eth0")
		id2 := generateSessionID("eth1")

		assert.NotEmpty(t, id1)
		assert.NotEmpty(t, id2)
		assert.NotEqual(t, id1, id2)
	})
}

// Helper functions for creating test certificates

func createTestCertificate(t *testing.T) *x509.Certificate {
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

func createExpiredCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-device"},
		NotBefore:             time.Now().Add(-2 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour), // Expired
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

func createFutureCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-device"},
		NotBefore:             time.Now().Add(time.Hour), // Not yet valid
		NotAfter:              time.Now().Add(2 * time.Hour),
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

// createCertWithOIDs creates a certificate with the specified policy OIDs
// embedded as a raw extension (since x509.CreateCertificate doesn't serialize
// PolicyIdentifiers for self-signed certificates properly).
func createCertWithOIDs(t *testing.T, oids []asn1.ObjectIdentifier) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-device-with-oids"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// If OIDs are provided, encode them as a CertificatePolicies extension
	if len(oids) > 0 {
		// CertificatePolicies ::= SEQUENCE OF PolicyInformation
		// PolicyInformation ::= SEQUENCE {
		//     policyIdentifier   CertPolicyId,
		//     policyQualifiers   SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL }
		// CertPolicyId ::= OBJECT IDENTIFIER
		type policyInformation struct {
			PolicyIdentifier asn1.ObjectIdentifier
		}

		var policies []policyInformation
		for _, oid := range oids {
			policies = append(policies, policyInformation{PolicyIdentifier: oid})
		}

		policyBytes, err := asn1.Marshal(policies)
		require.NoError(t, err)

		// OID for Certificate Policies: 2.5.29.32
		certPoliciesOID := asn1.ObjectIdentifier{2, 5, 29, 32}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:       certPoliciesOID,
			Critical: false,
			Value:    policyBytes,
		})
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
