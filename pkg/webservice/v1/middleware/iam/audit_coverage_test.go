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

package iam

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/security/audit"
)

// mockAuditLogger implements audit.AuditLogger for testing.
type mockAuditLogger struct {
	mu       sync.Mutex
	events   []audit.AuditEvent
	logErr   error
	asyncErr error
}

func newMockAuditLogger() *mockAuditLogger {
	return &mockAuditLogger{
		events: make([]audit.AuditEvent, 0),
	}
}

func (m *mockAuditLogger) Log(ctx context.Context, event audit.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.logErr != nil {
		return m.logErr
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditLogger) LogAsync(event audit.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.asyncErr != nil {
		return m.asyncErr
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockAuditLogger) Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditEvent, error) {
	return nil, nil
}

func (m *mockAuditLogger) Close() error {
	return nil
}

func (m *mockAuditLogger) lastEvent() audit.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return audit.AuditEvent{}
	}
	return m.events[len(m.events)-1]
}

func (m *mockAuditLogger) eventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

// TestExtractClientIP tests the extractClientIP function.
func TestExtractClientIP(t *testing.T) {
	t.Run("X-Forwarded-For single IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		ip := extractClientIP(req)
		assert.Equal(t, "10.0.0.1", ip)
	})

	t.Run("X-Forwarded-For multiple IPs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2, 10.0.0.3")
		ip := extractClientIP(req)
		assert.Equal(t, "10.0.0.1", ip)
	})

	t.Run("X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Real-IP", "192.168.1.100")
		ip := extractClientIP(req)
		assert.Equal(t, "192.168.1.100", ip)
	})

	t.Run("RemoteAddr with port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "172.16.0.1:8080"
		ip := extractClientIP(req)
		assert.Equal(t, "172.16.0.1", ip)
	})

	t.Run("RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "invalid-no-port"
		ip := extractClientIP(req)
		assert.Equal(t, "invalid-no-port", ip)
	})

	t.Run("X-Forwarded-For takes priority over X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		req.Header.Set("X-Real-IP", "192.168.1.100")
		ip := extractClientIP(req)
		assert.Equal(t, "10.0.0.1", ip)
	})
}

// TestWithAuthAuditLogger tests the WithAuthAuditLogger functional option.
func TestWithAuthAuditLogger(t *testing.T) {
	logger := createTestLogger()
	mockWriter := newMockHttpWriter()
	mockIAM := newMockIAMServiceClient()
	auditLog := newMockAuditLogger()

	config := AuthConfig{
		DefaultTenantID: "test-tenant",
	}

	mw, err := NewAuthMiddleware(
		logger,
		mockWriter,
		config,
		mockIAM,
		nil,
		nil,
		nil,
		WithAuthAuditLogger(auditLog),
	)
	require.NoError(t, err)
	assert.NotNil(t, mw)
	assert.Equal(t, auditLog, mw.auditLogger)
}

// TestLogAuthenticationFailed tests the audit logging of authentication failures.
func TestLogAuthenticationFailed(t *testing.T) {
	t.Run("with audit logger", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("User-Agent", "test-agent")

		mw.logAuthenticationFailed(req, "test-actor", "bad credentials")

		assert.Equal(t, 1, auditLog.eventCount())
		event := auditLog.lastEvent()
		assert.Equal(t, "test-actor", event.Actor)
		assert.Equal(t, "authentication_failed", event.Action)
		assert.Equal(t, "/api/v1/test", event.Resource)
		assert.Equal(t, audit.OutcomeFailure, event.Outcome)
		assert.Equal(t, "bad credentials", event.Details["reason"])
	})

	t.Run("without audit logger", func(t *testing.T) {
		logger := createTestLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		// Should not panic
		mw.logAuthenticationFailed(req, "test-actor", "bad credentials")
	})

	t.Run("with audit logger error", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		auditLog.asyncErr = errors.New("audit log unavailable")
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
		// Should not panic even when audit logger returns error
		mw.logAuthenticationFailed(req, "test-actor", "bad credentials")
	})
}

// TestLogAuthenticationSuccess tests the audit logging of authentication successes.
func TestLogAuthenticationSuccess(t *testing.T) {
	t.Run("with audit logger", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = "10.0.0.1:1234"

		mw.logAuthenticationSuccess(req, "user-123", "mtls")

		assert.Equal(t, 1, auditLog.eventCount())
		event := auditLog.lastEvent()
		assert.Equal(t, "user-123", event.Actor)
		assert.Equal(t, "authentication_success", event.Action)
		assert.Equal(t, audit.OutcomeSuccess, event.Outcome)
		assert.Equal(t, "mtls", event.Details["auth_method"])
	})

	t.Run("without audit logger", func(t *testing.T) {
		logger := createTestLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: nil,
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		mw.logAuthenticationSuccess(req, "user-123", "jwt")
	})

	t.Run("with audit logger error", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		auditLog.asyncErr = errors.New("disk full")
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		mw.logAuthenticationSuccess(req, "user-123", "jwt")
	})
}

// TestLogIDevIDValidation tests the audit logging of IDevID validation.
func TestLogIDevIDValidation(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "device-001",
			Organization: []string{"Test Org"},
		},
		SerialNumber: big.NewInt(12345),
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
	}

	t.Run("with audit logger success", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/device", nil)
		req.RemoteAddr = "10.0.0.1:1234"

		mw.logIDevIDValidation(req, cert, audit.OutcomeSuccess, "")

		assert.Equal(t, 1, auditLog.eventCount())
		event := auditLog.lastEvent()
		assert.Equal(t, "device-001", event.Actor)
		assert.Equal(t, "idevid_validation", event.Action)
		assert.Equal(t, "certificate", event.ResourceType)
		assert.Equal(t, audit.OutcomeSuccess, event.Outcome)
		assert.Contains(t, event.Details["cert_subject"], "device-001")
	})

	t.Run("with audit logger failure and reason", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/device", nil)

		mw.logIDevIDValidation(req, cert, audit.OutcomeFailure, "expired certificate")

		event := auditLog.lastEvent()
		assert.Equal(t, audit.OutcomeFailure, event.Outcome)
		assert.Equal(t, "expired certificate", event.Details["reason"])
	})

	t.Run("without audit logger", func(t *testing.T) {
		logger := createTestLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/device", nil)
		mw.logIDevIDValidation(req, cert, audit.OutcomeSuccess, "")
	})
}

// TestLogAttestationVerification tests the audit logging of TPM attestation.
func TestLogAttestationVerification(t *testing.T) {
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "device-002",
		},
	}

	t.Run("with device ID", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
		req.RemoteAddr = "10.0.0.1:1234"

		mw.logAttestationVerification(req, cert, "dev-123", audit.OutcomeSuccess, "")

		event := auditLog.lastEvent()
		assert.Equal(t, "device-002", event.Actor)
		assert.Equal(t, "attestation_verification", event.Action)
		assert.Equal(t, "tpm_attestation", event.ResourceType)
		assert.Equal(t, "dev-123", event.Resource)
		assert.Equal(t, "dev-123", event.Details["device_id"])
	})

	t.Run("with reason and no device ID", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)

		mw.logAttestationVerification(req, cert, "", audit.OutcomeFailure, "PCR mismatch")

		event := auditLog.lastEvent()
		assert.Equal(t, audit.OutcomeFailure, event.Outcome)
		assert.Equal(t, "PCR mismatch", event.Details["reason"])
		_, hasDeviceID := event.Details["device_id"]
		assert.False(t, hasDeviceID, "device_id should not be present when empty")
	})

	t.Run("without audit logger", func(t *testing.T) {
		logger := createTestLogger()
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: nil,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
		mw.logAttestationVerification(req, cert, "dev-123", audit.OutcomeSuccess, "")
	})

	t.Run("with audit logger error", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		auditLog.asyncErr = errors.New("write error")
		mw := &AuthMiddleware{
			logger:      logger,
			auditLogger: auditLog,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
		mw.logAttestationVerification(req, cert, "dev-123", audit.OutcomeSuccess, "")
	})
}

// TestLogAuthzDecision tests the authorization decision audit logging.
func TestLogAuthzDecision(t *testing.T) {
	t.Run("allowed decision", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		pepClient := newMockPEPServiceClient()

		config := AuthzConfig{DefaultDeny: true}
		mw, err := NewAuthzMiddleware(logger, newMockHttpWriter(), config, pepClient,
			WithAuthzAuditLogger(auditLog))
		require.NoError(t, err)

		session := NewIAMSession(&iamsdk.User{
			ID:       "user-1",
			TenantID: "tenant-1",
			Email:    "test@example.com",
			Roles:    []string{"admin"},
		})

		ctx := context.Background()
		mw.logAuthzDecision(ctx, session, "read", "/api/v1/devices", "device-policy", "allow-admin", true)

		assert.Equal(t, 1, auditLog.eventCount())
		event := auditLog.lastEvent()
		assert.Equal(t, "user-1", event.Actor)
		assert.Equal(t, "access_granted", event.Action)
		assert.Equal(t, "/api/v1/devices", event.Resource)
		assert.Equal(t, audit.OutcomeSuccess, event.Outcome)
		assert.Equal(t, "read", event.Details["requested_action"])
		assert.Equal(t, "device-policy", event.Details["policy_name"])
		assert.Equal(t, "allow-admin", event.Details["rule_name"])
		assert.Equal(t, "tenant-1", event.Details["tenant_id"])
	})

	t.Run("denied decision", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		pepClient := newMockPEPServiceClient()

		config := AuthzConfig{DefaultDeny: true}
		mw, err := NewAuthzMiddleware(logger, newMockHttpWriter(), config, pepClient,
			WithAuthzAuditLogger(auditLog))
		require.NoError(t, err)

		session := NewIAMSession(&iamsdk.User{
			ID:       "user-2",
			TenantID: "tenant-2",
		})

		ctx := context.Background()
		mw.logAuthzDecision(ctx, session, "delete", "/api/v1/secrets", "", "", false)

		event := auditLog.lastEvent()
		assert.Equal(t, "access_denied", event.Action)
		assert.Equal(t, audit.OutcomeDenied, event.Outcome)
	})

	t.Run("without audit logger", func(t *testing.T) {
		logger := createTestLogger()
		pepClient := newMockPEPServiceClient()

		config := AuthzConfig{DefaultDeny: true}
		mw, err := NewAuthzMiddleware(logger, newMockHttpWriter(), config, pepClient)
		require.NoError(t, err)

		session := NewIAMSession(&iamsdk.User{
			ID:       "user-3",
			TenantID: "tenant-3",
		})

		ctx := context.Background()
		// Should not panic when no audit logger
		mw.logAuthzDecision(ctx, session, "read", "/test", "", "", true)
	})

	t.Run("with audit logger error", func(t *testing.T) {
		logger := createTestLogger()
		auditLog := newMockAuditLogger()
		auditLog.asyncErr = errors.New("audit log full")
		pepClient := newMockPEPServiceClient()

		config := AuthzConfig{DefaultDeny: true}
		mw, err := NewAuthzMiddleware(logger, newMockHttpWriter(), config, pepClient,
			WithAuthzAuditLogger(auditLog))
		require.NoError(t, err)

		session := NewIAMSession(&iamsdk.User{
			ID:       "user-4",
			TenantID: "tenant-4",
		})

		ctx := context.Background()
		mw.logAuthzDecision(ctx, session, "read", "/test", "", "", true)
	})
}

// TestWithAuthzAuditLogger tests the WithAuthzAuditLogger functional option.
func TestWithAuthzAuditLogger(t *testing.T) {
	logger := createTestLogger()
	auditLog := newMockAuditLogger()
	pepClient := newMockPEPServiceClient()

	config := AuthzConfig{DefaultDeny: true}
	mw, err := NewAuthzMiddleware(logger, newMockHttpWriter(), config, pepClient,
		WithAuthzAuditLogger(auditLog))
	require.NoError(t, err)
	assert.NotNil(t, mw)
	assert.Equal(t, auditLog, mw.auditLogger)
}
