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

package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Mock implementations for testing

type mockAttestor struct {
	verifyFunc    func(ctx context.Context, quote, sig, aik []byte) (map[int][]byte, error)
	generateNonce func(ctx context.Context) ([]byte, error)
}

func (m *mockAttestor) VerifyQuote(ctx context.Context, quote, signature, aik []byte) (map[int][]byte, error) {
	if m.verifyFunc != nil {
		return m.verifyFunc(ctx, quote, signature, aik)
	}
	return map[int][]byte{
		0: {0x00, 0x01, 0x02, 0x03},
		7: {0x07, 0x08, 0x09, 0x0a},
	}, nil
}

func (m *mockAttestor) GenerateNonce(ctx context.Context) ([]byte, error) {
	if m.generateNonce != nil {
		return m.generateNonce(ctx)
	}
	return []byte("test-nonce-12345"), nil
}

type mockPolicyEngine struct {
	evaluateFunc func(ctx context.Context, policy string, input map[string]any) (*PolicyDecision, error)
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, policy string, input map[string]any) (*PolicyDecision, error) {
	if m.evaluateFunc != nil {
		return m.evaluateFunc(ctx, policy, input)
	}
	return &PolicyDecision{
		Allow:       true,
		Permissions: []string{"pull", "push"},
	}, nil
}

type mockQuicBaaSClient struct {
	mu     sync.RWMutex
	data   map[string][]byte
	putErr error
	getErr error
	delErr error
}

func newMockQuicBaaSClient() *mockQuicBaaSClient {
	return &mockQuicBaaSClient{
		data: make(map[string][]byte),
	}
}

func (m *mockQuicBaaSClient) Put(ctx context.Context, entityType, key string, value []byte, ttl time.Duration) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[entityType+":"+key] = value
	return nil
}

func (m *mockQuicBaaSClient) Get(ctx context.Context, entityType, key string) ([]byte, bool, error) {
	if m.getErr != nil {
		return nil, false, m.getErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.data[entityType+":"+key]
	return value, ok, nil
}

func (m *mockQuicBaaSClient) Delete(ctx context.Context, entityType, key string) error {
	if m.delErr != nil {
		return m.delErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, entityType+":"+key)
	return nil
}

// Helper to create valid attestation evidence
func createTestEvidence(t *testing.T, clientID string) string {
	t.Helper()
	evidence := AttestationEvidence{
		Quote:     []byte("test-quote-data"),
		Signature: []byte("test-signature"),
		AIK:       []byte("test-aik-public-key-bytes"),
		ClientID:  clientID,
		PCRs: map[int][]byte{
			0: {0x00, 0x01, 0x02, 0x03},
			7: {0x07, 0x08, 0x09, 0x0a},
		},
		Nonce:     []byte("test-nonce"),
		Timestamp: time.Now().UTC(),
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("failed to marshal evidence: %v", err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// Tests for NewRegistryAuthHandler

func TestNewRegistryAuthHandler_Success(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, err := NewRegistryAuthHandler(attestor, policy, db)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if handler == nil {
		t.Fatal("expected handler to be non-nil")
	}
	if handler.sessionDuration != DefaultSessionDuration {
		t.Errorf("expected default session duration %v, got %v", DefaultSessionDuration, handler.sessionDuration)
	}
}

func TestNewRegistryAuthHandler_WithOptions(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	customDuration := 2 * time.Hour
	requiredPCRs := map[int][]byte{
		0: {0x00, 0x01, 0x02, 0x03},
	}
	allowedAIKs := []string{"aik1", "aik2"}

	handler, err := NewRegistryAuthHandler(
		attestor, policy, db,
		WithSessionDuration(customDuration),
		WithRequiredPCRs(requiredPCRs),
		WithAllowedAIKs(allowedAIKs),
		WithPolicyName("custom.policy"),
	)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if handler.sessionDuration != customDuration {
		t.Errorf("expected session duration %v, got %v", customDuration, handler.sessionDuration)
	}
	if handler.policyName != "custom.policy" {
		t.Errorf("expected policy name 'custom.policy', got %s", handler.policyName)
	}
	if len(handler.allowedAIKs) != 2 {
		t.Errorf("expected 2 allowed AIKs, got %d", len(handler.allowedAIKs))
	}
}

func TestNewRegistryAuthHandler_NilAttestor(t *testing.T) {
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	_, err := NewRegistryAuthHandler(nil, policy, db)
	if err == nil {
		t.Fatal("expected error for nil attestor")
	}
	var nilErr ErrNilClient
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilClient, got %T", err)
	}
}

func TestNewRegistryAuthHandler_NilPolicyEngine(t *testing.T) {
	attestor := &mockAttestor{}
	db := newMockQuicBaaSClient()

	_, err := NewRegistryAuthHandler(attestor, nil, db)
	if err == nil {
		t.Fatal("expected error for nil policy engine")
	}
	var nilErr ErrNilClient
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilClient, got %T", err)
	}
}

func TestNewRegistryAuthHandler_NilQuicBaaS(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}

	_, err := NewRegistryAuthHandler(attestor, policy, nil)
	if err == nil {
		t.Fatal("expected error for nil QuicBaaS")
	}
	var nilErr ErrNilClient
	if !errors.As(err, &nilErr) {
		t.Errorf("expected ErrNilClient, got %T", err)
	}
}

// Tests for Authenticate

func TestAuthenticate_Success(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, err := NewRegistryAuthHandler(attestor, policy, db)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, createTestEvidence(t, "test-client-1"))

	ctx := context.Background()
	session, err := handler.Authenticate(ctx, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be non-nil")
	}
	if session.ClientID != "test-client-1" {
		t.Errorf("expected client ID 'test-client-1', got %s", session.ClientID)
	}
	if session.SessionID == "" {
		t.Error("expected session ID to be non-empty")
	}
	if !session.IsValid() {
		t.Error("expected session to be valid")
	}
}

func TestAuthenticate_NilContext(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)

	_, err := handler.Authenticate(nil, req) //nolint:staticcheck // testing nil context handling
	if err == nil {
		t.Fatal("expected error for nil context")
	}
	var nilCtxErr ErrNilContext
	if !errors.As(err, &nilCtxErr) {
		t.Errorf("expected ErrNilContext, got %T", err)
	}
}

func TestAuthenticate_NilRequest(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	var attestErr ErrAttestationRequired
	if !errors.As(err, &attestErr) {
		t.Errorf("expected ErrAttestationRequired, got %T", err)
	}
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	// No attestation header

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for missing header")
	}
	var attestErr ErrAttestationRequired
	if !errors.As(err, &attestErr) {
		t.Errorf("expected ErrAttestationRequired, got %T", err)
	}
}

func TestAuthenticate_InvalidBase64(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, "not-valid-base64!!!")

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	var attestErr ErrAttestationFailed
	if !errors.As(err, &attestErr) {
		t.Errorf("expected ErrAttestationFailed, got %T", err)
	}
}

func TestAuthenticate_InvalidJSON(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, base64.StdEncoding.EncodeToString([]byte("not json")))

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	var attestErr ErrAttestationFailed
	if !errors.As(err, &attestErr) {
		t.Errorf("expected ErrAttestationFailed, got %T", err)
	}
}

func TestAuthenticate_MissingQuote(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	evidence := AttestationEvidence{
		// Quote is empty
		Signature: []byte("sig"),
		AIK:       []byte("aik"),
		ClientID:  "client",
	}
	data, _ := json.Marshal(evidence)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, base64.StdEncoding.EncodeToString(data))

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for missing quote")
	}
	var attestErr ErrAttestationFailed
	if !errors.As(err, &attestErr) {
		t.Errorf("expected ErrAttestationFailed, got %T", err)
	}
}

func TestAuthenticate_QuoteVerificationFailed(t *testing.T) {
	attestor := &mockAttestor{
		verifyFunc: func(ctx context.Context, quote, sig, aik []byte) (map[int][]byte, error) {
			return nil, errors.New("verification failed")
		},
	}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, createTestEvidence(t, "test-client"))

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for quote verification failure")
	}
	var quoteErr ErrInvalidQuote
	if !errors.As(err, &quoteErr) {
		t.Errorf("expected ErrInvalidQuote, got %T", err)
	}
}

func TestAuthenticate_PolicyDenied(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{
		evaluateFunc: func(ctx context.Context, policy string, input map[string]any) (*PolicyDecision, error) {
			return &PolicyDecision{
				Allow:  false,
				Reason: "client not authorized",
			}, nil
		},
	}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, createTestEvidence(t, "test-client"))

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for policy denial")
	}
	var accessErr ErrAccessDenied
	if !errors.As(err, &accessErr) {
		t.Errorf("expected ErrAccessDenied, got %T", err)
	}
}

func TestAuthenticate_PCRMismatch(t *testing.T) {
	attestor := &mockAttestor{
		verifyFunc: func(ctx context.Context, quote, sig, aik []byte) (map[int][]byte, error) {
			return map[int][]byte{
				0: {0xFF, 0xFF, 0xFF, 0xFF}, // Wrong value
			}, nil
		},
	}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	requiredPCRs := map[int][]byte{
		0: {0x00, 0x01, 0x02, 0x03},
	}

	handler, _ := NewRegistryAuthHandler(attestor, policy, db, WithRequiredPCRs(requiredPCRs))

	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, createTestEvidence(t, "test-client"))

	ctx := context.Background()
	_, err := handler.Authenticate(ctx, req)
	if err == nil {
		t.Fatal("expected error for PCR mismatch")
	}
	var pcrErr ErrPCRMismatch
	if !errors.As(err, &pcrErr) {
		t.Errorf("expected ErrPCRMismatch, got %T", err)
	}
}

// Tests for ValidateSession

func TestValidateSession_Success(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	// First authenticate to create a session
	req := httptest.NewRequest(http.MethodGet, "/v2/test/manifests/latest", nil)
	req.Header.Set(HeaderAttestationEvidence, createTestEvidence(t, "test-client"))

	ctx := context.Background()
	session, err := handler.Authenticate(ctx, req)
	if err != nil {
		t.Fatalf("failed to authenticate: %v", err)
	}

	// Validate the session
	err = handler.ValidateSession(ctx, session)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateSession_NilContext(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	session := &RegistrySession{
		SessionID:  "test-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}

	err := handler.ValidateSession(nil, session) //nolint:staticcheck // testing nil context handling
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestValidateSession_NilSession(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	ctx := context.Background()
	err := handler.ValidateSession(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
	var sessionErr ErrInvalidSession
	if !errors.As(err, &sessionErr) {
		t.Errorf("expected ErrInvalidSession, got %T", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	attestor := &mockAttestor{}
	policy := &mockPolicyEngine{}
	db := newMockQuicBaaSClient()

	handler, _ := NewRegistryAuthHandler(attestor, policy, db)

	session := &RegistrySession{
		SessionID:  "test-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now().Add(-2 * time.Hour),
		ValidUntil: time.Now().Add(-1 * time.Hour), // Already expired
	}

	ctx := context.Background()
	err := handler.ValidateSession(ctx, session)
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	var expiredErr ErrSessionExpired
	if !errors.As(err, &expiredErr) {
		t.Errorf("expected ErrSessionExpired, got %T", err)
	}
}

// Tests for SessionManager

func TestSessionManager_Store_Success(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	session := &RegistrySession{
		SessionID:  "test-session-123",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}

	ctx := context.Background()
	err := mgr.Store(ctx, session)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify session was stored
	stored, err := mgr.Get(ctx, session.SessionID)
	if err != nil {
		t.Errorf("failed to get stored session: %v", err)
	}
	if stored.ClientID != session.ClientID {
		t.Errorf("expected client ID %s, got %s", session.ClientID, stored.ClientID)
	}
}

func TestSessionManager_Store_NilContext(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	session := &RegistrySession{
		SessionID: "test-session",
	}

	err := mgr.Store(nil, session) //nolint:staticcheck // testing nil context handling
	if err == nil {
		t.Fatal("expected error for nil context")
	}
}

func TestSessionManager_Store_NilSession(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	ctx := context.Background()
	err := mgr.Store(ctx, nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestSessionManager_Store_EmptySessionID(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	session := &RegistrySession{
		SessionID: "",
		ClientID:  "test-client",
	}

	ctx := context.Background()
	err := mgr.Store(ctx, session)
	if err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestSessionManager_Get_NotFound(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	ctx := context.Background()
	_, err := mgr.Get(ctx, "nonexistent-session")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
	var notFoundErr ErrSessionNotFound
	if !errors.As(err, &notFoundErr) {
		t.Errorf("expected ErrSessionNotFound, got %T", err)
	}
}

func TestSessionManager_Get_FromCache(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	session := &RegistrySession{
		SessionID:  "cached-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}

	ctx := context.Background()
	_ = mgr.Store(ctx, session)

	// Get should return from cache
	retrieved, err := mgr.Get(ctx, session.SessionID)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if retrieved.ClientID != session.ClientID {
		t.Errorf("expected client ID %s, got %s", session.ClientID, retrieved.ClientID)
	}
}

func TestSessionManager_Delete_Success(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	session := &RegistrySession{
		SessionID:  "to-delete-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}

	ctx := context.Background()
	_ = mgr.Store(ctx, session)

	err := mgr.Delete(ctx, session.SessionID)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Verify session was deleted
	_, err = mgr.Get(ctx, session.SessionID)
	if err == nil {
		t.Error("expected error for deleted session")
	}
}

func TestSessionManager_CleanExpired(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	// Store an expired session in cache directly
	expiredSession := &RegistrySession{
		SessionID:  "expired-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now().Add(-2 * time.Hour),
		ValidUntil: time.Now().Add(-1 * time.Hour),
	}
	mgr.cache.Store(expiredSession.SessionID, expiredSession)

	// Store a valid session
	validSession := &RegistrySession{
		SessionID:  "valid-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}
	mgr.cache.Store(validSession.SessionID, validSession)

	// Clean expired sessions
	mgr.CleanExpired()

	// Expired session should be removed from cache
	if _, ok := mgr.cache.Load(expiredSession.SessionID); ok {
		t.Error("expected expired session to be removed from cache")
	}

	// Valid session should still be in cache
	if _, ok := mgr.cache.Load(validSession.SessionID); !ok {
		t.Error("expected valid session to remain in cache")
	}
}

func TestSessionManager_Close(t *testing.T) {
	db := newMockQuicBaaSClient()
	mgr := NewSessionManager(db, time.Hour)

	// Store a session
	session := &RegistrySession{
		SessionID:  "test-session",
		ClientID:   "test-client",
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}
	mgr.cache.Store(session.SessionID, session)

	err := mgr.Close()
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}

	// Cache should be cleared
	count := 0
	mgr.cache.Range(func(k, v any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected cache to be empty, got %d items", count)
	}
}

// Tests for RegistrySession

func TestRegistrySession_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		session  RegistrySession
		expected bool
	}{
		{
			name: "valid session",
			session: RegistrySession{
				ValidFrom:  time.Now().Add(-time.Minute),
				ValidUntil: time.Now().Add(time.Hour),
			},
			expected: true,
		},
		{
			name: "expired session",
			session: RegistrySession{
				ValidFrom:  time.Now().Add(-2 * time.Hour),
				ValidUntil: time.Now().Add(-time.Hour),
			},
			expected: false,
		},
		{
			name: "not yet valid",
			session: RegistrySession{
				ValidFrom:  time.Now().Add(time.Hour),
				ValidUntil: time.Now().Add(2 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.IsValid()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestRegistrySession_RemainingTime(t *testing.T) {
	// Valid session with time remaining
	validSession := RegistrySession{
		ValidFrom:  time.Now(),
		ValidUntil: time.Now().Add(time.Hour),
	}
	remaining := validSession.RemainingTime()
	if remaining <= 0 || remaining > time.Hour {
		t.Errorf("expected remaining time between 0 and 1 hour, got %v", remaining)
	}

	// Expired session
	expiredSession := RegistrySession{
		ValidFrom:  time.Now().Add(-2 * time.Hour),
		ValidUntil: time.Now().Add(-time.Hour),
	}
	remaining = expiredSession.RemainingTime()
	if remaining != 0 {
		t.Errorf("expected 0 remaining time for expired session, got %v", remaining)
	}
}

// Tests for helper functions

func TestGenerateSessionID(t *testing.T) {
	id1 := generateSessionID()
	id2 := generateSessionID()

	if id1 == "" {
		t.Error("expected non-empty session ID")
	}
	if id1 == id2 {
		t.Error("expected unique session IDs")
	}
	if len(id1) != sessionIDLength*2 { // hex encoding doubles length
		t.Errorf("expected session ID length %d, got %d", sessionIDLength*2, len(id1))
	}
}

func TestAuthBytesEqual(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected bool
	}{
		{
			name:     "equal slices",
			a:        []byte{0x01, 0x02, 0x03},
			b:        []byte{0x01, 0x02, 0x03},
			expected: true,
		},
		{
			name:     "different slices",
			a:        []byte{0x01, 0x02, 0x03},
			b:        []byte{0x01, 0x02, 0x04},
			expected: false,
		},
		{
			name:     "different lengths",
			a:        []byte{0x01, 0x02},
			b:        []byte{0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "empty slices",
			a:        []byte{},
			b:        []byte{},
			expected: true,
		},
		{
			name:     "nil slices",
			a:        nil,
			b:        nil,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bytesEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
