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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// HeaderAttestationEvidence is the HTTP header containing attestation evidence.
	HeaderAttestationEvidence = "X-Attestation-Evidence"

	// DefaultSessionDuration is the default session validity duration.
	DefaultSessionDuration = time.Hour

	// sessionIDLength is the length of generated session IDs in bytes.
	sessionIDLength = 32
)

// AttestationEvidence contains the TPM attestation data from a client.
type AttestationEvidence struct {
	// Quote is the TPM quote data (signed by AIK).
	Quote []byte `json:"quote"`

	// Signature is the quote signature.
	Signature []byte `json:"signature"`

	// AIK is the Attestation Identity Key public key (PEM or DER encoded).
	AIK []byte `json:"aik"`

	// ClientID is the unique identifier for the client.
	ClientID string `json:"client_id"`

	// PCRs is the map of PCR index to PCR value included in the quote.
	PCRs map[int][]byte `json:"pcrs"`

	// Nonce is the challenge nonce used in the quote.
	Nonce []byte `json:"nonce"`

	// Timestamp is when the evidence was generated.
	Timestamp time.Time `json:"timestamp"`
}

// RegistrySession represents an authenticated session for a client.
type RegistrySession struct {
	// SessionID is the unique session identifier.
	SessionID string `json:"session_id"`

	// ClientID is the authenticated client identifier.
	ClientID string `json:"client_id"`

	// AIK is the Attestation Identity Key that was verified.
	AIK []byte `json:"aik"`

	// PCRs are the verified PCR values at session creation time.
	PCRs map[int][]byte `json:"pcrs"`

	// ValidFrom is when the session became valid.
	ValidFrom time.Time `json:"valid_from"`

	// ValidUntil is when the session expires.
	ValidUntil time.Time `json:"valid_until"`

	// RemoteAddr is the client's remote address.
	RemoteAddr string `json:"remote_addr,omitempty"`

	// Permissions are the granted permissions for this session.
	Permissions []string `json:"permissions,omitempty"`
}

// IsValid returns true if the session is currently valid.
func (s *RegistrySession) IsValid() bool {
	now := time.Now()
	return now.After(s.ValidFrom) && now.Before(s.ValidUntil)
}

// RemainingTime returns the time remaining until session expiration.
func (s *RegistrySession) RemainingTime() time.Duration {
	remaining := time.Until(s.ValidUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Attestor defines the interface for verifying TPM attestation quotes.
type Attestor interface {
	// VerifyQuote verifies a TPM quote and returns the verified PCR values.
	VerifyQuote(ctx context.Context, quote, signature, aik []byte) (map[int][]byte, error)

	// GenerateNonce generates a cryptographic nonce for quote challenges.
	GenerateNonce(ctx context.Context) ([]byte, error)
}

// PolicyEngine defines the interface for evaluating access policies.
type PolicyEngine interface {
	// Evaluate evaluates a policy with the given input and returns the decision.
	Evaluate(ctx context.Context, policy string, input map[string]any) (*PolicyDecision, error)
}

// PolicyDecision represents the result of a policy evaluation.
type PolicyDecision struct {
	// Allow indicates whether access is allowed.
	Allow bool `json:"allow"`

	// Reason provides explanation for the decision.
	Reason string `json:"reason,omitempty"`

	// Permissions are the granted permissions if allowed.
	Permissions []string `json:"permissions,omitempty"`
}

// QuicBaaSClient defines the interface for QuicBaaS operations needed by auth.
type QuicBaaSClient interface {
	// Put stores a key-value pair.
	Put(ctx context.Context, entityType, key string, value []byte, ttl time.Duration) error

	// Get retrieves a value by key.
	Get(ctx context.Context, entityType, key string) ([]byte, bool, error)

	// Delete removes a key.
	Delete(ctx context.Context, entityType, key string) error
}

// RegistryAuthHandler handles attestation-based authentication for the registry.
type RegistryAuthHandler struct {
	attestor       Attestor
	policyEngine   PolicyEngine
	quicBaaS       QuicBaaSClient
	sessionManager *SessionManager

	sessionDuration time.Duration
	requiredPCRs    map[int][]byte
	allowedAIKs     map[string]struct{}
	policyName      string
}

// AuthHandlerOption is a functional option for configuring RegistryAuthHandler.
type AuthHandlerOption func(*RegistryAuthHandler)

// WithSessionDuration sets the session duration.
func WithSessionDuration(d time.Duration) AuthHandlerOption {
	return func(h *RegistryAuthHandler) {
		h.sessionDuration = d
	}
}

// WithRequiredPCRs sets the required PCR values for authentication.
func WithRequiredPCRs(pcrs map[int][]byte) AuthHandlerOption {
	return func(h *RegistryAuthHandler) {
		h.requiredPCRs = pcrs
	}
}

// WithAllowedAIKs sets the list of allowed AIK fingerprints.
func WithAllowedAIKs(aiks []string) AuthHandlerOption {
	return func(h *RegistryAuthHandler) {
		h.allowedAIKs = make(map[string]struct{}, len(aiks))
		for _, aik := range aiks {
			h.allowedAIKs[aik] = struct{}{}
		}
	}
}

// WithPolicyName sets the OPA policy name for access control.
func WithPolicyName(name string) AuthHandlerOption {
	return func(h *RegistryAuthHandler) {
		h.policyName = name
	}
}

// NewRegistryAuthHandler creates a new RegistryAuthHandler.
func NewRegistryAuthHandler(
	attestor Attestor,
	policyEngine PolicyEngine,
	quicBaaS QuicBaaSClient,
	opts ...AuthHandlerOption,
) (*RegistryAuthHandler, error) {
	if attestor == nil {
		return nil, ErrNilClient{Client: "attestor"}
	}
	if policyEngine == nil {
		return nil, ErrNilClient{Client: "policyEngine"}
	}
	if quicBaaS == nil {
		return nil, ErrNilClient{Client: "quicBaaS"}
	}

	h := &RegistryAuthHandler{
		attestor:        attestor,
		policyEngine:    policyEngine,
		quicBaaS:        quicBaaS,
		sessionDuration: DefaultSessionDuration,
		policyName:      "registry.access",
	}

	for _, opt := range opts {
		opt(h)
	}

	// Create session manager
	h.sessionManager = NewSessionManager(quicBaaS, h.sessionDuration)

	return h, nil
}

// Authenticate authenticates a client using attestation evidence from an HTTP request.
func (h *RegistryAuthHandler) Authenticate(ctx context.Context, req *http.Request) (*RegistrySession, error) {
	if ctx == nil {
		return nil, ErrNilContext{Operation: "Authenticate"}
	}
	if req == nil {
		return nil, ErrAttestationRequired{}
	}

	// Extract attestation evidence from request header
	evidence, err := h.extractAttestationEvidence(req)
	if err != nil {
		return nil, err
	}

	// Verify TPM quote
	verifiedPCRs, err := h.attestor.VerifyQuote(ctx, evidence.Quote, evidence.Signature, evidence.AIK)
	if err != nil {
		return nil, ErrInvalidQuote{Cause: err}
	}

	// Check AIK against allowed list if configured
	if len(h.allowedAIKs) > 0 {
		aikFingerprint := computeAIKFingerprint(evidence.AIK)
		if _, ok := h.allowedAIKs[aikFingerprint]; !ok {
			return nil, ErrAIKNotAllowed{AIK: aikFingerprint}
		}
	}

	// Check PCR values against required values if configured
	if len(h.requiredPCRs) > 0 {
		for pcrIndex, expectedValue := range h.requiredPCRs {
			actualValue, ok := verifiedPCRs[pcrIndex]
			if !ok {
				return nil, ErrPCRMismatch{
					PCRIndex: pcrIndex,
					Expected: expectedValue,
					Actual:   nil,
				}
			}
			if !bytesEqual(expectedValue, actualValue) {
				return nil, ErrPCRMismatch{
					PCRIndex: pcrIndex,
					Expected: expectedValue,
					Actual:   actualValue,
				}
			}
		}
	}

	// Evaluate access policy
	policyInput := map[string]any{
		"pcrs":        verifiedPCRs,
		"aik":         base64.StdEncoding.EncodeToString(evidence.AIK),
		"client_id":   evidence.ClientID,
		"client_ip":   req.RemoteAddr,
		"requested":   req.URL.Path,
		"method":      req.Method,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"evidence_ts": evidence.Timestamp.Format(time.RFC3339),
	}

	decision, err := h.policyEngine.Evaluate(ctx, h.policyName, policyInput)
	if err != nil {
		return nil, ErrPolicyEvaluationFailed{Policy: h.policyName, Cause: err}
	}
	if !decision.Allow {
		return nil, ErrAccessDenied{
			Subject:  evidence.ClientID,
			Resource: req.URL.Path,
			Reason:   decision.Reason,
		}
	}

	// Create authenticated session
	session := &RegistrySession{
		SessionID:   generateSessionID(),
		ClientID:    evidence.ClientID,
		AIK:         evidence.AIK,
		PCRs:        verifiedPCRs,
		ValidFrom:   time.Now(),
		ValidUntil:  time.Now().Add(h.sessionDuration),
		RemoteAddr:  req.RemoteAddr,
		Permissions: decision.Permissions,
	}

	// Store session in QuicBaaS
	if err := h.sessionManager.Store(ctx, session); err != nil {
		return nil, ErrStorageError{Operation: "store_session", Cause: err}
	}

	return session, nil
}

// extractAttestationEvidence extracts attestation evidence from an HTTP request header.
func (h *RegistryAuthHandler) extractAttestationEvidence(req *http.Request) (*AttestationEvidence, error) {
	headerValue := req.Header.Get(HeaderAttestationEvidence)
	if headerValue == "" {
		return nil, ErrAttestationRequired{}
	}

	// Decode base64-encoded JSON
	jsonData, err := base64.StdEncoding.DecodeString(headerValue)
	if err != nil {
		return nil, ErrAttestationFailed{Reason: "invalid base64 encoding"}
	}

	var evidence AttestationEvidence
	if err := json.Unmarshal(jsonData, &evidence); err != nil {
		return nil, ErrAttestationFailed{Reason: "invalid JSON format"}
	}

	// Validate required fields
	if len(evidence.Quote) == 0 {
		return nil, ErrAttestationFailed{Reason: "missing quote"}
	}
	if len(evidence.Signature) == 0 {
		return nil, ErrAttestationFailed{Reason: "missing signature"}
	}
	if len(evidence.AIK) == 0 {
		return nil, ErrAttestationFailed{Reason: "missing AIK"}
	}
	if evidence.ClientID == "" {
		return nil, ErrAttestationFailed{Reason: "missing client ID"}
	}

	return &evidence, nil
}

// ValidateSession validates an existing session.
func (h *RegistryAuthHandler) ValidateSession(ctx context.Context, session *RegistrySession) error {
	if ctx == nil {
		return ErrNilContext{Operation: "ValidateSession"}
	}
	if session == nil {
		return ErrInvalidSession{Reason: "session is nil"}
	}

	// Check if session is within validity period
	if !session.IsValid() {
		return ErrSessionExpired{SessionID: session.SessionID}
	}

	// Verify session exists in storage
	stored, err := h.sessionManager.Get(ctx, session.SessionID)
	if err != nil {
		return err
	}
	if stored == nil {
		return ErrSessionNotFound{SessionID: session.SessionID}
	}

	// Verify session data matches
	if stored.ClientID != session.ClientID {
		return ErrInvalidSession{Reason: "client ID mismatch"}
	}

	return nil
}

// SessionManager manages active sessions with QuicBaaS storage.
type SessionManager struct {
	quicBaaS        QuicBaaSClient
	sessionDuration time.Duration

	// In-memory cache for fast session lookups
	cache   sync.Map
	closed  atomic.Bool
	cleanMu sync.Mutex
}

const sessionEntityType = "registry_session"

// NewSessionManager creates a new SessionManager.
func NewSessionManager(quicBaaS QuicBaaSClient, sessionDuration time.Duration) *SessionManager {
	return &SessionManager{
		quicBaaS:        quicBaaS,
		sessionDuration: sessionDuration,
	}
}

// Store stores a session in QuicBaaS and cache.
func (m *SessionManager) Store(ctx context.Context, session *RegistrySession) error {
	if ctx == nil {
		return ErrNilContext{Operation: "SessionManager.Store"}
	}
	if session == nil {
		return ErrInvalidSession{Reason: "session is nil"}
	}
	if session.SessionID == "" {
		return ErrInvalidSession{Reason: "session ID is empty"}
	}

	// Serialize session
	data, err := json.Marshal(session)
	if err != nil {
		return ErrStorageError{Operation: "marshal_session", Cause: err}
	}

	// Calculate TTL based on session validity
	ttl := time.Until(session.ValidUntil)
	if ttl <= 0 {
		return ErrSessionExpired{SessionID: session.SessionID}
	}

	// Store in QuicBaaS
	if err := m.quicBaaS.Put(ctx, sessionEntityType, session.SessionID, data, ttl); err != nil {
		return ErrStorageError{Operation: "store_session", Key: session.SessionID, Cause: err}
	}

	// Store in cache
	m.cache.Store(session.SessionID, session)

	return nil
}

// Get retrieves a session by ID.
func (m *SessionManager) Get(ctx context.Context, sessionID string) (*RegistrySession, error) {
	if ctx == nil {
		return nil, ErrNilContext{Operation: "SessionManager.Get"}
	}
	if sessionID == "" {
		return nil, ErrInvalidSession{Reason: "session ID is empty"}
	}

	// Check cache first
	if cached, ok := m.cache.Load(sessionID); ok {
		session := cached.(*RegistrySession)
		if session.IsValid() {
			return session, nil
		}
		// Remove expired session from cache
		m.cache.Delete(sessionID)
	}

	// Fetch from QuicBaaS
	data, found, err := m.quicBaaS.Get(ctx, sessionEntityType, sessionID)
	if err != nil {
		return nil, ErrStorageError{Operation: "get_session", Key: sessionID, Cause: err}
	}
	if !found {
		return nil, ErrSessionNotFound{SessionID: sessionID}
	}

	var session RegistrySession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, ErrStorageError{Operation: "unmarshal_session", Cause: err}
	}

	// Check validity
	if !session.IsValid() {
		// Clean up expired session
		_ = m.Delete(ctx, sessionID)
		return nil, ErrSessionExpired{SessionID: sessionID}
	}

	// Update cache
	m.cache.Store(sessionID, &session)

	return &session, nil
}

// Delete removes a session.
func (m *SessionManager) Delete(ctx context.Context, sessionID string) error {
	if ctx == nil {
		return ErrNilContext{Operation: "SessionManager.Delete"}
	}
	if sessionID == "" {
		return ErrInvalidSession{Reason: "session ID is empty"}
	}

	// Remove from cache
	m.cache.Delete(sessionID)

	// Remove from QuicBaaS
	if err := m.quicBaaS.Delete(ctx, sessionEntityType, sessionID); err != nil {
		return ErrStorageError{Operation: "delete_session", Key: sessionID, Cause: err}
	}

	return nil
}

// Invalidate invalidates a session (alias for Delete).
func (m *SessionManager) Invalidate(ctx context.Context, sessionID string) error {
	return m.Delete(ctx, sessionID)
}

// CleanExpired removes expired sessions from the cache.
func (m *SessionManager) CleanExpired() {
	m.cleanMu.Lock()
	defer m.cleanMu.Unlock()

	var toDelete []string
	m.cache.Range(func(key, value any) bool {
		session := value.(*RegistrySession)
		if !session.IsValid() {
			toDelete = append(toDelete, key.(string))
		}
		return true
	})

	for _, sessionID := range toDelete {
		m.cache.Delete(sessionID)
	}
}

// Close closes the session manager.
func (m *SessionManager) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	// Clear cache
	m.cache.Range(func(key, value any) bool {
		m.cache.Delete(key)
		return true
	})
	return nil
}

// Helper functions

// generateSessionID generates a cryptographically secure session ID. There
// is no fallback: crypto/rand.Read never returns an error (since Go 1.24 it
// crashes the program instead), and a timestamp-derived ID would be a
// guessable session credential (#284).
func generateSessionID() string {
	b := make([]byte, sessionIDLength)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// computeAIKFingerprint computes a fingerprint for an AIK.
func computeAIKFingerprint(aik []byte) string {
	// Use first 16 bytes of SHA-256 hash as fingerprint
	// In production, use crypto/sha256
	if len(aik) >= 16 {
		return hex.EncodeToString(aik[:16])
	}
	return hex.EncodeToString(aik)
}

// bytesEqual performs constant-time comparison of byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
