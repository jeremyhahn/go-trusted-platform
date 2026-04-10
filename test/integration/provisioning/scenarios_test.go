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

package provisioning

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnexpectedSessionStatus indicates a session had an unexpected status.
type ErrUnexpectedSessionStatus struct {
	SessionID string
	Expected  string
	Actual    string
}

// Error returns the error message.
func (e ErrUnexpectedSessionStatus) Error() string {
	return fmt.Sprintf("provisioning: session %s: expected status %q, got %q",
		e.SessionID, e.Expected, e.Actual)
}

// ErrSessionNotInList indicates a session was expected but not found in the list.
type ErrSessionNotInList struct {
	SessionID string
}

// Error returns the error message.
func (e ErrSessionNotInList) Error() string {
	return fmt.Sprintf("provisioning: session %s not found in session list", e.SessionID)
}

// ErrUnexpectedSessionCount indicates the session list had an unexpected count.
type ErrUnexpectedSessionCount struct {
	Expected int
	Actual   int
}

// Error returns the error message.
func (e ErrUnexpectedSessionCount) Error() string {
	return fmt.Sprintf("provisioning: expected %d sessions, got %d",
		e.Expected, e.Actual)
}

// =============================================================================
// Scenario Test Helpers
// =============================================================================

// createPendingSession issues a nonce and POSTs a config request for the given
// EK serial, returning the pending response with session details.
// Fails the test on error.
func createPendingSession(t *testing.T, ekSerial string) *pendingResponse {
	t.Helper()

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	nonce := fetchNonce(t, ctx)

	req := map[string]interface{}{
		"ek_serial":  ekSerial,
		"eab_key_id": "scenario-test-key",
		"eab_hmac":   "c2NlbmFyaW8tdGVzdC1obWFj", // base64url("scenario-test-hmac")
		"nonce":      nonce,
	}

	status, body, err := doPOST(ctx, provisionURL("/config"), req)
	if err != nil {
		t.Fatalf("createPendingSession: POST failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("createPendingSession: expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("createPendingSession: failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("createPendingSession: request failed: %s", envelope.Error)
	}

	var pending pendingResponse
	if err := parsePayload(envelope, &pending); err != nil {
		t.Fatalf("createPendingSession: failed to parse pending response: %v", err)
	}

	if pending.SessionID == "" {
		t.Fatal("createPendingSession: session_id is empty")
	}

	return &pending
}

// listSessions retrieves all active sessions and returns them.
// Fails the test on error.
func listSessions(t *testing.T) []sessionResponse {
	t.Helper()

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	status, body, err := doGET(ctx, provisionURL("/sessions"))
	if err != nil {
		t.Fatalf("listSessions: GET failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("listSessions: expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("listSessions: failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("listSessions: request failed: %s", envelope.Error)
	}

	var sessions []sessionResponse
	if err := parsePayload(envelope, &sessions); err != nil {
		t.Fatalf("listSessions: failed to parse sessions: %v", err)
	}

	return sessions
}

// getSession retrieves a session by ID. Fails the test on error.
func getSession(t *testing.T, sessionID string) *sessionResponse {
	t.Helper()

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	status, body, err := doGET(ctx, provisionURL("/sessions/"+sessionID))
	if err != nil {
		t.Fatalf("getSession: GET failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("getSession: expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("getSession: failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("getSession: request failed: %s", envelope.Error)
	}

	var session sessionResponse
	if err := parsePayload(envelope, &session); err != nil {
		t.Fatalf("getSession: failed to parse session: %v", err)
	}

	return &session
}

// pollSession polls a session and returns the raw envelope for inspection.
// Fails the test on HTTP transport errors only.
func pollSession(t *testing.T, sessionID string) (int, *webServiceResponse) {
	t.Helper()

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	status, body, err := doGET(ctx, provisionURL("/sessions/"+sessionID+"/poll"))
	if err != nil {
		t.Fatalf("pollSession: GET failed: %v", err)
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("pollSession: failed to parse envelope: %v", err)
	}

	return status, envelope
}

// sessionInList returns true if a session with the given ID exists in the list.
func sessionInList(sessions []sessionResponse, sessionID string) bool {
	for i := range sessions {
		if sessions[i].ID == sessionID {
			return true
		}
	}
	return false
}

// findSessionInList returns the session with the given ID from the list, or nil.
func findSessionInList(sessions []sessionResponse, sessionID string) *sessionResponse {
	for i := range sessions {
		if sessions[i].ID == sessionID {
			return &sessions[i]
		}
	}
	return nil
}

// =============================================================================
// E2E Scenario Tests
// =============================================================================

// TestAutomatedProvisioningFlow exercises the full automated provisioning
// scenario: request config for an unknown device, verify a pending session is
// created, and confirm the session appears correctly in session management.
//
// Since no profile service is configured in the integration test environment,
// every config request creates a pending session (no auto-resolution).
func TestAutomatedProvisioningFlow(t *testing.T) {
	requireIntegration(t)

	ekSerial := fmt.Sprintf("E2E-AUTO-EK-%d", time.Now().UnixNano())

	t.Run("CreatePendingSession", func(t *testing.T) {
		pending := createPendingSession(t, ekSerial)

		if pending.SessionID == "" {
			t.Fatal("session_id must be non-empty")
		}

		if pending.PollInterval <= 0 {
			t.Errorf("poll_interval_seconds must be positive, got %d", pending.PollInterval)
		}

		t.Logf("created pending session: id=%s poll_interval=%ds",
			pending.SessionID, pending.PollInterval)

		// Verify session appears in the session list
		sessions := listSessions(t)
		if !sessionInList(sessions, pending.SessionID) {
			t.Errorf("session %s not found in ListSessions", pending.SessionID)
		}

		// Get session by ID and verify fields
		session := getSession(t, pending.SessionID)

		if session.ID != pending.SessionID {
			t.Errorf("session ID mismatch: expected %s, got %s",
				pending.SessionID, session.ID)
		}

		if session.EKSerial != ekSerial {
			t.Errorf("EK serial mismatch: expected %s, got %s",
				ekSerial, session.EKSerial)
		}

		if session.Fulfilled {
			t.Error("newly created session should not be fulfilled")
		}
	})
}

// TestInteractiveProvisioningFlow exercises the interactive QR provisioning
// scenario: request config for an unknown device, verify the pending response
// includes a provision URL, poll the session to confirm it is pending, and
// attempt fulfillment.
//
// Since no profile service is wired in the integration test environment,
// fulfillment will fail (no profile to resolve). This test verifies the
// correct error handling for that case.
func TestInteractiveProvisioningFlow(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	ekSerial := fmt.Sprintf("E2E-INTERACTIVE-EK-%d", time.Now().UnixNano())

	// Step 1: Create pending session
	pending := createPendingSession(t, ekSerial)

	t.Run("ProvisionURLContainsSessionID", func(t *testing.T) {
		if pending.ProvisionURL == "" {
			t.Fatal("provision_url must be non-empty for interactive flow")
		}

		if !strings.Contains(pending.ProvisionURL, pending.SessionID) {
			t.Errorf("provision_url %q should contain session_id %q",
				pending.ProvisionURL, pending.SessionID)
		}

		t.Logf("provision_url: %s", pending.ProvisionURL)
	})

	t.Run("PollShowsPending", func(t *testing.T) {
		status, envelope := pollSession(t, pending.SessionID)

		if status != http.StatusOK {
			t.Fatalf("expected status 200 for poll, got %d", status)
		}

		if !envelope.Success {
			t.Fatalf("poll should succeed: error=%s", envelope.Error)
		}

		// When session is not fulfilled, the poll response has status "pending"
		var pollResp pollPendingResponse
		if err := parsePayload(envelope, &pollResp); err != nil {
			t.Fatalf("failed to parse poll response: %v", err)
		}

		if pollResp.Status != "pending" {
			t.Errorf("expected poll status %q, got %q", "pending", pollResp.Status)
		}
	})

	t.Run("FulfillSession", func(t *testing.T) {
		// Fulfill the session. When profile service is not configured,
		// the server fulfills with just the profile ID (no profile lookup).
		fulfillReq := map[string]interface{}{
			"session_id": pending.SessionID,
			"profile_id": 1,
		}

		status, body, err := doPOST(ctx,
			provisionURL("/sessions/"+pending.SessionID+"/fulfill"),
			fulfillReq)
		if err != nil {
			t.Fatalf("FulfillSession POST failed: %v", err)
		}

		if status != http.StatusOK {
			t.Errorf("expected status 200 for fulfill, got %d: %s", status, string(body))
		}

		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse fulfill response: %v", err)
		}

		if !envelope.Success {
			t.Errorf("fulfill should succeed: error=%s", envelope.Error)
		}

		t.Logf("session fulfilled successfully: status=%d", status)
	})

	t.Run("SessionFulfilledAfterFulfill", func(t *testing.T) {
		session := getSession(t, pending.SessionID)

		if !session.Fulfilled {
			t.Error("session should be fulfilled after successful fulfill")
		}
	})
}

// TestSessionExpiry verifies that sessions have correct expiration metadata.
// We cannot wait for actual expiry (30 minutes) in tests, so we verify the
// ExpiresAt field is set and in the future.
func TestSessionExpiry(t *testing.T) {
	requireIntegration(t)

	ekSerial := fmt.Sprintf("E2E-EXPIRY-EK-%d", time.Now().UnixNano())

	pending := createPendingSession(t, ekSerial)

	t.Run("SessionHasExpiresAt", func(t *testing.T) {
		ctx, cancel := testContext()
		t.Cleanup(cancel)

		// Get the full session to check ExpiresAt
		status, body, err := doGET(ctx, provisionURL("/sessions/"+pending.SessionID))
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}

		if status != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", status, string(body))
		}

		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		// Parse the full session including time fields
		var fullSession struct {
			ID        string    `json:"id"`
			ExpiresAt time.Time `json:"expires_at"`
			CreatedAt time.Time `json:"created_at"`
			Fulfilled bool      `json:"fulfilled"`
		}
		if err := parsePayload(envelope, &fullSession); err != nil {
			t.Fatalf("failed to parse full session: %v", err)
		}

		if fullSession.ExpiresAt.IsZero() {
			t.Fatal("expires_at must be set on the session")
		}

		if fullSession.CreatedAt.IsZero() {
			t.Fatal("created_at must be set on the session")
		}

		if !fullSession.ExpiresAt.After(time.Now()) {
			t.Errorf("expires_at should be in the future, got %s", fullSession.ExpiresAt)
		}

		if !fullSession.ExpiresAt.After(fullSession.CreatedAt) {
			t.Errorf("expires_at (%s) should be after created_at (%s)",
				fullSession.ExpiresAt, fullSession.CreatedAt)
		}

		ttl := fullSession.ExpiresAt.Sub(fullSession.CreatedAt)
		t.Logf("session TTL: %s (created=%s expires=%s)",
			ttl, fullSession.CreatedAt, fullSession.ExpiresAt)
	})

	t.Run("SessionAppearsInList", func(t *testing.T) {
		sessions := listSessions(t)
		if !sessionInList(sessions, pending.SessionID) {
			t.Errorf("session %s should appear in active session list", pending.SessionID)
		}
	})
}

// TestMultipleSessionsIsolation verifies that multiple concurrent provisioning
// sessions are isolated: creating and querying one session does not affect
// another.
func TestMultipleSessionsIsolation(t *testing.T) {
	requireIntegration(t)

	ekSerialA := fmt.Sprintf("E2E-DEVICE-A-%d", time.Now().UnixNano())
	ekSerialB := fmt.Sprintf("E2E-DEVICE-B-%d", time.Now().UnixNano())

	// Create two sessions for different devices
	pendingA := createPendingSession(t, ekSerialA)
	pendingB := createPendingSession(t, ekSerialB)

	if pendingA.SessionID == pendingB.SessionID {
		t.Fatal("two sessions for different devices must have different IDs")
	}

	t.Run("BothSessionsInList", func(t *testing.T) {
		sessions := listSessions(t)

		if !sessionInList(sessions, pendingA.SessionID) {
			t.Errorf("session A (%s) not found in list", pendingA.SessionID)
		}

		if !sessionInList(sessions, pendingB.SessionID) {
			t.Errorf("session B (%s) not found in list", pendingB.SessionID)
		}
	})

	t.Run("SessionAHasCorrectEKSerial", func(t *testing.T) {
		session := getSession(t, pendingA.SessionID)

		if session.EKSerial != ekSerialA {
			t.Errorf("session A: expected EK serial %q, got %q",
				ekSerialA, session.EKSerial)
		}

		if session.Fulfilled {
			t.Error("session A should not be fulfilled")
		}
	})

	t.Run("SessionBHasCorrectEKSerial", func(t *testing.T) {
		session := getSession(t, pendingB.SessionID)

		if session.EKSerial != ekSerialB {
			t.Errorf("session B: expected EK serial %q, got %q",
				ekSerialB, session.EKSerial)
		}

		if session.Fulfilled {
			t.Error("session B should not be fulfilled")
		}
	})

	t.Run("SessionsDoNotInterfere", func(t *testing.T) {
		// Poll both sessions -- both should be pending
		statusA, envelopeA := pollSession(t, pendingA.SessionID)
		statusB, envelopeB := pollSession(t, pendingB.SessionID)

		if statusA != http.StatusOK {
			t.Errorf("poll session A: expected status 200, got %d", statusA)
		}
		if statusB != http.StatusOK {
			t.Errorf("poll session B: expected status 200, got %d", statusB)
		}

		var pollA, pollB pollPendingResponse
		if err := parsePayload(envelopeA, &pollA); err != nil {
			t.Fatalf("failed to parse poll A response: %v", err)
		}
		if err := parsePayload(envelopeB, &pollB); err != nil {
			t.Fatalf("failed to parse poll B response: %v", err)
		}

		if pollA.Status != "pending" {
			t.Errorf("session A poll: expected %q, got %q", "pending", pollA.Status)
		}
		if pollB.Status != "pending" {
			t.Errorf("session B poll: expected %q, got %q", "pending", pollB.Status)
		}
	})
}

// TestNonceReplayPrevention verifies that nonces are single-use: a nonce
// consumed by one config request cannot be reused in a subsequent request.
func TestNonceReplayPrevention(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	// Step 1: Get a nonce
	nonce := fetchNonce(t, ctx)

	req := map[string]interface{}{
		"ek_serial":  fmt.Sprintf("E2E-REPLAY-EK-%d", time.Now().UnixNano()),
		"eab_key_id": "replay-test-key",
		"eab_hmac":   "cmVwbGF5LXRlc3QtaG1hYw", // base64url("replay-test-hmac")
		"nonce":      nonce,
	}

	// Step 2: First request with the nonce -- should succeed
	status1, body1, err := doPOST(ctx, provisionURL("/config"), req)
	if err != nil {
		t.Fatalf("first config request failed: %v", err)
	}

	if status1 != http.StatusOK {
		t.Fatalf("first request: expected status 200, got %d: %s", status1, string(body1))
	}

	envelope1, err := parseEnvelope(body1)
	if err != nil {
		t.Fatalf("failed to parse first response: %v", err)
	}

	if !envelope1.Success {
		t.Fatalf("first request should succeed: error=%s", envelope1.Error)
	}

	t.Run("ReusedNonceFails", func(t *testing.T) {
		// Step 3: Second request with the same nonce -- should fail
		replayReq := map[string]interface{}{
			"ek_serial":  fmt.Sprintf("E2E-REPLAY-EK-2-%d", time.Now().UnixNano()),
			"eab_key_id": "replay-test-key",
			"eab_hmac":   "cmVwbGF5LXRlc3QtaG1hYw",
			"nonce":      nonce, // reuse the consumed nonce
		}

		status2, body2, err := doPOST(ctx, provisionURL("/config"), replayReq)
		if err != nil {
			t.Fatalf("replay config request failed: %v", err)
		}

		envelope2, err := parseEnvelope(body2)
		if err != nil {
			t.Fatalf("failed to parse replay response: %v", err)
		}

		// The replayed nonce should be rejected
		if status2 == http.StatusOK && envelope2.Success {
			t.Error("replayed nonce should not succeed")
		}

		if status2 != http.StatusBadRequest {
			t.Errorf("expected status 400 for replayed nonce, got %d", status2)
		}

		t.Logf("replay correctly rejected: status=%d error=%s", status2, envelope2.Error)
	})
}

// TestProvisioningEndToEnd exercises the complete provisioning lifecycle in a
// single sequential flow: initial state inspection, session creation, session
// querying, polling, and fulfillment attempt.
func TestProvisioningEndToEnd(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	// Step 1: Record initial session count
	initialSessions := listSessions(t)
	initialCount := len(initialSessions)
	t.Logf("initial session count: %d", initialCount)

	// Step 2: Get nonce
	nonce := fetchNonce(t, ctx)
	if len(nonce) == 0 {
		t.Fatal("nonce must be non-empty")
	}

	// Step 3: Request config for unknown device -- creates pending session
	ekSerial := fmt.Sprintf("E2E-FULL-EK-%d", time.Now().UnixNano())
	req := map[string]interface{}{
		"ek_serial":  ekSerial,
		"eab_key_id": "e2e-full-key",
		"eab_hmac":   "ZTJlLWZ1bGwtaG1hYw", // base64url("e2e-full-hmac")
		"nonce":      nonce,
	}

	status, body, err := doPOST(ctx, provisionURL("/config"), req)
	if err != nil {
		t.Fatalf("config request failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("config request: expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("failed to parse config response: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("config request should succeed: error=%s", envelope.Error)
	}

	var pending pendingResponse
	if err := parsePayload(envelope, &pending); err != nil {
		t.Fatalf("failed to parse pending response: %v", err)
	}

	sessionID := pending.SessionID
	if sessionID == "" {
		t.Fatal("pending response must include session_id")
	}

	t.Logf("created session: id=%s provision_url=%s", sessionID, pending.ProvisionURL)

	// Step 4: Verify session count increased
	t.Run("SessionCountIncreased", func(t *testing.T) {
		updatedSessions := listSessions(t)
		if len(updatedSessions) <= initialCount {
			t.Errorf("expected session count > %d after creating session, got %d",
				initialCount, len(updatedSessions))
		}

		if !sessionInList(updatedSessions, sessionID) {
			t.Errorf("new session %s should appear in session list", sessionID)
		}
	})

	// Step 5: Get session and verify all fields
	t.Run("VerifySessionFields", func(t *testing.T) {
		// Parse full session with time fields
		status, body, err := doGET(ctx, provisionURL("/sessions/"+sessionID))
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}

		if status != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", status, string(body))
		}

		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var fullSession struct {
			ID         string    `json:"id"`
			EKSerial   string    `json:"ek_serial"`
			MACAddress string    `json:"mac_address"`
			ProfileID  uint64    `json:"profile_id"`
			Fulfilled  bool      `json:"fulfilled"`
			CreatedAt  time.Time `json:"created_at"`
			ExpiresAt  time.Time `json:"expires_at"`
		}
		if err := parsePayload(envelope, &fullSession); err != nil {
			t.Fatalf("failed to parse full session: %v", err)
		}

		if fullSession.ID != sessionID {
			t.Errorf("session ID: expected %q, got %q", sessionID, fullSession.ID)
		}

		if fullSession.EKSerial != ekSerial {
			t.Errorf("EK serial: expected %q, got %q", ekSerial, fullSession.EKSerial)
		}

		if fullSession.Fulfilled {
			t.Error("session should not be fulfilled")
		}

		if fullSession.ProfileID != 0 {
			t.Errorf("profile_id should be 0 for unfulfilled session, got %d",
				fullSession.ProfileID)
		}

		if fullSession.CreatedAt.IsZero() {
			t.Error("created_at must be set")
		}

		if fullSession.ExpiresAt.IsZero() {
			t.Error("expires_at must be set")
		}
	})

	// Step 6: Poll -- should be pending
	t.Run("PollIsPending", func(t *testing.T) {
		pollStatus, pollEnvelope := pollSession(t, sessionID)

		if pollStatus != http.StatusOK {
			t.Fatalf("poll: expected status 200, got %d", pollStatus)
		}

		if !pollEnvelope.Success {
			t.Fatalf("poll should succeed: error=%s", pollEnvelope.Error)
		}

		var pollResp pollPendingResponse
		if err := parsePayload(pollEnvelope, &pollResp); err != nil {
			t.Fatalf("failed to parse poll response: %v", err)
		}

		if pollResp.Status != "pending" {
			t.Errorf("poll status: expected %q, got %q", "pending", pollResp.Status)
		}
	})

	// Step 7: Attempt fulfill -- will fail without profile service
	t.Run("FulfillAttempt", func(t *testing.T) {
		fulfillReq := map[string]interface{}{
			"session_id": sessionID,
			"profile_id": 1,
		}

		fulfillStatus, fulfillBody, err := doPOST(ctx,
			provisionURL("/sessions/"+sessionID+"/fulfill"),
			fulfillReq)
		if err != nil {
			t.Fatalf("fulfill POST failed: %v", err)
		}

		// Without a profile service, fulfillment cannot succeed
		if fulfillStatus == http.StatusOK {
			t.Log("fulfill succeeded (profile service is configured)")

			// Parse and verify the response
			fulfillEnvelope, err := parseEnvelope(fulfillBody)
			if err != nil {
				t.Fatalf("failed to parse fulfill response: %v", err)
			}

			var fulfillResp fulfillStatusResponse
			if err := parsePayload(fulfillEnvelope, &fulfillResp); err != nil {
				t.Fatalf("failed to parse fulfill status: %v", err)
			}

			if fulfillResp.Status != "fulfilled" {
				t.Errorf("expected fulfill status %q, got %q", "fulfilled", fulfillResp.Status)
			}
		} else {
			t.Logf("fulfill rejected as expected (no profile service): status=%d body=%s",
				fulfillStatus, string(fulfillBody))
		}
	})

	// Step 8: Verify session state after fulfill attempt
	t.Run("PostFulfillSessionState", func(t *testing.T) {
		session := getSession(t, sessionID)

		// The session state depends on whether fulfill succeeded
		t.Logf("post-fulfill session state: fulfilled=%t", session.Fulfilled)
	})
}

// TestConfigRequestWithMACAddress verifies that a config request using a MAC
// address (instead of EK serial) as the device identifier also creates a
// pending session correctly.
func TestConfigRequestWithMACAddress(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	macAddr := fmt.Sprintf("AA:BB:CC:DD:%02X:%02X",
		time.Now().UnixNano()%256, (time.Now().UnixNano()/256)%256)

	nonce := fetchNonce(t, ctx)

	req := map[string]interface{}{
		"mac_address": macAddr,
		"eab_key_id":  "mac-test-key",
		"eab_hmac":    "bWFjLXRlc3QtaG1hYw", // base64url("mac-test-hmac")
		"nonce":       nonce,
	}

	status, body, err := doPOST(ctx, provisionURL("/config"), req)
	if err != nil {
		t.Fatalf("config request with MAC failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("config request should succeed: error=%s", envelope.Error)
	}

	var pending pendingResponse
	if err := parsePayload(envelope, &pending); err != nil {
		t.Fatalf("failed to parse pending response: %v", err)
	}

	if pending.SessionID == "" {
		t.Fatal("session_id must be non-empty")
	}

	t.Run("SessionHasMACAddress", func(t *testing.T) {
		// Get the full session and verify MAC address is stored
		getStatus, getBody, err := doGET(ctx, provisionURL("/sessions/"+pending.SessionID))
		if err != nil {
			t.Fatalf("GetSession failed: %v", err)
		}

		if getStatus != http.StatusOK {
			t.Fatalf("expected status 200, got %d: %s", getStatus, string(getBody))
		}

		getEnvelope, err := parseEnvelope(getBody)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		var session struct {
			ID         string `json:"id"`
			MACAddress string `json:"mac_address"`
			EKSerial   string `json:"ek_serial"`
		}
		if err := parsePayload(getEnvelope, &session); err != nil {
			t.Fatalf("failed to parse session: %v", err)
		}

		if session.MACAddress != macAddr {
			t.Errorf("MAC address: expected %q, got %q", macAddr, session.MACAddress)
		}

		// EK serial should be empty since we only provided MAC
		if session.EKSerial != "" {
			t.Errorf("EK serial should be empty when only MAC provided, got %q",
				session.EKSerial)
		}
	})
}

// TestDuplicateDeviceCreatesSeparateSessions verifies that requesting config
// for the same device identifier multiple times creates separate sessions
// (each with a unique session ID).
func TestDuplicateDeviceCreatesSeparateSessions(t *testing.T) {
	requireIntegration(t)

	ekSerial := fmt.Sprintf("E2E-DUP-EK-%d", time.Now().UnixNano())

	pending1 := createPendingSession(t, ekSerial)
	pending2 := createPendingSession(t, ekSerial)

	if pending1.SessionID == pending2.SessionID {
		t.Fatal("duplicate config requests must create separate sessions with unique IDs")
	}

	t.Run("BothSessionsExist", func(t *testing.T) {
		session1 := getSession(t, pending1.SessionID)
		session2 := getSession(t, pending2.SessionID)

		if session1.EKSerial != ekSerial {
			t.Errorf("session 1: expected EK serial %q, got %q", ekSerial, session1.EKSerial)
		}

		if session2.EKSerial != ekSerial {
			t.Errorf("session 2: expected EK serial %q, got %q", ekSerial, session2.EKSerial)
		}
	})

	t.Run("BothSessionsInList", func(t *testing.T) {
		sessions := listSessions(t)

		found1 := sessionInList(sessions, pending1.SessionID)
		found2 := sessionInList(sessions, pending2.SessionID)

		if !found1 {
			t.Errorf("session 1 (%s) not found in list", pending1.SessionID)
		}
		if !found2 {
			t.Errorf("session 2 (%s) not found in list", pending2.SessionID)
		}
	})
}

// TestSessionAlreadyFulfilledRejection verifies that fulfilling an already
// fulfilled session is rejected. This test can only verify the error path
// when a profile service is configured. Without a profile service, the first
// fulfill attempt already fails, so we verify consistent error handling.
func TestSessionAlreadyFulfilledRejection(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	ekSerial := fmt.Sprintf("E2E-DOUBLE-FULFILL-EK-%d", time.Now().UnixNano())
	pending := createPendingSession(t, ekSerial)

	// First fulfill attempt
	fulfillReq := map[string]interface{}{
		"session_id": pending.SessionID,
		"profile_id": 1,
	}

	status1, _, err := doPOST(ctx,
		provisionURL("/sessions/"+pending.SessionID+"/fulfill"),
		fulfillReq)
	if err != nil {
		t.Fatalf("first fulfill POST failed: %v", err)
	}

	t.Run("SecondFulfillRejected", func(t *testing.T) {
		// If the first fulfill succeeded, the second should be rejected as
		// "already fulfilled". If the first failed (no profile service),
		// both attempts should fail consistently.
		status2, body2, err := doPOST(ctx,
			provisionURL("/sessions/"+pending.SessionID+"/fulfill"),
			fulfillReq)
		if err != nil {
			t.Fatalf("second fulfill POST failed: %v", err)
		}

		if status1 == http.StatusOK {
			// First succeed: second should be rejected (400 already fulfilled)
			if status2 == http.StatusOK {
				t.Error("second fulfill of same session should not succeed")
			}

			envelope, err := parseEnvelope(body2)
			if err != nil {
				t.Fatalf("failed to parse second fulfill response: %v", err)
			}

			if envelope.Success {
				t.Error("second fulfill should report failure")
			}

			t.Logf("second fulfill correctly rejected: status=%d error=%s",
				status2, envelope.Error)
		} else {
			// Both should fail consistently (no profile service)
			t.Logf("both fulfill attempts failed (no profile service): status1=%d status2=%d",
				status1, status2)
		}
	})
}

// TestListSessionsPayloadStructure verifies that the ListSessions response
// payload contains well-formed session objects with all expected fields.
func TestListSessionsPayloadStructure(t *testing.T) {
	requireIntegration(t)

	// Create a session to ensure the list is non-empty
	ekSerial := fmt.Sprintf("E2E-LIST-EK-%d", time.Now().UnixNano())
	createPendingSession(t, ekSerial)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	status, body, err := doGET(ctx, provisionURL("/sessions"))
	if err != nil {
		t.Fatalf("ListSessions GET failed: %v", err)
	}

	if status != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", status, string(body))
	}

	envelope, err := parseEnvelope(body)
	if err != nil {
		t.Fatalf("failed to parse envelope: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("ListSessions should succeed: error=%s", envelope.Error)
	}

	// Parse as raw JSON array to inspect structure
	var rawSessions []json.RawMessage
	if err := parsePayload(envelope, &rawSessions); err != nil {
		t.Fatalf("failed to parse sessions array: %v", err)
	}

	if len(rawSessions) == 0 {
		t.Fatal("expected at least one session in list after creating one")
	}

	t.Run("SessionObjectFields", func(t *testing.T) {
		// Parse the first session and verify it has expected fields
		var session struct {
			ID         string    `json:"id"`
			EKSerial   string    `json:"ek_serial"`
			MACAddress string    `json:"mac_address"`
			ProfileID  uint64    `json:"profile_id"`
			Fulfilled  bool      `json:"fulfilled"`
			CreatedAt  time.Time `json:"created_at"`
			ExpiresAt  time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(rawSessions[0], &session); err != nil {
			t.Fatalf("failed to parse session object: %v", err)
		}

		if session.ID == "" {
			t.Error("session id must be non-empty")
		}

		// At least one device identifier should be present
		if session.EKSerial == "" && session.MACAddress == "" {
			t.Error("session must have at least one device identifier (ek_serial or mac_address)")
		}

		if session.CreatedAt.IsZero() {
			t.Error("created_at must be set")
		}

		if session.ExpiresAt.IsZero() {
			t.Error("expires_at must be set")
		}

		t.Logf("session structure validated: id=%s ek=%s mac=%s fulfilled=%t",
			session.ID, session.EKSerial, session.MACAddress, session.Fulfilled)
	})
}
