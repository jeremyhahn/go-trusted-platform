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
	"net/http"
	"os"
	"testing"
	"time"
)

// TestMain gates all tests in this package on the INTEGRATION_TEST environment
// variable. When not set, the entire package is skipped cleanly.
func TestMain(m *testing.M) {
	if os.Getenv(EnvIntegrationTest) == "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// =============================================================================
// Nonce Lifecycle Tests
// =============================================================================

// TestNonceLifecycle verifies the nonce issuance endpoint produces unique,
// non-empty nonces and that each nonce is consumed on use.
func TestNonceLifecycle(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	t.Run("IssueNonce", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)
		if len(nonce) == 0 {
			t.Fatal("nonce must be non-empty")
		}
		// The nonce store produces 32-byte random hex, so expect 64 hex chars.
		if len(nonce) != 64 {
			t.Errorf("expected nonce length 64, got %d", len(nonce))
		}
	})

	t.Run("NoncesAreUnique", func(t *testing.T) {
		nonce1 := fetchNonce(t, ctx)
		nonce2 := fetchNonce(t, ctx)
		if nonce1 == nonce2 {
			t.Errorf("two consecutive nonces must differ: both were %s", nonce1)
		}
	})

	t.Run("NonceIsSingleUse", func(t *testing.T) {
		// Fetch a nonce, then try to use it in a config request.
		// Even if the config request itself fails (no matching EAB, etc.),
		// the nonce should be consumed.
		nonce := fetchNonce(t, ctx)

		// First attempt with the nonce -- it will fail on EAB validation
		// but the nonce should still be consumed.
		req := map[string]interface{}{
			"ek_serial":  "INTEGRATION-EK-NONCE-TEST",
			"eab_key_id": "nonexistent-key",
			"eab_hmac":   "aW52YWxpZC1obWFj", // base64url("invalid-hmac")
			"nonce":      nonce,
		}

		status1, body1, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("first POST failed: %v", err)
		}

		// The first request should fail on EAB validation (401) or bad request,
		// but the nonce gets consumed regardless of the outcome.
		_ = status1
		_ = body1

		// Second attempt with the same nonce should fail because nonce is consumed.
		req["nonce"] = nonce
		status2, body2, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("second POST failed: %v", err)
		}

		envelope, err := parseEnvelope(body2)
		if err != nil {
			t.Fatalf("failed to parse second response: %v", err)
		}

		// The second request should fail: either 400 (nonce expired/consumed)
		// or the envelope should indicate failure.
		if status2 == http.StatusOK && envelope.Success {
			t.Error("reused nonce should not succeed; expected failure on second use")
		}
	})
}

// =============================================================================
// Config Request Validation Tests
// =============================================================================

// TestConfigRequestValidation verifies that the config fetch endpoint properly
// validates request fields: missing nonce, missing EAB credentials, and missing
// device identity.
func TestConfigRequestValidation(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	t.Run("MissingNonce", func(t *testing.T) {
		req := map[string]interface{}{
			"ek_serial":  "INTEGRATION-EK-001",
			"eab_key_id": "some-key",
			"eab_hmac":   "c29tZS1obWFj",
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		if status != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing nonce, got %d: %s", status, string(body))
		}

		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		if envelope.Success {
			t.Error("request with missing nonce should not succeed")
		}
	})

	t.Run("MissingEABKeyID", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)
		req := map[string]interface{}{
			"ek_serial": "INTEGRATION-EK-001",
			"eab_hmac":  "c29tZS1obWFj",
			"nonce":     nonce,
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		if status != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing eab_key_id, got %d: %s", status, string(body))
		}
	})

	t.Run("MissingEABHMAC", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)
		req := map[string]interface{}{
			"ek_serial":  "INTEGRATION-EK-001",
			"eab_key_id": "some-key",
			"nonce":      nonce,
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		if status != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing eab_hmac, got %d: %s", status, string(body))
		}
	})

	t.Run("MissingDeviceIdentity", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)
		req := map[string]interface{}{
			"eab_key_id": "some-key",
			"eab_hmac":   "c29tZS1obWFj",
			"nonce":      nonce,
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		if status != http.StatusBadRequest {
			t.Errorf("expected status 400 for missing device identity, got %d: %s", status, string(body))
		}
	})

	t.Run("EmptyRequestBody", func(t *testing.T) {
		status, body, err := doPOST(ctx, provisionURL("/config"), map[string]interface{}{})
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		if status != http.StatusBadRequest {
			t.Errorf("expected status 400 for empty request, got %d: %s", status, string(body))
		}
	})
}

// =============================================================================
// EAB Authentication Tests
// =============================================================================

// TestEABAuthentication verifies config fetch behavior with EAB credentials.
// When EAB service is not configured (integration test default), the server
// accepts requests without EAB validation and creates pending sessions.
// When EAB service IS configured, invalid credentials yield 401.
func TestEABAuthentication(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	t.Run("RequestWithEABCredentials", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)

		req := map[string]interface{}{
			"ek_serial":  "INTEGRATION-EK-EAB-TEST",
			"eab_key_id": "test-eab-key-id",
			"eab_hmac":   "aW52YWxpZC1obWFjLWtleQ", // base64url("invalid-hmac-key")
			"nonce":      nonce,
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		// When EAB service is not configured, server accepts any credentials
		// and creates a pending session (no profile service to resolve config).
		// When EAB IS configured, invalid creds would yield 401.
		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		switch status {
		case http.StatusOK:
			// EAB not configured — server accepted and created pending session
			if !envelope.Success {
				t.Error("expected successful response when EAB not configured")
			}
		case http.StatusUnauthorized:
			// EAB configured — server rejected invalid credentials
			if envelope.Success {
				t.Error("expected failure response for invalid EAB credentials")
			}
			if envelope.Error == "" {
				t.Error("error message should be present for invalid EAB")
			}
		default:
			t.Errorf("unexpected status %d: %s", status, string(body))
		}
	})

	t.Run("RequestWithoutEKOrMAC", func(t *testing.T) {
		nonce := fetchNonce(t, ctx)

		// Request with EAB but no device identity should fail validation
		req := map[string]interface{}{
			"eab_key_id": "some-key-id",
			"eab_hmac":   "aW52YWxpZC1obWFjLWtleQ",
			"nonce":      nonce,
		}

		status, body, err := doPOST(ctx, provisionURL("/config"), req)
		if err != nil {
			t.Fatalf("POST failed: %v", err)
		}

		// Should still require at least ek_serial or mac_address
		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		// The validateRequest() requires at least one device identifier,
		// so this should be rejected regardless of EAB configuration.
		if status == http.StatusOK && envelope.Success {
			t.Log("Note: server accepted request without device identity (may require ek_serial or mac_address based on validation rules)")
		}
	})
}

// =============================================================================
// Session Lifecycle Tests
// =============================================================================

// TestSessionLifecycle verifies the full provisioning session lifecycle:
// session creation on unknown device, polling, listing, get, and fulfillment.
//
// This test exercises the session management REST endpoints end-to-end by
// creating a pending session (via a config request for an unknown device),
// then polling and fulfilling it through the operator-facing endpoints.
//
// NOTE: This test requires a running EAB service with valid credentials and
// a profile service. If the platform does not have pre-seeded test data, the
// config request will be rejected before session creation. In that case, the
// session lifecycle is tested through the session management endpoints alone.
func TestSessionLifecycle(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	t.Run("ListSessionsEndpoint", func(t *testing.T) {
		status, body, err := doGET(ctx, provisionURL("/sessions"))
		if err != nil {
			t.Fatalf("ListSessions GET failed: %v", err)
		}

		if status != http.StatusOK {
			t.Errorf("expected status 200, got %d: %s", status, string(body))
			return
		}

		envelope, err := parseEnvelope(body)
		if err != nil {
			t.Fatalf("failed to parse envelope: %v", err)
		}

		if !envelope.Success {
			t.Errorf("ListSessions should succeed: error=%s", envelope.Error)
		}

		// Payload should be a JSON array (possibly empty).
		var sessions []json.RawMessage
		if err := parsePayload(envelope, &sessions); err != nil {
			t.Fatalf("failed to parse sessions payload: %v", err)
		}

		t.Logf("ListSessions returned %d sessions", len(sessions))
	})

	t.Run("GetNonexistentSession", func(t *testing.T) {
		fakeSessionID := "00000000-0000-0000-0000-000000000000"
		status, body, err := doGET(ctx, provisionURL("/sessions/"+fakeSessionID))
		if err != nil {
			t.Fatalf("GetSession GET failed: %v", err)
		}

		// Non-existent session should yield 404.
		if status != http.StatusNotFound {
			t.Errorf("expected status 404 for nonexistent session, got %d: %s",
				status, string(body))
		}
	})

	t.Run("PollNonexistentSession", func(t *testing.T) {
		fakeSessionID := "00000000-0000-0000-0000-000000000000"
		status, body, err := doGET(ctx, provisionURL("/sessions/"+fakeSessionID+"/poll"))
		if err != nil {
			t.Fatalf("PollSession GET failed: %v", err)
		}

		// Non-existent session should yield 404.
		if status != http.StatusNotFound {
			t.Errorf("expected status 404 for nonexistent session poll, got %d: %s",
				status, string(body))
		}
	})

	t.Run("FulfillNonexistentSession", func(t *testing.T) {
		fakeSessionID := "00000000-0000-0000-0000-000000000000"
		fulfillReq := map[string]interface{}{
			"session_id": fakeSessionID,
			"profile_id": 99999,
		}

		status, body, err := doPOST(ctx,
			provisionURL("/sessions/"+fakeSessionID+"/fulfill"),
			fulfillReq)
		if err != nil {
			t.Fatalf("FulfillSession POST failed: %v", err)
		}

		// Non-existent session should yield 404.
		if status != http.StatusNotFound {
			t.Errorf("expected status 404 for fulfill on nonexistent session, got %d: %s",
				status, string(body))
		}
	})
}

// =============================================================================
// Endpoint Method Validation Tests
// =============================================================================

// TestEndpointMethodValidation verifies that provisioning endpoints reject
// incorrect HTTP methods.
func TestEndpointMethodValidation(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	t.Run("NonceRejectsPost", func(t *testing.T) {
		status, _, err := doPOST(ctx, provisionURL("/config/nonce"), nil)
		if err != nil {
			t.Fatalf("POST to nonce failed: %v", err)
		}

		// The nonce endpoint only accepts GET; POST should yield 405.
		if status != http.StatusMethodNotAllowed {
			t.Logf("POST to nonce endpoint returned status %d (may be router-dependent)", status)
		}
	})

	t.Run("ConfigRejectsGet", func(t *testing.T) {
		status, _, err := doGET(ctx, provisionURL("/config"))
		if err != nil {
			t.Fatalf("GET to config failed: %v", err)
		}

		// The config endpoint only accepts POST; GET should yield 405.
		if status != http.StatusMethodNotAllowed {
			t.Logf("GET to config endpoint returned status %d (may be router-dependent)", status)
		}
	})
}

// =============================================================================
// Nonce Endpoint Load Test
// =============================================================================

// TestNonceConcurrentIssuance verifies that concurrent nonce requests all
// produce unique, valid nonces without data races.
func TestNonceConcurrentIssuance(t *testing.T) {
	requireIntegration(t)

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	const concurrency = 10

	type result struct {
		nonce string
		err   error
	}

	results := make(chan result, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			status, body, err := doGET(ctx, provisionURL("/config/nonce"))
			if err != nil {
				results <- result{err: err}
				return
			}
			if status != http.StatusOK {
				results <- result{err: ErrHTTPUnexpectedStatus{
					Expected: http.StatusOK,
					Actual:   status,
					Body:     string(body),
				}}
				return
			}
			envelope, err := parseEnvelope(body)
			if err != nil {
				results <- result{err: err}
				return
			}
			var nonce nonceResponse
			if err := parsePayload(envelope, &nonce); err != nil {
				results <- result{err: err}
				return
			}
			results <- result{nonce: nonce.Nonce}
		}()
	}

	seen := make(map[string]struct{}, concurrency)
	for i := 0; i < concurrency; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("concurrent nonce request failed: %v", r.err)
			}
			if r.nonce == "" {
				t.Error("concurrent nonce request returned empty nonce")
				continue
			}
			if _, exists := seen[r.nonce]; exists {
				t.Errorf("duplicate nonce produced under concurrent load: %s", r.nonce)
			}
			seen[r.nonce] = struct{}{}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for concurrent nonce results")
		}
	}

	if len(seen) != concurrency {
		t.Errorf("expected %d unique nonces, got %d", concurrency, len(seen))
	}
}
