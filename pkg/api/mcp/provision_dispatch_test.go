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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// provisionToolNames is the authoritative list of provisioning tool names the
// SDK MCP transport adapter codes against. Registration, routing, and this
// list must all agree.
var provisionToolNames = []string{
	"provision_get_nonce",
	"provision_fetch_config",
	"provision_sign_digest",
	"provision_poll_session",
	"provision_fulfill_session",
	"provision_list_sessions",
	"provision_get_session",
}

// provisionStubProvider satisfies ProvisionProvider for tests, capturing the
// arguments each method receives.
type provisionStubProvider struct {
	lastCall string

	getNonceFunc    func(ctx context.Context) (interface{}, error)
	fetchConfigFunc func(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error)
	signDigestFunc  func(ctx context.Context, req *ProvisionSignDigestRequest) (interface{}, error)
	pollFunc        func(ctx context.Context, sessionID string) (interface{}, error)
	fulfillFunc     func(ctx context.Context, sessionID string, profileID uint64) (interface{}, error)
	listFunc        func(ctx context.Context) (interface{}, error)
	getSessionFunc  func(ctx context.Context, sessionID string) (interface{}, error)
}

func (s *provisionStubProvider) ProvisionGetNonce(ctx context.Context) (interface{}, error) {
	s.lastCall = "get_nonce"
	if s.getNonceFunc != nil {
		return s.getNonceFunc(ctx)
	}
	return map[string]interface{}{"nonce": "stub-nonce"}, nil
}

func (s *provisionStubProvider) ProvisionFetchConfig(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error) {
	s.lastCall = "fetch_config"
	if s.fetchConfigFunc != nil {
		return s.fetchConfigFunc(ctx, req)
	}
	return map[string]interface{}{"config": map[string]interface{}{}, "status": "ok"}, nil
}

func (s *provisionStubProvider) ProvisionSignDigest(ctx context.Context, req *ProvisionSignDigestRequest) (interface{}, error) {
	s.lastCall = "sign_digest"
	if s.signDigestFunc != nil {
		return s.signDigestFunc(ctx, req)
	}
	return map[string]interface{}{"signature": "c2ln", "cert_pem": "Y2VydA=="}, nil
}

func (s *provisionStubProvider) ProvisionPollSession(ctx context.Context, sessionID string) (interface{}, error) {
	s.lastCall = "poll_session"
	if s.pollFunc != nil {
		return s.pollFunc(ctx, sessionID)
	}
	return map[string]interface{}{"status": "pending"}, nil
}

func (s *provisionStubProvider) ProvisionFulfillSession(ctx context.Context, sessionID string, profileID uint64) (interface{}, error) {
	s.lastCall = "fulfill_session"
	if s.fulfillFunc != nil {
		return s.fulfillFunc(ctx, sessionID, profileID)
	}
	return map[string]interface{}{"status": "fulfilled"}, nil
}

func (s *provisionStubProvider) ProvisionListSessions(ctx context.Context) (interface{}, error) {
	s.lastCall = "list_sessions"
	if s.listFunc != nil {
		return s.listFunc(ctx)
	}
	return map[string]interface{}{"sessions": []interface{}{}}, nil
}

func (s *provisionStubProvider) ProvisionGetSession(ctx context.Context, sessionID string) (interface{}, error) {
	s.lastCall = "get_session"
	if s.getSessionFunc != nil {
		return s.getSessionFunc(ctx, sessionID)
	}
	return map[string]interface{}{"session": map[string]interface{}{"id": sessionID}}, nil
}

// provisionCombinedProvider embeds both mockServiceProvider (satisfies the
// full ServiceProvider interface) and provisionStubProvider (satisfies
// ProvisionProvider) so the registry routes provision_* tools through the
// optional-interface path.
type provisionCombinedProvider struct {
	*mockServiceProvider
	*provisionStubProvider
}

// Compile-time assertions.
var (
	_ ServiceProvider   = (*provisionCombinedProvider)(nil)
	_ ProvisionProvider = (*provisionCombinedProvider)(nil)
	_ ProvisionProvider = (*provisionStubProvider)(nil)
)

func newProvisionRegistry() (*ToolRegistry, *provisionStubProvider) {
	stub := &provisionStubProvider{}
	svc := &provisionCombinedProvider{
		mockServiceProvider:   newMockServiceProvider(),
		provisionStubProvider: stub,
	}
	return NewToolRegistry(svc, newTestLogger()), stub
}

// =============================================================================
// Registration <-> routing parity
// =============================================================================

// TestProvisionToolRegistrationAndRoutingParity guards against the KMS-round
// bug class where a tool was registered but never routed. It asserts, without
// any vacuous path, that:
//  1. every expected provision_* tool is registered,
//  2. no unexpected provision_* tool is registered,
//  3. the registered set and the dispatch map keys are identical, and
//  4. ExecuteTool actually routes every tool to the provisioning executor
//     (a provider without ProvisionProvider yields ErrProvisionNotConfigured,
//     never "unknown tool").
func TestProvisionToolRegistrationAndRoutingParity(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		if strings.HasPrefix(tool.Name, "provision_") {
			registered[tool.Name] = true
		}
	}

	if len(registered) != len(provisionToolNames) {
		t.Errorf("registered %d provision_* tools, want %d: %v",
			len(registered), len(provisionToolNames), registered)
	}
	for _, name := range provisionToolNames {
		if !registered[name] {
			t.Errorf("expected tool %q is not registered", name)
		}
	}

	for name := range registered {
		if _, ok := provisionToolDispatch[name]; !ok {
			t.Errorf("registered tool %q has no executor in provisionToolDispatch", name)
		}
	}
	for name := range provisionToolDispatch {
		if !registered[name] {
			t.Errorf("dispatch map routes %q but the tool is not registered", name)
		}
	}

	for _, name := range provisionToolNames {
		if _, err := registry.ExecuteTool(ctx, name, map[string]interface{}{}); !errors.Is(err, ErrProvisionNotConfigured) {
			t.Errorf("ExecuteTool(%q) without provider: err = %v, want ErrProvisionNotConfigured", name, err)
		}
	}
}

// =============================================================================
// provision_get_nonce
// =============================================================================

func TestExecuteProvisionGetNonce_Success(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()

	result, err := registry.ExecuteTool(ctx, "provision_get_nonce", map[string]interface{}{})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if stub.lastCall != "get_nonce" {
		t.Errorf("lastCall = %q, want get_nonce", stub.lastCall)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if resultMap["nonce"] != "stub-nonce" {
		t.Errorf("nonce = %v, want stub-nonce", resultMap["nonce"])
	}
}

func TestExecuteProvisionGetNonce_ProviderError(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	stub.getNonceFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}

	if _, err := registry.ExecuteTool(ctx, "provision_get_nonce", map[string]interface{}{}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
}

// =============================================================================
// provision_fetch_config
// =============================================================================

func TestExecuteProvisionFetchConfig_ArgumentBinding(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	var captured *ProvisionFetchConfigRequest
	stub.fetchConfigFunc = func(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"config": map[string]interface{}{"hostname": "node1"}, "status": "ok"}, nil
	}

	args := map[string]interface{}{
		"ek_serial":   "ek-123",
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"ek_cert":     "ZGVy",
		"eab_key_id":  "key-1",
		"eab_hmac":    "aG1hYw",
		"nonce":       "nonce-1",
	}
	result, err := registry.ExecuteTool(ctx, "provision_fetch_config", args)
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider ProvisionFetchConfig was not called")
	}
	if captured.EKSerial != "ek-123" || captured.MACAddress != "aa:bb:cc:dd:ee:ff" ||
		captured.EKCert != "ZGVy" || captured.EABKeyID != "key-1" ||
		captured.EABHMAC != "aG1hYw" || captured.Nonce != "nonce-1" {
		t.Errorf("request fields not bound: %+v", captured)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if resultMap["status"] != "ok" {
		t.Errorf("status = %v, want ok", resultMap["status"])
	}
}

// TestExecuteProvisionFetchConfig_PendingShape verifies the pending result
// shape passes through unmodified so SDK clients can discriminate delivered
// (config present) from pending (session_id present).
func TestExecuteProvisionFetchConfig_PendingShape(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	stub.fetchConfigFunc = func(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error) {
		return map[string]interface{}{
			"session_id":            "sess-1",
			"provision_url":         "https://cp/provision/sess-1",
			"poll_interval_seconds": 5,
		}, nil
	}

	result, err := registry.ExecuteTool(ctx, "provision_fetch_config", map[string]interface{}{
		"eab_key_id": "key-1", "eab_hmac": "aG1hYw", "nonce": "n",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if resultMap["session_id"] != "sess-1" {
		t.Errorf("session_id = %v, want sess-1", resultMap["session_id"])
	}
	if _, hasConfig := resultMap["config"]; hasConfig {
		t.Error("pending result must not carry a config key")
	}
}

func TestExecuteProvisionFetchConfig_ProviderError(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	stub.fetchConfigFunc = func(ctx context.Context, req *ProvisionFetchConfigRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}

	if _, err := registry.ExecuteTool(ctx, "provision_fetch_config", map[string]interface{}{}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
}

// =============================================================================
// provision_sign_digest
// =============================================================================

func TestExecuteProvisionSignDigest_DecodesDigest(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	var captured *ProvisionSignDigestRequest
	stub.signDigestFunc = func(ctx context.Context, req *ProvisionSignDigestRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"signature": "c2ln", "cert_pem": "Y2VydA=="}, nil
	}

	args := map[string]interface{}{
		"ek_serial":  "ek-123",
		"eab_key_id": "key-1",
		"eab_hmac":   "aG1hYw",
		"nonce":      "nonce-1",
		"digest":     base64.StdEncoding.EncodeToString([]byte("uki-digest")),
		"key_ref":    "db",
	}
	if _, err := registry.ExecuteTool(ctx, "provision_sign_digest", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider ProvisionSignDigest was not called")
	}
	if string(captured.Digest) != "uki-digest" {
		t.Errorf("Digest = %q, want uki-digest", captured.Digest)
	}
	if captured.KeyRef != "db" {
		t.Errorf("KeyRef = %q, want db", captured.KeyRef)
	}
	if captured.EABKeyID != "key-1" || captured.Nonce != "nonce-1" {
		t.Errorf("identity fields not bound: %+v", captured)
	}
}

func TestExecuteProvisionSignDigest_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProvisionRegistry()

	if _, err := registry.ExecuteTool(ctx, "provision_sign_digest", map[string]interface{}{
		"eab_key_id": "key-1", "eab_hmac": "aG1hYw", "nonce": "n",
	}); !errors.Is(err, ErrProvisionDigestRequired) {
		t.Errorf("missing digest: err = %v, want ErrProvisionDigestRequired", err)
	}

	_, err := registry.ExecuteTool(ctx, "provision_sign_digest", map[string]interface{}{
		"eab_key_id": "key-1", "eab_hmac": "aG1hYw", "nonce": "n",
		"digest": "not-base64!!!",
	})
	var invalidDigest ErrProvisionInvalidDigest
	if !errors.As(err, &invalidDigest) {
		t.Errorf("invalid base64 digest: err = %v, want ErrProvisionInvalidDigest", err)
	}
}

// =============================================================================
// provision_poll_session
// =============================================================================

func TestExecuteProvisionPollSession_Success(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	var capturedID string
	stub.pollFunc = func(ctx context.Context, sessionID string) (interface{}, error) {
		capturedID = sessionID
		return map[string]interface{}{"status": "pending"}, nil
	}

	result, err := registry.ExecuteTool(ctx, "provision_poll_session", map[string]interface{}{
		"session_id": "sess-42",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedID != "sess-42" {
		t.Errorf("sessionID = %q, want sess-42", capturedID)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if resultMap["status"] != "pending" {
		t.Errorf("status = %v, want pending", resultMap["status"])
	}
}

func TestExecuteProvisionPollSession_MissingSessionID(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProvisionRegistry()

	if _, err := registry.ExecuteTool(ctx, "provision_poll_session", map[string]interface{}{}); !errors.Is(err, ErrProvisionSessionIDRequired) {
		t.Errorf("err = %v, want ErrProvisionSessionIDRequired", err)
	}
}

// =============================================================================
// provision_fulfill_session
// =============================================================================

func TestExecuteProvisionFulfillSession_ProfileIDForms(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	var capturedSession string
	var capturedProfile uint64
	stub.fulfillFunc = func(ctx context.Context, sessionID string, profileID uint64) (interface{}, error) {
		capturedSession = sessionID
		capturedProfile = profileID
		return map[string]interface{}{"status": "fulfilled"}, nil
	}

	// JSON number form.
	if _, err := registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"session_id": "sess-1",
		"profile_id": float64(7),
	}); err != nil {
		t.Fatalf("numeric profile_id: %v", err)
	}
	if capturedSession != "sess-1" || capturedProfile != 7 {
		t.Errorf("captured = (%q, %d), want (sess-1, 7)", capturedSession, capturedProfile)
	}

	// Decimal string form, exercising a value above 2^53 that a JSON
	// number could not carry without precision loss.
	if _, err := registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"session_id": "sess-2",
		"profile_id": "9007199254740993",
	}); err != nil {
		t.Fatalf("string profile_id: %v", err)
	}
	if capturedProfile != 9007199254740993 {
		t.Errorf("profile_id = %d, want 9007199254740993 (exact)", capturedProfile)
	}
}

// TestExecuteProvisionFulfillSession_ZeroProfileIDReachesService asserts a
// missing or zero profile_id is handed to the service as 0: the service
// owns the profile_id rule so MCP refuses it with the same typed error as
// every other transport (#304).
func TestExecuteProvisionFulfillSession_ZeroProfileIDReachesService(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	called := false
	capturedProfile := uint64(1)
	stub.fulfillFunc = func(ctx context.Context, sessionID string, profileID uint64) (interface{}, error) {
		called = true
		capturedProfile = profileID
		return map[string]interface{}{"status": "fulfilled"}, nil
	}

	for name, profileID := range map[string]interface{}{
		"missing": nil,
		"number":  float64(0),
		"string":  "0",
		"empty":   "",
	} {
		t.Run(name, func(t *testing.T) {
			called, capturedProfile = false, 1
			args := map[string]interface{}{"session_id": "sess-1"}
			if profileID != nil {
				args["profile_id"] = profileID
			}
			if _, err := registry.ExecuteTool(ctx, "provision_fulfill_session", args); err != nil {
				t.Fatalf("err = %v, want the call to reach the service", err)
			}
			if !called || capturedProfile != 0 {
				t.Errorf("called = %v, profile_id = %d; want the service called with 0", called, capturedProfile)
			}
		})
	}
}

func TestExecuteProvisionFulfillSession_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProvisionRegistry()

	if _, err := registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"profile_id": float64(7),
	}); !errors.Is(err, ErrProvisionSessionIDRequired) {
		t.Errorf("missing session_id: err = %v, want ErrProvisionSessionIDRequired", err)
	}

	var invalidID ErrProvisionInvalidProfileID
	_, err := registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"session_id": "sess-1",
		"profile_id": "not-a-number",
	})
	if !errors.As(err, &invalidID) {
		t.Errorf("non-numeric string profile_id: err = %v, want ErrProvisionInvalidProfileID", err)
	}

	_, err = registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"session_id": "sess-1",
		"profile_id": float64(-3),
	})
	if !errors.As(err, &invalidID) {
		t.Errorf("negative profile_id: err = %v, want ErrProvisionInvalidProfileID", err)
	}

	_, err = registry.ExecuteTool(ctx, "provision_fulfill_session", map[string]interface{}{
		"session_id": "sess-1",
		"profile_id": true,
	})
	if !errors.As(err, &invalidID) {
		t.Errorf("bool profile_id: err = %v, want ErrProvisionInvalidProfileID", err)
	}
}

// =============================================================================
// provision_list_sessions / provision_get_session
// =============================================================================

func TestExecuteProvisionListSessions_Success(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	stub.listFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"sessions": []interface{}{
				map[string]interface{}{"id": "sess-1"},
				map[string]interface{}{"id": "sess-2"},
			},
		}, nil
	}

	result, err := registry.ExecuteTool(ctx, "provision_list_sessions", map[string]interface{}{})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	sessions, ok := resultMap["sessions"].([]interface{})
	if !ok {
		t.Fatalf("sessions type = %T, want slice", resultMap["sessions"])
	}
	if len(sessions) != 2 {
		t.Errorf("len(sessions) = %d, want 2", len(sessions))
	}
}

func TestExecuteProvisionListSessions_ProviderError(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	stub.listFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}

	if _, err := registry.ExecuteTool(ctx, "provision_list_sessions", map[string]interface{}{}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
}

func TestExecuteProvisionGetSession_Success(t *testing.T) {
	ctx := context.Background()
	registry, stub := newProvisionRegistry()
	var capturedID string
	stub.getSessionFunc = func(ctx context.Context, sessionID string) (interface{}, error) {
		capturedID = sessionID
		return map[string]interface{}{"session": map[string]interface{}{"id": sessionID}}, nil
	}

	result, err := registry.ExecuteTool(ctx, "provision_get_session", map[string]interface{}{
		"session_id": "sess-9",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedID != "sess-9" {
		t.Errorf("sessionID = %q, want sess-9", capturedID)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	session, ok := resultMap["session"].(map[string]interface{})
	if !ok {
		t.Fatalf("session type = %T, want map", resultMap["session"])
	}
	if session["id"] != "sess-9" {
		t.Errorf("session.id = %v, want sess-9", session["id"])
	}
}

func TestExecuteProvisionGetSession_MissingSessionID(t *testing.T) {
	ctx := context.Background()
	registry, _ := newProvisionRegistry()

	if _, err := registry.ExecuteTool(ctx, "provision_get_session", map[string]interface{}{}); !errors.Is(err, ErrProvisionSessionIDRequired) {
		t.Errorf("err = %v, want ErrProvisionSessionIDRequired", err)
	}
}
