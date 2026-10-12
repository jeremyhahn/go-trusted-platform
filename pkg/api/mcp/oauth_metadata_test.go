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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestNewOAuthMetadataHandler(t *testing.T) {
	t.Run("with nil config uses defaults", func(t *testing.T) {
		handler := NewOAuthMetadataHandler(nil)

		if handler == nil {
			t.Fatal("expected handler to be created")
		}
		if handler.config == nil {
			t.Fatal("expected config to be set")
		}
		if handler.metadata == nil {
			t.Fatal("expected metadata to be built")
		}
	})

	t.Run("with valid config", func(t *testing.T) {
		config := &OAuthMetadataConfig{
			ResourceURL:             "https://mcp.example.com:8000",
			AuthorizationServerURLs: []string{"https://auth.example.com"},
			DocumentationURL:        "https://docs.example.com/mcp",
		}

		handler := NewOAuthMetadataHandler(config)

		if handler.metadata.Resource != config.ResourceURL {
			t.Errorf("expected resource %s, got %s", config.ResourceURL, handler.metadata.Resource)
		}
		if len(handler.metadata.AuthorizationServers) != 1 {
			t.Fatalf("expected 1 auth server, got %d", len(handler.metadata.AuthorizationServers))
		}
		if handler.metadata.AuthorizationServers[0] != config.AuthorizationServerURLs[0] {
			t.Errorf("expected auth server %s, got %s", config.AuthorizationServerURLs[0], handler.metadata.AuthorizationServers[0])
		}
		if handler.metadata.ResourceDocumentation != config.DocumentationURL {
			t.Errorf("expected docs URL %s, got %s", config.DocumentationURL, handler.metadata.ResourceDocumentation)
		}
	})
}

func TestOAuthMetadataHandler_ServeHTTP(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL:             "https://mcp.example.com:8000",
		AuthorizationServerURLs: []string{"https://auth.example.com"},
	}
	handler := NewOAuthMetadataHandler(config)

	t.Run("GET returns metadata JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		contentType := rec.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", contentType)
		}

		// Check Cache-Control header
		cacheControl := rec.Header().Get("Cache-Control")
		if cacheControl != "public, max-age=3600" {
			t.Errorf("expected Cache-Control public, max-age=3600, got %s", cacheControl)
		}

		var metadata OAuthProtectedResourceMetadata
		if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if metadata.Resource != config.ResourceURL {
			t.Errorf("expected resource %s, got %s", config.ResourceURL, metadata.Resource)
		}
		if len(metadata.AuthorizationServers) == 0 {
			t.Error("expected authorization_servers to be populated")
		}
		if len(metadata.ScopesSupported) == 0 {
			t.Error("expected scopes_supported to be populated")
		}
		if len(metadata.BearerMethodsSupported) == 0 {
			t.Error("expected bearer_methods_supported to be populated")
		}
		if metadata.BearerMethodsSupported[0] != "header" {
			t.Errorf("expected bearer method 'header', got %s", metadata.BearerMethodsSupported[0])
		}
	})

	t.Run("HEAD returns headers only", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}

		contentType := rec.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", contentType)
		}

		// Body should be empty for HEAD
		if rec.Body.Len() != 0 {
			t.Errorf("expected empty body for HEAD, got %d bytes", rec.Body.Len())
		}
	})

	t.Run("POST returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405, got %d", rec.Code)
		}

		allow := rec.Header().Get("Allow")
		if allow != "GET, HEAD" {
			t.Errorf("expected Allow: GET, HEAD, got %s", allow)
		}
	})

	t.Run("PUT returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405, got %d", rec.Code)
		}
	})

	t.Run("DELETE returns method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405, got %d", rec.Code)
		}
	})
}

func TestOAuthMetadataHandler_GetMetadata(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL:             "https://mcp.example.com:8000",
		AuthorizationServerURLs: []string{"https://auth.example.com"},
	}
	handler := NewOAuthMetadataHandler(config)

	metadata := handler.GetMetadata()

	if metadata == nil {
		t.Fatal("expected metadata to be returned")
	}
	if metadata.Resource != config.ResourceURL {
		t.Errorf("expected resource %s, got %s", config.ResourceURL, metadata.Resource)
	}
}

func TestOAuthMetadataHandler_SetResourceURL(t *testing.T) {
	handler := NewOAuthMetadataHandler(nil)

	newURL := "https://new-mcp.example.com:8000"
	handler.SetResourceURL(newURL)

	if handler.metadata.Resource != newURL {
		t.Errorf("expected resource %s, got %s", newURL, handler.metadata.Resource)
	}
	if handler.config.ResourceURL != newURL {
		t.Errorf("expected config resource %s, got %s", newURL, handler.config.ResourceURL)
	}
}

func TestOAuthMetadataHandler_SetAuthorizationServers(t *testing.T) {
	handler := NewOAuthMetadataHandler(nil)

	servers := []string{"https://auth1.example.com", "https://auth2.example.com"}
	handler.SetAuthorizationServers(servers)

	if len(handler.metadata.AuthorizationServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(handler.metadata.AuthorizationServers))
	}
	if handler.metadata.AuthorizationServers[0] != servers[0] {
		t.Errorf("expected server %s, got %s", servers[0], handler.metadata.AuthorizationServers[0])
	}
	if handler.metadata.AuthorizationServers[1] != servers[1] {
		t.Errorf("expected server %s, got %s", servers[1], handler.metadata.AuthorizationServers[1])
	}
}

func TestOAuthMetadataHandler_Validate(t *testing.T) {
	t.Run("missing resource URL returns error", func(t *testing.T) {
		handler := NewOAuthMetadataHandler(&OAuthMetadataConfig{
			ResourceURL:             "",
			AuthorizationServerURLs: []string{"https://auth.example.com"},
		})

		err := handler.Validate()
		if err == nil {
			t.Error("expected error for missing resource URL")
		}

		metaErr, ok := err.(*OAuthMetadataError)
		if !ok {
			t.Fatalf("expected *OAuthMetadataError, got %T", err)
		}
		if metaErr.Code != OAuthMetadataErrorMissingResource {
			t.Errorf("expected error code %d, got %d", OAuthMetadataErrorMissingResource, metaErr.Code)
		}
	})

	t.Run("missing authorization servers returns error", func(t *testing.T) {
		handler := NewOAuthMetadataHandler(&OAuthMetadataConfig{
			ResourceURL:             "https://mcp.example.com:8000",
			AuthorizationServerURLs: []string{},
		})

		err := handler.Validate()
		if err == nil {
			t.Error("expected error for missing authorization servers")
		}

		metaErr, ok := err.(*OAuthMetadataError)
		if !ok {
			t.Fatalf("expected *OAuthMetadataError, got %T", err)
		}
		if metaErr.Code != OAuthMetadataErrorMissingAuthServer {
			t.Errorf("expected error code %d, got %d", OAuthMetadataErrorMissingAuthServer, metaErr.Code)
		}
	})

	t.Run("valid config returns nil", func(t *testing.T) {
		handler := NewOAuthMetadataHandler(&OAuthMetadataConfig{
			ResourceURL:             "https://mcp.example.com:8000",
			AuthorizationServerURLs: []string{"https://auth.example.com"},
		})

		err := handler.Validate()
		if err != nil {
			t.Errorf("expected no error for valid config, got: %v", err)
		}
	})
}

// TestOAuthMetadataHandler_getSupportedScopes is the #315 ratchet:
// scopes_supported must be exactly the set of scopes the MCP tools enforce.
// A scope a tool requires but the metadata does not offer leaves a client
// with no documented way to request the grant; a scope offered but consulted
// by no tool advertises capability the server does not have.
func TestOAuthMetadataHandler_getSupportedScopes(t *testing.T) {
	handler := NewOAuthMetadataHandler(nil)
	advertised := make(map[string]bool)
	for _, scope := range handler.getSupportedScopes() {
		if advertised[scope] {
			t.Errorf("scope %q is advertised twice", scope)
		}
		advertised[scope] = true
	}

	enforced := make(map[string]bool)
	for tool, permission := range NewAuthorizationChecker(nil, nil).toolPermissions {
		if permission == "" {
			continue
		}
		scope := scopeForToolPermission(permission)
		if scope != permission {
			t.Errorf("tool %q requires malformed permission %q: it is not a resource:action scope", tool, permission)
			continue
		}
		enforced[scope] = true
		if !advertised[scope] {
			t.Errorf("tool %q requires scope %q, which scopes_supported does not advertise", tool, scope)
		}
	}

	for scope := range advertised {
		if !enforced[scope] {
			t.Errorf("scope %q is advertised but no MCP tool requires it", scope)
		}
	}
}

// TestOAuthMetadataHandler_getSupportedScopes_Issue315 pins the two lists the
// issue measured, so the regression reads by name.
func TestOAuthMetadataHandler_getSupportedScopes_Issue315(t *testing.T) {
	advertised := make(map[string]bool)
	for _, scope := range NewOAuthMetadataHandler(nil).getSupportedScopes() {
		advertised[scope] = true
	}

	usedButUnadvertised := []string{
		"bmc:read", "bmc:write", "bmc:power", "bmc:media", "bmc:admin",
		"invitation:read", "invitation:write", "invitation:delete",
		"ntp:read", "ntp:write",
		"proxy:read", "proxy:write", "proxy:delete",
	}
	for _, scope := range usedButUnadvertised {
		if !advertised[scope] {
			t.Errorf("scope %q is enforced by an MCP tool and must be advertised", scope)
		}
	}

	advertisedButUnused := []string{
		"mcp:tools", "mcp:resources",
		"ca:delete",
		"container:read", "container:write", "container:delete",
		"iam:read", "iam:write", "iam:delete",
		"kms:read", "kms:write", "kms:delete",
		"tenant:read", "tenant:write", "tenant:delete",
		"platform:admin",
	}
	for _, scope := range advertisedButUnused {
		if advertised[scope] {
			t.Errorf("scope %q is consulted by no MCP tool and must not be advertised", scope)
		}
	}
}

// TestAdvertisedScopes_NewResourceIsAdvertised is the mutation the issue asks
// for: a tool permission with a scope nothing else uses must be advertised
// without anyone editing a second list.
func TestAdvertisedScopes_NewResourceIsAdvertised(t *testing.T) {
	scopes := advertisedScopes(map[string]string{
		"widget_create": "widget:write",
		"widget_list":   "widget:read",
		"widget_get":    "widget:read",
	})

	want := []string{"widget:read", "widget:write"}
	if !slices.Equal(scopes, want) {
		t.Fatalf("advertisedScopes = %v, want %v (sorted, deduplicated)", scopes, want)
	}
}

// TestAdvertisedScopes_SkipsOpenAndMalformedPermissions: an open tool ("")
// requires no scope, and a malformed permission is not a scope a client can
// request, so neither is advertised.
func TestAdvertisedScopes_SkipsOpenAndMalformedPermissions(t *testing.T) {
	scopes := advertisedScopes(map[string]string{
		"health":     "",
		"no_colon":   "widgetwrite",
		"no_action":  "widget:",
		"no_service": ":write",
	})
	if len(scopes) != 0 {
		t.Fatalf("advertisedScopes = %v, want none", scopes)
	}

	if scopes := advertisedScopes(nil); len(scopes) != 0 {
		t.Fatalf("advertisedScopes(nil) = %v, want none", scopes)
	}
}

func TestDefaultOAuthMetadataConfig(t *testing.T) {
	config := DefaultOAuthMetadataConfig()

	if config == nil {
		t.Fatal("expected config to be created")
	}
	if config.ResourceURL != "" {
		t.Errorf("expected empty ResourceURL, got %s", config.ResourceURL)
	}
	if len(config.AuthorizationServerURLs) != 0 {
		t.Errorf("expected empty AuthorizationServerURLs, got %d", len(config.AuthorizationServerURLs))
	}
}

func TestOAuthMetadataError_Error(t *testing.T) {
	err := &OAuthMetadataError{
		Code:    OAuthMetadataErrorMissingResource,
		Message: "test error message",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "test error message") {
		t.Errorf("expected error string to contain message, got: %s", errStr)
	}
	if !strings.Contains(errStr, "oauth metadata error") {
		t.Errorf("expected error string to contain prefix, got: %s", errStr)
	}
}

func TestWWWAuthenticateChallenge(t *testing.T) {
	t.Run("minimal challenge", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge("", "", "", "")

		if !strings.Contains(challenge, "Bearer") {
			t.Error("expected challenge to start with Bearer")
		}
		if !strings.Contains(challenge, `realm="Trusted Platform MCP"`) {
			t.Error("expected default realm")
		}
	})

	t.Run("custom realm", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge("Custom Realm", "", "", "")

		if !strings.Contains(challenge, `realm="Custom Realm"`) {
			t.Errorf("expected custom realm in challenge: %s", challenge)
		}
	})

	t.Run("with scope", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge("", "vtpm:read vtpm:write", "", "")

		if !strings.Contains(challenge, `scope="vtpm:read vtpm:write"`) {
			t.Errorf("expected scope in challenge: %s", challenge)
		}
	})

	t.Run("with error code", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge("", "", "invalid_token", "")

		if !strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("expected error code in challenge: %s", challenge)
		}
	})

	t.Run("with error description", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge("", "", "invalid_token", "Token has expired")

		if !strings.Contains(challenge, `error_description="Token has expired"`) {
			t.Errorf("expected error description in challenge: %s", challenge)
		}
	})

	t.Run("full challenge", func(t *testing.T) {
		challenge := WWWAuthenticateChallenge(
			"MCP Server",
			"mcp:tools mcp:resources",
			"insufficient_scope",
			"The access token lacks required scope",
		)

		expected := []string{
			`realm="MCP Server"`,
			`scope="mcp:tools mcp:resources"`,
			`error="insufficient_scope"`,
			`error_description="The access token lacks required scope"`,
		}

		for _, exp := range expected {
			if !strings.Contains(challenge, exp) {
				t.Errorf("expected %s in challenge: %s", exp, challenge)
			}
		}
	})
}

func TestSetWWWAuthenticateHeader(t *testing.T) {
	rec := httptest.NewRecorder()

	SetWWWAuthenticateHeader(rec, "vtpm:read", "invalid_token", "Token expired")

	header := rec.Header().Get(WWWAuthenticateHeader)
	if header == "" {
		t.Error("expected WWW-Authenticate header to be set")
	}
	if !strings.Contains(header, "Bearer") {
		t.Error("expected Bearer authentication scheme")
	}
	if !strings.Contains(header, `realm="Trusted Platform MCP"`) {
		t.Error("expected default realm in header")
	}
	if !strings.Contains(header, `scope="vtpm:read"`) {
		t.Error("expected scope in header")
	}
	if !strings.Contains(header, `error="invalid_token"`) {
		t.Error("expected error in header")
	}
}

func TestOAuthProtectedResourceMetadata_JSONSerialization(t *testing.T) {
	metadata := &OAuthProtectedResourceMetadata{
		Resource:               "https://mcp.example.com:8000",
		AuthorizationServers:   []string{"https://auth.example.com"},
		ScopesSupported:        []string{"mcp:tools", "vtpm:read"},
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  "https://docs.example.com",
	}

	// Marshal
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Verify JSON structure
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Check required fields per RFC 9728
	if _, ok := decoded["resource"]; !ok {
		t.Error("expected 'resource' field in JSON")
	}
	if _, ok := decoded["authorization_servers"]; !ok {
		t.Error("expected 'authorization_servers' field in JSON")
	}

	// Roundtrip
	var roundtrip OAuthProtectedResourceMetadata
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("failed roundtrip unmarshal: %v", err)
	}

	if roundtrip.Resource != metadata.Resource {
		t.Errorf("expected resource %s, got %s", metadata.Resource, roundtrip.Resource)
	}
}
