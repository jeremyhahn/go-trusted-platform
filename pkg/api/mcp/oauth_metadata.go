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
	"fmt"
	"net/http"
	"slices"
)

// OAuthProtectedResourceMetadata represents the OAuth 2.0 Protected Resource Metadata
// per RFC 9728 and MCP specification (2025-11-05).
//
// Reference: https://www.rfc-editor.org/rfc/rfc9728
// MCP Auth: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
type OAuthProtectedResourceMetadata struct {
	// Resource is the protected resource's identifier URL (REQUIRED).
	Resource string `json:"resource"`

	// AuthorizationServers is a list of authorization server URLs that can issue
	// access tokens for this resource (REQUIRED).
	AuthorizationServers []string `json:"authorization_servers"`

	// ScopesSupported is a list of OAuth 2.0 scope values supported by this
	// resource (OPTIONAL but recommended).
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// BearerMethodsSupported lists the bearer token presentation methods
	// supported by this resource (OPTIONAL). Default is ["header"].
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceDocumentation is a URL to human-readable documentation
	// for this resource (OPTIONAL).
	ResourceDocumentation string `json:"resource_documentation,omitempty"`

	// ResourceSigningAlgValuesSupported lists the JWS algorithms supported
	// for resource server signatures (OPTIONAL).
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// ResourceEncryptionAlgValuesSupported lists the JWE algorithms supported
	// for encrypting content sent to this resource (OPTIONAL).
	ResourceEncryptionAlgValuesSupported []string `json:"resource_encryption_alg_values_supported,omitempty"`

	// ResourceEncryptionEncValuesSupported lists the JWE content encryption
	// algorithms supported for encrypting content (OPTIONAL).
	ResourceEncryptionEncValuesSupported []string `json:"resource_encryption_enc_values_supported,omitempty"`
}

// OAuthMetadataConfig holds configuration for the OAuth metadata endpoint.
type OAuthMetadataConfig struct {
	// ResourceURL is this MCP server's resource identifier URL.
	ResourceURL string

	// AuthorizationServerURLs lists the authorization servers that can issue tokens.
	AuthorizationServerURLs []string

	// DocumentationURL is optional human-readable documentation URL.
	DocumentationURL string
}

// DefaultOAuthMetadataConfig returns default OAuth metadata configuration.
func DefaultOAuthMetadataConfig() *OAuthMetadataConfig {
	return &OAuthMetadataConfig{
		ResourceURL:             "",
		AuthorizationServerURLs: []string{},
		DocumentationURL:        "",
	}
}

// OAuthMetadataHandler handles the OAuth Protected Resource Metadata endpoint.
type OAuthMetadataHandler struct {
	config   *OAuthMetadataConfig
	metadata *OAuthProtectedResourceMetadata
}

// NewOAuthMetadataHandler creates a new OAuth metadata endpoint handler.
func NewOAuthMetadataHandler(config *OAuthMetadataConfig) *OAuthMetadataHandler {
	if config == nil {
		config = DefaultOAuthMetadataConfig()
	}

	h := &OAuthMetadataHandler{
		config: config,
	}
	h.buildMetadata()
	return h
}

// buildMetadata constructs the metadata response from configuration.
func (h *OAuthMetadataHandler) buildMetadata() {
	h.metadata = &OAuthProtectedResourceMetadata{
		Resource:             h.config.ResourceURL,
		AuthorizationServers: h.config.AuthorizationServerURLs,
		ScopesSupported:      h.getSupportedScopes(),
		BearerMethodsSupported: []string{
			"header", // Bearer token in Authorization header only
		},
		ResourceDocumentation: h.config.DocumentationURL,
	}
}

// getSupportedScopes returns the OAuth scopes this MCP server enforces. It is
// derived from the tool permission catalog rather than kept as a second list,
// because two hand-maintained lists drifted apart in both directions (#315).
func (h *OAuthMetadataHandler) getSupportedScopes() []string {
	return advertisedScopes(toolPermissionCatalog())
}

// advertisedScopes returns the sorted, deduplicated token scopes the given
// tool permissions require. An open tool ("") requires no scope and a
// malformed permission is not a scope a client can request; neither is
// advertised.
func advertisedScopes(permissions map[string]string) []string {
	seen := make(map[string]struct{}, len(permissions))
	scopes := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		scope := scopeForToolPermission(permission)
		if scope == "" {
			continue
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	slices.Sort(scopes)
	return scopes
}

// ServeHTTP handles HTTP requests for the OAuth metadata endpoint.
func (h *OAuthMetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	if r.Method == http.MethodHead {
		return
	}

	if err := json.NewEncoder(w).Encode(h.metadata); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// GetMetadata returns the current OAuth metadata.
func (h *OAuthMetadataHandler) GetMetadata() *OAuthProtectedResourceMetadata {
	return h.metadata
}

// SetResourceURL updates the resource URL in metadata.
func (h *OAuthMetadataHandler) SetResourceURL(url string) {
	h.config.ResourceURL = url
	h.metadata.Resource = url
}

// SetAuthorizationServers updates the authorization servers in metadata.
func (h *OAuthMetadataHandler) SetAuthorizationServers(urls []string) {
	h.config.AuthorizationServerURLs = urls
	h.metadata.AuthorizationServers = urls
}

// Validate checks if the metadata configuration is valid.
func (h *OAuthMetadataHandler) Validate() error {
	if h.metadata.Resource == "" {
		return &OAuthMetadataError{
			Code:    OAuthMetadataErrorMissingResource,
			Message: "resource URL is required",
		}
	}
	if len(h.metadata.AuthorizationServers) == 0 {
		return &OAuthMetadataError{
			Code:    OAuthMetadataErrorMissingAuthServer,
			Message: "at least one authorization server is required",
		}
	}
	return nil
}

// OAuthMetadataErrorCode represents OAuth metadata error types.
type OAuthMetadataErrorCode int

const (
	// OAuthMetadataErrorNone indicates no error.
	OAuthMetadataErrorNone OAuthMetadataErrorCode = iota
	// OAuthMetadataErrorMissingResource indicates resource URL is not configured.
	OAuthMetadataErrorMissingResource
	// OAuthMetadataErrorMissingAuthServer indicates no authorization servers configured.
	OAuthMetadataErrorMissingAuthServer
	// OAuthMetadataErrorInvalidConfig indicates invalid configuration.
	OAuthMetadataErrorInvalidConfig
)

// OAuthMetadataError represents an OAuth metadata configuration error.
type OAuthMetadataError struct {
	Code    OAuthMetadataErrorCode
	Message string
}

func (e *OAuthMetadataError) Error() string {
	return fmt.Sprintf("oauth metadata error: %s", e.Message)
}

// WWW-Authenticate header constants for OAuth 2.1.
const (
	// WWWAuthenticateHeader is the HTTP header for authentication challenges.
	WWWAuthenticateHeader = "WWW-Authenticate"

	// BearerRealm is the realm identifier for bearer token authentication.
	BearerRealm = "Trusted Platform MCP"
)

// WWWAuthenticateChallenge generates the WWW-Authenticate header value for
// OAuth 2.1 bearer token authentication challenges per RFC 6750.
func WWWAuthenticateChallenge(realm string, scope string, errorCode string, errorDescription string) string {
	if realm == "" {
		realm = BearerRealm
	}

	challenge := fmt.Sprintf(`Bearer realm=%q`, realm)

	if scope != "" {
		challenge += fmt.Sprintf(`, scope=%q`, scope)
	}

	if errorCode != "" {
		challenge += fmt.Sprintf(`, error=%q`, errorCode)
	}

	if errorDescription != "" {
		challenge += fmt.Sprintf(`, error_description=%q`, errorDescription)
	}

	return challenge
}

// SetWWWAuthenticateHeader sets the WWW-Authenticate header on HTTP responses
// for 401 Unauthorized responses per RFC 6750.
func SetWWWAuthenticateHeader(w http.ResponseWriter, scope string, errorCode string, errorDescription string) {
	w.Header().Set(WWWAuthenticateHeader, WWWAuthenticateChallenge(BearerRealm, scope, errorCode, errorDescription))
}
