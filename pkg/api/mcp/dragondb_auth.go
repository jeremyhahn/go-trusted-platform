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
	"fmt"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// TokenValidator validates access tokens. This interface allows different
// implementations for embedded vs remote QuicBaaS modes.
type TokenValidator interface {
	// ValidateToken validates a token and returns the validation result.
	ValidateToken(ctx context.Context, token string) (*TokenValidationResult, error)
}

// TokenValidationResult contains the result of token validation.
type TokenValidationResult struct {
	Valid     bool
	UserID    string
	TenantID  string
	Roles     []string
	Groups    []string
	ExpiresAt int64
	Scope     string
}

// QuicBaaSAuthAdapter implements AuthorizationService and AuthManager
// using QuicBaaS's SDK PEP client for permissions and a TokenValidator
// for token validation.
//
// This adapter provides the bridge between MCP's authorization interfaces
// and QuicBaaS's IAM implementation.
type QuicBaaSAuthAdapter struct {
	// tokenValidator validates access tokens (can be QuicBaaS embedded or SDK)
	tokenValidator TokenValidator

	// pepClient is the QuicBaaS PEP (Policy Enforcement Point) SDK client
	// for authorization checks
	pepClient iam.PEPClient

	// defaultTenantID is used when no tenant is specified in the token
	defaultTenantID string

	// cachedClaims stores validated token claims (simple cache)
	cachedClaims map[string]*TokenValidationResult
}

// QuicBaaSAuthConfig holds configuration for the QuicBaaS auth adapter.
type QuicBaaSAuthConfig struct {
	// TokenValidator validates access tokens
	TokenValidator TokenValidator

	// PEPClient is the QuicBaaS PEP service SDK client
	PEPClient iam.PEPClient

	// DefaultTenantID is the default tenant for operations without explicit tenant
	DefaultTenantID string
}

// NewQuicBaaSAuthAdapter creates a new QuicBaaS authentication adapter.
//
// The adapter implements both AuthorizationService and AuthManager interfaces,
// allowing MCP to use QuicBaaS IAM for all authorization decisions.
//
// Components:
//   - TokenValidator: Validates access tokens (embedded QuicBaaS or SDK client)
//   - PEPClient: Permission checking via ABAC policies
func NewQuicBaaSAuthAdapter(config *QuicBaaSAuthConfig) *QuicBaaSAuthAdapter {
	if config == nil {
		config = &QuicBaaSAuthConfig{}
	}
	return &QuicBaaSAuthAdapter{
		tokenValidator:  config.TokenValidator,
		pepClient:       config.PEPClient,
		defaultTenantID: config.DefaultTenantID,
		cachedClaims:    make(map[string]*TokenValidationResult),
	}
}

// =============================================================================
// AuthManager interface implementation
// =============================================================================

// ValidateToken validates an access token and returns whether it's valid.
//
// Uses the configured TokenValidator to verify the token. The TokenValidator
// can be implemented using QuicBaaS embedded mode or the SDK client.
//
// Returns an error if the token validator is not configured.
func (a *QuicBaaSAuthAdapter) ValidateToken(ctx context.Context, token string) (bool, error) {
	if a.tokenValidator == nil {
		return false, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorServiceUnavailable,
			Message: "token validator not configured",
		}
	}

	if token == "" {
		return false, nil
	}

	result, err := a.tokenValidator.ValidateToken(ctx, token)
	if err != nil {
		return false, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorTokenValidation,
			Message: fmt.Sprintf("token validation failed: %v", err),
		}
	}

	// Cache the result for use in permission checking
	if result.Valid {
		a.cachedClaims[token] = result
	}

	return result.Valid, nil
}

// GetTokenClaims extracts claims from a validated access token.
//
// Returns a map containing standard JWT claims plus any custom claims.
// This is used for extracting subject ID, tenant, roles, etc.
func (a *QuicBaaSAuthAdapter) GetTokenClaims(ctx context.Context, token string) (map[string]interface{}, error) {
	if a.tokenValidator == nil {
		return nil, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorServiceUnavailable,
			Message: "token validator not configured",
		}
	}

	if token == "" {
		return nil, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorInvalidToken,
			Message: "token is empty",
		}
	}

	// Check cache first
	if cached, ok := a.cachedClaims[token]; ok && cached.Valid {
		return a.resultToClaimsMap(cached), nil
	}

	// Validate and get claims
	result, err := a.tokenValidator.ValidateToken(ctx, token)
	if err != nil {
		return nil, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorTokenValidation,
			Message: fmt.Sprintf("failed to get token claims: %v", err),
		}
	}

	if !result.Valid {
		return nil, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorInvalidToken,
			Message: "token is invalid",
		}
	}

	// Cache the result
	a.cachedClaims[token] = result

	return a.resultToClaimsMap(result), nil
}

// resultToClaimsMap converts a TokenValidationResult to a claims map.
func (a *QuicBaaSAuthAdapter) resultToClaimsMap(result *TokenValidationResult) map[string]interface{} {
	claims := make(map[string]interface{})
	claims["sub"] = result.UserID
	claims["tenant_id"] = result.TenantID
	claims["exp"] = result.ExpiresAt

	if len(result.Roles) > 0 {
		claims["roles"] = result.Roles
	}
	if len(result.Groups) > 0 {
		claims["groups"] = result.Groups
	}
	if result.Scope != "" {
		claims["scope"] = result.Scope
	}

	return claims
}

// =============================================================================
// AuthorizationService interface implementation
// =============================================================================

// CheckPermission checks if a subject (identified by token) has permission
// to perform an action on a resource.
//
// The permission check is performed via QuicBaaS's PEP (Policy Enforcement Point)
// which evaluates ABAC policies to make authorization decisions.
//
// Parameters:
//   - token: The access token identifying the subject
//   - resource: The resource being accessed (e.g., "vtpm", "device", "kms")
//   - action: The action being performed (e.g., "read", "write", "delete")
//
// Returns:
//   - bool: true if the action is allowed, false otherwise
//   - error: non-nil if there was an error checking permission
func (a *QuicBaaSAuthAdapter) CheckPermission(ctx context.Context, token string, resource string, action string) (bool, error) {
	if a.pepClient == nil {
		return false, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorServiceUnavailable,
			Message: "PEP service not available",
		}
	}

	// Get claims from cache or validate token
	var result *TokenValidationResult
	if cached, ok := a.cachedClaims[token]; ok {
		result = cached
	} else {
		// Validate and get claims
		claims, err := a.GetTokenClaims(ctx, token)
		if err != nil {
			return false, err
		}
		// Build result from claims
		result = a.claimsMapToResult(claims)
	}

	// Build the subject from token claims
	tenantID := result.TenantID
	if tenantID == "" {
		tenantID = a.defaultTenantID
	}

	// Build the PEP check request using SDK types
	checkReq := &iam.CheckRequest{
		Subject: iam.CheckSubject{
			ID:       result.UserID,
			TenantID: tenantID,
			Roles:    result.Roles,
			Groups:   result.Groups,
		},
		Action:   action,
		Resource: resource,
	}

	// Execute the policy check
	resp, err := a.pepClient.Check(ctx, checkReq)
	if err != nil {
		return false, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorPermissionCheck,
			Message: fmt.Sprintf("permission check failed: %v", err),
		}
	}

	return resp.Allowed, nil
}

// claimsMapToResult converts a claims map back to TokenValidationResult.
func (a *QuicBaaSAuthAdapter) claimsMapToResult(claims map[string]interface{}) *TokenValidationResult {
	result := &TokenValidationResult{Valid: true}

	if sub, ok := claims["sub"].(string); ok {
		result.UserID = sub
	}
	if tid, ok := claims["tenant_id"].(string); ok {
		result.TenantID = tid
	}
	if exp, ok := claims["exp"].(int64); ok {
		result.ExpiresAt = exp
	}
	if roles, ok := claims["roles"].([]string); ok {
		result.Roles = roles
	}
	if groups, ok := claims["groups"].([]string); ok {
		result.Groups = groups
	}
	if scope, ok := claims["scope"].(string); ok {
		result.Scope = scope
	}

	return result
}

// =============================================================================
// Helper methods
// =============================================================================

// IsConfigured returns true if the adapter has the required services configured.
func (a *QuicBaaSAuthAdapter) IsConfigured() bool {
	return a.tokenValidator != nil && a.pepClient != nil
}

// HasTokenValidator returns true if the token validator is configured.
func (a *QuicBaaSAuthAdapter) HasTokenValidator() bool {
	return a.tokenValidator != nil
}

// HasPEPClient returns true if the PEP client is configured.
func (a *QuicBaaSAuthAdapter) HasPEPClient() bool {
	return a.pepClient != nil
}

// ClearCache clears the token claims cache.
func (a *QuicBaaSAuthAdapter) ClearCache() {
	a.cachedClaims = make(map[string]*TokenValidationResult)
}

// SetDefaultTenantID sets the default tenant ID for operations.
func (a *QuicBaaSAuthAdapter) SetDefaultTenantID(tenantID string) {
	a.defaultTenantID = tenantID
}

// =============================================================================
// Error types
// =============================================================================

// QuicBaaSAuthErrorCode represents error types for QuicBaaS auth operations.
type QuicBaaSAuthErrorCode int

const (
	// QuicBaaSAuthErrorNone indicates no error.
	QuicBaaSAuthErrorNone QuicBaaSAuthErrorCode = iota
	// QuicBaaSAuthErrorServiceUnavailable indicates the QuicBaaS service is not available.
	QuicBaaSAuthErrorServiceUnavailable
	// QuicBaaSAuthErrorInvalidToken indicates the token is invalid.
	QuicBaaSAuthErrorInvalidToken
	// QuicBaaSAuthErrorTokenValidation indicates a token validation error.
	QuicBaaSAuthErrorTokenValidation
	// QuicBaaSAuthErrorPermissionCheck indicates a permission check error.
	QuicBaaSAuthErrorPermissionCheck
	// QuicBaaSAuthErrorClaimsExtraction indicates an error extracting claims.
	QuicBaaSAuthErrorClaimsExtraction
)

// QuicBaaSAuthError represents an error from QuicBaaS auth operations.
type QuicBaaSAuthError struct {
	Code    QuicBaaSAuthErrorCode
	Message string
}

func (e *QuicBaaSAuthError) Error() string {
	return fmt.Sprintf("quicbaas auth error: %s", e.Message)
}

// =============================================================================
// Permission mapping helper
// =============================================================================

// ToolPermission represents the permission required for an MCP tool.
type ToolPermission struct {
	Resource string
	Action   string
}

// ParseToolPermission parses a permission string (e.g., "vtpm:read") into
// resource and action components.
func ParseToolPermission(permission string) (*ToolPermission, error) {
	if permission == "" {
		return nil, nil // No permission required
	}

	parts := strings.SplitN(permission, ":", 2)
	if len(parts) != 2 {
		return nil, &QuicBaaSAuthError{
			Code:    QuicBaaSAuthErrorPermissionCheck,
			Message: fmt.Sprintf("invalid permission format: %s", permission),
		}
	}

	return &ToolPermission{
		Resource: parts[0],
		Action:   parts[1],
	}, nil
}
