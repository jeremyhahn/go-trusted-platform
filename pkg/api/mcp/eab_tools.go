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
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// EAB tool wiring
// =============================================================================
//
// These tools mirror the gRPC EABService surface so AI/LLM clients can drive
// the same External Account Binding (RFC 8555 §7.3.4) workflows over MCP.
// Tool names follow the project convention `platform_eab_<verb>` and are
// routed through a map-based dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the underlying daemon
// service is exposed via the optional EABProvider interface, satisfied by
// the daemon's MCPServiceProvider when an EAB service is wired in. When a
// provider is not wired, every EAB tool returns ErrEABNotConfigured so
// clients receive a clear, structured failure rather than a generic
// "unknown tool" error.

// ErrEABNotConfigured indicates the EAB backend is not wired into the MCP
// tool registry. Clients see this when the daemon was started without an
// EAB service available.
var ErrEABNotConfigured = errors.New("eab: service provider not configured")

// ErrEABCredentialIDRequired indicates the credential_id argument is
// missing or zero. credential_id is the primary key for credential RPCs
// keyed by ID.
var ErrEABCredentialIDRequired = errors.New("eab: credential_id is required and must be non-zero")

// ErrEABKeyIDRequired indicates the key_id argument is missing.
var ErrEABKeyIDRequired = errors.New("eab: key_id is required")

// ErrEABHMACKeyRequired indicates the hmac_key argument is missing.
var ErrEABHMACKeyRequired = errors.New("eab: hmac_key is required")

// ErrEABProfileIDRequired indicates the profile_id argument is missing
// or zero. profile_id is required for credential generation and listing
// by profile.
var ErrEABProfileIDRequired = errors.New("eab: profile_id is required and must be non-zero")

// ErrEABTenantIDRequired indicates the tenant_id argument is missing.
// tenant_id is required for credential generation.
var ErrEABTenantIDRequired = errors.New("eab: tenant_id is required")

// EABListParams carries the filter and pagination arguments for the
// platform_eab_list_credentials tool, mirroring the gRPC
// ListEABCredentialsRequest so both surfaces expose identical filtering.
type EABListParams struct {
	// TenantID scopes the listing to a tenant. Empty lists all tenants
	// (subject to ProfileID).
	TenantID string
	// ProfileID scopes the listing to a device profile. Zero means all
	// profiles.
	ProfileID uint64
	// ActiveOnly returns only active (non-revoked, non-expired,
	// non-used) credentials.
	ActiveOnly bool
	// Status filters by credential status name (active | revoked |
	// expired | used). Empty means no status filter.
	Status string
	// Page is the 1-based page number; zero returns the full set.
	Page uint32
	// PageSize is the page size; zero returns the full set.
	PageSize uint32
}

// EABProvider is the optional interface a ServiceProvider can satisfy to
// unlock EAB MCP tools. Implementations are expected to delegate to the
// platform eab.Service (the same backing implementation that powers the
// gRPC EABService) so the MCP and gRPC surfaces remain in lockstep.
//
// Method names map to MCP tools: platform_eab_create_credential, etc.
type EABProvider interface {
	// Credential lifecycle
	EABCreateCredential(ctx context.Context, profileID uint64, tenantID string, expiresInSeconds int64, hmacKeyLength int) (interface{}, error)
	EABGetCredential(ctx context.Context, credentialID uint64) (interface{}, error)
	EABGetCredentialByKeyID(ctx context.Context, keyID string) (interface{}, error)
	EABListCredentials(ctx context.Context, params EABListParams) (interface{}, error)
	EABRevokeCredential(ctx context.Context, credentialID uint64, revokerID uint64) (interface{}, error)
	EABValidateCredential(ctx context.Context, keyID string, hmacKey string) (interface{}, error)
	EABDeleteCredential(ctx context.Context, credentialID uint64) (interface{}, error)
	EABMarkCredentialUsed(ctx context.Context, credentialID uint64) (interface{}, error)
	EABCleanupExpiredCredentials(ctx context.Context, tenantID string) (interface{}, error)

	// Delivery
	EABGetCredentialQRCode(ctx context.Context, credentialID uint64, size int) (interface{}, error)
	EABGetEnrollmentURL(ctx context.Context, credentialID uint64, path string) (interface{}, error)
}

// eabProvider returns the EABProvider interface if the ServiceProvider
// implements it, else nil.
func (r *ToolRegistry) eabProvider() EABProvider {
	if p, ok := r.service.(EABProvider); ok {
		return p
	}
	return nil
}

// registerEABTools registers the platform_eab_* MCP tools. Each tool
// definition mirrors the equivalent gRPC RPC so AI/LLM clients can issue
// the same calls they would over gRPC.
func (r *ToolRegistry) registerEABTools() {
	credentialIDSchema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"credential_id": map[string]interface{}{
				"type":        "integer",
				"description": "Unique identifier of the EAB credential",
			},
		},
		"required": []string{"credential_id"},
	}

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_create_credential",
		Description: "Create a new External Account Binding credential for ACME device enrollment (RFC 8555 §7.3.4)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"profile_id": map[string]interface{}{
					"type":        "integer",
					"description": "Device profile ID the credential is associated with",
				},
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Tenant ID the credential belongs to",
				},
				"expires_in_seconds": map[string]interface{}{
					"type":        "integer",
					"description": "Expiration duration in seconds (required, must be positive)",
				},
				"hmac_key_length": map[string]interface{}{
					"type":        "integer",
					"description": "HMAC key length in bytes (minimum 32, default 32)",
				},
			},
			"required": []string{"profile_id", "tenant_id", "expires_in_seconds"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_get_credential",
		Description: "Retrieve an EAB credential by its numeric ID",
		InputSchema: credentialIDSchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_get_credential_by_key_id",
		Description: "Retrieve an EAB credential by its KeyID (the ACME EAB key identifier)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID of the credential (base64url-encoded)",
				},
			},
			"required": []string{"key_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_list_credentials",
		Description: "List EAB credentials, optionally filtered by tenant, profile, status and active state",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional tenant ID filter (empty = all tenants)",
				},
				"profile_id": map[string]interface{}{
					"type":        []string{"integer", "string"},
					"description": "Optional profile ID filter (0 = all profiles); large IDs may be sent as decimal strings",
				},
				"active_only": map[string]interface{}{
					"type":        "boolean",
					"description": "If true, return only active (non-revoked, non-expired, non-used) credentials",
				},
				"status": map[string]interface{}{
					"type":        "string",
					"description": "Optional status filter: active, revoked, expired or used",
				},
				"page": map[string]interface{}{
					"type":        "integer",
					"description": "1-based page number (0 = return the full set)",
				},
				"page_size": map[string]interface{}{
					"type":        "integer",
					"description": "Page size (0 = return the full set)",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_revoke_credential",
		Description: "Revoke an EAB credential so it can no longer be used for enrollment",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"credential_id": map[string]interface{}{"type": "integer"},
				"revoker_id": map[string]interface{}{
					"type":        "integer",
					"description": "ID of the user performing the revocation (audit trail)",
				},
			},
			"required": []string{"credential_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_validate_credential",
		Description: "Validate an EAB credential by KeyID + HMAC key (constant-time comparison)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"key_id": map[string]interface{}{
					"type":        "string",
					"description": "Key ID of the credential to validate",
				},
				"hmac_key": map[string]interface{}{
					"type":        "string",
					"description": "HMAC key to validate (base64url-encoded)",
				},
			},
			"required": []string{"key_id", "hmac_key"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_delete_credential",
		Description: "Permanently delete an EAB credential",
		InputSchema: credentialIDSchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_mark_credential_used",
		Description: "Mark an EAB credential as used after successful ACME enrollment",
		InputSchema: credentialIDSchema,
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_cleanup_expired_credentials",
		Description: "Delete all expired EAB credentials, optionally filtered by tenant",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"tenant_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional tenant ID filter (empty = all tenants)",
				},
			},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_get_credential_qr_code",
		Description: "Generate a PNG QR code image (base64-encoded) containing the EAB credential payload for device delivery",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"credential_id": map[string]interface{}{"type": "integer"},
				"size": map[string]interface{}{
					"type":        "integer",
					"description": "QR code image size in pixels (default 256)",
				},
			},
			"required": []string{"credential_id"},
		},
	})

	r.addTool(mcpwire.ToolDefinition{
		Name:        "platform_eab_get_enrollment_url",
		Description: "Generate an enrollment URL with the EAB credential embedded as query parameters",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"credential_id": map[string]interface{}{"type": "integer"},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Optional URL path override (default: configured base URL path)",
				},
			},
			"required": []string{"credential_id"},
		},
	})
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// eabToolHandler dispatches an EAB tool by name. Map-based dispatch keeps
// routing O(1) per project conventions.
type eabToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var eabToolDispatch = map[string]eabToolHandler{
	"platform_eab_create_credential":           (*ToolRegistry).executeEABCreateCredential,
	"platform_eab_get_credential":              (*ToolRegistry).executeEABGetCredential,
	"platform_eab_get_credential_by_key_id":    (*ToolRegistry).executeEABGetCredentialByKeyID,
	"platform_eab_list_credentials":            (*ToolRegistry).executeEABListCredentials,
	"platform_eab_revoke_credential":           (*ToolRegistry).executeEABRevokeCredential,
	"platform_eab_validate_credential":         (*ToolRegistry).executeEABValidateCredential,
	"platform_eab_delete_credential":           (*ToolRegistry).executeEABDeleteCredential,
	"platform_eab_mark_credential_used":        (*ToolRegistry).executeEABMarkCredentialUsed,
	"platform_eab_cleanup_expired_credentials": (*ToolRegistry).executeEABCleanupExpiredCredentials,
	"platform_eab_get_credential_qr_code":      (*ToolRegistry).executeEABGetCredentialQRCode,
	"platform_eab_get_enrollment_url":          (*ToolRegistry).executeEABGetEnrollmentURL,
}

// dispatchEABTool looks up an EAB tool and invokes it. Returns
// (result, handled, err) so the caller can fall through when handled is
// false (tool name doesn't belong to EAB).
func (r *ToolRegistry) dispatchEABTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := eabToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// eabCredentialID extracts the required `credential_id` argument as a
// uint64. Returns ErrEABCredentialIDRequired when missing or zero.
func eabCredentialID(args map[string]interface{}) (uint64, error) {
	id := uint64(getInt64(args, "credential_id"))
	if id == 0 {
		return 0, ErrEABCredentialIDRequired
	}
	return id, nil
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeEABCreateCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	profileID := uint64(getInt64(args, "profile_id"))
	if profileID == 0 {
		return nil, ErrEABProfileIDRequired
	}
	tenantID := getString(args, "tenant_id")
	if tenantID == "" {
		return nil, ErrEABTenantIDRequired
	}
	expiresInSeconds := getInt64(args, "expires_in_seconds")
	hmacKeyLength := getInt(args, "hmac_key_length")
	return p.EABCreateCredential(ctx, profileID, tenantID, expiresInSeconds, hmacKeyLength)
}

func (r *ToolRegistry) executeEABGetCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	return p.EABGetCredential(ctx, id)
}

func (r *ToolRegistry) executeEABGetCredentialByKeyID(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrEABKeyIDRequired
	}
	return p.EABGetCredentialByKeyID(ctx, keyID)
}

func (r *ToolRegistry) executeEABListCredentials(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	return p.EABListCredentials(ctx, EABListParams{
		TenantID:   getString(args, "tenant_id"),
		ProfileID:  uint64(getInt64(args, "profile_id")),
		ActiveOnly: getBool(args, "active_only"),
		Status:     getString(args, "status"),
		Page:       uint32(getInt64(args, "page")),
		PageSize:   uint32(getInt64(args, "page_size")),
	})
}

func (r *ToolRegistry) executeEABRevokeCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	revokerID := uint64(getInt64(args, "revoker_id"))
	return p.EABRevokeCredential(ctx, id, revokerID)
}

func (r *ToolRegistry) executeEABValidateCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrEABKeyIDRequired
	}
	hmacKey := getString(args, "hmac_key")
	if hmacKey == "" {
		return nil, ErrEABHMACKeyRequired
	}
	return p.EABValidateCredential(ctx, keyID, hmacKey)
}

func (r *ToolRegistry) executeEABDeleteCredential(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	return p.EABDeleteCredential(ctx, id)
}

func (r *ToolRegistry) executeEABMarkCredentialUsed(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	return p.EABMarkCredentialUsed(ctx, id)
}

func (r *ToolRegistry) executeEABCleanupExpiredCredentials(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	// tenant_id is optional for cleanup ("" = all tenants).
	tenantID := getString(args, "tenant_id")
	return p.EABCleanupExpiredCredentials(ctx, tenantID)
}

func (r *ToolRegistry) executeEABGetCredentialQRCode(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	size := getInt(args, "size")
	return p.EABGetCredentialQRCode(ctx, id, size)
}

func (r *ToolRegistry) executeEABGetEnrollmentURL(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.eabProvider()
	if p == nil {
		return nil, ErrEABNotConfigured
	}
	id, err := eabCredentialID(args)
	if err != nil {
		return nil, err
	}
	// path is optional; empty path means use configured base URL path.
	path := getString(args, "path")
	return p.EABGetEnrollmentURL(ctx, id, path)
}
