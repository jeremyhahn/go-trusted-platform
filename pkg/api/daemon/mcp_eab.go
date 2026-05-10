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

package daemon

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
)

// =============================================================================
// MCP EAB bridge
// =============================================================================
//
// MCPServiceProvider implements mcp.EABProvider by delegating to the same
// EABServicer that powers the gRPC EABService. This keeps the MCP and gRPC
// surfaces in lockstep: AI/LLM clients calling platform_eab_create_credential
// hit the exact same code path as a gRPC CreateCredential RPC.

// ErrEABNotConfigured indicates that no EAB servicer is wired into the
// MCPServiceProvider. Callers should treat this the same way the gRPC
// EAB service treats a nil servicer (FailedPrecondition).
type ErrEABNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrEABNotConfigured) Error() string {
	return "eab service not configured"
}

// ErrEABDeliveryNotConfigured indicates that no EAB delivery servicer is
// wired into the MCPServiceProvider. Callers see this when the daemon was
// started without QR/URL delivery configured.
type ErrEABDeliveryNotConfigured struct{}

// Error returns a human-readable description of the error.
func (ErrEABDeliveryNotConfigured) Error() string {
	return "eab delivery not configured"
}

// ErrEABInvalidHMACKey indicates a base64url-encoded HMAC key value sent
// over MCP could not be decoded.
type ErrEABInvalidHMACKey struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrEABInvalidHMACKey) Error() string {
	return "eab: invalid hmac_key encoding: " + e.Cause.Error()
}

// Unwrap exposes the underlying decode error for errors.Is/As.
func (e ErrEABInvalidHMACKey) Unwrap() error {
	return e.Cause
}

// EABServicer defines the EAB service operations the MCP bridge delegates
// to. The interface mirrors eab.Service so production wiring passes the
// concrete service while tests can supply fakes. Keeping this interface
// local to the daemon package avoids leaking domain types across the MCP
// boundary while still enabling lock-step behavior with the gRPC surface.
type EABServicer interface {
	Generate(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error)
	Get(ctx context.Context, id uint64) (*eab.Credential, error)
	GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error)
	ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error)
	ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error)
	Revoke(ctx context.Context, id uint64) error
	Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error)
	Delete(ctx context.Context, id uint64) error
	MarkUsed(ctx context.Context, id uint64) error
	CleanupExpired(ctx context.Context) (int, error)
}

// EABDeliveryServicer mirrors *eab.Delivery so the MCP bridge can render
// QR codes and enrollment URLs without importing the concrete type.
type EABDeliveryServicer interface {
	ToQRCode(cred *eab.Credential) ([]byte, error)
	ToURL(cred *eab.Credential) (string, error)
	ToURLWithPath(cred *eab.Credential, path string) (string, error)
}

// SetEABService injects the EAB service after construction. The daemon
// wires the same EABServicer that powers the gRPC EABServiceServer so the
// MCP and gRPC surfaces stay in lockstep.
func (p *MCPServiceProvider) SetEABService(svc EABServicer) {
	p.eabService = svc
}

// SetEABDelivery injects the EAB delivery handler after construction.
func (p *MCPServiceProvider) SetEABDelivery(d EABDeliveryServicer) {
	p.eabDelivery = d
}

// =============================================================================
// Credential lifecycle
// =============================================================================

// EABCreateCredential creates a new EAB credential for ACME device
// enrollment. The HMAC key is included in the response (only on create)
// per RFC 8555 §7.3.4.
func (p *MCPServiceProvider) EABCreateCredential(
	ctx context.Context,
	profileID uint64,
	tenantID string,
	expiresInSeconds int64,
	hmacKeyLength int,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	params := eab.GenerateParams{
		ProfileID:  profileID,
		TenantID:   tenantID,
		HMACKeyLen: hmacKeyLength,
	}
	if expiresInSeconds > 0 {
		params.ExpiresIn = time.Duration(expiresInSeconds) * time.Second
	}
	cred, err := p.eabService.Generate(ctx, params)
	if err != nil {
		return nil, err
	}
	// Include HMAC key only on create per RFC 8555.
	return eabCredentialJSON(cred, true), nil
}

// EABGetCredential retrieves a credential by its numeric ID. The HMAC
// key is omitted from the response.
func (p *MCPServiceProvider) EABGetCredential(ctx context.Context, credentialID uint64) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	cred, err := p.eabService.Get(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	return eabCredentialJSON(cred, false), nil
}

// EABGetCredentialByKeyID retrieves a credential by its KeyID. The HMAC
// key is omitted from the response.
func (p *MCPServiceProvider) EABGetCredentialByKeyID(ctx context.Context, keyID string) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	cred, err := p.eabService.GetByKeyID(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return eabCredentialJSON(cred, false), nil
}

// EABListCredentials lists credentials for a tenant, optionally filtered
// by profile and active status.
func (p *MCPServiceProvider) EABListCredentials(
	ctx context.Context,
	tenantID string,
	profileID uint64,
	activeOnly bool,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	var (
		creds []*eab.Credential
		err   error
	)
	if profileID > 0 {
		creds, err = p.eabService.ListByProfile(ctx, profileID)
	} else {
		creds, err = p.eabService.ListByTenant(ctx, tenantID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		// When ListByProfile is used, additionally filter by tenant so
		// the MCP-visible list never crosses tenant boundaries.
		if profileID > 0 && c.TenantID != tenantID {
			continue
		}
		if activeOnly && !c.IsValid() {
			continue
		}
		out = append(out, eabCredentialJSON(c, false))
	}
	return map[string]interface{}{
		"tenant_id":   tenantID,
		"profile_id":  profileID,
		"active_only": activeOnly,
		"credentials": out,
		"total":       len(out),
	}, nil
}

// EABRevokeCredential marks a credential as revoked.
func (p *MCPServiceProvider) EABRevokeCredential(
	ctx context.Context,
	credentialID uint64,
	revokerID uint64,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	if err := p.eabService.Revoke(ctx, credentialID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": credentialID,
		"revoker_id":    revokerID,
		"status":        "revoked",
	}, nil
}

// EABValidateCredential checks a (KeyID, HMAC key) pair using a
// constant-time comparison. The HMAC key arrives base64url-encoded so
// MCP/JSON transports stay safe; we decode before delegating.
func (p *MCPServiceProvider) EABValidateCredential(
	ctx context.Context,
	keyID string,
	hmacKey string,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	decoded, err := decodeEABHMACKey(hmacKey)
	if err != nil {
		return nil, err
	}
	cred, err := p.eabService.Validate(ctx, keyID, decoded)
	if err != nil {
		return map[string]interface{}{
			"valid":         false,
			"key_id":        keyID,
			"error_message": err.Error(),
		}, nil
	}
	return map[string]interface{}{
		"valid":      true,
		"credential": eabCredentialJSON(cred, false),
	}, nil
}

// EABDeleteCredential permanently removes a credential.
func (p *MCPServiceProvider) EABDeleteCredential(ctx context.Context, credentialID uint64) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	if err := p.eabService.Delete(ctx, credentialID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": credentialID,
		"status":        "deleted",
	}, nil
}

// EABMarkCredentialUsed marks a credential as used after successful
// ACME enrollment.
func (p *MCPServiceProvider) EABMarkCredentialUsed(ctx context.Context, credentialID uint64) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	if err := p.eabService.MarkUsed(ctx, credentialID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": credentialID,
		"status":        "used",
	}, nil
}

// EABCleanupExpiredCredentials removes all expired credentials. The
// underlying service does not currently support per-tenant cleanup; we
// echo the requested filter back so callers can confirm intent.
func (p *MCPServiceProvider) EABCleanupExpiredCredentials(ctx context.Context, tenantID string) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	deleted, err := p.eabService.CleanupExpired(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"deleted_count": deleted,
		"tenant_id":     tenantID,
		"status":        "ok",
	}, nil
}

// =============================================================================
// Delivery
// =============================================================================

// EABGetCredentialQRCode renders a credential as a base64-encoded PNG
// QR code for device delivery.
func (p *MCPServiceProvider) EABGetCredentialQRCode(
	ctx context.Context,
	credentialID uint64,
	size int,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	if p.eabDelivery == nil {
		return nil, ErrEABDeliveryNotConfigured{}
	}
	cred, err := p.eabService.Get(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	png, err := p.eabDelivery.ToQRCode(cred)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": credentialID,
		"content_type":  "image/png",
		"size":          size,
		"qr_code":       base64.StdEncoding.EncodeToString(png),
	}, nil
}

// EABGetEnrollmentURL renders an enrollment URL with the credential
// embedded as query parameters.
func (p *MCPServiceProvider) EABGetEnrollmentURL(
	ctx context.Context,
	credentialID uint64,
	path string,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}
	if p.eabDelivery == nil {
		return nil, ErrEABDeliveryNotConfigured{}
	}
	cred, err := p.eabService.Get(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	var url string
	if path != "" {
		url, err = p.eabDelivery.ToURLWithPath(cred, path)
	} else {
		url, err = p.eabDelivery.ToURL(cred)
	}
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": credentialID,
		"url":           url,
	}, nil
}

// =============================================================================
// Helpers
// =============================================================================

// eabCredentialJSON formats an EAB credential as a JSON-friendly map.
// Mirrors the proto EABCredential shape so MCP clients see the same
// fields gRPC clients already know. The HMAC key is included only when
// includeHMACKey is true (i.e. on create) per RFC 8555 §7.3.4.
func eabCredentialJSON(cred *eab.Credential, includeHMACKey bool) map[string]interface{} {
	if cred == nil {
		return nil
	}
	out := map[string]interface{}{
		"id":         cred.ID,
		"key_id":     cred.KeyID,
		"profile_id": cred.ProfileID,
		"tenant_id":  cred.TenantID,
		"status":     cred.Status.String(),
		"created_at": cred.CreatedAt,
	}
	if !cred.ExpiresAt.IsZero() {
		out["expires_at"] = cred.ExpiresAt
	}
	if !cred.UsedAt.IsZero() {
		out["used_at"] = cred.UsedAt
	}
	if includeHMACKey {
		out["hmac_key"] = base64.RawURLEncoding.EncodeToString(cred.HMACKey)
	}
	return out
}

// decodeEABHMACKey decodes a base64url-encoded HMAC key from MCP
// transport, accepting both raw (no padding) and standard variants so
// callers can use whichever encoding their stack produces.
func decodeEABHMACKey(encoded string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrEABInvalidHMACKey{Cause: err}
	}
	return decoded, nil
}
