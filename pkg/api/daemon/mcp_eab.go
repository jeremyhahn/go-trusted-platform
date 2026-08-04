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
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
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
// EAB service treats a nil servicer (Unavailable via requireService).
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

// EABServicer is the canonical EAB service interface shared by the gRPC,
// QUIC, MCP and REST surfaces. It is a type alias of the domain
// eab.Service interface (pkg/eab/types.go) so there is exactly ONE EAB
// service contract in the codebase.
type EABServicer = eab.Service

// EABDeliveryServicer mirrors *eab.Delivery so the MCP bridge can render
// QR codes and enrollment URLs without importing the concrete type.
type EABDeliveryServicer interface {
	ToQRCode(cred *eab.Credential) ([]byte, error)
	ToQRCodeSized(cred *eab.Credential, size int) ([]byte, error)
	ToURL(cred *eab.Credential) (string, error)
	ToURLWithPath(cred *eab.Credential, path string) (string, error)
}

// Compile-time check: the concrete delivery implements the view interface.
var _ EABDeliveryServicer = (*eab.Delivery)(nil)

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

// EABListCredentials lists credentials with the same filter cascade as
// the gRPC ListCredentials RPC: profile_id (tenant_id refines),
// tenant_id, or the full store when both are empty. status and
// active_only refine the result; pagination is applied last so the
// reported total reflects the filtered set.
func (p *MCPServiceProvider) EABListCredentials(
	ctx context.Context,
	params mcp.EABListParams,
) (interface{}, error) {
	if p.eabService == nil {
		return nil, ErrEABNotConfigured{}
	}

	var (
		creds []*eab.Credential
		err   error
	)
	switch {
	case params.ProfileID > 0:
		creds, err = p.eabService.ListByProfile(ctx, params.ProfileID)
	case params.TenantID != "":
		creds, err = p.eabService.ListByTenant(ctx, params.TenantID)
	default:
		creds, err = eabCollectAll(ctx, p.eabService)
	}
	if err != nil {
		return nil, err
	}

	filtered := make([]*eab.Credential, 0, len(creds))
	for _, c := range creds {
		// When ListByProfile is used, an additional tenant filter must
		// never leak another tenant's credentials.
		if params.ProfileID > 0 && params.TenantID != "" && c.TenantID != params.TenantID {
			continue
		}
		if params.Status != "" && c.Status.String() != params.Status {
			continue
		}
		if params.ActiveOnly && !c.IsValid() {
			continue
		}
		filtered = append(filtered, c)
	}

	pageCreds := filtered
	if params.PageSize > 0 {
		page := params.Page
		if page == 0 {
			page = 1
		}
		start := uint64(page-1) * uint64(params.PageSize)
		if start >= uint64(len(filtered)) {
			pageCreds = nil
		} else {
			end := start + uint64(params.PageSize)
			if end > uint64(len(filtered)) {
				end = uint64(len(filtered))
			}
			pageCreds = filtered[start:end]
		}
	}

	out := make([]map[string]interface{}, 0, len(pageCreds))
	for _, c := range pageCreds {
		out = append(out, eabCredentialJSON(c, false))
	}
	return map[string]interface{}{
		"tenant_id":   params.TenantID,
		"profile_id":  strconv.FormatUint(params.ProfileID, 10),
		"active_only": params.ActiveOnly,
		"status":      params.Status,
		"page":        params.Page,
		"page_size":   params.PageSize,
		"credentials": out,
		"total":       len(filtered),
	}, nil
}

// eabCollectAll walks the paginated credential store and returns every
// credential, mirroring the gRPC service's unfiltered list path.
func eabCollectAll(ctx context.Context, svc EABServicer) ([]*eab.Credential, error) {
	var all []*eab.Credential
	query := datastore.PageQuery{Page: 1, PageSize: eabPageCollectSize}
	for {
		result, err := svc.Page(ctx, query)
		if err != nil {
			return nil, err
		}
		all = append(all, result.Entities...)
		if !result.HasMore || len(result.Entities) == 0 {
			return all, nil
		}
		query.Page++
	}
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
		"credential_id": strconv.FormatUint(credentialID, 10),
		"revoker_id":    strconv.FormatUint(revokerID, 10),
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
		"credential_id": strconv.FormatUint(credentialID, 10),
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
		"credential_id": strconv.FormatUint(credentialID, 10),
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
	png, err := p.eabDelivery.ToQRCodeSized(cred, size)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"credential_id": strconv.FormatUint(credentialID, 10),
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
		"credential_id": strconv.FormatUint(credentialID, 10),
		"url":           url,
	}, nil
}

// =============================================================================
// Helpers
// =============================================================================

// eabCredentialJSON formats an EAB credential as a JSON-friendly map.
// Mirrors the proto EABCredential shape so MCP clients see the same
// fields gRPC clients already know. uint64 identifiers are rendered as
// decimal strings per the repo-wide uint64-on-the-wire convention (JSON
// numbers lose precision past 2^53). The HMAC key is included only when
// includeHMACKey is true (i.e. on create) per RFC 8555 §7.3.4.
func eabCredentialJSON(cred *eab.Credential, includeHMACKey bool) map[string]interface{} {
	if cred == nil {
		return nil
	}
	out := map[string]interface{}{
		"id":         strconv.FormatUint(cred.ID, 10),
		"key_id":     cred.KeyID,
		"profile_id": strconv.FormatUint(cred.ProfileID, 10),
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
