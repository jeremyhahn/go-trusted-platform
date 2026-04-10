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

package eab

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// RestHandler defines the HTTP handler interface for EAB credential operations.
type RestHandler interface {
	// Create creates a new EAB credential.
	// POST /api/v1/eab/credentials
	Create(w http.ResponseWriter, r *http.Request)

	// Get retrieves an EAB credential by its ID.
	// GET /api/v1/eab/credentials/{id}
	Get(w http.ResponseWriter, r *http.Request)

	// GetByKeyID retrieves an EAB credential by its KeyID.
	// GET /api/v1/eab/credentials/key/{key_id}
	GetByKeyID(w http.ResponseWriter, r *http.Request)

	// List lists all EAB credentials for a profile.
	// GET /api/v1/eab/credentials?profile_id=X
	List(w http.ResponseWriter, r *http.Request)

	// Revoke revokes an EAB credential.
	// POST /api/v1/eab/credentials/{id}/revoke
	Revoke(w http.ResponseWriter, r *http.Request)

	// Validate validates an EAB credential.
	// POST /api/v1/eab/credentials/validate
	Validate(w http.ResponseWriter, r *http.Request)

	// Delete deletes an EAB credential.
	// DELETE /api/v1/eab/credentials/{id}
	Delete(w http.ResponseWriter, r *http.Request)

	// GetQRCode generates a QR code for credential delivery.
	// GET /api/v1/eab/credentials/{id}/qr
	GetQRCode(w http.ResponseWriter, r *http.Request)

	// GetEnrollmentURL generates an enrollment URL.
	// GET /api/v1/eab/credentials/{id}/url
	GetEnrollmentURL(w http.ResponseWriter, r *http.Request)
}

// EABServicer defines the service interface for EAB credential operations.
type EABServicer interface {
	// Generate creates a new EAB credential.
	Generate(ctx context.Context, params eab.GenerateParams) (*eab.Credential, error)

	// Get retrieves an EAB credential by its ID.
	Get(ctx context.Context, id uint64) (*eab.Credential, error)

	// GetByKeyID retrieves an EAB credential by its KeyID.
	GetByKeyID(ctx context.Context, keyID string) (*eab.Credential, error)

	// ListByProfile retrieves all credentials for a given profile ID.
	ListByProfile(ctx context.Context, profileID uint64) ([]*eab.Credential, error)

	// ListByTenant retrieves all credentials for a given tenant ID.
	ListByTenant(ctx context.Context, tenantID string) ([]*eab.Credential, error)

	// Revoke marks a credential as revoked.
	Revoke(ctx context.Context, id uint64) error

	// Validate checks if a credential is valid for use.
	Validate(ctx context.Context, keyID string, hmacKey []byte) (*eab.Credential, error)

	// Delete removes a credential by ID.
	Delete(ctx context.Context, id uint64) error

	// Page retrieves a paginated list of credentials.
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*eab.Credential], error)
}

// DeliveryServicer defines the interface for credential delivery operations.
type DeliveryServicer interface {
	// ToQRCode generates a QR code image containing the EAB credentials.
	ToQRCode(cred *eab.Credential) ([]byte, error)

	// ToURL generates an enrollment URL with embedded credentials.
	ToURL(cred *eab.Credential) (string, error)
}

// CreateCredentialRequest represents the request body for creating a credential.
type CreateCredentialRequest struct {
	ProfileID        uint64 `json:"profile_id"`
	TenantID         string `json:"tenant_id,omitempty"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

// ValidateCredentialRequest represents the request body for validating a credential.
type ValidateCredentialRequest struct {
	KeyID   string `json:"key_id"`
	HMACKey string `json:"hmac_key"`
}

// CredentialResponse represents an EAB credential in API responses.
type CredentialResponse struct {
	ID        uint64 `json:"id"`
	KeyID     string `json:"key_id"`
	HMACKey   string `json:"hmac_key,omitempty"`
	ProfileID uint64 `json:"profile_id"`
	TenantID  string `json:"tenant_id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at,omitempty"`
	CreatedAt string `json:"created_at"`
	UsedAt    string `json:"used_at,omitempty"`
}

// CredentialListResponse represents a list of EAB credentials in API responses.
type CredentialListResponse struct {
	Credentials []CredentialResponse `json:"credentials"`
	Total       int                  `json:"total"`
}

// ValidateCredentialResponse represents the response for credential validation.
type ValidateCredentialResponse struct {
	Valid      bool                `json:"valid"`
	Credential *CredentialResponse `json:"credential,omitempty"`
}

// RevokeResponse represents the response for a successful revocation.
type RevokeResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// DeleteResponse represents the response for a successful deletion.
type DeleteResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// EnrollmentURLResponse represents the response containing an enrollment URL.
type EnrollmentURLResponse struct {
	URL string `json:"url"`
}

// ToCredentialResponse converts an eab.Credential to a CredentialResponse.
func ToCredentialResponse(cred *eab.Credential, includeHMACKey bool) CredentialResponse {
	resp := CredentialResponse{
		ID:        cred.ID,
		KeyID:     cred.KeyID,
		ProfileID: cred.ProfileID,
		TenantID:  cred.TenantID,
		Status:    cred.Status.String(),
		CreatedAt: cred.CreatedAt.Format(time.RFC3339),
	}
	if includeHMACKey {
		resp.HMACKey = base64.RawURLEncoding.EncodeToString(cred.HMACKey)
	}
	if !cred.ExpiresAt.IsZero() {
		resp.ExpiresAt = cred.ExpiresAt.Format(time.RFC3339)
	}
	if !cred.UsedAt.IsZero() {
		resp.UsedAt = cred.UsedAt.Format(time.RFC3339)
	}
	return resp
}

// ToCredentialListResponse converts a slice of eab.Credential to a CredentialListResponse.
func ToCredentialListResponse(credentials []*eab.Credential) CredentialListResponse {
	responses := make([]CredentialResponse, 0, len(credentials))
	for _, cred := range credentials {
		responses = append(responses, ToCredentialResponse(cred, false))
	}
	return CredentialListResponse{
		Credentials: responses,
		Total:       len(responses),
	}
}
