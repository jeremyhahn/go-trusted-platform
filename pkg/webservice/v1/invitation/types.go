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

package invitation

import (
	"context"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// RestHandler defines the HTTP handler interface for invitation operations.
type RestHandler interface {
	// Create creates a new invitation (tenant owner only).
	// POST /api/v1/invitations
	Create(w http.ResponseWriter, r *http.Request)

	// List lists all invitations for the current tenant.
	// GET /api/v1/invitations
	List(w http.ResponseWriter, r *http.Request)

	// GetByToken retrieves an invitation by its token (public endpoint).
	// GET /api/v1/invitations/token/{token}
	GetByToken(w http.ResponseWriter, r *http.Request)

	// Get retrieves an invitation by its ID.
	// GET /api/v1/invitations/{id}
	Get(w http.ResponseWriter, r *http.Request)

	// Revoke revokes an invitation (tenant owner only).
	// DELETE /api/v1/invitations/{id}
	Revoke(w http.ResponseWriter, r *http.Request)
}

// InvitationHandler is an alias for RestHandler for backward compatibility.
type InvitationHandler = RestHandler

// InvitationServicer defines the service interface for invitation operations.
type InvitationServicer interface {
	// Create creates a new invitation with optional expiry duration.
	Create(ctx context.Context, tenantID, email, role string, invitedByID uint64, expiresIn time.Duration) (*entities.Invitation, error)

	// Get retrieves an invitation by ID.
	Get(ctx context.Context, id uint64) (*entities.Invitation, error)

	// GetByToken retrieves an invitation by its secure token.
	GetByToken(ctx context.Context, token string) (*entities.Invitation, error)

	// ListByTenant retrieves all invitations for a tenant.
	ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error)

	// Revoke revokes an invitation.
	Revoke(ctx context.Context, id uint64) error
}

// UserServicer defines the user service interface needed by the invitation handler.
type UserServicer interface {
	// IsTenantOwner checks if the user is the owner of the specified tenant.
	IsTenantOwner(ctx context.Context, userID uint64, tenantID string) (bool, error)
}

// CreateInvitationRequest represents the request body for creating an invitation.
type CreateInvitationRequest struct {
	Email     string        `json:"email"`
	Role      string        `json:"role"`
	ExpiresIn time.Duration `json:"expires_in,omitempty"`
}

// InvitationResponse represents an invitation in API responses.
type InvitationResponse struct {
	ID        uint64    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	Token     string    `json:"token,omitempty" secret:"true"`
	InviteURL string    `json:"invite_url,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// InvitationListResponse represents a list of invitations in API responses.
type InvitationListResponse struct {
	Invitations []InvitationResponse `json:"invitations"`
	Total       int                  `json:"total"`
}

// RevokeResponse represents the response for a successful revocation.
type RevokeResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ValidRoles contains the set of valid roles that can be assigned via invitation.
var ValidRoles = map[string]struct{}{
	"admin":  {},
	"member": {},
	"viewer": {},
}

// IsValidRole checks if the given role is valid.
func IsValidRole(role string) bool {
	_, ok := ValidRoles[role]
	return ok
}

// ToInvitationResponse converts an Invitation entity to an InvitationResponse.
// Deprecated: Use ToInvitationResponseWithURL for responses that include the invite URL.
func ToInvitationResponse(inv *entities.Invitation, includeToken bool) InvitationResponse {
	return ToInvitationResponseWithURL(inv, includeToken, "")
}

// ToInvitationResponseWithURL converts an Invitation entity to an InvitationResponse
// with an optional invite URL constructed from the base URL.
func ToInvitationResponseWithURL(inv *entities.Invitation, includeToken bool, baseURL string) InvitationResponse {
	resp := InvitationResponse{
		ID:        inv.ID,
		TenantID:  inv.TenantID,
		Email:     inv.Email,
		Role:      inv.Role,
		Status:    string(inv.Status),
		ExpiresAt: inv.ExpiresAt,
		CreatedAt: inv.CreatedAt,
	}
	if includeToken {
		resp.Token = inv.Token
		if baseURL != "" && inv.Token != "" {
			resp.InviteURL = buildInviteURL(baseURL, inv.Token)
		}
	}
	return resp
}

// ToInvitationListResponse converts a slice of Invitation entities to an InvitationListResponse.
func ToInvitationListResponse(invitations []*entities.Invitation, baseURL string) InvitationListResponse {
	responses := make([]InvitationResponse, 0, len(invitations))
	for _, inv := range invitations {
		responses = append(responses, ToInvitationResponseWithURL(inv, false, baseURL))
	}
	return InvitationListResponse{
		Invitations: responses,
		Total:       len(responses),
	}
}

// buildInviteURL constructs the full invitation URL from base URL and token.
func buildInviteURL(baseURL, token string) string {
	if baseURL == "" || token == "" {
		return ""
	}
	// Remove trailing slash from baseURL if present
	if baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	return baseURL + "/invite/" + token
}
