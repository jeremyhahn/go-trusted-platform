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

// Package invitation provides SDK client types for invitation service operations.
package invitation

import "time"

// InvitationStatus represents the status of an invitation.
type InvitationStatus string

const (
	// StatusPending indicates the invitation is awaiting acceptance.
	StatusPending InvitationStatus = "pending"
	// StatusAccepted indicates the invitation has been accepted.
	StatusAccepted InvitationStatus = "accepted"
	// StatusExpired indicates the invitation has expired.
	StatusExpired InvitationStatus = "expired"
	// StatusRevoked indicates the invitation has been revoked.
	StatusRevoked InvitationStatus = "revoked"
)

// String returns the string representation of the status.
func (s InvitationStatus) String() string {
	return string(s)
}

// IsValid returns true if the status is a valid value.
func (s InvitationStatus) IsValid() bool {
	switch s {
	case StatusPending, StatusAccepted, StatusExpired, StatusRevoked:
		return true
	default:
		return false
	}
}

// Invitation represents an invitation to join a tenant.
type Invitation struct {
	// ID is the unique identifier for the invitation.
	ID uint64 `json:"id"`
	// Token is the secure token used to accept the invitation.
	Token string `json:"token"`
	// TenantID is the ID of the tenant the invitation is for.
	TenantID string `json:"tenant_id"`
	// Email is the email address of the invitee.
	Email string `json:"email"`
	// Role is the role to assign when the invitation is accepted.
	Role string `json:"role"`
	// Status is the current status of the invitation.
	Status InvitationStatus `json:"status"`
	// InvitedByID is the ID of the user who created the invitation.
	InvitedByID uint64 `json:"invited_by_id"`
	// ExpiresAt is when the invitation expires.
	ExpiresAt time.Time `json:"expires_at"`
	// CreatedAt is when the invitation was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when the invitation was last updated.
	UpdatedAt time.Time `json:"updated_at"`
	// AcceptedAt is when the invitation was accepted (nil if not accepted).
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
}

// IsExpired returns true if the invitation has expired based on current time.
func (inv *Invitation) IsExpired() bool {
	return time.Now().UTC().After(inv.ExpiresAt)
}

// IsPending returns true if the invitation status is pending.
func (inv *Invitation) IsPending() bool {
	return inv.Status == StatusPending
}

// CanAccept returns true if the invitation can be accepted.
func (inv *Invitation) CanAccept() bool {
	return inv.IsPending() && !inv.IsExpired()
}

// CreateInvitationRequest contains parameters for creating an invitation.
type CreateInvitationRequest struct {
	// Email is the email address to invite (required).
	Email string `json:"email"`
	// Role is the role to assign when accepted (required).
	Role string `json:"role"`
	// ExpiresIn is the duration until the invitation expires.
	// If zero, the server default will be used.
	ExpiresIn time.Duration `json:"expires_in,omitempty"`
}

// Validate validates the create request.
func (r *CreateInvitationRequest) Validate() error {
	if r.Email == "" {
		return &ErrValidationFailed{Field: "email", Reason: "email is required"}
	}
	if r.Role == "" {
		return &ErrValidationFailed{Field: "role", Reason: "role is required"}
	}
	return nil
}

// ListInvitationsRequest contains parameters for listing invitations.
type ListInvitationsRequest struct {
	// PendingOnly filters to only pending invitations.
	PendingOnly bool `json:"pending_only,omitempty"`
	// Limit is the maximum number of invitations to return.
	Limit int32 `json:"limit,omitempty"`
	// Offset is the pagination offset.
	Offset int32 `json:"offset,omitempty"`
}

// ListInvitationsResponse contains the result of listing invitations.
type ListInvitationsResponse struct {
	// Invitations is the list of invitations.
	Invitations []*Invitation `json:"invitations"`
	// Total is the total count of invitations matching the filter.
	Total int32 `json:"total"`
}
