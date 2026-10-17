//go:build integration

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

// Package invitation provides integration test adapters for Invitation services.
// This file defines the interface and types for invitation operations across all protocols.
package invitation

import (
	"context"
	"time"
)

// InvitationCommands defines the interface for invitation operations across all protocols
type InvitationCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// Invitation Operations

	// CreateInvitation creates a new invitation (tenant owner only)
	CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error)

	// GetInvitationByToken retrieves an invitation by its token (public endpoint)
	GetInvitationByToken(ctx context.Context, opts GetByTokenOptions) (*GetInvitationResult, error)

	// ListInvitations lists all invitations for a tenant
	ListInvitations(ctx context.Context, opts ListInvitationsOptions) (*ListInvitationsResult, error)

	// RevokeInvitation revokes a pending invitation (tenant owner only)
	RevokeInvitation(ctx context.Context, opts RevokeInvitationOptions) (*RevokeResult, error)

	// AcceptInvitation accepts an invitation using its token
	AcceptInvitation(ctx context.Context, opts AcceptInvitationOptions) (*AcceptResult, error)
}

// ============================================================================
// Invitation Types
// ============================================================================

// Invitation represents an invitation in test results
type Invitation struct {
	ID          uint64     `json:"id"`
	Token       string     `json:"token,omitempty"`
	TenantID    string     `json:"tenant_id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	InvitedByID uint64     `json:"invited_by_id,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
	AcceptedAt  *time.Time `json:"accepted_at,omitempty"`
}

// ============================================================================
// Create Invitation
// ============================================================================

// CreateInvitationOptions contains options for creating an invitation
type CreateInvitationOptions struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	// ExpiresIn overrides the server's default expiry when non-zero
	ExpiresIn time.Duration `json:"-"`
	// AsOwner indicates whether the caller is the tenant owner
	AsOwner bool `json:"-"`
	// UserID is the ID of the user making the request
	UserID uint64 `json:"-"`
}

// CreateInvitationResult contains the result of creating an invitation
type CreateInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

// ============================================================================
// Get Invitation by Token
// ============================================================================

// GetByTokenOptions contains options for retrieving an invitation by token
type GetByTokenOptions struct {
	Token string `json:"token"`
}

// GetInvitationResult contains the result of retrieving an invitation
type GetInvitationResult struct {
	Invitation *Invitation `json:"invitation"`
}

// ============================================================================
// List Invitations
// ============================================================================

// ListInvitationsOptions contains options for listing invitations
type ListInvitationsOptions struct {
	TenantID string `json:"tenant_id"`
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
}

// ListInvitationsResult contains the result of listing invitations
type ListInvitationsResult struct {
	Invitations []*Invitation `json:"invitations"`
	Total       int           `json:"total"`
}

// ============================================================================
// Revoke Invitation
// ============================================================================

// RevokeInvitationOptions contains options for revoking an invitation
type RevokeInvitationOptions struct {
	TenantID     string `json:"tenant_id"`
	InvitationID uint64 `json:"invitation_id"`
	// AsOwner indicates whether the caller is the tenant owner
	AsOwner bool `json:"-"`
	// UserID is the ID of the user making the request
	UserID uint64 `json:"-"`
}

// RevokeResult contains the result of revoking an invitation
type RevokeResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// ============================================================================
// Accept Invitation
// ============================================================================

// AcceptInvitationOptions contains options for accepting an invitation
type AcceptInvitationOptions struct {
	Token string `json:"token"`
	// UserID is the registered user accepting the invitation
	UserID   uint64 `json:"user_id"`
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

// AcceptResult contains the result of accepting an invitation
type AcceptResult struct {
	Success bool   `json:"success"`
	UserID  uint64 `json:"user_id,omitempty"`
	Message string `json:"message,omitempty"`
}

// ============================================================================
// Invitation Status Constants
// ============================================================================

const (
	// InvitationStatusPending indicates the invitation is pending
	InvitationStatusPending = "pending"
	// InvitationStatusAccepted indicates the invitation was accepted
	InvitationStatusAccepted = "accepted"
	// InvitationStatusExpired indicates the invitation has expired
	InvitationStatusExpired = "expired"
	// InvitationStatusRevoked indicates the invitation was revoked
	InvitationStatusRevoked = "revoked"
)

// ============================================================================
// Valid Roles
// ============================================================================

// ValidRoles contains the set of valid roles that can be assigned via invitation
var ValidRoles = map[string]struct{}{
	"admin":  {},
	"member": {},
	"viewer": {},
}

// IsValidRole checks if the given role is valid
func IsValidRole(role string) bool {
	_, ok := ValidRoles[role]
	return ok
}
