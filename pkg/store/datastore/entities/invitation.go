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

package entities

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// InvitationStatus represents the status of an invitation.
type InvitationStatus string

const (
	// InvitationStatusPending indicates the invitation is awaiting acceptance.
	InvitationStatusPending InvitationStatus = "pending"
	// InvitationStatusAccepted indicates the invitation has been accepted.
	InvitationStatusAccepted InvitationStatus = "accepted"
	// InvitationStatusExpired indicates the invitation has expired.
	InvitationStatusExpired InvitationStatus = "expired"
	// InvitationStatusRevoked indicates the invitation has been revoked.
	InvitationStatusRevoked InvitationStatus = "revoked"
)

// ErrTokenGeneration indicates a failure to generate a secure token.
type ErrTokenGeneration struct {
	Cause error
}

func (e ErrTokenGeneration) Error() string {
	if e.Cause == nil {
		return "invitation: failed to generate secure token"
	}
	return "invitation: failed to generate secure token: " + e.Cause.Error()
}

func (e ErrTokenGeneration) Unwrap() error {
	return e.Cause
}

// Invitation represents an invitation to join a tenant.
type Invitation struct {
	ID             uint64           `yaml:"id" json:"id"`
	Token          string           `yaml:"token" json:"token" secret:"true"`
	TenantID       string           `yaml:"tenant-id" json:"tenant_id"`
	Email          string           `yaml:"email" json:"email"`
	Role           string           `yaml:"role" json:"role"`
	Status         InvitationStatus `yaml:"status" json:"status"`
	InvitedByID    uint64           `yaml:"invited-by-id" json:"invited_by_id"`
	ExpiresAt      time.Time        `yaml:"expires-at" json:"expires_at"`
	CreatedAt      time.Time        `yaml:"created-at" json:"created_at"`
	UpdatedAt      time.Time        `yaml:"updated-at" json:"updated_at"`
	AcceptedAt     *time.Time       `yaml:"accepted-at,omitempty" json:"accepted_at,omitempty"`
	KeyValueEntity `yaml:"-" json:"-"`
}

// generateSecureToken generates a cryptographically secure 32-byte token
// encoded as base64url.
func generateSecureToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", ErrTokenGeneration{Cause: err}
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// NewInvitation creates a new invitation with a secure token.
// The expiresDuration parameter specifies how long the invitation remains valid.
func NewInvitation(tenantID, email, role string, invitedByID uint64, expiresDuration time.Duration) (*Invitation, error) {
	token, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &Invitation{
		ID:          util.NewID([]byte(token)),
		Token:       token,
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		Status:      InvitationStatusPending,
		InvitedByID: invitedByID,
		ExpiresAt:   now.Add(expiresDuration),
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// EntityID returns the entity's unique identifier.
func (inv *Invitation) EntityID() uint64 {
	return inv.ID
}

// SetEntityID sets the entity's unique identifier.
func (inv *Invitation) SetEntityID(id uint64) {
	inv.ID = id
}

// IsExpired returns true if the invitation has expired.
func (inv *Invitation) IsExpired() bool {
	return time.Now().UTC().After(inv.ExpiresAt)
}

// IsPending returns true if the invitation is still pending.
func (inv *Invitation) IsPending() bool {
	return inv.Status == InvitationStatusPending
}

// CanAccept returns true if the invitation can be accepted.
// An invitation can be accepted only if it is pending and not expired.
func (inv *Invitation) CanAccept() bool {
	return inv.IsPending() && !inv.IsExpired()
}

// Accept marks the invitation as accepted and sets the AcceptedAt timestamp.
func (inv *Invitation) Accept() {
	now := time.Now().UTC()
	inv.Status = InvitationStatusAccepted
	inv.AcceptedAt = &now
	inv.UpdatedAt = now
}

// Revoke marks the invitation as revoked.
func (inv *Invitation) Revoke() {
	inv.Status = InvitationStatusRevoked
	inv.UpdatedAt = time.Now().UTC()
}

// Expire marks the invitation as expired.
func (inv *Invitation) Expire() {
	inv.Status = InvitationStatusExpired
	inv.UpdatedAt = time.Now().UTC()
}

// GenerateToken generates a new cryptographically secure token for the invitation
// and updates the ID accordingly.
func (inv *Invitation) GenerateToken() error {
	token, err := generateSecureToken()
	if err != nil {
		return err
	}
	inv.Token = token
	inv.ID = util.NewID([]byte(token))
	inv.UpdatedAt = time.Now().UTC()
	return nil
}
