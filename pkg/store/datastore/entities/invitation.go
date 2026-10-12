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
//
// Invitation never reads the clock. Every constructor and method whose result
// depends on the time takes it as a now parameter, read once by the caller
// (#311). A clock fixed at construction cannot work here: invitations loaded
// from the datastore are reconstituted from a zero value and never pass
// through NewInvitation, so a stored clock would be nil on exactly the objects
// production handles most.
type Invitation struct {
	ID          uint64           `yaml:"id" json:"id"`
	Token       string           `yaml:"token" json:"token" secret:"true"`
	TenantID    string           `yaml:"tenant-id" json:"tenant_id"`
	Email       string           `yaml:"email" json:"email"`
	Role        string           `yaml:"role" json:"role"`
	Status      InvitationStatus `yaml:"status" json:"status"`
	InvitedByID uint64           `yaml:"invited-by-id" json:"invited_by_id"`
	ExpiresAt   time.Time        `yaml:"expires-at" json:"expires_at"`
	CreatedAt   time.Time        `yaml:"created-at" json:"created_at"`
	UpdatedAt   time.Time        `yaml:"updated-at" json:"updated_at"`
	AcceptedAt  *time.Time       `yaml:"accepted-at,omitempty" json:"accepted_at,omitempty"`

	// InitialAdmin marks this invitation as the one that provisions a
	// tenant's FIRST administrator, whose redemption makes the redeemer the
	// tenant owner (#158, owner ruling 2026-09-01).
	//
	// It is deliberately a property of the invitation rather than something
	// the redeemer asserts: the system admin decides, once, at creation time,
	// that this link confers ownership. A redeemer cannot ask for it, and an
	// ordinary invitation cannot become one after the fact.
	//
	// It is not the same as Role. A tenant's first administrator holds an
	// admin role AND owns the tenant; later administrators hold the role and
	// do not. Conflating them would make every admin invitation an ownership
	// grant.
	InitialAdmin bool `yaml:"initial-admin,omitempty" json:"initial_admin,omitempty"`

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

// NewInvitation creates a new invitation with a secure token, created at now
// and valid for expiresDuration from it.
// NewInvitation creates an ordinary tenant invitation. The redeemer becomes
// a member with the given role and does NOT become the tenant owner; use
// NewInitialAdminInvitation for the invitation that provisions a tenant's
// first administrator.
func NewInvitation(
	tenantID, email, role string,
	invitedByID uint64,
	expiresDuration time.Duration,
	now time.Time) (*Invitation, error) {
	token, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	now = now.UTC()
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

// NewInitialAdminInvitation creates the invitation that provisions a tenant's
// FIRST administrator: redeeming it makes the redeemer the tenant owner
// (#158).
//
// It is a separate constructor rather than a boolean parameter on
// NewInvitation because ownership is not an ordinary option — every existing
// call site should keep creating non-owner invitations, and a new call site
// that confers ownership should have to say so by name.
func NewInitialAdminInvitation(
	tenantID, email, role string,
	invitedByID uint64,
	expiresDuration time.Duration,
	now time.Time) (*Invitation, error) {

	inv, err := NewInvitation(tenantID, email, role, invitedByID, expiresDuration, now)
	if err != nil {
		return nil, err
	}
	inv.InitialAdmin = true
	return inv, nil
}

// EntityID returns the entity's unique identifier.
func (inv *Invitation) EntityID() uint64 {
	return inv.ID
}

// SetEntityID sets the entity's unique identifier.
func (inv *Invitation) SetEntityID(id uint64) {
	inv.ID = id
}

// IsExpired reports whether the invitation's expiry is strictly before now.
// An invitation is still valid at the exact instant it expires.
//
// A zero now is reported as expired. It can only mean a caller that never
// read the clock, and since the zero time precedes every expiry, answering it
// literally would make every invitation redeemable forever.
func (inv *Invitation) IsExpired(now time.Time) bool {
	if now.IsZero() {
		return true
	}
	return now.After(inv.ExpiresAt)
}

// IsPending returns true if the invitation is still pending.
func (inv *Invitation) IsPending() bool {
	return inv.Status == InvitationStatusPending
}

// CanAccept returns true if the invitation can be accepted.
// An invitation can be accepted only if it is pending and not expired at now.
func (inv *Invitation) CanAccept(now time.Time) bool {
	return inv.IsPending() && !inv.IsExpired(now)
}

// Accept marks the invitation as accepted at now.
func (inv *Invitation) Accept(now time.Time) {
	now = now.UTC()
	inv.Status = InvitationStatusAccepted
	inv.AcceptedAt = &now
	inv.UpdatedAt = now
}

// Revoke marks the invitation as revoked at now.
func (inv *Invitation) Revoke(now time.Time) {
	inv.Status = InvitationStatusRevoked
	inv.UpdatedAt = now.UTC()
}

// Expire marks the invitation as expired at now.
func (inv *Invitation) Expire(now time.Time) {
	inv.Status = InvitationStatusExpired
	inv.UpdatedAt = now.UTC()
}

// GenerateToken generates a new cryptographically secure token for the invitation
// at now and updates the ID accordingly.
func (inv *Invitation) GenerateToken(now time.Time) error {
	token, err := generateSecureToken()
	if err != nil {
		return err
	}
	inv.Token = token
	inv.ID = util.NewID([]byte(token))
	inv.UpdatedAt = now.UTC()
	return nil
}
