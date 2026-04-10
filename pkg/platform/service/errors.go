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

package service

import "fmt"

// ErrInvitationNotFound is returned when an invitation cannot be found.
type ErrInvitationNotFound struct {
	ID    uint64
	Token string
}

func (e ErrInvitationNotFound) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation not found: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation not found: id=%d", e.ID)
}

// ErrInvitationExpired is returned when an invitation has expired.
type ErrInvitationExpired struct {
	Token string
}

func (e ErrInvitationExpired) Error() string {
	return fmt.Sprintf("invitation expired: token=%s", e.Token)
}

// ErrInvitationAlreadyAccepted is returned when an invitation has already been accepted.
type ErrInvitationAlreadyAccepted struct {
	Token string
}

func (e ErrInvitationAlreadyAccepted) Error() string {
	return fmt.Sprintf("invitation already accepted: token=%s", e.Token)
}

// ErrInvitationRevoked is returned when an invitation has been revoked.
type ErrInvitationRevoked struct {
	Token string
}

func (e ErrInvitationRevoked) Error() string {
	return fmt.Sprintf("invitation has been revoked: token=%s", e.Token)
}

// ErrInvitationAlreadyRevoked is returned when attempting to revoke an already revoked invitation.
type ErrInvitationAlreadyRevoked struct {
	ID    uint64
	Token string
}

func (e ErrInvitationAlreadyRevoked) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation already revoked: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation already revoked: id=%d", e.ID)
}

// ErrEmailAlreadyRegistered is returned when an email is already registered in a tenant.
type ErrEmailAlreadyRegistered struct {
	Email    string
	TenantID string
}

func (e ErrEmailAlreadyRegistered) Error() string {
	return fmt.Sprintf("email already registered in tenant: email=%s, tenant_id=%s", e.Email, e.TenantID)
}

// ErrInvalidInvitationStatus is returned when an invitation has an unexpected status.
type ErrInvalidInvitationStatus struct {
	Status string
}

func (e ErrInvalidInvitationStatus) Error() string {
	return fmt.Sprintf("invalid invitation status: %s", e.Status)
}

// ErrNotTenantOwner is returned when a user attempts an owner-only action.
type ErrNotTenantOwner struct {
	UserID uint64
}

func (e ErrNotTenantOwner) Error() string {
	return fmt.Sprintf("user is not a tenant owner: user_id=%d", e.UserID)
}

// ErrTenantCreationFailed is returned when tenant creation fails.
type ErrTenantCreationFailed struct {
	Cause error
}

func (e ErrTenantCreationFailed) Error() string {
	if e.Cause == nil {
		return "tenant creation failed"
	}
	return fmt.Sprintf("tenant creation failed: %s", e.Cause.Error())
}

func (e ErrTenantCreationFailed) Unwrap() error {
	return e.Cause
}

// ErrUserAlreadyExists is returned when attempting to register an existing user.
type ErrUserAlreadyExists struct {
	Email string
}

func (e ErrUserAlreadyExists) Error() string {
	return fmt.Sprintf("user already exists: email=%s", e.Email)
}

// ErrInvalidInvitation is returned when an invitation is invalid.
type ErrInvalidInvitation struct {
	Reason string
}

func (e ErrInvalidInvitation) Error() string {
	return fmt.Sprintf("invalid invitation: %s", e.Reason)
}

// ErrTokenIssueFailed is returned when JWT token issuance fails.
type ErrTokenIssueFailed struct {
	Cause error
}

func (e ErrTokenIssueFailed) Error() string {
	if e.Cause == nil {
		return "token issuance failed"
	}
	return fmt.Sprintf("token issuance failed: %s", e.Cause.Error())
}

func (e ErrTokenIssueFailed) Unwrap() error {
	return e.Cause
}

// ErrInvitationSaveFailed is returned when saving an invitation fails.
type ErrInvitationSaveFailed struct {
	Cause error
}

func (e ErrInvitationSaveFailed) Error() string {
	if e.Cause == nil {
		return "invitation save failed"
	}
	return fmt.Sprintf("invitation save failed: %s", e.Cause.Error())
}

func (e ErrInvitationSaveFailed) Unwrap() error {
	return e.Cause
}

// ErrUserSaveFailed is returned when saving a user fails.
type ErrUserSaveFailed struct {
	Cause error
}

func (e ErrUserSaveFailed) Error() string {
	if e.Cause == nil {
		return "user save failed"
	}
	return fmt.Sprintf("user save failed: %s", e.Cause.Error())
}

func (e ErrUserSaveFailed) Unwrap() error {
	return e.Cause
}
