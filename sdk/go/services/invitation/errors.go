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

import "fmt"

// ErrValidationFailed is returned when request validation fails.
type ErrValidationFailed struct {
	Field  string
	Reason string
}

func (e *ErrValidationFailed) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("validation failed: %s", e.Reason)
}

// ErrCreateInvitationFailed is returned when creating an invitation fails.
type ErrCreateInvitationFailed struct {
	Cause error
}

func (e *ErrCreateInvitationFailed) Error() string {
	return fmt.Sprintf("failed to create invitation: %v", e.Cause)
}

func (e *ErrCreateInvitationFailed) Unwrap() error { return e.Cause }

// ErrGetInvitationFailed is returned when retrieving an invitation fails.
type ErrGetInvitationFailed struct {
	ID    uint64
	Token string
	Cause error
}

func (e *ErrGetInvitationFailed) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("failed to get invitation by token: %v", e.Cause)
	}
	return fmt.Sprintf("failed to get invitation %d: %v", e.ID, e.Cause)
}

func (e *ErrGetInvitationFailed) Unwrap() error { return e.Cause }

// ErrListInvitationsFailed is returned when listing invitations fails.
type ErrListInvitationsFailed struct {
	Cause error
}

func (e *ErrListInvitationsFailed) Error() string {
	return fmt.Sprintf("failed to list invitations: %v", e.Cause)
}

func (e *ErrListInvitationsFailed) Unwrap() error { return e.Cause }

// ErrRevokeInvitationFailed is returned when revoking an invitation fails.
type ErrRevokeInvitationFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrRevokeInvitationFailed) Error() string {
	return fmt.Sprintf("failed to revoke invitation %d: %v", e.ID, e.Cause)
}

func (e *ErrRevokeInvitationFailed) Unwrap() error { return e.Cause }

// ErrUnexpectedStatus is returned when the server answers with a non-success
// HTTP status. Message is the server's error text, empty when it sent none.
type ErrUnexpectedStatus struct {
	Operation  string
	StatusCode int
	Message    string
}

func (e *ErrUnexpectedStatus) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s failed: %s (status %d)", e.Operation, e.Message, e.StatusCode)
	}
	return fmt.Sprintf("%s failed: status %d", e.Operation, e.StatusCode)
}

// ErrResponseReadFailed is returned when the body of a non-success response
// cannot be read.
type ErrResponseReadFailed struct {
	Operation  string
	StatusCode int
	Cause      error
}

func (e *ErrResponseReadFailed) Error() string {
	return fmt.Sprintf("%s failed: status %d, failed to read response body: %v", e.Operation, e.StatusCode, e.Cause)
}

func (e *ErrResponseReadFailed) Unwrap() error { return e.Cause }

// ErrInvitationNotFound is returned when an invitation is not found.
type ErrInvitationNotFound struct {
	ID    uint64
	Token string
}

func (e *ErrInvitationNotFound) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation not found: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation not found: id=%d", e.ID)
}

// ErrInvitationExpired is returned when an invitation has expired.
type ErrInvitationExpired struct {
	ID    uint64
	Token string
}

func (e *ErrInvitationExpired) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation expired: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation expired: id=%d", e.ID)
}

// ErrInvitationAlreadyAccepted is returned when an invitation has already been accepted.
type ErrInvitationAlreadyAccepted struct {
	ID    uint64
	Token string
}

func (e *ErrInvitationAlreadyAccepted) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation already accepted: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation already accepted: id=%d", e.ID)
}

// ErrInvitationAlreadyRevoked is returned when an invitation has already been revoked.
type ErrInvitationAlreadyRevoked struct {
	ID    uint64
	Token string
}

func (e *ErrInvitationAlreadyRevoked) Error() string {
	if e.Token != "" {
		return fmt.Sprintf("invitation already revoked: token=%s", e.Token)
	}
	return fmt.Sprintf("invitation already revoked: id=%d", e.ID)
}

// ErrEmailAlreadyRegistered is returned when the email is already registered in the tenant.
type ErrEmailAlreadyRegistered struct {
	Email    string
	TenantID string
}

func (e *ErrEmailAlreadyRegistered) Error() string {
	return fmt.Sprintf("email already registered in tenant: email=%s, tenant_id=%s", e.Email, e.TenantID)
}
