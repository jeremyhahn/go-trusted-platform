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

// ErrInvalidRequestBody indicates the request body is invalid or malformed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return "invitation: invalid request body: " + e.Reason
	}
	return "invitation: invalid request body"
}

// ErrMissingEmail indicates the email field is required but not provided.
type ErrMissingEmail struct{}

func (e ErrMissingEmail) Error() string {
	return "invitation: email is required"
}

// ErrInvalidEmail indicates the email format is invalid.
type ErrInvalidEmail struct {
	Email string
}

func (e ErrInvalidEmail) Error() string {
	if e.Email != "" {
		return fmt.Sprintf("invitation: invalid email format: %s", e.Email)
	}
	return "invitation: invalid email format"
}

// ErrMissingRole indicates the role field is required but not provided.
type ErrMissingRole struct{}

func (e ErrMissingRole) Error() string {
	return "invitation: role is required"
}

// ErrInvalidRole indicates the specified role is not valid.
type ErrInvalidRole struct {
	Role string
}

func (e ErrInvalidRole) Error() string {
	if e.Role != "" {
		return fmt.Sprintf("invitation: invalid role: %s", e.Role)
	}
	return "invitation: invalid role"
}

// ErrMissingInvitationID indicates the invitation ID is required but not provided.
type ErrMissingInvitationID struct{}

func (e ErrMissingInvitationID) Error() string {
	return "invitation: invitation id is required"
}

// ErrInvalidInvitationID indicates the invitation ID format is invalid.
type ErrInvalidInvitationID struct {
	ID string
}

func (e ErrInvalidInvitationID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("invitation: invalid invitation id: %s", e.ID)
	}
	return "invitation: invalid invitation id"
}

// ErrMissingToken indicates the invitation token is required but not provided.
type ErrMissingToken struct{}

func (e ErrMissingToken) Error() string {
	return "invitation: token is required"
}

// ErrInvitationNotFound indicates the invitation was not found.
type ErrInvitationNotFound struct {
	ID    uint64
	Token string
}

func (e ErrInvitationNotFound) Error() string {
	if e.Token != "" {
		return "invitation: not found"
	}
	if e.ID > 0 {
		return fmt.Sprintf("invitation: not found: id=%d", e.ID)
	}
	return "invitation: not found"
}

// ErrInvitationExpired indicates the invitation has expired.
type ErrInvitationExpired struct {
	Token string
}

func (e ErrInvitationExpired) Error() string {
	return "invitation: invitation has expired"
}

// ErrInvitationAlreadyAccepted indicates the invitation was already accepted.
type ErrInvitationAlreadyAccepted struct {
	Token string
}

func (e ErrInvitationAlreadyAccepted) Error() string {
	return "invitation: invitation has already been accepted"
}

// ErrInvitationRevoked indicates the invitation was revoked.
type ErrInvitationRevoked struct {
	Token string
}

func (e ErrInvitationRevoked) Error() string {
	return "invitation: invitation has been revoked"
}

// ErrInvitationAlreadyRevoked indicates the invitation was already revoked.
type ErrInvitationAlreadyRevoked struct {
	ID uint64
}

func (e ErrInvitationAlreadyRevoked) Error() string {
	if e.ID > 0 {
		return fmt.Sprintf("invitation: invitation already revoked: id=%d", e.ID)
	}
	return "invitation: invitation already revoked"
}

// ErrNotTenantOwner indicates the user is not the tenant owner.
type ErrNotTenantOwner struct{}

func (e ErrNotTenantOwner) Error() string {
	return "invitation: only tenant owner can perform this operation"
}

// ErrUnauthorized indicates the user is not authenticated.
type ErrUnauthorized struct {
	Reason string
}

func (e ErrUnauthorized) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invitation: unauthorized: %s", e.Reason)
	}
	return "invitation: unauthorized"
}

// ErrServiceError indicates an internal service error occurred.
type ErrServiceError struct {
	Operation string
	Cause     error
}

func (e ErrServiceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invitation: %s failed: %s", e.Operation, e.Cause.Error())
	}
	return fmt.Sprintf("invitation: %s failed", e.Operation)
}

func (e ErrServiceError) Unwrap() error {
	return e.Cause
}

// ErrDuplicateInvitation indicates an invitation already exists for this email.
type ErrDuplicateInvitation struct {
	Email string
}

func (e ErrDuplicateInvitation) Error() string {
	if e.Email != "" {
		return fmt.Sprintf("invitation: invitation already exists for email: %s", e.Email)
	}
	return "invitation: invitation already exists for this email"
}

// ErrEmailAlreadyRegistered indicates the email is already registered in the tenant.
type ErrEmailAlreadyRegistered struct {
	Email    string
	TenantID string
}

func (e ErrEmailAlreadyRegistered) Error() string {
	if e.Email != "" && e.TenantID != "" {
		return fmt.Sprintf("invitation: email already registered in tenant: email=%s, tenant_id=%s", e.Email, e.TenantID)
	}
	if e.Email != "" {
		return fmt.Sprintf("invitation: email already registered: %s", e.Email)
	}
	return "invitation: email already registered"
}

// ErrMissingLogger indicates the logger is required but not provided.
type ErrMissingLogger struct{}

func (e ErrMissingLogger) Error() string {
	return "invitation: logger is required"
}

// ErrMissingInvitationService indicates the invitation service is required but not provided.
type ErrMissingInvitationService struct{}

func (e ErrMissingInvitationService) Error() string {
	return "invitation: invitation service is required"
}

// ErrMissingResponseWriter indicates the response writer is required but not provided.
type ErrMissingResponseWriter struct{}

func (e ErrMissingResponseWriter) Error() string {
	return "invitation: response writer is required"
}
