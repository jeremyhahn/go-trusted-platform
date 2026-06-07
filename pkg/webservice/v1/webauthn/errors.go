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

package webauthn

import "errors"

var (
	// ErrInvalidOrganizationID is returned when the organization ID is invalid.
	ErrInvalidOrganizationID = errors.New("webauthn: invalid organization id")

	// ErrUserAlreadyExists is returned when a user is already registered.
	ErrUserAlreadyExists = errors.New("webauthn: user already registered")

	// ErrInvalidUserIDHeader is returned when the X-User-Id header is invalid or missing.
	ErrInvalidUserIDHeader = errors.New("webauthn: invalid user id header")

	// ErrInvalidUserID is returned when the user ID is invalid.
	ErrInvalidUserID = errors.New("webauthn: invalid user")

	// ErrInvalidRequestBody is returned when the request body cannot be parsed.
	ErrInvalidRequestBody = errors.New("webauthn: invalid request body")

	// ErrUsernameRequired is returned when the username field is empty.
	ErrUsernameRequired = errors.New("webauthn: username is required")

	// ErrInvitationServiceNotConfigured is returned when invitation token is provided
	// but the invitation service is not configured.
	ErrInvitationServiceNotConfigured = errors.New("webauthn: invitation service not configured")

	// ErrInvitationEmailMismatch is returned when the invitation email does not match
	// the provided username.
	ErrInvitationEmailMismatch = errors.New("webauthn: invitation email does not match username")

	// ErrInvitationExpired is returned when the invitation has expired.
	ErrInvitationExpired = errors.New("webauthn: invitation has expired")

	// ErrInvitationAlreadyAccepted is returned when the invitation has already been accepted.
	ErrInvitationAlreadyAccepted = errors.New("webauthn: invitation has already been accepted")

	// ErrInvitationRevoked is returned when the invitation has been revoked.
	ErrInvitationRevoked = errors.New("webauthn: invitation has been revoked")

	// ErrInvalidInvitationStatus is returned when the invitation has an unexpected status.
	ErrInvalidInvitationStatus = errors.New("webauthn: invalid invitation status")

	// ErrSDKClientRequired is returned when the WebAuthn handler is
	// constructed without a SDK relying-party client.
	ErrSDKClientRequired = errors.New("webauthn: SDK WebAuthn client is required")

	// ErrInvalidConfig is returned when the relying-party Config is
	// missing the RPID or RPOrigins fields.
	ErrInvalidConfig = errors.New("webauthn: invalid relying-party configuration")

	// ErrRefreshUnsupported is returned when a caller attempts to use
	// the WebAuthn handler as a refresh-token middleware.
	ErrRefreshUnsupported = errors.New("webauthn: refresh tokens are issued via /jwt/refresh")
)
