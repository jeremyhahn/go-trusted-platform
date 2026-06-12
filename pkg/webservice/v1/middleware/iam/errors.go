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

package iam

import "fmt"

// ErrUnauthorized indicates an authentication failure.
type ErrUnauthorized struct {
	Reason string
}

func (e ErrUnauthorized) Error() string {
	if e.Reason == "" {
		return "unauthorized"
	}
	return fmt.Sprintf("unauthorized: %s", e.Reason)
}

// ErrForbidden indicates an authorization failure.
type ErrForbidden struct {
	Action   string
	Resource string
	Reason   string
}

func (e ErrForbidden) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("forbidden: %s", e.Reason)
	}
	return fmt.Sprintf("forbidden: action %q on resource %q denied", e.Action, e.Resource)
}

// ErrTLSRequired indicates TLS is required but not present.
type ErrTLSRequired struct{}

func (e ErrTLSRequired) Error() string {
	return "TLS connection required"
}

// ErrMTLSRequired indicates mutual TLS is required but client certificate is missing.
type ErrMTLSRequired struct{}

func (e ErrMTLSRequired) Error() string {
	return "client certificate required"
}

// ErrCertificateInvalid indicates a certificate validation failure.
type ErrCertificateInvalid struct {
	Reason string
}

func (e ErrCertificateInvalid) Error() string {
	if e.Reason == "" {
		return "certificate validation failed"
	}
	return fmt.Sprintf("certificate validation failed: %s", e.Reason)
}

// ErrTokenInvalid indicates a JWT token validation failure.
type ErrTokenInvalid struct {
	Reason string
}

func (e ErrTokenInvalid) Error() string {
	if e.Reason == "" {
		return "invalid token"
	}
	return fmt.Sprintf("invalid token: %s", e.Reason)
}

// ErrTokenExpired indicates an expired JWT token.
type ErrTokenExpired struct {
	ExpiredAt string
}

func (e ErrTokenExpired) Error() string {
	if e.ExpiredAt == "" {
		return "token expired"
	}
	return fmt.Sprintf("token expired at %s", e.ExpiredAt)
}

// ErrTokenNotYetValid indicates a token used before its valid time.
type ErrTokenNotYetValid struct {
	NotBefore string
}

func (e ErrTokenNotYetValid) Error() string {
	if e.NotBefore == "" {
		return "token not yet valid"
	}
	return fmt.Sprintf("token not valid before %s", e.NotBefore)
}

// ErrMissingToken indicates no authentication token was provided.
type ErrMissingToken struct{}

func (e ErrMissingToken) Error() string {
	return "authentication token required"
}

// ErrMissingTenantID indicates no tenant ID was provided.
type ErrMissingTenantID struct{}

func (e ErrMissingTenantID) Error() string {
	return "tenant ID required"
}

// ErrUserNotFound indicates the authenticated user was not found in IAM.
type ErrUserNotFound struct {
	Identifier string
}

func (e ErrUserNotFound) Error() string {
	if e.Identifier == "" {
		return "user not found"
	}
	return fmt.Sprintf("user not found: %s", e.Identifier)
}

// ErrMFARequired indicates MFA verification is required.
type ErrMFARequired struct{}

func (e ErrMFARequired) Error() string {
	return "MFA verification required"
}

// ErrMFAExpired indicates MFA verification has expired.
type ErrMFAExpired struct{}

func (e ErrMFAExpired) Error() string {
	return "MFA verification expired"
}

// ErrSessionInvalid indicates an invalid or expired session.
type ErrSessionInvalid struct {
	SessionID string
	Reason    string
}

func (e ErrSessionInvalid) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid session: %s", e.Reason)
	}
	if e.SessionID != "" {
		return fmt.Sprintf("invalid session: %s", e.SessionID)
	}
	return "invalid session"
}

// ErrServiceUnavailable indicates the IAM service is unavailable.
type ErrServiceUnavailable struct {
	Service string
	Reason  string
}

func (e ErrServiceUnavailable) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("service unavailable: %s - %s", e.Service, e.Reason)
	}
	return fmt.Sprintf("service unavailable: %s", e.Service)
}

// ErrInvalidConfig indicates an invalid middleware configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid configuration: %s - %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("invalid configuration: %s", e.Field)
}

// ErrAudienceMismatch indicates the token audience doesn't match expected values.
type ErrAudienceMismatch struct {
	Expected []string
	Actual   []string
}

func (e ErrAudienceMismatch) Error() string {
	return fmt.Sprintf("audience mismatch: expected %v, got %v", e.Expected, e.Actual)
}

// ErrIssuerMismatch indicates the token issuer doesn't match expected value.
type ErrIssuerMismatch struct {
	Expected string
	Actual   string
}

func (e ErrIssuerMismatch) Error() string {
	return fmt.Sprintf("issuer mismatch: expected %q, got %q", e.Expected, e.Actual)
}

// ErrTokenMissingExp indicates a token that has no exp claim.
// Every token must carry an explicit expiration; tokens without exp are
// rejected unconditionally to prevent never-expiring sessions.
type ErrTokenMissingExp struct{}

func (e ErrTokenMissingExp) Error() string {
	return "token missing required exp claim"
}

// ErrAlgorithmNotAllowed indicates the token's signing algorithm is not in
// the allowlist derived from the configured verification key type.
type ErrAlgorithmNotAllowed struct {
	Algorithm string
}

func (e ErrAlgorithmNotAllowed) Error() string {
	return fmt.Sprintf("signing algorithm not allowed: %s", e.Algorithm)
}
