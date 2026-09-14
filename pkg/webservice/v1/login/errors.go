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

package login

import quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"

// UnavailableError reports that no unified login client is wired. The
// driver fails closed with it rather than falling back to a locally
// minted credential: the platform is a consumer of the backbone's
// sessions, never an issuer of its own.
type UnavailableError struct{}

// Error implements error.
func (e *UnavailableError) Error() string {
	return "login: the unified login client is not configured"
}

// UnsupportedFactorError reports that no binder is registered for the
// requested factor type, so the driver cannot build the ceremony's
// requests. It is a wiring defect, not a client error.
type UnsupportedFactorError struct {
	// Type is the factor type that has no binder.
	Type quicbaas.FactorType
}

// Error implements error.
func (e *UnsupportedFactorError) Error() string {
	return "login: no binder is registered for factor type " + string(e.Type)
}

// NoBearerError reports that the ceremony completed without returning a
// bearer. An error-free response is not authentication: a nil response or
// an empty bearer proves nothing, so the driver refuses the login.
type NoBearerError struct{}

// Error implements error.
func (e *NoBearerError) Error() string {
	return "login: the ceremony returned no bearer"
}

// MissingSessionError reports that a challenge factor's finish request
// carried no ceremony session. A finish that cannot be correlated with a
// begin cannot be verified against its challenge.
type MissingSessionError struct{}

// Error implements error.
func (e *MissingSessionError) Error() string {
	return "login: the ceremony session is missing"
}

// MissingChallengeError reports that the backbone opened a challenge
// ceremony without returning the challenge material the client needs.
type MissingChallengeError struct {
	// Field is the challenge-metadata key that was absent.
	Field string
}

// Error implements error.
func (e *MissingChallengeError) Error() string {
	return "login: the challenge is missing " + e.Field
}

// InvalidProofError reports that a factor proof could not be read from
// the request: a malformed body, an oversized body, or a proof missing
// the credential identifier the lookup key is derived from.
type InvalidProofError struct {
	// Reason states what was wrong with the proof.
	Reason string
}

// Error implements error.
func (e *InvalidProofError) Error() string {
	return "login: invalid factor proof: " + e.Reason
}

// DriverConfigError reports a missing or invalid driver dependency. The
// driver refuses to construct rather than running with a nil collaborator
// it would only discover mid-ceremony.
type DriverConfigError struct {
	// Field is the dependency that was absent or invalid.
	Field string
}

// Error implements error.
func (e *DriverConfigError) Error() string {
	return "login: driver requires " + e.Field
}

// DuplicateBinderError reports two binders claiming the same factor type.
// Which one would win is unknowable to a reader, so construction fails
// rather than resolving it by map-insertion order.
type DuplicateBinderError struct {
	// Type is the contested factor type.
	Type quicbaas.FactorType
}

// Error implements error.
func (e *DuplicateBinderError) Error() string {
	return "login: more than one binder claims factor type " + string(e.Type)
}

// NoIdentityError reports that the ceremony issued a bearer without
// naming the principal it belongs to. A session credential cannot be
// minted for nobody, so the login is refused rather than answered with an
// anonymous one.
type NoIdentityError struct{}

// Error implements error.
func (e *NoIdentityError) Error() string {
	return "login: the ceremony resolved no identity"
}

// SessionIssueError reports that the platform could not mint the session
// credential for a principal the backbone HAD authenticated. The ceremony
// succeeded and the failure is entirely platform-side — a signing key
// that cannot be reached, an identity missing the claims the credential
// requires — so it is reported as a platform fault, never as a rejected
// login.
type SessionIssueError struct {
	// Cause is the underlying issuance failure.
	Cause error
}

// Error implements error.
func (e *SessionIssueError) Error() string {
	if e.Cause == nil {
		return "login: the platform session credential could not be issued"
	}
	return "login: the platform session credential could not be issued: " + e.Cause.Error()
}

// Unwrap exposes the underlying failure to errors.Is / errors.As.
func (e *SessionIssueError) Unwrap() error {
	return e.Cause
}

// FactorUnavailableError reports that a factor's ceremony cannot be run
// safely on this deployment, so the platform declines to open it at all.
//
// It is distinct from UnsupportedFactorError (no binder is registered — a
// wiring defect) and from UnavailableError (no backbone at all). This one
// says the binder exists and knows it cannot bind the caller's credential
// to the ceremony, which is a refusal to guess rather than a fault.
type FactorUnavailableError struct {
	// Type is the factor whose ceremony is declined.
	Type quicbaas.FactorType

	// Reason states why it cannot be run.
	Reason string
}

// Error implements error.
func (e *FactorUnavailableError) Error() string {
	return "login: the " + string(e.Type) + " factor is unavailable: " + e.Reason
}
