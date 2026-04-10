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

package attestation

import "fmt"

// ErrAttestationRequired is returned when attestation is required but no token is provided.
type ErrAttestationRequired struct {
	Zone string
}

func (e ErrAttestationRequired) Error() string {
	if e.Zone != "" {
		return fmt.Sprintf("attestation required for zone %s", e.Zone)
	}
	return "attestation is required for this zone"
}

// ErrAttestationExpired is returned when the attestation token has expired.
type ErrAttestationExpired struct {
	DeviceID  string
	ExpiredAt string
}

func (e ErrAttestationExpired) Error() string {
	if e.DeviceID != "" {
		return fmt.Sprintf("attestation token for device %s expired at %s", e.DeviceID, e.ExpiredAt)
	}
	return "attestation token has expired"
}

// ErrAttestationTooOld is returned when attestation evidence exceeds maximum age.
type ErrAttestationTooOld struct {
	Age    string
	MaxAge string
}

func (e ErrAttestationTooOld) Error() string {
	return fmt.Sprintf("attestation evidence age %s exceeds maximum %s", e.Age, e.MaxAge)
}

// ErrPCRMismatch is returned when PCR values do not match the required policy.
type ErrPCRMismatch struct {
	Policy   string
	Expected string
	Actual   string
}

func (e ErrPCRMismatch) Error() string {
	if e.Policy != "" {
		return fmt.Sprintf("PCR values do not match policy %s", e.Policy)
	}
	return "PCR values do not match the required policy"
}

// ErrEKNotAuthorized is returned when the endorsement key certificate is not authorized.
type ErrEKNotAuthorized struct {
	EKFingerprint string
	Reason        string
}

func (e ErrEKNotAuthorized) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("endorsement key %s not authorized: %s", e.EKFingerprint, e.Reason)
	}
	if e.EKFingerprint != "" {
		return fmt.Sprintf("endorsement key %s is not authorized", e.EKFingerprint)
	}
	return "endorsement key certificate is not authorized"
}

// ErrOperationNotAllowed is returned when the operation is not permitted by the token.
type ErrOperationNotAllowed struct {
	Operation         string
	AllowedOperations []string
}

func (e ErrOperationNotAllowed) Error() string {
	if e.Operation != "" && len(e.AllowedOperations) > 0 {
		return fmt.Sprintf("operation %s not allowed, permitted: %v", e.Operation, e.AllowedOperations)
	}
	if e.Operation != "" {
		return fmt.Sprintf("operation %s not allowed by attestation token", e.Operation)
	}
	return "operation not allowed by attestation token"
}

// ErrZoneNotAllowed is returned when the zone is not permitted by the token.
type ErrZoneNotAllowed struct {
	Zone         string
	AllowedZones []string
}

func (e ErrZoneNotAllowed) Error() string {
	if e.Zone != "" && len(e.AllowedZones) > 0 {
		return fmt.Sprintf("zone %s not allowed, permitted: %v", e.Zone, e.AllowedZones)
	}
	if e.Zone != "" {
		return fmt.Sprintf("zone %s not allowed by attestation token", e.Zone)
	}
	return "zone not allowed by attestation token"
}

// ErrInvalidToken is returned when the attestation token is invalid.
type ErrInvalidToken struct {
	Reason string
	Err    error
}

func (e ErrInvalidToken) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("invalid attestation token: %s: %v", e.Reason, e.Err)
	}
	if e.Reason != "" {
		return fmt.Sprintf("invalid attestation token: %s", e.Reason)
	}
	return "invalid attestation token"
}

func (e ErrInvalidToken) Unwrap() error {
	return e.Err
}

// ErrServiceUnavailable is returned when the attestation service is unavailable.
type ErrServiceUnavailable struct {
	Reason string
	Err    error
}

func (e ErrServiceUnavailable) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("attestation service unavailable: %s: %v", e.Reason, e.Err)
	}
	if e.Reason != "" {
		return fmt.Sprintf("attestation service unavailable: %s", e.Reason)
	}
	return "attestation service is unavailable"
}

func (e ErrServiceUnavailable) Unwrap() error {
	return e.Err
}

// ErrInvalidConfig is returned when the attestation configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid attestation config: field %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("invalid attestation config: %s", e.Reason)
}

// ErrVerificationFailed is returned when attestation verification fails.
type ErrVerificationFailed struct {
	Step   string
	Reason string
	Err    error
}

func (e ErrVerificationFailed) Error() string {
	msg := "attestation verification failed"
	if e.Step != "" {
		msg = fmt.Sprintf("%s at step %s", msg, e.Step)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e ErrVerificationFailed) Unwrap() error {
	return e.Err
}
