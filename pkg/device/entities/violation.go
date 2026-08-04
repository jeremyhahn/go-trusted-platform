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
	"fmt"
	"time"
)

// ViolationSeverity classifies how serious a device violation is. Severity
// drives the lifecycle branch: severe (or cert revocation) → port blocked
// + DeviceStateSuspended; non-severe → quarantine zone + DeviceStateQuarantined.
type ViolationSeverity string

const (
	// ViolationSeverityWarning indicates a non-critical compliance failure.
	// The device is moved to the quarantine zone for remediation; network
	// access is restricted but the port remains admin-up.
	ViolationSeverityWarning ViolationSeverity = "warning"

	// ViolationSeveritySevere indicates a critical security failure (e.g. PCR
	// mismatch, active revocation, hardware tampering). The port is set
	// admin-down and the device is suspended.
	ViolationSeveritySevere ViolationSeverity = "severe"
)

// IsValid reports whether the severity value is a recognised constant.
func (s ViolationSeverity) IsValid() bool {
	return s == ViolationSeverityWarning || s == ViolationSeveritySevere
}

// String returns the string representation of ViolationSeverity.
func (s ViolationSeverity) String() string {
	return string(s)
}

// ViolationSource identifies the subsystem that detected the violation.
// The type is intentionally open so future producers (vuln-scan,
// config-drift, CRL-push) can be added without changing consumers.
type ViolationSource string

const (
	// ViolationSourceAttestation indicates the violation was detected during
	// TPM attestation verification (PCR mismatch, quote replay, AK mismatch).
	ViolationSourceAttestation ViolationSource = "attestation"
)

// IsValid reports whether the source value is a recognised constant.
func (s ViolationSource) IsValid() bool {
	return s == ViolationSourceAttestation
}

// String returns the string representation of ViolationSource.
func (s ViolationSource) String() string {
	return string(s)
}

// ErrInvalidViolationSeverity is returned when an unrecognised severity value
// is supplied to a function that validates it.
type ErrInvalidViolationSeverity struct {
	Value ViolationSeverity
}

// Error implements the error interface.
func (e ErrInvalidViolationSeverity) Error() string {
	return fmt.Sprintf("device: invalid violation severity %q", e.Value)
}

// ErrInvalidViolationSource is returned when an unrecognised source value is
// supplied to a function that validates it.
type ErrInvalidViolationSource struct {
	Value ViolationSource
}

// Error implements the error interface.
func (e ErrInvalidViolationSource) Error() string {
	return fmt.Sprintf("device: invalid violation source %q", e.Value)
}

// ViolationEvent represents a single compliance violation detected for a device.
// It is emitted by the attestation verification path and consumed by the
// quarantine loop to drive port-level and device-level lifecycle transitions.
type ViolationEvent struct {
	// DeviceID is the unique identifier of the affected device.
	DeviceID uint64

	// Severity controls which lifecycle branch the consumer takes.
	Severity ViolationSeverity

	// Source identifies which subsystem detected the violation.
	Source ViolationSource

	// Detail is a human-readable description of the violation (e.g. PCR index
	// and expected vs. actual digest values).
	Detail string

	// OccurredAt is when the violation was detected.
	OccurredAt time.Time
}

// Validate returns an error if any required field is missing or invalid.
func (v *ViolationEvent) Validate() error {
	if v.DeviceID == 0 {
		return &MessageError{Msg: "device: violation event: device ID is required"}
	}
	if !v.Severity.IsValid() {
		return ErrInvalidViolationSeverity{Value: v.Severity}
	}
	if !v.Source.IsValid() {
		return ErrInvalidViolationSource{Value: v.Source}
	}
	if v.OccurredAt.IsZero() {
		return &MessageError{Msg: "device: violation event: occurred_at is required"}
	}
	return nil
}
