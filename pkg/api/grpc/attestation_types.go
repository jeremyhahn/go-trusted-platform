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

package grpc

import "time"

// =============================================================================
// Attestation Error Types
// =============================================================================

// ErrAttestationOperationFailed is returned when an attestation operation fails.
type ErrAttestationOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrAttestationOperationFailed) Error() string {
	if e.Cause != nil {
		return "attestation operation " + e.Operation + " failed: " + e.Cause.Error()
	}
	return "attestation operation " + e.Operation + " failed"
}

func (e ErrAttestationOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrAttestationInvalidRequest is returned when an invalid attestation request is made.
type ErrAttestationInvalidRequest struct {
	Reason string
}

func (e ErrAttestationInvalidRequest) Error() string {
	return "invalid attestation request: " + e.Reason
}

// ErrAttestationServiceUnavailable is returned when the attestation service is unavailable.
type ErrAttestationServiceUnavailable struct{}

func (e ErrAttestationServiceUnavailable) Error() string {
	return "attestation service is unavailable"
}

// =============================================================================
// Attestation Result Types
// =============================================================================

// AttestationDeviceResult contains the result of a device attestation.
type AttestationDeviceResult struct {
	DeviceID  string
	QuoteData []byte
	Signature []byte
	PCRs      map[int][]byte
	Nonce     []byte
	Timestamp time.Time
}

// AttestationReport represents an attestation report.
type AttestationReport struct {
	ID            string
	HostID        string
	DeviceID      string
	Status        string
	CreatedAt     time.Time
	VerifiedAt    time.Time
	ExpiresAt     time.Time
	ManifestID    string
	QuoteHash     []byte
	SignatureHash []byte
	Valid         bool
	Errors        []string
}

// AttestationReportFilter contains filters for listing attestation reports.
type AttestationReportFilter struct {
	HostID   string
	DeviceID string
	Status   string
	Limit    int
	Offset   int
}
