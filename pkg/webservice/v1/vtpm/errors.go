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

package vtpm

import "fmt"

// ErrMissingInstanceID is returned when instance ID is required but not provided.
type ErrMissingInstanceID struct{}

func (e ErrMissingInstanceID) Error() string {
	return "vtpm: instance ID is required"
}

// ErrMissingProfileID is returned when profile ID is required but not provided.
type ErrMissingProfileID struct{}

func (e ErrMissingProfileID) Error() string {
	return "vtpm: profile ID is required"
}

// ErrInvalidInstanceID is returned when instance ID format is invalid.
type ErrInvalidInstanceID struct {
	ID string
}

func (e ErrInvalidInstanceID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: invalid instance ID: %s", e.ID)
	}
	return "vtpm: invalid instance ID"
}

// ErrInvalidProfileID is returned when profile ID format is invalid.
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: invalid profile ID: %s", e.ID)
	}
	return "vtpm: invalid profile ID"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("vtpm: invalid request body: %s", e.Reason)
	}
	return "vtpm: invalid request body"
}

// ErrInvalidTPMVersion is returned when the TPM version is invalid.
type ErrInvalidTPMVersion struct {
	Version string
}

func (e ErrInvalidTPMVersion) Error() string {
	if e.Version != "" {
		return fmt.Sprintf("vtpm: invalid TPM version: %s", e.Version)
	}
	return "vtpm: invalid TPM version"
}

// ErrInvalidEKAlgorithm is returned when the EK algorithm is invalid.
type ErrInvalidEKAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidEKAlgorithm) Error() string {
	if e.Algorithm != "" {
		return fmt.Sprintf("vtpm: invalid EK algorithm: %s", e.Algorithm)
	}
	return "vtpm: invalid EK algorithm"
}

// ErrInstanceNotFound is returned when a vTPM instance is not found.
type ErrInstanceNotFound struct {
	ID string
}

func (e ErrInstanceNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: instance not found: %s", e.ID)
	}
	return "vtpm: instance not found"
}

// ErrProfileNotFound is returned when a device profile is not found.
type ErrProfileNotFound struct {
	ProfileID uint64
}

func (e ErrProfileNotFound) Error() string {
	if e.ProfileID != 0 {
		return fmt.Sprintf("vtpm: profile not found: %d", e.ProfileID)
	}
	return "vtpm: profile not found"
}

// ErrInstanceNotRunning is returned when the vTPM instance is not running.
type ErrInstanceNotRunning struct {
	ID string
}

func (e ErrInstanceNotRunning) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: instance not running: %s", e.ID)
	}
	return "vtpm: instance not running"
}

// ErrInstanceAlreadyRunning is returned when the vTPM instance is already running.
type ErrInstanceAlreadyRunning struct {
	ID string
}

func (e ErrInstanceAlreadyRunning) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: instance already running: %s", e.ID)
	}
	return "vtpm: instance already running"
}

// ErrServiceError is returned when a service operation fails.
type ErrServiceError struct {
	Operation string
	Cause     error
}

func (e ErrServiceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vtpm: %s failed: %s", e.Operation, e.Cause.Error())
	}
	return fmt.Sprintf("vtpm: %s failed", e.Operation)
}

func (e ErrServiceError) Unwrap() error {
	return e.Cause
}

// ErrMissingLogger is returned when logger is required but not provided.
type ErrMissingLogger struct{}

func (e ErrMissingLogger) Error() string {
	return "vtpm: logger is required"
}

// ErrMissingGeneratorService is returned when generator service is required but not provided.
type ErrMissingGeneratorService struct{}

func (e ErrMissingGeneratorService) Error() string {
	return "vtpm: generator service is required"
}

// ErrMissingResponseWriter is returned when response writer is required but not provided.
type ErrMissingResponseWriter struct{}

func (e ErrMissingResponseWriter) Error() string {
	return "vtpm: response writer is required"
}

// ErrEKCertNotAvailable is returned when EK certificate is not available.
type ErrEKCertNotAvailable struct {
	ID string
}

func (e ErrEKCertNotAvailable) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("vtpm: EK certificate not available for instance: %s", e.ID)
	}
	return "vtpm: EK certificate not available"
}
