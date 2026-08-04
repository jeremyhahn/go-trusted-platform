//go:build gcpcompute

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

package gcp

import "errors"

var (
	// ErrShieldedVMUnsupported is returned when the launch configuration would
	// not yield a vTPM-backed Shielded VM (e.g. the source image or machine
	// type cannot enable the vTPM).
	ErrShieldedVMUnsupported = errors.New("gcp compute: configuration does not yield a Shielded VM vTPM")

	// ErrCapabilityNotSupported is returned for orchestrator operations that
	// have no honest Google Compute Engine equivalent (e.g. 802.1X OVS port
	// activation, hot NIC attach/detach, or control-plane PCR-quote
	// verification which requires the in-guest attestation agent).
	ErrCapabilityNotSupported = errors.New("gcp compute: capability not supported by the GCE control plane")

	// ErrWaitTimeout is returned when an instance or disk does not reach the
	// expected state before the configured deadline.
	ErrWaitTimeout = errors.New("gcp compute: timed out waiting for target state")

	// ErrEndorsementKey is returned when the Shielded VM endorsement key cannot
	// be retrieved or parsed.
	ErrEndorsementKey = errors.New("gcp compute: failed to obtain Shielded VM endorsement key")
)

// ConfigError is a typed error describing an invalid GCP provider
// configuration.
type ConfigError struct {
	// Msg describes the configuration problem.
	Msg string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "gcp compute: invalid configuration: " + e.Msg
}

// APIError wraps an underlying Google Compute Engine SDK error with the
// operation that failed, preserving errors.Is/As matching through Unwrap.
type APIError struct {
	// Op is the GCE operation that failed (e.g. "InsertInstance").
	Op string

	// Err is the underlying SDK error.
	Err error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return "gcp compute: GCE " + e.Op + " failed: " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *APIError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel so
// errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	// Sentinel is the package sentinel error.
	Sentinel error

	// Cause is the underlying cause.
	Cause error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
