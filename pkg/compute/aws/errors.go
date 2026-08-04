//go:build awscompute

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

package aws

import "errors"

var (
	// ErrNitroTPMUnsupported is returned when the configured AMI is not
	// registered with TpmSupport=v2.0, so a launched instance would not
	// expose a NitroTPM 2.0 device to the guest.
	ErrNitroTPMUnsupported = errors.New("aws compute: AMI does not support NitroTPM 2.0 (TpmSupport=v2.0 required)")

	// ErrCapabilityNotSupported is returned for orchestrator operations that
	// have no honest AWS EC2 equivalent (e.g. 802.1X OVS port activation, or
	// control-plane PCR-quote verification which requires the in-guest
	// attestation agent).
	ErrCapabilityNotSupported = errors.New("aws compute: capability not supported by the AWS control plane")

	// ErrWaitTimeout is returned when an instance or volume does not reach the
	// expected state before the configured deadline.
	ErrWaitTimeout = errors.New("aws compute: timed out waiting for target state")

	// ErrEndorsementKey is returned when the NitroTPM endorsement key cannot
	// be retrieved or parsed.
	ErrEndorsementKey = errors.New("aws compute: failed to obtain NitroTPM endorsement key")
)

// ConfigError is a typed error describing an invalid AWS provider
// configuration.
type ConfigError struct {
	// Msg describes the configuration problem.
	Msg string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "aws compute: invalid configuration: " + e.Msg
}

// APIError wraps an underlying AWS SDK error with the operation that failed,
// preserving errors.Is/As matching through Unwrap.
type APIError struct {
	// Op is the EC2 operation that failed (e.g. "RunInstances").
	Op string

	// Err is the underlying SDK error.
	Err error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return "aws compute: EC2 " + e.Op + " failed: " + e.Err.Error()
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
