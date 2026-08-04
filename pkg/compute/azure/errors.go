//go:build azurecompute

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

package azure

import "errors"

var (
	// ErrTrustedLaunchUnsupported is returned when the launch configuration
	// would not yield a vTPM-backed Trusted Launch VM (e.g. the VM size or
	// image cannot enable the vTPM).
	ErrTrustedLaunchUnsupported = errors.New("azure compute: configuration does not yield a Trusted Launch vTPM")

	// ErrCapabilityNotSupported is returned for orchestrator operations that
	// have no honest Azure control-plane equivalent (e.g. 802.1X OVS port
	// activation, or vTPM endorsement-key / PCR-quote attestation, which on
	// Azure Trusted Launch is guest-driven through Microsoft Azure Attestation
	// rather than a control-plane API).
	ErrCapabilityNotSupported = errors.New("azure compute: capability not supported by the Azure control plane")

	// ErrWaitTimeout is returned when a VM does not reach the expected power
	// state before the configured deadline.
	ErrWaitTimeout = errors.New("azure compute: timed out waiting for target state")
)

// ConfigError is a typed error describing an invalid Azure provider
// configuration.
type ConfigError struct {
	// Msg describes the configuration problem.
	Msg string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return "azure compute: invalid configuration: " + e.Msg
}

// APIError wraps an underlying Azure SDK error with the operation that failed,
// preserving errors.Is/As matching through Unwrap.
type APIError struct {
	// Op is the Azure operation that failed (e.g. "CreateVM").
	Op string

	// Err is the underlying SDK error.
	Err error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return "azure compute: " + e.Op + " failed: " + e.Err.Error()
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
