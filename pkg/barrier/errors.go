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

package barrier

import "errors"

var (
	// ErrNotInitialized indicates the barrier has not been initialized.
	ErrNotInitialized = errors.New("barrier: not initialized")

	// ErrAlreadyInitialized indicates the barrier has already been initialized.
	ErrAlreadyInitialized = errors.New("barrier: already initialized")

	// ErrSealed indicates the barrier is sealed and operations cannot proceed.
	ErrSealed = errors.New("barrier: sealed")

	// ErrNotSealed indicates the barrier is not sealed when a seal was expected.
	ErrNotSealed = errors.New("barrier: not sealed")

	// ErrNilSDKClient indicates a nil SDK client was provided.
	ErrNilSDKClient = errors.New("barrier: nil SDK client")

	// ErrNilConfig indicates a nil configuration was provided.
	ErrNilConfig = errors.New("barrier: nil config")

	// ErrNilContext indicates a nil context was provided.
	ErrNilContext = errors.New("barrier: nil context")

	// ErrEmptySecret indicates an empty secret was provided.
	ErrEmptySecret = errors.New("barrier: empty secret")

	// ErrEmptyShare indicates an empty share was provided.
	ErrEmptyShare = errors.New("barrier: empty share")

	// ErrInvalidThreshold indicates an invalid threshold value.
	ErrInvalidThreshold = errors.New("barrier: invalid threshold")

	// ErrCeremonyNotSupported indicates the barrier strategy does not use a ceremony.
	ErrCeremonyNotSupported = errors.New("barrier: ceremony not supported for this seal strategy")

	// ErrEmptyUsername indicates an empty username was provided.
	ErrEmptyUsername = errors.New("barrier: empty username")

	// ErrEmptyCSR indicates an empty certificate signing request was provided.
	ErrEmptyCSR = errors.New("barrier: empty certificate signing request")

	// ErrEmptyNonce indicates an empty nonce was provided.
	ErrEmptyNonce = errors.New("barrier: empty nonce")

	// ErrEmptySignature indicates an empty signature was provided.
	ErrEmptySignature = errors.New("barrier: empty signature")
)

// ManagerError wraps barrier manager operation failures.
type ManagerError struct {
	Op  string
	Err error
}

// Error returns the formatted error string.
func (e *ManagerError) Error() string {
	return "barrier: " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the wrapped error.
func (e *ManagerError) Unwrap() error { return e.Err }

// ConfigError represents a barrier configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

// Error returns the formatted configuration error string.
func (e *ConfigError) Error() string {
	return "barrier: config: " + e.Field + ": " + e.Message
}
