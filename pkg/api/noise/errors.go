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

// Package noise wraps the go-truststrap Noise_NK bootstrap server as a
// platform protocol listener for secure CA bundle distribution.
package noise

import "fmt"

// ErrServerNotStarted is returned when an operation is attempted on a server
// that has not been started.
type ErrServerNotStarted struct{}

// Error returns the error message.
func (e *ErrServerNotStarted) Error() string {
	return "noise: server not started"
}

// ErrServerAlreadyStarted is returned when Start is called on a server that
// is already running.
type ErrServerAlreadyStarted struct{}

// Error returns the error message.
func (e *ErrServerAlreadyStarted) Error() string {
	return "noise: server already started"
}

// ErrServerStartFailed is returned when the server fails to start.
type ErrServerStartFailed struct {
	Cause error
}

// Error returns the error message including the underlying cause.
func (e *ErrServerStartFailed) Error() string {
	return fmt.Sprintf("noise: server start failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrServerStartFailed) Unwrap() error {
	return e.Cause
}

// ErrServerStopFailed is returned when the server fails to stop gracefully.
type ErrServerStopFailed struct {
	Cause error
}

// Error returns the error message including the underlying cause.
func (e *ErrServerStopFailed) Error() string {
	return fmt.Sprintf("noise: server stop failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrServerStopFailed) Unwrap() error {
	return e.Cause
}

// ErrNilConfig is returned when a nil configuration is provided.
type ErrNilConfig struct{}

// Error returns the error message.
func (e *ErrNilConfig) Error() string {
	return "noise: configuration is nil"
}

// ErrNilBundleProvider is returned when a nil BundleProvider is provided.
type ErrNilBundleProvider struct{}

// Error returns the error message.
func (e *ErrNilBundleProvider) Error() string {
	return "noise: bundle provider is nil"
}

// ErrNilLogger is returned when a nil logger is provided.
type ErrNilLogger struct{}

// Error returns the error message.
func (e *ErrNilLogger) Error() string {
	return "noise: logger is nil"
}

// ErrKeyGenerationFailed is returned when Noise static key generation fails.
type ErrKeyGenerationFailed struct {
	Cause error
}

// Error returns the error message including the underlying cause.
func (e *ErrKeyGenerationFailed) Error() string {
	return fmt.Sprintf("noise: key generation failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrKeyGenerationFailed) Unwrap() error {
	return e.Cause
}
