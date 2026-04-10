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

//go:build integration

package stress

import "fmt"

// ErrInvalidDuration indicates the stress test duration is invalid.
var ErrInvalidDuration = &StressError{Code: "INVALID_DURATION", Message: "duration must be positive"}

// ErrInvalidConcurrency indicates the concurrency level is invalid.
var ErrInvalidConcurrency = &StressError{Code: "INVALID_CONCURRENCY", Message: "concurrency must be positive"}

// ErrInvalidRateLimit indicates the rate limit is invalid.
var ErrInvalidRateLimit = &StressError{Code: "INVALID_RATE_LIMIT", Message: "rate limit cannot be negative"}

// ErrRunnerAlreadyRunning indicates the runner is already executing a test.
var ErrRunnerAlreadyRunning = &StressError{Code: "ALREADY_RUNNING", Message: "stress runner is already running"}

// ErrRunnerStopped indicates the runner was stopped.
var ErrRunnerStopped = &StressError{Code: "RUNNER_STOPPED", Message: "stress runner was stopped"}

// ErrContextCancelled indicates the context was cancelled.
var ErrContextCancelled = &StressError{Code: "CONTEXT_CANCELLED", Message: "context was cancelled"}

// StressError represents a stress test error with a code and message.
type StressError struct {
	Code    string
	Message string
	Cause   error
}

// Error implements the error interface.
func (e *StressError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause.
func (e *StressError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target.
func (e *StressError) Is(target error) bool {
	if t, ok := target.(*StressError); ok {
		return e.Code == t.Code
	}
	return false
}

// WithCause returns a copy of the error with the given cause.
func (e *StressError) WithCause(cause error) *StressError {
	return &StressError{
		Code:    e.Code,
		Message: e.Message,
		Cause:   cause,
	}
}

// ErrOperationFailed represents a failed stress test operation.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e *ErrOperationFailed) Error() string {
	return fmt.Sprintf("operation %s failed: %v", e.Operation, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrThresholdExceeded indicates a performance threshold was exceeded.
type ErrThresholdExceeded struct {
	Metric    string
	Threshold float64
	Actual    float64
}

// Error implements the error interface.
func (e *ErrThresholdExceeded) Error() string {
	return fmt.Sprintf("threshold exceeded for %s: expected <= %.2f, got %.2f",
		e.Metric, e.Threshold, e.Actual)
}
