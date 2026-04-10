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

package push

import "fmt"

// ErrPushFailed indicates that pushing the manifest to a target failed.
type ErrPushFailed struct {
	TargetID string
	Endpoint string
	Reason   string
	Cause    error
}

func (e ErrPushFailed) Error() string {
	msg := "push: failed"
	if e.TargetID != "" {
		msg = fmt.Sprintf("%s for target %s", msg, e.TargetID)
	}
	if e.Endpoint != "" {
		msg = fmt.Sprintf("%s at %s", msg, e.Endpoint)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrPushFailed) Unwrap() error {
	return e.Cause
}

// ErrTargetUnreachable indicates that the push target cannot be reached.
type ErrTargetUnreachable struct {
	TargetID string
	Endpoint string
	Reason   string
	Cause    error
}

func (e ErrTargetUnreachable) Error() string {
	msg := "push: target unreachable"
	if e.TargetID != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.TargetID)
	}
	if e.Endpoint != "" {
		msg = fmt.Sprintf("%s at %s", msg, e.Endpoint)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrTargetUnreachable) Unwrap() error {
	return e.Cause
}

// ErrAuthFailed indicates that authentication with the target failed.
type ErrAuthFailed struct {
	TargetID string
	Endpoint string
	Reason   string
	Cause    error
}

func (e ErrAuthFailed) Error() string {
	msg := "push: authentication failed"
	if e.TargetID != "" {
		msg = fmt.Sprintf("%s for target %s", msg, e.TargetID)
	}
	if e.Endpoint != "" {
		msg = fmt.Sprintf("%s at %s", msg, e.Endpoint)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAuthFailed) Unwrap() error {
	return e.Cause
}

// ErrRetryExhausted indicates that all retry attempts have been exhausted.
type ErrRetryExhausted struct {
	TargetID    string
	Endpoint    string
	Attempts    int
	MaxAttempts int
	LastError   error
}

func (e ErrRetryExhausted) Error() string {
	msg := fmt.Sprintf("push: retry exhausted after %d/%d attempts", e.Attempts, e.MaxAttempts)
	if e.TargetID != "" {
		msg = fmt.Sprintf("%s for target %s", msg, e.TargetID)
	}
	if e.Endpoint != "" {
		msg = fmt.Sprintf("%s at %s", msg, e.Endpoint)
	}
	if e.LastError != nil {
		msg = fmt.Sprintf("%s: last error: %v", msg, e.LastError)
	}
	return msg
}

func (e ErrRetryExhausted) Unwrap() error {
	return e.LastError
}

// ErrInvalidTarget indicates that the push target configuration is invalid.
type ErrInvalidTarget struct {
	TargetID string
	Field    string
	Reason   string
}

func (e ErrInvalidTarget) Error() string {
	msg := "push: invalid target"
	if e.TargetID != "" {
		msg = fmt.Sprintf("%s %s", msg, e.TargetID)
	}
	if e.Field != "" {
		msg = fmt.Sprintf("%s: invalid field %s", msg, e.Field)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrInvalidConfig indicates invalid push configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("push: invalid config for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("push: invalid config: %s", e.Reason)
}

// ErrClientNotInitialized indicates that the push client has not been initialized.
type ErrClientNotInitialized struct{}

func (e ErrClientNotInitialized) Error() string {
	return "push: client not initialized"
}

// ErrClientClosed indicates that the push client has been closed.
type ErrClientClosed struct{}

func (e ErrClientClosed) Error() string {
	return "push: client closed"
}

// ErrSchedulerNotInitialized indicates that the scheduler has not been initialized.
type ErrSchedulerNotInitialized struct{}

func (e ErrSchedulerNotInitialized) Error() string {
	return "push: scheduler not initialized"
}

// ErrSchedulerStopped indicates that the scheduler has been stopped.
type ErrSchedulerStopped struct{}

func (e ErrSchedulerStopped) Error() string {
	return "push: scheduler stopped"
}

// ErrSchedulerAlreadyRunning indicates the scheduler is already running.
type ErrSchedulerAlreadyRunning struct{}

func (e ErrSchedulerAlreadyRunning) Error() string {
	return "push: scheduler already running"
}

// ErrContextCanceled indicates the operation was canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("push: %s canceled", e.Operation)
	}
	return "push: operation canceled"
}

// ErrNoTargetsConfigured indicates that no push targets are configured.
type ErrNoTargetsConfigured struct{}

func (e ErrNoTargetsConfigured) Error() string {
	return "push: no targets configured"
}

// ErrTargetNotFound indicates that the specified target was not found.
type ErrTargetNotFound struct {
	TargetID string
}

func (e ErrTargetNotFound) Error() string {
	if e.TargetID != "" {
		return fmt.Sprintf("push: target not found: %s", e.TargetID)
	}
	return "push: target not found"
}

// ErrSerializationFailed indicates that serializing the manifest failed.
type ErrSerializationFailed struct {
	Reason string
	Cause  error
}

func (e ErrSerializationFailed) Error() string {
	msg := "push: serialization failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrTransportNotSupported indicates the transport type is not supported.
type ErrTransportNotSupported struct {
	Transport string
}

func (e ErrTransportNotSupported) Error() string {
	if e.Transport != "" {
		return fmt.Sprintf("push: transport not supported: %s", e.Transport)
	}
	return "push: transport not supported"
}

// ErrTLSConfigFailed indicates that TLS configuration failed.
type ErrTLSConfigFailed struct {
	Reason string
	Cause  error
}

func (e ErrTLSConfigFailed) Error() string {
	msg := "push: TLS configuration failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrTLSConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidResponse indicates that the server response was invalid.
type ErrInvalidResponse struct {
	StatusCode int
	Body       string
	Reason     string
}

func (e ErrInvalidResponse) Error() string {
	msg := "push: invalid response"
	if e.StatusCode != 0 {
		msg = fmt.Sprintf("%s: status %d", msg, e.StatusCode)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Body != "" && len(e.Body) < 200 {
		msg = fmt.Sprintf("%s: %s", msg, e.Body)
	}
	return msg
}
