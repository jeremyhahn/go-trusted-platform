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

package audit

import "fmt"

// ErrAuditLogFailed is returned when writing an audit log entry fails
type ErrAuditLogFailed struct {
	Reason string
	Err    error
}

func (e ErrAuditLogFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("audit log failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("audit log failed: %s", e.Reason)
}

func (e ErrAuditLogFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidEvent is returned when an audit event is invalid
type ErrInvalidEvent struct {
	Field  string
	Reason string
}

func (e ErrInvalidEvent) Error() string {
	return fmt.Sprintf("invalid audit event: field %s: %s", e.Field, e.Reason)
}

// ErrQueryFailed is returned when an audit query fails
type ErrQueryFailed struct {
	Reason string
	Err    error
}

func (e ErrQueryFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("audit query failed: %s: %v", e.Reason, e.Err)
	}
	return fmt.Sprintf("audit query failed: %s", e.Reason)
}

func (e ErrQueryFailed) Unwrap() error {
	return e.Err
}

// ErrLoggerClosed is returned when operations are attempted on a closed logger
type ErrLoggerClosed struct{}

func (e ErrLoggerClosed) Error() string {
	return "audit logger has been closed"
}

// ErrBufferFull is returned when the async buffer is full
type ErrBufferFull struct {
	Size int
}

func (e ErrBufferFull) Error() string {
	return fmt.Sprintf("audit buffer full, size: %d", e.Size)
}

// ErrPersistenceFailed is returned when persisting audit events fails
type ErrPersistenceFailed struct {
	EventID string
	Err     error
}

func (e ErrPersistenceFailed) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("audit persistence failed for event %s: %v", e.EventID, e.Err)
	}
	return fmt.Sprintf("audit persistence failed for event %s", e.EventID)
}

func (e ErrPersistenceFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidFilter is returned when an audit filter is invalid
type ErrInvalidFilter struct {
	Field  string
	Reason string
}

func (e ErrInvalidFilter) Error() string {
	return fmt.Sprintf("invalid audit filter: field %s: %s", e.Field, e.Reason)
}

// ErrContextCanceled is returned when an operation is canceled via context
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	return fmt.Sprintf("audit operation canceled: %s", e.Operation)
}

// ErrInvalidConfig is returned when the logger configuration is invalid
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid audit config: field %s: %s", e.Field, e.Reason)
}
