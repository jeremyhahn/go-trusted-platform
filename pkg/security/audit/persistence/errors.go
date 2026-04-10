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

package persistence

import "fmt"

// ErrStorageClosed is returned when operations are attempted on a closed persister.
type ErrStorageClosed struct{}

func (e ErrStorageClosed) Error() string {
	return "audit persister is closed"
}

// ErrStorageNotStarted is returned when operations are attempted before start.
type ErrStorageNotStarted struct{}

func (e ErrStorageNotStarted) Error() string {
	return "audit persister not started"
}

// ErrSerializationFailed is returned when audit event serialization fails.
type ErrSerializationFailed struct {
	EventID string
	Cause   error
}

func (e ErrSerializationFailed) Error() string {
	return fmt.Sprintf("audit event serialization failed: id=%s: %v", e.EventID, e.Cause)
}

func (e ErrSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeserializationFailed is returned when audit event deserialization fails.
type ErrDeserializationFailed struct {
	Cause error
}

func (e ErrDeserializationFailed) Error() string {
	return fmt.Sprintf("audit event deserialization failed: %v", e.Cause)
}

func (e ErrDeserializationFailed) Unwrap() error {
	return e.Cause
}

// ErrPutFailed is returned when storing an audit event fails.
type ErrPutFailed struct {
	EventID string
	Cause   error
}

func (e ErrPutFailed) Error() string {
	return fmt.Sprintf("failed to store audit event: id=%s: %v", e.EventID, e.Cause)
}

func (e ErrPutFailed) Unwrap() error {
	return e.Cause
}

// ErrQueryFailed is returned when querying audit events fails.
type ErrQueryFailed struct {
	Reason string
	Cause  error
}

func (e ErrQueryFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("audit query failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("audit query failed: %s", e.Reason)
}

func (e ErrQueryFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig is returned when persister configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid audit persister config: %s: %s", e.Field, e.Reason)
}

// ErrNilStorage is returned when a nil storage is provided.
type ErrNilStorage struct{}

func (e ErrNilStorage) Error() string {
	return "storage cannot be nil"
}

// ErrNilSDKClient is returned when a nil SDK client is provided.
type ErrNilSDKClient struct{}

func (e ErrNilSDKClient) Error() string {
	return "quicbaas SDK client cannot be nil"
}
