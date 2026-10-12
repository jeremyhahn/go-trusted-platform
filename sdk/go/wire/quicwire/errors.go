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

package quicwire

import (
	"errors"
	"fmt"
)

var (
	ErrClientClosed     = errors.New("client is closed")
	ErrConnectionFailed = errors.New("connection failed")
	ErrStreamFailed     = errors.New("stream operation failed")
	ErrPayloadTooLarge  = errors.New("payload exceeds maximum size")
	ErrTokenTooLarge    = errors.New("token exceeds maximum size")
	ErrNilRequest       = errors.New("request cannot be nil")
	ErrNilResponse      = errors.New("response cannot be nil")
)

// ErrInvalidConfig represents a configuration validation error
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s: %s", e.Field, e.Reason)
}

// ErrProtocol represents a protocol-level error
type ErrProtocol struct {
	Status  byte
	Message string
}

func (e ErrProtocol) Error() string {
	return fmt.Sprintf("protocol error (status 0x%02X): %s", e.Status, e.Message)
}

// StatusError returns an error for a given status code
func StatusError(status byte, message string) error {
	if status == StatusOK {
		return nil
	}
	return &ErrProtocol{
		Status:  status,
		Message: message,
	}
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
