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

package qemu

import "fmt"

// ErrMonitorConnectionFailed is returned when the QMP socket connection fails.
type ErrMonitorConnectionFailed struct {
	SocketPath string
	Cause      error
}

func (e ErrMonitorConnectionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to connect to QMP socket %s: %v", e.SocketPath, e.Cause)
	}
	return fmt.Sprintf("failed to connect to QMP socket %s", e.SocketPath)
}

func (e ErrMonitorConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrMonitorNotConnected is returned when an operation is attempted
// on a monitor that is not connected.
type ErrMonitorNotConnected struct{}

func (e ErrMonitorNotConnected) Error() string {
	return "QMP monitor is not connected"
}

// ErrMonitorAlreadyConnected is returned when attempting to connect
// a monitor that is already connected.
type ErrMonitorAlreadyConnected struct{}

func (e ErrMonitorAlreadyConnected) Error() string {
	return "QMP monitor is already connected"
}

// ErrMonitorHandshakeFailed is returned when the QMP capabilities
// handshake fails.
type ErrMonitorHandshakeFailed struct {
	Cause error
}

func (e ErrMonitorHandshakeFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("QMP handshake failed: %v", e.Cause)
	}
	return "QMP handshake failed"
}

func (e ErrMonitorHandshakeFailed) Unwrap() error {
	return e.Cause
}

// ErrMonitorCommandFailed is returned when a QMP command execution fails.
type ErrMonitorCommandFailed struct {
	Command string
	Cause   error
}

func (e ErrMonitorCommandFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("QMP command %q failed: %v", e.Command, e.Cause)
	}
	return fmt.Sprintf("QMP command %q failed", e.Command)
}

func (e ErrMonitorCommandFailed) Unwrap() error {
	return e.Cause
}

// ErrMonitorTimeout is returned when a monitor operation times out.
type ErrMonitorTimeout struct {
	Operation string
}

func (e ErrMonitorTimeout) Error() string {
	return fmt.Sprintf("QMP monitor operation timed out: %s", e.Operation)
}

// ErrMonitorSocketNotFound is returned when the QMP socket does not exist.
type ErrMonitorSocketNotFound struct {
	SocketPath string
}

func (e ErrMonitorSocketNotFound) Error() string {
	return fmt.Sprintf("QMP socket not found: %s", e.SocketPath)
}

// ErrMonitorInvalidResponse is returned when the QMP response cannot be parsed.
type ErrMonitorInvalidResponse struct {
	Command string
	Cause   error
}

func (e ErrMonitorInvalidResponse) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("invalid QMP response for %q: %v", e.Command, e.Cause)
	}
	return fmt.Sprintf("invalid QMP response for %q", e.Command)
}

func (e ErrMonitorInvalidResponse) Unwrap() error {
	return e.Cause
}

// ErrMonitorEventsNotSupported is returned when event subscription is not
// supported by the QEMU instance.
type ErrMonitorEventsNotSupported struct{}

func (e ErrMonitorEventsNotSupported) Error() string {
	return "QMP event streaming is not supported by this QEMU instance"
}

// ErrMonitorDisconnected is returned when the monitor connection is
// unexpectedly closed.
type ErrMonitorDisconnected struct{}

func (e ErrMonitorDisconnected) Error() string {
	return "QMP monitor connection was closed"
}
