// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vici

import (
	"errors"
	"strconv"
)

var (
	// ErrClosed is returned by an operation on a closed Conn.
	ErrClosed = errors.New("vici: connection closed")
	// ErrUnknownCommand is returned when charon does not know the command
	// (CMD_UNKNOWN) — the plugin is older than the caller expects.
	ErrUnknownCommand = errors.New("vici: unknown command")
	// ErrUnknownEvent is returned when charon does not know an event a
	// caller registered for (EVENT_UNKNOWN).
	ErrUnknownEvent = errors.New("vici: unknown event")
	// ErrMessageTooLarge is returned when a packet exceeds the protocol's
	// 512 KiB limit, in either direction.
	ErrMessageTooLarge = errors.New("vici: packet exceeds " + strconv.Itoa(MaxPacketSize) + " bytes")
	// ErrUnexpectedPacket is returned when charon sends a packet type the
	// exchange in progress does not allow.
	ErrUnexpectedPacket = errors.New("vici: unexpected packet")
	// ErrEmptyName is returned when a command or event name is empty.
	ErrEmptyName = errors.New("vici: command or event name is empty")
)

// EncodeError reports a message that cannot be encoded.
type EncodeError struct {
	// Key is the dotted path of the offending element.
	Key string
	// Reason says which limit it broke.
	Reason string
}

// Error implements the error interface.
func (e *EncodeError) Error() string {
	return "vici: encode " + e.Key + ": " + e.Reason
}

// DecodeError reports a malformed message received from charon.
type DecodeError struct {
	// Offset is the byte offset in the message payload.
	Offset int
	// Reason describes the defect.
	Reason string
}

// Error implements the error interface.
func (e *DecodeError) Error() string {
	return "vici: decode at offset " + strconv.Itoa(e.Offset) + ": " + e.Reason
}

// CommandError is a command charon executed and refused: its response
// carried success=no. Most commands report it this way; the caller
// receives the response as well so command-specific fields stay readable.
type CommandError struct {
	// Command is the command name.
	Command string
	// Message is charon's errmsg, which may be empty.
	Message string
}

// Error implements the error interface.
func (e *CommandError) Error() string {
	if e.Message == "" {
		return "vici: " + e.Command + " failed"
	}
	return "vici: " + e.Command + " failed: " + e.Message
}

// OpError is a transport failure during an operation.
type OpError struct {
	// Op is the operation ("dial", "write", "read", plus the command or
	// event name where one is in flight).
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *OpError) Error() string {
	return "vici: " + e.Op + ": " + e.Err.Error()
}

// Unwrap implements errors.Unwrap.
func (e *OpError) Unwrap() error { return e.Err }
