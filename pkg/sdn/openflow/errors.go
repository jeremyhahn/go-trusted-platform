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

package openflow

import "errors"

var (
	// ErrNotConnected indicates the client is not connected
	ErrNotConnected = errors.New("not connected to OpenFlow switch")

	// ErrConnectionFailed indicates a connection failure
	ErrConnectionFailed = errors.New("failed to connect to OpenFlow switch")

	// ErrConnectionClosed indicates the connection was closed
	ErrConnectionClosed = errors.New("connection closed")

	// ErrVersionMismatch indicates an OpenFlow version mismatch
	ErrVersionMismatch = errors.New("OpenFlow version mismatch")

	// ErrInvalidMessage indicates an invalid message was received
	ErrInvalidMessage = errors.New("invalid OpenFlow message")

	// ErrMessageTooShort indicates a message is too short
	ErrMessageTooShort = errors.New("message too short")

	// ErrMessageTooLong indicates a message exceeds the maximum size
	ErrMessageTooLong = errors.New("message too long")

	// ErrTimeout indicates an operation timed out
	ErrTimeout = errors.New("operation timed out")

	// ErrFlowModFailed indicates a flow modification failed
	ErrFlowModFailed = errors.New("flow modification failed")

	// ErrInvalidMatch indicates an invalid match specification
	ErrInvalidMatch = errors.New("invalid match specification")

	// ErrInvalidAction indicates an invalid action specification
	ErrInvalidAction = errors.New("invalid action specification")

	// ErrBadRequest indicates the switch rejected the request
	ErrBadRequest = errors.New("bad request")

	// ErrNoFeatures indicates features were not received
	ErrNoFeatures = errors.New("features not received")

	// ErrInvalidBridgeName indicates an invalid bridge name
	ErrInvalidBridgeName = errors.New("invalid bridge name")

	// ErrSocketPath indicates a socket path error
	ErrSocketPath = errors.New("invalid socket path")
)

// OFError represents an OpenFlow error message
type OFError struct {
	Type uint16 // Error type
	Code uint16 // Error code
	Data []byte // Variable-length data
}

// Error implements the error interface
func (e *OFError) Error() string {
	return formatOFError(e.Type, e.Code)
}

// formatOFError returns a human-readable error description
func formatOFError(errType, errCode uint16) string {
	switch errType {
	case OFPETHelloFailed:
		return formatHelloFailedError(errCode)
	case OFPETBadRequest:
		return formatBadRequestError(errCode)
	case OFPETBadAction:
		return formatBadActionError(errCode)
	case OFPETBadInstruction:
		return formatBadInstructionError(errCode)
	case OFPETBadMatch:
		return formatBadMatchError(errCode)
	case OFPETFlowModFailed:
		return formatFlowModFailedError(errCode)
	default:
		return "unknown OpenFlow error"
	}
}

func formatHelloFailedError(code uint16) string {
	switch code {
	case 0:
		return "hello failed: incompatible version"
	case 1:
		return "hello failed: permissions error"
	default:
		return "hello failed: unknown error"
	}
}

func formatBadRequestError(code uint16) string {
	switch code {
	case 0:
		return "bad request: bad version"
	case 1:
		return "bad request: bad type"
	case 2:
		return "bad request: bad multipart"
	case 3:
		return "bad request: bad experimenter"
	case 4:
		return "bad request: bad experimenter type"
	case 5:
		return "bad request: permissions error"
	case 6:
		return "bad request: bad length"
	case 7:
		return "bad request: buffer empty"
	case 8:
		return "bad request: buffer unknown"
	case 9:
		return "bad request: bad table id"
	case 10:
		return "bad request: is slave"
	case 11:
		return "bad request: bad port"
	case 12:
		return "bad request: bad packet"
	case 13:
		return "bad request: multipart buffer overflow"
	default:
		return "bad request: unknown error"
	}
}

func formatBadActionError(code uint16) string {
	switch code {
	case 0:
		return "bad action: bad type"
	case 1:
		return "bad action: bad length"
	case 2:
		return "bad action: bad experimenter"
	case 3:
		return "bad action: bad experimenter type"
	case 4:
		return "bad action: bad output port"
	case 5:
		return "bad action: bad argument"
	case 6:
		return "bad action: permissions error"
	case 7:
		return "bad action: too many"
	case 8:
		return "bad action: bad queue"
	case 9:
		return "bad action: bad output group"
	case 10:
		return "bad action: match inconsistent"
	case 11:
		return "bad action: unsupported order"
	case 12:
		return "bad action: bad tag"
	case 13:
		return "bad action: bad set type"
	case 14:
		return "bad action: bad set length"
	case 15:
		return "bad action: bad set argument"
	default:
		return "bad action: unknown error"
	}
}

func formatBadInstructionError(code uint16) string {
	switch code {
	case 0:
		return "bad instruction: unknown instruction"
	case 1:
		return "bad instruction: unsupported instruction"
	case 2:
		return "bad instruction: bad table id"
	case 3:
		return "bad instruction: unsupported metadata"
	case 4:
		return "bad instruction: unsupported metadata mask"
	case 5:
		return "bad instruction: bad experimenter"
	case 6:
		return "bad instruction: bad experimenter type"
	case 7:
		return "bad instruction: bad length"
	case 8:
		return "bad instruction: permissions error"
	default:
		return "bad instruction: unknown error"
	}
}

func formatBadMatchError(code uint16) string {
	switch code {
	case 0:
		return "bad match: bad type"
	case 1:
		return "bad match: bad length"
	case 2:
		return "bad match: bad tag"
	case 3:
		return "bad match: bad dl addr mask"
	case 4:
		return "bad match: bad nw addr mask"
	case 5:
		return "bad match: bad wildcards"
	case 6:
		return "bad match: bad field"
	case 7:
		return "bad match: bad value"
	case 8:
		return "bad match: bad mask"
	case 9:
		return "bad match: bad prereq"
	case 10:
		return "bad match: dup field"
	case 11:
		return "bad match: permissions error"
	default:
		return "bad match: unknown error"
	}
}

func formatFlowModFailedError(code uint16) string {
	switch code {
	case 0:
		return "flow mod failed: unknown"
	case 1:
		return "flow mod failed: table full"
	case 2:
		return "flow mod failed: bad table id"
	case 3:
		return "flow mod failed: overlap"
	case 4:
		return "flow mod failed: permissions error"
	case 5:
		return "flow mod failed: bad timeout"
	case 6:
		return "flow mod failed: bad command"
	case 7:
		return "flow mod failed: bad flags"
	default:
		return "flow mod failed: unknown error"
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

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
