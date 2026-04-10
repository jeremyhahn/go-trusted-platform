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

package netlink

import "fmt"

// Error types
type ErrorType string

const (
	ErrorTypeInvalidName   ErrorType = "invalid_name"
	ErrorTypeNotFound      ErrorType = "not_found"
	ErrorTypeAlreadyExists ErrorType = "already_exists"
	ErrorTypeCreateFailed  ErrorType = "create_failed"
	ErrorTypeDeleteFailed  ErrorType = "delete_failed"
	ErrorTypeSetupFailed   ErrorType = "setup_failed"
	ErrorTypeStateFailed   ErrorType = "state_failed"
	ErrorTypePermission    ErrorType = "permission"
)

// NetlinkError wraps errors with additional context
type NetlinkError struct {
	Type    ErrorType
	Message string
	Cause   error
}

func (e *NetlinkError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *NetlinkError) Unwrap() error {
	return e.Cause
}

// Error constructors
func ErrInvalidName(name string) error {
	return &NetlinkError{
		Type:    ErrorTypeInvalidName,
		Message: fmt.Sprintf("invalid interface name: %s", name),
	}
}

func ErrNotFound(name string) error {
	return &NetlinkError{
		Type:    ErrorTypeNotFound,
		Message: fmt.Sprintf("interface not found: %s", name),
	}
}

func ErrAlreadyExists(name string) error {
	return &NetlinkError{
		Type:    ErrorTypeAlreadyExists,
		Message: fmt.Sprintf("interface already exists: %s", name),
	}
}

func ErrCreateFailed(name string, cause error) error {
	return &NetlinkError{
		Type:    ErrorTypeCreateFailed,
		Message: fmt.Sprintf("failed to create interface: %s", name),
		Cause:   cause,
	}
}

func ErrDeleteFailed(name string, cause error) error {
	return &NetlinkError{
		Type:    ErrorTypeDeleteFailed,
		Message: fmt.Sprintf("failed to delete interface: %s", name),
		Cause:   cause,
	}
}

func ErrSetupFailed(name string, message string, cause error) error {
	return &NetlinkError{
		Type:    ErrorTypeSetupFailed,
		Message: fmt.Sprintf("failed to setup interface %s: %s", name, message),
		Cause:   cause,
	}
}

func ErrStateFailed(name string, state string, cause error) error {
	return &NetlinkError{
		Type:    ErrorTypeStateFailed,
		Message: fmt.Sprintf("failed to set interface %s to %s", name, state),
		Cause:   cause,
	}
}

func ErrPermission(operation string, cause error) error {
	return &NetlinkError{
		Type:    ErrorTypePermission,
		Message: fmt.Sprintf("permission denied for operation: %s (requires CAP_NET_ADMIN)", operation),
		Cause:   cause,
	}
}
