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

package common

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	// ErrNilClient indicates that a nil client was provided.
	ErrNilClient = errors.New("client cannot be nil")

	// ErrNilConnection indicates that the connection is nil.
	ErrNilConnection = errors.New("connection is nil")

	// ErrNotFound indicates that a resource was not found.
	ErrNotFound = errors.New("resource not found")

	// ErrAlreadyExists indicates that a resource already exists.
	ErrAlreadyExists = errors.New("resource already exists")

	// ErrInvalidArgument indicates that an invalid argument was provided.
	ErrInvalidArgument = errors.New("invalid argument")

	// ErrPermissionDenied indicates that permission was denied.
	ErrPermissionDenied = errors.New("permission denied")
)

// ErrOperationFailed is returned when a service operation fails.
type ErrOperationFailed struct {
	Service   string
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("%s.%s failed: %v", e.Service, e.Operation, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrResourceNotFound is returned when a specific resource is not found.
type ErrResourceNotFound struct {
	Resource string
	ID       string
}

// Error implements the error interface.
func (e ErrResourceNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("%s not found: %s", e.Resource, e.ID)
	}
	return fmt.Sprintf("%s not found", e.Resource)
}

// ErrValidation is returned when validation fails.
type ErrValidation struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e ErrValidation) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation failed: %s", e.Message)
}
