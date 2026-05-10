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

// Package switchcmd provides CLI commands for physical switch management.
package switchcmd

import "fmt"

// ErrSwitchNameRequired is returned when the --switch flag is not provided.
type ErrSwitchNameRequired struct{}

func (e ErrSwitchNameRequired) Error() string {
	return "switch: --switch is required"
}

// ErrPortNameRequired is returned when the --port flag is not provided.
type ErrPortNameRequired struct{}

func (e ErrPortNameRequired) Error() string {
	return "switch: --port is required"
}

// ErrVLANIDRequired is returned when the --vlan flag is not provided.
type ErrVLANIDRequired struct{}

func (e ErrVLANIDRequired) Error() string {
	return "switch: --vlan is required"
}

// ErrInvalidVLANID is returned when the VLAN ID is out of range.
type ErrInvalidVLANID struct {
	Value int
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("switch: invalid --vlan %d (must be 1-4094)", e.Value)
}

// ErrServerURLRequired is returned when the --server-url flag is not provided.
type ErrServerURLRequired struct{}

func (e ErrServerURLRequired) Error() string {
	return "switch: --server-url is required"
}

// ErrOperationFailed is returned when a switch operation fails.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrOperationFailed) Error() string {
	return fmt.Sprintf("switch: %s failed: %v", e.Operation, e.Cause)
}

func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrClientCreateFailed is returned when the switch SDK client cannot be created.
type ErrClientCreateFailed struct {
	Cause error
}

func (e ErrClientCreateFailed) Error() string {
	return fmt.Sprintf("switch: failed to create client: %v", e.Cause)
}

func (e ErrClientCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrContextResolveFailed is returned when the CLI context cannot be resolved.
type ErrContextResolveFailed struct {
	Cause error
}

func (e ErrContextResolveFailed) Error() string {
	return fmt.Sprintf("switch: failed to resolve context: %v", e.Cause)
}

func (e ErrContextResolveFailed) Unwrap() error {
	return e.Cause
}

// ErrTLSConfigFailed is returned when building TLS configuration fails.
type ErrTLSConfigFailed struct {
	Cause error
}

func (e ErrTLSConfigFailed) Error() string {
	return fmt.Sprintf("switch: failed to build TLS config: %v", e.Cause)
}

func (e ErrTLSConfigFailed) Unwrap() error {
	return e.Cause
}
