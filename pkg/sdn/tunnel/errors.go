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

package tunnel

import "fmt"

// ErrTunnelCreateFailed is returned when tunnel creation fails.
type ErrTunnelCreateFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelCreateFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to create %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelNotFound is returned when a tunnel does not exist.
type ErrTunnelNotFound struct {
	Name string
}

// Error implements the error interface.
func (e *ErrTunnelNotFound) Error() string {
	return fmt.Sprintf("tunnel: not found: %q", e.Name)
}

// ErrTunnelAlreadyExists is returned when a tunnel already exists with different config.
type ErrTunnelAlreadyExists struct {
	Name string
}

// Error implements the error interface.
func (e *ErrTunnelAlreadyExists) Error() string {
	return fmt.Sprintf("tunnel: already exists: %q", e.Name)
}

// ErrInvalidTunnelConfig is returned when tunnel configuration is invalid.
type ErrInvalidTunnelConfig struct {
	Name   string
	Reason string
}

// Error implements the error interface.
func (e *ErrInvalidTunnelConfig) Error() string {
	if e.Name == "" {
		return fmt.Sprintf("tunnel: invalid config: %s", e.Reason)
	}
	return fmt.Sprintf("tunnel: invalid config for %q: %s", e.Name, e.Reason)
}

// ErrTunnelRemoveFailed is returned when tunnel removal fails.
type ErrTunnelRemoveFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelRemoveFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to remove %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelRemoveFailed) Unwrap() error {
	return e.Cause
}

// ErrTunnelStatusFailed is returned when querying tunnel status fails.
type ErrTunnelStatusFailed struct {
	Name  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelStatusFailed) Error() string {
	return fmt.Sprintf("tunnel: failed to get status for %q: %v", e.Name, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrTunnelStatusFailed) Unwrap() error {
	return e.Cause
}
