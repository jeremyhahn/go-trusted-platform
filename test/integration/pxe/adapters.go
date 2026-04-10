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

//go:build integration

package pxe

import (
	"fmt"
)

// =============================================================================
// Common Error Types
// =============================================================================

// ErrConnectionFailed indicates a connection to the service failed.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection failed to %s: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRequestFailed indicates a request to the service failed.
type ErrRequestFailed struct {
	Protocol string
	Method   string
	Err      error
}

func (e ErrRequestFailed) Error() string {
	return fmt.Sprintf("%s request %s failed: %v", e.Protocol, e.Method, e.Err)
}

func (e ErrRequestFailed) Unwrap() error {
	return e.Err
}

// ErrAPIError indicates an error response from the service API.
type ErrAPIError struct {
	Protocol   string
	StatusCode int
	Message    string
}

func (e ErrAPIError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s API error (status %d): %s", e.Protocol, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("%s API error: %s", e.Protocol, e.Message)
}

// ErrDeviceNotFound indicates a device was not found.
type ErrDeviceNotFound struct {
	DeviceID   string
	MACAddress string
}

func (e ErrDeviceNotFound) Error() string {
	if e.DeviceID != "" {
		return fmt.Sprintf("device not found: %s", e.DeviceID)
	}
	return fmt.Sprintf("device not found with MAC: %s", e.MACAddress)
}

// ErrInvalidOperation indicates an invalid operation was attempted.
type ErrInvalidOperation struct {
	Operation string
	Reason    string
}

func (e ErrInvalidOperation) Error() string {
	return fmt.Sprintf("invalid operation %s: %s", e.Operation, e.Reason)
}
