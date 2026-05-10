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

package bmc

import "fmt"

// Power Errors

// ErrPowerFailed is returned when a power management operation fails.
type ErrPowerFailed struct {
	ProfileID uint64
	Action    string
	Cause     error
}

// Error implements the error interface.
func (e *ErrPowerFailed) Error() string {
	return fmt.Sprintf("bmc: power %s failed for profile %d: %v", e.Action, e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrPowerFailed) Unwrap() error {
	return e.Cause
}

// Boot Device Errors

// ErrBootDeviceFailed is returned when a boot device operation fails.
type ErrBootDeviceFailed struct {
	ProfileID uint64
	Cause     error
}

// Error implements the error interface.
func (e *ErrBootDeviceFailed) Error() string {
	return fmt.Sprintf("bmc: boot device operation failed for profile %d: %v", e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrBootDeviceFailed) Unwrap() error {
	return e.Cause
}

// Virtual Media Errors

// ErrVirtualMediaFailed is returned when a virtual media operation fails.
type ErrVirtualMediaFailed struct {
	ProfileID uint64
	Action    string
	Cause     error
}

// Error implements the error interface.
func (e *ErrVirtualMediaFailed) Error() string {
	return fmt.Sprintf("bmc: virtual media %s failed for profile %d: %v", e.Action, e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrVirtualMediaFailed) Unwrap() error {
	return e.Cause
}

// Sensor Errors

// ErrSensorsFailed is returned when a sensor query operation fails.
type ErrSensorsFailed struct {
	ProfileID uint64
	Cause     error
}

// Error implements the error interface.
func (e *ErrSensorsFailed) Error() string {
	return fmt.Sprintf("bmc: get sensors failed for profile %d: %v", e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrSensorsFailed) Unwrap() error {
	return e.Cause
}

// System Info Errors

// ErrSystemInfoFailed is returned when a system info query fails.
type ErrSystemInfoFailed struct {
	ProfileID uint64
	Cause     error
}

// Error implements the error interface.
func (e *ErrSystemInfoFailed) Error() string {
	return fmt.Sprintf("bmc: get system info failed for profile %d: %v", e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrSystemInfoFailed) Unwrap() error {
	return e.Cause
}

// Provisioning Errors

// ErrProvisionFailed is returned when a provisioning operation fails.
type ErrProvisionFailed struct {
	ProfileID uint64
	Cause     error
}

// Error implements the error interface.
func (e *ErrProvisionFailed) Error() string {
	return fmt.Sprintf("bmc: provision failed for profile %d: %v", e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrProvisionFailed) Unwrap() error {
	return e.Cause
}

// Certificate Errors

// ErrCertificateFailed is returned when a certificate operation fails.
type ErrCertificateFailed struct {
	ProfileID uint64
	Action    string
	Cause     error
}

// Error implements the error interface.
func (e *ErrCertificateFailed) Error() string {
	return fmt.Sprintf("bmc: certificate %s failed for profile %d: %v", e.Action, e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrCertificateFailed) Unwrap() error {
	return e.Cause
}

// User Errors

// ErrUserFailed is returned when a user management operation fails.
type ErrUserFailed struct {
	ProfileID uint64
	Action    string
	Cause     error
}

// Error implements the error interface.
func (e *ErrUserFailed) Error() string {
	return fmt.Sprintf("bmc: user %s failed for profile %d: %v", e.Action, e.ProfileID, e.Cause)
}

// Unwrap returns the underlying error for errors.Is and errors.As support.
func (e *ErrUserFailed) Unwrap() error {
	return e.Cause
}
