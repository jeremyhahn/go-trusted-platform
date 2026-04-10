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

package device

import "fmt"

// ErrInvalidDeviceID is returned when an invalid device ID is provided
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrDeviceNotFound is returned when a device is not found
type ErrDeviceNotFound struct {
	ID uint64
}

func (e ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %d", e.ID)
}

// ErrDeviceNotFoundBySerial is returned when a device is not found by serial number
type ErrDeviceNotFoundBySerial struct {
	Serial string
}

func (e ErrDeviceNotFoundBySerial) Error() string {
	return fmt.Sprintf("device not found with serial: %s", e.Serial)
}

// ErrSerialNumberRequired is returned when a serial number is required but not provided
type ErrSerialNumberRequired struct{}

func (e ErrSerialNumberRequired) Error() string {
	return "serial number is required"
}

// ErrDeleteDeviceFailed is returned when device deletion fails
type ErrDeleteDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrDeleteDeviceFailed) Error() string {
	return fmt.Sprintf("failed to delete device %d: %s", e.ID, e.Reason)
}

// ErrGetDeviceFailed is returned when getting a device fails
type ErrGetDeviceFailed struct {
	ID     uint64
	Reason string
}

func (e ErrGetDeviceFailed) Error() string {
	return fmt.Sprintf("failed to get device %d: %s", e.ID, e.Reason)
}

// ErrListDevicesFailed is returned when listing devices fails
type ErrListDevicesFailed struct {
	Reason string
}

func (e ErrListDevicesFailed) Error() string {
	return fmt.Sprintf("failed to list devices: %s", e.Reason)
}

// ErrFindDeviceBySerialFailed is returned when finding a device by serial fails
type ErrFindDeviceBySerialFailed struct {
	Serial string
	Reason string
}

func (e ErrFindDeviceBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find device by serial %s: %s", e.Serial, e.Reason)
}
