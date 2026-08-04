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

// ErrCreateFailed is returned when device creation fails.
type ErrCreateFailed struct {
	Cause error
}

func (e *ErrCreateFailed) Error() string {
	return fmt.Sprintf("device creation failed: %v", e.Cause)
}

func (e *ErrCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrGetFailed is returned when device retrieval fails.
type ErrGetFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetFailed) Error() string {
	return fmt.Sprintf("failed to get device %d: %v", e.ID, e.Cause)
}

func (e *ErrGetFailed) Unwrap() error {
	return e.Cause
}

// ErrUpdateFailed is returned when device update fails.
type ErrUpdateFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrUpdateFailed) Error() string {
	return fmt.Sprintf("failed to update device %d: %v", e.ID, e.Cause)
}

func (e *ErrUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteFailed is returned when device deletion fails.
type ErrDeleteFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete device %d: %v", e.ID, e.Cause)
}

func (e *ErrDeleteFailed) Unwrap() error {
	return e.Cause
}

// ErrListFailed is returned when listing devices fails.
type ErrListFailed struct {
	Cause error
}

func (e *ErrListFailed) Error() string {
	return fmt.Sprintf("failed to list devices: %v", e.Cause)
}

func (e *ErrListFailed) Unwrap() error {
	return e.Cause
}

// ErrFindBySerialFailed is returned when finding device by serial fails.
type ErrFindBySerialFailed struct {
	Serial string
	Cause  error
}

func (e *ErrFindBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find device by serial %s: %v", e.Serial, e.Cause)
}

func (e *ErrFindBySerialFailed) Unwrap() error {
	return e.Cause
}

// ErrCountFailed is returned when counting devices fails.
type ErrCountFailed struct {
	Cause error
}

func (e *ErrCountFailed) Error() string {
	return fmt.Sprintf("failed to count devices: %v", e.Cause)
}

func (e *ErrCountFailed) Unwrap() error {
	return e.Cause
}

// ErrActivateFailed is returned when device activation fails.
type ErrActivateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrActivateFailed) Error() string {
	return fmt.Sprintf("failed to activate device %s: %v", e.Serial, e.Cause)
}

func (e *ErrActivateFailed) Unwrap() error {
	return e.Cause
}

// Profile-related errors

// ErrCreateProfileFailed is returned when profile creation fails.
type ErrCreateProfileFailed struct {
	Cause error
}

func (e *ErrCreateProfileFailed) Error() string {
	return fmt.Sprintf("profile creation failed: %v", e.Cause)
}

func (e *ErrCreateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrGetProfileFailed is returned when profile retrieval fails.
type ErrGetProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrGetProfileFailed) Error() string {
	return fmt.Sprintf("failed to get profile %d: %v", e.ID, e.Cause)
}

func (e *ErrGetProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrUpdateProfileFailed is returned when profile update fails.
type ErrUpdateProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrUpdateProfileFailed) Error() string {
	return fmt.Sprintf("failed to update profile %d: %v", e.ID, e.Cause)
}

func (e *ErrUpdateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteProfileFailed is returned when profile deletion fails.
type ErrDeleteProfileFailed struct {
	ID    uint64
	Cause error
}

func (e *ErrDeleteProfileFailed) Error() string {
	return fmt.Sprintf("failed to delete profile %d: %v", e.ID, e.Cause)
}

func (e *ErrDeleteProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrListProfilesFailed is returned when listing profiles fails.
type ErrListProfilesFailed struct {
	Cause error
}

func (e *ErrListProfilesFailed) Error() string {
	return fmt.Sprintf("failed to list profiles: %v", e.Cause)
}

func (e *ErrListProfilesFailed) Unwrap() error {
	return e.Cause
}

// ErrFindProfileByMACFailed is returned when finding profile by MAC fails.
type ErrFindProfileByMACFailed struct {
	MACAddress string
	Cause      error
}

func (e *ErrFindProfileByMACFailed) Error() string {
	return fmt.Sprintf("failed to find profile by MAC %s: %v", e.MACAddress, e.Cause)
}

func (e *ErrFindProfileByMACFailed) Unwrap() error {
	return e.Cause
}

// ErrFindProfileBySerialFailed is returned when finding profile by serial fails.
type ErrFindProfileBySerialFailed struct {
	Serial string
	Cause  error
}

func (e *ErrFindProfileBySerialFailed) Error() string {
	return fmt.Sprintf("failed to find profile by serial %s: %v", e.Serial, e.Cause)
}

func (e *ErrFindProfileBySerialFailed) Unwrap() error {
	return e.Cause
}

// ErrFindMatchingProfileFailed is returned when finding matching profile fails.
type ErrFindMatchingProfileFailed struct {
	Cause error
}

func (e *ErrFindMatchingProfileFailed) Error() string {
	return fmt.Sprintf("failed to find matching profile: %v", e.Cause)
}

func (e *ErrFindMatchingProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrCountProfilesFailed is returned when counting profiles fails.
type ErrCountProfilesFailed struct {
	Cause error
}

func (e *ErrCountProfilesFailed) Error() string {
	return fmt.Sprintf("failed to count profiles: %v", e.Cause)
}

func (e *ErrCountProfilesFailed) Unwrap() error {
	return e.Cause
}

// ErrAssignProfileFailed is returned when assigning a profile to a device fails.
type ErrAssignProfileFailed struct {
	ProfileID uint64
	Cause     error
}

func (e *ErrAssignProfileFailed) Error() string {
	return fmt.Sprintf("failed to assign profile %d to device: %v", e.ProfileID, e.Cause)
}

func (e *ErrAssignProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrUnassignProfileFailed is returned when clearing a profile's device
// binding fails.
type ErrUnassignProfileFailed struct {
	ProfileID uint64
	Cause     error
}

func (e *ErrUnassignProfileFailed) Error() string {
	return fmt.Sprintf("failed to unassign profile %d from device: %v", e.ProfileID, e.Cause)
}

func (e *ErrUnassignProfileFailed) Unwrap() error {
	return e.Cause
}
