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

package pxe

import "fmt"

// Device Errors

type ErrRegisterDeviceFailed struct {
	MACAddress string
	Cause      error
}

func (e *ErrRegisterDeviceFailed) Error() string {
	return fmt.Sprintf("failed to register device %s: %v", e.MACAddress, e.Cause)
}

func (e *ErrRegisterDeviceFailed) Unwrap() error { return e.Cause }

type ErrGetDeviceFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetDeviceFailed) Error() string {
	return fmt.Sprintf("failed to get device %s: %v", e.ID, e.Cause)
}

func (e *ErrGetDeviceFailed) Unwrap() error { return e.Cause }

type ErrGetDeviceByMACFailed struct {
	MACAddress string
	Cause      error
}

func (e *ErrGetDeviceByMACFailed) Error() string {
	return fmt.Sprintf("failed to get device by MAC %s: %v", e.MACAddress, e.Cause)
}

func (e *ErrGetDeviceByMACFailed) Unwrap() error { return e.Cause }

type ErrListDevicesFailed struct {
	Cause error
}

func (e *ErrListDevicesFailed) Error() string {
	return fmt.Sprintf("failed to list devices: %v", e.Cause)
}

func (e *ErrListDevicesFailed) Unwrap() error { return e.Cause }

type ErrRemoveDeviceFailed struct {
	ID    string
	Cause error
}

func (e *ErrRemoveDeviceFailed) Error() string {
	return fmt.Sprintf("failed to remove device %s: %v", e.ID, e.Cause)
}

func (e *ErrRemoveDeviceFailed) Unwrap() error { return e.Cause }

// State Errors

type ErrUpdateStateFailed struct {
	ID    string
	Cause error
}

func (e *ErrUpdateStateFailed) Error() string {
	return fmt.Sprintf("failed to update state for device %s: %v", e.ID, e.Cause)
}

func (e *ErrUpdateStateFailed) Unwrap() error { return e.Cause }

type ErrSetEnrolledFailed struct {
	ID    string
	Cause error
}

func (e *ErrSetEnrolledFailed) Error() string {
	return fmt.Sprintf("failed to set device %s as enrolled: %v", e.ID, e.Cause)
}

func (e *ErrSetEnrolledFailed) Unwrap() error { return e.Cause }

type ErrAuthorizeFailed struct {
	ID    string
	Cause error
}

func (e *ErrAuthorizeFailed) Error() string {
	return fmt.Sprintf("failed to authorize device %s: %v", e.ID, e.Cause)
}

func (e *ErrAuthorizeFailed) Unwrap() error { return e.Cause }

type ErrQuarantineFailed struct {
	ID    string
	Cause error
}

func (e *ErrQuarantineFailed) Error() string {
	return fmt.Sprintf("failed to quarantine device %s: %v", e.ID, e.Cause)
}

func (e *ErrQuarantineFailed) Unwrap() error { return e.Cause }

type ErrRetryFailed struct {
	ID    string
	Cause error
}

func (e *ErrRetryFailed) Error() string {
	return fmt.Sprintf("failed to retry device %s: %v", e.ID, e.Cause)
}

func (e *ErrRetryFailed) Unwrap() error { return e.Cause }

// Event Errors

type ErrGetEventsFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetEventsFailed) Error() string {
	return fmt.Sprintf("failed to get events for device %s: %v", e.ID, e.Cause)
}

func (e *ErrGetEventsFailed) Unwrap() error { return e.Cause }

// Service Errors

type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get PXE service status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error { return e.Cause }

type ErrStartServiceFailed struct {
	Cause error
}

func (e *ErrStartServiceFailed) Error() string {
	return fmt.Sprintf("failed to start PXE service: %v", e.Cause)
}

func (e *ErrStartServiceFailed) Unwrap() error { return e.Cause }

type ErrStopServiceFailed struct {
	Cause error
}

func (e *ErrStopServiceFailed) Error() string {
	return fmt.Sprintf("failed to stop PXE service: %v", e.Cause)
}

func (e *ErrStopServiceFailed) Unwrap() error { return e.Cause }

// Webhook Errors

type ErrWebhookCompleteFailed struct {
	MACAddress string
	Cause      error
}

func (e *ErrWebhookCompleteFailed) Error() string {
	return fmt.Sprintf("failed webhook complete for %s: %v", e.MACAddress, e.Cause)
}

func (e *ErrWebhookCompleteFailed) Unwrap() error { return e.Cause }
