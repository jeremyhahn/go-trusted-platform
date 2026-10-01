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

import (
	"errors"
	"fmt"
)

// Sentinel errors for the pxe package.
var (
	// ErrInvalidConfig indicates the configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrInvalidVLAN indicates a VLAN ID is invalid.
	ErrInvalidVLAN = errors.New("invalid VLAN ID")

	// ErrInvalidTimeout indicates a timeout value is invalid.
	ErrInvalidTimeout = errors.New("invalid timeout")

	// ErrInvalidFirmwareConfig indicates the firmware configuration is invalid.
	ErrInvalidFirmwareConfig = errors.New("invalid firmware configuration")

	// ErrFirmwareNotFound indicates the firmware file was not found.
	ErrFirmwareNotFound = errors.New("firmware file not found")

	// ErrFirmwareDigestMismatch indicates the firmware digest does not match expected.
	ErrFirmwareDigestMismatch = errors.New("firmware digest mismatch")
)

// ErrServiceNotInitialized indicates the PXE service is not initialized.
type ErrServiceNotInitialized struct{}

func (e ErrServiceNotInitialized) Error() string {
	return "pxe: service not initialized"
}

// ErrServiceNotRunning indicates the PXE service is not running.
type ErrServiceNotRunning struct{}

func (e ErrServiceNotRunning) Error() string {
	return "pxe: service is not running"
}

// ErrServiceAlreadyRunning indicates the PXE service is already running.
type ErrServiceAlreadyRunning struct{}

func (e ErrServiceAlreadyRunning) Error() string {
	return "pxe: service is already running"
}

// ErrInvalidConfiguration indicates invalid service configuration.
type ErrInvalidConfiguration struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfiguration) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("pxe: invalid configuration for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("pxe: invalid configuration: %s", e.Reason)
}

// ErrDeviceNotFound indicates a device was not found by ID or MAC address.
type ErrDeviceNotFound struct {
	DeviceID   string
	MACAddress string
}

func (e ErrDeviceNotFound) Error() string {
	if e.DeviceID != "" {
		return fmt.Sprintf("pxe: device not found: %s", e.DeviceID)
	}
	if e.MACAddress != "" {
		return fmt.Sprintf("pxe: device not found with MAC: %s", e.MACAddress)
	}
	return "pxe: device not found"
}

// ErrDeviceAlreadyExists indicates a device is already registered.
type ErrDeviceAlreadyExists struct {
	DeviceID   string
	MACAddress string
}

func (e ErrDeviceAlreadyExists) Error() string {
	msg := "pxe: device already exists"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.DeviceID)
	}
	if e.MACAddress != "" {
		msg = fmt.Sprintf("%s (MAC=%s)", msg, e.MACAddress)
	}
	return msg
}

// ErrInvalidMACAddress indicates an invalid MAC address format.
type ErrInvalidMACAddress struct {
	MACAddress string
	Reason     string
}

func (e ErrInvalidMACAddress) Error() string {
	msg := "pxe: invalid MAC address"
	if e.MACAddress != "" {
		msg = fmt.Sprintf("%s %q", msg, e.MACAddress)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrInvalidState indicates an invalid provisioning state.
type ErrInvalidState struct {
	DeviceID string
	State    string
	Reason   string
}

func (e ErrInvalidState) Error() string {
	msg := "pxe: invalid state"
	if e.State != "" {
		msg = fmt.Sprintf("%s %q", msg, e.State)
	}
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrInvalidStateTransition indicates an invalid state transition.
type ErrInvalidStateTransition struct {
	DeviceID  string
	FromState string
	ToState   string
	Reason    string
}

func (e ErrInvalidStateTransition) Error() string {
	msg := fmt.Sprintf("pxe: invalid state transition from %q to %q", e.FromState, e.ToState)
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrProvisioningFailed indicates provisioning failed.
type ErrProvisioningFailed struct {
	DeviceID string
	Reason   string
	Cause    error
}

func (e ErrProvisioningFailed) Error() string {
	msg := "pxe: provisioning failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrProvisioningFailed) Unwrap() error {
	return e.Cause
}

// ErrEnrollmentFailed indicates ACME enrollment failed.
type ErrEnrollmentFailed struct {
	DeviceID string
	Reason   string
	Cause    error
}

func (e ErrEnrollmentFailed) Error() string {
	msg := "pxe: enrollment failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrEnrollmentFailed) Unwrap() error {
	return e.Cause
}

// ErrAuthorizationFailed indicates network authorization failed.
type ErrAuthorizationFailed struct {
	DeviceID   string
	MACAddress string
	Reason     string
	Cause      error
}

func (e ErrAuthorizationFailed) Error() string {
	msg := "pxe: authorization failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.MACAddress != "" {
		msg = fmt.Sprintf("%s (MAC=%s)", msg, e.MACAddress)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAuthorizationFailed) Unwrap() error {
	return e.Cause
}

// ErrVLANTransitionFailed indicates VLAN transition failed.
type ErrVLANTransitionFailed struct {
	DeviceID string
	FromVLAN uint16
	ToVLAN   uint16
	Reason   string
	Cause    error
}

func (e ErrVLANTransitionFailed) Error() string {
	msg := "pxe: VLAN transition failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.FromVLAN != 0 || e.ToVLAN != 0 {
		msg = fmt.Sprintf("%s (from=%d, to=%d)", msg, e.FromVLAN, e.ToVLAN)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrVLANTransitionFailed) Unwrap() error {
	return e.Cause
}

// ErrFirmwareVerificationFailed indicates iPXE firmware verification failed.
type ErrFirmwareVerificationFailed struct {
	DeviceID     string
	FirmwarePath string
	Reason       string
	Cause        error
}

func (e ErrFirmwareVerificationFailed) Error() string {
	msg := "pxe: firmware verification failed"
	if e.DeviceID != "" {
		msg = fmt.Sprintf("%s for device %q", msg, e.DeviceID)
	}
	if e.FirmwarePath != "" {
		msg = fmt.Sprintf("%s (firmware=%q)", msg, e.FirmwarePath)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrFirmwareVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrISONotFound indicates an ISO was not found in the registry.
type ErrISONotFound struct {
	ISOName string
	ISOID   string
}

func (e ErrISONotFound) Error() string {
	if e.ISOID != "" {
		return fmt.Sprintf("pxe: ISO not found: %s", e.ISOID)
	}
	if e.ISOName != "" {
		return fmt.Sprintf("pxe: ISO not found with name: %s", e.ISOName)
	}
	return "pxe: ISO not found"
}

// ErrWebhookValidationFailed indicates webhook payload validation failed.
type ErrWebhookValidationFailed struct {
	WebhookType string
	Field       string
	Reason      string
	Cause       error
}

func (e ErrWebhookValidationFailed) Error() string {
	msg := "pxe: webhook validation failed"
	if e.WebhookType != "" {
		msg = fmt.Sprintf("%s for %q", msg, e.WebhookType)
	}
	if e.Field != "" {
		msg = fmt.Sprintf("%s (field=%q)", msg, e.Field)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrWebhookValidationFailed) Unwrap() error {
	return e.Cause
}

// ErrMaxRetriesExceeded indicates the maximum retry count was exceeded.
type ErrMaxRetriesExceeded struct {
	Operation  string
	MaxRetries int
	Reason     string
	Cause      error
}

func (e ErrMaxRetriesExceeded) Error() string {
	msg := "pxe: max retries exceeded"
	if e.Operation != "" {
		msg = fmt.Sprintf("%s for %q", msg, e.Operation)
	}
	if e.MaxRetries > 0 {
		msg = fmt.Sprintf("%s (max=%d)", msg, e.MaxRetries)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrMaxRetriesExceeded) Unwrap() error {
	return e.Cause
}

// ErrTimeout indicates an operation timed out.
type ErrTimeout struct {
	Operation string
	Duration  string
	Cause     error
}

func (e ErrTimeout) Error() string {
	msg := "pxe: operation timed out"
	if e.Operation != "" {
		msg = fmt.Sprintf("pxe: %s timed out", e.Operation)
	}
	if e.Duration != "" {
		msg = fmt.Sprintf("%s after %s", msg, e.Duration)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrTimeout) Unwrap() error {
	return e.Cause
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

// ErrNetworkPlanRequired is returned when the PXE service is configured
// without the network plan: its quarantine and provisioning VLANs come only
// from the plan (sdn.environment), never from a default.
type ErrNetworkPlanRequired struct{}

// Error implements the error interface.
func (ErrNetworkPlanRequired) Error() string {
	return "pxe: the network plan (sdn.environment) is required to number the quarantine and provisioning zones"
}

// ErrVLANNotInPlan is returned when a device is authorized onto a VLAN that
// no zone of the network plan carries.
type ErrVLANNotInPlan struct {
	// VLAN is the requested VLAN.
	VLAN uint16
}

// Error implements the error interface.
func (e ErrVLANNotInPlan) Error() string {
	return fmt.Sprintf("pxe: VLAN %d is not a zone of the network plan", e.VLAN)
}
