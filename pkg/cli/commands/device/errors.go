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

// Register command errors

// ErrRegisterSerialRequired is returned when --serial is not provided
type ErrRegisterSerialRequired struct{}

func (e ErrRegisterSerialRequired) Error() string {
	return "device register: --serial is required"
}

// ErrRegisterCreateDeviceFailed is returned when the control plane rejects
// the CreateDevice call
type ErrRegisterCreateDeviceFailed struct {
	Serial string
	Cause  error
}

func (e ErrRegisterCreateDeviceFailed) Error() string {
	return fmt.Sprintf("device register: failed to create device %q: %v", e.Serial, e.Cause)
}

func (e ErrRegisterCreateDeviceFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterEmptyResponse is returned when CreateDevice succeeds but the
// response carries no device record
type ErrRegisterEmptyResponse struct {
	Serial string
}

func (e ErrRegisterEmptyResponse) Error() string {
	return fmt.Sprintf("device register: control plane returned no device for serial %q", e.Serial)
}

// Profile command errors

// ErrInvalidProfileID is returned when an invalid profile ID is provided
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	return fmt.Sprintf("device profile: invalid profile ID: %s", e.ID)
}

// ErrProfileNameRequired is returned when the profile name is not provided
type ErrProfileNameRequired struct{}

func (e ErrProfileNameRequired) Error() string {
	return "device profile: --name is required"
}

// ErrProfileInvalidRole is returned when an invalid profile role is provided
type ErrProfileInvalidRole struct {
	Role string
}

func (e ErrProfileInvalidRole) Error() string {
	return fmt.Sprintf("device profile: invalid role %q, must be one of: control-plane, gateway, worker, server, client, workstation, edge, iot, load-balancer", e.Role)
}

// ErrProfileEKCertReadFailed is returned when the EK certificate file cannot be read
type ErrProfileEKCertReadFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileEKCertReadFailed) Error() string {
	return fmt.Sprintf("device profile: failed to read EK certificate %s: %v", e.Path, e.Cause)
}

func (e ErrProfileEKCertReadFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileEKCertInvalid is returned when the EK certificate is not a valid
// PEM-encoded X.509 certificate
type ErrProfileEKCertInvalid struct {
	Reason string
}

func (e ErrProfileEKCertInvalid) Error() string {
	return fmt.Sprintf("device profile: EK certificate is not a valid PEM x509 certificate: %s", e.Reason)
}

// ErrProfileConfigReadFailed is returned when the config file cannot be read
type ErrProfileConfigReadFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileConfigReadFailed) Error() string {
	return fmt.Sprintf("device profile: failed to read config file %s: %v", e.Path, e.Cause)
}

func (e ErrProfileConfigReadFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileConfigParseFailed is returned when the config file cannot be parsed
type ErrProfileConfigParseFailed struct {
	Path  string
	Cause error
}

func (e ErrProfileConfigParseFailed) Error() string {
	return fmt.Sprintf("device profile: failed to parse config file %s: %v", e.Path, e.Cause)
}

func (e ErrProfileConfigParseFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileCreateFailed is returned when profile creation fails
type ErrProfileCreateFailed struct {
	Cause error
}

func (e ErrProfileCreateFailed) Error() string {
	return fmt.Sprintf("device profile: failed to create profile: %v", e.Cause)
}

func (e ErrProfileCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileGetFailed is returned when fetching a profile fails
type ErrProfileGetFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileGetFailed) Error() string {
	return fmt.Sprintf("device profile: failed to get profile %d: %v", e.ID, e.Cause)
}

func (e ErrProfileGetFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPagination is returned when a list verb is given a page or page
// size below one, before any connection is attempted.
type ErrInvalidPagination struct {
	Page     int
	PageSize int
}

func (e ErrInvalidPagination) Error() string {
	return fmt.Sprintf("device profile: invalid pagination: page %d, page-size %d (both must be >= 1)", e.Page, e.PageSize)
}

// ErrProfileListFailed is returned when listing profiles fails
type ErrProfileListFailed struct {
	Cause error
}

func (e ErrProfileListFailed) Error() string {
	return fmt.Sprintf("device profile: failed to list profiles: %v", e.Cause)
}

func (e ErrProfileListFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileUpdateFailed is returned when updating a profile fails
type ErrProfileUpdateFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileUpdateFailed) Error() string {
	return fmt.Sprintf("device profile: failed to update profile %d: %v", e.ID, e.Cause)
}

func (e ErrProfileUpdateFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileAssignFailed is returned when assigning a profile to a device fails.
type ErrProfileAssignFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileAssignFailed) Error() string {
	return fmt.Sprintf("device profile: failed to assign profile %d to device: %v", e.ID, e.Cause)
}

func (e ErrProfileAssignFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileUnassignFailed is returned when clearing a profile's device
// binding fails.
type ErrProfileUnassignFailed struct {
	ID    uint64
	Cause error
}

func (e ErrProfileUnassignFailed) Error() string {
	return fmt.Sprintf("device profile: failed to unassign profile %d from device: %v", e.ID, e.Cause)
}

func (e ErrProfileUnassignFailed) Unwrap() error {
	return e.Cause
}

// ErrAssignIdentityRequired is returned when a profile assignment resolves
// neither an EK serial nor a MAC address.
type ErrAssignIdentityRequired struct{}

func (e ErrAssignIdentityRequired) Error() string {
	return "device profile: assignment requires --device, --ek-serial, or --mac"
}

// ErrRecordAttestCertFailed is returned when the control plane refuses or
// fails to record a device's attestation certificate. Reason carries the
// control plane's message, which names every candidate it evaluated and why
// each was refused.
type ErrRecordAttestCertFailed struct {
	ID     uint64
	Reason string
}

func (e ErrRecordAttestCertFailed) Error() string {
	return fmt.Sprintf("attestation certificate not recorded for device %d: %s", e.ID, e.Reason)
}

// ErrBootKeyUnreadable is returned when the --key file cannot be read or
// holds no PEM private key that can sign.
type ErrBootKeyUnreadable struct {
	Path  string
	Cause error
}

func (e ErrBootKeyUnreadable) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("device boot: %s holds no PEM private key that can sign", e.Path)
	}
	return fmt.Sprintf("device boot: %s is not a usable private key: %v", e.Path, e.Cause)
}

func (e ErrBootKeyUnreadable) Unwrap() error {
	return e.Cause
}

// ErrBootQuoteCommandFailed is returned when the --quote-command program
// fails or prints no evidence. Stderr carries what the program reported.
type ErrBootQuoteCommandFailed struct {
	Command string
	Stderr  string
	Cause   error
}

func (e ErrBootQuoteCommandFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("device boot: quote command %s printed no evidence", e.Command)
	}
	return fmt.Sprintf("device boot: quote command %s failed: %v: %s", e.Command, e.Cause, e.Stderr)
}

func (e ErrBootQuoteCommandFailed) Unwrap() error {
	return e.Cause
}

// ErrBootCertificateFailed is returned when the control plane refuses or
// fails a boot-certificate request.
type ErrBootCertificateFailed struct {
	Identity string
	Reason   string
}

func (e ErrBootCertificateFailed) Error() string {
	return fmt.Sprintf("boot certificate not returned for %q: %s", e.Identity, e.Reason)
}

// ErrBootDeliveryFailed is returned when the control plane refuses or fails a
// boot-delivery request.
type ErrBootDeliveryFailed struct {
	Reason string
}

func (e ErrBootDeliveryFailed) Error() string {
	return fmt.Sprintf("boot delivery not returned: %s", e.Reason)
}
