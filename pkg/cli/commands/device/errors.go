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

// ErrRegisterHostnameRequired is returned when hostname is not provided
type ErrRegisterHostnameRequired struct{}

func (e ErrRegisterHostnameRequired) Error() string {
	return "device register: --hostname is required"
}

// ErrRegisterMACRequired is returned when MAC address is not provided
type ErrRegisterMACRequired struct{}

func (e ErrRegisterMACRequired) Error() string {
	return "device register: --mac is required"
}

// ErrRegisterRoleRequired is returned when role is not provided
type ErrRegisterRoleRequired struct{}

func (e ErrRegisterRoleRequired) Error() string {
	return "device register: --role is required"
}

// ErrRegisterInvalidRole is returned when an invalid role is provided
type ErrRegisterInvalidRole struct {
	Role string
}

func (e ErrRegisterInvalidRole) Error() string {
	return fmt.Sprintf("device register: invalid role %q, must be one of: control-plane, gateway, worker", e.Role)
}

// ErrRegisterTemplateRequired is returned when template name is not provided
type ErrRegisterTemplateRequired struct{}

func (e ErrRegisterTemplateRequired) Error() string {
	return "device register: --template is required"
}

// ErrRegisterServerRequired is returned when server URL is not provided
type ErrRegisterServerRequired struct{}

func (e ErrRegisterServerRequired) Error() string {
	return "device register: --server is required"
}

// ErrRegisterReadOverrideFile is returned when the override file cannot be read
type ErrRegisterReadOverrideFile struct {
	Path  string
	Cause error
}

func (e ErrRegisterReadOverrideFile) Error() string {
	return fmt.Sprintf("device register: failed to read override file %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterReadOverrideFile) Unwrap() error {
	return e.Cause
}

// ErrRegisterParseOverrideFile is returned when the override file cannot be parsed
type ErrRegisterParseOverrideFile struct {
	Path  string
	Cause error
}

func (e ErrRegisterParseOverrideFile) Error() string {
	return fmt.Sprintf("device register: failed to parse override file %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterParseOverrideFile) Unwrap() error {
	return e.Cause
}

// ErrRegisterLoadCACert is returned when the CA certificate cannot be loaded
type ErrRegisterLoadCACert struct {
	Path  string
	Cause error
}

func (e ErrRegisterLoadCACert) Error() string {
	return fmt.Sprintf("device register: failed to load CA certificate %s: %v", e.Path, e.Cause)
}

func (e ErrRegisterLoadCACert) Unwrap() error {
	return e.Cause
}

// ErrRegisterInvalidCACert is returned when the CA certificate PEM is invalid
type ErrRegisterInvalidCACert struct {
	Path string
}

func (e ErrRegisterInvalidCACert) Error() string {
	return fmt.Sprintf("device register: CA certificate file contains no valid PEM data: %s", e.Path)
}

// ErrRegisterTemplateLookupFailed is returned when the template lookup fails
type ErrRegisterTemplateLookupFailed struct {
	Name  string
	Cause error
}

func (e ErrRegisterTemplateLookupFailed) Error() string {
	return fmt.Sprintf("device register: failed to look up template %q: %v", e.Name, e.Cause)
}

func (e ErrRegisterTemplateLookupFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterCreateProfileFailed is returned when creating the profile from template fails
type ErrRegisterCreateProfileFailed struct {
	Cause error
}

func (e ErrRegisterCreateProfileFailed) Error() string {
	return fmt.Sprintf("device register: failed to create profile: %v", e.Cause)
}

func (e ErrRegisterCreateProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrRegisterInvalidMACAddress is returned when the MAC address format is invalid
type ErrRegisterInvalidMACAddress struct {
	MAC string
}

func (e ErrRegisterInvalidMACAddress) Error() string {
	return fmt.Sprintf("device register: invalid MAC address %q", e.MAC)
}

// ErrRegisterInvalidServerURL is returned when the server URL cannot be parsed
type ErrRegisterInvalidServerURL struct {
	Server string
	Cause  error
}

func (e ErrRegisterInvalidServerURL) Error() string {
	return fmt.Sprintf("device register: invalid server URL %q: %v", e.Server, e.Cause)
}

func (e ErrRegisterInvalidServerURL) Unwrap() error {
	return e.Cause
}
