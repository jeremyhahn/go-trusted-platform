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

package main

// GUIUnavailableError is returned when the binary is built without
// the desktop build tag or when no display is available.
type GUIUnavailableError struct{}

// Error returns a human-readable description.
func (e *GUIUnavailableError) Error() string {
	return "platformctl: GUI unavailable (build without desktop tag)"
}

// NotConnectedError is returned when a binding method is called
// before a client connection has been established.
type NotConnectedError struct{}

// Error returns a human-readable description.
func (e *NotConnectedError) Error() string {
	return "platformctl: not connected to platform daemon"
}

// ConnectError is returned when connection to the server fails.
type ConnectError struct {
	Address string
	Err     error
}

// Error returns a human-readable description.
func (e *ConnectError) Error() string {
	return "platformctl: connect to " + e.Address + " failed: " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ConnectError) Unwrap() error { return e.Err }

// InvalidProtocolError is returned when an unknown protocol string
// is provided to the Connect method.
type InvalidProtocolError struct {
	Protocol string
}

// Error returns a human-readable description.
func (e *InvalidProtocolError) Error() string {
	return "platformctl: invalid protocol: " + e.Protocol
}

// InvalidServiceTypeError is returned when a service type string
// cannot be parsed to a valid ServiceType enum value.
type InvalidServiceTypeError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidServiceTypeError) Error() string {
	return "platformctl: invalid service type: " + e.Input
}

// InvalidInputError is returned when a binding method receives
// an invalid input parameter value.
type InvalidInputError struct {
	Field  string
	Reason string
}

// Error returns a human-readable description.
func (e *InvalidInputError) Error() string {
	return "platformctl: invalid input for " + e.Field + ": " + e.Reason
}

// InvalidKeyAlgorithmError is returned when a key algorithm string
// cannot be parsed to a valid KeyAlgorithm enum value.
type InvalidKeyAlgorithmError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidKeyAlgorithmError) Error() string {
	return "platformctl: invalid key algorithm: " + e.Input
}

// InvalidPCRBankError is returned when a PCR bank string
// cannot be parsed to a valid PCRBank enum value.
type InvalidPCRBankError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidPCRBankError) Error() string {
	return "platformctl: invalid PCR bank: " + e.Input
}

// InvalidBundleModeError is returned when a vTPM bundle mode string
// cannot be parsed to a valid BundleMode enum value.
type InvalidBundleModeError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidBundleModeError) Error() string {
	return "platformctl: invalid bundle mode: " + e.Input
}

// InvalidDeviceRoleError is returned when a device role string
// cannot be parsed to a valid DeviceRole enum value.
type InvalidDeviceRoleError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidDeviceRoleError) Error() string {
	return "platformctl: invalid device role: " + e.Input
}

// InvalidEKAlgorithmError is returned when an EK algorithm string
// cannot be parsed to a valid EKAlgorithm enum value.
type InvalidEKAlgorithmError struct {
	Input string
}

// Error returns a human-readable description.
func (e *InvalidEKAlgorithmError) Error() string {
	return "platformctl: invalid EK algorithm: " + e.Input
}
