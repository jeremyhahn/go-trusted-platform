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

package auth

import "strings"

// ErrEmptyAddress is returned by NewClient when an empty quicbaas
// address is supplied.
type ErrEmptyAddress struct{}

// Error implements the error interface.
func (e *ErrEmptyAddress) Error() string {
	return "auth: quicbaas address is required"
}

// ErrSDKConnectFailed wraps SDK connection failures.
type ErrSDKConnectFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrSDKConnectFailed) Error() string {
	return "auth: failed to connect to quicbaas SDK: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrSDKConnectFailed) Unwrap() error { return e.Cause }

// ErrSecuritySurfaceUnavailable indicates the M10 ExtendedSecurityService
// surface is not reachable on the connected SDK client.
type ErrSecuritySurfaceUnavailable struct {
	Op string
}

// Error implements the error interface.
func (e *ErrSecuritySurfaceUnavailable) Error() string {
	return e.Op + ": quicbaas SDK Security().Auth().Factors() surface is unavailable"
}

// ErrInvalidFactorType is returned for unrecognized --type values.
type ErrInvalidFactorType struct {
	Type string
}

// Error implements the error interface.
func (e *ErrInvalidFactorType) Error() string {
	return "auth: invalid factor type " + e.Type + " (must be one of: mtls, fido2, piv)"
}

// ErrInvalidAuthMethod is returned for unrecognized --method values.
type ErrInvalidAuthMethod struct {
	Method string
}

// Error implements the error interface.
func (e *ErrInvalidAuthMethod) Error() string {
	return "auth: invalid auth method " + e.Method + " (must be one of: mtls, fido2, piv)"
}

// ErrMissingLabel is returned when --label is required but missing.
type ErrMissingLabel struct {
	Op string
}

// Error implements the error interface.
func (e *ErrMissingLabel) Error() string {
	return e.Op + ": --label is required"
}

// ErrMissingFactorID is returned when a factor id is required but
// missing.
type ErrMissingFactorID struct {
	Op string
}

// Error implements the error interface.
func (e *ErrMissingFactorID) Error() string {
	return e.Op + ": factor id is required"
}

// ErrMissingCertPath is returned when "--type mtls" is selected but
// --cert was not supplied.
type ErrMissingCertPath struct{}

// Error implements the error interface.
func (e *ErrMissingCertPath) Error() string {
	return "auth: client certificate is required for --method mtls (set --client-cert or place a cert at ~/.platformctl/admin.pem)"
}

// ErrCertRead wraps errors raised while reading or parsing a cert
// PEM file.
type ErrCertRead struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *ErrCertRead) Error() string {
	if e.Path == "" {
		return "auth: cert read error: " + e.Cause.Error()
	}
	return "auth: cert read error (" + e.Path + "): " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrCertRead) Unwrap() error { return e.Cause }

// ErrNoPIVReader is returned when --type piv is selected but no PC/SC
// readers are detected.
type ErrNoPIVReader struct{}

// Error implements the error interface.
func (e *ErrNoPIVReader) Error() string {
	return "auth: no PC/SC readers detected for --method piv"
}

// ErrFIDO2Failed wraps errors from FIDO2 hardware operations.
type ErrFIDO2Failed struct {
	Op    string
	Cause error
}

// Error implements the error interface.
func (e *ErrFIDO2Failed) Error() string {
	return "auth: " + e.Op + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrFIDO2Failed) Unwrap() error { return e.Cause }

// ErrPIVFailed wraps errors from PIV hardware operations.
type ErrPIVFailed struct {
	Op    string
	Cause error
}

// Error implements the error interface.
func (e *ErrPIVFailed) Error() string {
	return "auth: " + e.Op + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrPIVFailed) Unwrap() error { return e.Cause }

// ErrNoFactorsAvailable is returned by auto-discovery when no auth
// method is reachable from the client environment.
type ErrNoFactorsAvailable struct{}

// Error implements the error interface.
func (e *ErrNoFactorsAvailable) Error() string {
	return "auth login: no auth method available (no client cert at default path, no FIDO2 device, no PIV reader)"
}

// ErrAmbiguousAutoDiscovery is returned by auto-discovery when more
// than one factor type is reachable and the operator did not specify
// --method.
type ErrAmbiguousAutoDiscovery struct {
	Methods []string
}

// Error implements the error interface.
func (e *ErrAmbiguousAutoDiscovery) Error() string {
	return "auth login: multiple auth methods available (" +
		strings.Join(e.Methods, ", ") +
		"); pass --method to pick one"
}

// ErrNoFIDO2Device is returned when --method fido2 was selected but no
// authenticator is connected.
type ErrNoFIDO2Device struct{}

// Error implements the error interface.
func (e *ErrNoFIDO2Device) Error() string {
	return "auth login: no FIDO2 authenticator connected"
}

// ErrAmbiguousFIDO2Device is returned when --method fido2 sees more
// than one authenticator and the operator did not pass --device.
type ErrAmbiguousFIDO2Device struct {
	Devices []string
}

// Error implements the error interface.
func (e *ErrAmbiguousFIDO2Device) Error() string {
	return "auth login --method fido2: multiple authenticators connected (" +
		strings.Join(e.Devices, ", ") +
		"); pass --device <id> to pick one"
}

// ErrFIDO2DeviceNotFound is returned when --device matches no
// authenticator.
type ErrFIDO2DeviceNotFound struct {
	DeviceID string
}

// Error implements the error interface.
func (e *ErrFIDO2DeviceNotFound) Error() string {
	return "auth login --method fido2: device " + e.DeviceID + " not found"
}

// ErrAmbiguousPIVReader is returned when --method piv sees more than
// one reader and the operator did not pass --reader.
type ErrAmbiguousPIVReader struct {
	Readers []string
}

// Error implements the error interface.
func (e *ErrAmbiguousPIVReader) Error() string {
	return "auth login --method piv: multiple PC/SC readers connected (" +
		strings.Join(e.Readers, ", ") +
		"); pass --reader <name> to pick one"
}

// ErrPIVReaderNotFound is returned when --reader matches no PC/SC
// reader.
type ErrPIVReaderNotFound struct {
	Name string
}

// Error implements the error interface.
func (e *ErrPIVReaderNotFound) Error() string {
	return "auth login --method piv: reader " + e.Name + " not found"
}

// ErrPIVPINRequired is returned when --method piv requires a User PIN
// but none was supplied.
type ErrPIVPINRequired struct{}

// Error implements the error interface.
func (e *ErrPIVPINRequired) Error() string {
	return "auth login --method piv: User PIN is required (set --pin or PLATFORMCTL_USER_PIN)"
}

// ErrTokenWrite wraps errors raised while writing the issued session
// token to disk.
type ErrTokenWrite struct {
	Path  string
	Cause error
}

// Error implements the error interface.
func (e *ErrTokenWrite) Error() string {
	return "auth login: failed to write session token to " + e.Path + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrTokenWrite) Unwrap() error { return e.Cause }

// ErrUsernameLookupFailed is returned when resolving a CLI-supplied
// "--user" username to a stable user ID fails. The wrapped Cause is
// typically a typed error from the IAM Security().IAM().User().FindByUsername
// call.
type ErrUsernameLookupFailed struct {
	Username string
	Cause    error
}

// Error implements the error interface.
func (e *ErrUsernameLookupFailed) Error() string {
	return "auth: failed to resolve username " + e.Username + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrUsernameLookupFailed) Unwrap() error { return e.Cause }
