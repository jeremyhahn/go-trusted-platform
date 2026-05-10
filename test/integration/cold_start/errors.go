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

package cold_start

import "fmt"

// ErrPlatformdLaunch indicates the harness could not start a fresh
// platformd process for the cold-start scenario. The cause string carries
// the underlying os/exec error.
type ErrPlatformdLaunch struct {
	Phase string
	Cause error
}

// Error returns a human-readable description.
func (e *ErrPlatformdLaunch) Error() string {
	return fmt.Sprintf("cold_start: platformd launch failed during %s: %v", e.Phase, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *ErrPlatformdLaunch) Unwrap() error { return e.Cause }

// ErrInitOnlyBindCheck indicates the init-only bind contract was
// violated: in init-only mode platformd MUST only bind /healthz, /init,
// /unseal on the MCP port and MUST refuse all remote transports.
type ErrInitOnlyBindCheck struct {
	Protocol string
	Reason   string
}

// Error returns a human-readable description.
func (e *ErrInitOnlyBindCheck) Error() string {
	return fmt.Sprintf("cold_start: init-only bind check failed for %s: %s", e.Protocol, e.Reason)
}

// ErrTransportShouldRefuse indicates a remote transport accepted a
// connection while platformd is in init-only mode, violating §7 of the
// canonical bootstrap contract.
type ErrTransportShouldRefuse struct {
	Protocol string
	Endpoint string
}

// Error returns a human-readable description.
func (e *ErrTransportShouldRefuse) Error() string {
	return fmt.Sprintf("cold_start: %s endpoint %s should refuse connections in init-only mode", e.Protocol, e.Endpoint)
}

// ErrTransportShouldAccept indicates a remote transport refused a
// connection after the daemon transitioned to operational state, when
// it should be accepting traffic.
type ErrTransportShouldAccept struct {
	Protocol string
	Endpoint string
	Cause    error
}

// Error returns a human-readable description.
func (e *ErrTransportShouldAccept) Error() string {
	return fmt.Sprintf("cold_start: %s endpoint %s should accept connections after unseal: %v", e.Protocol, e.Endpoint, e.Cause)
}

// Unwrap returns the underlying dial error.
func (e *ErrTransportShouldAccept) Unwrap() error { return e.Cause }

// ErrJWTDecode indicates a returned JWT could not be decoded for the
// purpose of verifying the sub claim matches the expected username.
type ErrJWTDecode struct {
	Reason string
}

// Error returns a human-readable description.
func (e *ErrJWTDecode) Error() string {
	return "cold_start: jwt decode failed: " + e.Reason
}

// ErrAdminBundleInvalid indicates the admin bundle returned by init did
// not parse as a valid certificate + private key pair.
type ErrAdminBundleInvalid struct {
	Reason string
}

// Error returns a human-readable description.
func (e *ErrAdminBundleInvalid) Error() string {
	return "cold_start: admin bundle invalid: " + e.Reason
}

// ErrCertChainMismatch indicates a cert chain assertion failed because
// the leaf certificate did not chain to the expected platform CA.
type ErrCertChainMismatch struct {
	Reason string
}

// Error returns a human-readable description.
func (e *ErrCertChainMismatch) Error() string {
	return "cold_start: cert chain mismatch: " + e.Reason
}

// ErrFactorListMismatch indicates the factor list returned by the daemon
// did not match expectations after an add/remove sequence.
type ErrFactorListMismatch struct {
	Want string
	Got  string
}

// Error returns a human-readable description.
func (e *ErrFactorListMismatch) Error() string {
	return fmt.Sprintf("cold_start: factor list mismatch: want %q got %q", e.Want, e.Got)
}

// ErrAuthenticatorStubMissing is returned by FIDO2/PIV stub helpers
// while the real authenticator harness is pending (#143-b/c). Tests
// that hit this should call t.Skip rather than fail.
type ErrAuthenticatorStubMissing struct {
	Method string
}

// Error returns a human-readable description.
func (e *ErrAuthenticatorStubMissing) Error() string {
	return "cold_start: " + e.Method + " stub authenticator not yet implemented (#143-b/c)"
}

// ErrHealthzWaitTimeout indicates the daemon did not reach the expected
// state on the /healthz endpoint within the configured deadline.
type ErrHealthzWaitTimeout struct {
	WantState string
	LastState string
	Cause     error
}

// Error returns a human-readable description.
func (e *ErrHealthzWaitTimeout) Error() string {
	return fmt.Sprintf("cold_start: /healthz never reported %q (last=%q): %v", e.WantState, e.LastState, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrHealthzWaitTimeout) Unwrap() error { return e.Cause }
