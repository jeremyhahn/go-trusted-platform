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

// ErrInvalidProfileID indicates the profile ID URL parameter is not a valid uint64.
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("bmc: invalid profile id: %s", e.ID)
	}
	return "bmc: invalid profile id"
}

// ErrMissingAction indicates the power action field is required but not provided.
type ErrMissingAction struct{}

func (e ErrMissingAction) Error() string {
	return "bmc: action is required"
}

// ErrInvalidAction indicates an unrecognized power action value.
type ErrInvalidAction struct {
	Action string
}

func (e ErrInvalidAction) Error() string {
	return fmt.Sprintf("bmc: invalid action: %s", e.Action)
}

// ErrMissingISOURL indicates the ISO URL field is required but not provided.
type ErrMissingISOURL struct{}

func (e ErrMissingISOURL) Error() string {
	return "bmc: iso_url is required"
}

// ErrBMCServiceNotAvailable indicates the BMC service is not configured or available.
type ErrBMCServiceNotAvailable struct{}

func (e ErrBMCServiceNotAvailable) Error() string {
	return "bmc: service not available"
}

// ErrBaremetalServiceNotAvailable indicates the bare metal provisioning service
// is not configured or available.
type ErrBaremetalServiceNotAvailable struct{}

func (e ErrBaremetalServiceNotAvailable) Error() string {
	return "bmc: bare metal provisioning service not available"
}

// ErrInvalidRequestBody indicates the request body is invalid or malformed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	if e.Reason != "" {
		return "bmc: invalid request body: " + e.Reason
	}
	return "bmc: invalid request body"
}

// ErrMissingLogger indicates the logger is required but not provided.
type ErrMissingLogger struct{}

func (e ErrMissingLogger) Error() string {
	return "bmc: logger is required"
}

// ErrMissingResponseWriter indicates the response writer is required but not provided.
type ErrMissingResponseWriter struct{}

func (e ErrMissingResponseWriter) Error() string {
	return "bmc: response writer is required"
}

// ErrMissingBMCService indicates the BMC service is required but not provided.
type ErrMissingBMCService struct{}

func (e ErrMissingBMCService) Error() string {
	return "bmc: bmc service is required"
}

// ErrServiceError indicates an internal service error occurred.
type ErrServiceError struct {
	Operation string
	Cause     error
}

func (e ErrServiceError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bmc: %s failed: %s", e.Operation, e.Cause.Error())
	}
	return fmt.Sprintf("bmc: %s failed", e.Operation)
}

func (e ErrServiceError) Unwrap() error {
	return e.Cause
}

// ErrMissingBootDevice indicates the boot device field is required but not provided.
type ErrMissingBootDevice struct{}

func (e ErrMissingBootDevice) Error() string {
	return "bmc: device is required"
}

// ErrInvalidBootDevice indicates an unrecognized boot device value.
type ErrInvalidBootDevice struct {
	Device string
}

func (e ErrInvalidBootDevice) Error() string {
	return fmt.Sprintf("bmc: invalid boot device: %s", e.Device)
}

// ErrInvalidUserSlot indicates the user slot URL parameter is not a
// valid uint8.
type ErrInvalidUserSlot struct {
	Slot string
}

func (e ErrInvalidUserSlot) Error() string {
	if e.Slot != "" {
		return fmt.Sprintf("bmc: invalid user slot: %s", e.Slot)
	}
	return "bmc: invalid user slot"
}

// ErrMissingCertPEM indicates the cert_pem field is required but not provided.
type ErrMissingCertPEM struct{}

func (e ErrMissingCertPEM) Error() string {
	return "bmc: cert_pem is required"
}

// ErrMissingKeyPEM indicates the key_pem field is required but not provided.
type ErrMissingKeyPEM struct{}

func (e ErrMissingKeyPEM) Error() string {
	return "bmc: key_pem is required"
}

// ErrMissingUsername indicates the username field is required but not provided.
type ErrMissingUsername struct{}

func (e ErrMissingUsername) Error() string {
	return "bmc: username is required"
}

// ErrMissingPassword indicates the password field is required but not provided.
type ErrMissingPassword struct{}

func (e ErrMissingPassword) Error() string {
	return "bmc: password is required"
}

// ErrMissingPrivilege indicates the privilege field is required but not provided.
type ErrMissingPrivilege struct{}

func (e ErrMissingPrivilege) Error() string {
	return "bmc: privilege is required"
}

// ErrInvalidPrivilege indicates an unrecognized privilege value.
type ErrInvalidPrivilege struct {
	Privilege string
}

func (e ErrInvalidPrivilege) Error() string {
	return fmt.Sprintf("bmc: invalid privilege: %s", e.Privilege)
}
