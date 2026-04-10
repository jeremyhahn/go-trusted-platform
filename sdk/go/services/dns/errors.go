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

package dns

import "fmt"

// Zone Errors

type ErrCreateZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrCreateZoneFailed) Error() string {
	return fmt.Sprintf("failed to create zone %s: %v", e.Name, e.Cause)
}

func (e *ErrCreateZoneFailed) Unwrap() error { return e.Cause }

type ErrGetZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrGetZoneFailed) Error() string {
	return fmt.Sprintf("failed to get zone %s: %v", e.Name, e.Cause)
}

func (e *ErrGetZoneFailed) Unwrap() error { return e.Cause }

type ErrUpdateZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrUpdateZoneFailed) Error() string {
	return fmt.Sprintf("failed to update zone %s: %v", e.Name, e.Cause)
}

func (e *ErrUpdateZoneFailed) Unwrap() error { return e.Cause }

type ErrDeleteZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrDeleteZoneFailed) Error() string {
	return fmt.Sprintf("failed to delete zone %s: %v", e.Name, e.Cause)
}

func (e *ErrDeleteZoneFailed) Unwrap() error { return e.Cause }

type ErrListZonesFailed struct {
	Cause error
}

func (e *ErrListZonesFailed) Error() string {
	return fmt.Sprintf("failed to list zones: %v", e.Cause)
}

func (e *ErrListZonesFailed) Unwrap() error { return e.Cause }

// Record Errors

type ErrAddRecordFailed struct {
	ZoneName string
	Cause    error
}

func (e *ErrAddRecordFailed) Error() string {
	return fmt.Sprintf("failed to add record to zone %s: %v", e.ZoneName, e.Cause)
}

func (e *ErrAddRecordFailed) Unwrap() error { return e.Cause }

type ErrDeleteRecordFailed struct {
	ZoneName string
	Name     string
	Cause    error
}

func (e *ErrDeleteRecordFailed) Error() string {
	return fmt.Sprintf("failed to delete record %s from zone %s: %v", e.Name, e.ZoneName, e.Cause)
}

func (e *ErrDeleteRecordFailed) Unwrap() error { return e.Cause }

type ErrUpdateRecordFailed struct {
	ZoneName string
	Cause    error
}

func (e *ErrUpdateRecordFailed) Error() string {
	return fmt.Sprintf("failed to update record in zone %s: %v", e.ZoneName, e.Cause)
}

func (e *ErrUpdateRecordFailed) Unwrap() error { return e.Cause }

type ErrListRecordsFailed struct {
	ZoneName string
	Cause    error
}

func (e *ErrListRecordsFailed) Error() string {
	return fmt.Sprintf("failed to list records in zone %s: %v", e.ZoneName, e.Cause)
}

func (e *ErrListRecordsFailed) Unwrap() error { return e.Cause }

// DNSSEC Errors

type ErrSignZoneFailed struct {
	ZoneName string
	Cause    error
}

func (e *ErrSignZoneFailed) Error() string {
	return fmt.Sprintf("failed to sign zone %s: %v", e.ZoneName, e.Cause)
}

func (e *ErrSignZoneFailed) Unwrap() error { return e.Cause }

type ErrGetDNSSECStatusFailed struct {
	ZoneName string
	Cause    error
}

func (e *ErrGetDNSSECStatusFailed) Error() string {
	return fmt.Sprintf("failed to get DNSSEC status for zone %s: %v", e.ZoneName, e.Cause)
}

func (e *ErrGetDNSSECStatusFailed) Unwrap() error { return e.Cause }

// Resolution Errors

type ErrResolveFailed struct {
	FQDN  string
	Cause error
}

func (e *ErrResolveFailed) Error() string {
	return fmt.Sprintf("failed to resolve %s: %v", e.FQDN, e.Cause)
}

func (e *ErrResolveFailed) Unwrap() error { return e.Cause }

// Registration Errors

type ErrRegisterFailed struct {
	FQDN  string
	Cause error
}

func (e *ErrRegisterFailed) Error() string {
	return fmt.Sprintf("failed to register %s: %v", e.FQDN, e.Cause)
}

func (e *ErrRegisterFailed) Unwrap() error { return e.Cause }
