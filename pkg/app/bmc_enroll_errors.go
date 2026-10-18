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

package app

import "fmt"

// ErrBMCEnrollNoTrustResolver is returned when EnrollBMC is called but the
// app does not have a configured trust resolver for the BMC class.
type ErrBMCEnrollNoTrustResolver struct{}

func (e ErrBMCEnrollNoTrustResolver) Error() string {
	return "app: BMC enrollment requires a trust resolver; call BootstrapTrust or configure trust.bmc before enrolling"
}

// ErrBMCEnrollFactoryCert is returned when the enrollment ceremony cannot
// fetch the BMC's existing factory TLS certificate.
type ErrBMCEnrollFactoryCert struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollFactoryCert) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): factory cert fetch failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollFactoryCert) Unwrap() error { return e.Cause }

// ErrBMCEnrollCertVerify is returned when the newly deployed BMC certificate
// fails chain verification against the issuing CA.
type ErrBMCEnrollCertVerify struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollCertVerify) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): newly deployed cert verification failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollCertVerify) Unwrap() error { return e.Cause }

// ErrBMCEnrollNoInternalZone is returned when dns-register is requested but
// DNSConfig.InternalServer.Zone.Name is unset so no A record target zone can
// be determined.
type ErrBMCEnrollNoInternalZone struct {
	DeviceID uint64
}

func (e ErrBMCEnrollNoInternalZone) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): dns-register enabled but dns.internal.zone.name is not configured", e.DeviceID)
}

// ErrBMCEnrollCredStore is returned when writing to the BMC credential store
// fails during enrollment.
type ErrBMCEnrollCredStore struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollCredStore) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): credential store write failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollCredStore) Unwrap() error { return e.Cause }

// ErrBMCEnrollDNSRegister is returned when the dns-register step cannot write
// the BMC's A record into the internal zone.
type ErrBMCEnrollDNSRegister struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollDNSRegister) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): dns-register failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollDNSRegister) Unwrap() error { return e.Cause }

// ErrBMCDNSInvalidAddress is returned when the BMC address an A record would
// point at is not an IPv4 address.
type ErrBMCDNSInvalidAddress struct {
	Address string
}

func (e ErrBMCDNSInvalidAddress) Error() string {
	return fmt.Sprintf("app: BMC A record needs an IPv4 address, got %q", e.Address)
}

// ErrBMCEnrollDeviceSave is returned when the device entity cannot be
// updated with the BMCEnrollment stamp at the end of the ceremony.
type ErrBMCEnrollDeviceSave struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollDeviceSave) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): device save failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollDeviceSave) Unwrap() error { return e.Cause }

// ErrBMCEnrollDeviceLoad is returned when the device entity cannot be
// loaded by ID at the start of the device-stamp step.
type ErrBMCEnrollDeviceLoad struct {
	DeviceID uint64
	Cause    error
}

func (e ErrBMCEnrollDeviceLoad) Error() string {
	return fmt.Sprintf("app: BMC enrollment (device %d): device load failed: %v", e.DeviceID, e.Cause)
}

func (e ErrBMCEnrollDeviceLoad) Unwrap() error { return e.Cause }
