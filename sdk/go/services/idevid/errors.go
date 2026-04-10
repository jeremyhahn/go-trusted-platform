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

package idevid

import "fmt"

// IDevID Errors

type ErrGenerateIDevIDFailed struct {
	Cause error
}

func (e *ErrGenerateIDevIDFailed) Error() string {
	return fmt.Sprintf("failed to generate IDevID: %v", e.Cause)
}

func (e *ErrGenerateIDevIDFailed) Unwrap() error { return e.Cause }

type ErrGetIDevIDInfoFailed struct {
	Cause error
}

func (e *ErrGetIDevIDInfoFailed) Error() string {
	return fmt.Sprintf("failed to get IDevID info: %v", e.Cause)
}

func (e *ErrGetIDevIDInfoFailed) Unwrap() error { return e.Cause }

type ErrHasIDevIDFailed struct {
	Cause error
}

func (e *ErrHasIDevIDFailed) Error() string {
	return fmt.Sprintf("failed to check IDevID existence: %v", e.Cause)
}

func (e *ErrHasIDevIDFailed) Unwrap() error { return e.Cause }

type ErrDeleteIDevIDFailed struct {
	Cause error
}

func (e *ErrDeleteIDevIDFailed) Error() string {
	return fmt.Sprintf("failed to delete IDevID: %v", e.Cause)
}

func (e *ErrDeleteIDevIDFailed) Unwrap() error { return e.Cause }

// IAK Errors

type ErrGenerateIAKFailed struct {
	Cause error
}

func (e *ErrGenerateIAKFailed) Error() string {
	return fmt.Sprintf("failed to generate IAK: %v", e.Cause)
}

func (e *ErrGenerateIAKFailed) Unwrap() error { return e.Cause }

type ErrGetIAKInfoFailed struct {
	Cause error
}

func (e *ErrGetIAKInfoFailed) Error() string {
	return fmt.Sprintf("failed to get IAK info: %v", e.Cause)
}

func (e *ErrGetIAKInfoFailed) Unwrap() error { return e.Cause }

type ErrHasIAKFailed struct {
	Cause error
}

func (e *ErrHasIAKFailed) Error() string {
	return fmt.Sprintf("failed to check IAK existence: %v", e.Cause)
}

func (e *ErrHasIAKFailed) Unwrap() error { return e.Cause }

type ErrDeleteIAKFailed struct {
	Cause error
}

func (e *ErrDeleteIAKFailed) Error() string {
	return fmt.Sprintf("failed to delete IAK: %v", e.Cause)
}

func (e *ErrDeleteIAKFailed) Unwrap() error { return e.Cause }

// CSR Errors

type ErrCreateIDevIDCSRFailed struct {
	Cause error
}

func (e *ErrCreateIDevIDCSRFailed) Error() string {
	return fmt.Sprintf("failed to create IDevID CSR: %v", e.Cause)
}

func (e *ErrCreateIDevIDCSRFailed) Unwrap() error { return e.Cause }

type ErrCreateIAKCSRFailed struct {
	Cause error
}

func (e *ErrCreateIAKCSRFailed) Error() string {
	return fmt.Sprintf("failed to create IAK CSR: %v", e.Cause)
}

func (e *ErrCreateIAKCSRFailed) Unwrap() error { return e.Cause }

// Certificate Errors

type ErrInstallIDevIDCertFailed struct {
	Cause error
}

func (e *ErrInstallIDevIDCertFailed) Error() string {
	return fmt.Sprintf("failed to install IDevID certificate: %v", e.Cause)
}

func (e *ErrInstallIDevIDCertFailed) Unwrap() error { return e.Cause }

type ErrInstallIAKCertFailed struct {
	Cause error
}

func (e *ErrInstallIAKCertFailed) Error() string {
	return fmt.Sprintf("failed to install IAK certificate: %v", e.Cause)
}

func (e *ErrInstallIAKCertFailed) Unwrap() error { return e.Cause }

type ErrGetIDevIDCertFailed struct {
	Cause error
}

func (e *ErrGetIDevIDCertFailed) Error() string {
	return fmt.Sprintf("failed to get IDevID certificate: %v", e.Cause)
}

func (e *ErrGetIDevIDCertFailed) Unwrap() error { return e.Cause }

type ErrGetIAKCertFailed struct {
	Cause error
}

func (e *ErrGetIAKCertFailed) Error() string {
	return fmt.Sprintf("failed to get IAK certificate: %v", e.Cause)
}

func (e *ErrGetIAKCertFailed) Unwrap() error { return e.Cause }

type ErrDeleteIDevIDCertFailed struct {
	Cause error
}

func (e *ErrDeleteIDevIDCertFailed) Error() string {
	return fmt.Sprintf("failed to delete IDevID certificate: %v", e.Cause)
}

func (e *ErrDeleteIDevIDCertFailed) Unwrap() error { return e.Cause }

type ErrDeleteIAKCertFailed struct {
	Cause error
}

func (e *ErrDeleteIAKCertFailed) Error() string {
	return fmt.Sprintf("failed to delete IAK certificate: %v", e.Cause)
}

func (e *ErrDeleteIAKCertFailed) Unwrap() error { return e.Cause }

// Other Errors

type ErrGetDeviceAttributesFailed struct {
	Cause error
}

func (e *ErrGetDeviceAttributesFailed) Error() string {
	return fmt.Sprintf("failed to get device attributes: %v", e.Cause)
}

func (e *ErrGetDeviceAttributesFailed) Unwrap() error { return e.Cause }

type ErrActivateCredentialFailed struct {
	Cause error
}

func (e *ErrActivateCredentialFailed) Error() string {
	return fmt.Sprintf("failed to activate credential: %v", e.Cause)
}

func (e *ErrActivateCredentialFailed) Unwrap() error { return e.Cause }

type ErrFlushTransientContextsFailed struct {
	Cause error
}

func (e *ErrFlushTransientContextsFailed) Error() string {
	return fmt.Sprintf("failed to flush transient contexts: %v", e.Cause)
}

func (e *ErrFlushTransientContextsFailed) Unwrap() error { return e.Cause }
