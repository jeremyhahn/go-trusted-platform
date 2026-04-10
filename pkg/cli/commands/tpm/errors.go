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

package tpm

import "fmt"

// ErrInvalidAlgorithm is returned when an invalid key algorithm is specified
type ErrInvalidAlgorithm struct {
	Algorithm string
	Valid     []string
}

func (e ErrInvalidAlgorithm) Error() string {
	return fmt.Sprintf("invalid algorithm '%s': valid options are %v", e.Algorithm, e.Valid)
}

// ErrIDevIDNotFound is returned when IDevID key is not found
type ErrIDevIDNotFound struct{}

func (e ErrIDevIDNotFound) Error() string {
	return "IDevID key not found in TPM"
}

// ErrIAKNotFound is returned when IAK key is not found
type ErrIAKNotFound struct{}

func (e ErrIAKNotFound) Error() string {
	return "IAK key not found in TPM"
}

// ErrIDevIDAlreadyExists is returned when IDevID key already exists
type ErrIDevIDAlreadyExists struct{}

func (e ErrIDevIDAlreadyExists) Error() string {
	return "IDevID key already exists in TPM; use --overwrite to replace"
}

// ErrIAKAlreadyExists is returned when IAK key already exists
type ErrIAKAlreadyExists struct{}

func (e ErrIAKAlreadyExists) Error() string {
	return "IAK key already exists in TPM; use --overwrite to replace"
}

// ErrGenerateIDevIDFailed is returned when IDevID generation fails
type ErrGenerateIDevIDFailed struct {
	Reason string
}

func (e ErrGenerateIDevIDFailed) Error() string {
	return fmt.Sprintf("failed to generate IDevID: %s", e.Reason)
}

// ErrGenerateIAKFailed is returned when IAK generation fails
type ErrGenerateIAKFailed struct {
	Reason string
}

func (e ErrGenerateIAKFailed) Error() string {
	return fmt.Sprintf("failed to generate IAK: %s", e.Reason)
}

// ErrDeleteIDevIDFailed is returned when IDevID deletion fails
type ErrDeleteIDevIDFailed struct {
	Reason string
}

func (e ErrDeleteIDevIDFailed) Error() string {
	return fmt.Sprintf("failed to delete IDevID: %s", e.Reason)
}

// ErrDeleteIAKFailed is returned when IAK deletion fails
type ErrDeleteIAKFailed struct {
	Reason string
}

func (e ErrDeleteIAKFailed) Error() string {
	return fmt.Sprintf("failed to delete IAK: %s", e.Reason)
}

// ErrGetIDevIDInfoFailed is returned when getting IDevID info fails
type ErrGetIDevIDInfoFailed struct {
	Reason string
}

func (e ErrGetIDevIDInfoFailed) Error() string {
	return fmt.Sprintf("failed to get IDevID info: %s", e.Reason)
}

// ErrGetIAKInfoFailed is returned when getting IAK info fails
type ErrGetIAKInfoFailed struct {
	Reason string
}

func (e ErrGetIAKInfoFailed) Error() string {
	return fmt.Sprintf("failed to get IAK info: %s", e.Reason)
}

// ErrFlushFailed is returned when flushing transient contexts fails
type ErrFlushFailed struct {
	Reason string
}

func (e ErrFlushFailed) Error() string {
	return fmt.Sprintf("failed to flush transient contexts: %s", e.Reason)
}

// ErrGetDeviceAttributesFailed is returned when getting device attributes fails
type ErrGetDeviceAttributesFailed struct {
	Reason string
}

func (e ErrGetDeviceAttributesFailed) Error() string {
	return fmt.Sprintf("failed to get device attributes: %s", e.Reason)
}

// ErrCreateIDevIDCSRFailed is returned when IDevID CSR creation fails
type ErrCreateIDevIDCSRFailed struct {
	Reason string
}

func (e ErrCreateIDevIDCSRFailed) Error() string {
	return fmt.Sprintf("failed to create IDevID CSR: %s", e.Reason)
}

// ErrCreateIAKCSRFailed is returned when IAK CSR creation fails
type ErrCreateIAKCSRFailed struct {
	Reason string
}

func (e ErrCreateIAKCSRFailed) Error() string {
	return fmt.Sprintf("failed to create IAK CSR: %s", e.Reason)
}

// ErrInstallIDevIDCertificateFailed is returned when IDevID certificate installation fails
type ErrInstallIDevIDCertificateFailed struct {
	Reason string
}

func (e ErrInstallIDevIDCertificateFailed) Error() string {
	return fmt.Sprintf("failed to install IDevID certificate: %s", e.Reason)
}

// ErrInstallIAKCertificateFailed is returned when IAK certificate installation fails
type ErrInstallIAKCertificateFailed struct {
	Reason string
}

func (e ErrInstallIAKCertificateFailed) Error() string {
	return fmt.Sprintf("failed to install IAK certificate: %s", e.Reason)
}

// ErrGetIDevIDCertificateFailed is returned when getting IDevID certificate fails
type ErrGetIDevIDCertificateFailed struct {
	Reason string
}

func (e ErrGetIDevIDCertificateFailed) Error() string {
	return fmt.Sprintf("failed to get IDevID certificate: %s", e.Reason)
}

// ErrGetIAKCertificateFailed is returned when getting IAK certificate fails
type ErrGetIAKCertificateFailed struct {
	Reason string
}

func (e ErrGetIAKCertificateFailed) Error() string {
	return fmt.Sprintf("failed to get IAK certificate: %s", e.Reason)
}

// ErrIDevIDCertificateNotFound is returned when IDevID certificate is not found
type ErrIDevIDCertificateNotFound struct{}

func (e ErrIDevIDCertificateNotFound) Error() string {
	return "IDevID certificate not found"
}

// ErrIAKCertificateNotFound is returned when IAK certificate is not found
type ErrIAKCertificateNotFound struct{}

func (e ErrIAKCertificateNotFound) Error() string {
	return "IAK certificate not found"
}

// =============================================================================
// TPM Service Errors
// =============================================================================

// ErrTPMInfoFailed is returned when getting TPM info fails
type ErrTPMInfoFailed struct {
	Reason string
}

func (e ErrTPMInfoFailed) Error() string {
	return fmt.Sprintf("failed to get TPM info: %s", e.Reason)
}

// ErrTPMProvisionFailed is returned when TPM provisioning fails
type ErrTPMProvisionFailed struct {
	Reason string
}

func (e ErrTPMProvisionFailed) Error() string {
	return fmt.Sprintf("failed to provision TPM: %s", e.Reason)
}

// ErrTPMClearFailed is returned when TPM clear fails
type ErrTPMClearFailed struct {
	Reason string
}

func (e ErrTPMClearFailed) Error() string {
	return fmt.Sprintf("failed to clear TPM: %s", e.Reason)
}

// ErrDaemonConnectionRequired is returned when an operation requires daemon connection
type ErrDaemonConnectionRequired struct {
	Operation string
}

func (e ErrDaemonConnectionRequired) Error() string {
	return fmt.Sprintf("daemon connection required: operation '%s' not yet supported", e.Operation)
}

// =============================================================================
// EK Errors
// =============================================================================

// ErrEKCreateFailed is returned when EK creation fails
type ErrEKCreateFailed struct {
	Reason string
}

func (e ErrEKCreateFailed) Error() string {
	return fmt.Sprintf("failed to create EK: %s", e.Reason)
}

// ErrEKNotFound is returned when EK is not found
type ErrEKNotFound struct {
	Reason string
}

func (e ErrEKNotFound) Error() string {
	return fmt.Sprintf("EK not found: %s", e.Reason)
}

// ErrEKCertificateNotFound is returned when EK certificate is not found
type ErrEKCertificateNotFound struct {
	Reason string
}

func (e ErrEKCertificateNotFound) Error() string {
	return fmt.Sprintf("EK certificate not found: %s", e.Reason)
}

// ErrEKDeleteFailed is returned when EK deletion fails
type ErrEKDeleteFailed struct {
	Reason string
}

func (e ErrEKDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete EK: %s", e.Reason)
}

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is specified
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// =============================================================================
// SRK Errors
// =============================================================================

// ErrSRKCreateFailed is returned when SRK creation fails
type ErrSRKCreateFailed struct {
	Reason string
}

func (e ErrSRKCreateFailed) Error() string {
	return fmt.Sprintf("failed to create SRK: %s", e.Reason)
}

// ErrSRKNotFound is returned when SRK is not found
type ErrSRKNotFound struct {
	Reason string
}

func (e ErrSRKNotFound) Error() string {
	return fmt.Sprintf("SRK not found: %s", e.Reason)
}

// ErrSRKDeleteFailed is returned when SRK deletion fails
type ErrSRKDeleteFailed struct {
	Reason string
}

func (e ErrSRKDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete SRK: %s", e.Reason)
}

// =============================================================================
// Seal/Unseal Errors
// =============================================================================

// ErrSealFailed is returned when sealing data fails
type ErrSealFailed struct {
	Reason string
}

func (e ErrSealFailed) Error() string {
	return fmt.Sprintf("failed to seal data: %s", e.Reason)
}

// ErrUnsealFailed is returned when unsealing data fails
type ErrUnsealFailed struct {
	Reason string
}

func (e ErrUnsealFailed) Error() string {
	return fmt.Sprintf("failed to unseal data: %s", e.Reason)
}

// =============================================================================
// Event Log Errors
// =============================================================================

// ErrEventLogFailed is returned when getting event log fails
type ErrEventLogFailed struct {
	Reason string
}

func (e ErrEventLogFailed) Error() string {
	return fmt.Sprintf("failed to get event log: %s", e.Reason)
}

// =============================================================================
// NVRAM Errors
// =============================================================================

// ErrNVRAMDefineFailed is returned when NVRAM define fails
type ErrNVRAMDefineFailed struct {
	Index  uint32
	Reason string
}

func (e ErrNVRAMDefineFailed) Error() string {
	return fmt.Sprintf("failed to define NV index 0x%08X: %s", e.Index, e.Reason)
}

// ErrNVRAMWriteFailed is returned when NVRAM write fails
type ErrNVRAMWriteFailed struct {
	Index  uint32
	Reason string
}

func (e ErrNVRAMWriteFailed) Error() string {
	return fmt.Sprintf("failed to write NV index 0x%08X: %s", e.Index, e.Reason)
}

// ErrNVRAMReadFailed is returned when NVRAM read fails
type ErrNVRAMReadFailed struct {
	Index  uint32
	Reason string
}

func (e ErrNVRAMReadFailed) Error() string {
	return fmt.Sprintf("failed to read NV index 0x%08X: %s", e.Index, e.Reason)
}

// ErrNVRAMDeleteFailed is returned when NVRAM delete fails
type ErrNVRAMDeleteFailed struct {
	Index  uint32
	Reason string
}

func (e ErrNVRAMDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete NV index 0x%08X: %s", e.Index, e.Reason)
}
