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

package vtpm

import "fmt"

// Bundle Errors

// ErrCreateBundleFailed is returned when bundle creation fails.
type ErrCreateBundleFailed struct {
	Cause error
}

func (e *ErrCreateBundleFailed) Error() string {
	return fmt.Sprintf("failed to create vTPM bundle: %v", e.Cause)
}

func (e *ErrCreateBundleFailed) Unwrap() error {
	return e.Cause
}

// ErrGetBundleFailed is returned when getting a bundle fails.
type ErrGetBundleFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetBundleFailed) Error() string {
	return fmt.Sprintf("failed to get vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrGetBundleFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteBundleFailed is returned when deleting a bundle fails.
type ErrDeleteBundleFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteBundleFailed) Error() string {
	return fmt.Sprintf("failed to delete vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteBundleFailed) Unwrap() error {
	return e.Cause
}

// ErrListBundlesFailed is returned when listing bundles fails.
type ErrListBundlesFailed struct {
	Cause error
}

func (e *ErrListBundlesFailed) Error() string {
	return fmt.Sprintf("failed to list vTPM bundles: %v", e.Cause)
}

func (e *ErrListBundlesFailed) Unwrap() error {
	return e.Cause
}

// Template Errors

// ErrCreateTemplateFailed is returned when template creation fails.
type ErrCreateTemplateFailed struct {
	Cause error
}

func (e *ErrCreateTemplateFailed) Error() string {
	return fmt.Sprintf("failed to create vTPM template: %v", e.Cause)
}

func (e *ErrCreateTemplateFailed) Unwrap() error {
	return e.Cause
}

// ErrGetTemplateFailed is returned when getting a template fails.
type ErrGetTemplateFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetTemplateFailed) Error() string {
	return fmt.Sprintf("failed to get vTPM template %s: %v", e.ID, e.Cause)
}

func (e *ErrGetTemplateFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteTemplateFailed is returned when deleting a template fails.
type ErrDeleteTemplateFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteTemplateFailed) Error() string {
	return fmt.Sprintf("failed to delete vTPM template %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteTemplateFailed) Unwrap() error {
	return e.Cause
}

// ErrListTemplatesFailed is returned when listing templates fails.
type ErrListTemplatesFailed struct {
	Cause error
}

func (e *ErrListTemplatesFailed) Error() string {
	return fmt.Sprintf("failed to list vTPM templates: %v", e.Cause)
}

func (e *ErrListTemplatesFailed) Unwrap() error {
	return e.Cause
}

// ErrCloneTemplateFailed is returned when cloning a template fails.
type ErrCloneTemplateFailed struct {
	TemplateID string
	Cause      error
}

func (e *ErrCloneTemplateFailed) Error() string {
	return fmt.Sprintf("failed to clone vTPM template %s: %v", e.TemplateID, e.Cause)
}

func (e *ErrCloneTemplateFailed) Unwrap() error {
	return e.Cause
}

// Export/Import Errors

// ErrExportBundleFailed is returned when exporting a bundle fails.
type ErrExportBundleFailed struct {
	ID    string
	Cause error
}

func (e *ErrExportBundleFailed) Error() string {
	return fmt.Sprintf("failed to export vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrExportBundleFailed) Unwrap() error {
	return e.Cause
}

// ErrImportBundleFailed is returned when importing a bundle fails.
type ErrImportBundleFailed struct {
	Cause error
}

func (e *ErrImportBundleFailed) Error() string {
	return fmt.Sprintf("failed to import vTPM bundle: %v", e.Cause)
}

func (e *ErrImportBundleFailed) Unwrap() error {
	return e.Cause
}

// Validation Errors

// ErrValidateBundleFailed is returned when validating a bundle fails.
type ErrValidateBundleFailed struct {
	ID    string
	Cause error
}

func (e *ErrValidateBundleFailed) Error() string {
	return fmt.Sprintf("failed to validate vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrValidateBundleFailed) Unwrap() error {
	return e.Cause
}

// Path Getter Errors

// ErrGetBundlePathFailed is returned when getting bundle path fails.
type ErrGetBundlePathFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetBundlePathFailed) Error() string {
	return fmt.Sprintf("failed to get path for vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrGetBundlePathFailed) Unwrap() error {
	return e.Cause
}

// ErrGetTPMSocketPathFailed is returned when getting TPM socket path fails.
type ErrGetTPMSocketPathFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetTPMSocketPathFailed) Error() string {
	return fmt.Sprintf("failed to get TPM socket path for vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrGetTPMSocketPathFailed) Unwrap() error {
	return e.Cause
}

// ErrGetNVRAMPathFailed is returned when getting NVRAM path fails.
type ErrGetNVRAMPathFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetNVRAMPathFailed) Error() string {
	return fmt.Sprintf("failed to get NVRAM path for vTPM bundle %s: %v", e.ID, e.Cause)
}

func (e *ErrGetNVRAMPathFailed) Unwrap() error {
	return e.Cause
}

// Instance Errors

// ErrCreateInstanceFailed is returned when instance creation fails.
type ErrCreateInstanceFailed struct {
	Cause error
}

func (e *ErrCreateInstanceFailed) Error() string {
	return fmt.Sprintf("failed to create vTPM instance: %v", e.Cause)
}

func (e *ErrCreateInstanceFailed) Unwrap() error {
	return e.Cause
}

// ErrGetInstanceFailed is returned when getting an instance fails.
type ErrGetInstanceFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetInstanceFailed) Error() string {
	return fmt.Sprintf("failed to get vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrGetInstanceFailed) Unwrap() error {
	return e.Cause
}

// ErrGetInstanceByProfileFailed is returned when getting an instance by profile fails.
type ErrGetInstanceByProfileFailed struct {
	ProfileID uint64
	Cause     error
}

func (e *ErrGetInstanceByProfileFailed) Error() string {
	return fmt.Sprintf("failed to get vTPM instance for profile %d: %v", e.ProfileID, e.Cause)
}

func (e *ErrGetInstanceByProfileFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteInstanceFailed is returned when deleting an instance fails.
type ErrDeleteInstanceFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteInstanceFailed) Error() string {
	return fmt.Sprintf("failed to delete vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteInstanceFailed) Unwrap() error {
	return e.Cause
}

// ErrListInstancesFailed is returned when listing instances fails.
type ErrListInstancesFailed struct {
	Cause error
}

func (e *ErrListInstancesFailed) Error() string {
	return fmt.Sprintf("failed to list vTPM instances: %v", e.Cause)
}

func (e *ErrListInstancesFailed) Unwrap() error {
	return e.Cause
}

// ErrStartInstanceFailed is returned when starting an instance fails.
type ErrStartInstanceFailed struct {
	ID    string
	Cause error
}

func (e *ErrStartInstanceFailed) Error() string {
	return fmt.Sprintf("failed to start vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrStartInstanceFailed) Unwrap() error {
	return e.Cause
}

// ErrStopInstanceFailed is returned when stopping an instance fails.
type ErrStopInstanceFailed struct {
	ID    string
	Cause error
}

func (e *ErrStopInstanceFailed) Error() string {
	return fmt.Sprintf("failed to stop vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrStopInstanceFailed) Unwrap() error {
	return e.Cause
}

// ErrGetInstanceStatusFailed is returned when getting instance status fails.
type ErrGetInstanceStatusFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetInstanceStatusFailed) Error() string {
	return fmt.Sprintf("failed to get status for vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrGetInstanceStatusFailed) Unwrap() error {
	return e.Cause
}

// ErrExportEKCertFailed is returned when exporting an EK certificate fails.
type ErrExportEKCertFailed struct {
	ID    string
	Cause error
}

func (e *ErrExportEKCertFailed) Error() string {
	return fmt.Sprintf("failed to export EK certificate for vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrExportEKCertFailed) Unwrap() error {
	return e.Cause
}

// ErrGetEKFingerprintFailed is returned when getting an EK fingerprint fails.
type ErrGetEKFingerprintFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetEKFingerprintFailed) Error() string {
	return fmt.Sprintf("failed to get EK fingerprint for vTPM instance %s: %v", e.ID, e.Cause)
}

func (e *ErrGetEKFingerprintFailed) Unwrap() error {
	return e.Cause
}

// Lifecycle Errors

// ErrStartFailed is returned when starting a vTPM fails.
type ErrStartFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrStartFailed) Error() string {
	return fmt.Sprintf("failed to start vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrStartFailed) Unwrap() error { return e.Cause }

// ErrStopFailed is returned when stopping a vTPM fails.
type ErrStopFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrStopFailed) Error() string {
	return fmt.Sprintf("failed to stop vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrStopFailed) Unwrap() error { return e.Cause }

// ErrIsRunningFailed is returned when checking if a vTPM is running fails.
type ErrIsRunningFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrIsRunningFailed) Error() string {
	return fmt.Sprintf("failed to check vTPM running status %s: %v", e.BundleID, e.Cause)
}

func (e *ErrIsRunningFailed) Unwrap() error { return e.Cause }

// ErrQuoteFailed is returned when generating a vTPM quote fails.
type ErrQuoteFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrQuoteFailed) Error() string {
	return fmt.Sprintf("failed to generate vTPM quote %s: %v", e.BundleID, e.Cause)
}

func (e *ErrQuoteFailed) Unwrap() error { return e.Cause }

// ErrSealFailed is returned when sealing data to a vTPM fails.
type ErrSealFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrSealFailed) Error() string {
	return fmt.Sprintf("failed to seal data to vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrSealFailed) Unwrap() error { return e.Cause }

// ErrUnsealFailed is returned when unsealing data from a vTPM fails.
type ErrUnsealFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrUnsealFailed) Error() string {
	return fmt.Sprintf("failed to unseal data from vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrUnsealFailed) Unwrap() error { return e.Cause }

// ErrExtendPCRFailed is returned when extending a PCR fails.
type ErrExtendPCRFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrExtendPCRFailed) Error() string {
	return fmt.Sprintf("failed to extend PCR for vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrExtendPCRFailed) Unwrap() error { return e.Cause }

// ErrReadPCRFailed is returned when reading a PCR fails.
type ErrReadPCRFailed struct {
	BundleID string
	Cause    error
}

func (e *ErrReadPCRFailed) Error() string {
	return fmt.Sprintf("failed to read PCR for vTPM %s: %v", e.BundleID, e.Cause)
}

func (e *ErrReadPCRFailed) Unwrap() error { return e.Cause }
