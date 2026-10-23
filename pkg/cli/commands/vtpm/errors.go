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

// ErrDaemonConnectionRequired is returned when daemon connection is required
// and carries the connection setup failure that caused it.
type ErrDaemonConnectionRequired struct {
	Err error
}

func (e ErrDaemonConnectionRequired) Error() string {
	if e.Err == nil {
		return "daemon connection required: this command requires a running platformd daemon"
	}
	return "daemon connection required: this command requires a running platformd daemon: " + e.Err.Error()
}

func (e ErrDaemonConnectionRequired) Unwrap() error {
	return e.Err
}

// ErrVTPMNotAvailable is returned when the vTPM service is not available
type ErrVTPMNotAvailable struct{}

func (e ErrVTPMNotAvailable) Error() string {
	return "vTPM service not available"
}

// ErrBundleNotFound is returned when a bundle cannot be found
type ErrBundleNotFound struct {
	ID string
}

func (e ErrBundleNotFound) Error() string {
	return fmt.Sprintf("bundle not found: %s", e.ID)
}

// ErrTemplateNotFound is returned when a template cannot be found
type ErrTemplateNotFound struct {
	ID string
}

func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("template not found: %s", e.ID)
}

// ErrInvalidEKAlgorithm is returned when an invalid EK algorithm is specified
type ErrInvalidEKAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidEKAlgorithm) Error() string {
	return fmt.Sprintf("invalid EK algorithm: %s (use RSA or ECC)", e.Algorithm)
}

// ErrInvalidBundleMode is returned when an invalid bundle mode is specified
type ErrInvalidBundleMode struct {
	Mode string
}

func (e ErrInvalidBundleMode) Error() string {
	return fmt.Sprintf("invalid bundle mode: %s (use template or pre-assigned)", e.Mode)
}

// ErrInvalidLabel is returned when a label is malformed
type ErrInvalidLabel struct {
	Label string
}

func (e ErrInvalidLabel) Error() string {
	return fmt.Sprintf("invalid label format: %s (use key=value)", e.Label)
}

// ErrCreateBundleFailed is returned when bundle creation fails
type ErrCreateBundleFailed struct {
	Reason string
}

func (e ErrCreateBundleFailed) Error() string {
	return fmt.Sprintf("failed to create bundle: %s", e.Reason)
}

// ErrDeleteBundleFailed is returned when bundle deletion fails
type ErrDeleteBundleFailed struct {
	Reason string
}

func (e ErrDeleteBundleFailed) Error() string {
	return fmt.Sprintf("failed to delete bundle: %s", e.Reason)
}

// ErrListBundlesFailed is returned when listing bundles fails
type ErrListBundlesFailed struct {
	Reason string
}

func (e ErrListBundlesFailed) Error() string {
	return fmt.Sprintf("failed to list bundles: %s", e.Reason)
}

// ErrGetBundleInfoFailed is returned when getting bundle info fails
type ErrGetBundleInfoFailed struct {
	Reason string
}

func (e ErrGetBundleInfoFailed) Error() string {
	return fmt.Sprintf("failed to get bundle info: %s", e.Reason)
}

// ErrCloneBundleFailed is returned when cloning a bundle fails
type ErrCloneBundleFailed struct {
	Reason string
}

func (e ErrCloneBundleFailed) Error() string {
	return fmt.Sprintf("failed to clone bundle: %s", e.Reason)
}

// ErrExportBundleFailed is returned when exporting a bundle fails
type ErrExportBundleFailed struct {
	Reason string
}

func (e ErrExportBundleFailed) Error() string {
	return fmt.Sprintf("failed to export bundle: %s", e.Reason)
}

// ErrImportBundleFailed is returned when importing a bundle fails
type ErrImportBundleFailed struct {
	Reason string
}

func (e ErrImportBundleFailed) Error() string {
	return fmt.Sprintf("failed to import bundle: %s", e.Reason)
}

// ErrCreateTemplateFailed is returned when template creation fails
type ErrCreateTemplateFailed struct {
	Reason string
}

func (e ErrCreateTemplateFailed) Error() string {
	return fmt.Sprintf("failed to create template: %s", e.Reason)
}

// ErrDeleteTemplateFailed is returned when template deletion fails
type ErrDeleteTemplateFailed struct {
	Reason string
}

func (e ErrDeleteTemplateFailed) Error() string {
	return fmt.Sprintf("failed to delete template: %s", e.Reason)
}

// ErrListTemplatesFailed is returned when listing templates fails
type ErrListTemplatesFailed struct {
	Reason string
}

func (e ErrListTemplatesFailed) Error() string {
	return fmt.Sprintf("failed to list templates: %s", e.Reason)
}

// ErrOutputFileExists is returned when an output file already exists
type ErrOutputFileExists struct {
	Path string
}

func (e ErrOutputFileExists) Error() string {
	return fmt.Sprintf("output file already exists: %s", e.Path)
}

// ErrCreateOutputFileFailed is returned when creating an output file fails
type ErrCreateOutputFileFailed struct {
	Path   string
	Reason string
}

func (e ErrCreateOutputFileFailed) Error() string {
	return fmt.Sprintf("failed to create output file %s: %s", e.Path, e.Reason)
}

// ErrOpenArchiveFailed is returned when opening an archive fails
type ErrOpenArchiveFailed struct {
	Path   string
	Reason string
}

func (e ErrOpenArchiveFailed) Error() string {
	return fmt.Sprintf("failed to open archive %s: %s", e.Path, e.Reason)
}

// ErrMissingRequiredFlag is returned when a required flag is missing
type ErrMissingRequiredFlag struct {
	Flag string
}

func (e ErrMissingRequiredFlag) Error() string {
	return fmt.Sprintf("missing required flag: --%s", e.Flag)
}

// ============================================================================
// Runtime TPM Operation Errors
// ============================================================================

// ErrStartVTPMFailed is returned when starting a vTPM fails
type ErrStartVTPMFailed struct {
	Reason string
}

func (e ErrStartVTPMFailed) Error() string {
	return fmt.Sprintf("failed to start vTPM: %s", e.Reason)
}

// ErrStopVTPMFailed is returned when stopping a vTPM fails
type ErrStopVTPMFailed struct {
	Reason string
}

func (e ErrStopVTPMFailed) Error() string {
	return fmt.Sprintf("failed to stop vTPM: %s", e.Reason)
}

// ErrIsRunningFailed is returned when checking vTPM running status fails
type ErrIsRunningFailed struct {
	Reason string
}

func (e ErrIsRunningFailed) Error() string {
	return fmt.Sprintf("failed to check vTPM running status: %s", e.Reason)
}

// ErrQuoteVTPMFailed is returned when generating a TPM quote fails
type ErrQuoteVTPMFailed struct {
	Reason string
}

func (e ErrQuoteVTPMFailed) Error() string {
	return fmt.Sprintf("failed to generate TPM quote: %s", e.Reason)
}

// ErrSealVTPMFailed is returned when sealing data to the TPM fails
type ErrSealVTPMFailed struct {
	Reason string
}

func (e ErrSealVTPMFailed) Error() string {
	return fmt.Sprintf("failed to seal data: %s", e.Reason)
}

// ErrUnsealVTPMFailed is returned when unsealing data from the TPM fails
type ErrUnsealVTPMFailed struct {
	Reason string
}

func (e ErrUnsealVTPMFailed) Error() string {
	return fmt.Sprintf("failed to unseal data: %s", e.Reason)
}

// ErrExtendPCRFailed is returned when extending a PCR fails
type ErrExtendPCRFailed struct {
	Reason string
}

func (e ErrExtendPCRFailed) Error() string {
	return fmt.Sprintf("failed to extend PCR: %s", e.Reason)
}

// ErrReadPCRFailed is returned when reading a PCR fails
type ErrReadPCRFailed struct {
	Reason string
}

func (e ErrReadPCRFailed) Error() string {
	return fmt.Sprintf("failed to read PCR: %s", e.Reason)
}

// ErrInvalidNonce is returned when a nonce is invalid
type ErrInvalidNonce struct {
	Reason string
}

func (e ErrInvalidNonce) Error() string {
	return fmt.Sprintf("invalid nonce: %s (must be hex-encoded)", e.Reason)
}

// ErrInvalidPCRIndex is returned when a PCR index is invalid
type ErrInvalidPCRIndex struct {
	Index  string
	Reason string
}

func (e ErrInvalidPCRIndex) Error() string {
	return fmt.Sprintf("invalid PCR index %s: %s", e.Index, e.Reason)
}

// ErrInvalidBase64Data is returned when base64-encoded data is invalid
type ErrInvalidBase64Data struct {
	Reason string
}

func (e ErrInvalidBase64Data) Error() string {
	return fmt.Sprintf("invalid base64 data: %s", e.Reason)
}

// ErrInvalidHexData is returned when hex-encoded data is invalid
type ErrInvalidHexData struct {
	Reason string
}

func (e ErrInvalidHexData) Error() string {
	return fmt.Sprintf("invalid hex data: %s", e.Reason)
}
