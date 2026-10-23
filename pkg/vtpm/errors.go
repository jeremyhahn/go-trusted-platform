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

// =============================================================================
// Generator Errors
// =============================================================================

// ErrVTPMNotFound indicates the requested vTPM instance does not exist.
type ErrVTPMNotFound struct {
	ID string
}

func (e ErrVTPMNotFound) Error() string {
	return fmt.Sprintf("vtpm: instance not found: %s", e.ID)
}

// ErrVTPMAlreadyExists indicates a vTPM instance with the ID already exists.
type ErrVTPMAlreadyExists struct {
	ID string
}

func (e ErrVTPMAlreadyExists) Error() string {
	return fmt.Sprintf("vtpm: instance already exists: %s", e.ID)
}

// ErrGenerationFailed indicates vTPM generation failed.
type ErrGenerationFailed struct {
	Reason string
	Cause  error
}

func (e ErrGenerationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vtpm: generation failed: %s: %v", e.Reason, e.Cause)
	}
	return fmt.Sprintf("vtpm: generation failed: %s", e.Reason)
}

func (e ErrGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileNotAssociated indicates no vTPM instance is associated with the profile.
type ErrProfileNotAssociated struct {
	ProfileID uint64
}

func (e ErrProfileNotAssociated) Error() string {
	return fmt.Sprintf("vtpm: no instance associated with profile ID: %d", e.ProfileID)
}

// ErrProfileAssignmentFailed indicates the EK serial assignment to a device profile failed.
type ErrProfileAssignmentFailed struct {
	ProfileID uint64
	EKSerial  string
	Cause     error
}

func (e ErrProfileAssignmentFailed) Error() string {
	return fmt.Sprintf("vtpm: failed to assign EK serial %s to profile %d: %v",
		e.EKSerial, e.ProfileID, e.Cause)
}

func (e ErrProfileAssignmentFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Bundle Errors
// =============================================================================

// ErrBundleNotFound indicates the requested bundle does not exist.
type ErrBundleNotFound struct {
	ID string
}

func (e ErrBundleNotFound) Error() string {
	return fmt.Sprintf("vtpm: bundle not found: %s", e.ID)
}

// ErrBundleAlreadyExists indicates a bundle with the ID already exists.
type ErrBundleAlreadyExists struct {
	ID string
}

func (e ErrBundleAlreadyExists) Error() string {
	return fmt.Sprintf("vtpm: bundle already exists: %s", e.ID)
}

// ErrTemplateNotFound indicates the requested template does not exist.
type ErrTemplateNotFound struct {
	ID string
}

func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("vtpm: template not found: %s", e.ID)
}

// ErrTemplateAlreadyExists indicates a template with the ID already exists.
type ErrTemplateAlreadyExists struct {
	ID string
}

func (e ErrTemplateAlreadyExists) Error() string {
	return fmt.Sprintf("vtpm: template already exists: %s", e.ID)
}

// ErrMissingHostname indicates hostname was not provided for an operation that requires it.
type ErrMissingHostname struct{}

func (e ErrMissingHostname) Error() string {
	return "vtpm: hostname is required"
}

// ErrInvalidManifest indicates the manifest is invalid or corrupted.
type ErrInvalidManifest struct {
	Reason string
}

func (e ErrInvalidManifest) Error() string {
	return fmt.Sprintf("vtpm: invalid manifest: %s", e.Reason)
}

// =============================================================================
// TPM Key Errors
// =============================================================================

// ErrEKCertInjectionFailed indicates EK certificate injection to NV RAM failed.
type ErrEKCertInjectionFailed struct {
	Cause error
}

func (e ErrEKCertInjectionFailed) Error() string {
	return fmt.Sprintf("vtpm: EK certificate injection failed: %v", e.Cause)
}

func (e ErrEKCertInjectionFailed) Unwrap() error {
	return e.Cause
}

// ErrEKGenerationFailed indicates EK generation failed.
type ErrEKGenerationFailed struct {
	Cause error
}

func (e ErrEKGenerationFailed) Error() string {
	return fmt.Sprintf("vtpm: EK generation failed: %v", e.Cause)
}

func (e ErrEKGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrSRKGenerationFailed indicates SRK generation failed.
type ErrSRKGenerationFailed struct {
	Cause error
}

func (e ErrSRKGenerationFailed) Error() string {
	return fmt.Sprintf("vtpm: SRK generation failed: %v", e.Cause)
}

func (e ErrSRKGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrSecureBootEnrollmentFailed indicates Secure Boot key enrollment failed.
type ErrSecureBootEnrollmentFailed struct {
	Cause error
}

func (e ErrSecureBootEnrollmentFailed) Error() string {
	return fmt.Sprintf("vtpm: Secure Boot enrollment failed: %v", e.Cause)
}

func (e ErrSecureBootEnrollmentFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// SWTPM Errors
// =============================================================================

// ErrSWTPMOperationFailed indicates an swtpm operation failed.
type ErrSWTPMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSWTPMOperationFailed) Error() string {
	return fmt.Sprintf("vtpm: swtpm %s failed: %v", e.Operation, e.Cause)
}

func (e ErrSWTPMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrNVRAMWriteFailed indicates writing to TPM NV RAM failed.
type ErrNVRAMWriteFailed struct {
	NVIndex uint32
	Cause   error
}

func (e ErrNVRAMWriteFailed) Error() string {
	return fmt.Sprintf("vtpm: NV RAM write failed at index 0x%08X: %v", e.NVIndex, e.Cause)
}

func (e ErrNVRAMWriteFailed) Unwrap() error {
	return e.Cause
}

// ErrNVBufferMaxUnavailable indicates the TPM did not report a usable
// TPM_PT_NV_BUFFER_MAX, so no NV transfer size can be chosen.
type ErrNVBufferMaxUnavailable struct {
	Cause error
}

func (e ErrNVBufferMaxUnavailable) Error() string {
	return fmt.Sprintf("vtpm: TPM_PT_NV_BUFFER_MAX unavailable: %v", e.Cause)
}

func (e ErrNVBufferMaxUnavailable) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Archive Errors
// =============================================================================

// ErrArchiveOperationFailed indicates an archive export/import operation failed.
type ErrArchiveOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrArchiveOperationFailed) Error() string {
	return fmt.Sprintf("vtpm: archive %s failed: %v", e.Operation, e.Cause)
}

func (e ErrArchiveOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Configuration Errors
// =============================================================================

// ErrCAUnavailable indicates the CA service is not available.
type ErrCAUnavailable struct {
	Cause error
}

func (e ErrCAUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vtpm: CA unavailable: %v", e.Cause)
	}
	return "vtpm: CA unavailable"
}

func (e ErrCAUnavailable) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig indicates invalid configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("vtpm: invalid config for %s: %s", e.Field, e.Reason)
}

// ErrInvalidEKAlgorithm indicates a requested EK algorithm is neither RSA
// nor ECC.
type ErrInvalidEKAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidEKAlgorithm) Error() string {
	return fmt.Sprintf("vtpm: invalid EK algorithm %q (must be RSA or ECC)", e.Algorithm)
}

// ErrChecksumMismatch indicates a file checksum does not match the manifest.
type ErrChecksumMismatch struct {
	File     string
	Expected string
	Actual   string
}

func (e ErrChecksumMismatch) Error() string {
	return fmt.Sprintf("vtpm: checksum mismatch for %s: expected %s, got %s", e.File, e.Expected, e.Actual)
}

// ErrSecureBootKeyGenFailed indicates Secure Boot key generation failed.
type ErrSecureBootKeyGenFailed struct {
	Cause error
}

func (e ErrSecureBootKeyGenFailed) Error() string {
	return fmt.Sprintf("vtpm: Secure Boot key generation failed: %v", e.Cause)
}

func (e ErrSecureBootKeyGenFailed) Unwrap() error {
	return e.Cause
}

// ErrOVMFNotFound indicates OVMF firmware files are missing.
type ErrOVMFNotFound struct {
	Path string
}

func (e ErrOVMFNotFound) Error() string {
	return fmt.Sprintf("vtpm: OVMF not found: %s", e.Path)
}

// =============================================================================
// Runtime TPM Operation Errors
// =============================================================================

// ErrVTPMNotRunning indicates the vTPM is not running for the specified bundle.
type ErrVTPMNotRunning struct {
	BundleID string
}

func (e ErrVTPMNotRunning) Error() string {
	return fmt.Sprintf("vtpm: vTPM not running for bundle: %s", e.BundleID)
}

// ErrVTPMAlreadyRunning indicates the vTPM is already running for the specified bundle.
type ErrVTPMAlreadyRunning struct {
	BundleID string
}

func (e ErrVTPMAlreadyRunning) Error() string {
	return fmt.Sprintf("vtpm: vTPM already running for bundle: %s", e.BundleID)
}

// ErrVTPMStartFailed indicates the vTPM failed to start.
type ErrVTPMStartFailed struct {
	BundleID string
	Cause    error
}

func (e ErrVTPMStartFailed) Error() string {
	return fmt.Sprintf("vtpm: failed to start vTPM for bundle %s: %v", e.BundleID, e.Cause)
}

func (e ErrVTPMStartFailed) Unwrap() error {
	return e.Cause
}

// ErrVTPMStopFailed indicates the vTPM failed to stop.
type ErrVTPMStopFailed struct {
	BundleID string
	Cause    error
}

func (e ErrVTPMStopFailed) Error() string {
	return fmt.Sprintf("vtpm: failed to stop vTPM for bundle %s: %v", e.BundleID, e.Cause)
}

func (e ErrVTPMStopFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMQuoteFailed indicates a TPM quote operation failed.
// ErrVTPMAttestationKeyMissing indicates a provisioned vTPM holds no usable
// IAK at its persistent handle, so it cannot sign a quote.
type ErrVTPMAttestationKeyMissing struct {
	SocketPath string
	Cause      error
}

func (e ErrVTPMAttestationKeyMissing) Error() string {
	return fmt.Sprintf("vtpm: the provisioned vTPM at %s has no attestation key: %v", e.SocketPath, e.Cause)
}

func (e ErrVTPMAttestationKeyMissing) Unwrap() error {
	return e.Cause
}

type ErrTPMQuoteFailed struct {
	BundleID string
	Cause    error
}

func (e ErrTPMQuoteFailed) Error() string {
	return fmt.Sprintf("vtpm: TPM quote failed for bundle %s: %v", e.BundleID, e.Cause)
}

func (e ErrTPMQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMSealFailed indicates a TPM seal operation failed.
type ErrTPMSealFailed struct {
	BundleID string
	Cause    error
}

func (e ErrTPMSealFailed) Error() string {
	return fmt.Sprintf("vtpm: TPM seal failed for bundle %s: %v", e.BundleID, e.Cause)
}

func (e ErrTPMSealFailed) Unwrap() error {
	return e.Cause
}

// ErrTPMUnsealFailed indicates a TPM unseal operation failed.
type ErrTPMUnsealFailed struct {
	BundleID string
	Cause    error
}

func (e ErrTPMUnsealFailed) Error() string {
	return fmt.Sprintf("vtpm: TPM unseal failed for bundle %s: %v", e.BundleID, e.Cause)
}

func (e ErrTPMUnsealFailed) Unwrap() error {
	return e.Cause
}

// ErrPCRExtendFailed indicates a PCR extend operation failed.
type ErrPCRExtendFailed struct {
	BundleID string
	PCRIndex int
	Cause    error
}

func (e ErrPCRExtendFailed) Error() string {
	return fmt.Sprintf("vtpm: PCR extend failed for bundle %s, PCR %d: %v", e.BundleID, e.PCRIndex, e.Cause)
}

func (e ErrPCRExtendFailed) Unwrap() error {
	return e.Cause
}

// ErrPCRReadFailed indicates a PCR read operation failed.
type ErrPCRReadFailed struct {
	BundleID string
	PCRIndex int
	Cause    error
}

func (e ErrPCRReadFailed) Error() string {
	return fmt.Sprintf("vtpm: PCR read failed for bundle %s, PCR %d: %v", e.BundleID, e.PCRIndex, e.Cause)
}

func (e ErrPCRReadFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPCRIndex indicates an invalid PCR index was specified.
type ErrInvalidPCRIndex struct {
	PCRIndex int
}

func (e ErrInvalidPCRIndex) Error() string {
	return fmt.Sprintf("vtpm: invalid PCR index: %d (must be 0-23)", e.PCRIndex)
}

// ErrInvalidNonce indicates an invalid nonce was provided.
type ErrInvalidNonce struct {
	Reason string
}

func (e ErrInvalidNonce) Error() string {
	return fmt.Sprintf("vtpm: invalid nonce: %s", e.Reason)
}

// ErrTPMConnectionFailed indicates a connection to the TPM socket failed.
type ErrTPMConnectionFailed struct {
	SocketPath string
	Cause      error
}

func (e ErrTPMConnectionFailed) Error() string {
	return fmt.Sprintf("vtpm: failed to connect to TPM socket %s: %v", e.SocketPath, e.Cause)
}

func (e ErrTPMConnectionFailed) Unwrap() error {
	return e.Cause
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
