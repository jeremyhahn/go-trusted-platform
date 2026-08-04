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

// ErrVMAttestorDeviceTPMRequired indicates the VM attestor device was
// constructed without a TPM.
type ErrVMAttestorDeviceTPMRequired struct{}

// Error implements the error interface.
func (e ErrVMAttestorDeviceTPMRequired) Error() string {
	return "vtpm: VM attestor device requires a TPM"
}

// ErrUnsupportedQuoteAlgorithm indicates a quote was requested with a hash
// algorithm the vTPM quote path does not support.
type ErrUnsupportedQuoteAlgorithm struct {
	Algorithm string
}

// Error implements the error interface.
func (e ErrUnsupportedQuoteAlgorithm) Error() string {
	return fmt.Sprintf("vtpm: unsupported quote hash algorithm %q: only sha256 is supported", e.Algorithm)
}

// ErrVMQuoteFailed indicates the vTPM quote operation failed.
type ErrVMQuoteFailed struct {
	Cause error
}

// Error implements the error interface.
func (e ErrVMQuoteFailed) Error() string {
	return fmt.Sprintf("vtpm: VM quote failed: %v", e.Cause)
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e ErrVMQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrPCRReadFailedVM indicates a vTPM PCR read failed.
type ErrPCRReadFailedVM struct {
	PCR   int
	Cause error
}

// Error implements the error interface.
func (e ErrPCRReadFailedVM) Error() string {
	return fmt.Sprintf("vtpm: failed to read PCR %d: %v", e.PCR, e.Cause)
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e ErrPCRReadFailedVM) Unwrap() error {
	return e.Cause
}

// ErrPCRBankValueNotFound indicates the requested PCR value was not present
// in the requested hash bank.
type ErrPCRBankValueNotFound struct {
	PCR       int
	Algorithm string
}

// Error implements the error interface.
func (e ErrPCRBankValueNotFound) Error() string {
	return fmt.Sprintf("vtpm: PCR %d not found in %s bank", e.PCR, e.Algorithm)
}

// ErrAIKPublicKeyUnavailable indicates the vTPM IAK public key could not be
// retrieved or encoded.
type ErrAIKPublicKeyUnavailable struct {
	Cause error
}

// Error implements the error interface.
func (e ErrAIKPublicKeyUnavailable) Error() string {
	return fmt.Sprintf("vtpm: AIK public key unavailable: %v", e.Cause)
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e ErrAIKPublicKeyUnavailable) Unwrap() error {
	return e.Cause
}

// ErrEKCertificateUnavailable indicates the vTPM EK certificate could not be
// retrieved.
type ErrEKCertificateUnavailable struct {
	Cause error
}

// Error implements the error interface.
func (e ErrEKCertificateUnavailable) Error() string {
	return fmt.Sprintf("vtpm: EK certificate unavailable: %v", e.Cause)
}

// Unwrap exposes the underlying cause for errors.Is / errors.As.
func (e ErrEKCertificateUnavailable) Unwrap() error {
	return e.Cause
}

// ErrVMAttestorDeviceNoEKCert indicates the vTPM returned no EK certificate.
type ErrVMAttestorDeviceNoEKCert struct{}

// Error implements the error interface.
func (e ErrVMAttestorDeviceNoEKCert) Error() string {
	return "vtpm: vTPM has no EK certificate"
}
