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

package vm

import "fmt"

// ErrQuoteGenerationFailed indicates that TPM quote generation failed.
type ErrQuoteGenerationFailed struct {
	Reason string
	Cause  error
}

func (e ErrQuoteGenerationFailed) Error() string {
	msg := "vm: quote generation failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrQuoteGenerationFailed) Unwrap() error {
	return e.Cause
}

// ErrQuoteVerificationFailed indicates that TPM quote verification failed.
type ErrQuoteVerificationFailed struct {
	Reason string
	Cause  error
}

func (e ErrQuoteVerificationFailed) Error() string {
	msg := "vm: quote verification failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrQuoteVerificationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidVMIdentity indicates that the VM identity is invalid or malformed.
type ErrInvalidVMIdentity struct {
	VMID   string
	HostID string
	Reason string
}

func (e ErrInvalidVMIdentity) Error() string {
	msg := "vm: invalid VM identity"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.VMID != "" || e.HostID != "" {
		msg = fmt.Sprintf("%s (vmID=%q, hostID=%q)", msg, e.VMID, e.HostID)
	}
	return msg
}

// ErrEKCertificateInvalid indicates that the EK certificate is invalid.
type ErrEKCertificateInvalid struct {
	Reason string
	Cause  error
}

func (e ErrEKCertificateInvalid) Error() string {
	msg := "vm: EK certificate invalid"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrEKCertificateInvalid) Unwrap() error {
	return e.Cause
}

// ErrPCRMismatch indicates that PCR values do not match expected values.
type ErrPCRMismatch struct {
	PCRIndex      int
	ExpectedValue []byte
	ActualValue   []byte
}

func (e ErrPCRMismatch) Error() string {
	return fmt.Sprintf("vm: PCR %d mismatch: expected %x, got %x",
		e.PCRIndex, e.ExpectedValue, e.ActualValue)
}

// ErrNonceMismatch indicates that the nonce in the quote does not match the expected nonce.
type ErrNonceMismatch struct {
	Expected []byte
	Actual   []byte
}

func (e ErrNonceMismatch) Error() string {
	return fmt.Sprintf("vm: nonce mismatch: expected %x, got %x", e.Expected, e.Actual)
}

// ErrVTPMNotAvailable indicates that the vTPM is not available or accessible.
type ErrVTPMNotAvailable struct {
	Reason string
	Cause  error
}

func (e ErrVTPMNotAvailable) Error() string {
	msg := "vm: vTPM not available"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrVTPMNotAvailable) Unwrap() error {
	return e.Cause
}

// ErrAIKNotFound indicates that the AIK/AK was not found in the vTPM.
type ErrAIKNotFound struct {
	Reason string
}

func (e ErrAIKNotFound) Error() string {
	msg := "vm: AIK/AK not found"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrAttestorNotInitialized indicates that the attestor has not been initialized.
type ErrAttestorNotInitialized struct{}

func (e ErrAttestorNotInitialized) Error() string {
	return "vm: attestor not initialized"
}

// ErrVerifierNotInitialized indicates that the verifier has not been initialized.
type ErrVerifierNotInitialized struct{}

func (e ErrVerifierNotInitialized) Error() string {
	return "vm: verifier not initialized"
}

// ErrInvalidConfig indicates invalid configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("vm: invalid config for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("vm: invalid config: %s", e.Reason)
}

// ErrContextCanceled indicates the operation was canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("vm: %s canceled", e.Operation)
	}
	return "vm: operation canceled"
}

// ErrCertificateChainInvalid indicates that the certificate chain validation failed.
type ErrCertificateChainInvalid struct {
	Reason string
	Cause  error
}

func (e ErrCertificateChainInvalid) Error() string {
	msg := "vm: certificate chain invalid"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrCertificateChainInvalid) Unwrap() error {
	return e.Cause
}

// ErrInvalidHashAlgorithm indicates an invalid hash algorithm was specified.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	if e.Algorithm != "" {
		return fmt.Sprintf("vm: invalid hash algorithm %q", e.Algorithm)
	}
	return "vm: invalid hash algorithm"
}

// ErrSignatureInvalid indicates that the quote signature is invalid.
type ErrSignatureInvalid struct {
	Reason string
	Cause  error
}

func (e ErrSignatureInvalid) Error() string {
	msg := "vm: signature invalid"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSignatureInvalid) Unwrap() error {
	return e.Cause
}

// ErrPCRReadFailed indicates a PCR read operation failed.
type ErrPCRReadFailed struct {
	PCR   int
	Cause error
}

func (e ErrPCRReadFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vm: PCR %d read failed: %v", e.PCR, e.Cause)
	}
	return fmt.Sprintf("vm: PCR %d read failed", e.PCR)
}

func (e ErrPCRReadFailed) Unwrap() error {
	return e.Cause
}

// ErrQuoteExpired indicates that the quote timestamp is too old.
type ErrQuoteExpired struct {
	Age    int64
	MaxAge int64
}

func (e ErrQuoteExpired) Error() string {
	return fmt.Sprintf("vm: quote expired: age %d seconds exceeds max %d seconds", e.Age, e.MaxAge)
}

// ErrHostBindingInvalid indicates that the VM-to-host binding is invalid.
type ErrHostBindingInvalid struct {
	ExpectedHostID string
	ActualHostID   string
}

func (e ErrHostBindingInvalid) Error() string {
	return fmt.Sprintf("vm: host binding invalid: expected host %q, got %q",
		e.ExpectedHostID, e.ActualHostID)
}

// ErrBaselineMissing reports that no PCR baseline exists to verify against.
// It is deliberately distinct from ErrBaselineMismatch: a device with no
// baseline has not FAILED attestation, it cannot be evaluated — and only a
// cryptographic failure may drive quarantine (design of record, #226).
type ErrBaselineMissing struct {
	Reason string
}

func (e ErrBaselineMissing) Error() string {
	msg := "vm: no PCR baseline"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrBaselineMismatch reports that a device's reported PCR values diverge
// from the platform's baseline. Index is the first divergent register, or -1
// when the register SETS differ rather than a value.
type ErrBaselineMismatch struct {
	Index  int
	Reason string
}

func (e ErrBaselineMismatch) Error() string {
	msg := "vm: PCR baseline mismatch"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Index >= 0 {
		msg = fmt.Sprintf("%s (pcr %d)", msg, e.Index)
	}
	return msg
}

// ErrAKCertificateInvalid reports an attestation-key certificate that could
// not be parsed or does not chain to the platform's trust roots.
type ErrAKCertificateInvalid struct {
	Reason string
	Cause  error
}

func (e ErrAKCertificateInvalid) Error() string {
	msg := "vm: attestation key certificate invalid"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAKCertificateInvalid) Unwrap() error {
	return e.Cause
}

// ErrAKCertificateNotRestricted reports an attestation-key certificate that
// does not carry tcg-cap-verifiedTPMRestricted. Without it the certified key
// may be an Unrestricted key that can sign anything its holder chooses, so
// data it signs cannot be trusted as TPM internal data — TCG DevID v1 r12
// §8.2 makes checking for the attribute a MUST for that reason.
type ErrAKCertificateNotRestricted struct {
	Subject string
}

func (e ErrAKCertificateNotRestricted) Error() string {
	return fmt.Sprintf("vm: attestation key certificate %q does not carry tcg-cap-verifiedTPMRestricted", e.Subject)
}
