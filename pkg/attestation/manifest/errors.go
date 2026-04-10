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

package manifest

import "fmt"

// ErrManifestBuildFailed indicates that building the manifest failed.
type ErrManifestBuildFailed struct {
	Reason string
	Cause  error
}

func (e ErrManifestBuildFailed) Error() string {
	msg := "manifest: build failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrManifestBuildFailed) Unwrap() error {
	return e.Cause
}

// ErrManifestSignFailed indicates that signing the manifest failed.
type ErrManifestSignFailed struct {
	Reason string
	Cause  error
}

func (e ErrManifestSignFailed) Error() string {
	msg := "manifest: sign failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrManifestSignFailed) Unwrap() error {
	return e.Cause
}

// ErrManifestVerifyFailed indicates that verifying the manifest failed.
type ErrManifestVerifyFailed struct {
	Reason string
	Cause  error
}

func (e ErrManifestVerifyFailed) Error() string {
	msg := "manifest: verification failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrManifestVerifyFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidManifest indicates that the manifest is invalid or malformed.
type ErrInvalidManifest struct {
	Field  string
	Reason string
}

func (e ErrInvalidManifest) Error() string {
	msg := "manifest: invalid manifest"
	if e.Field != "" {
		msg = fmt.Sprintf("%s for %s", msg, e.Field)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrManifestExpired indicates that the manifest has expired.
type ErrManifestExpired struct {
	Age    int64
	MaxAge int64
}

func (e ErrManifestExpired) Error() string {
	return fmt.Sprintf("manifest: expired: age %d seconds exceeds max %d seconds", e.Age, e.MaxAge)
}

// ErrMerkleRootMismatch indicates that the Merkle root does not match.
type ErrMerkleRootMismatch struct {
	Expected []byte
	Actual   []byte
}

func (e ErrMerkleRootMismatch) Error() string {
	return fmt.Sprintf("manifest: Merkle root mismatch: expected %x, got %x", e.Expected, e.Actual)
}

// ErrBuilderNotInitialized indicates that the builder has not been initialized.
type ErrBuilderNotInitialized struct{}

func (e ErrBuilderNotInitialized) Error() string {
	return "manifest: builder not initialized"
}

// ErrSignerNotInitialized indicates that the signer has not been initialized.
type ErrSignerNotInitialized struct{}

func (e ErrSignerNotInitialized) Error() string {
	return "manifest: signer not initialized"
}

// ErrVerifierNotInitialized indicates that the verifier has not been initialized.
type ErrVerifierNotInitialized struct{}

func (e ErrVerifierNotInitialized) Error() string {
	return "manifest: verifier not initialized"
}

// ErrInvalidConfig indicates invalid configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("manifest: invalid config for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("manifest: invalid config: %s", e.Reason)
}

// ErrContextCanceled indicates the operation was canceled via context.
type ErrContextCanceled struct {
	Operation string
}

func (e ErrContextCanceled) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("manifest: %s canceled", e.Operation)
	}
	return "manifest: operation canceled"
}

// ErrNonceMismatch indicates that the nonce does not match the expected value.
type ErrNonceMismatch struct {
	Expected []byte
	Actual   []byte
}

func (e ErrNonceMismatch) Error() string {
	return fmt.Sprintf("manifest: nonce mismatch: expected %x, got %x", e.Expected, e.Actual)
}

// ErrTPMNotAvailable indicates that the TPM is not available.
type ErrTPMNotAvailable struct {
	Reason string
	Cause  error
}

func (e ErrTPMNotAvailable) Error() string {
	msg := "manifest: TPM not available"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrTPMNotAvailable) Unwrap() error {
	return e.Cause
}

// ErrAKNotFound indicates that the AK was not found.
type ErrAKNotFound struct {
	Reason string
}

func (e ErrAKNotFound) Error() string {
	msg := "manifest: AK not found"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrSignatureInvalid indicates that the manifest signature is invalid.
type ErrSignatureInvalid struct {
	Reason string
	Cause  error
}

func (e ErrSignatureInvalid) Error() string {
	msg := "manifest: signature invalid"
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

// ErrAttestationFailed indicates that collecting an attestation failed.
type ErrAttestationFailed struct {
	WorkloadType string
	WorkloadID   string
	Reason       string
	Cause        error
}

func (e ErrAttestationFailed) Error() string {
	msg := "manifest: attestation failed"
	if e.WorkloadType != "" || e.WorkloadID != "" {
		msg = fmt.Sprintf("%s for %s %s", msg, e.WorkloadType, e.WorkloadID)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidHashAlgorithm indicates an invalid hash algorithm was specified.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	if e.Algorithm != "" {
		return fmt.Sprintf("manifest: invalid hash algorithm %q", e.Algorithm)
	}
	return "manifest: invalid hash algorithm"
}

// ErrHostNotAttested indicates the host has not been attested.
type ErrHostNotAttested struct{}

func (e ErrHostNotAttested) Error() string {
	return "manifest: host not attested"
}

// ErrEmptyManifest indicates the manifest has no content.
type ErrEmptyManifest struct{}

func (e ErrEmptyManifest) Error() string {
	return "manifest: empty manifest (no attestations)"
}
