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

package attestation

import "fmt"

// ErrInvalidRequestBody is returned when the request body cannot be parsed.
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrManifestNotFound is returned when a manifest is not found.
type ErrManifestNotFound struct {
	ID string
}

func (e ErrManifestNotFound) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("manifest not found: %s", e.ID)
	}
	return "manifest not found"
}

// ErrManifestBuildFailed is returned when manifest building fails.
type ErrManifestBuildFailed struct {
	Reason string
}

func (e ErrManifestBuildFailed) Error() string {
	return fmt.Sprintf("manifest build failed: %s", e.Reason)
}

// ErrManifestVerifyFailed is returned when manifest verification fails.
type ErrManifestVerifyFailed struct {
	Reason string
}

func (e ErrManifestVerifyFailed) Error() string {
	return fmt.Sprintf("manifest verification failed: %s", e.Reason)
}

// ErrQuoteGenerationFailed is returned when TPM quote generation fails.
type ErrQuoteGenerationFailed struct {
	Reason string
}

func (e ErrQuoteGenerationFailed) Error() string {
	return fmt.Sprintf("quote generation failed: %s", e.Reason)
}

// ErrQuoteVerifyFailed is returned when TPM quote verification fails.
type ErrQuoteVerifyFailed struct {
	Reason string
}

func (e ErrQuoteVerifyFailed) Error() string {
	return fmt.Sprintf("quote verification failed: %s", e.Reason)
}

// ErrMissingNonce is returned when nonce is required but not provided.
type ErrMissingNonce struct{}

func (e ErrMissingNonce) Error() string {
	return "nonce is required"
}

// ErrInvalidNonce is returned when nonce format is invalid.
type ErrInvalidNonce struct {
	Reason string
}

func (e ErrInvalidNonce) Error() string {
	return fmt.Sprintf("invalid nonce: %s", e.Reason)
}

// ErrMissingManifest is returned when manifest is required but not provided.
type ErrMissingManifest struct{}

func (e ErrMissingManifest) Error() string {
	return "manifest is required"
}

// ErrMissingQuoteData is returned when quote data is required but not provided.
type ErrMissingQuoteData struct{}

func (e ErrMissingQuoteData) Error() string {
	return "quote data is required"
}

// ErrMissingSignature is returned when signature is required but not provided.
type ErrMissingSignature struct{}

func (e ErrMissingSignature) Error() string {
	return "signature is required"
}

// ErrMissingPublicKey is returned when public key is required but not provided.
type ErrMissingPublicKey struct{}

func (e ErrMissingPublicKey) Error() string {
	return "public key is required"
}

// ErrInvalidHashAlgorithm is returned when hash algorithm is invalid.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	return fmt.Sprintf("invalid hash algorithm: %s (valid: sha256, sha384, sha512)", e.Algorithm)
}

// ErrInvalidPCRIndex is returned when PCR index is invalid.
type ErrInvalidPCRIndex struct {
	Index int
}

func (e ErrInvalidPCRIndex) Error() string {
	return fmt.Sprintf("invalid PCR index: %d (valid: 0-23)", e.Index)
}

// ErrInvalidBase64 is returned when base64 decoding fails.
type ErrInvalidBase64 struct {
	Field  string
	Reason string
}

func (e ErrInvalidBase64) Error() string {
	return fmt.Sprintf("invalid base64 encoding for %s: %s", e.Field, e.Reason)
}

// ErrServiceUnavailable is returned when the attestation service is unavailable.
type ErrServiceUnavailable struct {
	Reason string
}

func (e ErrServiceUnavailable) Error() string {
	return fmt.Sprintf("attestation service unavailable: %s", e.Reason)
}
