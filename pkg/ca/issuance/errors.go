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

package issuance

import (
	"errors"
	"strconv"
	"strings"
)

// invalidRequest marks the errors that are the caller's, which transports
// report as an invalid argument rather than a server failure.
type invalidRequest interface {
	error
	invalidRequest()
}

// IsInvalidRequest reports whether err is a request the caller must fix.
func IsInvalidRequest(err error) bool {
	var target invalidRequest
	return errors.As(err, &target)
}

// UnknownStoreTypeError is a store name no key store answers to.
type UnknownStoreTypeError struct {
	Name string
}

func (e *UnknownStoreTypeError) Error() string {
	return "unknown key store type " + strconv.Quote(e.Name) +
		": use software (pkcs8), pkcs11, tpm2 (tpm), awskms, gcpkms, azurekv or vault"
}

func (e *UnknownStoreTypeError) invalidRequest() {}

// CSRError is a CSR the CA cannot certify.
type CSRError struct {
	Reason string
	Err    error
}

func (e *CSRError) Error() string {
	if e.Err != nil {
		return "invalid CSR: " + e.Reason + ": " + e.Err.Error()
	}
	return "invalid CSR: " + e.Reason
}

func (e *CSRError) Unwrap() error { return e.Err }

func (e *CSRError) invalidRequest() {}

// CSRSubjectError is a CSR whose subject carries more than one common name.
type CSRSubjectError struct {
	// Attributes names each attribute beyond the common name.
	Attributes []string
}

func (e *CSRSubjectError) Error() string {
	return "a code-signing CSR's subject must be its common name alone, but it also carries " +
		strings.Join(e.Attributes, ", ")
}

func (e *CSRSubjectError) invalidRequest() {}

// CSRSANError is a CSR that carries subject alternative names.
type CSRSANError struct{}

func (e *CSRSANError) Error() string {
	return "a code-signing CSR must carry no subject alternative names (DNS, IP, URI or email)"
}

func (e *CSRSANError) invalidRequest() {}

// CSRKeyError is a CSR whose common name names no key the KMS holds.
type CSRKeyError struct {
	KeyID string
	Err   error
}

func (e *CSRKeyError) Error() string {
	return "the CSR's common name " + strconv.Quote(e.KeyID) + " names no KMS key: " + e.Err.Error()
}

func (e *CSRKeyError) Unwrap() error { return e.Err }

func (e *CSRKeyError) invalidRequest() {}

// CSRKeyMismatchError is a CSR whose key is not the KMS key it names.
type CSRKeyMismatchError struct {
	KeyID string
}

func (e *CSRKeyMismatchError) Error() string {
	return "the CSR's key is not the public key of KMS key " + strconv.Quote(e.KeyID)
}

func (e *CSRKeyMismatchError) invalidRequest() {}

// KMSUnavailableError is a CSR signer built without the KMS it checks keys
// against.
type KMSUnavailableError struct{}

func (e *KMSUnavailableError) Error() string {
	return "no KMS is available to check the CSR's key against, so it is not certified"
}

// KMSPublicKeyError is a KMS public key that does not parse.
type KMSPublicKeyError struct {
	KeyID string
	Err   error
}

func (e *KMSPublicKeyError) Error() string {
	return "the KMS returned a public key for " + strconv.Quote(e.KeyID) + " that does not parse: " + e.Err.Error()
}

func (e *KMSPublicKeyError) Unwrap() error { return e.Err }

// SignCSRError is the CA failing to certify a valid CSR.
type SignCSRError struct {
	CommonName string
	Err        error
}

func (e *SignCSRError) Error() string {
	return "the CA did not certify the CSR for " + e.CommonName + ": " + e.Err.Error()
}

func (e *SignCSRError) Unwrap() error { return e.Err }

// SignCSRScopeError is a sign-csr caller whose platform token does not
// grant SignCSRScope, or who presented none.
type SignCSRScopeError struct {
	Reason string
}

func (e *SignCSRScopeError) Error() string {
	return "signing a CSR requires a platform token granting " + SignCSRScope + ": " + e.Reason
}

// renewalRefused marks the renewals the CA refuses in its present state,
// which transports report as a failed precondition rather than a server
// failure.
type renewalRefused interface {
	error
	renewalRefused()
}

// IsRenewalRefused reports whether err is a renewal the CA refuses in its
// present state.
func IsRenewalRefused(err error) bool {
	var target renewalRefused
	return errors.As(err, &target)
}

// RenewCAOwnCertificateError is a renewal of the CA's own root or
// intermediate certificate, whose key is the CA signing key.
type RenewCAOwnCertificateError struct {
	CommonName string
}

func (e *RenewCAOwnCertificateError) Error() string {
	return "cannot renew certificate " + e.CommonName +
		": it is the CA's own certificate, and renewing it would replace the CA signing key"
}

func (e *RenewCAOwnCertificateError) renewalRefused() {}

// RenewStoreUnavailableError is a renewal on a CA built without the keystore
// or certificate store the renewal changes.
type RenewStoreUnavailableError struct {
	CommonName string
	Store      string
}

func (e *RenewStoreUnavailableError) Error() string {
	return "cannot renew certificate " + e.CommonName + ": the CA has no " + e.Store
}

func (e *RenewStoreUnavailableError) renewalRefused() {}

// RenewKeyRotationError is the CA keystore failing to look up or rotate the
// key of the certificate being renewed. The old certificate is left in place.
type RenewKeyRotationError struct {
	CommonName string
	Err        error
}

func (e *RenewKeyRotationError) Error() string {
	return "cannot renew certificate " + e.CommonName + ": rotating its key failed: " + e.Err.Error()
}

func (e *RenewKeyRotationError) Unwrap() error { return e.Err }

// RenewSupersedeError is the CA failing to revoke the certificate being
// renewed or to remove it from the certificate store.
type RenewSupersedeError struct {
	CommonName string
	Err        error
}

func (e *RenewSupersedeError) Error() string {
	return "cannot renew certificate " + e.CommonName + ": superseding the old certificate failed: " + e.Err.Error()
}

func (e *RenewSupersedeError) Unwrap() error { return e.Err }
