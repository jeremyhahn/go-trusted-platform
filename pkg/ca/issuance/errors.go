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
	"crypto/x509"
	"encoding/asn1"
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

// UnknownRevocationReasonError is a revocation reason that is not an
// RFC 5280 §5.3.1 CRLReason code.
// UnsupportedKeyAlgorithmError is a requested key algorithm the CA cannot
// issue a certificate key for.
type UnsupportedKeyAlgorithmError struct {
	Algorithm string
}

func (e *UnsupportedKeyAlgorithmError) Error() string {
	return "unsupported key algorithm " + strconv.Quote(e.Algorithm) +
		": use RSA_2048, RSA_3072, RSA_4096, ECDSA_P256, ECDSA_P384, ECDSA_P521 or ED25519"
}

func (e *UnsupportedKeyAlgorithmError) invalidRequest() {}

type UnknownRevocationReasonError struct {
	Code int
}

func (e *UnknownRevocationReasonError) Error() string {
	return "unknown revocation reason " + strconv.Itoa(e.Code) +
		": RFC 5280 §5.3.1 defines codes 0-6 and 8-10"
}

func (e *UnknownRevocationReasonError) invalidRequest() {}

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

// RenewStoresUnavailableError is a CA without the key or certificate store a
// renewal re-keys and replaces the certificate in.
type RenewStoresUnavailableError struct{}

func (e *RenewStoresUnavailableError) Error() string {
	return "CA key or certificate store is not available"
}

// RenewError is a renewal step the CA failed.
type RenewError struct {
	// Step names what the renewal was doing.
	Step string
	Err  error
}

func (e *RenewError) Error() string {
	return "failed to " + e.Step + ": " + e.Err.Error()
}

func (e *RenewError) Unwrap() error { return e.Err }

// IssuerCertificateError is an isCA request whose issuer certificate could not
// be read, so its path length cannot be checked and no CA certificate is issued.
type IssuerCertificateError struct {
	Err error
}

func (e *IssuerCertificateError) Error() string {
	if e.Err == nil {
		return "the issuing CA has no certificate, so its path length cannot be checked"
	}
	return "read the issuing CA's certificate to check its path length: " + e.Err.Error()
}

func (e *IssuerCertificateError) Unwrap() error { return e.Err }

// IssuerPathLenExhaustedError is an isCA request to an issuer whose
// pathLenConstraint is 0, which may sign no subordinate CA (RFC 5280 §4.2.1.9).
type IssuerPathLenExhaustedError struct {
	// Issuer is the issuing CA's subject.
	Issuer string
}

func (e *IssuerPathLenExhaustedError) Error() string {
	return "issuer " + strconv.Quote(e.Issuer) + " has path length 0 and may issue no subordinate CA"
}

func (e *IssuerPathLenExhaustedError) invalidRequest() {}

// SubordinatePathLenError is an isCA request for a path length the issuer's
// pathLenConstraint does not allow: beneath an issuer with path length n the
// subordinate's is at most n-1, and a negative request (no limit) is refused
// (RFC 5280 §4.2.1.9).
type SubordinatePathLenError struct {
	// Issuer is the issuing CA's subject.
	Issuer    string
	Requested int
	Allowed   int
}

func (e *SubordinatePathLenError) Error() string {
	requested := strconv.Itoa(e.Requested)
	if e.Requested < 0 {
		requested = "unlimited"
	}
	return "a subordinate CA of issuer " + strconv.Quote(e.Issuer) + " may have path length at most " +
		strconv.Itoa(e.Allowed) + ", not " + requested
}

func (e *SubordinatePathLenError) invalidRequest() {}

// ErrCAExtKeyUsageUnsupported is an isCA request, or the renewal of a CA
// certificate, that carries an extended key usage restriction. The SDK issues
// a CA certificate only through the named go-xkms "ca" profile
// (IssueCertificateWithProfile with ca.NewCAProfile), and that profile sets
// ExtKeyUsage to none and ignores the request's: the CA would come out
// unrestricted, able to certify purposes the restriction excludes
// (RFC 5280 §4.2.1.12). The request is refused until the SDK profile carries
// the request's ExtKeyUsage.
type ErrCAExtKeyUsageUnsupported struct{}

func (ErrCAExtKeyUsageUnsupported) Error() string {
	return "a CA certificate with an extended key usage restriction cannot be issued: " +
		"the SDK's CA profile (go-xkms ca.NewCAProfile) drops the request's ExtKeyUsage, " +
		"so the CA would be issued unrestricted"
}

func (ErrCAExtKeyUsageUnsupported) invalidRequest() {}

// CARestrictionUnsupportedError is the renewal of a CA certificate that
// carries a restriction the SDK's certificate request cannot express: name
// constraints (RFC 5280 §4.2.1.10) or an extended key usage OID Go does not
// recognize (RFC 5280 §4.2.1.12). The go-xkms CertificateRequest the SDK
// re-exports (quicbaas sdk/go/xkms/ca.CACertificateRequest) has no field for
// either, so the renewed CA would come out without the restriction, able to
// certify names or purposes the old one could not. The renewal is refused
// before the old certificate is revoked until the SDK request carries them.
type CARestrictionUnsupportedError struct {
	// Restriction names what the certificate carries.
	Restriction string
}

func (e *CARestrictionUnsupportedError) Error() string {
	return "a CA certificate with " + e.Restriction + " cannot be renewed: " +
		"the SDK certificate request (go-xkms ca.CertificateRequest) has no field for it, " +
		"so the renewed CA would be issued without the restriction"
}

func (e *CARestrictionUnsupportedError) invalidRequest() {}

// ErrUnhandledCriticalExtension is the renewal of a certificate that carries
// a critical extension Go does not process (x509.Certificate's
// UnhandledCriticalExtensions). The renewal request cannot carry it, so the
// replacement would come out without an extension relying parties must
// reject the certificate over, or process under its restrictions
// (RFC 5280 §4.2). The renewal is refused before the old certificate is
// revoked. errors.Is matches any ErrUnhandledCriticalExtension, whatever its
// OIDs.
type ErrUnhandledCriticalExtension struct {
	// OIDs are the critical extensions the certificate carries unprocessed.
	OIDs []asn1.ObjectIdentifier
}

func (e ErrUnhandledCriticalExtension) Error() string {
	names := make([]string, 0, len(e.OIDs))
	for _, oid := range e.OIDs {
		names = append(names, oid.String())
	}
	return "a certificate with an unhandled critical extension (" + strings.Join(names, ", ") +
		") cannot be renewed: the renewal request cannot carry it, " +
		"so the renewed certificate would be issued without it"
}

// Is reports whether target is an ErrUnhandledCriticalExtension.
func (ErrUnhandledCriticalExtension) Is(target error) bool {
	_, ok := target.(ErrUnhandledCriticalExtension)
	return ok
}

func (ErrUnhandledCriticalExtension) invalidRequest() {}

// ErrInstallerRenewal is the renewal of a certificate carrying the
// tp-pxeInstaller marker. The renewal request cannot carry the marker, so the
// replacement would come out as an unrestricted client certificate; and an
// installer certificate is single-use for one PXE install, the next install
// issuing a new one (ruling 269(d)). The renewal is refused before the old
// certificate is revoked (Codex 8676).
type ErrInstallerRenewal struct{}

func (ErrInstallerRenewal) Error() string {
	return "an installer certificate (tp-pxeInstaller) is not renewable: the next PXE install issues a new one"
}

// Is reports whether target is an ErrInstallerRenewal.
func (ErrInstallerRenewal) Is(target error) bool {
	_, ok := target.(ErrInstallerRenewal)
	return ok
}

func (ErrInstallerRenewal) invalidRequest() {}

// ErrInstallerExtKeyUsage is a request naming PXE_INSTALLER with an extended
// key usage other than CLIENT_AUTH. The installer marker extension carries
// exactly id-kp-clientAuth and tp-pxeInstaller, so another usage would be
// dropped; it is refused instead.
type ErrInstallerExtKeyUsage struct {
	// Name is the extended key usage the request named beside PXE_INSTALLER.
	Name string
}

func (e ErrInstallerExtKeyUsage) Error() string {
	return "an installer certificate (PXE_INSTALLER) carries only CLIENT_AUTH: " +
		"extended key usage " + strconv.Quote(e.Name) + " cannot be added"
}

// Is reports whether target is an ErrInstallerExtKeyUsage.
func (ErrInstallerExtKeyUsage) Is(target error) bool {
	_, ok := target.(ErrInstallerExtKeyUsage)
	return ok
}

func (ErrInstallerExtKeyUsage) invalidRequest() {}

// InstallerMarkerEncodeError is a failure to encode the installer marker
// extension.
type InstallerMarkerEncodeError struct {
	Err error
}

func (e *InstallerMarkerEncodeError) Error() string {
	return "encode the installer marker extension: " + e.Err.Error()
}

func (e *InstallerMarkerEncodeError) Unwrap() error { return e.Err }

// CAKeyUsageUnsupportedError is an isCA request, or the renewal of a CA
// certificate, whose key usage differs from the one the SDK's CA profile
// writes. The pinned go-xkms ca.NewCAProfile replaces the request's KeyUsage
// with keyCertSign | cRLSign | digitalSignature, so a CA restricted to fewer
// usages would come out with authority it was not given (RFC 5280 §4.2.1.3).
// The request is refused, before a renewal revokes the old certificate, until
// the SDK profile carries the request's KeyUsage.
type CAKeyUsageUnsupportedError struct {
	// Requested is the key usage the request or the existing CA carries.
	Requested x509.KeyUsage
	// Profile is the key usage the SDK's CA profile writes.
	Profile x509.KeyUsage
}

func (e *CAKeyUsageUnsupportedError) Error() string {
	return "a CA certificate with key usage " + strconv.Itoa(int(e.Requested)) +
		" cannot be issued: the SDK's CA profile (go-xkms ca.NewCAProfile) replaces the request's KeyUsage with " +
		strconv.Itoa(int(e.Profile)) + ", so the CA would be issued with usages it was not given"
}

func (e *CAKeyUsageUnsupportedError) invalidRequest() {}

// ErrUnsupportedUsage is a key usage or extended key usage name the platform
// does not recognize. It is refused, never dropped: dropping it would widen
// the certificate, and on an isCA request grant the CA profile's full
// authority. errors.Is matches any ErrUnsupportedUsage, whatever its Name.
type ErrUnsupportedUsage struct {
	// Name is the unrecognized usage string as the caller sent it.
	Name string
}

func (e ErrUnsupportedUsage) Error() string {
	return "unsupported key usage or extended key usage " + strconv.Quote(e.Name)
}

// Is reports whether target is an ErrUnsupportedUsage.
func (ErrUnsupportedUsage) Is(target error) bool {
	_, ok := target.(ErrUnsupportedUsage)
	return ok
}

func (ErrUnsupportedUsage) invalidRequest() {}
