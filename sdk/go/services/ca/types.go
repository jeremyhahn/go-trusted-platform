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

package ca

import "time"

// KeyAlgorithm represents a cryptographic key algorithm.
type KeyAlgorithm string

const (
	// KeyAlgorithmUnspecified indicates no algorithm is set.
	KeyAlgorithmUnspecified KeyAlgorithm = "UNSPECIFIED"
	// KeyAlgorithmRSA2048 indicates RSA with 2048-bit key.
	KeyAlgorithmRSA2048 KeyAlgorithm = "RSA-2048"
	// KeyAlgorithmRSA3072 indicates RSA with 3072-bit key.
	KeyAlgorithmRSA3072 KeyAlgorithm = "RSA-3072"
	// KeyAlgorithmRSA4096 indicates RSA with 4096-bit key.
	KeyAlgorithmRSA4096 KeyAlgorithm = "RSA-4096"
	// KeyAlgorithmECDSAP256 indicates ECDSA with P-256 curve.
	KeyAlgorithmECDSAP256 KeyAlgorithm = "ECDSA-P256"
	// KeyAlgorithmECDSAP384 indicates ECDSA with P-384 curve.
	KeyAlgorithmECDSAP384 KeyAlgorithm = "ECDSA-P384"
	// KeyAlgorithmEd25519 indicates Ed25519.
	KeyAlgorithmEd25519 KeyAlgorithm = "Ed25519"
)

// CertificateStatus represents the status of a certificate.
type CertificateStatus string

const (
	// CertificateStatusUnspecified indicates no status is set.
	CertificateStatusUnspecified CertificateStatus = "UNSPECIFIED"
	// CertificateStatusValid indicates the certificate is valid.
	CertificateStatusValid CertificateStatus = "VALID"
	// CertificateStatusRevoked indicates the certificate is revoked.
	CertificateStatusRevoked CertificateStatus = "REVOKED"
	// CertificateStatusExpired indicates the certificate has expired.
	CertificateStatusExpired CertificateStatus = "EXPIRED"
	// CertificateStatusPending indicates the certificate is pending.
	CertificateStatusPending CertificateStatus = "PENDING"
)

// RevocationReason represents the reason for certificate revocation.
type RevocationReason string

const (
	// RevocationReasonUnspecified indicates no reason specified.
	RevocationReasonUnspecified RevocationReason = "UNSPECIFIED"
	// RevocationReasonKeyCompromise indicates the private key was compromised.
	RevocationReasonKeyCompromise RevocationReason = "KEY_COMPROMISE"
	// RevocationReasonCACompromise indicates the CA key was compromised.
	RevocationReasonCACompromise RevocationReason = "CA_COMPROMISE"
	// RevocationReasonAffiliationChanged indicates the affiliation changed.
	RevocationReasonAffiliationChanged RevocationReason = "AFFILIATION_CHANGED"
	// RevocationReasonSuperseded indicates the certificate was superseded.
	RevocationReasonSuperseded RevocationReason = "SUPERSEDED"
	// RevocationReasonCessationOfOperation indicates cessation of operation.
	RevocationReasonCessationOfOperation RevocationReason = "CESSATION_OF_OPERATION"
	// RevocationReasonCertificateHold indicates the certificate is on hold.
	RevocationReasonCertificateHold RevocationReason = "CERTIFICATE_HOLD"
	// RevocationReasonPrivilegeWithdrawn indicates privilege was withdrawn.
	RevocationReasonPrivilegeWithdrawn RevocationReason = "PRIVILEGE_WITHDRAWN"
)

// CAInfo contains information about the Certificate Authority.
type CAInfo struct {
	// IsInitialized indicates whether the CA is initialized.
	IsInitialized bool `json:"is_initialized" yaml:"is_initialized"`
	// CommonName is the CA's common name.
	CommonName string `json:"common_name" yaml:"common_name"`
	// IsIntermediate indicates whether this is an intermediate CA.
	IsIntermediate bool `json:"is_intermediate" yaml:"is_intermediate"`
	// DefaultAlgorithm is the default key algorithm.
	DefaultAlgorithm string `json:"default_algorithm" yaml:"default_algorithm"`
	// DefaultValidityDays is the default certificate validity period.
	DefaultValidityDays int32 `json:"default_validity_days" yaml:"default_validity_days"`
	// RootCert is the root certificate summary.
	RootCert *CertificateSummary `json:"root_cert,omitempty" yaml:"root_cert,omitempty"`
	// Intermediates are intermediate certificate summaries.
	Intermediates []*CertificateSummary `json:"intermediates,omitempty" yaml:"intermediates,omitempty"`
	// KeyStores are the configured key stores.
	KeyStores []*KeyStoreInfo `json:"key_stores,omitempty" yaml:"key_stores,omitempty"`
}

// CertificateSummary contains summary information about a certificate.
type CertificateSummary struct {
	// Serial is the certificate serial number.
	Serial string `json:"serial" yaml:"serial"`
	// CommonName is the certificate common name.
	CommonName string `json:"common_name" yaml:"common_name"`
	// Issuer is the issuer common name.
	Issuer string `json:"issuer" yaml:"issuer"`
	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time `json:"not_before" yaml:"not_before"`
	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after" yaml:"not_after"`
	// Status is the certificate status.
	Status CertificateStatus `json:"status" yaml:"status"`
	// KeyAlgorithm is the key algorithm used.
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm" yaml:"key_algorithm"`
}

// Certificate contains full certificate details.
type Certificate struct {
	// Serial is the certificate serial number.
	Serial string `json:"serial" yaml:"serial"`
	// Subject is the certificate subject.
	Subject *Subject `json:"subject,omitempty" yaml:"subject,omitempty"`
	// Issuer is the issuer common name.
	Issuer string `json:"issuer" yaml:"issuer"`
	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time `json:"not_before" yaml:"not_before"`
	// NotAfter is when the certificate expires.
	NotAfter time.Time `json:"not_after" yaml:"not_after"`
	// Status is the certificate status.
	Status CertificateStatus `json:"status" yaml:"status"`
	// KeyAlgorithm is the key algorithm used.
	KeyAlgorithm KeyAlgorithm `json:"key_algorithm" yaml:"key_algorithm"`
	// SignatureAlgorithm is the signature algorithm.
	SignatureAlgorithm string `json:"signature_algorithm" yaml:"signature_algorithm"`
	// IsCa indicates whether this is a CA certificate.
	IsCa bool `json:"is_ca" yaml:"is_ca"`
	// FingerprintSha256 is the SHA-256 fingerprint.
	FingerprintSha256 string `json:"fingerprint_sha256,omitempty" yaml:"fingerprint_sha256,omitempty"`
	// Pem is the PEM-encoded certificate.
	Pem []byte `json:"pem,omitempty" yaml:"pem,omitempty"`
	// Der is the DER-encoded certificate.
	Der []byte `json:"der,omitempty" yaml:"der,omitempty"`
}

// Subject contains certificate subject information.
type Subject struct {
	// CommonName is the subject common name.
	CommonName string `json:"common_name" yaml:"common_name"`
	// Organization is the subject organization.
	Organization string `json:"organization,omitempty" yaml:"organization,omitempty"`
}

// SubjectAlternativeNames contains SANs for a certificate.
type SubjectAlternativeNames struct {
	// DNSNames are DNS SANs.
	DNSNames []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	// IPAddresses are IP SANs.
	IPAddresses []string `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	// EmailAddresses are email SANs.
	EmailAddresses []string `json:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
}

// KeyStoreInfo contains information about a key store.
type KeyStoreInfo struct {
	// Type is the key store type.
	Type string `json:"type" yaml:"type"`
	// Available indicates whether the key store is available.
	Available bool `json:"available" yaml:"available"`
	// Capabilities are the key store capabilities.
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
}

// CRL contains Certificate Revocation List information.
type CRL struct {
	// LastUpdate is when the CRL was last updated.
	LastUpdate time.Time `json:"last_update" yaml:"last_update"`
	// NextUpdate is when the next CRL update is expected.
	NextUpdate time.Time `json:"next_update" yaml:"next_update"`
	// RevokedCount is the number of revoked certificates.
	RevokedCount int32 `json:"revoked_count" yaml:"revoked_count"`
	// RevokedCerts are the revoked certificate entries.
	RevokedCerts []*RevokedCertEntry `json:"revoked_certs,omitempty" yaml:"revoked_certs,omitempty"`
	// Data is the raw CRL data in DER format.
	Data []byte `json:"data,omitempty" yaml:"data,omitempty"`
}

// RevokedCertEntry contains information about a revoked certificate.
type RevokedCertEntry struct {
	// Serial is the revoked certificate serial number.
	Serial string `json:"serial" yaml:"serial"`
	// RevocationTime is when the certificate was revoked.
	RevocationTime time.Time `json:"revocation_time" yaml:"revocation_time"`
	// Reason is the revocation reason.
	Reason RevocationReason `json:"reason" yaml:"reason"`
}

// CABundle contains a CA certificate bundle.
type CABundle struct {
	// Pem is the PEM-encoded bundle.
	Pem []byte `json:"pem,omitempty" yaml:"pem,omitempty"`
	// CertCount is the number of certificates in the bundle.
	CertCount int32 `json:"cert_count" yaml:"cert_count"`
	// Certificates are summaries of the certificates in the bundle.
	Certificates []*CertificateSummary `json:"certificates,omitempty" yaml:"certificates,omitempty"`
}

// IssueCertificateParams contains parameters for issuing a certificate.
type IssueCertificateParams struct {
	// Subject is the certificate subject.
	Subject *Subject
	// KeyAlgorithm is the key algorithm.
	KeyAlgorithm KeyAlgorithm
	// StoreType is the key store type.
	StoreType string
	// ValidDays is the validity period in days.
	ValidDays int32
	// SANs are the subject alternative names.
	SANs *SubjectAlternativeNames
	// KeyUsage is the key usage extensions.
	KeyUsage []string
	// ExtKeyUsage is the extended key usage extensions.
	ExtKeyUsage []string
}

// IssueCertificateResult contains the result of issuing a certificate.
type IssueCertificateResult struct {
	// Certificate is the issued certificate.
	Certificate *Certificate `json:"certificate,omitempty" yaml:"certificate,omitempty"`
}

// RevokeCertificateParams contains parameters for revoking a certificate.
type RevokeCertificateParams struct {
	// Serial is the certificate serial number.
	Serial string
	// Reason is the revocation reason.
	Reason RevocationReason
	// DeleteKeys indicates whether to delete the associated keys.
	DeleteKeys bool
}

// RevokeCertificateResult contains the result of revoking a certificate.
type RevokeCertificateResult struct {
	// Serial is the certificate serial number.
	Serial string `json:"serial" yaml:"serial"`
	// Reason is the revocation reason.
	Reason RevocationReason `json:"reason" yaml:"reason"`
	// RevokedAt is when the certificate was revoked.
	RevokedAt time.Time `json:"revoked_at" yaml:"revoked_at"`
	// Success indicates whether the revocation succeeded.
	Success bool `json:"success" yaml:"success"`
	// Message is the status message.
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

// RenewCertificateParams contains parameters for renewing a certificate.
type RenewCertificateParams struct {
	// Serial is the certificate serial number.
	Serial string
	// ValidDays is the validity period in days.
	ValidDays int32
	// PreserveSANs indicates whether to preserve existing SANs.
	PreserveSANs bool
	// NewSANs are new SANs to add.
	NewSANs *SubjectAlternativeNames
}

// RenewCertificateResult contains the result of renewing a certificate.
type RenewCertificateResult struct {
	// NewCertificate is the renewed certificate.
	NewCertificate *Certificate `json:"new_certificate,omitempty" yaml:"new_certificate,omitempty"`
}

// VerifyCertificateParams contains parameters for verifying a certificate.
type VerifyCertificateParams struct {
	// CertificatePEM is the PEM-encoded certificate to verify.
	CertificatePEM []byte
	// VerifyRevocation indicates whether to check revocation.
	VerifyRevocation bool
	// VerifyExpiration indicates whether to check expiration.
	VerifyExpiration bool
}

// VerifyCertificateResult contains the result of verifying a certificate.
type VerifyCertificateResult struct {
	// Valid indicates whether the certificate is valid.
	Valid bool `json:"valid" yaml:"valid"`
	// Chain is the certificate chain names.
	Chain []string `json:"chain,omitempty" yaml:"chain,omitempty"`
	// Errors are validation errors.
	Errors []string `json:"errors,omitempty" yaml:"errors,omitempty"`
	// Warnings are validation warnings.
	Warnings []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// ListCertificatesParams contains parameters for listing certificates.
type ListCertificatesParams struct {
	// StatusFilter filters by certificate status.
	StatusFilter CertificateStatus
	// IssuerFilter filters by issuer common name.
	IssuerFilter string
	// Page is the page number.
	Page uint32
	// PageSize is the number of results per page.
	PageSize uint32
}

// ListCertificatesResult contains the result of listing certificates.
type ListCertificatesResult struct {
	// Certificates are the certificate summaries.
	Certificates []*CertificateSummary `json:"certificates" yaml:"certificates"`
	// Page is the current page.
	Page uint32 `json:"page" yaml:"page"`
	// TotalPages is the total number of pages.
	TotalPages uint32 `json:"total_pages" yaml:"total_pages"`
	// TotalItems is the total number of items.
	TotalItems uint64 `json:"total_items" yaml:"total_items"`
}

// GetCertificateParams contains parameters for getting a certificate.
type GetCertificateParams struct {
	// Serial is the certificate serial number.
	Serial string
	// IncludePEM indicates whether to include PEM data.
	IncludePEM bool
	// IncludeDER indicates whether to include DER data.
	IncludeDER bool
}
