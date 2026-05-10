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

//go:build integration

package ca

import (
	"context"
	"time"
)

// CACommands defines the central command set for CA integration testing.
// Each protocol adapter (CLI, REST, gRPC, QUIC, MCP, Unix) implements this interface.
// Tests are written once against this interface and run against all protocols.
type CACommands interface {
	// Protocol identification and lifecycle
	Name() string
	Setup(ctx context.Context) error
	Teardown() error

	// CA Info Commands (platformctl ca info)
	Info(ctx context.Context) (*InfoResult, error)

	// CA Init Commands (platformctl ca init)
	Init(ctx context.Context, opts InitOptions) (*InitResult, error)

	// Certificate Issue Commands (platformctl ca issue)
	IssueCertificate(ctx context.Context, opts IssueCertificateOptions) (*IssueCertificateResult, error)

	// Certificate Get Commands (platformctl ca certificate)
	GetCertificate(ctx context.Context, opts GetCertificateOptions) (*GetCertificateResult, error)

	// Certificate List Commands (platformctl ca list)
	ListCertificates(ctx context.Context, opts ListCertificatesOptions) (*ListCertificatesResult, error)

	// Certificate Verify Commands (platformctl ca verify)
	VerifyCertificate(ctx context.Context, opts VerifyCertificateOptions) (*VerifyCertificateResult, error)

	// Certificate Revoke Commands (platformctl ca revoke)
	RevokeCertificate(ctx context.Context, opts RevokeCertificateOptions) (*RevokeCertificateResult, error)

	// Certificate Renew Commands (platformctl ca renew)
	RenewCertificate(ctx context.Context, opts RenewCertificateOptions) (*RenewCertificateResult, error)

	// CRL Commands (platformctl ca crl)
	GetCRL(ctx context.Context, opts GetCRLOptions) (*GetCRLResult, error)

	// CRL Generate Commands (platformctl ca crl generate)
	GenerateCRL(ctx context.Context) (*GenerateCRLResult, error)

	// CRL Export Commands (platformctl ca crl export)
	ExportCRL(ctx context.Context, output string) (*ExportCRLResult, error)

	// Export Bundle Commands (platformctl ca bundle)
	ExportBundle(ctx context.Context, output string) (*ExportBundleResult, error)

	// Install CA Certificates Commands (platformctl ca install-ca-certificates)
	InstallCACertificates(ctx context.Context) (*InstallCACertificatesResult, error)

	// Uninstall CA Certificates Commands (platformctl ca uninstall-ca-certificates)
	UninstallCACertificates(ctx context.Context) (*UninstallCACertificatesResult, error)
}

// =============================================================================
// CA Info Types
// =============================================================================

// InfoResult contains the result of a CA info operation.
type InfoResult struct {
	CommonName          string
	IsInitialized       bool
	IsIntermediate      bool
	RootCertificate     *CertificateSummary
	Intermediates       []CertificateSummary
	KeyStores           []KeyStoreInfo
	DefaultAlgorithm    string
	DefaultValidityDays int32
}

// KeyStoreInfo contains key store information.
type KeyStoreInfo struct {
	Type         string
	Available    bool
	Capabilities []string
}

// =============================================================================
// CA Init Types
// =============================================================================

// InitOptions contains options for CA initialization.
type InitOptions struct {
	Force bool
}

// InitResult contains the result of a CA init operation.
type InitResult struct {
	Success bool
	Message string
}

// =============================================================================
// Certificate Issue Types
// =============================================================================

// IssueCertificateOptions contains options for certificate issuance.
type IssueCertificateOptions struct {
	CommonName  string
	StoreType   string
	Algorithm   string
	ValidDays   int32
	SANsDNS     []string
	SANsIPs     []string
	SANsEmail   []string
	KeyUsage    []string
	ExtKeyUsage []string
	IsCA        bool
	MaxPathLen  int32
}

// IssueCertificateResult contains the result of a certificate issuance.
type IssueCertificateResult struct {
	Success     bool
	Certificate *Certificate
}

// Certificate contains full certificate data.
type Certificate struct {
	Serial             string
	Subject            Subject
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	Status             CertificateStatus
	KeyAlgorithm       string
	SignatureAlgorithm string
	IsCA               bool
	MaxPathLen         int32
	SANsDNS            []string
	SANsIPs            []string
	SANsEmail          []string
	SANsURIs           []string
	KeyUsage           []string
	ExtKeyUsage        []string
	PEM                []byte
	DER                []byte
	FingerprintSHA256  string
}

// Subject contains certificate subject information.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
	Address            string
	PostalCode         string
}

// CertificateStatus indicates the current status of a certificate.
type CertificateStatus int32

const (
	CertificateStatusUnspecified CertificateStatus = 0
	CertificateStatusValid       CertificateStatus = 1
	CertificateStatusRevoked     CertificateStatus = 2
	CertificateStatusExpired     CertificateStatus = 3
	CertificateStatusPending     CertificateStatus = 4
)

// =============================================================================
// Certificate Get Types
// =============================================================================

// GetCertificateOptions contains options for retrieving a certificate.
type GetCertificateOptions struct {
	Serial     string
	CommonName string
	StoreType  string
	Algorithm  string
	IncludePEM bool
	IncludeDER bool
}

// GetCertificateResult contains the result of a certificate retrieval.
type GetCertificateResult struct {
	Certificate *Certificate
}

// =============================================================================
// Certificate List Types
// =============================================================================

// ListCertificatesOptions contains options for listing certificates.
type ListCertificatesOptions struct {
	Status string
	Issuer string
	Limit  int32
	Offset int32
}

// ListCertificatesResult contains the result of a certificate list operation.
type ListCertificatesResult struct {
	Certificates []CertificateSummary
	Total        int32
}

// CertificateSummary contains summary certificate information for lists.
type CertificateSummary struct {
	Serial       string
	CommonName   string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	Status       CertificateStatus
	KeyAlgorithm string
}

// =============================================================================
// Certificate Verify Types
// =============================================================================

// VerifyCertificateOptions contains options for certificate verification.
type VerifyCertificateOptions struct {
	CertPath        string
	Serial          string
	CertificatePEM  []byte
	CheckCRL        bool
	CheckExpiration bool
	Verbose         bool
}

// VerifyCertificateResult contains the result of a certificate verification.
type VerifyCertificateResult struct {
	Valid           bool
	Subject         string
	Issuer          string
	Serial          string
	NotBefore       time.Time
	NotAfter        time.Time
	Expired         bool
	Revoked         bool
	ChainValid      bool
	ChainLength     int
	ChainSubjects   []string
	ValidationError string
	ExpiresIn       string
	Errors          []string
	Warnings        []string
}

// =============================================================================
// Certificate Revoke Types
// =============================================================================

// RevokeCertificateOptions contains options for certificate revocation.
type RevokeCertificateOptions struct {
	CommonName string
	StoreType  string
	Algorithm  string
	Serial     string
	Reason     RevocationReason
	DeleteKeys bool
}

// RevocationReason specifies the reason for certificate revocation.
type RevocationReason int32

const (
	RevocationReasonUnspecified          RevocationReason = 0
	RevocationReasonKeyCompromise        RevocationReason = 1
	RevocationReasonCACompromise         RevocationReason = 2
	RevocationReasonAffiliationChanged   RevocationReason = 3
	RevocationReasonSuperseded           RevocationReason = 4
	RevocationReasonCessationOfOperation RevocationReason = 5
	RevocationReasonCertificateHold      RevocationReason = 6
	RevocationReasonRemoveFromCRL        RevocationReason = 8
	RevocationReasonPrivilegeWithdrawn   RevocationReason = 9
	RevocationReasonAACompromise         RevocationReason = 10
)

// RevokeCertificateResult contains the result of a certificate revocation.
type RevokeCertificateResult struct {
	Success   bool
	Serial    string
	Status    CertificateStatus
	RevokedAt time.Time
	Reason    RevocationReason
	Message   string
}

// =============================================================================
// Certificate Renew Types
// =============================================================================

// RenewCertificateOptions contains options for certificate renewal.
type RenewCertificateOptions struct {
	Serial       string
	ValidDays    int32
	Force        bool
	PreserveSANs bool
	NewSANsDNS   []string
	NewSANsIPs   []string
	NewSANsEmail []string
}

// RenewCertificateResult contains the result of a certificate renewal.
type RenewCertificateResult struct {
	Success        bool
	OldCertificate *Certificate
	NewCertificate *Certificate
	Message        string
}

// =============================================================================
// CRL Types
// =============================================================================

// GetCRLOptions contains options for retrieving the CRL.
type GetCRLOptions struct {
	IncludeEntries bool
}

// GetCRLResult contains the result of a CRL retrieval.
type GetCRLResult struct {
	Issuer       string
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedCount int32
	RevokedCerts []RevokedCertEntry
	Data         []byte
}

// RevokedCertEntry represents a revoked certificate entry.
type RevokedCertEntry struct {
	Serial         string
	RevocationTime time.Time
	Reason         RevocationReason
}

// GenerateCRLResult contains the result of a CRL generation.
type GenerateCRLResult struct {
	Success    bool
	ThisUpdate time.Time
	NextUpdate time.Time
	Message    string
}

// ExportCRLResult contains the result of a CRL export.
type ExportCRLResult struct {
	Success  bool
	FilePath string
	Size     int64
	Message  string
}

// =============================================================================
// Export Bundle Types
// =============================================================================

// ExportBundleResult contains the result of a CA bundle export.
type ExportBundleResult struct {
	Success   bool
	FilePath  string
	Size      int64
	CertCount int32
	Message   string
}

// =============================================================================
// Install/Uninstall Types
// =============================================================================

// InstallCACertificatesResult contains the result of installing CA certificates.
type InstallCACertificatesResult struct {
	Success   bool
	Installed []string
	Message   string
}

// UninstallCACertificatesResult contains the result of uninstalling CA certificates.
type UninstallCACertificatesResult struct {
	Success     bool
	Uninstalled []string
	Message     string
}
