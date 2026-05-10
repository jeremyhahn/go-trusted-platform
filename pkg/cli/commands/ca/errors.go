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

import "fmt"

// ErrDaemonConnectionRequired is returned when a command requires daemon connection
// but dual-mode is not yet implemented.
type ErrDaemonConnectionRequired struct{}

func (e ErrDaemonConnectionRequired) Error() string {
	return "daemon connection required: this command requires connection to the platform daemon"
}

// ErrCANotInitialized is returned when CA operations are attempted before initialization.
type ErrCANotInitialized struct{}

func (e ErrCANotInitialized) Error() string {
	return "certificate authority not initialized"
}

// ErrCANotConfigured is returned when CA configuration is missing.
type ErrCANotConfigured struct{}

func (e ErrCANotConfigured) Error() string {
	return "certificate authority not configured"
}

// ErrCertificateNotFound is returned when a certificate cannot be located.
type ErrCertificateNotFound struct {
	Serial string
}

func (e ErrCertificateNotFound) Error() string {
	return fmt.Sprintf("certificate not found: %s", e.Serial)
}

// ErrInvalidCertificatePath is returned when a certificate path is invalid.
type ErrInvalidCertificatePath struct {
	Path   string
	Reason string
}

func (e ErrInvalidCertificatePath) Error() string {
	return fmt.Sprintf("invalid certificate path %s: %s", e.Path, e.Reason)
}

// ErrCertificateExpired is returned when a certificate has expired.
type ErrCertificateExpired struct {
	Subject   string
	ExpiredAt string
}

func (e ErrCertificateExpired) Error() string {
	return fmt.Sprintf("certificate %s expired at %s", e.Subject, e.ExpiredAt)
}

// ErrCertificateRevoked is returned when a certificate has been revoked.
type ErrCertificateRevoked struct {
	Subject string
	Serial  string
}

func (e ErrCertificateRevoked) Error() string {
	return fmt.Sprintf("certificate %s (serial: %s) is revoked", e.Subject, e.Serial)
}

// ErrCertificateVerificationFailed is returned when certificate verification fails.
type ErrCertificateVerificationFailed struct {
	Subject string
	Reason  string
}

func (e ErrCertificateVerificationFailed) Error() string {
	return fmt.Sprintf("certificate verification failed for %s: %s", e.Subject, e.Reason)
}

// ErrCertificateNotExpiring is returned when renewal is attempted on a non-expiring certificate.
type ErrCertificateNotExpiring struct {
	Subject   string
	ExpiresIn string
}

func (e ErrCertificateNotExpiring) Error() string {
	return fmt.Sprintf("certificate %s not expiring soon (expires in %s), use --force to renew", e.Subject, e.ExpiresIn)
}

// ErrCRLNotFound is returned when a CRL cannot be located.
type ErrCRLNotFound struct {
	Issuer string
}

func (e ErrCRLNotFound) Error() string {
	return fmt.Sprintf("CRL not found for issuer: %s", e.Issuer)
}

// ErrCRLGenerationFailed is returned when CRL generation fails.
type ErrCRLGenerationFailed struct {
	Reason string
}

func (e ErrCRLGenerationFailed) Error() string {
	return fmt.Sprintf("CRL generation failed: %s", e.Reason)
}

// ErrCRLExportFailed is returned when CRL export fails.
type ErrCRLExportFailed struct {
	Reason string
}

func (e ErrCRLExportFailed) Error() string {
	return fmt.Sprintf("CRL export failed: %s", e.Reason)
}

// ErrCRLEmpty is returned when the CRL is empty.
type ErrCRLEmpty struct{}

func (e ErrCRLEmpty) Error() string {
	return "CRL is empty"
}

// ErrGetCRLFailed is returned when getting the CRL fails.
type ErrGetCRLFailed struct {
	Reason string
}

func (e ErrGetCRLFailed) Error() string {
	return fmt.Sprintf("failed to get CRL: %s", e.Reason)
}

// ErrInvalidOutputFormat is returned when an invalid output format is specified.
type ErrInvalidOutputFormat struct {
	Format string
}

func (e ErrInvalidOutputFormat) Error() string {
	return fmt.Sprintf("invalid output format: %s (valid: table, json, yaml)", e.Format)
}

// ErrInvalidStatus is returned when an invalid certificate status filter is specified.
type ErrInvalidStatus struct {
	Status string
}

func (e ErrInvalidStatus) Error() string {
	return fmt.Sprintf("invalid status filter: %s (valid: valid, revoked, expired, all)", e.Status)
}

// ErrMissingArgument is returned when a required argument is missing.
type ErrMissingArgument struct {
	Argument string
}

func (e ErrMissingArgument) Error() string {
	return fmt.Sprintf("missing required argument: %s", e.Argument)
}

// ErrInvalidSerial is returned when an invalid serial number is provided.
type ErrInvalidSerial struct {
	Serial string
}

func (e ErrInvalidSerial) Error() string {
	return fmt.Sprintf("invalid serial number: %s", e.Serial)
}

// ErrInvalidStoreType is returned when an invalid store type is provided.
type ErrInvalidStoreType struct {
	Store string
}

func (e ErrInvalidStoreType) Error() string {
	return fmt.Sprintf("invalid store type: %s", e.Store)
}

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm is provided.
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrInvalidRevocationReason is returned when an invalid revocation reason is provided.
type ErrInvalidRevocationReason struct {
	Reason string
}

func (e ErrInvalidRevocationReason) Error() string {
	return fmt.Sprintf("invalid revocation reason: %s", e.Reason)
}

// ErrIssueCertificateFailed is returned when certificate issuance fails.
type ErrIssueCertificateFailed struct {
	Reason string
}

func (e ErrIssueCertificateFailed) Error() string {
	return fmt.Sprintf("failed to issue certificate: %s", e.Reason)
}

// ErrGetCertificateFailed is returned when getting a certificate fails.
type ErrGetCertificateFailed struct {
	Reason string
}

func (e ErrGetCertificateFailed) Error() string {
	return fmt.Sprintf("failed to get certificate: %s", e.Reason)
}

// ErrRevokeCertificateFailed is returned when certificate revocation fails.
type ErrRevokeCertificateFailed struct {
	Reason string
}

func (e ErrRevokeCertificateFailed) Error() string {
	return fmt.Sprintf("failed to revoke certificate: %s", e.Reason)
}

// ErrRenewCertificateFailed is returned when certificate renewal fails.
type ErrRenewCertificateFailed struct {
	Reason string
}

func (e ErrRenewCertificateFailed) Error() string {
	return fmt.Sprintf("failed to renew certificate: %s", e.Reason)
}

// ErrVerifyCertificateFailed is returned when certificate verification fails.
type ErrVerifyCertificateFailed struct {
	Reason string
}

func (e ErrVerifyCertificateFailed) Error() string {
	return fmt.Sprintf("failed to verify certificate: %s", e.Reason)
}

// ErrCABundleFailed is returned when CA bundle retrieval or persistence fails.
type ErrCABundleFailed struct {
	Reason string
}

func (e ErrCABundleFailed) Error() string {
	return fmt.Sprintf("CA bundle operation failed: %s", e.Reason)
}

// ErrBundleEmpty is returned when the CA bundle is empty.
type ErrBundleEmpty struct{}

func (e ErrBundleEmpty) Error() string {
	return "CA bundle is empty"
}

// ErrInitCAFailed is returned when CA initialization fails.
type ErrInitCAFailed struct {
	Reason string
}

func (e ErrInitCAFailed) Error() string {
	return fmt.Sprintf("failed to initialize CA: %s", e.Reason)
}

// ErrGetCAInfoFailed is returned when getting CA info fails.
type ErrGetCAInfoFailed struct {
	Reason string
}

func (e ErrGetCAInfoFailed) Error() string {
	return fmt.Sprintf("failed to get CA info: %s", e.Reason)
}

// ErrInstallCertificatesFailed is returned when installing CA certificates fails.
type ErrInstallCertificatesFailed struct {
	Reason string
}

func (e ErrInstallCertificatesFailed) Error() string {
	return fmt.Sprintf("failed to install CA certificates: %s", e.Reason)
}

// ErrUninstallCertificatesFailed is returned when uninstalling CA certificates fails.
type ErrUninstallCertificatesFailed struct {
	Reason string
}

func (e ErrUninstallCertificatesFailed) Error() string {
	return fmt.Sprintf("failed to uninstall CA certificates: %s", e.Reason)
}

// ErrNotImplemented is returned when a feature is not yet implemented.
type ErrNotImplemented struct {
	Operation string
}

func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("operation not implemented: %s", e.Operation)
}
