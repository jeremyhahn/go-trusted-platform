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

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	ErrNilCRL         = errors.New("CRL is nil")
	ErrNilBundle      = errors.New("CA bundle is nil")
	ErrNilCertificate = errors.New("certificate is nil")
	ErrNoPEMData      = errors.New("certificate has no PEM data")
	ErrNoDERData      = errors.New("certificate has no DER data")
)

// ErrGetCAInfoFailed is returned when getting CA info fails.
type ErrGetCAInfoFailed struct {
	Cause error
}

func (e *ErrGetCAInfoFailed) Error() string {
	return fmt.Sprintf("failed to get CA info: %v", e.Cause)
}

func (e *ErrGetCAInfoFailed) Unwrap() error {
	return e.Cause
}

// ErrInitCAFailed is returned when CA initialization fails.
type ErrInitCAFailed struct {
	Cause error
}

func (e *ErrInitCAFailed) Error() string {
	return fmt.Sprintf("failed to initialize CA: %v", e.Cause)
}

func (e *ErrInitCAFailed) Unwrap() error {
	return e.Cause
}

// ErrInstallCACertificatesFailed is returned when installing CA certificates fails.
type ErrInstallCACertificatesFailed struct {
	Cause error
}

func (e *ErrInstallCACertificatesFailed) Error() string {
	return fmt.Sprintf("failed to install CA certificates: %v", e.Cause)
}

func (e *ErrInstallCACertificatesFailed) Unwrap() error {
	return e.Cause
}

// ErrUninstallCACertificatesFailed is returned when uninstalling CA certificates fails.
type ErrUninstallCACertificatesFailed struct {
	Cause error
}

func (e *ErrUninstallCACertificatesFailed) Error() string {
	return fmt.Sprintf("failed to uninstall CA certificates: %v", e.Cause)
}

func (e *ErrUninstallCACertificatesFailed) Unwrap() error {
	return e.Cause
}

// ErrIssueCertificateFailed is returned when certificate issuance fails.
type ErrIssueCertificateFailed struct {
	Cause error
}

func (e *ErrIssueCertificateFailed) Error() string {
	return fmt.Sprintf("failed to issue certificate: %v", e.Cause)
}

func (e *ErrIssueCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrSignCSRFailed is returned when the CA refuses or fails to certify a CSR.
type ErrSignCSRFailed struct {
	Cause error
}

func (e *ErrSignCSRFailed) Error() string {
	return fmt.Sprintf("failed to sign CSR: %v", e.Cause)
}

func (e *ErrSignCSRFailed) Unwrap() error {
	return e.Cause
}

// ErrNilSignCSRParams is returned when SignCSRDomain is called without
// parameters.
type ErrNilSignCSRParams struct{}

func (e ErrNilSignCSRParams) Error() string {
	return "sign CSR parameters are required"
}

// ErrGetCertificateFailed is returned when certificate retrieval fails.
type ErrGetCertificateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrGetCertificateFailed) Error() string {
	return fmt.Sprintf("failed to get certificate %s: %v", e.Serial, e.Cause)
}

func (e *ErrGetCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrListCertificatesFailed is returned when listing certificates fails.
type ErrListCertificatesFailed struct {
	Cause error
}

func (e *ErrListCertificatesFailed) Error() string {
	return fmt.Sprintf("failed to list certificates: %v", e.Cause)
}

func (e *ErrListCertificatesFailed) Unwrap() error {
	return e.Cause
}

// ErrRevokeCertificateFailed is returned when certificate revocation fails.
type ErrRevokeCertificateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrRevokeCertificateFailed) Error() string {
	return fmt.Sprintf("failed to revoke certificate %s: %v", e.Serial, e.Cause)
}

func (e *ErrRevokeCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrRenewCertificateFailed is returned when certificate renewal fails.
type ErrRenewCertificateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrRenewCertificateFailed) Error() string {
	return fmt.Sprintf("failed to renew certificate %s: %v", e.Serial, e.Cause)
}

func (e *ErrRenewCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyCertificateFailed is returned when certificate verification fails.
type ErrVerifyCertificateFailed struct {
	Cause error
}

func (e *ErrVerifyCertificateFailed) Error() string {
	return fmt.Sprintf("failed to verify certificate: %v", e.Cause)
}

func (e *ErrVerifyCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrGetCRLFailed is returned when getting CRL fails.
type ErrGetCRLFailed struct {
	Cause error
}

func (e *ErrGetCRLFailed) Error() string {
	return fmt.Sprintf("failed to get CRL: %v", e.Cause)
}

func (e *ErrGetCRLFailed) Unwrap() error {
	return e.Cause
}

// ErrGetCABundleFailed is returned when getting CA bundle fails.
type ErrGetCABundleFailed struct {
	Cause error
}

func (e *ErrGetCABundleFailed) Error() string {
	return fmt.Sprintf("failed to get CA bundle: %v", e.Cause)
}

func (e *ErrGetCABundleFailed) Unwrap() error {
	return e.Cause
}

// ErrDownloadCRLFailed is returned when downloading CRL fails.
type ErrDownloadCRLFailed struct {
	Cause error
}

func (e *ErrDownloadCRLFailed) Error() string {
	return fmt.Sprintf("failed to download CRL: %v", e.Cause)
}

func (e *ErrDownloadCRLFailed) Unwrap() error {
	return e.Cause
}

// ErrDownloadBundleFailed is returned when downloading CA bundle fails.
type ErrDownloadBundleFailed struct {
	Cause error
}

func (e *ErrDownloadBundleFailed) Error() string {
	return fmt.Sprintf("failed to download CA bundle: %v", e.Cause)
}

func (e *ErrDownloadBundleFailed) Unwrap() error {
	return e.Cause
}

// ErrDownloadCertificateFailed is returned when downloading a certificate fails.
type ErrDownloadCertificateFailed struct {
	Serial string
	Cause  error
}

func (e *ErrDownloadCertificateFailed) Error() string {
	return fmt.Sprintf("failed to download certificate %s: %v", e.Serial, e.Cause)
}

func (e *ErrDownloadCertificateFailed) Unwrap() error {
	return e.Cause
}

// ErrGetCertificateChainFailed is returned when getting certificate chain fails.
type ErrGetCertificateChainFailed struct {
	Serial string
	Cause  error
}

func (e *ErrGetCertificateChainFailed) Error() string {
	return fmt.Sprintf("failed to get certificate chain for %s: %v", e.Serial, e.Cause)
}

func (e *ErrGetCertificateChainFailed) Unwrap() error {
	return e.Cause
}

// ErrCheckRevocationFailed is returned when checking revocation status fails.
type ErrCheckRevocationFailed struct {
	Serial string
	Cause  error
}

func (e *ErrCheckRevocationFailed) Error() string {
	return fmt.Sprintf("failed to check revocation status for %s: %v", e.Serial, e.Cause)
}

func (e *ErrCheckRevocationFailed) Unwrap() error {
	return e.Cause
}
