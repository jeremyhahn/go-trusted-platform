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

package rest

import (
	"context"
	"crypto/x509"
	"math/big"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// =============================================================================
// CA Adapter
// =============================================================================
//
// CAAuthorityAdapter bridges the production CA implementation
// (quicbaasca.CACertificateAuthority / pkg/ca.TCGCA) to the REST handler interface
// (CAServiceInterface). The adapter exists because the production CA returns
// *IssuedCertificate from IssueCertificate and uses RevokeCert(cert, opts) +
// DefaultValidityPeriod() (days as int), while the REST handler interface
// uses *x509.Certificate, Revoke(cert, keyAttrs) and time.Duration.
//
// Wrapping the production CA at the REST boundary keeps the existing handler
// implementation intact and avoids duplicating the request/response logic.
// =============================================================================

// CAAuthorityAdapter wraps a production CA to satisfy CAServiceInterface.
type CAAuthorityAdapter struct {
	ca quicbaasca.CACertificateAuthority
}

// NewCAAuthorityAdapter creates a CAAuthorityAdapter wrapping the given CA.
// Returns nil when ca is nil so callers can use the result directly with
// NewCAHandlers without nil checks (NewCAHandlers itself accepts a nil CA
// and will return ErrCAServiceNotAvailable on every operation).
func NewCAAuthorityAdapter(ca quicbaasca.CACertificateAuthority) *CAAuthorityAdapter {
	if ca == nil {
		return nil
	}
	return &CAAuthorityAdapter{ca: ca}
}

// Identity returns the CA's identity (common name).
func (a *CAAuthorityAdapter) Identity() string {
	return a.ca.Identity()
}

// IsInitialized reports whether the CA has been initialized.
func (a *CAAuthorityAdapter) IsInitialized() bool {
	return a.ca.IsInitialized()
}

// DefaultKeyAlgorithm returns the CA's default public key algorithm.
func (a *CAAuthorityAdapter) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return a.ca.DefaultKeyAlgorithm()
}

// DefaultValidityPeriod returns the default certificate validity period.
// The production CA exposes the value as days (int); we convert to a
// time.Duration for the REST interface.
func (a *CAAuthorityAdapter) DefaultValidityPeriod() time.Duration {
	days := a.ca.DefaultValidityPeriod()
	return time.Duration(days) * 24 * time.Hour
}

// TrustedRoot returns the root CA certificate.
func (a *CAAuthorityAdapter) TrustedRoot() (*x509.Certificate, error) {
	return a.ca.TrustedRoot()
}

// TrustedIntermediate returns the intermediate CA certificate, if any.
func (a *CAAuthorityAdapter) TrustedIntermediate() (*x509.Certificate, error) {
	return a.ca.TrustedIntermediate()
}

// IssueCertificate issues a new certificate via the underlying CA.
// The production CA returns *IssuedCertificate; the adapter unwraps the
// embedded x509 certificate for the REST handler.
func (a *CAAuthorityAdapter) IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*x509.Certificate, error) {
	issued, err := a.ca.IssueCertificate(ctx, req)
	if err != nil {
		return nil, err
	}
	if issued == nil || issued.Certificate == nil {
		return nil, ErrCertificateIssueFailed{Err: ErrIssueReturnedNil{}}
	}
	return issued.Certificate, nil
}

// SignCSR certifies the key in a PEM CSR via the underlying CA.
func (a *CAAuthorityAdapter) SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error) {
	return a.ca.SignCSR(ctx, csrPEM, opts)
}

// Revoke revokes a certificate. The production CA exposes RevokeCert(cert,
// opts); we map the keyAttrs nil/non-nil signal into RevokeOptions.DeleteKeys.
func (a *CAAuthorityAdapter) Revoke(ctx context.Context, cert *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	return a.ca.RevokeCert(ctx, cert, quicbaasca.RevokeOptions{
		DeleteKeys: keyAttrs != nil,
	})
}

// CertificateStore returns the CA's certificate store.
func (a *CAAuthorityAdapter) CertificateStore() xkmssdk.CertStore {
	return a.ca.CertStore()
}

// CABundle returns the CA bundle filtered by the provided store type and key
// algorithm. When both filters are zero values the adapter calls the
// unfiltered CABundle() to avoid a known issue in CABundleFiltered where
// applying a non-empty store filter against an empty matching set returns
// "no certificates match filter".
func (a *CAAuthorityAdapter) CABundle(storeType xkmssdk.StoreType, keyAlg x509.PublicKeyAlgorithm) ([]byte, error) {
	if (storeType == "" || storeType == xkmssdk.StoreUnknown) && keyAlg == x509.UnknownPublicKeyAlgorithm {
		return a.ca.CABundle()
	}
	return a.ca.CABundleFiltered(storeType, keyAlg)
}

// ParseBundle parses a PEM-encoded CA bundle into individual certificates.
func (a *CAAuthorityAdapter) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	return a.ca.ParseBundle(bundle)
}

// GenerateCRL generates a Certificate Revocation List. The REST handler's CRL
// endpoint discovers this method via a runtime type assertion to the crlGenerator
// interface so it does not need to be part of CAServiceInterface.
func (a *CAAuthorityAdapter) GenerateCRL(ctx context.Context) ([]byte, error) {
	return a.ca.GenerateCRL(ctx)
}

// IsRevoked checks whether the certificate identified by serial is revoked.
// The REST handler's verify endpoint discovers this method via a runtime type
// assertion to the revokeChecker interface.
func (a *CAAuthorityAdapter) IsRevoked(serial *big.Int) (bool, error) {
	return a.ca.IsRevoked(serial)
}

// =============================================================================
// Adapter-specific Errors
// =============================================================================

// ErrIssueReturnedNil indicates the underlying CA returned a nil certificate.
type ErrIssueReturnedNil struct{}

func (e ErrIssueReturnedNil) Error() string {
	return "ca returned nil certificate"
}

// Compile-time interface compliance check.
var _ CAServiceInterface = (*CAAuthorityAdapter)(nil)
