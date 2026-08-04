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

package grpc

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	certstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"
)

// baseMockCA is a zero-behavior mock that implements every method of
// ca.TCGCA (and the ObjectStore() extension used via type assertion by
// the CA gRPC service). Individual tests embed baseMockCA in their own
// mock types and override just the methods they care about.
type baseMockCA struct{}

// crypto.Signer
func (m *baseMockCA) Public() crypto.PublicKey { return nil }
func (m *baseMockCA) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// Lifecycle
func (m *baseMockCA) Init(_ context.Context) error { return nil }
func (m *baseMockCA) Load(_ context.Context) error { return nil }
func (m *baseMockCA) IsInitialized() bool          { return false }

// CSR / Issuance
func (m *baseMockCA) SignCSR(_ context.Context, _ []byte, _ *xkmsca.SignOptions) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) CreateCSR(_ context.Context, _ *xkmsca.CACertificateRequest) ([]byte, error) {
	return nil, nil
}
func (m *baseMockCA) IssueCertificate(_ context.Context, _ *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	return nil, nil
}
func (m *baseMockCA) IssueCertificateWithProfile(_ context.Context, _ *xkmsca.CACertificateRequest, _ string) (*xkmsca.IssuedCertificate, error) {
	return nil, nil
}

// Trust chain
func (m *baseMockCA) CACertificate() (*x509.Certificate, error) { return nil, nil }
func (m *baseMockCA) CABundle() ([]byte, error)                 { return nil, nil }
func (m *baseMockCA) CABundleFiltered(_ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) ([]byte, error) {
	return nil, nil
}
func (m *baseMockCA) CABundleCertPool() (*x509.CertPool, error) { return nil, nil }
func (m *baseMockCA) Verify(_ *x509.Certificate, _ ...crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) TrustedRoot() (*x509.Certificate, error)         { return nil, nil }
func (m *baseMockCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }
func (m *baseMockCA) TrustedRootCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return nil, nil
}
func (m *baseMockCA) TrustedIntermediateCertPool(_ *x509.Certificate) (*x509.CertPool, error) {
	return nil, nil
}
func (m *baseMockCA) TrustedRootCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *baseMockCA) TrustedIntermediateCertPoolWithXSigner(_ *x509.Certificate, _ crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *baseMockCA) ParseBundle(_ []byte) ([]*x509.Certificate, error) { return nil, nil }
func (m *baseMockCA) RootCertificate(_ *x509.Certificate) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) OSTrustStore() (*x509.CertPool, error) { return nil, nil }

// Revocation
func (m *baseMockCA) Revoke(_ context.Context, _ *big.Int, _ int) error { return nil }
func (m *baseMockCA) RevokeCert(_ context.Context, _ *x509.Certificate, _ xkmsca.RevokeOptions) error {
	return nil
}
func (m *baseMockCA) IsRevoked(_ *big.Int) (bool, error) { return false, nil }
func (m *baseMockCA) GenerateCRL(_ context.Context) ([]byte, error) {
	return nil, nil
}
func (m *baseMockCA) ImportDistributionCRLs(_ *x509.Certificate) error { return nil }

// TLS
func (m *baseMockCA) TLSCertificate(_ context.Context, _ *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *baseMockCA) TLSConfig(_ context.Context, _ *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *baseMockCA) TLSConfigWithXSigner(_ context.Context, _ *xkmssdk.KeyAttributes, _ crypto.Signer) (*tls.Config, error) {
	return nil, nil
}
func (m *baseMockCA) QuantumSafeTLSConfig(_ context.Context, _ *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *baseMockCA) TLSBundle(_ context.Context, _ *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}
func (m *baseMockCA) TLSBundleWithCrossSigner(_ context.Context, _ *xkmssdk.KeyAttributes, _ crypto.Signer) ([]byte, error) {
	return nil, nil
}
func (m *baseMockCA) ServerTLSConfig(_ context.Context, _ *xkmssdk.KeyAttributes, _ bool) (*tls.Config, error) {
	return nil, nil
}
func (m *baseMockCA) ClientTLSConfig(_ context.Context, _ *xkmssdk.KeyAttributes, _ string) (*tls.Config, error) {
	return nil, nil
}

// Config
func (m *baseMockCA) Config() *xkmsca.CAIdentity         { return nil }
func (m *baseMockCA) Identity() string                   { return "" }
func (m *baseMockCA) IssuingIdentity() xkmsca.CAIdentity { return xkmsca.CAIdentity{} }
func (m *baseMockCA) CAConfig() xkmsca.CAConfig          { return xkmsca.CAConfig{} }
func (m *baseMockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm {
	return x509.UnknownPublicKeyAlgorithm
}
func (m *baseMockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.UnknownSignatureAlgorithm
}
func (m *baseMockCA) DefaultValidityPeriod() int     { return 0 }
func (m *baseMockCA) Hash() crypto.Hash              { return crypto.SHA256 }
func (m *baseMockCA) IsAutoImportingIssuerCAs() bool { return false }

// Keys & signing identity
func (m *baseMockCA) Signer(_ context.Context) (crypto.Signer, error) { return nil, nil }
func (m *baseMockCA) PrivateKey(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, nil
}
func (m *baseMockCA) PubKey(_ context.Context, _ *xkmssdk.KeyAttributes) (crypto.PublicKey, error) {
	return nil, nil
}
func (m *baseMockCA) SignedBlob(_ context.Context, _ []byte) ([]byte, error) { return nil, nil }
func (m *baseMockCA) CAKeyAttributes(_ xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *baseMockCA) CASigner(_ context.Context, _ xkmssdk.StoreType, _ x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return nil, nil
}

// Storage access
func (m *baseMockCA) KeyStore() xkmsbackend.Backend  { return nil }
func (m *baseMockCA) CertStore() certstore.CertStore { return nil }

// Certificates
func (m *baseMockCA) Issued(_ context.Context, _ string) (bool, error) { return false, nil }
func (m *baseMockCA) Exists(_ context.Context, _ string, _ x509.PublicKeyAlgorithm) (bool, error) {
	return false, nil
}
func (m *baseMockCA) Certificate(_ context.Context, _ *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) CertificatePEM(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (m *baseMockCA) ImportCertificate(_ context.Context, _ *x509.Certificate) error {
	return nil
}
func (m *baseMockCA) ImportCertificatePEM(_ context.Context, _ string, _ []byte) error { return nil }
func (m *baseMockCA) PEM(_ context.Context, _ *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}

// Object store helpers
func (m *baseMockCA) Blob(_ []byte) ([]byte, error)       { return nil, nil }
func (m *baseMockCA) ImportBlob(_ []byte, _ []byte) error { return nil }

// Cross-signing
func (m *baseMockCA) ImportXSignedCertificate(_ string, _ *x509.Certificate) error { return nil }
func (m *baseMockCA) XSignedCertificate(_ string, _ *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) XSignedRootCertificate(_ string, _ *x509.Certificate) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) XSignedIntermediateCertificates(_ string, _ *x509.Certificate) ([]*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) CrossSignedPEM(_ *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}

// AIA
func (m *baseMockCA) ImportIssuingCAs(_ context.Context, _ *x509.Certificate) error { return nil }

// Attestation
func (m *baseMockCA) ImportAttestation(_ context.Context, _ *xkmssdk.KeyAttributes, _ string, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportAttestationKeyCertificate(_ context.Context, _ *xkmssdk.KeyAttributes, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportAttestationEventLog(_ context.Context, _ *xkmssdk.KeyAttributes, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportAttestationPCRs(_ context.Context, _ *xkmssdk.KeyAttributes, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportAttestationQuote(_ context.Context, _ *xkmssdk.KeyAttributes, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportLocalAttestation(_ context.Context, _ *xkmssdk.KeyAttributes, _ *xkmssdk.Quote) error {
	return nil
}
func (m *baseMockCA) VerifyAttestationQuote(_ *xkmssdk.KeyAttributes, _ []byte) error    { return nil }
func (m *baseMockCA) VerifyAttestationEventLog(_ *xkmssdk.KeyAttributes, _ []byte) error { return nil }
func (m *baseMockCA) VerifyAttestationPCRs(_ *xkmssdk.KeyAttributes, _ []byte) error     { return nil }

// TCG enrollment verification
func (m *baseMockCA) VerifyTCG_CSR_IDevIDBytes(_ []byte, _ x509.SignatureAlgorithm) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}

// TCGCA extensions
func (m *baseMockCA) IssueEKCertificate(_ context.Context, _ *xkmsca.CACertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) IssueAKCertificate(_ context.Context, _ *xkmsca.CACertificateRequest, _ crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *baseMockCA) SignTCGCSRIDevID(_ context.Context, _ *xkmssdk.TCG_CSR_IDEVID, _ *xkmsca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *baseMockCA) EnrollDevice(_ context.Context, _ []byte, _ *xkmsca.CACertificateRequest) (*xkmsca.TCGEnrollmentResult, error) {
	return nil, nil
}
func (m *baseMockCA) SetTPM(_ xkmssdk.TrustedPlatformModule) {}
func (m *baseMockCA) VerifyQuote(_ *xkmssdk.KeyAttributes, _ *xkmssdk.Quote, _ []byte) error {
	return nil
}
func (m *baseMockCA) ImportEndorsementKeyCertificate(_ *x509.Certificate) error { return nil }
func (m *baseMockCA) EndorsementKeyCertificate(_ string) (*x509.Certificate, error) {
	return nil, nil
}
