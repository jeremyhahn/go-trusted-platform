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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	common "github.com/jeremyhahn/go-objstore/pkg/common"
	goca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, os.Stderr)
}

// testCA holds certificate and key for testing
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// Helper to create a self-signed CA certificate with key
func createTestCAWithKey(t *testing.T, cn string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createIntermediateCAWithKey creates an intermediate CA signed by the parent CA
func createIntermediateCAWithKey(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent.cert, &key.PublicKey, parent.key)
	if err != nil {
		t.Fatalf("failed to create intermediate CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse intermediate CA certificate: %v", err)
	}

	return &testCA{cert: cert, key: key}
}

// createCertSignedByCA creates a certificate signed by the given CA
func createCertSignedByCA(t *testing.T, cn string, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         cn,
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("192.168.1.1")},
		EmailAddresses:        []string{"test@example.com"},
	}

	// Add URI SANs
	uri, _ := url.Parse("https://example.com/test")
	template.URIs = []*url.URL{uri}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createExpiredCertSignedByCA creates an expired certificate signed by the given CA
func createExpiredCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "expired.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

// createFutureCertSignedByCA creates a not-yet-valid certificate signed by the given CA
func createFutureCertSignedByCA(t *testing.T, ca *testCA) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "future.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(24 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func assertGRPCError(t *testing.T, err error, expectedCode codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}

	if st.Code() != expectedCode {
		t.Errorf("expected code %v, got %v: %s", expectedCode, st.Code(), st.Message())
	}
}

// mockCertStore is a simple mock for the cert store interface
type mockCertStore struct {
	certs    map[string]*x509.Certificate
	listErr  error
	getError error
}

func newMockCertStore() *mockCertStore {
	return &mockCertStore{
		certs: make(map[string]*x509.Certificate),
	}
}

func (m *mockCertStore) GetCertificate(id string) (*x509.Certificate, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if cert, ok := m.certs[id]; ok {
		return cert, nil
	}
	return nil, errors.New("certificate not found")
}

func (m *mockCertStore) StoreCertificate(cert *x509.Certificate) error {
	return nil
}

func (m *mockCertStore) DeleteCertificate(id string) error {
	return nil
}

func (m *mockCertStore) ListCertificates() ([]*x509.Certificate, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var certs []*x509.Certificate
	for _, cert := range m.certs {
		certs = append(certs, cert)
	}
	return certs, nil
}

func (m *mockCertStore) StoreCertificateChain(chain []*x509.Certificate) error {
	return nil
}

func (m *mockCertStore) GetCertificateChain(cn string) ([]*x509.Certificate, error) {
	return nil, errors.New("chain not found")
}

func (m *mockCertStore) StoreCRL(crl *x509.RevocationList) error {
	return nil
}

func (m *mockCertStore) GetCRL(issuer string) (*x509.RevocationList, error) {
	return nil, errors.New("CRL not found")
}

func (m *mockCertStore) VerifyCertificate(cert *x509.Certificate, roots *x509.CertPool) error {
	return nil
}

func (m *mockCertStore) IsRevoked(cert *x509.Certificate) (bool, error) {
	return false, nil
}

func (m *mockCertStore) Close() error {
	return nil
}

// configurableMockCA is a mock CA with configurable responses
// It implements the goca.CACertificateAuthority interface.
type configurableMockCA struct {
	isInitialized   bool
	identity        string
	defaultKeyAlg   x509.PublicKeyAlgorithm
	defaultValidity time.Duration
	trustedRoot     *x509.Certificate
	trustedInter    *x509.Certificate
	issuedCert      *x509.Certificate
	issueCertErr    error
	revokeErr       error
	bundleErr       error
	bundle          []byte
	parsedBundle    []*x509.Certificate
	certStore       xkmssdk.CertStore
}

// crypto.Signer interface
func (m *configurableMockCA) Public() crypto.PublicKey { return nil }
func (m *configurableMockCA) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

// Core CA methods
func (m *configurableMockCA) SignCSR(csrPEM []byte, request *goca.CACertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) SignTCGCSRIDevID(tcgCSRIDevID *xkmssdk.TCG_CSR_IDEVID, request *goca.CACertificateRequest) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *configurableMockCA) CABundle(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error) {
	if m.bundleErr != nil {
		return nil, m.bundleErr
	}
	return m.bundle, nil
}
func (m *configurableMockCA) ImportCertificate(certificate *x509.Certificate) error { return nil }
func (m *configurableMockCA) Certificate(attrs *xkmssdk.KeyAttributes) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) CertificatePEM(cn string) ([]byte, error) { return nil, nil }
func (m *configurableMockCA) Verify(certificate *x509.Certificate, xsigner crypto.Signer) ([][]*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) Signer() (crypto.Signer, error)          { return nil, nil }
func (m *configurableMockCA) TrustedRoot() (*x509.Certificate, error) { return m.trustedRoot, nil }
func (m *configurableMockCA) TrustedIntermediate() (*x509.Certificate, error) {
	return m.trustedInter, nil
}
func (m *configurableMockCA) CreateCSR(request *goca.CACertificateRequest) ([]byte, error) {
	return nil, nil
}
func (m *configurableMockCA) TLSCertificate(attrs *xkmssdk.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, nil
}
func (m *configurableMockCA) TLSBundle(attrs *xkmssdk.KeyAttributes) ([]byte, error) { return nil, nil }
func (m *configurableMockCA) TLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *configurableMockCA) TLSConfigWithXSigner(attrs *xkmssdk.KeyAttributes, xsigner interface{}) (*tls.Config, error) {
	return nil, nil
}
func (m *configurableMockCA) QuantumSafeTLSConfig(attrs *xkmssdk.KeyAttributes) (*tls.Config, error) {
	return nil, nil
}
func (m *configurableMockCA) TLSBundleWithCrossSigner(attrs *xkmssdk.KeyAttributes, issuerCN string) ([][]byte, *x509.Certificate, error) {
	return nil, nil, nil
}
func (m *configurableMockCA) IssueCertificate(request *goca.CACertificateRequest) (*x509.Certificate, error) {
	if m.issueCertErr != nil {
		return nil, m.issueCertErr
	}
	return m.issuedCert, nil
}
func (m *configurableMockCA) Issued(cn string) (bool, error) { return false, nil }
func (m *configurableMockCA) Exists(cn string, algorithm x509.SignatureAlgorithm) (bool, error) {
	return false, nil
}
func (m *configurableMockCA) Revoke(certificate *x509.Certificate, keyAttrs *xkmssdk.KeyAttributes) error {
	return m.revokeErr
}
func (m *configurableMockCA) GenerateCRL() ([]byte, error)                        { return nil, nil }
func (m *configurableMockCA) IsRevoked(serial *big.Int) (bool, error)             { return false, nil }
func (m *configurableMockCA) ImportDistributionCRLs(cert *x509.Certificate) error { return nil }
func (m *configurableMockCA) IssueEKCertificate(request *goca.CACertificateRequest, ekPubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) IssueAKCertificate(request *goca.CACertificateRequest, pubKey crypto.PublicKey) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) ImportEndorsementKeyCertificate(cert *x509.Certificate) error {
	return nil
}
func (m *configurableMockCA) ImportXSignedCertificate(issuerCN string, cert *x509.Certificate) error {
	return nil
}
func (m *configurableMockCA) EndorsementKeyCertificate(cn string) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) SignedBlob(data interface{}) ([]byte, error) { return nil, nil }
func (m *configurableMockCA) TrustedRootCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *configurableMockCA) TrustedIntermediateCertPool(cert *x509.Certificate, xsigner crypto.Signer) (*x509.CertPool, error) {
	return nil, nil
}
func (m *configurableMockCA) CABundleCertPool(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) (*x509.CertPool, error) {
	return nil, nil
}
func (m *configurableMockCA) ImportIssuingCAs(cert *x509.Certificate) error { return nil }
func (m *configurableMockCA) ParseBundle(bundle []byte) ([]*x509.Certificate, error) {
	return m.parsedBundle, nil
}
func (m *configurableMockCA) RootCertificate(childCert *x509.Certificate) (*x509.Certificate, error) {
	return nil, nil
}
func (m *configurableMockCA) CertificateStore() xkmssdk.CertStore { return m.certStore }
func (m *configurableMockCA) ObjectStore() common.Storage         { return nil }
func (m *configurableMockCA) PEM(attrs *xkmssdk.KeyAttributes) ([]byte, error) {
	return nil, nil
}
func (m *configurableMockCA) ImportCertificatePEM(cn string, pemData []byte) error  { return nil }
func (m *configurableMockCA) Blob(key string) ([]byte, error)                       { return nil, nil }
func (m *configurableMockCA) ImportBlob(key string, data []byte) error              { return nil }
func (m *configurableMockCA) KeyStore() interface{}                                 { return nil }
func (m *configurableMockCA) Key(attrs *xkmssdk.KeyAttributes) (interface{}, error) { return nil, nil }
func (m *configurableMockCA) PubKey(attrs *xkmssdk.KeyAttributes) (crypto.PublicKey, error) {
	return nil, nil
}
func (m *configurableMockCA) OSTrustStore() (*x509.CertPool, error)              { return nil, nil }
func (m *configurableMockCA) IsAutoImportingIssuerCAs() bool                     { return false }
func (m *configurableMockCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm       { return m.defaultKeyAlg }
func (m *configurableMockCA) DefaultSignatureAlgorithm() x509.SignatureAlgorithm { return 0 }
func (m *configurableMockCA) DefaultValidityPeriod() time.Duration               { return m.defaultValidity }
func (m *configurableMockCA) Hash() crypto.Hash                                  { return crypto.SHA256 }
func (m *configurableMockCA) Identity() string                                   { return m.identity }
func (m *configurableMockCA) CAKeyAttributes(storeType xkmssdk.StoreType) (*xkmssdk.KeyAttributes, error) {
	return nil, nil
}
func (m *configurableMockCA) CASigner(storeType xkmssdk.StoreType, algorithm x509.PublicKeyAlgorithm) (crypto.Signer, error) {
	return nil, nil
}
func (m *configurableMockCA) Init() error         { return nil }
func (m *configurableMockCA) Load() error         { return nil }
func (m *configurableMockCA) IsInitialized() bool { return m.isInitialized }
func (m *configurableMockCA) CAConfig() goca.CAConfig {
	return goca.CAConfig{}
}
func (m *configurableMockCA) ImportAttestation(akAttrs *xkmssdk.KeyAttributes, blobType string, data []byte) error {
	return nil
}
func (m *configurableMockCA) ImportAttestationKeyCertificate(attrs *xkmssdk.KeyAttributes, akDER []byte) error {
	return nil
}
func (m *configurableMockCA) ImportAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *configurableMockCA) ImportAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *configurableMockCA) ImportAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *configurableMockCA) ImportLocalAttestation(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote) error {
	return nil
}
func (m *configurableMockCA) VerifyQuote(akAttrs *xkmssdk.KeyAttributes, quote *xkmssdk.Quote, nonce []byte) error {
	return nil
}
func (m *configurableMockCA) VerifyAttestationQuote(akAttrs *xkmssdk.KeyAttributes, quote []byte) error {
	return nil
}
func (m *configurableMockCA) VerifyAttestationEventLog(akAttrs *xkmssdk.KeyAttributes, eventLog []byte) error {
	return nil
}
func (m *configurableMockCA) VerifyAttestationPCRs(akAttrs *xkmssdk.KeyAttributes, pcrs []byte) error {
	return nil
}
func (m *configurableMockCA) VerifyTCG_CSR_IDevIDBytes(packedCSR []byte, sigAlg interface{}) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
}
func (m *configurableMockCA) SetTPM(tpm xkmssdk.TrustedPlatformModule) {}

// Test cases

func TestNewCAGRPCService(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	mockCA := &configurableMockCA{}

	service := NewCAGRPCService(logger, mockCA)

	if service == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestGetCAInfo_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	service := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := service.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCAInfo_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	mockCA := &configurableMockCA{
		isInitialized:   true,
		identity:        "test-ca",
		defaultKeyAlg:   x509.ECDSA,
		defaultValidity: 365 * 24 * time.Hour,
		trustedRoot:     rootCA.cert,
		trustedInter:    intermediateCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.CaInfo.IsInitialized {
		t.Error("expected CA to be initialized")
	}
	if resp.CaInfo.CommonName != "test-ca" {
		t.Errorf("expected CN 'test-ca', got %q", resp.CaInfo.CommonName)
	}
	if resp.CaInfo.DefaultAlgorithm != "ECDSA" {
		t.Errorf("expected algorithm ECDSA, got %q", resp.CaInfo.DefaultAlgorithm)
	}
	if !resp.CaInfo.IsIntermediate {
		t.Error("expected IsIntermediate to be true")
	}
}

func TestGetCAInfo_NotInitialized(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		isInitialized: false,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CaInfo.IsInitialized {
		t.Error("expected CA not to be initialized")
	}
}

func TestIssueCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestIssueCertificate_MissingRequest(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_MissingSubject(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{},
	})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_MissingCommonName(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{},
		},
	})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestIssueCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	issuedCert := createCertSignedByCA(t, "test.example.com", rootCA)

	mockCA := &configurableMockCA{
		issuedCert: issuedCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName:   "test.example.com",
				Organization: "Test Org",
				Country:      "US",
			},
			KeyAlgorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256,
			ValidDays:    365,
			KeyUsage:     []string{"DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"},
			ExtKeyUsage:  []string{"SERVER_AUTH", "CLIENT_AUTH"},
			Sans: &platformv1.SubjectAlternativeNames{
				DnsNames:    []string{"test.example.com", "www.example.com"},
				IpAddresses: []string{"192.168.1.1"},
			},
			StoreType: "software",
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success status")
	}
	if resp.Certificate == nil {
		t.Error("expected certificate in response")
	}
}

func TestIssueCertificate_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		issueCertErr: errors.New("failed to issue"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.IssueCertificate(ctx, &platformv1.IssueCertificateRequest{
		Request: &platformv1.CertificateRequest{
			Subject: &platformv1.Subject{
				CommonName: "test.example.com",
			},
		},
	})
	assertGRPCError(t, err, codes.Internal)
}

func TestGetCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestGetCertificate_FromRoot(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	serial := hex.EncodeToString(rootCA.cert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial:     serial,
		IncludePem: true,
		IncludeDer: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate == nil {
		t.Error("expected certificate")
	}
	if len(resp.Certificate.Pem) == 0 {
		t.Error("expected PEM to be included")
	}
	if len(resp.Certificate.Der) == 0 {
		t.Error("expected DER to be included")
	}
}

func TestGetCertificate_FromIntermediate(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)
	serial := hex.EncodeToString(intermediateCA.cert.SerialNumber.Bytes())

	mockCA := &configurableMockCA{
		trustedInter: intermediateCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: serial,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate.Subject.CommonName != "Test Intermediate CA" {
		t.Errorf("expected 'Test Intermediate CA', got %s", resp.Certificate.Subject.CommonName)
	}
}

func TestGetCertificate_FromCertStore(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: serial,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Certificate.Subject.CommonName != "test.example.com" {
		t.Errorf("expected 'test.example.com', got %s", resp.Certificate.Subject.CommonName)
	}
}

func TestGetCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.GetCertificate(ctx, &platformv1.GetCertificateRequest{
		Serial: "nonexistent",
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestListCertificates_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestListCertificates_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert1 := createCertSignedByCA(t, "cert1.example.com", rootCA)
	serial1 := hex.EncodeToString(cert1.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial1] = cert1

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
		certStore:   certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10,
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) == 0 {
		t.Error("expected certificates to be returned")
	}
	if resp.Pagination.Page != 1 {
		t.Error("expected page 1")
	}
}

func TestListCertificates_WithFilters(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_CA,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) == 0 {
		t.Error("expected CA certificates")
	}
}

func TestListCertificates_PaginationBeyondTotal(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     100,
			PageSize: 10,
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Certificates) != 0 {
		t.Error("expected empty list for page beyond total")
	}
}

func TestListCertificates_MaxPageSize(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.ListCertificates(ctx, &platformv1.ListCertificatesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 10000, // Over max
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Pagination.PageSize > caGRPCMaxPageSize {
		t.Error("page size should be capped at max")
	}
}

func TestRevokeCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestRevokeCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRevokeCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: "nonexistent",
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestRevokeCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE,
		DeleteKeys: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
	if resp.CertificateStatus != platformv1.CertificateStatus_CERTIFICATE_STATUS_REVOKED {
		t.Error("expected revoked status")
	}
}

func TestRevokeCertificate_Error(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	cert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(cert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = cert

	mockCA := &configurableMockCA{
		certStore: certStore,
		revokeErr: errors.New("revoke failed"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RevokeCertificate(ctx, &platformv1.RevokeCertificateRequest{
		Serial: serial,
	})
	assertGRPCError(t, err, codes.Internal)
}

func TestRenewCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{Serial: "test", ValidDays: 365})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestRenewCertificate_MissingSerial(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{ValidDays: 365})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRenewCertificate_MissingValidDays(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{Serial: "test"})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestRenewCertificate_NotFound(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    "nonexistent",
		ValidDays: 365,
	})
	assertGRPCError(t, err, codes.NotFound)
}

func TestRenewCertificate_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createCertSignedByCA(t, "test.example.com", rootCA)

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:  certStore,
		issuedCert: newCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:       serial,
		ValidDays:    365,
		PreserveSans: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
	if resp.OldCertificate == nil {
		t.Error("expected old certificate")
	}
	if resp.NewCertificate == nil {
		t.Error("expected new certificate")
	}
}

func TestRenewCertificate_WithNewSans(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())
	newCert := createCertSignedByCA(t, "test.example.com", rootCA)

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:  certStore,
		issuedCert: newCert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
		NewSans: &platformv1.SubjectAlternativeNames{
			DnsNames:    []string{"new.example.com"},
			IpAddresses: []string{"10.0.0.1"},
		},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Status.Success {
		t.Error("expected success")
	}
}

func TestRenewCertificate_Error(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	existingCert := createCertSignedByCA(t, "test.example.com", rootCA)
	serial := hex.EncodeToString(existingCert.SerialNumber.Bytes())

	certStore := newMockCertStore()
	certStore.certs[serial] = existingCert

	mockCA := &configurableMockCA{
		certStore:    certStore,
		issueCertErr: errors.New("failed to renew"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.RenewCertificate(ctx, &platformv1.RenewCertificateRequest{
		Serial:    serial,
		ValidDays: 365,
	})
	assertGRPCError(t, err, codes.Internal)
}

func TestVerifyCertificate_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{CertificatePem: []byte("test")})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestVerifyCertificate_MissingCertificate(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{})
	assertGRPCError(t, err, codes.InvalidArgument)
}

func TestVerifyCertificate_InvalidPEM(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: []byte("not a valid PEM"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate")
	}
	if len(resp.Errors) == 0 {
		t.Error("expected errors")
	}
}

func TestVerifyCertificate_InvalidDER(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificateDer: []byte("not valid DER"),
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate")
	}
}

func TestVerifyCertificate_ValidWithPEM(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestVerifyCertificate_ValidWithDER(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificateDer: leafCert.Raw,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate, errors: %v", resp.Errors)
	}
}

func TestVerifyCertificate_Expired(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	expiredCert := createExpiredCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: expiredCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Valid {
		t.Error("expected invalid certificate for expired cert")
	}
}

func TestVerifyCertificate_NotYetValid(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	futureCert := createFutureCertSignedByCA(t, rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: futureCert.Raw,
	})

	mockCA := &configurableMockCA{
		trustedRoot: rootCA.cert,
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem:   pemBlock,
		VerifyExpiration: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Warnings) == 0 {
		t.Error("expected warnings for not yet valid cert")
	}
}

func TestVerifyCertificate_WithTrustedRoots(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "External Root CA")
	leafCert := createCertSignedByCA(t, "test.example.com", rootCA)

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCert.Raw,
	})

	mockCA := &configurableMockCA{}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.VerifyCertificate(ctx, &platformv1.VerifyCertificateRequest{
		CertificatePem: pemBlock,
		TrustedRoots:   [][]byte{rootCA.cert.Raw},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Valid {
		t.Errorf("expected valid certificate with trusted root, errors: %v", resp.Errors)
	}
}

func TestGetCRL_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCRL_NoCRLSupport(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{}
	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCRL(ctx, &platformv1.GetCRLRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Crl == nil {
		t.Error("expected CRL response")
	}
	if resp.Crl.RevokedCount != 0 {
		t.Error("expected empty CRL")
	}
}

func TestGetCABundle_NilCA(t *testing.T) {
	t.Parallel()

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, nil)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.FailedPrecondition)
}

func TestGetCABundle_Error(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundleErr: errors.New("bundle error"),
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.Internal)
}

func TestGetCABundle_Empty(t *testing.T) {
	t.Parallel()

	mockCA := &configurableMockCA{
		bundle: []byte{},
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	_, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{})
	assertGRPCError(t, err, codes.NotFound)
}

func TestGetCABundle_Success(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test Root CA")
	intermediateCA := createIntermediateCAWithKey(t, "Test Intermediate CA", rootCA)

	var bundlePEM []byte
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootCA.cert.Raw,
	})...)
	bundlePEM = append(bundlePEM, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: intermediateCA.cert.Raw,
	})...)

	mockCA := &configurableMockCA{
		bundle:       bundlePEM,
		parsedBundle: []*x509.Certificate{rootCA.cert, intermediateCA.cert},
	}

	logger := createTestLogger()
	svc := NewCAGRPCService(logger, mockCA)
	ctx := context.Background()

	resp, err := svc.GetCABundle(ctx, &platformv1.GetCABundleRequest{
		IncludeIntermediates: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Bundle.Pem) == 0 {
		t.Error("expected PEM bundle")
	}
	if resp.Bundle.CertCount == 0 {
		t.Error("expected certificates in bundle")
	}
}

// Helper function tests

func TestKeyUsageToStrings(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	result := service.keyUsageToStrings(usage)

	expected := []string{"DIGITAL_SIGNATURE", "CERT_SIGN", "CRL_SIGN"}
	if len(result) != len(expected) {
		t.Errorf("expected %d usages, got %d", len(expected), len(result))
	}
}

func TestExtKeyUsageToStrings(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usages := []x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
		x509.ExtKeyUsageCodeSigning,
	}
	result := service.extKeyUsageToStrings(usages)

	if len(result) != 3 {
		t.Errorf("expected 3 usages, got %d", len(result))
	}
}

func TestParseKeyUsage(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usages := []string{"DIGITAL_SIGNATURE", "CERT_SIGN", "KEY_ENCIPHERMENT"}
	result := service.parseKeyUsage(usages)

	if result&x509.KeyUsageDigitalSignature == 0 {
		t.Error("expected digital signature")
	}
	if result&x509.KeyUsageCertSign == 0 {
		t.Error("expected cert sign")
	}
	if result&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("expected key encipherment")
	}
}

func TestParseExtKeyUsage(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	usages := []string{"SERVER_AUTH", "CLIENT_AUTH", "TIME_STAMPING", "OCSP_SIGNING"}
	result := service.parseExtKeyUsage(usages)

	if len(result) != 4 {
		t.Errorf("expected 4 usages, got %d", len(result))
	}
}

func TestKeyAlgorithmConversions(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	// Test x509 to string
	if service.keyAlgorithmToString(x509.RSA) != "RSA" {
		t.Error("expected RSA")
	}
	if service.keyAlgorithmToString(x509.ECDSA) != "ECDSA" {
		t.Error("expected ECDSA")
	}
	if service.keyAlgorithmToString(x509.Ed25519) != "ED25519" {
		t.Error("expected ED25519")
	}
	if service.keyAlgorithmToString(x509.DSA) != "UNKNOWN" {
		t.Error("expected UNKNOWN")
	}

	// Test x509 to proto
	if service.x509AlgorithmToProto(x509.RSA) != platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048 {
		t.Error("expected RSA_2048")
	}
	if service.x509AlgorithmToProto(x509.ECDSA) != platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256 {
		t.Error("expected ECDSA_P256")
	}
	if service.x509AlgorithmToProto(x509.Ed25519) != platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519 {
		t.Error("expected ED25519")
	}

	// Test proto to x509
	if service.protoAlgorithmToX509(platformv1.KeyAlgorithm_KEY_ALGORITHM_RSA_2048) != x509.RSA {
		t.Error("expected RSA")
	}
	if service.protoAlgorithmToX509(platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256) != x509.ECDSA {
		t.Error("expected ECDSA")
	}
	if service.protoAlgorithmToX509(platformv1.KeyAlgorithm_KEY_ALGORITHM_ED25519) != x509.Ed25519 {
		t.Error("expected Ed25519")
	}
}

func TestRevocationReasonToProto(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}

	testCases := []struct {
		reason   int
		expected platformv1.RevocationReason
	}{
		{1, platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE},
		{2, platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE},
		{3, platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED},
		{4, platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED},
		{5, platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION},
		{6, platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD},
		{8, platformv1.RevocationReason_REVOCATION_REASON_REMOVE_FROM_CRL},
		{9, platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN},
		{10, platformv1.RevocationReason_REVOCATION_REASON_AA_COMPROMISE},
		{99, platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED},
	}

	for _, tc := range testCases {
		result := service.revocationReasonToProto(tc.reason)
		if result != tc.expected {
			t.Errorf("for reason %d, expected %v, got %v", tc.reason, tc.expected, result)
		}
	}
}

func TestGetCertificateStatus(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test CA")
	service := &CAGRPCService{}

	// Valid cert
	validCert := createCertSignedByCA(t, "valid.example.com", rootCA)
	if service.getCertificateStatus(validCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID {
		t.Error("expected valid status")
	}

	// Expired cert
	expiredCert := createExpiredCertSignedByCA(t, rootCA)
	if service.getCertificateStatus(expiredCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED {
		t.Error("expected expired status")
	}

	// Future cert
	futureCert := createFutureCertSignedByCA(t, rootCA)
	if service.getCertificateStatus(futureCert) != platformv1.CertificateStatus_CERTIFICATE_STATUS_PENDING {
		t.Error("expected pending status")
	}
}

func TestGetCertificateType(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Test CA")
	service := &CAGRPCService{}

	// CA cert
	if service.getCertificateType(rootCA.cert) != platformv1.CertificateType_CERTIFICATE_TYPE_CA {
		t.Error("expected CA type")
	}

	// Server cert (has ServerAuth)
	serverCert := createCertSignedByCA(t, "server.example.com", rootCA)
	certType := service.getCertificateType(serverCert)
	if certType != platformv1.CertificateType_CERTIFICATE_TYPE_SERVER {
		t.Errorf("expected SERVER type, got %v", certType)
	}
}

func TestCertToSummary_Nil(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}
	if service.certToSummary(nil) != nil {
		t.Error("expected nil for nil certificate")
	}
}

func TestCertToProto_Nil(t *testing.T) {
	t.Parallel()

	service := &CAGRPCService{}
	if service.certToProto(nil, true, true) != nil {
		t.Error("expected nil for nil certificate")
	}
}

func TestFirstOrEmptyGRPC(t *testing.T) {
	t.Parallel()

	if firstOrEmptyGRPC([]string{"first", "second"}) != "first" {
		t.Error("expected first element")
	}
	if firstOrEmptyGRPC([]string{}) != "" {
		t.Error("expected empty string")
	}
	if firstOrEmptyGRPC(nil) != "" {
		t.Error("expected empty string for nil")
	}
}

func TestCASuccessStatusGRPC(t *testing.T) {
	t.Parallel()

	status := caSuccessStatusGRPC("test message")
	if !status.Success {
		t.Error("expected success")
	}
	if status.Message != "test message" {
		t.Error("wrong message")
	}
}

func TestCAFailureStatusGRPC(t *testing.T) {
	t.Parallel()

	status := caFailureStatusGRPC("error message")
	if status.Success {
		t.Error("expected failure")
	}
	if status.Message != "error message" {
		t.Error("wrong message")
	}
}

// Error type tests

func TestErrNilCAService(t *testing.T) {
	t.Parallel()

	err := ErrNilCAService{}
	if err.Error() != "ca service is nil" {
		t.Error("wrong error message")
	}
}

func TestErrMissingSerial(t *testing.T) {
	t.Parallel()

	err := ErrMissingSerial{}
	if err.Error() != "serial number is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCertificateRequest(t *testing.T) {
	t.Parallel()

	err := ErrMissingCertificateRequest{}
	if err.Error() != "certificate request is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingSubject(t *testing.T) {
	t.Parallel()

	err := ErrMissingSubject{}
	if err.Error() != "subject is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCommonName(t *testing.T) {
	t.Parallel()

	err := ErrMissingCommonName{}
	if err.Error() != "common name is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingCertificate(t *testing.T) {
	t.Parallel()

	err := ErrMissingCertificate{}
	if err.Error() != "certificate (PEM or DER) is required" {
		t.Error("wrong error message")
	}
}

func TestErrMissingValidDays(t *testing.T) {
	t.Parallel()

	err := ErrMissingValidDays{}
	if err.Error() != "valid_days must be positive" {
		t.Error("wrong error message")
	}
}

func TestErrCAOperationFailed(t *testing.T) {
	t.Parallel()

	err := ErrCAOperationFailed{Operation: "test", Reason: "failed"}
	expected := "CA operation test failed: failed"
	if err.Error() != expected {
		t.Errorf("expected %s, got %s", expected, err.Error())
	}
}

func TestErrCertificateNotFoundGRPC(t *testing.T) {
	t.Parallel()

	err := ErrCertificateNotFoundGRPC{Serial: "123"}
	expected := "certificate not found: 123"
	if err.Error() != expected {
		t.Errorf("expected %s, got %s", expected, err.Error())
	}
}

func TestMatchesCertFilter(t *testing.T) {
	t.Parallel()

	rootCA := createTestCAWithKey(t, "Root CA")
	service := &CAGRPCService{}

	// Match status filter
	req := &platformv1.ListCertificatesRequest{
		StatusFilter: platformv1.CertificateStatus_CERTIFICATE_STATUS_VALID,
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for valid status")
	}

	// Non-match status filter
	req = &platformv1.ListCertificatesRequest{
		StatusFilter: platformv1.CertificateStatus_CERTIFICATE_STATUS_EXPIRED,
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for expired status")
	}

	// Match type filter
	req = &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_CA,
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for CA type")
	}

	// Non-match type filter
	req = &platformv1.ListCertificatesRequest{
		TypeFilter: platformv1.CertificateType_CERTIFICATE_TYPE_SERVER,
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for server type")
	}

	// Match issuer filter
	req = &platformv1.ListCertificatesRequest{
		IssuerFilter: "Root CA",
	}
	if !service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected match for issuer")
	}

	// Non-match issuer filter
	req = &platformv1.ListCertificatesRequest{
		IssuerFilter: "Other CA",
	}
	if service.matchesCertFilter(rootCA.cert, req) {
		t.Error("expected no match for different issuer")
	}
}

// Additional tests for parseKeyUsage and parseExtKeyUsage

func TestCAGRPCService_parseKeyUsage_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA)

	tests := []struct {
		input    []string
		expected x509.KeyUsage
	}{
		{[]string{"DIGITAL_SIGNATURE"}, x509.KeyUsageDigitalSignature},
		{[]string{"CONTENT_COMMITMENT"}, x509.KeyUsageContentCommitment},
		{[]string{"KEY_ENCIPHERMENT"}, x509.KeyUsageKeyEncipherment},
		{[]string{"DATA_ENCIPHERMENT"}, x509.KeyUsageDataEncipherment},
		{[]string{"KEY_AGREEMENT"}, x509.KeyUsageKeyAgreement},
		{[]string{"CERT_SIGN"}, x509.KeyUsageCertSign},
		{[]string{"CRL_SIGN"}, x509.KeyUsageCRLSign},
		{[]string{"ENCIPHER_ONLY"}, x509.KeyUsageEncipherOnly},
		{[]string{"DECIPHER_ONLY"}, x509.KeyUsageDecipherOnly},
		{[]string{"unknown"}, 0},
		{nil, 0},
	}

	for _, tc := range tests {
		result := service.parseKeyUsage(tc.input)
		if result != tc.expected {
			t.Errorf("parseKeyUsage(%v) = %v, expected %v", tc.input, result, tc.expected)
		}
	}
}

func TestCAGRPCService_parseExtKeyUsage_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA)

	tests := []struct {
		input    []string
		expected []x509.ExtKeyUsage
	}{
		{[]string{"ANY"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{[]string{"SERVER_AUTH"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{[]string{"CLIENT_AUTH"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{[]string{"CODE_SIGNING"}, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}},
		{[]string{"EMAIL_PROTECTION"}, []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}},
		{[]string{"TIME_STAMPING"}, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}},
		{[]string{"OCSP_SIGNING"}, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}},
		{[]string{"unknown"}, nil},
		{nil, nil},
	}

	for _, tc := range tests {
		result := service.parseExtKeyUsage(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("parseExtKeyUsage(%v) returned %d items, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i, r := range result {
			if r != tc.expected[i] {
				t.Errorf("parseExtKeyUsage(%v)[%d] = %v, expected %v", tc.input, i, r, tc.expected[i])
			}
		}
	}
}

func TestCAGRPCService_keyUsageToStrings_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA)

	tests := []struct {
		input    x509.KeyUsage
		expected []string
	}{
		{x509.KeyUsageDigitalSignature, []string{"DIGITAL_SIGNATURE"}},
		{x509.KeyUsageContentCommitment, []string{"CONTENT_COMMITMENT"}},
		{x509.KeyUsageKeyEncipherment, []string{"KEY_ENCIPHERMENT"}},
		{x509.KeyUsageDataEncipherment, []string{"DATA_ENCIPHERMENT"}},
		{x509.KeyUsageKeyAgreement, []string{"KEY_AGREEMENT"}},
		{x509.KeyUsageCertSign, []string{"CERT_SIGN"}},
		{x509.KeyUsageCRLSign, []string{"CRL_SIGN"}},
		{x509.KeyUsageEncipherOnly, []string{"ENCIPHER_ONLY"}},
		{x509.KeyUsageDecipherOnly, []string{"DECIPHER_ONLY"}},
		{0, nil},
	}

	for _, tc := range tests {
		result := service.keyUsageToStrings(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("keyUsageToStrings(%v) returned %d items, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i, r := range result {
			if r != tc.expected[i] {
				t.Errorf("keyUsageToStrings(%v)[%d] = '%s', expected '%s'", tc.input, i, r, tc.expected[i])
			}
		}
	}
}

func TestCAGRPCService_extKeyUsageToStrings_AllTypes(t *testing.T) {
	logger := createTestLogger()
	mockCA := &configurableMockCA{}
	service := NewCAGRPCService(logger, mockCA)

	tests := []struct {
		input    []x509.ExtKeyUsage
		expected []string
	}{
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageAny}, []string{"ANY"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"SERVER_AUTH"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, []string{"CLIENT_AUTH"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, []string{"CODE_SIGNING"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}, []string{"EMAIL_PROTECTION"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}, []string{"TIME_STAMPING"}},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, []string{"OCSP_SIGNING"}},
		// Unmapped types return empty
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECEndSystem}, nil},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECTunnel}, nil},
		{[]x509.ExtKeyUsage{x509.ExtKeyUsageIPSECUser}, nil},
		{nil, nil},
	}

	for _, tc := range tests {
		result := service.extKeyUsageToStrings(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("extKeyUsageToStrings(%v) returned %d items, expected %d", tc.input, len(result), len(tc.expected))
			continue
		}
		for i, r := range result {
			if r != tc.expected[i] {
				t.Errorf("extKeyUsageToStrings(%v)[%d] = '%s', expected '%s'", tc.input, i, r, tc.expected[i])
			}
		}
	}
}
